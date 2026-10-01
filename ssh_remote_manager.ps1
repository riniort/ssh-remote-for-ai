param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class DarkTitleBarNative {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
"@

$ColorBackground = [System.Drawing.Color]::FromArgb(13, 15, 16)
$ColorSidebar = [System.Drawing.Color]::FromArgb(17, 19, 21)
$ColorSurface = [System.Drawing.Color]::FromArgb(24, 27, 29)
$ColorSurfaceHover = [System.Drawing.Color]::FromArgb(31, 36, 39)
$ColorBorder = [System.Drawing.Color]::FromArgb(45, 50, 54)
$ColorText = [System.Drawing.Color]::FromArgb(239, 243, 245)
$ColorMuted = [System.Drawing.Color]::FromArgb(132, 141, 148)
$ColorAccent = [System.Drawing.Color]::FromArgb(22, 194, 210)
$ColorAccentDark = [System.Drawing.Color]::FromArgb(8, 72, 79)
$ColorSuccess = [System.Drawing.Color]::FromArgb(52, 211, 123)
$ColorWarning = [System.Drawing.Color]::FromArgb(245, 173, 40)
$ColorDanger = [System.Drawing.Color]::FromArgb(241, 83, 83)

$script:KeyPath = ""
$script:PublicKey = ""
$script:SelectedAlias = ""
$script:ConnectionMode = "managed"
$script:SshConfigAlias = ""
$script:Profiles = @()
$script:ProfileStoreAvailable = $false
$script:ProfileStoreWarning = ""
$script:ProfileStoreModule = Join-Path $PSScriptRoot "src\SshRemoteManager.ProfileStore.psm1"

if (Test-Path -LiteralPath $script:ProfileStoreModule) {
    try {
        Import-Module -Name $script:ProfileStoreModule -Force -ErrorAction Stop
        $script:ProfileStoreAvailable = $null -ne (Get-Command Get-SrmProfiles -ErrorAction SilentlyContinue)
        if (-not $script:ProfileStoreAvailable) { throw "Get-SrmProfiles was not exported." }
    } catch {
        $script:ProfileStoreAvailable = $false
        $script:ProfileStoreWarning = "ProfileStore module could not be loaded; using legacy managed-block compatibility mode. $($_.Exception.Message)"
    }
}

function Get-PropertyValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
        return $Default
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function ConvertTo-NormalizedPublicKey {
    param([Parameter(Mandatory)][string]$Value)
    if ($script:ProfileStoreAvailable -and $null -ne (Get-Command ConvertTo-SrmPublicKey -ErrorAction SilentlyContinue)) {
        return ConvertTo-SrmPublicKey -Value $Value
    }
    $trimmed = $Value.Trim()
    $keyType = '(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-[A-Za-z0-9@._+-]+|sk-(?:ssh-ed25519|ecdsa-sha2-[A-Za-z0-9@._+-]+)@[A-Za-z0-9._-]+)'
    if ($trimmed -notmatch "^(?<type>$keyType)[ `t]+(?<blob>[A-Za-z0-9+/]+={0,3})(?:[ `t]+[^`r`n]*)?$") {
        throw 'The public key has an unsupported OpenSSH format.'
    }
    return "$($Matches.type) $($Matches.blob)"
}

function Get-SshConfigPath {
    return Join-Path (Join-Path $env:USERPROFILE ".ssh") "config"
}

function Remove-ManagedBlock {
    param([string]$Content, [string]$Alias)
    $escapedAlias = [regex]::Escape($Alias)
    return [regex]::Replace(
        $Content,
        "(?ms)^# BEGIN (?<kind>KEBLM MANAGED SSH|SSH REMOTE MANAGER): $escapedAlias\r?\n.*?^# END \k<kind>: $escapedAlias\r?\n?",
        ""
    )
}

function Get-ManagedProfiles {
    if ($script:ProfileStoreAvailable) {
        $profiles = foreach ($profile in @(Get-SrmProfiles)) {
            $alias = [string](Get-PropertyValue $profile "alias" "")
            $server = [string](Get-PropertyValue $profile "host" "")
            $environment = [string](Get-PropertyValue $profile "environment" "development")
            [pscustomobject]@{
                Alias = $alias
                DisplayName = [string](Get-PropertyValue $profile "displayName" $alias)
                Server = $server
                User = [string](Get-PropertyValue $profile "user" "")
                Port = [string](Get-PropertyValue $profile "port" 22)
                KeyPath = [string](Get-PropertyValue $profile "identityFile" "")
                Environment = $environment
                Capabilities = Get-PropertyValue $profile "capabilities" ([pscustomobject]@{})
                Allowlists = Get-PropertyValue $profile "allowlists" ([pscustomobject]@{})
                LastTestedUtc = [string](Get-PropertyValue $profile "lastTestedUtc" "")
                ConnectionMode = [string](Get-PropertyValue $profile "connectionMode" "managed")
                SshConfigAlias = [string](Get-PropertyValue $profile "sshConfigAlias" "")
                Display = "$alias  [$($environment.ToUpperInvariant())]  |  $server"
            }
        }
        return @($profiles | Sort-Object Alias)
    }

    $configPath = Get-SshConfigPath
    if (-not (Test-Path -LiteralPath $configPath)) {
        return @()
    }
    $content = Get-Content -LiteralPath $configPath -Raw
    $pattern = '(?ms)^# BEGIN (?<kind>KEBLM MANAGED SSH|SSH REMOTE MANAGER): (?<alias>[^\r\n]+)\r?\n(?<body>.*?)^# END \k<kind>: \k<alias>\r?\n?'
    $profiles = foreach ($match in [regex]::Matches($content, $pattern)) {
        $body = $match.Groups['body'].Value
        $alias = $match.Groups['alias'].Value.Trim()
        $serverMatch = [regex]::Match($body, '(?mi)^\s*HostName\s+(?<value>\S+)\s*$')
        $userMatch = [regex]::Match($body, '(?mi)^\s*User\s+(?<value>\S+)\s*$')
        $portMatch = [regex]::Match($body, '(?mi)^\s*Port\s+(?<value>\d+)\s*$')
        $keyMatch = [regex]::Match($body, '(?mi)^\s*IdentityFile\s+(?<value>.+?)\s*$')
        [pscustomobject]@{
            Alias = $alias
            Server = $serverMatch.Groups['value'].Value
            User = $userMatch.Groups['value'].Value
            Port = if ($portMatch.Success) { $portMatch.Groups['value'].Value } else { "22" }
            KeyPath = $keyMatch.Groups['value'].Value.Replace('/', '\')
            DisplayName = $alias
            Environment = "development"
            Capabilities = [pscustomobject]@{ serverInfo = $true; systemd = $false; docker = $false; logs = $false }
            Allowlists = [pscustomobject]@{ services = @(); logTargets = [pscustomobject]@{} }
            LastTestedUtc = ""
            ConnectionMode = "managed"
            SshConfigAlias = ""
            Display = if ($serverMatch.Success) { "$alias  |  $($serverMatch.Groups['value'].Value)" } else { $alias }
        }
    }
    return @($profiles | Sort-Object Alias)
}

function Load-ProfileList {
    $script:Profiles = @(Get-ManagedProfiles)
    $ProfileList.BeginUpdate()
    try {
        $ProfileList.Items.Clear()
        foreach ($profile in $script:Profiles) {
            [void]$ProfileList.Items.Add($profile)
        }
    } finally {
        $ProfileList.EndUpdate()
    }
    $ProfileCountLabel.Text = "$($script:Profiles.Count) managed profile(s)"
}

function Update-EnvironmentBadge {
    $environment = [string]$EnvironmentBox.SelectedItem
    if (-not $environment) { $environment = "development" }
    $EnvironmentBadge.Text = $environment.ToUpperInvariant()
    switch ($environment) {
        "production" {
            $EnvironmentBadge.BackColor = $ColorDanger
            $EnvironmentBadge.ForeColor = $ColorText
            $EnvironmentWarningLabel.Text = "PRODUCTION: read-only policy is enforced by default. Verify the target before testing."
            $EnvironmentWarningLabel.ForeColor = $ColorWarning
        }
        "staging" {
            $EnvironmentBadge.BackColor = $ColorWarning
            $EnvironmentBadge.ForeColor = $ColorBackground
            $EnvironmentWarningLabel.Text = "Staging profile: confirm the target and allowlists before use."
            $EnvironmentWarningLabel.ForeColor = $ColorWarning
        }
        default {
            $EnvironmentBadge.BackColor = $ColorAccentDark
            $EnvironmentBadge.ForeColor = $ColorAccent
            $EnvironmentWarningLabel.Text = "Development profile"
            $EnvironmentWarningLabel.ForeColor = $ColorMuted
        }
    }
}

function Clear-ProfileEditor {
    $script:SelectedAlias = ""
    $script:KeyPath = ""
    $script:PublicKey = ""
    $script:ConnectionMode = "managed"
    $script:SshConfigAlias = ""
    $AliasBox.Text = ""
    $HostBox.Text = ""
    $UserBox.Text = "codex-keblm"
    $PortBox.Text = "22"
    $PublicKeyBox.Text = ""
    $EnvironmentBox.SelectedItem = "development"
    $DisplayNameBox.Text = ""
    $ServerInfoCheck.Checked = $true
    $SystemdCheck.Checked = $false
    $DockerCheck.Checked = $false
    $LogsCheck.Checked = $false
    $ServicesBox.Text = ""
    $LogTargetsBox.Text = ""
    Update-EnvironmentBadge
    $LastTestedLabel.Text = "Connection: not tested"
    $KeyStatusLabel.Text = "A separate key will be created for this profile"
    $KeyStatusLabel.ForeColor = $ColorMuted
    $SavedStatusLabel.Text = "New profile"
    $AliasBox.Focus()
}

function Select-Profile {
    param($Profile)
    if ($null -eq $Profile) { return }
    $script:SelectedAlias = $Profile.Alias
    $script:ConnectionMode = if ($Profile.ConnectionMode) { $Profile.ConnectionMode } else { "managed" }
    $script:SshConfigAlias = $Profile.SshConfigAlias
    $AliasBox.Text = $Profile.Alias
    $DisplayNameBox.Text = $Profile.DisplayName
    $HostBox.Text = $Profile.Server
    $UserBox.Text = $Profile.User
    $PortBox.Text = $Profile.Port
    $EnvironmentBox.SelectedItem = $Profile.Environment
    if ($EnvironmentBox.SelectedIndex -lt 0) { $EnvironmentBox.SelectedItem = "development" }
    Update-EnvironmentBadge
    $capabilities = $Profile.Capabilities
    $ServerInfoCheck.Checked = [bool](Get-PropertyValue $capabilities "serverInfo" $true)
    $SystemdCheck.Checked = [bool](Get-PropertyValue $capabilities "systemd" $false)
    $DockerCheck.Checked = [bool](Get-PropertyValue $capabilities "docker" $false)
    $LogsCheck.Checked = [bool](Get-PropertyValue $capabilities "logs" $false)
    $allowlists = $Profile.Allowlists
    $ServicesBox.Text = (@(Get-PropertyValue $allowlists "services" @()) -join ", ")
    $logTargets = Get-PropertyValue $allowlists "logTargets" @()
    $logTargetLines = foreach ($target in @($logTargets)) {
        $name = Get-PropertyValue $target "name" ""
        $path = Get-PropertyValue $target "path" ""
        if ($name -and $path) { "$name=$path" }
    }
    # Accept the early mapping-shaped schema too, so prerelease stores remain editable.
    if (@($logTargetLines).Count -eq 0 -and $null -ne $logTargets -and $logTargets -isnot [System.Array]) {
        if ($logTargets -is [System.Collections.IDictionary]) {
            $logTargetLines = @($logTargets.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" })
        } else {
            $logTargetLines = @($logTargets.PSObject.Properties | Where-Object { $_.Name -notin @('Count', 'Length') } | ForEach-Object { "$($_.Name)=$($_.Value)" })
        }
    }
    $LogTargetsBox.Text = (@($logTargetLines) -join "`r`n")
    $LastTestedLabel.Text = if ($Profile.LastTestedUtc) { "Connection: last tested $($Profile.LastTestedUtc)" } else { "Connection: not tested" }
    $script:KeyPath = $Profile.KeyPath
    $publicKeyPath = if ($script:KeyPath -and $script:ProfileStoreAvailable -and $null -ne (Get-Command Get-SrmPublicKeyPath -ErrorAction SilentlyContinue)) {
        Get-SrmPublicKeyPath -IdentityFile $script:KeyPath
    } else {
        "$script:KeyPath.pub"
    }
    if ($script:ConnectionMode -eq "ssh-config-alias") {
        $script:PublicKey = ""
        $PublicKeyBox.Text = ""
        $KeyStatusLabel.Text = "Authentication is managed by existing SSH Host '$script:SshConfigAlias'"
        $KeyStatusLabel.ForeColor = $ColorAccent
    } elseif ($script:KeyPath -and (Test-Path -LiteralPath $publicKeyPath)) {
        $rawPublicKey = Get-Content -LiteralPath $publicKeyPath -Raw
        $script:PublicKey = ConvertTo-NormalizedPublicKey -Value $rawPublicKey
        $PublicKeyBox.Text = $script:PublicKey
        $KeyStatusLabel.Text = "Key ready: $publicKeyPath"
        $KeyStatusLabel.ForeColor = $ColorSuccess
    } else {
        $script:PublicKey = ""
        $PublicKeyBox.Text = ""
        $KeyStatusLabel.Text = "Public key not found for this profile"
        $KeyStatusLabel.ForeColor = $ColorWarning
    }
    $SavedStatusLabel.Text = "Editing '$($Profile.Alias)'"
}

function Show-Message {
    param(
        [string]$Text,
        [string]$Title = "SSH Remote Manager",
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    [void][System.Windows.Forms.MessageBox]::Show(
        $Form,
        $Text,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $Icon
    )
}

function Get-ValidatedValues {
    $alias = $AliasBox.Text.Trim()
    $server = $HostBox.Text.Trim()
    $user = $UserBox.Text.Trim()
    $portNumber = 0
    $environment = [string]$EnvironmentBox.SelectedItem

    if ($alias -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw "Alias must start with a letter or number and may contain only letters, numbers, dot, underscore, and hyphen."
    }
    if (
        -not $server -or $server.StartsWith('-') -or
        $server -match '\s' -or
        $server.Contains('"') -or
        $server.Contains("'") -or
        $server.Contains([string][char]96)
    ) {
        throw "Enter a valid server IP address or DNS name."
    }
    if ($user -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*[$]?$') {
        throw "Enter a valid Linux SSH username."
    }
    if (-not [int]::TryParse($PortBox.Text.Trim(), [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) {
        throw "Port must be a number from 1 to 65535."
    }
    if ($environment -notin @("development", "staging", "production")) {
        throw "Choose development, staging, or production."
    }

    $services = @($ServicesBox.Text -split '[,\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($service in $services) {
        if ($service -notmatch '^[A-Za-z0-9][A-Za-z0-9_.@-]*$') { throw "Invalid service allowlist entry: $service" }
    }
    $logTargets = @()
    foreach ($line in @($LogTargetsBox.Text -split '\r?\n')) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -notmatch '^(?<name>[A-Za-z0-9][A-Za-z0-9_.-]*)=(?<path>/.+)$') {
            throw "Log targets must use name=/absolute/path, one per line."
        }
        if ($Matches.path -match '(?:^|/)\.\.(?:/|$)' -or $Matches.path -match '[\r\n\x00]') {
            throw "Log target paths must be absolute and cannot contain traversal segments."
        }
        $logTargets += [pscustomobject][ordered]@{ name = $Matches.name; path = $Matches.path }
    }

    return [pscustomobject]@{
        Alias = $alias
        Server = $server
        User = $user
        Port = $portNumber
        DisplayName = if ($DisplayNameBox.Text.Trim()) { $DisplayNameBox.Text.Trim() } else { $alias }
        Environment = $environment
        Services = $services
        LogTargets = @($logTargets)
    }
}

function New-ProfileRecord {
    param($Values, [string]$LastTestedUtc = "")
    return [pscustomobject][ordered]@{
        alias = $Values.Alias
        displayName = $Values.DisplayName
        host = $Values.Server
        port = $Values.Port
        user = $Values.User
        environment = $Values.Environment
        connectionMode = $script:ConnectionMode
        sshConfigAlias = if ($script:ConnectionMode -eq "ssh-config-alias") { $script:SshConfigAlias } else { $null }
        identityFile = $script:KeyPath
        capabilities = [pscustomobject][ordered]@{
            serverInfo = $ServerInfoCheck.Checked
            systemd = $SystemdCheck.Checked
            docker = $DockerCheck.Checked
            logs = $LogsCheck.Checked
        }
        allowlists = [pscustomobject][ordered]@{
            services = @($Values.Services)
            logTargets = @($Values.LogTargets)
        }
        lastTestedUtc = $LastTestedUtc
    }
}

function Ensure-SshKey {
    if ($script:ConnectionMode -eq "ssh-config-alias") {
        throw "This imported profile uses authentication from SSH Host '$script:SshConfigAlias'. Edit that SSH config entry if its key must change."
    }
    $values = Get-ValidatedValues
    $sshFolder = Join-Path $env:USERPROFILE ".ssh"
    if (-not $script:KeyPath) {
        $safeAlias = $values.Alias -replace '[^A-Za-z0-9._-]', '_'
        $script:KeyPath = Join-Path $sshFolder "ssh_remote_manager_$safeAlias"
    }
    $publicKeyPath = if ($script:ProfileStoreAvailable -and $null -ne (Get-Command Get-SrmPublicKeyPath -ErrorAction SilentlyContinue)) {
        Get-SrmPublicKeyPath -IdentityFile $script:KeyPath
    } else {
        "$script:KeyPath.pub"
    }

    if (-not (Test-Path -LiteralPath $sshFolder)) {
        [void](New-Item -ItemType Directory -Path $sshFolder)
    }
    if (-not (Test-Path -LiteralPath $script:KeyPath)) {
        $sshKeygen = Get-Command ssh-keygen -ErrorAction Stop
        & $sshKeygen.Source -q -t ed25519 -f $script:KeyPath -C "ssh-remote-manager:$($values.Alias)" -N ""
        if ($LASTEXITCODE -ne 0) {
            throw "ssh-keygen failed with exit code $LASTEXITCODE."
        }
    }
    if (-not (Test-Path -LiteralPath $publicKeyPath)) {
        throw "Private key exists but its public key is missing: $publicKeyPath"
    }

    $rawPublicKey = Get-Content -LiteralPath $publicKeyPath -Raw
    $script:PublicKey = ConvertTo-NormalizedPublicKey -Value $rawPublicKey
    $PublicKeyBox.Text = $script:PublicKey
    $KeyStatusLabel.Text = "Key ready: $publicKeyPath"
    $KeyStatusLabel.ForeColor = $ColorSuccess
}

function Import-OpenSshKeyPair {
    if ($script:ConnectionMode -eq "ssh-config-alias") {
        throw "This profile uses authentication from an existing SSH Host. Create a managed profile to import a key pair."
    }
    $values = Get-ValidatedValues
    $privateDialog = New-Object System.Windows.Forms.OpenFileDialog
    $privateDialog.Title = "Select an OpenSSH private key (for example rsa.txt)"
    $privateDialog.Filter = "Private key files (*.txt;id_*)|*.txt;id_*|All files (*.*)|*.*"
    $privateDialog.CheckFileExists = $true
    $privateDialog.Multiselect = $false
    if ($privateDialog.ShowDialog($Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $sourcePrivate = [System.IO.Path]::GetFullPath($privateDialog.FileName)
    $sourceItem = Get-Item -LiteralPath $sourcePrivate -Force
    if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The selected private key cannot be a symlink, junction, or reparse point."
    }
    $reader = New-Object System.IO.StreamReader($sourcePrivate, [System.Text.Encoding]::ASCII, $true)
    try { $privateHeader = $reader.ReadLine() } finally { $reader.Dispose() }
    if ($privateHeader -cne '-----BEGIN OPENSSH PRIVATE KEY-----') {
        throw "The selected file is not an OpenSSH private key. Expected an OPENSSH PRIVATE KEY header."
    }

    $sourcePublic = if ($script:ProfileStoreAvailable -and $null -ne (Get-Command Get-SrmPublicKeyPath -ErrorAction SilentlyContinue)) {
        Get-SrmPublicKeyPath -IdentityFile $sourcePrivate
    } else {
        "$sourcePrivate.pub"
    }
    if (-not (Test-Path -LiteralPath $sourcePublic -PathType Leaf)) {
        throw "A matching public key was not found. For rsa.txt, place rsa.pub in the same folder."
    }
    $publicItem = Get-Item -LiteralPath $sourcePublic -Force
    if (($publicItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The selected public key cannot be a symlink, junction, or reparse point."
    }
    $rawPublicKey = Get-Content -LiteralPath $sourcePublic -Raw
    $publicKey = ConvertTo-NormalizedPublicKey -Value $rawPublicKey

    $sshKeygen = Get-Command ssh-keygen -ErrorAction Stop
    $derivedOutput = & $sshKeygen.Source -y -P "" -f $sourcePrivate 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $derivedOutput) {
        throw "The private key could not be validated. Encrypted keys are not supported because unattended SSH cannot prompt for a passphrase."
    }
    $derivedParts = ([string]($derivedOutput | Select-Object -First 1)).Trim() -split '\s+'
    $publicParts = $publicKey -split '\s+'
    if ($derivedParts.Count -lt 2 -or $publicParts.Count -lt 2 -or $derivedParts[0] -cne $publicParts[0] -or $derivedParts[1] -cne $publicParts[1]) {
        throw "The public key does not match the selected private key."
    }

    $keyDirectory = Join-Path (Join-Path $env:USERPROFILE ".ssh") "ssh-remote-manager\keys"
    if (-not (Test-Path -LiteralPath $keyDirectory)) { [void](New-Item -ItemType Directory -Path $keyDirectory -Force) }
    $safeAlias = $values.Alias -replace '[^A-Za-z0-9._-]', '_'
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $privateExtension = [System.IO.Path]::GetExtension($sourcePrivate)
    if ($privateExtension -ieq '.pub') {
        throw "Select the private-key file, not the .pub file."
    }
    $destinationPrivate = Join-Path $keyDirectory ("${safeAlias}_${suffix}${privateExtension}")
    $destinationPublic = [System.IO.Path]::ChangeExtension($destinationPrivate, '.pub')
    try {
        Copy-Item -LiteralPath $sourcePrivate -Destination $destinationPrivate -ErrorAction Stop
        Copy-Item -LiteralPath $sourcePublic -Destination $destinationPublic -ErrorAction Stop
    } catch {
        foreach ($partialPath in @($destinationPrivate, $destinationPublic)) {
            if (Test-Path -LiteralPath $partialPath -PathType Leaf) { Remove-Item -LiteralPath $partialPath -Force }
        }
        throw "The key pair could not be copied into the managed SSH directory."
    }

    $script:KeyPath = $destinationPrivate
    $script:PublicKey = $publicKey
    $PublicKeyBox.Text = $script:PublicKey
    $KeyStatusLabel.Text = "Imported OpenSSH key pair: $destinationPublic"
    $KeyStatusLabel.ForeColor = $ColorSuccess
}

function Get-InstallCommand {
    if (-not $script:PublicKey) {
        Ensure-SshKey
    }
    return "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && grep -qxF '$script:PublicKey' ~/.ssh/authorized_keys || printf '%s\n' '$script:PublicKey' >> ~/.ssh/authorized_keys"
}

function Get-RevokeCommand {
    if (-not $script:PublicKey) {
        throw "This profile has no local public key to revoke."
    }
    return "tmp=`$(mktemp) && awk -v key='$script:PublicKey' '`$0 != key' ~/.ssh/authorized_keys > `"`$tmp`" && cat `"`$tmp`" > ~/.ssh/authorized_keys; rc=`$?; rm -f `"`$tmp`"; exit `$rc"
}

function Get-ConnectionTargetAlias {
    param($Values)
    if ($script:ConnectionMode -eq "ssh-config-alias") { return $script:SshConfigAlias }
    return $Values.Alias
}

function Save-SshProfile {
    param([string]$LastTestedUtc = "")
    $values = Get-ValidatedValues
    if ($script:ConnectionMode -ne "ssh-config-alias") { Ensure-SshKey }

    if ($script:ProfileStoreAvailable) {
        if (-not $LastTestedUtc -and $script:SelectedAlias) {
            $existingProfile = $script:Profiles | Where-Object Alias -eq $script:SelectedAlias | Select-Object -First 1
            if ($null -ne $existingProfile) { $LastTestedUtc = $existingProfile.LastTestedUtc }
        }
        $profileRecord = New-ProfileRecord $values $LastTestedUtc
        Save-SrmProfile -Profile $profileRecord -OriginalAlias $script:SelectedAlias
        $script:SelectedAlias = $values.Alias
        $SavedStatusLabel.Text = "Saved profile '$($values.Alias)' to the SSH Remote Manager profile store"
        $SavedStatusLabel.ForeColor = $ColorSuccess
        Load-ProfileList
        for ($index = 0; $index -lt $ProfileList.Items.Count; $index++) {
            if ($ProfileList.Items[$index].Alias -eq $values.Alias) {
                $ProfileList.SelectedIndex = $index
                break
            }
        }
        return
    }

    $sshFolder = Join-Path $env:USERPROFILE ".ssh"
    $configPath = Join-Path $sshFolder "config"
    $begin = "# BEGIN SSH REMOTE MANAGER: $($values.Alias)"
    $end = "# END SSH REMOTE MANAGER: $($values.Alias)"
    $block = @"
$begin
Host $($values.Alias)
    HostName $($values.Server)
    User $($values.User)
    Port $($values.Port)
    IdentityFile $($script:KeyPath.Replace('\', '/'))
    IdentitiesOnly yes
$end
"@

    $existing = if (Test-Path -LiteralPath $configPath) {
        Get-Content -LiteralPath $configPath -Raw
    } else {
        ""
    }
    $withoutManaged = Remove-ManagedBlock $existing $values.Alias
    if ($script:SelectedAlias -and $script:SelectedAlias -ne $values.Alias) {
        $withoutManaged = Remove-ManagedBlock $withoutManaged $script:SelectedAlias
    }
    $withoutManaged = $withoutManaged.TrimEnd()
    $hostPattern = "(?mi)^\s*Host\s+([^\r\n#]*\s)?$([regex]::Escape($values.Alias))(\s|$)"
    if ($withoutManaged -match $hostPattern) {
        throw "SSH config already contains an unmanaged Host '$($values.Alias)'. Choose another alias or edit $configPath manually."
    }

    $newContent = if ($withoutManaged) { "$withoutManaged`r`n`r`n$block`r`n" } else { "$block`r`n" }
    Set-Content -LiteralPath $configPath -Value $newContent -Encoding utf8
    $script:SelectedAlias = $values.Alias
    $SavedStatusLabel.Text = "Saved SSH profile '$($values.Alias)' to $configPath"
    $SavedStatusLabel.ForeColor = $ColorSuccess
    Load-ProfileList
    for ($index = 0; $index -lt $ProfileList.Items.Count; $index++) {
        if ($ProfileList.Items[$index].Alias -eq $values.Alias) {
            $ProfileList.SelectedIndex = $index
            break
        }
    }
}

function Delete-SelectedProfile {
    if (-not $script:SelectedAlias) {
        throw "Select a managed profile first."
    }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $Form,
        "Remove local profile '$script:SelectedAlias'?`n`nThis does not remove its public key from the server. Copy and run the revoke command on the server first if access must be revoked.",
        "Remove SSH profile",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    if ($script:ProfileStoreAvailable) {
        Remove-SrmProfile -Alias $script:SelectedAlias -Confirm:$false
        Clear-ProfileEditor
        Load-ProfileList
        return
    }
    $configPath = Get-SshConfigPath
    $existing = if (Test-Path -LiteralPath $configPath) { Get-Content -LiteralPath $configPath -Raw } else { "" }
    $updated = (Remove-ManagedBlock $existing $script:SelectedAlias).TrimEnd()
    Set-Content -LiteralPath $configPath -Value $(if ($updated) { "$updated`r`n" } else { "" }) -Encoding utf8
    Clear-ProfileEditor
    Load-ProfileList
}

function Delete-SelectedLocalKey {
    if (-not $script:SelectedAlias -or -not $script:KeyPath) {
        throw "Select a profile with a local key first."
    }
    if ($script:ConnectionMode -eq "ssh-config-alias") {
        throw "This imported profile does not own its SSH config key. Manage that key outside SSH Remote Manager."
    }
    $sshRoot = [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE ".ssh"))
    $keyFullPath = [System.IO.Path]::GetFullPath($script:KeyPath)
    if (-not $keyFullPath.StartsWith(($sshRoot.TrimEnd('\') + '\'), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to delete a key outside $sshRoot."
    }
    $answer = [System.Windows.Forms.MessageBox]::Show(
        $Form,
        "Permanently delete the local private/public key pair for '$script:SelectedAlias'?`n`n$keyFullPath`n`nThis does NOT revoke the public key on any server and does NOT remove the profile. This cannot be undone.",
        "Delete local key pair",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    $publicKeyPath = if ($script:ProfileStoreAvailable -and $null -ne (Get-Command Get-SrmPublicKeyPath -ErrorAction SilentlyContinue)) {
        Get-SrmPublicKeyPath -IdentityFile $keyFullPath
    } else {
        "$keyFullPath.pub"
    }
    foreach ($path in @($keyFullPath, $publicKeyPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    $script:PublicKey = ""
    $PublicKeyBox.Text = ""
    $KeyStatusLabel.Text = "Local key pair deleted; server access may still be active until separately revoked"
    $KeyStatusLabel.ForeColor = $ColorDanger
}

function Get-UnmanagedSshHosts {
    $configPath = Get-SshConfigPath
    if (-not (Test-Path -LiteralPath $configPath)) { return @() }
    $entries = New-Object System.Collections.Generic.List[object]
    $current = $null
    $insideManagedBlock = $false
    foreach ($rawLine in @(Get-Content -LiteralPath $configPath)) {
        $line = $rawLine.Trim()
        if ($line -match '^# BEGIN (?:KEBLM MANAGED SSH|SSH REMOTE MANAGER):') {
            $insideManagedBlock = $true
            continue
        }
        if ($line -match '^# END (?:KEBLM MANAGED SSH|SSH REMOTE MANAGER):') {
            $insideManagedBlock = $false
            continue
        }
        if ($insideManagedBlock) { continue }
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line -match '^(?i)Include\s+(?<value>.+)$') {
            $entries.Add([pscustomobject]@{ Alias = "Include $($Matches.value)"; Display = "[READ-ONLY] Include $($Matches.value)"; Importable = $false })
            continue
        }
        if ($line -match '^(?i)Host\s+(?<value>.+)$') {
            if ($null -ne $current) { $entries.Add([pscustomobject]$current) }
            $hostValue = $Matches.value.Trim()
            $importable = $hostValue -match '^[A-Za-z0-9._-]+$'
            $current = [ordered]@{
                Alias = $hostValue
                Display = if ($importable) { $hostValue } else { "[READ-ONLY] $hostValue (wildcard/multiple)" }
                Importable = $importable
                Server = ""
                User = ""
                Port = "22"
                KeyPath = ""
            }
            continue
        }
        if ($null -eq $current) { continue }
        if ($line -match '^(?i)HostName\s+(?<value>\S+)$') { $current.Server = $Matches.value }
        elseif ($line -match '^(?i)User\s+(?<value>\S+)$') { $current.User = $Matches.value }
        elseif ($line -match '^(?i)Port\s+(?<value>\d+)$') { $current.Port = $Matches.value }
        elseif ($line -match '^(?i)IdentityFile\s+(?<value>.+)$') { $current.KeyPath = $Matches.value.Trim('"').Replace('/', '\') }
    }
    if ($null -ne $current) { $entries.Add([pscustomobject]$current) }
    return @($entries)
}

function Show-ImportSshHostDialog {
    $entries = @(Get-UnmanagedSshHosts)
    if ($entries.Count -eq 0) {
        Show-Message "No Host or Include entries were found in $(Get-SshConfigPath)."
        return
    }
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = "Import existing SSH Host"
    $dialog.StartPosition = "CenterParent"
    $dialog.Size = New-Object System.Drawing.Size(560, 390)
    $dialog.BackColor = $ColorBackground
    $dialog.ForeColor = $ColorText
    $dialog.Font = $Form.Font
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Select an exact Host entry. Wildcards, multiple aliases, and Include directives are shown read-only."
    $label.Location = New-Object System.Drawing.Point(18, 18)
    $label.Size = New-Object System.Drawing.Size(510, 42)
    $label.ForeColor = $ColorMuted
    $dialog.Controls.Add($label)
    $list = New-Object System.Windows.Forms.ListBox
    $list.DisplayMember = "Display"
    $list.Location = New-Object System.Drawing.Point(18, 68)
    $list.Size = New-Object System.Drawing.Size(510, 210)
    $list.BackColor = $ColorSidebar
    $list.ForeColor = $ColorText
    foreach ($entry in $entries) { [void]$list.Items.Add($entry) }
    $dialog.Controls.Add($list)
    $importButton = New-Object System.Windows.Forms.Button
    $importButton.Text = "Load selected Host"
    $importButton.Location = New-Object System.Drawing.Point(343, 295)
    $importButton.Size = New-Object System.Drawing.Size(185, 38)
    Set-DarkButton $importButton $ColorAccent $ColorBackground $ColorAccent
    $dialog.Controls.Add($importButton)
    $importButton.Add_Click({
        $entry = $list.SelectedItem
        if ($null -eq $entry) { return }
        if (-not $entry.Importable) {
            [void][System.Windows.Forms.MessageBox]::Show($dialog, "This entry remains read-only. Choose one exact Host alias to import.", "Import SSH Host", "OK", "Warning")
            return
        }
        $dialog.Tag = $entry
        $dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Close()
    })
    if ($dialog.ShowDialog($Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $entry = $dialog.Tag
    Clear-ProfileEditor
    $script:ConnectionMode = "ssh-config-alias"
    $script:SshConfigAlias = [string]$entry.Alias
    $AliasBox.Text = $entry.Alias
    $DisplayNameBox.Text = $entry.Alias
    $HostBox.Text = if ($entry.Server) { $entry.Server } else { $entry.Alias }
    if ($entry.User) { $UserBox.Text = $entry.User }
    $PortBox.Text = $entry.Port
    $script:KeyPath = ""
    $KeyStatusLabel.Text = "Authentication will remain managed by existing SSH Host '$($entry.Alias)'"
    $KeyStatusLabel.ForeColor = $ColorAccent
    $SavedStatusLabel.Text = "Ready to import Host '$($entry.Alias)' by reference. Saving will not rewrite the original SSH config entry."
    $SavedStatusLabel.ForeColor = $ColorWarning
}

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "SSH Remote Manager"
$Form.StartPosition = "CenterScreen"
$Form.Size = New-Object System.Drawing.Size(1120, 870)
$Form.MinimumSize = New-Object System.Drawing.Size(1120, 870)
$Form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$Form.BackColor = $ColorBackground
$Form.ForeColor = $ColorText

$TitleLabel = New-Object System.Windows.Forms.Label
$TitleLabel.Text = "SSH Remote Manager"
$TitleLabel.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 17)
$TitleLabel.AutoSize = $true
$TitleLabel.Location = New-Object System.Drawing.Point(293, 20)
$TitleLabel.ForeColor = $ColorText
$Form.Controls.Add($TitleLabel)

$HelpLabel = New-Object System.Windows.Forms.Label
$HelpLabel.Text = "Secure connection profiles | separate keys | no stored passwords"
$HelpLabel.AutoSize = $true
$HelpLabel.ForeColor = $ColorMuted
$HelpLabel.Location = New-Object System.Drawing.Point(296, 58)
$Form.Controls.Add($HelpLabel)

$ProfileHeading = New-Object System.Windows.Forms.Label
$ProfileHeading.Text = "Server profiles"
$ProfileHeading.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 14)
$ProfileHeading.AutoSize = $true
$ProfileHeading.Location = New-Object System.Drawing.Point(20, 22)
$ProfileHeading.ForeColor = $ColorText
$Form.Controls.Add($ProfileHeading)

$ProfileCountLabel = New-Object System.Windows.Forms.Label
$ProfileCountLabel.Text = "0 managed profile(s)"
$ProfileCountLabel.AutoSize = $true
$ProfileCountLabel.ForeColor = $ColorMuted
$ProfileCountLabel.Location = New-Object System.Drawing.Point(22, 55)
$Form.Controls.Add($ProfileCountLabel)

$ProfileList = New-Object System.Windows.Forms.ListBox
$ProfileList.DisplayMember = "Display"
$ProfileList.HorizontalScrollbar = $true
$ProfileList.Location = New-Object System.Drawing.Point(20, 82)
$ProfileList.Size = New-Object System.Drawing.Size(245, 478)
$ProfileList.BackColor = $ColorSidebar
$ProfileList.ForeColor = $ColorText
$ProfileList.BorderStyle = "FixedSingle"
$ProfileList.DrawMode = "OwnerDrawFixed"
$ProfileList.ItemHeight = 32
$Form.Controls.Add($ProfileList)

$NewProfileButton = New-Object System.Windows.Forms.Button
$NewProfileButton.Text = "New"
$NewProfileButton.Location = New-Object System.Drawing.Point(20, 572)
$NewProfileButton.Size = New-Object System.Drawing.Size(75, 38)
$Form.Controls.Add($NewProfileButton)

$ReloadProfilesButton = New-Object System.Windows.Forms.Button
$ReloadProfilesButton.Text = "Reload"
$ReloadProfilesButton.Location = New-Object System.Drawing.Point(101, 572)
$ReloadProfilesButton.Size = New-Object System.Drawing.Size(75, 38)
$Form.Controls.Add($ReloadProfilesButton)

$DeleteProfileButton = New-Object System.Windows.Forms.Button
$DeleteProfileButton.Text = "Remove"
$DeleteProfileButton.Location = New-Object System.Drawing.Point(182, 572)
$DeleteProfileButton.Size = New-Object System.Drawing.Size(83, 38)
$Form.Controls.Add($DeleteProfileButton)

$RevokeButton = New-Object System.Windows.Forms.Button
$RevokeButton.Text = "Copy server revoke command"
$RevokeButton.Location = New-Object System.Drawing.Point(20, 622)
$RevokeButton.Size = New-Object System.Drawing.Size(245, 38)
$Form.Controls.Add($RevokeButton)

$SidebarHelp = New-Object System.Windows.Forms.Label
$SidebarHelp.Text = "Remove profile, revoke server access, and delete local key are separate actions. Nothing here deletes a key automatically."
$SidebarHelp.MaximumSize = New-Object System.Drawing.Size(245, 50)
$SidebarHelp.AutoSize = $true
$SidebarHelp.ForeColor = $ColorWarning
$SidebarHelp.Location = New-Object System.Drawing.Point(20, 716)
$Form.Controls.Add($SidebarHelp)

$ImportHostButton = New-Object System.Windows.Forms.Button
$ImportHostButton.Text = "Import existing SSH Host"
$ImportHostButton.Location = New-Object System.Drawing.Point(20, 666)
$ImportHostButton.Size = New-Object System.Drawing.Size(245, 38)
$Form.Controls.Add($ImportHostButton)

$DeleteKeyButton = New-Object System.Windows.Forms.Button
$DeleteKeyButton.Text = "Delete local key pair..."
$DeleteKeyButton.Location = New-Object System.Drawing.Point(20, 778)
$DeleteKeyButton.Size = New-Object System.Drawing.Size(245, 38)
$Form.Controls.Add($DeleteKeyButton)

function Add-Field {
    param(
        [string]$Label,
        [string]$Value,
        [int]$Top,
        [int]$Width = 315,
        [int]$Left = 296
    )
    $labelControl = New-Object System.Windows.Forms.Label
    $labelControl.Text = $Label
    $labelControl.AutoSize = $true
    $labelControl.Location = New-Object System.Drawing.Point($Left, $Top)
    $labelControl.ForeColor = $ColorMuted
    $Form.Controls.Add($labelControl)

    $box = New-Object System.Windows.Forms.TextBox
    $box.Text = $Value
    $box.Location = New-Object System.Drawing.Point($Left, ($Top + 24))
    $box.Size = New-Object System.Drawing.Size($Width, 30)
    $box.BackColor = $ColorSurface
    $box.ForeColor = $ColorText
    $box.BorderStyle = "FixedSingle"
    $Form.Controls.Add($box)
    return $box
}

$AliasBox = Add-Field "Local alias" "keblm-remote" 92 170
$DisplayNameBox = Add-Field "Display name" "" 92 170 536
$HostBox = Add-Field "Server IP or domain" "" 158 714
$UserBox = Add-Field "SSH username (use a limited account)" "codex-keblm" 224 225
$PortBox = Add-Field "SSH port" "22" 224 100 610

$EnvironmentLabel = New-Object System.Windows.Forms.Label
$EnvironmentLabel.Text = "Environment"
$EnvironmentLabel.AutoSize = $true
$EnvironmentLabel.Location = New-Object System.Drawing.Point(780, 92)
$EnvironmentLabel.ForeColor = $ColorMuted
$Form.Controls.Add($EnvironmentLabel)

$EnvironmentBox = New-Object System.Windows.Forms.ComboBox
$EnvironmentBox.DropDownStyle = "DropDownList"
[void]$EnvironmentBox.Items.AddRange(@("development", "staging", "production"))
$EnvironmentBox.SelectedItem = "development"
$EnvironmentBox.Location = New-Object System.Drawing.Point(780, 116)
$EnvironmentBox.Size = New-Object System.Drawing.Size(175, 30)
$EnvironmentBox.BackColor = $ColorSurface
$EnvironmentBox.ForeColor = $ColorText
$Form.Controls.Add($EnvironmentBox)

$EnvironmentBadge = New-Object System.Windows.Forms.Label
$EnvironmentBadge.Text = "DEVELOPMENT"
$EnvironmentBadge.TextAlign = "MiddleCenter"
$EnvironmentBadge.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9)
$EnvironmentBadge.Location = New-Object System.Drawing.Point(965, 116)
$EnvironmentBadge.Size = New-Object System.Drawing.Size(125, 27)
$Form.Controls.Add($EnvironmentBadge)

$EnvironmentWarningLabel = New-Object System.Windows.Forms.Label
$EnvironmentWarningLabel.AutoSize = $true
$EnvironmentWarningLabel.MaximumSize = New-Object System.Drawing.Size(320, 38)
$EnvironmentWarningLabel.Location = New-Object System.Drawing.Point(770, 54)
$EnvironmentWarningLabel.ForeColor = $ColorMuted
$Form.Controls.Add($EnvironmentWarningLabel)

$CapabilitiesLabel = New-Object System.Windows.Forms.Label
$CapabilitiesLabel.Text = "Read-only capabilities"
$CapabilitiesLabel.AutoSize = $true
$CapabilitiesLabel.Location = New-Object System.Drawing.Point(296, 291)
$CapabilitiesLabel.ForeColor = $ColorMuted
$Form.Controls.Add($CapabilitiesLabel)

function Add-CapabilityCheck {
    param([string]$Text, [int]$Left)
    $check = New-Object System.Windows.Forms.CheckBox
    $check.Text = $Text
    $check.AutoSize = $true
    $check.Location = New-Object System.Drawing.Point($Left, 317)
    $check.ForeColor = $ColorText
    $check.BackColor = $ColorBackground
    $Form.Controls.Add($check)
    return $check
}
$ServerInfoCheck = Add-CapabilityCheck "Server info" 296
$SystemdCheck = Add-CapabilityCheck "systemd status" 420
$DockerCheck = Add-CapabilityCheck "Docker status" 560
$LogsCheck = Add-CapabilityCheck "Read logs" 695
$ServerInfoCheck.Checked = $true

$ServicesBox = Add-Field "Allowed services (comma-separated)" "" 350 285
$LogTargetsBox = Add-Field "Allowed logs (name=/absolute/path, one per line)" "" 350 340 676
$LogTargetsBox.Multiline = $true
$LogTargetsBox.Height = 54

function Add-PasteButton {
    param(
        [System.Windows.Forms.TextBox]$Target,
        [int]$Left,
        [int]$Top,
        [int]$Width = 70
    )
    $button = New-Object System.Windows.Forms.Button
    $button.Text = "Paste"
    $button.Location = New-Object System.Drawing.Point($Left, $Top)
    $button.Size = New-Object System.Drawing.Size($Width, 30)
    $button.Tag = $Target
    $button.Add_Click({
        param($sender, $eventArgs)
        try {
            if (-not [System.Windows.Forms.Clipboard]::ContainsText()) {
                throw "Clipboard does not contain text."
            }
            $value = [System.Windows.Forms.Clipboard]::GetText().Trim()
            if (-not $value) {
                throw "Clipboard text is empty."
            }
            $sender.Tag.Text = $value
            $sender.Tag.Focus()
            $sender.Tag.SelectionStart = $sender.Tag.TextLength
        } catch {
            Show-Message $_.Exception.Message "SSH Remote Manager Paste" ([System.Windows.Forms.MessageBoxIcon]::Warning)
        }
    })
    $Form.Controls.Add($button)
    return $button
}

$PasteAliasButton = Add-PasteButton $AliasBox 472 116 54
$PasteDisplayNameButton = Add-PasteButton $DisplayNameBox 712 116 54
$PasteHostButton = Add-PasteButton $HostBox 1018 182 72
$PasteUserButton = Add-PasteButton $UserBox 529 248 64
$PastePortButton = Add-PasteButton $PortBox 718 248 64
$PasteServicesButton = Add-PasteButton $ServicesBox 591 374
$PasteLogTargetsButton = Add-PasteButton $LogTargetsBox 1018 374 72

$GenerateButton = New-Object System.Windows.Forms.Button
$GenerateButton.Text = "1. Generate / show key"
$GenerateButton.Location = New-Object System.Drawing.Point(296, 446)
$GenerateButton.Size = New-Object System.Drawing.Size(165, 38)
$Form.Controls.Add($GenerateButton)

$ImportKeyButton = New-Object System.Windows.Forms.Button
$ImportKeyButton.Text = "Import key pair"
$ImportKeyButton.Location = New-Object System.Drawing.Point(472, 446)
$ImportKeyButton.Size = New-Object System.Drawing.Size(155, 38)
$Form.Controls.Add($ImportKeyButton)

$CopyKeyButton = New-Object System.Windows.Forms.Button
$CopyKeyButton.Text = "Copy public key"
$CopyKeyButton.Location = New-Object System.Drawing.Point(638, 446)
$CopyKeyButton.Size = New-Object System.Drawing.Size(145, 38)
$Form.Controls.Add($CopyKeyButton)

$CopyCommandButton = New-Object System.Windows.Forms.Button
$CopyCommandButton.Text = "Copy server install command"
$CopyCommandButton.Location = New-Object System.Drawing.Point(794, 446)
$CopyCommandButton.Size = New-Object System.Drawing.Size(296, 38)
$Form.Controls.Add($CopyCommandButton)

$KeyStatusLabel = New-Object System.Windows.Forms.Label
$KeyStatusLabel.Text = "Key not loaded yet"
$KeyStatusLabel.AutoSize = $true
$KeyStatusLabel.Location = New-Object System.Drawing.Point(296, 494)
$KeyStatusLabel.ForeColor = $ColorMuted
$Form.Controls.Add($KeyStatusLabel)

$PublicKeyBox = New-Object System.Windows.Forms.TextBox
$PublicKeyBox.Multiline = $true
$PublicKeyBox.ReadOnly = $true
$PublicKeyBox.ScrollBars = "Vertical"
$PublicKeyBox.Location = New-Object System.Drawing.Point(296, 521)
$PublicKeyBox.Size = New-Object System.Drawing.Size(794, 72)
$PublicKeyBox.BackColor = $ColorSurface
$PublicKeyBox.ForeColor = $ColorAccent
$PublicKeyBox.BorderStyle = "FixedSingle"
$PublicKeyBox.Font = New-Object System.Drawing.Font("Cascadia Mono", 9)
$Form.Controls.Add($PublicKeyBox)

$InstructionLabel = New-Object System.Windows.Forms.Label
$InstructionLabel.Text = "Open your provider's web terminal, sign in as the SSH user, and paste the install command once."
$InstructionLabel.AutoSize = $true
$InstructionLabel.ForeColor = $ColorMuted
$InstructionLabel.Location = New-Object System.Drawing.Point(296, 603)
$Form.Controls.Add($InstructionLabel)

$SaveButton = New-Object System.Windows.Forms.Button
$SaveButton.Text = "2. Save SSH profile"
$SaveButton.Location = New-Object System.Drawing.Point(296, 637)
$SaveButton.Size = New-Object System.Drawing.Size(205, 42)
$SaveButton.BackColor = $ColorAccent
$SaveButton.ForeColor = $ColorBackground
$SaveButton.FlatStyle = "Flat"
$Form.Controls.Add($SaveButton)

$TestButton = New-Object System.Windows.Forms.Button
$TestButton.Text = "3. Test connection"
$TestButton.Location = New-Object System.Drawing.Point(512, 637)
$TestButton.Size = New-Object System.Drawing.Size(185, 42)
$Form.Controls.Add($TestButton)

$OpenTerminalButton = New-Object System.Windows.Forms.Button
$OpenTerminalButton.Text = "Open SSH terminal"
$OpenTerminalButton.Location = New-Object System.Drawing.Point(708, 637)
$OpenTerminalButton.Size = New-Object System.Drawing.Size(180, 42)
$Form.Controls.Add($OpenTerminalButton)

$SavedStatusLabel = New-Object System.Windows.Forms.Label
$SavedStatusLabel.Text = ""
$SavedStatusLabel.AutoSize = $true
$SavedStatusLabel.Location = New-Object System.Drawing.Point(296, 719)
$Form.Controls.Add($SavedStatusLabel)

$LastTestedLabel = New-Object System.Windows.Forms.Label
$LastTestedLabel.Text = "Connection: not tested"
$LastTestedLabel.AutoSize = $true
$LastTestedLabel.Location = New-Object System.Drawing.Point(296, 691)
$LastTestedLabel.ForeColor = $ColorMuted
$Form.Controls.Add($LastTestedLabel)

$SecurityLabel = New-Object System.Windows.Forms.Label
$SecurityLabel.Text = "Security: never paste the private key or server password into chat. Revoke access by removing the matching public-key line from ~/.ssh/authorized_keys."
$SecurityLabel.MaximumSize = New-Object System.Drawing.Size(700, 50)
$SecurityLabel.AutoSize = $true
$SecurityLabel.ForeColor = $ColorWarning
$SecurityLabel.Location = New-Object System.Drawing.Point(296, 756)
$Form.Controls.Add($SecurityLabel)

$Divider = New-Object System.Windows.Forms.Panel
$Divider.Location = New-Object System.Drawing.Point(279, 0)
$Divider.Size = New-Object System.Drawing.Size(1, 870)
$Divider.BackColor = $ColorBorder
$Divider.Anchor = "Top,Bottom,Left"
$Form.Controls.Add($Divider)

function Set-DarkButton {
    param(
        [System.Windows.Forms.Button]$Button,
        [System.Drawing.Color]$BorderColor = $ColorBorder,
        [System.Drawing.Color]$TextColor = $ColorText,
        [System.Drawing.Color]$FillColor = $ColorSurface
    )
    $Button.FlatStyle = "Flat"
    $Button.FlatAppearance.BorderSize = 1
    $Button.FlatAppearance.BorderColor = $BorderColor
    $Button.FlatAppearance.MouseOverBackColor = $ColorSurfaceHover
    $Button.FlatAppearance.MouseDownBackColor = $ColorAccentDark
    $Button.BackColor = $FillColor
    $Button.ForeColor = $TextColor
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
}

foreach ($button in @(
    $NewProfileButton,
    $ReloadProfilesButton,
    $ImportHostButton,
    $GenerateButton,
    $ImportKeyButton,
    $CopyKeyButton,
    $CopyCommandButton,
    $TestButton,
    $OpenTerminalButton,
    $PasteAliasButton,
    $PasteDisplayNameButton,
    $PasteHostButton,
    $PasteUserButton,
    $PastePortButton,
    $PasteServicesButton,
    $PasteLogTargetsButton
)) {
    Set-DarkButton $button
}
Set-DarkButton $SaveButton $ColorAccent $ColorBackground $ColorAccent
Set-DarkButton $DeleteProfileButton $ColorDanger $ColorDanger $ColorSidebar
Set-DarkButton $RevokeButton $ColorWarning $ColorWarning $ColorSidebar
Set-DarkButton $DeleteKeyButton $ColorDanger $ColorDanger $ColorSidebar

$EnvironmentBox.Add_SelectedIndexChanged({ Update-EnvironmentBadge })
Update-EnvironmentBadge

$ProfileList.Add_DrawItem({
    param($sender, $eventArgs)
    if ($eventArgs.Index -lt 0) { return }
    $selected = ($eventArgs.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0
    $background = if ($selected) { $ColorAccentDark } else { $ColorSidebar }
    $foreground = if ($selected) { $ColorAccent } else { $ColorText }
    $backgroundBrush = New-Object System.Drawing.SolidBrush($background)
    $foregroundBrush = New-Object System.Drawing.SolidBrush($foreground)
    $accentBrush = New-Object System.Drawing.SolidBrush($ColorAccent)
    try {
        $eventArgs.Graphics.FillRectangle($backgroundBrush, $eventArgs.Bounds)
        $itemText = [string]$sender.Items[$eventArgs.Index].Display
        $textBounds = New-Object System.Drawing.RectangleF(
            ($eventArgs.Bounds.X + 10),
            ($eventArgs.Bounds.Y + 7),
            ($eventArgs.Bounds.Width - 15),
            ($eventArgs.Bounds.Height - 7)
        )
        $eventArgs.Graphics.DrawString($itemText, $sender.Font, $foregroundBrush, $textBounds)
        if ($selected) {
            $eventArgs.Graphics.FillRectangle($accentBrush, $eventArgs.Bounds.X, $eventArgs.Bounds.Y, 3, $eventArgs.Bounds.Height)
        }
    } finally {
        $backgroundBrush.Dispose()
        $foregroundBrush.Dispose()
        $accentBrush.Dispose()
    }
})

$Form.Add_Shown({
    $enabled = 1
    [void][DarkTitleBarNative]::DwmSetWindowAttribute($Form.Handle, 20, [ref]$enabled, 4)
})

$ProfileList.Add_SelectedIndexChanged({
    try {
        if ($ProfileList.SelectedIndex -ge 0) {
            Select-Profile $ProfileList.SelectedItem
        }
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$NewProfileButton.Add_Click({
    $ProfileList.ClearSelected()
    Clear-ProfileEditor
})

$ReloadProfilesButton.Add_Click({
    try {
        $previousAlias = $script:SelectedAlias
        Load-ProfileList
        $matched = $false
        for ($index = 0; $index -lt $ProfileList.Items.Count; $index++) {
            if ($ProfileList.Items[$index].Alias -eq $previousAlias) {
                $ProfileList.SelectedIndex = $index
                $matched = $true
                break
            }
        }
        if (-not $matched -and $ProfileList.Items.Count -gt 0) {
            $ProfileList.SelectedIndex = 0
        }
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$DeleteProfileButton.Add_Click({
    try {
        Delete-SelectedProfile
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$ImportHostButton.Add_Click({
    try { Show-ImportSshHostDialog } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Import Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$DeleteKeyButton.Add_Click({
    try { Delete-SelectedLocalKey } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$RevokeButton.Add_Click({
    try {
        if (-not $script:SelectedAlias) { throw "Select a managed profile first." }
        $answer = [System.Windows.Forms.MessageBox]::Show(
            $Form,
            "Copy a command that removes this profile's public key from the server?`n`nThis button does not connect to the server. Access changes only if you deliberately run the copied command on the intended server.",
            "Prepare server revocation",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $command = Get-RevokeCommand
        [System.Windows.Forms.Clipboard]::SetText($command)
        Show-Message "Revoke command copied. Run it on the selected server before deleting the local profile."
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$GenerateButton.Add_Click({
    try {
        Ensure-SshKey
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$ImportKeyButton.Add_Click({
    try {
        Import-OpenSshKeyPair
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Key Import Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$CopyKeyButton.Add_Click({
    try {
        Ensure-SshKey
        [System.Windows.Forms.Clipboard]::SetText($script:PublicKey)
        Show-Message "Public key copied. Paste only this public key into the server or hosting control panel."
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$CopyCommandButton.Add_Click({
    try {
        $command = Get-InstallCommand
        [System.Windows.Forms.Clipboard]::SetText($command)
        Show-Message "Server install command copied. Paste it into a terminal already logged in as the selected SSH user."
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$SaveButton.Add_Click({
    try {
        Save-SshProfile
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$TestButton.Add_Click({
    try {
        $values = Get-ValidatedValues
        $targetAlias = Get-ConnectionTargetAlias $values
        Save-SshProfile
        if ($values.Environment -eq "production") {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                $Form,
                "Test the PRODUCTION profile '$($values.Alias)' now?`n`nThe test uses BatchMode and a fixed read-only printf command.",
                "Confirm production connection test",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }
        $output = & ssh.exe -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8 -o ConnectionAttempts=1 -- $targetAlias true 2>&1
        $outputText = ($output | Out-String)
        if ($outputText.Length -gt 4096) { $outputText = $outputText.Substring(0, 4096) + "`n[output truncated]" }
        if ($LASTEXITCODE -eq 0) {
            $testedUtc = [DateTime]::UtcNow.ToString("o")
            Save-SshProfile -LastTestedUtc $testedUtc
            $LastTestedLabel.Text = "Connection: last tested $testedUtc"
            Show-Message "Connection successful.`n`nYou can now tell Codex: ssh $($values.Alias) is ready."
        } else {
            throw "Connection failed.`n`n$outputText`n`nInstall the public key on the server, then try again."
        }
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Test Failed" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$OpenTerminalButton.Add_Click({
    try {
        $values = Get-ValidatedValues
        $targetAlias = Get-ConnectionTargetAlias $values
        if ($values.Environment -eq "production") {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                $Form,
                "Open an interactive SSH terminal to PRODUCTION profile '$($values.Alias)'?",
                "Confirm production terminal",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }
        Start-Process -FilePath "ssh.exe" -ArgumentList @($targetAlias)
    } catch {
        Show-Message $_.Exception.Message "SSH Remote Manager Error" ([System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

if ($script:ProfileStoreAvailable -and $null -ne (Get-Command Import-SrmLegacyProfiles -ErrorAction SilentlyContinue)) {
    try {
        # This imports only legacy managed-marker blocks. Unmanaged Host/Include entries remain untouched.
        [void](Import-SrmLegacyProfiles)
    } catch {
        Show-Message "Legacy profile migration was skipped: $($_.Exception.Message)" "SSH Remote Manager Migration" ([System.Windows.Forms.MessageBoxIcon]::Warning)
    }
}
if ($script:ProfileStoreWarning) {
    Show-Message $script:ProfileStoreWarning "SSH Remote Manager Compatibility Mode" ([System.Windows.Forms.MessageBoxIcon]::Warning)
}
[void](Load-ProfileList)
if ($ProfileList.Items.Count -gt 0) {
    $ProfileList.SelectedIndex = 0
} else {
    Clear-ProfileEditor
}

[void]$Form.ShowDialog()
