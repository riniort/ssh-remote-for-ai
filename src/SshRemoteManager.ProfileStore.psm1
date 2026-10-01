Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SchemaVersion = 1
$script:MarkerPrefixes = @('SSH REMOTE MANAGER', 'KEBLM MANAGED SSH')

function Get-SrmDefaultSshRoot {
    if (-not $env:USERPROFILE) { throw 'USERPROFILE is not set.' }
    Join-Path $env:USERPROFILE '.ssh'
}

function Get-SrmDefaultStorePath {
    param([string]$SshRoot = (Get-SrmDefaultSshRoot))
    Join-Path (Join-Path $SshRoot 'ssh-remote-manager') 'profiles.json'
}

function Get-SrmDefaultConfigPath {
    param([string]$SshRoot = (Get-SrmDefaultSshRoot))
    Join-Path $SshRoot 'config'
}

function ConvertTo-SrmFullPath {
    param([Parameter(Mandatory)][string]$Path)
    [System.IO.Path]::GetFullPath($Path)
}

function Test-SrmPathWithinRoot {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $fullPath = (ConvertTo-SrmFullPath $Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $fullRoot = (ConvertTo-SrmFullPath $Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $comparison = if ($env:OS -eq 'Windows_NT') { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    $fullPath.Equals($fullRoot, $comparison) -or $fullPath.StartsWith($fullRoot + [System.IO.Path]::DirectorySeparatorChar, $comparison)
}

function Test-SrmPathHasReparsePoint {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $fullPath = ConvertTo-SrmFullPath $Path
    $fullRoot = (ConvertTo-SrmFullPath $Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $comparison = if ($env:OS -eq 'Windows_NT') { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    $current = $fullPath
    while (-not [string]::IsNullOrWhiteSpace($current) -and -not $current.Equals($fullRoot, $comparison)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }
        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, $comparison)) { break }
        $current = $parent
    }
    return $false
}

function Invoke-SrmWithFileLock {
    param(
        [Parameter(Mandatory)][string]$LockPath,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$TimeoutMilliseconds = 5000
    )
    $directory = Split-Path -Parent $LockPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $stream = $null
    while ($null -eq $stream) {
        try {
            $stream = [System.IO.File]::Open($LockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        } catch [System.IO.IOException] {
            if ($watch.ElapsedMilliseconds -ge $TimeoutMilliseconds) { throw "Timed out waiting for file lock '$LockPath'." }
            Start-Sleep -Milliseconds 50
        }
    }
    try { & $ScriptBlock } finally { $stream.Dispose() }
}

function Write-SrmAtomicText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content,
        [switch]$Backup
    )
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    $tempPath = Join-Path $directory ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($tempPath, $Content, $encoding)
        if (Test-Path -LiteralPath $Path) {
            if ($Backup) {
                $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
                $backupPath = "$Path.$stamp.bak"
                [System.IO.File]::Replace($tempPath, $Path, $backupPath, $true)
            } else {
                # Windows PowerShell binds $null to an empty string for this overload.
                # Use a same-directory throwaway backup to keep File.Replace atomic.
                $throwawayBackup = Join-Path $directory ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.rollback')
                try { [System.IO.File]::Replace($tempPath, $Path, $throwawayBackup, $true) }
                finally { if (Test-Path -LiteralPath $throwawayBackup) { Remove-Item -LiteralPath $throwawayBackup -Force } }
            }
        } else {
            [System.IO.File]::Move($tempPath, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
    }
}

function New-SrmEmptyStore {
    [pscustomobject]@{ schemaVersion = $script:SchemaVersion; profiles = @() }
}

function Get-SrmProfileStore {
    [CmdletBinding()]
    param(
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot)
    )
    if (-not (Test-Path -LiteralPath $StorePath)) { return (New-SrmEmptyStore) }
    $raw = [System.IO.File]::ReadAllText((ConvertTo-SrmFullPath $StorePath))
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "Profile store '$StorePath' is empty." }
    try { $store = $raw | ConvertFrom-Json } catch { throw "Profile store '$StorePath' is not valid JSON: $($_.Exception.Message)" }
    if ($store.schemaVersion -ne $script:SchemaVersion) { throw "Unsupported profile schema version '$($store.schemaVersion)'." }
    if ($null -eq $store.profiles) { throw "Profile store '$StorePath' has no profiles array." }
    $aliases = @{}
    foreach ($profile in @($store.profiles)) {
        Test-SrmProfile -Profile $profile -SshRoot $SshRoot -AllowMissingKey | Out-Null
        $key = ([string]$profile.alias).ToLowerInvariant()
        if ($aliases.ContainsKey($key)) { throw "Duplicate profile alias '$($profile.alias)' in profile store." }
        $aliases[$key] = $true
    }
    $store
}

function Get-SrmProfiles {
    [CmdletBinding()]
    param(
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot)
    )
    @((Get-SrmProfileStore -StorePath $StorePath -SshRoot $SshRoot).profiles | Sort-Object alias)
}

function Get-SrmProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Alias,
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot)
    )
    $matches = @((Get-SrmProfileStore -StorePath $StorePath -SshRoot $SshRoot).profiles | Where-Object { $_.alias -ieq $Alias })
    if ($matches.Count -eq 0) { return $null }
    $matches[0]
}

function Get-SrmConnectionMode {
    param([Parameter(Mandatory)]$Profile)
    $property = $Profile.PSObject.Properties['connectionMode']
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) { return 'managed' }
    [string]$property.Value
}

function Test-SrmProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [string]$SshRoot = (Get-SrmDefaultSshRoot),
        [switch]$AllowMissingKey
    )
    foreach ($property in @($Profile.PSObject.Properties.Name)) {
        if ($property -match '(?i)(password|passphrase|secret|token|privatekey|connectionstring)') {
            throw "Secret-bearing property '$property' is not allowed in a profile."
        }
    }
    if ([string]$Profile.alias -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw 'Alias must be 1-64 letters, numbers, dots, underscores, or hyphens and must start with a letter or number.' }
    if ([string]::IsNullOrWhiteSpace([string]$Profile.host) -or [string]$Profile.host -notmatch '^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$' -or [string]$Profile.host -eq '--') { throw "Invalid host for profile '$($Profile.alias)'." }
    if ([string]$Profile.user -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*[$]?$') { throw "Invalid SSH user for profile '$($Profile.alias)'." }
    $port = 0
    if (-not [int]::TryParse([string]$Profile.port, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw "Invalid port for profile '$($Profile.alias)'." }
    if ([string]$Profile.environment -notin @('development', 'staging', 'production')) { throw "Invalid environment for profile '$($Profile.alias)'." }
    $connectionMode = Get-SrmConnectionMode -Profile $Profile
    if ($connectionMode -notin @('managed', 'ssh-config-alias')) { throw "Invalid connectionMode for profile '$($Profile.alias)'." }
    $identityProperty = $Profile.PSObject.Properties['identityFile']
    $identityFile = if ($null -eq $identityProperty) { '' } else { [string]$identityProperty.Value }
    if ($connectionMode -eq 'managed' -and [string]::IsNullOrWhiteSpace($identityFile)) { throw "Profile '$($Profile.alias)' has no identityFile." }
    if (-not [string]::IsNullOrWhiteSpace($identityFile)) {
        if (-not (Test-SrmPathWithinRoot -Path $identityFile -Root $SshRoot)) { throw "identityFile for profile '$($Profile.alias)' must be under the SSH directory." }
        if (Test-SrmPathHasReparsePoint -Path $identityFile -Root $SshRoot) { throw "identityFile for profile '$($Profile.alias)' cannot traverse a symlink, junction, or reparse point." }
        if (-not $AllowMissingKey -and -not (Test-Path -LiteralPath $identityFile -PathType Leaf)) { throw "Private key is missing for profile '$($Profile.alias)'." }
    }
    if ($connectionMode -eq 'ssh-config-alias') {
        $aliasProperty = $Profile.PSObject.Properties['sshConfigAlias']
        $sshConfigAlias = if ($null -eq $aliasProperty) { '' } else { [string]$aliasProperty.Value }
        if ($sshConfigAlias -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw "Invalid sshConfigAlias for profile '$($Profile.alias)'." }
    }
    foreach ($service in @($Profile.allowlists.services)) {
        if ([string]$service -notmatch '^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$') { throw "Invalid allowed service '$service'." }
    }
    foreach ($target in @($Profile.allowlists.logTargets)) {
        if ([string]$target.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw 'Invalid log target name.' }
        $path = [string]$target.path
        if ($path -notmatch '^/[A-Za-z0-9_./-]+$' -or $path -match '(^|/)\.\.(/|$)') { throw "Invalid log target path '$path'." }
    }
    $true
}

function ConvertTo-SrmCanonicalProfile {
    param([Parameter(Mandatory)]$Profile)
    $connectionMode = Get-SrmConnectionMode -Profile $Profile
    $identityProperty = $Profile.PSObject.Properties['identityFile']
    $sshAliasProperty = $Profile.PSObject.Properties['sshConfigAlias']
    [pscustomobject]@{
        alias = [string]$Profile.alias
        displayName = [string]$Profile.displayName
        host = [string]$Profile.host
        port = [int]$Profile.port
        user = [string]$Profile.user
        environment = [string]$Profile.environment
        connectionMode = $connectionMode
        sshConfigAlias = if ($connectionMode -eq 'ssh-config-alias') { [string]$sshAliasProperty.Value } else { $null }
        identityFile = if ($null -eq $identityProperty) { '' } else { [string]$identityProperty.Value }
        capabilities = [pscustomobject]@{
            serverInfo = [bool]$Profile.capabilities.serverInfo
            systemd = [bool]$Profile.capabilities.systemd
            docker = [bool]$Profile.capabilities.docker
            logs = [bool]$Profile.capabilities.logs
        }
        allowlists = [pscustomobject]@{
            services = @($Profile.allowlists.services | ForEach-Object { [string]$_ })
            logTargets = @($Profile.allowlists.logTargets | ForEach-Object { [pscustomobject]@{ name = [string]$_.name; path = [string]$_.path } })
        }
        lastTestedUtc = if ($null -eq $Profile.lastTestedUtc) { $null } else { [string]$Profile.lastTestedUtc }
    }
}

function ConvertTo-SrmStoreJson {
    param([Parameter(Mandatory)]$Store)
    ($Store | ConvertTo-Json -Depth 8) + "`n"
}

function Save-SrmStoreInternal {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$StorePath)
    Write-SrmAtomicText -Path $StorePath -Content (ConvertTo-SrmStoreJson $Store)
}

function Remove-SrmManagedBlocks {
    param([AllowEmptyString()][string]$Content)
    $result = $Content
    foreach ($prefix in $script:MarkerPrefixes) {
        $escaped = [regex]::Escape($prefix)
        $pattern = "(?ms)^# BEGIN ${escaped}: (?<alias>[^\r\n]+)\r?\n.*?^# END ${escaped}: \k<alias>[ \t]*(?:\r?\n)?"
        $result = [regex]::Replace($result, $pattern, '')
    }
    $result
}

function Get-SrmUnmanagedHostAliases {
    param([AllowEmptyString()][string]$Content)
    $aliases = @()
    foreach ($match in [regex]::Matches($Content, '(?mi)^\s*Host\s+(?<hosts>[^#\r\n]+)')) {
        foreach ($hostName in ($match.Groups['hosts'].Value -split '\s+')) {
            if ($hostName -and $hostName -notmatch '[*?!]') { $aliases += $hostName }
        }
    }
    @($aliases)
}

function ConvertTo-SrmManagedBlock {
    param([Parameter(Mandatory)]$Profile)
    $identity = ([string]$Profile.identityFile).Replace('\', '/')
    @(
        "# BEGIN SSH REMOTE MANAGER: $($Profile.alias)",
        "Host $($Profile.alias)",
        "    HostName $($Profile.host)",
        "    User $($Profile.user)",
        "    Port $($Profile.port)",
        "    IdentityFile $identity",
        '    IdentitiesOnly yes',
        "# END SSH REMOTE MANAGER: $($Profile.alias)"
    ) -join "`r`n"
}

function Sync-SrmSshConfig {
    [CmdletBinding()]
    param(
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshConfigPath = (Get-SrmDefaultConfigPath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot),
        [int]$LockTimeoutMilliseconds = 5000
    )
    $store = Get-SrmProfileStore -StorePath $StorePath -SshRoot $SshRoot
    foreach ($profile in @($store.profiles)) { Test-SrmProfile -Profile $profile -SshRoot $SshRoot -AllowMissingKey | Out-Null }
    Invoke-SrmWithFileLock -LockPath "$SshConfigPath.lock" -TimeoutMilliseconds $LockTimeoutMilliseconds -ScriptBlock {
        $existing = if (Test-Path -LiteralPath $SshConfigPath) { [System.IO.File]::ReadAllText((ConvertTo-SrmFullPath $SshConfigPath)) } else { '' }
        $unmanaged = Remove-SrmManagedBlocks -Content $existing
        $hadManagedBlocks = $unmanaged -cne $existing
        $unmanagedAliases = @(Get-SrmUnmanagedHostAliases -Content $unmanaged)
        foreach ($profile in @($store.profiles)) {
            if ((Get-SrmConnectionMode -Profile $profile) -eq 'managed' -and @($unmanagedAliases | Where-Object { $_ -ieq $profile.alias }).Count -gt 0) { throw "SSH config contains unmanaged Host '$($profile.alias)'." }
        }
        $base = $unmanaged.TrimEnd("`r", "`n")
        $blocks = @($store.profiles | Where-Object { (Get-SrmConnectionMode -Profile $_) -eq 'managed' } | Sort-Object alias | ForEach-Object { ConvertTo-SrmManagedBlock -Profile $_ })
        $newContent = if (-not $hadManagedBlocks -and $blocks.Count -eq 0) { $existing } elseif ($base -and $blocks.Count) { $base + "`r`n`r`n" + ($blocks -join "`r`n`r`n") + "`r`n" } elseif ($blocks.Count) { ($blocks -join "`r`n`r`n") + "`r`n" } elseif ($base) { $base + "`r`n" } else { '' }
        if ($newContent -cne $existing) { Write-SrmAtomicText -Path $SshConfigPath -Content $newContent -Backup:([bool](Test-Path -LiteralPath $SshConfigPath)) }
    }
}

function Save-SrmProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Profile,
        [string]$OriginalAlias,
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshConfigPath = (Get-SrmDefaultConfigPath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot)
    )
    Test-SrmProfile -Profile $Profile -SshRoot $SshRoot -AllowMissingKey | Out-Null
    $canonicalProfile = ConvertTo-SrmCanonicalProfile -Profile $Profile
    Invoke-SrmWithFileLock -LockPath "$StorePath.lock" -ScriptBlock {
        $storeExisted = Test-Path -LiteralPath $StorePath
        $oldStoreText = if ($storeExisted) { [System.IO.File]::ReadAllText((ConvertTo-SrmFullPath $StorePath)) } else { $null }
        $store = Get-SrmProfileStore -StorePath $StorePath -SshRoot $SshRoot
        $lookup = if ($OriginalAlias) { $OriginalAlias } else { [string]$Profile.alias }
        $existing = @($store.profiles | Where-Object { $_.alias -ieq $lookup })
        $collision = @($store.profiles | Where-Object { $_.alias -ieq $canonicalProfile.alias -and $_.alias -ine $lookup })
        if ($collision.Count) { throw "Profile alias '$($canonicalProfile.alias)' already exists." }
        if ($OriginalAlias -and $existing.Count -eq 0) { throw "Profile '$OriginalAlias' does not exist." }
        $profiles = @($store.profiles | Where-Object { $_.alias -ine $lookup }) + @($canonicalProfile)
        $newStore = [pscustomobject]@{ schemaVersion = $script:SchemaVersion; profiles = @($profiles | Sort-Object alias) }
        Save-SrmStoreInternal -Store $newStore -StorePath $StorePath
        try {
            Sync-SrmSshConfig -StorePath $StorePath -SshConfigPath $SshConfigPath -SshRoot $SshRoot
        } catch {
            if ($storeExisted) { Write-SrmAtomicText -Path $StorePath -Content $oldStoreText } elseif (Test-Path -LiteralPath $StorePath) { Remove-Item -LiteralPath $StorePath -Force }
            throw "Profile save was rolled back because SSH config synchronization failed: $($_.Exception.Message)"
        }
    }
    Get-SrmProfile -Alias $canonicalProfile.alias -StorePath $StorePath -SshRoot $SshRoot
}

function Remove-SrmProfile {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][string]$Alias,
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshConfigPath = (Get-SrmDefaultConfigPath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot)
    )
    if (-not $PSCmdlet.ShouldProcess($Alias, 'Remove local profile (SSH keys are preserved)')) { return }
    Invoke-SrmWithFileLock -LockPath "$StorePath.lock" -ScriptBlock {
        $oldStoreText = [System.IO.File]::ReadAllText((ConvertTo-SrmFullPath $StorePath))
        $store = Get-SrmProfileStore -StorePath $StorePath -SshRoot $SshRoot
        if (@($store.profiles | Where-Object { $_.alias -ieq $Alias }).Count -eq 0) { throw "Profile '$Alias' does not exist." }
        $newStore = [pscustomobject]@{ schemaVersion = $script:SchemaVersion; profiles = @($store.profiles | Where-Object { $_.alias -ine $Alias }) }
        Save-SrmStoreInternal -Store $newStore -StorePath $StorePath
        try {
            Sync-SrmSshConfig -StorePath $StorePath -SshConfigPath $SshConfigPath -SshRoot $SshRoot
        } catch {
            Write-SrmAtomicText -Path $StorePath -Content $oldStoreText
            throw "Profile removal was rolled back because SSH config synchronization failed: $($_.Exception.Message)"
        }
    }
}

function Import-SrmLegacyProfiles {
    [CmdletBinding()]
    param(
        [string]$StorePath = (Get-SrmDefaultStorePath),
        [string]$SshConfigPath = (Get-SrmDefaultConfigPath),
        [string]$SshRoot = (Get-SrmDefaultSshRoot)
    )
    if (-not (Test-Path -LiteralPath $SshConfigPath)) { return @() }
    $content = [System.IO.File]::ReadAllText((ConvertTo-SrmFullPath $SshConfigPath))
    $imported = @()
    $store = Get-SrmProfileStore -StorePath $StorePath -SshRoot $SshRoot
    $profiles = @($store.profiles)
    foreach ($prefix in $script:MarkerPrefixes) {
        $escaped = [regex]::Escape($prefix)
        $pattern = "(?ms)^# BEGIN ${escaped}: (?<alias>[^\r\n]+)\r?\n(?<body>.*?)^# END ${escaped}: \k<alias>[ \t]*(?:\r?\n)?"
        foreach ($match in [regex]::Matches($content, $pattern)) {
            $alias = $match.Groups['alias'].Value.Trim()
            if (@($profiles | Where-Object { $_.alias -ieq $alias }).Count) { continue }
            $body = $match.Groups['body'].Value
            $getValue = { param($directive) $m = [regex]::Match($body, "(?mi)^\s*$directive\s+(?<value>.+?)\s*$"); if ($m.Success) { $m.Groups['value'].Value } else { '' } }
            $hostName = & $getValue 'HostName'
            $user = & $getValue 'User'
            $portText = & $getValue 'Port'; if (-not $portText) { $portText = '22' }
            $identity = (& $getValue 'IdentityFile').Trim('"').Replace('/', [System.IO.Path]::DirectorySeparatorChar)
            if (-not [System.IO.Path]::IsPathRooted($identity)) { $identity = Join-Path $SshRoot $identity }
            $profile = [pscustomobject]@{
                alias = $alias; displayName = $alias; host = $hostName; port = [int]$portText; user = $user
                environment = 'development'; connectionMode = 'managed'; sshConfigAlias = $null; identityFile = $identity
                capabilities = [pscustomobject]@{ serverInfo = $true; systemd = $false; docker = $false; logs = $false }
                allowlists = [pscustomobject]@{ services = @(); logTargets = @() }
                lastTestedUtc = $null
            }
            Test-SrmProfile -Profile $profile -SshRoot $SshRoot -AllowMissingKey | Out-Null
            $profiles += $profile; $imported += $profile
        }
    }
    if ($imported.Count) {
        $newStore = [pscustomobject]@{ schemaVersion = $script:SchemaVersion; profiles = @($profiles | Sort-Object alias) }
        Invoke-SrmWithFileLock -LockPath "$StorePath.lock" -ScriptBlock { Save-SrmStoreInternal -Store $newStore -StorePath $StorePath }
        Sync-SrmSshConfig -StorePath $StorePath -SshConfigPath $SshConfigPath -SshRoot $SshRoot
    }
    @($imported)
}

Export-ModuleMember -Function Get-SrmProfileStore, Get-SrmProfiles, Get-SrmProfile, Test-SrmProfile, Save-SrmProfile, Remove-SrmProfile, Sync-SrmSshConfig, Import-SrmLegacyProfiles
