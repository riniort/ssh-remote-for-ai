$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\SshRemoteManager.ProfileStore.psm1'
Import-Module $modulePath -Force

function Assert-Throws {
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock)
    $threw = $false
    try { & $ScriptBlock | Out-Null } catch { $threw = $true }
    if (-not $threw) { throw 'Expected the expression to throw an exception.' }
}

Describe 'SSH Remote Manager profile store' {
    BeforeEach {
        $script:testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('srm-profile-tests-' + [guid]::NewGuid().ToString('N'))
        $script:sshRoot = Join-Path $script:testRoot '.ssh'
        $script:storePath = Join-Path $script:sshRoot 'ssh-remote-manager\profiles.json'
        $script:configPath = Join-Path $script:sshRoot 'config'
        New-Item -ItemType Directory -Path $script:sshRoot -Force | Out-Null
    }

    AfterEach {
        if (Test-Path -LiteralPath $script:testRoot) { Remove-Item -LiteralPath $script:testRoot -Recurse -Force }
    }

    function New-TestProfile {
        param([string]$Alias = 'dev-one', [string]$KeyName = 'id_dev_one', [string]$Environment = 'development')
        $keyPath = Join-Path $script:sshRoot $KeyName
        Set-Content -LiteralPath $keyPath -Value 'test placeholder; never a real key' -Encoding Ascii
        [pscustomobject]@{
            alias = $Alias
            displayName = "Profile $Alias"
            host = "$Alias.example.test"
            port = 22
            user = 'deploy'
            environment = $Environment
            identityFile = $keyPath
            capabilities = [pscustomobject]@{ serverInfo = $true; systemd = $true; docker = $false; logs = $true }
            allowlists = [pscustomobject]@{
                services = @('web.service')
                logTargets = @([pscustomobject]@{ name = 'web'; path = '/var/log/web/app.log' })
            }
            lastTestedUtc = $null
        }
    }

    It 'creates, reads, updates, and removes a secretless profile' {
        $profile = New-TestProfile
        Save-SrmProfile -Profile $profile -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        (Get-SrmProfile -Alias 'DEV-ONE' -StorePath $script:storePath -SshRoot $script:sshRoot).displayName | Should Be 'Profile dev-one'
        ([System.IO.File]::ReadAllText($script:storePath)) | Should Not Match 'test placeholder'

        $profile.displayName = 'Updated profile'
        Save-SrmProfile -Profile $profile -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        @(Get-SrmProfiles -StorePath $script:storePath -SshRoot $script:sshRoot).Count | Should Be 1
        (Get-SrmProfile -Alias 'dev-one' -StorePath $script:storePath -SshRoot $script:sshRoot).displayName | Should Be 'Updated profile'

        Remove-SrmProfile -Alias 'dev-one' -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot -Confirm:$false
        @(Get-SrmProfiles -StorePath $script:storePath -SshRoot $script:sshRoot).Count | Should Be 0
    }

    It 'rejects duplicate aliases case-insensitively' {
        Save-SrmProfile -Profile (New-TestProfile -Alias 'alpha' -KeyName 'id_alpha') -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        Assert-Throws { Save-SrmProfile -Profile (New-TestProfile -Alias 'ALPHA' -KeyName 'id_other') -OriginalAlias 'missing' -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot }
        @(Get-SrmProfiles -StorePath $script:storePath -SshRoot $script:sshRoot).Count | Should Be 1
    }

    It 'renames a profile without moving or deleting its key' {
        $profile = New-TestProfile -Alias 'before' -KeyName 'id_stable'
        $keyPath = $profile.identityFile
        Save-SrmProfile -Profile $profile -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        $profile.alias = 'after'
        $profile.displayName = 'After'
        Save-SrmProfile -Profile $profile -OriginalAlias 'before' -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null

        (Test-Path -LiteralPath $keyPath) | Should Be $true
        (Get-SrmProfile -Alias 'before' -StorePath $script:storePath -SshRoot $script:sshRoot) | Should BeNullOrEmpty
        (Get-SrmProfile -Alias 'after' -StorePath $script:storePath -SshRoot $script:sshRoot).identityFile | Should Be $keyPath
        (Get-Content -LiteralPath $script:configPath -Raw) | Should Not Match 'Host before'
    }

    It 'keeps keys isolated and never deletes a key when deleting a profile' {
        $one = New-TestProfile -Alias 'one' -KeyName 'id_one'
        $two = New-TestProfile -Alias 'two' -KeyName 'id_two'
        Save-SrmProfile -Profile $one -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        Save-SrmProfile -Profile $two -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        Remove-SrmProfile -Alias 'one' -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot -Confirm:$false

        (Test-Path -LiteralPath $one.identityFile) | Should Be $true
        (Test-Path -LiteralPath $two.identityFile) | Should Be $true
        (Get-SrmProfile -Alias 'two' -StorePath $script:storePath -SshRoot $script:sshRoot).identityFile | Should Be $two.identityFile
    }

    It 'preserves unmanaged config and creates a backup before rewrite' {
        $unmanaged = "# personal comment`r`nHost personal`r`n    HostName personal.example.test`r`n"
        [System.IO.File]::WriteAllText($script:configPath, $unmanaged)
        Save-SrmProfile -Profile (New-TestProfile) -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null

        $result = Get-Content -LiteralPath $script:configPath -Raw
        $result | Should Match ([regex]::Escape($unmanaged.TrimEnd()))
        $result | Should Match '# BEGIN SSH REMOTE MANAGER: dev-one'
        @(Get-ChildItem -LiteralPath $script:sshRoot -Filter 'config.*.bak').Count | Should Be 1
        @(Get-ChildItem -LiteralPath $script:sshRoot -Filter '.config.*.tmp').Count | Should Be 0
    }

    It 'refuses to overwrite an unmanaged Host alias' {
        Set-Content -LiteralPath $script:configPath -Value "Host dev-one`n    HostName elsewhere.example" -Encoding Ascii
        Assert-Throws { Save-SrmProfile -Profile (New-TestProfile) -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot }
        (Test-Path -LiteralPath $script:storePath) | Should Be $false
        (Get-Content -LiteralPath $script:configPath -Raw) | Should Match 'elsewhere.example'
    }

    It 'migrates both legacy KEBLM and current neutral markers without changing keys' {
        $oldKey = Join-Path $script:sshRoot 'id_old'
        $newKey = Join-Path $script:sshRoot 'id_neutral'
        Set-Content -LiteralPath $oldKey -Value old -Encoding Ascii
        Set-Content -LiteralPath $newKey -Value neutral -Encoding Ascii
        $config = @"
# leave this alone
Host outside
    HostName outside.example

# BEGIN KEBLM MANAGED SSH: legacy
Host legacy
    HostName legacy.example.test
    User deploy
    Port 2201
    IdentityFile $($oldKey.Replace('\','/'))
# END KEBLM MANAGED SSH: legacy

# BEGIN SSH REMOTE MANAGER: neutral
Host neutral
    HostName neutral.example.test
    User operator
    IdentityFile $($newKey.Replace('\','/'))
# END SSH REMOTE MANAGER: neutral
"@
        [System.IO.File]::WriteAllText($script:configPath, $config)
        $migrated = @(Import-SrmLegacyProfiles -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot)

        $migrated.Count | Should Be 2
        @(Get-SrmProfiles -StorePath $script:storePath -SshRoot $script:sshRoot).Count | Should Be 2
        (Get-SrmProfile -Alias legacy -StorePath $script:storePath -SshRoot $script:sshRoot).port | Should Be 2201
        (Test-Path -LiteralPath $oldKey) | Should Be $true
        $rewritten = Get-Content -LiteralPath $script:configPath -Raw
        $rewritten | Should Match '# leave this alone'
        $rewritten | Should Not Match 'BEGIN KEBLM'
        ([regex]::Matches($rewritten, '# BEGIN SSH REMOTE MANAGER:')).Count | Should Be 2
    }

    It 'rejects malicious fields and keys outside the SSH root' {
        $badAlias = New-TestProfile; $badAlias.alias = '-oProxyCommand=calc'
        Assert-Throws { Test-SrmProfile -Profile $badAlias -SshRoot $script:sshRoot -AllowMissingKey }
        $badHost = New-TestProfile; $badHost.host = 'host;whoami'
        Assert-Throws { Test-SrmProfile -Profile $badHost -SshRoot $script:sshRoot -AllowMissingKey }
        $badUser = New-TestProfile; $badUser.user = 'root -o ProxyCommand=x'
        Assert-Throws { Test-SrmProfile -Profile $badUser -SshRoot $script:sshRoot -AllowMissingKey }
        $badService = New-TestProfile; $badService.allowlists.services = @('web; reboot')
        Assert-Throws { Test-SrmProfile -Profile $badService -SshRoot $script:sshRoot -AllowMissingKey }
        $badPath = New-TestProfile; $badPath.allowlists.logTargets = @([pscustomobject]@{ name='bad'; path='/var/log/../secret' })
        Assert-Throws { Test-SrmProfile -Profile $badPath -SshRoot $script:sshRoot -AllowMissingKey }
        $outside = New-TestProfile; $outside.identityFile = Join-Path $script:testRoot 'outside_key'
        Assert-Throws { Test-SrmProfile -Profile $outside -SshRoot $script:sshRoot -AllowMissingKey }
    }

    It 'rejects a key path that escapes through a junction' {
        $outsideDirectory = Join-Path $script:testRoot 'outside-keys'
        New-Item -ItemType Directory -Path $outsideDirectory | Out-Null
        Set-Content -LiteralPath (Join-Path $outsideDirectory 'id_jump') -Value 'not a real key' -Encoding Ascii
        $junction = Join-Path $script:sshRoot 'linked-keys'
        New-Item -ItemType Junction -Path $junction -Target $outsideDirectory | Out-Null
        $profile = New-TestProfile
        $profile.identityFile = Join-Path $junction 'id_jump'

        Assert-Throws { Test-SrmProfile -Profile $profile -SshRoot $script:sshRoot -AllowMissingKey }
    }

    It 'requires a supported environment and tolerates a missing key only when requested' {
        $profile = New-TestProfile -Environment production
        Remove-Item -LiteralPath $profile.identityFile
        Assert-Throws { Test-SrmProfile -Profile $profile -SshRoot $script:sshRoot }
        (Test-SrmProfile -Profile $profile -SshRoot $script:sshRoot -AllowMissingKey) | Should Be $true
        $profile.environment = 'prod'
        Assert-Throws { Test-SrmProfile -Profile $profile -SshRoot $script:sshRoot -AllowMissingKey }
    }

    It 'rejects secret-bearing profile properties' {
        $profile = New-TestProfile
        $profile | Add-Member -NotePropertyName password -NotePropertyValue 'must-not-persist'
        Assert-Throws { Save-SrmProfile -Profile $profile -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot }
        (Test-Path -LiteralPath $script:storePath) | Should Be $false
    }

    It 'times out safely when the SSH config lock is held' {
        Save-SrmProfile -Profile (New-TestProfile) -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null
        $before = Get-Content -LiteralPath $script:configPath -Raw
        $lock = [System.IO.File]::Open("$script:configPath.lock", 'OpenOrCreate', 'ReadWrite', 'None')
        try {
            Assert-Throws { Sync-SrmSshConfig -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot -LockTimeoutMilliseconds 100 }
        } finally {
            $lock.Dispose()
        }
        (Get-Content -LiteralPath $script:configPath -Raw) | Should Be $before
    }

    It 'imports an existing SSH Host by reference without rewriting it or requiring a key' {
        $original = "# operator-owned`r`nHost existing-prod`r`n    HostName prod.example.test`r`n    ProxyJump bastion`r`n"
        [System.IO.File]::WriteAllText($script:configPath, $original)
        $profile = [pscustomobject]@{
            alias = 'existing-prod'; displayName = 'Existing production'; host = 'prod.example.test'
            port = 22; user = 'deploy'; environment = 'production'; connectionMode = 'ssh-config-alias'
            sshConfigAlias = 'existing-prod'; identityFile = ''
            capabilities = [pscustomobject]@{ serverInfo = $true; systemd = $false; docker = $false; logs = $false }
            allowlists = [pscustomobject]@{ services = @(); logTargets = @() }; lastTestedUtc = $null
        }

        Save-SrmProfile -Profile $profile -StorePath $script:storePath -SshConfigPath $script:configPath -SshRoot $script:sshRoot | Out-Null

        [System.IO.File]::ReadAllText($script:configPath) | Should Be $original
        $saved = Get-SrmProfile -Alias 'existing-prod' -StorePath $script:storePath -SshRoot $script:sshRoot
        $saved.connectionMode | Should Be 'ssh-config-alias'
        $saved.sshConfigAlias | Should Be 'existing-prod'
        $saved.identityFile | Should Be ''
    }
}
