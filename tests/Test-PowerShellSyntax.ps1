$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$files = @(
    'ssh_remote_manager.ps1',
    'src\SshRemoteManager.ProfileStore.psm1',
    'scripts\start-mcp.ps1',
    'scripts\install.ps1',
    'scripts\update.ps1',
    'scripts\uninstall.ps1'
)
foreach ($relative in $files) {
    $path = Join-Path $root $relative
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "$relative syntax error: $($errors[0].Message)" }
}
foreach ($launcher in @('ssh_remote_manager.cmd', 'setup_remote_ssh_gui.cmd')) {
    $content = Get-Content -LiteralPath (Join-Path $root $launcher) -Raw
    if ($content -notmatch 'ssh_remote_manager\.ps1') { throw "$launcher does not launch the GUI." }
}
Write-Output 'PowerShell syntax and launcher smoke checks passed.'
