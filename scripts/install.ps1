[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [switch]$SkipMarketplace
)

$ErrorActionPreference = 'Stop'
$pluginName = 'ssh-remote-for-ai'
$source = (Split-Path -Parent $PSScriptRoot)
$userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$pluginsRoot = Join-Path $userProfile 'plugins'
$destination = Join-Path $pluginsRoot $pluginName
$marketplacePath = Join-Path $userProfile '.agents\plugins\marketplace.json'

if ((Test-Path -LiteralPath $destination) -and -not $Force) {
    throw "Plugin already exists at $destination. Re-run with -Force to update it."
}

if ($PSCmdlet.ShouldProcess($destination, 'Install SSH Remote Manager plugin')) {
    [void](New-Item -ItemType Directory -Path $destination -Force)
    Get-ChildItem -LiteralPath $source -Force |
        Where-Object { $_.Name -ne '.git' } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force }
}

if (-not $SkipMarketplace -and $PSCmdlet.ShouldProcess($marketplacePath, 'Register personal plugin')) {
    $scaffold = Join-Path $userProfile '.codex\skills\.system\plugin-creator\scripts\create_basic_plugin.py'
    if (-not (Test-Path -LiteralPath $scaffold)) {
        throw "Codex plugin-creator scaffold was not found at $scaffold."
    }
    $python = Get-Command python -ErrorAction Stop
    & $python.Source $scaffold $pluginName --path $pluginsRoot --with-marketplace --force --category 'Developer Tools'
    if ($LASTEXITCODE -ne 0) { throw "Personal marketplace registration failed with exit code $LASTEXITCODE." }
    # The scaffold intentionally writes a default manifest; restore the reviewed project manifest.
    Copy-Item -LiteralPath (Join-Path $source '.codex-plugin\plugin.json') -Destination (Join-Path $destination '.codex-plugin\plugin.json') -Force
}

Write-Host "Installed $pluginName at $destination"
Write-Host 'No SSH profiles, keys, or Codex global activation settings were changed.'
