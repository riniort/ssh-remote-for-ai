[CmdletBinding(SupportsShouldProcess)]
param([switch]$SkipMarketplace)

$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'install.ps1'
& $installer -Force -SkipMarketplace:$SkipMarketplace -Confirm:$false

$userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$pluginPath = Join-Path $userProfile 'plugins\ssh-remote-for-ai'
$cachebusterHelper = Join-Path $userProfile '.codex\skills\.system\plugin-creator\scripts\update_plugin_cachebuster.py'
if (-not (Test-Path -LiteralPath $cachebusterHelper)) {
    throw "Codex plugin-creator cachebuster helper was not found at $cachebusterHelper."
}
$python = Get-Command python -ErrorAction Stop
& $python.Source $cachebusterHelper $pluginPath
if ($LASTEXITCODE -ne 0) { throw "Plugin cachebuster update failed with exit code $LASTEXITCODE." }
Write-Host 'Plugin cachebuster updated. Reinstall it through Codex, then start a new task.'
