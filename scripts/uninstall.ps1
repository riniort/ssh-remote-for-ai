[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([switch]$KeepMarketplaceEntry)

$ErrorActionPreference = 'Stop'
$pluginName = 'ssh-remote-for-ai'
$userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$pluginsRoot = [System.IO.Path]::GetFullPath((Join-Path $userProfile 'plugins'))
$destination = [System.IO.Path]::GetFullPath((Join-Path $pluginsRoot $pluginName))
$marketplacePath = Join-Path $userProfile '.agents\plugins\marketplace.json'

if ((Split-Path -Leaf $destination) -ne $pluginName -or (Split-Path -Parent $destination) -ne $pluginsRoot) {
    throw 'Refusing to remove an unexpected path.'
}
if ((Test-Path -LiteralPath $destination) -and $PSCmdlet.ShouldProcess($destination, 'Remove installed plugin files')) {
    Remove-Item -LiteralPath $destination -Recurse -Force
}
if (-not $KeepMarketplaceEntry -and (Test-Path -LiteralPath $marketplacePath) -and
    $PSCmdlet.ShouldProcess($marketplacePath, 'Remove personal marketplace entry')) {
    $marketplace = Get-Content -LiteralPath $marketplacePath -Raw | ConvertFrom-Json
    $marketplace.plugins = @($marketplace.plugins | Where-Object { $_.name -ne $pluginName })
    $temporary = "$marketplacePath.tmp.$PID"
    $marketplace | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination $marketplacePath -Force
}
Write-Host 'Plugin files were removed. SSH profiles, audit records, and keys were intentionally preserved.'
