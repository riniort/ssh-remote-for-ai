param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Get-Command python -ErrorAction Stop
& $python.Source (Join-Path $root 'server\ssh_remote_mcp.py')
exit $LASTEXITCODE
