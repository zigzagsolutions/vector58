<#
.SYNOPSIS
  Checks an agent installation and prints the service's live status.
#>
[CmdletBinding()]
param([string] $InstallDir = (Join-Path $env:ProgramFiles 'Vector58\BrowserSecurity'))
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$ok = $true
function Check([string] $Name, [bool] $Pass, [string] $Detail = '') {
    $script:ok = $script:ok -and $Pass
    $mark = if ($Pass) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1} {2}" -f $mark, $Name, $Detail)
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
Check 'Service installed' ($null -ne $svc)
Check 'Service running' ($svc.Status -eq 'Running') "($($svc.Status))"
Check 'Service start type automatic' ($svc.StartType -eq 'Automatic')

foreach ($key in Get-NativeHostRegistryKeys) {
    $manifest = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).'(default)'
    Check "Registry $key" ($manifest -and (Test-Path $manifest)) $manifest
    if ($manifest -and (Test-Path $manifest)) {
        $m = Get-Content $manifest -Raw | ConvertFrom-Json
        Check '  host executable exists' (Test-Path $m.path) $m.path
        Check '  allowed_origins present' ($m.allowed_origins.Count -gt 0) ($m.allowed_origins -join ', ')
    }
}

$data = Get-AgentDataDirectory
Check 'Data directory exists' (Test-Path $data) $data
Check 'Enrollment completed (token consumed)' (-not (Test-Path (Join-Path $data 'enrollment.token')))
Check 'Device identity present' (Test-Path (Join-Path $data 'identity.json'))
Check 'Cached policy present' (Test-Path (Join-Path $data 'policy\current.json'))

Write-Host "`nLive status from the service:"
& (Join-Path $InstallDir 'Service\BrowserSecurity.Agent.Service.exe') status
if (-not $ok) { exit 1 }
