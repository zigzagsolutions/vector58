<#
.SYNOPSIS
  Removes the Browser Security agent. Run elevated.

.DESCRIPTION
  Stops and deletes the service, unregisters the native messaging host and
  tray, and removes program files. Machine data (device identity, cached
  policy, queued events) is removed unless -KeepData is given. The device
  record in the portal is not deleted; disable it there.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'Vector58\BrowserSecurity'),
    [switch] $KeepData
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
}
Get-Process -Name 'BrowserSecurity.Tray', 'BrowserSecurity.NativeHost' -ErrorAction SilentlyContinue | Stop-Process -Force
foreach ($key in Get-NativeHostRegistryKeys) { Remove-Item -Path $key -Force -ErrorAction SilentlyContinue }
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Vector58BrowserSecurityTray' -ErrorAction SilentlyContinue
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
if (-not $KeepData) {
    $data = Get-AgentDataDirectory
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
}
Write-Host 'Browser Security agent removed. Browser extension policies (if any) are managed separately.'
