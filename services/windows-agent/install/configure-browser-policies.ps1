<#
.SYNOPSIS
  Force-installs the extension in Chrome and Edge via machine policy (no Intune/GPO required).

.DESCRIPTION
  Writes ExtensionInstallForcelist entries. Force-installed extensions cannot
  be disabled or removed by users. For domain-joined fleets prefer Group
  Policy or Intune with the same values (see docs/browser-extension.md).
  For self-hosted .crx distribution, -ChromeUpdateUrl points at your update manifest.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidatePattern('^[a-p]{32}$')] [string] $ChromeExtensionId,
    [ValidatePattern('^[a-p]{32}$')] [string] $EdgeExtensionId,
    [string] $ChromeUpdateUrl = 'https://clients2.google.com/service/update2/crx',
    [string] $EdgeUpdateUrl = 'https://edge.microsoft.com/extensionwebstorebase/v1/crx',
    [switch] $Remove
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator

function Set-ForceInstall([string] $Key, [string] $Id, [string] $UpdateUrl) {
    New-Item -Path $Key -Force | Out-Null
    $existing = Get-ItemProperty -Path $Key
    $names = $existing.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' }
    $match = $names | Where-Object { $_.Value -like "$Id;*" }
    if ($Remove) {
        $match | ForEach-Object { Remove-ItemProperty -Path $Key -Name $_.Name }
        return
    }
    if ($match) { return }
    $next = 1 + (($names | ForEach-Object { [int]$_.Name } | Measure-Object -Maximum).Maximum)
    Set-ItemProperty -Path $Key -Name "$next" -Value "$Id;$UpdateUrl"
}

if ($ChromeExtensionId) { Set-ForceInstall 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' $ChromeExtensionId $ChromeUpdateUrl }
if ($EdgeExtensionId) { Set-ForceInstall 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' $EdgeExtensionId $EdgeUpdateUrl }
Write-Host 'Browser policies updated. Restart Chrome/Edge or visit chrome://policy / edge://policy and click "Reload policies".'
