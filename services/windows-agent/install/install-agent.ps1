<#
.SYNOPSIS
  Installs the Vector58 Browser Security agent on a Windows endpoint.

.DESCRIPTION
  Must run elevated. Steps:
    1. Copy published binaries to Program Files.
    2. Create the machine data directory (SYSTEM + Administrators only).
    3. Write agentsettings.json (control-plane URL, allowed extension IDs) and
       the one-time enrollment token. The service exchanges the token for a
       device credential on first start and deletes it.
    4. Register the native messaging host for Chrome and Edge (HKLM).
    5. Install and start the Windows service (LocalSystem, automatic, restart on failure).
    6. Register the tray app to start at sign-in for all users.

  The enrollment token is the only secret this script handles. Pass it from
  your deployment tool's secret store; do not hard-code it in scripts.

.EXAMPLE
  .\install-agent.ps1 -ApiBaseUrl https://security.example.com -EnrollmentToken $token `
      -ExtensionIds 'abcdefghijklmnopabcdefghijklmnop','ponmlkjihgfedcbaponmlkjihgfedcba'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [ValidatePattern('^https://')] [string] $ApiBaseUrl,
    [Parameter(Mandatory)] [ValidateLength(16, 256)] [string] $EnrollmentToken,
    # Chrome Web Store and Edge Add-ons assign different IDs; include both, plus the dev ID for testing.
    [ValidatePattern('^[a-p]{32}$')] [string[]] $ExtensionIds = @('ikgimjohebonbmlfdngiiebaadojbdmp'),
    [string] $PortalUrl = $ApiBaseUrl,
    [string] $SourceDir = (Join-Path $PSScriptRoot '..' 'artifacts' 'publish'),
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'Vector58\BrowserSecurity'),
    [switch] $NoTray
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator

$dataDir = Get-AgentDataDirectory
$serviceExe = Join-Path $InstallDir 'Service\BrowserSecurity.Agent.Service.exe'
$hostExe = Join-Path $InstallDir 'NativeHost\BrowserSecurity.NativeHost.exe'
$trayExe = Join-Path $InstallDir 'Tray\BrowserSecurity.Tray.exe'
$manifestPath = Join-Path $InstallDir "NativeHost\$NativeHostName.json"

# 1. Binaries (stop a running service first so files are not locked).
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}
foreach ($part in 'Service', 'NativeHost', 'Tray') {
    $src = Join-Path $SourceDir $part
    if (-not (Test-Path $src)) { throw "Missing $src. Run build-agent.ps1 first." }
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir $part) | Out-Null
    Copy-Item -Path (Join-Path $src '*') -Destination (Join-Path $InstallDir $part) -Recurse -Force
}

# 2. Data directory: SYSTEM + Administrators only, no inheritance.
New-RestrictedDirectory -Path $dataDir

# 3. Configuration and one-time enrollment token.
$settings = @{
    Agent = @{
        ApiBaseUrl          = $ApiBaseUrl
        PortalUrl           = $PortalUrl
        AllowedExtensionIds = @($ExtensionIds)
    }
}
Set-Content -Path (Join-Path $dataDir 'agentsettings.json') -Value ($settings | ConvertTo-Json -Depth 4) -Encoding utf8
Set-Content -Path (Join-Path $dataDir 'enrollment.token') -Value $EnrollmentToken -Encoding ascii -NoNewline
Set-Content -Path (Join-Path $InstallDir 'NativeHost\nativehost.json') -Encoding utf8 `
    -Value (@{ allowedExtensionIds = @($ExtensionIds) } | ConvertTo-Json)

# 4. Native messaging host manifest + browser registration.
$manifest = [ordered]@{
    name            = $NativeHostName
    description     = 'Vector58 Browser Security agent bridge'
    path            = $hostExe
    type            = 'stdio'
    allowed_origins = @($ExtensionIds | ForEach-Object { "chrome-extension://$_/" })
}
Set-Content -Path $manifestPath -Value ($manifest | ConvertTo-Json) -Encoding utf8
foreach ($key in Get-NativeHostRegistryKeys) {
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name '(default)' -Value $manifestPath
}

# 5. Windows service.
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    New-Service -Name $ServiceName -DisplayName $ServiceDisplayName -BinaryPathName "`"$serviceExe`"" `
        -StartupType Automatic -Description 'Enforces browser security policy for Chrome and Edge. Managed by your organization.' | Out-Null
}
# Restart after 5s, 30s, then every 60s; reset the failure count daily.
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
& sc.exe sidtype $ServiceName unrestricted | Out-Null
Start-Service -Name $ServiceName

# 6. Tray at sign-in (per user session; closing it never stops protection).
if (-not $NoTray) {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'Vector58BrowserSecurityTray' -Value "`"$trayExe`""
}

Write-Host "Installed. Verify with: & '$PSScriptRoot\verify-agent.ps1'"
