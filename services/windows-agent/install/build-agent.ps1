<#
.SYNOPSIS
  Publishes the agent service, native messaging host and tray app for Windows x64.

.DESCRIPTION
  Produces self-contained builds under artifacts/publish so endpoints do not
  need a separate .NET runtime. Runs on Windows, or cross-publishes from
  Linux/macOS with the .NET 10 SDK.

.EXAMPLE
  ./install/build-agent.ps1 -Configuration Release
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')] [string] $Configuration = 'Release',
    [string] $Runtime = 'win-x64',
    [string] $Output = (Join-Path $PSScriptRoot '..' 'artifacts' 'publish')
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')

$projects = @(
    @{ Name = 'Service';    Path = 'src/BrowserSecurity.Agent.Service/BrowserSecurity.Agent.Service.csproj' },
    @{ Name = 'NativeHost'; Path = 'src/BrowserSecurity.Agent.NativeMessaging/BrowserSecurity.Agent.NativeMessaging.csproj' },
    @{ Name = 'Tray';       Path = 'src/BrowserSecurity.Agent.Tray/BrowserSecurity.Agent.Tray.csproj' }
)

dotnet test (Join-Path $root 'BrowserSecurity.Agent.sln') -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw 'Agent tests failed; refusing to publish.' }

foreach ($p in $projects) {
    $dest = Join-Path $Output $p.Name
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    dotnet publish (Join-Path $root $p.Path) -c $Configuration -r $Runtime --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=embedded `
        -o $dest --nologo
    if ($LASTEXITCODE -ne 0) { throw "Publishing $($p.Name) failed." }
}

# Code signing extension point: sign every executable before distribution.
#   signtool sign /fd SHA256 /tr <timestamp-url> /td SHA256 /a <exe>
# Unsigned builds are for development only (see docs/windows-agent.md).
Get-ChildItem $Output -Recurse -Filter *.exe | ForEach-Object { Write-Host "Built $($_.FullName)" }
