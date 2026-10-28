# Shared constants and helpers for the agent install scripts.
# Values must match services/windows-agent/src/BrowserSecurity.Agent.Shared/AgentConstants.cs.

$ServiceName = 'Vector58BrowserSecurity'
$ServiceDisplayName = 'Vector58 Browser Security Agent'
$NativeHostName = 'com.vector58.browser_security'

function Get-AgentDataDirectory {
    Join-Path $env:ProgramData 'Vector58\BrowserSecurity'
}

function Get-NativeHostRegistryKeys {
    @(
        "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$NativeHostName",
        "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\$NativeHostName"
    )
}

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell session.'
    }
}

function New-RestrictedDirectory {
    param([Parameter(Mandatory)] [string] $Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {  # LocalSystem, BUILTIN\Administrators
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $Path -AclObject $acl
}
