using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace BrowserSecurity.Agent.Service.Bridge;

/// <summary>
/// Creates server pipe instances. On Windows the ACL lets interactive users
/// connect (the native host and tray run as the signed-in user) but not
/// create instances, so a user process cannot squat the pipe name; network
/// logons are denied. The first instance is created with FirstPipeInstance
/// so the service fails loudly if something already owns the name.
/// </summary>
public static class PipeFactory
{
    public static NamedPipeServerStream Create(string name, bool first)
    {
        var options = PipeOptions.Asynchronous;
        if (OperatingSystem.IsWindows())
        {
            if (first) options |= PipeOptions.FirstPipeInstance;
            return NamedPipeServerStreamAcl.Create(
                name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, options, 0, 0, WindowsPipeSecurity());
        }
        return new NamedPipeServerStream(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, options);
    }

    [SupportedOSPlatform("windows")]
    private static PipeSecurity WindowsPipeSecurity()
    {
        var s = new PipeSecurity();
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        s.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return s;
    }
}
