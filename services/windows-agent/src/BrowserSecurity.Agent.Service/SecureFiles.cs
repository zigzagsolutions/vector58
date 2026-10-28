using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace BrowserSecurity.Agent.Service;

/// <summary>Creates the data directory and writes files atomically with restrictive permissions.</summary>
public static class SecureFiles
{
    public static void EnsureDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) EnsureWindowsDirectory(path);
        else
        {
            Directory.CreateDirectory(path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    /// <summary>SYSTEM and Administrators only, inheritance disabled.</summary>
    [SupportedOSPlatform("windows")]
    private static void EnsureWindowsDirectory(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }
        var dir = new DirectoryInfo(path);
        if (!dir.Exists) dir.Create(security);
        else dir.SetAccessControl(security);
    }

    public static async Task WriteAtomicAsync(string path, byte[] content, CancellationToken ct = default)
    {
        var tmp = path + ".tmp";
        await File.WriteAllBytesAsync(tmp, content, ct).ConfigureAwait(false);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, path, overwrite: true);
    }
}
