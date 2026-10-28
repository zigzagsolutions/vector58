using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace BrowserSecurity.Agent.Service.Security;

public interface ISecretProtector
{
    /// <summary>True when secrets are encrypted at rest (DPAPI).</summary>
    bool IsProtected { get; }
    byte[] Protect(string secret);
    string Unprotect(byte[] data);
}

/// <summary>
/// DPAPI with CurrentUser scope. The service runs as LocalSystem, so only
/// SYSTEM can decrypt; administrators cannot read the secret off disk
/// without running code as SYSTEM.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Vector58.BrowserSecurity.DeviceSecret.v1");
    public bool IsProtected => true;
    public byte[] Protect(string secret) =>
        ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), Entropy, DataProtectionScope.CurrentUser);
    public string Unprotect(byte[] data) =>
        Encoding.UTF8.GetString(ProtectedData.Unprotect(data, Entropy, DataProtectionScope.CurrentUser));
}

/// <summary>
/// Development-only fallback for running the agent on Linux/macOS (CI,
/// local end-to-end tests). Stores the secret base64-encoded in a file only
/// the current user can read. Refused on Windows.
/// </summary>
public sealed class UnprotectedDevelopmentSecretProtector : ISecretProtector
{
    public UnprotectedDevelopmentSecretProtector()
    {
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Use DPAPI on Windows");
    }
    public bool IsProtected => false;
    public byte[] Protect(string secret) => Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes(secret)));
    public string Unprotect(byte[] data) => Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.ASCII.GetString(data)));
}
