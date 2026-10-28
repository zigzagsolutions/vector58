using System.Text.Json;
using BrowserSecurity.Agent.Service.Security;
using BrowserSecurity.Agent.Shared.Api;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service.Identity;

/// <summary>Who this device is, as issued by the control plane at enrollment.</summary>
public sealed record DeviceIdentity(
    Guid DeviceId,
    Guid OrganizationId,
    string OrganizationName,
    DateTimeOffset EnrolledAt,
    string ApiBaseUrl);

public interface IDeviceIdentityProvider
{
    /// <summary>Stable per-installation id, sent at enrollment so re-enrolling reuses the device record.</summary>
    Guid InstallationId { get; }

    /// <summary>Null when not enrolled, or when enrolled against a different control plane than configured.</summary>
    DeviceIdentity? Current { get; }

    /// <summary>Device bearer secret, decrypted on demand. Never logged.</summary>
    string? GetSecret();

    Task SaveAsync(EnrollmentResponse enrollment, CancellationToken ct);

    /// <summary>Forget the identity (device revoked). Cached policy stays enforced.</summary>
    void Clear();
}

/// <summary>
/// Persists identity.json (non-secret) and device.secret (protected with
/// DPAPI on Windows) in the agent data directory.
/// </summary>
public sealed class DeviceIdentityProvider : IDeviceIdentityProvider
{
    private readonly AgentOptions _options;
    private readonly ISecretProtector _protector;
    private readonly ILogger<DeviceIdentityProvider> _log;
    private readonly Lock _gate = new();
    private DeviceIdentity? _identity;
    private Guid? _installationId;

    public DeviceIdentityProvider(IOptions<AgentOptions> options, ISecretProtector protector, ILogger<DeviceIdentityProvider> log)
    {
        _options = options.Value;
        _protector = protector;
        _log = log;
        SecureFiles.EnsureDirectory(_options.DataDirectory);
        _identity = LoadIdentity();
    }

    private string IdentityPath => Path.Combine(_options.DataDirectory, "identity.json");
    private string SecretPath => Path.Combine(_options.DataDirectory, "device.secret");
    private string InstallationPath => Path.Combine(_options.DataDirectory, "installation.id");

    public Guid InstallationId
    {
        get
        {
            lock (_gate)
            {
                if (_installationId is { } id) return id;
                if (File.Exists(InstallationPath) && Guid.TryParse(File.ReadAllText(InstallationPath).Trim(), out var stored))
                    return (_installationId = stored).Value;
                var created = Guid.NewGuid();
                File.WriteAllText(InstallationPath, created.ToString());
                return (_installationId = created).Value;
            }
        }
    }

    public DeviceIdentity? Current
    {
        get
        {
            lock (_gate) return _identity;
        }
    }

    public string? GetSecret()
    {
        if (Current is null || !File.Exists(SecretPath)) return null;
        try
        {
            return _protector.Unprotect(File.ReadAllBytes(SecretPath));
        }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or FormatException)
        {
            _log.LogError("Device secret could not be decrypted; the device must be re-enrolled ({Error})", e.Message);
            return null;
        }
    }

    public async Task SaveAsync(EnrollmentResponse enrollment, CancellationToken ct)
    {
        var identity = new DeviceIdentity(
            enrollment.DeviceId,
            enrollment.OrganizationId,
            enrollment.OrganizationName,
            enrollment.EnrolledAt,
            _options.ValidatedApiBaseUri().ToString());
        await SecureFiles.WriteAtomicAsync(SecretPath, _protector.Protect(enrollment.DeviceSecret), ct).ConfigureAwait(false);
        await SecureFiles.WriteAtomicAsync(IdentityPath, JsonSerializer.SerializeToUtf8Bytes(identity, AgentJson.Options), ct).ConfigureAwait(false);
        lock (_gate) _identity = identity;
    }

    public void Clear()
    {
        lock (_gate)
        {
            _identity = null;
            File.Delete(SecretPath);
            File.Delete(IdentityPath);
        }
    }

    private DeviceIdentity? LoadIdentity()
    {
        if (!File.Exists(IdentityPath)) return null;
        try
        {
            var identity = JsonSerializer.Deserialize<DeviceIdentity>(File.ReadAllBytes(IdentityPath), AgentJson.Options);
            if (identity is null) return null;
            // The secret is only ever presented to the control plane that issued it.
            if (!string.Equals(identity.ApiBaseUrl, _options.ValidatedApiBaseUri().ToString(), StringComparison.OrdinalIgnoreCase))
            {
                _log.LogError(
                    "Device was enrolled against {Enrolled} but Agent:ApiBaseUrl is {Configured}; refusing to send credentials. Re-enroll the device.",
                    identity.ApiBaseUrl, _options.ApiBaseUrl);
                return null;
            }
            return identity;
        }
        catch (JsonException e)
        {
            _log.LogError("identity.json is corrupt ({Error}); the device must be re-enrolled", e.Message);
            return null;
        }
    }
}
