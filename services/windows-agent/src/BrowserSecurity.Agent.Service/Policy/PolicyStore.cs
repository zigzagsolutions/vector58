using System.Text;
using BrowserSecurity.Agent.Shared.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service.Policy;

public interface IPolicyStore
{
    /// <summary>Last-known-good policy; enforced until a newer valid one arrives.</summary>
    ValidatedPolicy? Current { get; }
    DateTimeOffset? StoredAt { get; }

    /// <summary>Loads and re-verifies the cache from disk. Falls back to the previous copy if the current one is damaged.</summary>
    ValidatedPolicy? Load();

    /// <summary>
    /// Stores a validated policy for the device's organization. Refuses other
    /// organizations, older versions and same-version content changes. A cached
    /// policy from a previous enrollment (different organization) is replaced.
    /// </summary>
    Task StoreAsync(ValidatedPolicy policy, Guid deviceOrganizationId, CancellationToken ct);
}

public sealed class PolicyRejectedException(string message) : Exception(message);

/// <summary>
/// Disk cache at &lt;data&gt;/policy/current.json with previous.json kept as a
/// fallback. Files contain the raw signed-off payload, re-verified (schema +
/// checksum) on every load, so a tampered or corrupted cache is never used.
/// </summary>
public sealed class PolicyStore : IPolicyStore
{
    private readonly string _dir;
    private readonly ILogger<PolicyStore> _log;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private ValidatedPolicy? _current;
    private DateTimeOffset? _storedAt;

    public PolicyStore(IOptions<AgentOptions> options, ILogger<PolicyStore> log, TimeProvider time)
    {
        _dir = Path.Combine(options.Value.DataDirectory, "policy");
        _log = log;
        _time = time;
        SecureFiles.EnsureDirectory(options.Value.DataDirectory);
        Directory.CreateDirectory(_dir);
    }

    private string CurrentPath => Path.Combine(_dir, "current.json");
    private string PreviousPath => Path.Combine(_dir, "previous.json");

    public ValidatedPolicy? Current { get { lock (_gate) return _current; } }
    public DateTimeOffset? StoredAt { get { lock (_gate) return _storedAt; } }

    public ValidatedPolicy? Load()
    {
        foreach (var path in new[] { CurrentPath, PreviousPath })
        {
            if (!File.Exists(path)) continue;
            try
            {
                var policy = PolicyValidator.Parse(File.ReadAllText(path, Encoding.UTF8));
                lock (_gate)
                {
                    _current = policy;
                    _storedAt = File.GetLastWriteTimeUtc(path);
                }
                if (path == PreviousPath) _log.LogWarning("Cached policy was damaged; using previous version v{Version}", policy.PolicyVersion);
                return policy;
            }
            catch (Exception e) when (e is PolicyValidationException or IOException)
            {
                _log.LogError("Cached policy {Path} rejected: {Error}", path, e.Message);
            }
        }
        return null;
    }

    public async Task StoreAsync(ValidatedPolicy policy, Guid deviceOrganizationId, CancellationToken ct)
    {
        if (policy.OrganizationId != deviceOrganizationId)
            throw new PolicyRejectedException("Policy belongs to a different organization than this device");
        var current = Current;
        if (current is not null && current.OrganizationId == deviceOrganizationId)
        {
            if (policy.PolicyVersion < current.PolicyVersion)
                throw new PolicyRejectedException($"Refusing rollback from v{current.PolicyVersion} to v{policy.PolicyVersion}");
            if (policy.PolicyVersion == current.PolicyVersion)
            {
                if (policy.Checksum == current.Checksum) return;
                // Published versions are immutable; a different body for the same number is suspicious.
                throw new PolicyRejectedException($"Policy v{policy.PolicyVersion} content differs from the cached copy");
            }
        }

        var bytes = Encoding.UTF8.GetBytes(policy.Raw.ToJsonString());
        if (File.Exists(CurrentPath)) File.Copy(CurrentPath, PreviousPath, overwrite: true);
        await SecureFiles.WriteAtomicAsync(CurrentPath, bytes, ct).ConfigureAwait(false);
        lock (_gate)
        {
            _current = policy;
            _storedAt = _time.GetUtcNow();
        }
    }
}
