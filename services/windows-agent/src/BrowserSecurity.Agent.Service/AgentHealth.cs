namespace BrowserSecurity.Agent.Service;

/// <summary>Process-wide health facts surfaced to the tray and diagnostics.</summary>
public sealed class AgentHealth(TimeProvider time)
{
    private readonly Lock _gate = new();
    private DateTimeOffset? _lastCloudContact;
    private string? _lastCloudError;
    public DateTimeOffset StartedAt { get; } = time.GetUtcNow();

    public DateTimeOffset? LastCloudContactAt { get { lock (_gate) return _lastCloudContact; } }
    public string? LastCloudError { get { lock (_gate) return _lastCloudError; } }

    public void CloudSucceeded()
    {
        lock (_gate)
        {
            _lastCloudContact = time.GetUtcNow();
            _lastCloudError = null;
        }
    }

    public void CloudFailed(string error)
    {
        lock (_gate) _lastCloudError = error;
    }

    public long UptimeSeconds => (long)(time.GetUtcNow() - StartedAt).TotalSeconds;
}
