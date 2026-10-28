namespace BrowserSecurity.Agent.Shared.Ipc;

/// <summary>Requests the tray (or support tooling) may send on the status pipe.</summary>
public static class StatusRequests
{
    public const string GetStatus = "GET_STATUS";

    /// <summary>Asks the service to poll the cloud now. Rate limited by the service; cannot weaken protection.</summary>
    public const string SyncNow = "SYNC_NOW";
}

public sealed record BrowserStatus(
    string ClientId,
    string Browser,
    string? BrowserVersion,
    string? ExtensionVersion,
    int? PolicyVersion,
    bool Connected,
    DateTimeOffset LastSeenAt);

public sealed record AgentStatusSnapshot(
    string AgentVersion,
    bool Enrolled,
    string? OrganizationName,
    Guid? DeviceId,
    int? PolicyVersion,
    int RuleCount,
    DateTimeOffset? PolicyStoredAt,
    DateTimeOffset? LastCloudContactAt,
    string? LastCloudError,
    IReadOnlyList<BrowserStatus> Browsers,
    int QueuedEvents,
    string? PortalUrl);

public enum TrayState
{
    Protected,
    Degraded,
    NotEnrolled,
    ServiceUnavailable,
}

public sealed record TrayView(TrayState State, string Tooltip, IReadOnlyList<string> Lines);

/// <summary>Pure mapping from service status to what the tray shows. Unit tested on any OS.</summary>
public static class TrayPresenter
{
    /// <summary>Cloud contact older than this is shown as degraded.</summary>
    public static readonly TimeSpan CloudStaleAfter = TimeSpan.FromMinutes(10);

    public static TrayView Present(AgentStatusSnapshot? s, DateTimeOffset now)
    {
        if (s is null)
        {
            return new TrayView(TrayState.ServiceUnavailable, "Browser Security: service not running",
                ["The Browser Security service is not reachable.", "Browser protection continues with the last applied policy."]);
        }
        if (!s.Enrolled)
        {
            return new TrayView(TrayState.NotEnrolled, "Browser Security: not enrolled",
                ["This device is not enrolled.", "Contact your IT department."]);
        }

        var lines = new List<string>
        {
            $"Organization: {s.OrganizationName}",
            s.PolicyVersion is { } v ? $"Policy: v{v} ({s.RuleCount} rules)" : "Policy: waiting for first policy",
        };
        var cloudStale = s.LastCloudContactAt is null || now - s.LastCloudContactAt > CloudStaleAfter;
        lines.Add(cloudStale ? "Cloud: unreachable (using cached policy)" : $"Cloud: connected ({Ago(now - s.LastCloudContactAt!.Value)})");

        var connected = s.Browsers.Where(b => b.Connected).ToList();
        if (s.Browsers.Count == 0) lines.Add("Browsers: no protected browser connected");
        foreach (var b in s.Browsers)
        {
            var name = b.Browser == "edge" ? "Microsoft Edge" : "Google Chrome";
            lines.Add($"{name}: {(b.Connected ? "protected" : "disconnected")}{(b.PolicyVersion is { } pv ? $", policy v{pv}" : "")}");
        }
        if (s.QueuedEvents > 0) lines.Add($"Events waiting to upload: {s.QueuedEvents}");

        var degraded = s.PolicyVersion is null || cloudStale || connected.Count == 0 ||
                       connected.Any(b => b.PolicyVersion != s.PolicyVersion);
        return new TrayView(
            degraded ? TrayState.Degraded : TrayState.Protected,
            degraded ? "Browser Security: attention needed" : "Browser Security: protected",
            lines);
    }

    private static string Ago(TimeSpan t) =>
        t.TotalSeconds < 60 ? "just now" : t.TotalMinutes < 60 ? $"{(int)t.TotalMinutes} min ago" : $"{(int)t.TotalHours} h ago";
}
