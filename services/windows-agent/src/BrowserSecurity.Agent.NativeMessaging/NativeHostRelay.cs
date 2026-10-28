using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Messaging;

namespace BrowserSecurity.Agent.NativeMessaging;

public enum RelayExit
{
    Normal = 0,
    ServiceUnavailable = 2,
    OriginNotAllowed = 3,
    BadArguments = 4,
}

/// <summary>
/// The browser starts one host process per connectNative() call and passes
/// the caller's origin as the first argument. The host checks it against the
/// allow-list (the browser manifest's allowed_origins is the first gate),
/// announces itself to the service, and then relays only the message types
/// each side is allowed to send. Logs go to stderr: stdout is the protocol.
/// </summary>
public sealed class NativeHostRelay(IReadOnlySet<string> allowedExtensionIds, TextWriter log)
{
    public static readonly TimeSpan PipeConnectTimeout = TimeSpan.FromSeconds(3);

    public static string? ExtensionIdFromOrigin(string origin)
    {
        const string prefix = "chrome-extension://";
        if (!origin.StartsWith(prefix, StringComparison.Ordinal) || !origin.EndsWith('/')) return null;
        var id = origin[prefix.Length..^1];
        return id.Length == 32 && id.All(c => c is >= 'a' and <= 'p') ? id : null;
    }

    public async Task<RelayExit> RunAsync(
        string[] args,
        Stream browserIn,
        Stream browserOut,
        Func<CancellationToken, Task<Stream>> connectService,
        CancellationToken ct)
    {
        var origin = args.FirstOrDefault(a => a.StartsWith("chrome-extension://", StringComparison.Ordinal));
        if (origin is null)
        {
            await log.WriteLineAsync("native host: missing caller origin argument").ConfigureAwait(false);
            return RelayExit.BadArguments;
        }
        var extensionId = ExtensionIdFromOrigin(origin);
        if (extensionId is null || !allowedExtensionIds.Contains(extensionId))
        {
            await log.WriteLineAsync($"native host: origin {origin} is not allowed").ConfigureAwait(false);
            return RelayExit.OriginNotAllowed;
        }

        Stream service;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(PipeConnectTimeout);
            service = await connectService(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception e) when (e is OperationCanceledException or TimeoutException or IOException or UnauthorizedAccessException)
        {
            // The extension keeps enforcing its cached rules, shows "degraded" and reconnects with backoff.
            await log.WriteLineAsync($"native host: agent service unavailable ({e.Message})").ConfigureAwait(false);
            return RelayExit.ServiceUnavailable;
        }

        await using (service.ConfigureAwait(false))
        {
            await MessageFraming.WriteJsonAsync(service, new JsonObject
            {
                ["type"] = NativeMessageTypes.HostHello,
                ["origin"] = origin,
                ["hostVersion"] = AgentConstants.AgentVersion,
                ["hostPid"] = Environment.ProcessId,
            }, AgentConstants.MaxMessageFromBrowserBytes, ct).ConfigureAwait(false);

            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var up = PumpAsync("browser->service", browserIn, service, AgentConstants.MaxMessageFromBrowserBytes,
                AgentConstants.MaxMessageFromBrowserBytes, NativeMessageTypes.FromExtension, stop.Token);
            var down = PumpAsync("service->browser", service, browserOut, AgentConstants.MaxMessageToBrowserBytes,
                AgentConstants.MaxMessageToBrowserBytes, NativeMessageTypes.ToExtension, stop.Token);
            await Task.WhenAny(up, down).ConfigureAwait(false);
            await stop.CancelAsync().ConfigureAwait(false);
            try
            {
                await Task.WhenAll(up, down).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when one side closes.
            }
        }
        return RelayExit.Normal;
    }

    private async Task PumpAsync(string name, Stream from, Stream to, int maxIn, int maxOut, IReadOnlySet<string> allowedTypes, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var frame = await MessageFraming.ReadFrameAsync(from, maxIn, ct).ConfigureAwait(false);
                if (frame is null) return;
                string? type;
                try
                {
                    type = JsonNode.Parse(frame) is JsonObject o && o["type"] is JsonValue v && v.GetValueKind() == JsonValueKind.String
                        ? v.GetValue<string>()
                        : null;
                }
                catch (JsonException)
                {
                    type = null;
                }
                if (type is null || !allowedTypes.Contains(type))
                {
                    await log.WriteLineAsync($"native host: {name} dropped message of type {type ?? "(invalid)"}").ConfigureAwait(false);
                    continue;
                }
                try
                {
                    await MessageFraming.WriteFrameAsync(to, frame, maxOut, ct).ConfigureAwait(false);
                }
                catch (FramingException e)
                {
                    await log.WriteLineAsync($"native host: {name} dropped oversized {type}: {e.Message}").ConfigureAwait(false);
                }
            }
        }
        catch (Exception e) when (e is FramingException or IOException or ObjectDisposedException)
        {
            await log.WriteLineAsync($"native host: {name} closed ({e.Message})").ConfigureAwait(false);
        }
    }

    public static IReadOnlySet<string> LoadAllowedIds(string configPath)
    {
        if (!File.Exists(configPath)) return new HashSet<string>();
        using var doc = JsonDocument.Parse(File.ReadAllText(configPath));
        return doc.RootElement.TryGetProperty("allowedExtensionIds", out var ids) && ids.ValueKind == JsonValueKind.Array
            ? ids.EnumerateArray().Where(i => i.ValueKind == JsonValueKind.String).Select(i => i.GetString()!).ToHashSet(StringComparer.Ordinal)
            : new HashSet<string>();
    }

}
