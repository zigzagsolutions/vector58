using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Api;
using BrowserSecurity.Agent.Shared.Ipc;
using BrowserSecurity.Agent.Shared.Messaging;
using BrowserSecurity.Agent.Shared.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service.Bridge;

public interface IBrowserBridge
{
    IReadOnlyList<BrowserStatus> Clients { get; }
    IReadOnlyList<BrowserClientReport> ClientReports { get; }

    /// <summary>Pushes a policy to every connected browser.</summary>
    Task BroadcastPolicyAsync(ValidatedPolicy policy, CancellationToken ct);

    /// <summary>Asks every connected extension for its local diagnostics.</summary>
    Task<IReadOnlyList<JsonObject>> RequestDiagnosticsAsync(TimeSpan timeout, CancellationToken ct);

    Task RunAsync(CancellationToken ct);
}

/// <summary>
/// Named-pipe endpoint for native messaging hosts (one per browser profile).
/// The pipe is a trust boundary: anything an interactive user runs can
/// connect, so only extension-to-host message types are accepted, events are
/// validated, and nothing received here can change policy.
/// </summary>
public sealed class BrowserBridge(
    IOptions<AgentOptions> options,
    IPolicyStore policyStore,
    ISecurityEventQueue events,
    TimeProvider time,
    ILogger<BrowserBridge> log) : IBrowserBridge
{
    public const int MaxEventBytes = 16 * 1024;
    private static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ForgetDisconnectedAfter = TimeSpan.FromHours(24);
    private static readonly TimeSpan WriteTimeout = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<Guid, Connection> _connections = new();
    private readonly ConcurrentDictionary<string, ClientRecord> _clients = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> _pendingDiagnostics = new();
    private readonly HashSet<string> _allowedOrigins =
        options.Value.AllowedExtensionIds.Select(id => $"chrome-extension://{id}/").ToHashSet(StringComparer.Ordinal);

    private sealed class Connection(Stream stream, string origin)
    {
        public Stream Stream { get; } = stream;
        public string Origin { get; } = origin;
        public SemaphoreSlim WriteLock { get; } = new(1, 1);
        public string? ClientId { get; set; }
    }

    private sealed record ClientRecord(
        string ClientId, string Browser, string? BrowserVersion, string? ExtensionVersion,
        int? PolicyVersion, int? DnrRuleCount, bool Connected, DateTimeOffset LastSeenAt);

    public IReadOnlyList<BrowserStatus> Clients
    {
        get
        {
            Prune();
            return _clients.Values
                .OrderBy(c => c.Browser, StringComparer.Ordinal).ThenBy(c => c.ClientId, StringComparer.Ordinal)
                .Select(c => new BrowserStatus(c.ClientId, c.Browser, c.BrowserVersion, c.ExtensionVersion, c.PolicyVersion, c.Connected, c.LastSeenAt))
                .ToList();
        }
    }

    public IReadOnlyList<BrowserClientReport> ClientReports =>
        _clients.Values
            .OrderByDescending(c => c.LastSeenAt)
            .Take(16)
            .Select(c => new BrowserClientReport(c.ClientId, c.Browser, c.BrowserVersion, c.ExtensionVersion, c.PolicyVersion, c.Connected, c.DnrRuleCount))
            .ToList();

    public async Task RunAsync(CancellationToken ct)
    {
        var first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = PipeFactory.Create(options.Value.BrowserPipeName, first);
                first = false;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                log.LogCritical("Cannot create browser pipe {Pipe}: {Error}", options.Value.BrowserPipeName, e.Message);
                await Task.Delay(TimeSpan.FromSeconds(5), time, ct).ConfigureAwait(false);
                continue;
            }
            try
            {
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }
            _ = Task.Run(() => HandleAsync(pipe, ct), CancellationToken.None);
        }
    }

    /// <summary>Serves one connected stream. Public so tests can drive it over any stream.</summary>
    public async Task HandleAsync(Stream stream, CancellationToken ct)
    {
        await using var _ = stream.ConfigureAwait(false);
        Connection? conn = null;
        var id = Guid.NewGuid();
        try
        {
            using var helloCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            helloCts.CancelAfter(HelloTimeout);
            var hello = await MessageFraming.ReadJsonAsync(stream, AgentConstants.MaxMessageFromBrowserBytes, helloCts.Token).ConfigureAwait(false);
            var origin = hello?["origin"]?.GetValueKind() == JsonValueKind.String ? hello["origin"]!.GetValue<string>() : null;
            if (Str(hello, "type") != NativeMessageTypes.HostHello || origin is null || !_allowedOrigins.Contains(origin))
            {
                log.LogWarning("Rejected browser connection from origin {Origin}", origin ?? "(none)");
                return;
            }
            conn = new Connection(stream, origin);
            _connections[id] = conn;
            log.LogInformation("Browser extension connected ({Origin})", origin);

            while (!ct.IsCancellationRequested)
            {
                var msg = await MessageFraming.ReadJsonAsync(stream, AgentConstants.MaxMessageFromBrowserBytes, ct).ConfigureAwait(false);
                if (msg is null) break;
                await OnMessageAsync(conn, msg, ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is FramingException or IOException or OperationCanceledException or ObjectDisposedException)
        {
            if (!ct.IsCancellationRequested) log.LogInformation("Browser connection closed: {Reason}", e.Message);
        }
        finally
        {
            _connections.TryRemove(id, out var _1);
            if (conn?.ClientId is { } clientId && _clients.TryGetValue(clientId, out var rec) &&
                !_connections.Values.Any(c => c.ClientId == clientId))
            {
                _clients[clientId] = rec with { Connected = false, LastSeenAt = time.GetUtcNow() };
            }
        }
    }

    private async Task OnMessageAsync(Connection conn, JsonObject msg, CancellationToken ct)
    {
        var type = Str(msg, "type");
        if (type is null || !NativeMessageTypes.FromExtension.Contains(type))
        {
            log.LogWarning("Dropped unexpected message type {Type} from browser", type ?? "(none)");
            return;
        }
        switch (type)
        {
            case NativeMessageTypes.ClientHealth:
                OnClientHealth(conn, msg["client"] as JsonObject);
                break;
            case NativeMessageTypes.RequestPolicy:
                // Always answer with the cached policy: the extension reports "unchanged"
                // cheaply, and this self-heals a browser whose dynamic rules were cleared.
                if (policyStore.Current is { } policy) await SendPolicyAsync(conn, policy, ct).ConfigureAwait(false);
                break;
            case NativeMessageTypes.PolicyStatus:
                if (conn.ClientId is { } cid && _clients.TryGetValue(cid, out var rec))
                {
                    var status = Str(msg, "status");
                    var version = msg["policyVersion"] is JsonValue v && v.TryGetValue<int>(out var pv) ? pv : rec.PolicyVersion;
                    _clients[cid] = rec with { PolicyVersion = status is "applied" or "unchanged" ? version : rec.PolicyVersion, LastSeenAt = time.GetUtcNow() };
                    if (status == "failed") log.LogWarning("Browser {Client} failed to apply policy: {Error}", cid, Str(msg, "error"));
                }
                break;
            case NativeMessageTypes.SecurityEvent:
                if (ValidateEvent(msg["event"] as JsonObject) is { } evt) events.Enqueue(evt);
                break;
            case NativeMessageTypes.DiagnosticRequest:
                if (msg["response"] is JsonObject response && Str(msg, "requestId") is { } requestId &&
                    _pendingDiagnostics.TryGetValue($"{requestId}", out var tcs))
                {
                    tcs.TrySetResult(new JsonObject { ["clientId"] = conn.ClientId, ["response"] = response.DeepClone() });
                }
                break;
            case NativeMessageTypes.CollectHistory:
                // Phase 1 extensions only ever answer "unsupported"; the agent already reports NOT_SUPPORTED.
                break;
        }
    }

    private void OnClientHealth(Connection conn, JsonObject? client)
    {
        var clientId = Str(client, "clientId");
        var browser = Str(client, "browser");
        if (clientId is null || clientId.Length is < 8 or > 64 || browser is not ("chrome" or "edge")) return;
        conn.ClientId = clientId;
        _clients[clientId] = new ClientRecord(
            clientId, browser,
            Truncate(Str(client, "browserVersion"), 64),
            Truncate(Str(client, "extensionVersion"), 32),
            Int(client, "policyVersion"),
            Int(client, "dnrRuleCount"),
            Connected: true,
            time.GetUtcNow());
    }

    /// <summary>Accepts only extension event types with a UUID id and bounded size.</summary>
    internal static JsonObject? ValidateEvent(JsonObject? evt)
    {
        if (evt is null) return null;
        var type = Str(evt, "eventType");
        if (type is null || !NativeMessageTypes.ExtensionEventTypes.Contains(type)) return null;
        if (!Guid.TryParse(Str(evt, "eventId"), out _)) return null;
        if (Str(evt, "occurredAt") is null) return null;
        var clone = (JsonObject)evt.DeepClone();
        return System.Text.Encoding.UTF8.GetByteCount(clone.ToJsonString()) <= MaxEventBytes ? clone : null;
    }

    /// <summary>
    /// Sends to every browser concurrently. A Windows pipe write completes only
    /// once the reader drains it, so a sequential loop would let one stalled
    /// browser hold back the policy for all the others.
    /// </summary>
    public Task BroadcastPolicyAsync(ValidatedPolicy policy, CancellationToken ct) =>
        Task.WhenAll(_connections.Values.Select(async conn =>
        {
            try
            {
                await SendPolicyAsync(conn, policy, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException)
            {
                log.LogInformation("Could not push policy to a browser: {Error}", e.Message);
            }
        }));

    private async Task SendPolicyAsync(Connection conn, ValidatedPolicy policy, CancellationToken ct)
    {
        var message = new JsonObject
        {
            ["type"] = NativeMessageTypes.PolicyUpdate,
            ["protocolVersion"] = AgentConstants.NativeProtocolVersion,
            ["policyVersion"] = policy.PolicyVersion,
            ["payload"] = policy.Raw.DeepClone(),
        };
        try
        {
            await SendAsync(conn, message, ct).ConfigureAwait(false);
        }
        catch (FramingException e)
        {
            // Over Chromium's 1 MiB limit: the browser keeps its current rules. Reported, never silently ignored.
            log.LogError("Policy v{Version} cannot be delivered to the browser: {Error}", policy.PolicyVersion, e.Message);
            events.Enqueue(AgentEvents.Create("POLICY_FAILED", time.GetUtcNow(), policy.PolicyVersion,
                new JsonObject { ["stage"] = "native_messaging", ["error"] = e.Message }));
        }
    }

    private static async Task SendAsync(Connection conn, JsonObject message, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(WriteTimeout);
        try
        {
            await conn.WriteLock.WaitAsync(timeout.Token).ConfigureAwait(false);
            try
            {
                await MessageFraming.WriteJsonAsync(conn.Stream, message, AgentConstants.MaxMessageToBrowserBytes, timeout.Token).ConfigureAwait(false);
            }
            finally
            {
                conn.WriteLock.Release();
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The browser stopped reading. An abandoned write may leave a partial
            // frame, so drop the connection; the extension reconnects and asks
            // for the policy again.
            await conn.Stream.DisposeAsync().ConfigureAwait(false);
            throw new IOException("Timed out writing to the browser; connection closed.");
        }
    }

    public async Task<IReadOnlyList<JsonObject>> RequestDiagnosticsAsync(TimeSpan timeout, CancellationToken ct)
    {
        var pending = _connections.Values.Select(conn => (conn, id: Guid.NewGuid().ToString("N"))).ToList();
        var keys = pending.Select(p => p.id).ToList();
        var sent = await Task.WhenAll(pending.Select(async p =>
        {
            var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingDiagnostics[p.id] = tcs;
            try
            {
                await SendAsync(p.conn, new JsonObject
                {
                    ["type"] = NativeMessageTypes.DiagnosticRequest,
                    ["protocolVersion"] = AgentConstants.NativeProtocolVersion,
                    ["requestId"] = p.id,
                }, ct).ConfigureAwait(false);
                return tcs.Task;
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException)
            {
                log.LogInformation("Diagnostic request failed: {Error}", e.Message);
                return null;
            }
        })).ConfigureAwait(false);
        var waits = sent.OfType<Task<JsonObject>>().ToList();
        try
        {
            await Task.WhenAny(Task.WhenAll(waits), Task.Delay(timeout, time, ct)).ConfigureAwait(false);
        }
        finally
        {
            foreach (var k in keys) _pendingDiagnostics.TryRemove(k, out var _1);
        }
        return waits.Where(t => t.IsCompletedSuccessfully).Select(t => t.Result).ToList();
    }

    private void Prune()
    {
        var cutoff = time.GetUtcNow() - ForgetDisconnectedAfter;
        foreach (var (k, v) in _clients)
            if (!v.Connected && v.LastSeenAt < cutoff) _clients.TryRemove(k, out var _1);
    }

    private static string? Str(JsonObject? o, string key) =>
        o?[key] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;

    private static int? Int(JsonObject? o, string key) =>
        o?[key] is JsonValue v && v.GetValueKind() == JsonValueKind.Number && v.TryGetValue<int>(out var i) ? i : null;

    private static string? Truncate(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}
