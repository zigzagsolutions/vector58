using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Api;
using BrowserSecurity.Agent.Shared.Ipc;
using BrowserSecurity.Agent.Shared.Messaging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service.Status;

/// <summary>
/// Status pipe for the tray. Read-only apart from SYNC_NOW, which only asks
/// the service to contact the cloud sooner (rate limited). There is no
/// request that disables or weakens protection.
/// </summary>
public sealed class StatusServer(
    IOptions<AgentOptions> options,
    IDeviceIdentityProvider identity,
    IPolicyStore store,
    IBrowserBridge bridge,
    ISecurityEventQueue events,
    AgentHealth health,
    AgentTriggers triggers,
    TimeProvider time,
    ILogger<StatusServer> log)
{
    private const int MaxRequestBytes = 4096;
    private static readonly TimeSpan SyncNowMinInterval = TimeSpan.FromSeconds(30);
    private DateTimeOffset _lastSyncNow = DateTimeOffset.MinValue;

    public AgentStatusSnapshot Snapshot()
    {
        var device = identity.Current;
        var policy = store.Current;
        return new AgentStatusSnapshot(
            AgentConstants.AgentVersion,
            device is not null,
            device?.OrganizationName,
            device?.DeviceId,
            policy?.PolicyVersion,
            policy?.Rules.Count ?? 0,
            store.StoredAt,
            health.LastCloudContactAt,
            health.LastCloudError,
            bridge.Clients,
            events.Count,
            options.Value.PortalUrl);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = PipeFactory.Create(options.Value.StatusPipeName, first);
                first = false;
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException e)
            {
                log.LogError("Status pipe error: {Error}", e.Message);
                await Task.Delay(TimeSpan.FromSeconds(5), time, ct).ConfigureAwait(false);
                continue;
            }
            _ = Task.Run(() => HandleAsync(pipe, ct), CancellationToken.None);
        }
    }

    public async Task HandleAsync(Stream stream, CancellationToken ct)
    {
        await using var _ = stream.ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            while (await MessageFraming.ReadJsonAsync(stream, MaxRequestBytes, timeout.Token).ConfigureAwait(false) is { } req)
            {
                var type = req["type"]?.GetValueKind() == JsonValueKind.String ? req["type"]!.GetValue<string>() : null;
                JsonNode reply;
                switch (type)
                {
                    case StatusRequests.GetStatus:
                        reply = JsonSerializer.SerializeToNode(Snapshot(), AgentJson.Options)!;
                        break;
                    case StatusRequests.SyncNow:
                        var now = time.GetUtcNow();
                        var accepted = now - _lastSyncNow >= SyncNowMinInterval;
                        if (accepted)
                        {
                            _lastSyncNow = now;
                            triggers.RequestSync();
                        }
                        reply = new JsonObject { ["accepted"] = accepted };
                        break;
                    default:
                        reply = new JsonObject { ["error"] = "unsupported request" };
                        break;
                }
                await MessageFraming.WriteJsonAsync(stream, reply, AgentConstants.MaxMessageToBrowserBytes, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is FramingException or IOException or OperationCanceledException)
        {
            // Client went away or misbehaved.
        }
    }
}
