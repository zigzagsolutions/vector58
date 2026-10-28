using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Shared.Api;
using BrowserSecurity.Agent.Shared.Messaging;

namespace BrowserSecurity.Agent.Shared.Ipc;

/// <summary>Client for the service's status pipe (used by the tray and the CLI).</summary>
public sealed class StatusClient(string pipeName = AgentConstants.StatusPipeName)
{
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Returns null when the service is not reachable.</summary>
    public async Task<AgentStatusSnapshot?> GetStatusAsync(CancellationToken ct = default)
    {
        var reply = await RequestAsync(StatusRequests.GetStatus, ct).ConfigureAwait(false);
        return reply?.Deserialize<AgentStatusSnapshot>(AgentJson.Options);
    }

    public async Task<bool> RequestSyncAsync(CancellationToken ct = default)
    {
        var reply = await RequestAsync(StatusRequests.SyncNow, ct).ConfigureAwait(false);
        return reply?["accepted"]?.GetValue<bool>() == true;
    }

    private async Task<JsonObject?> RequestAsync(string type, CancellationToken ct)
    {
        try
        {
            var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await using (pipe.ConfigureAwait(false))
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(ConnectTimeout);
                await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
                await MessageFraming.WriteJsonAsync(pipe, new JsonObject { ["type"] = type }, 4096, ct).ConfigureAwait(false);
                return await MessageFraming.ReadJsonAsync(pipe, AgentConstants.MaxMessageToBrowserBytes, ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or TimeoutException or IOException or UnauthorizedAccessException or FramingException or JsonException)
        {
            return null;
        }
    }
}
