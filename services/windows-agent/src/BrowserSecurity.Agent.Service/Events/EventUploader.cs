using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Shared.Api;

namespace BrowserSecurity.Agent.Service.Events;

public sealed class EventUploader(IApiClient api, ISecurityEventQueue queue, AgentHealth health)
{
    public const int BatchSize = 500;

    /// <summary>Uploads queued events in batches. Events are removed only after the server accepts them (ids make retries idempotent).</summary>
    public async Task<int> FlushAsync(CancellationToken ct)
    {
        var sent = 0;
        while (true)
        {
            var batch = queue.Peek(BatchSize);
            if (batch.Count == 0) return sent;
            await api.SendEventsAsync(new SecurityEventBatch(batch), ct).ConfigureAwait(false);
            health.CloudSucceeded();
            queue.Remove(batch.Count);
            sent += batch.Count;
        }
    }
}
