namespace BrowserSecurity.Agent.Service;

/// <summary>Wake-up signals so loops can run early (heartbeat says a new policy exists, tray asked for a sync).</summary>
public sealed class AgentTriggers
{
    public Signal Policy { get; } = new();
    public Signal Commands { get; } = new();
    public Signal Heartbeat { get; } = new();

    public void RequestSync()
    {
        Heartbeat.Set();
        Policy.Set();
        Commands.Set();
    }

    public sealed class Signal : IDisposable
    {
        private readonly SemaphoreSlim _sem = new(0, 1);

        public void Dispose() => _sem.Dispose();

        public void Set()
        {
            try
            {
                _sem.Release();
            }
            catch (SemaphoreFullException)
            {
                // Already signalled.
            }
        }

        /// <summary>Waits for the interval or an early signal, whichever comes first.</summary>
        public async Task WaitAsync(TimeSpan interval, TimeProvider time, CancellationToken ct)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var signalled = _sem.WaitAsync(linked.Token);
            var delay = Task.Delay(interval, time, linked.Token);
            await Task.WhenAny(signalled, delay).ConfigureAwait(false);
            await linked.CancelAsync().ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
        }
    }
}
