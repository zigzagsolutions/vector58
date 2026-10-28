using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Commands;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Service.Status;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service;

/// <summary>
/// Orchestrates the agent. Enforcement (cached policy -> browsers) starts
/// before any network call, so a device that boots offline is protected by
/// its last-known-good policy immediately.
/// </summary>
public sealed class AgentRuntime(
    IOptions<AgentOptions> options,
    IPolicyStore store,
    IBrowserBridge bridge,
    StatusServer status,
    EnrollmentService enrollment,
    IHeartbeatService heartbeat,
    IPolicySyncService policySync,
    ICommandService commands,
    EventUploader uploader,
    ISecurityEventQueue events,
    AgentHealth health,
    AgentTriggers triggers,
    TimeProvider time,
    ILogger<AgentRuntime> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var ct = stoppingToken;
        var o = options.Value;
        o.ValidatedApiBaseUri();
        var cached = store.Load();
        log.LogInformation("Agent starting; cached policy {Version}", cached is null ? "none" : $"v{cached.PolicyVersion}");

        var background = new List<Task>
        {
            bridge.RunAsync(ct),
            status.RunAsync(ct),
        };

        events.Enqueue(AgentEvents.Create("AGENT_STARTED", time.GetUtcNow(), cached?.PolicyVersion));

        await WaitForEnrollmentAsync(ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) return;

        background.Add(Loop("heartbeat", TimeSpan.FromSeconds(o.HeartbeatIntervalSeconds), triggers.Heartbeat, async c =>
        {
            var hb = await heartbeat.SendAsync(c).ConfigureAwait(false);
            if (hb.LatestPolicyVersion is { } latest && latest != store.Current?.PolicyVersion) triggers.Policy.Set();
            if (hb.PendingCommands > 0) triggers.Commands.Set();
        }, ct));
        background.Add(Loop("policy", TimeSpan.FromSeconds(o.PolicyPollIntervalSeconds), triggers.Policy, c => policySync.SyncAsync(c), ct));
        background.Add(Loop("commands", TimeSpan.FromSeconds(o.CommandPollIntervalSeconds), triggers.Commands, c => commands.PollAndExecuteAsync(c), ct));
        background.Add(Loop("events", TimeSpan.FromSeconds(o.EventFlushIntervalSeconds), new AgentTriggers.Signal(), c => uploader.FlushAsync(c), ct));

        try
        {
            await Task.WhenAll(background).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Shutdown.
        }
    }

    private async Task WaitForEnrollmentAsync(CancellationToken ct)
    {
        var attempt = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (await enrollment.EnsureEnrolledAsync(ct).ConfigureAwait(false)) return;
            }
            catch (Exception e) when (e is HttpRequestException or ApiException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                health.CloudFailed(e.Message);
                log.LogWarning("Enrollment attempt failed: {Error}", e.Message);
            }
            var delay = TimeSpan.FromSeconds(Math.Min(300, 5 * Math.Pow(2, Math.Min(attempt++, 6))));
            try
            {
                await Task.Delay(delay, time, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task Loop(string name, TimeSpan interval, AgentTriggers.Signal signal, Func<CancellationToken, Task> body, CancellationToken ct)
    {
        var failures = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await body(ct).ConfigureAwait(false);
                failures = 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (NotEnrolledException)
            {
                // Identity was cleared (revocation); stay protected and wait for a new enrollment token.
                await WaitForEnrollmentAsync(ct).ConfigureAwait(false);
            }
            catch (ApiException e) when (e.IsAuthFailure)
            {
                failures++;
                health.CloudFailed($"Device credential rejected ({e.Code}). The device may be revoked or its organization disabled.");
                log.LogError("{Loop}: device credential rejected ({Code}); enforcement continues with cached policy", name, e.Code);
            }
            catch (Exception e) when (e is HttpRequestException or ApiException or TaskCanceledException or IOException)
            {
                failures++;
                health.CloudFailed(e.Message);
                log.LogWarning("{Loop} failed ({Failures} in a row): {Error}", name, failures, e.Message);
            }
            catch (Exception e)
            {
                failures++;
                log.LogError(e, "{Loop} crashed; will retry", name);
            }

            // Back off on repeated failures, up to 10 minutes, so an outage does not hammer the API.
            var wait = failures == 0 ? interval : TimeSpan.FromSeconds(Math.Min(600, interval.TotalSeconds * Math.Pow(2, Math.Min(failures, 4))));
            try
            {
                await signal.WaitAsync(wait, time, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
