using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Shared.Policy;
using Microsoft.Extensions.Logging;

namespace BrowserSecurity.Agent.Service.Policy;

public enum PolicySyncOutcome
{
    NotEnrolled,
    Current,
    NoPolicyPublished,
    Updated,
    Rejected,
    Unreachable,
}

public interface IPolicySyncService
{
    Task<PolicySyncOutcome> SyncAsync(CancellationToken ct);
}

/// <summary>
/// Pulls the latest published policy. Failure behaviour (spec):
///   retrieval fails  -> keep last-known-good, retry later;
///   validation fails -> reject, keep previous, report POLICY_FAILED;
///   never remove protection because the control plane is unavailable.
/// </summary>
public sealed class PolicySyncService(
    IApiClient api,
    IDeviceIdentityProvider identity,
    IPolicyStore store,
    IBrowserBridge bridge,
    ISecurityEventQueue events,
    AgentHealth health,
    TimeProvider time,
    ILogger<PolicySyncService> log) : IPolicySyncService, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public void Dispose() => _gate.Dispose();

    public async Task<PolicySyncOutcome> SyncAsync(CancellationToken ct)
    {
        var device = identity.Current;
        if (device is null) return PolicySyncOutcome.NotEnrolled;
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var cached = store.Current;
            var cachedVersion = cached?.OrganizationId == device.OrganizationId ? cached.PolicyVersion : (int?)null;
            DevicePolicyResponseView response;
            try
            {
                var r = await api.GetPolicyAsync(cachedVersion, ct).ConfigureAwait(false);
                response = new DevicePolicyResponseView(r.Status, r.PolicyVersion, r.Payload);
                health.CloudSucceeded();
            }
            catch (Exception e) when (e is HttpRequestException or ApiException or TaskCanceledException && !ct.IsCancellationRequested)
            {
                health.CloudFailed(e.Message);
                log.LogWarning("Policy retrieval failed; keeping cached policy v{Version}: {Error}", cachedVersion, e.Message);
                return PolicySyncOutcome.Unreachable;
            }

            switch (response.Status)
            {
                case "current":
                    return PolicySyncOutcome.Current;
                case "none":
                    return PolicySyncOutcome.NoPolicyPublished;
                case "updated" when response.Payload is not null:
                    break;
                default:
                    return Reject(cachedVersion, response.PolicyVersion, $"Unexpected policy response status '{response.Status}'");
            }

            ValidatedPolicy policy;
            try
            {
                policy = PolicyValidator.Validate(response.Payload!);
                if (policy.PolicyVersion != response.PolicyVersion)
                    throw new PolicyValidationException("Envelope and payload policy versions differ");
                await store.StoreAsync(policy, device.OrganizationId, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is PolicyValidationException or PolicyRejectedException)
            {
                return Reject(cachedVersion, response.PolicyVersion, e.Message);
            }

            log.LogInformation("Policy v{Version} stored ({Rules} rules); pushing to browsers", policy.PolicyVersion, policy.Rules.Count);
            await bridge.BroadcastPolicyAsync(policy, ct).ConfigureAwait(false);
            return PolicySyncOutcome.Updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    private PolicySyncOutcome Reject(int? keptVersion, int? offeredVersion, string error)
    {
        log.LogError("Rejected policy v{Offered}; keeping v{Kept}: {Error}", offeredVersion, keptVersion, error);
        events.Enqueue(AgentEvents.Create("POLICY_FAILED", time.GetUtcNow(), offeredVersion,
            new JsonObject { ["stage"] = "agent", ["error"] = error, ["keptPolicyVersion"] = keptVersion }));
        return PolicySyncOutcome.Rejected;
    }

    private sealed record DevicePolicyResponseView(string Status, int? PolicyVersion, JsonObject? Payload);
}
