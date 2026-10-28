using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Api;
using Microsoft.Extensions.Logging;

namespace BrowserSecurity.Agent.Service.Commands;

public interface ICommandService
{
    /// <summary>Fetches pending commands and executes them. Returns the number executed.</summary>
    Task<int> PollAndExecuteAsync(CancellationToken ct);
}

/// <summary>
/// Executes the fixed Phase 1 command set. There is no generic "run this"
/// command: the agent never executes code or scripts delivered remotely.
/// </summary>
public sealed class CommandService(
    IApiClient api,
    IPolicySyncService policySync,
    IPolicyStore store,
    IBrowserBridge bridge,
    ISecurityEventQueue events,
    ISystemInfo system,
    AgentHealth health,
    TimeProvider time,
    ILogger<CommandService> log) : ICommandService
{
    public static readonly TimeSpan BrowserDiagnosticsTimeout = TimeSpan.FromSeconds(5);
    public const string NotSupported = "NOT_SUPPORTED";

    public async Task<int> PollAndExecuteAsync(CancellationToken ct)
    {
        var commands = await api.GetCommandsAsync(ct).ConfigureAwait(false);
        health.CloudSucceeded();
        foreach (var cmd in commands)
        {
            CommandResultRequest result;
            try
            {
                result = cmd.ExpiresAt <= time.GetUtcNow()
                    ? new CommandResultRequest(CommandStatuses.Failed, Error: "Command expired before execution")
                    : await ExecuteAsync(cmd, ct).ConfigureAwait(false);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                log.LogError(e, "Command {Id} ({Type}) failed", cmd.Id, cmd.CommandType);
                result = new CommandResultRequest(CommandStatuses.Failed, Error: e.Message.Length > 2000 ? e.Message[..2000] : e.Message);
            }
            await api.SubmitCommandResultAsync(cmd.Id, result, ct).ConfigureAwait(false);
            log.LogInformation("Command {Id} ({Type}) -> {Status}", cmd.Id, cmd.CommandType, result.Status);
        }
        return commands.Count;
    }

    internal async Task<CommandResultRequest> ExecuteAsync(DeviceCommand cmd, CancellationToken ct)
    {
        switch (cmd.CommandType)
        {
            case CommandTypes.RefreshPolicy:
            {
                var outcome = await policySync.SyncAsync(ct).ConfigureAwait(false);
                var result = new JsonObject { ["outcome"] = outcome.ToString(), ["policyVersion"] = store.Current?.PolicyVersion };
                return outcome is PolicySyncOutcome.Rejected or PolicySyncOutcome.Unreachable
                    ? new CommandResultRequest(CommandStatuses.Failed, result, $"Policy refresh {outcome}")
                    : new CommandResultRequest(CommandStatuses.Completed, result);
            }
            case CommandTypes.CheckExtensionStatus:
                return new CommandResultRequest(CommandStatuses.Completed, new JsonObject
                {
                    ["agentPolicyVersion"] = store.Current?.PolicyVersion,
                    ["browsers"] = BrowsersJson(),
                    ["extensions"] = new JsonArray([.. await bridge.RequestDiagnosticsAsync(BrowserDiagnosticsTimeout, ct).ConfigureAwait(false)]),
                    ["checkedAt"] = AgentJson.Timestamp(time.GetUtcNow()),
                });
            case CommandTypes.CollectDiagnostics:
                return new CommandResultRequest(CommandStatuses.Completed, await DiagnosticsAsync(ct).ConfigureAwait(false));
            case CommandTypes.CollectBrowserHistory:
                // Phase 1: browsing history is never collected. The command is
                // acknowledged so the incident timeline shows the request and outcome.
                return new CommandResultRequest(
                    CommandStatuses.Failed,
                    new JsonObject { ["code"] = NotSupported, ["incidentId"] = cmd.Payload["incidentId"]?.DeepClone() },
                    $"{NotSupported}: browser history collection is not available in this agent version");
            default:
                return new CommandResultRequest(CommandStatuses.Failed, new JsonObject { ["code"] = NotSupported }, $"{NotSupported}: unknown command type {cmd.CommandType}");
        }
    }

    private JsonArray BrowsersJson() => new([
        .. bridge.Clients.Select(b => (JsonNode)new JsonObject
        {
            ["clientId"] = b.ClientId,
            ["browser"] = b.Browser,
            ["browserVersion"] = b.BrowserVersion,
            ["extensionVersion"] = b.ExtensionVersion,
            ["policyVersion"] = b.PolicyVersion,
            ["connected"] = b.Connected,
            ["lastSeenAt"] = AgentJson.Timestamp(b.LastSeenAt),
        }),
    ]);

    /// <summary>Operational data only: versions, health, counts. No browsing data, files or credentials.</summary>
    private async Task<JsonObject> DiagnosticsAsync(CancellationToken ct)
    {
        var policy = store.Current;
        return new JsonObject
        {
            ["agent"] = new JsonObject
            {
                ["version"] = AgentConstants.AgentVersion,
                ["hostname"] = system.Hostname,
                ["osVersion"] = system.OsVersion,
                ["uptimeSeconds"] = health.UptimeSeconds,
                ["lastCloudContactAt"] = health.LastCloudContactAt is { } t ? AgentJson.Timestamp(t) : null,
                ["lastCloudError"] = health.LastCloudError,
            },
            ["policy"] = policy is null ? null : new JsonObject
            {
                ["version"] = policy.PolicyVersion,
                ["checksum"] = policy.Checksum,
                ["ruleCount"] = policy.Rules.Count,
                ["storedAt"] = store.StoredAt is { } s ? AgentJson.Timestamp(s) : null,
            },
            ["queuedEvents"] = events.Count,
            ["browsers"] = BrowsersJson(),
            ["extensions"] = new JsonArray([.. await bridge.RequestDiagnosticsAsync(BrowserDiagnosticsTimeout, ct).ConfigureAwait(false)]),
            ["collectedAt"] = AgentJson.Timestamp(time.GetUtcNow()),
        };
    }
}
