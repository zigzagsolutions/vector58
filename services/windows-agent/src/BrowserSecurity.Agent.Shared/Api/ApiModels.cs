using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace BrowserSecurity.Agent.Shared.Api;

// Mirrors packages/policy-types/src/api.ts. The server derives the tenant
// from the enrollment token or the device credential, never from these bodies.

public sealed record MachineInfo(
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Manufacturer = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Model = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Domain = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? OsBuild = null);

public sealed record EnrollmentRequest(
    string EnrollmentToken,
    Guid InstallationId,
    string Hostname,
    string OsVersion,
    string AgentVersion,
    string? LocalIp,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] MachineInfo? Machine = null);

public sealed record EnrollmentResponse(
    Guid DeviceId,
    Guid OrganizationId,
    string OrganizationName,
    string DeviceSecret,
    int HeartbeatIntervalSeconds,
    int PolicyPollIntervalSeconds,
    DateTimeOffset EnrolledAt);

public sealed record BrowserClientReport(
    string ClientId,
    string Browser,
    string? BrowserVersion,
    string? ExtensionVersion,
    int? PolicyVersion,
    bool NativeConnected,
    int? DnrRuleCount);

public sealed record AgentHeartbeat(
    string Hostname,
    string OsVersion,
    string AgentVersion,
    string? LocalIp,
    int? PolicyVersion,
    string? PolicyChecksum,
    long UptimeSeconds,
    IReadOnlyList<BrowserClientReport> BrowserClients);

public sealed record HeartbeatResponse(DateTimeOffset ServerTime, int? LatestPolicyVersion, int PendingCommands);

/// <summary>status: current | updated | none. Payload is kept raw for checksum verification.</summary>
public sealed record DevicePolicyResponse(string Status, int? PolicyVersion, JsonObject? Payload);

public sealed record DeviceCommand(Guid Id, string CommandType, JsonObject Payload, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt);

public sealed record DeviceCommandList(IReadOnlyList<DeviceCommand> Commands);

public sealed record CommandResultRequest(
    string Status,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] JsonObject? Result = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Error = null);

/// <summary>Events are forwarded as JSON objects; the server validates and normalizes them.</summary>
public sealed record SecurityEventBatch(IReadOnlyList<JsonObject> Events);

public sealed record SecurityEventIngestResponse(int Accepted, int Duplicates);

public sealed record ApiErrorBody(ApiErrorDetail Error);

public sealed record ApiErrorDetail(string Code, string Message);

public static class CommandTypes
{
    public const string RefreshPolicy = "REFRESH_POLICY";
    public const string CollectDiagnostics = "COLLECT_DIAGNOSTICS";
    public const string CheckExtensionStatus = "CHECK_EXTENSION_STATUS";
    public const string CollectBrowserHistory = "COLLECT_BROWSER_HISTORY";
}

public static class CommandStatuses
{
    public const string Running = "RUNNING";
    public const string Completed = "COMPLETED";
    public const string Failed = "FAILED";
}
