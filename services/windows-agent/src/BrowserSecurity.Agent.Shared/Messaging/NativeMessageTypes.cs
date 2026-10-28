namespace BrowserSecurity.Agent.Shared.Messaging;

/// <summary>Message types from packages/policy-types/src/native-messaging.ts.</summary>
public static class NativeMessageTypes
{
    public const string PolicyUpdate = "POLICY_UPDATE";
    public const string PolicyStatus = "POLICY_STATUS";
    public const string RequestPolicy = "REQUEST_POLICY";
    public const string ClientHealth = "CLIENT_HEALTH";
    public const string SecurityEvent = "SECURITY_EVENT";
    public const string CollectHistory = "COLLECT_HISTORY";
    public const string DiagnosticRequest = "DIAGNOSTIC_REQUEST";

    /// <summary>Sent by the native host to the service before relaying; never by the browser.</summary>
    public const string HostHello = "HOST_HELLO";

    /// <summary>What an extension may send. Anything else is dropped by the host and the service.</summary>
    public static readonly IReadOnlySet<string> FromExtension = new HashSet<string>
    {
        PolicyStatus, RequestPolicy, ClientHealth, SecurityEvent, CollectHistory, DiagnosticRequest,
    };

    /// <summary>What the service may send to an extension.</summary>
    public static readonly IReadOnlySet<string> ToExtension = new HashSet<string>
    {
        PolicyUpdate, CollectHistory, DiagnosticRequest,
    };

    /// <summary>Event types an extension may report; agent-only types are rejected.</summary>
    public static readonly IReadOnlySet<string> ExtensionEventTypes = new HashSet<string>
    {
        "URL_BLOCKED", "POLICY_APPLIED", "POLICY_FAILED", "EXTENSION_CONNECTED", "EXTENSION_DISCONNECTED",
    };
}
