namespace BrowserSecurity.Agent.Shared;

/// <summary>Values that must match the TypeScript side (packages/shared/src/constants.ts).</summary>
public static class AgentConstants
{
    public const string AgentVersion = "0.1.0";
    public const string NativeHostName = "com.vector58.browser_security";
    public const string ServiceName = "Vector58BrowserSecurity";
    public const string ServiceDisplayName = "Vector58 Browser Security Agent";

    /// <summary>Pipe used by the native messaging host (one connection per browser profile).</summary>
    public const string BrowserPipeName = "Vector58.BrowserSecurity.Browser";

    /// <summary>Read-mostly status pipe used by the tray application.</summary>
    public const string StatusPipeName = "Vector58.BrowserSecurity.Status";

    public const int PolicySchemaVersion = 1;
    public const int NativeProtocolVersion = 1;
    public const long MaxPolicyRuleId = 1L << 29;

    /// <summary>Chromium refuses host-to-extension messages larger than 1 MiB.</summary>
    public const int MaxMessageToBrowserBytes = 1024 * 1024;

    /// <summary>Chromium allows 64 MiB extension-to-host; we accept far less.</summary>
    public const int MaxMessageFromBrowserBytes = 4 * 1024 * 1024;

    public const string DeviceAuthScheme = "Device";
    public const string ApiV1Prefix = "/api/v1";
}
