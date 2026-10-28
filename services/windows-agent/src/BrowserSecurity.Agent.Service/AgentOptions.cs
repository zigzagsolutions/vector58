using BrowserSecurity.Agent.Shared;

namespace BrowserSecurity.Agent.Service;

public sealed class AgentOptions
{
    public const string Section = "Agent";

    /// <summary>Base URL of the control plane, e.g. https://security.example.com. Must be https.</summary>
    public string ApiBaseUrl { get; set; } = "";

    /// <summary>Shown in the tray; not used for authentication.</summary>
    public string? PortalUrl { get; set; }

    /// <summary>Machine-wide state: identity, protected secret, cached policy, event queue.</summary>
    public string DataDirectory { get; set; } = DefaultDataDirectory();

    public int HeartbeatIntervalSeconds { get; set; } = 60;
    public int PolicyPollIntervalSeconds { get; set; } = 300;
    public int CommandPollIntervalSeconds { get; set; } = 60;
    public int EventFlushIntervalSeconds { get; set; } = 15;

    /// <summary>Extension IDs allowed to talk to the agent (checked by the native host and again here).</summary>
    public List<string> AllowedExtensionIds { get; set; } = [];

    /// <summary>Development only: permit http:// for localhost control planes.</summary>
    public bool AllowInsecureLocalhost { get; set; }

    /// <summary>
    /// Development only (non-Windows): store the device secret without DPAPI. Never honoured on Windows.
    /// </summary>
    public bool AllowUnprotectedSecretStorage { get; set; }

    public string BrowserPipeName { get; set; } = AgentConstants.BrowserPipeName;
    public string StatusPipeName { get; set; } = AgentConstants.StatusPipeName;

    public static string DefaultDataDirectory() =>
        OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Vector58", "BrowserSecurity")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "vector58-browser-security");

    public Uri ValidatedApiBaseUri()
    {
        if (!Uri.TryCreate(ApiBaseUrl, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"Agent:ApiBaseUrl '{ApiBaseUrl}' is not an absolute URL");
        if (uri.Scheme == Uri.UriSchemeHttps) return uri;
        if (uri.Scheme == Uri.UriSchemeHttp && AllowInsecureLocalhost && uri.IsLoopback) return uri;
        throw new InvalidOperationException("Agent:ApiBaseUrl must use https (http is only allowed for localhost with AllowInsecureLocalhost)");
    }

    public string EnrollmentTokenPath => Path.Combine(DataDirectory, "enrollment.token");
}
