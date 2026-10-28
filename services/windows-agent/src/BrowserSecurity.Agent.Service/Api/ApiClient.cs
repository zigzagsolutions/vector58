using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Api;

namespace BrowserSecurity.Agent.Service.Api;

public sealed class ApiException(HttpStatusCode status, string code, string message) : Exception($"{(int)status} {code}: {message}")
{
    public HttpStatusCode Status { get; } = status;
    public string Code { get; } = code;

    /// <summary>The device credential was rejected (device revoked, disabled, or tenant disabled).</summary>
    public bool IsAuthFailure => Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
}

public sealed class NotEnrolledException() : Exception("Device is not enrolled");

public interface IApiClient
{
    Task<EnrollmentResponse> EnrollAsync(EnrollmentRequest request, CancellationToken ct);
    Task<HeartbeatResponse> HeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct);
    Task<DevicePolicyResponse> GetPolicyAsync(int? currentVersion, CancellationToken ct);
    Task<IReadOnlyList<DeviceCommand>> GetCommandsAsync(CancellationToken ct);
    Task SubmitCommandResultAsync(Guid commandId, CommandResultRequest result, CancellationToken ct);
    Task<SecurityEventIngestResponse> SendEventsAsync(SecurityEventBatch batch, CancellationToken ct);
}

/// <summary>HTTP client for /api/v1/device/*. Device auth: "Authorization: Device &lt;deviceId&gt;.&lt;secret&gt;".</summary>
public sealed class ApiClient(HttpClient http, IDeviceIdentityProvider identity) : IApiClient
{
    private const string P = AgentConstants.ApiV1Prefix;

    public async Task<EnrollmentResponse> EnrollAsync(EnrollmentRequest request, CancellationToken ct)
    {
        using var msg = new HttpRequestMessage(HttpMethod.Post, $"{P}/device/enroll") { Content = JsonContent.Create(request, options: AgentJson.Options) };
        return await SendAsync<EnrollmentResponse>(msg, ct).ConfigureAwait(false);
    }

    public async Task<HeartbeatResponse> HeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct)
    {
        using var msg = Authed(HttpMethod.Post, $"{P}/device/heartbeat", heartbeat);
        return await SendAsync<HeartbeatResponse>(msg, ct).ConfigureAwait(false);
    }

    public async Task<DevicePolicyResponse> GetPolicyAsync(int? currentVersion, CancellationToken ct)
    {
        var q = currentVersion is { } v ? $"?currentVersion={v}" : "";
        using var msg = Authed(HttpMethod.Get, $"{P}/device/policy{q}");
        return await SendAsync<DevicePolicyResponse>(msg, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DeviceCommand>> GetCommandsAsync(CancellationToken ct)
    {
        using var msg = Authed(HttpMethod.Get, $"{P}/device/commands");
        return (await SendAsync<DeviceCommandList>(msg, ct).ConfigureAwait(false)).Commands;
    }

    public async Task SubmitCommandResultAsync(Guid commandId, CommandResultRequest result, CancellationToken ct)
    {
        using var msg = Authed(HttpMethod.Post, $"{P}/device/commands/{commandId}/result", result);
        await SendAsync<JsonObject>(msg, ct).ConfigureAwait(false);
    }

    public async Task<SecurityEventIngestResponse> SendEventsAsync(SecurityEventBatch batch, CancellationToken ct)
    {
        using var msg = Authed(HttpMethod.Post, $"{P}/events/security", batch);
        return await SendAsync<SecurityEventIngestResponse>(msg, ct).ConfigureAwait(false);
    }

    private HttpRequestMessage Authed(HttpMethod method, string path, object? body = null)
    {
        var id = identity.Current ?? throw new NotEnrolledException();
        var secret = identity.GetSecret() ?? throw new NotEnrolledException();
        var msg = new HttpRequestMessage(method, path);
        msg.Headers.Authorization = new AuthenticationHeaderValue(AgentConstants.DeviceAuthScheme, $"{id.DeviceId}.{secret}");
        if (body is not null) msg.Content = JsonContent.Create(body, body.GetType(), options: AgentJson.Options);
        return msg;
    }

    private async Task<T> SendAsync<T>(HttpRequestMessage msg, CancellationToken ct)
    {
        using var res = await http.SendAsync(msg, ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
        {
            string code = "HTTP_ERROR", message = res.ReasonPhrase ?? "";
            try
            {
                var err = await res.Content.ReadFromJsonAsync<ApiErrorBody>(AgentJson.Options, ct).ConfigureAwait(false);
                if (err?.Error is { } e)
                {
                    code = e.Code;
                    message = e.Message;
                }
            }
            catch (JsonException)
            {
                // Non-JSON error page (proxy, CDN); keep the HTTP status.
            }
            throw new ApiException(res.StatusCode, code, message);
        }
        return await res.Content.ReadFromJsonAsync<T>(AgentJson.Options, ct).ConfigureAwait(false)
               ?? throw new ApiException(res.StatusCode, "EMPTY_RESPONSE", "Empty response body");
    }
}
