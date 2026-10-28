using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Api;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service.Identity;

/// <summary>
/// First-run enrollment. The installer drops a one-time enrollment token in
/// &lt;data&gt;/enrollment.token (SYSTEM/Administrators only). The service
/// exchanges it for a device credential and deletes the file. The token only
/// identifies the tenant to the server; the agent never chooses its tenant.
/// </summary>
public sealed class EnrollmentService(
    IOptions<AgentOptions> options,
    IApiClient api,
    IDeviceIdentityProvider identity,
    ISystemInfo system,
    ILogger<EnrollmentService> log)
{
    public bool HasPendingToken => File.Exists(options.Value.EnrollmentTokenPath);

    /// <returns>true when the device is enrolled after the call.</returns>
    public async Task<bool> EnsureEnrolledAsync(CancellationToken ct)
    {
        if (identity.Current is not null && identity.GetSecret() is not null && !HasPendingToken) return true;
        if (!HasPendingToken)
        {
            log.LogWarning("Device is not enrolled and no enrollment token is present ({Path})", options.Value.EnrollmentTokenPath);
            return false;
        }

        var token = (await File.ReadAllTextAsync(options.Value.EnrollmentTokenPath, ct).ConfigureAwait(false)).Trim();
        try
        {
            var response = await api.EnrollAsync(new EnrollmentRequest(
                token, identity.InstallationId, system.Hostname, system.OsVersion, AgentConstants.AgentVersion, system.LocalIp), ct).ConfigureAwait(false);
            await identity.SaveAsync(response, ct).ConfigureAwait(false);
            File.Delete(options.Value.EnrollmentTokenPath);
            log.LogInformation("Enrolled as device {DeviceId} in {Organization}", response.DeviceId, response.OrganizationName);
            return true;
        }
        catch (ApiException e) when (e.Status is System.Net.HttpStatusCode.BadRequest or System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.NotFound)
        {
            // Invalid, expired or revoked token: retrying will not help. Remove it so it is not retried forever.
            log.LogError("Enrollment token rejected ({Code}: {Message}); deleting it", e.Code, e.Message);
            File.Delete(options.Value.EnrollmentTokenPath);
            return identity.Current is not null;
        }
    }
}
