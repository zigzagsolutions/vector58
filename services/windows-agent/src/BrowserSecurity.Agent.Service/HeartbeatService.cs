using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Api;

namespace BrowserSecurity.Agent.Service;

public interface IHeartbeatService
{
    Task<HeartbeatResponse> SendAsync(CancellationToken ct);
}

public sealed class HeartbeatService(IApiClient api, IPolicyStore store, IBrowserBridge bridge, ISystemInfo system, AgentHealth health) : IHeartbeatService
{
    public async Task<HeartbeatResponse> SendAsync(CancellationToken ct)
    {
        var policy = store.Current;
        var response = await api.HeartbeatAsync(new AgentHeartbeat(
            system.Hostname,
            system.OsVersion,
            AgentConstants.AgentVersion,
            system.LocalIp,
            policy?.PolicyVersion,
            policy?.Checksum,
            health.UptimeSeconds,
            bridge.ClientReports), ct).ConfigureAwait(false);
        health.CloudSucceeded();
        return response;
    }
}
