using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service;
using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Commands;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Service.Security;
using BrowserSecurity.Agent.Service.Status;
using BrowserSecurity.Agent.Shared;
using BrowserSecurity.Agent.Shared.Ipc;
using BrowserSecurity.Agent.Shared.Messaging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

// Usage:
//   BrowserSecurity.Agent.Service                 run (as a Windows service or in the console)
//   BrowserSecurity.Agent.Service status          print the running service's status as JSON
if (args.Length > 0 && args[0] == "status") return await PrintStatusAsync();

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});
// Machine-level overrides (written by the installer), then BSP_AGENT__* environment variables.
builder.Configuration.AddJsonFile(Path.Combine(AgentOptions.DefaultDataDirectory(), "agentsettings.json"), optional: true, reloadOnChange: false);
builder.Configuration.AddEnvironmentVariables("BSP_");
builder.Services.AddWindowsService(o => o.ServiceName = AgentConstants.ServiceName);
if (OperatingSystem.IsWindows())
{
    // Application log, source "Vector58BrowserSecurity" (the service runs as SYSTEM, which may register the source).
    AgentServices.ConfigureEventLog(builder.Services);
}
AgentServices.Add(builder.Services, builder.Configuration.GetSection(AgentOptions.Section));

using var host = builder.Build();
await host.RunAsync();
return 0;

static async Task<int> PrintStatusAsync()
{
    await using var pipe = new NamedPipeClientStream(".", AgentConstants.StatusPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
    try
    {
        await pipe.ConnectAsync(3000);
    }
    catch (TimeoutException)
    {
        Console.Error.WriteLine("The Browser Security service is not running.");
        return 2;
    }
    await MessageFraming.WriteJsonAsync(pipe, new JsonObject { ["type"] = StatusRequests.GetStatus }, 4096);
    var reply = await MessageFraming.ReadJsonAsync(pipe, AgentConstants.MaxMessageToBrowserBytes);
    Console.WriteLine(reply?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

namespace BrowserSecurity.Agent.Service
{
    public static class AgentServices
    {
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        public static void ConfigureEventLog(IServiceCollection services) =>
            services.Configure<Microsoft.Extensions.Logging.EventLog.EventLogSettings>(s => s.SourceName = AgentConstants.ServiceName);

        public static void Add(IServiceCollection services, Microsoft.Extensions.Configuration.IConfiguration section)
        {
            services.Configure<AgentOptions>(section);
            services.AddSingleton(TimeProvider.System);
            services.AddSingleton<ISecretProtector>(sp =>
            {
                if (OperatingSystem.IsWindows()) return new DpapiSecretProtector();
                var o = sp.GetRequiredService<IOptions<AgentOptions>>().Value;
                if (!o.AllowUnprotectedSecretStorage)
                    throw new PlatformNotSupportedException("Non-Windows hosts require Agent:AllowUnprotectedSecretStorage=true (development only).");
                sp.GetRequiredService<ILogger<UnprotectedDevelopmentSecretProtector>>()
                    .LogWarning("Device secret is stored WITHOUT encryption (development mode)");
                return new UnprotectedDevelopmentSecretProtector();
            });
            services.AddSingleton<ISystemInfo, SystemInfo>();
            services.AddSingleton<AgentHealth>();
            services.AddSingleton<AgentTriggers>();
            services.AddSingleton<IDeviceIdentityProvider, DeviceIdentityProvider>();
            services.AddSingleton<IPolicyStore, PolicyStore>();
            services.AddSingleton<ISecurityEventQueue, SecurityEventQueue>();
            services.AddSingleton<IBrowserBridge, BrowserBridge>();
            services.AddHttpClient<IApiClient, ApiClient>((sp, http) =>
            {
                http.BaseAddress = sp.GetRequiredService<IOptions<AgentOptions>>().Value.ValidatedApiBaseUri();
                http.Timeout = TimeSpan.FromSeconds(30);
                http.DefaultRequestHeaders.UserAgent.ParseAdd($"Vector58-BrowserSecurity-Agent/{AgentConstants.AgentVersion}");
            });
            services.AddSingleton<IPolicySyncService, PolicySyncService>();
            services.AddSingleton<ICommandService, CommandService>();
            services.AddSingleton<IHeartbeatService, HeartbeatService>();
            services.AddSingleton<EventUploader>();
            services.AddSingleton<EnrollmentService>();
            services.AddSingleton<StatusServer>();
            services.AddHostedService<AgentRuntime>();
        }
    }
}
