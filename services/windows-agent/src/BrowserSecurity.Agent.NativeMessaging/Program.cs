using System.IO.Pipes;
using BrowserSecurity.Agent.NativeMessaging;
using BrowserSecurity.Agent.Shared;

// Started by Chrome/Edge via the native messaging manifest
// (com.vector58.browser_security.json). Never write to stdout here except
// protocol frames.
var configPath = Path.Combine(AppContext.BaseDirectory, "nativehost.json");
var allowed = NativeHostRelay.LoadAllowedIds(configPath);
var pipeName = Environment.GetEnvironmentVariable("BSP_AGENT_BROWSER_PIPE") ?? AgentConstants.BrowserPipeName;
var relay = new NativeHostRelay(allowed, Console.Error);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var exit = await relay.RunAsync(
    args,
    Console.OpenStandardInput(),
    Console.OpenStandardOutput(),
    async ct =>
    {
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(ct);
        return pipe;
    },
    cts.Token);
return (int)exit;
