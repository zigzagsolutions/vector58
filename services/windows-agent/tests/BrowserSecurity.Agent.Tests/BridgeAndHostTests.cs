using System.IO.Pipes;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.NativeMessaging;
using BrowserSecurity.Agent.Service;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Service.Status;
using BrowserSecurity.Agent.Shared.Ipc;
using BrowserSecurity.Agent.Shared.Messaging;
using BrowserSecurity.Agent.Shared.Policy;

namespace BrowserSecurity.Agent.Tests;

public sealed class BridgeFixture : IAsyncDisposable
{
    public const string ExtId = "ikgimjohebonbmlfdngiiebaadojbdmp";
    public const string Origin = $"chrome-extension://{ExtId}/";
    public TempDir Dir { get; } = new();
    public MemoryQueue Events { get; } = new();
    public PolicyStore Store { get; }
    public BrowserBridge Bridge { get; }
    public Microsoft.Extensions.Options.IOptions<AgentOptions> Options { get; }
    private readonly CancellationTokenSource _cts = new(TimeSpan.FromSeconds(30));
    private readonly Task _server;

    public BridgeFixture()
    {
        Options = TestOptions.For(Dir.Path);
        Store = new PolicyStore(Options, Log.For<PolicyStore>(), TimeProvider.System);
        Bridge = new BrowserBridge(Options, Store, Events, TimeProvider.System, Log.For<BrowserBridge>());
        _server = Bridge.RunAsync(_cts.Token);
    }

    public CancellationToken Token => _cts.Token;

    public async Task<NamedPipeClientStream> ConnectRawAsync()
    {
        var pipe = new NamedPipeClientStream(".", Options.Value.BrowserPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000, Token);
        return pipe;
    }

    public async Task<NamedPipeClientStream> ConnectAsExtensionAsync(string origin = Origin)
    {
        var pipe = await ConnectRawAsync();
        await MessageFraming.WriteJsonAsync(pipe, new JsonObject { ["type"] = "HOST_HELLO", ["origin"] = origin }, 1 << 20, Token);
        return pipe;
    }

    public static async Task Send(Stream s, string json, CancellationToken ct) => await MessageFraming.WriteJsonAsync(s, JsonNode.Parse(json)!, 1 << 22, ct);

    public static async Task<JsonObject> Receive(Stream s, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        return (await MessageFraming.ReadJsonAsync(s, 1 << 20, timeout.Token))!;
    }

    public static async Task Eventually(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++) await Task.Delay(50);
        Assert.True(condition());
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        try
        {
            await _server;
        }
        catch (OperationCanceledException)
        {
        }
        _cts.Dispose();
        Dir.Dispose();
    }
}

public class BrowserBridgeTests
{
    private const string Health = """{"type":"CLIENT_HEALTH","client":{"clientId":"client-0001","browser":"edge","browserVersion":"131.0","extensionVersion":"0.1.0","policyVersion":null,"nativeConnected":true,"dnrRuleCount":0}}""";

    private static string Event(string type = "URL_BLOCKED") =>
        $$$"""{"type":"SECURITY_EVENT","event":{"eventId":"{{{Guid.NewGuid()}}}","eventType":"{{{type}}}","occurredAt":"2026-10-28T12:00:00.000Z","url":"https://phase1-block-test.example/","ruleId":1}}""";

    [Fact]
    public async Task Serves_cached_policy_on_request_and_tracks_client_health()
    {
        await using var f = new BridgeFixture();
        var policy = PolicyValidator.Validate(Vectors.Policy(1));
        await f.Store.StoreAsync(policy, AgentFixture.Org2, default);

        await using var pipe = await f.ConnectAsExtensionAsync();
        await BridgeFixture.Send(pipe, Health, f.Token);
        await BridgeFixture.Send(pipe, """{"type":"REQUEST_POLICY","currentVersion":null}""", f.Token);
        var update = await BridgeFixture.Receive(pipe, f.Token);
        Assert.Equal("POLICY_UPDATE", Json.Str(update, "type"));
        Assert.Equal(2, update["policyVersion"]!.GetValue<int>());
        Assert.True(PolicyChecksum.Verify((JsonObject)update["payload"]!));

        await BridgeFixture.Send(pipe, """{"type":"POLICY_STATUS","policyVersion":2,"status":"applied","ruleCount":5,"appliedAt":"2026-10-28T12:00:00.000Z"}""", f.Token);
        await BridgeFixture.Eventually(() => f.Bridge.Clients.SingleOrDefault()?.PolicyVersion == 2);
        var client = f.Bridge.Clients.Single();
        Assert.Equal("edge", client.Browser);
        Assert.True(client.Connected);
        Assert.Equal("client-0001", f.Bridge.ClientReports.Single().ClientId);

        pipe.Close();
        await BridgeFixture.Eventually(() => !f.Bridge.Clients.Single().Connected);
    }

    [Fact]
    public async Task Broadcasts_new_policies_to_connected_browsers()
    {
        await using var f = new BridgeFixture();
        await using var a = await f.ConnectAsExtensionAsync();
        await using var b = await f.ConnectAsExtensionAsync();
        await BridgeFixture.Send(a, Health, f.Token);
        await BridgeFixture.Send(b, Health.Replace("client-0001", "client-0002", StringComparison.Ordinal), f.Token);
        await BridgeFixture.Eventually(() => f.Bridge.Clients.Count == 2);

        await f.Bridge.BroadcastPolicyAsync(PolicyValidator.Validate(Vectors.Policy(1)), f.Token);
        Assert.Equal("POLICY_UPDATE", Json.Str(await BridgeFixture.Receive(a, f.Token), "type"));
        Assert.Equal("POLICY_UPDATE", Json.Str(await BridgeFixture.Receive(b, f.Token), "type"));
    }

    [Fact]
    public async Task Queues_valid_extension_events_and_drops_forged_or_agent_only_ones()
    {
        await using var f = new BridgeFixture();
        await using var pipe = await f.ConnectAsExtensionAsync();
        await BridgeFixture.Send(pipe, Event(), f.Token);
        await BridgeFixture.Send(pipe, Event("AGENT_STARTED"), f.Token);    // agent-only type
        await BridgeFixture.Send(pipe, Event("DEVICE_ENROLLED"), f.Token);  // server-only type
        await BridgeFixture.Send(pipe, """{"type":"SECURITY_EVENT","event":{"eventId":"nope","eventType":"URL_BLOCKED","occurredAt":"x"}}""", f.Token);
        await BridgeFixture.Send(pipe, Event().Replace("\"ruleId\":1", $"\"ruleId\":1,\"pad\":\"{new string('x', 20_000)}\"", StringComparison.Ordinal), f.Token);
        await BridgeFixture.Send(pipe, Event("POLICY_FAILED"), f.Token);
        await BridgeFixture.Eventually(() => f.Events.Count == 2);
        await Task.Delay(200);
        Assert.Equal(["URL_BLOCKED", "POLICY_FAILED"], f.Events.Items.Select(e => Json.Str(e, "eventType")));
    }

    [Fact]
    public async Task A_browser_cannot_push_policy_to_the_agent()
    {
        await using var f = new BridgeFixture();
        await using var pipe = await f.ConnectAsExtensionAsync();
        var forged = new JsonObject { ["type"] = "POLICY_UPDATE", ["policyVersion"] = 2, ["payload"] = Vectors.Policy(1) };
        await MessageFraming.WriteJsonAsync(pipe, forged, 1 << 20, f.Token);
        await BridgeFixture.Send(pipe, Event(), f.Token);
        await BridgeFixture.Eventually(() => f.Events.Count == 1);
        Assert.Null(f.Store.Current);
    }

    [Fact]
    public async Task Rejects_connections_without_an_allowed_origin()
    {
        await using var f = new BridgeFixture();
        await using var pipe = await f.ConnectAsExtensionAsync("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/");
        await TrySend(pipe, Event(), f.Token);
        // The server closes the connection without reading further.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(f.Token);
        timeout.CancelAfter(2000);
        Assert.Null(await MessageFraming.ReadFrameAsync(pipe, 1024, timeout.Token));

        await using var noHello = await f.ConnectRawAsync();
        await TrySend(noHello, Event(), f.Token);
        await Task.Delay(200);
        Assert.Equal(0, f.Events.Count);
    }

    private static async Task TrySend(Stream s, string json, CancellationToken ct)
    {
        try
        {
            await BridgeFixture.Send(s, json, ct);
        }
        catch (IOException)
        {
            // Already closed by the server: also a rejection.
        }
    }

    [Fact]
    public async Task Collects_diagnostics_from_connected_extensions()
    {
        await using var f = new BridgeFixture();
        await using var pipe = await f.ConnectAsExtensionAsync();
        await BridgeFixture.Send(pipe, Health, f.Token);
        await BridgeFixture.Eventually(() => f.Bridge.Clients.Count == 1);

        var pending = f.Bridge.RequestDiagnosticsAsync(TimeSpan.FromSeconds(5), f.Token);
        var req = await BridgeFixture.Receive(pipe, f.Token);
        Assert.Equal("DIAGNOSTIC_REQUEST", Json.Str(req, "type"));
        await BridgeFixture.Send(pipe, $$$"""{"type":"DIAGNOSTIC_REQUEST","requestId":"{{{Json.Str(req, "requestId")}}}","response":{"browser":"edge","extensionVersion":"0.1.0","policyVersion":2,"dnrRuleCount":10,"queuedEvents":0,"lastError":null}}""", f.Token);
        var result = Assert.Single(await pending);
        Assert.Equal(10, result["response"]!["dnrRuleCount"]!.GetValue<int>());
    }
}

public class NativeHostRelayTests
{
    private static readonly IReadOnlySet<string> Allowed = new HashSet<string> { BridgeFixture.ExtId };

    [Theory]
    [InlineData("chrome-extension://ikgimjohebonbmlfdngiiebaadojbdmp/", "ikgimjohebonbmlfdngiiebaadojbdmp")]
    [InlineData("chrome-extension://ikgimjohebonbmlfdngiiebaadojbdmp", null)]
    [InlineData("chrome-extension://IKGIMJOHEBONBMLFDNGIIEBAADOJBDMP/", null)]
    [InlineData("https://ikgimjohebonbmlfdngiiebaadojbdmp/", null)]
    [InlineData("chrome-extension://short/", null)]
    public void Parses_extension_origins_strictly(string origin, string? expected) =>
        Assert.Equal(expected, NativeHostRelay.ExtensionIdFromOrigin(origin));

    [Fact]
    public async Task Refuses_unknown_extensions_before_touching_the_service()
    {
        var connected = false;
        var relay = new NativeHostRelay(Allowed, TextWriter.Null);
        var exit = await relay.RunAsync(["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"], Stream.Null, Stream.Null, _ =>
        {
            connected = true;
            return Task.FromResult(Stream.Null);
        }, default);
        Assert.Equal(RelayExit.OriginNotAllowed, exit);
        Assert.False(connected);
        Assert.Equal(RelayExit.BadArguments, await relay.RunAsync([], Stream.Null, Stream.Null, _ => Task.FromResult(Stream.Null), default));
    }

    [Fact]
    public async Task Exits_when_the_agent_service_is_not_running()
    {
        var relay = new NativeHostRelay(Allowed, TextWriter.Null);
        var exit = await relay.RunAsync([BridgeFixture.Origin, "--parent-window=0"], Stream.Null, Stream.Null, async ct =>
        {
            var pipe = new NamedPipeClientStream(".", "bsp-test-missing-" + Guid.NewGuid().ToString("N")[..8], PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(ct);
            return pipe;
        }, default);
        Assert.Equal(RelayExit.ServiceUnavailable, exit);
    }

    /// <summary>Browser (in-memory) -> real native host relay -> real named pipe -> real bridge.</summary>
    [Fact]
    public async Task Relays_end_to_end_between_browser_and_service()
    {
        await using var f = new BridgeFixture();
        await f.Store.StoreAsync(PolicyValidator.Validate(Vectors.Policy(1)), AgentFixture.Org2, default);
        using var browser = new DuplexPipe();
        var relay = new NativeHostRelay(Allowed, TextWriter.Null);
        var run = relay.RunAsync([BridgeFixture.Origin], browser.B, browser.B, async ct =>
        {
            var pipe = new NamedPipeClientStream(".", f.Options.Value.BrowserPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(ct);
            return pipe;
        }, f.Token);

        await BridgeFixture.Send(browser.A, """{"type":"CLIENT_HEALTH","client":{"clientId":"client-0001","browser":"chrome","browserVersion":"131","extensionVersion":"0.1.0","policyVersion":null,"nativeConnected":true,"dnrRuleCount":0}}""", f.Token);
        await BridgeFixture.Send(browser.A, """{"type":"RUN_SCRIPT","code":"calc.exe"}""", f.Token); // dropped by the host
        await BridgeFixture.Send(browser.A, """{"type":"REQUEST_POLICY","currentVersion":null}""", f.Token);
        var update = await BridgeFixture.Receive(browser.A, f.Token);
        Assert.Equal("POLICY_UPDATE", Json.Str(update, "type"));
        Assert.True(PolicyChecksum.Verify((JsonObject)update["payload"]!));

        await BridgeFixture.Send(browser.A, $$$"""{"type":"SECURITY_EVENT","event":{"eventId":"{{{Guid.NewGuid()}}}","eventType":"URL_BLOCKED","occurredAt":"2026-10-28T12:00:00.000Z"}}""", f.Token);
        await BridgeFixture.Eventually(() => f.Events.Count == 1);
        Assert.Equal("chrome", f.Bridge.Clients.Single().Browser);

        browser.A.Dispose(); // browser closes the port
        Assert.Equal(RelayExit.Normal, await run.WaitAsync(TimeSpan.FromSeconds(5)));
    }
}

public class StatusPipeTests
{
    [Fact]
    public async Task Tray_client_reads_status_and_sync_now_is_rate_limited()
    {
        using var tmp = new TempDir();
        var options = TestOptions.For(tmp.Path);
        var store = new PolicyStore(options, Log.For<PolicyStore>(), TimeProvider.System);
        await store.StoreAsync(PolicyValidator.Validate(Vectors.Policy(1)), AgentFixture.Org2, default);
        var identity = FakeIdentity.EnrolledIn(AgentFixture.Org2);
        var health = new AgentHealth(TimeProvider.System);
        health.CloudSucceeded();
        var triggers = new AgentTriggers();
        var server = new StatusServer(options, identity, store, new FakeBridge(), new MemoryQueue(), health, triggers, TimeProvider.System, Log.For<StatusServer>());
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var run = server.RunAsync(cts.Token);

        var client = new StatusClient(options.Value.StatusPipeName);
        var status = await client.GetStatusAsync(cts.Token);
        Assert.NotNull(status);
        Assert.True(status.Enrolled);
        Assert.Equal(2, status.PolicyVersion);
        Assert.Equal("Internal Company", status.OrganizationName);

        Assert.True(await client.RequestSyncAsync(cts.Token));
        Assert.False(await client.RequestSyncAsync(cts.Token));

        await cts.CancelAsync();
        await run;
    }

    [Fact]
    public async Task Client_reports_null_when_service_is_down() =>
        Assert.Null(await new StatusClient("bsp-test-nothing-" + Guid.NewGuid().ToString("N")[..8]).GetStatusAsync());
}

public class TrayPresenterTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-28T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    private static AgentStatusSnapshot Snapshot(int? policy = 2, DateTimeOffset? contact = null, params BrowserStatus[] browsers) =>
        new("0.1.0", true, "Acme", Guid.NewGuid(), policy, 12, Now, contact ?? Now.AddMinutes(-1), null, browsers, 0, "https://portal.example");

    private static BrowserStatus Browser(bool connected = true, int? policy = 2) => new("c-00000001", "edge", "131", "0.1.0", policy, connected, Now);

    [Fact]
    public void Protected_when_enrolled_current_and_browser_in_sync() =>
        Assert.Equal(TrayState.Protected, TrayPresenter.Present(Snapshot(browsers: Browser()), Now).State);

    [Fact]
    public void Degraded_cases()
    {
        Assert.Equal(TrayState.Degraded, TrayPresenter.Present(Snapshot(browsers: Browser(policy: 1)), Now).State);
        Assert.Equal(TrayState.Degraded, TrayPresenter.Present(Snapshot(browsers: Browser(connected: false)), Now).State);
        Assert.Equal(TrayState.Degraded, TrayPresenter.Present(Snapshot(contact: Now.AddHours(-1), browsers: Browser()), Now).State);
        Assert.Equal(TrayState.Degraded, TrayPresenter.Present(Snapshot(policy: null, browsers: Browser()), Now).State);
        Assert.Equal(TrayState.Degraded, TrayPresenter.Present(Snapshot(), Now).State);
    }

    [Fact]
    public void Service_down_and_not_enrolled()
    {
        Assert.Equal(TrayState.ServiceUnavailable, TrayPresenter.Present(null, Now).State);
        var notEnrolled = Snapshot() with { Enrolled = false };
        Assert.Equal(TrayState.NotEnrolled, TrayPresenter.Present(notEnrolled, Now).State);
    }
}
