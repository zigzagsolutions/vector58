using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service;
using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Commands;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Shared.Api;

namespace BrowserSecurity.Agent.Tests;

public sealed class AgentFixture : IDisposable
{
    public static readonly Guid Org2 = Guid.Parse("00000000-0000-4000-a000-000000000002");
    public TempDir Dir { get; } = new();
    public FakeApi Api { get; } = new();
    public FakeBridge Bridge { get; } = new();
    public MemoryQueue Events { get; } = new();
    public FakeIdentity Identity { get; } = FakeIdentity.EnrolledIn(Org2);
    public AgentHealth Health { get; } = new(TimeProvider.System);
    public PolicyStore Store { get; }
    public PolicySyncService Sync { get; }
    public CommandService Commands { get; }

    public AgentFixture()
    {
        Store = new PolicyStore(TestOptions.For(Dir.Path), Log.For<PolicyStore>(), TimeProvider.System);
        Sync = new PolicySyncService(Api, Identity, Store, Bridge, Events, Health, TimeProvider.System, Log.For<PolicySyncService>());
        Commands = new CommandService(Api, Sync, Store, Bridge, Events, new FakeSystem(), Health, TimeProvider.System, Log.For<CommandService>());
    }

    public static DevicePolicyResponse Updated(JsonObject payload) => new("updated", payload["policyVersion"]!.GetValue<int>(), payload);

    public void Dispose()
    {
        Sync.Dispose();
        Dir.Dispose();
    }
}

public class PolicySyncTests
{
    [Fact]
    public async Task Stores_and_pushes_a_new_valid_policy()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => AgentFixture.Updated(Vectors.Policy(1));
        Assert.Equal(PolicySyncOutcome.Updated, await f.Sync.SyncAsync(default));
        Assert.Equal(2, f.Store.Current!.PolicyVersion);
        Assert.Single(f.Bridge.Broadcasts);
        Assert.NotNull(f.Health.LastCloudContactAt);
    }

    [Fact]
    public async Task Sends_cached_version_and_accepts_current()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => AgentFixture.Updated(Vectors.Policy(1));
        await f.Sync.SyncAsync(default);
        int? sent = null;
        f.Api.Policy = v =>
        {
            sent = v;
            return new DevicePolicyResponse("current", v, null);
        };
        Assert.Equal(PolicySyncOutcome.Current, await f.Sync.SyncAsync(default));
        Assert.Equal(2, sent);
        Assert.Single(f.Bridge.Broadcasts);
    }

    [Fact]
    public async Task Rejects_checksum_mismatch_keeps_previous_and_reports_policy_failed()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => AgentFixture.Updated(Vectors.Policy(1));
        await f.Sync.SyncAsync(default);

        var tampered = Vectors.Policy(1);
        tampered["policyVersion"] = 3;
        f.Api.Policy = _ => new DevicePolicyResponse("updated", 3, tampered);
        Assert.Equal(PolicySyncOutcome.Rejected, await f.Sync.SyncAsync(default));
        Assert.Equal(2, f.Store.Current!.PolicyVersion);
        Assert.Single(f.Bridge.Broadcasts);
        var evt = Assert.Single(f.Events.Items);
        Assert.Equal("POLICY_FAILED", Json.Str(evt, "eventType"));
        Assert.Equal(2, evt["details"]!["keptPolicyVersion"]!.GetValue<int>());
    }

    [Fact]
    public async Task Rejects_a_policy_for_another_tenant()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => AgentFixture.Updated(Vectors.Policy(0)); // org ...0001; device is in org ...0002
        Assert.Equal(PolicySyncOutcome.Rejected, await f.Sync.SyncAsync(default));
        Assert.Null(f.Store.Current);
        Assert.Empty(f.Bridge.Broadcasts);
    }

    [Fact]
    public async Task Rejects_envelope_payload_version_mismatch()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => new DevicePolicyResponse("updated", 7, Vectors.Policy(1));
        Assert.Equal(PolicySyncOutcome.Rejected, await f.Sync.SyncAsync(default));
    }

    [Fact]
    public async Task Keeps_last_known_good_when_the_cloud_is_unreachable()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => AgentFixture.Updated(Vectors.Policy(1));
        await f.Sync.SyncAsync(default);
        f.Api.Fail = new HttpRequestException("No such host is known.");
        Assert.Equal(PolicySyncOutcome.Unreachable, await f.Sync.SyncAsync(default));
        Assert.Equal(2, f.Store.Current!.PolicyVersion);
        Assert.Equal("No such host is known.", f.Health.LastCloudError);
        Assert.Empty(f.Events.Items);
    }

    [Fact]
    public async Task Does_nothing_when_not_enrolled()
    {
        using var f = new AgentFixture();
        f.Identity.Clear();
        Assert.Equal(PolicySyncOutcome.NotEnrolled, await f.Sync.SyncAsync(default));
    }
}

public class CommandTests
{
    private static DeviceCommand Cmd(string type, JsonObject? payload = null, DateTimeOffset? expires = null) =>
        new(Guid.NewGuid(), type, payload ?? [], DateTimeOffset.UtcNow, expires ?? DateTimeOffset.UtcNow.AddHours(1));

    [Fact]
    public async Task Refresh_policy_syncs_and_reports_version()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => AgentFixture.Updated(Vectors.Policy(1));
        f.Api.Commands.Add(Cmd(CommandTypes.RefreshPolicy));
        Assert.Equal(1, await f.Commands.PollAndExecuteAsync(default));
        var (_, result) = f.Api.Results.Single();
        Assert.Equal("COMPLETED", result.Status);
        Assert.Equal(2, result.Result!["policyVersion"]!.GetValue<int>());
    }

    [Fact]
    public async Task Browser_history_collection_is_not_supported_in_phase_1()
    {
        using var f = new AgentFixture();
        var incident = Guid.NewGuid().ToString();
        f.Api.Commands.Add(Cmd(CommandTypes.CollectBrowserHistory, new JsonObject { ["incidentId"] = incident, ["startTime"] = "2026-10-27T00:00:00Z", ["endTime"] = "2026-10-28T00:00:00Z" }));
        await f.Commands.PollAndExecuteAsync(default);
        var (_, result) = f.Api.Results.Single();
        Assert.Equal("FAILED", result.Status);
        Assert.StartsWith("NOT_SUPPORTED", result.Error, StringComparison.Ordinal);
        Assert.Equal(incident, Json.Str(result.Result, "incidentId"));
    }

    [Fact]
    public async Task Diagnostics_contain_operational_data_only()
    {
        using var f = new AgentFixture();
        f.Api.Commands.Add(Cmd(CommandTypes.CollectDiagnostics));
        await f.Commands.PollAndExecuteAsync(default);
        var (_, result) = f.Api.Results.Single();
        Assert.Equal("COMPLETED", result.Status);
        var keys = result.Result!.Select(kv => kv.Key).ToHashSet();
        Assert.Equal(new HashSet<string> { "agent", "policy", "queuedEvents", "browsers", "extensions", "collectedAt" }, keys);
        Assert.DoesNotContain("bspd_", result.Result!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Expired_and_unknown_commands_fail_without_running()
    {
        using var f = new AgentFixture();
        f.Api.Policy = _ => throw new InvalidOperationException("must not sync");
        f.Api.Commands.Add(Cmd(CommandTypes.RefreshPolicy, expires: DateTimeOffset.UtcNow.AddMinutes(-1)));
        f.Api.Commands.Add(Cmd("RUN_POWERSHELL"));
        await f.Commands.PollAndExecuteAsync(default);
        Assert.All(f.Api.Results, r => Assert.Equal("FAILED", r.Result.Status));
        Assert.Contains("expired", f.Api.Results[0].Result.Error, StringComparison.Ordinal);
        Assert.StartsWith("NOT_SUPPORTED", f.Api.Results[1].Result.Error, StringComparison.Ordinal);
    }
}

public class EnrollmentTests
{
    [Fact]
    public async Task Exchanges_token_file_for_credentials_and_deletes_it()
    {
        using var tmp = new TempDir();
        var options = TestOptions.For(tmp.Path);
        File.WriteAllText(options.Value.EnrollmentTokenPath, "dev-internal-enroll-token-0000000001\n");
        var api = new FakeApi
        {
            Enroll = r => new EnrollmentResponse(Guid.NewGuid(), AgentFixture.Org2, "Acme", "bspd_new", 60, 300, DateTimeOffset.UtcNow),
        };
        var identity = new FakeIdentity();
        var svc = new EnrollmentService(options, api, identity, new FakeSystem(), Log.For<EnrollmentService>());
        Assert.True(await svc.EnsureEnrolledAsync(default));
        Assert.Equal("dev-internal-enroll-token-0000000001", api.Enrollments.Single().EnrollmentToken);
        Assert.Equal(identity.InstallationId, api.Enrollments.Single().InstallationId);
        Assert.False(File.Exists(options.Value.EnrollmentTokenPath));
        Assert.Equal("bspd_new", identity.GetSecret());
    }

    [Fact]
    public async Task Deletes_rejected_tokens_instead_of_retrying_forever()
    {
        using var tmp = new TempDir();
        var options = TestOptions.For(tmp.Path);
        File.WriteAllText(options.Value.EnrollmentTokenPath, "revoked-token-000000000");
        var api = new FakeApi { Fail = new ApiException(System.Net.HttpStatusCode.Unauthorized, "UNAUTHENTICATED", "Invalid enrollment token") };
        var svc = new EnrollmentService(options, api, new FakeIdentity(), new FakeSystem(), Log.For<EnrollmentService>());
        Assert.False(await svc.EnsureEnrolledAsync(default));
        Assert.False(File.Exists(options.Value.EnrollmentTokenPath));
    }

    [Fact]
    public async Task Network_failures_keep_the_token_for_retry()
    {
        using var tmp = new TempDir();
        var options = TestOptions.For(tmp.Path);
        File.WriteAllText(options.Value.EnrollmentTokenPath, "dev-internal-enroll-token-0000000001");
        var api = new FakeApi { Fail = new HttpRequestException("offline") };
        var svc = new EnrollmentService(options, api, new FakeIdentity(), new FakeSystem(), Log.For<EnrollmentService>());
        await Assert.ThrowsAsync<HttpRequestException>(() => svc.EnsureEnrolledAsync(default));
        Assert.True(File.Exists(options.Value.EnrollmentTokenPath));
    }
}

public class EventQueueTests
{
    [Fact]
    public void Persists_across_restarts_and_removes_only_uploaded_events()
    {
        using var tmp = new TempDir();
        var q = new SecurityEventQueue(TestOptions.For(tmp.Path), Log.For<SecurityEventQueue>());
        for (var i = 0; i < 5; i++) q.Enqueue(AgentEvents.Create("AGENT_HEARTBEAT", DateTimeOffset.UtcNow, i));
        q.Remove(2);
        var reopened = new SecurityEventQueue(TestOptions.For(tmp.Path), Log.For<SecurityEventQueue>());
        Assert.Equal(3, reopened.Count);
        Assert.Equal(2, reopened.Peek(1)[0]["policyVersion"]!.GetValue<int>());
    }

    [Fact]
    public void Survives_a_torn_final_line()
    {
        using var tmp = new TempDir();
        var q = new SecurityEventQueue(TestOptions.For(tmp.Path), Log.For<SecurityEventQueue>());
        q.Enqueue(AgentEvents.Create("AGENT_STARTED", DateTimeOffset.UtcNow, null));
        File.AppendAllText(Path.Combine(tmp.Path, "events", "queue.jsonl"), "{\"eventId\":\"trunc");
        Assert.Equal(1, new SecurityEventQueue(TestOptions.For(tmp.Path), Log.For<SecurityEventQueue>()).Count);
    }

    [Fact]
    public async Task Uploader_removes_events_only_after_the_server_accepts_them()
    {
        var q = new MemoryQueue();
        for (var i = 0; i < 1200; i++) q.Enqueue(AgentEvents.Create("AGENT_HEARTBEAT", DateTimeOffset.UtcNow, null));
        var api = new FakeApi();
        Assert.Equal(1200, await new EventUploader(api, q, new AgentHealth(TimeProvider.System)).FlushAsync(default));
        Assert.Equal([500, 500, 200], api.EventBatches.Select(b => b.Events.Count));

        q.Enqueue(AgentEvents.Create("AGENT_HEARTBEAT", DateTimeOffset.UtcNow, null));
        api.Fail = new HttpRequestException("offline");
        await Assert.ThrowsAsync<HttpRequestException>(() => new EventUploader(api, q, new AgentHealth(TimeProvider.System)).FlushAsync(default));
        Assert.Equal(1, q.Count);
    }

    [Fact]
    public void Agent_events_use_api_timestamp_format()
    {
        var e = AgentEvents.Create("AGENT_STARTED", DateTimeOffset.Parse("2026-10-28T12:00:00+02:00", System.Globalization.CultureInfo.InvariantCulture), null);
        Assert.Equal("2026-10-28T10:00:00.000Z", Json.Str(e, "occurredAt"));
        Assert.True(Guid.TryParse(Json.Str(e, "eventId"), out _));
    }
}
