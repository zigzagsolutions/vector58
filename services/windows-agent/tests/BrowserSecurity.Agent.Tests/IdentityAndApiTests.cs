using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service;
using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Shared.Api;

namespace BrowserSecurity.Agent.Tests;

public class DeviceIdentityTests
{
    private static readonly EnrollmentResponse Enrollment = new(
        Guid.Parse("f3000000-0000-4000-a000-000000000001"),
        Guid.Parse("00000000-0000-4000-a000-000000000001"),
        "Internal Company",
        "bspd_super-secret-value",
        60, 300, DateTimeOffset.Parse("2026-10-28T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

    [Fact]
    public async Task Stores_identity_and_never_writes_the_secret_in_plaintext()
    {
        using var tmp = new TempDir();
        var provider = new DeviceIdentityProvider(TestOptions.For(tmp.Path), new FakeProtector(), Log.For<DeviceIdentityProvider>());
        Assert.Null(provider.Current);
        await provider.SaveAsync(Enrollment, default);

        var reloaded = new DeviceIdentityProvider(TestOptions.For(tmp.Path), new FakeProtector(), Log.For<DeviceIdentityProvider>());
        Assert.Equal(Enrollment.DeviceId, reloaded.Current!.DeviceId);
        Assert.Equal("bspd_super-secret-value", reloaded.GetSecret());
        foreach (var f in Directory.GetFiles(tmp.Path, "*", SearchOption.AllDirectories))
            Assert.DoesNotContain("super-secret", File.ReadAllText(f), StringComparison.Ordinal);
    }

    [Fact]
    public void Installation_id_is_stable()
    {
        using var tmp = new TempDir();
        var a = new DeviceIdentityProvider(TestOptions.For(tmp.Path), new FakeProtector(), Log.For<DeviceIdentityProvider>()).InstallationId;
        var b = new DeviceIdentityProvider(TestOptions.For(tmp.Path), new FakeProtector(), Log.For<DeviceIdentityProvider>()).InstallationId;
        Assert.Equal(a, b);
    }

    [Fact]
    public async Task Refuses_to_present_credentials_to_a_different_control_plane()
    {
        using var tmp = new TempDir();
        await new DeviceIdentityProvider(TestOptions.For(tmp.Path), new FakeProtector(), Log.For<DeviceIdentityProvider>()).SaveAsync(Enrollment, default);
        var moved = new DeviceIdentityProvider(TestOptions.For(tmp.Path, "https://attacker.example/"), new FakeProtector(), Log.For<DeviceIdentityProvider>());
        Assert.Null(moved.Current);
        Assert.Null(moved.GetSecret());
    }

    [Fact]
    public void Options_require_https_except_explicit_localhost_development()
    {
        Assert.Throws<InvalidOperationException>(() => new AgentOptions { ApiBaseUrl = "http://control.example" }.ValidatedApiBaseUri());
        Assert.Throws<InvalidOperationException>(() => new AgentOptions { ApiBaseUrl = "http://localhost:3000" }.ValidatedApiBaseUri());
        Assert.Throws<InvalidOperationException>(() => new AgentOptions { ApiBaseUrl = "http://10.0.0.5", AllowInsecureLocalhost = true }.ValidatedApiBaseUri());
        new AgentOptions { ApiBaseUrl = "http://localhost:3000", AllowInsecureLocalhost = true }.ValidatedApiBaseUri();
        new AgentOptions { ApiBaseUrl = "https://control.example" }.ValidatedApiBaseUri();
    }
}

public class ApiClientTests
{
    private sealed class Recorder(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string? Body)> Requests { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add((request, body));
            return respond(request);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string json) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static (ApiClient Client, Recorder Handler) Create(Func<HttpRequestMessage, HttpResponseMessage> respond, FakeIdentity? identity = null)
    {
        var handler = new Recorder(respond);
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://control.example.test/") };
        return (new ApiClient(http, identity ?? FakeIdentity.EnrolledIn(Guid.NewGuid())), handler);
    }

    [Fact]
    public async Task Sends_device_credentials_and_camel_case_bodies_with_utc_timestamps()
    {
        var identity = FakeIdentity.EnrolledIn(Guid.NewGuid());
        var (client, handler) = Create(_ => Json(HttpStatusCode.OK, "{\"serverTime\":\"2026-10-28T12:00:00.000Z\",\"latestPolicyVersion\":3,\"pendingCommands\":1}"), identity);
        var hb = await client.HeartbeatAsync(new AgentHeartbeat("PC", "Windows", "0.1.0", null, 2, "abc", 10,
            [new BrowserClientReport("client-123456", "edge", "131", "0.1.0", 2, true, 4)]), default);

        Assert.Equal(3, hb.LatestPolicyVersion);
        var (req, body) = handler.Requests.Single();
        Assert.Equal("/api/v1/device/heartbeat", req.RequestUri!.AbsolutePath);
        Assert.Equal("Device", req.Headers.Authorization!.Scheme);
        Assert.Equal($"{identity.Current!.DeviceId}.bspd_test", req.Headers.Authorization.Parameter);
        var json = JsonNode.Parse(body!)!;
        Assert.Equal("PC", json["hostname"]!.GetValue<string>());
        Assert.Equal("edge", json["browserClients"]![0]!["browser"]!.GetValue<string>());
        Assert.Null(json["localIp"]); // serialized as explicit null, which the schema allows
    }

    [Fact]
    public async Task Enrollment_carries_no_device_credentials_or_tenant_identifiers()
    {
        var (client, handler) = Create(_ => Json(HttpStatusCode.Created,
            "{\"deviceId\":\"f3000000-0000-4000-a000-000000000001\",\"organizationId\":\"00000000-0000-4000-a000-000000000001\",\"organizationName\":\"Internal\",\"deviceSecret\":\"bspd_x\",\"heartbeatIntervalSeconds\":60,\"policyPollIntervalSeconds\":300,\"enrolledAt\":\"2026-10-28T12:00:00.000Z\"}"),
            new FakeIdentity());
        var res = await client.EnrollAsync(new EnrollmentRequest("dev-internal-enroll-token-0000000001", Guid.NewGuid(), "PC", "Windows", "0.1.0", null), default);
        Assert.Equal("Internal", res.OrganizationName);
        var (req, body) = handler.Requests.Single();
        Assert.Null(req.Headers.Authorization);
        var json = JsonNode.Parse(body!)!.AsObject();
        Assert.False(json.ContainsKey("organizationId"));
        Assert.False(json.ContainsKey("machine")); // optional, omitted rather than null
    }

    [Fact]
    public async Task Surfaces_api_error_envelopes()
    {
        var (client, _) = Create(_ => Json(HttpStatusCode.Unauthorized, "{\"error\":{\"code\":\"UNAUTHENTICATED\",\"message\":\"Invalid device credentials\"}}"));
        var e = await Assert.ThrowsAsync<ApiException>(() => client.GetPolicyAsync(null, default));
        Assert.True(e.IsAuthFailure);
        Assert.Equal("UNAUTHENTICATED", e.Code);
    }

    [Fact]
    public async Task Refuses_authenticated_calls_when_not_enrolled()
    {
        var (client, handler) = Create(_ => Json(HttpStatusCode.OK, "{}"), new FakeIdentity());
        await Assert.ThrowsAsync<NotEnrolledException>(() => client.GetCommandsAsync(default));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Parses_policy_and_command_responses()
    {
        var policy = Vectors.Policy(1);
        var (client, handler) = Create(req => req.RequestUri!.AbsolutePath switch
        {
            "/api/v1/device/policy" => Json(HttpStatusCode.OK, new JsonObject { ["status"] = "updated", ["policyVersion"] = 2, ["payload"] = policy }.ToJsonString()),
            _ => Json(HttpStatusCode.OK, "{\"commands\":[{\"id\":\"33333333-3333-4333-8333-333333333333\",\"commandType\":\"REFRESH_POLICY\",\"payload\":{},\"issuedAt\":\"2026-10-28T12:00:00.000Z\",\"expiresAt\":\"2026-10-29T12:00:00.000Z\"}]}"),
        });
        var p = await client.GetPolicyAsync(1, default);
        Assert.Equal("?currentVersion=1", handler.Requests[0].Request.RequestUri!.Query);
        Assert.Equal(policy.ToJsonString(), p.Payload!.ToJsonString());
        var cmds = await client.GetCommandsAsync(default);
        Assert.Equal("REFRESH_POLICY", cmds.Single().CommandType);
    }

    [Fact]
    public void Command_results_omit_absent_optional_fields()
    {
        var json = JsonSerializer.Serialize(new CommandResultRequest("COMPLETED"), AgentJson.Options);
        Assert.Equal("{\"status\":\"COMPLETED\"}", json);
    }
}
