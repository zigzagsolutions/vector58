using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Service;
using BrowserSecurity.Agent.Service.Api;
using BrowserSecurity.Agent.Service.Bridge;
using BrowserSecurity.Agent.Service.Events;
using BrowserSecurity.Agent.Service.Identity;
using BrowserSecurity.Agent.Service.Security;
using BrowserSecurity.Agent.Shared.Api;
using BrowserSecurity.Agent.Shared.Ipc;
using BrowserSecurity.Agent.Shared.Policy;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Tests;

public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "bsp-agent-tests-" + Guid.NewGuid().ToString("N"));
    public TempDir() => Directory.CreateDirectory(Path);
    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

public sealed class ManualTime(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
}

public static class Vectors
{
    private static readonly Lazy<JsonObject> Root = new(() =>
        (JsonObject)JsonNode.Parse(File.ReadAllText(System.IO.Path.Combine(AppContext.BaseDirectory, "Fixtures", "vectors.json")))!);

    public static JsonArray Canonical => (JsonArray)Root.Value["canonical"]!;

    /// <summary>Policies compiled by the TypeScript policy engine. [0] has org ...0001 v1, [1] org ...0002 v2.</summary>
    public static JsonObject Policy(int i) => (JsonObject)Root.Value["policies"]![i]!.DeepClone();
}

public sealed class TestOptions
{
    public static IOptions<AgentOptions> For(string dataDir, string apiBase = "https://control.example.test/") =>
        Options.Create(new AgentOptions
        {
            ApiBaseUrl = apiBase,
            DataDirectory = dataDir,
            AllowedExtensionIds = ["ikgimjohebonbmlfdngiiebaadojbdmp"],
            BrowserPipeName = "bsp-test-browser-" + Guid.NewGuid().ToString("N")[..12],
            StatusPipeName = "bsp-test-status-" + Guid.NewGuid().ToString("N")[..12],
            AllowUnprotectedSecretStorage = true,
        });
}

/// <summary>Reversible but visibly transformed, so tests can prove the secret is not stored as plaintext.</summary>
public sealed class FakeProtector : ISecretProtector
{
    public bool IsProtected => true;
    public byte[] Protect(string secret) => [.. System.Text.Encoding.UTF8.GetBytes(secret).Select(b => (byte)(b ^ 0x5A))];
    public string Unprotect(byte[] data) => System.Text.Encoding.UTF8.GetString([.. data.Select(b => (byte)(b ^ 0x5A))]);
}

public sealed class FakeIdentity : IDeviceIdentityProvider
{
    public Guid InstallationId { get; } = Guid.NewGuid();
    public DeviceIdentity? Current { get; set; }
    public string? Secret { get; set; }
    public string? GetSecret() => Current is null ? null : Secret;
    public Task SaveAsync(EnrollmentResponse enrollment, CancellationToken ct)
    {
        Current = new DeviceIdentity(enrollment.DeviceId, enrollment.OrganizationId, enrollment.OrganizationName, enrollment.EnrolledAt, "https://control.example.test/");
        Secret = enrollment.DeviceSecret;
        return Task.CompletedTask;
    }
    public void Clear() => Current = null;

    public static FakeIdentity EnrolledIn(Guid org) => new()
    {
        Current = new DeviceIdentity(Guid.NewGuid(), org, "Internal Company", DateTimeOffset.UtcNow, "https://control.example.test/"),
        Secret = "bspd_test",
    };
}

public sealed class FakeApi : IApiClient
{
    public Func<int?, DevicePolicyResponse> Policy { get; set; } = _ => new DevicePolicyResponse("none", null, null);
    public Exception? Fail { get; set; }
    public List<DeviceCommand> Commands { get; } = [];
    public List<(Guid Id, CommandResultRequest Result)> Results { get; } = [];
    public List<SecurityEventBatch> EventBatches { get; } = [];
    public List<AgentHeartbeat> Heartbeats { get; } = [];
    public List<EnrollmentRequest> Enrollments { get; } = [];
    public Func<EnrollmentRequest, EnrollmentResponse>? Enroll { get; set; }

    private void Check()
    {
        if (Fail is not null) throw Fail;
    }

    public Task<EnrollmentResponse> EnrollAsync(EnrollmentRequest request, CancellationToken ct)
    {
        Check();
        Enrollments.Add(request);
        return Task.FromResult(Enroll!(request));
    }

    public Task<HeartbeatResponse> HeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct)
    {
        Check();
        Heartbeats.Add(heartbeat);
        return Task.FromResult(new HeartbeatResponse(DateTimeOffset.UtcNow, null, 0));
    }

    public Task<DevicePolicyResponse> GetPolicyAsync(int? currentVersion, CancellationToken ct)
    {
        Check();
        return Task.FromResult(Policy(currentVersion));
    }

    public Task<IReadOnlyList<DeviceCommand>> GetCommandsAsync(CancellationToken ct)
    {
        Check();
        IReadOnlyList<DeviceCommand> list = [.. Commands];
        Commands.Clear();
        return Task.FromResult(list);
    }

    public Task SubmitCommandResultAsync(Guid commandId, CommandResultRequest result, CancellationToken ct)
    {
        Check();
        Results.Add((commandId, result));
        return Task.CompletedTask;
    }

    public Task<SecurityEventIngestResponse> SendEventsAsync(SecurityEventBatch batch, CancellationToken ct)
    {
        Check();
        EventBatches.Add(batch);
        return Task.FromResult(new SecurityEventIngestResponse(batch.Events.Count, 0));
    }
}

public sealed class FakeBridge : IBrowserBridge
{
    public List<ValidatedPolicy> Broadcasts { get; } = [];
    public IReadOnlyList<BrowserStatus> Clients { get; set; } = [];
    public IReadOnlyList<BrowserClientReport> ClientReports { get; set; } = [];
    public Task BroadcastPolicyAsync(ValidatedPolicy policy, CancellationToken ct)
    {
        Broadcasts.Add(policy);
        return Task.CompletedTask;
    }
    public Task<IReadOnlyList<JsonObject>> RequestDiagnosticsAsync(TimeSpan timeout, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<JsonObject>>([]);
    public Task RunAsync(CancellationToken ct) => Task.CompletedTask;
}

public sealed class FakeSystem : ISystemInfo
{
    public string Hostname => "TEST-PC-01";
    public string OsVersion => "Microsoft Windows 10.0.26100";
    public string? LocalIp => "10.0.0.15";
}

public sealed class MemoryQueue : ISecurityEventQueue
{
    public List<JsonObject> Items { get; } = [];
    public int Count => Items.Count;
    public void Enqueue(JsonObject securityEvent) => Items.Add(securityEvent);
    public IReadOnlyList<JsonObject> Peek(int max) => Items.Take(max).ToList();
    public void Remove(int count) => Items.RemoveRange(0, Math.Min(count, Items.Count));
}

/// <summary>Bidirectional in-process stream built from two anonymous pipes.</summary>
public sealed class DuplexPipe : IDisposable
{
    private readonly AnonymousPipeServerStream _aOut = new(PipeDirection.Out);
    private readonly AnonymousPipeServerStream _bOut = new(PipeDirection.Out);
    private readonly AnonymousPipeClientStream _aIn;
    private readonly AnonymousPipeClientStream _bIn;

    public DuplexPipe()
    {
        _bIn = new AnonymousPipeClientStream(PipeDirection.In, _aOut.ClientSafePipeHandle);
        _aIn = new AnonymousPipeClientStream(PipeDirection.In, _bOut.ClientSafePipeHandle);
        A = new Duplex(_aIn, _aOut);
        B = new Duplex(_bIn, _bOut);
    }

    /// <summary>Writes to A arrive at B and vice versa.</summary>
    public Stream A { get; }
    public Stream B { get; }

    public void Dispose()
    {
        foreach (var s in new Stream[] { _aOut, _bOut, _aIn, _bIn }) s.Dispose();
    }

    private sealed class Duplex(Stream read, Stream write) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => write.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => write.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => read.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => read.ReadAsync(buffer, cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => write.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => write.WriteAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) write.Dispose();
            base.Dispose(disposing);
        }
    }
}

public static class Log
{
    public static NullLogger<T> For<T>() => NullLogger<T>.Instance;
}

public static class Json
{
    public static JsonObject Obj(string json) => (JsonObject)JsonNode.Parse(json)!;
    public static string? Str(JsonNode? n, string key) => n?[key] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : null;
}
