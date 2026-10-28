using System.Text;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Shared.Messaging;

namespace BrowserSecurity.Agent.Tests;

public class FramingTests
{
    [Fact]
    public async Task Uses_32_bit_little_endian_length_prefix()
    {
        using var ms = new MemoryStream();
        await MessageFraming.WriteJsonAsync(ms, new JsonObject { ["type"] = "REQUEST_POLICY" }, 1024);
        var bytes = ms.ToArray();
        var body = Encoding.UTF8.GetBytes("{\"type\":\"REQUEST_POLICY\"}");
        Assert.Equal(new byte[] { (byte)body.Length, 0, 0, 0 }, bytes[..4]);
        Assert.Equal(body, bytes[4..]);
    }

    [Fact]
    public async Task Round_trips_multiple_frames_and_reports_clean_eof()
    {
        using var ms = new MemoryStream();
        for (var i = 0; i < 3; i++) await MessageFraming.WriteJsonAsync(ms, new JsonObject { ["n"] = i, ["s"] = "é🛡️" }, 1024);
        ms.Position = 0;
        for (var i = 0; i < 3; i++)
        {
            var m = await MessageFraming.ReadJsonAsync(ms, 1024);
            Assert.Equal(i, m!["n"]!.GetValue<int>());
            Assert.Equal("é🛡️", m["s"]!.GetValue<string>());
        }
        Assert.Null(await MessageFraming.ReadJsonAsync(ms, 1024));
    }

    [Fact]
    public async Task Enforces_size_limits_both_ways()
    {
        using var ms = new MemoryStream();
        await Assert.ThrowsAsync<FramingException>(() => MessageFraming.WriteFrameAsync(ms, new byte[2048], 1024));
        Assert.Equal(0, ms.Length);

        using var big = new MemoryStream([0x00, 0x00, 0x10, 0x00]); // 1 MiB declared
        await Assert.ThrowsAsync<FramingException>(() => MessageFraming.ReadFrameAsync(big, 1024));
    }

    [Fact]
    public async Task Rejects_truncated_and_non_object_frames()
    {
        await Assert.ThrowsAsync<FramingException>(() => MessageFraming.ReadFrameAsync(new MemoryStream([5, 0]), 1024));
        await Assert.ThrowsAsync<FramingException>(() => MessageFraming.ReadFrameAsync(new MemoryStream([5, 0, 0, 0, (byte)'{']), 1024));
        using var arr = new MemoryStream();
        await MessageFraming.WriteFrameAsync(arr, "[1]"u8.ToArray(), 1024);
        arr.Position = 0;
        await Assert.ThrowsAsync<FramingException>(() => MessageFraming.ReadJsonAsync(arr, 1024));
    }
}
