using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;

namespace BrowserSecurity.Agent.Shared.Messaging;

public sealed class FramingException(string message) : Exception(message);

/// <summary>
/// Chromium native messaging framing: a 32-bit little-endian length followed
/// by UTF-8 JSON. The same framing is used on the agent's named pipes so the
/// native host can relay frames without re-encoding.
/// </summary>
public static class MessageFraming
{
    /// <summary>Reads one frame. Returns null on clean end of stream.</summary>
    public static async Task<byte[]?> ReadFrameAsync(Stream stream, int maxBytes, CancellationToken ct = default)
    {
        var header = new byte[4];
        var read = await ReadExactlyOrEofAsync(stream, header, ct).ConfigureAwait(false);
        if (read == 0) return null;
        if (read < 4) throw new FramingException("Truncated frame header");
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length > (uint)maxBytes) throw new FramingException($"Frame of {length} bytes exceeds limit of {maxBytes}");
        var body = new byte[length];
        if (await ReadExactlyOrEofAsync(stream, body, ct).ConfigureAwait(false) < length)
            throw new FramingException("Truncated frame body");
        return body;
    }

    public static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> body, int maxBytes, CancellationToken ct = default)
    {
        if (body.Length > maxBytes) throw new FramingException($"Frame of {body.Length} bytes exceeds limit of {maxBytes}");
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)body.Length);
        body.CopyTo(frame.AsMemory(4));
        // Single write so concurrent writers serialized by the caller never interleave partial frames.
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static Task WriteJsonAsync(Stream stream, JsonNode message, int maxBytes, CancellationToken ct = default) =>
        WriteFrameAsync(stream, Encoding.UTF8.GetBytes(message.ToJsonString()), maxBytes, ct);

    public static async Task<JsonObject?> ReadJsonAsync(Stream stream, int maxBytes, CancellationToken ct = default)
    {
        var body = await ReadFrameAsync(stream, maxBytes, ct).ConfigureAwait(false);
        if (body is null) return null;
        try
        {
            return JsonNode.Parse(body) as JsonObject ?? throw new FramingException("Frame is not a JSON object");
        }
        catch (System.Text.Json.JsonException e)
        {
            throw new FramingException($"Frame is not valid JSON: {e.Message}");
        }
    }

    private static async Task<int> ReadExactlyOrEofAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
            if (n == 0) break;
            total += n;
        }
        return total;
    }
}
