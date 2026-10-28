using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Shared.Api;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BrowserSecurity.Agent.Service.Events;

public interface ISecurityEventQueue
{
    int Count { get; }
    void Enqueue(JsonObject securityEvent);
    IReadOnlyList<JsonObject> Peek(int max);
    /// <summary>Removes the first <paramref name="count"/> events after a successful upload.</summary>
    void Remove(int count);
}

/// <summary>
/// Durable, bounded FIFO (&lt;data&gt;/events/queue.jsonl). Survives restarts
/// and cloud outages; when full, the oldest events are dropped and a counter
/// is logged.
/// </summary>
public sealed class SecurityEventQueue : ISecurityEventQueue
{
    public const int MaxEvents = 10_000;
    private readonly string _path;
    private readonly ILogger<SecurityEventQueue> _log;
    private readonly Lock _gate = new();
    private readonly List<JsonObject> _events = [];
    private int _dropped;

    public SecurityEventQueue(IOptions<AgentOptions> options, ILogger<SecurityEventQueue> log)
    {
        _log = log;
        var dir = Path.Combine(options.Value.DataDirectory, "events");
        SecureFiles.EnsureDirectory(options.Value.DataDirectory);
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "queue.jsonl");
        Load();
    }

    public int Count { get { lock (_gate) return _events.Count; } }

    /// <summary>Events dropped because the queue was full since the last call.</summary>
    public int TakeDroppedCount()
    {
        lock (_gate)
        {
            var n = _dropped;
            _dropped = 0;
            return n;
        }
    }

    public void Enqueue(JsonObject securityEvent)
    {
        lock (_gate)
        {
            _events.Add(securityEvent);
            if (_events.Count > MaxEvents)
            {
                var overflow = _events.Count - MaxEvents;
                _events.RemoveRange(0, overflow);
                _dropped += overflow;
                Rewrite();
            }
            else
            {
                File.AppendAllText(_path, securityEvent.ToJsonString() + "\n", Encoding.UTF8);
            }
        }
    }

    public IReadOnlyList<JsonObject> Peek(int max)
    {
        lock (_gate) return _events.Take(max).Select(e => (JsonObject)e.DeepClone()).ToList();
    }

    public void Remove(int count)
    {
        lock (_gate)
        {
            _events.RemoveRange(0, Math.Min(count, _events.Count));
            Rewrite();
        }
    }

    private void Rewrite()
    {
        var tmp = _path + ".tmp";
        File.WriteAllLines(tmp, _events.Select(e => e.ToJsonString()), Encoding.UTF8);
        File.Move(tmp, _path, overwrite: true);
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        var bad = 0;
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                if (JsonNode.Parse(line) is JsonObject o) _events.Add(o);
                else bad++;
            }
            catch (JsonException)
            {
                bad++; // e.g. a torn final line after power loss
            }
        }
        if (_events.Count > MaxEvents) _events.RemoveRange(0, _events.Count - MaxEvents);
        if (bad > 0)
        {
            _log.LogWarning("Discarded {Count} unreadable queued events", bad);
            Rewrite();
        }
    }
}

/// <summary>Builds events originated by the agent itself.</summary>
public static class AgentEvents
{
    public static JsonObject Create(string eventType, DateTimeOffset now, int? policyVersion, JsonObject? details = null) => new()
    {
        ["eventId"] = Guid.NewGuid().ToString(),
        ["eventType"] = eventType,
        ["occurredAt"] = AgentJson.Timestamp(now),
        ["policyVersion"] = policyVersion,
        ["details"] = details ?? new JsonObject(),
    };
}
