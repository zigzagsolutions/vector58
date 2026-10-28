using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BrowserSecurity.Agent.Shared.Json;

/// <summary>
/// Canonical JSON identical to packages/shared/src/canonical-json.ts:
/// object keys sorted by UTF-16 code unit (ordinal), no whitespace, integers
/// only, and strings escaped exactly like JavaScript's JSON.stringify.
/// Parity is enforced by tests against vectors generated from the TypeScript
/// implementation (tests/fixtures/canonical-json-vectors.json).
/// </summary>
public static class CanonicalJson
{
    private const long MaxSafeInteger = 9007199254740991L;

    public static string Serialize(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(sb, node);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                return;
            case JsonObject obj:
            {
                sb.Append('{');
                var first = true;
                foreach (var kv in obj.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, kv.Key);
                    sb.Append(':');
                    Write(sb, kv.Value);
                }
                sb.Append('}');
                return;
            }
            case JsonArray arr:
            {
                sb.Append('[');
                for (var i = 0; i < arr.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    Write(sb, arr[i]);
                }
                sb.Append(']');
                return;
            }
            case JsonValue value:
                WriteValue(sb, value);
                return;
            default:
                throw new FormatException($"Unsupported JSON node {node.GetType().Name}");
        }
    }

    private static void WriteValue(StringBuilder sb, JsonValue value)
    {
        switch (value.GetValueKind())
        {
            case JsonValueKind.String:
                WriteString(sb, value.GetValue<string>());
                return;
            case JsonValueKind.True:
                sb.Append("true");
                return;
            case JsonValueKind.False:
                sb.Append("false");
                return;
            case JsonValueKind.Null:
                sb.Append("null");
                return;
            case JsonValueKind.Number:
            {
                long n;
                if (value.TryGetValue<long>(out var l)) n = l;
                else if (value.TryGetValue<int>(out var i)) n = i;
                else if (value.TryGetValue<JsonElement>(out var e) && e.TryGetInt64(out var el)) n = el;
                else throw new FormatException("Canonical JSON only supports integers");
                if (n > MaxSafeInteger || n < -MaxSafeInteger)
                    throw new FormatException("Canonical JSON only supports safe integers");
                sb.Append(n.ToString(CultureInfo.InvariantCulture));
                return;
            }
            default:
                throw new FormatException($"Unsupported JSON value kind {value.GetValueKind()}");
        }
    }

    /// <summary>Escapes like ECMAScript JSON.stringify (well-formed variant, ES2019+).</summary>
    internal static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                    {
                        AppendUnicodeEscape(sb, c);
                    }
                    else if (char.IsHighSurrogate(c))
                    {
                        if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                        {
                            sb.Append(c).Append(s[i + 1]);
                            i++;
                        }
                        else AppendUnicodeEscape(sb, c);
                    }
                    else if (char.IsLowSurrogate(c))
                    {
                        AppendUnicodeEscape(sb, c);
                    }
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    private static void AppendUnicodeEscape(StringBuilder sb, char c) =>
        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
}
