using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BrowserSecurity.Agent.Shared.Api;

public static class AgentJson
{
    /// <summary>camelCase, timestamps as RFC 3339 UTC with a Z suffix (what the API's zod schemas accept).</summary>
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = false };
        o.Converters.Add(new UtcTimestampConverter());
        o.MakeReadOnly(populateMissingResolver: true);
        return o;
    }

    public static string Timestamp(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private sealed class UtcTimestampConverter : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            DateTimeOffset.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
            writer.WriteStringValue(Timestamp(value));
    }
}
