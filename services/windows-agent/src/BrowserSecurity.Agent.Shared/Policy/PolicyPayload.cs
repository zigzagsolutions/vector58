using System.Text.Json;
using System.Text.Json.Nodes;

namespace BrowserSecurity.Agent.Shared.Policy;

public sealed record PolicyRule(long Id, string Type, string Value, string Action, string Category, int Priority, string Source);

/// <summary>A validated policy: the parsed view plus the exact JSON it came from.</summary>
public sealed class ValidatedPolicy
{
    internal ValidatedPolicy(JsonObject raw, int version, Guid organizationId, string checksum, IReadOnlyList<PolicyRule> rules, DateTimeOffset generatedAt)
    {
        Raw = raw;
        PolicyVersion = version;
        OrganizationId = organizationId;
        Checksum = checksum;
        Rules = rules;
        GeneratedAt = generatedAt;
    }

    /// <summary>Raw payload; forwarded to browsers unchanged so they can verify the same checksum.</summary>
    public JsonObject Raw { get; }
    public int PolicyVersion { get; }
    public Guid OrganizationId { get; }
    public string Checksum { get; }
    public IReadOnlyList<PolicyRule> Rules { get; }
    public DateTimeOffset GeneratedAt { get; }
}

public sealed class PolicyValidationException(string message) : Exception(message);

/// <summary>
/// Structural validation mirroring PolicyPayloadSchema in
/// packages/policy-types/src/policy-payload.ts, followed by checksum
/// verification. A policy that fails is never stored or forwarded.
/// </summary>
public static class PolicyValidator
{
    private static readonly HashSet<string> RuleTypes = ["domain", "exact_url"];
    private static readonly HashSet<string> Actions = ["block", "allow"];
    private static readonly HashSet<string> Sources = ["tenant", "global"];
    private static readonly HashSet<string> Categories =
        ["phishing", "malware", "command-and-control", "credential-theft", "fraud", "malicious-download", "custom"];

    public const int MaxRules = 30_000;

    public static ValidatedPolicy Validate(JsonObject payload)
    {
        var schemaVersion = RequireInt(payload, "schemaVersion");
        if (schemaVersion != AgentConstants.PolicySchemaVersion)
            throw new PolicyValidationException($"Unsupported policy schemaVersion {schemaVersion}");
        var version = RequireInt(payload, "policyVersion");
        if (version < 1) throw new PolicyValidationException("policyVersion must be positive");
        if (!Guid.TryParse(RequireString(payload, "organizationId"), out var orgId))
            throw new PolicyValidationException("organizationId is not a UUID");
        if (!DateTimeOffset.TryParse(RequireString(payload, "generatedAt"), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var generatedAt))
            throw new PolicyValidationException("generatedAt is not a timestamp");
        var checksum = RequireString(payload, "checksum");
        if (checksum.Length != 64 || !checksum.All(Uri.IsHexDigit) || checksum.Any(char.IsUpper))
            throw new PolicyValidationException("checksum must be 64 lowercase hex characters");

        if (payload["rules"] is not JsonArray rulesArray) throw new PolicyValidationException("rules must be an array");
        if (rulesArray.Count > MaxRules) throw new PolicyValidationException("too many rules");
        var rules = new List<PolicyRule>(rulesArray.Count);
        var ids = new HashSet<long>();
        foreach (var node in rulesArray)
        {
            if (node is not JsonObject r) throw new PolicyValidationException("rule must be an object");
            var id = RequireLong(r, "id");
            if (id < 1 || id > AgentConstants.MaxPolicyRuleId) throw new PolicyValidationException($"rule id {id} out of range");
            if (!ids.Add(id)) throw new PolicyValidationException($"duplicate rule id {id}");
            var rule = new PolicyRule(
                id,
                OneOf(r, "type", RuleTypes),
                RequireString(r, "value"),
                OneOf(r, "action", Actions),
                OneOf(r, "category", Categories),
                RequireInt(r, "priority"),
                OneOf(r, "source", Sources));
            if (rule.Value.Length is 0 or > 2048) throw new PolicyValidationException("rule value length out of range");
            if (rule.Priority is < 1 or > 10_000) throw new PolicyValidationException("rule priority out of range");
            rules.Add(rule);
        }

        if (!PolicyChecksum.Verify(payload)) throw new PolicyValidationException("Policy checksum verification failed");
        return new ValidatedPolicy((JsonObject)payload.DeepClone(), version, orgId, checksum, rules, generatedAt);
    }

    public static ValidatedPolicy Parse(string json)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (JsonException e)
        {
            throw new PolicyValidationException($"Policy is not valid JSON: {e.Message}");
        }
        return node is JsonObject obj ? Validate(obj) : throw new PolicyValidationException("Policy must be a JSON object");
    }

    private static string RequireString(JsonObject o, string key) =>
        o[key] is JsonValue v && v.GetValueKind() == JsonValueKind.String
            ? v.GetValue<string>()
            : throw new PolicyValidationException($"{key} must be a string");

    private static long RequireLong(JsonObject o, string key)
    {
        if (o[key] is JsonValue v && v.GetValueKind() == JsonValueKind.Number)
        {
            if (v.TryGetValue<long>(out var l)) return l;
            if (v.TryGetValue<int>(out var i)) return i;
            if (v.TryGetValue<JsonElement>(out var e) && e.TryGetInt64(out var el)) return el;
        }
        throw new PolicyValidationException($"{key} must be an integer");
    }

    private static int RequireInt(JsonObject o, string key)
    {
        var l = RequireLong(o, key);
        return l is >= int.MinValue and <= int.MaxValue ? (int)l : throw new PolicyValidationException($"{key} out of range");
    }

    private static string OneOf(JsonObject o, string key, HashSet<string> allowed)
    {
        var s = RequireString(o, key);
        return allowed.Contains(s) ? s : throw new PolicyValidationException($"{key} has unsupported value '{s}'");
    }
}
