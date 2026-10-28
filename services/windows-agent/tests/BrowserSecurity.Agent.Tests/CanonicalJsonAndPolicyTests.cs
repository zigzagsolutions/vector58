using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Shared.Json;
using BrowserSecurity.Agent.Shared.Policy;

namespace BrowserSecurity.Agent.Tests;

public class CanonicalJsonParityTests
{
    public static TheoryData<int> CanonicalCases()
    {
        var data = new TheoryData<int>();
        for (var i = 0; i < Vectors.Canonical.Count; i++) data.Add(i);
        return data;
    }

    [Theory]
    [MemberData(nameof(CanonicalCases))]
    public void Matches_typescript_canonical_json_byte_for_byte(int index)
    {
        var v = Vectors.Canonical[index]!;
        var input = JsonNode.Parse(v["input"]!.GetValue<string>());
        var canonical = CanonicalJson.Serialize(input);
        Assert.Equal(v["canonical"]!.GetValue<string>(), canonical);
        Assert.Equal(v["sha256"]!.GetValue<string>(), Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
    }

    [Fact]
    public void Rejects_non_integer_numbers()
    {
        Assert.Throws<FormatException>(() => CanonicalJson.Serialize(JsonNode.Parse("{\"a\":1.5}")));
        Assert.Throws<FormatException>(() => CanonicalJson.Serialize(JsonNode.Parse("9007199254740993")));
    }

    [Fact]
    public void Escapes_lone_surrogates_like_well_formed_json_stringify()
    {
        var sb = new StringBuilder();
        CanonicalJson.WriteString(sb, "a\uD800b\uDC00");
        Assert.Equal("\"a\\ud800b\\udc00\"", sb.ToString());
    }
}

public class PolicyValidationTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Accepts_policies_compiled_by_the_typescript_engine(int i)
    {
        var raw = Vectors.Policy(i);
        var p = PolicyValidator.Validate(raw);
        Assert.Equal(raw["checksum"]!.GetValue<string>(), PolicyChecksum.Compute(raw));
        Assert.Equal(i + 1, p.PolicyVersion);
        Assert.Equal(((JsonArray)raw["rules"]!).Count, p.Rules.Count);
    }

    [Fact]
    public void Detects_any_tampering()
    {
        var raw = Vectors.Policy(1);
        raw["rules"]!.AsArray().RemoveAt(0);
        var e = Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(raw));
        Assert.Contains("checksum", e.Message, StringComparison.OrdinalIgnoreCase);

        var flipped = Vectors.Policy(1);
        flipped["rules"]![0]!["action"] = flipped["rules"]![0]!["action"]!.GetValue<string>() == "block" ? "allow" : "block";
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(flipped));

        var org = Vectors.Policy(1);
        org["organizationId"] = "00000000-0000-4000-a000-000000000009";
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(org));
    }

    [Fact]
    public void Checksum_ignores_signature_but_covers_unknown_fields()
    {
        var raw = Vectors.Policy(1);
        raw["signature"] = "reserved-for-phase-2";
        PolicyValidator.Validate(raw);
        raw["futureField"] = 1;
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(raw));
    }

    [Theory]
    [InlineData("schemaVersion", "2")]
    [InlineData("policyVersion", "0")]
    [InlineData("organizationId", "\"not-a-uuid\"")]
    [InlineData("checksum", "\"ABC\"")]
    [InlineData("rules", "{}")]
    public void Rejects_structurally_invalid_payloads(string field, string json)
    {
        var raw = Vectors.Policy(1);
        raw[field] = JsonNode.Parse(json);
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(raw));
    }

    [Fact]
    public void Rejects_duplicate_and_out_of_range_rule_ids()
    {
        var dup = Vectors.Policy(1);
        dup["rules"]![1]!["id"] = dup["rules"]![0]!["id"]!.GetValue<long>();
        Assert.Contains("duplicate", Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(dup)).Message, StringComparison.Ordinal);

        var big = Vectors.Policy(1);
        big["rules"]![0]!["id"] = (1L << 29) + 1;
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Validate(big));
    }

    [Fact]
    public void Rejects_non_json()
    {
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Parse("{not json"));
        Assert.Throws<PolicyValidationException>(() => PolicyValidator.Parse("[]"));
    }
}
