using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using BrowserSecurity.Agent.Shared.Json;

namespace BrowserSecurity.Agent.Shared.Policy;

/// <summary>
/// checksum = sha256(canonicalJson(payload without "checksum" and "signature")),
/// identical to packages/policy-engine/src/checksum.ts. Computed over the raw
/// JSON received so fields this agent version does not model are still covered.
/// </summary>
public static class PolicyChecksum
{
    public static string Compute(JsonObject payload)
    {
        var copy = (JsonObject)payload.DeepClone();
        copy.Remove("checksum");
        copy.Remove("signature");
        var bytes = Encoding.UTF8.GetBytes(CanonicalJson.Serialize(copy));
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
    }

    public static bool Verify(JsonObject payload)
    {
        var claimed = payload["checksum"]?.GetValueKind() == System.Text.Json.JsonValueKind.String
            ? payload["checksum"]!.GetValue<string>()
            : null;
        if (claimed is null) return false;
        var actual = Compute(payload);
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(claimed));
    }
}
