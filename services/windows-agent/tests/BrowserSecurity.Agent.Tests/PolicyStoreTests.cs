using BrowserSecurity.Agent.Service.Policy;
using BrowserSecurity.Agent.Shared.Policy;

namespace BrowserSecurity.Agent.Tests;

public class PolicyStoreTests
{
    private static readonly Guid Org1 = Guid.Parse("00000000-0000-4000-a000-000000000001");
    private static readonly Guid Org2 = Guid.Parse("00000000-0000-4000-a000-000000000002");

    private static PolicyStore NewStore(string dir) => new(TestOptions.For(dir), Log.For<PolicyStore>(), TimeProvider.System);

    [Fact]
    public async Task Persists_last_known_good_across_restarts()
    {
        using var tmp = new TempDir();
        var p = PolicyValidator.Validate(Vectors.Policy(1));
        await NewStore(tmp.Path).StoreAsync(p, Org2, default);

        var reloaded = NewStore(tmp.Path);
        Assert.Null(reloaded.Current);
        var loaded = reloaded.Load();
        Assert.Equal(2, loaded!.PolicyVersion);
        Assert.Equal(p.Checksum, loaded.Checksum);
    }

    [Fact]
    public async Task Refuses_tampered_cache_and_falls_back_to_previous_version()
    {
        using var tmp = new TempDir();
        var store = NewStore(tmp.Path);
        var v1 = Vectors.Policy(1);
        v1["policyVersion"] = 1;
        v1["checksum"] = PolicyChecksum.Compute(v1);
        await store.StoreAsync(PolicyValidator.Validate(v1), Org2, default);
        await store.StoreAsync(PolicyValidator.Validate(Vectors.Policy(1)), Org2, default);

        // Someone edits the cache to drop a block rule.
        var path = Path.Combine(tmp.Path, "policy", "current.json");
        File.WriteAllText(path, File.ReadAllText(path).Replace("phase1-block-test.example", "harmless.example", StringComparison.Ordinal));

        var reloaded = NewStore(tmp.Path).Load();
        Assert.Equal(1, reloaded!.PolicyVersion);
    }

    [Fact]
    public async Task Returns_null_when_no_valid_cache_exists()
    {
        using var tmp = new TempDir();
        Directory.CreateDirectory(Path.Combine(tmp.Path, "policy"));
        File.WriteAllText(Path.Combine(tmp.Path, "policy", "current.json"), "garbage");
        Assert.Null(NewStore(tmp.Path).Load());
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Refuses_rollback_same_version_changes_and_foreign_organizations()
    {
        using var tmp = new TempDir();
        var store = NewStore(tmp.Path);
        var v2 = PolicyValidator.Validate(Vectors.Policy(1));
        await store.StoreAsync(v2, Org2, default);

        var v1Raw = Vectors.Policy(1);
        v1Raw["policyVersion"] = 1;
        v1Raw["checksum"] = PolicyChecksum.Compute(v1Raw);
        await Assert.ThrowsAsync<PolicyRejectedException>(() => store.StoreAsync(PolicyValidator.Validate(v1Raw), Org2, default));

        var altered = Vectors.Policy(1);
        altered["generatedAt"] = "2026-10-29T00:00:00.000Z";
        altered["checksum"] = PolicyChecksum.Compute(altered);
        await Assert.ThrowsAsync<PolicyRejectedException>(() => store.StoreAsync(PolicyValidator.Validate(altered), Org2, default));

        await Assert.ThrowsAsync<PolicyRejectedException>(() => store.StoreAsync(v2, Org1, default));

        // Identical re-store is a no-op.
        await store.StoreAsync(v2, Org2, default);
        Assert.Equal(2, store.Current!.PolicyVersion);
    }

    [Fact]
    public async Task Replaces_policy_from_a_previous_enrollment_in_another_organization()
    {
        using var tmp = new TempDir();
        var store = NewStore(tmp.Path);
        await store.StoreAsync(PolicyValidator.Validate(Vectors.Policy(1)), Org2, default); // org2 v2
        var org1v1 = PolicyValidator.Validate(Vectors.Policy(0));                             // org1 v1
        await store.StoreAsync(org1v1, Org1, default);
        Assert.Equal(Org1, store.Current!.OrganizationId);
    }
}
