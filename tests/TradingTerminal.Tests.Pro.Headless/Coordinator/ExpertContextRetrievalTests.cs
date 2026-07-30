using System.Text;
using System.Text.Json;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Retrieval;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class ExpertContextRetrievalTests
{
    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);

    private static readonly DatasetRights HostedRights =
        new(true, true, false, true, false);

    [Fact]
    public async Task Build_and_retrieval_are_deterministic_and_normalize_line_endings()
    {
        using var workspace = new TestWorkspace();
        const string normalized =
            "PositionSizingPolicy caps portfolio exposure.\n" +
            "Drawdown controls reduce risk before new orders.\n" +
            "Expected shortfall is evaluated before allocation.";
        var lf = await BuildPackAsync(workspace, "lf", normalized);
        var lfAgain = await ExpertContextPackTools.BuildAsync(lf.Manifest, lf.RootPath);
        var crlf = await BuildPackAsync(
            workspace,
            "crlf",
            normalized.Replace("\n", "\r\n", StringComparison.Ordinal));
        var crlfAgain = await ExpertContextPackTools.BuildAsync(crlf.Manifest, crlf.RootPath);

        lf.Pack.Should().BeEquivalentTo(lfAgain, options => options.WithStrictOrdering());
        crlf.Pack.Should().BeEquivalentTo(crlfAgain, options => options.WithStrictOrdering());
        lf.Pack.PackSha256.Should().NotBe(crlf.Pack.PackSha256,
            "the reviewed raw-byte identity remains bound to the pack");
        lf.Pack.Sources[0].ContentSha256.Should().Be(crlf.Pack.Sources[0].ContentSha256);
        lf.Pack.Chunks.Should().BeEquivalentTo(crlf.Pack.Chunks, options => options.WithStrictOrdering());
        lf.Pack.Chunks.Should().OnlyContain(chunk => !chunk.Content.Contains('\r'));

        var lfSelection = Resolve(lf.Pack, "tenant-a", "drawdown position sizing");
        var crlfSelection = Resolve(crlf.Pack, "tenant-a", "drawdown position sizing");

        lfSelection.Hits.Should().BeEquivalentTo(
            crlfSelection.Hits,
            options => options.WithStrictOrdering());
        lfSelection.QuerySha256.Should().Be(crlfSelection.QuerySha256);
        lfSelection.PolicySha256.Should().Be(crlfSelection.PolicySha256);
        lfSelection.TenantScopeSha256.Should().Be(crlfSelection.TenantScopeSha256);
    }

    [Fact]
    public async Task Pack_loader_accepts_the_pinned_artifact_and_rejects_tampering_and_duplicate_properties()
    {
        using var workspace = new TestWorkspace();
        var built = await BuildPackAsync(
            workspace,
            "load",
            "RiskBudget limits portfolio exposure.");
        var json = JsonSerializer.Serialize(built.Pack, CoordinatorJson.Options);
        var packPath = workspace.PathFor("context-pack.json");
        await File.WriteAllTextAsync(packPath, json, new UTF8Encoding(false));

        var loaded = ExpertContextPackTools.Load(packPath, built.Pack.PackSha256);

        loaded.Should().BeEquivalentTo(built.Pack, options => options.WithStrictOrdering());

        var tamperedPath = workspace.PathFor("tampered-pack.json");
        await File.WriteAllTextAsync(
            tamperedPath,
            json.Replace("RiskBudget", "RiskBudgeb", StringComparison.Ordinal),
            new UTF8Encoding(false));
        var loadTampered = () => ExpertContextPackTools.Load(
            tamperedPath,
            built.Pack.PackSha256);
        loadTampered.Should().Throw<CoordinatorValidationException>();

        var duplicatePath = workspace.PathFor("duplicate-pack.json");
        var duplicate = "{\"schemaVersion\":\"duplicate\"," + json[1..];
        await File.WriteAllTextAsync(duplicatePath, duplicate, new UTF8Encoding(false));
        var loadDuplicate = () => ExpertContextPackTools.Load(
            duplicatePath,
            built.Pack.PackSha256);
        loadDuplicate.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*duplicate property*");
    }

    [Fact]
    public async Task Resolver_requires_the_exact_server_owned_tenant_and_pack_binding()
    {
        using var workspace = new TestWorkspace();
        var built = await BuildPackAsync(workspace, "binding", "RiskBudget limits gross exposure.");
        var resolver = Resolver(built.Pack, "tenant-a");

        var wrongTenant = () => resolver.Resolve(Request(
            built.Pack,
            "tenant-b",
            "risk budget"));
        var wrongPack = () => resolver.Resolve(Request(
            built.Pack,
            "tenant-a",
            "risk budget") with
        { PackSha256 = new string('a', 64) });
        var wrongActivation = () => new PinnedExpertContextPackResolver(
            built.Pack,
            Activation(built.Pack, "tenant-a") with { CorpusVersion = "immutable-v2" });

        wrongTenant.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*server-owned tenant and pack activation*");
        wrongPack.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*server-owned tenant and pack activation*");
        wrongActivation.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*does not bind the supplied pack*");
    }

    [Fact]
    public async Task Tampered_pack_and_selection_are_rejected()
    {
        using var workspace = new TestWorkspace();
        var built = await BuildPackAsync(workspace, "tamper", "RiskBudget limits gross exposure.");
        var selection = Resolve(built.Pack, "tenant-a", "risk budget");
        var originalChunk = built.Pack.Chunks[0];
        var tamperedPack = built.Pack with
        {
            Chunks =
            [
                originalChunk with { Content = originalChunk.Content + " Tampered." }
            ]
        };
        var originalHit = selection.Hits[0];
        var tamperedSelection = selection with
        {
            Hits =
            [
                originalHit with { Content = originalHit.Content + " Tampered." }
            ]
        };

        var validatePack = () => ExpertContextPackTools.ValidatePack(tamperedPack);
        var validateSelection = () => ExpertContextPackTools.ValidateSelection(
            built.Pack,
            tamperedSelection);

        validatePack.Should().Throw<CoordinatorValidationException>();
        validateSelection.Should().Throw<CoordinatorValidationException>();
    }

    [Fact]
    public async Task Corpus_and_provider_rights_fail_closed()
    {
        using var workspace = new TestWorkspace();
        var missingStorage = await WriteCorpusAsync(
            workspace,
            "missing-storage",
            "Risk controls are mandatory.",
            new DatasetRights(false, true, false, true, false));
        var localOnly = await BuildPackAsync(
            workspace,
            "local-only",
            "Risk controls are mandatory.",
            new DatasetRights(true, true, false, false, false));

        var buildWithoutStorageRights = async () =>
            await ExpertContextPackTools.BuildAsync(missingStorage.Manifest, missingStorage.RootPath);
        var createHostedResolver = () => Resolver(localOnly.Pack, "tenant-a");

        await buildWithoutStorageRights.Should().ThrowAsync<CoordinatorValidationException>()
            .WithMessage("*storage and evaluation rights*");
        createHostedResolver.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*not licensed for hosted provider upload*");
    }

    [Fact]
    public async Task Manifest_rejects_parent_path_traversal_before_reading()
    {
        using var workspace = new TestWorkspace();
        var corpus = await WriteCorpusAsync(workspace, "traversal", "Reviewed context.");
        var traversalManifest = corpus.Manifest with
        {
            Sources =
            [
                corpus.Manifest.Sources[0] with { RelativePath = "../outside.md" }
            ]
        };

        var build = async () =>
            await ExpertContextPackTools.BuildAsync(traversalManifest, corpus.RootPath);

        await build.Should().ThrowAsync<CoordinatorValidationException>()
            .WithMessage("*canonical forward-slash relative path*");
    }

    [Fact]
    public async Task Resolver_rejects_no_match_and_a_match_that_cannot_fit_the_budget()
    {
        using var workspace = new TestWorkspace();
        var built = await BuildPackAsync(
            workspace,
            "budget",
            "RiskBudget limits gross exposure and drawdown.");
        var resolver = Resolver(built.Pack, "tenant-a");

        var noMatch = () => resolver.Resolve(Request(
            built.Pack,
            "tenant-a",
            "orthogonalUnseenVocabulary"));
        var tooSmall = () => resolver.Resolve(Request(
            built.Pack,
            "tenant-a",
            "risk budget",
            new ExpertContextQueryPolicy
            {
                SchemaVersion = ExpertContextPackTools.QueryPolicySchemaVersion,
                TopK = 1,
                MaxCharacters = 1,
                MaxPerSource = 1
            }));

        noMatch.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*No licensed context chunk matched*");
        tooSmall.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*No licensed context chunk matched*");
    }

    [Fact]
    public async Task Materialization_rejects_case_insensitive_reserved_source_collisions()
    {
        using var workspace = new TestWorkspace();
        var built = await BuildPackAsync(workspace, "collision", "RiskBudget limits exposure.");
        var selection = Resolve(built.Pack, "tenant-a", "risk budget");
        CoordinatorContextSource[] submitted =
        [
            new("DAXCTX.user", "Caller source", "Caller content")
        ];

        var materialize = () => ExpertContextPackTools.MaterializeExecutionSources(
            submitted,
            built.Pack,
            selection);

        materialize.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*reserved private-context prefix*");
    }

    [Fact]
    public async Task Materialization_includes_only_selected_chunks_plus_the_identity_manifest()
    {
        using var workspace = new TestWorkspace();
        var lines = Enumerable.Range(1, 90)
            .Select(index => index == 85
                ? "rareLiquidationGuard prevents an unsafe order."
                : $"General portfolio guidance line {index}.");
        var built = await BuildPackAsync(workspace, "selected-only", string.Join('\n', lines));
        built.Pack.Chunks.Should().HaveCountGreaterThan(1);
        var policy = new ExpertContextQueryPolicy
        {
            SchemaVersion = ExpertContextPackTools.QueryPolicySchemaVersion,
            TopK = 1,
            MaxCharacters = ExpertContextPackTools.MaxSelectionCharacters,
            MaxPerSource = 1
        };
        var selection = Resolve(
            built.Pack,
            "tenant-a",
            "rareLiquidationGuard",
            policy);
        CoordinatorContextSource[] submitted =
        [
            new("caller", "Caller evidence", "Submitted evidence")
        ];

        var executionSources = ExpertContextPackTools.MaterializeExecutionSources(
            submitted,
            built.Pack,
            selection);

        selection.Hits.Should().ContainSingle();
        executionSources.Select(source => source.Id).Should().Equal(
            "caller",
            ExpertContextPackTools.ReservedSourcePrefix + "manifest",
            selection.Hits[0].CitationId);
        executionSources[2].Content.Should().Be(selection.Hits[0].Content);
        var selectedChunkIds = selection.Hits.Select(hit => hit.ChunkId).ToHashSet(StringComparer.Ordinal);
        var unselected = built.Pack.Chunks.Where(chunk => !selectedChunkIds.Contains(chunk.Id)).ToArray();
        foreach (var chunk in unselected)
        {
            executionSources[1].Content.Should().NotContain(chunk.Id);
            executionSources[1].Content.Should().NotContain(chunk.ContentSha256);
            executionSources.Skip(2).Should().NotContain(source => source.Id.EndsWith(
                chunk.Id,
                StringComparison.Ordinal));
        }
    }

    private static PinnedExpertContextPackResolver Resolver(
        ExpertContextPack pack,
        string tenantId) =>
        new(pack, Activation(pack, tenantId));

    private static ExpertContextActivation Activation(ExpertContextPack pack, string tenantId) =>
        new()
        {
            TenantId = tenantId,
            CorpusId = pack.CorpusId,
            CorpusVersion = pack.CorpusVersion,
            PackSha256 = pack.PackSha256
        };

    private static ExpertContextSelection Resolve(
        ExpertContextPack pack,
        string tenantId,
        string query,
        ExpertContextQueryPolicy? policy = null) =>
        Resolver(pack, tenantId).Resolve(Request(pack, tenantId, query, policy));

    private static ExpertContextResolutionRequest Request(
        ExpertContextPack pack,
        string tenantId,
        string query,
        ExpertContextQueryPolicy? policy = null) =>
        new()
        {
            TenantId = tenantId,
            CorpusId = pack.CorpusId,
            CorpusVersion = pack.CorpusVersion,
            PackSha256 = pack.PackSha256,
            Query = query,
            Policy = policy ?? new ExpertContextQueryPolicy
            {
                SchemaVersion = ExpertContextPackTools.QueryPolicySchemaVersion,
                TopK = 4,
                MaxCharacters = 20_000,
                MaxPerSource = 4
            }
        };

    private static async Task<BuiltCorpus> BuildPackAsync(
        TestWorkspace workspace,
        string directoryName,
        string content,
        DatasetRights? rights = null)
    {
        var corpus = await WriteCorpusAsync(workspace, directoryName, content, rights);
        var pack = await ExpertContextPackTools.BuildAsync(corpus.Manifest, corpus.RootPath);
        return new BuiltCorpus(corpus.RootPath, corpus.Manifest, pack);
    }

    private static async Task<WrittenCorpus> WriteCorpusAsync(
        TestWorkspace workspace,
        string directoryName,
        string content,
        DatasetRights? rights = null)
    {
        var root = workspace.PathFor(directoryName);
        Directory.CreateDirectory(root);
        var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(content);
        await File.WriteAllBytesAsync(Path.Combine(root, "risk.md"), bytes);
        var manifest = new ExpertContextManifest
        {
            SchemaVersion = ExpertContextPackTools.ManifestSchemaVersion,
            CorpusId = "daxalgo-private",
            CorpusVersion = "immutable-v1",
            NormalizerVersion = ExpertContextPackTools.NormalizerVersion,
            ChunkerVersion = ExpertContextPackTools.ChunkerVersion,
            TokenizerVersion = ExpertContextPackTools.TokenizerVersion,
            ScorerVersion = ExpertContextPackTools.ScorerVersion,
            CreatedAtUtc = FixtureTime,
            CutoffUtc = FixtureTime,
            Sources =
            [
                new ExpertContextManifestSource
                {
                    Id = "risk",
                    RelativePath = "risk.md",
                    Title = "Risk management guidance",
                    Provenance = "Reviewed DaxAlgo private documentation.",
                    License = "DaxAlgo private; provider upload permitted.",
                    Domains = [ExpertDomain.RiskManagement],
                    Rights = rights ?? HostedRights,
                    AvailableAtUtc = FixtureTime,
                    RawSha256 = ContentHasher.HashBytes(bytes)
                }
            ]
        };
        return new WrittenCorpus(root, manifest);
    }

    private sealed record WrittenCorpus(
        string RootPath,
        ExpertContextManifest Manifest);

    private sealed record BuiltCorpus(
        string RootPath,
        ExpertContextManifest Manifest,
        ExpertContextPack Pack);
}
