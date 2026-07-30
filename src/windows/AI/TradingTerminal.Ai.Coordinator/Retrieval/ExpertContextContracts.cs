using TradingTerminal.Ai.Coordinator.Datasets;

namespace TradingTerminal.Ai.Coordinator.Retrieval;

public sealed record ExpertContextManifest
{
    public required string SchemaVersion { get; init; }
    public required string CorpusId { get; init; }
    public required string CorpusVersion { get; init; }
    public required string NormalizerVersion { get; init; }
    public required string ChunkerVersion { get; init; }
    public required string TokenizerVersion { get; init; }
    public required string ScorerVersion { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required DateTimeOffset CutoffUtc { get; init; }
    public IReadOnlyList<ExpertContextManifestSource> Sources { get; init; } = [];
}

public sealed record ExpertContextManifestSource
{
    public required string Id { get; init; }
    public required string RelativePath { get; init; }
    public required string Title { get; init; }
    public required string Provenance { get; init; }
    public required string License { get; init; }
    public IReadOnlyList<ExpertDomain> Domains { get; init; } = [];
    public required DatasetRights Rights { get; init; }
    public required DateTimeOffset AvailableAtUtc { get; init; }
    public required string RawSha256 { get; init; }
}

public sealed record ExpertContextPack
{
    public required string SchemaVersion { get; init; }
    public required string CorpusId { get; init; }
    public required string CorpusVersion { get; init; }
    public required string NormalizerVersion { get; init; }
    public required string ChunkerVersion { get; init; }
    public required string TokenizerVersion { get; init; }
    public required string ScorerVersion { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required DateTimeOffset CutoffUtc { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string IndexSha256 { get; init; }
    public required string PackSha256 { get; init; }
    public IReadOnlyList<ExpertContextPackSource> Sources { get; init; } = [];
    public IReadOnlyList<ExpertContextChunk> Chunks { get; init; } = [];
}

public sealed record ExpertContextPackSource
{
    public required string Id { get; init; }
    public required string RelativePath { get; init; }
    public required string Title { get; init; }
    public required string Provenance { get; init; }
    public required string License { get; init; }
    public IReadOnlyList<ExpertDomain> Domains { get; init; } = [];
    public required DatasetRights Rights { get; init; }
    public required DateTimeOffset AvailableAtUtc { get; init; }
    public required string RawSha256 { get; init; }
    public required string ContentSha256 { get; init; }
    public required int RawByteCount { get; init; }
    public required int LineCount { get; init; }
}

public sealed record ExpertContextChunk
{
    public required string Id { get; init; }
    public required string SourceId { get; init; }
    public required int Ordinal { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required string Content { get; init; }
    public required string ContentSha256 { get; init; }
    public IReadOnlyList<ExpertDomain> Domains { get; init; } = [];
}

public sealed record ExpertContextQueryPolicy
{
    public required string SchemaVersion { get; init; }
    public int TopK { get; init; } = 12;
    public int MaxCharacters { get; init; } = 40_000;
    public int MaxPerSource { get; init; } = 4;
}

public sealed record ExpertContextActivation
{
    public required string TenantId { get; init; }
    public required string CorpusId { get; init; }
    public required string CorpusVersion { get; init; }
    public required string PackSha256 { get; init; }
}

public sealed record ExpertContextResolutionRequest
{
    public required string TenantId { get; init; }
    public required string CorpusId { get; init; }
    public required string CorpusVersion { get; init; }
    public required string PackSha256 { get; init; }
    public required string Query { get; init; }
    public required ExpertContextQueryPolicy Policy { get; init; }
}

public sealed record ExpertContextSelection
{
    public required string SchemaVersion { get; init; }
    public required string CorpusId { get; init; }
    public required string CorpusVersion { get; init; }
    public required string PackSha256 { get; init; }
    public required string IndexSha256 { get; init; }
    public required string TenantScopeSha256 { get; init; }
    public required string QuerySha256 { get; init; }
    public required string PolicySha256 { get; init; }
    public required string SelectionSha256 { get; init; }
    public IReadOnlyList<ExpertContextHit> Hits { get; init; } = [];
}

public sealed record ExpertContextHit
{
    public required int Rank { get; init; }
    public required string CitationId { get; init; }
    public required string ChunkId { get; init; }
    public required string SourceId { get; init; }
    public required string Title { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required int Score { get; init; }
    public required string Content { get; init; }
    public required string ContentSha256 { get; init; }
    public required string License { get; init; }
}

public interface IExpertContextPackResolver
{
    ExpertContextSelection Resolve(ExpertContextResolutionRequest request);
}
