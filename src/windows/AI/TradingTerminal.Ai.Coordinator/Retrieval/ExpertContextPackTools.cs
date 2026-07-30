using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Retrieval;

public static class ExpertContextPackTools
{
    public const string ManifestSchemaVersion = "daxalgo-expert-context-manifest/v1";
    public const string PackSchemaVersion = "daxalgo-expert-context-pack/v1";
    public const string QueryPolicySchemaVersion = "daxalgo-expert-context-query-policy/v1";
    public const string SelectionSchemaVersion = "daxalgo-expert-context-selection/v1";
    public const string IndexSchemaVersion = "daxalgo-expert-context-lexical-index/v1";
    public const string NormalizerVersion = "utf8-lf-nfc/v1";
    public const string ChunkerVersion = "line-window-4000-80-overlap6/v1";
    public const string TokenizerVersion = "code-camel-alnum/v1";
    public const string ScorerVersion = "integer-exact-title-domain/v1";
    public const string ReservedSourcePrefix = "daxctx.";

    public const int MaxSourceCount = 2_048;
    public const int MaxSourceBytes = 5_000_000;
    public const long MaxAggregateSourceBytes = 100_000_000;
    public const int MaxChunkCount = 100_000;
    public const int MaxChunkCharacters = 4_000;
    public const int MaxChunkLines = 80;
    public const int ChunkOverlapLines = 6;
    public const int MaxQueryCharacters = 100_000;
    public const int MaxSelectionCount = 32;
    public const int MaxSelectionCharacters = 100_000;
    public const int MaxPackBytes = 200_000_000;

    private const string ZeroSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static async Task<ExpertContextPack> BuildAsync(
        ExpertContextManifest manifest,
        string sourceRoot,
        CancellationToken cancellationToken = default)
    {
        ValidateManifest(manifest);
        var root = ResolveSourceRoot(sourceRoot);
        var packedSources = new List<ExpertContextPackSource>(manifest.Sources.Count);
        var chunks = new List<ExpertContextChunk>();
        long aggregateBytes = 0;

        foreach (var source in manifest.Sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bytes = await ReadSourceAsync(root, source.RelativePath, cancellationToken)
                .ConfigureAwait(false);
            aggregateBytes = checked(aggregateBytes + bytes.Length);
            if (aggregateBytes > MaxAggregateSourceBytes)
            {
                throw new CoordinatorValidationException(
                    $"Context corpus exceeds the {MaxAggregateSourceBytes:N0}-byte aggregate limit.");
            }

            var rawSha256 = ContentHasher.HashBytes(bytes);
            if (!StringComparer.Ordinal.Equals(rawSha256, source.RawSha256))
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' does not match its reviewed raw SHA-256.");
            }

            var content = NormalizeSource(bytes, source.Id);
            var lines = content.Split('\n');
            var packedSource = new ExpertContextPackSource
            {
                Id = source.Id,
                RelativePath = source.RelativePath,
                Title = source.Title,
                Provenance = source.Provenance,
                License = source.License,
                Domains = source.Domains.ToArray(),
                Rights = source.Rights,
                AvailableAtUtc = source.AvailableAtUtc,
                RawSha256 = rawSha256,
                ContentSha256 = ContentHasher.HashUtf8(content),
                RawByteCount = bytes.Length,
                LineCount = lines.Length
            };
            packedSources.Add(packedSource);
            chunks.AddRange(ChunkSource(packedSource, lines));
            if (chunks.Count > MaxChunkCount)
            {
                throw new CoordinatorValidationException(
                    $"Context corpus exceeds the {MaxChunkCount:N0}-chunk limit.");
            }
        }

        var manifestSha256 = ContentHasher.HashJson(manifest);
        var pack = new ExpertContextPack
        {
            SchemaVersion = PackSchemaVersion,
            CorpusId = manifest.CorpusId,
            CorpusVersion = manifest.CorpusVersion,
            NormalizerVersion = manifest.NormalizerVersion,
            ChunkerVersion = manifest.ChunkerVersion,
            TokenizerVersion = manifest.TokenizerVersion,
            ScorerVersion = manifest.ScorerVersion,
            CreatedAtUtc = manifest.CreatedAtUtc,
            CutoffUtc = manifest.CutoffUtc,
            ManifestSha256 = manifestSha256,
            IndexSha256 = ZeroSha256,
            PackSha256 = ZeroSha256,
            Sources = packedSources,
            Chunks = chunks
        };
        pack = pack with { IndexSha256 = CreateIndex(pack).Sha256 };
        pack = pack with { PackSha256 = ComputePackSha256(pack) };
        ValidatePack(pack);
        return pack;
    }

    public static ExpertContextPack Load(string path, string expectedPackSha256)
    {
        RequireSha256(expectedPackSha256, "Expected context pack SHA-256");
        var pack = ReadPack(path);
        EnsureExpectedPackSha256(pack, expectedPackSha256);
        ValidatePack(pack);
        return pack;
    }

    public static PreparedExpertContextPack LoadPrepared(
        string path,
        string expectedPackSha256)
    {
        RequireSha256(expectedPackSha256, "Expected context pack SHA-256");
        var pack = ReadPack(path);
        EnsureExpectedPackSha256(pack, expectedPackSha256);
        return new PreparedExpertContextPack(pack);
    }

    private static ExpertContextPack ReadPack(string path)
    {
        RequireText(path, "Context pack path", 2_048);
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new CoordinatorValidationException("Context pack file does not exist.");
        }
        RejectReparsePathComponents(fullPath, "Context pack path");

        byte[] bytes;
        using (var stream = new FileStream(
                   fullPath,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   bufferSize: 64 * 1024,
                   FileOptions.SequentialScan))
        {
            if (stream.Length is < 1 or > MaxPackBytes)
            {
                throw new CoordinatorValidationException(
                    $"Context pack must contain 1 to {MaxPackBytes:N0} bytes.");
            }
            bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.Position != stream.Length)
            {
                throw new CoordinatorValidationException("Context pack changed while it was being read.");
            }
        }
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException("Context pack must be BOM-less UTF-8 JSON.");
        }

        string json;
        try
        {
            json = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new CoordinatorValidationException(
                $"Context pack must be valid UTF-8: {exception.Message}");
        }

        ExpertContextPack pack;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });
            ValidateNoDuplicateProperties(document.RootElement, "context pack");
            pack = JsonSerializer.Deserialize<ExpertContextPack>(json, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException("Context pack JSON was null.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"Context pack JSON is invalid: {exception.Message}");
        }
        return pack;
    }

    private static void EnsureExpectedPackSha256(
        ExpertContextPack pack,
        string expectedPackSha256)
    {
        if (!StringComparer.Ordinal.Equals(pack.PackSha256, expectedPackSha256))
        {
            throw new CoordinatorValidationException(
                "Context pack does not match the server-pinned SHA-256.");
        }
    }

    public static void ValidateManifest(ExpertContextManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        RequireExact(manifest.SchemaVersion, ManifestSchemaVersion, "manifest schema version");
        ValidateCorpusIdentity(manifest.CorpusId, manifest.CorpusVersion);
        RequireExact(manifest.NormalizerVersion, NormalizerVersion, "normalizer version");
        RequireExact(manifest.ChunkerVersion, ChunkerVersion, "chunker version");
        RequireExact(manifest.TokenizerVersion, TokenizerVersion, "tokenizer version");
        RequireExact(manifest.ScorerVersion, ScorerVersion, "scorer version");
        ValidateUtc(manifest.CreatedAtUtc, "createdAtUtc");
        ValidateUtc(manifest.CutoffUtc, "cutoffUtc");
        if (manifest.CutoffUtc > manifest.CreatedAtUtc)
        {
            throw new CoordinatorValidationException("Context cutoff must not follow manifest creation.");
        }
        if (manifest.Sources is null || manifest.Sources.Count is < 1 or > MaxSourceCount)
        {
            throw new CoordinatorValidationException(
                $"Context manifest must contain 1 to {MaxSourceCount:N0} sources.");
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? priorId = null;
        foreach (var source in manifest.Sources)
        {
            if (source is null)
            {
                throw new CoordinatorValidationException("Context manifest sources must not contain null entries.");
            }
            ValidateSafeId(source.Id, "context source ID", 64);
            if (priorId is not null && StringComparer.Ordinal.Compare(priorId, source.Id) >= 0)
            {
                throw new CoordinatorValidationException(
                    "Context manifest sources must be strictly sorted by ordinal source ID.");
            }
            priorId = source.Id;
            if (!ids.Add(source.Id))
            {
                throw new CoordinatorValidationException($"Duplicate context source ID '{source.Id}'.");
            }
            ValidateRelativePath(source.RelativePath);
            if (!paths.Add(source.RelativePath))
            {
                throw new CoordinatorValidationException(
                    $"Duplicate context source path '{source.RelativePath}'.");
            }
            RequireText(source.Title, $"Context source '{source.Id}' title", 300);
            RequireText(source.Provenance, $"Context source '{source.Id}' provenance", 2_000);
            RequireText(source.License, $"Context source '{source.Id}' license", 200);
            ValidateDomains(source.Domains, source.Id);
            ValidateRights(source.Rights, source.Id);
            ValidateUtc(source.AvailableAtUtc, $"Context source '{source.Id}' availableAtUtc");
            if (source.AvailableAtUtc > manifest.CutoffUtc)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' was unavailable at the corpus cutoff.");
            }
            RequireSha256(source.RawSha256, $"Context source '{source.Id}' raw SHA-256");
        }
    }

    public static void ValidatePack(ExpertContextPack pack) =>
        _ = ValidatePackAndCreateIndex(pack);

    internal static LexicalIndex ValidatePackAndCreateIndex(ExpertContextPack pack)
    {
        ArgumentNullException.ThrowIfNull(pack);
        RequireExact(pack.SchemaVersion, PackSchemaVersion, "pack schema version");
        ValidateCorpusIdentity(pack.CorpusId, pack.CorpusVersion);
        RequireExact(pack.NormalizerVersion, NormalizerVersion, "normalizer version");
        RequireExact(pack.ChunkerVersion, ChunkerVersion, "chunker version");
        RequireExact(pack.TokenizerVersion, TokenizerVersion, "tokenizer version");
        RequireExact(pack.ScorerVersion, ScorerVersion, "scorer version");
        ValidateUtc(pack.CreatedAtUtc, "createdAtUtc");
        ValidateUtc(pack.CutoffUtc, "cutoffUtc");
        if (pack.CutoffUtc > pack.CreatedAtUtc)
        {
            throw new CoordinatorValidationException("Context cutoff must not follow pack creation.");
        }
        RequireSha256(pack.ManifestSha256, "manifest SHA-256");
        RequireSha256(pack.IndexSha256, "index SHA-256");
        RequireSha256(pack.PackSha256, "pack SHA-256");
        if (pack.Sources is null || pack.Sources.Count is < 1 or > MaxSourceCount)
        {
            throw new CoordinatorValidationException(
                $"Context pack must contain 1 to {MaxSourceCount:N0} sources.");
        }
        if (pack.Chunks is null || pack.Chunks.Count is < 1 or > MaxChunkCount)
        {
            throw new CoordinatorValidationException(
                $"Context pack must contain 1 to {MaxChunkCount:N0} chunks.");
        }

        var sourceById = new Dictionary<string, ExpertContextPackSource>(StringComparer.Ordinal);
        var sourcePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? priorSourceId = null;
        long aggregateBytes = 0;
        foreach (var source in pack.Sources)
        {
            if (source is null)
            {
                throw new CoordinatorValidationException("Context pack sources must not contain null entries.");
            }
            ValidateSafeId(source.Id, "context source ID", 64);
            if (priorSourceId is not null && StringComparer.Ordinal.Compare(priorSourceId, source.Id) >= 0)
            {
                throw new CoordinatorValidationException(
                    "Context pack sources must be strictly sorted by ordinal source ID.");
            }
            priorSourceId = source.Id;
            if (!sourceById.TryAdd(source.Id, source))
            {
                throw new CoordinatorValidationException($"Duplicate context source ID '{source.Id}'.");
            }
            ValidateRelativePath(source.RelativePath);
            if (!sourcePaths.Add(source.RelativePath))
            {
                throw new CoordinatorValidationException(
                    $"Duplicate context source path '{source.RelativePath}'.");
            }
            RequireText(source.Title, $"Context source '{source.Id}' title", 300);
            RequireText(source.Provenance, $"Context source '{source.Id}' provenance", 2_000);
            RequireText(source.License, $"Context source '{source.Id}' license", 200);
            ValidateDomains(source.Domains, source.Id);
            ValidateRights(source.Rights, source.Id);
            ValidateUtc(source.AvailableAtUtc, $"Context source '{source.Id}' availableAtUtc");
            if (source.AvailableAtUtc > pack.CutoffUtc)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' was unavailable at the corpus cutoff.");
            }
            RequireSha256(source.RawSha256, $"Context source '{source.Id}' raw SHA-256");
            RequireSha256(source.ContentSha256, $"Context source '{source.Id}' content SHA-256");
            if (source.RawByteCount is < 1 or > MaxSourceBytes || source.LineCount < 1)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' has invalid byte or line counts.");
            }
            aggregateBytes = checked(aggregateBytes + source.RawByteCount);
            if (aggregateBytes > MaxAggregateSourceBytes)
            {
                throw new CoordinatorValidationException(
                    $"Context pack exceeds the {MaxAggregateSourceBytes:N0}-byte aggregate limit.");
            }
        }

        var chunksBySource = new Dictionary<string, List<ExpertContextChunk>>(StringComparer.Ordinal);
        var chunkIds = new HashSet<string>(StringComparer.Ordinal);
        string? priorChunkSource = null;
        var priorOrdinal = -1;
        foreach (var chunk in pack.Chunks)
        {
            if (chunk is null)
            {
                throw new CoordinatorValidationException("Context chunks must not contain null entries.");
            }
            if (!sourceById.TryGetValue(chunk.SourceId, out var source))
            {
                throw new CoordinatorValidationException(
                    $"Context chunk '{chunk.Id}' references an unknown source.");
            }
            if (priorChunkSource is not null)
            {
                var sourceOrder = StringComparer.Ordinal.Compare(priorChunkSource, chunk.SourceId);
                if (sourceOrder > 0 || (sourceOrder == 0 && chunk.Ordinal <= priorOrdinal))
                {
                    throw new CoordinatorValidationException(
                        "Context chunks must be strictly sorted by source ID and ordinal.");
                }
            }
            if (!StringComparer.Ordinal.Equals(priorChunkSource, chunk.SourceId))
            {
                priorOrdinal = -1;
            }
            priorChunkSource = chunk.SourceId;
            priorOrdinal = chunk.Ordinal;

            if (chunk.Ordinal < 0 || chunk.StartLine < 1 || chunk.EndLine < chunk.StartLine ||
                chunk.EndLine > source.LineCount)
            {
                throw new CoordinatorValidationException($"Context chunk '{chunk.Id}' has an invalid range.");
            }
            if (string.IsNullOrEmpty(chunk.Content) || chunk.Content.Length > MaxChunkCharacters ||
                !StringComparer.Ordinal.Equals(chunk.Content, NormalizeText(chunk.Content)))
            {
                throw new CoordinatorValidationException(
                    $"Context chunk '{chunk.Id}' is empty, oversized, or not canonically normalized.");
            }
            if (chunk.Content.Split('\n').Length != chunk.EndLine - chunk.StartLine + 1)
            {
                throw new CoordinatorValidationException(
                    $"Context chunk '{chunk.Id}' content does not match its line range.");
            }
            RequireSha256(chunk.ContentSha256, $"Context chunk '{chunk.Id}' content SHA-256");
            if (!StringComparer.Ordinal.Equals(ContentHasher.HashUtf8(chunk.Content), chunk.ContentSha256))
            {
                throw new CoordinatorValidationException(
                    $"Context chunk '{chunk.Id}' content SHA-256 does not match its content.");
            }
            var expectedId = ComputeChunkId(chunk.SourceId, chunk.Ordinal, chunk.ContentSha256);
            if (!StringComparer.Ordinal.Equals(expectedId, chunk.Id) || !chunkIds.Add(chunk.Id))
            {
                throw new CoordinatorValidationException(
                    $"Context chunk '{chunk.Id}' has an invalid or duplicate content-derived ID.");
            }
            if (!SequenceEqual(chunk.Domains, source.Domains))
            {
                throw new CoordinatorValidationException(
                    $"Context chunk '{chunk.Id}' domains do not match its source.");
            }
            if (!chunksBySource.TryGetValue(chunk.SourceId, out var sourceChunks))
            {
                sourceChunks = [];
                chunksBySource.Add(chunk.SourceId, sourceChunks);
            }
            sourceChunks.Add(chunk);
        }

        foreach (var source in pack.Sources)
        {
            if (!chunksBySource.TryGetValue(source.Id, out var sourceChunks))
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' has no chunks.");
            }
            ValidateChunkCoverage(source, sourceChunks);
        }

        var index = CreateIndex(pack);
        if (!StringComparer.Ordinal.Equals(pack.IndexSha256, index.Sha256))
        {
            throw new CoordinatorValidationException(
                "Context index SHA-256 does not match its deterministic lexical postings.");
        }

        if (!StringComparer.Ordinal.Equals(pack.PackSha256, ComputePackSha256(pack)))
        {
            throw new CoordinatorValidationException("Context pack SHA-256 does not match its canonical content.");
        }
        return index;
    }

    public static string ComputePackSha256(ExpertContextPack pack)
    {
        ArgumentNullException.ThrowIfNull(pack);
        return ContentHasher.HashJson(pack with { PackSha256 = ZeroSha256 });
    }

    public static void ValidateSelection(ExpertContextPack pack, ExpertContextSelection selection)
    {
        ValidatePack(pack);
        ValidateSelectionForPreparedPack(pack, selection);
    }

    internal static void ValidateSelectionForPreparedPack(
        ExpertContextPack pack,
        ExpertContextSelection selection,
        LexicalIndex? lexicalIndex = null)
    {
        ArgumentNullException.ThrowIfNull(selection);
        RequireExact(selection.SchemaVersion, SelectionSchemaVersion, "selection schema version");
        if (!StringComparer.Ordinal.Equals(selection.CorpusId, pack.CorpusId) ||
            !StringComparer.Ordinal.Equals(selection.CorpusVersion, pack.CorpusVersion) ||
            !StringComparer.Ordinal.Equals(selection.PackSha256, pack.PackSha256) ||
            !StringComparer.Ordinal.Equals(selection.IndexSha256, pack.IndexSha256))
        {
            throw new CoordinatorValidationException("Context selection does not bind the supplied pack.");
        }
        RequireSha256(selection.TenantScopeSha256, "tenant scope SHA-256");
        RequireSha256(selection.QuerySha256, "query SHA-256");
        RequireSha256(selection.PolicySha256, "policy SHA-256");
        RequireSha256(selection.SelectionSha256, "selection SHA-256");
        if (selection.Hits is null || selection.Hits.Count is < 1 or > MaxSelectionCount)
        {
            throw new CoordinatorValidationException(
                $"Context selection must contain 1 to {MaxSelectionCount} hits.");
        }

        var chunkById = lexicalIndex?.ChunksById ??
            pack.Chunks.ToDictionary(chunk => chunk.Id, StringComparer.Ordinal);
        var sourceById = lexicalIndex?.SourcesById ??
            pack.Sources.ToDictionary(source => source.Id, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        ExpertContextHit? prior = null;
        var aggregateCharacters = 0;
        for (var index = 0; index < selection.Hits.Count; index++)
        {
            var hit = selection.Hits[index] ??
                throw new CoordinatorValidationException("Context selection hits must not contain null entries.");
            if (hit.Rank != index + 1 || hit.Score <= 0 || !seen.Add(hit.ChunkId))
            {
                throw new CoordinatorValidationException("Context selection ranks, scores, or chunk IDs are invalid.");
            }
            if (!chunkById.TryGetValue(hit.ChunkId, out var chunk) ||
                !sourceById.TryGetValue(chunk.SourceId, out var source))
            {
                throw new CoordinatorValidationException(
                    $"Context hit '{hit.ChunkId}' does not exist in the bound pack.");
            }
            if (!source.Rights.MayUploadToProvider)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' is not licensed for provider upload.");
            }
            var expectedCitationId = ReservedSourcePrefix + chunk.Id;
            if (!StringComparer.Ordinal.Equals(hit.CitationId, expectedCitationId) ||
                !StringComparer.Ordinal.Equals(hit.SourceId, source.Id) ||
                !StringComparer.Ordinal.Equals(hit.Title, source.Title) ||
                hit.StartLine != chunk.StartLine || hit.EndLine != chunk.EndLine ||
                !StringComparer.Ordinal.Equals(hit.Content, chunk.Content) ||
                !StringComparer.Ordinal.Equals(hit.ContentSha256, chunk.ContentSha256) ||
                !StringComparer.Ordinal.Equals(hit.License, source.License))
            {
                throw new CoordinatorValidationException(
                    $"Context hit '{hit.ChunkId}' does not match its bound chunk and source.");
            }
            if (prior is not null && CompareHitOrder(prior, hit) > 0)
            {
                throw new CoordinatorValidationException("Context hits are not in deterministic score order.");
            }
            prior = hit;
            aggregateCharacters = checked(aggregateCharacters + hit.Content.Length);
            if (aggregateCharacters > MaxSelectionCharacters)
            {
                throw new CoordinatorValidationException(
                    $"Context selection exceeds {MaxSelectionCharacters:N0} characters.");
            }
        }
        if (!StringComparer.Ordinal.Equals(selection.SelectionSha256, ComputeSelectionSha256(selection)))
        {
            throw new CoordinatorValidationException(
                "Context selection SHA-256 does not match its canonical content.");
        }
    }

    public static IReadOnlyList<CoordinatorContextSource> MaterializeExecutionSources(
        IReadOnlyList<CoordinatorContextSource> submittedSources,
        ExpertContextPack pack,
        ExpertContextSelection selection)
    {
        ValidatePack(pack);
        return MaterializeExecutionSourcesForPreparedPack(submittedSources, pack, selection);
    }

    internal static IReadOnlyList<CoordinatorContextSource> MaterializeExecutionSourcesForPreparedPack(
        IReadOnlyList<CoordinatorContextSource> submittedSources,
        ExpertContextPack pack,
        ExpertContextSelection selection,
        LexicalIndex? lexicalIndex = null)
    {
        ArgumentNullException.ThrowIfNull(submittedSources);
        ValidateSelectionForPreparedPack(pack, selection, lexicalIndex);
        var result = new List<CoordinatorContextSource>(submittedSources.Count + selection.Hits.Count + 1);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var aggregateCharacters = 0;
        foreach (var source in submittedSources)
        {
            if (source is null)
            {
                throw new CoordinatorValidationException("Submitted sources must not contain null entries.");
            }
            if (source.Id.StartsWith(ReservedSourcePrefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new CoordinatorValidationException(
                    $"Submitted source ID '{source.Id}' uses the reserved private-context prefix.");
            }
            if (!ids.Add(source.Id))
            {
                throw new CoordinatorValidationException($"Duplicate submitted source ID '{source.Id}'.");
            }
            aggregateCharacters = checked(aggregateCharacters + (source.Content?.Length ?? 0));
            result.Add(source);
        }

        var manifestContent = JsonSerializer.Serialize(
            new ExecutionContextManifest(
                selection.CorpusId,
                selection.CorpusVersion,
                selection.PackSha256,
                selection.IndexSha256,
                selection.TenantScopeSha256,
                selection.QuerySha256,
                selection.PolicySha256,
                selection.SelectionSha256,
                selection.Hits.Select(hit => new ExecutionContextChunkBinding(
                    hit.CitationId,
                    hit.ContentSha256)).ToArray()),
            CoordinatorJson.Options);
        Add(new CoordinatorContextSource(
            ReservedSourcePrefix + "manifest",
            "DaxAlgo private context identity",
            manifestContent,
            License: "DaxAlgo private context; provider upload permitted",
            RetrievedAtUtc: pack.CreatedAtUtc));

        foreach (var hit in selection.Hits)
        {
            Add(new CoordinatorContextSource(
                hit.CitationId,
                $"{hit.Title} (lines {hit.StartLine}-{hit.EndLine})",
                hit.Content,
                License: hit.License,
                RetrievedAtUtc: pack.CreatedAtUtc));
        }
        return result;

        void Add(CoordinatorContextSource source)
        {
            if (!ids.Add(source.Id))
            {
                throw new CoordinatorValidationException(
                    $"Private context source ID '{source.Id}' collides with an execution source.");
            }
            aggregateCharacters = checked(aggregateCharacters + source.Content.Length);
            if (result.Count + 1 > CoordinatorValidation.MaxSourceCount ||
                aggregateCharacters > CoordinatorValidation.MaxAggregateSourceCharacters)
            {
                throw new CoordinatorValidationException(
                    "Selected private context does not fit the coordinator execution-source budget.");
            }
            result.Add(source);
        }
    }

    internal static string NormalizeQuery(string query)
    {
        RequireText(query, "Context query", MaxQueryCharacters);
        var normalized = NormalizeText(query);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new CoordinatorValidationException("Context query is required.");
        }
        return normalized;
    }

    public static void ValidateQueryPolicy(ExpertContextQueryPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        RequireExact(policy.SchemaVersion, QueryPolicySchemaVersion, "query policy schema version");
        if (policy.TopK is < 1 or > MaxSelectionCount ||
            policy.MaxCharacters is < 1 or > MaxSelectionCharacters ||
            policy.MaxPerSource is < 1 || policy.MaxPerSource > policy.TopK)
        {
            throw new CoordinatorValidationException("Context query policy limits are invalid.");
        }
    }

    internal static IReadOnlyList<ScoredChunk> Rank(
        ExpertContextPack pack,
        LexicalIndex index,
        string normalizedQuery)
    {
        var queryTokens = Tokenize(normalizedQuery).Distinct(StringComparer.Ordinal).ToArray();
        if (queryTokens.Length == 0)
        {
            throw new CoordinatorValidationException("Context query contains no searchable tokens.");
        }
        var scores = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var token in queryTokens)
        {
            if (!index.Postings.TryGetValue(token, out var postings))
            {
                continue;
            }
            foreach (var posting in postings)
            {
                scores.TryGetValue(posting.ChunkId, out var score);
                if (posting.ContentFrequency > 0)
                {
                    score += 1_000 + Math.Min(posting.ContentFrequency, 16) * 25;
                }
                if (posting.InTitle)
                {
                    score += 250;
                }
                if (posting.InDomain)
                {
                    score += 150;
                }
                scores[posting.ChunkId] = score;
            }
        }

        return scores.Select(item =>
            {
                var chunk = index.ChunksById[item.Key];
                return new ScoredChunk(
                    chunk,
                    index.SourcesById[chunk.SourceId],
                    checked((int)Math.Min(item.Value, int.MaxValue)));
            })
            .OrderByDescending(item => item.Score)
            .ThenBy(item => item.Source.Id, StringComparer.Ordinal)
            .ThenBy(item => item.Chunk.StartLine)
            .ThenBy(item => item.Chunk.Id, StringComparer.Ordinal)
            .ToArray();
    }

    internal static LexicalIndex CreateIndex(ExpertContextPack pack)
    {
        var sourceById = pack.Sources.ToDictionary(source => source.Id, StringComparer.Ordinal);
        var chunkById = pack.Chunks.ToDictionary(chunk => chunk.Id, StringComparer.Ordinal);
        var postings = new Dictionary<string, List<LexicalPosting>>(StringComparer.Ordinal);
        foreach (var chunk in pack.Chunks)
        {
            var source = sourceById[chunk.SourceId];
            var frequencies = Tokenize(chunk.Content)
                .GroupBy(token => token, StringComparer.Ordinal)
                .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
            var titleTokens = Tokenize(source.Title).ToHashSet(StringComparer.Ordinal);
            var domainTokens = source.Domains
                .SelectMany(domain => Tokenize(domain.ToString()))
                .ToHashSet(StringComparer.Ordinal);
            var tokens = frequencies.Keys
                .Concat(titleTokens)
                .Concat(domainTokens)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(token => token, StringComparer.Ordinal);
            foreach (var token in tokens)
            {
                frequencies.TryGetValue(token, out var frequency);
                if (!postings.TryGetValue(token, out var tokenPostings))
                {
                    tokenPostings = [];
                    postings.Add(token, tokenPostings);
                }
                tokenPostings.Add(new LexicalPosting(
                    chunk.Id,
                    frequency,
                    titleTokens.Contains(token),
                    domainTokens.Contains(token)));
            }
        }

        var ordered = postings
            .OrderBy(item => item.Key, StringComparer.Ordinal)
            .Select(item => new LexicalTokenIdentity(
                item.Key,
                item.Value.OrderBy(posting => posting.ChunkId, StringComparer.Ordinal).ToArray()))
            .ToArray();
        var identity = new LexicalIndexIdentity(
            IndexSchemaVersion,
            pack.CorpusId,
            pack.CorpusVersion,
            pack.TokenizerVersion,
            pack.ScorerVersion,
            ordered);
        return new LexicalIndex(
            ordered.ToDictionary(
                item => item.Token,
                item => (IReadOnlyList<LexicalPosting>)item.Postings,
                StringComparer.Ordinal),
            sourceById,
            chunkById,
            ContentHasher.HashJson(identity));
    }

    internal static string ComputeTenantScopeSha256(string tenantId) =>
        ContentHasher.HashUtf8("daxalgo-expert-context-tenant/v1\0" + tenantId);

    internal static string ComputeQuerySha256(string normalizedQuery) =>
        ContentHasher.HashUtf8("daxalgo-expert-context-query/v1\0" + normalizedQuery);

    internal static string ComputePolicySha256(ExpertContextQueryPolicy policy) =>
        ContentHasher.HashJson(policy);

    internal static string ComputeSelectionSha256(ExpertContextSelection selection) =>
        ContentHasher.HashJson(selection with { SelectionSha256 = ZeroSha256 });

    private static IEnumerable<ExpertContextChunk> ChunkSource(
        ExpertContextPackSource source,
        IReadOnlyList<string> lines)
    {
        var chunks = new List<ExpertContextChunk>();
        var start = 0;
        var ordinal = 0;
        while (start < lines.Count)
        {
            var end = start;
            var characters = 0;
            while (end < lines.Count && end - start < MaxChunkLines)
            {
                var added = lines[end].Length + (end == start ? 0 : 1);
                if (characters + added > MaxChunkCharacters)
                {
                    break;
                }
                characters += added;
                end++;
            }
            if (end == start)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' contains a line longer than {MaxChunkCharacters:N0} characters.");
            }
            var content = string.Join("\n", lines.Skip(start).Take(end - start));
            var contentSha256 = ContentHasher.HashUtf8(content);
            chunks.Add(new ExpertContextChunk
            {
                Id = ComputeChunkId(source.Id, ordinal, contentSha256),
                SourceId = source.Id,
                Ordinal = ordinal,
                StartLine = start + 1,
                EndLine = end,
                Content = content,
                ContentSha256 = contentSha256,
                Domains = source.Domains.ToArray()
            });
            ordinal++;
            start = end == lines.Count
                ? end
                : Math.Max(start + 1, end - ChunkOverlapLines);
        }
        return chunks;
    }

    private static void ValidateChunkCoverage(
        ExpertContextPackSource source,
        IReadOnlyList<ExpertContextChunk> chunks)
    {
        var reconstructedLines = new List<string>(source.LineCount);
        for (var index = 0; index < chunks.Count; index++)
        {
            var chunk = chunks[index];
            if (chunk.Ordinal != index)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' chunk ordinals must be contiguous from zero.");
            }
            var expectedStart = index == 0
                ? 1
                : Math.Max(chunks[index - 1].StartLine + 1,
                    chunks[index - 1].EndLine - ChunkOverlapLines + 1);
            if (chunk.StartLine != expectedStart)
            {
                throw new CoordinatorValidationException(
                    $"Context source '{source.Id}' chunk overlap is not canonical.");
            }

            var chunkLines = chunk.Content.Split('\n');
            for (var lineIndex = 0; lineIndex < chunkLines.Length; lineIndex++)
            {
                var sourceLineIndex = chunk.StartLine - 1 + lineIndex;
                if (sourceLineIndex < reconstructedLines.Count)
                {
                    if (!StringComparer.Ordinal.Equals(
                            reconstructedLines[sourceLineIndex],
                            chunkLines[lineIndex]))
                    {
                        throw new CoordinatorValidationException(
                            $"Context source '{source.Id}' overlapping chunks disagree.");
                    }
                }
                else if (sourceLineIndex == reconstructedLines.Count)
                {
                    reconstructedLines.Add(chunkLines[lineIndex]);
                }
                else
                {
                    throw new CoordinatorValidationException(
                        $"Context source '{source.Id}' chunks contain a line gap.");
                }
            }
        }
        if (chunks[^1].EndLine != source.LineCount || reconstructedLines.Count != source.LineCount)
        {
            throw new CoordinatorValidationException(
                $"Context source '{source.Id}' chunks do not cover the complete source.");
        }
        var reconstructedContent = string.Join("\n", reconstructedLines);
        if (!StringComparer.Ordinal.Equals(
                source.ContentSha256,
                ContentHasher.HashUtf8(reconstructedContent)))
        {
            throw new CoordinatorValidationException(
                $"Context source '{source.Id}' content SHA-256 does not match its chunks.");
        }
    }

    private static string ResolveSourceRoot(string sourceRoot)
    {
        RequireText(sourceRoot, "Context source root", 1_024);
        var root = Path.GetFullPath(sourceRoot);
        if (!Directory.Exists(root))
        {
            throw new CoordinatorValidationException("Context source root does not exist.");
        }
        RejectReparsePoint(root, "Context source root");
        return Path.TrimEndingDirectorySeparator(root);
    }

    private static async Task<byte[]> ReadSourceAsync(
        string root,
        string relativePath,
        CancellationToken cancellationToken)
    {
        var platformPath = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(Path.Combine(root, platformPath));
        var expectedRelative = Path.GetRelativePath(root, fullPath)
            .Replace(Path.DirectorySeparatorChar, '/');
        if (!StringComparer.OrdinalIgnoreCase.Equals(expectedRelative, relativePath))
        {
            throw new CoordinatorValidationException(
                $"Context source path '{relativePath}' escapes or aliases its source root.");
        }

        var current = root;
        foreach (var segment in relativePath.Split('/'))
        {
            current = Path.Combine(current, segment);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                throw new CoordinatorValidationException(
                    $"Context source path '{relativePath}' does not exist.");
            }
            RejectReparsePoint(current, $"Context source path '{relativePath}'");
        }
        if (!File.Exists(fullPath))
        {
            throw new CoordinatorValidationException(
                $"Context source path '{relativePath}' is not a file.");
        }

        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length is < 1 or > MaxSourceBytes)
        {
            throw new CoordinatorValidationException(
                $"Context source '{relativePath}' must contain 1 to {MaxSourceBytes:N0} bytes.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.Position != stream.Length)
        {
            throw new CoordinatorValidationException(
                $"Context source '{relativePath}' changed while it was being read.");
        }
        return bytes;
    }

    private static string NormalizeSource(byte[] bytes, string sourceId)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException(
                $"Context source '{sourceId}' must be BOM-less UTF-8.");
        }
        string text;
        try
        {
            text = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new CoordinatorValidationException(
                $"Context source '{sourceId}' must be valid UTF-8: {exception.Message}");
        }
        var normalized = NormalizeText(text);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new CoordinatorValidationException(
                $"Context source '{sourceId}' must contain non-whitespace text.");
        }
        return normalized;
    }

    private static string NormalizeText(string value)
    {
        if (value.IndexOf('\0') >= 0)
        {
            throw new CoordinatorValidationException("Context text must not contain NUL characters.");
        }
        try
        {
            return value.Replace("\r\n", "\n", StringComparison.Ordinal)
                .Replace('\r', '\n')
                .Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException exception)
        {
            throw new CoordinatorValidationException(
                $"Context text is not valid Unicode: {exception.Message}");
        }
    }

    private static IReadOnlyList<string> Tokenize(string value)
    {
        var tokens = new List<string>();
        var raw = new StringBuilder();
        foreach (var character in value)
        {
            if (char.IsLetterOrDigit(character))
            {
                if (raw.Length < 128)
                {
                    raw.Append(character);
                }
            }
            else
            {
                AddIdentifierTokens(raw, tokens);
            }
        }
        AddIdentifierTokens(raw, tokens);
        return tokens;
    }

    private static void AddIdentifierTokens(StringBuilder raw, ICollection<string> tokens)
    {
        if (raw.Length == 0)
        {
            return;
        }
        var value = raw.ToString();
        raw.Clear();
        tokens.Add(value.ToLowerInvariant());
        var start = 0;
        var parts = new List<string>();
        for (var index = 1; index < value.Length; index++)
        {
            var previous = value[index - 1];
            var current = value[index];
            var nextIsLower = index + 1 < value.Length && char.IsLower(value[index + 1]);
            var boundary =
                char.IsLower(previous) && char.IsUpper(current) ||
                char.IsLetter(previous) != char.IsLetter(current) ||
                char.IsUpper(previous) && char.IsUpper(current) && nextIsLower;
            if (boundary)
            {
                parts.Add(value[start..index].ToLowerInvariant());
                start = index;
            }
        }
        parts.Add(value[start..].ToLowerInvariant());
        if (parts.Count > 1)
        {
            foreach (var part in parts)
            {
                if (part.Length > 0)
                {
                    tokens.Add(part);
                }
            }
        }
    }

    private static string ComputeChunkId(string sourceId, int ordinal, string contentSha256) =>
        $"{sourceId}.{ordinal:D5}.{contentSha256[..12]}";

    private static int CompareHitOrder(ExpertContextHit left, ExpertContextHit right)
    {
        var score = right.Score.CompareTo(left.Score);
        if (score != 0)
        {
            return score;
        }
        var source = StringComparer.Ordinal.Compare(left.SourceId, right.SourceId);
        if (source != 0)
        {
            return source;
        }
        var line = left.StartLine.CompareTo(right.StartLine);
        return line != 0 ? line : StringComparer.Ordinal.Compare(left.ChunkId, right.ChunkId);
    }

    private static void ValidateCorpusIdentity(string corpusId, string corpusVersion)
    {
        ValidateSafeId(corpusId, "corpus ID", 100);
        ValidateSafeId(corpusVersion, "corpus version", 100);
        if (corpusVersion.Equals("latest", StringComparison.OrdinalIgnoreCase) ||
            corpusVersion.Equals("main", StringComparison.OrdinalIgnoreCase) ||
            corpusVersion.Equals("master", StringComparison.OrdinalIgnoreCase) ||
            corpusVersion.Equals("trunk", StringComparison.OrdinalIgnoreCase))
        {
            throw new CoordinatorValidationException("Context corpus version must be immutable.");
        }
    }

    private static void ValidateSafeId(string value, string name, int maxLength)
    {
        RequireText(value, name, maxLength);
        if (!value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new CoordinatorValidationException(
                $"{name} may contain only ASCII letters, digits, '.', '-' and '_'.");
        }
    }

    private static void ValidateRelativePath(string path)
    {
        RequireText(path, "Context source relative path", 500);
        if (Path.IsPathFullyQualified(path) || path.Contains('\\') || path.StartsWith('/') ||
            path.EndsWith('/') || path.Contains(':') ||
            path.Split('/').Any(segment => segment is "" or "." or ".."))
        {
            throw new CoordinatorValidationException(
                $"Context source path '{path}' must be a canonical forward-slash relative path.");
        }
    }

    private static void ValidateDomains(IReadOnlyList<ExpertDomain> domains, string sourceId)
    {
        if (domains is null || domains.Count == 0 ||
            domains.Any(domain => !Enum.IsDefined(domain)) ||
            !domains.SequenceEqual(domains.Distinct().OrderBy(domain => domain)))
        {
            throw new CoordinatorValidationException(
                $"Context source '{sourceId}' domains must be non-empty, unique, and enum-sorted.");
        }
    }

    private static void ValidateRights(DatasetRights rights, string sourceId)
    {
        if (rights is null || !rights.MayStore || !rights.MayEvaluate)
        {
            throw new CoordinatorValidationException(
                $"Context source '{sourceId}' requires storage and evaluation rights.");
        }
    }

    private static void ValidateUtc(DateTimeOffset value, string name)
    {
        if (value == default || value.Offset != TimeSpan.Zero)
        {
            throw new CoordinatorValidationException($"{name} must be an explicit UTC timestamp.");
        }
    }

    private static void RequireText(string value, string name, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maxLength)
        {
            throw new CoordinatorValidationException(
                $"{name} is required and must not exceed {maxLength:N0} characters.");
        }
    }

    private static void RequireExact(string actual, string expected, string name)
    {
        if (!StringComparer.Ordinal.Equals(actual, expected))
        {
            throw new CoordinatorValidationException($"Unsupported {name} '{actual}'.");
        }
    }

    private static void RequireSha256(string value, string name)
    {
        if (value is null || value.Length != 64 ||
            !value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f'))
        {
            throw new CoordinatorValidationException($"{name} must be a lowercase SHA-256 value.");
        }
    }

    private static bool SequenceEqual<T>(IReadOnlyList<T> left, IReadOnlyList<T> right) =>
        left is not null && right is not null && left.SequenceEqual(right);

    private static void RejectReparsePoint(string path, string name)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CoordinatorValidationException($"{name} could not be inspected: {exception.Message}");
        }
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new CoordinatorValidationException($"{name} must not traverse a reparse point.");
        }
    }

    private static void RejectReparsePathComponents(string fullPath, string name)
    {
        var root = Path.GetPathRoot(fullPath)
            ?? throw new CoordinatorValidationException($"{name} has no filesystem root.");
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, fullPath)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            RejectReparsePoint(current, name);
        }
    }

    private static void ValidateNoDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new CoordinatorValidationException(
                        $"{path} contains duplicate property '{property.Name}'.");
                }
                ValidateNoDuplicateProperties(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item, $"{path}[{index}]");
                index++;
            }
        }
    }

    internal sealed record ScoredChunk(
        ExpertContextChunk Chunk,
        ExpertContextPackSource Source,
        int Score);

    internal sealed record LexicalIndex(
        IReadOnlyDictionary<string, IReadOnlyList<LexicalPosting>> Postings,
        IReadOnlyDictionary<string, ExpertContextPackSource> SourcesById,
        IReadOnlyDictionary<string, ExpertContextChunk> ChunksById,
        string Sha256);

    internal sealed record LexicalPosting(
        string ChunkId,
        int ContentFrequency,
        bool InTitle,
        bool InDomain);

    private sealed record LexicalTokenIdentity(
        string Token,
        IReadOnlyList<LexicalPosting> Postings);

    private sealed record LexicalIndexIdentity(
        string SchemaVersion,
        string CorpusId,
        string CorpusVersion,
        string TokenizerVersion,
        string ScorerVersion,
        IReadOnlyList<LexicalTokenIdentity> Tokens);

    private sealed record ExecutionContextManifest(
        string CorpusId,
        string CorpusVersion,
        string PackSha256,
        string IndexSha256,
        string TenantScopeSha256,
        string QuerySha256,
        string PolicySha256,
        string SelectionSha256,
        IReadOnlyList<ExecutionContextChunkBinding> Chunks);

    private sealed record ExecutionContextChunkBinding(
        string CitationId,
        string ContentSha256);
}

public sealed class PreparedExpertContextPack
{
    private readonly ExpertContextPack pack;
    private readonly ExpertContextPackTools.LexicalIndex index;

    public PreparedExpertContextPack(ExpertContextPack pack)
    {
        this.pack = pack ?? throw new ArgumentNullException(nameof(pack));
        index = ExpertContextPackTools.ValidatePackAndCreateIndex(pack);
        PinnedExpertContextPackResolver.ValidateHostedRights(pack);
    }

    public string CorpusId => pack.CorpusId;

    public string CorpusVersion => pack.CorpusVersion;

    public string PackSha256 => pack.PackSha256;

    public PinnedExpertContextPackResolver Activate(ExpertContextActivation activation) =>
        new(pack, activation, index);

    public IReadOnlyList<CoordinatorContextSource> MaterializeExecutionSources(
        IReadOnlyList<CoordinatorContextSource> submittedSources,
        ExpertContextSelection selection) =>
        ExpertContextPackTools.MaterializeExecutionSourcesForPreparedPack(
            submittedSources,
            pack,
            selection,
            index);
}

public sealed class PinnedExpertContextPackResolver : IExpertContextPackResolver
{
    private readonly ExpertContextPack _pack;
    private readonly ExpertContextActivation _activation;
    private readonly ExpertContextPackTools.LexicalIndex _index;

    public PinnedExpertContextPackResolver(
        ExpertContextPack pack,
        ExpertContextActivation activation)
    {
        _pack = pack ?? throw new ArgumentNullException(nameof(pack));
        _index = ExpertContextPackTools.ValidatePackAndCreateIndex(pack);
        ValidateHostedRights(pack);
        ValidateActivation(pack, activation);
        _activation = activation;
    }

    internal PinnedExpertContextPackResolver(
        ExpertContextPack pack,
        ExpertContextActivation activation,
        ExpertContextPackTools.LexicalIndex index)
    {
        _pack = pack;
        _index = index;
        ValidateActivation(pack, activation);
        _activation = activation;
    }

    internal static void ValidateHostedRights(ExpertContextPack pack)
    {
        var unlicensed = pack.Sources.FirstOrDefault(source => !source.Rights.MayUploadToProvider);
        if (unlicensed is not null)
        {
            throw new CoordinatorValidationException(
                $"Context source '{unlicensed.Id}' is not licensed for hosted provider upload.");
        }
    }

    private static void ValidateActivation(
        ExpertContextPack pack,
        ExpertContextActivation activation)
    {
        ArgumentNullException.ThrowIfNull(activation);
        if (string.IsNullOrWhiteSpace(activation.TenantId) || activation.TenantId.Length > 200 ||
            activation.TenantId.Any(char.IsControl))
        {
            throw new CoordinatorValidationException("Context activation tenant ID is invalid.");
        }
        if (!StringComparer.Ordinal.Equals(activation.CorpusId, pack.CorpusId) ||
            !StringComparer.Ordinal.Equals(activation.CorpusVersion, pack.CorpusVersion) ||
            !StringComparer.Ordinal.Equals(activation.PackSha256, pack.PackSha256))
        {
            throw new CoordinatorValidationException("Context activation does not bind the supplied pack.");
        }
    }

    public ExpertContextSelection Resolve(ExpertContextResolutionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ExpertContextPackTools.ValidateQueryPolicy(request.Policy);
        if (!StringComparer.Ordinal.Equals(request.TenantId, _activation.TenantId) ||
            !StringComparer.Ordinal.Equals(request.CorpusId, _activation.CorpusId) ||
            !StringComparer.Ordinal.Equals(request.CorpusVersion, _activation.CorpusVersion) ||
            !StringComparer.Ordinal.Equals(request.PackSha256, _activation.PackSha256))
        {
            throw new CoordinatorValidationException(
                "Context request does not match the server-owned tenant and pack activation.");
        }

        var normalizedQuery = ExpertContextPackTools.NormalizeQuery(request.Query);
        var ranked = ExpertContextPackTools.Rank(_pack, _index, normalizedQuery);
        var selected = new List<ExpertContextPackTools.ScoredChunk>();
        var perSource = new Dictionary<string, int>(StringComparer.Ordinal);
        var characters = 0;
        foreach (var item in ranked)
        {
            perSource.TryGetValue(item.Source.Id, out var sourceCount);
            if (sourceCount >= request.Policy.MaxPerSource ||
                characters + item.Chunk.Content.Length > request.Policy.MaxCharacters)
            {
                continue;
            }
            selected.Add(item);
            perSource[item.Source.Id] = sourceCount + 1;
            characters += item.Chunk.Content.Length;
            if (selected.Count == request.Policy.TopK)
            {
                break;
            }
        }
        if (selected.Count == 0)
        {
            throw new CoordinatorValidationException(
                "No licensed context chunk matched the query within the selection budget.");
        }

        var hits = selected.Select((item, index) => new ExpertContextHit
        {
            Rank = index + 1,
            CitationId = ExpertContextPackTools.ReservedSourcePrefix + item.Chunk.Id,
            ChunkId = item.Chunk.Id,
            SourceId = item.Source.Id,
            Title = item.Source.Title,
            StartLine = item.Chunk.StartLine,
            EndLine = item.Chunk.EndLine,
            Score = item.Score,
            Content = item.Chunk.Content,
            ContentSha256 = item.Chunk.ContentSha256,
            License = item.Source.License
        }).ToArray();
        var selection = new ExpertContextSelection
        {
            SchemaVersion = ExpertContextPackTools.SelectionSchemaVersion,
            CorpusId = _pack.CorpusId,
            CorpusVersion = _pack.CorpusVersion,
            PackSha256 = _pack.PackSha256,
            IndexSha256 = _pack.IndexSha256,
            TenantScopeSha256 = ExpertContextPackTools.ComputeTenantScopeSha256(request.TenantId),
            QuerySha256 = ExpertContextPackTools.ComputeQuerySha256(normalizedQuery),
            PolicySha256 = ExpertContextPackTools.ComputePolicySha256(request.Policy),
            SelectionSha256 = new string('0', 64),
            Hits = hits
        };
        selection = selection with
        {
            SelectionSha256 = ExpertContextPackTools.ComputeSelectionSha256(selection)
        };
        ExpertContextPackTools.ValidateSelectionForPreparedPack(_pack, selection, _index);
        return selection;
    }
}
