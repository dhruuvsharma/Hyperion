using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

public sealed record ExpertModelDatasetDraftManifest
{
    public required string SchemaVersion { get; init; }
    public required string Producer { get; init; }
    public required DateTimeOffset ProducedAtUtc { get; init; }
    public required string Reviewer { get; init; }
    public required DateTimeOffset CutoffUtc { get; init; }
    public required string Provenance { get; init; }
    public required string License { get; init; }
    public required DatasetRights Rights { get; init; }
    public required string RightsBasis { get; init; }
    public IReadOnlyList<ExpertModelDatasetDraftExample> Examples { get; init; } = [];
}

public sealed record ExpertModelDatasetDraftExample
{
    public required string Id { get; init; }
    public required ExpertTaskKind TaskKind { get; init; }
    public IReadOnlyList<ExpertDomain> Domains { get; init; } = [];
    public IReadOnlyList<LlmMessage> Messages { get; init; } = [];
    public required string ContaminationGroup { get; init; }
    public required string KnowledgeClass { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Split { get; init; }
    public IReadOnlyList<ExpertModelDatasetDraftSource> Sources { get; init; } = [];
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

public sealed record ExpertModelDatasetDraftSource
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string ContentPath { get; init; }
    public required string Provenance { get; init; }
    public required string License { get; init; }
    public required DateTimeOffset RetrievedAtUtc { get; init; }
    public required DateTimeOffset AvailableAtUtc { get; init; }
    public string? Uri { get; init; }
}

public static class ExpertModelDatasetDraftAuthoringTools
{
    public const string SchemaVersion = "daxalgo.expert-model-dataset-draft/v1";
    public const string V2SchemaVersion = "daxalgo.expert-model-dataset-draft/v2";
    public const long MaxManifestBytes = 5_000_000;
    public const long MaxSourceBytes = 2_000_000;
    public const int MaxExamples = 10_000;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    private static readonly HashSet<string> AllowedKnowledgeClasses =
        new(["candidate-stable", "retrieval-only"], StringComparer.Ordinal);

    public static async Task<int> CompileAsync(
        string manifestPath,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        var fullManifestPath = Path.GetFullPath(manifestPath);
        var fullOutputPath = Path.GetFullPath(outputPath);
        if (StringComparer.OrdinalIgnoreCase.Equals(fullManifestPath, fullOutputPath))
        {
            throw new ArgumentException("Draft output must not overwrite its authoring manifest.", nameof(outputPath));
        }

        var manifestInfo = new FileInfo(fullManifestPath);
        if (!manifestInfo.Exists)
        {
            throw new FileNotFoundException("Draft authoring manifest was not found.", fullManifestPath);
        }
        if (manifestInfo.Length > MaxManifestBytes)
        {
            throw new CoordinatorValidationException(
                $"Draft authoring manifest exceeds the {MaxManifestBytes:N0}-byte input limit.");
        }

        ExpertModelDatasetDraftManifest manifest;
        try
        {
            var json = await ReadBoundedUtf8Async(
                    fullManifestPath,
                    MaxManifestBytes,
                    "Draft authoring manifest",
                    cancellationToken)
                .ConfigureAwait(false);
            manifest = JsonSerializer.Deserialize<ExpertModelDatasetDraftManifest>(json, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException("Draft authoring manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException(
                $"Draft authoring manifest is invalid: {exception.Message}");
        }
        catch (DecoderFallbackException exception)
        {
            throw new CoordinatorValidationException(
                $"Draft authoring manifest is not strict UTF-8: {exception.Message}");
        }

        ValidateManifest(manifest);
        var manifestDirectory = Path.GetDirectoryName(fullManifestPath)!;
        var examples = new List<ExpertModelDatasetExample>(manifest.Examples.Count);
        foreach (var draft in manifest.Examples)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sources = await LoadSourcesAsync(
                draft,
                manifestDirectory,
                fullManifestPath,
                fullOutputPath,
                manifest.Rights,
                manifest.RightsBasis,
                cancellationToken).ConfigureAwait(false);
            string[] evidence = [$"knowledgeClass={draft.KnowledgeClass}", .. draft.Evidence];
            var messages = draft.Messages.ToArray();
            examples.Add(new ExpertModelDatasetExample
            {
                SchemaVersion = CoordinatorVersions.ExpertModelDatasetSchema,
                Id = draft.Id,
                TaskKind = draft.TaskKind,
                Domains = draft.Domains.ToArray(),
                Messages = messages,
                ConversationSha256 = ExpertModelDatasetTools.ComputeConversationSha256(messages),
                Sources = sources,
                Lineage = new ExpertModelLineage
                {
                    Origin = ExpertDatasetOrigin.HumanAuthored,
                    Producer = manifest.Producer,
                    ProducedAtUtc = manifest.ProducedAtUtc
                },
                Verification = new ExpertVerificationEvidence
                {
                    Verified = false,
                    Reviewer = manifest.Reviewer,
                    VerifiedAtUtc = null,
                    EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                        evidence,
                        [],
                        []),
                    Evidence = evidence,
                    CompileSucceeded = false,
                    CompileEvidence = [],
                    TestsPassed = false,
                    TestEvidence = []
                },
                Split = ResolveSplit(manifest.SchemaVersion, draft),
                ContaminationGroup = draft.ContaminationGroup,
                Provenance =
                    $"{manifest.Provenance} [knowledgeClass={draft.KnowledgeClass}] " +
                    $"Rights basis: {manifest.RightsBasis}",
                License = manifest.License,
                Rights = manifest.Rights,
                ReviewStatus = "draft",
                CutoffUtc = manifest.CutoffUtc,
                UseForTraining = false
            });
        }

        Directory.CreateDirectory(Path.GetDirectoryName(fullOutputPath)!);
        var temporaryPath = $"{fullOutputPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            await WriteDraftAsync(temporaryPath, examples, cancellationToken).ConfigureAwait(false);
            var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(temporaryPath, cancellationToken)
                .ConfigureAwait(false);
            if (!report.IsValid)
            {
                var detail = string.Join(
                    " ",
                    report.Issues.Take(5).Select(issue =>
                        $"Line {issue.Line} ({issue.ExampleId ?? "?"}): {issue.Message}"));
                throw new CoordinatorValidationException(
                    $"Compiled draft failed canonical dataset validation; no output was written. {detail}");
            }
            if (report.TrainingEligibleCount != 0)
            {
                throw new CoordinatorValidationException(
                    "Compiled draft unexpectedly contains training-eligible rows; no output was written.");
            }

            File.Move(temporaryPath, fullOutputPath, overwrite: true);
            return report.ExampleCount;
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static void ValidateManifest(ExpertModelDatasetDraftManifest manifest)
    {
        if (manifest.SchemaVersion is not (SchemaVersion or V2SchemaVersion))
        {
            throw new CoordinatorValidationException("Unsupported draft authoring manifest schema version.");
        }
        if (string.IsNullOrWhiteSpace(manifest.Producer) || manifest.Producer.Length > 500)
        {
            throw new CoordinatorValidationException("Draft producer is required and must not exceed 500 characters.");
        }
        if (string.IsNullOrWhiteSpace(manifest.Reviewer) || manifest.Reviewer.Length > 500)
        {
            throw new CoordinatorValidationException(
                "Draft reviewer placeholder is required and must not exceed 500 characters.");
        }
        if (manifest.ProducedAtUtc == default || manifest.ProducedAtUtc > DateTimeOffset.UtcNow)
        {
            throw new CoordinatorValidationException("Draft producedAtUtc must be set and not be in the future.");
        }
        if (manifest.CutoffUtc == default || manifest.CutoffUtc > DateTimeOffset.UtcNow)
        {
            throw new CoordinatorValidationException("Draft cutoffUtc must be set and not be in the future.");
        }
        if (string.IsNullOrWhiteSpace(manifest.Provenance) || manifest.Provenance.Length > 2_000)
        {
            throw new CoordinatorValidationException(
                "Draft provenance is required and must not exceed 2,000 characters.");
        }
        if (string.IsNullOrWhiteSpace(manifest.License) || manifest.License.Length > 500)
        {
            throw new CoordinatorValidationException("Draft license is required and must not exceed 500 characters.");
        }
        if (manifest.Rights is null ||
            !manifest.Rights.MayStore ||
            !manifest.Rights.MayEvaluate ||
            manifest.Rights.MayTrain ||
            manifest.Rights.MayUploadToProvider ||
            manifest.Rights.MayRedistribute)
        {
            throw new CoordinatorValidationException(
                "Draft rights must explicitly permit only private storage and evaluation.");
        }
        if (string.IsNullOrWhiteSpace(manifest.RightsBasis) || manifest.RightsBasis.Length > 2_000)
        {
            throw new CoordinatorValidationException(
                "Draft rightsBasis is required and must not exceed 2,000 characters.");
        }
        if (manifest.Examples is null || manifest.Examples.Count == 0 || manifest.Examples.Count > MaxExamples)
        {
            throw new CoordinatorValidationException(
                $"Draft examples must contain between 1 and {MaxExamples:N0} entries.");
        }

        foreach (var example in manifest.Examples)
        {
            if (example is null)
            {
                throw new CoordinatorValidationException("Draft examples must not contain null entries.");
            }
            if (example.Messages is null || example.Domains is null || example.Sources is null ||
                example.Evidence is null)
            {
                throw new CoordinatorValidationException(
                    $"Draft example '{example.Id}' contains a null collection.");
            }
            if (example.Sources.Count == 0)
            {
                throw new CoordinatorValidationException(
                    $"Draft example '{example.Id}' must reference at least one source file.");
            }
            if (!AllowedKnowledgeClasses.Contains(example.KnowledgeClass))
            {
                throw new CoordinatorValidationException(
                    $"Draft example '{example.Id}' knowledgeClass must be candidate-stable or retrieval-only.");
            }
            _ = ResolveSplit(manifest.SchemaVersion, example);
            if (example.Evidence.Count == 0)
            {
                throw new CoordinatorValidationException(
                    $"Draft example '{example.Id}' must contain truthful intake evidence.");
            }
        }
    }

    internal static string ResolveSplit(
        string schemaVersion,
        ExpertModelDatasetDraftExample example)
    {
        if (schemaVersion == SchemaVersion)
        {
            if (example.Split is not null)
            {
                throw new CoordinatorValidationException(
                    $"Draft example '{example.Id}' must not declare split under v1; v1 is development-only.");
            }
            return "development";
        }
        if (schemaVersion == V2SchemaVersion &&
            example.Split is "development" or "calibration" or "sealed")
        {
            return example.Split;
        }
        throw new CoordinatorValidationException(
            $"Draft example '{example.Id}' must declare split as development, calibration, or sealed under v2.");
    }

    private static async Task<IReadOnlyList<DatasetSourceAsset>> LoadSourcesAsync(
        ExpertModelDatasetDraftExample draft,
        string manifestDirectory,
        string fullManifestPath,
        string fullOutputPath,
        DatasetRights rights,
        string rightsBasis,
        CancellationToken cancellationToken)
    {
        var sources = new List<DatasetSourceAsset>(draft.Sources.Count);
        foreach (var source in draft.Sources)
        {
            if (source is null)
            {
                throw new CoordinatorValidationException(
                    $"Draft example '{draft.Id}' contains a null source entry.");
            }
            var sourcePath = ResolveContainedSourcePath(manifestDirectory, source.ContentPath, source.Id);
            if (StringComparer.OrdinalIgnoreCase.Equals(sourcePath, fullManifestPath) ||
                StringComparer.OrdinalIgnoreCase.Equals(sourcePath, fullOutputPath))
            {
                throw new CoordinatorValidationException(
                    $"Draft source '{source.Id}' must not be the manifest or output dataset path.");
            }
            var sourceInfo = new FileInfo(sourcePath);
            if (!sourceInfo.Exists)
            {
                throw new CoordinatorValidationException($"Draft source '{source.Id}' was not found.");
            }
            if (sourceInfo.Length > MaxSourceBytes)
            {
                throw new CoordinatorValidationException(
                    $"Draft source '{source.Id}' exceeds the {MaxSourceBytes:N0}-byte input limit.");
            }

            string content;
            try
            {
                content = await ReadBoundedUtf8Async(
                        sourcePath,
                        MaxSourceBytes,
                        $"Draft source '{source.Id}'",
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (DecoderFallbackException exception)
            {
                throw new CoordinatorValidationException(
                    $"Draft source '{source.Id}' is not strict UTF-8: {exception.Message}");
            }
            sources.Add(new DatasetSourceAsset(
                source.Id,
                source.Title,
                content,
                $"{source.Provenance} Rights basis: {rightsBasis}",
                source.License,
                source.RetrievedAtUtc,
                source.AvailableAtUtc,
                source.Uri,
                rights));
        }
        return sources;
    }

    private static string ResolveContainedSourcePath(string manifestDirectory, string contentPath, string sourceId)
    {
        if (string.IsNullOrWhiteSpace(contentPath) || Path.IsPathRooted(contentPath))
        {
            throw new CoordinatorValidationException(
                $"Draft source '{sourceId}' contentPath must be a relative path.");
        }

        var fullPath = Path.GetFullPath(Path.Combine(manifestDirectory, contentPath));
        var relativePath = Path.GetRelativePath(manifestDirectory, fullPath);
        if (Path.IsPathRooted(relativePath) || relativePath == ".." ||
            relativePath.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
            relativePath.StartsWith($"..{Path.AltDirectorySeparatorChar}", StringComparison.Ordinal))
        {
            throw new CoordinatorValidationException(
                $"Draft source '{sourceId}' contentPath escapes the manifest directory.");
        }
        var normalizedInput = contentPath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        if (!StringComparer.OrdinalIgnoreCase.Equals(relativePath, normalizedInput))
        {
            throw new CoordinatorValidationException(
                $"Draft source '{sourceId}' contentPath must not contain aliases.");
        }

        RejectReparsePoint(manifestDirectory, $"Draft source '{sourceId}' root");
        var current = manifestDirectory;
        foreach (var segment in relativePath.Split(
                     Path.DirectorySeparatorChar,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (File.Exists(current) || Directory.Exists(current))
            {
                RejectReparsePoint(current, $"Draft source '{sourceId}' path");
            }
        }
        return fullPath;
    }

    private static async Task<string> ReadBoundedUtf8Async(
        string path,
        long maxBytes,
        string description,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maxBytes)
        {
            throw new CoordinatorValidationException(
                $"{description} exceeds the {maxBytes:N0}-byte input limit.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.Position != stream.Length)
        {
            throw new CoordinatorValidationException($"{description} changed while it was being read.");
        }
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException($"{description} must be BOM-less UTF-8.");
        }
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new CoordinatorValidationException(
                $"{description} is not strict UTF-8: {exception.Message}");
        }
    }

    private static void RejectReparsePoint(string path, string description)
    {
        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CoordinatorValidationException(
                $"{description} could not be inspected: {exception.Message}");
        }
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new CoordinatorValidationException($"{description} must not traverse a reparse point.");
        }
    }

    private static async Task WriteDraftAsync(
        string path,
        IReadOnlyList<ExpertModelDatasetExample> examples,
        CancellationToken cancellationToken)
    {
        long writtenBytes = 0;
        await using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            useAsync: true);
        await using var writer = new StreamWriter(stream, StrictUtf8) { NewLine = "\n" };
        foreach (var example in examples)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = JsonSerializer.Serialize(example, CompactJson);
            var lineBytes = Encoding.UTF8.GetByteCount(line) + 1L;
            if (lineBytes > ExpertModelDatasetTools.MaxDatasetBytes - writtenBytes)
            {
                throw new CoordinatorValidationException(
                    $"Compiled draft exceeds the {ExpertModelDatasetTools.MaxDatasetBytes:N0}-byte output limit.");
            }
            await writer.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
            writtenBytes += lineBytes;
        }
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
