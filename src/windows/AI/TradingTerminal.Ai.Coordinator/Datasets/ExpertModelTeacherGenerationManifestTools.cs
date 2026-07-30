using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

public sealed record ExpertModelTeacherGenerationCapturePlan
{
    public required string SchemaVersion { get; init; }
    public required string DraftManifestSha256 { get; init; }
    public required string CandidateCatalogSha256 { get; init; }
    public required ExpertModelTeacherIdentity Teacher { get; init; }
    public required ExpertModelTeacherGenerationPolicy Generation { get; init; }
    public required ExpertModelTeacherGenerationBudget Budget { get; init; }
    public required ExpertModelTeacherTokenizerPreflight TokenizerPreflight { get; init; }
    public required IReadOnlyList<ExpertModelTeacherTaskCapturePlan> Tasks { get; init; }
}

public sealed record ExpertModelTeacherIdentity
{
    public required string CandidateId { get; init; }
    public required string ProfileVersion { get; init; }
    public required string ChatTemplateSha256 { get; init; }
    public required string RuntimeSha256 { get; init; }
}

public sealed record ExpertModelTeacherGenerationPolicy
{
    public required decimal Temperature { get; init; }
    public required decimal TopP { get; init; }
    public required IReadOnlyList<int> Seeds { get; init; }
}

public sealed record ExpertModelTeacherGenerationBudget
{
    public required int MaxRequests { get; init; }
    public required int MaxPromptTokens { get; init; }
    public required int MaxCompletionTokens { get; init; }
    public required int MaxTotalTokens { get; init; }
}

public sealed record ExpertModelTeacherTokenizerPreflight
{
    public required string Protocol { get; init; }
    public required int MaxModelLen { get; init; }
}

public sealed record ExpertModelTeacherTaskCapturePlan
{
    public required string TaskId { get; init; }
    public required int MaxOutputTokens { get; init; }
}

public sealed record ExpertModelTeacherGenerationCompileResult(
    int TaskCount,
    int RequestCount,
    string OutputSha256);

public static class ExpertModelTeacherGenerationManifestTools
{
    public const string CapturePlanSchemaVersion =
        "daxalgo.vibe-quant.teacher-capture-plan/v1";
    public const string OutputSchemaVersion =
        "daxalgo.vibe-quant.teacher-generation-manifest/v2";
    public const string CandidateCatalogSchemaVersion =
        "daxalgo.vibe-quant.candidate-catalog/v1";
    public const string TokenizerProtocol = "vllm-tokenize-chat/v1";

    private const int MaxJsonBytes = 4_000_000;
    private const int MaxTasks = 10_000;
    private const int MaxRequests = 100_000;
    private const int MaxTokenBudget = 200_000_000;
    private const int MaxModelLength = 1_048_576;
    private const int MaxOutputTokens = 262_144;
    private const int MaxMessageCount = 64;
    private const int MaxMessageCharacters = 500_000;
    private const int MaxAggregateMessageCharacters = 2_000_000;
    private const int MaxSourceCount = 64;
    private const int MaxSourceBytes = 500_000;
    private const int MaxAggregateSourceCharacters = 2_000_000;
    private const int MaxPreparedSourceBytes = 25_000_000;
    private const int MaxEvidenceItems = 128;
    private const int MaxEvidenceCharacters = 2_000;
    private const int MaxReferenceAnswerRegexCharacters = 8_000_000;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly TimeSpan ReferenceAnswerMatchTimeout = TimeSpan.FromSeconds(5);
    private static readonly Regex SafeIdRegex = new(
        "^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Sha256Regex = new(
        "^[0-9a-f]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly IReadOnlyDictionary<string, ExpectedCandidate> ExpectedCandidates =
        new Dictionary<string, ExpectedCandidate>(StringComparer.Ordinal)
        {
            ["qwen2.5-coder-7b-instruct"] = new(
                "Qwen2.5-Coder 7B Instruct",
                "Qwen/Qwen2.5-Coder-7B-Instruct",
                "https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct",
                "c03e6d358207e414f1eca0bb1891e29f1db0e242",
                ["student"]),
            ["qwen2.5-coder-14b-instruct"] = new(
                "Qwen2.5-Coder 14B Instruct",
                "Qwen/Qwen2.5-Coder-14B-Instruct",
                "https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct",
                "aedcc2d42b622764e023cf882b6652e646b95671",
                ["student"]),
            ["gpt-oss-20b"] = new(
                "gpt-oss-20b",
                "openai/gpt-oss-20b",
                "https://huggingface.co/openai/gpt-oss-20b",
                "6cee5e81ee83917806bbde320786a8fb61efebee",
                ["student"]),
            ["qwen3-coder-30b-a3b-instruct"] = new(
                "Qwen3-Coder 30B-A3B Instruct",
                "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "b2cff646eb4bb1d68355c01b18ae02e7cf42d120",
                ["teacher", "fallback"]),
        };

    private static readonly JsonSerializerOptions OutputJson = new(CoordinatorJson.Options)
    {
        WriteIndented = true,
    };

    public static Task<ExpertModelTeacherGenerationCompileResult> CompileAsync(
        string manifestPath,
        string capturePlanPath,
        string candidateCatalogPath,
        string outputPath,
        CancellationToken cancellationToken = default) =>
        CompileCoreAsync(
            manifestPath,
            capturePlanPath,
            candidateCatalogPath,
            outputPath,
            beforeFinalInputRevalidation: null,
            cancellationToken);

    internal static Task<ExpertModelTeacherGenerationCompileResult> CompileAsync(
        string manifestPath,
        string capturePlanPath,
        string candidateCatalogPath,
        string outputPath,
        Func<CancellationToken, Task> beforeFinalInputRevalidation,
        CancellationToken cancellationToken = default) =>
        CompileCoreAsync(
            manifestPath,
            capturePlanPath,
            candidateCatalogPath,
            outputPath,
            beforeFinalInputRevalidation,
            cancellationToken);

    private static async Task<ExpertModelTeacherGenerationCompileResult> CompileCoreAsync(
        string manifestPath,
        string capturePlanPath,
        string candidateCatalogPath,
        string outputPath,
        Func<CancellationToken, Task>? beforeFinalInputRevalidation,
        CancellationToken cancellationToken)
    {
        var fullManifestPath = Path.GetFullPath(manifestPath);
        var fullPlanPath = Path.GetFullPath(capturePlanPath);
        var fullCatalogPath = Path.GetFullPath(candidateCatalogPath);
        var fullOutputPath = Path.GetFullPath(outputPath);
        var manifestDirectory = Path.GetDirectoryName(fullManifestPath)!;
        var outputDirectory = Path.GetDirectoryName(fullOutputPath)!;

        RequireDistinctPaths(
            fullManifestPath,
            fullPlanPath,
            fullCatalogPath,
            fullOutputPath);
        if (!StringComparer.OrdinalIgnoreCase.Equals(manifestDirectory, outputDirectory))
        {
            throw new CoordinatorValidationException(
                "Teacher-generation output must be in the draft manifest directory so source paths retain their exact meaning.");
        }
        if (File.Exists(fullOutputPath) || Directory.Exists(fullOutputPath))
        {
            throw new IOException($"Refusing to overwrite existing teacher-generation output '{fullOutputPath}'.");
        }

        var manifestSnapshotTask = ReadSnapshotAsync(
            fullManifestPath,
            ExpertModelDatasetDraftAuthoringTools.MaxManifestBytes,
            "Draft authoring manifest",
            cancellationToken);
        var planSnapshotTask = ReadSnapshotAsync(
            fullPlanPath,
            MaxJsonBytes,
            "Teacher-generation capture plan",
            cancellationToken);
        var catalogSnapshotTask = ReadSnapshotAsync(
            fullCatalogPath,
            MaxJsonBytes,
            "Candidate catalog",
            cancellationToken);
        await Task.WhenAll(manifestSnapshotTask, planSnapshotTask, catalogSnapshotTask)
            .ConfigureAwait(false);
        var manifestSnapshot = await manifestSnapshotTask.ConfigureAwait(false);
        var planSnapshot = await planSnapshotTask.ConfigureAwait(false);
        var catalogSnapshot = await catalogSnapshotTask.ConfigureAwait(false);

        var manifest = Deserialize<ExpertModelDatasetDraftManifest>(
            manifestSnapshot,
            "Draft authoring manifest");
        var plan = Deserialize<ExpertModelTeacherGenerationCapturePlan>(
            planSnapshot,
            "Teacher-generation capture plan");
        var catalog = Deserialize<CandidateCatalog>(catalogSnapshot, "Candidate catalog");

        ValidateManifest(manifest);
        ValidatePlanIdentity(plan, manifestSnapshot.Sha256, catalogSnapshot.Sha256);
        ValidateCatalog(catalog, plan.Teacher.CandidateId);
        ValidatePlanAgainstManifest(plan, manifest);

        var authoredMessagesByTask = new IReadOnlyList<LlmMessage>[manifest.Examples.Count];
        var referenceAnswers = new List<string>(manifest.Examples.Count);
        for (var index = 0; index < manifest.Examples.Count; index++)
        {
            authoredMessagesByTask[index] = ValidateAndStripReferenceAnswer(
                manifest.Examples[index],
                index);
            referenceAnswers.Add(manifest.Examples[index].Messages[^1].Content);
        }
        var referenceAnswerMatcher = BuildReferenceAnswerMatcher(referenceAnswers);
        for (var taskIndex = 0; taskIndex < manifest.Examples.Count; taskIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var retainedMessages = authoredMessagesByTask[taskIndex];
            for (var messageIndex = 0; messageIndex < retainedMessages.Count; messageIndex++)
            {
                if (ContainsReferenceAnswer(
                        referenceAnswerMatcher,
                        retainedMessages[messageIndex].Content,
                        $"Draft task '{manifest.Examples[taskIndex].Id}' retained message {messageIndex}"))
                {
                    throw new CoordinatorValidationException(
                        $"Draft task '{manifest.Examples[taskIndex].Id}' retained message {messageIndex} must not contain a stripped terminal reference answer.");
                }
            }
        }

        var inputAliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            fullManifestPath,
            fullPlanPath,
            fullCatalogPath,
            fullOutputPath,
        };
        var controlInputHashes = new HashSet<string>(StringComparer.Ordinal)
        {
            manifestSnapshot.Sha256,
            planSnapshot.Sha256,
            catalogSnapshot.Sha256,
        };
        var sourceSnapshots = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);
        var outputTasks = new List<TeacherGenerationTask>(manifest.Examples.Count);
        var promptIdentities = new HashSet<string>(StringComparer.Ordinal);
        var taskContentIdentities = new HashSet<string>(StringComparer.Ordinal);
        long preparedSourceBytes = 0;
        for (var index = 0; index < manifest.Examples.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var draft = manifest.Examples[index];
            var authoredMessages = authoredMessagesByTask[index];
            var outputSources = new List<TeacherGenerationSource>(draft.Sources.Count);
            var promptSources = new List<TeacherPromptSource>(draft.Sources.Count);
            var sourceIds = new HashSet<string>(StringComparer.Ordinal);
            long aggregateSourceCharacters = 0;
            foreach (var source in draft.Sources)
            {
                ValidateSourceMetadata(source, draft.Id, manifest.CutoffUtc);
                if (ContainsReferenceAnswer(
                        referenceAnswerMatcher,
                        source.Id,
                        $"Draft task '{draft.Id}' source ID"))
                {
                    throw new CoordinatorValidationException(
                        $"Draft task '{draft.Id}' source ID must not contain a stripped terminal reference answer.");
                }
                if (ContainsReferenceAnswer(
                        referenceAnswerMatcher,
                        source.Title,
                        $"Draft source '{source.Id}' title"))
                {
                    throw new CoordinatorValidationException(
                        $"Draft source '{source.Id}' title must not contain a stripped terminal reference answer.");
                }
                if (!sourceIds.Add(source.Id))
                {
                    throw new CoordinatorValidationException(
                        $"Draft example '{draft.Id}' contains duplicate source ID '{source.Id}'.");
                }
                var sourcePath = ResolveContainedSourcePath(
                    manifestDirectory,
                    source.ContentPath,
                    source.Id);
                if (inputAliases.Contains(sourcePath))
                {
                    throw new CoordinatorValidationException(
                        $"Draft source '{source.Id}' must not alias the draft manifest, capture plan, candidate catalog, or output.");
                }
                if (!sourceSnapshots.TryGetValue(sourcePath, out var sourceSnapshot))
                {
                    sourceSnapshot = await ReadSnapshotAsync(
                        sourcePath,
                        MaxSourceBytes,
                        $"Draft source '{source.Id}'",
                        cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(sourceSnapshot.Text))
                    {
                        throw new CoordinatorValidationException(
                            $"Draft source '{source.Id}' must not be empty.");
                    }
                    if (controlInputHashes.Contains(sourceSnapshot.Sha256))
                    {
                        throw new CoordinatorValidationException(
                            $"Draft source '{source.Id}' bytes must not alias a control input snapshot.");
                    }
                    if (ContainsReferenceAnswer(
                            referenceAnswerMatcher,
                            sourceSnapshot.Text,
                            $"Draft source '{source.Id}'"))
                    {
                        throw new CoordinatorValidationException(
                            $"Draft source '{source.Id}' must not contain a stripped terminal reference answer.");
                    }
                    sourceSnapshots.Add(sourcePath, sourceSnapshot);
                }
                aggregateSourceCharacters += sourceSnapshot.Text.Length;
                preparedSourceBytes = checked(preparedSourceBytes + sourceSnapshot.Bytes.LongLength);
                if (aggregateSourceCharacters > MaxAggregateSourceCharacters)
                {
                    throw new CoordinatorValidationException(
                        $"Draft example '{draft.Id}' source content exceeds {MaxAggregateSourceCharacters:N0} aggregate characters.");
                }
                if (preparedSourceBytes > MaxPreparedSourceBytes)
                {
                    throw new CoordinatorValidationException(
                        $"Draft source snapshots exceed the {MaxPreparedSourceBytes:N0}-byte preparation limit.");
                }
                outputSources.Add(new TeacherGenerationSource
                {
                    Id = source.Id,
                    Title = source.Title,
                    ContentPath = source.ContentPath,
                    ContentSha256 = sourceSnapshot.Sha256,
                    Provenance = source.Provenance,
                    License = source.License,
                    RetrievedAtUtc = FormatUtcSecond(source.RetrievedAtUtc),
                    AvailableAtUtc = FormatUtcSecond(source.AvailableAtUtc),
                    Uri = source.Uri,
                });
                promptSources.Add(new TeacherPromptSource(
                    source.Id,
                    source.Title,
                    FormatUtcSecond(source.AvailableAtUtc),
                    sourceSnapshot.Text));
            }

            var promptIdentity = ComputeStructuralSha256(
                new TeacherPromptIdentity(authoredMessages, promptSources));
            if (!promptIdentities.Add(promptIdentity))
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' duplicates an earlier source-grounded teacher prompt.");
            }
            var taskContentIdentity = ComputeStructuralSha256(new TeacherTaskContentIdentity(
                draft.TaskKind,
                draft.Domains,
                promptIdentity,
                draft.ContaminationGroup,
                draft.KnowledgeClass,
                FormatUtcSecond(manifest.CutoffUtc),
                plan.Tasks[index].MaxOutputTokens,
                draft.Evidence,
                outputSources));
            if (!taskContentIdentities.Add(taskContentIdentity))
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' duplicates an earlier derived teacher task record.");
            }

            outputTasks.Add(new TeacherGenerationTask
            {
                TaskId = draft.Id,
                TaskKind = draft.TaskKind,
                Domains = draft.Domains.ToArray(),
                Messages = authoredMessages,
                ContaminationGroup = draft.ContaminationGroup,
                KnowledgeClass = draft.KnowledgeClass,
                CutoffUtc = FormatUtcSecond(manifest.CutoffUtc),
                MaxOutputTokens = plan.Tasks[index].MaxOutputTokens,
                Evidence = draft.Evidence.ToArray(),
                Sources = outputSources,
            });
        }

        var requestCount = ValidateCaptureBudget(plan, outputTasks.Count);
        var outputDocument = new TeacherGenerationManifest
        {
            SchemaVersion = OutputSchemaVersion,
            Split = "development",
            DraftManifestSha256 = manifestSnapshot.Sha256,
            CandidateCatalogSha256 = catalogSnapshot.Sha256,
            Teacher = plan.Teacher,
            Generation = plan.Generation,
            Budget = plan.Budget,
            Authority = new TeacherGenerationAuthority
            {
                Producer = manifest.Producer,
                Reviewer = manifest.Reviewer,
                Provenance = manifest.Provenance,
                License = manifest.License,
                RightsBasis = manifest.RightsBasis,
                Rights = manifest.Rights,
            },
            TokenizerPreflight = plan.TokenizerPreflight,
            Tasks = outputTasks,
        };
        RejectReferenceAnswersInOutputStrings(outputDocument, referenceAnswerMatcher);
        var json = JsonSerializer.Serialize(outputDocument, OutputJson)
            .Replace("\r\n", "\n", StringComparison.Ordinal) + "\n";
        var outputBytes = StrictUtf8.GetBytes(json);
        if (outputBytes.Length > MaxJsonBytes)
        {
            throw new CoordinatorValidationException(
                $"Teacher-generation manifest exceeds the {MaxJsonBytes:N0}-byte output limit.");
        }
        var outputSha256 = ComputeSha256(outputBytes);

        RejectExistingReparseComponents(outputDirectory, "Teacher-generation output directory");
        var temporaryPath = Path.Combine(
            outputDirectory,
            $".{Path.GetFileName(fullOutputPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await stream.WriteAsync(outputBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            if (beforeFinalInputRevalidation is not null)
            {
                await beforeFinalInputRevalidation(cancellationToken).ConfigureAwait(false);
            }
            await RevalidateSnapshotAsync(manifestSnapshot, cancellationToken).ConfigureAwait(false);
            await RevalidateSnapshotAsync(planSnapshot, cancellationToken).ConfigureAwait(false);
            await RevalidateSnapshotAsync(catalogSnapshot, cancellationToken).ConfigureAwait(false);
            foreach (var sourceSnapshot in sourceSnapshots.Values)
            {
                await RevalidateSnapshotAsync(sourceSnapshot, cancellationToken).ConfigureAwait(false);
            }
            if (File.Exists(fullOutputPath) || Directory.Exists(fullOutputPath))
            {
                throw new IOException($"Refusing to overwrite existing teacher-generation output '{fullOutputPath}'.");
            }
            File.Move(temporaryPath, fullOutputPath, overwrite: false);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return new ExpertModelTeacherGenerationCompileResult(
            outputTasks.Count,
            requestCount,
            outputSha256);
    }

    private static void ValidateManifest(ExpertModelDatasetDraftManifest manifest)
    {
        if (manifest.SchemaVersion is not (
                ExpertModelDatasetDraftAuthoringTools.SchemaVersion or
                ExpertModelDatasetDraftAuthoringTools.V2SchemaVersion))
        {
            throw new CoordinatorValidationException("Unsupported draft authoring manifest schema version.");
        }
        RequireSafeId(manifest.Producer, "Draft producer");
        RequireSafeId(manifest.Reviewer, "Draft reviewer");
        ValidateWholeSecond(manifest.ProducedAtUtc, "Draft producedAtUtc");
        ValidateWholeSecond(manifest.CutoffUtc, "Draft cutoffUtc");
        if (manifest.ProducedAtUtc > DateTimeOffset.UtcNow || manifest.CutoffUtc > DateTimeOffset.UtcNow)
        {
            throw new CoordinatorValidationException("Draft timestamps must not be in the future.");
        }
        RequireText(manifest.Provenance, 2_000, "Draft provenance");
        RequireText(manifest.License, 500, "Draft license");
        RequireText(manifest.RightsBasis, 2_000, "Draft rightsBasis");
        RequireStorageEvaluationOnlyRights(manifest.Rights, "Draft rights");
        if (manifest.Examples is null || manifest.Examples.Count is < 1 or > MaxTasks)
        {
            throw new CoordinatorValidationException(
                $"Draft examples must contain 1 to {MaxTasks:N0} entries.");
        }

        var taskIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var draft in manifest.Examples)
        {
            if (draft is null)
            {
                throw new CoordinatorValidationException("Draft examples must not contain null entries.");
            }
            var split = ExpertModelDatasetDraftAuthoringTools.ResolveSplit(
                manifest.SchemaVersion,
                draft);
            if (manifest.SchemaVersion == ExpertModelDatasetDraftAuthoringTools.V2SchemaVersion &&
                split != "development")
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' uses split '{split}'; teacher generation accepts v2 development examples only.");
            }
            RequireSafeId(draft.Id, "Draft task ID");
            if (!taskIds.Add(draft.Id))
            {
                throw new CoordinatorValidationException($"Draft task ID '{draft.Id}' is duplicated.");
            }
            if (!Enum.IsDefined(draft.TaskKind))
            {
                throw new CoordinatorValidationException($"Draft task '{draft.Id}' has an unsupported taskKind.");
            }
            if (draft.Domains is null || draft.Domains.Count is < 1 or > 8 ||
                draft.Domains.Distinct().Count() != draft.Domains.Count ||
                draft.Domains.Any(domain => !Enum.IsDefined(domain)))
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' domains must contain 1 to 8 unique supported values.");
            }
            RequireSafeId(draft.ContaminationGroup, $"Draft task '{draft.Id}' contaminationGroup");
            if (draft.KnowledgeClass is not ("candidate-stable" or "retrieval-only"))
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' knowledgeClass must be candidate-stable or retrieval-only.");
            }
            ValidateEvidence(draft.Evidence, draft.Id);
            if (draft.Sources is null || draft.Sources.Count is < 1 or > MaxSourceCount)
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' must contain 1 to {MaxSourceCount} sources.");
            }
        }
    }

    private static void ValidatePlanIdentity(
        ExpertModelTeacherGenerationCapturePlan plan,
        string manifestSha256,
        string catalogSha256)
    {
        if (plan.SchemaVersion != CapturePlanSchemaVersion)
        {
            throw new CoordinatorValidationException("Unsupported teacher-generation capture-plan schema version.");
        }
        RequireSha256(plan.DraftManifestSha256, "Capture plan draftManifestSha256");
        RequireSha256(plan.CandidateCatalogSha256, "Capture plan candidateCatalogSha256");
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(plan.DraftManifestSha256),
                Encoding.ASCII.GetBytes(manifestSha256)))
        {
            throw new CoordinatorValidationException(
                "Capture plan draftManifestSha256 does not match the raw draft manifest bytes.");
        }
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(plan.CandidateCatalogSha256),
                Encoding.ASCII.GetBytes(catalogSha256)))
        {
            throw new CoordinatorValidationException(
                "Capture plan candidateCatalogSha256 does not match the raw candidate catalog bytes.");
        }
        if (plan.Teacher is null)
        {
            throw new CoordinatorValidationException("Capture plan teacher identity is required.");
        }
        RequireSafeId(plan.Teacher.CandidateId, "Capture plan teacher candidateId");
        RequirePinnedProfileVersion(plan.Teacher.ProfileVersion);
        RequireIdentitySha256(plan.Teacher.ChatTemplateSha256, "Capture plan chatTemplateSha256");
        RequireIdentitySha256(plan.Teacher.RuntimeSha256, "Capture plan runtimeSha256");
        if (StringComparer.Ordinal.Equals(
                plan.Teacher.ChatTemplateSha256,
                plan.Teacher.RuntimeSha256))
        {
            throw new CoordinatorValidationException(
                "Capture plan chat-template and runtime SHA-256 identities must be distinct.");
        }
    }

    private static void ValidatePlanAgainstManifest(
        ExpertModelTeacherGenerationCapturePlan plan,
        ExpertModelDatasetDraftManifest manifest)
    {
        if (plan.Tasks is null || plan.Tasks.Count != manifest.Examples.Count)
        {
            throw new CoordinatorValidationException(
                "Capture plan task rows must exactly match the draft task count and order.");
        }
        for (var index = 0; index < manifest.Examples.Count; index++)
        {
            var row = plan.Tasks[index]
                ?? throw new CoordinatorValidationException("Capture plan task rows must not contain null entries.");
            if (!StringComparer.Ordinal.Equals(row.TaskId, manifest.Examples[index].Id))
            {
                throw new CoordinatorValidationException(
                    $"Capture plan task row {index} must match draft task '{manifest.Examples[index].Id}'.");
            }
            if (row.MaxOutputTokens is < 1 or > MaxOutputTokens)
            {
                throw new CoordinatorValidationException(
                    $"Capture plan task '{row.TaskId}' maxOutputTokens must be between 1 and {MaxOutputTokens:N0}.");
            }
        }
    }

    private static int ValidateCaptureBudget(
        ExpertModelTeacherGenerationCapturePlan plan,
        int taskCount)
    {
        if (plan.Generation is null || plan.Generation.Temperature is <= 0m or > 2m ||
            plan.Generation.TopP is <= 0m or > 1m)
        {
            throw new CoordinatorValidationException(
                "Capture generation temperature must be greater than 0 and at most 2; topP must be greater than 0 and at most 1.");
        }
        if (plan.Generation.Seeds is null || plan.Generation.Seeds.Count is < 2 or > 8 ||
            plan.Generation.Seeds.Distinct().Count() != plan.Generation.Seeds.Count ||
            plan.Generation.Seeds.Any(seed => seed < 0))
        {
            throw new CoordinatorValidationException(
                "Capture generation seeds must contain 2 to 8 unique non-negative 32-bit integers.");
        }
        if (plan.TokenizerPreflight is null || plan.TokenizerPreflight.Protocol != TokenizerProtocol ||
            plan.TokenizerPreflight.MaxModelLen is < 1 or > MaxModelLength)
        {
            throw new CoordinatorValidationException(
                $"Capture tokenizerPreflight must use {TokenizerProtocol} with maxModelLen between 1 and {MaxModelLength:N0}.");
        }
        foreach (var task in plan.Tasks)
        {
            if (checked(1 + task.MaxOutputTokens) > plan.TokenizerPreflight.MaxModelLen)
            {
                throw new CoordinatorValidationException(
                    $"Capture task '{task.TaskId}' maxOutputTokens cannot fit a non-empty prompt inside maxModelLen.");
            }
        }
        if (plan.Budget is null || plan.Budget.MaxRequests is < 1 or > MaxRequests ||
            plan.Budget.MaxPromptTokens is < 1 or > MaxTokenBudget ||
            plan.Budget.MaxCompletionTokens is < 1 or > MaxTokenBudget ||
            plan.Budget.MaxTotalTokens is < 1 or > MaxTokenBudget)
        {
            throw new CoordinatorValidationException(
                "Capture budgets exceed the bounded teacher-generation limits.");
        }

        var requestCount = checked(taskCount * plan.Generation.Seeds.Count);
        if (requestCount > plan.Budget.MaxRequests)
        {
            throw new CoordinatorValidationException(
                $"Capture maxRequests is below the required {requestCount} requests.");
        }
        if (requestCount > plan.Budget.MaxPromptTokens)
        {
            throw new CoordinatorValidationException(
                $"Capture maxPromptTokens is below the required minimum {requestCount} tokens.");
        }
        var requestedCompletionTokens = checked(
            plan.Tasks.Sum(task => (long)task.MaxOutputTokens) * plan.Generation.Seeds.Count);
        if (requestedCompletionTokens > plan.Budget.MaxCompletionTokens)
        {
            throw new CoordinatorValidationException(
                $"Capture maxCompletionTokens is below the requested worst-case {requestedCompletionTokens} tokens.");
        }
        var minimumTotalTokens = checked(requestedCompletionTokens + requestCount);
        if (minimumTotalTokens > plan.Budget.MaxTotalTokens)
        {
            throw new CoordinatorValidationException(
                $"Capture maxTotalTokens is below the requested minimum {minimumTotalTokens} tokens.");
        }
        return requestCount;
    }

    private static IReadOnlyList<LlmMessage> ValidateAndStripReferenceAnswer(
        ExpertModelDatasetDraftExample draft,
        int taskIndex)
    {
        if (draft.Messages is null || draft.Messages.Count is < 2 or > MaxMessageCount)
        {
            throw new CoordinatorValidationException(
                $"Draft task '{draft.Id}' messages must contain 2 to {MaxMessageCount} entries.");
        }
        var start = draft.Messages[0]?.Role == "system" ? 1 : 0;
        if (start == draft.Messages.Count)
        {
            throw new CoordinatorValidationException($"Draft task '{draft.Id}' must contain a user prompt.");
        }
        var expected = "user";
        var aggregateCharacters = 0;
        for (var index = 0; index < draft.Messages.Count; index++)
        {
            var message = draft.Messages[index]
                ?? throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' messages must not contain null entries.");
            RequireText(message.Content, MaxMessageCharacters, $"Draft task '{draft.Id}' message {index} content");
            aggregateCharacters = checked(aggregateCharacters + message.Content.Length);
            if (index < start)
            {
                if (message.Role != "system")
                {
                    throw new CoordinatorValidationException(
                        $"Draft task '{draft.Id}' message 0 may only be system.");
                }
                continue;
            }
            if (message.Role != expected)
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{draft.Id}' message {index} must be '{expected}' to preserve chat ordering.");
            }
            expected = expected == "user" ? "assistant" : "user";
        }
        if (aggregateCharacters > MaxAggregateMessageCharacters)
        {
            throw new CoordinatorValidationException(
                $"Draft task '{draft.Id}' messages exceed {MaxAggregateMessageCharacters:N0} aggregate characters.");
        }
        if (draft.Messages[^1].Role != "assistant")
        {
            throw new CoordinatorValidationException(
                $"Draft task '{draft.Id}' must end with exactly one terminal assistant reference answer.");
        }
        var stripped = draft.Messages.Take(draft.Messages.Count - 1)
            .Select(message => new LlmMessage(message.Role, message.Content))
            .ToArray();
        if (stripped.Length is < 1 or > MaxMessageCount || stripped[^1].Role != "user")
        {
            throw new CoordinatorValidationException(
                $"Draft task at index {taskIndex} did not produce a valid teacher prompt after stripping its reference answer.");
        }
        return stripped;
    }

    private static Regex BuildReferenceAnswerMatcher(IReadOnlyList<string> referenceAnswers)
    {
        var uniqueAnswers = new HashSet<string>(StringComparer.Ordinal);
        var pattern = new StringBuilder("(?:");
        try
        {
            foreach (var referenceAnswer in referenceAnswers)
            {
                if (!uniqueAnswers.Add(referenceAnswer))
                {
                    continue;
                }
                var escaped = Regex.Escape(referenceAnswer);
                var separatorLength = uniqueAnswers.Count == 1 ? 0 : 1;
                var requiredCharacters = checked(escaped.Length + separatorLength + 1);
                if (pattern.Length > MaxReferenceAnswerRegexCharacters - requiredCharacters)
                {
                    throw new CoordinatorValidationException(
                        $"Stripped reference-answer matcher exceeds the {MaxReferenceAnswerRegexCharacters:N0}-character construction limit.");
                }
                if (separatorLength != 0)
                {
                    pattern.Append('|');
                }
                pattern.Append(escaped);
            }
            if (uniqueAnswers.Count == 0)
            {
                throw new CoordinatorValidationException(
                    "Stripped reference-answer matcher requires at least one terminal answer.");
            }
            pattern.Append(')');
            return new Regex(
                pattern.ToString(),
                RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
                ReferenceAnswerMatchTimeout);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or OverflowException)
        {
            throw new CoordinatorValidationException(
                $"Stripped reference-answer matcher could not be constructed; no output was written. {exception.Message}");
        }
    }

    private static bool ContainsReferenceAnswer(
        Regex matcher,
        string content,
        string field)
    {
        try
        {
            return matcher.IsMatch(content);
        }
        catch (RegexMatchTimeoutException exception)
        {
            throw new CoordinatorValidationException(
                $"{field} reference-answer scan timed out; no output was written. {exception.Message}");
        }
    }

    private static void RejectReferenceAnswersInOutputStrings(
        TeacherGenerationManifest outputDocument,
        Regex matcher)
    {
        var pending = new Stack<JsonElement>();
        pending.Push(JsonSerializer.SerializeToElement(outputDocument, OutputJson));
        var remainingCharacters = MaxJsonBytes;
        while (pending.TryPop(out var element))
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    pending.Push(property.Value);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    pending.Push(item);
                }
            }
            else if (element.ValueKind == JsonValueKind.String)
            {
                var value = element.GetString() ?? string.Empty;
                if (value.Length > remainingCharacters)
                {
                    throw new CoordinatorValidationException(
                        $"Teacher-generation output string values exceed the {MaxJsonBytes:N0}-character pre-serialization scan limit; no output was written.");
                }
                remainingCharacters -= value.Length;
                if (ContainsReferenceAnswer(
                        matcher,
                        value,
                        "Teacher-generation emitted JSON string value"))
                {
                    throw new CoordinatorValidationException(
                        "Teacher-generation emitted JSON string value must not contain a stripped terminal reference answer.");
                }
            }
        }
    }

    private static void ValidateEvidence(IReadOnlyList<string> evidence, string taskId)
    {
        if (evidence is null || evidence.Count is < 1 or > MaxEvidenceItems)
        {
            throw new CoordinatorValidationException(
                $"Draft task '{taskId}' evidence must contain 1 to {MaxEvidenceItems} items.");
        }
        var unique = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < evidence.Count; index++)
        {
            RequireText(evidence[index], MaxEvidenceCharacters, $"Draft task '{taskId}' evidence {index}");
            if (evidence[index].StartsWith("knowledgeClass=", StringComparison.Ordinal))
            {
                throw new CoordinatorValidationException(
                    $"Draft task '{taskId}' evidence must not override knowledgeClass.");
            }
            if (!unique.Add(evidence[index]))
            {
                throw new CoordinatorValidationException($"Draft task '{taskId}' contains duplicate evidence.");
            }
        }
    }

    private static void ValidateSourceMetadata(
        ExpertModelDatasetDraftSource source,
        string taskId,
        DateTimeOffset cutoffUtc)
    {
        if (source is null)
        {
            throw new CoordinatorValidationException($"Draft task '{taskId}' contains a null source.");
        }
        RequireSafeId(source.Id, $"Draft task '{taskId}' source ID");
        RequireText(source.Title, 500, $"Draft source '{source.Id}' title");
        RequireText(source.ContentPath, 500, $"Draft source '{source.Id}' contentPath");
        RequireText(source.Provenance, 2_000, $"Draft source '{source.Id}' provenance");
        RequireText(source.License, 500, $"Draft source '{source.Id}' license");
        ValidateWholeSecond(source.RetrievedAtUtc, $"Draft source '{source.Id}' retrievedAtUtc");
        ValidateWholeSecond(source.AvailableAtUtc, $"Draft source '{source.Id}' availableAtUtc");
        if (source.AvailableAtUtc > source.RetrievedAtUtc || source.RetrievedAtUtc > cutoffUtc)
        {
            throw new CoordinatorValidationException(
                $"Draft source '{source.Id}' requires availableAtUtc <= retrievedAtUtc <= cutoffUtc.");
        }
        if (source.Uri is not null)
        {
            RequireText(source.Uri, 2_000, $"Draft source '{source.Id}' uri");
            if (source.Uri.Any(character => character > 0x7f || char.IsWhiteSpace(character)) ||
                !Uri.TryCreate(source.Uri, UriKind.Absolute, out var uri) ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                (uri.Scheme is "http" or "https" && string.IsNullOrEmpty(uri.Host)))
            {
                throw new CoordinatorValidationException(
                    $"Draft source '{source.Id}' uri must be an absolute ASCII URI without credentials or whitespace.");
            }
        }
    }

    private static void ValidateCatalog(CandidateCatalog catalog, string selectedCandidateId)
    {
        if (catalog.SchemaVersion != CandidateCatalogSchemaVersion || catalog.CatalogVersion != "1.0.0" ||
            catalog.Candidates is null || catalog.Candidates.Count != ExpectedCandidates.Count)
        {
            throw new CoordinatorValidationException(
                "Candidate catalog must be the complete daxalgo.vibe-quant.candidate-catalog/v1 shortlist.");
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        CandidateCatalogEntry? selected = null;
        foreach (var candidate in catalog.Candidates)
        {
            if (candidate is null || !seen.Add(candidate.Id) ||
                !ExpectedCandidates.TryGetValue(candidate.Id, out var expected))
            {
                throw new CoordinatorValidationException(
                    "Candidate catalog contains a null, duplicate, or unapproved candidate.");
            }
            if (candidate.DisplayName != expected.DisplayName ||
                candidate.ModelId != expected.ModelId ||
                candidate.OfficialSourceUrl != expected.OfficialSourceUrl ||
                candidate.Revision != expected.Revision ||
                candidate.License != "Apache-2.0" ||
                candidate.LicenseUrl != "https://www.apache.org/licenses/LICENSE-2.0" ||
                candidate.Roles is null ||
                !candidate.Roles.SequenceEqual(expected.Roles, StringComparer.Ordinal))
            {
                throw new CoordinatorValidationException(
                    $"Candidate catalog entry '{candidate.Id}' does not match the approved pinned shortlist contract.");
            }
            if (candidate.Id == selectedCandidateId)
            {
                selected = candidate;
            }
        }
        if (!seen.SetEquals(ExpectedCandidates.Keys))
        {
            throw new CoordinatorValidationException(
                "Candidate catalog must contain every approved shortlist entry exactly once.");
        }
        if (selected is null)
        {
            throw new CoordinatorValidationException(
                "Capture plan teacher candidate does not exist in the pinned candidate catalog.");
        }
        if (!selected.Roles.Contains("teacher", StringComparer.Ordinal))
        {
            throw new CoordinatorValidationException(
                "Capture plan teacher candidate must carry the teacher role in the pinned candidate catalog.");
        }
    }

    private static string ResolveContainedSourcePath(
        string manifestDirectory,
        string contentPath,
        string sourceId)
    {
        if (Path.IsPathRooted(contentPath) || contentPath.Contains('\\'))
        {
            throw new CoordinatorValidationException(
                $"Draft source '{sourceId}' contentPath must be a portable relative forward-slash path.");
        }
        var segments = contentPath.Split('/');
        if (segments.Any(segment =>
                string.IsNullOrEmpty(segment) ||
                segment is "." or ".." ||
                segment.EndsWith(' ') ||
                segment.EndsWith('.') ||
                segment.Any(IsPortableInvalidPathCharacter)))
        {
            throw new CoordinatorValidationException(
                $"Draft source '{sourceId}' contentPath must not contain aliases, alternate-data-stream syntax, or portable invalid characters.");
        }
        var fullPath = Path.GetFullPath(
            Path.Combine(manifestDirectory, contentPath.Replace('/', Path.DirectorySeparatorChar)));
        var relative = Path.GetRelativePath(manifestDirectory, fullPath)
            .Replace(Path.DirectorySeparatorChar, '/');
        if (!StringComparer.Ordinal.Equals(relative, contentPath) || IsEscapingRelativePath(relative))
        {
            throw new CoordinatorValidationException(
                $"Draft source '{sourceId}' contentPath escapes or aliases the manifest directory.");
        }
        RejectExistingReparseComponents(manifestDirectory, $"Draft source '{sourceId}' root");
        RejectExistingReparseComponents(fullPath, $"Draft source '{sourceId}' path");
        return fullPath;
    }

    private static bool IsEscapingRelativePath(string relativePath) =>
        Path.IsPathRooted(relativePath) || relativePath == ".." ||
        relativePath.StartsWith("../", StringComparison.Ordinal);

    private static bool IsPortableInvalidPathCharacter(char character) =>
        character < 0x20 || character is '<' or '>' or ':' or '"' or '\\' or '|' or '?' or '*';

    private static void RequireDistinctPaths(params string[] paths)
    {
        if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length)
        {
            throw new CoordinatorValidationException(
                "Draft manifest, capture plan, candidate catalog, and output must be distinct paths.");
        }
    }

    private static void RequireStorageEvaluationOnlyRights(DatasetRights rights, string field)
    {
        if (rights is null || !rights.MayStore || !rights.MayEvaluate || rights.MayTrain ||
            rights.MayUploadToProvider || rights.MayRedistribute)
        {
            throw new CoordinatorValidationException(
                $"{field} must explicitly permit only private storage and evaluation.");
        }
    }

    private static void RequireSafeId(string value, string field)
    {
        if (value is null || !SafeIdRegex.IsMatch(value))
        {
            throw new CoordinatorValidationException(
                $"{field} must be a safe identifier of at most 200 characters.");
        }
    }

    private static void RequireText(string value, int maxCharacters, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maxCharacters)
        {
            throw new CoordinatorValidationException(
                $"{field} must be non-empty and at most {maxCharacters:N0} characters.");
        }
    }

    private static void RequireSha256(string value, string field)
    {
        if (value is null || !Sha256Regex.IsMatch(value))
        {
            throw new CoordinatorValidationException(
                $"{field} must be a lowercase 64-character SHA-256 value.");
        }
    }

    private static void RequireIdentitySha256(string value, string field)
    {
        RequireSha256(value, field);
        if (value.All(character => character == value[0]))
        {
            throw new CoordinatorValidationException(
                $"{field} must not be a repeated-character placeholder.");
        }
    }

    private static void RequirePinnedProfileVersion(string value)
    {
        RequireText(value, 500, "Capture plan teacher profileVersion");
        var normalized = value.ToLowerInvariant();
        if (normalized is "main" or "master" or "latest" or "trunk" ||
            normalized.Contains("replace_", StringComparison.Ordinal) ||
            normalized.Contains("todo", StringComparison.Ordinal) ||
            normalized.Contains("tbd", StringComparison.Ordinal))
        {
            throw new CoordinatorValidationException(
                "Capture plan teacher profileVersion must be immutable and must not be a placeholder.");
        }
    }

    private static void ValidateWholeSecond(DateTimeOffset value, string field)
    {
        if (value == default || value.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new CoordinatorValidationException(
                $"{field} must be set at whole-second precision.");
        }
    }

    private static string FormatUtcSecond(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);

    private static T Deserialize<T>(FileSnapshot snapshot, string description)
    {
        try
        {
            using var document = JsonDocument.Parse(snapshot.Bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64,
            });
            RejectDuplicateKeys(document.RootElement, description);
            return JsonSerializer.Deserialize<T>(snapshot.Bytes, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException($"{description} must not be empty.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException(
                $"{description} is invalid strict JSON: {exception.Message}");
        }
    }

    private static void RejectDuplicateKeys(JsonElement element, string field)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new CoordinatorValidationException(
                        $"{field} contains duplicate object key '{property.Name}'.");
                }
                RejectDuplicateKeys(property.Value, $"{field}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateKeys(item, $"{field}[{index++}]");
            }
        }
    }

    private static async Task<FileSnapshot> ReadSnapshotAsync(
        string path,
        long maxBytes,
        string description,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        RejectExistingReparseComponents(fullPath, description);
        await using var stream = new FileStream(
            fullPath,
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
        var expectedLength = stream.Length;
        var bytes = new byte[checked((int)expectedLength)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.Length != expectedLength || stream.Position != expectedLength)
        {
            throw new CoordinatorValidationException($"{description} changed while it was read.");
        }
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException($"{description} must be BOM-less UTF-8.");
        }
        string text;
        try
        {
            text = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new CoordinatorValidationException(
                $"{description} must be strict UTF-8: {exception.Message}");
        }
        return new FileSnapshot(fullPath, description, maxBytes, bytes, text, ComputeSha256(bytes));
    }

    private static async Task RevalidateSnapshotAsync(
        FileSnapshot expected,
        CancellationToken cancellationToken)
    {
        FileSnapshot actual;
        try
        {
            actual = await ReadSnapshotAsync(
                expected.Path,
                expected.MaxBytes,
                expected.Description,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CoordinatorValidationException(
                $"{expected.Description} changed before publication: {exception.Message}");
        }
        if (!CryptographicOperations.FixedTimeEquals(expected.Bytes, actual.Bytes))
        {
            throw new CoordinatorValidationException(
                $"{expected.Description} changed before publication; no output was written.");
        }
    }

    private static void RejectExistingReparseComponents(string path, string description)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath)
            ?? throw new CoordinatorValidationException($"{description} has no filesystem root.");
        var current = root;
        foreach (var segment in fullPath[root.Length..].Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                break;
            }
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(current);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new CoordinatorValidationException(
                    $"{description} could not be inspected: {exception.Message}");
            }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new CoordinatorValidationException(
                    $"{description} must not traverse a reparse point.");
            }
        }
    }

    private static string ComputeSha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string ComputeStructuralSha256<T>(T value) =>
        ComputeSha256(JsonSerializer.SerializeToUtf8Bytes(value, OutputJson));

    private sealed record FileSnapshot(
        string Path,
        string Description,
        long MaxBytes,
        byte[] Bytes,
        string Text,
        string Sha256);

    private sealed record ExpectedCandidate(
        string DisplayName,
        string ModelId,
        string OfficialSourceUrl,
        string Revision,
        IReadOnlyList<string> Roles);

    private sealed record TeacherPromptSource(
        string Id,
        string Title,
        string AvailableAtUtc,
        string Content);

    private sealed record TeacherPromptIdentity(
        IReadOnlyList<LlmMessage> AuthoredMessages,
        IReadOnlyList<TeacherPromptSource> Sources);

    private sealed record TeacherTaskContentIdentity(
        ExpertTaskKind TaskKind,
        IReadOnlyList<ExpertDomain> Domains,
        string PromptIdentity,
        string ContaminationGroup,
        string KnowledgeClass,
        string CutoffUtc,
        int MaxOutputTokens,
        IReadOnlyList<string> Evidence,
        IReadOnlyList<TeacherGenerationSource> Sources);

    private sealed record CandidateCatalog
    {
        public required string SchemaVersion { get; init; }
        public required string CatalogVersion { get; init; }
        public required IReadOnlyList<CandidateCatalogEntry> Candidates { get; init; }
    }

    private sealed record CandidateCatalogEntry
    {
        public required string Id { get; init; }
        public required string DisplayName { get; init; }
        public required string ModelId { get; init; }
        public required string Revision { get; init; }
        public required string License { get; init; }
        public required string LicenseUrl { get; init; }
        public required string OfficialSourceUrl { get; init; }
        public required IReadOnlyList<string> Roles { get; init; }
    }

    private sealed record TeacherGenerationManifest
    {
        public required string SchemaVersion { get; init; }
        public required string Split { get; init; }
        public required string DraftManifestSha256 { get; init; }
        public required string CandidateCatalogSha256 { get; init; }
        public required ExpertModelTeacherIdentity Teacher { get; init; }
        public required ExpertModelTeacherGenerationPolicy Generation { get; init; }
        public required ExpertModelTeacherGenerationBudget Budget { get; init; }
        public required TeacherGenerationAuthority Authority { get; init; }
        public required ExpertModelTeacherTokenizerPreflight TokenizerPreflight { get; init; }
        public required IReadOnlyList<TeacherGenerationTask> Tasks { get; init; }
    }

    private sealed record TeacherGenerationAuthority
    {
        public required string Producer { get; init; }
        public required string Reviewer { get; init; }
        public required string Provenance { get; init; }
        public required string License { get; init; }
        public required string RightsBasis { get; init; }
        public required DatasetRights Rights { get; init; }
    }

    private sealed record TeacherGenerationTask
    {
        public required string TaskId { get; init; }
        public required ExpertTaskKind TaskKind { get; init; }
        public required IReadOnlyList<ExpertDomain> Domains { get; init; }
        public required IReadOnlyList<LlmMessage> Messages { get; init; }
        public required string ContaminationGroup { get; init; }
        public required string KnowledgeClass { get; init; }
        public required string CutoffUtc { get; init; }
        public required int MaxOutputTokens { get; init; }
        public required IReadOnlyList<string> Evidence { get; init; }
        public required IReadOnlyList<TeacherGenerationSource> Sources { get; init; }
    }

    private sealed record TeacherGenerationSource
    {
        public required string Id { get; init; }
        public required string Title { get; init; }
        public required string ContentPath { get; init; }
        public required string ContentSha256 { get; init; }
        public required string Provenance { get; init; }
        public required string License { get; init; }
        public required string RetrievedAtUtc { get; init; }
        public required string AvailableAtUtc { get; init; }
        public string? Uri { get; init; }
    }
}
