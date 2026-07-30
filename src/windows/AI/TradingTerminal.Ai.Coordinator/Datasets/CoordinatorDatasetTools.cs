using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

public sealed record DatasetRights(
    bool MayStore,
    bool MayEvaluate,
    bool MayTrain,
    bool MayUploadToProvider,
    bool MayRedistribute);

public sealed record DatasetSourceAsset(
    string Id,
    string Title,
    string Content,
    string Provenance,
    string License,
    DateTimeOffset RetrievedAtUtc,
    DateTimeOffset? AvailableAtUtc,
    string? Uri,
    DatasetRights Rights);

public sealed record CoordinatorDatasetExample
{
    public required string SchemaVersion { get; init; }
    public required string Id { get; init; }
    public required string Split { get; init; }
    public required string ContaminationGroup { get; init; }
    public required CoordinatorRole Role { get; init; }
    public required string Objective { get; init; }
    public IReadOnlyList<DatasetSourceAsset> Sources { get; init; } = [];
    public IReadOnlyList<CoordinatorRoleOutput> PriorOutputs { get; init; } = [];
    public required CoordinatorRoleOutput ReferenceOutput { get; init; }
    public IReadOnlyList<string> RequiredConcepts { get; init; } = [];
    public IReadOnlyList<string> ForbiddenConcepts { get; init; } = [];
    public required string Provenance { get; init; }
    public required string License { get; init; }
    public required DatasetRights Rights { get; init; }
    public required string ReviewStatus { get; init; }
    public required DateTimeOffset CutoffUtc { get; init; }
    public bool UseForTraining { get; init; }
}

public sealed record DatasetValidationIssue(int Line, string? ExampleId, string Message);

public sealed record DatasetValidationReport(
    int ExampleCount,
    int TrainingEligibleCount,
    IReadOnlyList<DatasetValidationIssue> Issues)
{
    public bool IsValid => Issues.Count == 0;
}

public static class CoordinatorDatasetTools
{
    public const long MaxDatasetBytes = 100_000_000;
    public const int MaxDatasetExamples = 100_000;
    public const int MaxJsonLineCharacters = 2_000_000;
    public const int MaxReportedIssues = 10_000;
    public const long MaxSftExportBytes = 100_000_000;

    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private static readonly HashSet<string> AllowedSplits =
        new(["development", "calibration", "sealed"], StringComparer.Ordinal);

    public static async Task<DatasetValidationReport> ValidateJsonLinesAsync(
        string path,
        CancellationToken cancellationToken = default)
        => (await LoadAndValidateAsync(path, cancellationToken).ConfigureAwait(false)).Report;

    private static async Task<LoadedDataset> LoadAndValidateAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var issues = new List<DatasetValidationIssue>();
        var examples = new List<(int Line, CoordinatorDatasetExample Example)>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var contentSplits = new Dictionary<string, (string Split, string Id)>(StringComparer.Ordinal);
        var groupSplits = new Dictionary<string, (string Split, string Id)>(StringComparer.Ordinal);

        await using var stream = new FileStream(
            Path.GetFullPath(path),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > MaxDatasetBytes)
        {
            throw new CoordinatorValidationException(
                $"Dataset exceeds the {MaxDatasetBytes:N0}-byte input limit.");
        }

        using var reader = new StreamReader(stream, StrictUtf8, detectEncodingFromByteOrderMarks: false);
        var lineNumber = 0;
        var nonEmptyLineCount = 0;
        while (true)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (DecoderFallbackException exception)
            {
                throw new CoordinatorValidationException($"Dataset must be valid UTF-8: {exception.Message}");
            }
            if (line is null)
            {
                break;
            }
            lineNumber++;
            if (lineNumber == 1 && line.Length > 0 && line[0] == '\uFEFF')
            {
                line = line[1..];
            }
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            nonEmptyLineCount++;
            if (nonEmptyLineCount > MaxDatasetExamples)
            {
                throw new CoordinatorValidationException(
                    $"Dataset exceeds the {MaxDatasetExamples:N0}-example input limit.");
            }
            if (issues.Count >= MaxReportedIssues)
            {
                throw new CoordinatorValidationException(
                    $"Dataset reached the {MaxReportedIssues:N0}-issue reporting limit.");
            }
            if (line.Length > MaxJsonLineCharacters)
            {
                issues.Add(new DatasetValidationIssue(
                    lineNumber,
                    null,
                    $"JSON line exceeds {MaxJsonLineCharacters:N0} characters."));
                continue;
            }
            CoordinatorDatasetExample? example;
            try
            {
                using var document = JsonDocument.Parse(line);
                ValidateDatasetJsonShape(document.RootElement);
                example = JsonSerializer.Deserialize<CoordinatorDatasetExample>(line, CoordinatorJson.Options);
            }
            catch (Exception exception) when (exception is JsonException or CoordinatorValidationException)
            {
                issues.Add(new DatasetValidationIssue(lineNumber, null, $"Invalid dataset row: {exception.Message}"));
                continue;
            }

            if (example is null)
            {
                issues.Add(new DatasetValidationIssue(lineNumber, null, "Example must not be JSON null."));
                continue;
            }

            examples.Add((lineNumber, example));
            ValidateExample(lineNumber, example, issues);
            if (!ids.Add(example.Id))
            {
                issues.Add(new DatasetValidationIssue(lineNumber, example.Id, "Example ID is duplicated."));
            }

            if (example.Objective is not null && example.Sources is not null &&
                example.Sources.All(source => source is not null && source.Content is not null))
            {
                var contentHash = ContentHasher.HashJson(new
                {
                    example.Objective,
                    Sources = example.Sources
                        .Select(source => ContentHasher.HashUtf8(source.Content))
                        .OrderBy(hash => hash, StringComparer.Ordinal)
                        .ToArray()
                });
                if (contentSplits.TryGetValue(contentHash, out var priorContent) && priorContent.Split != example.Split)
                {
                    issues.Add(new DatasetValidationIssue(
                        lineNumber,
                        example.Id,
                        $"Exact content duplicates '{priorContent.Id}' across '{priorContent.Split}' and '{example.Split}'."));
                }
                else
                {
                    contentSplits[contentHash] = (example.Split, example.Id);
                }
            }

            if (!string.IsNullOrWhiteSpace(example.ContaminationGroup) &&
                groupSplits.TryGetValue(example.ContaminationGroup, out var priorGroup) && priorGroup.Split != example.Split)
            {
                issues.Add(new DatasetValidationIssue(
                    lineNumber,
                    example.Id,
                    $"Contamination group also appears in '{priorGroup.Split}' as '{priorGroup.Id}'."));
            }
            else if (!string.IsNullOrWhiteSpace(example.ContaminationGroup))
            {
                groupSplits[example.ContaminationGroup] = (example.Split, example.Id);
            }
            if (issues.Count >= MaxReportedIssues)
            {
                throw new CoordinatorValidationException(
                    $"Dataset reached the {MaxReportedIssues:N0}-issue reporting limit.");
            }
        }

        var trainingEligible = examples.Count(item => IsTrainingEligible(item.Example, requireProviderUploadRights: false));
        return new LoadedDataset(
            new DatasetValidationReport(examples.Count, trainingEligible, issues),
            examples.Select(item => item.Example).ToArray());
    }

    public static async Task<int> ExportSftJsonLinesAsync(
        string inputPath,
        string outputPath,
        bool requireProviderUploadRights,
        CancellationToken cancellationToken = default)
    {
        var fullInputPath = Path.GetFullPath(inputPath);
        var fullOutputPath = Path.GetFullPath(outputPath);
        if (StringComparer.OrdinalIgnoreCase.Equals(fullInputPath, fullOutputPath))
        {
            throw new ArgumentException("SFT output must not overwrite its source dataset.", nameof(outputPath));
        }

        var dataset = await LoadAndValidateAsync(inputPath, cancellationToken).ConfigureAwait(false);
        if (!dataset.Report.IsValid)
        {
            throw new CoordinatorValidationException("Dataset validation failed; no SFT file was written.");
        }
        if (requireProviderUploadRights)
        {
            foreach (var example in dataset.Examples)
            {
                if (IsTrainingEligible(example, requireProviderUploadRights: false) &&
                    !IsTrainingEligible(example, requireProviderUploadRights: true))
                {
                    throw new CoordinatorValidationException(
                        $"Training example '{example.Id}' lacks provider-upload rights; no SFT file was written.");
                }
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(fullOutputPath)!);
        var temporaryPath = $"{fullOutputPath}.{Guid.NewGuid():N}.tmp";
        var exported = 0;
        long exportedBytes = 0;
        try
        {
            {
                await using var outputStream = new FileStream(
                    temporaryPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    useAsync: true);
                await using var writer = new StreamWriter(
                    outputStream,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
                {
                    NewLine = CoordinatorPromptCatalog.PromptNewLine
                };
                foreach (var example in dataset.Examples)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!IsTrainingEligible(example, requireProviderUploadRights))
                    {
                        continue;
                    }

                    var row = new
                    {
                        messages = new object[]
                        {
                            new { role = "system", content = BuildSystemPrompt(example.Role) },
                            new { role = "user", content = BuildUserPrompt(example) },
                            new
                            {
                                role = "assistant",
                                content = JsonSerializer.Serialize(example.ReferenceOutput, CompactJson)
                            }
                        },
                        metadata = new
                        {
                            example.Id,
                            example.ContaminationGroup,
                            example.CutoffUtc,
                            sourceSchema = example.SchemaVersion,
                            policyVersion = CoordinatorVersions.Policy,
                            workflowVersion = CoordinatorVersions.Workflow,
                            promptCatalogSha256 = CoordinatorPromptCatalog.Sha256
                        }
                    };
                    var serializedRow = JsonSerializer.Serialize(row, CompactJson);
                    var rowBytes = Encoding.UTF8.GetByteCount(serializedRow) + 1L;
                    if (rowBytes > MaxSftExportBytes - exportedBytes)
                    {
                        throw new CoordinatorValidationException(
                            $"SFT export exceeds the {MaxSftExportBytes:N0}-byte output limit.");
                    }
                    await writer.WriteLineAsync(serializedRow.AsMemory(), cancellationToken)
                        .ConfigureAwait(false);
                    exportedBytes += rowBytes;
                    exported++;
                }

                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporaryPath, fullOutputPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return exported;
    }

    private static void ValidateExample(
        int line,
        CoordinatorDatasetExample example,
        ICollection<DatasetValidationIssue> issues)
    {
        void Require(string? value, string field)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"{field} is required."));
            }
        }

        Require(example.Id, nameof(example.Id));
        Require(example.Objective, nameof(example.Objective));
        Require(example.ContaminationGroup, nameof(example.ContaminationGroup));
        Require(example.Provenance, nameof(example.Provenance));
        Require(example.License, nameof(example.License));
        if (!IsSafeId(example.Id))
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Example ID contains unsupported characters."));
        }
        if (example.Objective?.Length > 20_000)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Objective exceeds 20,000 characters."));
        }
        if (example.Sources is null || example.PriorOutputs is null ||
            example.ReferenceOutput is null || example.Rights is null)
        {
            issues.Add(new DatasetValidationIssue(
                line,
                example.Id,
                "Sources, priorOutputs, referenceOutput, and rights are required."));
            return;
        }
        if (example.Sources.Count > CoordinatorValidation.MaxSourceCount)
        {
            issues.Add(new DatasetValidationIssue(
                line,
                example.Id,
                $"Sources exceed the {CoordinatorValidation.MaxSourceCount}-source limit."));
            return;
        }
        if (example.Sources
                .Where(source => source?.Content is not null)
                .Sum(source => (long)source!.Content.Length) > CoordinatorValidation.MaxAggregateSourceCharacters)
        {
            issues.Add(new DatasetValidationIssue(
                line,
                example.Id,
                $"Source content exceeds the {CoordinatorValidation.MaxAggregateSourceCharacters:N0}-character aggregate limit."));
        }

        if (example.RequiredConcepts is null || example.ForbiddenConcepts is null)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Required and forbidden concept arrays must not be null."));
        }
        if (example.SchemaVersion != CoordinatorVersions.DatasetSchema)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Unsupported dataset schema version."));
        }

        if (!AllowedSplits.Contains(example.Split))
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Split must be development, calibration, or sealed."));
        }

        if (example.CutoffUtc == default || example.CutoffUtc > DateTimeOffset.UtcNow)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "cutoffUtc must be set and not be in the future."));
        }

        if (!StringComparer.OrdinalIgnoreCase.Equals(example.ReviewStatus, "approved"))
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Review status must be 'approved'."));
        }

        if (example.UseForTraining && example.Split != "development")
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Only development examples may be used for training."));
        }

        if (!example.Rights.MayStore || !example.Rights.MayEvaluate)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Example lacks storage/evaluation rights."));
        }

        if (example.UseForTraining && !example.Rights.MayTrain)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, "Training is requested but the example lacks training rights."));
        }

        var sourceIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in example.Sources)
        {
            if (source is null)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, "Source entries must not be null."));
                continue;
            }

            Require(source.Id, "Source ID");
            Require(source.Title, $"Source '{source.Id}' title");
            Require(source.Content, $"Source '{source.Id}' content");
            Require(source.Provenance, $"Source '{source.Id}' provenance");
            Require(source.License, $"Source '{source.Id}' license");
            if (!IsSafeId(source.Id))
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source ID '{source.Id}' contains unsupported characters."));
            }
            if (source.Title?.Length > 500 || source.Content?.Length > 500_000)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source '{source.Id}' title or content exceeds its size limit."));
            }
            if (!sourceIds.Add(source.Id))
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Duplicate source ID '{source.Id}'."));
            }


            if (source.Rights is null)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source '{source.Id}' rights are required."));
                continue;
            }

            if (source.RetrievedAtUtc == default || source.RetrievedAtUtc > DateTimeOffset.UtcNow)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source '{source.Id}' retrieval time must be set and not be in the future."));
            }

            if (source.AvailableAtUtc > example.CutoffUtc)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source '{source.Id}' was unavailable at the task cutoff."));
            }
            if (example.Split is "calibration" or "sealed" && source.AvailableAtUtc is null)
            {
                issues.Add(new DatasetValidationIssue(
                    line,
                    example.Id,
                    $"Source '{source.Id}' requires availableAtUtc in calibration or sealed data."));
            }

            if (!source.Rights.MayStore || !source.Rights.MayEvaluate)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source '{source.Id}' lacks storage/evaluation rights."));
            }

            if (example.UseForTraining && !source.Rights.MayTrain)
            {
                issues.Add(new DatasetValidationIssue(line, example.Id, $"Source '{source.Id}' lacks training rights."));
            }
        }

        try
        {
            var currentRoleIndex = RoleIndex(example.Role);
            if (currentRoleIndex < 0 || example.PriorOutputs.Count != currentRoleIndex)
            {
                throw new CoordinatorValidationException(
                    $"Role '{example.Role}' requires the exact preceding workflow-output prefix.");
            }
            for (var priorIndex = 0; priorIndex < example.PriorOutputs.Count; priorIndex++)
            {
                var priorOutput = example.PriorOutputs[priorIndex];
                if (priorOutput is null)
                {
                    throw new CoordinatorValidationException("Prior output entries must not be null.");
                }

                if (priorOutput.Role != ResearchCoordinator.Workflow[priorIndex])
                {
                    throw new CoordinatorValidationException(
                        $"Prior output {priorIndex + 1} must be '{ResearchCoordinator.Workflow[priorIndex]}'.");
                }

                CoordinatorValidation.ParseRoleOutput(
                    JsonSerializer.Serialize(priorOutput, CoordinatorJson.Options),
                    priorOutput.Role,
                    sourceIds);
            }

            CoordinatorValidation.ParseRoleOutput(example.ReferenceOutput is null
                    ? "null"
                    : JsonSerializer.Serialize(example.ReferenceOutput, CoordinatorJson.Options),
                example.Role,
                sourceIds);
        }
        catch (CoordinatorValidationException exception)
        {
            issues.Add(new DatasetValidationIssue(line, example.Id, $"Reference output: {exception.Message}"));
        }
    }

    private static void ValidateDatasetJsonShape(JsonElement root)
    {
        RequireObjectProperties(
            root,
            "dataset example",
            "schemaVersion",
            "id",
            "split",
            "contaminationGroup",
            "role",
            "objective",
            "sources",
            "priorOutputs",
            "referenceOutput",
            "requiredConcepts",
            "forbiddenConcepts",
            "provenance",
            "license",
            "rights",
            "reviewStatus",
            "cutoffUtc",
            "useForTraining");
        RequireArray(root, "sources");
        RequireArray(root, "priorOutputs");
        RequireArray(root, "requiredConcepts");
        RequireArray(root, "forbiddenConcepts");
        ValidateRightsShape(root.GetProperty("rights"), "example rights");

        foreach (var source in root.GetProperty("sources").EnumerateArray())
        {
            RequireObjectProperties(
                source,
                "dataset source",
                "id",
                "title",
                "content",
                "provenance",
                "license",
                "retrievedAtUtc",
                "availableAtUtc",
                "uri",
                "rights");
            ValidateRightsShape(source.GetProperty("rights"), "source rights");
        }

        foreach (var priorOutput in root.GetProperty("priorOutputs").EnumerateArray())
        {
            ValidateRoleOutputShape(priorOutput, "prior output");
        }
        ValidateRoleOutputShape(root.GetProperty("referenceOutput"), "reference output");
    }

    private static void ValidateRoleOutputShape(JsonElement output, string name)
    {
        RequireObjectProperties(
            output,
            name,
            "schemaVersion",
            "role",
            "summary",
            "claims",
            "risks",
            "recommendations",
            "sourceIds",
            "decision");
        foreach (var arrayName in new[] { "claims", "risks", "recommendations", "sourceIds" })
        {
            RequireArray(output, arrayName);
        }
        foreach (var claim in output.GetProperty("claims").EnumerateArray())
        {
            RequireObjectProperties(claim, "claim", "statement", "evidenceSourceIds", "confidence");
            RequireArray(claim, "evidenceSourceIds");
        }
    }

    private static void ValidateRightsShape(JsonElement rights, string name)
    {
        var properties = new[]
        {
            "mayStore",
            "mayEvaluate",
            "mayTrain",
            "mayUploadToProvider",
            "mayRedistribute"
        };
        RequireObjectProperties(rights, name, properties);
        foreach (var propertyName in properties)
        {
            if (rights.GetProperty(propertyName).ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                throw new CoordinatorValidationException($"{name} '{propertyName}' must be a boolean.");
            }
        }
    }

    private static void RequireArray(JsonElement parent, string propertyName)
    {
        if (parent.GetProperty(propertyName).ValueKind != JsonValueKind.Array)
        {
            throw new CoordinatorValidationException($"'{propertyName}' must be an array.");
        }
    }

    private static void RequireObjectProperties(JsonElement element, string name, params string[] properties)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new CoordinatorValidationException($"{name} must be a JSON object.");
        }
        foreach (var property in properties)
        {
            if (!element.TryGetProperty(property, out _))
            {
                throw new CoordinatorValidationException($"{name} is missing required property '{property}'.");
            }
        }
    }

    private static bool IsTrainingEligible(CoordinatorDatasetExample example, bool requireProviderUploadRights) =>
        example.UseForTraining &&
        example.Split == "development" &&
        StringComparer.OrdinalIgnoreCase.Equals(example.ReviewStatus, "approved") &&
        example.Sources is not null &&
        example.Rights is not null &&
        example.Rights.MayTrain &&
        (!requireProviderUploadRights || example.Rights.MayUploadToProvider) &&
        example.Sources.All(source => source?.Rights is not null && source.Rights.MayTrain &&
            (!requireProviderUploadRights || source.Rights.MayUploadToProvider));

    private static int RoleIndex(CoordinatorRole role)
    {
        for (var index = 0; index < ResearchCoordinator.Workflow.Count; index++)
        {
            if (ResearchCoordinator.Workflow[index] == role)
            {
                return index;
            }
        }

        return -1;
    }

    private static string BuildSystemPrompt(CoordinatorRole role) =>
        CoordinatorPromptCatalog.SystemInstruction(role);

    private static string BuildUserPrompt(CoordinatorDatasetExample example)
        => CoordinatorPromptRenderer.BuildUserPrompt(
            example.Objective,
            example.Sources
                .Select(source => new CoordinatorPromptSource(source.Id, source.Title, source.Content))
                .ToArray(),
            example.PriorOutputs,
            example.Role);

    private static bool IsSafeId(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.All(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.');

    private sealed record LoadedDataset(
        DatasetValidationReport Report,
        IReadOnlyList<CoordinatorDatasetExample> Examples);
}
