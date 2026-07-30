using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

public enum ExpertTaskKind
{
    GeneralQuestionAnswering,
    CodeGeneration,
    CodeRepair,
    CodeReview,
    ArchitectureDesign,
    QuantitativeReasoning,
    StatisticalReasoning,
    RiskAnalysis,
    PortfolioAnalysis,
    MarketAnalysis,
    WpfUiDesign
}

public enum ExpertDomain
{
    CSharp,
    DaxAlgoArchitecture,
    QuantitativeMath,
    ProbabilityStatistics,
    RiskManagement,
    PortfolioManagement,
    FinanceMarkets,
    WpfUiDesign
}

public enum ExpertDatasetOrigin
{
    HumanAuthored,
    OpenWeightTeacher,
    HostedTeacher,
    DerivedRepair
}

public sealed record ExpertModelLineage
{
    public required ExpertDatasetOrigin Origin { get; init; }
    public required string Producer { get; init; }
    public string? ModelId { get; init; }
    public string? ModelRevision { get; init; }
    public string? PromptSha256 { get; init; }
    public string? ProfileVersion { get; init; }
    public required DateTimeOffset ProducedAtUtc { get; init; }
}

public sealed record ExpertVerificationEvidence
{
    public bool Verified { get; init; }
    public required string Reviewer { get; init; }
    public required DateTimeOffset? VerifiedAtUtc { get; init; }
    public required string EvidenceSha256 { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = [];
    public bool CompileSucceeded { get; init; }
    public IReadOnlyList<string> CompileEvidence { get; init; } = [];
    public bool TestsPassed { get; init; }
    public IReadOnlyList<string> TestEvidence { get; init; } = [];
}

public sealed record ExpertModelDatasetExample
{
    public required string SchemaVersion { get; init; }
    public required string Id { get; init; }
    public required ExpertTaskKind TaskKind { get; init; }
    public IReadOnlyList<ExpertDomain> Domains { get; init; } = [];
    public IReadOnlyList<LlmMessage> Messages { get; init; } = [];
    public required string ConversationSha256 { get; init; }
    public IReadOnlyList<DatasetSourceAsset> Sources { get; init; } = [];
    public required ExpertModelLineage Lineage { get; init; }
    public required ExpertVerificationEvidence Verification { get; init; }
    public required string Split { get; init; }
    public required string ContaminationGroup { get; init; }
    public required string Provenance { get; init; }
    public required string License { get; init; }
    public required DatasetRights Rights { get; init; }
    public required string ReviewStatus { get; init; }
    public required DateTimeOffset CutoffUtc { get; init; }
    public bool UseForTraining { get; init; }
}

public sealed record ExpertDatasetCoverageCell(
    ExpertTaskKind TaskKind,
    ExpertDomain Domain,
    string Split,
    int ExampleCount,
    int TrainingEligibleCount);

public sealed record ExpertDatasetCoverageReport(
    int ExampleCount,
    int TrainingEligibleCount,
    IReadOnlyDictionary<ExpertTaskKind, int> TaskCounts,
    IReadOnlyDictionary<ExpertDomain, int> DomainCounts,
    IReadOnlyDictionary<ExpertDatasetOrigin, int> OriginCounts,
    IReadOnlyDictionary<string, int> SplitCounts,
    IReadOnlyList<ExpertDatasetCoverageCell> Cells);

internal sealed record ExpertSftUnsignedMetadata(
    string SchemaVersion,
    string SourceCorpusSha256,
    string VerificationEvidenceSha256,
    string Id,
    string TaskKind,
    IReadOnlyList<string> Domains,
    string ConversationSha256,
    string Origin,
    string Producer,
    string? ModelId,
    string? ModelRevision,
    string? PromptSha256,
    string? ProfileVersion,
    string Split,
    string ContaminationGroup,
    string CutoffUtc,
    string SourceSchema);

public static class ExpertModelDatasetTools
{
    private const string CandidateStableKnowledgeClass = "knowledgeClass=candidate-stable";
    private const string RetrievalOnlyKnowledgeClass = "knowledgeClass=retrieval-only";
    public const long MaxDatasetBytes = 100_000_000;
    public const int MaxDatasetExamples = 100_000;
    public const int MaxJsonLineCharacters = 2_000_000;
    public const int MaxReportedIssues = 10_000;
    public const long MaxSftExportBytes = 100_000_000;
    public const int MaxMessageCount = 64;
    public const int MaxMessageCharacters = 500_000;
    public const int MaxAggregateMessageCharacters = 2_000_000;
    public const int MaxSourceCount = 64;
    public const int MaxSourceCharacters = 500_000;
    public const int MaxAggregateSourceCharacters = 2_000_000;
    public const int MaxEvidenceItems = 128;
    public const int MaxEvidenceCharacters = 2_000;

    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly HashSet<string> AllowedSplits =
        new(["development", "calibration", "sealed"], StringComparer.Ordinal);

    private static readonly HashSet<string> AllowedReviewStatuses =
        new(["draft", "pending", "approved", "rejected"], StringComparer.Ordinal);

    public static async Task<DatasetValidationReport> ValidateJsonLinesAsync(
        string path,
        CancellationToken cancellationToken = default)
        => (await LoadAndValidateAsync(path, cancellationToken).ConfigureAwait(false)).Report;

    public static string ComputeConversationSha256(IReadOnlyList<LlmMessage> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        var fields = messages.Select(message =>
        {
            ArgumentNullException.ThrowIfNull(message);
            ArgumentNullException.ThrowIfNull(message.Role);
            ArgumentNullException.ThrowIfNull(message.Content);
            return (IReadOnlyList<string>)[message.Role, message.Content];
        }).ToArray();
        return HashLengthPrefixedUtf8("daxalgo-expert-conversation/v1", fields);
    }

    public static string ComputeVerificationEvidenceSha256(
        IReadOnlyList<string> evidence,
        IReadOnlyList<string> compileEvidence,
        IReadOnlyList<string> testEvidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(compileEvidence);
        ArgumentNullException.ThrowIfNull(testEvidence);
        return HashLengthPrefixedUtf8(
            "daxalgo-expert-verification-evidence/v1",
            evidence,
            compileEvidence,
            testEvidence);
    }

    public static async Task<ExpertDatasetCoverageReport> BuildCoverageReportAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var dataset = await LoadAndValidateAsync(path, cancellationToken).ConfigureAwait(false);
        if (!dataset.Report.IsValid)
        {
            throw new CoordinatorValidationException(
                "Expert-model dataset validation failed; coverage was not calculated.");
        }

        var taskCounts = dataset.Examples
            .GroupBy(example => example.TaskKind)
            .OrderBy(group => group.Key)
            .ToDictionary(group => group.Key, group => group.Count());
        var domainCounts = dataset.Examples
            .SelectMany(example => example.Domains)
            .GroupBy(domain => domain)
            .OrderBy(group => group.Key)
            .ToDictionary(group => group.Key, group => group.Count());
        var originCounts = dataset.Examples
            .GroupBy(example => example.Lineage.Origin)
            .OrderBy(group => group.Key)
            .ToDictionary(group => group.Key, group => group.Count());
        var splitCounts = dataset.Examples
            .GroupBy(example => example.Split, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
        var cells = dataset.Examples
            .SelectMany(example => example.Domains.Select(domain => new { Example = example, Domain = domain }))
            .GroupBy(item => new { item.Example.TaskKind, item.Domain, item.Example.Split })
            .OrderBy(group => group.Key.TaskKind)
            .ThenBy(group => group.Key.Domain)
            .ThenBy(group => group.Key.Split, StringComparer.Ordinal)
            .Select(group => new ExpertDatasetCoverageCell(
                group.Key.TaskKind,
                group.Key.Domain,
                group.Key.Split,
                group.Count(),
                group.Count(item => IsTrainingEligible(
                    item.Example,
                    receipt: null,
                    requireProviderUploadRights: false))))
            .ToArray();

        return new ExpertDatasetCoverageReport(
            dataset.Report.ExampleCount,
            dataset.Report.TrainingEligibleCount,
            taskCounts,
            domainCounts,
            originCounts,
            splitCounts,
            cells);
    }

    public static Task<int> ExportSftJsonLinesAsync(
        string inputPath,
        string outputPath,
        bool requireProviderUploadRights,
        CancellationToken cancellationToken = default) =>
        ExportSftJsonLinesCoreAsync(
            inputPath,
            outputPath,
            receiptSetPath: null,
            receiptTrust: null,
            teacherLineageAdmissionPath: null,
            teacherLineageAdmissionTrust: null,
            requireProviderUploadRights,
            cancellationToken);

    public static Task<int> ExportSftJsonLinesAsync(
        string inputPath,
        string outputPath,
        string receiptSetPath,
        ExpertDatasetReviewReceiptTrust receiptTrust,
        bool requireProviderUploadRights,
        CancellationToken cancellationToken = default) =>
        ExportSftJsonLinesCoreAsync(
            inputPath,
            outputPath,
            receiptSetPath,
            receiptTrust,
            teacherLineageAdmissionPath: null,
            teacherLineageAdmissionTrust: null,
            requireProviderUploadRights,
            cancellationToken);

    public static Task<int> ExportSftJsonLinesAsync(
        string inputPath,
        string outputPath,
        string receiptSetPath,
        ExpertDatasetReviewReceiptTrust receiptTrust,
        string? teacherLineageAdmissionPath,
        ExpertTeacherLineageAdmissionTrust? teacherLineageAdmissionTrust,
        bool requireProviderUploadRights,
        CancellationToken cancellationToken = default) =>
        ExportSftJsonLinesCoreAsync(
            inputPath,
            outputPath,
            receiptSetPath,
            receiptTrust,
            teacherLineageAdmissionPath,
            teacherLineageAdmissionTrust,
            requireProviderUploadRights,
            cancellationToken);

    private static async Task<int> ExportSftJsonLinesCoreAsync(
        string inputPath,
        string outputPath,
        string? receiptSetPath,
        ExpertDatasetReviewReceiptTrust? receiptTrust,
        string? teacherLineageAdmissionPath,
        ExpertTeacherLineageAdmissionTrust? teacherLineageAdmissionTrust,
        bool requireProviderUploadRights,
        CancellationToken cancellationToken)
    {
        var fullInputPath = Path.GetFullPath(inputPath);
        var fullOutputPath = Path.GetFullPath(outputPath);
        if (StringComparer.OrdinalIgnoreCase.Equals(fullInputPath, fullOutputPath))
        {
            throw new ArgumentException("SFT output must not overwrite its source dataset.", nameof(outputPath));
        }

        var datasetBytes = await ReadBoundedDatasetBytesAsync(fullInputPath, cancellationToken)
            .ConfigureAwait(false);
        LoadedExpertDataset dataset;
        string sourceCorpusSha256;
        long datasetSizeBytes;
        try
        {
            datasetSizeBytes = datasetBytes.LongLength;
            sourceCorpusSha256 = ContentHasher.HashBytes(datasetBytes);
            dataset = await LoadAndValidateBytesAsync(datasetBytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(datasetBytes);
        }
        if (!dataset.Report.IsValid)
        {
            throw new CoordinatorValidationException(
                "Expert-model dataset validation failed; no SFT file was written.");
        }
        if (string.IsNullOrWhiteSpace(receiptSetPath) || receiptTrust is null)
        {
            throw new CoordinatorValidationException(
                "SFT export requires a detached authenticated review-receipt set and externally pinned trust policy; no file was written.");
        }
        if ((string.IsNullOrWhiteSpace(teacherLineageAdmissionPath)) !=
            (teacherLineageAdmissionTrust is null))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission path and externally pinned trust policy must be supplied together.");
        }

        var containsOpenWeightTeacher = dataset.Examples.Any(
            example => example.Lineage.Origin == ExpertDatasetOrigin.OpenWeightTeacher);
        VerifiedExpertTeacherLineageAdmission? teacherLineageAdmission = null;
        if (containsOpenWeightTeacher)
        {
            if (string.IsNullOrWhiteSpace(teacherLineageAdmissionPath) ||
                teacherLineageAdmissionTrust is null)
            {
                throw new CoordinatorValidationException(
                    "OpenWeightTeacher SFT export requires a separately authenticated teacher-lineage admission.");
            }
            teacherLineageAdmission = await ExpertModelTeacherLineageAdmissionTools.LoadAndVerifyAsync(
                teacherLineageAdmissionPath,
                sourceCorpusSha256,
                datasetSizeBytes,
                dataset.Examples,
                teacherLineageAdmissionTrust,
                TimeProvider.System,
                cancellationToken).ConfigureAwait(false);
        }
        else if (teacherLineageAdmissionPath is not null || teacherLineageAdmissionTrust is not null)
        {
            throw new CoordinatorValidationException(
                "A teacher-lineage admission must not be supplied for a dataset without OpenWeightTeacher rows.");
        }

        var unsignedMetadata = dataset.Examples.ToDictionary(
            example => example.Id,
            example => CreateUnsignedSftMetadata(example, sourceCorpusSha256),
            StringComparer.Ordinal);
        var receiptSubjects = dataset.Examples.Select(example =>
            new ExpertDatasetReviewReceiptSubject(
                example,
                ExpertModelDatasetReviewReceiptTools.ComputeCanonicalJsonSha256(
                    unsignedMetadata[example.Id]))).ToArray();
        var receipts = await ExpertModelDatasetReviewReceiptTools.LoadAndVerifyAsync(
            receiptSetPath,
            sourceCorpusSha256,
            receiptSubjects,
            receiptTrust,
            teacherLineageAdmission,
            TimeProvider.System,
            cancellationToken).ConfigureAwait(false);

        if (requireProviderUploadRights)
        {
            foreach (var example in dataset.Examples)
            {
                var receipt = receipts[example.Id];
                if (IsTrainingEligible(example, receipt, requireProviderUploadRights: false) &&
                    !IsTrainingEligible(example, receipt, requireProviderUploadRights: true))
                {
                    throw new CoordinatorValidationException(
                        $"Training example '{example.Id}' lacks provider-upload rights; no SFT file was written.");
                }
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(fullOutputPath)!);
        if (File.Exists(fullOutputPath))
        {
            throw new CoordinatorValidationException("SFT output already exists; no file was replaced.");
        }
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
                await using var writer = new StreamWriter(outputStream, StrictUtf8)
                {
                    NewLine = "\n"
                };

                foreach (var example in dataset.Examples)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var receipt = receipts[example.Id];
                    if (!IsTrainingEligible(example, receipt, requireProviderUploadRights))
                    {
                        continue;
                    }

                    var metadata = unsignedMetadata[example.Id];
                    var row = new
                    {
                        messages = example.Messages.Select(message => new
                        {
                            role = message.Role,
                            content = message.Content
                        }).ToArray(),
                        metadata
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

            var publicationTime = TimeProvider.System.GetUtcNow();
            if (receipts.Values.Any(receipt => publicationTime >= receipt.ExpiresAtUtc) ||
                teacherLineageAdmission is not null &&
                (publicationTime < teacherLineageAdmission.NotBeforeUtc ||
                 publicationTime >= teacherLineageAdmission.ExpiresAtUtc))
            {
                throw new CoordinatorValidationException(
                    "Authenticated review authority expired before SFT publication; no file was written.");
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

        return exported;
    }

    internal static ExpertSftUnsignedMetadata CreateUnsignedSftMetadata(
        ExpertModelDatasetExample example,
        string sourceCorpusSha256) =>
        new(
            ExpertModelDatasetReviewReceiptTools.SftMetadataSchemaVersion,
            sourceCorpusSha256,
            example.Verification.EvidenceSha256,
            example.Id,
            example.TaskKind.ToString(),
            example.Domains.Select(domain => domain.ToString()).ToArray(),
            example.ConversationSha256,
            example.Lineage.Origin.ToString(),
            example.Lineage.Producer,
            example.Lineage.ModelId,
            example.Lineage.ModelRevision,
            example.Lineage.PromptSha256,
            example.Lineage.ProfileVersion,
            example.Split,
            example.ContaminationGroup,
            ExpertModelDatasetReviewReceiptTools.CanonicalSftCutoffUtc(example.CutoffUtc),
            example.SchemaVersion);

    private static async Task<byte[]> ReadBoundedDatasetBytesAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        ExpertModelDatasetReviewReceiptTools.RejectReparsePathComponents(
            fullPath,
            "Expert-model dataset");
        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var length = stream.Length;
        if (length > MaxDatasetBytes)
        {
            throw new CoordinatorValidationException(
                $"Dataset exceeds the {MaxDatasetBytes:N0}-byte input limit.");
        }
        var bytes = new byte[checked((int)length)];
        try
        {
            await stream.ReadExactlyAsync(bytes.AsMemory(), cancellationToken).ConfigureAwait(false);
            var trailing = new byte[1];
            if (await stream.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw new CoordinatorValidationException("Expert-model dataset changed while it was read.");
            }
            return bytes;
        }
        catch (EndOfStreamException exception)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new CoordinatorValidationException(
                $"Expert-model dataset changed while it was read: {exception.Message}");
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    internal static async Task<LoadedExpertDataset> LoadAndValidateAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            Path.GetFullPath(path),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await LoadAndValidateStreamAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<LoadedExpertDataset> LoadAndValidateBytesAsync(
        byte[] bytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        using var stream = new MemoryStream(bytes, writable: false);
        return await LoadAndValidateStreamAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<LoadedExpertDataset> LoadAndValidateStreamAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var issues = new List<DatasetValidationIssue>();
        var examples = new List<(int Line, ExpertModelDatasetExample Example)>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var contentSplits = new Dictionary<string, (string Split, string Id)>(StringComparer.Ordinal);
        var groupSplits = new Dictionary<string, (string Split, string Id)>(StringComparer.Ordinal);

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
                throw new CoordinatorValidationException(
                    $"Expert-model dataset must be valid UTF-8: {exception.Message}");
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

            ExpertModelDatasetExample? example;
            try
            {
                using var document = JsonDocument.Parse(line);
                ValidateJsonShape(document.RootElement);
                example = JsonSerializer.Deserialize<ExpertModelDatasetExample>(line, CoordinatorJson.Options);
            }
            catch (Exception exception) when (exception is JsonException or CoordinatorValidationException)
            {
                issues.Add(new DatasetValidationIssue(
                    lineNumber,
                    null,
                    $"Invalid expert-model dataset row: {exception.Message}"));
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

            if (example.Messages is not null &&
                example.Messages.All(message => message is not null && message.Role is not null && message.Content is not null))
            {
                var contentHash = ComputeConversationSha256(example.Messages);
                if (contentSplits.TryGetValue(contentHash, out var priorContent) &&
                    priorContent.Split != example.Split)
                {
                    issues.Add(new DatasetValidationIssue(
                        lineNumber,
                        example.Id,
                        $"Exact message content duplicates '{priorContent.Id}' across " +
                        $"'{priorContent.Split}' and '{example.Split}'."));
                }
                else
                {
                    contentSplits[contentHash] = (example.Split, example.Id);
                }
            }

            if (!string.IsNullOrWhiteSpace(example.ContaminationGroup) &&
                groupSplits.TryGetValue(example.ContaminationGroup, out var priorGroup) &&
                priorGroup.Split != example.Split)
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
        }

        var trainingEligible = examples.Count(item =>
            IsTrainingEligible(
                item.Example,
                receipt: null,
                requireProviderUploadRights: false));
        return new LoadedExpertDataset(
            new DatasetValidationReport(examples.Count, trainingEligible, issues),
            examples.Select(item => item.Example).ToArray());
    }

    private static void ValidateExample(
        int line,
        ExpertModelDatasetExample example,
        ICollection<DatasetValidationIssue> issues)
    {
        void Add(string message) => issues.Add(new DatasetValidationIssue(line, example.Id, message));

        void Require(string? value, string field, int maxCharacters)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                Add($"{field} is required.");
            }
            else if (value.Length > maxCharacters)
            {
                Add($"{field} exceeds {maxCharacters:N0} characters.");
            }
        }

        Require(example.Id, nameof(example.Id), 200);
        Require(example.ContaminationGroup, nameof(example.ContaminationGroup), 200);
        Require(example.Provenance, nameof(example.Provenance), 2_000);
        Require(example.License, nameof(example.License), 500);
        Require(example.ReviewStatus, nameof(example.ReviewStatus), 100);
        if (!IsSafeId(example.Id))
        {
            Add("Example ID contains unsupported characters.");
        }
        if (!IsSafeId(example.ContaminationGroup))
        {
            Add("Contamination group contains unsupported characters.");
        }
        if (example.SchemaVersion != CoordinatorVersions.ExpertModelDatasetSchema)
        {
            Add("Unsupported expert-model dataset schema version.");
        }
        if (!AllowedSplits.Contains(example.Split))
        {
            Add("Split must be development, calibration, or sealed.");
        }
        if (!AllowedReviewStatuses.Contains(example.ReviewStatus))
        {
            Add("Review status must be draft, pending, approved, or rejected.");
        }
        if (example.CutoffUtc == default || example.CutoffUtc > DateTimeOffset.UtcNow)
        {
            Add("cutoffUtc must be set and not be in the future.");
        }
        if (example.Domains is null || example.Domains.Count == 0)
        {
            Add("At least one expert domain is required.");
        }
        else
        {
            if (example.Domains.Count > Enum.GetValues<ExpertDomain>().Length)
            {
                Add("Domain labels exceed the supported-domain count.");
            }
            if (example.Domains.Distinct().Count() != example.Domains.Count)
            {
                Add("Domain labels must not be duplicated.");
            }
        }

        if (example.Messages is null)
        {
            Add("Messages are required.");
        }
        else
        {
            ValidateMessages(example, line, issues);
            if (!IsSha256(example.ConversationSha256))
            {
                Add("conversationSha256 must be a lowercase SHA-256 value.");
            }
            else if (example.Messages.All(message =>
                         message is not null && message.Role is not null && message.Content is not null) &&
                     !StringComparer.Ordinal.Equals(
                         example.ConversationSha256,
                         ComputeConversationSha256(example.Messages)))
            {
                Add("conversationSha256 does not match the canonical message content.");
            }
        }

        if (example.Sources is null || example.Rights is null ||
            example.Lineage is null || example.Verification is null)
        {
            Add("Sources, rights, lineage, and verification are required.");
            return;
        }

        if (!example.Rights.MayStore || !example.Rights.MayEvaluate)
        {
            Add("Example lacks storage/evaluation rights.");
        }
        if (example.UseForTraining && !example.Rights.MayTrain)
        {
            Add("Training is requested but the example lacks training rights.");
        }
        if (example.UseForTraining && example.Split != "development")
        {
            Add("Only development examples may be used for training; calibration and sealed examples never train.");
        }
        if (example.UseForTraining &&
            example.ReviewStatus != "approved")
        {
            Add("Training examples must have approved review status.");
        }
        if (example.UseForTraining && !example.Verification.Verified)
        {
            Add("Training examples must be verified.");
        }
        var candidateStable = example.Verification.Evidence.Contains(
            CandidateStableKnowledgeClass,
            StringComparer.Ordinal);
        var retrievalOnly = example.Verification.Evidence.Contains(
            RetrievalOnlyKnowledgeClass,
            StringComparer.Ordinal);
        if (candidateStable && retrievalOnly)
        {
            Add("Verification evidence must declare only one knowledgeClass.");
        }
        if (example.UseForTraining && !candidateStable)
        {
            Add("Training examples must declare knowledgeClass=candidate-stable in verification evidence.");
        }
        if (retrievalOnly &&
            (example.UseForTraining ||
             example.Rights.MayTrain ||
             example.Sources.Any(source => source?.Rights?.MayTrain == true)))
        {
            Add("Retrieval-only examples must not request or declare training rights.");
        }

        ValidateLineage(example, line, issues);
        ValidateVerification(example, line, issues);
        ValidateSources(example, line, issues);
    }

    private static void ValidateLineage(
        ExpertModelDatasetExample example,
        int line,
        ICollection<DatasetValidationIssue> issues)
    {
        void Add(string message) => issues.Add(new DatasetValidationIssue(line, example.Id, message));
        var lineage = example.Lineage;
        if (string.IsNullOrWhiteSpace(lineage.Producer) || lineage.Producer.Length > 500)
        {
            Add("Lineage producer is required and must not exceed 500 characters.");
        }
        if (lineage.ProducedAtUtc == default || lineage.ProducedAtUtc > DateTimeOffset.UtcNow)
        {
            Add("lineage producedAtUtc must be set and not be in the future.");
        }

        var modelGenerated = lineage.Origin is not ExpertDatasetOrigin.HumanAuthored;
        if (!modelGenerated)
        {
            if (lineage.ModelId is not null || lineage.ModelRevision is not null ||
                lineage.PromptSha256 is not null || lineage.ProfileVersion is not null)
            {
                Add("Human-authored lineage must not claim model or prompt identity.");
            }
            return;
        }

        if (string.IsNullOrWhiteSpace(lineage.ModelId) || lineage.ModelId.Length > 500)
        {
            Add("Model-generated lineage requires a model ID of at most 500 characters.");
        }
        if (string.IsNullOrWhiteSpace(lineage.ModelRevision) || lineage.ModelRevision.Length > 500)
        {
            Add("Model-generated lineage requires a pinned model revision of at most 500 characters.");
        }
        else if (lineage.Origin == ExpertDatasetOrigin.OpenWeightTeacher &&
                 !IsLowercaseHex(lineage.ModelRevision, 40))
        {
            Add("Open-weight teacher lineage requires an exact lowercase 40-character source commit.");
        }
        else if (IsMutableRevisionLabel(lineage.ModelRevision))
        {
            Add("Model-generated lineage must not use a mutable or placeholder revision label.");
        }
        if (!IsSha256(lineage.PromptSha256))
        {
            Add("Model-generated lineage requires a lowercase prompt SHA-256 value.");
        }
        if (string.IsNullOrWhiteSpace(lineage.ProfileVersion) || lineage.ProfileVersion.Length > 500)
        {
            Add("Model-generated lineage requires a prompt/profile version of at most 500 characters.");
        }
    }

    private static void ValidateMessages(
        ExpertModelDatasetExample example,
        int line,
        ICollection<DatasetValidationIssue> issues)
    {
        void Add(string message) => issues.Add(new DatasetValidationIssue(line, example.Id, message));

        if (example.Messages.Count > MaxMessageCount)
        {
            Add($"Messages exceed the {MaxMessageCount}-message limit.");
        }
        if (example.Messages.Count == 0)
        {
            Add("At least one user/assistant message pair is required.");
            return;
        }

        long aggregateCharacters = 0;
        for (var index = 0; index < example.Messages.Count; index++)
        {
            var message = example.Messages[index];
            if (message is null)
            {
                Add($"Message {index + 1} must not be null.");
                continue;
            }
            if (message.Role is not ("system" or "user" or "assistant"))
            {
                Add($"Message {index + 1} role must be system, user, or assistant.");
            }
            if (string.IsNullOrWhiteSpace(message.Content))
            {
                Add($"Message {index + 1} content is required.");
            }
            else if (message.Content.Length > MaxMessageCharacters)
            {
                Add($"Message {index + 1} exceeds {MaxMessageCharacters:N0} characters.");
            }
            aggregateCharacters += message.Content?.Length ?? 0;
        }
        if (aggregateCharacters > MaxAggregateMessageCharacters)
        {
            Add($"Message content exceeds the {MaxAggregateMessageCharacters:N0}-character aggregate limit.");
        }

        var conversationStart = example.Messages[0]?.Role == "system" ? 1 : 0;
        if (example.Messages.Count - conversationStart < 2)
        {
            Add("Messages must contain a user prompt followed by an assistant answer.");
        }

        var expectedRole = "user";
        for (var index = conversationStart; index < example.Messages.Count; index++)
        {
            var actualRole = example.Messages[index]?.Role;
            if (actualRole != expectedRole)
            {
                Add($"Message {index + 1} must have role '{expectedRole}' to preserve chat ordering.");
            }
            expectedRole = expectedRole == "user" ? "assistant" : "user";
        }
        if (example.Messages[^1]?.Role != "assistant")
        {
            Add("The final message must have role 'assistant'.");
        }
    }

    private static void ValidateVerification(
        ExpertModelDatasetExample example,
        int line,
        ICollection<DatasetValidationIssue> issues)
    {
        void Add(string message) => issues.Add(new DatasetValidationIssue(line, example.Id, message));
        var verification = example.Verification;

        if (string.IsNullOrWhiteSpace(verification.Reviewer) || verification.Reviewer.Length > 500)
        {
            Add("Verification reviewer is required and must not exceed 500 characters.");
        }
        if (verification.Verified &&
            (verification.VerifiedAtUtc is null ||
             verification.VerifiedAtUtc.Value == default ||
             verification.VerifiedAtUtc.Value > DateTimeOffset.UtcNow))
        {
            Add("Verified evidence requires verifiedAtUtc to be set and not be in the future.");
        }
        if (verification.VerifiedAtUtc is { } verifiedAtUtc &&
            verifiedAtUtc < example.Lineage.ProducedAtUtc)
        {
            Add("Verification verifiedAtUtc must not precede lineage production.");
        }
        if (!verification.Verified && verification.VerifiedAtUtc is not null)
        {
            Add("Unverified evidence must not set verifiedAtUtc.");
        }
        if (!IsSha256(verification.EvidenceSha256))
        {
            Add("Verification evidenceSha256 must be a lowercase SHA-256 value.");
        }
        if (verification.Evidence is null ||
            verification.CompileEvidence is null ||
            verification.TestEvidence is null)
        {
            Add("Verification, compile, and test evidence arrays must not be null.");
            return;
        }

        ValidateEvidenceList(verification.Evidence, "Verification", line, example.Id, issues);
        ValidateEvidenceList(verification.CompileEvidence, "Compile", line, example.Id, issues);
        ValidateEvidenceList(verification.TestEvidence, "Test", line, example.Id, issues);
        if (IsSha256(verification.EvidenceSha256) &&
            verification.Evidence.All(item => item is not null) &&
            verification.CompileEvidence.All(item => item is not null) &&
            verification.TestEvidence.All(item => item is not null) &&
            !StringComparer.Ordinal.Equals(
                verification.EvidenceSha256,
                ComputeVerificationEvidenceSha256(
                    verification.Evidence,
                    verification.CompileEvidence,
                    verification.TestEvidence)))
        {
            Add("Verification evidenceSha256 does not match the canonical evidence content.");
        }
        if (verification.Evidence.Count == 0)
        {
            Add("Verification evidence must contain at least one entry.");
        }
        if (verification.CompileSucceeded && verification.CompileEvidence.Count == 0)
        {
            Add("Successful compilation requires compile evidence.");
        }
        if (verification.TestsPassed && verification.TestEvidence.Count == 0)
        {
            Add("Passing tests require test evidence.");
        }

        var codeEvidenceRequired = IsCodeRelated(example.TaskKind) &&
            (example.UseForTraining ||
             example.ReviewStatus == "approved");
        if (codeEvidenceRequired)
        {
            if (!verification.Verified)
            {
                Add("Code-related examples must be verified.");
            }
            if (!verification.CompileSucceeded || verification.CompileEvidence.Count == 0)
            {
                Add("Code-related examples require successful compile verification and evidence.");
            }
            if (!verification.TestsPassed || verification.TestEvidence.Count == 0)
            {
                Add("Code-related examples require successful test verification and evidence.");
            }
            if (verification.CompileSucceeded && verification.TestsPassed)
            {
                ValidateExecutableCodeEvidence(example, Add);
            }
        }
    }

    private static void ValidateExecutableCodeEvidence(
        ExpertModelDatasetExample example,
        Action<string> add)
    {
        if (example.TaskKind == ExpertTaskKind.CodeReview)
        {
            add("Code-review examples do not have a supported executable verifier profile.");
            return;
        }

        var compile = example.Verification.CompileEvidence;
        var tests = example.Verification.TestEvidence;
        if (compile.Count != 4 ||
            !TryReadEvidence(compile, 0, "profile", out var profile) ||
            !TryReadEvidence(compile, 1, "sourceSha256", out var sourceSha256) ||
            !TryReadEvidence(compile, 2, "compilerClosureSha256", out var compilerClosureSha256) ||
            !TryReadEvidence(compile, 3, "canonicalProgramSha256", out var canonicalProgramSha256))
        {
            add("Code-related compile evidence must use the exact executable-verifier evidence shape.");
            return;
        }
        var expectedSourceSha256 = Convert.ToHexString(
            SHA256.HashData(StrictUtf8.GetBytes(example.Messages[^1].Content))).ToLowerInvariant();
        if (profile != ExpertModelDatasetReviewTools.DaxqExecutableProfile ||
            !StringComparer.Ordinal.Equals(sourceSha256, expectedSourceSha256) ||
            !IsSha256(compilerClosureSha256) ||
            !IsSha256(canonicalProgramSha256))
        {
            add("Code-related compile evidence does not bind the supported profile, exact source, and compiler program.");
        }

        if (tests.Count != 5 ||
            !TryReadEvidence(tests, 0, "testSpecificationSha256", out var testSpecificationSha256) ||
            !TryReadEvidence(tests, 1, "executionTraceSha256", out var executionTraceSha256) ||
            !TryReadEvidence(tests, 2, "executableResultSha256", out var executableResultSha256) ||
            !TryReadEvidence(tests, 3, "vectorCount", out var vectorCountText) ||
            !TryReadEvidence(tests, 4, "callbackCount", out var callbackCountText))
        {
            add("Code-related test evidence must use the exact executable-verifier evidence shape.");
            return;
        }
        if (!IsSha256(testSpecificationSha256) ||
            !IsSha256(executionTraceSha256) ||
            !IsSha256(executableResultSha256) ||
            !TryParseCanonicalPositiveInt(vectorCountText, out var vectorCount) ||
            vectorCount is < 1 or > ExpertModelDatasetReviewTools.MaxExecutableVectorsPerExample ||
            !TryParseCanonicalPositiveInt(callbackCountText, out var callbackCount) ||
            callbackCount is < 1 or > ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerExample)
        {
            add("Code-related test evidence contains invalid hashes or execution counts.");
        }
    }

    private static bool TryParseCanonicalPositiveInt(string value, out int parsed) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out parsed) &&
        parsed > 0 &&
        StringComparer.Ordinal.Equals(value, parsed.ToString(CultureInfo.InvariantCulture));

    private static bool TryReadEvidence(
        IReadOnlyList<string> evidence,
        int index,
        string key,
        out string value)
    {
        var prefix = string.Concat(key, "=");
        var item = evidence[index];
        if (!item.StartsWith(prefix, StringComparison.Ordinal) || item.Length == prefix.Length)
        {
            value = string.Empty;
            return false;
        }
        value = item[prefix.Length..];
        return true;
    }

    private static void ValidateSources(
        ExpertModelDatasetExample example,
        int line,
        ICollection<DatasetValidationIssue> issues)
    {
        void Add(string message) => issues.Add(new DatasetValidationIssue(line, example.Id, message));

        if (example.Sources.Count > MaxSourceCount)
        {
            Add($"Sources exceed the {MaxSourceCount}-source limit.");
        }

        long aggregateCharacters = 0;
        var sourceIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in example.Sources)
        {
            if (source is null)
            {
                Add("Source entries must not be null.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(source.Id) || !IsSafeId(source.Id) || source.Id.Length > 200)
            {
                Add("Source IDs are required, must be safe, and must not exceed 200 characters.");
            }
            if (!sourceIds.Add(source.Id))
            {
                Add($"Duplicate source ID '{source.Id}'.");
            }
            if (string.IsNullOrWhiteSpace(source.Title) || source.Title.Length > 500)
            {
                Add($"Source '{source.Id}' title is required and must not exceed 500 characters.");
            }
            if (string.IsNullOrWhiteSpace(source.Content) || source.Content.Length > MaxSourceCharacters)
            {
                Add($"Source '{source.Id}' content is required and must not exceed {MaxSourceCharacters:N0} characters.");
            }
            aggregateCharacters += source.Content?.Length ?? 0;
            if (string.IsNullOrWhiteSpace(source.Provenance) || source.Provenance.Length > 2_000)
            {
                Add($"Source '{source.Id}' provenance is required and must not exceed 2,000 characters.");
            }
            if (string.IsNullOrWhiteSpace(source.License) || source.License.Length > 500)
            {
                Add($"Source '{source.Id}' license is required and must not exceed 500 characters.");
            }
            if (source.Uri?.Length > 2_048)
            {
                Add($"Source '{source.Id}' URI exceeds 2,048 characters.");
            }
            if (source.RetrievedAtUtc == default || source.RetrievedAtUtc > DateTimeOffset.UtcNow)
            {
                Add($"Source '{source.Id}' retrieval time must be set and not be in the future.");
            }
            if (source.AvailableAtUtc > example.CutoffUtc)
            {
                Add($"Source '{source.Id}' was unavailable at the task cutoff.");
            }
            if (example.Split is "calibration" or "sealed" && source.AvailableAtUtc is null)
            {
                Add($"Source '{source.Id}' requires availableAtUtc in calibration or sealed data.");
            }
            if (source.Rights is null)
            {
                Add($"Source '{source.Id}' rights are required.");
                continue;
            }
            if (!source.Rights.MayStore || !source.Rights.MayEvaluate)
            {
                Add($"Source '{source.Id}' lacks storage/evaluation rights.");
            }
            if (example.UseForTraining && !source.Rights.MayTrain)
            {
                Add($"Source '{source.Id}' lacks training rights.");
            }
        }

        if (aggregateCharacters > MaxAggregateSourceCharacters)
        {
            Add($"Source content exceeds the {MaxAggregateSourceCharacters:N0}-character aggregate limit.");
        }
    }

    private static void ValidateEvidenceList(
        IReadOnlyList<string> evidence,
        string name,
        int line,
        string? exampleId,
        ICollection<DatasetValidationIssue> issues)
    {
        if (evidence.Count > MaxEvidenceItems)
        {
            issues.Add(new DatasetValidationIssue(
                line,
                exampleId,
                $"{name} evidence exceeds the {MaxEvidenceItems}-item limit."));
        }
        for (var index = 0; index < evidence.Count; index++)
        {
            if (string.IsNullOrWhiteSpace(evidence[index]) || evidence[index].Length > MaxEvidenceCharacters)
            {
                issues.Add(new DatasetValidationIssue(
                    line,
                    exampleId,
                    $"{name} evidence entry {index + 1} is required and must not exceed " +
                    $"{MaxEvidenceCharacters:N0} characters."));
            }
        }
    }

    private static void ValidateJsonShape(JsonElement root)
    {
        RequireExactObjectProperties(
            root,
            "expert-model dataset example",
            "schemaVersion",
            "id",
            "taskKind",
            "domains",
            "messages",
            "conversationSha256",
            "sources",
            "lineage",
            "verification",
            "split",
            "contaminationGroup",
            "provenance",
            "license",
            "rights",
            "reviewStatus",
            "cutoffUtc",
            "useForTraining");
        RequireArray(root, "domains");
        RequireArray(root, "messages");
        RequireArray(root, "sources");
        ValidateRightsShape(root.GetProperty("rights"), "example rights");

        foreach (var message in root.GetProperty("messages").EnumerateArray())
        {
            RequireExactObjectProperties(message, "message", "role", "content");
        }
        foreach (var source in root.GetProperty("sources").EnumerateArray())
        {
            RequireExactObjectProperties(
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

        var lineage = root.GetProperty("lineage");
        RequireExactObjectProperties(
            lineage,
            "expert-model lineage",
            "origin",
            "producer",
            "modelId",
            "modelRevision",
            "promptSha256",
            "profileVersion",
            "producedAtUtc");

        var verification = root.GetProperty("verification");
        RequireExactObjectProperties(
            verification,
            "verification evidence",
            "verified",
            "reviewer",
            "verifiedAtUtc",
            "evidenceSha256",
            "evidence",
            "compileSucceeded",
            "compileEvidence",
            "testsPassed",
            "testEvidence");
        RequireArray(verification, "evidence");
        RequireArray(verification, "compileEvidence");
        RequireArray(verification, "testEvidence");
        RequireBoolean(verification, "verified", "verification evidence");
        RequireBoolean(verification, "compileSucceeded", "verification evidence");
        RequireBoolean(verification, "testsPassed", "verification evidence");
        RequireBoolean(root, "useForTraining", "expert-model dataset example");
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
        RequireExactObjectProperties(rights, name, properties);
        foreach (var propertyName in properties)
        {
            RequireBoolean(rights, propertyName, name);
        }
    }

    private static void RequireArray(JsonElement parent, string propertyName)
    {
        if (parent.GetProperty(propertyName).ValueKind != JsonValueKind.Array)
        {
            throw new CoordinatorValidationException($"'{propertyName}' must be an array.");
        }
    }

    private static void RequireBoolean(JsonElement parent, string propertyName, string name)
    {
        if (parent.GetProperty(propertyName).ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new CoordinatorValidationException($"{name} '{propertyName}' must be a boolean.");
        }
    }

    private static void RequireExactObjectProperties(
        JsonElement element,
        string name,
        params string[] properties)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new CoordinatorValidationException($"{name} must be a JSON object.");
        }

        var expected = properties.ToHashSet(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                throw new CoordinatorValidationException(
                    $"{name} contains duplicate property '{property.Name}'.");
            }
            if (!expected.Contains(property.Name))
            {
                throw new CoordinatorValidationException(
                    $"{name} contains unsupported property '{property.Name}'.");
            }
        }
        foreach (var property in properties)
        {
            if (!seen.Contains(property))
            {
                throw new CoordinatorValidationException(
                    $"{name} is missing required property '{property}'.");
            }
        }
    }

    private static bool IsTrainingEligible(
        ExpertModelDatasetExample example,
        ExpertDatasetReviewReceiptIdentity? receipt,
        bool requireProviderUploadRights) =>
        example.UseForTraining &&
        example.Split == "development" &&
        example.ReviewStatus == "approved" &&
        example.Verification is not null &&
        example.Verification.Verified &&
        example.Verification.Evidence.Contains(CandidateStableKnowledgeClass, StringComparer.Ordinal) &&
        receipt is { TrainingAuthorized: true } &&
        (!requireProviderUploadRights || receipt.ProviderUploadAuthorized) &&
        example.Sources is not null &&
        example.Rights is not null &&
        example.Rights.MayStore &&
        example.Rights.MayEvaluate &&
        example.Rights.MayTrain &&
        (!requireProviderUploadRights || example.Rights.MayUploadToProvider) &&
        example.Sources.All(source => source?.Rights is not null &&
            source.Rights.MayStore &&
            source.Rights.MayEvaluate &&
            source.Rights.MayTrain &&
            (!requireProviderUploadRights || source.Rights.MayUploadToProvider));

    private static bool IsCodeRelated(ExpertTaskKind taskKind) =>
        taskKind is ExpertTaskKind.CodeGeneration or ExpertTaskKind.CodeRepair or ExpertTaskKind.CodeReview;

    private static bool IsSafeId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || !IsAsciiLetterOrDigit(value[0]))
        {
            return false;
        }
        return value.All(character =>
            IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':');
    }

    private static bool IsAsciiLetterOrDigit(char character) =>
        character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9';

    private static bool IsSha256(string? value) =>
        IsLowercaseHex(value, 64);

    private static bool IsLowercaseHex(string? value, int length) =>
        value is not null && value.Length == length &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsMutableRevisionLabel(string value) =>
        value.Equals("main", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("master", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("latest", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("trunk", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("REPLACE_", StringComparison.OrdinalIgnoreCase);

    private static string HashLengthPrefixedUtf8(
        string domain,
        params IReadOnlyList<string>[] groups)
    {
        using var stream = new MemoryStream();
        WriteLengthPrefixedUtf8(stream, domain);
        WriteInt32BigEndian(stream, groups.Length);
        foreach (var group in groups)
        {
            ArgumentNullException.ThrowIfNull(group);
            WriteInt32BigEndian(stream, group.Count);
            foreach (var value in group)
            {
                ArgumentNullException.ThrowIfNull(value);
                WriteLengthPrefixedUtf8(stream, value);
            }
        }
        return ContentHasher.HashBytes(stream.GetBuffer().AsSpan(0, checked((int)stream.Length)));
    }

    private static void WriteLengthPrefixedUtf8(Stream stream, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteInt32BigEndian(stream, bytes.Length);
        stream.Write(bytes);
    }

    private static void WriteInt32BigEndian(Stream stream, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    internal sealed record LoadedExpertDataset(
        DatasetValidationReport Report,
        IReadOnlyList<ExpertModelDatasetExample> Examples);
}
