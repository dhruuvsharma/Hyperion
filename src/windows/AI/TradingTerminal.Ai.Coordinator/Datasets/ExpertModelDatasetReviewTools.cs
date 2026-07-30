using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

public sealed record ExpertDatasetVerificationManifest
{
    public required string SchemaVersion { get; init; }
    public required string DatasetSha256 { get; init; }
    public IReadOnlyList<ExpertDatasetVerifierAssignment> Verifiers { get; init; } = [];
}

public sealed record ExpertDatasetVerifierAssignment
{
    public required string ExampleId { get; init; }
    public required string VerifierId { get; init; }
    public IReadOnlyList<ExpertDatasetTextCheck> Checks { get; init; } = [];
    public ExpertDatasetExecutableVerificationSpec? ExecutableVerification { get; init; }
}

public sealed record ExpertDatasetTextCheck
{
    public required string Id { get; init; }
    public required string Kind { get; init; }
    public required string Value { get; init; }
    public bool IgnoreCase { get; init; }
}

public sealed record ExpertDatasetCheckResult(
    string Id,
    string Kind,
    string ExpectedSha256,
    bool Passed);

public sealed record ExpertDatasetExecutableVerificationSpec
{
    public required string Profile { get; init; }
    public IReadOnlyList<ExpertDatasetNumericTestVector> Vectors { get; init; } = [];
}

public sealed record ExpertDatasetNumericTestVector
{
    public required string Id { get; init; }
    public IReadOnlyList<ExpertDatasetNumericBar> Bars { get; init; } = [];
    public IReadOnlyList<double> Parameters { get; init; } = [];
    public ulong LaunchSeed { get; init; }
    public ExpertDatasetExpectedEffects? Initialization { get; init; }
    public IReadOnlyList<ExpertDatasetNumericCallback> Callbacks { get; init; } = [];
    public double MaximumAbsoluteDifference { get; init; }
}

public sealed record ExpertDatasetNumericBar(
    double Open,
    double High,
    double Low,
    double Close,
    double Volume);

public sealed record ExpertDatasetNumericCallback
{
    public required string Entrypoint { get; init; }
    public long TimeIndex { get; init; }
    public int CompletedBarIndex { get; init; }
    public double Bid { get; init; }
    public double Ask { get; init; }
    public double Last { get; init; }
    public double Volume { get; init; }
    public required ExpertDatasetExpectedEffects Expected { get; init; }
}

public sealed record ExpertDatasetExpectedEffects
{
    public IReadOnlyList<ExpertDatasetExpectedSignal> Signals { get; init; } = [];
    public IReadOnlyList<ExpertDatasetExpectedLog> Logs { get; init; } = [];
}

public sealed record ExpertDatasetExpectedSignal(long Kind, double Strength, long NoteId);

public sealed record ExpertDatasetExpectedLog(long MessageId, double Value);

public sealed record ExpertDatasetExecutableResult
{
    public required string Profile { get; init; }
    public required string SourceSha256 { get; init; }
    public required string CompilerClosureSha256 { get; init; }
    public required string TestSpecificationSha256 { get; init; }
    public string? CanonicalProgramSha256 { get; init; }
    public string? ExecutionTraceSha256 { get; init; }
    public bool CompileSucceeded { get; init; }
    public bool TestsPassed { get; init; }
    public int VectorCount { get; init; }
    public int CallbackCount { get; init; }
    public IReadOnlyList<string> DiagnosticCodes { get; init; } = [];
}

public sealed record ExpertDatasetVerificationResult(
    string ExampleId,
    string AssistantSha256,
    string VerifierId,
    string VerifierSha256,
    bool Supported,
    bool Passed,
    IReadOnlyList<ExpertDatasetCheckResult> Checks)
{
    public ExpertDatasetExecutableResult? Executable { get; init; }
    public string? UnsupportedReason { get; init; }
}

public sealed record ExpertDatasetVerificationReport
{
    public required string SchemaVersion { get; init; }
    public required string DatasetSha256 { get; init; }
    public required string VerificationManifestSha256 { get; init; }
    public int ExampleCount { get; init; }
    public bool AllPassed { get; init; }
    public IReadOnlyList<ExpertDatasetVerificationResult> Results { get; init; } = [];
    public required string ReportSha256 { get; init; }
}

public sealed record ExpertDatasetReviewManifest
{
    public required string SchemaVersion { get; init; }
    public required string DatasetSha256 { get; init; }
    public required string VerificationManifestSha256 { get; init; }
    public required string VerificationReportSha256 { get; init; }
    public required string Reviewer { get; init; }
    public required string ReviewBasis { get; init; }
    public required DateTimeOffset ReviewedAtUtc { get; init; }
    public IReadOnlyList<ExpertDatasetReviewDecision> Decisions { get; init; } = [];
}

public sealed record ExpertDatasetReviewDecision
{
    public required string ExampleId { get; init; }
    public required string Decision { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

public sealed record ExpertDatasetReviewApplyResult(
    int ExampleCount,
    int ApprovedCount,
    int RejectedCount,
    int TrainingEligibleCount,
    string OutputSha256);

internal interface IExpertDatasetExecutableVerifier
{
    Task<ExpertDatasetExecutableResult> VerifyAsync(
        ExpertModelDatasetExample example,
        ExpertDatasetVerifierAssignment assignment,
        CancellationToken cancellationToken);
}

public static partial class ExpertModelDatasetReviewTools
{
    public const string VerificationManifestSchemaVersion =
        "daxalgo.expert-model-dataset-verification-manifest/v1";
    public const string VerificationReportSchemaVersion =
        "daxalgo.expert-model-dataset-verification-report/v2";
    public const string ReviewManifestSchemaVersion =
        "daxalgo.expert-model-dataset-review-manifest/v1";
    public const long MaxManifestBytes = 5_000_000;
    public const long MaxVerificationReportBytes = 5_000_000;
    public const int MaxChecksPerExample = 64;
    public const int MaxCheckValueCharacters = 100_000;
    public const int MaxDecisionEvidenceItems = 32;
    public const string DaxqExecutableProfile = "daxq-sdk-abi3-source/v1";
    public const int MaxExecutableVectorsPerExample = 16;
    public const int MaxExecutableBarsPerVector = 4_096;
    public const int MaxExecutableCallbacksPerVector = 512;
    public const int MaxExecutableCallbacksPerExample = 512;
    public const int MaxExecutableParametersPerVector = 256;
    public const int MaxExecutableDiagnostics = 32;
    public const int MaxExecutableSourceCharacters = 262_144;

    private const string ZeroSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    private static readonly HashSet<string> CheckKinds =
        new(["contains", "not-contains", "equals", "sha256"], StringComparer.Ordinal);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifierRegex();

    public static Task<ExpertDatasetVerificationReport> VerifyAsync(
        string datasetPath,
        string verificationManifestPath,
        string outputReportPath,
        CancellationToken cancellationToken = default) =>
        VerifyCoreAsync(
            datasetPath,
            verificationManifestPath,
            outputReportPath,
            executableVerifier: null,
            cancellationToken);

    internal static Task<ExpertDatasetVerificationReport> VerifyWithExecutableVerifierAsync(
        string datasetPath,
        string verificationManifestPath,
        string outputReportPath,
        IExpertDatasetExecutableVerifier executableVerifier,
        CancellationToken cancellationToken = default) =>
        VerifyCoreAsync(
            datasetPath,
            verificationManifestPath,
            outputReportPath,
            executableVerifier,
            cancellationToken);

    private static async Task<ExpertDatasetVerificationReport> VerifyCoreAsync(
        string datasetPath,
        string verificationManifestPath,
        string outputReportPath,
        IExpertDatasetExecutableVerifier? executableVerifier,
        CancellationToken cancellationToken)
    {
        var context = await BuildVerificationContextAsync(
            datasetPath,
            verificationManifestPath,
            executableVerifier,
            cancellationToken).ConfigureAwait(false);
        await WriteJsonNoClobberAsync(
            outputReportPath,
            context.Report,
            "Verification report",
            MaxVerificationReportBytes,
            cancellationToken).ConfigureAwait(false);
        return context.Report;
    }

    public static Task<ExpertDatasetReviewApplyResult> ApplyReviewAsync(
        string datasetPath,
        string verificationManifestPath,
        string verificationReportPath,
        string reviewManifestPath,
        string outputDatasetPath,
        CancellationToken cancellationToken = default) =>
        ApplyReviewCoreAsync(
            datasetPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            outputDatasetPath,
            executableVerifier: null,
            cancellationToken);

    internal static Task<ExpertDatasetReviewApplyResult> ApplyReviewWithExecutableVerifierAsync(
        string datasetPath,
        string verificationManifestPath,
        string verificationReportPath,
        string reviewManifestPath,
        string outputDatasetPath,
        IExpertDatasetExecutableVerifier executableVerifier,
        CancellationToken cancellationToken = default) =>
        ApplyReviewCoreAsync(
            datasetPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            outputDatasetPath,
            executableVerifier,
            cancellationToken);

    private static async Task<ExpertDatasetReviewApplyResult> ApplyReviewCoreAsync(
        string datasetPath,
        string verificationManifestPath,
        string verificationReportPath,
        string reviewManifestPath,
        string outputDatasetPath,
        IExpertDatasetExecutableVerifier? executableVerifier,
        CancellationToken cancellationToken)
    {
        EnsureDistinctPaths(
            outputDatasetPath,
            datasetPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath);

        var context = await BuildVerificationContextAsync(
            datasetPath,
            verificationManifestPath,
            executableVerifier,
            cancellationToken).ConfigureAwait(false);
        var suppliedReport = await ReadJsonAsync<ExpertDatasetVerificationReport>(
            verificationReportPath,
            "Verification report",
            MaxVerificationReportBytes,
            cancellationToken).ConfigureAwait(false);
        ValidateVerificationReport(suppliedReport);
        if (!SerializeCompact(suppliedReport).AsSpan().SequenceEqual(SerializeCompact(context.Report)))
        {
            throw new CoordinatorValidationException(
                "Verification report does not exactly match a fresh execution against the bound dataset and manifest.");
        }

        var reviewBytes = await ReadBoundedBytesAsync(
            reviewManifestPath,
            MaxManifestBytes,
            "Review manifest",
            cancellationToken).ConfigureAwait(false);
        var review = DeserializeJson<ExpertDatasetReviewManifest>(reviewBytes, "Review manifest");
        var reviewManifestSha256 = Sha256Hex(reviewBytes);
        var decisions = ValidateReviewManifest(review, context);
        var verificationResults = context.Report.Results.ToDictionary(
            item => item.ExampleId,
            StringComparer.Ordinal);

        var reviewed = new List<ExpertModelDatasetExample>(context.Dataset.Examples.Count);
        var approvedCount = 0;
        var rejectedCount = 0;
        foreach (var example in context.Dataset.Examples)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var decision = decisions[example.Id];
            var result = verificationResults[example.Id];
            var approved = decision.Decision == "approved";
            if (approved)
            {
                approvedCount++;
            }
            else
            {
                rejectedCount++;
            }

            var evidence = example.Verification.Evidence.ToList();
            evidence.Add($"verificationManifestSha256={context.Report.VerificationManifestSha256}");
            evidence.Add($"verificationReportSha256={context.Report.ReportSha256}");
            evidence.Add($"reviewManifestSha256={reviewManifestSha256}");
            evidence.Add($"verifierId={result.VerifierId}");
            evidence.Add($"automatedChecksPassed={result.Passed.ToString().ToLowerInvariant()}");
            evidence.Add($"reviewBasisSha256={Sha256Hex(StrictUtf8.GetBytes(review.ReviewBasis))}");
            evidence.AddRange(decision.Evidence);
            if (evidence.Count > ExpertModelDatasetTools.MaxEvidenceItems)
            {
                throw new CoordinatorValidationException(
                    $"Review decision for '{example.Id}' exceeds the dataset evidence-item limit.");
            }

            IReadOnlyList<string> compileEvidence = example.Verification.CompileEvidence;
            IReadOnlyList<string> testEvidence = example.Verification.TestEvidence;
            var compileSucceeded = example.Verification.CompileSucceeded;
            var testsPassed = example.Verification.TestsPassed;
            if (IsCodeRelated(example.TaskKind))
            {
                compileEvidence = [];
                testEvidence = [];
                compileSucceeded = false;
                testsPassed = false;
                if (approved && result.Executable is { } executable)
                {
                    compileEvidence = BuildCompileEvidence(executable);
                    testEvidence = BuildTestEvidence(executable);
                    compileSucceeded = executable.CompileSucceeded;
                    testsPassed = executable.TestsPassed;
                }
            }

            var verification = example.Verification with
            {
                Verified = approved,
                Reviewer = review.Reviewer,
                VerifiedAtUtc = approved ? review.ReviewedAtUtc : null,
                Evidence = evidence,
                CompileSucceeded = compileSucceeded,
                CompileEvidence = compileEvidence,
                TestsPassed = testsPassed,
                TestEvidence = testEvidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    evidence,
                    compileEvidence,
                    testEvidence)
            };
            reviewed.Add(example with
            {
                Verification = verification,
                ReviewStatus = decision.Decision,
                UseForTraining = false
            });
        }

        var outputBytes = SerializeDataset(reviewed);
        var output = await ExpertModelDatasetTools.LoadAndValidateBytesAsync(
            outputBytes,
            cancellationToken).ConfigureAwait(false);
        if (!output.Report.IsValid)
        {
            throw new CoordinatorValidationException(
                "Reviewed dataset failed canonical validation; no output was written. " +
                DescribeIssues(output.Report));
        }
        if (output.Report.TrainingEligibleCount != 0)
        {
            throw new CoordinatorValidationException(
                "Review must not make rows training-eligible; no output was written.");
        }
        await WriteBytesNoClobberAsync(
            outputDatasetPath,
            outputBytes,
            "Reviewed dataset",
            cancellationToken).ConfigureAwait(false);
        return new ExpertDatasetReviewApplyResult(
            output.Report.ExampleCount,
            approvedCount,
            rejectedCount,
            output.Report.TrainingEligibleCount,
            Sha256Hex(outputBytes));
    }

    private static async Task<VerificationContext> BuildVerificationContextAsync(
        string datasetPath,
        string verificationManifestPath,
        IExpertDatasetExecutableVerifier? executableVerifier,
        CancellationToken cancellationToken)
    {
        var datasetBytes = await ReadBoundedBytesAsync(
            datasetPath,
            ExpertModelDatasetTools.MaxDatasetBytes,
            "Expert-model dataset",
            cancellationToken).ConfigureAwait(false);
        var datasetSha256 = Sha256Hex(datasetBytes);
        var dataset = await ExpertModelDatasetTools.LoadAndValidateBytesAsync(
            datasetBytes,
            cancellationToken).ConfigureAwait(false);
        if (!dataset.Report.IsValid)
        {
            throw new CoordinatorValidationException(
                "Expert-model dataset must be valid before verification. " +
                DescribeIssues(dataset.Report));
        }
        if (dataset.Examples.Count == 0)
        {
            throw new CoordinatorValidationException(
                "Expert-model dataset must contain at least one example for verification.");
        }

        var manifestBytes = await ReadBoundedBytesAsync(
            verificationManifestPath,
            MaxManifestBytes,
            "Verification manifest",
            cancellationToken).ConfigureAwait(false);
        var manifest = DeserializeJson<ExpertDatasetVerificationManifest>(
            manifestBytes,
            "Verification manifest");
        ValidateVerificationManifest(manifest, datasetSha256, dataset.Examples);
        var manifestSha256 = Sha256Hex(manifestBytes);
        var assignments = manifest.Verifiers.ToDictionary(item => item.ExampleId, StringComparer.Ordinal);

        var results = new List<ExpertDatasetVerificationResult>(dataset.Examples.Count);
        foreach (var example in dataset.Examples)
        {
            cancellationToken.ThrowIfCancellationRequested();
            results.Add(await EvaluateAsync(
                example,
                assignments[example.Id],
                executableVerifier,
                cancellationToken).ConfigureAwait(false));
        }
        var report = new ExpertDatasetVerificationReport
        {
            SchemaVersion = VerificationReportSchemaVersion,
            DatasetSha256 = datasetSha256,
            VerificationManifestSha256 = manifestSha256,
            ExampleCount = results.Count,
            AllPassed = results.All(result => result.Passed),
            Results = results,
            ReportSha256 = ZeroSha256
        };
        report = report with { ReportSha256 = ComputeReportSha256(report) };
        ValidateVerificationReport(report);
        return new VerificationContext(dataset, manifest, report);
    }

    private static async Task<ExpertDatasetVerificationResult> EvaluateAsync(
        ExpertModelDatasetExample example,
        ExpertDatasetVerifierAssignment assignment,
        IExpertDatasetExecutableVerifier? executableVerifier,
        CancellationToken cancellationToken)
    {
        var assistant = example.Messages[^1].Content;
        var assistantSha256 = Sha256Hex(StrictUtf8.GetBytes(assistant));
        var comparison = StringComparison.Ordinal;
        var checkResults = assignment.Checks.Select(check =>
        {
            comparison = check.IgnoreCase
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            var passed = check.Kind switch
            {
                "contains" => assistant.Contains(check.Value, comparison),
                "not-contains" => !assistant.Contains(check.Value, comparison),
                "equals" => string.Equals(assistant, check.Value, comparison),
                "sha256" => StringComparer.Ordinal.Equals(assistantSha256, check.Value),
                _ => false
            };
            return new ExpertDatasetCheckResult(
                check.Id,
                check.Kind,
                Sha256Hex(StrictUtf8.GetBytes(check.Value)),
                passed);
        }).ToArray();
        ExpertDatasetExecutableResult? executable = null;
        if (assignment.ExecutableVerification is not null)
        {
            if (executableVerifier is null)
            {
                throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' requires the trusted executable-verifier worker.");
            }
            executable = await executableVerifier.VerifyAsync(
                example,
                assignment,
                cancellationToken).ConfigureAwait(false)
                ?? throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' returned no executable result.");
            ValidateExecutableResult(example, assignment, executable);
        }

        var supported = !IsCodeRelated(example.TaskKind) || executable is not null;
        return new ExpertDatasetVerificationResult(
            example.Id,
            assistantSha256,
            assignment.VerifierId,
            Sha256Hex(SerializeCompact(assignment)),
            supported,
            supported && checkResults.All(check => check.Passed) &&
            (executable is null || executable.CompileSucceeded && executable.TestsPassed),
            checkResults)
        {
            Executable = executable,
            UnsupportedReason = supported ? null : "missing-supported-executable-profile"
        };
    }

    private static void ValidateVerificationManifest(
        ExpertDatasetVerificationManifest manifest,
        string datasetSha256,
        IReadOnlyList<ExpertModelDatasetExample> examples)
    {
        if (manifest.SchemaVersion != VerificationManifestSchemaVersion)
        {
            throw new CoordinatorValidationException("Unsupported verification-manifest schema version.");
        }
        RequireSha256(manifest.DatasetSha256, "Verification manifest datasetSha256");
        if (!StringComparer.Ordinal.Equals(manifest.DatasetSha256, datasetSha256))
        {
            throw new CoordinatorValidationException(
                "Verification manifest datasetSha256 does not match the exact dataset bytes.");
        }
        if (manifest.Verifiers is null || manifest.Verifiers.Count != examples.Count)
        {
            throw new CoordinatorValidationException(
                "Verification manifest must contain exactly one verifier for every dataset example.");
        }

        var examplesById = examples.ToDictionary(example => example.Id, StringComparer.Ordinal);
        var verifierIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var assignment in manifest.Verifiers)
        {
            if (assignment is null)
            {
                throw new CoordinatorValidationException("Verification assignments must not contain null entries.");
            }
            if (!examplesById.TryGetValue(assignment.ExampleId, out var example) ||
                !verifierIds.Add(assignment.ExampleId))
            {
                throw new CoordinatorValidationException(
                    $"Verification assignment '{assignment.ExampleId}' is missing, duplicated, or not in the dataset.");
            }
            RequireIdentifier(assignment.VerifierId, $"Verifier ID for '{assignment.ExampleId}'");
            if (assignment.Checks is null || assignment.Checks.Count is < 1 or > MaxChecksPerExample)
            {
                throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' must contain 1 to {MaxChecksPerExample} checks.");
            }
            var checkIds = new HashSet<string>(StringComparer.Ordinal);
            var hasPositiveCheck = false;
            foreach (var check in assignment.Checks)
            {
                if (check is null)
                {
                    throw new CoordinatorValidationException(
                        $"Verifier '{assignment.VerifierId}' must not contain null checks.");
                }
                RequireIdentifier(check.Id, $"Check ID in verifier '{assignment.VerifierId}'");
                if (!checkIds.Add(check.Id))
                {
                    throw new CoordinatorValidationException(
                        $"Verifier '{assignment.VerifierId}' contains duplicate check ID '{check.Id}'.");
                }
                if (!CheckKinds.Contains(check.Kind))
                {
                    throw new CoordinatorValidationException(
                        $"Verifier '{assignment.VerifierId}' check '{check.Id}' has an unsupported kind.");
                }
                if (string.IsNullOrWhiteSpace(check.Value) || check.Value.Length > MaxCheckValueCharacters)
                {
                    throw new CoordinatorValidationException(
                        $"Verifier '{assignment.VerifierId}' check '{check.Id}' has an invalid value length.");
                }
                if (check.Kind == "sha256")
                {
                    RequireSha256(check.Value, $"Verifier '{assignment.VerifierId}' check '{check.Id}' value");
                    if (check.IgnoreCase)
                    {
                        throw new CoordinatorValidationException("SHA-256 checks cannot ignore case.");
                    }
                }
                hasPositiveCheck |= check.Kind != "not-contains";
            }
            if (!hasPositiveCheck)
            {
                throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' must contain at least one positive check.");
            }
            if (assignment.ExecutableVerification is not null)
            {
                ValidateExecutableSpecification(example, assignment);
            }
        }
    }

    private static Dictionary<string, ExpertDatasetReviewDecision> ValidateReviewManifest(
        ExpertDatasetReviewManifest review,
        VerificationContext context)
    {
        if (review.SchemaVersion != ReviewManifestSchemaVersion)
        {
            throw new CoordinatorValidationException("Unsupported review-manifest schema version.");
        }
        foreach (var (value, name) in new[]
                 {
                     (review.DatasetSha256, "datasetSha256"),
                     (review.VerificationManifestSha256, "verificationManifestSha256"),
                     (review.VerificationReportSha256, "verificationReportSha256")
                 })
        {
            RequireSha256(value, $"Review manifest {name}");
        }
        if (!StringComparer.Ordinal.Equals(review.DatasetSha256, context.Report.DatasetSha256) ||
            !StringComparer.Ordinal.Equals(
                review.VerificationManifestSha256,
                context.Report.VerificationManifestSha256) ||
            !StringComparer.Ordinal.Equals(
                review.VerificationReportSha256,
                context.Report.ReportSha256))
        {
            throw new CoordinatorValidationException(
                "Review manifest does not bind the exact dataset, verification manifest, and verification report.");
        }
        RequireIdentifier(review.Reviewer, "Review manifest reviewer");
        if (string.IsNullOrWhiteSpace(review.ReviewBasis) ||
            review.ReviewBasis.Length > ExpertModelDatasetTools.MaxEvidenceCharacters)
        {
            throw new CoordinatorValidationException(
                "Review manifest reviewBasis is required and must fit the dataset evidence limit.");
        }
        if (review.ReviewedAtUtc == default || review.ReviewedAtUtc > DateTimeOffset.UtcNow)
        {
            throw new CoordinatorValidationException(
                "Review manifest reviewedAtUtc must be set and not be in the future.");
        }
        if (context.Dataset.Examples.Any(example =>
                review.ReviewedAtUtc < example.Lineage.ProducedAtUtc))
        {
            throw new CoordinatorValidationException(
                "Review manifest reviewedAtUtc must not precede any bound example's production time.");
        }
        if (review.Decisions is null || review.Decisions.Count != context.Dataset.Examples.Count)
        {
            throw new CoordinatorValidationException(
                "Review manifest must contain exactly one decision for every dataset example.");
        }

        var results = context.Report.Results.ToDictionary(item => item.ExampleId, StringComparer.Ordinal);
        var examples = context.Dataset.Examples.ToDictionary(item => item.Id, StringComparer.Ordinal);
        var decisions = new Dictionary<string, ExpertDatasetReviewDecision>(StringComparer.Ordinal);
        foreach (var decision in review.Decisions)
        {
            if (decision is null || !examples.TryGetValue(decision.ExampleId, out var example) ||
                !decisions.TryAdd(decision.ExampleId, decision))
            {
                throw new CoordinatorValidationException(
                    "Review decisions contain a null, duplicate, or unknown example ID.");
            }
            if (decision.Decision is not ("approved" or "rejected"))
            {
                throw new CoordinatorValidationException(
                    $"Review decision for '{decision.ExampleId}' must be approved or rejected.");
            }
            if (decision.Evidence is null ||
                decision.Evidence.Count is < 1 or > MaxDecisionEvidenceItems ||
                decision.Evidence.Any(item =>
                    string.IsNullOrWhiteSpace(item) ||
                    item.Length > ExpertModelDatasetTools.MaxEvidenceCharacters))
            {
                throw new CoordinatorValidationException(
                    $"Review decision for '{decision.ExampleId}' requires bounded non-empty evidence.");
            }
            if (example.UseForTraining ||
                !new[] { "draft", "pending" }.Contains(example.ReviewStatus, StringComparer.OrdinalIgnoreCase))
            {
                throw new CoordinatorValidationException(
                    $"Review decision for '{decision.ExampleId}' can only be applied to a non-training draft or pending row.");
            }
            if (decision.Decision == "approved" && !results[decision.ExampleId].Passed)
            {
                throw new CoordinatorValidationException(
                    $"Review decision for '{decision.ExampleId}' cannot approve failed automated checks.");
            }
            if (decision.Decision == "approved" && IsCodeRelated(example.TaskKind))
            {
                var executable = results[decision.ExampleId].Executable;
                if (example.TaskKind == ExpertTaskKind.CodeReview ||
                    executable is null ||
                    executable.Profile != DaxqExecutableProfile ||
                    !executable.CompileSucceeded ||
                    !executable.TestsPassed)
                {
                    throw new CoordinatorValidationException(
                        $"Review decision for '{decision.ExampleId}' cannot approve this code-related output without a passing supported executable compile/test verifier.");
                }
            }
        }
        return decisions;
    }

    private static void ValidateVerificationReport(ExpertDatasetVerificationReport report)
    {
        if (report.SchemaVersion != VerificationReportSchemaVersion)
        {
            throw new CoordinatorValidationException("Unsupported verification-report schema version.");
        }
        RequireSha256(report.DatasetSha256, "Verification report datasetSha256");
        RequireSha256(
            report.VerificationManifestSha256,
            "Verification report verificationManifestSha256");
        RequireSha256(report.ReportSha256, "Verification report reportSha256");
        if (report.Results is null ||
            report.ExampleCount is < 1 or > ExpertModelDatasetTools.MaxDatasetExamples ||
            report.ExampleCount != report.Results.Count)
        {
            throw new CoordinatorValidationException(
                "Verification report exampleCount does not match its results.");
        }
        var exampleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var result in report.Results)
        {
            if (result is null)
            {
                throw new CoordinatorValidationException(
                    "Verification report must not contain null results.");
            }
            RequireIdentifier(result.ExampleId, "Verification report exampleId");
            RequireIdentifier(result.VerifierId, "Verification report verifierId");
            RequireSha256(result.AssistantSha256, "Verification report assistantSha256");
            RequireSha256(result.VerifierSha256, "Verification report verifierSha256");
            if (!exampleIds.Add(result.ExampleId))
            {
                throw new CoordinatorValidationException(
                    "Verification report contains duplicate example IDs.");
            }
            if (result.Checks is null || result.Checks.Count is < 1 or > MaxChecksPerExample)
            {
                throw new CoordinatorValidationException(
                    "Verification report result has an invalid check count.");
            }
            var checkIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (var check in result.Checks)
            {
                if (check is null)
                {
                    throw new CoordinatorValidationException(
                        "Verification report must not contain null check results.");
                }
                RequireIdentifier(check.Id, "Verification report check ID");
                RequireSha256(check.ExpectedSha256, "Verification report expectedSha256");
                if (!CheckKinds.Contains(check.Kind) || !checkIds.Add(check.Id))
                {
                    throw new CoordinatorValidationException(
                        "Verification report contains an unsupported or duplicate check.");
                }
            }
            if (result.Executable is not null)
            {
                ValidateExecutableResultShape(result.Executable);
            }
            if (result.Supported != (result.UnsupportedReason is null) ||
                (!result.Supported &&
                 (result.Executable is not null ||
                  !SafeIdentifierRegex().IsMatch(result.UnsupportedReason!))))
            {
                throw new CoordinatorValidationException(
                    "Verification report result support state is invalid.");
            }
            var expectedPassed = result.Supported && result.Checks.All(check => check.Passed) &&
                (result.Executable is null ||
                 result.Executable.CompileSucceeded && result.Executable.TestsPassed);
            if (result.Passed != expectedPassed)
            {
                throw new CoordinatorValidationException(
                    "Verification report result pass state does not match its checks and executable result.");
            }
        }
        if (report.AllPassed != report.Results.All(result => result.Passed))
        {
            throw new CoordinatorValidationException(
                "Verification report allPassed does not match its results.");
        }
        if (!StringComparer.Ordinal.Equals(report.ReportSha256, ComputeReportSha256(report)))
        {
            throw new CoordinatorValidationException(
                "Verification report reportSha256 does not match its canonical content.");
        }
    }

    private static void ValidateExecutableSpecification(
        ExpertModelDatasetExample example,
        ExpertDatasetVerifierAssignment assignment)
    {
        var specification = assignment.ExecutableVerification!;
        var source = example.Messages[^1].Content;
        if (example.TaskKind is not (ExpertTaskKind.CodeGeneration or ExpertTaskKind.CodeRepair) ||
            !example.Domains.Contains(ExpertDomain.CSharp))
        {
            throw new CoordinatorValidationException(
                $"Verifier '{assignment.VerifierId}' can execute only C# CodeGeneration or CodeRepair rows.");
        }
        if (specification.Profile != DaxqExecutableProfile)
        {
            throw new CoordinatorValidationException(
                $"Verifier '{assignment.VerifierId}' uses an unsupported executable profile.");
        }
        if (specification.Vectors is null ||
            specification.Vectors.Count is < 1 or > MaxExecutableVectorsPerExample)
        {
            throw new CoordinatorValidationException(
                $"Verifier '{assignment.VerifierId}' requires 1 to {MaxExecutableVectorsPerExample} executable vectors.");
        }
        if (source.Length > MaxExecutableSourceCharacters)
        {
            throw new CoordinatorValidationException(
                $"Verifier '{assignment.VerifierId}' source exceeds the {MaxExecutableSourceCharacters:N0}-character executable bound.");
        }

        var vectorIds = new HashSet<string>(StringComparer.Ordinal);
        var totalCallbackCount = 0;
        foreach (var vector in specification.Vectors)
        {
            if (vector is null)
            {
                throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' must not contain null executable vectors.");
            }
            RequireIdentifier(vector.Id, $"Executable vector ID in verifier '{assignment.VerifierId}'");
            if (!vectorIds.Add(vector.Id))
            {
                throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' contains duplicate executable vector ID '{vector.Id}'.");
            }
            if (vector.Bars is null || vector.Bars.Count > MaxExecutableBarsPerVector ||
                vector.Parameters is null || vector.Parameters.Count > MaxExecutableParametersPerVector ||
                vector.Callbacks is null ||
                vector.Callbacks.Count is < 1 or > MaxExecutableCallbacksPerVector)
            {
                throw new CoordinatorValidationException(
                    $"Executable vector '{vector.Id}' exceeds a bars, parameters, or callbacks bound.");
            }
            totalCallbackCount = checked(totalCallbackCount + vector.Callbacks.Count);
            if (totalCallbackCount > MaxExecutableCallbacksPerExample)
            {
                throw new CoordinatorValidationException(
                    $"Verifier '{assignment.VerifierId}' exceeds the {MaxExecutableCallbacksPerExample:N0}-callback executable bound.");
            }
            if (!double.IsFinite(vector.MaximumAbsoluteDifference) ||
                vector.MaximumAbsoluteDifference is < 0d or > 1e-9d)
            {
                throw new CoordinatorValidationException(
                    $"Executable vector '{vector.Id}' tolerance must be finite and no greater than 1e-9.");
            }
            if (vector.Parameters.Any(value => !double.IsFinite(value)))
            {
                throw new CoordinatorValidationException(
                    $"Executable vector '{vector.Id}' parameters must be finite.");
            }
            foreach (var bar in vector.Bars)
            {
                if (bar is null ||
                    !double.IsFinite(bar.Open) || !double.IsFinite(bar.High) ||
                    !double.IsFinite(bar.Low) || !double.IsFinite(bar.Close) ||
                    !double.IsFinite(bar.Volume) || bar.Volume < 0d ||
                    bar.High < Math.Max(Math.Max(bar.Open, bar.Close), bar.Low) ||
                    bar.Low > Math.Min(Math.Min(bar.Open, bar.Close), bar.High))
                {
                    throw new CoordinatorValidationException(
                        $"Executable vector '{vector.Id}' contains an invalid OHLCV bar.");
                }
            }

            var expectedEffectCount = ValidateExpectedEffects(
                vector.Initialization,
                vector.Id,
                allowNull: true);
            long previousTimeIndex = -1;
            var previousBarIndex = -1;
            var previousOnBarIndex = -1;
            foreach (var callback in vector.Callbacks)
            {
                if (callback is null || callback.Entrypoint is not ("bar" or "tick") ||
                    callback.TimeIndex < 0 || callback.TimeIndex < previousTimeIndex ||
                    callback.CompletedBarIndex is < -1 || callback.CompletedBarIndex >= vector.Bars.Count ||
                    callback.CompletedBarIndex < previousBarIndex ||
                    callback.CompletedBarIndex > callback.TimeIndex)
                {
                    throw new CoordinatorValidationException(
                        $"Executable vector '{vector.Id}' contains an invalid or unordered callback.");
                }
                previousTimeIndex = callback.TimeIndex;
                previousBarIndex = callback.CompletedBarIndex;
                if (callback.Entrypoint == "bar")
                {
                    if (callback.CompletedBarIndex < 0 ||
                        callback.TimeIndex != callback.CompletedBarIndex ||
                        callback.CompletedBarIndex <= previousOnBarIndex ||
                        callback.Bid != 0d || callback.Ask != 0d ||
                        callback.Last != 0d || callback.Volume != 0d)
                    {
                        throw new CoordinatorValidationException(
                            $"Executable vector '{vector.Id}' bar callbacks must use a completed bar and zero tick inputs.");
                    }
                    previousOnBarIndex = callback.CompletedBarIndex;
                }
                else if (!double.IsFinite(callback.Bid) || !double.IsFinite(callback.Ask) ||
                         !double.IsFinite(callback.Last) || !double.IsFinite(callback.Volume) ||
                         callback.Bid < 0d || callback.Ask < callback.Bid || callback.Last < 0d ||
                         callback.Volume < 0d)
                {
                    throw new CoordinatorValidationException(
                        $"Executable vector '{vector.Id}' contains invalid tick inputs.");
                }
                expectedEffectCount += ValidateExpectedEffects(
                    callback.Expected,
                    vector.Id,
                    allowNull: false);
            }
            if (expectedEffectCount == 0)
            {
                throw new CoordinatorValidationException(
                    $"Executable vector '{vector.Id}' must assert at least one signal or log effect.");
            }
        }
    }

    private static int ValidateExpectedEffects(
        ExpertDatasetExpectedEffects? effects,
        string vectorId,
        bool allowNull)
    {
        if (effects is null)
        {
            if (allowNull)
            {
                return 0;
            }
            throw new CoordinatorValidationException(
                $"Executable vector '{vectorId}' callback expected effects are required.");
        }
        if (effects.Signals is null || effects.Signals.Count > 8 ||
            effects.Logs is null || effects.Logs.Count > 16)
        {
            throw new CoordinatorValidationException(
                $"Executable vector '{vectorId}' exceeds the signal or log effect bound.");
        }
        foreach (var signal in effects.Signals)
        {
            if (signal is null || signal.Kind is < -1 or > 1 || signal.NoteId < 0 ||
                !double.IsFinite(signal.Strength) || signal.Strength is < 0d or > 1d)
            {
                throw new CoordinatorValidationException(
                    $"Executable vector '{vectorId}' contains an invalid expected signal.");
            }
        }
        foreach (var log in effects.Logs)
        {
            if (log is null || log.MessageId < 0 || !double.IsFinite(log.Value))
            {
                throw new CoordinatorValidationException(
                    $"Executable vector '{vectorId}' contains an invalid expected log.");
            }
        }
        return effects.Signals.Count + effects.Logs.Count;
    }

    private static void ValidateExecutableResult(
        ExpertModelDatasetExample example,
        ExpertDatasetVerifierAssignment assignment,
        ExpertDatasetExecutableResult result)
    {
        ValidateExecutableResultShape(result);
        var specification = assignment.ExecutableVerification
            ?? throw new CoordinatorValidationException("Executable result has no bound specification.");
        var expectedSourceSha256 = Sha256Hex(StrictUtf8.GetBytes(example.Messages[^1].Content));
        var expectedTestSpecificationSha256 = Sha256Hex(SerializeCompact(specification));
        if (result.Profile != specification.Profile ||
            !StringComparer.Ordinal.Equals(result.SourceSha256, expectedSourceSha256) ||
            !StringComparer.Ordinal.Equals(
                result.TestSpecificationSha256,
                expectedTestSpecificationSha256) ||
            result.VectorCount != specification.Vectors.Count ||
            result.CallbackCount != specification.Vectors.Sum(vector => vector.Callbacks.Count))
        {
            throw new CoordinatorValidationException(
                $"Executable result for '{example.Id}' does not bind its exact source and test specification.");
        }
    }

    private static void ValidateExecutableResultShape(ExpertDatasetExecutableResult result)
    {
        if (result.Profile != DaxqExecutableProfile)
        {
            throw new CoordinatorValidationException("Executable result uses an unsupported profile.");
        }
        RequireSha256(result.SourceSha256, "Executable result sourceSha256");
        RequireSha256(result.CompilerClosureSha256, "Executable result compilerClosureSha256");
        RequireSha256(result.TestSpecificationSha256, "Executable result testSpecificationSha256");
        if (result.CompileSucceeded)
        {
            RequireSha256(result.CanonicalProgramSha256, "Executable result canonicalProgramSha256");
        }
        else if (result.CanonicalProgramSha256 is not null ||
                 result.ExecutionTraceSha256 is not null ||
                 result.TestsPassed)
        {
            throw new CoordinatorValidationException(
                "Failed executable compilation cannot claim a canonical program, execution trace, or passing tests.");
        }
        if (result.TestsPassed)
        {
            RequireSha256(result.ExecutionTraceSha256, "Executable result executionTraceSha256");
        }
        else if (result.ExecutionTraceSha256 is not null)
        {
            RequireSha256(result.ExecutionTraceSha256, "Executable result executionTraceSha256");
        }
        if (result.VectorCount is < 1 or > MaxExecutableVectorsPerExample ||
            result.CallbackCount is < 1 or > MaxExecutableCallbacksPerExample)
        {
            throw new CoordinatorValidationException("Executable result vector or callback count is invalid.");
        }
        if (result.DiagnosticCodes is null ||
            result.DiagnosticCodes.Count > MaxExecutableDiagnostics ||
            result.DiagnosticCodes.Any(code => !SafeIdentifierRegex().IsMatch(code)) ||
            result.DiagnosticCodes.Distinct(StringComparer.Ordinal).Count() != result.DiagnosticCodes.Count)
        {
            throw new CoordinatorValidationException("Executable result diagnostic codes are invalid.");
        }
        if (result.TestsPassed != (result.DiagnosticCodes.Count == 0))
        {
            throw new CoordinatorValidationException(
                "Executable result pass state does not match its diagnostic codes.");
        }
    }

    private static IReadOnlyList<string> BuildCompileEvidence(ExpertDatasetExecutableResult result) =>
    [
        $"profile={result.Profile}",
        $"sourceSha256={result.SourceSha256}",
        $"compilerClosureSha256={result.CompilerClosureSha256}",
        $"canonicalProgramSha256={result.CanonicalProgramSha256}"
    ];

    private static IReadOnlyList<string> BuildTestEvidence(ExpertDatasetExecutableResult result) =>
    [
        $"testSpecificationSha256={result.TestSpecificationSha256}",
        $"executionTraceSha256={result.ExecutionTraceSha256}",
        $"executableResultSha256={Sha256Hex(SerializeCompact(result))}",
        $"vectorCount={result.VectorCount}",
        $"callbackCount={result.CallbackCount}"
    ];

    private static async Task<T> ReadJsonAsync<T>(
        string path,
        string description,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedBytesAsync(
            path,
            maxBytes,
            description,
            cancellationToken).ConfigureAwait(false);
        return DeserializeJson<T>(bytes, description);
    }

    private static T DeserializeJson<T>(byte[] bytes, string description)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException($"{description} must be BOM-less UTF-8 JSON.");
        }
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException($"{description} must not be JSON null.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"{description} is invalid: {exception.Message}");
        }
    }

    private static async Task<byte[]> ReadBoundedBytesAsync(
        string path,
        long maxBytes,
        string description,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
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
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.Position != stream.Length)
        {
            throw new CoordinatorValidationException($"{description} changed while it was read.");
        }
        return bytes;
    }

    private static async Task WriteJsonNoClobberAsync<T>(
        string path,
        T value,
        string description,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, CoordinatorJson.Options);
        var withNewline = new byte[bytes.Length + 1];
        bytes.CopyTo(withNewline, 0);
        withNewline[^1] = (byte)'\n';
        if (withNewline.LongLength > maxBytes)
        {
            throw new CoordinatorValidationException(
                $"{description} exceeds the {maxBytes:N0}-byte output limit; no file was written.");
        }
        await WriteBytesNoClobberAsync(path, withNewline, description, cancellationToken)
            .ConfigureAwait(false);
    }

    private static byte[] SerializeDataset(IReadOnlyList<ExpertModelDatasetExample> examples)
    {
        using var buffer = new MemoryStream();
        foreach (var example in examples)
        {
            var line = SerializeCompact(example);
            if (line.Length + 1L > ExpertModelDatasetTools.MaxDatasetBytes - buffer.Length)
            {
                throw new CoordinatorValidationException(
                    $"Reviewed dataset exceeds the {ExpertModelDatasetTools.MaxDatasetBytes:N0}-byte output limit.");
            }
            buffer.Write(line);
            buffer.WriteByte((byte)'\n');
        }
        return buffer.ToArray();
    }

    private static async Task WriteBytesNoClobberAsync(
        string path,
        byte[] bytes,
        string description,
        CancellationToken cancellationToken)
    {
        var destination = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(destination)
            ?? throw new CoordinatorValidationException($"{description} path has no parent directory.");
        Directory.CreateDirectory(parent);
        if (File.Exists(destination))
        {
            throw new CoordinatorValidationException($"{description} already exists; no file was replaced.");
        }
        var temporary = Path.Combine(parent, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             64 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            File.Move(temporary, destination, overwrite: false);
        }
        finally
        {
            TryDelete(temporary);
        }
    }

    private static byte[] SerializeCompact<T>(T value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, CompactJson);

    private static string ComputeReportSha256(ExpertDatasetVerificationReport report) =>
        Sha256Hex(SerializeCompact(report with { ReportSha256 = ZeroSha256 }));

    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static void RequireSha256(string? value, string description)
    {
        if (value is null || value.Length != 64 ||
            value.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new CoordinatorValidationException($"{description} must be a lowercase SHA-256 value.");
        }
    }

    private static void RequireIdentifier(string? value, string description)
    {
        if (value is null || !SafeIdentifierRegex().IsMatch(value))
        {
            throw new CoordinatorValidationException($"{description} contains unsupported characters.");
        }
    }

    private static bool IsCodeRelated(ExpertTaskKind taskKind) => taskKind is
        ExpertTaskKind.CodeGeneration or ExpertTaskKind.CodeRepair or ExpertTaskKind.CodeReview;

    private static string DescribeIssues(DatasetValidationReport report) =>
        string.Join(
            " ",
            report.Issues.Take(5).Select(issue =>
                $"Line {issue.Line} ({issue.ExampleId ?? "?"}): {issue.Message}"));

    private static void EnsureDistinctPaths(string outputPath, params string[] inputPaths)
    {
        var output = Path.GetFullPath(outputPath);
        if (inputPaths.Any(input =>
                StringComparer.OrdinalIgnoreCase.Equals(output, Path.GetFullPath(input))))
        {
            throw new CoordinatorValidationException("Review output must not overwrite an input file.");
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Preserve the primary validation failure.
        }
        catch (UnauthorizedAccessException)
        {
            // Preserve the primary validation failure.
        }
    }

    private sealed record VerificationContext(
        ExpertModelDatasetTools.LoadedExpertDataset Dataset,
        ExpertDatasetVerificationManifest Manifest,
        ExpertDatasetVerificationReport Report);
}
