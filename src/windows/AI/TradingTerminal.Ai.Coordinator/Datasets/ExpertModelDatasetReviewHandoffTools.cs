using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

internal sealed record ExpertDatasetReviewHandoffEvidenceInput(string Id, string Path);

internal sealed record ExpertDatasetReviewHandoffPreparationResult(
    string PackageId,
    string PackageSha256,
    string ReviewedDatasetSha256,
    int RowCount,
    int EvidenceFileCount);

internal sealed record ExpertDatasetReviewHandoffDecisionTemplatePreparationResult(
    string PackageId,
    string PackageSha256,
    string ReviewedDatasetSha256,
    int RowCount,
    int SourceCount);

internal sealed record ExpertDatasetReviewHandoffDecisionCompilationResult(
    string DecisionId,
    string DecisionSha256,
    string PackageSha256,
    string ReviewedDatasetSha256,
    int RowCount,
    int SourceCount,
    int EvidenceFileCount);

internal sealed record ExpertDatasetReviewHandoffApplyResult(
    int ExampleCount,
    int RightsElevatedCount,
    int TrainingRequestedCount,
    int TrainingEligibleCount,
    string PackageSha256,
    string DecisionSha256,
    string OutputSha256);

internal sealed record ExpertDatasetIndependentReviewAuthority(
    bool ReceiptAuthority,
    bool TrainingEligibilityAuthority,
    bool ProviderUploadAuthority,
    bool SftExportAuthority,
    bool SigningKeyAuthority,
    bool ModelReleaseAuthority,
    bool EvaluationAuthority,
    bool PromotionAuthority,
    bool DeploymentAuthority,
    bool ExecutionAuthority);

internal sealed record ExpertDatasetIndependentReviewFile(
    string Id,
    string Path,
    string Purpose,
    long SizeBytes,
    string Sha256,
    string ContentBase64);

internal sealed record ExpertDatasetIndependentReviewRowInventory(
    string ExampleId,
    string DraftRowSha256,
    string ReviewedRowSha256,
    string ConversationSha256,
    string ReviewStatus,
    bool Verified,
    string Split,
    string KnowledgeClass,
    DatasetRights CurrentRights,
    bool UseForTraining,
    string VerificationEvidenceSha256,
    IReadOnlyList<string> VerificationEvidenceIdentities);

internal sealed record ExpertDatasetIndependentReviewSourceInventory(
    string ExampleId,
    string SourceId,
    string DraftSourceSha256,
    string ReviewedSourceSha256,
    string ContentSha256,
    DatasetRights CurrentRights);

internal sealed record ExpertDatasetIndependentReviewRowDecision(
    string ExampleId,
    DatasetRights Rights,
    bool UseForTraining,
    IReadOnlyList<string> EvidenceIds);

internal sealed record ExpertDatasetIndependentReviewSourceDecision(
    string ExampleId,
    string SourceId,
    DatasetRights Rights,
    IReadOnlyList<string> EvidenceIds);

internal sealed record ExpertDatasetIndependentReviewDecisionTemplate(
    string Reviewer,
    string ReviewBasis,
    DateTimeOffset? ReviewedAtUtc,
    IReadOnlyList<ExpertDatasetIndependentReviewRowDecision> Rows,
    IReadOnlyList<ExpertDatasetIndependentReviewSourceDecision> Sources);

internal sealed record ExpertDatasetIndependentReviewDecisionDraft(
    string SchemaVersion,
    string Status,
    ExpertDatasetIndependentReviewAuthority Authority,
    string PackageId,
    string PackageSha256,
    string ReviewedDatasetSha256,
    string Reviewer,
    string ReviewBasis,
    DateTimeOffset? ReviewedAtUtc,
    IReadOnlyList<ExpertDatasetIndependentReviewRowDecision> Rows,
    IReadOnlyList<ExpertDatasetIndependentReviewSourceDecision> Sources);

internal sealed record ExpertDatasetIndependentReviewPackage(
    string SchemaVersion,
    string PackageId,
    string Status,
    ExpertDatasetIndependentReviewAuthority Authority,
    string DraftDatasetSha256,
    string ReviewedDatasetSha256,
    IReadOnlyList<ExpertDatasetIndependentReviewFile> Files,
    IReadOnlyList<ExpertDatasetIndependentReviewRowInventory> Rows,
    IReadOnlyList<ExpertDatasetIndependentReviewSourceInventory> Sources,
    ExpertDatasetIndependentReviewDecisionTemplate DecisionTemplate);

internal sealed record ExpertDatasetIndependentReviewEvidenceFile(
    string Id,
    string FileName,
    long SizeBytes,
    string Sha256,
    string ContentBase64);

internal sealed record ExpertDatasetIndependentReviewDecision(
    string SchemaVersion,
    string DecisionId,
    string PackageId,
    string PackageSha256,
    string ReviewedDatasetSha256,
    ExpertDatasetIndependentReviewAuthority Authority,
    string Reviewer,
    string ReviewBasis,
    DateTimeOffset ReviewedAtUtc,
    IReadOnlyList<ExpertDatasetIndependentReviewEvidenceFile> EvidenceFiles,
    IReadOnlyList<ExpertDatasetIndependentReviewRowDecision> Rows,
    IReadOnlyList<ExpertDatasetIndependentReviewSourceDecision> Sources);

internal static class ExpertModelDatasetReviewHandoffTools
{
    internal const string PackageSchemaVersion =
        "daxalgo.expert-model-independent-review-package/v1";
    internal const string DecisionDraftSchemaVersion =
        "daxalgo.expert-model-independent-review-decision-draft/v1";
    internal const string DecisionSchemaVersion =
        "daxalgo.expert-model-independent-review-decision/v1";

    private const string PackageStatus = "unreviewed-handoff";
    private const string DecisionDraftStatus = "unsigned-non-authorizing";
    private const string ZeroSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    private const long MaxPackageBytes = 350_000_000;
    private const long MaxDecisionBytes = 75_000_000;
    private const long MaxEvidenceFileBytes = 10_000_000;
    private const long MaxAggregateEvidenceBytes = 50_000_000;
    private const int MaxEvidenceFiles = 32;
    private const string CandidateStable = "knowledgeClass=candidate-stable";
    private const string RetrievalOnly = "knowledgeClass=retrieval-only";

    private const string DraftFileId = "draft-dataset";
    private const string ReviewedFileId = "reviewed-dataset";
    private const string VerificationManifestFileId = "verification-manifest";
    private const string VerificationReportFileId = "verification-report";
    private const string ReviewManifestFileId = "review-manifest";
    private const string PackageEvidencePrefix = "evidence:";

    private static readonly string[] ReservedReviewAnchorPrefixes =
    [
        "reviewPackageSha256=",
        "reviewDecisionSha256=",
        "reviewEvidenceSha256:"
    ];

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions CanonicalJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };
    private static readonly ExpertDatasetIndependentReviewAuthority NoDownstreamAuthority = new(
        ReceiptAuthority: false,
        TrainingEligibilityAuthority: false,
        ProviderUploadAuthority: false,
        SftExportAuthority: false,
        SigningKeyAuthority: false,
        ModelReleaseAuthority: false,
        EvaluationAuthority: false,
        PromotionAuthority: false,
        DeploymentAuthority: false,
        ExecutionAuthority: false);

    internal static async Task<ExpertDatasetReviewHandoffPreparationResult> PrepareAsync(
        string draftDatasetPath,
        string reviewedDatasetPath,
        string verificationManifestPath,
        string verificationReportPath,
        string reviewManifestPath,
        IReadOnlyList<ExpertDatasetReviewHandoffEvidenceInput> evidenceFiles,
        string outputPackagePath,
        IExpertDatasetExecutableVerifier executableVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidenceFiles);
        ArgumentNullException.ThrowIfNull(executableVerifier);
        EnsureUniqueInputPaths(
            draftDatasetPath,
            reviewedDatasetPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            evidenceFiles.Select(item => item.Path));
        EnsureDistinctPaths(
            outputPackagePath,
            draftDatasetPath,
            reviewedDatasetPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            evidenceFiles.Select(item => item.Path));
        EnsureOutputAvailable(outputPackagePath, "Independent-review package");

        var draftBytes = await ReadBoundedBytesAsync(
            draftDatasetPath,
            ExpertModelDatasetTools.MaxDatasetBytes,
            "Draft dataset",
            cancellationToken).ConfigureAwait(false);
        var reviewedBytes = await ReadBoundedBytesAsync(
            reviewedDatasetPath,
            ExpertModelDatasetTools.MaxDatasetBytes,
            "Reviewed dataset",
            cancellationToken).ConfigureAwait(false);
        var verificationManifestBytes = await ReadBoundedBytesAsync(
            verificationManifestPath,
            ExpertModelDatasetReviewTools.MaxManifestBytes,
            "Verification manifest",
            cancellationToken).ConfigureAwait(false);
        var verificationReportBytes = await ReadBoundedBytesAsync(
            verificationReportPath,
            ExpertModelDatasetReviewTools.MaxVerificationReportBytes,
            "Verification report",
            cancellationToken).ConfigureAwait(false);
        var reviewManifestBytes = await ReadBoundedBytesAsync(
            reviewManifestPath,
            ExpertModelDatasetReviewTools.MaxManifestBytes,
            "Review manifest",
            cancellationToken).ConfigureAwait(false);
        var capturedEvidence = await CaptureEvidenceAsync(evidenceFiles, cancellationToken)
            .ConfigureAwait(false);

        var outputFullPath = Path.GetFullPath(outputPackagePath);
        var stagingDirectory = CreateStagingDirectory(outputFullPath, "prepare-review-handoff");
        ExpertDatasetIndependentReviewPackage package;
        byte[] packageBytes;
        try
        {
            var staged = await WriteReplayInputsAsync(
                stagingDirectory,
                draftBytes,
                verificationManifestBytes,
                verificationReportBytes,
                reviewManifestBytes,
                cancellationToken).ConfigureAwait(false);
            await ExpertModelDatasetReviewTools.ApplyReviewWithExecutableVerifierAsync(
                staged.DraftPath,
                staged.VerificationManifestPath,
                staged.VerificationReportPath,
                staged.ReviewManifestPath,
                staged.OutputPath,
                executableVerifier,
                cancellationToken).ConfigureAwait(false);
            var replayedBytes = await ReadBoundedBytesAsync(
                staged.OutputPath,
                ExpertModelDatasetTools.MaxDatasetBytes,
                "Freshly replayed reviewed dataset",
                cancellationToken).ConfigureAwait(false);
            RequireExactBytes(
                reviewedBytes,
                replayedBytes,
                "Reviewed dataset does not exactly match a fresh review replay.");

            package = await BuildPackageAsync(
                draftBytes,
                reviewedBytes,
                verificationManifestBytes,
                verificationReportBytes,
                reviewManifestBytes,
                capturedEvidence,
                cancellationToken).ConfigureAwait(false);
            package = package with { PackageId = ComputePackageId(package) };
            packageBytes = SerializeCanonical(package);
            if (packageBytes.LongLength > MaxPackageBytes)
            {
                throw new CoordinatorValidationException(
                    $"Independent-review package exceeds the {MaxPackageBytes:N0}-byte output limit.");
            }
        }
        finally
        {
            DeleteStagingDirectory(stagingDirectory);
        }

        await WriteBytesNoClobberAsync(
            outputFullPath,
            packageBytes,
            "Independent-review package",
            cancellationToken).ConfigureAwait(false);
        var persistedBytes = await ReadBoundedBytesAsync(
            outputFullPath,
            MaxPackageBytes,
            "Independent-review package",
            cancellationToken).ConfigureAwait(false);
        RequireExactBytes(packageBytes, persistedBytes, "Independent-review package changed while it was written.");
        return new ExpertDatasetReviewHandoffPreparationResult(
            package.PackageId,
            Sha256Hex(packageBytes),
            package.ReviewedDatasetSha256,
            package.Rows.Count,
            capturedEvidence.Count);
    }

    internal static async Task<ExpertDatasetReviewHandoffDecisionTemplatePreparationResult>
        PrepareDecisionTemplateAsync(
            string packagePath,
            string outputDecisionTemplatePath,
            IExpertDatasetExecutableVerifier executableVerifier,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(executableVerifier);
        EnsureDistinctPath(outputDecisionTemplatePath, packagePath);
        EnsureOutputAvailable(outputDecisionTemplatePath, "Independent-review decision template");

        var outputFullPath = Path.GetFullPath(outputDecisionTemplatePath);
        var validatedPackage = await ValidateAndReplayPackageAsync(
            packagePath,
            outputFullPath,
            "prepare-review-decision-template",
            executableVerifier,
            cancellationToken).ConfigureAwait(false);
        var worksheet = validatedPackage.Package.DecisionTemplate;
        var draft = new ExpertDatasetIndependentReviewDecisionDraft(
            DecisionDraftSchemaVersion,
            DecisionDraftStatus,
            NoDownstreamAuthority,
            validatedPackage.Package.PackageId,
            validatedPackage.PackageSha256,
            validatedPackage.Package.ReviewedDatasetSha256,
            worksheet.Reviewer,
            worksheet.ReviewBasis,
            worksheet.ReviewedAtUtc,
            worksheet.Rows,
            worksheet.Sources);
        ValidateDecisionDraft(draft, validatedPackage.Package, validatedPackage.PackageSha256);
        var draftBytes = SerializeCanonical(draft);
        if (draftBytes.LongLength > MaxDecisionBytes)
        {
            throw new CoordinatorValidationException(
                $"Independent-review decision template exceeds the {MaxDecisionBytes:N0}-byte output limit.");
        }

        await WriteBytesNoClobberAsync(
            outputFullPath,
            draftBytes,
            "Independent-review decision template",
            cancellationToken).ConfigureAwait(false);
        var persistedBytes = await ReadBoundedBytesAsync(
            outputFullPath,
            MaxDecisionBytes,
            "Independent-review decision template",
            cancellationToken).ConfigureAwait(false);
        RequireExactBytes(
            draftBytes,
            persistedBytes,
            "Independent-review decision template changed while it was written.");
        return new ExpertDatasetReviewHandoffDecisionTemplatePreparationResult(
            draft.PackageId,
            draft.PackageSha256,
            draft.ReviewedDatasetSha256,
            draft.Rows.Count,
            draft.Sources.Count);
    }

    internal static async Task<ExpertDatasetReviewHandoffDecisionCompilationResult> CompileDecisionAsync(
        string packagePath,
        string decisionTemplatePath,
        IReadOnlyList<ExpertDatasetReviewHandoffEvidenceInput> evidenceFiles,
        string outputDecisionPath,
        IExpertDatasetExecutableVerifier executableVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidenceFiles);
        ArgumentNullException.ThrowIfNull(executableVerifier);
        EnsureUniquePaths(
            evidenceFiles.Select(item => item.Path)
                .Prepend(decisionTemplatePath)
                .Prepend(packagePath));
        EnsureDistinctPaths(
            outputDecisionPath,
            packagePath,
            decisionTemplatePath,
            evidenceFiles.Select(item => item.Path));
        EnsureOutputAvailable(outputDecisionPath, "Independent-review decision");

        var templateBytes = await ReadBoundedBytesAsync(
            decisionTemplatePath,
            MaxDecisionBytes,
            "Independent-review decision template",
            cancellationToken).ConfigureAwait(false);
        var template = DeserializeClosedJson<ExpertDatasetIndependentReviewDecisionDraft>(
            templateBytes,
            "Independent-review decision template",
            RequireDecisionDraftProperties);
        var capturedEvidence = await CaptureEvidenceAsync(evidenceFiles, cancellationToken)
            .ConfigureAwait(false);
        if (capturedEvidence.Count == 0)
        {
            throw new CoordinatorValidationException(
                "Independent-review decision compilation requires immutable evidence.");
        }

        var outputFullPath = Path.GetFullPath(outputDecisionPath);
        var validatedPackage = await ValidateAndReplayPackageAsync(
            packagePath,
            outputFullPath,
            "compile-review-decision",
            executableVerifier,
            cancellationToken).ConfigureAwait(false);
        ValidateDecisionDraft(
            template,
            validatedPackage.Package,
            validatedPackage.PackageSha256);
        var evidence = capturedEvidence
            .OrderBy(item => item.Id, StringComparer.Ordinal)
            .Select(item => new ExpertDatasetIndependentReviewEvidenceFile(
                item.Id,
                item.FileName,
                item.Bytes.LongLength,
                Sha256Hex(item.Bytes),
                Convert.ToBase64String(item.Bytes)))
            .ToArray();
        var decision = new ExpertDatasetIndependentReviewDecision(
            DecisionSchemaVersion,
            ZeroSha256,
            validatedPackage.Package.PackageId,
            validatedPackage.PackageSha256,
            validatedPackage.Package.ReviewedDatasetSha256,
            NoDownstreamAuthority,
            template.Reviewer,
            template.ReviewBasis,
            template.ReviewedAtUtc ?? default,
            evidence,
            template.Rows,
            template.Sources);
        decision = decision with { DecisionId = ComputeDecisionId(decision) };
        _ = ValidateDecision(
            decision,
            validatedPackage.Package,
            validatedPackage.PackageSha256,
            validatedPackage.ContentReviewedAtUtc);
        var decisionBytes = SerializeCanonical(decision);
        if (decisionBytes.LongLength > MaxDecisionBytes)
        {
            throw new CoordinatorValidationException(
                $"Independent-review decision exceeds the {MaxDecisionBytes:N0}-byte output limit.");
        }

        await WriteBytesNoClobberAsync(
            outputFullPath,
            decisionBytes,
            "Independent-review decision",
            cancellationToken).ConfigureAwait(false);
        var persistedBytes = await ReadBoundedBytesAsync(
            outputFullPath,
            MaxDecisionBytes,
            "Independent-review decision",
            cancellationToken).ConfigureAwait(false);
        RequireExactBytes(decisionBytes, persistedBytes, "Independent-review decision changed while it was written.");
        return new ExpertDatasetReviewHandoffDecisionCompilationResult(
            decision.DecisionId,
            Sha256Hex(decisionBytes),
            validatedPackage.PackageSha256,
            decision.ReviewedDatasetSha256,
            decision.Rows.Count,
            decision.Sources.Count,
            decision.EvidenceFiles.Count);
    }

    internal static async Task<ExpertDatasetReviewHandoffApplyResult> ApplyDecisionAsync(
        string packagePath,
        string decisionPath,
        string outputDatasetPath,
        IExpertDatasetExecutableVerifier executableVerifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(executableVerifier);
        EnsureDistinctPaths(outputDatasetPath, packagePath, decisionPath, []);
        EnsureOutputAvailable(outputDatasetPath, "Rights-reviewed dataset");

        var outputFullPath = Path.GetFullPath(outputDatasetPath);
        var validatedPackage = await ValidateAndReplayPackageAsync(
            packagePath,
            outputFullPath,
            "apply-review-handoff",
            executableVerifier,
            cancellationToken).ConfigureAwait(false);
        var reviewedBytes = validatedPackage.ReviewedDatasetBytes;
        var packageSha256 = validatedPackage.PackageSha256;
        var decisionBytes = await ReadBoundedBytesAsync(
            decisionPath,
            MaxDecisionBytes,
            "Independent-review decision",
            cancellationToken).ConfigureAwait(false);
        var decision = DeserializeCanonical<ExpertDatasetIndependentReviewDecision>(
            decisionBytes,
            "Independent-review decision");
        var decisionSha256 = Sha256Hex(decisionBytes);
        var evidenceById = ValidateDecision(
            decision,
            validatedPackage.Package,
            packageSha256,
            validatedPackage.ContentReviewedAtUtc);

        var loaded = await ExpertModelDatasetTools.LoadAndValidateBytesAsync(
                reviewedBytes,
                cancellationToken).ConfigureAwait(false);
        RequireValidDataset(loaded, "Packaged reviewed dataset");
        var rowsById = decision.Rows.ToDictionary(item => item.ExampleId, StringComparer.Ordinal);
        var sourcesByKey = decision.Sources.ToDictionary(
            item => SourceKey(item.ExampleId, item.SourceId),
            StringComparer.Ordinal);
        var outputExamples = new List<ExpertModelDatasetExample>(loaded.Examples.Count);
        var rightsElevatedCount = 0;
        var trainingRequestedCount = 0;

        foreach (var example in loaded.Examples)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rowDecision = rowsById[example.Id];
            var eligible = IsCandidateStableDevelopmentRow(example);
            ValidateRightsDecision(
                rowDecision.Rights,
                rowDecision.UseForTraining,
                eligible,
                $"Row '{example.Id}'");
            var sourceDecisions = example.Sources
                .Select(source => sourcesByKey[SourceKey(example.Id, source.Id)])
                .ToArray();
            for (var index = 0; index < example.Sources.Count; index++)
            {
                ValidateRightsDecision(
                    sourceDecisions[index].Rights,
                    useForTraining: false,
                    eligible,
                    $"Source '{example.Id}/{example.Sources[index].Id}'");
            }
            ValidateSourceClosure(example.Id, rowDecision, sourceDecisions);

            if (RightsWereElevated(example.Rights, rowDecision.Rights))
            {
                rightsElevatedCount++;
            }
            if (rowDecision.UseForTraining)
            {
                trainingRequestedCount++;
            }

            var evidenceIds = rowDecision.EvidenceIds
                .Concat(sourceDecisions.SelectMany(item => item.EvidenceIds))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();
            var evidence = example.Verification.Evidence.ToList();
            evidence.Add($"reviewPackageSha256={packageSha256}");
            evidence.Add($"reviewDecisionSha256={decisionSha256}");
            evidence.AddRange(evidenceIds.Select(id =>
                $"reviewEvidenceSha256:{id}={evidenceById[id].Sha256}"));
            if (evidence.Count > ExpertModelDatasetTools.MaxEvidenceItems)
            {
                throw new CoordinatorValidationException(
                    $"Independent-review evidence for '{example.Id}' exceeds the dataset evidence-item limit.");
            }

            var verification = example.Verification with
            {
                Evidence = evidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    evidence,
                    example.Verification.CompileEvidence,
                    example.Verification.TestEvidence)
            };
            var updatedSources = example.Sources
                .Select((source, index) => source with { Rights = sourceDecisions[index].Rights })
                .ToArray();
            outputExamples.Add(example with
            {
                Rights = rowDecision.Rights,
                UseForTraining = rowDecision.UseForTraining,
                Sources = updatedSources,
                Verification = verification
            });
        }

        var outputBytes = SerializeDataset(outputExamples);
        var output = await ExpertModelDatasetTools.LoadAndValidateBytesAsync(
            outputBytes,
            cancellationToken).ConfigureAwait(false);
        RequireValidDataset(output, "Rights-reviewed dataset");
        if (output.Report.TrainingEligibleCount != 0)
        {
            throw new CoordinatorValidationException(
                "Independent review must not make rows training-eligible before signed receipts.");
        }
        await WriteBytesNoClobberAsync(
            outputFullPath,
            outputBytes,
            "Rights-reviewed dataset",
            cancellationToken).ConfigureAwait(false);
        return new ExpertDatasetReviewHandoffApplyResult(
            output.Report.ExampleCount,
            rightsElevatedCount,
            trainingRequestedCount,
            output.Report.TrainingEligibleCount,
            packageSha256,
            decisionSha256,
            Sha256Hex(outputBytes));
    }

    internal static string ComputePackageId(ExpertDatasetIndependentReviewPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);
        return $"review-package-{Sha256Hex(SerializeCanonical(package with { PackageId = ZeroSha256 }))}";
    }

    internal static string ComputeDecisionId(ExpertDatasetIndependentReviewDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        return $"review-decision-{Sha256Hex(SerializeCanonical(decision with { DecisionId = ZeroSha256 }))}";
    }

    internal static byte[] SerializeCanonical<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.SerializeToUtf8Bytes(value, CanonicalJson);
    }

    private static async Task<ValidatedPackage> ValidateAndReplayPackageAsync(
        string packagePath,
        string outputFullPath,
        string stagingPurpose,
        IExpertDatasetExecutableVerifier executableVerifier,
        CancellationToken cancellationToken)
    {
        var packageBytes = await ReadBoundedBytesAsync(
            packagePath,
            MaxPackageBytes,
            "Independent-review package",
            cancellationToken).ConfigureAwait(false);
        var package = DeserializeCanonical<ExpertDatasetIndependentReviewPackage>(
            packageBytes,
            "Independent-review package");
        ValidatePackageEnvelope(package);
        var packageFiles = ValidateAndDecodePackageFiles(package.Files);
        var draftBytes = packageFiles[DraftFileId];
        var reviewedBytes = packageFiles[ReviewedFileId];
        var verificationManifestBytes = packageFiles[VerificationManifestFileId];
        var verificationReportBytes = packageFiles[VerificationReportFileId];
        var reviewManifestBytes = packageFiles[ReviewManifestFileId];
        var packageEvidence = package.Files
            .Where(item => item.Id.StartsWith(PackageEvidencePrefix, StringComparison.Ordinal))
            .Select(item =>
            {
                var id = item.Id[PackageEvidencePrefix.Length..];
                return new CapturedEvidence(id, $"{id}.bin", packageFiles[item.Id]);
            })
            .ToArray();

        var stagingDirectory = CreateStagingDirectory(outputFullPath, stagingPurpose);
        try
        {
            var staged = await WriteReplayInputsAsync(
                stagingDirectory,
                draftBytes,
                verificationManifestBytes,
                verificationReportBytes,
                reviewManifestBytes,
                cancellationToken).ConfigureAwait(false);
            await ExpertModelDatasetReviewTools.ApplyReviewWithExecutableVerifierAsync(
                staged.DraftPath,
                staged.VerificationManifestPath,
                staged.VerificationReportPath,
                staged.ReviewManifestPath,
                staged.OutputPath,
                executableVerifier,
                cancellationToken).ConfigureAwait(false);
            var replayedBytes = await ReadBoundedBytesAsync(
                staged.OutputPath,
                ExpertModelDatasetTools.MaxDatasetBytes,
                "Freshly replayed reviewed dataset",
                cancellationToken).ConfigureAwait(false);
            RequireExactBytes(
                reviewedBytes,
                replayedBytes,
                "Packaged reviewed dataset does not exactly match a fresh review replay.");

            var expectedPackage = await BuildPackageAsync(
                draftBytes,
                reviewedBytes,
                verificationManifestBytes,
                verificationReportBytes,
                reviewManifestBytes,
                packageEvidence,
                cancellationToken).ConfigureAwait(false);
            expectedPackage = expectedPackage with { PackageId = ComputePackageId(expectedPackage) };
            RequireExactBytes(
                packageBytes,
                SerializeCanonical(expectedPackage),
                "Independent-review package inventory does not exactly match its immutable contents.");
            var reviewManifest = DeserializeJson<ExpertDatasetReviewManifest>(
                reviewManifestBytes,
                "Embedded review manifest");
            return new ValidatedPackage(
                package,
                Sha256Hex(packageBytes),
                reviewedBytes,
                reviewManifest.ReviewedAtUtc);
        }
        finally
        {
            DeleteStagingDirectory(stagingDirectory);
        }
    }

    private static async Task<ExpertDatasetIndependentReviewPackage> BuildPackageAsync(
        byte[] draftBytes,
        byte[] reviewedBytes,
        byte[] verificationManifestBytes,
        byte[] verificationReportBytes,
        byte[] reviewManifestBytes,
        IReadOnlyList<CapturedEvidence> evidenceFiles,
        CancellationToken cancellationToken)
    {
        var draft = await ExpertModelDatasetTools.LoadAndValidateBytesAsync(
            draftBytes,
            cancellationToken).ConfigureAwait(false);
        var reviewed = await ExpertModelDatasetTools.LoadAndValidateBytesAsync(
            reviewedBytes,
            cancellationToken).ConfigureAwait(false);
        RequireValidDataset(draft, "Draft dataset");
        RequireValidDataset(reviewed, "Reviewed dataset");
        RejectPreexistingReviewAnchors(reviewed.Examples);
        if (draft.Examples.Count == 0 || draft.Examples.Count != reviewed.Examples.Count)
        {
            throw new CoordinatorValidationException(
                "Draft and reviewed datasets must contain the same non-zero row count.");
        }

        var rows = new List<ExpertDatasetIndependentReviewRowInventory>(reviewed.Examples.Count);
        var sources = new List<ExpertDatasetIndependentReviewSourceInventory>();
        var rowTemplate = new List<ExpertDatasetIndependentReviewRowDecision>(reviewed.Examples.Count);
        var sourceTemplate = new List<ExpertDatasetIndependentReviewSourceDecision>();
        for (var rowIndex = 0; rowIndex < reviewed.Examples.Count; rowIndex++)
        {
            var draftRow = draft.Examples[rowIndex];
            var reviewedRow = reviewed.Examples[rowIndex];
            if (!StringComparer.Ordinal.Equals(draftRow.Id, reviewedRow.Id))
            {
                throw new CoordinatorValidationException(
                    "Draft and reviewed datasets must have identical row identity and order.");
            }
            if (draftRow.Sources.Count != reviewedRow.Sources.Count)
            {
                throw new CoordinatorValidationException(
                    $"Draft and reviewed source inventories differ for '{reviewedRow.Id}'.");
            }

            var identities = BuildVerificationEvidenceIdentities(reviewedRow.Verification);
            rows.Add(new ExpertDatasetIndependentReviewRowInventory(
                reviewedRow.Id,
                Sha256Hex(SerializeCanonical(draftRow)),
                Sha256Hex(SerializeCanonical(reviewedRow)),
                reviewedRow.ConversationSha256,
                reviewedRow.ReviewStatus,
                reviewedRow.Verification.Verified,
                reviewedRow.Split,
                GetKnowledgeClass(reviewedRow),
                reviewedRow.Rights,
                reviewedRow.UseForTraining,
                reviewedRow.Verification.EvidenceSha256,
                identities));
            rowTemplate.Add(new ExpertDatasetIndependentReviewRowDecision(
                reviewedRow.Id,
                DenyDownstreamRights(reviewedRow.Rights),
                UseForTraining: false,
                EvidenceIds: []));

            for (var sourceIndex = 0; sourceIndex < reviewedRow.Sources.Count; sourceIndex++)
            {
                var draftSource = draftRow.Sources[sourceIndex];
                var reviewedSource = reviewedRow.Sources[sourceIndex];
                if (!StringComparer.Ordinal.Equals(draftSource.Id, reviewedSource.Id))
                {
                    throw new CoordinatorValidationException(
                        $"Draft and reviewed source identity or order differs for '{reviewedRow.Id}'.");
                }
                sources.Add(new ExpertDatasetIndependentReviewSourceInventory(
                    reviewedRow.Id,
                    reviewedSource.Id,
                    Sha256Hex(SerializeCanonical(draftSource)),
                    Sha256Hex(SerializeCanonical(reviewedSource)),
                    Sha256Hex(StrictUtf8.GetBytes(reviewedSource.Content)),
                    reviewedSource.Rights));
                sourceTemplate.Add(new ExpertDatasetIndependentReviewSourceDecision(
                    reviewedRow.Id,
                    reviewedSource.Id,
                    DenyDownstreamRights(reviewedSource.Rights),
                    EvidenceIds: []));
            }
        }

        var files = new List<ExpertDatasetIndependentReviewFile>
        {
            CreatePackageFile(
                DraftFileId,
                "inputs/draft-dataset.jsonl",
                "review-input-draft-dataset",
                draftBytes),
            CreatePackageFile(
                ReviewedFileId,
                "inputs/reviewed-dataset.jsonl",
                "review-input-reviewed-dataset",
                reviewedBytes),
            CreatePackageFile(
                VerificationManifestFileId,
                "inputs/verification-manifest.json",
                "review-input-verification-manifest",
                verificationManifestBytes),
            CreatePackageFile(
                VerificationReportFileId,
                "inputs/verification-report.json",
                "review-input-verification-report",
                verificationReportBytes),
            CreatePackageFile(
                ReviewManifestFileId,
                "inputs/review-manifest.json",
                "review-input-review-manifest",
                reviewManifestBytes)
        };
        foreach (var evidence in evidenceFiles.OrderBy(item => item.Id, StringComparer.Ordinal))
        {
            files.Add(CreatePackageFile(
                PackageEvidencePrefix + evidence.Id,
                $"evidence/{evidence.Id}.bin",
                "independent-review-input-evidence",
                evidence.Bytes));
        }

        return new ExpertDatasetIndependentReviewPackage(
            PackageSchemaVersion,
            ZeroSha256,
            PackageStatus,
            NoDownstreamAuthority,
            Sha256Hex(draftBytes),
            Sha256Hex(reviewedBytes),
            files,
            rows,
            sources,
            new ExpertDatasetIndependentReviewDecisionTemplate(
                Reviewer: string.Empty,
                ReviewBasis: string.Empty,
                ReviewedAtUtc: null,
                Rows: rowTemplate,
                Sources: sourceTemplate));
    }

    private static void ValidatePackageEnvelope(ExpertDatasetIndependentReviewPackage package)
    {
        if (!StringComparer.Ordinal.Equals(package.SchemaVersion, PackageSchemaVersion))
        {
            throw new CoordinatorValidationException("Independent-review package schema is unsupported.");
        }
        if (!StringComparer.Ordinal.Equals(package.Status, PackageStatus))
        {
            throw new CoordinatorValidationException("Independent-review package status is invalid.");
        }
        RequireNoDownstreamAuthority(package.Authority, "Independent-review package");
        RequireSha256(package.DraftDatasetSha256, "Package draft dataset SHA-256");
        RequireSha256(package.ReviewedDatasetSha256, "Package reviewed dataset SHA-256");
        if (!StringComparer.Ordinal.Equals(package.PackageId, ComputePackageId(package)))
        {
            throw new CoordinatorValidationException("Independent-review package ID is invalid.");
        }
        if (package.Files is null || package.Rows is null || package.Sources is null ||
            package.DecisionTemplate is null)
        {
            throw new CoordinatorValidationException("Independent-review package inventories are required.");
        }
    }

    private static void ValidateDecisionDraft(
        ExpertDatasetIndependentReviewDecisionDraft draft,
        ExpertDatasetIndependentReviewPackage package,
        string packageSha256)
    {
        if (!StringComparer.Ordinal.Equals(draft.SchemaVersion, DecisionDraftSchemaVersion) ||
            !StringComparer.Ordinal.Equals(draft.Status, DecisionDraftStatus))
        {
            throw new CoordinatorValidationException(
                "Independent-review decision template version or unsigned status is invalid.");
        }
        RequireNoDownstreamAuthority(draft.Authority, "Independent-review decision template");
        if (!StringComparer.Ordinal.Equals(draft.PackageId, package.PackageId) ||
            !StringComparer.Ordinal.Equals(draft.PackageSha256, packageSha256) ||
            !StringComparer.Ordinal.Equals(draft.ReviewedDatasetSha256, package.ReviewedDatasetSha256))
        {
            throw new CoordinatorValidationException(
                "Independent-review decision template is not bound to the exact package and reviewed corpus.");
        }
        if (draft.Rows is null || draft.Sources is null)
        {
            throw new CoordinatorValidationException(
                "Independent-review decision template row and source inventories are required.");
        }
        RequireExactRows(draft.Rows, package.Rows);
        RequireExactSources(draft.Sources, package.Sources);
    }

    private static IReadOnlyDictionary<string, byte[]> ValidateAndDecodePackageFiles(
        IReadOnlyList<ExpertDatasetIndependentReviewFile> files)
    {
        if (files.Count < 5 || files.Count > 5 + MaxEvidenceFiles)
        {
            throw new CoordinatorValidationException("Independent-review package file inventory is incomplete or too large.");
        }
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        long aggregateEvidenceBytes = 0;
        foreach (var file in files)
        {
            if (!IsSafeIdentifier(file.Id) || !IsSafePackagePath(file.Path) ||
                string.IsNullOrWhiteSpace(file.Purpose))
            {
                throw new CoordinatorValidationException("Independent-review package contains an invalid file identity.");
            }
            var maximumSize = MaximumPackageFileSize(file.Id);
            if (maximumSize is null || file.SizeBytes < 0 || file.SizeBytes > maximumSize.Value)
            {
                throw new CoordinatorValidationException(
                    $"Package file '{file.Id}' is unknown or exceeds its bounded size limit.");
            }
            if (file.Id.StartsWith(PackageEvidencePrefix, StringComparison.Ordinal) && file.SizeBytes == 0)
            {
                throw new CoordinatorValidationException($"Package evidence file '{file.Id}' must not be empty.");
            }
            if (!result.TryAdd(file.Id, DecodeImmutableContent(
                    file.ContentBase64,
                    file.SizeBytes,
                    file.Sha256,
                    $"Package file '{file.Id}'")) ||
                !paths.Add(file.Path))
            {
                throw new CoordinatorValidationException("Independent-review package contains duplicate file identities.");
            }
            if (file.Id.StartsWith(PackageEvidencePrefix, StringComparison.Ordinal))
            {
                aggregateEvidenceBytes += file.SizeBytes;
            }
        }
        if (aggregateEvidenceBytes > MaxAggregateEvidenceBytes)
        {
            throw new CoordinatorValidationException("Package evidence files exceed the aggregate size limit.");
        }

        RequirePackageFile(files, DraftFileId, "inputs/draft-dataset.jsonl", "review-input-draft-dataset");
        RequirePackageFile(files, ReviewedFileId, "inputs/reviewed-dataset.jsonl", "review-input-reviewed-dataset");
        RequirePackageFile(
            files,
            VerificationManifestFileId,
            "inputs/verification-manifest.json",
            "review-input-verification-manifest");
        RequirePackageFile(
            files,
            VerificationReportFileId,
            "inputs/verification-report.json",
            "review-input-verification-report");
        RequirePackageFile(files, ReviewManifestFileId, "inputs/review-manifest.json", "review-input-review-manifest");
        foreach (var file in files.Where(item => item.Id.StartsWith(PackageEvidencePrefix, StringComparison.Ordinal)))
        {
            var id = file.Id[PackageEvidencePrefix.Length..];
            if (!IsSafeIdentifier(id) ||
                !StringComparer.Ordinal.Equals(file.Path, $"evidence/{id}.bin") ||
                !StringComparer.Ordinal.Equals(file.Purpose, "independent-review-input-evidence"))
            {
                throw new CoordinatorValidationException($"Package evidence file '{file.Id}' has invalid metadata.");
            }
        }
        return result;
    }

    private static IReadOnlyDictionary<string, ExpertDatasetIndependentReviewEvidenceFile> ValidateDecision(
        ExpertDatasetIndependentReviewDecision decision,
        ExpertDatasetIndependentReviewPackage package,
        string packageSha256,
        DateTimeOffset contentReviewedAtUtc)
    {
        if (!StringComparer.Ordinal.Equals(decision.SchemaVersion, DecisionSchemaVersion) ||
            !StringComparer.Ordinal.Equals(decision.DecisionId, ComputeDecisionId(decision)))
        {
            throw new CoordinatorValidationException("Independent-review decision identity is invalid.");
        }
        if (!StringComparer.Ordinal.Equals(decision.PackageId, package.PackageId) ||
            !StringComparer.Ordinal.Equals(decision.PackageSha256, packageSha256) ||
            !StringComparer.Ordinal.Equals(decision.ReviewedDatasetSha256, package.ReviewedDatasetSha256))
        {
            throw new CoordinatorValidationException(
                "Independent-review decision is not bound to the exact package and reviewed corpus.");
        }
        RequireNoDownstreamAuthority(decision.Authority, "Independent-review decision");
        if (string.IsNullOrWhiteSpace(decision.Reviewer) || decision.Reviewer.Length > 200 ||
            string.IsNullOrWhiteSpace(decision.ReviewBasis) || decision.ReviewBasis.Length > 4_000)
        {
            throw new CoordinatorValidationException(
                "Independent-review decision requires a bounded reviewer and review basis.");
        }
        ValidateDecisionChronology(decision.ReviewedAtUtc, contentReviewedAtUtc);
        if (decision.EvidenceFiles is null || decision.Rows is null || decision.Sources is null ||
            decision.EvidenceFiles.Count == 0 || decision.EvidenceFiles.Count > MaxEvidenceFiles)
        {
            throw new CoordinatorValidationException(
                "Independent-review decision requires bounded evidence and complete row/source decisions.");
        }

        var evidenceById = new Dictionary<string, ExpertDatasetIndependentReviewEvidenceFile>(StringComparer.Ordinal);
        var fileNames = new HashSet<string>(StringComparer.Ordinal);
        long aggregateEvidenceBytes = 0;
        foreach (var evidence in decision.EvidenceFiles)
        {
            if (!IsSafeIdentifier(evidence.Id) || !IsSafeFileName(evidence.FileName) ||
                !fileNames.Add(evidence.FileName) ||
                !evidenceById.TryAdd(evidence.Id, evidence))
            {
                throw new CoordinatorValidationException("Decision evidence contains duplicate or unsafe identities.");
            }
            if (evidence.SizeBytes <= 0 || evidence.SizeBytes > MaxEvidenceFileBytes)
            {
                throw new CoordinatorValidationException(
                    $"Decision evidence '{evidence.Id}' must be nonempty and within the per-file size limit.");
            }
            _ = DecodeImmutableContent(
                evidence.ContentBase64,
                evidence.SizeBytes,
                evidence.Sha256,
                $"Decision evidence '{evidence.Id}'");
            aggregateEvidenceBytes += evidence.SizeBytes;
        }
        if (aggregateEvidenceBytes > MaxAggregateEvidenceBytes)
        {
            throw new CoordinatorValidationException("Decision evidence exceeds the aggregate size limit.");
        }

        RequireExactRows(decision.Rows, package.Rows);
        RequireExactSources(decision.Sources, package.Sources);
        ValidateDecisionRights(decision, package);
        var usedEvidence = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in decision.Rows)
        {
            ValidateEvidenceReferences(row.EvidenceIds, evidenceById, usedEvidence, $"Row '{row.ExampleId}'");
        }
        foreach (var source in decision.Sources)
        {
            ValidateEvidenceReferences(
                source.EvidenceIds,
                evidenceById,
                usedEvidence,
                $"Source '{source.ExampleId}/{source.SourceId}'");
        }
        if (usedEvidence.Count != evidenceById.Count)
        {
            throw new CoordinatorValidationException("Decision contains unreferenced evidence files.");
        }
        return evidenceById;
    }

    private static void ValidateDecisionChronology(
        DateTimeOffset reviewedAtUtc,
        DateTimeOffset contentReviewedAtUtc)
    {
        if (reviewedAtUtc == default || reviewedAtUtc.Offset != TimeSpan.Zero ||
            reviewedAtUtc.Ticks % TimeSpan.TicksPerSecond != 0 ||
            reviewedAtUtc < contentReviewedAtUtc ||
            reviewedAtUtc > DateTimeOffset.UtcNow)
        {
            throw new CoordinatorValidationException(
                "Independent-review decision time must be UTC whole seconds, no earlier than the embedded " +
                "content review, and no later than now.");
        }
    }

    private static void ValidateDecisionRights(
        ExpertDatasetIndependentReviewDecision decision,
        ExpertDatasetIndependentReviewPackage package)
    {
        for (var index = 0; index < decision.Rows.Count; index++)
        {
            var row = decision.Rows[index];
            var inventory = package.Rows[index];
            var eligible = inventory.Split == "development" &&
                           inventory.ReviewStatus == "approved" &&
                           inventory.Verified &&
                           inventory.KnowledgeClass == "candidate-stable";
            ValidateRightsDecision(row.Rights, row.UseForTraining, eligible, $"Row '{row.ExampleId}'");
            var sources = decision.Sources
                .Where(item => StringComparer.Ordinal.Equals(item.ExampleId, row.ExampleId))
                .ToArray();
            foreach (var source in sources)
            {
                ValidateRightsDecision(
                    source.Rights,
                    useForTraining: false,
                    eligible,
                    $"Source '{source.ExampleId}/{source.SourceId}'");
            }
            ValidateSourceClosure(row.ExampleId, row, sources);
        }
    }

    private static void RequireExactRows(
        IReadOnlyList<ExpertDatasetIndependentReviewRowDecision> decisions,
        IReadOnlyList<ExpertDatasetIndependentReviewRowInventory> inventory)
    {
        if (decisions.Count != inventory.Count)
        {
            throw new CoordinatorValidationException("Decision row inventory is incomplete.");
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < decisions.Count; index++)
        {
            var decision = decisions[index];
            if (!seen.Add(decision.ExampleId))
            {
                throw new CoordinatorValidationException($"Decision row '{decision.ExampleId}' is duplicated.");
            }
            if (!StringComparer.Ordinal.Equals(decision.ExampleId, inventory[index].ExampleId))
            {
                throw new CoordinatorValidationException(
                    $"Decision row '{decision.ExampleId}' is unknown or out of canonical order.");
            }
            if (decision.Rights is null || decision.EvidenceIds is null)
            {
                throw new CoordinatorValidationException($"Decision row '{decision.ExampleId}' is incomplete.");
            }
        }
    }

    private static void RequireExactSources(
        IReadOnlyList<ExpertDatasetIndependentReviewSourceDecision> decisions,
        IReadOnlyList<ExpertDatasetIndependentReviewSourceInventory> inventory)
    {
        if (decisions.Count != inventory.Count)
        {
            throw new CoordinatorValidationException("Decision source inventory is incomplete.");
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < decisions.Count; index++)
        {
            var decision = decisions[index];
            var key = SourceKey(decision.ExampleId, decision.SourceId);
            if (!seen.Add(key))
            {
                throw new CoordinatorValidationException($"Decision source '{key}' is duplicated.");
            }
            if (!StringComparer.Ordinal.Equals(decision.ExampleId, inventory[index].ExampleId) ||
                !StringComparer.Ordinal.Equals(decision.SourceId, inventory[index].SourceId))
            {
                throw new CoordinatorValidationException(
                    $"Decision source '{key}' is unknown or out of canonical order.");
            }
            if (decision.Rights is null || decision.EvidenceIds is null)
            {
                throw new CoordinatorValidationException($"Decision source '{key}' is incomplete.");
            }
        }
    }

    private static void ValidateEvidenceReferences(
        IReadOnlyList<string> evidenceIds,
        IReadOnlyDictionary<string, ExpertDatasetIndependentReviewEvidenceFile> evidenceById,
        ISet<string> usedEvidence,
        string owner)
    {
        if (evidenceIds.Count == 0 || evidenceIds.Count > MaxEvidenceFiles ||
            evidenceIds.Distinct(StringComparer.Ordinal).Count() != evidenceIds.Count)
        {
            throw new CoordinatorValidationException($"{owner} must cite unique immutable evidence.");
        }
        foreach (var evidenceId in evidenceIds)
        {
            if (!evidenceById.ContainsKey(evidenceId))
            {
                throw new CoordinatorValidationException($"{owner} cites unknown evidence '{evidenceId}'.");
            }
            usedEvidence.Add(evidenceId);
        }
    }

    private static void ValidateRightsDecision(
        DatasetRights rights,
        bool useForTraining,
        bool eligible,
        string owner)
    {
        if (!rights.MayStore || !rights.MayEvaluate)
        {
            throw new CoordinatorValidationException($"{owner} must retain storage and evaluation rights.");
        }
        if (rights.MayUploadToProvider && !rights.MayTrain)
        {
            throw new CoordinatorValidationException($"{owner} provider upload requires training rights.");
        }
        if (useForTraining && !rights.MayTrain)
        {
            throw new CoordinatorValidationException($"{owner} training use requires training rights.");
        }
        if (!eligible && (rights.MayTrain || rights.MayUploadToProvider ||
                          rights.MayRedistribute || useForTraining))
        {
            throw new CoordinatorValidationException(
                $"{owner} may grant downstream rights only to approved, verified, candidate-stable development rows.");
        }
    }

    private static void ValidateSourceClosure(
        string exampleId,
        ExpertDatasetIndependentReviewRowDecision row,
        IReadOnlyList<ExpertDatasetIndependentReviewSourceDecision> sources)
    {
        if (row.Rights.MayTrain && sources.Any(item => !item.Rights.MayTrain))
        {
            throw new CoordinatorValidationException($"Row '{exampleId}' training rights lack source closure.");
        }
        if (row.Rights.MayUploadToProvider &&
            sources.Any(item => !item.Rights.MayTrain || !item.Rights.MayUploadToProvider))
        {
            throw new CoordinatorValidationException($"Row '{exampleId}' provider-upload rights lack source closure.");
        }
        if (row.Rights.MayRedistribute && sources.Any(item => !item.Rights.MayRedistribute))
        {
            throw new CoordinatorValidationException($"Row '{exampleId}' redistribution rights lack source closure.");
        }
        if (row.UseForTraining && sources.Any(item => !item.Rights.MayTrain))
        {
            throw new CoordinatorValidationException($"Row '{exampleId}' training request lacks source closure.");
        }
    }

    private static void RejectPreexistingReviewAnchors(
        IReadOnlyList<ExpertModelDatasetExample> examples)
    {
        foreach (var example in examples)
        {
            var existingEvidence = example.Verification.Evidence
                .Concat(example.Verification.CompileEvidence)
                .Concat(example.Verification.TestEvidence);
            var reserved = existingEvidence.FirstOrDefault(value =>
                ReservedReviewAnchorPrefixes.Any(prefix => value.StartsWith(prefix, StringComparison.Ordinal)));
            if (reserved is not null)
            {
                throw new CoordinatorValidationException(
                    $"Reviewed row '{example.Id}' contains a reserved independent-review evidence anchor.");
            }
        }
    }

    private static bool IsCandidateStableDevelopmentRow(ExpertModelDatasetExample example) =>
        example.Split == "development" &&
        example.ReviewStatus == "approved" &&
        example.Verification.Verified &&
        example.Verification.Evidence.Contains(CandidateStable, StringComparer.Ordinal) &&
        !example.Verification.Evidence.Contains(RetrievalOnly, StringComparer.Ordinal);

    private static bool RightsWereElevated(DatasetRights before, DatasetRights after) =>
        (!before.MayStore && after.MayStore) ||
        (!before.MayEvaluate && after.MayEvaluate) ||
        (!before.MayTrain && after.MayTrain) ||
        (!before.MayUploadToProvider && after.MayUploadToProvider) ||
        (!before.MayRedistribute && after.MayRedistribute);

    private static DatasetRights DenyDownstreamRights(DatasetRights rights) => new(
        MayStore: rights.MayStore,
        MayEvaluate: rights.MayEvaluate,
        MayTrain: false,
        MayUploadToProvider: false,
        MayRedistribute: false);

    private static string GetKnowledgeClass(ExpertModelDatasetExample example)
    {
        var candidate = example.Verification.Evidence.Contains(CandidateStable, StringComparer.Ordinal);
        var retrieval = example.Verification.Evidence.Contains(RetrievalOnly, StringComparer.Ordinal);
        return candidate ? "candidate-stable" : retrieval ? "retrieval-only" : "unspecified";
    }

    private static IReadOnlyList<string> BuildVerificationEvidenceIdentities(
        ExpertVerificationEvidence verification)
    {
        var identities = new List<string>();
        identities.AddRange(verification.Evidence.Select((value, index) =>
            $"evidence:{index}:{Sha256Hex(StrictUtf8.GetBytes(value))}"));
        identities.AddRange(verification.CompileEvidence.Select((value, index) =>
            $"compile:{index}:{Sha256Hex(StrictUtf8.GetBytes(value))}"));
        identities.AddRange(verification.TestEvidence.Select((value, index) =>
            $"test:{index}:{Sha256Hex(StrictUtf8.GetBytes(value))}"));
        return identities;
    }

    private static ExpertDatasetIndependentReviewFile CreatePackageFile(
        string id,
        string path,
        string purpose,
        byte[] bytes) => new(
            id,
            path,
            purpose,
            bytes.LongLength,
            Sha256Hex(bytes),
            Convert.ToBase64String(bytes));

    private static void RequirePackageFile(
        IReadOnlyList<ExpertDatasetIndependentReviewFile> files,
        string id,
        string path,
        string purpose)
    {
        var file = files.SingleOrDefault(item => StringComparer.Ordinal.Equals(item.Id, id));
        if (file is null || !StringComparer.Ordinal.Equals(file.Path, path) ||
            !StringComparer.Ordinal.Equals(file.Purpose, purpose))
        {
            throw new CoordinatorValidationException($"Package file '{id}' is missing or has invalid metadata.");
        }
    }

    private static byte[] DecodeImmutableContent(
        string contentBase64,
        long declaredSize,
        string declaredSha256,
        string description)
    {
        RequireSha256(declaredSha256, $"{description} SHA-256");
        if (declaredSize < 0 || declaredSize > int.MaxValue || contentBase64 is null)
        {
            throw new CoordinatorValidationException($"{description} has an invalid size or content.");
        }
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(contentBase64);
        }
        catch (FormatException exception)
        {
            throw new CoordinatorValidationException($"{description} content is not canonical base64: {exception.Message}");
        }
        if (!StringComparer.Ordinal.Equals(Convert.ToBase64String(bytes), contentBase64) ||
            bytes.LongLength != declaredSize ||
            !StringComparer.Ordinal.Equals(Sha256Hex(bytes), declaredSha256))
        {
            throw new CoordinatorValidationException($"{description} content, size, and SHA-256 do not match.");
        }
        return bytes;
    }

    private static async Task<IReadOnlyList<CapturedEvidence>> CaptureEvidenceAsync(
        IReadOnlyList<ExpertDatasetReviewHandoffEvidenceInput> inputs,
        CancellationToken cancellationToken)
    {
        if (inputs.Count > MaxEvidenceFiles)
        {
            throw new CoordinatorValidationException(
                $"Independent-review handoff accepts at most {MaxEvidenceFiles} evidence files.");
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var captured = new List<CapturedEvidence>(inputs.Count);
        long aggregateBytes = 0;
        foreach (var input in inputs)
        {
            if (!IsSafeIdentifier(input.Id) || !ids.Add(input.Id))
            {
                throw new CoordinatorValidationException("Handoff evidence IDs must be unique safe identifiers.");
            }
            var fullPath = Path.GetFullPath(input.Path);
            if (!paths.Add(fullPath))
            {
                throw new CoordinatorValidationException("Handoff evidence paths must be unique.");
            }
            var bytes = await ReadBoundedBytesAsync(
                fullPath,
                MaxEvidenceFileBytes,
                $"Handoff evidence '{input.Id}'",
                cancellationToken).ConfigureAwait(false);
            if (bytes.Length == 0)
            {
                throw new CoordinatorValidationException($"Handoff evidence '{input.Id}' must not be empty.");
            }
            aggregateBytes += bytes.LongLength;
            if (aggregateBytes > MaxAggregateEvidenceBytes)
            {
                throw new CoordinatorValidationException("Handoff evidence exceeds the aggregate size limit.");
            }
            captured.Add(new CapturedEvidence(input.Id, Path.GetFileName(fullPath), bytes));
        }
        return captured;
    }

    private static async Task<ReplayPaths> WriteReplayInputsAsync(
        string directory,
        byte[] draftBytes,
        byte[] verificationManifestBytes,
        byte[] verificationReportBytes,
        byte[] reviewManifestBytes,
        CancellationToken cancellationToken)
    {
        var paths = new ReplayPaths(
            Path.Combine(directory, "draft.jsonl"),
            Path.Combine(directory, "verification-manifest.json"),
            Path.Combine(directory, "verification-report.json"),
            Path.Combine(directory, "review-manifest.json"),
            Path.Combine(directory, "reviewed.jsonl"));
        await File.WriteAllBytesAsync(paths.DraftPath, draftBytes, cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(
            paths.VerificationManifestPath,
            verificationManifestBytes,
            cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(
            paths.VerificationReportPath,
            verificationReportBytes,
            cancellationToken).ConfigureAwait(false);
        await File.WriteAllBytesAsync(
            paths.ReviewManifestPath,
            reviewManifestBytes,
            cancellationToken).ConfigureAwait(false);
        return paths;
    }

    private static string CreateStagingDirectory(string outputFullPath, string purpose)
    {
        var parent = Path.GetDirectoryName(outputFullPath)
            ?? throw new CoordinatorValidationException("Output path has no parent directory.");
        Directory.CreateDirectory(parent);
        RejectExistingReparseComponents(parent, "Output parent");
        var stagingDirectory = Path.Combine(parent, $".{purpose}.{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDirectory);
        return stagingDirectory;
    }

    private static async Task<byte[]> ReadBoundedBytesAsync(
        string path,
        long maxBytes,
        string description,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        ExpertModelDatasetReviewReceiptTools.RejectReparsePathComponents(fullPath, description);
        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maxBytes)
        {
            throw new CoordinatorValidationException($"{description} exceeds the {maxBytes:N0}-byte input limit.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        try
        {
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            var trailing = new byte[1];
            if (await stream.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw new CoordinatorValidationException($"{description} changed while it was read.");
            }
            return bytes;
        }
        catch (EndOfStreamException exception)
        {
            throw new CoordinatorValidationException($"{description} changed while it was read: {exception.Message}");
        }
    }

    private static T DeserializeCanonical<T>(byte[] bytes, string description)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException($"{description} must be canonical BOM-less UTF-8 JSON.");
        }
        T value;
        try
        {
            value = JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException($"{description} must not be JSON null.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"{description} is invalid: {exception.Message}");
        }
        RequireExactBytes(bytes, SerializeCanonical(value), $"{description} must use canonical JSON encoding.");
        return value;
    }

    private static T DeserializeClosedJson<T>(
        byte[] bytes,
        string description,
        Action<JsonElement, string>? validateShape = null)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException($"{description} must be BOM-less UTF-8 JSON.");
        }
        try
        {
            _ = StrictUtf8.GetString(bytes);
            using var document = JsonDocument.Parse(bytes);
            RejectDuplicateJsonProperties(document.RootElement, description);
            validateShape?.Invoke(document.RootElement, description);
            return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException($"{description} must not be JSON null.");
        }
        catch (DecoderFallbackException exception)
        {
            throw new CoordinatorValidationException(
                $"{description} must be valid BOM-less UTF-8 JSON: {exception.Message}");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"{description} is invalid: {exception.Message}");
        }
    }

    private static void RejectDuplicateJsonProperties(JsonElement element, string description)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new CoordinatorValidationException(
                        $"{description} contains duplicate JSON property '{property.Name}'.");
                }
                RejectDuplicateJsonProperties(property.Value, description);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                RejectDuplicateJsonProperties(item, description);
            }
        }
    }

    private static void RequireDecisionDraftProperties(JsonElement root, string description)
    {
        RequireObjectProperties(
            root,
            description,
            "schemaVersion",
            "status",
            "authority",
            "packageId",
            "packageSha256",
            "reviewedDatasetSha256",
            "reviewer",
            "reviewBasis",
            "reviewedAtUtc",
            "rows",
            "sources");
        RequireObjectProperties(
            root.GetProperty("authority"),
            $"{description}.authority",
            "receiptAuthority",
            "trainingEligibilityAuthority",
            "providerUploadAuthority",
            "sftExportAuthority",
            "signingKeyAuthority",
            "modelReleaseAuthority",
            "evaluationAuthority",
            "promotionAuthority",
            "deploymentAuthority",
            "executionAuthority");
        RequireDecisionRows(root.GetProperty("rows"), $"{description}.rows");
        RequireDecisionSources(root.GetProperty("sources"), $"{description}.sources");
    }

    private static void RequireDecisionRows(JsonElement rows, string description)
    {
        if (rows.ValueKind != JsonValueKind.Array)
        {
            throw new CoordinatorValidationException($"{description} must be a JSON array.");
        }
        var index = 0;
        foreach (var row in rows.EnumerateArray())
        {
            var rowDescription = $"{description}[{index}]";
            RequireObjectProperties(row, rowDescription, "exampleId", "rights", "useForTraining", "evidenceIds");
            RequireRightsProperties(row.GetProperty("rights"), $"{rowDescription}.rights");
            index++;
        }
    }

    private static void RequireDecisionSources(JsonElement sources, string description)
    {
        if (sources.ValueKind != JsonValueKind.Array)
        {
            throw new CoordinatorValidationException($"{description} must be a JSON array.");
        }
        var index = 0;
        foreach (var source in sources.EnumerateArray())
        {
            var sourceDescription = $"{description}[{index}]";
            RequireObjectProperties(source, sourceDescription, "exampleId", "sourceId", "rights", "evidenceIds");
            RequireRightsProperties(source.GetProperty("rights"), $"{sourceDescription}.rights");
            index++;
        }
    }

    private static void RequireRightsProperties(JsonElement rights, string description) =>
        RequireObjectProperties(
            rights,
            description,
            "mayStore",
            "mayEvaluate",
            "mayTrain",
            "mayUploadToProvider",
            "mayRedistribute");

    private static void RequireObjectProperties(
        JsonElement element,
        string description,
        params string[] propertyNames)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new CoordinatorValidationException($"{description} must be a JSON object.");
        }
        foreach (var propertyName in propertyNames)
        {
            if (!element.TryGetProperty(propertyName, out _))
            {
                throw new CoordinatorValidationException(
                    $"{description} must contain JSON property '{propertyName}'.");
            }
        }
    }

    private static T DeserializeJson<T>(byte[] bytes, string description)
    {
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

    private static byte[] SerializeDataset(IReadOnlyList<ExpertModelDatasetExample> examples)
    {
        using var output = new MemoryStream();
        foreach (var example in examples)
        {
            var bytes = SerializeCanonical(example);
            if (bytes.LongLength + 1 > ExpertModelDatasetTools.MaxDatasetBytes - output.Length)
            {
                throw new CoordinatorValidationException("Rights-reviewed dataset exceeds the output size limit.");
            }
            output.Write(bytes);
            output.WriteByte((byte)'\n');
        }
        return output.ToArray();
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
        RejectExistingReparseComponents(parent, $"{description} parent");
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
            TryDeleteFile(temporary);
        }
    }

    private static void EnsureOutputAvailable(string path, string description)
    {
        var fullPath = Path.GetFullPath(path);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new CoordinatorValidationException($"{description} already exists; no file was replaced.");
        }
    }

    private static void EnsureDistinctPath(string outputPath, string inputPath)
    {
        if (StringComparer.OrdinalIgnoreCase.Equals(
                Path.GetFullPath(outputPath),
                Path.GetFullPath(inputPath)))
        {
            throw new CoordinatorValidationException("Review-handoff output must not overwrite an input file.");
        }
    }

    private static void EnsureDistinctPaths(
        string outputPath,
        string firstInputPath,
        string secondInputPath,
        string thirdInputPath,
        string fourthInputPath,
        string fifthInputPath,
        IEnumerable<string> additionalInputPaths)
    {
        EnsureDistinctPaths(
            outputPath,
            firstInputPath,
            secondInputPath,
            additionalInputPaths.Prepend(fifthInputPath).Prepend(fourthInputPath).Prepend(thirdInputPath));
    }

    private static void EnsureUniqueInputPaths(
        string draftDatasetPath,
        string reviewedDatasetPath,
        string verificationManifestPath,
        string verificationReportPath,
        string reviewManifestPath,
        IEnumerable<string> evidencePaths)
    {
        var paths = evidencePaths
            .Prepend(reviewManifestPath)
            .Prepend(verificationReportPath)
            .Prepend(verificationManifestPath)
            .Prepend(reviewedDatasetPath)
            .Prepend(draftDatasetPath)
            .Select(Path.GetFullPath)
            .ToArray();
        if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length)
        {
            throw new CoordinatorValidationException("Review-handoff inputs must use distinct files.");
        }
    }

    private static void EnsureUniquePaths(IEnumerable<string> inputPaths)
    {
        var paths = inputPaths.Select(Path.GetFullPath).ToArray();
        if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length)
        {
            throw new CoordinatorValidationException("Review-handoff inputs must use distinct files.");
        }
    }

    private static void EnsureDistinctPaths(
        string outputPath,
        string firstInputPath,
        string secondInputPath,
        IEnumerable<string> additionalInputPaths)
    {
        var output = Path.GetFullPath(outputPath);
        var inputs = additionalInputPaths.Prepend(secondInputPath).Prepend(firstInputPath);
        if (inputs.Any(input => StringComparer.OrdinalIgnoreCase.Equals(output, Path.GetFullPath(input))))
        {
            throw new CoordinatorValidationException("Review-handoff output must not overwrite an input file.");
        }
    }

    private static void RejectExistingReparseComponents(string fullPath, string description)
    {
        var root = Path.GetPathRoot(fullPath)
            ?? throw new CoordinatorValidationException($"{description} path has no filesystem root.");
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, fullPath)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!Directory.Exists(current) && !File.Exists(current))
            {
                break;
            }
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new CoordinatorValidationException($"{description} path must not traverse a reparse point.");
            }
        }
    }

    private static void RequireNoDownstreamAuthority(
        ExpertDatasetIndependentReviewAuthority authority,
        string description)
    {
        if (authority is null || authority != NoDownstreamAuthority)
        {
            throw new CoordinatorValidationException($"{description} must declare all downstream authority false.");
        }
    }

    private static void RequireValidDataset(
        ExpertModelDatasetTools.LoadedExpertDataset dataset,
        string description)
    {
        if (!dataset.Report.IsValid)
        {
            var issues = string.Join(
                " ",
                dataset.Report.Issues.Take(5).Select(issue =>
                    $"Line {issue.Line} ({issue.ExampleId ?? "?"}): {issue.Message}"));
            throw new CoordinatorValidationException($"{description} is invalid. {issues}");
        }
    }

    private static void RequireExactBytes(byte[] expected, byte[] actual, string message)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new CoordinatorValidationException(message);
        }
    }

    private static void RequireSha256(string? value, string description)
    {
        if (value is null || value.Length != 64 ||
            value.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new CoordinatorValidationException($"{description} must be a lowercase SHA-256 value.");
        }
    }

    private static bool IsSafeIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 200 &&
        IsAsciiLetterOrDigit(value[0]) &&
        value.All(character => IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':');

    private static bool IsSafePackagePath(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 500 &&
        !Path.IsPathRooted(value) &&
        !value.Contains('\\') &&
        value.Split('/').All(segment =>
            segment.Length > 0 && segment is not "." and not ".." &&
            segment.All(character => IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':'));

    private static bool IsSafeFileName(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 255 &&
        StringComparer.Ordinal.Equals(Path.GetFileName(value), value) &&
        value.All(character => IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static bool IsAsciiLetterOrDigit(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9';

    private static long? MaximumPackageFileSize(string id) => id switch
    {
        DraftFileId or ReviewedFileId => ExpertModelDatasetTools.MaxDatasetBytes,
        VerificationManifestFileId or ReviewManifestFileId => ExpertModelDatasetReviewTools.MaxManifestBytes,
        VerificationReportFileId => ExpertModelDatasetReviewTools.MaxVerificationReportBytes,
        _ when id.StartsWith(PackageEvidencePrefix, StringComparison.Ordinal) => MaxEvidenceFileBytes,
        _ => null
    };

    private static string SourceKey(string exampleId, string sourceId) => $"{exampleId}/{sourceId}";

    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void TryDeleteFile(string path)
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
            // Preserve the primary result.
        }
        catch (UnauthorizedAccessException)
        {
            // Preserve the primary result.
        }
    }

    internal static void DeleteStagingDirectory(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var name = Path.GetFileName(fullPath);
        var validPrefix = name.StartsWith(".prepare-review-handoff.", StringComparison.Ordinal) ||
                          name.StartsWith(".prepare-review-decision-template.", StringComparison.Ordinal) ||
                          name.StartsWith(".apply-review-handoff.", StringComparison.Ordinal) ||
                          name.StartsWith(".compile-review-decision.", StringComparison.Ordinal);
        var suffix = name[(name.LastIndexOf('.') + 1)..];
        if (!validPrefix || suffix.Length != 32 ||
            suffix.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new CoordinatorValidationException("Refusing to delete an unrecognized review-handoff staging path.");
        }
        try
        {
            if (Directory.Exists(fullPath))
            {
                Directory.Delete(fullPath, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CoordinatorValidationException(
                $"Review-handoff staging cleanup failed; no output was published: {exception.Message}");
        }
        if (Directory.Exists(fullPath))
        {
            throw new CoordinatorValidationException(
                "Review-handoff staging cleanup was incomplete; no output was published.");
        }
    }

    private sealed record CapturedEvidence(string Id, string FileName, byte[] Bytes);

    private sealed record ValidatedPackage(
        ExpertDatasetIndependentReviewPackage Package,
        string PackageSha256,
        byte[] ReviewedDatasetBytes,
        DateTimeOffset ContentReviewedAtUtc);

    private sealed record ReplayPaths(
        string DraftPath,
        string VerificationManifestPath,
        string VerificationReportPath,
        string ReviewManifestPath,
        string OutputPath);
}
