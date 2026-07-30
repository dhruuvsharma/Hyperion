using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Datasets;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageAdmissionEnvelope
{
    public required string SchemaVersion { get; init; }
    public required string PayloadType { get; init; }
    public required string PayloadEncoding { get; init; }
    public required string PayloadSha256 { get; init; }
    public required string Payload { get; init; }
    public required string Algorithm { get; init; }
    public required string SignatureFormat { get; init; }
    public required string Audience { get; init; }
    public required string KeyId { get; init; }
    public required string SignerRole { get; init; }
    public required string PublicKeySpkiSha256 { get; init; }
    public required string Signature { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageAdmissionPayload
{
    public required string SchemaVersion { get; init; }
    public required string LineageAdmissionId { get; init; }
    public required string Scope { get; init; }
    public required string Decision { get; init; }
    public required bool Reusable { get; init; }
    public required bool ReviewReceiptIssuanceAuthorized { get; init; }
    public required bool RuntimeAttested { get; init; }
    public required bool TeacherWeightsAttested { get; init; }
    public required bool TeacherCorrectnessAuthorized { get; init; }
    public required bool ReviewDecisionAuthorized { get; init; }
    public required bool RightsAuthorized { get; init; }
    public required bool ReleaseAuthorized { get; init; }
    public required bool TrainingAuthorized { get; init; }
    public required bool EvaluationAuthorized { get; init; }
    public required bool PromotionDecisionAuthorized { get; init; }
    public required bool DeploymentAuthorized { get; init; }
    public required bool HostedServingAuthorized { get; init; }
    public required bool InstallationAuthorized { get; init; }
    public required bool VerifierExecutionAuthorized { get; init; }
    public required bool StrategyExecutionAuthorized { get; init; }
    public required string ReviewerId { get; init; }
    public required string ReviewedAtUtc { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string NotBeforeUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public required ExpertTeacherLineageReviewerEvidence ReviewerEvidence { get; init; }
    public required ExpertTeacherLineageReviewedCorpus ReviewedCorpus { get; init; }
    public required ExpertTeacherLineageMaterialization Materialization { get; init; }
    public required ExpertTeacherLineageRuntimeObservation RuntimeObservation { get; init; }
    public required string Statement { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageReviewerEvidence
{
    public required string Sha256 { get; init; }
    public long SizeBytes { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageReviewedCorpus
{
    public required string Sha256 { get; init; }
    public long SizeBytes { get; init; }
    public int RecordCount { get; init; }
    public int OpenWeightTeacherRecordCount { get; init; }
    public required IReadOnlyList<ExpertTeacherLineageSubject> Subjects { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageSubject
{
    public required string ExampleId { get; init; }
    public required string StableSubjectSha256 { get; init; }
    public required string KnowledgeClass { get; init; }
    public required string TeacherAdmissionSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageMaterialization
{
    public required string MaterializationId { get; init; }
    public required string MaterializationRecordSha256 { get; init; }
    public required string DraftDatasetSha256 { get; init; }
    public long DraftDatasetSizeBytes { get; init; }
    public int DraftRecordCount { get; init; }
    public required string PackageTreeSchemaVersion { get; init; }
    public required string PackageTreeSha256 { get; init; }
    public int PackageFileCount { get; init; }
    public long PackageSizeBytes { get; init; }
    public required string SelectionManifestSha256 { get; init; }
    public required string CandidateSetSha256 { get; init; }
    public required string GenerationManifestSha256 { get; init; }
    public required string CandidateCatalogSha256 { get; init; }
    public required string OverlapDenySetSha256 { get; init; }
    public required string OverlapDenySetId { get; init; }
    public required string OverlapScopeSha256 { get; init; }
    public required string CandidateBatchId { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ExpertTeacherLineageRuntimeObservation
{
    public required string EvidenceStatus { get; init; }
    public required string RuntimeBindingFileSha256 { get; init; }
    public required string RuntimeBindingSha256 { get; init; }
    public required string CandidateCatalogSha256 { get; init; }
    public required string RuntimeDescriptorSha256 { get; init; }
    public required string ChatTemplateSha256 { get; init; }
    public required string ExecutionModelId { get; init; }
}

public sealed record ExpertTeacherLineageAdmissionTrust(
    string PublicKeyPath,
    string PublicKeySpkiSha256,
    string Audience,
    string KeyId,
    string SignerRole);

internal sealed record VerifiedExpertTeacherLineageAdmission(
    string LineageAdmissionId,
    string PayloadSha256,
    string EnvelopeSha256,
    string PublicKeySpkiSha256,
    string ReviewedCorpusSha256,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset ExpiresAtUtc);

internal static partial class ExpertModelTeacherLineageAdmissionTools
{
    internal const string EnvelopeSchemaVersion =
        "daxalgo.vibe-quant.teacher-materialization-lineage-admission-envelope/v1";
    internal const string PayloadSchemaVersion =
        "daxalgo.vibe-quant.teacher-materialization-lineage-admission/v1";
    internal const string Scope =
        "exact-open-weight-teacher-materialization-lineage-for-review-receipt-issuance-only";
    internal const string PayloadEncoding = "canonical-json-base64url";
    internal const string Algorithm = "ES256";
    internal const string SignatureFormat = "ieee-p1363-fixed-64-low-s";
    internal const string SubjectHashDomain = "daxalgo-vibe-quant-teacher-lineage-subject/v1";
    internal const string PackageTreeSchemaVersion =
        "daxalgo.vibe-quant.teacher-materialization-package-tree/v1";
    internal const string Statement =
        "This signed decision admits only the exact OpenWeightTeacher materialization lineage and exact reviewed-corpus bytes for review-receipt issuance. It binds an explicitly unattested runtime observation and does not attest runtime or weight identity, correctness, rights, review correctness, release, training, evaluation, promotion, deployment, hosted serving, installation, verifier execution, or strategy execution.";

    private const string AdmissionIdPrefix = "vqtlineage-";
    private const string SignatureDomain =
        "daxalgo-teacher-materialization-lineage-admission-signature/v1\0";
    private const string AdmissionIdDomain =
        "daxalgo-teacher-materialization-lineage-admission-id/v1\0";
    private const int MaxEnvelopeBytes = 12_000_000;
    private const int MaxPayloadBytes = 8_000_000;
    private const int MaxPublicKeyBytes = 1_000_000;
    private const int MaxReviewerEvidenceBytes = 16_000_000;
    private const int MaxMaterializationFiles = 100_100;
    private const long MaxMaterializationBytes = 512_000_000;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] P256Order = Convert.FromHexString(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly byte[] P256HalfOrder = Convert.FromHexString(
        "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifierRegex();

    [GeneratedRegex("^vqtlineage-[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex AdmissionIdRegex();

    [GeneratedRegex("^vqtmat-[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex MaterializationIdRegex();

    [GeneratedRegex("^vqtgen-[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex CandidateBatchIdRegex();

    [GeneratedRegex("^daxalgo-teacher-sha256-[0-9a-f]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex ExecutionModelIdRegex();

    internal static async Task<VerifiedExpertTeacherLineageAdmission> LoadAndVerifyAsync(
        string admissionPath,
        string datasetSha256,
        long datasetSizeBytes,
        IReadOnlyList<ExpertModelDatasetExample> examples,
        ExpertTeacherLineageAdmissionTrust trust,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(examples);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(timeProvider);
        RequireSha256(datasetSha256, "Teacher-lineage dataset SHA-256");
        if (datasetSizeBytes is < 1 or > ExpertModelDatasetTools.MaxDatasetBytes)
        {
            throw new CoordinatorValidationException("Teacher-lineage dataset size is invalid.");
        }
        ValidateTrust(trust);

        var teacherExamples = examples
            .Where(example => example.Lineage.Origin == ExpertDatasetOrigin.OpenWeightTeacher)
            .ToArray();
        if (teacherExamples.Length == 0)
        {
            throw new CoordinatorValidationException(
                "A teacher-lineage admission must not be supplied for a dataset without OpenWeightTeacher rows.");
        }
        if (teacherExamples.Length > 10_000)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission exceeds the OpenWeightTeacher row limit.");
        }

        var fullPath = Path.GetFullPath(admissionPath);
        ExpertModelDatasetReviewReceiptTools.RejectReparsePathComponents(
            fullPath,
            "Teacher-lineage admission");
        var fileBytes = await ReadBoundedFileAsync(
            fullPath,
            MaxEnvelopeBytes + 1,
            "Teacher-lineage admission",
            cancellationToken).ConfigureAwait(false);
        try
        {
            if (fileBytes.Length < 2 ||
                fileBytes[^1] != (byte)'\n' ||
                fileBytes[^2] is (byte)'\n' or (byte)'\r' ||
                fileBytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
            {
                throw new CoordinatorValidationException(
                    "Teacher-lineage admission must be BOM-less canonical JSON followed by exactly one LF.");
            }

            var envelopeBytes = fileBytes.AsSpan(0, fileBytes.Length - 1).ToArray();
            try
            {
                RequireCanonicalJson(envelopeBytes, "Teacher-lineage admission envelope");
                var envelope = DeserializeStrict<ExpertTeacherLineageAdmissionEnvelope>(
                    envelopeBytes,
                    "Teacher-lineage admission envelope");
                var publicKeySpki = ReadP256PublicKey(trust.PublicKeyPath);
                try
                {
                    var actualSpkiSha256 = Sha256Hex(publicKeySpki);
                    if (!FixedTimeEquals(actualSpkiSha256, trust.PublicKeySpkiSha256))
                    {
                        throw new CoordinatorValidationException(
                            "Teacher-lineage public key does not match the externally pinned SPKI SHA-256.");
                    }
                    ValidateEnvelope(envelope, trust, actualSpkiSha256);

                    var payloadBytes = DecodeCanonicalBase64Url(
                        envelope.Payload,
                        MaxPayloadBytes,
                        "Teacher-lineage admission payload");
                    try
                    {
                        var payloadSha256 = Sha256Hex(payloadBytes);
                        if (!FixedTimeEquals(payloadSha256, envelope.PayloadSha256))
                        {
                            throw new CoordinatorValidationException(
                                "Teacher-lineage payloadSha256 does not match the exact payload bytes.");
                        }
                        var signature = DecodeCanonicalBase64Url(
                            envelope.Signature,
                            64,
                            "Teacher-lineage admission signature",
                            exactLength: true);
                        try
                        {
                            VerifySignature(envelope, payloadBytes, signature, publicKeySpki);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(signature);
                        }

                        RequireCanonicalJson(payloadBytes, "Teacher-lineage admission payload");
                        var payload = DeserializeStrict<ExpertTeacherLineageAdmissionPayload>(
                            payloadBytes,
                            "Teacher-lineage admission payload");
                        var (notBefore, expiresAt) = ValidatePayload(
                            payload,
                            datasetSha256,
                            datasetSizeBytes,
                            examples,
                            teacherExamples,
                            timeProvider.GetUtcNow());
                        return new VerifiedExpertTeacherLineageAdmission(
                            payload.LineageAdmissionId,
                            payloadSha256,
                            Sha256Hex(envelopeBytes),
                            actualSpkiSha256,
                            payload.ReviewedCorpus.Sha256,
                            notBefore,
                            expiresAt);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(payloadBytes);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(publicKeySpki);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(envelopeBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    internal static string ComputeStableSubjectSha256(ExpertModelDatasetExample example)
    {
        ArgumentNullException.ThrowIfNull(example);
        if (example.Lineage.Origin != ExpertDatasetOrigin.OpenWeightTeacher)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage stable subjects require OpenWeightTeacher rows.");
        }

        var groups = new List<IReadOnlyList<string>>
        {
            new[]
            {
                "subject",
                RequiredText(example.SchemaVersion, "schemaVersion"),
                RequiredIdentifier(example.Id, "id"),
                example.TaskKind.ToString(),
                RequiredSha256(example.ConversationSha256, "conversationSha256"),
                RequiredText(example.Split, "split"),
                RequiredIdentifier(example.ContaminationGroup, "contaminationGroup"),
                RequiredText(example.Provenance, "provenance"),
                RequiredText(example.License, "license"),
                CanonicalSecond(example.CutoffUtc, "cutoffUtc"),
            },
            new[] { "domains" }.Concat(
                example.Domains.Select(domain => domain.ToString())).ToArray(),
        };
        for (var index = 0; index < example.Messages.Count; index++)
        {
            var message = example.Messages[index]
                ?? throw new CoordinatorValidationException("Teacher-lineage message must not be null.");
            groups.Add(new[]
            {
                "message",
                index.ToString(CultureInfo.InvariantCulture),
                RequiredText(message.Role, "message role"),
                RequiredText(message.Content, "message content"),
            });
        }
        for (var index = 0; index < example.Sources.Count; index++)
        {
            var source = example.Sources[index]
                ?? throw new CoordinatorValidationException("Teacher-lineage source must not be null.");
            groups.Add(new[]
            {
                "source",
                index.ToString(CultureInfo.InvariantCulture),
                RequiredText(source.Id, "source id"),
                RequiredText(source.Title, "source title"),
                RequiredText(source.Content, "source content"),
                RequiredText(source.Provenance, "source provenance"),
                RequiredText(source.License, "source license"),
                CanonicalSecond(source.RetrievedAtUtc, "source retrievedAtUtc"),
                CanonicalSecond(
                    source.AvailableAtUtc
                    ?? throw new CoordinatorValidationException(
                        "Teacher-lineage source availableAtUtc is required."),
                    "source availableAtUtc"),
                source.Uri is null ? "0" : "1",
                source.Uri ?? string.Empty,
            });
        }
        groups.Add(new[]
        {
            "lineage",
            "OpenWeightTeacher",
            RequiredText(example.Lineage.Producer, "lineage producer"),
            RequiredText(example.Lineage.ModelId, "lineage modelId"),
            RequiredText(example.Lineage.ModelRevision, "lineage modelRevision"),
            RequiredSha256(example.Lineage.PromptSha256, "lineage promptSha256"),
            RequiredText(example.Lineage.ProfileVersion, "lineage profileVersion"),
            CanonicalSecond(example.Lineage.ProducedAtUtc, "lineage producedAtUtc"),
        });

        using var framed = new MemoryStream();
        AppendText(framed, SubjectHashDomain);
        AppendInt32(framed, groups.Count);
        foreach (var group in groups)
        {
            AppendInt32(framed, group.Count);
            foreach (var value in group)
            {
                AppendText(framed, value);
            }
        }
        return Sha256Hex(framed.GetBuffer().AsSpan(0, checked((int)framed.Length)));
    }

    private static (DateTimeOffset NotBefore, DateTimeOffset ExpiresAt) ValidatePayload(
        ExpertTeacherLineageAdmissionPayload payload,
        string datasetSha256,
        long datasetSizeBytes,
        IReadOnlyList<ExpertModelDatasetExample> examples,
        IReadOnlyList<ExpertModelDatasetExample> teacherExamples,
        DateTimeOffset now)
    {
        if (payload.SchemaVersion != PayloadSchemaVersion ||
            payload.Scope != Scope ||
            payload.Decision != "admitted" ||
            !payload.Reusable ||
            !payload.ReviewReceiptIssuanceAuthorized ||
            payload.RuntimeAttested ||
            payload.TeacherWeightsAttested ||
            payload.TeacherCorrectnessAuthorized ||
            payload.ReviewDecisionAuthorized ||
            payload.RightsAuthorized ||
            payload.ReleaseAuthorized ||
            payload.TrainingAuthorized ||
            payload.EvaluationAuthorized ||
            payload.PromotionDecisionAuthorized ||
            payload.DeploymentAuthorized ||
            payload.HostedServingAuthorized ||
            payload.InstallationAuthorized ||
            payload.VerifierExecutionAuthorized ||
            payload.StrategyExecutionAuthorized ||
            payload.Statement != Statement)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission does not match the closed issuance-only authority contract.");
        }
        if (!AdmissionIdRegex().IsMatch(payload.LineageAdmissionId))
        {
            throw new CoordinatorValidationException("Teacher-lineage admission ID is invalid.");
        }
        RequireIdentifier(payload.ReviewerId, "Teacher-lineage reviewer ID");
        if (teacherExamples.Any(example =>
                example.Lineage.Producer == payload.ReviewerId ||
                example.Verification.Reviewer == payload.ReviewerId))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage reviewer must differ from the teacher producer and final row reviewers.");
        }
        var expectedId = ComputeAdmissionId(payload);
        if (!FixedTimeEquals(payload.LineageAdmissionId, expectedId))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission ID does not match its canonical content.");
        }

        var reviewedAt = ParseCanonicalUtc(payload.ReviewedAtUtc, "reviewedAtUtc");
        var issuedAt = ParseCanonicalUtc(payload.IssuedAtUtc, "issuedAtUtc");
        var notBefore = ParseCanonicalUtc(payload.NotBeforeUtc, "notBeforeUtc");
        var expiresAt = ParseCanonicalUtc(payload.ExpiresAtUtc, "expiresAtUtc");
        if (reviewedAt > issuedAt ||
            issuedAt > notBefore ||
            notBefore >= expiresAt ||
            expiresAt - notBefore > TimeSpan.FromDays(366) ||
            now < notBefore ||
            now >= expiresAt)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission validity window is invalid or inactive.");
        }
        if (teacherExamples.Any(example =>
                !example.Verification.Verified ||
                example.Verification.VerifiedAtUtc is not { } verifiedAt ||
                verifiedAt > reviewedAt ||
                example.Lineage.ProducedAtUtc > reviewedAt))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission review time must not precede teacher production or final row review.");
        }

        var reviewerEvidence = payload.ReviewerEvidence
            ?? throw new CoordinatorValidationException("Teacher-lineage reviewer evidence is required.");
        RequireSha256(reviewerEvidence.Sha256, "Teacher-lineage reviewer-evidence SHA-256");
        RequireRange(
            reviewerEvidence.SizeBytes,
            1,
            MaxReviewerEvidenceBytes,
            "Teacher-lineage reviewer-evidence size");

        var corpus = payload.ReviewedCorpus
            ?? throw new CoordinatorValidationException("Teacher-lineage reviewed corpus is required.");
        RequireSha256(corpus.Sha256, "Teacher-lineage reviewed-corpus SHA-256");
        if (!FixedTimeEquals(corpus.Sha256, datasetSha256) ||
            corpus.SizeBytes != datasetSizeBytes ||
            corpus.RecordCount != examples.Count ||
            corpus.OpenWeightTeacherRecordCount != teacherExamples.Count ||
            corpus.Subjects is null ||
            corpus.Subjects.Count != teacherExamples.Count)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission does not bind the exact reviewed dataset snapshot.");
        }
        var seenSubjects = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < teacherExamples.Count; index++)
        {
            var example = teacherExamples[index];
            var subject = corpus.Subjects[index]
                ?? throw new CoordinatorValidationException("Teacher-lineage subject must not be null.");
            var (knowledgeClass, teacherAdmissionSha256) = ReadTeacherAnchors(example);
            RequireIdentifier(subject.ExampleId, "Teacher-lineage subject example ID");
            RequireSha256(subject.StableSubjectSha256, "Teacher-lineage stable-subject SHA-256");
            RequireSha256(subject.TeacherAdmissionSha256, "Teacher-lineage teacher-admission SHA-256");
            if (!seenSubjects.Add(subject.ExampleId) ||
                subject.ExampleId != example.Id ||
                !FixedTimeEquals(subject.StableSubjectSha256, ComputeStableSubjectSha256(example)) ||
                subject.KnowledgeClass != knowledgeClass ||
                !FixedTimeEquals(subject.TeacherAdmissionSha256, teacherAdmissionSha256))
            {
                throw new CoordinatorValidationException(
                    "Teacher-lineage admission subjects do not match the exact ordered OpenWeightTeacher rows.");
            }
        }

        ValidateMaterialization(payload.Materialization);
        ValidateRuntimeObservation(payload.RuntimeObservation, payload.Materialization);
        return (notBefore, expiresAt);
    }

    private static void ValidateMaterialization(ExpertTeacherLineageMaterialization materialization)
    {
        if (materialization is null ||
            !MaterializationIdRegex().IsMatch(materialization.MaterializationId) ||
            materialization.PackageTreeSchemaVersion != PackageTreeSchemaVersion ||
            !CandidateBatchIdRegex().IsMatch(materialization.CandidateBatchId))
        {
            throw new CoordinatorValidationException("Teacher-lineage materialization identity is invalid.");
        }
        foreach (var (value, label) in new[]
                 {
                     (materialization.MaterializationRecordSha256, "materialization-record"),
                     (materialization.DraftDatasetSha256, "draft-dataset"),
                     (materialization.PackageTreeSha256, "package-tree"),
                     (materialization.SelectionManifestSha256, "selection-manifest"),
                     (materialization.CandidateSetSha256, "candidate-set"),
                     (materialization.GenerationManifestSha256, "generation-manifest"),
                     (materialization.CandidateCatalogSha256, "candidate-catalog"),
                     (materialization.OverlapDenySetSha256, "overlap-deny-set"),
                     (materialization.OverlapScopeSha256, "overlap-scope"),
                 })
        {
            RequireSha256(value, $"Teacher-lineage {label} SHA-256");
        }
        RequireIdentifier(materialization.OverlapDenySetId, "Teacher-lineage overlap deny-set ID");
        RequireRange(
            materialization.DraftDatasetSizeBytes,
            1,
            ExpertModelDatasetTools.MaxDatasetBytes,
            "Teacher-lineage draft-dataset size");
        RequireRange(materialization.DraftRecordCount, 1, 10_000, "Teacher-lineage draft-record count");
        RequireRange(
            materialization.PackageFileCount,
            1,
            MaxMaterializationFiles,
            "Teacher-lineage package-file count");
        RequireRange(
            materialization.PackageSizeBytes,
            1,
            MaxMaterializationBytes,
            "Teacher-lineage package size");
    }

    private static void ValidateRuntimeObservation(
        ExpertTeacherLineageRuntimeObservation runtime,
        ExpertTeacherLineageMaterialization materialization)
    {
        if (runtime is null ||
            runtime.EvidenceStatus != "unattested-observation" ||
            !ExecutionModelIdRegex().IsMatch(runtime.ExecutionModelId))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage runtime binding must remain an unattested observation.");
        }
        foreach (var (value, label) in new[]
                 {
                     (runtime.RuntimeBindingFileSha256, "runtime-binding file"),
                     (runtime.RuntimeBindingSha256, "runtime-binding"),
                     (runtime.CandidateCatalogSha256, "runtime candidate-catalog"),
                     (runtime.RuntimeDescriptorSha256, "runtime-descriptor"),
                     (runtime.ChatTemplateSha256, "chat-template"),
                 })
        {
            RequireSha256(value, $"Teacher-lineage {label} SHA-256");
        }
        if (!FixedTimeEquals(
                runtime.CandidateCatalogSha256,
                materialization.CandidateCatalogSha256))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage runtime candidate catalog does not match the materialization.");
        }
    }

    private static (string KnowledgeClass, string TeacherAdmissionSha256) ReadTeacherAnchors(
        ExpertModelDatasetExample example)
    {
        var knowledge = example.Verification.Evidence
            .Where(value => value.StartsWith("knowledgeClass=", StringComparison.Ordinal))
            .ToArray();
        var admissions = example.Verification.Evidence
            .Where(value => value.StartsWith("teacherAdmissionSha256=", StringComparison.Ordinal))
            .ToArray();
        if (knowledge.Length != 1 ||
            knowledge[0] is not ("knowledgeClass=candidate-stable" or "knowledgeClass=retrieval-only") ||
            admissions.Length != 1)
        {
            throw new CoordinatorValidationException(
                $"OpenWeightTeacher example '{example.Id}' lacks exact materialization anchors.");
        }
        var admissionSha256 = admissions[0]["teacherAdmissionSha256=".Length..];
        RequireSha256(admissionSha256, "Teacher materialization-admission SHA-256");
        return (knowledge[0]["knowledgeClass=".Length..], admissionSha256);
    }

    private static string ComputeAdmissionId(ExpertTeacherLineageAdmissionPayload payload)
    {
        var zeroed = payload with { LineageAdmissionId = AdmissionIdPrefix + new string('0', 64) };
        var canonical = ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(zeroed);
        try
        {
            var domain = StrictUtf8.GetBytes(AdmissionIdDomain);
            var input = new byte[domain.Length + canonical.Length];
            domain.CopyTo(input, 0);
            canonical.CopyTo(input, domain.Length);
            try
            {
                return AdmissionIdPrefix + Sha256Hex(input);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private static void ValidateTrust(ExpertTeacherLineageAdmissionTrust trust)
    {
        if (string.IsNullOrWhiteSpace(trust.PublicKeyPath))
        {
            throw new CoordinatorValidationException("Teacher-lineage public-key path is required.");
        }
        RequireSha256(trust.PublicKeySpkiSha256, "Teacher-lineage public-key SPKI SHA-256");
        RequireIdentifier(trust.Audience, "Teacher-lineage audience");
        RequireIdentifier(trust.KeyId, "Teacher-lineage key ID");
        RequireIdentifier(trust.SignerRole, "Teacher-lineage signer role");
    }

    private static void ValidateEnvelope(
        ExpertTeacherLineageAdmissionEnvelope envelope,
        ExpertTeacherLineageAdmissionTrust trust,
        string actualSpkiSha256)
    {
        if (envelope.SchemaVersion != EnvelopeSchemaVersion ||
            envelope.PayloadType != PayloadSchemaVersion ||
            envelope.PayloadEncoding != PayloadEncoding ||
            envelope.Algorithm != Algorithm ||
            envelope.SignatureFormat != SignatureFormat)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission envelope contract is unsupported.");
        }
        RequireSha256(envelope.PayloadSha256, "Teacher-lineage payload SHA-256");
        RequireSha256(envelope.PublicKeySpkiSha256, "Teacher-lineage public-key SPKI SHA-256");
        if (envelope.Audience != trust.Audience ||
            envelope.KeyId != trust.KeyId ||
            envelope.SignerRole != trust.SignerRole ||
            !FixedTimeEquals(envelope.PublicKeySpkiSha256, actualSpkiSha256))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission envelope does not match the externally pinned trust policy.");
        }
    }

    private static void VerifySignature(
        ExpertTeacherLineageAdmissionEnvelope envelope,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKeySpki)
    {
        if (signature.Length != 64 ||
            !IsP256Scalar(signature[..32]) ||
            !IsP256Scalar(signature[32..]) ||
            CompareBigEndian(signature[32..], P256HalfOrder) > 0)
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage signature must be a canonical low-S P1363 signature.");
        }

        using var input = new MemoryStream();
        AppendUInt64(input, StrictUtf8.GetBytes(SignatureDomain));
        foreach (var value in new[]
                 {
                     envelope.SchemaVersion,
                     envelope.PayloadType,
                     envelope.PayloadEncoding,
                     envelope.Algorithm,
                     envelope.SignatureFormat,
                     envelope.Audience,
                     envelope.KeyId,
                     envelope.SignerRole,
                     envelope.PublicKeySpkiSha256,
                     envelope.PayloadSha256,
                 })
        {
            AppendUInt64(input, StrictUtf8.GetBytes(value));
        }
        AppendUInt64(input, payload);
        var framed = input.ToArray();
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKeySpki, out var bytesRead);
            var parameters = verifier.ExportParameters(includePrivateParameters: false);
            if (bytesRead != publicKeySpki.Length ||
                parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value ||
                parameters.Q.X is not { Length: 32 } ||
                parameters.Q.Y is not { Length: 32 } ||
                !verifier.VerifyData(
                    framed,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new CoordinatorValidationException("Teacher-lineage admission signature is invalid.");
            }
        }
        catch (CryptographicException)
        {
            throw new CoordinatorValidationException("Teacher-lineage admission signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(framed);
        }
    }

    private static async Task<byte[]> ReadBoundedFileAsync(
        string path,
        int maximumBytes,
        string label,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var length = stream.Length;
        if (length is < 1 || length > maximumBytes)
        {
            throw new CoordinatorValidationException(
                $"{label} size must be between 1 and {maximumBytes:N0} bytes.");
        }
        var bytes = new byte[checked((int)length)];
        try
        {
            await stream.ReadExactlyAsync(bytes.AsMemory(), cancellationToken).ConfigureAwait(false);
            var trailing = new byte[1];
            if (await stream.ReadAsync(trailing, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw new CoordinatorValidationException($"{label} changed while it was read.");
            }
            return bytes;
        }
        catch (EndOfStreamException exception)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new CoordinatorValidationException($"{label} changed while it was read: {exception.Message}");
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private static byte[] ReadP256PublicKey(string path)
    {
        var fullPath = Path.GetFullPath(path);
        ExpertModelDatasetReviewReceiptTools.RejectReparsePathComponents(
            fullPath,
            "Teacher-lineage public key");
        var bytes = ReadBoundedFile(
            fullPath,
            MaxPublicKeyBytes,
            "Teacher-lineage public key");
        try
        {
            if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
            {
                throw new CoordinatorValidationException(
                    "Teacher-lineage public key must be bounded BOM-less PEM.");
            }
            var pem = StrictUtf8.GetString(bytes);
            var pemSpan = pem.AsSpan();
            if (!PemEncoding.TryFind(pemSpan, out var fields) ||
                !pemSpan[fields.Label].SequenceEqual("PUBLIC KEY") ||
                !pemSpan[..fields.Location.Start.GetOffset(pemSpan.Length)].Trim().IsEmpty ||
                !pemSpan[fields.Location.End.GetOffset(pemSpan.Length)..].Trim().IsEmpty)
            {
                throw new CoordinatorValidationException(
                    "Teacher-lineage public key must contain exactly one public P-256 SPKI PEM block.");
            }
            using var key = ECDsa.Create();
            key.ImportFromPem(pemSpan[fields.Location]);
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value ||
                parameters.Q.X is not { Length: 32 } ||
                parameters.Q.Y is not { Length: 32 })
            {
                throw new CoordinatorValidationException(
                    "Teacher-lineage public key must be P-256 SPKI.");
            }
            return key.ExportSubjectPublicKeyInfo();
        }
        catch (DecoderFallbackException)
        {
            throw new CoordinatorValidationException("Teacher-lineage public key must be valid UTF-8 PEM.");
        }
        catch (CryptographicException)
        {
            throw new CoordinatorValidationException("Teacher-lineage public key must be P-256 SPKI.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static byte[] ReadBoundedFile(string path, int maximumBytes, string label)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        var length = stream.Length;
        if (length is < 1 || length > maximumBytes)
        {
            throw new CoordinatorValidationException(
                $"{label} size must be between 1 and {maximumBytes:N0} bytes.");
        }
        var bytes = new byte[checked((int)length)];
        try
        {
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1)
            {
                throw new CoordinatorValidationException($"{label} changed while it was read.");
            }
            return bytes;
        }
        catch (EndOfStreamException exception)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new CoordinatorValidationException($"{label} changed while it was read: {exception.Message}");
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private static T DeserializeStrict<T>(byte[] bytes, string label)
    {
        try
        {
            _ = StrictUtf8.GetString(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new CoordinatorValidationException($"{label} must be a JSON object.");
            }
            ValidateNoDuplicateProperties(document.RootElement, label);
            return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException($"{label} was JSON null.");
        }
        catch (DecoderFallbackException)
        {
            throw new CoordinatorValidationException($"{label} must be valid UTF-8.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"{label} JSON is invalid: {exception.Message}");
        }
    }

    private static void RequireCanonicalJson(byte[] bytes, string label)
    {
        try
        {
            _ = StrictUtf8.GetString(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            ValidateNoDuplicateProperties(document.RootElement, label);
            var canonical = ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(
                document.RootElement);
            try
            {
                if (!bytes.AsSpan().SequenceEqual(canonical))
                {
                    throw new CoordinatorValidationException($"{label} is not canonical JSON.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
        catch (DecoderFallbackException)
        {
            throw new CoordinatorValidationException($"{label} must be valid UTF-8.");
        }
        catch (JsonException)
        {
            throw new CoordinatorValidationException($"{label} JSON is invalid.");
        }
    }

    private static void ValidateNoDuplicateProperties(JsonElement element, string label)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new CoordinatorValidationException($"{label} contains duplicate properties.");
                }
                ValidateNoDuplicateProperties(property.Value, label);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item, label);
            }
        }
    }

    private static byte[] DecodeCanonicalBase64Url(
        string value,
        int maximumBytes,
        string label,
        bool exactLength = false)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length > checked(maximumBytes * 2) ||
            value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new CoordinatorValidationException($"{label} is not canonical base64url.");
        }
        byte[] decoded;
        try
        {
            var base64 = value.Replace('-', '+').Replace('_', '/');
            base64 += new string('=', (4 - base64.Length % 4) % 4);
            decoded = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new CoordinatorValidationException($"{label} is not canonical base64url.");
        }
        if ((exactLength ? decoded.Length != maximumBytes : decoded.Length > maximumBytes) ||
            value != EncodeBase64Url(decoded))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new CoordinatorValidationException($"{label} is not canonical base64url.");
        }
        return decoded;
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static DateTimeOffset ParseCanonicalUtc(string value, string label)
    {
        if (!DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed) ||
            value != ExpertModelDatasetReviewReceiptTools.CanonicalUtc(parsed))
        {
            throw new CoordinatorValidationException(
                $"Teacher-lineage {label} is not canonical UTC-second time.");
        }
        return parsed;
    }

    private static string CanonicalSecond(DateTimeOffset value, string label)
    {
        if (value == default || value.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new CoordinatorValidationException(
                $"Teacher-lineage {label} must use whole-second precision.");
        }
        return ExpertModelDatasetReviewReceiptTools.CanonicalUtc(value);
    }

    private static string RequiredText(string? value, string label)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new CoordinatorValidationException($"Teacher-lineage {label} is required.");
        }
        return value;
    }

    private static string RequiredIdentifier(string? value, string label)
    {
        RequireIdentifier(value, $"Teacher-lineage {label}");
        return value!;
    }

    private static string RequiredSha256(string? value, string label)
    {
        RequireSha256(value, $"Teacher-lineage {label}");
        return value!;
    }

    private static void RequireIdentifier(string? value, string label)
    {
        if (value is null || !SafeIdentifierRegex().IsMatch(value))
        {
            throw new CoordinatorValidationException($"{label} is invalid.");
        }
    }

    private static void RequireSha256(string? value, string label)
    {
        if (value is null || value.Length != 64 ||
            value.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new CoordinatorValidationException($"{label} must be a lowercase SHA-256 value.");
        }
    }

    private static void RequireRange(long value, long minimum, long maximum, string label)
    {
        if (value < minimum || value > maximum)
        {
            throw new CoordinatorValidationException($"{label} is outside its allowed range.");
        }
    }

    private static bool FixedTimeEquals(string? left, string? right)
    {
        if (left is null || right is null || left.Length != right.Length)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(
            StrictUtf8.GetBytes(left),
            StrictUtf8.GetBytes(right));
    }

    private static string Sha256Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private static bool IsP256Scalar(ReadOnlySpan<byte> value) =>
        value.Length == 32 &&
        value.IndexOfAnyExcept((byte)0) >= 0 &&
        CompareBigEndian(value, P256Order) < 0;

    private static int CompareBigEndian(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        for (var index = 0; index < left.Length; index++)
        {
            if (left[index] != right[index])
            {
                return left[index].CompareTo(right[index]);
            }
        }
        return left.Length.CompareTo(right.Length);
    }

    private static void AppendInt32(Stream output, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        output.Write(bytes);
    }

    private static void AppendText(Stream output, string value)
    {
        var bytes = StrictUtf8.GetBytes(value);
        AppendInt32(output, bytes.Length);
        output.Write(bytes);
    }

    private static void AppendUInt64(Stream output, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)value.Length));
        output.Write(length);
        output.Write(value);
    }
}
