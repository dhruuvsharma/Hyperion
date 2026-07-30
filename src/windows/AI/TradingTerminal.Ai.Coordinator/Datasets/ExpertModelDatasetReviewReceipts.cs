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
public sealed record ExpertDatasetReviewReceiptEnvelope
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
public sealed record ExpertDatasetReviewReceiptPayload
{
    public required string SchemaVersion { get; init; }
    public required string ReceiptId { get; init; }
    public required string Decision { get; init; }
    public required string SourceCorpusSha256 { get; init; }
    public required string ExampleId { get; init; }
    public required string TaskKind { get; init; }
    public required IReadOnlyList<string> Domains { get; init; }
    public required string ConversationSha256 { get; init; }
    public required string VerificationEvidenceSha256 { get; init; }
    public required string ReviewedAtUtc { get; init; }
    public required string Reviewer { get; init; }
    public required string ReviewKind { get; init; }
    public required string SftMetadataSha256 { get; init; }
    public required ExpertDatasetReviewReceiptAuthorizations Authorizations { get; init; }
    public required ExpertDatasetReviewReceiptApproval Approval { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string NotBeforeUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ExpertDatasetReviewReceiptAuthorizations
{
    public required bool Evaluation { get; init; }
    public required bool Training { get; init; }
    public required bool ProviderUpload { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ExpertDatasetReviewReceiptApproval
{
    public required string ApprovalId { get; init; }
    public required string ActorId { get; init; }
    public required string ActorRole { get; init; }
    public required string Reference { get; init; }
    public required string EvidenceSha256 { get; init; }
    public long EvidenceSizeBytes { get; init; }
    public required string ApprovedAtUtc { get; init; }
}

public sealed record ExpertDatasetReviewReceiptTrust(
    string PublicKeyPath,
    string PublicKeySpkiSha256,
    string Audience,
    string KeyId,
    string SignerRole);

internal sealed record ExpertDatasetReviewReceiptSubject(
    ExpertModelDatasetExample Example,
    string SftMetadataSha256);

internal sealed record ExpertDatasetReviewReceiptIdentity(
    string ReceiptId,
    string PayloadSha256,
    string EnvelopeSha256,
    string PublicKeySpkiSha256,
    bool TrainingAuthorized,
    bool ProviderUploadAuthorized,
    DateTimeOffset ExpiresAtUtc,
    ExpertDatasetReviewReceiptEnvelope Envelope);

public static partial class ExpertModelDatasetReviewReceiptTools
{
    public const string EnvelopeSchemaVersion =
        "daxalgo.expert-model-review-receipt-envelope/v2";
    public const string PayloadSchemaVersion =
        "daxalgo.expert-model-review-receipt/v2";
    public const string SftMetadataSchemaVersion =
        "daxalgo.expert-model-sft-metadata/v2";
    public const string PayloadEncoding = "canonical-json-base64url";
    public const string Algorithm = "ES256";
    public const string SignatureFormat = "ieee-p1363-fixed-64-low-s";
    public const string SignatureDomain =
        "daxalgo-expert-model-review-receipt-signature/v2";
    public const string ReceiptIdDomain =
        "daxalgo-expert-model-review-receipt-id/v2";
    public const string ReceiptIdPrefix = "vqreview-";
    public const string ApprovedDecision = "approved";
    public const string DaxqReviewKind = "daxq-executable";
    public const string DeterministicTextReviewKind = "deterministic-text";
    public const int MaxReceiptSetBytes = 256_000_000;
    public const int MaxReceiptLineBytes = 256_000;
    public const int MaxReceiptPayloadBytes = 128_000;
    public const int MaxPublicKeyBytes = 1_000_000;
    public const int MaxApprovalReferenceCharacters = 500;
    public const long MaxApprovalEvidenceBytes = 16_000_000;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] P256Order = Convert.FromHexString(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly byte[] P256HalfOrder = Convert.FromHexString(
        "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");
    private static readonly string ZeroReceiptId = ReceiptIdPrefix + new string('0', 64);
    private static readonly JsonSerializerOptions CanonicalSerializationJson =
        CreateCanonicalSerializationJson();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdentifierRegex();

    internal static Task<IReadOnlyDictionary<string, ExpertDatasetReviewReceiptIdentity>>
        LoadAndVerifyAsync(
            string receiptSetPath,
            string sourceCorpusSha256,
            IReadOnlyList<ExpertDatasetReviewReceiptSubject> subjects,
            ExpertDatasetReviewReceiptTrust trust,
            TimeProvider timeProvider,
            CancellationToken cancellationToken) =>
        LoadAndVerifyAsync(
            receiptSetPath,
            sourceCorpusSha256,
            subjects,
            trust,
            teacherLineageAdmission: null,
            timeProvider,
            cancellationToken);

    internal static async Task<IReadOnlyDictionary<string, ExpertDatasetReviewReceiptIdentity>>
        LoadAndVerifyAsync(
            string receiptSetPath,
            string sourceCorpusSha256,
            IReadOnlyList<ExpertDatasetReviewReceiptSubject> subjects,
            ExpertDatasetReviewReceiptTrust trust,
            VerifiedExpertTeacherLineageAdmission? teacherLineageAdmission,
            TimeProvider timeProvider,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subjects);
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(timeProvider);
        RequireSha256(sourceCorpusSha256, "Source-corpus SHA-256");
        ValidateTrust(trust);
        foreach (var subject in subjects)
        {
            var example = subject.Example;
            var teacherAdmissionAnchorCount = example.Verification.Evidence.Count(
                value => value.StartsWith("teacherAdmissionSha256=", StringComparison.Ordinal));
            var isOpenWeightTeacher =
                example.Lineage.Origin == ExpertDatasetOrigin.OpenWeightTeacher;
            if (isOpenWeightTeacher && teacherAdmissionAnchorCount != 1)
            {
                throw new CoordinatorValidationException(
                    $"OpenWeightTeacher example '{example.Id}' must carry exactly one teacherAdmissionSha256 anchor.");
            }
            if (!isOpenWeightTeacher && teacherAdmissionAnchorCount != 0)
            {
                throw new CoordinatorValidationException(
                    $"Non-OpenWeightTeacher example '{example.Id}' must not carry a teacherAdmissionSha256 anchor.");
            }
        }
        var containsOpenWeightTeacher = subjects.Any(
            subject => subject.Example.Lineage.Origin == ExpertDatasetOrigin.OpenWeightTeacher);
        if (containsOpenWeightTeacher && teacherLineageAdmission is null)
        {
            throw new CoordinatorValidationException(
                "OpenWeightTeacher review receipts require a separately authenticated teacher-lineage admission.");
        }
        if (!containsOpenWeightTeacher && teacherLineageAdmission is not null)
        {
            throw new CoordinatorValidationException(
                "A teacher-lineage admission must not be supplied for a dataset without OpenWeightTeacher rows.");
        }
        if (teacherLineageAdmission is not null &&
            !FixedTimeEquals(teacherLineageAdmission.ReviewedCorpusSha256, sourceCorpusSha256))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission does not bind the review-receipt dataset.");
        }
        if (teacherLineageAdmission is not null &&
            FixedTimeEquals(
                teacherLineageAdmission.PublicKeySpkiSha256,
                trust.PublicKeySpkiSha256))
        {
            throw new CoordinatorValidationException(
                "Teacher-lineage admission and review receipts must use distinct signing authorities.");
        }

        var publicKeySpki = ReadP256PublicKey(trust.PublicKeyPath);
        try
        {
            var publicKeySpkiSha256 = Sha256Hex(publicKeySpki);
            if (!FixedTimeEquals(publicKeySpkiSha256, trust.PublicKeySpkiSha256))
            {
                throw new CoordinatorValidationException(
                    "The review-receipt public key does not match the externally pinned SPKI SHA-256.");
            }

            var receipts = new Dictionary<string, ExpertDatasetReviewReceiptIdentity>(StringComparer.Ordinal);
            var fullPath = Path.GetFullPath(receiptSetPath);
            RejectReparsePathComponents(fullPath, "Review-receipt set");
            var receiptSetBytes = await ReadBoundedFileAsync(
                fullPath,
                MaxReceiptSetBytes,
                "Review-receipt set",
                cancellationToken).ConfigureAwait(false);
            try
            {
                if (receiptSetBytes[^1] != (byte)'\n')
                {
                    throw new CoordinatorValidationException(
                        "Every review-receipt line must end with exactly LF, including the final line.");
                }
                if (receiptSetBytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
                {
                    throw new CoordinatorValidationException(
                        "Review-receipt set must be BOM-less UTF-8 JSONL.");
                }

                var lineStart = 0;
                var lineNumber = 0;
                var receiptIndex = 0;
                var now = timeProvider.GetUtcNow();
                while (lineStart < receiptSetBytes.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var lineEnd = Array.IndexOf(receiptSetBytes, (byte)'\n', lineStart);
                    if (lineEnd < 0)
                    {
                        throw new CoordinatorValidationException(
                            "Every review-receipt line must end with exactly LF.");
                    }
                    lineNumber++;
                    var lineLength = lineEnd - lineStart;
                    if (lineLength == 0)
                    {
                        throw new CoordinatorValidationException(
                            $"Review-receipt line {lineNumber} must not be blank.");
                    }
                    if (receiptSetBytes[lineEnd - 1] == (byte)'\r')
                    {
                        throw new CoordinatorValidationException(
                            $"Review-receipt line {lineNumber} must end with LF, not CRLF.");
                    }
                    if (lineLength > MaxReceiptLineBytes)
                    {
                        throw new CoordinatorValidationException(
                            $"Review-receipt line {lineNumber} exceeds the byte limit.");
                    }
                    if (receiptIndex >= subjects.Count)
                    {
                        throw new CoordinatorValidationException(
                            "Review-receipt set contains more rows than the dataset.");
                    }

                    var envelopeBytes = receiptSetBytes.AsSpan(lineStart, lineLength).ToArray();
                    try
                    {
                        string line;
                        try
                        {
                            line = StrictUtf8.GetString(envelopeBytes);
                        }
                        catch (DecoderFallbackException exception)
                        {
                            throw new CoordinatorValidationException(
                                $"Review-receipt set must be valid UTF-8: {exception.Message}");
                        }
                        if (string.IsNullOrWhiteSpace(line))
                        {
                            throw new CoordinatorValidationException(
                                $"Review-receipt line {lineNumber} must not be blank.");
                        }
                        RequireCanonicalJson(envelopeBytes, $"review-receipt line {lineNumber}");
                        var envelope = DeserializeStrict<ExpertDatasetReviewReceiptEnvelope>(
                            envelopeBytes,
                            $"review-receipt line {lineNumber}");
                        ValidateEnvelope(envelope, trust, publicKeySpkiSha256);
                        var payloadBytes = DecodeCanonicalBase64Url(
                            envelope.Payload,
                            MaxReceiptPayloadBytes,
                            "review-receipt payload");
                        try
                        {
                            var payloadSha256 = Sha256Hex(payloadBytes);
                            if (!FixedTimeEquals(payloadSha256, envelope.PayloadSha256))
                            {
                                throw new CoordinatorValidationException(
                                    "Review-receipt payloadSha256 does not match the exact payload bytes.");
                            }

                            var signature = DecodeCanonicalBase64Url(
                                envelope.Signature,
                                64,
                                "review-receipt signature",
                                exactLength: true);
                            try
                            {
                                VerifySignature(envelope, payloadBytes, signature, publicKeySpki);
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(signature);
                            }

                            RequireCanonicalJson(payloadBytes, "review-receipt payload");
                            var payload = DeserializeStrict<ExpertDatasetReviewReceiptPayload>(
                                payloadBytes,
                                "review-receipt payload");
                            var subject = subjects[receiptIndex];
                            if (payload.ExampleId != subject.Example.Id)
                            {
                                throw new CoordinatorValidationException(
                                    $"Review-receipt line {lineNumber} does not match dataset row order.");
                            }
                            if (receipts.ContainsKey(payload.ExampleId))
                            {
                                throw new CoordinatorValidationException(
                                    $"Review receipt for example '{payload.ExampleId}' is duplicated.");
                            }

                            var (_, receiptExpiresAt) = ValidatePayload(
                                payload,
                                envelope,
                                sourceCorpusSha256,
                                subject,
                                teacherLineageAdmission,
                                now);
                            receipts.Add(
                                payload.ExampleId,
                                new ExpertDatasetReviewReceiptIdentity(
                                    payload.ReceiptId,
                                    payloadSha256,
                                    Sha256Hex(envelopeBytes),
                                    publicKeySpkiSha256,
                                    payload.Authorizations.Training,
                                    payload.Authorizations.ProviderUpload,
                                    receiptExpiresAt,
                                    envelope));
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(payloadBytes);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(envelopeBytes);
                    }
                    receiptIndex++;
                    lineStart = lineEnd + 1;
                }

                if (receipts.Count != subjects.Count)
                {
                    var missing = subjects[receipts.Count].Example.Id;
                    throw new CoordinatorValidationException(
                        $"Review receipt is missing for dataset example '{missing}'.");
                }
                return receipts;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(receiptSetBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeySpki);
        }
    }

    public static string ComputeReceiptId(ExpertDatasetReviewReceiptPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var zeroed = payload with { ReceiptId = ZeroReceiptId };
        var canonical = SerializeCanonical(zeroed);
        try
        {
            using var framed = new LengthPrefixedBuilder();
            framed.Append(ReceiptIdDomain);
            framed.Append(canonical);
            var bytes = framed.ToArray();
            try
            {
                return ReceiptIdPrefix + Sha256Hex(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    public static string ComputeCanonicalJsonSha256<T>(T value)
    {
        var bytes = SerializeCanonical(value);
        try
        {
            return Sha256Hex(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static byte[] SerializeCanonicalJson<T>(T value) => SerializeCanonical(value);

    public static string CanonicalUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);

    public static string CanonicalSftCutoffUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'",
            CultureInfo.InvariantCulture);

    private static void ValidateTrust(ExpertDatasetReviewReceiptTrust trust)
    {
        if (string.IsNullOrWhiteSpace(trust.PublicKeyPath))
        {
            throw new CoordinatorValidationException("Review-receipt public-key path is required.");
        }
        RequireSha256(trust.PublicKeySpkiSha256, "Review-receipt public-key SPKI SHA-256");
        RequireIdentifier(trust.Audience, "Review-receipt audience");
        RequireIdentifier(trust.KeyId, "Review-receipt key ID");
        RequireIdentifier(trust.SignerRole, "Review-receipt signer role");
    }

    private static void ValidateEnvelope(
        ExpertDatasetReviewReceiptEnvelope envelope,
        ExpertDatasetReviewReceiptTrust trust,
        string publicKeySpkiSha256)
    {
        if (envelope.SchemaVersion != EnvelopeSchemaVersion ||
            envelope.PayloadType != PayloadSchemaVersion ||
            envelope.PayloadEncoding != PayloadEncoding ||
            envelope.Algorithm != Algorithm ||
            envelope.SignatureFormat != SignatureFormat)
        {
            throw new CoordinatorValidationException("Review-receipt envelope contract is unsupported.");
        }
        RequireSha256(envelope.PayloadSha256, "Review-receipt payload SHA-256");
        RequireSha256(envelope.PublicKeySpkiSha256, "Review-receipt public-key SPKI SHA-256");
        if (envelope.Audience != trust.Audience ||
            envelope.KeyId != trust.KeyId ||
            envelope.SignerRole != trust.SignerRole ||
            !FixedTimeEquals(envelope.PublicKeySpkiSha256, publicKeySpkiSha256))
        {
            throw new CoordinatorValidationException(
                "Review-receipt envelope does not match the externally pinned trust policy.");
        }
    }

    private static void VerifySignature(
        ExpertDatasetReviewReceiptEnvelope envelope,
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
                "Review-receipt signature must be a canonical low-S P1363 signature.");
        }

        using var input = new LengthPrefixedBuilder();
        input.Append(SignatureDomain);
        input.Append(envelope.SchemaVersion);
        input.Append(envelope.PayloadType);
        input.Append(envelope.PayloadEncoding);
        input.Append(envelope.Algorithm);
        input.Append(envelope.SignatureFormat);
        input.Append(envelope.Audience);
        input.Append(envelope.KeyId);
        input.Append(envelope.SignerRole);
        input.Append(envelope.PublicKeySpkiSha256);
        input.Append(envelope.PayloadSha256);
        input.Append(payload);
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
                throw new CoordinatorValidationException("Review-receipt signature is invalid.");
            }
        }
        catch (CryptographicException)
        {
            throw new CoordinatorValidationException("Review-receipt signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(framed);
        }
    }

    private static (DateTimeOffset NotBefore, DateTimeOffset ExpiresAt) ValidatePayload(
        ExpertDatasetReviewReceiptPayload payload,
        ExpertDatasetReviewReceiptEnvelope envelope,
        string sourceCorpusSha256,
        ExpertDatasetReviewReceiptSubject subject,
        VerifiedExpertTeacherLineageAdmission? teacherLineageAdmission,
        DateTimeOffset now)
    {
        var example = subject.Example;
        if (payload.SchemaVersion != PayloadSchemaVersion || payload.Decision != ApprovedDecision)
        {
            throw new CoordinatorValidationException("Review-receipt payload is not an approved v2 decision.");
        }
        RequireReceiptId(payload.ReceiptId);
        var expectedReceiptId = ComputeReceiptId(payload);
        if (!FixedTimeEquals(payload.ReceiptId[ReceiptIdPrefix.Length..],
                expectedReceiptId[ReceiptIdPrefix.Length..]))
        {
            throw new CoordinatorValidationException(
                "Review-receipt receiptId does not match its canonical content.");
        }
        if (!FixedTimeEquals(payload.SourceCorpusSha256, sourceCorpusSha256) ||
            payload.ExampleId != example.Id ||
            payload.TaskKind != example.TaskKind.ToString() ||
            payload.Domains is null ||
            !payload.Domains.SequenceEqual(example.Domains.Select(domain => domain.ToString()), StringComparer.Ordinal) ||
            !FixedTimeEquals(payload.ConversationSha256, example.ConversationSha256) ||
            !FixedTimeEquals(payload.VerificationEvidenceSha256, example.Verification.EvidenceSha256) ||
            payload.Reviewer != example.Verification.Reviewer ||
            !FixedTimeEquals(payload.SftMetadataSha256, subject.SftMetadataSha256))
        {
            throw new CoordinatorValidationException(
                $"Review receipt does not bind the exact current fields for example '{example.Id}'.");
        }
        RequireSha256(payload.SourceCorpusSha256, "Review-receipt source-corpus SHA-256");
        RequireSha256(payload.ConversationSha256, "Review-receipt conversation SHA-256");
        RequireSha256(payload.VerificationEvidenceSha256, "Review-receipt verification-evidence SHA-256");
        RequireSha256(payload.SftMetadataSha256, "Review-receipt SFT-metadata SHA-256");
        RequireIdentifier(payload.Reviewer, "Review-receipt reviewer");
        if (!example.Verification.Verified || example.Verification.VerifiedAtUtc is not { } verifiedAt)
        {
            throw new CoordinatorValidationException(
                $"Review receipt does not bind the verified review time for example '{example.Id}'.");
        }
        if (verifiedAt.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new CoordinatorValidationException(
                $"Verified review time must use whole-second precision for example '{example.Id}'.");
        }
        if (payload.ReviewedAtUtc != CanonicalUtc(verifiedAt))
        {
            throw new CoordinatorValidationException(
                $"Review receipt does not bind the verified review time for example '{example.Id}'.");
        }

        var expectedReviewKind = example.TaskKind is
            ExpertTaskKind.CodeGeneration or ExpertTaskKind.CodeRepair
                ? DaxqReviewKind
                : DeterministicTextReviewKind;
        if (payload.ReviewKind != expectedReviewKind)
        {
            throw new CoordinatorValidationException(
                $"Review receipt has the wrong review kind for example '{example.Id}'.");
        }
        if (payload.ReviewKind == DaxqReviewKind && !HasSupportedDaxqEvidence(example))
        {
            throw new CoordinatorValidationException(
                $"Review receipt lacks exact structured DAXQ evidence for example '{example.Id}'.");
        }

        var authorizations = payload.Authorizations
            ?? throw new CoordinatorValidationException("Review-receipt authorizations are required.");
        var evaluationAuthorized = example.Rights.MayStore &&
            example.Rights.MayEvaluate &&
            example.Sources.All(source => source?.Rights is
            {
                MayStore: true,
                MayEvaluate: true
            });
        var trainingAuthorized = evaluationAuthorized &&
            example.Split == "development" &&
            example.ReviewStatus == "approved" &&
            example.Verification.Verified &&
            example.Verification.Evidence.Contains(
                "knowledgeClass=candidate-stable",
                StringComparer.Ordinal) &&
            example.UseForTraining &&
            example.Rights.MayTrain &&
            example.Sources.All(source => source?.Rights?.MayTrain == true);
        var providerUploadAuthorized = trainingAuthorized &&
            example.Rights.MayUploadToProvider &&
            example.Sources.All(source => source?.Rights?.MayUploadToProvider == true);
        if (authorizations.Evaluation != evaluationAuthorized ||
            authorizations.Training != trainingAuthorized ||
            authorizations.ProviderUpload != providerUploadAuthorized)
        {
            throw new CoordinatorValidationException(
                $"Review-receipt authorizations do not exactly match the reviewed row for example '{example.Id}'.");
        }

        var approval = payload.Approval
            ?? throw new CoordinatorValidationException("Review-receipt approval is required.");
        RequireIdentifier(approval.ApprovalId, "Review-receipt approval ID");
        RequireIdentifier(approval.ActorId, "Review-receipt approval actor ID");
        RequireIdentifier(approval.ActorRole, "Review-receipt approval actor role");
        if (approval.ActorRole != envelope.SignerRole ||
            string.IsNullOrWhiteSpace(approval.Reference) ||
            approval.Reference.Length > MaxApprovalReferenceCharacters ||
            approval.Reference.Any(character => character is < ' ' or > '~') ||
            approval.EvidenceSizeBytes is < 1 or > MaxApprovalEvidenceBytes)
        {
            throw new CoordinatorValidationException("Review-receipt approval metadata is invalid.");
        }
        RequireSha256(approval.EvidenceSha256, "Review-receipt approval-evidence SHA-256");

        var reviewedAt = ParseCanonicalUtc(payload.ReviewedAtUtc, "review time");
        var approvedAt = ParseCanonicalUtc(approval.ApprovedAtUtc, "approval time");
        var issuedAt = ParseCanonicalUtc(payload.IssuedAtUtc, "issue time");
        var notBefore = ParseCanonicalUtc(payload.NotBeforeUtc, "activation time");
        var expiresAt = ParseCanonicalUtc(payload.ExpiresAtUtc, "expiry time");
        if (reviewedAt > approvedAt ||
            approvedAt > issuedAt ||
            issuedAt > notBefore ||
            notBefore >= expiresAt ||
            expiresAt - notBefore > TimeSpan.FromDays(366) ||
            now < notBefore ||
            now >= expiresAt)
        {
            throw new CoordinatorValidationException("Review-receipt validity window is invalid or inactive.");
        }
        if (example.Lineage.Origin == ExpertDatasetOrigin.OpenWeightTeacher &&
            (teacherLineageAdmission is null ||
             issuedAt < teacherLineageAdmission.NotBeforeUtc ||
             notBefore < teacherLineageAdmission.NotBeforeUtc ||
             expiresAt > teacherLineageAdmission.ExpiresAtUtc))
        {
            throw new CoordinatorValidationException(
                $"Review receipt for OpenWeightTeacher example '{example.Id}' is outside its teacher-lineage admission window.");
        }
        return (notBefore, expiresAt);
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
                MaxDepth = 32
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

    private static bool HasSupportedDaxqEvidence(ExpertModelDatasetExample example)
    {
        var compile = example.Verification.CompileEvidence;
        var tests = example.Verification.TestEvidence;
        if (!example.Verification.CompileSucceeded ||
            !example.Verification.TestsPassed ||
            compile.Count != 4 ||
            tests.Count != 5 ||
            !TryReadEvidence(compile, 0, "profile", out var profile) ||
            !TryReadEvidence(compile, 1, "sourceSha256", out var sourceSha256) ||
            !TryReadEvidence(compile, 2, "compilerClosureSha256", out var compilerClosureSha256) ||
            !TryReadEvidence(compile, 3, "canonicalProgramSha256", out var canonicalProgramSha256) ||
            !TryReadEvidence(tests, 0, "testSpecificationSha256", out var testSpecificationSha256) ||
            !TryReadEvidence(tests, 1, "executionTraceSha256", out var executionTraceSha256) ||
            !TryReadEvidence(tests, 2, "executableResultSha256", out var executableResultSha256) ||
            !TryReadEvidence(tests, 3, "vectorCount", out var vectorCountText) ||
            !TryReadEvidence(tests, 4, "callbackCount", out var callbackCountText))
        {
            return false;
        }
        var expectedSourceSha256 = Sha256Hex(StrictUtf8.GetBytes(example.Messages[^1].Content));
        return profile == ExpertModelDatasetReviewTools.DaxqExecutableProfile &&
            sourceSha256 == expectedSourceSha256 &&
            IsLowercaseHex(compilerClosureSha256, 64) &&
            IsLowercaseHex(canonicalProgramSha256, 64) &&
            IsLowercaseHex(testSpecificationSha256, 64) &&
            IsLowercaseHex(executionTraceSha256, 64) &&
            IsLowercaseHex(executableResultSha256, 64) &&
            int.TryParse(vectorCountText, NumberStyles.None, CultureInfo.InvariantCulture, out var vectorCount) &&
            vectorCount is >= 1 and <= ExpertModelDatasetReviewTools.MaxExecutableVectorsPerExample &&
            vectorCountText == vectorCount.ToString(CultureInfo.InvariantCulture) &&
            int.TryParse(callbackCountText, NumberStyles.None, CultureInfo.InvariantCulture, out var callbackCount) &&
            callbackCount is >= 1 and <= ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerExample &&
            callbackCountText == callbackCount.ToString(CultureInfo.InvariantCulture);
    }

    private static bool TryReadEvidence(
        IReadOnlyList<string> evidence,
        int index,
        string key,
        out string value)
    {
        var prefix = key + "=";
        var item = evidence[index];
        if (!item.StartsWith(prefix, StringComparison.Ordinal) || item.Length == prefix.Length)
        {
            value = string.Empty;
            return false;
        }
        value = item[prefix.Length..];
        return true;
    }

    private static byte[] SerializeCanonical<T>(T value)
    {
        var element = JsonSerializer.SerializeToElement(value, CanonicalSerializationJson);
        using var output = new MemoryStream();
        WriteCanonicalJson(output, element);
        return output.ToArray();
    }

    private static JsonSerializerOptions CreateCanonicalSerializationJson()
    {
        var options = new JsonSerializerOptions(CoordinatorJson.Options);
        options.Converters.Insert(0, ValidUnicodeStringJsonConverter.Instance);
        return options;
    }

    private static void RequireCanonicalJson(byte[] bytes, string label)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
            ValidateNoDuplicateProperties(document.RootElement, label);
            using var output = new MemoryStream(bytes.Length);
            WriteCanonicalJson(output, document.RootElement);
            if (!bytes.AsSpan().SequenceEqual(output.GetBuffer().AsSpan(0, checked((int)output.Length))))
            {
                throw new CoordinatorValidationException($"{label} is not canonical JSON.");
            }
        }
        catch (JsonException)
        {
            throw new CoordinatorValidationException($"{label} JSON is invalid.");
        }
    }

    private static void WriteCanonicalJson(Stream output, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                output.WriteByte((byte)'{');
                var firstProperty = true;
                foreach (var property in element.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    if (!firstProperty)
                    {
                        output.WriteByte((byte)',');
                    }
                    firstProperty = false;
                    WriteCanonicalString(output, property.Name);
                    output.WriteByte((byte)':');
                    WriteCanonicalJson(output, property.Value);
                }
                output.WriteByte((byte)'}');
                return;
            case JsonValueKind.Array:
                output.WriteByte((byte)'[');
                var firstItem = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!firstItem)
                    {
                        output.WriteByte((byte)',');
                    }
                    firstItem = false;
                    WriteCanonicalJson(output, item);
                }
                output.WriteByte((byte)']');
                return;
            case JsonValueKind.String:
                WriteCanonicalString(
                    output,
                    element.GetString()
                    ?? throw new CoordinatorValidationException("Canonical JSON string was null."));
                return;
            case JsonValueKind.Number:
                var raw = element.GetRawText();
                if (!long.TryParse(
                        raw,
                        NumberStyles.AllowLeadingSign,
                        CultureInfo.InvariantCulture,
                        out var integer))
                {
                    throw new CoordinatorValidationException("Canonical JSON contains an unsupported number.");
                }
                WriteUtf8(output, integer.ToString(CultureInfo.InvariantCulture));
                return;
            case JsonValueKind.True:
                WriteUtf8(output, "true");
                return;
            case JsonValueKind.False:
                WriteUtf8(output, "false");
                return;
            case JsonValueKind.Null:
                WriteUtf8(output, "null");
                return;
            default:
                throw new CoordinatorValidationException("Canonical JSON contains an unsupported value.");
        }
    }

    private static void WriteCanonicalString(Stream output, string value)
    {
        ValidateUnicodeScalars(value);
        output.WriteByte((byte)'"');
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            switch (character)
            {
                case '"':
                    WriteUtf8(output, "\\\"");
                    continue;
                case '\\':
                    WriteUtf8(output, "\\\\");
                    continue;
                case '\b':
                    WriteUtf8(output, "\\b");
                    continue;
                case '\t':
                    WriteUtf8(output, "\\t");
                    continue;
                case '\n':
                    WriteUtf8(output, "\\n");
                    continue;
                case '\f':
                    WriteUtf8(output, "\\f");
                    continue;
                case '\r':
                    WriteUtf8(output, "\\r");
                    continue;
            }

            if (character < 0x20)
            {
                const string lowercaseHex = "0123456789abcdef";
                output.WriteByte((byte)'\\');
                output.WriteByte((byte)'u');
                output.WriteByte((byte)'0');
                output.WriteByte((byte)'0');
                output.WriteByte((byte)lowercaseHex[character >> 4]);
                output.WriteByte((byte)lowercaseHex[character & 0x0f]);
                continue;
            }

            Rune rune;
            if (Rune.TryCreate(character, out rune))
            {
                WriteUtf8(output, rune);
                continue;
            }
            _ = Rune.TryCreate(character, value[++index], out rune);
            WriteUtf8(output, rune);
        }
        output.WriteByte((byte)'"');
    }

    private static void ValidateUnicodeScalars(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (!char.IsSurrogate(character))
            {
                continue;
            }
            if (!char.IsHighSurrogate(character) ||
                index + 1 >= value.Length ||
                !char.IsLowSurrogate(value[++index]))
            {
                throw new CoordinatorValidationException(
                    "Canonical JSON contains an invalid Unicode surrogate sequence.");
            }
        }
    }

    private static void WriteUtf8(Stream output, Rune rune)
    {
        Span<byte> buffer = stackalloc byte[4];
        var written = rune.EncodeToUtf8(buffer);
        output.Write(buffer[..written]);
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

    private static byte[] ReadP256PublicKey(string path)
    {
        var fullPath = Path.GetFullPath(path);
        RejectReparsePathComponents(fullPath, "Review-receipt public key");
        var bytes = ReadBoundedFile(fullPath, MaxPublicKeyBytes, "Review-receipt public key");
        try
        {
            if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
            {
                throw new CoordinatorValidationException("Review-receipt public key must be BOM-less PEM.");
            }
            string pem;
            try
            {
                pem = StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                throw new CoordinatorValidationException("Review-receipt public key must be valid UTF-8 PEM.");
            }
            var pemSpan = pem.AsSpan();
            if (!PemEncoding.TryFind(pemSpan, out var fields) ||
                !pemSpan[fields.Label].SequenceEqual("PUBLIC KEY") ||
                !pemSpan[..fields.Location.Start.GetOffset(pemSpan.Length)].Trim().IsEmpty ||
                !pemSpan[fields.Location.End.GetOffset(pemSpan.Length)..].Trim().IsEmpty)
            {
                throw new CoordinatorValidationException(
                    "Review-receipt public key must contain exactly one public P-256 SPKI PEM block.");
            }
            using var key = ECDsa.Create();
            key.ImportFromPem(pemSpan[fields.Location]);
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value ||
                parameters.Q.X is not { Length: 32 } ||
                parameters.Q.Y is not { Length: 32 })
            {
                throw new CoordinatorValidationException("Review-receipt public key must be P-256 SPKI.");
            }
            return key.ExportSubjectPublicKeyInfo();
        }
        catch (CryptographicException)
        {
            throw new CoordinatorValidationException("Review-receipt public key must be P-256 SPKI.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
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
            value != CanonicalUtc(parsed))
        {
            throw new CoordinatorValidationException($"Review-receipt {label} is not canonical UTC.");
        }
        return parsed;
    }

    private static void RequireReceiptId(string? value)
    {
        if (value is null ||
            !value.StartsWith(ReceiptIdPrefix, StringComparison.Ordinal) ||
            !IsLowercaseHex(value.AsSpan(ReceiptIdPrefix.Length), 64))
        {
            throw new CoordinatorValidationException("Review-receipt receiptId is invalid.");
        }
    }

    private static void RequireIdentifier(string value, string label)
    {
        if (value is null || !SafeIdentifierRegex().IsMatch(value))
        {
            throw new CoordinatorValidationException($"{label} is invalid.");
        }
    }

    private static void RequireSha256(string value, string label)
    {
        if (!IsLowercaseHex(value, 64))
        {
            throw new CoordinatorValidationException($"{label} must be a lowercase SHA-256 value.");
        }
    }

    private static bool IsLowercaseHex(string? value, int length) =>
        value is not null && IsLowercaseHex(value.AsSpan(), length);

    private static bool IsLowercaseHex(ReadOnlySpan<char> value, int length)
    {
        if (value.Length != length)
        {
            return false;
        }
        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
            {
                return false;
            }
        }
        return true;
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
        value.Length == 32 && value.IndexOfAnyExcept((byte)0) >= 0 && CompareBigEndian(value, P256Order) < 0;

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

    internal static void RejectReparsePathComponents(string fullPath, string label)
    {
        var root = Path.GetPathRoot(fullPath)
            ?? throw new CoordinatorValidationException($"{label} path has no filesystem root.");
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, fullPath)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new CoordinatorValidationException($"{label} path must not traverse a reparse point.");
            }
        }
    }

    private static void WriteUtf8(Stream output, string value) => output.Write(StrictUtf8.GetBytes(value));

    private sealed class LengthPrefixedBuilder : IDisposable
    {
        private readonly MemoryStream stream = new();

        public void Append(string value) => Append(StrictUtf8.GetBytes(value));

        public void Append(ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[sizeof(int)];
            BinaryPrimitives.WriteInt32BigEndian(length, checked(value.Length));
            stream.Write(length);
            stream.Write(value);
        }

        public byte[] ToArray() => stream.ToArray();

        public void Dispose() => stream.Dispose();
    }

    private sealed class ValidUnicodeStringJsonConverter : JsonConverter<string>
    {
        public static ValidUnicodeStringJsonConverter Instance { get; } = new();

        public override string? Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) => reader.GetString();

        public override void Write(
            Utf8JsonWriter writer,
            string value,
            JsonSerializerOptions options)
        {
            ValidateUnicodeScalars(value);
            writer.WriteStringValue(value);
        }

        public override string ReadAsPropertyName(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options) =>
            reader.GetString()
            ?? throw new JsonException("Canonical JSON property name must not be null.");

        public override void WriteAsPropertyName(
            Utf8JsonWriter writer,
            string value,
            JsonSerializerOptions options)
        {
            ValidateUnicodeScalars(value);
            writer.WritePropertyName(value);
        }
    }
}
