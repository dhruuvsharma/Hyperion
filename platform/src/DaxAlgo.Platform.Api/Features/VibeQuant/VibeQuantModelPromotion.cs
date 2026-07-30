using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Retrieval;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Platform.Features.VibeQuant;

internal static class VibeQuantModelPromotionVerifier
{
    public const string EnvelopeSchemaVersion = "daxalgo.vibe-quant.model-promotion-envelope/v1";
    public const string PayloadSchemaVersion = "daxalgo.vibe-quant.model-promotion/v1";
    public const string HostedPolicyV1SchemaVersion = "daxalgo.vibe-quant.hosted-deployment-policy/v1";
    public const string HostedPolicyV2SchemaVersion = "daxalgo.vibe-quant.hosted-deployment-policy/v2";
    public const string HostedPolicySchemaVersion = HostedPolicyV1SchemaVersion;
    private const string SignatureDomain = "daxalgo-vibe-quant-model-promotion-signature/v1";
    private const string PromotionIdDomain = "daxalgo-vibe-quant-model-promotion-id/v1";
    private const string QueryPolicyDomain = "daxalgo-vibe-quant-expert-context-query-policy/v1";
    private const string HostedPolicyV1Domain = "daxalgo-vibe-quant-hosted-deployment-policy/v1";
    private const string HostedPolicyV2Domain = "daxalgo-vibe-quant-hosted-deployment-policy/v2";
    private const string PayloadEncoding = "base64url";
    private const string Algorithm = "ES256";
    private const string SignatureFormat = "ieee-p1363";
    private const string Decision = "approved-for-production";
    private const int MaxEnvelopeBytes = 1_000_000;
    private const int MaxPayloadBytes = 500_000;
    private const int MaxPublicKeyFileBytes = 64_000;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] P256Order = Convert.FromHexString(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    private static readonly byte[] P256HalfOrder = Convert.FromHexString(
        "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8");

    public static VibeQuantModelPromotionIdentity Load(
        VibeQuantOptions options,
        VibeQuantServingProfile profile,
        string servingProfileSha256,
        string executionModelId,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (options.ModelPromotionEnvelopePath is null ||
            options.ModelPromotionEnvelopeSha256 is null ||
            options.ModelPromotionPublicKeyPath is null ||
            options.ModelPromotionPublicKeySpkiSha256 is null)
        {
            throw new InvalidOperationException("Live Vibe Quant model-promotion activation is incomplete.");
        }

        var envelopeBytes = ReadBoundedFile(
            options.ModelPromotionEnvelopePath,
            MaxEnvelopeBytes,
            "model-promotion envelope");
        try
        {
            var envelopeSha256 = HashBytes(envelopeBytes);
            RequirePinnedHash(
                envelopeSha256,
                options.ModelPromotionEnvelopeSha256,
                "The configured Vibe Quant model-promotion envelope does not match its pinned SHA-256.");
            var envelope = DeserializeStrict<VibeQuantModelPromotionEnvelope>(
                envelopeBytes,
                "model-promotion envelope");
            ValidateEnvelope(envelope, options);

            var publicKeySpki = ReadP256PublicKey(options.ModelPromotionPublicKeyPath);
            try
            {
                var publicKeySpkiSha256 = HashBytes(publicKeySpki);
                RequirePinnedHash(
                    publicKeySpkiSha256,
                    options.ModelPromotionPublicKeySpkiSha256,
                    "The configured Vibe Quant model-promotion public key does not match its pinned SPKI SHA-256.");
                RequirePinnedHash(
                    publicKeySpkiSha256,
                    envelope.PublicKeySpkiSha256,
                    "The Vibe Quant model-promotion envelope names a different public key.");

                var payloadBytes = DecodeCanonicalBase64Url(
                    envelope.Payload,
                    MaxPayloadBytes,
                    "model-promotion payload");
                try
                {
                    var payloadSha256 = HashBytes(payloadBytes);
                    RequirePinnedHash(
                        payloadSha256,
                        envelope.PayloadSha256,
                        "The Vibe Quant model-promotion payload hash is invalid.");
                    var signature = DecodeCanonicalBase64Url(
                        envelope.Signature,
                        64,
                        "model-promotion signature",
                        exactLength: true);
                    try
                    {
                        VerifySignature(envelope, payloadBytes, signature, publicKeySpki);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(signature);
                    }

                    RequireCanonicalJson(payloadBytes, "model-promotion payload");

                    var promotion = DeserializeStrict<VibeQuantModelPromotionPayload>(
                        payloadBytes,
                        "model-promotion payload");
                    return ValidatePromotion(
                        promotion,
                        envelope,
                        options,
                        profile,
                        servingProfileSha256,
                        executionModelId,
                        envelopeSha256,
                        payloadSha256,
                        timeProvider.GetUtcNow());
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

    private static void ValidateEnvelope(
        VibeQuantModelPromotionEnvelope envelope,
        VibeQuantOptions options)
    {
        if (!StringComparer.Ordinal.Equals(envelope.SchemaVersion, EnvelopeSchemaVersion) ||
            !StringComparer.Ordinal.Equals(envelope.PayloadType, PayloadSchemaVersion) ||
            !StringComparer.Ordinal.Equals(envelope.PayloadEncoding, PayloadEncoding) ||
            !StringComparer.Ordinal.Equals(envelope.Algorithm, Algorithm) ||
            !StringComparer.Ordinal.Equals(envelope.SignatureFormat, SignatureFormat))
        {
            throw new InvalidOperationException("The Vibe Quant model-promotion envelope contract is unsupported.");
        }
        RequirePromotionId(envelope.Audience, "Model-promotion audience");
        RequirePromotionId(envelope.KeyId, "Model-promotion key ID");
        RequirePromotionId(envelope.SignerRole, "Model-promotion signer role");
        RequireSha256(envelope.PayloadSha256, "Model-promotion payload SHA-256");
        RequireSha256(envelope.PublicKeySpkiSha256, "Model-promotion public-key SHA-256");
        if (!StringComparer.Ordinal.Equals(envelope.Audience, options.ModelPromotionAudience) ||
            !StringComparer.Ordinal.Equals(envelope.KeyId, options.ModelPromotionKeyId) ||
            !StringComparer.Ordinal.Equals(envelope.SignerRole, options.ModelPromotionSignerRole) ||
            !StringComparer.Ordinal.Equals(envelope.Audience, options.ModelAttestationAudience))
        {
            throw new InvalidOperationException(
                "The Vibe Quant model-promotion envelope does not match the active server trust policy.");
        }
    }

    private static void VerifySignature(
        VibeQuantModelPromotionEnvelope envelope,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKeySpki)
    {
        if (signature.Length != 64 || !IsP256Scalar(signature[..32]) ||
            !IsP256Scalar(signature[32..]) || CompareBigEndian(signature[32..], P256HalfOrder) > 0)
        {
            throw new InvalidOperationException(
                "The Vibe Quant model-promotion signature must be a canonical low-S P1363 signature.");
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
                throw new InvalidOperationException("The Vibe Quant model-promotion signature is invalid.");
            }
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("The Vibe Quant model-promotion signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(framed);
        }
    }

    private static VibeQuantModelPromotionIdentity ValidatePromotion(
        VibeQuantModelPromotionPayload promotion,
        VibeQuantModelPromotionEnvelope envelope,
        VibeQuantOptions options,
        VibeQuantServingProfile profile,
        string servingProfileSha256,
        string executionModelId,
        string envelopeSha256,
        string payloadSha256,
        DateTimeOffset now)
    {
        if (promotion.DataRelease is null ||
            promotion.PromotionEvidence is null ||
            promotion.Model is null ||
            promotion.Deployment is null ||
            promotion.Approval is null ||
            promotion.HostedDeploymentPolicy is null)
        {
            throw new InvalidOperationException(
                "The Vibe Quant model-promotion payload is incomplete.");
        }
        if (!StringComparer.Ordinal.Equals(promotion.SchemaVersion, PayloadSchemaVersion) ||
            !StringComparer.Ordinal.Equals(promotion.Decision, Decision) ||
            promotion.ProductionEligible is not true)
        {
            throw new InvalidOperationException("The Vibe Quant model-promotion decision is not production eligible.");
        }
        RequirePrefixedSha256(promotion.PromotionId, "vqprom-", "Model-promotion ID");
        var issuedAt = ParseUtcSecond(promotion.IssuedAtUtc, "Model-promotion issue time");
        var notBefore = ParseUtcSecond(promotion.NotBeforeUtc, "Model-promotion activation time");
        var expiresAt = ParseUtcSecond(promotion.ExpiresAtUtc, "Model-promotion expiry time");
        var approvedAt = ParseUtcSecond(promotion.Approval.ApprovedAtUtc, "Model-promotion approval time");
        if (approvedAt > issuedAt || issuedAt > notBefore || notBefore >= expiresAt ||
            expiresAt - notBefore > TimeSpan.FromDays(366) || now < notBefore || now >= expiresAt)
        {
            throw new InvalidOperationException("The Vibe Quant model-promotion validity window is invalid.");
        }

        ValidateDataRelease(promotion.DataRelease);
        ValidatePromotionEvidence(promotion.PromotionEvidence);
        ValidateModel(promotion.Model);
        ValidateDeployment(promotion.Deployment);
        ValidateApproval(promotion.Approval);
        var strategyAuthoringAuthorized = ValidateHostedPolicy(
            promotion.HostedDeploymentPolicy,
            promotion.Model.ExecutionModelId);
        var expectedPromotionId = "vqprom-" + ComputePromotionIdSha256(promotion);
        if (!StringComparer.Ordinal.Equals(promotion.PromotionId, expectedPromotionId))
        {
            throw new InvalidOperationException("The Vibe Quant model-promotion ID is invalid.");
        }
        if (!StringComparer.Ordinal.Equals(promotion.Deployment.Audience, envelope.Audience) ||
            !StringComparer.Ordinal.Equals(promotion.Deployment.DeploymentId, options.ModelPromotionDeploymentId) ||
            !StringComparer.Ordinal.Equals(promotion.Deployment.Environment, options.ModelPromotionEnvironment) ||
            !StringComparer.Ordinal.Equals(promotion.Approval.ActorRole, envelope.SignerRole))
        {
            throw new InvalidOperationException(
                "The Vibe Quant model-promotion deployment or approval identity is incompatible.");
        }
        ValidateModelBinding(
            promotion.Model,
            profile,
            servingProfileSha256,
            executionModelId);
        var actualHostedPolicySha256 = ComputeActualHostedPolicySha256(
            options,
            promotion.HostedDeploymentPolicy.SchemaVersion,
            executionModelId);
        if (!StringComparer.Ordinal.Equals(
                promotion.HostedDeploymentPolicy.PolicySha256,
                actualHostedPolicySha256))
        {
            throw new InvalidOperationException(
                "The Vibe Quant model-promotion hosted policy does not match the active server policy.");
        }

        return new VibeQuantModelPromotionIdentity(
            promotion.PromotionId,
            envelopeSha256,
            payloadSha256,
            promotion.Deployment.DeploymentId,
            promotion.HostedDeploymentPolicy.ProviderId,
            promotion.HostedDeploymentPolicy.PolicySha256,
            strategyAuthoringAuthorized,
            expiresAt,
            promotion.ExpiresAtUtc);
    }

    private static void ValidateDataRelease(VibeQuantPromotionDataRelease release)
    {
        RequirePrefixedSha256(release.ReleaseId, "vqrel-", "Promotion data-release ID");
        RequireSha256(release.ReleaseSha256, "Promotion data-release SHA-256");
        RequireSha256(release.ManifestSha256, "Promotion data-release manifest SHA-256");
        if (!StringComparer.Ordinal.Equals(release.ReleaseId, "vqrel-" + release.ReleaseSha256))
        {
            throw new InvalidOperationException(
                "Promotion data-release ID does not match its release SHA-256.");
        }
    }

    private static void ValidatePromotionEvidence(VibeQuantPromotionEvidence evidence)
    {
        foreach (var (value, name) in new[]
                 {
                     (evidence.ReportSha256, "report"),
                     (evidence.ReportFileSha256, "report file"),
                     (evidence.PolicySha256, "policy"),
                     (evidence.PolicyFileSha256, "policy file"),
                     (evidence.CalibrationTasksFileSha256, "calibration tasks file"),
                     (evidence.CalibrationTaskSetSha256, "calibration task set"),
                     (evidence.CalibrationEvidenceSha256, "calibration evidence"),
                     (evidence.SealedTasksFileSha256, "sealed tasks file"),
                     (evidence.SealedTaskSetSha256, "sealed task set"),
                     (evidence.CandidateResponsesFileSha256, "candidate responses file"),
                     (evidence.CandidateResponseSetSha256, "candidate response set"),
                     (evidence.CandidateVerifierResultsFileSha256, "candidate verifier results file"),
                     (evidence.CandidateVerifierResultSetSha256, "candidate verifier result set"),
                     (evidence.BaselineResponsesFileSha256, "baseline responses file"),
                     (evidence.BaselineResponseSetSha256, "baseline response set"),
                     (evidence.BaselineVerifierResultsFileSha256, "baseline verifier results file"),
                     (evidence.BaselineVerifierResultSetSha256, "baseline verifier result set"),
                 })
        {
            RequireSha256(value, $"Promotion {name} SHA-256");
        }
    }

    private static void ValidateModel(VibeQuantPromotionModel model)
    {
        RequireSha256(model.CandidateCatalogSha256, "Promotion candidate-catalog SHA-256");
        RequireProfileId(model.CandidateId, "Promotion candidate ID");
        RequireModelId(model.ModelId, "Promotion model ID");
        RequireRevision(model.ModelRevision, "Promotion model revision");
        RequireSha256(model.TrainingRunManifestSha256, "Promotion training-run manifest SHA-256");
        RequireSha256(model.ArtifactMetadataFileSha256, "Promotion artifact metadata file SHA-256");
        RequireSha256(model.ArtifactSha256, "Promotion artifact SHA-256");
        RequireSha256(model.ArtifactTreeSha256, "Promotion artifact-tree SHA-256");
        RequireProfileId(model.ServingProfileId, "Promotion serving-profile ID");
        RequireSha256(model.ServingProfileSha256, "Promotion serving-profile SHA-256");
        if (model.ExecutionModelId is null || !model.ExecutionModelId.StartsWith(
                VibeQuantModelDeploymentCatalog.ExecutionModelPrefix,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Promotion execution-model ID is invalid.");
        }
        RequireSha256(
            model.ExecutionModelId[VibeQuantModelDeploymentCatalog.ExecutionModelPrefix.Length..],
            "Promotion execution-model SHA-256");
        RequireSha256(model.ChatTemplateSha256, "Promotion chat-template SHA-256");
        if (model.ContainerImageDigest is not { Length: 71 } digest ||
            !digest.StartsWith("sha256:", StringComparison.Ordinal) ||
            !IsLowercaseHex(digest.AsSpan(7)))
        {
            throw new InvalidOperationException("Promotion container-image digest is invalid.");
        }
    }

    private static void ValidateDeployment(VibeQuantPromotionDeployment deployment)
    {
        RequirePromotionId(deployment.DeploymentId, "Promotion deployment ID");
        RequirePromotionId(deployment.Environment, "Promotion environment");
        RequirePromotionId(deployment.Audience, "Promotion deployment audience");
    }

    private static void ValidateApproval(VibeQuantPromotionApproval approval)
    {
        RequirePromotionId(approval.ApprovalId, "Promotion approval ID");
        RequirePromotionId(approval.ActorId, "Promotion actor ID");
        RequirePromotionId(approval.ActorRole, "Promotion actor role");
        if (string.IsNullOrWhiteSpace(approval.Reference) || approval.Reference.Length > 500 ||
            approval.Reference.Any(char.IsControl))
        {
            throw new InvalidOperationException("Promotion approval reference is invalid.");
        }
        RequireSha256(approval.EvidenceSha256, "Promotion approval evidence SHA-256");
        if (approval.EvidenceSizeBytes is < 1 or > 16_000_000)
        {
            throw new InvalidOperationException("Promotion approval evidence size is invalid.");
        }
    }

    private static bool ValidateHostedPolicy(
        VibeQuantHostedDeploymentPolicy policy,
        string executionModelId)
    {
        if (policy.Pricing is null || policy.Execution is null ||
            policy.Coordinator is null || policy.ExpertContext is null)
        {
            throw new InvalidOperationException("The signed Vibe Quant hosted policy is incomplete.");
        }
        if (policy.SchemaVersion is not (HostedPolicyV1SchemaVersion or HostedPolicyV2SchemaVersion) ||
            !StringComparer.Ordinal.Equals(policy.Protocol, "openai-compatible"))
        {
            throw new InvalidOperationException("The signed Vibe Quant hosted policy is unsupported.");
        }
        RequireSha256(policy.PolicySha256, "Hosted-policy SHA-256");
        ValidateProviderIdentity(policy.ProviderId, "Hosted provider ID");
        ValidatePricing(policy.Pricing);
        ValidateExecution(policy.Execution);
        ValidateCoordinator(policy.Coordinator);
        var strategyAuthoringCapability = ReadStrategyAuthoringCapability(policy);
        if (strategyAuthoringCapability is not null)
        {
            ValidateStrategyAuthoringCapability(strategyAuthoringCapability, executionModelId);
        }
        ValidateExpertContext(policy.ExpertContext);
        var queryPolicySha256 = ComputeQueryPolicySha256(policy.ExpertContext.QueryPolicy);
        if (!StringComparer.Ordinal.Equals(
                policy.ExpertContext.QueryPolicySha256,
                queryPolicySha256))
        {
            throw new InvalidOperationException("The signed expert-context query-policy hash is invalid.");
        }
        var expectedPolicySha256 = ComputeHostedPolicySha256(policy);
        if (!StringComparer.Ordinal.Equals(policy.PolicySha256, expectedPolicySha256))
        {
            throw new InvalidOperationException("The signed Vibe Quant hosted-policy hash is invalid.");
        }
        return strategyAuthoringCapability is not null;
    }

    private static VibeQuantPromotionStrategyAuthoringCapability? ReadStrategyAuthoringCapability(
        VibeQuantHostedDeploymentPolicy policy)
    {
        if (StringComparer.Ordinal.Equals(policy.SchemaVersion, HostedPolicyV1SchemaVersion))
        {
            if (policy.StrategyAuthoringCapability.ValueKind != JsonValueKind.Undefined)
            {
                throw new InvalidOperationException(
                    "Hosted-policy v1 cannot carry a strategy-authoring capability.");
            }
            return null;
        }
        if (!StringComparer.Ordinal.Equals(policy.SchemaVersion, HostedPolicyV2SchemaVersion) ||
            policy.StrategyAuthoringCapability.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "Hosted-policy v2 requires one strategy-authoring capability.");
        }
        try
        {
            return policy.StrategyAuthoringCapability.Deserialize<VibeQuantPromotionStrategyAuthoringCapability>(
                       CoordinatorJson.Options)
                ?? throw new InvalidOperationException(
                    "The signed strategy-authoring capability is JSON null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                "The signed strategy-authoring capability is invalid.",
                exception);
        }
    }

    private static void ValidateStrategyAuthoringCapability(
        VibeQuantPromotionStrategyAuthoringCapability capability,
        string executionModelId)
    {
        if (!StringComparer.Ordinal.Equals(capability.Purpose, "StrategyAuthoring") ||
            !StringComparer.Ordinal.Equals(capability.ExecutionModelId, executionModelId) ||
            !StringComparer.Ordinal.Equals(capability.PolicyVersion, CoordinatorVersions.StrategyPolicy) ||
            !StringComparer.Ordinal.Equals(capability.WorkflowVersion, CoordinatorVersions.StrategyWorkflow) ||
            !StringComparer.Ordinal.Equals(
                capability.PromptCatalogSha256,
                CoordinatorVersions.StrategyPromptCatalogSha256))
        {
            throw new InvalidOperationException(
                "The signed strategy-authoring capability does not match the active inert coordinator profile.");
        }
    }

    private static void ValidatePricing(VibeQuantPromotionPricing pricing)
    {
        _ = ParseCanonicalDecimal(pricing.InputUsdPerMillionTokens, allowZero: true, "Hosted input price");
        _ = ParseCanonicalDecimal(pricing.OutputUsdPerMillionTokens, allowZero: true, "Hosted output price");
        if (pricing.CreditsPerUsd is < 1 or > 1_000_000_000 ||
            pricing.MinimumChargeCredits is < 0 or > 1_000_000_000)
        {
            throw new InvalidOperationException("Hosted pricing conversion is invalid.");
        }
        ValidateCreditPricingVersion(pricing.CreditPricingVersion);
    }

    internal static void ValidateCreditPricingVersion(string value) =>
        RequireText(value, "Hosted credit-pricing version", 100);

    internal static void ValidateExpertContextIdentity(string value, string name)
    {
        if (value is not { Length: >= 1 and <= 100 } || !value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    internal static void ValidateExpertContextVersion(string value, string name)
    {
        ValidateExpertContextIdentity(value, name);
        if (value.Equals("latest", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("main", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("master", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("trunk", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{name} must identify an immutable corpus version.");
        }
    }

    internal static void ValidateProviderIdentity(string value, string name)
    {
        if (value is not { Length: >= 1 and <= 100 } ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            !value.All(character => char.IsAsciiLetterOrDigit(character) ||
                character is '-' or '_' or '.' or ':'))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    private static void ValidateExecution(VibeQuantPromotionExecution execution)
    {
        _ = ParseCanonicalDecimal(execution.MaxCostUsd, allowZero: false, "Hosted maximum cost");
        if (execution.MaxRequests is < 1 or > 100 ||
            execution.MaxAttemptsPerRole is < 1 or > 10 ||
            execution.MaxPromptTokens is < 1 or > 10_000_000 ||
            execution.MaxOutputTokens is < 1 or > 10_000_000 ||
            execution.MaxOutputTokensPerRequest is < 1 or > 1_000_000 ||
            execution.MaxOutputTokensPerRequest > execution.MaxOutputTokens ||
            execution.MaxResponseBytes is < 1 or > 2_000_000 ||
            execution.MaxArtifactBytes is < 1 or > 2_000_000 ||
            execution.MaxElapsedSeconds is < 1 or > 86_400 ||
            execution.RequestTimeoutSeconds is < 1 or > 3_600 ||
            execution.MaxElapsedSeconds < checked((execution.RequestTimeoutSeconds * 2) + 60) ||
            execution.MaxActiveRunsPerAccount is < 1 or > 100 ||
            execution.WorkerPollMilliseconds is < 50 or > 60_000 ||
            execution.ModelAttestationTimeoutSeconds is < 1 or > 60 ||
            execution.ModelAttestationRefreshSeconds is < 5 or > 300 ||
            execution.ModelAttestationTtlSeconds is < 10 or > 900 ||
            execution.ModelAttestationTimeoutSeconds >= execution.ModelAttestationRefreshSeconds ||
            execution.ModelAttestationRefreshSeconds >= execution.ModelAttestationTtlSeconds)
        {
            throw new InvalidOperationException("Hosted execution policy is invalid.");
        }
    }

    private static void ValidateCoordinator(VibeQuantPromotionCoordinator coordinator)
    {
        RequireText(coordinator.PolicyVersion, "Hosted coordinator policy version", 100);
        RequireText(coordinator.WorkflowVersion, "Hosted coordinator workflow version", 100);
        RequireSha256(coordinator.PromptCatalogSha256, "Hosted prompt-catalog SHA-256");
    }

    private static void ValidateExpertContext(VibeQuantPromotionExpertContext context)
    {
        if (context.QueryPolicy is null)
        {
            throw new InvalidOperationException("Hosted expert-context query policy is incomplete.");
        }
        if (!StringComparer.Ordinal.Equals(context.Mode, "Pinned"))
        {
            throw new InvalidOperationException("Hosted expert-context mode must be Pinned.");
        }
        ValidateExpertContextIdentity(context.CorpusId, "Hosted expert-context corpus ID");
        ValidateExpertContextVersion(context.CorpusVersion, "Hosted expert-context corpus version");
        RequireSha256(context.PackSha256, "Hosted expert-context pack SHA-256");
        RequireSha256(context.QueryPolicySha256, "Hosted expert-context query-policy SHA-256");
        if (!StringComparer.Ordinal.Equals(
                context.QueryPolicy.SchemaVersion,
                ExpertContextPackTools.QueryPolicySchemaVersion) ||
            context.QueryPolicy.TopK is < 1 or > 100 ||
            context.QueryPolicy.MaxCharacters is < 1 or > 500_000 ||
            context.QueryPolicy.MaxPerSource is < 1 or > 100 ||
            context.QueryPolicy.MaxPerSource > context.QueryPolicy.TopK ||
            context.QueryMaxCharacters is < 1 or > 1_000_000)
        {
            throw new InvalidOperationException("Hosted expert-context query policy is invalid.");
        }
    }

    private static void ValidateModelBinding(
        VibeQuantPromotionModel model,
        VibeQuantServingProfile profile,
        string servingProfileSha256,
        string executionModelId)
    {
        if (!StringComparer.Ordinal.Equals(model.CandidateCatalogSha256, profile.CandidateCatalogSha256) ||
            !StringComparer.Ordinal.Equals(model.CandidateId, profile.CandidateId) ||
            !StringComparer.Ordinal.Equals(model.ModelId, profile.BaseModel.ModelId) ||
            !StringComparer.Ordinal.Equals(model.ModelRevision, profile.BaseModel.Revision) ||
            !StringComparer.Ordinal.Equals(
                model.TrainingRunManifestSha256,
                profile.TrainingArtifact.TrainingRunManifestSha256) ||
            !StringComparer.Ordinal.Equals(model.ArtifactSha256, profile.TrainingArtifact.ArtifactSha256) ||
            !StringComparer.Ordinal.Equals(model.ArtifactTreeSha256, profile.TrainingArtifact.ArtifactTreeSha256) ||
            !StringComparer.Ordinal.Equals(model.ServingProfileId, profile.ProfileId) ||
            !StringComparer.Ordinal.Equals(model.ServingProfileSha256, servingProfileSha256) ||
            !StringComparer.Ordinal.Equals(model.ExecutionModelId, executionModelId) ||
            !StringComparer.Ordinal.Equals(model.ChatTemplateSha256, profile.ChatTemplateSha256) ||
            !StringComparer.Ordinal.Equals(model.ContainerImageDigest, profile.Runtime.ContainerImageDigest))
        {
            throw new InvalidOperationException(
                "The Vibe Quant model-promotion identity does not match the pinned serving profile.");
        }
    }

    private static string ComputeActualHostedPolicySha256(
        VibeQuantOptions options,
        string schemaVersion,
        string executionModelId)
    {
        var queryPolicy = options.CreateExpertContextPolicy();
        var signedQueryPolicy = new VibeQuantPromotionQueryPolicy
        {
            SchemaVersion = queryPolicy.SchemaVersion,
            TopK = queryPolicy.TopK,
            MaxCharacters = queryPolicy.MaxCharacters,
            MaxPerSource = queryPolicy.MaxPerSource,
        };
        var policy = new VibeQuantHostedDeploymentPolicy
        {
            SchemaVersion = schemaVersion,
            PolicySha256 = new string('0', 64),
            ProviderId = options.ProviderId,
            Protocol = options.Protocol,
            Pricing = new VibeQuantPromotionPricing
            {
                InputUsdPerMillionTokens = CanonicalDecimal(options.InputUsdPerMillionTokens, true, "input price"),
                OutputUsdPerMillionTokens = CanonicalDecimal(options.OutputUsdPerMillionTokens, true, "output price"),
                CreditsPerUsd = options.CreditsPerUsd,
                MinimumChargeCredits = options.MinimumChargeCredits,
                CreditPricingVersion = options.CreditPricingVersion,
            },
            Execution = new VibeQuantPromotionExecution
            {
                MaxRequests = options.MaxRequests,
                MaxAttemptsPerRole = options.MaxAttemptsPerRole,
                MaxPromptTokens = options.MaxPromptTokens,
                MaxOutputTokens = options.MaxOutputTokens,
                MaxOutputTokensPerRequest = options.MaxOutputTokensPerRequest,
                MaxCostUsd = CanonicalDecimal(options.MaxCostUsd, false, "maximum cost"),
                MaxResponseBytes = options.MaxResponseBytes,
                MaxArtifactBytes = options.MaxArtifactBytes,
                MaxElapsedSeconds = options.MaxElapsedSeconds,
                RequestTimeoutSeconds = options.RequestTimeoutSeconds,
                RequireReportedUsage = options.RequireReportedUsage,
                MaxActiveRunsPerAccount = options.MaxActiveRunsPerAccount,
                WorkerPollMilliseconds = options.WorkerPollMilliseconds,
                ModelAttestationTimeoutSeconds = options.ModelAttestationTimeoutSeconds,
                ModelAttestationRefreshSeconds = options.ModelAttestationRefreshSeconds,
                ModelAttestationTtlSeconds = options.ModelAttestationTtlSeconds,
            },
            Coordinator = new VibeQuantPromotionCoordinator
            {
                PolicyVersion = CoordinatorVersions.Policy,
                WorkflowVersion = CoordinatorVersions.Workflow,
                PromptCatalogSha256 = CoordinatorPromptCatalog.Sha256,
            },
            StrategyAuthoringCapability = StringComparer.Ordinal.Equals(
                schemaVersion,
                HostedPolicyV2SchemaVersion)
                ? JsonSerializer.SerializeToElement(
                    new VibeQuantPromotionStrategyAuthoringCapability
                    {
                        Purpose = "StrategyAuthoring",
                        ExecutionModelId = executionModelId,
                        PolicyVersion = CoordinatorVersions.StrategyPolicy,
                        WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
                        PromptCatalogSha256 = CoordinatorVersions.StrategyPromptCatalogSha256,
                    },
                    CoordinatorJson.Options)
                : default,
            ExpertContext = new VibeQuantPromotionExpertContext
            {
                Mode = options.ExpertContextMode,
                CorpusId = options.ExpertContextCorpusId ?? string.Empty,
                CorpusVersion = options.ExpertContextCorpusVersion ?? string.Empty,
                PackSha256 = options.ExpertContextPackSha256 ?? string.Empty,
                QueryPolicy = signedQueryPolicy,
                QueryPolicySha256 = ComputeQueryPolicySha256(signedQueryPolicy),
                QueryMaxCharacters = options.ExpertContextQueryMaxCharacters,
            },
        };
        return ComputeHostedPolicySha256(policy);
    }

    private static string ComputeQueryPolicySha256(VibeQuantPromotionQueryPolicy policy)
    {
        using var builder = new LengthPrefixedBuilder();
        builder.Append(QueryPolicyDomain);
        builder.Append(policy.SchemaVersion);
        builder.Append(policy.TopK);
        builder.Append(policy.MaxCharacters);
        builder.Append(policy.MaxPerSource);
        return builder.ComputeSha256();
    }

    internal static string ComputeHostedPolicySha256(VibeQuantHostedDeploymentPolicy policy)
    {
        using var builder = new LengthPrefixedBuilder();
        builder.Append(policy.SchemaVersion switch
        {
            HostedPolicyV1SchemaVersion => HostedPolicyV1Domain,
            HostedPolicyV2SchemaVersion => HostedPolicyV2Domain,
            _ => throw new InvalidOperationException("The signed Vibe Quant hosted policy is unsupported."),
        });
        AppendHostedPolicy(builder, policy, includePolicySha256: false);
        return builder.ComputeSha256();
    }

    internal static string ComputePromotionIdSha256(VibeQuantModelPromotionPayload promotion)
    {
        using var builder = new LengthPrefixedBuilder();
        builder.Append(PromotionIdDomain);
        builder.Append(promotion.SchemaVersion);
        builder.Append(promotion.Decision);
        builder.Append(promotion.ProductionEligible);
        builder.Append(promotion.IssuedAtUtc);
        builder.Append(promotion.NotBeforeUtc);
        builder.Append(promotion.ExpiresAtUtc);
        builder.Append(promotion.DataRelease.ReleaseId);
        builder.Append(promotion.DataRelease.ReleaseSha256);
        builder.Append(promotion.DataRelease.ManifestSha256);
        AppendPromotionEvidence(builder, promotion.PromotionEvidence);
        AppendModel(builder, promotion.Model);
        builder.Append(promotion.Deployment.DeploymentId);
        builder.Append(promotion.Deployment.Environment);
        builder.Append(promotion.Deployment.Audience);
        builder.Append(promotion.Approval.ApprovalId);
        builder.Append(promotion.Approval.ActorId);
        builder.Append(promotion.Approval.ActorRole);
        builder.Append(promotion.Approval.Reference);
        builder.Append(promotion.Approval.ApprovedAtUtc);
        builder.Append(promotion.Approval.EvidenceSha256);
        builder.Append(promotion.Approval.EvidenceSizeBytes);
        AppendHostedPolicy(builder, promotion.HostedDeploymentPolicy, includePolicySha256: true);
        return builder.ComputeSha256();
    }

    private static void AppendPromotionEvidence(
        LengthPrefixedBuilder builder,
        VibeQuantPromotionEvidence evidence)
    {
        builder.Append(evidence.ReportSha256);
        builder.Append(evidence.ReportFileSha256);
        builder.Append(evidence.PolicySha256);
        builder.Append(evidence.PolicyFileSha256);
        builder.Append(evidence.CalibrationTasksFileSha256);
        builder.Append(evidence.CalibrationTaskSetSha256);
        builder.Append(evidence.CalibrationEvidenceSha256);
        builder.Append(evidence.SealedTasksFileSha256);
        builder.Append(evidence.SealedTaskSetSha256);
        builder.Append(evidence.CandidateResponsesFileSha256);
        builder.Append(evidence.CandidateResponseSetSha256);
        builder.Append(evidence.CandidateVerifierResultsFileSha256);
        builder.Append(evidence.CandidateVerifierResultSetSha256);
        builder.Append(evidence.BaselineResponsesFileSha256);
        builder.Append(evidence.BaselineResponseSetSha256);
        builder.Append(evidence.BaselineVerifierResultsFileSha256);
        builder.Append(evidence.BaselineVerifierResultSetSha256);
    }

    private static void AppendModel(LengthPrefixedBuilder builder, VibeQuantPromotionModel model)
    {
        builder.Append(model.CandidateCatalogSha256);
        builder.Append(model.CandidateId);
        builder.Append(model.ModelId);
        builder.Append(model.ModelRevision);
        builder.Append(model.TrainingRunManifestSha256);
        builder.Append(model.ArtifactMetadataFileSha256);
        builder.Append(model.ArtifactSha256);
        builder.Append(model.ArtifactTreeSha256);
        builder.Append(model.ServingProfileId);
        builder.Append(model.ServingProfileSha256);
        builder.Append(model.ExecutionModelId);
        builder.Append(model.ChatTemplateSha256);
        builder.Append(model.ContainerImageDigest);
    }

    private static void AppendHostedPolicy(
        LengthPrefixedBuilder builder,
        VibeQuantHostedDeploymentPolicy policy,
        bool includePolicySha256)
    {
        builder.Append(policy.SchemaVersion);
        if (includePolicySha256)
        {
            builder.Append(policy.PolicySha256);
        }
        builder.Append(policy.ProviderId);
        builder.Append(policy.Protocol);
        builder.Append(policy.Pricing.InputUsdPerMillionTokens);
        builder.Append(policy.Pricing.OutputUsdPerMillionTokens);
        builder.Append(policy.Pricing.CreditsPerUsd);
        builder.Append(policy.Pricing.MinimumChargeCredits);
        builder.Append(policy.Pricing.CreditPricingVersion);
        builder.Append(policy.Execution.MaxRequests);
        builder.Append(policy.Execution.MaxAttemptsPerRole);
        builder.Append(policy.Execution.MaxPromptTokens);
        builder.Append(policy.Execution.MaxOutputTokens);
        builder.Append(policy.Execution.MaxOutputTokensPerRequest);
        builder.Append(policy.Execution.MaxCostUsd);
        builder.Append(policy.Execution.MaxResponseBytes);
        builder.Append(policy.Execution.MaxArtifactBytes);
        builder.Append(policy.Execution.MaxElapsedSeconds);
        builder.Append(policy.Execution.RequestTimeoutSeconds);
        builder.Append(policy.Execution.RequireReportedUsage);
        builder.Append(policy.Execution.MaxActiveRunsPerAccount);
        builder.Append(policy.Execution.WorkerPollMilliseconds);
        builder.Append(policy.Execution.ModelAttestationTimeoutSeconds);
        builder.Append(policy.Execution.ModelAttestationRefreshSeconds);
        builder.Append(policy.Execution.ModelAttestationTtlSeconds);
        builder.Append(policy.Coordinator.PolicyVersion);
        builder.Append(policy.Coordinator.WorkflowVersion);
        builder.Append(policy.Coordinator.PromptCatalogSha256);
        var strategyAuthoringCapability = ReadStrategyAuthoringCapability(policy);
        if (strategyAuthoringCapability is not null)
        {
            builder.Append(strategyAuthoringCapability.Purpose);
            builder.Append(strategyAuthoringCapability.ExecutionModelId);
            builder.Append(strategyAuthoringCapability.PolicyVersion);
            builder.Append(strategyAuthoringCapability.WorkflowVersion);
            builder.Append(strategyAuthoringCapability.PromptCatalogSha256);
        }
        builder.Append(policy.ExpertContext.Mode);
        builder.Append(policy.ExpertContext.CorpusId);
        builder.Append(policy.ExpertContext.CorpusVersion);
        builder.Append(policy.ExpertContext.PackSha256);
        builder.Append(policy.ExpertContext.QueryPolicy.SchemaVersion);
        builder.Append(policy.ExpertContext.QueryPolicy.TopK);
        builder.Append(policy.ExpertContext.QueryPolicy.MaxCharacters);
        builder.Append(policy.ExpertContext.QueryPolicy.MaxPerSource);
        builder.Append(policy.ExpertContext.QueryPolicySha256);
        builder.Append(policy.ExpertContext.QueryMaxCharacters);
    }

    private static string CanonicalDecimal(decimal value, bool allowZero, string label)
    {
        if (value < 0 || value > 1_000_000_000m || (!allowZero && value == 0) ||
            decimal.Round(value, 9) != value)
        {
            throw new InvalidOperationException($"The active Vibe Quant {label} is not promotion-canonical.");
        }
        return value.ToString("0.#########", CultureInfo.InvariantCulture);
    }

    private static decimal ParseCanonicalDecimal(string value, bool allowZero, string label)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 32 || value[0] == '-' ||
            !decimal.TryParse(
                value,
                NumberStyles.AllowDecimalPoint,
                CultureInfo.InvariantCulture,
                out var parsed) ||
            parsed > 1_000_000_000m || (!allowZero && parsed == 0) ||
            !StringComparer.Ordinal.Equals(value, CanonicalDecimal(parsed, allowZero, label)))
        {
            throw new InvalidOperationException($"{label} is not a canonical decimal string.");
        }
        return parsed;
    }

    private static DateTimeOffset ParseUtcSecond(string value, string label)
    {
        if (value is not { Length: 20 } ||
            !DateTimeOffset.TryParseExact(
                value,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new InvalidOperationException($"{label} must use canonical UTC-second form.");
        }
        return parsed;
    }

    private static T DeserializeStrict<T>(byte[] bytes, string label)
    {
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new InvalidOperationException($"The Vibe Quant {label} must be BOM-less UTF-8 JSON.");
        }
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
                throw new InvalidOperationException($"The Vibe Quant {label} must be a JSON object.");
            }
            ValidateNoDuplicateProperties(document.RootElement, label);
            return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new InvalidOperationException($"The Vibe Quant {label} was JSON null.");
        }
        catch (DecoderFallbackException)
        {
            throw new InvalidOperationException($"The Vibe Quant {label} must be valid UTF-8.");
        }
        catch (JsonException)
        {
            throw new InvalidOperationException($"The Vibe Quant {label} JSON is invalid.");
        }
    }

    private static void RequireCanonicalJson(byte[] bytes, string label)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
            ValidateNoDuplicateProperties(document.RootElement, label);
            using var output = new MemoryStream(bytes.Length);
            WriteCanonicalJson(output, document.RootElement);
            var canonical = output.GetBuffer().AsSpan(0, checked((int)output.Length));
            if (!bytes.AsSpan().SequenceEqual(canonical))
            {
                throw new InvalidOperationException(
                    $"The Vibe Quant {label} is not canonical JSON.");
            }
        }
        catch (JsonException)
        {
            throw new InvalidOperationException($"The Vibe Quant {label} JSON is invalid.");
        }
        catch (EncoderFallbackException)
        {
            throw new InvalidOperationException($"The Vibe Quant {label} JSON is invalid.");
        }
    }

    private static void WriteCanonicalJson(Stream output, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                output.WriteByte((byte)'{');
                var firstProperty = true;
                foreach (var property in element.EnumerateObject()
                             .OrderBy(item => item.Name, StringComparer.Ordinal))
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
                    ?? throw new InvalidOperationException("Canonical JSON string was null."));
                return;
            case JsonValueKind.Number:
                var rawNumber = element.GetRawText();
                if (!long.TryParse(
                        rawNumber,
                        NumberStyles.AllowLeadingSign,
                        CultureInfo.InvariantCulture,
                        out var integer))
                {
                    throw new InvalidOperationException(
                        "The Vibe Quant model-promotion payload contains an unsupported JSON number.");
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
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion payload contains unsupported JSON.");
        }
    }

    private static void WriteCanonicalString(Stream output, string value)
    {
        var escaped = new StringBuilder(value.Length + 2);
        escaped.Append('"');
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            switch (character)
            {
                case '"':
                    escaped.Append("\\\"");
                    break;
                case '\\':
                    escaped.Append("\\\\");
                    break;
                case '\b':
                    escaped.Append("\\b");
                    break;
                case '\f':
                    escaped.Append("\\f");
                    break;
                case '\n':
                    escaped.Append("\\n");
                    break;
                case '\r':
                    escaped.Append("\\r");
                    break;
                case '\t':
                    escaped.Append("\\t");
                    break;
                case < ' ':
                    escaped.Append("\\u");
                    escaped.Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    break;
                default:
                    if (char.IsHighSurrogate(character))
                    {
                        if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                        {
                            throw new InvalidOperationException(
                                "The Vibe Quant model-promotion payload contains invalid Unicode.");
                        }
                        escaped.Append(character);
                        escaped.Append(value[++index]);
                    }
                    else if (char.IsLowSurrogate(character))
                    {
                        throw new InvalidOperationException(
                            "The Vibe Quant model-promotion payload contains invalid Unicode.");
                    }
                    else
                    {
                        escaped.Append(character);
                    }
                    break;
            }
        }
        escaped.Append('"');
        WriteUtf8(output, escaped.ToString());
    }

    private static void WriteUtf8(Stream output, string value) =>
        output.Write(StrictUtf8.GetBytes(value));

    private static void ValidateNoDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidOperationException($"The Vibe Quant {path} contains duplicate properties.");
                }
                ValidateNoDuplicateProperties(property.Value, path);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item, path);
            }
        }
    }

    private static byte[] ReadP256PublicKey(string path)
    {
        var pemBytes = ReadBoundedFile(path, MaxPublicKeyFileBytes, "model-promotion public key");
        try
        {
            if (pemBytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
            {
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion public key must be BOM-less PEM.");
            }
            string pem;
            try
            {
                pem = StrictUtf8.GetString(pemBytes);
            }
            catch (DecoderFallbackException)
            {
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion public key must be valid UTF-8 PEM.");
            }
            const string begin = "-----BEGIN PUBLIC KEY-----";
            const string end = "-----END PUBLIC KEY-----";
            for (var index = 0; index < pem.Length; index++)
            {
                if (pem[index] == '\r' &&
                    (index + 1 >= pem.Length || pem[index + 1] != '\n'))
                {
                    throw new InvalidOperationException(
                        "The Vibe Quant model-promotion public key PEM is invalid.");
                }
            }
            var normalized = pem.Replace("\r\n", "\n", StringComparison.Ordinal);
            if (normalized.EndsWith('\n'))
            {
                normalized = normalized[..^1];
            }
            var lines = normalized.Split('\n');
            if (lines.Length < 3 ||
                !StringComparer.Ordinal.Equals(lines[0], begin) ||
                !StringComparer.Ordinal.Equals(lines[^1], end))
            {
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion public key must contain one PUBLIC KEY PEM block.");
            }
            var bodyLines = lines[1..^1];
            for (var index = 0; index < bodyLines.Length; index++)
            {
                var line = bodyLines[index];
                var isLast = index == bodyLines.Length - 1;
                if (line.Length is < 1 or > 64 || (!isLast && line.Length != 64) ||
                    line.Any(character =>
                        !char.IsAsciiLetterOrDigit(character) && character is not '+' and not '/' and not '=') ||
                    (!isLast && line.Contains('=')))
                {
                    throw new InvalidOperationException(
                        "The Vibe Quant model-promotion public key PEM is invalid.");
                }
            }
            var body = string.Concat(bodyLines);
            var paddingIndex = body.IndexOf('=');
            if (body.Length % 4 != 0 ||
                paddingIndex >= 0 &&
                (paddingIndex < body.Length - 2 || body[paddingIndex..].Any(character => character != '=')))
            {
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion public key PEM is invalid.");
            }
            byte[] spki;
            try
            {
                spki = Convert.FromBase64String(body);
            }
            catch (FormatException)
            {
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion public key PEM is invalid.");
            }
            try
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
                var parameters = key.ExportParameters(includePrivateParameters: false);
                if (bytesRead != spki.Length ||
                    parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value ||
                    parameters.Q.X is not { Length: 32 } ||
                    parameters.Q.Y is not { Length: 32 })
                {
                    throw new InvalidOperationException(
                        "The Vibe Quant model-promotion public key must be canonical P-256 SPKI.");
                }
                var canonicalSpki = key.ExportSubjectPublicKeyInfo();
                try
                {
                    if (!spki.AsSpan().SequenceEqual(canonicalSpki))
                    {
                        throw new InvalidOperationException(
                            "The Vibe Quant model-promotion public key must be canonical P-256 SPKI.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(canonicalSpki);
                }
                return spki;
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(spki);
                throw new InvalidOperationException(
                    "The Vibe Quant model-promotion public key must be canonical P-256 SPKI.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pemBytes);
        }
    }

    private static byte[] ReadBoundedFile(string path, int maximumBytes, string label)
    {
        var fullPath = Path.GetFullPath(path);
        RejectReparsePathComponents(fullPath, label);
        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is < 1 || stream.Length > maximumBytes)
        {
            throw new InvalidOperationException($"The Vibe Quant {label} size is invalid.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static void RejectReparsePathComponents(string fullPath, string label)
    {
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidOperationException($"The Vibe Quant {label} path has no filesystem root.");
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, fullPath)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    $"The Vibe Quant {label} path must not traverse a reparse point.");
            }
        }
    }

    private static byte[] DecodeCanonicalBase64Url(
        string value,
        int maximumBytes,
        string label,
        bool exactLength = false)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > checked(maximumBytes * 2) ||
            value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new InvalidOperationException($"The Vibe Quant {label} is not canonical base64url.");
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
            throw new InvalidOperationException($"The Vibe Quant {label} is not canonical base64url.");
        }
        if ((exactLength ? decoded.Length != maximumBytes : decoded.Length > maximumBytes) ||
            !StringComparer.Ordinal.Equals(value, EncodeBase64Url(decoded)))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidOperationException($"The Vibe Quant {label} is not canonical base64url.");
        }
        return decoded;
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool IsP256Scalar(ReadOnlySpan<byte> value) =>
        value.Length == 32 && value.IndexOfAnyExcept((byte)0) >= 0 && CompareBigEndian(value, P256Order) < 0;

    private static int CompareBigEndian(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return left.Length.CompareTo(right.Length);
        }
        for (var index = 0; index < left.Length; index++)
        {
            if (left[index] != right[index])
            {
                return left[index].CompareTo(right[index]);
            }
        }
        return 0;
    }

    private static string HashBytes(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private static void RequirePinnedHash(string actual, string expected, string message)
    {
        RequireSha256(expected, "Pinned SHA-256");
        var actualBytes = Convert.FromHexString(actual);
        var expectedBytes = Convert.FromHexString(expected);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes))
            {
                throw new InvalidOperationException(message);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualBytes);
            CryptographicOperations.ZeroMemory(expectedBytes);
        }
    }

    private static void RequirePromotionId(string value, string name)
    {
        if (value is not { Length: >= 1 and <= 200 } || !char.IsAsciiLetterOrDigit(value[0]) ||
            !value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':'))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    private static void RequireProfileId(string value, string name)
    {
        if (value is not { Length: >= 1 and <= 100 } || !char.IsAsciiLetterOrDigit(value[0]) ||
            !value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    private static void RequireModelId(string value, string name)
    {
        if (value is not { Length: >= 1 and <= 200 } || !char.IsAsciiLetterOrDigit(value[0]) ||
            !value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or '/'))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    private static void RequireText(string value, string name, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
        var length = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (++length > maximumLength || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Control)
            {
                throw new InvalidOperationException($"{name} is invalid.");
            }
        }
    }

    private static void RequireRevision(string value, string name)
    {
        if (value is not { Length: 40 } || !IsLowercaseHex(value))
        {
            throw new InvalidOperationException($"{name} must be an immutable lowercase commit.");
        }
    }

    private static void RequireSha256(string value, string name)
    {
        if (value is not { Length: 64 } || !IsLowercaseHex(value))
        {
            throw new InvalidOperationException($"{name} must be a lowercase SHA-256 value.");
        }
    }

    private static void RequirePrefixedSha256(string value, string prefix, string name)
    {
        if (value is null || !value.StartsWith(prefix, StringComparison.Ordinal) ||
            value.Length != prefix.Length + 64 || !IsLowercaseHex(value.AsSpan(prefix.Length)))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    private static bool IsLowercaseHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
            {
                return false;
            }
        }
        return true;
    }

    private sealed class LengthPrefixedBuilder : IDisposable
    {
        private readonly MemoryStream stream = new();

        public void Append(string value) => Append(StrictUtf8.GetBytes(value));

        public void Append(bool value) => Append(value ? "true" : "false");

        public void Append(int value) => Append(value.ToString(CultureInfo.InvariantCulture));

        public void Append(long value) => Append(value.ToString(CultureInfo.InvariantCulture));

        public void Append(ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
            stream.Write(length);
            stream.Write(value);
        }

        public byte[] ToArray() => stream.ToArray();

        public string ComputeSha256() => HashBytes(stream.GetBuffer().AsSpan(0, checked((int)stream.Length)));

        public void Dispose() => stream.Dispose();
    }
}

internal sealed record VibeQuantModelPromotionIdentity(
    string PromotionId,
    string EnvelopeSha256,
    string PayloadSha256,
    string DeploymentId,
    string ProviderId,
    string HostedPolicySha256,
    bool StrategyAuthoringAuthorized,
    DateTimeOffset ExpiresAtUtc,
    string ExpiresAtUtcText);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantModelPromotionEnvelope
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
internal sealed record VibeQuantModelPromotionPayload
{
    public required string SchemaVersion { get; init; }
    public required string PromotionId { get; init; }
    public required string Decision { get; init; }
    public required bool ProductionEligible { get; init; }
    public required string IssuedAtUtc { get; init; }
    public required string NotBeforeUtc { get; init; }
    public required string ExpiresAtUtc { get; init; }
    public required VibeQuantPromotionDataRelease DataRelease { get; init; }
    public required VibeQuantPromotionEvidence PromotionEvidence { get; init; }
    public required VibeQuantPromotionModel Model { get; init; }
    public required VibeQuantPromotionDeployment Deployment { get; init; }
    public required VibeQuantPromotionApproval Approval { get; init; }
    public required VibeQuantHostedDeploymentPolicy HostedDeploymentPolicy { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionDataRelease
{
    public required string ReleaseId { get; init; }
    public required string ReleaseSha256 { get; init; }
    public required string ManifestSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionEvidence
{
    public required string ReportSha256 { get; init; }
    public required string ReportFileSha256 { get; init; }
    public required string PolicySha256 { get; init; }
    public required string PolicyFileSha256 { get; init; }
    public required string CalibrationTasksFileSha256 { get; init; }
    public required string CalibrationTaskSetSha256 { get; init; }
    public required string CalibrationEvidenceSha256 { get; init; }
    public required string SealedTasksFileSha256 { get; init; }
    public required string SealedTaskSetSha256 { get; init; }
    public required string CandidateResponsesFileSha256 { get; init; }
    public required string CandidateResponseSetSha256 { get; init; }
    public required string CandidateVerifierResultsFileSha256 { get; init; }
    public required string CandidateVerifierResultSetSha256 { get; init; }
    public required string BaselineResponsesFileSha256 { get; init; }
    public required string BaselineResponseSetSha256 { get; init; }
    public required string BaselineVerifierResultsFileSha256 { get; init; }
    public required string BaselineVerifierResultSetSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionModel
{
    public required string CandidateCatalogSha256 { get; init; }
    public required string CandidateId { get; init; }
    public required string ModelId { get; init; }
    public required string ModelRevision { get; init; }
    public required string TrainingRunManifestSha256 { get; init; }
    public required string ArtifactMetadataFileSha256 { get; init; }
    public required string ArtifactSha256 { get; init; }
    public required string ArtifactTreeSha256 { get; init; }
    public required string ServingProfileId { get; init; }
    public required string ServingProfileSha256 { get; init; }
    public required string ExecutionModelId { get; init; }
    public required string ChatTemplateSha256 { get; init; }
    public required string ContainerImageDigest { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionDeployment
{
    public required string DeploymentId { get; init; }
    public required string Environment { get; init; }
    public required string Audience { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionApproval
{
    public required string ApprovalId { get; init; }
    public required string ActorId { get; init; }
    public required string ActorRole { get; init; }
    public required string Reference { get; init; }
    public required string ApprovedAtUtc { get; init; }
    public required string EvidenceSha256 { get; init; }
    public required long EvidenceSizeBytes { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantHostedDeploymentPolicy
{
    public required string SchemaVersion { get; init; }
    public required string PolicySha256 { get; init; }
    public required string ProviderId { get; init; }
    public required string Protocol { get; init; }
    public required VibeQuantPromotionPricing Pricing { get; init; }
    public required VibeQuantPromotionExecution Execution { get; init; }
    public required VibeQuantPromotionCoordinator Coordinator { get; init; }
    public JsonElement StrategyAuthoringCapability { get; init; }
    public required VibeQuantPromotionExpertContext ExpertContext { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionPricing
{
    public required string InputUsdPerMillionTokens { get; init; }
    public required string OutputUsdPerMillionTokens { get; init; }
    public required long CreditsPerUsd { get; init; }
    public required long MinimumChargeCredits { get; init; }
    public required string CreditPricingVersion { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionExecution
{
    public required int MaxRequests { get; init; }
    public required int MaxAttemptsPerRole { get; init; }
    public required int MaxPromptTokens { get; init; }
    public required int MaxOutputTokens { get; init; }
    public required int MaxOutputTokensPerRequest { get; init; }
    public required string MaxCostUsd { get; init; }
    public required int MaxResponseBytes { get; init; }
    public required int MaxArtifactBytes { get; init; }
    public required int MaxElapsedSeconds { get; init; }
    public required int RequestTimeoutSeconds { get; init; }
    public required bool RequireReportedUsage { get; init; }
    public required int MaxActiveRunsPerAccount { get; init; }
    public required int WorkerPollMilliseconds { get; init; }
    public required int ModelAttestationTimeoutSeconds { get; init; }
    public required int ModelAttestationRefreshSeconds { get; init; }
    public required int ModelAttestationTtlSeconds { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionCoordinator
{
    public required string PolicyVersion { get; init; }
    public required string WorkflowVersion { get; init; }
    public required string PromptCatalogSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionStrategyAuthoringCapability
{
    public required string Purpose { get; init; }
    public required string ExecutionModelId { get; init; }
    public required string PolicyVersion { get; init; }
    public required string WorkflowVersion { get; init; }
    public required string PromptCatalogSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionExpertContext
{
    public required string Mode { get; init; }
    public required string CorpusId { get; init; }
    public required string CorpusVersion { get; init; }
    public required string PackSha256 { get; init; }
    public required VibeQuantPromotionQueryPolicy QueryPolicy { get; init; }
    public required string QueryPolicySha256 { get; init; }
    public required int QueryMaxCharacters { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantPromotionQueryPolicy
{
    public required string SchemaVersion { get; init; }
    public required int TopK { get; init; }
    public required int MaxCharacters { get; init; }
    public required int MaxPerSource { get; init; }
}
