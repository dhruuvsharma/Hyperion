using System.Globalization;
using System.Text;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Retrieval;

namespace DaxAlgo.Platform.Configuration;

public sealed class VibeQuantOptions
{
    public const string SectionName = "VibeQuant";

    public string Mode { get; init; } = "Mock";

    public string WorkspacePath { get; init; } = Path.Combine(AppContext.BaseDirectory, "vibe-quant-data");

    public string ProviderId { get; init; } = "mock";

    public string ModelId { get; init; } = "deterministic-v1";

    public string Protocol { get; init; } = "mock";

    public string? BaseUrl { get; init; }

    public string? ApiKeyEnvironmentVariable { get; init; }

    public string? ModelDeploymentProfilePath { get; init; }

    public string? ModelDeploymentProfileSha256 { get; init; }

    public string? ModelPromotionEnvelopePath { get; init; }

    public string? ModelPromotionEnvelopeSha256 { get; init; }

    public string? ModelPromotionPublicKeyPath { get; init; }

    public string? ModelPromotionPublicKeySpkiSha256 { get; init; }

    public string? ModelPromotionAudience { get; init; }

    public string? ModelPromotionKeyId { get; init; }

    public string? ModelPromotionSignerRole { get; init; }

    public string? ModelPromotionDeploymentId { get; init; }

    public string? ModelPromotionEnvironment { get; init; }

    public string? ModelAttestationAudience { get; init; }

    public string? ModelAttestationKeyId { get; init; }

    public string? ModelAttestationKeyEnvironmentVariable { get; init; }

    public int ModelAttestationTimeoutSeconds { get; init; } = 10;

    public int ModelAttestationRefreshSeconds { get; init; } = 30;

    public int ModelAttestationTtlSeconds { get; init; } = 90;

    public decimal InputUsdPerMillionTokens { get; init; }

    public decimal OutputUsdPerMillionTokens { get; init; }

    public int MaxRequests { get; init; } = 8;

    public int MaxAttemptsPerRole { get; init; } = 2;

    public int MaxPromptTokens { get; init; } = 100_000;

    public int MaxOutputTokens { get; init; } = 25_000;

    public int MaxOutputTokensPerRequest { get; init; } = 4_096;

    public decimal MaxCostUsd { get; init; } = 5m;

    public int MaxResponseBytes { get; init; } = 1_000_000;

    public int MaxArtifactBytes { get; init; } = 2_000_000;

    public int MaxElapsedSeconds { get; init; } = 900;

    public int RequestTimeoutSeconds { get; init; } = 120;

    public bool RequireReportedUsage { get; init; } = true;

    public long CreditsPerUsd { get; init; } = 100;

    public long MinimumChargeCredits { get; init; } = 1;

    public string CreditPricingVersion { get; init; } = "development-v1";

    public int MaxActiveRunsPerAccount { get; init; } = 5;

    public int WorkerPollMilliseconds { get; init; } = 250;

    public string ExpertContextMode { get; init; } = "Disabled";

    public string? ExpertContextPackPath { get; init; }

    public string? ExpertContextCorpusId { get; init; }

    public string? ExpertContextCorpusVersion { get; init; }

    public string? ExpertContextPackSha256 { get; init; }

    public int ExpertContextTopK { get; init; } = 12;

    public int ExpertContextMaxCharacters { get; init; } = 40_000;

    public int ExpertContextMaxPerSource { get; init; } = 4;

    public int ExpertContextQueryMaxCharacters { get; init; } = 80_000;

    public CoordinatorBudget CreateBudget() => new(
        MaxRequests,
        MaxAttemptsPerRole,
        MaxPromptTokens,
        MaxOutputTokens,
        MaxOutputTokensPerRequest,
        MaxCostUsd,
        MaxResponseBytes,
        MaxArtifactBytes,
        MaxElapsedSeconds,
        RequestTimeoutSeconds,
        RequireReportedUsage);

    public long MaximumCreditCharge => checked((long)decimal.Ceiling(MaxCostUsd * CreditsPerUsd));

    public void Validate()
    {
        if (Mode is not ("Mock" or "Live"))
        {
            throw new InvalidOperationException("VibeQuant:Mode must be Mock or Live.");
        }
        if (string.IsNullOrWhiteSpace(WorkspacePath))
        {
            throw new InvalidOperationException("VibeQuant:WorkspacePath is required.");
        }
        if (string.IsNullOrWhiteSpace(ProviderId) || string.IsNullOrWhiteSpace(ModelId))
        {
            throw new InvalidOperationException("Vibe Quant provider and model IDs are required.");
        }
        if (Mode == "Mock" && Protocol != "mock")
        {
            throw new InvalidOperationException("Mock Vibe Quant mode requires protocol 'mock'.");
        }
        if (Mode == "Live" && Protocol != "openai-compatible")
        {
            throw new InvalidOperationException("Live Vibe Quant mode requires protocol 'openai-compatible'.");
        }
        if (Mode == "Live" && !IsProviderIdentity(ProviderId))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a safe provider ID limited to 100 characters.");
        }
        if (Mode == "Live" && string.IsNullOrWhiteSpace(BaseUrl))
        {
            throw new InvalidOperationException("Live Vibe Quant mode requires a server-owned base URL.");
        }
        if (Mode == "Live" &&
            !LlmProviderValidation.TryValidateEndpoint(BaseUrl, out _, out var endpointError))
        {
            throw new InvalidOperationException(
                $"Live Vibe Quant base URL is invalid: {endpointError ?? "endpoint validation failed."}");
        }
        if (Mode == "Live" && !IsDedicatedEnvironmentVariable(ApiKeyEnvironmentVariable, "DAXALGO_LLM_"))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a dedicated DAXALGO_LLM_ API-key environment-variable name.");
        }
        if (Mode == "Live" &&
            (string.IsNullOrWhiteSpace(ModelDeploymentProfilePath) ||
             !Path.IsPathFullyQualified(ModelDeploymentProfilePath) ||
             !File.Exists(ModelDeploymentProfilePath)))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires an existing absolute serving-profile path.");
        }
        if (Mode == "Live" && !IsLowercaseSha256(ModelDeploymentProfileSha256))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a lowercase serving-profile SHA-256.");
        }
        if (Mode == "Live" &&
            (string.IsNullOrWhiteSpace(ModelPromotionEnvelopePath) ||
             !Path.IsPathFullyQualified(ModelPromotionEnvelopePath) ||
             !File.Exists(ModelPromotionEnvelopePath)))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires an existing absolute model-promotion envelope path.");
        }
        if (Mode == "Live" && !IsLowercaseSha256(ModelPromotionEnvelopeSha256))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a lowercase model-promotion envelope SHA-256.");
        }
        if (Mode == "Live" &&
            (string.IsNullOrWhiteSpace(ModelPromotionPublicKeyPath) ||
             !Path.IsPathFullyQualified(ModelPromotionPublicKeyPath) ||
             !File.Exists(ModelPromotionPublicKeyPath)))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires an existing absolute model-promotion public-key path.");
        }
        if (Mode == "Live" && !IsLowercaseSha256(ModelPromotionPublicKeySpkiSha256))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a lowercase model-promotion SPKI SHA-256.");
        }
        if (Mode == "Live" &&
            (!IsPromotionIdentity(ModelPromotionAudience) ||
             !IsPromotionIdentity(ModelPromotionKeyId) ||
             !IsPromotionIdentity(ModelPromotionSignerRole) ||
             !IsPromotionIdentity(ModelPromotionDeploymentId) ||
             !IsPromotionIdentity(ModelPromotionEnvironment)))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires safe model-promotion audience, key, role, deployment, and environment identities.");
        }
        if (Mode == "Live" &&
            (!IsPromotionIdentity(ModelAttestationAudience) ||
             !IsPromotionIdentity(ModelAttestationKeyId)))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires safe model-attestation audience and key identities.");
        }
        if (Mode == "Live" &&
            !IsDedicatedEnvironmentVariable(
                ModelAttestationKeyEnvironmentVariable,
                "DAXALGO_MODEL_ATTESTATION_"))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a dedicated DAXALGO_MODEL_ATTESTATION_ key environment-variable name.");
        }
        if (Mode == "Live" &&
            (ModelAttestationTimeoutSeconds is < 1 or > 60 ||
             ModelAttestationRefreshSeconds is < 5 or > 300 ||
             ModelAttestationTtlSeconds is < 10 or > 900 ||
             ModelAttestationTimeoutSeconds >= ModelAttestationRefreshSeconds ||
             ModelAttestationRefreshSeconds >= ModelAttestationTtlSeconds))
        {
            throw new InvalidOperationException(
                "Live Vibe Quant model-attestation timeout, refresh, and TTL settings are invalid.");
        }
        if (CreditsPerUsd is < 1 or > 1_000_000_000 || MinimumChargeCredits is < 0 or > 1_000_000_000)
        {
            throw new InvalidOperationException("Vibe Quant credit conversion values are outside supported limits.");
        }
        if (!IsContractText(CreditPricingVersion, 100))
        {
            throw new InvalidOperationException(
                "Vibe Quant credit pricing version must be non-control text limited to 100 characters.");
        }
        if (MaxActiveRunsPerAccount is < 1 or > 100 || WorkerPollMilliseconds is < 50 or > 60_000)
        {
            throw new InvalidOperationException("Vibe Quant active-run or worker-poll configuration is invalid.");
        }
        if (MaxArtifactBytes > 2_000_000)
        {
            throw new InvalidOperationException(
                "VibeQuant:MaxArtifactBytes cannot exceed the hosted 2,000,000-byte response-safe limit.");
        }
        if (MaxElapsedSeconds < checked((RequestTimeoutSeconds * 2) + 60))
        {
            throw new InvalidOperationException(
                "VibeQuant:MaxElapsedSeconds must leave time to recover and retry one timed-out request.");
        }
        if (ExpertContextMode is not ("Disabled" or "Pinned"))
        {
            throw new InvalidOperationException(
                "VibeQuant:ExpertContextMode must be Disabled or Pinned.");
        }
        if (Mode == "Live" && ExpertContextMode != "Pinned")
        {
            throw new InvalidOperationException(
                "Live Vibe Quant mode requires a pinned expert-context pack.");
        }
        if (ExpertContextMode == "Pinned")
        {
            if (string.IsNullOrWhiteSpace(ExpertContextPackPath) ||
                !Path.IsPathFullyQualified(ExpertContextPackPath) ||
                !File.Exists(ExpertContextPackPath))
            {
                throw new InvalidOperationException(
                    "Pinned expert context requires an existing absolute pack path.");
            }
            if (!IsSafeIdentity(ExpertContextCorpusId) ||
                !IsSafeIdentity(ExpertContextCorpusVersion) ||
                IsMutableCorpusVersion(ExpertContextCorpusVersion!))
            {
                throw new InvalidOperationException(
                    "Pinned expert context corpus ID and immutable version are required safe identities.");
            }
            if (!IsLowercaseSha256(ExpertContextPackSha256))
            {
                throw new InvalidOperationException(
                    "Pinned expert context requires a lowercase pack SHA-256.");
            }
        }
        if (ExpertContextQueryMaxCharacters is < CoordinatorValidation.MaxObjectiveCharacters or
            > ExpertContextPackTools.MaxQueryCharacters)
        {
            throw new InvalidOperationException(
                "Vibe Quant expert-context query budget is outside supported limits.");
        }
        try
        {
            ExpertContextPackTools.ValidateQueryPolicy(CreateExpertContextPolicy());
        }
        catch (CoordinatorValidationException exception)
        {
            throw new InvalidOperationException(
                $"Vibe Quant expert-context policy is invalid: {exception.Message}",
                exception);
        }

        _ = MaximumCreditCharge;
        TradingTerminal.Ai.Coordinator.Orchestration.CoordinatorValidation.ValidateBudget(CreateBudget());
    }

    public ExpertContextQueryPolicy CreateExpertContextPolicy() => new()
    {
        SchemaVersion = ExpertContextPackTools.QueryPolicySchemaVersion,
        TopK = ExpertContextTopK,
        MaxCharacters = ExpertContextMaxCharacters,
        MaxPerSource = ExpertContextMaxPerSource
    };

    private static bool IsSafeIdentity(string? value) =>
        value is { Length: >= 1 and <= 100 } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static bool IsPromotionIdentity(string? value) =>
        value is { Length: >= 1 and <= 200 } &&
        char.IsAsciiLetterOrDigit(value[0]) &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or ':');

    private static bool IsProviderIdentity(string? value) =>
        value is { Length: >= 1 and <= 100 } &&
        char.IsAsciiLetterOrDigit(value[0]) &&
        value.All(character => char.IsAsciiLetterOrDigit(character) ||
            character is '-' or '_' or '.' or ':');

    private static bool IsMutableCorpusVersion(string value) =>
        value.Equals("latest", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("main", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("master", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("trunk", StringComparison.OrdinalIgnoreCase);

    private static bool IsContractText(string? value, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }
        var length = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (++length > maximumLength || Rune.GetUnicodeCategory(rune) == UnicodeCategory.Control)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsLowercaseSha256(string? value) =>
        value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsDedicatedEnvironmentVariable(string? value, string prefix) =>
        value is { Length: >= 1 and <= 128 } &&
        value.StartsWith(prefix, StringComparison.Ordinal) &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character == '_');
}
