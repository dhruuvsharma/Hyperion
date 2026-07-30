using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Orchestration;

public sealed class CoordinatorValidationException(string message) : Exception(message);

public static class CoordinatorValidation
{
    public const int MaxObjectiveCharacters = 20_000;
    public const int MaxSourceCount = 64;
    public const int MaxSourceContentCharacters = 500_000;
    public const int MaxAggregateSourceCharacters = 2_000_000;
    public const int MaxSourceUriCharacters = 2_048;
    public const int MaxSourceLicenseCharacters = 200;

    public static void ValidateSpec(CoordinatorRunSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Sources is null || spec.Provider is null || spec.Budget is null)
        {
            throw new CoordinatorValidationException("Sources, provider, and budget are required.");
        }
        if (spec.RunId == Guid.Empty)
        {
            throw new CoordinatorValidationException("Run ID must not be empty.");
        }
        if (spec.CreatedAtUtc == default || spec.CreatedAtUtc > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new CoordinatorValidationException("Run creation time must be set and not be in the future.");
        }

        RequireText(spec.Objective, "Objective", MaxObjectiveCharacters);
        RequireText(spec.Owner, "Owner", 200);
        RequireText(spec.PolicyVersion, "Policy version", 100);
        RequireText(spec.WorkflowVersion, "Workflow version", 100);
        RequireText(spec.Provider.ProviderId, "Provider ID", 100);
        RequireText(spec.Provider.ModelId, "Model ID", 200);
        RequireText(spec.Provider.Protocol, "Provider protocol", 100);
        if (spec.Provider.InputUsdPerMillionTokens is < 0m or > 1_000_000m ||
            spec.Provider.OutputUsdPerMillionTokens is < 0m or > 1_000_000m)
        {
            throw new CoordinatorValidationException("Provider token prices must be between 0 and 1,000,000 USD per million tokens.");
        }
        if (spec.Provider.Protocol == "replay" &&
            (spec.Provider.ReplaySha256 is not { Length: 64 } replaySha256 || !replaySha256.All(Uri.IsHexDigit)))
        {
            throw new CoordinatorValidationException("Replay runs require a valid replay-file SHA-256 binding.");
        }
        Uri? liveEndpoint = null;
        if (spec.Provider.Protocol == "openai-compatible" &&
            !LlmProviderValidation.TryValidateEndpoint(spec.Provider.Endpoint, out liveEndpoint, out var endpointError))
        {
            throw new CoordinatorValidationException(endpointError ?? "Live provider endpoint is invalid.");
        }
        if (spec.Provider.Protocol == "openai-compatible" && liveEndpoint is { IsLoopback: false } &&
            (spec.Provider.InputUsdPerMillionTokens <= 0m || spec.Provider.OutputUsdPerMillionTokens <= 0m))
        {
            throw new CoordinatorValidationException("Remote live runs require positive input and output token prices.");
        }
        if (spec.Provider.Protocol == "openai-compatible" && liveEndpoint is { IsLoopback: false } &&
            !IsDedicatedCredentialEnvironmentVariable(spec.Provider.CredentialEnvironmentVariable))
        {
            throw new CoordinatorValidationException(
                "Remote live runs require a dedicated DAXALGO_LLM_ credential environment-variable binding.");
        }
        if (spec.Provider.CredentialEnvironmentVariable is not null &&
            !IsDedicatedCredentialEnvironmentVariable(spec.Provider.CredentialEnvironmentVariable))
        {
            throw new CoordinatorValidationException("Credential environment-variable binding is invalid.");
        }
        if (spec.Provider.Protocol != "openai-compatible" &&
            spec.Provider.CredentialEnvironmentVariable is not null)
        {
            throw new CoordinatorValidationException("Only a live OpenAI-compatible provider may bind credentials.");
        }
        if (spec.Provider.Protocol != "replay" && spec.Provider.ReplaySha256 is not null)
        {
            throw new CoordinatorValidationException("Only replay providers may carry a replay-file binding.");
        }

        if (!IsSupportedProfile(spec))
        {
            throw new CoordinatorValidationException(
                "This executable only accepts its built-in policy, workflow, and provider profiles.");
        }
        if (!StringComparer.Ordinal.Equals(
                spec.PromptCatalogSha256,
                CoordinatorPromptCatalog.Sha256For(spec.Purpose)))
        {
            throw new CoordinatorValidationException("Run prompt-catalog SHA-256 does not match this executable.");
        }

        if (spec.Sources.Count > MaxSourceCount)
        {
            throw new CoordinatorValidationException(
                $"Run sources exceed the {MaxSourceCount}-source limit.");
        }

        var sourceIds = new HashSet<string>(StringComparer.Ordinal);
        var aggregateSourceCharacters = 0;
        foreach (var source in spec.Sources)
        {
            if (source is null)
            {
                throw new CoordinatorValidationException("Run sources must not contain null entries.");
            }
            RequireText(source.Id, "Source ID", 100);
            RequireText(source.Title, $"Source '{source.Id}' title", 500);
            RequireText(source.Content, $"Source '{source.Id}' content", MaxSourceContentCharacters);
            if (source.Uri is not null)
            {
                if (source.Uri.Length > MaxSourceUriCharacters ||
                    !System.Uri.TryCreate(source.Uri, UriKind.Absolute, out var sourceUri) ||
                    (sourceUri.Scheme != Uri.UriSchemeHttps && sourceUri.Scheme != Uri.UriSchemeHttp))
                {
                    throw new CoordinatorValidationException(
                        $"Source '{source.Id}' URI must be an absolute HTTP(S) URI within {MaxSourceUriCharacters} characters.");
                }
            }
            if (source.License is not null &&
                (string.IsNullOrWhiteSpace(source.License) || source.License.Length > MaxSourceLicenseCharacters))
            {
                throw new CoordinatorValidationException(
                    $"Source '{source.Id}' license must contain 1 to {MaxSourceLicenseCharacters} characters when supplied.");
            }
            aggregateSourceCharacters += source.Content.Length;
            if (aggregateSourceCharacters > MaxAggregateSourceCharacters)
            {
                throw new CoordinatorValidationException(
                    $"Run source content exceeds the {MaxAggregateSourceCharacters:N0}-character aggregate limit.");
            }
            if (!source.Id.All(character => char.IsLetterOrDigit(character) || character is '-' or '_' or '.'))
            {
                throw new CoordinatorValidationException(
                    $"Source ID '{source.Id}' may contain only letters, digits, '.', '-' and '_'.");
            }
            if (spec.Purpose == CoordinatorRunPurpose.StrategyAuthoring &&
                !CoordinatorStrategyArtifactValidation.IsSafeIdentifier(source.Id, 100))
            {
                throw new CoordinatorValidationException(
                    $"Strategy source ID '{source.Id}' must use the artifact-safe ASCII identifier grammar.");
            }

            if (!sourceIds.Add(source.Id))
            {
                throw new CoordinatorValidationException($"Duplicate source ID '{source.Id}'.");
            }
        }

        ValidateBudget(spec.Budget);
    }

    internal static bool IsSupportedProfile(CoordinatorRunSpec spec) => spec.Purpose switch
    {
        CoordinatorRunPurpose.Research =>
            spec.PolicyVersion == CoordinatorVersions.Policy &&
            spec.WorkflowVersion == CoordinatorVersions.Workflow,
        CoordinatorRunPurpose.StrategyAuthoring =>
            spec.PolicyVersion == CoordinatorVersions.StrategyPolicy &&
            spec.WorkflowVersion == CoordinatorVersions.StrategyWorkflow &&
            spec.Provider.Protocol is "mock" or "openai-compatible",
        _ => false
    };

    public static CoordinatorRoleOutput ParseRoleOutput(
        string json,
        CoordinatorRole expectedRole,
        IReadOnlySet<string> allowedSourceIds,
        CoordinatorRunPurpose purpose = CoordinatorRunPurpose.Research)
    {
        CoordinatorRoleOutput output;
        try
        {
            using var document = JsonDocument.Parse(json);
            var properties = new List<string>
            {
                "schemaVersion",
                "role",
                "summary",
                "claims",
                "risks",
                "recommendations",
                "sourceIds",
                "decision"
            };
            if (purpose == CoordinatorRunPurpose.StrategyAuthoring && expectedRole == CoordinatorRole.Synthesizer)
            {
                properties.Add("strategyDraft");
            }
            RequireObjectProperties(document.RootElement, "role output", [.. properties]);
            foreach (var arrayName in new[] { "claims", "risks", "recommendations", "sourceIds" })
            {
                if (document.RootElement.GetProperty(arrayName).ValueKind != JsonValueKind.Array)
                {
                    throw new CoordinatorValidationException($"Role output '{arrayName}' must be an array.");
                }
            }

            foreach (var claimElement in document.RootElement.GetProperty("claims").EnumerateArray())
            {
                RequireObjectProperties(
                    claimElement,
                    "claim",
                    "statement",
                    "evidenceSourceIds",
                    "confidence");
                if (claimElement.GetProperty("evidenceSourceIds").ValueKind != JsonValueKind.Array)
                {
                    throw new CoordinatorValidationException("Claim evidenceSourceIds must be an array.");
                }
            }

            output = JsonSerializer.Deserialize<CoordinatorRoleOutput>(json, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException("Model returned JSON null.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"Model output was not valid coordinator JSON: {exception.Message}");
        }

        if (output.SchemaVersion != CoordinatorVersions.ArtifactSchema)
        {
            throw new CoordinatorValidationException(
                $"Expected artifact schema '{CoordinatorVersions.ArtifactSchema}'.");
        }

        if (output.Role != expectedRole)
        {
            throw new CoordinatorValidationException(
                $"Expected role '{expectedRole}' but received '{output.Role}'.");
        }

        RequireText(output.Summary, "Role output summary", 30_000);
        if (output.Claims.Count > 100 || output.Risks.Count > 100 || output.Recommendations.Count > 100)
        {
            throw new CoordinatorValidationException("Role output exceeded the maximum list length.");
        }

        foreach (var risk in output.Risks)
        {
            RequireText(risk, "Risk", 10_000);
        }

        foreach (var recommendation in output.Recommendations)
        {
            RequireText(recommendation, "Recommendation", 10_000);
        }

        foreach (var claim in output.Claims)
        {
            RequireText(claim.Statement, "Claim statement", 10_000);
            if (claim.Confidence is < 0m or > 1m)
            {
                throw new CoordinatorValidationException("Claim confidence must be between 0 and 1.");
            }

            ValidateSourceIds(claim.EvidenceSourceIds, allowedSourceIds);
        }

        ValidateSourceIds(output.SourceIds, allowedSourceIds);
        if (purpose == CoordinatorRunPurpose.StrategyAuthoring &&
            (output.SourceIds.Any(sourceId =>
                 !CoordinatorStrategyArtifactValidation.IsSafeIdentifier(sourceId, 100)) ||
             output.SourceIds.Distinct(StringComparer.Ordinal).Count() != output.SourceIds.Count))
        {
            throw new CoordinatorValidationException(
                "Strategy output source IDs must be unique artifact-safe ASCII identifiers.");
        }
        if (expectedRole == CoordinatorRole.RiskJudge && output.Decision == CoordinatorDecision.None)
        {
            throw new CoordinatorValidationException("RiskJudge must return Approve, Revise, or Reject.");
        }

        if (expectedRole != CoordinatorRole.RiskJudge && output.Decision != CoordinatorDecision.None)
        {
            throw new CoordinatorValidationException("Only RiskJudge may set a decision.");
        }

        ValidateStrategyDraft(output, expectedRole, purpose);

        return output;
    }

    private static void ValidateStrategyDraft(
        CoordinatorRoleOutput output,
        CoordinatorRole expectedRole,
        CoordinatorRunPurpose purpose)
    {
        var requiresDraft = purpose == CoordinatorRunPurpose.StrategyAuthoring &&
                            expectedRole == CoordinatorRole.Synthesizer;
        if (!requiresDraft)
        {
            if (output.StrategyDraft is not null)
            {
                throw new CoordinatorValidationException(
                    "Only the strategy-authoring Synthesizer may return a strategy draft.");
            }
            return;
        }

        var draft = output.StrategyDraft
            ?? throw new CoordinatorValidationException("Strategy-authoring Synthesizer output requires a strategy draft.");
        try
        {
            CoordinatorStrategyArtifactValidation.ValidateDraft(draft);
        }
        catch (InvalidDataException exception)
        {
            throw new CoordinatorValidationException(exception.Message);
        }
    }

    public static void ValidateBudget(CoordinatorBudget budget)
    {
        if (budget.MaxRequests <= 0 || budget.MaxAttemptsPerRole <= 0 || budget.MaxPromptTokens <= 0 ||
            budget.MaxOutputTokens <= 0 || budget.MaxOutputTokensPerRequest <= 0 ||
            budget.MaxResponseBytes <= 0 || budget.MaxArtifactBytes <= 0 ||
            budget.MaxElapsedSeconds <= 0 || budget.RequestTimeoutSeconds <= 0 || budget.MaxCostUsd < 0m)
        {
            throw new CoordinatorValidationException("Coordinator budget limits must be positive (cost may be zero).");
        }

        if (budget.MaxOutputTokensPerRequest > budget.MaxOutputTokens)
        {
            throw new CoordinatorValidationException("Per-request output tokens cannot exceed the run output-token limit.");
        }
        if (budget.MaxRequests > 1_000 || budget.MaxAttemptsPerRole > 20 ||
            budget.MaxPromptTokens > 10_000_000 || budget.MaxOutputTokens > 10_000_000 ||
            budget.MaxOutputTokensPerRequest > 1_000_000 || budget.MaxCostUsd > 1_000_000m ||
            budget.MaxResponseBytes > 100_000_000 || budget.MaxArtifactBytes > 100_000_000 ||
            budget.MaxElapsedSeconds > 86_400 || budget.RequestTimeoutSeconds > 3_600)
        {
            throw new CoordinatorValidationException("Coordinator budget exceeds the first-slice safety ceiling.");
        }
    }

    private static void ValidateSourceIds(IEnumerable<string> sourceIds, IReadOnlySet<string> allowedSourceIds)
    {
        foreach (var sourceId in sourceIds)
        {
            if (!allowedSourceIds.Contains(sourceId))
            {
                throw new CoordinatorValidationException($"Output cited unknown source ID '{sourceId}'.");
            }
        }
    }

    private static void RequireText(string? value, string name, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new CoordinatorValidationException($"{name} is required.");
        }

        if (value.Length > maxLength)
        {
            throw new CoordinatorValidationException($"{name} exceeds {maxLength} characters.");
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

    private static bool IsDedicatedCredentialEnvironmentVariable(string? value) =>
        value is { Length: <= 128 } &&
        value.StartsWith("DAXALGO_LLM_", StringComparison.Ordinal) &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character == '_');
}
