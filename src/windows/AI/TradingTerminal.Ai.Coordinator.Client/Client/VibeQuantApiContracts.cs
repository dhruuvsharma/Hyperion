using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Client;

public static class VibeQuantApiVersions
{
    public const string RunSpecification = "vibe-quant-run-spec/v1";
    public const int MaximumRequestBytes = 8_000_000;
    public const int MaximumResponseBytes = 4_000_000;
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CreateVibeQuantRunRequest(
    string Objective,
    IReadOnlyList<CoordinatorContextSource> Sources,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    CoordinatorRunPurpose Purpose = CoordinatorRunPurpose.Research);

public sealed record VibeQuantProviderView(
    string ProviderId,
    string ModelId,
    string Protocol);

public sealed record VibeQuantSourceView(
    string Id,
    string Title,
    string ContentSha256,
    int ContentCharacters,
    string? Uri,
    string? License,
    DateTimeOffset? RetrievedAtUtc);

public sealed record VibeQuantBudgetView(
    int MaxRequests,
    int MaxAttemptsPerRole,
    int MaxPromptTokens,
    int MaxOutputTokens,
    int MaxOutputTokensPerRequest,
    int MaxResponseBytes,
    int MaxArtifactBytes,
    int MaxElapsedSeconds,
    int RequestTimeoutSeconds);

public sealed record VibeQuantRunSpecification(
    string SchemaVersion,
    Guid RunId,
    string Objective,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<VibeQuantSourceView> Sources,
    VibeQuantProviderView Provider,
    VibeQuantBudgetView Budget,
    long MaximumCreditCharge,
    string CreditPricingVersion,
    string PolicyVersion,
    string WorkflowVersion,
    string PromptCatalogSha256,
    string ExecutionProfileBinding);

public sealed record VibeQuantRunSpecResponse(
    string SpecSha256,
    VibeQuantRunSpecification Spec);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record StartVibeQuantRunRequest(string SpecSha256);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ReleaseVibeQuantRunRequest(string ArtifactSha256);

public sealed record VibeQuantRunStatusResponse(
    Guid RunId,
    CoordinatorRunStatus Status,
    string SpecSha256,
    int CompletedRoleCount,
    bool CancellationRequested,
    long ReservedCredits,
    long ChargedCredits,
    string? FinalArtifactSha256,
    string? SafeMessage,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset UpdatedAtUtc);

public sealed record VibeQuantArtifactResponse(
    Guid RunId,
    string Sha256,
    CoordinatorRole Role,
    CoordinatorRoleOutput? Output,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    CoordinatorStrategySourceArtifact? StrategyArtifact = null);

public sealed record VibeQuantCreditBalanceResponse(
    long AvailableCredits,
    long ReservedCredits,
    long ConsumedCredits,
    string CreditPricingVersion,
    DateTimeOffset UpdatedAtUtc);
