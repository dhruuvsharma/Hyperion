using System.Text.Json.Serialization;

namespace TradingTerminal.Ai.Coordinator.Contracts;

public static class CoordinatorVersions
{
    public const string Policy = "research-only/v1";
    public const string Workflow = "fixed-research/v1";
    public const string ArtifactSchema = "coordinator-role-output/v1";
    public const string StrategyPolicy = "strategy-authoring-inert/v1";
    public const string StrategyWorkflow = "fixed-strategy-authoring/v1";
    public const string FreeStrategyPolicy = "free-strategy-authoring-inert/v1";
    public const string FreeStrategyWorkflow = "fixed-free-strategy-authoring/v1";
    public const string StrategyArtifactSchema = "coordinator-strategy-source/v1";
    public const string StrategyArtifactKind = "StrategySource";
    public const string StrategyDeliveryState = "inert-source/v1";
    public const string StrategyCompilerProfile = "terminal-authored-strategy/v1";
    public const string ResearchPromptCatalogSha256 =
        "cf2ab6ea1bf26ae396c2366f0e2d6b5df00a2687caea5089440c97e46c68567a";
    public const string StrategyPromptCatalogSha256 =
        "bb79da228ed798981334970908f4cdb8739edb1e728f67b21156adbe101cdb0b";
    public const string DatasetSchema = "coordinator-dataset/v1";
    public const string ExpertModelDatasetSchema = "expert-model-dataset/v1";
}

public static class LlmProviderProtocols
{
    public const string Mock = "mock";
    public const string OpenAiCompatible = "openai-compatible";
    public const string AnthropicMessages = "anthropic-messages/v1";
    public const string GoogleGemini = "google-gemini-generate-content/v1";
    public const string Replay = "replay";
    public const string ExternalAdapter = "external-adapter/v1";
}

public enum CoordinatorRunPurpose
{
    Research,
    StrategyAuthoring
}

public enum CoordinatorRunStatus
{
    AwaitingStartApproval,
    Ready,
    Running,
    AwaitingReleaseApproval,
    Completed,
    NeedsRevision,
    Rejected,
    Cancelled,
    Failed,
    BudgetExhausted
}

public enum CoordinatorRole
{
    Planner,
    EvidenceAnalyst,
    Critic,
    Synthesizer,
    RiskJudge
}

public enum CoordinatorDecision
{
    None,
    Approve,
    Revise,
    Reject
}

public enum ApprovalGate
{
    Start,
    Release
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CoordinatorContextSource(
    string Id,
    string Title,
    string Content,
    string? Uri = null,
    string? License = null,
    DateTimeOffset? RetrievedAtUtc = null);

public sealed record LlmProviderDescriptor(
    string ProviderId,
    string ModelId,
    string Protocol,
    string? Endpoint,
    decimal InputUsdPerMillionTokens = 0m,
    decimal OutputUsdPerMillionTokens = 0m,
    string? CredentialEnvironmentVariable = null,
    string? ReplaySha256 = null);

public sealed record CoordinatorBudget(
    int MaxRequests = 8,
    int MaxAttemptsPerRole = 2,
    int MaxPromptTokens = 100_000,
    int MaxOutputTokens = 25_000,
    int MaxOutputTokensPerRequest = 4_096,
    decimal MaxCostUsd = 5m,
    int MaxResponseBytes = 1_000_000,
    int MaxArtifactBytes = 2_000_000,
    int MaxElapsedSeconds = 900,
    int RequestTimeoutSeconds = 120,
    bool RequireReportedUsage = true);

public sealed record CoordinatorRunSpec(
    Guid RunId,
    string Objective,
    string Owner,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<CoordinatorContextSource> Sources,
    LlmProviderDescriptor Provider,
    CoordinatorBudget Budget,
    string PolicyVersion = CoordinatorVersions.Policy,
    string WorkflowVersion = CoordinatorVersions.Workflow,
    string PromptCatalogSha256 = "",
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    CoordinatorRunPurpose Purpose = CoordinatorRunPurpose.Research);

public sealed record CoordinatorUsage(
    long Requests = 0,
    long PromptTokens = 0,
    long OutputTokens = 0,
    decimal CostUsd = 0m,
    long ResponseBytes = 0,
    long ArtifactBytes = 0);

public sealed record CoordinatorApproval(
    ApprovalGate Gate,
    string Actor,
    DateTimeOffset ApprovedAtUtc,
    string BoundSpecSha256,
    string? BoundArtifactSha256);

public sealed record CoordinatorArtifactReference(
    CoordinatorRole Role,
    string Kind,
    string SchemaVersion,
    string Sha256,
    string RelativePath,
    long SizeBytes,
    DateTimeOffset CreatedAtUtc);

public sealed record CoordinatorInvocation(
    Guid InvocationId,
    CoordinatorRole Role,
    int Attempt,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string PromptSha256,
    string Status,
    LlmUsage? Usage,
    string? ArtifactSha256,
    string? SafeError,
    int ReservedPromptTokens = 0,
    int ReservedOutputTokens = 0,
    int ReservedResponseBytes = 0,
    LlmUsage? ReportedUsage = null,
    string? ProviderRequestId = null);

public sealed record CoordinatorRunSnapshot
{
    public required CoordinatorRunSpec Spec { get; init; }
    public required CoordinatorRunStatus Status { get; init; }
    public long Version { get; init; }
    public int CompletedRoleCount { get; init; }
    public CoordinatorUsage Usage { get; init; } = new();
    public IReadOnlyList<CoordinatorArtifactReference> Artifacts { get; init; } = [];
    public IReadOnlyList<CoordinatorInvocation> Invocations { get; init; } = [];
    public IReadOnlyList<CoordinatorApproval> Approvals { get; init; } = [];
    public string? FinalArtifactSha256 { get; init; }
    public string? SafeMessage { get; init; }
    public DateTimeOffset UpdatedAtUtc { get; init; }
}

public sealed record CoordinatorClaim(
    string Statement,
    IReadOnlyList<string> EvidenceSourceIds,
    decimal Confidence);

public sealed record CoordinatorRoleOutput
{
    public required string SchemaVersion { get; init; }
    public required CoordinatorRole Role { get; init; }
    public required string Summary { get; init; }
    public IReadOnlyList<CoordinatorClaim> Claims { get; init; } = [];
    public IReadOnlyList<string> Risks { get; init; } = [];
    public IReadOnlyList<string> Recommendations { get; init; } = [];
    public IReadOnlyList<string> SourceIds { get; init; } = [];
    public CoordinatorDecision Decision { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CoordinatorStrategyDraft? StrategyDraft { get; init; }
}

public sealed record StoredArtifact(
    string Sha256,
    string RelativePath,
    long SizeBytes);

public sealed record CoordinatorEventRecord(
    Guid RunId,
    long Sequence,
    string Type,
    string PayloadJson,
    string PreviousSha256,
    string Sha256,
    DateTimeOffset OccurredAtUtc);

public sealed record LlmMessage(string Role, string Content);

public sealed record LlmRequest(
    string RequestId,
    CoordinatorRole Role,
    string SystemPrompt,
    IReadOnlyList<LlmMessage> Messages,
    int MaxOutputTokens,
    int MaxResponseBytes,
    decimal Temperature = 0m);

public sealed record LlmUsage(long InputTokens, long OutputTokens);

public sealed record LlmCompletion(
    string Text,
    LlmUsage? Usage,
    string? FinishReason = null,
    string? ProviderRequestId = null,
    long ResponseBytes = 0);

public sealed record LlmFailure(
    string Kind,
    string SafeMessage,
    bool Retryable,
    long? ResponseBytes = null);

public sealed record LlmCallResult(LlmCompletion? Completion, LlmFailure? Failure)
{
    public bool IsSuccess => Completion is not null && Failure is null;

    public static LlmCallResult Success(LlmCompletion completion) => new(completion, null);

    public static LlmCallResult Failed(
        string kind,
        string safeMessage,
        bool retryable = false,
        long? responseBytes = null) =>
        new(null, new LlmFailure(kind, safeMessage, retryable, responseBytes));
}
