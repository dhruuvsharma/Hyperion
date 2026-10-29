using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace Hyperion.FreeStrategyWorkflow;

public static class FreeStrategyWorkflowVersions
{
    public const string Manifest = "hyperion-free-strategy-workflow/v1";
    public const string RepairLineage = "hyperion-free-strategy-repair-lineage/v1";
    public const string GauntletReport = "hyperion-free-strategy-gauntlet-report/v1";
    public const int MaximumRepairRounds = 2;
    public const int MaximumInitialSources = 58;
}

public static class FreeStrategyWorkflowSourceIds
{
    public const string ReservedPrefix = "hyperion.repair.";
    public const string Lineage = ReservedPrefix + "lineage";
    public const string RootObjective = ReservedPrefix + "root-objective";
    public const string ParentDraft = ReservedPrefix + "parent-draft";
    public const string ParentReview = ReservedPrefix + "parent-review";
    public const string ChangeRequest = ReservedPrefix + "change-request";
    public const string Diagnostics = ReservedPrefix + "diagnostics";
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FreeStrategyWorkflowRequest
{
    public required string Objective { get; init; }

    public required string Owner { get; init; }

    public IReadOnlyList<CoordinatorContextSource> Sources { get; init; } = [];

    public CoordinatorBudget Budget { get; init; } = FreeStrategyWorkflowDefaults.CreateBudget();
}

public sealed record FreeStrategyWorkflowDraft(
    CoordinatorRunSnapshot Snapshot,
    string SpecificationSha256);

public sealed record FreeStrategyWorkflowResult(
    CoordinatorRunSnapshot Snapshot,
    CoordinatorStrategySourceArtifact? StrategyArtifact);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FreeStrategyWorkflowRevisionRequest
{
    public required Guid ParentRunId { get; init; }

    public required string Owner { get; init; }

    public required string ChangeRequest { get; init; }

    public string? Diagnostics { get; init; }

    public CoordinatorBudget Budget { get; init; } = FreeStrategyWorkflowDefaults.CreateBudget();
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FreeStrategyRepairLineage
{
    public string SchemaVersion { get; init; } = FreeStrategyWorkflowVersions.RepairLineage;

    public required int RepairRound { get; init; }

    public required Guid ParentRunId { get; init; }

    public required string ParentSpecificationSha256 { get; init; }

    public required string ParentSynthesizerArtifactSha256 { get; init; }

    public required string ParentRiskJudgeArtifactSha256 { get; init; }

    public string? ParentFinalArtifactSha256 { get; init; }

    public required CoordinatorDecision ParentDecision { get; init; }

    public required string RootObjectiveSha256 { get; init; }

    public required string ChangeRequestSha256 { get; init; }

    public string? DiagnosticsSha256 { get; init; }
}

public sealed record FreeStrategyGauntletCheck(
    string Id,
    bool Passed,
    string Summary);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FreeStrategyGauntletReport
{
    public string SchemaVersion { get; init; } = FreeStrategyWorkflowVersions.GauntletReport;

    public required Guid RunId { get; init; }

    public required CoordinatorRunStatus Status { get; init; }

    public string? FinalArtifactSha256 { get; init; }

    public IReadOnlyList<FreeStrategyGauntletCheck> Checks { get; init; } = [];

    public required bool ProcessIntegrityPassed { get; init; }

    public required bool ReadyForHumanReleaseReview { get; init; }

    public bool SemanticCorrectnessGuaranteed { get; init; }

    public string CompilationVerification { get; init; } = "not-run-by-free-workflow";

    public string FunctionalVerification { get; init; } = "not-run-by-free-workflow";
}

public static class FreeStrategyWorkflowDefaults
{
    public static CoordinatorBudget CreateBudget() => new(
        MaxRequests: 10,
        MaxAttemptsPerRole: 2,
        MaxPromptTokens: 500_000,
        MaxOutputTokens: 40_000,
        MaxOutputTokensPerRequest: 8_000,
        MaxCostUsd: 5m,
        MaxResponseBytes: 1_000_000,
        MaxArtifactBytes: 2_000_000,
        MaxElapsedSeconds: 900,
        RequestTimeoutSeconds: 120,
        RequireReportedUsage: false);
}
