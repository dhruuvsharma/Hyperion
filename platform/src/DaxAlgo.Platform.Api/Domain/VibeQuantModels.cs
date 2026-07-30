using TradingTerminal.Ai.Coordinator.Contracts;

namespace DaxAlgo.Platform.Domain;

public sealed class VibeQuantCreditWallet
{
    public Guid AccountId { get; set; }

    public long AvailableCredits { get; set; }

    public long ReservedCredits { get; set; }

    public long ConsumedCredits { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public long Version { get; set; }
}

public enum VibeQuantCreditEntryKind
{
    Grant,
    Reserve,
    Charge,
    Release,
    Adjustment
}

public sealed class VibeQuantCreditLedgerEntry
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public Guid? RunId { get; set; }

    public VibeQuantCreditEntryKind Kind { get; set; }

    public long AvailableDelta { get; set; }

    public long ReservedDelta { get; set; }

    public long ConsumedDelta { get; set; }

    public long AvailableAfter { get; set; }

    public long ReservedAfter { get; set; }

    public long ConsumedAfter { get; set; }

    public required string IdempotencyKey { get; set; }

    public required string Reference { get; set; }

    public required string PricingVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class VibeQuantRun
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public required string IdempotencyKey { get; set; }

    public required string RequestSha256 { get; set; }

    public required string SpecSha256 { get; set; }

    public required string SpecJson { get; set; }

    public required string ExecutionSpecJson { get; set; }

    public required string ExecutionSpecSha256 { get; set; }

    public required string ExecutionProfileBinding { get; set; }

    public required string ExecutionBindingNonce { get; set; }

    public CoordinatorRunStatus Status { get; set; }

    public required string UsageJson { get; set; }

    public int CompletedRoleCount { get; set; }

    public long ReservedCredits { get; set; }

    public long ChargedCredits { get; set; }

    public long CreditRatePerUsd { get; set; }

    public long MinimumChargeCredits { get; set; }

    public decimal BillableCostUsd { get; set; }

    public bool CreditsSettled { get; set; }

    public bool CancellationRequested { get; set; }

    public DateTimeOffset? CancellationRequestedAt { get; set; }

    public Guid? WorkerLeaseId { get; set; }

    public DateTimeOffset? WorkerLeaseExpiresAt { get; set; }

    public int WorkerLeaseDurationSeconds { get; set; }

    public int ExecutionAttempt { get; set; }

    public string? FinalArtifactSha256 { get; set; }

    public string? SafeMessage { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public long Version { get; set; }
}
