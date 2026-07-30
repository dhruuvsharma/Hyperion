using System.Data;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Platform.Features.VibeQuant;

public sealed class VibeQuantMutationGate : IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async ValueTask<IDisposable> EnterAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        return new Releaser(gate);
    }

    private sealed class Releaser(SemaphoreSlim gate) : IDisposable
    {
        public void Dispose() => gate.Release();
    }

    public void Dispose() => gate.Dispose();
}

internal sealed class VibeQuantExecutionActivationMismatchException : Exception
{
}

public sealed class VibeQuantService(
    PlatformDbContext database,
    VibeQuantOptions options,
    VibeQuantSpecificationFactory specificationFactory,
    EntitlementService entitlements,
    IVibeQuantExecutionRuntime executionRuntime,
    VibeQuantExecutionCancellationRegistry cancellationRegistry,
    VibeQuantModelReadinessService modelReadiness,
    VibeQuantMutationGate mutationGate,
    TimeProvider timeProvider)
{
    public async Task<VibeQuantCreditBalanceResponse> GetCreditsAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        var wallet = await database.VibeQuantCreditWallets.AsNoTracking()
            .SingleOrDefaultAsync(item => item.AccountId == accountId, cancellationToken);
        return wallet is null
            ? new VibeQuantCreditBalanceResponse(0, 0, 0, options.CreditPricingVersion, timeProvider.GetUtcNow())
            : ToCreditResponse(wallet);
    }

    public async Task<VibeQuantCreditBalanceResponse> GrantCreditsAsync(
        Guid accountId,
        long credits,
        string idempotencyKey,
        string reason,
        CancellationToken cancellationToken)
    {
        if (credits is < 1 or > 1_000_000_000)
        {
            throw new PlatformValidationException("Credit grant must be between 1 and 1,000,000,000.");
        }
        ValidateIdempotencyKey(idempotencyKey);
        var normalizedReason = NormalizeReason(reason);
        var ledgerKey = $"grant:{idempotencyKey}";
        var reference = $"{credits}:{normalizedReason}";

        using var gate = await mutationGate.EnterAsync(cancellationToken);
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var duplicate = await database.VibeQuantCreditLedger.AsNoTracking().SingleOrDefaultAsync(
            item => item.AccountId == accountId && item.IdempotencyKey == ledgerKey,
            cancellationToken);
        if (duplicate is not null)
        {
            if (!StringComparer.Ordinal.Equals(duplicate.Reference, reference))
            {
                throw new PlatformConflictException("The idempotency key was already used for a different credit grant.");
            }
            await CommitAsync(transaction, cancellationToken);
            return await GetCreditsAsync(accountId, cancellationToken);
        }

        var profileExists = await database.Profiles.AnyAsync(item => item.Id == accountId, cancellationToken);
        if (!profileExists)
        {
            throw new PlatformNotFoundException("Product profile not found.");
        }
        var wallet = await database.VibeQuantCreditWallets.SingleOrDefaultAsync(
            item => item.AccountId == accountId,
            cancellationToken);
        if (wallet is null)
        {
            wallet = new VibeQuantCreditWallet
            {
                AccountId = accountId,
                UpdatedAt = timeProvider.GetUtcNow(),
                Version = 1,
            };
            database.VibeQuantCreditWallets.Add(wallet);
        }

        wallet.AvailableCredits = checked(wallet.AvailableCredits + credits);
        wallet.UpdatedAt = timeProvider.GetUtcNow();
        wallet.Version = checked(wallet.Version + 1);
        database.VibeQuantCreditLedger.Add(CreateLedgerEntry(
            wallet,
            null,
            VibeQuantCreditEntryKind.Grant,
            credits,
            0,
            0,
            ledgerKey,
            reference,
            "grant"));
        await database.SaveChangesAsync(cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return ToCreditResponse(wallet);
    }

    public async Task<VibeQuantRunSpecResponse> CreateRunAsync(
        Guid accountId,
        CreateVibeQuantRunRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        ValidateIdempotencyKey(idempotencyKey);
        ArgumentNullException.ThrowIfNull(request);
        if (!Enum.IsDefined(request.Purpose))
        {
            throw new PlatformValidationException("Vibe Quant run purpose is not supported.");
        }
        var requestSha256 = ContentHasher.HashJson(request);

        using var gate = await mutationGate.EnterAsync(cancellationToken);
        var existing = await database.VibeQuantRuns.AsNoTracking().SingleOrDefaultAsync(
            item => item.AccountId == accountId && item.IdempotencyKey == idempotencyKey,
            cancellationToken);
        if (existing is not null)
        {
            if (!StringComparer.Ordinal.Equals(existing.RequestSha256, requestSha256))
            {
                throw new PlatformConflictException("The idempotency key was already used with a different request.");
            }
            return ToSpecResponse(existing);
        }

        var activeCount = await database.VibeQuantRuns.CountAsync(
            item => item.AccountId == accountId &&
                    (item.Status == CoordinatorRunStatus.AwaitingStartApproval ||
                     item.Status == CoordinatorRunStatus.Ready ||
                     item.Status == CoordinatorRunStatus.Running ||
                     item.Status == CoordinatorRunStatus.AwaitingReleaseApproval),
            cancellationToken);
        if (activeCount >= options.MaxActiveRunsPerAccount)
        {
            throw new PlatformConflictException("The account has reached its active Vibe Quant run limit.");
        }

        var runId = Guid.NewGuid();
        var envelope = specificationFactory.Create(accountId, runId, request);
        var spec = DeserializePublicSpec(envelope.SpecJson);
        var run = new VibeQuantRun
        {
            Id = runId,
            AccountId = accountId,
            IdempotencyKey = idempotencyKey,
            RequestSha256 = envelope.RequestSha256,
            SpecSha256 = envelope.SpecSha256,
            SpecJson = envelope.SpecJson,
            ExecutionSpecJson = envelope.ExecutionSpecJson,
            ExecutionSpecSha256 = envelope.ExecutionSpecSha256,
            ExecutionProfileBinding = envelope.ExecutionProfileBinding,
            ExecutionBindingNonce = envelope.ExecutionBindingNonce,
            Status = CoordinatorRunStatus.AwaitingStartApproval,
            UsageJson = SerializeUsage(new CoordinatorUsage()),
            CreditRatePerUsd = options.CreditsPerUsd,
            MinimumChargeCredits = options.MinimumChargeCredits,
            BillableCostUsd = 0m,
            WorkerLeaseDurationSeconds = checked(spec.Budget.RequestTimeoutSeconds + 60),
            CreatedAt = spec.CreatedAtUtc,
            UpdatedAt = spec.CreatedAtUtc,
            Version = 1,
        };
        database.VibeQuantRuns.Add(run);
        await database.SaveChangesAsync(cancellationToken);
        return ToSpecResponse(run);
    }

    public async Task<VibeQuantRunSpecResponse> GetSpecificationAsync(
        Guid accountId,
        Guid runId,
        CancellationToken cancellationToken) =>
        ToSpecResponse(await RequireRunAsync(accountId, runId, cancellationToken));

    public async Task<VibeQuantRunStatusResponse> GetStatusAsync(
        Guid accountId,
        Guid runId,
        CancellationToken cancellationToken) =>
        ToStatusResponse(await RequireRunAsync(accountId, runId, cancellationToken));

    public async Task<IReadOnlyList<VibeQuantRunStatusResponse>> ListAsync(
        Guid accountId,
        CancellationToken cancellationToken) =>
        (await database.VibeQuantRuns.AsNoTracking()
            .Where(item => item.AccountId == accountId)
            .OrderByDescending(item => item.UpdatedAt)
            .Take(100)
            .ToListAsync(cancellationToken))
        .Select(ToStatusResponse)
        .ToArray();

    public async Task<VibeQuantRunStatusResponse> StartAsync(
        Guid accountId,
        Guid runId,
        string specSha256,
        CancellationToken cancellationToken)
    {
        ValidateSha256(specSha256, "Specification SHA-256");
        using var gate = await mutationGate.EnterAsync(cancellationToken);
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        await entitlements.RequireTierAsync(accountId, PlanTier.Professional, cancellationToken);
        var run = await RequireTrackedRunAsync(accountId, runId, cancellationToken);
        if (!StringComparer.Ordinal.Equals(run.SpecSha256, specSha256.ToLowerInvariant()))
        {
            throw new PlatformConflictException(
                "Start approval does not match the exact server run specification.");
        }
        if (run.Status is CoordinatorRunStatus.Completed or CoordinatorRunStatus.Cancelled or
            CoordinatorRunStatus.Rejected or CoordinatorRunStatus.AwaitingReleaseApproval)
        {
            await CommitAsync(transaction, cancellationToken);
            return ToStatusResponse(run);
        }
        VibeQuantRunSpecification spec;
        CoordinatorRunSpec executionSpec;
        try
        {
            spec = ValidateStoredSpecification(run, out executionSpec);
        }
        catch (VibeQuantExecutionActivationMismatchException)
        {
            var retiredLeaseId = run.WorkerLeaseId;
            if (run.Status is CoordinatorRunStatus.AwaitingStartApproval or
                CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)
            {
                await RejectRetiredExecutionAsync(run, cancellationToken);
                await database.SaveChangesAsync(cancellationToken);
            }
            await CommitAsync(transaction, cancellationToken);
            if (retiredLeaseId is { } leaseId)
            {
                cancellationRegistry.Request(run.Id);
                cancellationRegistry.Complete(run.Id, leaseId);
            }
            throw new PlatformConflictException(
                "The Vibe Quant execution activation has changed; create a new run.");
        }
        if (run.Status != CoordinatorRunStatus.AwaitingStartApproval)
        {
            if (run.Status is CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)
            {
                await CommitAsync(transaction, cancellationToken);
                return ToStatusResponse(run);
            }
            throw new PlatformConflictException($"Run in state '{run.Status}' cannot be started.");
        }

        modelReadiness.RequireReady(executionSpec.Provider.ModelId);
        var reservation = spec.MaximumCreditCharge;
        var wallet = await database.VibeQuantCreditWallets.SingleOrDefaultAsync(
            item => item.AccountId == accountId,
            cancellationToken);
        if (wallet is null || wallet.AvailableCredits < reservation)
        {
            throw new PlatformPaymentRequiredException(
                $"This run requires {reservation} available credits; add credits before starting it.");
        }

        wallet.AvailableCredits -= reservation;
        wallet.ReservedCredits = checked(wallet.ReservedCredits + reservation);
        wallet.UpdatedAt = timeProvider.GetUtcNow();
        wallet.Version = checked(wallet.Version + 1);
        run.ReservedCredits = reservation;
        run.Status = CoordinatorRunStatus.Ready;
        run.SafeMessage = "Queued for server execution.";
        Touch(run);
        database.VibeQuantCreditLedger.Add(CreateLedgerEntry(
            wallet,
            run.Id,
            VibeQuantCreditEntryKind.Reserve,
            -reservation,
            reservation,
            0,
            $"reserve:{run.Id:N}",
            run.SpecSha256,
            spec.CreditPricingVersion));
        await database.SaveChangesAsync(cancellationToken);
        await CommitAsync(transaction, cancellationToken);
        return ToStatusResponse(run);
    }

    public async Task<VibeQuantArtifactResponse> GetArtifactAsync(
        Guid accountId,
        Guid runId,
        string artifactSha256,
        CancellationToken cancellationToken)
    {
        ValidateSha256(artifactSha256, "Artifact SHA-256");
        var run = await RequireRunAsync(accountId, runId, cancellationToken);
        return await executionRuntime.ReadArtifactAsync(run, artifactSha256.ToLowerInvariant(), cancellationToken);
    }

    public async Task<VibeQuantRunStatusResponse> ReleaseAsync(
        Guid accountId,
        Guid runId,
        string artifactSha256,
        CancellationToken cancellationToken)
    {
        ValidateSha256(artifactSha256, "Artifact SHA-256");
        artifactSha256 = artifactSha256.ToLowerInvariant();
        using var gate = await mutationGate.EnterAsync(cancellationToken);
        var run = await RequireTrackedRunAsync(accountId, runId, cancellationToken);
        if (run.Status == CoordinatorRunStatus.Completed &&
            StringComparer.Ordinal.Equals(run.FinalArtifactSha256, artifactSha256))
        {
            return ToStatusResponse(run);
        }
        if (run.Status != CoordinatorRunStatus.AwaitingReleaseApproval ||
            !StringComparer.Ordinal.Equals(run.FinalArtifactSha256, artifactSha256.ToLowerInvariant()))
        {
            throw new PlatformConflictException("Release approval must bind the exact final artifact awaiting review.");
        }

        var result = await executionRuntime.ApproveReleaseAsync(
            run,
            artifactSha256,
            cancellationToken);
        if (run.Status != CoordinatorRunStatus.AwaitingReleaseApproval)
        {
            throw new PlatformConflictException("The run changed while release approval was being recorded.");
        }
        ApplyExecutionResult(run, result);
        await database.SaveChangesAsync(cancellationToken);
        return ToStatusResponse(run);
    }

    public async Task<VibeQuantRunStatusResponse> CancelAsync(
        Guid accountId,
        Guid runId,
        CancellationToken cancellationToken)
    {
        using var gate = await mutationGate.EnterAsync(cancellationToken);
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var run = await RequireTrackedRunAsync(accountId, runId, cancellationToken);
        if (run.Status is CoordinatorRunStatus.Completed or CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected)
        {
            await CommitAsync(transaction, cancellationToken);
            return ToStatusResponse(run);
        }

        if (run.Status == CoordinatorRunStatus.Running)
        {
            if (!run.CancellationRequested)
            {
                run.CancellationRequested = true;
                run.CancellationRequestedAt = timeProvider.GetUtcNow();
                run.SafeMessage = "Cancellation requested by the authenticated account.";
                Touch(run);
                await database.SaveChangesAsync(cancellationToken);
            }
            cancellationRegistry.Request(run.Id);
        }
        else
        {
            run.Status = CoordinatorRunStatus.Cancelled;
            run.SafeMessage = "Cancelled by the authenticated account.";
            Touch(run);
            if (run.ReservedCredits > 0)
            {
                await SettleCreditsAsync(run, 0, cancellationToken);
            }
            await database.SaveChangesAsync(cancellationToken);
        }
        await CommitAsync(transaction, cancellationToken);
        return ToStatusResponse(run);
    }

    public async Task<VibeQuantRun?> ClaimNextAsync(CancellationToken cancellationToken)
    {
        using var gate = await mutationGate.EnterAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        var candidates = await database.VibeQuantRuns
            .Where(item => item.Status == CoordinatorRunStatus.Ready ||
                item.Status == CoordinatorRunStatus.Running &&
                (item.WorkerLeaseExpiresAt == null || item.WorkerLeaseExpiresAt <= now))
            .OrderBy(item => item.CreatedAt)
            .Take(100)
            .ToListAsync(cancellationToken);
        VibeQuantRun? run = null;
        string? executionModelId = null;
        var retiredLeases = new List<(Guid RunId, Guid LeaseId)>();
        var rejectedRetiredExecution = false;
        foreach (var candidate in candidates)
        {
            CoordinatorRunSpec executionSpec;
            try
            {
                _ = ValidateStoredSpecification(candidate, out executionSpec);
            }
            catch (VibeQuantExecutionActivationMismatchException)
            {
                if (candidate.WorkerLeaseId is { } rejectedLeaseId)
                {
                    retiredLeases.Add((candidate.Id, rejectedLeaseId));
                }
                await RejectRetiredExecutionAsync(candidate, cancellationToken);
                rejectedRetiredExecution = true;
                continue;
            }
            if (!modelReadiness.IsActiveModel(executionSpec.Provider.ModelId) ||
                modelReadiness.IsPromotionExpired)
            {
                if (candidate.WorkerLeaseId is { } rejectedLeaseId)
                {
                    retiredLeases.Add((candidate.Id, rejectedLeaseId));
                }
                await RejectRetiredExecutionAsync(candidate, cancellationToken);
                rejectedRetiredExecution = true;
                continue;
            }
            if (run is null && modelReadiness.IsReadyFor(executionSpec.Provider.ModelId))
            {
                run = candidate;
                executionModelId = executionSpec.Provider.ModelId;
            }
        }
        if (rejectedRetiredExecution)
        {
            await database.SaveChangesAsync(cancellationToken);
            CompleteRetiredLeases(retiredLeases);
        }
        if (run is null)
        {
            return null;
        }
        modelReadiness.RequireReady(executionModelId);
        var recovered = run.Status == CoordinatorRunStatus.Running;
        var expiredLeaseId = run.WorkerLeaseId;
        run.Status = CoordinatorRunStatus.Running;
        run.WorkerLeaseId = Guid.NewGuid();
        run.WorkerLeaseExpiresAt = now.AddSeconds(run.WorkerLeaseDurationSeconds);
        run.ExecutionAttempt = checked(run.ExecutionAttempt + 1);
        run.SafeMessage = recovered
            ? "Recovering an expired Vibe Quant server lease."
            : "Executing on the Vibe Quant server.";
        Touch(run);
        await database.SaveChangesAsync(cancellationToken);
        if (expiredLeaseId is { } staleLeaseId)
        {
            cancellationRegistry.Complete(run.Id, staleLeaseId);
        }
        cancellationRegistry.Ensure(run.Id, run.WorkerLeaseId.Value, run.CancellationRequested);
        return Clone(run);
    }

    private async Task RejectRetiredExecutionAsync(
        VibeQuantRun run,
        CancellationToken cancellationToken)
    {
        run.Status = CoordinatorRunStatus.Failed;
        run.SafeMessage =
            "The queued Vibe Quant execution activation is no longer active; create a new run.";
        run.WorkerLeaseId = null;
        run.WorkerLeaseExpiresAt = null;
        Touch(run);
        if (run.ReservedCredits > 0)
        {
            await SettleCreditsAsync(run, 0, cancellationToken);
        }
    }

    private void CompleteRetiredLeases(IEnumerable<(Guid RunId, Guid LeaseId)> retiredLeases)
    {
        foreach (var (runId, leaseId) in retiredLeases)
        {
            cancellationRegistry.Complete(runId, leaseId);
        }
    }

    public async Task<bool> RenewLeaseAsync(
        Guid runId,
        Guid workerLeaseId,
        CancellationToken cancellationToken)
    {
        using var gate = await mutationGate.EnterAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        var run = await database.VibeQuantRuns.SingleOrDefaultAsync(
            item => item.Id == runId,
            cancellationToken) ?? throw new PlatformNotFoundException("Vibe Quant run not found.");
        if (run.Status != CoordinatorRunStatus.Running ||
            run.WorkerLeaseId != workerLeaseId ||
            run.WorkerLeaseExpiresAt is null ||
            run.WorkerLeaseExpiresAt <= now)
        {
            throw new PlatformConflictException("The Vibe Quant worker lease cannot be renewed.");
        }

        run.WorkerLeaseExpiresAt = now.AddSeconds(run.WorkerLeaseDurationSeconds);
        run.Version = checked(run.Version + 1);
        await database.SaveChangesAsync(cancellationToken);
        return run.CancellationRequested;
    }

    public async Task CompleteExecutionAsync(
        Guid runId,
        Guid workerLeaseId,
        VibeQuantExecutionResult result,
        CancellationToken cancellationToken)
    {
        using var gate = await mutationGate.EnterAsync(cancellationToken);
        await using var transaction = await BeginTransactionAsync(cancellationToken);
        var run = await database.VibeQuantRuns.SingleOrDefaultAsync(item => item.Id == runId, cancellationToken)
            ?? throw new PlatformNotFoundException("Vibe Quant run not found.");
        if (run.CreditsSettled)
        {
            await CommitAsync(transaction, cancellationToken);
            return;
        }

        if (run.WorkerLeaseId != workerLeaseId)
        {
            throw new PlatformConflictException("The Vibe Quant worker lease is stale.");
        }

        var effectiveResult = run.CancellationRequested
            ? result with
            {
                Status = CoordinatorRunStatus.Cancelled,
                SafeMessage = "Cancelled by the authenticated account."
            }
            : result;
        var charge = CalculateCharge(effectiveResult, run);
        run.BillableCostUsd = effectiveResult.BillableCostUsd;
        await SettleCreditsAsync(run, charge, cancellationToken);
        ApplyExecutionResult(run, effectiveResult);
        run.WorkerLeaseId = null;
        run.WorkerLeaseExpiresAt = null;
        await database.SaveChangesAsync(cancellationToken);
        await CommitAsync(transaction, cancellationToken);
    }

    private async Task SettleCreditsAsync(
        VibeQuantRun run,
        long charge,
        CancellationToken cancellationToken)
    {
        if (run.CreditsSettled)
        {
            return;
        }
        if (charge < 0 || charge > run.ReservedCredits)
        {
            throw new InvalidOperationException("Vibe Quant credit settlement is outside the reserved amount.");
        }
        var wallet = await database.VibeQuantCreditWallets.SingleAsync(
            item => item.AccountId == run.AccountId,
            cancellationToken);
        if (wallet.ReservedCredits < run.ReservedCredits)
        {
            throw new InvalidOperationException("Vibe Quant wallet reservation is inconsistent with the run.");
        }

        var reserved = run.ReservedCredits;
        var refund = reserved - charge;
        wallet.AvailableCredits = checked(wallet.AvailableCredits + refund);
        wallet.ReservedCredits -= reserved;
        wallet.ConsumedCredits = checked(wallet.ConsumedCredits + charge);
        wallet.UpdatedAt = timeProvider.GetUtcNow();
        wallet.Version = checked(wallet.Version + 1);
        run.ReservedCredits = 0;
        run.ChargedCredits = charge;
        run.CreditsSettled = true;
        database.VibeQuantCreditLedger.Add(CreateLedgerEntry(
            wallet,
            run.Id,
            VibeQuantCreditEntryKind.Charge,
            refund,
            -reserved,
            charge,
            $"settle:{run.Id:N}",
            $"reserved={reserved};charged={charge};refunded={refund}",
            DeserializePublicSpec(run.SpecJson).CreditPricingVersion));
    }

    private static long CalculateCharge(VibeQuantExecutionResult result, VibeQuantRun run)
    {
        var costCharge = checked((long)decimal.Ceiling(result.BillableCostUsd * run.CreditRatePerUsd));
        var charge = result.CompletedRoleCount > 0
            ? Math.Max(run.MinimumChargeCredits, costCharge)
            : costCharge;
        return Math.Min(run.ReservedCredits, charge);
    }

    private VibeQuantCreditLedgerEntry CreateLedgerEntry(
        VibeQuantCreditWallet wallet,
        Guid? runId,
        VibeQuantCreditEntryKind kind,
        long availableDelta,
        long reservedDelta,
        long consumedDelta,
        string idempotencyKey,
        string reference,
        string pricingVersion) => new()
        {
            Id = Guid.NewGuid(),
            AccountId = wallet.AccountId,
            RunId = runId,
            Kind = kind,
            AvailableDelta = availableDelta,
            ReservedDelta = reservedDelta,
            ConsumedDelta = consumedDelta,
            AvailableAfter = wallet.AvailableCredits,
            ReservedAfter = wallet.ReservedCredits,
            ConsumedAfter = wallet.ConsumedCredits,
            IdempotencyKey = idempotencyKey,
            Reference = reference,
            PricingVersion = pricingVersion,
            CreatedAt = timeProvider.GetUtcNow(),
        };

    private async Task<VibeQuantRun> RequireRunAsync(
        Guid accountId,
        Guid runId,
        CancellationToken cancellationToken) =>
        await database.VibeQuantRuns.AsNoTracking().SingleOrDefaultAsync(
            item => item.AccountId == accountId && item.Id == runId,
            cancellationToken)
        ?? throw new PlatformNotFoundException("Vibe Quant run not found.");

    private async Task<VibeQuantRun> RequireTrackedRunAsync(
        Guid accountId,
        Guid runId,
        CancellationToken cancellationToken) =>
        await database.VibeQuantRuns.SingleOrDefaultAsync(
            item => item.AccountId == accountId && item.Id == runId,
            cancellationToken)
        ?? throw new PlatformNotFoundException("Vibe Quant run not found.");

    private async ValueTask<IDbContextTransaction?> BeginTransactionAsync(CancellationToken cancellationToken)
    {
        if (!database.Database.IsRelational())
        {
            return null;
        }
        return await database.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
    }

    private static async Task CommitAsync(
        IDbContextTransaction? transaction,
        CancellationToken cancellationToken)
    {
        if (transaction is not null)
        {
            await transaction.CommitAsync(cancellationToken);
        }
    }

    private void Touch(VibeQuantRun run)
    {
        run.UpdatedAt = timeProvider.GetUtcNow();
        run.Version = checked(run.Version + 1);
    }

    private void ApplyExecutionResult(VibeQuantRun run, VibeQuantExecutionResult result)
    {
        run.Status = result.Status;
        run.CompletedRoleCount = result.CompletedRoleCount;
        run.UsageJson = SerializeUsage(result.Usage);
        run.FinalArtifactSha256 = result.FinalArtifactSha256;
        run.SafeMessage = result.SafeMessage;
        run.UpdatedAt = timeProvider.GetUtcNow();
        run.Version = checked(run.Version + 1);
    }

    private static VibeQuantRunStatusResponse ToStatusResponse(VibeQuantRun run) => new(
        run.Id,
        run.Status,
        run.SpecSha256,
        run.CompletedRoleCount,
        run.CancellationRequested,
        run.ReservedCredits,
        run.ChargedCredits,
        run.FinalArtifactSha256,
        run.SafeMessage,
        run.CreatedAt,
        run.UpdatedAt);

    private static VibeQuantRunSpecResponse ToSpecResponse(VibeQuantRun run) =>
        new(run.SpecSha256, DeserializePublicSpec(run.SpecJson));

    private VibeQuantCreditBalanceResponse ToCreditResponse(VibeQuantCreditWallet wallet) => new(
        wallet.AvailableCredits,
        wallet.ReservedCredits,
        wallet.ConsumedCredits,
        options.CreditPricingVersion,
        wallet.UpdatedAt);

    private static VibeQuantRunSpecification DeserializePublicSpec(string json) =>
        JsonSerializer.Deserialize<VibeQuantRunSpecification>(json, CoordinatorJson.Options)
        ?? throw new InvalidOperationException("Stored Vibe Quant specification was JSON null.");

    private static string SerializeUsage(CoordinatorUsage usage) =>
        JsonSerializer.Serialize(usage, CoordinatorJson.Options);

    private static CoordinatorUsage DeserializeUsage(string json) =>
        JsonSerializer.Deserialize<CoordinatorUsage>(json, CoordinatorJson.Options)
        ?? throw new InvalidOperationException("Stored Vibe Quant usage was JSON null.");

    private static VibeQuantRun Clone(VibeQuantRun run) => new()
    {
        Id = run.Id,
        AccountId = run.AccountId,
        IdempotencyKey = run.IdempotencyKey,
        RequestSha256 = run.RequestSha256,
        SpecSha256 = run.SpecSha256,
        SpecJson = run.SpecJson,
        ExecutionSpecJson = run.ExecutionSpecJson,
        ExecutionSpecSha256 = run.ExecutionSpecSha256,
        ExecutionProfileBinding = run.ExecutionProfileBinding,
        ExecutionBindingNonce = run.ExecutionBindingNonce,
        Status = run.Status,
        UsageJson = run.UsageJson,
        CompletedRoleCount = run.CompletedRoleCount,
        ReservedCredits = run.ReservedCredits,
        ChargedCredits = run.ChargedCredits,
        CreditRatePerUsd = run.CreditRatePerUsd,
        MinimumChargeCredits = run.MinimumChargeCredits,
        BillableCostUsd = run.BillableCostUsd,
        CreditsSettled = run.CreditsSettled,
        CancellationRequested = run.CancellationRequested,
        CancellationRequestedAt = run.CancellationRequestedAt,
        WorkerLeaseId = run.WorkerLeaseId,
        WorkerLeaseExpiresAt = run.WorkerLeaseExpiresAt,
        WorkerLeaseDurationSeconds = run.WorkerLeaseDurationSeconds,
        ExecutionAttempt = run.ExecutionAttempt,
        FinalArtifactSha256 = run.FinalArtifactSha256,
        SafeMessage = run.SafeMessage,
        CreatedAt = run.CreatedAt,
        UpdatedAt = run.UpdatedAt,
        Version = run.Version,
    };

    private VibeQuantRunSpecification ValidateStoredSpecification(
        VibeQuantRun run,
        out CoordinatorRunSpec executionSpec)
    {
        var spec = DeserializePublicSpec(run.SpecJson);
        executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
                run.ExecutionSpecJson,
                CoordinatorJson.Options)
            ?? throw new InvalidOperationException(
                "Stored Vibe Quant execution specification was JSON null.");
        if (!StringComparer.Ordinal.Equals(ContentHasher.HashJson(spec), run.SpecSha256) ||
            !StringComparer.Ordinal.Equals(
                ContentHasher.HashJson(executionSpec),
                run.ExecutionSpecSha256) ||
            executionSpec.RunId != run.Id ||
            !StringComparer.Ordinal.Equals(executionSpec.Owner, run.AccountId.ToString("D")) ||
            spec.RunId != run.Id ||
            !StringComparer.Ordinal.Equals(spec.ExecutionProfileBinding, run.ExecutionProfileBinding))
        {
            throw new InvalidOperationException("Stored Vibe Quant specification integrity validation failed.");
        }
        if (!specificationFactory.IsCurrentExecutionProfileBinding(
                run.ExecutionSpecJson,
                run.ExecutionBindingNonce,
                run.ExecutionProfileBinding))
        {
            throw new VibeQuantExecutionActivationMismatchException();
        }
        var validCoordinatorProfile =
            StringComparer.Ordinal.Equals(spec.PolicyVersion, executionSpec.PolicyVersion) &&
            StringComparer.Ordinal.Equals(spec.WorkflowVersion, executionSpec.WorkflowVersion) &&
            StringComparer.Ordinal.Equals(
                spec.PromptCatalogSha256,
                executionSpec.PromptCatalogSha256) &&
            specificationFactory.IsCurrentCoordinatorProfile(
                executionSpec.Purpose,
                executionSpec.PolicyVersion,
                executionSpec.WorkflowVersion,
                executionSpec.PromptCatalogSha256);
        if (spec.SchemaVersion != VibeQuantApiVersions.RunSpecification || !validCoordinatorProfile)
        {
            throw new PlatformConflictException(
                "The Vibe Quant specification is not compatible with the active server policy; create a new run.");
        }
        return spec;
    }

    private static void ValidateIdempotencyKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 100 || value.Any(character => character is < '!' or > '~'))
        {
            throw new PlatformValidationException(
                "Idempotency-Key must contain 1 to 100 printable ASCII characters without spaces.");
        }
    }

    private static void ValidateSha256(string value, string label)
    {
        if (value is not { Length: 64 } || !value.All(Uri.IsHexDigit))
        {
            throw new PlatformValidationException($"{label} must contain exactly 64 hexadecimal characters.");
        }
    }

    private static string NormalizeReason(string value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length > 400)
        {
            throw new PlatformValidationException("Credit grant reason must contain 1 to 400 characters.");
        }
        return normalized;
    }
}
