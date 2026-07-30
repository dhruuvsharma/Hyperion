using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Orchestration;

public sealed class ResearchCoordinator(
    ICoordinatorStore store,
    ICoordinatorArtifactStore artifactStore,
    ILlmProvider provider)
{
    public static IReadOnlyList<CoordinatorRole> Workflow { get; } =
    [
        CoordinatorRole.Planner,
        CoordinatorRole.EvidenceAnalyst,
        CoordinatorRole.Critic,
        CoordinatorRole.Synthesizer,
        CoordinatorRole.RiskJudge
    ];

    private readonly RolePromptBuilder _promptBuilder = new(artifactStore);

    public async Task<CoordinatorRunSnapshot> CreateAsync(
        CoordinatorRunSpec spec,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(spec.PromptCatalogSha256))
        {
            spec = spec with { PromptCatalogSha256 = CoordinatorPromptCatalog.Sha256For(spec.Purpose) };
        }
        CoordinatorValidation.ValidateSpec(spec);
        EnsureProviderMatches(spec.Provider);
        await store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        var snapshot = new CoordinatorRunSnapshot
        {
            Spec = spec,
            Status = CoordinatorRunStatus.AwaitingStartApproval,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        return await store.CreateAsync(
            snapshot,
            "RunCreated",
            new { specSha256 = ContentHasher.HashJson(spec) },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<CoordinatorRunSnapshot> ApproveStartAsync(
        Guid runId,
        string actor,
        string reviewedSpecSha256,
        CancellationToken cancellationToken = default)
    {
        RequireActor(actor);
        var snapshot = await GetRequiredAsync(runId, cancellationToken).ConfigureAwait(false);
        if (snapshot.Status != CoordinatorRunStatus.AwaitingStartApproval)
        {
            throw new InvalidOperationException($"Run is '{snapshot.Status}', not awaiting start approval.");
        }

        var actualSpecSha256 = ContentHasher.HashJson(snapshot.Spec);
        if (!StringComparer.Ordinal.Equals(actualSpecSha256, reviewedSpecSha256))
        {
            throw new InvalidOperationException("Start approval must bind the exact reviewed run-specification SHA-256.");
        }

        var approval = new CoordinatorApproval(
            ApprovalGate.Start,
            actor.Trim(),
            DateTimeOffset.UtcNow,
            actualSpecSha256,
            null);
        return await store.AppendAsync(
            snapshot with
            {
                Status = CoordinatorRunStatus.Ready,
                Approvals = [.. snapshot.Approvals, approval],
                SafeMessage = null
            },
            snapshot.Version,
            "StartApproved",
            approval,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<CoordinatorRunSnapshot> ApproveReleaseAsync(
        Guid runId,
        string actor,
        string artifactSha256,
        CancellationToken cancellationToken = default)
    {
        RequireActor(actor);
        var snapshot = await GetRequiredAsync(runId, cancellationToken).ConfigureAwait(false);
        if (snapshot.Status != CoordinatorRunStatus.AwaitingReleaseApproval)
        {
            throw new InvalidOperationException($"Run is '{snapshot.Status}', not awaiting release approval.");
        }

        if (snapshot.FinalArtifactSha256 is null ||
            !StringComparer.Ordinal.Equals(snapshot.FinalArtifactSha256, artifactSha256))
        {
            throw new InvalidOperationException("Release approval must bind the exact final artifact SHA-256.");
        }

        var finalReference = snapshot.Artifacts.SingleOrDefault(item => item.Sha256 == artifactSha256)
            ?? throw new CoordinatorIntegrityException("Final artifact reference is missing from the run.");
        if (finalReference.SchemaVersion == CoordinatorVersions.ArtifactSchema)
        {
            if (snapshot.Spec.Purpose != CoordinatorRunPurpose.Research ||
                finalReference.Role != CoordinatorRole.Synthesizer ||
                finalReference.Kind != CoordinatorRole.Synthesizer.ToString())
            {
                throw new CoordinatorIntegrityException(
                    "Research release must bind the exact Synthesizer role artifact.");
            }
            var researchOutput = await artifactStore.ReadJsonAsync<CoordinatorRoleOutput>(
                    finalReference.RelativePath,
                    finalReference.Sha256,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                _ = CoordinatorValidation.ParseRoleOutput(
                    JsonSerializer.Serialize(researchOutput, CoordinatorJson.Options),
                    CoordinatorRole.Synthesizer,
                    snapshot.Spec.Sources.Select(source => source.Id).ToHashSet(StringComparer.Ordinal),
                    CoordinatorRunPurpose.Research);
            }
            catch (CoordinatorValidationException exception)
            {
                throw new CoordinatorIntegrityException(exception.Message);
            }
        }
        else if (finalReference.SchemaVersion == CoordinatorVersions.StrategyArtifactSchema)
        {
            var strategyArtifact = await artifactStore.ReadJsonAsync<CoordinatorStrategySourceArtifact>(
                    finalReference.RelativePath,
                    finalReference.Sha256,
                    cancellationToken)
                .ConfigureAwait(false);
            try
            {
                CoordinatorStrategyArtifactValidation.ValidateForRun(
                    strategyArtifact,
                    snapshot.Spec,
                    snapshot.Artifacts);
            }
            catch (InvalidDataException exception)
            {
                throw new CoordinatorIntegrityException(exception.Message);
            }
            await ValidateStrategyArtifactLineageAsync(
                snapshot,
                strategyArtifact,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            throw new CoordinatorIntegrityException("Final artifact schema is not supported.");
        }

        var approval = new CoordinatorApproval(
            ApprovalGate.Release,
            actor.Trim(),
            DateTimeOffset.UtcNow,
            ContentHasher.HashJson(snapshot.Spec),
            artifactSha256);
        return await store.AppendAsync(
            snapshot with
            {
                Status = CoordinatorRunStatus.Completed,
                Approvals = [.. snapshot.Approvals, approval],
                SafeMessage = "Released by human approval."
            },
            snapshot.Version,
            "ReleaseApproved",
            approval,
            cancellationToken).ConfigureAwait(false);
    }

    public Task<CoordinatorRunSnapshot> ResumeAsync(
        Guid runId,
        CancellationToken cancellationToken = default) =>
        ResumeAsync(runId, recordCancellation: true, cancellationToken);

    public async Task<CoordinatorRunSnapshot> ResumeAsync(
        Guid runId,
        bool recordCancellation,
        CancellationToken cancellationToken = default)
    {
        var snapshot = await GetRequiredAsync(runId, cancellationToken).ConfigureAwait(false);
        CoordinatorValidation.ValidateSpec(snapshot.Spec);
        EnsureProviderMatches(snapshot.Spec.Provider);
        VerifyStartApproval(snapshot);
        if (snapshot.Status is not (CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running))
        {
            throw new InvalidOperationException($"Run in state '{snapshot.Status}' cannot be resumed.");
        }

        if (provider is IResumableLlmProvider resumableProvider)
        {
            resumableProvider.ResumeAfter(checked((int)snapshot.Usage.Requests));
        }

        snapshot = await CloseInterruptedInvocationAsync(snapshot, cancellationToken).ConfigureAwait(false);
        if (snapshot.Status == CoordinatorRunStatus.Ready)
        {
            snapshot = await store.AppendAsync(
                snapshot with { Status = CoordinatorRunStatus.Running, SafeMessage = null },
                snapshot.Version,
                "RunStarted",
                new { },
                cancellationToken).ConfigureAwait(false);
        }

        while (snapshot.CompletedRoleCount < Workflow.Count)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var role = Workflow[snapshot.CompletedRoleCount];
            var attempts = snapshot.Invocations.Count(item => item.Role == role);
            if (attempts >= snapshot.Spec.Budget.MaxAttemptsPerRole)
            {
                return await StopAsync(
                    snapshot,
                    CoordinatorRunStatus.Failed,
                    $"Role '{role}' exhausted its attempt limit.",
                    "AttemptLimitReached",
                    cancellationToken).ConfigureAwait(false);
            }

            var prompt = await _promptBuilder.BuildAsync(snapshot, role, cancellationToken).ConfigureAwait(false);
            var promptText = prompt.SystemPrompt + "\n" + prompt.UserPrompt;
            var estimatedPromptTokens = EstimateTokens(promptText);
            var budgetFailure = PreflightBudget(
                snapshot,
                estimatedPromptTokens,
                out var maxOutputTokens,
                out var maxResponseBytes,
                out var requestTimeout);
            if (budgetFailure is not null)
            {
                return await StopAsync(
                    snapshot,
                    CoordinatorRunStatus.BudgetExhausted,
                    budgetFailure,
                    "BudgetExhausted",
                    cancellationToken).ConfigureAwait(false);
            }

            var invocationId = Guid.NewGuid();
            var invocation = new CoordinatorInvocation(
                invocationId,
                role,
                attempts + 1,
                DateTimeOffset.UtcNow,
                null,
                ContentHasher.HashUtf8(promptText),
                "Started",
                null,
                null,
                null,
                estimatedPromptTokens,
                maxOutputTokens,
                maxResponseBytes);
            snapshot = await store.AppendAsync(
                snapshot with
                {
                    Invocations = [.. snapshot.Invocations, invocation],
                    Usage = snapshot.Usage with { Requests = snapshot.Usage.Requests + 1 }
                },
                snapshot.Version,
                "InvocationStarted",
                new
                {
                    invocationId,
                    role,
                    invocation.Attempt,
                    invocation.PromptSha256,
                    estimatedPromptTokens,
                    maxOutputTokens,
                    maxResponseBytes,
                    requestTimeoutMilliseconds = requestTimeout.TotalMilliseconds
                },
                cancellationToken).ConfigureAwait(false);

            var request = new LlmRequest(
                invocationId.ToString("N"),
                role,
                prompt.SystemPrompt,
                [new LlmMessage("user", prompt.UserPrompt)],
                maxOutputTokens,
                maxResponseBytes);
            LlmCallResult result;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(requestTimeout);
                result = await provider.CompleteAsync(request, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                if (recordCancellation)
                {
                    await RecordCancellationAsync(snapshot, invocationId).ConfigureAwait(false);
                }
                throw;
            }
            catch (OperationCanceledException)
            {
                result = LlmCallResult.Failed("timeout", "Model request timed out.", retryable: true);
            }
            catch (Exception exception)
            {
                result = LlmCallResult.Failed(
                    "provider_exception",
                    $"Provider raised an unexpected {exception.GetType().Name}.",
                    retryable: false);
            }

            if (!result.IsSuccess)
            {
                var failure = result.Failure ?? new LlmFailure(
                    "unknown",
                    "Provider failed without details.",
                    false);
                var failedResponseBytes = failure.ResponseBytes is >= 0
                    ? failure.ResponseBytes.Value
                    : maxResponseBytes;
                snapshot = await RecordFailureAsync(
                    snapshot,
                    invocationId,
                    failure,
                    cancellationToken,
                    new LlmUsage(estimatedPromptTokens, maxOutputTokens),
                    failedResponseBytes).ConfigureAwait(false);
                if (failure.Retryable)
                {
                    continue;
                }

                return snapshot;
            }

            var completion = result.Completion!;
            var responseBytes = Math.Max(
                Encoding.UTF8.GetByteCount(completion.Text),
                completion.ResponseBytes);
            if (!StringComparer.Ordinal.Equals(completion.FinishReason, "stop"))
            {
                return await RecordFailureAsync(
                    snapshot,
                    invocationId,
                    new LlmFailure(
                        LlmFailureKinds.InvalidResponse,
                        "Provider did not return an untruncated 'stop' completion.",
                        false,
                        responseBytes),
                    cancellationToken,
                    new LlmUsage(estimatedPromptTokens, maxOutputTokens),
                    responseBytes).ConfigureAwait(false);
            }
            var localOutputEstimate = EstimateTokens(completion.Text);
            if (completion.Usage is null && snapshot.Spec.Budget.RequireReportedUsage)
            {
                return await RecordBudgetFailureAsync(
                    snapshot,
                    invocationId,
                    "Provider did not report token usage.",
                    responseBytes,
                    cancellationToken,
                    new LlmUsage(estimatedPromptTokens, maxOutputTokens)).ConfigureAwait(false);
            }

            if (completion.Usage is { InputTokens: < 0 } or { OutputTokens: < 0 })
            {
                return await RecordBudgetFailureAsync(
                    snapshot,
                    invocationId,
                    "Provider reported invalid negative token usage.",
                    responseBytes,
                    cancellationToken,
                    new LlmUsage(estimatedPromptTokens, maxOutputTokens)).ConfigureAwait(false);
            }

            var chargedUsage = new LlmUsage(
                Math.Max(estimatedPromptTokens, completion.Usage?.InputTokens ?? 0),
                Math.Max(localOutputEstimate, completion.Usage?.OutputTokens ?? 0));
            if (completion.Usage is { OutputTokens: var reportedOutput } && reportedOutput > maxOutputTokens)
            {
                return await RecordBudgetFailureAsync(
                    snapshot,
                    invocationId,
                    "Provider reported more output tokens than the approved request maximum.",
                    responseBytes,
                    cancellationToken,
                    chargedUsage).ConfigureAwait(false);
            }

            if (chargedUsage.OutputTokens > maxOutputTokens)
            {
                return await RecordBudgetFailureAsync(
                    snapshot,
                    invocationId,
                    "Response exceeded the conservative per-request output-token limit.",
                    responseBytes,
                    cancellationToken,
                    chargedUsage).ConfigureAwait(false);
            }

            var updatedUsage = AddUsage(snapshot, chargedUsage, responseBytes, artifactBytes: 0);
            var postflightFailure = CheckActualBudget(snapshot, updatedUsage);
            if (postflightFailure is not null)
            {
                return await RecordBudgetFailureAsync(
                    snapshot,
                    invocationId,
                    postflightFailure,
                    responseBytes,
                    cancellationToken,
                    chargedUsage).ConfigureAwait(false);
            }

            CoordinatorRoleOutput output;
            try
            {
                output = CoordinatorValidation.ParseRoleOutput(
                    completion.Text,
                    role,
                    snapshot.Spec.Sources.Select(source => source.Id).ToHashSet(StringComparer.Ordinal),
                    snapshot.Spec.Purpose);
            }
            catch (CoordinatorValidationException exception)
            {
                snapshot = await RecordFailureAsync(
                    snapshot,
                    invocationId,
                    new LlmFailure("invalid_output", exception.Message, true),
                    cancellationToken,
                    chargedUsage,
                    responseBytes).ConfigureAwait(false);
                continue;
            }

            var artifactSizeBytes = JsonSerializer.SerializeToUtf8Bytes(output, CoordinatorJson.Options).LongLength;
            var expectedRoleArtifactSha256 = ContentHasher.HashJson(output);
            CoordinatorStrategySourceArtifact? strategySourceArtifact = null;
            long strategySourceArtifactSizeBytes = 0;
            string? expectedStrategySourceArtifactSha256 = null;
            if (snapshot.Spec.Purpose == CoordinatorRunPurpose.StrategyAuthoring &&
                role == CoordinatorRole.RiskJudge &&
                output.Decision == CoordinatorDecision.Approve)
            {
                var synthesizerReference = snapshot.Artifacts.SingleOrDefault(item =>
                    item.Role == CoordinatorRole.Synthesizer &&
                    item.SchemaVersion == CoordinatorVersions.ArtifactSchema)
                    ?? throw new CoordinatorIntegrityException(
                        "Approved strategy source is missing its synthesizer artifact.");
                var synthesizerOutput = await artifactStore.ReadJsonAsync<CoordinatorRoleOutput>(
                        synthesizerReference.RelativePath,
                        synthesizerReference.Sha256,
                        cancellationToken)
                    .ConfigureAwait(false);
                strategySourceArtifact = CreateStrategySourceArtifact(
                    snapshot.Spec,
                    synthesizerOutput,
                    synthesizerReference.Sha256,
                    expectedRoleArtifactSha256);
                strategySourceArtifactSizeBytes = JsonSerializer.SerializeToUtf8Bytes(
                    strategySourceArtifact,
                    CoordinatorJson.Options).LongLength;
                expectedStrategySourceArtifactSha256 = ContentHasher.HashJson(strategySourceArtifact);
            }

            var admittedArtifactBytes = checked(artifactSizeBytes + strategySourceArtifactSizeBytes);
            updatedUsage = AddUsage(snapshot, chargedUsage, responseBytes, admittedArtifactBytes);
            postflightFailure = CheckActualBudget(snapshot, updatedUsage);
            if (postflightFailure is not null)
            {
                return await RecordBudgetFailureAsync(
                    snapshot,
                    invocationId,
                    postflightFailure,
                    responseBytes,
                    cancellationToken,
                    chargedUsage).ConfigureAwait(false);
            }

            var stored = await artifactStore.PutJsonAsync(output, cancellationToken).ConfigureAwait(false);
            if (stored.SizeBytes != artifactSizeBytes ||
                !StringComparer.Ordinal.Equals(stored.Sha256, expectedRoleArtifactSha256))
            {
                throw new CoordinatorIntegrityException("Stored role artifact changed after budget admission.");
            }

            var artifact = new CoordinatorArtifactReference(
                role,
                role.ToString(),
                CoordinatorVersions.ArtifactSchema,
                stored.Sha256,
                stored.RelativePath,
                stored.SizeBytes,
                DateTimeOffset.UtcNow);
            var appendedArtifacts = new List<CoordinatorArtifactReference> { artifact };
            var finalHash = snapshot.FinalArtifactSha256;
            var nextStatus = CoordinatorRunStatus.Running;
            string? safeMessage = null;
            if (snapshot.Spec.Purpose == CoordinatorRunPurpose.Research &&
                role == CoordinatorRole.Synthesizer)
            {
                finalHash = stored.Sha256;
            }
            if (role == CoordinatorRole.RiskJudge)
            {
                (nextStatus, safeMessage) = output.Decision switch
                {
                    CoordinatorDecision.Approve => (CoordinatorRunStatus.AwaitingReleaseApproval, "Awaiting human release approval."),
                    CoordinatorDecision.Revise => (CoordinatorRunStatus.NeedsRevision, "Risk judge requested revision."),
                    CoordinatorDecision.Reject => (CoordinatorRunStatus.Rejected,
                        snapshot.Spec.Purpose == CoordinatorRunPurpose.StrategyAuthoring
                            ? "Risk judge rejected the strategy source."
                            : "Risk judge rejected the memo."),
                    _ => throw new InvalidOperationException("Risk judge returned no decision.")
                };
            }
            if (strategySourceArtifact is not null)
            {
                var storedStrategySource = await artifactStore.PutJsonAsync(
                    strategySourceArtifact,
                    cancellationToken).ConfigureAwait(false);
                if (storedStrategySource.SizeBytes != strategySourceArtifactSizeBytes ||
                    !StringComparer.Ordinal.Equals(
                        storedStrategySource.Sha256,
                        expectedStrategySourceArtifactSha256))
                {
                    throw new CoordinatorIntegrityException(
                        "Stored strategy source artifact changed after budget admission.");
                }
                appendedArtifacts.Add(new CoordinatorArtifactReference(
                    CoordinatorRole.Synthesizer,
                    CoordinatorVersions.StrategyArtifactKind,
                    CoordinatorVersions.StrategyArtifactSchema,
                    storedStrategySource.Sha256,
                    storedStrategySource.RelativePath,
                    storedStrategySource.SizeBytes,
                    DateTimeOffset.UtcNow));
                finalHash = storedStrategySource.Sha256;
            }

            var completedInvocation = invocation with
            {
                CompletedAtUtc = DateTimeOffset.UtcNow,
                Status = "Completed",
                Usage = chargedUsage,
                ArtifactSha256 = stored.Sha256,
                ReportedUsage = completion.Usage,
                ProviderRequestId = completion.ProviderRequestId
            };
            snapshot = await store.AppendAsync(
                snapshot with
                {
                    Status = nextStatus,
                    CompletedRoleCount = snapshot.CompletedRoleCount + 1,
                    Usage = updatedUsage,
                    Artifacts = [.. snapshot.Artifacts, .. appendedArtifacts],
                    Invocations = ReplaceInvocation(snapshot.Invocations, completedInvocation),
                    FinalArtifactSha256 = finalHash,
                    SafeMessage = safeMessage
                },
                snapshot.Version,
                "RoleCompleted",
                new { invocationId, role, artifact.Sha256, output.Decision, finalHash },
                cancellationToken).ConfigureAwait(false);
        }

        return snapshot;
    }

    public async Task<CoordinatorRunSnapshot> CancelAsync(
        Guid runId,
        string actor,
        CancellationToken cancellationToken = default) =>
        await SetTerminalAsync(runId, actor, CoordinatorRunStatus.Cancelled, "RunCancelled", cancellationToken)
            .ConfigureAwait(false);

    public async Task<CoordinatorRunSnapshot> RejectAsync(
        Guid runId,
        string actor,
        CancellationToken cancellationToken = default) =>
        await SetTerminalAsync(runId, actor, CoordinatorRunStatus.Rejected, "RunRejected", cancellationToken)
            .ConfigureAwait(false);

    private async Task<CoordinatorRunSnapshot> GetRequiredAsync(Guid runId, CancellationToken cancellationToken)
    {
        await store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        return await store.GetVerifiedAsync(runId, cancellationToken).ConfigureAwait(false);
    }

    private async Task<CoordinatorRunSnapshot> CloseInterruptedInvocationAsync(
        CoordinatorRunSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        var interrupted = snapshot.Invocations.LastOrDefault(item => item.Status == "Started");
        if (interrupted is null)
        {
            return snapshot;
        }

        var staleAfter = TimeSpan.FromSeconds(snapshot.Spec.Budget.RequestTimeoutSeconds + 30L);
        if (DateTimeOffset.UtcNow - interrupted.StartedAtUtc < staleAfter)
        {
            throw new CoordinatorInvocationStillActiveException(
                $"Invocation '{interrupted.InvocationId:D}' may still be active; retry after its request timeout plus 30 seconds.");
        }

        var reservedUsage = new LlmUsage(
            interrupted.ReservedPromptTokens,
            interrupted.ReservedOutputTokens);
        var closed = interrupted with
        {
            Status = "Interrupted",
            CompletedAtUtc = DateTimeOffset.UtcNow,
            SafeError = "The prior process stopped before recording a completion.",
            Usage = reservedUsage
        };
        var conservativeUsage = AddUsage(
            snapshot,
            reservedUsage,
            responseBytes: interrupted.ReservedResponseBytes,
            artifactBytes: 0);
        return await store.AppendAsync(
            snapshot with
            {
                Invocations = ReplaceInvocation(snapshot.Invocations, closed),
                Usage = conservativeUsage,
                SafeMessage = "Interrupted request budget was conservatively charged before retry."
            },
            snapshot.Version,
            "InvocationInterrupted",
            new { interrupted.InvocationId, interrupted.Role },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<CoordinatorRunSnapshot> RecordFailureAsync(
        CoordinatorRunSnapshot snapshot,
        Guid invocationId,
        LlmFailure failure,
        CancellationToken cancellationToken,
        LlmUsage? usage = null,
        long responseBytes = 0)
    {
        var invocation = snapshot.Invocations.Single(item => item.InvocationId == invocationId) with
        {
            Status = "Failed",
            CompletedAtUtc = DateTimeOffset.UtcNow,
            SafeError = failure.SafeMessage,
            Usage = usage
        };
        var nextStatus = failure.Retryable ? CoordinatorRunStatus.Running : CoordinatorRunStatus.Failed;
        var nextUsage = usage is null ? snapshot.Usage : AddUsage(snapshot, usage, responseBytes, 0);
        return await store.AppendAsync(
            snapshot with
            {
                Status = nextStatus,
                Invocations = ReplaceInvocation(snapshot.Invocations, invocation),
                Usage = nextUsage,
                SafeMessage = failure.SafeMessage
            },
            snapshot.Version,
            "InvocationFailed",
            new { invocationId, failure.Kind, failure.SafeMessage, failure.Retryable },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<CoordinatorRunSnapshot> RecordBudgetFailureAsync(
        CoordinatorRunSnapshot snapshot,
        Guid invocationId,
        string message,
        long responseBytes,
        CancellationToken cancellationToken,
        LlmUsage? usage = null)
    {
        var invocation = snapshot.Invocations.Single(item => item.InvocationId == invocationId) with
        {
            Status = "BudgetBlocked",
            CompletedAtUtc = DateTimeOffset.UtcNow,
            SafeError = message,
            Usage = usage
        };
        var nextUsage = usage is null
            ? snapshot.Usage with { ResponseBytes = SaturatingAdd(snapshot.Usage.ResponseBytes, responseBytes) }
            : AddUsage(snapshot, usage, responseBytes, 0);
        return await store.AppendAsync(
            snapshot with
            {
                Status = CoordinatorRunStatus.BudgetExhausted,
                Invocations = ReplaceInvocation(snapshot.Invocations, invocation),
                Usage = nextUsage,
                SafeMessage = message
            },
            snapshot.Version,
            "BudgetExhausted",
            new { invocationId, message },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task RecordCancellationAsync(CoordinatorRunSnapshot snapshot, Guid invocationId)
    {
        var active = snapshot.Invocations.Single(item => item.InvocationId == invocationId);
        var reservedUsage = new LlmUsage(active.ReservedPromptTokens, active.ReservedOutputTokens);
        var invocation = active with
        {
            Status = "Cancelled",
            CompletedAtUtc = DateTimeOffset.UtcNow,
            SafeError = "Cancelled by operator.",
            Usage = reservedUsage
        };
        await store.AppendAsync(
            snapshot with
            {
                Status = CoordinatorRunStatus.Cancelled,
                Invocations = ReplaceInvocation(snapshot.Invocations, invocation),
                Usage = AddUsage(snapshot, reservedUsage, active.ReservedResponseBytes, 0),
                SafeMessage = "Cancelled by operator."
            },
            snapshot.Version,
            "InvocationCancelled",
            new { invocationId },
            CancellationToken.None).ConfigureAwait(false);
    }

    private async Task<CoordinatorRunSnapshot> SetTerminalAsync(
        Guid runId,
        string actor,
        CoordinatorRunStatus status,
        string eventType,
        CancellationToken cancellationToken)
    {
        RequireActor(actor);
        var snapshot = await GetRequiredAsync(runId, cancellationToken).ConfigureAwait(false);
        if (snapshot.Status is CoordinatorRunStatus.Completed or CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected)
        {
            throw new InvalidOperationException($"Run is already terminal in state '{snapshot.Status}'.");
        }

        var invocations = snapshot.Invocations;
        var usage = snapshot.Usage;
        var active = snapshot.Invocations.LastOrDefault(item => item.Status == "Started");
        if (active is not null)
        {
            var reservedUsage = new LlmUsage(active.ReservedPromptTokens, active.ReservedOutputTokens);
            var closed = active with
            {
                Status = status == CoordinatorRunStatus.Cancelled ? "CancelledExternally" : "RejectedExternally",
                CompletedAtUtc = DateTimeOffset.UtcNow,
                SafeError = $"{eventType} by another operator process.",
                Usage = reservedUsage
            };
            invocations = ReplaceInvocation(invocations, closed);
            usage = AddUsage(snapshot, reservedUsage, active.ReservedResponseBytes, 0);
        }

        return await store.AppendAsync(
            snapshot with
            {
                Status = status,
                Invocations = invocations,
                Usage = usage,
                SafeMessage = $"{eventType} by {actor.Trim()}."
            },
            snapshot.Version,
            eventType,
            new { actor = actor.Trim() },
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<CoordinatorRunSnapshot> StopAsync(
        CoordinatorRunSnapshot snapshot,
        CoordinatorRunStatus status,
        string message,
        string eventType,
        CancellationToken cancellationToken) =>
        await store.AppendAsync(
            snapshot with { Status = status, SafeMessage = message },
            snapshot.Version,
            eventType,
            new { message },
            cancellationToken).ConfigureAwait(false);

    private static string? PreflightBudget(
        CoordinatorRunSnapshot snapshot,
        int estimatedPromptTokens,
        out int maxOutputTokens,
        out int maxResponseBytes,
        out TimeSpan requestTimeout)
    {
        var budget = snapshot.Spec.Budget;
        maxOutputTokens = 0;
        maxResponseBytes = 0;
        requestTimeout = TimeSpan.Zero;
        var remainingOutputTokens = budget.MaxOutputTokens - snapshot.Usage.OutputTokens;
        maxOutputTokens = remainingOutputTokens > 0
            ? checked((int)Math.Min(budget.MaxOutputTokensPerRequest, remainingOutputTokens))
            : 0;
        if (snapshot.Usage.Requests + 1 > budget.MaxRequests)
        {
            return "Request limit reached.";
        }

        if (snapshot.Usage.PromptTokens + estimatedPromptTokens > budget.MaxPromptTokens)
        {
            return "Prompt-token limit would be exceeded.";
        }

        if (maxOutputTokens <= 0)
        {
            return "Output-token limit reached.";
        }

        var remainingResponseBytes = budget.MaxResponseBytes - snapshot.Usage.ResponseBytes;
        if (remainingResponseBytes <= 0)
        {
            return "Response-byte limit reached.";
        }
        maxResponseBytes = checked((int)Math.Min(int.MaxValue, remainingResponseBytes));

        if (snapshot.Usage.ArtifactBytes >= budget.MaxArtifactBytes)
        {
            return "Artifact-byte limit reached.";
        }

        var firstStarted = snapshot.Invocations.OrderBy(item => item.StartedAtUtc).FirstOrDefault()?.StartedAtUtc;
        var remainingElapsed = firstStarted is null
            ? TimeSpan.FromSeconds(budget.MaxElapsedSeconds)
            : TimeSpan.FromSeconds(budget.MaxElapsedSeconds) - (DateTimeOffset.UtcNow - firstStarted.Value);
        if (remainingElapsed <= TimeSpan.Zero)
        {
            return "Elapsed-time limit reached.";
        }
        requestTimeout = TimeSpan.FromSeconds(budget.RequestTimeoutSeconds);
        if (remainingElapsed < requestTimeout)
        {
            requestTimeout = remainingElapsed;
        }

        var reservedCost = CalculateCost(snapshot.Spec.Provider, estimatedPromptTokens, maxOutputTokens);
        return snapshot.Usage.CostUsd + reservedCost > budget.MaxCostUsd
            ? "Cost limit would be exceeded by the next request."
            : null;
    }

    private static string? CheckActualBudget(CoordinatorRunSnapshot snapshot, CoordinatorUsage usage)
    {
        var budget = snapshot.Spec.Budget;
        if (usage.PromptTokens > budget.MaxPromptTokens) return "Provider-reported prompt tokens exceeded the limit.";
        if (usage.OutputTokens > budget.MaxOutputTokens) return "Provider-reported output tokens exceeded the limit.";
        if (usage.CostUsd > budget.MaxCostUsd) return "Provider-reported usage exceeded the cost limit.";
        if (usage.ResponseBytes > budget.MaxResponseBytes) return "Response-byte limit exceeded.";
        if (usage.ArtifactBytes > budget.MaxArtifactBytes) return "Artifact-byte limit exceeded.";
        var firstStarted = snapshot.Invocations.OrderBy(item => item.StartedAtUtc).FirstOrDefault()?.StartedAtUtc;
        if (firstStarted is not null && DateTimeOffset.UtcNow - firstStarted > TimeSpan.FromSeconds(budget.MaxElapsedSeconds))
            return "Elapsed-time limit exceeded.";
        return null;
    }

    private static CoordinatorUsage AddUsage(
        CoordinatorRunSnapshot snapshot,
        LlmUsage usage,
        long responseBytes,
        long artifactBytes) =>
        snapshot.Usage with
        {
            PromptTokens = SaturatingAdd(snapshot.Usage.PromptTokens, usage.InputTokens),
            OutputTokens = SaturatingAdd(snapshot.Usage.OutputTokens, usage.OutputTokens),
            CostUsd = snapshot.Usage.CostUsd + CalculateCost(snapshot.Spec.Provider, usage.InputTokens, usage.OutputTokens),
            ResponseBytes = SaturatingAdd(snapshot.Usage.ResponseBytes, responseBytes),
            ArtifactBytes = SaturatingAdd(snapshot.Usage.ArtifactBytes, artifactBytes)
        };

    private static long SaturatingAdd(long left, long right) =>
        left >= long.MaxValue - right ? long.MaxValue : left + right;

    private static decimal CalculateCost(LlmProviderDescriptor providerDescriptor, long inputTokens, long outputTokens) =>
        (inputTokens * providerDescriptor.InputUsdPerMillionTokens
         + outputTokens * providerDescriptor.OutputUsdPerMillionTokens) / 1_000_000m;

    private static CoordinatorStrategySourceArtifact CreateStrategySourceArtifact(
        CoordinatorRunSpec spec,
        CoordinatorRoleOutput synthesizerOutput,
        string synthesizerArtifactSha256,
        string riskJudgeArtifactSha256)
    {
        var draft = synthesizerOutput.StrategyDraft
            ?? throw new CoordinatorIntegrityException(
                "Approved strategy source is missing its validated synthesizer draft.");
        var artifact = new CoordinatorStrategySourceArtifact
        {
            SchemaVersion = CoordinatorVersions.StrategyArtifactSchema,
            RunId = spec.RunId,
            ObjectiveSha256 = ContentHasher.HashUtf8(spec.Objective),
            StrategyId = draft.StrategyId,
            DisplayName = draft.DisplayName,
            Files = draft.Files.Select(file => new CoordinatorStrategySourceFile(
                file.RelativePath,
                file.Content,
                ContentHasher.HashUtf8(file.Content))).ToArray(),
            EvidenceSourceIds = synthesizerOutput.SourceIds.ToArray(),
            SynthesizerArtifactSha256 = synthesizerArtifactSha256,
            RiskJudgeArtifactSha256 = riskJudgeArtifactSha256,
            DeliveryState = CoordinatorVersions.StrategyDeliveryState,
            CompilerProfile = CoordinatorVersions.StrategyCompilerProfile,
            RequiresHumanRelease = true,
            RequiresTerminalCompileConsent = true,
            InstallEligible = false
        };
        try
        {
            CoordinatorStrategyArtifactValidation.Validate(artifact);
        }
        catch (InvalidDataException exception)
        {
            throw new CoordinatorIntegrityException(exception.Message);
        }
        return artifact;
    }

    private async Task ValidateStrategyArtifactLineageAsync(
        CoordinatorRunSnapshot snapshot,
        CoordinatorStrategySourceArtifact artifact,
        CancellationToken cancellationToken)
    {
        var synthesizerReference = snapshot.Artifacts.Single(reference =>
            reference.Role == CoordinatorRole.Synthesizer &&
            reference.SchemaVersion == CoordinatorVersions.ArtifactSchema &&
            StringComparer.Ordinal.Equals(reference.Sha256, artifact.SynthesizerArtifactSha256));
        var riskJudgeReference = snapshot.Artifacts.Single(reference =>
            reference.Role == CoordinatorRole.RiskJudge &&
            reference.SchemaVersion == CoordinatorVersions.ArtifactSchema &&
            StringComparer.Ordinal.Equals(reference.Sha256, artifact.RiskJudgeArtifactSha256));
        var synthesizerOutput = await artifactStore.ReadJsonAsync<CoordinatorRoleOutput>(
                synthesizerReference.RelativePath,
                synthesizerReference.Sha256,
                cancellationToken)
            .ConfigureAwait(false);
        var riskJudgeOutput = await artifactStore.ReadJsonAsync<CoordinatorRoleOutput>(
                riskJudgeReference.RelativePath,
                riskJudgeReference.Sha256,
                cancellationToken)
            .ConfigureAwait(false);
        var allowedSourceIds = snapshot.Spec.Sources
            .Select(source => source.Id)
            .ToHashSet(StringComparer.Ordinal);
        try
        {
            synthesizerOutput = CoordinatorValidation.ParseRoleOutput(
                JsonSerializer.Serialize(synthesizerOutput, CoordinatorJson.Options),
                CoordinatorRole.Synthesizer,
                allowedSourceIds,
                CoordinatorRunPurpose.StrategyAuthoring);
            riskJudgeOutput = CoordinatorValidation.ParseRoleOutput(
                JsonSerializer.Serialize(riskJudgeOutput, CoordinatorJson.Options),
                CoordinatorRole.RiskJudge,
                allowedSourceIds,
                CoordinatorRunPurpose.StrategyAuthoring);
        }
        catch (CoordinatorValidationException exception)
        {
            throw new CoordinatorIntegrityException(exception.Message);
        }
        if (riskJudgeOutput.Decision != CoordinatorDecision.Approve)
        {
            throw new CoordinatorIntegrityException(
                "Released strategy source is not bound to an approving Risk Judge artifact.");
        }

        var expectedArtifact = CreateStrategySourceArtifact(
            snapshot.Spec,
            synthesizerOutput,
            synthesizerReference.Sha256,
            riskJudgeReference.Sha256);
        if (!StringComparer.Ordinal.Equals(
                ContentHasher.HashJson(expectedArtifact),
                ContentHasher.HashJson(artifact)))
        {
            throw new CoordinatorIntegrityException(
                "Released strategy source does not reproduce from its exact role artifacts.");
        }
    }

    // UTF-8 bytes are a deliberately conservative tokenizer-independent upper bound for preflight.
    private static int EstimateTokens(string text) => Math.Max(1, Encoding.UTF8.GetByteCount(text));

    private static IReadOnlyList<CoordinatorInvocation> ReplaceInvocation(
        IReadOnlyList<CoordinatorInvocation> invocations,
        CoordinatorInvocation replacement) =>
        invocations.Select(item => item.InvocationId == replacement.InvocationId ? replacement : item).ToArray();

    private void EnsureProviderMatches(LlmProviderDescriptor descriptor)
    {
        if (provider.Descriptor != descriptor)
        {
            throw new InvalidOperationException(
                "Configured provider, model, protocol, endpoint, prices, or credential/replay binding does not match the approved run specification.");
        }
    }

    private static void VerifyStartApproval(CoordinatorRunSnapshot snapshot)
    {
        var approval = snapshot.Approvals.LastOrDefault(item => item.Gate == ApprovalGate.Start)
            ?? throw new InvalidOperationException("Run has no start approval.");
        if (!StringComparer.Ordinal.Equals(approval.BoundSpecSha256, ContentHasher.HashJson(snapshot.Spec)))
        {
            throw new InvalidOperationException("Start approval does not match the current run specification.");
        }
    }

    private static void RequireActor(string actor)
    {
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 200)
        {
            throw new ArgumentException("Actor is required and must be at most 200 characters.", nameof(actor));
        }
    }
}
