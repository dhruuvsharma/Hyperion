using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace Hyperion.FreeStrategyWorkflow;

/// <summary>
/// Runs the fixed, bounded strategy-authoring roles against a caller-supplied provider. It produces
/// only inert source. Start approval, release approval, and Terminal compile consent remain separate.
/// </summary>
public sealed class FreeStrategyWorkflowRunner
{
    private readonly ICoordinatorStore _store;
    private readonly ICoordinatorArtifactStore _artifactStore;
    private readonly ILlmProvider _provider;

    public FreeStrategyWorkflowRunner(
        ICoordinatorStore store,
        ICoordinatorArtifactStore artifactStore,
        ILlmProvider provider)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(artifactStore);
        ArgumentNullException.ThrowIfNull(provider);
        _store = store;
        _artifactStore = artifactStore;
        _provider = provider;
    }

    public async Task<FreeStrategyWorkflowDraft> CreateAsync(
        FreeStrategyWorkflowRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Sources);
        if (request.Sources.Count > FreeStrategyWorkflowVersions.MaximumInitialSources)
        {
            throw new ArgumentException(
                $"Initial runs accept at most {FreeStrategyWorkflowVersions.MaximumInitialSources} sources so the bounded repair contract retains six reserved source slots.",
                nameof(request));
        }
        if (request.Sources.Any(source =>
                source.Id.StartsWith(FreeStrategyWorkflowSourceIds.ReservedPrefix, StringComparison.Ordinal)))
        {
            throw new ArgumentException(
                $"Source IDs beginning with '{FreeStrategyWorkflowSourceIds.ReservedPrefix}' are reserved for repair lineage.",
                nameof(request));
        }

        return await CreateDraftAsync(
            request.Objective,
            request.Owner,
            request.Sources,
            request.Budget,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<FreeStrategyWorkflowDraft> CreateRevisionAsync(
        FreeStrategyWorkflowRevisionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRevisionRequest(request);
        var parent = await GetVerifiedFreeSnapshotAsync(request.ParentRunId, cancellationToken)
            .ConfigureAwait(false);
        EnsureProviderMatches(parent.Spec.Provider);
        if (parent.Status is not (
                CoordinatorRunStatus.NeedsRevision or
                CoordinatorRunStatus.Rejected or
                CoordinatorRunStatus.AwaitingReleaseApproval or
                CoordinatorRunStatus.Completed))
        {
            throw new InvalidOperationException(
                $"Run in state '{parent.Status}' cannot seed a repair run.");
        }

        _ = await BuildResultAsync(parent, cancellationToken).ConfigureAwait(false);
        var synthesizer = await ReadRoleOutputAsync(
            parent,
            CoordinatorRole.Synthesizer,
            cancellationToken).ConfigureAwait(false);
        var riskJudge = await ReadRoleOutputAsync(
            parent,
            CoordinatorRole.RiskJudge,
            cancellationToken).ConfigureAwait(false);
        var rootObjective = ReadRootObjective(parent);
        var repairRound = checked((ReadRepairLineage(parent)?.RepairRound ?? 0) + 1);
        if (repairRound > FreeStrategyWorkflowVersions.MaximumRepairRounds)
        {
            throw new InvalidOperationException(
                $"The bounded repair loop permits at most {FreeStrategyWorkflowVersions.MaximumRepairRounds} rounds.");
        }

        var synthesizerReference = RequiredRoleReference(parent, CoordinatorRole.Synthesizer);
        var riskJudgeReference = RequiredRoleReference(parent, CoordinatorRole.RiskJudge);
        var lineage = new FreeStrategyRepairLineage
        {
            RepairRound = repairRound,
            ParentRunId = parent.Spec.RunId,
            ParentSpecificationSha256 = ContentHasher.HashJson(parent.Spec),
            ParentSynthesizerArtifactSha256 = synthesizerReference.Sha256,
            ParentRiskJudgeArtifactSha256 = riskJudgeReference.Sha256,
            ParentFinalArtifactSha256 = parent.FinalArtifactSha256,
            ParentDecision = riskJudge.Decision,
            RootObjectiveSha256 = ContentHasher.HashUtf8(rootObjective),
            ChangeRequestSha256 = ContentHasher.HashUtf8(request.ChangeRequest),
            DiagnosticsSha256 = request.Diagnostics is null
                ? null
                : ContentHasher.HashUtf8(request.Diagnostics),
        };
        var sources = parent.Spec.Sources
            .Where(source => !source.Id.StartsWith(
                FreeStrategyWorkflowSourceIds.ReservedPrefix,
                StringComparison.Ordinal))
            .ToList();
        sources.Add(new CoordinatorContextSource(
            FreeStrategyWorkflowSourceIds.Lineage,
            $"Repair lineage round {repairRound}",
            JsonSerializer.Serialize(lineage, CoordinatorJson.Options)));
        sources.Add(new CoordinatorContextSource(
            FreeStrategyWorkflowSourceIds.RootObjective,
            "Original strategy objective",
            rootObjective));
        sources.Add(new CoordinatorContextSource(
            FreeStrategyWorkflowSourceIds.ParentDraft,
            "Exact parent Synthesizer output",
            JsonSerializer.Serialize(synthesizer, CoordinatorJson.Options)));
        sources.Add(new CoordinatorContextSource(
            FreeStrategyWorkflowSourceIds.ParentReview,
            "Exact parent Risk Judge output",
            JsonSerializer.Serialize(riskJudge, CoordinatorJson.Options)));
        sources.Add(new CoordinatorContextSource(
            FreeStrategyWorkflowSourceIds.ChangeRequest,
            "User-approved repair request",
            request.ChangeRequest));
        if (request.Diagnostics is not null)
        {
            sources.Add(new CoordinatorContextSource(
                FreeStrategyWorkflowSourceIds.Diagnostics,
                "User-supplied deterministic diagnostics",
                request.Diagnostics));
        }
        ValidateRepairSourceCapacity(sources);

        return await CreateDraftAsync(
            RepairObjective(repairRound),
            request.Owner,
            sources,
            request.Budget,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<FreeStrategyGauntletReport> InspectGauntletAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        var snapshot = await GetVerifiedFreeSnapshotAsync(runId, cancellationToken).ConfigureAwait(false);
        EnsureProviderMatches(snapshot.Spec.Provider);
        var result = await BuildResultAsync(snapshot, cancellationToken).ConfigureAwait(false);
        var specificationSha256 = ContentHasher.HashJson(snapshot.Spec);
        var startApprovals = snapshot.Approvals.Where(approval =>
            approval.Gate == ApprovalGate.Start).ToArray();
        var hasBoundStartApproval = startApprovals.Length == 1 &&
                                    StringComparer.Ordinal.Equals(
                                        startApprovals[0].BoundSpecSha256,
                                        specificationSha256) &&
                                    startApprovals[0].BoundArtifactSha256 is null;
        var hasEveryRoleArtifact = ResearchCoordinator.Workflow.All(role =>
            snapshot.Artifacts.Count(reference =>
                reference.Role == role &&
                reference.SchemaVersion == CoordinatorVersions.ArtifactSchema) == 1);
        var verifiedRoleOutputs = new Dictionary<CoordinatorRole, CoordinatorRoleOutput>();
        if (hasEveryRoleArtifact)
        {
            foreach (var role in ResearchCoordinator.Workflow)
            {
                verifiedRoleOutputs[role] = await ReadRoleOutputAsync(
                    snapshot,
                    role,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        var riskJudgeApproved = verifiedRoleOutputs.TryGetValue(
            CoordinatorRole.RiskJudge,
            out var riskJudge) && riskJudge.Decision == CoordinatorDecision.Approve;
        verifiedRoleOutputs.TryGetValue(CoordinatorRole.Synthesizer, out var synthesizer);

        var artifactBound = result.StrategyArtifact is not null &&
                            synthesizer is not null &&
                            snapshot.FinalArtifactSha256 is not null &&
                            StringComparer.Ordinal.Equals(
                                ContentHasher.HashJson(result.StrategyArtifact),
                                snapshot.FinalArtifactSha256) &&
                            StrategyArtifactReproduces(
                                snapshot,
                                result.StrategyArtifact,
                                synthesizer);
        var inertAuthority = result.StrategyArtifact is
        {
            RequiresHumanRelease: true,
            RequiresTerminalCompileConsent: true,
            InstallEligible: false,
            DeliveryState: CoordinatorVersions.StrategyDeliveryState,
        };
        var readyOrReleased = snapshot.Status is
            CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed;
        var releaseApprovals = snapshot.Approvals.Where(approval =>
            approval.Gate == ApprovalGate.Release).ToArray();
        var releaseApprovalConsistent = snapshot.Status switch
        {
            CoordinatorRunStatus.AwaitingReleaseApproval => releaseApprovals.Length == 0,
            CoordinatorRunStatus.Completed => releaseApprovals.Length == 1 &&
                StringComparer.Ordinal.Equals(releaseApprovals[0].BoundSpecSha256, specificationSha256) &&
                StringComparer.Ordinal.Equals(
                    releaseApprovals[0].BoundArtifactSha256,
                    snapshot.FinalArtifactSha256),
            _ => false,
        };
        var checks = new[]
        {
            new FreeStrategyGauntletCheck(
                "verified-event-chain-and-profile",
                true,
                "The durable event chain and exact local free-workflow profile were verified."),
            new FreeStrategyGauntletCheck(
                "exact-start-approval",
                hasBoundStartApproval,
                "One start approval must bind the exact specification SHA-256."),
            new FreeStrategyGauntletCheck(
                "complete-role-artifacts",
                hasEveryRoleArtifact,
                "Planner, Evidence Analyst, Critic, Synthesizer, and Risk Judge artifacts must each be present once."),
            new FreeStrategyGauntletCheck(
                "risk-judge-approval",
                riskJudgeApproved,
                "The exact Risk Judge output must approve the parent Synthesizer output."),
            new FreeStrategyGauntletCheck(
                "strategy-artifact-lineage",
                artifactBound,
                "The source artifact must reproduce from its exact run and role-artifact lineage."),
            new FreeStrategyGauntletCheck(
                "inert-authority-boundary",
                inertAuthority,
                "The artifact must require release and Terminal compile consent and grant no installation authority."),
            new FreeStrategyGauntletCheck(
                "release-review-state",
                readyOrReleased,
                "The run must be awaiting exact human release review or already released."),
            new FreeStrategyGauntletCheck(
                "release-approval-consistency",
                releaseApprovalConsistent,
                "An awaiting run must have no release approval; a completed run must have exactly one approval bound to its specification and artifact."),
        };
        var processIntegrityPassed = checks.All(check => check.Passed);
        return new FreeStrategyGauntletReport
        {
            RunId = snapshot.Spec.RunId,
            Status = snapshot.Status,
            FinalArtifactSha256 = snapshot.FinalArtifactSha256,
            Checks = checks,
            ProcessIntegrityPassed = processIntegrityPassed,
            ReadyForHumanReleaseReview = processIntegrityPassed &&
                                         snapshot.Status == CoordinatorRunStatus.AwaitingReleaseApproval,
            SemanticCorrectnessGuaranteed = false,
        };
    }

    private async Task<FreeStrategyWorkflowDraft> CreateDraftAsync(
        string objective,
        string owner,
        IReadOnlyList<CoordinatorContextSource> sources,
        CoordinatorBudget budget,
        CancellationToken cancellationToken)
    {
        var spec = new CoordinatorRunSpec(
            Guid.NewGuid(),
            objective,
            owner,
            DateTimeOffset.UtcNow,
            sources,
            _provider.Descriptor,
            budget,
            CoordinatorVersions.FreeStrategyPolicy,
            CoordinatorVersions.FreeStrategyWorkflow,
            CoordinatorPromptCatalog.StrategySha256,
            CoordinatorRunPurpose.StrategyAuthoring);
        var snapshot = await Coordinator().CreateAsync(spec, cancellationToken).ConfigureAwait(false);
        return new FreeStrategyWorkflowDraft(snapshot, ContentHasher.HashJson(snapshot.Spec));
    }

    public async Task<FreeStrategyWorkflowResult> StartAsync(
        Guid runId,
        string actor,
        string reviewedSpecificationSha256,
        CancellationToken cancellationToken = default)
    {
        ValidateActor(actor);
        var snapshot = await GetVerifiedFreeSnapshotAsync(runId, cancellationToken).ConfigureAwait(false);
        EnsureProviderMatches(snapshot.Spec.Provider);
        var actualSpecificationSha256 = ContentHasher.HashJson(snapshot.Spec);
        if (!StringComparer.Ordinal.Equals(actualSpecificationSha256, reviewedSpecificationSha256))
        {
            throw new InvalidOperationException(
                "Start approval must bind the exact reviewed run-specification SHA-256.");
        }

        var coordinator = Coordinator();
        if (snapshot.Status == CoordinatorRunStatus.AwaitingStartApproval)
        {
            snapshot = await coordinator.ApproveStartAsync(
                runId,
                actor,
                reviewedSpecificationSha256,
                cancellationToken).ConfigureAwait(false);
        }

        if (snapshot.Status is CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)
        {
            snapshot = await coordinator.ResumeAsync(runId, cancellationToken).ConfigureAwait(false);
        }
        return await BuildResultAsync(snapshot, cancellationToken).ConfigureAwait(false);
    }

    public async Task<CoordinatorRunSnapshot> ApproveReleaseAsync(
        Guid runId,
        string actor,
        string reviewedArtifactSha256,
        CancellationToken cancellationToken = default)
    {
        var snapshot = await GetVerifiedFreeSnapshotAsync(runId, cancellationToken).ConfigureAwait(false);
        EnsureProviderMatches(snapshot.Spec.Provider);
        return await Coordinator().ApproveReleaseAsync(
            runId,
            actor,
            reviewedArtifactSha256,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<FreeStrategyWorkflowResult> GetAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        var snapshot = await GetVerifiedFreeSnapshotAsync(runId, cancellationToken).ConfigureAwait(false);
        return await BuildResultAsync(snapshot, cancellationToken).ConfigureAwait(false);
    }

    private ResearchCoordinator Coordinator() => new(_store, _artifactStore, _provider);

    private async Task<FreeStrategyWorkflowResult> BuildResultAsync(
        CoordinatorRunSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        if (snapshot.FinalArtifactSha256 is null)
        {
            return new FreeStrategyWorkflowResult(snapshot, null);
        }

        var reference = snapshot.Artifacts.SingleOrDefault(item =>
            item.Kind == CoordinatorVersions.StrategyArtifactKind &&
            item.SchemaVersion == CoordinatorVersions.StrategyArtifactSchema &&
            StringComparer.Ordinal.Equals(item.Sha256, snapshot.FinalArtifactSha256));
        if (reference is null)
        {
            throw new CoordinatorIntegrityException(
                "The final strategy artifact reference is missing from the run.");
        }

        var artifact = await _artifactStore.ReadJsonAsync<CoordinatorStrategySourceArtifact>(
            reference.RelativePath,
            reference.Sha256,
            cancellationToken).ConfigureAwait(false);
        CoordinatorStrategyArtifactValidation.ValidateForRun(
            artifact,
            snapshot.Spec,
            snapshot.Artifacts);
        return new FreeStrategyWorkflowResult(snapshot, artifact);
    }

    private async Task<CoordinatorRunSnapshot> GetVerifiedFreeSnapshotAsync(
        Guid runId,
        CancellationToken cancellationToken)
    {
        await _store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        return await GetVerifiedFreeSnapshotCoreAsync(
            runId,
            new HashSet<Guid>(),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<CoordinatorRunSnapshot> GetVerifiedFreeSnapshotCoreAsync(
        Guid runId,
        HashSet<Guid> lineageStack,
        CancellationToken cancellationToken)
    {
        if (!lineageStack.Add(runId) ||
            lineageStack.Count > FreeStrategyWorkflowVersions.MaximumRepairRounds + 1)
        {
            throw new CoordinatorIntegrityException(
                "Repair lineage contains a cycle or exceeds the bounded repair depth.");
        }

        var snapshot = await _store.GetVerifiedAsync(runId, cancellationToken).ConfigureAwait(false);
        CoordinatorValidation.ValidateSpec(snapshot.Spec);
        if (snapshot.Spec.RunId != runId)
        {
            throw new CoordinatorIntegrityException("The loaded run ID does not match the requested run.");
        }
        if (snapshot.Spec.Purpose != CoordinatorRunPurpose.StrategyAuthoring ||
            snapshot.Spec.PolicyVersion != CoordinatorVersions.FreeStrategyPolicy ||
            snapshot.Spec.WorkflowVersion != CoordinatorVersions.FreeStrategyWorkflow)
        {
            throw new CoordinatorIntegrityException(
                "The run does not use the exact local free strategy-workflow profile.");
        }
        await ValidateRepairLineageAsync(snapshot, lineageStack, cancellationToken)
            .ConfigureAwait(false);
        lineageStack.Remove(runId);
        return snapshot;
    }

    private async Task ValidateRepairLineageAsync(
        CoordinatorRunSnapshot snapshot,
        HashSet<Guid> lineageStack,
        CancellationToken cancellationToken)
    {
        var reservedSources = snapshot.Spec.Sources.Where(source =>
            source.Id.StartsWith(
                FreeStrategyWorkflowSourceIds.ReservedPrefix,
                StringComparison.Ordinal)).ToArray();
        var lineage = ReadRepairLineage(snapshot);
        if (lineage is null)
        {
            if (reservedSources.Length != 0)
            {
                throw new CoordinatorIntegrityException(
                    "An initial free-workflow run cannot contain reserved repair sources.");
            }
            return;
        }

        var allowedReservedIds = new HashSet<string>(StringComparer.Ordinal)
        {
            FreeStrategyWorkflowSourceIds.Lineage,
            FreeStrategyWorkflowSourceIds.RootObjective,
            FreeStrategyWorkflowSourceIds.ParentDraft,
            FreeStrategyWorkflowSourceIds.ParentReview,
            FreeStrategyWorkflowSourceIds.ChangeRequest,
            FreeStrategyWorkflowSourceIds.Diagnostics,
        };
        if (reservedSources.Any(source => !allowedReservedIds.Contains(source.Id)))
        {
            throw new CoordinatorIntegrityException(
                "Repair lineage contains an unknown reserved source.");
        }

        var parent = await GetVerifiedFreeSnapshotCoreAsync(
            lineage.ParentRunId,
            lineageStack,
            cancellationToken).ConfigureAwait(false);
        if (parent.Status is not (
                CoordinatorRunStatus.NeedsRevision or
                CoordinatorRunStatus.Rejected or
                CoordinatorRunStatus.AwaitingReleaseApproval or
                CoordinatorRunStatus.Completed))
        {
            throw new CoordinatorIntegrityException(
                "Repair lineage references a parent that could not seed a revision.");
        }

        var parentRound = ReadRepairLineage(parent)?.RepairRound ?? 0;
        var parentSynthesizer = await ReadRoleOutputAsync(
            parent,
            CoordinatorRole.Synthesizer,
            cancellationToken).ConfigureAwait(false);
        var parentRiskJudge = await ReadRoleOutputAsync(
            parent,
            CoordinatorRole.RiskJudge,
            cancellationToken).ConfigureAwait(false);
        var parentSynthesizerReference = RequiredRoleReference(
            parent,
            CoordinatorRole.Synthesizer);
        var parentRiskJudgeReference = RequiredRoleReference(
            parent,
            CoordinatorRole.RiskJudge);
        if (parent.FinalArtifactSha256 is not null)
        {
            _ = await BuildResultAsync(parent, cancellationToken).ConfigureAwait(false);
        }

        var inheritedSources = snapshot.Spec.Sources.Where(source =>
            !source.Id.StartsWith(
                FreeStrategyWorkflowSourceIds.ReservedPrefix,
                StringComparison.Ordinal));
        var parentInheritedSources = parent.Spec.Sources.Where(source =>
            !source.Id.StartsWith(
                FreeStrategyWorkflowSourceIds.ReservedPrefix,
                StringComparison.Ordinal));
        if (lineage.RepairRound != parentRound + 1 ||
            !StringComparer.Ordinal.Equals(snapshot.Spec.Objective, RepairObjective(lineage.RepairRound)) ||
            snapshot.Spec.Provider != parent.Spec.Provider ||
            !inheritedSources.SequenceEqual(parentInheritedSources) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentSpecificationSha256,
                ContentHasher.HashJson(parent.Spec)) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentSynthesizerArtifactSha256,
                parentSynthesizerReference.Sha256) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentRiskJudgeArtifactSha256,
                parentRiskJudgeReference.Sha256) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentFinalArtifactSha256,
                parent.FinalArtifactSha256) ||
            lineage.ParentDecision != parentRiskJudge.Decision ||
            !StringComparer.Ordinal.Equals(
                lineage.RootObjectiveSha256,
                ContentHasher.HashUtf8(ReadRootObjective(parent))) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentSynthesizerArtifactSha256,
                ContentHasher.HashJson(parentSynthesizer)) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentRiskJudgeArtifactSha256,
                ContentHasher.HashJson(parentRiskJudge)))
        {
            throw new CoordinatorIntegrityException(
                "Repair lineage does not match its verified parent run and artifacts.");
        }
    }

    private void EnsureProviderMatches(LlmProviderDescriptor descriptor)
    {
        if (_provider.Descriptor != descriptor)
        {
            throw new InvalidOperationException(
                "Configured provider, model, protocol, endpoint, prices, or credential binding does not match the approved run specification.");
        }
    }

    private async Task<CoordinatorRoleOutput> ReadRoleOutputAsync(
        CoordinatorRunSnapshot snapshot,
        CoordinatorRole role,
        CancellationToken cancellationToken)
    {
        var reference = RequiredRoleReference(snapshot, role);
        var output = await _artifactStore.ReadJsonAsync<CoordinatorRoleOutput>(
            reference.RelativePath,
            reference.Sha256,
            cancellationToken).ConfigureAwait(false);
        try
        {
            return CoordinatorValidation.ParseRoleOutput(
                JsonSerializer.Serialize(output, CoordinatorJson.Options),
                role,
                snapshot.Spec.Sources.Select(source => source.Id).ToHashSet(StringComparer.Ordinal),
                CoordinatorRunPurpose.StrategyAuthoring);
        }
        catch (CoordinatorValidationException exception)
        {
            throw new CoordinatorIntegrityException(exception.Message);
        }
    }

    private static CoordinatorArtifactReference RequiredRoleReference(
        CoordinatorRunSnapshot snapshot,
        CoordinatorRole role)
    {
        var matches = snapshot.Artifacts.Where(reference =>
            reference.Role == role &&
            reference.SchemaVersion == CoordinatorVersions.ArtifactSchema).ToArray();
        return matches.Length == 1
            ? matches[0]
            : throw new CoordinatorIntegrityException(
                $"Repair lineage requires exactly one verified {role} role artifact.");
    }

    private static bool StrategyArtifactReproduces(
        CoordinatorRunSnapshot snapshot,
        CoordinatorStrategySourceArtifact artifact,
        CoordinatorRoleOutput synthesizer)
    {
        if (synthesizer.StrategyDraft is not { } draft)
        {
            return false;
        }

        var expected = new CoordinatorStrategySourceArtifact
        {
            SchemaVersion = CoordinatorVersions.StrategyArtifactSchema,
            RunId = snapshot.Spec.RunId,
            ObjectiveSha256 = ContentHasher.HashUtf8(snapshot.Spec.Objective),
            StrategyId = draft.StrategyId,
            DisplayName = draft.DisplayName,
            Files = draft.Files.Select(file => new CoordinatorStrategySourceFile(
                file.RelativePath,
                file.Content,
                ContentHasher.HashUtf8(file.Content))).ToArray(),
            EvidenceSourceIds = synthesizer.SourceIds.ToArray(),
            SynthesizerArtifactSha256 = RequiredRoleReference(
                snapshot,
                CoordinatorRole.Synthesizer).Sha256,
            RiskJudgeArtifactSha256 = RequiredRoleReference(
                snapshot,
                CoordinatorRole.RiskJudge).Sha256,
            DeliveryState = CoordinatorVersions.StrategyDeliveryState,
            CompilerProfile = CoordinatorVersions.StrategyCompilerProfile,
            RequiresHumanRelease = true,
            RequiresTerminalCompileConsent = true,
            InstallEligible = false,
        };
        return StringComparer.Ordinal.Equals(
            ContentHasher.HashJson(expected),
            ContentHasher.HashJson(artifact));
    }

    private static string ReadRootObjective(CoordinatorRunSnapshot snapshot)
    {
        var sources = snapshot.Spec.Sources.Where(source =>
            source.Id == FreeStrategyWorkflowSourceIds.RootObjective).ToArray();
        if (sources.Length > 1)
        {
            throw new CoordinatorIntegrityException("Repair lineage contains duplicate root-objective sources.");
        }
        return sources.Length == 1 ? sources[0].Content : snapshot.Spec.Objective;
    }

    private static FreeStrategyRepairLineage? ReadRepairLineage(CoordinatorRunSnapshot snapshot)
    {
        var sources = snapshot.Spec.Sources.Where(source =>
            source.Id == FreeStrategyWorkflowSourceIds.Lineage).ToArray();
        if (sources.Length == 0)
        {
            return null;
        }
        if (sources.Length != 1)
        {
            throw new CoordinatorIntegrityException("Repair lineage contains duplicate lineage sources.");
        }

        FreeStrategyRepairLineage lineage;
        try
        {
            lineage = JsonSerializer.Deserialize<FreeStrategyRepairLineage>(
                sources[0].Content,
                CoordinatorJson.Options)
                ?? throw new JsonException("Repair lineage must not be JSON null.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorIntegrityException(
                $"Repair lineage is invalid: {exception.Message}");
        }

        var rootObjectiveSource = RequiredRepairSource(snapshot, FreeStrategyWorkflowSourceIds.RootObjective);
        var parentDraftSource = RequiredRepairSource(snapshot, FreeStrategyWorkflowSourceIds.ParentDraft);
        var parentReviewSource = RequiredRepairSource(snapshot, FreeStrategyWorkflowSourceIds.ParentReview);
        var changeRequestSource = RequiredRepairSource(snapshot, FreeStrategyWorkflowSourceIds.ChangeRequest);
        var diagnosticsSources = snapshot.Spec.Sources.Where(source =>
            source.Id == FreeStrategyWorkflowSourceIds.Diagnostics).ToArray();
        if (diagnosticsSources.Length > 1)
        {
            throw new CoordinatorIntegrityException("Repair lineage contains duplicate diagnostics sources.");
        }

        var rootObjective = rootObjectiveSource.Content;
        if (lineage.SchemaVersion != FreeStrategyWorkflowVersions.RepairLineage ||
            lineage.RepairRound is < 1 or > FreeStrategyWorkflowVersions.MaximumRepairRounds ||
            lineage.ParentRunId == Guid.Empty ||
            !CoordinatorStrategyArtifactValidation.IsSha256(lineage.ParentSpecificationSha256) ||
            !CoordinatorStrategyArtifactValidation.IsSha256(lineage.ParentSynthesizerArtifactSha256) ||
            !CoordinatorStrategyArtifactValidation.IsSha256(lineage.ParentRiskJudgeArtifactSha256) ||
            (lineage.ParentFinalArtifactSha256 is not null &&
             !CoordinatorStrategyArtifactValidation.IsSha256(lineage.ParentFinalArtifactSha256)) ||
            lineage.ParentDecision == CoordinatorDecision.None ||
            (lineage.ParentDecision == CoordinatorDecision.Approve) !=
            (lineage.ParentFinalArtifactSha256 is not null) ||
            !StringComparer.Ordinal.Equals(
                lineage.RootObjectiveSha256,
                ContentHasher.HashUtf8(rootObjective)) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentSynthesizerArtifactSha256,
                ContentHasher.HashUtf8(parentDraftSource.Content)) ||
            !StringComparer.Ordinal.Equals(
                lineage.ParentRiskJudgeArtifactSha256,
                ContentHasher.HashUtf8(parentReviewSource.Content)) ||
            !CoordinatorStrategyArtifactValidation.IsSha256(lineage.ChangeRequestSha256) ||
            !StringComparer.Ordinal.Equals(
                lineage.ChangeRequestSha256,
                ContentHasher.HashUtf8(changeRequestSource.Content)) ||
            (lineage.DiagnosticsSha256 is not null &&
             (!CoordinatorStrategyArtifactValidation.IsSha256(lineage.DiagnosticsSha256) ||
              diagnosticsSources.Length != 1 ||
              !StringComparer.Ordinal.Equals(
                  lineage.DiagnosticsSha256,
                  ContentHasher.HashUtf8(diagnosticsSources[0].Content)))) ||
            (lineage.DiagnosticsSha256 is null && diagnosticsSources.Length != 0))
        {
            throw new CoordinatorIntegrityException("Repair lineage fields are invalid.");
        }
        return lineage;
    }

    private static string RepairObjective(int repairRound) => $"""
        Produce repair round {repairRound} for the exact parent strategy identified by source '{FreeStrategyWorkflowSourceIds.Lineage}'.
        Preserve the root objective and evidence constraints. Apply the user-approved change request and grounded diagnostics.
        Treat the parent draft as inert source, address the parent review, and emit one complete replacement strategy rather than a patch.
        """;

    private static void ValidateRepairSourceCapacity(
        IReadOnlyCollection<CoordinatorContextSource> sources)
    {
        if (sources.Count > CoordinatorValidation.MaxSourceCount ||
            sources.Any(source =>
                source.Content.Length > CoordinatorValidation.MaxSourceContentCharacters) ||
            sources.Sum(source => (long)source.Content.Length) >
            CoordinatorValidation.MaxAggregateSourceCharacters)
        {
            throw new InvalidOperationException(
                "The exact parent outputs, inherited evidence, change request, and diagnostics exceed the bounded repair-context limits. Reduce the original evidence or repair inputs; no partial lineage was created.");
        }
    }

    private static CoordinatorContextSource RequiredRepairSource(
        CoordinatorRunSnapshot snapshot,
        string sourceId)
    {
        var sources = snapshot.Spec.Sources.Where(source => source.Id == sourceId).ToArray();
        return sources.Length == 1
            ? sources[0]
            : throw new CoordinatorIntegrityException(
                $"Repair lineage requires exactly one '{sourceId}' source.");
    }

    private static void ValidateRevisionRequest(FreeStrategyWorkflowRevisionRequest request)
    {
        if (request.ParentRunId == Guid.Empty)
        {
            throw new ArgumentException("Parent run ID must not be empty.", nameof(request));
        }
        ValidateActor(request.Owner);
        if (string.IsNullOrWhiteSpace(request.ChangeRequest) ||
            request.ChangeRequest.Length > CoordinatorValidation.MaxSourceContentCharacters ||
            request.ChangeRequest.IndexOf('\0') >= 0)
        {
            throw new ArgumentException(
                $"Change request is required and must be at most {CoordinatorValidation.MaxSourceContentCharacters:N0} characters.",
                nameof(request));
        }
        if (request.Diagnostics is not null &&
            (string.IsNullOrWhiteSpace(request.Diagnostics) ||
             request.Diagnostics.Length > CoordinatorValidation.MaxSourceContentCharacters ||
             request.Diagnostics.IndexOf('\0') >= 0))
        {
            throw new ArgumentException(
                $"Diagnostics must be non-empty and at most {CoordinatorValidation.MaxSourceContentCharacters:N0} characters when supplied.",
                nameof(request));
        }
        ArgumentNullException.ThrowIfNull(request.Budget);
        CoordinatorValidation.ValidateBudget(request.Budget);
    }

    private static void ValidateActor(string actor)
    {
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 200)
        {
            throw new ArgumentException(
                "Actor is required and must be at most 200 characters.",
                nameof(actor));
        }
    }
}
