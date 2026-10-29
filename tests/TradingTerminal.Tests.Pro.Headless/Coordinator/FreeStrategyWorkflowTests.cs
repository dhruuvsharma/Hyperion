using System.Text.Json;
using FluentAssertions;
using Hyperion.FreeStrategyWorkflow;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class FreeStrategyWorkflowTests
{
    [Fact]
    public async Task Local_workflow_preserves_start_release_and_compile_consent_boundaries()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var runner = CreateRunner(workspace, provider);

        var draft = await runner.CreateAsync(Request());

        draft.Snapshot.Status.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
        draft.Snapshot.Spec.PolicyVersion.Should().Be(CoordinatorVersions.FreeStrategyPolicy);
        draft.Snapshot.Spec.WorkflowVersion.Should().Be(CoordinatorVersions.FreeStrategyWorkflow);
        draft.SpecificationSha256.Should().HaveLength(64);

        var result = await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "local-reviewer",
            draft.SpecificationSha256);

        result.Snapshot.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        result.StrategyArtifact.Should().NotBeNull();
        result.StrategyArtifact!.RequiresHumanRelease.Should().BeTrue();
        result.StrategyArtifact.RequiresTerminalCompileConsent.Should().BeTrue();
        result.StrategyArtifact.InstallEligible.Should().BeFalse();
        result.StrategyArtifact.Files.Should().ContainSingle();

        var released = await runner.ApproveReleaseAsync(
            result.Snapshot.Spec.RunId,
            "local-reviewer",
            result.Snapshot.FinalArtifactSha256!);

        released.Status.Should().Be(CoordinatorRunStatus.Completed);
    }

    [Fact]
    public async Task External_adapter_keeps_provider_endpoint_and_credentials_out_of_the_run()
    {
        using var workspace = new TestWorkspace();
        var mock = new DeterministicMockLlmProvider();
        var provider = new FreeStrategyExternalProvider(
            "terminal-provider",
            "terminal-selected-model",
            mock.CompleteAsync);
        var runner = CreateRunner(workspace, provider);

        var draft = await runner.CreateAsync(Request());
        var result = await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "terminal-user",
            draft.SpecificationSha256);

        draft.Snapshot.Spec.Provider.Protocol.Should().Be(LlmProviderProtocols.ExternalAdapter);
        draft.Snapshot.Spec.Provider.Endpoint.Should().BeNull();
        draft.Snapshot.Spec.Provider.CredentialEnvironmentVariable.Should().BeNull();
        result.Snapshot.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        result.StrategyArtifact.Should().NotBeNull();
    }

    [Fact]
    public async Task Start_resumes_an_already_approved_run_idempotently()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var store = new SqliteCoordinatorStore(workspace.PathFor("workflow.db"));
        var artifacts = new ContentAddressedArtifactStore(workspace.PathFor("artifacts"));
        var runner = new FreeStrategyWorkflowRunner(store, artifacts, provider);
        var draft = await runner.CreateAsync(Request());
        await new ResearchCoordinator(store, artifacts, provider).ApproveStartAsync(
            draft.Snapshot.Spec.RunId,
            "local-reviewer",
            draft.SpecificationSha256);

        var result = await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "local-reviewer",
            draft.SpecificationSha256);

        result.Snapshot.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        result.StrategyArtifact.Should().NotBeNull();
    }

    [Fact]
    public async Task Provider_mismatch_is_rejected_before_start_approval_is_persisted()
    {
        using var workspace = new TestWorkspace();
        var original = new DeterministicMockLlmProvider(new LlmProviderDescriptor(
            "mock-a", "deterministic-v1", LlmProviderProtocols.Mock, Endpoint: null));
        var replacement = new DeterministicMockLlmProvider(new LlmProviderDescriptor(
            "mock-b", "deterministic-v1", LlmProviderProtocols.Mock, Endpoint: null));
        var store = new SqliteCoordinatorStore(workspace.PathFor("workflow.db"));
        var artifacts = new ContentAddressedArtifactStore(workspace.PathFor("artifacts"));
        var draft = await new FreeStrategyWorkflowRunner(store, artifacts, original).CreateAsync(Request());
        var runner = new FreeStrategyWorkflowRunner(store, artifacts, replacement);

        Func<Task> start = async () => await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "local-reviewer",
            draft.SpecificationSha256);

        await start.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*does not match the approved run specification*");
        var stored = await store.GetVerifiedAsync(draft.Snapshot.Spec.RunId);
        stored.Status.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
        stored.Approvals.Should().BeEmpty();
    }

    [Fact]
    public void Hosted_strategy_profile_does_not_accept_the_local_external_adapter()
    {
        var provider = new FreeStrategyExternalProvider(
            "terminal-provider",
            "terminal-selected-model",
            (_, _) => Task.FromResult(LlmCallResult.Failed("unused", "unused")));
        var spec = new CoordinatorRunSpec(
            Guid.NewGuid(),
            "Create a bounded strategy.",
            "tester",
            DateTimeOffset.UtcNow,
            [],
            provider.Descriptor,
            FreeStrategyWorkflowDefaults.CreateBudget(),
            CoordinatorVersions.StrategyPolicy,
            CoordinatorVersions.StrategyWorkflow,
            CoordinatorPromptCatalog.StrategySha256,
            CoordinatorRunPurpose.StrategyAuthoring);

        Action validate = () => CoordinatorValidation.ValidateSpec(spec);

        validate.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*built-in policy, workflow, and provider profiles*");
    }

    [Fact]
    public async Task Free_wrapper_rejects_a_hosted_profile_from_a_shared_store()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var store = new SqliteCoordinatorStore(workspace.PathFor("workflow.db"));
        var artifacts = new ContentAddressedArtifactStore(workspace.PathFor("artifacts"));
        var hosted = new ResearchCoordinator(store, artifacts, provider);
        var hostedRun = await hosted.CreateAsync(new CoordinatorRunSpec(
            Guid.NewGuid(),
            "Create a bounded strategy.",
            "tester",
            DateTimeOffset.UtcNow,
            [],
            provider.Descriptor,
            FreeStrategyWorkflowDefaults.CreateBudget(),
            CoordinatorVersions.StrategyPolicy,
            CoordinatorVersions.StrategyWorkflow,
            CoordinatorPromptCatalog.StrategySha256,
            CoordinatorRunPurpose.StrategyAuthoring));
        var runner = new FreeStrategyWorkflowRunner(store, artifacts, provider);

        Func<Task> read = async () => await runner.GetAsync(hostedRun.Spec.RunId);

        await read.Should().ThrowAsync<CoordinatorIntegrityException>()
            .WithMessage("*exact local free strategy-workflow profile*");
    }

    [Fact]
    public async Task Missing_final_strategy_reference_fails_closed()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var spec = new CoordinatorRunSpec(
            Guid.NewGuid(),
            "Create a bounded strategy.",
            "tester",
            DateTimeOffset.UtcNow,
            [],
            provider.Descriptor,
            FreeStrategyWorkflowDefaults.CreateBudget(),
            CoordinatorVersions.FreeStrategyPolicy,
            CoordinatorVersions.FreeStrategyWorkflow,
            CoordinatorPromptCatalog.StrategySha256,
            CoordinatorRunPurpose.StrategyAuthoring);
        var snapshot = new CoordinatorRunSnapshot
        {
            Spec = spec,
            Status = CoordinatorRunStatus.AwaitingReleaseApproval,
            FinalArtifactSha256 = new string('a', 64),
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        var runner = new FreeStrategyWorkflowRunner(
            new FixedSnapshotStore(snapshot),
            new ContentAddressedArtifactStore(workspace.PathFor("artifacts")),
            provider);

        Func<Task> read = async () => await runner.GetAsync(spec.RunId);

        await read.Should().ThrowAsync<CoordinatorIntegrityException>()
            .WithMessage("*final strategy artifact reference is missing*");
    }

    [Fact]
    public async Task Distributable_manifest_is_bound_to_the_executable_profile()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "FreeStrategyWorkflow", "workflow.v1.json");
        await using var stream = File.OpenRead(path);
        using var document = await JsonDocument.ParseAsync(stream);
        var root = document.RootElement;

        root.GetProperty("schemaVersion").GetString().Should().Be(FreeStrategyWorkflowVersions.Manifest);
        root.GetProperty("policyVersion").GetString().Should().Be(CoordinatorVersions.FreeStrategyPolicy);
        root.GetProperty("workflowVersion").GetString().Should().Be(CoordinatorVersions.FreeStrategyWorkflow);
        root.GetProperty("promptCatalogSha256").GetString().Should().Be(CoordinatorPromptCatalog.StrategySha256);
        root.GetProperty("roles").EnumerateArray().Select(item => item.GetString())
            .Should().Equal(ResearchCoordinator.Workflow.Select(role => role.ToString()));
        root.GetProperty("providerProtocols").EnumerateArray().Select(item => item.GetString())
            .Should().Contain([
                LlmProviderProtocols.AnthropicMessages,
                LlmProviderProtocols.GoogleGemini,
            ]);
        root.GetProperty("gauntlet").GetProperty("schemaVersion").GetString()
            .Should().Be(FreeStrategyWorkflowVersions.GauntletReport);
        root.GetProperty("gauntlet").GetProperty("semanticCorrectnessGuaranteed")
            .GetBoolean().Should().BeFalse();
        root.GetProperty("repair").GetProperty("maximumRounds").GetInt32()
            .Should().Be(FreeStrategyWorkflowVersions.MaximumRepairRounds);
        root.GetProperty("repair").GetProperty("maximumInitialSources").GetInt32()
            .Should().Be(FreeStrategyWorkflowVersions.MaximumInitialSources);
        root.GetProperty("repair").GetProperty("createsFreshRun").GetBoolean().Should().BeTrue();
        root.GetProperty("modelTools").GetArrayLength().Should().Be(0);
        root.GetProperty("providerSecretValuesInRun").GetBoolean().Should().BeFalse();
        root.GetProperty("hostedCreditsUsed").GetBoolean().Should().BeFalse();
        root.GetProperty("output").GetProperty("installEligible").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Deterministic_gauntlet_reports_process_integrity_without_claiming_code_correctness()
    {
        using var workspace = new TestWorkspace();
        var runner = CreateRunner(workspace, new DeterministicMockLlmProvider());
        var draft = await runner.CreateAsync(Request());

        var beforeStart = await runner.InspectGauntletAsync(draft.Snapshot.Spec.RunId);
        beforeStart.ProcessIntegrityPassed.Should().BeFalse();
        beforeStart.SemanticCorrectnessGuaranteed.Should().BeFalse();

        var result = await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "local-reviewer",
            draft.SpecificationSha256);
        var report = await runner.InspectGauntletAsync(result.Snapshot.Spec.RunId);

        report.SchemaVersion.Should().Be(FreeStrategyWorkflowVersions.GauntletReport);
        report.ProcessIntegrityPassed.Should().BeTrue();
        report.ReadyForHumanReleaseReview.Should().BeTrue();
        report.SemanticCorrectnessGuaranteed.Should().BeFalse();
        report.CompilationVerification.Should().Be("not-run-by-free-workflow");
        report.FunctionalVerification.Should().Be("not-run-by-free-workflow");
        report.Checks.Should().OnlyContain(check => check.Passed);

        await runner.ApproveReleaseAsync(
            result.Snapshot.Spec.RunId,
            "local-reviewer",
            result.Snapshot.FinalArtifactSha256!);
        var releasedReport = await runner.InspectGauntletAsync(result.Snapshot.Spec.RunId);
        releasedReport.ProcessIntegrityPassed.Should().BeTrue();
        releasedReport.ReadyForHumanReleaseReview.Should().BeFalse();
        releasedReport.Checks.Single(check => check.Id == "release-approval-consistency")
            .Passed.Should().BeTrue();
    }

    [Fact]
    public async Task Repair_rounds_bind_exact_parent_outputs_and_require_fresh_approvals()
    {
        using var workspace = new TestWorkspace();
        var runner = CreateRunner(workspace, new DeterministicMockLlmProvider());
        var originalDraft = await runner.CreateAsync(Request());
        var original = await runner.StartAsync(
            originalDraft.Snapshot.Spec.RunId,
            "local-reviewer",
            originalDraft.SpecificationSha256);

        var repairOne = await runner.CreateRevisionAsync(new FreeStrategyWorkflowRevisionRequest
        {
            ParentRunId = original.Snapshot.Spec.RunId,
            Owner = "local-reviewer",
            ChangeRequest = "Replace the entry condition while preserving the hard risk limits.",
            Diagnostics = "CS0103: The name 'UnsupportedIndicator' does not exist.",
        });

        repairOne.Snapshot.Status.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
        repairOne.Snapshot.Approvals.Should().BeEmpty();
        repairOne.Snapshot.Spec.RunId.Should().NotBe(original.Snapshot.Spec.RunId);
        var lineageSource = repairOne.Snapshot.Spec.Sources.Single(source =>
            source.Id == FreeStrategyWorkflowSourceIds.Lineage);
        var lineage = JsonSerializer.Deserialize<FreeStrategyRepairLineage>(
            lineageSource.Content,
            CoordinatorJson.Options)!;
        lineage.RepairRound.Should().Be(1);
        lineage.ParentRunId.Should().Be(original.Snapshot.Spec.RunId);
        lineage.ParentSynthesizerArtifactSha256.Should().HaveLength(64);
        lineage.ParentRiskJudgeArtifactSha256.Should().HaveLength(64);
        repairOne.Snapshot.Spec.Sources.Should().Contain(source =>
            source.Id == FreeStrategyWorkflowSourceIds.ParentDraft);
        repairOne.Snapshot.Spec.Sources.Should().Contain(source =>
            source.Id == FreeStrategyWorkflowSourceIds.ParentReview);
        repairOne.Snapshot.Spec.Sources.Should().Contain(source =>
            source.Id == FreeStrategyWorkflowSourceIds.Diagnostics);

        var repairedOne = await runner.StartAsync(
            repairOne.Snapshot.Spec.RunId,
            "local-reviewer",
            repairOne.SpecificationSha256);
        var repairTwo = await runner.CreateRevisionAsync(new FreeStrategyWorkflowRevisionRequest
        {
            ParentRunId = repairedOne.Snapshot.Spec.RunId,
            Owner = "local-reviewer",
            ChangeRequest = "Resolve the remaining review finding without changing position sizing.",
        });
        var repairedTwo = await runner.StartAsync(
            repairTwo.Snapshot.Spec.RunId,
            "local-reviewer",
            repairTwo.SpecificationSha256);

        Func<Task> thirdRepair = async () => await runner.CreateRevisionAsync(
            new FreeStrategyWorkflowRevisionRequest
            {
                ParentRunId = repairedTwo.Snapshot.Spec.RunId,
                Owner = "local-reviewer",
                ChangeRequest = "Attempt an unbounded third repair.",
            });

        await thirdRepair.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*at most 2 rounds*");
    }

    [Fact]
    public async Task Initial_requests_cannot_impersonate_reserved_repair_sources()
    {
        using var workspace = new TestWorkspace();
        var runner = CreateRunner(workspace, new DeterministicMockLlmProvider());
        var request = Request() with
        {
            Sources =
            [
                new CoordinatorContextSource(
                    FreeStrategyWorkflowSourceIds.Lineage,
                    "Forged lineage",
                    "{}")
            ]
        };

        Func<Task> create = async () => await runner.CreateAsync(request);

        await create.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*reserved for repair lineage*");
    }

    [Fact]
    public async Task Initial_requests_reserve_six_source_slots_for_repair_lineage()
    {
        using var workspace = new TestWorkspace();
        var runner = CreateRunner(workspace, new DeterministicMockLlmProvider());
        var request = Request() with
        {
            Sources = Enumerable.Range(0, FreeStrategyWorkflowVersions.MaximumInitialSources + 1)
                .Select(index => new CoordinatorContextSource(
                    $"source-{index}",
                    $"Source {index}",
                    "bounded content"))
                .ToArray(),
        };

        Func<Task> create = async () => await runner.CreateAsync(request);

        await create.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*retains six reserved source slots*");
    }

    [Fact]
    public async Task Loaded_initial_runs_reject_reserved_sources_created_below_the_wrapper()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var store = workspace.CreateStore();
        var artifacts = workspace.CreateArtifactStore();
        var coordinator = new ResearchCoordinator(store, artifacts, provider);
        var spec = new CoordinatorRunSpec(
            Guid.NewGuid(),
            "Create a deterministic inert strategy.",
            "forged-caller",
            DateTimeOffset.UtcNow,
            [new CoordinatorContextSource("hyperion.repair.forged", "Forged", "forged")],
            provider.Descriptor,
            FreeStrategyWorkflowDefaults.CreateBudget(),
            CoordinatorVersions.FreeStrategyPolicy,
            CoordinatorVersions.FreeStrategyWorkflow,
            CoordinatorPromptCatalog.StrategySha256,
            CoordinatorRunPurpose.StrategyAuthoring);
        await coordinator.CreateAsync(spec);
        var runner = new FreeStrategyWorkflowRunner(store, artifacts, provider);

        Func<Task> inspect = async () => await runner.InspectGauntletAsync(spec.RunId);

        await inspect.Should().ThrowAsync<CoordinatorIntegrityException>()
            .WithMessage("*cannot contain reserved repair sources*");
    }

    [Fact]
    public async Task Loaded_repair_runs_cross_check_the_actual_parent_specification()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var store = workspace.CreateStore();
        var artifacts = workspace.CreateArtifactStore();
        var runner = new FreeStrategyWorkflowRunner(store, artifacts, provider);
        var originalDraft = await runner.CreateAsync(Request());
        var original = await runner.StartAsync(
            originalDraft.Snapshot.Spec.RunId,
            "local-reviewer",
            originalDraft.SpecificationSha256);
        var legitimateRepair = await runner.CreateRevisionAsync(new FreeStrategyWorkflowRevisionRequest
        {
            ParentRunId = original.Snapshot.Spec.RunId,
            Owner = "local-reviewer",
            ChangeRequest = "Apply the exact reviewed correction.",
        });
        var lineageSource = legitimateRepair.Snapshot.Spec.Sources.Single(source =>
            source.Id == FreeStrategyWorkflowSourceIds.Lineage);
        var lineage = JsonSerializer.Deserialize<FreeStrategyRepairLineage>(
            lineageSource.Content,
            CoordinatorJson.Options)! with
        {
            ParentSpecificationSha256 = new string('0', 64),
        };
        var forgedSources = legitimateRepair.Snapshot.Spec.Sources.Select(source =>
            source.Id == FreeStrategyWorkflowSourceIds.Lineage
                ? source with { Content = JsonSerializer.Serialize(lineage, CoordinatorJson.Options) }
                : source).ToArray();
        var forgedSpec = legitimateRepair.Snapshot.Spec with
        {
            RunId = Guid.NewGuid(),
            CreatedAtUtc = DateTimeOffset.UtcNow,
            Sources = forgedSources,
        };
        await new ResearchCoordinator(store, artifacts, provider).CreateAsync(forgedSpec);

        Func<Task> load = async () => await runner.GetAsync(forgedSpec.RunId);

        await load.Should().ThrowAsync<CoordinatorIntegrityException>()
            .WithMessage("*does not match its verified parent*");
    }

    [Fact]
    public async Task Gauntlet_fails_closed_when_any_role_artifact_is_missing()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var store = workspace.CreateStore();
        var artifacts = workspace.CreateArtifactStore();
        var runner = new FreeStrategyWorkflowRunner(store, artifacts, provider);
        var draft = await runner.CreateAsync(Request());
        var result = await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "local-reviewer",
            draft.SpecificationSha256);
        var planner = result.Snapshot.Artifacts.Single(reference =>
            reference.Role == CoordinatorRole.Planner &&
            reference.SchemaVersion == CoordinatorVersions.ArtifactSchema);
        File.Delete(Path.Combine(artifacts.RootPath, planner.RelativePath));

        Func<Task> inspect = async () => await runner.InspectGauntletAsync(result.Snapshot.Spec.RunId);

        await inspect.Should().ThrowAsync<FileNotFoundException>();
    }

    private static FreeStrategyWorkflowRunner CreateRunner(TestWorkspace workspace, ILlmProvider provider) =>
        new(
            new SqliteCoordinatorStore(workspace.PathFor("workflow.db")),
            new ContentAddressedArtifactStore(workspace.PathFor("artifacts")),
            provider);

    private static FreeStrategyWorkflowRequest Request() => new()
    {
        Objective = "Create a deterministic, inert example strategy.",
        Owner = "local-user",
        Sources = [],
    };

    private sealed class FixedSnapshotStore(CoordinatorRunSnapshot snapshot) : ICoordinatorStore
    {
        public Task InitializeAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<CoordinatorRunSnapshot> GetVerifiedAsync(
            Guid runId,
            CancellationToken cancellationToken = default) => Task.FromResult(snapshot);

        public Task<CoordinatorRunSnapshot> CreateAsync(
            CoordinatorRunSnapshot value,
            string eventType,
            object eventPayload,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<CoordinatorRunSnapshot?> GetAsync(
            Guid runId,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IReadOnlyList<CoordinatorRunSnapshot>> ListAsync(
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<CoordinatorRunSnapshot> AppendAsync(
            CoordinatorRunSnapshot value,
            long expectedVersion,
            string eventType,
            object eventPayload,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IReadOnlyList<CoordinatorEventRecord>> ReadEventsAsync(
            Guid runId,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task VerifyEventChainAsync(
            Guid runId,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
