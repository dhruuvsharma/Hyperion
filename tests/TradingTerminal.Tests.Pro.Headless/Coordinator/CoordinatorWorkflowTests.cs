using FluentAssertions;
using Microsoft.Data.Sqlite;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Security;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class CoordinatorWorkflowTests
{
    [Fact]
    public async Task Strategy_workflow_releases_only_a_hash_bound_inert_source_artifact()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var artifacts = workspace.CreateArtifactStore();
        var coordinator = CoordinatorTestData.Coordinator(
            workspace,
            provider,
            workspace.CreateStore(),
            artifacts);
        var spec = CoordinatorTestData.Spec(provider.Descriptor) with
        {
            Objective = "Create a bounded mock strategy source artifact.",
            Purpose = CoordinatorRunPurpose.StrategyAuthoring,
            PolicyVersion = CoordinatorVersions.StrategyPolicy,
            WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
            PromptCatalogSha256 = CoordinatorPromptCatalog.StrategySha256
        };

        var created = await coordinator.CreateAsync(spec);
        await coordinator.ApproveStartAsync(
            spec.RunId,
            "strategy-reviewer",
            ContentHasher.HashJson(spec));
        var awaiting = await coordinator.ResumeAsync(spec.RunId);

        awaiting.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        awaiting.CompletedRoleCount.Should().Be(5);
        awaiting.Artifacts.Should().HaveCount(6);
        var finalReference = awaiting.Artifacts.Should().ContainSingle(item =>
            item.Sha256 == awaiting.FinalArtifactSha256 &&
            item.SchemaVersion == CoordinatorVersions.StrategyArtifactSchema).Subject;
        var artifact = await artifacts.ReadJsonAsync<CoordinatorStrategySourceArtifact>(
            finalReference.RelativePath,
            finalReference.Sha256);
        CoordinatorStrategyArtifactValidation.ValidateForRun(artifact, spec, awaiting.Artifacts);
        artifact.RunId.Should().Be(spec.RunId);
        artifact.ObjectiveSha256.Should().Be(ContentHasher.HashUtf8(spec.Objective));
        artifact.Files.Should().ContainSingle();
        artifact.Files[0].ContentSha256.Should().Be(ContentHasher.HashUtf8(artifact.Files[0].Content));
        artifact.RequiresHumanRelease.Should().BeTrue();
        artifact.RequiresTerminalCompileConsent.Should().BeTrue();
        artifact.InstallEligible.Should().BeFalse();
        Action validateTamperedBinding = () => CoordinatorStrategyArtifactValidation.ValidateForRun(
            artifact with { ObjectiveSha256 = new string('a', 64) },
            spec,
            awaiting.Artifacts);
        validateTamperedBinding.Should().Throw<InvalidDataException>()
            .WithMessage("*exact run evidence*");

        var completed = await coordinator.ApproveReleaseAsync(
            spec.RunId,
            "strategy-releaser",
            finalReference.Sha256);
        completed.Status.Should().Be(CoordinatorRunStatus.Completed);
        completed.Approvals.Should().ContainSingle(item =>
            item.Gate == ApprovalGate.Release &&
            item.BoundArtifactSha256 == finalReference.Sha256);
    }

    [Theory]
    [InlineData("-strategy", "Strategy")]
    [InlineData("_strategy", "Strategy")]
    [InlineData(".strategy", "Strategy")]
    [InlineData("strategy", "Strategy\0Name")]
    public void Strategy_draft_and_artifact_validation_share_strict_identity_rules(
        string strategyId,
        string displayName)
    {
        var draft = new CoordinatorStrategyDraft
        {
            StrategyId = strategyId,
            DisplayName = displayName,
            Files = [new CoordinatorStrategyDraftFile("Strategy.cs", "public sealed class Strategy { }")]
        };

        Action validate = () => CoordinatorStrategyArtifactValidation.ValidateDraft(draft);

        validate.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void Strategy_draft_rejects_case_insensitive_duplicate_paths()
    {
        var draft = new CoordinatorStrategyDraft
        {
            StrategyId = "strategy",
            DisplayName = "Strategy",
            Files =
            [
                new CoordinatorStrategyDraftFile("Strategy.cs", "public sealed class One { }"),
                new CoordinatorStrategyDraftFile("strategy.cs", "public sealed class Two { }")
            ]
        };

        Action validate = () => CoordinatorStrategyArtifactValidation.ValidateDraft(draft);

        validate.Should().Throw<InvalidDataException>().WithMessage("*duplicate C# file*");
    }

    [Theory]
    [InlineData("CON.cs")]
    [InlineData("AUX.cs")]
    [InlineData("folder./Strategy.cs")]
    [InlineData(".hidden/Strategy.cs")]
    public void Strategy_draft_rejects_windows_device_and_normalization_aliases(string relativePath)
    {
        var draft = new CoordinatorStrategyDraft
        {
            StrategyId = "strategy",
            DisplayName = "Strategy",
            Files = [new CoordinatorStrategyDraftFile(relativePath, "public sealed class Strategy { }")]
        };

        Action validate = () => CoordinatorStrategyArtifactValidation.ValidateDraft(draft);

        validate.Should().Throw<InvalidDataException>().WithMessage("*invalid or duplicate C# file*");
    }

    [Fact]
    public void Research_contract_serialization_omits_new_default_strategy_fields()
    {
        var specJson = JsonSerializer.Serialize(
            CoordinatorTestData.Spec(CoordinatorTestData.Descriptor()),
            TradingTerminal.Ai.Coordinator.Serialization.CoordinatorJson.Options);
        var outputJson = JsonSerializer.Serialize(
            new CoordinatorRoleOutput
            {
                SchemaVersion = CoordinatorVersions.ArtifactSchema,
                Role = CoordinatorRole.Planner,
                Summary = "Legacy research-compatible role output."
            },
            TradingTerminal.Ai.Coordinator.Serialization.CoordinatorJson.Options);

        specJson.Should().NotContain("\"purpose\"");
        outputJson.Should().NotContain("\"strategyDraft\"");
        CoordinatorPromptCatalog.Sha256.Should().Be(CoordinatorVersions.ResearchPromptCatalogSha256);
    }

    [Fact]
    public async Task Strategy_workflow_rejects_unsafe_source_paths_before_release()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor(protocol: "mock");
        var provider = new ScriptedLlmProvider(descriptor, (request, _) =>
        {
            if (request.Role != CoordinatorRole.Synthesizer)
            {
                return LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request));
            }
            var output = new CoordinatorRoleOutput
            {
                SchemaVersion = CoordinatorVersions.ArtifactSchema,
                Role = request.Role,
                Summary = "Unsafe strategy draft for rejection testing.",
                StrategyDraft = new CoordinatorStrategyDraft
                {
                    StrategyId = "unsafe-strategy",
                    DisplayName = "Unsafe Strategy",
                    Files = [new CoordinatorStrategyDraftFile("../Strategy.cs", "public sealed class Unsafe { }")]
                }
            };
            return LlmCallResult.Success(new LlmCompletion(
                JsonSerializer.Serialize(output, TradingTerminal.Ai.Coordinator.Serialization.CoordinatorJson.Options),
                new LlmUsage(32, 24),
                "stop"));
        });
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var spec = CoordinatorTestData.Spec(descriptor) with
        {
            Purpose = CoordinatorRunPurpose.StrategyAuthoring,
            PolicyVersion = CoordinatorVersions.StrategyPolicy,
            WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
            PromptCatalogSha256 = CoordinatorPromptCatalog.StrategySha256
        };
        var created = await coordinator.CreateAsync(spec);
        await coordinator.ApproveStartAsync(
            spec.RunId,
            "strategy-reviewer",
            CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.Failed);
        result.CompletedRoleCount.Should().Be(3);
        result.FinalArtifactSha256.Should().BeNull();
        result.Artifacts.Should().NotContain(item =>
            item.SchemaVersion == CoordinatorVersions.StrategyArtifactSchema);
    }

    [Theory]
    [InlineData("mock", null)]
    [InlineData("openai-compatible", "http://127.0.0.1:11434/v1/")]
    public void Strategy_workflow_accepts_supported_provider_protocols(string protocol, string? endpoint)
    {
        var spec = CoordinatorTestData.Spec(CoordinatorTestData.Descriptor(protocol: protocol, endpoint: endpoint)) with
        {
            Purpose = CoordinatorRunPurpose.StrategyAuthoring,
            PolicyVersion = CoordinatorVersions.StrategyPolicy,
            WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
            PromptCatalogSha256 = CoordinatorVersions.StrategyPromptCatalogSha256
        };

        CoordinatorValidation.IsSupportedProfile(spec).Should().BeTrue();
    }

    [Fact]
    public void Strategy_workflow_rejects_unsupported_provider_protocols()
    {
        var spec = CoordinatorTestData.Spec(CoordinatorTestData.Descriptor(protocol: "test")) with
        {
            Purpose = CoordinatorRunPurpose.StrategyAuthoring,
            PolicyVersion = CoordinatorVersions.StrategyPolicy,
            WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
            PromptCatalogSha256 = CoordinatorVersions.StrategyPromptCatalogSha256
        };

        Action validate = () => CoordinatorValidation.ValidateSpec(spec);

        validate.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*built-in policy, workflow, and provider profiles*");
    }

    [Fact]
    public void Strategy_workflow_rejects_source_ids_that_cannot_enter_the_final_artifact()
    {
        var spec = CoordinatorTestData.Spec(
            CoordinatorTestData.Descriptor(protocol: "mock"),
            sources: [new CoordinatorContextSource(".hidden", "Hidden", "Evidence.")]) with
        {
            Purpose = CoordinatorRunPurpose.StrategyAuthoring,
            PolicyVersion = CoordinatorVersions.StrategyPolicy,
            WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
            PromptCatalogSha256 = CoordinatorPromptCatalog.StrategySha256
        };

        Action validate = () => CoordinatorValidation.ValidateSpec(spec);

        validate.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*artifact-safe ASCII identifier grammar*");
    }

    [Fact]
    public void Run_spec_rejects_excessive_source_count_and_aggregate_content()
    {
        var descriptor = CoordinatorTestData.Descriptor();
        var tooManySources = Enumerable.Range(0, CoordinatorValidation.MaxSourceCount + 1)
            .Select(index => new CoordinatorContextSource($"source-{index}", "Source", "Evidence."))
            .ToArray();
        var countSpec = CoordinatorTestData.Spec(descriptor, sources: tooManySources) with
        {
            PromptCatalogSha256 = CoordinatorPromptCatalog.Sha256
        };

        Action validateCount = () => CoordinatorValidation.ValidateSpec(countSpec);

        validateCount.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*source limit*");

        var largeContent = new string('x', 400_001);
        var aggregateSources = Enumerable.Range(0, 5)
            .Select(index => new CoordinatorContextSource($"source-{index}", "Source", largeContent))
            .ToArray();
        var aggregateSpec = CoordinatorTestData.Spec(descriptor, sources: aggregateSources) with
        {
            PromptCatalogSha256 = CoordinatorPromptCatalog.Sha256
        };

        Action validateAggregate = () => CoordinatorValidation.ValidateSpec(aggregateSpec);

        validateAggregate.Should().Throw<CoordinatorValidationException>()
            .WithMessage("*aggregate limit*");
    }

    [Theory]
    [InlineData("protocol")]
    [InlineData("endpoint")]
    [InlineData("input-price")]
    [InlineData("output-price")]
    public async Task Resume_rejects_any_changed_approved_provider_descriptor_before_calling_it(string changedField)
    {
        using var workspace = new TestWorkspace();
        var approvedDescriptor = new LlmProviderDescriptor(
            "same-provider",
            "same-model",
            "approved-protocol",
            "https://approved.example/v1",
            InputUsdPerMillionTokens: 1.25m,
            OutputUsdPerMillionTokens: 2.50m);
        var initialProvider = new ScriptedLlmProvider(
            approvedDescriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var store = workspace.CreateStore();
        var initialCoordinator = CoordinatorTestData.Coordinator(workspace, initialProvider, store);
        var created = await initialCoordinator.CreateAsync(CoordinatorTestData.Spec(approvedDescriptor));
        await initialCoordinator.ApproveStartAsync(
            created.Spec.RunId,
            "provider-reviewer",
            CoordinatorTestData.SpecSha256(created));
        var changedDescriptor = changedField switch
        {
            "protocol" => approvedDescriptor with { Protocol = "changed-protocol" },
            "endpoint" => approvedDescriptor with { Endpoint = "https://changed.example/v1" },
            "input-price" => approvedDescriptor with { InputUsdPerMillionTokens = 9.99m },
            "output-price" => approvedDescriptor with { OutputUsdPerMillionTokens = 9.99m },
            _ => throw new ArgumentOutOfRangeException(nameof(changedField))
        };
        var changedProvider = new ScriptedLlmProvider(
            changedDescriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var restartedCoordinator = CoordinatorTestData.Coordinator(
            workspace,
            changedProvider,
            workspace.CreateStore(),
            workspace.CreateArtifactStore());

        Func<Task> resume = () => restartedCoordinator.ResumeAsync(created.Spec.RunId);

        var failure = await resume.Should().ThrowAsync<InvalidOperationException>();
        failure.Which.Message.Should().Contain("does not match the approved run specification");
        changedProvider.CallCount.Should().Be(0);
        var persisted = await store.GetAsync(created.Spec.RunId);
        persisted!.Status.Should().Be(CoordinatorRunStatus.Ready);
        persisted.Invocations.Should().BeEmpty();
    }

    [Fact]
    public async Task Recent_started_invocation_is_not_closed_or_called_again()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var store = workspace.CreateStore();
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider, store);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(RequestTimeoutSeconds: 120)));
        var approved = await coordinator.ApproveStartAsync(
            created.Spec.RunId,
            "restart-reviewer",
            CoordinatorTestData.SpecSha256(created));
        var recent = new CoordinatorInvocation(
            Guid.NewGuid(),
            CoordinatorRole.Planner,
            1,
            DateTimeOffset.UtcNow,
            null,
            new string('b', 64),
            "Started",
            null,
            null,
            null);
        await store.AppendAsync(
            approved with
            {
                Status = CoordinatorRunStatus.Running,
                Invocations = [recent],
                Usage = approved.Usage with { Requests = 1 }
            },
            approved.Version,
            "InvocationStarted",
            new { recent.InvocationId, recent.Role });

        Func<Task> resume = () => coordinator.ResumeAsync(created.Spec.RunId);

        var failure = await resume.Should().ThrowAsync<CoordinatorInvocationStillActiveException>();
        failure.Which.Message.Should().Contain("may still be active");
        provider.CallCount.Should().Be(0);
        var persisted = await store.GetAsync(created.Spec.RunId);
        persisted!.Status.Should().Be(CoordinatorRunStatus.Running);
        persisted.Invocations.Should().ContainSingle(item => item.Status == "Started");
        (await store.ReadEventsAsync(created.Spec.RunId))
            .Should().NotContain(item => item.Type == "InvocationInterrupted");
    }

    [Fact]
    public async Task Retryable_failure_without_usage_consumes_the_admitted_prompt_and_output_budget()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (_, _) => LlmCallResult.Failed(
                LlmFailureKinds.ProviderUnavailable,
                "Temporary provider failure.",
                retryable: true));
        var store = workspace.CreateStore();
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider, store);
        var budget = new CoordinatorBudget(
            MaxRequests: 2,
            MaxAttemptsPerRole: 2,
            MaxPromptTokens: 1_000_000,
            MaxOutputTokens: 64,
            MaxOutputTokensPerRequest: 64);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(descriptor, budget));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.SafeMessage.Should().Be("Output-token limit reached.");
        result.Usage.Requests.Should().Be(1);
        result.Usage.PromptTokens.Should().BeGreaterThan(0);
        result.Usage.OutputTokens.Should().Be(64);
        result.Invocations.Should().ContainSingle();
        result.Invocations[0].Status.Should().Be("Failed");
        result.Invocations[0].Usage.Should().NotBeNull();
        result.Invocations[0].Usage!.InputTokens.Should().Be(result.Usage.PromptTokens);
        result.Invocations[0].Usage!.OutputTokens.Should().Be(64);
        provider.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task Provider_zero_usage_cannot_reduce_the_conservative_token_charge()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        LlmCompletion? providerCompletion = null;
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) =>
            {
                providerCompletion = CoordinatorTestData.ValidCompletion(request, new LlmUsage(0, 0));
                return LlmCallResult.Success(providerCompletion);
            });
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(MaxRequests: 1)));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        var invocation = result.Invocations.Should().ContainSingle().Subject;
        var localOutputEstimate = System.Text.Encoding.UTF8.GetByteCount(providerCompletion!.Text);
        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.CompletedRoleCount.Should().Be(1);
        invocation.Status.Should().Be("Completed");
        invocation.Usage.Should().NotBeNull();
        invocation.Usage!.InputTokens.Should().Be(invocation.ReservedPromptTokens).And.BeGreaterThan(0);
        invocation.Usage.OutputTokens.Should().Be(localOutputEstimate).And.BeGreaterThan(0);
        result.Usage.PromptTokens.Should().Be(invocation.ReservedPromptTokens);
        result.Usage.OutputTokens.Should().Be(localOutputEstimate);
        provider.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task Full_provider_payload_bytes_are_charged_before_an_artifact_is_committed()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(
                CoordinatorTestData.ValidCompletion(request) with { ResponseBytes = 10_001 }));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(MaxResponseBytes: 10_000)));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.Usage.ResponseBytes.Should().Be(10_001);
        result.Artifacts.Should().BeEmpty();
        result.Invocations.Should().ContainSingle(item => item.Status == "BudgetBlocked");
    }

    [Fact]
    public async Task Artifact_budget_is_checked_before_any_artifact_file_is_written()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(MaxArtifactBytes: 1)));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.SafeMessage.Should().Be("Artifact-byte limit exceeded.");
        result.Artifacts.Should().BeEmpty();
        var artifactRoot = workspace.PathFor("artifacts");
        (Directory.Exists(artifactRoot)
                ? Directory.EnumerateFiles(artifactRoot, "*", SearchOption.AllDirectories)
                : [])
            .Should().BeEmpty();
    }

    [Fact]
    public async Task Conservative_local_output_over_the_per_request_max_fails_closed()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var response = new string('\u20ac', 22);
        System.Text.Encoding.UTF8.GetByteCount(response).Should().Be(66);
        var provider = new ScriptedLlmProvider(
            descriptor,
            (_, _) => LlmCallResult.Success(new LlmCompletion(
                response,
                new LlmUsage(1, 1),
                "stop")));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(
                MaxOutputTokens: 10_000,
                MaxOutputTokensPerRequest: 64)));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.SafeMessage.Should().Be("Response exceeded the conservative per-request output-token limit.");
        result.CompletedRoleCount.Should().Be(0);
        result.Artifacts.Should().BeEmpty();
        result.Usage.OutputTokens.Should().Be(66);
        result.Invocations.Should().ContainSingle(item =>
            item.Status == "BudgetBlocked" &&
            item.Usage != null &&
            item.Usage.OutputTokens == 66);
        provider.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task Caller_cancellation_during_provider_call_is_persisted_without_an_artifact_and_propagates()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new BlockingLlmProvider(descriptor);
        var store = workspace.CreateStore();
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider, store);
        var budget = new CoordinatorBudget(
            MaxOutputTokens: 500,
            MaxOutputTokensPerRequest: 123);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(descriptor, budget));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "cancellation-tester", CoordinatorTestData.SpecSha256(created));
        using var cancellation = new CancellationTokenSource();

        var resume = coordinator.ResumeAsync(created.Spec.RunId, cancellation.Token);
        await provider.Started.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();

        Func<Task> awaitResume = async () => await resume;
        await awaitResume.Should().ThrowAsync<OperationCanceledException>();
        var persisted = await store.GetAsync(created.Spec.RunId);
        persisted.Should().NotBeNull();
        persisted!.Status.Should().Be(CoordinatorRunStatus.Cancelled);
        persisted.CompletedRoleCount.Should().Be(0);
        persisted.Artifacts.Should().BeEmpty();
        var invocation = persisted.Invocations.Should().ContainSingle(item =>
            item.Role == CoordinatorRole.Planner &&
            item.Status == "Cancelled" &&
            item.ArtifactSha256 == null).Subject;
        invocation.ReservedPromptTokens.Should().BeGreaterThan(0);
        invocation.ReservedOutputTokens.Should().Be(123);
        invocation.Usage.Should().Be(new LlmUsage(
            invocation.ReservedPromptTokens,
            invocation.ReservedOutputTokens));
        persisted.Usage.Requests.Should().Be(1);
        persisted.Usage.PromptTokens.Should().Be(invocation.ReservedPromptTokens);
        persisted.Usage.OutputTokens.Should().Be(invocation.ReservedOutputTokens);
        persisted.Usage.ResponseBytes.Should().Be(invocation.ReservedResponseBytes);
        await store.VerifyEventChainAsync(created.Spec.RunId);
        (await store.ReadEventsAsync(created.Spec.RunId)).Should().Contain(item => item.Type == "InvocationCancelled");
    }

    [Fact]
    public async Task Process_interruption_leaves_the_active_invocation_recoverable()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new BlockingLlmProvider(descriptor);
        var store = workspace.CreateStore();
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider, store);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(descriptor));
        await coordinator.ApproveStartAsync(
            created.Spec.RunId,
            "recovery-tester",
            CoordinatorTestData.SpecSha256(created));
        using var interruption = new CancellationTokenSource();

        var resume = coordinator.ResumeAsync(
            created.Spec.RunId,
            recordCancellation: false,
            interruption.Token);
        await provider.Started.WaitAsync(TimeSpan.FromSeconds(5));
        interruption.Cancel();

        Func<Task> awaitResume = async () => await resume;
        await awaitResume.Should().ThrowAsync<OperationCanceledException>();
        var persisted = await store.GetAsync(created.Spec.RunId);
        persisted.Should().NotBeNull();
        persisted!.Status.Should().Be(CoordinatorRunStatus.Running);
        persisted.Invocations.Should().ContainSingle(item => item.Status == "Started");
        (await store.ReadEventsAsync(created.Spec.RunId)).Should().NotContain(
            item => item.Type == "InvocationCancelled");
    }

    [Fact]
    public async Task Event_verification_detects_direct_snapshot_projection_tampering()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var store = workspace.CreateStore();
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider, store);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(descriptor));
        await store.VerifyEventChainAsync(created.Spec.RunId);
        var tamperedJson = JsonSerializer.Serialize(
            created with { Status = CoordinatorRunStatus.Failed, SafeMessage = "tampered" },
            TradingTerminal.Ai.Coordinator.Serialization.CoordinatorJson.Options);

        await using (var connection = new SqliteConnection($"Data Source={store.DatabasePath}"))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE coordinator_runs SET snapshot_json = $snapshot WHERE run_id = $runId;";
            command.Parameters.AddWithValue("$snapshot", tamperedJson);
            command.Parameters.AddWithValue("$runId", created.Spec.RunId.ToString("D"));
            (await command.ExecuteNonQueryAsync()).Should().Be(1);
        }

        Func<Task> verify = () => store.VerifyEventChainAsync(created.Spec.RunId);

        var failure = await verify.Should().ThrowAsync<CoordinatorIntegrityException>();
        failure.Which.Message.Should().Contain("projection does not match the latest audit event");
    }

    [Fact]
    public async Task Resume_cannot_invoke_a_model_before_start_approval()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(descriptor));

        Func<Task> wrongApproval = () => coordinator.ApproveStartAsync(
            created.Spec.RunId,
            "unbound-reviewer",
            new string('0', 64));
        (await wrongApproval.Should().ThrowAsync<InvalidOperationException>()).Which.Message
            .Should().Contain("exact reviewed run-specification");

        Func<Task> resume = () => coordinator.ResumeAsync(created.Spec.RunId);

        var failure = await resume.Should().ThrowAsync<InvalidOperationException>();
        failure.Which.Message.Should().Contain("start approval");
        provider.CallCount.Should().Be(0);

        var persisted = await workspace.CreateStore().GetAsync(created.Spec.RunId);
        persisted.Should().NotBeNull();
        persisted!.Status.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
        persisted.Invocations.Should().BeEmpty();
    }

    [Fact]
    public async Task Mock_run_reaches_release_gate_and_release_binds_the_exact_artifact_hash()
    {
        using var workspace = new TestWorkspace();
        var provider = new DeterministicMockLlmProvider();
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(provider.Descriptor));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "human-reviewer", CoordinatorTestData.SpecSha256(created));

        var awaitingRelease = await coordinator.ResumeAsync(created.Spec.RunId);

        awaitingRelease.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        awaitingRelease.CompletedRoleCount.Should().Be(ResearchCoordinator.Workflow.Count);
        awaitingRelease.Artifacts.Should().HaveCount(ResearchCoordinator.Workflow.Count);
        awaitingRelease.FinalArtifactSha256.Should().NotBeNullOrWhiteSpace();
        awaitingRelease.Artifacts.Single(item => item.Role == CoordinatorRole.Synthesizer).Sha256
            .Should().Be(awaitingRelease.FinalArtifactSha256);

        var wrongHash = new string('0', 64);
        Func<Task> wrongApproval = () => coordinator.ApproveReleaseAsync(
            created.Spec.RunId,
            "human-reviewer",
            wrongHash);
        (await wrongApproval.Should().ThrowAsync<InvalidOperationException>()).Which.Message
            .Should().Contain("exact final artifact");

        var released = await coordinator.ApproveReleaseAsync(
            created.Spec.RunId,
            "human-reviewer",
            awaitingRelease.FinalArtifactSha256!);

        released.Status.Should().Be(CoordinatorRunStatus.Completed);
        released.Approvals.Should().ContainSingle(item =>
            item.Gate == ApprovalGate.Release &&
            item.BoundArtifactSha256 == awaitingRelease.FinalArtifactSha256);
    }

    [Fact]
    public async Task Restart_closes_an_interrupted_invocation_resumes_and_preserves_the_event_chain()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var firstStore = workspace.CreateStore();
        var firstCoordinator = CoordinatorTestData.Coordinator(workspace, new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request))), firstStore);
        var created = await firstCoordinator.CreateAsync(CoordinatorTestData.Spec(descriptor));
        var approved = await firstCoordinator.ApproveStartAsync(
            created.Spec.RunId,
            "restart-tester",
            CoordinatorTestData.SpecSha256(created));

        var interrupted = new CoordinatorInvocation(
            Guid.NewGuid(),
            CoordinatorRole.Planner,
            1,
            DateTimeOffset.UtcNow - TimeSpan.FromSeconds(approved.Spec.Budget.RequestTimeoutSeconds + 31),
            null,
            new string('a', 64),
            "Started",
            null,
            null,
            null);
        await firstStore.AppendAsync(
            approved with
            {
                Status = CoordinatorRunStatus.Running,
                Invocations = [interrupted],
                Usage = approved.Usage with { Requests = 1 }
            },
            approved.Version,
            "InvocationStarted",
            new { interrupted.InvocationId, interrupted.Role });

        var restartedStore = workspace.CreateStore();
        var restartedProvider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var restarted = CoordinatorTestData.Coordinator(
            workspace,
            restartedProvider,
            restartedStore,
            workspace.CreateArtifactStore());

        var result = await restarted.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        result.Invocations.Where(item => item.Role == CoordinatorRole.Planner)
            .Select(item => item.Status)
            .Should().Equal("Interrupted", "Completed");
        result.Usage.Requests.Should().Be(ResearchCoordinator.Workflow.Count + 1);

        await restartedStore.VerifyEventChainAsync(created.Spec.RunId);
        var events = await restartedStore.ReadEventsAsync(created.Spec.RunId);
        events.Select(item => item.Sequence)
            .Should().Equal(Enumerable.Range(1, events.Count).Select(index => (long)index));
        events[0].PreviousSha256.Should().BeEmpty();
        for (var index = 1; index < events.Count; index++)
            events[index].PreviousSha256.Should().Be(events[index - 1].Sha256);
        events.Should().Contain(item => item.Type == "InvocationInterrupted");
    }

    [Fact]
    public async Task Request_budget_stops_the_workflow_before_an_extra_provider_call()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request)));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var spec = CoordinatorTestData.Spec(descriptor, new CoordinatorBudget(MaxRequests: 1));
        var created = await coordinator.CreateAsync(spec);
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.CompletedRoleCount.Should().Be(1);
        result.SafeMessage.Should().Be("Request limit reached.");
        provider.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task Missing_provider_usage_fails_closed_without_committing_an_artifact()
    {
        using var workspace = new TestWorkspace();
        var descriptor = CoordinatorTestData.Descriptor();
        var provider = new ScriptedLlmProvider(
            descriptor,
            (request, _) => LlmCallResult.Success(CoordinatorTestData.ValidCompletion(request, usage: null) with
            {
                Usage = null
            }));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(RequireReportedUsage: true)));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "budget-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.BudgetExhausted);
        result.CompletedRoleCount.Should().Be(0);
        result.Artifacts.Should().BeEmpty();
        result.Invocations.Should().ContainSingle(item => item.Status == "BudgetBlocked");
        result.SafeMessage.Should().Contain("did not report token usage");
        provider.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task Executable_looking_invalid_output_remains_inert_and_is_never_written_as_an_artifact()
    {
        using var workspace = new TestWorkspace();
        var markerPath = workspace.PathFor("must-not-exist.txt");
        var descriptor = CoordinatorTestData.Descriptor();
        var maliciousText = $$"""
            ```csharp
            File.WriteAllText(@"{{markerPath}}", "executed");
            Process.Start("cmd.exe", "/c echo unsafe");
            ```
            """;
        var provider = new ScriptedLlmProvider(
            descriptor,
            (_, _) => LlmCallResult.Success(new LlmCompletion(
                maliciousText,
                new LlmUsage(16, 16),
                "stop")));
        var coordinator = CoordinatorTestData.Coordinator(workspace, provider);
        var created = await coordinator.CreateAsync(CoordinatorTestData.Spec(
            descriptor,
            new CoordinatorBudget(MaxAttemptsPerRole: 2)));
        await coordinator.ApproveStartAsync(created.Spec.RunId, "safety-reviewer", CoordinatorTestData.SpecSha256(created));

        var result = await coordinator.ResumeAsync(created.Spec.RunId);

        result.Status.Should().Be(CoordinatorRunStatus.Failed);
        result.CompletedRoleCount.Should().Be(0);
        result.Artifacts.Should().BeEmpty();
        provider.CallCount.Should().Be(2);
        File.Exists(markerPath).Should().BeFalse();
        var artifactRoot = workspace.PathFor("artifacts");
        (Directory.Exists(artifactRoot)
                ? Directory.EnumerateFiles(artifactRoot, "*", SearchOption.AllDirectories)
                : [])
            .Should().BeEmpty();
    }
}
