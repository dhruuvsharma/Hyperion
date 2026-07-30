using System.IO;
using System.Net.Http;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.App.Authoring;
using TradingTerminal.Core.Strategies.Authoring;
using TradingTerminal.Infrastructure.Backtest;
using Xunit;

namespace TradingTerminal.Tests.Authoring;

public sealed class HostedStrategyAuthoringTests
{
    [Theory]
    [InlineData("mock")]
    [InlineData("openai-compatible")]
    public async Task Exact_preview_and_release_are_required_before_source_import_without_compile(
        string protocol)
    {
        var runId = Guid.NewGuid();
        const string objective = "Build a bounded BTC strategy with explicit risk limits.";
        var specification = CreateSpecification(runId, objective, protocol);
        var riskReview = CreateRiskReview();
        var riskReviewSha256 = ContentHasher.HashJson(riskReview);
        var artifact = CreateArtifact(runId, objective, riskReviewSha256);
        var artifactSha256 = ContentHasher.HashJson(artifact);
        var awaitingRelease = CreateStatus(
            runId,
            specification.SpecSha256,
            CoordinatorRunStatus.AwaitingReleaseApproval,
            artifactSha256);
        var completed = CreateStatus(
            runId,
            specification.SpecSha256,
            CoordinatorRunStatus.Completed,
            artifactSha256);
        var api = Substitute.For<IVibeQuantApiClient>();
        api.GetCreditsAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(
            new VibeQuantCreditBalanceResponse(5_000, 0, 0, "pricing-v1", DateTimeOffset.UtcNow)));
        api.CreateRunAsync(
                Arg.Any<CreateVibeQuantRunRequest>(),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(specification));
        api.StartAsync(runId, specification.SpecSha256, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(CreateStatus(
                runId,
                specification.SpecSha256,
                CoordinatorRunStatus.Running)));
        api.GetStatusAsync(runId, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(awaitingRelease));
        api.GetArtifactAsync(runId, artifactSha256, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new VibeQuantArtifactResponse(
                runId,
                artifactSha256,
                CoordinatorRole.Synthesizer,
                null,
                artifact)));
        api.GetArtifactAsync(runId, riskReviewSha256, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new VibeQuantArtifactResponse(
                runId,
                riskReviewSha256,
                CoordinatorRole.RiskJudge,
                riskReview)));
        api.ReleaseAsync(runId, artifactSha256, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(completed));

        var compiler = Substitute.For<IStrategyCompiler>();
        var workspace = CreateWorkspace(compiler);
        var viewModel = CreateViewModel(api, workspace);
        viewModel.Objective = objective;
        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);

            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
            workspace.StrategyId.Should().NotBe(artifact.StrategyId);
            compiler.DidNotReceive().Compile(Arg.Any<StrategyScript>());

            await viewModel.StartCommand.ExecuteAsync(null);

            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
            viewModel.RunReservedCredits.Should().Be(0);
            viewModel.RunChargedCredits.Should().Be(500);
            viewModel.PreviewedArtifactSha256.Should().Be(artifactSha256);
            viewModel.Files.Should().ContainSingle();
            viewModel.RiskReviewSummary.Should().Be(riskReview.Summary);
            viewModel.ReleaseConfirmed.Should().BeFalse();
            workspace.StrategyId.Should().NotBe(artifact.StrategyId);
            compiler.DidNotReceive().Compile(Arg.Any<StrategyScript>());

            await viewModel.ReleaseCommand.ExecuteAsync(null);

            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.Completed);
            viewModel.ReleaseConfirmed.Should().BeTrue();
            workspace.StrategyId.Should().NotBe(artifact.StrategyId);
            compiler.DidNotReceive().Compile(Arg.Any<StrategyScript>());

            workspace.IsGenerating = true;
            viewModel.ImportCommand.CanExecute(null).Should().BeFalse();
            workspace.IsGenerating = false;
            viewModel.ImportCommand.CanExecute(null).Should().BeTrue();
            viewModel.ImportCommand.Execute(null);

            workspace.StrategyId.Should().Be(artifact.StrategyId);
            workspace.DisplayName.Should().Be(artifact.DisplayName);
            workspace.Files.Should().ContainSingle(file =>
                file.Name == artifact.Files[0].RelativePath &&
                file.Content == artifact.Files[0].Content);
            compiler.DidNotReceive().Compile(Arg.Any<StrategyScript>());
            await api.Received(1).ReleaseAsync(runId, artifactSha256, Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
            AuthoringSessionStore.Delete(artifact.StrategyId);
        }
    }

    [Fact]
    public async Task Objective_mismatch_keeps_release_and_import_locked()
    {
        var runId = Guid.NewGuid();
        const string objective = "Build a bounded ES strategy.";
        var specification = CreateSpecification(runId, objective);
        var artifact = CreateArtifact(
            runId,
            "A different objective.",
            ContentHasher.HashJson(CreateRiskReview()));
        var artifactSha256 = ContentHasher.HashJson(artifact);
        var awaitingRelease = CreateStatus(
            runId,
            specification.SpecSha256,
            CoordinatorRunStatus.AwaitingReleaseApproval,
            artifactSha256);
        var api = Substitute.For<IVibeQuantApiClient>();
        api.GetCreditsAsync(Arg.Any<CancellationToken>()).Returns(Task.FromResult(
            new VibeQuantCreditBalanceResponse(5_000, 0, 0, "pricing-v1", DateTimeOffset.UtcNow)));
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(specification));
        api.StartAsync(runId, specification.SpecSha256, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(awaitingRelease));
        api.GetStatusAsync(runId, Arg.Any<CancellationToken>()).Returns(Task.FromResult(awaitingRelease));
        api.GetArtifactAsync(runId, artifactSha256, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new VibeQuantArtifactResponse(
                runId,
                artifactSha256,
                CoordinatorRole.Synthesizer,
                null,
                artifact)));
        var workspace = CreateWorkspace(Substitute.For<IStrategyCompiler>());
        var viewModel = CreateViewModel(api, workspace);
        viewModel.Objective = objective;
        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);
            await viewModel.StartCommand.ExecuteAsync(null);

            viewModel.PreviewedArtifactSha256.Should().BeNull();
            viewModel.Message.Should().Contain("not bound");
            viewModel.ReleaseCommand.CanExecute(null).Should().BeFalse();
            viewModel.ImportCommand.CanExecute(null).Should().BeFalse();
            await api.DidNotReceive().ReleaseAsync(
                Arg.Any<Guid>(),
                Arg.Any<string>(),
                Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Malformed_hash_bound_risk_review_clears_preview_and_keeps_release_locked()
    {
        var runId = Guid.NewGuid();
        const string objective = "Build a bounded mock strategy.";
        var specification = CreateSpecification(runId, objective);
        var malformedRisk = CreateRiskReview() with { Risks = null! };
        var riskSha256 = ContentHasher.HashJson(malformedRisk);
        var artifact = CreateArtifact(runId, objective, riskSha256);
        var artifactSha256 = ContentHasher.HashJson(artifact);
        var awaiting = CreateStatus(
            runId,
            specification.SpecSha256,
            CoordinatorRunStatus.AwaitingReleaseApproval,
            artifactSha256);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(specification);
        api.StartAsync(runId, specification.SpecSha256, Arg.Any<CancellationToken>()).Returns(awaiting);
        api.GetStatusAsync(runId, Arg.Any<CancellationToken>()).Returns(awaiting);
        api.GetArtifactAsync(runId, artifactSha256, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, artifactSha256, CoordinatorRole.Synthesizer, null, artifact));
        api.GetArtifactAsync(runId, riskSha256, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, riskSha256, CoordinatorRole.RiskJudge, malformedRisk));
        var workspace = CreateWorkspace(Substitute.For<IStrategyCompiler>());
        var viewModel = CreateViewModel(api, workspace);
        viewModel.Objective = objective;

        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);
            await viewModel.StartCommand.ExecuteAsync(null);

            viewModel.PreviewedArtifactSha256.Should().BeNull();
            viewModel.Files.Should().BeEmpty();
            viewModel.ReleaseConfirmed.Should().BeFalse();
            viewModel.ReleaseCommand.CanExecute(null).Should().BeFalse();
            viewModel.Message.Should().Contain("semantic validation");
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Release_receipt_is_revoked_when_a_later_status_swaps_the_final_hash()
    {
        var runId = Guid.NewGuid();
        const string objective = "Build a bounded mock strategy.";
        var specification = CreateSpecification(runId, objective);
        var risk = CreateRiskReview();
        var riskSha256 = ContentHasher.HashJson(risk);
        var artifactA = CreateArtifact(runId, objective, riskSha256, displayName: "Artifact A");
        var artifactB = CreateArtifact(runId, objective, riskSha256, displayName: "Artifact B");
        var hashA = ContentHasher.HashJson(artifactA);
        var hashB = ContentHasher.HashJson(artifactB);
        var awaitingA = CreateStatus(runId, specification.SpecSha256,
            CoordinatorRunStatus.AwaitingReleaseApproval, hashA);
        var completedA = CreateStatus(runId, specification.SpecSha256,
            CoordinatorRunStatus.Completed, hashA);
        var completedB = CreateStatus(runId, specification.SpecSha256,
            CoordinatorRunStatus.Completed, hashB);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(specification);
        api.StartAsync(runId, specification.SpecSha256, Arg.Any<CancellationToken>()).Returns(
            CreateStatus(runId, specification.SpecSha256, CoordinatorRunStatus.Running));
        api.GetStatusAsync(runId, Arg.Any<CancellationToken>()).Returns(
            awaitingA,
            awaitingA,
            awaitingA,
            completedB);
        api.GetArtifactAsync(runId, hashA, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, hashA, CoordinatorRole.Synthesizer, null, artifactA));
        api.GetArtifactAsync(runId, hashB, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, hashB, CoordinatorRole.Synthesizer, null, artifactB));
        api.GetArtifactAsync(runId, riskSha256, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, riskSha256, CoordinatorRole.RiskJudge, risk));
        api.ReleaseAsync(runId, hashA, Arg.Any<CancellationToken>()).Returns(completedA);
        var workspace = CreateWorkspace(Substitute.For<IStrategyCompiler>());
        var viewModel = CreateViewModel(api, workspace);
        viewModel.Objective = objective;

        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);
            await viewModel.StartCommand.ExecuteAsync(null);
            await viewModel.ReleaseCommand.ExecuteAsync(null);
            viewModel.ReleaseConfirmed.Should().BeTrue();

            await viewModel.RefreshStatusCommand.ExecuteAsync(null);

            viewModel.PreviewedArtifactSha256.Should().Be(hashB);
            viewModel.ReleaseConfirmed.Should().BeFalse();
            viewModel.ImportCommand.CanExecute(null).Should().BeFalse();
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Bookmarked_release_review_resumes_without_starting_or_charging_again()
    {
        var runId = Guid.NewGuid();
        const string objective = "Resume this exact mock strategy review.";
        var specification = CreateSpecification(runId, objective);
        var risk = CreateRiskReview();
        var riskSha256 = ContentHasher.HashJson(risk);
        var artifact = CreateArtifact(runId, objective, riskSha256);
        var artifactSha256 = ContentHasher.HashJson(artifact);
        var awaiting = CreateStatus(runId, specification.SpecSha256,
            CoordinatorRunStatus.AwaitingReleaseApproval, artifactSha256);
        var completed = CreateStatus(runId, specification.SpecSha256,
            CoordinatorRunStatus.Completed, artifactSha256);
        var bookmark = new HostedStrategyRunBookmark(
            HostedStrategyRunBookmark.CurrentSchemaVersion,
            ConnectionBinding,
            objective,
            "terminal-strategy-resume",
            runId,
            specification.SpecSha256,
            DateTimeOffset.UtcNow);
        var bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
        bookmarkStore.Read().Returns(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid,
            bookmark));
        bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.GetCreditsAsync(Arg.Any<CancellationToken>()).Returns(
            Task.FromException<VibeQuantCreditBalanceResponse>(
                new HttpRequestException("Wallet telemetry unavailable.")));
        api.GetSpecificationAsync(runId, Arg.Any<CancellationToken>()).Returns(specification);
        api.GetStatusAsync(runId, Arg.Any<CancellationToken>()).Returns(awaiting);
        api.GetArtifactAsync(runId, artifactSha256, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, artifactSha256, CoordinatorRole.Synthesizer, null, artifact));
        api.GetArtifactAsync(runId, riskSha256, Arg.Any<CancellationToken>()).Returns(
            new VibeQuantArtifactResponse(runId, riskSha256, CoordinatorRole.RiskJudge, risk));
        api.ReleaseAsync(runId, artifactSha256, Arg.Any<CancellationToken>()).Returns(completed);
        var workspace = CreateWorkspace(Substitute.For<IStrategyCompiler>());
        var viewModel = CreateViewModel(api, workspace, bookmarkStore);

        try
        {
            await viewModel.InitializeCommand.ExecuteAsync(null);

            viewModel.Objective.Should().Be(objective);
            viewModel.RunId.Should().Be(runId);
            viewModel.PreviewedArtifactSha256.Should().Be(artifactSha256);
            viewModel.ReleaseConfirmed.Should().BeFalse();
            viewModel.SpecificationDetails.Should().Contain(specification.SpecSha256);
            await api.DidNotReceive().StartAsync(
                Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<CancellationToken>());

            await viewModel.ReleaseCommand.ExecuteAsync(null);
            viewModel.ReleaseConfirmed.Should().BeTrue();
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Unreadable_bookmark_blocks_new_runs_until_two_step_discard()
    {
        var invalid = new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.InvalidOrUnreadable);
        var missing = new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Missing);
        var bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
        bookmarkStore.Read().Returns(invalid, missing);
        bookmarkStore.TryCreate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        bookmarkStore.TryClear(Arg.Any<HostedStrategyRunBookmarkReadResult>()).Returns(true);
        var api = Substitute.For<IVibeQuantApiClient>();
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()),
            bookmarkStore);
        viewModel.Objective = "Do not submit while recovery is ambiguous.";

        try
        {
            await viewModel.InitializeCommand.ExecuteAsync(null);
            viewModel.SubmitCommand.CanExecute(null).Should().BeFalse();
            viewModel.Message.Should().Contain("unreadable");

            viewModel.DiscardRecoveryCommand.Execute(null);
            viewModel.SubmitCommand.CanExecute(null).Should().BeFalse();
            viewModel.Message.Should().Contain("can orphan");
            viewModel.DiscardRecoveryCommand.CanExecute(null).Should().BeFalse();

            viewModel.RecoveryDiscardConfirmation = "DISCARD";
            viewModel.DiscardRecoveryCommand.CanExecute(null).Should().BeTrue();
            viewModel.DiscardRecoveryCommand.Execute(null);
            viewModel.SubmitCommand.CanExecute(null).Should().BeTrue();
            bookmarkStore.Received(1).TryClear(Arg.Any<HostedStrategyRunBookmarkReadResult>());
            await api.DidNotReceive().CreateRunAsync(
                Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Pre_response_bookmark_replays_the_exact_quote_without_starting_or_charging()
    {
        var runId = Guid.NewGuid();
        const string objective = "Recover the quote after a pre-response crash.";
        const string idempotencyKey = "terminal-strategy-pre-response";
        var specification = CreateSpecification(runId, objective);
        var bookmark = new HostedStrategyRunBookmark(
            HostedStrategyRunBookmark.CurrentSchemaVersion,
            ConnectionBinding,
            objective,
            idempotencyKey,
            null,
            null,
            DateTimeOffset.UtcNow);
        var bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
        bookmarkStore.Read().Returns(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid,
            bookmark));
        bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(
                Arg.Is<CreateVibeQuantRunRequest>(request =>
                    request.Objective == objective &&
                    request.Purpose == CoordinatorRunPurpose.StrategyAuthoring),
                idempotencyKey,
                Arg.Any<CancellationToken>())
            .Returns(specification);
        api.GetStatusAsync(runId, Arg.Any<CancellationToken>()).Returns(
            CreateStatus(runId, specification.SpecSha256, CoordinatorRunStatus.AwaitingStartApproval));
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()),
            bookmarkStore);

        try
        {
            await viewModel.InitializeCommand.ExecuteAsync(null);

            viewModel.Objective.Should().Be(objective);
            viewModel.RunId.Should().Be(runId);
            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
            viewModel.StartCommand.CanExecute(null).Should().BeTrue();
            await api.Received(1).CreateRunAsync(
                Arg.Any<CreateVibeQuantRunRequest>(),
                idempotencyKey,
                Arg.Any<CancellationToken>());
            bookmarkStore.Received(1).TryUpdate(Arg.Is<HostedStrategyRunBookmark>(saved =>
                saved.RunId == runId && saved.SpecSha256 == specification.SpecSha256));
            await api.DidNotReceive().StartAsync(
                Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Pre_response_replay_stays_uncharged_when_the_bookmark_CAS_upgrade_is_lost()
    {
        var runId = Guid.NewGuid();
        const string objective = "Fail closed when another process owns recovery.";
        var specification = CreateSpecification(runId, objective);
        var bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
        bookmarkStore.Read().Returns(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid,
            new HostedStrategyRunBookmark(
                HostedStrategyRunBookmark.CurrentSchemaVersion,
                ConnectionBinding,
                objective,
                "terminal-strategy-cas-conflict",
                null,
                null,
                DateTimeOffset.UtcNow)));
        bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(false);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(specification);
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()),
            bookmarkStore);

        try
        {
            await viewModel.InitializeCommand.ExecuteAsync(null);

            viewModel.Message.Should().Contain("persist the hosted-run recovery bookmark");
            viewModel.StartCommand.CanExecute(null).Should().BeFalse();
            await api.DidNotReceive().GetStatusAsync(
                Arg.Any<Guid>(), Arg.Any<CancellationToken>());
            await api.DidNotReceive().StartAsync(
                Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Active_bookmark_from_another_connection_requires_typed_CAS_discard_without_replay()
    {
        var foreignRunId = Guid.NewGuid();
        var foreign = new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid,
            new HostedStrategyRunBookmark(
                HostedStrategyRunBookmark.CurrentSchemaVersion,
                new string('d', 64),
                "Private objective that must not cross servers.",
                "terminal-strategy-bound",
                foreignRunId,
                new string('e', 64),
                DateTimeOffset.UtcNow));
        var missing = new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Missing);
        var bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
        bookmarkStore.Read().Returns(foreign, missing);
        bookmarkStore.TryCreate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        bookmarkStore.TryClear(foreign).Returns(true);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()),
            bookmarkStore);

        try
        {
            await viewModel.InitializeCommand.ExecuteAsync(null);

            viewModel.RunId.Should().BeNull();
            viewModel.Objective.Should().BeEmpty();
            viewModel.Message.Should().Contain("different loopback connection");
            viewModel.DiscardRecoveryCommand.CanExecute(null).Should().BeTrue();

            viewModel.DiscardRecoveryCommand.Execute(null);
            viewModel.Message.Should().Contain(foreignRunId.ToString("D"));
            viewModel.Message.Should().Contain("does not cancel");
            viewModel.DiscardRecoveryCommand.CanExecute(null).Should().BeFalse();

            viewModel.RecoveryDiscardConfirmation = "DISCARD";
            viewModel.DiscardRecoveryCommand.CanExecute(null).Should().BeTrue();
            viewModel.DiscardRecoveryCommand.Execute(null);

            bookmarkStore.Received(1).TryClear(foreign);
            viewModel.Objective = "A new local mock objective.";
            viewModel.SubmitCommand.CanExecute(null).Should().BeTrue();
            await api.DidNotReceive().CreateRunAsync(
                Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
            await api.DidNotReceive().GetSpecificationAsync(
                Arg.Any<Guid>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Status_above_the_approved_credit_maximum_is_rejected_before_state_changes()
    {
        var runId = Guid.NewGuid();
        const string objective = "Bound the mock run charge.";
        var specification = CreateSpecification(runId, objective);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(specification);
        api.StartAsync(runId, specification.SpecSha256, Arg.Any<CancellationToken>()).Returns(
            CreateStatus(runId, specification.SpecSha256, CoordinatorRunStatus.Running) with
            {
                ReservedCredits = specification.Spec.MaximumCreditCharge + 1,
            });
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()));
        viewModel.Objective = objective;

        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);
            await viewModel.StartCommand.ExecuteAsync(null);

            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.AwaitingStartApproval);
            viewModel.RunReservedCredits.Should().Be(0);
            viewModel.Message.Should().Contain("approved charge");
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Start_never_reserves_credits_after_the_exact_recovery_bookmark_is_lost()
    {
        var runId = Guid.NewGuid();
        const string objective = "Keep recovery bound before charging.";
        var specification = CreateSpecification(runId, objective);
        var store = Substitute.For<IHostedStrategyRunBookmarkStore>();
        store.Read().Returns(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Missing));
        store.TryCreate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        store.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true, false);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(specification);
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()),
            store);
        viewModel.Objective = objective;

        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);
            viewModel.StartCommand.CanExecute(null).Should().BeTrue();

            await viewModel.StartCommand.ExecuteAsync(null);

            viewModel.Message.Should().Contain("recovery bookmark");
            await api.DidNotReceive().StartAsync(
                Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public async Task Cancel_during_monitoring_wins_over_stale_polling_and_clears_recovery()
    {
        var runId = Guid.NewGuid();
        const string objective = "Cancel the active mock run safely.";
        var specification = CreateSpecification(runId, objective);
        var api = Substitute.For<IVibeQuantApiClient>();
        ConfigureCredits(api);
        api.CreateRunAsync(Arg.Any<CreateVibeQuantRunRequest>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(specification);
        api.StartAsync(runId, specification.SpecSha256, Arg.Any<CancellationToken>()).Returns(
            CreateStatus(runId, specification.SpecSha256, CoordinatorRunStatus.Running));
        api.CancelAsync(runId, Arg.Any<CancellationToken>()).Returns(
            CreateStatus(runId, specification.SpecSha256, CoordinatorRunStatus.Cancelled));
        var pollingStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var delay = Substitute.For<IHostedStrategyPollDelay>();
        delay.WaitAsync(Arg.Any<CancellationToken>()).Returns(callInfo =>
        {
            pollingStarted.TrySetResult();
            return Task.Delay(Timeout.Infinite, callInfo.Arg<CancellationToken>());
        });
        var bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
        bookmarkStore.Read().Returns(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Missing));
        bookmarkStore.TryCreate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
        bookmarkStore.TryClear(Arg.Any<HostedStrategyRunBookmarkReadResult>()).Returns(true);
        var viewModel = CreateViewModel(
            api,
            CreateWorkspace(Substitute.For<IStrategyCompiler>()),
            bookmarkStore,
            pollDelay: delay);
        viewModel.Objective = objective;

        try
        {
            await viewModel.SubmitCommand.ExecuteAsync(null);
            var startTask = viewModel.StartCommand.ExecuteAsync(null);
            await pollingStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.Running);
            viewModel.CancelCommand.CanExecute(null).Should().BeTrue();
            await viewModel.CancelCommand.ExecuteAsync(null);
            await startTask.WaitAsync(TimeSpan.FromSeconds(5));

            viewModel.RunStatus.Should().Be(CoordinatorRunStatus.Cancelled);
            viewModel.RunReservedCredits.Should().Be(0);
            viewModel.RunChargedCredits.Should().Be(0);
            viewModel.Message.Should().Contain("refunded");
            bookmarkStore.Received(1).TryClear(Arg.Any<HostedStrategyRunBookmarkReadResult>());
            await api.DidNotReceive().GetStatusAsync(
                Arg.Any<Guid>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            viewModel.Dispose();
        }
    }

    [Fact]
    public void Imported_mock_id_preserves_an_existing_local_authoring_session()
    {
        const string strategyId = "mock-generated-strategy";
        var sessionPath = Path.Combine(AuthoringSessionStore.Directory, $"{strategyId}.json");
        var originalBytes = File.Exists(sessionPath) ? File.ReadAllBytes(sessionPath) : null;
        var existing = AuthoringSessionStore.Load(strategyId);
        var createdFixture = existing is null;
        if (createdFixture)
        {
            AuthoringSessionStore.Save(new AuthoringSessionSnapshot(
                strategyId,
                "Preserved local session",
                [new AuthoringChatEntry(AuthoringChatEntry.User, "Keep this history.", DateTime.Now)],
                [],
                [new StrategyFile("Existing.cs", "// existing")],
                UpdatedUtc: DateTime.UtcNow)).Should().BeTrue();
            existing = AuthoringSessionStore.Load(strategyId);
        }

        var compiler = Substitute.For<IStrategyCompiler>();
        var workspace = CreateWorkspace(compiler);
        string? importedId = null;
        try
        {
            importedId = workspace.ImportDraft(new StrategyScript(
                strategyId,
                "Mock Generated Strategy",
                [new StrategyFile("Strategy.cs", "public sealed class MockGeneratedStrategy { }")]));

            importedId.Should().NotBe(strategyId);
            workspace.StrategyId.Should().Be(importedId);
            var preserved = AuthoringSessionStore.Load(strategyId);
            preserved.Should().NotBeNull();
            preserved!.DisplayName.Should().Be(existing!.DisplayName);
            preserved.Chat.Select(entry => entry.Text).Should().Equal(existing.Chat.Select(entry => entry.Text));
            preserved.Files.Should().BeEquivalentTo(existing.Files);
            compiler.DidNotReceive().Compile(Arg.Any<StrategyScript>());
        }
        finally
        {
            workspace.Dispose();
            if (importedId is not null) AuthoringSessionStore.Delete(importedId);
            if (originalBytes is null)
            {
                AuthoringSessionStore.Delete(strategyId);
            }
            else
            {
                Directory.CreateDirectory(AuthoringSessionStore.Directory);
                File.WriteAllBytes(sessionPath, originalBytes);
            }
        }
    }

    [Fact]
    public void Remote_development_headers_are_rejected_before_a_client_is_created()
    {
        var options = Options.Create(new VibeQuantHostedOptions
        {
            Enabled = true,
            ServerBaseUrl = "https://platform.example",
            AuthenticationMode = "development",
            DevelopmentSubject = "developer",
            DevelopmentEmail = null,
        });
        var httpFactory = Substitute.For<IHttpClientFactory>();
        var factory = new VibeQuantDesktopClientFactory(options, httpFactory);

        var availability = factory.GetAvailability();

        availability.IsAvailable.Should().BeFalse();
        availability.Message.Should().Contain("loopback");
        httpFactory.DidNotReceive().CreateClient(Arg.Any<string>());
    }

    [Fact]
    public void Loopback_mock_connection_has_a_stable_nonsecret_binding_and_development_headers()
    {
        var options = Options.Create(new VibeQuantHostedOptions
        {
            Enabled = true,
            ServerBaseUrl = "http://127.0.0.1:5080/",
            AuthenticationMode = "development",
            DevelopmentSubject = "terminal-test",
            DevelopmentEmail = "terminal-test@development.invalid",
        });
        var http = new HttpClient(new EmptyHandler());
        var httpFactory = Substitute.For<IHttpClientFactory>();
        httpFactory.CreateClient(VibeQuantDesktopClientFactory.HttpClientName).Returns(http);
        var factory = new VibeQuantDesktopClientFactory(options, httpFactory);

        var availability = factory.GetAvailability();
        _ = factory.Create();

        availability.IsAvailable.Should().BeTrue();
        availability.ConnectionBinding.Should().MatchRegex("^[0-9a-f]{64}$");
        http.BaseAddress.Should().Be(new Uri("http://127.0.0.1:5080"));
        http.DefaultRequestHeaders.GetValues("X-Dev-Subject").Should().ContainSingle("terminal-test");
        http.DefaultRequestHeaders.Authorization.Should().BeNull();
    }

    [Fact]
    public void Remote_bearer_credit_authority_is_not_available_in_the_plugin_host_process()
    {
        var options = Options.Create(new VibeQuantHostedOptions
        {
            Enabled = true,
            ServerBaseUrl = "https://platform.example/",
            AuthenticationMode = "bearer",
            DevelopmentSubject = null,
            DevelopmentEmail = null,
        });
        var httpFactory = Substitute.For<IHttpClientFactory>();
        var factory = new VibeQuantDesktopClientFactory(options, httpFactory);

        var availability = factory.GetAvailability();

        availability.IsAvailable.Should().BeFalse();
        availability.Message.Should().Contain("production desktop credit authority");
        httpFactory.DidNotReceive().CreateClient(Arg.Any<string>());
    }

    private static void ConfigureCredits(IVibeQuantApiClient api) =>
        api.GetCreditsAsync(Arg.Any<CancellationToken>()).Returns(
            new VibeQuantCreditBalanceResponse(5_000, 0, 0, "pricing-v1", DateTimeOffset.UtcNow));

    private static HostedStrategyAuthoringViewModel CreateViewModel(
        IVibeQuantApiClient api,
        StrategyAuthoringViewModel workspace,
        IHostedStrategyRunBookmarkStore? bookmarkStore = null,
        string connectionBinding = ConnectionBinding,
        IHostedStrategyPollDelay? pollDelay = null)
    {
        var factory = Substitute.For<IVibeQuantDesktopClientFactory>();
        factory.GetAvailability().Returns(new VibeQuantHostedAvailability(true, "Ready.", connectionBinding));
        factory.Create().Returns(api);
        var delay = pollDelay ?? Substitute.For<IHostedStrategyPollDelay>();
        if (pollDelay is null)
            delay.WaitAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        if (bookmarkStore is null)
        {
            bookmarkStore = Substitute.For<IHostedStrategyRunBookmarkStore>();
            bookmarkStore.Read().Returns(new HostedStrategyRunBookmarkReadResult(
                HostedStrategyRunBookmarkReadState.Missing));
            bookmarkStore.TryCreate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
            bookmarkStore.TryUpdate(Arg.Any<HostedStrategyRunBookmark>()).Returns(true);
            bookmarkStore.TryClear(Arg.Any<HostedStrategyRunBookmarkReadResult>()).Returns(true);
        }
        return new HostedStrategyAuthoringViewModel(
            factory,
            delay,
            bookmarkStore,
            workspace,
            NullLogger<HostedStrategyAuthoringViewModel>.Instance);
    }

    private static StrategyAuthoringViewModel CreateWorkspace(IStrategyCompiler compiler) => new(
        compiler,
        Substitute.For<IBacktestStrategyRegistry>(),
        NullLogger<StrategyAuthoringViewModel>.Instance);

    private static VibeQuantRunSpecResponse CreateSpecification(
        Guid runId,
        string objective,
        string protocol = "mock")
    {
        var specification = new VibeQuantRunSpecification(
            VibeQuantApiVersions.RunSpecification,
            runId,
            objective,
            DateTimeOffset.UtcNow,
            [],
            new VibeQuantProviderView(
                protocol == "mock" ? "mock" : "daxalgo-private",
                "daxalgo-expert-rehearsal",
                protocol),
            new VibeQuantBudgetView(8, 2, 100_000, 25_000, 4_096, 1_000_000, 2_000_000, 900, 120),
            500,
            "pricing-v1",
            CoordinatorVersions.StrategyPolicy,
            CoordinatorVersions.StrategyWorkflow,
            CoordinatorVersions.StrategyPromptCatalogSha256,
            new string('e', 64));
        return new VibeQuantRunSpecResponse(ContentHasher.HashJson(specification), specification);
    }

    private static CoordinatorStrategySourceArtifact CreateArtifact(
        Guid runId,
        string objective,
        string riskReviewSha256,
        string? strategyId = null,
        string displayName = "Hosted strategy")
    {
        const string source = "public sealed class HostedStrategy { }";
        return new CoordinatorStrategySourceArtifact
        {
            SchemaVersion = CoordinatorVersions.StrategyArtifactSchema,
            RunId = runId,
            ObjectiveSha256 = ContentHasher.HashUtf8(objective),
            StrategyId = strategyId ?? $"hosted-{runId:N}",
            DisplayName = displayName,
            Files =
            [
                new CoordinatorStrategySourceFile(
                    "HostedStrategy.cs",
                    source,
                    ContentHasher.HashUtf8(source)),
            ],
            EvidenceSourceIds = [],
            SynthesizerArtifactSha256 = new string('a', 64),
            RiskJudgeArtifactSha256 = riskReviewSha256,
            DeliveryState = CoordinatorVersions.StrategyDeliveryState,
            CompilerProfile = CoordinatorVersions.StrategyCompilerProfile,
            RequiresHumanRelease = true,
            RequiresTerminalCompileConsent = true,
            InstallEligible = false,
        };
    }

    private static CoordinatorRoleOutput CreateRiskReview() => new()
    {
        SchemaVersion = CoordinatorVersions.ArtifactSchema,
        Role = CoordinatorRole.RiskJudge,
        Summary = "Risk review approved the inert source for human inspection only.",
        Risks = ["Generated code remains untrusted until local compile and review."],
        Recommendations = ["Keep broker execution disabled."],
        Decision = CoordinatorDecision.Approve,
    };

    private static VibeQuantRunStatusResponse CreateStatus(
        Guid runId,
        string specificationSha256,
        CoordinatorRunStatus status,
        string? finalArtifactSha256 = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new VibeQuantRunStatusResponse(
            runId,
            status,
            specificationSha256,
            status is CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed ? 5 : 0,
            false,
            status is CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running ? 500 : 0,
            status is CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed ? 500 : 0,
            finalArtifactSha256,
            null,
            now,
            now);
    }

    private sealed class EmptyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }

    private const string ConnectionBinding =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
}
