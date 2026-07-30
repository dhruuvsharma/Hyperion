using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Features.VibeQuant;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class VibeQuantApiTests
{
    [Fact]
    public void CancellationRegistryIsLeaseScopedAndLatchesPreRegistrationRequests()
    {
        using var registry = new VibeQuantExecutionCancellationRegistry();
        var runId = Guid.NewGuid();
        var staleLease = Guid.NewGuid();
        var currentLease = Guid.NewGuid();
        var staleToken = registry.Ensure(runId, staleLease, cancellationRequested: false);
        var currentToken = registry.Ensure(runId, currentLease, cancellationRequested: false);

        registry.Complete(runId, staleLease);
        registry.Request(runId);

        Assert.False(staleToken.CanBeCanceled && staleToken.IsCancellationRequested);
        Assert.True(currentToken.IsCancellationRequested);

        var pendingRunId = Guid.NewGuid();
        registry.Request(pendingRunId);
        var lateToken = registry.Ensure(pendingRunId, Guid.NewGuid(), cancellationRequested: false);
        Assert.True(lateToken.IsCancellationRequested);
    }

    [Fact]
    public async Task AdministrativeCreditGrantIsIdempotentAndBindsTheRequestBody()
    {
        await using var factory = new PlatformApiFactory();
        using var accountClient = CreateAuthenticatedClient(factory, "grant-target");
        var accountId = await BootstrapAsync(factory, accountClient, "grant-target");
        using var admin = CreateAuthenticatedClient(factory, "grant-admin", "platform-admin");

        var first = await PostGrantAsync(admin, accountId, 250, "same-grant", "Pilot allocation.");
        var retry = await PostGrantAsync(admin, accountId, 250, "same-grant", "Pilot allocation.");
        var changed = await PostGrantAsync(admin, accountId, 251, "same-grant", "Pilot allocation.");

        first.EnsureSuccessStatusCode();
        retry.EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var wallet = await database.VibeQuantCreditWallets.SingleAsync(item => item.AccountId == accountId);
        Assert.Equal(250, wallet.AvailableCredits);
        Assert.Single(await database.VibeQuantCreditLedger
            .Where(item => item.AccountId == accountId)
            .ToListAsync());
    }

    [Fact]
    public async Task CreatePublishesTheTransportLimitAndRejectsOversizedSourcesAndServerFieldSpoofing()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "vibe-quant-closed-create";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);

        var createEndpoint = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(endpoint => endpoint.RoutePattern.RawText == "/api/v1/vibe-quant/runs" &&
                endpoint.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Contains("POST"));
        Assert.Equal(
            VibeQuantApiVersions.MaximumRequestBytes,
            createEndpoint.Metadata.GetRequiredMetadata<IRequestSizeLimitMetadata>().MaxRequestBodySize);

        using var oversized = new HttpRequestMessage(HttpMethod.Post, "/api/v1/vibe-quant/runs")
        {
            Content = JsonContent.Create(new CreateVibeQuantRunRequest(
                "Oversized source.",
                [new CoordinatorContextSource("large", "Large", new string('x', 8_100_000))]))
        };
        oversized.Headers.Add("Idempotency-Key", "oversized-server-create");
        var oversizedResponse = await client.SendAsync(oversized);
        Assert.Contains(
            oversizedResponse.StatusCode,
            new[] { HttpStatusCode.BadRequest, HttpStatusCode.RequestEntityTooLarge });

        using var spoofed = new HttpRequestMessage(HttpMethod.Post, "/api/v1/vibe-quant/runs")
        {
            Content = new StringContent(
                """
                {"objective":"Spoof server policy.","sources":[],"accountId":"00000000-0000-0000-0000-000000000000","provider":{"providerId":"attacker"},"maximumCreditCharge":0}
                """,
                System.Text.Encoding.UTF8,
                "application/json")
        };
        spoofed.Headers.Add("Idempotency-Key", "spoofed-server-create");
        var spoofedResponse = await client.SendAsync(spoofed);
        Assert.Equal(HttpStatusCode.BadRequest, spoofedResponse.StatusCode);
    }

    [Fact]
    public async Task HostedRunReservesSettlesAndScopesCreditsAndArtifacts()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "vibe-quant-user";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 1_000, "initial-allocation");

        var create = await CreateRunAsync(client, "hosted-run-1", "Assess the supplied observation.");
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var specification = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(specification);
        Assert.Equal(500, specification.Spec.MaximumCreditCharge);
        Assert.Equal("mock", specification.Spec.Provider.Protocol);
        Assert.Equal(64, specification.Spec.ExecutionProfileBinding.Length);
        var publicSpecJson = JsonSerializer.Serialize(specification, CoordinatorJson.Options);
        Assert.DoesNotContain("maxCostUsd", publicSpecJson);
        Assert.DoesNotContain("credentialEnvironmentVariable", publicSpecJson);
        Assert.DoesNotContain("inputUsdPerMillionTokens", publicSpecJson);
        Assert.DoesNotContain("A bounded synthetic observation.", publicSpecJson);
        Assert.Equal(64, Assert.Single(specification.Spec.Sources).ContentSha256.Length);

        var wrongStart = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{specification.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(new string('f', 64)));
        Assert.Equal(HttpStatusCode.Conflict, wrongStart.StatusCode);

        var started = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{specification.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(specification.SpecSha256));
        Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);

        var pendingCredits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(pendingCredits);
        Assert.Equal(1_000, pendingCredits.AvailableCredits + pendingCredits.ReservedCredits);

        var status = await WaitForStatusAsync(
            client,
            specification.Spec.RunId,
            CoordinatorRunStatus.AwaitingReleaseApproval);
        Assert.Equal(5, status.CompletedRoleCount);
        Assert.NotNull(status.FinalArtifactSha256);
        Assert.Equal(1, status.ChargedCredits);
        Assert.Equal(0, status.ReservedCredits);
        Assert.DoesNotContain("costUsd", JsonSerializer.Serialize(status, CoordinatorJson.Options));

        var artifact = await client.GetFromJsonAsync<VibeQuantArtifactResponse>(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/artifacts/{status.FinalArtifactSha256}",
            CoordinatorJson.Options);
        Assert.NotNull(artifact);
        Assert.Equal(CoordinatorRole.Synthesizer, artifact.Role);
        Assert.Equal(status.FinalArtifactSha256, artifact.Sha256);

        var wrongRelease = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/release",
            new ReleaseVibeQuantRunRequest(new string('e', 64)));
        Assert.Equal(HttpStatusCode.Conflict, wrongRelease.StatusCode);

        var released = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/release",
            new ReleaseVibeQuantRunRequest(status.FinalArtifactSha256!.ToUpperInvariant()));
        released.EnsureSuccessStatusCode();
        var completed = await released.Content.ReadFromJsonAsync<VibeQuantRunStatusResponse>(CoordinatorJson.Options);
        Assert.NotNull(completed);
        Assert.Equal(CoordinatorRunStatus.Completed, completed.Status);
        var repeatedRelease = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/release",
            new ReleaseVibeQuantRunRequest(status.FinalArtifactSha256.ToUpperInvariant()));
        repeatedRelease.EnsureSuccessStatusCode();

        var settledCredits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(settledCredits);
        Assert.Equal(999, settledCredits.AvailableCredits);
        Assert.Equal(0, settledCredits.ReservedCredits);
        Assert.Equal(1, settledCredits.ConsumedCredits);

        using var other = CreateAuthenticatedClient(factory, "vibe-quant-other");
        var otherAccount = await BootstrapAsync(factory, other, "vibe-quant-other");
        await GrantProfessionalAsync(factory, otherAccount);
        var crossTenant = await other.GetAsync($"/api/v1/vibe-quant/runs/{status.RunId:D}");
        Assert.Equal(HttpStatusCode.NotFound, crossTenant.StatusCode);
        var crossTenantArtifact = await other.GetAsync(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/artifacts/{status.FinalArtifactSha256}");
        Assert.Equal(HttpStatusCode.NotFound, crossTenantArtifact.StatusCode);
    }

    [Fact]
    public async Task MockHostedStrategyRunReturnsReleasedInertSourceAndChargesCredits()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "vibe-quant-strategy-user";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "strategy-allocation");

        var create = await CreateRunAsync(
            client,
            "hosted-strategy-1",
            "Create a bounded inert strategy source artifact.",
            CoordinatorRunPurpose.StrategyAuthoring);
        create.EnsureSuccessStatusCode();
        var specification = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(specification);
        Assert.Equal(CoordinatorVersions.StrategyPolicy, specification.Spec.PolicyVersion);
        Assert.Equal(CoordinatorVersions.StrategyWorkflow, specification.Spec.WorkflowVersion);
        Assert.Equal(CoordinatorPromptCatalog.StrategySha256, specification.Spec.PromptCatalogSha256);

        var changedPurpose = await CreateRunAsync(
            client,
            "hosted-strategy-1",
            "Create a bounded inert strategy source artifact.");
        Assert.Equal(HttpStatusCode.Conflict, changedPurpose.StatusCode);
        var invalidPurpose = await CreateRunAsync(
            client,
            "hosted-strategy-invalid-purpose",
            "Create a bounded inert strategy source artifact.",
            (CoordinatorRunPurpose)99);
        Assert.Equal(HttpStatusCode.BadRequest, invalidPurpose.StatusCode);

        var started = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{specification.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(specification.SpecSha256));
        Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        var status = await WaitForStatusAsync(
            client,
            specification.Spec.RunId,
            CoordinatorRunStatus.AwaitingReleaseApproval);
        Assert.NotNull(status.FinalArtifactSha256);
        Assert.Equal(1, status.ChargedCredits);

        var artifactResponse = await client.GetFromJsonAsync<VibeQuantArtifactResponse>(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/artifacts/{status.FinalArtifactSha256}",
            CoordinatorJson.Options);
        Assert.NotNull(artifactResponse);
        Assert.Null(artifactResponse.Output);
        var artifact = Assert.IsType<CoordinatorStrategySourceArtifact>(artifactResponse.StrategyArtifact);
        CoordinatorStrategyArtifactValidation.Validate(artifact);
        Assert.Equal(status.RunId, artifact.RunId);
        Assert.False(artifact.InstallEligible);
        Assert.True(artifact.RequiresTerminalCompileConsent);
        Assert.Equal(
            artifact.Files[0].ContentSha256,
            ContentHasher.HashUtf8(artifact.Files[0].Content));

        var released = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{status.RunId:D}/release",
            new ReleaseVibeQuantRunRequest(status.FinalArtifactSha256));
        released.EnsureSuccessStatusCode();
        var completed = await released.Content.ReadFromJsonAsync<VibeQuantRunStatusResponse>(CoordinatorJson.Options);
        Assert.NotNull(completed);
        Assert.Equal(CoordinatorRunStatus.Completed, completed.Status);

        var credits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(credits);
        Assert.Equal(499, credits.AvailableCredits);
        Assert.Equal(1, credits.ConsumedCredits);
    }

    [Fact]
    public async Task CompetingRunsCannotOverspendAndCancellationRefundsTheReservation()
    {
        await using var factory = new PlatformApiFactory(workerPollMilliseconds: 60_000);
        const string subject = "vibe-quant-competing-runs";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "competing-allocation");

        var firstResponse = await CreateRunAsync(client, "competing-1", "First competing objective.");
        var secondResponse = await CreateRunAsync(client, "competing-2", "Second competing objective.");
        var first = await firstResponse.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        var second = await secondResponse.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(first);
        Assert.NotNull(second);

        var starts = await Task.WhenAll(
            client.PostAsJsonAsync(
                $"/api/v1/vibe-quant/runs/{first.Spec.RunId:D}/start",
                new StartVibeQuantRunRequest(first.SpecSha256)),
            client.PostAsJsonAsync(
                $"/api/v1/vibe-quant/runs/{second.Spec.RunId:D}/start",
                new StartVibeQuantRunRequest(second.SpecSha256)));
        Assert.Single(starts, response => response.StatusCode == HttpStatusCode.Accepted);
        Assert.Single(starts, response => response.StatusCode == HttpStatusCode.PaymentRequired);

        var acceptedRun = starts[0].StatusCode == HttpStatusCode.Accepted ? first.Spec.RunId : second.Spec.RunId;
        var reserved = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(reserved);
        Assert.Equal(0, reserved.AvailableCredits);
        Assert.Equal(500, reserved.ReservedCredits);

        var cancelled = await client.PostAsync(
            $"/api/v1/vibe-quant/runs/{acceptedRun:D}/cancel",
            JsonContent.Create(new { }));
        cancelled.EnsureSuccessStatusCode();
        var refunded = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(refunded);
        Assert.Equal(500, refunded.AvailableCredits);
        Assert.Equal(0, refunded.ReservedCredits);
        Assert.Equal(0, refunded.ConsumedCredits);
    }

    [Fact]
    public async Task FailedProviderWorkRefundsCreditsAndDoesNotBillSafetyBudgetUsage()
    {
        await using var factory = new PlatformApiFactory(services =>
        {
            services.RemoveAll<IVibeQuantExecutionRuntime>();
            services.AddScoped<IVibeQuantExecutionRuntime, AlwaysFailsExecutionRuntime>();
        });
        const string subject = "vibe-quant-failed-provider";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "failed-run-allocation");
        var create = await CreateRunAsync(client, "failed-run", "Exercise failed provider settlement.");
        var spec = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(spec);
        var start = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{spec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(spec.SpecSha256));
        start.EnsureSuccessStatusCode();

        var failed = await WaitForStatusAsync(client, spec.Spec.RunId, CoordinatorRunStatus.Failed);
        Assert.Equal(0, failed.ChargedCredits);
        Assert.Equal(0, failed.ReservedCredits);
        var credits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(credits);
        Assert.Equal(500, credits.AvailableCredits);
        Assert.Equal(0, credits.ReservedCredits);
        Assert.Equal(0, credits.ConsumedCredits);
    }

    [Fact]
    public async Task ConfirmedUsageRoundsUpCreditsAndDuplicateCompletionCannotChargeTwice()
    {
        await using var factory = new PlatformApiFactory(services =>
        {
            services.RemoveAll<IVibeQuantExecutionRuntime>();
            services.AddScoped<IVibeQuantExecutionRuntime, FixedCostExecutionRuntime>();
        });
        const string subject = "vibe-quant-confirmed-cost";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "confirmed-cost-allocation");
        var create = await CreateRunAsync(client, "confirmed-cost", "Settle confirmed provider usage.");
        var spec = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(spec);
        var start = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{spec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(spec.SpecSha256));
        start.EnsureSuccessStatusCode();

        var status = await WaitForStatusAsync(
            client,
            spec.Spec.RunId,
            CoordinatorRunStatus.AwaitingReleaseApproval);
        Assert.Equal(124, status.ChargedCredits);
        Assert.Equal(0, status.ReservedCredits);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<VibeQuantService>().CompleteExecutionAsync(
                status.RunId,
                Guid.NewGuid(),
                FixedCostExecutionRuntime.Result,
                default);
        }

        var credits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(credits);
        Assert.Equal(376, credits.AvailableCredits);
        Assert.Equal(0, credits.ReservedCredits);
        Assert.Equal(124, credits.ConsumedCredits);

        await using var verificationScope = factory.Services.CreateAsyncScope();
        var database = verificationScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var entries = await database.VibeQuantCreditLedger.AsNoTracking()
            .Where(entry => entry.AccountId == accountId)
            .ToListAsync();
        Assert.Equal(376, entries.Sum(entry => entry.AvailableDelta));
        Assert.Equal(0, entries.Sum(entry => entry.ReservedDelta));
        Assert.Equal(124, entries.Sum(entry => entry.ConsumedDelta));
    }

    [Fact]
    public async Task RunningCancellationSignalsTheWorkerAndSettlesAsCancelled()
    {
        await using var factory = new PlatformApiFactory(services =>
        {
            services.RemoveAll<IVibeQuantExecutionRuntime>();
            services.AddSingleton<BlockingExecutionSignal>();
            services.AddScoped<IVibeQuantExecutionRuntime, BlockingExecutionRuntime>();
        });
        const string subject = "vibe-quant-running-cancel";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "running-cancel-allocation");
        var create = await CreateRunAsync(client, "running-cancel", "Cancel an active server run.");
        var spec = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(spec);
        var start = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{spec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(spec.SpecSha256));
        start.EnsureSuccessStatusCode();
        var signal = factory.Services.GetRequiredService<BlockingExecutionSignal>();
        await signal.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var cancel = await client.PostAsync(
            $"/api/v1/vibe-quant/runs/{spec.Spec.RunId:D}/cancel",
            JsonContent.Create(new { }));
        cancel.EnsureSuccessStatusCode();
        var requested = await cancel.Content.ReadFromJsonAsync<VibeQuantRunStatusResponse>(CoordinatorJson.Options);
        Assert.NotNull(requested);
        Assert.True(requested.CancellationRequested);

        var cancelled = await WaitForStatusAsync(client, spec.Spec.RunId, CoordinatorRunStatus.Cancelled);
        Assert.Equal(0, cancelled.ChargedCredits);
        var credits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(credits);
        Assert.Equal(500, credits.AvailableCredits);
        Assert.Equal(0, credits.ReservedCredits);
    }

    [Fact]
    public async Task ExpiredWorkerLeaseIsReclaimedAndStaleCompletionIsFenced()
    {
        await using var factory = new PlatformApiFactory(workerPollMilliseconds: 60_000);
        const string subject = "vibe-quant-lease-recovery";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "lease-recovery-allocation");
        var create = await CreateRunAsync(client, "lease-recovery", "Recover an expired worker lease.");
        var spec = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(spec);
        var start = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{spec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(spec.SpecSha256));
        start.EnsureSuccessStatusCode();

        DaxAlgo.Platform.Domain.VibeQuantRun firstClaim;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            firstClaim = Assert.IsType<DaxAlgo.Platform.Domain.VibeQuantRun>(
                await scope.ServiceProvider.GetRequiredService<VibeQuantService>().ClaimNextAsync(default));
        }
        await Task.Delay(20);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<VibeQuantService>();
            Assert.False(await service.RenewLeaseAsync(
                firstClaim.Id,
                firstClaim.WorkerLeaseId!.Value,
                default));
        }
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var tracked = await database.VibeQuantRuns.SingleAsync(run => run.Id == firstClaim.Id);
            Assert.True(tracked.WorkerLeaseExpiresAt > firstClaim.WorkerLeaseExpiresAt);
            tracked.CancellationRequested = true;
            await database.SaveChangesAsync();
        }
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<VibeQuantService>();
            Assert.True(await service.RenewLeaseAsync(
                firstClaim.Id,
                firstClaim.WorkerLeaseId!.Value,
                default));
        }
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var tracked = await database.VibeQuantRuns.SingleAsync(run => run.Id == firstClaim.Id);
            tracked.CancellationRequested = false;
            tracked.CancellationRequestedAt = null;
            tracked.WorkerLeaseExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            await database.SaveChangesAsync();
        }
        DaxAlgo.Platform.Domain.VibeQuantRun recovered;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            recovered = Assert.IsType<DaxAlgo.Platform.Domain.VibeQuantRun>(
                await scope.ServiceProvider.GetRequiredService<VibeQuantService>().ClaimNextAsync(default));
        }
        Assert.NotEqual(firstClaim.WorkerLeaseId, recovered.WorkerLeaseId);
        Assert.Equal(2, recovered.ExecutionAttempt);
        Assert.Equal(
            spec.Spec.Budget.RequestTimeoutSeconds + 60,
            recovered.WorkerLeaseDurationSeconds);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<VibeQuantService>();
            await Assert.ThrowsAsync<PlatformConflictException>(() => service.RenewLeaseAsync(
                firstClaim.Id,
                firstClaim.WorkerLeaseId!.Value,
                default));
        }

        var failedResult = new VibeQuantExecutionResult(
            CoordinatorRunStatus.Failed,
            0,
            new CoordinatorUsage(),
            0m,
            null,
            "Recovered test failure.");
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<VibeQuantService>();
            await Assert.ThrowsAsync<PlatformConflictException>(() => service.CompleteExecutionAsync(
                firstClaim.Id,
                firstClaim.WorkerLeaseId!.Value,
                failedResult,
                default));
        }
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<VibeQuantService>().CompleteExecutionAsync(
                recovered.Id,
                recovered.WorkerLeaseId!.Value,
                failedResult,
                default);
        }
        var failed = await client.GetFromJsonAsync<VibeQuantRunStatusResponse>(
            $"/api/v1/vibe-quant/runs/{recovered.Id:D}",
            CoordinatorJson.Options);
        Assert.NotNull(failed);
        Assert.Equal(CoordinatorRunStatus.Failed, failed.Status);
        Assert.Equal(0, failed.ReservedCredits);
    }

    [Fact]
    public async Task ClaimScansPastTransientReadinessAndRefundsRetiredAndExpiredActivations()
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreatePromotionBoundLiveOptions(
            apiKeyEnvironment,
            attestationKeyEnvironment,
            suffix);
        options.Validate();
        var clock = new ManualPromotionTimeProvider(
            new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero));
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = Assert.IsType<VibeQuantModelDeploymentIdentity>(catalog.Identity);
        var specificationFactory = new VibeQuantSpecificationFactory(options, clock, catalog);
        var attestationKey = Enumerable.Range(0, 32)
            .Select(value => checked((byte)value))
            .ToArray();
        using var clientFactory = new PromotionAttestationClientFactory(
            new PromotionAttestationHandler(options, identity, attestationKey));
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(
            attestationKeyEnvironment,
            Base64Url.Encode(attestationKey));
        try
        {
            await using var factory = new PlatformApiFactory(
                services =>
                {
                    services.RemoveAll<VibeQuantOptions>();
                    services.AddSingleton(options);
                    services.RemoveAll<VibeQuantModelDeploymentCatalog>();
                    services.AddSingleton(catalog);
                    services.RemoveAll<VibeQuantSpecificationFactory>();
                    services.AddSingleton(specificationFactory);
                    services.RemoveAll<VibeQuantModelReadinessService>();
                    services.AddSingleton(readiness);
                    RemoveVibeQuantWorker(services);
                },
                workerPollMilliseconds: 60_000);
            const string subject = "vibe-quant-promotion-claim";
            using var client = CreateAuthenticatedClient(factory, subject);
            var accountId = await BootstrapAsync(factory, client, subject);
            await GrantProfessionalAsync(factory, accountId);
            await GrantCreditsAsync(factory, accountId, 1_000, "promotion-claim-allocation");

            var current = await CreateAndStartRunAsync(
                factory,
                client,
                "promotion-current",
                "Assess RiskBudget evidence for the current model run.",
                identity.ExecutionModelId);
            clock.Advance(TimeSpan.FromSeconds(1));
            var stale = await CreateAndStartRunAsync(
                factory,
                client,
                "promotion-stale",
                "Assess RiskBudget evidence for the stale model run.",
                identity.ExecutionModelId);
            await RebindExecutionModelAsync(factory, stale.Spec.RunId, "deterministic-v1");

            clock.Advance(TimeSpan.FromSeconds(options.ModelAttestationTtlSeconds + 1));
            await using (var claimScope = factory.Services.CreateAsyncScope())
            {
                Assert.Null(await claimScope.ServiceProvider.GetRequiredService<VibeQuantService>()
                    .ClaimNextAsync(default));
            }

            await using (var verificationScope = factory.Services.CreateAsyncScope())
            {
                var database = verificationScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
                var staleRun = await database.VibeQuantRuns.AsNoTracking()
                    .SingleAsync(run => run.Id == stale.Spec.RunId);
                var wallet = await database.VibeQuantCreditWallets.AsNoTracking()
                    .SingleAsync(item => item.AccountId == accountId);
                Assert.Equal(CoordinatorRunStatus.Failed, staleRun.Status);
                Assert.True(staleRun.CreditsSettled);
                Assert.Equal(0, staleRun.ReservedCredits);
                Assert.Equal(0, staleRun.ExecutionAttempt);
                Assert.Null(staleRun.WorkerLeaseId);
                Assert.DoesNotContain("deterministic-v1", staleRun.SafeMessage, StringComparison.Ordinal);
                Assert.DoesNotContain(identity.ExecutionModelId, staleRun.SafeMessage, StringComparison.Ordinal);
                Assert.DoesNotContain(identity.PromotionPayloadSha256, staleRun.SafeMessage, StringComparison.Ordinal);
                var currentRun = await database.VibeQuantRuns.AsNoTracking()
                    .SingleAsync(run => run.Id == current.Spec.RunId);
                Assert.Equal(CoordinatorRunStatus.Ready, currentRun.Status);
                Assert.False(currentRun.CreditsSettled);
                Assert.Equal(500, currentRun.ReservedCredits);
                Assert.Equal(500, wallet.AvailableCredits);
                Assert.Equal(500, wallet.ReservedCredits);
                Assert.Equal(0, wallet.ConsumedCredits);
            }

            clock.Advance(identity.PromotionExpiresAtUtc - clock.GetUtcNow() + TimeSpan.FromSeconds(1));
            Assert.True(readiness.IsPromotionExpired);
            await using (var expiredScope = factory.Services.CreateAsyncScope())
            {
                Assert.Null(await expiredScope.ServiceProvider
                    .GetRequiredService<VibeQuantService>()
                    .ClaimNextAsync(default));
            }
            await using var finalScope = factory.Services.CreateAsyncScope();
            var finalDatabase = finalScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var expiredRun = await finalDatabase.VibeQuantRuns.AsNoTracking()
                .SingleAsync(run => run.Id == current.Spec.RunId);
            var finalWallet = await finalDatabase.VibeQuantCreditWallets.AsNoTracking()
                .SingleAsync(item => item.AccountId == accountId);
            Assert.Equal(CoordinatorRunStatus.Failed, expiredRun.Status);
            Assert.True(expiredRun.CreditsSettled);
            Assert.Equal(0, expiredRun.ReservedCredits);
            Assert.Equal(0, expiredRun.ExecutionAttempt);
            Assert.Null(expiredRun.WorkerLeaseId);
            Assert.DoesNotContain(identity.ExecutionModelId, expiredRun.SafeMessage, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionPayloadSha256, expiredRun.SafeMessage, StringComparison.Ordinal);
            Assert.Equal(1_000, finalWallet.AvailableCredits);
            Assert.Equal(0, finalWallet.ReservedCredits);
            Assert.Equal(0, finalWallet.ConsumedCredits);
        }
        finally
        {
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task SignedV2LiveStrategySurvivesCreateStartAndClaimWithCreditReservation()
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreatePromotionBoundLiveOptions(
            apiKeyEnvironment,
            attestationKeyEnvironment,
            suffix,
            strategyAuthoring: true);
        options.Validate();
        var clock = new ManualPromotionTimeProvider(
            new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero));
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = Assert.IsType<VibeQuantModelDeploymentIdentity>(catalog.Identity);
        var specificationFactory = new VibeQuantSpecificationFactory(options, clock, catalog);
        var attestationKey = Enumerable.Range(0, 32)
            .Select(value => checked((byte)value))
            .ToArray();
        using var clientFactory = new PromotionAttestationClientFactory(
            new PromotionAttestationHandler(options, identity, attestationKey));
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(
            attestationKeyEnvironment,
            Base64Url.Encode(attestationKey));
        try
        {
            await using var factory = new PlatformApiFactory(
                services =>
                {
                    services.RemoveAll<VibeQuantOptions>();
                    services.AddSingleton(options);
                    services.RemoveAll<VibeQuantModelDeploymentCatalog>();
                    services.AddSingleton(catalog);
                    services.RemoveAll<VibeQuantSpecificationFactory>();
                    services.AddSingleton(specificationFactory);
                    services.RemoveAll<VibeQuantModelReadinessService>();
                    services.AddSingleton(readiness);
                    RemoveVibeQuantWorker(services);
                },
                workerPollMilliseconds: 60_000);
            const string subject = "vibe-quant-live-strategy-v2";
            using var client = CreateAuthenticatedClient(factory, subject);
            var accountId = await BootstrapAsync(factory, client, subject);
            await GrantProfessionalAsync(factory, accountId);
            await GrantCreditsAsync(factory, accountId, 500, "live-strategy-v2-allocation");

            var create = await CreateRunAsync(
                client,
                "live-strategy-v2",
                "Create bounded inert strategy source for review.",
                CoordinatorRunPurpose.StrategyAuthoring);
            create.EnsureSuccessStatusCode();
            var specification = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(
                CoordinatorJson.Options);
            Assert.NotNull(specification);
            Assert.Equal("openai-compatible", specification.Spec.Provider.Protocol);
            Assert.Equal(CoordinatorVersions.StrategyPolicy, specification.Spec.PolicyVersion);
            Assert.Equal(CoordinatorVersions.StrategyWorkflow, specification.Spec.WorkflowVersion);
            Assert.Equal(
                CoordinatorVersions.StrategyPromptCatalogSha256,
                specification.Spec.PromptCatalogSha256);

            var start = await client.PostAsJsonAsync(
                $"/api/v1/vibe-quant/runs/{specification.Spec.RunId:D}/start",
                new StartVibeQuantRunRequest(specification.SpecSha256),
                CoordinatorJson.Options);
            start.EnsureSuccessStatusCode();
            var started = await start.Content.ReadFromJsonAsync<VibeQuantRunStatusResponse>(
                CoordinatorJson.Options);
            Assert.NotNull(started);
            Assert.Equal(CoordinatorRunStatus.Ready, started.Status);
            Assert.Equal(500, started.ReservedCredits);

            await using var scope = factory.Services.CreateAsyncScope();
            var claimed = await scope.ServiceProvider.GetRequiredService<VibeQuantService>()
                .ClaimNextAsync(default);
            Assert.NotNull(claimed);
            var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
                claimed.ExecutionSpecJson,
                CoordinatorJson.Options);
            Assert.NotNull(executionSpec);
            Assert.Equal(CoordinatorRunPurpose.StrategyAuthoring, executionSpec.Purpose);
            Assert.Equal(identity.ExecutionModelId, executionSpec.Provider.ModelId);
            Assert.Equal(CoordinatorVersions.StrategyPolicy, executionSpec.PolicyVersion);
        }
        finally
        {
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task EndpointRotationInvalidatesAwaitingAndQueuedRunsWithoutLeakingActivation()
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreatePromotionBoundLiveOptions(
            apiKeyEnvironment,
            attestationKeyEnvironment,
            suffix);
        var retiredOptions = CreatePromotionBoundLiveOptions(
            apiKeyEnvironment,
            attestationKeyEnvironment,
            suffix + "_RETIRED",
            baseUrl: "https://retired-inference.example.test/v1");
        options.Validate();
        retiredOptions.Validate();
        var clock = new ManualPromotionTimeProvider(
            new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero));
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var retiredCatalog = new VibeQuantModelDeploymentCatalog(retiredOptions, clock);
        var identity = Assert.IsType<VibeQuantModelDeploymentIdentity>(catalog.Identity);
        Assert.Equal(identity.ExecutionModelId, retiredCatalog.ExecutionModelId);
        Assert.NotEqual(catalog.ActivationSha256, retiredCatalog.ActivationSha256);
        var specificationFactory = new VibeQuantSpecificationFactory(options, clock, catalog);
        var retiredFactory = new VibeQuantSpecificationFactory(
            retiredOptions,
            clock,
            retiredCatalog);
        var attestationKey = Enumerable.Range(0, 32)
            .Select(value => checked((byte)value))
            .ToArray();
        using var clientFactory = new PromotionAttestationClientFactory(
            new PromotionAttestationHandler(options, identity, attestationKey));
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(
            attestationKeyEnvironment,
            Base64Url.Encode(attestationKey));
        try
        {
            await using var factory = new PlatformApiFactory(
                services =>
                {
                    services.RemoveAll<VibeQuantOptions>();
                    services.AddSingleton(options);
                    services.RemoveAll<VibeQuantModelDeploymentCatalog>();
                    services.AddSingleton(catalog);
                    services.RemoveAll<VibeQuantSpecificationFactory>();
                    services.AddSingleton(specificationFactory);
                    services.RemoveAll<VibeQuantModelReadinessService>();
                    services.AddSingleton(readiness);
                    RemoveVibeQuantWorker(services);
                });
            const string subject = "vibe-quant-activation-rotation";
            using var client = CreateAuthenticatedClient(factory, subject);
            var accountId = await BootstrapAsync(factory, client, subject);
            await GrantProfessionalAsync(factory, accountId);
            await GrantCreditsAsync(factory, accountId, 500, "activation-rotation-allocation");

            var awaitingResponse = await CreateRunAsync(
                client,
                "retired-awaiting",
                "Assess RiskBudget for an awaiting run bound to a retired endpoint.");
            awaitingResponse.EnsureSuccessStatusCode();
            var awaiting = await awaitingResponse.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(
                CoordinatorJson.Options);
            Assert.NotNull(awaiting);
            var awaitingSha256 = await RebindExecutionActivationAsync(
                factory,
                awaiting.Spec.RunId,
                retiredFactory,
                retiredOptions.BaseUrl!,
                retiredOptions.ApiKeyEnvironmentVariable!);
            var rejectedStart = await client.PostAsJsonAsync(
                $"/api/v1/vibe-quant/runs/{awaiting.Spec.RunId:D}/start",
                new StartVibeQuantRunRequest(awaitingSha256));
            Assert.Equal(HttpStatusCode.Conflict, rejectedStart.StatusCode);
            await using (var terminalScope = factory.Services.CreateAsyncScope())
            {
                var terminalDatabase = terminalScope.ServiceProvider
                    .GetRequiredService<PlatformDbContext>();
                var terminalRun = await terminalDatabase.VibeQuantRuns
                    .SingleAsync(run => run.Id == awaiting.Spec.RunId);
                Assert.Equal(CoordinatorRunStatus.Failed, terminalRun.Status);
                Assert.Equal(0, terminalRun.ReservedCredits);
                terminalRun.Status = CoordinatorRunStatus.Completed;
                await terminalDatabase.SaveChangesAsync();
            }
            var terminalRetry = await client.PostAsJsonAsync(
                $"/api/v1/vibe-quant/runs/{awaiting.Spec.RunId:D}/start",
                new StartVibeQuantRunRequest(awaitingSha256));
            terminalRetry.EnsureSuccessStatusCode();
            var terminalStatus = await terminalRetry.Content
                .ReadFromJsonAsync<VibeQuantRunStatusResponse>(CoordinatorJson.Options);
            Assert.Equal(CoordinatorRunStatus.Completed, terminalStatus?.Status);

            var queued = await CreateAndStartRunAsync(
                factory,
                client,
                "retired-queued",
                "Assess RiskBudget for a queued run bound to a retired endpoint.",
                identity.ExecutionModelId);
            _ = await RebindExecutionActivationAsync(
                factory,
                queued.Spec.RunId,
                retiredFactory,
                retiredOptions.BaseUrl!,
                retiredOptions.ApiKeyEnvironmentVariable!);
            await using (var claimScope = factory.Services.CreateAsyncScope())
            {
                Assert.Null(await claimScope.ServiceProvider.GetRequiredService<VibeQuantService>()
                    .ClaimNextAsync(default));
            }

            await using var verificationScope = factory.Services.CreateAsyncScope();
            var database = verificationScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var awaitingRun = await database.VibeQuantRuns.AsNoTracking()
                .SingleAsync(run => run.Id == awaiting.Spec.RunId);
            var queuedRun = await database.VibeQuantRuns.AsNoTracking()
                .SingleAsync(run => run.Id == queued.Spec.RunId);
            var wallet = await database.VibeQuantCreditWallets.AsNoTracking()
                .SingleAsync(item => item.AccountId == accountId);
            Assert.Equal(CoordinatorRunStatus.Completed, awaitingRun.Status);
            Assert.Equal(0, awaitingRun.ReservedCredits);
            Assert.Equal(CoordinatorRunStatus.Failed, queuedRun.Status);
            Assert.True(queuedRun.CreditsSettled);
            Assert.Equal(0, queuedRun.ReservedCredits);
            Assert.Equal(500, wallet.AvailableCredits);
            Assert.Equal(0, wallet.ReservedCredits);
            Assert.Equal(0, wallet.ConsumedCredits);
            Assert.DoesNotContain(retiredOptions.BaseUrl!, queuedRun.SafeMessage, StringComparison.Ordinal);
            Assert.DoesNotContain(retiredOptions.ApiKeyEnvironmentVariable!, queuedRun.SafeMessage, StringComparison.Ordinal);
            Assert.DoesNotContain(catalog.ActivationSha256, queuedRun.SafeMessage, StringComparison.Ordinal);
            Assert.DoesNotContain(retiredCatalog.ActivationSha256, queuedRun.SafeMessage, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task CreateAndStartAreIdempotentAndCannotOverspend()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "vibe-quant-idempotency";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "single-run-allocation");

        var first = await CreateRunAsync(client, "same-command", "First objective.");
        var retry = await CreateRunAsync(client, "same-command", "First objective.");
        first.EnsureSuccessStatusCode();
        retry.EnsureSuccessStatusCode();
        var firstSpec = await first.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        var retrySpec = await retry.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(firstSpec);
        Assert.NotNull(retrySpec);
        Assert.Equal(firstSpec.Spec.RunId, retrySpec.Spec.RunId);

        var changed = await CreateRunAsync(client, "same-command", "Changed objective.");
        Assert.Equal(HttpStatusCode.Conflict, changed.StatusCode);

        var starts = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{firstSpec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(firstSpec.SpecSha256))));
        Assert.All(starts, response => Assert.Equal(HttpStatusCode.Accepted, response.StatusCode));
        _ = await WaitForStatusAsync(
            client,
            firstSpec.Spec.RunId,
            CoordinatorRunStatus.AwaitingReleaseApproval);

        var credits = await client.GetFromJsonAsync<VibeQuantCreditBalanceResponse>(
            "/api/v1/vibe-quant/credits",
            CoordinatorJson.Options);
        Assert.NotNull(credits);
        Assert.Equal(499, credits.AvailableCredits);
        Assert.Equal(1, credits.ConsumedCredits);

        var second = await CreateRunAsync(client, "second-run", "A second objective.");
        second.EnsureSuccessStatusCode();
        var secondSpec = await second.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(CoordinatorJson.Options);
        Assert.NotNull(secondSpec);
        var insufficient = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{secondSpec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(secondSpec.SpecSha256));
        Assert.Equal(HttpStatusCode.PaymentRequired, insufficient.StatusCode);
    }

    [Fact]
    public async Task VibeQuantRequiresAuthenticationAndProfessionalEntitlement()
    {
        await using var factory = new PlatformApiFactory();
        using var anonymous = factory.CreateClient();
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await anonymous.GetAsync("/api/v1/vibe-quant/credits")).StatusCode);

        using var basic = CreateAuthenticatedClient(factory, "vibe-quant-basic");
        await BootstrapAsync(factory, basic, "vibe-quant-basic");
        Assert.Equal(
            HttpStatusCode.Forbidden,
            (await basic.GetAsync("/api/v1/vibe-quant/credits")).StatusCode);
    }

    private static async Task<HttpResponseMessage> CreateRunAsync(
        HttpClient client,
        string idempotencyKey,
        string objective,
        CoordinatorRunPurpose purpose = CoordinatorRunPurpose.Research)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/vibe-quant/runs")
        {
            Content = JsonContent.Create(new CreateVibeQuantRunRequest(
                objective,
                [new CoordinatorContextSource("observation", "Observation", "A bounded synthetic observation.")],
                purpose))
        };
        request.Headers.Add("Idempotency-Key", idempotencyKey);
        return await client.SendAsync(request);
    }

    private static async Task<VibeQuantRunStatusResponse> WaitForStatusAsync(
        HttpClient client,
        Guid runId,
        CoordinatorRunStatus expected)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            var status = await client.GetFromJsonAsync<VibeQuantRunStatusResponse>(
                $"/api/v1/vibe-quant/runs/{runId:D}",
                CoordinatorJson.Options,
                timeout.Token);
            Assert.NotNull(status);
            if (status.Status == expected)
            {
                return status;
            }
            Assert.DoesNotContain(
                status.Status,
                new[]
                {
                    CoordinatorRunStatus.Failed,
                    CoordinatorRunStatus.BudgetExhausted,
                    CoordinatorRunStatus.NeedsRevision,
                    CoordinatorRunStatus.Rejected,
                });
            await Task.Delay(25, timeout.Token);
        }
    }

    private static HttpClient CreateAuthenticatedClient(
        PlatformApiFactory factory,
        string subject,
        string? role = null)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Dev-Subject", subject);
        client.DefaultRequestHeaders.Add("X-Dev-Email", $"{subject}@example.test");
        if (role is not null)
        {
            client.DefaultRequestHeaders.Add("X-Dev-Roles", role);
        }
        return client;
    }

    private static async Task<Guid> BootstrapAsync(
        PlatformApiFactory factory,
        HttpClient client,
        string subject)
    {
        var response = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { displayName = subject });
        response.EnsureSuccessStatusCode();
        return await factory.GetAccountIdAsync(subject);
    }

    private static async Task GrantProfessionalAsync(PlatformApiFactory factory, Guid accountId)
    {
        using var webhook = factory.CreateClient();
        webhook.DefaultRequestHeaders.Add("X-Development-Webhook", "accepted");
        var response = await webhook.PostAsJsonAsync(
            "/api/v1/billing/webhooks",
            new
            {
                id = $"evt-{Guid.NewGuid():N}",
                type = "subscription.updated",
                accountId,
                subscriptionId = $"sub-{Guid.NewGuid():N}",
                priceId = "dev_price_professional_monthly",
                status = "Active",
                currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30),
            });
        response.EnsureSuccessStatusCode();
    }

    private static async Task GrantCreditsAsync(
        PlatformApiFactory factory,
        Guid accountId,
        long credits,
        string key)
    {
        using var admin = CreateAuthenticatedClient(factory, "vibe-quant-admin", "platform-admin");
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/v1/admin/vibe-quant/credits/grants")
        {
            Content = JsonContent.Create(new { accountId, credits, reason = "Test allocation." })
        };
        request.Headers.Add("Idempotency-Key", key);
        var response = await admin.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    private static async Task<HttpResponseMessage> PostGrantAsync(
        HttpClient admin,
        Guid accountId,
        long credits,
        string key,
        string reason)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/api/v1/admin/vibe-quant/credits/grants")
        {
            Content = JsonContent.Create(new { accountId, credits, reason })
        };
        request.Headers.Add("Idempotency-Key", key);
        return await admin.SendAsync(request);
    }

    private static async Task<VibeQuantRunSpecResponse> CreateAndStartRunAsync(
        PlatformApiFactory factory,
        HttpClient client,
        string idempotencyKey,
        string objective,
        string executionModelId)
    {
        var create = await CreateRunAsync(client, idempotencyKey, objective);
        create.EnsureSuccessStatusCode();
        var spec = await create.Content.ReadFromJsonAsync<VibeQuantRunSpecResponse>(
            CoordinatorJson.Options);
        Assert.NotNull(spec);
        await RebindExecutionModelAsync(factory, spec.Spec.RunId, executionModelId);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var updated = await database.VibeQuantRuns.AsNoTracking()
                .SingleAsync(run => run.Id == spec.Spec.RunId);
            spec = spec with { SpecSha256 = updated.SpecSha256 };
        }
        var start = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{spec.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(spec.SpecSha256));
        Assert.Equal(HttpStatusCode.Accepted, start.StatusCode);
        return spec;
    }

    private static async Task RebindExecutionModelAsync(
        PlatformApiFactory factory,
        Guid runId,
        string executionModelId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var run = await database.VibeQuantRuns.SingleAsync(item => item.Id == runId);
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
                run.ExecutionSpecJson,
                CoordinatorJson.Options)
            ?? throw new InvalidOperationException("Stored execution specification was null.");
        executionSpec = executionSpec with
        {
            Provider = executionSpec.Provider with { ModelId = executionModelId }
        };
        var executionJson = JsonSerializer.Serialize(executionSpec, CoordinatorJson.Options);
        var binding = scope.ServiceProvider
            .GetRequiredService<VibeQuantSpecificationFactory>()
            .ComputeExecutionProfileBinding(
            executionJson,
            run.ExecutionBindingNonce);
        var publicSpec = JsonSerializer.Deserialize<VibeQuantRunSpecification>(
                run.SpecJson,
                CoordinatorJson.Options)
            ?? throw new InvalidOperationException("Stored public specification was null.");
        publicSpec = publicSpec with { ExecutionProfileBinding = binding };
        run.ExecutionSpecJson = executionJson;
        run.ExecutionSpecSha256 = ContentHasher.HashJson(executionSpec);
        run.ExecutionProfileBinding = binding;
        run.SpecJson = JsonSerializer.Serialize(publicSpec, CoordinatorJson.Options);
        run.SpecSha256 = ContentHasher.HashJson(publicSpec);
        await database.SaveChangesAsync();
    }

    private static async Task<string> RebindExecutionActivationAsync(
        PlatformApiFactory factory,
        Guid runId,
        VibeQuantSpecificationFactory retiredFactory,
        string endpoint,
        string credentialEnvironmentVariable)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var run = await database.VibeQuantRuns.SingleAsync(item => item.Id == runId);
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
                run.ExecutionSpecJson,
                CoordinatorJson.Options)
            ?? throw new InvalidOperationException("Stored execution specification was null.");
        executionSpec = executionSpec with
        {
            Provider = executionSpec.Provider with
            {
                Endpoint = endpoint,
                CredentialEnvironmentVariable = credentialEnvironmentVariable,
            }
        };
        var executionJson = JsonSerializer.Serialize(executionSpec, CoordinatorJson.Options);
        var binding = retiredFactory.ComputeExecutionProfileBinding(
            executionJson,
            run.ExecutionBindingNonce);
        var publicSpec = JsonSerializer.Deserialize<VibeQuantRunSpecification>(
                run.SpecJson,
                CoordinatorJson.Options)
            ?? throw new InvalidOperationException("Stored public specification was null.");
        publicSpec = publicSpec with { ExecutionProfileBinding = binding };
        run.ExecutionSpecJson = executionJson;
        run.ExecutionSpecSha256 = ContentHasher.HashJson(executionSpec);
        run.ExecutionProfileBinding = binding;
        run.SpecJson = JsonSerializer.Serialize(publicSpec, CoordinatorJson.Options);
        run.SpecSha256 = ContentHasher.HashJson(publicSpec);
        await database.SaveChangesAsync();
        return run.SpecSha256;
    }

    private static void RemoveVibeQuantWorker(IServiceCollection services)
    {
        var worker = services.SingleOrDefault(descriptor =>
            descriptor.ServiceType == typeof(IHostedService) &&
            descriptor.ImplementationType == typeof(VibeQuantWorker));
        if (worker is not null)
        {
            services.Remove(worker);
        }
    }

    private static VibeQuantOptions CreatePromotionBoundLiveOptions(
        string apiKeyEnvironment,
        string attestationKeyEnvironment,
        string suffix,
        string baseUrl = "https://inference.example.test/v1",
        bool strategyAuthoring = false) => new()
        {
            Mode = "Live",
            WorkspacePath = Path.Combine(Path.GetTempPath(), $"daxalgo-promotion-claim-{suffix}"),
            ProviderId = "daxalgo-private",
            ModelId = "daxalgo-expert-sha256-" +
                "e3a16a70bfcf6a015c0d952a14f0740a99207f72e44dd618e45f949f40e8fb9f",
            Protocol = "openai-compatible",
            BaseUrl = baseUrl,
            ApiKeyEnvironmentVariable = apiKeyEnvironment,
            ModelDeploymentProfilePath = FindPromotionFixture("serving-profile.v1.golden.json"),
            ModelDeploymentProfileSha256 =
                "e3a16a70bfcf6a015c0d952a14f0740a99207f72e44dd618e45f949f40e8fb9f",
            ModelPromotionEnvelopePath = FindPromotionFixture(
                strategyAuthoring
                    ? "model-promotion-envelope.v1.strategy-authoring-v2.golden.json"
                    : "model-promotion-envelope.v1.golden.json"),
            ModelPromotionEnvelopeSha256 = strategyAuthoring
                ? "5d01f4a8d34fb6f843545f07fa5b4467936dce2eb3caea4ec53402048b06aa80"
                : "fc1b22b9a0f9c3cb3734118b8d97594d475ce240356151954b2fcc1190d222ec",
            ModelPromotionPublicKeyPath = FindPromotionFixture(
                strategyAuthoring
                    ? "model-promotion-public-key.v1.strategy-authoring-v2.golden.pem"
                    : "model-promotion-public-key.v1.golden.pem"),
            ModelPromotionPublicKeySpkiSha256 = strategyAuthoring
                ? "247b7578bc40da1d52209b2aeb57355997978df6f93a51fba9d108cde06dbfdf"
                : "8d427956ca78742a0a2f77b685f8feea717a788056474baab96c7553b82ac300",
            ModelPromotionAudience = "daxalgo-platform-prod",
            ModelPromotionKeyId = strategyAuthoring
                ? "model-promotion-strategy-v2-golden"
                : "model-promotion-golden-v1",
            ModelPromotionSignerRole = "production-model-approver",
            ModelPromotionDeploymentId = "vqdpl-prod",
            ModelPromotionEnvironment = "production",
            ModelAttestationAudience = "daxalgo-platform-prod",
            ModelAttestationKeyId = "test-hmac-v1",
            ModelAttestationKeyEnvironmentVariable = attestationKeyEnvironment,
            InputUsdPerMillionTokens = 0.25m,
            OutputUsdPerMillionTokens = 0.75m,
            ExpertContextMode = "Pinned",
            ExpertContextPackPath = FindPlatformTestData(
                "expert-context-pack.v1.promotion.json"),
            ExpertContextCorpusId = "daxalgo-private",
            ExpertContextCorpusVersion = "2026.07.27-test",
            ExpertContextPackSha256 =
                "3c273cdd7ee54f9bfd5933451c2c1530d893400e3e6595b003fda08a499b0e65",
            ExpertContextTopK = 1,
            ExpertContextMaxCharacters = 10_000,
            ExpertContextMaxPerSource = 1,
            ExpertContextQueryMaxCharacters = 30_000,
        };

    private static string FindPromotionFixture(string fileName) =>
        FindRepositoryFile(
            Path.Combine("tools", "hyperion-model", "tests", "fixtures", fileName));

    private static string FindPlatformTestData(string fileName) =>
        FindRepositoryFile(Path.Combine(
            "platform",
            "tests",
            "DaxAlgo.Platform.Api.Tests",
            "TestData",
            fileName));

    private static string FindRepositoryFile(string relativePath)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, relativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException($"Could not locate repository fixture '{relativePath}'.");
    }

    private sealed class PromotionAttestationClientFactory(HttpMessageHandler handler)
        : IHttpClientFactory, IDisposable
    {
        private readonly HttpClient client = new(handler, disposeHandler: true);

        public HttpClient CreateClient(string name) => client;

        public void Dispose() => client.Dispose();
    }

    private sealed class PromotionAttestationHandler(
        VibeQuantOptions options,
        VibeQuantModelDeploymentIdentity identity,
        byte[] key) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestJson = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(requestJson);
            var nonce = document.RootElement.GetProperty("nonce").GetString()!;
            var proof = VibeQuantModelReadinessProof.Compute(
                key,
                options.ModelAttestationAudience!,
                nonce,
                options.ModelAttestationKeyId!,
                identity);
            var responseJson = JsonSerializer.Serialize(new
            {
                schemaVersion = VibeQuantModelReadinessService.SchemaVersion,
                nonce,
                keyId = options.ModelAttestationKeyId,
                proof = Base64Url.Encode(proof),
            });
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class ManualPromotionTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset now = utcNow;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan duration) => now = now.Add(duration);
    }

    private sealed class AlwaysFailsExecutionRuntime : IVibeQuantExecutionRuntime
    {
        public Task<VibeQuantExecutionResult> ExecuteAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            CancellationToken cancellationToken) =>
            Task.FromResult(new VibeQuantExecutionResult(
                CoordinatorRunStatus.Failed,
                0,
                new CoordinatorUsage(1, 100_000, 25_000, 5m, 1_000_000, 0),
                0m,
                null,
                "The provider request failed."));

        public Task<VibeQuantArtifactResponse> ReadArtifactAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            string artifactSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<VibeQuantExecutionResult> ApproveReleaseAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            string artifactSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task CancelAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FixedCostExecutionRuntime : IVibeQuantExecutionRuntime
    {
        public static VibeQuantExecutionResult Result { get; } = new(
            CoordinatorRunStatus.AwaitingReleaseApproval,
            2,
            new CoordinatorUsage(2, 1_000, 500, 1.234m, 2_000, 1_000),
            1.234m,
            new string('a', 64),
            "Awaiting human release approval.");

        public Task<VibeQuantExecutionResult> ExecuteAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            CancellationToken cancellationToken) => Task.FromResult(Result);

        public Task<VibeQuantArtifactResponse> ReadArtifactAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            string artifactSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<VibeQuantExecutionResult> ApproveReleaseAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            string artifactSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task CancelAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class BlockingExecutionSignal
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class BlockingExecutionRuntime(BlockingExecutionSignal signal) : IVibeQuantExecutionRuntime
    {
        public async Task<VibeQuantExecutionResult> ExecuteAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            CancellationToken cancellationToken)
        {
            signal.Started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("Unreachable.");
        }

        public Task<VibeQuantArtifactResponse> ReadArtifactAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            string artifactSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<VibeQuantExecutionResult> ApproveReleaseAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            string artifactSha256,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task CancelAsync(
            DaxAlgo.Platform.Domain.VibeQuantRun run,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
