using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.VibeQuant;
using DaxAlgo.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Retrieval;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class VibeQuantExpertContextTests
{
    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task PinnedContextIsPrivateFrozenIdempotentAndCreditMetered()
    {
        await using var context = await PrivateContextFixture.CreateAsync(
            "RiskBudget and DrawdownGuard are required for portfolio strategy allocation.");
        var pinnedOptions = context.CreateOptions(context.Pack.PackSha256);
        pinnedOptions.Validate();
        await using var factory = new PlatformApiFactory(
            services =>
            {
                services.RemoveAll<VibeQuantOptions>();
                services.RemoveAll<VibeQuantSpecificationFactory>();
                services.AddSingleton(pinnedOptions);
                services.AddSingleton<VibeQuantSpecificationFactory>();
            });
        var configuredOptions = factory.Services.GetRequiredService<VibeQuantOptions>();
        Assert.Equal("Pinned", configuredOptions.ExpertContextMode);
        Assert.Equal(context.PackPath, configuredOptions.ExpertContextPackPath);
        const string subject = "vibe-quant-private-context";
        using var http = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, http, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 1_000, "private-context-allocation");
        var api = new VibeQuantApiClient(http);
        var request = new CreateVibeQuantRunRequest(
            "Design a RiskBudget strategy with DrawdownGuard controls.",
            [new CoordinatorContextSource(
                "observation",
                "Portfolio observation",
                "The requested strategy needs risk budget allocation.")]);

        var created = await api.CreateRunAsync(request, "private-context-run");

        Assert.Single(created.Spec.Sources);
        Assert.Equal(500, created.Spec.MaximumCreditCharge);
        Assert.Equal("observation", created.Spec.Sources[0].Id);
        var publicJson = JsonSerializer.Serialize(created, CoordinatorJson.Options);
        Assert.DoesNotContain("daxctx.", publicJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(context.Pack.PackSha256, publicJson, StringComparison.Ordinal);
        Assert.DoesNotContain("DrawdownGuard are required", publicJson, StringComparison.Ordinal);

        VibeQuantRun stored;
        VibeQuantSpecificationFactory activeFactory;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            activeFactory = scope.ServiceProvider.GetRequiredService<VibeQuantSpecificationFactory>();
            stored = await database.VibeQuantRuns.AsNoTracking()
                .SingleAsync(run => run.Id == created.Spec.RunId);
        }
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
            stored.ExecutionSpecJson,
            CoordinatorJson.Options);
        Assert.NotNull(executionSpec);
        Assert.Equal(request.Sources.Count + 2, executionSpec.Sources.Count);
        Assert.Equal("observation", executionSpec.Sources[0].Id);
        Assert.Equal("daxctx.manifest", executionSpec.Sources[1].Id);
        Assert.StartsWith("daxctx.", executionSpec.Sources[2].Id, StringComparison.Ordinal);
        Assert.Contains("DrawdownGuard are required", executionSpec.Sources[2].Content, StringComparison.Ordinal);
        Assert.Contains(context.Pack.PackSha256, executionSpec.Sources[1].Content, StringComparison.Ordinal);
        Assert.Equal(stored.ExecutionSpecSha256, ContentHasher.HashJson(executionSpec));
        Assert.Equal(created.Spec.ExecutionProfileBinding, stored.ExecutionProfileBinding);
        Assert.Equal(
            stored.ExecutionProfileBinding,
            activeFactory.ComputeExecutionProfileBinding(
                stored.ExecutionSpecJson,
                stored.ExecutionBindingNonce));
        Assert.DoesNotContain("daxctx.", stored.SpecJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(context.Pack.PackSha256, stored.SpecJson, StringComparison.Ordinal);
        using (var manifest = JsonDocument.Parse(executionSpec.Sources[1].Content))
        {
            var binding = Assert.Single(manifest.RootElement.GetProperty("chunks").EnumerateArray());
            Assert.Equal(executionSpec.Sources[2].Id, binding.GetProperty("citationId").GetString());
            Assert.Equal(
                ContentHasher.HashUtf8(executionSpec.Sources[2].Content),
                binding.GetProperty("contentSha256").GetString());
        }
        var uncharged = await api.GetCreditsAsync();
        Assert.Equal(1_000, uncharged.AvailableCredits);
        Assert.Equal(0, uncharged.ReservedCredits);
        Assert.Equal(0, uncharged.ConsumedCredits);

        File.Delete(context.PackPath);
        var retry = await api.CreateRunAsync(request, "private-context-run");
        Assert.Equal(created.Spec.RunId, retry.Spec.RunId);
        Assert.Equal(created.SpecSha256, retry.SpecSha256);
        Assert.Equal(created.Spec.ExecutionProfileBinding, retry.Spec.ExecutionProfileBinding);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var rows = await database.VibeQuantRuns.AsNoTracking().ToListAsync();
            var retryStored = Assert.Single(rows);
            Assert.Equal(stored.ExecutionSpecJson, retryStored.ExecutionSpecJson);
            Assert.Equal(stored.ExecutionSpecSha256, retryStored.ExecutionSpecSha256);
            Assert.Equal(stored.ExecutionProfileBinding, retryStored.ExecutionProfileBinding);
            Assert.Equal(stored.ExecutionBindingNonce, retryStored.ExecutionBindingNonce);
        }

        var started = await api.StartAsync(created.Spec.RunId, created.SpecSha256);
        Assert.Equal(500, started.ReservedCredits);
        var completed = await WaitForStatusAsync(
            api,
            created.Spec.RunId,
            CoordinatorRunStatus.AwaitingReleaseApproval);
        Assert.Equal(5, completed.CompletedRoleCount);
        Assert.Equal(1, completed.ChargedCredits);
        var credits = await api.GetCreditsAsync();
        Assert.Equal(999, credits.AvailableCredits);
        Assert.Equal(0, credits.ReservedCredits);
        Assert.Equal(1, credits.ConsumedCredits);
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var completedStored = await database.VibeQuantRuns.AsNoTracking().SingleAsync();
            Assert.Equal(stored.ExecutionSpecJson, completedStored.ExecutionSpecJson);
            Assert.Equal(stored.ExecutionSpecSha256, completedStored.ExecutionSpecSha256);
            Assert.Equal(stored.ExecutionProfileBinding, completedStored.ExecutionProfileBinding);
            Assert.Equal(stored.ExecutionBindingNonce, completedStored.ExecutionBindingNonce);
        }
    }

    [Fact]
    public async Task PinnedContextRejectsPackThatDoesNotMatchServerConfiguration()
    {
        await using var context = await PrivateContextFixture.CreateAsync(
            "RiskBudget is required for strategy allocation.");
        var options = context.CreateOptions(new string('a', 64));
        options.Validate();

        var createFactory = () => new VibeQuantSpecificationFactory(options, TimeProvider.System);

        var exception = Assert.Throws<InvalidOperationException>(createFactory);
        Assert.Contains("failed validation", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PinnedContextRejectsContentTamperedPack()
    {
        await using var context = await PrivateContextFixture.CreateAsync(
            "RiskBudget is required for strategy allocation.");
        await context.TamperPackContentAsync();
        var options = context.CreateOptions(context.Pack.PackSha256);
        options.Validate();

        var createFactory = () => new VibeQuantSpecificationFactory(options, TimeProvider.System);

        var exception = Assert.Throws<InvalidOperationException>(createFactory);
        Assert.Contains("failed validation", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DisabledExpertContextPreservesLegacySubmittedOnlySpecification()
    {
        var options = new VibeQuantOptions
        {
            ExpertContextMode = "Disabled",
            ExpertContextPackPath = Path.Combine(Path.GetTempPath(), "does-not-exist.json"),
            ExpertContextCorpusId = "poisoned",
            ExpertContextCorpusVersion = "latest",
            ExpertContextPackSha256 = new string('z', 64)
        };
        options.Validate();
        var factory = new VibeQuantSpecificationFactory(options, TimeProvider.System);
        CoordinatorContextSource[] submitted =
        [
            new("caller", "Caller source", "Caller-only content.")
        ];

        var envelope = factory.Create(
            Guid.NewGuid(),
            Guid.NewGuid(),
            new CreateVibeQuantRunRequest("Assess caller evidence.", submitted));
        var execution = JsonSerializer.Deserialize<CoordinatorRunSpec>(
            envelope.ExecutionSpecJson,
            CoordinatorJson.Options);
        var publicSpec = JsonSerializer.Deserialize<VibeQuantRunSpecification>(
            envelope.SpecJson,
            CoordinatorJson.Options);

        Assert.NotNull(execution);
        Assert.NotNull(publicSpec);
        Assert.Single(execution.Sources);
        Assert.Single(publicSpec.Sources);
        Assert.Equal("caller", execution.Sources[0].Id);
        Assert.DoesNotContain("daxctx.", envelope.ExecutionSpecJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RetrievalFailureIsPrivateSafeAndDoesNotPersistOrCharge()
    {
        await using var context = await PrivateContextFixture.CreateAsync(
            "RiskBudget and DrawdownGuard are private architecture controls.");
        var options = context.CreateOptions(context.Pack.PackSha256);
        options.Validate();
        await using var factory = CreatePinnedFactory(options);
        const string subject = "vibe-quant-no-context-match";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 50, "no-match-allocation");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/vibe-quant/runs")
        {
            Content = JsonContent.Create(new CreateVibeQuantRunRequest(
                "orthogonalUnseenVocabulary",
                [new CoordinatorContextSource("input", "Unrelated input", "alphaOmegaTerm")]))
        };
        request.Headers.Add("Idempotency-Key", "no-context-match");

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("could not select compatible private context", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("risk", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DrawdownGuard", body, StringComparison.Ordinal);
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        Assert.Empty(await database.VibeQuantRuns.AsNoTracking().ToListAsync());
        var wallet = await database.VibeQuantCreditWallets.AsNoTracking()
            .SingleAsync(item => item.AccountId == accountId);
        Assert.Equal(50, wallet.AvailableCredits);
        Assert.Equal(0, wallet.ReservedCredits);
        Assert.Equal(0, wallet.ConsumedCredits);
    }

    [Fact]
    public async Task StoredExecutionHashMismatchIsRejectedBeforeCreditReservation()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "vibe-quant-stored-hash-mismatch";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "hash-mismatch-allocation");
        var api = new VibeQuantApiClient(client);
        var created = await api.CreateRunAsync(
            new CreateVibeQuantRunRequest(
                "Assess caller evidence.",
                [new CoordinatorContextSource("caller", "Caller", "Evidence")]),
            "stored-hash-mismatch");
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var run = await database.VibeQuantRuns.SingleAsync(item => item.Id == created.Spec.RunId);
            run.ExecutionSpecSha256 = new string('a', 64);
            await database.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{created.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(created.SpecSha256));

        Assert.NotEqual(System.Net.HttpStatusCode.Accepted, response.StatusCode);
        await using var verificationScope = factory.Services.CreateAsyncScope();
        var verificationDatabase = verificationScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var wallet = await verificationDatabase.VibeQuantCreditWallets.AsNoTracking()
            .SingleAsync(item => item.AccountId == accountId);
        var stored = await verificationDatabase.VibeQuantRuns.AsNoTracking()
            .SingleAsync(item => item.Id == created.Spec.RunId);
        Assert.Equal(500, wallet.AvailableCredits);
        Assert.Equal(0, wallet.ReservedCredits);
        Assert.Equal(CoordinatorRunStatus.AwaitingStartApproval, stored.Status);
    }

    [Fact]
    public async Task RehashedExecutionJsonTamperIsRejectedByProfileBindingBeforeCreditReservation()
    {
        await using var context = await PrivateContextFixture.CreateAsync(
            "RiskBudget is required for strategy allocation.");
        var options = context.CreateOptions(context.Pack.PackSha256);
        options.Validate();
        await using var factory = CreatePinnedFactory(options);
        const string subject = "vibe-quant-stored-binding-mismatch";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject);
        await GrantProfessionalAsync(factory, accountId);
        await GrantCreditsAsync(factory, accountId, 500, "binding-mismatch-allocation");
        var api = new VibeQuantApiClient(client);
        var created = await api.CreateRunAsync(
            new CreateVibeQuantRunRequest(
                "Design a RiskBudget strategy.",
                [new CoordinatorContextSource("caller", "Caller", "RiskBudget evidence")]),
            "stored-binding-mismatch");
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var run = await database.VibeQuantRuns.SingleAsync(item => item.Id == created.Spec.RunId);
            var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
                    run.ExecutionSpecJson,
                    CoordinatorJson.Options)
                ?? throw new InvalidOperationException("Execution specification was JSON null.");
            var tamperedSources = executionSpec.Sources.Select(source =>
                source.Id.StartsWith(ExpertContextPackTools.ReservedSourcePrefix, StringComparison.Ordinal) &&
                !StringComparer.Ordinal.Equals(
                    source.Id,
                    ExpertContextPackTools.ReservedSourcePrefix + "manifest")
                    ? source with { Content = source.Content + "\nTAMPERED" }
                    : source).ToArray();
            var tamperedSpec = executionSpec with { Sources = tamperedSources };
            run.ExecutionSpecJson = JsonSerializer.Serialize(tamperedSpec, CoordinatorJson.Options);
            run.ExecutionSpecSha256 = ContentHasher.HashJson(tamperedSpec);
            await database.SaveChangesAsync();
        }

        var response = await client.PostAsJsonAsync(
            $"/api/v1/vibe-quant/runs/{created.Spec.RunId:D}/start",
            new StartVibeQuantRunRequest(created.SpecSha256));

        Assert.NotEqual(System.Net.HttpStatusCode.Accepted, response.StatusCode);
        await using var verificationScope = factory.Services.CreateAsyncScope();
        var verificationDatabase = verificationScope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var wallet = await verificationDatabase.VibeQuantCreditWallets.AsNoTracking()
            .SingleAsync(item => item.AccountId == accountId);
        var stored = await verificationDatabase.VibeQuantRuns.AsNoTracking()
            .SingleAsync(item => item.Id == created.Spec.RunId);
        Assert.Equal(500, wallet.AvailableCredits);
        Assert.Equal(0, wallet.ReservedCredits);
        Assert.Equal(CoordinatorRunStatus.Failed, stored.Status);
    }

    [Fact]
    public async Task SubstitutedCoordinatorSnapshotReturnsTrustedTerminalFailure()
    {
        await using var context = await PrivateContextFixture.CreateAsync(
            "RiskBudget is required for strategy allocation.");
        var options = context.CreateOptions(context.Pack.PackSha256);
        options.Validate();
        var specificationFactory = new VibeQuantSpecificationFactory(options, TimeProvider.System);
        var accountId = Guid.NewGuid();
        var runId = Guid.NewGuid();
        var firstEnvelope = specificationFactory.Create(
            accountId,
            runId,
            new CreateVibeQuantRunRequest(
                "Design a RiskBudget strategy.",
                [new CoordinatorContextSource("caller", "Caller", "RiskBudget evidence")]));
        var substitutedEnvelope = specificationFactory.Create(
            accountId,
            runId,
            new CreateVibeQuantRunRequest(
                "Replace the frozen RiskBudget objective.",
                [new CoordinatorContextSource("caller", "Caller", "RiskBudget evidence")]));
        var runtime = new VibeQuantExecutionRuntime(
            options,
            new UnusedHttpClientFactory(),
                new VibeQuantModelReadinessService(
                    options,
                    new UnusedHttpClientFactory(),
                    TimeProvider.System,
                    NullLogger<VibeQuantModelReadinessService>.Instance),
            specificationFactory,
            NullLogger<VibeQuantExecutionRuntime>.Instance);

        var original = await runtime.ExecuteAsync(
            CreateExecutionRun(accountId, runId, firstEnvelope),
            default);
        var rejected = await runtime.ExecuteAsync(
            CreateExecutionRun(accountId, runId, substitutedEnvelope),
            default);

        Assert.Equal(CoordinatorRunStatus.AwaitingReleaseApproval, original.Status);
        Assert.Equal(CoordinatorRunStatus.Failed, rejected.Status);
        Assert.Equal(0, rejected.CompletedRoleCount);
        Assert.Equal(new CoordinatorUsage(), rejected.Usage);
        Assert.Equal(0m, rejected.BillableCostUsd);
        Assert.Null(rejected.FinalArtifactSha256);
        Assert.Contains("inconsistent", rejected.SafeMessage, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<VibeQuantRunStatusResponse> WaitForStatusAsync(
        VibeQuantApiClient client,
        Guid runId,
        CoordinatorRunStatus expected)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (true)
        {
            var status = await client.GetStatusAsync(runId, timeout.Token);
            if (status.Status == expected)
            {
                return status;
            }
            Assert.DoesNotContain(status.Status, new[]
            {
                CoordinatorRunStatus.Failed,
                CoordinatorRunStatus.BudgetExhausted,
                CoordinatorRunStatus.NeedsRevision,
                CoordinatorRunStatus.Rejected
            });
            await Task.Delay(25, timeout.Token);
        }
    }

    private static PlatformApiFactory CreatePinnedFactory(VibeQuantOptions options) =>
        new(services =>
        {
            services.RemoveAll<VibeQuantOptions>();
            services.RemoveAll<VibeQuantSpecificationFactory>();
            services.AddSingleton(options);
            services.AddSingleton<VibeQuantSpecificationFactory>();
        });

    private static VibeQuantRun CreateExecutionRun(
        Guid accountId,
        Guid runId,
        VibeQuantSpecificationEnvelope envelope) => new()
        {
            Id = runId,
            AccountId = accountId,
            IdempotencyKey = $"runtime-{Guid.NewGuid():N}",
            RequestSha256 = envelope.RequestSha256,
            SpecSha256 = envelope.SpecSha256,
            SpecJson = envelope.SpecJson,
            ExecutionSpecJson = envelope.ExecutionSpecJson,
            ExecutionSpecSha256 = envelope.ExecutionSpecSha256,
            ExecutionProfileBinding = envelope.ExecutionProfileBinding,
            ExecutionBindingNonce = envelope.ExecutionBindingNonce,
            Status = CoordinatorRunStatus.Running,
            UsageJson = JsonSerializer.Serialize(new CoordinatorUsage(), CoordinatorJson.Options)
        };

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
                currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30)
            });
        response.EnsureSuccessStatusCode();
    }

    private static async Task GrantCreditsAsync(
        PlatformApiFactory factory,
        Guid accountId,
        long credits,
        string key)
    {
        using var admin = CreateAuthenticatedClient(factory, "private-context-admin", "platform-admin");
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

    private sealed class PrivateContextFixture : IAsyncDisposable
    {
        private PrivateContextFixture(
            string rootPath,
            string packPath,
            ExpertContextPack pack)
        {
            RootPath = rootPath;
            PackPath = packPath;
            Pack = pack;
        }

        public string RootPath { get; }

        public string PackPath { get; }

        public ExpertContextPack Pack { get; }

        public static async Task<PrivateContextFixture> CreateAsync(string content)
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                "daxalgo-vibe-quant-context-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var sourcePath = Path.Combine(root, "risk.md");
            var sourceBytes = new UTF8Encoding(false).GetBytes(content);
            await File.WriteAllBytesAsync(sourcePath, sourceBytes);
            var manifest = new ExpertContextManifest
            {
                SchemaVersion = ExpertContextPackTools.ManifestSchemaVersion,
                CorpusId = "daxalgo-private",
                CorpusVersion = "2026.07.27-test",
                NormalizerVersion = ExpertContextPackTools.NormalizerVersion,
                ChunkerVersion = ExpertContextPackTools.ChunkerVersion,
                TokenizerVersion = ExpertContextPackTools.TokenizerVersion,
                ScorerVersion = ExpertContextPackTools.ScorerVersion,
                CreatedAtUtc = FixtureTime,
                CutoffUtc = FixtureTime,
                Sources =
                [
                    new ExpertContextManifestSource
                    {
                        Id = "risk",
                        RelativePath = "risk.md",
                        Title = "DaxAlgo risk architecture",
                        Provenance = "Reviewed private DaxAlgo documentation.",
                        License = "DaxAlgo private; provider upload permitted.",
                        Domains = [ExpertDomain.RiskManagement],
                        Rights = new DatasetRights(true, true, false, true, false),
                        AvailableAtUtc = FixtureTime,
                        RawSha256 = ContentHasher.HashBytes(sourceBytes)
                    }
                ]
            };
            var pack = await ExpertContextPackTools.BuildAsync(manifest, root);
            var packPath = Path.Combine(root, "context-pack.json");
            await File.WriteAllTextAsync(
                packPath,
                JsonSerializer.Serialize(pack, CoordinatorJson.Options),
                new UTF8Encoding(false));
            return new PrivateContextFixture(root, packPath, pack);
        }

        public VibeQuantOptions CreateOptions(string expectedPackSha256) => new()
        {
            WorkspacePath = Path.Combine(RootPath, "vibe-quant-data"),
            ExpertContextMode = "Pinned",
            ExpertContextPackPath = PackPath,
            ExpertContextCorpusId = Pack.CorpusId,
            ExpertContextCorpusVersion = Pack.CorpusVersion,
            ExpertContextPackSha256 = expectedPackSha256,
            ExpertContextTopK = 1,
            ExpertContextMaxCharacters = 10_000,
            ExpertContextMaxPerSource = 1,
            ExpertContextQueryMaxCharacters = 30_000
        };

        public async Task TamperPackContentAsync()
        {
            var json = await File.ReadAllTextAsync(PackPath);
            await File.WriteAllTextAsync(
                PackPath,
                json.Replace("RiskBudget", "RiskBudgeb", StringComparison.Ordinal),
                new UTF8Encoding(false));
        }

        public ValueTask DisposeAsync()
        {
            var fullRoot = Path.GetFullPath(RootPath);
            var safeParent = Path.GetFullPath(Path.Combine(
                Path.GetTempPath(),
                "daxalgo-vibe-quant-context-tests"));
            if (!fullRoot.StartsWith(
                    Path.TrimEndingDirectorySeparator(safeParent) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Refusing to clean an unsafe context test path.");
            }
            if (Directory.Exists(fullRoot))
            {
                SqliteConnection.ClearAllPools();
                Directory.Delete(fullRoot, recursive: true);
            }
            return ValueTask.CompletedTask;
        }
    }

    private sealed class UnusedHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            throw new InvalidOperationException("Mock coordinator execution must not create an HTTP client.");
    }
}
