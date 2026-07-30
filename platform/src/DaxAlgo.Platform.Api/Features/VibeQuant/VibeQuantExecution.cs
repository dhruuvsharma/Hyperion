using System.Buffers.Binary;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Platform.Features.VibeQuant;

public sealed record VibeQuantSpecificationEnvelope(
    string RequestSha256,
    string SpecSha256,
    string ExecutionSpecSha256,
    string ExecutionProfileBinding,
    string ExecutionBindingNonce,
    string SpecJson,
    string ExecutionSpecJson);

public sealed class VibeQuantSpecificationFactory
{
    private const string ExecutionBindingDomain =
        "daxalgo-vibe-quant-execution-profile-binding/v2";
    private readonly VibeQuantOptions options;
    private readonly TimeProvider timeProvider;
    private readonly VibeQuantModelDeploymentCatalog modelDeployment;
    private readonly VibeQuantExpertContextCatalog expertContext;

    public VibeQuantSpecificationFactory(
        VibeQuantOptions options,
        TimeProvider timeProvider)
        : this(
            options,
            timeProvider,
            new VibeQuantModelDeploymentCatalog(options, timeProvider))
    {
    }

    internal VibeQuantSpecificationFactory(
        VibeQuantOptions options,
        TimeProvider timeProvider,
        VibeQuantModelDeploymentCatalog modelDeployment)
    {
        this.options = options;
        this.timeProvider = timeProvider;
        this.modelDeployment = modelDeployment;
        expertContext = new VibeQuantExpertContextCatalog(options);
    }

    public VibeQuantSpecificationEnvelope Create(
        Guid accountId,
        Guid runId,
        CreateVibeQuantRunRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Sources is null)
        {
            throw new PlatformValidationException("Vibe Quant sources are required.");
        }
        if (!Enum.IsDefined(request.Purpose))
        {
            throw new PlatformValidationException("Vibe Quant run purpose is not supported.");
        }
        if (!modelDeployment.AuthorizesPurpose(request.Purpose))
        {
            throw new PlatformValidationException(
                "The active signed deployment policy does not authorize this Vibe Quant purpose.");
        }

        var policyVersion = request.Purpose == CoordinatorRunPurpose.StrategyAuthoring
            ? CoordinatorVersions.StrategyPolicy
            : CoordinatorVersions.Policy;
        var workflowVersion = request.Purpose == CoordinatorRunPurpose.StrategyAuthoring
            ? CoordinatorVersions.StrategyWorkflow
            : CoordinatorVersions.Workflow;
        var promptCatalogSha256 = CoordinatorPromptCatalog.Sha256For(request.Purpose);

        var provider = new LlmProviderDescriptor(
            options.ProviderId,
            modelDeployment.ExecutionModelId,
            options.Protocol,
            options.Mode == "Live" ? options.BaseUrl : null,
            options.InputUsdPerMillionTokens,
            options.OutputUsdPerMillionTokens,
            options.Mode == "Live" ? options.ApiKeyEnvironmentVariable : null);
        var submittedSpec = new CoordinatorRunSpec(
            runId,
            request.Objective,
            accountId.ToString("D"),
            timeProvider.GetUtcNow(),
            request.Sources,
            provider,
            options.CreateBudget(),
            PolicyVersion: policyVersion,
            WorkflowVersion: workflowVersion,
            PromptCatalogSha256: promptCatalogSha256,
            Purpose: request.Purpose);

        try
        {
            CoordinatorValidation.ValidateSpec(submittedSpec);
        }
        catch (CoordinatorValidationException exception)
        {
            throw new PlatformValidationException(exception.Message);
        }

        CoordinatorRunSpec executionSpec;
        try
        {
            var executionSources = expertContext.MaterializeExecutionSources(
                accountId,
                submittedSpec.Objective,
                submittedSpec.Sources);
            executionSpec = submittedSpec with { Sources = executionSources };
            CoordinatorValidation.ValidateSpec(executionSpec);
        }
        catch (CoordinatorValidationException)
        {
            throw new PlatformValidationException(
                "Vibe Quant could not select compatible private context for this request.");
        }
        return CreateEnvelope(request, submittedSpec, executionSpec);
    }

    private VibeQuantSpecificationEnvelope CreateEnvelope(
        CreateVibeQuantRunRequest request,
        CoordinatorRunSpec submittedSpec,
        CoordinatorRunSpec executionSpec)
    {
        var provider = executionSpec.Provider;
        var executionSpecJson = JsonSerializer.Serialize(executionSpec, CoordinatorJson.Options);
        var executionSpecSha256 = ContentHasher.HashJson(executionSpec);
        var executionBindingNonceBytes = RandomNumberGenerator.GetBytes(32);
        var executionBindingNonce = Convert.ToBase64String(executionBindingNonceBytes);
        var executionProfileBinding = ComputeExecutionProfileBinding(
            executionSpecJson,
            executionBindingNonceBytes);

        var publicSpec = new VibeQuantRunSpecification(
            VibeQuantApiVersions.RunSpecification,
            executionSpec.RunId,
            submittedSpec.Objective,
            submittedSpec.CreatedAtUtc,
            submittedSpec.Sources.Select(source => new VibeQuantSourceView(
                source.Id,
                source.Title,
                ContentHasher.HashUtf8(source.Content),
                source.Content.Length,
                source.Uri,
                source.License,
                source.RetrievedAtUtc)).ToArray(),
            new VibeQuantProviderView(provider.ProviderId, modelDeployment.PublicModelId, provider.Protocol),
            new VibeQuantBudgetView(
                executionSpec.Budget.MaxRequests,
                executionSpec.Budget.MaxAttemptsPerRole,
                executionSpec.Budget.MaxPromptTokens,
                executionSpec.Budget.MaxOutputTokens,
                executionSpec.Budget.MaxOutputTokensPerRequest,
                executionSpec.Budget.MaxResponseBytes,
                executionSpec.Budget.MaxArtifactBytes,
                executionSpec.Budget.MaxElapsedSeconds,
                executionSpec.Budget.RequestTimeoutSeconds),
            Math.Max(options.MinimumChargeCredits, options.MaximumCreditCharge),
            options.CreditPricingVersion,
            executionSpec.PolicyVersion,
            executionSpec.WorkflowVersion,
            executionSpec.PromptCatalogSha256,
            executionProfileBinding);

        return new VibeQuantSpecificationEnvelope(
            ContentHasher.HashJson(request),
            ContentHasher.HashJson(publicSpec),
            executionSpecSha256,
            executionProfileBinding,
            executionBindingNonce,
            JsonSerializer.Serialize(publicSpec, CoordinatorJson.Options),
            executionSpecJson);
    }

    public string ComputeExecutionProfileBinding(string executionSpecJson, string nonceBase64) =>
        ComputeExecutionProfileBinding(executionSpecJson, Convert.FromBase64String(nonceBase64));

    internal bool IsCurrentExecutionProfileBinding(
        string executionSpecJson,
        string nonceBase64,
        string binding) => StringComparer.Ordinal.Equals(
        ComputeExecutionProfileBinding(executionSpecJson, nonceBase64),
        binding);

    internal bool IsCurrentCoordinatorProfile(
        CoordinatorRunPurpose purpose,
        string policyVersion,
        string workflowVersion,
        string promptCatalogSha256) =>
        modelDeployment.AuthorizesPurpose(purpose) && purpose switch
        {
            CoordinatorRunPurpose.Research =>
                StringComparer.Ordinal.Equals(policyVersion, CoordinatorVersions.Policy) &&
                StringComparer.Ordinal.Equals(workflowVersion, CoordinatorVersions.Workflow) &&
                StringComparer.Ordinal.Equals(
                    promptCatalogSha256,
                    CoordinatorVersions.ResearchPromptCatalogSha256),
            CoordinatorRunPurpose.StrategyAuthoring =>
                StringComparer.Ordinal.Equals(policyVersion, CoordinatorVersions.StrategyPolicy) &&
                StringComparer.Ordinal.Equals(workflowVersion, CoordinatorVersions.StrategyWorkflow) &&
                StringComparer.Ordinal.Equals(
                    promptCatalogSha256,
                    CoordinatorVersions.StrategyPromptCatalogSha256),
            _ => false,
        };

    private string ComputeExecutionProfileBinding(
        string executionSpecJson,
        ReadOnlySpan<byte> nonce)
    {
        using var payload = new MemoryStream();
        Append(payload, ExecutionBindingDomain);
        Append(payload, executionSpecJson);
        Append(payload, modelDeployment.ActivationSha256);
        return Convert.ToHexStringLower(HMACSHA256.HashData(
            nonce,
            payload.GetBuffer().AsSpan(0, checked((int)payload.Length))));
    }

    private static void Append(Stream output, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
        output.Write(length);
        output.Write(bytes);
    }
}

public sealed record VibeQuantExecutionResult(
    CoordinatorRunStatus Status,
    int CompletedRoleCount,
    CoordinatorUsage Usage,
    decimal BillableCostUsd,
    string? FinalArtifactSha256,
    string? SafeMessage);

public interface IVibeQuantExecutionRuntime
{
    Task<VibeQuantExecutionResult> ExecuteAsync(VibeQuantRun run, CancellationToken cancellationToken);

    Task<VibeQuantArtifactResponse> ReadArtifactAsync(
        VibeQuantRun run,
        string artifactSha256,
        CancellationToken cancellationToken);

    Task<VibeQuantExecutionResult> ApproveReleaseAsync(
        VibeQuantRun run,
        string artifactSha256,
        CancellationToken cancellationToken);

    Task CancelAsync(VibeQuantRun run, CancellationToken cancellationToken);
}

public sealed class VibeQuantExecutionRuntime(
    VibeQuantOptions options,
    IHttpClientFactory httpClientFactory,
    VibeQuantModelReadinessService modelReadiness,
    VibeQuantSpecificationFactory specificationFactory,
    ILogger<VibeQuantExecutionRuntime> logger) : IVibeQuantExecutionRuntime
{
    public async Task<VibeQuantExecutionResult> ExecuteAsync(
        VibeQuantRun run,
        CancellationToken cancellationToken)
    {
        RuntimeHandle? runtime = null;
        try
        {
            var spec = DeserializeExecutionSpec(run, requireCurrentActivation: true);
            runtime = CreateRuntime(run, spec, enableProviderDispatch: true);
            await runtime.Store.InitializeAsync(cancellationToken).ConfigureAwait(false);
            var existing = await runtime.Store.GetAsync(run.Id, cancellationToken).ConfigureAwait(false);
            var snapshot = existing is null
                ? await runtime.Coordinator.CreateAsync(spec, cancellationToken).ConfigureAwait(false)
                : await runtime.Store.GetVerifiedAsync(run.Id, cancellationToken).ConfigureAwait(false);
            snapshot = EnsureSnapshotBinding(run, snapshot);
            if (snapshot.Status == CoordinatorRunStatus.AwaitingStartApproval)
            {
                snapshot = EnsureSnapshotBinding(run, await runtime.Coordinator.ApproveStartAsync(
                    run.Id,
                    $"platform-account:{run.AccountId:D}",
                    ContentHasher.HashJson(snapshot.Spec),
                    cancellationToken).ConfigureAwait(false));
            }
            if (snapshot.Status is CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)
            {
                snapshot = EnsureSnapshotBinding(run, await runtime.Coordinator.ResumeAsync(
                    run.Id,
                    recordCancellation: false,
                    cancellationToken).ConfigureAwait(false));
            }
            return FromSnapshot(run, snapshot);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            var snapshot = runtime is null
                ? null
                : await TryReadSnapshotAsync(runtime.Store, run.Id, CancellationToken.None).ConfigureAwait(false);
            return snapshot is null
                ? CreateTrustedTerminalResult(
                    CoordinatorRunStatus.Cancelled,
                    "Vibe Quant execution was cancelled.")
                : CreateTerminalResultFromSnapshotOrIntegrityFailure(
                    run,
                    snapshot,
                    CoordinatorRunStatus.Cancelled,
                    "Vibe Quant execution was cancelled.");
        }
        catch (CoordinatorInvocationStillActiveException)
        {
            throw;
        }
        catch (CoordinatorIntegrityException exception)
        {
            VibeQuantLogging.ExecutionFailed(logger, run.Id, exception.GetType().Name, exception);
            return CreateIntegrityFailureResult();
        }
        catch (Exception exception)
        {
            VibeQuantLogging.ExecutionFailed(logger, run.Id, exception.GetType().Name, exception);
            var snapshot = runtime is null
                ? null
                : await TryReadSnapshotAsync(runtime.Store, run.Id, cancellationToken).ConfigureAwait(false);
            return snapshot is null
                ? CreateTrustedTerminalResult(
                    CoordinatorRunStatus.Failed,
                    "The server could not complete this Vibe Quant run.")
                : CreateTerminalResultFromSnapshotOrIntegrityFailure(
                    run,
                    snapshot,
                    CoordinatorRunStatus.Failed,
                    "The server could not complete this Vibe Quant run.");
        }
        finally
        {
            runtime?.Dispose();
        }
    }

    public async Task<VibeQuantArtifactResponse> ReadArtifactAsync(
        VibeQuantRun run,
        string artifactSha256,
        CancellationToken cancellationToken)
    {
        var spec = DeserializeExecutionSpec(run, requireCurrentActivation: false);
        using var runtime = CreateRuntime(run, spec, enableProviderDispatch: false);
        await runtime.Store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        var snapshot = await runtime.Store.GetVerifiedAsync(run.Id, cancellationToken).ConfigureAwait(false)
            ?? throw new PlatformNotFoundException("Vibe Quant artifact not found.");
        snapshot = EnsureSnapshotBinding(run, snapshot);
        var reference = snapshot.Artifacts.SingleOrDefault(item =>
            StringComparer.Ordinal.Equals(item.Sha256, artifactSha256));
        if (reference is null)
        {
            throw new PlatformNotFoundException("Vibe Quant artifact not found.");
        }
        if (reference.SchemaVersion == CoordinatorVersions.ArtifactSchema)
        {
            var output = await runtime.Artifacts.ReadJsonAsync<CoordinatorRoleOutput>(
                reference.RelativePath,
                reference.Sha256,
                cancellationToken).ConfigureAwait(false);
            return new VibeQuantArtifactResponse(run.Id, reference.Sha256, reference.Role, output);
        }
        if (reference.SchemaVersion == CoordinatorVersions.StrategyArtifactSchema)
        {
            var strategyArtifact = await runtime.Artifacts.ReadJsonAsync<CoordinatorStrategySourceArtifact>(
                reference.RelativePath,
                reference.Sha256,
                cancellationToken).ConfigureAwait(false);
            try
            {
                CoordinatorStrategyArtifactValidation.ValidateForRun(
                    strategyArtifact,
                    spec,
                    snapshot.Artifacts);
            }
            catch (InvalidDataException exception)
            {
                throw new CoordinatorIntegrityException(exception.Message);
            }
            return new VibeQuantArtifactResponse(
                run.Id,
                reference.Sha256,
                reference.Role,
                null,
                strategyArtifact);
        }
        throw new CoordinatorIntegrityException("Vibe Quant artifact schema is not supported.");
    }

    public async Task<VibeQuantExecutionResult> ApproveReleaseAsync(
        VibeQuantRun run,
        string artifactSha256,
        CancellationToken cancellationToken)
    {
        var spec = DeserializeExecutionSpec(run, requireCurrentActivation: false);
        using var runtime = CreateRuntime(run, spec, enableProviderDispatch: false);
        await runtime.Store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        var snapshot = await runtime.Store.GetVerifiedAsync(run.Id, cancellationToken).ConfigureAwait(false)
            ?? throw new PlatformNotFoundException("Vibe Quant run not found in the execution store.");
        snapshot = EnsureSnapshotBinding(run, snapshot);
        if (snapshot.Status == CoordinatorRunStatus.Completed)
        {
            if (!StringComparer.Ordinal.Equals(snapshot.FinalArtifactSha256, artifactSha256))
            {
                throw new CoordinatorIntegrityException(
                    "The completed execution snapshot does not match the approved artifact.");
            }
            return FromSnapshot(run, snapshot);
        }

        snapshot = EnsureSnapshotBinding(run, await runtime.Coordinator.ApproveReleaseAsync(
            run.Id,
            $"platform-account:{run.AccountId:D}",
            artifactSha256,
            cancellationToken).ConfigureAwait(false));
        return FromSnapshot(run, snapshot);
    }

    public async Task CancelAsync(VibeQuantRun run, CancellationToken cancellationToken)
    {
        var spec = DeserializeExecutionSpec(run, requireCurrentActivation: false);
        using var runtime = CreateRuntime(run, spec, enableProviderDispatch: false);
        await runtime.Store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        var snapshot = await runtime.Store.GetVerifiedAsync(run.Id, cancellationToken).ConfigureAwait(false);
        if (snapshot is not null)
        {
            snapshot = EnsureSnapshotBinding(run, snapshot);
        }
        if (snapshot is not null && snapshot.Status is not (
                CoordinatorRunStatus.Completed or
                CoordinatorRunStatus.Cancelled or
                CoordinatorRunStatus.Rejected))
        {
            await runtime.Coordinator.CancelAsync(
                run.Id,
                $"platform-account:{run.AccountId:D}",
                cancellationToken).ConfigureAwait(false);
        }
    }

    private RuntimeHandle CreateRuntime(
        VibeQuantRun run,
        CoordinatorRunSpec spec,
        bool enableProviderDispatch)
    {
        var accountPath = run.AccountId.ToString("N");
        var runPath = run.Id.ToString("N");
        var root = Path.GetFullPath(Path.Combine(options.WorkspacePath, "runs", accountPath, runPath));
        Directory.CreateDirectory(root);
        var store = new SqliteCoordinatorStore(Path.Combine(root, "coordinator.db"));
        var artifacts = new ContentAddressedArtifactStore(Path.Combine(root, "artifacts"));

        HttpClient? httpClient = null;
        ILlmProvider provider;
        if (!enableProviderDispatch)
        {
            provider = new NonDispatchingLlmProvider(spec.Provider);
        }
        else if (spec.Provider.Protocol == "mock")
        {
            provider = new DeterministicMockLlmProvider(spec.Provider);
        }
        else if (spec.Provider.Protocol == "openai-compatible")
        {
            var environmentVariable = spec.Provider.CredentialEnvironmentVariable;
            var apiKey = string.IsNullOrWhiteSpace(environmentVariable)
                ? null
                : Environment.GetEnvironmentVariable(environmentVariable);
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                throw new InvalidOperationException("The server-side Vibe Quant provider credential is unavailable.");
            }
            httpClient = httpClientFactory.CreateClient("VibeQuantLlm");
            provider = new ReadinessGatedLlmProvider(
                new OpenAiCompatibleLlmProvider(
                    httpClient,
                    spec.Provider,
                    apiKey,
                    spec.Budget.MaxResponseBytes),
                modelReadiness);
        }
        else
        {
            throw new InvalidOperationException(
                $"Stored Vibe Quant provider protocol '{spec.Provider.Protocol}' is unsupported.");
        }

        return new RuntimeHandle(
            store,
            artifacts,
            new ResearchCoordinator(store, artifacts, provider),
            httpClient);
    }

    private CoordinatorRunSpec DeserializeExecutionSpec(
        VibeQuantRun run,
        bool requireCurrentActivation)
    {
        var spec = JsonSerializer.Deserialize<CoordinatorRunSpec>(run.ExecutionSpecJson, CoordinatorJson.Options)
            ?? throw new CoordinatorIntegrityException("The server-side run specification was JSON null.");
        if (!StringComparer.Ordinal.Equals(ContentHasher.HashJson(spec), run.ExecutionSpecSha256) ||
            requireCurrentActivation &&
            (!specificationFactory.IsCurrentExecutionProfileBinding(
                 run.ExecutionSpecJson,
                 run.ExecutionBindingNonce,
                 run.ExecutionProfileBinding) ||
             !specificationFactory.IsCurrentCoordinatorProfile(
                 spec.Purpose,
                 spec.PolicyVersion,
                 spec.WorkflowVersion,
                 spec.PromptCatalogSha256)) ||
            spec.RunId != run.Id ||
            !StringComparer.Ordinal.Equals(spec.Owner, run.AccountId.ToString("D")))
        {
            throw new CoordinatorIntegrityException(
                "The server-side Vibe Quant execution specification failed its stored binding.");
        }
        return spec;
    }

    private static CoordinatorRunSnapshot EnsureSnapshotBinding(
        VibeQuantRun run,
        CoordinatorRunSnapshot? snapshot)
    {
        if (snapshot is null)
        {
            throw new CoordinatorIntegrityException(
                "The Vibe Quant execution snapshot was unexpectedly absent.");
        }
        if (snapshot.Spec.RunId != run.Id ||
            !StringComparer.Ordinal.Equals(snapshot.Spec.Owner, run.AccountId.ToString("D")) ||
            !StringComparer.Ordinal.Equals(
                ContentHasher.HashJson(snapshot.Spec),
                run.ExecutionSpecSha256))
        {
            throw new CoordinatorIntegrityException(
                "The Vibe Quant coordinator snapshot does not match its frozen execution specification.");
        }
        return snapshot;
    }

    private static VibeQuantExecutionResult FromSnapshot(
        VibeQuantRun run,
        CoordinatorRunSnapshot snapshot)
    {
        snapshot = EnsureSnapshotBinding(run, snapshot);
        return new(
            snapshot.Status,
            snapshot.CompletedRoleCount,
            snapshot.Usage,
            CalculateBillableCost(snapshot),
            snapshot.FinalArtifactSha256,
            snapshot.SafeMessage);
    }

    private VibeQuantExecutionResult CreateTerminalResultFromSnapshotOrIntegrityFailure(
        VibeQuantRun run,
        CoordinatorRunSnapshot snapshot,
        CoordinatorRunStatus status,
        string safeMessage)
    {
        try
        {
            return FromSnapshot(run, snapshot) with
            {
                Status = status,
                SafeMessage = safeMessage
            };
        }
        catch (CoordinatorIntegrityException exception)
        {
            VibeQuantLogging.ExecutionFailed(logger, run.Id, exception.GetType().Name, exception);
            return CreateIntegrityFailureResult();
        }
    }

    private static VibeQuantExecutionResult CreateIntegrityFailureResult() =>
        CreateTrustedTerminalResult(
            CoordinatorRunStatus.Failed,
            "The server rejected inconsistent Vibe Quant execution state.");

    private static VibeQuantExecutionResult CreateTrustedTerminalResult(
        CoordinatorRunStatus status,
        string safeMessage) => new(
            status,
            0,
            new CoordinatorUsage(),
            0m,
            null,
            safeMessage);

    private static decimal CalculateBillableCost(CoordinatorRunSnapshot snapshot)
    {
        decimal inputTokens = 0m;
        decimal outputTokens = 0m;
        foreach (var invocation in snapshot.Invocations)
        {
            if (invocation.Status != "Completed" || invocation.ReportedUsage is null)
            {
                continue;
            }
            inputTokens = checked(inputTokens + invocation.ReportedUsage.InputTokens);
            outputTokens = checked(outputTokens + invocation.ReportedUsage.OutputTokens);
        }
        return checked(
            inputTokens * snapshot.Spec.Provider.InputUsdPerMillionTokens / 1_000_000m +
            outputTokens * snapshot.Spec.Provider.OutputUsdPerMillionTokens / 1_000_000m);
    }

    private static async Task<CoordinatorRunSnapshot?> TryReadSnapshotAsync(
        ICoordinatorStore store,
        Guid runId,
        CancellationToken cancellationToken)
    {
        try
        {
            return await store.GetVerifiedAsync(runId, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
    }

    private sealed class RuntimeHandle(
        ICoordinatorStore store,
        ICoordinatorArtifactStore artifacts,
        ResearchCoordinator coordinator,
        HttpClient? httpClient) : IDisposable
    {
        public ICoordinatorStore Store { get; } = store;

        public ICoordinatorArtifactStore Artifacts { get; } = artifacts;

        public ResearchCoordinator Coordinator { get; } = coordinator;

        public void Dispose() => httpClient?.Dispose();
    }

    private sealed class NonDispatchingLlmProvider(LlmProviderDescriptor descriptor) : ILlmProvider
    {
        public LlmProviderDescriptor Descriptor { get; } = descriptor;

        public Task<LlmCallResult> CompleteAsync(
            LlmRequest request,
            CancellationToken ct = default) => Task.FromResult(LlmCallResult.Failed(
            LlmFailureKinds.ProviderUnavailable,
            "Provider dispatch is disabled for this operation.",
            retryable: false,
            responseBytes: 0));
    }

    internal sealed class ReadinessGatedLlmProvider(
        ILlmProvider inner,
        VibeQuantModelReadinessService readiness) : ILlmProvider
    {
        public LlmProviderDescriptor Descriptor => inner.Descriptor;

        public Task<LlmCallResult> CompleteAsync(
            LlmRequest request,
            CancellationToken ct = default) =>
            readiness.IsReadyFor(Descriptor.ModelId)
                ? inner.CompleteAsync(request, ct)
                : Task.FromResult(LlmCallResult.Failed(
                    LlmFailureKinds.ProviderUnavailable,
                    "The Vibe Quant execution model is not ready.",
                    retryable: true,
                    responseBytes: 0));
    }
}
