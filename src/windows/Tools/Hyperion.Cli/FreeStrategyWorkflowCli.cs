using System.Globalization;
using System.Text;
using System.Text.Json;
using Hyperion.FreeStrategyWorkflow;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Coordinator.Cli;

internal sealed class FreeStrategyWorkflowCli(
    TextWriter output,
    Func<HttpMessageHandler>? httpHandlerFactory = null)
{
    public Task<int> RunAsync(CliArguments args, CancellationToken cancellationToken) =>
        args.Positionals[1] switch
        {
            "init" => InitAsync(args, cancellationToken),
            "create" => CreateAsync(args, cancellationToken),
            "start" => StartAsync(args, cancellationToken),
            "status" => StatusAsync(args, cancellationToken),
            "show" => ShowAsync(args, cancellationToken),
            "gauntlet" => GauntletAsync(args, cancellationToken),
            "revise" => ReviseAsync(args, cancellationToken),
            "release" => ReleaseAsync(args, cancellationToken),
            _ => throw new ArgumentException(
                $"Unknown workflow command '{args.Positionals[1]}'. Use 'hyperion workflow --help'."),
        };

    private async Task<int> InitAsync(CliArguments args, CancellationToken cancellationToken)
    {
        var path = Path.GetFullPath(args.Optional("config") ?? "free-strategy-workflow.json");
        if (File.Exists(path))
        {
            throw new IOException($"Refusing to overwrite existing config '{path}'.");
        }

        var profileId = ResolveProfileId(args);
        var profile = FreeStrategyProviderProfiles.Get(profileId);
        if (args.Optional("protocol") is { } requestedProtocol &&
            !StringComparer.Ordinal.Equals(requestedProtocol, profile.Protocol))
        {
            throw new ArgumentException(
                $"Provider profile '{profileId}' requires protocol '{profile.Protocol}'.");
        }
        var isMock = profile.Protocol == LlmProviderProtocols.Mock;
        var endpoint = args.Optional("endpoint") ?? profile.Endpoint;
        if (profile.AllowsEndpointOverride && endpoint is null)
        {
            throw new ArgumentException("--endpoint is required for a custom provider profile.");
        }
        string? credentialEnvironmentVariable = profile.CredentialEnvironmentVariable;
        if (profile.AllowsEndpointOverride)
        {
            var endpointUri = LlmProviderValidation.ValidateEndpoint(endpoint);
            var expectedVariable = FreeStrategyProviderProfiles.CredentialVariableForCustomEndpoint(endpointUri);
            credentialEnvironmentVariable = endpointUri.IsLoopback && !args.Has("token-env")
                ? null
                : expectedVariable;
        }
        if (args.Optional("token-env") is { } requestedVariable &&
            !StringComparer.Ordinal.Equals(requestedVariable, credentialEnvironmentVariable))
        {
            throw new ArgumentException(
                "--token-env must match the provider profile's origin-bound credential slot.");
        }
        var config = new FreeStrategyWorkflowCliConfig
        {
            AllowRemoteProviderDataEgress = args.Has("allow-provider-egress"),
            AllowCustomProviderEndpoint = args.Has("allow-custom-provider"),
            Provider = new FreeStrategyWorkflowProviderConfig
            {
                ProfileId = profileId,
                Protocol = profile.Protocol,
                ProviderId = args.Optional("provider") ?? profile.ProviderId,
                ModelId = args.Optional("model") ?? (isMock ? "deterministic-v1" :
                    throw new ArgumentException("--model is required for a live provider.")),
                Endpoint = endpoint,
                CredentialEnvironmentVariable = credentialEnvironmentVariable,
                InputUsdPerMillionTokens = ParseDecimal(args.Optional("input-price"), "--input-price"),
                OutputUsdPerMillionTokens = ParseDecimal(args.Optional("output-price"), "--output-price"),
            }
        };
        FreeStrategyWorkflowCliConfigLoader.Validate(config);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(config, CoordinatorJson.Options),
            new UTF8Encoding(false),
            cancellationToken).ConfigureAwait(false);
        await output.WriteLineAsync($"Created {path}").ConfigureAwait(false);
        await output.WriteLineAsync(
            "The config stores an environment-variable name only; it never stores a provider secret.")
            .ConfigureAwait(false);
        if (credentialEnvironmentVariable is not null)
        {
            await output.WriteLineAsync(
                $"Set {credentialEnvironmentVariable} in the launch environment before workflow start.")
                .ConfigureAwait(false);
        }
        return 0;
    }

    private async Task<int> CreateAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: false, cancellationToken)
            .ConfigureAwait(false);
        var objective = await CliApplication.ReadBoundedUtf8TextAsync(
            args.Required("brief"),
            CliApplication.MaxBriefFileBytes,
            TradingTerminal.Ai.Coordinator.Orchestration.CoordinatorValidation.MaxObjectiveCharacters,
            "Free-workflow brief",
            cancellationToken).ConfigureAwait(false);
        var sources = await CliApplication.ReadSourcesAsync(args.All("source"), cancellationToken)
            .ConfigureAwait(false);
        var request = new FreeStrategyWorkflowRequest
        {
            Objective = objective,
            Owner = args.Optional("owner") ?? Environment.UserName,
            Sources = sources,
            Budget = runtime.Config.Budget,
        };
        var draft = await runtime.Workspace.Runner.CreateAsync(request, cancellationToken)
            .ConfigureAwait(false);
        await PrintDraftAsync(draft).ConfigureAwait(false);
        return 0;
    }

    private async Task<int> StartAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: true, cancellationToken)
            .ConfigureAwait(false);
        var result = await runtime.Workspace.Runner.StartAsync(
            CliApplication.ParseRunId(args),
            Actor(args),
            RequireSha256(args.Required("spec"), "--spec"),
            cancellationToken).ConfigureAwait(false);
        await PrintResultAsync(result).ConfigureAwait(false);
        return result.Snapshot.Status == CoordinatorRunStatus.AwaitingReleaseApproval ? 0 : 2;
    }

    private async Task<int> StatusAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: false, cancellationToken)
            .ConfigureAwait(false);
        var result = await runtime.Workspace.Runner.GetAsync(
            CliApplication.ParseRunId(args),
            cancellationToken).ConfigureAwait(false);
        await PrintResultAsync(result).ConfigureAwait(false);
        return 0;
    }

    private async Task<int> ShowAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: false, cancellationToken)
            .ConfigureAwait(false);
        var result = await runtime.Workspace.Runner.GetAsync(
            CliApplication.ParseRunId(args),
            cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(result.StrategyArtifact ?? (object)result.Snapshot).ConfigureAwait(false);
        return result.StrategyArtifact is null ? 2 : 0;
    }

    private async Task<int> GauntletAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: false, cancellationToken)
            .ConfigureAwait(false);
        var report = await runtime.Workspace.Runner.InspectGauntletAsync(
            CliApplication.ParseRunId(args),
            cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(report).ConfigureAwait(false);
        return report.ProcessIntegrityPassed ? 0 : 2;
    }

    private async Task<int> ReviseAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: false, cancellationToken)
            .ConfigureAwait(false);
        var changeRequest = await CliApplication.ReadBoundedUtf8TextAsync(
            args.Required("request"),
            CliApplication.MaxSourceFileBytes,
            TradingTerminal.Ai.Coordinator.Orchestration.CoordinatorValidation.MaxSourceContentCharacters,
            "Free-workflow repair request",
            cancellationToken).ConfigureAwait(false);
        string? diagnostics = null;
        if (args.Optional("diagnostics") is { } diagnosticsPath)
        {
            diagnostics = await CliApplication.ReadBoundedUtf8TextAsync(
                diagnosticsPath,
                CliApplication.MaxSourceFileBytes,
                TradingTerminal.Ai.Coordinator.Orchestration.CoordinatorValidation.MaxSourceContentCharacters,
                "Free-workflow diagnostics",
                cancellationToken).ConfigureAwait(false);
        }

        var draft = await runtime.Workspace.Runner.CreateRevisionAsync(
            new FreeStrategyWorkflowRevisionRequest
            {
                ParentRunId = CliApplication.ParseRunId(args),
                Owner = args.Optional("owner") ?? Environment.UserName,
                ChangeRequest = changeRequest,
                Diagnostics = diagnostics,
                Budget = runtime.Config.Budget,
            },
            cancellationToken).ConfigureAwait(false);
        await PrintDraftAsync(draft).ConfigureAwait(false);
        return 0;
    }

    private async Task<int> ReleaseAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, requireCredential: false, cancellationToken)
            .ConfigureAwait(false);
        var snapshot = await runtime.Workspace.Runner.ApproveReleaseAsync(
            CliApplication.ParseRunId(args),
            Actor(args),
            RequireSha256(args.Required("artifact"), "--artifact"),
            cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(snapshot).ConfigureAwait(false);
        return 0;
    }

    private Task PrintResultAsync(FreeStrategyWorkflowResult result) => PrintJsonAsync(new
    {
        schemaVersion = FreeStrategyWorkflowVersions.Manifest,
        result.Snapshot.Spec.RunId,
        result.Snapshot.Status,
        result.Snapshot.FinalArtifactSha256,
        result.Snapshot.Usage,
        result.Snapshot.SafeMessage,
        hasStrategyArtifact = result.StrategyArtifact is not null,
        requiresHumanRelease = result.StrategyArtifact?.RequiresHumanRelease,
        requiresTerminalCompileConsent = result.StrategyArtifact?.RequiresTerminalCompileConsent,
        installEligible = result.StrategyArtifact?.InstallEligible,
    });

    private Task PrintDraftAsync(FreeStrategyWorkflowDraft draft) => PrintJsonAsync(new
    {
        schemaVersion = FreeStrategyWorkflowVersions.Manifest,
        draft.Snapshot.Spec.RunId,
        draft.Snapshot.Status,
        specificationSha256 = draft.SpecificationSha256,
        specification = draft.Snapshot.Spec,
        next = "Review the specification, then call workflow start with its exact SHA-256."
    });

    private Task PrintJsonAsync<T>(T value) =>
        output.WriteLineAsync(JsonSerializer.Serialize(value, CoordinatorJson.Options));

    private Task<FreeStrategyWorkflowCliRuntime> OpenRuntimeAsync(
        CliArguments args,
        bool requireCredential,
        CancellationToken cancellationToken) =>
        FreeStrategyWorkflowCliRuntime.CreateAsync(
            args.Required("config"),
            args.Required("workspace"),
            requireCredential,
            cancellationToken,
            httpHandlerFactory);

    private static string Actor(CliArguments args) => args.Optional("actor") ?? Environment.UserName;

    private static string RequireSha256(string value, string option) =>
        CoordinatorStrategyArtifactValidation.IsSha256(value)
            ? value
            : throw new ArgumentException($"{option} must be a lowercase SHA-256 value.");

    private static decimal ParseDecimal(string? value, string option)
    {
        if (value is null)
        {
            return 0m;
        }
        return decimal.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
             : throw new ArgumentException($"{option} must be an invariant decimal value.");
    }

    private static string ResolveProfileId(CliArguments args)
    {
        if (args.Optional("profile") is { } explicitProfile)
        {
            return explicitProfile;
        }
        if (args.Optional("protocol") == LlmProviderProtocols.Mock)
        {
            return FreeStrategyProviderProfiles.Mock;
        }

        var endpoint = args.Optional("endpoint");
        var provider = args.Optional("provider");
        if ((endpoint is null || StringComparer.Ordinal.Equals(
                endpoint,
                "http://127.0.0.1:11434/v1")) &&
            (provider is null || provider is "local" or "ollama"))
        {
            return FreeStrategyProviderProfiles.Ollama;
        }
        return FreeStrategyProviderProfiles.CustomOpenAiCompatible;
    }

    public static Task PrintHelpAsync(TextWriter writer) => writer.WriteLineAsync("""
        hyperion workflow - free local/BYOK strategy-authoring workflow

          workflow init --config FILE [--profile mock|ollama|openai|openrouter|groq|mistral|deepseek|anthropic|gemini|custom-openai-compatible]
                        [--model ID] [--provider ID] [--endpoint URL]
                        [--token-env ORIGIN_BOUND_NAME]
                        [--input-price USD_PER_MILLION] [--output-price USD_PER_MILLION]
                        [--allow-provider-egress] [--allow-custom-provider]
          workflow create --config FILE --workspace DIR --brief FILE [--source ID=FILE]
                          [--owner ID]
          workflow start --config FILE --workspace DIR --run ID --spec SHA256 [--actor ID]
          workflow status --config FILE --workspace DIR --run ID
          workflow show --config FILE --workspace DIR --run ID
          workflow gauntlet --config FILE --workspace DIR --run ID
          workflow revise --config FILE --workspace DIR --run PARENT_ID --request FILE
                          [--diagnostics FILE] [--owner ID]
          workflow release --config FILE --workspace DIR --run ID --artifact SHA256 [--actor ID]

        `init` defaults to local OpenAI-compatible/Ollama at http://127.0.0.1:11434/v1. Use profile
        `mock` for a network-free rehearsal. Built-in remote profiles pin their official origin,
        native protocol, authentication scheme, and dedicated DAXALGO_LLM_* credential slot.
        The OpenAI profile uses the Chat Completions compatibility shape and rejects o-series models;
        a native OpenAI Responses profile is not implemented.
        Remote HTTPS endpoints require positive declared input/output prices.
        They also require --allow-provider-egress because the brief and supplied sources leave the device.
        A custom remote OpenAI-compatible endpoint additionally requires --allow-custom-provider and
        receives only a credential slot containing its canonical origin's full SHA-256.
        Provider secrets are never stored in the config, workspace, run specification, or artifacts.
        The workflow consumes no hosted Hyperion credits. Third-party provider charges remain external.
        Output is inert source: release approval and separate Terminal compile consent are mandatory.
        `gauntlet` verifies workflow hashes, approvals, role coverage, judge approval, and inert artifact
        lineage only. It does not compile, test, backtest, or guarantee semantic correctness.
        `revise` creates a new hash-bound run from the exact parent draft/review and optional diagnostics.
        It permits at most two repair rounds; every round requires fresh start and release approval.
        Repeat the exact workflow start command after an unclean process exit while the run remains
        Ready or Running. An explicit cancellation is terminal and does not resume.
        Local workspaces and review output contain plaintext user/model content; protect their storage and logs.
        """);
}
