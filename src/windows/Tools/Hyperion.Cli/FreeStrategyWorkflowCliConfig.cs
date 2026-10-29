using System.Text.Json;
using System.Text.Json.Serialization;
using Hyperion.FreeStrategyWorkflow;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Coordinator.Cli;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FreeStrategyWorkflowCliConfig
{
    public const string CurrentSchemaVersion = "hyperion-free-strategy-workflow-client/v2";

    public string SchemaVersion { get; init; } = CurrentSchemaVersion;

    public required FreeStrategyWorkflowProviderConfig Provider { get; init; }

    public CoordinatorBudget Budget { get; init; } = FreeStrategyWorkflowDefaults.CreateBudget();

    public bool AllowRemoteProviderDataEgress { get; init; }

    public bool AllowCustomProviderEndpoint { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record FreeStrategyWorkflowProviderConfig
{
    public required string ProfileId { get; init; }

    public string Protocol { get; init; } = LlmProviderProtocols.OpenAiCompatible;

    public required string ProviderId { get; init; }

    public required string ModelId { get; init; }

    public string? Endpoint { get; init; }

    public string? CredentialEnvironmentVariable { get; init; }

    public decimal InputUsdPerMillionTokens { get; init; }

    public decimal OutputUsdPerMillionTokens { get; init; }

    public LlmProviderDescriptor ToDescriptor() => new(
        ProviderId,
        ModelId,
        Protocol,
        Endpoint,
        InputUsdPerMillionTokens,
        OutputUsdPerMillionTokens,
        CredentialEnvironmentVariable);
}

internal sealed record FreeStrategyProviderProfile(
    string Id,
    string Protocol,
    string ProviderId,
    string? Endpoint,
    string? CredentialEnvironmentVariable,
    bool AllowsEndpointOverride = false,
    bool AllowsProviderIdOverride = false);

internal static class FreeStrategyProviderProfiles
{
    internal const string Mock = "mock";
    internal const string Ollama = "ollama";
    internal const string OpenAi = "openai";
    internal const string OpenRouter = "openrouter";
    internal const string Groq = "groq";
    internal const string Mistral = "mistral";
    internal const string DeepSeek = "deepseek";
    internal const string Anthropic = "anthropic";
    internal const string Gemini = "gemini";
    internal const string CustomOpenAiCompatible = "custom-openai-compatible";

    private static readonly IReadOnlyDictionary<string, FreeStrategyProviderProfile> Profiles =
        new Dictionary<string, FreeStrategyProviderProfile>(StringComparer.Ordinal)
        {
            [Mock] = new(Mock, LlmProviderProtocols.Mock, "mock", null, null),
            [Ollama] = new(
                Ollama,
                LlmProviderProtocols.OpenAiCompatible,
                "ollama",
                "http://127.0.0.1:11434/v1",
                null),
            [OpenAi] = new(
                OpenAi,
                LlmProviderProtocols.OpenAiCompatible,
                "openai",
                "https://api.openai.com/v1",
                "DAXALGO_LLM_OPENAI_API_KEY"),
            [OpenRouter] = new(
                OpenRouter,
                LlmProviderProtocols.OpenAiCompatible,
                "openrouter",
                "https://openrouter.ai/api/v1",
                "DAXALGO_LLM_OPENROUTER_API_KEY"),
            [Groq] = new(
                Groq,
                LlmProviderProtocols.OpenAiCompatible,
                "groq",
                "https://api.groq.com/openai/v1",
                "DAXALGO_LLM_GROQ_API_KEY"),
            [Mistral] = new(
                Mistral,
                LlmProviderProtocols.OpenAiCompatible,
                "mistral",
                "https://api.mistral.ai/v1",
                "DAXALGO_LLM_MISTRAL_API_KEY"),
            [DeepSeek] = new(
                DeepSeek,
                LlmProviderProtocols.OpenAiCompatible,
                "deepseek",
                "https://api.deepseek.com/v1",
                "DAXALGO_LLM_DEEPSEEK_API_KEY"),
            [Anthropic] = new(
                Anthropic,
                LlmProviderProtocols.AnthropicMessages,
                "anthropic",
                "https://api.anthropic.com/v1",
                "DAXALGO_LLM_ANTHROPIC_API_KEY"),
            [Gemini] = new(
                Gemini,
                LlmProviderProtocols.GoogleGemini,
                "google-gemini",
                "https://generativelanguage.googleapis.com/v1beta",
                "DAXALGO_LLM_GEMINI_API_KEY"),
            [CustomOpenAiCompatible] = new(
                CustomOpenAiCompatible,
                LlmProviderProtocols.OpenAiCompatible,
                "custom",
                null,
                null,
                AllowsEndpointOverride: true,
                AllowsProviderIdOverride: true),
        };

    internal static FreeStrategyProviderProfile Get(string profileId) =>
        Profiles.TryGetValue(profileId, out var profile)
            ? profile
            : throw new InvalidDataException(
                $"Unknown provider profile '{profileId}'. Supported profiles: {string.Join(", ", Profiles.Keys)}.");

    internal static string CredentialVariableForCustomEndpoint(Uri endpoint)
    {
        var origin = endpoint.GetComponents(
            UriComponents.SchemeAndServer,
            UriFormat.UriEscaped).TrimEnd('/').ToLowerInvariant();
        return $"DAXALGO_LLM_CUSTOM_{ContentHasher.HashUtf8(origin).ToUpperInvariant()}";
    }
}

public static class FreeStrategyWorkflowCliConfigLoader
{
    public const int MaxConfigBytes = 1_000_000;

    public static async Task<FreeStrategyWorkflowCliConfig> LoadAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > MaxConfigBytes)
        {
            throw new InvalidDataException(
                $"Free-workflow config exceeds the {MaxConfigBytes:N0}-byte input limit.");
        }

        var config = await JsonSerializer.DeserializeAsync<FreeStrategyWorkflowCliConfig>(
                stream,
                CoordinatorJson.Options,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException("Free-workflow config must not be JSON null.");
        Validate(config);
        return config;
    }

    public static void Validate(FreeStrategyWorkflowCliConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (config.SchemaVersion != FreeStrategyWorkflowCliConfig.CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"schemaVersion must be '{FreeStrategyWorkflowCliConfig.CurrentSchemaVersion}'.");
        }
        if (config.Provider is null || config.Budget is null)
        {
            throw new InvalidDataException("provider and budget are required.");
        }

        var profile = FreeStrategyProviderProfiles.Get(config.Provider.ProfileId);
        if (!StringComparer.Ordinal.Equals(config.Provider.Protocol, profile.Protocol))
        {
            throw new InvalidDataException(
                $"Provider profile '{profile.Id}' requires protocol '{profile.Protocol}'.");
        }
        if (!profile.AllowsProviderIdOverride &&
            !StringComparer.Ordinal.Equals(config.Provider.ProviderId, profile.ProviderId))
        {
            throw new InvalidDataException(
                $"Provider profile '{profile.Id}' requires provider ID '{profile.ProviderId}'.");
        }
        if (!profile.AllowsEndpointOverride &&
            !StringComparer.Ordinal.Equals(config.Provider.Endpoint, profile.Endpoint))
        {
            throw new InvalidDataException(
                $"Provider profile '{profile.Id}' requires its fixed canonical endpoint.");
        }
        if (!profile.AllowsEndpointOverride &&
            !StringComparer.Ordinal.Equals(
                config.Provider.CredentialEnvironmentVariable,
                profile.CredentialEnvironmentVariable))
        {
            throw new InvalidDataException(
                $"Provider profile '{profile.Id}' requires its origin-bound credential slot.");
        }
        if (profile.Id == FreeStrategyProviderProfiles.OpenAi &&
            IsOpenAiReasoningModel(config.Provider.ModelId))
        {
            throw new InvalidDataException(
                "The OpenAI profile uses the Chat Completions compatibility adapter, whose max_tokens request is not compatible with o-series models. A native Responses profile is not implemented.");
        }

        if (config.Provider.Protocol is
            LlmProviderProtocols.OpenAiCompatible or
            LlmProviderProtocols.AnthropicMessages or
            LlmProviderProtocols.GoogleGemini)
        {
            var endpoint = LlmProviderValidation.ValidateEndpoint(config.Provider.Endpoint);
            if (!endpoint.IsLoopback && !config.AllowRemoteProviderDataEgress)
            {
                throw new InvalidDataException(
                    "A remote provider requires explicit allowRemoteProviderDataEgress consent.");
            }
            if (profile.AllowsEndpointOverride)
            {
                var expectedVariable = FreeStrategyProviderProfiles.CredentialVariableForCustomEndpoint(endpoint);
                if (!endpoint.IsLoopback && !config.AllowCustomProviderEndpoint)
                {
                    throw new InvalidDataException(
                        "A remote custom endpoint requires explicit allowCustomProviderEndpoint consent.");
                }
                if ((!endpoint.IsLoopback || config.Provider.CredentialEnvironmentVariable is not null) &&
                    !StringComparer.Ordinal.Equals(
                        config.Provider.CredentialEnvironmentVariable,
                        expectedVariable))
                {
                    throw new InvalidDataException(
                        "A custom endpoint must use its origin-bound DAXALGO_LLM_CUSTOM_* credential slot.");
                }
            }
            else if (!profile.AllowsEndpointOverride && config.AllowCustomProviderEndpoint)
            {
                throw new InvalidDataException(
                    "allowCustomProviderEndpoint is valid only for a custom provider profile.");
            }
        }
        else if (config.Provider.Protocol == LlmProviderProtocols.Mock)
        {
            if (config.Provider.Endpoint is not null ||
                config.Provider.CredentialEnvironmentVariable is not null ||
                config.Provider.InputUsdPerMillionTokens != 0m ||
                config.Provider.OutputUsdPerMillionTokens != 0m ||
                 config.AllowRemoteProviderDataEgress ||
                 config.AllowCustomProviderEndpoint)
            {
                throw new InvalidDataException(
                    "The deterministic mock protocol cannot configure an endpoint, credential, prices, or provider egress.");
            }
        }
        else
        {
            throw new InvalidDataException(
                "CLI protocol must be mock, OpenAI-compatible, Anthropic Messages, or Google Gemini.");
        }

        try
        {
            CoordinatorValidation.ValidateSpec(new CoordinatorRunSpec(
                Guid.NewGuid(),
                "Validate the local free-workflow configuration.",
                "hyperion-cli-config-validation",
                DateTimeOffset.UtcNow,
                [],
                config.Provider.ToDescriptor(),
                config.Budget,
                CoordinatorVersions.FreeStrategyPolicy,
                CoordinatorVersions.FreeStrategyWorkflow,
                CoordinatorPromptCatalog.StrategySha256,
                CoordinatorRunPurpose.StrategyAuthoring));
        }
        catch (CoordinatorValidationException exception)
        {
            throw new InvalidDataException(exception.Message, exception);
        }
    }

    private static bool IsOpenAiReasoningModel(string modelId) =>
        modelId.Length >= 2 &&
        (modelId[0] is 'o' or 'O') &&
        char.IsAsciiDigit(modelId[1]) &&
        (modelId.Length == 2 || modelId[2] == '-');
}
