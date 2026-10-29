using System.Net;
using Hyperion.FreeStrategyWorkflow;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;

namespace DaxAlgo.Coordinator.Cli;

internal sealed class FreeStrategyWorkflowCliRuntime : IDisposable
{
    private FreeStrategyWorkflowCliRuntime(
        FreeStrategyWorkflowCliConfig config,
        HttpClient? httpClient,
        FreeStrategyWorkflowWorkspace workspace)
    {
        Config = config;
        HttpClient = httpClient;
        Workspace = workspace;
    }

    public FreeStrategyWorkflowCliConfig Config { get; }

    public HttpClient? HttpClient { get; }

    public FreeStrategyWorkflowWorkspace Workspace { get; }

    public static async Task<FreeStrategyWorkflowCliRuntime> CreateAsync(
        string configPath,
        string workspacePath,
        bool requireCredential,
        CancellationToken cancellationToken,
        Func<HttpMessageHandler>? httpHandlerFactory = null)
    {
        var config = await FreeStrategyWorkflowCliConfigLoader.LoadAsync(configPath, cancellationToken)
            .ConfigureAwait(false);
        if (config.Provider.Protocol == LlmProviderProtocols.Mock)
        {
            var mock = new DeterministicMockLlmProvider(config.Provider.ToDescriptor());
            return new FreeStrategyWorkflowCliRuntime(
                config,
                httpClient: null,
                new FreeStrategyWorkflowWorkspace(workspacePath, mock));
        }

        var descriptor = config.Provider.ToDescriptor();
        if (!requireCredential)
        {
            return new FreeStrategyWorkflowCliRuntime(
                config,
                httpClient: null,
                new FreeStrategyWorkflowWorkspace(
                    workspacePath,
                    new ReadOnlyLlmProvider(descriptor)));
        }

        string? credential = null;
        var variable = config.Provider.CredentialEnvironmentVariable;
        if (variable is not null)
        {
            credential = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(credential) ||
                credential.IndexOfAny(['\r', '\n']) >= 0 ||
                !StringComparer.Ordinal.Equals(credential, credential.Trim()))
            {
                throw new InvalidOperationException(
                    $"The configured provider credential environment variable '{variable}' is empty or invalid.");
            }
        }

        var handler = httpHandlerFactory?.Invoke() ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            Credentials = null,
            UseCookies = false,
            UseProxy = false,
        };
        var httpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        try
        {
            ILlmProvider provider = config.Provider.Protocol switch
            {
                LlmProviderProtocols.OpenAiCompatible => new OpenAiCompatibleLlmProvider(
                    httpClient,
                    descriptor,
                    credential),
                LlmProviderProtocols.AnthropicMessages => new AnthropicMessagesLlmProvider(
                    httpClient,
                    descriptor,
                    credential ?? throw MissingCredential(variable)),
                LlmProviderProtocols.GoogleGemini => new GoogleGeminiLlmProvider(
                    httpClient,
                    descriptor,
                    credential ?? throw MissingCredential(variable)),
                _ => throw new InvalidOperationException(
                    $"Unsupported live provider protocol '{config.Provider.Protocol}'."),
            };
            var workspace = new FreeStrategyWorkflowWorkspace(workspacePath, provider);
            return new FreeStrategyWorkflowCliRuntime(config, httpClient, workspace);
        }
        catch
        {
            httpClient.Dispose();
            throw;
        }
    }

    public void Dispose() => HttpClient?.Dispose();

    private static InvalidOperationException MissingCredential(string? variable) => new(
        variable is null
            ? "The selected provider profile requires a credential environment variable."
            : $"The configured provider credential environment variable '{variable}' is empty or invalid.");

    private sealed class ReadOnlyLlmProvider(LlmProviderDescriptor descriptor) : ILlmProvider
    {
        public LlmProviderDescriptor Descriptor { get; } = descriptor;

        public Task<LlmCallResult> CompleteAsync(
            LlmRequest request,
            CancellationToken ct = default) =>
            Task.FromResult(LlmCallResult.Failed(
                LlmFailureKinds.InvalidRequest,
                "This read-only workflow operation cannot dispatch a provider request."));
    }
}
