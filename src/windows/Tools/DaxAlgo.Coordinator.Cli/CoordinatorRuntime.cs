using System.Net.Http.Headers;
using TradingTerminal.Ai.Coordinator.Client;

namespace DaxAlgo.Coordinator.Cli;

internal sealed class CoordinatorRuntime : IDisposable
{
    private CoordinatorRuntime(CoordinatorCliConfig config, HttpClient httpClient)
    {
        Config = config;
        HttpClient = httpClient;
        Client = new VibeQuantApiClient(httpClient);
    }

    public CoordinatorCliConfig Config { get; }

    public HttpClient HttpClient { get; }

    public IVibeQuantApiClient Client { get; }

    public static async Task<CoordinatorRuntime> CreateAsync(
        string configPath,
        CancellationToken cancellationToken)
    {
        var config = await CoordinatorCliConfigLoader.LoadAsync(configPath, cancellationToken)
            .ConfigureAwait(false);
        var endpoint = new Uri(config.ServerBaseUrl, UriKind.Absolute);
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(endpoint.GetLeftPart(UriPartial.Authority)),
            Timeout = Timeout.InfiniteTimeSpan,
        };

        if (config.Authentication.Mode == "development")
        {
            httpClient.DefaultRequestHeaders.Add(
                "X-Dev-Subject",
                config.Authentication.DevelopmentSubject);
            if (config.Authentication.DevelopmentEmail is not null)
            {
                httpClient.DefaultRequestHeaders.Add(
                    "X-Dev-Email",
                    config.Authentication.DevelopmentEmail);
            }
        }
        else
        {
            var variable = config.Authentication.AccessTokenEnvironmentVariable!;
            var token = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(token) || token.IndexOfAny(['\r', '\n']) >= 0)
            {
                httpClient.Dispose();
                throw new InvalidOperationException(
                    $"The configured platform access-token environment variable '{variable}' is empty or invalid.");
            }
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
        }

        return new CoordinatorRuntime(config, httpClient);
    }

    public void Dispose() => HttpClient.Dispose();
}
