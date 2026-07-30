using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using TradingTerminal.Ai.Coordinator.Client;

namespace TradingTerminal.App.Authoring;

/// <summary>
/// Professional-shell connection settings for the hosted Hyperion authoring workflow. The
/// feature is disabled by default; production credentials are never stored in configuration.
/// </summary>
public sealed class VibeQuantHostedOptions
{
    public const string SectionName = "VibeQuantHosted";

    public bool Enabled { get; set; }

    public string ServerBaseUrl { get; set; } = "http://127.0.0.1:5080";

    public string AuthenticationMode { get; set; } = "development";

    public string? DevelopmentSubject { get; set; } = "local-vibe-quant-terminal";

    public string? DevelopmentEmail { get; set; } = "local-vibe-quant-terminal@development.invalid";

    public int PollIntervalMilliseconds { get; set; } = 1_000;
}

public sealed record VibeQuantHostedAvailability(
    bool IsAvailable,
    string Message,
    string? ConnectionBinding = null);

public interface IVibeQuantDesktopClientFactory
{
    VibeQuantHostedAvailability GetAvailability();

    IVibeQuantApiClient Create();
}

/// <summary>Creates the strict coordinator client without following redirects or retaining a token
/// in settings. Development identity headers are accepted only for a loopback origin.</summary>
public sealed class VibeQuantDesktopClientFactory(
    IOptions<VibeQuantHostedOptions> options,
    IHttpClientFactory httpClientFactory) : IVibeQuantDesktopClientFactory
{
    public const string HttpClientName = "DaxAlgo.VibeQuantHosted";

    public VibeQuantHostedAvailability GetAvailability()
    {
        try
        {
            var connection = Validate();
            return new VibeQuantHostedAvailability(
                true,
                "Loopback development connection is ready. Hosted source remains inert until explicit release and import.",
                connection.Binding);
        }
        catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException)
        {
            return new VibeQuantHostedAvailability(false, exception.Message);
        }
    }

    public IVibeQuantApiClient Create()
    {
        var validated = Validate();
        var http = httpClientFactory.CreateClient(HttpClientName);
        http.BaseAddress = validated.Origin;
        http.Timeout = Timeout.InfiniteTimeSpan;

        http.DefaultRequestHeaders.Add("X-Dev-Subject", validated.DevelopmentSubject);
        if (validated.DevelopmentEmail is not null)
            http.DefaultRequestHeaders.Add("X-Dev-Email", validated.DevelopmentEmail);

        return new VibeQuantApiClient(http);
    }

    private ValidatedConnection Validate()
    {
        var value = options.Value;
        if (!value.Enabled)
            throw new InvalidOperationException(
                "Hosted Hyperion is disabled. Enable the legacy VibeQuantHosted configuration section in a local override.");

        if (!Uri.TryCreate(value.ServerBaseUrl, UriKind.Absolute, out var endpoint) ||
            endpoint.Port is < 1 or > 65535 ||
            !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment) ||
            endpoint.AbsolutePath is not ("" or "/"))
        {
            throw new InvalidDataException("VibeQuantHosted:ServerBaseUrl must contain only an absolute server origin.");
        }

        if (endpoint.Scheme != Uri.UriSchemeHttps &&
            !(endpoint.Scheme == Uri.UriSchemeHttp && endpoint.IsLoopback))
        {
            throw new InvalidDataException(
                "VibeQuantHosted:ServerBaseUrl must use HTTPS, except for loopback development HTTP.");
        }

        if (value.PollIntervalMilliseconds is < 250 or > 30_000)
            throw new InvalidDataException("VibeQuantHosted:PollIntervalMilliseconds must be between 250 and 30000.");

        if (value.AuthenticationMode?.Trim() != "development" || !endpoint.IsLoopback)
            throw new InvalidDataException(
                "Hosted Terminal authoring currently permits only loopback development authentication; production desktop credit authority is not enabled.");
        RequireSafeHeader(value.DevelopmentSubject, "VibeQuantHosted:DevelopmentSubject");
        if (value.DevelopmentEmail is not null)
            RequireSafeHeader(value.DevelopmentEmail, "VibeQuantHosted:DevelopmentEmail");

        var origin = new Uri(endpoint.GetLeftPart(UriPartial.Authority));
        var bindingText = string.Join("\n", origin.AbsoluteUri, value.DevelopmentSubject, value.DevelopmentEmail ?? string.Empty);
        var binding = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(bindingText))).ToLowerInvariant();
        return new ValidatedConnection(
            origin,
            value.DevelopmentSubject!,
            value.DevelopmentEmail,
            binding);
    }

    private static void RequireSafeHeader(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 320 || value.IndexOfAny(['\r', '\n']) >= 0)
            throw new InvalidDataException($"{name} is required and must be a safe HTTP header value.");
    }

    private sealed record ValidatedConnection(
        Uri Origin,
        string DevelopmentSubject,
        string? DevelopmentEmail,
        string Binding);
}

public interface IHostedStrategyPollDelay
{
    Task WaitAsync(CancellationToken cancellationToken);
}

public sealed class HostedStrategyPollDelay(IOptions<VibeQuantHostedOptions> options)
    : IHostedStrategyPollDelay
{
    public Task WaitAsync(CancellationToken cancellationToken)
    {
        var milliseconds = options.Value.PollIntervalMilliseconds;
        if (milliseconds is < 250 or > 30_000) milliseconds = 1_000;
        return Task.Delay(milliseconds, cancellationToken);
    }
}
