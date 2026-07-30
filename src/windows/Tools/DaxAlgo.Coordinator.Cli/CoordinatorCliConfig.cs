using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Coordinator.Cli;

public sealed record CoordinatorCliConfig
{
    public const string CurrentSchemaVersion = "vibe-quant-client/v1";

    public string SchemaVersion { get; init; } = CurrentSchemaVersion;

    public string ServerBaseUrl { get; init; } = "http://127.0.0.1:5080";

    public CoordinatorClientAuthenticationConfig Authentication { get; init; } = new();
}

public sealed record CoordinatorClientAuthenticationConfig
{
    public string Mode { get; init; } = "development";

    public string? AccessTokenEnvironmentVariable { get; init; }

    public string? DevelopmentSubject { get; init; } = "local-vibe-quant-operator";

    public string? DevelopmentEmail { get; init; } = "local-vibe-quant-operator@development.invalid";
}

public static class CoordinatorCliConfigLoader
{
    public const int MaxConfigBytes = 1_000_000;

    public static async Task<CoordinatorCliConfig> LoadAsync(
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
            throw new InvalidDataException($"Coordinator client config exceeds the {MaxConfigBytes:N0}-byte input limit.");
        }
        var config = await JsonSerializer.DeserializeAsync<CoordinatorCliConfig>(
                stream,
                CoordinatorJson.Options,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidDataException("Coordinator client config must not be JSON null.");
        Validate(config);
        return config;
    }

    public static void Validate(CoordinatorCliConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (config.Authentication is null)
        {
            throw new InvalidDataException("authentication is required.");
        }
        if (config.SchemaVersion != CoordinatorCliConfig.CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"schemaVersion must be '{CoordinatorCliConfig.CurrentSchemaVersion}'.");
        }
        if (!Uri.TryCreate(config.ServerBaseUrl, UriKind.Absolute, out var endpoint) ||
            endpoint.IsDefaultPort && endpoint.Port is < 1 or > 65535)
        {
            throw new InvalidDataException("serverBaseUrl must be an absolute URL.");
        }
        if (!string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment) ||
            endpoint.AbsolutePath is not ("" or "/"))
        {
            throw new InvalidDataException("serverBaseUrl must contain only the server origin.");
        }
        if (endpoint.Scheme != Uri.UriSchemeHttps &&
            !(endpoint.Scheme == Uri.UriSchemeHttp && endpoint.IsLoopback))
        {
            throw new InvalidDataException("serverBaseUrl must use HTTPS, except loopback development HTTP.");
        }

        if (config.Authentication.Mode == "development")
        {
            if (!endpoint.IsLoopback)
            {
                throw new InvalidDataException("Development authentication is restricted to a loopback server.");
            }
            RequireHeaderValue(config.Authentication.DevelopmentSubject, "authentication.developmentSubject");
            if (config.Authentication.DevelopmentEmail is not null)
            {
                RequireHeaderValue(config.Authentication.DevelopmentEmail, "authentication.developmentEmail");
            }
            if (config.Authentication.AccessTokenEnvironmentVariable is not null)
            {
                throw new InvalidDataException("Development authentication must not configure an access-token variable.");
            }
            return;
        }

        if (config.Authentication.Mode == "bearer")
        {
            var variable = config.Authentication.AccessTokenEnvironmentVariable;
            if (string.IsNullOrWhiteSpace(variable) ||
                !variable.StartsWith("DAXALGO_PLATFORM_", StringComparison.Ordinal) ||
                variable.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '_')))
            {
                throw new InvalidDataException(
                    "Bearer authentication requires a dedicated DAXALGO_PLATFORM_ access-token environment variable.");
            }
            if (config.Authentication.DevelopmentSubject is not null ||
                config.Authentication.DevelopmentEmail is not null)
            {
                throw new InvalidDataException("Bearer authentication must not configure development identity headers.");
            }
            return;
        }

        throw new InvalidDataException("authentication.mode must be development or bearer.");
    }

    private static void RequireHeaderValue(string? value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 320 || value.IndexOfAny(['\r', '\n']) >= 0)
        {
            throw new InvalidDataException($"{name} is required and must be a safe HTTP header value.");
        }
    }
}
