namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>Validates model-provider endpoints without ever echoing a possibly sensitive URL.</summary>
public static class LlmProviderValidation
{
    public static bool TryValidateEndpoint(string? endpoint, out Uri? endpointUri, out string? safeError)
    {
        endpointUri = null;
        safeError = null;

        if (string.IsNullOrWhiteSpace(endpoint) ||
            !Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed))
        {
            safeError = "The provider endpoint must be an absolute URI.";
            return false;
        }

        if (!string.IsNullOrEmpty(parsed.UserInfo))
        {
            safeError = "The provider endpoint must not contain credentials.";
            return false;
        }

        if (!string.IsNullOrEmpty(parsed.Query) || !string.IsNullOrEmpty(parsed.Fragment))
        {
            safeError = "The provider endpoint must not contain a query string or fragment.";
            return false;
        }

        var isHttps = parsed.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isLoopbackHttp = parsed.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                             parsed.IsLoopback;
        if (!isHttps && !isLoopbackHttp)
        {
            safeError = "The provider endpoint must use HTTPS unless it is loopback.";
            return false;
        }

        endpointUri = parsed;
        return true;
    }

    public static Uri ValidateEndpoint(string? endpoint, string parameterName = "endpoint")
    {
        if (TryValidateEndpoint(endpoint, out var endpointUri, out var safeError)) return endpointUri!;
        throw new ArgumentException(safeError, parameterName);
    }

    internal static Uri AppendPath(Uri endpoint, string relativePath)
    {
        var builder = new UriBuilder(endpoint)
        {
            Path = $"{endpoint.AbsolutePath.TrimEnd('/')}/{relativePath.TrimStart('/')}",
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri;
    }
}
