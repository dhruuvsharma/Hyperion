using System.Net;
using System.Text;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>Shared bounded HTTP response handling for native hosted-model adapters.</summary>
internal static class NativeLlmProviderHttp
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static Uri ValidateConfiguration(
        HttpClient http,
        LlmProviderDescriptor descriptor,
        string expectedProtocol,
        int maxResponseBytes)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(descriptor);
        if (string.IsNullOrWhiteSpace(descriptor.ProviderId))
            throw new ArgumentException("The provider id is required.", nameof(descriptor));
        if (string.IsNullOrWhiteSpace(descriptor.ModelId))
            throw new ArgumentException("The model id is required.", nameof(descriptor));
        if (!StringComparer.Ordinal.Equals(descriptor.Protocol, expectedProtocol))
        {
            throw new ArgumentException(
                $"The provider descriptor must use the '{expectedProtocol}' protocol.",
                nameof(descriptor));
        }
        if (maxResponseBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes), "The response-byte limit must be positive.");

        return LlmProviderValidation.ValidateEndpoint(descriptor.Endpoint, nameof(descriptor));
    }

    internal static string ValidateApiKey(string? apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("The API key is required.", nameof(apiKey));
        if (apiKey.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException("The API key contains invalid characters.", nameof(apiKey));

        return apiKey;
    }

    internal static LlmCallResult FailureFor(HttpStatusCode statusCode) => statusCode switch
    {
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => LlmCallResult.Failed(
            LlmFailureKinds.Authentication,
            "The provider rejected its credentials.",
            responseBytes: 0),
        HttpStatusCode.RequestTimeout or HttpStatusCode.GatewayTimeout => LlmCallResult.Failed(
            LlmFailureKinds.Timeout,
            "The provider request timed out.",
            retryable: true,
            responseBytes: 0),
        (HttpStatusCode)429 => LlmCallResult.Failed(
            LlmFailureKinds.RateLimited,
            "The provider rate-limited the request.",
            retryable: true,
            responseBytes: 0),
        >= HttpStatusCode.InternalServerError => LlmCallResult.Failed(
            LlmFailureKinds.ProviderUnavailable,
            "The provider is temporarily unavailable.",
            retryable: true,
            responseBytes: 0),
        _ => LlmCallResult.Failed(
            LlmFailureKinds.ProviderRejected,
            $"The provider rejected the request with HTTP {(int)statusCode}.",
            responseBytes: 0)
    };

    internal static async Task<NativeLlmProviderPayload> ReadBoundedUtf8Async(
        HttpContent content,
        int maxBytes,
        CancellationToken ct)
    {
        if (content.Headers.ContentLength is { } declared && declared > maxBytes)
            throw new NativeLlmProviderResponseTooLargeException(0);

        await using var input = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var output = new MemoryStream(Math.Min(maxBytes, 81_920));
        var buffer = new byte[81_920];
        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > maxBytes)
                throw new NativeLlmProviderResponseTooLargeException(output.Length + read);
            output.Write(buffer, 0, read);
        }

        var byteCount = checked((int)output.Length);
        return new NativeLlmProviderPayload(
            StrictUtf8.GetString(output.GetBuffer(), 0, byteCount),
            byteCount);
    }
}

internal sealed class NativeLlmProviderResponseTooLargeException(long bytesRead) : Exception
{
    internal long BytesRead { get; } = bytesRead;
}

internal sealed record NativeLlmProviderPayload(string Text, int ByteCount);
