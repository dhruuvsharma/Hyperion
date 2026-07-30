using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>Text completion over the OpenAI-compatible <c>chat/completions</c> protocol.</summary>
public sealed class OpenAiCompatibleLlmProvider : ILlmProvider
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _completionEndpoint;
    private readonly string? _apiKey;
    private readonly int _maxResponseBytes;

    public OpenAiCompatibleLlmProvider(
        HttpClient http,
        LlmProviderDescriptor descriptor,
        string? apiKey,
        int maxResponseBytes = 1_000_000)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(descriptor);
        if (string.IsNullOrWhiteSpace(descriptor.ProviderId))
            throw new ArgumentException("The provider id is required.", nameof(descriptor));
        if (string.IsNullOrWhiteSpace(descriptor.ModelId))
            throw new ArgumentException("The model id is required.", nameof(descriptor));
        if (maxResponseBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxResponseBytes), "The response-byte limit must be positive.");
        if (apiKey?.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("The API key contains invalid characters.", nameof(apiKey));

        var endpoint = LlmProviderValidation.ValidateEndpoint(descriptor.Endpoint, nameof(descriptor));
        _http = http;
        _completionEndpoint = LlmProviderValidation.AppendPath(endpoint, "chat/completions");
        _apiKey = string.IsNullOrWhiteSpace(apiKey) ? null : apiKey.Trim();
        _maxResponseBytes = maxResponseBytes;
        Descriptor = descriptor;
    }

    public LlmProviderDescriptor Descriptor { get; }

    public async Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (LlmRequestValidation.Validate(request) is { } invalid) return invalid;

        var messages = new List<WireMessage>(request.Messages.Count + 1)
        {
            new("system", request.SystemPrompt)
        };
        foreach (var message in request.Messages)
        {
            var role = NormalizeRole(message.Role);
            if (role is null)
            {
                return LlmCallResult.Failed(
                    LlmFailureKinds.InvalidRequest,
                    "Only user and assistant LLM messages are permitted.");
            }
            messages.Add(new WireMessage(role, message.Content));
        }

        var body = new ChatRequest(
            Descriptor.ModelId,
            messages,
            request.MaxOutputTokens,
            request.Temperature);

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _completionEndpoint)
        {
            Content = JsonContent.Create(body, options: WireJson)
        };
        httpRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (_apiKey is not null)
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);

        long observedResponseBytes = 0;
        try
        {
            using var response = await _http.SendAsync(
                httpRequest,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode) return FailureFor(response.StatusCode);

            var payload = await ReadBoundedUtf8Async(
                    response.Content,
                    Math.Min(_maxResponseBytes, request.MaxResponseBytes),
                    ct)
                .ConfigureAwait(false);
            observedResponseBytes = payload.ByteCount;
            var parsed = JsonSerializer.Deserialize<ChatResponse>(payload.Text, WireJson);
            var choice = parsed?.Choices?.FirstOrDefault();
            var text = choice?.Message?.Content;
            if (string.IsNullOrWhiteSpace(text))
            {
                return LlmCallResult.Failed(
                    LlmFailureKinds.InvalidResponse,
                    "The provider returned no message content.",
                    responseBytes: observedResponseBytes);
            }
            if (!StringComparer.Ordinal.Equals(choice?.FinishReason, "stop"))
            {
                return LlmCallResult.Failed(
                    LlmFailureKinds.InvalidResponse,
                    "The provider did not return an untruncated 'stop' completion.",
                    responseBytes: observedResponseBytes);
            }

            LlmUsage? usage = null;
            if (parsed?.Usage is { } reported)
            {
                if (reported.PromptTokens < 0 || reported.CompletionTokens < 0)
                {
                    return LlmCallResult.Failed(
                        LlmFailureKinds.InvalidResponse,
                        "The provider returned invalid token usage.",
                        responseBytes: observedResponseBytes);
                }
                usage = new LlmUsage(reported.PromptTokens, reported.CompletionTokens);
            }

            return LlmCallResult.Success(new LlmCompletion(
                text,
                usage,
                choice?.FinishReason,
                parsed?.Id,
                payload.ByteCount));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.Timeout,
                "The provider request timed out.",
                retryable: true,
                responseBytes: observedResponseBytes == 0 ? null : observedResponseBytes);
        }
        catch (ResponseTooLargeException exception)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.ResponseTooLarge,
                "The provider response exceeded the configured byte limit.",
                responseBytes: exception.BytesRead);
        }
        catch (JsonException)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidResponse,
                "The provider returned invalid JSON.",
                responseBytes: observedResponseBytes);
        }
        catch (DecoderFallbackException)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidResponse,
                "The provider returned invalid UTF-8.",
                responseBytes: observedResponseBytes == 0 ? null : observedResponseBytes);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.Transport,
                "The provider request failed at the transport boundary.",
                retryable: true,
                responseBytes: observedResponseBytes == 0 ? null : observedResponseBytes);
        }
    }

    private static string? NormalizeRole(string? role) => role?.Trim().ToLowerInvariant() switch
    {
        "user" => "user",
        "assistant" => "assistant",
        _ => null
    };

    private static LlmCallResult FailureFor(HttpStatusCode statusCode) => statusCode switch
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

    private static async Task<BoundedUtf8Payload> ReadBoundedUtf8Async(
        HttpContent content,
        int maxBytes,
        CancellationToken ct)
    {
        if (content.Headers.ContentLength is { } declared && declared > maxBytes)
            throw new ResponseTooLargeException(0);

        await using var input = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var output = new MemoryStream(Math.Min(maxBytes, 81_920));
        var buffer = new byte[81_920];
        while (true)
        {
            var read = await input.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > maxBytes) throw new ResponseTooLargeException(output.Length + read);
            output.Write(buffer, 0, read);
        }
        var byteCount = checked((int)output.Length);
        return new BoundedUtf8Payload(
            StrictUtf8.GetString(output.GetBuffer(), 0, byteCount),
            byteCount);
    }

    private sealed class ResponseTooLargeException(long bytesRead) : Exception
    {
        public long BytesRead { get; } = bytesRead;
    }

    private sealed record BoundedUtf8Payload(string Text, int ByteCount);

    private sealed record WireMessage(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("content")] string Content);

    private sealed record ChatRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("messages")] IReadOnlyList<WireMessage> Messages,
        [property: JsonPropertyName("max_tokens")] int MaxTokens,
        [property: JsonPropertyName("temperature")] decimal Temperature);

    private sealed record ChatResponse(
        [property: JsonPropertyName("id")] string? Id,
        [property: JsonPropertyName("choices")] IReadOnlyList<Choice>? Choices,
        [property: JsonPropertyName("usage")] WireUsage? Usage);

    private sealed record Choice(
        [property: JsonPropertyName("message")] WireMessage? Message,
        [property: JsonPropertyName("finish_reason")] string? FinishReason);

    private sealed record WireUsage(
        [property: JsonPropertyName("prompt_tokens")] int PromptTokens,
        [property: JsonPropertyName("completion_tokens")] int CompletionTokens);
}
