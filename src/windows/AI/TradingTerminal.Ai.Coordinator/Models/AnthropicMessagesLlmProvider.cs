using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>Text completion over Anthropic's native Messages API.</summary>
public sealed class AnthropicMessagesLlmProvider : ILlmProvider
{
    public const string AnthropicVersion = "2023-06-01";

    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _messagesEndpoint;
    private readonly string _apiKey;
    private readonly int _maxResponseBytes;

    public AnthropicMessagesLlmProvider(
        HttpClient http,
        LlmProviderDescriptor descriptor,
        string apiKey,
        int maxResponseBytes = 1_000_000)
    {
        var endpoint = NativeLlmProviderHttp.ValidateConfiguration(
            http,
            descriptor,
            LlmProviderProtocols.AnthropicMessages,
            maxResponseBytes);

        _http = http;
        _messagesEndpoint = LlmProviderValidation.AppendPath(endpoint, "messages");
        _apiKey = NativeLlmProviderHttp.ValidateApiKey(apiKey);
        _maxResponseBytes = maxResponseBytes;
        Descriptor = descriptor;
    }

    public LlmProviderDescriptor Descriptor { get; }

    public async Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (LlmRequestValidation.Validate(request) is { } invalid) return invalid;
        if (request.Messages.Count == 0)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidRequest,
                "The LLM message list must contain at least one message.");
        }
        if (request.Temperature > 1m)
        {
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidRequest,
                "Anthropic temperature must be between 0 and 1.");
        }

        var messages = new List<WireMessage>(request.Messages.Count);
        foreach (var message in request.Messages)
        {
            if (!IsPermittedRole(message.Role))
            {
                return LlmCallResult.Failed(
                    LlmFailureKinds.InvalidRequest,
                    "Only user and assistant LLM messages are permitted.");
            }
            messages.Add(new WireMessage(message.Role, message.Content));
        }

        var body = new MessagesRequest(
            Descriptor.ModelId,
            request.MaxOutputTokens,
            request.SystemPrompt,
            messages,
            request.Temperature);

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _messagesEndpoint)
        {
            Content = JsonContent.Create(body, options: WireJson)
        };
        httpRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        httpRequest.Headers.Add("anthropic-version", AnthropicVersion);
        httpRequest.Headers.Add("x-api-key", _apiKey);

        long observedResponseBytes = 0;
        try
        {
            using var response = await _http.SendAsync(
                httpRequest,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode) return NativeLlmProviderHttp.FailureFor(response.StatusCode);

            var payload = await NativeLlmProviderHttp.ReadBoundedUtf8Async(
                    response.Content,
                    Math.Min(_maxResponseBytes, request.MaxResponseBytes),
                    ct)
                .ConfigureAwait(false);
            observedResponseBytes = payload.ByteCount;
            var parsed = JsonSerializer.Deserialize<MessagesResponse>(payload.Text, WireJson);
            if (ContainsCredential(payload.Text) ||
                ContainsCredential(parsed?.Id) ||
                parsed?.Content?.Any(block => ContainsCredential(block?.Text)) is true)
            {
                return InvalidResponse(
                    "The provider response contained configured credential material.",
                    observedResponseBytes);
            }
            if (!StringComparer.Ordinal.Equals(parsed?.Type, "message") ||
                !StringComparer.Ordinal.Equals(parsed.Role, "assistant"))
            {
                return InvalidResponse(
                    "The provider returned an invalid message envelope.",
                    observedResponseBytes);
            }

            if (!IsUntruncatedStopReason(parsed.StopReason))
            {
                return InvalidResponse(
                    "The provider did not return an untruncated text completion.",
                    observedResponseBytes);
            }

            if (parsed.Content is null ||
                parsed.Content.Count == 0 ||
                parsed.Content.Any(block =>
                    block is null ||
                    !StringComparer.Ordinal.Equals(block.Type, "text") ||
                    block.Text is null))
            {
                return InvalidResponse(
                    "The provider returned invalid message content.",
                    observedResponseBytes);
            }

            var text = string.Concat(parsed.Content.Select(block => block!.Text));
            if (ContainsCredential(text))
            {
                return InvalidResponse(
                    "The provider response contained configured credential material.",
                    observedResponseBytes);
            }
            if (string.IsNullOrWhiteSpace(text))
            {
                return InvalidResponse(
                    "The provider returned no message content.",
                    observedResponseBytes);
            }

            if (!TryParseUsage(parsed.Usage, out var usage))
            {
                return InvalidResponse(
                    "The provider returned invalid token usage.",
                    observedResponseBytes);
            }

            return LlmCallResult.Success(new LlmCompletion(
                text,
                usage,
                "stop",
                parsed.Id,
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
        catch (NativeLlmProviderResponseTooLargeException exception)
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

    private static bool IsPermittedRole(string role) => role is "user" or "assistant";

    private static bool IsUntruncatedStopReason(string? stopReason) =>
        stopReason is "end_turn" or "stop_sequence";

    private static bool TryParseUsage(WireUsage? reported, out LlmUsage? usage)
    {
        usage = null;
        if (reported is null) return true;
        if (reported.InputTokens is null or < 0 || reported.OutputTokens is null or < 0) return false;
        usage = new LlmUsage(reported.InputTokens.Value, reported.OutputTokens.Value);
        return true;
    }

    private static LlmCallResult InvalidResponse(string message, long responseBytes) =>
        LlmCallResult.Failed(
            LlmFailureKinds.InvalidResponse,
            message,
            responseBytes: responseBytes);

    private bool ContainsCredential(string? value) =>
        value is not null && value.Contains(_apiKey, StringComparison.Ordinal);

    private sealed record WireMessage(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("content")] string Content);

    private sealed record MessagesRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("max_tokens")] int MaxTokens,
        [property: JsonPropertyName("system")] string System,
        [property: JsonPropertyName("messages")] IReadOnlyList<WireMessage> Messages,
        [property: JsonPropertyName("temperature")] decimal Temperature);

    private sealed record MessagesResponse(
        [property: JsonPropertyName("id")] string? Id,
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("role")] string? Role,
        [property: JsonPropertyName("content")] IReadOnlyList<ContentBlock?>? Content,
        [property: JsonPropertyName("stop_reason")] string? StopReason,
        [property: JsonPropertyName("usage")] WireUsage? Usage);

    private sealed record ContentBlock(
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("text")] string? Text);

    private sealed record WireUsage(
        [property: JsonPropertyName("input_tokens")] long? InputTokens,
        [property: JsonPropertyName("output_tokens")] long? OutputTokens);
}
