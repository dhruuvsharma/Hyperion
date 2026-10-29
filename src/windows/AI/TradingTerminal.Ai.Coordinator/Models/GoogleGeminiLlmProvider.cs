using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>Text completion over Google's native Gemini generateContent API.</summary>
public sealed class GoogleGeminiLlmProvider : ILlmProvider
{
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _generateContentEndpoint;
    private readonly string _apiKey;
    private readonly int _maxResponseBytes;

    public GoogleGeminiLlmProvider(
        HttpClient http,
        LlmProviderDescriptor descriptor,
        string apiKey,
        int maxResponseBytes = 1_000_000)
    {
        var endpoint = NativeLlmProviderHttp.ValidateConfiguration(
            http,
            descriptor,
            LlmProviderProtocols.GoogleGemini,
            maxResponseBytes);

        _http = http;
        _generateContentEndpoint = LlmProviderValidation.AppendPath(
            endpoint,
            $"models/{Uri.EscapeDataString(NormalizeModelId(descriptor.ModelId))}:generateContent");
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

        var contents = new List<WireContent>(request.Messages.Count);
        foreach (var message in request.Messages)
        {
            var role = ToGeminiRole(message.Role);
            if (role is null)
            {
                return LlmCallResult.Failed(
                    LlmFailureKinds.InvalidRequest,
                    "Only user and assistant LLM messages are permitted.");
            }
            contents.Add(new WireContent(role, [new WirePart(message.Content)]));
        }

        var body = new GenerateContentRequest(
            contents,
            new SystemInstruction([new WirePart(request.SystemPrompt)]),
            new GenerationConfig(request.MaxOutputTokens, request.Temperature));

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, _generateContentEndpoint)
        {
            Content = JsonContent.Create(body, options: WireJson)
        };
        httpRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        httpRequest.Headers.Add("x-goog-api-key", _apiKey);

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
            var parsed = JsonSerializer.Deserialize<GenerateContentResponse>(payload.Text, WireJson);
            if (ContainsCredential(payload.Text) ||
                ContainsCredential(parsed?.ResponseId) ||
                parsed?.Candidates?.Any(candidate =>
                    candidate?.Content?.Parts?.Any(part => ContainsCredential(part?.Text)) is true) is true)
            {
                return InvalidResponse(
                    "The provider response contained configured credential material.",
                    observedResponseBytes);
            }
            if (parsed?.Candidates is null || parsed.Candidates.Count != 1)
            {
                return InvalidResponse(
                    "The provider returned an invalid candidate envelope.",
                    observedResponseBytes);
            }

            var candidate = parsed.Candidates[0];
            if (candidate is null)
            {
                return InvalidResponse(
                    "The provider returned an invalid candidate envelope.",
                    observedResponseBytes);
            }
            if (!StringComparer.Ordinal.Equals(candidate.FinishReason, "STOP"))
            {
                return InvalidResponse(
                    "The provider did not return an untruncated text completion.",
                    observedResponseBytes);
            }

            if (!StringComparer.Ordinal.Equals(candidate.Content?.Role, "model") ||
                candidate.Content.Parts is null ||
                candidate.Content.Parts.Count == 0 ||
                candidate.Content.Parts.Any(part =>
                    part is null || part.Text is null || part.Thought is true))
            {
                return InvalidResponse(
                    "The provider returned invalid message content.",
                    observedResponseBytes);
            }

            var text = string.Concat(candidate.Content.Parts.Select(part => part!.Text));
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

            if (!TryParseUsage(parsed.UsageMetadata, out var usage))
            {
                return InvalidResponse(
                    "The provider returned invalid token usage.",
                    observedResponseBytes);
            }

            return LlmCallResult.Success(new LlmCompletion(
                text,
                usage,
                "stop",
                parsed.ResponseId,
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

    private static string NormalizeModelId(string modelId) =>
        modelId.StartsWith("models/", StringComparison.Ordinal)
            ? modelId["models/".Length..]
            : modelId;

    private static string? ToGeminiRole(string role) => role switch
    {
        "user" => "user",
        "assistant" => "model",
        _ => null
    };

    private static bool TryParseUsage(WireUsage? reported, out LlmUsage? usage)
    {
        usage = null;
        if (reported is null) return true;
        if (reported.PromptTokenCount is null or < 0 ||
            reported.CandidatesTokenCount is null or < 0 ||
            reported.ThoughtsTokenCount is < 0)
            return false;
        try
        {
            usage = new LlmUsage(
                reported.PromptTokenCount.Value,
                checked(reported.CandidatesTokenCount.Value + (reported.ThoughtsTokenCount ?? 0)));
        }
        catch (OverflowException)
        {
            return false;
        }
        return true;
    }

    private static LlmCallResult InvalidResponse(string message, long responseBytes) =>
        LlmCallResult.Failed(
            LlmFailureKinds.InvalidResponse,
            message,
            responseBytes: responseBytes);

    private bool ContainsCredential(string? value) =>
        value is not null && value.Contains(_apiKey, StringComparison.Ordinal);

    private sealed record WirePart(
        [property: JsonPropertyName("text")] string? Text,
        [property: JsonPropertyName("thought")] bool? Thought = null);

    private sealed record WireContent(
        [property: JsonPropertyName("role")] string? Role,
        [property: JsonPropertyName("parts")] IReadOnlyList<WirePart?>? Parts);

    private sealed record SystemInstruction(
        [property: JsonPropertyName("parts")] IReadOnlyList<WirePart> Parts);

    private sealed record GenerationConfig(
        [property: JsonPropertyName("maxOutputTokens")] int MaxOutputTokens,
        [property: JsonPropertyName("temperature")] decimal Temperature);

    private sealed record GenerateContentRequest(
        [property: JsonPropertyName("contents")] IReadOnlyList<WireContent> Contents,
        [property: JsonPropertyName("systemInstruction")] SystemInstruction SystemInstruction,
        [property: JsonPropertyName("generationConfig")] GenerationConfig GenerationConfig);

    private sealed record GenerateContentResponse(
        [property: JsonPropertyName("candidates")] IReadOnlyList<Candidate?>? Candidates,
        [property: JsonPropertyName("usageMetadata")] WireUsage? UsageMetadata,
        [property: JsonPropertyName("responseId")] string? ResponseId);

    private sealed record Candidate(
        [property: JsonPropertyName("content")] WireContent? Content,
        [property: JsonPropertyName("finishReason")] string? FinishReason);

    private sealed record WireUsage(
        [property: JsonPropertyName("promptTokenCount")] long? PromptTokenCount,
        [property: JsonPropertyName("candidatesTokenCount")] long? CandidatesTokenCount,
        [property: JsonPropertyName("thoughtsTokenCount")] long? ThoughtsTokenCount);
}
