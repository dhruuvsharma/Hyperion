using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>
/// Minimal text-completion boundary used by the research coordinator. Implementations return typed
/// provider failures; caller cancellation remains cancellation and is never converted into a result.
/// </summary>
public interface ILlmProvider
{
    LlmProviderDescriptor Descriptor { get; }

    string ProviderId => Descriptor.ProviderId;

    string ModelId => Descriptor.ModelId;

    Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default);
}

/// <summary>Allows a durable coordinator to align an ordered replay after process restart.</summary>
public interface IResumableLlmProvider
{
    void ResumeAfter(int consumedRequestCount);
}

/// <summary>Stable failure kinds emitted by the built-in provider implementations.</summary>
public static class LlmFailureKinds
{
    public const string InvalidRequest = "invalid_request";
    public const string Authentication = "authentication";
    public const string RateLimited = "rate_limited";
    public const string Timeout = "timeout";
    public const string Transport = "transport";
    public const string ProviderUnavailable = "provider_unavailable";
    public const string ProviderRejected = "provider_rejected";
    public const string InvalidResponse = "invalid_response";
    public const string ResponseTooLarge = "response_too_large";
    public const string ReplayMismatch = "replay_mismatch";
    public const string ReplayExhausted = "replay_exhausted";
}

internal static class LlmRequestValidation
{
    public static LlmCallResult? Validate(LlmRequest? request)
    {
        if (request is null)
            return LlmCallResult.Failed(LlmFailureKinds.InvalidRequest, "The LLM request is missing.");
        if (string.IsNullOrWhiteSpace(request.RequestId))
            return LlmCallResult.Failed(LlmFailureKinds.InvalidRequest, "The LLM request id is missing.");
        if (string.IsNullOrWhiteSpace(request.SystemPrompt))
            return LlmCallResult.Failed(LlmFailureKinds.InvalidRequest, "The LLM system prompt is missing.");
        if (request.MaxOutputTokens <= 0)
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidRequest,
                "MaxOutputTokens must be greater than zero.");
        if (request.MaxResponseBytes <= 0)
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidRequest,
                "MaxResponseBytes must be greater than zero.");
        if (request.Temperature is < 0m or > 2m)
            return LlmCallResult.Failed(
                LlmFailureKinds.InvalidRequest,
                "Temperature must be between 0 and 2.");
        if (request.Messages is null || request.Messages.Any(message =>
                message is null ||
                string.IsNullOrWhiteSpace(message.Role) ||
                string.IsNullOrWhiteSpace(message.Content)))
            return LlmCallResult.Failed(LlmFailureKinds.InvalidRequest, "The LLM message list is invalid.");

        return null;
    }
}
