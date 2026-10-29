using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;

namespace Hyperion.FreeStrategyWorkflow;

/// <summary>
/// Adapts a Terminal- or application-owned model client to the provider-neutral coordinator boundary.
/// Provider endpoints and credentials remain owned by the caller and never enter the run specification.
/// </summary>
public sealed class FreeStrategyExternalProvider : ILlmProvider
{
    private readonly Func<LlmRequest, CancellationToken, Task<LlmCallResult>> _complete;

    public FreeStrategyExternalProvider(
        string providerId,
        string modelId,
        Func<LlmRequest, CancellationToken, Task<LlmCallResult>> complete,
        decimal inputUsdPerMillionTokens = 0m,
        decimal outputUsdPerMillionTokens = 0m)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerId);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);
        ArgumentNullException.ThrowIfNull(complete);
        if (inputUsdPerMillionTokens is < 0m or > 1_000_000m ||
            outputUsdPerMillionTokens is < 0m or > 1_000_000m)
        {
            throw new ArgumentOutOfRangeException(
                nameof(inputUsdPerMillionTokens),
                "Provider prices must be between 0 and 1,000,000 USD per million tokens.");
        }

        Descriptor = new LlmProviderDescriptor(
            providerId.Trim(),
            modelId.Trim(),
            LlmProviderProtocols.ExternalAdapter,
            Endpoint: null,
            InputUsdPerMillionTokens: inputUsdPerMillionTokens,
            OutputUsdPerMillionTokens: outputUsdPerMillionTokens);
        _complete = complete;
    }

    public LlmProviderDescriptor Descriptor { get; }

    public Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default) =>
        _complete(request, ct);
}
