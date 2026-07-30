using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>
/// Network-free provider used by smoke tests and manual workflow rehearsal. It always emits a valid
/// role artifact and reports deterministic synthetic token usage.
/// </summary>
public sealed class DeterministicMockLlmProvider : ILlmProvider
{
    public DeterministicMockLlmProvider(LlmProviderDescriptor? descriptor = null)
    {
        Descriptor = descriptor ?? new LlmProviderDescriptor(
            ProviderId: "mock",
            ModelId: "deterministic-v1",
            Protocol: "mock",
            Endpoint: null);
    }

    public LlmProviderDescriptor Descriptor { get; }

    public Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (LlmRequestValidation.Validate(request) is { } invalid)
            return Task.FromResult(invalid);

        var artifact = new CoordinatorRoleOutput
        {
            SchemaVersion = CoordinatorVersions.ArtifactSchema,
            Role = request.Role,
            Summary = $"Deterministic mock output for {request.Role}.",
            Claims = [],
            Risks = [],
            Recommendations = [IsStrategyRequest(request)
                ? "Keep the source inert until human release and Terminal compile consent."
                : "Continue through the research-only workflow."],
            SourceIds = [],
            Decision = request.Role == CoordinatorRole.RiskJudge
                ? CoordinatorDecision.Approve
                : CoordinatorDecision.None,
            StrategyDraft = IsStrategyRequest(request) && request.Role == CoordinatorRole.Synthesizer
                ? CreateStrategyDraft()
                : null
        };

        var text = JsonSerializer.Serialize(artifact, CoordinatorJson.Options);
        var responseBytes = Encoding.UTF8.GetByteCount(text);
        if (responseBytes > request.MaxResponseBytes)
        {
            return Task.FromResult(LlmCallResult.Failed(
                LlmFailureKinds.ResponseTooLarge,
                "The deterministic response exceeds MaxResponseBytes."));
        }
        var outputTokens = EstimateTokens(text);
        if (outputTokens > request.MaxOutputTokens)
        {
            return Task.FromResult(LlmCallResult.Failed(
                LlmFailureKinds.ProviderRejected,
                "The deterministic response exceeds MaxOutputTokens."));
        }

        var input = new StringBuilder(request.SystemPrompt);
        foreach (var message in request.Messages)
            input.Append(message.Role).Append(':').Append(message.Content);

        var completion = new LlmCompletion(
            Text: text,
            Usage: new LlmUsage(EstimateTokens(input.ToString()), outputTokens),
            FinishReason: "stop",
            ProviderRequestId: $"mock-{request.Role.ToString().ToLowerInvariant()}",
            ResponseBytes: responseBytes);
        return Task.FromResult(LlmCallResult.Success(completion));
    }

    private static int EstimateTokens(string value)
    {
        var bytes = Encoding.UTF8.GetByteCount(value);
        return Math.Max(1, checked((bytes + 3) / 4));
    }

    private static bool IsStrategyRequest(LlmRequest request) =>
        request.SystemPrompt.Contains("inert strategy-authoring workflow", StringComparison.Ordinal);

    private static CoordinatorStrategyDraft CreateStrategyDraft() => new()
    {
        StrategyId = "mock-generated-strategy",
        DisplayName = "Mock Generated Strategy",
        Files =
        [
            new CoordinatorStrategyDraftFile(
                "Strategy.cs",
                """
                public sealed class MockGeneratedStrategy : IBacktestStrategy
                {
                    private readonly Contract _contract;

                    public MockGeneratedStrategy(Contract contract) => _contract = contract;

                    public Task OnStartAsync(IClock clock, IOrderRouter router, CancellationToken ct) =>
                        Task.CompletedTask;

                    public Task OnTickAsync(Tick tick, IClock clock, IOrderRouter router, CancellationToken ct) =>
                        Task.CompletedTask;

                    public Task OnOrderEventAsync(OrderEvent evt, CancellationToken ct) => Task.CompletedTask;

                    public Task OnEndAsync(IClock clock, IOrderRouter router, CancellationToken ct) =>
                        Task.CompletedTask;
                }
                """)
        ]
    };
}
