using System.Text.Json;
using Microsoft.Data.Sqlite;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

internal sealed class TestWorkspace : IDisposable
{
    private readonly string _parent;

    public TestWorkspace()
    {
        _parent = Path.Combine(Path.GetTempPath(), "daxalgo-coordinator-tests");
        RootPath = Path.Combine(_parent, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(RootPath);
    }

    public string RootPath { get; }

    public string PathFor(params string[] parts) =>
        Path.Combine([RootPath, .. parts]);

    public SqliteCoordinatorStore CreateStore() => new(PathFor("coordinator.db"));

    public ContentAddressedArtifactStore CreateArtifactStore() => new(PathFor("artifacts"));

    public void Dispose()
    {
        var root = Path.GetFullPath(RootPath);
        var safeParent = Path.GetFullPath(_parent).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!root.StartsWith(safeParent, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Refusing to clean a test directory outside the test root.");
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }
}

internal static class CoordinatorTestData
{
    public static LlmProviderDescriptor Descriptor(
        string providerId = "test",
        string modelId = "test-model",
        string protocol = "test",
        string? endpoint = null) =>
        new(providerId, modelId, protocol, endpoint);

    public static CoordinatorRunSpec Spec(
        LlmProviderDescriptor descriptor,
        CoordinatorBudget? budget = null,
        IReadOnlyList<CoordinatorContextSource>? sources = null) =>
        new(
            Guid.NewGuid(),
            "Assess the supplied evidence through the bounded research-only workflow.",
            "test-operator",
            DateTimeOffset.UtcNow,
            sources ?? [],
            descriptor,
            budget ?? new CoordinatorBudget());

    public static ResearchCoordinator Coordinator(
        TestWorkspace workspace,
        ILlmProvider provider,
        SqliteCoordinatorStore? store = null,
        ContentAddressedArtifactStore? artifacts = null) =>
        new(store ?? workspace.CreateStore(), artifacts ?? workspace.CreateArtifactStore(), provider);

    public static string SpecSha256(CoordinatorRunSnapshot snapshot) => ContentHasher.HashJson(snapshot.Spec);

    public static LlmCompletion ValidCompletion(LlmRequest request, LlmUsage? usage = null)
    {
        var output = new CoordinatorRoleOutput
        {
            SchemaVersion = CoordinatorVersions.ArtifactSchema,
            Role = request.Role,
            Summary = $"Validated output for {request.Role}.",
            Recommendations = ["Continue only within the approved research boundary."],
            Decision = request.Role == CoordinatorRole.RiskJudge
                ? CoordinatorDecision.Approve
                : CoordinatorDecision.None
        };
        return new LlmCompletion(
            JsonSerializer.Serialize(output, CoordinatorJson.Options),
            usage ?? new LlmUsage(32, 24),
            "stop",
            $"test-{request.Role}");
    }
}

internal sealed class ScriptedLlmProvider(
    LlmProviderDescriptor descriptor,
    Func<LlmRequest, int, LlmCallResult> handler) : ILlmProvider
{
    private int _callCount;

    public LlmProviderDescriptor Descriptor { get; } = descriptor;

    public int CallCount => Volatile.Read(ref _callCount);

    public Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var call = Interlocked.Increment(ref _callCount);
        return Task.FromResult(handler(request, call));
    }
}

internal sealed class BlockingLlmProvider(LlmProviderDescriptor descriptor) : ILlmProvider
{
    private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public LlmProviderDescriptor Descriptor { get; } = descriptor;

    public Task Started => _started.Task;

    public async Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default)
    {
        _started.TrySetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        return LlmCallResult.Failed(LlmFailureKinds.ProviderUnavailable, "Blocking provider unexpectedly completed.");
    }
}
