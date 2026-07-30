using TradingTerminal.Ai.Coordinator.Contracts;

namespace TradingTerminal.Ai.Coordinator.Persistence;

public interface ICoordinatorStore
{
    Task InitializeAsync(CancellationToken cancellationToken = default);

    Task<CoordinatorRunSnapshot> CreateAsync(
        CoordinatorRunSnapshot snapshot,
        string eventType,
        object eventPayload,
        CancellationToken cancellationToken = default);

    Task<CoordinatorRunSnapshot?> GetAsync(Guid runId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CoordinatorRunSnapshot>> ListAsync(CancellationToken cancellationToken = default);

    Task<CoordinatorRunSnapshot> AppendAsync(
        CoordinatorRunSnapshot snapshot,
        long expectedVersion,
        string eventType,
        object eventPayload,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CoordinatorEventRecord>> ReadEventsAsync(
        Guid runId,
        CancellationToken cancellationToken = default);

    Task<CoordinatorRunSnapshot> GetVerifiedAsync(
        Guid runId,
        CancellationToken cancellationToken = default);

    Task VerifyEventChainAsync(Guid runId, CancellationToken cancellationToken = default);
}

public interface ICoordinatorArtifactStore
{
    string RootPath { get; }

    Task<StoredArtifact> PutJsonAsync<T>(T value, CancellationToken cancellationToken = default);

    Task<T> ReadJsonAsync<T>(string relativePath, string expectedSha256, CancellationToken cancellationToken = default);
}

public sealed class CoordinatorConcurrencyException(string message) : InvalidOperationException(message);

public sealed class CoordinatorIntegrityException(string message) : Exception(message);
