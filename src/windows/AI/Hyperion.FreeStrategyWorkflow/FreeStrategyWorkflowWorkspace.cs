using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Persistence;

namespace Hyperion.FreeStrategyWorkflow;

/// <summary>Creates one durable local SQLite/CAS workspace for Terminal or CLI integration.</summary>
public sealed class FreeStrategyWorkflowWorkspace
{
    public FreeStrategyWorkflowWorkspace(string rootPath, ILlmProvider provider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentNullException.ThrowIfNull(provider);
        RootPath = Path.GetFullPath(rootPath);
        Directory.CreateDirectory(RootPath);
        DatabasePath = Path.Combine(RootPath, "workflow.db");
        ArtifactPath = Path.Combine(RootPath, "artifacts");
        Store = new SqliteCoordinatorStore(DatabasePath);
        ArtifactStore = new ContentAddressedArtifactStore(ArtifactPath);
        Runner = new FreeStrategyWorkflowRunner(Store, ArtifactStore, provider);
    }

    public string RootPath { get; }

    public string DatabasePath { get; }

    public string ArtifactPath { get; }

    public ICoordinatorStore Store { get; }

    public ICoordinatorArtifactStore ArtifactStore { get; }

    public FreeStrategyWorkflowRunner Runner { get; }
}
