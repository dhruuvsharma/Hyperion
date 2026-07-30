using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Persistence;

namespace TradingTerminal.Ai.Coordinator.Orchestration;

public sealed record CoordinatorPrompt(string SystemPrompt, string UserPrompt);

public sealed class RolePromptBuilder(ICoordinatorArtifactStore artifactStore)
{
    public async Task<CoordinatorPrompt> BuildAsync(
        CoordinatorRunSnapshot snapshot,
        CoordinatorRole role,
        CancellationToken cancellationToken = default)
    {
        var priorOutputs = new List<CoordinatorRoleOutput>(snapshot.Artifacts.Count);
        foreach (var reference in snapshot.Artifacts)
        {
            priorOutputs.Add(await artifactStore.ReadJsonAsync<CoordinatorRoleOutput>(
                reference.RelativePath,
                reference.Sha256,
                cancellationToken).ConfigureAwait(false));
        }

        var sources = snapshot.Spec.Sources
            .Select(source => new CoordinatorPromptSource(source.Id, source.Title, source.Content))
            .ToArray();
        var userPrompt = CoordinatorPromptRenderer.BuildUserPrompt(
            snapshot.Spec.Objective,
            sources,
            priorOutputs,
            role,
            snapshot.Spec.Purpose);
        return new CoordinatorPrompt(
            CoordinatorPromptCatalog.SystemInstruction(role, snapshot.Spec.Purpose),
            userPrompt);
    }
}
