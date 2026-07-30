using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Orchestration;

public sealed record CoordinatorPromptSource(string Id, string Title, string Content);

public static class CoordinatorPromptRenderer
{
    public static string BuildUserPrompt(
        string objective,
        IReadOnlyList<CoordinatorPromptSource> sources,
        IReadOnlyList<CoordinatorRoleOutput> priorOutputs,
        CoordinatorRole role,
        CoordinatorRunPurpose purpose = CoordinatorRunPurpose.Research)
    {
        var prompt = new StringBuilder();
        AppendLine(prompt, CoordinatorPromptCatalog.ResearchObjectiveHeading);
        AppendLine(prompt, objective);
        AppendLine(prompt);
        AppendLine(prompt, CoordinatorPromptCatalog.SourcesHeading);
        AppendLine(prompt, CoordinatorPromptCatalog.SourceSafetyInstruction);
        foreach (var source in sources)
        {
            AppendLine(
                prompt,
                $"<{CoordinatorPromptCatalog.SourceElementName} id=\"{source.Id}\" title=\"{Escape(source.Title)}\">");
            AppendLine(prompt, Escape(source.Content));
            AppendLine(prompt, CoordinatorPromptCatalog.SourceCloseTag);
        }

        if (priorOutputs.Count > 0)
        {
            AppendLine(prompt);
            AppendLine(prompt, CoordinatorPromptCatalog.PriorOutputsHeading);
            foreach (var priorOutput in priorOutputs)
            {
                AppendLine(prompt, JsonSerializer.Serialize(priorOutput, CoordinatorJson.Options));
            }
        }

        AppendLine(prompt);
        AppendLine(prompt, $"{CoordinatorPromptCatalog.CurrentRolePrefix} {role}");
        AppendLine(prompt, CoordinatorPromptCatalog.RoleInstruction(role, purpose));
        AppendLine(prompt, CoordinatorPromptCatalog.ReturnInstruction);
        AppendLine(
            prompt,
            purpose == CoordinatorRunPurpose.StrategyAuthoring && role == CoordinatorRole.Synthesizer
                ? CoordinatorPromptCatalog.StrategyOutputContract
                : CoordinatorPromptCatalog.OutputContract);
        AppendLine(prompt, CoordinatorPromptCatalog.EvidenceInstruction);
        if (role == CoordinatorRole.RiskJudge)
        {
            AppendLine(prompt, CoordinatorPromptCatalog.RiskDecisionInstruction);
        }

        return prompt.ToString();
    }

    private static void AppendLine(StringBuilder prompt, string? value = null) =>
        prompt.Append(value).Append(CoordinatorPromptCatalog.PromptNewLine);

    private static string Escape(string value) => value
        .Replace("&", "&amp;", StringComparison.Ordinal)
        .Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal)
        .Replace("\"", "&quot;", StringComparison.Ordinal);
}
