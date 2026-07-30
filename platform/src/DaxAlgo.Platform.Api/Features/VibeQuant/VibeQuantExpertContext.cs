using System.Text;
using DaxAlgo.Platform.Configuration;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Retrieval;

namespace DaxAlgo.Platform.Features.VibeQuant;

internal sealed class VibeQuantExpertContextCatalog
{
    private readonly PreparedExpertContextPack? preparedPack;
    private readonly ExpertContextQueryPolicy? policy;
    private readonly int queryMaxCharacters;

    public VibeQuantExpertContextCatalog(VibeQuantOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        queryMaxCharacters = options.ExpertContextQueryMaxCharacters;
        if (options.ExpertContextMode == "Disabled")
        {
            return;
        }
        if (options.ExpertContextMode != "Pinned" ||
            options.ExpertContextPackPath is null ||
            options.ExpertContextPackSha256 is null ||
            options.ExpertContextCorpusId is null ||
            options.ExpertContextCorpusVersion is null)
        {
            throw new InvalidOperationException("Vibe Quant expert-context activation is incomplete.");
        }

        try
        {
            preparedPack = ExpertContextPackTools.LoadPrepared(
                options.ExpertContextPackPath,
                options.ExpertContextPackSha256);
            policy = options.CreateExpertContextPolicy();
            ExpertContextPackTools.ValidateQueryPolicy(policy);
        }
        catch (CoordinatorValidationException exception)
        {
            throw new InvalidOperationException(
                "The configured Vibe Quant expert-context pack failed validation.",
                exception);
        }
        if (!StringComparer.Ordinal.Equals(preparedPack.CorpusId, options.ExpertContextCorpusId) ||
            !StringComparer.Ordinal.Equals(preparedPack.CorpusVersion, options.ExpertContextCorpusVersion))
        {
            throw new InvalidOperationException(
                "The configured Vibe Quant expert-context pack has the wrong corpus identity.");
        }
    }

    public IReadOnlyList<CoordinatorContextSource> MaterializeExecutionSources(
        Guid accountId,
        string objective,
        IReadOnlyList<CoordinatorContextSource> submittedSources)
    {
        if (preparedPack is null)
        {
            return submittedSources;
        }

        var tenantId = accountId.ToString("D");
        var resolver = preparedPack.Activate(
            new ExpertContextActivation
            {
                TenantId = tenantId,
                CorpusId = preparedPack.CorpusId,
                CorpusVersion = preparedPack.CorpusVersion,
                PackSha256 = preparedPack.PackSha256
            });
        var selection = resolver.Resolve(new ExpertContextResolutionRequest
        {
            TenantId = tenantId,
            CorpusId = preparedPack.CorpusId,
            CorpusVersion = preparedPack.CorpusVersion,
            PackSha256 = preparedPack.PackSha256,
            Query = BuildQuery(objective, submittedSources, queryMaxCharacters),
            Policy = policy!
        });
        return preparedPack.MaterializeExecutionSources(
            submittedSources,
            selection);
    }

    private static string BuildQuery(
        string objective,
        IReadOnlyList<CoordinatorContextSource> submittedSources,
        int maxCharacters)
    {
        var builder = new StringBuilder(Math.Min(maxCharacters, 16_384));
        AppendBounded(builder, objective, maxCharacters);
        foreach (var source in submittedSources)
        {
            AppendBounded(builder, "\n\n[source:", maxCharacters);
            AppendBounded(builder, source.Id, maxCharacters);
            AppendBounded(builder, "]\n", maxCharacters);
            AppendBounded(builder, source.Title, maxCharacters);
            AppendBounded(builder, "\n", maxCharacters);
            AppendBounded(builder, source.Content, maxCharacters);
            if (builder.Length == maxCharacters)
            {
                break;
            }
        }
        return builder.ToString();
    }

    private static void AppendBounded(StringBuilder builder, string value, int maxCharacters)
    {
        var remaining = maxCharacters - builder.Length;
        if (remaining <= 0 || value.Length == 0)
        {
            return;
        }
        var count = Math.Min(remaining, value.Length);
        if (count < value.Length && count > 0 &&
            char.IsHighSurrogate(value[count - 1]) && char.IsLowSurrogate(value[count]))
        {
            count--;
        }
        builder.Append(value, 0, count);
    }
}
