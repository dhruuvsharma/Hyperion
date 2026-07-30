using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Providers;
using System.Collections.ObjectModel;

namespace DaxAlgo.Platform.Features.Billing;

public sealed record PlanOffer(
    PlanTier Tier,
    string Currency,
    long UnitAmountInCents,
    string? BillingInterval);

public interface IPlanCatalog
{
    IReadOnlyList<PlanOffer> Plans { get; }

    PlanTier ResolveProviderPrice(string provider, string priceId);
}

public sealed class PlanCatalog : IPlanCatalog
{
    private static readonly ReadOnlyCollection<PlanOffer> CanonicalPlans = Array.AsReadOnly<PlanOffer>(
    [
        new(PlanTier.Basic, "USD", 0, null),
        new(PlanTier.Professional, "USD", 7_900, "month"),
    ]);

    private readonly string configuredProvider;
    private readonly Dictionary<string, PlanTier> prices;

    public PlanCatalog(BillingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        configuredProvider = RequireConfiguration(options.Provider, "Billing:Provider");
        var professional = RequireConfiguration(
            options.PriceIds.ProfessionalMonthly,
            "Billing:PriceIds:ProfessionalMonthly");
        prices = new Dictionary<string, PlanTier>(StringComparer.Ordinal)
        {
            [professional] = PlanTier.Professional,
        };
    }

    public IReadOnlyList<PlanOffer> Plans => CanonicalPlans;

    public PlanTier ResolveProviderPrice(string provider, string priceId)
    {
        if (!string.Equals(configuredProvider, provider, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(priceId)
            || !prices.TryGetValue(priceId, out var tier))
        {
            throw new BillingWebhookException("The billing event contains an unrecognized provider price ID.");
        }

        return tier;
    }

    private static string RequireConfiguration(string value, string path)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{path} must be configured.");
        }

        return value.Trim();
    }
}
