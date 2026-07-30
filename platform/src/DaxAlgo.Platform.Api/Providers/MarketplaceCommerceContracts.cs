namespace DaxAlgo.Platform.Providers;

public enum MarketplacePricingMode
{
    OneTime,
    MonthlySubscription,
}

public sealed record MarketplaceExpressAccountRequest(
    Guid SellerAccountId,
    string Email,
    string DisplayName,
    string Country,
    string IdempotencyKey);

public sealed record MarketplaceExpressAccount(
    string ProviderAccountId,
    bool ChargesEnabled,
    bool PayoutsEnabled,
    bool DetailsSubmitted);

public sealed record MarketplaceOnboardingLinkRequest(
    string SellerConnectAccountId,
    string IdempotencyKey);

public sealed record MarketplaceOnboardingLink(
    string SellerConnectAccountId,
    string Url,
    DateTimeOffset ExpiresAt);

public sealed record MarketplaceCheckoutRequest(
    Guid OrderId,
    Guid ListingId,
    Guid ReleaseId,
    Guid BuyerAccountId,
    string SellerConnectAccountId,
    string Title,
    long AmountInMinorUnits,
    string Currency,
    MarketplacePricingMode PricingMode,
    string IdempotencyKey);

public sealed record MarketplaceCheckout(
    string ProviderCheckoutId,
    string CheckoutUrl);

public sealed record MarketplaceBalanceAmount(
    long AmountInMinorUnits,
    string Currency);

public sealed record MarketplacePayout(
    string ProviderPayoutId,
    long AmountInMinorUnits,
    string Currency,
    string Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset ArrivalDate,
    string Method,
    bool Automatic,
    string? FailureCode);

public sealed record MarketplacePayoutReport(
    IReadOnlyList<MarketplaceBalanceAmount> Available,
    IReadOnlyList<MarketplaceBalanceAmount> Pending,
    IReadOnlyList<MarketplacePayout> Payouts,
    string? NextCursor);

public interface IMarketplaceCommerceProvider
{
    string Name { get; }

    Task<MarketplaceExpressAccount> CreateExpressAccountAsync(
        MarketplaceExpressAccountRequest request,
        CancellationToken cancellationToken);

    Task<MarketplaceOnboardingLink> CreateOnboardingLinkAsync(
        MarketplaceOnboardingLinkRequest request,
        CancellationToken cancellationToken);

    Task<MarketplaceCheckout> CreateCheckoutAsync(
        MarketplaceCheckoutRequest request,
        CancellationToken cancellationToken);

    Task<MarketplacePayoutReport> GetPayoutReportAsync(
        string sellerConnectAccountId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken);
}

public sealed class MarketplaceSalesDisabledException()
    : InvalidOperationException("Marketplace sales are disabled pending GA approval.");
