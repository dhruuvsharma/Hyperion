using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed record MarketplaceOnboardingResult(
    MarketplacePublisher Publisher,
    MarketplaceOnboardingLink Link);

public sealed record MarketplacePublisherPayoutReport(
    MarketplacePublisher? Publisher,
    MarketplacePayoutReport? Report);

public sealed class MarketplacePublisherService(
    PlatformDbContext database,
    IMarketplaceCommerceProvider commerceProvider,
    TimeProvider timeProvider)
{
    public Task<MarketplacePublisher?> FindAsync(
        Guid accountId,
        CancellationToken cancellationToken) =>
        database.MarketplacePublishers.AsNoTracking().SingleOrDefaultAsync(
            candidate => candidate.AccountId == accountId,
            cancellationToken);

    public async Task<MarketplacePublisherPayoutReport> GetPayoutReportAsync(
        Guid accountId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken)
    {
        var publisher = await FindAsync(accountId, cancellationToken);
        if (publisher is null || string.IsNullOrWhiteSpace(publisher.ConnectAccountId))
        {
            return new MarketplacePublisherPayoutReport(publisher, null);
        }

        var report = await commerceProvider.GetPayoutReportAsync(
            publisher.ConnectAccountId,
            cursor,
            pageSize,
            cancellationToken);
        return new MarketplacePublisherPayoutReport(publisher, report);
    }

    public async Task<MarketplaceOnboardingResult> CreateOnboardingLinkAsync(
        Guid accountId,
        string email,
        string displayName,
        string country,
        CancellationToken cancellationToken)
    {
        var publisher = await database.MarketplacePublishers.SingleOrDefaultAsync(
            candidate => candidate.AccountId == accountId,
            cancellationToken);
        if (publisher is null)
        {
            var account = await commerceProvider.CreateExpressAccountAsync(
                new MarketplaceExpressAccountRequest(
                    accountId,
                    email,
                    displayName,
                    country,
                    $"marketplace-express-account:{accountId:N}"),
                cancellationToken);
            var now = timeProvider.GetUtcNow();
            publisher = new MarketplacePublisher
            {
                AccountId = accountId,
                ConnectAccountId = account.ProviderAccountId,
                DetailsSubmitted = account.DetailsSubmitted,
                ChargesEnabled = account.ChargesEnabled,
                PayoutsEnabled = account.PayoutsEnabled,
                Status = ResolveStatus(
                    account.DetailsSubmitted,
                    account.ChargesEnabled,
                    account.PayoutsEnabled),
                CreatedAt = now,
                UpdatedAt = now,
            };
            database.MarketplacePublishers.Add(publisher);
            await database.SaveChangesAsync(cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(publisher.ConnectAccountId))
        {
            throw new InvalidOperationException("The marketplace publisher has no Connect account identity.");
        }

        var link = await commerceProvider.CreateOnboardingLinkAsync(
            new MarketplaceOnboardingLinkRequest(
                publisher.ConnectAccountId,
                $"marketplace-onboarding-link:{accountId:N}:{publisher.UpdatedAt.ToUnixTimeSeconds()}"),
            cancellationToken);
        return new MarketplaceOnboardingResult(publisher, link);
    }

    public async Task<MarketplacePublisher> ApplyProviderStatusAsync(
        string connectAccountId,
        bool detailsSubmitted,
        bool chargesEnabled,
        bool payoutsEnabled,
        CancellationToken cancellationToken)
    {
        var publisher = await database.MarketplacePublishers.SingleOrDefaultAsync(
            candidate => candidate.ConnectAccountId == connectAccountId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("The Connect publisher account does not exist.");
        publisher.DetailsSubmitted = detailsSubmitted;
        publisher.ChargesEnabled = chargesEnabled;
        publisher.PayoutsEnabled = payoutsEnabled;
        publisher.Status = ResolveStatus(detailsSubmitted, chargesEnabled, payoutsEnabled);
        publisher.UpdatedAt = timeProvider.GetUtcNow();
        await database.SaveChangesAsync(cancellationToken);
        return publisher;
    }

    private static MarketplacePublisherStatus ResolveStatus(
        bool detailsSubmitted,
        bool chargesEnabled,
        bool payoutsEnabled) =>
        detailsSubmitted && chargesEnabled && payoutsEnabled
            ? MarketplacePublisherStatus.Complete
            : detailsSubmitted
                ? MarketplacePublisherStatus.Restricted
                : MarketplacePublisherStatus.Pending;
}
