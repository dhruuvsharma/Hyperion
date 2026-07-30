using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class MarketplaceGrantService(
    PlatformDbContext database,
    TimeProvider timeProvider,
    SignalSessionRegistry? signalSessions = null)
{
    private static readonly DateTimeOffset OneTimeGrantExpiry =
        new(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);

    public async Task<EntitlementGrant> ActivateAsync(
        Guid orderId,
        DateTimeOffset? subscriptionValidUntil,
        string? providerSubscriptionId,
        CancellationToken cancellationToken)
    {
        var order = await database.Orders.SingleOrDefaultAsync(
            candidate => candidate.Id == orderId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("The marketplace order does not exist.");
        var release = await database.StrategyReleases
            .SingleOrDefaultAsync(
                candidate => candidate.Id == order.ReleaseId
                    && candidate.CatalogItemId == order.CatalogItemId
                    && candidate.Status == MarketplaceReleaseStatus.Approved,
                cancellationToken)
            ?? throw new PlatformConflictException("The purchased marketplace release is not approved.");

        var now = timeProvider.GetUtcNow();
        var grantType = order.PriceMode == MarketplacePriceMode.Subscription
            ? EntitlementGrantType.MarketplaceSubscription
            : EntitlementGrantType.MarketplaceLicense;
        var validUntil = grantType == EntitlementGrantType.MarketplaceSubscription
            ? subscriptionValidUntil
                ?? throw new PlatformValidationException(
                    "A marketplace subscription grant requires its provider period end.")
            : OneTimeGrantExpiry;
        if (validUntil <= now)
        {
            throw new PlatformValidationException("The marketplace grant validity must end in the future.");
        }

        var grant = await database.EntitlementGrants.SingleOrDefaultAsync(
            candidate => candidate.OrderId == order.Id,
            cancellationToken);
        if (grant?.Status == EntitlementGrantStatus.Revoked)
        {
            return grant;
        }

        if (grant is null)
        {
            grant = new EntitlementGrant
            {
                Id = Guid.NewGuid(),
                AccountId = order.BuyerAccountId,
                CatalogItemId = order.CatalogItemId,
                OrderId = order.Id,
                Type = grantType,
                ValidFrom = now,
            };
            database.EntitlementGrants.Add(grant);
        }
        else if (grant.AccountId != order.BuyerAccountId
            || grant.CatalogItemId != order.CatalogItemId
            || grant.Type != grantType)
        {
            throw new InvalidOperationException("The persisted marketplace grant does not match its order.");
        }

        grant.Status = EntitlementGrantStatus.Active;
        grant.ValidUntil = validUntil;
        grant.RevokedAt = null;
        grant.UpdatedAt = now;
        order.Status = OrderStatus.Paid;
        order.ProviderSubscriptionId = providerSubscriptionId ?? order.ProviderSubscriptionId;
        order.UpdatedAt = now;

        var license = await database.MarketplaceLicenses.SingleOrDefaultAsync(
            candidate => candidate.AccountId == order.BuyerAccountId
                && candidate.ReleaseId == release.Id,
            cancellationToken);
        if (license is null)
        {
            license = new MarketplaceLicense
            {
                Id = Guid.NewGuid(),
                AccountId = order.BuyerAccountId,
                ReleaseId = release.Id,
                GrantId = grant.Id,
            };
            database.MarketplaceLicenses.Add(license);
        }
        else if (license.GrantId != grant.Id)
        {
            throw new PlatformConflictException("The marketplace release is already licensed by another grant.");
        }

        license.Status = MarketplaceLicenseStatus.Active;
        license.ValidFrom = grant.ValidFrom;
        license.ValidUntil = grant.ValidUntil;
        license.RevokedAt = null;
        await database.SaveChangesAsync(cancellationToken);
        return grant;
    }

    public async Task RevokeAsync(
        Guid orderId,
        OrderStatus orderStatus,
        string reason,
        CancellationToken cancellationToken)
    {
        if (orderStatus is not (OrderStatus.Refunded or OrderStatus.Canceled))
        {
            throw new ArgumentOutOfRangeException(nameof(orderStatus));
        }

        var order = await database.Orders.SingleOrDefaultAsync(
            candidate => candidate.Id == orderId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("The marketplace order does not exist.");
        var grant = await database.EntitlementGrants.SingleOrDefaultAsync(
            candidate => candidate.OrderId == order.Id,
            cancellationToken);
        var now = timeProvider.GetUtcNow();
        order.Status = orderStatus;
        order.UpdatedAt = now;
        if (grant is null)
        {
            await database.SaveChangesAsync(cancellationToken);
            return;
        }

        var license = await database.MarketplaceLicenses.SingleOrDefaultAsync(
            candidate => candidate.GrantId == grant.Id,
            cancellationToken);

        grant.Status = EntitlementGrantStatus.Revoked;
        grant.RevokedAt = now;
        grant.UpdatedAt = now;
        if (license is null)
        {
            await database.SaveChangesAsync(cancellationToken);
            return;
        }

        license.Status = MarketplaceLicenseStatus.Revoked;
        license.RevokedAt = now;
        var sessionsToRevoke = await database.SignalSessions
            .Where(candidate => candidate.LicenseId == license.Id
                && candidate.EndedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var session in sessionsToRevoke)
        {
            session.RevokedAt = now;
            session.EndedAt = now;
        }
        if (!await database.Revocations.AnyAsync(
                candidate => candidate.TargetType == "license"
                    && candidate.TargetId == license.Id.ToString("D"),
                cancellationToken))
        {
            database.Revocations.Add(new EntitlementRevocation
            {
                TargetType = "license",
                TargetId = license.Id.ToString("D"),
                Reason = reason,
                IssuedAt = now,
            });
        }

        await database.SaveChangesAsync(cancellationToken);
        signalSessions?.RevokeLicense(license.Id);
    }
}
