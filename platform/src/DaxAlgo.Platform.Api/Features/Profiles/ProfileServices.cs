using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Billing;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Profiles;

public sealed class ProfileService(
    PlatformDbContext database,
    TimeProvider timeProvider)
{
    public Task<Profile?> FindAsync(string subject, CancellationToken cancellationToken) =>
        database.Profiles.AsNoTracking().SingleOrDefaultAsync(x => x.Subject == subject, cancellationToken);

    public async Task<Profile> BootstrapAsync(
        ManagedIdentity identity,
        string? requestedDisplayName,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var profile = await database.Profiles.SingleOrDefaultAsync(
            x => x.Subject == identity.Subject,
            cancellationToken);

        if (profile is null)
        {
            profile = new Profile
            {
                Id = Guid.NewGuid(),
                Subject = identity.Subject,
                Email = identity.Email,
                DisplayName = NormalizeDisplayName(requestedDisplayName, identity.DisplayName),
                CreatedAt = now,
                UpdatedAt = now,
            };
            database.Profiles.Add(profile);
        }
        else
        {
            profile.Email = identity.Email;
            profile.DisplayName = NormalizeDisplayName(requestedDisplayName, identity.DisplayName);
            profile.UpdatedAt = now;
        }

        await database.SaveChangesAsync(cancellationToken);
        return profile;
    }

    public async Task<Profile> RequireAsync(
        ManagedIdentity identity,
        CancellationToken cancellationToken)
    {
        return await FindAsync(identity.Subject, cancellationToken)
            ?? throw new PlatformConflictException("Bootstrap the product profile before using this endpoint.");
    }

    private static string NormalizeDisplayName(string? requested, string fallback)
    {
        var value = string.IsNullOrWhiteSpace(requested) ? fallback : requested.Trim();
        if (value.Length is < 1 or > 120)
        {
            throw new PlatformValidationException("Display name must contain 1 to 120 characters.");
        }

        return value;
    }
}

public sealed class EntitlementProjector(BillingGracePolicy gracePolicy)
{
    private static readonly IReadOnlyList<string> BasicCapabilities =
        ["terminal.core", "marketplace.catalog", "marketplace.publisher", "strategy.authoring"];

    private static readonly IReadOnlyList<string> ProfessionalCapabilities =
        [.. BasicCapabilities, "analysis.advanced", "terminal.professional", "ai.vibe_quant"];

    public EntitlementSnapshot Project(
        Guid accountId,
        AccountSubscription? subscription,
        DateTimeOffset now)
    {
        now = now.ToUniversalTime();
        var subscriptionValidUntil = subscription?.Status == SubscriptionStatus.PastDue
            ? gracePolicy.GetPastDueValidUntil(subscription.CurrentPeriodEnd)
            : subscription?.CurrentPeriodEnd;
        var paidPlanIsActive = subscription is not null
            && subscription.Status switch
            {
                SubscriptionStatus.Active or SubscriptionStatus.Canceled =>
                    subscription.CurrentPeriodEnd > now,
                SubscriptionStatus.PastDue => subscriptionValidUntil > now,
                _ => false,
            };
        var entitlementIsActive = subscription?.Status is not (
            SubscriptionStatus.Unpaid or SubscriptionStatus.Revoked);

        var tier = paidPlanIsActive ? subscription!.Plan : PlanTier.Basic;
        var leaseEnd = entitlementIsActive ? now.AddDays(7) : now;
        if (paidPlanIsActive && subscriptionValidUntil!.Value < leaseEnd)
        {
            leaseEnd = subscriptionValidUntil.Value;
        }

        var capabilities = tier switch
        {
            PlanTier.Professional => ProfessionalCapabilities,
            _ => BasicCapabilities,
        };

        return new EntitlementSnapshot(
            accountId,
            tier,
            IsActive: entitlementIsActive,
            IssuedAt: now,
            LeaseExpiresAt: leaseEnd,
            SubscriptionValidUntil: subscriptionValidUntil,
            capabilities);
    }
}

public sealed class EntitlementService(
    PlatformDbContext database,
    EntitlementProjector projector,
    TimeProvider timeProvider)
{
    public async Task<EntitlementSnapshot> GetAsync(
        Guid accountId,
        CancellationToken cancellationToken) =>
        await GetAtAsync(accountId, timeProvider.GetUtcNow(), cancellationToken);

    public async Task<EntitlementSnapshot> GetAtAsync(
        Guid accountId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var subscription = await database.Subscriptions.AsNoTracking()
            .SingleOrDefaultAsync(x => x.AccountId == accountId, cancellationToken);
        return projector.Project(accountId, subscription, now);
    }

    public async Task<EntitlementSnapshot> RequireTierAsync(
        Guid accountId,
        PlanTier requiredTier,
        CancellationToken cancellationToken)
    {
        var entitlement = await GetAsync(accountId, cancellationToken);
        if (entitlement.Tier < requiredTier)
        {
            throw new PlatformForbiddenException(
                $"{requiredTier} entitlement is required for this operation.");
        }

        return entitlement;
    }
}

public sealed class PlatformValidationException(string message) : Exception(message);

public sealed class PlatformConflictException(string message) : Exception(message);

public sealed class PlatformNotFoundException(string message) : Exception(message);

public sealed class PlatformForbiddenException(string message) : Exception(message);

public sealed class PlatformPaymentRequiredException(string message) : Exception(message);

public sealed class PlatformServiceUnavailableException(string message) : Exception(message);
