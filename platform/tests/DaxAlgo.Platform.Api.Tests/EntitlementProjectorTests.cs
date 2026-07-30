using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Billing;
using DaxAlgo.Platform.Features.Profiles;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class EntitlementProjectorTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ActiveSubscriptionProjectsPaidTierAndBoundedOfflineLease()
    {
        var subscription = new AccountSubscription
        {
            AccountId = Guid.NewGuid(),
            Provider = "test",
            ProviderSubscriptionId = "sub_1",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.Active,
            CurrentPeriodEnd = Now.AddDays(3),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector().Project(
            subscription.AccountId,
            subscription,
            Now);

        Assert.Equal(PlanTier.Professional, entitlement.Tier);
        Assert.Equal(Now.AddDays(3), entitlement.LeaseExpiresAt);
        Assert.Contains("analysis.advanced", entitlement.Capabilities);
        Assert.Contains("strategy.authoring", entitlement.Capabilities);
        Assert.Contains("marketplace.publisher", entitlement.Capabilities);
        Assert.Contains("ai.vibe_quant", entitlement.Capabilities);
    }

    [Fact]
    public void ExpiredSubscriptionFallsBackToBasic()
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = "sub_2",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.Active,
            CurrentPeriodEnd = Now.AddMinutes(-1),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector().Project(accountId, subscription, Now);

        Assert.Equal(PlanTier.Basic, entitlement.Tier);
        Assert.Equal(Now.AddDays(7), entitlement.LeaseExpiresAt);
        Assert.Contains("strategy.authoring", entitlement.Capabilities);
        Assert.DoesNotContain("analysis.advanced", entitlement.Capabilities);
    }

    [Theory]
    [InlineData(SubscriptionStatus.Active)]
    [InlineData(SubscriptionStatus.Canceled)]
    public void PaidThroughBoundaryFallsBackToBasicWithAFutureLease(
        SubscriptionStatus status)
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = $"sub_boundary_{status}",
            Plan = PlanTier.Professional,
            Status = status,
            CurrentPeriodEnd = Now,
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector().Project(accountId, subscription, Now);

        Assert.Equal(PlanTier.Basic, entitlement.Tier);
        Assert.Equal(Now, entitlement.IssuedAt);
        Assert.Equal(Now.AddDays(7), entitlement.LeaseExpiresAt);
        Assert.Contains("marketplace.publisher", entitlement.Capabilities);
    }

    [Fact]
    public void CanceledSubscriptionRetainsPaidTierThroughCurrentPeriod()
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = "sub_canceled",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.Canceled,
            CurrentPeriodEnd = Now.AddMinutes(1),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector().Project(accountId, subscription, Now);

        Assert.Equal(PlanTier.Professional, entitlement.Tier);
    }

    [Fact]
    public void TrialingSubscriptionDoesNotGrantPaidTierByDefault()
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = "sub_trialing",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.Trialing,
            CurrentPeriodEnd = Now.AddDays(7),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector().Project(accountId, subscription, Now);

        Assert.Equal(PlanTier.Basic, entitlement.Tier);
    }

    [Fact]
    public void PastDueSubscriptionRetainsPaidTierInsideVersionedGrace()
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = "sub_past_due_grace",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.PastDue,
            CurrentPeriodEnd = Now.AddDays(-1),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector(pastDueGraceDays: 3).Project(
            accountId,
            subscription,
            Now);

        Assert.Equal(PlanTier.Professional, entitlement.Tier);
        Assert.Equal(Now.AddDays(2), entitlement.SubscriptionValidUntil);
        Assert.Equal(Now.AddDays(2), entitlement.LeaseExpiresAt);
    }

    [Theory]
    [InlineData(-3)]
    [InlineData(-4)]
    public void PastDueSubscriptionAtOrBeyondMaximumGraceFallsBackToBasic(
        int periodEndDaysFromNow)
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = $"sub_past_due_{periodEndDaysFromNow}",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.PastDue,
            CurrentPeriodEnd = Now.AddDays(periodEndDaysFromNow),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector(pastDueGraceDays: 3).Project(
            accountId,
            subscription,
            Now);

        Assert.Equal(PlanTier.Basic, entitlement.Tier);
        Assert.Equal(Now.AddDays(7), entitlement.LeaseExpiresAt);
        Assert.DoesNotContain("terminal.professional", entitlement.Capabilities);
    }

    [Theory]
    [InlineData(SubscriptionStatus.Unpaid)]
    [InlineData(SubscriptionStatus.Revoked)]
    public void InactiveSubscriptionStatusesDoNotGrantPaidTier(
        SubscriptionStatus status)
    {
        var accountId = Guid.NewGuid();
        var subscription = new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = $"sub_inactive_{status}",
            Plan = PlanTier.Professional,
            Status = status,
            CurrentPeriodEnd = Now.AddDays(30),
            UpdatedAt = Now,
        };

        var entitlement = CreateProjector().Project(accountId, subscription, Now);

        Assert.Equal(PlanTier.Basic, entitlement.Tier);
        Assert.False(entitlement.IsActive);
        Assert.Equal(Now, entitlement.LeaseExpiresAt);
        Assert.DoesNotContain("terminal.professional", entitlement.Capabilities);
    }

    private static EntitlementProjector CreateProjector(int pastDueGraceDays = 3) =>
        new(new BillingGracePolicy(new BillingGracePolicyOptions
        {
            Version = BillingGracePolicy.CurrentVersion,
            PastDueGraceDays = pastDueGraceDays,
        }));
}
