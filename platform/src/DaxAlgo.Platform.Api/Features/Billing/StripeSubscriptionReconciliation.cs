using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;
using Stripe;

namespace DaxAlgo.Platform.Features.Billing;

public sealed class StripeSubscriptionReconciler(
    PlatformDbContext database,
    StripeBillingProvider provider,
    IPlanCatalog planCatalog,
    TimeProvider timeProvider,
    ILogger<StripeSubscriptionReconciler> logger)
{
    public async Task ReconcileOnceAsync(CancellationToken cancellationToken)
    {
        var subscriptions = await database.Subscriptions
            .Where(subscription =>
                subscription.Provider == StripeBillingProvider.ProviderName
                && subscription.Status != SubscriptionStatus.Revoked)
            .ToListAsync(cancellationToken);

        foreach (var subscription in subscriptions)
        {
            try
            {
                var state = await provider.GetSubscriptionStateAsync(
                    subscription.ProviderSubscriptionId,
                    cancellationToken);
                if (state.AccountId is not null && state.AccountId != subscription.AccountId)
                {
                    throw new BillingWebhookException(
                        "The Stripe subscription metadata belongs to a different account.");
                }

                subscription.Plan = planCatalog.ResolveProviderPrice(
                    StripeBillingProvider.ProviderName,
                    state.PriceId);
                subscription.Status = state.Status;
                subscription.CurrentPeriodEnd = state.CurrentPeriodEnd;
                subscription.UpdatedAt = timeProvider.GetUtcNow();
            }
            catch (StripeException exception)
                when (string.Equals(
                    exception.StripeError?.Code,
                    "resource_missing",
                    StringComparison.Ordinal))
            {
                subscription.Status = SubscriptionStatus.Revoked;
                subscription.UpdatedAt = timeProvider.GetUtcNow();
                StripeBillingLogging.SubscriptionMissing(
                    logger,
                    subscription.ProviderSubscriptionId,
                    exception);
            }
            catch (BillingWebhookException exception)
            {
                subscription.Status = SubscriptionStatus.Unpaid;
                subscription.UpdatedAt = timeProvider.GetUtcNow();
                StripeBillingLogging.SubscriptionInvalid(
                    logger,
                    subscription.ProviderSubscriptionId,
                    exception);
            }
            catch (StripeException exception)
            {
                StripeBillingLogging.SubscriptionRefreshFailed(
                    logger,
                    subscription.ProviderSubscriptionId,
                    exception);
            }
        }

        await database.SaveChangesAsync(cancellationToken);
    }
}

public sealed class StripeSubscriptionReconciliationWorker(
    IServiceScopeFactory scopeFactory,
    TimeProvider timeProvider,
    ILogger<StripeSubscriptionReconciliationWorker> logger) : BackgroundService
{
    private static readonly TimeSpan ReconciliationInterval = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(ReconciliationInterval, timeProvider);
        do
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var reconciler = scope.ServiceProvider.GetRequiredService<StripeSubscriptionReconciler>();
                await reconciler.ReconcileOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                StripeBillingLogging.ReconciliationCycleFailed(logger, exception);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

internal static partial class StripeBillingLogging
{
    [LoggerMessage(
        EventId = 2101,
        Level = LogLevel.Warning,
        Message = "Stripe subscription {SubscriptionId} no longer exists and was revoked.")]
    public static partial void SubscriptionMissing(
        ILogger logger,
        string subscriptionId,
        Exception exception);

    [LoggerMessage(
        EventId = 2102,
        Level = LogLevel.Error,
        Message = "Stripe subscription {SubscriptionId} returned invalid billing state and was suspended.")]
    public static partial void SubscriptionInvalid(
        ILogger logger,
        string subscriptionId,
        Exception exception);

    [LoggerMessage(
        EventId = 2103,
        Level = LogLevel.Warning,
        Message = "Stripe subscription {SubscriptionId} could not be refreshed; local state was retained.")]
    public static partial void SubscriptionRefreshFailed(
        ILogger logger,
        string subscriptionId,
        Exception exception);

    [LoggerMessage(
        EventId = 2104,
        Level = LogLevel.Error,
        Message = "The Stripe subscription reconciliation cycle failed.")]
    public static partial void ReconciliationCycleFailed(
        ILogger logger,
        Exception exception);
}
