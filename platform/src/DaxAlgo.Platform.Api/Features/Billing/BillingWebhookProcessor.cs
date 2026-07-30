using System.Collections.Concurrent;
using System.Data;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Features.Marketplace;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace DaxAlgo.Platform.Features.Billing;

public enum BillingWebhookOutcome
{
    Processed,
    Duplicate,
}

public sealed class BillingWebhookProcessor(
    PlatformDbContext database,
    IBillingProvider provider,
    IPlanCatalog planCatalog,
    IWebhookExecutionGate executionGate,
    MarketplaceGrantService marketplaceGrants,
    MarketplacePublisherService marketplacePublishers,
    TimeProvider timeProvider)
{
    public async Task<BillingWebhookOutcome> ProcessAsync(
        ReadOnlyMemory<byte> payload,
        IHeaderDictionary headers,
        CancellationToken cancellationToken)
    {
        var billingEvent = await provider.VerifyWebhookAsync(payload, headers, cancellationToken);
        await using var lease = await executionGate.EnterAsync(
            $"{provider.Name}:{billingEvent.EventId}",
            cancellationToken);

        if (await ReceiptExistsAsync(billingEvent.EventId, cancellationToken))
        {
            return BillingWebhookOutcome.Duplicate;
        }

        IDbContextTransaction? transaction = null;
        if (database.Database.IsRelational())
        {
            transaction = await database.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);
        }

        try
        {
            await ApplyAsync(billingEvent, cancellationToken);
            database.BillingWebhookReceipts.Add(new BillingWebhookReceipt
            {
                Provider = provider.Name,
                EventId = billingEvent.EventId,
                ProcessedAt = timeProvider.GetUtcNow(),
            });
            await database.SaveChangesAsync(cancellationToken);
            if (transaction is not null)
            {
                await transaction.CommitAsync(cancellationToken);
            }

            return BillingWebhookOutcome.Processed;
        }
        catch (DbUpdateException)
        {
            if (transaction is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
            }

            database.ChangeTracker.Clear();
            if (await ReceiptExistsAsync(billingEvent.EventId, cancellationToken))
            {
                return BillingWebhookOutcome.Duplicate;
            }

            throw;
        }
        finally
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync();
            }
        }
    }

    private Task<bool> ReceiptExistsAsync(string eventId, CancellationToken cancellationToken) =>
        database.BillingWebhookReceipts.AsNoTracking().AnyAsync(
            x => x.Provider == provider.Name && x.EventId == eventId,
            cancellationToken);

    private async Task ApplyAsync(
        VerifiedBillingEvent billingEvent,
        CancellationToken cancellationToken)
    {
        if (billingEvent.Purpose == BillingEventPurpose.MarketplacePublisher)
        {
            await ApplyMarketplacePublisherAsync(billingEvent, cancellationToken);
            return;
        }

        if (billingEvent.Purpose == BillingEventPurpose.MarketplaceOrder
            || billingEvent.EventType is "order.paid" or "order.refunded")
        {
            await ApplyMarketplaceOrderAsync(billingEvent, cancellationToken);
            return;
        }

        switch (billingEvent.EventType)
        {
            case "subscription.updated":
            case "customer.subscription.created":
            case "customer.subscription.updated":
                await ApplySubscriptionAsync(billingEvent, cancellationToken);
                break;
            case "subscription.revoked":
            case "charge.refunded":
            case "charge.dispute.created":
                await ApplySubscriptionRevocationAsync(billingEvent, cancellationToken);
                break;
            case "order.paid":
                await ApplyOrderStateAsync(billingEvent, OrderStatus.Paid, cancellationToken);
                break;
            case "order.refunded":
                await ApplyOrderStateAsync(billingEvent, OrderStatus.Refunded, cancellationToken);
                break;
        }
    }

    private async Task ApplySubscriptionAsync(
        VerifiedBillingEvent billingEvent,
        CancellationToken cancellationToken)
    {
        if (billingEvent.AccountId is null
            || string.IsNullOrWhiteSpace(billingEvent.SubscriptionId)
            || string.IsNullOrWhiteSpace(billingEvent.PriceId)
            || billingEvent.SubscriptionStatus is null
            || billingEvent.CurrentPeriodEnd is null)
        {
            throw new BillingWebhookException(
                "Subscription events require accountId, subscriptionId, priceId, status, and currentPeriodEnd.");
        }

        var tier = planCatalog.ResolveProviderPrice(provider.Name, billingEvent.PriceId);

        if (!await database.Profiles.AnyAsync(
                x => x.Id == billingEvent.AccountId.Value,
                cancellationToken))
        {
            throw new BillingWebhookException("The subscription account does not exist.");
        }

        var subscription = await database.Subscriptions.SingleOrDefaultAsync(
            x => x.AccountId == billingEvent.AccountId.Value,
            cancellationToken);
        if (subscription is null)
        {
            subscription = new AccountSubscription
            {
                AccountId = billingEvent.AccountId.Value,
                Provider = provider.Name,
                ProviderSubscriptionId = billingEvent.SubscriptionId,
            };
            database.Subscriptions.Add(subscription);
        }

        var preserveRevocation = subscription.Status == SubscriptionStatus.Revoked
            && string.Equals(
                subscription.ProviderSubscriptionId,
                billingEvent.SubscriptionId,
                StringComparison.Ordinal);
        subscription.Provider = provider.Name;
        subscription.ProviderSubscriptionId = billingEvent.SubscriptionId;
        subscription.Plan = tier;
        subscription.Status = preserveRevocation
            ? SubscriptionStatus.Revoked
            : billingEvent.SubscriptionStatus.Value;
        subscription.CurrentPeriodEnd = billingEvent.CurrentPeriodEnd.Value;
        subscription.UpdatedAt = timeProvider.GetUtcNow();
    }

    private async Task ApplyMarketplacePublisherAsync(
        VerifiedBillingEvent billingEvent,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(billingEvent.EventType, "account.updated", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(billingEvent.ConnectAccountId)
            || billingEvent.DetailsSubmitted is null
            || billingEvent.ChargesEnabled is null
            || billingEvent.PayoutsEnabled is null)
        {
            throw new BillingWebhookException(
                "A Connect account update requires account identity and capability state.");
        }

        _ = await marketplacePublishers.ApplyProviderStatusAsync(
            billingEvent.ConnectAccountId,
            billingEvent.DetailsSubmitted.Value,
            billingEvent.ChargesEnabled.Value,
            billingEvent.PayoutsEnabled.Value,
            cancellationToken);
    }

    private async Task ApplyMarketplaceOrderAsync(
        VerifiedBillingEvent billingEvent,
        CancellationToken cancellationToken)
    {
        if (billingEvent.OrderId is null)
        {
            throw new BillingWebhookException(
                $"{billingEvent.EventType} requires a marketplace order identity.");
        }

        var order = await database.Orders.AsNoTracking().SingleOrDefaultAsync(
            candidate => candidate.Id == billingEvent.OrderId.Value,
            cancellationToken)
            ?? throw new BillingWebhookException("The marketplace order does not exist.");
        if (billingEvent.AccountId is not null
            && billingEvent.AccountId.Value != order.BuyerAccountId)
        {
            throw new BillingWebhookException(
                "The marketplace webhook buyer does not match its order.");
        }

        if (!string.IsNullOrWhiteSpace(order.ProviderSubscriptionId)
            && !string.IsNullOrWhiteSpace(billingEvent.SubscriptionId)
            && !string.Equals(
                order.ProviderSubscriptionId,
                billingEvent.SubscriptionId,
                StringComparison.Ordinal))
        {
            throw new BillingWebhookException(
                "The marketplace webhook subscription does not match its order.");
        }

        if (billingEvent.EventType is "charge.refunded" or "charge.dispute.created" or "order.refunded")
        {
            await marketplaceGrants.RevokeAsync(
                order.Id,
                OrderStatus.Refunded,
                billingEvent.EventType,
                cancellationToken);
            return;
        }

        if (billingEvent.SubscriptionStatus is SubscriptionStatus.Unpaid or SubscriptionStatus.Revoked)
        {
            await marketplaceGrants.RevokeAsync(
                order.Id,
                OrderStatus.Canceled,
                billingEvent.EventType,
                cancellationToken);
            return;
        }

        if (billingEvent.SubscriptionStatus == SubscriptionStatus.PastDue)
        {
            // Do not extend a recurring grant from a delinquent period update. Its previously
            // persisted validity remains authoritative until recovery or an explicit revocation.
            return;
        }

        if (billingEvent.SubscriptionStatus == SubscriptionStatus.Canceled
            && (billingEvent.CurrentPeriodEnd is null
                || billingEvent.CurrentPeriodEnd.Value <= timeProvider.GetUtcNow()))
        {
            await marketplaceGrants.RevokeAsync(
                order.Id,
                OrderStatus.Canceled,
                billingEvent.EventType,
                cancellationToken);
            return;
        }

        if (order.PriceMode == MarketplacePriceMode.Subscription
            && billingEvent.CurrentPeriodEnd is null)
        {
            // Checkout completion proves correlation; the signed subscription event supplies the
            // authoritative period end before a recurring marketplace grant is activated.
            return;
        }

        _ = await marketplaceGrants.ActivateAsync(
            order.Id,
            billingEvent.CurrentPeriodEnd,
            billingEvent.SubscriptionId,
            cancellationToken);
    }

    private async Task ApplySubscriptionRevocationAsync(
        VerifiedBillingEvent billingEvent,
        CancellationToken cancellationToken)
    {
        if (billingEvent.AccountId is null
            && string.IsNullOrWhiteSpace(billingEvent.SubscriptionId))
        {
            throw new BillingWebhookException(
                $"{billingEvent.EventType} requires accountId or subscriptionId.");
        }

        var subscriptions = database.Subscriptions.Where(x => x.Provider == provider.Name);
        if (billingEvent.AccountId is not null)
        {
            subscriptions = subscriptions.Where(x => x.AccountId == billingEvent.AccountId.Value);
        }

        if (!string.IsNullOrWhiteSpace(billingEvent.SubscriptionId))
        {
            subscriptions = subscriptions.Where(
                x => x.ProviderSubscriptionId == billingEvent.SubscriptionId);
        }

        var subscription = await subscriptions.SingleOrDefaultAsync(cancellationToken)
            ?? throw new BillingWebhookException("The subscription to revoke does not exist.");
        subscription.Status = SubscriptionStatus.Revoked;
        subscription.UpdatedAt = timeProvider.GetUtcNow();
    }

    private async Task ApplyOrderStateAsync(
        VerifiedBillingEvent billingEvent,
        OrderStatus status,
        CancellationToken cancellationToken)
    {
        if (billingEvent.OrderId is null)
        {
            throw new BillingWebhookException($"{billingEvent.EventType} requires orderId.");
        }

        var order = await database.Orders.SingleOrDefaultAsync(
            x => x.Id == billingEvent.OrderId.Value,
            cancellationToken)
            ?? throw new BillingWebhookException("The marketplace order does not exist.");
        order.Status = status;
        order.UpdatedAt = timeProvider.GetUtcNow();
    }
}

public interface IWebhookExecutionGate
{
    ValueTask<IAsyncDisposable> EnterAsync(string key, CancellationToken cancellationToken);
}

public sealed class InProcessWebhookExecutionGate : IWebhookExecutionGate
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> gates = new(StringComparer.Ordinal);

    public async ValueTask<IAsyncDisposable> EnterAsync(
        string key,
        CancellationToken cancellationToken)
    {
        var gate = gates.GetOrAdd(key, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        return new Releaser(gate);
    }

    private sealed class Releaser(SemaphoreSlim gate) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            gate.Release();
            return ValueTask.CompletedTask;
        }
    }
}
