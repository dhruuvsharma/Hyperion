using System.Text;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using Stripe;
using Stripe.Checkout;

namespace DaxAlgo.Platform.Providers;

public sealed class StripeBillingProvider : IBillingProvider
{
    public const string ProviderName = "stripe";

    private const int WebhookToleranceSeconds = 300;
    private const string AccountMetadataKey = "account_id";
    private const string BuyerAccountMetadataKey = "buyer_account_id";
    private const string OrderMetadataKey = "order_id";
    private const string SubscriptionMetadataKey = "subscription_id";
    private const string CommerceKindMetadataKey = "commerce_kind";
    private const string MarketplaceCommerceKind = "marketplace";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly IStripeClient stripeClient;
    private readonly TimeProvider timeProvider;
    private readonly string stripeWebhookSecret;
    private readonly string professionalPriceId;

    public StripeBillingProvider(
        BillingOptions options,
        IStripeClient stripeClient,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.stripeClient = stripeClient ?? throw new ArgumentNullException(nameof(stripeClient));
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _ = RequireStripeConfiguration(
            options.StripeSecretKey,
            "Billing:StripeSecretKey",
            "sk_");
        stripeWebhookSecret = RequireStripeConfiguration(
            options.StripeWebhookSecret,
            "Billing:StripeWebhookSecret",
            "whsec_");
        professionalPriceId = RequireConfiguration(
            options.PriceIds.ProfessionalMonthly,
            "Billing:PriceIds:ProfessionalMonthly");
    }

    public string Name => ProviderName;

    public async Task<BillingCheckout> CreateCheckoutAsync(
        MarketplaceOrder order,
        CatalogItem item,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(order);
        ArgumentNullException.ThrowIfNull(item);

        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AccountMetadataKey] = order.BuyerAccountId.ToString("D"),
            [OrderMetadataKey] = order.Id.ToString("D"),
        };
        var session = await new SessionService(stripeClient).CreateAsync(
            new SessionCreateOptions
            {
                Mode = "subscription",
                UiMode = "hosted_page",
                ClientReferenceId = order.Id.ToString("D"),
                Metadata = metadata,
                LineItems =
                [
                    new SessionLineItemOptions
                    {
                        Price = professionalPriceId,
                        Quantity = 1,
                    },
                ],
                SubscriptionData = new SessionSubscriptionDataOptions
                {
                    Metadata = new Dictionary<string, string>(metadata, StringComparer.Ordinal),
                },
            },
            new RequestOptions
            {
                IdempotencyKey = $"pro-subscription:{order.Id:N}",
            },
            cancellationToken);

        return new BillingCheckout(session.Id, session.Url, OrderStatus.Pending);
    }

    public async Task<VerifiedBillingEvent> VerifyWebhookAsync(
        ReadOnlyMemory<byte> payload,
        IHeaderDictionary headers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!headers.TryGetValue("Stripe-Signature", out var signature)
            || string.IsNullOrWhiteSpace(signature))
        {
            throw new BillingWebhookException("The Stripe-Signature header is missing.");
        }

        Event stripeEvent;
        try
        {
            var json = StrictUtf8.GetString(payload.Span);
            stripeEvent = EventUtility.ConstructEvent(
                json,
                signature.ToString(),
                stripeWebhookSecret,
                WebhookToleranceSeconds,
                timeProvider.GetUtcNow().ToUnixTimeSeconds(),
                throwOnApiVersionMismatch: true);
        }
        catch (DecoderFallbackException)
        {
            throw new BillingWebhookException("The Stripe webhook payload is not valid UTF-8.");
        }
        catch (StripeException)
        {
            throw new BillingWebhookException("The Stripe webhook signature or payload is invalid.");
        }

        if (string.IsNullOrWhiteSpace(stripeEvent.Id)
            || string.IsNullOrWhiteSpace(stripeEvent.Type))
        {
            throw new BillingWebhookException("The Stripe webhook must include an event ID and type.");
        }

        return stripeEvent.Type switch
        {
            "customer.subscription.created" or "customer.subscription.updated" =>
                await MapSubscriptionEventAsync(stripeEvent, cancellationToken),
            "checkout.session.completed" or "checkout.session.async_payment_succeeded"
                or "checkout.session.async_payment_failed" => MapCheckoutSessionEvent(stripeEvent),
            "account.updated" => MapConnectedAccountEvent(stripeEvent),
            "charge.refunded" => await MapRefundEventAsync(stripeEvent, cancellationToken),
            "charge.dispute.created" => await MapDisputeEventAsync(stripeEvent, cancellationToken),
            _ => new VerifiedBillingEvent(
                stripeEvent.Id,
                stripeEvent.Type,
                null,
                null,
                null,
                null,
                null,
                null),
        };
    }

    internal async Task<StripeSubscriptionState> GetSubscriptionStateAsync(
        string subscriptionId,
        CancellationToken cancellationToken)
    {
        var subscription = await new SubscriptionService(stripeClient).GetAsync(
            subscriptionId,
            options: null,
            requestOptions: null,
            cancellationToken);
        return await MapSubscriptionAsync(subscription, cancellationToken);
    }

    private async Task<VerifiedBillingEvent> MapSubscriptionEventAsync(
        Event stripeEvent,
        CancellationToken cancellationToken)
    {
        if (stripeEvent.Data.Object is not Stripe.Subscription subscription)
        {
            throw new BillingWebhookException("The Stripe subscription event payload is invalid.");
        }

        var state = await MapSubscriptionAsync(subscription, cancellationToken);
        return new VerifiedBillingEvent(
            stripeEvent.Id,
            stripeEvent.Type,
            state.AccountId,
            state.SubscriptionId,
            state.PriceId,
            state.Status,
            state.CurrentPeriodEnd,
            state.OrderId)
        {
            Purpose = state.Purpose,
        };
    }

    private async Task<StripeSubscriptionState> MapSubscriptionAsync(
        Stripe.Subscription subscription,
        CancellationToken cancellationToken)
    {
        var item = subscription.Items?.Data?.FirstOrDefault(candidate => candidate.Price is not null)
            ?? throw new BillingWebhookException(
                "The Stripe subscription has no price-bearing subscription item.");
        if (string.IsNullOrWhiteSpace(item.Price.Id))
        {
            throw new BillingWebhookException(
                "The Stripe subscription item has no price ID.");
        }

        var priceId = item.Price.Id;
        var purpose = IsMarketplace(subscription.Metadata)
            ? BillingEventPurpose.MarketplaceOrder
            : BillingEventPurpose.Edition;
        var accountId = ReadGuid(
            subscription.Metadata,
            purpose == BillingEventPurpose.MarketplaceOrder
                ? BuyerAccountMetadataKey
                : AccountMetadataKey);
        if (accountId is null && subscription.Customer is not null)
        {
            accountId = ReadGuid(subscription.Customer.Metadata, AccountMetadataKey);
        }

        if (accountId is null && !string.IsNullOrWhiteSpace(subscription.CustomerId))
        {
            var customer = await new CustomerService(stripeClient).GetAsync(
                subscription.CustomerId,
                options: null,
                requestOptions: null,
                cancellationToken);
            accountId = ReadGuid(customer.Metadata, AccountMetadataKey);
        }

        return new StripeSubscriptionState(
            subscription.Id,
            accountId,
            priceId,
            MapStatus(subscription.Status),
            new DateTimeOffset(DateTime.SpecifyKind(item.CurrentPeriodEnd, DateTimeKind.Utc)),
            ReadGuid(subscription.Metadata, OrderMetadataKey),
            purpose);
    }

    private static VerifiedBillingEvent MapCheckoutSessionEvent(Event stripeEvent)
    {
        if (stripeEvent.Data.Object is not Session session)
        {
            throw new BillingWebhookException("The Stripe Checkout event payload is invalid.");
        }

        if (!IsMarketplace(session.Metadata))
        {
            return new VerifiedBillingEvent(
                stripeEvent.Id,
                stripeEvent.Type,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        var orderId = ReadGuid(session.Metadata, OrderMetadataKey)
            ?? throw new BillingWebhookException("The marketplace Checkout session has no order identity.");
        var accountId = ReadGuid(session.Metadata, BuyerAccountMetadataKey)
            ?? throw new BillingWebhookException("The marketplace Checkout session has no buyer identity.");
        var isSubscription = string.Equals(session.Mode, "subscription", StringComparison.Ordinal);
        var paymentSucceeded = string.Equals(session.PaymentStatus, "paid", StringComparison.Ordinal);
        return new VerifiedBillingEvent(
            stripeEvent.Id,
            stripeEvent.Type,
            accountId,
            session.SubscriptionId,
            null,
            isSubscription || paymentSucceeded
                ? SubscriptionStatus.Active
                : SubscriptionStatus.Unpaid,
            null,
            orderId)
        {
            Purpose = BillingEventPurpose.MarketplaceOrder,
        };
    }

    private static VerifiedBillingEvent MapConnectedAccountEvent(Event stripeEvent)
    {
        if (stripeEvent.Data.Object is not Account account
            || string.IsNullOrWhiteSpace(account.Id))
        {
            throw new BillingWebhookException("The Stripe Connect account event payload is invalid.");
        }

        if (!IsMarketplace(account.Metadata))
        {
            return new VerifiedBillingEvent(
                stripeEvent.Id,
                stripeEvent.Type,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        return new VerifiedBillingEvent(
            stripeEvent.Id,
            stripeEvent.Type,
            null,
            null,
            null,
            null,
            null,
            null)
        {
            Purpose = BillingEventPurpose.MarketplacePublisher,
            ConnectAccountId = account.Id,
            DetailsSubmitted = account.DetailsSubmitted,
            ChargesEnabled = account.ChargesEnabled,
            PayoutsEnabled = account.PayoutsEnabled,
        };
    }

    private async Task<VerifiedBillingEvent> MapRefundEventAsync(
        Event stripeEvent,
        CancellationToken cancellationToken)
    {
        if (stripeEvent.Data.Object is not Charge charge)
        {
            throw new BillingWebhookException("The Stripe refund event payload is invalid.");
        }

        var reference = await ResolveChargeReferenceAsync(charge, cancellationToken);
        return CreateRevocationEvent(stripeEvent, reference);
    }

    private async Task<VerifiedBillingEvent> MapDisputeEventAsync(
        Event stripeEvent,
        CancellationToken cancellationToken)
    {
        if (stripeEvent.Data.Object is not Dispute dispute
            || string.IsNullOrWhiteSpace(dispute.ChargeId))
        {
            throw new BillingWebhookException("The Stripe dispute event payload is invalid.");
        }

        var charge = dispute.Charge ?? await new ChargeService(stripeClient).GetAsync(
            dispute.ChargeId,
            options: null,
            requestOptions: null,
            cancellationToken);
        var reference = await ResolveChargeReferenceAsync(charge, cancellationToken);
        return CreateRevocationEvent(stripeEvent, reference);
    }

    private async Task<StripeSubscriptionReference> ResolveChargeReferenceAsync(
        Charge charge,
        CancellationToken cancellationToken)
    {
        var purpose = IsMarketplace(charge.Metadata)
            ? BillingEventPurpose.MarketplaceOrder
            : BillingEventPurpose.Edition;
        var accountId = ReadGuid(
            charge.Metadata,
            purpose == BillingEventPurpose.MarketplaceOrder
                ? BuyerAccountMetadataKey
                : AccountMetadataKey);
        var orderId = ReadGuid(charge.Metadata, OrderMetadataKey);
        var subscriptionId = ReadValue(charge.Metadata, SubscriptionMetadataKey);
        if (!string.IsNullOrWhiteSpace(subscriptionId))
        {
            var state = accountId is null
                ? await GetSubscriptionStateAsync(subscriptionId, cancellationToken)
                : null;
            return new StripeSubscriptionReference(
                subscriptionId,
                accountId ?? state?.AccountId,
                orderId ?? state?.OrderId,
                purpose == BillingEventPurpose.MarketplaceOrder
                    ? purpose
                    : state?.Purpose ?? purpose);
        }

        if (string.IsNullOrWhiteSpace(charge.PaymentIntentId))
        {
            if (accountId is not null)
            {
                return new StripeSubscriptionReference(null, accountId, orderId, purpose);
            }

            throw new BillingWebhookException(
                "The Stripe charge cannot be correlated to a subscription.");
        }

        var invoicePayments = await new InvoicePaymentService(stripeClient).ListAsync(
            new InvoicePaymentListOptions
            {
                Limit = 1,
                Payment = new InvoicePaymentPaymentOptions
                {
                    Type = "payment_intent",
                    PaymentIntent = charge.PaymentIntentId,
                },
            },
            requestOptions: null,
            cancellationToken);
        var invoiceId = invoicePayments.Data.FirstOrDefault()?.InvoiceId;
        if (string.IsNullOrWhiteSpace(invoiceId))
        {
            throw new BillingWebhookException(
                "The Stripe charge is not associated with a subscription invoice.");
        }

        var invoice = await new InvoiceService(stripeClient).GetAsync(
            invoiceId,
            options: null,
            requestOptions: null,
            cancellationToken);
        var subscriptionDetails = invoice.Parent?.SubscriptionDetails;
        if (IsMarketplace(subscriptionDetails?.Metadata))
        {
            purpose = BillingEventPurpose.MarketplaceOrder;
        }

        subscriptionId = subscriptionDetails?.SubscriptionId;
        accountId ??= ReadGuid(
            subscriptionDetails?.Metadata,
            purpose == BillingEventPurpose.MarketplaceOrder
                ? BuyerAccountMetadataKey
                : AccountMetadataKey);
        orderId ??= ReadGuid(subscriptionDetails?.Metadata, OrderMetadataKey);
        if (string.IsNullOrWhiteSpace(subscriptionId) && accountId is null)
        {
            throw new BillingWebhookException(
                "The Stripe invoice cannot be correlated to a subscription account.");
        }

        if (accountId is null && !string.IsNullOrWhiteSpace(subscriptionId))
        {
            var state = await GetSubscriptionStateAsync(subscriptionId, cancellationToken);
            accountId = state.AccountId;
            orderId ??= state.OrderId;
            purpose = state.Purpose;
        }

        return new StripeSubscriptionReference(subscriptionId, accountId, orderId, purpose);
    }

    private static VerifiedBillingEvent CreateRevocationEvent(
        Event stripeEvent,
        StripeSubscriptionReference reference) =>
        new(
            stripeEvent.Id,
            stripeEvent.Type,
            reference.AccountId,
            reference.SubscriptionId,
            null,
            SubscriptionStatus.Revoked,
            null,
            reference.OrderId)
        {
            Purpose = reference.Purpose,
        };

    private static SubscriptionStatus MapStatus(string status) => status switch
    {
        "trialing" => SubscriptionStatus.Trialing,
        "active" => SubscriptionStatus.Active,
        "past_due" => SubscriptionStatus.PastDue,
        "canceled" => SubscriptionStatus.Canceled,
        "unpaid" => SubscriptionStatus.Unpaid,
        _ => SubscriptionStatus.Unpaid,
    };

    private static Guid? ReadGuid(
        IReadOnlyDictionary<string, string>? metadata,
        string key) =>
        Guid.TryParse(ReadValue(metadata, key), out var value) ? value : null;

    private static string? ReadValue(
        IReadOnlyDictionary<string, string>? metadata,
        string key) =>
        metadata is not null
        && metadata.TryGetValue(key, out var value)
        && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

    private static bool IsMarketplace(IReadOnlyDictionary<string, string>? metadata) =>
        string.Equals(
            ReadValue(metadata, CommerceKindMetadataKey),
            MarketplaceCommerceKind,
            StringComparison.Ordinal);

    private static string RequireStripeConfiguration(
        string value,
        string path,
        string requiredPrefix)
    {
        var configured = RequireConfiguration(value, path);
        if (configured.StartsWith("replace-", StringComparison.OrdinalIgnoreCase)
            || !configured.StartsWith(requiredPrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{path} must be supplied through a production secret source.");
        }

        return configured;
    }

    private static string RequireConfiguration(string value, string path)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{path} must be configured.");
        }

        return value.Trim();
    }

    private sealed record StripeSubscriptionReference(
        string? SubscriptionId,
        Guid? AccountId,
        Guid? OrderId,
        BillingEventPurpose Purpose);
}

internal sealed record StripeSubscriptionState(
    string SubscriptionId,
    Guid? AccountId,
    string PriceId,
    SubscriptionStatus Status,
    DateTimeOffset CurrentPeriodEnd,
    Guid? OrderId,
    BillingEventPurpose Purpose);
