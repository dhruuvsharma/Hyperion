using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Billing;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Stripe;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class StripeBillingProviderTests
{
    private const string StripeApiVersion = "2026-06-24.dahlia";
    private const string SecretKey = "sk_test_platform_provider";
    private const string WebhookSecret = "whsec_platform_provider";
    private const string ProfessionalPriceId = "price_professional_monthly";
    private static readonly DateTimeOffset Now =
        new(2026, 7, 26, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task ValidSubscriptionSignatureMapsTrustedSubscriptionFields()
    {
        var accountId = Guid.NewGuid();
        var orderId = Guid.NewGuid();
        var periodEnd = Now.AddDays(30);
        var payload = CreateSubscriptionPayload(accountId, orderId, periodEnd);
        var headers = CreateSignedHeaders(payload, Now);
        var provider = CreateProvider(new RejectingStripeHttpClient());

        var billingEvent = await provider.VerifyWebhookAsync(
            Encoding.UTF8.GetBytes(payload),
            headers,
            CancellationToken.None);

        Assert.Equal("evt_subscription_updated", billingEvent.EventId);
        Assert.Equal("customer.subscription.updated", billingEvent.EventType);
        Assert.Equal(accountId, billingEvent.AccountId);
        Assert.Equal("sub_professional", billingEvent.SubscriptionId);
        Assert.Equal(ProfessionalPriceId, billingEvent.PriceId);
        Assert.Equal(SubscriptionStatus.Active, billingEvent.SubscriptionStatus);
        Assert.Equal(periodEnd, billingEvent.CurrentPeriodEnd);
        Assert.Equal(orderId, billingEvent.OrderId);
    }

    [Fact]
    public async Task MissingSignatureIsRejected()
    {
        var payload = CreateSubscriptionPayload(Guid.NewGuid(), Guid.NewGuid(), Now.AddDays(30));
        var provider = CreateProvider(new RejectingStripeHttpClient());

        var exception = await Assert.ThrowsAsync<BillingWebhookException>(() =>
            provider.VerifyWebhookAsync(
                Encoding.UTF8.GetBytes(payload),
                new HeaderDictionary(),
                CancellationToken.None));

        Assert.Contains("missing", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TamperedPayloadIsRejected()
    {
        var payload = CreateSubscriptionPayload(Guid.NewGuid(), Guid.NewGuid(), Now.AddDays(30));
        var headers = CreateSignedHeaders(payload, Now);
        var tampered = payload.Replace(
            "evt_subscription_updated",
            "evt_subscription_tampered",
            StringComparison.Ordinal);
        var provider = CreateProvider(new RejectingStripeHttpClient());

        await Assert.ThrowsAsync<BillingWebhookException>(() =>
            provider.VerifyWebhookAsync(
                Encoding.UTF8.GetBytes(tampered),
                headers,
                CancellationToken.None));
    }

    [Fact]
    public async Task ExpiredSignatureIsRejected()
    {
        var payload = CreateSubscriptionPayload(Guid.NewGuid(), Guid.NewGuid(), Now.AddDays(30));
        var signedAt = Now.AddSeconds(-301);
        var headers = CreateSignedHeaders(payload, signedAt);
        var provider = CreateProvider(new RejectingStripeHttpClient());

        await Assert.ThrowsAsync<BillingWebhookException>(() =>
            provider.VerifyWebhookAsync(
                Encoding.UTF8.GetBytes(payload),
                headers,
                CancellationToken.None));
    }

    [Fact]
    public async Task SignedPaidMarketplaceCheckoutMapsTrustedOrderAndBuyer()
    {
        var buyerAccountId = Guid.NewGuid();
        var orderId = Guid.NewGuid();
        var payload = CreateMarketplaceCheckoutPayload(buyerAccountId, orderId);
        var provider = CreateProvider(new RejectingStripeHttpClient());

        var billingEvent = await provider.VerifyWebhookAsync(
            Encoding.UTF8.GetBytes(payload),
            CreateSignedHeaders(payload, Now),
            CancellationToken.None);

        Assert.Equal("evt_marketplace_checkout", billingEvent.EventId);
        Assert.Equal("checkout.session.completed", billingEvent.EventType);
        Assert.Equal(BillingEventPurpose.MarketplaceOrder, billingEvent.Purpose);
        Assert.Equal(buyerAccountId, billingEvent.AccountId);
        Assert.Equal(orderId, billingEvent.OrderId);
        Assert.Equal(SubscriptionStatus.Active, billingEvent.SubscriptionStatus);
    }

    [Fact]
    public async Task SignedConnectAccountUpdateMapsPublisherCapabilityState()
    {
        var payload = CreateConnectAccountPayload();
        var provider = CreateProvider(new RejectingStripeHttpClient());

        var billingEvent = await provider.VerifyWebhookAsync(
            Encoding.UTF8.GetBytes(payload),
            CreateSignedHeaders(payload, Now),
            CancellationToken.None);

        Assert.Equal(BillingEventPurpose.MarketplacePublisher, billingEvent.Purpose);
        Assert.Equal("acct_marketplace_seller", billingEvent.ConnectAccountId);
        Assert.True(billingEvent.DetailsSubmitted);
        Assert.True(billingEvent.ChargesEnabled);
        Assert.False(billingEvent.PayoutsEnabled);
    }

    [Fact]
    public async Task SignedRefundMapsChargeMetadataToRevokedSubscription()
    {
        var accountId = Guid.NewGuid();
        const string subscriptionId = "sub_refunded";
        var payload = CreateRefundPayload(accountId, subscriptionId);
        var provider = CreateProvider(new RejectingStripeHttpClient());

        var billingEvent = await provider.VerifyWebhookAsync(
            Encoding.UTF8.GetBytes(payload),
            CreateSignedHeaders(payload, Now),
            CancellationToken.None);

        Assert.Equal("evt_charge_refunded", billingEvent.EventId);
        Assert.Equal("charge.refunded", billingEvent.EventType);
        Assert.Equal(accountId, billingEvent.AccountId);
        Assert.Equal(subscriptionId, billingEvent.SubscriptionId);
        Assert.Equal(SubscriptionStatus.Revoked, billingEvent.SubscriptionStatus);
        Assert.Null(billingEvent.PriceId);
        Assert.Null(billingEvent.CurrentPeriodEnd);
    }

    [Fact]
    public async Task SignedDisputeResolvesInvoiceSubscriptionAndMapsRevocation()
    {
        var accountId = Guid.NewGuid();
        var stripeHttpClient = new DisputeCorrelationStripeHttpClient(accountId);
        var provider = CreateProvider(stripeHttpClient);
        var payload = CreateDisputePayload();

        var billingEvent = await provider.VerifyWebhookAsync(
            Encoding.UTF8.GetBytes(payload),
            CreateSignedHeaders(payload, Now),
            CancellationToken.None);

        Assert.Equal("evt_charge_disputed", billingEvent.EventId);
        Assert.Equal("charge.dispute.created", billingEvent.EventType);
        Assert.Equal(accountId, billingEvent.AccountId);
        Assert.Equal("sub_disputed", billingEvent.SubscriptionId);
        Assert.Equal(SubscriptionStatus.Revoked, billingEvent.SubscriptionStatus);
        Assert.Equal(
            [
                "/v1/charges/ch_disputed",
                "/v1/invoice_payments",
                "/v1/invoices/in_disputed",
            ],
            stripeHttpClient.RequestPaths);
    }

    [Fact]
    public async Task CheckoutUsesRecurringProfessionalPriceAndCorrelationMetadata()
    {
        var stripeHttpClient = new CheckoutStripeHttpClient();
        var provider = CreateProvider(stripeHttpClient);
        var accountId = Guid.NewGuid();
        var order = new MarketplaceOrder
        {
            Id = Guid.NewGuid(),
            BuyerAccountId = accountId,
            CatalogItemId = Guid.NewGuid(),
            ReleaseId = Guid.NewGuid(),
            AmountInCents = 7_900,
            Status = OrderStatus.Pending,
            CreatedAt = Now,
            UpdatedAt = Now,
        };
        var item = new CatalogItem
        {
            Id = order.CatalogItemId,
            PublisherAccountId = Guid.NewGuid(),
            Slug = "professional-monthly",
            Title = "Professional",
            Description = "Professional monthly subscription.",
            Version = "1.0.0",
            PriceInCents = 7_900,
            Status = CatalogItemStatus.Published,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

        var checkout = await provider.CreateCheckoutAsync(
            order,
            item,
            CancellationToken.None);

        Assert.Equal("cs_test_professional", checkout.ProviderCheckoutId);
        Assert.Equal("https://checkout.stripe.test/cs_test_professional", checkout.CheckoutUrl);
        Assert.Equal(OrderStatus.Pending, checkout.InitialStatus);

        var request = Assert.IsType<StripeRequest>(stripeHttpClient.LastRequest);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/v1/checkout/sessions", request.Uri.AbsolutePath);
        Assert.Equal($"pro-subscription:{order.Id:N}", request.StripeHeaders["Idempotency-Key"]);
        using var content = request.Content;
        Assert.NotNull(content);
        var form = ParseForm(await content.ReadAsStringAsync(CancellationToken.None));
        Assert.Equal("subscription", form["mode"]);
        Assert.Equal("hosted_page", form["ui_mode"]);
        Assert.Equal(order.Id.ToString("D"), form["client_reference_id"]);
        Assert.Equal(ProfessionalPriceId, form["line_items[0][price]"]);
        Assert.Equal("1", form["line_items[0][quantity]"]);
        Assert.Equal(accountId.ToString("D"), form["metadata[account_id]"]);
        Assert.Equal(order.Id.ToString("D"), form["metadata[order_id]"]);
        Assert.Equal(accountId.ToString("D"), form["subscription_data[metadata][account_id]"]);
        Assert.Equal(order.Id.ToString("D"), form["subscription_data[metadata][order_id]"]);
        Assert.DoesNotContain("success_url", form.Keys);
        Assert.DoesNotContain("cancel_url", form.Keys);
    }

    [Fact]
    public async Task ReconciliationRefreshesLocalSubscriptionFromStripeState()
    {
        var accountId = Guid.NewGuid();
        var periodEnd = Now.AddDays(30);
        var stripeHttpClient = new SubscriptionStripeHttpClient(accountId, periodEnd);
        var provider = CreateProvider(stripeHttpClient);
        var databaseOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase($"stripe-reconciliation-{Guid.NewGuid():N}")
            .Options;
        await using var database = new PlatformDbContext(databaseOptions);
        database.Profiles.Add(new Profile
        {
            Id = accountId,
            Subject = "stripe-reconciliation",
            Email = "stripe-reconciliation@example.test",
            DisplayName = "Stripe Reconciliation",
            CreatedAt = Now.AddDays(-60),
            UpdatedAt = Now.AddDays(-60),
        });
        database.Subscriptions.Add(new AccountSubscription
        {
            AccountId = accountId,
            Provider = StripeBillingProvider.ProviderName,
            ProviderSubscriptionId = "sub_reconcile",
            Plan = DaxAlgo.Platform.Domain.PlanTier.Basic,
            Status = SubscriptionStatus.PastDue,
            CurrentPeriodEnd = Now.AddDays(-1),
            UpdatedAt = Now.AddDays(-1),
        });
        await database.SaveChangesAsync(CancellationToken.None);
        var reconciler = new StripeSubscriptionReconciler(
            database,
            provider,
            new PlanCatalog(CreateBillingOptions()),
            new FixedTimeProvider(Now),
            NullLogger<StripeSubscriptionReconciler>.Instance);

        await reconciler.ReconcileOnceAsync(CancellationToken.None);

        database.ChangeTracker.Clear();
        var subscription = await database.Subscriptions.SingleAsync(CancellationToken.None);
        Assert.Equal(DaxAlgo.Platform.Domain.PlanTier.Professional, subscription.Plan);
        Assert.Equal(SubscriptionStatus.Active, subscription.Status);
        Assert.Equal(periodEnd, subscription.CurrentPeriodEnd);
        Assert.Equal(Now, subscription.UpdatedAt);
        var request = Assert.IsType<StripeRequest>(stripeHttpClient.LastRequest);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("/v1/subscriptions/sub_reconcile", request.Uri.AbsolutePath);
    }

    private static StripeBillingProvider CreateProvider(IHttpClient httpClient)
    {
        var options = CreateBillingOptions();
        return new StripeBillingProvider(
            options,
            new StripeClient(SecretKey, httpClient: httpClient),
            new FixedTimeProvider(Now));
    }

    private static BillingOptions CreateBillingOptions() =>
        new()
        {
            Provider = StripeBillingProvider.ProviderName,
            StripeSecretKey = SecretKey,
            StripeWebhookSecret = WebhookSecret,
            PriceIds = new BillingPriceIds
            {
                ProfessionalMonthly = ProfessionalPriceId,
            },
        };

    private static string CreateSubscriptionPayload(
        Guid accountId,
        Guid orderId,
        DateTimeOffset periodEnd) =>
        JsonSerializer.Serialize(new
        {
            id = "evt_subscription_updated",
            @object = "event",
            api_version = StripeApiVersion,
            created = Now.ToUnixTimeSeconds(),
            data = new
            {
                @object = new
                {
                    id = "sub_professional",
                    @object = "subscription",
                    customer = "cus_professional",
                    metadata = new Dictionary<string, string>
                    {
                        ["account_id"] = accountId.ToString("D"),
                        ["order_id"] = orderId.ToString("D"),
                    },
                    status = "active",
                    items = new
                    {
                        @object = "list",
                        data = new[]
                        {
                            new
                            {
                                id = "si_professional",
                                @object = "subscription_item",
                                current_period_start = Now.ToUnixTimeSeconds(),
                                current_period_end = periodEnd.ToUnixTimeSeconds(),
                                price = new
                                {
                                    id = ProfessionalPriceId,
                                    @object = "price",
                                },
                            },
                        },
                        has_more = false,
                    },
                },
            },
            livemode = false,
            pending_webhooks = 1,
            type = "customer.subscription.updated",
        });

    private static string CreateRefundPayload(Guid accountId, string subscriptionId) =>
        JsonSerializer.Serialize(new
        {
            id = "evt_charge_refunded",
            @object = "event",
            api_version = StripeApiVersion,
            created = Now.ToUnixTimeSeconds(),
            data = new
            {
                @object = new
                {
                    id = "ch_refunded",
                    @object = "charge",
                    metadata = new Dictionary<string, string>
                    {
                        ["account_id"] = accountId.ToString("D"),
                        ["subscription_id"] = subscriptionId,
                    },
                    refunded = true,
                },
            },
            livemode = false,
            pending_webhooks = 1,
            type = "charge.refunded",
        });

    private static string CreateMarketplaceCheckoutPayload(Guid buyerAccountId, Guid orderId) =>
        JsonSerializer.Serialize(new
        {
            id = "evt_marketplace_checkout",
            @object = "event",
            api_version = StripeApiVersion,
            created = Now.ToUnixTimeSeconds(),
            data = new
            {
                @object = new
                {
                    id = "cs_marketplace_paid",
                    @object = "checkout.session",
                    mode = "payment",
                    payment_status = "paid",
                    status = "complete",
                    metadata = new Dictionary<string, string>
                    {
                        ["commerce_kind"] = "marketplace",
                        ["buyer_account_id"] = buyerAccountId.ToString("D"),
                        ["order_id"] = orderId.ToString("D"),
                    },
                },
            },
            livemode = false,
            pending_webhooks = 1,
            type = "checkout.session.completed",
        });

    private static string CreateConnectAccountPayload() =>
        JsonSerializer.Serialize(new
        {
            id = "evt_connect_account_updated",
            @object = "event",
            api_version = StripeApiVersion,
            created = Now.ToUnixTimeSeconds(),
            data = new
            {
                @object = new
                {
                    id = "acct_marketplace_seller",
                    @object = "account",
                    details_submitted = true,
                    charges_enabled = true,
                    payouts_enabled = false,
                    metadata = new Dictionary<string, string>
                    {
                        ["commerce_kind"] = "marketplace",
                    },
                },
            },
            livemode = false,
            pending_webhooks = 1,
            type = "account.updated",
        });

    private static string CreateDisputePayload() =>
        JsonSerializer.Serialize(new
        {
            id = "evt_charge_disputed",
            @object = "event",
            api_version = StripeApiVersion,
            created = Now.ToUnixTimeSeconds(),
            data = new
            {
                @object = new
                {
                    id = "dp_disputed",
                    @object = "dispute",
                    charge = "ch_disputed",
                    status = "needs_response",
                },
            },
            livemode = false,
            pending_webhooks = 1,
            type = "charge.dispute.created",
        });

    private static HeaderDictionary CreateSignedHeaders(string payload, DateTimeOffset signedAt)
    {
        var timestamp = signedAt.ToUnixTimeSeconds().ToString(
            System.Globalization.CultureInfo.InvariantCulture);
        var signature = EventUtility.ComputeSignature(WebhookSecret, timestamp, payload);
        return new HeaderDictionary
        {
            ["Stripe-Signature"] = $"t={timestamp},v1={signature}",
        };
    }

    private static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                part => WebUtility.UrlDecode(part[0]),
                part => part.Length == 2 ? WebUtility.UrlDecode(part[1]) : string.Empty,
                StringComparer.Ordinal);

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class RejectingStripeHttpClient : IHttpClient
    {
        public Task<StripeResponse> MakeRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default) =>
            Task.FromException<StripeResponse>(
                new InvalidOperationException("The test did not expect a Stripe API request."));

        public Task<StripeStreamedResponse> MakeStreamingRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default) =>
            Task.FromException<StripeStreamedResponse>(
                new InvalidOperationException("The test did not expect a Stripe streaming request."));
    }

    private sealed class CheckoutStripeHttpClient : IHttpClient
    {
        public StripeRequest? LastRequest { get; private set; }

        public Task<StripeResponse> MakeRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastRequest = request;
            var response = new HttpResponseMessage().Headers;
            return Task.FromResult(new StripeResponse(
                HttpStatusCode.OK,
                response,
                """
                {
                  "id": "cs_test_professional",
                  "object": "checkout.session",
                  "mode": "subscription",
                  "status": "open",
                  "url": "https://checkout.stripe.test/cs_test_professional"
                }
                """));
        }

        public Task<StripeStreamedResponse> MakeStreamingRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default) =>
            Task.FromException<StripeStreamedResponse>(
                new InvalidOperationException("The test did not expect a Stripe streaming request."));
    }

    private sealed class SubscriptionStripeHttpClient(
        Guid accountId,
        DateTimeOffset periodEnd) : IHttpClient
    {
        public StripeRequest? LastRequest { get; private set; }

        public Task<StripeResponse> MakeRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastRequest = request;
            var response = new HttpResponseMessage().Headers;
            return Task.FromResult(new StripeResponse(
                HttpStatusCode.OK,
                response,
                JsonSerializer.Serialize(new
                {
                    id = "sub_reconcile",
                    @object = "subscription",
                    customer = "cus_reconcile",
                    metadata = new Dictionary<string, string>
                    {
                        ["account_id"] = accountId.ToString("D"),
                    },
                    status = "active",
                    items = new
                    {
                        @object = "list",
                        data = new[]
                        {
                            new
                            {
                                id = "si_reconcile",
                                @object = "subscription_item",
                                current_period_start = Now.ToUnixTimeSeconds(),
                                current_period_end = periodEnd.ToUnixTimeSeconds(),
                                price = new
                                {
                                    id = ProfessionalPriceId,
                                    @object = "price",
                                },
                            },
                        },
                        has_more = false,
                    },
                })));
        }

        public Task<StripeStreamedResponse> MakeStreamingRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default) =>
            Task.FromException<StripeStreamedResponse>(
                new InvalidOperationException("The test did not expect a Stripe streaming request."));
    }

    private sealed class DisputeCorrelationStripeHttpClient(Guid accountId) : IHttpClient
    {
        public List<string> RequestPaths { get; } = [];

        public Task<StripeResponse> MakeRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestPaths.Add(request.Uri.AbsolutePath);
            var json = request.Uri.AbsolutePath switch
            {
                "/v1/charges/ch_disputed" =>
                    """
                    {
                      "id": "ch_disputed",
                      "object": "charge",
                      "metadata": {},
                      "payment_intent": "pi_disputed"
                    }
                    """,
                "/v1/invoice_payments" =>
                    """
                    {
                      "object": "list",
                      "data": [
                        {
                          "id": "inpay_disputed",
                          "object": "invoice_payment",
                          "invoice": "in_disputed",
                          "payment": {
                            "type": "payment_intent",
                            "payment_intent": "pi_disputed"
                          },
                          "status": "paid"
                        }
                      ],
                      "has_more": false,
                      "url": "/v1/invoice_payments"
                    }
                    """,
                "/v1/invoices/in_disputed" => JsonSerializer.Serialize(new
                {
                    id = "in_disputed",
                    @object = "invoice",
                    parent = new
                    {
                        type = "subscription_details",
                        subscription_details = new
                        {
                            subscription = "sub_disputed",
                            metadata = new Dictionary<string, string>
                            {
                                ["account_id"] = accountId.ToString("D"),
                            },
                        },
                    },
                    status = "paid",
                }),
                _ => throw new InvalidOperationException(
                    $"Unexpected Stripe request path: {request.Uri.AbsolutePath}"),
            };
            var response = new HttpResponseMessage().Headers;
            return Task.FromResult(new StripeResponse(HttpStatusCode.OK, response, json));
        }

        public Task<StripeStreamedResponse> MakeStreamingRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default) =>
            Task.FromException<StripeStreamedResponse>(
                new InvalidOperationException("The test did not expect a Stripe streaming request."));
    }
}
