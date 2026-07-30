using System.Net;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Providers;
using Stripe;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class MarketplaceCommerceProviderTests
{
    private const string StripeSecretKey = "sk_test_marketplace_connect";
    private static readonly DateTimeOffset LinkExpiry =
        new(2026, 7, 27, 13, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task DevelopmentCheckoutFailsClosedWhileMarketplaceSalesAreDisabled()
    {
        var options = new MarketplaceCommerceOptions();
        var provider = new DevelopmentMarketplaceCommerceProvider(options);

        Assert.False(options.SalesEnabled);
        await Assert.ThrowsAsync<MarketplaceSalesDisabledException>(() =>
            provider.CreateCheckoutAsync(CreateCheckoutRequest(), CancellationToken.None));
    }

    [Fact]
    public async Task DevelopmentCommerceResponsesAreDeterministic()
    {
        var options = CreateOptions();
        var provider = new DevelopmentMarketplaceCommerceProvider(options);
        var sellerId = Guid.NewGuid();
        var accountRequest = new MarketplaceExpressAccountRequest(
            sellerId,
            "seller@example.test",
            "Seller",
            "GB",
            "seller-account-1");

        var firstAccount = await provider.CreateExpressAccountAsync(
            accountRequest,
            CancellationToken.None);
        var secondAccount = await provider.CreateExpressAccountAsync(
            accountRequest,
            CancellationToken.None);
        Assert.Equal(firstAccount, secondAccount);
        Assert.Equal($"acct_dev_{sellerId:N}", firstAccount.ProviderAccountId);

        var checkoutRequest = CreateCheckoutRequest();
        var firstCheckout = await provider.CreateCheckoutAsync(
            checkoutRequest,
            CancellationToken.None);
        var secondCheckout = await provider.CreateCheckoutAsync(
            checkoutRequest,
            CancellationToken.None);
        Assert.Equal(firstCheckout, secondCheckout);
        Assert.Contains(checkoutRequest.OrderId.ToString("N"), firstCheckout.ProviderCheckoutId);
    }

    [Fact]
    public async Task StripeCreatesExpressAccountAndOnboardingLinkWithIdempotency()
    {
        var stripeHttpClient = new MarketplaceStripeHttpClient();
        var provider = CreateStripeProvider(stripeHttpClient);
        var sellerId = Guid.NewGuid();

        var account = await provider.CreateExpressAccountAsync(
            new MarketplaceExpressAccountRequest(
                sellerId,
                "seller@example.test",
                "Example Seller",
                "gb",
                "connect-account-1"),
            CancellationToken.None);
        var link = await provider.CreateOnboardingLinkAsync(
            new MarketplaceOnboardingLinkRequest(
                account.ProviderAccountId,
                "connect-link-1"),
            CancellationToken.None);

        Assert.Equal("acct_test_seller", account.ProviderAccountId);
        Assert.Equal("https://connect.stripe.test/onboarding", link.Url);
        Assert.Equal(LinkExpiry, link.ExpiresAt);
        Assert.Equal(2, stripeHttpClient.Requests.Count);

        var accountRequest = stripeHttpClient.Requests[0];
        Assert.Equal("/v1/accounts", accountRequest.Uri.AbsolutePath);
        Assert.Equal("connect-account-1", accountRequest.StripeHeaders["Idempotency-Key"]);
        var accountForm = ParseForm(await accountRequest.Content!.ReadAsStringAsync());
        Assert.Equal("express", accountForm["type"]);
        Assert.Equal("GB", accountForm["country"]);
        Assert.Equal("seller@example.test", accountForm["email"]);
        Assert.Equal("Example Seller", accountForm["business_profile[name]"]);
        Assert.Equal("true", accountForm["capabilities[card_payments][requested]"]);
        Assert.Equal("true", accountForm["capabilities[transfers][requested]"]);
        Assert.Equal("14", accountForm["settings[payouts][schedule][delay_days]"]);
        Assert.Equal("daily", accountForm["settings[payouts][schedule][interval]"]);
        Assert.Equal(sellerId.ToString("D"), accountForm["metadata[seller_account_id]"]);

        var linkRequest = stripeHttpClient.Requests[1];
        Assert.Equal("/v1/account_links", linkRequest.Uri.AbsolutePath);
        Assert.Equal("connect-link-1", linkRequest.StripeHeaders["Idempotency-Key"]);
        var linkForm = ParseForm(await linkRequest.Content!.ReadAsStringAsync());
        Assert.Equal("acct_test_seller", linkForm["account"]);
        Assert.Equal("account_onboarding", linkForm["type"]);
        Assert.Equal(CreateOptions().ConnectRefreshUrl, linkForm["refresh_url"]);
        Assert.Equal(CreateOptions().ConnectReturnUrl, linkForm["return_url"]);
    }

    [Fact]
    public async Task OneTimeCheckoutUsesDestinationChargeAndConfiguredFee()
    {
        var stripeHttpClient = new MarketplaceStripeHttpClient();
        var provider = CreateStripeProvider(stripeHttpClient);
        var request = CreateCheckoutRequest(
            MarketplacePricingMode.OneTime,
            amountInMinorUnits: 10_000);

        var checkout = await provider.CreateCheckoutAsync(request, CancellationToken.None);

        Assert.Equal("cs_test_marketplace", checkout.ProviderCheckoutId);
        var stripeRequest = Assert.Single(stripeHttpClient.Requests);
        Assert.Equal("/v1/checkout/sessions", stripeRequest.Uri.AbsolutePath);
        Assert.Equal(request.IdempotencyKey, stripeRequest.StripeHeaders["Idempotency-Key"]);
        var form = ParseForm(await stripeRequest.Content!.ReadAsStringAsync());
        Assert.Equal("payment", form["mode"]);
        Assert.Equal("true", form["automatic_tax[enabled]"]);
        Assert.Equal("usd", form["line_items[0][price_data][currency]"]);
        Assert.Equal("10000", form["line_items[0][price_data][unit_amount]"]);
        Assert.Equal(request.Title, form["line_items[0][price_data][product_data][name]"]);
        Assert.Equal("1750", form["payment_intent_data[application_fee_amount]"]);
        Assert.Equal(
            request.SellerConnectAccountId,
            form["payment_intent_data[transfer_data][destination]"]);
        Assert.Equal("marketplace", form["metadata[commerce_kind]"]);
        Assert.Equal(request.OrderId.ToString("D"), form["metadata[order_id]"]);
        Assert.Equal(request.ReleaseId.ToString("D"), form["metadata[release_id]"]);
        Assert.Equal("one_time", form["metadata[pricing_mode]"]);
        Assert.Equal("1250", form["metadata[application_fee_basis_points]"]);
        Assert.Equal("500", form["metadata[reserve_basis_points]"]);
        Assert.Equal("14", form["metadata[payout_delay_days]"]);
        Assert.Equal("true", form["metadata[automatic_tax_enabled]"]);
        Assert.Equal("stripe_automatic_tax", form["metadata[tax_handling]"]);
        Assert.Equal("seller", form["metadata[merchant_of_record]"]);
        Assert.DoesNotContain("subscription_data[application_fee_percent]", form.Keys);
    }

    [Fact]
    public async Task MonthlyCheckoutUsesDestinationSubscriptionAndConfiguredFeePercent()
    {
        var stripeHttpClient = new MarketplaceStripeHttpClient();
        var provider = CreateStripeProvider(stripeHttpClient);
        var request = CreateCheckoutRequest(
            MarketplacePricingMode.MonthlySubscription,
            amountInMinorUnits: 3_000);

        await provider.CreateCheckoutAsync(request, CancellationToken.None);

        var stripeRequest = Assert.Single(stripeHttpClient.Requests);
        var form = ParseForm(await stripeRequest.Content!.ReadAsStringAsync());
        Assert.Equal("subscription", form["mode"]);
        Assert.Equal("month", form["line_items[0][price_data][recurring][interval]"]);
        Assert.Equal("1", form["line_items[0][price_data][recurring][interval_count]"]);
        Assert.Equal("17.5", form["subscription_data[application_fee_percent]"]);
        Assert.Equal(
            request.SellerConnectAccountId,
            form["subscription_data[transfer_data][destination]"]);
        Assert.Equal("monthly_subscription", form["metadata[pricing_mode]"]);
        Assert.DoesNotContain("payment_intent_data[application_fee_amount]", form.Keys);
    }

    [Fact]
    public async Task StripePayoutReportUsesConnectedAccountAndMapsBalanceCursorAndPayouts()
    {
        var stripeHttpClient = new MarketplaceStripeHttpClient();
        var provider = CreateStripeProvider(stripeHttpClient);

        var report = await provider.GetPayoutReportAsync(
            "acct_test_seller",
            "po_previous",
            pageSize: 1,
            CancellationToken.None);

        Assert.Equal(2, stripeHttpClient.Requests.Count);
        Assert.Equal("/v1/balance", stripeHttpClient.Requests[0].Uri.AbsolutePath);
        Assert.Equal("acct_test_seller", stripeHttpClient.Requests[0].StripeHeaders["Stripe-Account"]);
        var payoutRequest = stripeHttpClient.Requests[1];
        Assert.Equal("/v1/payouts", payoutRequest.Uri.AbsolutePath);
        Assert.Equal("acct_test_seller", payoutRequest.StripeHeaders["Stripe-Account"]);
        var query = ParseForm(payoutRequest.Uri.Query.TrimStart('?'));
        Assert.Equal("1", query["limit"]);
        Assert.Equal("po_previous", query["starting_after"]);
        Assert.Equal(12_500, Assert.Single(report.Available).AmountInMinorUnits);
        Assert.Equal(2_500, Assert.Single(report.Pending).AmountInMinorUnits);
        var payout = Assert.Single(report.Payouts);
        Assert.Equal("po_test_marketplace", payout.ProviderPayoutId);
        Assert.Equal(7_000, payout.AmountInMinorUnits);
        Assert.Equal("USD", payout.Currency);
        Assert.Equal("paid", payout.Status);
        Assert.Equal("po_test_marketplace", report.NextCursor);
    }

    [Fact]
    public void CommercialConfigurationRejectsImpossibleFeeAndReserve()
    {
        var options = CreateOptions(
            applicationFeeBasisPoints: 8_000,
            reserveBasisPoints: 3_000);

        Assert.Throws<InvalidOperationException>(() =>
            new DevelopmentMarketplaceCommerceProvider(options));
    }

    private static StripeConnectMarketplaceCommerceProvider CreateStripeProvider(
        IHttpClient httpClient) =>
        new(
            CreateOptions(),
            new StripeClient(StripeSecretKey, httpClient: httpClient));

    private static MarketplaceCommerceOptions CreateOptions(
        int applicationFeeBasisPoints = 1_250,
        int reserveBasisPoints = 500) =>
        new()
        {
            Provider = StripeConnectMarketplaceCommerceProvider.ProviderName,
            SalesEnabled = true,
            ApplicationFeeBasisPoints = applicationFeeBasisPoints,
            ReserveBasisPoints = reserveBasisPoints,
            PayoutDelayDays = 14,
            AutomaticTaxEnabled = true,
            TaxHandling = "stripe_automatic_tax",
            MerchantOfRecord = "seller",
            Currency = "usd",
            ConnectRefreshUrl = "https://marketplace.example.test/connect/refresh",
            ConnectReturnUrl = "https://marketplace.example.test/connect/return",
            CheckoutSuccessUrl =
                "https://marketplace.example.test/orders/success?session_id={CHECKOUT_SESSION_ID}",
            CheckoutCancelUrl = "https://marketplace.example.test/orders/cancel",
        };

    private static MarketplaceCheckoutRequest CreateCheckoutRequest(
        MarketplacePricingMode pricingMode = MarketplacePricingMode.OneTime,
        long amountInMinorUnits = 2_500) =>
        new(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            "acct_test_seller",
            "Canonical Strategy",
            amountInMinorUnits,
            "usd",
            pricingMode,
            "marketplace-checkout-1");

    private static Dictionary<string, string> ParseForm(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                part => WebUtility.UrlDecode(part[0]),
                part => part.Length == 2 ? WebUtility.UrlDecode(part[1]) : string.Empty,
                StringComparer.Ordinal);

    private sealed class MarketplaceStripeHttpClient : IHttpClient
    {
        public List<StripeRequest> Requests { get; } = [];

        public Task<StripeResponse> MakeRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            var headers = new HttpResponseMessage().Headers;
            var body = request.Uri.AbsolutePath switch
            {
                "/v1/accounts" =>
                    """
                    {
                      "id": "acct_test_seller",
                      "object": "account",
                      "charges_enabled": false,
                      "details_submitted": false,
                      "payouts_enabled": false
                    }
                    """,
                "/v1/account_links" => $$"""
                    {
                      "object": "account_link",
                      "created": {{LinkExpiry.AddMinutes(-30).ToUnixTimeSeconds()}},
                      "expires_at": {{LinkExpiry.ToUnixTimeSeconds()}},
                      "url": "https://connect.stripe.test/onboarding"
                    }
                    """,
                "/v1/checkout/sessions" =>
                    """
                    {
                      "id": "cs_test_marketplace",
                      "object": "checkout.session",
                      "status": "open",
                      "url": "https://checkout.stripe.test/cs_test_marketplace"
                    }
                    """,
                "/v1/balance" =>
                    """
                    {
                      "object": "balance",
                      "available": [{ "amount": 12500, "currency": "usd" }],
                      "pending": [{ "amount": 2500, "currency": "usd" }]
                    }
                    """,
                "/v1/payouts" =>
                    """
                    {
                      "object": "list",
                      "data": [
                        {
                          "id": "po_test_marketplace",
                          "object": "payout",
                          "amount": 7000,
                          "arrival_date": 1785157200,
                          "automatic": true,
                          "created": 1785153600,
                          "currency": "usd",
                          "method": "standard",
                          "status": "paid"
                        }
                      ],
                      "has_more": true,
                      "url": "/v1/payouts"
                    }
                    """,
                _ => throw new InvalidOperationException(
                    $"Unexpected Stripe request path '{request.Uri.AbsolutePath}'."),
            };
            return Task.FromResult(new StripeResponse(HttpStatusCode.OK, headers, body));
        }

        public Task<StripeStreamedResponse> MakeStreamingRequestAsync(
            StripeRequest request,
            CancellationToken cancellationToken = default) =>
            Task.FromException<StripeStreamedResponse>(
                new InvalidOperationException("The test did not expect a streaming request."));
    }
}
