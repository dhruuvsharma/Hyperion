using System.Net.Mail;
using DaxAlgo.Platform.Configuration;
using Stripe;
using Stripe.Checkout;

namespace DaxAlgo.Platform.Providers;

public sealed class StripeConnectMarketplaceCommerceProvider : IMarketplaceCommerceProvider
{
    public const string ProviderName = "stripe-connect";

    private readonly MarketplaceCommerceOptions options;
    private readonly IStripeClient stripeClient;

    public StripeConnectMarketplaceCommerceProvider(
        MarketplaceCommerceOptions options,
        IStripeClient stripeClient)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.stripeClient = stripeClient ?? throw new ArgumentNullException(nameof(stripeClient));
        MarketplaceCommerceValidation.ValidateOptions(options);
    }

    public string Name => ProviderName;

    public async Task<MarketplaceExpressAccount> CreateExpressAccountAsync(
        MarketplaceExpressAccountRequest request,
        CancellationToken cancellationToken)
    {
        MarketplaceCommerceValidation.ValidateExpressAccountRequest(request);
        var account = await new AccountService(stripeClient).CreateAsync(
            new AccountCreateOptions
            {
                Type = "express",
                Country = request.Country.Trim().ToUpperInvariant(),
                Email = request.Email.Trim(),
                BusinessProfile = new AccountBusinessProfileOptions
                {
                    Name = request.DisplayName.Trim(),
                },
                Capabilities = new AccountCapabilitiesOptions
                {
                    CardPayments = new AccountCapabilitiesCardPaymentsOptions { Requested = true },
                    Transfers = new AccountCapabilitiesTransfersOptions { Requested = true },
                },
                Settings = new AccountSettingsOptions
                {
                    Payouts = new AccountSettingsPayoutsOptions
                    {
                        Schedule = new AccountSettingsPayoutsScheduleOptions
                        {
                            DelayDays = options.PayoutDelayDays,
                            Interval = "daily",
                        },
                    },
                },
                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["seller_account_id"] = request.SellerAccountId.ToString("D"),
                    ["commerce_kind"] = "marketplace",
                },
            },
            new RequestOptions { IdempotencyKey = request.IdempotencyKey },
            cancellationToken);

        return new MarketplaceExpressAccount(
            account.Id,
            account.ChargesEnabled,
            account.PayoutsEnabled,
            account.DetailsSubmitted);
    }

    public async Task<MarketplaceOnboardingLink> CreateOnboardingLinkAsync(
        MarketplaceOnboardingLinkRequest request,
        CancellationToken cancellationToken)
    {
        MarketplaceCommerceValidation.ValidateOnboardingRequest(request);
        var link = await new AccountLinkService(stripeClient).CreateAsync(
            new AccountLinkCreateOptions
            {
                Account = request.SellerConnectAccountId.Trim(),
                RefreshUrl = options.ConnectRefreshUrl.Trim(),
                ReturnUrl = options.ConnectReturnUrl.Trim(),
                Type = "account_onboarding",
            },
            new RequestOptions { IdempotencyKey = request.IdempotencyKey },
            cancellationToken);

        return new MarketplaceOnboardingLink(
            request.SellerConnectAccountId.Trim(),
            link.Url,
            new DateTimeOffset(DateTime.SpecifyKind(link.ExpiresAt, DateTimeKind.Utc)));
    }

    public async Task<MarketplaceCheckout> CreateCheckoutAsync(
        MarketplaceCheckoutRequest request,
        CancellationToken cancellationToken)
    {
        MarketplaceCommerceValidation.ValidateCheckoutRequest(options, request);
        var metadata = CreateCheckoutMetadata(request);
        var sessionOptions = new SessionCreateOptions
        {
            Mode = request.PricingMode == MarketplacePricingMode.OneTime
                ? "payment"
                : "subscription",
            UiMode = "hosted_page",
            ClientReferenceId = request.OrderId.ToString("D"),
            SuccessUrl = options.CheckoutSuccessUrl.Trim(),
            CancelUrl = options.CheckoutCancelUrl.Trim(),
            AutomaticTax = new SessionAutomaticTaxOptions
            {
                Enabled = options.AutomaticTaxEnabled,
            },
            Metadata = metadata,
            LineItems =
            [
                new SessionLineItemOptions
                {
                    Quantity = 1,
                    PriceData = CreatePriceData(request),
                },
            ],
        };

        if (request.PricingMode == MarketplacePricingMode.OneTime)
        {
            sessionOptions.PaymentIntentData = new SessionPaymentIntentDataOptions
            {
                ApplicationFeeAmount = CalculateApplicationFee(
                    request.AmountInMinorUnits,
                    checked(options.ApplicationFeeBasisPoints + options.ReserveBasisPoints)),
                TransferData = new SessionPaymentIntentDataTransferDataOptions
                {
                    Destination = request.SellerConnectAccountId.Trim(),
                },
                Metadata = new Dictionary<string, string>(metadata, StringComparer.Ordinal),
            };
        }
        else
        {
            sessionOptions.SubscriptionData = new SessionSubscriptionDataOptions
            {
                ApplicationFeePercent = checked(
                    options.ApplicationFeeBasisPoints + options.ReserveBasisPoints) / 100m,
                TransferData = new SessionSubscriptionDataTransferDataOptions
                {
                    Destination = request.SellerConnectAccountId.Trim(),
                },
                Metadata = new Dictionary<string, string>(metadata, StringComparer.Ordinal),
            };
        }

        var session = await new SessionService(stripeClient).CreateAsync(
            sessionOptions,
            new RequestOptions { IdempotencyKey = request.IdempotencyKey },
            cancellationToken);
        if (string.IsNullOrWhiteSpace(session.Url))
        {
            throw new InvalidOperationException("Stripe did not return a hosted Checkout URL.");
        }

        return new MarketplaceCheckout(session.Id, session.Url);
    }

    public async Task<MarketplacePayoutReport> GetPayoutReportAsync(
        string sellerConnectAccountId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken)
    {
        MarketplaceCommerceValidation.ValidatePayoutReportRequest(
            sellerConnectAccountId,
            cursor,
            pageSize);
        var requestOptions = new RequestOptions
        {
            StripeAccount = sellerConnectAccountId.Trim(),
        };
        var balance = await new BalanceService(stripeClient).GetAsync(
            requestOptions,
            cancellationToken);
        var payouts = await new PayoutService(stripeClient).ListAsync(
            new PayoutListOptions
            {
                Limit = pageSize,
                StartingAfter = string.IsNullOrWhiteSpace(cursor) ? null : cursor.Trim(),
            },
            requestOptions,
            cancellationToken);

        return new MarketplacePayoutReport(
            balance.Available.Select(item => new MarketplaceBalanceAmount(
                item.Amount,
                item.Currency.ToUpperInvariant())).ToArray(),
            balance.Pending.Select(item => new MarketplaceBalanceAmount(
                item.Amount,
                item.Currency.ToUpperInvariant())).ToArray(),
            payouts.Data.Select(item => new MarketplacePayout(
                item.Id,
                item.Amount,
                item.Currency.ToUpperInvariant(),
                item.Status,
                new DateTimeOffset(DateTime.SpecifyKind(item.Created, DateTimeKind.Utc)),
                new DateTimeOffset(DateTime.SpecifyKind(item.ArrivalDate, DateTimeKind.Utc)),
                item.Method,
                item.Automatic,
                item.FailureCode)).ToArray(),
            payouts.HasMore && payouts.Data.Count != 0
                ? payouts.Data[^1].Id
                : null);
    }

    private static SessionLineItemPriceDataOptions CreatePriceData(
        MarketplaceCheckoutRequest request) =>
        new()
        {
            Currency = request.Currency.Trim().ToLowerInvariant(),
            UnitAmount = request.AmountInMinorUnits,
            ProductData = new SessionLineItemPriceDataProductDataOptions
            {
                Name = request.Title.Trim(),
            },
            Recurring = request.PricingMode == MarketplacePricingMode.MonthlySubscription
                ? new SessionLineItemPriceDataRecurringOptions
                {
                    Interval = "month",
                    IntervalCount = 1,
                }
                : null,
        };

    private Dictionary<string, string> CreateCheckoutMetadata(
        MarketplaceCheckoutRequest request) =>
        new(StringComparer.Ordinal)
        {
            ["commerce_kind"] = "marketplace",
            ["order_id"] = request.OrderId.ToString("D"),
            ["listing_id"] = request.ListingId.ToString("D"),
            ["release_id"] = request.ReleaseId.ToString("D"),
            ["buyer_account_id"] = request.BuyerAccountId.ToString("D"),
            ["seller_connect_account_id"] = request.SellerConnectAccountId.Trim(),
            ["pricing_mode"] = request.PricingMode == MarketplacePricingMode.OneTime
                ? "one_time"
                : "monthly_subscription",
            ["commercial_policy_version"] = options.PolicyVersion.Trim(),
            ["application_fee_basis_points"] = options.ApplicationFeeBasisPoints.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            ["reserve_basis_points"] = options.ReserveBasisPoints.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            ["payout_delay_days"] = options.PayoutDelayDays.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            ["automatic_tax_enabled"] = options.AutomaticTaxEnabled ? "true" : "false",
            ["tax_handling"] = options.TaxHandling.Trim(),
            ["merchant_of_record"] = options.MerchantOfRecord.Trim(),
        };

    private static long CalculateApplicationFee(long amount, int basisPoints) =>
        checked((long)decimal.Round(
            amount * basisPoints / 10_000m,
            decimals: 0,
            MidpointRounding.AwayFromZero));
}

public sealed class DevelopmentMarketplaceCommerceProvider : IMarketplaceCommerceProvider
{
    public const string ProviderName = "development";

    private readonly MarketplaceCommerceOptions options;

    public DevelopmentMarketplaceCommerceProvider(MarketplaceCommerceOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        MarketplaceCommerceValidation.ValidateOptions(options);
    }

    public string Name => ProviderName;

    public Task<MarketplaceExpressAccount> CreateExpressAccountAsync(
        MarketplaceExpressAccountRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MarketplaceCommerceValidation.ValidateExpressAccountRequest(request);
        return Task.FromResult(new MarketplaceExpressAccount(
            $"acct_dev_{request.SellerAccountId:N}",
            ChargesEnabled: false,
            PayoutsEnabled: false,
            DetailsSubmitted: false));
    }

    public Task<MarketplaceOnboardingLink> CreateOnboardingLinkAsync(
        MarketplaceOnboardingLinkRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MarketplaceCommerceValidation.ValidateOnboardingRequest(request);
        var separator = options.ConnectReturnUrl.Contains('?') ? "&" : "?";
        var url = options.ConnectReturnUrl.Trim()
            + separator
            + "development_connect_account="
            + Uri.EscapeDataString(request.SellerConnectAccountId.Trim());
        return Task.FromResult(new MarketplaceOnboardingLink(
            request.SellerConnectAccountId.Trim(),
            url,
            new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero)));
    }

    public Task<MarketplaceCheckout> CreateCheckoutAsync(
        MarketplaceCheckoutRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MarketplaceCommerceValidation.ValidateCheckoutRequest(options, request);
        var checkoutId = $"dev_marketplace_checkout_{request.OrderId:N}";
        var separator = options.CheckoutSuccessUrl.Contains('?') ? "&" : "?";
        var url = options.CheckoutSuccessUrl.Trim()
            .Replace("{CHECKOUT_SESSION_ID}", checkoutId, StringComparison.Ordinal)
            + separator
            + "development_checkout="
            + Uri.EscapeDataString(checkoutId);
        return Task.FromResult(new MarketplaceCheckout(checkoutId, url));
    }

    public Task<MarketplacePayoutReport> GetPayoutReportAsync(
        string sellerConnectAccountId,
        string? cursor,
        int pageSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MarketplaceCommerceValidation.ValidatePayoutReportRequest(
            sellerConnectAccountId,
            cursor,
            pageSize);
        return Task.FromResult(new MarketplacePayoutReport([], [], [], null));
    }
}

internal static class MarketplaceCommerceValidation
{
    public static void ValidateOptions(MarketplaceCommerceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.ApplicationFeeBasisPoints is < 0 or > 10_000)
        {
            throw new InvalidOperationException(
                "MarketplaceCommerce:ApplicationFeeBasisPoints must be between 0 and 10000.");
        }

        if (options.ReserveBasisPoints is < 0 or > 10_000
            || options.ApplicationFeeBasisPoints + options.ReserveBasisPoints > 10_000)
        {
            throw new InvalidOperationException(
                "MarketplaceCommerce fee plus reserve basis points must be between 0 and 10000.");
        }

        if (options.PayoutDelayDays is < 0 or > 90)
        {
            throw new InvalidOperationException(
                "MarketplaceCommerce:PayoutDelayDays must be between 0 and 90.");
        }

        var currency = options.Currency?.Trim();
        if (currency is null
            || currency.Length != 3
            || currency.Any(character => !char.IsAsciiLetter(character)))
        {
            throw new InvalidOperationException(
                "MarketplaceCommerce:Currency must be a three-letter ISO currency code.");
        }

        RequireConfiguration(options.Provider, "MarketplaceCommerce:Provider", 40);
        RequireConfiguration(options.PolicyVersion, "MarketplaceCommerce:PolicyVersion", 100);
        RequireConfiguration(options.TaxHandling, "MarketplaceCommerce:TaxHandling", 100);
        RequireConfiguration(options.MerchantOfRecord, "MarketplaceCommerce:MerchantOfRecord", 100);
        RequireHttpsUrl(options.ConnectRefreshUrl, "MarketplaceCommerce:ConnectRefreshUrl");
        RequireHttpsUrl(options.ConnectReturnUrl, "MarketplaceCommerce:ConnectReturnUrl");
        RequireHttpsUrl(options.CheckoutSuccessUrl, "MarketplaceCommerce:CheckoutSuccessUrl");
        RequireHttpsUrl(options.CheckoutCancelUrl, "MarketplaceCommerce:CheckoutCancelUrl");
    }

    public static void ValidateExpressAccountRequest(MarketplaceExpressAccountRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SellerAccountId == Guid.Empty)
        {
            throw new ArgumentException("Seller account ID cannot be empty.", nameof(request));
        }

        if (!MailAddress.TryCreate(request.Email?.Trim(), out _))
        {
            throw new ArgumentException("Seller email must be valid.", nameof(request));
        }

        RequireRequestValue(request.DisplayName, "Seller display name", 120);
        var country = request.Country?.Trim();
        if (country is null
            || country.Length != 2
            || country.Any(character => !char.IsAsciiLetter(character)))
        {
            throw new ArgumentException("Seller country must be a two-letter ISO code.", nameof(request));
        }

        ValidateIdempotencyKey(request.IdempotencyKey);
    }

    public static void ValidateOnboardingRequest(MarketplaceOnboardingLinkRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateConnectAccountId(request.SellerConnectAccountId);
        ValidateIdempotencyKey(request.IdempotencyKey);
    }

    public static void ValidateCheckoutRequest(
        MarketplaceCommerceOptions options,
        MarketplaceCheckoutRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!options.SalesEnabled)
        {
            throw new MarketplaceSalesDisabledException();
        }

        if (request.OrderId == Guid.Empty
            || request.ListingId == Guid.Empty
            || request.ReleaseId == Guid.Empty
            || request.BuyerAccountId == Guid.Empty)
        {
            throw new ArgumentException(
                "Order, listing, release, and buyer account IDs must be non-empty.",
                nameof(request));
        }

        ValidateConnectAccountId(request.SellerConnectAccountId);
        RequireRequestValue(request.Title, "Listing title", 160);
        if (request.AmountInMinorUnits is < 1 or > 100_000_000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "Marketplace amount must be between 1 and 100,000,000 minor currency units.");
        }

        var currency = request.Currency?.Trim().ToLowerInvariant();
        if (!string.Equals(currency, options.Currency.Trim().ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Marketplace checkout currency must match the configured marketplace currency.",
                nameof(request));
        }

        if (!Enum.IsDefined(request.PricingMode))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Unknown marketplace pricing mode.");
        }

        ValidateIdempotencyKey(request.IdempotencyKey);
    }

    public static void ValidatePayoutReportRequest(
        string sellerConnectAccountId,
        string? cursor,
        int pageSize)
    {
        ValidateConnectAccountId(sellerConnectAccountId);
        if (pageSize is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(pageSize),
                "Payout page size must be between 1 and 100.");
        }

        if (!string.IsNullOrEmpty(cursor)
            && (cursor.Length > 255
                || !cursor.StartsWith("po_", StringComparison.Ordinal)
                || cursor.Any(character =>
                    !(char.IsAsciiLetterOrDigit(character) || character == '_'))))
        {
            throw new ArgumentException("The payout cursor is invalid.", nameof(cursor));
        }
    }

    private static void ValidateConnectAccountId(string value)
    {
        var normalized = value?.Trim();
        if (normalized is null
            || normalized.Length is < 6 or > 255
            || !normalized.StartsWith("acct_", StringComparison.Ordinal)
            || normalized.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character == '_')))
        {
            throw new ArgumentException("Seller Connect account ID is invalid.", nameof(value));
        }
    }

    private static void ValidateIdempotencyKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 255
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || value.Any(character => character is < '!' or > '~'))
        {
            throw new ArgumentException(
                "Idempotency key must contain 1 to 255 printable ASCII characters without spaces.",
                nameof(value));
        }
    }

    private static void RequireConfiguration(string value, string path, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > maximumLength)
        {
            throw new InvalidOperationException($"{path} must contain 1 to {maximumLength} characters.");
        }
    }

    private static void RequireHttpsUrl(string value, string path)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidOperationException($"{path} must be an absolute HTTPS URL without a fragment.");
        }
    }

    private static void RequireRequestValue(string value, string label, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Trim().Length > maximumLength)
        {
            throw new ArgumentException($"{label} must contain 1 to {maximumLength} characters.");
        }
    }
}
