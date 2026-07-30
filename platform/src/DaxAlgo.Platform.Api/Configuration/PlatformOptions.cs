namespace DaxAlgo.Platform.Configuration;

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    public string Provider { get; init; } = "InMemory";

    public string DatabaseName { get; init; } = "daxalgo-platform-development";

    public string? ConnectionString { get; init; }
}

public sealed class IdentityOptions
{
    public const string SectionName = "Identity";

    public string Provider { get; init; } = "Development";
}

public sealed class GoogleAuthOptions
{
    public const string SectionName = "GoogleAuth";

    public string ClientId { get; init; } = string.Empty;

    public string[] AllowedAudiences { get; init; } = [];
}

public sealed class BillingOptions
{
    public const string SectionName = "Billing";

    public string Provider { get; init; } = "Development";

    public string StripeSecretKey { get; init; } = string.Empty;

    public string StripeWebhookSecret { get; init; } = string.Empty;

    public BillingPriceIds PriceIds { get; init; } = new();

    public BillingGracePolicyOptions GracePolicy { get; init; } = new();
}

public sealed class BillingPriceIds
{
    public string ProfessionalMonthly { get; init; } = "dev_price_professional_monthly";
}

public sealed class BillingGracePolicyOptions
{
    public int Version { get; init; } = 1;

    public int PastDueGraceDays { get; init; } = 3;
}

public sealed class EntitlementLeaseOptions
{
    public const string SectionName = "Lease";

    public string Provider { get; init; } = "development";

    public string KeyVaultUri { get; init; } = string.Empty;

    public string EditionLeaseKey { get; init; } = string.Empty;

    public string StrategyLicenseLeaseKey { get; init; } = string.Empty;

    public string Algorithm { get; init; } = "ES256";

    public string Issuer { get; init; } = "daxalgo-platform-development";

    public string Audience { get; init; } = "daxalgo-desktop";

    public int DurationHours { get; init; } = 168;
}

public sealed class MarketplaceLicensingOptions
{
    public const string SectionName = "MarketplaceLicensing";

    public string Provider { get; init; } = "development";

    public string KeyVaultUri { get; init; } = string.Empty;

    public string SigningKey { get; init; } = string.Empty;

    public string ContentWrappingKey { get; init; } = string.Empty;

    public string Issuer { get; init; } = "daxalgo-platform-development";

    public string Audience { get; init; } = "daxalgo-daxq-host";

    public int ChallengeTtlSeconds { get; init; } = 120;

    public int ContentKeyTtlSeconds { get; init; } = 900;

    public int RunTokenTtlMinutes { get; init; } = 30;

    public int OfflineGraceHours { get; init; } = 24;

    public int DownloadGrantTtlSeconds { get; init; } = 300;
}

public sealed class SignalExecutionOptions
{
    public const string SectionName = "SignalExecution";

    public string Provider { get; init; } = "Disabled";

    public string PublicWebSocketBaseUri { get; init; } = string.Empty;

    public string SessionTokenKey { get; init; } = string.Empty;

    public string TokenIssuer { get; init; } = "daxalgo-platform-development";

    public string TokenAudience { get; init; } = "daxalgo-signal-stream";

    public int SessionTokenTtlSeconds { get; init; } = 300;

    public int HeartbeatIntervalSeconds { get; init; } = 5;

    public int AuthorizationPollMilliseconds { get; init; } = 500;

    public string Image { get; init; } = string.Empty;

    public string Entrypoint { get; init; } = "/opt/daxalgo/bin/daxalgo-signal-worker";

    public string ReleaseSigningKeyId { get; init; } = string.Empty;

    public string ReleaseVerificationKeySpki { get; init; } = string.Empty;

    public int WallClockSeconds { get; init; } = 300;

    public int MemoryMb { get; init; } = 512;

    public decimal Cpus { get; init; } = 1m;

    public int PidsLimit { get; init; } = 64;

    public int DiskMb { get; init; } = 128;

    public int MaximumOutputBytes { get; init; } = 1024 * 1024;

    public int MaximumConcurrentSessions { get; init; } = 4;
}

public sealed class MarketplaceCommerceOptions
{
    public const string SectionName = "MarketplaceCommerce";

    public string Provider { get; init; } = "Development";

    public bool SalesEnabled { get; init; }

    public string PolicyVersion { get; init; } = "marketplace-commerce-development-v1";

    // Development placeholders only. Business/legal owners must approve every commercial value before GA.
    public int ApplicationFeeBasisPoints { get; init; } = 1_500;

    public int ReserveBasisPoints { get; init; }

    public int PayoutDelayDays { get; init; } = 7;

    public bool AutomaticTaxEnabled { get; init; } = true;

    public string TaxHandling { get; init; } = "stripe_automatic_tax";

    public string MerchantOfRecord { get; init; } = "undecided";

    public string Currency { get; init; } = "usd";

    public string ConnectRefreshUrl { get; init; } =
        "https://marketplace.development.invalid/connect/refresh";

    public string ConnectReturnUrl { get; init; } =
        "https://marketplace.development.invalid/connect/return";

    public string CheckoutSuccessUrl { get; init; } =
        "https://marketplace.development.invalid/orders/success?session_id={CHECKOUT_SESSION_ID}";

    public string CheckoutCancelUrl { get; init; } =
        "https://marketplace.development.invalid/orders/cancel";
}
