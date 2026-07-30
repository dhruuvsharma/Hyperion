using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using DaxAlgo.Platform.Api;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Features.Billing;
using DaxAlgo.Platform.Features.Devices;
using DaxAlgo.Platform.Features.Entitlements;
using DaxAlgo.Platform.Features.Marketplace;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Features.VibeQuant;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Stripe;

var builder = WebApplication.CreateBuilder(args);

var identityOptions = builder.Configuration.GetSection(IdentityOptions.SectionName).Get<IdentityOptions>()
    ?? new IdentityOptions();
var googleAuthOptions = builder.Configuration.GetSection(GoogleAuthOptions.SectionName).Get<GoogleAuthOptions>()
    ?? new GoogleAuthOptions();
var billingOptions = builder.Configuration.GetSection(BillingOptions.SectionName).Get<BillingOptions>()
    ?? new BillingOptions();
var leaseOptions = builder.Configuration
    .GetSection(EntitlementLeaseOptions.SectionName)
    .Get<EntitlementLeaseOptions>()
    ?? new EntitlementLeaseOptions();
var marketplaceLicensingOptions = builder.Configuration
    .GetSection(MarketplaceLicensingOptions.SectionName)
    .Get<MarketplaceLicensingOptions>()
    ?? new MarketplaceLicensingOptions();
var marketplaceCommerceOptions = builder.Configuration
    .GetSection(MarketplaceCommerceOptions.SectionName)
    .Get<MarketplaceCommerceOptions>()
    ?? new MarketplaceCommerceOptions();
var marketplaceBuildWorkerOptions = builder.Configuration
    .GetSection(MarketplaceBuildWorkerOptions.SectionName)
    .Get<MarketplaceBuildWorkerOptions>()
    ?? new MarketplaceBuildWorkerOptions();
var marketplaceSubmissionOptions = builder.Configuration
    .GetSection(MarketplaceSubmissionOptions.SectionName)
    .Get<MarketplaceSubmissionOptions>()
    ?? new MarketplaceSubmissionOptions();
var signalExecutionOptions = builder.Configuration
    .GetSection(SignalExecutionOptions.SectionName)
    .Get<SignalExecutionOptions>()
    ?? new SignalExecutionOptions();
var vibeQuantOptions = builder.Configuration
    .GetSection(VibeQuantOptions.SectionName)
    .Get<VibeQuantOptions>()
    ?? new VibeQuantOptions();
vibeQuantOptions.Validate();
var vibeQuantModelDeployment = new VibeQuantModelDeploymentCatalog(
    vibeQuantOptions,
    TimeProvider.System);
var identityProviderMode = ManagedIdentityProviderSelection.Resolve(
    identityOptions,
    googleAuthOptions,
    builder.Environment);

var usesDevelopmentBilling = string.Equals(
    billingOptions.Provider,
    "Development",
    StringComparison.OrdinalIgnoreCase);
var usesStripeBilling = string.Equals(
    billingOptions.Provider,
    StripeBillingProvider.ProviderName,
    StringComparison.OrdinalIgnoreCase);
if (!usesDevelopmentBilling && !usesStripeBilling)
{
    throw new InvalidOperationException(
        $"Billing provider '{billingOptions.Provider}' is not installed. Expected Development or stripe.");
}

MarketplaceCommerceValidation.ValidateOptions(marketplaceCommerceOptions);
var usesDevelopmentMarketplaceCommerce = string.Equals(
    marketplaceCommerceOptions.Provider,
    DevelopmentMarketplaceCommerceProvider.ProviderName,
    StringComparison.OrdinalIgnoreCase);
var usesStripeMarketplaceCommerce = string.Equals(
    marketplaceCommerceOptions.Provider,
    StripeConnectMarketplaceCommerceProvider.ProviderName,
    StringComparison.OrdinalIgnoreCase);
if (!usesDevelopmentMarketplaceCommerce && !usesStripeMarketplaceCommerce)
{
    throw new InvalidOperationException(
        $"Marketplace commerce provider '{marketplaceCommerceOptions.Provider}' is not installed.");
}

if (usesStripeMarketplaceCommerce && !usesStripeBilling)
{
    throw new InvalidOperationException(
        "Stripe Connect marketplace commerce requires the Stripe billing provider so one verified webhook inbox owns both edition and marketplace events.");
}

if (marketplaceSubmissionOptions.MaximumSourceBytes is < 16 * 1024 or > 4 * 1024 * 1024
    || marketplaceSubmissionOptions.MaximumReferenceDatasetBytes is < 64 * 1024 or > 64 * 1024 * 1024
    || string.IsNullOrWhiteSpace(marketplaceSubmissionOptions.CapabilityPolicyVersion))
{
    throw new InvalidOperationException(
        "Marketplace submission source/dataset limits and capability policy version are invalid.");
}

var leaseSigningMode = EntitlementLeaseSigningProviderSelection.Resolve(
    leaseOptions.Provider,
    builder.Environment.EnvironmentName);
var marketplaceLicensingMode = MarketplaceLicenseCryptographyProviderSelection.Resolve(
    marketplaceLicensingOptions.Provider,
    builder.Environment.EnvironmentName);

if (string.IsNullOrWhiteSpace(leaseOptions.Issuer)
    || string.IsNullOrWhiteSpace(leaseOptions.Audience)
    || !string.Equals(
        leaseOptions.Algorithm,
        EntitlementLeaseSigningEncoding.Es256Algorithm,
        StringComparison.Ordinal)
    || leaseOptions.DurationHours is < 1 or > 168)
{
    throw new InvalidOperationException(
        "Lease issuer/audience are required, algorithm must be ES256, and duration must be between 1 and 168 hours.");
}

if (leaseSigningMode == EntitlementLeaseSigningMode.AzureKms)
{
    ValidateAzureLeaseOptions(leaseOptions);
}

ValidateMarketplaceLicensingOptions(marketplaceLicensingOptions);
ValidateSignalExecutionOptions(signalExecutionOptions, builder.Environment);
if (marketplaceLicensingMode == MarketplaceLicenseCryptographyMode.AzureKms)
{
    ValidateAzureMarketplaceLicensingOptions(marketplaceLicensingOptions);
}

var usesDevelopmentIdentity = identityProviderMode == ManagedIdentityProviderMode.Development;
var usesDevelopmentSigning = leaseSigningMode is
    EntitlementLeaseSigningMode.DevelopmentHmac or
    EntitlementLeaseSigningMode.SoftwareEs256;
if (!builder.Environment.IsDevelopment()
    && !builder.Environment.IsEnvironment("Testing")
    && (usesDevelopmentIdentity
        || usesDevelopmentBilling
        || usesDevelopmentSigning
        || usesDevelopmentMarketplaceCommerce))
{
    throw new InvalidOperationException(
        "Development identity, billing, and signing adapters are enabled only in Development or Testing.");
}

var billingGracePolicy = new BillingGracePolicy(billingOptions.GracePolicy);
StripeBillingProvider? stripeBillingProvider = null;
StripeClient? stripeClient = null;
if (usesStripeBilling || usesStripeMarketplaceCommerce)
{
    stripeClient = new StripeClient(billingOptions.StripeSecretKey.Trim());
}
if (usesStripeBilling)
{
    stripeBillingProvider = new StripeBillingProvider(
        billingOptions,
        stripeClient!,
        TimeProvider.System);
}

builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddOpenApi("v1");
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<PlatformExceptionHandler>();
if (usesDevelopmentIdentity)
{
    builder.Services.AddAuthentication(DevelopmentAuthenticationHandler.SchemeName)
        .AddScheme<AuthenticationSchemeOptions, DevelopmentAuthenticationHandler>(
            DevelopmentAuthenticationHandler.SchemeName,
            _ => { });
    builder.Services.AddSingleton<IManagedIdentityProvider, DevelopmentManagedIdentityProvider>();
}
else
{
    builder.Services.AddAuthentication(GoogleAuthenticationHandler.SchemeName)
        .AddScheme<AuthenticationSchemeOptions, GoogleAuthenticationHandler>(
            GoogleAuthenticationHandler.SchemeName,
            _ => { });
    builder.Services.AddSingleton(googleAuthOptions);
    builder.Services.AddHttpClient(
            GoogleManagedIdentityProvider.HttpClientName,
            client => client.Timeout = TimeSpan.FromSeconds(10))
        .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
        });
    builder.Services.AddSingleton<GoogleManagedIdentityProvider>();
    builder.Services.AddSingleton<IManagedIdentityProvider>(services =>
        services.GetRequiredService<GoogleManagedIdentityProvider>());
}
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("platform-admin", policy => policy.RequireRole("platform-admin"));
builder.Services.AddPlatformPersistence(builder.Configuration);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(billingOptions);
builder.Services.AddSingleton(billingGracePolicy);
if (stripeBillingProvider is null)
{
    builder.Services.AddSingleton<IBillingProvider, DevelopmentBillingProvider>();
}
else
{
    builder.Services.AddSingleton(stripeBillingProvider);
    builder.Services.AddSingleton<IBillingProvider>(stripeBillingProvider);
    builder.Services.AddScoped<StripeSubscriptionReconciler>();
    builder.Services.AddHostedService<StripeSubscriptionReconciliationWorker>();
}
builder.Services.AddSingleton<IPlanCatalog>(new PlanCatalog(billingOptions));
builder.Services.AddSingleton(leaseOptions);
builder.Services.AddSingleton(marketplaceLicensingOptions);
builder.Services.AddSingleton(marketplaceCommerceOptions);
builder.Services.AddSingleton(marketplaceBuildWorkerOptions);
builder.Services.AddSingleton(marketplaceSubmissionOptions);
builder.Services.AddSingleton(signalExecutionOptions);
builder.Services.AddSingleton(vibeQuantOptions);
if (leaseSigningMode == EntitlementLeaseSigningMode.AzureKms
    || marketplaceLicensingMode == MarketplaceLicenseCryptographyMode.AzureKms)
{
    builder.Services.AddSingleton<TokenCredential>(_ => new DefaultAzureCredential());
}
switch (leaseSigningMode)
{
    case EntitlementLeaseSigningMode.DevelopmentHmac:
        builder.Services.AddSingleton<
            IEntitlementLeaseSigningProvider,
            DevelopmentEntitlementLeaseSigningProvider>();
        break;
    case EntitlementLeaseSigningMode.SoftwareEs256:
        builder.Services.AddSingleton<
            IEntitlementLeaseSigningProvider,
            SoftwareEntitlementLeaseSigningProvider>();
        break;
    case EntitlementLeaseSigningMode.AzureKms:
        builder.Services.AddSingleton<
            IEntitlementLeaseSigningProvider,
            AzureEntitlementLeaseSigningProvider>();
        break;
    default:
        throw new InvalidOperationException("Unknown lease signing mode.");
}
switch (marketplaceLicensingMode)
{
    case MarketplaceLicenseCryptographyMode.SoftwareEs256:
        builder.Services.AddSingleton<SoftwareMarketplaceLicenseCryptographyProvider>();
        builder.Services.AddSingleton<IMarketplaceLicenseCryptographyProvider>(services =>
            services.GetRequiredService<SoftwareMarketplaceLicenseCryptographyProvider>());
        builder.Services.AddSingleton<IContentKeyProvisioningProvider>(services =>
            services.GetRequiredService<SoftwareMarketplaceLicenseCryptographyProvider>());
        break;
    case MarketplaceLicenseCryptographyMode.AzureKms:
        builder.Services.AddSingleton<AzureMarketplaceLicenseCryptographyProvider>();
        builder.Services.AddSingleton<IMarketplaceLicenseCryptographyProvider>(services =>
            services.GetRequiredService<AzureMarketplaceLicenseCryptographyProvider>());
        builder.Services.AddSingleton<IContentKeyProvisioningProvider>(services =>
            services.GetRequiredService<AzureMarketplaceLicenseCryptographyProvider>());
        break;
    default:
        throw new InvalidOperationException("Unknown marketplace licensing cryptography mode.");
}
if (usesStripeMarketplaceCommerce)
{
    builder.Services.AddSingleton<IStripeClient>(stripeClient!);
    builder.Services.AddSingleton<
        IMarketplaceCommerceProvider,
        StripeConnectMarketplaceCommerceProvider>();
}
else
{
    builder.Services.AddSingleton<
        IMarketplaceCommerceProvider,
        DevelopmentMarketplaceCommerceProvider>();
}
if (string.Equals(
        signalExecutionOptions.Provider,
        "Docker",
        StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<ISignalSandboxRunner, DockerSignalSandboxRunner>();
}
else if (string.Equals(
    signalExecutionOptions.Provider,
    "Disabled",
    StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<ISignalSandboxRunner, DisabledSignalSandboxRunner>();
}
else
{
    throw new InvalidOperationException(
        $"Signal execution provider '{signalExecutionOptions.Provider}' is not installed.");
}
builder.Services.AddSingleton<IMarketplaceArtifactStore, InMemoryMarketplaceArtifactStore>();
if (string.Equals(
        marketplaceBuildWorkerOptions.Provider,
        "Docker",
        StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<IMarketplaceBuildWorker, DockerMarketplaceBuildWorker>();
}
else if (string.Equals(
    marketplaceBuildWorkerOptions.Provider,
    "Disabled",
    StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<IMarketplaceBuildWorker, DisabledMarketplaceBuildWorker>();
}
else
{
    throw new InvalidOperationException(
        $"Marketplace build-worker provider '{marketplaceBuildWorkerOptions.Provider}' is not installed.");
}
if (builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("Testing"))
{
    builder.Services.AddSingleton<
        IMarketplaceAttestationSigner,
        DevelopmentMarketplaceAttestationSigner>();
}
else
{
    builder.Services.AddSingleton<
        IMarketplaceAttestationSigner,
        DisabledMarketplaceAttestationSigner>();
}
builder.Services.AddSingleton<IWebhookExecutionGate, InProcessWebhookExecutionGate>();
builder.Services.AddSingleton<IDeviceRegistrationGate, InProcessDeviceRegistrationGate>();
builder.Services.AddSingleton<MarketplaceLicensingMutationGate>();
builder.Services.AddSingleton<SignalSessionRegistry>();
builder.Services.AddSingleton<SignalSessionTokenService>();
builder.Services.AddScoped<ProfileService>();
builder.Services.AddSingleton<EntitlementProjector>();
builder.Services.AddScoped<EntitlementService>();
builder.Services.AddScoped<DeviceService>();
builder.Services.AddScoped<EntitlementLeaseService>();
builder.Services.AddScoped<MarketplaceService>();
builder.Services.AddScoped<MarketplaceSubmissionPipeline>();
builder.Services.AddScoped<MarketplaceReviewService>();
builder.Services.AddScoped<MarketplaceGrantService>();
builder.Services.AddScoped<MarketplacePublisherService>();
builder.Services.AddScoped<MarketplaceAttestationService>();
builder.Services.AddScoped<MarketplaceLicensingService>();
builder.Services.AddScoped<MarketplaceSignalSessionService>();
builder.Services.AddScoped<BillingWebhookProcessor>();
builder.Services.AddSingleton<VibeQuantMutationGate>();
builder.Services.AddSingleton<VibeQuantExecutionCancellationRegistry>();
builder.Services.AddSingleton(vibeQuantModelDeployment);
builder.Services.AddSingleton(new VibeQuantSpecificationFactory(
    vibeQuantOptions,
    TimeProvider.System,
    vibeQuantModelDeployment));
builder.Services.AddScoped<IVibeQuantExecutionRuntime, VibeQuantExecutionRuntime>();
builder.Services.AddScoped<VibeQuantService>();
builder.Services.AddHttpClient("VibeQuantLlm", client => client.Timeout = Timeout.InfiniteTimeSpan)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
    });
builder.Services.AddHttpClient(
        VibeQuantModelReadinessService.HttpClientName,
        client => client.Timeout = TimeSpan.FromSeconds(vibeQuantOptions.ModelAttestationTimeoutSeconds))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        ConnectTimeout = TimeSpan.FromSeconds(vibeQuantOptions.ModelAttestationTimeoutSeconds),
    });
builder.Services.AddSingleton(services => new VibeQuantModelReadinessService(
    vibeQuantOptions,
    services.GetRequiredService<IHttpClientFactory>(),
    TimeProvider.System,
    services.GetRequiredService<ILogger<VibeQuantModelReadinessService>>(),
    vibeQuantModelDeployment));
builder.Services.AddHostedService(services =>
    services.GetRequiredService<VibeQuantModelReadinessService>());
builder.Services.AddHealthChecks()
    .AddCheck<VibeQuantModelReadinessHealthCheck>("vibe-quant-model-readiness");
builder.Services.AddHostedService<VibeQuantWorker>();

var app = builder.Build();

app.UseExceptionHandler();
app.UseWebSockets();
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health", new HealthCheckOptions
{
    AllowCachingResponses = false,
});
app.MapOpenApi();
app.MapProfileEndpoints();
app.MapDeviceEndpoints();
app.MapEntitlementLeaseEndpoints();
app.MapMarketplaceEndpoints();
app.MapMarketplaceLicensingEndpoints();
app.MapMarketplaceSignalEndpoints();
app.MapBillingEndpoints();
app.MapVibeQuantEndpoints();

await app.Services.InitializePlatformDatabaseAsync();
await app.RunAsync();

static void ValidateAzureLeaseOptions(EntitlementLeaseOptions options)
{
    if (!Uri.TryCreate(options.KeyVaultUri, UriKind.Absolute, out var keyVaultUri)
        || !string.Equals(keyVaultUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        || keyVaultUri.Host.StartsWith("replace-", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            "Lease:KeyVaultUri must be a non-placeholder absolute HTTPS Azure vault or Managed HSM URI.");
    }

    var editionKeyName = GetVersionedAzureKeyName(
        options.EditionLeaseKey,
        "Lease:EditionLeaseKey");
    var strategyKeyName = GetVersionedAzureKeyName(
        options.StrategyLicenseLeaseKey,
        "Lease:StrategyLicenseLeaseKey");
    if (string.Equals(editionKeyName, strategyKeyName, StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            "Edition and strategy-license leases must use independently named Azure keys.");
    }
}

static void ValidateMarketplaceLicensingOptions(MarketplaceLicensingOptions options)
{
    if (string.IsNullOrWhiteSpace(options.Issuer)
        || string.IsNullOrWhiteSpace(options.Audience)
        || options.ChallengeTtlSeconds is < 30 or > 600
        || options.ContentKeyTtlSeconds is < 60 or > 3600
        || options.RunTokenTtlMinutes is < 1 or > 60
        || options.OfflineGraceHours is < 0 or > 24
        || options.DownloadGrantTtlSeconds is < 30 or > 900)
    {
        throw new InvalidOperationException(
            "Marketplace licensing issuer/audience are required; challenge, key, run-token, "
            + "offline-grace, and download TTLs must remain within their security bounds.");
    }
}

static void ValidateSignalExecutionOptions(
    SignalExecutionOptions options,
    IHostEnvironment environment)
{
    var disabled = string.Equals(options.Provider, "Disabled", StringComparison.OrdinalIgnoreCase);
    var docker = string.Equals(options.Provider, "Docker", StringComparison.OrdinalIgnoreCase);
    if (!disabled && !docker)
    {
        throw new InvalidOperationException(
            "SignalExecution:Provider must be Disabled or Docker.");
    }

    if (options.SessionTokenTtlSeconds is < 30 or > 900
        || options.HeartbeatIntervalSeconds is < 1 or > 60
        || options.AuthorizationPollMilliseconds is < 100 or > 2000
        || string.IsNullOrWhiteSpace(options.TokenIssuer)
        || string.IsNullOrWhiteSpace(options.TokenAudience))
    {
        throw new InvalidOperationException(
            "Signal execution token, heartbeat, and authorization-poll settings are outside their security bounds.");
    }

    if (disabled)
    {
        return;
    }

    DockerSignalSandboxRunner.ValidateOptions(options);
    if (string.IsNullOrWhiteSpace(options.ReleaseSigningKeyId)
        || string.IsNullOrWhiteSpace(options.ReleaseVerificationKeySpki))
    {
        throw new InvalidOperationException(
            "Docker signal execution requires a trusted release signing key ID and public key.");
    }

    try
    {
        if (MarketplaceCryptographyEncoding.Decode(options.ReleaseVerificationKeySpki).Length < 64)
        {
            throw new FormatException();
        }
    }
    catch (Exception exception) when (exception is ArgumentException or FormatException)
    {
        throw new InvalidOperationException(
            "SignalExecution:ReleaseVerificationKeySpki must be a base64url-encoded public key.",
            exception);
    }

    if (!environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
    {
        if (!Uri.TryCreate(options.PublicWebSocketBaseUri, UriKind.Absolute, out var endpoint)
            || !string.Equals(endpoint.Scheme, "wss", StringComparison.OrdinalIgnoreCase)
            || endpoint.IsLoopback
            || endpoint.Host.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Production signal execution requires an explicit non-loopback wss:// public endpoint.");
        }

        try
        {
            if (MarketplaceCryptographyEncoding.Decode(options.SessionTokenKey).Length < 32)
            {
                throw new FormatException();
            }
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new InvalidOperationException(
                "Production SignalExecution:SessionTokenKey must contain at least 32 base64url-encoded bytes.",
                exception);
        }
    }
}

static void ValidateAzureMarketplaceLicensingOptions(MarketplaceLicensingOptions options)
{
    if (!Uri.TryCreate(options.KeyVaultUri, UriKind.Absolute, out var keyVaultUri)
        || !string.Equals(keyVaultUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
        || keyVaultUri.Host.StartsWith("replace-", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            "MarketplaceLicensing:KeyVaultUri must be a non-placeholder HTTPS Azure vault or Managed HSM URI.");
    }

    var signingKeyName = GetVersionedAzureKeyName(
        options.SigningKey,
        "MarketplaceLicensing:SigningKey");
    var wrappingKeyName = GetVersionedAzureKeyName(
        options.ContentWrappingKey,
        "MarketplaceLicensing:ContentWrappingKey");
    if (string.Equals(signingKeyName, wrappingKeyName, StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException(
            "Marketplace signing and content wrapping must use independently named Azure keys.");
    }
}

static string GetVersionedAzureKeyName(string value, string configurationKey)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException(
            $"{configurationKey} must use a non-placeholder key-name/key-version value.");
    }

    var segments = value.Trim().Split(
        '/',
        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (segments.Length != 2
        || segments.Any(segment => segment.StartsWith("replace-", StringComparison.OrdinalIgnoreCase)))
    {
        throw new InvalidOperationException(
            $"{configurationKey} must use a non-placeholder key-name/key-version value.");
    }

    return segments[0];
}

public partial class Program;
