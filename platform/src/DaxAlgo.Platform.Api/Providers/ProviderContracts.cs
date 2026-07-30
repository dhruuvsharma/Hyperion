using System.Security.Claims;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Domain;

namespace DaxAlgo.Platform.Providers;

public sealed record ManagedIdentity(string Subject, string Email, string DisplayName);

public interface IManagedIdentityProvider
{
    ManagedIdentity Resolve(ClaimsPrincipal principal);
}

public sealed record BillingCheckout(
    string ProviderCheckoutId,
    string? CheckoutUrl,
    OrderStatus InitialStatus);

public enum BillingEventPurpose
{
    Edition,
    MarketplaceOrder,
    MarketplacePublisher,
}

public sealed record VerifiedBillingEvent(
    string EventId,
    string EventType,
    Guid? AccountId,
    string? SubscriptionId,
    string? PriceId,
    SubscriptionStatus? SubscriptionStatus,
    DateTimeOffset? CurrentPeriodEnd,
    Guid? OrderId)
{
    public BillingEventPurpose Purpose { get; init; }

    public string? ConnectAccountId { get; init; }

    public bool? DetailsSubmitted { get; init; }

    public bool? ChargesEnabled { get; init; }

    public bool? PayoutsEnabled { get; init; }
}

public interface IBillingProvider
{
    string Name { get; }

    Task<BillingCheckout> CreateCheckoutAsync(
        MarketplaceOrder order,
        CatalogItem item,
        CancellationToken cancellationToken);

    Task<VerifiedBillingEvent> VerifyWebhookAsync(
        ReadOnlyMemory<byte> payload,
        IHeaderDictionary headers,
        CancellationToken cancellationToken);
}

public sealed class BillingWebhookException(string message) : Exception(message);

public sealed record MarketplaceLicenseSignature(
    string EncodedPayload,
    string EncodedSignature,
    string KeyId,
    string Algorithm);

public sealed record MarketplaceLicenseJsonWebKey(
    [property: JsonPropertyName("kty")] string KeyType,
    [property: JsonPropertyName("use")] string PublicKeyUse,
    [property: JsonPropertyName("kid")] string KeyId,
    [property: JsonPropertyName("alg")] string Algorithm,
    [property: JsonPropertyName("crv")] string Curve,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y);

public interface IMarketplaceLicenseCryptographyProvider
{
    ValueTask<MarketplaceLicenseSignature> SignAsync(
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken);

    ValueTask<MarketplaceLicenseJsonWebKey> GetVerificationKeyAsync(
        CancellationToken cancellationToken);

    ValueTask<byte[]> UnwrapContentKeyAsync(
        string algorithm,
        ReadOnlyMemory<byte> wrappedContentKey,
        CancellationToken cancellationToken);
}

public interface IContentKeyProvisioningProvider
{
    ValueTask<byte[]> WrapContentKeyAsync(
        string algorithm,
        ReadOnlyMemory<byte> contentKey,
        CancellationToken cancellationToken);
}
