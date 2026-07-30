using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Domain;

namespace DaxAlgo.Platform.Providers;

public sealed class DevelopmentManagedIdentityProvider : IManagedIdentityProvider
{
    public ManagedIdentity Resolve(ClaimsPrincipal principal)
    {
        var subject = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new UnauthorizedAccessException("The authenticated identity has no stable subject.");
        }

        var email = principal.FindFirstValue(ClaimTypes.Email) ?? $"{subject}@development.invalid";
        var name = principal.FindFirstValue(ClaimTypes.Name) ?? subject;
        return new ManagedIdentity(subject, email, name);
    }
}

public sealed class DevelopmentBillingProvider : IBillingProvider
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public string Name => "development";

    public Task<BillingCheckout> CreateCheckoutAsync(
        MarketplaceOrder order,
        CatalogItem item,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var status = item.PriceInCents == 0 ? OrderStatus.Paid : OrderStatus.Pending;
        var checkoutId = $"dev_checkout_{order.Id:N}";
        var checkoutUrl = status == OrderStatus.Pending
            ? $"https://checkout.development.invalid/{checkoutId}"
            : null;

        return Task.FromResult(new BillingCheckout(checkoutId, checkoutUrl, status));
    }

    public Task<VerifiedBillingEvent> VerifyWebhookAsync(
        ReadOnlyMemory<byte> payload,
        IHeaderDictionary headers,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!headers.TryGetValue("X-Development-Webhook", out var marker)
            || !string.Equals(marker.ToString(), "accepted", StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("The development webhook marker is missing or invalid.");
        }

        DevelopmentBillingEvent? billingEvent;
        try
        {
            billingEvent = JsonSerializer.Deserialize<DevelopmentBillingEvent>(payload.Span, SerializerOptions);
        }
        catch (JsonException exception)
        {
            throw new BillingWebhookException($"The webhook payload is invalid: {exception.Message}");
        }

        if (billingEvent is null
            || string.IsNullOrWhiteSpace(billingEvent.Id)
            || string.IsNullOrWhiteSpace(billingEvent.Type))
        {
            throw new BillingWebhookException("The webhook must include id and type.");
        }

        return Task.FromResult(new VerifiedBillingEvent(
            billingEvent.Id,
            billingEvent.Type,
            billingEvent.AccountId,
            billingEvent.SubscriptionId,
            billingEvent.PriceId,
            billingEvent.Status,
            billingEvent.CurrentPeriodEnd,
            billingEvent.OrderId)
        {
            Purpose = billingEvent.Purpose,
            ConnectAccountId = billingEvent.ConnectAccountId,
            DetailsSubmitted = billingEvent.DetailsSubmitted,
            ChargesEnabled = billingEvent.ChargesEnabled,
            PayoutsEnabled = billingEvent.PayoutsEnabled,
        });
    }

    private sealed record DevelopmentBillingEvent(
        string Id,
        string Type,
        Guid? AccountId,
        string? SubscriptionId,
        string? PriceId,
        SubscriptionStatus? Status,
        DateTimeOffset? CurrentPeriodEnd,
        Guid? OrderId,
        BillingEventPurpose Purpose = BillingEventPurpose.Edition,
        string? ConnectAccountId = null,
        bool? DetailsSubmitted = null,
        bool? ChargesEnabled = null,
        bool? PayoutsEnabled = null);
}
