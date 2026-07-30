using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;

namespace DaxAlgo.Platform.Features.Marketplace;

public static class MarketplaceSignalEndpoints
{
    public static IEndpointRouteBuilder MapMarketplaceSignalEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
                "/v1/marketplace/licenses/{licenseId:guid}/signal-sessions",
                async (
                    Guid licenseId,
                    SignalSessionOpenRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceSignalSessionService sessions,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await profiles.RequireAsync(
                        identities.Resolve(context.User),
                        cancellationToken);
                    return Results.Ok(await sessions.OpenAsync(
                        profile.Id,
                        licenseId,
                        request,
                        RequireIdempotencyKey(context.Request),
                        context.Request,
                        cancellationToken));
                })
            .WithTags("Tier-3 signals")
            .RequireAuthorization()
            .WithName("OpenMarketplaceSignalSession");

        endpoints.MapGet(
                "/v1/signals/{sessionId:guid}",
                async (
                    Guid sessionId,
                    HttpContext context,
                    MarketplaceSignalSessionService sessions,
                    CancellationToken cancellationToken) =>
                {
                    await sessions.StreamAsync(
                        sessionId,
                        RequireBearerToken(context.Request),
                        context,
                        cancellationToken);
                })
            .WithTags("Tier-3 signals")
            .AllowAnonymous()
            .WithName("StreamMarketplaceSignals");

        return endpoints;
    }

    private static string RequireIdempotencyKey(HttpRequest request)
    {
        var value = request.Headers["Idempotency-Key"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new PlatformValidationException("Idempotency-Key header is required.");
        }

        return value;
    }

    private static string RequireBearerToken(HttpRequest request)
    {
        var header = request.Headers.Authorization.FirstOrDefault();
        const string prefix = "Bearer ";
        if (header is null
            || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(header[prefix.Length..]))
        {
            throw new PlatformForbiddenException(
                "A signal-session bearer token is required for the WebSocket upgrade.");
        }

        return header[prefix.Length..].Trim();
    }
}
