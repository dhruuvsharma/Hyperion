using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Providers;

namespace DaxAlgo.Platform.Features.Profiles;

public static class ProfileEndpoints
{
    public static IEndpointRouteBuilder MapProfileEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/v1")
            .WithTags("Profiles and entitlements")
            .RequireAuthorization();

        group.MapPost(
                "/profiles/bootstrap",
                async (
                    BootstrapProfileRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    CancellationToken cancellationToken) =>
                {
                    var identity = identities.Resolve(context.User);
                    var profile = await profiles.BootstrapAsync(
                        identity,
                        request.DisplayName,
                        cancellationToken);
                    return Results.Ok(ProfileResponse.From(profile));
                })
            .WithName("BootstrapProfile");

        group.MapGet(
                "/profiles/me",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    CancellationToken cancellationToken) =>
                {
                    var identity = identities.Resolve(context.User);
                    var profile = await profiles.FindAsync(identity.Subject, cancellationToken)
                        ?? throw new PlatformNotFoundException("Product profile not found.");
                    return Results.Ok(ProfileResponse.From(profile));
                })
            .WithName("GetMyProfile");

        group.MapGet(
                "/entitlements/me",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    CancellationToken cancellationToken) =>
                {
                    var identity = identities.Resolve(context.User);
                    var profile = await profiles.RequireAsync(identity, cancellationToken);
                    var entitlement = await entitlements.GetAsync(profile.Id, cancellationToken);
                    return Results.Ok(EntitlementResponse.From(entitlement));
                })
            .WithName("GetMyEntitlement");

        return endpoints;
    }
}

public sealed record BootstrapProfileRequest(string? DisplayName);

public sealed record ProfileResponse(
    string Email,
    string DisplayName)
{
    internal static ProfileResponse From(Profile profile) =>
        new(profile.Email, profile.DisplayName);
}

public sealed record EntitlementResponse(
    PlanTier Tier,
    bool IsActive,
    DateTimeOffset IssuedAt,
    DateTimeOffset LeaseExpiresAt,
    DateTimeOffset? SubscriptionValidUntil,
    IReadOnlyList<string> Capabilities)
{
    internal static EntitlementResponse From(EntitlementSnapshot entitlement) =>
        new(
            entitlement.Tier,
            entitlement.IsActive,
            entitlement.IssuedAt,
            entitlement.LeaseExpiresAt,
            entitlement.SubscriptionValidUntil,
            entitlement.Capabilities);
}
