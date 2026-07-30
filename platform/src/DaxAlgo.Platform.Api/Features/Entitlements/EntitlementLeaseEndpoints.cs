using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;

namespace DaxAlgo.Platform.Features.Entitlements;

public static class EntitlementLeaseEndpoints
{
    public static IEndpointRouteBuilder MapEntitlementLeaseEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
                "/api/v1/entitlements/lease",
                async (
                    IssueEntitlementLeaseRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementLeaseService leases,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await profiles.RequireAsync(
                        identities.Resolve(context.User),
                        cancellationToken);
                    return Results.Ok(await leases.IssueAsync(
                        profile.Id,
                        request.DeviceId,
                        cancellationToken));
                })
            .WithTags("Profiles and entitlements")
            .RequireAuthorization()
            .WithName("IssueEntitlementLease");

        endpoints.MapGet(
                "/api/v1/entitlements/lease/jwks",
                async (
                    IEntitlementLeaseSigningProvider signingProvider,
                    CancellationToken cancellationToken) =>
                {
                    var keys = await signingProvider.GetVerificationKeysAsync(cancellationToken);
                    return Results.Ok(new EntitlementLeaseJsonWebKeySet(keys));
                })
            .WithTags("Profiles and entitlements")
            .AllowAnonymous()
            .WithName("GetEntitlementLeaseVerificationKeys");
        return endpoints;
    }
}

public sealed record IssueEntitlementLeaseRequest(Guid DeviceId);
