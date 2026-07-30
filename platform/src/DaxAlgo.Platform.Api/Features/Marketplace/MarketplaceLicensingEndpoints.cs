using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Mvc;

namespace DaxAlgo.Platform.Features.Marketplace;

public static class MarketplaceLicensingEndpoints
{
    public static IEndpointRouteBuilder MapMarketplaceLicensingEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
                "/v1/devices/challenges",
                async (
                    DeviceProofChallengeRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceLicensingService licensing,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await ResolveAccountAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(await licensing.IssueChallengeAsync(
                        accountId,
                        request,
                        RequireIdempotencyKey(context.Request),
                        cancellationToken));
                })
            .WithTags("DAXQ licensing")
            .RequireAuthorization()
            .WithName("IssueDaxqDeviceProofChallenge");

        endpoints.MapPost(
                "/v1/marketplace/licenses/{licenseId:guid}/content-keys",
                async (
                    Guid licenseId,
                    ContentKeyReleaseRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceLicensingService licensing,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await ResolveAccountAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(await licensing.ReleaseContentKeyAsync(
                        accountId,
                        licenseId,
                        request,
                        RequireIdempotencyKey(context.Request),
                        cancellationToken));
                })
            .WithTags("DAXQ licensing")
            .RequireAuthorization()
            .WithName("ReleaseDaxqContentKey");

        endpoints.MapPost(
                "/v1/marketplace/licenses/{licenseId:guid}/heartbeats",
                async (
                    Guid licenseId,
                    MarketplaceHeartbeatRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceLicensingService licensing,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await ResolveAccountAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(await licensing.HeartbeatAsync(
                        accountId,
                        licenseId,
                        request,
                        RequireIdempotencyKey(context.Request),
                        cancellationToken));
                })
            .WithTags("DAXQ licensing")
            .RequireAuthorization()
            .WithName("RefreshDaxqRunToken");

        endpoints.MapGet(
                "/v1/marketplace/releases/{releaseId:guid}/download-grant",
                async (
                    Guid releaseId,
                    [FromQuery(Name = "license_id")] Guid licenseId,
                    [FromQuery(Name = "device_id")] Guid deviceId,
                    [FromQuery(Name = "challenge_id")] Guid challengeId,
                    [FromQuery(Name = "device_signature")] string deviceSignature,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceLicensingService licensing,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await ResolveAccountAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(await licensing.GetDownloadGrantAsync(
                        accountId,
                        releaseId,
                        licenseId,
                        deviceId,
                        challengeId,
                        deviceSignature,
                        RequireIdempotencyKey(context.Request),
                        cancellationToken));
                })
            .WithTags("DAXQ licensing")
            .RequireAuthorization()
            .WithName("GetDaxqDownloadGrant");

        endpoints.MapGet(
                "/v1/marketplace/revocations",
                async (
                    [FromQuery(Name = "after_seq")] long? afterSequence,
                    MarketplaceLicensingService licensing,
                    CancellationToken cancellationToken) =>
                    Results.Ok(await licensing.GetRevocationFeedAsync(
                        afterSequence ?? 0,
                        cancellationToken)))
            .WithTags("DAXQ licensing")
            .RequireAuthorization()
            .WithName("GetDaxqRevocations");

        endpoints.MapGet(
                "/v1/marketplace/licensing/jwks",
                async (
                    MarketplaceLicensingService licensing,
                    CancellationToken cancellationToken) =>
                    Results.Ok(await licensing.GetVerificationKeysAsync(cancellationToken)))
            .WithTags("DAXQ licensing")
            .RequireAuthorization()
            .WithName("GetDaxqLicensingVerificationKeys");

        return endpoints;
    }

    private static async Task<Guid> ResolveAccountAsync(
        HttpContext context,
        IManagedIdentityProvider identities,
        ProfileService profiles,
        CancellationToken cancellationToken)
    {
        var profile = await profiles.RequireAsync(
            identities.Resolve(context.User),
            cancellationToken);
        return profile.Id;
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
}
