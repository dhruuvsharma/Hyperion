using System.Text.Json.Serialization;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Mvc;
using TradingTerminal.Ai.Coordinator.Client;

namespace DaxAlgo.Platform.Features.VibeQuant;

public static class VibeQuantEndpoints
{
    public static IEndpointRouteBuilder MapVibeQuantEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/v1/vibe-quant")
            .WithTags("Hyperion")
            .RequireAuthorization();

        group.MapGet(
                "/credits",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    return Results.Ok(await service.GetCreditsAsync(accountId, cancellationToken));
                })
            .WithName("GetMyVibeQuantCredits");

        group.MapPost(
                "/runs",
                async (
                    CreateVibeQuantRunRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    var result = await service.CreateRunAsync(
                        accountId,
                        request,
                        RequireIdempotencyKey(context.Request),
                        cancellationToken);
                    return Results.Created($"/api/v1/vibe-quant/runs/{result.Spec.RunId:D}", result);
                })
            .WithName("CreateVibeQuantRun")
            .WithMetadata(new RequestSizeLimitAttribute(VibeQuantApiVersions.MaximumRequestBytes));

        group.MapGet(
                "/runs",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    return Results.Ok(await service.ListAsync(accountId, cancellationToken));
                })
            .WithName("ListVibeQuantRuns");

        group.MapGet(
                "/runs/{runId:guid}",
                async (
                    Guid runId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    return Results.Ok(await service.GetStatusAsync(accountId, runId, cancellationToken));
                })
            .WithName("GetVibeQuantRun");

        group.MapGet(
                "/runs/{runId:guid}/spec",
                async (
                    Guid runId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    return Results.Ok(await service.GetSpecificationAsync(accountId, runId, cancellationToken));
                })
            .WithName("GetVibeQuantRunSpecification");

        group.MapPost(
                "/runs/{runId:guid}/start",
                async (
                    Guid runId,
                    StartVibeQuantRunRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    var result = await service.StartAsync(
                        accountId,
                        runId,
                        request.SpecSha256,
                        cancellationToken);
                    return Results.Accepted($"/api/v1/vibe-quant/runs/{runId:D}", result);
                })
            .WithName("StartVibeQuantRun");

        group.MapGet(
                "/runs/{runId:guid}/artifacts/{artifactSha256}",
                async (
                    Guid runId,
                    string artifactSha256,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    return Results.Ok(await service.GetArtifactAsync(
                        accountId,
                        runId,
                        artifactSha256,
                        cancellationToken));
                })
            .WithName("GetVibeQuantArtifact");

        group.MapPost(
                "/runs/{runId:guid}/release",
                async (
                    Guid runId,
                    ReleaseVibeQuantRunRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    return Results.Ok(await service.ReleaseAsync(
                        accountId,
                        runId,
                        request.ArtifactSha256,
                        cancellationToken));
                })
            .WithName("ReleaseVibeQuantRun");

        group.MapPost(
                "/runs/{runId:guid}/cancel",
                async (
                    Guid runId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    EntitlementService entitlements,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var accountId = await RequireProfessionalAccountAsync(
                        context,
                        identities,
                        profiles,
                        entitlements,
                        cancellationToken);
                    var result = await service.CancelAsync(accountId, runId, cancellationToken);
                    return Results.Accepted($"/api/v1/vibe-quant/runs/{runId:D}", result);
                })
            .WithName("CancelVibeQuantRun");

        endpoints.MapPost(
                "/api/v1/admin/vibe-quant/credits/grants",
                async (
                    GrantVibeQuantCreditsRequest request,
                    HttpContext context,
                    VibeQuantService service,
                    CancellationToken cancellationToken) =>
                {
                    var result = await service.GrantCreditsAsync(
                        request.AccountId,
                        request.Credits,
                        RequireIdempotencyKey(context.Request),
                        request.Reason,
                        cancellationToken);
                    return Results.Ok(result);
                })
            .WithTags("Hyperion administration")
            .WithName("GrantVibeQuantCredits")
            .RequireAuthorization("platform-admin");

        return endpoints;
    }

    private static async Task<Guid> RequireProfessionalAccountAsync(
        HttpContext context,
        IManagedIdentityProvider identities,
        ProfileService profiles,
        EntitlementService entitlements,
        CancellationToken cancellationToken)
    {
        var identity = identities.Resolve(context.User);
        var profile = await profiles.RequireAsync(identity, cancellationToken);
        await entitlements.RequireTierAsync(profile.Id, PlanTier.Professional, cancellationToken);
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

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record GrantVibeQuantCreditsRequest(Guid AccountId, long Credits, string Reason);
