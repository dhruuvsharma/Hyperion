using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;

namespace DaxAlgo.Platform.Features.Devices;

public static class DeviceEndpoints
{
    public static IEndpointRouteBuilder MapDeviceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/v1/devices")
            .WithTags("Devices")
            .RequireAuthorization();

        group.MapGet(
                "/",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    DeviceService devices,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await profiles.RequireAsync(
                        identities.Resolve(context.User),
                        cancellationToken);
                    var registeredDevices = await devices.GetAsync(profile.Id, cancellationToken);
                    return Results.Ok(registeredDevices.Select(DeviceResponse.From));
                })
            .WithName("GetMyDevices");

        group.MapPost(
                "/",
                async (
                    RegisterDeviceRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    DeviceService devices,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await profiles.RequireAsync(
                        identities.Resolve(context.User),
                        cancellationToken);
                    var device = await devices.RegisterAsync(
                        profile.Id,
                        request.DeviceId,
                        request.DisplayName,
                        request.PublicKeySpki,
                        request.FingerprintSha256,
                        cancellationToken);
                    return Results.Created(
                        $"/api/v1/devices/{device.DeviceId}",
                        DeviceResponse.From(device));
                })
            .WithName("RegisterDevice");

        group.MapPost(
                "/{deviceId:guid}/revoke",
                async (
                    Guid deviceId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    DeviceService devices,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await profiles.RequireAsync(
                        identities.Resolve(context.User),
                        cancellationToken);
                    var device = await devices.RevokeAsync(
                        profile.Id,
                        deviceId,
                        cancellationToken);
                    return Results.Ok(DeviceResponse.From(device));
                })
            .WithName("RevokeDevice");

        return endpoints;
    }
}

public sealed record RegisterDeviceRequest(
    Guid DeviceId,
    string? DisplayName,
    string? PublicKeySpki = null,
    string? FingerprintSha256 = null);

public sealed record DeviceResponse(
    Guid DeviceId,
    string DisplayName,
    DateTimeOffset RegisteredAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset? RevokedAt)
{
    internal static DeviceResponse From(RegisteredDevice device) =>
        new(
            device.DeviceId,
            device.DisplayName,
            device.RegisteredAt,
            device.LastSeenAt,
            device.RevokedAt);
}
