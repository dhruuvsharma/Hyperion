using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Devices;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;

namespace DaxAlgo.Platform.Features.Entitlements;

public sealed class EntitlementLeaseService(
    DeviceService devices,
    EntitlementService entitlements,
    IEntitlementLeaseSigningProvider signingProvider,
    EntitlementLeaseOptions options,
    TimeProvider timeProvider)
{
    private static readonly JsonSerializerOptions SigningSerializerOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    public async Task<EntitlementLeaseWireDto> IssueAsync(
        Guid accountId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        await devices.RequireActiveAsync(accountId, deviceId, cancellationToken);
        var issuedAt = timeProvider.GetUtcNow();
        var entitlement = await entitlements.GetAtAsync(
            accountId,
            issuedAt,
            cancellationToken);
        if (!entitlement.IsActive)
        {
            throw new PlatformForbiddenException(
                "An active entitlement is required to issue an edition lease.");
        }

        var configuredExpiry = issuedAt.AddHours(options.DurationHours);
        var expiresAt = entitlement.LeaseExpiresAt < configuredExpiry
            ? entitlement.LeaseExpiresAt
            : configuredExpiry;

        var claims = new EntitlementLeaseSigningPayload(
            EntitlementLeaseWireDto.CurrentSchemaVersion,
            Guid.NewGuid().ToString("N"),
            NormalizedEntitlementState.Active,
            entitlement.Tier,
            accountId.ToString("D"),
            deviceId,
            options.Issuer.Trim(),
            options.Audience.Trim(),
            issuedAt,
            issuedAt,
            expiresAt);
        var canonicalPayload = JsonSerializer.SerializeToUtf8Bytes(
            claims,
            SigningSerializerOptions);
        var signature = await signingProvider.SignAsync(
            EntitlementLeaseKind.EditionLease,
            canonicalPayload,
            cancellationToken);
        var currentEntitlement = await entitlements.GetAtAsync(
            accountId,
            issuedAt,
            cancellationToken);
        if (!currentEntitlement.IsActive)
        {
            throw new PlatformForbiddenException(
                "An active entitlement is required to issue an edition lease.");
        }

        return new EntitlementLeaseWireDto(
            claims.SchemaVersion,
            claims.LeaseId,
            claims.State,
            claims.Edition,
            claims.ProductAccountId,
            claims.DeviceId,
            claims.Issuer,
            claims.Audience,
            claims.IssuedAtUtc,
            claims.NotBeforeUtc,
            claims.ExpiresAtUtc,
            signature.KeyId,
            signature.Algorithm,
            signature.EncodedPayload,
            signature.EncodedSignature);
    }
}

public sealed record EntitlementLeaseWireDto
{
    public const int CurrentSchemaVersion = 1;

    public static readonly TimeSpan MaximumLeaseDuration = TimeSpan.FromDays(7);

    public EntitlementLeaseWireDto(
        int schemaVersion,
        string leaseId,
        NormalizedEntitlementState state,
        PlanTier edition,
        string productAccountId,
        Guid deviceId,
        string issuer,
        string audience,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset notBeforeUtc,
        DateTimeOffset expiresAtUtc,
        string keyId,
        string algorithm,
        string encodedPayload,
        string encodedSignature)
    {
        if (schemaVersion != CurrentSchemaVersion)
        {
            throw new ArgumentOutOfRangeException(
                nameof(schemaVersion),
                schemaVersion,
                "Unsupported entitlement lease schema version.");
        }

        if (!Enum.IsDefined(state))
        {
            throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown entitlement state.");
        }

        if (!Enum.IsDefined(edition))
        {
            throw new ArgumentOutOfRangeException(nameof(edition), edition, "Unknown product edition.");
        }

        if (deviceId == Guid.Empty)
        {
            throw new ArgumentException("Device ID cannot be empty.", nameof(deviceId));
        }

        var issued = issuedAtUtc.ToUniversalTime();
        var notBefore = notBeforeUtc.ToUniversalTime();
        var expires = expiresAtUtc.ToUniversalTime();
        if (notBefore < issued || expires <= notBefore)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAtUtc),
                expiresAtUtc,
                "Lease times must satisfy issued <= not-before < expires.");
        }

        if (expires - issued > MaximumLeaseDuration)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expiresAtUtc),
                expiresAtUtc,
                "Entitlement leases cannot exceed seven days.");
        }

        SchemaVersion = schemaVersion;
        LeaseId = Require(leaseId, nameof(leaseId));
        State = state;
        Edition = edition;
        ProductAccountId = Require(productAccountId, nameof(productAccountId));
        DeviceId = deviceId;
        Issuer = Require(issuer, nameof(issuer));
        Audience = Require(audience, nameof(audience));
        IssuedAtUtc = issued;
        NotBeforeUtc = notBefore;
        ExpiresAtUtc = expires;
        KeyId = Require(keyId, nameof(keyId));
        Algorithm = Require(algorithm, nameof(algorithm));
        EncodedPayload = Require(encodedPayload, nameof(encodedPayload), trim: false);
        EncodedSignature = Require(encodedSignature, nameof(encodedSignature), trim: false);
    }

    [JsonPropertyName("schemaVersion")]
    public int SchemaVersion { get; }

    [JsonPropertyName("leaseId")]
    public string LeaseId { get; }

    [JsonPropertyName("state")]
    [JsonConverter(typeof(JsonStringEnumConverter<NormalizedEntitlementState>))]
    public NormalizedEntitlementState State { get; }

    [JsonPropertyName("edition")]
    [JsonConverter(typeof(JsonStringEnumConverter<PlanTier>))]
    public PlanTier Edition { get; }

    [JsonPropertyName("productAccountId")]
    public string ProductAccountId { get; }

    [JsonPropertyName("deviceId")]
    public Guid DeviceId { get; }

    [JsonPropertyName("issuer")]
    public string Issuer { get; }

    [JsonPropertyName("audience")]
    public string Audience { get; }

    [JsonPropertyName("issuedAtUtc")]
    public DateTimeOffset IssuedAtUtc { get; }

    [JsonPropertyName("notBeforeUtc")]
    public DateTimeOffset NotBeforeUtc { get; }

    [JsonPropertyName("expiresAtUtc")]
    public DateTimeOffset ExpiresAtUtc { get; }

    [JsonPropertyName("keyId")]
    public string KeyId { get; }

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; }

    [JsonPropertyName("encodedPayload")]
    public string EncodedPayload { get; }

    [JsonPropertyName("encodedSignature")]
    public string EncodedSignature { get; }

    private static string Require(string value, string parameterName, bool trim = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        return trim ? value.Trim() : value;
    }
}

internal sealed record EntitlementLeaseSigningPayload(
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("leaseId")] string LeaseId,
    [property: JsonPropertyName("state")] NormalizedEntitlementState State,
    [property: JsonPropertyName("edition")] PlanTier Edition,
    [property: JsonPropertyName("productAccountId")] string ProductAccountId,
    [property: JsonPropertyName("deviceId")] Guid DeviceId,
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("issuedAtUtc")] DateTimeOffset IssuedAtUtc,
    [property: JsonPropertyName("notBeforeUtc")] DateTimeOffset NotBeforeUtc,
    [property: JsonPropertyName("expiresAtUtc")] DateTimeOffset ExpiresAtUtc);
