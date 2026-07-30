using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Billing;
using DaxAlgo.Platform.Features.Devices;
using DaxAlgo.Platform.Features.Entitlements;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class EntitlementLeaseTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    [Fact]
    public async Task DevelopmentSigningIsDeterministicForTheSameCanonicalPayload()
    {
        var signer = new DevelopmentEntitlementLeaseSigningProvider();
        var payload = new byte[] { 1, 2, 3, 4 };

        var first = await signer.SignAsync(
            EntitlementLeaseKind.EditionLease,
            payload,
            CancellationToken.None);
        var second = await signer.SignAsync(
            EntitlementLeaseKind.EditionLease,
            payload,
            CancellationToken.None);
        var strategy = await signer.SignAsync(
            EntitlementLeaseKind.StrategyLicenseLease,
            payload,
            CancellationToken.None);

        Assert.Equal(first, second);
        Assert.Equal("HS256-DEVELOPMENT-ONLY", first.Algorithm);
        Assert.NotEqual(first.KeyId, strategy.KeyId);
        Assert.NotEqual(first.EncodedSignature, strategy.EncodedSignature);
    }

    [Fact]
    public async Task SoftwareEs256SigningRoundTripsWithSeparatedLeaseKeys()
    {
        using var signer = new SoftwareEntitlementLeaseSigningProvider();
        var payload = new byte[] { 1, 2, 3, 4 };

        var edition = await signer.SignAsync(
            EntitlementLeaseKind.EditionLease,
            payload,
            CancellationToken.None);
        var strategy = await signer.SignAsync(
            EntitlementLeaseKind.StrategyLicenseLease,
            payload,
            CancellationToken.None);
        var verificationKeys = await signer.GetVerificationKeysAsync(CancellationToken.None);
        var editionJwk = Assert.Single(
            verificationKeys,
            key => key.LeaseKind == "edition-lease");
        var strategyJwk = Assert.Single(
            verificationKeys,
            key => key.LeaseKind == "strategy-license-lease");
        using var editionVerifier = CreateVerifier(editionJwk);
        using var strategyVerifier = CreateVerifier(strategyJwk);
        var editionSignature = DecodeBase64Url(edition.EncodedSignature);
        var strategySignature = DecodeBase64Url(strategy.EncodedSignature);

        Assert.Equal("ES256", edition.Algorithm);
        Assert.Equal(payload, DecodeBase64Url(edition.EncodedPayload));
        Assert.NotEqual(edition.KeyId, strategy.KeyId);
        Assert.True(Verify(editionVerifier, payload, editionSignature));
        Assert.True(Verify(strategyVerifier, payload, strategySignature));
        Assert.False(Verify(strategyVerifier, payload, editionSignature));
        Assert.False(Verify(editionVerifier, payload, strategySignature));
    }

    [Theory]
    [InlineData("development", "Development", "DevelopmentHmac")]
    [InlineData("development", "Testing", "SoftwareEs256")]
    [InlineData("software-es256", "Testing", "SoftwareEs256")]
    [InlineData("azure-kms", "Development", "AzureKms")]
    [InlineData("development", "Production", "AzureKms")]
    public void LeaseSigningAdapterSelectionIsEnvironmentAware(
        string provider,
        string environment,
        string expected)
    {
        Assert.Equal(
            expected,
            EntitlementLeaseSigningProviderSelection.Resolve(provider, environment).ToString());
    }

    [Fact]
    public void UnknownLeaseSigningAdapterFailsClosed()
    {
        Assert.Throws<InvalidOperationException>(() =>
            EntitlementLeaseSigningProviderSelection.Resolve("unknown", "Development"));
    }

    [Fact]
    public void WireContractRejectsMoreThanSevenDays()
    {
        var act = () => new EntitlementLeaseWireDto(
            EntitlementLeaseWireDto.CurrentSchemaVersion,
            "lease-1",
            NormalizedEntitlementState.Active,
            PlanTier.Professional,
            Guid.NewGuid().ToString("D"),
            Guid.NewGuid(),
            "issuer",
            "audience",
            Now,
            Now,
            Now.AddDays(7).AddTicks(1),
            "key",
            "algorithm",
            "payload",
            "signature");

        Assert.Throws<ArgumentOutOfRangeException>(act);
    }

    [Fact]
    public void PlatformWireContractMatchesTheSharedVersionOneGoldenPayload()
    {
        var platformLease = new EntitlementLeaseWireDto(
            EntitlementLeaseWireDto.CurrentSchemaVersion,
            "lease-golden-v1",
            NormalizedEntitlementState.Active,
            PlanTier.Professional,
            "11111111-1111-1111-1111-111111111111",
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            "daxalgo-platform",
            "daxalgo-desktop",
            Now,
            Now,
            Now.AddDays(7),
            "key-v1",
            "EdDSA",
            "eyJnb2xkZW4iOnRydWV9",
            "c2lnbmF0dXJl");
        var fixture = JsonNode.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "entitlement-lease-v1.json")));
        var emitted = JsonSerializer.SerializeToNode(platformLease, SerializerOptions);

        Assert.True(JsonNode.DeepEquals(fixture, emitted));
    }

    [Fact]
    public async Task LeaseIssuanceUsesOneInstantAtThePaidThroughBoundary()
    {
        var accountId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var databaseOptions = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase($"lease-boundary-{Guid.NewGuid():N}")
            .Options;
        await using var database = new PlatformDbContext(databaseOptions);
        database.Profiles.Add(new Profile
        {
            Id = accountId,
            Subject = "lease-boundary",
            Email = "lease-boundary@example.test",
            DisplayName = "Lease Boundary",
            CreatedAt = Now,
            UpdatedAt = Now,
        });
        database.Subscriptions.Add(new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = "sub_boundary",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.Active,
            CurrentPeriodEnd = Now.AddTicks(1),
            UpdatedAt = Now,
        });
        database.Devices.Add(new RegisteredDevice
        {
            AccountId = accountId,
            DeviceId = deviceId,
            DisplayName = "Boundary workstation",
            RegisteredAt = Now,
            LastSeenAt = Now,
        });
        await database.SaveChangesAsync();

        var clock = new AdvancingTimeProvider(Now, TimeSpan.FromSeconds(1));
        var deviceService = new DeviceService(
            database,
            new InProcessDeviceRegistrationGate(),
            clock);
        var entitlementService = new EntitlementService(
            database,
            new EntitlementProjector(new BillingGracePolicy(new BillingGracePolicyOptions
            {
                Version = BillingGracePolicy.CurrentVersion,
                PastDueGraceDays = 3,
            })),
            clock);
        var service = new EntitlementLeaseService(
            deviceService,
            entitlementService,
            new DevelopmentEntitlementLeaseSigningProvider(),
            new EntitlementLeaseOptions
            {
                Issuer = "test-issuer",
                Audience = "test-audience",
                DurationHours = 168,
            },
            clock);

        var lease = await service.IssueAsync(accountId, deviceId, CancellationToken.None);

        Assert.Equal(1, clock.CallCount);
        Assert.Equal(PlanTier.Professional, lease.Edition);
        Assert.Equal(Now, lease.IssuedAtUtc);
        Assert.Equal(Now.AddTicks(1), lease.ExpiresAtUtc);
    }

    private sealed class AdvancingTimeProvider(
        DateTimeOffset initial,
        TimeSpan step) : TimeProvider
    {
        private int callCount;

        public int CallCount => Volatile.Read(ref callCount);

        public override DateTimeOffset GetUtcNow()
        {
            var callIndex = Interlocked.Increment(ref callCount) - 1;
            return initial.AddTicks(step.Ticks * callIndex);
        }
    }

    private static ECDsa CreateVerifier(EntitlementLeaseJsonWebKey key) =>
        ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = DecodeBase64Url(key.X),
                Y = DecodeBase64Url(key.Y),
            },
        });

    private static bool Verify(ECDsa verifier, byte[] payload, byte[] signature) =>
        verifier.VerifyData(
            payload,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        return Convert.FromBase64String(base64);
    }
}
