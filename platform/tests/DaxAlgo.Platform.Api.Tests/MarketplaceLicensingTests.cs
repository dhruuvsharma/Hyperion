using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Marketplace;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class MarketplaceLicensingTests
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public void Rfc3394KeyWrapMatchesThePublishedVector()
    {
        var keyEncryptionKey = Convert.FromHexString(
            "000102030405060708090A0B0C0D0E0F");
        var plaintext = Convert.FromHexString(
            "00112233445566778899AABBCCDDEEFF");
        var expected = Convert.FromHexString(
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

        var wrapped = AesKeyWrap.Wrap(keyEncryptionKey, plaintext);
        Assert.Equal(expected, wrapped);
        Assert.Equal(plaintext, AesKeyWrap.Unwrap(keyEncryptionKey, wrapped));
    }

    [Theory]
    [InlineData("development")]
    [InlineData("software-es256")]
    public void SoftwareLicensingProviderFailsClosedOutsideDevelopmentAndTesting(string provider)
    {
        Assert.Throws<InvalidOperationException>(() =>
            MarketplaceLicenseCryptographyProviderSelection.Resolve(provider, "Staging"));
    }

    [Fact]
    public async Task ContentKeyReleaseIsDeviceBoundAuditedAndDurablyIdempotent()
    {
        await using var factory = new PlatformApiFactory();
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedLicensedReleaseAsync(factory, client, deviceKey);
        using var sessionKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var sessionPublicKey = sessionKey.ExportSubjectPublicKeyInfo();
        var binding = Sha256Hex(sessionPublicKey);
        const string idempotencyKey = "content-key-release-1";
        var challenge = await IssueChallengeAsync(
            client,
            fixture,
            binding,
            MarketplaceLicensingService.ContentKeyOperation,
            idempotencyKey);
        var signature = SignProof(
            deviceKey,
            challenge,
            fixture,
            binding,
            MarketplaceLicensingService.ContentKeyOperation,
            idempotencyKey);
        var request = new ContentKeyReleaseRequest(
            fixture.ReleaseId,
            fixture.DeviceId,
            challenge.ChallengeId,
            Encode(sessionPublicKey),
            signature);

        var first = await PostJsonAsync(
            client,
            $"/v1/marketplace/licenses/{fixture.LicenseId:D}/content-keys",
            request,
            idempotencyKey);
        first.EnsureSuccessStatusCode();
        var response = await first.Content.ReadFromJsonAsync<ContentKeyReleaseResponse>();
        Assert.NotNull(response);
        Assert.Equal("A256KW", response.KeyWrapAlgorithm);
        Assert.Equal("A256GCM", response.ContentAlgorithm);
        Assert.Equal(fixture.ContentKeyId, response.ContentKeyId);
        Assert.InRange(response.TtlSeconds, 1, 900);
        Assert.Equal("ES256", response.RunToken.Algorithm);
        Assert.NotNull(response.OfflineLease);
        Assert.True(response.OfflineLease!.ExpiresAt <= response.OfflineLease.AccessValidUntil);
        Assert.InRange(
            response.OfflineLease.ExpiresAt - response.OfflineLease.IssuedAt,
            TimeSpan.FromHours(23),
            TimeSpan.FromHours(24));

        using var serverKey = ECDiffieHellman.Create();
        var serverPublicKey = Decode(response.ServerEphemeralPublicKey);
        serverKey.ImportSubjectPublicKeyInfo(serverPublicKey, out var bytesRead);
        Assert.Equal(serverPublicKey.Length, bytesRead);
        var sharedSecret = sessionKey.DeriveRawSecretAgreement(serverKey.PublicKey);
        var kdfInfo = Encoding.UTF8.GetBytes(
            $"DAXQ-CONTENT-KEY-V1|{fixture.LicenseId:D}|{fixture.ReleaseId:D}|{fixture.DeviceId:D}|{fixture.ContentKeyId}");
        var wrappingKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sharedSecret,
            32,
            Decode(challenge.Nonce),
            kdfInfo);
        var contentKey = AesKeyWrap.Unwrap(wrappingKey, Decode(response.WrappedKey));
        Assert.Equal(fixture.ContentKey, contentKey);
        CryptographicOperations.ZeroMemory(contentKey);
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(wrappingKey);

        var replay = await PostJsonAsync(
            client,
            $"/v1/marketplace/licenses/{fixture.LicenseId:D}/content-keys",
            request,
            idempotencyKey);
        replay.EnsureSuccessStatusCode();
        var replayedResponse = await replay.Content.ReadFromJsonAsync<ContentKeyReleaseResponse>();
        Assert.Equal(response.WrappedKey, replayedResponse!.WrappedKey);
        Assert.Equal(response.RunToken.TokenId, replayedResponse.RunToken.TokenId);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var audit = Assert.Single(await database.ContentKeyReleases.AsNoTracking()
            .Where(candidate => candidate.LicenseId == fixture.LicenseId)
            .ToListAsync());
        Assert.Equal(challenge.ChallengeId, audit.ChallengeId);
        Assert.Equal(fixture.LicenseId, audit.LicenseId);
        Assert.Equal(fixture.DeviceId, audit.DeviceId);
        Assert.Equal(binding, audit.SessionPublicKeySha256);
    }

    [Fact]
    public async Task ContentKeyReleaseDeniesInactiveEntitlementRevokedReleaseAndUnknownDevice()
    {
        await using var inactiveFactory = new PlatformApiFactory();
        using var inactiveClient = CreateAuthenticatedClient(inactiveFactory);
        using var inactiveDeviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var inactive = await SeedLicensedReleaseAsync(
            inactiveFactory,
            inactiveClient,
            inactiveDeviceKey,
            activeSubscription: false);
        var inactiveResponse = await CreateAndPostContentKeyRequestAsync(
            inactiveClient,
            inactiveDeviceKey,
            inactive,
            "inactive-entitlement");
        Assert.Equal(HttpStatusCode.Forbidden, inactiveResponse.StatusCode);
        Assert.Equal("application/problem+json", inactiveResponse.Content.Headers.ContentType?.MediaType);

        await using var revokedFactory = new PlatformApiFactory();
        using var revokedClient = CreateAuthenticatedClient(revokedFactory);
        using var revokedDeviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var revoked = await SeedLicensedReleaseAsync(revokedFactory, revokedClient, revokedDeviceKey);
        _ = await AddRevocationAsync(
            revokedFactory,
            "release",
            revoked.ReleaseId.ToString("D"));
        var revokedResponse = await CreateAndPostContentKeyRequestAsync(
            revokedClient,
            revokedDeviceKey,
            revoked,
            "revoked-release");
        Assert.Equal(HttpStatusCode.Forbidden, revokedResponse.StatusCode);

        await using var unknownFactory = new PlatformApiFactory();
        using var unknownClient = CreateAuthenticatedClient(unknownFactory);
        using var registeredDeviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var unknown = await SeedLicensedReleaseAsync(
            unknownFactory,
            unknownClient,
            registeredDeviceKey);
        using var unknownSessionKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var unknownDeviceResponse = await PostJsonAsync(
            unknownClient,
            $"/v1/marketplace/licenses/{unknown.LicenseId:D}/content-keys",
            new ContentKeyReleaseRequest(
                unknown.ReleaseId,
                Guid.NewGuid(),
                Guid.NewGuid(),
                Encode(unknownSessionKey.ExportSubjectPublicKeyInfo()),
                Encode(RandomNumberGenerator.GetBytes(64))),
            "unknown-device");
        Assert.Equal(HttpStatusCode.NotFound, unknownDeviceResponse.StatusCode);
    }

    [Fact]
    public async Task HeartbeatDeniesImmediatelyAfterSubscriptionLapse()
    {
        await using var factory = new PlatformApiFactory();
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedLicensedReleaseAsync(factory, client, deviceKey);
        var contentResponse = await CreateAndPostContentKeyRequestAsync(
            client,
            deviceKey,
            fixture,
            "heartbeat-seed");
        contentResponse.EnsureSuccessStatusCode();
        var released = await contentResponse.Content.ReadFromJsonAsync<ContentKeyReleaseResponse>();
        Assert.NotNull(released);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var grant = await database.EntitlementGrants.SingleAsync(
                item => item.AccountId == fixture.AccountId);
            grant.Status = EntitlementGrantStatus.Revoked;
            grant.RevokedAt = DateTimeOffset.UtcNow;
            grant.ValidUntil = DateTimeOffset.UtcNow.AddMinutes(-1);
            var license = await database.MarketplaceLicenses.SingleAsync(
                item => item.AccountId == fixture.AccountId);
            license.Status = MarketplaceLicenseStatus.Revoked;
            license.RevokedAt = DateTimeOffset.UtcNow;
            await database.SaveChangesAsync();
        }

        var envelope = new MarketplaceSignedEnvelope(
            released!.RunToken.KeyId,
            released.RunToken.Algorithm,
            released.RunToken.EncodedPayload,
            released.RunToken.EncodedSignature);
        var binding = Sha256Hex(Encoding.UTF8.GetBytes(
            envelope.EncodedPayload + "." + envelope.EncodedSignature));
        const string idempotencyKey = "heartbeat-after-lapse";
        var challenge = await IssueChallengeAsync(
            client,
            fixture,
            binding,
            MarketplaceLicensingService.HeartbeatOperation,
            idempotencyKey);
        var signature = SignProof(
            deviceKey,
            challenge,
            fixture,
            binding,
            MarketplaceLicensingService.HeartbeatOperation,
            idempotencyKey);
        var heartbeat = await PostJsonAsync(
            client,
            $"/v1/marketplace/licenses/{fixture.LicenseId:D}/heartbeats",
            new MarketplaceHeartbeatRequest(
                fixture.ReleaseId,
                fixture.DeviceId,
                challenge.ChallengeId,
                envelope,
                signature),
            idempotencyKey);
        Assert.Equal(HttpStatusCode.Forbidden, heartbeat.StatusCode);
    }

    [Fact]
    public async Task SignedRevocationFeedIsMonotonicAndRejectsRollbackCursor()
    {
        await using var factory = new PlatformApiFactory();
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _ = await SeedLicensedReleaseAsync(factory, client, deviceKey);
        var firstSequence = await AddRevocationAsync(
            factory,
            "license",
            Guid.NewGuid().ToString("D"));
        var secondSequence = await AddRevocationAsync(
            factory,
            "release",
            Guid.NewGuid().ToString("D"));

        var first = await client.GetFromJsonAsync<SignedRevocationFeed>(
            "/v1/marketplace/revocations?after_seq=0");
        Assert.NotNull(first);
        Assert.Equal(0, first.FromSequence);
        Assert.Equal(secondSequence, first.ThroughSequence);
        Assert.Equal(
            [firstSequence, secondSequence],
            first.Revocations.Select(item => item.Sequence));
        await AssertValidFeedSignatureAsync(client, first);

        var thirdSequence = await AddRevocationAsync(
            factory,
            "account",
            Guid.NewGuid().ToString("D"));
        var second = await client.GetFromJsonAsync<SignedRevocationFeed>(
            $"/v1/marketplace/revocations?after_seq={secondSequence}");
        Assert.NotNull(second);
        Assert.Equal(secondSequence, second.FromSequence);
        Assert.Equal(thirdSequence, second.ThroughSequence);
        Assert.Equal(thirdSequence, Assert.Single(second.Revocations).Sequence);
        await AssertValidFeedSignatureAsync(client, second);

        var rollback = await client.GetAsync(
            $"/v1/marketplace/revocations?after_seq={thirdSequence + 1}");
        Assert.Equal(HttpStatusCode.Conflict, rollback.StatusCode);
        Assert.Equal("application/problem+json", rollback.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task DownloadGrantRequiresDeviceProofAndIsShortLived()
    {
        await using var factory = new PlatformApiFactory();
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedLicensedReleaseAsync(factory, client, deviceKey);
        const string idempotencyKey = "download-grant-1";
        var challenge = await IssueChallengeAsync(
            client,
            fixture,
            fixture.CipherSha256,
            MarketplaceLicensingService.DownloadGrantOperation,
            idempotencyKey);
        var signature = SignProof(
            deviceKey,
            challenge,
            fixture,
            fixture.CipherSha256,
            MarketplaceLicensingService.DownloadGrantOperation,
            idempotencyKey);
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"/v1/marketplace/releases/{fixture.ReleaseId:D}/download-grant"
            + $"?license_id={fixture.LicenseId:D}"
            + $"&device_id={fixture.DeviceId:D}"
            + $"&challenge_id={challenge.ChallengeId:D}"
            + $"&device_signature={Uri.EscapeDataString(signature)}");
        request.Headers.Add("Idempotency-Key", idempotencyKey);
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var grant = await response.Content.ReadFromJsonAsync<DownloadGrantResponse>();
        Assert.NotNull(grant);
        Assert.Equal(fixture.CipherSha256, grant.CipherSha256);
        Assert.Contains("daxq_signature=", grant.DownloadUrl, StringComparison.Ordinal);
        Assert.InRange(
            grant.ExpiresAt - DateTimeOffset.UtcNow,
            TimeSpan.Zero,
            TimeSpan.FromMinutes(5));
    }

    private static async Task<HttpResponseMessage> CreateAndPostContentKeyRequestAsync(
        HttpClient client,
        ECDsa deviceKey,
        LicensingFixture fixture,
        string idempotencyKey)
    {
        using var sessionKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var sessionPublicKey = sessionKey.ExportSubjectPublicKeyInfo();
        var binding = Sha256Hex(sessionPublicKey);
        var challenge = await IssueChallengeAsync(
            client,
            fixture,
            binding,
            MarketplaceLicensingService.ContentKeyOperation,
            idempotencyKey);
        var signature = SignProof(
            deviceKey,
            challenge,
            fixture,
            binding,
            MarketplaceLicensingService.ContentKeyOperation,
            idempotencyKey);
        return await PostJsonAsync(
            client,
            $"/v1/marketplace/licenses/{fixture.LicenseId:D}/content-keys",
            new ContentKeyReleaseRequest(
                fixture.ReleaseId,
                fixture.DeviceId,
                challenge.ChallengeId,
                Encode(sessionPublicKey),
                signature),
            idempotencyKey);
    }

    private static async Task<DeviceProofChallengeResponse> IssueChallengeAsync(
        HttpClient client,
        LicensingFixture fixture,
        string bindingSha256,
        string operation,
        string idempotencyKey)
    {
        var response = await PostJsonAsync(
            client,
            "/v1/devices/challenges",
            new DeviceProofChallengeRequest(
                fixture.DeviceId,
                fixture.LicenseId,
                fixture.ReleaseId,
                operation,
                bindingSha256),
            idempotencyKey);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<DeviceProofChallengeResponse>())!;
    }

    private static string SignProof(
        ECDsa deviceKey,
        DeviceProofChallengeResponse challenge,
        LicensingFixture fixture,
        string bindingSha256,
        string operation,
        string idempotencyKey)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new DeviceProofPayload(
                1,
                operation,
                challenge.ChallengeId,
                challenge.Nonce,
                fixture.LicenseId,
                fixture.ReleaseId,
                fixture.DeviceId,
                bindingSha256,
                idempotencyKey),
            SerializerOptions);
        return Encode(deviceKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private static async Task AssertValidFeedSignatureAsync(
        HttpClient client,
        SignedRevocationFeed feed)
    {
        var keys = await client.GetFromJsonAsync<MarketplaceLicenseJsonWebKeySet>(
            "/v1/marketplace/licensing/jwks");
        var key = Assert.Single(keys!.Keys, item => item.KeyId == feed.KeyId);
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Decode(key.X),
                Y = Decode(key.Y),
            },
        });
        Assert.True(verifier.VerifyData(
            Decode(feed.EncodedPayload),
            Decode(feed.EncodedSignature),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var payload = JsonDocument.Parse(Decode(feed.EncodedPayload));
        Assert.Equal(feed.ThroughSequence, payload.RootElement.GetProperty("through_seq").GetInt64());
    }

    private static async Task<LicensingFixture> SeedLicensedReleaseAsync(
        PlatformApiFactory factory,
        HttpClient client,
        ECDsa deviceKey,
        bool activeSubscription = true)
    {
        var subject = client.DefaultRequestHeaders.GetValues("X-Dev-Subject").Single();
        var bootstrap = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { displayName = "DAXQ license test" });
        bootstrap.EnsureSuccessStatusCode();
        var accountId = await factory.GetAccountIdAsync(subject);
        var deviceId = Guid.NewGuid();
        var devicePublicKey = deviceKey.ExportSubjectPublicKeyInfo();
        var registration = await client.PostAsJsonAsync(
            "/api/v1/devices",
            new
            {
                deviceId,
                displayName = "DAXQ workstation",
                publicKeySpki = Encode(devicePublicKey),
                fingerprintSha256 = Sha256Hex(devicePublicKey),
            });
        registration.EnsureSuccessStatusCode();

        var now = DateTimeOffset.UtcNow;
        var catalogItemId = Guid.NewGuid();
        var releaseId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var orderId = Guid.NewGuid();
        var grantId = Guid.NewGuid();
        var contentKeyId = $"ck_{Guid.NewGuid():N}";
        var contentKey = RandomNumberGenerator.GetBytes(32);
        var cipherSha256 = Sha256Hex(RandomNumberGenerator.GetBytes(64));
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var provisioner = scope.ServiceProvider.GetRequiredService<IContentKeyProvisioningProvider>();
        database.CatalogItems.Add(new CatalogItem
        {
            Id = catalogItemId,
            PublisherAccountId = accountId,
            Slug = $"daxq-{Guid.NewGuid():N}",
            Title = "Protected strategy",
            Description = "Protected strategy licensing fixture.",
            Version = "1.0.0",
            PriceInCents = 3_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Currency = "USD",
            Status = CatalogItemStatus.Published,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.StrategyReleases.Add(new MarketplaceStrategyRelease
        {
            Id = releaseId,
            CatalogItemId = catalogItemId,
            SubmissionId = Guid.NewGuid(),
            Version = "1.0.0",
            Status = MarketplaceReleaseStatus.Approved,
            ArtifactBlobUri = "https://artifacts.example.test/strategy.daxq",
            ExecutionClass = "restricted_only",
            VmAbiVersion = 1,
            ContentKeyId = contentKeyId,
            CipherSha256 = cipherSha256,
            DiversifySeedId = "seed-test-v1",
            DiversificationSeedSha256 = Sha256Hex(RandomNumberGenerator.GetBytes(32)),
            SourceSha256 = Sha256Hex(RandomNumberGenerator.GetBytes(32)),
            ArtifactSha256 = cipherSha256,
            ParityStatisticsJson = "{}",
            ParityStatisticsSha256 = Sha256Hex("{}"u8),
            ListingMetricsJson = "{}",
            ListingMetricsSha256 = Sha256Hex("{}"u8),
            ScanEvidenceJson = "{}",
            SbomSha256 = Sha256Hex("{}"u8),
            CreatedAt = now,
            ApprovedAt = now,
        });
        database.Orders.Add(new MarketplaceOrder
        {
            Id = orderId,
            BuyerAccountId = accountId,
            CatalogItemId = catalogItemId,
            ReleaseId = releaseId,
            AmountInCents = 3_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Currency = "USD",
            CommercialPolicyVersion = "test-v1",
            Status = OrderStatus.Paid,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.EntitlementGrants.Add(new EntitlementGrant
        {
            Id = grantId,
            AccountId = accountId,
            CatalogItemId = catalogItemId,
            OrderId = orderId,
            Type = EntitlementGrantType.MarketplaceLicense,
            Status = activeSubscription
                ? EntitlementGrantStatus.Active
                : EntitlementGrantStatus.Expired,
            ValidFrom = now.AddMinutes(-1),
            ValidUntil = activeSubscription ? now.AddDays(30) : now.AddMinutes(-1),
            UpdatedAt = now,
        });
        database.MarketplaceLicenses.Add(new MarketplaceLicense
        {
            Id = licenseId,
            AccountId = accountId,
            ReleaseId = releaseId,
            GrantId = grantId,
            Status = MarketplaceLicenseStatus.Active,
            ValidFrom = now.AddMinutes(-1),
            ValidUntil = activeSubscription ? now.AddDays(30) : now.AddMinutes(-1),
        });
        database.ContentKeys.Add(new MarketplaceContentKey
        {
            ContentKeyId = contentKeyId,
            ReleaseId = releaseId,
            KmsWrappedKey = await provisioner.WrapContentKeyAsync(
                SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
                contentKey,
                CancellationToken.None),
            Algorithm = SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
            CreatedAt = now,
        });
        await database.SaveChangesAsync();
        return new LicensingFixture(
            accountId,
            deviceId,
            licenseId,
            releaseId,
            contentKeyId,
            contentKey,
            cipherSha256);
    }

    private static async Task<long> AddRevocationAsync(
        PlatformApiFactory factory,
        string targetType,
        string targetId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var revocation = new EntitlementRevocation
        {
            TargetType = targetType,
            TargetId = targetId,
            Reason = "Test revocation",
            IssuedAt = DateTimeOffset.UtcNow,
        };
        database.Revocations.Add(revocation);
        await database.SaveChangesAsync();
        return revocation.Sequence;
    }

    private static HttpClient CreateAuthenticatedClient(PlatformApiFactory factory)
    {
        var subject = $"daxq-license-{Guid.NewGuid():N}";
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Dev-Subject", subject);
        client.DefaultRequestHeaders.Add("X-Dev-Email", $"{subject}@example.test");
        return client;
    }

    private static async Task<HttpResponseMessage> PostJsonAsync<T>(
        HttpClient client,
        string path,
        T value,
        string idempotencyKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(value),
        };
        request.Headers.Add("Idempotency-Key", idempotencyKey);
        return await client.SendAsync(request);
    }

    private static string Sha256Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    private static string Encode(ReadOnlySpan<byte> value) =>
        MarketplaceCryptographyEncoding.Encode(value);

    private static byte[] Decode(string value) =>
        MarketplaceCryptographyEncoding.Decode(value);

    private sealed record LicensingFixture(
        Guid AccountId,
        Guid DeviceId,
        Guid LicenseId,
        Guid ReleaseId,
        string ContentKeyId,
        byte[] ContentKey,
        string CipherSha256);
}
