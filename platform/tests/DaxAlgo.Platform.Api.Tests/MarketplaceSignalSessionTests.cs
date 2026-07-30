using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Formats.Tar;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Marketplace;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class MarketplaceSignalSessionTests
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task SessionStreamsSignalAndRefundClosesImmediatelyAndRefusesReconnect()
    {
        var runner = new DelayedCancellationSignalRunner();
        await using var factory = CreateFactory(runner);
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedAsync(factory, client, deviceKey, MarketplaceExecutionClasses.ServerSignal);
        var opened = await OpenAsync(client, deviceKey, fixture, "signal-open-revoke");
        var configured = factory.Services.GetRequiredService<SignalExecutionOptions>();
        Assert.NotEmpty(MarketplaceCryptographyEncoding.Decode(configured.ReleaseVerificationKeySpki));

        var webSockets = factory.Server.CreateWebSocketClient();
        webSockets.ConfigureRequest = request =>
            request.Headers.Authorization = $"Bearer {opened.SessionToken}";
        using var socket = await webSockets.ConnectAsync(
            new Uri(opened.WebSocketUrl),
            CancellationToken.None);
        using var firstFrame = await ReceiveJsonAsync(socket, TimeSpan.FromSeconds(3));
        Assert.Equal("signal", firstFrame.RootElement.GetProperty("type").GetString());
        Assert.Equal("long", firstFrame.RootElement.GetProperty("kind").GetString());
        Assert.Equal(0.75d, firstFrame.RootElement.GetProperty("strength").GetDouble());

        var revokedAt = DateTimeOffset.UtcNow;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var grants = scope.ServiceProvider.GetRequiredService<MarketplaceGrantService>();
            await grants.RevokeAsync(
                fixture.OrderId,
                OrderStatus.Refunded,
                "test refund",
                CancellationToken.None);
        }

        using var closeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var close = await socket.ReceiveAsync(new byte[1024], closeTimeout.Token);
        Assert.Equal(WebSocketMessageType.Close, close.MessageType);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, close.CloseStatus);
        Assert.InRange(DateTimeOffset.UtcNow - revokedAt, TimeSpan.Zero, TimeSpan.FromSeconds(1.5));
        Assert.False(runner.CleanupCompleted.Task.IsCompleted);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var stored = await database.SignalSessions.AsNoTracking().SingleAsync(
                item => item.Id == opened.SessionId);
            Assert.NotNull(stored.RevokedAt);
            Assert.NotNull(stored.EndedAt);
        }

        var reconnect = factory.Server.CreateWebSocketClient();
        reconnect.ConfigureRequest = request =>
            request.Headers.Authorization = $"Bearer {opened.SessionToken}";
        using var reconnectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await Assert.ThrowsAnyAsync<Exception>(() => reconnect.ConnectAsync(
            new Uri(opened.WebSocketUrl),
            reconnectTimeout.Token));
    }

    [Fact]
    public async Task SessionOpenRequiresServerSignalEntitlementDeviceAndValidProof()
    {
        await using var localFactory = CreateFactory(new WaitingSignalRunner());
        using var localClient = CreateAuthenticatedClient(localFactory);
        using var localKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var local = await SeedAsync(
            localFactory,
            localClient,
            localKey,
            MarketplaceExecutionClasses.RestrictedOnly);
        var localResponse = await CreateOpenRequestAsync(
            localClient,
            localKey,
            local,
            "local-class-denied");
        Assert.Equal(HttpStatusCode.Forbidden, localResponse.StatusCode);

        await using var inactiveFactory = CreateFactory(new WaitingSignalRunner());
        using var inactiveClient = CreateAuthenticatedClient(inactiveFactory);
        using var inactiveKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var inactive = await SeedAsync(
            inactiveFactory,
            inactiveClient,
            inactiveKey,
            MarketplaceExecutionClasses.ServerSignal,
            active: false);
        var inactiveResponse = await CreateOpenRequestAsync(
            inactiveClient,
            inactiveKey,
            inactive,
            "inactive-denied");
        Assert.Equal(HttpStatusCode.Forbidden, inactiveResponse.StatusCode);

        await using var proofFactory = CreateFactory(new WaitingSignalRunner());
        using var proofClient = CreateAuthenticatedClient(proofFactory);
        using var proofKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proofFixture = await SeedAsync(
            proofFactory,
            proofClient,
            proofKey,
            MarketplaceExecutionClasses.ServerSignal);
        var invalidProof = await CreateOpenRequestAsync(
            proofClient,
            proofKey,
            proofFixture,
            "bad-proof",
            invalidSignature: true);
        Assert.Equal(HttpStatusCode.Forbidden, invalidProof.StatusCode);

        var nonce = RandomNumberGenerator.GetBytes(32);
        var binding = Sha256Hex(nonce);
        const string revokedDeviceKey = "revoked-device";
        var challenge = await IssueChallengeAsync(
            proofClient,
            proofFixture,
            binding,
            revokedDeviceKey);
        await using (var scope = proofFactory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var device = await database.Devices.SingleAsync(
                item => item.AccountId == proofFixture.AccountId
                    && item.DeviceId == proofFixture.DeviceId);
            device.RevokedAt = DateTimeOffset.UtcNow;
            await database.SaveChangesAsync();
        }

        var signature = SignProof(
            proofKey,
            challenge,
            proofFixture,
            binding,
            revokedDeviceKey);
        var revokedDevice = await PostJsonAsync(
            proofClient,
            $"/v1/marketplace/licenses/{proofFixture.LicenseId:D}/signal-sessions",
            new SignalSessionOpenRequest(
                proofFixture.ReleaseId,
                proofFixture.DeviceId,
                challenge.ChallengeId,
                Encode(nonce),
                signature),
            revokedDeviceKey);
        Assert.Equal(HttpStatusCode.Conflict, revokedDevice.StatusCode);
    }

    [Fact]
    public async Task UnavailableSandboxRefusesSessionBeforeIssuance()
    {
        await using var factory = CreateFactory(new DisabledSignalSandboxRunner());
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedAsync(
            factory,
            client,
            deviceKey,
            MarketplaceExecutionClasses.ServerSignal);

        var response = await CreateOpenRequestAsync(
            client,
            deviceKey,
            fixture,
            "sandbox-unavailable");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        Assert.Empty(await database.SignalSessions.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task RefundMarksAnUnconnectedSessionRevokedAndEnded()
    {
        await using var factory = CreateFactory(new WaitingSignalRunner());
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedAsync(
            factory,
            client,
            deviceKey,
            MarketplaceExecutionClasses.ServerSignal);
        var opened = await OpenAsync(client, deviceKey, fixture, "unconnected-revoke");

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var grants = scope.ServiceProvider.GetRequiredService<MarketplaceGrantService>();
            await grants.RevokeAsync(
                fixture.OrderId,
                OrderStatus.Refunded,
                "unconnected refund",
                CancellationToken.None);
        }

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var session = await database.SignalSessions.AsNoTracking().SingleAsync(
                item => item.Id == opened.SessionId);
            Assert.NotNull(session.RevokedAt);
            Assert.NotNull(session.EndedAt);
        }
    }

    [Theory]
    [InlineData("http://localhost")]
    [InlineData("ws://signals.example.test")]
    [InlineData("wss://signals.example.test")]
    public async Task DevelopmentSignalEndpointRejectsUnsafeConfiguredUris(string endpoint)
    {
        await using var factory = CreateFactory(new WaitingSignalRunner(), endpoint);
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedAsync(
            factory,
            client,
            deviceKey,
            MarketplaceExecutionClasses.ServerSignal);

        var response = await CreateOpenRequestAsync(
            client,
            deviceKey,
            fixture,
            $"unsafe-signal-endpoint-{Guid.NewGuid():N}");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task SignalFloodCannotStarveCrossInstanceAuthorizationPolling()
    {
        await using var factory = CreateFactory(new FloodSignalRunner());
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedAsync(
            factory,
            client,
            deviceKey,
            MarketplaceExecutionClasses.ServerSignal);
        var opened = await OpenAsync(client, deviceKey, fixture, "flood-poll-revoke");
        var webSockets = factory.Server.CreateWebSocketClient();
        webSockets.ConfigureRequest = request =>
            request.Headers.Authorization = $"Bearer {opened.SessionToken}";
        using var socket = await webSockets.ConnectAsync(
            new Uri(opened.WebSocketUrl),
            CancellationToken.None);
        using var first = await ReceiveJsonAsync(socket, TimeSpan.FromSeconds(3));
        Assert.Equal("signal", first.RootElement.GetProperty("type").GetString());

        var revokedAt = DateTimeOffset.UtcNow;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var grant = await database.EntitlementGrants.SingleAsync(
                item => item.OrderId == fixture.OrderId);
            var license = await database.MarketplaceLicenses.SingleAsync(
                item => item.Id == fixture.LicenseId);
            grant.Status = EntitlementGrantStatus.Revoked;
            grant.RevokedAt = revokedAt;
            license.Status = MarketplaceLicenseStatus.Revoked;
            license.RevokedAt = revokedAt;
            await database.SaveChangesAsync();
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        WebSocketReceiveResult received;
        do
        {
            received = await socket.ReceiveAsync(new byte[4096], timeout.Token);
        }
        while (received.MessageType != WebSocketMessageType.Close);

        Assert.Equal(WebSocketCloseStatus.PolicyViolation, received.CloseStatus);
        Assert.InRange(DateTimeOffset.UtcNow - revokedAt, TimeSpan.Zero, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task ServerSignalReleaseCannotUseLocalContentKeyDelivery()
    {
        await using var factory = CreateFactory(new WaitingSignalRunner());
        using var client = CreateAuthenticatedClient(factory);
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = await SeedAsync(
            factory,
            client,
            deviceKey,
            MarketplaceExecutionClasses.ServerSignal);
        using var sessionKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var response = await PostJsonAsync(
            client,
            $"/v1/marketplace/licenses/{fixture.LicenseId:D}/content-keys",
            new ContentKeyReleaseRequest(
                fixture.ReleaseId,
                fixture.DeviceId,
                Guid.NewGuid(),
                Encode(sessionKey.ExportSubjectPublicKeyInfo()),
                Encode(RandomNumberGenerator.GetBytes(64))),
            "tier3-no-local-key");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        using var download = new HttpRequestMessage(
            HttpMethod.Get,
            $"/v1/marketplace/releases/{fixture.ReleaseId:D}/download-grant"
            + $"?license_id={fixture.LicenseId:D}&device_id={fixture.DeviceId:D}"
            + $"&challenge_id={Guid.NewGuid():D}"
            + $"&device_signature={Uri.EscapeDataString(Encode(RandomNumberGenerator.GetBytes(64)))}");
        download.Headers.Add("Idempotency-Key", "tier3-no-download");
        var downloadResponse = await client.SendAsync(download);
        Assert.Equal(HttpStatusCode.Forbidden, downloadResponse.StatusCode);
    }

    [Fact]
    public void DockerRunnerHasNoNetworkMountsOrHostPrivilegesAndHasAllResourceBounds()
    {
        var probeCount = 0;
        using var runner = new DockerSignalSandboxRunner(
            new SignalExecutionOptions
            {
                Provider = "Docker",
                Image = "registry.example/daxalgo-signal@sha256:"
                    + new string('a', 64),
                Entrypoint = "/opt/daxalgo/bin/daxalgo-signal-worker",
                WallClockSeconds = 60,
                MemoryMb = 512,
                Cpus = 1,
                PidsLimit = 64,
                DiskMb = 128,
                MaximumOutputBytes = 1024 * 1024,
                MaximumConcurrentSessions = 2,
            },
            () =>
            {
                probeCount++;
                return false;
            });

        Assert.False(runner.IsAvailable);
        Assert.False(runner.IsAvailable);
        Assert.Equal(1, probeCount);

        var arguments = runner.BuildCreateArguments("test-container");
        Assert.Contains("--network", arguments);
        Assert.Equal("none", arguments[arguments.ToList().IndexOf("--network") + 1]);
        Assert.Contains("--read-only", arguments);
        Assert.Contains("--cap-drop", arguments);
        Assert.Contains("ALL", arguments);
        Assert.Contains("no-new-privileges", arguments);
        Assert.Contains("65534:65534", arguments);
        Assert.Contains(arguments, item => item.StartsWith("--memory=", StringComparison.Ordinal));
        Assert.Contains(arguments, item => item.StartsWith("--cpus=", StringComparison.Ordinal));
        Assert.Contains(arguments, item => item.StartsWith("--pids-limit=", StringComparison.Ordinal));
        Assert.DoesNotContain("--mount", arguments);
        Assert.DoesNotContain("--volume", arguments);
        Assert.DoesNotContain("-v", arguments);
        Assert.DoesNotContain("host", arguments);
    }

    [Fact]
    public async Task DockerInputsStreamToTmpfsWithPrivateOwnershipAndNoHostPath()
    {
        var contentKey = RandomNumberGenerator.GetBytes(32);
        var request = new SignalSandboxRequest(
            Guid.NewGuid(),
            "package"u8.ToArray(),
            contentKey,
            "frames"u8.ToArray(),
            "test-key",
            "spki"u8.ToArray());
        using var archive = new MemoryStream();
        await DockerSignalSandboxRunner.WriteInputsArchiveAsync(
            archive,
            request,
            leaveOpen: true,
            CancellationToken.None);
        archive.Position = 0;
        using var reader = new TarReader(archive, leaveOpen: true);
        var entries = new List<TarEntry>();
        while (reader.GetNextEntry(copyData: true) is { } entry)
        {
            entries.Add(entry);
        }

        var directory = Assert.Single(entries, item => item.Name == "input/");
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            directory.Mode);
        Assert.Equal(65534, directory.Uid);
        Assert.Equal(65534, directory.Gid);
        foreach (var file in entries.Where(item => item.EntryType == TarEntryType.RegularFile))
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, file.Mode);
            Assert.Equal(65534, file.Uid);
            Assert.Equal(65534, file.Gid);
        }

        var keyEntry = Assert.Single(entries, item => item.Name == "input/content-key.bin");
        using var keyBytes = new MemoryStream();
        await keyEntry.DataStream!.CopyToAsync(keyBytes);
        Assert.Equal(contentKey, keyBytes.ToArray());
        var copyArguments = DockerSignalSandboxRunner.BuildCopyArguments("test-container");
        Assert.Equal("-", copyArguments[2]);
        Assert.DoesNotContain(copyArguments, item => Path.IsPathRooted(item));
        CryptographicOperations.ZeroMemory(contentKey);
    }

    private static PlatformApiFactory CreateFactory(
        ISignalSandboxRunner runner,
        string publicWebSocketBaseUri = "ws://localhost") =>
        new(
            services =>
            {
                services.RemoveAll<ISignalSandboxRunner>();
                services.AddSingleton(runner);
                services.RemoveAll<SignalExecutionOptions>();
                services.AddSingleton(new SignalExecutionOptions
                {
                    Provider = "Disabled",
                    PublicWebSocketBaseUri = publicWebSocketBaseUri,
                    ReleaseSigningKeyId = "test-release-key",
                    ReleaseVerificationKeySpki = Encode(RandomNumberGenerator.GetBytes(91)),
                    AuthorizationPollMilliseconds = 100,
                    HeartbeatIntervalSeconds = 1,
                });
            });

    private static async Task<SignalSessionOpenResponse> OpenAsync(
        HttpClient client,
        ECDsa deviceKey,
        SignalFixture fixture,
        string idempotencyKey)
    {
        var response = await CreateOpenRequestAsync(
            client,
            deviceKey,
            fixture,
            idempotencyKey);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SignalSessionOpenResponse>())!;
    }

    private static async Task<HttpResponseMessage> CreateOpenRequestAsync(
        HttpClient client,
        ECDsa deviceKey,
        SignalFixture fixture,
        string idempotencyKey,
        bool invalidSignature = false)
    {
        var nonce = RandomNumberGenerator.GetBytes(32);
        var binding = Sha256Hex(nonce);
        var challenge = await IssueChallengeAsync(client, fixture, binding, idempotencyKey);
        var signature = invalidSignature
            ? Encode(RandomNumberGenerator.GetBytes(64))
            : SignProof(deviceKey, challenge, fixture, binding, idempotencyKey);
        return await PostJsonAsync(
            client,
            $"/v1/marketplace/licenses/{fixture.LicenseId:D}/signal-sessions",
            new SignalSessionOpenRequest(
                fixture.ReleaseId,
                fixture.DeviceId,
                challenge.ChallengeId,
                Encode(nonce),
                signature),
            idempotencyKey);
    }

    private static async Task<DeviceProofChallengeResponse> IssueChallengeAsync(
        HttpClient client,
        SignalFixture fixture,
        string binding,
        string idempotencyKey)
    {
        var response = await PostJsonAsync(
            client,
            "/v1/devices/challenges",
            new DeviceProofChallengeRequest(
                fixture.DeviceId,
                fixture.LicenseId,
                fixture.ReleaseId,
                MarketplaceLicensingService.SignalSessionOperation,
                binding),
            idempotencyKey);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<DeviceProofChallengeResponse>())!;
    }

    private static string SignProof(
        ECDsa deviceKey,
        DeviceProofChallengeResponse challenge,
        SignalFixture fixture,
        string binding,
        string idempotencyKey)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new DeviceProofPayload(
                1,
                MarketplaceLicensingService.SignalSessionOperation,
                challenge.ChallengeId,
                challenge.Nonce,
                fixture.LicenseId,
                fixture.ReleaseId,
                fixture.DeviceId,
                binding,
                idempotencyKey),
            SerializerOptions);
        return Encode(deviceKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private static async Task<SignalFixture> SeedAsync(
        PlatformApiFactory factory,
        HttpClient client,
        ECDsa deviceKey,
        string executionClass,
        bool active = true)
    {
        var bootstrap = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { displayName = "Signal buyer" });
        bootstrap.EnsureSuccessStatusCode();
        var subject = client.DefaultRequestHeaders.GetValues("X-Dev-Subject").Single();
        var accountId = await factory.GetAccountIdAsync(subject);
        var deviceId = Guid.NewGuid();
        var devicePublicKey = deviceKey.ExportSubjectPublicKeyInfo();
        var registration = await client.PostAsJsonAsync(
            "/api/v1/devices",
            new
            {
                deviceId,
                displayName = "Signal workstation",
                publicKeySpki = Encode(devicePublicKey),
                fingerprintSha256 = Sha256Hex(devicePublicKey),
            });
        registration.EnsureSuccessStatusCode();

        var now = DateTimeOffset.UtcNow;
        var catalogId = Guid.NewGuid();
        var submissionId = Guid.NewGuid();
        var releaseId = Guid.NewGuid();
        var orderId = Guid.NewGuid();
        var grantId = Guid.NewGuid();
        var licenseId = Guid.NewGuid();
        var contentKeyId = $"ck_{Guid.NewGuid():N}";
        var contentKey = RandomNumberGenerator.GetBytes(32);
        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var artifacts = scope.ServiceProvider.GetRequiredService<IMarketplaceArtifactStore>();
        var provisioner = scope.ServiceProvider.GetRequiredService<IContentKeyProvisioningProvider>();
        var package = await artifacts.PutQuarantineAsync(
            "artifact",
            "test-daxq-package"u8.ToArray(),
            CancellationToken.None);
        var frames = await artifacts.PutQuarantineAsync(
            "reference",
            "{\"bars\":[],\"parameters\":[],\"callbacks\":[],\"dataRequirements\":[],\"launchSeed\":1}"u8.ToArray(),
            CancellationToken.None);
        database.CatalogItems.Add(new CatalogItem
        {
            Id = catalogId,
            PublisherAccountId = accountId,
            Slug = $"signals-{Guid.NewGuid():N}",
            Title = "Tier-3 signals",
            Description = "Server-only signal execution fixture.",
            Version = "1.0.0",
            PriceInCents = 5_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Status = CatalogItemStatus.Published,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.Submissions.Add(new MarketplaceSubmission
        {
            Id = submissionId,
            PublisherAccountId = accountId,
            Slug = $"signals-{Guid.NewGuid():N}",
            Title = "Tier-3 signals",
            Description = "Server-only signal execution fixture.",
            Version = "1.0.0",
            PriceInCents = 5_000,
            PriceMode = MarketplacePriceMode.OneTime,
            SourceSha256 = Sha256Hex("source"u8),
            SourceQuarantineUri = "marketplace-quarantine://source/test",
            ReferenceDatasetSha256 = frames.Sha256,
            ReferenceDatasetQuarantineUri = frames.Uri,
            RequestedExecutionClass = executionClass,
            CatalogItemId = catalogId,
            ReleaseId = releaseId,
            Status = SubmissionStatus.Approved,
            SourceReview = MarketplaceHumanReviewState.Passed,
            DeclaredBehaviorReview = MarketplaceHumanReviewState.Passed,
            DiffReview = MarketplaceHumanReviewState.Passed,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.StrategyReleases.Add(new MarketplaceStrategyRelease
        {
            Id = releaseId,
            CatalogItemId = catalogId,
            SubmissionId = submissionId,
            Version = "1.0.0",
            Status = MarketplaceReleaseStatus.Approved,
            ArtifactBlobUri = package.Uri,
            ExecutionClass = executionClass,
            VmAbiVersion = 3,
            ContentKeyId = contentKeyId,
            CipherSha256 = Sha256Hex("cipher"u8),
            DiversificationSeedSha256 = Sha256Hex("seed"u8),
            SourceSha256 = Sha256Hex("source"u8),
            ArtifactSha256 = package.Sha256,
            ParityStatisticsSha256 = Sha256Hex("{}"u8),
            ListingMetricsSha256 = Sha256Hex("{}"u8),
            SbomSha256 = Sha256Hex("{}"u8),
            CreatedAt = now,
            ApprovedAt = now,
        });
        database.Orders.Add(new MarketplaceOrder
        {
            Id = orderId,
            BuyerAccountId = accountId,
            CatalogItemId = catalogId,
            ReleaseId = releaseId,
            AmountInCents = 5_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Status = OrderStatus.Paid,
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.EntitlementGrants.Add(new EntitlementGrant
        {
            Id = grantId,
            AccountId = accountId,
            CatalogItemId = catalogId,
            OrderId = orderId,
            Type = EntitlementGrantType.MarketplaceLicense,
            Status = active ? EntitlementGrantStatus.Active : EntitlementGrantStatus.Expired,
            ValidFrom = now.AddMinutes(-1),
            ValidUntil = active ? now.AddDays(30) : now.AddMinutes(-1),
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
            ValidUntil = active ? now.AddDays(30) : now.AddMinutes(-1),
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
        CryptographicOperations.ZeroMemory(contentKey);
        return new SignalFixture(
            accountId,
            deviceId,
            licenseId,
            releaseId,
            orderId);
    }

    private static HttpClient CreateAuthenticatedClient(PlatformApiFactory factory)
    {
        var subject = $"signal-{Guid.NewGuid():N}";
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

    private static async Task<JsonDocument> ReceiveJsonAsync(
        WebSocket socket,
        TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        var buffer = new byte[4096];
        var received = await socket.ReceiveAsync(buffer, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        Assert.True(received.EndOfMessage);
        return JsonDocument.Parse(buffer.AsMemory(0, received.Count));
    }

    private static string Sha256Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private static string Encode(ReadOnlySpan<byte> value) =>
        MarketplaceCryptographyEncoding.Encode(value);

    private sealed record SignalFixture(
        Guid AccountId,
        Guid DeviceId,
        Guid LicenseId,
        Guid ReleaseId,
        Guid OrderId);

    private sealed class WaitingSignalRunner : ISignalSandboxRunner
    {
        public bool IsAvailable => true;

        public async IAsyncEnumerable<SignalSandboxSignal> RunAsync(
            SignalSandboxRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            yield return new SignalSandboxSignal("long", 0.75d, 42);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    private sealed class DelayedCancellationSignalRunner : ISignalSandboxRunner
    {
        public bool IsAvailable => true;

        public TaskCompletionSource CleanupCompleted { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public async IAsyncEnumerable<SignalSandboxSignal> RunAsync(
            SignalSandboxRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            yield return new SignalSandboxSignal("long", 0.75d, 42);
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), CancellationToken.None);
                CleanupCompleted.TrySetResult();
            }
        }
    }

    private sealed class FloodSignalRunner : ISignalSandboxRunner
    {
        public bool IsAvailable => true;

        public async IAsyncEnumerable<SignalSandboxSignal> RunAsync(
            SignalSandboxRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return new SignalSandboxSignal("long", 0.5d, 1);
                await Task.Yield();
            }
        }
    }
}
