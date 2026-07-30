using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Billing;
using DaxAlgo.Platform.Features.Marketplace;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class MarketplaceSellingFlowTests
{
    private static readonly string[] DeclaredCapabilities = ["bars", "signals"];
    private static readonly string[] ListingMediaUrls =
        ["https://media.example.test/strategy.png"];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    [Fact]
    public async Task SubmissionPipelineAcceptsAndBlocksBannedSurfaceAndParityDivergence()
    {
        var worker = new DeterministicMarketplaceBuildWorker();
        await using var factory = CreateFactory(worker);
        using var client = CreateAuthenticatedClient(factory, "submission-publisher");
        _ = await BootstrapAsync(factory, client, "Submission Publisher");

        var accepted = await CreateSubmissionAsync(
            client,
            "public sealed class AcceptedStrategy { }",
            priceInCents: 0);
        var acceptedResponse = await client.PostAsync(
            $"/api/v1/submissions/{accepted.Id:D}/submit",
            content: null);
        acceptedResponse.EnsureSuccessStatusCode();
        Assert.Equal(
            SubmissionStatus.AwaitingReview,
            (await acceptedResponse.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions))!.Status);

        var banned = await CreateSubmissionAsync(
            client,
            "using System.Net; public sealed class BannedStrategy { }",
            priceInCents: 0);
        var bannedResponse = await client.PostAsync(
            $"/api/v1/submissions/{banned.Id:D}/submit",
            content: null);
        bannedResponse.EnsureSuccessStatusCode();
        var bannedSubmission = await bannedResponse.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        Assert.Equal(SubmissionStatus.Blocked, bannedSubmission!.Status);
        Assert.Contains("CAPABILITY_BLOCK", bannedSubmission.BuildDiagnosticsJson, StringComparison.Ordinal);

        var divergent = await CreateSubmissionAsync(
            client,
            "public sealed class ParityDivergenceStrategy { }",
            priceInCents: 0);
        var divergentResponse = await client.PostAsync(
            $"/api/v1/submissions/{divergent.Id:D}/submit",
            content: null);
        divergentResponse.EnsureSuccessStatusCode();
        var divergentSubmission = await divergentResponse.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        Assert.Equal(SubmissionStatus.Blocked, divergentSubmission!.Status);
        Assert.Contains("DAXQ3007", divergentSubmission.BuildDiagnosticsJson, StringComparison.Ordinal);
        Assert.Equal(2, worker.InvocationCount);
    }

    [Fact]
    public async Task ServerSignalIsExplicitSubmissionOptInWhileBuildEvidenceRemainsRestricted()
    {
        var worker = new DeterministicMarketplaceBuildWorker();
        await using var factory = CreateFactory(worker);
        using var client = CreateAuthenticatedClient(
            factory,
            "server-signal-publisher",
            platformAdmin: true);
        _ = await BootstrapAsync(factory, client, "Server Signal Publisher");
        var submission = await CreateSubmissionAsync(
            client,
            "public sealed class ServerSignalStrategy { }",
            priceInCents: 0,
            executionClass: MarketplaceExecutionClasses.ServerSignal);
        Assert.Equal(MarketplaceExecutionClasses.ServerSignal, submission.RequestedExecutionClass);

        (await client.PostAsync($"/api/v1/submissions/{submission.Id:D}/submit", null))
            .EnsureSuccessStatusCode();
        var approval = await client.PostAsJsonAsync(
            $"/api/v1/admin/submissions/{submission.Id:D}/decision",
            new
            {
                approve = true,
                sourceReviewed = true,
                declaredBehaviorReviewed = true,
                diffReviewed = true,
            });
        approval.EnsureSuccessStatusCode();
        var approved = await approval.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        var storedSubmission = await database.Submissions.AsNoTracking().SingleAsync(
            item => item.Id == submission.Id);
        var release = await database.StrategyReleases.AsNoTracking().SingleAsync(
            item => item.Id == approved!.ReleaseId);
        Assert.Equal(MarketplaceExecutionClasses.ServerSignal, storedSubmission.RequestedExecutionClass);
        Assert.Equal(MarketplaceExecutionClasses.ServerSignal, release.ExecutionClass);
        Assert.Equal(
            MarketplaceSubmissionPipeline.RestrictedExecutionClass,
            worker.LastExecutionClass);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BasicAndProfessionalAccountsCanPublishReviewedReleases(bool professional)
    {
        var worker = new DeterministicMarketplaceBuildWorker();
        await using var factory = CreateFactory(worker);
        var subject = professional ? "publish-professional" : "publish-basic";
        using var client = CreateAuthenticatedClient(factory, subject, platformAdmin: true);
        var accountId = await BootstrapAsync(factory, client, "Edition Publisher");
        if (professional)
        {
            await GrantProfessionalAsync(factory, accountId);
        }

        var submission = await CreateSubmissionAsync(
            client,
            "public sealed class EditionStrategy { }",
            priceInCents: 0);
        var built = await client.PostAsync(
            $"/api/v1/submissions/{submission.Id:D}/submit",
            content: null);
        built.EnsureSuccessStatusCode();
        var builtSubmission = await built.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        Assert.Equal(SubmissionStatus.AwaitingReview, builtSubmission!.Status);

        var reviewPacket = await client.GetFromJsonAsync<SubmissionReviewPacketResponse>(
            $"/api/v1/admin/submissions/{submission.Id:D}",
            JsonOptions);
        Assert.NotNull(reviewPacket);
        Assert.Equal("public sealed class EditionStrategy { }", reviewPacket.SourceCode);
        Assert.Null(reviewPacket.PreviousApprovedSourceCode);
        Assert.Equal(DeclaredCapabilities, reviewPacket.DeclaredCapabilities);
        Assert.StartsWith(
            "marketplace-quarantine://sbom/",
            reviewPacket.SbomQuarantineUri,
            StringComparison.Ordinal);
        Assert.True(reviewPacket.ScanEvidence.HasValue);
        Assert.True(
            reviewPacket.ScanEvidence.Value
                .GetProperty(nameof(MarketplaceScanEvidence.CapabilityAnalyzerPassed))
                .GetBoolean());
        Assert.Equal(
            DeclaredCapabilities,
            reviewPacket.ScanEvidence.Value
                .GetProperty(nameof(MarketplaceScanEvidence.ImplementedCapabilities))
                .EnumerateArray()
                .Select(value => value.GetString())
                .ToArray());
        Assert.True(reviewPacket.SourceDiffSummary.HasValue);
        Assert.Equal(
            "first_release",
            reviewPacket.SourceDiffSummary.Value.GetProperty("kind").GetString());
        Assert.Equal(MarketplaceHumanReviewState.Pending, reviewPacket.SourceReview);
        Assert.Equal(MarketplaceHumanReviewState.Pending, reviewPacket.DeclaredBehaviorReview);
        Assert.Equal(MarketplaceHumanReviewState.Pending, reviewPacket.DiffReview);

        var approval = await client.PostAsJsonAsync(
            $"/api/v1/admin/submissions/{submission.Id:D}/decision",
            new
            {
                approve = true,
                sourceReviewed = true,
                declaredBehaviorReviewed = true,
                diffReviewed = true,
                notes = "Reviewed test release.",
            });
        approval.EnsureSuccessStatusCode();
        var approved = await approval.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        Assert.Equal(SubmissionStatus.Approved, approved!.Status);

        var edited = await client.PutAsJsonAsync(
            $"/api/v1/publisher/listings/{approved.CatalogItemId:D}",
            new
            {
                title = "Edited Marketplace Strategy",
                description = "Editable seller copy for the approved marketplace strategy.",
                templateCopyJson = "{\"headline\":\"Seller edited headline\"}",
                mediaUrls = ListingMediaUrls,
                priceInCents = 0,
                priceMode = "OneTime",
            });
        edited.EnsureSuccessStatusCode();
        var editedListing = await edited.Content.ReadFromJsonAsync<ListingResponse>(JsonOptions);
        Assert.Equal("Seller edited headline", editedListing!.TemplateCopy.GetProperty("headline").GetString());
        Assert.Equal("https://media.example.test/strategy.png", Assert.Single(editedListing.MediaUrls));

        var published = await client.PostAsync(
            $"/api/v1/publisher/listings/{approved.CatalogItemId:D}/publish",
            content: null);
        published.EnsureSuccessStatusCode();
        Assert.Equal(
            CatalogItemStatus.Published,
            (await published.Content.ReadFromJsonAsync<ListingResponse>(JsonOptions))!.Status);

        var catalog = await client.GetFromJsonAsync<CatalogItemResponse[]>("/api/v1/catalog", JsonOptions);
        var listing = Assert.Single(catalog!, item => item.Id == approved.CatalogItemId);
        Assert.Equal(approved.ReleaseId, listing.ReleaseId);
        Assert.Equal("Edited Marketplace Strategy", listing.Title);
        Assert.Equal("Seller edited headline", listing.TemplateCopy.GetProperty("headline").GetString());
        Assert.Equal("restricted_only", listing.ExecutionClass);
        Assert.NotNull(listing.AttestationSha256);
        Assert.Equal(
            MarketplaceSubmissionPipeline.ListingMetricsSchemaVersion,
            listing.ListingMetrics.GetProperty("schemaVersion").GetString());
    }

    [Fact]
    public async Task SubsequentReleaseReviewIncludesPreviousApprovedSourceAndCanPromote()
    {
        var worker = new DeterministicMarketplaceBuildWorker();
        await using var factory = CreateFactory(worker);
        using var client = CreateAuthenticatedClient(
            factory,
            "versioned-publisher",
            platformAdmin: true);
        _ = await BootstrapAsync(factory, client, "Versioned Publisher");
        var slug = $"versioned-{Guid.NewGuid():N}";
        const string firstSource = "public sealed class VersionOneStrategy { }";
        const string secondSource = "public sealed class VersionTwoStrategy { }";

        var first = await CreateSubmissionAsync(
            client,
            firstSource,
            priceInCents: 0,
            slug: slug,
            version: "1.0.0");
        (await client.PostAsync($"/api/v1/submissions/{first.Id:D}/submit", null))
            .EnsureSuccessStatusCode();
        var firstApproval = await client.PostAsJsonAsync(
            $"/api/v1/admin/submissions/{first.Id:D}/decision",
            new
            {
                approve = true,
                sourceReviewed = true,
                declaredBehaviorReviewed = true,
                diffReviewed = true,
            });
        firstApproval.EnsureSuccessStatusCode();
        var firstApproved = await firstApproval.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        (await client.PostAsync(
            $"/api/v1/publisher/listings/{firstApproved!.CatalogItemId:D}/publish",
            null)).EnsureSuccessStatusCode();

        var second = await CreateSubmissionAsync(
            client,
            secondSource,
            priceInCents: 0,
            slug: slug,
            version: "1.1.0");
        (await client.PostAsync($"/api/v1/submissions/{second.Id:D}/submit", null))
            .EnsureSuccessStatusCode();
        var packet = await client.GetFromJsonAsync<SubmissionReviewPacketResponse>(
            $"/api/v1/admin/submissions/{second.Id:D}",
            JsonOptions);
        Assert.NotNull(packet);
        Assert.Equal(firstSource, packet.PreviousApprovedSourceCode);
        Assert.NotNull(packet.PreviousApprovedSourceSha256);
        Assert.Equal(
            "changed_source",
            packet.SourceDiffSummary!.Value.GetProperty("kind").GetString());

        var secondApproval = await client.PostAsJsonAsync(
            $"/api/v1/admin/submissions/{second.Id:D}/decision",
            new
            {
                approve = true,
                sourceReviewed = true,
                declaredBehaviorReviewed = true,
                diffReviewed = true,
            });
        secondApproval.EnsureSuccessStatusCode();
        var secondApproved = await secondApproval.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        var catalog = await client.GetFromJsonAsync<CatalogItemResponse[]>(
            "/api/v1/catalog",
            JsonOptions);
        var listing = Assert.Single(
            catalog!,
            candidate => string.Equals(candidate.Slug, slug, StringComparison.Ordinal));
        Assert.Equal(secondApproved!.ReleaseId, listing.ReleaseId);
        Assert.Equal("1.1.0", listing.Version);
    }

    [Fact]
    public async Task PurchaseCreatesIdempotentGrantAndReleasesTheWorkerContentKey()
    {
        var worker = new DeterministicMarketplaceBuildWorker();
        var configuration = new Dictionary<string, string?>
        {
            ["MarketplaceCommerce:SalesEnabled"] = "true",
            ["MarketplaceCommerce:PolicyVersion"] = "marketplace-test-commercials-v7",
            ["MarketplaceCommerce:ApplicationFeeBasisPoints"] = "1200",
            ["MarketplaceCommerce:ReserveBasisPoints"] = "300",
            ["MarketplaceCommerce:PayoutDelayDays"] = "14",
            ["MarketplaceCommerce:AutomaticTaxEnabled"] = "false",
            ["MarketplaceCommerce:TaxHandling"] = "test-platform-tax",
            ["MarketplaceCommerce:MerchantOfRecord"] = "test-platform",
        };
        await using var factory = CreateFactory(worker, configuration);
        using var publisher = CreateAuthenticatedClient(
            factory,
            "paid-publisher",
            platformAdmin: true);
        _ = await BootstrapAsync(factory, publisher, "Paid Publisher");
        var onboarding = await publisher.PostAsJsonAsync(
            "/api/v1/publisher/connect/onboarding-links",
            new { country = "GB" });
        onboarding.EnsureSuccessStatusCode();
        var onboardingResult = await onboarding.Content.ReadFromJsonAsync<PublisherOnboardingResponse>(JsonOptions);
        Assert.NotNull(onboardingResult);
        await PostDevelopmentWebhookAsync(
            factory,
            new
            {
                id = $"evt-{Guid.NewGuid():N}",
                type = "account.updated",
                purpose = "MarketplacePublisher",
                connectAccountId = onboardingResult.ConnectAccountId,
                detailsSubmitted = true,
                chargesEnabled = true,
                payoutsEnabled = true,
            });

        var submission = await CreateSubmissionAsync(
            publisher,
            "public sealed class PaidStrategy { }",
            priceInCents: 10_000);
        var built = await publisher.PostAsync(
            $"/api/v1/submissions/{submission.Id:D}/submit",
            content: null);
        built.EnsureSuccessStatusCode();
        var builtSubmission = await built.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        var approval = await publisher.PostAsJsonAsync(
            $"/api/v1/admin/submissions/{submission.Id:D}/decision",
            new
            {
                approve = true,
                sourceReviewed = true,
                declaredBehaviorReviewed = true,
                diffReviewed = true,
            });
        approval.EnsureSuccessStatusCode();
        var approved = await approval.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions);
        var publish = await publisher.PostAsync(
            $"/api/v1/publisher/listings/{approved!.CatalogItemId:D}/publish",
            content: null);
        publish.EnsureSuccessStatusCode();

        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var deviceId = Guid.NewGuid();
        var encodedDeviceKey = deviceKey.ExportSubjectPublicKeyInfo();
        using var buyer = CreateAuthenticatedClient(factory, "marketplace-buyer");
        _ = await BootstrapAsync(factory, buyer, "Marketplace Buyer");
        var checkout = await buyer.PostAsJsonAsync(
            "/api/v1/orders",
            new
            {
                catalogItemId = approved.CatalogItemId,
                device = new
                {
                    deviceId,
                    displayName = "Buyer workstation",
                    publicKeySpki = Encode(encodedDeviceKey),
                    fingerprintSha256 = Sha256Hex(encodedDeviceKey),
                },
            });
        Assert.True(
            checkout.IsSuccessStatusCode,
            await checkout.Content.ReadAsStringAsync());
        var order = await checkout.Content.ReadFromJsonAsync<OrderResponse>(JsonOptions);
        Assert.NotNull(order);
        Assert.Equal(approved.ReleaseId, order.ReleaseId);
        Assert.Equal(1_200, order.ApplicationFeeInCents);
        Assert.Equal(300, order.ReserveInCents);
        Assert.Equal(8_500, order.SellerProceedsInCents);
        Assert.Equal("marketplace-test-commercials-v7", order.CommercialPolicyVersion);
        Assert.Equal(14, order.PayoutDelayDays);
        Assert.False(order.AutomaticTaxEnabled);
        Assert.Equal("test-platform-tax", order.TaxHandling);
        Assert.Equal("test-platform", order.MerchantOfRecord);
        Assert.Equal(OrderStatus.Pending, order.Status);

        var eventId = $"evt-{Guid.NewGuid():N}";
        var webhookPayload = new
        {
            id = eventId,
            type = "order.paid",
            purpose = "MarketplaceOrder",
            orderId = order.Id,
        };
        var processed = await PostDevelopmentWebhookAsync(factory, webhookPayload);
        var duplicate = await PostDevelopmentWebhookAsync(factory, webhookPayload);
        Assert.Equal(BillingWebhookOutcome.Processed, processed.Outcome);
        Assert.Equal(BillingWebhookOutcome.Duplicate, duplicate.Outcome);

        Guid licenseId;
        string cipherSha256;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
            var grant = await database.EntitlementGrants.AsNoTracking().SingleAsync(
                candidate => candidate.CatalogItemId == approved.CatalogItemId);
            Assert.Equal(EntitlementGrantType.MarketplaceLicense, grant.Type);
            Assert.Equal(EntitlementGrantStatus.Active, grant.Status);
            var license = await database.MarketplaceLicenses.AsNoTracking().SingleAsync(
                candidate => candidate.GrantId == grant.Id);
            Assert.Equal(grant.Id, license.GrantId);
            Assert.Equal(approved.ReleaseId, license.ReleaseId);
            licenseId = license.Id;
            var release = await database.StrategyReleases.AsNoTracking().SingleAsync(
                candidate => candidate.Id == approved.ReleaseId);
            cipherSha256 = release.CipherSha256;
            Assert.StartsWith(
                "https://marketplace-artifacts.development.invalid/releases/",
                release.SbomBlobUri,
                StringComparison.Ordinal);

            var options = scope.ServiceProvider.GetRequiredService<MarketplaceCommerceOptions>();
            Assert.Equal(14, options.PayoutDelayDays);
            Assert.False(options.AutomaticTaxEnabled);
            Assert.Equal("test-platform-tax", options.TaxHandling);
            Assert.Equal("test-platform", options.MerchantOfRecord);
        }

        using var sessionKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var sessionPublicKey = sessionKey.ExportSubjectPublicKeyInfo();
        var binding = Sha256Hex(sessionPublicKey);
        const string idempotencyKey = "purchased-content-key-roundtrip";
        var challenge = await IssueChallengeAsync(
            buyer,
            deviceId,
            licenseId,
            approved.ReleaseId!.Value,
            binding,
            idempotencyKey);
        var signature = SignProof(
            deviceKey,
            challenge,
            deviceId,
            licenseId,
            approved.ReleaseId.Value,
            binding,
            idempotencyKey);
        var keyResponse = await PostJsonAsync(
            buyer,
            $"/v1/marketplace/licenses/{licenseId:D}/content-keys",
            new ContentKeyReleaseRequest(
                approved.ReleaseId.Value,
                deviceId,
                challenge.ChallengeId,
                Encode(sessionPublicKey),
                signature),
            idempotencyKey);
        keyResponse.EnsureSuccessStatusCode();
        var released = await keyResponse.Content.ReadFromJsonAsync<ContentKeyReleaseResponse>(JsonOptions);
        Assert.NotNull(released);

        using var serverKey = ECDiffieHellman.Create();
        var serverPublicKey = Decode(released.ServerEphemeralPublicKey);
        serverKey.ImportSubjectPublicKeyInfo(serverPublicKey, out _);
        var sharedSecret = sessionKey.DeriveRawSecretAgreement(serverKey.PublicKey);
        var info = Encoding.UTF8.GetBytes(
            $"DAXQ-CONTENT-KEY-V1|{licenseId:D}|{approved.ReleaseId:D}|{deviceId:D}|{released.ContentKeyId}");
        var wrappingKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sharedSecret,
            32,
            Decode(challenge.Nonce),
            info);
        var contentKey = AesKeyWrap.Unwrap(wrappingKey, Decode(released.WrappedKey));
        Assert.Equal(worker.ContentKey, contentKey);
        CryptographicOperations.ZeroMemory(contentKey);
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(wrappingKey);

        const string downloadIdempotencyKey = "purchased-download-grant-roundtrip";
        var downloadChallenge = await IssueChallengeAsync(
            buyer,
            deviceId,
            licenseId,
            approved.ReleaseId.Value,
            cipherSha256,
            downloadIdempotencyKey,
            MarketplaceLicensingService.DownloadGrantOperation);
        var downloadSignature = SignProof(
            deviceKey,
            downloadChallenge,
            deviceId,
            licenseId,
            approved.ReleaseId.Value,
            cipherSha256,
            downloadIdempotencyKey,
            MarketplaceLicensingService.DownloadGrantOperation);
        using var downloadRequest = new HttpRequestMessage(
            HttpMethod.Get,
            $"/v1/marketplace/releases/{approved.ReleaseId:D}/download-grant"
            + $"?license_id={licenseId:D}&device_id={deviceId:D}"
            + $"&challenge_id={downloadChallenge.ChallengeId:D}"
            + $"&device_signature={Uri.EscapeDataString(downloadSignature)}");
        downloadRequest.Headers.Add("Idempotency-Key", downloadIdempotencyKey);
        var downloadResponse = await buyer.SendAsync(downloadRequest);
        downloadResponse.EnsureSuccessStatusCode();
        var downloadGrant = await downloadResponse.Content.ReadFromJsonAsync<DownloadGrantResponse>(
            JsonOptions);
        Assert.NotNull(downloadGrant);
        Assert.StartsWith(
            "https://marketplace-artifacts.development.invalid/releases/",
            downloadGrant.DownloadUrl,
            StringComparison.Ordinal);
        Assert.Equal(cipherSha256, downloadGrant.CipherSha256);
    }

    [Fact]
    public async Task MarketplaceSalesRemainDisabledByDefault()
    {
        await using var factory = new PlatformApiFactory();
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var options = scope.ServiceProvider.GetRequiredService<MarketplaceCommerceOptions>();
            Assert.False(options.SalesEnabled);
        }

        using var client = CreateAuthenticatedClient(factory, "sales-disabled-buyer");
        _ = await BootstrapAsync(factory, client, "Sales Disabled Buyer");
        var response = await client.PostAsJsonAsync(
            "/api/v1/orders",
            new { catalogItemId = Guid.NewGuid() });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains(
            "Marketplace sales are disabled",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    private static PlatformApiFactory CreateFactory(
        DeterministicMarketplaceBuildWorker worker,
        IReadOnlyDictionary<string, string?>? configuration = null)
    {
        MarketplaceCommerceOptions? commerceOptions = null;
        if (configuration is not null)
        {
            var testConfiguration = new ConfigurationBuilder()
                .AddInMemoryCollection(configuration)
                .Build();
            commerceOptions = testConfiguration
                .GetSection(MarketplaceCommerceOptions.SectionName)
                .Get<MarketplaceCommerceOptions>();
        }

        return new PlatformApiFactory(
            services =>
            {
                services.AddSingleton<IMarketplaceBuildWorker>(worker);
                if (commerceOptions is not null)
                {
                    services.AddSingleton(commerceOptions);
                }
            },
            configurationValues: configuration);
    }

    private static async Task<SubmissionResponse> CreateSubmissionAsync(
        HttpClient client,
        string sourceCode,
        long priceInCents,
        string? slug = null,
        string version = "1.0.0",
        string? executionClass = null)
    {
        var response = await client.PostAsJsonAsync(
            "/api/v1/submissions",
            new
            {
                slug = slug ?? $"strategy-{Guid.NewGuid():N}",
                title = "Marketplace Strategy",
                description = "A deterministic marketplace strategy used by the end-to-end tests.",
                version,
                priceInCents,
                priceMode = "OneTime",
                currency = "USD",
                sourceCode,
                referenceDatasetJson = "{\"bars\":[],\"callbacks\":[]}",
                declaredCapabilities = DeclaredCapabilities,
                licenseExpression = "Proprietary",
                executionClass,
            });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SubmissionResponse>(JsonOptions))!;
    }

    private static HttpClient CreateAuthenticatedClient(
        PlatformApiFactory factory,
        string subject,
        bool platformAdmin = false)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Dev-Subject", subject);
        client.DefaultRequestHeaders.Add("X-Dev-Email", $"{subject}@example.test");
        if (platformAdmin)
        {
            client.DefaultRequestHeaders.Add("X-Dev-Roles", "platform-admin");
        }

        return client;
    }

    private static async Task<Guid> BootstrapAsync(
        PlatformApiFactory factory,
        HttpClient client,
        string displayName)
    {
        var response = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { displayName });
        response.EnsureSuccessStatusCode();
        var subject = client.DefaultRequestHeaders.GetValues("X-Dev-Subject").Single();
        return await factory.GetAccountIdAsync(subject);
    }

    private static async Task GrantProfessionalAsync(
        PlatformApiFactory factory,
        Guid accountId)
    {
        _ = await PostDevelopmentWebhookAsync(
            factory,
            new
            {
                id = $"evt-{Guid.NewGuid():N}",
                type = "subscription.updated",
                accountId,
                subscriptionId = $"sub-{Guid.NewGuid():N}",
                priceId = "dev_price_professional_monthly",
                status = "Active",
                currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30),
            });
    }

    private static async Task<BillingWebhookResponse> PostDevelopmentWebhookAsync<T>(
        PlatformApiFactory factory,
        T payload)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Development-Webhook", "accepted");
        var response = await client.PostAsJsonAsync("/api/v1/billing/webhooks", payload);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<BillingWebhookResponse>(JsonOptions))!;
    }

    private static async Task<DeviceProofChallengeResponse> IssueChallengeAsync(
        HttpClient client,
        Guid deviceId,
        Guid licenseId,
        Guid releaseId,
        string binding,
        string idempotencyKey,
        string operation = MarketplaceLicensingService.ContentKeyOperation)
    {
        var response = await PostJsonAsync(
            client,
            "/v1/devices/challenges",
            new DeviceProofChallengeRequest(
                deviceId,
                licenseId,
                releaseId,
                operation,
                binding),
            idempotencyKey);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<DeviceProofChallengeResponse>(JsonOptions))!;
    }

    private static string SignProof(
        ECDsa deviceKey,
        DeviceProofChallengeResponse challenge,
        Guid deviceId,
        Guid licenseId,
        Guid releaseId,
        string binding,
        string idempotencyKey,
        string operation = MarketplaceLicensingService.ContentKeyOperation)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new DeviceProofPayload(
                1,
                operation,
                challenge.ChallengeId,
                challenge.Nonce,
                licenseId,
                releaseId,
                deviceId,
                binding,
                idempotencyKey),
            JsonOptions);
        return Encode(deviceKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
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

    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static string Encode(ReadOnlySpan<byte> bytes) =>
        MarketplaceCryptographyEncoding.Encode(bytes);

    private static byte[] Decode(string value) =>
        MarketplaceCryptographyEncoding.Decode(value);

    private sealed class DeterministicMarketplaceBuildWorker : IMarketplaceBuildWorker
    {
        private static readonly byte[] ParityStatistics =
            "{\"schemaVersion\":\"daxq-backtest-parity-stats-v1\",\"signalCount\":1}"u8.ToArray();
        private static readonly byte[] ListingMetrics =
            "{\"schemaVersion\":\"daxq-listing-metrics-v1\",\"netPnlUsd\":12.5}"u8.ToArray();
        private static readonly byte[] Sbom =
            "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[]}"u8.ToArray();
        private int invocationCount;

        public byte[] ContentKey { get; } = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();

        public int InvocationCount => Volatile.Read(ref invocationCount);

        public string? LastExecutionClass { get; private set; }

        public Task<MarketplaceBuildResult> RunAsync(
            MarketplaceBuildRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref invocationCount);
            var source = Encoding.UTF8.GetString(request.Source);
            if (source.Contains("ParityDivergence", StringComparison.Ordinal))
            {
                return Task.FromResult(MarketplaceBuildResult.Blocked(
                    "marketplace-test-worker-v1",
                    "DAXQ3007: managed and DAXQ signal strength diverged."));
            }

            var artifact = Encoding.UTF8.GetBytes($"DAXQ:{request.SubmissionId:D}:{request.StrategyId}");
            var artifactHash = Sha256Hex(artifact);
            var result = new MarketplaceBuildResult(
                MarketplaceBuildDecision.Pass,
                "marketplace-test-worker-v1",
                [],
                new MarketplaceScanEvidence(
                    true,
                    true,
                    true,
                    true,
                    true,
                    "compiler-policy-v1",
                    "malware-test-v1",
                    "secret-test-v1",
                    "license-test-v1",
                    "sbom-test-v1",
                    DeclaredCapabilities),
                artifact,
                artifactHash,
                artifactHash,
                $"ck_{request.SubmissionId:N}",
                ContentKey.ToArray(),
                3,
                MarketplaceSubmissionPipeline.RestrictedExecutionClass,
                Sha256Hex(request.DiversificationSeed),
                ParityStatistics.ToArray(),
                Sha256Hex(ParityStatistics),
                ListingMetrics.ToArray(),
                Sha256Hex(ListingMetrics),
                Sbom.ToArray(),
                Sha256Hex(Sbom));
            LastExecutionClass = result.ExecutionClass;
            return Task.FromResult(result);
        }
    }
}
