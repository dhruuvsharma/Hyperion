using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class MarketplaceReadEndpointsTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 27, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task AnonymousCatalogReturnsOnlyPublishedListingsSearchesAndPaginatesWithSalesOff()
    {
        await using var factory = new PlatformApiFactory();
        var fixture = await SeedAsync(factory);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/catalog?pageSize=1");
        response.EnsureSuccessStatusCode();
        var firstPage = await response.Content.ReadFromJsonAsync<JsonElement>();
        var first = Assert.Single(firstPage.EnumerateArray());
        var firstId = first.GetProperty("id").GetGuid();
        Assert.Contains(firstId, new[] { fixture.AlphaListingId, fixture.BetaListingId });
        Assert.Equal("ComingSoon", first.GetProperty("salesStatus").GetString());
        var cursor = Assert.Single(response.Headers.GetValues("X-Next-Cursor"));

        var next = await client.GetFromJsonAsync<JsonElement>(
            "/api/v1/catalog?pageSize=1&cursor=" + Uri.EscapeDataString(cursor));
        var nextId = Assert.Single(next.EnumerateArray()).GetProperty("id").GetGuid();
        Assert.Contains(nextId, new[] { fixture.AlphaListingId, fixture.BetaListingId });
        Assert.NotEqual(firstId, nextId);

        var search = await client.GetFromJsonAsync<JsonElement>("/api/v1/catalog?query=beta");
        Assert.Equal(fixture.BetaListingId, Assert.Single(search.EnumerateArray()).GetProperty("id").GetGuid());
        Assert.DoesNotContain(
            fixture.DraftListingId,
            (await client.GetFromJsonAsync<JsonElement>("/api/v1/catalog"))
                .EnumerateArray()
                .Select(item => item.GetProperty("id").GetGuid()));
    }

    [Fact]
    public async Task AnonymousDetailIncludesPublisherTrustDeclarationsAndVerifiedReviews()
    {
        await using var factory = new PlatformApiFactory();
        var fixture = await SeedAsync(factory);
        using var client = factory.CreateClient();

        var detail = await client.GetFromJsonAsync<JsonElement>(
            $"/api/v1/catalog/{fixture.AlphaListingId:D}");

        Assert.Equal(
            "Alpha Publisher",
            detail.GetProperty("publisher").GetProperty("displayName").GetString());
        Assert.Equal(JsonValueKind.Null, detail.GetProperty("publisherSignature").ValueKind);
        Assert.Equal("NotCaptured", detail.GetProperty("publisherSignatureStatus").GetString());
        Assert.Equal("Approved", detail.GetProperty("releaseStatus").GetString());
        Assert.Equal("Approved", detail.GetProperty("reviewStatus").GetString());
        Assert.Equal(
            ["bars", "signals"],
            detail.GetProperty("declaredCapabilities").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(JsonValueKind.Null, detail.GetProperty("declaredDataRequirements").ValueKind);
        Assert.Equal(JsonValueKind.Null, detail.GetProperty("declaredPermissions").ValueKind);
        var review = Assert.Single(detail.GetProperty("reviews").EnumerateArray());
        Assert.True(review.GetProperty("verifiedBuyer").GetBoolean());
        Assert.Equal("Verified review", review.GetProperty("body").GetString());

        var reviewList = await client.GetFromJsonAsync<JsonElement>(
            $"/api/v1/catalog/{fixture.AlphaListingId:D}/reviews");
        Assert.True(Assert.Single(reviewList.EnumerateArray()).GetProperty("verifiedBuyer").GetBoolean());
    }

    [Fact]
    public async Task SellerReadsAreOwnerScopedAndExposeSubmissionSalesConnectAndPayoutEvidence()
    {
        var reporting = new ReportingCommerceProvider();
        await using var factory = new PlatformApiFactory(services =>
        {
            services.RemoveAll<IMarketplaceCommerceProvider>();
            services.AddSingleton<IMarketplaceCommerceProvider>(reporting);
        });
        var fixture = await SeedAsync(factory);
        using var client = CreateAuthenticatedClient(factory, "alpha-publisher");

        var listings = await client.GetFromJsonAsync<JsonElement>("/api/v1/publisher/listings");
        var listingIds = listings.EnumerateArray().Select(item => item.GetProperty("id").GetGuid()).ToArray();
        Assert.Contains(fixture.AlphaListingId, listingIds);
        Assert.Contains(fixture.DraftListingId, listingIds);
        Assert.DoesNotContain(fixture.BetaListingId, listingIds);
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await client.GetAsync($"/api/v1/publisher/listings/{fixture.BetaListingId:D}")).StatusCode);

        var submissions = await client.GetFromJsonAsync<JsonElement>("/api/v1/submissions");
        var submission = Assert.Single(submissions.EnumerateArray());
        Assert.Equal("marketplace-build-v1", submission.GetProperty("buildPolicyVersion").GetString());
        Assert.True(submission.GetProperty("scanEvidence").GetProperty("allPassed").GetBoolean());
        Assert.Equal(17, submission.GetProperty("parityStatistics").GetProperty("samples").GetInt32());
        Assert.Equal("alpha-sbom", submission.GetProperty("sbomSha256").GetString());

        var sales = await client.GetFromJsonAsync<JsonElement>("/api/v1/publisher/sales");
        var sale = Assert.Single(sales.EnumerateArray());
        Assert.Equal(fixture.AlphaListingId, sale.GetProperty("catalogItemId").GetGuid());
        Assert.Equal(7_500, sale.GetProperty("sellerProceedsInCents").GetInt64());
        Assert.False(sale.TryGetProperty("buyerAccountId", out _));

        var connect = await client.GetFromJsonAsync<JsonElement>("/api/v1/publisher/connect");
        Assert.Equal("acct_alpha", connect.GetProperty("connectAccountId").GetString());
        Assert.True(connect.GetProperty("payoutsEnabled").GetBoolean());

        var payoutResponse = await client.GetAsync("/api/v1/publisher/payouts?pageSize=1");
        payoutResponse.EnsureSuccessStatusCode();
        var payouts = await payoutResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Available", payouts.GetProperty("reportingStatus").GetString());
        Assert.Equal(12_500, Assert.Single(payouts.GetProperty("available").EnumerateArray())
            .GetProperty("amountInMinorUnits").GetInt64());
        Assert.Equal("po_alpha", Assert.Single(payouts.GetProperty("payouts").EnumerateArray())
            .GetProperty("providerPayoutId").GetString());
        Assert.Equal("acct_alpha", reporting.RequestedConnectAccountId);
    }

    [Theory]
    [InlineData("/api/v1/publisher/listings")]
    [InlineData("/api/v1/publisher/connect")]
    [InlineData("/api/v1/publisher/sales")]
    [InlineData("/api/v1/publisher/payouts")]
    [InlineData("/api/v1/submissions")]
    public async Task UnauthenticatedSellerReadsAreRejected(string path)
    {
        await using var factory = new PlatformApiFactory();
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(path)).StatusCode);
    }

    [Fact]
    public async Task InvalidCursorReturnsProblemJson()
    {
        await using var factory = new PlatformApiFactory();
        await SeedAsync(factory);
        using var client = CreateAuthenticatedClient(factory, "alpha-publisher");

        var responses = new[]
        {
            await client.GetAsync("/api/v1/publisher/listings?cursor=%2A%2A%2A"),
            await client.GetAsync("/api/v1/publisher/listings?cursor=e30&pageSize=1"),
            await client.GetAsync("/api/v1/publisher/payouts?cursor=not-a-payout"),
            await client.GetAsync("/api/v1/catalog?pageSize=invalid"),
        };

        foreach (var response in responses)
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        }
    }

    private static async Task<MarketplaceFixture> SeedAsync(PlatformApiFactory factory)
    {
        var alphaAccountId = Guid.NewGuid();
        var betaAccountId = Guid.NewGuid();
        var buyerAccountId = Guid.NewGuid();
        var alphaListingId = Guid.NewGuid();
        var betaListingId = Guid.NewGuid();
        var draftListingId = Guid.NewGuid();
        var alphaSubmissionId = Guid.NewGuid();
        var betaSubmissionId = Guid.NewGuid();
        var alphaReleaseId = Guid.NewGuid();
        var betaReleaseId = Guid.NewGuid();

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        database.Profiles.AddRange(
            Profile(alphaAccountId, "alpha-publisher", "Alpha Publisher"),
            Profile(betaAccountId, "beta-publisher", "Beta Publisher"),
            Profile(buyerAccountId, "buyer", "Verified Buyer"));
        database.CatalogItems.AddRange(
            Listing(alphaListingId, alphaAccountId, "alpha-strategy", "Alpha Strategy", CatalogItemStatus.Published),
            Listing(betaListingId, betaAccountId, "beta-strategy", "Beta Strategy", CatalogItemStatus.Published),
            Listing(draftListingId, alphaAccountId, "draft-strategy", "Draft Strategy", CatalogItemStatus.Draft));
        database.Submissions.AddRange(
            Submission(alphaSubmissionId, alphaAccountId, alphaListingId, alphaReleaseId, "alpha-strategy", "Alpha Strategy"),
            Submission(betaSubmissionId, betaAccountId, betaListingId, betaReleaseId, "beta-strategy", "Beta Strategy"));
        database.StrategyReleases.AddRange(
            Release(alphaReleaseId, alphaListingId, alphaSubmissionId, "alpha-artifact"),
            Release(betaReleaseId, betaListingId, betaSubmissionId, "beta-artifact"));
        database.Reviews.AddRange(
            new MarketplaceReview
            {
                Id = Guid.NewGuid(),
                CatalogItemId = alphaListingId,
                AuthorAccountId = buyerAccountId,
                Rating = 5,
                Body = "Verified review",
                Status = ReviewStatus.Published,
                CreatedAt = Now,
                UpdatedAt = Now,
            },
            new MarketplaceReview
            {
                Id = Guid.NewGuid(),
                CatalogItemId = alphaListingId,
                AuthorAccountId = betaAccountId,
                Rating = 1,
                Body = "Hidden review",
                Status = ReviewStatus.Hidden,
                CreatedAt = Now,
                UpdatedAt = Now,
            },
            new MarketplaceReview
            {
                Id = Guid.NewGuid(),
                CatalogItemId = alphaListingId,
                AuthorAccountId = alphaAccountId,
                Rating = 2,
                Body = "Unverified imported review",
                Status = ReviewStatus.Published,
                CreatedAt = Now,
                UpdatedAt = Now,
            });
        database.MarketplacePublishers.AddRange(
            Publisher(alphaAccountId, "acct_alpha"),
            Publisher(betaAccountId, "acct_beta"));
        database.Orders.AddRange(
            Order(alphaListingId, alphaReleaseId, buyerAccountId, 7_500),
            Order(betaListingId, betaReleaseId, alphaAccountId, 4_000));
        await database.SaveChangesAsync();
        return new MarketplaceFixture(alphaListingId, betaListingId, draftListingId);
    }

    private static Profile Profile(Guid id, string subject, string displayName) =>
        new()
        {
            Id = id,
            Subject = subject,
            Email = subject + "@example.test",
            DisplayName = displayName,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

    private static CatalogItem Listing(
        Guid id,
        Guid publisherId,
        string slug,
        string title,
        CatalogItemStatus status) =>
        new()
        {
            Id = id,
            PublisherAccountId = publisherId,
            Slug = slug,
            Title = title,
            Description = title + " marketplace description",
            Version = "1.0.0",
            PriceInCents = 10_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Currency = "USD",
            TemplateCopyJson = "{}",
            MediaJson = "[]",
            Status = status,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

    private static MarketplaceSubmission Submission(
        Guid id,
        Guid publisherId,
        Guid listingId,
        Guid releaseId,
        string slug,
        string title) =>
        new()
        {
            Id = id,
            PublisherAccountId = publisherId,
            Slug = slug,
            Title = title,
            Description = title + " marketplace description",
            Version = "1.0.0",
            PriceInCents = 10_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Currency = "USD",
            SourceSha256 = slug + "-source",
            ReferenceDatasetSha256 = slug + "-dataset",
            DeclaredCapabilitiesJson = "[\"bars\",\"signals\"]",
            RequestedExecutionClass = "restricted_only",
            BuildPolicyVersion = "marketplace-build-v1",
            BuildDiagnosticsJson = "[]",
            ScanEvidenceJson = "{\"allPassed\":true}",
            ParityStatisticsJson = "{\"samples\":17}",
            ParityStatisticsSha256 = slug + "-parity",
            ListingMetricsJson = "{\"trades\":9}",
            ListingMetricsSha256 = slug + "-metrics",
            SourceDiffSummaryJson = "{\"changedLines\":3}",
            SbomSha256 = slug.StartsWith("alpha", StringComparison.Ordinal) ? "alpha-sbom" : "beta-sbom",
            ArtifactSha256 = slug + "-artifact",
            CatalogItemId = listingId,
            ReleaseId = releaseId,
            SourceReview = MarketplaceHumanReviewState.Passed,
            DeclaredBehaviorReview = MarketplaceHumanReviewState.Passed,
            DiffReview = MarketplaceHumanReviewState.Passed,
            Status = SubmissionStatus.Approved,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

    private static MarketplaceStrategyRelease Release(
        Guid id,
        Guid listingId,
        Guid submissionId,
        string artifactSha256) =>
        new()
        {
            Id = id,
            CatalogItemId = listingId,
            SubmissionId = submissionId,
            Version = "1.0.0",
            Status = MarketplaceReleaseStatus.Approved,
            ArtifactBlobUri = "approved://" + id.ToString("N"),
            ExecutionClass = "restricted_only",
            CipherSha256 = artifactSha256 + "-cipher",
            SourceSha256 = artifactSha256 + "-source",
            ArtifactSha256 = artifactSha256,
            ParityStatisticsJson = "{\"samples\":17}",
            ParityStatisticsSha256 = artifactSha256 + "-parity",
            ListingMetricsJson = "{\"trades\":9}",
            ListingMetricsSha256 = artifactSha256 + "-metrics",
            ScanEvidenceJson = "{\"allPassed\":true}",
            SbomSha256 = artifactSha256 + "-sbom",
            SbomBlobUri = "approved://sbom/" + id.ToString("N"),
            AttestationSha256 = artifactSha256 + "-attestation",
            CreatedAt = Now,
            ApprovedAt = Now,
        };

    private static MarketplacePublisher Publisher(Guid accountId, string connectAccountId) =>
        new()
        {
            AccountId = accountId,
            ConnectAccountId = connectAccountId,
            Status = MarketplacePublisherStatus.Complete,
            DetailsSubmitted = true,
            ChargesEnabled = true,
            PayoutsEnabled = true,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

    private static MarketplaceOrder Order(
        Guid listingId,
        Guid releaseId,
        Guid buyerAccountId,
        long sellerProceeds) =>
        new()
        {
            Id = Guid.NewGuid(),
            BuyerAccountId = buyerAccountId,
            CatalogItemId = listingId,
            ReleaseId = releaseId,
            AmountInCents = 10_000,
            PriceMode = MarketplacePriceMode.OneTime,
            Currency = "USD",
            ApplicationFeeInCents = 1_500,
            ReserveInCents = 1_000,
            SellerProceedsInCents = sellerProceeds,
            CommercialPolicyVersion = "test-policy",
            PayoutDelayDays = 7,
            AutomaticTaxEnabled = true,
            TaxHandling = "stripe_automatic_tax",
            MerchantOfRecord = "undecided",
            Status = OrderStatus.Paid,
            CreatedAt = Now,
            UpdatedAt = Now,
        };

    private static HttpClient CreateAuthenticatedClient(PlatformApiFactory factory, string subject)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Dev-Subject", subject);
        client.DefaultRequestHeaders.Add("X-Dev-Email", subject + "@example.test");
        client.DefaultRequestHeaders.Add("X-Dev-Name", subject);
        return client;
    }

    private sealed record MarketplaceFixture(
        Guid AlphaListingId,
        Guid BetaListingId,
        Guid DraftListingId);

    private sealed class ReportingCommerceProvider : IMarketplaceCommerceProvider
    {
        public string Name => "reporting-test";

        public string? RequestedConnectAccountId { get; private set; }

        public Task<MarketplaceExpressAccount> CreateExpressAccountAsync(
            MarketplaceExpressAccountRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<MarketplaceOnboardingLink> CreateOnboardingLinkAsync(
            MarketplaceOnboardingLinkRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<MarketplaceCheckout> CreateCheckoutAsync(
            MarketplaceCheckoutRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<MarketplacePayoutReport> GetPayoutReportAsync(
            string sellerConnectAccountId,
            string? cursor,
            int pageSize,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestedConnectAccountId = sellerConnectAccountId;
            return Task.FromResult(new MarketplacePayoutReport(
                [new MarketplaceBalanceAmount(12_500, "USD")],
                [new MarketplaceBalanceAmount(2_500, "USD")],
                [
                    new MarketplacePayout(
                        "po_alpha",
                        8_000,
                        "USD",
                        "paid",
                        Now.AddDays(-2),
                        Now.AddDays(-1),
                        "standard",
                        Automatic: true,
                        FailureCode: null),
                ],
                "po_alpha"));
        }
    }
}
