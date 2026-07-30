using System.Globalization;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Devices;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Mvc;

namespace DaxAlgo.Platform.Features.Marketplace;

public static class MarketplaceEndpoints
{
    public static IEndpointRouteBuilder MapMarketplaceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        MapCatalog(endpoints);
        MapSubmissions(endpoints);
        MapPublisher(endpoints);
        MapOrders(endpoints);
        return endpoints;
    }

    private static void MapCatalog(IEndpointRouteBuilder endpoints)
    {
        var catalog = endpoints.MapGroup("/api/v1/catalog")
            .WithTags("Marketplace catalog");
        catalog.MapGet(
                "/",
                async (
                    [FromQuery] string? query,
                    [FromQuery] string? cursor,
                    [FromQuery] string? pageSize,
                    HttpContext context,
                    MarketplaceService marketplace,
                    MarketplaceCommerceOptions commerceOptions,
                    CancellationToken cancellationToken) =>
                {
                    var page = await marketplace.GetCatalogAsync(
                        query,
                        cursor,
                        ParsePageSize(pageSize),
                        cancellationToken);
                    WriteNextCursor(context.Response, page.NextCursor);
                    return Results.Ok(page.Items.Select(item =>
                        CatalogItemResponse.From(item, commerceOptions.SalesEnabled)));
                })
            .AllowAnonymous()
            .WithName("GetCatalog");
        catalog.MapGet(
                "/{catalogItemId:guid}",
                async (
                    Guid catalogItemId,
                    MarketplaceService marketplace,
                    MarketplaceCommerceOptions commerceOptions,
                    CancellationToken cancellationToken) =>
                    Results.Ok(CatalogItemResponse.From(
                        await marketplace.GetCatalogItemAsync(catalogItemId, cancellationToken),
                        commerceOptions.SalesEnabled)))
            .AllowAnonymous()
            .WithName("GetCatalogItem");
        catalog.MapGet(
                "/{catalogItemId:guid}/reviews",
                async (
                    Guid catalogItemId,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                    Results.Ok((await marketplace.GetReviewsAsync(catalogItemId, cancellationToken))
                        .Select(ReviewResponse.From)))
            .AllowAnonymous()
            .WithName("GetCatalogReviews");
        catalog.MapPost(
                "/{catalogItemId:guid}/reviews",
                async (
                    Guid catalogItemId,
                    CreateReviewRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var review = await marketplace.CreateReviewAsync(
                        profile.Id,
                        catalogItemId,
                        request.Rating,
                        request.Body,
                        cancellationToken);
                    return Results.Created(
                        $"/api/v1/catalog/{catalogItemId}/reviews",
                        ReviewResponse.From(review, verifiedBuyer: true));
                })
            .RequireAuthorization()
            .WithName("CreateCatalogReview");
    }

    private static void MapSubmissions(IEndpointRouteBuilder endpoints)
    {
        var submissions = endpoints.MapGroup("/api/v1/submissions")
            .WithTags("Marketplace submissions")
            .RequireAuthorization();
        submissions.MapGet(
                "/",
                async (
                    [FromQuery] string? cursor,
                    [FromQuery] string? pageSize,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var page = await marketplace.GetSubmissionsAsync(
                        profile.Id,
                        cursor,
                        ParsePageSize(pageSize),
                        cancellationToken);
                    WriteNextCursor(context.Response, page.NextCursor);
                    return Results.Ok(page.Items.Select(SubmissionResponse.From));
                })
            .WithName("GetMySubmissions");
        submissions.MapGet(
                "/{submissionId:guid}",
                async (
                    Guid submissionId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(SubmissionResponse.From(
                        await marketplace.GetSubmissionAsync(
                            profile.Id,
                            submissionId,
                            cancellationToken)));
                })
            .WithName("GetMyMarketplaceSubmission");
        submissions.MapPost(
                "/",
                async (
                    CreateSubmissionRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var submission = await marketplace.CreateSubmissionAsync(
                        profile.Id,
                        request.Slug,
                        request.Title,
                        request.Description,
                        request.Version,
                        request.PriceInCents,
                        request.PriceMode,
                        request.Currency,
                        request.SourceCode,
                        request.ReferenceDatasetJson,
                        request.DeclaredCapabilities,
                        request.LicenseExpression,
                        request.ExecutionClass,
                        cancellationToken);
                    return Results.Created(
                        $"/api/v1/submissions/{submission.Id}",
                        SubmissionResponse.From(submission));
                })
            .WithName("CreateSubmission");
        submissions.MapPost(
                "/{submissionId:guid}/submit",
                async (
                    Guid submissionId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(SubmissionResponse.From(
                        await marketplace.SubmitAsync(
                            profile.Id,
                            submissionId,
                            cancellationToken)));
                })
            .WithName("SubmitMarketplaceSubmission");

        endpoints.MapPost(
                "/api/v1/admin/submissions/{submissionId:guid}/decision",
                async (
                    Guid submissionId,
                    SubmissionDecisionRequest request,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                    Results.Ok(SubmissionResponse.From(
                        await marketplace.DecideAsync(
                            submissionId,
                            request.Approve,
                            request.SourceReviewed,
                            request.DeclaredBehaviorReviewed,
                            request.DiffReviewed,
                            request.Notes,
                            cancellationToken))))
            .WithTags("Marketplace administration")
            .RequireAuthorization("platform-admin")
            .WithName("DecideMarketplaceSubmission");
        endpoints.MapGet(
                "/api/v1/admin/submissions/{submissionId:guid}",
                async (
                    Guid submissionId,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                    Results.Ok(SubmissionReviewPacketResponse.From(
                        await marketplace.GetReviewPacketAsync(
                            submissionId,
                            cancellationToken))))
            .WithTags("Marketplace administration")
            .RequireAuthorization("platform-admin")
            .WithName("GetMarketplaceSubmissionReviewPacket");
    }

    private static void MapPublisher(IEndpointRouteBuilder endpoints)
    {
        var publisher = endpoints.MapGroup("/api/v1/publisher")
            .WithTags("Marketplace publisher")
            .RequireAuthorization();
        publisher.MapGet(
                "/connect",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplacePublisherService publishers,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(PublisherStatusResponse.From(
                        await publishers.FindAsync(profile.Id, cancellationToken)));
                })
            .WithName("GetMarketplacePublisherStatus");
        publisher.MapGet(
                "/listings",
                async (
                    [FromQuery] string? cursor,
                    [FromQuery] string? pageSize,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var page = await marketplace.GetListingsAsync(
                        profile.Id,
                        cursor,
                        ParsePageSize(pageSize),
                        cancellationToken);
                    WriteNextCursor(context.Response, page.NextCursor);
                    return Results.Ok(page.Items.Select(ListingResponse.From));
                })
            .WithName("GetMyMarketplaceListings");
        publisher.MapGet(
                "/listings/{catalogItemId:guid}",
                async (
                    Guid catalogItemId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(ListingResponse.From(
                        await marketplace.GetListingAsync(
                            profile.Id,
                            catalogItemId,
                            cancellationToken)));
                })
            .WithName("GetMyMarketplaceListing");
        publisher.MapGet(
                "/sales",
                async (
                    [FromQuery] string? cursor,
                    [FromQuery] string? pageSize,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var page = await marketplace.GetSellerSalesAsync(
                        profile.Id,
                        cursor,
                        ParsePageSize(pageSize),
                        cancellationToken);
                    WriteNextCursor(context.Response, page.NextCursor);
                    return Results.Ok(page.Items.Select(SellerSaleResponse.From));
                })
            .WithName("GetMyMarketplaceSales");
        publisher.MapGet(
                "/payouts",
                async (
                    [FromQuery] string? cursor,
                    [FromQuery] string? pageSize,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplacePublisherService publishers,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var resolvedPageSize = ValidatePayoutPage(ParsePageSize(pageSize), cursor);
                    var report = await publishers.GetPayoutReportAsync(
                        profile.Id,
                        cursor,
                        resolvedPageSize,
                        cancellationToken);
                    WriteNextCursor(context.Response, report.Report?.NextCursor);
                    return Results.Ok(PublisherPayoutsResponse.From(report));
                })
            .WithName("GetMyMarketplacePayouts");
        publisher.MapPost(
                "/connect/onboarding-links",
                async (
                    CreatePublisherOnboardingLinkRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplacePublisherService publishers,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    var result = await publishers.CreateOnboardingLinkAsync(
                        profile.Id,
                        profile.Email,
                        profile.DisplayName,
                        request.Country,
                        cancellationToken);
                    return Results.Ok(PublisherOnboardingResponse.From(result));
                })
            .WithName("CreateMarketplacePublisherOnboardingLink");
        publisher.MapPut(
                "/listings/{catalogItemId:guid}",
                async (
                    Guid catalogItemId,
                    UpdateListingRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(ListingResponse.From(
                        await marketplace.UpdateListingAsync(
                            profile.Id,
                            catalogItemId,
                            request.Title,
                            request.Description,
                            request.TemplateCopyJson,
                            request.MediaUrls,
                            request.PriceInCents,
                            request.PriceMode,
                            cancellationToken)));
                })
            .WithName("UpdateMarketplaceListing");
        publisher.MapPost(
                "/listings/{catalogItemId:guid}/publish",
                async (
                    Guid catalogItemId,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok(ListingResponse.From(
                        await marketplace.PublishListingAsync(
                            profile.Id,
                            catalogItemId,
                            cancellationToken)));
                })
            .WithName("PublishMarketplaceListing");
    }

    private static void MapOrders(IEndpointRouteBuilder endpoints)
    {
        var orders = endpoints.MapGroup("/api/v1/orders")
            .WithTags("Marketplace orders")
            .RequireAuthorization();
        orders.MapGet(
                "/",
                async (
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    return Results.Ok((await marketplace.GetOrdersAsync(
                            profile.Id,
                            cancellationToken))
                        .Select(OrderResponse.From));
                })
            .WithName("GetMyOrders");
        orders.MapPost(
                "/",
                async (
                    CreateOrderRequest request,
                    HttpContext context,
                    IManagedIdentityProvider identities,
                    ProfileService profiles,
                    DeviceService devices,
                    MarketplaceService marketplace,
                    CancellationToken cancellationToken) =>
                {
                    var profile = await RequireProfileAsync(
                        context,
                        identities,
                        profiles,
                        cancellationToken);
                    marketplace.EnsureSalesEnabled();
                    if (request.Device is not null)
                    {
                        _ = await devices.RegisterAsync(
                            profile.Id,
                            request.Device.DeviceId,
                            request.Device.DisplayName,
                            request.Device.PublicKeySpki,
                            request.Device.FingerprintSha256,
                            cancellationToken);
                    }

                    var order = await marketplace.CreateOrderAsync(
                        profile.Id,
                        request.CatalogItemId,
                        cancellationToken);
                    return Results.Created(
                        $"/api/v1/orders/{order.Id}",
                        OrderResponse.From(order));
                })
            .WithName("CreateMarketplaceOrder");
    }

    private static async Task<Profile> RequireProfileAsync(
        HttpContext context,
        IManagedIdentityProvider identities,
        ProfileService profiles,
        CancellationToken cancellationToken) =>
        await profiles.RequireAsync(
            identities.Resolve(context.User),
            cancellationToken);

    private static void WriteNextCursor(HttpResponse response, string? cursor)
    {
        if (!string.IsNullOrWhiteSpace(cursor))
        {
            response.Headers["X-Next-Cursor"] = cursor;
        }
    }

    private static int? ParsePageSize(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var pageSize))
        {
            throw new PlatformValidationException("Page size must be an integer between 1 and 100.");
        }

        return pageSize;
    }

    private static int ValidatePayoutPage(int? pageSize, string? cursor)
    {
        var resolved = pageSize ?? 50;
        if (resolved is < 1 or > 100)
        {
            throw new PlatformValidationException("Page size must be between 1 and 100.");
        }

        if (!string.IsNullOrEmpty(cursor)
            && (cursor.Length > 255
                || !cursor.StartsWith("po_", StringComparison.Ordinal)
                || cursor.Any(character =>
                    !(char.IsAsciiLetterOrDigit(character) || character == '_'))))
        {
            throw new PlatformValidationException("The pagination cursor is invalid.");
        }

        return resolved;
    }
}

public sealed record CreateSubmissionRequest(
    string Slug,
    string Title,
    string Description,
    string Version,
    long PriceInCents,
    MarketplacePriceMode PriceMode,
    string Currency,
    string SourceCode,
    string ReferenceDatasetJson,
    IReadOnlyList<string>? DeclaredCapabilities,
    string LicenseExpression,
    string? ExecutionClass = null);

public sealed record SubmissionDecisionRequest(
    bool Approve,
    bool SourceReviewed,
    bool DeclaredBehaviorReviewed,
    bool DiffReviewed,
    string? Notes);

public sealed record CreatePublisherOnboardingLinkRequest(string Country = "US");

public sealed record UpdateListingRequest(
    string Title,
    string Description,
    string TemplateCopyJson,
    IReadOnlyList<string>? MediaUrls,
    long PriceInCents,
    MarketplacePriceMode PriceMode);

public sealed record MarketplaceDeviceRegistrationRequest(
    Guid DeviceId,
    string DisplayName,
    string? PublicKeySpki,
    string? FingerprintSha256);

public sealed record CreateOrderRequest(
    Guid CatalogItemId,
    MarketplaceDeviceRegistrationRequest? Device);

public sealed record CreateReviewRequest(int Rating, string Body);

public sealed record PublisherIdentityResponse(string DisplayName);

public sealed record PublisherSignatureResponse(
    string KeyId,
    string Algorithm,
    string EncodedSignature);

public sealed record CatalogItemResponse(
    Guid Id,
    string Slug,
    string Title,
    string Description,
    string Version,
    long PriceInCents,
    MarketplacePriceMode PriceMode,
    string Currency,
    JsonElement TemplateCopy,
    IReadOnlyList<string> MediaUrls,
    Guid ReleaseId,
    string ExecutionClass,
    string ArtifactSha256,
    string? AttestationSha256,
    JsonElement ParityStatistics,
    JsonElement ListingMetrics,
    PublisherIdentityResponse Publisher,
    PublisherSignatureResponse? PublisherSignature,
    string PublisherSignatureStatus,
    MarketplaceReleaseStatus ReleaseStatus,
    SubmissionStatus ReviewStatus,
    MarketplaceHumanReviewState SourceReview,
    MarketplaceHumanReviewState DeclaredBehaviorReview,
    MarketplaceHumanReviewState DiffReview,
    IReadOnlyList<string> DeclaredCapabilities,
    IReadOnlyList<string>? DeclaredDataRequirements,
    IReadOnlyList<string>? DeclaredPermissions,
    string DeclarationStatus,
    string SalesStatus,
    IReadOnlyList<ReviewResponse> Reviews)
{
    internal static CatalogItemResponse From(
        MarketplaceCatalogView view,
        bool salesEnabled) =>
        new(
            view.Item.Id,
            view.Item.Slug,
            view.Item.Title,
            view.Item.Description,
            view.Item.Version,
            view.Item.PriceInCents,
            view.Item.PriceMode,
            view.Item.Currency,
            JsonSerializer.Deserialize<JsonElement>(view.Item.TemplateCopyJson),
            JsonSerializer.Deserialize<string[]>(view.Item.MediaJson) ?? [],
            view.Release.Id,
            view.Release.ExecutionClass,
            view.Release.ArtifactSha256,
            view.Release.AttestationSha256,
            JsonSerializer.Deserialize<JsonElement>(view.Release.ParityStatisticsJson),
            JsonSerializer.Deserialize<JsonElement>(view.Release.ListingMetricsJson),
            new PublisherIdentityResponse(view.Publisher.DisplayName),
            PublisherSignature: null,
            PublisherSignatureStatus: "NotCaptured",
            view.Release.Status,
            view.Submission.Status,
            view.Submission.SourceReview,
            view.Submission.DeclaredBehaviorReview,
            view.Submission.DiffReview,
            JsonSerializer.Deserialize<string[]>(view.Submission.DeclaredCapabilitiesJson) ?? [],
            DeclaredDataRequirements: null,
            DeclaredPermissions: null,
            DeclarationStatus: "LegacyCapabilitiesOnly",
            SalesStatus: salesEnabled ? "Available" : "ComingSoon",
            view.Reviews.Select(ReviewResponse.From).ToArray());
}

public sealed record ListingResponse(
    Guid Id,
    string Slug,
    string Title,
    string Description,
    string Version,
    long PriceInCents,
    MarketplacePriceMode PriceMode,
    string Currency,
    JsonElement TemplateCopy,
    IReadOnlyList<string> MediaUrls,
    CatalogItemStatus Status)
{
    internal static ListingResponse From(CatalogItem item) =>
        new(
            item.Id,
            item.Slug,
            item.Title,
            item.Description,
            item.Version,
            item.PriceInCents,
            item.PriceMode,
            item.Currency,
            JsonSerializer.Deserialize<JsonElement>(item.TemplateCopyJson),
            JsonSerializer.Deserialize<string[]>(item.MediaJson) ?? [],
            item.Status);
}

public sealed record SubmissionResponse(
    Guid Id,
    string Slug,
    string Title,
    string Description,
    string Version,
    long PriceInCents,
    MarketplacePriceMode PriceMode,
    string Currency,
    string RequestedExecutionClass,
    SubmissionStatus Status,
    string SourceSha256,
    string? ArtifactSha256,
    string? ParityStatisticsSha256,
    string? ListingMetricsSha256,
    MarketplaceHumanReviewState SourceReview,
    MarketplaceHumanReviewState DeclaredBehaviorReview,
    MarketplaceHumanReviewState DiffReview,
    Guid? CatalogItemId,
    Guid? ReleaseId,
    string? ReviewNotes,
    string? BuildDiagnosticsJson,
    string? BuildPolicyVersion,
    JsonElement? ScanEvidence,
    JsonElement? ParityStatistics,
    JsonElement? ListingMetrics,
    JsonElement? SourceDiffSummary,
    string? SbomSha256,
    IReadOnlyList<string> DeclaredCapabilities)
{
    internal static SubmissionResponse From(MarketplaceSubmission submission) =>
        new(
            submission.Id,
            submission.Slug,
            submission.Title,
            submission.Description,
            submission.Version,
            submission.PriceInCents,
            submission.PriceMode,
            submission.Currency,
            submission.RequestedExecutionClass,
            submission.Status,
            submission.SourceSha256,
            submission.ArtifactSha256,
            submission.ParityStatisticsSha256,
            submission.ListingMetricsSha256,
            submission.SourceReview,
            submission.DeclaredBehaviorReview,
            submission.DiffReview,
            submission.CatalogItemId,
            submission.ReleaseId,
            submission.ReviewNotes,
            submission.BuildDiagnosticsJson,
            submission.BuildPolicyVersion,
            ParseOptionalJson(submission.ScanEvidenceJson),
            ParseOptionalJson(submission.ParityStatisticsJson),
            ParseOptionalJson(submission.ListingMetricsJson),
            ParseOptionalJson(submission.SourceDiffSummaryJson),
            submission.SbomSha256,
            JsonSerializer.Deserialize<string[]>(submission.DeclaredCapabilitiesJson) ?? []);

    private static JsonElement? ParseOptionalJson(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : JsonSerializer.Deserialize<JsonElement>(value);
}

public sealed record SubmissionReviewPacketResponse(
    Guid Id,
    string Slug,
    string Version,
    SubmissionStatus Status,
    string SourceCode,
    string? PreviousApprovedSourceCode,
    string SourceSha256,
    IReadOnlyList<string> DeclaredCapabilities,
    string LicenseExpression,
    string? PreviousApprovedSourceSha256,
    JsonElement? SourceDiffSummary,
    string? BuildPolicyVersion,
    JsonElement? ScanEvidence,
    JsonElement? ParityStatistics,
    JsonElement? ListingMetrics,
    string? SbomSha256,
    string? SbomQuarantineUri,
    MarketplaceHumanReviewState SourceReview,
    MarketplaceHumanReviewState DeclaredBehaviorReview,
    MarketplaceHumanReviewState DiffReview)
{
    internal static SubmissionReviewPacketResponse From(MarketplaceReviewPacket packet)
    {
        var submission = packet.Submission;
        return new SubmissionReviewPacketResponse(
            submission.Id,
            submission.Slug,
            submission.Version,
            submission.Status,
            packet.SourceCode,
            packet.PreviousApprovedSourceCode,
            submission.SourceSha256,
            JsonSerializer.Deserialize<string[]>(submission.DeclaredCapabilitiesJson) ?? [],
            submission.LicenseExpression,
            submission.PreviousApprovedSourceSha256,
            ParseOptionalJson(submission.SourceDiffSummaryJson),
            submission.BuildPolicyVersion,
            ParseOptionalJson(submission.ScanEvidenceJson),
            ParseOptionalJson(submission.ParityStatisticsJson),
            ParseOptionalJson(submission.ListingMetricsJson),
            submission.SbomSha256,
            submission.SbomQuarantineUri,
            submission.SourceReview,
            submission.DeclaredBehaviorReview,
            submission.DiffReview);
    }

    private static JsonElement? ParseOptionalJson(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : JsonSerializer.Deserialize<JsonElement>(value);
}

public sealed record PublisherOnboardingResponse(
    string ConnectAccountId,
    MarketplacePublisherStatus Status,
    bool ChargesEnabled,
    bool PayoutsEnabled,
    string OnboardingUrl,
    DateTimeOffset ExpiresAt)
{
    internal static PublisherOnboardingResponse From(MarketplaceOnboardingResult result) =>
        new(
            result.Publisher.ConnectAccountId!,
            result.Publisher.Status,
            result.Publisher.ChargesEnabled,
            result.Publisher.PayoutsEnabled,
            result.Link.Url,
            result.Link.ExpiresAt);
}

public sealed record PublisherStatusResponse(
    string? ConnectAccountId,
    MarketplacePublisherStatus Status,
    bool DetailsSubmitted,
    bool ChargesEnabled,
    bool PayoutsEnabled,
    DateTimeOffset? UpdatedAt)
{
    internal static PublisherStatusResponse From(MarketplacePublisher? publisher) =>
        publisher is null
            ? new PublisherStatusResponse(
                ConnectAccountId: null,
                MarketplacePublisherStatus.NotStarted,
                DetailsSubmitted: false,
                ChargesEnabled: false,
                PayoutsEnabled: false,
                UpdatedAt: null)
            : new PublisherStatusResponse(
                publisher.ConnectAccountId,
                publisher.Status,
                publisher.DetailsSubmitted,
                publisher.ChargesEnabled,
                publisher.PayoutsEnabled,
                publisher.UpdatedAt);
}

public sealed record SellerSaleResponse(
    Guid OrderId,
    Guid CatalogItemId,
    Guid ReleaseId,
    string ListingTitle,
    long GrossAmountInCents,
    long ApplicationFeeInCents,
    long ReserveInCents,
    long SellerProceedsInCents,
    MarketplacePriceMode PriceMode,
    string Currency,
    OrderStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt)
{
    internal static SellerSaleResponse From(MarketplaceSellerSale sale) =>
        new(
            sale.Order.Id,
            sale.Order.CatalogItemId,
            sale.Order.ReleaseId,
            sale.Listing.Title,
            sale.Order.AmountInCents,
            sale.Order.ApplicationFeeInCents,
            sale.Order.ReserveInCents,
            sale.Order.SellerProceedsInCents,
            sale.Order.PriceMode,
            sale.Order.Currency,
            sale.Order.Status,
            sale.Order.CreatedAt,
            sale.Order.UpdatedAt);
}

public sealed record MarketplaceBalanceResponse(
    long AmountInMinorUnits,
    string Currency)
{
    internal static MarketplaceBalanceResponse From(MarketplaceBalanceAmount amount) =>
        new(amount.AmountInMinorUnits, amount.Currency);
}

public sealed record MarketplacePayoutResponse(
    string ProviderPayoutId,
    long AmountInMinorUnits,
    string Currency,
    string Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset ArrivalDate,
    string Method,
    bool Automatic,
    string? FailureCode)
{
    internal static MarketplacePayoutResponse From(MarketplacePayout payout) =>
        new(
            payout.ProviderPayoutId,
            payout.AmountInMinorUnits,
            payout.Currency,
            payout.Status,
            payout.CreatedAt,
            payout.ArrivalDate,
            payout.Method,
            payout.Automatic,
            payout.FailureCode);
}

public sealed record PublisherPayoutsResponse(
    string? ConnectAccountId,
    MarketplacePublisherStatus Status,
    bool PayoutsEnabled,
    string ReportingStatus,
    IReadOnlyList<MarketplaceBalanceResponse> Available,
    IReadOnlyList<MarketplaceBalanceResponse> Pending,
    IReadOnlyList<MarketplacePayoutResponse> Payouts,
    string? NextCursor)
{
    internal static PublisherPayoutsResponse From(MarketplacePublisherPayoutReport result)
    {
        if (result.Publisher is null
            || string.IsNullOrWhiteSpace(result.Publisher.ConnectAccountId)
            || result.Report is null)
        {
            return new PublisherPayoutsResponse(
                result.Publisher?.ConnectAccountId,
                result.Publisher?.Status ?? MarketplacePublisherStatus.NotStarted,
                result.Publisher?.PayoutsEnabled ?? false,
                "NotConnected",
                [],
                [],
                [],
                null);
        }

        return new PublisherPayoutsResponse(
            result.Publisher.ConnectAccountId,
            result.Publisher.Status,
            result.Publisher.PayoutsEnabled,
            "Available",
            result.Report.Available.Select(MarketplaceBalanceResponse.From).ToArray(),
            result.Report.Pending.Select(MarketplaceBalanceResponse.From).ToArray(),
            result.Report.Payouts.Select(MarketplacePayoutResponse.From).ToArray(),
            result.Report.NextCursor);
    }
}

public sealed record OrderResponse(
    Guid Id,
    Guid CatalogItemId,
    Guid ReleaseId,
    long AmountInCents,
    MarketplacePriceMode PriceMode,
    string Currency,
    long ApplicationFeeInCents,
    long ReserveInCents,
    long SellerProceedsInCents,
    string CommercialPolicyVersion,
    int PayoutDelayDays,
    bool AutomaticTaxEnabled,
    string TaxHandling,
    string MerchantOfRecord,
    OrderStatus Status,
    string? CheckoutUrl)
{
    internal static OrderResponse From(MarketplaceOrder order) =>
        new(
            order.Id,
            order.CatalogItemId,
            order.ReleaseId,
            order.AmountInCents,
            order.PriceMode,
            order.Currency,
            order.ApplicationFeeInCents,
            order.ReserveInCents,
            order.SellerProceedsInCents,
            order.CommercialPolicyVersion,
            order.PayoutDelayDays,
            order.AutomaticTaxEnabled,
            order.TaxHandling,
            order.MerchantOfRecord,
            order.Status,
            order.CheckoutUrl);
}

public sealed record ReviewResponse(
    Guid Id,
    int Rating,
    string Body,
    DateTimeOffset CreatedAt,
    bool VerifiedBuyer)
{
    internal static ReviewResponse From(MarketplaceVerifiedReview review) =>
        From(review.Review, review.VerifiedBuyer);

    internal static ReviewResponse From(MarketplaceReview review, bool verifiedBuyer) =>
        new(review.Id, review.Rating, review.Body, review.CreatedAt, verifiedBuyer);
}
