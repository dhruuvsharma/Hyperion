using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed record MarketplaceCatalogView(
    CatalogItem Item,
    MarketplaceStrategyRelease Release,
    Profile Publisher,
    MarketplaceSubmission Submission,
    IReadOnlyList<MarketplaceVerifiedReview> Reviews);

public sealed record MarketplaceVerifiedReview(
    MarketplaceReview Review,
    bool VerifiedBuyer);

public sealed record MarketplacePage<T>(
    IReadOnlyList<T> Items,
    string? NextCursor);

public sealed record MarketplaceSellerSale(
    MarketplaceOrder Order,
    CatalogItem Listing);

public sealed record MarketplaceReviewPacket(
    MarketplaceSubmission Submission,
    string SourceCode,
    string? PreviousApprovedSourceCode);

public sealed class MarketplaceService(
    PlatformDbContext database,
    IMarketplaceArtifactStore artifactStore,
    MarketplaceSubmissionPipeline submissionPipeline,
    MarketplaceReviewService reviewService,
    MarketplaceGrantService grantService,
    IMarketplaceCommerceProvider commerceProvider,
    MarketplaceCommerceOptions commerceOptions,
    MarketplaceSubmissionOptions submissionOptions,
    TimeProvider timeProvider)
{
    public async Task<MarketplacePage<MarketplaceCatalogView>> GetCatalogAsync(
        string? query,
        string? cursor,
        int? pageSize,
        CancellationToken cancellationToken)
    {
        var normalizedQuery = query?.Trim();
        if (normalizedQuery?.Length > 100)
        {
            throw new PlatformValidationException("Catalog search may contain at most 100 characters.");
        }

        var limit = ValidatePageSize(pageSize);
        var decodedCursor = DecodeCursor<UpdatedCursor>(cursor);
        var catalogQuery =
            from item in database.CatalogItems.AsNoTracking()
            where item.Status == CatalogItemStatus.Published
            from release in database.StrategyReleases.AsNoTracking()
                .Where(candidate => candidate.CatalogItemId == item.Id
                    && candidate.Status == MarketplaceReleaseStatus.Approved)
                .OrderByDescending(candidate => candidate.ApprovedAt)
                .ThenByDescending(candidate => candidate.Id)
                .Take(1)
            join submission in database.Submissions.AsNoTracking()
                on release.SubmissionId equals submission.Id
            join publisher in database.Profiles.AsNoTracking()
                on item.PublisherAccountId equals publisher.Id
            select new
            {
                Item = item,
                Release = release,
                Publisher = publisher,
                Submission = submission,
            };
        if (!string.IsNullOrWhiteSpace(normalizedQuery))
        {
            if (database.Database.IsNpgsql())
            {
                var searchPattern = $"%{EscapeLikePattern(normalizedQuery)}%";
                catalogQuery = catalogQuery.Where(view =>
                    EF.Functions.ILike(view.Item.Title, searchPattern, "\\")
                    || EF.Functions.ILike(view.Item.Description, searchPattern, "\\")
                    || EF.Functions.ILike(view.Item.Slug, searchPattern, "\\")
                    || EF.Functions.ILike(view.Release.ExecutionClass, searchPattern, "\\")
                    || EF.Functions.ILike(view.Publisher.DisplayName, searchPattern, "\\"));
            }
            else
            {
                catalogQuery = catalogQuery.Where(view =>
                    view.Item.Title.Contains(normalizedQuery, StringComparison.OrdinalIgnoreCase)
                    || view.Item.Description.Contains(normalizedQuery, StringComparison.OrdinalIgnoreCase)
                    || view.Item.Slug.Contains(normalizedQuery, StringComparison.OrdinalIgnoreCase)
                    || view.Release.ExecutionClass.Contains(normalizedQuery, StringComparison.OrdinalIgnoreCase)
                    || view.Publisher.DisplayName.Contains(normalizedQuery, StringComparison.OrdinalIgnoreCase));
            }
        }

        if (decodedCursor is not null)
        {
            catalogQuery = catalogQuery.Where(view => view.Item.UpdatedAt < decodedCursor.UpdatedAt
                || (view.Item.UpdatedAt == decodedCursor.UpdatedAt
                    && view.Item.Id.CompareTo(decodedCursor.Id) < 0));
        }

        var rows = await catalogQuery
            .OrderByDescending(view => view.Item.UpdatedAt)
            .ThenByDescending(view => view.Item.Id)
            .Take(limit + 1)
            .ToListAsync(cancellationToken);
        var hasMore = rows.Count > limit;
        var page = rows.Take(limit)
            .Select(view => new MarketplaceCatalogView(
                view.Item,
                view.Release,
                view.Publisher,
                view.Submission,
                []))
            .ToArray();
        var last = page.LastOrDefault()?.Item;
        return new MarketplacePage<MarketplaceCatalogView>(
            page,
            hasMore && last is not null
                ? EncodeCursor(new UpdatedCursor(last.UpdatedAt, last.Id))
                : null);
    }

    public async Task<MarketplaceCatalogView> GetCatalogItemAsync(
        Guid id,
        CancellationToken cancellationToken)
    {
        var item = await database.CatalogItems.AsNoTracking()
            .SingleOrDefaultAsync(
                candidate => candidate.Id == id
                    && candidate.Status == CatalogItemStatus.Published,
                cancellationToken)
            ?? throw new PlatformNotFoundException("Catalog item not found.");
        var release = await RequireLatestApprovedReleaseAsync(item.Id, cancellationToken);
        var publisher = await database.Profiles.AsNoTracking().SingleOrDefaultAsync(
            candidate => candidate.Id == item.PublisherAccountId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("The catalog publisher was not found.");
        var submission = await database.Submissions.AsNoTracking().SingleOrDefaultAsync(
            candidate => candidate.Id == release.SubmissionId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("The catalog review record was not found.");
        var reviews = await GetVerifiedReviewsAsync(item.Id, cancellationToken);
        return new MarketplaceCatalogView(item, release, publisher, submission, reviews);
    }

    public async Task<MarketplacePage<MarketplaceSubmission>> GetSubmissionsAsync(
        Guid publisherAccountId,
        string? cursor,
        int? pageSize,
        CancellationToken cancellationToken)
    {
        var limit = ValidatePageSize(pageSize);
        var decodedCursor = DecodeCursor<UpdatedCursor>(cursor);
        var query = database.Submissions.AsNoTracking()
            .Where(submission => submission.PublisherAccountId == publisherAccountId);
        if (decodedCursor is not null)
        {
            query = query.Where(submission => submission.UpdatedAt < decodedCursor.UpdatedAt
                || (submission.UpdatedAt == decodedCursor.UpdatedAt
                    && submission.Id.CompareTo(decodedCursor.Id) < 0));
        }

        var submissions = await query
            .OrderByDescending(submission => submission.UpdatedAt)
            .ThenByDescending(submission => submission.Id)
            .Take(limit + 1)
            .ToListAsync(cancellationToken);
        var hasMore = submissions.Count > limit;
        var page = submissions.Take(limit).ToArray();
        var last = page.LastOrDefault();
        return new MarketplacePage<MarketplaceSubmission>(
            page,
            hasMore && last is not null
                ? EncodeCursor(new UpdatedCursor(last.UpdatedAt, last.Id))
                : null);
    }

    public async Task<MarketplaceSubmission> GetSubmissionAsync(
        Guid publisherAccountId,
        Guid submissionId,
        CancellationToken cancellationToken) =>
        await database.Submissions.AsNoTracking().SingleOrDefaultAsync(
            submission => submission.Id == submissionId
                && submission.PublisherAccountId == publisherAccountId,
            cancellationToken)
        ?? throw new PlatformNotFoundException("Marketplace submission not found.");

    public async Task<MarketplaceReviewPacket> GetReviewPacketAsync(
        Guid submissionId,
        CancellationToken cancellationToken)
    {
        var submission = await database.Submissions.AsNoTracking().SingleOrDefaultAsync(
            candidate => candidate.Id == submissionId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Submission not found.");
        var sourceCode = await ReadVerifiedSourceAsync(
            submission.SourceQuarantineUri,
            submission.SourceSha256,
            cancellationToken);
        string? previousApprovedSourceCode = null;
        if (submission.CatalogItemId is not null
            && !string.IsNullOrWhiteSpace(submission.PreviousApprovedSourceSha256))
        {
            var previousSubmission = await database.Submissions.AsNoTracking()
                .Where(candidate => candidate.Id != submission.Id
                    && candidate.CatalogItemId == submission.CatalogItemId
                    && candidate.Status == SubmissionStatus.Approved
                    && candidate.SourceSha256 == submission.PreviousApprovedSourceSha256)
                .OrderByDescending(candidate => candidate.UpdatedAt)
                .FirstOrDefaultAsync(cancellationToken);
            if (previousSubmission is not null)
            {
                previousApprovedSourceCode = await ReadVerifiedSourceAsync(
                    previousSubmission.SourceQuarantineUri,
                    previousSubmission.SourceSha256,
                    cancellationToken);
            }
        }

        return new MarketplaceReviewPacket(
            submission,
            sourceCode,
            previousApprovedSourceCode);
    }

    public async Task<MarketplaceSubmission> CreateSubmissionAsync(
        Guid publisherAccountId,
        string slug,
        string title,
        string description,
        string version,
        long priceInCents,
        MarketplacePriceMode priceMode,
        string currency,
        string sourceCode,
        string referenceDatasetJson,
        IReadOnlyList<string>? declaredCapabilities,
        string licenseExpression,
        string? requestedExecutionClass,
        CancellationToken cancellationToken)
    {
        ValidateListing(slug, title, description, version, priceInCents, priceMode, currency);
        if (!string.Equals(
                currency.Trim(),
                commerceOptions.Currency.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new PlatformValidationException(
                "The listing currency must match the configured marketplace currency.");
        }

        ValidateSubmissionPayload(sourceCode, referenceDatasetJson, declaredCapabilities, licenseExpression);
        var executionClass = MarketplaceExecutionClasses.NormalizeRequested(requestedExecutionClass);
        if (await database.CatalogItems.AnyAsync(
                item => item.Slug == slug && item.PublisherAccountId != publisherAccountId,
                cancellationToken)
            || await database.Submissions.AnyAsync(
                submission => submission.Slug == slug
                    && (submission.Status == SubmissionStatus.Draft
                        || submission.Status == SubmissionStatus.Processing
                        || submission.Status == SubmissionStatus.AwaitingReview),
                cancellationToken))
        {
            throw new PlatformConflictException("That marketplace slug is already in use.");
        }

        var source = Encoding.UTF8.GetBytes(sourceCode);
        var dataset = Encoding.UTF8.GetBytes(referenceDatasetJson);
        if (source.Length > submissionOptions.MaximumSourceBytes
            || dataset.Length > submissionOptions.MaximumReferenceDatasetBytes)
        {
            throw new PlatformValidationException(
                "The source or parity reference dataset exceeds the configured upload limit.");
        }
        var sourceObject = await artifactStore.PutQuarantineAsync(
            "source",
            source,
            cancellationToken);
        var datasetObject = await artifactStore.PutQuarantineAsync(
            "dataset",
            dataset,
            cancellationToken);
        var now = timeProvider.GetUtcNow();
        var submission = new MarketplaceSubmission
        {
            Id = Guid.NewGuid(),
            PublisherAccountId = publisherAccountId,
            Slug = slug,
            Title = title.Trim(),
            Description = description.Trim(),
            Version = version.Trim(),
            PriceInCents = priceInCents,
            PriceMode = priceMode,
            Currency = currency.Trim().ToUpperInvariant(),
            SourceSha256 = sourceObject.Sha256,
            SourceQuarantineUri = sourceObject.Uri,
            ReferenceDatasetSha256 = datasetObject.Sha256,
            ReferenceDatasetQuarantineUri = datasetObject.Uri,
            DeclaredCapabilitiesJson = JsonSerializer.Serialize(
                (declaredCapabilities ?? []).Select(capability => capability.Trim())
                    .Order(StringComparer.Ordinal)
                    .ToArray()),
            RequestedExecutionClass = executionClass,
            LicenseExpression = licenseExpression.Trim(),
            Status = SubmissionStatus.Draft,
            SourceReview = MarketplaceHumanReviewState.Pending,
            DeclaredBehaviorReview = MarketplaceHumanReviewState.Pending,
            DiffReview = MarketplaceHumanReviewState.Pending,
            CreatedAt = now,
            UpdatedAt = now,
        };
        database.Submissions.Add(submission);
        await database.SaveChangesAsync(cancellationToken);
        return submission;
    }

    public Task<MarketplaceSubmission> SubmitAsync(
        Guid publisherAccountId,
        Guid submissionId,
        CancellationToken cancellationToken) =>
        submissionPipeline.ProcessAsync(
            publisherAccountId,
            submissionId,
            cancellationToken);

    public Task<MarketplaceSubmission> DecideAsync(
        Guid submissionId,
        bool approve,
        bool sourceReviewed,
        bool declaredBehaviorReviewed,
        bool diffReviewed,
        string? notes,
        CancellationToken cancellationToken) =>
        reviewService.DecideAsync(
            submissionId,
            approve,
            sourceReviewed,
            declaredBehaviorReviewed,
            diffReviewed,
            notes,
            cancellationToken);

    public async Task<MarketplacePage<CatalogItem>> GetListingsAsync(
        Guid publisherAccountId,
        string? cursor,
        int? pageSize,
        CancellationToken cancellationToken)
    {
        var limit = ValidatePageSize(pageSize);
        var decodedCursor = DecodeCursor<UpdatedCursor>(cursor);
        var query = database.CatalogItems.AsNoTracking()
            .Where(item => item.PublisherAccountId == publisherAccountId);
        if (decodedCursor is not null)
        {
            query = query.Where(item => item.UpdatedAt < decodedCursor.UpdatedAt
                || (item.UpdatedAt == decodedCursor.UpdatedAt
                    && item.Id.CompareTo(decodedCursor.Id) < 0));
        }

        var listings = await query
            .OrderByDescending(item => item.UpdatedAt)
            .ThenByDescending(item => item.Id)
            .Take(limit + 1)
            .ToListAsync(cancellationToken);
        var hasMore = listings.Count > limit;
        var page = listings.Take(limit).ToArray();
        var last = page.LastOrDefault();
        return new MarketplacePage<CatalogItem>(
            page,
            hasMore && last is not null
                ? EncodeCursor(new UpdatedCursor(last.UpdatedAt, last.Id))
                : null);
    }

    public async Task<CatalogItem> GetListingAsync(
        Guid publisherAccountId,
        Guid catalogItemId,
        CancellationToken cancellationToken) =>
        await database.CatalogItems.AsNoTracking().SingleOrDefaultAsync(
            item => item.Id == catalogItemId
                && item.PublisherAccountId == publisherAccountId,
            cancellationToken)
        ?? throw new PlatformNotFoundException("Marketplace listing not found.");

    public async Task<CatalogItem> UpdateListingAsync(
        Guid publisherAccountId,
        Guid catalogItemId,
        string title,
        string description,
        string templateCopyJson,
        IReadOnlyList<string>? mediaUrls,
        long priceInCents,
        MarketplacePriceMode priceMode,
        CancellationToken cancellationToken)
    {
        var listing = await RequireOwnedListingAsync(
            publisherAccountId,
            catalogItemId,
            cancellationToken);
        ValidateListing(
            listing.Slug,
            title,
            description,
            listing.Version,
            priceInCents,
            priceMode,
            listing.Currency);
        ValidateTemplateJson(templateCopyJson);
        var normalizedMedia = NormalizeMedia(mediaUrls);
        if (priceInCents > 0)
        {
            await RequirePaymentReadyPublisherAsync(publisherAccountId, cancellationToken);
        }

        listing.Title = title.Trim();
        listing.Description = description.Trim();
        listing.TemplateCopyJson = templateCopyJson;
        listing.MediaJson = JsonSerializer.Serialize(normalizedMedia);
        listing.PriceInCents = priceInCents;
        listing.PriceMode = priceMode;
        listing.UpdatedAt = timeProvider.GetUtcNow();
        await database.SaveChangesAsync(cancellationToken);
        return listing;
    }

    public async Task<CatalogItem> PublishListingAsync(
        Guid publisherAccountId,
        Guid catalogItemId,
        CancellationToken cancellationToken)
    {
        var listing = await RequireOwnedListingAsync(
            publisherAccountId,
            catalogItemId,
            cancellationToken);
        _ = await RequireLatestApprovedReleaseAsync(listing.Id, cancellationToken);
        if (listing.PriceInCents > 0)
        {
            await RequirePaymentReadyPublisherAsync(publisherAccountId, cancellationToken);
        }

        listing.Status = CatalogItemStatus.Published;
        listing.UpdatedAt = timeProvider.GetUtcNow();
        await database.SaveChangesAsync(cancellationToken);
        return listing;
    }

    public Task<List<MarketplaceOrder>> GetOrdersAsync(
        Guid buyerAccountId,
        CancellationToken cancellationToken) =>
        database.Orders.AsNoTracking()
            .Where(order => order.BuyerAccountId == buyerAccountId)
            .OrderByDescending(order => order.CreatedAt)
            .ToListAsync(cancellationToken);

    public async Task<MarketplacePage<MarketplaceSellerSale>> GetSellerSalesAsync(
        Guid publisherAccountId,
        string? cursor,
        int? pageSize,
        CancellationToken cancellationToken)
    {
        var limit = ValidatePageSize(pageSize);
        var decodedCursor = DecodeCursor<UpdatedCursor>(cursor);
        var query =
            from order in database.Orders.AsNoTracking()
            join listing in database.CatalogItems.AsNoTracking()
                on order.CatalogItemId equals listing.Id
            where listing.PublisherAccountId == publisherAccountId
            select new
            {
                Order = order,
                Listing = listing,
            };
        if (decodedCursor is not null)
        {
            query = query.Where(sale => sale.Order.UpdatedAt < decodedCursor.UpdatedAt
                || (sale.Order.UpdatedAt == decodedCursor.UpdatedAt
                    && sale.Order.Id.CompareTo(decodedCursor.Id) < 0));
        }

        var sales = await query
            .OrderByDescending(sale => sale.Order.UpdatedAt)
            .ThenByDescending(sale => sale.Order.Id)
            .Take(limit + 1)
            .ToListAsync(cancellationToken);
        var hasMore = sales.Count > limit;
        var page = sales.Take(limit)
            .Select(sale => new MarketplaceSellerSale(sale.Order, sale.Listing))
            .ToArray();
        var last = page.LastOrDefault()?.Order;
        return new MarketplacePage<MarketplaceSellerSale>(
            page,
            hasMore && last is not null
                ? EncodeCursor(new UpdatedCursor(last.UpdatedAt, last.Id))
                : null);
    }

    public async Task<MarketplaceOrder> CreateOrderAsync(
        Guid buyerAccountId,
        Guid catalogItemId,
        CancellationToken cancellationToken)
    {
        EnsureSalesEnabled();

        var catalog = await GetCatalogItemAsync(catalogItemId, cancellationToken);
        if (await database.Orders.AnyAsync(
                order => order.BuyerAccountId == buyerAccountId
                    && order.CatalogItemId == catalogItemId
                    && order.Status == OrderStatus.Paid,
                cancellationToken))
        {
            throw new PlatformConflictException("The account already owns this catalog item.");
        }

        MarketplacePublisher? publisher = null;
        if (catalog.Item.PriceInCents > 0)
        {
            publisher = await RequirePaymentReadyPublisherAsync(
                catalog.Item.PublisherAccountId,
                cancellationToken);
        }

        var applicationFee = CalculateBasisPoints(
            catalog.Item.PriceInCents,
            commerceOptions.ApplicationFeeBasisPoints);
        var reserve = CalculateBasisPoints(
            catalog.Item.PriceInCents,
            commerceOptions.ReserveBasisPoints);
        var now = timeProvider.GetUtcNow();
        var order = new MarketplaceOrder
        {
            Id = Guid.NewGuid(),
            BuyerAccountId = buyerAccountId,
            CatalogItemId = catalog.Item.Id,
            ReleaseId = catalog.Release.Id,
            AmountInCents = catalog.Item.PriceInCents,
            PriceMode = catalog.Item.PriceMode,
            Currency = catalog.Item.Currency,
            ApplicationFeeInCents = applicationFee,
            ReserveInCents = reserve,
            SellerProceedsInCents = checked(catalog.Item.PriceInCents - applicationFee - reserve),
            CommercialPolicyVersion = commerceOptions.PolicyVersion,
            PayoutDelayDays = commerceOptions.PayoutDelayDays,
            AutomaticTaxEnabled = commerceOptions.AutomaticTaxEnabled,
            TaxHandling = commerceOptions.TaxHandling.Trim(),
            MerchantOfRecord = commerceOptions.MerchantOfRecord.Trim(),
            Status = OrderStatus.Pending,
            CreatedAt = now,
            UpdatedAt = now,
        };
        database.Orders.Add(order);
        await database.SaveChangesAsync(cancellationToken);

        if (catalog.Item.PriceInCents == 0)
        {
            order.ProviderCheckoutId = $"free_{order.Id:N}";
            await grantService.ActivateAsync(
                order.Id,
                subscriptionValidUntil: null,
                providerSubscriptionId: null,
                cancellationToken);
            return order;
        }

        var checkout = await commerceProvider.CreateCheckoutAsync(
            new MarketplaceCheckoutRequest(
                order.Id,
                catalog.Item.Id,
                catalog.Release.Id,
                buyerAccountId,
                publisher!.ConnectAccountId!,
                catalog.Item.Title,
                catalog.Item.PriceInCents,
                catalog.Item.Currency,
                catalog.Item.PriceMode == MarketplacePriceMode.OneTime
                    ? MarketplacePricingMode.OneTime
                    : MarketplacePricingMode.MonthlySubscription,
                $"marketplace-checkout:{order.Id:N}"),
            cancellationToken);
        order.ProviderCheckoutId = checkout.ProviderCheckoutId;
        order.CheckoutUrl = checkout.CheckoutUrl;
        order.UpdatedAt = timeProvider.GetUtcNow();
        await database.SaveChangesAsync(cancellationToken);
        return order;
    }

    public void EnsureSalesEnabled()
    {
        if (!commerceOptions.SalesEnabled)
        {
            throw new PlatformForbiddenException(
                "Marketplace sales are disabled pending the GA commercial and security gate.");
        }
    }

    public async Task<IReadOnlyList<MarketplaceVerifiedReview>> GetReviewsAsync(
        Guid catalogItemId,
        CancellationToken cancellationToken)
    {
        if (!await database.CatalogItems.AsNoTracking().AnyAsync(
                item => item.Id == catalogItemId
                    && item.Status == CatalogItemStatus.Published,
                cancellationToken))
        {
            throw new PlatformNotFoundException("Catalog item not found.");
        }

        return await GetVerifiedReviewsAsync(catalogItemId, cancellationToken);
    }

    public async Task<MarketplaceReview> CreateReviewAsync(
        Guid authorAccountId,
        Guid catalogItemId,
        int rating,
        string body,
        CancellationToken cancellationToken)
    {
        if (rating is < 1 or > 5)
        {
            throw new PlatformValidationException("Rating must be between 1 and 5.");
        }

        var normalizedBody = body.Trim();
        if (normalizedBody.Length is < 1 or > 2000)
        {
            throw new PlatformValidationException("Review body must contain 1 to 2000 characters.");
        }

        if (!await database.EntitlementGrants.AnyAsync(
                grant => grant.AccountId == authorAccountId
                    && grant.CatalogItemId == catalogItemId
                    && grant.Status == EntitlementGrantStatus.Active
                    && grant.ValidUntil > timeProvider.GetUtcNow(),
                cancellationToken))
        {
            throw new PlatformConflictException("Only a verified purchaser can review this item.");
        }

        if (await database.Reviews.AnyAsync(
                review => review.AuthorAccountId == authorAccountId
                    && review.CatalogItemId == catalogItemId,
                cancellationToken))
        {
            throw new PlatformConflictException("The account has already reviewed this item.");
        }

        var now = timeProvider.GetUtcNow();
        var review = new MarketplaceReview
        {
            Id = Guid.NewGuid(),
            CatalogItemId = catalogItemId,
            AuthorAccountId = authorAccountId,
            Rating = rating,
            Body = normalizedBody,
            Status = ReviewStatus.Published,
            CreatedAt = now,
            UpdatedAt = now,
        };
        database.Reviews.Add(review);
        await database.SaveChangesAsync(cancellationToken);
        return review;
    }

    private async Task<CatalogItem> RequireOwnedListingAsync(
        Guid publisherAccountId,
        Guid catalogItemId,
        CancellationToken cancellationToken) =>
        await database.CatalogItems.SingleOrDefaultAsync(
            item => item.Id == catalogItemId
                && item.PublisherAccountId == publisherAccountId,
            cancellationToken)
        ?? throw new PlatformNotFoundException("Marketplace listing not found.");

    private async Task<MarketplacePublisher> RequirePaymentReadyPublisherAsync(
        Guid publisherAccountId,
        CancellationToken cancellationToken)
    {
        var publisher = await database.MarketplacePublishers.AsNoTracking().SingleOrDefaultAsync(
            candidate => candidate.AccountId == publisherAccountId,
            cancellationToken);
        if (publisher is null
            || publisher.Status != MarketplacePublisherStatus.Complete
            || !publisher.DetailsSubmitted
            || !publisher.ChargesEnabled
            || !publisher.PayoutsEnabled
            || string.IsNullOrWhiteSpace(publisher.ConnectAccountId))
        {
            throw new PlatformConflictException(
                "The publisher has not completed Stripe Connect onboarding for charges and payouts.");
        }

        return publisher;
    }

    private async Task<MarketplaceStrategyRelease> RequireLatestApprovedReleaseAsync(
        Guid catalogItemId,
        CancellationToken cancellationToken) =>
        await database.StrategyReleases.AsNoTracking()
            .Where(release => release.CatalogItemId == catalogItemId
                && release.Status == MarketplaceReleaseStatus.Approved)
            .OrderByDescending(release => release.ApprovedAt)
            .FirstOrDefaultAsync(cancellationToken)
        ?? throw new PlatformNotFoundException("The marketplace listing has no approved release.");

    private static void ValidateListing(
        string slug,
        string title,
        string description,
        string version,
        long priceInCents,
        MarketplacePriceMode priceMode,
        string currency)
    {
        if (slug.Length is < 3 or > 100
            || slug.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '-'))
            || !string.Equals(slug, slug.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw new PlatformValidationException(
                "Slug must contain 3 to 100 lowercase ASCII letters, digits, or hyphens.");
        }

        if (title.Trim().Length is < 3 or > 160)
        {
            throw new PlatformValidationException("Title must contain 3 to 160 characters.");
        }

        if (description.Trim().Length is < 10 or > 4000)
        {
            throw new PlatformValidationException("Description must contain 10 to 4000 characters.");
        }

        if (version.Trim().Length is < 1 or > 40)
        {
            throw new PlatformValidationException("Version must contain 1 to 40 characters.");
        }

        if (priceInCents is < 0 or > 1_000_000)
        {
            throw new PlatformValidationException("Price must be between 0 and 1,000,000 minor currency units.");
        }

        if (!Enum.IsDefined(priceMode))
        {
            throw new PlatformValidationException("The marketplace price mode is invalid.");
        }

        if (priceMode == MarketplacePriceMode.Subscription && priceInCents == 0)
        {
            throw new PlatformValidationException(
                "A marketplace subscription must have a positive price.");
        }

        if (currency.Trim().Length != 3
            || currency.Any(character => !char.IsAsciiLetter(character)))
        {
            throw new PlatformValidationException("Currency must be a three-letter ISO code.");
        }
    }

    private static void ValidateSubmissionPayload(
        string sourceCode,
        string referenceDatasetJson,
        IReadOnlyList<string>? declaredCapabilities,
        string licenseExpression)
    {
        if (string.IsNullOrWhiteSpace(sourceCode))
        {
            throw new PlatformValidationException("Strategy source is required.");
        }

        try
        {
            using var dataset = JsonDocument.Parse(referenceDatasetJson);
            if (dataset.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException();
            }
        }
        catch (JsonException)
        {
            throw new PlatformValidationException("The parity reference dataset must be a JSON object.");
        }

        if (declaredCapabilities is { Count: > 32 }
            || declaredCapabilities?.Any(capability => string.IsNullOrWhiteSpace(capability)
                || capability.Trim().Length > 100) == true)
        {
            throw new PlatformValidationException(
                "Declare at most 32 non-empty capabilities of at most 100 characters each.");
        }

        if (string.IsNullOrWhiteSpace(licenseExpression)
            || licenseExpression.Trim().Length > 100)
        {
            throw new PlatformValidationException(
                "A bounded SPDX expression or 'Proprietary' declaration is required.");
        }
    }

    private static void ValidateTemplateJson(string templateCopyJson)
    {
        if (Encoding.UTF8.GetByteCount(templateCopyJson) > 64 * 1024)
        {
            throw new PlatformValidationException("Listing template copy may contain at most 64 KiB.");
        }

        try
        {
            using var document = JsonDocument.Parse(templateCopyJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new JsonException();
            }
        }
        catch (JsonException)
        {
            throw new PlatformValidationException("Listing template copy must be a JSON object.");
        }
    }

    private static List<string> NormalizeMedia(IReadOnlyList<string>? mediaUrls)
    {
        if (mediaUrls is null)
        {
            return [];
        }

        if (mediaUrls.Count > 8)
        {
            throw new PlatformValidationException("A listing may contain at most eight media URLs.");
        }

        var normalized = new List<string>(mediaUrls.Count);
        foreach (var value in mediaUrls)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                || !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new PlatformValidationException(
                    "Listing media must use absolute HTTPS URLs without fragments.");
            }

            normalized.Add(uri.AbsoluteUri);
        }

        return normalized;
    }

    private static long CalculateBasisPoints(long amount, int basisPoints) =>
        checked((long)decimal.Round(
            amount * basisPoints / 10_000m,
            decimals: 0,
            MidpointRounding.AwayFromZero));

    private static string EscapeLikePattern(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);

    private async Task<string> ReadVerifiedSourceAsync(
        string uri,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        var source = (await artifactStore.ReadAsync(uri, cancellationToken)).ToArray();
        byte[] expectedHash;
        try
        {
            expectedHash = Convert.FromHexString(expectedSha256);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                "The submission source hash is invalid.",
                exception);
        }

        var actualHash = SHA256.HashData(source);
        if (expectedHash.Length != actualHash.Length
            || !CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
        {
            throw new InvalidOperationException(
                "The immutable source no longer matches the reviewed submission hash.");
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(source);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidOperationException(
                "The immutable submission source is no longer valid UTF-8.",
                exception);
        }
    }

    private async Task<IReadOnlyList<MarketplaceVerifiedReview>> GetVerifiedReviewsAsync(
        Guid catalogItemId,
        CancellationToken cancellationToken)
    {
        var reviews = await database.Reviews.AsNoTracking()
            .Where(review => review.CatalogItemId == catalogItemId
                && review.Status == ReviewStatus.Published
                && database.Orders.Any(order => order.CatalogItemId == review.CatalogItemId
                    && order.BuyerAccountId == review.AuthorAccountId
                    && order.Status == OrderStatus.Paid))
            .OrderByDescending(review => review.CreatedAt)
            .ToListAsync(cancellationToken);
        return reviews.Select(review => new MarketplaceVerifiedReview(review, true)).ToArray();
    }

    private static int ValidatePageSize(int? pageSize)
    {
        if (pageSize is < 1 or > 100)
        {
            throw new PlatformValidationException("Page size must be between 1 and 100.");
        }

        return pageSize ?? 50;
    }

    private static T? DecodeCursor<T>(string? cursor)
        where T : class
    {
        if (string.IsNullOrWhiteSpace(cursor))
        {
            return null;
        }

        if (cursor.Length > 1024)
        {
            throw new PlatformValidationException("The pagination cursor is invalid.");
        }

        try
        {
            var bytes = DecodeBase64Url(cursor);
            var decoded = JsonSerializer.Deserialize<T>(bytes)
                ?? throw new JsonException();
            if (decoded is UpdatedCursor updated
                && (updated.UpdatedAt == default || updated.Id == Guid.Empty))
            {
                throw new JsonException();
            }

            return decoded;
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            throw new PlatformValidationException("The pagination cursor is invalid.");
        }
    }

    private static string EncodeCursor<T>(T cursor) =>
        Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(cursor))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] DecodeBase64Url(string value)
    {
        if (value.Any(character => !(char.IsAsciiLetterOrDigit(character)
            || character is '-' or '_')))
        {
            throw new FormatException();
        }

        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = (normalized.Length % 4) switch
        {
            0 => normalized,
            2 => normalized + "==",
            3 => normalized + "=",
            _ => throw new FormatException(),
        };
        return Convert.FromBase64String(normalized);
    }

    private sealed record UpdatedCursor(DateTimeOffset UpdatedAt, Guid Id);

}
