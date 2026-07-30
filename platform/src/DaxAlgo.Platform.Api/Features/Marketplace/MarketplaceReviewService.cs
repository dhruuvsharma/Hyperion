using System.Data;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class MarketplaceReviewService(
    PlatformDbContext database,
    IMarketplaceArtifactStore artifactStore,
    MarketplaceAttestationService attestationService,
    TimeProvider timeProvider)
{
    public async Task<MarketplaceSubmission> DecideAsync(
        Guid submissionId,
        bool approve,
        bool sourceReviewed,
        bool declaredBehaviorReviewed,
        bool diffReviewed,
        string? notes,
        CancellationToken cancellationToken)
    {
        var submission = await database.Submissions.SingleOrDefaultAsync(
            candidate => candidate.Id == submissionId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Submission not found.");
        if (submission.Status != SubmissionStatus.AwaitingReview
            || submission.ReleaseId is null
            || submission.CatalogItemId is null)
        {
            throw new PlatformConflictException("Only a successfully built submission can be reviewed.");
        }

        submission.SourceReview = ToReviewState(sourceReviewed);
        submission.DeclaredBehaviorReview = ToReviewState(declaredBehaviorReviewed);
        submission.DiffReview = ToReviewState(diffReviewed);
        submission.ReviewNotes = NormalizeNotes(notes);
        submission.UpdatedAt = timeProvider.GetUtcNow();
        if (!approve)
        {
            submission.Status = SubmissionStatus.Rejected;
            await database.SaveChangesAsync(cancellationToken);
            return submission;
        }

        if (!sourceReviewed || !declaredBehaviorReviewed || !diffReviewed)
        {
            throw new PlatformValidationException(
                "Approval requires source, declared-versus-implemented behavior, and prior-release diff review.");
        }

        var release = await database.StrategyReleases.SingleAsync(
            candidate => candidate.Id == submission.ReleaseId.Value,
            cancellationToken);
        var listing = await database.CatalogItems.SingleAsync(
            candidate => candidate.Id == submission.CatalogItemId.Value,
            cancellationToken);
        if (release.Status != MarketplaceReleaseStatus.Quarantined
            || listing.Status is not (CatalogItemStatus.Draft or CatalogItemStatus.Published))
        {
            throw new PlatformConflictException("The release is no longer in its reviewable quarantine state.");
        }

        if (listing.PriceInCents > 0)
        {
            var publisher = await database.MarketplacePublishers.AsNoTracking().SingleOrDefaultAsync(
                candidate => candidate.AccountId == submission.PublisherAccountId,
                cancellationToken);
            if (publisher is null
                || publisher.Status != MarketplacePublisherStatus.Complete
                || !publisher.DetailsSubmitted
                || !publisher.ChargesEnabled
                || !publisher.PayoutsEnabled
                || string.IsNullOrWhiteSpace(publisher.ConnectAccountId))
            {
                throw new PlatformConflictException(
                    "Paid publication requires completed Stripe Connect onboarding with charges and payouts enabled.");
            }
        }

        IDbContextTransaction? transaction = null;
        if (database.Database.IsRelational())
        {
            transaction = await database.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);
        }

        try
        {
            if (await database.StrategyReleases.AsNoTracking().AnyAsync(
                    candidate => candidate.Id != release.Id
                        && candidate.DiversificationSeedSha256 == release.DiversificationSeedSha256,
                    cancellationToken))
            {
                throw new PlatformConflictException(
                    "The diversification seed has already been used by a historical release.");
            }

            var attestation = await attestationService.CreateAsync(
                submission,
                release,
                cancellationToken);
            var approvedArtifact = await artifactStore.PromoteApprovedAsync(
                release.ArtifactBlobUri,
                release.Id,
                $"{submission.Slug}-{submission.Version}.daxq",
                release.ArtifactSha256,
                cancellationToken);
            var approvedSbom = await artifactStore.PromoteApprovedAsync(
                release.SbomBlobUri,
                release.Id,
                "sbom.spdx.json",
                release.SbomSha256,
                cancellationToken);
            var approvedAttestation = await artifactStore.PutApprovedMetadataAsync(
                release.Id,
                "marketplace-review.dsse.json",
                attestation,
                cancellationToken);

            var now = timeProvider.GetUtcNow();
            release.ArtifactBlobUri = approvedArtifact.Uri;
            release.SbomBlobUri = approvedSbom.Uri;
            release.AttestationBlobUri = approvedAttestation.Uri;
            release.AttestationSha256 = approvedAttestation.Sha256;
            release.Status = MarketplaceReleaseStatus.Approved;
            release.ApprovedAt = now;
            listing.Title = submission.Title;
            listing.Description = submission.Description;
            listing.Version = submission.Version;
            listing.PriceInCents = submission.PriceInCents;
            listing.PriceMode = submission.PriceMode;
            listing.Currency = submission.Currency;
            listing.UpdatedAt = now;
            submission.Status = SubmissionStatus.Approved;
            submission.UpdatedAt = now;
            await database.SaveChangesAsync(cancellationToken);
            if (transaction is not null)
            {
                await transaction.CommitAsync(cancellationToken);
            }

            return submission;
        }
        catch
        {
            if (transaction is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
            }

            throw;
        }
        finally
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync();
            }
        }
    }

    private static MarketplaceHumanReviewState ToReviewState(bool passed) =>
        passed ? MarketplaceHumanReviewState.Passed : MarketplaceHumanReviewState.Failed;

    private static string? NormalizeNotes(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return null;
        }

        var normalized = notes.Trim();
        if (normalized.Length > 1000)
        {
            throw new PlatformValidationException("Review notes may contain at most 1000 characters.");
        }

        return normalized;
    }
}
