using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class MarketplaceSubmissionOptions
{
    public const string SectionName = "MarketplaceSubmission";

    public int MaximumSourceBytes { get; init; } = 1024 * 1024;

    public int MaximumReferenceDatasetBytes { get; init; } = 8 * 1024 * 1024;

    public string CapabilityPolicyVersion { get; init; } = "marketplace-source-policy-v1";
}

public sealed class MarketplaceSubmissionPipeline(
    PlatformDbContext database,
    IMarketplaceArtifactStore artifactStore,
    IMarketplaceBuildWorker buildWorker,
    IContentKeyProvisioningProvider contentKeyProvisioner,
    MarketplaceSubmissionOptions options,
    TimeProvider timeProvider)
{
    public const string RestrictedExecutionClass = MarketplaceExecutionClasses.RestrictedOnly;
    public const string ParityStatisticsSchemaVersion = "daxq-backtest-parity-stats-v1";
    public const string ListingMetricsSchemaVersion = "daxq-listing-metrics-v1";

    public async Task<MarketplaceSubmission> ProcessAsync(
        Guid publisherAccountId,
        Guid submissionId,
        CancellationToken cancellationToken)
    {
        var submission = await database.Submissions.SingleOrDefaultAsync(
            candidate => candidate.Id == submissionId
                && candidate.PublisherAccountId == publisherAccountId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Submission not found.");
        if (submission.Status != SubmissionStatus.Draft)
        {
            throw new PlatformConflictException("Only a draft submission can enter the build pipeline.");
        }

        var source = (await artifactStore.ReadAsync(
            submission.SourceQuarantineUri,
            cancellationToken)).ToArray();
        var referenceDataset = (await artifactStore.ReadAsync(
            submission.ReferenceDatasetQuarantineUri,
            cancellationToken)).ToArray();
        VerifyHash(source, submission.SourceSha256, "source");
        VerifyHash(referenceDataset, submission.ReferenceDatasetSha256, "reference dataset");
        var preflightDiagnostics = MarketplaceSourcePolicyAnalyzer.Analyze(
            source,
            submission.LicenseExpression,
            options);
        if (preflightDiagnostics.Count != 0)
        {
            submission.Status = SubmissionStatus.Blocked;
            submission.BuildPolicyVersion = options.CapabilityPolicyVersion;
            submission.BuildDiagnosticsJson = JsonSerializer.Serialize(preflightDiagnostics);
            submission.UpdatedAt = timeProvider.GetUtcNow();
            await database.SaveChangesAsync(cancellationToken);
            return submission;
        }

        var seed = RandomNumberGenerator.GetBytes(32);
        var seedSha256 = Convert.ToHexStringLower(SHA256.HashData(seed));
        var declaredCapabilities =
            JsonSerializer.Deserialize<string[]>(submission.DeclaredCapabilitiesJson) ?? [];
        if (await database.StrategyReleases.AnyAsync(
                release => release.DiversificationSeedSha256 == seedSha256,
                cancellationToken))
        {
            CryptographicOperations.ZeroMemory(seed);
            throw new InvalidOperationException("A generated diversification seed unexpectedly collided with release history.");
        }

        submission.Status = SubmissionStatus.Processing;
        submission.DiversificationSeedSha256 = seedSha256;
        submission.BuildPolicyVersion = options.CapabilityPolicyVersion;
        submission.BuildDiagnosticsJson = "[]";
        submission.UpdatedAt = timeProvider.GetUtcNow();
        await database.SaveChangesAsync(cancellationToken);

        MarketplaceBuildResult result;
        try
        {
            result = await buildWorker.RunAsync(
                new MarketplaceBuildRequest(
                    submission.Id,
                    submission.Slug,
                    submission.Version,
                    source,
                    referenceDataset,
                    seed,
                    declaredCapabilities,
                    submission.LicenseExpression),
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }

        if (result.Decision != MarketplaceBuildDecision.Pass)
        {
            ZeroContentKey(result.ContentKey);
            submission.Status = result.Decision == MarketplaceBuildDecision.RetryableFailure
                ? SubmissionStatus.Draft
                : SubmissionStatus.Blocked;
            submission.BuildPolicyVersion = result.PolicyVersion;
            submission.BuildDiagnosticsJson = JsonSerializer.Serialize(result.Diagnostics);
            submission.UpdatedAt = timeProvider.GetUtcNow();
            await database.SaveChangesAsync(cancellationToken);
            return submission;
        }

        var undeclaredCapabilities = result.ScanEvidence?.ImplementedCapabilities
            .Except(declaredCapabilities, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray() ?? [];
        if (undeclaredCapabilities.Length != 0)
        {
            ZeroContentKey(result.ContentKey);
            submission.Status = SubmissionStatus.Blocked;
            submission.BuildPolicyVersion = result.PolicyVersion;
            submission.BuildDiagnosticsJson = JsonSerializer.Serialize(
                undeclaredCapabilities.Select(
                    capability => $"CAPABILITY_BLOCK: Implemented capability '{capability}' was not declared."));
            submission.ScanEvidenceJson = JsonSerializer.Serialize(result.ScanEvidence);
            submission.UpdatedAt = timeProvider.GetUtcNow();
            await database.SaveChangesAsync(cancellationToken);
            return submission;
        }

        MarketplaceStoredObject artifact;
        MarketplaceStoredObject sbom;
        byte[] wrappedContentKey;
        try
        {
            ValidateSuccessfulBuild(result, seedSha256);
            artifact = await artifactStore.PutQuarantineAsync(
                "daxq",
                result.Artifact!,
                cancellationToken);
            sbom = await artifactStore.PutQuarantineAsync(
                "sbom",
                result.Sbom!,
                cancellationToken);
            wrappedContentKey = await contentKeyProvisioner.WrapContentKeyAsync(
                SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
                result.ContentKey!,
                cancellationToken);
        }
        finally
        {
            ZeroContentKey(result.ContentKey);
        }

        var now = timeProvider.GetUtcNow();
        var catalogItem = await database.CatalogItems.SingleOrDefaultAsync(
            item => item.Slug == submission.Slug,
            cancellationToken);
        if (catalogItem is null)
        {
            catalogItem = new CatalogItem
            {
                Id = Guid.NewGuid(),
                PublisherAccountId = submission.PublisherAccountId,
                Slug = submission.Slug,
                Title = submission.Title,
                Description = submission.Description,
                Version = submission.Version,
                PriceInCents = submission.PriceInCents,
                PriceMode = submission.PriceMode,
                Currency = submission.Currency,
                TemplateCopyJson = CreateTemplateCopyJson(submission),
                MediaJson = "[]",
                Status = CatalogItemStatus.Draft,
                CreatedAt = now,
                UpdatedAt = now,
            };
            database.CatalogItems.Add(catalogItem);
        }
        else if (catalogItem.PublisherAccountId != publisherAccountId)
        {
            throw new PlatformConflictException("The catalog slug belongs to another publisher.");
        }

        var previousRelease = await database.StrategyReleases.AsNoTracking()
            .Where(release => release.CatalogItemId == catalogItem.Id
                && release.Status == MarketplaceReleaseStatus.Approved)
            .OrderByDescending(release => release.ApprovedAt)
            .FirstOrDefaultAsync(cancellationToken);
        submission.PreviousApprovedSourceSha256 = previousRelease?.SourceSha256;
        submission.SourceDiffSummaryJson = JsonSerializer.Serialize(new
        {
            kind = previousRelease is null
                ? "first_release"
                : string.Equals(
                    previousRelease.SourceSha256,
                    submission.SourceSha256,
                    StringComparison.Ordinal)
                    ? "unchanged_source"
                    : "changed_source",
            previousSourceSha256 = previousRelease?.SourceSha256,
            sourceSha256 = submission.SourceSha256,
        });

        var release = new MarketplaceStrategyRelease
        {
            Id = Guid.NewGuid(),
            CatalogItemId = catalogItem.Id,
            SubmissionId = submission.Id,
            Version = submission.Version,
            Status = MarketplaceReleaseStatus.Quarantined,
            ArtifactBlobUri = artifact.Uri,
            ExecutionClass = MarketplaceExecutionClasses.NormalizeRequested(
                submission.RequestedExecutionClass),
            VmAbiVersion = result.VmAbiVersion,
            ContentKeyId = result.ContentKeyId,
            CipherSha256 = result.CipherSha256!,
            DiversifySeedId = result.DiversificationSeedSha256,
            DiversificationSeedSha256 = result.DiversificationSeedSha256!,
            SourceSha256 = submission.SourceSha256,
            ArtifactSha256 = result.ArtifactSha256!,
            ParityStatisticsJson = Encoding.UTF8.GetString(result.CanonicalParityStatistics!),
            ParityStatisticsSha256 = result.ParityStatisticsSha256!,
            ListingMetricsJson = Encoding.UTF8.GetString(result.CanonicalListingMetrics!),
            ListingMetricsSha256 = result.ListingMetricsSha256!,
            ScanEvidenceJson = JsonSerializer.Serialize(result.ScanEvidence),
            SbomSha256 = result.SbomSha256!,
            SbomBlobUri = sbom.Uri,
            CreatedAt = now,
        };
        database.StrategyReleases.Add(release);
        database.ContentKeys.Add(new MarketplaceContentKey
        {
            ContentKeyId = result.ContentKeyId!,
            ReleaseId = release.Id,
            KmsWrappedKey = wrappedContentKey,
            Algorithm = SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
            CreatedAt = now,
        });

        submission.CatalogItemId = catalogItem.Id;
        submission.ReleaseId = release.Id;
        submission.ArtifactSha256 = result.ArtifactSha256;
        submission.ArtifactQuarantineUri = artifact.Uri;
        submission.ContentKeyId = result.ContentKeyId;
        submission.KmsWrappedContentKey = wrappedContentKey;
        submission.ContentKeyWrappingAlgorithm = SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm;
        submission.BuildPolicyVersion = result.PolicyVersion;
        submission.BuildDiagnosticsJson = JsonSerializer.Serialize(result.Diagnostics);
        submission.ScanEvidenceJson = release.ScanEvidenceJson;
        submission.ParityStatisticsJson = release.ParityStatisticsJson;
        submission.ParityStatisticsSha256 = release.ParityStatisticsSha256;
        submission.ListingMetricsJson = release.ListingMetricsJson;
        submission.ListingMetricsSha256 = release.ListingMetricsSha256;
        submission.SbomSha256 = release.SbomSha256;
        submission.SbomQuarantineUri = sbom.Uri;
        submission.SourceReview = MarketplaceHumanReviewState.Pending;
        submission.DeclaredBehaviorReview = MarketplaceHumanReviewState.Pending;
        submission.DiffReview = MarketplaceHumanReviewState.Pending;
        submission.Status = SubmissionStatus.AwaitingReview;
        submission.UpdatedAt = now;
        await database.SaveChangesAsync(cancellationToken);
        return submission;
    }

    private static void ValidateSuccessfulBuild(
        MarketplaceBuildResult result,
        string expectedSeedSha256)
    {
        if (result.ScanEvidence is null || !result.ScanEvidence.AllPassed
            || string.IsNullOrWhiteSpace(result.ScanEvidence.CapabilityAnalyzerVersion)
            || string.IsNullOrWhiteSpace(result.ScanEvidence.MalwareScannerVersion)
            || string.IsNullOrWhiteSpace(result.ScanEvidence.SecretScannerVersion)
            || string.IsNullOrWhiteSpace(result.ScanEvidence.LicenseScannerVersion)
            || string.IsNullOrWhiteSpace(result.ScanEvidence.SbomToolVersion)
            || result.ScanEvidence.ImplementedCapabilities is null
            || result.ScanEvidence.ImplementedCapabilities.Any(string.IsNullOrWhiteSpace)
            || result.Artifact is not { Length: > 0 }
            || result.ContentKey is not { Length: 32 }
            || result.CanonicalParityStatistics is not { Length: > 0 }
            || result.CanonicalListingMetrics is not { Length: > 0 }
            || result.Sbom is not { Length: > 0 }
            || string.IsNullOrWhiteSpace(result.PolicyVersion)
            || string.IsNullOrWhiteSpace(result.ContentKeyId)
            || !string.Equals(result.ExecutionClass, RestrictedExecutionClass, StringComparison.Ordinal)
            || result.VmAbiVersion is null or <= 0
            || !string.Equals(
                result.DiversificationSeedSha256,
                expectedSeedSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The build worker returned incomplete or non-restricted release evidence.");
        }

        VerifyHash(result.Artifact, result.ArtifactSha256, "artifact");
        VerifyHash(result.CanonicalParityStatistics, result.ParityStatisticsSha256, "parity statistics");
        VerifyHash(result.CanonicalListingMetrics, result.ListingMetricsSha256, "listing metrics");
        VerifyHash(result.Sbom, result.SbomSha256, "SBOM");
        RequireSchemaVersion(
            result.CanonicalParityStatistics,
            ParityStatisticsSchemaVersion,
            "parity statistics");
        RequireSchemaVersion(
            result.CanonicalListingMetrics,
            ListingMetricsSchemaVersion,
            "listing metrics");
        _ = ParseSha256(result.CipherSha256, "cipher");
    }

    private static void VerifyHash(byte[] bytes, string? expectedHash, string name)
    {
        var expected = ParseSha256(expectedHash, name);
        var actual = SHA256.HashData(bytes);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new InvalidOperationException($"The declared {name} hash does not match its canonical bytes.");
        }
    }

    private static byte[] ParseSha256(string? value, string name)
    {
        try
        {
            var decoded = Convert.FromHexString(value ?? string.Empty);
            if (decoded.Length != 32)
            {
                throw new FormatException();
            }

            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException($"The build worker returned an invalid {name} SHA-256 value.", exception);
        }
    }

    private static void RequireSchemaVersion(byte[] json, string expected, string name)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("schemaVersion", out var version)
            || !string.Equals(version.GetString(), expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"The canonical {name} does not use schema '{expected}'.");
        }
    }

    private static string CreateTemplateCopyJson(MarketplaceSubmission submission) =>
        JsonSerializer.Serialize(new
        {
            headline = submission.Title,
            summary = submission.Description,
            riskDisclosure = "Backtest metrics are simulated under the versioned canonical listing model and are not a promise of future performance.",
        });

    private static void ZeroContentKey(byte[]? contentKey)
    {
        if (contentKey is not null)
        {
            CryptographicOperations.ZeroMemory(contentKey);
        }
    }
}

internal static class MarketplaceSourcePolicyAnalyzer
{
    private static readonly string[] BannedSurfaceTokens =
    [
        "System.Net",
        "System.IO",
        "System.Diagnostics.Process",
        "System.Reflection.Emit",
        "DllImport",
        "LibraryImport",
        "Microsoft.Win32.Registry",
        "AssemblyLoadContext",
        "Assembly.Load",
        "Environment.",
        "unsafe",
    ];

    private static readonly string[] SecretAssignmentTokens =
    [
        "apiKey = \"",
        "api_key = \"",
        "secret = \"",
        "password = \"",
        "privateKey = \"",
    ];

    public static IReadOnlyList<string> Analyze(
        byte[] source,
        string licenseExpression,
        MarketplaceSubmissionOptions options)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(options);
        var diagnostics = new List<string>();
        if (source.Length == 0 || source.Length > options.MaximumSourceBytes)
        {
            diagnostics.Add("SOURCE_SIZE: Source must be non-empty and within the configured upload limit.");
            return diagnostics;
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(source);
        }
        catch (DecoderFallbackException)
        {
            diagnostics.Add("SOURCE_UTF8: Source must be valid BOM-less UTF-8 text.");
            return diagnostics;
        }

        foreach (var token in BannedSurfaceTokens.Where(
                     token => text.Contains(token, StringComparison.Ordinal)))
        {
            diagnostics.Add($"CAPABILITY_BLOCK: Source references banned surface '{token}'.");
        }

        foreach (var token in SecretAssignmentTokens.Where(
                     token => text.Contains(token, StringComparison.OrdinalIgnoreCase)))
        {
            diagnostics.Add($"SECRET_BLOCK: Source appears to contain a hard-coded secret assignment '{token[..^2]}'.");
        }

        if (string.IsNullOrWhiteSpace(licenseExpression)
            || licenseExpression.Trim().Length > 100)
        {
            diagnostics.Add("LICENSE_BLOCK: A bounded SPDX expression or 'Proprietary' declaration is required.");
        }

        return diagnostics;
    }
}
