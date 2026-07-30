namespace DaxAlgo.Platform.Domain;

public enum PlanTier
{
    Basic = 0,
    Professional = 2,
}

public enum SubscriptionStatus
{
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Revoked,
}

public enum CatalogItemStatus
{
    Draft,
    Published,
    Withdrawn,
}

public enum SubmissionStatus
{
    Draft,
    Processing,
    Blocked,
    AwaitingReview,
    Approved,
    Rejected,
}

public enum MarketplacePriceMode
{
    OneTime,
    Subscription,
}

public enum MarketplacePublisherStatus
{
    NotStarted,
    Pending,
    Complete,
    Restricted,
}

public enum MarketplaceReleaseStatus
{
    Quarantined,
    Approved,
    Revoked,
}

public enum MarketplaceHumanReviewState
{
    Pending,
    Passed,
    Failed,
}

public enum OrderStatus
{
    Pending,
    Paid,
    Refunded,
    Canceled,
}

public enum ReviewStatus
{
    Published,
    Hidden,
}

public enum NormalizedEntitlementState
{
    Active,
    Suspended,
    Revoked,
}

public enum MarketplaceLicenseStatus
{
    Active,
    Revoked,
}

public enum EntitlementGrantType
{
    MarketplaceLicense,
    MarketplaceSubscription,
}

public enum EntitlementGrantStatus
{
    Active,
    Revoked,
    Expired,
}

public sealed class Profile
{
    public Guid Id { get; set; }

    public required string Subject { get; set; }

    public required string Email { get; set; }

    public required string DisplayName { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class AccountSubscription
{
    public Guid AccountId { get; set; }

    public required string Provider { get; set; }

    public required string ProviderSubscriptionId { get; set; }

    public PlanTier Plan { get; set; }

    public SubscriptionStatus Status { get; set; }

    public DateTimeOffset CurrentPeriodEnd { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class RegisteredDevice
{
    public Guid AccountId { get; set; }

    public Guid DeviceId { get; set; }

    public required string DisplayName { get; set; }

    public string? PublicKeySpki { get; set; }

    public string? FingerprintSha256 { get; set; }

    public DateTimeOffset RegisteredAt { get; set; }

    public DateTimeOffset LastSeenAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class CatalogItem
{
    public Guid Id { get; set; }

    public Guid PublisherAccountId { get; set; }

    public required string Slug { get; set; }

    public required string Title { get; set; }

    public required string Description { get; set; }

    public required string Version { get; set; }

    public long PriceInCents { get; set; }

    public MarketplacePriceMode PriceMode { get; set; }

    public string Currency { get; set; } = "USD";

    public string TemplateCopyJson { get; set; } = "{}";

    public string MediaJson { get; set; } = "[]";

    public CatalogItemStatus Status { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class MarketplaceSubmission
{
    public Guid Id { get; set; }

    public Guid PublisherAccountId { get; set; }

    public required string Slug { get; set; }

    public required string Title { get; set; }

    public required string Description { get; set; }

    public required string Version { get; set; }

    public long PriceInCents { get; set; }

    public MarketplacePriceMode PriceMode { get; set; }

    public string Currency { get; set; } = "USD";

    public string SourceSha256 { get; set; } = string.Empty;

    public string SourceQuarantineUri { get; set; } = string.Empty;

    public string ReferenceDatasetSha256 { get; set; } = string.Empty;

    public string ReferenceDatasetQuarantineUri { get; set; } = string.Empty;

    public string LicenseExpression { get; set; } = "Proprietary";

    public string DeclaredCapabilitiesJson { get; set; } = "[]";

    public string RequestedExecutionClass { get; set; } = "restricted_only";

    public string? PreviousApprovedSourceSha256 { get; set; }

    public string? SourceDiffSummaryJson { get; set; }

    public string? DiversificationSeedSha256 { get; set; }

    public string? BuildPolicyVersion { get; set; }

    public string? BuildDiagnosticsJson { get; set; }

    public string? ScanEvidenceJson { get; set; }

    public string? ParityStatisticsJson { get; set; }

    public string? ParityStatisticsSha256 { get; set; }

    public string? ListingMetricsJson { get; set; }

    public string? ListingMetricsSha256 { get; set; }

    public string? SbomSha256 { get; set; }

    public string? SbomQuarantineUri { get; set; }

    public string? ArtifactSha256 { get; set; }

    public string? ArtifactQuarantineUri { get; set; }

    public string? ContentKeyId { get; set; }

    public byte[]? KmsWrappedContentKey { get; set; }

    public string? ContentKeyWrappingAlgorithm { get; set; }

    public Guid? CatalogItemId { get; set; }

    public Guid? ReleaseId { get; set; }

    public MarketplaceHumanReviewState SourceReview { get; set; }

    public MarketplaceHumanReviewState DeclaredBehaviorReview { get; set; }

    public MarketplaceHumanReviewState DiffReview { get; set; }

    public SubmissionStatus Status { get; set; }

    public string? ReviewNotes { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class MarketplaceOrder
{
    public Guid Id { get; set; }

    public Guid BuyerAccountId { get; set; }

    public Guid CatalogItemId { get; set; }

    public Guid ReleaseId { get; set; }

    public long AmountInCents { get; set; }

    public MarketplacePriceMode PriceMode { get; set; }

    public string Currency { get; set; } = "USD";

    public long ApplicationFeeInCents { get; set; }

    public long ReserveInCents { get; set; }

    public long SellerProceedsInCents { get; set; }

    public string CommercialPolicyVersion { get; set; } = string.Empty;

    public int PayoutDelayDays { get; set; }

    public bool AutomaticTaxEnabled { get; set; }

    public string TaxHandling { get; set; } = string.Empty;

    public string MerchantOfRecord { get; set; } = string.Empty;

    public OrderStatus Status { get; set; }

    public string? ProviderCheckoutId { get; set; }

    public string? CheckoutUrl { get; set; }

    public string? ProviderSubscriptionId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class MarketplaceReview
{
    public Guid Id { get; set; }

    public Guid CatalogItemId { get; set; }

    public Guid AuthorAccountId { get; set; }

    public int Rating { get; set; }

    public required string Body { get; set; }

    public ReviewStatus Status { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class BillingWebhookReceipt
{
    public required string Provider { get; set; }

    public required string EventId { get; set; }

    public DateTimeOffset ProcessedAt { get; set; }
}

public sealed class MarketplacePublisher
{
    public Guid AccountId { get; set; }

    public string? ConnectAccountId { get; set; }

    public MarketplacePublisherStatus Status { get; set; }

    public bool DetailsSubmitted { get; set; }

    public bool ChargesEnabled { get; set; }

    public bool PayoutsEnabled { get; set; }

    public string? TermsVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class MarketplaceStrategyRelease
{
    public Guid Id { get; set; }

    public Guid CatalogItemId { get; set; }

    public Guid SubmissionId { get; set; }

    public string Version { get; set; } = string.Empty;

    public MarketplaceReleaseStatus Status { get; set; }

    public required string ArtifactBlobUri { get; set; }

    public required string ExecutionClass { get; set; }

    public int? VmAbiVersion { get; set; }

    public string? ContentKeyId { get; set; }

    public required string CipherSha256 { get; set; }

    public string? DiversifySeedId { get; set; }

    public string DiversificationSeedSha256 { get; set; } = string.Empty;

    public string SourceSha256 { get; set; } = string.Empty;

    public string ArtifactSha256 { get; set; } = string.Empty;

    public string ParityStatisticsJson { get; set; } = "{}";

    public string ParityStatisticsSha256 { get; set; } = string.Empty;

    public string ListingMetricsJson { get; set; } = "{}";

    public string ListingMetricsSha256 { get; set; } = string.Empty;

    public string ScanEvidenceJson { get; set; } = "{}";

    public string SbomSha256 { get; set; } = string.Empty;

    public string SbomBlobUri { get; set; } = string.Empty;

    public string? AttestationBlobUri { get; set; }

    public string? AttestationSha256 { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? ApprovedAt { get; set; }
}

public sealed class EntitlementGrant
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public Guid CatalogItemId { get; set; }

    public Guid OrderId { get; set; }

    public EntitlementGrantType Type { get; set; }

    public EntitlementGrantStatus Status { get; set; }

    public DateTimeOffset ValidFrom { get; set; }

    public DateTimeOffset ValidUntil { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class MarketplaceLicense
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public Guid ReleaseId { get; set; }

    public Guid GrantId { get; set; }

    public MarketplaceLicenseStatus Status { get; set; }

    public DateTimeOffset ValidFrom { get; set; }

    public DateTimeOffset ValidUntil { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class MarketplaceSignalSession
{
    public Guid Id { get; set; }

    public Guid LicenseId { get; set; }

    public Guid AccountId { get; set; }

    public Guid DeviceId { get; set; }

    public Guid ReleaseId { get; set; }

    public DateTimeOffset StartedAt { get; set; }

    public DateTimeOffset LastHeartbeatAt { get; set; }

    public DateTimeOffset? EndedAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class MarketplaceContentKey
{
    public required string ContentKeyId { get; set; }

    public Guid ReleaseId { get; set; }

    public required byte[] KmsWrappedKey { get; set; }

    public required string Algorithm { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset? RotatedAt { get; set; }
}

public sealed class ContentKeyReleaseAudit
{
    public Guid Id { get; set; }

    public Guid ChallengeId { get; set; }

    public Guid LicenseId { get; set; }

    public Guid AccountId { get; set; }

    public Guid DeviceId { get; set; }

    public Guid ReleaseId { get; set; }

    public DateTimeOffset ReleasedAt { get; set; }

    public required string SessionPublicKeySha256 { get; set; }

    public int TtlSeconds { get; set; }
}

public sealed class EntitlementRevocation
{
    public long Sequence { get; set; }

    public required string TargetType { get; set; }

    public required string TargetId { get; set; }

    public required string Reason { get; set; }

    public DateTimeOffset IssuedAt { get; set; }
}

public sealed class DeviceProofChallenge
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public Guid LicenseId { get; set; }

    public Guid ReleaseId { get; set; }

    public Guid DeviceId { get; set; }

    public required string Operation { get; set; }

    public required string BindingSha256 { get; set; }

    public required string Nonce { get; set; }

    public required string IdempotencyKey { get; set; }

    public required string RequestSha256 { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public string? ResponseJson { get; set; }

    public long Version { get; set; }
}

public sealed record EntitlementSnapshot(
    Guid AccountId,
    PlanTier Tier,
    bool IsActive,
    DateTimeOffset IssuedAt,
    DateTimeOffset LeaseExpiresAt,
    DateTimeOffset? SubscriptionValidUntil,
    IReadOnlyList<string> Capabilities);
