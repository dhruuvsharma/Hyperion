using DaxAlgo.Platform.Domain;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Persistence;

public sealed class PlatformDbContext(DbContextOptions<PlatformDbContext> options) : DbContext(options)
{
    public DbSet<Profile> Profiles => Set<Profile>();

    public DbSet<AccountSubscription> Subscriptions => Set<AccountSubscription>();

    public DbSet<RegisteredDevice> Devices => Set<RegisteredDevice>();

    public DbSet<CatalogItem> CatalogItems => Set<CatalogItem>();

    public DbSet<MarketplaceSubmission> Submissions => Set<MarketplaceSubmission>();

    public DbSet<MarketplaceOrder> Orders => Set<MarketplaceOrder>();

    public DbSet<MarketplaceReview> Reviews => Set<MarketplaceReview>();

    public DbSet<BillingWebhookReceipt> BillingWebhookReceipts => Set<BillingWebhookReceipt>();

    public DbSet<MarketplacePublisher> MarketplacePublishers => Set<MarketplacePublisher>();

    public DbSet<MarketplaceStrategyRelease> StrategyReleases => Set<MarketplaceStrategyRelease>();

    public DbSet<EntitlementGrant> EntitlementGrants => Set<EntitlementGrant>();

    public DbSet<MarketplaceLicense> MarketplaceLicenses => Set<MarketplaceLicense>();

    public DbSet<MarketplaceSignalSession> SignalSessions => Set<MarketplaceSignalSession>();

    public DbSet<MarketplaceContentKey> ContentKeys => Set<MarketplaceContentKey>();

    public DbSet<ContentKeyReleaseAudit> ContentKeyReleases => Set<ContentKeyReleaseAudit>();

    public DbSet<EntitlementRevocation> Revocations => Set<EntitlementRevocation>();

    public DbSet<DeviceProofChallenge> DeviceProofChallenges => Set<DeviceProofChallenge>();

    public DbSet<VibeQuantCreditWallet> VibeQuantCreditWallets => Set<VibeQuantCreditWallet>();

    public DbSet<VibeQuantCreditLedgerEntry> VibeQuantCreditLedger => Set<VibeQuantCreditLedgerEntry>();

    public DbSet<VibeQuantRun> VibeQuantRuns => Set<VibeQuantRun>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var profiles = modelBuilder.Entity<Profile>();
        profiles.ToTable("profiles");
        profiles.HasKey(x => x.Id);
        profiles.Property(x => x.Subject).HasMaxLength(200).IsRequired();
        profiles.Property(x => x.Email).HasMaxLength(320).IsRequired();
        profiles.Property(x => x.DisplayName).HasMaxLength(120).IsRequired();
        profiles.HasIndex(x => x.Subject).IsUnique();

        var subscriptions = modelBuilder.Entity<AccountSubscription>();
        subscriptions.ToTable("subscriptions");
        subscriptions.HasKey(x => x.AccountId);
        subscriptions.Property(x => x.Provider).HasMaxLength(40).IsRequired();
        subscriptions.Property(x => x.ProviderSubscriptionId).HasMaxLength(200).IsRequired();
        subscriptions.Property(x => x.Plan).HasConversion<int>();
        subscriptions.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
        subscriptions.HasIndex(x => new { x.Provider, x.ProviderSubscriptionId }).IsUnique();
        subscriptions.HasOne<Profile>()
            .WithOne()
            .HasForeignKey<AccountSubscription>(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);

        var devices = modelBuilder.Entity<RegisteredDevice>();
        devices.ToTable("registered_devices");
        devices.HasKey(x => new { x.AccountId, x.DeviceId });
        devices.Property(x => x.DisplayName).HasMaxLength(120).IsRequired();
        devices.Property(x => x.PublicKeySpki).HasMaxLength(512);
        devices.Property(x => x.FingerprintSha256).HasMaxLength(64).IsFixedLength();
        devices.HasIndex(x => new { x.AccountId, x.RevokedAt });
        devices.HasOne<Profile>().WithMany().HasForeignKey(x => x.AccountId).OnDelete(DeleteBehavior.Cascade);

        var catalog = modelBuilder.Entity<CatalogItem>();
        catalog.ToTable("catalog_items");
        catalog.HasKey(x => x.Id);
        catalog.Property(x => x.Slug).HasMaxLength(100).IsRequired();
        catalog.Property(x => x.Title).HasMaxLength(160).IsRequired();
        catalog.Property(x => x.Description).HasMaxLength(4000).IsRequired();
        catalog.Property(x => x.Version).HasMaxLength(40).IsRequired();
        catalog.Property(x => x.PriceMode).HasConversion<string>().HasMaxLength(32);
        catalog.Property(x => x.Currency).HasMaxLength(3).IsFixedLength().IsRequired();
        catalog.Property(x => x.TemplateCopyJson).IsRequired();
        catalog.Property(x => x.MediaJson).IsRequired();
        catalog.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
        catalog.HasIndex(x => x.Slug).IsUnique();
        catalog.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.PublisherAccountId)
            .OnDelete(DeleteBehavior.NoAction);

        var submissions = modelBuilder.Entity<MarketplaceSubmission>();
        submissions.ToTable("marketplace_submissions");
        submissions.HasKey(x => x.Id);
        submissions.Property(x => x.Slug).HasMaxLength(100).IsRequired();
        submissions.Property(x => x.Title).HasMaxLength(160).IsRequired();
        submissions.Property(x => x.Description).HasMaxLength(4000).IsRequired();
        submissions.Property(x => x.Version).HasMaxLength(40).IsRequired();
        submissions.Property(x => x.PriceMode).HasConversion<string>().HasMaxLength(32);
        submissions.Property(x => x.Currency).HasMaxLength(3).IsFixedLength().IsRequired();
        submissions.Property(x => x.SourceSha256).HasMaxLength(64).IsFixedLength().IsRequired();
        submissions.Property(x => x.SourceQuarantineUri).HasMaxLength(2000).IsRequired();
        submissions.Property(x => x.ReferenceDatasetSha256).HasMaxLength(64).IsFixedLength().IsRequired();
        submissions.Property(x => x.ReferenceDatasetQuarantineUri).HasMaxLength(2000).IsRequired();
        submissions.Property(x => x.LicenseExpression).HasMaxLength(100).IsRequired();
        submissions.Property(x => x.DeclaredCapabilitiesJson).IsRequired();
        submissions.Property(x => x.RequestedExecutionClass).HasMaxLength(32).IsRequired();
        submissions.Property(x => x.PreviousApprovedSourceSha256).HasMaxLength(64).IsFixedLength();
        submissions.Property(x => x.DiversificationSeedSha256).HasMaxLength(64).IsFixedLength();
        submissions.Property(x => x.BuildPolicyVersion).HasMaxLength(100);
        submissions.Property(x => x.ParityStatisticsSha256).HasMaxLength(64).IsFixedLength();
        submissions.Property(x => x.ListingMetricsSha256).HasMaxLength(64).IsFixedLength();
        submissions.Property(x => x.SbomSha256).HasMaxLength(64).IsFixedLength();
        submissions.Property(x => x.SbomQuarantineUri).HasMaxLength(2000);
        submissions.Property(x => x.ArtifactSha256).HasMaxLength(64).IsFixedLength();
        submissions.Property(x => x.ArtifactQuarantineUri).HasMaxLength(2000);
        submissions.Property(x => x.ContentKeyId).HasMaxLength(128);
        submissions.Property(x => x.ContentKeyWrappingAlgorithm).HasMaxLength(32);
        submissions.Property(x => x.SourceReview).HasConversion<string>().HasMaxLength(32);
        submissions.Property(x => x.DeclaredBehaviorReview).HasConversion<string>().HasMaxLength(32);
        submissions.Property(x => x.DiffReview).HasConversion<string>().HasMaxLength(32);
        submissions.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
        submissions.Property(x => x.ReviewNotes).HasMaxLength(1000);
        submissions.HasIndex(x => x.SourceSha256);
        submissions.HasIndex(x => x.DiversificationSeedSha256);
        submissions.HasIndex(x => x.ReleaseId).IsUnique();
        submissions.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.PublisherAccountId)
            .OnDelete(DeleteBehavior.NoAction);

        var orders = modelBuilder.Entity<MarketplaceOrder>();
        orders.ToTable("marketplace_orders");
        orders.HasKey(x => x.Id);
        orders.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
        orders.Property(x => x.PriceMode).HasConversion<string>().HasMaxLength(32);
        orders.Property(x => x.Currency).HasMaxLength(3).IsFixedLength().IsRequired();
        orders.Property(x => x.CommercialPolicyVersion).HasMaxLength(100).IsRequired();
        orders.Property(x => x.TaxHandling).HasMaxLength(100).IsRequired();
        orders.Property(x => x.MerchantOfRecord).HasMaxLength(100).IsRequired();
        orders.Property(x => x.ProviderCheckoutId).HasMaxLength(200);
        orders.Property(x => x.CheckoutUrl).HasMaxLength(1000);
        orders.Property(x => x.ProviderSubscriptionId).HasMaxLength(200);
        orders.HasIndex(x => x.ProviderCheckoutId).IsUnique();
        orders.HasIndex(x => x.ProviderSubscriptionId);
        orders.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.BuyerAccountId)
            .OnDelete(DeleteBehavior.NoAction);
        orders.HasOne<CatalogItem>()
            .WithMany()
            .HasForeignKey(x => x.CatalogItemId)
            .OnDelete(DeleteBehavior.NoAction);
        orders.HasOne<MarketplaceStrategyRelease>()
            .WithMany()
            .HasForeignKey(x => x.ReleaseId)
            .OnDelete(DeleteBehavior.NoAction);

        var reviews = modelBuilder.Entity<MarketplaceReview>();
        reviews.ToTable("marketplace_reviews");
        reviews.HasKey(x => x.Id);
        reviews.Property(x => x.Body).HasMaxLength(2000).IsRequired();
        reviews.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
        reviews.HasIndex(x => new { x.CatalogItemId, x.AuthorAccountId }).IsUnique();
        reviews.HasOne<CatalogItem>().WithMany().HasForeignKey(x => x.CatalogItemId).OnDelete(DeleteBehavior.Cascade);
        reviews.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AuthorAccountId)
            .OnDelete(DeleteBehavior.NoAction);

        var receipts = modelBuilder.Entity<BillingWebhookReceipt>();
        receipts.ToTable("billing_webhook_receipts");
        receipts.HasKey(x => new { x.Provider, x.EventId });
        receipts.Property(x => x.Provider).HasMaxLength(40);
        receipts.Property(x => x.EventId).HasMaxLength(200);

        var publishers = modelBuilder.Entity<MarketplacePublisher>();
        publishers.ToTable("publisher", "marketplace");
        publishers.HasKey(x => x.AccountId);
        publishers.Property(x => x.AccountId).HasColumnName("account_id");
        publishers.Property(x => x.ConnectAccountId).HasColumnName("connect_account_id").HasMaxLength(200);
        publishers.Property(x => x.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32);
        publishers.Property(x => x.DetailsSubmitted).HasColumnName("details_submitted");
        publishers.Property(x => x.ChargesEnabled).HasColumnName("charges_enabled");
        publishers.Property(x => x.PayoutsEnabled).HasColumnName("payouts_enabled");
        publishers.Property(x => x.TermsVersion).HasColumnName("terms_version").HasMaxLength(100);
        publishers.Property(x => x.CreatedAt).HasColumnName("created_at");
        publishers.Property(x => x.UpdatedAt).HasColumnName("updated_at");
        publishers.HasIndex(x => x.ConnectAccountId).IsUnique();
        publishers.HasOne<Profile>()
            .WithOne()
            .HasForeignKey<MarketplacePublisher>(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);

        var strategyReleases = modelBuilder.Entity<MarketplaceStrategyRelease>();
        strategyReleases.ToTable("strategy_release", "marketplace");
        strategyReleases.HasKey(x => x.Id);
        strategyReleases.Property(x => x.Id).HasColumnName("id");
        strategyReleases.Property(x => x.CatalogItemId).HasColumnName("catalog_item_id");
        strategyReleases.Property(x => x.SubmissionId).HasColumnName("submission_id");
        strategyReleases.Property(x => x.Version).HasColumnName("version").HasMaxLength(40).IsRequired();
        strategyReleases.Property(x => x.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32);
        strategyReleases.Property(x => x.ArtifactBlobUri).HasColumnName("artifact_blob_uri").HasMaxLength(2000).IsRequired();
        strategyReleases.Property(x => x.ExecutionClass).HasColumnName("execution_class").HasMaxLength(32).IsRequired();
        strategyReleases.Property(x => x.VmAbiVersion).HasColumnName("vm_abi_version");
        strategyReleases.Property(x => x.ContentKeyId).HasColumnName("content_key_id").HasMaxLength(128);
        strategyReleases.Property(x => x.CipherSha256).HasColumnName("cipher_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.DiversifySeedId).HasColumnName("diversify_seed_id").HasMaxLength(200);
        strategyReleases.Property(x => x.DiversificationSeedSha256).HasColumnName("diversification_seed_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.SourceSha256).HasColumnName("source_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.ArtifactSha256).HasColumnName("artifact_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.ParityStatisticsJson).HasColumnName("parity_statistics_json").IsRequired();
        strategyReleases.Property(x => x.ParityStatisticsSha256).HasColumnName("parity_statistics_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.ListingMetricsJson).HasColumnName("listing_metrics_json").IsRequired();
        strategyReleases.Property(x => x.ListingMetricsSha256).HasColumnName("listing_metrics_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.ScanEvidenceJson).HasColumnName("scan_evidence_json").IsRequired();
        strategyReleases.Property(x => x.SbomSha256).HasColumnName("sbom_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        strategyReleases.Property(x => x.SbomBlobUri).HasColumnName("sbom_blob_uri").HasMaxLength(2000).IsRequired();
        strategyReleases.Property(x => x.AttestationBlobUri).HasColumnName("attestation_blob_uri").HasMaxLength(2000);
        strategyReleases.Property(x => x.AttestationSha256).HasColumnName("attestation_sha256").HasMaxLength(64).IsFixedLength();
        strategyReleases.Property(x => x.CreatedAt).HasColumnName("created_at");
        strategyReleases.Property(x => x.ApprovedAt).HasColumnName("approved_at");
        strategyReleases.HasIndex(x => new { x.CatalogItemId, x.CreatedAt });
        strategyReleases.HasIndex(x => new { x.CatalogItemId, x.Version }).IsUnique();
        strategyReleases.HasIndex(x => x.SubmissionId).IsUnique();
        strategyReleases.HasIndex(x => x.DiversificationSeedSha256).IsUnique();
        strategyReleases.HasOne<CatalogItem>()
            .WithMany()
            .HasForeignKey(x => x.CatalogItemId)
            .OnDelete(DeleteBehavior.NoAction);
        strategyReleases.HasOne<MarketplaceSubmission>()
            .WithOne()
            .HasForeignKey<MarketplaceStrategyRelease>(x => x.SubmissionId)
            .OnDelete(DeleteBehavior.NoAction);

        var entitlementGrants = modelBuilder.Entity<EntitlementGrant>();
        entitlementGrants.ToTable("grant", "entitlements");
        entitlementGrants.HasKey(x => x.Id);
        entitlementGrants.Property(x => x.Id).HasColumnName("id");
        entitlementGrants.Property(x => x.AccountId).HasColumnName("account_id");
        entitlementGrants.Property(x => x.CatalogItemId).HasColumnName("catalog_item_id");
        entitlementGrants.Property(x => x.OrderId).HasColumnName("order_id");
        entitlementGrants.Property(x => x.Type).HasColumnName("grant_type").HasConversion<string>().HasMaxLength(40);
        entitlementGrants.Property(x => x.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32);
        entitlementGrants.Property(x => x.ValidFrom).HasColumnName("valid_from");
        entitlementGrants.Property(x => x.ValidUntil).HasColumnName("valid_until");
        entitlementGrants.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        entitlementGrants.Property(x => x.UpdatedAt).HasColumnName("updated_at");
        entitlementGrants.HasIndex(x => x.OrderId).IsUnique();
        entitlementGrants.HasIndex(x => new { x.AccountId, x.CatalogItemId });
        entitlementGrants.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
        entitlementGrants.HasOne<CatalogItem>()
            .WithMany()
            .HasForeignKey(x => x.CatalogItemId)
            .OnDelete(DeleteBehavior.NoAction);
        entitlementGrants.HasOne<MarketplaceOrder>()
            .WithOne()
            .HasForeignKey<EntitlementGrant>(x => x.OrderId)
            .OnDelete(DeleteBehavior.NoAction);

        var marketplaceLicenses = modelBuilder.Entity<MarketplaceLicense>();
        marketplaceLicenses.ToTable("license", "marketplace");
        marketplaceLicenses.HasKey(x => x.Id);
        marketplaceLicenses.Property(x => x.Id).HasColumnName("id");
        marketplaceLicenses.Property(x => x.AccountId).HasColumnName("account_id");
        marketplaceLicenses.Property(x => x.ReleaseId).HasColumnName("release_id");
        marketplaceLicenses.Property(x => x.GrantId).HasColumnName("grant_id");
        marketplaceLicenses.Property(x => x.Status).HasColumnName("status").HasConversion<string>().HasMaxLength(32);
        marketplaceLicenses.Property(x => x.ValidFrom).HasColumnName("valid_from");
        marketplaceLicenses.Property(x => x.ValidUntil).HasColumnName("valid_until");
        marketplaceLicenses.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        marketplaceLicenses.HasIndex(x => new { x.AccountId, x.ReleaseId }).IsUnique();
        marketplaceLicenses.HasIndex(x => x.GrantId).IsUnique();
        marketplaceLicenses.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
        marketplaceLicenses.HasOne<MarketplaceStrategyRelease>()
            .WithMany()
            .HasForeignKey(x => x.ReleaseId)
            .OnDelete(DeleteBehavior.NoAction);
        marketplaceLicenses.HasOne<EntitlementGrant>()
            .WithOne()
            .HasForeignKey<MarketplaceLicense>(x => x.GrantId)
            .OnDelete(DeleteBehavior.NoAction);

        var signalSessions = modelBuilder.Entity<MarketplaceSignalSession>();
        signalSessions.ToTable("signal_session", "marketplace");
        signalSessions.HasKey(x => x.Id);
        signalSessions.Property(x => x.Id).HasColumnName("id");
        signalSessions.Property(x => x.LicenseId).HasColumnName("license_id");
        signalSessions.Property(x => x.AccountId).HasColumnName("account_id");
        signalSessions.Property(x => x.DeviceId).HasColumnName("device_id");
        signalSessions.Property(x => x.ReleaseId).HasColumnName("release_id");
        signalSessions.Property(x => x.StartedAt).HasColumnName("started_at");
        signalSessions.Property(x => x.LastHeartbeatAt).HasColumnName("last_heartbeat_at");
        signalSessions.Property(x => x.EndedAt).HasColumnName("ended_at");
        signalSessions.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        signalSessions.HasIndex(x => new { x.LicenseId, x.EndedAt });
        signalSessions.HasIndex(x => new { x.AccountId, x.DeviceId, x.EndedAt });
        signalSessions.HasOne<MarketplaceLicense>()
            .WithMany()
            .HasForeignKey(x => x.LicenseId)
            .OnDelete(DeleteBehavior.NoAction);
        signalSessions.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
        signalSessions.HasOne<RegisteredDevice>()
            .WithMany()
            .HasForeignKey(x => new { x.AccountId, x.DeviceId })
            .OnDelete(DeleteBehavior.NoAction);
        signalSessions.HasOne<MarketplaceStrategyRelease>()
            .WithMany()
            .HasForeignKey(x => x.ReleaseId)
            .OnDelete(DeleteBehavior.NoAction);

        var contentKeys = modelBuilder.Entity<MarketplaceContentKey>();
        contentKeys.ToTable("content_key", "entitlements");
        contentKeys.HasKey(x => x.ContentKeyId);
        contentKeys.Property(x => x.ContentKeyId).HasColumnName("content_key_id").HasMaxLength(128);
        contentKeys.Property(x => x.ReleaseId).HasColumnName("release_id");
        contentKeys.Property(x => x.KmsWrappedKey).HasColumnName("kms_wrapped_key").IsRequired();
        contentKeys.Property(x => x.Algorithm).HasColumnName("alg").HasMaxLength(32).IsRequired();
        contentKeys.Property(x => x.CreatedAt).HasColumnName("created_at");
        contentKeys.Property(x => x.RotatedAt).HasColumnName("rotated_at");
        contentKeys.HasIndex(x => x.ReleaseId);
        contentKeys.HasOne<MarketplaceStrategyRelease>()
            .WithMany()
            .HasForeignKey(x => x.ReleaseId)
            .OnDelete(DeleteBehavior.NoAction);

        var contentKeyReleases = modelBuilder.Entity<ContentKeyReleaseAudit>();
        contentKeyReleases.ToTable("content_key_release", "marketplace");
        contentKeyReleases.HasKey(x => x.Id);
        contentKeyReleases.Property(x => x.Id).HasColumnName("id");
        contentKeyReleases.Property(x => x.ChallengeId).HasColumnName("challenge_id");
        contentKeyReleases.Property(x => x.LicenseId).HasColumnName("license_id");
        contentKeyReleases.Property(x => x.AccountId).HasColumnName("account_id");
        contentKeyReleases.Property(x => x.DeviceId).HasColumnName("device_id");
        contentKeyReleases.Property(x => x.ReleaseId).HasColumnName("release_id");
        contentKeyReleases.Property(x => x.ReleasedAt).HasColumnName("released_at");
        contentKeyReleases.Property(x => x.SessionPublicKeySha256)
            .HasColumnName("session_pubkey_sha256")
            .HasMaxLength(64)
            .IsFixedLength()
            .IsRequired();
        contentKeyReleases.Property(x => x.TtlSeconds).HasColumnName("ttl_seconds");
        contentKeyReleases.HasIndex(x => new { x.LicenseId, x.ReleasedAt });
        contentKeyReleases.HasIndex(x => x.ChallengeId).IsUnique();
        contentKeyReleases.HasOne<MarketplaceLicense>()
            .WithMany()
            .HasForeignKey(x => x.LicenseId)
            .OnDelete(DeleteBehavior.NoAction);
        contentKeyReleases.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
        contentKeyReleases.HasOne<MarketplaceStrategyRelease>()
            .WithMany()
            .HasForeignKey(x => x.ReleaseId)
            .OnDelete(DeleteBehavior.NoAction);
        contentKeyReleases.HasOne<DeviceProofChallenge>()
            .WithMany()
            .HasForeignKey(x => x.ChallengeId)
            .OnDelete(DeleteBehavior.NoAction);

        var revocations = modelBuilder.Entity<EntitlementRevocation>();
        revocations.ToTable("revocation", "entitlements");
        revocations.HasKey(x => x.Sequence);
        revocations.Property(x => x.Sequence).HasColumnName("seq").ValueGeneratedOnAdd();
        revocations.Property(x => x.TargetType).HasColumnName("target_type").HasMaxLength(32).IsRequired();
        revocations.Property(x => x.TargetId).HasColumnName("target_id").HasMaxLength(200).IsRequired();
        revocations.Property(x => x.Reason).HasColumnName("reason").HasMaxLength(500).IsRequired();
        revocations.Property(x => x.IssuedAt).HasColumnName("issued_at");
        revocations.HasIndex(x => new { x.TargetType, x.TargetId });

        var proofChallenges = modelBuilder.Entity<DeviceProofChallenge>();
        proofChallenges.ToTable("device_proof_challenge", "entitlements");
        proofChallenges.HasKey(x => x.Id);
        proofChallenges.Property(x => x.Id).HasColumnName("id");
        proofChallenges.Property(x => x.AccountId).HasColumnName("account_id");
        proofChallenges.Property(x => x.LicenseId).HasColumnName("license_id");
        proofChallenges.Property(x => x.ReleaseId).HasColumnName("release_id");
        proofChallenges.Property(x => x.DeviceId).HasColumnName("device_id");
        proofChallenges.Property(x => x.Operation).HasColumnName("operation").HasMaxLength(32).IsRequired();
        proofChallenges.Property(x => x.BindingSha256).HasColumnName("binding_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        proofChallenges.Property(x => x.Nonce).HasColumnName("nonce").HasMaxLength(100).IsRequired();
        proofChallenges.Property(x => x.IdempotencyKey).HasColumnName("idempotency_key").HasMaxLength(100).IsRequired();
        proofChallenges.Property(x => x.RequestSha256).HasColumnName("request_sha256").HasMaxLength(64).IsFixedLength().IsRequired();
        proofChallenges.Property(x => x.CreatedAt).HasColumnName("created_at");
        proofChallenges.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        proofChallenges.Property(x => x.ConsumedAt).HasColumnName("consumed_at");
        proofChallenges.Property(x => x.ResponseJson).HasColumnName("response_json");
        proofChallenges.Property(x => x.Version).HasColumnName("version").IsConcurrencyToken();
        proofChallenges.HasIndex(x => new { x.AccountId, x.Operation, x.IdempotencyKey }).IsUnique();
        proofChallenges.HasIndex(x => x.ExpiresAt);
        proofChallenges.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
        proofChallenges.HasOne<MarketplaceLicense>()
            .WithMany()
            .HasForeignKey(x => x.LicenseId)
            .OnDelete(DeleteBehavior.NoAction);
        proofChallenges.HasOne<MarketplaceStrategyRelease>()
            .WithMany()
            .HasForeignKey(x => x.ReleaseId)
            .OnDelete(DeleteBehavior.NoAction);

        var creditWallets = modelBuilder.Entity<VibeQuantCreditWallet>();
        creditWallets.ToTable("vibe_quant_credit_wallets");
        creditWallets.HasKey(x => x.AccountId);
        creditWallets.Property(x => x.Version).IsConcurrencyToken();
        creditWallets.HasOne<Profile>()
            .WithOne()
            .HasForeignKey<VibeQuantCreditWallet>(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);

        var creditLedger = modelBuilder.Entity<VibeQuantCreditLedgerEntry>();
        creditLedger.ToTable("vibe_quant_credit_ledger");
        creditLedger.HasKey(x => x.Id);
        creditLedger.Property(x => x.Kind).HasConversion<string>().HasMaxLength(32);
        creditLedger.Property(x => x.IdempotencyKey).HasMaxLength(160).IsRequired();
        creditLedger.Property(x => x.Reference).HasMaxLength(500).IsRequired();
        creditLedger.Property(x => x.PricingVersion).HasMaxLength(100).IsRequired();
        creditLedger.HasIndex(x => new { x.AccountId, x.IdempotencyKey }).IsUnique();
        creditLedger.HasIndex(x => new { x.AccountId, x.CreatedAt });
        creditLedger.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
        creditLedger.HasOne<VibeQuantRun>()
            .WithMany()
            .HasForeignKey(x => x.RunId)
            .OnDelete(DeleteBehavior.NoAction);

        var vibeQuantRuns = modelBuilder.Entity<VibeQuantRun>();
        vibeQuantRuns.ToTable("vibe_quant_runs");
        vibeQuantRuns.HasKey(x => x.Id);
        vibeQuantRuns.Property(x => x.IdempotencyKey).HasMaxLength(100).IsRequired();
        vibeQuantRuns.Property(x => x.RequestSha256).HasMaxLength(64).IsFixedLength().IsRequired();
        vibeQuantRuns.Property(x => x.SpecSha256).HasMaxLength(64).IsFixedLength().IsRequired();
        vibeQuantRuns.Property(x => x.SpecJson).IsRequired();
        vibeQuantRuns.Property(x => x.ExecutionSpecJson).IsRequired();
        vibeQuantRuns.Property(x => x.ExecutionSpecSha256).HasMaxLength(64).IsFixedLength().IsRequired();
        vibeQuantRuns.Property(x => x.ExecutionProfileBinding).HasMaxLength(64).IsFixedLength().IsRequired();
        vibeQuantRuns.Property(x => x.ExecutionBindingNonce).HasMaxLength(64).IsRequired();
        vibeQuantRuns.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
        vibeQuantRuns.Property(x => x.UsageJson).IsRequired();
        vibeQuantRuns.Property(x => x.FinalArtifactSha256).HasMaxLength(64).IsFixedLength();
        vibeQuantRuns.Property(x => x.SafeMessage).HasMaxLength(1000);
        vibeQuantRuns.Property(x => x.BillableCostUsd).HasPrecision(18, 8);
        vibeQuantRuns.Property(x => x.WorkerLeaseDurationSeconds).IsRequired();
        vibeQuantRuns.Property(x => x.Version).IsConcurrencyToken();
        vibeQuantRuns.HasIndex(x => new { x.AccountId, x.IdempotencyKey }).IsUnique();
        vibeQuantRuns.HasIndex(x => new { x.AccountId, x.UpdatedAt });
        vibeQuantRuns.HasIndex(x => new { x.Status, x.CreatedAt });
        vibeQuantRuns.HasIndex(x => new { x.Status, x.WorkerLeaseExpiresAt });
        vibeQuantRuns.HasOne<Profile>()
            .WithMany()
            .HasForeignKey(x => x.AccountId)
            .OnDelete(DeleteBehavior.NoAction);
    }
}
