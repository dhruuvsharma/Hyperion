using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Persistence;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class PersistenceModelTests
{
    [Fact]
    public async Task LegacyPlanMigrationIsSafeNoOpForCurrentTierData()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase($"migration-{Guid.NewGuid():N}")
            .Options;
        await using var database = new PlatformDbContext(options);
        var accountId = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 7, 26, 12, 0, 0, TimeSpan.Zero);
        var currentPeriodEnd = now.AddDays(30);
        database.Profiles.Add(new Profile
        {
            Id = accountId,
            Subject = "migration-current-tier",
            Email = "migration@example.test",
            DisplayName = "Migration Test",
            CreatedAt = now,
            UpdatedAt = now,
        });
        database.Subscriptions.Add(new AccountSubscription
        {
            AccountId = accountId,
            Provider = "test",
            ProviderSubscriptionId = "sub-professional",
            Plan = PlanTier.Professional,
            Status = SubscriptionStatus.Active,
            CurrentPeriodEnd = currentPeriodEnd,
            UpdatedAt = now,
        });
        await database.SaveChangesAsync();

        Assert.Equal(0, await LegacyPlanTierMigration.ApplyAsync(database));
        Assert.Equal(0, await LegacyPlanTierMigration.ApplyAsync(database));

        database.ChangeTracker.Clear();
        var subscription = await database.Subscriptions.SingleAsync();
        Assert.Equal(PlanTier.Professional, subscription.Plan);
        Assert.Equal("sub-professional", subscription.ProviderSubscriptionId);
        Assert.Equal(currentPeriodEnd, subscription.CurrentPeriodEnd);
    }

    [Fact]
    public void EfDeleteBehaviorsMatchTheCheckedInPostgresSchema()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase($"model-{Guid.NewGuid():N}")
            .Options;
        using var database = new PlatformDbContext(options);

        AssertDeleteBehavior<AccountSubscription>(
            database,
            nameof(AccountSubscription.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<RegisteredDevice>(
            database,
            nameof(RegisteredDevice.AccountId),
            DeleteBehavior.Cascade);
        AssertDeleteBehavior<CatalogItem>(
            database,
            nameof(CatalogItem.PublisherAccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceSubmission>(
            database,
            nameof(MarketplaceSubmission.PublisherAccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceOrder>(
            database,
            nameof(MarketplaceOrder.BuyerAccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceOrder>(
            database,
            nameof(MarketplaceOrder.CatalogItemId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceOrder>(
            database,
            nameof(MarketplaceOrder.ReleaseId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceReview>(
            database,
            nameof(MarketplaceReview.CatalogItemId),
            DeleteBehavior.Cascade);
        AssertDeleteBehavior<MarketplaceReview>(
            database,
            nameof(MarketplaceReview.AuthorAccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplacePublisher>(
            database,
            nameof(MarketplacePublisher.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceStrategyRelease>(
            database,
            nameof(MarketplaceStrategyRelease.CatalogItemId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceStrategyRelease>(
            database,
            nameof(MarketplaceStrategyRelease.SubmissionId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<EntitlementGrant>(
            database,
            nameof(EntitlementGrant.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<EntitlementGrant>(
            database,
            nameof(EntitlementGrant.CatalogItemId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<EntitlementGrant>(
            database,
            nameof(EntitlementGrant.OrderId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceLicense>(
            database,
            nameof(MarketplaceLicense.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceLicense>(
            database,
            nameof(MarketplaceLicense.ReleaseId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceLicense>(
            database,
            nameof(MarketplaceLicense.GrantId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceSignalSession>(
            database,
            nameof(MarketplaceSignalSession.LicenseId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceSignalSession>(
            database,
            nameof(MarketplaceSignalSession.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<MarketplaceSignalSession>(
            database,
            nameof(MarketplaceSignalSession.ReleaseId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<VibeQuantCreditWallet>(
            database,
            nameof(VibeQuantCreditWallet.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<VibeQuantCreditLedgerEntry>(
            database,
            nameof(VibeQuantCreditLedgerEntry.AccountId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<VibeQuantCreditLedgerEntry>(
            database,
            nameof(VibeQuantCreditLedgerEntry.RunId),
            DeleteBehavior.NoAction);
        AssertDeleteBehavior<VibeQuantRun>(
            database,
            nameof(VibeQuantRun.AccountId),
            DeleteBehavior.NoAction);
    }

    [Fact]
    public void DaxqLicensingEntitiesUseTheRequiredSchemasAndDurableIdempotencyKeys()
    {
        var options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase($"daxq-model-{Guid.NewGuid():N}")
            .Options;
        using var database = new PlatformDbContext(options);

        AssertTable<MarketplacePublisher>(database, "marketplace", "publisher");
        AssertTable<MarketplaceStrategyRelease>(database, "marketplace", "strategy_release");
        AssertTable<MarketplaceLicense>(database, "marketplace", "license");
        AssertTable<MarketplaceSignalSession>(database, "marketplace", "signal_session");
        AssertTable<EntitlementGrant>(database, "entitlements", "grant");
        AssertTable<MarketplaceContentKey>(database, "entitlements", "content_key");
        AssertTable<ContentKeyReleaseAudit>(database, "marketplace", "content_key_release");
        AssertTable<EntitlementRevocation>(database, "entitlements", "revocation");
        AssertTable<DeviceProofChallenge>(database, "entitlements", "device_proof_challenge");

        var contentKey = database.Model.FindEntityType(typeof(MarketplaceContentKey));
        Assert.NotNull(contentKey);
        Assert.Equal(
            128,
            contentKey!.FindProperty(nameof(MarketplaceContentKey.ContentKeyId))!.GetMaxLength());

        AssertUniqueIndex<MarketplacePublisher>(
            database,
            nameof(MarketplacePublisher.ConnectAccountId));
        AssertUniqueIndex<MarketplaceSubmission>(
            database,
            nameof(MarketplaceSubmission.ReleaseId));
        AssertUniqueIndex<MarketplaceStrategyRelease>(
            database,
            nameof(MarketplaceStrategyRelease.SubmissionId));
        AssertUniqueIndex<MarketplaceStrategyRelease>(
            database,
            nameof(MarketplaceStrategyRelease.CatalogItemId),
            nameof(MarketplaceStrategyRelease.Version));
        AssertUniqueIndex<MarketplaceStrategyRelease>(
            database,
            nameof(MarketplaceStrategyRelease.DiversificationSeedSha256));
        AssertUniqueIndex<EntitlementGrant>(database, nameof(EntitlementGrant.OrderId));
        AssertUniqueIndex<MarketplaceLicense>(database, nameof(MarketplaceLicense.GrantId));
        AssertUniqueIndex<MarketplaceLicense>(
            database,
            nameof(MarketplaceLicense.AccountId),
            nameof(MarketplaceLicense.ReleaseId));

        var audit = database.Model.FindEntityType(typeof(ContentKeyReleaseAudit));
        Assert.NotNull(audit);
        Assert.Contains(
            audit!.GetIndexes(),
            index => index.IsUnique
                && index.Properties.Select(property => property.Name)
                    .SequenceEqual([nameof(ContentKeyReleaseAudit.ChallengeId)]));
        var challenge = database.Model.FindEntityType(typeof(DeviceProofChallenge));
        Assert.NotNull(challenge);
        Assert.True(challenge!.FindProperty(nameof(DeviceProofChallenge.Version))!.IsConcurrencyToken);
    }

    [Fact]
    public void CheckedInSchemaUpgradesExistingDatabasesForTier3FieldsAndChallengeOperation()
    {
        var schema = File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "platform-schema.sql"));
        Assert.Contains(
            "ADD COLUMN IF NOT EXISTS \"RequestedExecutionClass\"",
            schema,
            StringComparison.Ordinal);
        Assert.Contains(
            "ck_marketplace_submissions_execution_class",
            schema,
            StringComparison.Ordinal);
        Assert.Contains(
            "ck_device_proof_challenge_operation",
            schema,
            StringComparison.Ordinal);
        Assert.Contains("'signal_session'", schema, StringComparison.Ordinal);
    }

    private static void AssertDeleteBehavior<TEntity>(
        PlatformDbContext database,
        string foreignKeyProperty,
        DeleteBehavior expected)
        where TEntity : class
    {
        var entity = database.Model.FindEntityType(typeof(TEntity));
        Assert.NotNull(entity);
        var relationship = Assert.Single(
            entity!.GetForeignKeys(),
            key => key.Properties.Count == 1
                && key.Properties[0].Name == foreignKeyProperty);
        Assert.Equal(expected, relationship.DeleteBehavior);
    }

    private static void AssertTable<TEntity>(
        PlatformDbContext database,
        string expectedSchema,
        string expectedTable)
        where TEntity : class
    {
        var entity = database.Model.FindEntityType(typeof(TEntity));
        Assert.NotNull(entity);
        Assert.Equal(expectedSchema, entity!.GetSchema());
        Assert.Equal(expectedTable, entity.GetTableName());
    }

    private static void AssertUniqueIndex<TEntity>(
        PlatformDbContext database,
        params string[] propertyNames)
        where TEntity : class
    {
        var entity = database.Model.FindEntityType(typeof(TEntity));
        Assert.NotNull(entity);
        Assert.Contains(
            entity!.GetIndexes(),
            index => index.IsUnique
                && index.Properties.Select(property => property.Name).SequenceEqual(propertyNames));
    }
}
