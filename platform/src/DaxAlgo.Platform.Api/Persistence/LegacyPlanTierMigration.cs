using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Persistence;

public static class LegacyPlanTierMigration
{
    private const string InMemoryProvider = "Microsoft.EntityFrameworkCore.InMemory";
    private const string PostgreSqlProvider = "Npgsql.EntityFrameworkCore.PostgreSQL";

    private const string CreateAuditTableSql = """
        CREATE TABLE IF NOT EXISTS subscription_plan_migration_audit_events (
            "MigrationKey" varchar(100) NOT NULL,
            "AccountId" uuid NOT NULL,
            "ProviderSubscriptionId" varchar(200) NOT NULL,
            "CurrentPeriodEnd" timestamptz NOT NULL,
            "PreviousPlan" integer NOT NULL,
            "NewPlan" integer NOT NULL,
            "OccurredAt" timestamptz NOT NULL,
            PRIMARY KEY ("MigrationKey", "AccountId")
        );
        """;

    private const string PromoteLegacyPlanSql = """
        WITH promoted AS (
            UPDATE subscriptions
            SET "Plan" = 2
            WHERE "Plan" = 1
            RETURNING "AccountId", "ProviderSubscriptionId", "CurrentPeriodEnd"
        )
        INSERT INTO subscription_plan_migration_audit_events (
            "MigrationKey",
            "AccountId",
            "ProviderSubscriptionId",
            "CurrentPeriodEnd",
            "PreviousPlan",
            "NewPlan",
            "OccurredAt")
        SELECT
            '20260726-plan-1-to-2',
            "AccountId",
            "ProviderSubscriptionId",
            "CurrentPeriodEnd",
            1,
            2,
            CURRENT_TIMESTAMP
        FROM promoted
        ON CONFLICT ("MigrationKey", "AccountId") DO NOTHING;
        """;

    public static async Task<int> ApplyAsync(
        PlatformDbContext database,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        if (string.Equals(database.Database.ProviderName, InMemoryProvider, StringComparison.Ordinal))
        {
            return 0;
        }

        if (!string.Equals(database.Database.ProviderName, PostgreSqlProvider, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Unsupported database provider '{database.Database.ProviderName}' for platform data migrations.");
        }

        await using var transaction = await database.Database.BeginTransactionAsync(cancellationToken);
        await database.Database.ExecuteSqlRawAsync(CreateAuditTableSql, cancellationToken);
        var affectedRows = await database.Database.ExecuteSqlRawAsync(
            PromoteLegacyPlanSql,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return affectedRows;
    }
}
