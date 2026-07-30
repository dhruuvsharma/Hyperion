using DaxAlgo.Platform.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace DaxAlgo.Platform.Persistence;

public static class PersistenceRegistration
{
    public static IServiceCollection AddPlatformPersistence(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var storage = configuration.GetSection(StorageOptions.SectionName).Get<StorageOptions>()
            ?? new StorageOptions();

        services.AddDbContext<PlatformDbContext>(options =>
        {
            if (string.Equals(storage.Provider, "InMemory", StringComparison.OrdinalIgnoreCase))
            {
                options.UseInMemoryDatabase(storage.DatabaseName);
                return;
            }

            if (string.Equals(storage.Provider, "Postgres", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(storage.ConnectionString))
                {
                    throw new InvalidOperationException(
                        "Storage:ConnectionString is required when Storage:Provider is Postgres.");
                }

                options.UseNpgsql(storage.ConnectionString);
                return;
            }

            throw new InvalidOperationException(
                $"Unsupported Storage:Provider '{storage.Provider}'. Expected InMemory or Postgres.");
        });

        services.AddHealthChecks()
            .AddCheck<PlatformDatabaseHealthCheck>("platform-database");
        return services;
    }

    public static async Task InitializePlatformDatabaseAsync(
        this IServiceProvider services,
        CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        if (string.Equals(
                context.Database.ProviderName,
                "Microsoft.EntityFrameworkCore.InMemory",
                StringComparison.Ordinal))
        {
            await context.Database.EnsureCreatedAsync(cancellationToken);
        }

        await LegacyPlanTierMigration.ApplyAsync(context, cancellationToken);
    }
}

public sealed class PlatformDatabaseHealthCheck(
    IServiceScopeFactory scopeFactory) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        return await database.Database.CanConnectAsync(cancellationToken)
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("The platform database is unavailable.");
    }
}
