using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class PlatformApiFactory : WebApplicationFactory<Program>
{
    private readonly Action<IServiceCollection>? configureServices;
    private readonly IReadOnlyDictionary<string, string?> configurationValues;
    private readonly int workerPollMilliseconds;
    private readonly string databaseName = $"platform-tests-{Guid.NewGuid():N}";
    private readonly string vibeQuantWorkspace = Path.Combine(
        Path.GetTempPath(),
        $"daxalgo-vibe-quant-tests-{Guid.NewGuid():N}");

    public PlatformApiFactory(
        Action<IServiceCollection>? configureServices = null,
        int workerPollMilliseconds = 50,
        IReadOnlyDictionary<string, string?>? configurationValues = null)
    {
        this.configureServices = configureServices;
        this.workerPollMilliseconds = workerPollMilliseconds;
        this.configurationValues = configurationValues
            ?? new Dictionary<string, string?>();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            var values = new Dictionary<string, string?>
            {
                ["Storage:Provider"] = "InMemory",
                ["Storage:DatabaseName"] = databaseName,
                ["Identity:Provider"] = "Development",
                ["Billing:Provider"] = "Development",
                ["Lease:Provider"] = EntitlementLeaseSigningProviderSelection.SoftwareProvider,
                ["VibeQuant:Mode"] = "Mock",
                ["VibeQuant:WorkspacePath"] = vibeQuantWorkspace,
                ["VibeQuant:WorkerPollMilliseconds"] = workerPollMilliseconds.ToString(
                    System.Globalization.CultureInfo.InvariantCulture),
            };
            foreach (var (key, value) in configurationValues)
            {
                values[key] = value;
            }

            configuration.AddInMemoryCollection(values);
        });
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<PlatformDbContext>>();
            services.RemoveAll<PlatformDbContext>();
            services.AddDbContext<PlatformDbContext>(options =>
                options.UseInMemoryDatabase(databaseName));
        });
        if (configureServices is not null)
        {
            builder.ConfigureServices(configureServices);
        }
    }

    public async Task<Guid> GetAccountIdAsync(string subject)
    {
        await using var scope = Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<PlatformDbContext>();
        return await database.Profiles.AsNoTracking()
            .Where(profile => profile.Subject == subject)
            .Select(profile => profile.Id)
            .SingleAsync();
    }
}
