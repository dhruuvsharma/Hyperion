using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace TradingTerminal.App.Authoring;

public static class HostedStrategyAuthoringServiceCollectionExtensions
{
    public static IServiceCollection AddHostedStrategyAuthoring(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<VibeQuantHostedOptions>(
            configuration.GetSection(VibeQuantHostedOptions.SectionName));
        services.AddHttpClient(VibeQuantDesktopClientFactory.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
            });
        services.AddSingleton<IVibeQuantDesktopClientFactory, VibeQuantDesktopClientFactory>();
        services.AddSingleton<IHostedStrategyPollDelay, HostedStrategyPollDelay>();
        services.AddSingleton<IHostedStrategyRunBookmarkStore, HostedStrategyRunBookmarkStore>();
        services.AddTransient<HostedStrategyAuthoringViewModel>();
        services.AddTransient<HostedStrategyAuthoringWindow>();
        services.AddSingleton<IHostedStrategyAuthoringDialog, HostedStrategyAuthoringDialog>();
        return services;
    }
}
