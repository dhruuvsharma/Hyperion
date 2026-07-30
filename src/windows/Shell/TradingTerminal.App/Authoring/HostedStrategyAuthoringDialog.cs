using System.Windows;
using Microsoft.Extensions.DependencyInjection;

namespace TradingTerminal.App.Authoring;

public interface IHostedStrategyAuthoringDialog
{
    void Show(Window? owner);
}

public sealed class HostedStrategyAuthoringDialog(IServiceProvider services)
    : IHostedStrategyAuthoringDialog
{
    public void Show(Window? owner)
    {
        using var scope = services.CreateScope();
        var window = scope.ServiceProvider.GetRequiredService<HostedStrategyAuthoringWindow>();
        window.Owner = owner;
        window.ShowDialog();
    }
}
