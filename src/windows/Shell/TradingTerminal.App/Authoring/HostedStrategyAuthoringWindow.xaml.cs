using System.Windows;
using MahApps.Metro.Controls;

namespace TradingTerminal.App.Authoring;

public partial class HostedStrategyAuthoringWindow : MetroWindow
{
    private readonly HostedStrategyAuthoringViewModel _viewModel;
    private bool _initialized;

    public HostedStrategyAuthoringWindow(HostedStrategyAuthoringViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        Loaded += OnLoaded;
        Closed += OnClosed;
        viewModel.CloseRequested += OnCloseRequested;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_initialized) return;
        _initialized = true;
        await _viewModel.InitializeCommand.ExecuteAsync(null);
    }

    private void OnCloseRequested(object? sender, EventArgs e) => Close();

    private void OnClosed(object? sender, EventArgs e)
    {
        _viewModel.CloseRequested -= OnCloseRequested;
        _viewModel.Dispose();
    }
}
