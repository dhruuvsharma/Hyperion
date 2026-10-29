namespace DaxAlgo.Coordinator.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        return await new CliApplication(Console.Out, Console.Error)
            .RunAsync(args, cancellation.Token)
            .ConfigureAwait(false);
    }
}
