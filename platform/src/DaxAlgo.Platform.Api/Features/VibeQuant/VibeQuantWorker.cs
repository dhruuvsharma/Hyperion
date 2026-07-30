using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using TradingTerminal.Ai.Coordinator.Contracts;

namespace DaxAlgo.Platform.Features.VibeQuant;

public sealed class VibeQuantWorker(
    IServiceScopeFactory scopeFactory,
    VibeQuantOptions options,
    VibeQuantExecutionCancellationRegistry cancellationRegistry,
    ILogger<VibeQuantWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                VibeQuantRun? run;
                await using (var claimScope = scopeFactory.CreateAsyncScope())
                {
                    var service = claimScope.ServiceProvider.GetRequiredService<VibeQuantService>();
                    run = await service.ClaimNextAsync(stoppingToken);
                }
                if (run is null)
                {
                    await Task.Delay(options.WorkerPollMilliseconds, stoppingToken);
                    continue;
                }

                if (run.WorkerLeaseId is not { } workerLeaseId)
                {
                    throw new InvalidOperationException("Claimed Vibe Quant run has no worker lease.");
                }

                try
                {
                    var requestedToken = cancellationRegistry.Ensure(
                        run.Id,
                        workerLeaseId,
                        run.CancellationRequested);
                    using var leaseLost = new CancellationTokenSource();
                    using var executionCancellation = CancellationTokenSource.CreateLinkedTokenSource(
                        stoppingToken,
                        requestedToken,
                        leaseLost.Token);
                    using var heartbeatCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    var heartbeat = MaintainLeaseAsync(
                        run.Id,
                        workerLeaseId,
                        run.WorkerLeaseDurationSeconds,
                        leaseLost,
                        heartbeatCancellation.Token);
                    VibeQuantExecutionResult result;
                    try
                    {
                        await using var executionScope = scopeFactory.CreateAsyncScope();
                        var runtime = executionScope.ServiceProvider.GetRequiredService<IVibeQuantExecutionRuntime>();
                        result = await runtime.ExecuteAsync(run, executionCancellation.Token);
                    }
                    catch (OperationCanceledException) when (
                        requestedToken.IsCancellationRequested && !stoppingToken.IsCancellationRequested)
                    {
                        result = new VibeQuantExecutionResult(
                            CoordinatorRunStatus.Cancelled,
                            0,
                            new CoordinatorUsage(),
                            0m,
                            null,
                            "Cancelled by the authenticated account.");
                    }
                    finally
                    {
                        heartbeatCancellation.Cancel();
                        await heartbeat.ConfigureAwait(false);
                    }

                    if (leaseLost.IsCancellationRequested)
                    {
                        throw new PlatformConflictException("The Vibe Quant worker lost its execution lease.");
                    }

                    await using var completionScope = scopeFactory.CreateAsyncScope();
                    var service = completionScope.ServiceProvider.GetRequiredService<VibeQuantService>();
                    await service.CompleteExecutionAsync(run.Id, workerLeaseId, result, stoppingToken);
                }
                finally
                {
                    cancellationRegistry.Complete(run.Id, workerLeaseId);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                VibeQuantLogging.WorkerLoopFailed(logger, exception);
                await Task.Delay(options.WorkerPollMilliseconds, stoppingToken);
            }
        }
    }

    private async Task MaintainLeaseAsync(
        Guid runId,
        Guid workerLeaseId,
        int leaseDurationSeconds,
        CancellationTokenSource leaseLost,
        CancellationToken cancellationToken)
    {
        var heartbeatInterval = TimeSpan.FromSeconds(Math.Max(1, Math.Min(10, leaseDurationSeconds / 3)));
        try
        {
            while (true)
            {
                await Task.Delay(heartbeatInterval, cancellationToken).ConfigureAwait(false);
                await using var scope = scopeFactory.CreateAsyncScope();
                var service = scope.ServiceProvider.GetRequiredService<VibeQuantService>();
                if (await service.RenewLeaseAsync(
                        runId,
                        workerLeaseId,
                        cancellationToken).ConfigureAwait(false))
                {
                    cancellationRegistry.Request(runId);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch
        {
            leaseLost.Cancel();
            throw;
        }
    }
}
