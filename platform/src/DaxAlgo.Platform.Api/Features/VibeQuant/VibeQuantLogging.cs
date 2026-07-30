namespace DaxAlgo.Platform.Features.VibeQuant;

internal static partial class VibeQuantLogging
{
    [LoggerMessage(
        EventId = 4101,
        Level = LogLevel.Error,
        Message = "Vibe Quant execution failed for run {RunId} with {FailureType}.")]
    public static partial void ExecutionFailed(
        ILogger logger,
        Guid runId,
        string failureType,
        Exception exception);

    [LoggerMessage(
        EventId = 4102,
        Level = LogLevel.Warning,
        Message = "Could not signal local coordinator cancellation for run {RunId}.")]
    public static partial void CancellationSignalFailed(
        ILogger logger,
        Guid runId,
        Exception exception);

    [LoggerMessage(
        EventId = 4103,
        Level = LogLevel.Error,
        Message = "The Vibe Quant worker loop failed; it will retry after the poll interval.")]
    public static partial void WorkerLoopFailed(ILogger logger, Exception exception);
}
