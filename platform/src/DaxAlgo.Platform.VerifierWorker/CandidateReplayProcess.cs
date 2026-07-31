using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Text.Json;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class CandidateReplayProcess
{
    private const string RequestSchema = "daxalgo.verifier.candidate-replay-request/v1";
    private const string ResponseSchema = "daxalgo.verifier.candidate-replay-response/v1";
    private const int MaximumAssemblyBytes = 4 * 1024 * 1024;
    private const int MaximumRequestBytes = 1024 * 1024;
    private const int MaximumResultBytes = 256 * 1024;
    private const int MaximumCapturedOutputBytes = 16 * 1024;
    private const int MaximumCleanupAttempts = 21;
    private const long MaximumNumericValue = 1_000_000_000_000;
    private static readonly TimeSpan CleanupRetryDelay = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan ReplayTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan TerminationTimeout = TimeSpan.FromSeconds(2);

    public static async Task<CandidateExecution> ExecuteAsync(
        byte[] assemblyBytes,
        string strategyTypeName,
        VerifierContract requestContract,
        VerificationCase verificationCase)
    {
        ArgumentNullException.ThrowIfNull(assemblyBytes);
        ArgumentException.ThrowIfNullOrWhiteSpace(strategyTypeName);
        ArgumentNullException.ThrowIfNull(requestContract);
        ArgumentNullException.ThrowIfNull(verificationCase);
        if (assemblyBytes.Length is 0 or > MaximumAssemblyBytes)
        {
            return Failure(
                "replay-assembly-bound",
                "CandidateProcessProtocol",
                "The compiled candidate exceeded the replay assembly bound.");
        }

        var appHostPath = ResolveWorkerAppHost();
        var workDirectory = Directory.CreateTempSubdirectory("daxalgo-verifier-replay-");
        Process? process = null;
        var processStarted = false;
        Exception? primaryException = null;
        try
        {
            var assemblyPath = Path.Combine(workDirectory.FullName, "candidate.dll");
            var requestPath = Path.Combine(workDirectory.FullName, "request.json");
            var resultPath = Path.Combine(workDirectory.FullName, "result.json");
            var assemblySha256 = VerifierToolchain.Hash(assemblyBytes);
            var request = new CandidateReplayRequest(
                RequestSchema,
                assemblySha256,
                strategyTypeName,
                requestContract,
                verificationCase);
            var requestBytes = JsonSerializer.SerializeToUtf8Bytes(
                request,
                CandidateReplayJsonContext.Default.CandidateReplayRequest);
            if (requestBytes.Length > MaximumRequestBytes)
            {
                return Failure(
                    "replay-request-bound",
                    "CandidateProcessProtocol",
                    "The candidate replay request exceeded its byte bound.");
            }

            WriteSnapshot(assemblyPath, assemblyBytes);
            WriteSnapshot(requestPath, requestBytes);
            var requestSha256 = VerifierToolchain.Hash(requestBytes);
            process = CreateProcess(
                appHostPath,
                workDirectory.FullName,
                assemblyPath,
                requestPath,
                resultPath);
            if (!process.Start())
            {
                throw new InvalidOperationException("The fixed verifier apphost did not start.");
            }
            processStarted = true;

            var outputExceeded = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var stdoutTask = CaptureBoundedAsync(
                process.StandardOutput.BaseStream,
                outputExceeded);
            var stderrTask = CaptureBoundedAsync(
                process.StandardError.BaseStream,
                outputExceeded);
            var exitTask = process.WaitForExitAsync();
            using var timeoutCancellation = new CancellationTokenSource();
            var timeoutTask = Task.Delay(ReplayTimeout, timeoutCancellation.Token);
            await Task.WhenAny(exitTask, timeoutTask, outputExceeded.Task);

            if (!exitTask.IsCompleted)
            {
                var exceeded = outputExceeded.Task.IsCompleted;
                await TerminateProcessTreeAsync(process);
                await FinishCapturesAsync(stdoutTask, stderrTask);
                return exceeded
                    ? Failure(
                        "replay-output-bound",
                        "CandidateProcessOutputLimit",
                        "The candidate replay exceeded its process-output bound.")
                    : Failure(
                        "replay-timeout",
                        "CandidateProcessTimeout",
                        "The candidate replay exceeded its hard time bound.");
            }

            timeoutCancellation.Cancel();
            await exitTask;
            var captures = await FinishCapturesAsync(stdoutTask, stderrTask);
            if (captures.Any(item => item.Exceeded))
            {
                return Failure(
                    "replay-output-bound",
                    "CandidateProcessOutputLimit",
                    "The candidate replay exceeded its process-output bound.");
            }

            if (process.ExitCode != 0)
            {
                return Failure(
                    "replay-crash",
                    "CandidateProcessFailure",
                    "The candidate replay process terminated without a valid result.");
            }

            if (captures.Any(item => item.Bytes.Length != 0))
            {
                return Failure(
                    "replay-unexpected-output",
                    "CandidateProcessProtocol",
                    "The candidate replay produced unexpected process output.");
            }

            return ReadResponse(
                resultPath,
                requestSha256,
                assemblySha256);
        }
        catch (Exception exception)
        {
            primaryException = exception;
            throw;
        }
        finally
        {
            var cleanupException = await CleanupReplayResourcesAsync(
                process,
                processStarted,
                workDirectory.FullName);
            if (cleanupException is not null)
            {
                ThrowCleanupFailure(primaryException, cleanupException);
            }
        }
    }

    public static async Task<int> RunChildAsync(
        string assemblyPath,
        string requestPath,
        string resultPath)
    {
        var assemblyBytes = HeadlessStrategyVerifier.ReadBoundedFile(
            assemblyPath,
            MaximumAssemblyBytes);
        var requestBytes = HeadlessStrategyVerifier.ReadBoundedFile(
            requestPath,
            MaximumRequestBytes);
        var request = JsonSerializer.Deserialize(
            requestBytes,
            CandidateReplayJsonContext.Default.CandidateReplayRequest);
        if (request is null
            || !requestBytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(
                request,
                CandidateReplayJsonContext.Default.CandidateReplayRequest))
            || !IsValidRequest(request)
            || !string.Equals(
                VerifierToolchain.Hash(assemblyBytes),
                request.AssemblySha256,
                StringComparison.Ordinal))
        {
            return 4;
        }

        var execution = await CandidateExecutor.ExecuteInProcessAsync(
            assemblyBytes,
            request.StrategyTypeName,
            request.Contract,
            request.Case);
        var response = new CandidateReplayResponse(
            ResponseSchema,
            VerifierToolchain.Hash(requestBytes),
            request.AssemblySha256,
            execution);
        var responseBytes = JsonSerializer.SerializeToUtf8Bytes(
            response,
            CandidateReplayJsonContext.Default.CandidateReplayResponse);
        if (responseBytes.Length > MaximumResultBytes)
        {
            return 4;
        }

        WriteSnapshot(Path.GetFullPath(resultPath), responseBytes);
        return 0;
    }

    private static Process CreateProcess(
        string appHostPath,
        string workDirectory,
        string assemblyPath,
        string requestPath,
        string resultPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = appHostPath,
            WorkingDirectory = workDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.Environment.Clear();
        foreach (var argument in new[]
                 {
                     "replay",
                     "--assembly",
                     assemblyPath,
                     "--request",
                     requestPath,
                     "--result",
                     resultPath,
                 })
        {
            startInfo.ArgumentList.Add(argument);
        }

        return new() { StartInfo = startInfo };
    }

    private static string ResolveWorkerAppHost()
    {
        var name = OperatingSystem.IsWindows()
            ? "DaxAlgo.Platform.VerifierWorker.exe"
            : "DaxAlgo.Platform.VerifierWorker";
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, name));
        var file = new FileInfo(path);
        if (!file.Exists
            || file.LinkTarget is not null
            || (file.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("The fixed verifier apphost is unavailable.");
        }

        return path;
    }

    private static async Task<OutputCapture> CaptureBoundedAsync(
        Stream stream,
        TaskCompletionSource outputExceeded)
    {
        var buffer = new byte[4096];
        using var captured = new MemoryStream(MaximumCapturedOutputBytes);
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0)
            {
                return new(captured.ToArray(), Exceeded: false);
            }

            var remaining = MaximumCapturedOutputBytes - checked((int)captured.Length);
            var accepted = Math.Min(read, Math.Max(remaining, 0));
            if (accepted > 0)
            {
                captured.Write(buffer, 0, accepted);
            }

            if (accepted != read)
            {
                outputExceeded.TrySetResult();
                return new(captured.ToArray(), Exceeded: true);
            }
        }
    }

    private static async Task<OutputCapture[]> FinishCapturesAsync(
        Task<OutputCapture> stdoutTask,
        Task<OutputCapture> stderrTask)
    {
        try
        {
            return await Task.WhenAll(stdoutTask, stderrTask).WaitAsync(TerminationTimeout);
        }
        catch (TimeoutException exception)
        {
            throw new InvalidOperationException(
                "The candidate replay output pipes did not close after process termination.",
                exception);
        }
    }

    private static async Task TerminateProcessTreeAsync(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) when (process.HasExited)
        {
        }

        try
        {
            await process.WaitForExitAsync().WaitAsync(TerminationTimeout);
        }
        catch (TimeoutException exception)
        {
            throw new InvalidOperationException(
                "The candidate replay process tree could not be terminated.",
                exception);
        }
    }

    private static Task DeleteWorkDirectoryAsync(string workDirectory) =>
        DeleteWorkDirectoryAsync(
            workDirectory,
            static delay => Task.Delay(delay),
            MaximumCleanupAttempts);

    internal static async Task DeleteWorkDirectoryAsync(
        string workDirectory,
        Func<TimeSpan, Task> retryDelay,
        int maximumAttempts)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workDirectory);
        ArgumentNullException.ThrowIfNull(retryDelay);
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumAttempts, 1);

        var resolved = Path.GetFullPath(workDirectory);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                Directory.Delete(resolved, recursive: true);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                return;
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException
                && attempt < maximumAttempts)
            {
                await retryDelay(CleanupRetryDelay);
            }
        }
    }

    private static Task<Exception?> CleanupReplayResourcesAsync(
        Process? process,
        bool processStarted,
        string workDirectory) =>
        CleanupReplayResourcesAsync(
            process,
            processStarted,
            workDirectory,
            static delay => Task.Delay(delay),
            MaximumCleanupAttempts);

    internal static async Task<Exception?> CleanupReplayResourcesAsync(
        Process? process,
        bool processStarted,
        string workDirectory,
        Func<TimeSpan, Task> retryDelay,
        int maximumAttempts)
    {
        Exception? cleanupException = null;
        if (process is not null)
        {
            if (processStarted)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        await TerminateProcessTreeAsync(process);
                    }
                }
                catch (Exception exception)
                {
                    cleanupException = AppendCleanupFailure(cleanupException, exception);
                }
            }

            try
            {
                process.Dispose();
            }
            catch (Exception exception)
            {
                cleanupException = AppendCleanupFailure(cleanupException, exception);
            }
        }

        try
        {
            await DeleteWorkDirectoryAsync(workDirectory, retryDelay, maximumAttempts);
        }
        catch (Exception exception)
        {
            cleanupException = AppendCleanupFailure(cleanupException, exception);
        }

        return cleanupException;
    }

    internal static void ThrowCleanupFailure(
        Exception? primaryException,
        Exception cleanupException)
    {
        ArgumentNullException.ThrowIfNull(cleanupException);
        if (primaryException is not null)
        {
            throw new AggregateException(
                "The candidate replay failed and resource cleanup also failed.",
                primaryException,
                cleanupException);
        }

        ExceptionDispatchInfo.Capture(cleanupException).Throw();
        throw new UnreachableException();
    }

    private static Exception AppendCleanupFailure(
        Exception? current,
        Exception next) =>
        current is null
            ? next
            : new AggregateException(
                "Multiple candidate replay resource-cleanup operations failed.",
                current,
                next);

    private static CandidateExecution ReadResponse(
        string resultPath,
        string requestSha256,
        string assemblySha256)
    {
        try
        {
            var responseBytes = HeadlessStrategyVerifier.ReadBoundedFile(
                resultPath,
                MaximumResultBytes);
            var response = JsonSerializer.Deserialize(
                responseBytes,
                CandidateReplayJsonContext.Default.CandidateReplayResponse);
            if (response is null
                || !responseBytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(
                    response,
                    CandidateReplayJsonContext.Default.CandidateReplayResponse))
                || !string.Equals(response.SchemaVersion, ResponseSchema, StringComparison.Ordinal)
                || !string.Equals(response.RequestSha256, requestSha256, StringComparison.Ordinal)
                || !string.Equals(response.AssemblySha256, assemblySha256, StringComparison.Ordinal)
                || !IsValidExecution(response.Execution))
            {
                return MalformedResponse();
            }

            return response.Execution;
        }
        catch (Exception exception) when (exception is
            IOException or
            InvalidDataException or
            UnauthorizedAccessException or
            ArgumentException or
            NotSupportedException or
            JsonException)
        {
            return MalformedResponse();
        }
    }

    private static bool IsValidRequest(CandidateReplayRequest request) =>
        string.Equals(request.SchemaVersion, RequestSchema, StringComparison.Ordinal)
        && IsSha256(request.AssemblySha256)
        && IsText(request.StrategyTypeName, 1, 512, allowBlank: false)
        && IsValidContract(request.Contract)
        && request.Case is not null
        && IsText(request.Case.CaseId, 1, 128, allowBlank: false)
        && request.Case.StartUtc.Kind == DateTimeKind.Utc
        && request.Case.Ticks is { Length: <= 2048 }
        && request.Case.Ticks.All(item => item is not null
            && item.OffsetMilliseconds is >= 0 and <= 604_800_000
            && double.IsFinite(item.Bid)
            && double.IsFinite(item.Ask)
            && Math.Abs(item.Bid) <= MaximumNumericValue
            && Math.Abs(item.Ask) <= MaximumNumericValue
            && item.BidSize is >= 0 and <= MaximumNumericValue
            && item.AskSize is >= 0 and <= MaximumNumericValue);

    private static bool IsValidExecution(CandidateExecution? execution)
    {
        if (execution?.Trace is null
            || execution.Trace.Length > CandidateExecutor.MaximumTraceEntries
            || !IsSha256(execution.Hash)
            || (execution.Error is not null
                && (!IsText(execution.Error.Code, 1, 64, allowBlank: false)
                    || !IsText(execution.Error.Type, 1, 256, allowBlank: false)
                    || !IsText(execution.Error.Message, 1, 512, allowBlank: false))))
        {
            return false;
        }

        for (var index = 0; index < execution.Trace.Length; index++)
        {
            var item = execution.Trace[index];
            if (item is null
                || item.Sequence != index + 1
                || item.Kind is not ("place" or "cancel")
                || !IsText(item.AtUtc, 20, 40, allowBlank: false)
                || !IsText(item.ClientOrderId, 1, 256, allowBlank: false)
                || !IsOptionalText(item.Side, 64)
                || !IsOptionalText(item.Type, 64)
                || !IsOptionalText(item.TimeInForce, 64)
                || (item.Quantity is not null
                    && item.Quantity is not (>= 1 and <= MaximumNumericValue))
                || !IsOptionalNumber(item.LimitPrice)
                || !IsOptionalNumber(item.StopPrice))
            {
                return false;
            }

            if (item.Kind == "place")
            {
                if (!IsValidContract(item.Contract)
                    || item.Side is null
                    || item.Type is null
                    || item.Quantity is null
                    || item.TimeInForce is null)
                {
                    return false;
                }
            }
            else if (item.Contract is not null
                     || item.Side is not null
                     || item.Type is not null
                     || item.Quantity is not null
                     || item.LimitPrice is not null
                     || item.StopPrice is not null
                     || item.TimeInForce is not null)
            {
                return false;
            }
        }

        return string.Equals(
            execution.Hash,
            CandidateExecutor.ComputeHash(execution.Trace, execution.Error),
            StringComparison.Ordinal);
    }

    private static bool IsValidContract(VerifierContract? contract) =>
        contract is not null
        && IsText(contract.Symbol, 1, 64, allowBlank: false)
        && IsText(contract.SecType, 1, 32, allowBlank: false)
        && IsText(contract.Exchange, 1, 64, allowBlank: false)
        && IsText(contract.Currency, 1, 16, allowBlank: false)
        && IsText(contract.PrimaryExchange, 1, 64, allowBlank: false);

    private static bool IsOptionalText(string? value, int maximumLength) =>
        value is null || IsText(value, 1, maximumLength, allowBlank: true);

    private static bool IsText(
        string? value,
        int minimumLength,
        int maximumLength,
        bool allowBlank) =>
        value is not null
        && value.Length >= minimumLength
        && value.Length <= maximumLength
        && (allowBlank || !string.IsNullOrWhiteSpace(value))
        && value.All(character => !char.IsControl(character) && !char.IsSurrogate(character));

    private static bool IsOptionalNumber(double? value) =>
        value is null
        || (double.IsFinite(value.Value) && Math.Abs(value.Value) <= MaximumNumericValue);

    private static bool IsSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static CandidateExecution MalformedResponse() =>
        Failure(
            "replay-malformed-output",
            "CandidateProcessProtocol",
            "The candidate replay returned a malformed result.");

    private static CandidateExecution Failure(
        string code,
        string type,
        string message)
    {
        VerifierTraceEntry[] trace = [];
        var error = new VerifierRuntimeError(code, type, message);
        return new(trace, error, CandidateExecutor.ComputeHash(trace, error));
    }

    private static void WriteSnapshot(string path, byte[] bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 16 * 1024,
            options: FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private sealed record OutputCapture(byte[] Bytes, bool Exceeded);
}
