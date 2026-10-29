using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using DaxAlgo.Daxq.Compiler;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Coordinator.Cli;

internal sealed class DaxqExpertDatasetExecutableVerifier : IExpertDatasetExecutableVerifier
{
    private const string WorkerRequestSchemaVersion =
        "daxalgo.expert-model-daxq-worker-request/v1";
    private const string TraceSchemaVersion = "daxalgo.expert-model-daxq-trace/v1";
    private const int MaxWorkerRequestBytes = 8_000_000;
    private const int MaxWorkerResponseBytes = 128_000;
    private const int MaxCapturedOutputCharacters = 64_000;
    private const long MaxWorkerProcessMemoryBytes = 768L * 1024L * 1024L;
    private const string WorkerStartSignal = "daxalgo-daxq-worker-start/v1";
    private static readonly TimeSpan WorkerTimeout = TimeSpan.FromSeconds(20);

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    public async Task<ExpertDatasetExecutableResult> VerifyAsync(
        ExpertModelDatasetExample example,
        ExpertDatasetVerifierAssignment assignment,
        CancellationToken cancellationToken)
    {
        var specification = assignment.ExecutableVerification
            ?? throw new CoordinatorValidationException(
                $"Verifier '{assignment.VerifierId}' has no executable specification.");
        var request = new WorkerRequest
        {
            SchemaVersion = WorkerRequestSchemaVersion,
            Source = example.Messages[^1].Content,
            Specification = specification
        };
        var workspaceRoot = Path.Combine(
            Path.GetTempPath(),
            "daxalgo-expert-verifier",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workspaceRoot);
        var requestPath = Path.Combine(workspaceRoot, "request.json");
        var responsePath = Path.Combine(workspaceRoot, "response.json");
        try
        {
            await WriteJsonNewAsync(
                requestPath,
                request,
                MaxWorkerRequestBytes,
                cancellationToken).ConfigureAwait(false);
            await RunWorkerProcessAsync(
                requestPath,
                responsePath,
                workspaceRoot,
                cancellationToken).ConfigureAwait(false);
            var result = await ReadJsonAsync<ExpertDatasetExecutableResult>(
                responsePath,
                MaxWorkerResponseBytes,
                "DAXQ verifier response",
                cancellationToken).ConfigureAwait(false);
            var expectedSourceSha256 = Sha256Hex(StrictUtf8.GetBytes(request.Source));
            var expectedSpecificationSha256 = Sha256Hex(
                JsonSerializer.SerializeToUtf8Bytes(specification, CompactJson));
            if (result.Profile != ExpertModelDatasetReviewTools.DaxqExecutableProfile ||
                !StringComparer.Ordinal.Equals(result.SourceSha256, expectedSourceSha256) ||
                !StringComparer.Ordinal.Equals(
                    result.TestSpecificationSha256,
                    expectedSpecificationSha256))
            {
                throw new CoordinatorValidationException(
                    "DAXQ verifier response does not bind the exact source and test specification.");
            }
            return result;
        }
        finally
        {
            TryDeleteWorkspace(workspaceRoot);
        }
    }

    internal static async Task<int> RunWorkerAsync(
        string requestPath,
        string outputPath,
        CancellationToken cancellationToken)
    {
        var startSignal = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (!StringComparer.Ordinal.Equals(startSignal, WorkerStartSignal))
        {
            throw new CoordinatorValidationException(
                "DAXQ verifier worker did not receive its constrained-start signal.");
        }
        var request = await ReadJsonAsync<WorkerRequest>(
            requestPath,
            MaxWorkerRequestBytes,
            "DAXQ verifier request",
            cancellationToken).ConfigureAwait(false);
        ValidateWorkerRequest(request);
        var result = Execute(request);
        await WriteJsonNewAsync(
            outputPath,
            result,
            MaxWorkerResponseBytes,
            cancellationToken).ConfigureAwait(false);
        return 0;
    }

    private static ExpertDatasetExecutableResult Execute(WorkerRequest request)
    {
        var sourceSha256 = Sha256Hex(StrictUtf8.GetBytes(request.Source));
        var specificationSha256 = Sha256Hex(
            JsonSerializer.SerializeToUtf8Bytes(request.Specification, CompactJson));
        var compilerClosureSha256 = ComputeCompilerClosureSha256();
        DaxqLoweringResult lowering;
        try
        {
            lowering = new DaxqRoslynCompiler().CompileAndLower(
                request.Source,
                "ExpertStrategy.cs");
        }
        catch (DaxqCompilationException exception)
        {
            return FailedCompilation(
                sourceSha256,
                specificationSha256,
                compilerClosureSha256,
                request.Specification,
                exception.Diagnostics.Select(diagnostic => diagnostic.Code));
        }

        DaxqPlaintextBuildResult plaintext;
        try
        {
            plaintext = DaxqPlaintextBuilder.BuildCanonical(lowering.Program);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return FailedCompilation(
                sourceSha256,
                specificationSha256,
                compilerClosureSha256,
                request.Specification,
                ["DAXQ-VERIFY-PLAINTEXT"]);
        }

        var canonicalProgramSha256 = Sha256Hex(plaintext.PreDiversificationPlaintext);
        var loadFault = DaxqProgram.TryLoad(
            plaintext.PreDiversificationPlaintext,
            out var program);
        if (loadFault != DaxqFault.Ok || program is null)
        {
            return FailedTests(
                sourceSha256,
                specificationSha256,
                compilerClosureSha256,
                canonicalProgramSha256,
                request.Specification,
                traceSha256: null,
                ["DAXQ-VERIFY-PROGRAM-LOAD"]);
        }
        using var verifiedProgram = program;

        var diagnostics = new HashSet<string>(StringComparer.Ordinal);
        var traces = new List<VectorTrace>(request.Specification.Vectors.Count);
        foreach (var vector in request.Specification.Vectors)
        {
            var vectorTrace = ExecuteVector(
                verifiedProgram,
                lowering.Program,
                vector,
                diagnostics);
            traces.Add(vectorTrace);
        }
        var trace = new ExecutionTrace
        {
            SchemaVersion = TraceSchemaVersion,
            SourceSha256 = sourceSha256,
            TestSpecificationSha256 = specificationSha256,
            Vectors = traces
        };
        var traceSha256 = Sha256Hex(JsonSerializer.SerializeToUtf8Bytes(trace, CompactJson));
        return new ExpertDatasetExecutableResult
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            SourceSha256 = sourceSha256,
            CompilerClosureSha256 = compilerClosureSha256,
            TestSpecificationSha256 = specificationSha256,
            CanonicalProgramSha256 = canonicalProgramSha256,
            ExecutionTraceSha256 = traceSha256,
            CompileSucceeded = true,
            TestsPassed = diagnostics.Count == 0,
            VectorCount = request.Specification.Vectors.Count,
            CallbackCount = request.Specification.Vectors.Sum(vector => vector.Callbacks.Count),
            DiagnosticCodes = diagnostics.Order(StringComparer.Ordinal).ToArray()
        };
    }

    private static VectorTrace ExecuteVector(
        DaxqProgram program,
        DaxqCanonicalProgram canonicalProgram,
        ExpertDatasetNumericTestVector vector,
        ISet<string> diagnostics)
    {
        var parameterCount = vector.Parameters.Count;
        if (canonicalProgram.ReferencedParameterIds.Any(id => id < 0 || id >= parameterCount))
        {
            diagnostics.Add("DAXQ-VERIFY-PARAMETER-COVERAGE");
        }

        var hasInitialize = program.HasEntrypoint(DaxqEntrypoint.Initialize);
        var hasOnBar = program.HasEntrypoint(DaxqEntrypoint.OnBar);
        var hasOnTick = program.HasEntrypoint(DaxqEntrypoint.OnTick);
        if (hasInitialize != (vector.Initialization is not null) ||
            hasOnBar != vector.Callbacks.Any(callback => callback.Entrypoint == "bar") ||
            hasOnTick != vector.Callbacks.Any(callback => callback.Entrypoint == "tick"))
        {
            diagnostics.Add("DAXQ-VERIFY-ENTRYPOINT-COVERAGE");
        }
        if (vector.Callbacks.Any(callback =>
                callback.Entrypoint == "bar" && !hasOnBar ||
                callback.Entrypoint == "tick" && !hasOnTick))
        {
            diagnostics.Add("DAXQ-VERIFY-UNDECLARED-ENTRYPOINT");
        }

        var bars = vector.Bars
            .Select(bar => new DaxqBar(bar.Open, bar.High, bar.Low, bar.Close, bar.Volume))
            .ToArray();
        var parameters = vector.Parameters.ToArray();
        var host = new DaxqSdkAbi3FrameHost(bars, parameters);
        using var vm = new DaxqReferenceVm(
            program,
            host,
            vector.LaunchSeed);
        InvocationTrace? initialization = null;
        if (hasInitialize)
        {
            var result = vm.Initialize();
            initialization = Capture("initialize", 0, -1, result, vm);
            CompareEffects(
                vector.Initialization,
                result,
                vm,
                vector.MaximumAbsoluteDifference,
                diagnostics);
        }

        var callbacks = new List<InvocationTrace>(vector.Callbacks.Count);
        foreach (var callback in vector.Callbacks)
        {
            host.CurrentCompletedBarIndex = callback.CompletedBarIndex;
            var result = callback.Entrypoint == "bar"
                ? vm.OnBar(callback.TimeIndex)
                : vm.OnTick(
                    callback.TimeIndex,
                    callback.Bid,
                    callback.Ask,
                    callback.Last,
                    callback.Volume);
            callbacks.Add(Capture(
                callback.Entrypoint,
                callback.TimeIndex,
                callback.CompletedBarIndex,
                result,
                vm));
            CompareEffects(
                callback.Expected,
                result,
                vm,
                vector.MaximumAbsoluteDifference,
                diagnostics);
        }
        return new VectorTrace
        {
            Id = vector.Id,
            Initialization = initialization,
            Callbacks = callbacks
        };
    }

    private static void CompareEffects(
        ExpertDatasetExpectedEffects? expected,
        DaxqInvocationResult invocation,
        DaxqReferenceVm vm,
        double tolerance,
        ISet<string> diagnostics)
    {
        if (!invocation.Succeeded)
        {
            diagnostics.Add($"DAXQ-VERIFY-FAULT-{invocation.Fault}");
            return;
        }
        if (expected is null)
        {
            diagnostics.Add("DAXQ-VERIFY-MISSING-EXPECTATION");
            return;
        }
        var actualSignals = vm.EmittedSignals;
        if (actualSignals.Length != expected.Signals.Count)
        {
            diagnostics.Add("DAXQ-VERIFY-SIGNAL-COUNT");
        }
        else
        {
            for (var index = 0; index < actualSignals.Length; index++)
            {
                var actual = actualSignals[index];
                var wanted = expected.Signals[index];
                if (actual.Kind != wanted.Kind || actual.NoteId != wanted.NoteId ||
                    Math.Abs(actual.Strength - wanted.Strength) > tolerance)
                {
                    diagnostics.Add("DAXQ-VERIFY-SIGNAL-MISMATCH");
                }
            }
        }
        var actualLogs = vm.Logs;
        if (actualLogs.Length != expected.Logs.Count)
        {
            diagnostics.Add("DAXQ-VERIFY-LOG-COUNT");
        }
        else
        {
            for (var index = 0; index < actualLogs.Length; index++)
            {
                var actual = actualLogs[index];
                var wanted = expected.Logs[index];
                if (actual.MessageId != wanted.MessageId ||
                    Math.Abs(actual.Value - wanted.Value) > tolerance)
                {
                    diagnostics.Add("DAXQ-VERIFY-LOG-MISMATCH");
                }
            }
        }
    }

    private static InvocationTrace Capture(
        string entrypoint,
        long timeIndex,
        int completedBarIndex,
        DaxqInvocationResult result,
        DaxqReferenceVm vm) =>
        new()
        {
            Entrypoint = entrypoint,
            TimeIndex = timeIndex,
            CompletedBarIndex = completedBarIndex,
            Fault = result.Fault.ToString(),
            ExecutedInstructions = result.Fault == DaxqFault.Timeout ? 0 : result.ExecutedInstructions,
            MaximumStackDepth = result.Fault == DaxqFault.Timeout ? 0 : result.MaxStackDepth,
            Signals = vm.EmittedSignals.ToArray(),
            Logs = vm.Logs.ToArray()
        };

    private static ExpertDatasetExecutableResult FailedCompilation(
        string sourceSha256,
        string specificationSha256,
        string compilerClosureSha256,
        ExpertDatasetExecutableVerificationSpec specification,
        IEnumerable<string> diagnosticCodes) =>
        new()
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            SourceSha256 = sourceSha256,
            CompilerClosureSha256 = compilerClosureSha256,
            TestSpecificationSha256 = specificationSha256,
            CanonicalProgramSha256 = null,
            ExecutionTraceSha256 = null,
            CompileSucceeded = false,
            TestsPassed = false,
            VectorCount = specification.Vectors.Count,
            CallbackCount = specification.Vectors.Sum(vector => vector.Callbacks.Count),
            DiagnosticCodes = diagnosticCodes
                .Where(code => !string.IsNullOrWhiteSpace(code))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .Take(ExpertModelDatasetReviewTools.MaxExecutableDiagnostics)
                .ToArray()
        };

    private static ExpertDatasetExecutableResult FailedTests(
        string sourceSha256,
        string specificationSha256,
        string compilerClosureSha256,
        string canonicalProgramSha256,
        ExpertDatasetExecutableVerificationSpec specification,
        string? traceSha256,
        IEnumerable<string> diagnosticCodes) =>
        new()
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            SourceSha256 = sourceSha256,
            CompilerClosureSha256 = compilerClosureSha256,
            TestSpecificationSha256 = specificationSha256,
            CanonicalProgramSha256 = canonicalProgramSha256,
            ExecutionTraceSha256 = traceSha256,
            CompileSucceeded = true,
            TestsPassed = false,
            VectorCount = specification.Vectors.Count,
            CallbackCount = specification.Vectors.Sum(vector => vector.Callbacks.Count),
            DiagnosticCodes = diagnosticCodes
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .Take(ExpertModelDatasetReviewTools.MaxExecutableDiagnostics)
                .ToArray()
        };

    private static void ValidateWorkerRequest(WorkerRequest request)
    {
        if (request.SchemaVersion != WorkerRequestSchemaVersion ||
            string.IsNullOrWhiteSpace(request.Source) ||
            request.Source.Length > ExpertModelDatasetReviewTools.MaxExecutableSourceCharacters ||
            request.Source.IndexOf('\0') >= 0 ||
            request.Specification is null ||
            request.Specification.Profile != ExpertModelDatasetReviewTools.DaxqExecutableProfile ||
            request.Specification.Vectors is null ||
            request.Specification.Vectors.Count is < 1 or >
                ExpertModelDatasetReviewTools.MaxExecutableVectorsPerExample)
        {
            throw new CoordinatorValidationException("DAXQ verifier request is invalid or exceeds its bounds.");
        }
        var totalCallbacks = request.Specification.Vectors.Sum(vector =>
            vector?.Callbacks?.Count ?? ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerExample + 1);
        if (totalCallbacks > ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerExample)
        {
            throw new CoordinatorValidationException(
                "DAXQ verifier request exceeds its total callback bound.");
        }
    }

    private static string ComputeCompilerClosureSha256()
    {
        var paths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var tpa = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string ?? string.Empty;
        foreach (var path in tpa.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            if (name.Length > 0)
            {
                paths.TryAdd(name, path);
            }
        }
        var compilerAssembly = typeof(DaxqRoslynCompiler).Assembly;
        var closureAssemblies = new List<Assembly>
        {
            compilerAssembly,
            typeof(DaxqReferenceVm).Assembly,
            typeof(DaxqEntrypoint).Assembly,
            typeof(ExpertModelDatasetReviewTools).Assembly,
            typeof(CliApplication).Assembly
        };
        closureAssemblies.AddRange(
            compilerAssembly.GetReferencedAssemblies().Select(Assembly.Load));
        foreach (var assembly in closureAssemblies)
        {
            if (!string.IsNullOrEmpty(assembly.Location))
            {
                paths[assembly.GetName().Name!] = assembly.Location;
            }
        }
        var closure = new
        {
            runtime = Environment.Version.ToString(),
            framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            assemblies = paths
                .OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .Select(item => new
                {
                    name = item.Key,
                    sha256 = Sha256File(item.Value)
                })
                .ToArray()
        };
        return Sha256Hex(JsonSerializer.SerializeToUtf8Bytes(closure, CompactJson));
    }

    private static async Task RunWorkerProcessAsync(
        string requestPath,
        string responsePath,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = ResolveDotnetHostPath(),
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add(typeof(CliApplication).Assembly.Location);
        startInfo.ArgumentList.Add("__daxq-worker");
        startInfo.ArgumentList.Add("--request");
        startInfo.ArgumentList.Add(requestPath);
        startInfo.ArgumentList.Add("--output");
        startInfo.ArgumentList.Add(responsePath);
        startInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        startInfo.Environment["DOTNET_NOLOGO"] = "1";
        startInfo.Environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1";

        using var workerJob = WindowsWorkerJob.Create(MaxWorkerProcessMemoryBytes);
        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                throw new CoordinatorValidationException("DAXQ verifier worker did not start.");
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            throw new CoordinatorValidationException(
                $"DAXQ verifier worker could not start: {exception.Message}");
        }
        var stdoutTask = ReadBoundedTextAsync(
            process.StandardOutput,
            MaxCapturedOutputCharacters,
            "standard output",
            cancellationToken);
        var stderrTask = ReadBoundedTextAsync(
            process.StandardError,
            MaxCapturedOutputCharacters,
            "standard error",
            cancellationToken);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            workerJob.Assign(process);
            cancellationToken.ThrowIfCancellationRequested();
            await process.StandardInput.WriteLineAsync(WorkerStartSignal).ConfigureAwait(false);
            await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
            process.StandardInput.Close();
            while (!process.HasExited)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (stdoutTask.IsFaulted || stdoutTask.IsCanceled)
                {
                    _ = await stdoutTask.ConfigureAwait(false);
                }
                if (stderrTask.IsFaulted || stderrTask.IsCanceled)
                {
                    _ = await stderrTask.ConfigureAwait(false);
                }
                if (stopwatch.Elapsed > WorkerTimeout)
                {
                    KillWorker(process);
                    throw new CoordinatorValidationException("DAXQ verifier worker exceeded its wall-clock limit.");
                }
                try
                {
                    process.Refresh();
                }
                catch (InvalidOperationException) when (process.HasExited)
                {
                    break;
                }
                if (process.WorkingSet64 > MaxWorkerProcessMemoryBytes)
                {
                    KillWorker(process);
                    throw new CoordinatorValidationException("DAXQ verifier worker exceeded its working-set limit.");
                }
                await Task.Delay(25, cancellationToken).ConfigureAwait(false);
            }
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            if (process.ExitCode != 0 || !File.Exists(responsePath))
            {
                var detail = stderr.Length == 0
                    ? "no bounded diagnostic"
                    : stderr[..Math.Min(stderr.Length, 500)].ReplaceLineEndings(" ");
                throw new CoordinatorValidationException(
                    $"DAXQ verifier worker failed with exit code {process.ExitCode}: {detail}");
            }
        }
        catch
        {
            KillWorker(process);
            throw;
        }
    }

    internal static async Task<string> ReadBoundedTextAsync(
        TextReader reader,
        int maxCharacters,
        string description,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxCharacters);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        var buffer = new char[Math.Min(4_096, maxCharacters)];
        var captured = new StringBuilder(Math.Min(maxCharacters, 4_096));
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return captured.ToString();
            }
            if (captured.Length > maxCharacters - read)
            {
                throw new CoordinatorValidationException(
                    $"DAXQ verifier worker {description} exceeded its character bound.");
            }
            captured.Append(buffer, 0, read);
        }
    }

    private static void KillWorker(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Preserve the primary verifier failure.
        }
    }

    private static string ResolveDotnetHostPath()
    {
        if (Environment.ProcessPath is { } processPath &&
            Path.GetFileNameWithoutExtension(processPath)
                .Equals("dotnet", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(processPath))
        {
            return processPath;
        }
        var programFilesHost = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "dotnet",
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dotnet.exe" : "dotnet");
        if (File.Exists(programFilesHost))
        {
            return programFilesHost;
        }
        throw new CoordinatorValidationException(
            "DAXQ verifier requires an absolute trusted .NET host path.");
    }

    private static async Task<T> ReadJsonAsync<T>(
        string path,
        int maxBytes,
        string description,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maxBytes)
        {
            throw new CoordinatorValidationException($"{description} exceeds its byte limit.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new CoordinatorValidationException($"{description} must be BOM-less UTF-8 JSON.");
        }
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new CoordinatorValidationException($"{description} must not be JSON null.");
        }
        catch (JsonException exception)
        {
            throw new CoordinatorValidationException($"{description} is invalid: {exception.Message}");
        }
    }

    private static async Task WriteJsonNewAsync<T>(
        string path,
        T value,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, CompactJson);
        if (bytes.Length + 1 > maxBytes)
        {
            throw new CoordinatorValidationException("DAXQ verifier JSON output exceeds its byte limit.");
        }
        await using var stream = new FileStream(
            Path.GetFullPath(path),
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void TryDeleteWorkspace(string workspace)
    {
        try
        {
            var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "daxalgo-expert-verifier"))
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var target = Path.GetFullPath(workspace);
            if (target.StartsWith(root, StringComparison.OrdinalIgnoreCase) && Directory.Exists(target))
            {
                Directory.Delete(target, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Best-effort cleanup after a unique private verifier run.
        }
    }

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record WorkerRequest
    {
        public required string SchemaVersion { get; init; }
        public required string Source { get; init; }
        public required ExpertDatasetExecutableVerificationSpec Specification { get; init; }
    }

    private sealed record ExecutionTrace
    {
        public required string SchemaVersion { get; init; }
        public required string SourceSha256 { get; init; }
        public required string TestSpecificationSha256 { get; init; }
        public IReadOnlyList<VectorTrace> Vectors { get; init; } = [];
    }

    private sealed record VectorTrace
    {
        public required string Id { get; init; }
        public InvocationTrace? Initialization { get; init; }
        public IReadOnlyList<InvocationTrace> Callbacks { get; init; } = [];
    }

    private sealed record InvocationTrace
    {
        public required string Entrypoint { get; init; }
        public long TimeIndex { get; init; }
        public int CompletedBarIndex { get; init; }
        public required string Fault { get; init; }
        public uint ExecutedInstructions { get; init; }
        public uint MaximumStackDepth { get; init; }
        public IReadOnlyList<DaxqSignal> Signals { get; init; } = [];
        public IReadOnlyList<DaxqLogRecord> Logs { get; init; } = [];
    }

    internal sealed class WindowsWorkerJob : SafeHandleZeroOrMinusOneIsInvalid
    {
        private const uint JobObjectLimitProcessMemory = 0x00000100;
        private const uint JobObjectLimitKillOnJobClose = 0x00002000;

        private WindowsWorkerJob()
            : base(ownsHandle: true)
        {
        }

        public static WindowsWorkerJob Create(long processMemoryLimitBytes)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(processMemoryLimitBytes);
            if (!OperatingSystem.IsWindows())
            {
                throw new CoordinatorValidationException(
                    "DAXQ verifier worker isolation requires Windows Job Objects.");
            }

            var job = CreateJobObjectW(IntPtr.Zero, null);
            if (job.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                job.Dispose();
                throw new CoordinatorValidationException(
                    $"DAXQ verifier worker Job Object could not be created (Win32 {error}).");
            }

            var information = new JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    LimitFlags = JobObjectLimitProcessMemory | JobObjectLimitKillOnJobClose
                },
                ProcessMemoryLimit = (nuint)processMemoryLimitBytes
            };
            if (!SetInformationJobObject(
                    job,
                    JobObjectInformationClass.ExtendedLimitInformation,
                    ref information,
                    (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
            {
                var error = Marshal.GetLastWin32Error();
                job.Dispose();
                throw new CoordinatorValidationException(
                    $"DAXQ verifier worker memory limit could not be configured (Win32 {error}).");
            }
            return job;
        }

        public void Assign(Process process)
        {
            ArgumentNullException.ThrowIfNull(process);
            if (!AssignProcessToJobObject(this, process.Handle))
            {
                var error = Marshal.GetLastWin32Error();
                throw new CoordinatorValidationException(
                    $"DAXQ verifier worker could not enter its constrained Job Object (Win32 {error}).");
            }
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern WindowsWorkerJob CreateJobObjectW(IntPtr jobAttributes, string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            WindowsWorkerJob job,
            JobObjectInformationClass informationClass,
            ref JobObjectExtendedLimitInformation information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(WindowsWorkerJob job, IntPtr process);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private enum JobObjectInformationClass
        {
            ExtendedLimitInformation = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public nuint MinimumWorkingSetSize;
            public nuint MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public nuint Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public nuint ProcessMemoryLimit;
            public nuint JobMemoryLimit;
            public nuint PeakProcessMemoryUsed;
            public nuint PeakJobMemoryUsed;
        }

    }
}
