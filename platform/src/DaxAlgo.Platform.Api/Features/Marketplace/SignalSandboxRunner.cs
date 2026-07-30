using System.Diagnostics;
using System.Formats.Tar;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class DisabledSignalSandboxRunner : ISignalSandboxRunner
{
    public bool IsAvailable => false;

    public async IAsyncEnumerable<SignalSandboxSignal> RunAsync(
        SignalSandboxRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        await Task.CompletedTask;
        yield break;
    }
}

public sealed class DockerSignalSandboxRunner : ISignalSandboxRunner, IDisposable
{
    private const string ContainerWork = "/work";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SignalExecutionOptions options;
    private readonly SemaphoreSlim concurrencyGate;
    private readonly Lazy<bool> availability;

    public DockerSignalSandboxRunner(SignalExecutionOptions options)
        : this(options, ProbeDocker)
    {
    }

    internal DockerSignalSandboxRunner(
        SignalExecutionOptions options,
        Func<bool> availabilityProbe)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentNullException.ThrowIfNull(availabilityProbe);
        ValidateOptions(options);
        concurrencyGate = new SemaphoreSlim(
            options.MaximumConcurrentSessions,
            options.MaximumConcurrentSessions);
        availability = new Lazy<bool>(
            availabilityProbe,
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public bool IsAvailable => availability.Value;

    public async IAsyncEnumerable<SignalSandboxSignal> RunAsync(
        SignalSandboxRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await concurrencyGate.WaitAsync(cancellationToken);
        try
        {
            await foreach (var signal in RunIsolatedAsync(request, cancellationToken))
            {
                yield return signal;
            }
        }
        finally
        {
            concurrencyGate.Release();
        }
    }

    private async IAsyncEnumerable<SignalSandboxSignal> RunIsolatedAsync(
        SignalSandboxRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (request.DaxqPackage.IsEmpty
            || request.ContentKey.Length != 32
            || request.MarketDataFrames.IsEmpty
            || request.ReleaseVerificationKeySpki.IsEmpty
            || string.IsNullOrWhiteSpace(request.ReleaseSigningKeyId))
        {
            throw new InvalidOperationException("The signal worker inputs are incomplete.");
        }

        var workingDirectory = Path.GetTempPath();
        var containerName = $"daxalgo-signal-{Guid.NewGuid():N}";
        var containerCreated = false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.WallClockSeconds));

        try
        {
            var create = await RunControlProcessAsync(
                BuildCreateArguments(containerName),
                workingDirectory,
                timeout.Token);
            if (!create)
            {
                throw new InvalidOperationException(
                    "The deny-by-default signal worker container could not be created.");
            }

            containerCreated = true;
            if (!await RunControlProcessAsync(
                    ["start", containerName],
                    workingDirectory,
                    timeout.Token)
                || !await CopyInputsToTmpfsAsync(
                    containerName,
                    request,
                    workingDirectory,
                    timeout.Token))
            {
                throw new InvalidOperationException(
                    "The signal worker could not receive its isolated input set.");
            }

            using var process = StartProcess(
                [
                    "exec", containerName, options.Entrypoint, "run",
                    "--package", $"{ContainerWork}/input/release.daxq",
                    "--content-key", $"{ContainerWork}/input/content-key.bin",
                    "--frames", $"{ContainerWork}/input/frames.json",
                    "--release-key", $"{ContainerWork}/input/release-key.spki",
                    "--release-key-id", request.ReleaseSigningKeyId,
                ],
                workingDirectory);
            var stderr = DrainBoundedAsync(process.StandardError, 256 * 1024, timeout.Token);
            var outputBytes = 0;
            try
            {
                while (await process.StandardOutput.ReadLineAsync(timeout.Token) is { } line)
                {
                    outputBytes = checked(outputBytes + line.Length + 1);
                    if (outputBytes > options.MaximumOutputBytes)
                    {
                        throw new InvalidOperationException(
                            "The signal worker exceeded its bounded output budget.");
                    }

                    WorkerSignal? item;
                    try
                    {
                        item = JsonSerializer.Deserialize<WorkerSignal>(line, JsonOptions);
                    }
                    catch (JsonException exception)
                    {
                        throw new InvalidOperationException(
                            "The signal worker emitted an invalid frame.",
                            exception);
                    }

                    if (item is null
                        || item.Kind is not ("long" or "short" or "flat")
                        || !double.IsFinite(item.Strength)
                        || item.Strength is < 0 or > 1)
                    {
                        throw new InvalidOperationException(
                            "The signal worker emitted a frame outside the wire contract.");
                    }

                    yield return new SignalSandboxSignal(item.Kind, item.Strength, item.NoteId);
                }

                await process.WaitForExitAsync(timeout.Token);
                await stderr;
                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException(
                        "The deny-by-default signal worker failed safely.");
                }
            }
            finally
            {
                if (!process.HasExited)
                {
                    KillTree(process);
                }
            }
        }
        finally
        {
            if (containerCreated)
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                _ = await RunControlProcessAsync(
                    ["rm", "--force", containerName],
                    workingDirectory,
                    cleanup.Token);
            }
        }
    }

    internal IReadOnlyList<string> BuildCreateArguments(string containerName)
    {
        var invariant = CultureInfo.InvariantCulture;
        return
        [
            "create",
            "--name", containerName,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            $"--memory={options.MemoryMb.ToString(invariant)}m",
            $"--memory-swap={options.MemoryMb.ToString(invariant)}m",
            $"--cpus={options.Cpus.ToString(invariant)}",
            $"--pids-limit={options.PidsLimit.ToString(invariant)}",
            "--tmpfs", $"{ContainerWork}:rw,noexec,nosuid,size={options.DiskMb.ToString(invariant)}m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--workdir", ContainerWork,
            options.Image,
            options.Entrypoint,
            "idle",
            "--work", ContainerWork,
        ];
    }

    private static Process StartProcess(
        IReadOnlyList<string> arguments,
        string workingDirectory,
        bool redirectStandardInput = false)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "docker",
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = redirectStandardInput,
                CreateNoWindow = true,
            },
        };
        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        try
        {
            if (!process.Start())
            {
                process.Dispose();
                throw new InvalidOperationException("The Docker CLI could not be started.");
            }
        }
        catch (System.ComponentModel.Win32Exception exception)
        {
            process.Dispose();
            throw new InvalidOperationException("The Docker CLI is unavailable.", exception);
        }

        return process;
    }

    private static async Task<bool> CopyInputsToTmpfsAsync(
        string containerName,
        SignalSandboxRequest request,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        using var process = StartProcess(
            BuildCopyArguments(containerName),
            workingDirectory,
            redirectStandardInput: true);
        var stdout = DrainBoundedAsync(process.StandardOutput, 256 * 1024, cancellationToken);
        var stderr = DrainBoundedAsync(process.StandardError, 256 * 1024, cancellationToken);
        try
        {
            await WriteInputsArchiveAsync(
                process.StandardInput.BaseStream,
                request,
                leaveOpen: false,
                cancellationToken);

            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdout, stderr);
            return process.ExitCode == 0;
        }
        catch (OperationCanceledException)
        {
            KillTree(process);
            throw;
        }
    }

    internal static IReadOnlyList<string> BuildCopyArguments(string containerName) =>
        ["cp", "--archive", "-", $"{containerName}:{ContainerWork}"];

    internal static async Task WriteInputsArchiveAsync(
        Stream destination,
        SignalSandboxRequest request,
        bool leaveOpen,
        CancellationToken cancellationToken)
    {
        var package = request.DaxqPackage.ToArray();
        var contentKey = request.ContentKey.ToArray();
        var frames = request.MarketDataFrames.ToArray();
        var releaseKey = request.ReleaseVerificationKeySpki.ToArray();
        try
        {
            await using (var writer = new TarWriter(
                destination,
                TarEntryFormat.Pax,
                leaveOpen))
            {
                var directory = new PaxTarEntry(TarEntryType.Directory, "input/")
                {
                    Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                    Uid = 65534,
                    Gid = 65534,
                };
                await writer.WriteEntryAsync(directory, cancellationToken);
                await WriteInputEntryAsync(writer, "input/release.daxq", package, cancellationToken);
                await WriteInputEntryAsync(writer, "input/content-key.bin", contentKey, cancellationToken);
                await WriteInputEntryAsync(writer, "input/frames.json", frames, cancellationToken);
                await WriteInputEntryAsync(writer, "input/release-key.spki", releaseKey, cancellationToken);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentKey);
        }
    }

    private static async Task WriteInputEntryAsync(
        TarWriter writer,
        string name,
        byte[] content,
        CancellationToken cancellationToken)
    {
        using var data = new MemoryStream(content, writable: false);
        var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
        {
            DataStream = data,
            Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            Uid = 65534,
            Gid = 65534,
        };
        await writer.WriteEntryAsync(entry, cancellationToken);
    }

    private static async Task<bool> RunControlProcessAsync(
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        Process process;
        try
        {
            process = StartProcess(arguments, workingDirectory);
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        using (process)
        {
            var stdout = DrainBoundedAsync(process.StandardOutput, 256 * 1024, cancellationToken);
            var stderr = DrainBoundedAsync(process.StandardError, 256 * 1024, cancellationToken);
            try
            {
                await process.WaitForExitAsync(cancellationToken);
                await Task.WhenAll(stdout, stderr);
                return process.ExitCode == 0;
            }
            catch (OperationCanceledException)
            {
                KillTree(process);
                throw;
            }
        }
    }

    private static bool ProbeDocker()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            return RunControlProcessAsync(
                    ["version", "--format", "{{.Server.Version}}"],
                    Path.GetTempPath(),
                    timeout.Token)
                .GetAwaiter()
                .GetResult();
        }
        catch (Exception exception) when (exception is
            OperationCanceledException or
            InvalidOperationException or
            IOException)
        {
            return false;
        }
    }

    private static async Task DrainBoundedAsync(
        StreamReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var total = 0;
        while (true)
        {
            var read = await reader.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return;
            }

            total = checked(total + read);
            if (total > maximumCharacters)
            {
                throw new InvalidOperationException("A worker process exceeded its diagnostic output limit.");
            }
        }
    }

    private static void KillTree(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
    }

    internal static void ValidateOptions(SignalExecutionOptions options)
    {
        if (!string.Equals(options.Provider, "Docker", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(options.Image)
            || !options.Image.Contains("@sha256:", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(options.Entrypoint)
            || options.WallClockSeconds is < 10 or > 1800
            || options.MemoryMb is < 128 or > 8192
            || options.Cpus is < 0.25m or > 8m
            || options.PidsLimit is < 16 or > 1024
            || options.DiskMb is < 64 or > 4096
            || options.MaximumOutputBytes is < 1024 or > 16 * 1024 * 1024
            || options.MaximumConcurrentSessions is < 1 or > 128)
        {
            throw new InvalidOperationException(
                "The Docker signal worker requires a digest-pinned image and bounded time, CPU, memory, pids, disk, output, and concurrency settings.");
        }
    }

    public void Dispose()
    {
        concurrencyGate.Dispose();
        GC.SuppressFinalize(this);
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record WorkerSignal(
        [property: JsonPropertyName("kind")] string Kind,
        [property: JsonPropertyName("strength")] double Strength,
        [property: JsonPropertyName("note_id")] long NoteId);
}
