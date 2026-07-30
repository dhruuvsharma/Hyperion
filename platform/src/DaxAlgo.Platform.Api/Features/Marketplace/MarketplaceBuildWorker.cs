using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class MarketplaceBuildWorkerOptions
{
    public const string SectionName = "MarketplaceBuildWorker";

    public string Provider { get; init; } = "Disabled";

    public string Image { get; init; } = string.Empty;

    public string Entrypoint { get; init; } = "/opt/daxalgo/bin/marketplace-build-worker";

    public string PolicyVersion { get; init; } = "marketplace-daxq-v1";

    public int WallClockSeconds { get; init; } = 300;

    public int MemoryMb { get; init; } = 1024;

    public decimal Cpus { get; init; } = 1m;

    public int PidsLimit { get; init; } = 128;

    public int DiskMb { get; init; } = 512;

    public int MaximumOutputBytes { get; init; } = 32 * 1024 * 1024;

    public int MaximumConcurrentBuilds { get; init; } = 2;
}

public enum MarketplaceBuildDecision
{
    Pass,
    Block,
    RetryableFailure,
}

public sealed record MarketplaceBuildRequest(
    Guid SubmissionId,
    string StrategyId,
    string Version,
    byte[] Source,
    byte[] ReferenceDataset,
    byte[] DiversificationSeed,
    IReadOnlyList<string> DeclaredCapabilities,
    string LicenseExpression);

public sealed record MarketplaceScanEvidence(
    bool CapabilityAnalyzerPassed,
    bool MalwareScanPassed,
    bool SecretScanPassed,
    bool LicenseScanPassed,
    bool SbomGenerated,
    string CapabilityAnalyzerVersion,
    string MalwareScannerVersion,
    string SecretScannerVersion,
    string LicenseScannerVersion,
    string SbomToolVersion,
    IReadOnlyList<string> ImplementedCapabilities)
{
    public bool AllPassed => CapabilityAnalyzerPassed
        && MalwareScanPassed
        && SecretScanPassed
        && LicenseScanPassed
        && SbomGenerated;
}

public sealed record MarketplaceBuildResult(
    MarketplaceBuildDecision Decision,
    string PolicyVersion,
    IReadOnlyList<string> Diagnostics,
    MarketplaceScanEvidence? ScanEvidence,
    byte[]? Artifact,
    string? ArtifactSha256,
    string? CipherSha256,
    string? ContentKeyId,
    byte[]? ContentKey,
    int? VmAbiVersion,
    string? ExecutionClass,
    string? DiversificationSeedSha256,
    byte[]? CanonicalParityStatistics,
    string? ParityStatisticsSha256,
    byte[]? CanonicalListingMetrics,
    string? ListingMetricsSha256,
    byte[]? Sbom,
    string? SbomSha256)
{
    public static MarketplaceBuildResult Blocked(string policyVersion, params string[] diagnostics) =>
        new(
            MarketplaceBuildDecision.Block,
            policyVersion,
            diagnostics,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null);

    public static MarketplaceBuildResult Retryable(string policyVersion, string diagnostic) =>
        Blocked(policyVersion, diagnostic) with { Decision = MarketplaceBuildDecision.RetryableFailure };
}

public interface IMarketplaceBuildWorker
{
    Task<MarketplaceBuildResult> RunAsync(
        MarketplaceBuildRequest request,
        CancellationToken cancellationToken);
}

public sealed class DisabledMarketplaceBuildWorker(MarketplaceBuildWorkerOptions options)
    : IMarketplaceBuildWorker
{
    public Task<MarketplaceBuildResult> RunAsync(
        MarketplaceBuildRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(MarketplaceBuildResult.Retryable(
            options.PolicyVersion,
            "A compliant disposable marketplace build worker is not configured."));
    }
}

public sealed class DockerMarketplaceBuildWorker : IMarketplaceBuildWorker, IDisposable
{
    private const string ContainerWork = "/work";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly MarketplaceBuildWorkerOptions options;
    private readonly SemaphoreSlim concurrencyGate;

    public DockerMarketplaceBuildWorker(MarketplaceBuildWorkerOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        ValidateOptions(options);
        concurrencyGate = new SemaphoreSlim(options.MaximumConcurrentBuilds, options.MaximumConcurrentBuilds);
    }

    public async Task<MarketplaceBuildResult> RunAsync(
        MarketplaceBuildRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await concurrencyGate.WaitAsync(cancellationToken);
        try
        {
            return await RunIsolatedAsync(request, cancellationToken);
        }
        finally
        {
            concurrencyGate.Release();
        }
    }

    private async Task<MarketplaceBuildResult> RunIsolatedAsync(
        MarketplaceBuildRequest request,
        CancellationToken cancellationToken)
    {
        if (request.DiversificationSeed.Length != 32)
        {
            return MarketplaceBuildResult.Blocked(
                options.PolicyVersion,
                "The release diversification seed must contain exactly 32 bytes.");
        }

        var stagingRoot = Path.Combine(
            Path.GetTempPath(),
            "daxalgo-marketplace-build",
            Guid.NewGuid().ToString("N"));
        var inputDirectory = Path.Combine(stagingRoot, "input");
        var outputDirectory = Path.Combine(stagingRoot, "output");
        var containerName = $"daxalgo-marketplace-{Guid.NewGuid():N}";
        var containerCreated = false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.WallClockSeconds));

        try
        {
            Directory.CreateDirectory(inputDirectory);
            Directory.CreateDirectory(outputDirectory);
            await File.WriteAllBytesAsync(
                Path.Combine(inputDirectory, "strategy.cs"),
                request.Source,
                timeout.Token);
            await File.WriteAllBytesAsync(
                Path.Combine(inputDirectory, "reference.json"),
                request.ReferenceDataset,
                timeout.Token);
            await File.WriteAllTextAsync(
                Path.Combine(inputDirectory, "request.json"),
                JsonSerializer.Serialize(
                    new WorkerRequestDocument(
                        request.SubmissionId,
                        request.StrategyId,
                        request.Version,
                        Convert.ToHexStringLower(request.DiversificationSeed),
                        request.DeclaredCapabilities,
                        request.LicenseExpression),
                    JsonOptions),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                timeout.Token);

            var create = await RunProcessAsync(
                "docker",
                BuildCreateArguments(containerName),
                stagingRoot,
                timeout.Token);
            if (!create.Succeeded)
            {
                return MarketplaceBuildResult.Retryable(
                    options.PolicyVersion,
                    create.NotFound
                        ? "The Docker CLI is unavailable for the marketplace build worker."
                        : $"The disposable worker could not be created (exit {create.ExitCode}).");
            }

            containerCreated = true;
            var start = await RunProcessAsync(
                "docker",
                ["start", containerName],
                stagingRoot,
                timeout.Token);
            if (!start.Succeeded)
            {
                return MarketplaceBuildResult.Retryable(
                    options.PolicyVersion,
                    "The disposable worker could not enter its isolated idle state.");
            }

            var copyInput = await RunProcessAsync(
                "docker",
                ["cp", string.Concat(inputDirectory, "/."), $"{containerName}:{ContainerWork}/input"],
                stagingRoot,
                timeout.Token);
            if (!copyInput.Succeeded)
            {
                return MarketplaceBuildResult.Retryable(
                    options.PolicyVersion,
                    "The immutable submission could not be copied into the disposable worker.");
            }

            var run = await RunProcessAsync(
                "docker",
                ["exec", containerName, options.Entrypoint, "build", .. BuildWorkerArguments()],
                stagingRoot,
                timeout.Token);
            if (!run.Succeeded)
            {
                return run.ExitCode == 3
                    ? MarketplaceBuildResult.Blocked(
                        options.PolicyVersion,
                        "The compiler parity gate blocked publication.")
                    : MarketplaceBuildResult.Retryable(
                        options.PolicyVersion,
                        "The disposable worker failed or exceeded its wall-clock budget.");
            }

            var copyOutput = await RunProcessAsync(
                "docker",
                ["cp", $"{containerName}:{ContainerWork}/output/.", outputDirectory],
                stagingRoot,
                timeout.Token);
            if (!copyOutput.Succeeded)
            {
                return MarketplaceBuildResult.Retryable(
                    options.PolicyVersion,
                    "The disposable worker produced no declared result set.");
            }

            return await ReadDeclaredResultAsync(outputDirectory, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return MarketplaceBuildResult.Retryable(
                options.PolicyVersion,
                "The disposable marketplace worker exceeded its wall-clock budget.");
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or JsonException
            or CryptographicException
            or InvalidOperationException)
        {
            return MarketplaceBuildResult.Retryable(
                options.PolicyVersion,
                $"The disposable marketplace worker failed safely ({exception.GetType().Name}).");
        }
        finally
        {
            if (containerCreated)
            {
                using var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                _ = await RunProcessAsync(
                    "docker",
                    ["rm", "--force", containerName],
                    stagingRoot,
                    cleanupTimeout.Token);
            }

            DeleteStagingDirectory(stagingRoot);
        }
    }

    private IReadOnlyList<string> BuildCreateArguments(string containerName)
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
            "--tmpfs", $"{ContainerWork}:rw,nosuid,size={options.DiskMb.ToString(invariant)}m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--workdir", ContainerWork,
            options.Image,
            options.Entrypoint,
            "idle",
            "--work", ContainerWork,
        ];
    }

    private static string[] BuildWorkerArguments() =>
    [
        "--request", $"{ContainerWork}/input/request.json",
        "--source", $"{ContainerWork}/input/strategy.cs",
        "--dataset", $"{ContainerWork}/input/reference.json",
        "--output", $"{ContainerWork}/output",
    ];

    private async Task<MarketplaceBuildResult> ReadDeclaredResultAsync(
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        var manifestBytes = await ReadBoundedFileAsync(
            Path.Combine(outputDirectory, "result.json"),
            256 * 1024,
            cancellationToken);
        var manifest = JsonSerializer.Deserialize<WorkerResultDocument>(manifestBytes, JsonOptions)
            ?? throw new JsonException("The worker result manifest is empty.");
        if (manifest.Decision is not "pass")
        {
            return new MarketplaceBuildResult(
                manifest.Retryable
                    ? MarketplaceBuildDecision.RetryableFailure
                    : MarketplaceBuildDecision.Block,
                manifest.PolicyVersion ?? options.PolicyVersion,
                manifest.Diagnostics ?? ["The marketplace worker blocked publication."],
                manifest.ScanEvidence,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                manifest.DiversificationSeedSha256,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        var artifact = await ReadBoundedFileAsync(
            Path.Combine(outputDirectory, "artifact.daxq"),
            options.MaximumOutputBytes,
            cancellationToken);
        var contentKey = await ReadBoundedFileAsync(
            Path.Combine(outputDirectory, "content-key.bin"),
            32,
            cancellationToken);
        var parity = await ReadBoundedFileAsync(
            Path.Combine(outputDirectory, "parity-statistics.json"),
            256 * 1024,
            cancellationToken);
        var metrics = await ReadBoundedFileAsync(
            Path.Combine(outputDirectory, "listing-metrics.json"),
            256 * 1024,
            cancellationToken);
        var sbom = await ReadBoundedFileAsync(
            Path.Combine(outputDirectory, "sbom.spdx.json"),
            4 * 1024 * 1024,
            cancellationToken);
        if (contentKey.Length != 32)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw new InvalidOperationException("The declared content key must contain exactly 32 bytes.");
        }

        VerifyHash(artifact, manifest.ArtifactSha256, "artifact");
        VerifyHash(parity, manifest.ParityStatisticsSha256, "parity statistics");
        VerifyHash(metrics, manifest.ListingMetricsSha256, "listing metrics");
        VerifyHash(sbom, manifest.SbomSha256, "SBOM");
        if (manifest.ScanEvidence is null || !manifest.ScanEvidence.AllPassed)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            return MarketplaceBuildResult.Blocked(
                manifest.PolicyVersion ?? options.PolicyVersion,
                "One or more blocking marketplace scans did not pass.");
        }

        return new MarketplaceBuildResult(
            MarketplaceBuildDecision.Pass,
            manifest.PolicyVersion ?? options.PolicyVersion,
            manifest.Diagnostics ?? [],
            manifest.ScanEvidence,
            artifact,
            manifest.ArtifactSha256,
            manifest.CipherSha256,
            manifest.ContentKeyId,
            contentKey,
            manifest.VmAbiVersion,
            manifest.ExecutionClass,
            manifest.DiversificationSeedSha256,
            parity,
            manifest.ParityStatisticsSha256,
            metrics,
            manifest.ListingMetricsSha256,
            sbom,
            manifest.SbomSha256);
    }

    private static async Task<byte[]> ReadBoundedFileAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length <= 0 || file.Length > maximumBytes)
        {
            throw new InvalidOperationException("A declared worker output is missing or outside its size bound.");
        }

        return await File.ReadAllBytesAsync(path, cancellationToken);
    }

    private static void VerifyHash(byte[] bytes, string? expected, string name)
    {
        if (string.IsNullOrWhiteSpace(expected))
        {
            throw new InvalidOperationException($"The worker did not declare a {name} SHA-256 value.");
        }

        byte[] expectedBytes;
        try
        {
            expectedBytes = Convert.FromHexString(expected);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException($"The worker declared an invalid {name} SHA-256 value.", exception);
        }

        var actual = SHA256.HashData(bytes);
        if (expectedBytes.Length != actual.Length
            || !CryptographicOperations.FixedTimeEquals(actual, expectedBytes))
        {
            throw new InvalidOperationException($"The declared {name} hash does not match its bytes.");
        }
    }

    private static async Task<ProcessOutcome> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
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
                return new ProcessOutcome(false, false, null);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new ProcessOutcome(false, exception is System.ComponentModel.Win32Exception, null);
        }

        var standardOutput = DrainBoundedAsync(process.StandardOutput, cancellationToken);
        var standardError = DrainBoundedAsync(process.StandardError, cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(standardOutput, standardError);
            return new ProcessOutcome(process.ExitCode == 0, false, process.ExitCode);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw;
        }
    }

    private static async Task DrainBoundedAsync(
        StreamReader reader,
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
            if (total > 256 * 1024)
            {
                throw new InvalidOperationException("A worker process exceeded its diagnostic output limit.");
            }
        }
    }

    private static void DeleteStagingDirectory(string stagingRoot)
    {
        var expectedRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "daxalgo-marketplace-build"));
        var resolved = Path.GetFullPath(stagingRoot);
        if (!resolved.StartsWith(string.Concat(expectedRoot, Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            Directory.Delete(resolved, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void ValidateOptions(MarketplaceBuildWorkerOptions options)
    {
        if (!string.Equals(options.Provider, "Docker", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(options.Image)
            || !options.Image.Contains("@sha256:", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(options.Entrypoint)
            || options.WallClockSeconds is < 30 or > 1800
            || options.MemoryMb is < 256 or > 8192
            || options.Cpus is < 0.25m or > 8m
            || options.PidsLimit is < 32 or > 1024
            || options.DiskMb is < 128 or > 4096
            || options.MaximumOutputBytes is < 1024 or > 256 * 1024 * 1024
            || options.MaximumConcurrentBuilds is < 1 or > 16)
        {
            throw new InvalidOperationException(
                "The Docker marketplace worker requires a digest-pinned image and bounded time, CPU, memory, pids, disk, output, and concurrency settings.");
        }
    }

    public void Dispose()
    {
        concurrencyGate.Dispose();
        GC.SuppressFinalize(this);
    }

    private sealed record WorkerRequestDocument(
        Guid SubmissionId,
        string StrategyId,
        string Version,
        string DiversificationSeed,
        IReadOnlyList<string> DeclaredCapabilities,
        string LicenseExpression);

    private sealed record WorkerResultDocument(
        string Decision,
        bool Retryable,
        string? PolicyVersion,
        string[]? Diagnostics,
        MarketplaceScanEvidence? ScanEvidence,
        string? ArtifactSha256,
        string? CipherSha256,
        string? ContentKeyId,
        int? VmAbiVersion,
        string? ExecutionClass,
        string? DiversificationSeedSha256,
        string? ParityStatisticsSha256,
        string? ListingMetricsSha256,
        string? SbomSha256);

    private sealed record ProcessOutcome(bool Succeeded, bool NotFound, int? ExitCode);
}
