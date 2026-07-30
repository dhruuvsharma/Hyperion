namespace DaxAlgo.Daxq.Compiler;

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;

internal static class Program
{
    public static int Main(string[] args) => DaxqCompilerCli.Run(args);
}

internal static class DaxqCompilerCli
{
    private const string CompileUsage =
        "Usage: daxq-compiler compile --source <strategy.cs> --output <artifact.daxq> " +
        "--strategy-id <id> --version <semver> --release-seed <64-hex-chars>";
    private const string GateUsage =
        "Usage: daxq-compiler parity-gate --source <strategy.cs> --output <artifact.daxq> " +
        "--strategy-id <id> --version <semver> --release-seed <64-hex-chars> " +
        "--dataset <reference.json> [--tolerance <absolute-strength-difference>]";

    public static int Run(string[] args)
    {
        if (!TryReadVerbAndOptions(args, out var verb, out var options))
        {
            WriteUsage();
            return 2;
        }

        try
        {
            return verb switch
            {
                "compile" => RunCompile(options),
                "parity-gate" => RunParityGate(options),
                _ => UnknownVerb(),
            };
        }
        catch (DaxqCompilationException exception)
        {
            foreach (var diagnostic in exception.Diagnostics)
                Console.Error.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
            return 1;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                            ArgumentException or CryptographicException or JsonException or
                                            InvalidOperationException)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    private static int RunCompile(IReadOnlyDictionary<string, string> options)
    {
        string[] allowed = ["--source", "--output", "--strategy-id", "--version", "--release-seed"];
        if (!HasRequiredOptions(options, allowed, allowed))
        {
            Console.Error.WriteLine(CompileUsage);
            return 2;
        }

        using var releaseKey = CreateDevelopmentSigningKey();
        var artifact = Compile(
            options,
            ["bars"],
            Array.Empty<DaxqParameterManifest>(),
            releaseKey);
        var fullOutput = ValidateOutputPath(options["--output"]);
        WritePackage(fullOutput, artifact.Package.PackageBytes);
        var releaseRecord = WriteReleaseRecord(
            fullOutput,
            artifact.Release,
            statisticsSha256: null,
            listingMetricsSha256: null);
        Console.WriteLine(
            $"Wrote {fullOutput} ({artifact.Package.PackageBytes.Length} bytes); " +
            $"releaseRecord={releaseRecord}.");
        return 0;
    }

    private static int RunParityGate(IReadOnlyDictionary<string, string> options)
    {
        string[] required =
        [
            "--source",
            "--output",
            "--strategy-id",
            "--version",
            "--release-seed",
            "--dataset",
        ];
        string[] allowed = [.. required, "--tolerance"];
        if (!HasRequiredOptions(options, required, allowed))
        {
            Console.Error.WriteLine(GateUsage);
            return 2;
        }

        var reference = ReadReferenceData(options["--dataset"]);
        var referenceData = reference.ReferenceData;
        var tolerance = ParseTolerance(options.GetValueOrDefault("--tolerance"));

        using var releaseKey = CreateDevelopmentSigningKey();
        var artifact = Compile(options, reference.DataRequirements, reference.Parameters, releaseKey);
        var result = new DaxqBacktestParityGate().Evaluate(artifact, referenceData, tolerance);
        if (!result.PublicationAllowed)
        {
            foreach (var diagnostic in result.Diagnostics)
            {
                var disposition = diagnostic.Retryable
                    ? "BLOCK publication (retryable)"
                    : "BLOCK publication";
                Console.Error.WriteLine($"{diagnostic.Code}: {disposition}: {diagnostic.Message}");
            }
            return 3;
        }

        var fullOutput = ValidateOutputPath(options["--output"]);
        WritePackage(fullOutput, artifact.Package.PackageBytes);
        var releaseRecord = WriteReleaseRecord(
            fullOutput,
            artifact.Release,
            result.StatisticsSha256,
            result.ListingMetricsSha256);
        Console.Out.WriteLine(Encoding.UTF8.GetString(DaxqBacktestParityOutputJson.Write(result)));
        Console.Error.WriteLine(
            $"PASS publication gate; wrote {fullOutput}; " +
            $"statisticsSha256={result.StatisticsSha256}; " +
            $"listingMetricsSha256={result.ListingMetricsSha256}; " +
            $"releaseRecord={releaseRecord}.");
        return 0;
    }

    private static DaxqCompilationArtifact Compile(
        IReadOnlyDictionary<string, string> options,
        IReadOnlyList<string> dataRequirements,
        IReadOnlyList<DaxqParameterManifest> parameters,
        ECDsa releaseKey)
    {
        var input = Path.GetFullPath(options["--source"]);
        if (!File.Exists(input))
            throw new ArgumentException($"Source file not found: {input}");

        var strategyId = options["--strategy-id"];
        var version = options["--version"];
        return new DaxqCompiler().Compile(
            File.ReadAllText(input),
            new DaxqCompilerOptions
            {
                SourceFileName = Path.GetFileName(input),
                StrategyId = strategyId,
                Version = version,
                DataRequirements = dataRequirements,
                Parameters = parameters,
                DiversificationSeed = ParseReleaseSeed(options["--release-seed"]),
                ContentKeyId = $"dev:{strategyId}:{version}",
                ContentKey = SHA256.HashData("DAXQ-LOCAL-DEV-CONTENT-KEY"u8),
                Nonce = RandomNumberGenerator.GetBytes(DaxqFormat.NonceSizeBytes),
                ReleaseKeyId = "daxq-local-dev-p256-v1",
                ReleaseSigningKey = releaseKey,
            });
    }

    private static ParsedReferenceDataset ReadReferenceData(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            throw new ArgumentException($"Reference dataset not found: {fullPath}");
        var document = JsonSerializer.Deserialize<ReferenceDatasetDocument>(
            File.ReadAllText(fullPath),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ??
            throw new JsonException("The reference dataset JSON is empty.");

        var bars = document.Bars
            .Select(bar => new DaxqBar(bar.Open, bar.High, bar.Low, bar.Close, bar.Volume))
            .ToArray();
        var callbacks = document.Callbacks.Select((callback, index) => callback.Entrypoint switch
        {
            "bar" => new DaxqBacktestCallback(
                DaxqEntrypoint.OnBar,
                callback.TimeIndex,
                callback.CompletedBarIndex,
                0d,
                0d,
                0d,
                0d),
            "tick" => DaxqBacktestCallback.Tick(
                callback.TimeIndex,
                callback.CompletedBarIndex,
                callback.Bid,
                callback.Ask,
                callback.Last,
                callback.Volume),
            _ => throw new JsonException(
                $"Reference callback {index} must use entrypoint 'bar' or 'tick'."),
        }).ToArray();
        var manifests = document.Parameters.Select(parameter => new DaxqParameterManifest
        {
            Id = parameter.Id,
            Type = parameter.Type,
            Min = parameter.Min?.Clone(),
            Max = parameter.Max?.Clone(),
            Default = parameter.Default.Clone(),
        }).ToArray();
        var values = document.Parameters.Select((parameter, index) => parameter.Type switch
        {
            "float" => parameter.Default.GetDouble(),
            "int" => checked((double)parameter.Default.GetInt64()),
            "bool" => parameter.Default.GetBoolean() ? 1d : 0d,
            _ => throw new JsonException($"Reference parameter {index} has unsupported type '{parameter.Type}'."),
        }).ToArray();
        return new ParsedReferenceDataset(
            new DaxqBacktestReferenceData
            {
                Bars = bars,
                Parameters = values,
                Callbacks = callbacks,
                LaunchSeed = document.LaunchSeed,
            },
            document.DataRequirements,
            manifests);
    }

    private static DaxqParityTolerance ParseTolerance(string? value)
    {
        if (value is null)
            return new DaxqParityTolerance();
        if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) ||
            !double.IsFinite(parsed) || parsed < 0d)
        {
            throw new ArgumentException("The parity tolerance must be a finite nonnegative number.");
        }
        return new DaxqParityTolerance
        {
            MaximumAbsoluteSignalStrengthDifference = parsed,
        };
    }

    private static byte[] ParseReleaseSeed(string value)
    {
        byte[] seed;
        try
        {
            seed = Convert.FromHexString(value);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The release seed must contain exactly 64 hexadecimal characters.", exception);
        }
        if (seed.Length != 32)
            throw new ArgumentException("The release seed must contain exactly 64 hexadecimal characters.");
        return seed;
    }

    private static string ValidateOutputPath(string output)
    {
        var fullOutput = Path.GetFullPath(output);
        if (!string.Equals(Path.GetExtension(fullOutput), DaxqFormat.PackageExtension, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The output path must use the .daxq extension.");
        return fullOutput;
    }

    private static void WritePackage(string fullOutput, byte[] package)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(fullOutput)!);
        File.WriteAllBytes(fullOutput, package);
    }

    private static string WriteReleaseRecord(
        string fullOutput,
        DaxqReleaseMetadata release,
        string? statisticsSha256,
        string? listingMetricsSha256)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("strategyId", release.StrategyId);
            writer.WriteString("version", release.Version);
            writer.WriteString("packageSha256", release.PackageSha256);
            writer.WriteString("diversificationSeed", release.DiversificationSeedHex);
            writer.WriteString("diversificationSeedSha256", release.DiversificationSeedSha256);
            if (statisticsSha256 is not null)
                writer.WriteString("statisticsSha256", statisticsSha256);
            if (listingMetricsSha256 is not null)
                writer.WriteString("listingMetricsSha256", listingMetricsSha256);
            writer.WriteEndObject();
        }

        var recordPath = string.Concat(fullOutput, ".release.json");
        File.WriteAllBytes(recordPath, stream.ToArray());
        return recordPath;
    }

    private static bool TryReadVerbAndOptions(
        string[] args,
        out string verb,
        out IReadOnlyDictionary<string, string> options)
    {
        verb = string.Empty;
        options = new Dictionary<string, string>();
        if (args.Length == 0)
            return false;

        var optionOffset = args[0].StartsWith("--", StringComparison.Ordinal) ? 0 : 1;
        verb = optionOffset == 0 ? "compile" : args[0];
        if ((args.Length - optionOffset) % 2 != 0)
            return false;

        var parsed = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = optionOffset; index < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) ||
                !parsed.TryAdd(args[index], args[index + 1]))
            {
                return false;
            }
        }
        options = parsed;
        return true;
    }

    private static bool HasRequiredOptions(
        IReadOnlyDictionary<string, string> options,
        IReadOnlyCollection<string> required,
        IReadOnlyCollection<string> allowed) =>
        required.All(option => options.TryGetValue(option, out var value) && !string.IsNullOrWhiteSpace(value)) &&
        options.Keys.All(allowed.Contains);

    private static int UnknownVerb()
    {
        WriteUsage();
        return 2;
    }

    private static void WriteUsage()
    {
        Console.Error.WriteLine(CompileUsage);
        Console.Error.WriteLine(GateUsage);
    }

    private static ECDsa CreateDevelopmentSigningKey()
    {
        var d = new byte[32];
        d[^1] = 1;
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint
            {
                X = Convert.FromHexString(
                    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                Y = Convert.FromHexString(
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            },
        });
    }

    private sealed record ReferenceDatasetDocument
    {
        public string[] DataRequirements { get; init; } = [];

        public ReferenceBarDocument[] Bars { get; init; } = [];

        public ReferenceParameterDocument[] Parameters { get; init; } = [];

        public ReferenceCallbackDocument[] Callbacks { get; init; } = [];

        public ulong LaunchSeed { get; init; }
    }

    private sealed record ReferenceParameterDocument
    {
        public string Id { get; init; } = string.Empty;

        public string Type { get; init; } = string.Empty;

        public JsonElement? Min { get; init; }

        public JsonElement? Max { get; init; }

        public JsonElement Default { get; init; }
    }

    private sealed record ReferenceBarDocument
    {
        public double Open { get; init; }

        public double High { get; init; }

        public double Low { get; init; }

        public double Close { get; init; }

        public double Volume { get; init; }
    }

    private sealed record ReferenceCallbackDocument
    {
        public string Entrypoint { get; init; } = string.Empty;

        public long TimeIndex { get; init; }

        public int CompletedBarIndex { get; init; } = -1;

        public double Bid { get; init; }

        public double Ask { get; init; }

        public double Last { get; init; }

        public double Volume { get; init; }
    }

    private sealed record ParsedReferenceDataset(
        DaxqBacktestReferenceData ReferenceData,
        string[] DataRequirements,
        DaxqParameterManifest[] Parameters);
}
