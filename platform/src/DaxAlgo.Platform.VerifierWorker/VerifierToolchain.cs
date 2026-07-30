using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Sdk;
using Microsoft.CodeAnalysis.CSharp;
using TradingTerminal.Core.Backtest;

namespace DaxAlgo.Platform.VerifierWorker;

internal sealed class VerifierToolchain
{
    private static readonly JsonSerializerOptions ClosureJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly string[] RuntimeReferenceNames =
    [
        "System.Private.CoreLib.dll",
        "System.Runtime.dll",
        "System.Collections.dll",
        "System.Linq.dll",
        "System.Threading.dll",
        "System.Threading.Tasks.dll",
        "System.Runtime.Extensions.dll",
        "System.Console.dll",
        "System.IO.FileSystem.dll",
        "System.Net.Primitives.dll",
        "System.Net.Http.dll",
        "System.Diagnostics.Process.dll",
        "System.Reflection.dll",
        "System.Runtime.Loader.dll",
        "System.Runtime.InteropServices.dll",
    ];

    private VerifierToolchain(
        string[] referencePaths,
        VerifierWorkerIdentity identity)
    {
        ReferencePaths = referencePaths;
        Identity = identity;
    }

    public string[] ReferencePaths { get; }

    public VerifierWorkerIdentity Identity { get; }

    public static VerifierToolchain Create()
    {
        var runtimeDirectory = Path.GetDirectoryName(typeof(object).Assembly.Location)
            ?? throw new InvalidOperationException("The managed runtime directory is unavailable.");
        var references = RuntimeReferenceNames
            .Select(name => Path.Combine(runtimeDirectory, name))
            .Append(typeof(IBacktestStrategy).Assembly.Location)
            .Append(typeof(SdkInfo).Assembly.Location)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (references.Any(path => !File.Exists(path)))
        {
            throw new InvalidOperationException("The frozen compiler reference closure is incomplete.");
        }

        var closure = references
            .Select(CreateArtifactIdentity)
            .OrderBy(item => item.Name, StringComparer.Ordinal)
            .ThenBy(item => item.Version, StringComparer.Ordinal)
            .ToArray();
        var closureBytes = JsonSerializer.SerializeToUtf8Bytes(
            closure,
            ClosureJsonOptions);
        var identity = new VerifierWorkerIdentity(
            Version: "1.0.0",
            Worker: CreateArtifactIdentity(typeof(HeadlessStrategyVerifier).Assembly.Location),
            Runtime: CreateArtifactIdentity(typeof(object).Assembly.Location),
            Core: CreateArtifactIdentity(typeof(IBacktestStrategy).Assembly.Location),
            Sdk: CreateArtifactIdentity(typeof(SdkInfo).Assembly.Location),
            Roslyn: CreateArtifactIdentity(typeof(CSharpCompilation).Assembly.Location),
            CompilerClosure: closure,
            CompilerClosureSha256: Hash(closureBytes));
        return new(references, identity);
    }

    public static string Hash(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static VerifierArtifactIdentity CreateArtifactIdentity(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var name = AssemblyName.GetAssemblyName(fullPath);
        return new(
            name.Name ?? Path.GetFileNameWithoutExtension(fullPath),
            name.Version?.ToString() ?? "0.0.0.0",
            Hash(File.ReadAllBytes(fullPath)));
    }
}
