using DaxAlgo.Daxq.Vm;
using DaxAlgo.Daxq.Contracts;
using System.Security.Cryptography;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>One compiler diagnostic suitable for a submission response.</summary>
public sealed record DaxqCompilerDiagnostic(
    string Code,
    string Message,
    string? File = null,
    int? Line = null,
    int? Column = null);

/// <summary>A deterministic Roslyn image plus its verified canonical DAXQ lowering.</summary>
public sealed record DaxqLoweringResult(
    byte[] ManagedAssembly,
    DaxqCanonicalProgram Program,
    IReadOnlyList<DaxqCompilerDiagnostic> Diagnostics);

/// <summary>Release inputs for the complete source-to-package compiler pipeline.</summary>
public sealed record DaxqCompilerOptions
{
    public string SourceFileName { get; init; } = "Strategy.cs";

    public required string StrategyId { get; init; }

    public required string Version { get; init; }

    /// <summary>The manifest version to emit. Existing callers remain on frozen format v1.</summary>
    public int FormatVersion { get; init; } = DaxqFormat.FormatVersion;

    /// <summary>
    /// Optional publisher declaration checked against compiler-inferred signal/presentation capability.
    /// When omitted, the compiler selects the only valid kind.
    /// </summary>
    public DaxqKind? Kind { get; init; }

    /// <summary>The declarative DAXQ v2 presentation surface; no render bytecode is accepted here.</summary>
    public DaxqPresentationManifest? Presentation { get; init; }

    public required IReadOnlyList<string> DataRequirements { get; init; }

    public IReadOnlyList<DaxqParameterManifest> Parameters { get; init; } =
        Array.Empty<DaxqParameterManifest>();

    /// <summary>Exactly 32 unique release-specific bytes used for all diversification domains.</summary>
    public required byte[] DiversificationSeed { get; init; }

    public byte[] Watermark { get; init; } = new byte[32];

    public required string ContentKeyId { get; init; }

    public required byte[] ContentKey { get; init; }

    public required byte[] Nonce { get; init; }

    public required string ReleaseKeyId { get; init; }

    public required ECDsa ReleaseSigningKey { get; init; }
}

/// <summary>All inspectable stages of one successful source-to-DAXQ compilation.</summary>
public sealed record DaxqCompilationArtifact(
    DaxqLoweringResult Lowering,
    DaxqPlaintextBuildResult Plaintext,
    DaxqPackageArtifact Package,
    DaxqReleaseMetadata Release);

/// <summary>Server-side release record persisted by the caller alongside the produced package.</summary>
public sealed record DaxqReleaseMetadata(
    string StrategyId,
    string Version,
    string DiversificationSeedHex,
    string DiversificationSeedSha256,
    string PackageSha256);

/// <summary>One canonical constant-pool entry, stored as its exact VM scalar bits.</summary>
public readonly record struct DaxqConstant(DaxqValueType Type, long Bits)
{
    public static DaxqConstant FromInt64(long value) => new(DaxqValueType.I64, value);

    public static DaxqConstant FromDouble(double value)
    {
        if (!double.IsFinite(value))
            throw new ArgumentOutOfRangeException(nameof(value));
        return new(DaxqValueType.F64, BitConverter.DoubleToInt64Bits(value == 0d ? 0d : value));
    }
}

/// <summary>One canonical VM entrypoint before per-release map diversification.</summary>
public sealed record DaxqCanonicalEntrypoint(
    DaxqEntrypoint Id,
    ushort LocalCount,
    byte[] Bytecode);

/// <summary>The deterministic pre-diversification compiler output.</summary>
public sealed record DaxqCanonicalProgram(
    IReadOnlyList<DaxqConstant> Constants,
    IReadOnlyList<DaxqValueType> StateTypes,
    IReadOnlyList<DaxqCanonicalEntrypoint> Entrypoints)
{
    /// <summary>Host functions reached by verified strategy entrypoints.</summary>
    public IReadOnlySet<HostFn> ReferencedHostFunctions { get; init; } = new HashSet<HostFn>();

    /// <summary>Compile-time parameter indexes reached through <see cref="HostFn.Param"/>.</summary>
    public IReadOnlyList<long> ReferencedParameterIds { get; init; } = Array.Empty<long>();

    public byte[] Bytecode => Entrypoints
        .OrderBy(entrypoint => entrypoint.Id)
        .SelectMany(entrypoint => entrypoint.Bytecode)
        .ToArray();
}
