using System.Security.Cryptography;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>Inputs required to seal and release-sign one DAXQ package.</summary>
public sealed record DaxqPackageWriteOptions
{
    /// <summary>Authenticated DQXP v1 plaintext to encrypt.</summary>
    public required byte[] PlaintextBytes { get; init; }

    /// <summary>Stable lowercase marketplace strategy identifier.</summary>
    public required string StrategyId { get; init; }

    /// <summary>Canonical SemVer 2.0.0 release version.</summary>
    public required string Version { get; init; }

    /// <summary>The manifest format version to emit.</summary>
    public int FormatVersion { get; init; } = DaxqFormat.FormatVersion;

    /// <summary>The compiler-resolved artifact kind.</summary>
    public DaxqKind Kind { get; init; } = DaxqKind.Strategy;

    /// <summary>The optional declarative presentation carried by a v2 manifest.</summary>
    public DaxqPresentationManifest? Presentation { get; init; }

    /// <summary>Required input capabilities. Values are normalized to ordinal order.</summary>
    public required IReadOnlyList<string> DataRequirements { get; init; }

    /// <summary>Manifest parameters. Values are normalized to parameter-ID order.</summary>
    public IReadOnlyList<DaxqParameterManifest> Parameters { get; init; } =
        Array.Empty<DaxqParameterManifest>();

    /// <summary>Server-side custody-record identifier for the content key.</summary>
    public required string ContentKeyId { get; init; }

    /// <summary>Exactly 32 bytes of content-key material. The writer never places it in the artifact.</summary>
    public required byte[] ContentKey { get; init; }

    /// <summary>Exactly 12 unique bytes for this content key.</summary>
    public required byte[] Nonce { get; init; }

    /// <summary>Trusted marketplace release-key identifier.</summary>
    public required string ReleaseKeyId { get; init; }

    /// <summary>ECDSA P-256 private key used for the detached ES256 release signature.</summary>
    public required ECDsa ReleaseSigningKey { get; init; }
}

/// <summary>A complete DAXQ package and its independently testable release components.</summary>
public sealed record DaxqPackageArtifact
{
    public required byte[] PackageBytes { get; init; }

    public required byte[] PlaintextBytes { get; init; }

    public required byte[] CiphertextAndTagBytes { get; init; }

    public required byte[] ManifestJsonBytes { get; init; }

    public required byte[] PackageIndexJsonBytes { get; init; }

    public required byte[] SignatureInputBytes { get; init; }

    public required byte[] SignatureBytes { get; init; }

    public required byte[] SignatureJsonBytes { get; init; }

    public required string CipherSha256 { get; init; }

    public required string ManifestSha256 { get; init; }

    public required string PackageIndexSha256 { get; init; }
}
