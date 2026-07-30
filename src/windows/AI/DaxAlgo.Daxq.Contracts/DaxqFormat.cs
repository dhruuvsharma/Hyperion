namespace DaxAlgo.Daxq.Contracts;

/// <summary>Frozen file, format, cryptographic, and VM ABI constants for DAXQ package versions 1 and 2.</summary>
public static class DaxqFormat
{
    /// <summary>The protected-strategy package extension.</summary>
    public const string PackageExtension = ".daxq";

    /// <summary>The cleartext manifest ZIP entry.</summary>
    public const string ManifestEntryName = "manifest.json";

    /// <summary>The encrypted strategy ZIP entry.</summary>
    public const string CiphertextEntryName = "strategy.dqx";

    /// <summary>The package integrity-index ZIP entry.</summary>
    public const string PackageIndexEntryName = "package.json";

    /// <summary>The detached release-signature ZIP entry.</summary>
    public const string SignatureEntryName = "signature.json";

    /// <summary>The frozen DAXQ v1 manifest and package format version.</summary>
    public const int FormatVersion = 1;

    /// <summary>The additive protected-presentation manifest format version.</summary>
    public const int PresentationFormatVersion = 2;

    /// <summary>The only supported deterministic plaintext-container version.</summary>
    public const int PlaintextContainerVersion = 1;

    /// <summary>The frozen VM ABI version used by DAXQ format v1.</summary>
    public const int VmAbiVersion = 3;

    /// <summary>The minimum VM ABI reserved for protected presentation.</summary>
    public const int RenderVmAbiVersion = 4;

    /// <summary>The SDK ABI required by DAXQ format v1.</summary>
    public const int SdkAbiVersion = 3;

    /// <summary>The legacy kind token used by frozen v1 compiler and Host call sites.</summary>
    public static readonly DaxqLegacyKind Kind = default;

    /// <summary>The frozen v1 wire spelling of <see cref="DaxqKind.Strategy"/>.</summary>
    public const string LegacyKindWireName = "daxq";

    /// <summary>The first render host-function block version.</summary>
    public const int RenderHostFunctionBlockVersion = 1;

    /// <summary>The sole render entrypoint declared by DAXQ v2.</summary>
    public const string RenderEntrypoint = "Render";

    /// <summary>The maximum number of panels one presentation may declare or request.</summary>
    public const int MaximumPresentationPanels = 8;

    /// <summary>The maximum number of immutable snapshot slots a presentation may publish.</summary>
    public const int MaximumPresentationSnapshotSlots = 256;

    /// <summary>The hard upper bound for a requested render-operation budget per frame.</summary>
    public const int MaximumRenderOpsPerFrame = 100_000;

    /// <summary>The hard upper bound for a requested vertex budget per series.</summary>
    public const int MaximumRenderVerticesPerSeries = 65_536;

    /// <summary>The hard upper bound for a requested render-string length.</summary>
    public const int MaximumRenderStringLength = 4_096;

    /// <summary>The required content-encryption algorithm label.</summary>
    public const string CipherAlgorithm = "AES-256-GCM";

    /// <summary>The required detached-signature algorithm label.</summary>
    public const string SignatureAlgorithm = "ES256";

    /// <summary>The AES-GCM nonce size in bytes.</summary>
    public const int NonceSizeBytes = 12;

    /// <summary>The AES-GCM authentication-tag size in bytes.</summary>
    public const int AuthenticationTagSizeBytes = 16;

    /// <summary>The IEEE-P1363 P-256 signature size in bytes.</summary>
    public const int SignatureSizeBytes = 64;
}
