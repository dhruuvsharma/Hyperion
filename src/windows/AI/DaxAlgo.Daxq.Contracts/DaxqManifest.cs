using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>The cleartext <c>manifest.json</c> contract for DAXQ package versions 1 and 2.</summary>
[JsonConverter(typeof(DaxqManifestJsonConverter))]
public sealed record DaxqManifest
{
    /// <summary>The package-format version. Supported values are 1 and 2.</summary>
    [JsonPropertyName("formatVersion")]
    [JsonPropertyOrder(0)]
    public required int FormatVersion { get; init; }

    /// <summary>The closed artifact kind. Frozen v1 wire value <c>daxq</c> reads as strategy.</summary>
    [JsonPropertyName("kind")]
    [JsonPropertyOrder(1)]
    public required DaxqKind Kind { get; init; }

    /// <summary>The stable marketplace strategy ID.</summary>
    [JsonPropertyName("strategyId")]
    [JsonPropertyOrder(2)]
    public required string StrategyId { get; init; }

    /// <summary>The canonical strategy release version.</summary>
    [JsonPropertyName("version")]
    [JsonPropertyOrder(3)]
    public required string Version { get; init; }

    /// <summary>The SDK ABI used by indicator and parameter IDs.</summary>
    [JsonPropertyName("sdkAbiVersion")]
    [JsonPropertyOrder(4)]
    public required int SdkAbiVersion { get; init; }

    /// <summary>The marketplace execution class. DAXQ packages use sealed bytecode.</summary>
    [JsonPropertyName("executionClass")]
    [JsonPropertyOrder(5)]
    public required ExecutionClass ExecutionClass { get; init; }

    /// <summary>Unique, ordinal-sorted input capabilities required by the strategy.</summary>
    [JsonPropertyName("dataRequirements")]
    [JsonPropertyOrder(6)]
    public required string[] DataRequirements { get; init; }

    /// <summary>Canonical parameter declarations, ordered by ID.</summary>
    [JsonPropertyName("params")]
    [JsonPropertyOrder(7)]
    public required DaxqParameterManifest[] Parameters { get; init; }

    /// <summary>Content-key and authenticated-encryption metadata.</summary>
    [JsonPropertyName("protection")]
    [JsonPropertyOrder(8)]
    public required DaxqProtectionManifest Protection { get; init; }

    /// <summary>Per-buyer watermark metadata.</summary>
    [JsonPropertyName("watermark")]
    [JsonPropertyOrder(9)]
    public required DaxqWatermarkManifest Watermark { get; init; }

    /// <summary>The minimum VM ABI. DAXQ v1 requires <see cref="DaxqFormat.VmAbiVersion"/>.</summary>
    [JsonPropertyName("vmMin")]
    [JsonPropertyOrder(10)]
    public required int VmMin { get; init; }

    /// <summary>Informational file hashes; canonical writers sort keys ordinally.</summary>
    [JsonPropertyName("files")]
    [JsonPropertyOrder(11)]
    public required Dictionary<string, string> Files { get; init; }

    /// <summary>The optional protected-presentation declaration for a drawing DAXQ v2 artifact.</summary>
    [JsonPropertyName("presentation")]
    [JsonPropertyOrder(12)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DaxqPresentationManifest? Presentation { get; init; }
}

/// <summary>One numeric or Boolean strategy parameter in a DAXQ manifest.</summary>
public sealed record DaxqParameterManifest
{
    /// <summary>The stable parameter ID.</summary>
    [JsonPropertyName("id")]
    [JsonPropertyOrder(0)]
    public required string Id { get; init; }

    /// <summary>The frozen wire type: <c>int</c>, <c>float</c>, or <c>bool</c>.</summary>
    [JsonPropertyName("type")]
    [JsonPropertyOrder(1)]
    public required string Type { get; init; }

    /// <summary>The optional inclusive numeric minimum.</summary>
    [JsonPropertyName("min")]
    [JsonPropertyOrder(2)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Min { get; init; }

    /// <summary>The optional inclusive numeric maximum.</summary>
    [JsonPropertyName("max")]
    [JsonPropertyOrder(3)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public JsonElement? Max { get; init; }

    /// <summary>The required default value, matching <see cref="Type"/>.</summary>
    [JsonPropertyName("default")]
    [JsonPropertyOrder(4)]
    public required JsonElement Default { get; init; }
}

/// <summary>AES-GCM and server-side content-key metadata.</summary>
public sealed record DaxqProtectionManifest
{
    /// <summary>The authenticated-encryption algorithm label.</summary>
    [JsonPropertyName("alg")]
    [JsonPropertyOrder(0)]
    public required string Algorithm { get; init; }

    /// <summary>The server-side KMS custody-record ID; this is not key material.</summary>
    [JsonPropertyName("contentKeyId")]
    [JsonPropertyOrder(1)]
    public required string ContentKeyId { get; init; }

    /// <summary>The unpadded base64url 96-bit AES-GCM nonce.</summary>
    [JsonPropertyName("nonce")]
    [JsonPropertyOrder(2)]
    public required string Nonce { get; init; }

    /// <summary>Lowercase SHA-256 of the complete <c>strategy.dqx</c> bytes.</summary>
    [JsonPropertyName("cipherSha256")]
    [JsonPropertyOrder(3)]
    public required string CipherSha256 { get; init; }
}

/// <summary>Per-buyer watermark scheme and encrypted payload slot name.</summary>
public sealed record DaxqWatermarkManifest
{
    /// <summary>The watermark scheme. V1 requires <c>per-buyer-v1</c>.</summary>
    [JsonPropertyName("scheme")]
    [JsonPropertyOrder(0)]
    public required string Scheme { get; init; }

    /// <summary>The corresponding plaintext watermark slot. V1 requires <c>wm</c>.</summary>
    [JsonPropertyName("slot")]
    [JsonPropertyOrder(1)]
    public required string Slot { get; init; }
}

/// <summary>Declared protected-presentation surface for one DAXQ v2 artifact.</summary>
public sealed record DaxqPresentationManifest
{
    /// <summary>Canonical render entrypoints. V2 declares only <c>render</c>.</summary>
    [JsonPropertyName("entrypoints")]
    [JsonPropertyOrder(0)]
    public required string[] Entrypoints { get; init; }

    /// <summary>The number of statically declared host-owned panels.</summary>
    [JsonPropertyName("panelCount")]
    [JsonPropertyOrder(1)]
    public required int PanelCount { get; init; }

    /// <summary>Canonical panel declarations ordered by zero-based ID.</summary>
    [JsonPropertyName("panels")]
    [JsonPropertyOrder(2)]
    public required DaxqPanelManifest[] Panels { get; init; }

    /// <summary>The render host-function block version required by this presentation.</summary>
    [JsonPropertyName("hostFnVersion")]
    [JsonPropertyOrder(3)]
    public required int HostFnVersion { get; init; }

    /// <summary>The declared count of immutable presentation snapshot slots.</summary>
    [JsonPropertyName("snapshotSlots")]
    [JsonPropertyOrder(4)]
    public required int SnapshotSlots { get; init; }

    /// <summary>The bounded per-frame render budget requested by the publisher.</summary>
    [JsonPropertyName("budget")]
    [JsonPropertyOrder(5)]
    public required DaxqRenderBudgetManifest Budget { get; init; }
}

/// <summary>One statically declared host-owned presentation panel.</summary>
public sealed record DaxqPanelManifest
{
    /// <summary>The zero-based panel ID used by <c>panel_begin</c>.</summary>
    [JsonPropertyName("id")]
    [JsonPropertyOrder(0)]
    public required int Id { get; init; }

    /// <summary>The panel capability granted to the artifact.</summary>
    [JsonPropertyName("kind")]
    [JsonPropertyOrder(1)]
    public required DaxqPanelKind Kind { get; init; }
}

/// <summary>Publisher-requested hard limits for one protected render frame.</summary>
public sealed record DaxqRenderBudgetManifest
{
    /// <summary>The maximum draw operations permitted in one frame.</summary>
    [JsonPropertyName("maxOpsPerFrame")]
    [JsonPropertyOrder(0)]
    public required int MaxOpsPerFrame { get; init; }

    /// <summary>The maximum vertices permitted in one series.</summary>
    [JsonPropertyName("maxVerticesPerSeries")]
    [JsonPropertyOrder(1)]
    public required int MaxVerticesPerSeries { get; init; }

    /// <summary>The maximum length of one render string.</summary>
    [JsonPropertyName("maxStringLength")]
    [JsonPropertyOrder(2)]
    public required int MaxStringLength { get; init; }

    /// <summary>The maximum panels that may be addressed in one frame.</summary>
    [JsonPropertyName("maxPanels")]
    [JsonPropertyOrder(3)]
    public required int MaxPanels { get; init; }
}
