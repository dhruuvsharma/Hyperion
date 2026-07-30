using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>Closed artifact kinds introduced by the DAXQ v2 manifest.</summary>
[JsonConverter(typeof(DaxqKindJsonConverter))]
public enum DaxqKind : byte
{
    /// <summary>An artifact that publishes strategy signals.</summary>
    [JsonStringEnumMemberName("strategy")]
    Strategy = 0,

    /// <summary>An artifact that draws a protected presentation.</summary>
    [JsonStringEnumMemberName("visualizer")]
    Visualizer = 1,

    /// <summary>An artifact that publishes signals and draws a protected presentation.</summary>
    [JsonStringEnumMemberName("composite")]
    Composite = 2,
}

/// <summary>
/// Compatibility token for frozen v1 call sites. It converts only to the legacy <c>daxq</c> wire
/// string or to the semantic <see cref="DaxqKind.Strategy"/> value.
/// </summary>
public readonly struct DaxqLegacyKind
{
    /// <summary>Converts the compatibility token to the frozen v1 wire value.</summary>
    public static implicit operator string(DaxqLegacyKind value) => DaxqFormat.LegacyKindWireName;

    /// <summary>Converts the compatibility token to its semantic artifact kind.</summary>
    public static implicit operator DaxqKind(DaxqLegacyKind value) => DaxqKind.Strategy;

    /// <inheritdoc/>
    public override string ToString() => DaxqFormat.LegacyKindWireName;
}
