using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>Closed presentation panel kinds available to a DAXQ v2 artifact.</summary>
[JsonConverter(typeof(DaxqPanelKindJsonConverter))]
public enum DaxqPanelKind : byte
{
    /// <summary>A host-owned plotted-series panel with axes.</summary>
    [JsonStringEnumMemberName("plot")]
    Plot = 0,

    /// <summary>A host-owned immediate-mode drawing canvas.</summary>
    [JsonStringEnumMemberName("canvas")]
    Canvas = 1,
}
