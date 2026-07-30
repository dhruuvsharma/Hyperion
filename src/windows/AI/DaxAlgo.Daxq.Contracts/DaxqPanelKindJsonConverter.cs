using System.Text.Json;
using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>Enforces the exact lowercase, string-only presentation panel-kind wire contract.</summary>
internal sealed class DaxqPanelKindJsonConverter : JsonConverter<DaxqPanelKind>
{
    public override DaxqPanelKind Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException("panel kind must be an exact lowercase string.");

        return Parse(reader.GetString());
    }

    public override void Write(
        Utf8JsonWriter writer,
        DaxqPanelKind value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(WireName(value));

    internal static DaxqPanelKind Parse(string? value) => value switch
    {
        "plot" => DaxqPanelKind.Plot,
        "canvas" => DaxqPanelKind.Canvas,
        _ => throw new JsonException("Unsupported panel kind value."),
    };

    internal static string WireName(DaxqPanelKind value) => value switch
    {
        DaxqPanelKind.Plot => "plot",
        DaxqPanelKind.Canvas => "canvas",
        _ => throw new JsonException("Unsupported DaxqPanelKind value."),
    };
}
