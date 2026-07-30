using System.Text.Json;
using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>Enforces the exact lowercase, string-only DAXQ v2 kind wire contract.</summary>
internal sealed class DaxqKindJsonConverter : JsonConverter<DaxqKind>
{
    public override DaxqKind Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
            throw new JsonException("kind must be an exact lowercase string.");

        return Parse(reader.GetString());
    }

    public override void Write(
        Utf8JsonWriter writer,
        DaxqKind value,
        JsonSerializerOptions options) =>
        writer.WriteStringValue(WireName(value));

    internal static DaxqKind Parse(string? value) => value switch
    {
        "strategy" => DaxqKind.Strategy,
        "visualizer" => DaxqKind.Visualizer,
        "composite" => DaxqKind.Composite,
        _ => throw new JsonException("Unsupported kind value."),
    };

    internal static string WireName(DaxqKind value) => value switch
    {
        DaxqKind.Strategy => "strategy",
        DaxqKind.Visualizer => "visualizer",
        DaxqKind.Composite => "composite",
        _ => throw new JsonException("Unsupported DaxqKind value."),
    };
}
