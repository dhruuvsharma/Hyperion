using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler;

internal static class DaxqBacktestParityOutputJson
{
    public static byte[] Write(DaxqBacktestParityResult result)
    {
        ArgumentNullException.ThrowIfNull(result.CanonicalStatisticsJson);
        ArgumentNullException.ThrowIfNull(result.CanonicalListingMetricsJson);

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("parityStatistics");
            writer.WriteRawValue(result.CanonicalStatisticsJson, skipInputValidation: false);
            writer.WritePropertyName("listingMetrics");
            writer.WriteRawValue(result.CanonicalListingMetricsJson, skipInputValidation: false);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
