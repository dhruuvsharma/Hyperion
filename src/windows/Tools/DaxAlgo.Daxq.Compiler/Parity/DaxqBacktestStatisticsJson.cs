using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler;

internal static class DaxqBacktestStatisticsJson
{
    public static byte[] Write(DaxqBacktestStatistics statistics)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", statistics.SchemaVersion);
            writer.WriteNumber("initializationCallbacks", statistics.InitializationCallbacks);
            writer.WriteNumber("barCallbacks", statistics.BarCallbacks);
            writer.WriteNumber("tickCallbacks", statistics.TickCallbacks);
            writer.WriteNumber("executedInstructions", statistics.ExecutedInstructions);
            writer.WriteNumber("maximumStackDepth", statistics.MaximumStackDepth);
            writer.WriteNumber("logCount", statistics.LogCount);
            writer.WriteNumber("signalCount", statistics.SignalCount);
            writer.WriteNumber("longSignalCount", statistics.LongSignalCount);
            writer.WriteNumber("shortSignalCount", statistics.ShortSignalCount);
            writer.WriteNumber("flatSignalCount", statistics.FlatSignalCount);
            writer.WriteNumber("minimumSignalStrength", statistics.MinimumSignalStrength);
            writer.WriteNumber("maximumSignalStrength", statistics.MaximumSignalStrength);
            writer.WriteNumber("averageSignalStrength", statistics.AverageSignalStrength);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
