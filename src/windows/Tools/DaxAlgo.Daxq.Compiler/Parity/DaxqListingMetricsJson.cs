using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler;

internal static class DaxqListingMetricsJson
{
    public static byte[] Write(DaxqListingMetrics metrics)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("schemaVersion", metrics.SchemaVersion);
            writer.WriteString("currency", metrics.Currency);
            writer.WriteString("fillModel", metrics.FillModel);
            writer.WriteString("sizingModel", metrics.SizingModel);
            writer.WriteString("profitLossModel", metrics.ProfitLossModel);
            writer.WriteNumber("startingEquity", metrics.StartingEquity);
            writer.WriteNumber("maximumGrossNotional", metrics.MaximumGrossNotional);
            writer.WriteNumber("commissionBasisPointsPerFill", metrics.CommissionBasisPointsPerFill);
            writer.WriteNumber("adverseSlippageBasisPointsPerFill", metrics.AdverseSlippageBasisPointsPerFill);
            writer.WriteNumber("grossProfitLoss", metrics.GrossProfitLoss);
            writer.WriteNumber("commissionFees", metrics.CommissionFees);
            writer.WriteNumber("slippageCost", metrics.SlippageCost);
            writer.WriteNumber("netProfitLoss", metrics.NetProfitLoss);
            writer.WriteNumber("returnPercent", metrics.ReturnPercent);
            writer.WriteNumber("closedTrades", metrics.ClosedTrades);
            writer.WriteNumber("winningTrades", metrics.WinningTrades);
            writer.WriteNumber("losingTrades", metrics.LosingTrades);
            writer.WriteNumber("winRatePercent", metrics.WinRatePercent);
            writer.WriteNumber("maximumDrawdown", metrics.MaximumDrawdown);
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }
}
