using DaxAlgo.Daxq.Vm;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>The publication decision produced by the server-side backtest-parity gate.</summary>
public enum DaxqPublicationDecision
{
    Pass = 0,
    Block = 1,
}

/// <summary>Numeric comparison policy for managed and DAXQ signal strengths.</summary>
public sealed record DaxqParityTolerance
{
    /// <summary>Maximum allowed absolute difference between matching signal strengths.</summary>
    public double MaximumAbsoluteSignalStrengthDifference { get; init; }
}

/// <summary>One ordered callback in a canonical parity reference run.</summary>
public readonly record struct DaxqBacktestCallback(
    DaxqEntrypoint Entrypoint,
    long TimeIndex,
    int CompletedBarIndex,
    double Bid,
    double Ask,
    double Last,
    double Volume)
{
    public static DaxqBacktestCallback Bar(int completedBarIndex) =>
        new(DaxqEntrypoint.OnBar, completedBarIndex, completedBarIndex, 0d, 0d, 0d, 0d);

    public static DaxqBacktestCallback Tick(
        long timeIndex,
        int completedBarIndex,
        double bid,
        double ask,
        double last,
        double volume) =>
        new(DaxqEntrypoint.OnTick, timeIndex, completedBarIndex, bid, ask, last, volume);
}

/// <summary>Immutable-by-convention inputs for one managed-versus-DAXQ reference run.</summary>
public sealed record DaxqBacktestReferenceData
{
    public required IReadOnlyList<DaxqBar> Bars { get; init; }

    public IReadOnlyList<double> Parameters { get; init; } = Array.Empty<double>();

    public required IReadOnlyList<DaxqBacktestCallback> Callbacks { get; init; }

    public ulong LaunchSeed { get; init; }
}

/// <summary>One actionable publication-gate diagnostic.</summary>
public sealed record DaxqParityDiagnostic(
    string Code,
    string Message,
    int? CallbackOrdinal = null,
    int? SignalOrdinal = null,
    bool Retryable = false);

/// <summary>
/// Canonical, deterministic statistics for the VM side of a successful parity run. These are
/// execution and signal statistics; DAXQ v1 does not define a fill, sizing, fee, or P&amp;L model.
/// </summary>
public sealed record DaxqBacktestStatistics(
    string SchemaVersion,
    int InitializationCallbacks,
    int BarCallbacks,
    int TickCallbacks,
    ulong ExecutedInstructions,
    uint MaximumStackDepth,
    int LogCount,
    int SignalCount,
    int LongSignalCount,
    int ShortSignalCount,
    int FlatSignalCount,
    double MinimumSignalStrength,
    double MaximumSignalStrength,
    double AverageSignalStrength)
{
    public const string CurrentSchemaVersion = "daxq-backtest-parity-stats-v1";
}

/// <summary>
/// Canonical listing metrics produced from a successful parity run under one frozen financial model.
/// Gross P&amp;L is reference-price-to-reference-price; commission and adverse slippage are explicit
/// costs deducted to obtain net P&amp;L and return. Monetary values use <see cref="Currency"/>.
/// </summary>
public sealed record DaxqListingMetrics(
    string SchemaVersion,
    string Currency,
    string FillModel,
    string SizingModel,
    string ProfitLossModel,
    double StartingEquity,
    double MaximumGrossNotional,
    double CommissionBasisPointsPerFill,
    double AdverseSlippageBasisPointsPerFill,
    double GrossProfitLoss,
    double CommissionFees,
    double SlippageCost,
    double NetProfitLoss,
    double ReturnPercent,
    int ClosedTrades,
    int WinningTrades,
    int LosingTrades,
    double WinRatePercent,
    double MaximumDrawdown)
{
    public const string CurrentSchemaVersion = "daxq-listing-metrics-v1";

    public const string PolicyCurrency = "USD";

    public const string PolicyFillModel =
        "next_callback_bar_close_or_tick_midpoint_last_fallback";

    public const string PolicySizingModel =
        "last_signal_fixed_gross_notional_scaled_by_strength";

    public const string PolicyProfitLossModel =
        "reference_price_mark_to_market_with_final_liquidation";

    public const double PolicyStartingEquity = 100_000d;

    public const double PolicyMaximumGrossNotional = 10_000d;

    public const double PolicyCommissionBasisPointsPerFill = 1d;

    public const double PolicyAdverseSlippageBasisPointsPerFill = 1d;
}

/// <summary>Publication decision, diagnostics, and canonical statistics/metrics for one gate run.</summary>
public sealed record DaxqBacktestParityResult(
    DaxqPublicationDecision Decision,
    DaxqBacktestStatistics? Statistics,
    byte[]? CanonicalStatisticsJson,
    string? StatisticsSha256,
    IReadOnlyList<DaxqParityDiagnostic> Diagnostics)
{
    public bool PublicationAllowed => Decision == DaxqPublicationDecision.Pass;

    public DaxqListingMetrics? ListingMetrics { get; init; }

    public byte[]? CanonicalListingMetricsJson { get; init; }

    public string? ListingMetricsSha256 { get; init; }
}
