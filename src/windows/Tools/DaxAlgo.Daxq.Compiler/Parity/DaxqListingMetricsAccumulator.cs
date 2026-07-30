using DaxAlgo.Daxq.Vm;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>
/// Implements <c>daxq-listing-metrics-v1</c>. The last signal emitted by one callback becomes a fixed
/// gross-notional target at the next callback reference price. A changed target closes the current
/// trade and reopens it, even when direction is unchanged; an identical target does not rebalance.
/// </summary>
internal sealed class DaxqListingMetricsAccumulator
{
    private const double BasisPoint = 0.0001d;

    private double _pendingTargetNotional;
    private bool _hasPendingTarget;
    private double _currentTargetNotional;
    private double _positionQuantity;
    private double _entryReferencePrice;
    private double _entryCommission;
    private double _entrySlippage;
    private double _grossProfitLoss;
    private double _commissionFees;
    private double _slippageCost;
    private double _equityPeak = DaxqListingMetrics.PolicyStartingEquity;
    private double _maximumDrawdown;
    private int _closedTrades;
    private int _winningTrades;
    private int _losingTrades;

    public void BeginCallback(double referencePrice)
    {
        ValidateReferencePrice(referencePrice);
        ObserveEquity(referencePrice);
        if (!_hasPendingTarget)
            return;

        ExecuteTarget(_pendingTargetNotional, referencePrice);
        _hasPendingTarget = false;
        ObserveEquity(referencePrice);
    }

    public void ObserveSignals(ReadOnlySpan<DaxqSignal> signals)
    {
        if (signals.IsEmpty)
            return;

        var signal = signals[^1];
        if (signal.Kind is < -1 or > 1 ||
            !double.IsFinite(signal.Strength) ||
            signal.Strength is < 0d or > 1d)
        {
            throw new InvalidOperationException("A parity signal is outside the listing-metric policy.");
        }

        var direction = Math.Sign(signal.Kind);
        _pendingTargetNotional = direction == 0
            ? 0d
            : Normalize(direction * DaxqListingMetrics.PolicyMaximumGrossNotional * signal.Strength);
        _hasPendingTarget = true;
    }

    public DaxqListingMetrics Complete(double finalReferencePrice)
    {
        ValidateReferencePrice(finalReferencePrice);
        ObserveEquity(finalReferencePrice);
        if (_positionQuantity != 0d)
        {
            ClosePosition(finalReferencePrice);
            _currentTargetNotional = 0d;
            ObserveEquity(finalReferencePrice);
        }
        _hasPendingTarget = false;

        var netProfitLoss = RequireFinite(
            _grossProfitLoss - _commissionFees - _slippageCost,
            "Net profit/loss");
        var returnPercent = RequireFinite(
            netProfitLoss / DaxqListingMetrics.PolicyStartingEquity * 100d,
            "Return percentage");
        var winRatePercent = _closedTrades == 0
            ? 0d
            : RequireFinite(_winningTrades * 100d / _closedTrades, "Win rate");

        return new DaxqListingMetrics(
            DaxqListingMetrics.CurrentSchemaVersion,
            DaxqListingMetrics.PolicyCurrency,
            DaxqListingMetrics.PolicyFillModel,
            DaxqListingMetrics.PolicySizingModel,
            DaxqListingMetrics.PolicyProfitLossModel,
            DaxqListingMetrics.PolicyStartingEquity,
            DaxqListingMetrics.PolicyMaximumGrossNotional,
            DaxqListingMetrics.PolicyCommissionBasisPointsPerFill,
            DaxqListingMetrics.PolicyAdverseSlippageBasisPointsPerFill,
            Normalize(_grossProfitLoss),
            Normalize(_commissionFees),
            Normalize(_slippageCost),
            Normalize(netProfitLoss),
            Normalize(returnPercent),
            _closedTrades,
            _winningTrades,
            _losingTrades,
            Normalize(winRatePercent),
            Normalize(_maximumDrawdown));
    }

    private void ExecuteTarget(double targetNotional, double referencePrice)
    {
        if (targetNotional == _currentTargetNotional)
            return;

        if (_positionQuantity != 0d)
            ClosePosition(referencePrice);
        if (targetNotional != 0d)
            OpenPosition(targetNotional, referencePrice);
        _currentTargetNotional = targetNotional;
    }

    private void OpenPosition(double targetNotional, double referencePrice)
    {
        var absoluteNotional = Math.Abs(targetNotional);
        _positionQuantity = RequireFinite(targetNotional / referencePrice, "Position quantity");
        _entryReferencePrice = referencePrice;
        _entryCommission = FillCost(
            absoluteNotional,
            DaxqListingMetrics.PolicyCommissionBasisPointsPerFill,
            "Entry commission");
        _entrySlippage = FillCost(
            absoluteNotional,
            DaxqListingMetrics.PolicyAdverseSlippageBasisPointsPerFill,
            "Entry slippage");
        _commissionFees = RequireFinite(_commissionFees + _entryCommission, "Commission fees");
        _slippageCost = RequireFinite(_slippageCost + _entrySlippage, "Slippage cost");
    }

    private void ClosePosition(double referencePrice)
    {
        var gross = RequireFinite(
            _positionQuantity * (referencePrice - _entryReferencePrice),
            "Closed-trade gross profit/loss");
        var exitNotional = RequireFinite(Math.Abs(_positionQuantity) * referencePrice, "Exit notional");
        var exitCommission = FillCost(
            exitNotional,
            DaxqListingMetrics.PolicyCommissionBasisPointsPerFill,
            "Exit commission");
        var exitSlippage = FillCost(
            exitNotional,
            DaxqListingMetrics.PolicyAdverseSlippageBasisPointsPerFill,
            "Exit slippage");

        _grossProfitLoss = RequireFinite(_grossProfitLoss + gross, "Gross profit/loss");
        _commissionFees = RequireFinite(_commissionFees + exitCommission, "Commission fees");
        _slippageCost = RequireFinite(_slippageCost + exitSlippage, "Slippage cost");
        var tradeNet = RequireFinite(
            gross - _entryCommission - _entrySlippage - exitCommission - exitSlippage,
            "Closed-trade net profit/loss");
        _closedTrades++;
        if (tradeNet > 0d)
            _winningTrades++;
        else if (tradeNet < 0d)
            _losingTrades++;

        _positionQuantity = 0d;
        _entryReferencePrice = 0d;
        _entryCommission = 0d;
        _entrySlippage = 0d;
    }

    private void ObserveEquity(double referencePrice)
    {
        var unrealized = _positionQuantity == 0d
            ? 0d
            : RequireFinite(
                _positionQuantity * (referencePrice - _entryReferencePrice),
                "Unrealized profit/loss");
        var equity = RequireFinite(
            DaxqListingMetrics.PolicyStartingEquity + _grossProfitLoss + unrealized -
            _commissionFees - _slippageCost,
            "Marked equity");
        _equityPeak = Math.Max(_equityPeak, equity);
        _maximumDrawdown = Math.Max(_maximumDrawdown, _equityPeak - equity);
    }

    private static double FillCost(double referenceNotional, double basisPoints, string name) =>
        RequireFinite(referenceNotional * basisPoints * BasisPoint, name);

    private static void ValidateReferencePrice(double value)
    {
        if (!double.IsFinite(value) || value <= 0d)
            throw new ArgumentException("Every listing-metric reference price must be finite and positive.");
    }

    private static double RequireFinite(double value, string name)
    {
        if (!double.IsFinite(value))
            throw new InvalidOperationException($"{name} became non-finite under the listing-metric policy.");
        return value;
    }

    private static double Normalize(double value) => value == 0d ? 0d : value;
}
