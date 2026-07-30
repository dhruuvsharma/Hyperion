using System.Runtime.CompilerServices;

namespace DaxAlgo.Daxq.Vm;

/// <summary>One finite, normalized canonical OHLCV bar supplied to the DAXQ SDK ABI 3 host.</summary>
public readonly record struct DaxqBar
{
    public DaxqBar(double open, double high, double low, double close, double volume)
    {
        if (!double.IsFinite(open) || !double.IsFinite(high) || !double.IsFinite(low) ||
            !double.IsFinite(close) || !double.IsFinite(volume))
        {
            throw new ArgumentOutOfRangeException(nameof(open), "Every DAXQ OHLCV value must be finite.");
        }

        Open = DaxqValue.Normalize(open);
        High = DaxqValue.Normalize(high);
        Low = DaxqValue.Normalize(low);
        Close = DaxqValue.Normalize(close);
        Volume = DaxqValue.Normalize(volume);
    }

    public double Open { get; }

    public double High { get; }

    public double Low { get; }

    public double Close { get; }

    public double Volume { get; }
}

/// <summary>
/// Allocation-free standalone implementation of the frozen SDK ABI 3 bar, parameter, and indicator
/// host slice. The caller owns the read-only memories and must not mutate their backing storage while
/// a VM invocation is in progress.
/// </summary>
public sealed class DaxqSdkAbi3FrameHost : IDaxqHost
{
    private readonly ReadOnlyMemory<DaxqBar> _history;
    private readonly ReadOnlyMemory<double> _parameters;
    private readonly int _maximumIndicatorSamples;
    private int _currentCompletedBarIndex;

    public DaxqSdkAbi3FrameHost(
        ReadOnlyMemory<DaxqBar> canonicalHistory,
        ReadOnlyMemory<double> numericParameters,
        int currentCompletedBarIndex = -1,
        int maximumIndicatorSamples = 65_536)
    {
        if (maximumIndicatorSamples <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumIndicatorSamples));
        if (numericParameters.Length > 256)
            throw new ArgumentOutOfRangeException(nameof(numericParameters));
        foreach (var value in numericParameters.Span)
        {
            if (!double.IsFinite(value))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(numericParameters),
                    "DAXQ numeric parameters must be finite.");
            }
        }

        _history = canonicalHistory;
        _parameters = numericParameters;
        _maximumIndicatorSamples = maximumIndicatorSamples;
        CurrentCompletedBarIndex = currentCompletedBarIndex;
    }

    /// <summary>The zero-based history index of the most recently completed bar, or -1 when absent.</summary>
    public int CurrentCompletedBarIndex
    {
        get => _currentCompletedBarIndex;
        set
        {
            if (value < -1 || value >= _history.Length)
                throw new ArgumentOutOfRangeException(nameof(value));
            _currentCompletedBarIndex = value;
        }
    }

    /// <summary>The configured hard bound on chronological samples processed by one indicator call.</summary>
    public int MaximumIndicatorSamples => _maximumIndicatorSamples;

    public DaxqFault ReadBar(long field, long lookback, out double value)
    {
        value = 0d;
        if (field is < 1 or > 5 || lookback is < 0 or > 65_535 ||
            lookback > _currentCompletedBarIndex)
        {
            return DaxqFault.Host;
        }

        var bar = _history.Span[_currentCompletedBarIndex - (int)lookback];
        value = Field(bar, field);
        return DaxqFault.Ok;
    }

    public DaxqFault ReadIndicator(
        long indicator,
        long period,
        long sourceField,
        out double value)
    {
        value = 0d;
        if (indicator is < 1 or > 4 || period is < 1 or > 65_535 ||
            sourceField is < 1 or > 5 || _currentCompletedBarIndex < 0 ||
            _currentCompletedBarIndex + 1 > _maximumIndicatorSamples ||
            (indicator == 4 && sourceField != 4))
        {
            return DaxqFault.Host;
        }

        var period32 = (int)period;
        return indicator switch
        {
            1 => ReadEma(period32, sourceField, out value),
            2 => ReadSma(period32, sourceField, out value),
            3 => ReadRsi(period32, sourceField, out value),
            4 => ReadAtr(period32, out value),
            _ => DaxqFault.Host,
        };
    }

    public DaxqFault ReadParameter(long parameterId, out double value)
    {
        if (parameterId < 0 || parameterId >= _parameters.Length)
        {
            value = 0d;
            return DaxqFault.Host;
        }
        value = DaxqValue.Normalize(_parameters.Span[(int)parameterId]);
        return DaxqFault.Ok;
    }

    private DaxqFault ReadEma(int period, long sourceField, out double value)
    {
        value = 0d;
        var available = _currentCompletedBarIndex + 1;
        if (available < period)
            return DaxqFault.Host;

        var history = _history.Span;
        var sum = 0d;
        for (var index = 0; index < period; index++)
        {
            if (!TryAdd(sum, Field(history[index], sourceField), out sum))
                return DaxqFault.Numeric;
        }
        if (!TryDivide(sum, period, out var ema) ||
            !TryDivide(2d, period + 1d, out var alpha))
        {
            return DaxqFault.Numeric;
        }

        for (var index = period; index <= _currentCompletedBarIndex; index++)
        {
            if (!TrySubtract(Field(history[index], sourceField), ema, out var difference) ||
                !TryMultiply(alpha, difference, out var adjustment) ||
                !TryAdd(ema, adjustment, out ema))
            {
                return DaxqFault.Numeric;
            }
        }

        value = DaxqValue.Normalize(ema);
        return DaxqFault.Ok;
    }

    private DaxqFault ReadSma(int period, long sourceField, out double value)
    {
        value = 0d;
        var available = _currentCompletedBarIndex + 1;
        if (available < period)
            return DaxqFault.Host;

        var history = _history.Span;
        var first = available - period;
        var sum = 0d;
        for (var index = first; index <= _currentCompletedBarIndex; index++)
        {
            if (!TryAdd(sum, Field(history[index], sourceField), out sum))
                return DaxqFault.Numeric;
        }
        if (!TryDivide(sum, period, out value))
            return DaxqFault.Numeric;
        value = DaxqValue.Normalize(value);
        return DaxqFault.Ok;
    }

    private DaxqFault ReadRsi(int period, long sourceField, out double value)
    {
        value = 0d;
        var available = _currentCompletedBarIndex + 1;
        if (available < period + 1)
            return DaxqFault.Host;

        var history = _history.Span;
        var gainSum = 0d;
        var lossSum = 0d;
        for (var index = 1; index <= period; index++)
        {
            if (!TryDelta(
                    Field(history[index - 1], sourceField),
                    Field(history[index], sourceField),
                    out var gain,
                    out var loss) ||
                !TryAdd(gainSum, gain, out gainSum) ||
                !TryAdd(lossSum, loss, out lossSum))
            {
                return DaxqFault.Numeric;
            }
        }
        if (!TryDivide(gainSum, period, out var averageGain) ||
            !TryDivide(lossSum, period, out var averageLoss))
        {
            return DaxqFault.Numeric;
        }

        for (var index = period + 1; index <= _currentCompletedBarIndex; index++)
        {
            if (!TryDelta(
                    Field(history[index - 1], sourceField),
                    Field(history[index], sourceField),
                    out var gain,
                    out var loss) ||
                !TryWilderUpdate(averageGain, gain, period, out averageGain) ||
                !TryWilderUpdate(averageLoss, loss, period, out averageLoss))
            {
                return DaxqFault.Numeric;
            }
        }

        if (averageGain == 0d && averageLoss == 0d)
            value = 50d;
        else if (averageGain == 0d)
            value = 0d;
        else if (averageLoss == 0d)
            value = 100d;
        else
        {
            if (!TryDivide(averageGain, averageLoss, out var relativeStrength) ||
                !TryAdd(1d, relativeStrength, out var denominator) ||
                !TryDivide(100d, denominator, out var fraction) ||
                !TrySubtract(100d, fraction, out value))
            {
                return DaxqFault.Numeric;
            }
        }

        value = DaxqValue.Normalize(value);
        return DaxqFault.Ok;
    }

    private DaxqFault ReadAtr(int period, out double value)
    {
        value = 0d;
        var available = _currentCompletedBarIndex + 1;
        if (available < period)
            return DaxqFault.Host;

        var sum = 0d;
        for (var index = 0; index < period; index++)
        {
            if (!TryTrueRange(index, out var trueRange) || !TryAdd(sum, trueRange, out sum))
                return DaxqFault.Numeric;
        }
        if (!TryDivide(sum, period, out var average))
            return DaxqFault.Numeric;

        for (var index = period; index <= _currentCompletedBarIndex; index++)
        {
            if (!TryTrueRange(index, out var trueRange) ||
                !TryWilderUpdate(average, trueRange, period, out average))
            {
                return DaxqFault.Numeric;
            }
        }

        value = DaxqValue.Normalize(average);
        return DaxqFault.Ok;
    }

    private bool TryTrueRange(int index, out double value)
    {
        var history = _history.Span;
        var bar = history[index];
        if (!TrySubtract(bar.High, bar.Low, out var highLow))
        {
            value = 0d;
            return false;
        }
        if (index == 0)
        {
            value = highLow;
            return true;
        }

        if (!TrySubtract(bar.High, history[index - 1].Close, out var highPrevious) ||
            !TrySubtract(bar.Low, history[index - 1].Close, out var lowPrevious))
        {
            value = 0d;
            return false;
        }
        highPrevious = Math.Abs(highPrevious);
        lowPrevious = Math.Abs(lowPrevious);
        if (!double.IsFinite(highPrevious) || !double.IsFinite(lowPrevious))
        {
            value = 0d;
            return false;
        }
        value = Math.Max(highLow, Math.Max(highPrevious, lowPrevious));
        return double.IsFinite(value);
    }

    private static bool TryDelta(
        double previous,
        double current,
        out double gain,
        out double loss)
    {
        gain = 0d;
        loss = 0d;
        if (!TrySubtract(current, previous, out var delta))
            return false;
        if (delta > 0d)
            gain = delta;
        else if (delta < 0d)
        {
            loss = StrictNegate(delta);
            if (!double.IsFinite(loss))
                return false;
        }
        return true;
    }

    private static bool TryWilderUpdate(
        double previous,
        double current,
        int period,
        out double value)
    {
        if (!TryMultiply(previous, period - 1d, out var weighted) ||
            !TryAdd(weighted, current, out var numerator) ||
            !TryDivide(numerator, period, out value))
        {
            value = 0d;
            return false;
        }
        return true;
    }

    private static double Field(DaxqBar bar, long field) => field switch
    {
        1 => bar.Open,
        2 => bar.High,
        3 => bar.Low,
        4 => bar.Close,
        5 => bar.Volume,
        _ => double.NaN,
    };

    private static bool TryAdd(double left, double right, out double value)
    {
        value = StrictAdd(left, right);
        return double.IsFinite(value);
    }

    private static bool TrySubtract(double left, double right, out double value)
    {
        value = StrictSubtract(left, right);
        return double.IsFinite(value);
    }

    private static bool TryMultiply(double left, double right, out double value)
    {
        value = StrictMultiply(left, right);
        return double.IsFinite(value);
    }

    private static bool TryDivide(double left, double right, out double value)
    {
        if (right == 0d)
        {
            value = 0d;
            return false;
        }
        value = StrictDivide(left, right);
        return double.IsFinite(value);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static double StrictAdd(double left, double right) => left + right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static double StrictSubtract(double left, double right) => left - right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static double StrictMultiply(double left, double right) => left * right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static double StrictDivide(double left, double right) => left / right;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static double StrictNegate(double value) => -value;
}
