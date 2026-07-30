namespace DaxAlgo.Sdk;

/// <summary>Frozen SDK ABI 3 indicator identifiers available to protected strategies.</summary>
public enum Ind : long
{
    Ema = 1,
    Sma = 2,
    Rsi = 3,
    Atr = 4,
}

/// <summary>Frozen SDK ABI 3 OHLCV field identifiers.</summary>
public enum BarField : long
{
    Open = 1,
    High = 2,
    Low = 3,
    Close = 4,
    Volume = 5,
}

/// <summary>Frozen SDK ABI 3 signal identifiers.</summary>
public enum SignalKind : long
{
    Short = -1,
    Flat = 0,
    Long = 1,
}

/// <summary>
/// The numeric-only source facade accepted by the server-side DAXQ compiler. It mirrors the frozen
/// SDK ABI 3 host table; it is not a general host or broker API.
/// </summary>
public interface IStrategyContext
{
    double Indicator(Ind indicator, long period, BarField sourceField = BarField.Close);

    void Emit(SignalKind kind, double strength, long noteId = 0);

    double Param(long parameterId);

    double Bar(BarField field, long lookback = 0);

    long TimeIndex();

    double Random();

    void Log(long messageId, double value);
}

/// <summary>
/// Restricted numeric strategy kernel compiled to DAXQ. Implement at least <see cref="OnBar"/> or
/// <see cref="OnTick"/>. Scalar instance fields are persistent state and are lowered to typed slots.
/// </summary>
public interface IBacktestStrategy
{
    void Initialize(IStrategyContext context)
    {
    }

    void OnBar(IStrategyContext context)
    {
    }

    void OnTick(
        IStrategyContext context,
        double bid,
        double ask,
        double last,
        double volume)
    {
    }
}
