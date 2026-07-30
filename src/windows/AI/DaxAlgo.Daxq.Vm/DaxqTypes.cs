using System.Diagnostics;

namespace DaxAlgo.Daxq.Vm;

/// <summary>Stable native and managed fault codes for DAXQ VM ABI 3.</summary>
public enum DaxqFault : int
{
    Ok = 0,
    InvalidArgument = 1,
    AbiMismatch = 2,
    InvalidFormat = 3,
    Verification = 4,
    EntrypointNotFound = 5,
    InvalidLifecycle = 6,
    Type = 7,
    Numeric = 8,
    DivideByZero = 9,
    IndexOutOfRange = 10,
    Host = 11,
    InstructionBudget = 12,
    StackBudget = 13,
    Timeout = 14,
    BufferLimit = 15,
    EffectLimit = 16,
    Reentrant = 17,
    Internal = 18,
}

/// <summary>Frozen DAXQ VM ABI 3 callback IDs.</summary>
public enum DaxqEntrypoint : byte
{
    Initialize = 0,
    OnBar = 1,
    OnTick = 2,
}

/// <summary>Frozen scalar tags used by DQXP state, arguments, and the native ABI.</summary>
public enum DaxqValueType : byte
{
    I64 = 1,
    F64 = 2,
    Bool = 3,
}

/// <summary>One tagged DAXQ scalar value.</summary>
public readonly struct DaxqValue : IEquatable<DaxqValue>
{
    private readonly long _bits;

    private DaxqValue(DaxqValueType type, long bits)
    {
        Type = type;
        _bits = bits;
    }

    public DaxqValueType Type { get; }

    public static DaxqValue FromInt64(long value) => new(DaxqValueType.I64, value);

    public static DaxqValue FromDouble(double value)
    {
        if (!double.IsFinite(value))
            throw new ArgumentOutOfRangeException(nameof(value), "DAXQ f64 values must be finite.");
        return new(DaxqValueType.F64, BitConverter.DoubleToInt64Bits(Normalize(value)));
    }

    public static DaxqValue FromBoolean(bool value) => new(DaxqValueType.Bool, value ? 1 : 0);

    public long AsInt64() => Type == DaxqValueType.I64
        ? _bits
        : throw new InvalidOperationException("The DAXQ value is not i64.");

    public double AsDouble() => Type == DaxqValueType.F64
        ? BitConverter.Int64BitsToDouble(_bits)
        : throw new InvalidOperationException("The DAXQ value is not f64.");

    public bool AsBoolean() => Type == DaxqValueType.Bool
        ? _bits != 0
        : throw new InvalidOperationException("The DAXQ value is not bool.");

    public bool Equals(DaxqValue other) => Type == other.Type && _bits == other._bits;

    public override bool Equals(object? obj) => obj is DaxqValue other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Type, _bits);

    public static bool operator ==(DaxqValue left, DaxqValue right) => left.Equals(right);

    public static bool operator !=(DaxqValue left, DaxqValue right) => !left.Equals(right);

    internal long RawBits => _bits;

    internal static DaxqValue FromRaw(DaxqValueType type, long bits) => new(type, bits);

    internal static double Normalize(double value) => value == 0d ? 0d : value;
}

/// <summary>One signal staged by the DAXQ <c>emit</c> host call.</summary>
public readonly record struct DaxqSignal(long Kind, double Strength, long NoteId);

/// <summary>One numeric diagnostic staged by the DAXQ <c>log</c> host call.</summary>
public readonly record struct DaxqLogRecord(long MessageId, double Value);

/// <summary>Allocation-free result metadata for one callback invocation.</summary>
public readonly record struct DaxqInvocationResult(
    DaxqFault Fault,
    uint ExecutedInstructions,
    uint MaxStackDepth,
    int SignalCount,
    int LogCount)
{
    public bool Succeeded => Fault == DaxqFault.Ok;
}

/// <summary>
/// Read-only numeric services available to DAXQ bytecode. Effects, deterministic time-index, state,
/// and RNG are mediated by the VM so they can be committed atomically.
/// </summary>
public interface IDaxqHost
{
    DaxqFault ReadBar(long field, long lookback, out double value);

    DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value);

    DaxqFault ReadParameter(long parameterId, out double value);
}

/// <summary>A host that rejects all external reads; useful for bytecode that uses no read callbacks.</summary>
public sealed class DaxqNullHost : IDaxqHost
{
    private DaxqNullHost()
    {
    }

    public static DaxqNullHost Instance { get; } = new();

    public DaxqFault ReadBar(long field, long lookback, out double value)
    {
        value = 0d;
        return DaxqFault.Host;
    }

    public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
    {
        value = 0d;
        return DaxqFault.Host;
    }

    public DaxqFault ReadParameter(long parameterId, out double value)
    {
        value = 0d;
        return DaxqFault.Host;
    }
}

/// <summary>One callback's deterministic and fail-stop execution limits.</summary>
public readonly record struct DaxqEntrypointBudget(
    int InstructionLimit,
    int StackDepthLimit,
    TimeSpan Timeout);

/// <summary>
/// DAXQ VM ABI 3 limits. The default is the frozen contract; custom values may only tighten it and
/// are intended for deterministic budget tests or an additional host safety envelope.
/// </summary>
public sealed class DaxqExecutionLimits
{
    public static DaxqExecutionLimits Contract { get; } = new(
        new(1_000_000, 512, TimeSpan.FromMilliseconds(250)),
        new(100_000, 256, TimeSpan.FromMilliseconds(25)),
        new(25_000, 128, TimeSpan.FromMilliseconds(5)));

    public DaxqExecutionLimits(
        DaxqEntrypointBudget initialize,
        DaxqEntrypointBudget onBar,
        DaxqEntrypointBudget onTick)
    {
        Validate(initialize, ContractBudget(DaxqEntrypoint.Initialize), nameof(initialize));
        Validate(onBar, ContractBudget(DaxqEntrypoint.OnBar), nameof(onBar));
        Validate(onTick, ContractBudget(DaxqEntrypoint.OnTick), nameof(onTick));
        Initialize = initialize;
        OnBar = onBar;
        OnTick = onTick;
    }

    private DaxqExecutionLimits(
        DaxqEntrypointBudget initialize,
        DaxqEntrypointBudget onBar,
        DaxqEntrypointBudget onTick,
        bool contract)
    {
        Debug.Assert(contract);
        Initialize = initialize;
        OnBar = onBar;
        OnTick = onTick;
    }

    public DaxqEntrypointBudget Initialize { get; }

    public DaxqEntrypointBudget OnBar { get; }

    public DaxqEntrypointBudget OnTick { get; }

    internal DaxqEntrypointBudget For(DaxqEntrypoint entrypoint) => entrypoint switch
    {
        DaxqEntrypoint.Initialize => Initialize,
        DaxqEntrypoint.OnBar => OnBar,
        DaxqEntrypoint.OnTick => OnTick,
        _ => default,
    };

    private static DaxqEntrypointBudget ContractBudget(DaxqEntrypoint entrypoint) => entrypoint switch
    {
        DaxqEntrypoint.Initialize => new(1_000_000, 512, TimeSpan.FromMilliseconds(250)),
        DaxqEntrypoint.OnBar => new(100_000, 256, TimeSpan.FromMilliseconds(25)),
        DaxqEntrypoint.OnTick => new(25_000, 128, TimeSpan.FromMilliseconds(5)),
        _ => default,
    };

    private static void Validate(
        DaxqEntrypointBudget value,
        DaxqEntrypointBudget maximum,
        string parameterName)
    {
        if (value.InstructionLimit <= 0 || value.InstructionLimit > maximum.InstructionLimit ||
            value.StackDepthLimit <= 0 || value.StackDepthLimit > maximum.StackDepthLimit ||
            value.Timeout <= TimeSpan.Zero || value.Timeout > maximum.Timeout)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                "Custom DAXQ limits must be positive and no greater than the frozen ABI 3 limits.");
        }
    }
}

/// <summary>Monotonic clock used only by the fail-stop watchdog and never exposed to bytecode.</summary>
public interface IDaxqMonotonicClock
{
    long Frequency { get; }

    long GetTimestamp();
}

internal sealed class StopwatchDaxqClock : IDaxqMonotonicClock
{
    private StopwatchDaxqClock()
    {
    }

    public static StopwatchDaxqClock Instance { get; } = new();

    public long Frequency => Stopwatch.Frequency;

    public long GetTimestamp() => Stopwatch.GetTimestamp();
}
