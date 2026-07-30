using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Vm;

/// <summary>
/// Pure managed VM ABI 3 interpreter used as the deterministic oracle and server-parity engine.
/// All callback working storage is allocated at construction and effects commit only after RET.
/// </summary>
public sealed class DaxqReferenceVm : IDisposable
{
    private const int MaximumStackDepth = 512;
    private const int MaximumBuffers = 16;
    private const int MaximumBufferElements = 65_536;
    private const int MaximumBufferBytes = 65_536;
    private const int MaximumEmits = 8;
    private const int MaximumLogs = 16;

    private readonly DaxqProgram _program;
    private readonly IDaxqHost _host;
    private readonly DaxqExecutionLimits _limits;
    private readonly IDaxqMonotonicClock _clock;
    private readonly RuntimeValue[] _state;
    private readonly RuntimeValue[] _workingState;
    private readonly RuntimeValue[] _stack = new RuntimeValue[MaximumStackDepth];
    private readonly RuntimeValue[] _locals = new RuntimeValue[256];
    private readonly RuntimeValue[] _arguments = new RuntimeValue[5];
    private readonly RuntimeValue[] _bufferElements = new RuntimeValue[MaximumBufferElements];
    private readonly BufferDescriptor[] _buffers = new BufferDescriptor[MaximumBuffers];
    private readonly DaxqSignal[] _signals = new DaxqSignal[MaximumEmits];
    private readonly DaxqLogRecord[] _logs = new DaxqLogRecord[MaximumLogs];
    private Xoshiro256StarStar _rng;
    private Xoshiro256StarStar _workingRng;
    private int _stagedSignalCount;
    private int _stagedLogCount;
    private int _visibleSignalCount;
    private int _visibleLogCount;
    private int _bufferCount;
    private int _bufferElementCount;
    private int _bufferByteCount;
    private long _timeIndex;
    private bool _initializeSucceeded;
    private int _invoking;
    private int _disposed;

    public DaxqReferenceVm(
        DaxqProgram program,
        IDaxqHost host,
        ulong launchSeed,
        DaxqExecutionLimits? limits = null,
        IDaxqMonotonicClock? clock = null)
    {
        _program = program ?? throw new ArgumentNullException(nameof(program));
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _limits = limits ?? DaxqExecutionLimits.Contract;
        _clock = clock ?? StopwatchDaxqClock.Instance;
        if (_clock.Frequency <= 0)
            throw new ArgumentOutOfRangeException(nameof(clock), "The watchdog clock frequency must be positive.");

        _state = new RuntimeValue[program.StateTypes.Length];
        _workingState = new RuntimeValue[program.StateTypes.Length];
        for (var index = 0; index < program.StateTypes.Length; index++)
        {
            _state[index] = RuntimeValue.Zero(program.StateTypes[index]);
            _workingState[index] = _state[index];
        }

        _rng = Xoshiro256StarStar.Create(launchSeed);
    }

    /// <summary>Signals from the most recent successful callback; invalidated by the next invocation.</summary>
    public ReadOnlySpan<DaxqSignal> EmittedSignals => _signals.AsSpan(0, _visibleSignalCount);

    /// <summary>Logs from the most recent successful callback; invalidated by the next invocation.</summary>
    public ReadOnlySpan<DaxqLogRecord> Logs => _logs.AsSpan(0, _visibleLogCount);

    public DaxqInvocationResult Initialize() => Invoke(DaxqEntrypoint.Initialize, []);

    public DaxqInvocationResult OnBar(long barIndex)
    {
        Span<DaxqValue> arguments = stackalloc DaxqValue[1];
        arguments[0] = DaxqValue.FromInt64(barIndex);
        return Invoke(DaxqEntrypoint.OnBar, arguments);
    }

    public DaxqInvocationResult OnTick(
        long barIndex,
        double bid,
        double ask,
        double last,
        double volume)
    {
        if (!double.IsFinite(bid) || !double.IsFinite(ask) ||
            !double.IsFinite(last) || !double.IsFinite(volume))
        {
            return EmptyResult(DaxqFault.InvalidArgument);
        }

        Span<DaxqValue> arguments = stackalloc DaxqValue[5];
        arguments[0] = DaxqValue.FromInt64(barIndex);
        arguments[1] = DaxqValue.FromDouble(bid);
        arguments[2] = DaxqValue.FromDouble(ask);
        arguments[3] = DaxqValue.FromDouble(last);
        arguments[4] = DaxqValue.FromDouble(volume);
        return Invoke(DaxqEntrypoint.OnTick, arguments);
    }

    /// <summary>Invokes one verified callback without allocating callback-local managed objects.</summary>
    public DaxqInvocationResult Invoke(DaxqEntrypoint entrypoint, ReadOnlySpan<DaxqValue> arguments)
    {
        if (Volatile.Read(ref _disposed) != 0)
            return EmptyResult(DaxqFault.InvalidLifecycle);
        if ((byte)entrypoint >= _program.Entrypoints.Length ||
            _program.Entrypoints[(byte)entrypoint] is not { } verified)
        {
            return EmptyResult(DaxqFault.EntrypointNotFound);
        }
        if (Interlocked.CompareExchange(ref _invoking, 1, 0) != 0)
            return EmptyResult(DaxqFault.Reentrant);

        try
        {
            _visibleSignalCount = 0;
            _visibleLogCount = 0;
            if (entrypoint == DaxqEntrypoint.Initialize && _initializeSucceeded)
                return EmptyResult(DaxqFault.InvalidLifecycle);
            if (!TrySetArguments(verified, arguments))
                return EmptyResult(DaxqFault.InvalidArgument);
            _timeIndex = entrypoint == DaxqEntrypoint.Initialize ? 0 : arguments[0].AsInt64();
            Array.Copy(_state, _workingState, _state.Length);
            _workingRng = _rng;
            _stagedSignalCount = 0;
            _stagedLogCount = 0;
            _bufferCount = 0;
            _bufferElementCount = 0;
            _bufferByteCount = 0;

            return Execute(verified);
        }
        catch (Exception)
        {
            return EmptyResult(DaxqFault.Internal);
        }
        finally
        {
            Volatile.Write(ref _invoking, 0);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_state.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_workingState.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_stack.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_locals.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_arguments.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_bufferElements.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_buffers.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_signals.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_logs.AsSpan()));
    }

    /// <summary>Reads one committed persistent state slot.</summary>
    public DaxqFault TryGetState(int slot, out DaxqValue value)
    {
        if ((uint)slot >= (uint)_state.Length)
        {
            value = default;
            return DaxqFault.IndexOutOfRange;
        }
        value = _state[slot].ToPublicScalar();
        return DaxqFault.Ok;
    }

    private DaxqInvocationResult Execute(VerifiedEntrypoint entrypoint)
    {
        var budget = _limits.For(entrypoint.Id);
        var timeoutTicks = Math.Max(1L, checked((long)Math.Ceiling(
            budget.Timeout.TotalSeconds * _clock.Frequency)));
        var started = _clock.GetTimestamp();
        uint executed = 0;
        uint maximumStack = 0;
        var stackCount = 0;
        var instructionIndex = 0;

        while (true)
        {
            if (TimedOut(started, timeoutTicks))
                return Failure(DaxqFault.Timeout, executed, maximumStack);
            if (executed >= budget.InstructionLimit)
                return Failure(DaxqFault.InstructionBudget, executed, maximumStack);

            var instruction = entrypoint.Instructions[instructionIndex];
            executed++;
            var nextInstruction = instructionIndex + 1;
            var returned = false;
            var fault = ExecuteInstruction(
                instruction,
                budget.StackDepthLimit,
                ref stackCount,
                ref maximumStack,
                ref nextInstruction,
                ref returned);
            if (fault != DaxqFault.Ok)
                return Failure(fault, executed, maximumStack);
            if (TimedOut(started, timeoutTicks))
                return Failure(DaxqFault.Timeout, executed, maximumStack);

            if (returned)
            {
                Array.Copy(_workingState, _state, _state.Length);
                _rng = _workingRng;
                _visibleSignalCount = _stagedSignalCount;
                _visibleLogCount = _stagedLogCount;
                if (entrypoint.Id == DaxqEntrypoint.Initialize)
                    _initializeSucceeded = true;
                return new DaxqInvocationResult(
                    DaxqFault.Ok,
                    executed,
                    maximumStack,
                    _visibleSignalCount,
                    _visibleLogCount);
            }

            instructionIndex = nextInstruction;
        }
    }

    private DaxqFault ExecuteInstruction(
        DecodedInstruction instruction,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack,
        ref int nextInstruction,
        ref bool returned)
    {
        switch (instruction.Opcode)
        {
            case Opcode.PUSH_F64:
            case Opcode.PUSH_I64:
                return Push(
                    RuntimeValue.FromPublic(_program.Constants[instruction.OperandA]),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.PUSH_BOOL:
                return Push(
                    RuntimeValue.FromBool(instruction.OperandA != 0),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.LD_LOC:
                return Push(_locals[instruction.OperandA], stackLimit, ref stackCount, ref maximumStack);
            case Opcode.ST_LOC:
                _locals[instruction.OperandA] = Pop(ref stackCount);
                return DaxqFault.Ok;
            case Opcode.LD_ARG:
                return Push(_arguments[instruction.OperandA], stackLimit, ref stackCount, ref maximumStack);
            case Opcode.ADD:
            case Opcode.SUB:
            case Opcode.MUL:
            case Opcode.DIV:
            case Opcode.MOD:
                return ExecuteBinaryNumeric(
                    instruction.Opcode, stackLimit, ref stackCount, ref maximumStack);
            case Opcode.NEG:
                return ExecuteNegate(stackLimit, ref stackCount, ref maximumStack);
            case Opcode.CEQ:
            case Opcode.CNE:
            case Opcode.CLT:
            case Opcode.CLE:
            case Opcode.CGT:
            case Opcode.CGE:
                return ExecuteComparison(
                    instruction.Opcode, stackLimit, ref stackCount, ref maximumStack);
            case Opcode.AND:
            case Opcode.OR:
                var boolRight = Pop(ref stackCount).Bool;
                var boolLeft = Pop(ref stackCount).Bool;
                return Push(
                    RuntimeValue.FromBool(instruction.Opcode == Opcode.AND
                        ? boolLeft && boolRight
                        : boolLeft || boolRight),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.NOT:
                return Push(
                    RuntimeValue.FromBool(!Pop(ref stackCount).Bool),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.I2F:
                return Push(
                    RuntimeValue.FromDouble(Pop(ref stackCount).I64),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.F2I:
                var conversion = Pop(ref stackCount).F64;
                if (conversion < -9_223_372_036_854_775_808d ||
                    conversion >= 9_223_372_036_854_775_808d)
                {
                    return DaxqFault.Numeric;
                }
                return Push(
                    RuntimeValue.FromInt64((long)Math.Truncate(conversion)),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.BR:
                nextInstruction = instruction.TargetInstruction;
                return DaxqFault.Ok;
            case Opcode.BRT:
                if (Pop(ref stackCount).Bool)
                    nextInstruction = instruction.TargetInstruction;
                return DaxqFault.Ok;
            case Opcode.BRF:
                if (!Pop(ref stackCount).Bool)
                    nextInstruction = instruction.TargetInstruction;
                return DaxqFault.Ok;
            case Opcode.NEWBUF:
                return NewBuffer(
                    instruction.OperandA,
                    instruction.OperandB,
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.LDELEM:
                return LoadElement(stackLimit, ref stackCount, ref maximumStack);
            case Opcode.STELEM:
                return StoreElement(ref stackCount);
            case Opcode.LEN:
                var descriptor = GetBuffer(Pop(ref stackCount));
                return Push(
                    RuntimeValue.FromInt64(descriptor.Length),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.LD_STATE:
                return Push(
                    _workingState[instruction.OperandA],
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.ST_STATE:
                _workingState[instruction.OperandA] = Pop(ref stackCount);
                return DaxqFault.Ok;
            case Opcode.CALL_HOST:
                return CallHost(
                    (HostFn)instruction.OperandA,
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case Opcode.RET:
                if (stackCount != 0)
                    return DaxqFault.Internal;
                returned = true;
                return DaxqFault.Ok;
            default:
                return DaxqFault.Internal;
        }
    }

    private DaxqFault ExecuteBinaryNumeric(
        Opcode opcode,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        var right = Pop(ref stackCount);
        var left = Pop(ref stackCount);
        RuntimeValue result;
        if (left.Type == VmType.I64)
        {
            if ((opcode is Opcode.DIV or Opcode.MOD) && right.I64 == 0)
                return DaxqFault.DivideByZero;
            if ((opcode is Opcode.DIV or Opcode.MOD) &&
                left.I64 == long.MinValue && right.I64 == -1)
            {
                return DaxqFault.Numeric;
            }

            try
            {
                result = RuntimeValue.FromInt64(opcode switch
                {
                    Opcode.ADD => checked(left.I64 + right.I64),
                    Opcode.SUB => checked(left.I64 - right.I64),
                    Opcode.MUL => checked(left.I64 * right.I64),
                    Opcode.DIV => left.I64 / right.I64,
                    Opcode.MOD => left.I64 % right.I64,
                    _ => throw new InvalidOperationException(),
                });
            }
            catch (OverflowException)
            {
                return DaxqFault.Numeric;
            }
        }
        else
        {
            var rightValue = right.F64;
            var leftValue = left.F64;
            if ((opcode is Opcode.DIV or Opcode.MOD) && rightValue == 0d)
                return DaxqFault.DivideByZero;

            var modFault = DaxqFault.Ok;
            var value = opcode switch
            {
                Opcode.ADD => StrictAdd(leftValue, rightValue),
                Opcode.SUB => StrictSubtract(leftValue, rightValue),
                Opcode.MUL => StrictMultiply(leftValue, rightValue),
                Opcode.DIV => StrictDivide(leftValue, rightValue),
                Opcode.MOD => StrictMod(leftValue, rightValue, out modFault),
                _ => double.NaN,
            };
            if ((opcode == Opcode.MOD && modFault != DaxqFault.Ok) || !double.IsFinite(value))
                return DaxqFault.Numeric;
            result = RuntimeValue.FromDouble(value);
        }

        return Push(result, stackLimit, ref stackCount, ref maximumStack);
    }

    private DaxqFault ExecuteNegate(
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        var value = Pop(ref stackCount);
        if (value.Type == VmType.I64)
        {
            if (value.I64 == long.MinValue)
                return DaxqFault.Numeric;
            return Push(
                RuntimeValue.FromInt64(-value.I64),
                stackLimit,
                ref stackCount,
                ref maximumStack);
        }

        var negated = StrictNegate(value.F64);
        return double.IsFinite(negated)
            ? Push(RuntimeValue.FromDouble(negated), stackLimit, ref stackCount, ref maximumStack)
            : DaxqFault.Numeric;
    }

    private DaxqFault ExecuteComparison(
        Opcode opcode,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        var right = Pop(ref stackCount);
        var left = Pop(ref stackCount);
        bool result;
        if (left.Type == VmType.I64)
        {
            result = opcode switch
            {
                Opcode.CEQ => left.I64 == right.I64,
                Opcode.CNE => left.I64 != right.I64,
                Opcode.CLT => left.I64 < right.I64,
                Opcode.CLE => left.I64 <= right.I64,
                Opcode.CGT => left.I64 > right.I64,
                Opcode.CGE => left.I64 >= right.I64,
                _ => false,
            };
        }
        else if (left.Type == VmType.F64)
        {
            result = opcode switch
            {
                Opcode.CEQ => left.F64 == right.F64,
                Opcode.CNE => left.F64 != right.F64,
                Opcode.CLT => left.F64 < right.F64,
                Opcode.CLE => left.F64 <= right.F64,
                Opcode.CGT => left.F64 > right.F64,
                Opcode.CGE => left.F64 >= right.F64,
                _ => false,
            };
        }
        else
        {
            result = opcode switch
            {
                Opcode.CEQ => left.Bool == right.Bool,
                Opcode.CNE => left.Bool != right.Bool,
                _ => false,
            };
        }

        return Push(
            RuntimeValue.FromBool(result),
            stackLimit,
            ref stackCount,
            ref maximumStack);
    }

    private DaxqFault NewBuffer(
        int elementTag,
        int length,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        var elementType = (VmType)elementTag;
        var elementWidth = elementType == VmType.Bool ? 1 : 8;
        var byteCount = checked(length * elementWidth);
        if (_bufferCount >= MaximumBuffers || _bufferByteCount > MaximumBufferBytes - byteCount ||
            _bufferElementCount > MaximumBufferElements - length)
        {
            return DaxqFault.BufferLimit;
        }

        var bufferType = elementType switch
        {
            VmType.I64 => VmType.BufferI64,
            VmType.F64 => VmType.BufferF64,
            VmType.Bool => VmType.BufferBool,
            _ => VmType.Unknown,
        };
        var descriptorIndex = _bufferCount++;
        _buffers[descriptorIndex] = new BufferDescriptor(
            bufferType, _bufferElementCount, length);
        var zero = RuntimeValue.Zero(elementType);
        for (var index = 0; index < length; index++)
            _bufferElements[_bufferElementCount + index] = zero;
        _bufferElementCount += length;
        _bufferByteCount += byteCount;

        return Push(
            RuntimeValue.FromBuffer(bufferType, descriptorIndex),
            stackLimit,
            ref stackCount,
            ref maximumStack);
    }

    private DaxqFault LoadElement(
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        var index = Pop(ref stackCount).I64;
        var descriptor = GetBuffer(Pop(ref stackCount));
        if (index < 0 || index >= descriptor.Length)
            return DaxqFault.IndexOutOfRange;
        return Push(
            _bufferElements[descriptor.Start + (int)index],
            stackLimit,
            ref stackCount,
            ref maximumStack);
    }

    private DaxqFault StoreElement(ref int stackCount)
    {
        var value = Pop(ref stackCount);
        var index = Pop(ref stackCount).I64;
        var descriptor = GetBuffer(Pop(ref stackCount));
        if (index < 0 || index >= descriptor.Length)
            return DaxqFault.IndexOutOfRange;
        _bufferElements[descriptor.Start + (int)index] = value;
        return DaxqFault.Ok;
    }

    private DaxqFault CallHost(
        HostFn host,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        switch (host)
        {
            case HostFn.Bar:
                var lookback = Pop(ref stackCount).I64;
                var field = Pop(ref stackCount).I64;
                if (field is < 1 or > 5 || lookback is < 0 or > 65_535)
                    return DaxqFault.Host;
                var barFault = InvokeBar(field, lookback, out var barValue);
                if (barFault != DaxqFault.Ok)
                    return barFault;
                return PushFinite(barValue, stackLimit, ref stackCount, ref maximumStack);
            case HostFn.Ind:
                var source = Pop(ref stackCount).I64;
                var period = Pop(ref stackCount).I64;
                var indicator = Pop(ref stackCount).I64;
                if (indicator is < 1 or > 4 || period is < 1 or > 65_535 ||
                    source is < 1 or > 5 || (indicator == 4 && source != 4))
                {
                    return DaxqFault.Host;
                }
                var indicatorFault = InvokeIndicator(indicator, period, source, out var indicatorValue);
                if (indicatorFault != DaxqFault.Ok)
                    return indicatorFault;
                return PushFinite(indicatorValue, stackLimit, ref stackCount, ref maximumStack);
            case HostFn.Param:
                var parameter = Pop(ref stackCount).I64;
                if (parameter is < 0 or > 255)
                    return DaxqFault.Host;
                var parameterFault = InvokeParameter(parameter, out var parameterValue);
                if (parameterFault != DaxqFault.Ok)
                    return parameterFault;
                return PushFinite(parameterValue, stackLimit, ref stackCount, ref maximumStack);
            case HostFn.Emit:
                var note = Pop(ref stackCount).I64;
                var strength = Pop(ref stackCount).F64;
                var kind = Pop(ref stackCount).I64;
                if (kind is < -1 or > 1 || note < 0 || !double.IsFinite(strength) ||
                    strength < 0d || strength > 1d)
                {
                    return DaxqFault.Host;
                }
                if (_stagedSignalCount >= MaximumEmits)
                    return DaxqFault.EffectLimit;
                _signals[_stagedSignalCount++] = new DaxqSignal(
                    kind, DaxqValue.Normalize(strength), note);
                return DaxqFault.Ok;
            case HostFn.TIndex:
                return Push(
                    RuntimeValue.FromInt64(_timeIndex),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case HostFn.Rng:
                return Push(
                    RuntimeValue.FromDouble(_workingRng.NextDouble()),
                    stackLimit,
                    ref stackCount,
                    ref maximumStack);
            case HostFn.Log:
                var logValue = Pop(ref stackCount).F64;
                var message = Pop(ref stackCount).I64;
                if (message < 0 || !double.IsFinite(logValue))
                    return DaxqFault.Host;
                if (_stagedLogCount >= MaximumLogs)
                    return DaxqFault.EffectLimit;
                _logs[_stagedLogCount++] = new DaxqLogRecord(
                    message, DaxqValue.Normalize(logValue));
                return DaxqFault.Ok;
            default:
                return DaxqFault.Internal;
        }
    }

    private DaxqFault InvokeBar(long field, long lookback, out double value)
    {
        try
        {
            return NormalizeHostReadFault(_host.ReadBar(field, lookback, out value));
        }
        catch (Exception)
        {
            value = 0d;
            return DaxqFault.Host;
        }
    }

    private DaxqFault InvokeIndicator(long indicator, long period, long source, out double value)
    {
        try
        {
            return NormalizeHostReadFault(_host.ReadIndicator(indicator, period, source, out value));
        }
        catch (Exception)
        {
            value = 0d;
            return DaxqFault.Host;
        }
    }

    private DaxqFault InvokeParameter(long parameter, out double value)
    {
        try
        {
            return NormalizeHostReadFault(_host.ReadParameter(parameter, out value));
        }
        catch (Exception)
        {
            value = 0d;
            return DaxqFault.Host;
        }
    }

    private static DaxqFault NormalizeHostReadFault(DaxqFault fault) => fault switch
    {
        DaxqFault.Ok => DaxqFault.Ok,
        DaxqFault.Numeric => DaxqFault.Numeric,
        _ => DaxqFault.Host,
    };

    private DaxqFault PushFinite(
        double value,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        if (!double.IsFinite(value))
            return DaxqFault.Numeric;
        return Push(
            RuntimeValue.FromDouble(value),
            stackLimit,
            ref stackCount,
            ref maximumStack);
    }

    private DaxqFault Push(
        RuntimeValue value,
        int stackLimit,
        ref int stackCount,
        ref uint maximumStack)
    {
        if (stackCount >= stackLimit || stackCount >= _stack.Length)
            return DaxqFault.StackBudget;
        _stack[stackCount++] = value;
        if ((uint)stackCount > maximumStack)
            maximumStack = (uint)stackCount;
        return DaxqFault.Ok;
    }

    private RuntimeValue Pop(ref int stackCount) => _stack[--stackCount];

    private BufferDescriptor GetBuffer(RuntimeValue handle) => _buffers[checked((int)handle.Bits)];

    private bool TrySetArguments(VerifiedEntrypoint entrypoint, ReadOnlySpan<DaxqValue> arguments)
    {
        if (arguments.Length != entrypoint.ArgumentTypes.Length)
            return false;
        for (var index = 0; index < arguments.Length; index++)
        {
            var expected = entrypoint.ArgumentTypes[index];
            var value = arguments[index];
            if ((byte)value.Type != (byte)expected)
                return false;
            if (value.Type == DaxqValueType.F64 && !double.IsFinite(value.AsDouble()))
                return false;
            _arguments[index] = RuntimeValue.FromPublic(value);
        }
        return true;
    }

    private bool TimedOut(long started, long timeoutTicks) =>
        unchecked(_clock.GetTimestamp() - started) >= timeoutTicks;

    private DaxqInvocationResult Failure(
        DaxqFault fault,
        uint executed,
        uint maximumStack)
    {
        _visibleSignalCount = 0;
        _visibleLogCount = 0;
        return new DaxqInvocationResult(fault, executed, maximumStack, 0, 0);
    }

    private DaxqInvocationResult EmptyResult(DaxqFault fault)
        => new(fault, 0, 0, 0, 0);

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

    private static double StrictMod(double left, double right, out DaxqFault fault)
    {
        var quotient = StrictDivide(left, right);
        if (!double.IsFinite(quotient))
        {
            fault = DaxqFault.Numeric;
            return double.NaN;
        }
        var truncated = Math.Truncate(quotient);
        var product = StrictMultiply(truncated, right);
        if (!double.IsFinite(product))
        {
            fault = DaxqFault.Numeric;
            return double.NaN;
        }
        var result = StrictSubtract(left, product);
        fault = double.IsFinite(result) ? DaxqFault.Ok : DaxqFault.Numeric;
        return result;
    }

    private readonly record struct BufferDescriptor(VmType Type, int Start, int Length);
}

internal readonly struct RuntimeValue
{
    private RuntimeValue(VmType type, long bits)
    {
        Type = type;
        Bits = bits;
    }

    public VmType Type { get; }

    public long Bits { get; }

    public long I64 => Bits;

    public double F64 => BitConverter.Int64BitsToDouble(Bits);

    public bool Bool => Bits != 0;

    public static RuntimeValue FromInt64(long value) => new(VmType.I64, value);

    public static RuntimeValue FromDouble(double value) => new(
        VmType.F64,
        BitConverter.DoubleToInt64Bits(DaxqValue.Normalize(value)));

    public static RuntimeValue FromBool(bool value) => new(VmType.Bool, value ? 1 : 0);

    public static RuntimeValue FromBuffer(VmType type, int index) => new(type, index);

    public static RuntimeValue FromPublic(DaxqValue value) => new((VmType)value.Type, value.RawBits);

    public static RuntimeValue Zero(VmType type) => new(type, 0);

    public DaxqValue ToPublicScalar() => DaxqValue.FromRaw((DaxqValueType)Type, Bits);
}

internal struct Xoshiro256StarStar
{
    private ulong _s0;
    private ulong _s1;
    private ulong _s2;
    private ulong _s3;

    public static Xoshiro256StarStar Create(ulong seed)
    {
        var splitMixState = seed;
        return new Xoshiro256StarStar
        {
            _s0 = SplitMix64(ref splitMixState),
            _s1 = SplitMix64(ref splitMixState),
            _s2 = SplitMix64(ref splitMixState),
            _s3 = SplitMix64(ref splitMixState),
        };
    }

    public double NextDouble()
    {
        var value = NextUInt64();
        return (value >> 11) * (1d / 9_007_199_254_740_992d);
    }

    private ulong NextUInt64()
    {
        unchecked
        {
            var result = RotateLeft(_s1 * 5, 7) * 9;
            var temporary = _s1 << 17;
            _s2 ^= _s0;
            _s3 ^= _s1;
            _s1 ^= _s2;
            _s0 ^= _s3;
            _s2 ^= temporary;
            _s3 = RotateLeft(_s3, 45);
            return result;
        }
    }

    private static ulong SplitMix64(ref ulong state)
    {
        unchecked
        {
            state += 0x9e3779b97f4a7c15UL;
            var value = state;
            value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9UL;
            value = (value ^ (value >> 27)) * 0x94d049bb133111ebUL;
            return value ^ (value >> 31);
        }
    }

    private static ulong RotateLeft(ulong value, int count) =>
        (value << count) | (value >> (64 - count));
}
