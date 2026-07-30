using Xunit.Abstractions;

namespace DaxAlgo.Daxq.Vm.Tests;

public sealed class FaultAndBudgetTests
{
    private readonly ITestOutputHelper _output;

    public FaultAndBudgetTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Reference_faults_cover_numeric_index_effect_and_all_budget_classes()
    {
        AssertReferenceFault(OverflowProgram(), DaxqNullHost.Instance, DaxqFault.Numeric);
        AssertReferenceFault(DivideByZeroProgram(), DaxqNullHost.Instance, DaxqFault.DivideByZero);
        AssertReferenceFault(NonFiniteHostProgram(), new NonFiniteHost(), DaxqFault.Numeric);
        AssertReferenceFault(BadBufferIndexProgram(), DaxqNullHost.Instance, DaxqFault.IndexOutOfRange);
        AssertReferenceFault(InstructionLoopProgram(), DaxqNullHost.Instance, DaxqFault.InstructionBudget);
        AssertReferenceFault(StackBudgetProgram(), DaxqNullHost.Instance, DaxqFault.StackBudget);
        AssertReferenceFault(TimeoutProgram(), new SlowHost(), DaxqFault.Timeout);
        AssertReferenceFault(EffectLimitProgram(), DaxqNullHost.Instance, DaxqFault.EffectLimit);
        AssertReferenceFault(BufferLimitProgram(), DaxqNullHost.Instance, DaxqFault.BufferLimit);
    }

    [Fact]
    public void Tightened_reference_watchdog_faults_before_executing_bytecode()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        var limits = new DaxqExecutionLimits(
            DaxqExecutionLimits.Contract.Initialize,
            new DaxqEntrypointBudget(100_000, 256, TimeSpan.FromMilliseconds(1)),
            DaxqExecutionLimits.Contract.OnTick);
        var vm = new DaxqReferenceVm(
            Load(builder),
            DaxqNullHost.Instance,
            1,
            limits,
            new AdvancingClock(step: 1, frequency: 1_000));

        var result = vm.OnBar(0);

        Assert.Equal(DaxqFault.Timeout, result.Fault);
        Assert.Equal(0u, result.ExecutedInstructions);
    }

    [Fact]
    public void Native_and_reference_fault_codes_match_when_the_built_DLL_is_available()
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
        {
            _output.WriteLine("Native fault parity not run: daxq_vm DLL was not found.");
            return;
        }
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        _output.WriteLine($"Native fault parity DLL: {library}");

        AssertNativeParity(OverflowProgram(), DaxqNullHost.Instance, DaxqFault.Numeric);
        AssertNativeParity(DivideByZeroProgram(), DaxqNullHost.Instance, DaxqFault.DivideByZero);
        AssertNativeParity(NonFiniteHostProgram(), new NonFiniteHost(), DaxqFault.Numeric);
        AssertNativeParity(BadBufferIndexProgram(), DaxqNullHost.Instance, DaxqFault.IndexOutOfRange);
        AssertNativeParity(InstructionLoopProgram(), DaxqNullHost.Instance, DaxqFault.InstructionBudget);
        AssertNativeParity(StackBudgetProgram(), DaxqNullHost.Instance, DaxqFault.StackBudget);
        AssertNativeParity(TimeoutProgram(), new SlowHost(), DaxqFault.Timeout);
    }

    [Fact]
    public void F2I_range_and_integer_minimum_divide_and_modulo_fault_numeric()
    {
        AssertReferenceFault(F2IOutOfRangeProgram(), DaxqNullHost.Instance, DaxqFault.Numeric);
        AssertReferenceFault(MinimumByNegativeOneProgram(Opcode.DIV), DaxqNullHost.Instance, DaxqFault.Numeric);
        AssertReferenceFault(MinimumByNegativeOneProgram(Opcode.MOD), DaxqNullHost.Instance, DaxqFault.Numeric);
    }

    [Fact]
    public void OnTick_rejects_non_finite_callback_arguments_before_execution()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnTick).Op(Opcode.RET);
        var vm = new DaxqReferenceVm(Load(builder), DaxqNullHost.Instance, 1);

        Assert.Equal(DaxqFault.InvalidArgument, vm.OnTick(0, double.NaN, 1, 1, 1).Fault);
        Assert.Equal(DaxqFault.InvalidArgument, vm.OnTick(0, 1, double.PositiveInfinity, 1, 1).Fault);
    }

    [Fact]
    public void Runtime_parameter_id_above_manifest_limit_host_faults_without_reaching_the_SDK()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1)
            .Op(Opcode.LD_ARG).U16(0).Call(HostFn.Param, 1)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        var program = Load(builder);
        var referenceHost = new CountingParameterHost();
        var reference = new DaxqReferenceVm(program, referenceHost, 1);

        Assert.Equal(DaxqFault.Host, reference.OnBar(256).Fault);
        Assert.Equal(0, referenceHost.CallCount);

        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        var nativeHost = new CountingParameterHost();
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, nativeHost, 1, out var native));
        using (native)
        {
            Assert.Equal(DaxqFault.Host, native!.OnBar(256).Fault);
            Assert.Equal(0, nativeHost.CallCount);
        }
    }

    private static void AssertReferenceFault(
        DaxqTestContainerBuilder builder,
        IDaxqHost host,
        DaxqFault expected)
    {
        var vm = new DaxqReferenceVm(Load(builder), host, 77);
        var result = vm.OnBar(0);
        Assert.Equal(expected, result.Fault);
        Assert.Empty(vm.EmittedSignals.ToArray());
        Assert.Empty(vm.Logs.ToArray());
    }

    private static void AssertNativeParity(
        DaxqTestContainerBuilder builder,
        IDaxqHost host,
        DaxqFault expected)
    {
        var program = Load(builder);
        var reference = new DaxqReferenceVm(program, host, 88);
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.TryCreate(program, host, 88, out var native));
        using (native)
        {
            var referenceResult = reference.OnBar(0);
            var nativeResult = native!.OnBar(0);
            Assert.Equal(expected, referenceResult.Fault);
            Assert.Equal(referenceResult.Fault, nativeResult.Fault);
            Assert.Empty(reference.EmittedSignals.ToArray());
            Assert.Empty(reference.Logs.ToArray());
            Assert.Empty(native.EmittedSignals.ToArray());
            Assert.Empty(native.Logs.ToArray());
        }
    }

    private static DaxqTestContainerBuilder OverflowProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var maximum = builder.AddInt64(long.MaxValue);
        var one = builder.AddInt64(1);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.PUSH_I64).U16(maximum).Op(Opcode.PUSH_I64).U16(one)
            .Op(Opcode.ADD).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder DivideByZeroProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var one = builder.AddInt64(1);
        var zero = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.PUSH_I64).U16(one).Op(Opcode.PUSH_I64).U16(zero)
            .Op(Opcode.DIV).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder NonFiniteHostProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var close = builder.AddInt64(4);
        var zero = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.PUSH_I64).U16(close).Op(Opcode.PUSH_I64).U16(zero)
            .Call(HostFn.Bar, 2).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder BadBufferIndexProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var one = builder.AddInt64(1);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.NEWBUF).U8((byte)DaxqValueType.I64).U16(1)
            .Op(Opcode.PUSH_I64).U16(one).Op(Opcode.LDELEM)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder InstructionLoopProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        var loop = code.Mark();
        var branch = code.Branch(Opcode.BR);
        code.PatchBranch(branch, loop);
        return builder;
    }

    private static DaxqTestContainerBuilder StackBudgetProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        for (var index = 0; index < 257; index++)
            code.Op(Opcode.PUSH_BOOL).U8(1);
        for (var index = 0; index < 256; index++)
            code.Op(Opcode.AND);
        var branch = code.Branch(Opcode.BRT);
        var end = code.Mark();
        code.Op(Opcode.RET);
        code.PatchBranch(branch, end);
        return builder;
    }

    private static DaxqTestContainerBuilder TimeoutProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var kind = builder.AddInt64(1);
        var strength = builder.AddDouble(1);
        var note = builder.AddInt64(0);
        var close = builder.AddInt64(4);
        var zero = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.PUSH_I64).U16(kind).Op(Opcode.PUSH_F64).U16(strength)
            .Op(Opcode.PUSH_I64).U16(note).Call(HostFn.Emit, 3)
            .Op(Opcode.PUSH_I64).U16(close).Op(Opcode.PUSH_I64).U16(zero)
            .Call(HostFn.Bar, 2).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder EffectLimitProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var kind = builder.AddInt64(1);
        var strength = builder.AddDouble(1);
        var note = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        for (var index = 0; index < 9; index++)
        {
            code.Op(Opcode.PUSH_I64).U16(kind).Op(Opcode.PUSH_F64).U16(strength)
                .Op(Opcode.PUSH_I64).U16(note).Call(HostFn.Emit, 3);
        }
        code.Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder BufferLimitProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        for (var index = 0; index < 17; index++)
        {
            code.Op(Opcode.NEWBUF).U8((byte)DaxqValueType.I64).U16(0)
                .Op(Opcode.ST_LOC).U16(0);
        }
        code.Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder F2IOutOfRangeProgram()
    {
        var builder = new DaxqTestContainerBuilder();
        var value = builder.AddDouble(9_223_372_036_854_775_808d);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.PUSH_F64).U16(value).Op(Opcode.F2I)
            .Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqTestContainerBuilder MinimumByNegativeOneProgram(Opcode opcode)
    {
        var builder = new DaxqTestContainerBuilder();
        var minimum = builder.AddInt64(long.MinValue);
        var negativeOne = builder.AddInt64(-1);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, 1);
        code.Op(Opcode.PUSH_I64).U16(minimum).Op(Opcode.PUSH_I64).U16(negativeOne)
            .Op(opcode).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        return builder;
    }

    private static DaxqProgram Load(DaxqTestContainerBuilder builder)
    {
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        return program!;
    }

    private sealed class NonFiniteHost : IDaxqHost
    {
        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            value = double.NaN;
            return DaxqFault.Ok;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }
    }

    private sealed class SlowHost : IDaxqHost
    {
        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            Thread.Sleep(40);
            value = 1;
            return DaxqFault.Ok;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }
    }

    private sealed class CountingParameterHost : IDaxqHost
    {
        public int CallCount { get; private set; }

        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            CallCount++;
            value = 1;
            return DaxqFault.Ok;
        }
    }

    private sealed class AdvancingClock : IDaxqMonotonicClock
    {
        private readonly long _step;
        private long _timestamp;

        public AdvancingClock(long step, long frequency)
        {
            _step = step;
            Frequency = frequency;
        }

        public long Frequency { get; }

        public long GetTimestamp() => Interlocked.Add(ref _timestamp, _step);
    }
}
