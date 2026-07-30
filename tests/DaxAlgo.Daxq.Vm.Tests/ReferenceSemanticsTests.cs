namespace DaxAlgo.Daxq.Vm.Tests;

public sealed class ReferenceSemanticsTests
{
    [Fact]
    public void Numeric_boolean_comparison_and_conversion_opcodes_follow_v1_semantics()
    {
        var builder = new DaxqTestContainerBuilder();
        var two = builder.AddInt64(2);
        var three = builder.AddInt64(3);
        var five = builder.AddInt64(5);
        var seven = builder.AddInt64(7);
        var six = builder.AddInt64(6);
        var one = builder.AddInt64(1);
        var negativeThree = builder.AddInt64(-3);
        var negativeFraction = builder.AddDouble(-3.75);
        var threeFloat = builder.AddDouble(3);
        var onePointFive = builder.AddDouble(1.5);
        var twoFloat = builder.AddDouble(2);
        var threePointFive = builder.AddDouble(3.5);
        var fourFloat = builder.AddDouble(4);
        var sevenPointFive = builder.AddDouble(7.5);
        var negativeOnePointFive = builder.AddDouble(-1.5);
        var zero = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, localCount: 1);

        CheckInteger(code, two, three, Opcode.ADD, five, Opcode.CEQ);
        CheckInteger(code, seven, two, Opcode.SUB, five, Opcode.CEQ); code.Op(Opcode.AND);
        CheckInteger(code, two, three, Opcode.MUL, six, Opcode.CEQ); code.Op(Opcode.AND);
        CheckInteger(code, six, two, Opcode.DIV, three, Opcode.CEQ); code.Op(Opcode.AND);
        CheckInteger(code, seven, three, Opcode.MOD, one, Opcode.CEQ); code.Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(three).Op(Opcode.NEG)
            .Op(Opcode.PUSH_I64).U16(negativeThree).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(two).Op(Opcode.PUSH_I64).U16(three)
            .Op(Opcode.CLT).Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(two).Op(Opcode.PUSH_I64).U16(two)
            .Op(Opcode.CLE).Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(three).Op(Opcode.PUSH_I64).U16(two)
            .Op(Opcode.CGT).Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(three).Op(Opcode.PUSH_I64).U16(three)
            .Op(Opcode.CGE).Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(two).Op(Opcode.PUSH_I64).U16(three)
            .Op(Opcode.CNE).Op(Opcode.AND);
        code.Op(Opcode.PUSH_BOOL).U8(0).Op(Opcode.PUSH_BOOL).U8(1)
            .Op(Opcode.OR).Op(Opcode.AND);
        code.Op(Opcode.PUSH_BOOL).U8(0).Op(Opcode.NOT).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(negativeFraction).Op(Opcode.F2I)
            .Op(Opcode.PUSH_I64).U16(negativeThree).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_I64).U16(three).Op(Opcode.I2F)
            .Op(Opcode.PUSH_F64).U16(threeFloat).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(onePointFive).Op(Opcode.PUSH_F64).U16(twoFloat)
            .Op(Opcode.ADD).Op(Opcode.PUSH_F64).U16(threePointFive).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(threePointFive).Op(Opcode.PUSH_F64).U16(onePointFive)
            .Op(Opcode.SUB).Op(Opcode.PUSH_F64).U16(twoFloat).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(twoFloat).Op(Opcode.PUSH_F64).U16(twoFloat)
            .Op(Opcode.MUL).Op(Opcode.PUSH_F64).U16(fourFloat).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(fourFloat).Op(Opcode.PUSH_F64).U16(twoFloat)
            .Op(Opcode.DIV).Op(Opcode.PUSH_F64).U16(twoFloat).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(sevenPointFive).Op(Opcode.PUSH_F64).U16(twoFloat)
            .Op(Opcode.MOD).Op(Opcode.PUSH_F64).U16(onePointFive).Op(Opcode.CEQ).Op(Opcode.AND);
        code.Op(Opcode.PUSH_F64).U16(onePointFive).Op(Opcode.NEG)
            .Op(Opcode.PUSH_F64).U16(negativeOnePointFive).Op(Opcode.CEQ).Op(Opcode.AND);

        var successBranch = code.Branch(Opcode.BRT);
        code.Op(Opcode.PUSH_I64).U16(one).Op(Opcode.PUSH_I64).U16(zero)
            .Op(Opcode.DIV).Op(Opcode.ST_LOC).U16(0).Op(Opcode.RET);
        var success = code.Mark();
        code.Op(Opcode.RET);
        code.PatchBranch(successBranch, success);

        var vm = CreateReference(builder);
        Assert.Equal(DaxqFault.Ok, vm.OnBar(0).Fault);
    }

    [Fact]
    public void Buffers_locals_state_and_lengths_are_typed_bounded_and_committed()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddState(DaxqValueType.I64);
        var one = builder.AddInt64(1);
        var fortyTwo = builder.AddInt64(42);
        var two = builder.AddInt64(2);
        var message = builder.AddInt64(9);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, localCount: 1);
        code.Op(Opcode.NEWBUF).U8((byte)DaxqValueType.I64).U16(2).Op(Opcode.ST_LOC).U16(0)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(one)
            .Op(Opcode.PUSH_I64).U16(fortyTwo).Op(Opcode.STELEM)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(one).Op(Opcode.LDELEM)
            .Op(Opcode.ST_STATE).U16(0)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.LEN)
            .Op(Opcode.PUSH_I64).U16(two).Op(Opcode.CEQ);
        var successBranch = code.Branch(Opcode.BRT);
        code.Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(two)
            .Op(Opcode.LDELEM).Op(Opcode.ST_STATE).U16(0).Op(Opcode.RET);
        var success = code.Mark();
        code.Op(Opcode.PUSH_I64).U16(message)
            .Op(Opcode.LD_STATE).U16(0).Op(Opcode.I2F)
            .Call(HostFn.Log, 2).Op(Opcode.RET);
        code.PatchBranch(successBranch, success);

        var vm = CreateReference(builder);
        var result = vm.OnBar(0);

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Equal(DaxqFault.Ok, vm.TryGetState(0, out var state));
        Assert.Equal(42, state.AsInt64());
        Assert.Equal(new DaxqLogRecord(9, 42), Assert.Single(vm.Logs.ToArray()));
    }

    [Fact]
    public void Bar_parameter_time_index_rng_and_log_host_surface_is_closed_and_numeric()
    {
        var builder = new DaxqTestContainerBuilder();
        var messageBar = builder.AddInt64(1);
        var fieldClose = builder.AddInt64(4);
        var lookback = builder.AddInt64(0);
        var messageParameter = builder.AddInt64(2);
        var parameter = builder.AddInt64(0);
        var messageIndex = builder.AddInt64(3);
        var messageRng = builder.AddInt64(4);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        code.Op(Opcode.PUSH_I64).U16(messageBar)
            .Op(Opcode.PUSH_I64).U16(fieldClose).Op(Opcode.PUSH_I64).U16(lookback)
            .Call(HostFn.Bar, 2).Call(HostFn.Log, 2)
            .Op(Opcode.PUSH_I64).U16(messageParameter)
            .Op(Opcode.PUSH_I64).U16(parameter).Call(HostFn.Param, 1).Call(HostFn.Log, 2)
            .Op(Opcode.PUSH_I64).U16(messageIndex).Call(HostFn.TIndex, 0).Op(Opcode.I2F)
            .Call(HostFn.Log, 2)
            .Op(Opcode.PUSH_I64).U16(messageRng).Call(HostFn.Rng, 0).Call(HostFn.Log, 2)
            .Op(Opcode.RET);

        var host = new FixedHost();
        var vm = CreateReference(builder, host, seed: 42);
        var result = vm.OnBar(1234);

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Collection(
            vm.Logs.ToArray(),
            item => Assert.Equal(new DaxqLogRecord(1, 101.25), item),
            item => Assert.Equal(new DaxqLogRecord(2, 0.5), item),
            item => Assert.Equal(new DaxqLogRecord(3, 1234), item),
            item =>
            {
                Assert.Equal(4, item.MessageId);
                Assert.InRange(item.Value, 0d, Math.BitDecrement(1d));
            });
    }

    [Fact]
    public void All_three_primitive_buffer_types_round_trip_values()
    {
        var builder = new DaxqTestContainerBuilder();
        var zero = builder.AddInt64(0);
        var floatValue = builder.AddDouble(1.25);
        var one = builder.AddInt64(1);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar, localCount: 3);
        code.Op(Opcode.NEWBUF).U8((byte)DaxqValueType.F64).U16(1).Op(Opcode.ST_LOC).U16(0)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(zero)
            .Op(Opcode.PUSH_F64).U16(floatValue).Op(Opcode.STELEM)
            .Op(Opcode.LD_LOC).U16(0).Op(Opcode.PUSH_I64).U16(zero).Op(Opcode.LDELEM)
            .Op(Opcode.PUSH_F64).U16(floatValue).Op(Opcode.CEQ)
            .Op(Opcode.NEWBUF).U8((byte)DaxqValueType.Bool).U16(1).Op(Opcode.ST_LOC).U16(1)
            .Op(Opcode.LD_LOC).U16(1).Op(Opcode.PUSH_I64).U16(zero)
            .Op(Opcode.PUSH_BOOL).U8(1).Op(Opcode.STELEM)
            .Op(Opcode.LD_LOC).U16(1).Op(Opcode.PUSH_I64).U16(zero).Op(Opcode.LDELEM)
            .Op(Opcode.AND);
        var successBranch = code.Branch(Opcode.BRT);
        code.Op(Opcode.PUSH_I64).U16(one).Op(Opcode.PUSH_I64).U16(zero)
            .Op(Opcode.DIV).Op(Opcode.ST_LOC).U16(2).Op(Opcode.RET);
        var success = code.Mark();
        code.Op(Opcode.RET);
        code.PatchBranch(successBranch, success);

        var vm = CreateReference(builder);
        Assert.Equal(DaxqFault.Ok, vm.OnBar(0).Fault);
    }

    [Fact]
    public void Failed_callback_rolls_back_state_rng_emits_and_logs()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.AddState(DaxqValueType.I64);
        var zero = builder.AddInt64(0);
        var stateValue = builder.AddInt64(99);
        var message = builder.AddInt64(7);
        var kind = builder.AddInt64(1);
        var strength = builder.AddDouble(1);
        var note = builder.AddInt64(0);
        var one = builder.AddInt64(1);
        var messageState = builder.AddInt64(8);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        code.Op(Opcode.LD_ARG).U16(0).Op(Opcode.PUSH_I64).U16(zero).Op(Opcode.CEQ);
        var successBranch = code.Branch(Opcode.BRF);
        code.Op(Opcode.PUSH_I64).U16(stateValue).Op(Opcode.ST_STATE).U16(0)
            .Op(Opcode.PUSH_I64).U16(message).Call(HostFn.Rng, 0).Call(HostFn.Log, 2)
            .Op(Opcode.PUSH_I64).U16(kind).Op(Opcode.PUSH_F64).U16(strength)
            .Op(Opcode.PUSH_I64).U16(note).Call(HostFn.Emit, 3)
            .Op(Opcode.PUSH_I64).U16(one).Op(Opcode.PUSH_I64).U16(zero).Op(Opcode.DIV)
            .Op(Opcode.ST_STATE).U16(0).Op(Opcode.RET);
        var success = code.Mark();
        code.Op(Opcode.PUSH_I64).U16(message).Call(HostFn.Rng, 0).Call(HostFn.Log, 2)
            .Op(Opcode.PUSH_I64).U16(messageState).Op(Opcode.LD_STATE).U16(0).Op(Opcode.I2F)
            .Call(HostFn.Log, 2)
            .Op(Opcode.RET);
        code.PatchBranch(successBranch, success);

        var program = Load(builder);
        var vm = new DaxqReferenceVm(program, DaxqNullHost.Instance, 12345);
        var fresh = new DaxqReferenceVm(program, DaxqNullHost.Instance, 12345);

        Assert.Equal(DaxqFault.DivideByZero, vm.OnBar(0).Fault);
        Assert.Empty(vm.EmittedSignals.ToArray());
        Assert.Empty(vm.Logs.ToArray());
        Assert.Equal(DaxqFault.Ok, vm.TryGetState(0, out var state));
        Assert.Equal(0, state.AsInt64());

        Assert.Equal(DaxqFault.Ok, vm.OnBar(1).Fault);
        Assert.Equal(DaxqFault.Ok, fresh.OnBar(1).Fault);
        Assert.Equal(fresh.Logs.ToArray(), vm.Logs.ToArray());
        Assert.Equal(new DaxqLogRecord(8, 0), vm.Logs[1]);

        var library = NativeTestSupport.FindLibrary();
        if (library is null)
            return;
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        Assert.Equal(
            DaxqFault.Ok,
            DaxqNativeVm.TryCreate(program, DaxqNullHost.Instance, 12345, out var native));
        using (native)
        {
            Assert.Equal(DaxqFault.DivideByZero, native!.OnBar(0).Fault);
            Assert.Empty(native.EmittedSignals.ToArray());
            Assert.Empty(native.Logs.ToArray());

            Assert.Equal(DaxqFault.Ok, native.OnBar(1).Fault);
            Assert.Equal(fresh.Logs.ToArray(), native.Logs.ToArray());
            Assert.Equal(new DaxqLogRecord(8, 0), native.Logs[1]);
        }
    }

    [Fact]
    public void Initialize_commits_only_once()
    {
        var builder = new DaxqTestContainerBuilder();
        var message = builder.AddInt64(1);
        var initialize = builder.AddEntrypoint(DaxqEntrypoint.Initialize);
        initialize.Op(Opcode.PUSH_I64).U16(message).Call(HostFn.TIndex, 0).Op(Opcode.I2F)
            .Call(HostFn.Log, 2).Op(Opcode.RET);
        builder.AddEntrypoint(DaxqEntrypoint.OnBar).Op(Opcode.RET);
        var vm = CreateReference(builder);

        Assert.Equal(DaxqFault.Ok, vm.OnBar(99).Fault);
        Assert.Equal(DaxqFault.Ok, vm.Initialize().Fault);
        Assert.Equal(0d, Assert.Single(vm.Logs.ToArray()).Value);
        Assert.Equal(DaxqFault.InvalidLifecycle, vm.Initialize().Fault);
    }

    private static void CheckInteger(
        DaxqTestContainerBuilder.BytecodeBuilder code,
        ushort left,
        ushort right,
        Opcode arithmetic,
        ushort expected,
        Opcode comparison)
    {
        code.Op(Opcode.PUSH_I64).U16(left)
            .Op(Opcode.PUSH_I64).U16(right)
            .Op(arithmetic)
            .Op(Opcode.PUSH_I64).U16(expected)
            .Op(comparison);
    }

    private static DaxqReferenceVm CreateReference(
        DaxqTestContainerBuilder builder,
        IDaxqHost? host = null,
        ulong seed = 1) => new(Load(builder), host ?? DaxqNullHost.Instance, seed);

    private static DaxqProgram Load(DaxqTestContainerBuilder builder)
    {
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        return program!;
    }

    private sealed class FixedHost : IDaxqHost
    {
        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            value = 101.25;
            return field == 4 && lookback == 0 ? DaxqFault.Ok : DaxqFault.Host;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0.5;
            return parameterId == 0 ? DaxqFault.Ok : DaxqFault.Host;
        }
    }
}
