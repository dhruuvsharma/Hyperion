using System.Text.Json;
using Xunit.Abstractions;

namespace DaxAlgo.Daxq.Vm.Tests;

public sealed class GoldenVectorTests
{
    private readonly ITestOutputHelper _output;

    public GoldenVectorTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Theory]
    [InlineData(13d, 12d, 1, 1)]
    [InlineData(11d, 12d, -1, 1)]
    [InlineData(12d, 12d, 0, 0)]
    public void Golden_ema_cross_executes_long_short_and_flat_paths(
        double fast,
        double slow,
        long expectedKind,
        int expectedCount)
    {
        var program = LoadGoldenProgram();
        var vm = new DaxqReferenceVm(program, new EmaHost(fast, slow), launchSeed: 123);

        var result = vm.OnBar(41);

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Equal(expectedCount, result.SignalCount);
        Assert.Equal(expectedCount, vm.EmittedSignals.Length);
        if (expectedCount != 0)
        {
            Assert.Equal(expectedKind, vm.EmittedSignals[0].Kind);
            Assert.Equal(1d, vm.EmittedSignals[0].Strength);
            Assert.Equal(0, vm.EmittedSignals[0].NoteId);
        }
    }

    [Fact]
    public void Diversified_opcode_and_host_maps_execute_canonical_semantics()
    {
        var builder = new DaxqTestContainerBuilder();
        builder.SwapOpcodeEncoding(Opcode.PUSH_I64, Opcode.PUSH_F64);
        builder.SwapHostEncoding(HostFn.Param, HostFn.Bar);
        var message = builder.AddInt64(7);
        var parameter = builder.AddInt64(0);
        var code = builder.AddEntrypoint(DaxqEntrypoint.OnBar);
        code.Op(Opcode.PUSH_I64).U16(message)
            .Op(Opcode.PUSH_I64).U16(parameter)
            .Call(HostFn.Param, 1)
            .Call(HostFn.Log, 2)
            .Op(Opcode.RET);

        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(builder.Build(), out var program));
        var vm = new DaxqReferenceVm(program!, new ParameterHost(0.75), launchSeed: 1);
        var result = vm.OnBar(0);

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Equal(new DaxqLogRecord(7, 0.75), Assert.Single(vm.Logs.ToArray()));
    }

    [Theory]
    [InlineData(13d, 12d)]
    [InlineData(11d, 12d)]
    [InlineData(12d, 12d)]
    public void Native_VM_matches_all_golden_signal_paths_when_the_built_DLL_is_available(
        double fast,
        double slow)
    {
        var library = NativeTestSupport.FindLibrary();
        if (library is null)
        {
            _output.WriteLine("Native parity not run: daxq_vm DLL was not found in the focused CMake build outputs.");
            return;
        }

        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.ConfigureNativeLibrary(library));
        var program = LoadGoldenProgram();
        var host = new EmaHost(fast, slow);
        var reference = new DaxqReferenceVm(program, host, launchSeed: 456);
        Assert.Equal(DaxqFault.Ok, DaxqNativeVm.TryCreate(program, host, 456, out var native));
        using (native)
        {
            var referenceResult = reference.OnBar(15);
            var nativeResult = native!.OnBar(15);
            Assert.Equal(referenceResult.Fault, nativeResult.Fault);
            Assert.Equal(reference.EmittedSignals.ToArray(), native.EmittedSignals.ToArray());
            Assert.Equal(reference.Logs.ToArray(), native.Logs.ToArray());
        }
    }

    private static DaxqProgram LoadGoldenProgram()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "ema-cross-v1.vector.json")));
        var plaintext = Convert.FromHexString(
            document.RootElement.GetProperty("canonicalPlaintextHex").GetString()!);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(plaintext, out var program));
        return program!;
    }

    private sealed class EmaHost : IDaxqHost
    {
        private readonly double _fast;
        private readonly double _slow;

        public EmaHost(double fast, double slow)
        {
            _fast = fast;
            _slow = slow;
        }

        public DaxqFault ReadBar(long field, long lookback, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }

        public DaxqFault ReadIndicator(long indicator, long period, long sourceField, out double value)
        {
            Assert.Equal(1, indicator);
            Assert.Equal(4, sourceField);
            value = period switch
            {
                12 => _fast,
                26 => _slow,
                _ => double.NaN,
            };
            return period is 12 or 26 ? DaxqFault.Ok : DaxqFault.Host;
        }

        public DaxqFault ReadParameter(long parameterId, out double value)
        {
            value = 0;
            return DaxqFault.Host;
        }
    }

    private sealed class ParameterHost : IDaxqHost
    {
        private readonly double _value;

        public ParameterHost(double value)
        {
            _value = value;
        }

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
            value = _value;
            return parameterId == 0 ? DaxqFault.Ok : DaxqFault.Host;
        }
    }
}
