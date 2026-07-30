using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using DaxAlgo.Sdk;

namespace DaxAlgo.Daxq.Compiler.Tests;

public sealed class CompilerParityTests
{
    private const string EmaCrossSource = """
        using DaxAlgo.Sdk;

        public sealed class EmaCross : IBacktestStrategy
        {
            public void OnBar(IStrategyContext context)
            {
                double fast = context.Indicator(Ind.Ema, 3, BarField.Close);
                double slow = context.Indicator(Ind.Ema, 5, BarField.Close);
                if (fast > slow)
                    context.Emit(SignalKind.Long, 1.0, 0);
                else if (fast < slow)
                    context.Emit(SignalKind.Short, 0.75, 0);
            }
        }
        """;

    private const string StatefulBreakoutSource = """
        using DaxAlgo.Sdk;

        public sealed class StatefulBreakout : IBacktestStrategy
        {
            private double _previous;
            private double _threshold;
            private bool _hasPrevious;

            public void Initialize(IStrategyContext context)
            {
                _threshold = context.Param(0);
            }

            public void OnBar(IStrategyContext context)
            {
                double current = context.Bar(BarField.Close, 0);
                if (_hasPrevious && current > _previous + _threshold)
                    context.Emit(SignalKind.Long, 0.5, 0);
                _previous = current;
                _hasPrevious = true;
            }
        }
        """;

    private const string TickDeterminismSource = """
        using DaxAlgo.Sdk;

        public sealed class TickDeterminism : IBacktestStrategy
        {
            public void OnTick(
                IStrategyContext context,
                double bid,
                double ask,
                double last,
                double volume)
            {
                long index = context.TimeIndex();
                double sample = context.Random();
                context.Log(7, sample);
                if (index >= 3 && bid < ask)
                    context.Emit(SignalKind.Long, sample, 0);
            }
        }
        """;

    [Fact]
    public void Ema_cross_managed_execution_matches_reference_VM_exactly()
    {
        var bars = Enumerable.Range(1, 12)
            .Select(index => new DaxqBar(index, index + 2, index - 1, index, index * 10))
            .ToArray();
        AssertParity(EmaCrossSource, bars, ReadOnlyMemory<double>.Empty, firstBar: 4);
    }

    [Fact]
    public void Scalar_state_bar_and_parameter_strategy_matches_reference_VM_exactly()
    {
        DaxqBar[] bars =
        [
            new(10, 11, 9, 10, 100),
            new(10, 12, 9, 11, 110),
            new(11, 13, 10, 12.5, 120),
            new(12, 13, 11, 12.75, 130),
            new(12, 15, 11, 14.5, 140),
        ];
        AssertParity(StatefulBreakoutSource, bars, new double[] { 1.0 }, firstBar: 0);
    }

    [Fact]
    public void Same_source_has_byte_identical_pre_diversification_output()
    {
        var compiler = new DaxqRoslynCompiler();
        var first = compiler.CompileAndLower(EmaCrossSource);
        var second = compiler.CompileAndLower(EmaCrossSource);

        Assert.Equal(first.Program.Bytecode, second.Program.Bytecode);
        Assert.Equal(
            DaxqPlaintextBuilder.BuildCanonical(first.Program).PreDiversificationPlaintext,
            DaxqPlaintextBuilder.BuildCanonical(second.Program).PreDiversificationPlaintext);
    }

    [Fact]
    public void OnTick_time_index_rng_and_log_match_reference_VM_exactly()
    {
        const ulong launchSeed = 0x5eed;
        var contentKey = Enumerable.Repeat((byte)0x31, 32).ToArray();
        var nonce = Enumerable.Range(1, 12).Select(index => (byte)index).ToArray();
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var artifact = new DaxqCompiler().Compile(TickDeterminismSource, new DaxqCompilerOptions
        {
            StrategyId = "example.tick-determinism",
            Version = "1.0.0",
            DataRequirements = ["ticks"],
            DiversificationSeed = Enumerable.Repeat((byte)0xc3, 32).ToArray(),
            ContentKeyId = "dev:example.tick-determinism:1.0.0",
            ContentKey = contentKey,
            Nonce = nonce,
            ReleaseKeyId = "dev-parity-p256-v1",
            ReleaseSigningKey = signingKey,
        });
        var package = DaxqPackageTestReader.ReadVerifyAndDecrypt(
            artifact.Package.PackageBytes,
            contentKey,
            signingKey);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(package.PlaintextBytes, out var program));

        DaxqBar[] bars = [new(1, 1, 1, 1, 1)];
        var host = new DaxqSdkAbi3FrameHost(bars, ReadOnlyMemory<double>.Empty, 0);
        var managed = CreateManagedStrategy(artifact.Lowering.ManagedAssembly);
        var managedContext = new ManagedContext(host, launchSeed);
        var vm = new DaxqReferenceVm(program!, host, launchSeed);
        var ticks = new[]
        {
            (Index: 2L, Bid: 100d, Ask: 101d, Last: 100.5d, Volume: 1d),
            (Index: 3L, Bid: 101d, Ask: 102d, Last: 101.5d, Volume: 2d),
            (Index: 4L, Bid: 103d, Ask: 102d, Last: 102.5d, Volume: 3d),
        };
        foreach (var tick in ticks)
        {
            managedContext.CurrentIndex = tick.Index;
            managedContext.BeginCallback();
            managed.OnTick(
                managedContext,
                tick.Bid,
                tick.Ask,
                tick.Last,
                tick.Volume);

            var result = vm.OnTick(
                tick.Index,
                tick.Bid,
                tick.Ask,
                tick.Last,
                tick.Volume);

            Assert.Equal(DaxqFault.Ok, result.Fault);
            Assert.Equal(managedContext.Signals, vm.EmittedSignals.ToArray());
            Assert.Equal(managedContext.Logs, vm.Logs.ToArray());
        }
    }

    private static void AssertParity(
        string source,
        DaxqBar[] bars,
        ReadOnlyMemory<double> parameters,
        int firstBar)
    {
        var contentKey = Enumerable.Range(1, 32).Select(index => (byte)index).ToArray();
        var nonce = Enumerable.Range(1, 12).Select(index => (byte)(index + 32)).ToArray();
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameterManifest = parameters.ToArray()
            .Select((value, index) => new DaxqParameterManifest
            {
                Id = $"p{index}",
                Type = "float",
                Default = JsonSerializer.SerializeToElement(value),
            })
            .ToArray();
        var artifact = new DaxqCompiler().Compile(source, new DaxqCompilerOptions
        {
            StrategyId = "example.parity-strategy",
            Version = "1.0.0",
            DataRequirements = ["bars"],
            Parameters = parameterManifest,
            DiversificationSeed = Enumerable.Repeat((byte)0xa5, 32).ToArray(),
            ContentKeyId = "dev:example.parity-strategy:1.0.0",
            ContentKey = contentKey,
            Nonce = nonce,
            ReleaseKeyId = "dev-parity-p256-v1",
            ReleaseSigningKey = signingKey,
        });
        var lowering = artifact.Lowering;
        var package = DaxqPackageTestReader.ReadVerifyAndDecrypt(
            artifact.Package.PackageBytes,
            contentKey,
            signingKey);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(package.PlaintextBytes, out var program));

        var packagedParameters = package.Manifest.Parameters
            .Select(parameter => parameter.Default.GetDouble())
            .ToArray();

        var managed = CreateManagedStrategy(lowering.ManagedAssembly);
        var frameHost = new DaxqSdkAbi3FrameHost(bars, packagedParameters, firstBar);
        var managedContext = new ManagedContext(frameHost, 0x5eed);
        var vm = new DaxqReferenceVm(program!, frameHost, launchSeed: 0x5eed);

        managed.Initialize(managedContext);
        if (program!.HasEntrypoint(DaxqEntrypoint.Initialize))
            Assert.Equal(DaxqFault.Ok, vm.Initialize().Fault);

        for (var index = firstBar; index < bars.Length; index++)
        {
            frameHost.CurrentCompletedBarIndex = index;
            managedContext.CurrentIndex = index;
            managedContext.BeginCallback();
            managed.OnBar(managedContext);
            var managedSignals = managedContext.Signals.ToArray();

            var result = vm.OnBar(index);
            Assert.Equal(DaxqFault.Ok, result.Fault);
            Assert.Equal(managedSignals, vm.EmittedSignals.ToArray());
        }
    }

    private static IBacktestStrategy CreateManagedStrategy(byte[] assemblyImage)
    {
        var assembly = Assembly.Load(assemblyImage);
        var strategyType = Assert.Single(assembly.GetTypes(), type =>
            type is { IsClass: true, IsAbstract: false } &&
            typeof(IBacktestStrategy).IsAssignableFrom(type));
        return (IBacktestStrategy)Activator.CreateInstance(strategyType)!;
    }

    private sealed class ManagedContext : IStrategyContext
    {
        private readonly DaxqSdkAbi3FrameHost _host;
        private readonly List<DaxqSignal> _signals = [];
        private readonly List<DaxqLogRecord> _logs = [];
        private TestRng _rng;

        public ManagedContext(DaxqSdkAbi3FrameHost host, ulong launchSeed)
        {
            _host = host;
            _rng = TestRng.Create(launchSeed);
        }

        public IReadOnlyList<DaxqSignal> Signals => _signals;

        public IReadOnlyList<DaxqLogRecord> Logs => _logs;

        public long CurrentIndex { get; set; }

        public void BeginCallback()
        {
            _signals.Clear();
            _logs.Clear();
        }

        public double Indicator(Ind indicator, long period, BarField sourceField = BarField.Close)
        {
            Require(_host.ReadIndicator((long)indicator, period, (long)sourceField, out var value));
            return value;
        }

        public void Emit(SignalKind kind, double strength, long noteId = 0) =>
            _signals.Add(new DaxqSignal((long)kind, strength, noteId));

        public double Param(long parameterId)
        {
            Require(_host.ReadParameter(parameterId, out var value));
            return value;
        }

        public double Bar(BarField field, long lookback = 0)
        {
            Require(_host.ReadBar((long)field, lookback, out var value));
            return value;
        }

        public long TimeIndex() => CurrentIndex;

        public double Random() => _rng.NextDouble();

        public void Log(long messageId, double value) =>
            _logs.Add(new DaxqLogRecord(messageId, value));

        private static void Require(DaxqFault fault)
        {
            if (fault != DaxqFault.Ok)
                throw new InvalidOperationException($"Managed host fault: {fault}.");
        }

        private struct TestRng
        {
            private ulong _s0;
            private ulong _s1;
            private ulong _s2;
            private ulong _s3;

            public static TestRng Create(ulong seed)
            {
                var state = seed;
                return new TestRng
                {
                    _s0 = SplitMix64(ref state),
                    _s1 = SplitMix64(ref state),
                    _s2 = SplitMix64(ref state),
                    _s3 = SplitMix64(ref state),
                };
            }

            public double NextDouble() =>
                (NextUInt64() >> 11) * (1d / 9_007_199_254_740_992d);

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
    }
}
