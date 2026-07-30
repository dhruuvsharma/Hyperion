using System.Globalization;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using DaxAlgo.Daxq.Vm;
using DaxAlgo.Sdk;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>Server-only publication gate comparing a reviewed managed build with released DAXQ.</summary>
public sealed class DaxqBacktestParityGate
{
    private const int MaximumSignalsPerCallback = 8;
    private const int MaximumLogsPerCallback = 16;

    /// <summary>Runs the exact managed image and packaged plaintext produced by one compilation.</summary>
    public DaxqBacktestParityResult Evaluate(
        DaxqCompilationArtifact artifact,
        DaxqBacktestReferenceData referenceData,
        DaxqParityTolerance? tolerance = null)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        return EvaluateCore(
            artifact.Lowering.ManagedAssembly,
            artifact.Package.PlaintextBytes,
            referenceData,
            tolerance ?? new DaxqParityTolerance());
    }

    private static DaxqBacktestParityResult EvaluateCore(
        byte[] managedAssembly,
        byte[] daxqPlaintext,
        DaxqBacktestReferenceData referenceData,
        DaxqParityTolerance tolerance)
    {
        ArgumentNullException.ThrowIfNull(managedAssembly);
        ArgumentNullException.ThrowIfNull(daxqPlaintext);
        ArgumentNullException.ThrowIfNull(referenceData);
        ArgumentNullException.ThrowIfNull(tolerance);
        if (managedAssembly.Length == 0)
            throw new ArgumentException("The seller managed assembly must not be empty.", nameof(managedAssembly));
        if (daxqPlaintext.Length == 0)
            throw new ArgumentException("The DQXP plaintext must not be empty.", nameof(daxqPlaintext));

        var allowedDifference = tolerance.MaximumAbsoluteSignalStrengthDifference;
        if (!double.IsFinite(allowedDifference) || allowedDifference < 0d)
        {
            throw new ArgumentOutOfRangeException(
                nameof(tolerance),
                "The signal-strength tolerance must be finite and nonnegative.");
        }

        var data = ReferenceDataSnapshot.Create(referenceData);
        var loadFault = DaxqProgram.TryLoad(daxqPlaintext, out var program);
        if (loadFault != DaxqFault.Ok)
        {
            return Block(new DaxqParityDiagnostic(
                "DAXQ3001",
                $"The packaged DQXP plaintext could not be loaded by the reference interpreter: {loadFault}."));
        }

        var coverageDiagnostic = ValidateCoverage(program!, data.Callbacks);
        if (coverageDiagnostic is not null)
            return Block(coverageDiagnostic);

        ManagedStrategyHandle managed;
        try
        {
            managed = CreateManagedStrategy(managedAssembly);
        }
        catch (Exception exception) when (exception is BadImageFormatException or FileLoadException or
                                            ReflectionTypeLoadException or InvalidOperationException or
                                            MissingMethodException or TargetInvocationException)
        {
            return Block(new DaxqParityDiagnostic(
                "DAXQ3002",
                $"The reviewed seller build could not be instantiated: {exception.Message}"));
        }
        using (managed)
        {
            var entrypointDiagnostic = ValidateEntrypoints(program!, managed.Entrypoints);
            if (entrypointDiagnostic is not null)
                return Block(entrypointDiagnostic);

            var managedStrategy = managed.Strategy;
            var managedHost = new DaxqSdkAbi3FrameHost(data.Bars, data.Parameters);
            var vmHost = new DaxqSdkAbi3FrameHost(data.Bars, data.Parameters);
            var managedContext = new ManagedParityContext(managedHost, data.LaunchSeed);
            var vm = new DaxqReferenceVm(program!, vmHost, data.LaunchSeed);
            var statistics = new StatisticsAccumulator();
            var listingMetrics = new DaxqListingMetricsAccumulator();

            managedContext.BeginCallback(0);
            DaxqInvocationResult? initializeResult = null;
            if (program!.HasEntrypoint(DaxqEntrypoint.Initialize))
            {
                initializeResult = vm.Initialize();
                if (!initializeResult.Value.Succeeded)
                    return VmFailure("Initialize", null, initializeResult.Value);
            }
            try
            {
                managedStrategy.Initialize(managedContext);
            }
            catch (Exception exception)
            {
                return ManagedFailure("Initialize", null, exception);
            }

            if (initializeResult is { } completedInitialization)
            {
                var comparison = CompareSignals(
                    managedContext.Signals,
                    vm.EmittedSignals,
                    allowedDifference,
                    "Initialize",
                    null);
                if (comparison is not null)
                    return Block(comparison);
                statistics.Observe(DaxqEntrypoint.Initialize, completedInitialization, vm.EmittedSignals);
                listingMetrics.ObserveSignals(vm.EmittedSignals);
            }
            else if (managedContext.Signals.Count != 0)
            {
                return Block(new DaxqParityDiagnostic(
                    "DAXQ3005",
                    "The managed Initialize callback emitted signals but the DAXQ release has no Initialize entrypoint."));
            }

            for (var callbackOrdinal = 0; callbackOrdinal < data.Callbacks.Length; callbackOrdinal++)
            {
                var callback = data.Callbacks[callbackOrdinal];
                managedHost.CurrentCompletedBarIndex = callback.CompletedBarIndex;
                vmHost.CurrentCompletedBarIndex = callback.CompletedBarIndex;
                listingMetrics.BeginCallback(data.ReferencePrices[callbackOrdinal]);
                managedContext.BeginCallback(callback.TimeIndex);

                var result = callback.Entrypoint == DaxqEntrypoint.OnBar
                    ? vm.OnBar(callback.TimeIndex)
                    : vm.OnTick(
                        callback.TimeIndex,
                        callback.Bid,
                        callback.Ask,
                        callback.Last,
                        callback.Volume);
                if (!result.Succeeded)
                    return VmFailure(Describe(callback), callbackOrdinal, result);

                try
                {
                    if (callback.Entrypoint == DaxqEntrypoint.OnBar)
                    {
                        managedStrategy.OnBar(managedContext);
                    }
                    else
                    {
                        managedStrategy.OnTick(
                            managedContext,
                            callback.Bid,
                            callback.Ask,
                            callback.Last,
                            callback.Volume);
                    }
                }
                catch (Exception exception)
                {
                    return ManagedFailure(Describe(callback), callbackOrdinal, exception);
                }

                var comparison = CompareSignals(
                    managedContext.Signals,
                    vm.EmittedSignals,
                    allowedDifference,
                    Describe(callback),
                    callbackOrdinal);
                if (comparison is not null)
                    return Block(comparison);

                statistics.Observe(callback.Entrypoint, result, vm.EmittedSignals);
                listingMetrics.ObserveSignals(vm.EmittedSignals);
            }

            var canonicalStatistics = statistics.Build();
            var canonicalStatisticsJson = DaxqBacktestStatisticsJson.Write(canonicalStatistics);
            var canonicalListingMetrics = listingMetrics.Complete(data.ReferencePrices[^1]);
            var canonicalListingMetricsJson = DaxqListingMetricsJson.Write(canonicalListingMetrics);
            return new DaxqBacktestParityResult(
                DaxqPublicationDecision.Pass,
                canonicalStatistics,
                canonicalStatisticsJson,
                Convert.ToHexStringLower(SHA256.HashData(canonicalStatisticsJson)),
                Array.Empty<DaxqParityDiagnostic>())
            {
                ListingMetrics = canonicalListingMetrics,
                CanonicalListingMetricsJson = canonicalListingMetricsJson,
                ListingMetricsSha256 = Convert.ToHexStringLower(SHA256.HashData(canonicalListingMetricsJson)),
            };
        }
    }

    private static ManagedStrategyHandle CreateManagedStrategy(byte[] assemblyImage)
    {
        var loadContext = new SellerAssemblyLoadContext();
        try
        {
            using var stream = new MemoryStream(assemblyImage, writable: false);
            var assembly = loadContext.LoadFromStream(stream);
            var strategyTypes = assembly.GetTypes()
                .Where(type => type is { IsClass: true, IsAbstract: false } &&
                               typeof(IBacktestStrategy).IsAssignableFrom(type))
                .ToArray();
            if (strategyTypes.Length != 1)
            {
                throw new InvalidOperationException(
                    $"Expected exactly one concrete {nameof(IBacktestStrategy)} but found {strategyTypes.Length}.");
            }
            var strategyType = strategyTypes[0];
            var strategy = (IBacktestStrategy)(Activator.CreateInstance(strategyType) ??
                throw new MissingMethodException(strategyType.FullName, ".ctor()"));
            return new ManagedStrategyHandle(
                loadContext,
                strategy,
                GetImplementedEntrypoints(strategyType));
        }
        catch
        {
            loadContext.Unload();
            throw;
        }
    }

    private static IReadOnlySet<DaxqEntrypoint> GetImplementedEntrypoints(Type strategyType)
    {
        var map = strategyType.GetInterfaceMap(typeof(IBacktestStrategy));
        var result = new HashSet<DaxqEntrypoint>();
        for (var index = 0; index < map.InterfaceMethods.Length; index++)
        {
            if (map.TargetMethods[index].DeclaringType == typeof(IBacktestStrategy))
                continue;
            result.Add(map.InterfaceMethods[index].Name switch
            {
                nameof(IBacktestStrategy.Initialize) => DaxqEntrypoint.Initialize,
                nameof(IBacktestStrategy.OnBar) => DaxqEntrypoint.OnBar,
                nameof(IBacktestStrategy.OnTick) => DaxqEntrypoint.OnTick,
                _ => throw new InvalidOperationException("The managed strategy implements an unknown callback."),
            });
        }
        return result;
    }

    private static DaxqParityDiagnostic? ValidateEntrypoints(
        DaxqProgram program,
        IReadOnlySet<DaxqEntrypoint> managedEntrypoints)
    {
        foreach (var entrypoint in Enum.GetValues<DaxqEntrypoint>())
        {
            if (program.HasEntrypoint(entrypoint) != managedEntrypoints.Contains(entrypoint))
            {
                return new DaxqParityDiagnostic(
                    "DAXQ3003",
                    $"Managed and packaged callback surfaces differ for {entrypoint}.");
            }
        }
        return null;
    }

    private static DaxqParityDiagnostic? ValidateCoverage(
        DaxqProgram program,
        IReadOnlyList<DaxqBacktestCallback> callbacks)
    {
        foreach (var entrypoint in new[] { DaxqEntrypoint.OnBar, DaxqEntrypoint.OnTick })
        {
            var implemented = program.HasEntrypoint(entrypoint);
            var covered = callbacks.Any(callback => callback.Entrypoint == entrypoint);
            if (implemented && !covered)
            {
                return new DaxqParityDiagnostic(
                    "DAXQ3003",
                    $"The reference dataset does not exercise the packaged {entrypoint} entrypoint.");
            }
            if (!implemented && covered)
            {
                return new DaxqParityDiagnostic(
                    "DAXQ3003",
                    $"The reference dataset invokes {entrypoint}, which the packaged strategy does not implement.");
            }
        }
        return null;
    }

    private static DaxqParityDiagnostic? CompareSignals(
        IReadOnlyList<DaxqSignal> managed,
        ReadOnlySpan<DaxqSignal> interpreted,
        double allowedDifference,
        string callback,
        int? callbackOrdinal)
    {
        if (managed.Count != interpreted.Length)
        {
            return new DaxqParityDiagnostic(
                "DAXQ3005",
                $"Signal-count divergence at {callback}: managed emitted {managed.Count}, " +
                $"DAXQ emitted {interpreted.Length}.",
                callbackOrdinal);
        }

        for (var signalOrdinal = 0; signalOrdinal < managed.Count; signalOrdinal++)
        {
            var managedSignal = managed[signalOrdinal];
            var interpretedSignal = interpreted[signalOrdinal];
            if (managedSignal.Kind != interpretedSignal.Kind)
            {
                return new DaxqParityDiagnostic(
                    "DAXQ3006",
                    $"Signal-kind divergence at {callback}, signal {signalOrdinal}: " +
                    $"managed={managedSignal.Kind}, DAXQ={interpretedSignal.Kind}.",
                    callbackOrdinal,
                    signalOrdinal);
            }
            if (managedSignal.NoteId != interpretedSignal.NoteId)
            {
                return new DaxqParityDiagnostic(
                    "DAXQ3006",
                    $"Signal-note divergence at {callback}, signal {signalOrdinal}: " +
                    $"managed={managedSignal.NoteId}, DAXQ={interpretedSignal.NoteId}.",
                    callbackOrdinal,
                    signalOrdinal);
            }

            var difference = Math.Abs(managedSignal.Strength - interpretedSignal.Strength);
            if (!double.IsFinite(difference) || difference > allowedDifference)
            {
                return new DaxqParityDiagnostic(
                    "DAXQ3007",
                    $"Signal-strength divergence at {callback}, signal {signalOrdinal}: " +
                    $"managed={Format(managedSignal.Strength)}, DAXQ={Format(interpretedSignal.Strength)}, " +
                    $"absoluteDifference={Format(difference)}, tolerance={Format(allowedDifference)}.",
                    callbackOrdinal,
                    signalOrdinal);
            }
        }
        return null;
    }

    private static DaxqBacktestParityResult ManagedFailure(
        string callback,
        int? callbackOrdinal,
        Exception exception) =>
        Block(new DaxqParityDiagnostic(
            "DAXQ3004",
            $"The reviewed managed build failed at {callback}: {exception.Message}",
            callbackOrdinal));

    private static DaxqBacktestParityResult VmFailure(
        string callback,
        int? callbackOrdinal,
        DaxqInvocationResult result) =>
        Block(result.Fault == DaxqFault.Timeout
            ? new DaxqParityDiagnostic(
                "DAXQ3008",
                $"The reference VM watchdog timed out at {callback}; retry the parity run before publication.",
                callbackOrdinal,
                Retryable: true)
            : new DaxqParityDiagnostic(
                "DAXQ3004",
                $"The packaged DAXQ release faulted at {callback}: {result.Fault} " +
                $"after {result.ExecutedInstructions} instructions.",
                callbackOrdinal));

    private static DaxqBacktestParityResult Block(DaxqParityDiagnostic diagnostic) =>
        new(
            DaxqPublicationDecision.Block,
            null,
            null,
            null,
            [diagnostic]);

    private static string Describe(DaxqBacktestCallback callback) =>
        $"{callback.Entrypoint} timeIndex={callback.TimeIndex}";

    private static string Format(double value) => value.ToString("R", CultureInfo.InvariantCulture);

    private sealed class ManagedStrategyHandle : IDisposable
    {
        private SellerAssemblyLoadContext? _loadContext;

        public ManagedStrategyHandle(
            SellerAssemblyLoadContext loadContext,
            IBacktestStrategy strategy,
            IReadOnlySet<DaxqEntrypoint> entrypoints)
        {
            _loadContext = loadContext;
            Strategy = strategy;
            Entrypoints = entrypoints;
        }

        public IBacktestStrategy Strategy { get; private set; }

        public IReadOnlySet<DaxqEntrypoint> Entrypoints { get; }

        public void Dispose()
        {
            Strategy = null!;
            Interlocked.Exchange(ref _loadContext, null)?.Unload();
        }
    }

    private sealed class SellerAssemblyLoadContext : AssemblyLoadContext
    {
        public SellerAssemblyLoadContext()
            : base(isCollectible: true)
        {
        }

        protected override Assembly? Load(AssemblyName assemblyName) =>
            Default.Assemblies.FirstOrDefault(
                assembly => AssemblyName.ReferenceMatchesDefinition(assembly.GetName(), assemblyName));
    }

    private sealed class ManagedParityContext : IStrategyContext
    {
        private readonly DaxqSdkAbi3FrameHost _host;
        private readonly List<DaxqSignal> _signals = [];
        private readonly List<DaxqLogRecord> _logs = [];
        private ParityRng _rng;
        private long _timeIndex;

        public ManagedParityContext(DaxqSdkAbi3FrameHost host, ulong launchSeed)
        {
            _host = host;
            _rng = ParityRng.Create(launchSeed);
        }

        public IReadOnlyList<DaxqSignal> Signals => _signals;

        public void BeginCallback(long timeIndex)
        {
            _timeIndex = timeIndex;
            _signals.Clear();
            _logs.Clear();
        }

        public double Indicator(Ind indicator, long period, BarField sourceField = BarField.Close)
        {
            Require(_host.ReadIndicator((long)indicator, period, (long)sourceField, out var value));
            return value;
        }

        public void Emit(SignalKind kind, double strength, long noteId = 0)
        {
            if ((long)kind is < -1 or > 1 || noteId < 0 || !double.IsFinite(strength) ||
                strength is < 0d or > 1d)
            {
                throw new InvalidOperationException("Managed emit arguments violate the DAXQ host contract.");
            }
            if (_signals.Count >= MaximumSignalsPerCallback)
                throw new InvalidOperationException("Managed emit count exceeds the DAXQ callback limit.");
            _signals.Add(new DaxqSignal((long)kind, Normalize(strength), noteId));
        }

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

        public long TimeIndex() => _timeIndex;

        public double Random() => _rng.NextDouble();

        public void Log(long messageId, double value)
        {
            if (messageId < 0 || !double.IsFinite(value))
                throw new InvalidOperationException("Managed log arguments violate the DAXQ host contract.");
            if (_logs.Count >= MaximumLogsPerCallback)
                throw new InvalidOperationException("Managed log count exceeds the DAXQ callback limit.");
            _logs.Add(new DaxqLogRecord(messageId, Normalize(value)));
        }

        private static void Require(DaxqFault fault)
        {
            if (fault != DaxqFault.Ok)
                throw new InvalidOperationException($"Managed host fault: {fault}.");
        }

        private static double Normalize(double value) => value == 0d ? 0d : value;
    }

    private sealed class StatisticsAccumulator
    {
        private int _initializationCallbacks;
        private int _barCallbacks;
        private int _tickCallbacks;
        private ulong _executedInstructions;
        private uint _maximumStackDepth;
        private int _logCount;
        private int _signalCount;
        private int _longSignalCount;
        private int _shortSignalCount;
        private int _flatSignalCount;
        private double _strengthSum;
        private double _minimumStrength = double.PositiveInfinity;
        private double _maximumStrength = double.NegativeInfinity;

        public void Observe(
            DaxqEntrypoint entrypoint,
            DaxqInvocationResult result,
            ReadOnlySpan<DaxqSignal> signals)
        {
            switch (entrypoint)
            {
                case DaxqEntrypoint.Initialize:
                    _initializationCallbacks++;
                    break;
                case DaxqEntrypoint.OnBar:
                    _barCallbacks++;
                    break;
                case DaxqEntrypoint.OnTick:
                    _tickCallbacks++;
                    break;
            }

            _executedInstructions = checked(_executedInstructions + result.ExecutedInstructions);
            _maximumStackDepth = Math.Max(_maximumStackDepth, result.MaxStackDepth);
            _logCount = checked(_logCount + result.LogCount);
            foreach (var signal in signals)
            {
                _signalCount++;
                if (signal.Kind > 0)
                    _longSignalCount++;
                else if (signal.Kind < 0)
                    _shortSignalCount++;
                else
                    _flatSignalCount++;
                _strengthSum += signal.Strength;
                _minimumStrength = Math.Min(_minimumStrength, signal.Strength);
                _maximumStrength = Math.Max(_maximumStrength, signal.Strength);
            }
        }

        public DaxqBacktestStatistics Build()
        {
            var minimum = _signalCount == 0 ? 0d : _minimumStrength;
            var maximum = _signalCount == 0 ? 0d : _maximumStrength;
            var average = _signalCount == 0 ? 0d : _strengthSum / _signalCount;
            if (!double.IsFinite(average))
                throw new InvalidOperationException("Canonical signal statistics became non-finite.");

            return new DaxqBacktestStatistics(
                DaxqBacktestStatistics.CurrentSchemaVersion,
                _initializationCallbacks,
                _barCallbacks,
                _tickCallbacks,
                _executedInstructions,
                _maximumStackDepth,
                _logCount,
                _signalCount,
                _longSignalCount,
                _shortSignalCount,
                _flatSignalCount,
                Normalize(minimum),
                Normalize(maximum),
                Normalize(average));
        }

        private static double Normalize(double value) => value == 0d ? 0d : value;
    }

    private sealed record ReferenceDataSnapshot(
        DaxqBar[] Bars,
        double[] Parameters,
        DaxqBacktestCallback[] Callbacks,
        double[] ReferencePrices,
        ulong LaunchSeed)
    {
        public static ReferenceDataSnapshot Create(DaxqBacktestReferenceData source)
        {
            ArgumentNullException.ThrowIfNull(source.Bars);
            ArgumentNullException.ThrowIfNull(source.Parameters);
            ArgumentNullException.ThrowIfNull(source.Callbacks);
            var bars = source.Bars.ToArray();
            var parameters = source.Parameters.ToArray();
            var callbacks = source.Callbacks.ToArray();
            if (callbacks.Length == 0)
                throw new ArgumentException("The parity reference dataset must contain at least one callback.", nameof(source));
            if (bars.Length > 65_536)
                throw new ArgumentException("The parity reference history may contain at most 65,536 bars.", nameof(source));
            if (bars.Any(bar => !double.IsFinite(bar.Open) || !double.IsFinite(bar.High) ||
                                !double.IsFinite(bar.Low) || !double.IsFinite(bar.Close) ||
                                !double.IsFinite(bar.Volume)))
            {
                throw new ArgumentException("Every reference bar value must be finite.", nameof(source));
            }
            if (parameters.Length > 256 || parameters.Any(value => !double.IsFinite(value)))
                throw new ArgumentException("Reference parameters must contain at most 256 finite values.", nameof(source));

            long previousTimeIndex = -1;
            var previousCompletedBarIndex = -1;
            var previousOnBarIndex = -1;
            var referencePrices = new double[callbacks.Length];
            for (var index = 0; index < callbacks.Length; index++)
            {
                var callback = callbacks[index];
                if (callback.Entrypoint is not (DaxqEntrypoint.OnBar or DaxqEntrypoint.OnTick))
                    throw new ArgumentException($"Reference callback {index} has an invalid entrypoint.", nameof(source));
                if (callback.CompletedBarIndex < -1 || callback.CompletedBarIndex >= bars.Length ||
                    (callback.Entrypoint == DaxqEntrypoint.OnBar && callback.CompletedBarIndex < 0))
                {
                    throw new ArgumentException(
                        $"Reference callback {index} has completed-bar index {callback.CompletedBarIndex} outside the supplied history.",
                        nameof(source));
                }
                if (callback.TimeIndex < 0 || callback.TimeIndex < previousTimeIndex ||
                    callback.CompletedBarIndex < previousCompletedBarIndex ||
                    callback.CompletedBarIndex > callback.TimeIndex)
                {
                    throw new ArgumentException(
                        $"Reference callback {index} is not in canonical nondecreasing time/bar order.",
                        nameof(source));
                }
                if (callback.Entrypoint == DaxqEntrypoint.OnBar &&
                    (callback.TimeIndex != callback.CompletedBarIndex ||
                     callback.CompletedBarIndex <= previousOnBarIndex))
                {
                    throw new ArgumentException(
                        $"Reference OnBar callback {index} must advance to its matching completed-bar index.",
                        nameof(source));
                }
                if (callback.Entrypoint == DaxqEntrypoint.OnTick &&
                    (!double.IsFinite(callback.Bid) || !double.IsFinite(callback.Ask) ||
                     !double.IsFinite(callback.Last) || !double.IsFinite(callback.Volume)))
                {
                    throw new ArgumentException($"Reference tick {index} contains a non-finite value.", nameof(source));
                }
                previousTimeIndex = callback.TimeIndex;
                previousCompletedBarIndex = callback.CompletedBarIndex;
                if (callback.Entrypoint == DaxqEntrypoint.OnBar)
                    previousOnBarIndex = callback.CompletedBarIndex;
                referencePrices[index] = ResolveReferencePrice(callback, bars, index);
            }

            return new ReferenceDataSnapshot(bars, parameters, callbacks, referencePrices, source.LaunchSeed);
        }

        private static double ResolveReferencePrice(
            DaxqBacktestCallback callback,
            IReadOnlyList<DaxqBar> bars,
            int callbackOrdinal)
        {
            if (callback.Entrypoint == DaxqEntrypoint.OnBar)
            {
                var close = bars[callback.CompletedBarIndex].Close;
                if (close <= 0d)
                {
                    throw new ArgumentException(
                        $"Reference bar callback {callbackOrdinal} requires a positive close price.");
                }
                return close;
            }

            var hasBid = callback.Bid > 0d;
            var hasAsk = callback.Ask > 0d;
            if (hasBid && hasAsk)
            {
                if (callback.Ask < callback.Bid)
                {
                    throw new ArgumentException(
                        $"Reference tick callback {callbackOrdinal} has ask below bid.");
                }
                var midpoint = callback.Bid + ((callback.Ask - callback.Bid) / 2d);
                if (!double.IsFinite(midpoint) || midpoint <= 0d)
                {
                    throw new ArgumentException(
                        $"Reference tick callback {callbackOrdinal} has no finite positive midpoint.");
                }
                return midpoint;
            }

            if (callback.Last <= 0d)
            {
                throw new ArgumentException(
                    $"Reference tick callback {callbackOrdinal} requires an ordered positive bid/ask or positive last price.");
            }
            return callback.Last;
        }
    }

    private struct ParityRng
    {
        private ulong _s0;
        private ulong _s1;
        private ulong _s2;
        private ulong _s3;

        public static ParityRng Create(ulong seed)
        {
            var state = seed;
            return new ParityRng
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
