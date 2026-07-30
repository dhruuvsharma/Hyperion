using System.Globalization;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;
using DaxAlgo.Sdk;
using TradingTerminal.Core.Backtest;
using TradingTerminal.Core.Domain;
using TradingTerminal.Core.Time;
using TradingTerminal.Core.Trading;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class CandidateExecutor
{
    internal const int MaximumTraceEntries = 64;
    private static readonly TimeSpan CallbackTimeout = TimeSpan.FromSeconds(1);

    public static Task<CandidateExecution> ExecuteAsync(
        byte[] assemblyBytes,
        string strategyTypeName,
        VerifierContract requestContract,
        VerificationCase verificationCase) =>
        CandidateReplayProcess.ExecuteAsync(
            assemblyBytes,
            strategyTypeName,
            requestContract,
            verificationCase);

    internal static async Task<CandidateExecution> ExecuteInProcessAsync(
        byte[] assemblyBytes,
        string strategyTypeName,
        VerifierContract requestContract,
        VerificationCase verificationCase)
    {
        var loadContext = new CandidateLoadContext();
        var trace = Array.Empty<VerifierTraceEntry>();
        VerifierRuntimeError? error = null;
        RecordingOrderRouter? router = null;
        try
        {
            using var assemblyStream = new MemoryStream(assemblyBytes, writable: false);
            var candidateAssembly = loadContext.LoadFromStream(assemblyStream);
            var strategyType = candidateAssembly.GetType(
                strategyTypeName,
                throwOnError: true,
                ignoreCase: false)
                ?? throw new CandidateContractException("The candidate strategy type is missing.");
            if (!typeof(IBacktestStrategy).IsAssignableFrom(strategyType))
            {
                throw new CandidateContractException("The candidate type does not implement IBacktestStrategy.");
            }

            var contract = new Contract(
                requestContract.Symbol,
                requestContract.SecType,
                requestContract.Exchange,
                requestContract.Currency,
                requestContract.PrimaryExchange);
            var constructor = strategyType.GetConstructor([typeof(Contract)])
                ?? throw new CandidateContractException("The candidate Contract constructor is missing.");
            var strategy = constructor.Invoke([contract]) as IBacktestStrategy
                ?? throw new CandidateContractException("The candidate constructor returned an invalid strategy.");
            var clock = new FixedClock(verificationCase.StartUtc);
            router = new RecordingOrderRouter(clock, MaximumTraceEntries);

            await InvokeBoundedAsync(
                cancellationToken => strategy.OnStartAsync(clock, router, cancellationToken));
            foreach (var item in verificationCase.Ticks)
            {
                clock.AdvanceTo(verificationCase.StartUtc.AddMilliseconds(item.OffsetMilliseconds));
                var tick = new Tick(
                    clock.UtcNow,
                    item.Bid,
                    item.Ask,
                    item.BidSize,
                    item.AskSize);
                await InvokeBoundedAsync(
                    cancellationToken => strategy.OnTickAsync(tick, clock, router, cancellationToken));
            }

            await InvokeBoundedAsync(
                cancellationToken => strategy.OnEndAsync(clock, router, cancellationToken));
            trace = router.Trace;
        }
        catch (Exception exception)
        {
            var effective = Unwrap(exception);
            error = ToRuntimeError(effective);
            trace = effective is TraceLimitException traceLimit
                ? traceLimit.Trace
                : router?.Trace ?? [];
        }
        finally
        {
            loadContext.Unload();
        }

        var hash = ComputeHash(trace, error);
        return new(trace, error, hash);
    }

    internal static string ComputeHash(
        VerifierTraceEntry[] trace,
        VerifierRuntimeError? error) =>
        VerifierToolchain.Hash(Canonicalize(trace, error));

    private static async Task InvokeBoundedAsync(
        Func<CancellationToken, Task> callback)
    {
        using var cancellation = new CancellationTokenSource(CallbackTimeout);
        var invocation = Task.Run(
            async () =>
            {
                var originalCulture = CultureInfo.CurrentCulture;
                var originalUiCulture = CultureInfo.CurrentUICulture;
                try
                {
                    CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
                    CultureInfo.CurrentUICulture = CultureInfo.InvariantCulture;
                    var task = callback(cancellation.Token)
                        ?? throw new CandidateContractException("A strategy callback returned a null Task.");
                    await task.WaitAsync(cancellation.Token);
                }
                finally
                {
                    CultureInfo.CurrentCulture = originalCulture;
                    CultureInfo.CurrentUICulture = originalUiCulture;
                }
            },
            CancellationToken.None);
        try
        {
            await invocation.WaitAsync(CallbackTimeout);
        }
        catch (TimeoutException)
        {
            await cancellation.CancelAsync();
            throw new CandidateTimeoutException("A strategy callback exceeded the one-second bound.");
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            throw new CandidateTimeoutException("A strategy callback exceeded the one-second bound.");
        }
    }

    private static Exception Unwrap(Exception exception)
    {
        while (true)
        {
            if (exception is TargetInvocationException { InnerException: { } invocationInner })
            {
                exception = invocationInner;
                continue;
            }

            if (exception is AggregateException aggregate
                && aggregate.InnerExceptions.Count == 1)
            {
                exception = aggregate.InnerExceptions[0];
                continue;
            }

            return exception;
        }
    }

    private static VerifierRuntimeError ToRuntimeError(Exception exception)
    {
        var code = exception switch
        {
            CandidateTimeoutException => "callback-timeout",
            TraceLimitException => "trace-limit",
            CandidateContractException => "candidate-contract",
            _ => "candidate-exception",
        };
        var type = BoundText(exception.GetType().FullName ?? exception.GetType().Name, 256);
        var message = BoundText(exception.Message, 512);
        return new(code, type, message);
    }

    private static string BoundText(string value, int maximumLength)
    {
        var sanitized = new string(value
            .Where(character => !char.IsControl(character) && !char.IsSurrogate(character))
            .Take(maximumLength)
            .ToArray());
        return sanitized.Length == 0 ? "Candidate execution failed." : sanitized;
    }

    private static byte[] Canonicalize(
        VerifierTraceEntry[] trace,
        VerifierRuntimeError? error)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(
                   stream,
                   new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            writer.WriteStartObject();
            writer.WriteString(
                "schemaVersion",
                "daxalgo.verifier.headless-strategy-trace/v1");
            writer.WritePropertyName("trace");
            writer.WriteStartArray();
            foreach (var item in trace)
            {
                WriteTraceEntry(writer, item);
            }

            writer.WriteEndArray();
            writer.WritePropertyName("error");
            if (error is null)
            {
                writer.WriteNullValue();
            }
            else
            {
                writer.WriteStartObject();
                writer.WriteString("code", error.Code);
                writer.WriteString("type", error.Type);
                writer.WriteString("message", error.Message);
                writer.WriteEndObject();
            }

            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void WriteTraceEntry(Utf8JsonWriter writer, VerifierTraceEntry item)
    {
        writer.WriteStartObject();
        writer.WriteNumber("sequence", item.Sequence);
        writer.WriteString("kind", item.Kind);
        writer.WriteString("atUtc", item.AtUtc);
        writer.WriteString("clientOrderId", item.ClientOrderId);
        writer.WritePropertyName("contract");
        if (item.Contract is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            writer.WriteStartObject();
            writer.WriteString("symbol", item.Contract.Symbol);
            writer.WriteString("secType", item.Contract.SecType);
            writer.WriteString("exchange", item.Contract.Exchange);
            writer.WriteString("currency", item.Contract.Currency);
            writer.WriteString("primaryExchange", item.Contract.PrimaryExchange);
            writer.WriteEndObject();
        }

        WriteNullableString(writer, "side", item.Side);
        WriteNullableString(writer, "type", item.Type);
        if (item.Quantity is null)
        {
            writer.WriteNull("quantity");
        }
        else
        {
            writer.WriteNumber("quantity", item.Quantity.Value);
        }

        WriteNullableDouble(writer, "limitPrice", item.LimitPrice);
        WriteNullableDouble(writer, "stopPrice", item.StopPrice);
        WriteNullableString(writer, "timeInForce", item.TimeInForce);
        writer.WriteEndObject();
    }

    private static void WriteNullableString(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(name);
        }
        else
        {
            writer.WriteString(name, value);
        }
    }

    private static void WriteNullableDouble(Utf8JsonWriter writer, string name, double? value)
    {
        if (value is null)
        {
            writer.WriteNull(name);
        }
        else
        {
            writer.WriteNumber(name, value.Value);
        }
    }

    private sealed class CandidateLoadContext() : AssemblyLoadContext(isCollectible: true)
    {
        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (string.Equals(
                    assemblyName.Name,
                    typeof(IBacktestStrategy).Assembly.GetName().Name,
                    StringComparison.Ordinal))
            {
                return typeof(IBacktestStrategy).Assembly;
            }

            if (string.Equals(
                    assemblyName.Name,
                    typeof(SdkInfo).Assembly.GetName().Name,
                    StringComparison.Ordinal))
            {
                return typeof(SdkInfo).Assembly;
            }

            return null;
        }
    }

    private sealed class FixedClock(DateTime initialUtc) : IClock
    {
        public DateTime UtcNow { get; private set; } = EnsureUtc(initialUtc);

        public void AdvanceTo(DateTime value)
        {
            var utc = EnsureUtc(value);
            if (utc < UtcNow)
            {
                throw new InvalidOperationException("The verifier clock cannot move backwards.");
            }

            UtcNow = utc;
        }

        private static DateTime EnsureUtc(DateTime value) =>
            value.Kind == DateTimeKind.Utc
                ? value
                : DateTime.SpecifyKind(value, DateTimeKind.Utc);
    }

    private sealed class RecordingOrderRouter(
        FixedClock clock,
        int maximumTraceEntries) : IOrderRouter
    {
        private readonly List<VerifierTraceEntry> _trace = [];
        private long _sequence;

        public IObservable<OrderEvent> OrderEvents { get; } = EmptyOrderEvents.Instance;

        public VerifierTraceEntry[] Trace => _trace.ToArray();

        public Task<OrderResult> PlaceOrderAsync(
            OrderRequest request,
            CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(request);
            ValidateOrder(request);
            Add(new(
                Sequence: ++_sequence,
                Kind: "place",
                AtUtc: clock.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                ClientOrderId: request.ClientOrderId,
                Contract: new(
                    request.Contract.Symbol,
                    request.Contract.SecType,
                    request.Contract.Exchange,
                    request.Contract.Currency,
                    request.Contract.PrimaryExchange),
                Side: request.Side.ToString(),
                Type: request.Type.ToString(),
                Quantity: request.Quantity,
                LimitPrice: request.LimitPrice,
                StopPrice: request.StopPrice,
                TimeInForce: request.TimeInForce.ToString()));
            return Task.FromResult(new OrderResult(
                request.ClientOrderId,
                BrokerOrderId: null,
                OrderState.Working));
        }

        public Task CancelOrderAsync(
            string clientOrderId,
            CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            ValidateText(clientOrderId, nameof(clientOrderId), 256);
            Add(new(
                Sequence: ++_sequence,
                Kind: "cancel",
                AtUtc: clock.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                ClientOrderId: clientOrderId,
                Contract: null,
                Side: null,
                Type: null,
                Quantity: null,
                LimitPrice: null,
                StopPrice: null,
                TimeInForce: null));
            return Task.CompletedTask;
        }

        private void Add(VerifierTraceEntry item)
        {
            if (_trace.Count >= maximumTraceEntries)
            {
                throw new TraceLimitException(_trace.ToArray());
            }

            _trace.Add(item);
        }

        private static void ValidateOrder(OrderRequest request)
        {
            ValidateText(request.ClientOrderId, nameof(request.ClientOrderId), 256);
            ArgumentNullException.ThrowIfNull(request.Contract);
            ValidateText(request.Contract.Symbol, nameof(request.Contract.Symbol), 64);
            ValidateText(request.Contract.SecType, nameof(request.Contract.SecType), 32);
            ValidateText(request.Contract.Exchange, nameof(request.Contract.Exchange), 64);
            ValidateText(request.Contract.Currency, nameof(request.Contract.Currency), 16);
            ValidateText(request.Contract.PrimaryExchange, nameof(request.Contract.PrimaryExchange), 64);
            if (request.Quantity is <= 0 or > 1_000_000_000_000)
            {
                throw new CandidateContractException("Order quantity is outside the trace bound.");
            }

            ValidatePrice(request.LimitPrice);
            ValidatePrice(request.StopPrice);
        }

        private static void ValidatePrice(double? value)
        {
            if (value is not null
                && (!double.IsFinite(value.Value) || Math.Abs(value.Value) > 1_000_000_000_000d))
            {
                throw new CandidateContractException("Order price is outside the trace bound.");
            }
        }

        private static void ValidateText(string? value, string name, int maximumLength)
        {
            if (string.IsNullOrWhiteSpace(value)
                || value.Length > maximumLength
                || value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
            {
                throw new CandidateContractException($"{name} is outside the trace text bound.");
            }
        }
    }

    private sealed class EmptyOrderEvents : IObservable<OrderEvent>
    {
        public static EmptyOrderEvents Instance { get; } = new();

        public IDisposable Subscribe(IObserver<OrderEvent> observer)
        {
            ArgumentNullException.ThrowIfNull(observer);
            return EmptyDisposable.Instance;
        }
    }

    private sealed class EmptyDisposable : IDisposable
    {
        public static EmptyDisposable Instance { get; } = new();

        public void Dispose()
        {
        }
    }

    private sealed class CandidateTimeoutException(string message) : Exception(message);

    private sealed class CandidateContractException(string message) : Exception(message);

    private sealed class TraceLimitException(VerifierTraceEntry[] trace)
        : Exception("The candidate exceeded the per-case trace bound.")
    {
        public VerifierTraceEntry[] Trace { get; } = trace;
    }
}
