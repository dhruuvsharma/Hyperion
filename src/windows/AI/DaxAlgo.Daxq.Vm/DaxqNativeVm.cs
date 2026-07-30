using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DaxAlgo.Daxq.Vm;

/// <summary>Cached-delegate P/Invoke bridge for the native <c>daxq_vm</c> ABI 3 DLL.</summary>
public sealed unsafe class DaxqNativeVm : IDisposable
{
    private const string NativeLibraryName = "daxq_vm";
    private const uint AbiVersion = 3;
    private const uint ProtectionAbiVersion = 1;
    private const int MaximumEmits = 8;
    private const int MaximumLogs = 16;

    private static readonly object ResolverLock = new();
    private static string? _configuredLibraryPath;
    private static nint _configuredLibraryHandle;

    private static readonly BarCallback BarDelegate = BarThunk;
    private static readonly IndicatorCallback IndicatorDelegate = IndicatorThunk;
    private static readonly ParameterCallback ParameterDelegate = ParameterThunk;
    private static readonly EmitCallback EmitDelegate = EmitThunk;
    private static readonly StateCallback StateDelegate = StateThunk;
    private static readonly TimeIndexCallback TimeIndexDelegate = TimeIndexThunk;
    private static readonly RngCallback RngDelegate = RngThunk;
    private static readonly LogCallback LogDelegate = LogThunk;

    private static readonly nint BarPointer = Marshal.GetFunctionPointerForDelegate(BarDelegate);
    private static readonly nint IndicatorPointer = Marshal.GetFunctionPointerForDelegate(IndicatorDelegate);
    private static readonly nint ParameterPointer = Marshal.GetFunctionPointerForDelegate(ParameterDelegate);
    private static readonly nint EmitPointer = Marshal.GetFunctionPointerForDelegate(EmitDelegate);
    private static readonly nint StatePointer = Marshal.GetFunctionPointerForDelegate(StateDelegate);
    private static readonly nint TimeIndexPointer = Marshal.GetFunctionPointerForDelegate(TimeIndexDelegate);
    private static readonly nint RngPointer = Marshal.GetFunctionPointerForDelegate(RngDelegate);
    private static readonly nint LogPointer = Marshal.GetFunctionPointerForDelegate(LogDelegate);

    static DaxqNativeVm()
    {
        NativeLibrary.SetDllImportResolver(typeof(DaxqNativeVm).Assembly, ResolveNativeLibrary);
    }

    private readonly DaxqValueType[]?[] _entrypointArgumentTypes = new DaxqValueType[3][];
    private readonly IDaxqHost _host;
    private readonly DaxqSignal[] _signals = new DaxqSignal[MaximumEmits];
    private readonly DaxqLogRecord[] _logs = new DaxqLogRecord[MaximumLogs];
    private GCHandle _selfHandle;
    private nint _handle;
    private Xoshiro256StarStar _rng;
    private Xoshiro256StarStar _workingRng;
    private long _timeIndex;
    private int _stagedSignalCount;
    private int _stagedLogCount;
    private int _visibleSignalCount;
    private int _visibleLogCount;
    private int _invoking;
    private int _disposeRequested;
    private int _cleanupStarted;
    private bool _initializeSucceeded;

    private DaxqNativeVm(DaxqProgram program, IDaxqHost host, ulong launchSeed)
    {
        for (var index = 0; index < _entrypointArgumentTypes.Length; index++)
        {
            if (program.Entrypoints[index] is { } entrypoint)
            {
                _entrypointArgumentTypes[index] = entrypoint.ArgumentTypes
                    .Select(static type => (DaxqValueType)type)
                    .ToArray();
            }
        }
        _host = host;
        _rng = Xoshiro256StarStar.Create(launchSeed);
        _selfHandle = GCHandle.Alloc(this, GCHandleType.Weak);
    }

    /// <summary>Signals from the most recent successful callback; invalidated by the next invocation.</summary>
    public ReadOnlySpan<DaxqSignal> EmittedSignals => _signals.AsSpan(0, _visibleSignalCount);

    /// <summary>Logs from the most recent successful callback; invalidated by the next invocation.</summary>
    public ReadOnlySpan<DaxqLogRecord> Logs => _logs.AsSpan(0, _visibleLogCount);

    /// <summary>
    /// Configures an explicit native library path before the first native call. This is primarily for
    /// test/build layouts where the DLL is not beside the managed application.
    /// </summary>
    internal static DaxqFault ConfigureNativeLibrary(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || !Path.IsPathFullyQualified(fullPath))
            return DaxqFault.InvalidArgument;

        lock (ResolverLock)
        {
            if (_configuredLibraryHandle != 0)
            {
                return string.Equals(_configuredLibraryPath, fullPath, StringComparison.OrdinalIgnoreCase)
                    ? DaxqFault.Ok
                    : DaxqFault.InvalidLifecycle;
            }

            try
            {
                _configuredLibraryPath = fullPath;
                _configuredLibraryHandle = NativeLibrary.Load(fullPath);
                return DaxqFault.Ok;
            }
            catch (Exception)
            {
                _configuredLibraryPath = null;
                _configuredLibraryHandle = 0;
                return DaxqFault.Internal;
            }
        }
    }

    /// <summary>Attempts to create and configure a native VM without throwing loader exceptions.</summary>
    public static DaxqFault TryCreate(
        DaxqProgram? program,
        IDaxqHost? host,
        ulong launchSeed,
        out DaxqNativeVm? vm)
    {
        vm = null;
        if (program is null || host is null)
            return DaxqFault.InvalidArgument;

        DaxqNativeVm? candidate = null;
        try
        {
            candidate = new DaxqNativeVm(program, host, launchSeed);
            var fault = candidate.CreateNativeHandle(program);
            if (fault != DaxqFault.Ok)
            {
                candidate.Dispose();
                return fault;
            }
            vm = candidate;
            return DaxqFault.Ok;
        }
        catch (DllNotFoundException)
        {
            candidate?.Dispose();
            return DaxqFault.Internal;
        }
        catch (EntryPointNotFoundException)
        {
            candidate?.Dispose();
            return DaxqFault.AbiMismatch;
        }
        catch (BadImageFormatException)
        {
            candidate?.Dispose();
            return DaxqFault.AbiMismatch;
        }
        catch (Exception)
        {
            candidate?.Dispose();
            return DaxqFault.Internal;
        }
    }

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

    /// <summary>Invokes one native callback through the stable C ABI.</summary>
    public DaxqInvocationResult Invoke(DaxqEntrypoint entrypoint, ReadOnlySpan<DaxqValue> arguments)
    {
        if ((byte)entrypoint >= _entrypointArgumentTypes.Length)
        {
            return EmptyResult(DaxqFault.EntrypointNotFound);
        }
        var argumentTypes = _entrypointArgumentTypes[(byte)entrypoint];
        if (argumentTypes is null)
            return EmptyResult(DaxqFault.EntrypointNotFound);
        if (Interlocked.CompareExchange(ref _invoking, 1, 0) != 0)
            return EmptyResult(DaxqFault.Reentrant);

        try
        {
            _visibleSignalCount = 0;
            _visibleLogCount = 0;
            if (Volatile.Read(ref _disposeRequested) != 0 || _handle == 0 ||
                (entrypoint == DaxqEntrypoint.Initialize && _initializeSucceeded))
            {
                return EmptyResult(DaxqFault.InvalidLifecycle);
            }
            if (arguments.Length != argumentTypes.Length)
                return EmptyResult(DaxqFault.InvalidArgument);

            NativeValue* nativeArguments = stackalloc NativeValue[5];
            new Span<byte>(nativeArguments, sizeof(NativeValue) * 5).Clear();
            for (var index = 0; index < arguments.Length; index++)
            {
                var value = arguments[index];
                if (value.Type != argumentTypes[index] ||
                    (value.Type == DaxqValueType.F64 && !double.IsFinite(value.AsDouble())))
                {
                    return EmptyResult(DaxqFault.InvalidArgument);
                }
                nativeArguments[index].Tag = (byte)value.Type;
                nativeArguments[index].Bits = value.RawBits;
            }

            _timeIndex = entrypoint == DaxqEntrypoint.Initialize ? 0 : arguments[0].AsInt64();
            _workingRng = _rng;
            _stagedSignalCount = 0;
            _stagedLogCount = 0;

            var options = new NativeInvokeOptions
            {
                AbiVersion = AbiVersion,
                StructSize = (uint)sizeof(NativeInvokeOptions),
                EntrypointId = (byte)entrypoint,
                ArgCount = (uint)arguments.Length,
                Args = arguments.Length == 0 ? null : nativeArguments,
            };
            var nativeResult = new NativeInvokeResult
            {
                AbiVersion = AbiVersion,
                StructSize = (uint)sizeof(NativeInvokeResult),
            };

            var callFault = NormalizeFault(NativeMethods.Invoke(_handle, &options, &nativeResult));
            var resultFault = NormalizeFault(nativeResult.Fault);
            var fault = callFault != DaxqFault.Ok ? callFault : resultFault;
            if (fault == DaxqFault.Ok)
            {
                _rng = _workingRng;
                _visibleSignalCount = _stagedSignalCount;
                _visibleLogCount = _stagedLogCount;
                if (entrypoint == DaxqEntrypoint.Initialize)
                    _initializeSucceeded = true;
            }

            return new DaxqInvocationResult(
                fault,
                nativeResult.ExecutedInstructions,
                nativeResult.MaxStackDepth,
                _visibleSignalCount,
                _visibleLogCount);
        }
        catch (DllNotFoundException)
        {
            return EmptyResult(DaxqFault.Internal);
        }
        catch (EntryPointNotFoundException)
        {
            return EmptyResult(DaxqFault.AbiMismatch);
        }
        catch (Exception)
        {
            return EmptyResult(DaxqFault.Internal);
        }
        finally
        {
            Volatile.Write(ref _invoking, 0);
            TryFinalizeDispose();
            GC.KeepAlive(this);
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _disposeRequested, 1);
        TryFinalizeDispose();
        GC.SuppressFinalize(this);
    }

    ~DaxqNativeVm()
    {
        Dispose();
    }

    /// <summary>
    /// Installs signed licensing evidence in the native VM. The native protected region verifies the
    /// ES256 signature, binding, and absolute expiry before permitting bytecode dispatch.
    /// </summary>
    internal DaxqFault ApplyLicenseEvidence(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> publicKey)
    {
        if (payload.IsEmpty || signature.Length != 64 || publicKey.Length != 64 ||
            Volatile.Read(ref _disposeRequested) != 0 || _handle == 0)
        {
            return DaxqFault.InvalidArgument;
        }

        try
        {
            fixed (byte* payloadPointer = payload)
            {
                var evidence = new NativeLicenseEvidence
                {
                    AbiVersion = ProtectionAbiVersion,
                    StructSize = (uint)sizeof(NativeLicenseEvidence),
                    Payload = new NativeBlob(payloadPointer, payload.Length),
                };
                signature.CopyTo(new Span<byte>(evidence.Signature, 64));
                publicKey.CopyTo(new Span<byte>(evidence.PublicKey, 64));
                return NormalizeFault(NativeMethods.ApplyLicenseEvidence(_handle, &evidence));
            }
        }
        catch (EntryPointNotFoundException)
        {
            return DaxqFault.AbiMismatch;
        }
        catch (Exception)
        {
            return DaxqFault.Internal;
        }
    }

    /// <summary>Irreversibly revokes this VM handle inside the protected native region.</summary>
    internal DaxqFault RevokeLicense()
    {
        if (_handle == 0)
            return DaxqFault.InvalidLifecycle;
        try { return NormalizeFault(NativeMethods.RevokeLicense(_handle)); }
        catch (EntryPointNotFoundException) { return DaxqFault.AbiMismatch; }
        catch (Exception) { return DaxqFault.Internal; }
    }

    private DaxqFault CreateNativeHandle(DaxqProgram program)
    {
        fixed (byte* bytecode = program.Bytecode)
        fixed (byte* constants = program.ConstantPoolSection)
        fixed (byte* opcodeMap = program.OpcodeMapSection)
        fixed (byte* hostMap = program.HostMapSection)
        fixed (byte* entrypoints = program.EntrypointSection)
        {
            var options = new NativeCreateOptions
            {
                AbiVersion = AbiVersion,
                StructSize = (uint)sizeof(NativeCreateOptions),
                Bytecode = new NativeBlob(bytecode, program.Bytecode.Length),
                ConstantPool = new NativeBlob(constants, program.ConstantPoolSection.Length),
                OpcodeMap = new NativeBlob(opcodeMap, program.OpcodeMapSection.Length),
                HostMap = new NativeBlob(hostMap, program.HostMapSection.Length),
                Entrypoints = new NativeBlob(entrypoints, program.EntrypointSection.Length),
            };
            nint handle = 0;
            var createFault = NormalizeFault(NativeMethods.Create(&options, &handle));
            if (createFault != DaxqFault.Ok || handle == 0)
                return createFault == DaxqFault.Ok ? DaxqFault.Internal : createFault;
            _handle = handle;
        }

        var integrityFault = NormalizeFault(NativeMethods.VerifyIntegrity());
        if (integrityFault != DaxqFault.Ok)
        {
            NativeMethods.Destroy(_handle);
            _handle = 0;
            return integrityFault;
        }

        var callbacks = new NativeHostCallbacks
        {
            AbiVersion = AbiVersion,
            StructSize = (uint)sizeof(NativeHostCallbacks),
            Context = GCHandle.ToIntPtr(_selfHandle),
            Bar = BarPointer,
            Indicator = IndicatorPointer,
            Parameter = ParameterPointer,
            Emit = EmitPointer,
            State = StatePointer,
            TimeIndex = TimeIndexPointer,
            Rng = RngPointer,
            Log = LogPointer,
        };
        var callbackFault = NormalizeFault(NativeMethods.SetHostCallbacks(_handle, &callbacks));
        if (callbackFault != DaxqFault.Ok)
        {
            NativeMethods.Destroy(_handle);
            _handle = 0;
        }
        return callbackFault;
    }

    private static nint ResolveNativeLibrary(
        string libraryName,
        Assembly assembly,
        DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, NativeLibraryName, StringComparison.Ordinal))
            return 0;
        lock (ResolverLock)
        {
            return _configuredLibraryHandle != 0
                ? _configuredLibraryHandle
                : throw new DllNotFoundException(
                    "The native DAXQ VM has not passed the host integrity gate.");
        }
    }

    private static int BarThunk(nint context, long field, long lookback, double* value)
    {
        try
        {
            if (value is null)
                return (int)DaxqFault.InvalidArgument;
            var vm = FromContext(context);
            return NormalizeReadCallbackFault(vm._host.ReadBar(field, lookback, out *value), value);
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static int IndicatorThunk(
        nint context,
        long indicator,
        long period,
        long source,
        double* value)
    {
        try
        {
            if (value is null)
                return (int)DaxqFault.InvalidArgument;
            var vm = FromContext(context);
            return NormalizeReadCallbackFault(
                vm._host.ReadIndicator(indicator, period, source, out *value), value);
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static int ParameterThunk(nint context, long parameterId, double* value)
    {
        try
        {
            if (value is null)
                return (int)DaxqFault.InvalidArgument;
            if (parameterId is < 0 or > 255)
                return (int)DaxqFault.Host;
            var vm = FromContext(context);
            return NormalizeReadCallbackFault(vm._host.ReadParameter(parameterId, out *value), value);
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static int EmitThunk(nint context, long kind, double strength, long noteId)
    {
        try
        {
            var vm = FromContext(context);
            if (kind is < -1 or > 1 || noteId < 0 || !double.IsFinite(strength) ||
                strength < 0d || strength > 1d)
            {
                return (int)DaxqFault.Host;
            }
            if (vm._stagedSignalCount >= MaximumEmits)
                return (int)DaxqFault.EffectLimit;
            vm._signals[vm._stagedSignalCount++] = new DaxqSignal(
                kind, DaxqValue.Normalize(strength), noteId);
            return 0;
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static int TimeIndexThunk(nint context, long* value)
    {
        try
        {
            if (value is null)
                return (int)DaxqFault.InvalidArgument;
            *value = FromContext(context)._timeIndex;
            return 0;
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static int StateThunk(nint context) => 0;

    private static int RngThunk(nint context, double* value)
    {
        try
        {
            if (value is null)
                return (int)DaxqFault.InvalidArgument;
            var vm = FromContext(context);
            *value = vm._workingRng.NextDouble();
            return 0;
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static int LogThunk(nint context, long messageId, double value)
    {
        try
        {
            var vm = FromContext(context);
            if (messageId < 0 || !double.IsFinite(value))
                return (int)DaxqFault.Host;
            if (vm._stagedLogCount >= MaximumLogs)
                return (int)DaxqFault.EffectLimit;
            vm._logs[vm._stagedLogCount++] = new DaxqLogRecord(
                messageId, DaxqValue.Normalize(value));
            return 0;
        }
        catch (Exception)
        {
            return (int)DaxqFault.Host;
        }
    }

    private static DaxqNativeVm FromContext(nint context) =>
        (DaxqNativeVm)GCHandle.FromIntPtr(context).Target!;

    private static int NormalizeReadCallbackFault(DaxqFault fault, double* value)
    {
        if (fault == DaxqFault.Ok)
            return 0;
        if (fault == DaxqFault.Numeric)
        {
            *value = double.NaN;
            return 0;
        }
        return (int)DaxqFault.Host;
    }

    private static DaxqFault NormalizeFault(int value) =>
        value is >= (int)DaxqFault.Ok and <= (int)DaxqFault.Internal
            ? (DaxqFault)value
            : DaxqFault.Internal;

    private DaxqInvocationResult EmptyResult(DaxqFault fault)
        => new(fault, 0, 0, 0, 0);

    private void TryFinalizeDispose()
    {
        if (Volatile.Read(ref _disposeRequested) == 0 ||
            Volatile.Read(ref _invoking) != 0 ||
            Interlocked.CompareExchange(ref _cleanupStarted, 1, 0) != 0)
        {
            return;
        }

        var handle = _handle;
        _handle = 0;
        if (handle != 0)
        {
            try
            {
                NativeMethods.Destroy(handle);
            }
            catch (Exception)
            {
                // Destruction must never escape into the terminal shutdown path.
            }
        }
        foreach (var argumentTypes in _entrypointArgumentTypes)
        {
            if (argumentTypes is not null)
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(argumentTypes.AsSpan()));
        }
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_signals.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_logs.AsSpan()));
        DisposeManagedHandleOnly();
    }

    private void DisposeManagedHandleOnly()
    {
        if (_selfHandle.IsAllocated)
            _selfHandle.Free();
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int BarCallback(nint context, long field, long lookback, double* value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int IndicatorCallback(
        nint context,
        long indicator,
        long period,
        long source,
        double* value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int ParameterCallback(nint context, long parameterId, double* value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int EmitCallback(nint context, long kind, double strength, long noteId);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int StateCallback(nint context);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int TimeIndexCallback(nint context, long* value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int RngCallback(nint context, double* value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int LogCallback(nint context, long messageId, double value);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeBlob
    {
        public NativeBlob(byte* data, int length)
        {
            Data = data;
            Length = checked((uint)length);
        }

        public readonly byte* Data;
        public readonly uint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCreateOptions
    {
        public uint AbiVersion;
        public uint StructSize;
        public NativeBlob Bytecode;
        public NativeBlob ConstantPool;
        public NativeBlob OpcodeMap;
        public NativeBlob HostMap;
        public NativeBlob Entrypoints;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeHostCallbacks
    {
        public uint AbiVersion;
        public uint StructSize;
        public nint Context;
        public nint Bar;
        public nint Indicator;
        public nint Parameter;
        public nint Emit;
        public nint State;
        public nint TimeIndex;
        public nint Rng;
        public nint Log;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeLicenseEvidence
    {
        public uint AbiVersion;
        public uint StructSize;
        public NativeBlob Payload;
        public fixed byte Signature[64];
        public fixed byte PublicKey[64];
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct NativeValue
    {
        [FieldOffset(0)]
        public byte Tag;

        [FieldOffset(8)]
        public long Bits;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeInvokeOptions
    {
        public uint AbiVersion;
        public uint StructSize;
        public byte EntrypointId;
        public byte Reserved0;
        public byte Reserved1;
        public byte Reserved2;
        public byte Reserved3;
        public byte Reserved4;
        public byte Reserved5;
        public byte Reserved6;
        public uint ArgCount;
        public uint Reserved;
        public NativeValue* Args;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeInvokeResult
    {
        public uint AbiVersion;
        public uint StructSize;
        public int Fault;
        public uint ExecutedInstructions;
        public uint MaxStackDepth;
        public uint Reserved;
    }

    private static class NativeMethods
    {
        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_create", ExactSpelling = true)]
        public static extern int Create(NativeCreateOptions* options, nint* handle);

        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_set_host_callbacks", ExactSpelling = true)]
        public static extern int SetHostCallbacks(nint handle, NativeHostCallbacks* callbacks);

        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_apply_license_evidence", ExactSpelling = true)]
        public static extern int ApplyLicenseEvidence(nint handle, NativeLicenseEvidence* evidence);

        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_revoke_license", ExactSpelling = true)]
        public static extern int RevokeLicense(nint handle);

        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_verify_integrity", ExactSpelling = true)]
        public static extern int VerifyIntegrity();

        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_invoke", ExactSpelling = true)]
        public static extern int Invoke(
            nint handle,
            NativeInvokeOptions* options,
            NativeInvokeResult* result);

        [DllImport(NativeLibraryName, CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "daxq_vm_destroy", ExactSpelling = true)]
        public static extern void Destroy(nint handle);
    }
}
