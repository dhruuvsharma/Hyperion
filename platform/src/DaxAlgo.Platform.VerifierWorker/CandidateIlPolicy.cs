using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class CandidateIlPolicy
{
    private static readonly string[] CompilerGeneratedDiagnosticTypes =
    [
        "System.Diagnostics.DebuggableAttribute",
        "System.Diagnostics.DebuggerHiddenAttribute",
        "System.Diagnostics.DebuggerStepThroughAttribute",
    ];

    private static readonly Dictionary<ushort, OperandType> OperandTypes =
        typeof(OpCodes)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(OpCode))
            .Select(field => (OpCode)(field.GetValue(null)
                ?? throw new InvalidOperationException("An IL opcode is unavailable.")))
            .ToDictionary(opcode => unchecked((ushort)opcode.Value), opcode => opcode.OperandType);

    private static readonly string[] ForbiddenNamespacePrefixes =
    [
        "Microsoft.Win32",
        "System.Diagnostics",
        "System.IO",
        "System.Management",
        "System.Net",
        "System.Reflection",
        "System.Runtime.InteropServices",
        "System.Runtime.Intrinsics",
        "System.Runtime.Loader",
        "System.Security.Cryptography",
        "System.Timers",
    ];

    private static readonly string[] ForbiddenTypeNames =
    [
        "System.AppContext",
        "System.Activator",
        "System.AppDomain",
        "System.Console",
        "System.Environment",
        "System.GC",
        "System.HashCode",
        "System.Runtime.CompilerServices.AsyncVoidMethodBuilder",
        "System.Runtime.CompilerServices.ModuleInitializerAttribute",
        "System.OperatingSystem",
        "System.Random",
        "System.TimeProvider",
        "System.TimeZoneInfo",
        "System.Threading.SynchronizationContext",
        "System.Threading.CancellationTokenSource",
        "System.Threading.AutoResetEvent",
        "System.Threading.Barrier",
        "System.Threading.CountdownEvent",
        "System.Threading.EventWaitHandle",
        "System.Threading.ManualResetEvent",
        "System.Threading.ManualResetEventSlim",
        "System.Threading.Monitor",
        "System.Threading.Mutex",
        "System.Threading.NativeOverlapped",
        "System.Threading.PeriodicTimer",
        "System.Threading.ReaderWriterLock",
        "System.Threading.ReaderWriterLockSlim",
        "System.Threading.RegisteredWaitHandle",
        "System.Threading.Semaphore",
        "System.Threading.SemaphoreSlim",
        "System.Threading.SpinLock",
        "System.Threading.SpinWait",
        "System.Threading.Thread",
        "System.Threading.ThreadPool",
        "System.Threading.Timer",
        "System.Threading.WaitHandle",
        "System.Threading.Tasks.Parallel",
        "System.Threading.Tasks.TaskCompletionSource",
        "System.Threading.Tasks.TaskFactory",
        "System.Threading.Tasks.TaskScheduler",
        "System.Linq.ParallelEnumerable",
    ];

    public static List<VerifierDiagnostic> Inspect(
        byte[] assemblyBytes,
        IReadOnlyCollection<string> allowedAssemblyNames)
    {
        var diagnostics = new List<VerifierDiagnostic>();
        using var stream = new MemoryStream(assemblyBytes, writable: false);
        using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        if (!peReader.HasMetadata)
        {
            Add(diagnostics, "DAXV2200", "The candidate output is not a managed assembly.");
            return diagnostics;
        }

        var reader = peReader.GetMetadataReader();
        foreach (var handle in reader.AssemblyReferences)
        {
            var reference = reader.GetAssemblyReference(handle);
            var name = reader.GetString(reference.Name);
            if (!allowedAssemblyNames.Contains(name, StringComparer.Ordinal))
            {
                Add(diagnostics, "DAXV2201", $"Assembly reference '{name}' is outside the frozen closure.");
            }
        }

        foreach (var handle in reader.TypeReferences)
        {
            var reference = reader.GetTypeReference(handle);
            var typeName = JoinTypeName(reader.GetString(reference.Namespace), reader.GetString(reference.Name));
            if (IsForbiddenType(typeName))
            {
                Add(diagnostics, "DAXV2202", $"Type reference '{typeName}' is forbidden.");
            }
        }

        foreach (var handle in reader.MemberReferences)
        {
            var reference = reader.GetMemberReference(handle);
            var parentType = GetTypeName(reader, reference.Parent);
            var memberName = reader.GetString(reference.Name);
            if (IsForbiddenType(parentType) || IsForbiddenMember(parentType, memberName))
            {
                Add(diagnostics, "DAXV2203", $"Member reference '{parentType}.{memberName}' is forbidden.");
            }
        }

        foreach (var handle in reader.TypeDefinitions)
        {
            var definition = reader.GetTypeDefinition(handle);
            if ((definition.Attributes & TypeAttributes.LayoutMask) == TypeAttributes.ExplicitLayout)
            {
                Add(diagnostics, "DAXV2204", "Explicit-layout types are not permitted.");
            }
        }

        foreach (var handle in reader.FieldDefinitions)
        {
            var definition = reader.GetFieldDefinition(handle);
            var attributes = definition.Attributes;
            if ((attributes & FieldAttributes.Static) != 0
                && (attributes & FieldAttributes.Literal) == 0)
            {
                Add(
                    diagnostics,
                    "DAXV2205",
                    $"Static field '{reader.GetString(definition.Name)}' is not a compile-time constant.");
            }
        }

        foreach (var handle in reader.MethodDefinitions)
        {
            var definition = reader.GetMethodDefinition(handle);
            if (reader.GetString(definition.Name) == "Finalize")
            {
                Add(diagnostics, "DAXV2208", "Finalizers are not permitted.");
            }

            if ((definition.Attributes & MethodAttributes.PinvokeImpl) != 0)
            {
                Add(
                    diagnostics,
                    "DAXV2206",
                    $"Method '{reader.GetString(definition.Name)}' uses platform invocation.");
            }

            if (definition.RelativeVirtualAddress == 0)
            {
                continue;
            }

            var body = peReader.GetMethodBody(definition.RelativeVirtualAddress);
            var il = body.GetILBytes();
            if (il is not null && ContainsCalli(il))
            {
                Add(
                    diagnostics,
                    "DAXV2207",
                    $"Method '{reader.GetString(definition.Name)}' contains an indirect native call.");
            }
        }

        return diagnostics;
    }

    private static bool ContainsCalli(byte[] il)
    {
        var index = 0;
        while (index < il.Length)
        {
            ushort opcode = il[index++];
            if (opcode == 0xFE)
            {
                if (index >= il.Length)
                {
                    return true;
                }

                opcode = (ushort)(0xFE00 | il[index++]);
            }

            if (opcode == 0x29)
            {
                return true;
            }

            if (!OperandTypes.TryGetValue(opcode, out var operandType))
            {
                return true;
            }

            var operandLength = operandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or
                OperandType.ShortInlineI or
                OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineBrTarget or
                OperandType.InlineField or
                OperandType.InlineI or
                OperandType.InlineMethod or
                OperandType.InlineSig or
                OperandType.InlineString or
                OperandType.InlineTok or
                OperandType.InlineType or
                OperandType.ShortInlineR => 4,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch when index + 4 <= il.Length =>
                    checked(4 + (BitConverter.ToInt32(il, index) * 4)),
                _ => il.Length,
            };
            if (operandLength < 0 || index + operandLength > il.Length)
            {
                return true;
            }

            index += operandLength;
        }

        return false;
    }

    private static string GetTypeName(MetadataReader reader, EntityHandle handle) =>
        handle.Kind switch
        {
            HandleKind.TypeReference => GetTypeReferenceName(reader, (TypeReferenceHandle)handle),
            HandleKind.TypeDefinition => GetTypeDefinitionName(reader, (TypeDefinitionHandle)handle),
            HandleKind.TypeSpecification => reader.GetTypeSpecification(
                    (TypeSpecificationHandle)handle)
                .DecodeSignature(TypeNameProvider.Instance, genericContext: null),
            _ => string.Empty,
        };

    private static string GetTypeReferenceName(MetadataReader reader, TypeReferenceHandle handle)
    {
        var reference = reader.GetTypeReference(handle);
        return JoinTypeName(reader.GetString(reference.Namespace), reader.GetString(reference.Name));
    }

    private static string GetTypeDefinitionName(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var definition = reader.GetTypeDefinition(handle);
        return JoinTypeName(reader.GetString(definition.Namespace), reader.GetString(definition.Name));
    }

    private static string JoinTypeName(string namespaceName, string name) =>
        string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";

    private static bool IsForbiddenType(string typeName) =>
        (CandidateApiSurface.IsProfileTypeName(typeName)
            && !CandidateApiSurface.IsAllowedTypeName(typeName))
        || (!CompilerGeneratedDiagnosticTypes.Contains(typeName, StringComparer.Ordinal)
        && (IsForbiddenTypeName(typeName)
        || ForbiddenNamespacePrefixes.Any(prefix =>
            typeName.Equals(prefix, StringComparison.Ordinal)
            || typeName.StartsWith(prefix + ".", StringComparison.Ordinal))));

    private static bool IsForbiddenMember(string typeName, string memberName) =>
        (CandidateApiSurface.IsProfileTypeName(typeName)
            && !CandidateApiSurface.IsAllowedMember(typeName, memberName))
        || (!CompilerGeneratedDiagnosticTypes.Contains(typeName, StringComparer.Ordinal)
            && typeName == "System.Type")
        || (typeName is "System.DateTime" or "System.DateTimeOffset"
            && memberName is "get_Now" or "get_UtcNow" or "get_Today")
        || (typeName == "System.Guid" && memberName == "NewGuid")
        || memberName == "GetHashCode"
        || (typeName == "System.Object" && memberName == "GetType")
        || (typeName == "System.Delegate" && memberName == "DynamicInvoke")
        || (typeName.StartsWith("System.", StringComparison.Ordinal)
            && memberName is "BeginInvoke" or "EndInvoke")
        || (typeName == "System.Threading.CancellationToken"
            && memberName is "Register" or "UnsafeRegister")
        || (IsTypeOrGeneric(typeName, "System.IProgress")
            && memberName == "Report")
        || (IsTypeOrGeneric(typeName, "System.Progress")
            && memberName == "Report")
        || (typeName.StartsWith("System.Runtime.CompilerServices.", StringComparison.Ordinal)
            && memberName is "OnCompleted" or "UnsafeOnCompleted")
        || (IsTypeOrGeneric(typeName, "System.Threading.Tasks.Task")
            && memberName is ".ctor" or "Run" or "Start" or "RunSynchronously" or
                "ContinueWith" or "Delay" or "Yield" or "Wait" or "WaitAll" or
                "WaitAny" or "WaitAsync" or "Result" or "get_Result" or "get_Factory")
        || (IsTypeOrGeneric(typeName, "System.Threading.Tasks.ValueTask")
            && memberName is "Result" or "get_Result" or "AsTask")
        || (typeName == "System.Delegate" && memberName == "CreateDelegate")
        || (typeName == "System.Runtime.CompilerServices.RuntimeHelpers"
            && memberName is not "InitializeArray");

    private static bool IsForbiddenTypeName(string typeName) =>
        ForbiddenTypeNames.Contains(typeName, StringComparer.Ordinal)
        || IsTypeOrGeneric(typeName, "System.IProgress")
        || IsTypeOrGeneric(typeName, "System.Progress")
        || IsTypeOrGeneric(typeName, "System.Linq.ParallelQuery")
        || IsTypeOrGeneric(typeName, "System.Threading.Tasks.TaskCompletionSource")
        || typeName.StartsWith("System.Threading.Tasks.TaskFactory", StringComparison.Ordinal)
        || typeName.StartsWith("System.Threading.Tasks.Parallel", StringComparison.Ordinal);

    private static bool IsTypeOrGeneric(string typeName, string definitionName) =>
        typeName.Equals(definitionName, StringComparison.Ordinal)
        || typeName.StartsWith(definitionName + "<", StringComparison.Ordinal)
        || typeName.StartsWith(definitionName + "`", StringComparison.Ordinal);

    private sealed class TypeNameProvider : ISignatureTypeProvider<string, object?>
    {
        public static TypeNameProvider Instance { get; } = new();

        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => $"System.{typeCode}";

        public string GetTypeFromDefinition(
            MetadataReader reader,
            TypeDefinitionHandle handle,
            byte rawTypeKind) =>
            GetTypeDefinitionName(reader, handle);

        public string GetTypeFromReference(
            MetadataReader reader,
            TypeReferenceHandle handle,
            byte rawTypeKind) =>
            GetTypeReferenceName(reader, handle);

        public string GetTypeFromSpecification(
            MetadataReader reader,
            object? genericContext,
            TypeSpecificationHandle handle,
            byte rawTypeKind) =>
            reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);

        public string GetSZArrayType(string elementType) => $"{elementType}[]";
        public string GetArrayType(string elementType, ArrayShape shape) => $"{elementType}[,]";
        public string GetByReferenceType(string elementType) => $"{elementType}&";
        public string GetPointerType(string elementType) => $"{elementType}*";
        public string GetPinnedType(string elementType) => elementType;
        public string GetModifiedType(string modifierType, string unmodifiedType, bool isRequired) =>
            unmodifiedType;
        public string GetGenericInstantiation(
            string genericType,
            ImmutableArray<string> typeArguments) =>
            genericType;
        public string GetGenericMethodParameter(object? genericContext, int index) => $"!!{index}";
        public string GetGenericTypeParameter(object? genericContext, int index) => $"!{index}";
        public string GetFunctionPointerType(MethodSignature<string> signature) => "<function-pointer>";
    }

    private static void Add(
        List<VerifierDiagnostic> diagnostics,
        string code,
        string message) =>
        diagnostics.Add(new("il-policy", code, "error", message));
}
