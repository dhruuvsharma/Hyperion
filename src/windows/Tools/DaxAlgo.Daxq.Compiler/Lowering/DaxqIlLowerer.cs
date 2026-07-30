using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>Blocking ECMA-335 subset verifier and deterministic IL-to-DAXQ lowerer.</summary>
internal static class DaxqIlLowerer
{
    private const string KernelInterface = "DaxAlgo.Sdk.IBacktestStrategy";
    private const string ContextInterface = "DaxAlgo.Sdk.IStrategyContext";
    private static readonly string ContractAssembly =
        typeof(DaxAlgo.Sdk.IBacktestStrategy).Assembly.GetName().Name!;
    private static readonly IReadOnlyDictionary<short, OpCode> OpCodesByValue =
        typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(OpCode))
            .Select(field => (OpCode)field.GetValue(null)!)
            .ToDictionary(opcode => opcode.Value);

    public static DaxqCanonicalProgram Lower(byte[] assemblyImage, string sourceName)
    {
        ArgumentNullException.ThrowIfNull(assemblyImage);
        using var pe = new PEReader(new MemoryStream(assemblyImage, writable: false));
        if (!pe.HasMetadata)
            Fail("DAXQ2000", "Roslyn output is not a managed assembly.", sourceName);

        var metadata = pe.GetMetadataReader();
        var provider = new DaxqSignatureTypeProvider();
        var kernel = FindKernel(metadata, sourceName);
        ValidateAssemblySurface(metadata, kernel, sourceName);
        var state = ReadState(metadata, provider, kernel, sourceName);
        ValidateConstructors(pe, metadata, kernel, state.FieldSlots, sourceName);

        var methods = FindEntrypoints(metadata, provider, kernel, sourceName);
        var constants = new ConstantPoolBuilder();
        var referencedHosts = new HashSet<HostFn>();
        var referencedParameterIds = new SortedSet<long>();
        var entrypoints = new List<DaxqCanonicalEntrypoint>(methods.Count);
        foreach (var method in methods.OrderBy(pair => pair.Key))
        {
            entrypoints.Add(LowerMethod(
                pe,
                metadata,
                provider,
                method.Key,
                method.Value,
                state.FieldSlots,
                constants,
                referencedHosts,
                referencedParameterIds,
                sourceName));
        }

        return new DaxqCanonicalProgram(constants.Values, state.Types, entrypoints)
        {
            ReferencedHostFunctions = referencedHosts,
            ReferencedParameterIds = referencedParameterIds.ToArray(),
        };
    }

    private static TypeDefinitionHandle FindKernel(MetadataReader metadata, string sourceName)
    {
        var candidates = new List<TypeDefinitionHandle>();
        foreach (var handle in metadata.TypeDefinitions)
        {
            var definition = metadata.GetTypeDefinition(handle);
            if ((definition.Attributes & TypeAttributes.Interface) != 0 ||
                (definition.Attributes & TypeAttributes.Abstract) != 0)
            {
                continue;
            }

            foreach (var implementationHandle in definition.GetInterfaceImplementations())
            {
                var implementation = metadata.GetInterfaceImplementation(implementationHandle);
                if (IsTrustedContractType(metadata, implementation.Interface, KernelInterface))
                {
                    candidates.Add(handle);
                    break;
                }
            }
        }

        if (candidates.Count != 1)
        {
            Fail(
                "DAXQ2001",
                $"Expected exactly one concrete type directly implementing {KernelInterface}; found {candidates.Count}.",
                sourceName);
        }
        return candidates[0];
    }

    private static void ValidateAssemblySurface(
        MetadataReader metadata,
        TypeDefinitionHandle kernel,
        string sourceName)
    {
        foreach (var handle in metadata.TypeDefinitions)
        {
            if (handle == kernel)
                continue;

            var definition = metadata.GetTypeDefinition(handle);
            var name = metadata.GetString(definition.Name);
            if (name == "<Module>")
                continue;

            Fail(
                "DAXQ2032",
                $"Additional type '{FullTypeName(metadata, handle)}' is outside the single-kernel DAXQ subset.",
                sourceName);
        }

        foreach (var handle in metadata.GetTypeDefinition(kernel).GetMethods())
        {
            var method = metadata.GetMethodDefinition(handle);
            var name = metadata.GetString(method.Name);
            if (name == ".ctor" || TryEntrypoint(name, out _))
                continue;

            Fail(
                "DAXQ2033",
                $"Method '{name}' is outside the Initialize/OnBar/OnTick strategy kernel.",
                sourceName);
        }
    }

    private static StateLayout ReadState(
        MetadataReader metadata,
        DaxqSignatureTypeProvider provider,
        TypeDefinitionHandle kernel,
        string sourceName)
    {
        var definition = metadata.GetTypeDefinition(kernel);
        var types = new List<DaxqValueType>();
        var slots = new Dictionary<FieldDefinitionHandle, StateField>();
        foreach (var handle in definition.GetFields())
        {
            var field = metadata.GetFieldDefinition(handle);
            var name = metadata.GetString(field.Name);
            if ((field.Attributes & FieldAttributes.Static) != 0)
                Fail("DAXQ2002", $"Static field '{name}' is outside the DAXQ subset.", sourceName);

            var type = field.DecodeSignature(provider, genericContext: null);
            var vmType = ToVmType(type, $"field '{name}'", sourceName);
            var slot = checked((ushort)types.Count);
            if (slot >= 256)
                Fail("DAXQ2003", "A DAXQ package may declare at most 256 state fields.", sourceName);
            types.Add(vmType);
            slots.Add(handle, new StateField(slot, type));
        }
        return new StateLayout(types, slots);
    }

    private static void ValidateConstructors(
        PEReader pe,
        MetadataReader metadata,
        TypeDefinitionHandle kernel,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> fields,
        string sourceName)
    {
        var definition = metadata.GetTypeDefinition(kernel);
        var instanceConstructors = 0;
        foreach (var handle in definition.GetMethods())
        {
            var method = metadata.GetMethodDefinition(handle);
            var name = metadata.GetString(method.Name);
            if (name == ".cctor")
                Fail("DAXQ2004", "Static constructors are outside the DAXQ subset.", sourceName);
            if (name != ".ctor")
                continue;

            instanceConstructors++;
            var signature = method.DecodeSignature(new DaxqSignatureTypeProvider(), genericContext: null);
            if (signature.ParameterTypes.Length != 0 || method.RelativeVirtualAddress == 0)
                Fail("DAXQ2005", "The strategy must have only a trivial parameterless constructor.", sourceName);

            var body = pe.GetMethodBody(method.RelativeVirtualAddress);
            if (body.ExceptionRegions.Length != 0)
                Fail("DAXQ2005", "The strategy constructor cannot contain exception handling.", sourceName);
            var instructions = IlDecoder.Decode(body.GetILBytes().ToImmutableArray(), sourceName, ".ctor");
            var meaningful = instructions.Where(instruction => instruction.OpCode != OpCodes.Nop).ToArray();
            if (meaningful.Length != 3 ||
                meaningful[0].OpCode != OpCodes.Ldarg_0 ||
                meaningful[1].OpCode != OpCodes.Call ||
                meaningful[2].OpCode != OpCodes.Ret ||
                !IsObjectConstructor(metadata, meaningful[1].TokenOperand))
            {
                Fail(
                    "DAXQ2005",
                    "Constructor logic and field initializers are not lowered; initialize scalar state in Initialize instead.",
                    sourceName);
            }
        }

        if (instanceConstructors != 1)
            Fail("DAXQ2005", "The strategy must have exactly one trivial parameterless constructor.", sourceName);
    }

    private static SortedDictionary<DaxqEntrypoint, MethodDefinitionHandle> FindEntrypoints(
        MetadataReader metadata,
        DaxqSignatureTypeProvider provider,
        TypeDefinitionHandle kernel,
        string sourceName)
    {
        var found = new SortedDictionary<DaxqEntrypoint, MethodDefinitionHandle>();
        foreach (var handle in metadata.GetTypeDefinition(kernel).GetMethods())
        {
            var method = metadata.GetMethodDefinition(handle);
            var name = metadata.GetString(method.Name);
            if (!TryEntrypoint(name, out var entrypoint))
                continue;
            if (found.ContainsKey(entrypoint))
                Fail("DAXQ2006", $"Entrypoint '{name}' is overloaded; exactly one signature is allowed.", sourceName);

            ValidateEntrypointSignature(metadata, provider, method, name, entrypoint, sourceName);
            found.Add(entrypoint, handle);
        }

        if (!found.ContainsKey(DaxqEntrypoint.OnBar) && !found.ContainsKey(DaxqEntrypoint.OnTick))
            Fail("DAXQ2007", "Implement OnBar or OnTick; inherited default methods are not packaged.", sourceName);
        return found;
    }

    private static void ValidateEntrypointSignature(
        MetadataReader metadata,
        DaxqSignatureTypeProvider provider,
        MethodDefinition method,
        string name,
        DaxqEntrypoint entrypoint,
        string sourceName)
    {
        if ((method.Attributes & MethodAttributes.Static) != 0 ||
            (method.Attributes & MethodAttributes.Public) == 0 ||
            method.RelativeVirtualAddress == 0)
        {
            Fail("DAXQ2008", $"Entrypoint '{name}' must be a public instance method with a body.", sourceName);
        }

        var signature = method.DecodeSignature(provider, genericContext: null);
        IlType[] expected = entrypoint switch
        {
            DaxqEntrypoint.Initialize or DaxqEntrypoint.OnBar => [IlType.Context],
            DaxqEntrypoint.OnTick =>
                [IlType.Context, IlType.F64, IlType.F64, IlType.F64, IlType.F64],
            _ => throw new InvalidOperationException(),
        };
        if (signature.ReturnType != IlType.Void ||
            signature.GenericParameterCount != 0 ||
            !signature.ParameterTypes.SequenceEqual(expected))
        {
            Fail("DAXQ2009", $"Entrypoint '{name}' does not match the frozen SDK ABI 3 signature.", sourceName);
        }
    }

    private static DaxqCanonicalEntrypoint LowerMethod(
        PEReader pe,
        MetadataReader metadata,
        DaxqSignatureTypeProvider provider,
        DaxqEntrypoint entrypoint,
        MethodDefinitionHandle methodHandle,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> state,
        ConstantPoolBuilder constants,
        ISet<HostFn> referencedHosts,
        ISet<long> referencedParameterIds,
        string sourceName)
    {
        var method = metadata.GetMethodDefinition(methodHandle);
        var methodName = metadata.GetString(method.Name);
        var body = pe.GetMethodBody(method.RelativeVirtualAddress);
        if (body.ExceptionRegions.Length != 0)
            Fail("DAXQ2010", $"Entrypoint '{methodName}' cannot contain exception handling.", sourceName);

        var locals = ReadLocals(metadata, provider, body.LocalSignature, methodName, sourceName);
        if (locals.Length > 256)
            Fail("DAXQ2011", $"Entrypoint '{methodName}' declares more than 256 locals.", sourceName);
        var instructions = IlDecoder.Decode(body.GetILBytes().ToImmutableArray(), sourceName, methodName);
        if (instructions.Count == 0)
            Fail("DAXQ2012", $"Entrypoint '{methodName}' has an empty IL body.", sourceName);

        var analysis = Analyze(
            metadata,
            entrypoint,
            methodName,
            instructions,
            locals,
            state,
            referencedHosts,
            referencedParameterIds,
            sourceName);
        var bytecode = Translate(
            metadata,
            entrypoint,
            methodName,
            instructions,
            analysis,
            state,
            constants,
            sourceName);
        return new DaxqCanonicalEntrypoint(entrypoint, checked((ushort)locals.Length), bytecode);
    }

    private static IlType[] ReadLocals(
        MetadataReader metadata,
        DaxqSignatureTypeProvider provider,
        StandaloneSignatureHandle signatureHandle,
        string methodName,
        string sourceName)
    {
        if (signatureHandle.IsNil)
            return [];
        var locals = metadata.GetStandaloneSignature(signatureHandle)
            .DecodeLocalSignature(provider, genericContext: null)
            .ToArray();
        for (var index = 0; index < locals.Length; index++)
        {
            if (!locals[index].IsScalar)
                Fail("DAXQ2013", $"Local {index} in '{methodName}' is not i64, f64, or bool.", sourceName);
        }
        return locals;
    }

    private static AnalysisResult Analyze(
        MetadataReader metadata,
        DaxqEntrypoint entrypoint,
        string methodName,
        IReadOnlyList<IlInstruction> instructions,
        IReadOnlyList<IlType> locals,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> state,
        ISet<HostFn> referencedHosts,
        ISet<long> referencedParameterIds,
        string sourceName)
    {
        var byOffset = instructions.Select((instruction, index) => (instruction.Offset, index))
            .ToDictionary(pair => pair.Offset, pair => pair.index);
        var incoming = new Dictionary<int, ImmutableArray<StackValue>>
        {
            [instructions[0].Offset] = [],
        };
        var queue = new Queue<int>();
        queue.Enqueue(instructions[0].Offset);
        var boolConstants = new HashSet<int>();

        while (queue.TryDequeue(out var offset))
        {
            var index = byOffset[offset];
            var instruction = instructions[index];
            var stack = incoming[offset].ToList();
            ApplyStackEffect(
                metadata,
                entrypoint,
                methodName,
                instruction,
                stack,
                locals,
                state,
                boolConstants,
                referencedHosts,
                referencedParameterIds,
                sourceName);

            foreach (var successor in Successors(instruction, index, instructions))
            {
                if (!byOffset.ContainsKey(successor))
                    Fail("DAXQ2014", $"Branch in '{methodName}' targets invalid IL offset 0x{successor:x4}.", sourceName);
                var outgoing = stack.ToImmutableArray();
                if (!incoming.TryGetValue(successor, out var existing))
                {
                    incoming.Add(successor, outgoing);
                    queue.Enqueue(successor);
                }
                else if (!StackEquals(existing, outgoing))
                {
                    Fail("DAXQ2015", $"Entrypoint '{methodName}' has a type-inconsistent stack merge.", sourceName);
                }
            }
        }

        var unreachable = instructions.FirstOrDefault(instruction => !incoming.ContainsKey(instruction.Offset));
        if (unreachable is not null)
        {
            Fail(
                "DAXQ2016",
                $"Entrypoint '{methodName}' contains unreachable IL at 0x{unreachable.Offset:x4}.",
                sourceName);
        }
        return new AnalysisResult(incoming, boolConstants);
    }

    private static void ApplyStackEffect(
        MetadataReader metadata,
        DaxqEntrypoint entrypoint,
        string methodName,
        IlInstruction instruction,
        List<StackValue> stack,
        IReadOnlyList<IlType> locals,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> state,
        ISet<int> boolConstants,
        ISet<HostFn> referencedHosts,
        ISet<long> referencedParameterIds,
        string sourceName)
    {
        var opcode = instruction.OpCode;
        if (opcode == OpCodes.Nop)
            return;
        if (TryLoadArgument(opcode, instruction, out var argument))
        {
            stack.Add(new StackValue(ArgumentType(entrypoint, argument, methodName, instruction.Offset, sourceName), instruction.Offset));
            return;
        }
        if (TryLoadLocal(opcode, instruction, out var local))
        {
            stack.Add(new StackValue(LocalType(locals, local, methodName, instruction.Offset, sourceName), instruction.Offset));
            return;
        }
        if (TryStoreLocal(opcode, instruction, out local))
        {
            var expected = LocalType(locals, local, methodName, instruction.Offset, sourceName);
            PopExpected(stack, expected, methodName, instruction, boolConstants, sourceName);
            return;
        }
        if (TryInt32Constant(opcode, instruction, out var int32))
        {
            stack.Add(new StackValue(IlType.I4, instruction.Offset, int32));
            return;
        }
        if (opcode == OpCodes.Ldc_I8)
        {
            stack.Add(new StackValue(IlType.I64, instruction.Offset, instruction.Int64Operand));
            return;
        }
        if (opcode == OpCodes.Ldc_R8)
        {
            if (!double.IsFinite(instruction.DoubleOperand))
                Fail("DAXQ2017", $"'{methodName}' contains a non-finite f64 constant.", sourceName);
            stack.Add(new StackValue(
                IlType.F64,
                instruction.Offset,
                DoubleConstant: instruction.DoubleOperand));
            return;
        }
        if (opcode == OpCodes.Ldc_R4)
            FailUnsupported(methodName, instruction, "binary32 constants", sourceName);

        if (opcode is var _ && (opcode == OpCodes.Add || opcode == OpCodes.Add_Ovf ||
                               opcode == OpCodes.Sub || opcode == OpCodes.Sub_Ovf ||
                               opcode == OpCodes.Mul || opcode == OpCodes.Mul_Ovf ||
                               opcode == OpCodes.Div || opcode == OpCodes.Rem))
        {
            var right = PopNumeric(stack, methodName, instruction, sourceName);
            var left = PopNumeric(stack, methodName, instruction, sourceName);
            if (left.Type == IlType.I4 && right.Type == IlType.I4)
            {
                Fail(
                    "DAXQ2018",
                    $"Int32 arithmetic in '{methodName}' at IL 0x{instruction.Offset:x4} cannot preserve VM parity; use Int64.",
                    sourceName);
            }
            var common = CommonNumeric(left.Type, right.Type, methodName, instruction, sourceName);
            if (common.IsInteger &&
                (opcode == OpCodes.Add || opcode == OpCodes.Sub || opcode == OpCodes.Mul))
            {
                Fail(
                    "DAXQ2018",
                    $"Unchecked integer arithmetic in '{methodName}' at IL 0x{instruction.Offset:x4} cannot preserve VM parity.",
                    sourceName);
            }
            stack.Add(new StackValue(common, instruction.Offset));
            return;
        }
        if (opcode == OpCodes.Neg)
        {
            var value = PopNumeric(stack, methodName, instruction, sourceName);
            if (value.Type.IsInteger)
                Fail("DAXQ2018", $"Unchecked integer negation in '{methodName}' cannot preserve VM parity.", sourceName);
            stack.Add(new StackValue(value.Type, instruction.Offset));
            return;
        }
        if (opcode == OpCodes.And || opcode == OpCodes.Or)
        {
            PopExpected(stack, IlType.Bool, methodName, instruction, boolConstants, sourceName);
            PopExpected(stack, IlType.Bool, methodName, instruction, boolConstants, sourceName);
            stack.Add(new StackValue(IlType.Bool, instruction.Offset));
            return;
        }
        if (opcode == OpCodes.Ceq)
        {
            var right = Pop(stack, methodName, instruction, sourceName);
            var left = Pop(stack, methodName, instruction, sourceName);
            HarmonizeEquality(left, right, boolConstants, methodName, instruction, sourceName);
            stack.Add(new StackValue(IlType.Bool, instruction.Offset));
            return;
        }
        if (opcode == OpCodes.Clt || opcode == OpCodes.Clt_Un ||
            opcode == OpCodes.Cgt || opcode == OpCodes.Cgt_Un)
        {
            var right = PopNumeric(stack, methodName, instruction, sourceName);
            var left = PopNumeric(stack, methodName, instruction, sourceName);
            _ = CommonNumeric(left.Type, right.Type, methodName, instruction, sourceName);
            stack.Add(new StackValue(IlType.Bool, instruction.Offset));
            return;
        }
        if (opcode == OpCodes.Conv_I8)
        {
            var value = Pop(stack, methodName, instruction, sourceName);
            if (!value.Type.IsInteger)
                TypeFail(methodName, instruction, "conv.i8 requires an integer", sourceName);
            stack.Add(value with { Type = IlType.I64 });
            return;
        }
        if (opcode == OpCodes.Conv_R8)
        {
            var value = Pop(stack, methodName, instruction, sourceName);
            if (!value.Type.IsInteger)
                TypeFail(methodName, instruction, "conv.r8 requires an integer", sourceName);
            stack.Add(new StackValue(
                IlType.F64,
                instruction.Offset,
                DoubleConstant: value.Int64Constant is { } integer ? integer : null));
            return;
        }
        if (opcode == OpCodes.Ldfld || opcode == OpCodes.Stfld)
        {
            var field = ResolveStateField(metadata, instruction.TokenOperand, state, methodName, instruction, sourceName);
            if (opcode == OpCodes.Ldfld)
            {
                PopExpected(stack, IlType.This, methodName, instruction, boolConstants, sourceName);
                stack.Add(new StackValue(field.Type, instruction.Offset));
            }
            else
            {
                PopExpected(stack, field.Type, methodName, instruction, boolConstants, sourceName);
                PopExpected(stack, IlType.This, methodName, instruction, boolConstants, sourceName);
            }
            return;
        }
        if (opcode == OpCodes.Call || opcode == OpCodes.Callvirt)
        {
            var call = ResolveHostCall(metadata, instruction.TokenOperand, methodName, instruction, sourceName);
            var arguments = new StackValue[call.Parameters.Length];
            for (var index = call.Parameters.Length - 1; index >= 0; index--)
            {
                arguments[index] = PopExpected(
                    stack,
                    call.Parameters[index],
                    methodName,
                    instruction,
                    boolConstants,
                    sourceName);
            }
            PopExpected(stack, IlType.Context, methodName, instruction, boolConstants, sourceName);
            ValidateHostConstants(call, arguments, methodName, instruction, sourceName);
            referencedHosts.Add(call.Host);
            if (call.Host == HostFn.Param)
            {
                var parameterId = arguments[0].Int64Constant;
                if (parameterId is null || parameterId < 0 || parameterId > byte.MaxValue)
                {
                    Fail(
                        "DAXQ2029",
                        $"Parameter ID in '{methodName}' at IL 0x{instruction.Offset:x4} must be a constant in [0,255].",
                        sourceName);
                }
                referencedParameterIds.Add(parameterId.Value);
            }
            if (call.ReturnType != IlType.Void)
                stack.Add(new StackValue(call.ReturnType, instruction.Offset));
            return;
        }
        if (IsComparisonBranch(opcode, out _))
        {
            var right = Pop(stack, methodName, instruction, sourceName);
            var left = Pop(stack, methodName, instruction, sourceName);
            HarmonizeComparisonBranch(left, right, boolConstants, methodName, instruction, sourceName);
            return;
        }
        if (opcode == OpCodes.Brtrue || opcode == OpCodes.Brtrue_S ||
            opcode == OpCodes.Brfalse || opcode == OpCodes.Brfalse_S)
        {
            PopExpected(stack, IlType.Bool, methodName, instruction, boolConstants, sourceName);
            return;
        }
        if (opcode == OpCodes.Br || opcode == OpCodes.Br_S)
            return;
        if (opcode == OpCodes.Ret)
        {
            if (stack.Count != 0)
                TypeFail(methodName, instruction, "RET requires an empty evaluation stack", sourceName);
            return;
        }

        FailUnsupported(methodName, instruction, opcode.Name ?? "unknown IL", sourceName);
    }

    private static byte[] Translate(
        MetadataReader metadata,
        DaxqEntrypoint entrypoint,
        string methodName,
        IReadOnlyList<IlInstruction> instructions,
        AnalysisResult analysis,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> state,
        ConstantPoolBuilder constants,
        string sourceName)
    {
        var output = new List<byte>();
        var ilToBytecode = new Dictionary<int, int>();
        var patches = new List<BranchPatch>();

        foreach (var instruction in instructions)
        {
            ilToBytecode[instruction.Offset] = output.Count;
            var opcode = instruction.OpCode;
            if (opcode == OpCodes.Nop ||
                (TryLoadArgument(opcode, instruction, out var argument) && argument <= 1) ||
                opcode == OpCodes.Conv_I8)
            {
                continue;
            }
            if (TryLoadArgument(opcode, instruction, out argument))
            {
                WriteOp(output, Opcode.LD_ARG);
                WriteU16(output, checked((ushort)(argument - 1)));
                continue;
            }
            if (TryLoadLocal(opcode, instruction, out var local))
            {
                WriteOp(output, Opcode.LD_LOC);
                WriteU16(output, checked((ushort)local));
                continue;
            }
            if (TryStoreLocal(opcode, instruction, out local))
            {
                WriteOp(output, Opcode.ST_LOC);
                WriteU16(output, checked((ushort)local));
                continue;
            }
            if (TryInt32Constant(opcode, instruction, out var int32))
            {
                if (analysis.BooleanConstantOffsets.Contains(instruction.Offset))
                {
                    WriteOp(output, Opcode.PUSH_BOOL);
                    output.Add(checked((byte)int32));
                }
                else
                {
                    WriteOp(output, Opcode.PUSH_I64);
                    WriteU16(output, constants.Add(DaxqConstant.FromInt64(int32)));
                }
                continue;
            }
            if (opcode == OpCodes.Ldc_I8)
            {
                WriteOp(output, Opcode.PUSH_I64);
                WriteU16(output, constants.Add(DaxqConstant.FromInt64(instruction.Int64Operand)));
                continue;
            }
            if (opcode == OpCodes.Ldc_R8)
            {
                WriteOp(output, Opcode.PUSH_F64);
                WriteU16(output, constants.Add(DaxqConstant.FromDouble(instruction.DoubleOperand)));
                continue;
            }
            if (TrySimpleOpcode(opcode, analysis.Incoming[instruction.Offset], out var vmOpcode))
            {
                WriteOp(output, vmOpcode);
                continue;
            }
            if (opcode == OpCodes.Conv_R8)
            {
                WriteOp(output, Opcode.I2F);
                continue;
            }
            if (opcode == OpCodes.Ldfld || opcode == OpCodes.Stfld)
            {
                var field = ResolveStateField(metadata, instruction.TokenOperand, state, methodName, instruction, sourceName);
                WriteOp(output, opcode == OpCodes.Ldfld ? Opcode.LD_STATE : Opcode.ST_STATE);
                WriteU16(output, field.Slot);
                continue;
            }
            if (opcode == OpCodes.Call || opcode == OpCodes.Callvirt)
            {
                var call = ResolveHostCall(metadata, instruction.TokenOperand, methodName, instruction, sourceName);
                WriteOp(output, Opcode.CALL_HOST);
                WriteU16(output, (ushort)call.Host);
                output.Add(checked((byte)call.Parameters.Length));
                continue;
            }
            if (IsComparisonBranch(opcode, out var comparison))
            {
                WriteOp(output, comparison);
                WriteBranch(output, Opcode.BRT, instruction.BranchTarget, patches);
                continue;
            }
            if (opcode == OpCodes.Brtrue || opcode == OpCodes.Brtrue_S)
            {
                WriteBranch(output, Opcode.BRT, instruction.BranchTarget, patches);
                continue;
            }
            if (opcode == OpCodes.Brfalse || opcode == OpCodes.Brfalse_S)
            {
                WriteBranch(output, Opcode.BRF, instruction.BranchTarget, patches);
                continue;
            }
            if (opcode == OpCodes.Br || opcode == OpCodes.Br_S)
            {
                WriteBranch(output, Opcode.BR, instruction.BranchTarget, patches);
                continue;
            }
            if (opcode == OpCodes.Ret)
            {
                WriteOp(output, Opcode.RET);
                continue;
            }
            FailUnsupported(methodName, instruction, opcode.Name ?? "unknown IL", sourceName);
        }
        ilToBytecode[instructions[^1].EndOffset] = output.Count;

        var branchBytes = new byte[sizeof(int)];
        foreach (var patch in patches)
        {
            if (!ilToBytecode.TryGetValue(patch.TargetIlOffset, out var target))
                Fail("DAXQ2014", $"Branch in '{methodName}' has no lowerable target.", sourceName);
            var delta = checked(target - (patch.OperandOffset + sizeof(int)));
            BinaryPrimitives.WriteInt32LittleEndian(branchBytes, delta);
            for (var index = 0; index < branchBytes.Length; index++)
                output[patch.OperandOffset + index] = branchBytes[index];
        }
        return output.ToArray();
    }

    private static IEnumerable<int> Successors(
        IlInstruction instruction,
        int index,
        IReadOnlyList<IlInstruction> instructions)
    {
        var opcode = instruction.OpCode;
        if (opcode == OpCodes.Ret)
            yield break;
        if (opcode == OpCodes.Br || opcode == OpCodes.Br_S)
        {
            yield return instruction.BranchTarget;
            yield break;
        }
        if (opcode.FlowControl == FlowControl.Cond_Branch)
        {
            if (opcode == OpCodes.Switch)
                yield break;
            yield return instruction.BranchTarget;
        }
        if (index + 1 < instructions.Count)
            yield return instructions[index + 1].Offset;
        else
            Fail("DAXQ2019", "Control flow falls off the end of an entrypoint.", null);
    }

    private static bool TrySimpleOpcode(
        OpCode opcode,
        ImmutableArray<StackValue> incoming,
        out Opcode result)
    {
        if (opcode == OpCodes.Add || opcode == OpCodes.Add_Ovf) result = Opcode.ADD;
        else if (opcode == OpCodes.Sub || opcode == OpCodes.Sub_Ovf) result = Opcode.SUB;
        else if (opcode == OpCodes.Mul || opcode == OpCodes.Mul_Ovf) result = Opcode.MUL;
        else if (opcode == OpCodes.Div) result = Opcode.DIV;
        else if (opcode == OpCodes.Rem) result = Opcode.MOD;
        else if (opcode == OpCodes.Neg) result = Opcode.NEG;
        else if (opcode == OpCodes.Ceq) result = Opcode.CEQ;
        else if (opcode == OpCodes.Clt || opcode == OpCodes.Clt_Un) result = Opcode.CLT;
        else if (opcode == OpCodes.Cgt || opcode == OpCodes.Cgt_Un) result = Opcode.CGT;
        else if (opcode == OpCodes.And) result = Opcode.AND;
        else if (opcode == OpCodes.Or) result = Opcode.OR;
        else
        {
            result = default;
            return false;
        }
        return true;
    }

    private static bool IsComparisonBranch(OpCode opcode, out Opcode comparison)
    {
        if (opcode == OpCodes.Beq || opcode == OpCodes.Beq_S) comparison = Opcode.CEQ;
        else if (opcode == OpCodes.Bne_Un || opcode == OpCodes.Bne_Un_S) comparison = Opcode.CNE;
        else if (opcode == OpCodes.Blt || opcode == OpCodes.Blt_S ||
                 opcode == OpCodes.Blt_Un || opcode == OpCodes.Blt_Un_S) comparison = Opcode.CLT;
        else if (opcode == OpCodes.Ble || opcode == OpCodes.Ble_S ||
                 opcode == OpCodes.Ble_Un || opcode == OpCodes.Ble_Un_S) comparison = Opcode.CLE;
        else if (opcode == OpCodes.Bgt || opcode == OpCodes.Bgt_S ||
                 opcode == OpCodes.Bgt_Un || opcode == OpCodes.Bgt_Un_S) comparison = Opcode.CGT;
        else if (opcode == OpCodes.Bge || opcode == OpCodes.Bge_S ||
                 opcode == OpCodes.Bge_Un || opcode == OpCodes.Bge_Un_S) comparison = Opcode.CGE;
        else
        {
            comparison = default;
            return false;
        }
        return true;
    }

    private static void HarmonizeComparisonBranch(
        StackValue left,
        StackValue right,
        ISet<int> boolConstants,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        if (IsEqualityOnlyBranch(instruction.OpCode))
            HarmonizeEquality(left, right, boolConstants, methodName, instruction, sourceName);
        else
            _ = CommonNumeric(left.Type, right.Type, methodName, instruction, sourceName);
    }

    private static bool IsEqualityOnlyBranch(OpCode opcode) =>
        opcode == OpCodes.Beq || opcode == OpCodes.Beq_S ||
        opcode == OpCodes.Bne_Un || opcode == OpCodes.Bne_Un_S;

    private static void HarmonizeEquality(
        StackValue left,
        StackValue right,
        ISet<int> boolConstants,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        if (left.Type == right.Type || (left.Type.IsInteger && right.Type.IsInteger))
            return;
        if (left.Type == IlType.Bool && MarkBooleanConstant(right, boolConstants))
            return;
        if (right.Type == IlType.Bool && MarkBooleanConstant(left, boolConstants))
            return;
        TypeFail(methodName, instruction, "equality operands have different scalar types", sourceName);
    }

    private static StackValue PopExpected(
        List<StackValue> stack,
        IlType expected,
        string methodName,
        IlInstruction instruction,
        ISet<int> boolConstants,
        string sourceName)
    {
        var value = Pop(stack, methodName, instruction, sourceName);
        if (value.Type == expected || (value.Type.IsInteger && expected.IsInteger))
            return value;
        if (expected == IlType.Bool && MarkBooleanConstant(value, boolConstants))
            return value with { Type = IlType.Bool };
        TypeFail(methodName, instruction, $"expected {expected}, found {value.Type}", sourceName);
        return default;
    }

    private static bool MarkBooleanConstant(StackValue value, ISet<int> boolConstants)
    {
        if (value.Type != IlType.I4 || value.Int64Constant is not (0 or 1))
            return false;
        boolConstants.Add(value.ProducerOffset);
        return true;
    }

    private static StackValue PopNumeric(
        List<StackValue> stack,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        var value = Pop(stack, methodName, instruction, sourceName);
        if (!value.Type.IsNumeric)
            TypeFail(methodName, instruction, $"expected a numeric value, found {value.Type}", sourceName);
        return value;
    }

    private static StackValue Pop(
        List<StackValue> stack,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        if (stack.Count == 0)
            TypeFail(methodName, instruction, "evaluation stack underflow", sourceName);
        var index = stack.Count - 1;
        var value = stack[index];
        stack.RemoveAt(index);
        return value;
    }

    private static IlType CommonNumeric(
        IlType left,
        IlType right,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        if (left == IlType.F64 && right == IlType.F64)
            return IlType.F64;
        if (left.IsInteger && right.IsInteger)
            return IlType.I64;
        TypeFail(methodName, instruction, "numeric operands must have the same type", sourceName);
        return default;
    }

    private static IlType ArgumentType(
        DaxqEntrypoint entrypoint,
        int index,
        string methodName,
        int offset,
        string sourceName)
    {
        if (index == 0)
            return IlType.This;
        if (index == 1)
            return IlType.Context;
        if (entrypoint == DaxqEntrypoint.OnTick && index is >= 2 and <= 5)
            return IlType.F64;
        Fail("DAXQ2020", $"Invalid argument {index} in '{methodName}' at IL 0x{offset:x4}.", sourceName);
        return default;
    }

    private static IlType LocalType(
        IReadOnlyList<IlType> locals,
        int index,
        string methodName,
        int offset,
        string sourceName)
    {
        if ((uint)index >= (uint)locals.Count)
            Fail("DAXQ2021", $"Invalid local {index} in '{methodName}' at IL 0x{offset:x4}.", sourceName);
        return locals[index];
    }

    private static StateField ResolveStateField(
        MetadataReader metadata,
        int token,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> fields,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        EntityHandle handle;
        try { handle = MetadataTokens.EntityHandle(token); }
        catch (ArgumentException) { handle = default; }
        if (handle.Kind != HandleKind.FieldDefinition)
        {
            Fail(
                "DAXQ2022",
                $"'{methodName}' accesses a field outside its scalar strategy state at IL 0x{instruction.Offset:x4}.",
                sourceName);
        }
        if (!fields.TryGetValue((FieldDefinitionHandle)handle, out var field))
        {
            Fail(
                "DAXQ2022",
                $"'{methodName}' accesses a field outside its scalar strategy state at IL 0x{instruction.Offset:x4}.",
                sourceName);
        }
        return field;
    }

    private static void ValidateHostConstants(
        HostCall call,
        IReadOnlyList<StackValue> arguments,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        static bool Outside(StackValue value, long minimum, long maximum) =>
            value.Int64Constant is { } known && (known < minimum || known > maximum);

        var invalid = call.Host switch
        {
            HostFn.Bar =>
                Outside(arguments[0], 1, 5) || Outside(arguments[1], 0, 65_535),
            HostFn.Ind =>
                Outside(arguments[0], 1, 4) || Outside(arguments[1], 1, 65_535) ||
                Outside(arguments[2], 1, 5) ||
                (arguments[0].Int64Constant == 4 && arguments[2].Int64Constant is not (null or 4)),
            HostFn.Param => Outside(arguments[0], 0, byte.MaxValue),
            HostFn.Emit =>
                Outside(arguments[0], -1, 1) ||
                arguments[1].DoubleConstant is { } strength && (strength < 0d || strength > 1d) ||
                arguments[2].Int64Constant is { } note && note < 0,
            HostFn.Log => arguments[0].Int64Constant is { } message && message < 0,
            _ => false,
        };
        if (invalid)
        {
            Fail(
                "DAXQ2031",
                $"Host call '{call.Host}' in '{methodName}' at IL 0x{instruction.Offset:x4} has a constant argument outside the frozen ABI 3 bounds.",
                sourceName);
        }
    }

    private static HostCall ResolveHostCall(
        MetadataReader metadata,
        int token,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        EntityHandle handle;
        try { handle = MetadataTokens.EntityHandle(token); }
        catch (ArgumentException) { handle = default; }
        if (handle.Kind != HandleKind.MemberReference)
            RejectCall(metadata, handle, methodName, instruction, sourceName);

        var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
        var owner = FullTypeName(metadata, member.Parent);
        var name = metadata.GetString(member.Name);
        if (owner != ContextInterface || !IsTrustedContractType(metadata, member.Parent, ContextInterface))
            RejectCall(metadata, handle, methodName, instruction, sourceName);

        var signature = member.DecodeMethodSignature(new DaxqSignatureTypeProvider(), genericContext: null);
        var expected = name switch
        {
            "Indicator" => new HostCall(HostFn.Ind, [IlType.I64, IlType.I64, IlType.I64], IlType.F64),
            "Emit" => new HostCall(HostFn.Emit, [IlType.I64, IlType.F64, IlType.I64], IlType.Void),
            "Param" => new HostCall(HostFn.Param, [IlType.I64], IlType.F64),
            "Bar" => new HostCall(HostFn.Bar, [IlType.I64, IlType.I64], IlType.F64),
            "TimeIndex" => new HostCall(HostFn.TIndex, [], IlType.I64),
            "Random" => new HostCall(HostFn.Rng, [], IlType.F64),
            "Log" => new HostCall(HostFn.Log, [IlType.I64, IlType.F64], IlType.Void),
            _ => default,
        };
        if (expected.Host == (HostFn)0 ||
            !signature.Header.IsInstance ||
            signature.GenericParameterCount != 0 ||
            signature.ReturnType != expected.ReturnType ||
            !signature.ParameterTypes.SequenceEqual(expected.Parameters))
        {
            RejectCall(metadata, handle, methodName, instruction, sourceName);
        }
        return expected;
    }

    private static void RejectCall(
        MetadataReader metadata,
        EntityHandle handle,
        string methodName,
        IlInstruction instruction,
        string sourceName)
    {
        var target = handle.Kind switch
        {
            HandleKind.MemberReference => MemberName(metadata, (MemberReferenceHandle)handle),
            HandleKind.MethodDefinition => metadata.GetString(metadata.GetMethodDefinition((MethodDefinitionHandle)handle).Name),
            HandleKind.MethodSpecification => "generic method",
            _ => "unresolved method",
        };
        Fail(
            "DAXQ2023",
            $"Call to '{target}' from '{methodName}' at IL 0x{instruction.Offset:x4} is outside the DAXQ host whitelist.",
            sourceName);
    }

    private static bool IsObjectConstructor(MetadataReader metadata, int token)
    {
        EntityHandle handle;
        try { handle = MetadataTokens.EntityHandle(token); }
        catch (ArgumentException) { return false; }
        if (handle.Kind != HandleKind.MemberReference)
            return false;
        var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
        return metadata.GetString(member.Name) == ".ctor" && FullTypeName(metadata, member.Parent) == "System.Object";
    }

    private static string MemberName(MetadataReader metadata, MemberReferenceHandle handle)
    {
        var member = metadata.GetMemberReference(handle);
        return $"{FullTypeName(metadata, member.Parent)}.{metadata.GetString(member.Name)}";
    }

    private static string FullTypeName(MetadataReader metadata, EntityHandle handle)
    {
        return handle.Kind switch
        {
            HandleKind.TypeReference => FullName(metadata,
                metadata.GetTypeReference((TypeReferenceHandle)handle).Namespace,
                metadata.GetTypeReference((TypeReferenceHandle)handle).Name),
            HandleKind.TypeDefinition => FullName(metadata,
                metadata.GetTypeDefinition((TypeDefinitionHandle)handle).Namespace,
                metadata.GetTypeDefinition((TypeDefinitionHandle)handle).Name),
            _ => string.Empty,
        };
    }

    private static bool IsTrustedContractType(
        MetadataReader metadata,
        EntityHandle handle,
        string expectedName)
    {
        if (handle.Kind != HandleKind.TypeReference || FullTypeName(metadata, handle) != expectedName)
            return false;

        var reference = metadata.GetTypeReference((TypeReferenceHandle)handle);
        if (reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
            return false;
        var assembly = metadata.GetAssemblyReference((AssemblyReferenceHandle)reference.ResolutionScope);
        return metadata.GetString(assembly.Name) == ContractAssembly;
    }

    private static string FullName(MetadataReader metadata, StringHandle nsHandle, StringHandle nameHandle)
    {
        var ns = nsHandle.IsNil ? string.Empty : metadata.GetString(nsHandle);
        var name = metadata.GetString(nameHandle);
        return ns.Length == 0 ? name : $"{ns}.{name}";
    }

    private static bool TryEntrypoint(string name, out DaxqEntrypoint entrypoint)
    {
        if (name == "Initialize") entrypoint = DaxqEntrypoint.Initialize;
        else if (name == "OnBar") entrypoint = DaxqEntrypoint.OnBar;
        else if (name == "OnTick") entrypoint = DaxqEntrypoint.OnTick;
        else
        {
            entrypoint = default;
            return false;
        }
        return true;
    }

    private static bool TryLoadArgument(OpCode opcode, IlInstruction instruction, out int index)
    {
        if (opcode == OpCodes.Ldarg_0) index = 0;
        else if (opcode == OpCodes.Ldarg_1) index = 1;
        else if (opcode == OpCodes.Ldarg_2) index = 2;
        else if (opcode == OpCodes.Ldarg_3) index = 3;
        else if (opcode == OpCodes.Ldarg || opcode == OpCodes.Ldarg_S) index = instruction.VariableOperand;
        else
        {
            index = 0;
            return false;
        }
        return true;
    }

    private static bool TryLoadLocal(OpCode opcode, IlInstruction instruction, out int index)
    {
        if (opcode == OpCodes.Ldloc_0) index = 0;
        else if (opcode == OpCodes.Ldloc_1) index = 1;
        else if (opcode == OpCodes.Ldloc_2) index = 2;
        else if (opcode == OpCodes.Ldloc_3) index = 3;
        else if (opcode == OpCodes.Ldloc || opcode == OpCodes.Ldloc_S) index = instruction.VariableOperand;
        else
        {
            index = 0;
            return false;
        }
        return true;
    }

    private static bool TryStoreLocal(OpCode opcode, IlInstruction instruction, out int index)
    {
        if (opcode == OpCodes.Stloc_0) index = 0;
        else if (opcode == OpCodes.Stloc_1) index = 1;
        else if (opcode == OpCodes.Stloc_2) index = 2;
        else if (opcode == OpCodes.Stloc_3) index = 3;
        else if (opcode == OpCodes.Stloc || opcode == OpCodes.Stloc_S) index = instruction.VariableOperand;
        else
        {
            index = 0;
            return false;
        }
        return true;
    }

    private static bool TryInt32Constant(OpCode opcode, IlInstruction instruction, out long value)
    {
        if (opcode == OpCodes.Ldc_I4_M1) value = -1;
        else if (opcode == OpCodes.Ldc_I4_0) value = 0;
        else if (opcode == OpCodes.Ldc_I4_1) value = 1;
        else if (opcode == OpCodes.Ldc_I4_2) value = 2;
        else if (opcode == OpCodes.Ldc_I4_3) value = 3;
        else if (opcode == OpCodes.Ldc_I4_4) value = 4;
        else if (opcode == OpCodes.Ldc_I4_5) value = 5;
        else if (opcode == OpCodes.Ldc_I4_6) value = 6;
        else if (opcode == OpCodes.Ldc_I4_7) value = 7;
        else if (opcode == OpCodes.Ldc_I4_8) value = 8;
        else if (opcode == OpCodes.Ldc_I4 || opcode == OpCodes.Ldc_I4_S) value = instruction.Int32Operand;
        else
        {
            value = 0;
            return false;
        }
        return true;
    }

    private static DaxqValueType ToVmType(IlType type, string location, string sourceName) => type.Kind switch
    {
        IlTypeKind.I64 => DaxqValueType.I64,
        IlTypeKind.F64 => DaxqValueType.F64,
        IlTypeKind.Bool => DaxqValueType.Bool,
        _ => FailValue<DaxqValueType>("DAXQ2024", $"Unsupported {location} type '{type}'.", sourceName),
    };

    private static bool StackEquals(ImmutableArray<StackValue> left, ImmutableArray<StackValue> right)
    {
        if (left.Length != right.Length)
            return false;
        for (var index = 0; index < left.Length; index++)
        {
            if (left[index].Type != right[index].Type &&
                !(left[index].Type.IsInteger && right[index].Type.IsInteger))
            {
                return false;
            }
        }
        return true;
    }

    private static void WriteOp(List<byte> output, Opcode opcode) => output.Add((byte)opcode);

    private static void WriteU16(List<byte> output, ushort value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
        output.AddRange(bytes);
    }

    private static void WriteBranch(List<byte> output, Opcode opcode, int target, ICollection<BranchPatch> patches)
    {
        WriteOp(output, opcode);
        var operand = output.Count;
        output.AddRange([0, 0, 0, 0]);
        patches.Add(new BranchPatch(operand, target));
    }

    private static void FailUnsupported(string method, IlInstruction instruction, string surface, string sourceName) =>
        Fail(
            "DAXQ2025",
            $"Unsupported IL '{surface}' in '{method}' at 0x{instruction.Offset:x4}.",
            sourceName);

    private static void TypeFail(string method, IlInstruction instruction, string message, string sourceName) =>
        Fail("DAXQ2026", $"Type verification failed in '{method}' at IL 0x{instruction.Offset:x4}: {message}.", sourceName);

    [DoesNotReturn]
    private static void Fail(string code, string message, string? sourceName) =>
        throw new DaxqCompilationException([new DaxqCompilerDiagnostic(code, message, sourceName)]);

    private static T FailValue<T>(string code, string message, string? sourceName)
    {
        Fail(code, message, sourceName);
        return default!;
    }

    private sealed class ConstantPoolBuilder
    {
        private readonly List<DaxqConstant> _values = [];
        private readonly Dictionary<DaxqConstant, ushort> _indices = [];

        public IReadOnlyList<DaxqConstant> Values => _values;

        public ushort Add(DaxqConstant value)
        {
            if (_indices.TryGetValue(value, out var existing))
                return existing;
            var index = checked((ushort)_values.Count);
            _values.Add(value);
            _indices.Add(value, index);
            return index;
        }
    }

    private sealed class DaxqSignatureTypeProvider : ISignatureTypeProvider<IlType, object?>
    {
        public IlType GetArrayType(IlType elementType, ArrayShape shape) => IlType.Unsupported;
        public IlType GetByReferenceType(IlType elementType) => IlType.Unsupported;
        public IlType GetFunctionPointerType(MethodSignature<IlType> signature) => IlType.Unsupported;
        public IlType GetGenericInstantiation(IlType genericType, ImmutableArray<IlType> typeArguments) => IlType.Unsupported;
        public IlType GetGenericMethodParameter(object? genericContext, int index) => IlType.Unsupported;
        public IlType GetGenericTypeParameter(object? genericContext, int index) => IlType.Unsupported;
        public IlType GetModifiedType(IlType modifier, IlType unmodifiedType, bool isRequired) => unmodifiedType;
        public IlType GetPinnedType(IlType elementType) => IlType.Unsupported;
        public IlType GetPointerType(IlType elementType) => IlType.Unsupported;
        public IlType GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
        {
            PrimitiveTypeCode.Void => IlType.Void,
            PrimitiveTypeCode.Boolean => IlType.Bool,
            PrimitiveTypeCode.Int32 => IlType.I4,
            PrimitiveTypeCode.Int64 => IlType.I64,
            PrimitiveTypeCode.Double => IlType.F64,
            _ => IlType.Unsupported,
        };
        public IlType GetSZArrayType(IlType elementType) => IlType.Unsupported;
        public IlType GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) =>
            Named(FullTypeName(reader, handle));
        public IlType GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) =>
            Named(FullTypeName(reader, handle));
        public IlType GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) =>
            IlType.Unsupported;

        private static IlType Named(string name) => name switch
        {
            ContextInterface => IlType.Context,
            "DaxAlgo.Sdk.Ind" or "DaxAlgo.Sdk.BarField" or "DaxAlgo.Sdk.SignalKind" => IlType.I64,
            _ => IlType.Unsupported,
        };
    }

    private static class IlDecoder
    {
        public static IReadOnlyList<IlInstruction> Decode(ImmutableArray<byte> bytes, string sourceName, string methodName)
        {
            var result = new List<IlInstruction>();
            var offset = 0;
            try
            {
                while (offset < bytes.Length)
                {
                    var start = offset;
                    var first = bytes[offset++];
                    short value = first == 0xfe
                        ? unchecked((short)(0xfe00 | bytes[offset++]))
                        : first;
                    if (!OpCodesByValue.TryGetValue(value, out var opcode))
                        Fail("DAXQ2027", $"Unknown IL opcode 0x{value:x4} in '{methodName}'.", sourceName);

                    object? operand = opcode.OperandType switch
                    {
                        OperandType.InlineNone => null,
                        OperandType.ShortInlineI => opcode == OpCodes.Ldc_I4_S
                            ? (int)unchecked((sbyte)bytes[offset++])
                            : (int)bytes[offset++],
                        OperandType.InlineI => ReadI32(bytes, ref offset),
                        OperandType.InlineI8 => ReadI64(bytes, ref offset),
                        OperandType.ShortInlineR => ReadF32(bytes, ref offset),
                        OperandType.InlineR => ReadF64(bytes, ref offset),
                        OperandType.ShortInlineBrTarget => checked(offset + 1 + unchecked((sbyte)bytes[offset++])),
                        OperandType.InlineBrTarget => ReadBranchTarget(bytes, ref offset),
                        OperandType.ShortInlineVar => (int)bytes[offset++],
                        OperandType.InlineVar => (int)ReadU16(bytes, ref offset),
                        OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineType or
                        OperandType.InlineTok or OperandType.InlineString or OperandType.InlineSig => ReadI32(bytes, ref offset),
                        OperandType.InlineSwitch => ReadSwitch(bytes, ref offset),
                        _ => throw new BadImageFormatException(),
                    };
                    result.Add(new IlInstruction(start, offset, opcode, operand));
                }
            }
            catch (Exception exception) when (exception is IndexOutOfRangeException or OverflowException or BadImageFormatException)
            {
                Fail("DAXQ2028", $"Malformed IL in '{methodName}'.", sourceName);
            }
            return result;
        }

        private static ushort ReadU16(ImmutableArray<byte> bytes, ref int offset)
        {
            var value = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
            offset += 2;
            return value;
        }

        private static int ReadI32(ImmutableArray<byte> bytes, ref int offset)
        {
            var value = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset, 4));
            offset += 4;
            return value;
        }

        private static long ReadI64(ImmutableArray<byte> bytes, ref int offset)
        {
            var value = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(offset, 8));
            offset += 8;
            return value;
        }

        private static float ReadF32(ImmutableArray<byte> bytes, ref int offset)
        {
            var value = BinaryPrimitives.ReadSingleLittleEndian(bytes.AsSpan(offset, 4));
            offset += 4;
            return value;
        }

        private static double ReadF64(ImmutableArray<byte> bytes, ref int offset)
        {
            var value = BinaryPrimitives.ReadDoubleLittleEndian(bytes.AsSpan(offset, 8));
            offset += 8;
            return value;
        }

        private static int ReadBranchTarget(ImmutableArray<byte> bytes, ref int offset)
        {
            var delta = ReadI32(bytes, ref offset);
            return checked(offset + delta);
        }

        private static int[] ReadSwitch(ImmutableArray<byte> bytes, ref int offset)
        {
            var count = ReadI32(bytes, ref offset);
            if (count < 0)
                throw new BadImageFormatException();
            var baseOffset = checked(offset + (count * sizeof(int)));
            var targets = new int[count];
            for (var index = 0; index < count; index++)
                targets[index] = checked(baseOffset + ReadI32(bytes, ref offset));
            return targets;
        }
    }

    private enum IlTypeKind
    {
        Unsupported,
        Void,
        I4,
        I64,
        F64,
        Bool,
        This,
        Context,
    }

    private readonly record struct IlType(IlTypeKind Kind)
    {
        public static IlType Unsupported => new(IlTypeKind.Unsupported);
        public static IlType Void => new(IlTypeKind.Void);
        public static IlType I4 => new(IlTypeKind.I4);
        public static IlType I64 => new(IlTypeKind.I64);
        public static IlType F64 => new(IlTypeKind.F64);
        public static IlType Bool => new(IlTypeKind.Bool);
        public static IlType This => new(IlTypeKind.This);
        public static IlType Context => new(IlTypeKind.Context);
        public bool IsInteger => Kind is IlTypeKind.I4 or IlTypeKind.I64;
        public bool IsNumeric => IsInteger || Kind == IlTypeKind.F64;
        public bool IsScalar => Kind is IlTypeKind.I64 or IlTypeKind.F64 or IlTypeKind.Bool;
        public override string ToString() => Kind.ToString().ToLowerInvariant();
    }

    private sealed record IlInstruction(int Offset, int EndOffset, OpCode OpCode, object? Operand)
    {
        public int TokenOperand => Operand is int value ? value : 0;
        public int VariableOperand => Operand is int value ? value : -1;
        public int Int32Operand => Operand is int value ? value : 0;
        public long Int64Operand => Operand is long value ? value : 0;
        public double DoubleOperand => Operand is double value ? value : double.NaN;
        public int BranchTarget => Operand is int value ? value : -1;
    }

    private readonly record struct StackValue(
        IlType Type,
        int ProducerOffset,
        long? Int64Constant = null,
        double? DoubleConstant = null);
    private readonly record struct StateField(ushort Slot, IlType Type);
    private sealed record StateLayout(
        IReadOnlyList<DaxqValueType> Types,
        IReadOnlyDictionary<FieldDefinitionHandle, StateField> FieldSlots);
    private sealed record AnalysisResult(
        IReadOnlyDictionary<int, ImmutableArray<StackValue>> Incoming,
        IReadOnlySet<int> BooleanConstantOffsets);
    private readonly record struct HostCall(HostFn Host, IlType[] Parameters, IlType ReturnType);
    private readonly record struct BranchPatch(int OperandOffset, int TargetIlOffset);
}
