using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Vm;

/// <summary>A fully parsed and statically verified DQXP v1 program.</summary>
public sealed class DaxqProgram : IDisposable
{
    private int _disposed;

    private DaxqProgram(
        byte[] bytecode,
        byte[] constantPoolSection,
        byte[] opcodeMapSection,
        byte[] hostMapSection,
        byte[] entrypointSection,
        DaxqValue[] constants,
        VmType[] stateTypes,
        VerifiedEntrypoint?[] entrypoints)
    {
        Bytecode = bytecode;
        ConstantPoolSection = constantPoolSection;
        OpcodeMapSection = opcodeMapSection;
        HostMapSection = hostMapSection;
        EntrypointSection = entrypointSection;
        Constants = constants;
        StateTypes = stateTypes;
        Entrypoints = entrypoints;
    }

    /// <summary>The number of package-global persistent scalar slots.</summary>
    public int StateSlotCount => StateTypes.Length;

    /// <summary>Returns whether the verified program declares the requested callback.</summary>
    public bool HasEntrypoint(DaxqEntrypoint entrypoint) =>
        (byte)entrypoint < Entrypoints.Length && Entrypoints[(byte)entrypoint] is not null;

    /// <summary>
    /// Strictly parses all six DQXP sections and verifies every bytecode region before returning a
    /// reusable program. The input is decrypted, authenticated plaintext; package decryption is out
    /// of scope for this type.
    /// </summary>
    public static DaxqFault TryLoad(ReadOnlySpan<byte> plaintext, out DaxqProgram? program)
    {
        program = null;
        try
        {
            var fault = TryReadSections(plaintext, out var sections);
            if (fault != DaxqFault.Ok)
                return fault;

            fault = TryReadConstants(sections.ConstantPool, out var constants);
            if (fault != DaxqFault.Ok)
                return fault;

            fault = TryReadOpcodeMap(sections.OpcodeMap, out var opcodeMap);
            if (fault != DaxqFault.Ok)
                return fault;

            fault = TryReadHostMap(sections.HostMap, out var hostMap);
            if (fault != DaxqFault.Ok)
                return fault;

            fault = TryReadEntrypoints(sections.Entrypoints, sections.Bytecode.Length,
                out var stateTypes, out var declarations);
            if (fault != DaxqFault.Ok)
                return fault;

            fault = ValidateWatermark(sections.Watermark);
            if (fault != DaxqFault.Ok)
                return fault;

            var entrypoints = new VerifiedEntrypoint?[3];
            var constantSeen = new bool[constants.Length];
            var nextConstant = 0;
            foreach (var declaration in declarations.OrderBy(item => item.CodeOffset))
            {
                fault = TryDecodeAndVerify(
                    sections.Bytecode,
                    declaration,
                    constants,
                    opcodeMap,
                    hostMap,
                    stateTypes,
                    constantSeen,
                    ref nextConstant,
                    out var verified);
                if (fault != DaxqFault.Ok)
                    return fault;
                entrypoints[(byte)declaration.Id] = verified;
            }
            if (nextConstant != constants.Length)
                return DaxqFault.Verification;

            program = new DaxqProgram(
                sections.Bytecode,
                sections.ConstantPool,
                sections.OpcodeMap,
                sections.HostMap,
                sections.Entrypoints,
                constants,
                stateTypes,
                entrypoints);
            return DaxqFault.Ok;
        }
        catch (ArgumentException)
        {
            return DaxqFault.InvalidFormat;
        }
        catch (OverflowException)
        {
            return DaxqFault.InvalidFormat;
        }
    }

    internal byte[] Bytecode { get; }

    internal byte[] ConstantPoolSection { get; }

    internal byte[] OpcodeMapSection { get; }

    internal byte[] HostMapSection { get; }

    internal byte[] EntrypointSection { get; }

    internal DaxqValue[] Constants { get; }

    internal VmType[] StateTypes { get; }

    internal VerifiedEntrypoint?[] Entrypoints { get; }

    /// <summary>
    /// Clears the decrypted bytecode plus all decoded constants and instructions. A native runtime
    /// owns its private copy before this is called; the managed reference VM keeps the program until
    /// that explicitly selected development/test runtime is disposed.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        CryptographicOperations.ZeroMemory(Bytecode);
        CryptographicOperations.ZeroMemory(ConstantPoolSection);
        CryptographicOperations.ZeroMemory(OpcodeMapSection);
        CryptographicOperations.ZeroMemory(HostMapSection);
        CryptographicOperations.ZeroMemory(EntrypointSection);
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(Constants.AsSpan()));
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(StateTypes.AsSpan()));
        for (var index = 0; index < Entrypoints.Length; index++)
        {
            if (Entrypoints[index] is not { } entrypoint)
                continue;
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(entrypoint.ArgumentTypes.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(entrypoint.LocalTypes.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(entrypoint.Instructions.AsSpan()));
            Entrypoints[index] = null;
        }
    }

    private static DaxqFault TryReadSections(ReadOnlySpan<byte> plaintext, out DqxpSections sections)
    {
        sections = default;
        const int headerLength = 16;
        const int sectionCount = 6;
        const int directoryRecordLength = 12;
        const int bodiesOffset = headerLength + (sectionCount * directoryRecordLength);

        if (plaintext.Length < bodiesOffset || !plaintext[..4].SequenceEqual("DQXP"u8) ||
            BinaryPrimitives.ReadUInt16LittleEndian(plaintext[4..]) != DaxqFormat.PlaintextContainerVersion ||
            BinaryPrimitives.ReadUInt16LittleEndian(plaintext[6..]) != DaxqFormat.VmAbiVersion ||
            BinaryPrimitives.ReadUInt16LittleEndian(plaintext[8..]) != sectionCount ||
            BinaryPrimitives.ReadUInt16LittleEndian(plaintext[10..]) != 0 ||
            BinaryPrimitives.ReadUInt32LittleEndian(plaintext[12..]) != (uint)plaintext.Length)
        {
            return DaxqFault.InvalidFormat;
        }

        var expectedOffset = bodiesOffset;
        var bodies = new byte[sectionCount][];
        for (var index = 0; index < sectionCount; index++)
        {
            var record = plaintext.Slice(headerLength + (index * directoryRecordLength), directoryRecordLength);
            if (BinaryPrimitives.ReadUInt16LittleEndian(record) != index + 1 ||
                BinaryPrimitives.ReadUInt16LittleEndian(record[2..]) != 0)
            {
                return DaxqFault.InvalidFormat;
            }

            var offset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(record[4..]));
            var length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(record[8..]));
            if (offset != expectedOffset || length < 0 || offset > plaintext.Length - length)
                return DaxqFault.InvalidFormat;

            bodies[index] = plaintext.Slice(offset, length).ToArray();
            expectedOffset = checked(offset + length);
        }

        if (expectedOffset != plaintext.Length)
            return DaxqFault.InvalidFormat;

        sections = new DqxpSections(
            bodies[0], bodies[1], bodies[2], bodies[3], bodies[4], bodies[5]);
        return DaxqFault.Ok;
    }

    private static DaxqFault TryReadConstants(ReadOnlySpan<byte> section, out DaxqValue[] constants)
    {
        constants = [];
        if (section.Length < 2)
            return DaxqFault.InvalidFormat;

        var count = BinaryPrimitives.ReadUInt16LittleEndian(section);
        if (section.Length != checked(2 + (count * 9)))
            return DaxqFault.InvalidFormat;

        constants = new DaxqValue[count];
        var offset = 2;
        for (var index = 0; index < count; index++, offset += 9)
        {
            var tag = (DaxqValueType)section[offset];
            var bits = BinaryPrimitives.ReadInt64LittleEndian(section[(offset + 1)..]);
            switch (tag)
            {
                case DaxqValueType.I64:
                    constants[index] = DaxqValue.FromRaw(tag, bits);
                    break;
                case DaxqValueType.F64:
                    var value = BitConverter.Int64BitsToDouble(bits);
                    if (!double.IsFinite(value))
                        return DaxqFault.InvalidFormat;
                    constants[index] = DaxqValue.FromDouble(value);
                    break;
                default:
                    return DaxqFault.InvalidFormat;
            }
        }

        return DaxqFault.Ok;
    }

    private static DaxqFault TryReadOpcodeMap(ReadOnlySpan<byte> section, out byte[] map)
    {
        map = new byte[256];
        if (section.Length < 2)
            return DaxqFault.InvalidFormat;

        var count = BinaryPrimitives.ReadUInt16LittleEndian(section);
        if (count > 255 || section.Length != checked(2 + (count * 2)))
            return DaxqFault.InvalidFormat;

        Span<bool> canonicalSeen = stackalloc bool[256];
        canonicalSeen.Clear();
        byte previousEncoded = 0;
        for (var index = 0; index < count; index++)
        {
            var offset = 2 + (index * 2);
            var encoded = section[offset];
            var canonical = section[offset + 1];
            if (encoded == 0 || encoded <= previousEncoded || canonical == 0 ||
                !Enum.IsDefined((Opcode)canonical) || canonicalSeen[canonical])
            {
                return DaxqFault.InvalidFormat;
            }

            map[encoded] = canonical;
            canonicalSeen[canonical] = true;
            previousEncoded = encoded;
        }

        return DaxqFault.Ok;
    }

    private static DaxqFault TryReadHostMap(ReadOnlySpan<byte> section, out HostMapEntry[] map)
    {
        map = [];
        if (section.Length < 2)
            return DaxqFault.InvalidFormat;

        var count = BinaryPrimitives.ReadUInt16LittleEndian(section);
        if (count > Enum.GetValues<HostFn>().Length || section.Length != checked(2 + (count * 4)))
            return DaxqFault.InvalidFormat;

        map = new HostMapEntry[count];
        Span<bool> canonicalSeen = stackalloc bool[9];
        canonicalSeen.Clear();
        ushort previousEncoded = 0;
        for (var index = 0; index < count; index++)
        {
            var offset = 2 + (index * 4);
            var encoded = BinaryPrimitives.ReadUInt16LittleEndian(section[offset..]);
            var canonical = BinaryPrimitives.ReadUInt16LittleEndian(section[(offset + 2)..]);
            if (encoded == 0 || encoded <= previousEncoded || canonical == 0 ||
                !Enum.IsDefined((HostFn)canonical) || canonicalSeen[canonical])
            {
                return DaxqFault.InvalidFormat;
            }

            map[index] = new HostMapEntry(encoded, (HostFn)canonical);
            canonicalSeen[canonical] = true;
            previousEncoded = encoded;
        }

        return DaxqFault.Ok;
    }

    private static DaxqFault TryReadEntrypoints(
        ReadOnlySpan<byte> section,
        int bytecodeLength,
        out VmType[] stateTypes,
        out EntrypointDeclaration[] declarations)
    {
        stateTypes = [];
        declarations = [];
        if (section.Length < 3)
            return DaxqFault.InvalidFormat;

        var stateCount = BinaryPrimitives.ReadUInt16LittleEndian(section);
        if (stateCount > 256 || section.Length < 3 + stateCount)
            return DaxqFault.InvalidFormat;

        stateTypes = new VmType[stateCount];
        for (var index = 0; index < stateCount; index++)
        {
            var type = ScalarVmType(section[2 + index]);
            if (type == VmType.Unknown)
                return DaxqFault.InvalidFormat;
            stateTypes[index] = type;
        }

        var countOffset = 2 + stateCount;
        var entryCount = section[countOffset];
        const int recordLength = 16;
        if (entryCount is < 1 or > 3 ||
            section.Length != checked(countOffset + 1 + (entryCount * recordLength)))
        {
            return DaxqFault.InvalidFormat;
        }

        declarations = new EntrypointDeclaration[entryCount];
        var previousId = -1;
        var hasOnBarOrTick = false;
        for (var index = 0; index < entryCount; index++)
        {
            var record = section.Slice(countOffset + 1 + (index * recordLength), recordLength);
            var rawId = record[0];
            if (rawId > (byte)DaxqEntrypoint.OnTick || rawId <= previousId)
                return DaxqFault.InvalidFormat;

            var id = (DaxqEntrypoint)rawId;
            var expectedArguments = ArgumentTypes(id);
            var argCount = record[1];
            var localCount = BinaryPrimitives.ReadUInt16LittleEndian(record[2..]);
            var reserved = BinaryPrimitives.ReadUInt32LittleEndian(record[4..]);
            var codeOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(record[8..]));
            var codeLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(record[12..]));
            if (argCount != expectedArguments.Length || localCount > 256 || reserved != 0 ||
                codeLength <= 0 || codeOffset < 0 || codeOffset > bytecodeLength - codeLength)
            {
                return DaxqFault.InvalidFormat;
            }

            declarations[index] = new EntrypointDeclaration(
                id, localCount, codeOffset, codeLength, expectedArguments);
            previousId = rawId;
            hasOnBarOrTick |= id is DaxqEntrypoint.OnBar or DaxqEntrypoint.OnTick;
        }

        if (!hasOnBarOrTick)
            return DaxqFault.InvalidFormat;

        var byOffset = declarations.OrderBy(item => item.CodeOffset).ToArray();
        var expectedOffset = 0;
        foreach (var declaration in byOffset)
        {
            if (declaration.CodeOffset != expectedOffset)
                return DaxqFault.InvalidFormat;
            expectedOffset = checked(expectedOffset + declaration.CodeLength);
        }

        return expectedOffset == bytecodeLength ? DaxqFault.Ok : DaxqFault.InvalidFormat;
    }

    private static DaxqFault ValidateWatermark(ReadOnlySpan<byte> section)
    {
        if (section.Length < 5 || section[0] != 1)
            return DaxqFault.InvalidFormat;

        var slotLength = BinaryPrimitives.ReadUInt16LittleEndian(section[1..]);
        var valueLengthOffset = 3 + slotLength;
        if (valueLengthOffset > section.Length - 2)
            return DaxqFault.InvalidFormat;

        var slotBytes = section.Slice(3, slotLength);
        if (!slotBytes.SequenceEqual("wm"u8))
            return DaxqFault.InvalidFormat;

        var valueLength = BinaryPrimitives.ReadUInt16LittleEndian(section[valueLengthOffset..]);
        if (valueLength != 32 || section.Length != valueLengthOffset + 2 + valueLength)
            return DaxqFault.InvalidFormat;

        return DaxqFault.Ok;
    }

    private static DaxqFault TryDecodeAndVerify(
        byte[] bytecode,
        EntrypointDeclaration declaration,
        DaxqValue[] constants,
        byte[] opcodeMap,
        HostMapEntry[] hostMap,
        VmType[] stateTypes,
        bool[] constantSeen,
        ref int nextConstant,
        out VerifiedEntrypoint? verified)
    {
        verified = null;
        var code = bytecode.AsSpan(declaration.CodeOffset, declaration.CodeLength);
        var decoded = new List<DecodedInstruction>();
        var offset = 0;
        while (offset < code.Length)
        {
            var instructionOffset = offset;
            var encodedOpcode = code[offset++];
            var canonicalOpcode = opcodeMap[encodedOpcode];
            if (encodedOpcode == 0 || canonicalOpcode == 0)
                return DaxqFault.Verification;

            var opcode = (Opcode)canonicalOpcode;
            var operandA = 0;
            var operandB = 0;
            switch (opcode)
            {
                case Opcode.PUSH_F64:
                case Opcode.PUSH_I64:
                case Opcode.LD_LOC:
                case Opcode.ST_LOC:
                case Opcode.LD_ARG:
                case Opcode.LD_STATE:
                case Opcode.ST_STATE:
                    if (!TryReadUInt16(code, ref offset, out operandA))
                        return DaxqFault.Verification;
                    break;
                case Opcode.PUSH_BOOL:
                    if (!TryReadByte(code, ref offset, out operandA))
                        return DaxqFault.Verification;
                    break;
                case Opcode.BR:
                case Opcode.BRT:
                case Opcode.BRF:
                    if (!TryReadInt32(code, ref offset, out operandA))
                        return DaxqFault.Verification;
                    break;
                case Opcode.NEWBUF:
                    if (!TryReadByte(code, ref offset, out operandA) ||
                        !TryReadUInt16(code, ref offset, out operandB))
                    {
                        return DaxqFault.Verification;
                    }
                    break;
                case Opcode.CALL_HOST:
                    if (!TryReadUInt16(code, ref offset, out var encodedHost) ||
                        !TryReadByte(code, ref offset, out operandB) ||
                        !TryResolveHost(hostMap, checked((ushort)encodedHost), out var host))
                    {
                        return DaxqFault.Verification;
                    }
                    operandA = (ushort)host;
                    break;
                case Opcode.ADD:
                case Opcode.SUB:
                case Opcode.MUL:
                case Opcode.DIV:
                case Opcode.MOD:
                case Opcode.NEG:
                case Opcode.CEQ:
                case Opcode.CNE:
                case Opcode.CLT:
                case Opcode.CLE:
                case Opcode.CGT:
                case Opcode.CGE:
                case Opcode.AND:
                case Opcode.OR:
                case Opcode.NOT:
                case Opcode.I2F:
                case Opcode.F2I:
                case Opcode.LDELEM:
                case Opcode.STELEM:
                case Opcode.LEN:
                case Opcode.RET:
                    break;
                default:
                    return DaxqFault.Verification;
            }

            var instruction = new DecodedInstruction(
                instructionOffset, offset, opcode, operandA, operandB, -1);
            if (!ValidateStaticOperands(instruction, declaration, constants, stateTypes))
                return DaxqFault.Verification;
            if (opcode is Opcode.PUSH_F64 or Opcode.PUSH_I64 && !constantSeen[operandA])
            {
                if (operandA != nextConstant)
                    return DaxqFault.Verification;
                constantSeen[operandA] = true;
                nextConstant++;
            }
            decoded.Add(instruction);
        }

        if (offset != code.Length || decoded.Count == 0)
            return DaxqFault.Verification;

        var offsetToInstruction = new Dictionary<int, int>(decoded.Count);
        for (var index = 0; index < decoded.Count; index++)
            offsetToInstruction.Add(decoded[index].Offset, index);

        for (var index = 0; index < decoded.Count; index++)
        {
            var instruction = decoded[index];
            if (instruction.Opcode is Opcode.BR or Opcode.BRT or Opcode.BRF)
            {
                var targetLong = (long)instruction.NextOffset + instruction.OperandA;
                if (targetLong < 0 || targetLong >= code.Length ||
                    !offsetToInstruction.TryGetValue((int)targetLong, out var target))
                {
                    return DaxqFault.Verification;
                }
                decoded[index] = instruction with { TargetInstruction = target };
            }
        }

        var localTypes = new VmType[declaration.LocalCount];
        var fault = VerifyDataFlow(decoded, declaration, constants, stateTypes, localTypes);
        if (fault != DaxqFault.Ok)
            return fault;

        verified = new VerifiedEntrypoint(
            declaration.Id,
            declaration.ArgumentTypes,
            localTypes,
            decoded.ToArray());
        return DaxqFault.Ok;
    }

    private static bool ValidateStaticOperands(
        DecodedInstruction instruction,
        EntrypointDeclaration declaration,
        DaxqValue[] constants,
        VmType[] stateTypes)
    {
        switch (instruction.Opcode)
        {
            case Opcode.PUSH_F64:
                return instruction.OperandA < constants.Length &&
                    constants[instruction.OperandA].Type == DaxqValueType.F64;
            case Opcode.PUSH_I64:
                return instruction.OperandA < constants.Length &&
                    constants[instruction.OperandA].Type == DaxqValueType.I64;
            case Opcode.PUSH_BOOL:
                return instruction.OperandA is 0 or 1;
            case Opcode.LD_LOC:
            case Opcode.ST_LOC:
                return instruction.OperandA < declaration.LocalCount;
            case Opcode.LD_ARG:
                return instruction.OperandA < declaration.ArgumentTypes.Length;
            case Opcode.NEWBUF:
                return ScalarVmType(instruction.OperandA) != VmType.Unknown && instruction.OperandB <= 4096;
            case Opcode.LD_STATE:
            case Opcode.ST_STATE:
                return instruction.OperandA < stateTypes.Length;
            case Opcode.CALL_HOST:
                return HostArity((HostFn)instruction.OperandA) == instruction.OperandB &&
                    (HostFn)instruction.OperandA != HostFn.State;
            default:
                return true;
        }
    }

    private static DaxqFault VerifyDataFlow(
        List<DecodedInstruction> instructions,
        EntrypointDeclaration declaration,
        DaxqValue[] constants,
        VmType[] stateTypes,
        VmType[] localTypes)
    {
        var states = new FlowState?[instructions.Count];
        var pending = new Queue<int>();
        states[0] = new FlowState(declaration.LocalCount);
        pending.Enqueue(0);

        while (pending.Count > 0)
        {
            var index = pending.Dequeue();
            var output = states[index]!.Clone();
            var instruction = instructions[index];
            if (!ApplyInstruction(instruction, output, declaration, constants, stateTypes, localTypes))
                return DaxqFault.Verification;

            if (instruction.Opcode == Opcode.RET)
            {
                if (output.Stack.Count != 0)
                    return DaxqFault.Verification;
                continue;
            }

            if (instruction.Opcode == Opcode.BR)
            {
                if (!MergeState(instruction.TargetInstruction, output, states, pending))
                    return DaxqFault.Verification;
                continue;
            }

            if (instruction.Opcode is Opcode.BRT or Opcode.BRF)
            {
                if (index + 1 >= instructions.Count ||
                    !MergeState(instruction.TargetInstruction, output, states, pending) ||
                    !MergeState(index + 1, output, states, pending))
                {
                    return DaxqFault.Verification;
                }
                continue;
            }

            if (index + 1 >= instructions.Count || !MergeState(index + 1, output, states, pending))
                return DaxqFault.Verification;
        }

        if (states.Any(state => state is null))
            return DaxqFault.Verification;

        for (var index = 0; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            if (instruction.Opcode != Opcode.CALL_HOST)
                continue;
            var stack = new List<AbstractValue>(states[index]!.Stack);
            if (!ApplyHostCall(
                    (HostFn)instruction.OperandA,
                    declaration.Id,
                    stack,
                    validateValues: true))
                return DaxqFault.Verification;
        }
        return DaxqFault.Ok;
    }

    private static bool ApplyInstruction(
        DecodedInstruction instruction,
        FlowState state,
        EntrypointDeclaration declaration,
        DaxqValue[] constants,
        VmType[] stateTypes,
        VmType[] localTypes)
    {
        switch (instruction.Opcode)
        {
            case Opcode.PUSH_F64:
                state.Stack.Add(AbstractValue.FromConstant(constants[instruction.OperandA]));
                return true;
            case Opcode.PUSH_I64:
                state.Stack.Add(AbstractValue.FromConstant(constants[instruction.OperandA]));
                return true;
            case Opcode.PUSH_BOOL:
                state.Stack.Add(AbstractValue.FromBool(instruction.OperandA != 0));
                return true;
            case Opcode.LD_LOC:
                if (!state.InitializedLocals[instruction.OperandA] ||
                    localTypes[instruction.OperandA] == VmType.Unknown)
                {
                    return false;
                }
                state.Stack.Add(state.LocalValues[instruction.OperandA]);
                return true;
            case Opcode.ST_LOC:
                if (!TryPopAny(state.Stack, out var stored))
                    return false;
                if (localTypes[instruction.OperandA] != VmType.Unknown &&
                    localTypes[instruction.OperandA] != stored.Type)
                {
                    return false;
                }
                localTypes[instruction.OperandA] = stored.Type;
                state.InitializedLocals[instruction.OperandA] = true;
                state.LocalValues[instruction.OperandA] = stored;
                return true;
            case Opcode.LD_ARG:
                state.Stack.Add(AbstractValue.Unknown(declaration.ArgumentTypes[instruction.OperandA]));
                return true;
            case Opcode.ADD:
            case Opcode.SUB:
            case Opcode.MUL:
            case Opcode.DIV:
            case Opcode.MOD:
                return ApplyBinaryNumeric(instruction.Opcode, state.Stack);
            case Opcode.NEG:
                return ApplyNegate(state.Stack);
            case Opcode.CEQ:
            case Opcode.CNE:
                return ApplyComparison(instruction.Opcode, state.Stack, numericOnly: false);
            case Opcode.CLT:
            case Opcode.CLE:
            case Opcode.CGT:
            case Opcode.CGE:
                return ApplyComparison(instruction.Opcode, state.Stack, numericOnly: true);
            case Opcode.AND:
            case Opcode.OR:
                return ApplyBooleanBinary(instruction.Opcode, state.Stack);
            case Opcode.NOT:
                if (!TryPop(state.Stack, VmType.Bool, out var booleanValue))
                    return false;
                return Push(
                    state.Stack,
                    booleanValue.IsKnown
                        ? AbstractValue.FromBool(!booleanValue.Bool)
                        : AbstractValue.Unknown(VmType.Bool));
            case Opcode.I2F:
                if (!TryPop(state.Stack, VmType.I64, out var integerValue))
                    return false;
                return Push(
                    state.Stack,
                    integerValue.IsKnown
                        ? AbstractValue.FromF64(integerValue.I64)
                        : AbstractValue.Unknown(VmType.F64));
            case Opcode.F2I:
                if (!TryPop(state.Stack, VmType.F64, out var floatingValue))
                    return false;
                if (!floatingValue.IsKnown)
                    return Push(state.Stack, AbstractValue.Unknown(VmType.I64));
                var floating = floatingValue.F64;
                return Push(
                    state.Stack,
                    floating >= -9_223_372_036_854_775_808d &&
                    floating < 9_223_372_036_854_775_808d
                        ? AbstractValue.FromI64((long)Math.Truncate(floating))
                        : AbstractValue.Unknown(VmType.I64));
            case Opcode.BR:
                return true;
            case Opcode.BRT:
            case Opcode.BRF:
                return TryPop(state.Stack, VmType.Bool, out _);
            case Opcode.NEWBUF:
                state.Stack.Add(AbstractValue.FromBuffer(
                    BufferVmType(instruction.OperandA),
                    instruction.OperandB));
                return true;
            case Opcode.LDELEM:
                if (!TryPop(state.Stack, VmType.I64, out _) ||
                    !TryPopBuffer(state.Stack, out var bufferType))
                    return false;
                state.Stack.Add(AbstractValue.Unknown(BufferElementType(bufferType.Type)));
                return true;
            case Opcode.STELEM:
                if (!TryPopAny(state.Stack, out var element) ||
                    !TryPop(state.Stack, VmType.I64, out _) ||
                    !TryPopBuffer(state.Stack, out var targetBuffer))
                {
                    return false;
                }
                return element.Type == BufferElementType(targetBuffer.Type);
            case Opcode.LEN:
                if (!TryPopBuffer(state.Stack, out var lengthBuffer))
                    return false;
                return Push(
                    state.Stack,
                    lengthBuffer.IsKnown
                        ? AbstractValue.FromI64(lengthBuffer.I64)
                        : AbstractValue.Unknown(VmType.I64));
            case Opcode.LD_STATE:
                state.Stack.Add(AbstractValue.Unknown(stateTypes[instruction.OperandA]));
                return true;
            case Opcode.ST_STATE:
                return TryPop(state.Stack, stateTypes[instruction.OperandA], out _);
            case Opcode.CALL_HOST:
                return ApplyHostCall(
                    (HostFn)instruction.OperandA,
                    declaration.Id,
                    state.Stack,
                    validateValues: false);
            case Opcode.RET:
                return true;
            default:
                return false;
        }
    }

    private static bool ApplyHostCall(
        HostFn host,
        DaxqEntrypoint entrypoint,
        List<AbstractValue> stack,
        bool validateValues)
    {
        switch (host)
        {
            case HostFn.Bar:
                if (!TryPop(stack, VmType.I64, out var lookback) ||
                    !TryPop(stack, VmType.I64, out var field) ||
                    (validateValues &&
                        (IsKnownOutside(field, 1, 5) || IsKnownOutside(lookback, 0, 65_535))))
                {
                    return false;
                }
                return Push(stack, AbstractValue.Unknown(VmType.F64));
            case HostFn.Ind:
                if (!TryPop(stack, VmType.I64, out var source) ||
                    !TryPop(stack, VmType.I64, out var period) ||
                    !TryPop(stack, VmType.I64, out var indicator) ||
                    (validateValues &&
                        (IsKnownOutside(indicator, 1, 4) ||
                            IsKnownOutside(period, 1, 65_535) ||
                            IsKnownOutside(source, 1, 5) ||
                            (indicator.IsKnown && indicator.I64 == 4 &&
                                source.IsKnown && source.I64 != 4))))
                {
                    return false;
                }
                return Push(stack, AbstractValue.Unknown(VmType.F64));
            case HostFn.Param:
                if (!TryPop(stack, VmType.I64, out var parameter) ||
                    (validateValues && IsKnownOutside(parameter, 0, 255)))
                {
                    return false;
                }
                return Push(stack, AbstractValue.Unknown(VmType.F64));
            case HostFn.Emit:
                if (!TryPop(stack, VmType.I64, out var note) ||
                    !TryPop(stack, VmType.F64, out var strength) ||
                    !TryPop(stack, VmType.I64, out var kind) ||
                    (validateValues &&
                        (IsKnownOutside(kind, -1, 1) ||
                            (strength.IsKnown && (strength.F64 < 0d || strength.F64 > 1d)) ||
                            (note.IsKnown && note.I64 < 0))))
                {
                    return false;
                }
                return true;
            case HostFn.TIndex:
                return Push(
                    stack,
                    entrypoint == DaxqEntrypoint.Initialize
                        ? AbstractValue.FromI64(0)
                        : AbstractValue.Unknown(VmType.I64));
            case HostFn.Rng:
                return Push(stack, AbstractValue.Unknown(VmType.F64));
            case HostFn.Log:
                return TryPop(stack, VmType.F64, out _) &&
                    TryPop(stack, VmType.I64, out var message) &&
                    (!validateValues || !message.IsKnown || message.I64 >= 0);
            default:
                return false;
        }
    }

    private static bool IsKnownOutside(AbstractValue value, long minimum, long maximum) =>
        value.IsKnown && (value.I64 < minimum || value.I64 > maximum);

    private static bool ApplyBinaryNumeric(Opcode opcode, List<AbstractValue> stack)
    {
        if (!TryPopNumeric(stack, out var right) ||
            !TryPopNumeric(stack, out var left) || left.Type != right.Type)
        {
            return false;
        }

        var result = AbstractValue.Unknown(left.Type);
        if (left.IsKnown && right.IsKnown)
        {
            result = left.Type == VmType.I64
                ? EvaluateIntegerBinary(opcode, left.I64, right.I64)
                : EvaluateFloatingBinary(opcode, left.F64, right.F64);
        }
        return Push(stack, result);
    }

    private static AbstractValue EvaluateIntegerBinary(Opcode opcode, long left, long right)
    {
        if ((opcode is Opcode.DIV or Opcode.MOD) &&
            (right == 0 || (left == long.MinValue && right == -1)))
        {
            return AbstractValue.Unknown(VmType.I64);
        }

        try
        {
            return AbstractValue.FromI64(opcode switch
            {
                Opcode.ADD => checked(left + right),
                Opcode.SUB => checked(left - right),
                Opcode.MUL => checked(left * right),
                Opcode.DIV => left / right,
                Opcode.MOD => left % right,
                _ => throw new InvalidOperationException(),
            });
        }
        catch (OverflowException)
        {
            return AbstractValue.Unknown(VmType.I64);
        }
    }

    private static AbstractValue EvaluateFloatingBinary(Opcode opcode, double left, double right)
    {
        if ((opcode is Opcode.DIV or Opcode.MOD) && right == 0d)
            return AbstractValue.Unknown(VmType.F64);

        var valid = true;
        var value = opcode switch
        {
            Opcode.ADD => StrictAdd(left, right),
            Opcode.SUB => StrictSubtract(left, right),
            Opcode.MUL => StrictMultiply(left, right),
            Opcode.DIV => StrictDivide(left, right),
            Opcode.MOD => StrictMod(left, right, out valid),
            _ => double.NaN,
        };
        return valid && double.IsFinite(value)
            ? AbstractValue.FromF64(value)
            : AbstractValue.Unknown(VmType.F64);
    }

    private static bool ApplyNegate(List<AbstractValue> stack)
    {
        if (!TryPopNumeric(stack, out var value))
            return false;
        if (!value.IsKnown)
            return Push(stack, AbstractValue.Unknown(value.Type));
        if (value.Type == VmType.I64)
        {
            return Push(
                stack,
                value.I64 == long.MinValue
                    ? AbstractValue.Unknown(VmType.I64)
                    : AbstractValue.FromI64(-value.I64));
        }
        return Push(stack, AbstractValue.FromF64(StrictNegate(value.F64)));
    }

    private static bool ApplyComparison(
        Opcode opcode,
        List<AbstractValue> stack,
        bool numericOnly)
    {
        if (!TryPopScalar(stack, out var right) ||
            !TryPopScalar(stack, out var left) || left.Type != right.Type ||
            (numericOnly && left.Type == VmType.Bool))
        {
            return false;
        }

        if (!left.IsKnown || !right.IsKnown)
            return Push(stack, AbstractValue.Unknown(VmType.Bool));

        var result = left.Type switch
        {
            VmType.I64 => Compare(opcode, left.I64, right.I64),
            VmType.F64 => Compare(opcode, left.F64, right.F64),
            VmType.Bool => opcode == Opcode.CEQ
                ? left.Bool == right.Bool
                : left.Bool != right.Bool,
            _ => false,
        };
        return Push(stack, AbstractValue.FromBool(result));
    }

    private static bool ApplyBooleanBinary(Opcode opcode, List<AbstractValue> stack)
    {
        if (!TryPop(stack, VmType.Bool, out var right) ||
            !TryPop(stack, VmType.Bool, out var left))
        {
            return false;
        }
        if (!left.IsKnown || !right.IsKnown)
            return Push(stack, AbstractValue.Unknown(VmType.Bool));
        return Push(
            stack,
            AbstractValue.FromBool(opcode == Opcode.AND
                ? left.Bool && right.Bool
                : left.Bool || right.Bool));
    }

    private static bool Compare(Opcode opcode, long left, long right) => opcode switch
    {
        Opcode.CEQ => left == right,
        Opcode.CNE => left != right,
        Opcode.CLT => left < right,
        Opcode.CLE => left <= right,
        Opcode.CGT => left > right,
        Opcode.CGE => left >= right,
        _ => false,
    };

    private static bool Compare(Opcode opcode, double left, double right) => opcode switch
    {
        Opcode.CEQ => left == right,
        Opcode.CNE => left != right,
        Opcode.CLT => left < right,
        Opcode.CLE => left <= right,
        Opcode.CGT => left > right,
        Opcode.CGE => left >= right,
        _ => false,
    };

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

    private static double StrictMod(double left, double right, out bool valid)
    {
        var quotient = StrictDivide(left, right);
        if (!double.IsFinite(quotient))
        {
            valid = false;
            return double.NaN;
        }
        var product = StrictMultiply(Math.Truncate(quotient), right);
        if (!double.IsFinite(product))
        {
            valid = false;
            return double.NaN;
        }
        var result = StrictSubtract(left, product);
        valid = double.IsFinite(result);
        return result;
    }

    private static bool TryPopNumeric(List<AbstractValue> stack, out AbstractValue value)
    {
        if (TryPopAny(stack, out value) && value.Type is VmType.I64 or VmType.F64)
            return true;
        value = default;
        return false;
    }

    private static bool TryPopScalar(List<AbstractValue> stack, out AbstractValue value)
    {
        if (TryPopAny(stack, out value) && value.Type is VmType.I64 or VmType.F64 or VmType.Bool)
            return true;
        value = default;
        return false;
    }

    private static bool TryPopBuffer(List<AbstractValue> stack, out AbstractValue value)
    {
        if (TryPopAny(stack, out value) && IsBuffer(value.Type))
            return true;
        value = default;
        return false;
    }

    private static bool TryPop(
        List<AbstractValue> stack,
        VmType expected,
        out AbstractValue value) =>
        TryPopAny(stack, out value) && value.Type == expected;

    private static bool TryPopAny(List<AbstractValue> stack, out AbstractValue value)
    {
        if (stack.Count == 0)
        {
            value = default;
            return false;
        }
        var last = stack.Count - 1;
        value = stack[last];
        stack.RemoveAt(last);
        return true;
    }

    private static bool Push(List<AbstractValue> stack, AbstractValue value)
    {
        stack.Add(value);
        return true;
    }

    private static bool MergeState(
        int target,
        FlowState incoming,
        FlowState?[] states,
        Queue<int> pending)
    {
        if (target < 0 || target >= states.Length)
            return false;

        var current = states[target];
        if (current is null)
        {
            states[target] = incoming.Clone();
            pending.Enqueue(target);
            return true;
        }

        if (current.Stack.Count != incoming.Stack.Count)
            return false;
        var changed = false;
        for (var index = 0; index < current.Stack.Count; index++)
        {
            if (current.Stack[index].Type != incoming.Stack[index].Type)
                return false;
            var merged = AbstractValue.Merge(current.Stack[index], incoming.Stack[index]);
            if (merged != current.Stack[index])
            {
                current.Stack[index] = merged;
                changed = true;
            }
        }

        for (var index = 0; index < current.InitializedLocals.Length; index++)
        {
            var merged = current.InitializedLocals[index] && incoming.InitializedLocals[index];
            if (merged != current.InitializedLocals[index])
            {
                current.InitializedLocals[index] = merged;
                changed = true;
            }
            if (merged)
            {
                if (current.LocalValues[index].Type != incoming.LocalValues[index].Type)
                    return false;
                var mergedValue = AbstractValue.Merge(
                    current.LocalValues[index], incoming.LocalValues[index]);
                if (mergedValue != current.LocalValues[index])
                {
                    current.LocalValues[index] = mergedValue;
                    changed = true;
                }
            }
        }

        if (changed)
            pending.Enqueue(target);
        return true;
    }

    private static bool TryReadByte(ReadOnlySpan<byte> code, ref int offset, out int value)
    {
        value = 0;
        if (offset >= code.Length)
            return false;
        value = code[offset++];
        return true;
    }

    private static bool TryReadUInt16(ReadOnlySpan<byte> code, ref int offset, out int value)
    {
        value = 0;
        if (offset > code.Length - 2)
            return false;
        value = BinaryPrimitives.ReadUInt16LittleEndian(code[offset..]);
        offset += 2;
        return true;
    }

    private static bool TryReadInt32(ReadOnlySpan<byte> code, ref int offset, out int value)
    {
        value = 0;
        if (offset > code.Length - 4)
            return false;
        value = BinaryPrimitives.ReadInt32LittleEndian(code[offset..]);
        offset += 4;
        return true;
    }

    private static bool TryResolveHost(HostMapEntry[] map, ushort encoded, out HostFn host)
    {
        var low = 0;
        var high = map.Length - 1;
        while (low <= high)
        {
            var middle = low + ((high - low) / 2);
            if (map[middle].Encoded == encoded)
            {
                host = map[middle].Canonical;
                return true;
            }
            if (map[middle].Encoded < encoded)
                low = middle + 1;
            else
                high = middle - 1;
        }
        host = default;
        return false;
    }

    private static int HostArity(HostFn host) => host switch
    {
        HostFn.Bar => 2,
        HostFn.Ind => 3,
        HostFn.Param => 1,
        HostFn.Emit => 3,
        HostFn.TIndex => 0,
        HostFn.Rng => 0,
        HostFn.Log => 2,
        _ => -1,
    };

    private static VmType[] ArgumentTypes(DaxqEntrypoint id) => id switch
    {
        DaxqEntrypoint.Initialize => [],
        DaxqEntrypoint.OnBar => [VmType.I64],
        DaxqEntrypoint.OnTick => [VmType.I64, VmType.F64, VmType.F64, VmType.F64, VmType.F64],
        _ => [],
    };

    private static VmType ScalarVmType(int tag) => tag switch
    {
        (int)DaxqValueType.I64 => VmType.I64,
        (int)DaxqValueType.F64 => VmType.F64,
        (int)DaxqValueType.Bool => VmType.Bool,
        _ => VmType.Unknown,
    };

    private static VmType BufferVmType(int elementTag) => elementTag switch
    {
        (int)DaxqValueType.I64 => VmType.BufferI64,
        (int)DaxqValueType.F64 => VmType.BufferF64,
        (int)DaxqValueType.Bool => VmType.BufferBool,
        _ => VmType.Unknown,
    };

    private static VmType BufferElementType(VmType buffer) => buffer switch
    {
        VmType.BufferI64 => VmType.I64,
        VmType.BufferF64 => VmType.F64,
        VmType.BufferBool => VmType.Bool,
        _ => VmType.Unknown,
    };

    private static bool IsBuffer(VmType type) =>
        type is VmType.BufferI64 or VmType.BufferF64 or VmType.BufferBool;

    private readonly record struct DqxpSections(
        byte[] Bytecode,
        byte[] ConstantPool,
        byte[] OpcodeMap,
        byte[] HostMap,
        byte[] Entrypoints,
        byte[] Watermark);

    private readonly record struct HostMapEntry(ushort Encoded, HostFn Canonical);

    private readonly record struct AbstractValue(VmType Type, bool IsKnown, long Bits)
    {
        public long I64 => Bits;

        public double F64 => BitConverter.Int64BitsToDouble(Bits);

        public bool Bool => Bits != 0;

        public static AbstractValue Unknown(VmType type) => new(type, false, 0);

        public static AbstractValue FromI64(long value) => new(VmType.I64, true, value);

        public static AbstractValue FromF64(double value) => new(
            VmType.F64,
            true,
            BitConverter.DoubleToInt64Bits(DaxqValue.Normalize(value)));

        public static AbstractValue FromBool(bool value) => new(VmType.Bool, true, value ? 1 : 0);

        public static AbstractValue FromBuffer(VmType type, int length) => new(type, true, length);

        public static AbstractValue FromConstant(DaxqValue value) => value.Type switch
        {
            DaxqValueType.I64 => FromI64(value.AsInt64()),
            DaxqValueType.F64 => FromF64(value.AsDouble()),
            _ => throw new InvalidOperationException(),
        };

        public static AbstractValue Merge(AbstractValue left, AbstractValue right) =>
            left.IsKnown && right.IsKnown && left.Bits == right.Bits
                ? left
                : Unknown(left.Type);
    }

    private sealed class FlowState
    {
        public FlowState(int localCount)
        {
            InitializedLocals = new bool[localCount];
            LocalValues = new AbstractValue[localCount];
            Stack = [];
        }

        private FlowState(
            bool[] initializedLocals,
            AbstractValue[] localValues,
            List<AbstractValue> stack)
        {
            InitializedLocals = initializedLocals;
            LocalValues = localValues;
            Stack = stack;
        }

        public bool[] InitializedLocals { get; }

        public AbstractValue[] LocalValues { get; }

        public List<AbstractValue> Stack { get; }

        public FlowState Clone() => new(
            (bool[])InitializedLocals.Clone(),
            (AbstractValue[])LocalValues.Clone(),
            new List<AbstractValue>(Stack));
    }

    private readonly record struct EntrypointDeclaration(
        DaxqEntrypoint Id,
        int LocalCount,
        int CodeOffset,
        int CodeLength,
        VmType[] ArgumentTypes);
}

internal enum VmType : byte
{
    Unknown = 0,
    I64 = 1,
    F64 = 2,
    Bool = 3,
    BufferI64 = 4,
    BufferF64 = 5,
    BufferBool = 6,
}

internal readonly record struct DecodedInstruction(
    int Offset,
    int NextOffset,
    Opcode Opcode,
    int OperandA,
    int OperandB,
    int TargetInstruction);

internal sealed class VerifiedEntrypoint
{
    public VerifiedEntrypoint(
        DaxqEntrypoint id,
        VmType[] argumentTypes,
        VmType[] localTypes,
        DecodedInstruction[] instructions)
    {
        Id = id;
        ArgumentTypes = argumentTypes;
        LocalTypes = localTypes;
        Instructions = instructions;
    }

    public DaxqEntrypoint Id { get; }

    public VmType[] ArgumentTypes { get; }

    public VmType[] LocalTypes { get; }

    public DecodedInstruction[] Instructions { get; }
}
