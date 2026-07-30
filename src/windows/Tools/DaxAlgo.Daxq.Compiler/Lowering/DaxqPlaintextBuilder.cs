using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>One encoded-to-canonical opcode-map entry written to DQXP section 3.</summary>
public readonly record struct DaxqOpcodeMapEntry(byte Encoded, Opcode Canonical);

/// <summary>One encoded-to-canonical host-map entry written to DQXP section 4.</summary>
public readonly record struct DaxqHostMapEntry(ushort Encoded, HostFn Canonical);

/// <summary>
/// The deterministic pre-diversification output and one release-specific diversified encoding.
/// <see cref="Constants"/> is the normalized canonical first-use order. Diversified releases keep
/// that v1-mandated order but seed-encode eligible constants through exact negation transforms.
/// </summary>
public sealed record DaxqPlaintextBuildResult(
    byte[] CanonicalBytecode,
    byte[] PreDiversificationPlaintext,
    byte[] DiversifiedBytecode,
    byte[] DiversifiedPlaintext,
    IReadOnlyList<DaxqConstant> Constants,
    IReadOnlyList<DaxqConstant> DiversifiedConstants,
    IReadOnlyList<DaxqOpcodeMapEntry> OpcodeMap,
    IReadOnlyList<DaxqHostMapEntry> HostMap);

/// <summary>Builds exact DQXP v1 plaintext and deterministic per-release map diversification.</summary>
public static class DaxqPlaintextBuilder
{
    private const int HeaderLength = 16;
    private const int SectionCount = 6;
    private const int DirectoryRecordLength = 12;
    private const int WatermarkValueLength = 32;

    private static readonly byte[] ZeroWatermark = new byte[WatermarkValueLength];
    private static readonly Opcode[] CanonicalOpcodes = Enum.GetValues<Opcode>()
        .OrderBy(value => (byte)value)
        .ToArray();
    private static readonly HostFn[] CanonicalHosts = Enum.GetValues<HostFn>()
        .OrderBy(value => (ushort)value)
        .ToArray();

    /// <summary>Builds the canonical identity-map plaintext with the unpersonalized watermark.</summary>
    public static DaxqPlaintextBuildResult BuildCanonical(DaxqCanonicalProgram program) =>
        BuildCanonical(program, ZeroWatermark);

    /// <summary>Builds the canonical identity-map plaintext with the exact 32-byte watermark value.</summary>
    public static DaxqPlaintextBuildResult BuildCanonical(
        DaxqCanonicalProgram program,
        ReadOnlySpan<byte> watermarkValue)
    {
        var normalized = Normalize(program);
        var opcodeMap = IdentityOpcodeMap();
        var hostMap = IdentityHostMap();
        var canonicalBytecode = JoinBytecode(normalized.Entrypoints);
        var plaintext = BuildPlaintext(normalized, canonicalBytecode, opcodeMap, hostMap, watermarkValue);
        VerifyPlaintext(plaintext, "canonical");

        return new DaxqPlaintextBuildResult(
            canonicalBytecode,
            plaintext,
            canonicalBytecode.ToArray(),
            plaintext.ToArray(),
            normalized.Constants,
            normalized.Constants,
            opcodeMap,
            hostMap);
    }

    /// <summary>
    /// Builds canonical and release-diversified plaintext using an exact, non-empty release seed and
    /// the unpersonalized watermark. Identical inputs produce byte-identical output.
    /// </summary>
    public static DaxqPlaintextBuildResult BuildDiversified(
        DaxqCanonicalProgram program,
        ReadOnlySpan<byte> diversificationSeed) =>
        BuildDiversified(program, ZeroWatermark, diversificationSeed);

    /// <summary>
    /// Builds canonical and release-diversified plaintext using the exact 32-byte watermark value.
    /// Opcode bytes and CALL_HOST ids are rewritten in place without changing instruction widths.
    /// </summary>
    public static DaxqPlaintextBuildResult BuildDiversified(
        DaxqCanonicalProgram program,
        ReadOnlySpan<byte> watermarkValue,
        ReadOnlySpan<byte> diversificationSeed)
    {
        if (diversificationSeed.Length != 32)
        {
            throw new ArgumentException(
                "A release diversification seed must contain exactly 32 bytes.",
                nameof(diversificationSeed));
        }

        var normalized = Normalize(program);
        var canonicalBytecode = JoinBytecode(normalized.Entrypoints);
        var identityOpcodeMap = IdentityOpcodeMap();
        var identityHostMap = IdentityHostMap();
        var canonicalPlaintext = BuildPlaintext(
            normalized,
            canonicalBytecode,
            identityOpcodeMap,
            identityHostMap,
            watermarkValue);
        VerifyPlaintext(canonicalPlaintext, "canonical");

        var opcodeMap = DiversifyOpcodes(diversificationSeed);
        var hostMap = DiversifyHosts(diversificationSeed);
        var (diversifiedConstants, negatedConstants) = DiversifyConstants(
            normalized.Constants,
            diversificationSeed);
        var diversifiedEntrypoints = RewriteEncodings(
            normalized.Entrypoints,
            opcodeMap,
            hostMap,
            negatedConstants);
        var diversifiedBytecode = JoinBytecode(diversifiedEntrypoints);
        var diversifiedProgram = normalized with
        {
            Constants = diversifiedConstants,
            Entrypoints = diversifiedEntrypoints,
        };
        var diversifiedPlaintext = BuildPlaintext(
            diversifiedProgram,
            diversifiedBytecode,
            opcodeMap,
            hostMap,
            watermarkValue);
        VerifyPlaintext(diversifiedPlaintext, "diversified");

        return new DaxqPlaintextBuildResult(
            canonicalBytecode,
            canonicalPlaintext,
            diversifiedBytecode,
            diversifiedPlaintext,
            normalized.Constants,
            diversifiedConstants,
            opcodeMap,
            hostMap);
    }

    private static NormalizedProgram Normalize(DaxqCanonicalProgram program)
    {
        ArgumentNullException.ThrowIfNull(program);
        if (program.Constants is null)
            throw new ArgumentException("The constant list is required.", nameof(program));
        if (program.StateTypes is null)
            throw new ArgumentException("The state-type list is required.", nameof(program));
        if (program.Entrypoints is null)
            throw new ArgumentException("The entrypoint list is required.", nameof(program));
        if (program.Constants.Count > ushort.MaxValue)
            throw new ArgumentException("A DQXP constant pool may contain at most 65,535 entries.", nameof(program));
        if (program.StateTypes.Count > 256)
            throw new ArgumentException("A DQXP program may declare at most 256 state slots.", nameof(program));

        var stateTypes = program.StateTypes.ToArray();
        for (var index = 0; index < stateTypes.Length; index++)
        {
            if (stateTypes[index] is not (DaxqValueType.I64 or DaxqValueType.F64 or DaxqValueType.Bool))
                throw new ArgumentException($"State slot {index} has an invalid scalar type.", nameof(program));
        }

        var inputConstants = program.Constants.ToArray();
        ValidateConstants(inputConstants, nameof(program));

        var ordered = program.Entrypoints
            .OrderBy(entrypoint => entrypoint?.Id)
            .ToArray();
        if (ordered.Length is < 1 or > 3)
            throw new ArgumentException("A DQXP program must declare between one and three entrypoints.", nameof(program));
        if (!ordered.Any(entrypoint => entrypoint?.Id is DaxqEntrypoint.OnBar or DaxqEntrypoint.OnTick))
            throw new ArgumentException("A DQXP program must declare OnBar or OnTick.", nameof(program));

        var seenEntrypoints = new HashSet<DaxqEntrypoint>();
        var constantRemap = Enumerable.Repeat(-1, inputConstants.Length).ToArray();
        var firstUseConstants = new List<DaxqConstant>(inputConstants.Length);
        var normalizedEntrypoints = new DaxqCanonicalEntrypoint[ordered.Length];

        for (var index = 0; index < ordered.Length; index++)
        {
            var entrypoint = ordered[index]
                ?? throw new ArgumentException("Entrypoints may not contain null.", nameof(program));
            if (!Enum.IsDefined(entrypoint.Id) || !seenEntrypoints.Add(entrypoint.Id))
                throw new ArgumentException($"Entrypoint id '{entrypoint.Id}' is invalid or duplicated.", nameof(program));
            if (entrypoint.LocalCount > 256)
                throw new ArgumentException($"Entrypoint '{entrypoint.Id}' exceeds 256 locals.", nameof(program));
            if (entrypoint.Bytecode is null || entrypoint.Bytecode.Length == 0)
                throw new ArgumentException($"Entrypoint '{entrypoint.Id}' has no bytecode.", nameof(program));

            var code = entrypoint.Bytecode.ToArray();
            NormalizeConstantReferences(
                code,
                inputConstants,
                constantRemap,
                firstUseConstants,
                entrypoint.Id,
                nameof(program));
            normalizedEntrypoints[index] = new DaxqCanonicalEntrypoint(
                entrypoint.Id,
                entrypoint.LocalCount,
                code);
        }

        if (constantRemap.Any(index => index < 0))
            throw new ArgumentException("Every declared constant must be referenced by canonical bytecode.", nameof(program));

        return new NormalizedProgram(firstUseConstants.ToArray(), stateTypes, normalizedEntrypoints);
    }

    private static void ValidateConstants(DaxqConstant[] constants, string parameterName)
    {
        for (var index = 0; index < constants.Length; index++)
        {
            var constant = constants[index];
            if (constant.Type == DaxqValueType.I64)
                continue;
            if (constant.Type != DaxqValueType.F64)
                throw new ArgumentException($"Constant {index} has an invalid pool type.", parameterName);

            var value = BitConverter.Int64BitsToDouble(constant.Bits);
            if (!double.IsFinite(value))
                throw new ArgumentException($"Constant {index} is not a finite f64.", parameterName);
            if (constant.Bits == long.MinValue)
                throw new ArgumentException($"Constant {index} encodes negative zero; DAXQ requires positive zero.", parameterName);
        }
    }

    private static void NormalizeConstantReferences(
        byte[] code,
        DaxqConstant[] inputConstants,
        int[] constantRemap,
        List<DaxqConstant> firstUseConstants,
        DaxqEntrypoint entrypoint,
        string parameterName)
    {
        var offset = 0;
        while (offset < code.Length)
        {
            var instructionOffset = offset;
            var opcode = ReadCanonicalOpcode(code, ref offset, entrypoint, parameterName);
            switch (opcode)
            {
                case Opcode.PUSH_F64:
                case Opcode.PUSH_I64:
                    {
                        EnsureRemaining(code, offset, 2, opcode, entrypoint, parameterName);
                        var oldIndex = BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(offset));
                        if (oldIndex >= inputConstants.Length)
                            throw InvalidBytecode(entrypoint, instructionOffset, $"constant index {oldIndex} is out of range", parameterName);
                        var expectedType = opcode == Opcode.PUSH_F64 ? DaxqValueType.F64 : DaxqValueType.I64;
                        if (inputConstants[oldIndex].Type != expectedType)
                            throw InvalidBytecode(entrypoint, instructionOffset, $"{opcode} references a non-{expectedType} constant", parameterName);

                        var newIndex = constantRemap[oldIndex];
                        if (newIndex < 0)
                        {
                            newIndex = firstUseConstants.Count;
                            if (newIndex > ushort.MaxValue)
                                throw new ArgumentException("The first-use constant pool exceeds 65,535 entries.", parameterName);
                            constantRemap[oldIndex] = newIndex;
                            firstUseConstants.Add(inputConstants[oldIndex]);
                        }
                        BinaryPrimitives.WriteUInt16LittleEndian(code.AsSpan(offset), checked((ushort)newIndex));
                        offset += 2;
                        break;
                    }
                case Opcode.PUSH_BOOL:
                    EnsureRemaining(code, offset, 1, opcode, entrypoint, parameterName);
                    offset += 1;
                    break;
                case Opcode.LD_LOC:
                case Opcode.ST_LOC:
                case Opcode.LD_ARG:
                case Opcode.LD_STATE:
                case Opcode.ST_STATE:
                    EnsureRemaining(code, offset, 2, opcode, entrypoint, parameterName);
                    offset += 2;
                    break;
                case Opcode.BR:
                case Opcode.BRT:
                case Opcode.BRF:
                    EnsureRemaining(code, offset, 4, opcode, entrypoint, parameterName);
                    offset += 4;
                    break;
                case Opcode.NEWBUF:
                    EnsureRemaining(code, offset, 3, opcode, entrypoint, parameterName);
                    offset += 3;
                    break;
                case Opcode.CALL_HOST:
                    {
                        EnsureRemaining(code, offset, 3, opcode, entrypoint, parameterName);
                        var rawHost = BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(offset));
                        if (!Enum.IsDefined((HostFn)rawHost) || rawHost == (ushort)HostFn.State)
                            throw InvalidBytecode(entrypoint, instructionOffset, $"host id {rawHost} is invalid", parameterName);
                        offset += 3;
                        break;
                    }
                default:
                    break;
            }
        }
    }

    private static DaxqCanonicalEntrypoint[] RewriteEncodings(
        DaxqCanonicalEntrypoint[] entrypoints,
        IReadOnlyList<DaxqOpcodeMapEntry> opcodeMap,
        IReadOnlyList<DaxqHostMapEntry> hostMap,
        IReadOnlyList<bool> negatedConstants)
    {
        var opcodeEncoding = opcodeMap.ToDictionary(entry => entry.Canonical, entry => entry.Encoded);
        var hostEncoding = hostMap.ToDictionary(entry => entry.Canonical, entry => entry.Encoded);
        var rewritten = new DaxqCanonicalEntrypoint[entrypoints.Length];

        for (var entrypointIndex = 0; entrypointIndex < entrypoints.Length; entrypointIndex++)
        {
            var entrypoint = entrypoints[entrypointIndex];
            var code = entrypoint.Bytecode;
            var output = new List<byte>(code.Length + negatedConstants.Count(value => value));
            var oldToNewOffset = new Dictionary<int, int>();
            var branchPatches = new List<BranchPatch>();
            var offset = 0;
            while (offset < code.Length)
            {
                var instructionOffset = offset;
                oldToNewOffset.Add(instructionOffset, output.Count);
                var opcode = (Opcode)code[offset++];
                output.Add(opcodeEncoding[opcode]);

                switch (opcode)
                {
                    case Opcode.PUSH_F64:
                    case Opcode.PUSH_I64:
                        {
                            var canonicalIndex = BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(offset));
                            WriteUInt16(output, canonicalIndex);
                            offset += 2;
                            if (negatedConstants[canonicalIndex])
                                output.Add(opcodeEncoding[Opcode.NEG]);
                            break;
                        }
                    case Opcode.LD_LOC:
                    case Opcode.ST_LOC:
                    case Opcode.LD_ARG:
                    case Opcode.LD_STATE:
                    case Opcode.ST_STATE:
                        output.Add(code[offset]);
                        output.Add(code[offset + 1]);
                        offset += 2;
                        break;
                    case Opcode.PUSH_BOOL:
                        output.Add(code[offset]);
                        offset += 1;
                        break;
                    case Opcode.BR:
                    case Opcode.BRT:
                    case Opcode.BRF:
                        {
                            var oldDelta = BinaryPrimitives.ReadInt32LittleEndian(code.AsSpan(offset));
                            var oldTarget = checked(offset + 4 + oldDelta);
                            var operandOffset = output.Count;
                            output.AddRange([0, 0, 0, 0]);
                            branchPatches.Add(new BranchPatch(operandOffset, oldTarget));
                            offset += 4;
                            break;
                        }
                    case Opcode.NEWBUF:
                        output.Add(code[offset]);
                        output.Add(code[offset + 1]);
                        output.Add(code[offset + 2]);
                        offset += 3;
                        break;
                    case Opcode.CALL_HOST:
                        {
                            var host = (HostFn)BinaryPrimitives.ReadUInt16LittleEndian(code.AsSpan(offset));
                            WriteUInt16(output, hostEncoding[host]);
                            output.Add(code[offset + 2]);
                            offset += 3;
                            break;
                        }
                    default:
                        break;
                }
            }

            var rewrittenCode = output.ToArray();
            foreach (var patch in branchPatches)
            {
                if (!oldToNewOffset.TryGetValue(patch.OldTargetOffset, out var newTarget))
                {
                    throw new InvalidOperationException(
                        $"Entrypoint '{entrypoint.Id}' has a branch target that is not an instruction boundary.");
                }
                var newDelta = checked(newTarget - (patch.OperandOffset + sizeof(int)));
                BinaryPrimitives.WriteInt32LittleEndian(
                    rewrittenCode.AsSpan(patch.OperandOffset),
                    newDelta);
            }

            rewritten[entrypointIndex] = new DaxqCanonicalEntrypoint(
                entrypoint.Id,
                entrypoint.LocalCount,
                rewrittenCode);
        }

        return rewritten;
    }

    private static void WriteUInt16(List<byte> output, ushort value)
    {
        output.Add((byte)value);
        output.Add((byte)(value >> 8));
    }

    private static (DaxqConstant[] Constants, bool[] Negated) DiversifyConstants(
        DaxqConstant[] constants,
        ReadOnlySpan<byte> seed)
    {
        var eligible = Enumerable.Range(0, constants.Length)
            .Where(index => CanNegate(constants[index]))
            .ToArray();
        Shuffle(eligible, new StablePermutation(seed, "DAXQ-v1-constants"));

        var diversified = constants.ToArray();
        var negated = new bool[constants.Length];
        var selectedCount = eligible.Length == 0 ? 0 : Math.Max(1, (eligible.Length + 1) / 2);
        for (var selected = 0; selected < selectedCount; selected++)
        {
            var index = eligible[selected];
            var constant = constants[index];
            diversified[index] = constant.Type == DaxqValueType.I64
                ? DaxqConstant.FromInt64(-constant.Bits)
                : DaxqConstant.FromDouble(-BitConverter.Int64BitsToDouble(constant.Bits));
            negated[index] = true;
        }
        return (diversified, negated);
    }

    private static bool CanNegate(DaxqConstant constant) => constant.Type switch
    {
        DaxqValueType.I64 => constant.Bits is not (0 or long.MinValue),
        DaxqValueType.F64 => constant.Bits != 0,
        _ => false,
    };

    private static byte[] BuildPlaintext(
        NormalizedProgram program,
        byte[] bytecode,
        IReadOnlyList<DaxqOpcodeMapEntry> opcodeMap,
        IReadOnlyList<DaxqHostMapEntry> hostMap,
        ReadOnlySpan<byte> watermarkValue)
    {
        if (watermarkValue.Length != WatermarkValueLength)
            throw new ArgumentException("A DAXQ v1 watermark value must be exactly 32 bytes.", nameof(watermarkValue));

        byte[][] sections =
        [
            bytecode,
            BuildConstantPool(program.Constants),
            BuildOpcodeMap(opcodeMap),
            BuildHostMap(hostMap),
            BuildEntrypoints(program.Entrypoints, program.StateTypes),
            BuildWatermark(watermarkValue),
        ];

        var totalLength = checked(HeaderLength +
            (SectionCount * DirectoryRecordLength) +
            sections.Sum(section => section.Length));
        var plaintext = new byte[totalLength];
        "DQXP"u8.CopyTo(plaintext);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(4), DaxqFormat.PlaintextContainerVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(6), DaxqFormat.VmAbiVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(8), SectionCount);
        BinaryPrimitives.WriteUInt32LittleEndian(plaintext.AsSpan(12), checked((uint)totalLength));

        var sectionOffset = HeaderLength + (SectionCount * DirectoryRecordLength);
        for (var index = 0; index < sections.Length; index++)
        {
            var directory = plaintext.AsSpan(HeaderLength + (index * DirectoryRecordLength), DirectoryRecordLength);
            BinaryPrimitives.WriteUInt16LittleEndian(directory, checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32LittleEndian(directory[4..], checked((uint)sectionOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(directory[8..], checked((uint)sections[index].Length));
            sections[index].CopyTo(plaintext, sectionOffset);
            sectionOffset = checked(sectionOffset + sections[index].Length);
        }

        return plaintext;
    }

    private static byte[] BuildConstantPool(DaxqConstant[] constants)
    {
        var section = new byte[checked(2 + (constants.Length * 9))];
        BinaryPrimitives.WriteUInt16LittleEndian(section, checked((ushort)constants.Length));
        for (var index = 0; index < constants.Length; index++)
        {
            var offset = 2 + (index * 9);
            section[offset] = (byte)constants[index].Type;
            BinaryPrimitives.WriteInt64LittleEndian(section.AsSpan(offset + 1), constants[index].Bits);
        }
        return section;
    }

    private static byte[] BuildOpcodeMap(IReadOnlyList<DaxqOpcodeMapEntry> entries)
    {
        var ordered = entries.OrderBy(entry => entry.Encoded).ToArray();
        var section = new byte[checked(2 + (ordered.Length * 2))];
        BinaryPrimitives.WriteUInt16LittleEndian(section, checked((ushort)ordered.Length));
        for (var index = 0; index < ordered.Length; index++)
        {
            section[2 + (index * 2)] = ordered[index].Encoded;
            section[3 + (index * 2)] = (byte)ordered[index].Canonical;
        }
        return section;
    }

    private static byte[] BuildHostMap(IReadOnlyList<DaxqHostMapEntry> entries)
    {
        var ordered = entries.OrderBy(entry => entry.Encoded).ToArray();
        var section = new byte[checked(2 + (ordered.Length * 4))];
        BinaryPrimitives.WriteUInt16LittleEndian(section, checked((ushort)ordered.Length));
        for (var index = 0; index < ordered.Length; index++)
        {
            var offset = 2 + (index * 4);
            BinaryPrimitives.WriteUInt16LittleEndian(section.AsSpan(offset), ordered[index].Encoded);
            BinaryPrimitives.WriteUInt16LittleEndian(section.AsSpan(offset + 2), (ushort)ordered[index].Canonical);
        }
        return section;
    }

    private static byte[] BuildEntrypoints(
        DaxqCanonicalEntrypoint[] entrypoints,
        DaxqValueType[] stateTypes)
    {
        var section = new byte[checked(2 + stateTypes.Length + 1 + (entrypoints.Length * 16))];
        BinaryPrimitives.WriteUInt16LittleEndian(section, checked((ushort)stateTypes.Length));
        for (var index = 0; index < stateTypes.Length; index++)
            section[2 + index] = (byte)stateTypes[index];

        var countOffset = 2 + stateTypes.Length;
        section[countOffset] = checked((byte)entrypoints.Length);
        var codeOffset = 0;
        for (var index = 0; index < entrypoints.Length; index++)
        {
            var entrypoint = entrypoints[index];
            var record = section.AsSpan(countOffset + 1 + (index * 16), 16);
            record[0] = (byte)entrypoint.Id;
            record[1] = ArgumentCount(entrypoint.Id);
            BinaryPrimitives.WriteUInt16LittleEndian(record[2..], entrypoint.LocalCount);
            BinaryPrimitives.WriteUInt32LittleEndian(record[8..], checked((uint)codeOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(record[12..], checked((uint)entrypoint.Bytecode.Length));
            codeOffset = checked(codeOffset + entrypoint.Bytecode.Length);
        }
        return section;
    }

    private static byte[] BuildWatermark(ReadOnlySpan<byte> watermarkValue)
    {
        var section = new byte[1 + 2 + 2 + 2 + WatermarkValueLength];
        section[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(section.AsSpan(1), 2);
        "wm"u8.CopyTo(section.AsSpan(3));
        BinaryPrimitives.WriteUInt16LittleEndian(section.AsSpan(5), WatermarkValueLength);
        watermarkValue.CopyTo(section.AsSpan(7));
        return section;
    }

    private static DaxqOpcodeMapEntry[] IdentityOpcodeMap() =>
        CanonicalOpcodes
            .Select(opcode => new DaxqOpcodeMapEntry((byte)opcode, opcode))
            .ToArray();

    private static DaxqHostMapEntry[] IdentityHostMap() =>
        CanonicalHosts
            .Select(host => new DaxqHostMapEntry((ushort)host, host))
            .ToArray();

    private static DaxqOpcodeMapEntry[] DiversifyOpcodes(ReadOnlySpan<byte> seed)
    {
        var encoded = CanonicalOpcodes.Select(value => (byte)value).ToArray();
        Shuffle(encoded, new StablePermutation(seed, "DAXQ-v1-opcodes"));
        EnsureNonIdentity(encoded, CanonicalOpcodes.Select(value => (byte)value).ToArray());
        return CanonicalOpcodes
            .Select((canonical, index) => new DaxqOpcodeMapEntry(encoded[index], canonical))
            .OrderBy(entry => entry.Encoded)
            .ToArray();
    }

    private static DaxqHostMapEntry[] DiversifyHosts(ReadOnlySpan<byte> seed)
    {
        var encoded = CanonicalHosts.Select(value => (ushort)value).ToArray();
        Shuffle(encoded, new StablePermutation(seed, "DAXQ-v1-hosts"));
        EnsureNonIdentity(encoded, CanonicalHosts.Select(value => (ushort)value).ToArray());
        return CanonicalHosts
            .Select((canonical, index) => new DaxqHostMapEntry(encoded[index], canonical))
            .OrderBy(entry => entry.Encoded)
            .ToArray();
    }


    private static void Shuffle<T>(T[] values, StablePermutation random)
    {
        for (var index = values.Length - 1; index > 0; index--)
        {
            var other = random.Next(index + 1);
            (values[index], values[other]) = (values[other], values[index]);
        }
    }

    private static void EnsureNonIdentity<T>(T[] values, T[] identity) where T : IEquatable<T>
    {
        if (values.Length > 1 && values.SequenceEqual(identity))
            (values[0], values[1]) = (values[1], values[0]);
    }

    private static Opcode ReadCanonicalOpcode(
        byte[] code,
        ref int offset,
        DaxqEntrypoint entrypoint,
        string parameterName)
    {
        var instructionOffset = offset;
        var raw = code[offset++];
        if (raw == 0 || !Enum.IsDefined((Opcode)raw))
            throw InvalidBytecode(entrypoint, instructionOffset, $"opcode 0x{raw:x2} is not canonical", parameterName);
        return (Opcode)raw;
    }

    private static void EnsureRemaining(
        byte[] code,
        int offset,
        int count,
        Opcode opcode,
        DaxqEntrypoint entrypoint,
        string parameterName)
    {
        if (offset > code.Length - count)
            throw InvalidBytecode(entrypoint, offset - 1, $"{opcode} has a truncated operand", parameterName);
    }

    private static ArgumentException InvalidBytecode(
        DaxqEntrypoint entrypoint,
        int offset,
        string message,
        string parameterName) =>
        new($"Entrypoint '{entrypoint}' byte {offset}: {message}.", parameterName);

    private static byte ArgumentCount(DaxqEntrypoint entrypoint) => entrypoint switch
    {
        DaxqEntrypoint.Initialize => 0,
        DaxqEntrypoint.OnBar => 1,
        DaxqEntrypoint.OnTick => 5,
        _ => throw new ArgumentOutOfRangeException(nameof(entrypoint)),
    };

    private static byte[] JoinBytecode(IEnumerable<DaxqCanonicalEntrypoint> entrypoints) =>
        entrypoints.SelectMany(entrypoint => entrypoint.Bytecode).ToArray();

    private static void VerifyPlaintext(byte[] plaintext, string flavor)
    {
        var fault = DaxqProgram.TryLoad(plaintext, out _);
        if (fault != DaxqFault.Ok)
            throw new InvalidOperationException($"The {flavor} DQXP plaintext failed reference verification: {fault}.");
    }

    private sealed record NormalizedProgram(
        DaxqConstant[] Constants,
        DaxqValueType[] StateTypes,
        DaxqCanonicalEntrypoint[] Entrypoints);

    private readonly record struct BranchPatch(int OperandOffset, int OldTargetOffset);

    /// <summary>A stable SplitMix64 stream domain-separated by SHA-256 from release seed bytes.</summary>
    private sealed class StablePermutation
    {
        private ulong _state;

        public StablePermutation(ReadOnlySpan<byte> seed, string domain)
        {
            var domainBytes = Encoding.ASCII.GetBytes(domain);
            var material = new byte[checked(domainBytes.Length + 1 + seed.Length)];
            domainBytes.CopyTo(material, 0);
            seed.CopyTo(material.AsSpan(domainBytes.Length + 1));
            var digest = SHA256.HashData(material);
            _state = BinaryPrimitives.ReadUInt64LittleEndian(digest);
        }

        public int Next(int exclusiveMaximum)
        {
            if (exclusiveMaximum <= 0)
                throw new ArgumentOutOfRangeException(nameof(exclusiveMaximum));

            var bound = checked((ulong)exclusiveMaximum);
            var threshold = unchecked(0UL - bound) % bound;
            ulong sample;
            do
            {
                sample = NextUInt64();
            }
            while (sample < threshold);
            return checked((int)(sample % bound));
        }

        private ulong NextUInt64()
        {
            _state += 0x9e3779b97f4a7c15UL;
            var value = _state;
            value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9UL;
            value = (value ^ (value >> 27)) * 0x94d049bb133111ebUL;
            return value ^ (value >> 31);
        }
    }
}
