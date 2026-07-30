using System.Buffers.Binary;

namespace DaxAlgo.Daxq.Vm.Tests;

internal sealed class DaxqTestContainerBuilder
{
    private readonly List<DaxqValue> _constants = [];
    private readonly List<(DaxqEntrypoint Id, ushort Locals, BytecodeBuilder Code)> _entrypoints = [];
    private readonly List<DaxqValueType> _stateTypes = [];
    private readonly Dictionary<Opcode, byte> _opcodeEncoding =
        Enum.GetValues<Opcode>().ToDictionary(value => value, value => (byte)value);
    private readonly Dictionary<HostFn, ushort> _hostEncoding =
        Enum.GetValues<HostFn>().ToDictionary(value => value, value => (ushort)value);

    public ushort AddInt64(long value)
    {
        _constants.Add(DaxqValue.FromInt64(value));
        return checked((ushort)(_constants.Count - 1));
    }

    public ushort AddDouble(double value)
    {
        _constants.Add(DaxqValue.FromDouble(value));
        return checked((ushort)(_constants.Count - 1));
    }

    public ushort AddState(DaxqValueType type)
    {
        _stateTypes.Add(type);
        return checked((ushort)(_stateTypes.Count - 1));
    }

    public BytecodeBuilder AddEntrypoint(DaxqEntrypoint id, ushort localCount = 0)
    {
        var code = new BytecodeBuilder(this);
        _entrypoints.Add((id, localCount, code));
        return code;
    }

    public void SwapOpcodeEncoding(Opcode left, Opcode right) =>
        (_opcodeEncoding[left], _opcodeEncoding[right]) = (_opcodeEncoding[right], _opcodeEncoding[left]);

    public void SwapHostEncoding(HostFn left, HostFn right) =>
        (_hostEncoding[left], _hostEncoding[right]) = (_hostEncoding[right], _hostEncoding[left]);

    public byte[] Build()
    {
        var orderedEntrypoints = _entrypoints.OrderBy(entry => entry.Id).ToArray();
        Assert.NotEmpty(orderedEntrypoints);
        Assert.Contains(
            orderedEntrypoints,
            entry => entry.Id is DaxqEntrypoint.OnBar or DaxqEntrypoint.OnTick);

        var bytecode = orderedEntrypoints.SelectMany(entry => entry.Code.ToArray()).ToArray();
        var constants = BuildConstantPool();
        var opcodeMap = BuildOpcodeMap();
        var hostMap = BuildHostMap();
        var entrypoints = BuildEntrypoints(orderedEntrypoints);
        var watermark = BuildWatermark();
        byte[][] sections = [bytecode, constants, opcodeMap, hostMap, entrypoints, watermark];

        var length = checked(16 + (sections.Length * 12) + sections.Sum(section => section.Length));
        var plaintext = new byte[length];
        "DQXP"u8.CopyTo(plaintext);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(6), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(8), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(plaintext.AsSpan(12), checked((uint)length));

        var sectionOffset = 16 + (sections.Length * 12);
        for (var index = 0; index < sections.Length; index++)
        {
            var directory = plaintext.AsSpan(16 + (index * 12), 12);
            BinaryPrimitives.WriteUInt16LittleEndian(directory, checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32LittleEndian(directory[4..], checked((uint)sectionOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(directory[8..], checked((uint)sections[index].Length));
            sections[index].CopyTo(plaintext, sectionOffset);
            sectionOffset += sections[index].Length;
        }
        return plaintext;
    }

    private byte[] BuildConstantPool()
    {
        var bytes = new byte[2 + (_constants.Count * 9)];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)_constants.Count));
        for (var index = 0; index < _constants.Count; index++)
        {
            bytes[2 + (index * 9)] = (byte)_constants[index].Type;
            BinaryPrimitives.WriteInt64LittleEndian(
                bytes.AsSpan(3 + (index * 9)),
                _constants[index].RawBitsForTests());
        }
        return bytes;
    }

    private byte[] BuildOpcodeMap()
    {
        var entries = _opcodeEncoding.OrderBy(pair => pair.Value).ToArray();
        var bytes = new byte[2 + (entries.Length * 2)];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)entries.Length));
        for (var index = 0; index < entries.Length; index++)
        {
            bytes[2 + (index * 2)] = entries[index].Value;
            bytes[3 + (index * 2)] = (byte)entries[index].Key;
        }
        return bytes;
    }

    private byte[] BuildHostMap()
    {
        var entries = _hostEncoding.OrderBy(pair => pair.Value).ToArray();
        var bytes = new byte[2 + (entries.Length * 4)];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)entries.Length));
        for (var index = 0; index < entries.Length; index++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(2 + (index * 4)), entries[index].Value);
            BinaryPrimitives.WriteUInt16LittleEndian(
                bytes.AsSpan(4 + (index * 4)), (ushort)entries[index].Key);
        }
        return bytes;
    }

    private byte[] BuildEntrypoints(
        (DaxqEntrypoint Id, ushort Locals, BytecodeBuilder Code)[] orderedEntrypoints)
    {
        var bytes = new byte[2 + _stateTypes.Count + 1 + (orderedEntrypoints.Length * 16)];
        BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)_stateTypes.Count));
        for (var index = 0; index < _stateTypes.Count; index++)
            bytes[2 + index] = (byte)_stateTypes[index];
        var countOffset = 2 + _stateTypes.Count;
        bytes[countOffset] = checked((byte)orderedEntrypoints.Length);

        var codeOffset = 0;
        for (var index = 0; index < orderedEntrypoints.Length; index++)
        {
            var entrypoint = orderedEntrypoints[index];
            var record = bytes.AsSpan(countOffset + 1 + (index * 16), 16);
            record[0] = (byte)entrypoint.Id;
            record[1] = entrypoint.Id switch
            {
                DaxqEntrypoint.Initialize => 0,
                DaxqEntrypoint.OnBar => 1,
                DaxqEntrypoint.OnTick => 5,
                _ => throw new InvalidOperationException(),
            };
            BinaryPrimitives.WriteUInt16LittleEndian(record[2..], entrypoint.Locals);
            BinaryPrimitives.WriteUInt32LittleEndian(record[8..], checked((uint)codeOffset));
            BinaryPrimitives.WriteUInt32LittleEndian(record[12..], checked((uint)entrypoint.Code.Length));
            codeOffset += entrypoint.Code.Length;
        }
        return bytes;
    }

    private static byte[] BuildWatermark()
    {
        var bytes = new byte[39];
        bytes[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(1), 2);
        bytes[3] = (byte)'w';
        bytes[4] = (byte)'m';
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(5), 32);
        return bytes;
    }

    internal sealed class BytecodeBuilder
    {
        private readonly DaxqTestContainerBuilder _owner;
        private readonly List<byte> _bytes = [];

        public BytecodeBuilder(DaxqTestContainerBuilder owner)
        {
            _owner = owner;
        }

        public int Length => _bytes.Count;

        public int Mark() => _bytes.Count;

        public BytecodeBuilder Op(Opcode opcode)
        {
            _bytes.Add(_owner._opcodeEncoding[opcode]);
            return this;
        }

        public BytecodeBuilder U8(int value)
        {
            _bytes.Add(checked((byte)value));
            return this;
        }

        public BytecodeBuilder U16(int value)
        {
            Span<byte> bytes = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)value));
            _bytes.AddRange(bytes);
            return this;
        }

        public int Branch(Opcode opcode)
        {
            Op(opcode);
            var operandOffset = _bytes.Count;
            _bytes.AddRange([0, 0, 0, 0]);
            return operandOffset;
        }

        public void PatchBranch(int operandOffset, int targetOffset)
        {
            Span<byte> delta = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(delta, targetOffset - (operandOffset + 4));
            for (var index = 0; index < delta.Length; index++)
                _bytes[operandOffset + index] = delta[index];
        }

        public BytecodeBuilder Call(HostFn host, int argumentCount)
        {
            Op(Opcode.CALL_HOST);
            U16(_owner._hostEncoding[host]);
            U8(argumentCount);
            return this;
        }

        public byte[] ToArray() => _bytes.ToArray();
    }
}

internal static class DaxqValueTestExtensions
{
    public static long RawBitsForTests(this DaxqValue value) => value.Type switch
    {
        DaxqValueType.I64 => value.AsInt64(),
        DaxqValueType.F64 => BitConverter.DoubleToInt64Bits(value.AsDouble()),
        DaxqValueType.Bool => value.AsBoolean() ? 1 : 0,
        _ => throw new InvalidOperationException(),
    };
}
