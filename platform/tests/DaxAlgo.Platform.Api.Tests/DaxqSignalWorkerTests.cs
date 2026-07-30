using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;
using DaxAlgo.Platform.SignalWorker;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class DaxqSignalWorkerTests
{
    [Fact]
    public void SignedEncryptedDaxqRunsThroughReferenceVmAndEmitsSignal()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var contentKey = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(DaxqFormat.NonceSizeBytes);
        var plaintext = BuildSignalProgram();
        const string keyId = "signal-worker-test-key";
        var package = BuildPackage(
            plaintext,
            contentKey,
            nonce,
            keyId,
            signingKey);
        var frames = Encoding.UTF8.GetBytes("""
            {
              "dataRequirements": ["bars"],
              "bars": [
                { "open": 99, "high": 102, "low": 98, "close": 101, "volume": 10 }
              ],
              "parameters": [],
              "callbacks": [
                { "entrypoint": "bar", "timeIndex": 0, "completedBarIndex": 0,
                  "bid": 0, "ask": 0, "last": 0, "volume": 0 }
              ],
              "launchSeed": 7
            }
            """);
        var signals = new List<WorkerSignal>();

        DaxqSignalWorker.Execute(
            package,
            contentKey,
            frames,
            keyId,
            signingKey.ExportSubjectPublicKeyInfo(),
            signals.Add);

        var signal = Assert.Single(signals);
        Assert.Equal("long", signal.Kind);
        Assert.Equal(0.75d, signal.Strength);
        Assert.Equal(42, signal.NoteId);
        CryptographicOperations.ZeroMemory(contentKey);
        CryptographicOperations.ZeroMemory(plaintext);
    }

    [Fact]
    public void TamperedSignatureWrongTrustBindingAndWrongContentKeyAreRejected()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var contentKey = RandomNumberGenerator.GetBytes(32);
        var plaintext = BuildSignalProgram();
        const string keyId = "signal-worker-test-key";
        var package = BuildPackage(
            plaintext,
            contentKey,
            RandomNumberGenerator.GetBytes(DaxqFormat.NonceSizeBytes),
            keyId,
            signingKey);
        var frames = """
            {"dataRequirements":["bars"],"bars":[{"open":1,"high":1,"low":1,"close":1,"volume":1}],
             "parameters":[],"callbacks":[{"entrypoint":"bar","timeIndex":0,
             "completedBarIndex":0,"bid":0,"ask":0,"last":0,"volume":0}],"launchSeed":1}
            """u8.ToArray();
        var tampered = (byte[])package.Clone();
        var marker = "\"sig\":\""u8.ToArray();
        var markerIndex = IndexOf(tampered, marker);
        Assert.True(markerIndex >= 0);
        var signatureIndex = markerIndex + marker.Length;
        tampered[signatureIndex] = tampered[signatureIndex] == (byte)'A' ? (byte)'B' : (byte)'A';

        var signatureFailure = Record.Exception(() => DaxqSignalWorker.Execute(
            tampered,
            contentKey,
            frames,
            keyId,
            signingKey.ExportSubjectPublicKeyInfo(),
            _ => { }));
        Assert.True(
            signatureFailure is CryptographicException or InvalidDataException,
            signatureFailure?.ToString());
        Assert.Throws<CryptographicException>(() => DaxqSignalWorker.Execute(
            package,
            contentKey,
            frames,
            "different-trusted-key",
            signingKey.ExportSubjectPublicKeyInfo(),
            _ => { }));
        var wrongContentKey = RandomNumberGenerator.GetBytes(32);
        Assert.ThrowsAny<CryptographicException>(() => DaxqSignalWorker.Execute(
            package,
            wrongContentKey,
            frames,
            keyId,
            signingKey.ExportSubjectPublicKeyInfo(),
            _ => { }));
        CryptographicOperations.ZeroMemory(contentKey);
        CryptographicOperations.ZeroMemory(wrongContentKey);
        CryptographicOperations.ZeroMemory(plaintext);
    }

    private static byte[] BuildSignalProgram()
    {
        var bytecode = new List<byte>();
        WriteInstruction(bytecode, Opcode.PUSH_I64, 0);
        WriteInstruction(bytecode, Opcode.PUSH_F64, 1);
        WriteInstruction(bytecode, Opcode.PUSH_I64, 2);
        bytecode.Add((byte)Opcode.CALL_HOST);
        WriteUInt16(bytecode, (ushort)HostFn.Emit);
        bytecode.Add(3);
        bytecode.Add((byte)Opcode.RET);

        var constants = new byte[2 + (3 * 9)];
        BinaryPrimitives.WriteUInt16LittleEndian(constants, 3);
        WriteConstant(constants, 0, DaxqValueType.I64, 1);
        WriteConstant(constants, 1, DaxqValueType.F64, BitConverter.DoubleToInt64Bits(0.75d));
        WriteConstant(constants, 2, DaxqValueType.I64, 42);

        var usedOpcodes = new[]
        {
            Opcode.PUSH_F64,
            Opcode.PUSH_I64,
            Opcode.CALL_HOST,
            Opcode.RET,
        };
        var opcodeMap = new byte[2 + (usedOpcodes.Length * 2)];
        BinaryPrimitives.WriteUInt16LittleEndian(opcodeMap, (ushort)usedOpcodes.Length);
        for (var index = 0; index < usedOpcodes.Length; index++)
        {
            opcodeMap[2 + (index * 2)] = (byte)usedOpcodes[index];
            opcodeMap[3 + (index * 2)] = (byte)usedOpcodes[index];
        }

        var hostMap = new byte[6];
        BinaryPrimitives.WriteUInt16LittleEndian(hostMap, 1);
        BinaryPrimitives.WriteUInt16LittleEndian(hostMap.AsSpan(2), (ushort)HostFn.Emit);
        BinaryPrimitives.WriteUInt16LittleEndian(hostMap.AsSpan(4), (ushort)HostFn.Emit);

        var entrypoints = new byte[19];
        BinaryPrimitives.WriteUInt16LittleEndian(entrypoints, 0);
        entrypoints[2] = 1;
        entrypoints[3] = (byte)DaxqEntrypoint.OnBar;
        entrypoints[4] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(
            entrypoints.AsSpan(15),
            (uint)bytecode.Count);

        var watermark = new byte[39];
        watermark[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(watermark.AsSpan(1), 2);
        watermark[3] = (byte)'w';
        watermark[4] = (byte)'m';
        BinaryPrimitives.WriteUInt16LittleEndian(watermark.AsSpan(5), 32);

        byte[][] sections =
        [
            bytecode.ToArray(),
            constants,
            opcodeMap,
            hostMap,
            entrypoints,
            watermark,
        ];
        var length = 16 + (sections.Length * 12) + sections.Sum(section => section.Length);
        var plaintext = new byte[length];
        "DQXP"u8.CopyTo(plaintext);
        BinaryPrimitives.WriteUInt16LittleEndian(
            plaintext.AsSpan(4),
            DaxqFormat.PlaintextContainerVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(
            plaintext.AsSpan(6),
            DaxqFormat.VmAbiVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(plaintext.AsSpan(8), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(plaintext.AsSpan(12), (uint)length);
        var sectionOffset = 16 + (sections.Length * 12);
        for (var index = 0; index < sections.Length; index++)
        {
            var directory = plaintext.AsSpan(16 + (index * 12), 12);
            BinaryPrimitives.WriteUInt16LittleEndian(directory, (ushort)(index + 1));
            BinaryPrimitives.WriteUInt32LittleEndian(directory[4..], (uint)sectionOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(directory[8..], (uint)sections[index].Length);
            sections[index].CopyTo(plaintext, sectionOffset);
            sectionOffset += sections[index].Length;
        }

        return plaintext;
    }

    private static byte[] BuildPackage(
        byte[] plaintext,
        byte[] contentKey,
        byte[] nonce,
        string keyId,
        ECDsa signingKey)
    {
        var ciphertext = new byte[plaintext.Length + DaxqFormat.AuthenticationTagSizeBytes];
        using (var aes = new AesGcm(contentKey, DaxqFormat.AuthenticationTagSizeBytes))
        {
            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext.AsSpan(0, plaintext.Length),
                ciphertext.AsSpan(plaintext.Length),
                ReadOnlySpan<byte>.Empty);
        }

        var cipherSha = Sha256Hex(ciphertext);
        var manifest = new DaxqManifest
        {
            FormatVersion = DaxqFormat.FormatVersion,
            Kind = DaxqFormat.Kind,
            StrategyId = "worker.signal.test",
            Version = "1.0.0",
            SdkAbiVersion = DaxqFormat.SdkAbiVersion,
            ExecutionClass = ExecutionClass.SealedBytecode,
            DataRequirements = ["bars"],
            Parameters = [],
            Protection = new DaxqProtectionManifest
            {
                Algorithm = DaxqFormat.CipherAlgorithm,
                ContentKeyId = "ck_worker_signal_test",
                Nonce = Base64Url(nonce),
                CipherSha256 = cipherSha,
            },
            Watermark = new DaxqWatermarkManifest
            {
                Scheme = "per-buyer-v1",
                Slot = "wm",
            },
            VmMin = DaxqFormat.VmAbiVersion,
            Files = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [DaxqFormat.ManifestEntryName] = "self",
                [DaxqFormat.CiphertextEntryName] = cipherSha,
            },
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        var indexBytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            formatVersion = DaxqFormat.FormatVersion,
            files = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [DaxqFormat.ManifestEntryName] = Sha256Hex(manifestBytes),
                [DaxqFormat.CiphertextEntryName] = cipherSha,
            },
        });
        var signature = signingKey.SignData(
            BuildSignatureInput(keyId, manifestBytes, indexBytes),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var signatureBytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = DaxqFormat.SignatureAlgorithm,
            keyId,
            sig = Base64Url(signature),
        });

        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8))
        {
            WriteEntry(archive, DaxqFormat.ManifestEntryName, manifestBytes);
            WriteEntry(archive, DaxqFormat.CiphertextEntryName, ciphertext);
            WriteEntry(archive, DaxqFormat.PackageIndexEntryName, indexBytes);
            WriteEntry(archive, DaxqFormat.SignatureEntryName, signatureBytes);
        }

        CryptographicOperations.ZeroMemory(ciphertext);
        return output.ToArray();
    }

    private static byte[] BuildSignatureInput(string keyId, byte[] manifest, byte[] index)
    {
        var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
        using var stream = new MemoryStream();
        stream.Write("DAXQ-SIG-V1"u8);
        stream.WriteByte(0);
        Span<byte> integer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(integer[..2], (ushort)keyIdBytes.Length);
        stream.Write(integer[..2]);
        stream.Write(keyIdBytes);
        BinaryPrimitives.WriteUInt32BigEndian(integer, (uint)manifest.Length);
        stream.Write(integer);
        stream.Write(manifest);
        BinaryPrimitives.WriteUInt32BigEndian(integer, (uint)index.Length);
        stream.Write(integer);
        stream.Write(index);
        return stream.ToArray();
    }

    private static void WriteInstruction(List<byte> bytes, Opcode opcode, ushort operand)
    {
        bytes.Add((byte)opcode);
        WriteUInt16(bytes, operand);
    }

    private static void WriteUInt16(List<byte> bytes, ushort value)
    {
        bytes.Add((byte)value);
        bytes.Add((byte)(value >> 8));
    }

    private static void WriteConstant(
        byte[] bytes,
        int index,
        DaxqValueType type,
        long rawValue)
    {
        bytes[2 + (index * 9)] = (byte)type;
        BinaryPrimitives.WriteInt64LittleEndian(
            bytes.AsSpan(3 + (index * 9)),
            rawValue);
    }

    private static void WriteEntry(ZipArchive archive, string name, byte[] bytes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        using var stream = entry.Open();
        stream.Write(bytes);
    }

    private static string Sha256Hex(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static int IndexOf(ReadOnlySpan<byte> value, ReadOnlySpan<byte> marker)
    {
        for (var index = 0; index <= value.Length - marker.Length; index++)
        {
            if (value.Slice(index, marker.Length).SequenceEqual(marker))
            {
                return index;
            }
        }

        return -1;
    }
}
