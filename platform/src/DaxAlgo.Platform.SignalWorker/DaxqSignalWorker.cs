using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;

namespace DaxAlgo.Platform.SignalWorker;

public static class DaxqSignalWorker
{
    private static readonly JsonSerializerOptions InputJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 32,
    };

    public static void Execute(
        byte[] packageBytes,
        byte[] contentKey,
        byte[] marketDataFrames,
        string releaseSigningKeyId,
        byte[] releaseVerificationKeySpki,
        Action<WorkerSignal> emit)
    {
        ArgumentNullException.ThrowIfNull(packageBytes);
        ArgumentNullException.ThrowIfNull(contentKey);
        ArgumentNullException.ThrowIfNull(marketDataFrames);
        ArgumentException.ThrowIfNullOrWhiteSpace(releaseSigningKeyId);
        ArgumentNullException.ThrowIfNull(releaseVerificationKeySpki);
        ArgumentNullException.ThrowIfNull(emit);

        var loaded = ReadPackage(
            packageBytes,
            releaseSigningKeyId,
            releaseVerificationKeySpki);
        var plaintext = Decrypt(loaded.Manifest, loaded.Ciphertext, contentKey);
        try
        {
            var fault = DaxqProgram.TryLoad(plaintext, out var program);
            if (fault != DaxqFault.Ok || program is null)
            {
                throw new InvalidDataException($"The DAXQ VM rejected the plaintext ({fault}).");
            }

            using (program)
            {
                var frames = ReadFrames(marketDataFrames, loaded.Manifest, program);
                var host = new DaxqSdkAbi3FrameHost(frames.Bars, frames.Parameters);
                using var vm = new DaxqReferenceVm(program, host, frames.LaunchSeed);
                if (program.HasEntrypoint(DaxqEntrypoint.Initialize))
                {
                    RequireSuccess(vm.Initialize(), "Initialize");
                    Emit(vm.EmittedSignals, emit);
                }

                foreach (var callback in frames.Callbacks)
                {
                    host.CurrentCompletedBarIndex = callback.CompletedBarIndex;
                    var result = callback.Entrypoint == "bar"
                        ? vm.OnBar(callback.TimeIndex)
                        : vm.OnTick(
                            callback.TimeIndex,
                            callback.Bid,
                            callback.Ask,
                            callback.Last,
                            callback.Volume);
                    RequireSuccess(result, callback.Entrypoint);
                    Emit(vm.EmittedSignals, emit);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(loaded.Ciphertext);
        }
    }

    private static void Emit(ReadOnlySpan<DaxqSignal> signals, Action<WorkerSignal> emit)
    {
        foreach (var signal in signals)
        {
            var kind = signal.Kind switch
            {
                1 => "long",
                -1 => "short",
                0 => "flat",
                _ => throw new InvalidDataException("The VM emitted an unsupported signal kind."),
            };
            if (!double.IsFinite(signal.Strength) || signal.Strength is < 0 or > 1)
            {
                throw new InvalidDataException("The VM emitted an invalid signal strength.");
            }

            emit(new WorkerSignal(kind, signal.Strength, signal.NoteId));
        }
    }

    private static void RequireSuccess(DaxqInvocationResult result, string callback)
    {
        if (!result.Succeeded)
        {
            throw new InvalidDataException($"The DAXQ VM rejected {callback} ({result.Fault}).");
        }
    }

    private static ReferenceFrames ReadFrames(
        byte[] bytes,
        DaxqManifest manifest,
        DaxqProgram program)
    {
        var document = JsonSerializer.Deserialize<ReferenceFramesDocument>(bytes, InputJsonOptions)
            ?? throw new JsonException("The reference frame source is empty.");
        if (document.Bars.Length > 1_000_000
            || document.Callbacks.Length > 1_000_000
            || document.Parameters.Length > 256
            || !document.DataRequirements.SequenceEqual(manifest.DataRequirements, StringComparer.Ordinal)
            || document.Parameters.Length != manifest.Parameters.Length)
        {
            throw new InvalidDataException("The reference frame source does not match the release manifest.");
        }

        var bars = document.Bars
            .Select(item => new DaxqBar(item.Open, item.High, item.Low, item.Close, item.Volume))
            .ToArray();
        var parameters = new double[document.Parameters.Length];
        for (var index = 0; index < document.Parameters.Length; index++)
        {
            var supplied = document.Parameters[index];
            var declared = manifest.Parameters[index];
            if (!string.Equals(supplied.Id, declared.Id, StringComparison.Ordinal)
                || !string.Equals(supplied.Type, declared.Type, StringComparison.Ordinal)
                || supplied.Default.GetRawText() != declared.Default.GetRawText())
            {
                throw new InvalidDataException(
                    "The reference parameter defaults do not match the signed release manifest.");
            }

            parameters[index] = supplied.Type switch
            {
                "float" when supplied.Default.TryGetDouble(out var value) && double.IsFinite(value) => value,
                "int" when supplied.Default.TryGetInt64(out var value) => checked((double)value),
                "bool" when supplied.Default.ValueKind is JsonValueKind.True or JsonValueKind.False =>
                    supplied.Default.GetBoolean() ? 1d : 0d,
                _ => throw new InvalidDataException("A reference parameter default is invalid."),
            };
        }

        foreach (var callback in document.Callbacks)
        {
            if (callback.CompletedBarIndex < -1
                || callback.CompletedBarIndex >= bars.Length
                || callback.Entrypoint is not ("bar" or "tick")
                || (callback.Entrypoint == "bar" && !program.HasEntrypoint(DaxqEntrypoint.OnBar))
                || (callback.Entrypoint == "tick" && !program.HasEntrypoint(DaxqEntrypoint.OnTick))
                || (callback.Entrypoint == "tick"
                    && (!double.IsFinite(callback.Bid)
                        || !double.IsFinite(callback.Ask)
                        || !double.IsFinite(callback.Last)
                        || !double.IsFinite(callback.Volume))))
            {
                throw new InvalidDataException("A reference callback is outside the frozen VM contract.");
            }
        }

        return new ReferenceFrames(
            bars,
            parameters,
            document.Callbacks,
            document.LaunchSeed);
    }

    private static LoadedPackage ReadPackage(
        byte[] packageBytes,
        string expectedKeyId,
        byte[] releaseVerificationKeySpki)
    {
        if (packageBytes.Length is <= 0 or > 10 * 1024 * 1024)
        {
            throw new InvalidDataException("The DAXQ package is outside its size bound.");
        }

        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            DaxqFormat.ManifestEntryName,
            DaxqFormat.CiphertextEntryName,
            DaxqFormat.PackageIndexEntryName,
            DaxqFormat.SignatureEntryName,
        };
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        using (var stream = new MemoryStream(packageBytes, writable: false))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false, Encoding.UTF8))
        {
            if (archive.Entries.Count != expected.Count)
            {
                throw new InvalidDataException("A DAXQ v1 package must contain exactly four entries.");
            }

            foreach (var entry in archive.Entries)
            {
                var name = entry.FullName;
                var limit = name switch
                {
                    DaxqFormat.ManifestEntryName => 64 * 1024,
                    DaxqFormat.CiphertextEntryName => 8 * 1024 * 1024,
                    DaxqFormat.PackageIndexEntryName => 16 * 1024,
                    DaxqFormat.SignatureEntryName => 4 * 1024,
                    _ => 0,
                };
                var unixFileType = (entry.ExternalAttributes >> 16) & 0xF000;
                if (!expected.Contains(name)
                    || name != entry.Name
                    || name.Contains('/')
                    || name.Contains('\\')
                    || unixFileType == 0xA000
                    || (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0
                    || entry.Length is <= 0 or > int.MaxValue
                    || entry.Length > limit
                    || (entry.Length > 4096
                        && (entry.CompressedLength == 0
                            || entry.Length / entry.CompressedLength > 100)))
                {
                    throw new InvalidDataException("The DAXQ package contains an unsafe ZIP entry.");
                }

                var value = new byte[checked((int)entry.Length)];
                using var input = entry.Open();
                input.ReadExactly(value);
                if (input.ReadByte() != -1 || !entries.TryAdd(name, value))
                {
                    throw new InvalidDataException("The DAXQ package contains a malformed entry.");
                }
            }
        }

        var manifestBytes = entries[DaxqFormat.ManifestEntryName];
        var ciphertext = entries[DaxqFormat.CiphertextEntryName];
        var indexBytes = entries[DaxqFormat.PackageIndexEntryName];
        var signatureBytes = entries[DaxqFormat.SignatureEntryName];
        var manifest = JsonSerializer.Deserialize<DaxqManifest>(manifestBytes)
            ?? throw new JsonException("The DAXQ manifest is empty.");
        ValidateManifest(manifest, ciphertext);
        ValidateIndex(indexBytes, manifestBytes, ciphertext);
        VerifySignature(
            signatureBytes,
            manifestBytes,
            indexBytes,
            expectedKeyId,
            releaseVerificationKeySpki);
        return new LoadedPackage(manifest, ciphertext);
    }

    private static void ValidateManifest(DaxqManifest manifest, byte[] ciphertext)
    {
        if (manifest.FormatVersion != DaxqFormat.FormatVersion
            || manifest.Kind != DaxqFormat.Kind
            || manifest.SdkAbiVersion != DaxqFormat.SdkAbiVersion
            || manifest.VmMin != DaxqFormat.VmAbiVersion
            || manifest.ExecutionClass != ExecutionClass.SealedBytecode
            || manifest.DataRequirements is not { Length: >= 1 and <= 2 }
            || manifest.DataRequirements.Any(value => value is not ("bars" or "ticks"))
            || manifest.Parameters.Length > 256
            || manifest.Protection.Algorithm != DaxqFormat.CipherAlgorithm
            || manifest.Watermark.Scheme != "per-buyer-v1"
            || manifest.Watermark.Slot != "wm"
            || manifest.Files.Count != 2
            || manifest.Files.GetValueOrDefault(DaxqFormat.ManifestEntryName) != "self"
            || manifest.Files.GetValueOrDefault(DaxqFormat.CiphertextEntryName)
                != manifest.Protection.CipherSha256)
        {
            throw new InvalidDataException("The manifest is not a supported sealed DAXQ v1 program.");
        }

        AssertSha256(ciphertext, manifest.Protection.CipherSha256);
        _ = DecodeBase64Url(manifest.Protection.Nonce, DaxqFormat.NonceSizeBytes);
    }

    private static void ValidateIndex(byte[] indexBytes, byte[] manifestBytes, byte[] ciphertext)
    {
        using var document = JsonDocument.Parse(indexBytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || root.EnumerateObject().Select(item => item.Name).Order().ToArray()
                is not ["files", "formatVersion"]
            || root.GetProperty("formatVersion").GetInt32() != DaxqFormat.FormatVersion)
        {
            throw new InvalidDataException("The DAXQ integrity index is invalid.");
        }

        var files = root.GetProperty("files");
        var names = files.EnumerateObject().Select(item => item.Name).Order().ToArray();
        if (names.Length != 2
            || names[0] != DaxqFormat.ManifestEntryName
            || names[1] != DaxqFormat.CiphertextEntryName)
        {
            throw new InvalidDataException("The DAXQ integrity index is invalid.");
        }

        AssertSha256(manifestBytes, files.GetProperty(DaxqFormat.ManifestEntryName).GetString());
        AssertSha256(ciphertext, files.GetProperty(DaxqFormat.CiphertextEntryName).GetString());
    }

    private static void VerifySignature(
        byte[] signatureEnvelope,
        byte[] manifest,
        byte[] index,
        string expectedKeyId,
        byte[] publicKeySpki)
    {
        using var document = JsonDocument.Parse(signatureEnvelope, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        var properties = root.EnumerateObject().Select(item => item.Name).Order().ToArray();
        var keyId = root.GetProperty("keyId").GetString();
        if (properties.Length != 3
            || properties[0] != "alg"
            || properties[1] != "keyId"
            || properties[2] != "sig"
            || root.GetProperty("alg").GetString() != DaxqFormat.SignatureAlgorithm
            || !string.Equals(keyId, expectedKeyId, StringComparison.Ordinal))
        {
            throw new CryptographicException("The DAXQ signature metadata is not trusted.");
        }

        var signature = DecodeBase64Url(
            root.GetProperty("sig").GetString(),
            DaxqFormat.SignatureSizeBytes);
        var input = BuildSignatureInput(expectedKeyId, manifest, index);
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(publicKeySpki, out var bytesRead);
        if (bytesRead != publicKeySpki.Length
            || !verifier.VerifyData(
                input,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new CryptographicException("The DAXQ release signature is invalid.");
        }
    }

    private static byte[] BuildSignatureInput(string keyId, byte[] manifest, byte[] index)
    {
        var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
        using var stream = new MemoryStream();
        stream.Write("DAXQ-SIG-V1"u8);
        stream.WriteByte(0);
        Span<byte> integer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(integer, checked((ushort)keyIdBytes.Length));
        stream.Write(integer[..2]);
        stream.Write(keyIdBytes);
        BinaryPrimitives.WriteUInt32BigEndian(integer, checked((uint)manifest.Length));
        stream.Write(integer);
        stream.Write(manifest);
        BinaryPrimitives.WriteUInt32BigEndian(integer, checked((uint)index.Length));
        stream.Write(integer);
        stream.Write(index);
        return stream.ToArray();
    }

    private static byte[] Decrypt(DaxqManifest manifest, byte[] ciphertextAndTag, byte[] contentKey)
    {
        if (contentKey.Length != 32
            || ciphertextAndTag.Length <= DaxqFormat.AuthenticationTagSizeBytes)
        {
            throw new InvalidDataException("The encrypted DAXQ payload is invalid.");
        }

        var nonce = DecodeBase64Url(manifest.Protection.Nonce, DaxqFormat.NonceSizeBytes);
        var plaintext = new byte[ciphertextAndTag.Length - DaxqFormat.AuthenticationTagSizeBytes];
        try
        {
            using var aes = new AesGcm(contentKey, DaxqFormat.AuthenticationTagSizeBytes);
            aes.Decrypt(
                nonce,
                ciphertextAndTag.AsSpan(0, plaintext.Length),
                ciphertextAndTag.AsSpan(plaintext.Length),
                plaintext,
                ReadOnlySpan<byte>.Empty);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static void AssertSha256(byte[] bytes, string? expected)
    {
        if (expected is not { Length: 64 }
            || expected.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new InvalidDataException("A DAXQ SHA-256 value is not canonical.");
        }

        var actual = SHA256.HashData(bytes);
        var expectedBytes = Convert.FromHexString(expected);
        if (!CryptographicOperations.FixedTimeEquals(actual, expectedBytes))
        {
            throw new InvalidDataException("A DAXQ integrity hash did not match.");
        }
    }

    private static byte[] DecodeBase64Url(string? value, int expectedLength)
    {
        if (string.IsNullOrEmpty(value)
            || value.Any(character => character is not (
                >= 'A' and <= 'Z' or
                >= 'a' and <= 'z' or
                >= '0' and <= '9' or
                '-' or '_')))
        {
            throw new InvalidDataException("A DAXQ base64url value is malformed.");
        }

        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            0 => padded,
            2 => padded + "==",
            3 => padded + "=",
            _ => throw new InvalidDataException("A DAXQ base64url value is malformed."),
        };
        var decoded = Convert.FromBase64String(padded);
        if (decoded.Length != expectedLength
            || Convert.ToBase64String(decoded).TrimEnd('=').Replace('+', '-').Replace('/', '_') != value)
        {
            throw new InvalidDataException("A DAXQ base64url value is non-canonical.");
        }

        return decoded;
    }

    private sealed record LoadedPackage(DaxqManifest Manifest, byte[] Ciphertext);

    private sealed record ReferenceFrames(
        DaxqBar[] Bars,
        double[] Parameters,
        ReferenceCallback[] Callbacks,
        ulong LaunchSeed);

    private sealed record ReferenceFramesDocument
    {
        public string[] DataRequirements { get; init; } = [];

        public ReferenceBar[] Bars { get; init; } = [];

        public ReferenceParameter[] Parameters { get; init; } = [];

        public ReferenceCallback[] Callbacks { get; init; } = [];

        public ulong LaunchSeed { get; init; }
    }

    private sealed record ReferenceParameter
    {
        public string Id { get; init; } = string.Empty;

        public string Type { get; init; } = string.Empty;

        public JsonElement Default { get; init; }
    }

    private sealed record ReferenceBar
    {
        public double Open { get; init; }

        public double High { get; init; }

        public double Low { get; init; }

        public double Close { get; init; }

        public double Volume { get; init; }
    }

    private sealed record ReferenceCallback
    {
        public string Entrypoint { get; init; } = string.Empty;

        public long TimeIndex { get; init; }

        public int CompletedBarIndex { get; init; } = -1;

        public double Bid { get; init; }

        public double Ask { get; init; }

        public double Last { get; init; }

        public double Volume { get; init; }
    }
}

public sealed record WorkerSignal(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("strength")] double Strength,
    [property: JsonPropertyName("note_id")] long NoteId);
