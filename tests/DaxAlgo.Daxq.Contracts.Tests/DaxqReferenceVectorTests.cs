using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Contracts.Tests;

public sealed class DaxqReferenceVectorTests
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    private static readonly JsonSerializerOptions FixtureJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    [Fact]
    public void Contract_constants_are_frozen()
    {
        Assert.Equal(".daxq", DaxqFormat.PackageExtension);
        Assert.Equal(1, DaxqFormat.FormatVersion);
        Assert.Equal(2, DaxqFormat.PresentationFormatVersion);
        Assert.Equal(1, DaxqFormat.PlaintextContainerVersion);
        Assert.Equal(3, DaxqFormat.VmAbiVersion);
        Assert.Equal(4, DaxqFormat.RenderVmAbiVersion);
        Assert.Equal(3, DaxqFormat.SdkAbiVersion);
        Assert.Equal(DaxqKind.Strategy, (DaxqKind)DaxqFormat.Kind);
        Assert.Equal("daxq", DaxqFormat.LegacyKindWireName);
        Assert.Equal("manifest.json", DaxqFormat.ManifestEntryName);
        Assert.Equal("strategy.dqx", DaxqFormat.CiphertextEntryName);
        Assert.Equal("package.json", DaxqFormat.PackageIndexEntryName);
        Assert.Equal("signature.json", DaxqFormat.SignatureEntryName);
    }

    [Fact]
    public void Canonical_opcode_map_matches_the_frozen_enum_and_vector_bytes()
    {
        using var document = JsonDocument.Parse(ReadFixture("opcode-map-v1.json"));
        var root = document.RootElement;
        Assert.Equal(DaxqFormat.FormatVersion, root.GetProperty("formatVersion").GetInt32());
        Assert.Equal(DaxqFormat.VmAbiVersion, root.GetProperty("vmAbiVersion").GetInt32());
        Assert.Equal("encoded_to_canonical", root.GetProperty("mapDirection").GetString());

        var entries = root.GetProperty("entries").EnumerateArray().ToArray();
        Assert.Equal(Enum.GetValues<Opcode>().Length, entries.Length);

        var encoded = new byte[2 + (entries.Length * 2)];
        BinaryPrimitives.WriteUInt16LittleEndian(encoded, checked((ushort)entries.Length));
        for (var index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            var encodedId = entry.GetProperty("encodedId").GetByte();
            var opcodeId = entry.GetProperty("opcodeId").GetByte();
            var name = entry.GetProperty("name").GetString()!;

            Assert.Equal(index + 1, encodedId);
            Assert.Equal(encodedId, opcodeId);
            Assert.Equal((Opcode)opcodeId, Enum.Parse<Opcode>(name, ignoreCase: false));
            encoded[2 + (index * 2)] = encodedId;
            encoded[3 + (index * 2)] = opcodeId;
        }

        AssertBytesEqual(Hex(LoadVector().OpcodeMapHex), encoded);
    }

    [Fact]
    public void Canonical_host_map_matches_the_frozen_enum_and_vector_bytes()
    {
        using var document = JsonDocument.Parse(ReadFixture("host-map-v1.json"));
        var root = document.RootElement;
        Assert.Equal(DaxqFormat.FormatVersion, root.GetProperty("formatVersion").GetInt32());
        Assert.Equal(DaxqFormat.VmAbiVersion, root.GetProperty("vmAbiVersion").GetInt32());
        Assert.Equal("encoded_to_canonical", root.GetProperty("mapDirection").GetString());

        var entries = root.GetProperty("entries").EnumerateArray().ToArray();
        Assert.Equal(Enum.GetValues<HostFn>().Length, entries.Length);
        string[] expectedWireNames = ["bar", "ind", "param", "emit", "state", "tindex", "rng", "log"];

        var encoded = new byte[2 + (entries.Length * 4)];
        BinaryPrimitives.WriteUInt16LittleEndian(encoded, checked((ushort)entries.Length));
        for (var index = 0; index < entries.Length; index++)
        {
            var entry = entries[index];
            var encodedId = entry.GetProperty("encodedId").GetUInt16();
            var hostId = entry.GetProperty("hostId").GetUInt16();
            var name = entry.GetProperty("name").GetString()!;

            Assert.Equal(index + 1, encodedId);
            Assert.Equal(encodedId, hostId);
            Assert.Equal((HostFn)hostId, Enum.Parse<HostFn>(name, ignoreCase: false));
            Assert.Equal(expectedWireNames[index], entry.GetProperty("wireName").GetString());
            Assert.Equal(hostId != (ushort)HostFn.State, entry.GetProperty("callable").GetBoolean());

            var offset = 2 + (index * 4);
            BinaryPrimitives.WriteUInt16LittleEndian(encoded.AsSpan(offset, 2), encodedId);
            BinaryPrimitives.WriteUInt16LittleEndian(encoded.AsSpan(offset + 2, 2), hostId);
        }

        AssertBytesEqual(Hex(LoadVector().HostMapHex), encoded);
    }

    [Fact]
    public void Ema_cross_listing_container_and_encryption_match_the_golden_vector()
    {
        var vector = LoadVector();
        var bytecode = Hex(vector.BytecodeHex);
        Assert.Equal(88, bytecode.Length);
        Assert.Equal(vector.BytecodeSha256, Sha256(bytecode));
        AssertBytesEqual(bytecode, ReadListingBytes());

        var components = new[]
        {
            bytecode,
            Hex(vector.ConstantPoolHex),
            Hex(vector.OpcodeMapHex),
            Hex(vector.HostMapHex),
            Hex(vector.EntrypointsHex),
            Hex(vector.WatermarkHex),
        };
        Assert.Equal(vector.ConstantPoolSha256, Sha256(components[1]));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(components[4].AsSpan(0, 2)));
        Assert.Equal(1, components[4][2]);
        Assert.Equal(1, components[4][3]);
        Assert.Equal(1, components[4][4]);

        var plaintext = Hex(vector.CanonicalPlaintextHex);
        Assert.Equal(vector.CanonicalPlaintextSha256, Sha256(plaintext));
        Assert.Equal("DQXP", Encoding.ASCII.GetString(plaintext, 0, 4));
        Assert.Equal(DaxqFormat.PlaintextContainerVersion,
            BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(4, 2)));
        Assert.Equal(DaxqFormat.VmAbiVersion,
            BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(6, 2)));
        Assert.Equal(components.Length, BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(8, 2)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(10, 2)));
        Assert.Equal(plaintext.Length,
            checked((int)BinaryPrimitives.ReadUInt32LittleEndian(plaintext.AsSpan(12, 4))));

        var expectedOffset = 16 + (components.Length * 12);
        for (var index = 0; index < components.Length; index++)
        {
            var directoryOffset = 16 + (index * 12);
            Assert.Equal(index + 1,
                BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(directoryOffset, 2)));
            Assert.Equal(0,
                BinaryPrimitives.ReadUInt16LittleEndian(plaintext.AsSpan(directoryOffset + 2, 2)));
            var sectionOffset = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(
                plaintext.AsSpan(directoryOffset + 4, 4)));
            var sectionLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(
                plaintext.AsSpan(directoryOffset + 8, 4)));
            Assert.Equal(expectedOffset, sectionOffset);
            Assert.Equal(components[index].Length, sectionLength);
            AssertBytesEqual(components[index], plaintext.AsSpan(sectionOffset, sectionLength).ToArray());
            expectedOffset += sectionLength;
        }
        Assert.Equal(plaintext.Length, expectedOffset);

        var key = Hex(vector.Aes256KeyHex);
        var nonce = Hex(vector.NonceHex);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[DaxqFormat.AuthenticationTagSizeBytes];
        using (var aes = new AesGcm(key, DaxqFormat.AuthenticationTagSizeBytes))
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var encryptedFile = ciphertext.Concat(tag).ToArray();
        AssertBytesEqual(Hex(vector.CiphertextAndTagHex), encryptedFile);
        Assert.Equal(vector.CipherSha256, Sha256(encryptedFile));
    }

    [Fact]
    public void Manifest_dto_round_trips_to_the_canonical_reference_bytes()
    {
        var vector = LoadVector();
        var manifest = JsonSerializer.Deserialize<DaxqManifest>(
            ReadFixture("ema-cross-v1.manifest.json"), ManifestJsonOptions)!;

        Assert.Equal(DaxqFormat.FormatVersion, manifest.FormatVersion);
        Assert.Equal((DaxqKind)DaxqFormat.Kind, manifest.Kind);
        Assert.Equal(DaxqFormat.VmAbiVersion, manifest.VmMin);
        Assert.Equal(DaxqFormat.SdkAbiVersion, manifest.SdkAbiVersion);
        Assert.Equal(ExecutionClass.SealedBytecode, manifest.ExecutionClass);
        Assert.Equal(DaxqFormat.CipherAlgorithm, manifest.Protection.Algorithm);
        Assert.Equal(vector.CipherSha256, manifest.Protection.CipherSha256);
        Assert.Equal("self", manifest.Files[DaxqFormat.ManifestEntryName]);
        Assert.Equal(vector.CipherSha256, manifest.Files[DaxqFormat.CiphertextEntryName]);

        var dtoBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJsonOptions);
        AssertBytesEqual(Hex(vector.CanonicalManifestUtf8Hex), dtoBytes);
        var roundTrip = JsonSerializer.Deserialize<DaxqManifest>(dtoBytes, ManifestJsonOptions)!;
        Assert.Equal(manifest.StrategyId, roundTrip.StrategyId);
        Assert.Equal(manifest.Version, roundTrip.Version);
        Assert.Equal(manifest.ExecutionClass, roundTrip.ExecutionClass);
        Assert.Equal(manifest.Files, roundTrip.Files);

        var canonicalManifest = SerializeCanonicalManifest(manifest);
        AssertBytesEqual(Hex(vector.CanonicalManifestUtf8Hex), canonicalManifest);
        Assert.Equal(vector.ManifestSha256, Sha256(canonicalManifest));

        using var indexDocument = JsonDocument.Parse(ReadFixture("ema-cross-v1.package.json"));
        var canonicalIndex = SerializeCanonicalPackageIndex(indexDocument.RootElement);
        AssertBytesEqual(Hex(vector.CanonicalPackageIndexUtf8Hex), canonicalIndex);
        Assert.Equal(vector.PackageIndexSha256, Sha256(canonicalIndex));
        var indexedFiles = indexDocument.RootElement.GetProperty("files");
        Assert.Equal(vector.ManifestSha256,
            indexedFiles.GetProperty(DaxqFormat.ManifestEntryName).GetString());
        Assert.Equal(vector.CipherSha256,
            indexedFiles.GetProperty(DaxqFormat.CiphertextEntryName).GetString());
    }

    [Fact]
    public void Signature_framing_and_p256_signature_match_the_golden_vector()
    {
        var vector = LoadVector();
        var manifestBytes = Hex(vector.CanonicalManifestUtf8Hex);
        var indexBytes = Hex(vector.CanonicalPackageIndexUtf8Hex);
        var signatureInput = BuildSignatureInput(vector.ReleaseKeyId, manifestBytes, indexBytes);
        AssertBytesEqual(Hex(vector.SignatureInputHex), signatureInput);
        Assert.Equal(vector.SignatureInputSha256, Sha256(signatureInput));
        Assert.Equal(0, signatureInput["DAXQ-SIG-V1".Length]);

        using var signatureDocument = JsonDocument.Parse(ReadFixture("ema-cross-v1.signature.json"));
        var signatureRoot = signatureDocument.RootElement;
        Assert.Equal(DaxqFormat.SignatureAlgorithm, signatureRoot.GetProperty("alg").GetString());
        Assert.Equal(vector.ReleaseKeyId, signatureRoot.GetProperty("keyId").GetString());
        AssertBytesEqual(
            Hex(vector.CanonicalSignatureUtf8Hex),
            SerializeCanonicalSignature(signatureRoot));

        var signature = Base64UrlDecode(signatureRoot.GetProperty("sig").GetString()!);
        AssertBytesEqual(Hex(vector.SignatureP1363Hex), signature);
        Assert.Equal(DaxqFormat.SignatureSizeBytes, signature.Length);

        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = Hex(vector.ReleasePublicKeyXHex),
                Y = Hex(vector.ReleasePublicKeyYHex),
            },
        });
        Assert.True(verifier.VerifyData(
            signatureInput,
            signature,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("\"SEALED_BYTECODE\"")]
    [InlineData("\"SealedBytecode\"")]
    [InlineData("\"unknown\"")]
    public void Execution_class_rejects_noncanonical_wire_values(string json)
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<ExecutionClass>(json, ManifestJsonOptions));
    }

    [Fact]
    public void Parameter_dtos_round_trip_in_frozen_order_with_canonical_scalars()
    {
        const string json = """
            [
              { "id":"enabled", "type":"bool", "default":true },
              { "id":"lookback", "type":"int", "min":5, "max":200, "default":20 },
              { "id":"threshold", "type":"float", "min":0.25, "max":1.5, "default":1.25 }
            ]
            """;
        var parameters = JsonSerializer.Deserialize<DaxqParameterManifest[]>(json, ManifestJsonOptions)!;
        const string expected = "[{\"id\":\"enabled\",\"type\":\"bool\",\"default\":true}," +
            "{\"id\":\"lookback\",\"type\":\"int\",\"min\":5,\"max\":200,\"default\":20}," +
            "{\"id\":\"threshold\",\"type\":\"float\",\"min\":0.25,\"max\":1.5,\"default\":1.25}]";

        Assert.Equal(expected, Encoding.UTF8.GetString(SerializeCanonicalParameters(parameters)));
        var dtoBytes = JsonSerializer.SerializeToUtf8Bytes(parameters, ManifestJsonOptions);
        var roundTrip = JsonSerializer.Deserialize<DaxqParameterManifest[]>(dtoBytes, ManifestJsonOptions)!;
        Assert.Equal(parameters.Select(parameter => parameter.Id), roundTrip.Select(parameter => parameter.Id));
    }

    [Fact]
    public void Canonical_float_reference_values_match_rfc8785_boundaries()
    {
        var negativeZero = BitConverter.Int64BitsToDouble(long.MinValue);
        (double Value, string Canonical)[] cases =
        [
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e30, "1e+30"),
            (double.Epsilon, "5e-324"),
            (double.MaxValue, "1.7976931348623157e+308"),
            (negativeZero, "0"),
        ];

        foreach (var (value, canonical) in cases)
            Assert.Equal(canonical, CanonicalDouble(value));
    }

    [Fact]
    public void Golden_json_fixtures_have_unique_properties()
    {
        string[] fixtures =
        [
            "opcode-map-v1.json",
            "host-map-v1.json",
            "ema-cross-v1.vector.json",
            "ema-cross-v1.manifest.json",
            "ema-cross-v1.package.json",
            "ema-cross-v1.signature.json",
        ];

        foreach (var fixture in fixtures)
        {
            using var document = JsonDocument.Parse(ReadFixture(fixture));
            AssertUniqueProperties(document.RootElement, fixture);
        }
    }

    private static ReferenceVector LoadVector() =>
        JsonSerializer.Deserialize<ReferenceVector>(
            ReadFixture("ema-cross-v1.vector.json"), FixtureJsonOptions)!;

    private static byte[] ReadListingBytes()
    {
        var bytes = new List<byte>();
        foreach (var line in File.ReadLines(FixturePath("ema-cross-v1.daxqasm")))
        {
            var match = Regex.Match(
                line,
                "^(?<offset>[0-9a-f]{4})\\s+(?<bytes>[0-9a-f]+)\\s+",
                RegexOptions.CultureInvariant);
            if (!match.Success)
                continue;

            Assert.Equal(bytes.Count,
                int.Parse(match.Groups["offset"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            bytes.AddRange(Hex(match.Groups["bytes"].Value));
        }

        return bytes.ToArray();
    }

    private static byte[] SerializeCanonicalManifest(DaxqManifest manifest)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("formatVersion", manifest.FormatVersion);
            writer.WriteString("kind", DaxqFormat.LegacyKindWireName);
            writer.WriteString("strategyId", manifest.StrategyId);
            writer.WriteString("version", manifest.Version);
            writer.WriteNumber("sdkAbiVersion", manifest.SdkAbiVersion);
            writer.WriteString("executionClass", ExecutionClassWireName(manifest.ExecutionClass));
            writer.WriteStartArray("dataRequirements");
            foreach (var requirement in manifest.DataRequirements)
                writer.WriteStringValue(requirement);
            writer.WriteEndArray();
            writer.WritePropertyName("params");
            WriteParameters(writer, manifest.Parameters);
            writer.WriteStartObject("protection");
            writer.WriteString("alg", manifest.Protection.Algorithm);
            writer.WriteString("contentKeyId", manifest.Protection.ContentKeyId);
            writer.WriteString("nonce", manifest.Protection.Nonce);
            writer.WriteString("cipherSha256", manifest.Protection.CipherSha256);
            writer.WriteEndObject();
            writer.WriteStartObject("watermark");
            writer.WriteString("scheme", manifest.Watermark.Scheme);
            writer.WriteString("slot", manifest.Watermark.Slot);
            writer.WriteEndObject();
            writer.WriteNumber("vmMin", manifest.VmMin);
            writer.WriteStartObject("files");
            foreach (var (name, hash) in manifest.Files.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                writer.WriteString(name, hash);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static byte[] SerializeCanonicalParameters(DaxqParameterManifest[] parameters)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
            WriteParameters(writer, parameters);
        return stream.ToArray();
    }

    private static void WriteParameters(
        Utf8JsonWriter writer,
        IEnumerable<DaxqParameterManifest> parameters)
    {
        writer.WriteStartArray();
        foreach (var parameter in parameters)
        {
            writer.WriteStartObject();
            writer.WriteString("id", parameter.Id);
            writer.WriteString("type", parameter.Type);
            if (parameter.Min is { } min)
                WriteParameterScalar(writer, "min", parameter.Type, min, allowBoolean: false);
            if (parameter.Max is { } max)
                WriteParameterScalar(writer, "max", parameter.Type, max, allowBoolean: false);
            WriteParameterScalar(writer, "default", parameter.Type, parameter.Default, allowBoolean: true);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    private static void WriteParameterScalar(
        Utf8JsonWriter writer,
        string propertyName,
        string type,
        JsonElement value,
        bool allowBoolean)
    {
        writer.WritePropertyName(propertyName);
        switch (type)
        {
            case "int":
                writer.WriteNumberValue(value.GetInt64());
                break;
            case "float":
                var number = value.GetDouble();
                if (!double.IsFinite(number))
                    throw new JsonException("DAXQ floating parameters must be finite.");
                writer.WriteRawValue(CanonicalDouble(number), skipInputValidation: false);
                break;
            case "bool" when allowBoolean:
                writer.WriteBooleanValue(value.GetBoolean());
                break;
            default:
                throw new JsonException($"Unsupported DAXQ parameter type '{type}'.");
        }
    }

    private static byte[] SerializeCanonicalPackageIndex(JsonElement root)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("formatVersion", root.GetProperty("formatVersion").GetInt32());
            writer.WriteStartObject("files");
            foreach (var property in root.GetProperty("files").EnumerateObject()
                         .OrderBy(property => property.Name, StringComparer.Ordinal))
                writer.WriteString(property.Name, property.Value.GetString());
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static byte[] SerializeCanonicalSignature(JsonElement root)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", root.GetProperty("alg").GetString());
            writer.WriteString("keyId", root.GetProperty("keyId").GetString());
            writer.WriteString("sig", root.GetProperty("sig").GetString());
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    private static byte[] BuildSignatureInput(string keyId, byte[] manifest, byte[] index)
    {
        using var stream = new MemoryStream();
        stream.Write("DAXQ-SIG-V1"u8);
        stream.WriteByte(0);
        var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
        Span<byte> integer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(integer[..2], checked((ushort)keyIdBytes.Length));
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

    private static string ExecutionClassWireName(ExecutionClass value) => value switch
    {
        ExecutionClass.SourceOpen => "source_open",
        ExecutionClass.SealedBytecode => "sealed_bytecode",
        ExecutionClass.ServerSignal => "server_signal",
        _ => throw new JsonException("Unsupported ExecutionClass value."),
    };

    private static string CanonicalDouble(double value)
    {
        if (!double.IsFinite(value))
            throw new JsonException("DAXQ floating parameters must be finite.");
        if (value == 0d)
            return "0";

        var roundTrip = value.ToString("R", CultureInfo.InvariantCulture);
        var exponentMarker = roundTrip.IndexOf('E');
        if (exponentMarker < 0)
            return roundTrip;

        var mantissa = roundTrip[..exponentMarker];
        var exponent = int.Parse(roundTrip[(exponentMarker + 1)..], CultureInfo.InvariantCulture);
        var magnitude = Math.Abs(value);
        if (magnitude >= 1e-6 && magnitude < 1e21)
            return ScientificToFixed(mantissa, exponent);

        return string.Concat(
            mantissa,
            "e",
            exponent >= 0 ? "+" : "-",
            Math.Abs(exponent).ToString(CultureInfo.InvariantCulture));
    }

    private static string ScientificToFixed(string mantissa, int exponent)
    {
        var negative = mantissa[0] == '-';
        var unsignedMantissa = negative ? mantissa[1..] : mantissa;
        var decimalPoint = unsignedMantissa.IndexOf('.');
        var integerDigits = decimalPoint < 0 ? unsignedMantissa.Length : decimalPoint;
        var digits = decimalPoint < 0
            ? unsignedMantissa
            : unsignedMantissa.Remove(decimalPoint, 1);
        var decimalPosition = integerDigits + exponent;

        string fixedValue;
        if (decimalPosition <= 0)
            fixedValue = string.Concat("0.", new string('0', -decimalPosition), digits);
        else if (decimalPosition >= digits.Length)
            fixedValue = string.Concat(digits, new string('0', decimalPosition - digits.Length));
        else
            fixedValue = string.Concat(digits[..decimalPosition], ".", digits[decimalPosition..]);

        return negative ? string.Concat("-", fixedValue) : fixedValue;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - (base64.Length % 4)) % 4);
        return Convert.FromBase64String(base64);
    }

    private static void AssertUniqueProperties(JsonElement element, string location)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                Assert.True(names.Add(property.Name), $"Duplicate property '{property.Name}' in {location}.");
                AssertUniqueProperties(property.Value, $"{location}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
                AssertUniqueProperties(item, $"{location}[{index++}]");
        }
    }

    private static string ReadFixture(string name) => File.ReadAllText(FixturePath(name), Encoding.UTF8);

    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static byte[] Hex(string value) => Convert.FromHexString(value);

    private static string Sha256(byte[] value) => Convert.ToHexStringLower(SHA256.HashData(value));

    private static void AssertBytesEqual(byte[] expected, byte[] actual) =>
        Assert.True(expected.AsSpan().SequenceEqual(actual),
            $"Expected {Convert.ToHexStringLower(expected)}, actual {Convert.ToHexStringLower(actual)}.");

    private sealed record ReferenceVector
    {
        public required string BytecodeHex { get; init; }
        public required string BytecodeSha256 { get; init; }
        public required string ConstantPoolHex { get; init; }
        public required string ConstantPoolSha256 { get; init; }
        public required string OpcodeMapHex { get; init; }
        public required string HostMapHex { get; init; }
        public required string EntrypointsHex { get; init; }
        public required string WatermarkHex { get; init; }
        public required string CanonicalPlaintextHex { get; init; }
        public required string CanonicalPlaintextSha256 { get; init; }
        public required string Aes256KeyHex { get; init; }
        public required string NonceHex { get; init; }
        public required string CiphertextAndTagHex { get; init; }
        public required string CipherSha256 { get; init; }
        public required string CanonicalManifestUtf8Hex { get; init; }
        public required string ManifestSha256 { get; init; }
        public required string CanonicalPackageIndexUtf8Hex { get; init; }
        public required string PackageIndexSha256 { get; init; }
        public required string ReleaseKeyId { get; init; }
        public required string ReleasePublicKeyXHex { get; init; }
        public required string ReleasePublicKeyYHex { get; init; }
        public required string SignatureInputHex { get; init; }
        public required string SignatureInputSha256 { get; init; }
        public required string SignatureP1363Hex { get; init; }
        public required string CanonicalSignatureUtf8Hex { get; init; }
    }
}
