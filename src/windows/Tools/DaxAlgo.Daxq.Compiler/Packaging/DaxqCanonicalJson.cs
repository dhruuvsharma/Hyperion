using System.Globalization;
using System.Text.Json;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Compiler;

internal static class DaxqCanonicalJson
{
    public static byte[] WriteManifest(
        NormalizedDaxqPackageOptions options,
        string nonce,
        string cipherSha256)
    {
        if (options.FormatVersion == DaxqFormat.PresentationFormatVersion)
        {
            var manifest = new DaxqManifest
            {
                FormatVersion = options.FormatVersion,
                Kind = options.Kind,
                StrategyId = options.StrategyId,
                Version = options.Version,
                SdkAbiVersion = DaxqFormat.SdkAbiVersion,
                ExecutionClass = ExecutionClass.SealedBytecode,
                DataRequirements = options.DataRequirements,
                Parameters = options.Parameters,
                Protection = new DaxqProtectionManifest
                {
                    Algorithm = DaxqFormat.CipherAlgorithm,
                    ContentKeyId = options.ContentKeyId,
                    Nonce = nonce,
                    CipherSha256 = cipherSha256,
                },
                Watermark = new DaxqWatermarkManifest
                {
                    Scheme = "per-buyer-v1",
                    Slot = "wm",
                },
                VmMin = options.Presentation is null
                    ? DaxqFormat.VmAbiVersion
                    : DaxqFormat.RenderVmAbiVersion,
                Files = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [DaxqFormat.ManifestEntryName] = "self",
                    [DaxqFormat.CiphertextEntryName] = cipherSha256,
                },
                Presentation = options.Presentation,
            };
            return JsonSerializer.SerializeToUtf8Bytes(manifest);
        }

        // This is the frozen pre-v2 writer. Keep it byte-for-byte stable for format v1.
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("formatVersion", DaxqFormat.FormatVersion);
            writer.WriteString("kind", DaxqFormat.Kind);
            writer.WriteString("strategyId", options.StrategyId);
            writer.WriteString("version", options.Version);
            writer.WriteNumber("sdkAbiVersion", DaxqFormat.SdkAbiVersion);
            writer.WriteString("executionClass", "sealed_bytecode");
            writer.WriteStartArray("dataRequirements");
            foreach (var requirement in options.DataRequirements)
                writer.WriteStringValue(requirement);
            writer.WriteEndArray();
            writer.WritePropertyName("params");
            WriteParameters(writer, options.Parameters);
            writer.WriteStartObject("protection");
            writer.WriteString("alg", DaxqFormat.CipherAlgorithm);
            writer.WriteString("contentKeyId", options.ContentKeyId);
            writer.WriteString("nonce", nonce);
            writer.WriteString("cipherSha256", cipherSha256);
            writer.WriteEndObject();
            writer.WriteStartObject("watermark");
            writer.WriteString("scheme", "per-buyer-v1");
            writer.WriteString("slot", "wm");
            writer.WriteEndObject();
            writer.WriteNumber("vmMin", DaxqFormat.VmAbiVersion);
            writer.WriteStartObject("files");
            writer.WriteString(DaxqFormat.ManifestEntryName, "self");
            writer.WriteString(DaxqFormat.CiphertextEntryName, cipherSha256);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    public static byte[] WritePackageIndex(string manifestSha256, string cipherSha256)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("formatVersion", DaxqFormat.FormatVersion);
            writer.WriteStartObject("files");
            writer.WriteString(DaxqFormat.ManifestEntryName, manifestSha256);
            writer.WriteString(DaxqFormat.CiphertextEntryName, cipherSha256);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return stream.ToArray();
    }

    public static byte[] WriteSignature(string releaseKeyId, string signature)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", DaxqFormat.SignatureAlgorithm);
            writer.WriteString("keyId", releaseKeyId);
            writer.WriteString("sig", signature);
            writer.WriteEndObject();
        }
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
            if (parameter.Min is { } minimum)
                WriteParameterValue(writer, "min", parameter.Type, minimum);
            if (parameter.Max is { } maximum)
                WriteParameterValue(writer, "max", parameter.Type, maximum);
            WriteParameterValue(writer, "default", parameter.Type, parameter.Default);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    private static void WriteParameterValue(
        Utf8JsonWriter writer,
        string propertyName,
        string type,
        JsonElement value)
    {
        writer.WritePropertyName(propertyName);
        switch (type)
        {
            case "int":
                writer.WriteNumberValue(value.GetInt64());
                break;
            case "float":
                writer.WriteRawValue(CanonicalDouble(value.GetDouble()), skipInputValidation: false);
                break;
            case "bool":
                writer.WriteBooleanValue(value.GetBoolean());
                break;
            default:
                throw new InvalidOperationException($"Unsupported validated DAXQ parameter type '{type}'.");
        }
    }

    private static string CanonicalDouble(double value)
    {
        if (!double.IsFinite(value))
            throw new InvalidOperationException("A validated DAXQ floating parameter became non-finite.");
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
}
