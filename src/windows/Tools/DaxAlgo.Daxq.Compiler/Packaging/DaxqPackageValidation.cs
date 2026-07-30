using System.Security.Cryptography;
using System.Text.Json;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Compiler;

internal sealed record NormalizedDaxqPackageOptions(
    byte[] PlaintextBytes,
    string StrategyId,
    string Version,
    int FormatVersion,
    DaxqKind Kind,
    DaxqPresentationManifest? Presentation,
    string[] DataRequirements,
    DaxqParameterManifest[] Parameters,
    string ContentKeyId,
    byte[] ContentKey,
    byte[] Nonce,
    string ReleaseKeyId,
    ECDsa ReleaseSigningKey);

internal static class DaxqPackageValidation
{
    private const long MaximumExactInteger = 9_007_199_254_740_991L;
    private const string P256Oid = "1.2.840.10045.3.1.7";

    public static NormalizedDaxqPackageOptions Normalize(DaxqPackageWriteOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.PlaintextBytes);
        ArgumentNullException.ThrowIfNull(options.StrategyId);
        ArgumentNullException.ThrowIfNull(options.Version);
        ArgumentNullException.ThrowIfNull(options.DataRequirements);
        ArgumentNullException.ThrowIfNull(options.Parameters);
        ArgumentNullException.ThrowIfNull(options.ContentKeyId);
        ArgumentNullException.ThrowIfNull(options.ContentKey);
        ArgumentNullException.ThrowIfNull(options.Nonce);
        ArgumentNullException.ThrowIfNull(options.ReleaseKeyId);
        ArgumentNullException.ThrowIfNull(options.ReleaseSigningKey);

        ValidateStrategyId(options.StrategyId);
        ValidateSemVer(options.Version);
        ValidateManifestProfile(options);
        ValidateKeyId(options.ContentKeyId, nameof(options.ContentKeyId));
        ValidateKeyId(options.ReleaseKeyId, nameof(options.ReleaseKeyId));

        if (options.ContentKey.Length != 32)
            throw new ArgumentException("A DAXQ content key must be exactly 32 bytes.", nameof(options));
        if (options.Nonce.Length != DaxqFormat.NonceSizeBytes)
        {
            throw new ArgumentException(
                $"A DAXQ nonce must be exactly {DaxqFormat.NonceSizeBytes} bytes.",
                nameof(options));
        }

        ValidateP256Key(options.ReleaseSigningKey);
        var requirements = NormalizeDataRequirements(options.DataRequirements);
        var parameters = NormalizeParameters(options.Parameters);
        return new NormalizedDaxqPackageOptions(
            (byte[])options.PlaintextBytes.Clone(),
            options.StrategyId,
            options.Version,
            options.FormatVersion,
            options.Kind,
            options.Presentation,
            requirements,
            parameters,
            options.ContentKeyId,
            (byte[])options.ContentKey.Clone(),
            (byte[])options.Nonce.Clone(),
            options.ReleaseKeyId,
            options.ReleaseSigningKey);
    }

    private static void ValidateManifestProfile(DaxqPackageWriteOptions options)
    {
        if (options.FormatVersion is not (DaxqFormat.FormatVersion or DaxqFormat.PresentationFormatVersion))
            throw new ArgumentException($"Unsupported DAXQ formatVersion {options.FormatVersion}.", nameof(options));

        if (options.FormatVersion == DaxqFormat.FormatVersion &&
            (options.Kind != DaxqKind.Strategy || options.Presentation is not null))
        {
            throw new ArgumentException(
                "DAXQ v1 must remain a strategy and cannot contain a presentation block.",
                nameof(options));
        }
    }

    private static string[] NormalizeDataRequirements(IReadOnlyList<string> requirements)
    {
        if (requirements.Count is < 1 or > 2)
            throw new ArgumentException("DAXQ dataRequirements must contain one or both v1 capabilities.");

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var requirement in requirements)
        {
            if (requirement is not ("bars" or "ticks"))
                throw new ArgumentException("DAXQ v1 dataRequirements accepts only 'bars' and 'ticks'.");
            if (!seen.Add(requirement))
                throw new ArgumentException($"Duplicate DAXQ data requirement '{requirement}'.");
        }
        return seen.OrderBy(value => value, StringComparer.Ordinal).ToArray();
    }

    private static DaxqParameterManifest[] NormalizeParameters(
        IReadOnlyList<DaxqParameterManifest> parameters)
    {
        if (parameters.Count > 256)
            throw new ArgumentException("DAXQ v1 permits at most 256 parameters.");

        var copy = new DaxqParameterManifest[parameters.Count];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < parameters.Count; index++)
        {
            var parameter = parameters[index]
                ?? throw new ArgumentException("DAXQ parameters cannot contain null entries.");
            ValidateParameterId(parameter.Id);
            if (!seen.Add(parameter.Id))
                throw new ArgumentException($"Duplicate DAXQ parameter ID '{parameter.Id}'.");
            ValidateParameter(parameter);
            copy[index] = parameter;
        }
        Array.Sort(copy, static (left, right) => StringComparer.Ordinal.Compare(left.Id, right.Id));
        return copy;
    }

    private static void ValidateParameter(DaxqParameterManifest parameter)
    {
        switch (parameter.Type)
        {
            case "int":
                {
                    var minimum = ReadOptionalInteger(parameter.Min, parameter.Id, "min");
                    var maximum = ReadOptionalInteger(parameter.Max, parameter.Id, "max");
                    var defaultValue = ReadInteger(parameter.Default, parameter.Id, "default");
                    ValidateBounds(parameter.Id, minimum, maximum, defaultValue);
                    break;
                }
            case "float":
                {
                    var minimum = ReadOptionalFloat(parameter.Min, parameter.Id, "min");
                    var maximum = ReadOptionalFloat(parameter.Max, parameter.Id, "max");
                    var defaultValue = ReadFloat(parameter.Default, parameter.Id, "default");
                    ValidateBounds(parameter.Id, minimum, maximum, defaultValue);
                    break;
                }
            case "bool":
                if (parameter.Min is not null || parameter.Max is not null)
                    throw new ArgumentException($"Boolean parameter '{parameter.Id}' cannot declare bounds.");
                if (parameter.Default.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    throw new ArgumentException($"Boolean parameter '{parameter.Id}' requires a Boolean default.");
                break;
            default:
                throw new ArgumentException(
                    $"Parameter '{parameter.Id}' has unsupported DAXQ type '{parameter.Type}'.");
        }
    }

    private static long? ReadOptionalInteger(JsonElement? value, string id, string member) =>
        value is { } element ? ReadInteger(element, id, member) : null;

    private static long ReadInteger(JsonElement value, string id, string member)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var number) ||
            number < -MaximumExactInteger || number > MaximumExactInteger)
        {
            throw new ArgumentException(
                $"Integer parameter '{id}' {member} must be an exact integer in the v1 safe range.");
        }
        return number;
    }

    private static double? ReadOptionalFloat(JsonElement? value, string id, string member) =>
        value is { } element ? ReadFloat(element, id, member) : null;

    private static double ReadFloat(JsonElement value, string id, string member)
    {
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out var number) ||
            !double.IsFinite(number))
        {
            throw new ArgumentException($"Float parameter '{id}' {member} must be finite.");
        }
        return number == 0d ? 0d : number;
    }

    private static void ValidateBounds<T>(string id, T? minimum, T? maximum, T defaultValue)
        where T : struct, IComparable<T>
    {
        if (minimum is { } min && maximum is { } max && min.CompareTo(max) > 0)
            throw new ArgumentException($"Parameter '{id}' has min greater than max.");
        if (minimum is { } lower && defaultValue.CompareTo(lower) < 0)
            throw new ArgumentException($"Parameter '{id}' default is below min.");
        if (maximum is { } upper && defaultValue.CompareTo(upper) > 0)
            throw new ArgumentException($"Parameter '{id}' default is above max.");
    }

    private static void ValidateStrategyId(string value)
    {
        if (value.Length is < 1 or > 128 || !IsLowerAlphaNumeric(value[0]) ||
            !IsLowerAlphaNumeric(value[^1]))
        {
            throw new ArgumentException("strategyId does not match the frozen DAXQ v1 profile.");
        }
        foreach (var character in value)
        {
            if (!IsLowerAlphaNumeric(character) && character is not ('.' or '-'))
                throw new ArgumentException("strategyId does not match the frozen DAXQ v1 profile.");
        }
    }

    private static void ValidateParameterId(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 64 || value[0] is < 'a' or > 'z')
            throw new ArgumentException("A parameter ID does not match the frozen DAXQ v1 profile.");
        foreach (var character in value)
        {
            if (character is not (>= 'a' and <= 'z') && character is not (>= '0' and <= '9') &&
                character != '_')
            {
                throw new ArgumentException("A parameter ID does not match the frozen DAXQ v1 profile.");
            }
        }
    }

    private static void ValidateKeyId(string value, string parameterName)
    {
        if (value.Length is < 1 or > 128 || !IsAsciiAlphaNumeric(value[0]))
            throw new ArgumentException("DAXQ key ID does not match the frozen v1 profile.", parameterName);
        foreach (var character in value)
        {
            if (!IsAsciiAlphaNumeric(character) && character is not ('.' or '_' or ':' or '-'))
                throw new ArgumentException("DAXQ key ID does not match the frozen v1 profile.", parameterName);
        }
    }

    private static void ValidateSemVer(string value)
    {
        if (value.Length is < 1 or > 64 || value.Any(character =>
                !IsAsciiAlphaNumeric(character) && character is not ('.' or '+' or '-')))
        {
            throw new ArgumentException("version must be canonical SemVer 2.0.0.");
        }

        var plus = value.IndexOf('+');
        if (plus >= 0 && value.IndexOf('+', plus + 1) >= 0)
            throw new ArgumentException("version must be canonical SemVer 2.0.0.");
        var coreAndPre = plus < 0 ? value : value[..plus];
        var build = plus < 0 ? null : value[(plus + 1)..];
        if (build is not null && !ValidIdentifiers(build, forbidNumericLeadingZero: false))
            throw new ArgumentException("version must be canonical SemVer 2.0.0.");

        var dash = coreAndPre.IndexOf('-');
        var core = dash < 0 ? coreAndPre : coreAndPre[..dash];
        var prerelease = dash < 0 ? null : coreAndPre[(dash + 1)..];
        var parts = core.Split('.', StringSplitOptions.None);
        if (parts.Length != 3 || parts.Any(part => !CanonicalNumericIdentifier(part)) ||
            (prerelease is not null && !ValidIdentifiers(prerelease, forbidNumericLeadingZero: true)))
        {
            throw new ArgumentException("version must be canonical SemVer 2.0.0.");
        }
    }

    private static bool ValidIdentifiers(string value, bool forbidNumericLeadingZero)
    {
        var identifiers = value.Split('.', StringSplitOptions.None);
        if (identifiers.Length == 0)
            return false;
        foreach (var identifier in identifiers)
        {
            if (identifier.Length == 0 || identifier.Any(character =>
                    !IsAsciiAlphaNumeric(character) && character != '-'))
            {
                return false;
            }
            if (forbidNumericLeadingZero && identifier.All(character => character is >= '0' and <= '9') &&
                identifier.Length > 1 && identifier[0] == '0')
            {
                return false;
            }
        }
        return true;
    }

    private static bool CanonicalNumericIdentifier(string value) =>
        value.Length > 0 && value.All(character => character is >= '0' and <= '9') &&
        (value.Length == 1 || value[0] != '0');

    private static void ValidateP256Key(ECDsa key)
    {
        if (key.KeySize != 256)
            throw new ArgumentException("The DAXQ release signing key must be ECDSA P-256.");
        try
        {
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (!string.Equals(parameters.Curve.Oid.Value, P256Oid, StringComparison.Ordinal) ||
                parameters.Q.X is not { Length: 32 } || parameters.Q.Y is not { Length: 32 })
            {
                throw new ArgumentException("The DAXQ release signing key must use the NIST P-256 curve.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException("The DAXQ release signing key is not a usable P-256 key.", exception);
        }
    }

    private static bool IsLowerAlphaNumeric(char value) =>
        value is >= 'a' and <= 'z' or >= '0' and <= '9';

    private static bool IsAsciiAlphaNumeric(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9';
}
