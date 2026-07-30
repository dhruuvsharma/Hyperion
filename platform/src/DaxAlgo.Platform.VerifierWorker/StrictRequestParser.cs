using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class StrictRequestParser
{
    internal const string RequestSchema = "daxalgo.verifier.headless-strategy-request/v1";
    internal const string Profile = "daxalgo-sdk-headless-source/v1";
    private const int MaximumCases = 8;
    private const int MaximumTicksPerCase = 2048;
    private const int MaximumTotalTicks = 8192;
    private const long MaximumOffsetMilliseconds = 7L * 24 * 60 * 60 * 1000;
    private const long MaximumQuoteSize = 1_000_000_000_000;
    private const double MaximumPrice = 1_000_000_000_000d;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static RequestParseResult Parse(byte[] bytes)
    {
        var diagnostics = new List<VerifierDiagnostic>();
        if (bytes.Length == 0)
        {
            Add(diagnostics, "DAXV1000", "The request is empty.");
            return new(null, diagnostics.ToArray());
        }

        if (HasUtf8Bom(bytes))
        {
            Add(diagnostics, "DAXV1001", "UTF-8 byte-order marks are not permitted.");
        }

        if (bytes.AsSpan().Contains((byte)0))
        {
            Add(diagnostics, "DAXV1002", "NUL bytes are not permitted.");
        }

        string json;
        try
        {
            json = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            Add(diagnostics, "DAXV1003", "The request is not strict UTF-8.");
            return new(null, diagnostics.ToArray());
        }

        if (diagnostics.Count != 0)
        {
            return new(null, diagnostics.ToArray());
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 16,
                });
        }
        catch (JsonException exception)
        {
            Add(
                diagnostics,
                "DAXV1004",
                "The request is not valid JSON.",
                exception.LineNumber is null ? null : checked((int)exception.LineNumber.Value + 1),
                exception.BytePositionInLine is null
                    ? null
                    : checked((int)exception.BytePositionInLine.Value + 1));
            return new(null, diagnostics.ToArray());
        }

        using (document)
        {
            var root = document.RootElement;
            if (!ValidateObjectKeys(
                    root,
                    "request",
                    diagnostics,
                    "schemaVersion",
                    "profile",
                    "requestId",
                    "sourceSha256",
                    "contract",
                    "cases"))
            {
                return new(null, Sort(diagnostics));
            }

            var schema = ReadString(root, "schemaVersion", 1, 128, diagnostics);
            var profile = ReadString(root, "profile", 1, 128, diagnostics);
            var requestId = ReadIdentifier(root, "requestId", diagnostics);
            var sourceSha256 = ReadSha256(root, "sourceSha256", diagnostics);
            if (!string.Equals(schema, RequestSchema, StringComparison.Ordinal))
            {
                Add(diagnostics, "DAXV1010", "The request schemaVersion is unsupported.");
            }

            if (!string.Equals(profile, Profile, StringComparison.Ordinal))
            {
                Add(diagnostics, "DAXV1011", "The request profile is unsupported.");
            }

            var contract = ParseContract(root.GetProperty("contract"), diagnostics);
            var cases = ParseCases(root.GetProperty("cases"), diagnostics);
            if (diagnostics.Count != 0
                || requestId is null
                || sourceSha256 is null
                || contract is null
                || cases is null)
            {
                return new(null, Sort(diagnostics));
            }

            return new(
                new VerificationRequest(requestId, sourceSha256, contract, cases),
                []);
        }
    }

    private static VerifierContract? ParseContract(
        JsonElement element,
        List<VerifierDiagnostic> diagnostics)
    {
        if (!ValidateObjectKeys(
                element,
                "contract",
                diagnostics,
                "symbol",
                "secType",
                "exchange",
                "currency",
                "primaryExchange"))
        {
            return null;
        }

        var symbol = ReadString(element, "symbol", 1, 64, diagnostics);
        var secType = ReadString(element, "secType", 1, 32, diagnostics);
        var exchange = ReadString(element, "exchange", 1, 64, diagnostics);
        var currency = ReadString(element, "currency", 1, 16, diagnostics);
        var primaryExchange = ReadString(element, "primaryExchange", 1, 64, diagnostics);
        return symbol is null
            || secType is null
            || exchange is null
            || currency is null
            || primaryExchange is null
            ? null
            : new(symbol, secType, exchange, currency, primaryExchange);
    }

    private static VerificationCase[]? ParseCases(
        JsonElement element,
        List<VerifierDiagnostic> diagnostics)
    {
        if (element.ValueKind != JsonValueKind.Array)
        {
            Add(diagnostics, "DAXV1020", "cases must be an array.");
            return null;
        }

        var count = element.GetArrayLength();
        if (count is < 1 or > MaximumCases)
        {
            Add(diagnostics, "DAXV1021", $"cases must contain between 1 and {MaximumCases} items.");
            return null;
        }

        var cases = new List<VerificationCase>(count);
        var caseIds = new HashSet<string>(StringComparer.Ordinal);
        var totalTicks = 0;
        foreach (var item in element.EnumerateArray())
        {
            if (!ValidateObjectKeys(item, "case", diagnostics, "caseId", "startUtc", "ticks"))
            {
                continue;
            }

            var caseId = ReadIdentifier(item, "caseId", diagnostics);
            if (caseId is not null && !caseIds.Add(caseId))
            {
                Add(diagnostics, "DAXV1022", "caseId values must be unique.");
            }

            var startUtc = ReadStartUtc(item, diagnostics);
            var ticks = ParseTicks(item.GetProperty("ticks"), diagnostics);
            if (ticks is not null)
            {
                totalTicks += ticks.Length;
            }

            if (caseId is not null && startUtc is not null && ticks is not null)
            {
                cases.Add(new(caseId, startUtc.Value, ticks));
            }
        }

        if (totalTicks > MaximumTotalTicks)
        {
            Add(
                diagnostics,
                "DAXV1023",
                $"The request exceeds the {MaximumTotalTicks}-tick aggregate bound.");
        }

        return diagnostics.Count == 0 ? cases.ToArray() : null;
    }

    private static VerificationTick[]? ParseTicks(
        JsonElement element,
        List<VerifierDiagnostic> diagnostics)
    {
        if (element.ValueKind != JsonValueKind.Array)
        {
            Add(diagnostics, "DAXV1030", "ticks must be an array.");
            return null;
        }

        var count = element.GetArrayLength();
        if (count is < 1 or > MaximumTicksPerCase)
        {
            Add(
                diagnostics,
                "DAXV1031",
                $"ticks must contain between 1 and {MaximumTicksPerCase} items.");
            return null;
        }

        var ticks = new List<VerificationTick>(count);
        long previousOffset = -1;
        foreach (var item in element.EnumerateArray())
        {
            if (!ValidateObjectKeys(
                    item,
                    "tick",
                    diagnostics,
                    "offsetMilliseconds",
                    "bid",
                    "ask",
                    "bidSize",
                    "askSize"))
            {
                continue;
            }

            var offset = ReadInt64(item, "offsetMilliseconds", diagnostics);
            var bid = ReadDouble(item, "bid", diagnostics);
            var ask = ReadDouble(item, "ask", diagnostics);
            var bidSize = ReadInt64(item, "bidSize", diagnostics);
            var askSize = ReadInt64(item, "askSize", diagnostics);
            if (offset is null || bid is null || ask is null || bidSize is null || askSize is null)
            {
                continue;
            }

            if (offset < 0 || offset > MaximumOffsetMilliseconds || offset <= previousOffset)
            {
                Add(
                    diagnostics,
                    "DAXV1032",
                    "Tick offsets must be strictly increasing and within the seven-day bound.");
            }

            if (!double.IsFinite(bid.Value)
                || !double.IsFinite(ask.Value)
                || bid <= 0
                || ask < bid
                || ask > MaximumPrice)
            {
                Add(diagnostics, "DAXV1033", "Tick prices are outside the supported finite bounds.");
            }

            if (bidSize < 0
                || askSize < 0
                || bidSize > MaximumQuoteSize
                || askSize > MaximumQuoteSize)
            {
                Add(diagnostics, "DAXV1034", "Tick sizes are outside the supported bounds.");
            }

            previousOffset = offset.Value;
            ticks.Add(new(offset.Value, bid.Value, ask.Value, bidSize.Value, askSize.Value));
        }

        return diagnostics.Count == 0 ? ticks.ToArray() : null;
    }

    private static DateTime? ReadStartUtc(
        JsonElement element,
        List<VerifierDiagnostic> diagnostics)
    {
        var value = ReadString(element, "startUtc", 20, 40, diagnostics);
        if (value is null
            || !value.EndsWith('Z')
            || !DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed)
            || parsed.Year is < 2000 or > 2100)
        {
            Add(diagnostics, "DAXV1040", "startUtc must be a bounded UTC timestamp ending in Z.");
            return null;
        }

        return parsed.UtcDateTime;
    }

    private static string? ReadIdentifier(
        JsonElement element,
        string propertyName,
        List<VerifierDiagnostic> diagnostics)
    {
        var value = ReadString(element, propertyName, 1, 128, diagnostics);
        if (value is null)
        {
            return null;
        }

        if (value.Any(character => character is not (
                >= 'A' and <= 'Z' or
                >= 'a' and <= 'z' or
                >= '0' and <= '9' or
                '.' or '_' or ':' or '-')))
        {
            Add(diagnostics, "DAXV1041", $"{propertyName} contains an unsupported character.");
            return null;
        }

        return value;
    }

    private static string? ReadSha256(
        JsonElement element,
        string propertyName,
        List<VerifierDiagnostic> diagnostics)
    {
        var value = ReadString(element, propertyName, 64, 64, diagnostics);
        if (value is null
            || value.Any(character => character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            Add(diagnostics, "DAXV1042", $"{propertyName} must be a lowercase SHA-256 value.");
            return null;
        }

        return value;
    }

    private static string? ReadString(
        JsonElement element,
        string propertyName,
        int minimumLength,
        int maximumLength,
        List<VerifierDiagnostic> diagnostics)
    {
        var property = element.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.String)
        {
            Add(diagnostics, "DAXV1043", $"{propertyName} must be a string.");
            return null;
        }

        var value = property.GetString();
        if (value is null
            || string.IsNullOrWhiteSpace(value)
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || value.Length < minimumLength
            || value.Length > maximumLength
            || value.Any(character => char.IsControl(character) || char.IsSurrogate(character)))
        {
            Add(diagnostics, "DAXV1044", $"{propertyName} is outside its text bound.");
            return null;
        }

        return value;
    }

    private static long? ReadInt64(
        JsonElement element,
        string propertyName,
        List<VerifierDiagnostic> diagnostics)
    {
        var property = element.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt64(out var value))
        {
            Add(diagnostics, "DAXV1045", $"{propertyName} must be an exact 64-bit integer.");
            return null;
        }

        return value;
    }

    private static double? ReadDouble(
        JsonElement element,
        string propertyName,
        List<VerifierDiagnostic> diagnostics)
    {
        var property = element.GetProperty(propertyName);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetDouble(out var value))
        {
            Add(diagnostics, "DAXV1046", $"{propertyName} must be a finite JSON number.");
            return null;
        }

        return value;
    }

    private static bool ValidateObjectKeys(
        JsonElement element,
        string label,
        List<VerifierDiagnostic> diagnostics,
        params string[] expectedKeys)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            Add(diagnostics, "DAXV1050", $"{label} must be an object.");
            return false;
        }

        var expected = new HashSet<string>(expectedKeys, StringComparer.Ordinal);
        var observed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!observed.Add(property.Name))
            {
                Add(diagnostics, "DAXV1051", $"{label} contains a duplicate key.");
            }
            else if (!expected.Contains(property.Name))
            {
                Add(diagnostics, "DAXV1052", $"{label} contains an unknown key.");
            }
        }

        if (!expected.SetEquals(observed))
        {
            Add(diagnostics, "DAXV1053", $"{label} does not contain the exact required keys.");
        }

        return diagnostics.Count == 0;
    }

    private static bool HasUtf8Bom(byte[] bytes) =>
        bytes is [0xEF, 0xBB, 0xBF, ..];

    private static void Add(
        List<VerifierDiagnostic> diagnostics,
        string code,
        string message,
        int? line = null,
        int? column = null) =>
        diagnostics.Add(new("request", code, "error", message, line, column));

    private static VerifierDiagnostic[] Sort(List<VerifierDiagnostic> diagnostics) =>
        diagnostics
            .OrderBy(item => item.Stage, StringComparer.Ordinal)
            .ThenBy(item => item.Code, StringComparer.Ordinal)
            .ThenBy(item => item.Line)
            .ThenBy(item => item.Column)
            .ThenBy(item => item.Message, StringComparer.Ordinal)
            .Take(HeadlessStrategyVerifier.MaximumDiagnostics)
            .ToArray();
}
