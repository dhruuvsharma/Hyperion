using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DaxAlgo.Platform.VerifierWorker;

public static class HeadlessStrategyVerifier
{
    public const string ResultSchema = "daxalgo.verifier.headless-strategy-worker-result/v1";
    public const string ResultFileName = "result.json";
    public const int MaximumRequestBytes = 1024 * 1024;
    public const int MaximumSourceBytes = 256 * 1024;
    public const int MaximumResultBytes = 8 * 1024 * 1024;
    public const int MaximumDiagnostics = 128;

    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static async Task<HeadlessVerifierResult> VerifyAsync(
        byte[] requestBytes,
        byte[] sourceBytes)
    {
        ArgumentNullException.ThrowIfNull(requestBytes);
        ArgumentNullException.ThrowIfNull(sourceBytes);
        if (requestBytes.Length > MaximumRequestBytes
            || sourceBytes.Length > MaximumSourceBytes)
        {
            throw new ArgumentException("Verifier input exceeds the worker byte bound.");
        }

        var requestSha256 = VerifierToolchain.Hash(requestBytes);
        var sourceSha256 = VerifierToolchain.Hash(sourceBytes);
        var toolchain = VerifierToolchain.Create();
        var parsed = StrictRequestParser.Parse(requestBytes);
        var requestDiagnostics = parsed.Diagnostics.ToList();
        var sourceEncodingValid = TryDecodeSource(sourceBytes, out var source, out var sourceError);
        if (sourceError is not null)
        {
            requestDiagnostics.Add(sourceError);
        }

        var declaredSourceSha256 = parsed.Request?.SourceSha256;
        var sourceHashMatched = declaredSourceSha256 is not null
            && FixedTimeHexEquals(declaredSourceSha256, sourceSha256);
        if (declaredSourceSha256 is not null && !sourceHashMatched)
        {
            requestDiagnostics.Add(new(
                "request",
                "DAXV1103",
                "error",
                "sourceSha256 does not match the exact source bytes."));
        }

        var boundedRequestDiagnostics = CandidateCompiler.SortAndBound(
            requestDiagnostics,
            out var requestDiagnosticsTruncated);
        var requestValid = parsed.Request is not null
            && sourceEncodingValid
            && sourceHashMatched
            && boundedRequestDiagnostics.Length == 0;
        var requestEvidence = new VerifierRequestEvidence(
            parsed.Request?.RequestId,
            requestSha256,
            requestValid,
            boundedRequestDiagnostics,
            requestDiagnosticsTruncated);
        var sourceEvidence = new VerifierSourceEvidence(
            sourceSha256,
            declaredSourceSha256,
            sourceEncodingValid,
            sourceHashMatched);

        if (!requestValid || parsed.Request is null || source is null)
        {
            return new(
                ResultSchema,
                requestEvidence,
                sourceEvidence,
                toolchain.Identity,
                EmptyCompileEvidence(),
                EmptyPolicyEvidence(),
                [],
                Completed: true,
                Accepted: false);
        }

        var compilation = CandidateCompiler.Compile(source, toolchain);
        var canExecute = compilation.AssemblyBytes is not null
            && compilation.Evidence.Succeeded
            && compilation.PolicyEvidence.SourcePassed
            && compilation.PolicyEvidence.IlPassed
            && compilation.StrategyTypeName is not null;
        var caseResults = new List<VerifierCaseResult>(parsed.Request.Cases.Length);
        if (canExecute)
        {
            foreach (var verificationCase in parsed.Request.Cases)
            {
                var first = await CandidateExecutor.ExecuteAsync(
                    compilation.AssemblyBytes!,
                    compilation.StrategyTypeName!,
                    parsed.Request.Contract,
                    verificationCase);
                var second = await CandidateExecutor.ExecuteAsync(
                    compilation.AssemblyBytes!,
                    compilation.StrategyTypeName!,
                    parsed.Request.Contract,
                    verificationCase);
                var deterministic = string.Equals(
                    first.Hash,
                    second.Hash,
                    StringComparison.Ordinal);
                var caseResult = new VerifierCaseResult(
                    verificationCase.CaseId,
                    Succeeded: deterministic && first.Error is null && second.Error is null,
                    Trace: first.Trace,
                    SecondTrace: second.Trace,
                    FirstTraceSha256: first.Hash,
                    SecondTraceSha256: second.Hash,
                    Deterministic: deterministic,
                    FirstError: first.Error,
                    SecondError: second.Error);
                caseResults.Add(caseResult);
                if (!caseResult.Succeeded)
                {
                    break;
                }
            }
        }

        var accepted = canExecute
            && caseResults.Count == parsed.Request.Cases.Length
            && caseResults.All(item => item.Succeeded);
        return new(
            ResultSchema,
            requestEvidence,
            sourceEvidence,
            toolchain.Identity,
            compilation.Evidence,
            compilation.PolicyEvidence,
            caseResults.ToArray(),
            Completed: true,
            Accepted: accepted);
    }

    public static byte[] SerializeResult(HeadlessVerifierResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.SerializeToUtf8Bytes(
            result,
            VerifierJsonContext.Default.HeadlessVerifierResult);
    }

    public static byte[] ReadBoundedFile(string path, int maximumBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);

        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists
            || file.Length < 0
            || file.Length > maximumBytes
            || file.LinkTarget is not null
            || (file.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("A verifier input is unavailable or outside its byte bound.");
        }

        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            options: FileOptions.SequentialScan);
        if (stream.Length > maximumBytes || stream.Length > int.MaxValue)
        {
            throw new InvalidDataException("A verifier input is outside its byte bound.");
        }

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
        {
            throw new InvalidDataException("A verifier input changed while it was being read.");
        }

        return bytes;
    }

    private static bool TryDecodeSource(
        byte[] sourceBytes,
        out string? source,
        out VerifierDiagnostic? error)
    {
        source = null;
        error = null;
        if (sourceBytes.Length == 0)
        {
            error = new(
                "source",
                "DAXV1100",
                "error",
                "The source file is empty.");
            return false;
        }

        if (sourceBytes is [0xEF, 0xBB, 0xBF, ..])
        {
            error = new(
                "source",
                "DAXV1101",
                "error",
                "UTF-8 byte-order marks are not permitted in source.");
            return false;
        }

        if (sourceBytes.AsSpan().Contains((byte)0))
        {
            error = new(
                "source",
                "DAXV1102",
                "error",
                "NUL bytes are not permitted in source.");
            return false;
        }

        try
        {
            source = StrictUtf8.GetString(sourceBytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            error = new(
                "source",
                "DAXV1104",
                "error",
                "The source file is not strict UTF-8.");
            return false;
        }
    }

    private static bool FixedTimeHexEquals(string expectedHex, string actualHex)
    {
        var expected = Convert.FromHexString(expectedHex);
        var actual = Convert.FromHexString(actualHex);
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static VerifierCompileEvidence EmptyCompileEvidence() =>
        new(
            Attempted: false,
            Succeeded: false,
            AssemblySha256: null,
            Diagnostics: [],
            DiagnosticsTruncated: false);

    private static VerifierPolicyEvidence EmptyPolicyEvidence() =>
        new(
            Attempted: false,
            SourcePassed: false,
            IlPassed: false,
            Diagnostics: [],
            DiagnosticsTruncated: false);
}
