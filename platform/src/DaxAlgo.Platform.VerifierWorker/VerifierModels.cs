using System.Text.Json.Serialization;

namespace DaxAlgo.Platform.VerifierWorker;

public sealed record HeadlessVerifierResult(
    string SchemaVersion,
    VerifierRequestEvidence Request,
    VerifierSourceEvidence Source,
    VerifierWorkerIdentity Toolchain,
    VerifierCompileEvidence Compile,
    VerifierPolicyEvidence Policy,
    VerifierCaseResult[] Cases,
    bool Completed,
    bool Accepted);

public sealed record VerifierRequestEvidence(
    string? RequestId,
    string Sha256,
    bool Valid,
    VerifierDiagnostic[] Diagnostics,
    bool DiagnosticsTruncated);

public sealed record VerifierSourceEvidence(
    string Sha256,
    string? DeclaredSha256,
    bool EncodingValid,
    bool HashMatched);

public sealed record VerifierWorkerIdentity(
    string Version,
    VerifierArtifactIdentity Worker,
    VerifierArtifactIdentity Runtime,
    VerifierArtifactIdentity Core,
    VerifierArtifactIdentity Sdk,
    VerifierArtifactIdentity Roslyn,
    VerifierArtifactIdentity[] CompilerClosure,
    string CompilerClosureSha256);

public sealed record VerifierArtifactIdentity(
    string Name,
    string Version,
    string Sha256);

public sealed record VerifierCompileEvidence(
    bool Attempted,
    bool Succeeded,
    string? AssemblySha256,
    VerifierDiagnostic[] Diagnostics,
    bool DiagnosticsTruncated);

public sealed record VerifierPolicyEvidence(
    bool Attempted,
    bool SourcePassed,
    bool IlPassed,
    VerifierDiagnostic[] Diagnostics,
    bool DiagnosticsTruncated);

public sealed record VerifierDiagnostic(
    string Stage,
    string Code,
    string Severity,
    string Message,
    int? Line = null,
    int? Column = null);

public sealed record VerifierCaseResult(
    string CaseId,
    bool Succeeded,
    VerifierTraceEntry[] Trace,
    VerifierTraceEntry[] SecondTrace,
    string FirstTraceSha256,
    string SecondTraceSha256,
    bool Deterministic,
    VerifierRuntimeError? FirstError,
    VerifierRuntimeError? SecondError);

public sealed record VerifierTraceEntry(
    long Sequence,
    string Kind,
    string AtUtc,
    string ClientOrderId,
    VerifierContract? Contract,
    string? Side,
    string? Type,
    long? Quantity,
    double? LimitPrice,
    double? StopPrice,
    string? TimeInForce);

public sealed record VerifierContract(
    string Symbol,
    string SecType,
    string Exchange,
    string Currency,
    string PrimaryExchange);

public sealed record VerifierRuntimeError(
    string Code,
    string Type,
    string Message);

internal sealed record VerificationRequest(
    string RequestId,
    string SourceSha256,
    VerifierContract Contract,
    VerificationCase[] Cases);

internal sealed record VerificationCase(
    string CaseId,
    DateTime StartUtc,
    VerificationTick[] Ticks);

internal sealed record VerificationTick(
    long OffsetMilliseconds,
    double Bid,
    double Ask,
    long BidSize,
    long AskSize);

internal sealed record RequestParseResult(
    VerificationRequest? Request,
    VerifierDiagnostic[] Diagnostics);

internal sealed record CompilationResult(
    byte[]? AssemblyBytes,
    VerifierCompileEvidence Evidence,
    VerifierPolicyEvidence PolicyEvidence,
    string? StrategyTypeName);

internal sealed record CandidateExecution(
    VerifierTraceEntry[] Trace,
    VerifierRuntimeError? Error,
    string Hash);

internal sealed record CandidateReplayRequest(
    string SchemaVersion,
    string AssemblySha256,
    string StrategyTypeName,
    VerifierContract Contract,
    VerificationCase Case);

internal sealed record CandidateReplayResponse(
    string SchemaVersion,
    string RequestSha256,
    string AssemblySha256,
    CandidateExecution Execution);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    GenerationMode = JsonSourceGenerationMode.Serialization,
    WriteIndented = false)]
[JsonSerializable(typeof(HeadlessVerifierResult))]
internal sealed partial class VerifierJsonContext : JsonSerializerContext;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    GenerationMode = JsonSourceGenerationMode.Default,
    WriteIndented = false)]
[JsonSerializable(typeof(CandidateReplayRequest))]
[JsonSerializable(typeof(CandidateReplayResponse))]
internal sealed partial class CandidateReplayJsonContext : JsonSerializerContext;
