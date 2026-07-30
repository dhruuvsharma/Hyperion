using System.Globalization;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.CodeAnalysis.Text;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class CandidateCompiler
{
    public static CompilationResult Compile(string source, VerifierToolchain toolchain)
    {
        var parseOptions = new CSharpParseOptions(
            LanguageVersion.CSharp13,
            DocumentationMode.None,
            SourceCodeKind.Regular);
        var syntaxTree = CSharpSyntaxTree.ParseText(
            SourceText.From(source, new UTF8Encoding(false, true), SourceHashAlgorithm.Sha256),
            parseOptions,
            path: "source.cs");
        var references = toolchain.ReferencePaths
            .Select(path => MetadataReference.CreateFromFile(path))
            .ToArray();
        var compilationOptions = new CSharpCompilationOptions(
            OutputKind.DynamicallyLinkedLibrary,
            optimizationLevel: OptimizationLevel.Release,
            checkOverflow: true,
            allowUnsafe: false,
            platform: Microsoft.CodeAnalysis.Platform.AnyCpu,
            generalDiagnosticOption: ReportDiagnostic.Default,
            warningLevel: 4,
            concurrentBuild: false,
            deterministic: true,
            metadataImportOptions: MetadataImportOptions.Public,
            nullableContextOptions: NullableContextOptions.Enable);
        var compilation = CSharpCompilation.Create(
            "DaxAlgo.HeadlessCandidate",
            [syntaxTree],
            references,
            compilationOptions);

        var sourcePolicyDiagnostics = CandidateSourcePolicy.Inspect(
            syntaxTree,
            compilation,
            out var strategyTypeName);
        using var peStream = new MemoryStream();
        var emitResult = compilation.Emit(
            peStream,
            options: new EmitOptions(
                debugInformationFormat: DebugInformationFormat.Embedded,
                includePrivateMembers: false));
        var compileDiagnostics = emitResult.Diagnostics
            .Where(item => item.Severity != DiagnosticSeverity.Hidden)
            .Select(ToVerifierDiagnostic)
            .ToList();
        var compileEvidence = BuildCompileEvidence(
            emitResult.Success,
            emitResult.Success ? peStream.ToArray() : null,
            compileDiagnostics);

        var ilPolicyDiagnostics = new List<VerifierDiagnostic>();
        byte[]? assemblyBytes = null;
        if (emitResult.Success)
        {
            assemblyBytes = peStream.ToArray();
            ilPolicyDiagnostics.AddRange(CandidateIlPolicy.Inspect(
                assemblyBytes,
                toolchain.Identity.CompilerClosure.Select(item => item.Name).ToArray()));
        }

        var allPolicyDiagnostics = sourcePolicyDiagnostics
            .Concat(ilPolicyDiagnostics)
            .ToList();
        var sortedPolicy = SortAndBound(allPolicyDiagnostics, out var policyTruncated);
        var policyEvidence = new VerifierPolicyEvidence(
            Attempted: true,
            SourcePassed: sourcePolicyDiagnostics.Count == 0,
            IlPassed: emitResult.Success && ilPolicyDiagnostics.Count == 0,
            Diagnostics: sortedPolicy,
            DiagnosticsTruncated: policyTruncated);
        return new(
            assemblyBytes,
            compileEvidence,
            policyEvidence,
            strategyTypeName);
    }

    private static VerifierCompileEvidence BuildCompileEvidence(
        bool succeeded,
        byte[]? assemblyBytes,
        List<VerifierDiagnostic> diagnostics)
    {
        var sorted = SortAndBound(diagnostics, out var truncated);
        return new(
            Attempted: true,
            Succeeded: succeeded,
            AssemblySha256: assemblyBytes is null ? null : VerifierToolchain.Hash(assemblyBytes),
            Diagnostics: sorted,
            DiagnosticsTruncated: truncated);
    }

    private static VerifierDiagnostic ToVerifierDiagnostic(Diagnostic diagnostic)
    {
        int? line = null;
        int? column = null;
        if (diagnostic.Location is { IsInSource: true })
        {
            var position = diagnostic.Location.GetLineSpan().StartLinePosition;
            line = position.Line + 1;
            column = position.Character + 1;
        }

        return new(
            "compile",
            diagnostic.Id,
            diagnostic.Severity.ToString().ToLowerInvariant(),
            diagnostic.GetMessage(CultureInfo.InvariantCulture),
            line,
            column);
    }

    internal static VerifierDiagnostic[] SortAndBound(
        IEnumerable<VerifierDiagnostic> diagnostics,
        out bool truncated)
    {
        var sorted = diagnostics
            .Select(item => item with { Message = BoundDiagnosticText(item.Message) })
            .Distinct()
            .OrderBy(item => item.Stage, StringComparer.Ordinal)
            .ThenBy(item => item.Code, StringComparer.Ordinal)
            .ThenBy(item => item.Severity, StringComparer.Ordinal)
            .ThenBy(item => item.Line)
            .ThenBy(item => item.Column)
            .ThenBy(item => item.Message, StringComparer.Ordinal)
            .ToArray();
        truncated = sorted.Length > HeadlessStrategyVerifier.MaximumDiagnostics;
        return sorted.Take(HeadlessStrategyVerifier.MaximumDiagnostics).ToArray();
    }

    private static string BoundDiagnosticText(string value)
    {
        var bounded = new string(value
            .Where(character => !char.IsControl(character) && !char.IsSurrogate(character))
            .Take(512)
            .ToArray());
        return bounded.Length == 0 ? "Verifier diagnostic." : bounded;
    }
}
