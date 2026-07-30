using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using TradingTerminal.Infrastructure.Plugins;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>Deterministic Roslyn front-end followed by the blocking DAXQ IL subset gate.</summary>
public sealed class DaxqRoslynCompiler
{
    private static readonly CSharpParseOptions ParseOptions = new(LanguageVersion.Latest);

    public DaxqLoweringResult CompileAndLower(string source, string fileName = "Strategy.cs")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        var syntaxTree = CSharpSyntaxTree.ParseText(source, ParseOptions, path: fileName, encoding: Encoding.UTF8);
        var compilation = CSharpCompilation.Create(
            BuildAssemblyName(source),
            [syntaxTree],
            BuildReferences(),
            new CSharpCompilationOptions(
                OutputKind.DynamicallyLinkedLibrary,
                optimizationLevel: OptimizationLevel.Release,
                checkOverflow: true,
                allowUnsafe: false,
                nullableContextOptions: NullableContextOptions.Enable,
                deterministic: true));

        using var imageStream = new MemoryStream();
        var emit = compilation.Emit(imageStream);
        var diagnostics = emit.Diagnostics
            .Where(diagnostic => diagnostic.Severity is DiagnosticSeverity.Error or DiagnosticSeverity.Warning)
            .Select(MapDiagnostic)
            .ToArray();
        if (!emit.Success || diagnostics.Length != 0)
            throw new DaxqCompilationException(diagnostics);

        var image = imageStream.ToArray();
        var scan = PluginPolicyScanner.ScanImage(image, fileName);
        var scanDiagnostics = scan.Findings
            .Where(finding => finding.Severity != PluginScanSeverity.Clean)
            .Select(finding => new DaxqCompilerDiagnostic(
                "DAXQ1100",
                $"IL policy rejected '{finding.Rule}': {finding.Detail}",
                fileName))
            .ToArray();
        if (scanDiagnostics.Length != 0)
            throw new DaxqCompilationException([.. diagnostics, .. scanDiagnostics]);

        var program = DaxqIlLowerer.Lower(image, fileName);
        return new DaxqLoweringResult(image, program, diagnostics);
    }

    private static IEnumerable<MetadataReference> BuildReferences()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tpa = AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") as string ?? string.Empty;
        foreach (var path in tpa.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                seen.Add(Path.GetFileNameWithoutExtension(path)))
            {
                yield return MetadataReference.CreateFromFile(path);
            }
        }

        var contractAssembly = typeof(DaxAlgo.Sdk.IBacktestStrategy).Assembly.Location;
        if (seen.Add(Path.GetFileNameWithoutExtension(contractAssembly)))
            yield return MetadataReference.CreateFromFile(contractAssembly);
    }

    private static string BuildAssemblyName(string source)
    {
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(source)));
        return $"DaxAlgo.Daxq.Submission.{digest[..24]}";
    }

    private static DaxqCompilerDiagnostic MapDiagnostic(Diagnostic diagnostic)
    {
        var span = diagnostic.Location.GetLineSpan();
        return new DaxqCompilerDiagnostic(
            diagnostic.Id,
            diagnostic.GetMessage(),
            span.Path,
            diagnostic.Location == Location.None ? null : span.StartLinePosition.Line + 1,
            diagnostic.Location == Location.None ? null : span.StartLinePosition.Character + 1);
    }
}

/// <summary>A blocking source or IL-subset compilation failure.</summary>
public sealed class DaxqCompilationException : Exception
{
    public DaxqCompilationException(IReadOnlyList<DaxqCompilerDiagnostic> diagnostics)
        : base(diagnostics.Count == 0
            ? "DAXQ compilation failed."
            : string.Join(Environment.NewLine, diagnostics.Select(d => $"{d.Code}: {d.Message}")))
    {
        Diagnostics = diagnostics;
    }

    public IReadOnlyList<DaxqCompilerDiagnostic> Diagnostics { get; }
}
