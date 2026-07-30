namespace DaxAlgo.Daxq.Compiler;

using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;
using System.Security.Cryptography;
using System.Text.Json;

/// <summary>Complete server-side Roslyn-to-signed-DAXQ compiler pipeline.</summary>
public sealed class DaxqCompiler
{
    private readonly DaxqRoslynCompiler _frontEnd = new();

    public DaxqCompilationArtifact Compile(string source, DaxqCompilerOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.DiversificationSeed);
        ArgumentNullException.ThrowIfNull(options.Watermark);
        if (options.DiversificationSeed.Length != 32)
        {
            throw new ArgumentException(
                "The per-release diversification seed must contain exactly 32 bytes.",
                nameof(options));
        }
        if (options.Watermark.Length != 32)
            throw new ArgumentException("The DAXQ v1 watermark must contain exactly 32 bytes.", nameof(options));

        var lowering = _frontEnd.CompileAndLower(source, options.SourceFileName);
        var requirements = new HashSet<string>(options.DataRequirements, StringComparer.Ordinal);
        if ((lowering.Program.Entrypoints.Any(entrypoint => entrypoint.Id == DaxqEntrypoint.OnBar) ||
             lowering.Program.ReferencedHostFunctions.Contains(HostFn.Bar) ||
             lowering.Program.ReferencedHostFunctions.Contains(HostFn.Ind)) &&
            !requirements.Contains("bars"))
        {
            throw new ArgumentException(
                "A strategy using OnBar, Bar, or Indicator must declare the 'bars' data requirement.",
                nameof(options));
        }
        if (lowering.Program.Entrypoints.Any(entrypoint => entrypoint.Id == DaxqEntrypoint.OnTick) &&
            !requirements.Contains("ticks"))
        {
            throw new ArgumentException("An OnTick strategy must declare the 'ticks' data requirement.", nameof(options));
        }
        var invalidParameterId = lowering.Program.ReferencedParameterIds
            .Where(id => id >= options.Parameters.Count)
            .DefaultIfEmpty(-1)
            .First();
        if (invalidParameterId >= 0)
        {
            throw new DaxqCompilationException(
            [
                new DaxqCompilerDiagnostic(
                    "DAXQ2030",
                    $"Parameter ID {invalidParameterId} is not declared by the {options.Parameters.Count}-entry manifest."),
            ]);
        }

        var kind = ResolveManifestKind(options, lowering.Program);
        DaxqPlaintextBuildResult plaintext;
        try
        {
            plaintext = DaxqPlaintextBuilder.BuildDiversified(
                lowering.Program,
                options.Watermark,
                options.DiversificationSeed);
        }
        catch (InvalidOperationException exception)
        {
            throw new DaxqCompilationException(
            [
                new DaxqCompilerDiagnostic(
                    "DAXQ2034",
                    $"Lowered bytecode failed the DAXQ v1 verifier: {exception.Message}"),
            ]);
        }
        DaxqPackageArtifact package;
        try
        {
            package = DaxqPackageWriter.Write(new DaxqPackageWriteOptions
            {
                PlaintextBytes = plaintext.DiversifiedPlaintext,
                StrategyId = options.StrategyId,
                Version = options.Version,
                FormatVersion = options.FormatVersion,
                Kind = kind,
                Presentation = options.Presentation,
                DataRequirements = options.DataRequirements,
                Parameters = options.Parameters,
                ContentKeyId = options.ContentKeyId,
                ContentKey = options.ContentKey,
                Nonce = options.Nonce,
                ReleaseKeyId = options.ReleaseKeyId,
                ReleaseSigningKey = options.ReleaseSigningKey,
            });
        }
        catch (JsonException exception) when (options.FormatVersion == DaxqFormat.PresentationFormatVersion)
        {
            throw new DaxqCompilationException
            ([
                new DaxqCompilerDiagnostic(
                    "DAXQ2041",
                    DescribeManifestFailure(exception, options.Presentation)),
            ]);
        }
        var releaseSeed = options.DiversificationSeed.ToArray();
        return new DaxqCompilationArtifact(
            lowering,
            plaintext,
            package,
            new DaxqReleaseMetadata(
                options.StrategyId,
                options.Version,
                Convert.ToHexStringLower(releaseSeed),
                Convert.ToHexStringLower(SHA256.HashData(releaseSeed)),
                Convert.ToHexStringLower(SHA256.HashData(package.PackageBytes))));
    }

    private static DaxqKind ResolveManifestKind(
        DaxqCompilerOptions options,
        DaxqCanonicalProgram program)
    {
        if (options.FormatVersion is not (DaxqFormat.FormatVersion or DaxqFormat.PresentationFormatVersion))
        {
            throw ManifestDiagnostic(
                $"Unsupported DAXQ formatVersion {options.FormatVersion}; supported values are " +
                $"{DaxqFormat.FormatVersion} and {DaxqFormat.PresentationFormatVersion}.");
        }

        if (options.FormatVersion == DaxqFormat.FormatVersion)
        {
            if (options.Presentation is not null)
                throw ManifestDiagnostic("DAXQ v1 cannot contain a presentation block; use formatVersion 2.");
            if (options.Kind is { } v1Kind && v1Kind != DaxqKind.Strategy)
                throw ManifestDiagnostic("DAXQ v1 kind must remain strategy (wire value 'daxq').");
            return DaxqKind.Strategy;
        }

        if (options.Kind is { } declaredKind && !Enum.IsDefined(declaredKind))
            throw ManifestDiagnostic($"Unsupported declared DAXQ kind value {(byte)declaredKind}.");
        if (options.Kind == DaxqKind.Strategy && options.Presentation is not null)
        {
            throw ManifestDiagnostic(
                "A DAXQ strategy cannot contain a presentation block; use composite.");
        }

        var inferredKind = options.Presentation is null
            ? DaxqKind.Strategy
            : program.ReferencedHostFunctions.Contains(HostFn.Emit)
                ? DaxqKind.Composite
                : DaxqKind.Visualizer;
        if (options.Kind is { } kind && kind != inferredKind)
        {
            throw ManifestDiagnostic(
                $"Declared DAXQ kind '{kind.ToString().ToLowerInvariant()}' does not match compiler-inferred " +
                $"kind '{inferredKind.ToString().ToLowerInvariant()}'.");
        }
        return inferredKind;
    }

    private static DaxqCompilationException ManifestDiagnostic(string message) =>
        new([new DaxqCompilerDiagnostic("DAXQ2040", message)]);

    private static string DescribeManifestFailure(
        JsonException exception,
        DaxqPresentationManifest? presentation)
    {
        if (presentation is null)
            return $"Invalid DAXQ v2 manifest: {exception.Message}";

        var budget = presentation.Budget;
        return $"Invalid DAXQ v2 presentation: {exception.Message} " +
               $"Declared values: renderVmAbi={DaxqFormat.RenderVmAbiVersion}, " +
               $"hostFnVersion={presentation.HostFnVersion}, panelCount={presentation.PanelCount}, " +
               $"panelDeclarations={presentation.Panels?.Length.ToString() ?? "null"}, " +
               $"snapshotSlots={presentation.SnapshotSlots}, " +
               $"maxOpsPerFrame={budget?.MaxOpsPerFrame.ToString() ?? "null"}, " +
               $"maxVerticesPerSeries={budget?.MaxVerticesPerSeries.ToString() ?? "null"}, " +
               $"maxStringLength={budget?.MaxStringLength.ToString() ?? "null"}, " +
               $"maxPanels={budget?.MaxPanels.ToString() ?? "null"}. " +
               $"Contract limits: render ABI {DaxqFormat.RenderVmAbiVersion}; " +
               $"host-fn block v{DaxqFormat.RenderHostFunctionBlockVersion}; " +
               $"panels 1..{DaxqFormat.MaximumPresentationPanels}; " +
               $"snapshotSlots 0..{DaxqFormat.MaximumPresentationSnapshotSlots}; " +
               $"maxOpsPerFrame 1..{DaxqFormat.MaximumRenderOpsPerFrame}; " +
               $"maxVerticesPerSeries 0..{DaxqFormat.MaximumRenderVerticesPerSeries}; " +
               $"maxStringLength 0..{DaxqFormat.MaximumRenderStringLength}; " +
               $"maxPanels panelCount..{DaxqFormat.MaximumPresentationPanels}.";
    }
}
