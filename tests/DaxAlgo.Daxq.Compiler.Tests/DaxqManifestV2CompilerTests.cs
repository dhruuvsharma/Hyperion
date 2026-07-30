using System.Security.Cryptography;
using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler.Tests;

public sealed class DaxqManifestV2CompilerTests
{
    private const string FrozenV1PackageBase64 = """
        UEsDBBQAAAgAAAAAIQCfzR28UAIAAFACAAANAAAAbWFuaWZlc3QuanNvbnsiZm9ybWF0VmVyc2lvbiI6MSwia2luZCI6ImRheHEiLCJzdHJhdGVneUlkIjoiZXhhbXBsZS52MS1iYXNlbGluZSIsInZlcnNpb24iOiIxLjIuMyIsInNka0FiaVZlcnNpb24iOjMsImV4ZWN1dGlvbkNsYXNzIjoic2VhbGVkX2J5dGVjb2RlIiwiZGF0YVJlcXVpcmVtZW50cyI6WyJiYXJzIl0sInBhcmFtcyI6W3siaWQiOiJ0aHJlc2hvbGQiLCJ0eXBlIjoiZmxvYXQiLCJkZWZhdWx0IjowLjV9XSwicHJvdGVjdGlvbiI6eyJhbGciOiJBRVMtMjU2LUdDTSIsImNvbnRlbnRLZXlJZCI6ImRldjpleGFtcGxlLnYxLWJhc2VsaW5lOjEuMi4zIiwibm9uY2UiOiJDZ3NNRFE0UEVCRVNFeFFWIiwiY2lwaGVyU2hhMjU2IjoiNTFhODkxYjc4Y2Y3MWIyM2Y4ZmY4ZGVkYzY2MjYzZTA5OWQzNGQ4ZDgwYzYzMWQ4YjFkYWViYWY1ODJkMjI2NCJ9LCJ3YXRlcm1hcmsiOnsic2NoZW1lIjoicGVyLWJ1eWVyLXYxIiwic2xvdCI6IndtIn0sInZtTWluIjozLCJmaWxlcyI6eyJtYW5pZmVzdC5qc29uIjoic2VsZiIsInN0cmF0ZWd5LmRxeCI6IjUxYTg5MWI3OGNmNzFiMjNmOGZmOGRlZGM2NjI2M2UwOTlkMzRkOGQ4MGM2MzFkOGIxZGFlYmFmNTgyZDIyNjQifX1QSwMEFAAACAAAAAAhAGp2AMxgAQAAYAEAAAwAAABzdHJhdGVneS5kcXgr7GKYat3UdbAE2A2OreVI/B7fL+dq/rTMWcuWU13c41ZhULGMhMJXm1H2/IQYHd9wuqeFXVNHd2nBAzYpfYLtZJeZGNWlAarNW+/S2uINfSQqWNcjxcknKU4J2bd8vMWYvw+LWrW4YJ8mq0N7pUkXM09Bvd3hXx7vr+2+bhdT23b/zzTGxazSCkXO8pBUMRr2ew5F1/b2QGiLE9XYp0n4RBCMxc3mW9YVyiVftVqBRZVGjNmZeWUPEVLFxGx9E/0F7sxzTJzaHTn0EVG8NpHOl2tKAyTo0J+idZ9qYIWrbjZ9RQW2rHvsob8EZX0vUk/EFQUaR6zy9jRZO2MbxOSeU9fOwp0zaU0l7xbCXmy6aS8+/ZQl4QpNks5DOuQ1/aCATbZaW6KSwrs6YGscocnFIZadc93ybS8JgsZdpYuZoihZk5s8mMF6xv/k9HQNaN2sHPsBijXJPV1FDyqV8/eqUEsDBBQAAAgAAAAAIQB/xu5wwgAAAMIAAAAMAAAAcGFja2FnZS5qc29ueyJmb3JtYXRWZXJzaW9uIjoxLCJmaWxlcyI6eyJtYW5pZmVzdC5qc29uIjoiZDEzZTJjYzUxNjM1N2NmN2Q1NzFhZDEzMWE5ZWQ3MmIyNTUyZjk5NjkzMzc5ODQzYzlkNTI3YWY0NWU2ZWZiYSIsInN0cmF0ZWd5LmRxeCI6IjUxYTg5MWI3OGNmNzFiMjNmOGZmOGRlZGM2NjI2M2UwOTlkMzRkOGQ4MGM2MzFkOGIxZGFlYmFmNTgyZDIyNjQifX1QSwMEFAAACAAAAAAhACDsh3iMAAAAjAAAAA4AAABzaWduYXR1cmUuanNvbnsiYWxnIjoiRVMyNTYiLCJrZXlJZCI6ImRldi1yZWxlYXNlLXAyNTYtdjEiLCJzaWciOiJwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwYVdscGFXbHBhV2xwUSJ9UEsBAhQAFAAACAAAAAAhAJ/NHbxQAgAAUAIAAA0AAAAAAAAAAAAAAAAAAAAAAG1hbmlmZXN0Lmpzb25QSwECFAAUAAAIAAAAACEAanYAzGABAABgAQAADAAAAAAAAAAAAAAAAAB7AgAAc3RyYXRlZ3kuZHF4UEsBAhQAFAAACAAAAAAhAH/G7nDCAAAAwgAAAAwAAAAAAAAAAAAAAAAABQQAAHBhY2thZ2UuanNvblBLAQIUABQAAAgAAAAAIQAg7Id4jAAAAIwAAAAOAAAAAAAAAAAAAAAAAPEEAABzaWduYXR1cmUuanNvblBLBQYAAAAABAAEAOsAAACpBQAAAAA=
        """;

    private const string V1Source = """
        using DaxAlgo.Sdk;

        public sealed class V1Baseline : IBacktestStrategy
        {
            public void OnBar(IStrategyContext context)
            {
                if (context.Bar(BarField.Close, 0) > context.Param(0))
                    context.Emit(SignalKind.Long, 1.0, 7);
            }
        }
        """;

    private const string VisualizerSource = """
        using DaxAlgo.Sdk;

        public sealed class VisualizerState : IBacktestStrategy
        {
            public void OnBar(IStrategyContext context) =>
                context.Log(1, context.Bar(BarField.Close, 0));
        }
        """;

    [Fact]
    public void V1_compile_is_byte_identical_to_the_pre_v2_package()
    {
        using var signingKey = CreateSigningKey();
        var artifact = CompileV1Baseline(signingKey);

        Assert.Equal(Convert.FromBase64String(FrozenV1PackageBase64), artifact.Package.PackageBytes);
    }

    [Fact]
    public void Visualizer_emits_v2_kind_presentation_and_indexed_manifest_digest()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var contentKey = TestContentKey();
        var artifact = Compile(
            VisualizerSource,
            signingKey,
            DaxqFormat.PresentationFormatVersion,
            CreatePresentation(),
            kind: null);
        var package = DaxqPackageTestReader.ReadVerifyAndDecrypt(
            artifact.Package.PackageBytes,
            contentKey,
            signingKey);

        Assert.Equal(DaxqFormat.PresentationFormatVersion, package.Manifest.FormatVersion);
        Assert.Equal(DaxqKind.Visualizer, package.Manifest.Kind);
        Assert.Equal(DaxqFormat.RenderVmAbiVersion, package.Manifest.VmMin);
        Assert.Equal([DaxqPanelKind.Plot, DaxqPanelKind.Canvas],
            package.Manifest.Presentation!.Panels.Select(panel => panel.Kind));
        Assert.Equal(
            package.ManifestBytes,
            JsonSerializer.SerializeToUtf8Bytes(package.Manifest));

        using var index = JsonDocument.Parse(package.PackageIndexBytes);
        Assert.Equal(DaxqFormat.FormatVersion,
            index.RootElement.GetProperty("formatVersion").GetInt32());
        Assert.Equal(
            [DaxqFormat.ManifestEntryName, DaxqFormat.CiphertextEntryName],
            index.RootElement.GetProperty("files").EnumerateObject().Select(property => property.Name));
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(package.ManifestBytes)),
            index.RootElement.GetProperty("files").GetProperty(DaxqFormat.ManifestEntryName).GetString());
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(package.CiphertextBytes)),
            index.RootElement.GetProperty("files").GetProperty(DaxqFormat.CiphertextEntryName).GetString());
    }

    [Fact]
    public void Signal_emitting_presentation_is_inferred_as_composite()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var artifact = Compile(
            V1Source,
            signingKey,
            DaxqFormat.PresentationFormatVersion,
            CreatePresentation(),
            kind: null);
        var manifest = JsonSerializer.Deserialize<DaxqManifest>(artifact.Package.ManifestJsonBytes)!;

        Assert.Equal(DaxqKind.Composite, manifest.Kind);
        Assert.NotNull(manifest.Presentation);
    }

    [Fact]
    public void V2_without_presentation_is_inferred_as_strategy()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var artifact = Compile(
            V1Source,
            signingKey,
            DaxqFormat.PresentationFormatVersion,
            presentation: null,
            kind: null);
        var manifest = JsonSerializer.Deserialize<DaxqManifest>(artifact.Package.ManifestJsonBytes)!;

        Assert.Equal(DaxqKind.Strategy, manifest.Kind);
        Assert.Equal(DaxqFormat.VmAbiVersion, manifest.VmMin);
        Assert.Null(manifest.Presentation);
    }

    [Fact]
    public void Presentation_is_declaration_only_and_does_not_change_the_encrypted_DQXP_payload()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var v1 = Compile(
            VisualizerSource,
            signingKey,
            DaxqFormat.FormatVersion,
            presentation: null,
            kind: null);
        var v2 = Compile(
            VisualizerSource,
            signingKey,
            DaxqFormat.PresentationFormatVersion,
            CreatePresentation(),
            kind: null);

        Assert.Equal(v1.Package.PlaintextBytes, v2.Package.PlaintextBytes);
        Assert.Equal(v1.Package.CiphertextAndTagBytes, v2.Package.CiphertextAndTagBytes);
        Assert.NotEqual(v1.Package.ManifestJsonBytes, v2.Package.ManifestJsonBytes);
        Assert.NotEqual(v1.Package.ManifestSha256, v2.Package.ManifestSha256);
    }

    [Fact]
    public void Declared_strategy_with_presentation_is_rejected_with_diagnostic()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var exception = Assert.Throws<DaxqCompilationException>(() => Compile(
            V1Source,
            signingKey,
            DaxqFormat.PresentationFormatVersion,
            CreatePresentation(),
            DaxqKind.Strategy));

        var diagnostic = Assert.Single(exception.Diagnostics, item => item.Code == "DAXQ2040");
        Assert.Contains(
            "A DAXQ strategy cannot contain a presentation block; use composite.",
            diagnostic.Message,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("hostFnVersion", 2, "hostFnVersion=2", "host-fn block v1")]
    [InlineData("panelCount", 9, "panelCount=9", "panels 1..8")]
    [InlineData("snapshotSlots", 257, "snapshotSlots=257", "snapshotSlots 0..256")]
    [InlineData("maxOpsPerFrame", 100_001, "maxOpsPerFrame=100001", "maxOpsPerFrame 1..100000")]
    [InlineData("maxVerticesPerSeries", 65_537, "maxVerticesPerSeries=65537", "maxVerticesPerSeries 0..65536")]
    [InlineData("maxStringLength", 4_097, "maxStringLength=4097", "maxStringLength 0..4096")]
    [InlineData("maxPanels", 9, "maxPanels=9", "maxPanels panelCount..8")]
    public void Presentation_limit_breaches_name_limit_and_offending_value(
        string member,
        int value,
        string expectedValue,
        string expectedLimit)
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var exception = Assert.Throws<DaxqCompilationException>(() => Compile(
            VisualizerSource,
            signingKey,
            DaxqFormat.PresentationFormatVersion,
            Breach(CreatePresentation(), member, value),
            kind: null));

        var diagnostic = Assert.Single(exception.Diagnostics, item => item.Code == "DAXQ2041");
        Assert.Contains(expectedValue, diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains(expectedLimit, diagnostic.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(DaxqFormat.FormatVersion)]
    [InlineData(DaxqFormat.PresentationFormatVersion)]
    public void Sealing_and_signing_round_trip_for_v1_and_v2(int formatVersion)
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var contentKey = TestContentKey();
        var artifact = Compile(
            formatVersion == DaxqFormat.FormatVersion ? V1Source : VisualizerSource,
            signingKey,
            formatVersion,
            formatVersion == DaxqFormat.FormatVersion ? null : CreatePresentation(),
            kind: null);

        var package = DaxqPackageTestReader.ReadVerifyAndDecrypt(
            artifact.Package.PackageBytes,
            contentKey,
            signingKey);
        Assert.Equal(formatVersion, package.Manifest.FormatVersion);
        Assert.Equal(artifact.Plaintext.DiversifiedPlaintext, package.PlaintextBytes);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(package.PlaintextBytes, out _));
    }

    private static DaxqCompilationArtifact CompileV1Baseline(ECDsa signingKey) =>
        new DaxqCompiler().Compile(V1Source, new DaxqCompilerOptions
        {
            StrategyId = "example.v1-baseline",
            Version = "1.2.3",
            DataRequirements = ["bars"],
            Parameters =
            [
                new DaxqParameterManifest
                {
                    Id = "threshold",
                    Type = "float",
                    Default = JsonSerializer.SerializeToElement(0.5),
                },
            ],
            DiversificationSeed = Enumerable.Repeat((byte)0x5a, 32).ToArray(),
            Watermark = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray(),
            ContentKeyId = "dev:example.v1-baseline:1.2.3",
            ContentKey = TestContentKey(),
            Nonce = Enumerable.Range(10, 12).Select(value => (byte)value).ToArray(),
            ReleaseKeyId = "dev-release-p256-v1",
            ReleaseSigningKey = signingKey,
        });

    private static DaxqCompilationArtifact Compile(
        string source,
        ECDsa signingKey,
        int formatVersion,
        DaxqPresentationManifest? presentation,
        DaxqKind? kind) =>
        new DaxqCompiler().Compile(source, new DaxqCompilerOptions
        {
            StrategyId = "example.presentation",
            Version = "2.0.0",
            FormatVersion = formatVersion,
            Kind = kind,
            Presentation = presentation,
            DataRequirements = ["bars"],
            Parameters = source == V1Source
                ?
                [
                    new DaxqParameterManifest
                    {
                        Id = "threshold",
                        Type = "float",
                        Default = JsonSerializer.SerializeToElement(0.5),
                    },
                ]
                : [],
            DiversificationSeed = Enumerable.Repeat((byte)0x42, 32).ToArray(),
            Watermark = Enumerable.Repeat((byte)0x24, 32).ToArray(),
            ContentKeyId = "dev:example.presentation:2.0.0",
            ContentKey = TestContentKey(),
            Nonce = Enumerable.Range(20, 12).Select(value => (byte)value).ToArray(),
            ReleaseKeyId = "dev-release-p256-v1",
            ReleaseSigningKey = signingKey,
        });

    private static byte[] TestContentKey() =>
        Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();

    private static DaxqPresentationManifest CreatePresentation() => new()
    {
        Entrypoints = [DaxqFormat.RenderEntrypoint],
        PanelCount = 2,
        Panels =
        [
            new DaxqPanelManifest { Id = 0, Kind = DaxqPanelKind.Plot },
            new DaxqPanelManifest { Id = 1, Kind = DaxqPanelKind.Canvas },
        ],
        HostFnVersion = DaxqFormat.RenderHostFunctionBlockVersion,
        SnapshotSlots = 64,
        Budget = new DaxqRenderBudgetManifest
        {
            MaxOpsPerFrame = 10_000,
            MaxVerticesPerSeries = 4_096,
            MaxStringLength = 256,
            MaxPanels = 2,
        },
    };

    private static DaxqPresentationManifest Breach(
        DaxqPresentationManifest presentation,
        string member,
        int value) => member switch
        {
            "hostFnVersion" => presentation with { HostFnVersion = value },
            "panelCount" => presentation with
            {
                PanelCount = value,
                Panels = Enumerable.Range(0, value)
                    .Select(id => new DaxqPanelManifest { Id = id, Kind = DaxqPanelKind.Plot })
                    .ToArray(),
                Budget = presentation.Budget with { MaxPanels = value },
            },
            "snapshotSlots" => presentation with { SnapshotSlots = value },
            "maxOpsPerFrame" => presentation with
            {
                Budget = presentation.Budget with { MaxOpsPerFrame = value },
            },
            "maxVerticesPerSeries" => presentation with
            {
                Budget = presentation.Budget with { MaxVerticesPerSeries = value },
            },
            "maxStringLength" => presentation with
            {
                Budget = presentation.Budget with { MaxStringLength = value },
            },
            "maxPanels" => presentation with
            {
                Budget = presentation.Budget with { MaxPanels = value },
            },
            _ => throw new ArgumentOutOfRangeException(nameof(member), member, null),
        };

    private static ECDsa CreateSigningKey() => new FixedSignatureEcdsa();

    private sealed class FixedSignatureEcdsa : ECDsa
    {
        private readonly ECDsa _key;

        public FixedSignatureEcdsa()
        {
            var d = new byte[32];
            d[^1] = 1;
            _key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = d,
                Q = new ECPoint
                {
                    X = Convert.FromHexString(
                        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                    Y = Convert.FromHexString(
                        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                },
            });
            KeySizeValue = 256;
        }

        public override ECParameters ExportParameters(bool includePrivateParameters) =>
            _key.ExportParameters(includePrivateParameters);

        public override void ImportParameters(ECParameters parameters) =>
            _key.ImportParameters(parameters);

        public override byte[] SignHash(byte[] hash) => Enumerable.Repeat((byte)0xa5, 64).ToArray();

        public override bool VerifyHash(byte[] hash, byte[] signature) =>
            signature.AsSpan().SequenceEqual(Enumerable.Repeat((byte)0xa5, 64).ToArray());

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _key.Dispose();
            base.Dispose(disposing);
        }
    }
}
