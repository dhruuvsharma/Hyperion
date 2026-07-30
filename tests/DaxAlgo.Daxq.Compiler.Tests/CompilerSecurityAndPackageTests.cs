using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler.Tests;

public sealed class CompilerSecurityAndPackageTests
{
    private const string SimpleSource = """
        using DaxAlgo.Sdk;

        public sealed class SimpleStrategy : IBacktestStrategy
        {
            public void OnBar(IStrategyContext context)
            {
                if (context.Bar(BarField.Close, 0) > context.Param(0))
                    context.Emit(SignalKind.Long, 1.0, 0);
            }
        }
        """;

    [Theory]
    [MemberData(nameof(RejectedSources))]
    public void Unsupported_surfaces_are_hard_rejected(string source, string expectedCode)
    {
        var exception = Assert.Throws<DaxqCompilationException>(() =>
            new DaxqRoslynCompiler().CompileAndLower(source));

        Assert.Contains(exception.Diagnostics, diagnostic => diagnostic.Code == expectedCode);
    }

    [Fact]
    public void Diversification_is_complete_bijective_deterministic_and_VM_loadable()
    {
        var program = new DaxqRoslynCompiler().CompileAndLower(SimpleSource).Program;
        var firstSeed = Enumerable.Repeat((byte)0x12, 32).ToArray();
        var otherSeed = Enumerable.Repeat((byte)0x34, 32).ToArray();
        var first = DaxqPlaintextBuilder.BuildDiversified(program, firstSeed);
        var repeated = DaxqPlaintextBuilder.BuildDiversified(program, firstSeed);
        var other = DaxqPlaintextBuilder.BuildDiversified(program, otherSeed);

        Assert.Equal(Enum.GetValues<Opcode>().Length, first.OpcodeMap.Count);
        Assert.Equal(Enum.GetValues<HostFn>().Length, first.HostMap.Count);
        Assert.Equal(first.OpcodeMap.Count, first.OpcodeMap.Select(entry => entry.Encoded).Distinct().Count());
        Assert.Equal(first.HostMap.Count, first.HostMap.Select(entry => entry.Encoded).Distinct().Count());
        Assert.Equal(first.DiversifiedPlaintext, repeated.DiversifiedPlaintext);
        Assert.NotEqual(first.DiversifiedPlaintext, other.DiversifiedPlaintext);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(first.DiversifiedPlaintext, out _));
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(other.DiversifiedPlaintext, out _));
    }

    [Fact]
    public void Complete_package_decrypts_loads_indexes_and_verifies_release_signature()
    {
        var contentKey = Enumerable.Range(0, 32).Select(index => (byte)index).ToArray();
        var nonce = Enumerable.Range(0, 12).Select(index => (byte)(index + 10)).ToArray();
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var artifact = new DaxqCompiler().Compile(SimpleSource, new DaxqCompilerOptions
        {
            StrategyId = "example.simple-strategy",
            Version = "1.0.0",
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
            ContentKeyId = "dev:example.simple-strategy:1.0.0",
            ContentKey = contentKey,
            Nonce = nonce,
            ReleaseKeyId = "dev-release-p256-v1",
            ReleaseSigningKey = signingKey,
        });

        var package = DaxqPackageTestReader.ReadVerifyAndDecrypt(
            artifact.Package.PackageBytes,
            contentKey,
            signingKey);
        Assert.Equal(artifact.Plaintext.DiversifiedPlaintext, package.PlaintextBytes);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(package.PlaintextBytes, out _));

        using var zipStream = new MemoryStream(artifact.Package.PackageBytes);
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);
        Assert.Equal(
            new[] { "manifest.json", "package.json", "signature.json", "strategy.dqx" },
            archive.Entries.Select(entry => entry.FullName).Order(StringComparer.Ordinal).ToArray());
        Assert.All(archive.Entries, entry => Assert.DoesNotContain('/', entry.FullName));

        using var index = JsonDocument.Parse(package.PackageIndexBytes);
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(package.ManifestBytes)),
            index.RootElement.GetProperty("files").GetProperty("manifest.json").GetString());
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(package.CiphertextBytes)),
            index.RootElement.GetProperty("files").GetProperty("strategy.dqx").GetString());
        Assert.Equal(DaxqFormat.SignatureSizeBytes, package.SignatureBytes.Length);
    }

    [Fact]
    public void Builder_preserves_branch_operands_and_exact_nonzero_watermark()
    {
        var code = new byte[]
        {
            (byte)Opcode.LD_ARG, 0, 0,
            (byte)Opcode.PUSH_I64, 0, 0,
            (byte)Opcode.CGT,
            (byte)Opcode.BRF, 1, 0, 0, 0,
            (byte)Opcode.RET,
            (byte)Opcode.RET,
        };
        var program = new DaxqCanonicalProgram(
            [DaxqConstant.FromInt64(0)],
            [],
            [new DaxqCanonicalEntrypoint(DaxqEntrypoint.OnBar, 0, code)]);
        var watermark = Enumerable.Range(0, 32).Select(index => (byte)(255 - index)).ToArray();

        var result = DaxqPlaintextBuilder.BuildDiversified(
            program,
            watermark,
            Enumerable.Repeat((byte)0x98, 32).ToArray());

        Assert.Equal(
            result.CanonicalBytecode.AsSpan(8, 4).ToArray(),
            result.DiversifiedBytecode.AsSpan(8, 4).ToArray());
        Assert.Equal(watermark, result.DiversifiedPlaintext[^32..]);
    }

    [Fact]
    public void Builder_rewrites_constant_pool_to_global_first_use_order()
    {
        var code = new byte[]
        {
            (byte)Opcode.PUSH_I64, 1, 0,
            (byte)Opcode.PUSH_F64, 0, 0,
            (byte)Opcode.CALL_HOST, (byte)HostFn.Log, 0, 2,
            (byte)Opcode.RET,
        };
        var program = new DaxqCanonicalProgram(
            [DaxqConstant.FromDouble(0.25), DaxqConstant.FromInt64(7)],
            [],
            [new DaxqCanonicalEntrypoint(DaxqEntrypoint.OnBar, 0, code)]);

        var result = DaxqPlaintextBuilder.BuildCanonical(program);

        Assert.Equal(DaxqValueType.I64, result.Constants[0].Type);
        Assert.Equal(7, result.Constants[0].Bits);
        Assert.Equal(DaxqValueType.F64, result.Constants[1].Type);
        Assert.Equal(0, result.CanonicalBytecode[1]);
        Assert.Equal(1, result.CanonicalBytecode[4]);
    }

    [Fact]
    public void Package_manifest_must_declare_every_referenced_parameter_id()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var exception = Assert.Throws<DaxqCompilationException>(() =>
            new DaxqCompiler().Compile(SimpleSource, new DaxqCompilerOptions
            {
                StrategyId = "example.missing-parameter",
                Version = "1.0.0",
                DataRequirements = ["bars"],
                DiversificationSeed = Enumerable.Repeat((byte)1, 32).ToArray(),
                ContentKeyId = "dev:missing-parameter",
                ContentKey = new byte[32],
                Nonce = new byte[12],
                ReleaseKeyId = "dev-release-p256-v1",
                ReleaseSigningKey = signingKey,
            }));

        Assert.Contains(exception.Diagnostics, diagnostic => diagnostic.Code == "DAXQ2030");
    }

    [Fact]
    public void Int32_state_is_rejected_instead_of_becoming_semantically_wider_VM_state()
    {
        const string source = """
            using DaxAlgo.Sdk;
            public sealed class Bad : IBacktestStrategy
            {
                private int _counter;
                public void OnBar(IStrategyContext context)
                {
                    _counter++;
                    context.Log(1, _counter);
                }
            }
            """;

        var exception = Assert.Throws<DaxqCompilationException>(() =>
            new DaxqRoslynCompiler().CompileAndLower(source));

        Assert.Contains(exception.Diagnostics, diagnostic => diagnostic.Code == "DAXQ2024");
    }

    [Fact]
    public void Provably_invalid_host_constant_is_a_clear_compiler_diagnostic()
    {
        const string source = """
            using DaxAlgo.Sdk;
            public sealed class Bad : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context) =>
                    context.Log(1, context.Bar((BarField)99, 0));
            }
            """;

        var exception = Assert.Throws<DaxqCompilationException>(() =>
            new DaxqRoslynCompiler().CompileAndLower(source));

        Assert.Contains(exception.Diagnostics, diagnostic => diagnostic.Code == "DAXQ2031");
    }

    [Fact]
    public void Additional_executable_types_are_rejected_before_managed_loading()
    {
        const string source = """
            using DaxAlgo.Sdk;
            public sealed class Good : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context) => context.Log(1, 0);
            }
            public static class Hidden
            {
                public static void Run() => System.Console.WriteLine("outside kernel");
            }
            """;

        var exception = Assert.Throws<DaxqCompilationException>(() =>
            new DaxqRoslynCompiler().CompileAndLower(source));

        Assert.Contains(exception.Diagnostics, diagnostic => diagnostic.Code == "DAXQ2032");
    }

    public static TheoryData<string, string> RejectedSources => new()
    {
        {
            """
            using DaxAlgo.Sdk;
            using System.IO;
            public sealed class Bad : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context) => context.Log(1, File.Exists("secret") ? 1.0 : 0.0);
            }
            """,
            "DAXQ1100"
        },
        {
            """
            using DaxAlgo.Sdk;
            using System;
            public sealed class Bad : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context) => context.Log(1, Math.Abs(context.Param(0)));
            }
            """,
            "DAXQ2023"
        },
        {
            """
            using DaxAlgo.Sdk;
            public sealed class Bad : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context)
                {
                    context.Log(1, new object().GetHashCode());
                }
            }
            """,
            "DAXQ2025"
        },
        {
            """
            using DaxAlgo.Sdk;
            using System.Runtime.InteropServices;
            public sealed class Bad : IBacktestStrategy
            {
                [DllImport("kernel32.dll")]
                private static extern int Beep(int frequency, int duration);
                public void OnBar(IStrategyContext context) => context.Log(1, Beep(100, 10));
            }
            """,
            "DAXQ1100"
        },
        {
            """
            using DaxAlgo.Sdk;
            public sealed class Bad : IBacktestStrategy
            {
                public unsafe void OnBar(IStrategyContext context)
                {
                    long value = 0;
                    long* pointer = &value;
                    context.Log(1, *pointer);
                }
            }
            """,
            "CS0227"
        },
        {
            """
            using DaxAlgo.Sdk;
            public sealed class Bad : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context) =>
                    context.Log(1, typeof(string).GetMethods().Length);
            }
            """,
            "DAXQ2025"
        },
    };
}
