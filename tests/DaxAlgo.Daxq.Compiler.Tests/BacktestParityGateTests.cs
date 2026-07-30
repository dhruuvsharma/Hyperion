using System.Security.Cryptography;
using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler.Tests;

public sealed class BacktestParityGateTests
{
    private const string StrategySource = """
        using DaxAlgo.Sdk;

        public sealed class ListingStrategy : IBacktestStrategy
        {
            public void OnBar(IStrategyContext context)
            {
                double close = context.Bar(BarField.Close, 0);
                if (close >= context.Param(0))
                    context.Emit(SignalKind.Long, 0.6, 11);
                else
                    context.Emit(SignalKind.Short, 0.4, 12);
            }
        }
        """;

    private const string FinancialModelStrategySource = """
        using DaxAlgo.Sdk;

        public sealed class FinancialModelStrategy : IBacktestStrategy
        {
            public void Initialize(IStrategyContext context) =>
                context.Emit(SignalKind.Long, 1.0, 1);

            public void OnBar(IStrategyContext context)
            {
                double close = context.Bar(BarField.Close, 0);
                if (close >= 115.0)
                    context.Emit(SignalKind.Short, 0.5, 4);
                else if (close >= 105.0)
                    context.Emit(SignalKind.Long, 0.5, 3);
                else
                    context.Emit(SignalKind.Long, 1.0, 2);
            }
        }
        """;

    private const string TickFinancialModelStrategySource = """
        using DaxAlgo.Sdk;

        public sealed class TickFinancialModelStrategy : IBacktestStrategy
        {
            public void Initialize(IStrategyContext context) =>
                context.Emit(SignalKind.Long, 1.0, 1);

            public void OnTick(
                IStrategyContext context,
                double bid,
                double ask,
                double last,
                double volume)
            {
                context.Emit(SignalKind.Flat, 1.0, 2);
            }
        }
        """;

    [Fact]
    public void Faithful_transpile_passes_publication_gate_and_emits_canonical_statistics()
    {
        var artifact = Compile(Enumerable.Repeat((byte)0x31, 32).ToArray());
        var result = new DaxqBacktestParityGate().Evaluate(artifact, ReferenceData());

        Assert.True(result.PublicationAllowed);
        Assert.Equal(DaxqPublicationDecision.Pass, result.Decision);
        Assert.Empty(result.Diagnostics);
        var statistics = Assert.IsType<DaxqBacktestStatistics>(result.Statistics);
        Assert.Equal(DaxqBacktestStatistics.CurrentSchemaVersion, statistics.SchemaVersion);
        Assert.Equal(4, statistics.BarCallbacks);
        Assert.Equal(4, statistics.SignalCount);
        Assert.Equal(3, statistics.LongSignalCount);
        Assert.Equal(1, statistics.ShortSignalCount);
        Assert.NotNull(result.CanonicalStatisticsJson);
        Assert.Equal(64, result.StatisticsSha256!.Length);
        var listingMetrics = Assert.IsType<DaxqListingMetrics>(result.ListingMetrics);
        Assert.Equal(DaxqListingMetrics.CurrentSchemaVersion, listingMetrics.SchemaVersion);
        Assert.NotNull(result.CanonicalListingMetricsJson);
        Assert.Equal(64, result.ListingMetricsSha256!.Length);
    }

    [Fact]
    public void Injected_lowering_divergence_blocks_publication_with_signal_diagnostic()
    {
        var artifact = Compile(Enumerable.Repeat((byte)0x42, 32).ToArray());
        var corrupted = ReplaceStrength(artifact, 0.6, 0.9);
        var corruptedArtifact = artifact with
        {
            Plaintext = corrupted,
            Package = artifact.Package with { PlaintextBytes = corrupted.DiversifiedPlaintext },
        };

        var result = new DaxqBacktestParityGate().Evaluate(corruptedArtifact, ReferenceData());

        Assert.False(result.PublicationAllowed);
        Assert.Equal(DaxqPublicationDecision.Block, result.Decision);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal("DAXQ3007", diagnostic.Code);
        Assert.Contains("managed=0.6", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("DAXQ=0.9", diagnostic.Message, StringComparison.Ordinal);
        Assert.Null(result.Statistics);
        Assert.Null(result.ListingMetrics);
    }

    [Fact]
    public void Configured_tolerance_allows_bounded_signal_difference()
    {
        var artifact = Compile(Enumerable.Repeat((byte)0x53, 32).ToArray());
        var changed = ReplaceStrength(artifact, 0.6, 0.61);
        var changedArtifact = artifact with
        {
            Plaintext = changed,
            Package = artifact.Package with { PlaintextBytes = changed.DiversifiedPlaintext },
        };

        var result = new DaxqBacktestParityGate().Evaluate(
            changedArtifact,
            ReferenceData(),
            new DaxqParityTolerance
            {
                MaximumAbsoluteSignalStrengthDifference = 0.02,
            });

        Assert.True(result.PublicationAllowed);
    }

    [Fact]
    public void Canonical_statistics_are_byte_deterministic()
    {
        var artifact = Compile(Enumerable.Repeat((byte)0x64, 32).ToArray());
        var gate = new DaxqBacktestParityGate();

        var first = gate.Evaluate(artifact, ReferenceData());
        var second = gate.Evaluate(artifact, ReferenceData());

        Assert.True(first.PublicationAllowed);
        Assert.True(second.PublicationAllowed);
        Assert.Equal(first.Statistics, second.Statistics);
        Assert.Equal(first.CanonicalStatisticsJson, second.CanonicalStatisticsJson);
        Assert.Equal(first.StatisticsSha256, second.StatisticsSha256);
        Assert.Equal(first.ListingMetrics, second.ListingMetrics);
        Assert.Equal(first.CanonicalListingMetricsJson, second.CanonicalListingMetricsJson);
        Assert.Equal(first.ListingMetricsSha256, second.ListingMetricsSha256);

        using var cliOutput = JsonDocument.Parse(DaxqBacktestParityOutputJson.Write(first));
        Assert.Equal(2, cliOutput.RootElement.EnumerateObject().Count());
        Assert.Equal(
            DaxqBacktestStatistics.CurrentSchemaVersion,
            cliOutput.RootElement
                .GetProperty("parityStatistics")
                .GetProperty("schemaVersion")
                .GetString());
        Assert.Equal(
            DaxqListingMetrics.CurrentSchemaVersion,
            cliOutput.RootElement
                .GetProperty("listingMetrics")
                .GetProperty("schemaVersion")
                .GetString());
    }

    [Fact]
    public void Canonical_listing_metrics_apply_v1_cost_resize_and_final_liquidation_policy()
    {
        var artifact = CompileFinancialModel(
            FinancialModelStrategySource,
            "example.financial-model",
            ["bars"]);
        DaxqBar[] bars =
        [
            new(100, 101, 99, 100, 100),
            new(110, 111, 109, 110, 100),
            new(120, 121, 119, 120, 100),
            new(90, 91, 89, 90, 100),
        ];

        var result = new DaxqBacktestParityGate().Evaluate(
            artifact,
            new DaxqBacktestReferenceData
            {
                Bars = bars,
                Callbacks = Enumerable.Range(0, bars.Length)
                    .Select(DaxqBacktestCallback.Bar)
                    .ToArray(),
            });

        Assert.True(result.PublicationAllowed);
        var metrics = Assert.IsType<DaxqListingMetrics>(result.ListingMetrics);
        Assert.Equal("USD", metrics.Currency);
        Assert.Equal(DaxqListingMetrics.PolicyFillModel, metrics.FillModel);
        Assert.Equal(DaxqListingMetrics.PolicySizingModel, metrics.SizingModel);
        Assert.Equal(DaxqListingMetrics.PolicyProfitLossModel, metrics.ProfitLossModel);
        Assert.Equal(100_000d, metrics.StartingEquity);
        Assert.Equal(10_000d, metrics.MaximumGrossNotional);
        AssertClose(750d, metrics.GrossProfitLoss);
        AssertClose(4.075d, metrics.CommissionFees);
        AssertClose(4.075d, metrics.SlippageCost);
        AssertClose(741.85d, metrics.NetProfitLoss);
        AssertClose(0.74185d, metrics.ReturnPercent);
        Assert.Equal(3, metrics.ClosedTrades);
        Assert.Equal(1, metrics.WinningTrades);
        Assert.Equal(2, metrics.LosingTrades);
        AssertClose(100d / 3d, metrics.WinRatePercent);
        AssertClose(1_256.15d, metrics.MaximumDrawdown);

        using var json = JsonDocument.Parse(result.CanonicalListingMetricsJson!);
        Assert.Equal(
            DaxqListingMetrics.CurrentSchemaVersion,
            json.RootElement.GetProperty("schemaVersion").GetString());
        Assert.Equal(
            DaxqListingMetrics.PolicyFillModel,
            json.RootElement.GetProperty("fillModel").GetString());
        Assert.Equal(
            DaxqListingMetrics.PolicySizingModel,
            json.RootElement.GetProperty("sizingModel").GetString());
        Assert.Equal(
            DaxqListingMetrics.PolicyProfitLossModel,
            json.RootElement.GetProperty("profitLossModel").GetString());
        Assert.Equal(
            result.ListingMetricsSha256,
            Convert.ToHexStringLower(SHA256.HashData(result.CanonicalListingMetricsJson!)));
    }

    [Fact]
    public void Tick_listing_metrics_use_midpoint_then_positive_last_fallback()
    {
        var artifact = CompileFinancialModel(
            TickFinancialModelStrategySource,
            "example.tick-financial-model",
            ["ticks"]);
        var result = new DaxqBacktestParityGate().Evaluate(
            artifact,
            new DaxqBacktestReferenceData
            {
                Bars = [],
                Callbacks =
                [
                    DaxqBacktestCallback.Tick(0, -1, 99, 101, 100, 1),
                    DaxqBacktestCallback.Tick(1, -1, 0, 0, 110, 1),
                ],
            });

        Assert.True(result.PublicationAllowed);
        var metrics = Assert.IsType<DaxqListingMetrics>(result.ListingMetrics);
        AssertClose(1_000d, metrics.GrossProfitLoss);
        AssertClose(2.1d, metrics.CommissionFees);
        AssertClose(2.1d, metrics.SlippageCost);
        AssertClose(995.8d, metrics.NetProfitLoss);
        AssertClose(0.9958d, metrics.ReturnPercent);
        Assert.Equal(1, metrics.ClosedTrades);
        Assert.Equal(1, metrics.WinningTrades);
        AssertClose(2.2d, metrics.MaximumDrawdown);
    }

    [Fact]
    public void Listing_metric_reference_prices_reject_crossed_quotes()
    {
        var artifact = CompileFinancialModel(
            TickFinancialModelStrategySource,
            "example.invalid-tick-financial-model",
            ["ticks"]);
        var referenceData = new DaxqBacktestReferenceData
        {
            Bars = [],
            Callbacks = [DaxqBacktestCallback.Tick(0, -1, 101, 99, 100, 1)],
        };

        var exception = Assert.Throws<ArgumentException>(() =>
            new DaxqBacktestParityGate().Evaluate(artifact, referenceData));

        Assert.Contains("ask below bid", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Release_seeds_change_all_encodings_while_preserving_interpreted_behaviour()
    {
        var firstSeed = Enumerable.Repeat((byte)0x75, 32).ToArray();
        var secondSeed = Enumerable.Repeat((byte)0x86, 32).ToArray();
        var first = Compile(firstSeed);
        var second = Compile(secondSeed);

        Assert.False(first.Plaintext.DiversifiedBytecode.SequenceEqual(second.Plaintext.DiversifiedBytecode));
        Assert.False(first.Plaintext.DiversifiedConstants.SequenceEqual(second.Plaintext.DiversifiedConstants));
        Assert.False(first.Plaintext.OpcodeMap.SequenceEqual(second.Plaintext.OpcodeMap));
        Assert.False(first.Plaintext.HostMap.SequenceEqual(second.Plaintext.HostMap));
        Assert.Equal(Convert.ToHexStringLower(firstSeed), first.Release.DiversificationSeedHex);
        Assert.Equal(Convert.ToHexStringLower(secondSeed), second.Release.DiversificationSeedHex);
        Assert.NotEqual(first.Release.DiversificationSeedSha256, second.Release.DiversificationSeedSha256);

        var gate = new DaxqBacktestParityGate();
        var firstResult = gate.Evaluate(first, ReferenceData());
        var secondResult = gate.Evaluate(second, ReferenceData());
        Assert.True(firstResult.PublicationAllowed);
        Assert.True(secondResult.PublicationAllowed);
        Assert.Equal(firstResult.Statistics!.SignalCount, secondResult.Statistics!.SignalCount);
        Assert.Equal(firstResult.Statistics.LongSignalCount, secondResult.Statistics.LongSignalCount);
        Assert.Equal(firstResult.Statistics.ShortSignalCount, secondResult.Statistics.ShortSignalCount);
        Assert.Equal(firstResult.Statistics.MinimumSignalStrength, secondResult.Statistics.MinimumSignalStrength);
        Assert.Equal(firstResult.Statistics.MaximumSignalStrength, secondResult.Statistics.MaximumSignalStrength);
        Assert.Equal(firstResult.Statistics.AverageSignalStrength, secondResult.Statistics.AverageSignalStrength);
    }

    private static DaxqCompilationArtifact Compile(byte[] releaseSeed)
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new DaxqCompiler().Compile(StrategySource, new DaxqCompilerOptions
        {
            StrategyId = "example.listing-strategy",
            Version = "1.0.0",
            DataRequirements = ["bars"],
            Parameters =
            [
                new DaxqParameterManifest
                {
                    Id = "threshold",
                    Type = "float",
                    Default = JsonSerializer.SerializeToElement(10d),
                },
            ],
            DiversificationSeed = releaseSeed,
            ContentKeyId = "dev:example.listing-strategy:1.0.0",
            ContentKey = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray(),
            Nonce = Enumerable.Range(1, 12).Select(value => (byte)(value + 40)).ToArray(),
            ReleaseKeyId = "dev-parity-p256-v1",
            ReleaseSigningKey = signingKey,
        });
    }

    private static DaxqCompilationArtifact CompileFinancialModel(
        string source,
        string strategyId,
        IReadOnlyList<string> dataRequirements)
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new DaxqCompiler().Compile(source, new DaxqCompilerOptions
        {
            StrategyId = strategyId,
            Version = "1.0.0",
            DataRequirements = dataRequirements,
            DiversificationSeed = Enumerable.Repeat((byte)0xa5, 32).ToArray(),
            ContentKeyId = $"dev:{strategyId}:1.0.0",
            ContentKey = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray(),
            Nonce = Enumerable.Range(1, 12).Select(value => (byte)(value + 60)).ToArray(),
            ReleaseKeyId = "dev-listing-metrics-p256-v1",
            ReleaseSigningKey = signingKey,
        });
    }

    private static void AssertClose(double expected, double actual) =>
        Assert.InRange(Math.Abs(actual - expected), 0d, 1e-9);

    private static DaxqPlaintextBuildResult ReplaceStrength(
        DaxqCompilationArtifact artifact,
        double expected,
        double replacement)
    {
        var replaced = false;
        var constants = artifact.Lowering.Program.Constants.Select(constant =>
        {
            if (constant.Type == DaxqValueType.F64 &&
                BitConverter.Int64BitsToDouble(constant.Bits) == expected)
            {
                replaced = true;
                return DaxqConstant.FromDouble(replacement);
            }
            return constant;
        }).ToArray();
        Assert.True(replaced);
        var corruptedProgram = artifact.Lowering.Program with { Constants = constants };
        return DaxqPlaintextBuilder.BuildDiversified(
            corruptedProgram,
            Convert.FromHexString(artifact.Release.DiversificationSeedHex));
    }

    private static DaxqBacktestReferenceData ReferenceData()
    {
        DaxqBar[] bars =
        [
            new(9, 11, 8, 10, 100),
            new(10, 10, 8, 9, 110),
            new(9, 12, 9, 11, 120),
            new(11, 13, 10, 12, 130),
        ];
        return new DaxqBacktestReferenceData
        {
            Bars = bars,
            Parameters = [10d],
            Callbacks = Enumerable.Range(0, bars.Length)
                .Select(DaxqBacktestCallback.Bar)
                .ToArray(),
            LaunchSeed = 0x5eed,
        };
    }
}
