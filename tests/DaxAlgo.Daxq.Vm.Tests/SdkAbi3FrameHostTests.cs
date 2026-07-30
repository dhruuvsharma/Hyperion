using System.Text.Json;

namespace DaxAlgo.Daxq.Vm.Tests;

public sealed class SdkAbi3FrameHostTests
{
    [Fact]
    public void Bar_and_parameter_reads_use_current_completed_bar_and_frozen_ranges()
    {
        DaxqBar[] bars =
        [
            Bar(10),
            Bar(20),
            Bar(30),
        ];
        var host = new DaxqSdkAbi3FrameHost(bars, new double[] { 4, 0.25 }, 2);

        Assert.Equal(DaxqFault.Ok, host.ReadBar(4, 0, out var currentClose));
        Assert.Equal(30, currentClose);
        Assert.Equal(DaxqFault.Ok, host.ReadBar(4, 2, out var oldestClose));
        Assert.Equal(10, oldestClose);
        Assert.Equal(DaxqFault.Host, host.ReadBar(4, 3, out _));
        Assert.Equal(DaxqFault.Host, host.ReadBar(0, 0, out _));
        Assert.Equal(DaxqFault.Ok, host.ReadParameter(1, out var parameter));
        Assert.Equal(0.25, parameter);
        Assert.Equal(DaxqFault.Host, host.ReadParameter(2, out _));

        host.CurrentCompletedBarIndex = 1;
        Assert.Equal(DaxqFault.Ok, host.ReadBar(4, 0, out currentClose));
        Assert.Equal(20, currentClose);
    }

    [Fact]
    public void EMA_SMA_RSI_and_ATR_follow_frozen_seed_and_recurrence_rules()
    {
        DaxqBar[] bars =
        [
            new(9, 10, 8, 9, 100),
            new(11, 12, 9, 11, 110),
            new(12, 13, 10, 12, 120),
            new(14, 15, 12, 14, 130),
        ];
        var host = new DaxqSdkAbi3FrameHost(bars, ReadOnlyMemory<double>.Empty, 3);

        Assert.Equal(DaxqFault.Ok, host.ReadIndicator(1, 3, 4, out var ema));
        var emaSeed = (9d + 11d + 12d) / 3d;
        var expectedEma = emaSeed + (2d / 4d) * (14d - emaSeed);
        Assert.Equal(expectedEma, ema);

        Assert.Equal(DaxqFault.Ok, host.ReadIndicator(2, 3, 4, out var sma));
        Assert.Equal((11d + 12d + 14d) / 3d, sma);

        Assert.Equal(DaxqFault.Ok, host.ReadIndicator(3, 2, 4, out var rsi));
        var seededGain = (2d + 1d) / 2d;
        var seededLoss = 0d;
        var updatedGain = ((seededGain * 1d) + 2d) / 2d;
        var updatedLoss = ((seededLoss * 1d) + 0d) / 2d;
        var expectedRsi = updatedLoss == 0d ? 100d :
            100d - (100d / (1d + (updatedGain / updatedLoss)));
        Assert.Equal(expectedRsi, rsi);

        Assert.Equal(DaxqFault.Ok, host.ReadIndicator(4, 2, 4, out var atr));
        var expectedAtr = (((2d + 3d) / 2d * 1d + 3d) / 2d * 1d + 3d) / 2d;
        Assert.Equal(expectedAtr, atr);
    }

    [Fact]
    public void RSI_special_cases_and_indicator_warmup_faults_are_exact()
    {
        var flat = new DaxqSdkAbi3FrameHost(
            new[] { Bar(5), Bar(5), Bar(5), Bar(5) },
            ReadOnlyMemory<double>.Empty,
            3);
        Assert.Equal(DaxqFault.Ok, flat.ReadIndicator(3, 3, 4, out var flatRsi));
        Assert.Equal(50, flatRsi);

        var falling = new DaxqSdkAbi3FrameHost(
            new[] { Bar(5), Bar(4), Bar(3), Bar(2) },
            ReadOnlyMemory<double>.Empty,
            3);
        Assert.Equal(DaxqFault.Ok, falling.ReadIndicator(3, 3, 4, out var fallingRsi));
        Assert.Equal(0, fallingRsi);

        var rising = new DaxqSdkAbi3FrameHost(
            new[] { Bar(1), Bar(2), Bar(3), Bar(4) },
            ReadOnlyMemory<double>.Empty,
            1);
        Assert.Equal(DaxqFault.Host, rising.ReadIndicator(1, 3, 4, out _));
        Assert.Equal(DaxqFault.Host, rising.ReadIndicator(2, 3, 4, out _));
        Assert.Equal(DaxqFault.Host, rising.ReadIndicator(3, 2, 4, out _));
        Assert.Equal(DaxqFault.Host, rising.ReadIndicator(4, 3, 4, out _));
        Assert.Equal(DaxqFault.Host, rising.ReadIndicator(4, 1, 1, out _));

        var bounded = new DaxqSdkAbi3FrameHost(
            new[] { Bar(1), Bar(2), Bar(3), Bar(4) },
            ReadOnlyMemory<double>.Empty,
            currentCompletedBarIndex: 3,
            maximumIndicatorSamples: 3);
        Assert.Equal(DaxqFault.Host, bounded.ReadIndicator(1, 2, 4, out _));
    }

    [Fact]
    public void Golden_EMA_cross_runs_against_the_exact_frame_host()
    {
        var bars = Enumerable.Range(1, 30).Select(value => Bar(value)).ToArray();
        var host = new DaxqSdkAbi3FrameHost(bars, ReadOnlyMemory<double>.Empty, bars.Length - 1);
        using var document = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", "ema-cross-v1.vector.json")));
        var plaintext = Convert.FromHexString(
            document.RootElement.GetProperty("canonicalPlaintextHex").GetString()!);
        Assert.Equal(DaxqFault.Ok, DaxqProgram.TryLoad(plaintext, out var program));
        var vm = new DaxqReferenceVm(program!, host, 1);

        var result = vm.OnBar(29);

        Assert.Equal(DaxqFault.Ok, result.Fault);
        Assert.Equal(1, Assert.Single(vm.EmittedSignals.ToArray()).Kind);
    }

    [Fact]
    public void Indicator_hot_path_allocates_no_managed_bytes()
    {
        var bars = Enumerable.Range(1, 100).Select(value => Bar(value)).ToArray();
        var host = new DaxqSdkAbi3FrameHost(bars, new double[] { 1 }, bars.Length - 1);
        Assert.Equal(DaxqFault.Ok, host.ReadIndicator(1, 12, 4, out _));
        Assert.Equal(DaxqFault.Ok, host.ReadIndicator(3, 14, 4, out _));

        var before = GC.GetAllocatedBytesForCurrentThread();
        for (var index = 0; index < 1_000; index++)
        {
            if (host.ReadIndicator(1, 12, 4, out _) != DaxqFault.Ok ||
                host.ReadIndicator(2, 12, 4, out _) != DaxqFault.Ok ||
                host.ReadIndicator(3, 14, 4, out _) != DaxqFault.Ok ||
                host.ReadIndicator(4, 14, 4, out _) != DaxqFault.Ok)
            {
                throw new InvalidOperationException();
            }
        }
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(0, allocated);
    }

    private static DaxqBar Bar(double close) => new(
        open: close,
        high: close + 1,
        low: close - 1,
        close,
        volume: close * 10);
}
