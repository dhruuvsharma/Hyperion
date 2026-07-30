using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Daxq.Contracts;

namespace DaxAlgo.Daxq.Contracts.Tests;

public sealed class DaxqManifestV2Tests
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    [Fact]
    public void Visualizer_with_presentation_round_trips()
    {
        var manifest = CreateDrawingManifest(DaxqKind.Visualizer);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJsonOptions);
        var roundTrip = JsonSerializer.Deserialize<DaxqManifest>(bytes, ManifestJsonOptions)!;

        Assert.Equal(DaxqFormat.PresentationFormatVersion, roundTrip.FormatVersion);
        Assert.Equal(DaxqKind.Visualizer, roundTrip.Kind);
        Assert.Equal(DaxqFormat.RenderVmAbiVersion, roundTrip.VmMin);
        Assert.Equal(64, roundTrip.Presentation!.SnapshotSlots);
        Assert.Equal([DaxqPanelKind.Plot, DaxqPanelKind.Canvas],
            roundTrip.Presentation.Panels.Select(panel => panel.Kind));
    }

    [Fact]
    public void Composite_with_presentation_round_trips()
    {
        var manifest = CreateDrawingManifest(DaxqKind.Composite);

        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJsonOptions);
        var roundTrip = JsonSerializer.Deserialize<DaxqManifest>(bytes, ManifestJsonOptions)!;

        Assert.Equal(DaxqKind.Composite, roundTrip.Kind);
        Assert.NotNull(roundTrip.Presentation);
        Assert.Equal(bytes, JsonSerializer.SerializeToUtf8Bytes(roundTrip, ManifestJsonOptions));
    }

    [Fact]
    public void Absent_v2_kind_reads_as_strategy()
    {
        var json = Serialize(CreateStrategyManifest())
            .Replace("\"kind\":\"strategy\",", string.Empty, StringComparison.Ordinal);

        var manifest = JsonSerializer.Deserialize<DaxqManifest>(json, ManifestJsonOptions)!;

        Assert.Equal(DaxqKind.Strategy, manifest.Kind);
        Assert.Null(manifest.Presentation);
    }

    [Fact]
    public void Absent_v1_kind_reads_as_strategy_and_writes_the_frozen_wire_value()
    {
        var v1 = CreateStrategyManifest() with
        {
            FormatVersion = DaxqFormat.FormatVersion,
            VmMin = DaxqFormat.VmAbiVersion,
        };
        var json = Serialize(v1)
            .Replace("\"kind\":\"daxq\",", string.Empty, StringComparison.Ordinal);

        var manifest = JsonSerializer.Deserialize<DaxqManifest>(json, ManifestJsonOptions)!;
        var canonical = Serialize(manifest);

        Assert.Equal(DaxqKind.Strategy, manifest.Kind);
        Assert.Contains("\"kind\":\"daxq\"", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void Canonical_v2_serialization_is_byte_stable()
    {
        var first = JsonSerializer.SerializeToUtf8Bytes(
            CreateDrawingManifest(DaxqKind.Visualizer), ManifestJsonOptions);
        var manifest = JsonSerializer.Deserialize<DaxqManifest>(first, ManifestJsonOptions)!;
        var second = JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJsonOptions);

        Assert.True(first.AsSpan().SequenceEqual(second),
            $"First {Convert.ToHexStringLower(first)}, second {Convert.ToHexStringLower(second)}.");
    }

    [Fact]
    public void Unknown_manifest_property_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Insert(1, "\"unexpected\":true,");

        AssertRejected(json, "unknown property 'unexpected'");
    }

    [Fact]
    public void Unknown_presentation_property_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"entrypoints\":[\"Render\"],",
                "\"entrypoints\":[\"Render\"],\"unexpected\":true,", StringComparison.Ordinal);

        AssertRejected(json, "unknown property 'unexpected'");
    }

    [Fact]
    public void Duplicate_manifest_property_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"kind\":\"visualizer\",",
                "\"kind\":\"visualizer\",\"kind\":\"visualizer\",", StringComparison.Ordinal);

        AssertRejected(json, "duplicate property 'kind'");
    }

    [Fact]
    public void Duplicate_presentation_property_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"snapshotSlots\":64,",
                "\"snapshotSlots\":64,\"snapshotSlots\":64,", StringComparison.Ordinal);

        AssertRejected(json, "duplicate property 'snapshotSlots'");
    }

    [Fact]
    public void V1_presentation_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"formatVersion\":2", "\"formatVersion\":1", StringComparison.Ordinal)
            .Replace("\"kind\":\"visualizer\"", "\"kind\":\"daxq\"", StringComparison.Ordinal)
            .Replace("\"vmMin\":4", "\"vmMin\":3", StringComparison.Ordinal);

        AssertRejected(json, "v1 cannot contain a presentation block");
    }

    [Theory]
    [InlineData("\"panelCount\":2", "\"panelCount\":9", "panelCount exceeds")]
    [InlineData("\"snapshotSlots\":64", "\"snapshotSlots\":257", "snapshotSlots exceeds")]
    [InlineData("\"maxOpsPerFrame\":10000", "\"maxOpsPerFrame\":100001", "maxOpsPerFrame limit")]
    [InlineData("\"maxVerticesPerSeries\":4096", "\"maxVerticesPerSeries\":65537", "maxVerticesPerSeries limit")]
    [InlineData("\"maxStringLength\":256", "\"maxStringLength\":4097", "maxStringLength limit")]
    [InlineData("\"maxPanels\":2", "\"maxPanels\":9", "maxPanels limit")]
    public void Presentation_counts_and_budgets_above_hard_limits_are_rejected_fail_closed(
        string original,
        string replacement,
        string expectedDiagnostic)
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace(original, replacement, StringComparison.Ordinal);

        AssertRejected(json, expectedDiagnostic);
    }

    [Fact]
    public void Panel_count_above_requested_budget_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"maxPanels\":2", "\"maxPanels\":1", StringComparison.Ordinal);

        AssertRejected(json, "maxPanels limit");
    }

    [Fact]
    public void Visualizer_without_presentation_is_rejected_fail_closed()
    {
        var json = Serialize(CreateStrategyManifest())
            .Replace("\"kind\":\"strategy\"", "\"kind\":\"visualizer\"", StringComparison.Ordinal);

        AssertRejected(json, "require a presentation block");
    }

    [Fact]
    public void Composite_without_presentation_is_rejected_fail_closed()
    {
        var json = Serialize(CreateStrategyManifest())
            .Replace("\"kind\":\"strategy\"", "\"kind\":\"composite\"", StringComparison.Ordinal);

        AssertRejected(json, "require a presentation block");
    }

    [Fact]
    public void Presentation_below_render_vm_abi_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"vmMin\":4", "\"vmMin\":3", StringComparison.Ordinal);

        AssertRejected(json, "requires the render VM ABI");
    }

    [Fact]
    public void Strategy_with_presentation_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"kind\":\"visualizer\"", "\"kind\":\"strategy\"", StringComparison.Ordinal);

        AssertRejected(json, "use composite");
    }

    [Theory]
    [InlineData("widget")]
    [InlineData("VISUALIZER")]
    [InlineData("daxq")]
    public void Unknown_or_noncanonical_v2_kind_is_rejected_fail_closed(string kind)
    {
        var json = Serialize(CreateStrategyManifest())
            .Replace("\"kind\":\"strategy\"", $"\"kind\":\"{kind}\"", StringComparison.Ordinal);

        AssertRejected(json, "Unsupported kind value");
    }

    [Fact]
    public void Unknown_panel_kind_is_rejected_fail_closed()
    {
        var json = Serialize(CreateDrawingManifest(DaxqKind.Visualizer))
            .Replace("\"kind\":\"plot\"", "\"kind\":\"overlay\"", StringComparison.Ordinal);

        AssertRejected(json, "Unsupported panel kind value");
    }

    [Theory]
    [InlineData("1")]
    [InlineData("\"VISUALIZER\"")]
    [InlineData("\"daxq\"")]
    [InlineData("\"unknown\"")]
    public void Kind_converter_rejects_noncanonical_wire_values(string json)
    {
        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<DaxqKind>(json, ManifestJsonOptions));
        Assert.Contains("kind", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unsupported_format_version_is_rejected_fail_closed()
    {
        var json = Serialize(CreateStrategyManifest())
            .Replace("\"formatVersion\":2", "\"formatVersion\":3", StringComparison.Ordinal);

        AssertRejected(json, "Unsupported DAXQ formatVersion value");
    }

    [Fact]
    public void Render_host_function_ids_are_reserved_but_not_callable_v1_host_functions()
    {
        ushort[] reserved =
        [
            ReservedRenderHostFn.PanelBegin,
            ReservedRenderHostFn.PanelEnd,
            ReservedRenderHostFn.AxisX,
            ReservedRenderHostFn.AxisY,
            ReservedRenderHostFn.SeriesBegin,
            ReservedRenderHostFn.SeriesPush,
            ReservedRenderHostFn.SeriesEnd,
            ReservedRenderHostFn.DrawLine,
            ReservedRenderHostFn.DrawRect,
            ReservedRenderHostFn.DrawText,
            ReservedRenderHostFn.DrawMarker,
            ReservedRenderHostFn.SetStyle,
            ReservedRenderHostFn.ThemeColor,
            ReservedRenderHostFn.Viewport,
            ReservedRenderHostFn.Cursor,
        ];

        Assert.Equal(
            Enumerable.Range(ReservedRenderHostFn.BlockStart, reserved.Length).Select(value => (ushort)value),
            reserved);
        Assert.Equal(0x01ff, ReservedRenderHostFn.BlockEnd);
        Assert.All(reserved, id => Assert.False(Enum.IsDefined(typeof(HostFn), id)));
    }

    private static DaxqManifest CreateDrawingManifest(DaxqKind kind) => new()
    {
        FormatVersion = DaxqFormat.PresentationFormatVersion,
        Kind = kind,
        StrategyId = "example.depth-map",
        Version = "2.0.0",
        SdkAbiVersion = DaxqFormat.SdkAbiVersion,
        ExecutionClass = ExecutionClass.SealedBytecode,
        DataRequirements = ["depth"],
        Parameters = [],
        Protection = CreateProtection(),
        Watermark = CreateWatermark(),
        VmMin = DaxqFormat.RenderVmAbiVersion,
        Files = CreateFiles(),
        Presentation = new DaxqPresentationManifest
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
        },
    };

    private static DaxqManifest CreateStrategyManifest() => new()
    {
        FormatVersion = DaxqFormat.PresentationFormatVersion,
        Kind = DaxqKind.Strategy,
        StrategyId = "example.strategy",
        Version = "2.0.0",
        SdkAbiVersion = DaxqFormat.SdkAbiVersion,
        ExecutionClass = ExecutionClass.SealedBytecode,
        DataRequirements = ["bars"],
        Parameters = [],
        Protection = CreateProtection(),
        Watermark = CreateWatermark(),
        VmMin = DaxqFormat.VmAbiVersion,
        Files = CreateFiles(),
    };

    private static DaxqProtectionManifest CreateProtection() => new()
    {
        Algorithm = DaxqFormat.CipherAlgorithm,
        ContentKeyId = "ck_example",
        Nonce = "AAECAwQFBgcICQoL",
        CipherSha256 = new string('0', 64),
    };

    private static DaxqWatermarkManifest CreateWatermark() => new()
    {
        Scheme = "per-buyer-v1",
        Slot = "wm",
    };

    private static Dictionary<string, string> CreateFiles() => new(StringComparer.Ordinal)
    {
        [DaxqFormat.ManifestEntryName] = "self",
        [DaxqFormat.CiphertextEntryName] = new string('0', 64),
    };

    private static string Serialize(DaxqManifest manifest) =>
        Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(manifest, ManifestJsonOptions));

    private static void AssertRejected(string json, string expectedDiagnostic)
    {
        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<DaxqManifest>(json, ManifestJsonOptions));
        Assert.Contains(expectedDiagnostic, exception.Message, StringComparison.Ordinal);
    }
}
