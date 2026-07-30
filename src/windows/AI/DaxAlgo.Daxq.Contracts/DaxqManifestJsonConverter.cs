using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>Reads and writes the exact, version-aware DAXQ manifest wire contract.</summary>
internal sealed class DaxqManifestJsonConverter : JsonConverter<DaxqManifest>
{
    private static readonly string[] ManifestRequiredProperties =
    [
        "formatVersion", "strategyId", "version", "sdkAbiVersion", "executionClass",
        "dataRequirements", "params", "protection", "watermark", "vmMin", "files",
    ];

    public override DaxqManifest Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        var properties = ReadObject(document.RootElement, "manifest");
        var formatVersion = ReadInt32(Required(properties, "formatVersion", "manifest"),
            "manifest.formatVersion");
        if (formatVersion is not (DaxqFormat.FormatVersion or DaxqFormat.PresentationFormatVersion))
            throw new JsonException("Unsupported DAXQ formatVersion value.");

        RequireExactProperties(
            properties,
            ManifestRequiredProperties,
            ["kind", "presentation"],
            "manifest");

        var kind = ReadKind(properties, formatVersion);
        var presentation = properties.TryGetValue("presentation", out var presentationElement)
            ? ReadPresentation(presentationElement)
            : null;

        var manifest = new DaxqManifest
        {
            FormatVersion = formatVersion,
            Kind = kind,
            StrategyId = ReadString(Required(properties, "strategyId", "manifest"),
                "manifest.strategyId"),
            Version = ReadString(Required(properties, "version", "manifest"),
                "manifest.version"),
            SdkAbiVersion = ReadInt32(Required(properties, "sdkAbiVersion", "manifest"),
                "manifest.sdkAbiVersion"),
            ExecutionClass = ReadExecutionClass(
                Required(properties, "executionClass", "manifest")),
            DataRequirements = ReadStringArray(
                Required(properties, "dataRequirements", "manifest"),
                "manifest.dataRequirements"),
            Parameters = ReadParameters(Required(properties, "params", "manifest")),
            Protection = ReadProtection(Required(properties, "protection", "manifest")),
            Watermark = ReadWatermark(Required(properties, "watermark", "manifest")),
            VmMin = ReadInt32(Required(properties, "vmMin", "manifest"), "manifest.vmMin"),
            Files = ReadFiles(Required(properties, "files", "manifest")),
            Presentation = presentation,
        };

        ValidateManifest(manifest);
        return manifest;
    }

    public override void Write(
        Utf8JsonWriter writer,
        DaxqManifest value,
        JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidateManifest(value);

        writer.WriteStartObject();
        writer.WriteNumber("formatVersion", value.FormatVersion);
        writer.WriteString("kind", value.FormatVersion == DaxqFormat.FormatVersion
            ? DaxqFormat.LegacyKindWireName
            : DaxqKindJsonConverter.WireName(value.Kind));
        writer.WriteString("strategyId", value.StrategyId);
        writer.WriteString("version", value.Version);
        writer.WriteNumber("sdkAbiVersion", value.SdkAbiVersion);
        writer.WriteString("executionClass", ExecutionClassJsonConverter.WireName(value.ExecutionClass));
        WriteStringArray(writer, "dataRequirements", value.DataRequirements);
        writer.WritePropertyName("params");
        WriteParameters(writer, value.Parameters);
        WriteProtection(writer, value.Protection);
        WriteWatermark(writer, value.Watermark);
        writer.WriteNumber("vmMin", value.VmMin);
        WriteFiles(writer, value.Files);
        if (value.Presentation is not null)
            WritePresentation(writer, value.Presentation);
        writer.WriteEndObject();
    }

    private static DaxqKind ReadKind(
        IReadOnlyDictionary<string, JsonElement> properties,
        int formatVersion)
    {
        if (!properties.TryGetValue("kind", out var element))
            return DaxqKind.Strategy;
        if (element.ValueKind != JsonValueKind.String)
            throw new JsonException("manifest.kind must be an exact lowercase string.");

        var wireName = element.GetString();
        if (formatVersion == DaxqFormat.FormatVersion)
        {
            if (wireName != DaxqFormat.LegacyKindWireName)
                throw new JsonException("DAXQ v1 kind must be 'daxq'.");
            return DaxqKind.Strategy;
        }

        return DaxqKindJsonConverter.Parse(wireName);
    }

    private static ExecutionClass ReadExecutionClass(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.String)
            throw new JsonException("manifest.executionClass must be an exact lowercase string.");
        return ExecutionClassJsonConverter.Parse(element.GetString());
    }

    private static DaxqParameterManifest[] ReadParameters(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Array)
            throw new JsonException("manifest.params must be an array.");

        var parameters = new List<DaxqParameterManifest>();
        var index = 0;
        foreach (var item in element.EnumerateArray())
        {
            var location = $"manifest.params[{index++}]";
            var properties = ReadObject(item, location);
            RequireExactProperties(properties, ["id", "type", "default"], ["min", "max"], location);
            parameters.Add(new DaxqParameterManifest
            {
                Id = ReadString(Required(properties, "id", location), $"{location}.id"),
                Type = ReadString(Required(properties, "type", location), $"{location}.type"),
                Min = properties.TryGetValue("min", out var min) ? min.Clone() : null,
                Max = properties.TryGetValue("max", out var max) ? max.Clone() : null,
                Default = Required(properties, "default", location).Clone(),
            });
        }
        return [.. parameters];
    }

    private static DaxqProtectionManifest ReadProtection(JsonElement element)
    {
        const string location = "manifest.protection";
        var properties = ReadObject(element, location);
        RequireExactProperties(properties,
            ["alg", "contentKeyId", "nonce", "cipherSha256"], [], location);
        return new DaxqProtectionManifest
        {
            Algorithm = ReadString(Required(properties, "alg", location), $"{location}.alg"),
            ContentKeyId = ReadString(Required(properties, "contentKeyId", location),
                $"{location}.contentKeyId"),
            Nonce = ReadString(Required(properties, "nonce", location), $"{location}.nonce"),
            CipherSha256 = ReadString(Required(properties, "cipherSha256", location),
                $"{location}.cipherSha256"),
        };
    }

    private static DaxqWatermarkManifest ReadWatermark(JsonElement element)
    {
        const string location = "manifest.watermark";
        var properties = ReadObject(element, location);
        RequireExactProperties(properties, ["scheme", "slot"], [], location);
        return new DaxqWatermarkManifest
        {
            Scheme = ReadString(Required(properties, "scheme", location), $"{location}.scheme"),
            Slot = ReadString(Required(properties, "slot", location), $"{location}.slot"),
        };
    }

    private static Dictionary<string, string> ReadFiles(JsonElement element)
    {
        const string location = "manifest.files";
        var properties = ReadObject(element, location);
        RequireExactProperties(properties,
            [DaxqFormat.ManifestEntryName, DaxqFormat.CiphertextEntryName], [], location);
        return properties.ToDictionary(
            pair => pair.Key,
            pair => ReadString(pair.Value, $"{location}.{pair.Key}"),
            StringComparer.Ordinal);
    }

    private static DaxqPresentationManifest ReadPresentation(JsonElement element)
    {
        const string location = "manifest.presentation";
        var properties = ReadObject(element, location);
        RequireExactProperties(properties,
            ["entrypoints", "panelCount", "panels", "hostFnVersion", "snapshotSlots", "budget"],
            [], location);

        var panelsElement = Required(properties, "panels", location);
        if (panelsElement.ValueKind != JsonValueKind.Array)
            throw new JsonException("manifest.presentation.panels must be an array.");
        var panels = new List<DaxqPanelManifest>();
        var index = 0;
        foreach (var panelElement in panelsElement.EnumerateArray())
        {
            var panelLocation = $"manifest.presentation.panels[{index++}]";
            var panelProperties = ReadObject(panelElement, panelLocation);
            RequireExactProperties(panelProperties, ["id", "kind"], [], panelLocation);
            var kindElement = Required(panelProperties, "kind", panelLocation);
            if (kindElement.ValueKind != JsonValueKind.String)
                throw new JsonException($"{panelLocation}.kind must be an exact lowercase string.");
            panels.Add(new DaxqPanelManifest
            {
                Id = ReadInt32(Required(panelProperties, "id", panelLocation), $"{panelLocation}.id"),
                Kind = DaxqPanelKindJsonConverter.Parse(kindElement.GetString()),
            });
        }

        var budgetElement = Required(properties, "budget", location);
        var budgetProperties = ReadObject(budgetElement, $"{location}.budget");
        RequireExactProperties(budgetProperties,
            ["maxOpsPerFrame", "maxVerticesPerSeries", "maxStringLength", "maxPanels"],
            [], $"{location}.budget");

        return new DaxqPresentationManifest
        {
            Entrypoints = ReadStringArray(Required(properties, "entrypoints", location),
                $"{location}.entrypoints"),
            PanelCount = ReadInt32(Required(properties, "panelCount", location),
                $"{location}.panelCount"),
            Panels = [.. panels],
            HostFnVersion = ReadInt32(Required(properties, "hostFnVersion", location),
                $"{location}.hostFnVersion"),
            SnapshotSlots = ReadInt32(Required(properties, "snapshotSlots", location),
                $"{location}.snapshotSlots"),
            Budget = new DaxqRenderBudgetManifest
            {
                MaxOpsPerFrame = ReadInt32(Required(budgetProperties, "maxOpsPerFrame", location),
                    $"{location}.budget.maxOpsPerFrame"),
                MaxVerticesPerSeries = ReadInt32(
                    Required(budgetProperties, "maxVerticesPerSeries", location),
                    $"{location}.budget.maxVerticesPerSeries"),
                MaxStringLength = ReadInt32(Required(budgetProperties, "maxStringLength", location),
                    $"{location}.budget.maxStringLength"),
                MaxPanels = ReadInt32(Required(budgetProperties, "maxPanels", location),
                    $"{location}.budget.maxPanels"),
            },
        };
    }

    private static void ValidateManifest(DaxqManifest manifest)
    {
        if (manifest.FormatVersion is not (DaxqFormat.FormatVersion or DaxqFormat.PresentationFormatVersion))
            throw new JsonException("Unsupported DAXQ formatVersion value.");
        if (!Enum.IsDefined(manifest.Kind))
            throw new JsonException("Unsupported kind value.");
        if (manifest.DataRequirements is null || manifest.Parameters is null ||
            manifest.Protection is null || manifest.Watermark is null || manifest.Files is null)
        {
            throw new JsonException("A required DAXQ manifest member is null.");
        }

        if (manifest.FormatVersion == DaxqFormat.FormatVersion)
        {
            if (manifest.Kind != DaxqKind.Strategy)
                throw new JsonException("DAXQ v1 kind must be strategy.");
            if (manifest.Presentation is not null)
                throw new JsonException("DAXQ v1 cannot contain a presentation block.");
            if (manifest.VmMin != DaxqFormat.VmAbiVersion)
                throw new JsonException("DAXQ v1 vmMin must remain VM ABI 3.");
            return;
        }

        if (manifest.VmMin < DaxqFormat.VmAbiVersion)
            throw new JsonException("DAXQ v2 vmMin cannot be below VM ABI 3.");
        if (manifest.Kind == DaxqKind.Strategy && manifest.Presentation is not null)
            throw new JsonException("A DAXQ strategy cannot contain a presentation block; use composite.");
        if (manifest.Kind is DaxqKind.Visualizer or DaxqKind.Composite && manifest.Presentation is null)
            throw new JsonException("Drawing DAXQ kinds require a presentation block.");
        if (manifest.Presentation is null)
            return;
        if (manifest.VmMin < DaxqFormat.RenderVmAbiVersion)
            throw new JsonException("A DAXQ presentation requires the render VM ABI.");

        ValidatePresentation(manifest.Presentation);
    }

    private static void ValidatePresentation(DaxqPresentationManifest presentation)
    {
        if (presentation.Entrypoints is null || presentation.Entrypoints.Length != 1 ||
            presentation.Entrypoints[0] != DaxqFormat.RenderEntrypoint)
        {
            throw new JsonException("presentation.entrypoints must contain only 'Render'.");
        }
        if (presentation.PanelCount is < 1 or > DaxqFormat.MaximumPresentationPanels)
            throw new JsonException("presentation.panelCount exceeds the declared panel limit.");
        if (presentation.Panels is null || presentation.PanelCount != presentation.Panels.Length)
            throw new JsonException("presentation.panelCount must match the panel declarations.");
        for (var index = 0; index < presentation.Panels.Length; index++)
        {
            var panel = presentation.Panels[index];
            if (panel is null || panel.Id != index || !Enum.IsDefined(panel.Kind))
                throw new JsonException("presentation panels must use ordered IDs and supported kinds.");
        }
        if (presentation.HostFnVersion != DaxqFormat.RenderHostFunctionBlockVersion)
            throw new JsonException("Unsupported presentation hostFnVersion value.");
        if (presentation.SnapshotSlots is < 0 or > DaxqFormat.MaximumPresentationSnapshotSlots)
            throw new JsonException("presentation.snapshotSlots exceeds the declared slot limit.");
        if (presentation.Budget is null)
            throw new JsonException("presentation.budget is required.");

        var budget = presentation.Budget;
        if (budget.MaxOpsPerFrame is < 1 or > DaxqFormat.MaximumRenderOpsPerFrame)
            throw new JsonException("presentation budget exceeds the maxOpsPerFrame limit.");
        if (budget.MaxVerticesPerSeries is < 0 or > DaxqFormat.MaximumRenderVerticesPerSeries)
            throw new JsonException("presentation budget exceeds the maxVerticesPerSeries limit.");
        if (budget.MaxStringLength is < 0 or > DaxqFormat.MaximumRenderStringLength)
            throw new JsonException("presentation budget exceeds the maxStringLength limit.");
        if (budget.MaxPanels < presentation.PanelCount ||
            budget.MaxPanels > DaxqFormat.MaximumPresentationPanels)
        {
            throw new JsonException("presentation budget exceeds the maxPanels limit.");
        }
    }

    private static void WriteParameters(Utf8JsonWriter writer, IEnumerable<DaxqParameterManifest> parameters)
    {
        writer.WriteStartArray();
        foreach (var parameter in parameters)
        {
            if (parameter is null)
                throw new JsonException("manifest.params cannot contain null.");
            writer.WriteStartObject();
            writer.WriteString("id", parameter.Id);
            writer.WriteString("type", parameter.Type);
            if (parameter.Min is { } min)
            {
                writer.WritePropertyName("min");
                min.WriteTo(writer);
            }
            if (parameter.Max is { } max)
            {
                writer.WritePropertyName("max");
                max.WriteTo(writer);
            }
            writer.WritePropertyName("default");
            parameter.Default.WriteTo(writer);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    private static void WriteProtection(Utf8JsonWriter writer, DaxqProtectionManifest protection)
    {
        writer.WriteStartObject("protection");
        writer.WriteString("alg", protection.Algorithm);
        writer.WriteString("contentKeyId", protection.ContentKeyId);
        writer.WriteString("nonce", protection.Nonce);
        writer.WriteString("cipherSha256", protection.CipherSha256);
        writer.WriteEndObject();
    }

    private static void WriteWatermark(Utf8JsonWriter writer, DaxqWatermarkManifest watermark)
    {
        writer.WriteStartObject("watermark");
        writer.WriteString("scheme", watermark.Scheme);
        writer.WriteString("slot", watermark.Slot);
        writer.WriteEndObject();
    }

    private static void WriteFiles(Utf8JsonWriter writer, IReadOnlyDictionary<string, string> files)
    {
        writer.WriteStartObject("files");
        foreach (var (name, hash) in files.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            writer.WriteString(name, hash);
        writer.WriteEndObject();
    }

    private static void WritePresentation(Utf8JsonWriter writer, DaxqPresentationManifest presentation)
    {
        writer.WriteStartObject("presentation");
        WriteStringArray(writer, "entrypoints", presentation.Entrypoints);
        writer.WriteNumber("panelCount", presentation.PanelCount);
        writer.WriteStartArray("panels");
        foreach (var panel in presentation.Panels)
        {
            writer.WriteStartObject();
            writer.WriteNumber("id", panel.Id);
            writer.WriteString("kind", DaxqPanelKindJsonConverter.WireName(panel.Kind));
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteNumber("hostFnVersion", presentation.HostFnVersion);
        writer.WriteNumber("snapshotSlots", presentation.SnapshotSlots);
        writer.WriteStartObject("budget");
        writer.WriteNumber("maxOpsPerFrame", presentation.Budget.MaxOpsPerFrame);
        writer.WriteNumber("maxVerticesPerSeries", presentation.Budget.MaxVerticesPerSeries);
        writer.WriteNumber("maxStringLength", presentation.Budget.MaxStringLength);
        writer.WriteNumber("maxPanels", presentation.Budget.MaxPanels);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteStringArray(Utf8JsonWriter writer, string propertyName, IEnumerable<string> values)
    {
        writer.WriteStartArray(propertyName);
        foreach (var value in values)
            writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    private static Dictionary<string, JsonElement> ReadObject(JsonElement element, string location)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new JsonException($"{location} must be an object.");

        var properties = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!properties.TryAdd(property.Name, property.Value))
                throw new JsonException($"{location} contains duplicate property '{property.Name}'.");
        }
        return properties;
    }

    private static void RequireExactProperties(
        IReadOnlyDictionary<string, JsonElement> properties,
        IReadOnlyCollection<string> required,
        IReadOnlyCollection<string> optional,
        string location)
    {
        foreach (var property in properties.Keys)
        {
            if (!required.Contains(property, StringComparer.Ordinal) &&
                !optional.Contains(property, StringComparer.Ordinal))
            {
                throw new JsonException($"{location} contains unknown property '{property}'.");
            }
        }
        foreach (var property in required)
        {
            if (!properties.ContainsKey(property))
                throw new JsonException($"{location} omitted required property '{property}'.");
        }
    }

    private static JsonElement Required(
        IReadOnlyDictionary<string, JsonElement> properties,
        string name,
        string location) =>
        properties.TryGetValue(name, out var value)
            ? value
            : throw new JsonException($"{location} omitted required property '{name}'.");

    private static int ReadInt32(JsonElement element, string location)
    {
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt32(out var value))
            throw new JsonException($"{location} must be a 32-bit integer.");
        return value;
    }

    private static string ReadString(JsonElement element, string location)
    {
        if (element.ValueKind != JsonValueKind.String)
            throw new JsonException($"{location} must be a string.");
        return element.GetString()!;
    }

    private static string[] ReadStringArray(JsonElement element, string location)
    {
        if (element.ValueKind != JsonValueKind.Array)
            throw new JsonException($"{location} must be an array.");
        var values = new List<string>();
        var index = 0;
        foreach (var item in element.EnumerateArray())
            values.Add(ReadString(item, $"{location}[{index++}]"));
        return [.. values];
    }
}
