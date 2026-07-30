namespace DaxAlgo.Daxq.Contracts;

/// <summary>Canonical host callback IDs for VM ABI 3. Numeric assignments are immutable.</summary>
public enum HostFn : ushort
{
    /// <summary>Read one OHLCV field at a bounded lookback.</summary>
    Bar = 1,

    /// <summary>Read one deterministic SDK indicator value.</summary>
    Ind = 2,

    /// <summary>Read one numeric strategy parameter.</summary>
    Param = 3,

    /// <summary>Stage one strategy signal.</summary>
    Emit = 4,

    /// <summary>
    /// Identifies the VM-mediated state facility. Bytecode uses LD_STATE/ST_STATE; CALL_HOST State is
    /// invalid.
    /// </summary>
    State = 5,

    /// <summary>Read the current deterministic bar index.</summary>
    TIndex = 6,

    /// <summary>Read the next seeded deterministic pseudo-random value.</summary>
    Rng = 7,

    /// <summary>Stage one bounded numeric diagnostic record.</summary>
    Log = 8,
}

/// <summary>
/// Reserved canonical IDs for the DAXQ v2 render host-function block. These constants are not
/// members of <see cref="HostFn"/> and are therefore not callable until the VM phase implements the
/// block. That phase must expose only the render block to the Render entrypoint. Its capability
/// boundary is enforced by omission: no account, credential, store, file, socket, reflection, or
/// signal-state write function is reserved, so those capabilities cannot be granted accidentally.
/// </summary>
public static class ReservedRenderHostFn
{
    /// <summary>The first ID in the reserved render block.</summary>
    public const ushort BlockStart = 0x0100;

    /// <summary>Reserved <c>panel_begin</c> ID.</summary>
    public const ushort PanelBegin = 0x0100;

    /// <summary>Reserved <c>panel_end</c> ID.</summary>
    public const ushort PanelEnd = 0x0101;

    /// <summary>Reserved <c>axis_x</c> ID.</summary>
    public const ushort AxisX = 0x0102;

    /// <summary>Reserved <c>axis_y</c> ID.</summary>
    public const ushort AxisY = 0x0103;

    /// <summary>Reserved <c>series_begin</c> ID.</summary>
    public const ushort SeriesBegin = 0x0104;

    /// <summary>Reserved <c>series_push</c> ID.</summary>
    public const ushort SeriesPush = 0x0105;

    /// <summary>Reserved <c>series_end</c> ID.</summary>
    public const ushort SeriesEnd = 0x0106;

    /// <summary>Reserved <c>draw_line</c> ID.</summary>
    public const ushort DrawLine = 0x0107;

    /// <summary>Reserved <c>draw_rect</c> ID.</summary>
    public const ushort DrawRect = 0x0108;

    /// <summary>Reserved <c>draw_text</c> ID.</summary>
    public const ushort DrawText = 0x0109;

    /// <summary>Reserved <c>draw_marker</c> ID.</summary>
    public const ushort DrawMarker = 0x010a;

    /// <summary>Reserved <c>set_style</c> ID.</summary>
    public const ushort SetStyle = 0x010b;

    /// <summary>Reserved <c>theme_color</c> ID.</summary>
    public const ushort ThemeColor = 0x010c;

    /// <summary>Reserved read-only <c>viewport</c> ID.</summary>
    public const ushort Viewport = 0x010d;

    /// <summary>Reserved read-only <c>cursor</c> ID.</summary>
    public const ushort Cursor = 0x010e;

    /// <summary>The last ID in the reserved render block.</summary>
    public const ushort BlockEnd = 0x01ff;
}
