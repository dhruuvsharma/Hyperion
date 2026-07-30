namespace DaxAlgo.Daxq.Contracts;

/// <summary>Canonical opcode IDs for VM ABI 3. Numeric assignments are immutable.</summary>
public enum Opcode : byte
{
    /// <summary>Push a constant-pool binary64 value.</summary>
    PUSH_F64 = 0x01,

    /// <summary>Push a constant-pool signed 64-bit integer.</summary>
    PUSH_I64 = 0x02,

    /// <summary>Push an immediate Boolean.</summary>
    PUSH_BOOL = 0x03,

    /// <summary>Load a local.</summary>
    LD_LOC = 0x04,

    /// <summary>Store a local.</summary>
    ST_LOC = 0x05,

    /// <summary>Load a callback argument.</summary>
    LD_ARG = 0x06,

    /// <summary>Add two same-typed numeric values.</summary>
    ADD = 0x07,

    /// <summary>Subtract two same-typed numeric values.</summary>
    SUB = 0x08,

    /// <summary>Multiply two same-typed numeric values.</summary>
    MUL = 0x09,

    /// <summary>Divide two same-typed numeric values.</summary>
    DIV = 0x0a,

    /// <summary>Compute the remainder of two same-typed numeric values.</summary>
    MOD = 0x0b,

    /// <summary>Negate a numeric value.</summary>
    NEG = 0x0c,

    /// <summary>Compare two same-typed scalar values for equality.</summary>
    CEQ = 0x0d,

    /// <summary>Compare two same-typed scalar values for inequality.</summary>
    CNE = 0x0e,

    /// <summary>Compare two same-typed numeric values for less-than.</summary>
    CLT = 0x0f,

    /// <summary>Compare two same-typed numeric values for less-than-or-equal.</summary>
    CLE = 0x10,

    /// <summary>Compare two same-typed numeric values for greater-than.</summary>
    CGT = 0x11,

    /// <summary>Compare two same-typed numeric values for greater-than-or-equal.</summary>
    CGE = 0x12,

    /// <summary>Compute Boolean AND.</summary>
    AND = 0x13,

    /// <summary>Compute Boolean OR.</summary>
    OR = 0x14,

    /// <summary>Negate a Boolean.</summary>
    NOT = 0x15,

    /// <summary>Convert a signed 64-bit integer to binary64.</summary>
    I2F = 0x16,

    /// <summary>Convert binary64 to a signed 64-bit integer.</summary>
    F2I = 0x17,

    /// <summary>Branch unconditionally.</summary>
    BR = 0x18,

    /// <summary>Branch when the popped Boolean is true.</summary>
    BRT = 0x19,

    /// <summary>Branch when the popped Boolean is false.</summary>
    BRF = 0x1a,

    /// <summary>Allocate a bounded callback-local primitive buffer.</summary>
    NEWBUF = 0x1b,

    /// <summary>Load a bounded primitive-buffer element.</summary>
    LDELEM = 0x1c,

    /// <summary>Store a bounded primitive-buffer element.</summary>
    STELEM = 0x1d,

    /// <summary>Read a bounded primitive-buffer length.</summary>
    LEN = 0x1e,

    /// <summary>Load a persistent scalar state slot.</summary>
    LD_STATE = 0x1f,

    /// <summary>Stage a persistent scalar state-slot write.</summary>
    ST_STATE = 0x20,

    /// <summary>Call one whitelisted host function.</summary>
    CALL_HOST = 0x21,

    /// <summary>Return successfully from the current callback.</summary>
    RET = 0x22,
}
