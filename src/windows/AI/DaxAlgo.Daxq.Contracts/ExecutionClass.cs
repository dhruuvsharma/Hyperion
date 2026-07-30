using System.Text.Json.Serialization;

namespace DaxAlgo.Daxq.Contracts;

/// <summary>Buyer-visible marketplace execution classes and their frozen wire values.</summary>
[JsonConverter(typeof(ExecutionClassJsonConverter))]
public enum ExecutionClass : byte
{
    /// <summary>Buyer receives auditable source.</summary>
    [JsonStringEnumMemberName("source_open")]
    SourceOpen = 0,

    /// <summary>Buyer receives protected DAXQ bytecode.</summary>
    [JsonStringEnumMemberName("sealed_bytecode")]
    SealedBytecode = 1,

    /// <summary>Strategy executes server-side and returns signals only.</summary>
    [JsonStringEnumMemberName("server_signal")]
    ServerSignal = 2,
}
