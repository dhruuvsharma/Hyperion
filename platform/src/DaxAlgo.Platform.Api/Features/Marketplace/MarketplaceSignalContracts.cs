using System.Text.Json.Serialization;

namespace DaxAlgo.Platform.Features.Marketplace;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record SignalSessionOpenRequest(
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("challenge_id")] Guid ChallengeId,
    [property: JsonPropertyName("client_session_nonce")] string ClientSessionNonce,
    [property: JsonPropertyName("device_signature")] string DeviceSignature);

public sealed record SignalSessionOpenResponse(
    [property: JsonPropertyName("session_id")] Guid SessionId,
    [property: JsonPropertyName("websocket_url")] string WebSocketUrl,
    [property: JsonPropertyName("session_token")] string SessionToken,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("heartbeat_interval_seconds")] int HeartbeatIntervalSeconds);

internal sealed record SignalSessionTokenClaims(
    [property: JsonPropertyName("v")] int SchemaVersion,
    [property: JsonPropertyName("session_id")] Guid SessionId,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("account_id")] Guid AccountId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("iss")] string Issuer,
    [property: JsonPropertyName("aud")] string Audience,
    [property: JsonPropertyName("iat")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("exp")] DateTimeOffset ExpiresAt);

public sealed record SignalSandboxRequest(
    Guid SessionId,
    ReadOnlyMemory<byte> DaxqPackage,
    ReadOnlyMemory<byte> ContentKey,
    ReadOnlyMemory<byte> MarketDataFrames,
    string ReleaseSigningKeyId,
    ReadOnlyMemory<byte> ReleaseVerificationKeySpki);

public sealed record SignalSandboxSignal(
    string Kind,
    double Strength,
    long NoteId);

public interface ISignalSandboxRunner
{
    bool IsAvailable { get; }

    IAsyncEnumerable<SignalSandboxSignal> RunAsync(
        SignalSandboxRequest request,
        CancellationToken cancellationToken);
}

internal sealed record SignalWireFrame(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("sequence")] long Sequence,
    [property: JsonPropertyName("emitted_at")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    DateTimeOffset? EmittedAt,
    [property: JsonPropertyName("kind")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Kind,
    [property: JsonPropertyName("strength")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    double? Strength,
    [property: JsonPropertyName("note_id")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    long? NoteId,
    [property: JsonPropertyName("sent_at")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    DateTimeOffset? SentAt);
