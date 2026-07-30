using System.Text.Json.Serialization;

namespace DaxAlgo.Platform.Features.Marketplace;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record DeviceProofChallengeRequest(
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("binding_sha256")] string BindingSha256);

public sealed record DeviceProofChallengeResponse(
    [property: JsonPropertyName("challenge_id")] Guid ChallengeId,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record ContentKeyReleaseRequest(
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("challenge_id")] Guid ChallengeId,
    [property: JsonPropertyName("session_public_key")] string SessionPublicKey,
    [property: JsonPropertyName("device_signature")] string DeviceSignature);

public sealed record ContentKeyReleaseResponse(
    [property: JsonPropertyName("wrapped_key")] string WrappedKey,
    [property: JsonPropertyName("key_wrap_algorithm")] string KeyWrapAlgorithm,
    [property: JsonPropertyName("content_algorithm")] string ContentAlgorithm,
    [property: JsonPropertyName("content_key_id")] string ContentKeyId,
    [property: JsonPropertyName("ttl_seconds")] int TtlSeconds,
    [property: JsonPropertyName("server_ephemeral_public_key")] string ServerEphemeralPublicKey,
    [property: JsonPropertyName("run_token")] MarketplaceSignedToken RunToken,
    [property: JsonPropertyName("offline_lease")] MarketplaceSignedToken? OfflineLease);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record MarketplaceHeartbeatRequest(
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("challenge_id")] Guid ChallengeId,
    [property: JsonPropertyName("run_token")] MarketplaceSignedEnvelope RunToken,
    [property: JsonPropertyName("device_signature")] string DeviceSignature);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record MarketplaceSignedEnvelope(
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("encoded_payload")] string EncodedPayload,
    [property: JsonPropertyName("encoded_signature")] string EncodedSignature);

public sealed record MarketplaceHeartbeatResponse(
    [property: JsonPropertyName("ttl_seconds")] int TtlSeconds,
    [property: JsonPropertyName("run_token")] MarketplaceSignedToken RunToken,
    [property: JsonPropertyName("offline_lease")] MarketplaceSignedToken? OfflineLease);

public sealed record MarketplaceSignedToken(
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("token_kind")] string TokenKind,
    [property: JsonPropertyName("token_id")] string TokenId,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("account_id")] Guid AccountId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("access_valid_until")] DateTimeOffset AccessValidUntil,
    [property: JsonPropertyName("revocation_seq")] long RevocationSequence,
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("encoded_payload")] string EncodedPayload,
    [property: JsonPropertyName("encoded_signature")] string EncodedSignature);

public sealed record DownloadGrantResponse(
    [property: JsonPropertyName("download_url")] string DownloadUrl,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("cipher_sha256")] string CipherSha256);

public sealed record RevocationFeedItem(
    [property: JsonPropertyName("seq")] long Sequence,
    [property: JsonPropertyName("target_type")] string TargetType,
    [property: JsonPropertyName("target_id")] string TargetId,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt);

public sealed record SignedRevocationFeed(
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("from_seq")] long FromSequence,
    [property: JsonPropertyName("through_seq")] long ThroughSequence,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("revocations")] IReadOnlyList<RevocationFeedItem> Revocations,
    [property: JsonPropertyName("key_id")] string KeyId,
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("encoded_payload")] string EncodedPayload,
    [property: JsonPropertyName("encoded_signature")] string EncodedSignature);

public sealed record MarketplaceLicenseJsonWebKeySet(
    [property: JsonPropertyName("keys")] IReadOnlyList<Providers.MarketplaceLicenseJsonWebKey> Keys);

internal sealed record MarketplaceTokenClaims(
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("token_kind")] string TokenKind,
    [property: JsonPropertyName("token_id")] string TokenId,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("account_id")] Guid AccountId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("access_valid_until")] DateTimeOffset AccessValidUntil,
    [property: JsonPropertyName("revocation_seq")] long RevocationSequence);

internal sealed record RevocationFeedClaims(
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("from_seq")] long FromSequence,
    [property: JsonPropertyName("through_seq")] long ThroughSequence,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("revocations")] IReadOnlyList<RevocationFeedItem> Revocations);

internal sealed record DownloadGrantClaims(
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("grant_id")] string GrantId,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("account_id")] Guid AccountId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("cipher_sha256")] string CipherSha256,
    [property: JsonPropertyName("issued_at")] DateTimeOffset IssuedAt,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt);

internal sealed record DeviceProofPayload(
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("challenge_id")] Guid ChallengeId,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("binding_sha256")] string BindingSha256,
    [property: JsonPropertyName("idempotency_key")] string IdempotencyKey);

internal sealed record ChallengeRequestFingerprint(
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("license_id")] Guid LicenseId,
    [property: JsonPropertyName("release_id")] Guid ReleaseId,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("binding_sha256")] string BindingSha256);
