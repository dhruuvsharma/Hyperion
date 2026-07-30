using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Devices;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class MarketplaceLicensingService(
    PlatformDbContext database,
    DeviceService devices,
    IMarketplaceLicenseCryptographyProvider cryptography,
    MarketplaceLicensingOptions options,
    MarketplaceLicensingMutationGate mutationGate,
    TimeProvider timeProvider)
{
    public const string ContentKeyOperation = "content_key";
    public const string HeartbeatOperation = "heartbeat";
    public const string DownloadGrantOperation = "download_grant";
    public const string SignalSessionOperation = "signal_session";

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public async Task<DeviceProofChallengeResponse> IssueChallengeAsync(
        Guid accountId,
        DeviceProofChallengeRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        ValidateIdentifiers(request.DeviceId, request.LicenseId, request.ReleaseId);
        ValidateIdempotencyKey(idempotencyKey);
        var operation = NormalizeOperation(request.Operation);
        var binding = NormalizeSha256(request.BindingSha256, "binding_sha256");
        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(
            new ChallengeRequestFingerprint(
                request.DeviceId,
                request.LicenseId,
                request.ReleaseId,
                operation,
                binding),
            SerializerOptions);
        var requestSha256 = Convert.ToHexString(SHA256.HashData(requestBytes)).ToLowerInvariant();

        await using var gate = await mutationGate.EnterAsync(
            $"challenge:{accountId:D}:{operation}:{idempotencyKey}",
            cancellationToken);
        var existing = await database.DeviceProofChallenges.SingleOrDefaultAsync(
            item => item.AccountId == accountId
                && item.Operation == operation
                && item.IdempotencyKey == idempotencyKey,
            cancellationToken);
        if (existing is not null)
        {
            if (!string.Equals(existing.RequestSha256, requestSha256, StringComparison.Ordinal))
            {
                throw new PlatformConflictException(
                    "The idempotency key was already used for a different device challenge.");
            }

            return ToChallengeResponse(existing);
        }

        var device = await RequireProofDeviceAsync(
            accountId,
            request.DeviceId,
            cancellationToken);
        _ = device;
        var licenseExists = await database.MarketplaceLicenses.AsNoTracking().AnyAsync(
            item => item.Id == request.LicenseId
                && item.AccountId == accountId
                && item.ReleaseId == request.ReleaseId,
            cancellationToken);
        if (!licenseExists)
        {
            throw new PlatformNotFoundException("Marketplace license not found.");
        }

        var now = timeProvider.GetUtcNow();
        var challenge = new DeviceProofChallenge
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            LicenseId = request.LicenseId,
            ReleaseId = request.ReleaseId,
            DeviceId = request.DeviceId,
            Operation = operation,
            BindingSha256 = binding,
            Nonce = MarketplaceCryptographyEncoding.Encode(RandomNumberGenerator.GetBytes(32)),
            IdempotencyKey = idempotencyKey,
            RequestSha256 = requestSha256,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(options.ChallengeTtlSeconds),
        };
        database.DeviceProofChallenges.Add(challenge);
        try
        {
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            database.ChangeTracker.Clear();
            var raced = await database.DeviceProofChallenges.AsNoTracking().SingleOrDefaultAsync(
                item => item.AccountId == accountId
                    && item.Operation == operation
                    && item.IdempotencyKey == idempotencyKey,
                cancellationToken);
            if (raced is not null
                && string.Equals(raced.RequestSha256, requestSha256, StringComparison.Ordinal))
            {
                return ToChallengeResponse(raced);
            }

            throw;
        }

        return ToChallengeResponse(challenge);
    }

    public async Task<ContentKeyReleaseResponse> ReleaseContentKeyAsync(
        Guid accountId,
        Guid licenseId,
        ContentKeyReleaseRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        ValidateIdentifiers(request.DeviceId, licenseId, request.ReleaseId);
        ValidateIdempotencyKey(idempotencyKey);
        var sessionPublicKey = DecodeBase64Url(
            request.SessionPublicKey,
            "session_public_key");
        ValidateP256EcdhPublicKey(sessionPublicKey);
        var binding = Convert.ToHexString(SHA256.HashData(sessionPublicKey)).ToLowerInvariant();

        await using var gate = await mutationGate.EnterAsync(
            $"proof:{request.ChallengeId:D}",
            cancellationToken);
        var live = await RequireLiveLicenseAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            cancellationToken);
        var device = await RequireProofDeviceAsync(
            accountId,
            request.DeviceId,
            cancellationToken);
        var challenge = await RequireChallengeAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            request.DeviceId,
            request.ChallengeId,
            ContentKeyOperation,
            binding,
            idempotencyKey,
            cancellationToken);
        if (challenge.ResponseJson is not null)
        {
            return DeserializeStoredResponse<ContentKeyReleaseResponse>(challenge.ResponseJson);
        }

        VerifyDeviceProof(device, challenge, request.DeviceSignature);
        var contentKeyId = NormalizeContentKeyId(live.Release.ContentKeyId);
        var contentKeyRecord = await database.ContentKeys.AsNoTracking().SingleOrDefaultAsync(
            item => item.ReleaseId == request.ReleaseId
                && item.ContentKeyId == contentKeyId,
            cancellationToken)
            ?? throw new PlatformConflictException(
                "The release does not have a provisioned content key.");

        byte[]? contentKey = null;
        byte[]? sharedSecret = null;
        byte[]? sessionWrappingKey = null;
        try
        {
            contentKey = await cryptography.UnwrapContentKeyAsync(
                contentKeyRecord.Algorithm,
                contentKeyRecord.KmsWrappedKey,
                cancellationToken);
            if (contentKey.Length != 32)
            {
                throw new CryptographicException(
                    "The unwrapped DAXQ content key must contain exactly 32 bytes.");
            }

            using var clientEphemeral = ECDiffieHellman.Create();
            clientEphemeral.ImportSubjectPublicKeyInfo(sessionPublicKey, out var bytesRead);
            if (bytesRead != sessionPublicKey.Length)
            {
                throw new PlatformValidationException(
                    "The session public key contains trailing data.");
            }

            using var serverEphemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            sharedSecret = serverEphemeral.DeriveRawSecretAgreement(clientEphemeral.PublicKey);
            var kdfInfo = Encoding.UTF8.GetBytes(
                $"DAXQ-CONTENT-KEY-V1|{licenseId:D}|{request.ReleaseId:D}|{request.DeviceId:D}|{contentKeyRecord.ContentKeyId}");
            sessionWrappingKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                sharedSecret,
                32,
                DecodeBase64Url(challenge.Nonce, "challenge nonce"),
                kdfInfo);
            var wrappedForSession = AesKeyWrap.Wrap(sessionWrappingKey, contentKey);

            live = await RequireLiveLicenseAsync(
                accountId,
                licenseId,
                request.ReleaseId,
                cancellationToken);
            var issued = await IssueRunTokensAsync(live, request.DeviceId, cancellationToken);
            var ttlSeconds = BoundTtlSeconds(options.ContentKeyTtlSeconds, live.AccessValidUntil);
            var response = new ContentKeyReleaseResponse(
                MarketplaceCryptographyEncoding.Encode(wrappedForSession),
                SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
                "A256GCM",
                contentKeyRecord.ContentKeyId,
                ttlSeconds,
                MarketplaceCryptographyEncoding.Encode(
                    serverEphemeral.ExportSubjectPublicKeyInfo()),
                issued.RunToken,
                issued.OfflineLease);

            database.ContentKeyReleases.Add(new ContentKeyReleaseAudit
            {
                Id = Guid.NewGuid(),
                ChallengeId = challenge.Id,
                LicenseId = licenseId,
                AccountId = accountId,
                DeviceId = request.DeviceId,
                ReleaseId = request.ReleaseId,
                ReleasedAt = timeProvider.GetUtcNow(),
                SessionPublicKeySha256 = binding,
                TtlSeconds = ttlSeconds,
            });
            challenge.ConsumedAt = timeProvider.GetUtcNow();
            challenge.ResponseJson = JsonSerializer.Serialize(response, SerializerOptions);
            challenge.Version++;
            try
            {
                await database.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException)
            {
                database.ChangeTracker.Clear();
                var stored = await database.DeviceProofChallenges.AsNoTracking()
                    .Where(item => item.Id == challenge.Id)
                    .Select(item => item.ResponseJson)
                    .SingleOrDefaultAsync(cancellationToken);
                if (stored is not null)
                {
                    return DeserializeStoredResponse<ContentKeyReleaseResponse>(stored);
                }

                throw;
            }

            return response;
        }
        finally
        {
            if (contentKey is not null)
            {
                CryptographicOperations.ZeroMemory(contentKey);
            }

            if (sharedSecret is not null)
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }

            if (sessionWrappingKey is not null)
            {
                CryptographicOperations.ZeroMemory(sessionWrappingKey);
            }

            CryptographicOperations.ZeroMemory(sessionPublicKey);
        }
    }

    public async Task<MarketplaceHeartbeatResponse> HeartbeatAsync(
        Guid accountId,
        Guid licenseId,
        MarketplaceHeartbeatRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        ValidateIdentifiers(request.DeviceId, licenseId, request.ReleaseId);
        ValidateIdempotencyKey(idempotencyKey);
        var bindingBytes = Encoding.UTF8.GetBytes(
            request.RunToken.EncodedPayload + "." + request.RunToken.EncodedSignature);
        var binding = Convert.ToHexString(SHA256.HashData(bindingBytes)).ToLowerInvariant();

        await using var gate = await mutationGate.EnterAsync(
            $"proof:{request.ChallengeId:D}",
            cancellationToken);
        var live = await RequireLiveLicenseAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            cancellationToken);
        var device = await RequireProofDeviceAsync(
            accountId,
            request.DeviceId,
            cancellationToken);
        var challenge = await RequireChallengeAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            request.DeviceId,
            request.ChallengeId,
            HeartbeatOperation,
            binding,
            idempotencyKey,
            cancellationToken);
        if (challenge.ResponseJson is not null)
        {
            return DeserializeStoredResponse<MarketplaceHeartbeatResponse>(challenge.ResponseJson);
        }

        VerifyDeviceProof(device, challenge, request.DeviceSignature);
        await VerifyRunTokenAsync(
            request.RunToken,
            accountId,
            licenseId,
            request.ReleaseId,
            request.DeviceId,
            cancellationToken);
        live = await RequireLiveLicenseAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            cancellationToken);
        var issued = await IssueRunTokensAsync(live, request.DeviceId, cancellationToken);
        var ttlSeconds = checked((int)Math.Floor(
            (issued.RunToken.ExpiresAt - issued.RunToken.IssuedAt).TotalSeconds));
        var response = new MarketplaceHeartbeatResponse(
            ttlSeconds,
            issued.RunToken,
            issued.OfflineLease);
        challenge.ConsumedAt = timeProvider.GetUtcNow();
        challenge.ResponseJson = JsonSerializer.Serialize(response, SerializerOptions);
        challenge.Version++;
        try
        {
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            database.ChangeTracker.Clear();
            var stored = await database.DeviceProofChallenges.AsNoTracking()
                .Where(item => item.Id == challenge.Id)
                .Select(item => item.ResponseJson)
                .SingleOrDefaultAsync(cancellationToken);
            if (stored is not null)
            {
                return DeserializeStoredResponse<MarketplaceHeartbeatResponse>(stored);
            }

            throw;
        }

        return response;
    }

    public async Task<DownloadGrantResponse> GetDownloadGrantAsync(
        Guid accountId,
        Guid releaseId,
        Guid licenseId,
        Guid deviceId,
        Guid challengeId,
        string deviceSignature,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        ValidateIdentifiers(deviceId, licenseId, releaseId);
        ValidateIdempotencyKey(idempotencyKey);
        await using var gate = await mutationGate.EnterAsync(
            $"proof:{challengeId:D}",
            cancellationToken);
        var live = await RequireLiveLicenseAsync(
            accountId,
            licenseId,
            releaseId,
            cancellationToken);
        var device = await RequireProofDeviceAsync(accountId, deviceId, cancellationToken);
        var binding = NormalizeSha256(live.Release.CipherSha256, "cipher_sha256");
        var challenge = await RequireChallengeAsync(
            accountId,
            licenseId,
            releaseId,
            deviceId,
            challengeId,
            DownloadGrantOperation,
            binding,
            idempotencyKey,
            cancellationToken);
        if (challenge.ResponseJson is not null)
        {
            return DeserializeStoredResponse<DownloadGrantResponse>(challenge.ResponseJson);
        }

        VerifyDeviceProof(device, challenge, deviceSignature);
        live = await RequireLiveLicenseAsync(
            accountId,
            licenseId,
            releaseId,
            cancellationToken);
        var issuedAt = timeProvider.GetUtcNow();
        var expiresAt = Minimum(
            issuedAt.AddSeconds(options.DownloadGrantTtlSeconds),
            live.AccessValidUntil);
        if (expiresAt <= issuedAt)
        {
            throw new PlatformForbiddenException("The marketplace license has expired.");
        }

        var claims = new DownloadGrantClaims(
            1,
            Guid.NewGuid().ToString("N"),
            licenseId,
            releaseId,
            accountId,
            deviceId,
            live.Release.CipherSha256,
            issuedAt,
            expiresAt);
        var signature = await cryptography.SignAsync(
            JsonSerializer.SerializeToUtf8Bytes(claims, SerializerOptions),
            cancellationToken);
        var artifactUri = RequireArtifactUri(live.Release.ArtifactBlobUri);
        var separator = string.IsNullOrEmpty(artifactUri.Query) ? "?" : "&";
        var downloadUrl = artifactUri.AbsoluteUri
            + separator
            + "daxq_payload=" + Uri.EscapeDataString(signature.EncodedPayload)
            + "&daxq_signature=" + Uri.EscapeDataString(signature.EncodedSignature)
            + "&daxq_key_id=" + Uri.EscapeDataString(signature.KeyId);
        var response = new DownloadGrantResponse(
            downloadUrl,
            expiresAt,
            live.Release.CipherSha256);
        challenge.ConsumedAt = timeProvider.GetUtcNow();
        challenge.ResponseJson = JsonSerializer.Serialize(response, SerializerOptions);
        challenge.Version++;
        try
        {
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            database.ChangeTracker.Clear();
            var stored = await database.DeviceProofChallenges.AsNoTracking()
                .Where(item => item.Id == challenge.Id)
                .Select(item => item.ResponseJson)
                .SingleOrDefaultAsync(cancellationToken);
            if (stored is not null)
            {
                return DeserializeStoredResponse<DownloadGrantResponse>(stored);
            }

            throw;
        }

        return response;
    }

    public async Task<SignedRevocationFeed> GetRevocationFeedAsync(
        long afterSequence,
        CancellationToken cancellationToken)
    {
        if (afterSequence < 0)
        {
            throw new PlatformValidationException("after_seq cannot be negative.");
        }

        var latestSequence = await database.Revocations.AsNoTracking()
            .OrderByDescending(item => item.Sequence)
            .Select(item => item.Sequence)
            .FirstOrDefaultAsync(cancellationToken);
        if (afterSequence > latestSequence)
        {
            throw new PlatformConflictException(
                "The requested revocation cursor is ahead of this server; reject the stale feed.");
        }

        var revocations = await database.Revocations.AsNoTracking()
            .Where(item => item.Sequence > afterSequence)
            .OrderBy(item => item.Sequence)
            .Take(1000)
            .Select(item => new RevocationFeedItem(
                item.Sequence,
                item.TargetType,
                item.TargetId,
                item.Reason,
                item.IssuedAt))
            .ToListAsync(cancellationToken);
        var throughSequence = revocations.Count == 0
            ? latestSequence
            : revocations[^1].Sequence;
        var claims = new RevocationFeedClaims(
            1,
            afterSequence,
            throughSequence,
            timeProvider.GetUtcNow(),
            revocations);
        var signature = await cryptography.SignAsync(
            JsonSerializer.SerializeToUtf8Bytes(claims, SerializerOptions),
            cancellationToken);
        return new SignedRevocationFeed(
            claims.SchemaVersion,
            claims.FromSequence,
            claims.ThroughSequence,
            claims.IssuedAt,
            claims.Revocations,
            signature.KeyId,
            signature.Algorithm,
            signature.EncodedPayload,
            signature.EncodedSignature);
    }

    public async Task<MarketplaceLicenseJsonWebKeySet> GetVerificationKeysAsync(
        CancellationToken cancellationToken) =>
        new([await cryptography.GetVerificationKeyAsync(cancellationToken)]);

    internal Task<LiveLicenseContext> RequireLiveLicenseAsync(
        Guid accountId,
        Guid licenseId,
        Guid releaseId,
        CancellationToken cancellationToken) =>
        RequireLiveLicenseAsync(
            accountId,
            licenseId,
            releaseId,
            MarketplaceExecutionClasses.RestrictedOnly,
            cancellationToken);

    internal async Task<LiveLicenseContext> RequireLiveLicenseAsync(
        Guid accountId,
        Guid licenseId,
        Guid releaseId,
        string expectedExecutionClass,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var license = await database.MarketplaceLicenses.AsNoTracking().SingleOrDefaultAsync(
            item => item.Id == licenseId
                && item.AccountId == accountId
                && item.ReleaseId == releaseId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Marketplace license not found.");
        if (license.Status != MarketplaceLicenseStatus.Active
            || license.RevokedAt is not null
            || license.ValidFrom > now
            || license.ValidUntil <= now)
        {
            throw new PlatformForbiddenException("The marketplace license is not active.");
        }

        var grant = await database.EntitlementGrants.AsNoTracking().SingleOrDefaultAsync(
            item => item.Id == license.GrantId
                && item.AccountId == accountId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Marketplace entitlement grant not found.");
        if (grant.Status != EntitlementGrantStatus.Active
            || grant.RevokedAt is not null
            || grant.ValidFrom > now
            || grant.ValidUntil <= now)
        {
            throw new PlatformForbiddenException("The marketplace entitlement grant is not active.");
        }

        var release = await database.StrategyReleases.AsNoTracking().SingleOrDefaultAsync(
            item => item.Id == releaseId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Strategy release not found.");
        if (release.Status != MarketplaceReleaseStatus.Approved
            || !string.Equals(
                release.ExecutionClass,
                expectedExecutionClass,
                StringComparison.Ordinal))
        {
            throw new PlatformForbiddenException(
                $"The marketplace release is not approved for '{expectedExecutionClass}' execution.");
        }
        var accountTarget = accountId.ToString("D");
        var licenseTarget = licenseId.ToString("D");
        var releaseTarget = releaseId.ToString("D");
        var revoked = await database.Revocations.AsNoTracking().AnyAsync(
            item => (item.TargetType == "account" && item.TargetId == accountTarget)
                || (item.TargetType == "license" && item.TargetId == licenseTarget)
                || (item.TargetType == "release" && item.TargetId == releaseTarget),
            cancellationToken);
        if (revoked)
        {
            throw new PlatformForbiddenException(
                "The account, license, or strategy release has been revoked.");
        }

        return new LiveLicenseContext(
            license,
            release,
            Minimum(license.ValidUntil, grant.ValidUntil));
    }

    internal async Task<RegisteredDevice> RequireProofDeviceAsync(
        Guid accountId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var device = await devices.RequireActiveAsync(accountId, deviceId, cancellationToken);
        if (string.IsNullOrWhiteSpace(device.PublicKeySpki)
            || string.IsNullOrWhiteSpace(device.FingerprintSha256))
        {
            throw new PlatformForbiddenException(
                "The active device must register a P-256 proof key before DAXQ licensing.");
        }

        return device;
    }

    internal async Task<DeviceProofChallenge> RequireChallengeAsync(
        Guid accountId,
        Guid licenseId,
        Guid releaseId,
        Guid deviceId,
        Guid challengeId,
        string operation,
        string bindingSha256,
        string idempotencyKey,
        CancellationToken cancellationToken)
    {
        var challenge = await database.DeviceProofChallenges.SingleOrDefaultAsync(
            item => item.Id == challengeId
                && item.AccountId == accountId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Device-proof challenge not found.");
        if (challenge.LicenseId != licenseId
            || challenge.ReleaseId != releaseId
            || challenge.DeviceId != deviceId
            || !string.Equals(challenge.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(challenge.BindingSha256, bindingSha256, StringComparison.Ordinal)
            || !string.Equals(challenge.IdempotencyKey, idempotencyKey, StringComparison.Ordinal))
        {
            throw new PlatformConflictException(
                "The device-proof challenge does not match this request.");
        }

        if (challenge.ResponseJson is not null)
        {
            return challenge;
        }

        if (challenge.ConsumedAt is not null)
        {
            throw new PlatformConflictException("The device-proof challenge has already been consumed.");
        }

        if (challenge.ExpiresAt <= timeProvider.GetUtcNow())
        {
            throw new PlatformForbiddenException("The device-proof challenge has expired.");
        }

        return challenge;
    }

    internal static void VerifyDeviceProof(
        RegisteredDevice device,
        DeviceProofChallenge challenge,
        string encodedSignature)
    {
        var publicKey = DecodeBase64Url(device.PublicKeySpki!, "registered device public key");
        var signature = DecodeBase64Url(encodedSignature, "device_signature");
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new DeviceProofPayload(
                1,
                challenge.Operation,
                challenge.Id,
                challenge.Nonce,
                challenge.LicenseId,
                challenge.ReleaseId,
                challenge.DeviceId,
                challenge.BindingSha256,
                challenge.IdempotencyKey),
            SerializerOptions);
        try
        {
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
            if (bytesRead != publicKey.Length
                || !verifier.VerifyData(
                    payload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new PlatformForbiddenException("The device proof is invalid.");
            }
        }
        catch (CryptographicException)
        {
            throw new PlatformForbiddenException("The device proof is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private async Task<(MarketplaceSignedToken RunToken, MarketplaceSignedToken? OfflineLease)>
        IssueRunTokensAsync(
            LiveLicenseContext live,
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var issuedAt = timeProvider.GetUtcNow();
        var revocationSequence = await GetLatestRevocationSequenceAsync(cancellationToken);
        var runToken = await IssueTokenAsync(
            "run_token",
            live,
            deviceId,
            issuedAt,
            Minimum(issuedAt.AddMinutes(options.RunTokenTtlMinutes), live.AccessValidUntil),
            revocationSequence,
            cancellationToken);
        MarketplaceSignedToken? offlineLease = null;
        if (options.OfflineGraceHours > 0)
        {
            offlineLease = await IssueTokenAsync(
                "offline_lease",
                live,
                deviceId,
                issuedAt,
                Minimum(issuedAt.AddHours(options.OfflineGraceHours), live.AccessValidUntil),
                revocationSequence,
                cancellationToken);
        }

        return (runToken, offlineLease);
    }

    private async Task<MarketplaceSignedToken> IssueTokenAsync(
        string tokenKind,
        LiveLicenseContext live,
        Guid deviceId,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        long revocationSequence,
        CancellationToken cancellationToken)
    {
        if (expiresAt <= issuedAt)
        {
            throw new PlatformForbiddenException("The marketplace access window has expired.");
        }

        var claims = new MarketplaceTokenClaims(
            1,
            tokenKind,
            Guid.NewGuid().ToString("N"),
            live.License.Id,
            live.Release.Id,
            live.License.AccountId,
            deviceId,
            options.Issuer.Trim(),
            options.Audience.Trim(),
            issuedAt,
            expiresAt,
            live.AccessValidUntil,
            revocationSequence);
        var signature = await cryptography.SignAsync(
            JsonSerializer.SerializeToUtf8Bytes(claims, SerializerOptions),
            cancellationToken);
        return new MarketplaceSignedToken(
            claims.SchemaVersion,
            claims.TokenKind,
            claims.TokenId,
            claims.LicenseId,
            claims.ReleaseId,
            claims.AccountId,
            claims.DeviceId,
            claims.Issuer,
            claims.Audience,
            claims.IssuedAt,
            claims.ExpiresAt,
            claims.AccessValidUntil,
            claims.RevocationSequence,
            signature.KeyId,
            signature.Algorithm,
            signature.EncodedPayload,
            signature.EncodedSignature);
    }

    private async Task VerifyRunTokenAsync(
        MarketplaceSignedEnvelope token,
        Guid accountId,
        Guid licenseId,
        Guid releaseId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(token.Algorithm, "ES256", StringComparison.Ordinal))
        {
            throw new PlatformForbiddenException("The run-token algorithm is invalid.");
        }

        var verificationKey = await cryptography.GetVerificationKeyAsync(cancellationToken);
        if (!string.Equals(token.KeyId, verificationKey.KeyId, StringComparison.Ordinal))
        {
            throw new PlatformForbiddenException("The run-token signing key is not trusted.");
        }

        var payload = DecodeBase64Url(token.EncodedPayload, "run-token payload");
        var signature = DecodeBase64Url(token.EncodedSignature, "run-token signature");
        try
        {
            using var verifier = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = MarketplaceCryptographyEncoding.Decode(verificationKey.X),
                    Y = MarketplaceCryptographyEncoding.Decode(verificationKey.Y),
                },
            });
            if (!verifier.VerifyData(
                    payload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new PlatformForbiddenException("The run-token signature is invalid.");
            }

            var claims = JsonSerializer.Deserialize<MarketplaceTokenClaims>(payload, SerializerOptions)
                ?? throw new PlatformForbiddenException("The run-token payload is invalid.");
            if (claims.SchemaVersion != 1
                || !string.Equals(claims.TokenKind, "run_token", StringComparison.Ordinal)
                || claims.AccountId != accountId
                || claims.LicenseId != licenseId
                || claims.ReleaseId != releaseId
                || claims.DeviceId != deviceId
                || !string.Equals(claims.Issuer, options.Issuer.Trim(), StringComparison.Ordinal)
                || !string.Equals(claims.Audience, options.Audience.Trim(), StringComparison.Ordinal)
                || claims.AccessValidUntil < claims.ExpiresAt)
            {
                throw new PlatformForbiddenException("The run-token claims are invalid.");
            }
        }
        catch (JsonException)
        {
            throw new PlatformForbiddenException("The run-token payload is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private async Task<long> GetLatestRevocationSequenceAsync(CancellationToken cancellationToken) =>
        await database.Revocations.AsNoTracking()
            .OrderByDescending(item => item.Sequence)
            .Select(item => item.Sequence)
            .FirstOrDefaultAsync(cancellationToken);

    private int BoundTtlSeconds(int configuredSeconds, DateTimeOffset accessValidUntil)
    {
        var remaining = Math.Floor((accessValidUntil - timeProvider.GetUtcNow()).TotalSeconds);
        if (remaining < 1)
        {
            throw new PlatformForbiddenException("The marketplace access window has expired.");
        }

        return checked((int)Math.Min(configuredSeconds, remaining));
    }

    private static Uri RequireArtifactUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new PlatformConflictException(
                "The strategy release does not have a valid artifact blob URI.");
        }

        return uri;
    }

    private static string NormalizeContentKeyId(string? value)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length > 128
            || !char.IsAsciiLetterOrDigit(value[0])
            || value.Skip(1).Any(character =>
                !(char.IsAsciiLetterOrDigit(character)
                    || character is '.' or '_' or ':' or '-')))
        {
            throw new PlatformConflictException(
                "The release content-key identifier does not satisfy the frozen DAXQ v1 contract.");
        }

        return value;
    }

    private static DeviceProofChallengeResponse ToChallengeResponse(DeviceProofChallenge challenge) =>
        new(challenge.Id, challenge.Nonce, challenge.ExpiresAt);

    private static T DeserializeStoredResponse<T>(string responseJson) =>
        JsonSerializer.Deserialize<T>(responseJson, SerializerOptions)
        ?? throw new InvalidOperationException("The stored idempotent response is invalid.");

    private static string NormalizeOperation(string value)
    {
        var operation = value?.Trim();
        return operation switch
        {
            ContentKeyOperation => ContentKeyOperation,
            HeartbeatOperation => HeartbeatOperation,
            DownloadGrantOperation => DownloadGrantOperation,
            SignalSessionOperation => SignalSessionOperation,
            _ => throw new PlatformValidationException(
                "operation must be content_key, heartbeat, download_grant, or signal_session."),
        };
    }

    internal static string NormalizeSha256(string value, string label)
    {
        var normalized = value?.Trim().ToLowerInvariant();
        if (normalized is null
            || normalized.Length != 64
            || normalized.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new PlatformValidationException(
                $"{label} must contain exactly 64 hexadecimal characters.");
        }

        return normalized;
    }

    internal static void ValidateIdempotencyKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 100
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || value.Any(character => character is < '!' or > '~'))
        {
            throw new PlatformValidationException(
                "Idempotency-Key must contain 1 to 100 printable ASCII characters without spaces.");
        }
    }

    internal static void ValidateIdentifiers(Guid deviceId, Guid licenseId, Guid releaseId)
    {
        if (deviceId == Guid.Empty || licenseId == Guid.Empty || releaseId == Guid.Empty)
        {
            throw new PlatformValidationException(
                "device_id, license_id, and release_id must be non-empty UUIDs.");
        }
    }

    internal static byte[] DecodeBase64Url(string value, string label)
    {
        try
        {
            return MarketplaceCryptographyEncoding.Decode(value);
        }
        catch (Exception exception) when (
            exception is ArgumentException or FormatException)
        {
            throw new PlatformValidationException($"{label} must be base64url encoded.");
        }
    }

    private static void ValidateP256EcdhPublicKey(byte[] encodedKey)
    {
        try
        {
            using var key = ECDiffieHellman.Create();
            key.ImportSubjectPublicKeyInfo(encodedKey, out var bytesRead);
            var parameters = key.ExportParameters(includePrivateParameters: false);
            if (bytesRead != encodedKey.Length
                || parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value
                || parameters.Q.X is not { Length: 32 }
                || parameters.Q.Y is not { Length: 32 })
            {
                throw new CryptographicException();
            }
        }
        catch (CryptographicException)
        {
            throw new PlatformValidationException(
                "session_public_key must be a P-256 SubjectPublicKeyInfo value.");
        }
    }

    private static DateTimeOffset Minimum(DateTimeOffset first, DateTimeOffset second) =>
        first <= second ? first : second;

    internal sealed record LiveLicenseContext(
        MarketplaceLicense License,
        MarketplaceStrategyRelease Release,
        DateTimeOffset AccessValidUntil);
}

public sealed class MarketplaceLicensingMutationGate
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> gates = new(StringComparer.Ordinal);

    public async ValueTask<IAsyncDisposable> EnterAsync(
        string key,
        CancellationToken cancellationToken)
    {
        var gate = gates.GetOrAdd(key, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        return new Releaser(gate);
    }

    private sealed class Releaser(SemaphoreSlim gate) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            gate.Release();
            return ValueTask.CompletedTask;
        }
    }
}
