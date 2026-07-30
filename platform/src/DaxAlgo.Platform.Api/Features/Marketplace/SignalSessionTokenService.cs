using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class SignalSessionTokenService : IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly SignalExecutionOptions options;
    private readonly TimeProvider timeProvider;
    private readonly byte[] key;

    public SignalSessionTokenService(
        SignalExecutionOptions options,
        IHostEnvironment environment,
        TimeProvider timeProvider)
    {
        this.options = options;
        this.timeProvider = timeProvider;
        if (string.IsNullOrWhiteSpace(options.SessionTokenKey))
        {
            if (!string.Equals(options.Provider, "Disabled", StringComparison.OrdinalIgnoreCase)
                && !environment.IsDevelopment()
                && !environment.IsEnvironment("Testing"))
            {
                throw new InvalidOperationException(
                    "SignalExecution:SessionTokenKey is required outside Development and Testing.");
            }

            key = RandomNumberGenerator.GetBytes(32);
        }
        else
        {
            try
            {
                key = MarketplaceCryptographyEncoding.Decode(options.SessionTokenKey.Trim());
            }
            catch (Exception exception) when (exception is ArgumentException or FormatException)
            {
                throw new InvalidOperationException(
                    "SignalExecution:SessionTokenKey must be base64url encoded.",
                    exception);
            }

            if (key.Length < 32)
            {
                throw new InvalidOperationException(
                    "SignalExecution:SessionTokenKey must contain at least 32 bytes.");
            }
        }
    }

    public (string Token, DateTimeOffset ExpiresAt) Issue(
        MarketplaceSignalSession session,
        DateTimeOffset accessValidUntil)
    {
        var issuedAt = timeProvider.GetUtcNow();
        var expiresAt = issuedAt.AddSeconds(options.SessionTokenTtlSeconds);
        if (accessValidUntil < expiresAt)
        {
            expiresAt = accessValidUntil;
        }

        if (expiresAt <= issuedAt)
        {
            throw new PlatformForbiddenException("The marketplace access window has expired.");
        }

        var claims = new SignalSessionTokenClaims(
            1,
            session.Id,
            session.LicenseId,
            session.AccountId,
            session.DeviceId,
            session.ReleaseId,
            options.TokenIssuer.Trim(),
            options.TokenAudience.Trim(),
            issuedAt,
            expiresAt);
        var payload = JsonSerializer.SerializeToUtf8Bytes(claims, SerializerOptions);
        var encodedPayload = MarketplaceCryptographyEncoding.Encode(payload);
        var signature = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(encodedPayload));
        return ($"{encodedPayload}.{MarketplaceCryptographyEncoding.Encode(signature)}", expiresAt);
    }

    internal SignalSessionTokenClaims Validate(string token, bool allowExpired = false)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 4096)
        {
            throw new PlatformForbiddenException("The signal-session token is invalid.");
        }

        var segments = token.Split('.');
        if (segments.Length != 2 || segments.Any(string.IsNullOrEmpty))
        {
            throw new PlatformForbiddenException("The signal-session token is invalid.");
        }

        byte[] payload;
        byte[] signature;
        try
        {
            payload = MarketplaceCryptographyEncoding.Decode(segments[0]);
            signature = MarketplaceCryptographyEncoding.Decode(segments[1]);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new PlatformForbiddenException("The signal-session token is invalid.");
        }

        try
        {
            var expected = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(segments[0]));
            if (signature.Length != expected.Length
                || !CryptographicOperations.FixedTimeEquals(signature, expected))
            {
                throw new PlatformForbiddenException("The signal-session token is invalid.");
            }

            SignalSessionTokenClaims claims;
            try
            {
                claims = JsonSerializer.Deserialize<SignalSessionTokenClaims>(payload, SerializerOptions)
                    ?? throw new PlatformForbiddenException("The signal-session token is invalid.");
            }
            catch (JsonException)
            {
                throw new PlatformForbiddenException("The signal-session token is invalid.");
            }

            if (claims.SchemaVersion != 1
                || claims.SessionId == Guid.Empty
                || claims.LicenseId == Guid.Empty
                || claims.AccountId == Guid.Empty
                || claims.DeviceId == Guid.Empty
                || claims.ReleaseId == Guid.Empty
                || !string.Equals(claims.Issuer, options.TokenIssuer.Trim(), StringComparison.Ordinal)
                || !string.Equals(claims.Audience, options.TokenAudience.Trim(), StringComparison.Ordinal)
                || claims.IssuedAt > timeProvider.GetUtcNow().AddSeconds(30)
                || (!allowExpired && claims.ExpiresAt <= timeProvider.GetUtcNow()))
            {
                throw new PlatformForbiddenException("The signal-session token is invalid or expired.");
            }

            return claims;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(key);
}
