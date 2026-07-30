using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;

namespace DaxAlgo.Platform.Providers;

public sealed class GoogleManagedIdentityProvider : IManagedIdentityProvider, IDisposable
{
    public const string HttpClientName = "GoogleIdentityJwks";
    public const string ValidatedIdentityClaim = "daxalgo:google_identity_validated";

    private const string GoogleIssuer = "https://accounts.google.com";
    private const string GoogleJwksUri = "https://www.googleapis.com/oauth2/v3/certs";
    private const string Rs256Algorithm = "RS256";
    private const int MaximumTokenLength = 32 * 1024;
    private const int MaximumJwksLength = 1024 * 1024;
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan UnknownKeyRefreshInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan FailedRefreshRetryInterval = TimeSpan.FromSeconds(10);

    private readonly IHttpClientFactory httpClientFactory;
    private readonly TimeProvider timeProvider;
    private readonly HashSet<string> allowedAudiences;
    private readonly SemaphoreSlim refreshGate = new(1, 1);
    private readonly Lock cacheLock = new();
    private IReadOnlyDictionary<string, GoogleJsonWebKey> cachedKeys =
        new Dictionary<string, GoogleJsonWebKey>(StringComparer.Ordinal);
    private DateTimeOffset cacheExpiresAt = DateTimeOffset.MinValue;
    private DateTimeOffset nextUnknownKeyRefreshAt = DateTimeOffset.MinValue;
    private DateTimeOffset nextFailedRefreshAttemptAt = DateTimeOffset.MinValue;

    public GoogleManagedIdentityProvider(
        IHttpClientFactory httpClientFactory,
        GoogleAuthOptions options,
        TimeProvider timeProvider)
    {
        this.httpClientFactory = httpClientFactory;
        this.timeProvider = timeProvider;
        allowedAudiences = GoogleAuthValidation.GetAllowedAudiences(options);
    }

    public ManagedIdentity Resolve(ClaimsPrincipal principal)
    {
        var identity = principal.Identities.SingleOrDefault(candidate =>
            candidate.IsAuthenticated
            && string.Equals(
                candidate.AuthenticationType,
                GoogleAuthenticationHandler.SchemeName,
                StringComparison.Ordinal));
        if (identity is null
            || !string.Equals(
                identity.FindFirst(ValidatedIdentityClaim)?.Value,
                bool.TrueString,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("A validated Google identity is required.");
        }

        var subject = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = identity.FindFirst(ClaimTypes.Email)?.Value;
        var name = identity.FindFirst(ClaimTypes.Name)?.Value;
        if (string.IsNullOrWhiteSpace(subject)
            || string.IsNullOrWhiteSpace(email)
            || string.IsNullOrWhiteSpace(name))
        {
            throw new UnauthorizedAccessException("The Google identity is incomplete.");
        }

        return new ManagedIdentity(subject, email, name);
    }

    public async Task<ManagedIdentity> ValidateAsync(
        string idToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(idToken) || idToken.Length > MaximumTokenLength)
        {
            throw InvalidToken();
        }

        var segments = idToken.Split('.');
        if (segments.Length != 3 || segments.Any(string.IsNullOrWhiteSpace))
        {
            throw InvalidToken();
        }

        JsonDocument header;
        JsonDocument payload;
        byte[] signature;
        try
        {
            header = JsonDocument.Parse(DecodeBase64Url(segments[0]));
            payload = JsonDocument.Parse(DecodeBase64Url(segments[1]));
            signature = DecodeBase64Url(segments[2]);
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            throw InvalidToken(exception);
        }

        using (header)
        using (payload)
        {
            if (header.RootElement.ValueKind != JsonValueKind.Object
                || payload.RootElement.ValueKind != JsonValueKind.Object
                || !TryGetRequiredString(header.RootElement, "alg", out var algorithm)
                || !string.Equals(algorithm, Rs256Algorithm, StringComparison.Ordinal)
                || !TryGetRequiredString(header.RootElement, "kid", out var keyId))
            {
                throw InvalidToken();
            }

            var key = await GetSigningKeyAsync(keyId, cancellationToken);
            var signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{segments[1]}");
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = key.Modulus,
                Exponent = key.Exponent,
            });
            if (!rsa.VerifyData(
                    signingInput,
                    signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1))
            {
                throw InvalidToken();
            }

            return ValidateClaims(payload.RootElement);
        }
    }

    public void Dispose()
    {
        refreshGate.Dispose();
    }

    private ManagedIdentity ValidateClaims(JsonElement claims)
    {
        if (!TryGetRequiredString(claims, "iss", out var issuer)
            || !string.Equals(issuer, GoogleIssuer, StringComparison.Ordinal)
            || !HasValidAudienceAndAuthorizedParty(claims)
            || !TryGetNumericDate(claims, "exp", out var expiresAt))
        {
            throw InvalidToken();
        }

        var now = timeProvider.GetUtcNow();
        if (now > expiresAt.Add(ClockSkew)
            || (TryGetNumericDate(claims, "nbf", out var notBefore)
                && now.Add(ClockSkew) < notBefore))
        {
            throw InvalidToken();
        }

        if (!TryGetRequiredString(claims, "sub", out var subject)
            || subject.Length > 255
            || !TryGetRequiredString(claims, "email", out var email)
            || email.Length > 320)
        {
            throw InvalidToken();
        }

        var displayName = TryGetRequiredString(claims, "name", out var name)
            ? name
            : email;
        if (displayName.Length > 120)
        {
            displayName = displayName[..120];
        }

        return new ManagedIdentity(subject, email, displayName);
    }

    private bool HasValidAudienceAndAuthorizedParty(JsonElement claims)
    {
        if (!claims.TryGetProperty("aud", out var audience))
        {
            return false;
        }

        var audienceCount = 0;
        var hasAllowedAudience = false;
        if (audience.ValueKind == JsonValueKind.String)
        {
            audienceCount = 1;
            hasAllowedAudience = allowedAudiences.Contains(audience.GetString() ?? string.Empty);
        }
        else if (audience.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in audience.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(item.GetString()))
                {
                    return false;
                }

                audienceCount++;
                hasAllowedAudience |= allowedAudiences.Contains(item.GetString()!);
            }
        }
        else
        {
            return false;
        }

        var hasAuthorizedParty = claims.TryGetProperty("azp", out var authorizedParty);
        if (audienceCount == 0
            || !hasAllowedAudience
            || (audienceCount > 1 && !hasAuthorizedParty))
        {
            return false;
        }

        return !hasAuthorizedParty
            || (authorizedParty.ValueKind == JsonValueKind.String
                && allowedAudiences.Contains(authorizedParty.GetString() ?? string.Empty));
    }

    private async Task<GoogleJsonWebKey> GetSigningKeyAsync(
        string keyId,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        if (TryGetCachedKey(keyId, now, out var key))
        {
            return key;
        }

        await refreshGate.WaitAsync(cancellationToken);
        try
        {
            now = timeProvider.GetUtcNow();
            if (TryGetCachedKey(keyId, now, out key))
            {
                return key;
            }

            if (!ReserveRefreshAttempt(now))
            {
                throw InvalidToken();
            }

            await RefreshKeysAsync(cancellationToken);
            lock (cacheLock)
            {
                if (cachedKeys.TryGetValue(keyId, out key!))
                {
                    return key;
                }

                nextUnknownKeyRefreshAt = timeProvider.GetUtcNow().Add(UnknownKeyRefreshInterval);
            }

            throw InvalidToken();
        }
        finally
        {
            refreshGate.Release();
        }
    }

    private bool ReserveRefreshAttempt(DateTimeOffset now)
    {
        lock (cacheLock)
        {
            if (cacheExpiresAt > now)
            {
                if (nextUnknownKeyRefreshAt > now)
                {
                    return false;
                }

                nextUnknownKeyRefreshAt = now.Add(UnknownKeyRefreshInterval);
                return true;
            }

            if (nextFailedRefreshAttemptAt > now)
            {
                return false;
            }

            nextFailedRefreshAttemptAt = now.Add(FailedRefreshRetryInterval);
            return true;
        }
    }

    private bool TryGetCachedKey(
        string keyId,
        DateTimeOffset now,
        out GoogleJsonWebKey key)
    {
        lock (cacheLock)
        {
            if (cacheExpiresAt > now && cachedKeys.TryGetValue(keyId, out key!))
            {
                return true;
            }
        }

        key = default!;
        return false;
    }

    private async Task RefreshKeysAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, GoogleJwksUri);
        using var response = await httpClientFactory.CreateClient(HttpClientName).SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK
            || response.Content.Headers.ContentLength > MaximumJwksLength)
        {
            throw InvalidToken();
        }

        var body = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (body.Length > MaximumJwksLength)
        {
            throw InvalidToken();
        }

        IReadOnlyDictionary<string, GoogleJsonWebKey> keys;
        try
        {
            keys = ParseKeys(body);
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            throw InvalidToken(exception);
        }

        if (keys.Count == 0)
        {
            throw InvalidToken();
        }

        var now = timeProvider.GetUtcNow();
        var maxAge = response.Headers.CacheControl?.MaxAge ?? TimeSpan.Zero;
        var age = response.Headers.Age ?? TimeSpan.Zero;
        var ttl = maxAge > age ? maxAge - age : TimeSpan.Zero;
        lock (cacheLock)
        {
            cachedKeys = keys;
            cacheExpiresAt = now.Add(ttl);
            if (nextUnknownKeyRefreshAt <= now)
            {
                nextUnknownKeyRefreshAt = now;
            }
            nextFailedRefreshAttemptAt = DateTimeOffset.MinValue;
        }
    }

    private static Dictionary<string, GoogleJsonWebKey> ParseKeys(byte[] body)
    {
        using var document = JsonDocument.Parse(body);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("keys", out var keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("The Google JWKS response is invalid.");
        }

        var keys = new Dictionary<string, GoogleJsonWebKey>(StringComparer.Ordinal);
        foreach (var element in keysElement.EnumerateArray())
        {
            if (keys.Count >= 64
                || element.ValueKind != JsonValueKind.Object
                || !TryGetRequiredString(element, "kid", out var keyId)
                || !TryGetRequiredString(element, "kty", out var keyType)
                || !string.Equals(keyType, "RSA", StringComparison.Ordinal)
                || (element.TryGetProperty("use", out var keyUse)
                    && (keyUse.ValueKind != JsonValueKind.String
                        || !string.Equals(keyUse.GetString(), "sig", StringComparison.Ordinal)))
                || !TryGetRequiredString(element, "alg", out var algorithm)
                || !string.Equals(algorithm, Rs256Algorithm, StringComparison.Ordinal)
                || !TryGetRequiredString(element, "n", out var modulus)
                || !TryGetRequiredString(element, "e", out var exponent))
            {
                continue;
            }

            var decodedModulus = DecodeBase64Url(modulus);
            var decodedExponent = DecodeBase64Url(exponent);
            if (decodedModulus.Length is < 256 or > 1024
                || decodedExponent.Length is < 1 or > 8)
            {
                continue;
            }

            keys.TryAdd(keyId, new GoogleJsonWebKey(decodedModulus, decodedExponent));
        }

        return keys;
    }

    private static bool TryGetRequiredString(
        JsonElement element,
        string propertyName,
        out string value)
    {
        if (element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(property.GetString()))
        {
            value = property.GetString()!;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetNumericDate(
        JsonElement element,
        string propertyName,
        out DateTimeOffset value)
    {
        if (element.TryGetProperty(propertyName, out var property)
            && property.ValueKind == JsonValueKind.Number
            && property.TryGetInt64(out var seconds))
        {
            try
            {
                value = DateTimeOffset.FromUnixTimeSeconds(seconds);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
            }
        }

        value = default;
        return false;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        if (value.Length == 0
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_')))
        {
            throw new FormatException("Invalid base64url value.");
        }

        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = (normalized.Length % 4) switch
        {
            0 => normalized,
            2 => normalized + "==",
            3 => normalized + "=",
            _ => throw new FormatException("Invalid base64url value."),
        };
        return Convert.FromBase64String(normalized);
    }

    private static UnauthorizedAccessException InvalidToken(Exception? innerException = null) =>
        new("The Google ID token is invalid.", innerException);

    private sealed record GoogleJsonWebKey(byte[] Modulus, byte[] Exponent);
}

internal enum ManagedIdentityProviderMode
{
    Development,
    Google,
}

internal static class ManagedIdentityProviderSelection
{
    public static ManagedIdentityProviderMode Resolve(
        IdentityOptions identityOptions,
        GoogleAuthOptions googleOptions,
        IHostEnvironment environment)
    {
        var provider = identityOptions.Provider.Trim();
        var isDevelopment = environment.IsDevelopment()
            || environment.IsEnvironment("Testing");
        var isDevelopmentProvider = string.Equals(
            provider,
            "Development",
            StringComparison.OrdinalIgnoreCase);
        var isGoogleProvider = string.Equals(
            provider,
            "Google",
            StringComparison.OrdinalIgnoreCase);
        if (!isDevelopmentProvider && !isGoogleProvider)
        {
            throw new InvalidOperationException(
                $"Identity provider '{identityOptions.Provider}' is not installed. Expected Development or Google.");
        }

        if (isDevelopment && isDevelopmentProvider)
        {
            return ManagedIdentityProviderMode.Development;
        }

        if (isGoogleProvider
            || (!isDevelopment && !string.IsNullOrWhiteSpace(googleOptions.ClientId)))
        {
            _ = GoogleAuthValidation.GetAllowedAudiences(googleOptions);
            return ManagedIdentityProviderMode.Google;
        }

        throw new InvalidOperationException(
            "Development identity is enabled only in Development or Testing; configure GoogleAuth:ClientId for production.");
    }
}

internal static class GoogleAuthValidation
{
    public static HashSet<string> GetAllowedAudiences(GoogleAuthOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ClientId)
            || options.ClientId.Trim().Length > 512)
        {
            throw new InvalidOperationException("GoogleAuth:ClientId is required and must be at most 512 characters.");
        }

        if (options.AllowedAudiences.Length > 16)
        {
            throw new InvalidOperationException("GoogleAuth:AllowedAudiences may contain at most 16 entries.");
        }

        var audiences = new HashSet<string>(StringComparer.Ordinal)
        {
            options.ClientId.Trim(),
        };
        foreach (var audience in options.AllowedAudiences)
        {
            if (string.IsNullOrWhiteSpace(audience))
            {
                continue;
            }

            if (audience.Trim().Length > 512)
            {
                throw new InvalidOperationException(
                    "GoogleAuth:AllowedAudiences entries must be at most 512 characters.");
            }

            audiences.Add(audience.Trim());
        }

        return audiences;
    }
}
