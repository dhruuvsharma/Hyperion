using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace DaxAlgo.Platform.Providers;

public enum EntitlementLeaseKind
{
    EditionLease,
    StrategyLicenseLease,
}

public sealed record EntitlementLeaseSignature(
    string EncodedPayload,
    string EncodedSignature,
    string KeyId,
    string Algorithm);

public sealed record EntitlementLeaseJsonWebKey(
    [property: JsonPropertyName("kty")] string KeyType,
    [property: JsonPropertyName("use")] string PublicKeyUse,
    [property: JsonPropertyName("kid")] string KeyId,
    [property: JsonPropertyName("alg")] string Algorithm,
    [property: JsonPropertyName("crv")] string Curve,
    [property: JsonPropertyName("x")] string X,
    [property: JsonPropertyName("y")] string Y,
    [property: JsonPropertyName("leaseKind")] string LeaseKind);

public sealed record EntitlementLeaseJsonWebKeySet(
    [property: JsonPropertyName("keys")] IReadOnlyList<EntitlementLeaseJsonWebKey> Keys);

public interface IEntitlementLeaseSigningProvider
{
    ValueTask<EntitlementLeaseSignature> SignAsync(
        EntitlementLeaseKind leaseKind,
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<EntitlementLeaseJsonWebKey>> GetVerificationKeysAsync(
        CancellationToken cancellationToken);
}

public sealed class DevelopmentEntitlementLeaseSigningProvider : IEntitlementLeaseSigningProvider
{
    private static readonly byte[] EditionLeaseDevelopmentOnlyKey = Encoding.UTF8.GetBytes(
        "daxalgo-development-only-edition-lease-signing-material-v1");

    private static readonly byte[] StrategyLicenseDevelopmentOnlyKey = Encoding.UTF8.GetBytes(
        "daxalgo-development-only-strategy-license-signing-material-v1");

    public ValueTask<EntitlementLeaseSignature> SignAsync(
        EntitlementLeaseKind leaseKind,
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EntitlementLeaseSigningEncoding.RequirePayload(canonicalPayload);
        var (key, keyId) = leaseKind switch
        {
            EntitlementLeaseKind.EditionLease => (
                EditionLeaseDevelopmentOnlyKey,
                "development-edition-lease-only-v1"),
            EntitlementLeaseKind.StrategyLicenseLease => (
                StrategyLicenseDevelopmentOnlyKey,
                "development-strategy-license-only-v1"),
            _ => throw new ArgumentOutOfRangeException(
                nameof(leaseKind),
                leaseKind,
                "Unknown entitlement lease kind."),
        };
        var signature = HMACSHA256.HashData(key, canonicalPayload.Span);
        return ValueTask.FromResult(new EntitlementLeaseSignature(
            EntitlementLeaseSigningEncoding.Encode(canonicalPayload.Span),
            EntitlementLeaseSigningEncoding.Encode(signature),
            keyId,
            "HS256-DEVELOPMENT-ONLY"));
    }

    public ValueTask<IReadOnlyList<EntitlementLeaseJsonWebKey>> GetVerificationKeysAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlyList<EntitlementLeaseJsonWebKey>>(
            Array.Empty<EntitlementLeaseJsonWebKey>());
    }
}

public sealed class SoftwareEntitlementLeaseSigningProvider :
    IEntitlementLeaseSigningProvider,
    IDisposable
{
    private readonly SoftwareSigningKey editionLeaseKey = new(
        "testing-edition-lease-es256",
        EntitlementLeaseKind.EditionLease);

    private readonly SoftwareSigningKey strategyLicenseLeaseKey = new(
        "testing-strategy-license-lease-es256",
        EntitlementLeaseKind.StrategyLicenseLease);

    private readonly IReadOnlyList<EntitlementLeaseJsonWebKey> verificationKeys;

    public SoftwareEntitlementLeaseSigningProvider()
    {
        verificationKeys =
        [
            editionLeaseKey.VerificationKey,
            strategyLicenseLeaseKey.VerificationKey,
        ];
    }

    public ValueTask<EntitlementLeaseSignature> SignAsync(
        EntitlementLeaseKind leaseKind,
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EntitlementLeaseSigningEncoding.RequirePayload(canonicalPayload);
        var key = leaseKind switch
        {
            EntitlementLeaseKind.EditionLease => editionLeaseKey,
            EntitlementLeaseKind.StrategyLicenseLease => strategyLicenseLeaseKey,
            _ => throw new ArgumentOutOfRangeException(
                nameof(leaseKind),
                leaseKind,
                "Unknown entitlement lease kind."),
        };
        var signature = key.Sign(canonicalPayload.Span);
        return ValueTask.FromResult(new EntitlementLeaseSignature(
            EntitlementLeaseSigningEncoding.Encode(canonicalPayload.Span),
            EntitlementLeaseSigningEncoding.Encode(signature),
            key.KeyId,
            EntitlementLeaseSigningEncoding.Es256Algorithm));
    }

    public ValueTask<IReadOnlyList<EntitlementLeaseJsonWebKey>> GetVerificationKeysAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(verificationKeys);
    }

    public void Dispose()
    {
        editionLeaseKey.Dispose();
        strategyLicenseLeaseKey.Dispose();
        GC.SuppressFinalize(this);
    }

    private sealed class SoftwareSigningKey : IDisposable
    {
        private readonly Lock signingLock = new();
        private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public SoftwareSigningKey(string keyIdPrefix, EntitlementLeaseKind leaseKind)
        {
            var parameters = key.ExportParameters(includePrivateParameters: false);
            KeyId = EntitlementLeaseSigningEncoding.CreateKeyId(
                keyIdPrefix,
                parameters.Q.X,
                parameters.Q.Y);
            VerificationKey = EntitlementLeaseSigningEncoding.CreateJsonWebKey(
                KeyId,
                leaseKind,
                parameters.Q.X,
                parameters.Q.Y);
        }

        public string KeyId { get; }

        public EntitlementLeaseJsonWebKey VerificationKey { get; }

        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            lock (signingLock)
            {
                return key.SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }

        public void Dispose()
        {
            key.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}

internal enum EntitlementLeaseSigningMode
{
    DevelopmentHmac,
    SoftwareEs256,
    AzureKms,
}

internal static class EntitlementLeaseSigningProviderSelection
{
    public const string DevelopmentProvider = "development";
    public const string SoftwareProvider = "software-es256";
    public const string AzureProvider = "azure-kms";

    public static EntitlementLeaseSigningMode Resolve(
        string configuredProvider,
        string environmentName)
    {
        if (string.Equals(environmentName, "Production", StringComparison.OrdinalIgnoreCase))
        {
            return EntitlementLeaseSigningMode.AzureKms;
        }

        if (string.Equals(configuredProvider, AzureProvider, StringComparison.OrdinalIgnoreCase))
        {
            return EntitlementLeaseSigningMode.AzureKms;
        }

        if (string.Equals(configuredProvider, DevelopmentProvider, StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(environmentName, "Testing", StringComparison.OrdinalIgnoreCase))
            {
                return EntitlementLeaseSigningMode.SoftwareEs256;
            }

            return EntitlementLeaseSigningMode.DevelopmentHmac;
        }

        if (string.Equals(configuredProvider, SoftwareProvider, StringComparison.OrdinalIgnoreCase))
        {
            return EntitlementLeaseSigningMode.SoftwareEs256;
        }

        throw new InvalidOperationException(
            $"Lease signing provider '{configuredProvider}' is not installed. "
            + $"Expected {DevelopmentProvider}, {SoftwareProvider}, or {AzureProvider}.");
    }
}

internal static class EntitlementLeaseSigningEncoding
{
    public const string Es256Algorithm = "ES256";

    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public static void RequirePayload(ReadOnlyMemory<byte> canonicalPayload)
    {
        if (canonicalPayload.IsEmpty)
        {
            throw new ArgumentException(
                "A canonical lease payload is required.",
                nameof(canonicalPayload));
        }
    }

    public static EntitlementLeaseJsonWebKey CreateJsonWebKey(
        string keyId,
        EntitlementLeaseKind leaseKind,
        byte[]? x,
        byte[]? y)
    {
        RequireP256Coordinates(x, y);

        return new EntitlementLeaseJsonWebKey(
            "EC",
            "sig",
            keyId,
            Es256Algorithm,
            "P-256",
            Encode(x!),
            Encode(y!),
            leaseKind switch
            {
                EntitlementLeaseKind.EditionLease => "edition-lease",
                EntitlementLeaseKind.StrategyLicenseLease => "strategy-license-lease",
                _ => throw new ArgumentOutOfRangeException(
                    nameof(leaseKind),
                    leaseKind,
                    "Unknown entitlement lease kind."),
            });
    }

    public static string CreateKeyId(string prefix, byte[]? x, byte[]? y)
    {
        RequireP256Coordinates(x, y);
        var publicKey = new byte[x!.Length + y!.Length];
        x.CopyTo(publicKey, 0);
        y.CopyTo(publicKey, x.Length);
        return $"{prefix}-{Encode(SHA256.HashData(publicKey))}";
    }

    private static void RequireP256Coordinates(byte[]? x, byte[]? y)
    {
        if (x is not { Length: 32 } || y is not { Length: 32 })
        {
            throw new CryptographicException(
                "The ES256 verification key must contain P-256 public coordinates.");
        }
    }
}
