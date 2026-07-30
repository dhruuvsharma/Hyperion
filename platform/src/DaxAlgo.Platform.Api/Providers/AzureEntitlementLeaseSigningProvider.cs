using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using DaxAlgo.Platform.Configuration;

namespace DaxAlgo.Platform.Providers;

public sealed class AzureEntitlementLeaseSigningProvider :
    IEntitlementLeaseSigningProvider,
    IDisposable
{
    private readonly TokenCredential credential;
    private readonly KeyClient keyClient;
    private readonly AzureLeaseKeyReference editionLeaseKeyReference;
    private readonly AzureLeaseKeyReference strategyLicenseLeaseKeyReference;
    private readonly SemaphoreSlim keyLoadGate = new(1, 1);
    private AzureLeaseKey? editionLeaseKey;
    private AzureLeaseKey? strategyLicenseLeaseKey;

    public AzureEntitlementLeaseSigningProvider(
        EntitlementLeaseOptions options,
        TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.credential = credential ?? throw new ArgumentNullException(nameof(credential));
        keyClient = new KeyClient(new Uri(options.KeyVaultUri, UriKind.Absolute), credential);
        editionLeaseKeyReference = AzureLeaseKeyReference.Parse(
            options.EditionLeaseKey,
            nameof(options.EditionLeaseKey));
        strategyLicenseLeaseKeyReference = AzureLeaseKeyReference.Parse(
            options.StrategyLicenseLeaseKey,
            nameof(options.StrategyLicenseLeaseKey));
        if (string.Equals(
                editionLeaseKeyReference.Name,
                strategyLicenseLeaseKeyReference.Name,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Edition and strategy-license leases must use independently named Azure keys.");
        }
    }

    public async ValueTask<EntitlementLeaseSignature> SignAsync(
        EntitlementLeaseKind leaseKind,
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken)
    {
        EntitlementLeaseSigningEncoding.RequirePayload(canonicalPayload);
        var key = await GetKeyAsync(leaseKind, cancellationToken);
        var comparisonKey = await GetKeyAsync(
            leaseKind == EntitlementLeaseKind.EditionLease
                ? EntitlementLeaseKind.StrategyLicenseLease
                : EntitlementLeaseKind.EditionLease,
            cancellationToken);
        EnsureKeysAreDistinct(key, comparisonKey);
        var digest = SHA256.HashData(canonicalPayload.Span);
        var result = await key.CryptographyClient.SignAsync(
            SignatureAlgorithm.ES256,
            digest,
            cancellationToken);
        if (result.Signature is not { Length: 64 })
        {
            throw new CryptographicException(
                "Azure Key Vault returned an invalid ES256 signature length.");
        }

        return new EntitlementLeaseSignature(
            EntitlementLeaseSigningEncoding.Encode(canonicalPayload.Span),
            EntitlementLeaseSigningEncoding.Encode(result.Signature),
            key.KeyId,
            EntitlementLeaseSigningEncoding.Es256Algorithm);
    }

    public async ValueTask<IReadOnlyList<EntitlementLeaseJsonWebKey>> GetVerificationKeysAsync(
        CancellationToken cancellationToken)
    {
        var edition = await GetKeyAsync(EntitlementLeaseKind.EditionLease, cancellationToken);
        var strategy = await GetKeyAsync(
            EntitlementLeaseKind.StrategyLicenseLease,
            cancellationToken);
        EnsureKeysAreDistinct(edition, strategy);
        return [edition.VerificationKey, strategy.VerificationKey];
    }

    public void Dispose()
    {
        keyLoadGate.Dispose();
        GC.SuppressFinalize(this);
    }

    private async ValueTask<AzureLeaseKey> GetKeyAsync(
        EntitlementLeaseKind leaseKind,
        CancellationToken cancellationToken)
    {
        var cached = GetCachedKey(leaseKind);
        if (cached is not null)
        {
            return cached;
        }

        await keyLoadGate.WaitAsync(cancellationToken);
        try
        {
            cached = GetCachedKey(leaseKind);
            if (cached is not null)
            {
                return cached;
            }

            var reference = leaseKind switch
            {
                EntitlementLeaseKind.EditionLease => editionLeaseKeyReference,
                EntitlementLeaseKind.StrategyLicenseLease => strategyLicenseLeaseKeyReference,
                _ => throw new ArgumentOutOfRangeException(
                    nameof(leaseKind),
                    leaseKind,
                    "Unknown entitlement lease kind."),
            };
            var response = await keyClient.GetKeyAsync(
                reference.Name,
                reference.Version,
                cancellationToken);
            var key = response.Value;
            if (key.Key.CurveName != KeyCurveName.P256)
            {
                throw new CryptographicException(
                    $"Azure key '{key.Id}' must be an ECDSA P-256 key for ES256 signing.");
            }

            var loaded = new AzureLeaseKey(
                key.Id.AbsoluteUri,
                new CryptographyClient(key.Id, credential),
                EntitlementLeaseSigningEncoding.CreateJsonWebKey(
                    key.Id.AbsoluteUri,
                    leaseKind,
                    key.Key.X,
                    key.Key.Y));
            SetCachedKey(leaseKind, loaded);
            return loaded;
        }
        finally
        {
            keyLoadGate.Release();
        }
    }

    private AzureLeaseKey? GetCachedKey(EntitlementLeaseKind leaseKind) => leaseKind switch
    {
        EntitlementLeaseKind.EditionLease => Volatile.Read(ref editionLeaseKey),
        EntitlementLeaseKind.StrategyLicenseLease => Volatile.Read(ref strategyLicenseLeaseKey),
        _ => throw new ArgumentOutOfRangeException(
            nameof(leaseKind),
            leaseKind,
            "Unknown entitlement lease kind."),
    };

    private void SetCachedKey(EntitlementLeaseKind leaseKind, AzureLeaseKey key)
    {
        switch (leaseKind)
        {
            case EntitlementLeaseKind.EditionLease:
                Volatile.Write(ref editionLeaseKey, key);
                break;
            case EntitlementLeaseKind.StrategyLicenseLease:
                Volatile.Write(ref strategyLicenseLeaseKey, key);
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(leaseKind),
                    leaseKind,
                    "Unknown entitlement lease kind.");
        }
    }

    private static void EnsureKeysAreDistinct(AzureLeaseKey first, AzureLeaseKey second)
    {
        if (string.Equals(
                first.VerificationKey.X,
                second.VerificationKey.X,
                StringComparison.Ordinal)
            && string.Equals(
                first.VerificationKey.Y,
                second.VerificationKey.Y,
                StringComparison.Ordinal))
        {
            throw new CryptographicException(
                "Edition and strategy-license leases must not reuse the same Azure key material.");
        }
    }

    private sealed record AzureLeaseKey(
        string KeyId,
        CryptographyClient CryptographyClient,
        EntitlementLeaseJsonWebKey VerificationKey);

    private sealed record AzureLeaseKeyReference(string Name, string Version)
    {
        public static AzureLeaseKeyReference Parse(string value, string optionName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException(
                    $"Lease option '{optionName}' must use the key-name/key-version format.");
            }

            var segments = value.Trim().Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (segments.Length != 2)
            {
                throw new InvalidOperationException(
                    $"Lease option '{optionName}' must use the key-name/key-version format.");
            }

            return new AzureLeaseKeyReference(segments[0], segments[1]);
        }
    }
}
