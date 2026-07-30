using System.Security.Cryptography;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using DaxAlgo.Platform.Configuration;

namespace DaxAlgo.Platform.Providers;

public sealed class AzureMarketplaceLicenseCryptographyProvider :
    IMarketplaceLicenseCryptographyProvider,
    IContentKeyProvisioningProvider,
    IDisposable
{
    private readonly TokenCredential credential;
    private readonly KeyClient keyClient;
    private readonly AzureMarketplaceKeyReference signingKeyReference;
    private readonly CryptographyClient contentWrappingClient;
    private readonly SemaphoreSlim keyLoadGate = new(1, 1);
    private AzureMarketplaceSigningKey? signingKey;

    public AzureMarketplaceLicenseCryptographyProvider(
        MarketplaceLicensingOptions options,
        TokenCredential credential)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.credential = credential ?? throw new ArgumentNullException(nameof(credential));
        var vaultUri = new Uri(options.KeyVaultUri, UriKind.Absolute);
        keyClient = new KeyClient(vaultUri, credential);
        signingKeyReference = AzureMarketplaceKeyReference.Parse(
            options.SigningKey,
            nameof(options.SigningKey));
        var wrappingKey = AzureMarketplaceKeyReference.Parse(
            options.ContentWrappingKey,
            nameof(options.ContentWrappingKey));
        if (string.Equals(
                signingKeyReference.Name,
                wrappingKey.Name,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Marketplace signing and content wrapping must use independently named Azure keys.");
        }

        var wrappingKeyUri = new Uri(
            vaultUri,
            $"keys/{Uri.EscapeDataString(wrappingKey.Name)}/{Uri.EscapeDataString(wrappingKey.Version)}");
        contentWrappingClient = new CryptographyClient(wrappingKeyUri, credential);
    }

    public async ValueTask<MarketplaceLicenseSignature> SignAsync(
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken)
    {
        if (canonicalPayload.IsEmpty)
        {
            throw new ArgumentException("A canonical payload is required.", nameof(canonicalPayload));
        }

        var key = await GetSigningKeyAsync(cancellationToken);
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

        return new MarketplaceLicenseSignature(
            MarketplaceCryptographyEncoding.Encode(canonicalPayload.Span),
            MarketplaceCryptographyEncoding.Encode(result.Signature),
            key.VerificationKey.KeyId,
            "ES256");
    }

    public async ValueTask<MarketplaceLicenseJsonWebKey> GetVerificationKeyAsync(
        CancellationToken cancellationToken) =>
        (await GetSigningKeyAsync(cancellationToken)).VerificationKey;

    public async ValueTask<byte[]> UnwrapContentKeyAsync(
        string algorithm,
        ReadOnlyMemory<byte> wrappedContentKey,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(
                algorithm,
                SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
                StringComparison.Ordinal))
        {
            throw new CryptographicException(
                $"Unsupported content-key wrapping algorithm '{algorithm}'.");
        }

        if (wrappedContentKey.IsEmpty)
        {
            throw new CryptographicException("The KMS-wrapped content key is empty.");
        }

        var response = await contentWrappingClient.UnwrapKeyAsync(
            KeyWrapAlgorithm.A256KW,
            wrappedContentKey.ToArray(),
            cancellationToken);
        if (response.Key is not { Length: 32 } contentKey)
        {
            throw new CryptographicException(
                "Azure Key Vault returned a content key with an invalid length.");
        }

        return contentKey;
    }

    public async ValueTask<byte[]> WrapContentKeyAsync(
        string algorithm,
        ReadOnlyMemory<byte> contentKey,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(
                algorithm,
                SoftwareMarketplaceLicenseCryptographyProvider.ContentKeyWrappingAlgorithm,
                StringComparison.Ordinal))
        {
            throw new CryptographicException(
                $"Unsupported content-key wrapping algorithm '{algorithm}'.");
        }

        if (contentKey.Length != 32)
        {
            throw new CryptographicException("DAXQ content keys must contain exactly 32 bytes.");
        }

        var response = await contentWrappingClient.WrapKeyAsync(
            KeyWrapAlgorithm.A256KW,
            contentKey.ToArray(),
            cancellationToken);
        if (response.EncryptedKey is not { Length: > 0 } wrapped)
        {
            throw new CryptographicException("Azure Key Vault returned an empty wrapped content key.");
        }

        return wrapped;
    }

    public void Dispose()
    {
        keyLoadGate.Dispose();
        GC.SuppressFinalize(this);
    }

    private async ValueTask<AzureMarketplaceSigningKey> GetSigningKeyAsync(
        CancellationToken cancellationToken)
    {
        var cached = Volatile.Read(ref signingKey);
        if (cached is not null)
        {
            return cached;
        }

        await keyLoadGate.WaitAsync(cancellationToken);
        try
        {
            cached = Volatile.Read(ref signingKey);
            if (cached is not null)
            {
                return cached;
            }

            var response = await keyClient.GetKeyAsync(
                signingKeyReference.Name,
                signingKeyReference.Version,
                cancellationToken);
            var key = response.Value;
            if (key.Key.CurveName != KeyCurveName.P256
                || key.Key.X is not { Length: 32 }
                || key.Key.Y is not { Length: 32 })
            {
                throw new CryptographicException(
                    $"Azure key '{key.Id}' must be an ECDSA P-256 key for ES256 signing.");
            }

            cached = new AzureMarketplaceSigningKey(
                new CryptographyClient(key.Id, credential),
                new MarketplaceLicenseJsonWebKey(
                    "EC",
                    "sig",
                    key.Id.AbsoluteUri,
                    "ES256",
                    "P-256",
                    MarketplaceCryptographyEncoding.Encode(key.Key.X),
                    MarketplaceCryptographyEncoding.Encode(key.Key.Y)));
            Volatile.Write(ref signingKey, cached);
            return cached;
        }
        finally
        {
            keyLoadGate.Release();
        }
    }

    private sealed record AzureMarketplaceSigningKey(
        CryptographyClient CryptographyClient,
        MarketplaceLicenseJsonWebKey VerificationKey);

    private sealed record AzureMarketplaceKeyReference(string Name, string Version)
    {
        public static AzureMarketplaceKeyReference Parse(string value, string optionName)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException(
                    $"Marketplace licensing option '{optionName}' must use key-name/key-version.");
            }

            var segments = value.Trim().Split(
                '/',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (segments.Length != 2)
            {
                throw new InvalidOperationException(
                    $"Marketplace licensing option '{optionName}' must use key-name/key-version.");
            }

            return new AzureMarketplaceKeyReference(segments[0], segments[1]);
        }
    }
}
