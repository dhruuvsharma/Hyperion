using System.Buffers.Binary;
using System.Security.Cryptography;
using DaxAlgo.Platform.Configuration;

namespace DaxAlgo.Platform.Providers;

internal enum MarketplaceLicenseCryptographyMode
{
    SoftwareEs256,
    AzureKms,
}

internal static class MarketplaceLicenseCryptographyProviderSelection
{
    public const string DevelopmentProvider = "development";
    public const string SoftwareProvider = "software-es256";
    public const string AzureProvider = "azure-kms";

    public static MarketplaceLicenseCryptographyMode Resolve(
        string configuredProvider,
        string environmentName)
    {
        if (string.Equals(configuredProvider, AzureProvider, StringComparison.OrdinalIgnoreCase))
        {
            return MarketplaceLicenseCryptographyMode.AzureKms;
        }

        if (string.Equals(configuredProvider, DevelopmentProvider, StringComparison.OrdinalIgnoreCase)
            || string.Equals(configuredProvider, SoftwareProvider, StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(environmentName, "Development", StringComparison.OrdinalIgnoreCase)
                || string.Equals(environmentName, "Testing", StringComparison.OrdinalIgnoreCase))
            {
                return MarketplaceLicenseCryptographyMode.SoftwareEs256;
            }

            throw new InvalidOperationException(
                "Software marketplace licensing cryptography is enabled only in Development or Testing.");
        }

        throw new InvalidOperationException(
            $"Marketplace licensing provider '{configuredProvider}' is not installed. "
            + $"Expected {DevelopmentProvider}, {SoftwareProvider}, or {AzureProvider}.");
    }
}

public sealed class SoftwareMarketplaceLicenseCryptographyProvider :
    IMarketplaceLicenseCryptographyProvider,
    IContentKeyProvisioningProvider,
    IDisposable
{
    public const string ContentKeyWrappingAlgorithm = "A256KW";

    private readonly Lock signingLock = new();
    private readonly ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] contentWrappingKey = RandomNumberGenerator.GetBytes(32);
    private readonly MarketplaceLicenseJsonWebKey verificationKey;

    public SoftwareMarketplaceLicenseCryptographyProvider()
    {
        var parameters = signingKey.ExportParameters(includePrivateParameters: false);
        var keyId = "testing-marketplace-license-es256-"
            + Convert.ToHexString(SHA256.HashData([
                .. parameters.Q.X!,
                .. parameters.Q.Y!,
            ]))[..16].ToLowerInvariant();
        verificationKey = new MarketplaceLicenseJsonWebKey(
            "EC",
            "sig",
            keyId,
            "ES256",
            "P-256",
            MarketplaceCryptographyEncoding.Encode(parameters.Q.X),
            MarketplaceCryptographyEncoding.Encode(parameters.Q.Y));
    }

    public ValueTask<MarketplaceLicenseSignature> SignAsync(
        ReadOnlyMemory<byte> canonicalPayload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (canonicalPayload.IsEmpty)
        {
            throw new ArgumentException("A canonical payload is required.", nameof(canonicalPayload));
        }

        byte[] signature;
        lock (signingLock)
        {
            signature = signingKey.SignData(
                canonicalPayload.Span,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        return ValueTask.FromResult(new MarketplaceLicenseSignature(
            MarketplaceCryptographyEncoding.Encode(canonicalPayload.Span),
            MarketplaceCryptographyEncoding.Encode(signature),
            verificationKey.KeyId,
            "ES256"));
    }

    public ValueTask<MarketplaceLicenseJsonWebKey> GetVerificationKeyAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(verificationKey);
    }

    public ValueTask<byte[]> UnwrapContentKeyAsync(
        string algorithm,
        ReadOnlyMemory<byte> wrappedContentKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireA256Kw(algorithm);
        return ValueTask.FromResult(AesKeyWrap.Unwrap(contentWrappingKey, wrappedContentKey.Span));
    }

    ValueTask<byte[]> IContentKeyProvisioningProvider.WrapContentKeyAsync(
        string algorithm,
        ReadOnlyMemory<byte> contentKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RequireA256Kw(algorithm);
        if (contentKey.Length != 32)
        {
            throw new CryptographicException("DAXQ content keys must contain exactly 32 bytes.");
        }

        return ValueTask.FromResult(AesKeyWrap.Wrap(contentWrappingKey, contentKey.Span));
    }

    public void Dispose()
    {
        signingKey.Dispose();
        CryptographicOperations.ZeroMemory(contentWrappingKey);
        GC.SuppressFinalize(this);
    }

    private static void RequireA256Kw(string algorithm)
    {
        if (!string.Equals(algorithm, ContentKeyWrappingAlgorithm, StringComparison.Ordinal))
        {
            throw new CryptographicException(
                $"Unsupported content-key wrapping algorithm '{algorithm}'.");
        }
    }
}

internal static class MarketplaceCryptographyEncoding
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public static byte[] Decode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        return Convert.FromBase64String(base64);
    }
}

internal static class AesKeyWrap
{
    private static ReadOnlySpan<byte> InitialValue =>
        [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

    public static byte[] Wrap(ReadOnlySpan<byte> keyEncryptionKey, ReadOnlySpan<byte> plaintext)
    {
        ValidateKeyEncryptionKey(keyEncryptionKey);
        if (plaintext.Length < 16 || plaintext.Length % 8 != 0)
        {
            throw new CryptographicException(
                "RFC 3394 plaintext must be a multiple of 64 bits and at least 128 bits.");
        }

        var blockCount = plaintext.Length / 8;
        var result = new byte[plaintext.Length + 8];
        InitialValue.CopyTo(result);
        plaintext.CopyTo(result.AsSpan(8));
        Span<byte> block = stackalloc byte[16];
        Span<byte> encrypted = stackalloc byte[16];
        using var aes = CreateAes(keyEncryptionKey);
        for (var round = 0; round < 6; round++)
        {
            for (var index = 1; index <= blockCount; index++)
            {
                result.AsSpan(0, 8).CopyTo(block);
                result.AsSpan(index * 8, 8).CopyTo(block[8..]);
                aes.EncryptEcb(block, encrypted, PaddingMode.None);
                encrypted[..8].CopyTo(result);
                XorCounter(result.AsSpan(0, 8), checked((ulong)((blockCount * round) + index)));
                encrypted[8..].CopyTo(result.AsSpan(index * 8, 8));
            }
        }

        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(encrypted);
        return result;
    }

    public static byte[] Unwrap(ReadOnlySpan<byte> keyEncryptionKey, ReadOnlySpan<byte> ciphertext)
    {
        ValidateKeyEncryptionKey(keyEncryptionKey);
        if (ciphertext.Length < 24 || ciphertext.Length % 8 != 0)
        {
            throw new CryptographicException(
                "RFC 3394 ciphertext must be a multiple of 64 bits and at least 192 bits.");
        }

        var blockCount = (ciphertext.Length / 8) - 1;
        var working = ciphertext.ToArray();
        Span<byte> block = stackalloc byte[16];
        Span<byte> decrypted = stackalloc byte[16];
        using var aes = CreateAes(keyEncryptionKey);
        for (var round = 5; round >= 0; round--)
        {
            for (var index = blockCount; index >= 1; index--)
            {
                working.AsSpan(0, 8).CopyTo(block);
                XorCounter(block[..8], checked((ulong)((blockCount * round) + index)));
                working.AsSpan(index * 8, 8).CopyTo(block[8..]);
                aes.DecryptEcb(block, decrypted, PaddingMode.None);
                decrypted[..8].CopyTo(working);
                decrypted[8..].CopyTo(working.AsSpan(index * 8, 8));
            }
        }

        if (!CryptographicOperations.FixedTimeEquals(working.AsSpan(0, 8), InitialValue))
        {
            CryptographicOperations.ZeroMemory(working);
            throw new CryptographicException("RFC 3394 integrity check failed.");
        }

        var plaintext = working.AsSpan(8).ToArray();
        CryptographicOperations.ZeroMemory(working);
        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(decrypted);
        return plaintext;
    }

    private static Aes CreateAes(ReadOnlySpan<byte> key)
    {
        var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        return aes;
    }

    private static void ValidateKeyEncryptionKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new CryptographicException("AES key-encryption keys must contain 128, 192, or 256 bits.");
        }
    }

    private static void XorCounter(Span<byte> value, ulong counter)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, counter);
        for (var index = 0; index < value.Length; index++)
        {
            value[index] ^= encoded[index];
        }
    }
}
