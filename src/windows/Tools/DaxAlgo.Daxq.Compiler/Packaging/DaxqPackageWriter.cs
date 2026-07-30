using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using DaxAlgo.Daxq.Contracts;
using DaxAlgo.Daxq.Vm;

namespace DaxAlgo.Daxq.Compiler;

/// <summary>Seals authenticated DQXP plaintext into a canonical, release-signed DAXQ package.</summary>
public static class DaxqPackageWriter
{
    private static readonly DateTimeOffset ZipEpoch =
        new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>Validates, encrypts, indexes, signs, and packages one DAXQ release.</summary>
    public static DaxqPackageArtifact Write(DaxqPackageWriteOptions options)
    {
        var normalized = DaxqPackageValidation.Normalize(options);
        try
        {
            var loadFault = DaxqProgram.TryLoad(normalized.PlaintextBytes, out _);
            if (loadFault != DaxqFault.Ok)
            {
                throw new InvalidDataException(
                    $"The supplied DQXP plaintext failed v1 verification: {loadFault}.");
            }

            var ciphertextAndTag = Encrypt(normalized);
            var cipherSha256 = Sha256(ciphertextAndTag);
            var manifest = DaxqCanonicalJson.WriteManifest(
                normalized,
                Base64Url(normalized.Nonce),
                cipherSha256);
            var manifestSha256 = Sha256(manifest);
            var packageIndex = DaxqCanonicalJson.WritePackageIndex(manifestSha256, cipherSha256);
            var packageIndexSha256 = Sha256(packageIndex);
            var signatureInput = BuildSignatureInput(
                normalized.ReleaseKeyId,
                manifest,
                packageIndex);
            var signature = Sign(normalized.ReleaseSigningKey, signatureInput);
            var signatureJson = DaxqCanonicalJson.WriteSignature(
                normalized.ReleaseKeyId,
                Base64Url(signature));
            var package = BuildPackage(manifest, ciphertextAndTag, packageIndex, signatureJson);

            return new DaxqPackageArtifact
            {
                PackageBytes = package,
                PlaintextBytes = normalized.PlaintextBytes,
                CiphertextAndTagBytes = ciphertextAndTag,
                ManifestJsonBytes = manifest,
                PackageIndexJsonBytes = packageIndex,
                SignatureInputBytes = signatureInput,
                SignatureBytes = signature,
                SignatureJsonBytes = signatureJson,
                CipherSha256 = cipherSha256,
                ManifestSha256 = manifestSha256,
                PackageIndexSha256 = packageIndexSha256,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(normalized.ContentKey);
        }
    }

    private static byte[] Encrypt(NormalizedDaxqPackageOptions options)
    {
        var ciphertext = new byte[options.PlaintextBytes.Length];
        var tag = new byte[DaxqFormat.AuthenticationTagSizeBytes];
        using (var aes = new AesGcm(options.ContentKey, DaxqFormat.AuthenticationTagSizeBytes))
        {
            aes.Encrypt(
                options.Nonce,
                options.PlaintextBytes,
                ciphertext,
                tag,
                ReadOnlySpan<byte>.Empty);
        }

        var result = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);
        return result;
    }

    private static byte[] BuildSignatureInput(
        string releaseKeyId,
        byte[] manifest,
        byte[] packageIndex)
    {
        var keyId = Encoding.UTF8.GetBytes(releaseKeyId);
        using var stream = new MemoryStream();
        stream.Write("DAXQ-SIG-V1"u8);
        stream.WriteByte(0);
        Span<byte> integer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(integer[..2], checked((ushort)keyId.Length));
        stream.Write(integer[..2]);
        stream.Write(keyId);
        BinaryPrimitives.WriteUInt32BigEndian(integer, checked((uint)manifest.Length));
        stream.Write(integer);
        stream.Write(manifest);
        BinaryPrimitives.WriteUInt32BigEndian(integer, checked((uint)packageIndex.Length));
        stream.Write(integer);
        stream.Write(packageIndex);
        return stream.ToArray();
    }

    private static byte[] Sign(ECDsa signingKey, byte[] signatureInput)
    {
        try
        {
            var signature = signingKey.SignData(
                signatureInput,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (signature.Length != DaxqFormat.SignatureSizeBytes)
            {
                throw new CryptographicException(
                    $"ES256 returned {signature.Length} bytes instead of {DaxqFormat.SignatureSizeBytes}.");
            }
            return signature;
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                "The release signing key could not produce a DAXQ ES256 signature.",
                nameof(signingKey),
                exception);
        }
    }

    private static byte[] BuildPackage(
        byte[] manifest,
        byte[] ciphertextAndTag,
        byte[] packageIndex,
        byte[] signature)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(
                   stream,
                   ZipArchiveMode.Create,
                   leaveOpen: true,
                   entryNameEncoding: Encoding.UTF8))
        {
            WriteEntry(archive, DaxqFormat.ManifestEntryName, manifest);
            WriteEntry(archive, DaxqFormat.CiphertextEntryName, ciphertextAndTag);
            WriteEntry(archive, DaxqFormat.PackageIndexEntryName, packageIndex);
            WriteEntry(archive, DaxqFormat.SignatureEntryName, signature);
        }
        return stream.ToArray();
    }

    private static void WriteEntry(ZipArchive archive, string name, byte[] content)
    {
        if (name.Contains('/') || name.Contains('\\'))
            throw new InvalidOperationException("DAXQ package entries must be root files.");
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = ZipEpoch;
        entry.ExternalAttributes = 0;
        using var destination = entry.Open();
        destination.Write(content);
    }

    private static string Sha256(byte[] value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
