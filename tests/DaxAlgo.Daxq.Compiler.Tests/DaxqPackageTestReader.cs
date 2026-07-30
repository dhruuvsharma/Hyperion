using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DaxAlgo.Daxq.Compiler.Tests;

internal sealed record VerifiedDaxqPackage(
    DaxqManifest Manifest,
    byte[] ManifestBytes,
    byte[] PackageIndexBytes,
    byte[] SignatureBytes,
    byte[] CiphertextBytes,
    byte[] PlaintextBytes);

/// <summary>
/// Independent test-side package consumer. It intentionally uses only the ZIP bytes and frozen
/// format contract, not the writer's returned component arrays or signature-input helper.
/// </summary>
internal static class DaxqPackageTestReader
{
    public static VerifiedDaxqPackage ReadVerifyAndDecrypt(
        byte[] packageBytes,
        byte[] contentKey,
        ECDsa releaseVerificationKey)
    {
        var entries = ReadExactEntries(packageBytes);
        var manifestBytes = entries[DaxqFormat.ManifestEntryName];
        var ciphertext = entries[DaxqFormat.CiphertextEntryName];
        var packageIndexBytes = entries[DaxqFormat.PackageIndexEntryName];
        var signatureEnvelopeBytes = entries[DaxqFormat.SignatureEntryName];

        var manifest = JsonSerializer.Deserialize<DaxqManifest>(manifestBytes)
            ?? throw new InvalidDataException("manifest.json was empty.");
        using var index = JsonDocument.Parse(packageIndexBytes);
        var indexedFiles = index.RootElement.GetProperty("files");
        AssertHash(manifestBytes, indexedFiles.GetProperty(DaxqFormat.ManifestEntryName).GetString());
        AssertHash(ciphertext, indexedFiles.GetProperty(DaxqFormat.CiphertextEntryName).GetString());
        AssertHash(ciphertext, manifest.Protection.CipherSha256);

        using var envelope = JsonDocument.Parse(signatureEnvelopeBytes);
        var root = envelope.RootElement;
        if (root.GetProperty("alg").GetString() != DaxqFormat.SignatureAlgorithm)
            throw new InvalidDataException("signature.json used the wrong algorithm.");
        var keyId = root.GetProperty("keyId").GetString()
            ?? throw new InvalidDataException("signature.json omitted keyId.");
        var signature = Base64UrlDecode(root.GetProperty("sig").GetString());
        var signatureInput = BuildSignatureInput(keyId, manifestBytes, packageIndexBytes);
        if (!releaseVerificationKey.VerifyData(
                signatureInput,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            throw new CryptographicException("The extracted DAXQ release signature is invalid.");
        }

        var nonce = Base64UrlDecode(manifest.Protection.Nonce);
        if (ciphertext.Length < DaxqFormat.AuthenticationTagSizeBytes)
            throw new InvalidDataException("strategy.dqx is shorter than its authentication tag.");
        var plaintext = new byte[ciphertext.Length - DaxqFormat.AuthenticationTagSizeBytes];
        using (var aes = new AesGcm(contentKey, DaxqFormat.AuthenticationTagSizeBytes))
        {
            aes.Decrypt(
                nonce,
                ciphertext.AsSpan(0, plaintext.Length),
                ciphertext.AsSpan(plaintext.Length),
                plaintext);
        }

        return new VerifiedDaxqPackage(
            manifest,
            manifestBytes,
            packageIndexBytes,
            signature,
            ciphertext,
            plaintext);
    }

    private static Dictionary<string, byte[]> ReadExactEntries(byte[] packageBytes)
    {
        string[] expected =
        [
            DaxqFormat.ManifestEntryName,
            DaxqFormat.PackageIndexEntryName,
            DaxqFormat.SignatureEntryName,
            DaxqFormat.CiphertextEntryName,
        ];
        using var stream = new MemoryStream(packageBytes, writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false, Encoding.UTF8);
        if (archive.Entries.Count != expected.Length)
            throw new InvalidDataException("A DAXQ v1 package must contain exactly four entries.");

        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var entry in archive.Entries)
        {
            if (!expected.Contains(entry.FullName, StringComparer.Ordinal) ||
                entry.FullName.Contains('/') || entry.FullName.Contains('\\') ||
                !entries.TryAdd(entry.FullName, ReadEntry(entry)))
            {
                throw new InvalidDataException($"Unexpected or duplicate DAXQ entry '{entry.FullName}'.");
            }
        }
        return entries;
    }

    private static byte[] ReadEntry(ZipArchiveEntry entry)
    {
        using var input = entry.Open();
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
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

    private static void AssertHash(byte[] content, string? expected)
    {
        var actual = Convert.ToHexStringLower(SHA256.HashData(content));
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
            throw new InvalidDataException("A DAXQ package hash did not match its extracted entry.");
    }

    private static byte[] Base64UrlDecode(string? value)
    {
        if (string.IsNullOrEmpty(value))
            throw new InvalidDataException("A required base64url value was empty.");
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            0 => padded,
            2 => padded + "==",
            3 => padded + "=",
            _ => throw new InvalidDataException("A base64url value had invalid length."),
        };
        return Convert.FromBase64String(padded);
    }
}
