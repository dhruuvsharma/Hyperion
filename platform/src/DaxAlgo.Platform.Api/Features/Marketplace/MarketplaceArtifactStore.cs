using System.Collections.Concurrent;
using System.Security.Cryptography;
using DaxAlgo.Platform.Features.Profiles;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed record MarketplaceStoredObject(
    string Uri,
    string Sha256,
    long Length);

public interface IMarketplaceArtifactStore
{
    ValueTask<MarketplaceStoredObject> PutQuarantineAsync(
        string category,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken);

    ValueTask<ReadOnlyMemory<byte>> ReadAsync(
        string uri,
        CancellationToken cancellationToken);

    ValueTask<MarketplaceStoredObject> PromoteApprovedAsync(
        string quarantineUri,
        Guid releaseId,
        string fileName,
        string expectedSha256,
        CancellationToken cancellationToken);

    ValueTask<MarketplaceStoredObject> PutApprovedMetadataAsync(
        Guid releaseId,
        string fileName,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken);
}

public sealed class InMemoryMarketplaceArtifactStore : IMarketplaceArtifactStore
{
    private readonly ConcurrentDictionary<string, byte[]> objects = new(StringComparer.Ordinal);

    public ValueTask<MarketplaceStoredObject> PutQuarantineAsync(
        string category,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedCategory = NormalizeSegment(category, nameof(category));
        var bytes = content.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var uri = $"marketplace-quarantine://{normalizedCategory}/{hash}";
        PutImmutable(uri, bytes);
        return ValueTask.FromResult(new MarketplaceStoredObject(uri, hash, bytes.LongLength));
    }

    public ValueTask<ReadOnlyMemory<byte>> ReadAsync(
        string uri,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!objects.TryGetValue(uri, out var bytes))
        {
            throw new PlatformNotFoundException("The immutable marketplace object was not found.");
        }

        return ValueTask.FromResult<ReadOnlyMemory<byte>>(bytes.ToArray());
    }

    public async ValueTask<MarketplaceStoredObject> PromoteApprovedAsync(
        string quarantineUri,
        Guid releaseId,
        string fileName,
        string expectedSha256,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadAsync(quarantineUri, cancellationToken);
        var actualHash = Convert.ToHexStringLower(SHA256.HashData(bytes.Span));
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actualHash),
                ParseSha256(expectedSha256)))
        {
            throw new InvalidOperationException("The quarantined marketplace object hash changed before promotion.");
        }

        var normalizedFileName = NormalizeSegment(fileName, nameof(fileName));
        var uri = $"https://marketplace-artifacts.development.invalid/releases/{releaseId:D}/{actualHash}/{normalizedFileName}";
        PutImmutable(uri, bytes.ToArray());
        return new MarketplaceStoredObject(uri, actualHash, bytes.Length);
    }

    public ValueTask<MarketplaceStoredObject> PutApprovedMetadataAsync(
        Guid releaseId,
        string fileName,
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var normalizedFileName = NormalizeSegment(fileName, nameof(fileName));
        var bytes = content.ToArray();
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
        var uri = $"https://marketplace-artifacts.development.invalid/releases/{releaseId:D}/{hash}/{normalizedFileName}";
        PutImmutable(uri, bytes);
        return ValueTask.FromResult(new MarketplaceStoredObject(uri, hash, bytes.LongLength));
    }

    private void PutImmutable(string uri, byte[] bytes)
    {
        var stored = objects.GetOrAdd(uri, bytes);
        if (!stored.AsSpan().SequenceEqual(bytes))
        {
            throw new InvalidOperationException("An immutable marketplace object URI already contains different bytes.");
        }
    }

    private static string NormalizeSegment(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.')))
        {
            throw new ArgumentException("Marketplace object segments must be non-empty safe ASCII names.", parameterName);
        }

        return value;
    }

    private static byte[] ParseSha256(string value)
    {
        try
        {
            var bytes = Convert.FromHexString(value);
            return bytes.Length == 32
                ? bytes
                : throw new FormatException();
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Expected a 64-character SHA-256 value.", nameof(value), exception);
        }
    }
}
