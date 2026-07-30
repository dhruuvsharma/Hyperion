using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Persistence;

public sealed class ContentAddressedArtifactStore : ICoordinatorArtifactStore
{
    public ContentAddressedArtifactStore(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        RootPath = Path.GetFullPath(rootPath);
    }

    public string RootPath { get; }

    public async Task<StoredArtifact> PutJsonAsync<T>(T value, CancellationToken cancellationToken = default)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, CoordinatorJson.Options);
        var sha256 = ContentHasher.HashBytes(bytes);
        var relativePath = Path.Combine("sha256", sha256[..2], $"{sha256}.json");
        var fullPath = Resolve(relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

        if (File.Exists(fullPath))
        {
            var existing = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
            if (!existing.AsSpan().SequenceEqual(bytes))
            {
                throw new CoordinatorIntegrityException($"Artifact hash collision at '{relativePath}'.");
            }

            return new StoredArtifact(sha256, relativePath, bytes.LongLength);
        }

        var temporaryPath = $"{fullPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            await File.WriteAllBytesAsync(temporaryPath, bytes, cancellationToken).ConfigureAwait(false);
            try
            {
                File.Move(temporaryPath, fullPath, overwrite: false);
            }
            catch (IOException) when (File.Exists(fullPath))
            {
                var existing = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
                if (!existing.AsSpan().SequenceEqual(bytes))
                {
                    throw new CoordinatorIntegrityException($"Artifact hash collision at '{relativePath}'.");
                }
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return new StoredArtifact(sha256, relativePath, bytes.LongLength);
    }

    public async Task<T> ReadJsonAsync<T>(
        string relativePath,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        var fullPath = Resolve(relativePath);
        var bytes = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
        var actualSha256 = ContentHasher.HashBytes(bytes);
        if (!StringComparer.Ordinal.Equals(actualSha256, expectedSha256))
        {
            throw new CoordinatorIntegrityException(
                $"Artifact '{relativePath}' failed SHA-256 verification.");
        }

        return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
            ?? throw new CoordinatorIntegrityException($"Artifact '{relativePath}' contained JSON null.");
    }

    private string Resolve(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        var fullPath = Path.GetFullPath(Path.Combine(RootPath, relativePath));
        var rootWithSeparator = RootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!fullPath.StartsWith(rootWithSeparator, pathComparison))
        {
            throw new ArgumentException("Artifact path escapes the configured root.", nameof(relativePath));
        }

        return fullPath;
    }
}
