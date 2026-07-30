using System.Buffers.Binary;

namespace DaxAlgo.Platform.VerifierWorker;

internal static class VerifierInputStager
{
    private static ReadOnlySpan<byte> Magic => "DAXVSTG1"u8;
    private const int HeaderBytes = 16;

    public static async Task StageAsync(Stream input, string workPath)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrWhiteSpace(workPath);

        var header = new byte[HeaderBytes];
        await input.ReadExactlyAsync(header);
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new FormatException("The verifier staging frame magic is invalid.");
        }

        var requestLength = BinaryPrimitives.ReadUInt32BigEndian(
            header.AsSpan(Magic.Length, sizeof(uint)));
        var sourceLength = BinaryPrimitives.ReadUInt32BigEndian(
            header.AsSpan(Magic.Length + sizeof(uint), sizeof(uint)));
        if (requestLength is 0 or > HeadlessStrategyVerifier.MaximumRequestBytes
            || sourceLength is 0 or > HeadlessStrategyVerifier.MaximumSourceBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(input),
                "A verifier staging frame length is outside its byte bound.");
        }

        var requestBytes = new byte[requestLength];
        var sourceBytes = new byte[sourceLength];
        await input.ReadExactlyAsync(requestBytes);
        await input.ReadExactlyAsync(sourceBytes);
        var trailing = new byte[1];
        if (await input.ReadAsync(trailing) != 0)
        {
            throw new InvalidDataException("The verifier staging frame contains trailing bytes.");
        }

        var directory = new DirectoryInfo(Path.GetFullPath(workPath));
        if (!directory.Exists
            || directory.LinkTarget is not null
            || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new DirectoryNotFoundException("The verifier staging directory is unavailable.");
        }

        await WriteSnapshotAsync(
            Path.Combine(directory.FullName, "request.json"),
            requestBytes);
        await WriteSnapshotAsync(
            Path.Combine(directory.FullName, "source.cs"),
            sourceBytes);
    }

    private static async Task WriteSnapshotAsync(string path, byte[] bytes)
    {
        await using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 16 * 1024,
            options: FileOptions.Asynchronous | FileOptions.WriteThrough);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
        stream.Flush(flushToDisk: true);
    }
}
