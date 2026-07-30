using System.Buffers;
using System.IO;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TradingTerminal.App.Authoring;

public interface IHostedStrategyRunBookmarkStore
{
    HostedStrategyRunBookmarkReadResult Read();

    bool TryCreate(HostedStrategyRunBookmark bookmark);

    bool TryUpdate(HostedStrategyRunBookmark bookmark);

    bool TryClear(HostedStrategyRunBookmarkReadResult expected);
}

public enum HostedStrategyRunBookmarkReadState
{
    Missing,
    Valid,
    InvalidOrUnreadable,
}

public sealed record HostedStrategyRunBookmarkReadResult(
    HostedStrategyRunBookmarkReadState State,
    HostedStrategyRunBookmark? Bookmark = null);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record HostedStrategyRunBookmark(
    string SchemaVersion,
    string ConnectionBinding,
    string Objective,
    string IdempotencyKey,
    Guid? RunId,
    string? SpecSha256,
    DateTimeOffset UpdatedAtUtc)
{
    public const string CurrentSchemaVersion = "daxalgo.hosted-strategy-run-bookmark/v1";
}

/// <summary>
/// Persists the one resumable hosted-authoring identity. The bookmark contains no credentials or
/// generated source, is read through a strict bounded schema, and is replaced atomically.
/// </summary>
public sealed class HostedStrategyRunBookmarkStore : IHostedStrategyRunBookmarkStore
{
    // A 20,000-character objective can expand to roughly 120 KB when JSON escapes every UTF-16 code
    // unit, so the byte cap must bound malformed input without rejecting valid objectives.
    private const int MaximumBookmarkBytes = 256 * 1024;
    private const int MaximumObjectiveCharacters = 20_000;
    private const int MaximumIdempotencyKeyCharacters = 100;
    private const int JsonDepthLimit = 4;
    private static readonly string[] PropertyNames =
    [
        "schemaVersion",
        "connectionBinding",
        "objective",
        "idempotencyKey",
        "runId",
        "specSha256",
        "updatedAtUtc",
    ];
    private static readonly HashSet<string> RequiredProperties = new(PropertyNames, StringComparer.Ordinal);
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = JsonDepthLimit,
    };

    private readonly string _path;
    private readonly string _directory;
    private readonly string _lockPath;

    public HostedStrategyRunBookmarkStore()
        : this(DefaultPath)
    {
    }

    public HostedStrategyRunBookmarkStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _directory = Path.GetDirectoryName(_path)
            ?? throw new ArgumentException("Hosted bookmark path must include a directory.", nameof(path));
        _lockPath = $"{_path}.lock";
        if (string.IsNullOrWhiteSpace(Path.GetFileName(_path)))
            throw new ArgumentException("Hosted bookmark path must include a file name.", nameof(path));
    }

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DaxAlgo Terminal",
        "authoring",
        "hosted-run.json");

    public HostedStrategyRunBookmarkReadResult Read()
    {
        try
        {
            if (!File.Exists(_path))
                return Directory.Exists(_path)
                    ? InvalidRead()
                    : new HostedStrategyRunBookmarkReadResult(HostedStrategyRunBookmarkReadState.Missing);

            using var input = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                4096,
                FileOptions.SequentialScan);
            var bytes = ReadBounded(input);
            if (bytes is null || HasUtf8Bom(bytes)) return InvalidRead();

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = JsonDepthLimit,
            });
            if (!HasExactShape(document.RootElement)) return InvalidRead();

            var bookmark = JsonSerializer.Deserialize<HostedStrategyRunBookmark>(bytes, Json);
            return IsValid(bookmark)
                ? new HostedStrategyRunBookmarkReadResult(HostedStrategyRunBookmarkReadState.Valid, bookmark)
                : InvalidRead();
        }
        catch (Exception exception) when (IsSafeReadFailure(exception))
        {
            return InvalidRead();
        }
    }

    private static HostedStrategyRunBookmarkReadResult InvalidRead() =>
        new(HostedStrategyRunBookmarkReadState.InvalidOrUnreadable);

    public bool TryCreate(HostedStrategyRunBookmark bookmark) => WithExclusiveLock(() =>
    {
        if (Read().State != HostedStrategyRunBookmarkReadState.Missing) return false;
        return Write(bookmark);
    });

    public bool TryUpdate(HostedStrategyRunBookmark bookmark) => WithExclusiveLock(() =>
    {
        var current = Read();
        if (current.State != HostedStrategyRunBookmarkReadState.Valid || current.Bookmark is null ||
            current.Bookmark.ConnectionBinding != bookmark.ConnectionBinding ||
            current.Bookmark.Objective != bookmark.Objective ||
            current.Bookmark.IdempotencyKey != bookmark.IdempotencyKey ||
            current.Bookmark.RunId is not null && current.Bookmark.RunId != bookmark.RunId ||
            current.Bookmark.SpecSha256 is not null && current.Bookmark.SpecSha256 != bookmark.SpecSha256)
        {
            return false;
        }
        return Write(bookmark);
    });

    private bool Write(HostedStrategyRunBookmark bookmark)
    {
        ArgumentNullException.ThrowIfNull(bookmark);
        if (!IsValid(bookmark)) return false;

        byte[] bytes;
        try
        {
            bytes = JsonSerializer.SerializeToUtf8Bytes(bookmark, Json);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            return false;
        }
        if (bytes.Length is 0 or > MaximumBookmarkBytes) return false;

        string? temporaryPath = null;
        try
        {
            Directory.CreateDirectory(_directory);
            temporaryPath = Path.Combine(
                _directory,
                $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
            using (var output = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, _path, overwrite: true);
            temporaryPath = null;
            return true;
        }
        catch (Exception exception) when (IsSafeIoFailure(exception))
        {
            return false;
        }
        finally
        {
            if (temporaryPath is not null) TryDelete(temporaryPath);
        }
    }

    public bool TryClear(HostedStrategyRunBookmarkReadResult expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        return WithExclusiveLock(() =>
        {
            var current = Read();
            if (current.State != expected.State || current.Bookmark != expected.Bookmark) return false;
            File.Delete(_path);
            return true;
        });
    }

    private bool WithExclusiveLock(Func<bool> action)
    {
        try
        {
            Directory.CreateDirectory(_directory);
            using var gate = new FileStream(
                _lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
            return action();
        }
        catch (Exception exception) when (IsSafeIoFailure(exception))
        {
            return false;
        }
    }

    private static byte[]? ReadBounded(Stream input)
    {
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            if (output.Length + read > MaximumBookmarkBytes) return null;
            output.Write(buffer, 0, read);
        }
        return output.Length == 0 ? null : output.ToArray();
    }

    private static bool HasUtf8Bom(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf;

    private static bool HasExactShape(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return false;

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
        {
            if (!RequiredProperties.Contains(property.Name) || !names.Add(property.Name)) return false;
        }
        return names.Count == RequiredProperties.Count;
    }

    private static bool IsValid(HostedStrategyRunBookmark? bookmark)
    {
        if (bookmark is null ||
            !StringComparer.Ordinal.Equals(
                bookmark.SchemaVersion,
                HostedStrategyRunBookmark.CurrentSchemaVersion) ||
            !IsCanonicalSha256(bookmark.ConnectionBinding) ||
            !IsValidObjective(bookmark.Objective) ||
            !IsValidIdempotencyKey(bookmark.IdempotencyKey) ||
            bookmark.RunId == Guid.Empty ||
            bookmark.UpdatedAtUtc == default ||
            bookmark.UpdatedAtUtc.Offset != TimeSpan.Zero)
        {
            return false;
        }

        var hasRun = bookmark.RunId.HasValue;
        var hasSpec = bookmark.SpecSha256 is not null;
        return hasRun == hasSpec &&
               (!hasSpec || IsCanonicalSha256(bookmark.SpecSha256));
    }

    private static bool IsValidObjective(string? value) =>
        value is { Length: >= 1 and <= MaximumObjectiveCharacters } &&
        !string.IsNullOrWhiteSpace(value) &&
        value == value.Trim() &&
        value.IndexOf('\0') < 0 &&
        IsValidUtf16(value);

    private static bool IsValidIdempotencyKey(string? value) =>
        value is { Length: >= 1 and <= MaximumIdempotencyKeyCharacters } &&
        value.All(character => character is >= '!' and <= '~');

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsValidUtf16(string value)
    {
        var remaining = value.AsSpan();
        while (!remaining.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(remaining, out _, out var consumed) != OperationStatus.Done)
                return false;
            remaining = remaining[consumed..];
        }
        return true;
    }

    private static bool IsSafeReadFailure(Exception exception) =>
        IsSafeIoFailure(exception) || exception is JsonException;

    private static bool IsSafeIoFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or NotSupportedException or SecurityException;

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (IsSafeIoFailure(exception))
        {
        }
    }
}
