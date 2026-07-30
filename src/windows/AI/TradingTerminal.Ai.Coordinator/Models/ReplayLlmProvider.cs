using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;

namespace TradingTerminal.Ai.Coordinator.Models;

/// <summary>One ordered, immutable completion or failure in a provider replay JSONL file.</summary>
public sealed record LlmReplayEntry
{
    public required string SchemaVersion { get; init; }
    public required int Sequence { get; init; }
    public required string ProviderId { get; init; }
    public required string ModelId { get; init; }
    public required string RequestSha256 { get; init; }
    public LlmCompletion? Completion { get; init; }
    public LlmFailure? Failure { get; init; }
}

/// <summary>
/// Strict network-free replay. Calls must match the next entry's canonical request hash; a mismatch
/// never advances the cursor and there is no live-provider fallback.
/// </summary>
public sealed class ReplayLlmProvider : ILlmProvider, IResumableLlmProvider
{
    public const string ReplaySchemaVersion = "llm-replay/v1";
    public const int MaxReplayFileBytes = 100_000_000;
    public const int MaxReplayEntries = 1_000;
    public const int MaxReplayLineCharacters = 2_000_000;

    private static readonly JsonSerializerOptions ReplayJson = CreateJsonOptions();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly IReadOnlyList<LlmReplayEntry> _entries;
    private readonly object _gate = new();
    private int _next;

    public ReplayLlmProvider(string replayPath)
        : this(Load(ReadReplayBytes(replayPath)))
    {
    }

    public ReplayLlmProvider(LlmProviderDescriptor descriptor, string replayPath)
        : this(descriptor, ReadReplayBytes(replayPath))
    {
    }

    public ReplayLlmProvider(LlmProviderDescriptor descriptor, ReadOnlyMemory<byte> replayBytes)
        : this(Load(descriptor, replayBytes))
    {
    }

    public ReplayLlmProvider(LlmProviderDescriptor descriptor, IEnumerable<LlmReplayEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(entries);
        if (string.IsNullOrWhiteSpace(descriptor.ProviderId))
            throw new ArgumentException("The replay provider id is required.", nameof(descriptor));
        if (string.IsNullOrWhiteSpace(descriptor.ModelId))
            throw new ArgumentException("The replay model id is required.", nameof(descriptor));

        Descriptor = descriptor;
        _entries = entries.ToArray();
        ValidateEntries(_entries, descriptor);
    }

    private ReplayLlmProvider(LoadedReplay replay)
        : this(replay.Descriptor, replay.Entries)
    {
    }

    public LlmProviderDescriptor Descriptor { get; }

    public int RemainingEntries
    {
        get { lock (_gate) return _entries.Count - _next; }
    }

    public void ResumeAfter(int consumedRequestCount)
    {
        if (consumedRequestCount < 0 || consumedRequestCount > _entries.Count)
        {
            throw new InvalidDataException(
                $"Replay cannot resume after {consumedRequestCount} requests; it contains {_entries.Count} entries.");
        }

        lock (_gate)
        {
            _next = consumedRequestCount;
        }
    }

    public Task<LlmCallResult> CompleteAsync(LlmRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (LlmRequestValidation.Validate(request) is { } invalid)
            return Task.FromResult(invalid);

        var actualHash = ComputeRequestSha256(Descriptor, request);
        lock (_gate)
        {
            if (_next >= _entries.Count)
            {
                return Task.FromResult(LlmCallResult.Failed(
                    LlmFailureKinds.ReplayExhausted,
                    "The replay has no remaining entries."));
            }

            var entry = _entries[_next];
            if (!entry.RequestSha256.Equals(actualHash, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(LlmCallResult.Failed(
                    LlmFailureKinds.ReplayMismatch,
                    $"Replay entry {entry.Sequence} does not match the canonical request."));
            }

            _next++;
            return Task.FromResult(entry.Completion is { } completion
                ? LlmCallResult.Success(completion)
                : new LlmCallResult(null, entry.Failure));
        }
    }

    /// <summary>
    /// Hashes the semantic request plus provider/model identity. The caller-generated request id is
    /// deliberately excluded so the same workflow can be replayed under a new run id.
    /// </summary>
    public static string ComputeRequestSha256(LlmProviderDescriptor descriptor, LlmRequest request)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(request);

        var canonical = new CanonicalRequest(
            descriptor.ProviderId,
            descriptor.ModelId,
            request.Role,
            request.SystemPrompt,
            request.Messages,
            request.MaxOutputTokens,
            request.MaxResponseBytes,
            request.Temperature);
        return ContentHasher.HashBytes(JsonSerializer.SerializeToUtf8Bytes(canonical, ReplayJson));
    }

    /// <summary>Serializes one compact line suitable for a replay JSONL fixture.</summary>
    public static string SerializeEntry(LlmReplayEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return JsonSerializer.Serialize(entry, ReplayJson);
    }

    private static LoadedReplay Load(ReadOnlyMemory<byte> replayBytes)
    {
        var entries = LoadEntries(replayBytes);
        if (entries.Count == 0) throw new InvalidDataException("The replay file is empty.");
        var first = entries[0];
        var descriptor = new LlmProviderDescriptor(first.ProviderId, first.ModelId, "replay", null);
        return new LoadedReplay(descriptor, entries);
    }

    private static LoadedReplay Load(
        LlmProviderDescriptor descriptor,
        ReadOnlyMemory<byte> replayBytes)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        if (descriptor.ReplaySha256 is { } expectedSha256)
        {
            var actualSha256 = ContentHasher.HashBytes(replayBytes.Span);
            if (!StringComparer.OrdinalIgnoreCase.Equals(actualSha256, expectedSha256))
            {
                throw new InvalidDataException("Replay file does not match its approved SHA-256 binding.");
            }
        }

        return new LoadedReplay(descriptor, LoadEntries(replayBytes));
    }

    private static IReadOnlyList<LlmReplayEntry> LoadEntries(ReadOnlyMemory<byte> replayBytes)
    {
        if (replayBytes.Length > MaxReplayFileBytes)
        {
            throw new InvalidDataException(
                $"Replay exceeds the {MaxReplayFileBytes:N0}-byte input limit.");
        }

        var entries = new List<LlmReplayEntry>();
        var lineNumber = 0;
        string content;
        try
        {
            content = StrictUtf8.GetString(replayBytes.Span);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("Replay must be valid UTF-8.", exception);
        }

        using var reader = new StringReader(content);
        while (reader.ReadLine() is { } line)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (line.Length > MaxReplayLineCharacters)
                throw new InvalidDataException($"Replay line {lineNumber} exceeds the input limit.");
            if (entries.Count >= MaxReplayEntries)
                throw new InvalidDataException($"Replay exceeds the {MaxReplayEntries:N0}-entry input limit.");
            try
            {
                entries.Add(JsonSerializer.Deserialize<LlmReplayEntry>(line, ReplayJson)
                    ?? throw new InvalidDataException($"Replay line {lineNumber} is empty."));
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException($"Replay line {lineNumber} is invalid JSON.", ex);
            }
        }
        return entries;
    }

    private static byte[] ReadReplayBytes(string replayPath)
    {
        if (string.IsNullOrWhiteSpace(replayPath))
            throw new ArgumentException("The replay path is required.", nameof(replayPath));

        using var stream = new FileStream(
            Path.GetFullPath(replayPath),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length > MaxReplayFileBytes)
        {
            throw new InvalidDataException(
                $"Replay exceeds the {MaxReplayFileBytes:N0}-byte input limit.");
        }

        using var snapshot = new MemoryStream((int)stream.Length);
        stream.CopyTo(snapshot);
        if (snapshot.Length > MaxReplayFileBytes)
        {
            throw new InvalidDataException(
                $"Replay exceeds the {MaxReplayFileBytes:N0}-byte input limit.");
        }
        return snapshot.ToArray();
    }

    private static void ValidateEntries(
        IReadOnlyList<LlmReplayEntry> entries,
        LlmProviderDescriptor descriptor)
    {
        if (entries.Count == 0) throw new InvalidDataException("The replay contains no entries.");

        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            var expectedSequence = index + 1;
            if (!StringComparer.Ordinal.Equals(entry.SchemaVersion, ReplaySchemaVersion))
                throw new InvalidDataException($"Replay entry {expectedSequence} has an unsupported schema version.");
            if (entry.Sequence != expectedSequence)
                throw new InvalidDataException($"Replay entry {expectedSequence} is out of order.");
            if (!StringComparer.Ordinal.Equals(entry.ProviderId, descriptor.ProviderId) ||
                !StringComparer.Ordinal.Equals(entry.ModelId, descriptor.ModelId))
                throw new InvalidDataException($"Replay entry {expectedSequence} targets a different provider or model.");
            if (!IsSha256(entry.RequestSha256))
                throw new InvalidDataException($"Replay entry {expectedSequence} has an invalid request hash.");
            if ((entry.Completion is null) == (entry.Failure is null))
                throw new InvalidDataException(
                    $"Replay entry {expectedSequence} must contain exactly one completion or failure.");
            if (entry.Completion is { } completion && string.IsNullOrWhiteSpace(completion.Text))
                throw new InvalidDataException($"Replay entry {expectedSequence} has no completion text.");
            if (entry.Completion is { } terminalCompletion &&
                !StringComparer.Ordinal.Equals(terminalCompletion.FinishReason, "stop"))
                throw new InvalidDataException($"Replay entry {expectedSequence} is not an untruncated 'stop' completion.");
            if (entry.Completion?.Usage is { } usage &&
                (usage.InputTokens < 0 || usage.OutputTokens < 0))
                throw new InvalidDataException($"Replay entry {expectedSequence} has invalid token usage.");
            if (entry.Completion is { ResponseBytes: < 0 })
                throw new InvalidDataException($"Replay entry {expectedSequence} has invalid response bytes.");
            if (entry.Failure is { } failure &&
                (string.IsNullOrWhiteSpace(failure.Kind) || string.IsNullOrWhiteSpace(failure.SafeMessage)))
                throw new InvalidDataException($"Replay entry {expectedSequence} has an invalid failure.");
            if (entry.Failure?.ResponseBytes is < 0)
                throw new InvalidDataException($"Replay entry {expectedSequence} has invalid failure response bytes.");
        }
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            WriteIndented = false
        };
        options.Converters.Add(new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false));
        return options;
    }

    private sealed record CanonicalRequest(
        string ProviderId,
        string ModelId,
        CoordinatorRole Role,
        string SystemPrompt,
        IReadOnlyList<LlmMessage> Messages,
        int MaxOutputTokens,
        int MaxResponseBytes,
        decimal Temperature);

    private sealed record LoadedReplay(
        LlmProviderDescriptor Descriptor,
        IReadOnlyList<LlmReplayEntry> Entries);
}
