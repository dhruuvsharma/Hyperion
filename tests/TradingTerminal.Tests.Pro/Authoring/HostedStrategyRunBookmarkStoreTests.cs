using System.IO;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using TradingTerminal.App.Authoring;
using Xunit;

namespace TradingTerminal.Tests.Authoring;

public sealed class HostedStrategyRunBookmarkStoreTests
{
    [Fact]
    public void Save_load_replace_and_clear_round_trip_only_the_closed_bookmark_schema()
    {
        using var directory = new TestDirectory();
        var path = directory.PathFor("hosted-run.json");
        var store = new HostedStrategyRunBookmarkStore(path);
        var first = CreateBookmark("first-objective", runId: null, specSha256: null);
        var second = first with
        {
            RunId = Guid.NewGuid(),
            SpecSha256 = new string('a', 64),
            UpdatedAtUtc = first.UpdatedAtUtc.AddMinutes(1),
        };

        store.TryCreate(first).Should().BeTrue();
        store.Read().Should().BeEquivalentTo(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid, first));
        store.TryUpdate(second).Should().BeTrue();
        store.Read().Should().BeEquivalentTo(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid, second));

        var json = File.ReadAllText(path, Encoding.UTF8);
        using var document = JsonDocument.Parse(json);
        document.RootElement.EnumerateObject().Select(property => property.Name).Should().BeEquivalentTo(
            ["schemaVersion", "connectionBinding", "objective", "idempotencyKey", "runId", "specSha256", "updatedAtUtc"],
            options => options.WithStrictOrdering());
        json.Should().NotContain("token").And.NotContain("authorization").And.NotContain("credential");
        Directory.EnumerateFiles(directory.Path, "*.tmp").Should().BeEmpty();

        store.TryClear(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid,
            second)).Should().BeTrue();
        store.Read().State.Should().Be(HostedStrategyRunBookmarkReadState.Missing);
        store.TryClear(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Missing)).Should().BeTrue(
            "clearing an absent bookmark is idempotent");
    }

    [Fact]
    public void Load_rejects_unknown_missing_duplicate_bom_and_oversized_json_without_throwing()
    {
        using var directory = new TestDirectory();
        var path = directory.PathFor("hosted-run.json");
        var store = new HostedStrategyRunBookmarkStore(path);
        var valid = JsonSerializer.Serialize(CreateBookmark("bounded-objective", null, null),
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        var malformed = new[]
        {
            "{}",
            valid[..^1] + ",\"accessToken\":\"secret\"}",
            valid[..^1] + ",\"objective\":\"duplicate\"}",
            valid.Replace(",\"updatedAtUtc\":", ",\"removedUpdatedAtUtc\":"),
            valid.Replace(
                $"\"schemaVersion\":\"{HostedStrategyRunBookmark.CurrentSchemaVersion}\"",
                "\"schemaVersion\":\"unsupported/v2\""),
            valid.Replace("\"specSha256\":null", $"\"specSha256\":\"{new string('A', 64)}\""),
        };

        foreach (var candidate in malformed)
        {
            File.WriteAllText(path, candidate, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            store.Read().State.Should().Be(HostedStrategyRunBookmarkReadState.InvalidOrUnreadable, candidate);
        }

        File.WriteAllText(path, valid, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        store.Read().State.Should().Be(
            HostedStrategyRunBookmarkReadState.InvalidOrUnreadable,
            "bookmark JSON must be BOM-less UTF-8");

        File.WriteAllText(path, new string('x', 300_000), new UTF8Encoding(false));
        store.Read().State.Should().Be(
            HostedStrategyRunBookmarkReadState.InvalidOrUnreadable,
            "bookmark input is bounded before JSON parsing");
    }

    [Fact]
    public void Invalid_save_does_not_replace_the_existing_bookmark()
    {
        using var directory = new TestDirectory();
        var path = directory.PathFor("hosted-run.json");
        var store = new HostedStrategyRunBookmarkStore(path);
        var valid = CreateBookmark("preserved-objective", Guid.NewGuid(), new string('b', 64));
        store.TryCreate(valid).Should().BeTrue();
        var before = File.ReadAllBytes(path);

        var invalidBookmarks = new[]
        {
            valid with { SchemaVersion = "unsupported/v2" },
            valid with { ConnectionBinding = new string('A', 64) },
            valid with { Objective = " objective-with-unbound-whitespace " },
            valid with { IdempotencyKey = "contains whitespace" },
            valid with { RunId = null },
            valid with { SpecSha256 = new string('B', 64) },
            valid with { UpdatedAtUtc = valid.UpdatedAtUtc.ToOffset(TimeSpan.FromHours(1)) },
        };

        foreach (var invalid in invalidBookmarks)
            store.TryUpdate(invalid).Should().BeFalse();

        File.ReadAllBytes(path).Should().Equal(before);
        store.Read().Bookmark.Should().BeEquivalentTo(valid);
    }

    [Fact]
    public void Io_failures_are_reported_without_throwing_or_leaving_temporary_files()
    {
        using var directory = new TestDirectory();
        var path = directory.PathFor("target-is-a-directory");
        Directory.CreateDirectory(path);
        var store = new HostedStrategyRunBookmarkStore(path);

        store.Read().State.Should().Be(HostedStrategyRunBookmarkReadState.InvalidOrUnreadable);
        store.TryCreate(CreateBookmark("objective", null, null)).Should().BeFalse();
        store.TryClear(new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.InvalidOrUnreadable)).Should().BeFalse();
        Directory.EnumerateFiles(directory.Path, "*.tmp").Should().BeEmpty();
    }

    [Fact]
    public void Competing_process_cannot_replace_an_existing_recovery_identity()
    {
        using var directory = new TestDirectory();
        var path = directory.PathFor("hosted-run.json");
        var firstStore = new HostedStrategyRunBookmarkStore(path);
        var secondStore = new HostedStrategyRunBookmarkStore(path);
        var first = CreateBookmark("first-objective", null, null);
        var competing = CreateBookmark("competing-objective", null, null);

        firstStore.TryCreate(first).Should().BeTrue();
        var staleRead = firstStore.Read();
        var upgraded = first with
        {
            RunId = Guid.NewGuid(),
            SpecSha256 = new string('e', 64),
        };
        firstStore.TryUpdate(upgraded).Should().BeTrue();
        secondStore.TryClear(staleRead).Should().BeFalse();
        secondStore.TryCreate(competing).Should().BeFalse();
        secondStore.TryUpdate(competing with
        {
            RunId = Guid.NewGuid(),
            SpecSha256 = new string('d', 64),
        }).Should().BeFalse();
        firstStore.Read().Bookmark.Should().BeEquivalentTo(upgraded);
    }

    private static HostedStrategyRunBookmark CreateBookmark(
        string objective,
        Guid? runId,
        string? specSha256) => new(
        HostedStrategyRunBookmark.CurrentSchemaVersion,
        new string('c', 64),
        objective,
        $"terminal-strategy-{Guid.NewGuid():N}",
        runId,
        specSha256,
        new DateTimeOffset(2026, 7, 28, 9, 0, 0, TimeSpan.Zero));

    private sealed class TestDirectory : IDisposable
    {
        public TestDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "daxalgo-hosted-bookmark-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public string PathFor(string fileName) => System.IO.Path.Combine(Path, fileName);

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }
    }
}
