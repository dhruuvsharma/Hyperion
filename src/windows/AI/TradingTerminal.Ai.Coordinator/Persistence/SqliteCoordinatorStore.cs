using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Persistence;

public sealed class SqliteCoordinatorStore : ICoordinatorStore
{
    private const string Schema = """
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS coordinator_runs (
            run_id TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            status TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS coordinator_events (
            run_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            previous_sha256 TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            occurred_at_utc TEXT NOT NULL,
            PRIMARY KEY (run_id, sequence),
            FOREIGN KEY (run_id) REFERENCES coordinator_runs(run_id)
        );
        CREATE INDEX IF NOT EXISTS ix_coordinator_runs_updated
            ON coordinator_runs(updated_at_utc DESC);
        """;

    private readonly string _connectionString;

    public SqliteCoordinatorStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        DatabasePath = Path.GetFullPath(databasePath);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            ForeignKeys = true
        }.ToString();
    }

    public string DatabasePath { get; }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = Schema;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<CoordinatorRunSnapshot> CreateAsync(
        CoordinatorRunSnapshot snapshot,
        string eventType,
        object eventPayload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);

        var created = snapshot with { Version = 0, UpdatedAtUtc = DateTimeOffset.UtcNow };
        var createdJson = JsonSerializer.Serialize(created, CoordinatorJson.Options);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO coordinator_runs(run_id, version, status, snapshot_json, updated_at_utc)
                VALUES ($runId, $version, $status, $snapshot, $updatedAt);
                """;
            command.Parameters.AddWithValue("$runId", created.Spec.RunId.ToString("D"));
            command.Parameters.AddWithValue("$version", created.Version);
            command.Parameters.AddWithValue("$status", created.Status.ToString());
            command.Parameters.AddWithValue("$snapshot", createdJson);
            command.Parameters.AddWithValue("$updatedAt", Format(created.UpdatedAtUtc));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await InsertEventAsync(
            connection,
            transaction,
            created.Spec.RunId,
            1,
            eventType,
            SerializeEventPayload(createdJson, eventPayload),
            string.Empty,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return created;
    }

    public async Task<CoordinatorRunSnapshot?> GetAsync(Guid runId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT snapshot_json FROM coordinator_runs WHERE run_id = $runId;";
        command.Parameters.AddWithValue("$runId", runId.ToString("D"));
        var value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value is string json ? DeserializeSnapshot(json) : null;
    }

    public async Task<IReadOnlyList<CoordinatorRunSnapshot>> ListAsync(CancellationToken cancellationToken = default)
    {
        var result = new List<CoordinatorRunSnapshot>();
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT snapshot_json FROM coordinator_runs ORDER BY updated_at_utc DESC;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(DeserializeSnapshot(reader.GetString(0)));
        }

        return result;
    }

    public async Task<CoordinatorRunSnapshot> AppendAsync(
        CoordinatorRunSnapshot snapshot,
        long expectedVersion,
        string eventType,
        object eventPayload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);

        long actualVersion;
        long sequence;
        string previousSha256;
        await using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = """
                SELECT r.version,
                       COALESCE((SELECT MAX(e.sequence) FROM coordinator_events e WHERE e.run_id = r.run_id), 0),
                       COALESCE((SELECT e.sha256 FROM coordinator_events e WHERE e.run_id = r.run_id ORDER BY e.sequence DESC LIMIT 1), '')
                FROM coordinator_runs r WHERE r.run_id = $runId;
                """;
            read.Parameters.AddWithValue("$runId", snapshot.Spec.RunId.ToString("D"));
            await using var reader = await read.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new KeyNotFoundException($"Coordinator run '{snapshot.Spec.RunId:D}' was not found.");
            }

            actualVersion = reader.GetInt64(0);
            sequence = reader.GetInt64(1) + 1;
            previousSha256 = reader.GetString(2);
        }

        if (actualVersion != expectedVersion)
        {
            throw new CoordinatorConcurrencyException(
                $"Run '{snapshot.Spec.RunId:D}' expected version {expectedVersion} but found {actualVersion}.");
        }

        var next = snapshot with
        {
            Version = expectedVersion + 1,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        var nextJson = JsonSerializer.Serialize(next, CoordinatorJson.Options);
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE coordinator_runs
                SET version = $nextVersion, status = $status, snapshot_json = $snapshot, updated_at_utc = $updatedAt
                WHERE run_id = $runId AND version = $expectedVersion;
                """;
            update.Parameters.AddWithValue("$nextVersion", next.Version);
            update.Parameters.AddWithValue("$status", next.Status.ToString());
            update.Parameters.AddWithValue("$snapshot", nextJson);
            update.Parameters.AddWithValue("$updatedAt", Format(next.UpdatedAtUtc));
            update.Parameters.AddWithValue("$runId", next.Spec.RunId.ToString("D"));
            update.Parameters.AddWithValue("$expectedVersion", expectedVersion);
            var rows = await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            if (rows != 1)
            {
                throw new CoordinatorConcurrencyException($"Run '{snapshot.Spec.RunId:D}' changed concurrently.");
            }
        }

        await InsertEventAsync(
            connection,
            transaction,
            next.Spec.RunId,
            sequence,
            eventType,
            SerializeEventPayload(nextJson, eventPayload),
            previousSha256,
            DateTimeOffset.UtcNow,
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return next;
    }

    public async Task<IReadOnlyList<CoordinatorEventRecord>> ReadEventsAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return await ReadEventsAsync(connection, null, runId, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<CoordinatorEventRecord>> ReadEventsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        Guid runId,
        CancellationToken cancellationToken)
    {
        var result = new List<CoordinatorEventRecord>();
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT sequence, event_type, payload_json, previous_sha256, sha256, occurred_at_utc
            FROM coordinator_events WHERE run_id = $runId ORDER BY sequence;
            """;
        command.Parameters.AddWithValue("$runId", runId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new CoordinatorEventRecord(
                runId,
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                DateTimeOffset.Parse(reader.GetString(5), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)));
        }

        return result;
    }

    public async Task VerifyEventChainAsync(Guid runId, CancellationToken cancellationToken = default) =>
        _ = await GetVerifiedAsync(runId, cancellationToken).ConfigureAwait(false);

    public async Task<CoordinatorRunSnapshot> GetVerifiedAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        using var transaction = connection.BeginTransaction();
        var events = await ReadEventsAsync(connection, transaction, runId, cancellationToken).ConfigureAwait(false);
        if (events.Count == 0)
        {
            throw new CoordinatorIntegrityException($"Run '{runId:D}' has no audit events.");
        }

        var previous = string.Empty;
        long expectedSequence = 1;
        foreach (var item in events)
        {
            if (item.Sequence != expectedSequence || !StringComparer.Ordinal.Equals(item.PreviousSha256, previous))
            {
                throw new CoordinatorIntegrityException($"Event chain linkage failed at sequence {item.Sequence}.");
            }

            var expectedHash = HashEvent(
                item.RunId,
                item.Sequence,
                item.Type,
                item.PayloadJson,
                item.PreviousSha256,
                item.OccurredAtUtc);
            if (!StringComparer.Ordinal.Equals(item.Sha256, expectedHash))
            {
                throw new CoordinatorIntegrityException($"Event hash failed at sequence {item.Sequence}.");
            }

            previous = item.Sha256;
            expectedSequence++;
        }

        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT snapshot_json, version FROM coordinator_runs WHERE run_id = $runId;";
        command.Parameters.AddWithValue("$runId", runId.ToString("D"));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new CoordinatorIntegrityException($"Run '{runId:D}' projection is missing.");
        }

        var snapshotJson = reader.GetString(0);
        var projectionVersion = reader.GetInt64(1);
        var projectedSnapshot = DeserializeSnapshot(snapshotJson);
        if (projectedSnapshot.Version != projectionVersion || events[^1].Sequence != projectionVersion + 1)
        {
            throw new CoordinatorIntegrityException("Run projection version does not match the audit sequence.");
        }

        string boundSnapshotSha256;
        try
        {
            using var payload = JsonDocument.Parse(events[^1].PayloadJson);
            if (!payload.RootElement.TryGetProperty("snapshotSha256", out var binding) ||
                binding.ValueKind != JsonValueKind.String ||
                binding.GetString() is not { } parsedBinding)
            {
                throw new CoordinatorIntegrityException("Latest event has no snapshot binding.");
            }

            boundSnapshotSha256 = parsedBinding;
        }
        catch (JsonException exception)
        {
            throw new CoordinatorIntegrityException($"Latest event snapshot binding is invalid: {exception.Message}");
        }

        if (!StringComparer.Ordinal.Equals(ContentHasher.HashUtf8(snapshotJson), boundSnapshotSha256))
        {
            throw new CoordinatorIntegrityException("Run projection does not match the latest audit event.");
        }
        return projectedSnapshot;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static async Task InsertEventAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid runId,
        long sequence,
        string eventType,
        string payloadJson,
        string previousSha256,
        DateTimeOffset occurredAtUtc,
        CancellationToken cancellationToken)
    {
        var sha256 = HashEvent(runId, sequence, eventType, payloadJson, previousSha256, occurredAtUtc);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO coordinator_events(
                run_id, sequence, event_type, payload_json, previous_sha256, sha256, occurred_at_utc)
            VALUES ($runId, $sequence, $eventType, $payload, $previous, $sha256, $occurredAt);
            """;
        command.Parameters.AddWithValue("$runId", runId.ToString("D"));
        command.Parameters.AddWithValue("$sequence", sequence);
        command.Parameters.AddWithValue("$eventType", eventType);
        command.Parameters.AddWithValue("$payload", payloadJson);
        command.Parameters.AddWithValue("$previous", previousSha256);
        command.Parameters.AddWithValue("$sha256", sha256);
        command.Parameters.AddWithValue("$occurredAt", Format(occurredAtUtc));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string HashEvent(
        Guid runId,
        long sequence,
        string eventType,
        string payloadJson,
        string previousSha256,
        DateTimeOffset occurredAtUtc) =>
        ContentHasher.HashUtf8(string.Join(
            '\n',
            runId.ToString("D"),
            sequence.ToString(CultureInfo.InvariantCulture),
            eventType,
            Format(occurredAtUtc),
            previousSha256,
            payloadJson));

    private static CoordinatorRunSnapshot DeserializeSnapshot(string json) =>
        JsonSerializer.Deserialize<CoordinatorRunSnapshot>(json, CoordinatorJson.Options)
        ?? throw new CoordinatorIntegrityException("Stored run snapshot contained JSON null.");

    private static string SerializeEventPayload(string snapshotJson, object eventPayload) =>
        JsonSerializer.Serialize(
            new
            {
                snapshotSha256 = ContentHasher.HashUtf8(snapshotJson),
                data = eventPayload
            },
            CoordinatorJson.Options);

    private static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
}
