using System.Collections.Concurrent;
using System.Data;
using System.Security.Cryptography;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Features.Marketplace;
using DaxAlgo.Platform.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace DaxAlgo.Platform.Features.Devices;

public sealed class DeviceService(
    PlatformDbContext database,
    IDeviceRegistrationGate registrationGate,
    TimeProvider timeProvider,
    SignalSessionRegistry? signalSessions = null)
{
    public const int MaximumActiveDevices = 2;

    public Task<List<RegisteredDevice>> GetAsync(
        Guid accountId,
        CancellationToken cancellationToken) =>
        database.Devices.AsNoTracking()
            .Where(x => x.AccountId == accountId)
            .OrderByDescending(x => x.LastSeenAt)
            .ToListAsync(cancellationToken);

    public async Task<RegisteredDevice> RegisterAsync(
        Guid accountId,
        Guid deviceId,
        string? displayName,
        CancellationToken cancellationToken) =>
        await RegisterAsync(
            accountId,
            deviceId,
            displayName,
            publicKeySpki: null,
            fingerprintSha256: null,
            cancellationToken);

    public async Task<RegisteredDevice> RegisterAsync(
        Guid accountId,
        Guid deviceId,
        string? displayName,
        string? publicKeySpki,
        string? fingerprintSha256,
        CancellationToken cancellationToken)
    {
        if (deviceId == Guid.Empty)
        {
            throw new PlatformValidationException("Device ID cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(displayName)
            || displayName.Trim().Length is < 1 or > 120)
        {
            throw new PlatformValidationException("Device name must contain 1 to 120 characters.");
        }

        var normalizedName = displayName.Trim();
        var deviceKey = NormalizeDeviceKey(publicKeySpki, fingerprintSha256);
        await using var gate = await registrationGate.EnterAsync(accountId, cancellationToken);
        IDbContextTransaction? transaction = null;
        if (database.Database.IsRelational())
        {
            transaction = await database.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);
        }

        try
        {
            var now = timeProvider.GetUtcNow();
            var existing = await database.Devices.SingleOrDefaultAsync(
                x => x.AccountId == accountId && x.DeviceId == deviceId,
                cancellationToken);
            if (existing is not null)
            {
                if (existing.RevokedAt is not null)
                {
                    throw new PlatformConflictException(
                        "A revoked device ID cannot be registered again.");
                }

                if (deviceKey is not null)
                {
                    if (existing.PublicKeySpki is not null
                        && !string.Equals(
                            existing.PublicKeySpki,
                            deviceKey.Value.PublicKeySpki,
                            StringComparison.Ordinal))
                    {
                        throw new PlatformConflictException(
                            "The registered device key cannot be replaced in place.");
                    }

                    existing.PublicKeySpki = deviceKey.Value.PublicKeySpki;
                    existing.FingerprintSha256 = deviceKey.Value.FingerprintSha256;
                }

                existing.DisplayName = normalizedName;
                existing.LastSeenAt = now;
                await database.SaveChangesAsync(cancellationToken);
                if (transaction is not null)
                {
                    await transaction.CommitAsync(cancellationToken);
                }

                return existing;
            }

            var activeCount = await database.Devices.CountAsync(
                x => x.AccountId == accountId && x.RevokedAt == null,
                cancellationToken);
            if (activeCount >= MaximumActiveDevices)
            {
                throw new PlatformConflictException(
                    $"An account can have at most {MaximumActiveDevices} active devices.");
            }

            var device = new RegisteredDevice
            {
                AccountId = accountId,
                DeviceId = deviceId,
                DisplayName = normalizedName,
                PublicKeySpki = deviceKey?.PublicKeySpki,
                FingerprintSha256 = deviceKey?.FingerprintSha256,
                RegisteredAt = now,
                LastSeenAt = now,
            };
            database.Devices.Add(device);
            await database.SaveChangesAsync(cancellationToken);
            if (transaction is not null)
            {
                await transaction.CommitAsync(cancellationToken);
            }

            return device;
        }
        finally
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync();
            }
        }
    }

    public async Task<RegisteredDevice> RevokeAsync(
        Guid accountId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var device = await database.Devices.SingleOrDefaultAsync(
            x => x.AccountId == accountId && x.DeviceId == deviceId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Registered device not found.");
        if (device.RevokedAt is null)
        {
            var now = timeProvider.GetUtcNow();
            device.RevokedAt = now;
            var sessions = await database.SignalSessions
                .Where(item => item.AccountId == accountId
                    && item.DeviceId == deviceId
                    && item.EndedAt == null)
                .ToListAsync(cancellationToken);
            foreach (var session in sessions)
            {
                session.RevokedAt = now;
                session.EndedAt = now;
            }

            await database.SaveChangesAsync(cancellationToken);
            signalSessions?.RevokeDevice(accountId, deviceId);
        }

        return device;
    }

    public async Task<RegisteredDevice> RequireActiveAsync(
        Guid accountId,
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var device = await database.Devices.AsNoTracking().SingleOrDefaultAsync(
            x => x.AccountId == accountId && x.DeviceId == deviceId,
            cancellationToken);
        if (device is null)
        {
            throw new PlatformNotFoundException("Registered device not found.");
        }

        if (device.RevokedAt is not null)
        {
            throw new PlatformConflictException("The registered device has been revoked.");
        }

        return device;
    }

    private static (string PublicKeySpki, string FingerprintSha256)? NormalizeDeviceKey(
        string? publicKeySpki,
        string? fingerprintSha256)
    {
        if (string.IsNullOrWhiteSpace(publicKeySpki)
            && string.IsNullOrWhiteSpace(fingerprintSha256))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(publicKeySpki)
            || string.IsNullOrWhiteSpace(fingerprintSha256))
        {
            throw new PlatformValidationException(
                "The device public key and SHA-256 fingerprint must be supplied together.");
        }

        byte[] encodedKey;
        try
        {
            encodedKey = DecodeBase64Url(publicKeySpki.Trim());
            using var verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(encodedKey, out var bytesRead);
            var parameters = verifier.ExportParameters(includePrivateParameters: false);
            if (bytesRead != encodedKey.Length
                || parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value
                || parameters.Q.X is not { Length: 32 }
                || parameters.Q.Y is not { Length: 32 })
            {
                throw new CryptographicException("The device key is not P-256.");
            }
        }
        catch (Exception exception) when (
            exception is FormatException or CryptographicException)
        {
            throw new PlatformValidationException(
                "The device public key must be a base64url P-256 SubjectPublicKeyInfo value.");
        }

        var computedFingerprint = Convert.ToHexString(SHA256.HashData(encodedKey)).ToLowerInvariant();
        if (!string.Equals(
                computedFingerprint,
                fingerprintSha256.Trim(),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new PlatformValidationException(
                "The device-key fingerprint does not match the registered public key.");
        }

        return (EncodeBase64Url(encodedKey), computedFingerprint);
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        return Convert.FromBase64String(base64);
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

public interface IDeviceRegistrationGate
{
    ValueTask<IAsyncDisposable> EnterAsync(Guid accountId, CancellationToken cancellationToken);
}

public sealed class InProcessDeviceRegistrationGate : IDeviceRegistrationGate
{
    private readonly ConcurrentDictionary<Guid, SemaphoreSlim> gates = new();

    public async ValueTask<IAsyncDisposable> EnterAsync(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        var gate = gates.GetOrAdd(accountId, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        return new Releaser(gate);
    }

    private sealed class Releaser(SemaphoreSlim gate) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            gate.Release();
            return ValueTask.CompletedTask;
        }
    }
}
