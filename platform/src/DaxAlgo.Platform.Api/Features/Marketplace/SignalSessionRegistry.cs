using System.Collections.Concurrent;
using DaxAlgo.Platform.Features.Profiles;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class SignalSessionRegistry
{
    private readonly ConcurrentDictionary<Guid, Entry> active = new();

    public Registration Register(
        Guid sessionId,
        Guid licenseId,
        Guid accountId,
        Guid deviceId,
        Guid releaseId,
        CancellationToken requestAborted)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(requestAborted);
        var entry = new Entry(licenseId, accountId, deviceId, releaseId, source);
        if (!active.TryAdd(sessionId, entry))
        {
            source.Dispose();
            throw new PlatformConflictException("The signal session already has an active stream.");
        }

        return new Registration(this, sessionId, entry);
    }

    public void RevokeLicense(Guid licenseId) => Revoke(entry => entry.LicenseId == licenseId);

    public void RevokeDevice(Guid accountId, Guid deviceId) =>
        Revoke(entry => entry.AccountId == accountId && entry.DeviceId == deviceId);

    public void RevokeAccount(Guid accountId) => Revoke(entry => entry.AccountId == accountId);

    public void RevokeRelease(Guid releaseId) => Revoke(entry => entry.ReleaseId == releaseId);

    private void Revoke(Func<Entry, bool> predicate)
    {
        foreach (var entry in active.Values.Where(predicate))
        {
            entry.Source.Cancel();
        }
    }

    private void Remove(Guid sessionId, Entry entry)
    {
        active.TryRemove(new KeyValuePair<Guid, Entry>(sessionId, entry));
        entry.Source.Dispose();
    }

    internal sealed record Entry(
        Guid LicenseId,
        Guid AccountId,
        Guid DeviceId,
        Guid ReleaseId,
        CancellationTokenSource Source);

    public sealed class Registration : IDisposable
    {
        private SignalSessionRegistry? owner;
        private readonly Guid sessionId;
        private readonly Entry entry;

        internal Registration(SignalSessionRegistry owner, Guid sessionId, Entry entry)
        {
            this.owner = owner;
            this.sessionId = sessionId;
            this.entry = entry;
        }

        public CancellationToken CancellationToken => entry.Source.Token;

        public void Dispose() => Interlocked.Exchange(ref owner, null)?.Remove(sessionId, entry);
    }
}
