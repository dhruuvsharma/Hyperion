using System.Collections.Concurrent;

namespace DaxAlgo.Platform.Features.VibeQuant;

public sealed class VibeQuantExecutionCancellationRegistry : IDisposable
{
    private readonly ConcurrentDictionary<Guid, RunState> runs = new();

    public CancellationToken Ensure(
        Guid runId,
        Guid workerLeaseId,
        bool cancellationRequested)
    {
        while (true)
        {
            var state = runs.GetOrAdd(runId, static _ => new RunState());
            CancellationTokenSource source;
            var cancel = false;
            lock (state.Gate)
            {
                if (state.Retired)
                {
                    continue;
                }
                state.CancellationRequested |= cancellationRequested;
                if (!state.Leases.TryGetValue(workerLeaseId, out var existing))
                {
                    source = new CancellationTokenSource();
                    state.Leases.Add(workerLeaseId, source);
                }
                else
                {
                    source = existing;
                }
                cancel = state.CancellationRequested;
            }
            if (cancel)
            {
                TryCancel(source);
            }
            return source.Token;
        }
    }

    public void Request(Guid runId)
    {
        while (true)
        {
            var state = runs.GetOrAdd(runId, static _ => new RunState());
            CancellationTokenSource[] sources;
            lock (state.Gate)
            {
                if (state.Retired)
                {
                    continue;
                }
                state.CancellationRequested = true;
                sources = [.. state.Leases.Values];
            }
            foreach (var source in sources)
            {
                TryCancel(source);
            }
            return;
        }
    }

    public void Complete(Guid runId, Guid workerLeaseId)
    {
        if (!runs.TryGetValue(runId, out var state))
        {
            return;
        }

        CancellationTokenSource? source = null;
        lock (state.Gate)
        {
            if (state.Leases.Remove(workerLeaseId, out source) && state.Leases.Count == 0)
            {
                state.Retired = true;
                runs.TryRemove(new KeyValuePair<Guid, RunState>(runId, state));
            }
        }
        source?.Dispose();
    }

    public void Dispose()
    {
        foreach (var pair in runs)
        {
            CancellationTokenSource[] sources;
            lock (pair.Value.Gate)
            {
                pair.Value.Retired = true;
                sources = [.. pair.Value.Leases.Values];
                pair.Value.Leases.Clear();
            }
            foreach (var source in sources)
            {
                source.Dispose();
            }
        }
        runs.Clear();
    }

    private static void TryCancel(CancellationTokenSource source)
    {
        try
        {
            source.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        catch (AggregateException)
        {
        }
    }

    private sealed class RunState
    {
        public object Gate { get; } = new();

        public Dictionary<Guid, CancellationTokenSource> Leases { get; } = [];

        public bool CancellationRequested { get; set; }

        public bool Retired { get; set; }
    }
}
