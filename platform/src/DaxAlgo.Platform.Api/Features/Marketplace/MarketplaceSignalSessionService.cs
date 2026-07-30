using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Persistence;
using DaxAlgo.Platform.Providers;
using Microsoft.EntityFrameworkCore;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed class MarketplaceSignalSessionService(
    PlatformDbContext database,
    MarketplaceLicensingService licensing,
    MarketplaceLicensingMutationGate mutationGate,
    IMarketplaceLicenseCryptographyProvider cryptography,
    IMarketplaceArtifactStore artifactStore,
    ISignalSandboxRunner sandboxRunner,
    SignalSessionTokenService tokenService,
    SignalSessionRegistry registry,
    IServiceScopeFactory scopeFactory,
    SignalExecutionOptions options,
    IHostEnvironment environment,
    TimeProvider timeProvider)
{
    private const int MaximumSignalsPerAuthorizationTurn = 32;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public async Task<SignalSessionOpenResponse> OpenAsync(
        Guid accountId,
        Guid licenseId,
        SignalSessionOpenRequest request,
        string idempotencyKey,
        HttpRequest httpRequest,
        CancellationToken cancellationToken)
    {
        if (!sandboxRunner.IsAvailable)
        {
            throw new PlatformServiceUnavailableException(
                "Tier-3 server-side signal execution is not configured on this host.");
        }

        MarketplaceLicensingService.ValidateIdentifiers(
            request.DeviceId,
            licenseId,
            request.ReleaseId);
        MarketplaceLicensingService.ValidateIdempotencyKey(idempotencyKey);
        var clientNonce = MarketplaceLicensingService.DecodeBase64Url(
            request.ClientSessionNonce,
            "client_session_nonce");
        if (clientNonce.Length != 32)
        {
            CryptographicOperations.ZeroMemory(clientNonce);
            throw new PlatformValidationException(
                "client_session_nonce must contain exactly 32 random bytes.");
        }

        var binding = Convert.ToHexStringLower(SHA256.HashData(clientNonce));
        CryptographicOperations.ZeroMemory(clientNonce);
        await using var gate = await mutationGate.EnterAsync(
            $"proof:{request.ChallengeId:D}",
            cancellationToken);
        var live = await licensing.RequireLiveLicenseAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            MarketplaceExecutionClasses.ServerSignal,
            cancellationToken);
        var device = await licensing.RequireProofDeviceAsync(
            accountId,
            request.DeviceId,
            cancellationToken);
        var challenge = await licensing.RequireChallengeAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            request.DeviceId,
            request.ChallengeId,
            MarketplaceLicensingService.SignalSessionOperation,
            binding,
            idempotencyKey,
            cancellationToken);
        if (challenge.ResponseJson is not null)
        {
            return JsonSerializer.Deserialize<SignalSessionOpenResponse>(
                challenge.ResponseJson,
                SerializerOptions)
                ?? throw new InvalidOperationException("The stored signal-session response is invalid.");
        }

        MarketplaceLicensingService.VerifyDeviceProof(
            device,
            challenge,
            request.DeviceSignature);
        live = await licensing.RequireLiveLicenseAsync(
            accountId,
            licenseId,
            request.ReleaseId,
            MarketplaceExecutionClasses.ServerSignal,
            cancellationToken);
        var now = timeProvider.GetUtcNow();
        var session = new MarketplaceSignalSession
        {
            Id = Guid.NewGuid(),
            LicenseId = licenseId,
            AccountId = accountId,
            DeviceId = request.DeviceId,
            ReleaseId = request.ReleaseId,
            StartedAt = now,
            LastHeartbeatAt = now,
        };
        var issued = tokenService.Issue(session, live.AccessValidUntil);
        var response = new SignalSessionOpenResponse(
            session.Id,
            BuildWebSocketUrl(httpRequest, session.Id),
            issued.Token,
            issued.ExpiresAt,
            options.HeartbeatIntervalSeconds);

        database.SignalSessions.Add(session);
        challenge.ConsumedAt = now;
        challenge.ResponseJson = JsonSerializer.Serialize(response, SerializerOptions);
        challenge.Version++;
        try
        {
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            database.ChangeTracker.Clear();
            var stored = await database.DeviceProofChallenges.AsNoTracking()
                .Where(item => item.Id == challenge.Id)
                .Select(item => item.ResponseJson)
                .SingleOrDefaultAsync(cancellationToken);
            if (stored is not null)
            {
                return JsonSerializer.Deserialize<SignalSessionOpenResponse>(stored, SerializerOptions)
                    ?? throw new InvalidOperationException(
                        "The stored signal-session response is invalid.");
            }

            throw;
        }

        return response;
    }

    public async Task StreamAsync(
        Guid sessionId,
        string sessionToken,
        HttpContext context,
        CancellationToken cancellationToken)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            throw new PlatformValidationException("A WebSocket upgrade request is required.");
        }

        var claims = tokenService.Validate(sessionToken, allowExpired: true);
        if (claims.SessionId != sessionId)
        {
            throw new PlatformForbiddenException("The signal-session token does not match this stream.");
        }

        if (claims.ExpiresAt <= timeProvider.GetUtcNow())
        {
            await MarkClaimedSessionRevokedAsync(claims, cancellationToken);
            throw new PlatformForbiddenException("The signal-session token has expired.");
        }

        StreamContext streamContext;
        try
        {
            streamContext = await RequireStreamContextAsync(claims, cancellationToken);
        }
        catch (Exception exception) when (exception is
            PlatformForbiddenException or
            PlatformConflictException or
            PlatformNotFoundException)
        {
            await MarkClaimedSessionRevokedAsync(claims, cancellationToken);
            throw;
        }
        var releaseKey = MarketplaceLicensingService.DecodeBase64Url(
            options.ReleaseVerificationKeySpki,
            "SignalExecution release verification key");
        var package = await artifactStore.ReadAsync(
            streamContext.Release.ArtifactBlobUri,
            cancellationToken);
        var frames = await artifactStore.ReadAsync(
            streamContext.ReferenceDatasetUri,
            cancellationToken);
        byte[]? contentKey = null;
        WebSocket? socket = null;
        try
        {
            contentKey = await cryptography.UnwrapContentKeyAsync(
                streamContext.ContentKey.Algorithm,
                streamContext.ContentKey.KmsWrappedKey,
                cancellationToken);
            if (contentKey.Length != 32)
            {
                throw new CryptographicException(
                    "The unwrapped DAXQ content key must contain exactly 32 bytes.");
            }

            using var registration = registry.Register(
                streamContext.Session.Id,
                streamContext.Session.LicenseId,
                streamContext.Session.AccountId,
                streamContext.Session.DeviceId,
                streamContext.Session.ReleaseId,
                cancellationToken);
            socket = await context.WebSockets.AcceptWebSocketAsync();
            var sandboxRequest = new SignalSandboxRequest(
                streamContext.Session.Id,
                package,
                contentKey,
                frames,
                options.ReleaseSigningKeyId.Trim(),
                releaseKey);
            await RunStreamAsync(
                socket,
                claims,
                streamContext.Session,
                sandboxRequest,
                registration.CancellationToken,
                cancellationToken);
        }
        finally
        {
            if (socket is not null)
            {
                socket.Dispose();
            }

            if (contentKey is not null)
            {
                CryptographicOperations.ZeroMemory(contentKey);
            }

            CryptographicOperations.ZeroMemory(releaseKey);
        }
    }

    private async Task RunStreamAsync(
        WebSocket socket,
        SignalSessionTokenClaims claims,
        MarketplaceSignalSession session,
        SignalSandboxRequest sandboxRequest,
        CancellationToken registryCancellation,
        CancellationToken requestCancellation)
    {
        var channel = Channel.CreateBounded<SignalSandboxSignal>(new BoundedChannelOptions(256)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true,
        });
        using var streamCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            registryCancellation,
            requestCancellation);
        using var authorizationRevoked = new CancellationTokenSource();
        using var monitorCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            registryCancellation,
            requestCancellation);
        using var authorizedStreamCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            streamCancellation.Token,
            authorizationRevoked.Token);
        using var clientClosed = new CancellationTokenSource();
        var producer = ProduceSignalsAsync(
            sandboxRequest,
            channel.Writer,
            authorizedStreamCancellation.Token);
        var receiver = ReceiveUntilClosedAsync(
            socket,
            clientClosed,
            authorizedStreamCancellation.Token);
        var authorizationMonitor = MonitorAuthorizationAsync(
            claims,
            authorizationRevoked,
            monitorCancellation.Token);
        var revoked = false;
        var nextHeartbeat = timeProvider.GetUtcNow().AddSeconds(options.HeartbeatIntervalSeconds);
        long sequence = 0;

        try
        {
            while (socket.State == WebSocketState.Open && !clientClosed.IsCancellationRequested)
            {
                if (registryCancellation.IsCancellationRequested
                    && !requestCancellation.IsCancellationRequested)
                {
                    revoked = true;
                    break;
                }

                var now = timeProvider.GetUtcNow();
                if (authorizationRevoked.IsCancellationRequested || claims.ExpiresAt <= now)
                {
                    revoked = true;
                    break;
                }

                for (var batch = 0;
                    batch < MaximumSignalsPerAuthorizationTurn
                        && channel.Reader.TryRead(out var signal);
                    batch++)
                {
                    await SendAsync(
                        socket,
                        new SignalWireFrame(
                            "signal",
                            Interlocked.Increment(ref sequence),
                            timeProvider.GetUtcNow(),
                            signal.Kind,
                            signal.Strength,
                            signal.NoteId,
                            null),
                        authorizedStreamCancellation.Token);
                }

                now = timeProvider.GetUtcNow();
                if (now >= nextHeartbeat)
                {
                    await SendAsync(
                        socket,
                        new SignalWireFrame(
                            "heartbeat",
                            Interlocked.Increment(ref sequence),
                            null,
                            null,
                            null,
                            null,
                            now),
                        authorizedStreamCancellation.Token);
                    session.LastHeartbeatAt = now;
                    await database.SaveChangesAsync(authorizedStreamCancellation.Token);
                    nextHeartbeat = now.AddSeconds(options.HeartbeatIntervalSeconds);
                }

                if (channel.Reader.Completion.IsCompleted)
                {
                    await channel.Reader.Completion;
                    break;
                }

                var delay = nextHeartbeat - timeProvider.GetUtcNow();
                if (delay < TimeSpan.Zero)
                {
                    delay = TimeSpan.Zero;
                }

                var signalAvailable = channel.Reader
                    .WaitToReadAsync(authorizedStreamCancellation.Token)
                    .AsTask();
                var timer = Task.Delay(delay, authorizedStreamCancellation.Token);
                await Task.WhenAny(signalAvailable, timer, receiver);
            }
        }
        catch (OperationCanceledException) when (
            requestCancellation.IsCancellationRequested
            || clientClosed.IsCancellationRequested
            || registryCancellation.IsCancellationRequested
            || authorizationRevoked.IsCancellationRequested)
        {
            revoked = !requestCancellation.IsCancellationRequested
                && (registryCancellation.IsCancellationRequested
                    || authorizationRevoked.IsCancellationRequested);
        }
        catch
        {
            await CloseOutputSafelyAsync(
                socket,
                WebSocketCloseStatus.InternalServerError,
                "signal execution failed");
            throw;
        }
        finally
        {
            await CloseOutputSafelyAsync(
                socket,
                revoked ? WebSocketCloseStatus.PolicyViolation : WebSocketCloseStatus.NormalClosure,
                revoked ? "signal session revoked" : "signal session ended");
            monitorCancellation.Cancel();
            streamCancellation.Cancel();
            authorizationRevoked.Cancel();
            var endedAt = timeProvider.GetUtcNow();
            session.EndedAt ??= endedAt;
            if (revoked)
            {
                session.RevokedAt ??= endedAt;
            }

            try
            {
                await database.SaveChangesAsync(CancellationToken.None);
            }
            finally
            {
                try
                {
                    await Task.WhenAll(producer, receiver, authorizationMonitor);
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
    }

    private async Task MonitorAuthorizationAsync(
        SignalSessionTokenClaims claims,
        CancellationTokenSource authorizationRevoked,
        CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                await Task.Delay(
                    TimeSpan.FromMilliseconds(options.AuthorizationPollMilliseconds),
                    timeProvider,
                    cancellationToken);
                if (claims.ExpiresAt <= timeProvider.GetUtcNow())
                {
                    authorizationRevoked.Cancel();
                    return;
                }

                await using var scope = scopeFactory.CreateAsyncScope();
                var scopedLicensing = scope.ServiceProvider
                    .GetRequiredService<MarketplaceLicensingService>();
                var scopedDatabase = scope.ServiceProvider
                    .GetRequiredService<PlatformDbContext>();
                if (!await IsStillAuthorizedAsync(
                        scopedLicensing,
                        scopedDatabase,
                        claims,
                        cancellationToken))
                {
                    authorizationRevoked.Cancel();
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch
        {
            authorizationRevoked.Cancel();
        }
    }

    private async Task ProduceSignalsAsync(
        SignalSandboxRequest request,
        ChannelWriter<SignalSandboxSignal> writer,
        CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var signal in sandboxRunner.RunAsync(request, cancellationToken))
            {
                await writer.WriteAsync(signal, cancellationToken);
            }

            writer.TryComplete();
        }
        catch (Exception exception)
        {
            writer.TryComplete(exception);
        }
    }

    private static async Task ReceiveUntilClosedAsync(
        WebSocket socket,
        CancellationTokenSource clientClosed,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        try
        {
            while (socket.State == WebSocketState.Open)
            {
                var received = await socket.ReceiveAsync(buffer, cancellationToken);
                if (received.MessageType == WebSocketMessageType.Close)
                {
                    clientClosed.Cancel();
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (WebSocketException)
        {
            clientClosed.Cancel();
        }
    }

    private static async Task<bool> IsStillAuthorizedAsync(
        MarketplaceLicensingService scopedLicensing,
        PlatformDbContext scopedDatabase,
        SignalSessionTokenClaims claims,
        CancellationToken cancellationToken)
    {
        try
        {
            _ = await scopedLicensing.RequireLiveLicenseAsync(
                claims.AccountId,
                claims.LicenseId,
                claims.ReleaseId,
                MarketplaceExecutionClasses.ServerSignal,
                cancellationToken);
            _ = await scopedLicensing.RequireProofDeviceAsync(
                claims.AccountId,
                claims.DeviceId,
                cancellationToken);
            return await scopedDatabase.SignalSessions.AsNoTracking().AnyAsync(
                item => item.Id == claims.SessionId
                    && item.LicenseId == claims.LicenseId
                    && item.AccountId == claims.AccountId
                    && item.DeviceId == claims.DeviceId
                    && item.ReleaseId == claims.ReleaseId
                    && item.EndedAt == null
                    && item.RevokedAt == null,
                cancellationToken);
        }
        catch (Exception exception) when (exception is
            PlatformForbiddenException or
            PlatformConflictException or
            PlatformNotFoundException)
        {
            return false;
        }
    }

    private async Task<StreamContext> RequireStreamContextAsync(
        SignalSessionTokenClaims claims,
        CancellationToken cancellationToken)
    {
        var session = await database.SignalSessions.SingleOrDefaultAsync(
            item => item.Id == claims.SessionId,
            cancellationToken)
            ?? throw new PlatformNotFoundException("Signal session not found.");
        if (session.LicenseId != claims.LicenseId
            || session.AccountId != claims.AccountId
            || session.DeviceId != claims.DeviceId
            || session.ReleaseId != claims.ReleaseId
            || session.EndedAt is not null
            || session.RevokedAt is not null)
        {
            throw new PlatformForbiddenException("The signal session is no longer active.");
        }

        var live = await licensing.RequireLiveLicenseAsync(
            claims.AccountId,
            claims.LicenseId,
            claims.ReleaseId,
            MarketplaceExecutionClasses.ServerSignal,
            cancellationToken);
        _ = await licensing.RequireProofDeviceAsync(
            claims.AccountId,
            claims.DeviceId,
            cancellationToken);
        var submission = await database.Submissions.AsNoTracking().SingleOrDefaultAsync(
            item => item.Id == live.Release.SubmissionId,
            cancellationToken)
            ?? throw new PlatformConflictException(
                "The server-side release has no immutable reference frame source.");
        var contentKey = await database.ContentKeys.AsNoTracking().SingleOrDefaultAsync(
            item => item.ReleaseId == live.Release.Id
                && item.ContentKeyId == live.Release.ContentKeyId,
            cancellationToken)
            ?? throw new PlatformConflictException(
                "The server-side release does not have a provisioned content key.");
        return new StreamContext(
            session,
            live.Release,
            contentKey,
            submission.ReferenceDatasetQuarantineUri);
    }

    private async Task MarkClaimedSessionRevokedAsync(
        SignalSessionTokenClaims claims,
        CancellationToken cancellationToken)
    {
        var session = await database.SignalSessions.SingleOrDefaultAsync(
            item => item.Id == claims.SessionId
                && item.LicenseId == claims.LicenseId
                && item.AccountId == claims.AccountId
                && item.DeviceId == claims.DeviceId
                && item.ReleaseId == claims.ReleaseId,
            cancellationToken);
        if (session is null || session.EndedAt is not null)
        {
            return;
        }

        var now = timeProvider.GetUtcNow();
        session.RevokedAt = now;
        session.EndedAt = now;
        await database.SaveChangesAsync(cancellationToken);
    }

    private string BuildWebSocketUrl(HttpRequest request, Guid sessionId)
    {
        if (Uri.TryCreate(options.PublicWebSocketBaseUri, UriKind.Absolute, out var configured))
        {
            var secure = string.Equals(
                configured.Scheme,
                "wss",
                StringComparison.OrdinalIgnoreCase);
            var webSocket = string.Equals(
                    configured.Scheme,
                    "ws",
                    StringComparison.OrdinalIgnoreCase);
            var localEnvironment = environment.IsDevelopment()
                || environment.IsEnvironment("Testing");
            var valid = localEnvironment
                ? configured.IsLoopback && (secure || webSocket)
                : secure && !configured.IsLoopback;
            if (!valid)
            {
                throw new PlatformServiceUnavailableException(
                    "The public signal WebSocket endpoint is not safe for this host environment.");
            }

            return new Uri(configured, $"/v1/signals/{sessionId:D}").AbsoluteUri;
        }

        if (!environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
        {
            throw new PlatformServiceUnavailableException(
                "The public signal WebSocket endpoint is not configured.");
        }

        var host = request.Host.Host;
        var loopback = string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));
        if (!loopback)
        {
            throw new PlatformForbiddenException(
                "Development signal sessions bind only to a loopback host.");
        }

        return new UriBuilder(
            request.IsHttps ? "wss" : "ws",
            host,
            request.Host.Port ?? -1,
            $"/v1/signals/{sessionId:D}").Uri.AbsoluteUri;
    }

    private static async Task SendAsync(
        WebSocket socket,
        SignalWireFrame frame,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(frame, SerializerOptions);
        await socket.SendAsync(
            payload,
            WebSocketMessageType.Text,
            endOfMessage: true,
            cancellationToken);
    }

    private static async Task CloseOutputSafelyAsync(
        WebSocket socket,
        WebSocketCloseStatus status,
        string description)
    {
        if (socket.State is not (WebSocketState.Open or WebSocketState.CloseReceived))
        {
            return;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await socket.CloseOutputAsync(status, description, timeout.Token);
        }
        catch (Exception exception) when (exception is
            OperationCanceledException or
            WebSocketException or
            ObjectDisposedException)
        {
        }
    }

    private sealed record StreamContext(
        MarketplaceSignalSession Session,
        MarketplaceStrategyRelease Release,
        MarketplaceContentKey ContentKey,
        string ReferenceDatasetUri);
}
