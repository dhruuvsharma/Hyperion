using System.Buffers.Binary;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Features.Profiles;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace DaxAlgo.Platform.Features.VibeQuant;

public sealed class VibeQuantModelReadinessService : IHostedService, IDisposable
{
    public const string HttpClientName = "VibeQuantModelReadiness";
    public const string SchemaVersion = "daxalgo.vibe-quant.model-readiness/v2";
    private const string AttestationRelativePath = "daxalgo/readiness/attest";
    private const int MaxResponseBytes = 4_096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
    private static readonly Action<ILogger, string, Exception?> LogAttestationFailure =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(1, "VibeQuantModelReadinessFailed"),
            "Vibe Quant model-readiness attestation failed with {FailureType}.");

    private readonly VibeQuantOptions options;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<VibeQuantModelReadinessService> logger;
    private readonly VibeQuantModelDeploymentIdentity? identity;
    private readonly CancellationTokenSource refreshCancellation = new();
    private ReadinessLease lease;
    private Task? refreshLoop;

    public VibeQuantModelReadinessService(
        VibeQuantOptions options,
        IHttpClientFactory httpClientFactory,
        TimeProvider timeProvider,
        ILogger<VibeQuantModelReadinessService> logger)
        : this(
            options,
            httpClientFactory,
            timeProvider,
            logger,
            new VibeQuantModelDeploymentCatalog(options, timeProvider))
    {
    }

    internal VibeQuantModelReadinessService(
        VibeQuantOptions options,
        IHttpClientFactory httpClientFactory,
        TimeProvider timeProvider,
        ILogger<VibeQuantModelReadinessService> logger,
        VibeQuantModelDeploymentCatalog modelDeployment)
    {
        this.options = options;
        this.httpClientFactory = httpClientFactory;
        this.timeProvider = timeProvider;
        this.logger = logger;
        identity = modelDeployment.Identity;
        lease = options.Mode == "Mock"
            ? new ReadinessLease(DateTimeOffset.MaxValue)
            : ReadinessLease.NotReady;
    }

    public bool IsReady
    {
        get
        {
            if (options.Mode == "Mock")
            {
                return true;
            }
            var now = timeProvider.GetUtcNow();
            return !IsPromotionExpired &&
                   Volatile.Read(ref lease).ExpiresAt > now;
        }
    }

    public bool IsPromotionExpired =>
        options.Mode != "Mock" &&
        (identity is null || identity.PromotionExpiresAtUtc <= timeProvider.GetUtcNow());

    public bool IsActiveModel(string executionModelId) =>
        options.Mode == "Mock" ||
        StringComparer.Ordinal.Equals(identity?.ExecutionModelId, executionModelId);

    public bool IsReadyFor(string executionModelId) =>
        IsReady && IsActiveModel(executionModelId);

    public void RequireReady(string? executionModelId = null)
    {
        if (executionModelId is null ? !IsReady : !IsReadyFor(executionModelId))
        {
            throw new PlatformServiceUnavailableException(
                "The Vibe Quant execution model is not ready; retry later.");
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (options.Mode == "Mock")
        {
            return;
        }

        try
        {
            if (!await VerifyOnceAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidOperationException();
            }
            SetReady();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            Volatile.Write(ref lease, ReadinessLease.NotReady);
            LogRefreshFailure(exception);
            throw new InvalidOperationException(
                "Initial Vibe Quant model-readiness attestation failed.");
        }

        refreshLoop = RefreshLoopAsync(refreshCancellation.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            refreshCancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        if (refreshLoop is null)
        {
            return;
        }
        try
        {
            await refreshLoop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    public void Dispose()
    {
        try
        {
            refreshCancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        refreshCancellation.Dispose();
    }

    private async Task RefreshLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(
                    TimeSpan.FromSeconds(options.ModelAttestationRefreshSeconds),
                    timeProvider,
                    cancellationToken).ConfigureAwait(false);
                if (await VerifyOnceAsync(cancellationToken).ConfigureAwait(false))
                {
                    SetReady();
                }
                else
                {
                    Volatile.Write(ref lease, ReadinessLease.NotReady);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (OperationCanceledException exception)
            {
                LogRefreshFailure(exception);
            }
            catch (HttpRequestException exception)
            {
                LogRefreshFailure(exception);
            }
            catch (IOException exception)
            {
                LogRefreshFailure(exception);
            }
            catch (Exception exception)
            {
                Volatile.Write(ref lease, ReadinessLease.NotReady);
                LogRefreshFailure(exception);
            }
        }
    }

    private async Task<bool> VerifyOnceAsync(CancellationToken cancellationToken)
    {
        var expectedIdentity = identity
            ?? throw new InvalidOperationException("Live Vibe Quant model identity is unavailable.");
        if (expectedIdentity.PromotionExpiresAtUtc <= timeProvider.GetUtcNow())
        {
            return false;
        }
        var apiKey = ReadVisibleAsciiSecret(options.ApiKeyEnvironmentVariable, "provider credential");
        var attestationKey = ReadAttestationKey(options.ModelAttestationKeyEnvironmentVariable);
        try
        {
            var nonceBytes = RandomNumberGenerator.GetBytes(32);
            var nonce = Base64Url.Encode(nonceBytes);
            var endpoint = AppendPath(options.BaseUrl!, AttestationRelativePath);
            var requestBody = new ModelReadinessRequest(
                SchemaVersion,
                options.ModelAttestationAudience!,
                nonce);
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = JsonContent.Create(requestBody, options: WireJson)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(options.ModelAttestationTimeoutSeconds));
            using var response = await httpClientFactory.CreateClient(HttpClientName)
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode ||
                !Equals(response.RequestMessage?.RequestUri, endpoint) ||
                !StringComparer.OrdinalIgnoreCase.Equals(
                    response.Content.Headers.ContentType?.MediaType,
                    "application/json"))
            {
                return false;
            }

            var bytes = await ReadBoundedAsync(response.Content, timeout.Token).ConfigureAwait(false);
            var attestation = DeserializeAttestation(bytes);
            if (!StringComparer.Ordinal.Equals(attestation.SchemaVersion, SchemaVersion) ||
                !StringComparer.Ordinal.Equals(attestation.Nonce, nonce) ||
                !StringComparer.Ordinal.Equals(attestation.KeyId, options.ModelAttestationKeyId))
            {
                return false;
            }
            var actualProof = Base64Url.Decode(attestation.Proof, 32);
            var expectedProof = VibeQuantModelReadinessProof.Compute(
                attestationKey,
                options.ModelAttestationAudience!,
                nonce,
                options.ModelAttestationKeyId!,
                expectedIdentity);
            return CryptographicOperations.FixedTimeEquals(actualProof, expectedProof);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(attestationKey);
        }
    }

    private void SetReady()
    {
        var expectedIdentity = identity
            ?? throw new InvalidOperationException("Live Vibe Quant model identity is unavailable.");
        var now = timeProvider.GetUtcNow();
        if (expectedIdentity.PromotionExpiresAtUtc <= now)
        {
            throw new InvalidOperationException("The Vibe Quant model promotion has expired.");
        }
        var expiresAt = now.AddSeconds(options.ModelAttestationTtlSeconds);
        if (expectedIdentity.PromotionExpiresAtUtc < expiresAt)
        {
            expiresAt = expectedIdentity.PromotionExpiresAtUtc;
        }
        Volatile.Write(ref lease, new ReadinessLease(expiresAt));
    }

    private void LogRefreshFailure(Exception exception) =>
        LogAttestationFailure(logger, exception.GetType().Name, null);

    private static Uri AppendPath(string baseUrl, string relativePath)
    {
        var endpoint = new Uri(baseUrl, UriKind.Absolute);
        return new UriBuilder(endpoint)
        {
            Path = $"{endpoint.AbsolutePath.TrimEnd('/')}/{relativePath}",
            Query = string.Empty,
            Fragment = string.Empty
        }.Uri;
    }

    private static string ReadVisibleAsciiSecret(string? environmentVariable, string label)
    {
        var value = environmentVariable is null
            ? null
            : Environment.GetEnvironmentVariable(environmentVariable);
        if (string.IsNullOrWhiteSpace(value) ||
            value.Any(character => character is < '!' or > '~'))
        {
            throw new InvalidOperationException($"The server-side Vibe Quant {label} is unavailable.");
        }
        return value.Trim();
    }

    private static byte[] ReadAttestationKey(string? environmentVariable)
    {
        var encoded = ReadVisibleAsciiSecret(environmentVariable, "attestation key");
        var key = Base64Url.Decode(encoded);
        if (key.Length < 32)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException(
                "The server-side Vibe Quant attestation key is invalid.");
        }
        return key;
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is < 1 or > MaxResponseBytes)
        {
            throw new InvalidOperationException("The model-readiness response size is invalid.");
        }
        await using var input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(MaxResponseBytes);
        var buffer = new byte[1_024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > MaxResponseBytes)
            {
                throw new InvalidOperationException("The model-readiness response is too large.");
            }
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static ModelReadinessResponse DeserializeAttestation(byte[] bytes)
    {
        _ = StrictUtf8.GetString(bytes);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8
        });
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                throw new InvalidOperationException(
                    "The model-readiness response contains duplicate properties.");
            }
        }
        return JsonSerializer.Deserialize<ModelReadinessResponse>(bytes, WireJson)
            ?? throw new InvalidOperationException("The model-readiness response was JSON null.");
    }

    private sealed record ReadinessLease(DateTimeOffset ExpiresAt)
    {
        public static ReadinessLease NotReady { get; } = new(DateTimeOffset.MinValue);
    }

    private sealed record ModelReadinessRequest(
        [property: JsonPropertyName("schemaVersion")] string SchemaVersion,
        [property: JsonPropertyName("audience")] string Audience,
        [property: JsonPropertyName("nonce")] string Nonce);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record ModelReadinessResponse
    {
        public required string SchemaVersion { get; init; }

        public required string Nonce { get; init; }

        public required string KeyId { get; init; }

        public required string Proof { get; init; }
    }
}

public sealed class VibeQuantModelReadinessHealthCheck(
    VibeQuantModelReadinessService readiness) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default) => Task.FromResult(
        readiness.IsReady
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("The Vibe Quant execution model is unavailable."));
}

internal static class VibeQuantModelReadinessProof
{
    public static byte[] Compute(
        ReadOnlySpan<byte> key,
        string audience,
        string nonce,
        string keyId,
        VibeQuantModelDeploymentIdentity identity)
    {
        using var payload = new MemoryStream();
        Append(payload, VibeQuantModelReadinessService.SchemaVersion);
        Append(payload, audience);
        Append(payload, nonce);
        Append(payload, keyId);
        Append(payload, identity.ServingProfileSha256);
        Append(payload, identity.ArtifactSha256);
        Append(payload, identity.ArtifactTreeSha256);
        Append(payload, identity.ExecutionModelId);
        Append(payload, identity.PromotionEnvelopeSha256);
        Append(payload, identity.PromotionPayloadSha256);
        Append(payload, identity.DeploymentId);
        Append(payload, identity.ProviderId);
        Append(payload, identity.HostedPolicySha256);
        Append(payload, identity.PromotionExpiresAtUtcText);
        return HMACSHA256.HashData(key, payload.GetBuffer().AsSpan(0, checked((int)payload.Length)));
    }

    private static void Append(Stream output, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        output.Write(length);
        output.Write(bytes);
    }
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string value, int? expectedLength = null)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new InvalidOperationException("The model-readiness value is not valid base64url.");
        }
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(padded);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                "The model-readiness value is not valid base64url.",
                exception);
        }
        if (expectedLength is { } length && decoded.Length != length)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidOperationException("The model-readiness value has an invalid length.");
        }
        if (!StringComparer.Ordinal.Equals(Encode(decoded), value))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidOperationException(
                "The model-readiness value is not canonical base64url.");
        }
        return decoded;
    }
}
