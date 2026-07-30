using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class GoogleManagedIdentityProviderTests
{
    private const string ClientId = "google-client-id.apps.googleusercontent.com";
    private static readonly DateTimeOffset Now = new(2026, 7, 27, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task ValidGoogleTokenResolvesManagedIdentityAndCachesJwksForMaxAge()
    {
        using var signingKey = RSA.Create(2048);
        var clock = new AdjustableTimeProvider(Now);
        var handler = new GoogleJwksHandler(CreateJwks(signingKey, "google-key"), TimeSpan.FromMinutes(10));
        using var provider = CreateProvider(handler, clock);
        var token = CreateToken(signingKey, "google-key", ClientId, Now.AddMinutes(5));

        var first = await provider.ValidateAsync(token, CancellationToken.None);
        var second = await provider.ValidateAsync(token, CancellationToken.None);

        Assert.Equal("google-subject", first.Subject);
        Assert.Equal("user@example.com", first.Email);
        Assert.Equal("Google User", first.DisplayName);
        Assert.Equal(first, second);
        Assert.Equal(1, handler.RequestCount);

        clock.Advance(TimeSpan.FromMinutes(11));
        _ = await provider.ValidateAsync(
            CreateToken(signingKey, "google-key", ClientId, clock.GetUtcNow().AddMinutes(5)),
            CancellationToken.None);
        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task ExpiredWrongAudienceAndBadSignatureTokensAreRejected()
    {
        using var signingKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        var handler = new GoogleJwksHandler(CreateJwks(signingKey, "google-key"), TimeSpan.FromHours(1));
        using var provider = CreateProvider(handler, new AdjustableTimeProvider(Now));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.ValidateAsync(
            CreateToken(signingKey, "google-key", ClientId, Now.AddMinutes(-3)),
            CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.ValidateAsync(
            CreateToken(signingKey, "google-key", "wrong-client", Now.AddMinutes(5)),
            CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.ValidateAsync(
            CreateToken(otherKey, "google-key", ClientId, Now.AddMinutes(5)),
            CancellationToken.None));
    }

    [Fact]
    public async Task UnknownKeyRefreshIsThrottledAndMultipleAudiencesRequireAuthorizedParty()
    {
        using var signingKey = RSA.Create(2048);
        var handler = new GoogleJwksHandler(CreateJwks(signingKey, "google-key"), TimeSpan.FromHours(1));
        using var provider = CreateProvider(handler, new AdjustableTimeProvider(Now));

        _ = await provider.ValidateAsync(
            CreateToken(signingKey, "google-key", ClientId, Now.AddMinutes(5)),
            CancellationToken.None);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.ValidateAsync(
            CreateToken(signingKey, "unknown-one", ClientId, Now.AddMinutes(5)),
            CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.ValidateAsync(
            CreateToken(signingKey, "unknown-two", ClientId, Now.AddMinutes(5)),
            CancellationToken.None));
        Assert.Equal(2, handler.RequestCount);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.ValidateAsync(
            CreateToken(
                signingKey,
                "google-key",
                new[] { ClientId, "secondary-client" },
                Now.AddMinutes(5)),
            CancellationToken.None));
        _ = await provider.ValidateAsync(
            CreateToken(
                signingKey,
                "google-key",
                new[] { ClientId, "secondary-client" },
                Now.AddMinutes(5),
                authorizedParty: ClientId),
            CancellationToken.None);
    }

    [Fact]
    public async Task BearerGoogleTokenBootstrapsProfileRegistersDeviceAndIssuesLease()
    {
        using var signingKey = RSA.Create(2048);
        var clock = new AdjustableTimeProvider(Now);
        var handler = new GoogleJwksHandler(CreateJwks(signingKey, "google-key"), TimeSpan.FromHours(1));
        var httpClientFactory = new StaticHttpClientFactory(handler);
        await using var factory = new PlatformApiFactory(
            services =>
            {
                services.RemoveAll<IHttpClientFactory>();
                services.RemoveAll<TimeProvider>();
                services.RemoveAll<IManagedIdentityProvider>();
                services.AddSingleton<IHttpClientFactory>(httpClientFactory);
                services.AddSingleton<TimeProvider>(clock);
                services.AddSingleton(new GoogleAuthOptions { ClientId = ClientId });
                services.AddSingleton<GoogleManagedIdentityProvider>();
                services.AddSingleton<IManagedIdentityProvider>(provider =>
                    provider.GetRequiredService<GoogleManagedIdentityProvider>());
                services.AddAuthentication(GoogleAuthenticationHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, GoogleAuthenticationHandler>(
                        GoogleAuthenticationHandler.SchemeName,
                        _ => { });
            });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            CreateToken(signingKey, "google-key", ClientId, Now.AddMinutes(5)));

        var bootstrap = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { },
            CancellationToken.None);
        Assert.True(
            bootstrap.IsSuccessStatusCode,
            await bootstrap.Content.ReadAsStringAsync(CancellationToken.None));
        var profile = await bootstrap.Content.ReadFromJsonAsync<JsonElement>(
            CancellationToken.None);
        Assert.Equal("user@example.com", profile.GetProperty("email").GetString());
        Assert.Equal("Google User", profile.GetProperty("displayName").GetString());
        _ = await factory.GetAccountIdAsync("google-subject");

        var deviceId = Guid.NewGuid();
        var registration = await client.PostAsJsonAsync(
            "/api/v1/devices",
            new { deviceId, displayName = "Google workstation" },
            CancellationToken.None);
        registration.EnsureSuccessStatusCode();
        var lease = await client.PostAsJsonAsync(
            "/api/v1/entitlements/lease",
            new { deviceId },
            CancellationToken.None);
        lease.EnsureSuccessStatusCode();
        var leaseJson = await lease.Content.ReadFromJsonAsync<JsonElement>(
            CancellationToken.None);
        Assert.Equal(deviceId, leaseJson.GetProperty("deviceId").GetGuid());
        Assert.Equal("Basic", leaseJson.GetProperty("edition").GetString());
        Assert.Equal(1, handler.RequestCount);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            CreateToken(signingKey, "google-key", ClientId, Now.AddMinutes(-3)));
        var rejected = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { },
            CancellationToken.None);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        Assert.Equal("Bearer", rejected.Headers.WwwAuthenticate.Single().Scheme);
        Assert.Equal("no-store", rejected.Headers.CacheControl?.ToString());
    }

    [Fact]
    public void AdapterSelectionKeepsLocalDevelopmentAndRequiresGoogleInProduction()
    {
        var development = new TestHostEnvironment(Environments.Development);
        var testing = new TestHostEnvironment("Testing");
        var production = new TestHostEnvironment(Environments.Production);
        var developmentIdentity = new IdentityOptions { Provider = "Development" };
        var googleIdentity = new IdentityOptions { Provider = "Google" };
        var google = new GoogleAuthOptions { ClientId = ClientId };

        Assert.Equal(
            ManagedIdentityProviderMode.Development,
            ManagedIdentityProviderSelection.Resolve(developmentIdentity, new GoogleAuthOptions(), development));
        Assert.Equal(
            ManagedIdentityProviderMode.Development,
            ManagedIdentityProviderSelection.Resolve(developmentIdentity, google, testing));
        Assert.Equal(
            ManagedIdentityProviderMode.Google,
            ManagedIdentityProviderSelection.Resolve(developmentIdentity, google, production));
        Assert.Equal(
            ManagedIdentityProviderMode.Google,
            ManagedIdentityProviderSelection.Resolve(googleIdentity, google, testing));
        Assert.Throws<InvalidOperationException>(() =>
            ManagedIdentityProviderSelection.Resolve(developmentIdentity, new GoogleAuthOptions(), production));
        Assert.Throws<InvalidOperationException>(() =>
            ManagedIdentityProviderSelection.Resolve(googleIdentity, new GoogleAuthOptions(), production));
    }

    private static GoogleManagedIdentityProvider CreateProvider(
        HttpMessageHandler handler,
        TimeProvider timeProvider) =>
        new(
            new StaticHttpClientFactory(handler),
            new GoogleAuthOptions { ClientId = ClientId },
            timeProvider);

    private static string CreateToken(
        RSA signingKey,
        string keyId,
        object audience,
        DateTimeOffset expiresAt,
        string? authorizedParty = null)
    {
        var header = Encode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            alg = "RS256",
            kid = keyId,
            typ = "JWT",
        }));
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = "https://accounts.google.com",
            ["aud"] = audience,
            ["sub"] = "google-subject",
            ["email"] = "user@example.com",
            ["name"] = "Google User",
            ["iat"] = Now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
        };
        if (authorizedParty is not null)
        {
            claims["azp"] = authorizedParty;
        }

        var payload = Encode(JsonSerializer.SerializeToUtf8Bytes(claims));
        var input = Encoding.ASCII.GetBytes($"{header}.{payload}");
        var signature = signingKey.SignData(
            input,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Encode(signature)}";
    }

    private static string CreateJwks(RSA signingKey, string keyId)
    {
        var parameters = signingKey.ExportParameters(includePrivateParameters: false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = keyId,
                    n = Encode(parameters.Modulus!),
                    e = Encode(parameters.Exponent!),
                },
            },
        });
    }

    private static string Encode(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class GoogleJwksHandler(string jwks, TimeSpan maxAge) : HttpMessageHandler
    {
        private int requestCount;

        public int RequestCount => Volatile.Read(ref requestCount);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal("https://www.googleapis.com/oauth2/v3/certs", request.RequestUri?.AbsoluteUri);
            Interlocked.Increment(ref requestCount);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(jwks, Encoding.UTF8, "application/json"),
            };
            response.Headers.CacheControl = new CacheControlHeaderValue
            {
                Public = true,
                MaxAge = maxAge,
            };
            return Task.FromResult(response);
        }
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory, IDisposable
    {
        private readonly HttpClient client;

        public StaticHttpClientFactory(HttpMessageHandler handler)
        {
            client = new HttpClient(handler, disposeHandler: false);
        }

        public HttpClient CreateClient(string name)
        {
            Assert.Equal(GoogleManagedIdentityProvider.HttpClientName, name);
            return client;
        }

        public void Dispose()
        {
            client.Dispose();
        }
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset value = utcNow;

        public override DateTimeOffset GetUtcNow() => value;

        public void Advance(TimeSpan duration)
        {
            value = value.Add(duration);
        }
    }

    private sealed class TestHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;

        public string ApplicationName { get; set; } = "DaxAlgo.Platform.Api.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
