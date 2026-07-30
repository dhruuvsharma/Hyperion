using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class PlatformApiTests
{
    private static readonly string[] PublisherCapabilities = ["bars", "signals"];

    [Fact]
    public async Task AuthenticatedPlansAreCanonicalAndServerOwned()
    {
        await using var factory = new PlatformApiFactory();
        using var client = CreateAuthenticatedClient(factory, "plans-reader");

        var plans = await client.GetFromJsonAsync<JsonElement>("/api/v1/plans");
        var offers = plans.EnumerateArray().ToArray();

        Assert.Equal(2, offers.Length);
        AssertPlan(offers[0], "Basic", 0, expectedInterval: null);
        AssertPlan(offers[1], "Professional", 7_900, "month");
    }

    [Fact]
    public async Task HealthOpenApiAndAuthorizationAreExposed()
    {
        await using var factory = new PlatformApiFactory();
        using var client = factory.CreateClient();

        var health = await client.GetAsync("/health");
        var openApi = await client.GetAsync("/openapi/v1.json");
        var verificationKeys = await client.GetAsync("/api/v1/entitlements/lease/jwks");
        var unauthorized = await client.GetAsync("/api/v1/profiles/me");
        var anonymousCatalog = await client.GetAsync("/api/v1/catalog");
        var anonymousPlans = await client.GetAsync("/api/v1/plans");

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(HttpStatusCode.OK, openApi.StatusCode);
        Assert.Equal(HttpStatusCode.OK, verificationKeys.StatusCode);
        Assert.Equal(
            2,
            (await ReadJsonAsync(verificationKeys)).GetProperty("keys").GetArrayLength());
        Assert.Contains(
            "/api/v1/entitlements/me",
            await openApi.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        Assert.Equal(HttpStatusCode.OK, anonymousCatalog.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousPlans.StatusCode);
    }

    [Fact]
    public async Task SubscriptionWebhookIsIdempotentAndProjectsEntitlement()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "account-subscription";
        using var accountClient = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(
            factory,
            accountClient,
            subject,
            "Subscription Account");

        using var webhookClient = factory.CreateClient();
        webhookClient.DefaultRequestHeaders.Add("X-Development-Webhook", "accepted");
        var webhook = new
        {
            id = $"evt-{Guid.NewGuid():N}",
            type = "subscription.updated",
            accountId,
            subscriptionId = "dev-subscription-1",
            priceId = "dev_price_professional_monthly",
            status = "Active",
            currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30),
        };

        var first = await webhookClient.PostAsJsonAsync("/api/v1/billing/webhooks", webhook);
        var second = await webhookClient.PostAsJsonAsync("/api/v1/billing/webhooks", webhook);
        first.EnsureSuccessStatusCode();
        second.EnsureSuccessStatusCode();

        Assert.Equal("Processed", (await ReadJsonAsync(first)).GetProperty("outcome").GetString());
        Assert.Equal("Duplicate", (await ReadJsonAsync(second)).GetProperty("outcome").GetString());

        var entitlement = await accountClient.GetFromJsonAsync<JsonElement>("/api/v1/entitlements/me");
        AssertJsonProperties(
            entitlement,
            "tier",
            "isActive",
            "issuedAt",
            "leaseExpiresAt",
            "subscriptionValidUntil",
            "capabilities");
        Assert.Equal("Professional", entitlement.GetProperty("tier").GetString());
        Assert.Contains(
            "terminal.professional",
            entitlement.GetProperty("capabilities")
                .EnumerateArray()
                .Select(value => value.GetString()));
    }

    [Fact]
    public async Task SubscriptionWebhookRejectsUnknownPriceAndIgnoresEventTier()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "account-price-policy";
        using var accountClient = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(
            factory,
            accountClient,
            subject,
            "Price Policy Account");
        using var webhookClient = factory.CreateClient();
        webhookClient.DefaultRequestHeaders.Add("X-Development-Webhook", "accepted");

        var unknown = await webhookClient.PostAsJsonAsync(
            "/api/v1/billing/webhooks",
            new
            {
                id = $"evt-{Guid.NewGuid():N}",
                type = "subscription.updated",
                accountId,
                subscriptionId = "dev-subscription-unknown",
                priceId = "price_not_allowlisted",
                plan = "Professional",
                status = "Active",
                currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30),
            });
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);

        var trusted = await webhookClient.PostAsJsonAsync(
            "/api/v1/billing/webhooks",
            new
            {
                id = $"evt-{Guid.NewGuid():N}",
                type = "subscription.updated",
                accountId,
                subscriptionId = "dev-subscription-professional",
                priceId = "dev_price_professional_monthly",
                plan = "Basic",
                status = "Active",
                currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30),
            });
        trusted.EnsureSuccessStatusCode();

        var entitlement = await accountClient.GetFromJsonAsync<JsonElement>("/api/v1/entitlements/me");
        Assert.Equal("Professional", entitlement.GetProperty("tier").GetString());
    }

    [Theory]
    [InlineData("charge.refunded")]
    [InlineData("charge.dispute.created")]
    public async Task ChargeRevocationWebhookDropsProfessionalSubscriptionToBasicAndIsIdempotent(
        string eventType)
    {
        await using var factory = new PlatformApiFactory();
        var subject = $"account-{eventType.Replace('.', '-')}";
        using var accountClient = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(
            factory,
            accountClient,
            subject,
            "Revocation Account");
        var subscriptionId = await GrantSubscriptionAsync(
            factory,
            accountId,
            "dev_price_professional_monthly");
        var deviceId = Guid.NewGuid();
        Assert.Equal(
            HttpStatusCode.Created,
            (await RegisterDeviceAsync(accountClient, deviceId, "Revocation workstation")).StatusCode);

        var before = await accountClient.GetFromJsonAsync<JsonElement>(
            "/api/v1/entitlements/me");
        Assert.Equal("Professional", before.GetProperty("tier").GetString());

        using var webhookClient = factory.CreateClient();
        webhookClient.DefaultRequestHeaders.Add("X-Development-Webhook", "accepted");
        var revocation = new
        {
            id = $"evt-{Guid.NewGuid():N}",
            type = eventType,
            accountId,
            subscriptionId,
        };

        var first = await webhookClient.PostAsJsonAsync(
            "/api/v1/billing/webhooks",
            revocation);
        var second = await webhookClient.PostAsJsonAsync(
            "/api/v1/billing/webhooks",
            revocation);
        first.EnsureSuccessStatusCode();
        second.EnsureSuccessStatusCode();

        Assert.Equal("Processed", (await ReadJsonAsync(first)).GetProperty("outcome").GetString());
        Assert.Equal("Duplicate", (await ReadJsonAsync(second)).GetProperty("outcome").GetString());

        var after = await accountClient.GetFromJsonAsync<JsonElement>(
            "/api/v1/entitlements/me");
        Assert.Equal("Basic", after.GetProperty("tier").GetString());
        Assert.False(after.GetProperty("isActive").GetBoolean());
        Assert.DoesNotContain(
            "terminal.professional",
            after.GetProperty("capabilities")
                .EnumerateArray()
                .Select(value => value.GetString()));
        var deniedLease = await accountClient.PostAsJsonAsync(
            "/api/v1/entitlements/lease",
            new { deviceId });
        Assert.Equal(HttpStatusCode.Forbidden, deniedLease.StatusCode);
    }

    [Fact]
    public async Task DeviceLimitRevocationAndLeaseBindingAreEnforced()
    {
        await using var factory = new PlatformApiFactory();
        const string subject = "account-devices";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject, "Device Account");
        var firstDevice = Guid.NewGuid();
        var secondDevice = Guid.NewGuid();
        var replacementDevice = Guid.NewGuid();

        var firstRegistration = await RegisterDeviceAsync(client, firstDevice, "First workstation");
        Assert.Equal(HttpStatusCode.Created, firstRegistration.StatusCode);
        AssertJsonProperties(
            await ReadJsonAsync(firstRegistration),
            "deviceId",
            "displayName",
            "registeredAt",
            "lastSeenAt",
            "revokedAt");
        Assert.Equal(
            HttpStatusCode.Created,
            (await RegisterDeviceAsync(client, secondDevice, "Second workstation")).StatusCode);
        Assert.Equal(
            HttpStatusCode.Conflict,
            (await RegisterDeviceAsync(client, replacementDevice, "Third workstation")).StatusCode);

        var leaseResponse = await client.PostAsJsonAsync(
            "/api/v1/entitlements/lease",
            new { deviceId = secondDevice });
        leaseResponse.EnsureSuccessStatusCode();
        var lease = await ReadJsonAsync(leaseResponse);
        Assert.Equal(1, lease.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("Active", lease.GetProperty("state").GetString());
        Assert.Equal("Basic", lease.GetProperty("edition").GetString());
        Assert.Equal(accountId, lease.GetProperty("productAccountId").GetGuid());
        Assert.Equal(secondDevice, lease.GetProperty("deviceId").GetGuid());
        Assert.StartsWith(
            "testing-edition-lease-es256-",
            lease.GetProperty("keyId").GetString()!);
        Assert.Equal("ES256", lease.GetProperty("algorithm").GetString());
        var issuedAt = lease.GetProperty("issuedAtUtc").GetDateTimeOffset();
        var notBefore = lease.GetProperty("notBeforeUtc").GetDateTimeOffset();
        var expiresAt = lease.GetProperty("expiresAtUtc").GetDateTimeOffset();
        Assert.Equal(issuedAt, notBefore);
        Assert.InRange(expiresAt - issuedAt, TimeSpan.FromDays(6), TimeSpan.FromDays(7));

        var signedPayload = DecodeBase64Url(lease.GetProperty("encodedPayload").GetString()!);
        using var payload = JsonDocument.Parse(signedPayload);
        Assert.Equal(
            accountId,
            payload.RootElement.GetProperty("productAccountId").GetGuid());
        Assert.Equal(
            secondDevice,
            payload.RootElement.GetProperty("deviceId").GetGuid());
        var keySet = await client.GetFromJsonAsync<JsonElement>(
            "/api/v1/entitlements/lease/jwks");
        var verificationKey = keySet.GetProperty("keys")
            .EnumerateArray()
            .Single(key => key.GetProperty("kid").GetString()
                == lease.GetProperty("keyId").GetString());
        using var verifier = CreateEs256Verifier(verificationKey);
        Assert.True(verifier.VerifyData(
            signedPayload,
            DecodeBase64Url(lease.GetProperty("encodedSignature").GetString()!),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        var revoked = await client.PostAsync(
            $"/api/v1/devices/{secondDevice}/revoke",
            content: null);
        revoked.EnsureSuccessStatusCode();
        AssertJsonProperties(
            await ReadJsonAsync(revoked),
            "deviceId",
            "displayName",
            "registeredAt",
            "lastSeenAt",
            "revokedAt");
        var revokedLease = await client.PostAsJsonAsync(
            "/api/v1/entitlements/lease",
            new { deviceId = secondDevice });
        Assert.Equal(HttpStatusCode.Conflict, revokedLease.StatusCode);

        Assert.Equal(
            HttpStatusCode.Created,
            (await RegisterDeviceAsync(client, replacementDevice, "Replacement workstation")).StatusCode);
        var devices = await client.GetFromJsonAsync<JsonElement>("/api/v1/devices");
        foreach (var device in devices.EnumerateArray())
        {
            AssertJsonProperties(
                device,
                "deviceId",
                "displayName",
                "registeredAt",
                "lastSeenAt",
                "revokedAt");
        }

        Assert.Equal(
            2,
            devices.EnumerateArray().Count(device => device.GetProperty("revokedAt").ValueKind
                == JsonValueKind.Null));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BasicAndProfessionalAccountsCanCreatePublisherSubmissions(bool professional)
    {
        await using var factory = new PlatformApiFactory();
        var subject = professional ? "professional-publisher" : "basic-publisher";
        using var client = CreateAuthenticatedClient(factory, subject);
        var accountId = await BootstrapAsync(factory, client, subject, "Marketplace Publisher");
        if (professional)
        {
            await GrantSubscriptionAsync(
                factory,
                accountId,
                "dev_price_professional_monthly");
        }

        var response = await client.PostAsJsonAsync(
            "/api/v1/submissions",
            new
            {
                slug = $"publisher-{Guid.NewGuid():N}",
                title = "Publisher Strategy",
                description = "A deterministic marketplace submission created by either edition.",
                version = "1.0.0",
                priceInCents = 0,
                priceMode = "OneTime",
                currency = "USD",
                sourceCode = "// SPDX-License-Identifier: Proprietary\npublic sealed class Strategy { }",
                referenceDatasetJson = "{}",
                declaredCapabilities = PublisherCapabilities,
                licenseExpression = "Proprietary",
            });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("Draft", (await ReadJsonAsync(response)).GetProperty("status").GetString());
    }

    private static HttpClient CreateAuthenticatedClient(
        PlatformApiFactory factory,
        string subject,
        string? role = null)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Dev-Subject", subject);
        client.DefaultRequestHeaders.Add("X-Dev-Email", $"{subject}@example.test");
        if (role is not null)
        {
            client.DefaultRequestHeaders.Add("X-Dev-Roles", role);
        }

        return client;
    }

    private static Task<HttpResponseMessage> RegisterDeviceAsync(
        HttpClient client,
        Guid deviceId,
        string displayName) =>
        client.PostAsJsonAsync("/api/v1/devices", new { deviceId, displayName });

    private static async Task<string> GrantSubscriptionAsync(
        PlatformApiFactory factory,
        Guid accountId,
        string priceId)
    {
        var subscriptionId = $"sub-{Guid.NewGuid():N}";
        using var webhookClient = factory.CreateClient();
        webhookClient.DefaultRequestHeaders.Add("X-Development-Webhook", "accepted");
        var response = await webhookClient.PostAsJsonAsync(
            "/api/v1/billing/webhooks",
            new
            {
                id = $"evt-{Guid.NewGuid():N}",
                type = "subscription.updated",
                accountId,
                subscriptionId,
                priceId,
                status = "Active",
                currentPeriodEnd = DateTimeOffset.UtcNow.AddDays(30),
            });
        response.EnsureSuccessStatusCode();
        return subscriptionId;
    }

    private static void AssertPlan(
        JsonElement plan,
        string expectedTier,
        long expectedAmount,
        string? expectedInterval)
    {
        Assert.Equal(expectedTier, plan.GetProperty("tier").GetString());
        Assert.Equal("USD", plan.GetProperty("currency").GetString());
        Assert.Equal(expectedAmount, plan.GetProperty("unitAmountInCents").GetInt64());
        if (expectedInterval is null)
        {
            Assert.Equal(JsonValueKind.Null, plan.GetProperty("billingInterval").ValueKind);
        }
        else
        {
            Assert.Equal(expectedInterval, plan.GetProperty("billingInterval").GetString());
        }
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        return Convert.FromBase64String(base64);
    }

    private static ECDsa CreateEs256Verifier(JsonElement key) =>
        ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = DecodeBase64Url(key.GetProperty("x").GetString()!),
                Y = DecodeBase64Url(key.GetProperty("y").GetString()!),
            },
        });

    private static async Task<Guid> BootstrapAsync(
        PlatformApiFactory factory,
        HttpClient client,
        string subject,
        string displayName)
    {
        var response = await client.PostAsJsonAsync(
            "/api/v1/profiles/bootstrap",
            new { displayName });
        response.EnsureSuccessStatusCode();
        var profile = await ReadJsonAsync(response);
        AssertJsonProperties(profile, "email", "displayName");
        Assert.Equal($"{subject}@example.test", profile.GetProperty("email").GetString());
        Assert.Equal(displayName, profile.GetProperty("displayName").GetString());

        var currentProfile = await client.GetFromJsonAsync<JsonElement>("/api/v1/profiles/me");
        AssertJsonProperties(currentProfile, "email", "displayName");
        return await factory.GetAccountIdAsync(subject);
    }

    private static void AssertJsonProperties(JsonElement value, params string[] expected)
    {
        var actual = value.EnumerateObject()
            .Select(property => property.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(expected.Order(StringComparer.Ordinal), actual);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return document.RootElement.Clone();
    }
}
