using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DaxAlgo.Platform.Configuration;
using DaxAlgo.Platform.Domain;
using DaxAlgo.Platform.Features.VibeQuant;
using Microsoft.Data.Sqlite;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Persistence;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;

namespace DaxAlgo.Platform.Api.Tests;

public sealed class VibeQuantModelDeploymentTests
{
    private const string GoldenProfileSha256 =
        "e3a16a70bfcf6a015c0d952a14f0740a99207f72e44dd618e45f949f40e8fb9f";
    private const string GoldenEnvelopeSha256 =
        "fc1b22b9a0f9c3cb3734118b8d97594d475ce240356151954b2fcc1190d222ec";
    private const string GoldenPayloadSha256 =
        "a59717b1c319c2c3b89e28fc7244d2c6c817c400de8272b68212b940fb4d6c36";
    private const string GoldenSpkiSha256 =
        "8d427956ca78742a0a2f77b685f8feea717a788056474baab96c7553b82ac300";
    private const string GoldenHostedPolicySha256 =
        "192cedb03e29200df0eaafd8136cfe0f6cfbf769f4c09db02dae843ebc59a20b";
    private const string GoldenPromotionId =
        "vqprom-b9adeced7080ba6e942d47d79ce76d6cdac5fa351d09c205afc3726e86effa66";
    private const string StrategyV2EnvelopeSha256 =
        "5d01f4a8d34fb6f843545f07fa5b4467936dce2eb3caea4ec53402048b06aa80";
    private const string StrategyV2PayloadSha256 =
        "f5e8b8aa7a32c65a2c634f0d686d546a5c7688a55f4ad6581f2deac63e47cebd";
    private const string StrategyV2SpkiSha256 =
        "247b7578bc40da1d52209b2aeb57355997978df6f93a51fba9d108cde06dbfdf";
    private const string StrategyV2HostedPolicySha256 =
        "9fdac22db0aa96062b6c328c4be7a2a95c13dfad2876ba21bccf1cc96a120ee8";
    private static readonly DateTimeOffset GoldenValidationTime =
        new(2026, 7, 27, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ModelReadinessProofMatchesThePythonLengthPrefixedContract()
    {
        var profileSha256 = new string('1', 64);
        var identity = new VibeQuantModelDeploymentIdentity(
            profileSha256,
            new string('2', 64),
            new string('3', 64),
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(profileSha256),
            new string('4', 64),
            new string('5', 64),
            "vqdpl-prod",
            "daxalgo-private",
            new string('6', 64),
            new DateTimeOffset(2027, 7, 27, 12, 0, 0, TimeSpan.Zero),
            "2027-07-27T12:00:00Z");
        var nonce = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";

        var proof = VibeQuantModelReadinessProof.Compute(
            Enumerable.Range(0, 32).Select(value => checked((byte)value)).ToArray(),
            "daxalgo-platform-prod",
            nonce,
            "prod-hmac-v1",
            identity);

        Assert.Equal(
            "m4z9GqfCk_HT_bmiXQrMr7fUFG3uOaDXURYkKq97r0Y",
            Base64Url.Encode(proof));
    }

    [Fact]
    public void Base64UrlRejectsNonCanonicalTrailingBits()
    {
        var canonical = Base64Url.Encode(new byte[32]);
        Assert.EndsWith("A", canonical, StringComparison.Ordinal);
        var nonCanonical = canonical[..^1] + "B";

        var exception = Assert.Throws<InvalidOperationException>(() =>
            Base64Url.Decode(nonCanonical, expectedLength: 32));

        Assert.Contains("canonical", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(new byte[32], Base64Url.Decode(canonical, expectedLength: 32));
    }

    [Fact]
    public void CrossLanguageVocabularyAcceptsColonIdsAndUnicodePricingText()
    {
        const string pricingVersion = "pricing/2026.07-v1-🚀";
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-cross-language-vocabulary"),
            promotionAudience: "daxalgo:platform-prod",
            attestationAudience: "daxalgo:platform-prod",
            attestationKeyId: "readiness:key-v1",
            creditPricingVersion: pricingVersion);

        options.Validate();
        VibeQuantModelPromotionVerifier.ValidateCreditPricingVersion(pricingVersion);
        VibeQuantModelPromotionVerifier.ValidateExpertContextIdentity(
            ".private-corpus_v1",
            "Corpus ID");
        VibeQuantModelPromotionVerifier.ValidateExpertContextVersion(
            "_2026.07-v1",
            "Corpus version");
        VibeQuantModelPromotionVerifier.ValidateProviderIdentity(
            "p" + new string(':', 99),
            "Provider ID");

        Assert.Throws<InvalidOperationException>(() =>
            VibeQuantModelPromotionVerifier.ValidateCreditPricingVersion("pricing\u0007v1"));
        Assert.Throws<InvalidOperationException>(() =>
            VibeQuantModelPromotionVerifier.ValidateExpertContextIdentity(
                "private:corpus",
                "Corpus ID"));
        Assert.Throws<InvalidOperationException>(() =>
            VibeQuantModelPromotionVerifier.ValidateExpertContextVersion("MaIn", "Corpus version"));
        Assert.Throws<InvalidOperationException>(() =>
            VibeQuantModelPromotionVerifier.ValidateProviderIdentity(
                new string('p', 101),
                "Provider ID"));

        var mutableCorpusOptions = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-mutable-corpus-version"),
            expertContextCorpusVersion: "LATEST");
        Assert.Throws<InvalidOperationException>(mutableCorpusOptions.Validate);
        var corpusAliasOptions = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-corpus-alias"),
            expertContextCorpusId: "corpus:private");
        Assert.Throws<InvalidOperationException>(corpusAliasOptions.Validate);
        var longProviderOptions = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-long-provider"),
            providerId: new string('p', 101));
        Assert.Throws<InvalidOperationException>(longProviderOptions.Validate);
    }

    [Fact]
    public void PythonAuthoredGoldenProfileHasTheSameExecutionIdentity()
    {
        var profilePath = FindRepositoryFixturePath("serving-profile.v1.golden.json");
        var actualSha256 = ContentHasher.HashBytes(File.ReadAllBytes(profilePath));
        Assert.Equal(GoldenProfileSha256, actualSha256);
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            profilePath,
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-golden-profile-workspace"));
        options.Validate();

        var catalog = new VibeQuantModelDeploymentCatalog(
            options,
            new ManualTimeProvider(GoldenValidationTime));

        Assert.Equal(
            VibeQuantModelDeploymentCatalog.ExecutionModelPrefix + GoldenProfileSha256,
            catalog.ExecutionModelId);
        Assert.Equal("daxalgo-expert-qwen25-7b-v1", catalog.PublicModelId);
        var identity = Assert.IsType<VibeQuantModelDeploymentIdentity>(catalog.Identity);
        Assert.Equal(GoldenEnvelopeSha256, identity.PromotionEnvelopeSha256);
        Assert.Equal(GoldenPayloadSha256, identity.PromotionPayloadSha256);
        Assert.Equal("vqdpl-prod", identity.DeploymentId);
        Assert.Equal("daxalgo-private", identity.ProviderId);
        Assert.Equal(GoldenHostedPolicySha256, identity.HostedPolicySha256);
        Assert.Equal("2027-07-27T12:00:00Z", identity.PromotionExpiresAtUtcText);
        Assert.Equal(GoldenSpkiSha256, options.ModelPromotionPublicKeySpkiSha256);
        using var envelope = JsonDocument.Parse(File.ReadAllBytes(
            FindRepositoryFixturePath("model-promotion-envelope.v1.golden.json")));
        using var payload = JsonDocument.Parse(Base64Url.Decode(
            envelope.RootElement.GetProperty("payload").GetString()!));
        Assert.Equal(GoldenPromotionId, payload.RootElement.GetProperty("promotionId").GetString());
        Assert.True(catalog.AuthorizesPurpose(CoordinatorRunPurpose.Research));
        Assert.False(catalog.AuthorizesPurpose(CoordinatorRunPurpose.StrategyAuthoring));
    }

    [Fact]
    public void PythonAuthoredStrategyV2PromotionAuthorizesTheExactInertProfile()
    {
        var profilePath = FindRepositoryFixturePath("serving-profile.v1.golden.json");
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            profilePath,
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-strategy-v2-workspace"),
            promotionEnvelopePath: FindRepositoryFixturePath(
                "model-promotion-envelope.v1.strategy-authoring-v2.golden.json"),
            promotionEnvelopeSha256: StrategyV2EnvelopeSha256,
            promotionPublicKeyPath: FindRepositoryFixturePath(
                "model-promotion-public-key.v1.strategy-authoring-v2.golden.pem"),
            promotionPublicKeySpkiSha256: StrategyV2SpkiSha256,
            promotionKeyId: "model-promotion-strategy-v2-golden");
        options.Validate();
        var clock = new ManualTimeProvider(GoldenValidationTime);

        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = Assert.IsType<VibeQuantModelDeploymentIdentity>(catalog.Identity);
        Assert.Equal(StrategyV2PayloadSha256, identity.PromotionPayloadSha256);
        Assert.Equal(StrategyV2HostedPolicySha256, identity.HostedPolicySha256);
        Assert.True(catalog.AuthorizesPurpose(CoordinatorRunPurpose.Research));
        Assert.True(catalog.AuthorizesPurpose(CoordinatorRunPurpose.StrategyAuthoring));

        var envelope = new VibeQuantSpecificationFactory(options, clock, catalog).Create(
            Guid.NewGuid(),
            Guid.NewGuid(),
            new CreateVibeQuantRunRequest(
                "Create inert strategy source for review.",
                [],
                CoordinatorRunPurpose.StrategyAuthoring));
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
            envelope.ExecutionSpecJson,
            CoordinatorJson.Options);
        Assert.NotNull(executionSpec);
        Assert.Equal(CoordinatorVersions.StrategyPolicy, executionSpec.PolicyVersion);
        Assert.Equal(CoordinatorVersions.StrategyWorkflow, executionSpec.WorkflowVersion);
        Assert.Equal(CoordinatorVersions.StrategyPromptCatalogSha256, executionSpec.PromptCatalogSha256);
        Assert.Equal("openai-compatible", executionSpec.Provider.Protocol);
    }

    [Theory]
    [InlineData(HostedPolicyMutation.V1Capability)]
    [InlineData(HostedPolicyMutation.MissingCapability)]
    [InlineData(HostedPolicyMutation.NullCapability)]
    [InlineData(HostedPolicyMutation.ExtraCapabilityField)]
    [InlineData(HostedPolicyMutation.Purpose)]
    [InlineData(HostedPolicyMutation.ExecutionModel)]
    [InlineData(HostedPolicyMutation.Policy)]
    [InlineData(HostedPolicyMutation.Workflow)]
    [InlineData(HostedPolicyMutation.PromptCatalog)]
    public void SignedHostedPolicyRejectsStrategyCapabilityShapeAndIdentityMutations(
        HostedPolicyMutation mutation)
    {
        var sourceEnvelope = mutation == HostedPolicyMutation.V1Capability
            ? "model-promotion-envelope.v1.golden.json"
            : "model-promotion-envelope.v1.strategy-authoring-v2.golden.json";
        using var promotion = ResignedPromotionFixture.Create(
            sourceEnvelopeFileName: sourceEnvelope,
            hostedPolicyMutation: mutation);
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(promotion.RootPath, "workspace"),
            promotionFixture: promotion);
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new VibeQuantModelDeploymentCatalog(options, new ManualTimeProvider(GoldenValidationTime)));

        Assert.Contains("strategy-authoring", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SignedNonCanonicalPromotionPayloadIsRejected()
    {
        using var fixture = ServingProfileFixture.Create();
        using var promotion = ResignedPromotionFixture.Create(nonCanonicalPayload: true);
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(fixture.ProfileSha256),
            fixture.ProfilePath,
            fixture.ProfileSha256,
            Path.Combine(fixture.RootPath, "workspace"),
            promotionFixture: promotion);
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new VibeQuantModelDeploymentCatalog(
                options,
                new ManualTimeProvider(
                    new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero))));

        Assert.Contains("canonical JSON", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MathematicallyValidHighSSignatureIsRejected()
    {
        using var fixture = ServingProfileFixture.Create();
        using var promotion = ResignedPromotionFixture.Create(highSSignature: true);
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(fixture.ProfileSha256),
            fixture.ProfilePath,
            fixture.ProfileSha256,
            Path.Combine(fixture.RootPath, "workspace"),
            promotionFixture: promotion);
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new VibeQuantModelDeploymentCatalog(
                options,
                new ManualTimeProvider(
                    new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero))));

        Assert.Contains("low-S", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SignedHostedPolicyMustMatchTheActiveServerPolicy()
    {
        var profilePath = FindRepositoryFixturePath("serving-profile.v1.golden.json");
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            profilePath,
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-policy-binding-workspace"),
            inputUsdPerMillionTokens: 0.26m);
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            new VibeQuantModelDeploymentCatalog(
                options,
                new ManualTimeProvider(
                    new DateTimeOffset(2026, 7, 27, 12, 0, 0, TimeSpan.Zero))));

        Assert.Contains("hosted policy", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileSeparatesPublicNameFromExecutionArtifactIdentity()
    {
        var profilePath = FindRepositoryFixturePath("serving-profile.v1.golden.json");
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            profilePath,
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), "daxalgo-profile-separation-workspace"));
        options.Validate();
        var factory = new VibeQuantSpecificationFactory(
            options,
            new ManualTimeProvider(GoldenValidationTime));

        var envelope = factory.Create(
            Guid.NewGuid(),
            Guid.NewGuid(),
            new CreateVibeQuantRunRequest(
                "Assess risk-adjusted strategy evidence.",
                [new CoordinatorContextSource("caller", "Caller evidence", "Risk budget evidence.")]));
        var publicSpec = JsonSerializer.Deserialize<VibeQuantRunSpecification>(
            envelope.SpecJson,
            CoordinatorJson.Options);
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
            envelope.ExecutionSpecJson,
            CoordinatorJson.Options);

        Assert.NotNull(publicSpec);
        Assert.NotNull(executionSpec);
        Assert.Equal("daxalgo-expert-qwen25-7b-v1", publicSpec.Provider.ModelId);
        Assert.Equal(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            executionSpec.Provider.ModelId);
        Assert.DoesNotContain(GoldenProfileSha256, envelope.SpecJson, StringComparison.Ordinal);
        Assert.DoesNotContain(profilePath, envelope.SpecJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(profilePath, envelope.ExecutionSpecJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileRejectsChangedBytes()
    {
        using var fixture = ServingProfileFixture.Create();
        var options = fixture.CreateLiveOptions();
        File.AppendAllText(fixture.ProfilePath, " ", new UTF8Encoding(false));

        var createFactory = () => new VibeQuantSpecificationFactory(
            options,
            new ManualTimeProvider(GoldenValidationTime));

        var exception = Assert.Throws<InvalidOperationException>(createFactory);
        Assert.Contains("pinned SHA-256", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileRejectsDuplicateProperties()
    {
        using var fixture = ServingProfileFixture.Create();
        var original = File.ReadAllText(fixture.ProfilePath, Encoding.UTF8);
        File.WriteAllText(
            fixture.ProfilePath,
            original.Replace(
                "{",
                "{\"profileId\":\"duplicate\",",
                StringComparison.Ordinal),
            new UTF8Encoding(false));
        var sha256 = ContentHasher.HashBytes(File.ReadAllBytes(fixture.ProfilePath));
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(sha256),
            fixture.ProfilePath,
            sha256,
            Path.Combine(fixture.RootPath, "workspace"));
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(
            () => new VibeQuantSpecificationFactory(
                options,
                new ManualTimeProvider(GoldenValidationTime)));

        Assert.Contains("duplicate", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileRejectsModelAliasNotDerivedFromProfile()
    {
        using var fixture = ServingProfileFixture.Create();
        var options = CreateLiveOptions(
            "friendly-mutable-alias",
            fixture.ProfilePath,
            fixture.ProfileSha256,
            Path.Combine(fixture.RootPath, "workspace"));
        options.Validate();

        var createFactory = () => new VibeQuantSpecificationFactory(
            options,
            new ManualTimeProvider(GoldenValidationTime));

        var exception = Assert.Throws<InvalidOperationException>(createFactory);
        Assert.Contains("model ID", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileRejectsSemanticallyInvalidArtifactIdentity()
    {
        using var fixture = ServingProfileFixture.Create(
            profile => profile with
            {
                TrainingArtifact = profile.TrainingArtifact with { ArtifactTreeSha256 = "not-a-sha" }
            });
        var options = fixture.CreateLiveOptions();
        options.Validate();

        var createFactory = () => new VibeQuantSpecificationFactory(
            options,
            new ManualTimeProvider(GoldenValidationTime));

        var exception = Assert.Throws<InvalidOperationException>(createFactory);
        Assert.Contains("artifact tree", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileRejectsSmokeArtifacts()
    {
        using var fixture = ServingProfileFixture.Create(
            profile => profile with
            {
                TrainingArtifact = profile.TrainingArtifact with { Mode = "smoke" }
            });
        var options = fixture.CreateLiveOptions();
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(
            () => new VibeQuantSpecificationFactory(
                options,
                new ManualTimeProvider(GoldenValidationTime)));

        Assert.Contains("mode", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PinnedServingProfileRejectsCandidateRuntimeMismatch()
    {
        using var fixture = ServingProfileFixture.Create(
            profile => profile with
            {
                Runtime = profile.Runtime with { MaxModelLength = 32_769 }
            });
        var options = fixture.CreateLiveOptions();
        options.Validate();

        var exception = Assert.Throws<InvalidOperationException>(
            () => new VibeQuantSpecificationFactory(
                options,
                new ManualTimeProvider(GoldenValidationTime)));

        Assert.Contains("incompatible", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LiveModeRequiresPinnedServingProfileConfiguration()
    {
        var options = CreateLiveOptions(
            modelId: "daxalgo-expert-sha256-" + new string('a', 64),
            profilePath: null,
            profileSha256: null,
            workspacePath: Path.Combine(Path.GetTempPath(), "daxalgo-missing-serving-profile"));

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.Contains("serving-profile path", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MockModePreservesLegacyModelIdentityAndIgnoresDeploymentFields()
    {
        var options = new VibeQuantOptions
        {
            Mode = "Mock",
            ProviderId = "mock",
            ModelId = "deterministic-v1",
            Protocol = "mock",
            ModelDeploymentProfilePath = Path.Combine(Path.GetTempPath(), "does-not-exist.json"),
            ModelDeploymentProfileSha256 = "not-a-sha"
        };
        options.Validate();
        var factory = new VibeQuantSpecificationFactory(
            options,
            new ManualTimeProvider(GoldenValidationTime));

        var envelope = factory.Create(
            Guid.NewGuid(),
            Guid.NewGuid(),
            new CreateVibeQuantRunRequest(
                "Assess evidence.",
                [new CoordinatorContextSource("caller", "Caller", "Evidence")]));
        var publicSpec = JsonSerializer.Deserialize<VibeQuantRunSpecification>(
            envelope.SpecJson,
            CoordinatorJson.Options);
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
            envelope.ExecutionSpecJson,
            CoordinatorJson.Options);

        Assert.Equal("deterministic-v1", publicSpec?.Provider.ModelId);
        Assert.Equal("deterministic-v1", executionSpec?.Provider.ModelId);
    }

    [Fact]
    public async Task LiveReadinessUsesAHashPrivateProofAndExpiresTheCachedLease()
    {
        var profilePath = FindRepositoryFixturePath("serving-profile.v1.golden.json");
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            profilePath,
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), $"daxalgo-readiness-{suffix}"),
            apiKeyEnvironment,
            attestationKeyEnvironment);
        options.Validate();
        var clock = new ManualTimeProvider(GoldenValidationTime);
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = catalog.Identity!;
        var key = Enumerable.Range(0, 32).Select(value => checked((byte)value)).ToArray();
        var handler = new AttestationHandler(options, identity, key);
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(attestationKeyEnvironment, Base64Url.Encode(key));
        using var clientFactory = new SingleHttpClientFactory(handler);
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        try
        {
            await readiness.StartAsync(default);

            Assert.True(readiness.IsReady);
            Assert.True(readiness.IsReadyFor(identity.ExecutionModelId));
            Assert.False(readiness.IsReadyFor("daxalgo-expert-sha256-" + new string('f', 64)));
            Assert.DoesNotContain(identity.ServingProfileSha256, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.ArtifactSha256, handler.ResponseJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.ArtifactTreeSha256, handler.ResponseJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.ExecutionModelId, handler.ResponseJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionEnvelopeSha256, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionPayloadSha256, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.DeploymentId, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.ProviderId, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.HostedPolicySha256, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionExpiresAtUtcText, handler.RequestJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionEnvelopeSha256, handler.ResponseJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionPayloadSha256, handler.ResponseJson, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.HostedPolicySha256, handler.ResponseJson, StringComparison.Ordinal);

            clock.Advance(TimeSpan.FromSeconds(options.ModelAttestationTtlSeconds + 1));
            Assert.False(readiness.IsReady);
            var health = await new VibeQuantModelReadinessHealthCheck(readiness)
                .CheckHealthAsync(new HealthCheckContext());
            Assert.Equal(HealthStatus.Unhealthy, health.Status);
        }
        finally
        {
            await readiness.StopAsync(default);
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task ReadinessLeaseCannotOutliveTheSignedPromotion()
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), $"daxalgo-expiry-{suffix}"),
            apiKeyEnvironment,
            attestationKeyEnvironment);
        var clock = new ManualTimeProvider(
            new DateTimeOffset(2027, 7, 27, 11, 59, 55, TimeSpan.Zero));
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = catalog.Identity!;
        var key = Enumerable.Range(0, 32).Select(value => checked((byte)value)).ToArray();
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(attestationKeyEnvironment, Base64Url.Encode(key));
        using var clientFactory = new SingleHttpClientFactory(
            new AttestationHandler(options, identity, key));
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        try
        {
            await readiness.StartAsync(default);
            Assert.True(readiness.IsReady);

            clock.Advance(TimeSpan.FromSeconds(6));

            Assert.False(readiness.IsReady);
        }
        finally
        {
            await readiness.StopAsync(default);
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task LiveReadinessRejectsAMismatchedProofWithoutLeakingIdentity()
    {
        var profilePath = FindRepositoryFixturePath("serving-profile.v1.golden.json");
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            profilePath,
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), $"daxalgo-readiness-{suffix}"),
            apiKeyEnvironment,
            attestationKeyEnvironment);
        var clock = new ManualTimeProvider(GoldenValidationTime);
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = catalog.Identity!;
        var key = Enumerable.Range(0, 32).Select(value => checked((byte)value)).ToArray();
        var handler = new AttestationHandler(options, identity, key, corruptProof: true);
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(attestationKeyEnvironment, Base64Url.Encode(key));
        using var clientFactory = new SingleHttpClientFactory(handler);
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        try
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(
                () => readiness.StartAsync(default));

            Assert.False(readiness.IsReady);
            Assert.DoesNotContain(identity.ServingProfileSha256, exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.ExecutionModelId, exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.PromotionPayloadSha256, exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(identity.HostedPolicySha256, exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            await readiness.StopAsync(default);
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Theory]
    [InlineData(AttestationResponseKind.CaseVariantProof)]
    [InlineData(AttestationResponseKind.AliasDuplicateProof)]
    public async Task LiveReadinessRejectsCaseVariantsAndAliasDuplicates(
        AttestationResponseKind responseKind)
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), $"daxalgo-readiness-wire-{suffix}"),
            apiKeyEnvironment,
            attestationKeyEnvironment);
        var clock = new ManualTimeProvider(GoldenValidationTime);
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = Assert.IsType<VibeQuantModelDeploymentIdentity>(catalog.Identity);
        var key = Enumerable.Range(0, 32).Select(value => checked((byte)value)).ToArray();
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(attestationKeyEnvironment, Base64Url.Encode(key));
        using var clientFactory = new SingleHttpClientFactory(
            new AttestationHandler(options, identity, key, responseKind: responseKind));
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => readiness.StartAsync(default));
            Assert.False(readiness.IsReady);
        }
        finally
        {
            await readiness.StopAsync(default);
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task EveryProviderDispatchRechecksThePromotionBoundReadinessLease()
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var apiKeyEnvironment = $"DAXALGO_LLM_TEST_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var options = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            Path.Combine(Path.GetTempPath(), $"daxalgo-dispatch-{suffix}"),
            apiKeyEnvironment,
            attestationKeyEnvironment);
        var clock = new ManualTimeProvider(GoldenValidationTime);
        var catalog = new VibeQuantModelDeploymentCatalog(options, clock);
        var identity = catalog.Identity!;
        var key = Enumerable.Range(0, 32).Select(value => checked((byte)value)).ToArray();
        var handler = new AttestationHandler(options, identity, key);
        Environment.SetEnvironmentVariable(apiKeyEnvironment, "test-provider-secret");
        Environment.SetEnvironmentVariable(attestationKeyEnvironment, Base64Url.Encode(key));
        using var clientFactory = new SingleHttpClientFactory(handler);
        var readiness = new VibeQuantModelReadinessService(
            options,
            clientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            catalog);
        try
        {
            await readiness.StartAsync(default);
            var inner = new CountingLlmProvider(new LlmProviderDescriptor(
                options.ProviderId,
                identity.ExecutionModelId,
                options.Protocol,
                options.BaseUrl,
                options.InputUsdPerMillionTokens,
                options.OutputUsdPerMillionTokens,
                options.ApiKeyEnvironmentVariable));
            var gated = new VibeQuantExecutionRuntime.ReadinessGatedLlmProvider(
                inner,
                readiness);

            _ = await gated.CompleteAsync(null!);
            Assert.Equal(1, inner.CallCount);
            clock.Advance(TimeSpan.FromSeconds(options.ModelAttestationTtlSeconds + 1));
            var unavailable = await gated.CompleteAsync(null!);

            Assert.Equal(1, inner.CallCount);
            Assert.Equal(LlmFailureKinds.ProviderUnavailable, unavailable.Failure?.Kind);
            Assert.True(unavailable.Failure?.Retryable is true);
        }
        finally
        {
            await readiness.StopAsync(default);
            Environment.SetEnvironmentVariable(apiKeyEnvironment, null);
            Environment.SetEnvironmentVariable(attestationKeyEnvironment, null);
        }
    }

    [Fact]
    public async Task PostExecutionAccessSurvivesActivationRotationWithoutProviderConstruction()
    {
        var suffix = Guid.NewGuid().ToString("N").ToUpperInvariant();
        var workspace = Path.Combine(
            Path.GetTempPath(),
            $"daxalgo-post-execution-rotation-{suffix}");
        var retiredApiKeyEnvironment = $"DAXALGO_LLM_RETIRED_{suffix}";
        var currentApiKeyEnvironment = $"DAXALGO_LLM_CURRENT_{suffix}";
        var attestationKeyEnvironment = $"DAXALGO_MODEL_ATTESTATION_TEST_{suffix}";
        var retiredOptions = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            workspace,
            retiredApiKeyEnvironment,
            attestationKeyEnvironment,
            baseUrl: "https://retired-inference.example.test/v1");
        var currentOptions = CreateLiveOptions(
            VibeQuantModelDeploymentCatalog.CreateExecutionModelId(GoldenProfileSha256),
            FindRepositoryFixturePath("serving-profile.v1.golden.json"),
            GoldenProfileSha256,
            workspace,
            currentApiKeyEnvironment,
            attestationKeyEnvironment,
            baseUrl: "https://current-inference.example.test/v1");
        var clock = new ManualTimeProvider(GoldenValidationTime);
        var retiredCatalog = new VibeQuantModelDeploymentCatalog(retiredOptions, clock);
        var currentCatalog = new VibeQuantModelDeploymentCatalog(currentOptions, clock);
        Assert.NotEqual(retiredCatalog.ActivationSha256, currentCatalog.ActivationSha256);
        var retiredFactory = new VibeQuantSpecificationFactory(
            retiredOptions,
            clock,
            retiredCatalog);
        var currentFactory = new VibeQuantSpecificationFactory(
            currentOptions,
            clock,
            currentCatalog);
        var accountId = Guid.NewGuid();
        var runId = Guid.NewGuid();
        var envelope = retiredFactory.Create(
            accountId,
            runId,
            new CreateVibeQuantRunRequest(
                "Assess RiskBudget evidence after activation rotation.",
                [new CoordinatorContextSource("caller", "Caller", "RiskBudget evidence.")]));
        var executionSpec = JsonSerializer.Deserialize<CoordinatorRunSpec>(
                envelope.ExecutionSpecJson,
                CoordinatorJson.Options)
            ?? throw new InvalidOperationException("Execution specification was null.");
        var run = new VibeQuantRun
        {
            Id = runId,
            AccountId = accountId,
            IdempotencyKey = $"post-execution-{runId:N}",
            RequestSha256 = envelope.RequestSha256,
            SpecSha256 = envelope.SpecSha256,
            SpecJson = envelope.SpecJson,
            ExecutionSpecJson = envelope.ExecutionSpecJson,
            ExecutionSpecSha256 = envelope.ExecutionSpecSha256,
            ExecutionProfileBinding = envelope.ExecutionProfileBinding,
            ExecutionBindingNonce = envelope.ExecutionBindingNonce,
            Status = CoordinatorRunStatus.AwaitingReleaseApproval,
            UsageJson = JsonSerializer.Serialize(new CoordinatorUsage(), CoordinatorJson.Options),
        };
        var root = Path.Combine(
            workspace,
            "runs",
            accountId.ToString("N"),
            runId.ToString("N"));
        Directory.CreateDirectory(root);
        var store = new SqliteCoordinatorStore(Path.Combine(root, "coordinator.db"));
        var artifacts = new ContentAddressedArtifactStore(Path.Combine(root, "artifacts"));
        var coordinator = new ResearchCoordinator(
            store,
            artifacts,
            new DeterministicMockLlmProvider(executionSpec.Provider));
        await store.InitializeAsync(default);
        var snapshot = await coordinator.CreateAsync(executionSpec, default);
        snapshot = await coordinator.ApproveStartAsync(
            runId,
            "test-approver",
            ContentHasher.HashJson(snapshot.Spec),
            default);
        snapshot = await coordinator.ResumeAsync(runId, recordCancellation: false, default);
        Assert.Equal(CoordinatorRunStatus.AwaitingReleaseApproval, snapshot.Status);
        var artifactSha256 = Assert.IsType<string>(snapshot.FinalArtifactSha256);

        var httpClientFactory = new ThrowingHttpClientFactory();
        var readiness = new VibeQuantModelReadinessService(
            currentOptions,
            httpClientFactory,
            clock,
            NullLogger<VibeQuantModelReadinessService>.Instance,
            currentCatalog);
        var runtime = new VibeQuantExecutionRuntime(
            currentOptions,
            httpClientFactory,
            readiness,
            currentFactory,
            NullLogger<VibeQuantExecutionRuntime>.Instance);
        try
        {
            var artifact = await runtime.ReadArtifactAsync(run, artifactSha256, default);
            var approved = await runtime.ApproveReleaseAsync(run, artifactSha256, default);
            await runtime.CancelAsync(run, default);

            Assert.Equal(artifactSha256, artifact.Sha256);
            Assert.Equal(CoordinatorRunStatus.Completed, approved.Status);
            Assert.Equal(0, httpClientFactory.CallCount);
            Assert.Null(Environment.GetEnvironmentVariable(retiredApiKeyEnvironment));
        }
        finally
        {
            await readiness.StopAsync(default);
            var fullWorkspace = Path.GetFullPath(workspace);
            var expectedParent = Path.GetFullPath(Path.GetTempPath());
            if (fullWorkspace.StartsWith(expectedParent, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(fullWorkspace).StartsWith(
                    "daxalgo-post-execution-rotation-",
                    StringComparison.Ordinal) &&
                Directory.Exists(fullWorkspace))
            {
                SqliteConnection.ClearAllPools();
                Directory.Delete(fullWorkspace, recursive: true);
            }
        }
    }

    private static VibeQuantOptions CreateLiveOptions(
        string modelId,
        string? profilePath,
        string? profileSha256,
        string workspacePath,
        string apiKeyEnvironmentVariable = "DAXALGO_LLM_EXPERT_MODEL",
        string attestationKeyEnvironmentVariable = "DAXALGO_MODEL_ATTESTATION_TEST",
        ResignedPromotionFixture? promotionFixture = null,
        decimal inputUsdPerMillionTokens = 0.25m,
        string promotionAudience = "daxalgo-platform-prod",
        string attestationAudience = "daxalgo-platform-prod",
        string attestationKeyId = "test-hmac-v1",
        string creditPricingVersion = "development-v1",
        string baseUrl = "https://inference.example.test/v1",
        string providerId = "daxalgo-private",
        string expertContextCorpusId = "daxalgo-private",
        string expertContextCorpusVersion = "2026.07.27-test",
        string? promotionEnvelopePath = null,
        string? promotionEnvelopeSha256 = null,
        string? promotionPublicKeyPath = null,
        string? promotionPublicKeySpkiSha256 = null,
        string promotionKeyId = "model-promotion-golden-v1") => new()
        {
            Mode = "Live",
            WorkspacePath = workspacePath,
            ProviderId = providerId,
            ModelId = modelId,
            Protocol = "openai-compatible",
            BaseUrl = baseUrl,
            ApiKeyEnvironmentVariable = apiKeyEnvironmentVariable,
            ModelDeploymentProfilePath = profilePath,
            ModelDeploymentProfileSha256 = profileSha256,
            ModelPromotionEnvelopePath = promotionFixture?.EnvelopePath ?? promotionEnvelopePath ??
                FindRepositoryFixturePath("model-promotion-envelope.v1.golden.json"),
            ModelPromotionEnvelopeSha256 = promotionFixture?.EnvelopeSha256 ?? promotionEnvelopeSha256 ??
                GoldenEnvelopeSha256,
            ModelPromotionPublicKeyPath = promotionFixture?.PublicKeyPath ?? promotionPublicKeyPath ??
                FindRepositoryFixturePath("model-promotion-public-key.v1.golden.pem"),
            ModelPromotionPublicKeySpkiSha256 = promotionFixture?.PublicKeySpkiSha256 ??
                promotionPublicKeySpkiSha256 ??
                GoldenSpkiSha256,
            ModelPromotionAudience = promotionAudience,
            ModelPromotionKeyId = promotionFixture?.KeyId ?? promotionKeyId,
            ModelPromotionSignerRole = "production-model-approver",
            ModelPromotionDeploymentId = "vqdpl-prod",
            ModelPromotionEnvironment = "production",
            ModelAttestationAudience = attestationAudience,
            ModelAttestationKeyId = attestationKeyId,
            ModelAttestationKeyEnvironmentVariable = attestationKeyEnvironmentVariable,
            InputUsdPerMillionTokens = inputUsdPerMillionTokens,
            OutputUsdPerMillionTokens = 0.75m,
            CreditPricingVersion = creditPricingVersion,
            ExpertContextMode = "Pinned",
            ExpertContextPackPath = FindPlatformTestDataPath(
                "expert-context-pack.v1.promotion.json"),
            ExpertContextCorpusId = expertContextCorpusId,
            ExpertContextCorpusVersion = expertContextCorpusVersion,
            ExpertContextPackSha256 =
                "3c273cdd7ee54f9bfd5933451c2c1530d893400e3e6595b003fda08a499b0e65",
            ExpertContextTopK = 1,
            ExpertContextMaxCharacters = 10_000,
            ExpertContextMaxPerSource = 1,
            ExpertContextQueryMaxCharacters = 30_000
        };

    private sealed class SingleHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory, IDisposable
    {
        private readonly HttpClient client = new(handler, disposeHandler: true);

        public HttpClient CreateClient(string name) => client;

        public void Dispose() => client.Dispose();
    }

    private sealed class ThrowingHttpClientFactory : IHttpClientFactory
    {
        private int callCount;

        public int CallCount => Volatile.Read(ref callCount);

        public HttpClient CreateClient(string name)
        {
            Interlocked.Increment(ref callCount);
            throw new InvalidOperationException("A retired provider client must not be created.");
        }
    }

    private sealed class CountingLlmProvider(LlmProviderDescriptor descriptor) : ILlmProvider
    {
        private int callCount;

        public LlmProviderDescriptor Descriptor { get; } = descriptor;

        public int CallCount => Volatile.Read(ref callCount);

        public Task<LlmCallResult> CompleteAsync(
            LlmRequest request,
            CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            Interlocked.Increment(ref callCount);
            return Task.FromResult(LlmCallResult.Failed("test", "Inner provider called."));
        }
    }

    private sealed class AttestationHandler(
        VibeQuantOptions options,
        VibeQuantModelDeploymentIdentity identity,
        byte[] key,
        bool corruptProof = false,
        AttestationResponseKind responseKind = AttestationResponseKind.Valid) : HttpMessageHandler
    {
        public string RequestJson { get; private set; } = string.Empty;

        public string ResponseJson { get; private set; } = string.Empty;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestJson = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(RequestJson);
            var nonce = document.RootElement.GetProperty("nonce").GetString()!;
            var proof = VibeQuantModelReadinessProof.Compute(
                key,
                options.ModelAttestationAudience!,
                nonce,
                options.ModelAttestationKeyId!,
                identity);
            if (corruptProof)
            {
                proof[0] ^= 0xff;
            }
            var proofText = Base64Url.Encode(proof);
            var response = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["schemaVersion"] = VibeQuantModelReadinessService.SchemaVersion,
                ["nonce"] = nonce,
                ["keyId"] = options.ModelAttestationKeyId,
            };
            if (responseKind != AttestationResponseKind.CaseVariantProof)
            {
                response["proof"] = proofText;
            }
            if (responseKind is AttestationResponseKind.CaseVariantProof or
                AttestationResponseKind.AliasDuplicateProof)
            {
                response["Proof"] = proofText;
            }
            ResponseJson = JsonSerializer.Serialize(response);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = new StringContent(ResponseJson, Encoding.UTF8, "application/json")
            };
        }
    }

    public enum AttestationResponseKind
    {
        Valid,
        CaseVariantProof,
        AliasDuplicateProof,
    }

    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset now = utcNow;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan duration) => now = now.Add(duration);
    }

    private static string FindRepositoryFixturePath(string fileName)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "tools",
                "hyperion-model",
                "tests",
                "fixtures",
                fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException($"Could not locate cross-language fixture '{fileName}'.");
    }

    private static string FindPlatformTestDataPath(string fileName)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "platform",
                "tests",
                "DaxAlgo.Platform.Api.Tests",
                "TestData",
                fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException($"Could not locate Platform test data '{fileName}'.");
    }

    private sealed class ResignedPromotionFixture : IDisposable
    {
        private static readonly JsonSerializerOptions CanonicalJsonOptions =
            new(JsonSerializerDefaults.Web);
        private static readonly BigInteger P256Order = BigInteger.Parse(
            "00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            NumberStyles.AllowHexSpecifier,
            System.Globalization.CultureInfo.InvariantCulture);

        private ResignedPromotionFixture(
            string rootPath,
            string envelopePath,
            string envelopeSha256,
            string publicKeyPath,
            string publicKeySpkiSha256,
            string keyId)
        {
            RootPath = rootPath;
            EnvelopePath = envelopePath;
            EnvelopeSha256 = envelopeSha256;
            PublicKeyPath = publicKeyPath;
            PublicKeySpkiSha256 = publicKeySpkiSha256;
            KeyId = keyId;
        }

        public string RootPath { get; }
        public string EnvelopePath { get; }
        public string EnvelopeSha256 { get; }
        public string PublicKeyPath { get; }
        public string PublicKeySpkiSha256 { get; }
        public string KeyId { get; }

        public static ResignedPromotionFixture Create(
            bool nonCanonicalPayload = false,
            bool highSSignature = false,
            string sourceEnvelopeFileName = "model-promotion-envelope.v1.golden.json",
            HostedPolicyMutation? hostedPolicyMutation = null)
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                $"daxalgo-promotion-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var envelope = JsonNode.Parse(File.ReadAllBytes(FindRepositoryFixturePath(
                    sourceEnvelopeFileName)))?.AsObject()
                ?? throw new InvalidOperationException("Golden model-promotion envelope is invalid.");
            var payload = Base64Url.Decode(envelope["payload"]!.GetValue<string>());
            if (hostedPolicyMutation is not null)
            {
                var payloadObject = JsonNode.Parse(payload)?.AsObject()
                    ?? throw new InvalidOperationException("Golden model-promotion payload is invalid.");
                ApplyHostedPolicyMutation(payloadObject, hostedPolicyMutation.Value);
                if (hostedPolicyMutation.Value is HostedPolicyMutation.Purpose or
                    HostedPolicyMutation.ExecutionModel or HostedPolicyMutation.Policy or
                    HostedPolicyMutation.Workflow or HostedPolicyMutation.PromptCatalog)
                {
                    RebindDerivedIdentities(payloadObject);
                }
                payload = JsonSerializer.SerializeToUtf8Bytes(
                    CloneWithCanonicalPropertyOrder(payloadObject),
                    CanonicalJsonOptions);
            }
            if (nonCanonicalPayload)
            {
                payload = [.. payload, (byte)'\n'];
            }

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var spki = key.ExportSubjectPublicKeyInfo();
            var spkiSha256 = ContentHasher.HashBytes(spki);
            envelope["payload"] = Base64Url.Encode(payload);
            envelope["payloadSha256"] = ContentHasher.HashBytes(payload);
            envelope["publicKeySpkiSha256"] = spkiSha256;
            var signature = key.SignData(
                CreateSignatureInput(envelope, payload),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            NormalizeSignatureS(signature, highSSignature);
            envelope["signature"] = Base64Url.Encode(signature);

            var publicKeyPath = Path.Combine(root, "promotion-public.pem");
            File.WriteAllText(
                publicKeyPath,
                key.ExportSubjectPublicKeyInfoPem(),
                new UTF8Encoding(false));
            var envelopePath = Path.Combine(root, "promotion-envelope.json");
            var envelopeBytes = JsonSerializer.SerializeToUtf8Bytes(
                envelope,
                CoordinatorJson.Options);
            File.WriteAllBytes(envelopePath, envelopeBytes);
            return new ResignedPromotionFixture(
                root,
                envelopePath,
                ContentHasher.HashBytes(envelopeBytes),
                publicKeyPath,
                spkiSha256,
                envelope["keyId"]!.GetValue<string>());
        }

        private static void ApplyHostedPolicyMutation(
            JsonObject payload,
            HostedPolicyMutation mutation)
        {
            var policy = payload["hostedDeploymentPolicy"]?.AsObject()
                ?? throw new InvalidOperationException("Golden hosted policy is invalid.");
            if (mutation == HostedPolicyMutation.V1Capability)
            {
                policy["strategyAuthoringCapability"] = CreateStrategyCapability(payload);
                return;
            }
            if (mutation == HostedPolicyMutation.MissingCapability)
            {
                policy.Remove("strategyAuthoringCapability");
                return;
            }
            if (mutation == HostedPolicyMutation.NullCapability)
            {
                policy["strategyAuthoringCapability"] = null;
                return;
            }
            var capability = policy["strategyAuthoringCapability"]?.AsObject()
                ?? throw new InvalidOperationException("Golden strategy capability is invalid.");
            switch (mutation)
            {
                case HostedPolicyMutation.ExtraCapabilityField:
                    capability["zzUnsupported"] = true;
                    break;
                case HostedPolicyMutation.Purpose:
                    capability["purpose"] = "Research";
                    break;
                case HostedPolicyMutation.ExecutionModel:
                    capability["executionModelId"] =
                        VibeQuantModelDeploymentCatalog.ExecutionModelPrefix + new string('f', 64);
                    break;
                case HostedPolicyMutation.Policy:
                    capability["policyVersion"] = CoordinatorVersions.Policy;
                    break;
                case HostedPolicyMutation.Workflow:
                    capability["workflowVersion"] = CoordinatorVersions.Workflow;
                    break;
                case HostedPolicyMutation.PromptCatalog:
                    capability["promptCatalogSha256"] = new string('f', 64);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mutation));
            }
        }

        private static JsonObject CreateStrategyCapability(JsonObject payload) => new()
        {
            ["executionModelId"] = payload["model"]!["executionModelId"]!.GetValue<string>(),
            ["policyVersion"] = CoordinatorVersions.StrategyPolicy,
            ["promptCatalogSha256"] = CoordinatorVersions.StrategyPromptCatalogSha256,
            ["purpose"] = "StrategyAuthoring",
            ["workflowVersion"] = CoordinatorVersions.StrategyWorkflow,
        };

        private static void RebindDerivedIdentities(JsonObject payload)
        {
            var policyNode = payload["hostedDeploymentPolicy"]?.AsObject()
                ?? throw new InvalidOperationException("Golden hosted policy is invalid.");
            var policy = JsonSerializer.Deserialize<VibeQuantHostedDeploymentPolicy>(
                JsonSerializer.SerializeToUtf8Bytes(
                    CloneWithCanonicalPropertyOrder(policyNode),
                    CanonicalJsonOptions),
                CoordinatorJson.Options)
                ?? throw new InvalidOperationException("Golden hosted policy cannot be rebound.");
            policyNode["policySha256"] =
                VibeQuantModelPromotionVerifier.ComputeHostedPolicySha256(policy);

            var promotion = JsonSerializer.Deserialize<VibeQuantModelPromotionPayload>(
                JsonSerializer.SerializeToUtf8Bytes(
                    CloneWithCanonicalPropertyOrder(payload),
                    CanonicalJsonOptions),
                CoordinatorJson.Options)
                ?? throw new InvalidOperationException("Golden promotion cannot be rebound.");
            payload["promotionId"] = "vqprom-" +
                VibeQuantModelPromotionVerifier.ComputePromotionIdSha256(promotion);
        }

        private static JsonNode? CloneWithCanonicalPropertyOrder(JsonNode? node)
        {
            if (node is JsonObject sourceObject)
            {
                var result = new JsonObject();
                foreach (var property in sourceObject.OrderBy(
                             item => item.Key,
                             StringComparer.Ordinal))
                {
                    result[property.Key] = CloneWithCanonicalPropertyOrder(property.Value);
                }
                return result;
            }
            if (node is JsonArray sourceArray)
            {
                var result = new JsonArray();
                foreach (var item in sourceArray)
                {
                    result.Add(CloneWithCanonicalPropertyOrder(item));
                }
                return result;
            }
            return node?.DeepClone();
        }

        private static byte[] CreateSignatureInput(JsonObject envelope, byte[] payload)
        {
            using var output = new MemoryStream();
            Append(output, "daxalgo-vibe-quant-model-promotion-signature/v1");
            foreach (var name in new[]
                     {
                         "schemaVersion",
                         "payloadType",
                         "payloadEncoding",
                         "algorithm",
                         "signatureFormat",
                         "audience",
                         "keyId",
                         "signerRole",
                         "publicKeySpkiSha256",
                         "payloadSha256",
                     })
            {
                Append(output, envelope[name]!.GetValue<string>());
            }
            Append(output, payload);
            return output.ToArray();
        }

        private static void Append(Stream output, string value) =>
            Append(output, Encoding.UTF8.GetBytes(value));

        private static void Append(Stream output, ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
            output.Write(length);
            output.Write(value);
        }

        private static void NormalizeSignatureS(byte[] signature, bool highS)
        {
            var s = new BigInteger(signature.AsSpan(32), isUnsigned: true, isBigEndian: true);
            if (s > P256Order / 2)
            {
                s = P256Order - s;
            }
            if (highS)
            {
                s = P256Order - s;
            }
            var encoded = s.ToByteArray(isUnsigned: true, isBigEndian: true);
            signature.AsSpan(32).Clear();
            encoded.CopyTo(signature.AsSpan(64 - encoded.Length));
        }

        public void Dispose()
        {
            var root = Path.GetFullPath(RootPath);
            var expectedParent = Path.GetFullPath(Path.GetTempPath());
            if (!root.StartsWith(expectedParent, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(root).StartsWith("daxalgo-promotion-tests-", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Refusing to remove an unexpected promotion test path.");
            }
            Directory.Delete(root, recursive: true);
        }
    }

    public enum HostedPolicyMutation
    {
        V1Capability,
        MissingCapability,
        NullCapability,
        ExtraCapabilityField,
        Purpose,
        ExecutionModel,
        Policy,
        Workflow,
        PromptCatalog,
    }

    private sealed class ServingProfileFixture : IDisposable
    {
        private ServingProfileFixture(
            string rootPath,
            string profilePath,
            string profileSha256,
            VibeQuantServingProfile profile)
        {
            RootPath = rootPath;
            ProfilePath = profilePath;
            ProfileSha256 = profileSha256;
            Profile = profile;
        }

        public string RootPath { get; }

        public string ProfilePath { get; }

        public string ProfileSha256 { get; }

        public VibeQuantServingProfile Profile { get; }

        public static ServingProfileFixture Create(
            Func<VibeQuantServingProfile, VibeQuantServingProfile>? transform = null)
        {
            var root = Path.Combine(
                Path.GetTempPath(),
                $"daxalgo-serving-profile-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
            var profile = new VibeQuantServingProfile
            {
                SchemaVersion = VibeQuantModelDeploymentCatalog.SchemaVersion,
                ProfileId = "daxalgo-expert-qwen25-7b-v1",
                CandidateCatalogSha256 = new string('1', 64),
                CandidateId = "qwen2.5-coder-7b-instruct",
                BaseModel = new VibeQuantServingBaseModel
                {
                    ModelId = "Qwen/Qwen2.5-Coder-7B-Instruct",
                    Revision = "c03e6d358207e414f1eca0bb1891e29f1db0e242"
                },
                TrainingArtifact = new VibeQuantServingTrainingArtifact
                {
                    Mode = "unpromoted-candidate",
                    TrainingRunManifestSha256 = new string('2', 64),
                    ArtifactSha256 = new string('3', 64),
                    ArtifactTreeSha256 = new string('4', 64)
                },
                ChatTemplateSha256 = new string('5', 64),
                Runtime = new VibeQuantServingRuntime
                {
                    Engine = "vllm",
                    EngineVersion = "0.10.0",
                    ContainerImageDigest = "sha256:" + new string('6', 64),
                    Quantization = "bitsandbytes-nf4",
                    ComputeDtype = "bfloat16",
                    MaxModelLength = 8_192,
                    TensorParallelSize = 1,
                    GpuProfile = "l40s-48gb"
                },
                Protocol = "openai-compatible"
            };
            profile = transform?.Invoke(profile) ?? profile;
            var bytes = JsonSerializer.SerializeToUtf8Bytes(profile, CoordinatorJson.Options);
            var profilePath = Path.Combine(root, "serving-profile.json");
            File.WriteAllBytes(profilePath, bytes);
            return new ServingProfileFixture(
                root,
                profilePath,
                ContentHasher.HashBytes(bytes),
                profile);
        }

        public VibeQuantOptions CreateLiveOptions() =>
            VibeQuantModelDeploymentTests.CreateLiveOptions(
                VibeQuantModelDeploymentCatalog.CreateExecutionModelId(ProfileSha256),
                ProfilePath,
                ProfileSha256,
                Path.Combine(RootPath, "workspace"));

        public void Dispose()
        {
            var root = Path.GetFullPath(RootPath);
            var expectedParent = Path.GetFullPath(Path.GetTempPath());
            if (!root.StartsWith(expectedParent, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(root).StartsWith(
                    "daxalgo-serving-profile-tests-",
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Refusing to remove an unexpected serving-profile test path.");
            }
            Directory.Delete(root, recursive: true);
        }
    }
}
