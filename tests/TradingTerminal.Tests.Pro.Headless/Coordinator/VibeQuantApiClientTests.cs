using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class VibeQuantApiClientTests
{
    [Fact]
    public async Task Create_sends_idempotency_key_and_parses_the_server_owned_specification()
    {
        var runId = Guid.NewGuid();
        var spec = CreateSpecification(runId, "Bounded objective.");
        var response = new VibeQuantRunSpecResponse(ContentHasher.HashJson(spec), spec);
        using var http = new HttpClient(new StubHandler(request =>
        {
            request.Method.Should().Be(HttpMethod.Post);
            request.RequestUri!.AbsolutePath.Should().Be("/api/v1/vibe-quant/runs");
            request.Headers.GetValues("Idempotency-Key").Should().ContainSingle("command-1");
            return JsonResponse(HttpStatusCode.Created, response);
        }))
        {
            BaseAddress = new Uri("https://platform.example"),
        };
        var client = new VibeQuantApiClient(http);

        var created = await client.CreateRunAsync(
            new CreateVibeQuantRunRequest("Bounded objective.", []),
            "command-1");

        created.Spec.RunId.Should().Be(runId);
        created.Spec.Provider.ModelId.Should().Be("model-v1");
        created.Spec.MaximumCreditCharge.Should().Be(500);
    }

    [Fact]
    public async Task Create_rejects_a_server_objective_that_does_not_match_the_submission()
    {
        var spec = CreateSpecification(Guid.NewGuid(), "Changed by server.");
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.Created,
            new VibeQuantRunSpecResponse(ContentHasher.HashJson(spec), spec)));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.CreateRunAsync(
            new CreateVibeQuantRunRequest("Submitted objective.", []),
            "objective-correlation");

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("objective");
    }

    [Fact]
    public async Task Create_rejects_a_prompt_catalog_that_does_not_match_the_submitted_purpose()
    {
        var spec = CreateSpecification(Guid.NewGuid(), "Bounded objective.") with
        {
            PromptCatalogSha256 = new string('d', 64)
        };
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.Created,
            new VibeQuantRunSpecResponse(ContentHasher.HashJson(spec), spec)));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.CreateRunAsync(
            new CreateVibeQuantRunRequest("Bounded objective.", []),
            "prompt-profile-correlation");

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("submitted purpose");
    }

    [Theory]
    [InlineData("mock")]
    [InlineData("openai-compatible")]
    public async Task Strategy_authoring_accepts_supported_protocols_with_the_exact_strategy_profile(
        string protocol)
    {
        var objective = "Create inert source for review.";
        var spec = CreateStrategySpecification(Guid.NewGuid(), objective) with
        {
            Provider = new VibeQuantProviderView("managed", "model-v1", protocol),
        };
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.Created,
            new VibeQuantRunSpecResponse(ContentHasher.HashJson(spec), spec)));
        var client = new VibeQuantApiClient(http);

        var response = await client.CreateRunAsync(
            new CreateVibeQuantRunRequest(objective, [], CoordinatorRunPurpose.StrategyAuthoring),
            "strategy-supported-profile");

        response.Spec.Provider.Protocol.Should().Be(protocol);
        response.Spec.PolicyVersion.Should().Be(CoordinatorVersions.StrategyPolicy);
    }

    [Fact]
    public async Task Strategy_authoring_rejects_an_unsupported_protocol_even_with_matching_profile_hashes()
    {
        var objective = "Create inert source for review.";
        var spec = CreateStrategySpecification(Guid.NewGuid(), objective) with
        {
            Provider = new VibeQuantProviderView("managed", "model-v1", "custom"),
        };
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.Created,
            new VibeQuantRunSpecResponse(ContentHasher.HashJson(spec), spec)));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.CreateRunAsync(
            new CreateVibeQuantRunRequest(objective, [], CoordinatorRunPurpose.StrategyAuthoring),
            "strategy-unsupported-profile");

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("submitted purpose");
    }

    [Fact]
    public async Task Start_rejects_a_status_for_a_different_specification_hash()
    {
        var runId = Guid.NewGuid();
        var approved = new string('a', 64);
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.Accepted,
            CreateStatus(runId, CoordinatorRunStatus.Ready, specSha256: new string('b', 64))));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.StartAsync(runId, approved);

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("approved specification");
    }

    [Theory]
    [InlineData(CoordinatorRunStatus.Cancelled)]
    [InlineData(CoordinatorRunStatus.Rejected)]
    public async Task Start_accepts_an_idempotent_terminal_response_for_the_same_specification(
        CoordinatorRunStatus terminalStatus)
    {
        var runId = Guid.NewGuid();
        var approved = new string('a', 64);
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.OK,
            CreateStatus(runId, terminalStatus, specSha256: approved)));
        var client = new VibeQuantApiClient(http);

        var result = await client.StartAsync(runId, approved);

        result.Status.Should().Be(terminalStatus);
        result.SpecSha256.Should().Be(approved);
    }

    [Fact]
    public async Task Release_rejects_a_status_for_a_different_artifact_hash()
    {
        var runId = Guid.NewGuid();
        var approved = new string('c', 64);
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.OK,
            CreateStatus(
                runId,
                CoordinatorRunStatus.Completed,
                finalArtifactSha256: new string('d', 64))));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.ReleaseAsync(runId, approved);

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("approved artifact");
    }

    [Fact]
    public async Task Cancel_rejects_a_running_status_without_durable_cancellation_intent()
    {
        var runId = Guid.NewGuid();
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.Accepted,
            CreateStatus(runId, CoordinatorRunStatus.Running, cancellationRequested: false)));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.CancelAsync(runId);

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("cancellation response");
    }

    [Fact]
    public async Task Problem_details_are_mapped_without_exposing_arbitrary_response_content()
    {
        using var http = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.PaymentRequired)
        {
            Content = new StringContent(
                "{\"detail\":\"More credits are required.\",\"secret\":\"do-not-return\"}",
                Encoding.UTF8,
                "application/problem+json"),
        }))
        {
            BaseAddress = new Uri("https://platform.example"),
        };
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetCreditsAsync();

        var failure = (await call.Should().ThrowAsync<VibeQuantApiException>()).Which;
        failure.StatusCode.Should().Be(HttpStatusCode.PaymentRequired);
        failure.Message.Should().Be("More credits are required.");
        failure.Message.Should().NotContain("do-not-return");
    }

    [Fact]
    public async Task Credit_response_rejects_negative_or_default_values()
    {
        using var http = new HttpClient(new StubHandler(_ => JsonResponse(
            HttpStatusCode.OK,
            new VibeQuantCreditBalanceResponse(-1, 0, 0, "pricing-v1", default))))
        {
            BaseAddress = new Uri("https://platform.example"),
        };
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetCreditsAsync();

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("credit balance");
    }

    [Fact]
    public async Task Status_response_must_match_the_requested_run()
    {
        var requested = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        using var http = new HttpClient(new StubHandler(_ => JsonResponse(
            HttpStatusCode.OK,
            new VibeQuantRunStatusResponse(
                Guid.NewGuid(),
                CoordinatorRunStatus.Running,
                new string('a', 64),
                1,
                false,
                10,
                0,
                null,
                null,
                now,
                now))))
        {
            BaseAddress = new Uri("https://platform.example"),
        };
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetStatusAsync(requested);

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("run status");
    }

    [Fact]
    public async Task Response_body_is_bounded_even_when_the_server_declares_success()
    {
        using var http = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[4_000_001]),
        }))
        {
            BaseAddress = new Uri("https://platform.example"),
        };
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetCreditsAsync();

        (await call.Should().ThrowAsync<VibeQuantApiException>()).Which.Message
            .Should().Contain("exceeded");
    }

    [Fact]
    public async Task Create_rejects_a_serialized_request_larger_than_eight_megabytes_before_sending()
    {
        var sent = false;
        using var http = CreateHttp(_ =>
        {
            sent = true;
            throw new InvalidOperationException("The oversized request must not be sent.");
        });
        var client = new VibeQuantApiClient(http);
        var request = new CreateVibeQuantRunRequest(
            "Bounded objective.",
            [new CoordinatorContextSource("large", "Large source", new string('x', 8_100_000))]);

        Func<Task> call = async () => await client.CreateRunAsync(request, "oversized-create");

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("byte limit");
        sent.Should().BeFalse();
    }

    [Fact]
    public async Task Response_body_is_bounded_when_content_length_is_unknown()
    {
        using var http = CreateHttp(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new UnknownLengthContent(4_000_001),
        });
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetCreditsAsync();

        (await call.Should().ThrowAsync<VibeQuantApiException>()).Which.Message
            .Should().Contain("exceeded");
    }

    [Fact]
    public async Task Strategy_artifact_response_accepts_only_hash_bound_inert_source()
    {
        var runId = Guid.NewGuid();
        const string source = "public sealed class GeneratedStrategy { }";
        var artifact = new CoordinatorStrategySourceArtifact
        {
            SchemaVersion = CoordinatorVersions.StrategyArtifactSchema,
            RunId = runId,
            ObjectiveSha256 = new string('a', 64),
            StrategyId = "generated-strategy",
            DisplayName = "Generated Strategy",
            Files = [new CoordinatorStrategySourceFile("Strategy.cs", source, ContentHasher.HashUtf8(source))],
            SynthesizerArtifactSha256 = new string('b', 64),
            RiskJudgeArtifactSha256 = new string('c', 64),
            DeliveryState = CoordinatorVersions.StrategyDeliveryState,
            CompilerProfile = CoordinatorVersions.StrategyCompilerProfile,
            RequiresHumanRelease = true,
            RequiresTerminalCompileConsent = true,
            InstallEligible = false
        };
        var routeHash = ContentHasher.HashJson(artifact);
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.OK,
            new VibeQuantArtifactResponse(
                runId,
                routeHash,
                CoordinatorRole.Synthesizer,
                null,
                artifact)));
        var client = new VibeQuantApiClient(http);

        var response = await client.GetArtifactAsync(runId, routeHash);

        response.StrategyArtifact.Should().BeEquivalentTo(artifact);
        response.Output.Should().BeNull();
    }

    [Fact]
    public async Task Strategy_artifact_response_rejects_an_ambiguous_output_union()
    {
        var runId = Guid.NewGuid();
        const string source = "public sealed class GeneratedStrategy { }";
        var artifact = new CoordinatorStrategySourceArtifact
        {
            SchemaVersion = CoordinatorVersions.StrategyArtifactSchema,
            RunId = runId,
            ObjectiveSha256 = new string('a', 64),
            StrategyId = "generated-strategy",
            DisplayName = "Generated Strategy",
            Files = [new CoordinatorStrategySourceFile("Strategy.cs", source, ContentHasher.HashUtf8(source))],
            SynthesizerArtifactSha256 = new string('b', 64),
            RiskJudgeArtifactSha256 = new string('c', 64),
            DeliveryState = CoordinatorVersions.StrategyDeliveryState,
            CompilerProfile = CoordinatorVersions.StrategyCompilerProfile,
            RequiresHumanRelease = true,
            RequiresTerminalCompileConsent = true,
            InstallEligible = false
        };
        var routeHash = ContentHasher.HashJson(artifact);
        var roleOutput = new CoordinatorRoleOutput
        {
            SchemaVersion = CoordinatorVersions.ArtifactSchema,
            Role = CoordinatorRole.Synthesizer,
            Summary = "Ambiguous second artifact representation."
        };
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.OK,
            new VibeQuantArtifactResponse(
                runId,
                routeHash,
                CoordinatorRole.Synthesizer,
                roleOutput,
                artifact)));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetArtifactAsync(runId, routeHash);

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("artifact failed");
    }

    [Fact]
    public async Task Artifact_response_rejects_content_that_does_not_match_the_route_hash()
    {
        var runId = Guid.NewGuid();
        var routeHash = new string('a', 64);
        var output = new CoordinatorRoleOutput
        {
            SchemaVersion = CoordinatorVersions.ArtifactSchema,
            Role = CoordinatorRole.Synthesizer,
            Summary = "Different bytes than the requested content hash.",
        };
        using var http = CreateHttp(_ => JsonResponse(
            HttpStatusCode.OK,
            new VibeQuantArtifactResponse(runId, routeHash, CoordinatorRole.Synthesizer, output)));
        var client = new VibeQuantApiClient(http);

        Func<Task> call = async () => await client.GetArtifactAsync(runId, routeHash);

        (await call.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("artifact failed");
    }

    private static HttpResponseMessage JsonResponse<T>(HttpStatusCode status, T value) => new(status)
    {
        Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value, CoordinatorJson.Options))
        {
            Headers = { ContentType = new("application/json") }
        }
    };

    private static HttpClient CreateHttp(Func<HttpRequestMessage, HttpResponseMessage> responder) => new(
        new StubHandler(responder))
    {
        BaseAddress = new Uri("https://platform.example"),
    };

    private static VibeQuantRunSpecification CreateSpecification(Guid runId, string objective) => new(
        VibeQuantApiVersions.RunSpecification,
        runId,
        objective,
        DateTimeOffset.UtcNow,
        [],
        new VibeQuantProviderView("managed", "model-v1", "openai-compatible"),
        new VibeQuantBudgetView(8, 2, 100_000, 25_000, 4_096, 1_000_000, 2_000_000, 900, 120),
        500,
        "pricing-v1",
        CoordinatorVersions.Policy,
        CoordinatorVersions.Workflow,
        CoordinatorVersions.ResearchPromptCatalogSha256,
        new string('c', 64));

    private static VibeQuantRunSpecification CreateStrategySpecification(Guid runId, string objective) =>
        CreateSpecification(runId, objective) with
        {
            Provider = new VibeQuantProviderView("mock", "daxalgo-expert-rehearsal", "mock"),
            PolicyVersion = CoordinatorVersions.StrategyPolicy,
            WorkflowVersion = CoordinatorVersions.StrategyWorkflow,
            PromptCatalogSha256 = CoordinatorVersions.StrategyPromptCatalogSha256,
        };

    private static VibeQuantRunStatusResponse CreateStatus(
        Guid runId,
        CoordinatorRunStatus status,
        string? specSha256 = null,
        bool cancellationRequested = false,
        string? finalArtifactSha256 = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new VibeQuantRunStatusResponse(
            runId,
            status,
            specSha256 ?? new string('a', 64),
            0,
            cancellationRequested,
            0,
            0,
            finalArtifactSha256,
            null,
            now,
            now);
    }

    private sealed class StubHandler(
        Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    private sealed class UnknownLengthContent(int length) : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await using var input = new MemoryStream(new byte[length], writable: false);
            await input.CopyToAsync(stream);
        }

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new MemoryStream(new byte[length], writable: false));

        protected override bool TryComputeLength(out long computedLength)
        {
            computedLength = 0;
            return false;
        }
    }
}
