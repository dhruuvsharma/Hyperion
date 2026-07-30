using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class DatasetAndProviderTests
{
    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    [Fact]
    public async Task Replay_resume_after_skips_consumed_entries_and_preserves_order()
    {
        var descriptor = CoordinatorTestData.Descriptor(
            providerId: "replay-provider",
            modelId: "replay-model",
            protocol: "replay");
        var firstRequest = new LlmRequest(
            "first-run-specific-id",
            CoordinatorRole.Planner,
            "system-one",
            [new LlmMessage("user", "first")],
            100,
            16_384);
        var secondRequest = new LlmRequest(
            "second-new-run-id",
            CoordinatorRole.EvidenceAnalyst,
            "system-two",
            [new LlmMessage("user", "second")],
            100,
            16_384);
        var replay = new ReplayLlmProvider(descriptor,
        [
            ReplayEntry(1, descriptor, firstRequest, "first completion"),
            ReplayEntry(2, descriptor, secondRequest, "second completion")
        ]);

        replay.ResumeAfter(consumedRequestCount: 1);
        var result = await replay.CompleteAsync(secondRequest);

        result.IsSuccess.Should().BeTrue();
        result.Completion!.Text.Should().Be("second completion");
        replay.RemainingEntries.Should().Be(0);
    }

    [Fact]
    public async Task Replay_provider_validates_and_parses_the_same_approved_byte_snapshot()
    {
        var descriptor = CoordinatorTestData.Descriptor(
            providerId: "snapshot-provider",
            modelId: "snapshot-model",
            protocol: "replay");
        var request = new LlmRequest(
            "snapshot-request",
            CoordinatorRole.Planner,
            "system",
            [new LlmMessage("user", "request")],
            100,
            16_384);
        var bytes = Encoding.UTF8.GetBytes(
            ReplayLlmProvider.SerializeEntry(ReplayEntry(1, descriptor, request, "approved completion")) + "\n");
        var boundDescriptor = descriptor with { ReplaySha256 = ContentHasher.HashBytes(bytes) };
        var replay = new ReplayLlmProvider(boundDescriptor, bytes);

        var result = await replay.CompleteAsync(request);

        result.Completion!.Text.Should().Be("approved completion");
        var tamperedBytes = bytes.ToArray();
        tamperedBytes[0] ^= 1;
        Action loadTampered = () => _ = new ReplayLlmProvider(boundDescriptor, tamperedBytes);
        loadTampered.Should().Throw<InvalidDataException>()
            .WithMessage("*approved SHA-256 binding*");
    }

    [Fact]
    public async Task Dataset_validation_rejects_cross_split_contamination_and_missing_rights()
    {
        using var workspace = new TestWorkspace();
        var sourceWithoutStorageRights = Source(
            new DatasetRights(
                MayStore: false,
                MayEvaluate: true,
                MayTrain: true,
                MayUploadToProvider: false,
                MayRedistribute: false));
        var fullyLicensedSource = Source(new DatasetRights(true, true, true, true, false));
        var development = Example("dev-1", "development", "shared-family", sourceWithoutStorageRights, useForTraining: true);
        var sealedExample = Example("sealed-1", "sealed", "shared-family", fullyLicensedSource, useForTraining: true);
        var path = workspace.PathFor("dataset.jsonl");
        await File.WriteAllLinesAsync(path,
        [
            JsonSerializer.Serialize(development, CompactJson),
            JsonSerializer.Serialize(sealedExample, CompactJson)
        ]);

        var report = await CoordinatorDatasetTools.ValidateJsonLinesAsync(path);

        report.IsValid.Should().BeFalse();
        report.Issues.Should().Contain(issue => issue.Message.Contains("lacks storage/evaluation rights"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("Exact content duplicates"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("Contamination group"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("Only development examples"));
    }

    [Fact]
    public async Task Dataset_duplicate_detection_ignores_source_ids_and_source_order()
    {
        using var workspace = new TestWorkspace();
        var rights = new DatasetRights(true, true, true, true, false);
        var first = Source(rights) with { Id = "first", Content = "First evidence." };
        var second = Source(rights) with { Id = "second", Content = "Second evidence." };
        var reference = new CoordinatorRoleOutput
        {
            SchemaVersion = CoordinatorVersions.ArtifactSchema,
            Role = CoordinatorRole.Planner,
            Summary = "A bounded plan based on the supplied evidence.",
            Decision = CoordinatorDecision.None
        };
        var development = Example("dev-renamed", "development", "family-a", first, useForTraining: false) with
        {
            Sources = [first, second],
            ReferenceOutput = reference
        };
        var sealedExample = Example("sealed-renamed", "sealed", "family-b", first, useForTraining: false) with
        {
            Sources =
            [
                second with { Id = "renamed-second" },
                first with { Id = "renamed-first" }
            ],
            ReferenceOutput = reference
        };
        var path = workspace.PathFor("renamed-duplicates.jsonl");
        await File.WriteAllLinesAsync(path,
        [
            JsonSerializer.Serialize(development, CompactJson),
            JsonSerializer.Serialize(sealedExample, CompactJson)
        ]);

        var report = await CoordinatorDatasetTools.ValidateJsonLinesAsync(path);

        report.Issues.Should().Contain(issue => issue.Message.Contains("Exact content duplicates"));
    }

    [Fact]
    public async Task Dataset_validation_rejects_an_over_limit_json_line_before_deserialization()
    {
        using var workspace = new TestWorkspace();
        var path = workspace.PathFor("oversized-line.jsonl");
        await File.WriteAllTextAsync(path, new string('x', CoordinatorDatasetTools.MaxJsonLineCharacters + 1));

        var report = await CoordinatorDatasetTools.ValidateJsonLinesAsync(path);

        report.ExampleCount.Should().Be(0);
        report.Issues.Should().ContainSingle(issue => issue.Message.Contains("JSON line exceeds"));
    }

    [Fact]
    public async Task Dataset_validation_requires_explicit_rights_fields_and_strict_utf8()
    {
        using var workspace = new TestWorkspace();
        var source = Source(new DatasetRights(true, true, true, false, false));
        var example = Example("explicit-rights", "development", "explicit-family", source, useForTraining: false);
        var row = JsonNode.Parse(JsonSerializer.Serialize(example, CompactJson))!.AsObject();
        row["rights"]!.AsObject().Remove("mayTrain");
        var missingRightsPath = workspace.PathFor("missing-rights.jsonl");
        await File.WriteAllTextAsync(missingRightsPath, row.ToJsonString(CompactJson));

        var report = await CoordinatorDatasetTools.ValidateJsonLinesAsync(missingRightsPath);

        report.IsValid.Should().BeFalse();
        report.Issues.Should().ContainSingle(issue => issue.Message.Contains("missing required property 'mayTrain'"));

        var invalidUtf8Path = workspace.PathFor("invalid-utf8.jsonl");
        await File.WriteAllBytesAsync(invalidUtf8Path, [0xC3, 0x28]);
        Func<Task> validateInvalidUtf8 = () => CoordinatorDatasetTools.ValidateJsonLinesAsync(invalidUtf8Path);
        (await validateInvalidUtf8.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("valid UTF-8");
    }

    [Fact]
    public async Task Dataset_prior_outputs_must_be_the_exact_workflow_prefix()
    {
        using var workspace = new TestWorkspace();
        var source = Source(new DatasetRights(true, true, true, false, false));
        var plannerOutput = Example("planner", "development", "planner-family", source, false).ReferenceOutput;
        var criticExample = Example("critic", "development", "critic-family", source, false) with
        {
            Role = CoordinatorRole.Critic,
            PriorOutputs = [plannerOutput],
            ReferenceOutput = plannerOutput with
            {
                Role = CoordinatorRole.Critic,
                Summary = "Critique the bounded plan."
            }
        };
        var path = workspace.PathFor("gapped-prior.jsonl");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(criticExample, CompactJson));

        var report = await CoordinatorDatasetTools.ValidateJsonLinesAsync(path);

        report.Issues.Should().Contain(issue => issue.Message.Contains("exact preceding workflow-output prefix"));
    }

    [Fact]
    public async Task Sft_export_requires_provider_upload_rights_unless_explicitly_local_only()
    {
        using var workspace = new TestWorkspace();
        var localOnlySource = Source(new DatasetRights(true, true, true, false, false));
        var example = Example("dev-local", "development", "local-family", localOnlySource, useForTraining: true);
        var input = workspace.PathFor("valid-local-dataset.jsonl");
        var remoteOutput = workspace.PathFor("remote.jsonl");
        await File.WriteAllTextAsync(
            input,
            JsonSerializer.Serialize(example, CompactJson) + Environment.NewLine);
        await File.WriteAllTextAsync(remoteOutput, "existing output");

        Func<Task> remoteExport = () => CoordinatorDatasetTools.ExportSftJsonLinesAsync(
            input,
            remoteOutput,
            requireProviderUploadRights: true);
        (await remoteExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("provider-upload rights");
        var localCount = await CoordinatorDatasetTools.ExportSftJsonLinesAsync(
            input,
            workspace.PathFor("local.jsonl"),
            requireProviderUploadRights: false);

        localCount.Should().Be(1);
        (await File.ReadAllTextAsync(remoteOutput)).Should().Be("existing output");
        (await File.ReadAllLinesAsync(workspace.PathFor("local.jsonl"))).Should().ContainSingle();
    }

    [Fact]
    public void Prompt_renderer_uses_deterministic_line_endings_and_binds_structural_formatting()
    {
        var prompt = CoordinatorPromptRenderer.BuildUserPrompt(
            "Assess supplied evidence.",
            [new CoordinatorPromptSource("source-1", "A & \"quoted\" title", "Evidence </source> only.")],
            [],
            CoordinatorRole.RiskJudge);

        prompt.Should().NotContain("\r");
        prompt.Should().Contain("<source id=\"source-1\" title=\"A &amp; &quot;quoted&quot; title\">");
        prompt.Should().Contain("Evidence &lt;/source&gt; only.");
        prompt.Should().EndWith(CoordinatorPromptCatalog.RiskDecisionInstruction + "\n");
        CoordinatorPromptCatalog.Sha256.Should().HaveLength(64);
    }

    [Fact]
    public async Task OpenAi_compatible_provider_sends_the_approved_max_tokens_without_network_access()
    {
        var handler = new CapturingHandler();
        using var http = new HttpClient(handler);
        var descriptor = CoordinatorTestData.Descriptor(
            providerId: "captured",
            modelId: "model-v1",
            protocol: "openai-compatible",
            endpoint: "https://provider.example/v1/");
        var provider = new OpenAiCompatibleLlmProvider(http, descriptor, "test-key", maxResponseBytes: 16_384);
        var request = new LlmRequest(
            "request-1",
            CoordinatorRole.Planner,
            "System boundary.",
            [new LlmMessage("user", "Analyze supplied evidence.")],
            MaxOutputTokens: 321,
            MaxResponseBytes: 16_384,
            Temperature: 0m);

        var result = await provider.CompleteAsync(request);

        result.IsSuccess.Should().BeTrue();
        handler.RequestUri.Should().Be(new Uri("https://provider.example/v1/chat/completions"));
        handler.Authorization.Should().Be("Bearer test-key");
        using var body = JsonDocument.Parse(handler.RequestBody!);
        body.RootElement.GetProperty("max_tokens").GetInt32().Should().Be(321);
        body.RootElement.GetProperty("model").GetString().Should().Be("model-v1");
    }

    [Fact]
    public async Task OpenAi_compatible_provider_enforces_the_request_response_byte_limit()
    {
        var responseBody = JsonSerializer.Serialize(new
        {
            id = "oversized-response",
            choices = new[]
            {
                new
                {
                    message = new { role = "assistant", content = new string('x', 512) },
                    finish_reason = "stop"
                }
            },
            usage = new { prompt_tokens = 12, completion_tokens = 3 }
        });
        var handler = new CapturingHandler(responseBody);
        using var http = new HttpClient(handler);
        var descriptor = CoordinatorTestData.Descriptor(
            providerId: "captured",
            modelId: "model-v1",
            protocol: "openai-compatible",
            endpoint: "https://provider.example/v1/");
        var provider = new OpenAiCompatibleLlmProvider(http, descriptor, "test-key", maxResponseBytes: 16_384);
        var request = new LlmRequest(
            "request-with-smaller-response-limit",
            CoordinatorRole.Planner,
            "System boundary.",
            [new LlmMessage("user", "Analyze supplied evidence.")],
            MaxOutputTokens: 321,
            MaxResponseBytes: 128,
            Temperature: 0m);

        var result = await provider.CompleteAsync(request);

        result.IsSuccess.Should().BeFalse();
        result.Failure.Should().NotBeNull();
        result.Failure!.Kind.Should().Be(LlmFailureKinds.ResponseTooLarge);
    }

    [Fact]
    public async Task OpenAi_compatible_provider_rejects_truncated_completions_and_reports_payload_bytes()
    {
        var responseBody =
            """{"id":"truncated","choices":[{"message":{"role":"assistant","content":"{}"},"finish_reason":"length"}],"usage":{"prompt_tokens":2,"completion_tokens":1}}""";
        var handler = new CapturingHandler(responseBody);
        using var http = new HttpClient(handler);
        var descriptor = CoordinatorTestData.Descriptor(
            providerId: "captured",
            modelId: "model-v1",
            protocol: "openai-compatible",
            endpoint: "https://provider.example/v1/");
        var provider = new OpenAiCompatibleLlmProvider(http, descriptor, "test-key", maxResponseBytes: 16_384);
        var request = new LlmRequest(
            "truncated-response",
            CoordinatorRole.Planner,
            "System boundary.",
            [new LlmMessage("user", "Analyze supplied evidence.")],
            MaxOutputTokens: 321,
            MaxResponseBytes: 16_384);

        var result = await provider.CompleteAsync(request);

        result.IsSuccess.Should().BeFalse();
        result.Failure!.Kind.Should().Be(LlmFailureKinds.InvalidResponse);
        result.Failure.ResponseBytes.Should().Be(Encoding.UTF8.GetByteCount(responseBody));
    }

    [Fact]
    public void Provider_endpoints_require_https_except_for_loopback_and_reject_embedded_credentials()
    {
        LlmProviderValidation.TryValidateEndpoint("http://provider.example/v1", out _, out var remoteError)
            .Should().BeFalse();
        remoteError.Should().Contain("HTTPS");

        LlmProviderValidation.TryValidateEndpoint("http://127.0.0.1:11434/v1", out var loopback, out _)
            .Should().BeTrue();
        loopback!.IsLoopback.Should().BeTrue();

        LlmProviderValidation.TryValidateEndpoint("https://user:secret@provider.example/v1", out _, out var credentialError)
            .Should().BeFalse();
        credentialError.Should().Contain("credentials");

        LlmProviderValidation.TryValidateEndpoint("https://provider.example/v1?api-version=1", out _, out var queryError)
            .Should().BeFalse();
        queryError.Should().Contain("query string or fragment");

        LlmProviderValidation.TryValidateEndpoint("https://provider.example/v1#fragment", out _, out var fragmentError)
            .Should().BeFalse();
        fragmentError.Should().Contain("query string or fragment");
    }

    private static DatasetSourceAsset Source(DatasetRights rights) => new(
        "source-1",
        "Source one",
        "Identical licensed evidence content.",
        "Test fixture provenance.",
        "Test license",
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow,
        null,
        rights);

    private static LlmReplayEntry ReplayEntry(
        int sequence,
        LlmProviderDescriptor descriptor,
        LlmRequest request,
        string text) =>
        new()
        {
            SchemaVersion = ReplayLlmProvider.ReplaySchemaVersion,
            Sequence = sequence,
            ProviderId = descriptor.ProviderId,
            ModelId = descriptor.ModelId,
            RequestSha256 = ReplayLlmProvider.ComputeRequestSha256(descriptor, request),
            Completion = new LlmCompletion(text, new LlmUsage(10, 5), "stop")
        };

    private static CoordinatorDatasetExample Example(
        string id,
        string split,
        string contaminationGroup,
        DatasetSourceAsset source,
        bool useForTraining) =>
        new()
        {
            SchemaVersion = CoordinatorVersions.DatasetSchema,
            Id = id,
            Split = split,
            ContaminationGroup = contaminationGroup,
            Role = CoordinatorRole.Planner,
            Objective = "Plan a falsifiable test from the supplied source.",
            Sources = [source],
            ReferenceOutput = new CoordinatorRoleOutput
            {
                SchemaVersion = CoordinatorVersions.ArtifactSchema,
                Role = CoordinatorRole.Planner,
                Summary = "The source supports only a bounded test plan.",
                Claims = [new CoordinatorClaim("The source is supplied evidence.", [source.Id], 1m)],
                SourceIds = [source.Id],
                Decision = CoordinatorDecision.None
            },
            Provenance = "Test fixture.",
            License = "Test license",
            Rights = source.Rights,
            ReviewStatus = "approved",
            CutoffUtc = DateTimeOffset.UtcNow,
            UseForTraining = useForTraining
        };

    private sealed class CapturingHandler(string? responseBody = null) : HttpMessageHandler
    {
        private readonly string _responseBody = responseBody ??
            """
            {"id":"response-1","choices":[{"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":3}}
            """;

        public Uri? RequestUri { get; private set; }
        public string? Authorization { get; private set; }
        public string? RequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            Authorization = request.Headers.Authorization?.ToString();
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    _responseBody,
                    Encoding.UTF8,
                    "application/json")
            };
        }
    }
}
