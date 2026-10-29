using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Hyperion.FreeStrategyWorkflow;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class NativeLlmProviderTests
{
    [Fact]
    public async Task Anthropic_adapter_uses_native_messages_shape_and_header_only_key()
    {
        const string response =
            """{"id":"msg-1","type":"message","role":"assistant","content":[{"type":"text","text":"{}"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":3}}""";
        var handler = new NativeCapturingHandler(response);
        using var http = new HttpClient(handler);
        var provider = new AnthropicMessagesLlmProvider(
            http,
            CoordinatorTestData.Descriptor(
                "anthropic",
                "claude-test",
                LlmProviderProtocols.AnthropicMessages,
                "https://api.anthropic.com/v1"),
            "anthropic-test-key");

        var result = await provider.CompleteAsync(Request());

        result.IsSuccess.Should().BeTrue();
        result.Completion!.Usage.Should().Be(new LlmUsage(12, 3));
        result.Completion.FinishReason.Should().Be("stop");
        handler.RequestUri.Should().Be(new Uri("https://api.anthropic.com/v1/messages"));
        handler.Headers["x-api-key"].Should().Be("anthropic-test-key");
        handler.Headers["anthropic-version"].Should().Be(AnthropicMessagesLlmProvider.AnthropicVersion);
        handler.Authorization.Should().BeNull();
        handler.RequestBody.Should().NotContain("anthropic-test-key");
        using var body = JsonDocument.Parse(handler.RequestBody!);
        body.RootElement.GetProperty("max_tokens").GetInt32().Should().Be(321);
        body.RootElement.GetProperty("system").GetString().Should().Be("System boundary.");
    }

    [Fact]
    public async Task Anthropic_adapter_rejects_truncated_completion()
    {
        const string response =
            """{"id":"msg-1","type":"message","role":"assistant","content":[{"type":"text","text":"{}"}],"stop_reason":"max_tokens","usage":{"input_tokens":12,"output_tokens":321}}""";
        var handler = new NativeCapturingHandler(response);
        using var http = new HttpClient(handler);
        var provider = new AnthropicMessagesLlmProvider(
            http,
            CoordinatorTestData.Descriptor(
                "anthropic",
                "claude-test",
                LlmProviderProtocols.AnthropicMessages,
                "https://api.anthropic.com/v1"),
            "anthropic-test-key");

        var result = await provider.CompleteAsync(Request());

        result.IsSuccess.Should().BeFalse();
        result.Failure!.Kind.Should().Be(LlmFailureKinds.InvalidResponse);
        result.Failure.ResponseBytes.Should().Be(Encoding.UTF8.GetByteCount(response));
    }

    [Fact]
    public async Task Gemini_adapter_uses_native_content_shape_and_header_only_key()
    {
        const string response =
            """{"candidates":[{"content":{"role":"model","parts":[{"text":"{}"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2,"thoughtsTokenCount":7},"responseId":"gemini-1"}""";
        var handler = new NativeCapturingHandler(response);
        using var http = new HttpClient(handler);
        var provider = new GoogleGeminiLlmProvider(
            http,
            CoordinatorTestData.Descriptor(
                "google-gemini",
                "gemini-test",
                LlmProviderProtocols.GoogleGemini,
                "https://generativelanguage.googleapis.com/v1beta"),
            "gemini-test-key");

        var result = await provider.CompleteAsync(Request());

        result.IsSuccess.Should().BeTrue();
        result.Completion!.Usage.Should().Be(new LlmUsage(9, 9));
        result.Completion.FinishReason.Should().Be("stop");
        handler.RequestUri.Should().Be(
            new Uri("https://generativelanguage.googleapis.com/v1beta/models/gemini-test:generateContent"));
        handler.Headers["x-goog-api-key"].Should().Be("gemini-test-key");
        handler.Authorization.Should().BeNull();
        handler.RequestBody.Should().NotContain("gemini-test-key");
        using var body = JsonDocument.Parse(handler.RequestBody!);
        body.RootElement.GetProperty("generationConfig").GetProperty("maxOutputTokens")
            .GetInt32().Should().Be(321);
        body.RootElement.GetProperty("systemInstruction").GetProperty("parts")[0]
            .GetProperty("text").GetString().Should().Be("System boundary.");
    }

    [Fact]
    public async Task Gemini_adapter_rejects_truncated_completion()
    {
        const string response =
            """{"candidates":[{"content":{"role":"model","parts":[{"text":"{}"}]},"finishReason":"MAX_TOKENS"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":321}}""";
        var handler = new NativeCapturingHandler(response);
        using var http = new HttpClient(handler);
        var provider = new GoogleGeminiLlmProvider(
            http,
            CoordinatorTestData.Descriptor(
                "google-gemini",
                "gemini-test",
                LlmProviderProtocols.GoogleGemini,
                "https://generativelanguage.googleapis.com/v1beta"),
            "gemini-test-key");

        var result = await provider.CompleteAsync(Request());

        result.IsSuccess.Should().BeFalse();
        result.Failure!.Kind.Should().Be(LlmFailureKinds.InvalidResponse);
        result.Failure.ResponseBytes.Should().Be(Encoding.UTF8.GetByteCount(response));
    }

    [Theory]
    [InlineData(LlmProviderProtocols.AnthropicMessages)]
    [InlineData(LlmProviderProtocols.GoogleGemini)]
    public async Task Native_adapter_completes_the_five_role_free_workflow(string protocol)
    {
        const string secret = "native-workflow-test-key";
        using var workspace = new TestWorkspace();
        var endpoint = protocol == LlmProviderProtocols.AnthropicMessages
            ? "https://api.anthropic.com/v1"
            : "https://generativelanguage.googleapis.com/v1beta";
        var descriptor = new LlmProviderDescriptor(
            protocol == LlmProviderProtocols.AnthropicMessages ? "anthropic" : "google-gemini",
            "native-test-model",
            protocol,
            endpoint,
            1m,
            1m,
            "DAXALGO_LLM_NATIVE_TEST_KEY");
        var handler = new NativeWorkflowHandler(protocol, secret);
        using var http = new HttpClient(handler);
        ILlmProvider provider = protocol == LlmProviderProtocols.AnthropicMessages
            ? new AnthropicMessagesLlmProvider(http, descriptor, secret)
            : new GoogleGeminiLlmProvider(http, descriptor, secret);
        var runner = new FreeStrategyWorkflowWorkspace(
            workspace.PathFor("native-workflow"),
            provider).Runner;
        var draft = await runner.CreateAsync(new FreeStrategyWorkflowRequest
        {
            Objective = "Create one deterministic inert example strategy.",
            Owner = "native-provider-test",
            Budget = FreeStrategyWorkflowDefaults.CreateBudget(),
        });

        var result = await runner.StartAsync(
            draft.Snapshot.Spec.RunId,
            "native-provider-test",
            draft.SpecificationSha256);
        var gauntlet = await runner.InspectGauntletAsync(result.Snapshot.Spec.RunId);

        result.Snapshot.Status.Should().Be(CoordinatorRunStatus.AwaitingReleaseApproval);
        handler.RequestCount.Should().Be(5);
        handler.RequestBodies.Should().OnlyContain(body => !body.Contains(secret, StringComparison.Ordinal));
        gauntlet.ProcessIntegrityPassed.Should().BeTrue();
    }

    [Theory]
    [InlineData(LlmProviderProtocols.AnthropicMessages)]
    [InlineData(LlmProviderProtocols.GoogleGemini)]
    public async Task Native_adapter_rejects_a_success_payload_that_echoes_its_key(string protocol)
    {
        const string secret = "native-echo-test-key";
        var split = secret.Length / 2;
        var response = protocol == LlmProviderProtocols.AnthropicMessages
            ? JsonSerializer.Serialize(new
            {
                id = "msg-echo",
                type = "message",
                role = "assistant",
                content = new[]
                {
                    new { type = "text", text = secret[..split] },
                    new { type = "text", text = secret[split..] },
                },
                stop_reason = "end_turn",
                usage = new { input_tokens = 2, output_tokens = 1 },
            })
            : JsonSerializer.Serialize(new
            {
                candidates = new[]
                {
                    new
                    {
                        content = new
                        {
                            role = "model",
                            parts = new[]
                            {
                                new { text = secret[..split] },
                                new { text = secret[split..] },
                            },
                        },
                        finishReason = "STOP",
                    },
                },
                usageMetadata = new { promptTokenCount = 2, candidatesTokenCount = 1 },
                responseId = "gemini-echo",
            });
        var handler = new NativeCapturingHandler(response);
        using var http = new HttpClient(handler);
        var descriptor = CoordinatorTestData.Descriptor(
            protocol == LlmProviderProtocols.AnthropicMessages ? "anthropic" : "google-gemini",
            "native-test",
            protocol,
            protocol == LlmProviderProtocols.AnthropicMessages
                ? "https://api.anthropic.com/v1"
                : "https://generativelanguage.googleapis.com/v1beta");
        ILlmProvider provider = protocol == LlmProviderProtocols.AnthropicMessages
            ? new AnthropicMessagesLlmProvider(http, descriptor, secret)
            : new GoogleGeminiLlmProvider(http, descriptor, secret);

        var result = await provider.CompleteAsync(Request());

        result.IsSuccess.Should().BeFalse();
        result.Failure!.Kind.Should().Be(LlmFailureKinds.InvalidResponse);
        result.Failure.SafeMessage.Should().NotContain(secret);
    }

    private static LlmRequest Request() => new(
        "native-provider-request",
        CoordinatorRole.Planner,
        "System boundary.",
        [new LlmMessage("user", "Analyze supplied evidence.")],
        MaxOutputTokens: 321,
        MaxResponseBytes: 16_384,
        Temperature: 0m);

    private sealed class NativeCapturingHandler(string responseBody) : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }

        public string? Authorization { get; private set; }

        public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string? RequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            Authorization = request.Headers.Authorization?.ToString();
            foreach (var header in request.Headers)
            {
                Headers[header.Key] = string.Join(",", header.Value);
            }
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class NativeWorkflowHandler(string protocol, string expectedSecret) : HttpMessageHandler
    {
        private readonly DeterministicMockLlmProvider _mock = new();

        public int RequestCount { get; private set; }

        public List<string> RequestBodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var expectedHeader = protocol == LlmProviderProtocols.AnthropicMessages
                ? "x-api-key"
                : "x-goog-api-key";
            request.Headers.GetValues(expectedHeader).Single().Should().Be(expectedSecret);
            var bodyText = await request.Content!.ReadAsStringAsync(cancellationToken);
            RequestBodies.Add(bodyText);
            RequestCount++;
            using var body = JsonDocument.Parse(bodyText);
            var systemPrompt = protocol == LlmProviderProtocols.AnthropicMessages
                ? body.RootElement.GetProperty("system").GetString()!
                : body.RootElement.GetProperty("systemInstruction").GetProperty("parts")[0]
                    .GetProperty("text").GetString()!;
            var conversation = protocol == LlmProviderProtocols.AnthropicMessages
                ? body.RootElement.GetProperty("messages")
                : body.RootElement.GetProperty("contents");
            var lastMessage = conversation[conversation.GetArrayLength() - 1];
            var userPrompt = protocol == LlmProviderProtocols.AnthropicMessages
                ? lastMessage.GetProperty("content").GetString()!
                : lastMessage.GetProperty("parts")[0]
                    .GetProperty("text").GetString()!;
            var role = Enum.GetValues<CoordinatorRole>().Single(candidate =>
                userPrompt.Contains($"CURRENT ROLE: {candidate}", StringComparison.Ordinal));
            var completion = await _mock.CompleteAsync(new LlmRequest(
                $"native-workflow-{RequestCount}",
                role,
                systemPrompt,
                [new LlmMessage("user", userPrompt)],
                8_000,
                1_000_000), cancellationToken);
            completion.IsSuccess.Should().BeTrue();

            var responseBody = protocol == LlmProviderProtocols.AnthropicMessages
                ? JsonSerializer.Serialize(new
                {
                    id = $"anthropic-{RequestCount}",
                    type = "message",
                    role = "assistant",
                    content = new[] { new { type = "text", text = completion.Completion!.Text } },
                    stop_reason = "end_turn",
                    usage = new { input_tokens = 10, output_tokens = 5 },
                })
                : JsonSerializer.Serialize(new
                {
                    candidates = new[]
                    {
                        new
                        {
                            content = new
                            {
                                role = "model",
                                parts = new[] { new { text = completion.Completion!.Text } },
                            },
                            finishReason = "STOP",
                        },
                    },
                    usageMetadata = new { promptTokenCount = 10, candidatesTokenCount = 5 },
                    responseId = $"gemini-{RequestCount}",
                });
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json"),
            };
        }
    }
}
