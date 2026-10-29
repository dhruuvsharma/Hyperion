using System.Net;
using System.Text;
using System.Text.Json;
using DaxAlgo.Coordinator.Cli;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Models;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class CliAndDependencyBoundaryTests
{
    [Fact]
    public async Task Config_loader_rejects_an_oversized_file_before_deserialization()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("oversized-config.json");
        await using (var stream = new FileStream(configPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.SetLength(CoordinatorCliConfigLoader.MaxConfigBytes + 1L);
        }

        Func<Task> load = async () =>
            await CoordinatorCliConfigLoader.LoadAsync(configPath, CancellationToken.None);

        (await load.Should().ThrowAsync<InvalidDataException>()).Which.Message
            .Should().Contain("byte input limit");
    }

    [Fact]
    public void Client_config_rejects_remote_http_and_development_headers_off_loopback()
    {
        var insecureBearer = BearerConfig("http://platform.example");
        var remoteDevelopment = DevelopmentConfig("https://platform.example");

        Action validateBearer = () => CoordinatorCliConfigLoader.Validate(insecureBearer);
        Action validateDevelopment = () => CoordinatorCliConfigLoader.Validate(remoteDevelopment);

        validateBearer.Should().Throw<InvalidDataException>().WithMessage("*HTTPS*");
        validateDevelopment.Should().Throw<InvalidDataException>().WithMessage("*loopback*");
    }

    [Fact]
    public void Bearer_config_requires_a_dedicated_platform_token_variable()
    {
        var config = BearerConfig("https://platform.example") with
        {
            Authentication = new CoordinatorClientAuthenticationConfig
            {
                Mode = "bearer",
                AccessTokenEnvironmentVariable = "OPENAI_API_KEY",
                DevelopmentSubject = null,
                DevelopmentEmail = null,
            }
        };

        Action validate = () => CoordinatorCliConfigLoader.Validate(config);

        validate.Should().Throw<InvalidDataException>()
            .WithMessage("*DAXALGO_PLATFORM_*");
    }

    [Fact]
    public async Task Runtime_applies_only_the_configured_platform_authentication_headers()
    {
        using var workspace = new TestWorkspace();
        var developmentPath = workspace.PathFor("development.json");
        await File.WriteAllTextAsync(
            developmentPath,
            JsonSerializer.Serialize(DevelopmentConfig("http://127.0.0.1:5080"), CoordinatorJson.Options));
        using var development = await CoordinatorRuntime.CreateAsync(developmentPath, default);
        development.HttpClient.DefaultRequestHeaders.GetValues("X-Dev-Subject")
            .Should().ContainSingle("cli-tester");
        development.HttpClient.DefaultRequestHeaders.Authorization.Should().BeNull();

        var variable = $"DAXALGO_PLATFORM_TEST_{Guid.NewGuid():N}";
        var bearerPath = workspace.PathFor("bearer.json");
        var bearerConfig = BearerConfig("https://platform.example") with
        {
            Authentication = new CoordinatorClientAuthenticationConfig
            {
                Mode = "bearer",
                AccessTokenEnvironmentVariable = variable,
                DevelopmentSubject = null,
                DevelopmentEmail = null,
            }
        };
        await File.WriteAllTextAsync(
            bearerPath,
            JsonSerializer.Serialize(bearerConfig, CoordinatorJson.Options));
        Environment.SetEnvironmentVariable(variable, " test-platform-token ");
        try
        {
            using var bearer = await CoordinatorRuntime.CreateAsync(bearerPath, default);
            bearer.HttpClient.DefaultRequestHeaders.Authorization!.Scheme.Should().Be("Bearer");
            bearer.HttpClient.DefaultRequestHeaders.Authorization.Parameter.Should().Be("test-platform-token");
            bearer.HttpClient.DefaultRequestHeaders.Contains("X-Dev-Subject").Should().BeFalse();
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [Fact]
    public async Task Init_creates_a_server_client_config_without_provider_or_credit_authority()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("coordinator-client.json");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            [
                "init",
                "--config", configPath,
                "--server", "http://127.0.0.1:5080",
                "--auth", "development",
                "--subject", "cli-tester"
            ],
            CancellationToken.None);

        exitCode.Should().Be(0, error.ToString());
        var config = await CoordinatorCliConfigLoader.LoadAsync(configPath, CancellationToken.None);
        config.ServerBaseUrl.Should().Be("http://127.0.0.1:5080");
        config.Authentication.DevelopmentSubject.Should().Be("cli-tester");
        var raw = await File.ReadAllTextAsync(configPath);
        var normalized = raw.ToLowerInvariant();
        normalized.Should().NotContain("apikey");
        normalized.Should().NotContain("providerid");
        normalized.Should().NotContain("workspacepath");
        normalized.Should().NotContain("maxcostusd");
        File.Exists(workspace.PathFor("coordinator-examples", "dataset.jsonl")).Should().BeTrue();
        File.Exists(workspace.PathFor("coordinator-examples", "expert-dataset.jsonl")).Should().BeTrue();
    }

    [Fact]
    public async Task Expert_dataset_commands_validate_and_report_the_init_fixture()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("coordinator-client.json");
        using var initOutput = new StringWriter();
        using var initError = new StringWriter();
        var initCode = await new CliApplication(initOutput, initError).RunAsync(
            ["init", "--config", configPath, "--server", "http://127.0.0.1:5080"],
            CancellationToken.None);
        initCode.Should().Be(0, initError.ToString());
        var datasetPath = workspace.PathFor("coordinator-examples", "expert-dataset.jsonl");

        using var validateOutput = new StringWriter();
        using var validateError = new StringWriter();
        var validateCode = await new CliApplication(validateOutput, validateError).RunAsync(
            ["expert-dataset", "validate", "--input", datasetPath],
            CancellationToken.None);
        validateCode.Should().Be(0, validateError.ToString());
        validateOutput.ToString().Should().Contain("Examples: 1").And.Contain("issues: 0");

        using var coverageOutput = new StringWriter();
        using var coverageError = new StringWriter();
        var coverageCode = await new CliApplication(coverageOutput, coverageError).RunAsync(
            ["expert-dataset", "coverage", "--input", datasetPath],
            CancellationToken.None);
        coverageCode.Should().Be(0, coverageError.ToString());
        coverageOutput.ToString().Should().Contain("QuantitativeReasoning/QuantitativeMath");
    }

    [Fact]
    public async Task Client_rejects_an_oversized_brief_before_sending_a_server_request()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("coordinator-client.json");
        var briefPath = workspace.PathFor("brief.md");
        await File.WriteAllTextAsync(
            configPath,
            JsonSerializer.Serialize(DevelopmentConfig("http://127.0.0.1:9"), CoordinatorJson.Options));
        await File.WriteAllTextAsync(
            briefPath,
            new string('x', CoordinatorValidation.MaxObjectiveCharacters + 1));
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            ["create", "--config", configPath, "--brief", briefPath],
            CancellationToken.None);

        exitCode.Should().Be(1);
        error.ToString().Should().Contain("character input limit");
        error.ToString().ToLowerInvariant().Should().NotContain("connection");
    }

    [Fact]
    public async Task Client_rejects_an_unknown_run_purpose_before_sending_a_server_request()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("coordinator-client.json");
        var briefPath = workspace.PathFor("brief.md");
        await File.WriteAllTextAsync(
            configPath,
            JsonSerializer.Serialize(DevelopmentConfig("http://127.0.0.1:9"), CoordinatorJson.Options));
        await File.WriteAllTextAsync(briefPath, "Bounded strategy brief.");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            ["create", "--config", configPath, "--brief", briefPath, "--purpose", "unknown"],
            CancellationToken.None);

        exitCode.Should().Be(1);
        error.ToString().Should().Contain("--purpose must be research or strategy");
        error.ToString().ToLowerInvariant().Should().NotContain("connection");
    }

    [Fact]
    public async Task Help_separates_hosted_jobs_from_the_local_free_workflow()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync([], CancellationToken.None);

        exitCode.Should().Be(0);
        output.ToString().Should().Contain("hosted Hyperion operator and local free-workflow CLI");
        output.ToString().Should().Contain("credits --config");
        output.ToString().Should().Contain("--purpose research|strategy")
            .And.Contain("exact signed hosted capability")
            .And.Contain("explicit compile consent");
        output.ToString().Should().Contain("expert-dataset export-sft")
            .And.Contain("--receipt-set FILE")
            .And.Contain("--receipt-public-key-spki-sha256 SHA256")
            .And.Contain("--teacher-lineage-admission FILE")
            .And.Contain("--teacher-lineage-public-key-spki-sha256 SHA256");
        output.ToString().Should().NotContain("resume --config");
        output.ToString().Should().NotContain("--actor");
        output.ToString().ToLowerInvariant().Should().NotContain("provider key");
        output.ToString().Should().Contain("workflow --help")
            .And.Contain("separate config/workspace")
            .And.Contain("consumes no hosted credits");
    }

    [Fact]
    public async Task Workflow_init_writes_a_separate_config_without_a_provider_secret()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("free-workflow.json");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            [
                "workflow", "init",
                "--config", configPath,
                "--provider", "ollama",
                "--model", "qwen-code",
                "--endpoint", "http://127.0.0.1:11434/v1"
            ],
            CancellationToken.None);

        exitCode.Should().Be(0, error.ToString());
        var config = await FreeStrategyWorkflowCliConfigLoader.LoadAsync(
            configPath,
            CancellationToken.None);
        config.SchemaVersion.Should().Be(FreeStrategyWorkflowCliConfig.CurrentSchemaVersion);
        config.Provider.ProviderId.Should().Be("ollama");
        config.Provider.CredentialEnvironmentVariable.Should().BeNull();
        var raw = await File.ReadAllTextAsync(configPath);
        raw.ToLowerInvariant().Should().NotContain("apikey").And.NotContain("secret");
        raw.Should().NotContain(CoordinatorCliConfig.CurrentSchemaVersion);
    }

    [Fact]
    public async Task Workflow_remote_config_requires_explicit_data_egress_consent()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("remote-workflow.json");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            [
                "workflow", "init",
                "--config", configPath,
                "--profile", "custom-openai-compatible",
                "--provider", "remote",
                "--model", "remote-model",
                "--endpoint", "https://provider.example/v1",
                "--input-price", "1.25",
                "--output-price", "3.5",
                "--allow-custom-provider"
            ],
            CancellationToken.None);

        exitCode.Should().Be(1);
        error.ToString().Should().Contain("allowRemoteProviderDataEgress");
        File.Exists(configPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("openai", "openai-compatible", "https://api.openai.com/v1", "DAXALGO_LLM_OPENAI_API_KEY")]
    [InlineData("anthropic", "anthropic-messages/v1", "https://api.anthropic.com/v1", "DAXALGO_LLM_ANTHROPIC_API_KEY")]
    [InlineData("gemini", "google-gemini-generate-content/v1", "https://generativelanguage.googleapis.com/v1beta", "DAXALGO_LLM_GEMINI_API_KEY")]
    public async Task Workflow_builtin_profiles_pin_protocol_origin_and_secret_slot(
        string profile,
        string protocol,
        string endpoint,
        string credentialVariable)
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor($"{profile}.json");

        var init = await RunCliAsync([
            "workflow", "init",
            "--config", configPath,
            "--profile", profile,
            "--model", "provider-model",
            "--input-price", "1",
            "--output-price", "2",
            "--allow-provider-egress"
        ]);

        init.ExitCode.Should().Be(0, init.Error);
        var config = await FreeStrategyWorkflowCliConfigLoader.LoadAsync(
            configPath,
            CancellationToken.None);
        config.Provider.ProfileId.Should().Be(profile);
        config.Provider.Protocol.Should().Be(protocol);
        config.Provider.Endpoint.Should().Be(endpoint);
        config.Provider.CredentialEnvironmentVariable.Should().Be(credentialVariable);
        (await File.ReadAllTextAsync(configPath)).Should().NotContain("provider-model-secret");
    }

    [Fact]
    public async Task Workflow_openai_chat_profile_rejects_o_series_models()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("openai-o3.json");

        var init = await RunCliAsync([
            "workflow", "init",
            "--config", configPath,
            "--profile", "openai",
            "--model", "o3",
            "--input-price", "1",
            "--output-price", "2",
            "--allow-provider-egress"
        ]);

        init.ExitCode.Should().Be(1);
        init.Error.Should().Contain("not compatible with o-series models");
        File.Exists(configPath).Should().BeFalse();
    }

    [Fact]
    public async Task Workflow_custom_profile_binds_a_distinct_secret_slot_to_the_exact_origin()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("custom.json");
        var init = await RunCliAsync([
            "workflow", "init",
            "--config", configPath,
            "--profile", "custom-openai-compatible",
            "--provider", "custom-provider",
            "--model", "custom-model",
            "--endpoint", "https://models.example/v1",
            "--input-price", "1",
            "--output-price", "2",
            "--allow-provider-egress",
            "--allow-custom-provider"
        ]);

        init.ExitCode.Should().Be(0, init.Error);
        var config = await FreeStrategyWorkflowCliConfigLoader.LoadAsync(
            configPath,
            CancellationToken.None);
        var originalVariable = config.Provider.CredentialEnvironmentVariable;
        originalVariable.Should().StartWith("DAXALGO_LLM_CUSTOM_");
        originalVariable.Should().HaveLength("DAXALGO_LLM_CUSTOM_".Length + 64);
        var redirected = config with
        {
            Provider = config.Provider with { Endpoint = "https://attacker.example/v1" }
        };

        Action validateRedirect = () => FreeStrategyWorkflowCliConfigLoader.Validate(redirected);

        validateRedirect.Should().Throw<InvalidDataException>()
            .WithMessage("*origin-bound*");
    }

    [Fact]
    public async Task Workflow_cli_completes_a_fake_remote_provider_lifecycle_without_persisting_its_key()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("provider-workflow.json");
        var statePath = workspace.PathFor("provider-state");
        var briefPath = workspace.PathFor("provider-brief.md");
        await File.WriteAllTextAsync(briefPath, "Create a bounded inert provider-backed strategy.");
        var init = await RunCliAsync([
            "workflow", "init",
            "--config", configPath,
            "--profile", "custom-openai-compatible",
            "--provider", "fake-provider",
            "--model", "fake-model",
            "--endpoint", "https://workflow-provider.example/v1",
            "--input-price", "1",
            "--output-price", "2",
            "--allow-provider-egress",
            "--allow-custom-provider"
        ]);
        init.ExitCode.Should().Be(0, init.Error);
        var config = await FreeStrategyWorkflowCliConfigLoader.LoadAsync(
            configPath,
            CancellationToken.None);
        var variable = config.Provider.CredentialEnvironmentVariable!;
        const string secret = "provider-lifecycle-test-key";
        Environment.SetEnvironmentVariable(variable, secret);
        try
        {
            var create = await RunCliAsync([
                "workflow", "create",
                "--config", configPath,
                "--workspace", statePath,
                "--brief", briefPath,
                "--owner", "provider-user"
            ]);
            create.ExitCode.Should().Be(0, create.Error);
            using var created = JsonDocument.Parse(create.Output);
            var runId = created.RootElement.GetProperty("runId").GetGuid();
            var specification = created.RootElement.GetProperty("specificationSha256").GetString()!;
            var handler = new WorkflowOpenAiHandler(secret);
            using var output = new StringWriter();
            var cli = new FreeStrategyWorkflowCli(output, () => handler);

            var exitCode = await cli.RunAsync(
                CliArguments.Parse([
                    "workflow", "start",
                    "--config", configPath,
                    "--workspace", statePath,
                    "--run", runId.ToString(),
                    "--spec", specification,
                    "--actor", "provider-user"
                ]),
                CancellationToken.None);

            exitCode.Should().Be(0);
            handler.RequestCount.Should().Be(5);
            handler.RequestBodies.Should().OnlyContain(body => !body.Contains(secret, StringComparison.Ordinal));
            output.ToString().Should().NotContain(secret);
            using var started = JsonDocument.Parse(output.ToString());
            started.RootElement.GetProperty("status").GetString().Should().Be("AwaitingReleaseApproval");
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var file in Directory.EnumerateFiles(statePath, "*", SearchOption.AllDirectories)
                         .Append(configPath))
            {
                Encoding.UTF8.GetString(await File.ReadAllBytesAsync(file)).Should().NotContain(secret);
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [Fact]
    public async Task Workflow_cli_runs_the_complete_mock_approval_lifecycle()
    {
        using var workspace = new TestWorkspace();
        var configPath = workspace.PathFor("mock-workflow.json");
        var statePath = workspace.PathFor("workflow-state");
        var briefPath = workspace.PathFor("brief.md");
        await File.WriteAllTextAsync(briefPath, "Create a deterministic inert example strategy.");

        var init = await RunCliAsync([
            "workflow", "init",
            "--config", configPath,
            "--protocol", "mock"
        ]);
        init.ExitCode.Should().Be(0, init.Error);

        var create = await RunCliAsync([
            "workflow", "create",
            "--config", configPath,
            "--workspace", statePath,
            "--brief", briefPath,
            "--owner", "cli-user"
        ]);
        create.ExitCode.Should().Be(0, create.Error);
        using var created = JsonDocument.Parse(create.Output);
        var runId = created.RootElement.GetProperty("runId").GetGuid();
        var spec = created.RootElement.GetProperty("specificationSha256").GetString()!;

        var start = await RunCliAsync([
            "workflow", "start",
            "--config", configPath,
            "--workspace", statePath,
            "--run", runId.ToString(),
            "--spec", spec,
            "--actor", "cli-user"
        ]);
        start.ExitCode.Should().Be(0, start.Error);
        using var started = JsonDocument.Parse(start.Output);
        started.RootElement.GetProperty("status").GetString().Should().Be("AwaitingReleaseApproval");
        var artifact = started.RootElement.GetProperty("finalArtifactSha256").GetString()!;
        started.RootElement.GetProperty("installEligible").GetBoolean().Should().BeFalse();

        var gauntlet = await RunCliAsync([
            "workflow", "gauntlet",
            "--config", configPath,
            "--workspace", statePath,
            "--run", runId.ToString()
        ]);
        gauntlet.ExitCode.Should().Be(0, gauntlet.Error);
        using var inspected = JsonDocument.Parse(gauntlet.Output);
        inspected.RootElement.GetProperty("processIntegrityPassed").GetBoolean().Should().BeTrue();
        inspected.RootElement.GetProperty("semanticCorrectnessGuaranteed").GetBoolean().Should().BeFalse();
        inspected.RootElement.GetProperty("compilationVerification").GetString()
            .Should().Be("not-run-by-free-workflow");

        var show = await RunCliAsync([
            "workflow", "show",
            "--config", configPath,
            "--workspace", statePath,
            "--run", runId.ToString()
        ]);
        show.ExitCode.Should().Be(0, show.Error);
        using var shown = JsonDocument.Parse(show.Output);
        shown.RootElement.GetProperty("schemaVersion").GetString()
            .Should().Be(CoordinatorVersions.StrategyArtifactSchema);
        shown.RootElement.GetProperty("requiresTerminalCompileConsent").GetBoolean().Should().BeTrue();

        var release = await RunCliAsync([
            "workflow", "release",
            "--config", configPath,
            "--workspace", statePath,
            "--run", runId.ToString(),
            "--artifact", artifact,
            "--actor", "cli-user"
        ]);
        release.ExitCode.Should().Be(0, release.Error);
        using var released = JsonDocument.Parse(release.Output);
        released.RootElement.GetProperty("status").GetString().Should().Be("Completed");

        var repairRequestPath = workspace.PathFor("repair-request.md");
        var diagnosticsPath = workspace.PathFor("compiler-diagnostics.txt");
        await File.WriteAllTextAsync(repairRequestPath, "Repair the exact compiler error only.");
        await File.WriteAllTextAsync(diagnosticsPath, "CS0103: Unknown symbol.");
        var revise = await RunCliAsync([
            "workflow", "revise",
            "--config", configPath,
            "--workspace", statePath,
            "--run", runId.ToString(),
            "--request", repairRequestPath,
            "--diagnostics", diagnosticsPath,
            "--owner", "cli-user"
        ]);
        revise.ExitCode.Should().Be(0, revise.Error);
        using var revised = JsonDocument.Parse(revise.Output);
        revised.RootElement.GetProperty("status").GetString().Should().Be("AwaitingStartApproval");
        revised.RootElement.GetProperty("runId").GetGuid().Should().NotBe(runId);
    }

    [Fact]
    public async Task Workflow_help_states_the_local_cost_and_authority_boundaries()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            ["workflow", "--help"],
            CancellationToken.None);

        exitCode.Should().Be(0, error.ToString());
        output.ToString().Should().Contain("free local/BYOK")
            .And.Contain("consumes no hosted Hyperion credits")
            .And.Contain("Third-party provider charges remain external")
            .And.Contain("Terminal compile consent")
            .And.Contain("does not compile, test, backtest, or guarantee semantic correctness")
            .And.Contain("at most two repair rounds");
    }

    [Fact]
    public void Coordinator_and_cli_assembly_references_exclude_host_execution_projects()
    {
        var forbidden = new HashSet<string>(StringComparer.Ordinal)
        {
            "TradingTerminal.App",
            "TradingTerminal.Core",
            "TradingTerminal.Infrastructure",
            "DaxAlgo.Codegen"
        };
        var references = new[]
            {
                typeof(ResearchCoordinator).Assembly,
                typeof(CliApplication).Assembly
            }
            .SelectMany(assembly => assembly.GetReferencedAssemblies())
            .Select(reference => reference.Name)
            .Where(name => name is not null)
            .Cast<string>()
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        references.Should().NotContain(name => forbidden.Contains(name));
    }

    [Fact]
    public void Hosted_api_client_does_not_reference_the_execution_engine_or_sqlite()
    {
        var references = typeof(VibeQuantApiClient).Assembly
            .GetReferencedAssemblies()
            .Select(reference => reference.Name)
            .Where(name => name is not null)
            .Cast<string>()
            .ToArray();

        references.Should().NotContain("TradingTerminal.Ai.Coordinator");
        references.Should().NotContain("Microsoft.Data.Sqlite");
    }

    private static CoordinatorCliConfig DevelopmentConfig(string serverBaseUrl) => new()
    {
        ServerBaseUrl = serverBaseUrl,
        Authentication = new CoordinatorClientAuthenticationConfig
        {
            Mode = "development",
            DevelopmentSubject = "cli-tester",
            DevelopmentEmail = "cli-tester@development.invalid",
            AccessTokenEnvironmentVariable = null,
        }
    };

    private static CoordinatorCliConfig BearerConfig(string serverBaseUrl) => new()
    {
        ServerBaseUrl = serverBaseUrl,
        Authentication = new CoordinatorClientAuthenticationConfig
        {
            Mode = "bearer",
            AccessTokenEnvironmentVariable = "DAXALGO_PLATFORM_ACCESS_TOKEN",
            DevelopmentSubject = null,
            DevelopmentEmail = null,
        }
    };

    private static async Task<(int ExitCode, string Output, string Error)> RunCliAsync(string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exitCode = await new CliApplication(output, error).RunAsync(args, CancellationToken.None);
        return (exitCode, output.ToString(), error.ToString());
    }

    private sealed class WorkflowOpenAiHandler(string expectedSecret) : HttpMessageHandler
    {
        private readonly DeterministicMockLlmProvider _mock = new();

        public int RequestCount { get; private set; }

        public List<string> RequestBodies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            request.Headers.Authorization?.ToString().Should().Be($"Bearer {expectedSecret}");
            var bodyText = await request.Content!.ReadAsStringAsync(cancellationToken);
            RequestBodies.Add(bodyText);
            RequestCount++;
            using var body = JsonDocument.Parse(bodyText);
            var messages = body.RootElement.GetProperty("messages");
            var systemPrompt = messages[0].GetProperty("content").GetString()!;
            var userPrompt = messages[messages.GetArrayLength() - 1].GetProperty("content").GetString()!;
            var role = Enum.GetValues<CoordinatorRole>().Single(candidate =>
                userPrompt.Contains($"CURRENT ROLE: {candidate}", StringComparison.Ordinal));
            var completion = await _mock.CompleteAsync(new LlmRequest(
                $"provider-{RequestCount}",
                role,
                systemPrompt,
                [new LlmMessage("user", userPrompt)],
                body.RootElement.GetProperty("max_tokens").GetInt32(),
                1_000_000));
            completion.IsSuccess.Should().BeTrue();
            var response = JsonSerializer.Serialize(new
            {
                id = $"provider-response-{RequestCount}",
                choices = new[]
                {
                    new
                    {
                        message = new { role = "assistant", content = completion.Completion!.Text },
                        finish_reason = "stop"
                    }
                },
                usage = new { prompt_tokens = 10, completion_tokens = 5 }
            });
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            };
        }
    }
}
