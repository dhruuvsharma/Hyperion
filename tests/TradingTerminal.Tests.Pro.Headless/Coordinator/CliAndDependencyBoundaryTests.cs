using System.Text.Json;
using DaxAlgo.Coordinator.Cli;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Client;
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
    public async Task Help_describes_hosted_jobs_and_removes_local_provider_commands()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync([], CancellationToken.None);

        exitCode.Should().Be(0);
        output.ToString().Should().Contain("hosted Hyperion coordinator");
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
}
