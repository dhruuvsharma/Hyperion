using System.Text.Json;
using System.Text.Json.Nodes;
using DaxAlgo.Coordinator.Cli;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class ExpertModelDatasetDraftAuthoringTests
{
    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Cli_compiles_all_domains_into_valid_non_training_drafts()
    {
        using var workspace = new TestWorkspace();
        var manifestPath = await WriteManifestAsync(workspace);
        var outputPath = workspace.PathFor("compiled", "seed-draft.jsonl");
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            [
                "expert-dataset", "compile-draft",
                "--manifest", manifestPath,
                "--output", outputPath
            ],
            CancellationToken.None);

        exitCode.Should().Be(0, error.ToString());
        output.ToString().Should().Contain("Compiled 8").And.Contain("0 are training-eligible");
        var validation = await ExpertModelDatasetTools.ValidateJsonLinesAsync(outputPath);
        validation.IsValid.Should().BeTrue();
        validation.ExampleCount.Should().Be(8);
        validation.TrainingEligibleCount.Should().Be(0);
        var coverage = await ExpertModelDatasetTools.BuildCoverageReportAsync(outputPath);
        foreach (var domain in Enum.GetValues<ExpertDomain>())
        {
            coverage.DomainCounts[domain].Should().Be(1);
        }

        var rows = (await File.ReadAllLinesAsync(outputPath))
            .Select(line => JsonNode.Parse(line)!.AsObject())
            .ToArray();
        rows.Should().OnlyContain(row => row["split"]!.GetValue<string>() == "development");
        rows.Should().OnlyContain(row => row["reviewStatus"]!.GetValue<string>() == "draft");
        rows.Should().OnlyContain(row => !row["useForTraining"]!.GetValue<bool>());
        rows.Should().OnlyContain(row => !row["verification"]!["verified"]!.GetValue<bool>());
        rows.Should().OnlyContain(row => row["verification"]!["verifiedAtUtc"] == null);
        rows.Should().OnlyContain(row => !row["rights"]!["mayTrain"]!.GetValue<bool>());
        rows.Should().OnlyContain(row => !row["rights"]!["mayUploadToProvider"]!.GetValue<bool>());
        rows.Should().OnlyContain(row =>
            row["sources"]!.AsArray().All(source => !source!["rights"]!["mayTrain"]!.GetValue<bool>()));
        rows.Select(row => row["sources"]![0]!["content"]!.GetValue<string>()).Should()
            .OnlyContain(content => content.StartsWith("Project-owned draft evidence", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Compiler_v2_emits_explicit_evaluation_splits_without_authority()
    {
        using var workspace = new TestWorkspace();
        var manifestPath = await WriteManifestAsync(workspace);
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        manifest["schemaVersion"] = ExpertModelDatasetDraftAuthoringTools.V2SchemaVersion;
        var examples = manifest["examples"]!.AsArray();
        for (var index = 0; index < examples.Count; index++)
        {
            examples[index]!["split"] = index % 2 == 0 ? "calibration" : "sealed";
        }
        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString(CoordinatorJson.Options));
        var outputPath = workspace.PathFor("compiled", "evaluation-draft.jsonl");

        var count = await ExpertModelDatasetDraftAuthoringTools.CompileAsync(manifestPath, outputPath);

        count.Should().Be(8);
        var validation = await ExpertModelDatasetTools.LoadAndValidateAsync(
            outputPath,
            CancellationToken.None);
        validation.Report.IsValid.Should().BeTrue();
        validation.Report.TrainingEligibleCount.Should().Be(0);
        validation.Examples.Select(example => example.Split).Should()
            .Equal("calibration", "sealed", "calibration", "sealed", "calibration", "sealed", "calibration", "sealed");
        validation.Examples.Should().OnlyContain(example =>
            example.ReviewStatus == "draft" &&
            !example.UseForTraining &&
            !example.Verification.Verified &&
            example.Rights.MayStore &&
            example.Rights.MayEvaluate &&
            !example.Rights.MayTrain &&
            !example.Rights.MayUploadToProvider &&
            !example.Rights.MayRedistribute &&
            example.Sources.All(source =>
                source.Rights.MayStore &&
                source.Rights.MayEvaluate &&
                !source.Rights.MayTrain &&
                !source.Rights.MayUploadToProvider &&
                !source.Rights.MayRedistribute));
    }

    [Theory]
    [InlineData("missing-v2-split")]
    [InlineData("invalid-v2-split")]
    [InlineData("v1-explicit-split")]
    public async Task Compiler_enforces_versioned_split_contract(string mutation)
    {
        using var workspace = new TestWorkspace();
        var manifestPath = await WriteManifestAsync(workspace);
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        var examples = manifest["examples"]!.AsArray();
        if (mutation == "v1-explicit-split")
        {
            examples[0]!["split"] = "sealed";
        }
        else
        {
            manifest["schemaVersion"] = ExpertModelDatasetDraftAuthoringTools.V2SchemaVersion;
            foreach (var example in examples)
            {
                example!["split"] = "development";
            }
            if (mutation == "missing-v2-split")
            {
                examples[0]!.AsObject().Remove("split");
            }
            else
            {
                examples[0]!["split"] = "holdout";
            }
        }
        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString(CoordinatorJson.Options));

        Func<Task> compile = async () => await ExpertModelDatasetDraftAuthoringTools.CompileAsync(
            manifestPath,
            workspace.PathFor("output.jsonl"));

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("split");
    }

    [Fact]
    public async Task Compiler_rejects_unknown_manifest_fields_without_replacing_output()
    {
        using var workspace = new TestWorkspace();
        var manifestPath = await WriteManifestAsync(workspace);
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        manifest["unexpected"] = true;
        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString(CoordinatorJson.Options));
        var outputPath = workspace.PathFor("existing.jsonl");
        await File.WriteAllTextAsync(outputPath, "existing output");

        Func<Task> compile = async () => await ExpertModelDatasetDraftAuthoringTools.CompileAsync(
            manifestPath,
            outputPath);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("invalid");
        (await File.ReadAllTextAsync(outputPath)).Should().Be("existing output");
    }

    [Fact]
    public async Task Compiler_rejects_source_paths_outside_the_manifest_directory()
    {
        using var workspace = new TestWorkspace();
        var manifestPath = await WriteManifestAsync(workspace);
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        manifest["examples"]![0]!["sources"]![0]!["contentPath"] = "../outside.md";
        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString(CoordinatorJson.Options));

        Func<Task> compile = async () => await ExpertModelDatasetDraftAuthoringTools.CompileAsync(
            manifestPath,
            workspace.PathFor("output.jsonl"));

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("escapes the manifest directory");
    }

    [Fact]
    public async Task Compiler_requires_an_explicit_storage_and_evaluation_only_rights_declaration()
    {
        using var workspace = new TestWorkspace();
        var manifestPath = await WriteManifestAsync(workspace);
        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject();
        manifest["rights"]!["mayTrain"] = true;
        await File.WriteAllTextAsync(manifestPath, manifest.ToJsonString(CoordinatorJson.Options));

        Func<Task> compile = async () => await ExpertModelDatasetDraftAuthoringTools.CompileAsync(
            manifestPath,
            workspace.PathFor("output.jsonl"));

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("explicitly permit only private storage and evaluation");
    }

    private static async Task<string> WriteManifestAsync(TestWorkspace workspace)
    {
        var manifestDirectory = workspace.PathFor("authoring");
        var evidenceDirectory = Path.Combine(manifestDirectory, "evidence");
        Directory.CreateDirectory(evidenceDirectory);
        var domains = Enum.GetValues<ExpertDomain>();
        var taskKinds = new[]
        {
            ExpertTaskKind.GeneralQuestionAnswering,
            ExpertTaskKind.ArchitectureDesign,
            ExpertTaskKind.QuantitativeReasoning,
            ExpertTaskKind.StatisticalReasoning,
            ExpertTaskKind.RiskAnalysis,
            ExpertTaskKind.PortfolioAnalysis,
            ExpertTaskKind.MarketAnalysis,
            ExpertTaskKind.WpfUiDesign
        };
        var examples = new List<ExpertModelDatasetDraftExample>();
        for (var index = 0; index < domains.Length; index++)
        {
            var domain = domains[index];
            var id = $"draft-{domain.ToString().ToLowerInvariant()}";
            var contentPath = Path.Combine("evidence", $"{id}.md");
            await File.WriteAllTextAsync(
                Path.Combine(manifestDirectory, contentPath),
                $"Project-owned draft evidence for {domain}.\n");
            examples.Add(new ExpertModelDatasetDraftExample
            {
                Id = id,
                TaskKind = taskKinds[index],
                Domains = [domain],
                Messages =
                [
                    new LlmMessage("system", "Answer only from the supplied reviewed context."),
                    new LlmMessage("user", $"Explain the bounded fixture for {domain}."),
                    new LlmMessage("assistant", $"This is the draft bounded answer for {domain}.")
                ],
                ContaminationGroup = $"family-{id}",
                KnowledgeClass = index is 1 or 7 ? "retrieval-only" : "candidate-stable",
                Sources =
                [
                    new ExpertModelDatasetDraftSource
                    {
                        Id = $"source-{id}",
                        Title = $"Draft evidence for {domain}",
                        ContentPath = contentPath.Replace('\\', '/'),
                        Provenance = "Project-owned draft-authoring test fixture.",
                        License = "Project-owned test fixture",
                        RetrievedAtUtc = FixtureTime,
                        AvailableAtUtc = FixtureTime,
                        Uri = $"repo://tests/draft/{id}"
                    }
                ],
                Evidence = [$"Draft intake for {id}; no independent review or training approval is recorded."]
            });
        }

        var manifest = new ExpertModelDatasetDraftManifest
        {
            SchemaVersion = ExpertModelDatasetDraftAuthoringTools.SchemaVersion,
            Producer = "draft-fixture-author",
            ProducedAtUtc = FixtureTime,
            Reviewer = "unassigned-independent-reviewer",
            CutoffUtc = FixtureTime,
            Provenance = "Project-owned expert-model draft-authoring test fixture.",
            License = "Project-owned test fixture",
            Rights = new DatasetRights(true, true, false, false, false),
            RightsBasis = "Test-only private storage and evaluation fixture.",
            Examples = examples
        };
        var manifestPath = Path.Combine(manifestDirectory, "seed-draft.json");
        await File.WriteAllTextAsync(
            manifestPath,
            JsonSerializer.Serialize(manifest, CoordinatorJson.Options));
        return manifestPath;
    }
}
