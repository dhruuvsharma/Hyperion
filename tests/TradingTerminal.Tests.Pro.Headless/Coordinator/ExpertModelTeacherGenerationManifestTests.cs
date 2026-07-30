using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DaxAlgo.Coordinator.Cli;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class ExpertModelTeacherGenerationManifestTests
{
    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Cli_compiles_v2_manifest_without_reference_answers_or_authority_escalation()
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var exitCode = await new CliApplication(output, error).RunAsync(
            [
                "expert-dataset", "compile-teacher-manifest",
                "--manifest", fixture.ManifestPath,
                "--capture-plan", fixture.PlanPath,
                "--candidate-catalog", fixture.CatalogPath,
                "--output", fixture.OutputPath,
            ],
            CancellationToken.None);

        exitCode.Should().Be(0, error.ToString());
        output.ToString().Should().Contain("Compiled 2 teacher-generation tasks for 4 requests")
            .And.Contain("No teacher, review, training, release, model, or promotion evidence was created");
        var bytes = await File.ReadAllBytesAsync(fixture.OutputPath);
        bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }).Should().BeFalse();
        var json = Encoding.UTF8.GetString(bytes);
        json.Should().NotContain("\r").And.NotContain(fixture.ReferenceAnswers[0])
            .And.NotContain(fixture.ReferenceAnswers[1]);

        var manifest = JsonNode.Parse(json)!.AsObject();
        manifest["schemaVersion"]!.GetValue<string>().Should()
            .Be(ExpertModelTeacherGenerationManifestTools.OutputSchemaVersion);
        manifest["split"]!.GetValue<string>().Should().Be("development");
        manifest["draftManifestSha256"]!.GetValue<string>().Should()
            .Be(await FileSha256Async(fixture.ManifestPath));
        manifest["candidateCatalogSha256"]!.GetValue<string>().Should()
            .Be(await FileSha256Async(fixture.CatalogPath));
        manifest["teacher"]!["candidateId"]!.GetValue<string>().Should()
            .Be("qwen3-coder-30b-a3b-instruct");
        manifest["tokenizerPreflight"]!["protocol"]!.GetValue<string>().Should()
            .Be(ExpertModelTeacherGenerationManifestTools.TokenizerProtocol);
        manifest["authority"]!["producer"]!.GetValue<string>().Should().Be("draft-fixture-author");
        manifest["authority"]!["reviewer"]!.GetValue<string>().Should()
            .Be("unassigned-independent-reviewer");
        manifest["authority"]!["rights"]!["mayStore"]!.GetValue<bool>().Should().BeTrue();
        manifest["authority"]!["rights"]!["mayEvaluate"]!.GetValue<bool>().Should().BeTrue();
        manifest["authority"]!["rights"]!["mayTrain"]!.GetValue<bool>().Should().BeFalse();
        manifest["authority"]!["rights"]!["mayUploadToProvider"]!.GetValue<bool>().Should().BeFalse();
        manifest["authority"]!["rights"]!["mayRedistribute"]!.GetValue<bool>().Should().BeFalse();

        var tasks = manifest["tasks"]!.AsArray();
        tasks.Should().HaveCount(2);
        tasks[0]!["taskId"]!.GetValue<string>().Should().Be("draft-csharp-001");
        tasks[0]!["taskKind"]!.GetValue<string>().Should().Be("CodeReview");
        tasks[0]!["domains"]![0]!.GetValue<string>().Should().Be("CSharp");
        tasks[0]!["contaminationGroup"]!.GetValue<string>().Should().Be("family-csharp");
        tasks[0]!["knowledgeClass"]!.GetValue<string>().Should().Be("candidate-stable");
        tasks[0]!["cutoffUtc"]!.GetValue<string>().Should().Be("2025-01-15T12:00:00Z");
        tasks[0]!["messages"]!.AsArray().Select(item => item!["role"]!.GetValue<string>())
            .Should().Equal("system", "user");
        tasks[1]!["messages"]!.AsArray().Select(item => item!["role"]!.GetValue<string>())
            .Should().Equal("user", "assistant", "user");
        tasks[0]!["sources"]![0]!["contentPath"]!.GetValue<string>().Should()
            .Be("evidence/source-csharp.md");
        tasks[0]!["sources"]![0]!["contentSha256"]!.GetValue<string>().Should()
            .Be(await FileSha256Async(fixture.SourcePaths[0]));
        tasks[0]!["sources"]![0]!["retrievedAtUtc"]!.GetValue<string>().Should()
            .Be("2025-01-15T12:00:00Z");
        tasks[0]!["sources"]![0]!["availableAtUtc"]!.GetValue<string>().Should()
            .Be("2025-01-15T12:00:00Z");
        tasks[0]!["sources"]![0]!["uri"]!.GetValue<string>().Should()
            .Be("repo://tests/source-csharp");
    }

    [Fact]
    public async Task Compiler_accepts_v2_development_only_draft()
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        manifest["schemaVersion"] = ExpertModelDatasetDraftAuthoringTools.V2SchemaVersion;
        foreach (var example in manifest["examples"]!.AsArray())
        {
            example!["split"] = "development";
        }
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        var result = await CompileAsync(fixture);

        result.TaskCount.Should().Be(2);
        File.Exists(fixture.OutputPath).Should().BeTrue();
    }

    [Theory]
    [InlineData("calibration")]
    [InlineData("sealed")]
    public async Task Compiler_rejects_v2_non_development_rows_before_teacher_capture(string split)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        manifest["schemaVersion"] = ExpertModelDatasetDraftAuthoringTools.V2SchemaVersion;
        foreach (var example in manifest["examples"]!.AsArray())
        {
            example!["split"] = "development";
        }
        manifest["examples"]![0]!["split"] = split;
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        Func<Task> compile = async () => await CompileAsync(fixture);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain($"split '{split}'")
            .And.Contain("teacher generation accepts v2 development examples only");
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("wrong-draft-hash")]
    [InlineData("wrong-catalog-hash")]
    [InlineData("missing-candidate")]
    [InlineData("student-candidate")]
    [InlineData("tampered-catalog-revision")]
    public async Task Compiler_rejects_wrong_bindings_or_non_teacher_candidates(string mutation)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var plan = await ReadObjectAsync(fixture.PlanPath);
        switch (mutation)
        {
            case "wrong-draft-hash":
                plan["draftManifestSha256"] = Sha256("wrong-draft");
                break;
            case "wrong-catalog-hash":
                plan["candidateCatalogSha256"] = Sha256("wrong-catalog");
                break;
            case "missing-candidate":
                plan["teacher"]!["candidateId"] = "not-in-catalog";
                break;
            case "student-candidate":
                plan["teacher"]!["candidateId"] = "qwen2.5-coder-7b-instruct";
                break;
            case "tampered-catalog-revision":
                var catalog = await ReadObjectAsync(fixture.CatalogPath);
                catalog["candidates"]![3]!["revision"] = new string('a', 40);
                await WriteNodeAsync(fixture.CatalogPath, catalog);
                plan["candidateCatalogSha256"] = await FileSha256Async(fixture.CatalogPath);
                break;
        }
        await WriteNodeAsync(fixture.PlanPath, plan);

        Func<Task> compile = async () => await CompileAsync(fixture);

        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Fact]
    public async Task Compiler_prompt_identity_is_source_grounded_and_rejects_true_duplicates()
    {
        using (var distinctWorkspace = new TestWorkspace())
        {
            var fixture = await WriteFixtureAsync(distinctWorkspace);
            var manifest = await ReadObjectAsync(fixture.ManifestPath);
            manifest["examples"]![1]!["messages"] = manifest["examples"]![0]!["messages"]!.DeepClone();
            manifest["examples"]![1]!["messages"]![2]!["content"] = fixture.ReferenceAnswers[1];
            await WriteNodeAsync(fixture.ManifestPath, manifest);
            await RebindDraftHashAsync(fixture);

            var result = await CompileAsync(fixture);

            result.TaskCount.Should().Be(2);
        }

        using var duplicateWorkspace = new TestWorkspace();
        var duplicateFixture = await WriteFixtureAsync(duplicateWorkspace);
        var duplicateManifest = await ReadObjectAsync(duplicateFixture.ManifestPath);
        duplicateManifest["examples"]![1]!["messages"] =
            duplicateManifest["examples"]![0]!["messages"]!.DeepClone();
        duplicateManifest["examples"]![1]!["messages"]![2]!["content"] =
            duplicateFixture.ReferenceAnswers[1];
        duplicateManifest["examples"]![1]!["sources"] =
            duplicateManifest["examples"]![0]!["sources"]!.DeepClone();
        await WriteNodeAsync(duplicateFixture.ManifestPath, duplicateManifest);
        await RebindDraftHashAsync(duplicateFixture);

        Func<Task> compileDuplicate = async () => await CompileAsync(duplicateFixture);

        (await compileDuplicate.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain("duplicates an earlier source-grounded teacher prompt");
        File.Exists(duplicateFixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("terminal-user")]
    [InlineData("assistant-first")]
    [InlineData("task-order")]
    public async Task Compiler_rejects_malformed_conversations_and_non_exact_task_rows(string mutation)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        if (mutation == "task-order")
        {
            var plan = await ReadObjectAsync(fixture.PlanPath);
            var tasks = plan["tasks"]!.AsArray();
            var first = tasks[0]!.DeepClone();
            var second = tasks[1]!.DeepClone();
            tasks[0] = second;
            tasks[1] = first;
            await WriteNodeAsync(fixture.PlanPath, plan);
        }
        else
        {
            var manifest = await ReadObjectAsync(fixture.ManifestPath);
            var messages = manifest["examples"]![0]!["messages"]!.AsArray();
            if (mutation == "terminal-user")
            {
                messages[^1]!["role"] = "user";
            }
            else
            {
                messages[1]!["role"] = "assistant";
            }
            await WriteNodeAsync(fixture.ManifestPath, manifest);
            await RebindDraftHashAsync(fixture);
        }

        Func<Task> compile = async () => await CompileAsync(fixture);

        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("requests")]
    [InlineData("prompt")]
    [InlineData("completion")]
    [InlineData("total")]
    [InlineData("context")]
    public async Task Compiler_rejects_insufficient_budgets_and_context_window(string mutation)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var plan = await ReadObjectAsync(fixture.PlanPath);
        switch (mutation)
        {
            case "requests":
                plan["budget"]!["maxRequests"] = 3;
                break;
            case "prompt":
                plan["budget"]!["maxPromptTokens"] = 3;
                break;
            case "completion":
                plan["budget"]!["maxCompletionTokens"] = 767;
                break;
            case "total":
                plan["budget"]!["maxTotalTokens"] = 771;
                break;
            case "context":
                plan["tokenizerPreflight"]!["maxModelLen"] = 256;
                break;
        }
        await WriteNodeAsync(fixture.PlanPath, plan);

        Func<Task> compile = async () => await CompileAsync(fixture);

        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("equal-hashes")]
    [InlineData("repeated-hash")]
    [InlineData("mutable-profile")]
    public async Task Compiler_rejects_placeholder_runtime_and_profile_identities(string mutation)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var plan = await ReadObjectAsync(fixture.PlanPath);
        switch (mutation)
        {
            case "equal-hashes":
                plan["teacher"]!["runtimeSha256"] = plan["teacher"]!["chatTemplateSha256"]!.GetValue<string>();
                break;
            case "repeated-hash":
                plan["teacher"]!["runtimeSha256"] = new string('a', 64);
                break;
            case "mutable-profile":
                plan["teacher"]!["profileVersion"] = "latest";
                break;
        }
        await WriteNodeAsync(fixture.PlanPath, plan);

        Func<Task> compile = async () => await CompileAsync(fixture);

        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("../outside.md")]
    [InlineData("capture-plan.json")]
    [InlineData("candidate-catalog.json")]
    [InlineData("teacher-generation.v2.json")]
    [InlineData("evidence/source-csharp.md:alternate-stream")]
    [InlineData("evidence/source?.md")]
    public async Task Compiler_rejects_source_escape_and_control_file_aliases(string contentPath)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        manifest["examples"]![0]!["sources"]![0]!["contentPath"] = contentPath;
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        Func<Task> compile = async () => await CompileAsync(fixture);

        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Fact]
    public async Task Compiler_rejects_source_bytes_aliasing_a_control_snapshot()
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var aliasPath = Path.Combine(
            Path.GetDirectoryName(fixture.SourcePaths[0])!,
            "catalog-control-alias.json");
        if (!TryCreateHardLink(aliasPath, fixture.CatalogPath))
        {
            File.Copy(fixture.CatalogPath, aliasPath);
        }
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        manifest["examples"]![0]!["sources"]![0]!["contentPath"] =
            "evidence/catalog-control-alias.json";
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        Func<Task> compile = async () => await CompileAsync(fixture);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain("bytes must not alias a control input snapshot");
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Fact]
    public async Task Compiler_rejects_any_source_containing_a_cross_task_reference_answer()
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        await File.WriteAllTextAsync(
            fixture.SourcePaths[0],
            $"Leaked answer from another task: {fixture.ReferenceAnswers[1]}\n",
            new UTF8Encoding(false));

        Func<Task> compile = async () => await CompileAsync(fixture);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain("must not contain a stripped terminal reference answer");
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("cross-task-user")]
    [InlineData("earlier-assistant")]
    public async Task Compiler_rejects_reference_answers_in_any_retained_authored_message(string mutation)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        if (mutation == "cross-task-user")
        {
            manifest["examples"]![1]!["messages"]![0]!["content"] = fixture.ReferenceAnswers[0];
        }
        else
        {
            manifest["examples"]![1]!["messages"]![1]!["content"] = fixture.ReferenceAnswers[1];
        }
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        Func<Task> compile = async () => await CompileAsync(fixture);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain("retained message").And.Contain("stripped terminal reference answer");
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("id")]
    [InlineData("title")]
    public async Task Compiler_rejects_reference_answers_in_source_prompt_metadata(string field)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        var source = manifest["examples"]![0]!["sources"]![0]!;
        if (field == "id")
        {
            source["id"] = $"source-{fixture.ReferenceAnswers[0]}";
        }
        else
        {
            source["title"] = $"Leaked title {fixture.ReferenceAnswers[1]}";
        }
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        Func<Task> compile = async () => await CompileAsync(fixture);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain(field == "id" ? "source ID" : "title")
            .And.Contain("stripped terminal reference answer");
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("authority")]
    [InlineData("evidence")]
    [InlineData("source-metadata")]
    public async Task Compiler_rejects_reference_answers_in_any_emitted_string_value(string field)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        switch (field)
        {
            case "authority":
                manifest["provenance"] = $"Leaked authority {fixture.ReferenceAnswers[0]}";
                break;
            case "evidence":
                manifest["examples"]![0]!["evidence"]![0] =
                    $"Leaked evidence {fixture.ReferenceAnswers[1]}";
                break;
            case "source-metadata":
                manifest["examples"]![0]!["sources"]![0]!["provenance"] =
                    $"Leaked source provenance {fixture.ReferenceAnswers[0]}";
                break;
        }
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);

        Func<Task> compile = async () => await CompileAsync(fixture);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain("emitted JSON string value")
            .And.Contain("stripped terminal reference answer");
        File.Exists(fixture.OutputPath).Should().BeFalse();
    }

    [Theory]
    [InlineData("REFERENCE-anythingRISK")]
    [InlineData("reference.+[risk]")]
    public async Task Compiler_reference_answer_union_is_literal_and_case_sensitive(string sourceContent)
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var manifest = await ReadObjectAsync(fixture.ManifestPath);
        manifest["examples"]![1]!["messages"]![3]!["content"] = "REFERENCE.+[RISK]";
        await WriteNodeAsync(fixture.ManifestPath, manifest);
        await RebindDraftHashAsync(fixture);
        await File.WriteAllTextAsync(
            fixture.SourcePaths[0],
            sourceContent + "\n",
            new UTF8Encoding(false));

        var result = await CompileAsync(fixture);

        result.TaskCount.Should().Be(2);
    }

    [Fact]
    public async Task Compiler_revalidates_source_bytes_before_publication()
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);

        Func<Task> compile = async () => await ExpertModelTeacherGenerationManifestTools.CompileAsync(
            fixture.ManifestPath,
            fixture.PlanPath,
            fixture.CatalogPath,
            fixture.OutputPath,
            async cancellationToken => await File.WriteAllTextAsync(
                fixture.SourcePaths[0],
                "mutated source bytes\n",
                new UTF8Encoding(false),
                cancellationToken));

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message.Should()
            .Contain("changed before publication");
        File.Exists(fixture.OutputPath).Should().BeFalse();
        Directory.GetFiles(Path.GetDirectoryName(fixture.OutputPath)!, "*.tmp").Should().BeEmpty();
    }

    [Fact]
    public async Task Compiler_rejects_unknown_fields_and_preserves_existing_output()
    {
        using var workspace = new TestWorkspace();
        var fixture = await WriteFixtureAsync(workspace);
        var plan = await ReadObjectAsync(fixture.PlanPath);
        plan["unexpected"] = true;
        await WriteNodeAsync(fixture.PlanPath, plan);

        Func<Task> unknownField = async () => await CompileAsync(fixture);

        await unknownField.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(fixture.OutputPath).Should().BeFalse();

        await WriteFixturePlanAsync(fixture);
        await File.WriteAllTextAsync(fixture.OutputPath, "existing output", new UTF8Encoding(false));
        Func<Task> existingOutput = async () => await CompileAsync(fixture);

        await existingOutput.Should().ThrowAsync<IOException>();
        (await File.ReadAllTextAsync(fixture.OutputPath)).Should().Be("existing output");
        Directory.GetFiles(Path.GetDirectoryName(fixture.OutputPath)!, "*.tmp").Should().BeEmpty();
    }

    private static Task<ExpertModelTeacherGenerationCompileResult> CompileAsync(Fixture fixture) =>
        ExpertModelTeacherGenerationManifestTools.CompileAsync(
            fixture.ManifestPath,
            fixture.PlanPath,
            fixture.CatalogPath,
            fixture.OutputPath);

    private static async Task<Fixture> WriteFixtureAsync(TestWorkspace workspace)
    {
        var root = workspace.PathFor("authoring");
        var evidenceDirectory = Path.Combine(root, "evidence");
        Directory.CreateDirectory(evidenceDirectory);
        var sourcePaths = new[]
        {
            Path.Combine(evidenceDirectory, "source-csharp.md"),
            Path.Combine(evidenceDirectory, "source-risk.md"),
        };
        await File.WriteAllTextAsync(
            sourcePaths[0],
            "Project-owned C# evidence.\n",
            new UTF8Encoding(false));
        await File.WriteAllTextAsync(
            sourcePaths[1],
            "Project-owned risk evidence.\n",
            new UTF8Encoding(false));
        var referenceAnswers = new[]
        {
            "REFERENCE-ANSWER-CSHARP-MUST-BE-STRIPPED",
            "REFERENCE-ANSWER-RISK-MUST-BE-STRIPPED",
        };
        var rights = new DatasetRights(true, true, false, false, false);
        var examples = new[]
        {
            new ExpertModelDatasetDraftExample
            {
                Id = "draft-csharp-001",
                TaskKind = ExpertTaskKind.CodeReview,
                Domains = [ExpertDomain.CSharp],
                Messages =
                [
                    new LlmMessage("system", "Use only the supplied source snapshot."),
                    new LlmMessage("user", "Review the bounded C# fixture."),
                    new LlmMessage("assistant", referenceAnswers[0]),
                ],
                ContaminationGroup = "family-csharp",
                KnowledgeClass = "candidate-stable",
                Sources =
                [
                    Source(
                        "source-csharp",
                        "C# source",
                        "evidence/source-csharp.md",
                        "repo://tests/source-csharp"),
                ],
                Evidence = ["Project-owned intake only; no review or training authority."],
            },
            new ExpertModelDatasetDraftExample
            {
                Id = "draft-risk-001",
                TaskKind = ExpertTaskKind.RiskAnalysis,
                Domains = [ExpertDomain.RiskManagement],
                Messages =
                [
                    new LlmMessage("user", "State the first bounded risk observation."),
                    new LlmMessage("assistant", "A prior draft turn that remains model-visible."),
                    new LlmMessage("user", "Now give the final bounded risk answer."),
                    new LlmMessage("assistant", referenceAnswers[1]),
                ],
                ContaminationGroup = "family-risk",
                KnowledgeClass = "retrieval-only",
                Sources =
                [
                    Source(
                        "source-risk",
                        "Risk source",
                        "evidence/source-risk.md",
                        uri: null),
                ],
                Evidence = ["Private evaluation intake only; no independent review is recorded."],
            },
        };
        var manifest = new ExpertModelDatasetDraftManifest
        {
            SchemaVersion = ExpertModelDatasetDraftAuthoringTools.SchemaVersion,
            Producer = "draft-fixture-author",
            ProducedAtUtc = FixtureTime,
            Reviewer = "unassigned-independent-reviewer",
            CutoffUtc = FixtureTime,
            Provenance = "Project-owned teacher-manifest compiler fixture.",
            License = "Project-owned test fixture",
            Rights = rights,
            RightsBasis = "Private storage and evaluation only.",
            Examples = examples,
        };
        var manifestPath = Path.Combine(root, "seed-draft.json");
        await WriteJsonAsync(manifestPath, manifest);

        var catalogPath = Path.Combine(root, "candidate-catalog.json");
        await WriteJsonAsync(catalogPath, CandidateCatalog());
        var fixture = new Fixture(
            manifestPath,
            Path.Combine(root, "capture-plan.json"),
            catalogPath,
            Path.Combine(root, "teacher-generation.v2.json"),
            sourcePaths,
            referenceAnswers);
        await WriteFixturePlanAsync(fixture);
        return fixture;
    }

    private static ExpertModelDatasetDraftSource Source(
        string id,
        string title,
        string contentPath,
        string? uri) =>
        new()
        {
            Id = id,
            Title = title,
            ContentPath = contentPath,
            Provenance = "Project-owned compiler test fixture.",
            License = "Project-owned test fixture",
            RetrievedAtUtc = FixtureTime,
            AvailableAtUtc = FixtureTime,
            Uri = uri,
        };

    private static object CandidateCatalog() => new
    {
        schemaVersion = ExpertModelTeacherGenerationManifestTools.CandidateCatalogSchemaVersion,
        catalogVersion = "1.0.0",
        candidates = new object[]
        {
            Candidate(
                "qwen2.5-coder-7b-instruct",
                "Qwen2.5-Coder 7B Instruct",
                "Qwen/Qwen2.5-Coder-7B-Instruct",
                "https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct",
                "c03e6d358207e414f1eca0bb1891e29f1db0e242",
                ["student"]),
            Candidate(
                "qwen2.5-coder-14b-instruct",
                "Qwen2.5-Coder 14B Instruct",
                "Qwen/Qwen2.5-Coder-14B-Instruct",
                "https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct",
                "aedcc2d42b622764e023cf882b6652e646b95671",
                ["student"]),
            Candidate(
                "gpt-oss-20b",
                "gpt-oss-20b",
                "openai/gpt-oss-20b",
                "https://huggingface.co/openai/gpt-oss-20b",
                "6cee5e81ee83917806bbde320786a8fb61efebee",
                ["student"]),
            Candidate(
                "qwen3-coder-30b-a3b-instruct",
                "Qwen3-Coder 30B-A3B Instruct",
                "Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct",
                "b2cff646eb4bb1d68355c01b18ae02e7cf42d120",
                ["teacher", "fallback"]),
        },
    };

    private static object Candidate(
        string id,
        string displayName,
        string modelId,
        string officialSourceUrl,
        string revision,
        string[] roles) => new
        {
            id,
            displayName,
            modelId,
            revision,
            license = "Apache-2.0",
            licenseUrl = "https://www.apache.org/licenses/LICENSE-2.0",
            officialSourceUrl,
            roles,
        };

    private static async Task WriteFixturePlanAsync(Fixture fixture)
    {
        var plan = new ExpertModelTeacherGenerationCapturePlan
        {
            SchemaVersion = ExpertModelTeacherGenerationManifestTools.CapturePlanSchemaVersion,
            DraftManifestSha256 = await FileSha256Async(fixture.ManifestPath),
            CandidateCatalogSha256 = await FileSha256Async(fixture.CatalogPath),
            Teacher = new ExpertModelTeacherIdentity
            {
                CandidateId = "qwen3-coder-30b-a3b-instruct",
                ProfileVersion = "teacher-profile-2025-01-15",
                ChatTemplateSha256 = Sha256("pinned-chat-template"),
                RuntimeSha256 = Sha256("pinned-vllm-runtime"),
            },
            Generation = new ExpertModelTeacherGenerationPolicy
            {
                Temperature = 0.3m,
                TopP = 0.95m,
                Seeds = [17, 23],
            },
            Budget = new ExpertModelTeacherGenerationBudget
            {
                MaxRequests = 4,
                MaxPromptTokens = 10_000,
                MaxCompletionTokens = 1_000,
                MaxTotalTokens = 11_000,
            },
            TokenizerPreflight = new ExpertModelTeacherTokenizerPreflight
            {
                Protocol = ExpertModelTeacherGenerationManifestTools.TokenizerProtocol,
                MaxModelLen = 4_096,
            },
            Tasks =
            [
                new ExpertModelTeacherTaskCapturePlan
                {
                    TaskId = "draft-csharp-001",
                    MaxOutputTokens = 256,
                },
                new ExpertModelTeacherTaskCapturePlan
                {
                    TaskId = "draft-risk-001",
                    MaxOutputTokens = 128,
                },
            ],
        };
        await WriteJsonAsync(fixture.PlanPath, plan);
    }

    private static async Task RebindDraftHashAsync(Fixture fixture)
    {
        var plan = await ReadObjectAsync(fixture.PlanPath);
        plan["draftManifestSha256"] = await FileSha256Async(fixture.ManifestPath);
        await WriteNodeAsync(fixture.PlanPath, plan);
    }

    private static async Task<JsonObject> ReadObjectAsync(string path) =>
        JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();

    private static Task WriteNodeAsync(string path, JsonNode node) =>
        File.WriteAllTextAsync(
            path,
            node.ToJsonString(CoordinatorJson.Options),
            new UTF8Encoding(false));

    private static Task WriteJsonAsync<T>(string path, T value) =>
        File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(value, CoordinatorJson.Options),
            new UTF8Encoding(false));

    private static async Task<string> FileSha256Async(string path) =>
        Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))).ToLowerInvariant();

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static bool TryCreateHardLink(string newFilePath, string existingFilePath) =>
        OperatingSystem.IsWindows() &&
        CreateHardLink(newFilePath, existingFilePath, IntPtr.Zero);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes);

    private sealed record Fixture(
        string ManifestPath,
        string PlanPath,
        string CatalogPath,
        string OutputPath,
        IReadOnlyList<string> SourcePaths,
        IReadOnlyList<string> ReferenceAnswers);
}
