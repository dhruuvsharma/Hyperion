using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class ExpertModelDatasetTests
{
    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Conversation_hash_uses_the_cross_platform_length_prefixed_contract()
    {
        LlmMessage[] messages =
        [
            new("system", "DaxAlgo expert v1"),
            new("user", "Price > 100? π = 3.14\nRisk: 1%"),
            new("assistant", "Use < & > safely. 🚀")
        ];

        ExpertModelDatasetTools.ComputeConversationSha256(messages).Should().Be(
            "83a92500a6825b04b0096f4b521a60fc8bd539e7fe0dec021b7bd19bd3149310");
    }

    [Fact]
    public async Task Valid_nontraining_dataset_reports_coverage_but_export_requires_receipts()
    {
        using var workspace = new TestWorkspace();
        var rights = new DatasetRights(true, true, true, true, false);
        var development = Example(
            "quant-dev",
            "development",
            "quant-family",
            rights,
            useForTraining: false,
            ExpertTaskKind.QuantitativeReasoning,
            [ExpertDomain.QuantitativeMath, ExpertDomain.ProbabilityStatistics]);
        var sealedExample = Example(
            "market-sealed",
            "sealed",
            "market-family",
            rights,
            useForTraining: false,
            ExpertTaskKind.MarketAnalysis,
            [ExpertDomain.FinanceMarkets]);
        var input = workspace.PathFor("expert-dataset.jsonl");
        var output = workspace.PathFor("provider-sft.jsonl");
        await WriteDatasetAsync(input, development, sealedExample);

        var validation = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);
        var coverage = await ExpertModelDatasetTools.BuildCoverageReportAsync(input);

        validation.IsValid.Should().BeTrue();
        validation.ExampleCount.Should().Be(2);
        validation.TrainingEligibleCount.Should().Be(0);

        coverage.ExampleCount.Should().Be(2);
        coverage.TrainingEligibleCount.Should().Be(0);
        coverage.TaskCounts[ExpertTaskKind.QuantitativeReasoning].Should().Be(1);
        coverage.TaskCounts[ExpertTaskKind.MarketAnalysis].Should().Be(1);
        coverage.DomainCounts[ExpertDomain.ProbabilityStatistics].Should().Be(1);
        coverage.OriginCounts[ExpertDatasetOrigin.HumanAuthored].Should().Be(2);
        coverage.SplitCounts.Should().Contain(new KeyValuePair<string, int>("development", 1));
        coverage.SplitCounts.Should().Contain(new KeyValuePair<string, int>("sealed", 1));
        coverage.Cells.Should().Contain(cell =>
            cell.TaskKind == ExpertTaskKind.QuantitativeReasoning &&
            cell.Domain == ExpertDomain.QuantitativeMath &&
            cell.Split == "development" &&
            cell.ExampleCount == 1 &&
            cell.TrainingEligibleCount == 0);
        Func<Task> export = () => ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            input,
            output,
            requireProviderUploadRights: true);
        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("detached authenticated review-receipt set");
        File.Exists(output).Should().BeFalse();
    }

    [Fact]
    public async Task Training_exports_fail_closed_without_receipts_and_preserve_outputs()
    {
        using var workspace = new TestWorkspace();
        var trainableRights = new DatasetRights(true, true, true, false, false);
        var sourceWithoutTrainingRights = new DatasetRights(true, true, false, false, false);
        var invalidTraining = Example(
            "source-rights",
            "development",
            "source-rights-family",
            sourceWithoutTrainingRights,
            useForTraining: true) with
        {
            Rights = trainableRights
        };
        var invalidPath = workspace.PathFor("missing-source-rights.jsonl");
        await WriteDatasetAsync(invalidPath, invalidTraining);

        var invalidReport = await ExpertModelDatasetTools.ValidateJsonLinesAsync(invalidPath);

        invalidReport.Issues.Should().Contain(issue => issue.Message.Contains("lacks training rights"));

        var localOnly = Example(
            "local-only",
            "development",
            "local-only-family",
            trainableRights,
            useForTraining: true);
        var localOnlyPath = workspace.PathFor("local-only.jsonl");
        var providerOutput = workspace.PathFor("provider.jsonl");
        await WriteDatasetAsync(localOnlyPath, localOnly);
        await File.WriteAllTextAsync(providerOutput, "existing output");

        Func<Task> providerExport = () => ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            localOnlyPath,
            providerOutput,
            requireProviderUploadRights: true);
        (await providerExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("detached authenticated review-receipt set");
        var localOutput = workspace.PathFor("local-sft.jsonl");
        Func<Task> localExport = () => ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            localOnlyPath,
            localOutput,
            requireProviderUploadRights: false);

        await localExport.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(localOutput).Should().BeFalse();
        (await File.ReadAllTextAsync(providerOutput)).Should().Be("existing output");
    }

    [Fact]
    public async Task Retrieval_only_knowledge_cannot_declare_training_rights()
    {
        using var workspace = new TestWorkspace();
        var rights = new DatasetRights(true, true, true, false, false);
        var example = Example(
            "retrieval-only",
            "development",
            "retrieval-only-family",
            rights,
            useForTraining: false);
        var evidence = new[]
        {
            "knowledgeClass=retrieval-only",
            "The answer was reviewed only for retrieval use."
        };
        example = example with
        {
            Verification = example.Verification with
            {
                Evidence = evidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    evidence,
                    [],
                    [])
            }
        };
        var input = workspace.PathFor("retrieval-only.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("Retrieval-only examples"));
    }

    [Fact]
    public async Task Validation_rejects_exact_content_and_contamination_groups_across_splits()
    {
        using var workspace = new TestWorkspace();
        var rights = new DatasetRights(true, true, true, false, false);
        var development = Example(
            "split-dev",
            "development",
            "shared-family",
            rights,
            useForTraining: false);
        var calibration = Example(
            "split-calibration",
            "calibration",
            "shared-family",
            rights,
            useForTraining: false) with
        {
            Messages = development.Messages
        };
        var input = workspace.PathFor("cross-split.jsonl");
        await WriteDatasetAsync(input, development, calibration);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.IsValid.Should().BeFalse();
        report.Issues.Should().Contain(issue => issue.Message.Contains("Exact message content"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("Contamination group"));
    }

    [Fact]
    public async Task Validation_rejects_invalid_message_order_and_non_assistant_ending()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "bad-order",
            "development",
            "bad-order-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false) with
        {
            Messages =
            [
                new LlmMessage("assistant", "An answer cannot begin the conversation."),
                new LlmMessage("user", "This also leaves the conversation unfinished.")
            ]
        };
        var input = workspace.PathFor("bad-order.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().Contain(issue => issue.Message.Contains("preserve chat ordering"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("final message"));
    }

    [Fact]
    public async Task Validation_requires_at_least_one_domain_label()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "missing-domain",
            "development",
            "missing-domain-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false) with
        {
            Domains = []
        };
        var input = workspace.PathFor("missing-domain.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("At least one expert domain"));
    }

    [Fact]
    public async Task Code_tasks_require_compile_and_test_verification_evidence()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "unverified-code",
            "development",
            "unverified-code-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false,
            ExpertTaskKind.CodeGeneration,
            [ExpertDomain.CSharp]) with
        {
            Verification = new ExpertVerificationEvidence
            {
                Verified = true,
                Reviewer = "test-reviewer",
                VerifiedAtUtc = FixtureTime,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    ["The answer was reviewed for correctness."],
                    [],
                    []),
                Evidence = ["The answer was reviewed for correctness."],
                CompileSucceeded = false,
                CompileEvidence = [],
                TestsPassed = false,
                TestEvidence = []
            }
        };
        var input = workspace.PathFor("unverified-code.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().Contain(issue => issue.Message.Contains("compile verification"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("test verification"));
    }

    [Fact]
    public async Task Approved_code_tasks_require_exact_executable_verifier_evidence()
    {
        using var workspace = new TestWorkspace();
        var valid = Example(
            "verified-code",
            "development",
            "verified-code-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false,
            ExpertTaskKind.CodeGeneration,
            [ExpertDomain.CSharp]);
        var validPath = workspace.PathFor("verified-code.jsonl");
        await WriteDatasetAsync(validPath, valid);

        var validReport = await ExpertModelDatasetTools.ValidateJsonLinesAsync(validPath);

        validReport.IsValid.Should().BeTrue();

        var arbitraryCompileEvidence = new[] { "The generated code compiled successfully." };
        var arbitraryTestEvidence = new[] { "The focused test suite passed." };
        var forged = valid with
        {
            Id = "forged-code-evidence",
            ContaminationGroup = "forged-code-evidence-family",
            Verification = valid.Verification with
            {
                CompileEvidence = arbitraryCompileEvidence,
                TestEvidence = arbitraryTestEvidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    valid.Verification.Evidence,
                    arbitraryCompileEvidence,
                    arbitraryTestEvidence)
            }
        };
        var forgedPath = workspace.PathFor("forged-code-evidence.jsonl");
        await WriteDatasetAsync(forgedPath, forged);

        var forgedReport = await ExpertModelDatasetTools.ValidateJsonLinesAsync(forgedPath);

        forgedReport.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("exact executable-verifier evidence shape"));

        var nonCanonicalCounts = valid.Verification.TestEvidence.ToArray();
        nonCanonicalCounts[3] = "vectorCount=01";
        var nonCanonical = valid with
        {
            Id = "noncanonical-code-counts",
            ContaminationGroup = "noncanonical-code-counts-family",
            Verification = valid.Verification with
            {
                TestEvidence = nonCanonicalCounts,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    valid.Verification.Evidence,
                    valid.Verification.CompileEvidence,
                    nonCanonicalCounts)
            }
        };
        var nonCanonicalPath = workspace.PathFor("noncanonical-code-counts.jsonl");
        await WriteDatasetAsync(nonCanonicalPath, nonCanonical);

        var nonCanonicalReport = await ExpertModelDatasetTools.ValidateJsonLinesAsync(
            nonCanonicalPath);

        nonCanonicalReport.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("execution counts"));
    }

    [Fact]
    public async Task Approved_code_tasks_bind_compile_evidence_to_exact_assistant_source()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "source-bound-code",
            "development",
            "source-bound-code-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false,
            ExpertTaskKind.CodeRepair,
            [ExpertDomain.CSharp]);
        var compileEvidence = example.Verification.CompileEvidence.ToArray();
        compileEvidence[1] = $"sourceSha256={new string('f', 64)}";
        example = example with
        {
            Verification = example.Verification with
            {
                CompileEvidence = compileEvidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    example.Verification.Evidence,
                    compileEvidence,
                    example.Verification.TestEvidence)
            }
        };
        var input = workspace.PathFor("source-bound-code.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("exact source"));
    }

    [Theory]
    [InlineData(ExpertTaskKind.GeneralQuestionAnswering, ExpertDomain.FinanceMarkets)]
    [InlineData(ExpertTaskKind.QuantitativeReasoning, ExpertDomain.QuantitativeMath)]
    [InlineData(ExpertTaskKind.CodeGeneration, ExpertDomain.CSharp)]
    [InlineData(ExpertTaskKind.WpfUiDesign, ExpertDomain.WpfUiDesign)]
    public async Task Every_training_row_remains_ineligible_without_authenticated_receipts(
        ExpertTaskKind taskKind,
        ExpertDomain domain)
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "unauthenticated-code-training",
            "development",
            "unauthenticated-code-training-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: true,
            taskKind,
            [domain]);
        var input = workspace.PathFor("unauthenticated-code-training.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.IsValid.Should().BeTrue();
        report.TrainingEligibleCount.Should().Be(0);
        report.Issues.Should().BeEmpty();
        var output = workspace.PathFor("must-not-export-code-sft.jsonl");
        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            input,
            output,
            requireProviderUploadRights: false);
        await export.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(output).Should().BeFalse();
    }

    [Fact]
    public async Task Approved_code_review_tasks_remain_unsupported()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "unsupported-code-review",
            "development",
            "unsupported-code-review-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false,
            ExpertTaskKind.CodeReview,
            [ExpertDomain.CSharp]);
        var input = workspace.PathFor("unsupported-code-review.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("supported executable verifier profile"));
    }

    [Fact]
    public async Task Validation_binds_conversation_content_and_model_generated_lineage()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "tampered-lineage",
            "development",
            "tampered-lineage-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false) with
        {
            ConversationSha256 = new string('0', 64),
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.OpenWeightTeacher,
                Producer = "test-teacher",
                ModelId = "test/open-weight-teacher",
                ModelRevision = "main",
                ProfileVersion = "test-teacher/v1",
                ProducedAtUtc = FixtureTime
            }
        };
        var input = workspace.PathFor("tampered-lineage.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().Contain(issue => issue.Message.Contains("canonical message content"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("exact lowercase 40-character source commit"));
        report.Issues.Should().Contain(issue => issue.Message.Contains("prompt SHA-256"));
    }

    [Fact]
    public async Task Verification_timestamp_cannot_precede_lineage_production()
    {
        using var workspace = new TestWorkspace();
        var basis = Example(
            "pre-production-verification",
            "development",
            "pre-production-verification-family",
            new DatasetRights(true, true, false, false, false),
            useForTraining: false);
        var example = basis with
        {
            Verification = basis.Verification with
            {
                VerifiedAtUtc = FixtureTime.AddTicks(-1)
            }
        };
        var input = workspace.PathFor("pre-production-verification.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("must not precede lineage production"));
    }

    [Fact]
    public async Task Validation_binds_verification_evidence_content()
    {
        using var workspace = new TestWorkspace();
        var example = Example(
            "tampered-evidence",
            "development",
            "tampered-evidence-family",
            new DatasetRights(true, true, true, false, false),
            useForTraining: false) with
        {
            Verification = Example(
                "evidence-source",
                "development",
                "evidence-source-family",
                new DatasetRights(true, true, true, false, false),
                useForTraining: false).Verification with
            {
                Evidence = ["Evidence content changed after the hash was recorded."]
            }
        };
        var input = workspace.PathFor("tampered-evidence.jsonl");
        await WriteDatasetAsync(input, example);

        var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input);

        report.Issues.Should().ContainSingle(issue =>
            issue.Message.Contains("canonical evidence content"));
    }

    private static async Task WriteDatasetAsync(
        string path,
        params ExpertModelDatasetExample[] examples) =>
        await File.WriteAllLinesAsync(
            path,
            examples.Select(example => JsonSerializer.Serialize(example, CompactJson)));

    private static ExpertModelDatasetExample Example(
        string id,
        string split,
        string contaminationGroup,
        DatasetRights rights,
        bool useForTraining,
        ExpertTaskKind taskKind = ExpertTaskKind.GeneralQuestionAnswering,
        IReadOnlyList<ExpertDomain>? domains = null)
    {
        var codeRelated = taskKind is
            ExpertTaskKind.CodeGeneration or ExpertTaskKind.CodeRepair or ExpertTaskKind.CodeReview;
        LlmMessage[] messages =
        [
            new("system", "Answer as a bounded DaxAlgo domain expert."),
            new("user", $"Provide a verified answer for fixture {id}."),
            new("assistant", $"This is the reviewed answer for fixture {id}.")
        ];
        var evidence = new[]
        {
            "knowledgeClass=candidate-stable",
            "The answer was reviewed against its licensed source."
        };
        string[] compileEvidence = codeRelated
            ?
            [
                $"profile={ExpertModelDatasetReviewTools.DaxqExecutableProfile}",
                $"sourceSha256={Sha256(messages[^1].Content)}",
                $"compilerClosureSha256={new string('1', 64)}",
                $"canonicalProgramSha256={new string('2', 64)}"
            ]
            : [];
        string[] testEvidence = codeRelated
            ?
            [
                $"testSpecificationSha256={new string('3', 64)}",
                $"executionTraceSha256={new string('4', 64)}",
                $"executableResultSha256={new string('5', 64)}",
                "vectorCount=1",
                "callbackCount=1"
            ]
            : [];
        return new ExpertModelDatasetExample
        {
            SchemaVersion = CoordinatorVersions.ExpertModelDatasetSchema,
            Id = id,
            TaskKind = taskKind,
            Domains = domains ?? [ExpertDomain.FinanceMarkets],
            Messages = messages,
            ConversationSha256 = ExpertModelDatasetTools.ComputeConversationSha256(messages),
            Sources =
            [
                new DatasetSourceAsset(
                    $"source-{id}",
                    "Licensed test source",
                    $"Licensed evidence for fixture {id}.",
                    "Synthetic test fixture.",
                    "Test-only license",
                    FixtureTime,
                    FixtureTime,
                    null,
                    rights)
            ],
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.HumanAuthored,
                Producer = "test-reviewer",
                ProducedAtUtc = FixtureTime
            },
            Verification = new ExpertVerificationEvidence
            {
                Verified = true,
                Reviewer = "test-reviewer",
                VerifiedAtUtc = FixtureTime,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    evidence,
                    compileEvidence,
                    testEvidence),
                Evidence = evidence,
                CompileSucceeded = codeRelated,
                CompileEvidence = compileEvidence,
                TestsPassed = codeRelated,
                TestEvidence = testEvidence
            },
            Split = split,
            ContaminationGroup = contaminationGroup,
            Provenance = "Synthetic expert-model dataset test fixture.",
            License = "Test-only license",
            Rights = rights,
            ReviewStatus = "approved",
            CutoffUtc = FixtureTime,
            UseForTraining = useForTraining
        };
    }

    private static string Sha256(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
