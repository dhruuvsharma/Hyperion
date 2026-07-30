using System.Diagnostics;
using System.Security.Cryptography;
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

public sealed class ExpertModelDatasetReviewTests
{
    private const string PassingDaxqSource = """
        using DaxAlgo.Sdk;

        public sealed class ReviewedDaxqStrategy : IBacktestStrategy
        {
            public void OnBar(IStrategyContext context)
            {
                if (context.Bar(BarField.Close, 0) >= 100.0)
                    context.Emit(SignalKind.Long, 0.75, 17);
                else
                    context.Emit(SignalKind.Short, 0.25, 9);
            }
        }
        """;

    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };

    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Cli_verification_and_review_preserve_rights_and_zero_training_eligibility()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [
                new ExpertDatasetTextCheck
                {
                    Id = "bounded-claim",
                    Kind = "contains",
                    Value = "bounded evidence",
                    IgnoreCase = true
                },
                new ExpertDatasetTextCheck
                {
                    Id = "no-profit-claim",
                    Kind = "not-contains",
                    Value = "guaranteed annual return",
                    IgnoreCase = true
                }
            ]);
        var reportPath = workspace.PathFor("verification-report.json");
        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        var cli = new CliApplication(cliOutput, cliError);

        var verifyExit = await cli.RunAsync(
            [
                "expert-dataset", "verify-draft",
                "--input", dataset,
                "--manifest", verificationManifest,
                "--output", reportPath
            ],
            CancellationToken.None);

        verifyExit.Should().Be(0, cliError.ToString());
        var report = JsonSerializer.Deserialize<ExpertDatasetVerificationReport>(
            await File.ReadAllTextAsync(reportPath),
            CoordinatorJson.Options)!;
        report.AllPassed.Should().BeTrue();
        report.Results.Should().ContainSingle(result => result.Passed);
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var reviewedDataset = workspace.PathFor("reviewed.jsonl");

        var reviewExit = await cli.RunAsync(
            [
                "expert-dataset", "apply-review",
                "--input", dataset,
                "--verification-manifest", verificationManifest,
                "--verification-report", reportPath,
                "--review-manifest", reviewManifest,
                "--output", reviewedDataset
            ],
            CancellationToken.None);

        reviewExit.Should().Be(0, cliError.ToString());
        var validation = await ExpertModelDatasetTools.ValidateJsonLinesAsync(reviewedDataset);
        validation.IsValid.Should().BeTrue();
        validation.TrainingEligibleCount.Should().Be(0);
        var row = JsonNode.Parse((await File.ReadAllLinesAsync(reviewedDataset)).Single())!.AsObject();
        row["reviewStatus"]!.GetValue<string>().Should().Be("approved");
        row["useForTraining"]!.GetValue<bool>().Should().BeFalse();
        row["verification"]!["verified"]!.GetValue<bool>().Should().BeTrue();
        row["rights"]!["mayTrain"]!.GetValue<bool>().Should().BeFalse();
        row["rights"]!["mayUploadToProvider"]!.GetValue<bool>().Should().BeFalse();
        row["sources"]![0]!["rights"]!["mayTrain"]!.GetValue<bool>().Should().BeFalse();
        cliOutput.ToString().Should().Contain("0 are training-eligible");
    }

    [Fact]
    public async Task Failed_automated_checks_cannot_be_human_approved()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [
                new ExpertDatasetTextCheck
                {
                    Id = "missing-required-fact",
                    Kind = "contains",
                    Value = "This sentence is absent.",
                    IgnoreCase = false
                }
            ]);
        var reportPath = workspace.PathFor("failed-report.json");
        var report = await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            verificationManifest,
            reportPath);
        report.AllPassed.Should().BeFalse();
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var output = workspace.PathFor("must-not-exist.jsonl");

        Func<Task> apply = async () => await ExpertModelDatasetReviewTools.ApplyReviewAsync(
            dataset,
            verificationManifest,
            reportPath,
            reviewManifest,
            output);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("cannot approve failed automated checks");
        File.Exists(output).Should().BeFalse();
    }

    [Fact]
    public async Task Review_timestamp_cannot_precede_the_bound_example_production_time()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [
                new ExpertDatasetTextCheck
                {
                    Id = "bounded-claim",
                    Kind = "contains",
                    Value = "bounded evidence",
                    IgnoreCase = true
                }
            ]);
        var reportPath = workspace.PathFor("pre-production-review-report.json");
        var report = await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            verificationManifest,
            reportPath);
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved",
            FixtureTime.AddTicks(-1));
        var output = workspace.PathFor("pre-production-review-output.jsonl");

        Func<Task> apply = async () => await ExpertModelDatasetReviewTools.ApplyReviewAsync(
            dataset,
            verificationManifest,
            reportPath,
            reviewManifest,
            output);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("must not precede any bound example's production time");
        File.Exists(output).Should().BeFalse();
    }

    [Fact]
    public async Task Review_reexecutes_verifiers_and_preserves_an_existing_output_on_tamper()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [
                new ExpertDatasetTextCheck
                {
                    Id = "bounded-claim",
                    Kind = "contains",
                    Value = "bounded evidence",
                    IgnoreCase = true
                }
            ]);
        var reportPath = workspace.PathFor("report.json");
        var report = await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            verificationManifest,
            reportPath);
        var originalReport = await File.ReadAllTextAsync(reportPath);
        Func<Task> repeatVerification = async () => await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            verificationManifest,
            reportPath);
        (await repeatVerification.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("already exists");
        (await File.ReadAllTextAsync(reportPath)).Should().Be(originalReport);
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var reportNode = JsonNode.Parse(await File.ReadAllTextAsync(reportPath))!.AsObject();
        reportNode["results"]![0]!["assistantSha256"] = new string('f', 64);
        reportNode["reportSha256"] = new string('0', 64);
        var forgedHash = Convert.ToHexString(SHA256.HashData(
            JsonSerializer.SerializeToUtf8Bytes(reportNode, CompactJson))).ToLowerInvariant();
        reportNode["reportSha256"] = forgedHash;
        await File.WriteAllTextAsync(reportPath, reportNode.ToJsonString(CoordinatorJson.Options));
        var output = workspace.PathFor("existing.jsonl");
        await File.WriteAllTextAsync(output, "existing private review output");

        Func<Task> apply = async () => await ExpertModelDatasetReviewTools.ApplyReviewAsync(
            dataset,
            verificationManifest,
            reportPath,
            reviewManifest,
            output);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("does not exactly match a fresh execution");
        (await File.ReadAllTextAsync(output)).Should().Be("existing private review output");
    }

    [Fact]
    public async Task Valid_review_never_replaces_an_existing_output()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [
                new ExpertDatasetTextCheck
                {
                    Id = "bounded-claim",
                    Kind = "contains",
                    Value = "bounded evidence",
                    IgnoreCase = true
                }
            ]);
        var reportPath = workspace.PathFor("valid-report.json");
        var report = await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            verificationManifest,
            reportPath);
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var output = workspace.PathFor("existing-valid.jsonl");
        await File.WriteAllTextAsync(output, "existing private review output");

        Func<Task> apply = async () => await ExpertModelDatasetReviewTools.ApplyReviewAsync(
            dataset,
            verificationManifest,
            reportPath,
            reviewManifest,
            output);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("already exists");
        (await File.ReadAllTextAsync(output)).Should().Be("existing private review output");
    }

    [Fact]
    public async Task Verification_refuses_an_oversized_report_without_publishing_it()
    {
        using var workspace = new TestWorkspace();
        var seedDataset = await CompileDraftAsync(workspace);
        var seedRow = JsonNode.Parse((await File.ReadAllLinesAsync(seedDataset)).Single())!.AsObject();
        const int exampleCount = 700;
        var rows = Enumerable.Range(0, exampleCount).Select(index =>
        {
            var row = seedRow.DeepClone().AsObject();
            row["id"] = $"review-example-{index:0000}";
            row["contaminationGroup"] = $"review-example-family-{index:0000}";
            row["sources"]![0]!["id"] = $"review-source-{index:0000}";
            return row.ToJsonString(CompactJson);
        });
        var dataset = workspace.PathFor("large-draft.jsonl");
        await File.WriteAllLinesAsync(dataset, rows);
        var checks = Enumerable.Range(0, ExpertModelDatasetReviewTools.MaxChecksPerExample)
            .Select(index => new ExpertDatasetTextCheck
            {
                Id = $"check-{index:00}",
                Kind = "contains",
                Value = "e",
                IgnoreCase = false
            })
            .ToArray();
        var manifest = new ExpertDatasetVerificationManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.VerificationManifestSchemaVersion,
            DatasetSha256 = await Sha256Async(dataset),
            Verifiers = Enumerable.Range(0, exampleCount)
                .Select(index => new ExpertDatasetVerifierAssignment
                {
                    ExampleId = $"review-example-{index:0000}",
                    VerifierId = "large-report-verifier-v1",
                    Checks = checks
                })
                .ToArray()
        };
        var manifestPath = workspace.PathFor("large-verification.json");
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, CompactJson));
        new FileInfo(manifestPath).Length.Should()
            .BeLessThan(ExpertModelDatasetReviewTools.MaxManifestBytes);
        var reportPath = workspace.PathFor("oversized-report.json");

        Func<Task> verify = async () => await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            manifestPath,
            reportPath);

        (await verify.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("output limit");
        File.Exists(reportPath).Should().BeFalse();
    }

    [Fact]
    public async Task Cli_fixture_write_is_no_clobber_and_failure_atomic()
    {
        using var workspace = new TestWorkspace();
        var destination = workspace.PathFor("fixture.txt");
        await CliApplication.WriteIfMissingAsync(destination, "first", CancellationToken.None);
        await CliApplication.WriteIfMissingAsync(destination, "second", CancellationToken.None);
        (await File.ReadAllTextAsync(destination)).Should().Be("first");

        var cancelledDestination = workspace.PathFor("cancelled.txt");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Func<Task> cancelledWrite = async () => await CliApplication.WriteIfMissingAsync(
            cancelledDestination,
            new string('x', 100_000),
            cancellation.Token);

        await cancelledWrite.Should().ThrowAsync<OperationCanceledException>();
        File.Exists(cancelledDestination).Should().BeFalse();
        Directory.GetFiles(workspace.RootPath, "*.tmp", SearchOption.TopDirectoryOnly)
            .Should().BeEmpty();
    }

    [Fact]
    public async Task Code_drafts_without_an_executable_profile_fail_verification_and_approval()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace, ExpertTaskKind.CodeGeneration);
        var validation = await ExpertModelDatasetTools.ValidateJsonLinesAsync(dataset);
        validation.IsValid.Should().BeTrue();
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [
                new ExpertDatasetTextCheck
                {
                    Id = "bounded-claim",
                    Kind = "contains",
                    Value = "bounded evidence",
                    IgnoreCase = true
                }
            ]);
        var reportPath = workspace.PathFor("code-report.json");
        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        var cli = new CliApplication(cliOutput, cliError);
        var verifyExit = await cli.RunAsync(
            [
                "expert-dataset", "verify-draft",
                "--input", dataset,
                "--manifest", verificationManifest,
                "--output", reportPath
            ],
            CancellationToken.None);
        verifyExit.Should().Be(2, cliError.ToString());
        var report = JsonSerializer.Deserialize<ExpertDatasetVerificationReport>(
            await File.ReadAllTextAsync(reportPath),
            CoordinatorJson.Options)!;
        report.AllPassed.Should().BeFalse();
        var unsupported = report.Results.Should().ContainSingle().Which;
        unsupported.Supported.Should().BeFalse();
        unsupported.Passed.Should().BeFalse();
        unsupported.UnsupportedReason.Should().Be("missing-supported-executable-profile");
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var output = workspace.PathFor("code-reviewed.jsonl");

        Func<Task> apply = async () => await ExpertModelDatasetReviewTools.ApplyReviewAsync(
            dataset,
            verificationManifest,
            reportPath,
            reviewManifest,
            output);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("cannot approve failed automated checks");
        File.Exists(output).Should().BeFalse();
    }

    [Theory]
    [InlineData(ExpertTaskKind.CodeGeneration)]
    [InlineData(ExpertTaskKind.CodeRepair)]
    public async Task Cli_Daxq_verification_approves_only_exact_compiled_and_tested_source(
        ExpertTaskKind taskKind)
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(workspace, taskKind, PassingDaxqSource);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [ExactSourceCheck(PassingDaxqSource)],
            CreateDaxqSpecification());
        var reportPath = workspace.PathFor($"daxq-{taskKind}-report.json");
        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        var cli = new CliApplication(cliOutput, cliError);

        var verifyExit = await cli.RunAsync(
            [
                "expert-dataset", "verify-draft",
                "--input", dataset,
                "--manifest", verificationManifest,
                "--output", reportPath
            ],
            CancellationToken.None);

        verifyExit.Should().Be(0, cliError.ToString());
        var report = JsonSerializer.Deserialize<ExpertDatasetVerificationReport>(
            await File.ReadAllTextAsync(reportPath),
            CoordinatorJson.Options)!;
        var executable = report.Results.Should().ContainSingle().Which.Executable;
        executable.Should().NotBeNull();
        executable!.CompileSucceeded.Should().BeTrue();
        executable.TestsPassed.Should().BeTrue();
        executable.DiagnosticCodes.Should().BeEmpty();
        executable.VectorCount.Should().Be(1);
        executable.CallbackCount.Should().Be(2);

        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var reviewedDataset = workspace.PathFor($"daxq-{taskKind}-reviewed.jsonl");
        var reviewExit = await cli.RunAsync(
            [
                "expert-dataset", "apply-review",
                "--input", dataset,
                "--verification-manifest", verificationManifest,
                "--verification-report", reportPath,
                "--review-manifest", reviewManifest,
                "--output", reviewedDataset
            ],
            CancellationToken.None);

        reviewExit.Should().Be(0, cliError.ToString());
        var validation = await ExpertModelDatasetTools.ValidateJsonLinesAsync(reviewedDataset);
        validation.IsValid.Should().BeTrue();
        validation.TrainingEligibleCount.Should().Be(0);
        var row = JsonNode.Parse((await File.ReadAllLinesAsync(reviewedDataset)).Single())!.AsObject();
        row["reviewStatus"]!.GetValue<string>().Should().Be("approved");
        row["useForTraining"]!.GetValue<bool>().Should().BeFalse();
        row["verification"]!["compileSucceeded"]!.GetValue<bool>().Should().BeTrue();
        row["verification"]!["testsPassed"]!.GetValue<bool>().Should().BeTrue();
        row["verification"]!["compileEvidence"]!.AsArray().Should().HaveCount(4);
        row["verification"]!["testEvidence"]!.AsArray().Should().HaveCount(5);
        row["rights"]!["mayTrain"]!.GetValue<bool>().Should().BeFalse();
        row["rights"]!["mayUploadToProvider"]!.GetValue<bool>().Should().BeFalse();
    }

    [Fact]
    public async Task Daxq_test_mismatch_cannot_be_human_approved()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(
            workspace,
            ExpertTaskKind.CodeGeneration,
            PassingDaxqSource);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [ExactSourceCheck(PassingDaxqSource)],
            CreateDaxqSpecification(mismatchedExpectation: true));
        var reportPath = workspace.PathFor("daxq-mismatch-report.json");
        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        var cli = new CliApplication(cliOutput, cliError);

        var verifyExit = await cli.RunAsync(
            [
                "expert-dataset", "verify-draft",
                "--input", dataset,
                "--manifest", verificationManifest,
                "--output", reportPath
            ],
            CancellationToken.None);

        verifyExit.Should().Be(2, cliError.ToString());
        var report = JsonSerializer.Deserialize<ExpertDatasetVerificationReport>(
            await File.ReadAllTextAsync(reportPath),
            CoordinatorJson.Options)!;
        report.AllPassed.Should().BeFalse();
        var executable = report.Results.Should().ContainSingle().Which.Executable!;
        executable.CompileSucceeded.Should().BeTrue();
        executable.TestsPassed.Should().BeFalse();
        executable.DiagnosticCodes.Should().Contain("DAXQ-VERIFY-SIGNAL-MISMATCH");
        var reviewManifest = await WriteReviewManifestAsync(
            workspace,
            dataset,
            verificationManifest,
            report,
            "approved");
        var reviewedDataset = workspace.PathFor("daxq-mismatch-reviewed.jsonl");

        var reviewExit = await cli.RunAsync(
            [
                "expert-dataset", "apply-review",
                "--input", dataset,
                "--verification-manifest", verificationManifest,
                "--verification-report", reportPath,
                "--review-manifest", reviewManifest,
                "--output", reviewedDataset
            ],
            CancellationToken.None);

        reviewExit.Should().Be(1);
        cliError.ToString().Should().Contain("cannot approve failed automated checks");
        File.Exists(reviewedDataset).Should().BeFalse();
    }

    [Fact]
    public async Task Daxq_verifier_enforces_real_callback_timeout_with_deterministic_evidence()
    {
        using var workspace = new TestWorkspace();
        var source = CreateTimeoutDaxqSource(5_000);
        source.Length.Should().BeLessThan(ExpertModelDatasetReviewTools.MaxExecutableSourceCharacters);
        var dataset = await CompileDraftAsync(
            workspace,
            ExpertTaskKind.CodeGeneration,
            source);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [ExactSourceCheck(source)],
            CreateTimeoutDaxqSpecification());
        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        var cli = new CliApplication(cliOutput, cliError);
        var reports = new List<ExpertDatasetVerificationReport>();

        foreach (var reportName in new[] { "daxq-timeout-a.json", "daxq-timeout-b.json" })
        {
            var reportPath = workspace.PathFor(reportName);
            var exitCode = await cli.RunAsync(
                [
                    "expert-dataset", "verify-draft",
                    "--input", dataset,
                    "--manifest", verificationManifest,
                    "--output", reportPath
                ],
                CancellationToken.None);

            exitCode.Should().Be(2, cliError.ToString());
            reports.Add(JsonSerializer.Deserialize<ExpertDatasetVerificationReport>(
                await File.ReadAllTextAsync(reportPath),
                CoordinatorJson.Options)!);
        }

        var first = reports[0].Results.Should().ContainSingle().Which.Executable!;
        var second = reports[1].Results.Should().ContainSingle().Which.Executable!;
        first.CompileSucceeded.Should().BeTrue();
        first.TestsPassed.Should().BeFalse();
        first.DiagnosticCodes.Should().Contain("DAXQ-VERIFY-FAULT-Timeout");
        second.DiagnosticCodes.Should().Contain("DAXQ-VERIFY-FAULT-Timeout");
        second.ExecutionTraceSha256.Should().Be(first.ExecutionTraceSha256);
    }

    [Fact]
    public async Task Daxq_verifier_rejects_static_initialization_without_executing_it()
    {
        using var workspace = new TestWorkspace();
        var markerPath = workspace.PathFor("must-not-be-created.txt");
        var escapedMarkerPath = markerPath.Replace("\"", "\"\"");
        var source = $$"""
            using DaxAlgo.Sdk;

            public sealed class UnsafeStrategy : IBacktestStrategy
            {
                static UnsafeStrategy()
                {
                    System.IO.File.WriteAllText(@"{{escapedMarkerPath}}", "executed");
                }

                public void OnBar(IStrategyContext context)
                {
                    context.Emit(SignalKind.Long, 1.0, 1);
                }
            }
            """;
        var dataset = await CompileDraftAsync(
            workspace,
            ExpertTaskKind.CodeGeneration,
            source);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [ExactSourceCheck(source)],
            CreateDaxqSpecification());
        var reportPath = workspace.PathFor("daxq-static-constructor-report.json");
        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        var cli = new CliApplication(cliOutput, cliError);

        var verifyExit = await cli.RunAsync(
            [
                "expert-dataset", "verify-draft",
                "--input", dataset,
                "--manifest", verificationManifest,
                "--output", reportPath
            ],
            CancellationToken.None);

        verifyExit.Should().Be(2, cliError.ToString());
        var report = JsonSerializer.Deserialize<ExpertDatasetVerificationReport>(
            await File.ReadAllTextAsync(reportPath),
            CoordinatorJson.Options)!;
        var executable = report.Results.Should().ContainSingle().Which.Executable!;
        executable.CompileSucceeded.Should().BeFalse();
        executable.TestsPassed.Should().BeFalse();
        executable.DiagnosticCodes.Should().NotBeEmpty();
        File.Exists(markerPath).Should().BeFalse();
    }

    [Fact]
    public async Task CodeReview_rows_cannot_request_the_Daxq_executable_profile()
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(
            workspace,
            ExpertTaskKind.CodeReview,
            PassingDaxqSource);
        var verificationManifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [ExactSourceCheck(PassingDaxqSource)],
            CreateDaxqSpecification());
        var reportPath = workspace.PathFor("daxq-code-review-report.json");

        Func<Task> verify = async () => await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            verificationManifest,
            reportPath);

        (await verify.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("CodeGeneration or CodeRepair");
        File.Exists(reportPath).Should().BeFalse();
    }

    [Fact]
    public async Task Executable_source_and_callback_bounds_match_worker_acceptance()
    {
        var maximumSource = PadDaxqSource(
            ExpertModelDatasetReviewTools.MaxExecutableSourceCharacters);
        await AssertExecutableManifestStopsAsync(
            maximumSource,
            CreateDaxqSpecification(),
            "requires the trusted executable-verifier worker");
        await AssertExecutableManifestStopsAsync(
            PadDaxqSource(ExpertModelDatasetReviewTools.MaxExecutableSourceCharacters + 1),
            CreateDaxqSpecification(),
            "source exceeds");
        await AssertExecutableManifestStopsAsync(
            PassingDaxqSource,
            CreateCallbackBoundSpecification(
                ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerExample),
            "requires the trusted executable-verifier worker");
        await AssertExecutableManifestStopsAsync(
            PassingDaxqSource,
            CreateCallbackBoundSpecification(
                ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerExample + 1),
            "callback executable bound");
    }

    [Fact]
    public async Task Worker_output_capture_rejects_the_first_character_beyond_its_bound()
    {
        const int limit = 1_024;
        var exact = await DaxqExpertDatasetExecutableVerifier.ReadBoundedTextAsync(
            new StringReader(new string('x', limit)),
            limit,
            "test output",
            CancellationToken.None);
        exact.Should().HaveLength(limit);

        Func<Task> oversized = async () => await DaxqExpertDatasetExecutableVerifier.ReadBoundedTextAsync(
            new StringReader(new string('x', limit + 1)),
            limit,
            "test output",
            CancellationToken.None);

        (await oversized.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exceeded its character bound");
    }

    [Fact]
    public async Task Windows_worker_job_allows_bounded_and_denies_oversized_allocation()
    {
        const long jobLimitBytes = 256L * 1024L * 1024L;
        var bounded = await RunJobAllocationProbeAsync(jobLimitBytes, 1L * 1024L * 1024L);
        bounded.ExitCode.Should().Be(0, bounded.StandardError);
        bounded.StandardOutput.Should().Be("allocated");

        var oversized = await RunJobAllocationProbeAsync(jobLimitBytes, 512L * 1024L * 1024L);
        oversized.ExitCode.Should().NotBe(0);
        oversized.StandardOutput.Should().NotContain("allocated");
    }

    [Fact]
    public async Task Executable_vectors_reject_noncanonical_frames_and_negative_effect_ids()
    {
        var basis = CreateDaxqSpecification();
        var basisVector = basis.Vectors.Single();
        var noncanonicalCallbacks = basisVector.Callbacks.ToArray();
        noncanonicalCallbacks[0] = noncanonicalCallbacks[0] with { TimeIndex = 1 };
        var noncanonical = basis with
        {
            Vectors = [basisVector with { Callbacks = noncanonicalCallbacks }]
        };

        var negativeSignalCallbacks = basisVector.Callbacks.ToArray();
        negativeSignalCallbacks[0] = negativeSignalCallbacks[0] with
        {
            Expected = new ExpertDatasetExpectedEffects
            {
                Signals = [new ExpertDatasetExpectedSignal(-1, 0.25, -1)]
            }
        };
        var negativeSignal = basis with
        {
            Vectors = [basisVector with { Callbacks = negativeSignalCallbacks }]
        };

        var negativeLogCallbacks = basisVector.Callbacks.ToArray();
        negativeLogCallbacks[0] = negativeLogCallbacks[0] with
        {
            Expected = new ExpertDatasetExpectedEffects
            {
                Logs = [new ExpertDatasetExpectedLog(-1, 1.0)]
            }
        };
        var negativeLog = basis with
        {
            Vectors = [basisVector with { Callbacks = negativeLogCallbacks }]
        };

        await AssertExecutableManifestStopsAsync(
            PassingDaxqSource,
            noncanonical,
            "bar callbacks");
        await AssertExecutableManifestStopsAsync(
            PassingDaxqSource,
            negativeSignal,
            "invalid expected signal");
        await AssertExecutableManifestStopsAsync(
            PassingDaxqSource,
            negativeLog,
            "invalid expected log");
    }

    private static async Task<string> CompileDraftAsync(
        TestWorkspace workspace,
        ExpertTaskKind taskKind = ExpertTaskKind.GeneralQuestionAnswering,
        string? assistantContent = null)
    {
        var authoring = workspace.PathFor("authoring");
        Directory.CreateDirectory(authoring);
        await File.WriteAllTextAsync(
            Path.Combine(authoring, "source.md"),
            "Project-owned bounded evidence for review.\n");
        var manifest = new ExpertModelDatasetDraftManifest
        {
            SchemaVersion = ExpertModelDatasetDraftAuthoringTools.SchemaVersion,
            Producer = "review-fixture-author",
            ProducedAtUtc = FixtureTime,
            Reviewer = "unassigned-independent-reviewer",
            CutoffUtc = FixtureTime,
            Provenance = "Project-owned dataset-review test fixture.",
            License = "Project-owned test fixture",
            Rights = new DatasetRights(true, true, false, false, false),
            RightsBasis = "Test-only private storage and evaluation.",
            Examples =
            [
                new ExpertModelDatasetDraftExample
                {
                    Id = "review-example-001",
                    TaskKind = taskKind,
                    Domains = [ExpertDomain.CSharp],
                    Messages =
                    [
                        new LlmMessage("system", "Answer within the reviewed evidence boundary."),
                        new LlmMessage("user", "State the safe conclusion."),
                        new LlmMessage(
                            "assistant",
                            assistantContent ??
                            "The bounded evidence supports research review, not a guaranteed profit claim.")
                    ],
                    ContaminationGroup = "review-example-family-001",
                    KnowledgeClass = "candidate-stable",
                    Sources =
                    [
                        new ExpertModelDatasetDraftSource
                        {
                            Id = "review-source-001",
                            Title = "Review fixture source",
                            ContentPath = "source.md",
                            Provenance = "Project-owned test fixture.",
                            License = "Project-owned test fixture",
                            RetrievedAtUtc = FixtureTime,
                            AvailableAtUtc = FixtureTime,
                            Uri = "repo://tests/review-source-001"
                        }
                    ],
                    Evidence = ["Awaiting independent automated and human review."]
                }
            ]
        };
        var manifestPath = Path.Combine(authoring, "draft.json");
        await File.WriteAllTextAsync(
            manifestPath,
            JsonSerializer.Serialize(manifest, CoordinatorJson.Options));
        var dataset = workspace.PathFor("draft.jsonl");
        await ExpertModelDatasetDraftAuthoringTools.CompileAsync(manifestPath, dataset);
        return dataset;
    }

    private static async Task<string> WriteVerificationManifestAsync(
        TestWorkspace workspace,
        string dataset,
        IReadOnlyList<ExpertDatasetTextCheck> checks,
        ExpertDatasetExecutableVerificationSpec? executableVerification = null)
    {
        var manifest = new ExpertDatasetVerificationManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.VerificationManifestSchemaVersion,
            DatasetSha256 = await Sha256Async(dataset),
            Verifiers =
            [
                new ExpertDatasetVerifierAssignment
                {
                    ExampleId = "review-example-001",
                    VerifierId = "review-text-verifier-v1",
                    Checks = checks,
                    ExecutableVerification = executableVerification
                }
            ]
        };
        var path = workspace.PathFor($"verification-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(manifest, CoordinatorJson.Options));
        return path;
    }

    private static ExpertDatasetTextCheck ExactSourceCheck(string source) =>
        new()
        {
            Id = "exact-source",
            Kind = "sha256",
            Value = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(source)))
                .ToLowerInvariant(),
            IgnoreCase = false
        };

    private static ExpertDatasetExecutableVerificationSpec CreateDaxqSpecification(
        bool mismatchedExpectation = false) =>
        new()
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            Vectors =
            [
                new ExpertDatasetNumericTestVector
                {
                    Id = "threshold-vector",
                    Bars =
                    [
                        new ExpertDatasetNumericBar(99.0, 100.0, 98.0, 99.0, 1_000.0),
                        new ExpertDatasetNumericBar(100.0, 102.0, 99.0, 101.0, 1_200.0)
                    ],
                    LaunchSeed = 7,
                    MaximumAbsoluteDifference = 0,
                    Callbacks =
                    [
                        new ExpertDatasetNumericCallback
                        {
                            Entrypoint = "bar",
                            TimeIndex = 0,
                            CompletedBarIndex = 0,
                            Expected = new ExpertDatasetExpectedEffects
                            {
                                Signals = [new ExpertDatasetExpectedSignal(-1, 0.25, 9)]
                            }
                        },
                        new ExpertDatasetNumericCallback
                        {
                            Entrypoint = "bar",
                            TimeIndex = 1,
                            CompletedBarIndex = 1,
                            Expected = new ExpertDatasetExpectedEffects
                            {
                                Signals =
                                [
                                    new ExpertDatasetExpectedSignal(
                                        1,
                                        mismatchedExpectation ? 0.5 : 0.75,
                                        17)
                                ]
                            }
                        }
                    ]
                }
            ]
        };

    private static ExpertDatasetExecutableVerificationSpec CreateCallbackBoundSpecification(
        int callbackCount) =>
        new()
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            Vectors = Enumerable.Range(
                    0,
                    (callbackCount + ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerVector - 1) /
                    ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerVector)
                .Select(vectorIndex =>
                {
                    var remaining = callbackCount -
                        vectorIndex * ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerVector;
                    var count = Math.Min(
                        remaining,
                        ExpertModelDatasetReviewTools.MaxExecutableCallbacksPerVector);
                    return new ExpertDatasetNumericTestVector
                    {
                        Id = $"callback-bound-{vectorIndex}",
                        Bars = Enumerable.Range(0, count)
                            .Select(_ => new ExpertDatasetNumericBar(
                                100.0,
                                102.0,
                                99.0,
                                101.0,
                                1_000.0))
                            .ToArray(),
                        LaunchSeed = 7,
                        MaximumAbsoluteDifference = 0,
                        Callbacks = Enumerable.Range(0, count)
                            .Select(index => new ExpertDatasetNumericCallback
                            {
                                Entrypoint = "bar",
                                TimeIndex = index,
                                CompletedBarIndex = index,
                                Expected = new ExpertDatasetExpectedEffects
                                {
                                    Signals = [new ExpertDatasetExpectedSignal(1, 0.75, 17)]
                                }
                            })
                            .ToArray()
                    };
                })
                .ToArray()
        };

    private static string CreateTimeoutDaxqSource(int indicatorCallCount)
    {
        var source = new System.Text.StringBuilder(
            "using DaxAlgo.Sdk;public sealed class Slow:IBacktestStrategy{public void OnBar(IStrategyContext c){double v=0;");
        for (var index = 0; index < indicatorCallCount; index++)
        {
            source.Append("v=c.Indicator(Ind.Sma,4096);");
        }
        source.Append(
            "if(v>=0)c.Emit(SignalKind.Long,0.5,1);else c.Emit(SignalKind.Short,0.5,1);}}");
        return source.ToString();
    }

    private static ExpertDatasetExecutableVerificationSpec CreateTimeoutDaxqSpecification() =>
        new()
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            Vectors =
            [
                new ExpertDatasetNumericTestVector
                {
                    Id = "timeout-vector",
                    Bars = Enumerable.Range(0, 4_096)
                        .Select(_ => new ExpertDatasetNumericBar(1.0, 1.0, 1.0, 1.0, 1.0))
                        .ToArray(),
                    LaunchSeed = 7,
                    MaximumAbsoluteDifference = 0,
                    Callbacks =
                    [
                        new ExpertDatasetNumericCallback
                        {
                            Entrypoint = "bar",
                            TimeIndex = 4_095,
                            CompletedBarIndex = 4_095,
                            Expected = new ExpertDatasetExpectedEffects
                            {
                                Signals = [new ExpertDatasetExpectedSignal(1, 0.5, 1)]
                            }
                        }
                    ]
                }
            ]
        };

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)>
        RunJobAllocationProbeAsync(long jobLimitBytes, long allocationBytes)
    {
        var powershellPath = Path.Combine(
            Environment.SystemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = powershellPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(
            string.Concat(
                "$null=[Console]::In.ReadLine();$ErrorActionPreference='Stop';try{",
                "$buffer=New-Object byte[] ",
                allocationBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ";[GC]::KeepAlive($buffer);[Console]::Out.Write('allocated');exit 0}",
                "catch{[Console]::Out.Write('blocked');exit 23}"));

        using var process = new Process { StartInfo = startInfo };
        process.Start().Should().BeTrue();
        using var job = DaxqExpertDatasetExecutableVerifier.WindowsWorkerJob.Create(jobLimitBytes);
        job.Assign(process);
        await process.StandardInput.WriteLineAsync("go");
        process.StandardInput.Close();
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        return (process.ExitCode, await outputTask, await errorTask);
    }

    private static string PadDaxqSource(int characterCount)
    {
        var prefix = string.Concat(PassingDaxqSource, "\n/*");
        const string suffix = "*/";
        return string.Concat(
            prefix,
            new string('x', characterCount - prefix.Length - suffix.Length),
            suffix);
    }

    private static async Task AssertExecutableManifestStopsAsync(
        string source,
        ExpertDatasetExecutableVerificationSpec specification,
        string expectedMessage)
    {
        using var workspace = new TestWorkspace();
        var dataset = await CompileDraftAsync(
            workspace,
            ExpertTaskKind.CodeGeneration,
            source);
        var manifest = await WriteVerificationManifestAsync(
            workspace,
            dataset,
            [ExactSourceCheck(source)],
            specification);
        var reportPath = workspace.PathFor("bounded-report.json");

        Func<Task> verify = async () => await ExpertModelDatasetReviewTools.VerifyAsync(
            dataset,
            manifest,
            reportPath);

        (await verify.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain(expectedMessage);
        File.Exists(reportPath).Should().BeFalse();
    }

    private static async Task<string> WriteReviewManifestAsync(
        TestWorkspace workspace,
        string dataset,
        string verificationManifest,
        ExpertDatasetVerificationReport report,
        string decision,
        DateTimeOffset? reviewedAtUtc = null)
    {
        var manifest = new ExpertDatasetReviewManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.ReviewManifestSchemaVersion,
            DatasetSha256 = await Sha256Async(dataset),
            VerificationManifestSha256 = await Sha256Async(verificationManifest),
            VerificationReportSha256 = report.ReportSha256,
            Reviewer = "independent-reviewer-001",
            ReviewBasis = "Independent fixture review of the exact bound answer and automated checks.",
            ReviewedAtUtc = reviewedAtUtc ?? FixtureTime,
            Decisions =
            [
                new ExpertDatasetReviewDecision
                {
                    ExampleId = "review-example-001",
                    Decision = decision,
                    Evidence = ["Reviewed the exact prompt, answer, source, and automated result."]
                }
            ]
        };
        var path = workspace.PathFor($"review-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(manifest, CoordinatorJson.Options));
        return path;
    }

    private static async Task<string> Sha256Async(string path)
    {
        var bytes = await File.ReadAllBytesAsync(path);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
