using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class ExpertModelDatasetReviewHandoffTests
{
    private const string ZeroSha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    private const string RightsEvidenceText =
        "The independent reviewer confirms candidate-row rights and retrieval-row restrictions.";
    private static readonly DateTimeOffset FixtureTime =
        new(2025, 1, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly DatasetRights BaseRights = new(true, true, false, false, false);
    private static readonly DatasetRights TrainingRights = new(true, true, true, true, false);
    private static readonly FailIfInvokedVerifier Verifier = new();

    [Fact]
    public async Task Prepare_and_apply_bind_exact_inputs_and_stop_before_receipt_authority()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);

        fixture.Package.SchemaVersion.Should().Be(ExpertModelDatasetReviewHandoffTools.PackageSchemaVersion);
        fixture.Package.PackageId.Should().Be(fixture.Preparation.PackageId);
        fixture.Package.Authority.Should().Be(NoAuthority());
        fixture.Package.Files.Select(item => item.Id).Should().Equal(
            "draft-dataset",
            "reviewed-dataset",
            "verification-manifest",
            "verification-report",
            "review-manifest",
            "evidence:review-brief");
        fixture.Package.Rows.Should().HaveCount(2);
        fixture.Package.Sources.Should().HaveCount(2);
        fixture.Package.DecisionTemplate.Reviewer.Should().BeEmpty();
        fixture.Package.DecisionTemplate.ReviewedAtUtc.Should().BeNull();
        fixture.Package.DecisionTemplate.Rows.Should().OnlyContain(item =>
            !item.Rights.MayTrain && !item.Rights.MayUploadToProvider && !item.UseForTraining);
        fixture.Package.DecisionTemplate.Sources.Should().OnlyContain(item =>
            !item.Rights.MayTrain && !item.Rights.MayUploadToProvider);
        fixture.Package.Rows.Should().OnlyContain(item =>
            item.VerificationEvidenceIdentities.Count > 0 && item.VerificationEvidenceSha256.Length == 64);

        var decision = CreateDecision(fixture);
        var decisionPath = await WriteDecisionAsync(workspace, "decision.json", decision);
        var outputPath = workspace.PathFor("rights-reviewed.jsonl");

        var result = await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            fixture.PackagePath,
            decisionPath,
            outputPath,
            Verifier);

        result.ExampleCount.Should().Be(2);
        result.RightsElevatedCount.Should().Be(1);
        result.TrainingRequestedCount.Should().Be(1);
        result.TrainingEligibleCount.Should().Be(0);
        result.PackageSha256.Should().Be(fixture.Preparation.PackageSha256);
        var output = await ExpertModelDatasetTools.LoadAndValidateAsync(outputPath, CancellationToken.None);
        output.Report.IsValid.Should().BeTrue();
        output.Report.TrainingEligibleCount.Should().Be(0);
        var candidate = output.Examples.Single(item => item.Id == "candidate-row");
        candidate.Rights.Should().Be(TrainingRights);
        candidate.UseForTraining.Should().BeTrue();
        candidate.Sources.Should().OnlyContain(item => item.Rights == TrainingRights);
        candidate.Verification.Evidence.Should().Contain($"reviewPackageSha256={result.PackageSha256}");
        candidate.Verification.Evidence.Should().Contain($"reviewDecisionSha256={result.DecisionSha256}");
        candidate.Verification.Evidence.Should().Contain(item =>
            item.StartsWith("reviewEvidenceSha256:rights-proof=", StringComparison.Ordinal));
        var retrieval = output.Examples.Single(item => item.Id == "retrieval-row");
        retrieval.Rights.Should().Be(BaseRights);
        retrieval.UseForTraining.Should().BeFalse();
        retrieval.Sources.Should().OnlyContain(item => item.Rights == BaseRights);
    }

    [Fact]
    public async Task Compile_decision_binds_the_exact_package_and_emits_a_canonical_non_authorizing_decision()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var expected = CreateDecision(fixture);
        var templatePath = workspace.PathFor("completed-template.json");
        var templatePreparation = await ExpertModelDatasetReviewHandoffTools.PrepareDecisionTemplateAsync(
            fixture.PackagePath,
            templatePath,
            Verifier);
        var preparedTemplate = JsonSerializer.Deserialize<ExpertDatasetIndependentReviewDecisionDraft>(
            await File.ReadAllBytesAsync(templatePath),
            CoordinatorJson.Options)!;
        await File.WriteAllBytesAsync(
            templatePath,
            ExpertModelDatasetReviewHandoffTools.SerializeCanonical(preparedTemplate with
            {
                Reviewer = expected.Reviewer,
                ReviewBasis = expected.ReviewBasis,
                ReviewedAtUtc = expected.ReviewedAtUtc,
                Rows = expected.Rows,
                Sources = expected.Sources
            }));
        var evidencePath = workspace.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);
        var decisionPath = workspace.PathFor("compiled-decision.json");

        var result = await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
            fixture.PackagePath,
            templatePath,
            [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
            decisionPath,
            Verifier);

        var decisionBytes = await File.ReadAllBytesAsync(decisionPath);
        var decision = JsonSerializer.Deserialize<ExpertDatasetIndependentReviewDecision>(
            decisionBytes,
            CoordinatorJson.Options)!;
        ExpertModelDatasetReviewHandoffTools.SerializeCanonical(decision).Should().Equal(decisionBytes);
        decision.Should().BeEquivalentTo(expected);
        decision.Authority.Should().Be(NoAuthority());
        result.DecisionId.Should().Be(decision.DecisionId);
        result.DecisionSha256.Should().Be(Sha256(decisionBytes));
        result.PackageSha256.Should().Be(fixture.Preparation.PackageSha256);
        result.ReviewedDatasetSha256.Should().Be(fixture.Package.ReviewedDatasetSha256);
        templatePreparation.PackageSha256.Should().Be(result.PackageSha256);
        result.RowCount.Should().Be(2);
        result.SourceCount.Should().Be(2);
        result.EvidenceFileCount.Should().Be(1);
        Directory.EnumerateDirectories(workspace.RootPath, ".compile-review-decision.*").Should().BeEmpty();
    }

    [Fact]
    public async Task Prepare_decision_template_emits_a_bound_safe_default_and_is_no_clobber()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var templatePath = workspace.PathFor("prepared-decision-template.json");

        var result = await ExpertModelDatasetReviewHandoffTools.PrepareDecisionTemplateAsync(
            fixture.PackagePath,
            templatePath,
            Verifier);

        var templateBytes = await File.ReadAllBytesAsync(templatePath);
        var template = JsonSerializer.Deserialize<ExpertDatasetIndependentReviewDecisionDraft>(
            templateBytes,
            CoordinatorJson.Options)!;
        ExpertModelDatasetReviewHandoffTools.SerializeCanonical(template).Should().Equal(templateBytes);
        template.SchemaVersion.Should().Be(ExpertModelDatasetReviewHandoffTools.DecisionDraftSchemaVersion);
        template.Status.Should().Be("unsigned-non-authorizing");
        template.Authority.Should().Be(NoAuthority());
        template.PackageId.Should().Be(fixture.Package.PackageId);
        template.PackageSha256.Should().Be(fixture.Preparation.PackageSha256);
        template.ReviewedDatasetSha256.Should().Be(fixture.Package.ReviewedDatasetSha256);
        template.Reviewer.Should().BeEmpty();
        template.ReviewBasis.Should().BeEmpty();
        template.ReviewedAtUtc.Should().BeNull();
        template.Rows.Should().OnlyContain(item =>
            item.EvidenceIds.Count == 0 &&
            !item.Rights.MayTrain &&
            !item.Rights.MayUploadToProvider &&
            !item.Rights.MayRedistribute &&
            !item.UseForTraining);
        template.Sources.Should().OnlyContain(item =>
            item.EvidenceIds.Count == 0 &&
            !item.Rights.MayTrain &&
            !item.Rights.MayUploadToProvider &&
            !item.Rights.MayRedistribute);
        result.PackageId.Should().Be(template.PackageId);
        result.PackageSha256.Should().Be(template.PackageSha256);
        result.RowCount.Should().Be(template.Rows.Count);
        result.SourceCount.Should().Be(template.Sources.Count);

        Func<Task> prepareAgain = async () =>
            await ExpertModelDatasetReviewHandoffTools.PrepareDecisionTemplateAsync(
                fixture.PackagePath,
                templatePath,
                Verifier);
        await prepareAgain.Should().ThrowAsync<CoordinatorValidationException>();
        (await File.ReadAllBytesAsync(templatePath)).Should().Equal(templateBytes);
        Directory.EnumerateDirectories(workspace.RootPath, ".prepare-review-decision-template.*")
            .Should().BeEmpty();
    }

    [Fact]
    public async Task Prepare_compile_and_apply_each_freshly_invoke_the_supported_executable_verifier()
    {
        using var workspace = new TestWorkspace();
        var verifier = new CountingExecutableVerifier();
        var reviewed = await CreateExecutableReviewedFixtureAsync(workspace, verifier);
        var beforePrepare = verifier.InvocationCount;

        var fixture = await PackageReviewedFixtureAsync(workspace, reviewed, verifier);

        verifier.InvocationCount.Should().Be(beforePrepare + 1);
        var decision = CreateDecision(fixture);
        var templatePath = workspace.PathFor("executable-template.json");
        var beforeTemplatePreparation = verifier.InvocationCount;
        await ExpertModelDatasetReviewHandoffTools.PrepareDecisionTemplateAsync(
            fixture.PackagePath,
            templatePath,
            verifier);
        verifier.InvocationCount.Should().Be(beforeTemplatePreparation + 1);
        await File.WriteAllBytesAsync(
            templatePath,
            ExpertModelDatasetReviewHandoffTools.SerializeCanonical(DraftFrom(decision)));
        var evidencePath = workspace.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);
        var decisionPath = workspace.PathFor("executable-decision.json");
        var beforeCompile = verifier.InvocationCount;

        await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
            fixture.PackagePath,
            templatePath,
            [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
            decisionPath,
            verifier);

        verifier.InvocationCount.Should().Be(beforeCompile + 1);
        var outputPath = workspace.PathFor("executable-rights-reviewed.jsonl");
        var beforeApply = verifier.InvocationCount;

        var result = await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            fixture.PackagePath,
            decisionPath,
            outputPath,
            verifier);

        verifier.InvocationCount.Should().Be(beforeApply + 1);
        result.ExampleCount.Should().Be(1);
        result.TrainingRequestedCount.Should().Be(1);
        result.TrainingEligibleCount.Should().Be(0);
        var output = await ExpertModelDatasetTools.LoadAndValidateAsync(outputPath, CancellationToken.None);
        output.Report.IsValid.Should().BeTrue();
        output.Examples.Should().ContainSingle(item =>
            item.TaskKind == ExpertTaskKind.CodeGeneration &&
            item.Verification.CompileSucceeded &&
            item.Verification.TestsPassed);
    }

    [Fact]
    public async Task Compile_decision_is_no_clobber_and_preserves_the_existing_output()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var decision = CreateDecision(fixture);
        var templatePath = await WriteDecisionDraftAsync(
            workspace,
            "completed-template.json",
            DraftFrom(decision));
        var evidencePath = workspace.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);
        var outputPath = workspace.PathFor("existing-decision.json");
        var sentinel = Encoding.UTF8.GetBytes("do-not-replace");
        await File.WriteAllBytesAsync(outputPath, sentinel);

        Func<Task> compile = async () => await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
            fixture.PackagePath,
            templatePath,
            [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
            outputPath,
            Verifier);

        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        (await File.ReadAllBytesAsync(outputPath)).Should().Equal(sentinel);
    }

    [Fact]
    public async Task Compile_decision_rejects_invalid_chronology_variants_without_publication()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var decision = CreateDecision(fixture);
        var evidencePath = workspace.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);
        var chronology = new[]
        {
            FixtureTime.AddSeconds(-1),
            new DateTimeOffset(2025, 1, 15, 13, 0, 0, TimeSpan.FromHours(1)),
            FixtureTime.AddMilliseconds(1),
            DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60)
        };

        for (var index = 0; index < chronology.Length; index++)
        {
            var template = DraftFrom(decision) with { ReviewedAtUtc = chronology[index] };
            var templatePath = await WriteDecisionDraftAsync(
                workspace,
                $"chronology-{index}.json",
                template);
            var outputPath = workspace.PathFor($"chronology-{index}-decision.json");
            Func<Task> compile = async () => await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
                fixture.PackagePath,
                templatePath,
                [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
                outputPath,
                Verifier);

            (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
                .Should().Contain("UTC whole seconds");
            File.Exists(outputPath).Should().BeFalse();
        }
    }

    [Fact]
    public async Task Compile_decision_rejects_a_bound_template_substituted_across_matching_packages()
    {
        using var workspaceA = new TestWorkspace();
        using var workspaceB = new TestWorkspace();
        var fixtureA = await CreatePackagedFixtureAsync(workspaceA);
        var reviewedB = await CreateReviewedFixtureAsync(workspaceB);
        await File.AppendAllTextAsync(reviewedB.HandoffEvidencePath, " Package B evidence.");
        var fixtureB = await PackageReviewedFixtureAsync(workspaceB, reviewedB, Verifier);
        fixtureB.Package.PackageId.Should().NotBe(fixtureA.Package.PackageId);
        fixtureB.Package.Rows.Select(item => item.ExampleId)
            .Should().Equal(fixtureA.Package.Rows.Select(item => item.ExampleId));
        fixtureB.Package.Sources.Select(item => (item.ExampleId, item.SourceId))
            .Should().Equal(fixtureA.Package.Sources.Select(item => (item.ExampleId, item.SourceId)));

        var templatePath = await WriteDecisionDraftAsync(
            workspaceA,
            "package-a-template.json",
            DraftFrom(CreateDecision(fixtureA)));
        var evidencePath = workspaceA.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);
        var outputPath = workspaceB.PathFor("substituted-decision.json");

        Func<Task> compile = async () => await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
            fixtureB.PackagePath,
            templatePath,
            [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
            outputPath,
            Verifier);

        (await compile.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("not bound to the exact package");
        File.Exists(outputPath).Should().BeFalse();
    }

    [Fact]
    public async Task Compile_decision_rejects_wrong_template_version_status_authority_and_bindings()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var baseline = DraftFrom(CreateDecision(fixture));
        var variants = new[]
        {
            baseline with { SchemaVersion = "daxalgo.expert-model-independent-review-decision-draft/v2" },
            baseline with { Status = "reviewed-authorizing" },
            baseline with { Authority = baseline.Authority with { ReceiptAuthority = true } },
            baseline with { PackageId = $"review-package-{new string('a', 64)}" },
            baseline with { PackageSha256 = new string('b', 64) },
            baseline with { ReviewedDatasetSha256 = new string('c', 64) }
        };
        var evidencePath = workspace.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);

        for (var index = 0; index < variants.Length; index++)
        {
            var templatePath = await WriteDecisionDraftAsync(
                workspace,
                $"invalid-bound-template-{index}.json",
                variants[index]);
            var outputPath = workspace.PathFor($"invalid-bound-decision-{index}.json");
            Func<Task> compile = async () => await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
                fixture.PackagePath,
                templatePath,
                [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
                outputPath,
                Verifier);

            await compile.Should().ThrowAsync<CoordinatorValidationException>();
            File.Exists(outputPath).Should().BeFalse();
        }
    }

    [Fact]
    public async Task Compile_decision_accepts_editor_json_and_rejects_duplicate_or_unmapped_properties()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var draft = DraftFrom(CreateDecision(fixture));
        var editorBytes = SerializeEditorJson(draft);
        editorBytes.Should().NotEqual(ExpertModelDatasetReviewHandoffTools.SerializeCanonical(draft));
        var evidencePath = workspace.PathFor("rights-proof.txt");
        await File.WriteAllTextAsync(evidencePath, RightsEvidenceText);
        var editorPath = workspace.PathFor("editor-template.json");
        await File.WriteAllBytesAsync(editorPath, editorBytes);
        var decisionPath = workspace.PathFor("editor-decision.json");

        await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
            fixture.PackagePath,
            editorPath,
            [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
            decisionPath,
            Verifier);

        File.Exists(decisionPath).Should().BeTrue();
        var invalidInputs = new[]
        {
            InsertRootJsonProperty(
                editorBytes,
                $"\"schemaVersion\":\"{ExpertModelDatasetReviewHandoffTools.DecisionDraftSchemaVersion}\""),
            InsertRootJsonProperty(editorBytes, "\"unexpectedAuthority\":true"),
            InsertAfterFirstJsonToken(editorBytes, "\"mayStore\": true", "\"mayStore\": true"),
            InsertAfterFirstJsonToken(editorBytes, "\"mayStore\": true", "\"unexpectedRight\": true"),
            RemoveJsonProperty(editorBytes, "reviewedAtUtc"),
            RemoveJsonProperty(editorBytes, "receiptAuthority"),
            RemoveJsonProperty(editorBytes, "useForTraining"),
            RemoveJsonProperty(editorBytes, "mayStore")
        };
        for (var index = 0; index < invalidInputs.Length; index++)
        {
            var invalidPath = workspace.PathFor($"invalid-editor-template-{index}.json");
            await File.WriteAllBytesAsync(invalidPath, invalidInputs[index]);
            var invalidOutput = workspace.PathFor($"invalid-editor-decision-{index}.json");
            Func<Task> compile = async () => await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
                fixture.PackagePath,
                invalidPath,
                [new ExpertDatasetReviewHandoffEvidenceInput("rights-proof", evidencePath)],
                invalidOutput,
                Verifier);

            await compile.Should().ThrowAsync<CoordinatorValidationException>();
            File.Exists(invalidOutput).Should().BeFalse();
        }
    }

    [Fact]
    public async Task Package_and_decision_evidence_must_be_nonempty()
    {
        using var packageWorkspace = new TestWorkspace();
        var reviewed = await CreateReviewedFixtureAsync(packageWorkspace);
        var emptyPackageEvidence = packageWorkspace.PathFor("empty-package-evidence.txt");
        await File.WriteAllBytesAsync(emptyPackageEvidence, []);
        var packagePath = packageWorkspace.PathFor("empty-evidence-package.json");
        Func<Task> prepare = async () => await ExpertModelDatasetReviewHandoffTools.PrepareAsync(
            reviewed.DraftPath,
            reviewed.ReviewedPath,
            reviewed.VerificationManifestPath,
            reviewed.VerificationReportPath,
            reviewed.ReviewManifestPath,
            [new ExpertDatasetReviewHandoffEvidenceInput("empty-proof", emptyPackageEvidence)],
            packagePath,
            Verifier);
        await prepare.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(packagePath).Should().BeFalse();

        using var decisionWorkspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(decisionWorkspace);
        var decision = CreateDecision(fixture);
        var templatePath = await WriteDecisionDraftAsync(
            decisionWorkspace,
            "completed-template.json",
            DraftFrom(decision));
        var emptyDecisionEvidence = decisionWorkspace.PathFor("empty-decision-evidence.txt");
        await File.WriteAllBytesAsync(emptyDecisionEvidence, []);
        var decisionPath = decisionWorkspace.PathFor("empty-evidence-decision.json");
        Func<Task> compile = async () => await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
            fixture.PackagePath,
            templatePath,
            [new ExpertDatasetReviewHandoffEvidenceInput("empty-proof", emptyDecisionEvidence)],
            decisionPath,
            Verifier);
        await compile.Should().ThrowAsync<CoordinatorValidationException>();
        File.Exists(decisionPath).Should().BeFalse();
    }

    [Fact]
    public async Task Reserved_review_anchor_prefixes_are_rejected_before_package_publication()
    {
        foreach (var anchor in new[]
                 {
                     "reviewPackageSha256=preexisting",
                     "reviewDecisionSha256=preexisting",
                     "reviewEvidenceSha256:preexisting=hash"
                 })
        {
            using var workspace = new TestWorkspace();
            var fixture = await CreateReviewedFixtureAsync(workspace, anchor);
            var packagePath = workspace.PathFor("reserved-anchor-package.json");
            Func<Task> prepare = async () => await ExpertModelDatasetReviewHandoffTools.PrepareAsync(
                fixture.DraftPath,
                fixture.ReviewedPath,
                fixture.VerificationManifestPath,
                fixture.VerificationReportPath,
                fixture.ReviewManifestPath,
                [new ExpertDatasetReviewHandoffEvidenceInput("review-brief", fixture.HandoffEvidencePath)],
                packagePath,
                Verifier);

            (await prepare.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
                .Should().Contain("reserved independent-review evidence anchor");
            File.Exists(packagePath).Should().BeFalse();
            Directory.EnumerateDirectories(workspace.RootPath, ".prepare-review-handoff.*").Should().BeEmpty();
        }
    }

    [Fact]
    public void Staging_cleanup_is_complete_and_fails_closed_when_a_child_is_locked()
    {
        using var workspace = new TestWorkspace();
        var cleanable = workspace.PathFor($".prepare-review-handoff.{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(cleanable, "nested"));
        File.WriteAllText(Path.Combine(cleanable, "nested", "file.txt"), "temporary");

        ExpertModelDatasetReviewHandoffTools.DeleteStagingDirectory(cleanable);

        Directory.Exists(cleanable).Should().BeFalse();

        var locked = workspace.PathFor($".compile-review-decision.{Guid.NewGuid():N}");
        Directory.CreateDirectory(locked);
        var lockedPath = Path.Combine(locked, "locked.tmp");
        using (var stream = new FileStream(
                   lockedPath,
                   FileMode.CreateNew,
                   FileAccess.ReadWrite,
                   FileShare.None))
        {
            Action cleanup = () => ExpertModelDatasetReviewHandoffTools.DeleteStagingDirectory(locked);
            cleanup.Should().Throw<CoordinatorValidationException>()
                .WithMessage("*no output was published*");
            Directory.Exists(locked).Should().BeTrue();
        }
        ExpertModelDatasetReviewHandoffTools.DeleteStagingDirectory(locked);
        Directory.Exists(locked).Should().BeFalse();
    }

    [Fact]
    public async Task Prepare_rejects_a_reviewed_corpus_that_is_not_the_fresh_replay()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreateReviewedFixtureAsync(workspace);
        await File.AppendAllTextAsync(fixture.ReviewedPath, "\n");
        var packagePath = workspace.PathFor("mutated-package.json");

        Func<Task> prepare = async () => await ExpertModelDatasetReviewHandoffTools.PrepareAsync(
            fixture.DraftPath,
            fixture.ReviewedPath,
            fixture.VerificationManifestPath,
            fixture.VerificationReportPath,
            fixture.ReviewManifestPath,
            [new ExpertDatasetReviewHandoffEvidenceInput("review-brief", fixture.HandoffEvidencePath)],
            packagePath,
            Verifier);

        (await prepare.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("fresh review replay");
        File.Exists(packagePath).Should().BeFalse();
    }

    [Fact]
    public async Task Apply_rejects_a_self_consistent_package_content_mutation_before_decision_use()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var reviewedIndex = fixture.Package.Files
            .Select((item, index) => (item, index))
            .Single(pair => pair.item.Id == "reviewed-dataset").index;
        var reviewedFile = fixture.Package.Files[reviewedIndex];
        var mutatedBytes = Convert.FromBase64String(reviewedFile.ContentBase64).Concat([(byte)'\n']).ToArray();
        var files = fixture.Package.Files.ToArray();
        files[reviewedIndex] = reviewedFile with
        {
            SizeBytes = mutatedBytes.LongLength,
            Sha256 = Sha256(mutatedBytes),
            ContentBase64 = Convert.ToBase64String(mutatedBytes)
        };
        var mutatedPackage = fixture.Package with
        {
            PackageId = ZeroSha256,
            ReviewedDatasetSha256 = Sha256(mutatedBytes),
            Files = files
        };
        mutatedPackage = mutatedPackage with
        {
            PackageId = ExpertModelDatasetReviewHandoffTools.ComputePackageId(mutatedPackage)
        };
        var packagePath = workspace.PathFor("mutated-package.json");
        await File.WriteAllBytesAsync(
            packagePath,
            ExpertModelDatasetReviewHandoffTools.SerializeCanonical(mutatedPackage));
        var decisionPath = await WriteDecisionAsync(workspace, "decision.json", CreateDecision(fixture));
        var outputPath = workspace.PathFor("output.jsonl");

        Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            packagePath,
            decisionPath,
            outputPath,
            Verifier);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("fresh review replay");
        File.Exists(outputPath).Should().BeFalse();
    }

    [Fact]
    public async Task Apply_rejects_noncanonical_package_bytes()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var packagePath = workspace.PathFor("noncanonical-package.json");
        var canonical = await File.ReadAllBytesAsync(fixture.PackagePath);
        await File.WriteAllBytesAsync(packagePath, canonical.Concat([(byte)'\n']).ToArray());
        var decisionPath = await WriteDecisionAsync(workspace, "decision.json", CreateDecision(fixture));

        Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            packagePath,
            decisionPath,
            workspace.PathFor("output.jsonl"),
            Verifier);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("canonical JSON");
    }

    [Fact]
    public async Task Apply_rejects_wrong_incomplete_duplicate_and_unknown_decision_inventories()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var baseline = CreateDecision(fixture);
        var row0 = baseline.Rows[0];
        var source0 = baseline.Sources[0];
        var cases = new ExpertDatasetIndependentReviewDecision[]
        {
            baseline with { PackageSha256 = new string('a', 64) },
            baseline with { Rows = baseline.Rows.Take(1).ToArray() },
            baseline with { Rows = [row0, row0] },
            baseline with { Rows = [row0 with { ExampleId = "unknown-row" }, baseline.Rows[1]] },
            baseline with { Sources = baseline.Sources.Take(1).ToArray() },
            baseline with { Sources = [source0, source0] },
            baseline with
            {
                Sources = [source0 with { SourceId = "unknown-source" }, baseline.Sources[1]]
            }
        };

        for (var index = 0; index < cases.Length; index++)
        {
            var decision = Reidentify(cases[index]);
            var decisionPath = await WriteDecisionAsync(workspace, $"invalid-{index}.json", decision);
            var outputPath = workspace.PathFor($"invalid-{index}.jsonl");
            Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
                fixture.PackagePath,
                decisionPath,
                outputPath,
                Verifier);

            await apply.Should().ThrowAsync<CoordinatorValidationException>();
            File.Exists(outputPath).Should().BeFalse();
        }
    }

    [Fact]
    public async Task Apply_keeps_retrieval_only_rows_non_training_even_with_complete_source_rights()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var decision = CreateDecision(fixture);
        var rows = decision.Rows.Select(item => item.ExampleId == "retrieval-row"
            ? item with { Rights = TrainingRights, UseForTraining = true }
            : item).ToArray();
        var sources = decision.Sources.Select(item => item.ExampleId == "retrieval-row"
            ? item with { Rights = TrainingRights }
            : item).ToArray();
        decision = Reidentify(decision with { Rows = rows, Sources = sources });
        var decisionPath = await WriteDecisionAsync(workspace, "retrieval-training.json", decision);

        Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            fixture.PackagePath,
            decisionPath,
            workspace.PathFor("output.jsonl"),
            Verifier);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("approved, verified, candidate-stable development rows");
    }

    [Fact]
    public async Task Apply_rejects_any_mutated_downstream_authority()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var decision = CreateDecision(fixture);
        decision = Reidentify(decision with
        {
            Authority = decision.Authority with { ReceiptAuthority = true }
        });
        var decisionPath = await WriteDecisionAsync(workspace, "authorizing-decision.json", decision);
        var outputPath = workspace.PathFor("output.jsonl");

        Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            fixture.PackagePath,
            decisionPath,
            outputPath,
            Verifier);

        (await apply.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("all downstream authority false");
        File.Exists(outputPath).Should().BeFalse();
    }

    [Fact]
    public async Task Apply_enforces_upload_implies_training_and_exact_source_closure()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var baseline = CreateDecision(fixture);
        var uploadWithoutTrainingRows = baseline.Rows.Select(item => item.ExampleId == "candidate-row"
            ? item with { Rights = item.Rights with { MayTrain = false }, UseForTraining = false }
            : item).ToArray();
        var sourceClosure = baseline.Sources.Select(item => item.ExampleId == "candidate-row"
            ? item with { Rights = item.Rights with { MayUploadToProvider = false } }
            : item).ToArray();
        var cases = new[]
        {
            Reidentify(baseline with { Rows = uploadWithoutTrainingRows }),
            Reidentify(baseline with { Sources = sourceClosure })
        };

        for (var index = 0; index < cases.Length; index++)
        {
            var decisionPath = await WriteDecisionAsync(workspace, $"closure-{index}.json", cases[index]);
            Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
                fixture.PackagePath,
                decisionPath,
                workspace.PathFor($"closure-{index}.jsonl"),
                Verifier);

            await apply.Should().ThrowAsync<CoordinatorValidationException>();
        }
    }

    [Fact]
    public async Task Apply_rejects_mutated_or_unreferenced_immutable_decision_evidence()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var baseline = CreateDecision(fixture);
        var evidence = baseline.EvidenceFiles[0];
        var mutatedEvidence = evidence with
        {
            ContentBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("changed evidence"))
        };
        var unusedBytes = Encoding.UTF8.GetBytes("unused evidence");
        var unusedEvidence = new ExpertDatasetIndependentReviewEvidenceFile(
            "unused-proof",
            "unused.txt",
            unusedBytes.LongLength,
            Sha256(unusedBytes),
            Convert.ToBase64String(unusedBytes));
        var cases = new[]
        {
            Reidentify(baseline with { EvidenceFiles = [mutatedEvidence] }),
            Reidentify(baseline with { EvidenceFiles = [evidence, unusedEvidence] })
        };

        for (var index = 0; index < cases.Length; index++)
        {
            var decisionPath = await WriteDecisionAsync(workspace, $"evidence-{index}.json", cases[index]);
            Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
                fixture.PackagePath,
                decisionPath,
                workspace.PathFor($"evidence-{index}.jsonl"),
                Verifier);

            await apply.Should().ThrowAsync<CoordinatorValidationException>();
        }
    }

    [Fact]
    public async Task Apply_is_no_clobber_and_preserves_the_existing_output()
    {
        using var workspace = new TestWorkspace();
        var fixture = await CreatePackagedFixtureAsync(workspace);
        var decisionPath = await WriteDecisionAsync(workspace, "decision.json", CreateDecision(fixture));
        var outputPath = workspace.PathFor("existing.jsonl");
        var sentinel = Encoding.UTF8.GetBytes("do-not-replace");
        await File.WriteAllBytesAsync(outputPath, sentinel);

        Func<Task> apply = async () => await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
            fixture.PackagePath,
            decisionPath,
            outputPath,
            Verifier);

        await apply.Should().ThrowAsync<CoordinatorValidationException>();
        (await File.ReadAllBytesAsync(outputPath)).Should().Equal(sentinel);
    }

    private static async Task<PackagedFixture> CreatePackagedFixtureAsync(TestWorkspace workspace)
    {
        var reviewed = await CreateReviewedFixtureAsync(workspace);
        return await PackageReviewedFixtureAsync(workspace, reviewed, Verifier);
    }

    private static async Task<PackagedFixture> PackageReviewedFixtureAsync(
        TestWorkspace workspace,
        ReviewedFixture reviewed,
        IExpertDatasetExecutableVerifier verifier)
    {
        var packagePath = workspace.PathFor("review-package.json");
        var preparation = await ExpertModelDatasetReviewHandoffTools.PrepareAsync(
            reviewed.DraftPath,
            reviewed.ReviewedPath,
            reviewed.VerificationManifestPath,
            reviewed.VerificationReportPath,
            reviewed.ReviewManifestPath,
            [new ExpertDatasetReviewHandoffEvidenceInput("review-brief", reviewed.HandoffEvidencePath)],
            packagePath,
            verifier);
        var packageBytes = await File.ReadAllBytesAsync(packagePath);
        var package = JsonSerializer.Deserialize<ExpertDatasetIndependentReviewPackage>(
            packageBytes,
            CoordinatorJson.Options)!;
        ExpertModelDatasetReviewHandoffTools.SerializeCanonical(package).Should().Equal(packageBytes);
        return new PackagedFixture(reviewed, packagePath, preparation, package, packageBytes);
    }

    private static async Task<ReviewedFixture> CreateReviewedFixtureAsync(
        TestWorkspace workspace,
        string? additionalCandidateEvidence = null)
    {
        var authoringDirectory = workspace.PathFor("authoring");
        Directory.CreateDirectory(authoringDirectory);
        await File.WriteAllTextAsync(
            Path.Combine(authoringDirectory, "candidate.md"),
            "Candidate-stable project evidence.");
        await File.WriteAllTextAsync(
            Path.Combine(authoringDirectory, "retrieval.md"),
            "Retrieval-only project evidence.");
        var manifest = new ExpertModelDatasetDraftManifest
        {
            SchemaVersion = ExpertModelDatasetDraftAuthoringTools.SchemaVersion,
            Producer = "review-handoff-fixture",
            ProducedAtUtc = FixtureTime,
            Reviewer = "unassigned-independent-reviewer",
            CutoffUtc = FixtureTime,
            Provenance = "Project-owned review-handoff fixture.",
            License = "Project-owned test fixture",
            Rights = BaseRights,
            RightsBasis = "Storage and evaluation only until independent rights review.",
            Examples =
            [
                DraftExample(
                    "candidate-row",
                    "candidate-source",
                    "candidate.md",
                    "candidate-stable",
                    "The bounded candidate evidence supports this test conclusion.",
                    additionalCandidateEvidence),
                DraftExample(
                    "retrieval-row",
                    "retrieval-source",
                    "retrieval.md",
                    "retrieval-only",
                    "The bounded retrieval evidence supports lookup only.")
            ]
        };
        var authoringPath = Path.Combine(authoringDirectory, "draft.json");
        await File.WriteAllTextAsync(
            authoringPath,
            JsonSerializer.Serialize(manifest, CoordinatorJson.Options));
        var draftPath = workspace.PathFor("draft.jsonl");
        await ExpertModelDatasetDraftAuthoringTools.CompileAsync(authoringPath, draftPath);

        var verificationManifest = new ExpertDatasetVerificationManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.VerificationManifestSchemaVersion,
            DatasetSha256 = Sha256(await File.ReadAllBytesAsync(draftPath)),
            Verifiers =
            [
                VerificationAssignment("candidate-row", "candidate"),
                VerificationAssignment("retrieval-row", "retrieval")
            ]
        };
        var verificationManifestPath = workspace.PathFor("verification-manifest.json");
        await File.WriteAllTextAsync(
            verificationManifestPath,
            JsonSerializer.Serialize(verificationManifest, CoordinatorJson.Options));
        var verificationReportPath = workspace.PathFor("verification-report.json");
        var report = await ExpertModelDatasetReviewTools.VerifyWithExecutableVerifierAsync(
            draftPath,
            verificationManifestPath,
            verificationReportPath,
            Verifier);

        var reviewManifest = new ExpertDatasetReviewManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.ReviewManifestSchemaVersion,
            DatasetSha256 = Sha256(await File.ReadAllBytesAsync(draftPath)),
            VerificationManifestSha256 = Sha256(await File.ReadAllBytesAsync(verificationManifestPath)),
            VerificationReportSha256 = report.ReportSha256,
            Reviewer = "independent-content-reviewer",
            ReviewBasis = "Reviewed both exact prompts, answers, sources, and automated checks.",
            ReviewedAtUtc = FixtureTime,
            Decisions =
            [
                ReviewDecision("candidate-row"),
                ReviewDecision("retrieval-row")
            ]
        };
        var reviewManifestPath = workspace.PathFor("review-manifest.json");
        await File.WriteAllTextAsync(
            reviewManifestPath,
            JsonSerializer.Serialize(reviewManifest, CoordinatorJson.Options));
        var reviewedPath = workspace.PathFor("reviewed.jsonl");
        await ExpertModelDatasetReviewTools.ApplyReviewWithExecutableVerifierAsync(
            draftPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            reviewedPath,
            Verifier);
        var handoffEvidencePath = workspace.PathFor("review-brief.txt");
        await File.WriteAllTextAsync(
            handoffEvidencePath,
            "Independent reviewer must confirm exact rights and keep downstream authority denied.");
        return new ReviewedFixture(
            draftPath,
            reviewedPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            handoffEvidencePath);
    }

    private static async Task<ReviewedFixture> CreateExecutableReviewedFixtureAsync(
        TestWorkspace workspace,
        CountingExecutableVerifier verifier)
    {
        const string source = """
            using DaxAlgo.Sdk;

            public sealed class HandoffStrategy : IBacktestStrategy
            {
                public void OnBar(IStrategyContext context)
                {
                    context.Emit(SignalKind.Long, 0.75, 17);
                }
            }
            """;
        var authoringDirectory = workspace.PathFor("executable-authoring");
        Directory.CreateDirectory(authoringDirectory);
        await File.WriteAllTextAsync(
            Path.Combine(authoringDirectory, "source.md"),
            "Project-owned executable verification fixture.");
        var manifest = new ExpertModelDatasetDraftManifest
        {
            SchemaVersion = ExpertModelDatasetDraftAuthoringTools.SchemaVersion,
            Producer = "review-handoff-executable-fixture",
            ProducedAtUtc = FixtureTime,
            Reviewer = "unassigned-independent-reviewer",
            CutoffUtc = FixtureTime,
            Provenance = "Project-owned executable review-handoff fixture.",
            License = "Project-owned test fixture",
            Rights = BaseRights,
            RightsBasis = "Storage and evaluation only until independent rights review.",
            Examples =
            [
                new ExpertModelDatasetDraftExample
                {
                    Id = "code-row",
                    TaskKind = ExpertTaskKind.CodeGeneration,
                    Domains = [ExpertDomain.CSharp],
                    Messages =
                    [
                        new LlmMessage("system", "Return the bounded DaxQ strategy source."),
                        new LlmMessage("user", "Emit one deterministic long signal."),
                        new LlmMessage("assistant", source)
                    ],
                    ContaminationGroup = "code-row-family",
                    KnowledgeClass = "candidate-stable",
                    Sources =
                    [
                        new ExpertModelDatasetDraftSource
                        {
                            Id = "code-source",
                            Title = "Executable fixture source",
                            ContentPath = "source.md",
                            Provenance = "Project-owned test evidence.",
                            License = "Project-owned test fixture",
                            RetrievedAtUtc = FixtureTime,
                            AvailableAtUtc = FixtureTime,
                            Uri = "repo://tests/code-source"
                        }
                    ],
                    Evidence = ["Awaiting executable and independent human review."]
                }
            ]
        };
        var authoringPath = Path.Combine(authoringDirectory, "draft.json");
        await File.WriteAllTextAsync(
            authoringPath,
            JsonSerializer.Serialize(manifest, CoordinatorJson.Options));
        var draftPath = workspace.PathFor("draft.jsonl");
        await ExpertModelDatasetDraftAuthoringTools.CompileAsync(authoringPath, draftPath);

        var executable = new ExpertDatasetExecutableVerificationSpec
        {
            Profile = ExpertModelDatasetReviewTools.DaxqExecutableProfile,
            Vectors =
            [
                new ExpertDatasetNumericTestVector
                {
                    Id = "long-signal-vector",
                    Bars =
                    [
                        new ExpertDatasetNumericBar(99, 101, 98, 100, 1_000),
                        new ExpertDatasetNumericBar(100, 102, 99, 101, 1_200)
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
                            Bid = 0,
                            Ask = 0,
                            Last = 0,
                            Volume = 0,
                            Expected = new ExpertDatasetExpectedEffects
                            {
                                Signals = [new ExpertDatasetExpectedSignal(1, 0.75, 17)]
                            }
                        }
                    ]
                }
            ]
        };
        var verificationManifest = new ExpertDatasetVerificationManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.VerificationManifestSchemaVersion,
            DatasetSha256 = Sha256(await File.ReadAllBytesAsync(draftPath)),
            Verifiers =
            [
                new ExpertDatasetVerifierAssignment
                {
                    ExampleId = "code-row",
                    VerifierId = "counting-executable-verifier-v1",
                    Checks =
                    [
                        new ExpertDatasetTextCheck
                        {
                            Id = "exact-source",
                            Kind = "sha256",
                            Value = Sha256(Encoding.UTF8.GetBytes(source)),
                            IgnoreCase = false
                        }
                    ],
                    ExecutableVerification = executable
                }
            ]
        };
        var verificationManifestPath = workspace.PathFor("verification-manifest.json");
        await File.WriteAllTextAsync(
            verificationManifestPath,
            JsonSerializer.Serialize(verificationManifest, CoordinatorJson.Options));
        var verificationReportPath = workspace.PathFor("verification-report.json");
        var report = await ExpertModelDatasetReviewTools.VerifyWithExecutableVerifierAsync(
            draftPath,
            verificationManifestPath,
            verificationReportPath,
            verifier);
        var reviewManifest = new ExpertDatasetReviewManifest
        {
            SchemaVersion = ExpertModelDatasetReviewTools.ReviewManifestSchemaVersion,
            DatasetSha256 = Sha256(await File.ReadAllBytesAsync(draftPath)),
            VerificationManifestSha256 = Sha256(await File.ReadAllBytesAsync(verificationManifestPath)),
            VerificationReportSha256 = report.ReportSha256,
            Reviewer = "independent-executable-reviewer",
            ReviewBasis = "Reviewed exact source, executable specification, and deterministic result.",
            ReviewedAtUtc = FixtureTime,
            Decisions =
            [
                new ExpertDatasetReviewDecision
                {
                    ExampleId = "code-row",
                    Decision = "approved",
                    Evidence = ["Reviewed exact source and fresh executable verification result."]
                }
            ]
        };
        var reviewManifestPath = workspace.PathFor("review-manifest.json");
        await File.WriteAllTextAsync(
            reviewManifestPath,
            JsonSerializer.Serialize(reviewManifest, CoordinatorJson.Options));
        var reviewedPath = workspace.PathFor("reviewed.jsonl");
        await ExpertModelDatasetReviewTools.ApplyReviewWithExecutableVerifierAsync(
            draftPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            reviewedPath,
            verifier);
        var handoffEvidencePath = workspace.PathFor("review-brief.txt");
        await File.WriteAllTextAsync(
            handoffEvidencePath,
            "Independent reviewer must confirm executable rights without downstream authority.");
        return new ReviewedFixture(
            draftPath,
            reviewedPath,
            verificationManifestPath,
            verificationReportPath,
            reviewManifestPath,
            handoffEvidencePath);
    }

    private static ExpertModelDatasetDraftExample DraftExample(
        string rowId,
        string sourceId,
        string contentPath,
        string knowledgeClass,
        string assistantContent,
        string? additionalEvidence = null) => new()
        {
            Id = rowId,
            TaskKind = ExpertTaskKind.GeneralQuestionAnswering,
            Domains = [ExpertDomain.DaxAlgoArchitecture],
            Messages =
            [
                new LlmMessage("system", "Answer only from bounded project evidence."),
                new LlmMessage("user", $"State the bounded conclusion for {rowId}."),
                new LlmMessage("assistant", assistantContent)
            ],
            ContaminationGroup = $"{rowId}-family",
            KnowledgeClass = knowledgeClass,
            Sources =
            [
                new ExpertModelDatasetDraftSource
                {
                    Id = sourceId,
                    Title = $"Source for {rowId}",
                    ContentPath = contentPath,
                    Provenance = "Project-owned test evidence.",
                    License = "Project-owned test fixture",
                    RetrievedAtUtc = FixtureTime,
                    AvailableAtUtc = FixtureTime,
                    Uri = $"repo://tests/{sourceId}"
                }
            ],
            Evidence = additionalEvidence is null
                ? ["Awaiting exact automated and independent human review."]
                : ["Awaiting exact automated and independent human review.", additionalEvidence]
        };

    private static ExpertDatasetVerifierAssignment VerificationAssignment(string rowId, string value) => new()
    {
        ExampleId = rowId,
        VerifierId = "handoff-text-verifier-v1",
        Checks =
        [
            new ExpertDatasetTextCheck
            {
                Id = $"contains-{value}",
                Kind = "contains",
                Value = value,
                IgnoreCase = true
            }
        ]
    };

    private static ExpertDatasetReviewDecision ReviewDecision(string rowId) => new()
    {
        ExampleId = rowId,
        Decision = "approved",
        Evidence = ["Reviewed exact row, source, and automated result."]
    };

    private static ExpertDatasetIndependentReviewDecision CreateDecision(PackagedFixture fixture)
    {
        var evidenceBytes = Encoding.UTF8.GetBytes(RightsEvidenceText);
        var evidence = new ExpertDatasetIndependentReviewEvidenceFile(
            "rights-proof",
            "rights-proof.txt",
            evidenceBytes.LongLength,
            Sha256(evidenceBytes),
            Convert.ToBase64String(evidenceBytes));
        var rows = fixture.Package.Rows.Select(item => new ExpertDatasetIndependentReviewRowDecision(
            item.ExampleId,
            item.KnowledgeClass == "candidate-stable" ? TrainingRights : BaseRights,
            UseForTraining: item.KnowledgeClass == "candidate-stable",
            EvidenceIds: ["rights-proof"])).ToArray();
        var rowInventory = fixture.Package.Rows.ToDictionary(item => item.ExampleId, StringComparer.Ordinal);
        var sources = fixture.Package.Sources.Select(item => new ExpertDatasetIndependentReviewSourceDecision(
            item.ExampleId,
            item.SourceId,
            rowInventory[item.ExampleId].KnowledgeClass == "candidate-stable" ? TrainingRights : BaseRights,
            EvidenceIds: ["rights-proof"])).ToArray();
        var decision = new ExpertDatasetIndependentReviewDecision(
            ExpertModelDatasetReviewHandoffTools.DecisionSchemaVersion,
            ZeroSha256,
            fixture.Package.PackageId,
            Sha256(fixture.PackageBytes),
            fixture.Package.ReviewedDatasetSha256,
            NoAuthority(),
            "independent-rights-reviewer",
            "Reviewed the exact package, row/source rights, knowledge classes, and immutable evidence.",
            FixtureTime,
            [evidence],
            rows,
            sources);
        return Reidentify(decision);
    }

    private static ExpertDatasetIndependentReviewDecision Reidentify(
        ExpertDatasetIndependentReviewDecision decision)
    {
        decision = decision with { DecisionId = ZeroSha256 };
        return decision with
        {
            DecisionId = ExpertModelDatasetReviewHandoffTools.ComputeDecisionId(decision)
        };
    }

    private static ExpertDatasetIndependentReviewDecisionDraft DraftFrom(
        ExpertDatasetIndependentReviewDecision decision) => new(
            ExpertModelDatasetReviewHandoffTools.DecisionDraftSchemaVersion,
            "unsigned-non-authorizing",
            NoAuthority(),
            decision.PackageId,
            decision.PackageSha256,
            decision.ReviewedDatasetSha256,
            decision.Reviewer,
            decision.ReviewBasis,
            decision.ReviewedAtUtc,
            decision.Rows,
            decision.Sources);

    private static async Task<string> WriteDecisionDraftAsync(
        TestWorkspace workspace,
        string fileName,
        ExpertDatasetIndependentReviewDecisionDraft template)
    {
        var path = workspace.PathFor(fileName);
        await File.WriteAllBytesAsync(
            path,
            ExpertModelDatasetReviewHandoffTools.SerializeCanonical(template));
        return path;
    }

    private static byte[] SerializeEditorJson(ExpertDatasetIndependentReviewDecisionDraft draft)
    {
        var editorOrdered = new
        {
            draft.ReviewBasis,
            draft.Sources,
            draft.SchemaVersion,
            draft.PackageSha256,
            draft.Rows,
            draft.Status,
            draft.Authority,
            draft.ReviewedAtUtc,
            draft.PackageId,
            draft.Reviewer,
            draft.ReviewedDatasetSha256
        };
        return JsonSerializer.SerializeToUtf8Bytes(
            editorOrdered,
            new JsonSerializerOptions(CoordinatorJson.Options) { WriteIndented = true });
    }

    private static byte[] InsertRootJsonProperty(byte[] bytes, string property)
    {
        var json = Encoding.UTF8.GetString(bytes);
        var objectStart = json.IndexOf('{');
        if (objectStart < 0)
        {
            throw new InvalidOperationException("Editor JSON fixture must be an object.");
        }
        return Encoding.UTF8.GetBytes(json.Insert(objectStart + 1, $"\n  {property},"));
    }

    private static byte[] InsertAfterFirstJsonToken(byte[] bytes, string token, string property)
    {
        var json = Encoding.UTF8.GetString(bytes);
        var tokenStart = json.IndexOf(token, StringComparison.Ordinal);
        if (tokenStart < 0)
        {
            throw new InvalidOperationException($"Editor JSON fixture does not contain '{token}'.");
        }
        return Encoding.UTF8.GetBytes(
            json.Insert(tokenStart + token.Length, $",\n        {property}"));
    }

    private static byte[] RemoveJsonProperty(byte[] bytes, string propertyName)
    {
        var json = Encoding.UTF8.GetString(bytes);
        var tokenStart = json.IndexOf($"\"{propertyName}\"", StringComparison.Ordinal);
        if (tokenStart < 0)
        {
            throw new InvalidOperationException($"Editor JSON fixture does not contain '{propertyName}'.");
        }
        var lineStart = json.LastIndexOf('\n', tokenStart) + 1;
        var lineEnd = json.IndexOf('\n', tokenStart);
        if (lineEnd < 0)
        {
            throw new InvalidOperationException($"Editor JSON property '{propertyName}' must not be the last line.");
        }
        lineEnd++;
        var propertyLine = json[lineStart..lineEnd];
        if (!propertyLine.Contains(',', StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Editor JSON property '{propertyName}' must have a trailing comma.");
        }
        return Encoding.UTF8.GetBytes(json.Remove(lineStart, lineEnd - lineStart));
    }

    private static async Task<string> WriteDecisionAsync(
        TestWorkspace workspace,
        string fileName,
        ExpertDatasetIndependentReviewDecision decision)
    {
        var path = workspace.PathFor(fileName);
        await File.WriteAllBytesAsync(
            path,
            ExpertModelDatasetReviewHandoffTools.SerializeCanonical(decision));
        return path;
    }

    private static ExpertDatasetIndependentReviewAuthority NoAuthority() => new(
        ReceiptAuthority: false,
        TrainingEligibilityAuthority: false,
        ProviderUploadAuthority: false,
        SftExportAuthority: false,
        SigningKeyAuthority: false,
        ModelReleaseAuthority: false,
        EvaluationAuthority: false,
        PromotionAuthority: false,
        DeploymentAuthority: false,
        ExecutionAuthority: false);

    private static string Sha256(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private sealed class CountingExecutableVerifier : IExpertDatasetExecutableVerifier
    {
        public int InvocationCount { get; private set; }

        public Task<ExpertDatasetExecutableResult> VerifyAsync(
            ExpertModelDatasetExample example,
            ExpertDatasetVerifierAssignment assignment,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            InvocationCount++;
            var specification = assignment.ExecutableVerification
                ?? throw new InvalidOperationException("The counting verifier requires an executable specification.");
            var source = example.Messages.Last(message => message.Role == "assistant").Content;
            return Task.FromResult(new ExpertDatasetExecutableResult
            {
                Profile = specification.Profile,
                SourceSha256 = Sha256(Encoding.UTF8.GetBytes(source)),
                CompilerClosureSha256 = Sha256(Encoding.UTF8.GetBytes("counting-compiler-closure-v1")),
                TestSpecificationSha256 = Sha256(
                    ExpertModelDatasetReviewHandoffTools.SerializeCanonical(specification)),
                CanonicalProgramSha256 = Sha256(Encoding.UTF8.GetBytes("canonical-program-v1")),
                ExecutionTraceSha256 = Sha256(Encoding.UTF8.GetBytes("execution-trace-v1")),
                CompileSucceeded = true,
                TestsPassed = true,
                VectorCount = specification.Vectors.Count,
                CallbackCount = specification.Vectors.Sum(vector => vector.Callbacks.Count),
                DiagnosticCodes = []
            });
        }
    }

    private sealed class FailIfInvokedVerifier : IExpertDatasetExecutableVerifier
    {
        public Task<ExpertDatasetExecutableResult> VerifyAsync(
            ExpertModelDatasetExample example,
            ExpertDatasetVerifierAssignment assignment,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("General-QA fixtures must not invoke executable verification.");
    }

    private sealed record ReviewedFixture(
        string DraftPath,
        string ReviewedPath,
        string VerificationManifestPath,
        string VerificationReportPath,
        string ReviewManifestPath,
        string HandoffEvidencePath);

    private sealed record PackagedFixture(
        ReviewedFixture Reviewed,
        string PackagePath,
        ExpertDatasetReviewHandoffPreparationResult Preparation,
        ExpertDatasetIndependentReviewPackage Package,
        byte[] PackageBytes);
}
