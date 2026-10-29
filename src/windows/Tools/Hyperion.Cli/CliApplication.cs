using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Coordinator.Cli;

public sealed class CliApplication(TextWriter output, TextWriter error)
{
    internal const int MaxBriefFileBytes = CoordinatorValidation.MaxObjectiveCharacters * 4 + 4;
    internal const int MaxSourceFileBytes = CoordinatorValidation.MaxSourceContentCharacters * 4 + 4;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false,
    };

    public async Task<int> RunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        var parsed = CliArguments.Parse(args);
        if (parsed.Positionals.Count == 0)
        {
            await PrintHelpAsync().ConfigureAwait(false);
            return 0;
        }
        if (parsed.Positionals[0] == "workflow")
        {
            if (parsed.Has("help") || parsed.Positionals.Count == 1)
            {
                await FreeStrategyWorkflowCli.PrintHelpAsync(output).ConfigureAwait(false);
                return 0;
            }
        }
        else if (parsed.Has("help"))
        {
            await PrintHelpAsync().ConfigureAwait(false);
            return 0;
        }

        try
        {
            return parsed.Positionals[0] switch
            {
                "workflow" => await new FreeStrategyWorkflowCli(output)
                    .RunAsync(parsed, cancellationToken).ConfigureAwait(false),
                "init" => await InitAsync(parsed, cancellationToken).ConfigureAwait(false),
                "credits" => await CreditsAsync(parsed, cancellationToken).ConfigureAwait(false),
                "create" => await CreateAsync(parsed, startImmediately: false, cancellationToken).ConfigureAwait(false),
                "run" => await CreateAsync(parsed, startImmediately: true, cancellationToken).ConfigureAwait(false),
                "approve" => await ApproveAsync(parsed, cancellationToken).ConfigureAwait(false),
                "status" => await StatusAsync(parsed, cancellationToken).ConfigureAwait(false),
                "spec" => await SpecAsync(parsed, cancellationToken).ConfigureAwait(false),
                "list" => await ListAsync(parsed, cancellationToken).ConfigureAwait(false),
                "show" => await ShowAsync(parsed, cancellationToken).ConfigureAwait(false),
                "cancel" => await CancelAsync(parsed, cancellationToken).ConfigureAwait(false),
                "dataset" => await DatasetAsync(parsed, cancellationToken).ConfigureAwait(false),
                "expert-dataset" => await ExpertDatasetAsync(parsed, cancellationToken).ConfigureAwait(false),
                "__daxq-worker" => await DaxqExpertDatasetExecutableVerifier.RunWorkerAsync(
                    Path.GetFullPath(parsed.Required("request")),
                    Path.GetFullPath(parsed.Required("output")),
                    cancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentException($"Unknown command '{parsed.Positionals[0]}'. Use --help."),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync("Cancelled.").ConfigureAwait(false);
            return 130;
        }
        catch (VibeQuantApiException exception)
        {
            await error.WriteLineAsync($"Server error {(int)exception.StatusCode}: {exception.Message}")
                .ConfigureAwait(false);
            return 1;
        }
        catch (Exception exception)
        {
            await error.WriteLineAsync($"Error: {exception.Message}").ConfigureAwait(false);
            return 1;
        }
    }

    private async Task<int> InitAsync(CliArguments args, CancellationToken cancellationToken)
    {
        var configPath = Path.GetFullPath(args.Optional("config") ?? "coordinator-client.json");
        if (File.Exists(configPath))
        {
            throw new IOException($"Refusing to overwrite existing config '{configPath}'.");
        }

        var authenticationMode = args.Optional("auth") ?? "development";
        var authentication = authenticationMode switch
        {
            "development" => new CoordinatorClientAuthenticationConfig
            {
                Mode = "development",
                DevelopmentSubject = args.Optional("subject") ?? Environment.UserName,
                DevelopmentEmail = args.Optional("email") ?? $"{Environment.UserName}@development.invalid",
                AccessTokenEnvironmentVariable = null,
            },
            "bearer" => new CoordinatorClientAuthenticationConfig
            {
                Mode = "bearer",
                AccessTokenEnvironmentVariable = args.Optional("token-env") ?? "DAXALGO_PLATFORM_ACCESS_TOKEN",
                DevelopmentSubject = null,
                DevelopmentEmail = null,
            },
            _ => throw new ArgumentException("--auth must be development or bearer."),
        };
        var config = new CoordinatorCliConfig
        {
            ServerBaseUrl = args.Optional("server") ?? "http://127.0.0.1:5080",
            Authentication = authentication,
        };
        CoordinatorCliConfigLoader.Validate(config);

        Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
        await File.WriteAllTextAsync(
            configPath,
            JsonSerializer.Serialize(config, CoordinatorJson.Options),
            new UTF8Encoding(false),
            cancellationToken).ConfigureAwait(false);

        var exampleDirectory = Path.Combine(Path.GetDirectoryName(configPath)!, "coordinator-examples");
        Directory.CreateDirectory(exampleDirectory);
        await WriteIfMissingAsync(
            Path.Combine(exampleDirectory, "brief.md"),
            "Assess whether the supplied evidence supports a small, testable volatility-regime research hypothesis.\n",
            cancellationToken).ConfigureAwait(false);
        await WriteIfMissingAsync(
            Path.Combine(exampleDirectory, "source.txt"),
            "Synthetic observation: volatility clusters in the seeded sample, but no live-market claim has been established.\n",
            cancellationToken).ConfigureAwait(false);
        await WriteExampleDatasetAsync(
            Path.Combine(exampleDirectory, "dataset.jsonl"),
            cancellationToken).ConfigureAwait(false);
        await WriteExampleExpertDatasetAsync(
            Path.Combine(exampleDirectory, "expert-dataset.jsonl"),
            cancellationToken).ConfigureAwait(false);

        await output.WriteLineAsync($"Created {configPath}").ConfigureAwait(false);
        await output.WriteLineAsync($"Examples: {exampleDirectory}").ConfigureAwait(false);
        await output.WriteLineAsync(
            "The client contains no LLM provider key, model, price, budget, credit balance, or local run database.")
            .ConfigureAwait(false);
        return 0;
    }

    private async Task<int> CreditsAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(await runtime.Client.GetCreditsAsync(cancellationToken).ConfigureAwait(false));
        return 0;
    }

    private async Task<int> CreateAsync(
        CliArguments args,
        bool startImmediately,
        CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        var objective = await ReadBoundedUtf8TextAsync(
            args.Required("brief"),
            MaxBriefFileBytes,
            CoordinatorValidation.MaxObjectiveCharacters,
            "Coordinator brief",
            cancellationToken).ConfigureAwait(false);
        var sources = await ReadSourcesAsync(args.All("source"), cancellationToken).ConfigureAwait(false);
        var purpose = (args.Optional("purpose") ?? "research") switch
        {
            "research" => CoordinatorRunPurpose.Research,
            "strategy" => CoordinatorRunPurpose.StrategyAuthoring,
            _ => throw new ArgumentException("--purpose must be research or strategy.")
        };
        var idempotencyKey = args.Optional("idempotency-key") ?? $"cli-{Guid.NewGuid():N}";
        var created = await runtime.Client.CreateRunAsync(
            new CreateVibeQuantRunRequest(objective, sources, purpose),
            idempotencyKey,
            cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(created).ConfigureAwait(false);

        if (startImmediately)
        {
            var queued = await runtime.Client.StartAsync(
                created.Spec.RunId,
                created.SpecSha256,
                cancellationToken).ConfigureAwait(false);
            await PrintStatusAsync(queued, args.Has("json")).ConfigureAwait(false);
        }
        return 0;
    }

    private async Task<int> ApproveAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        var runId = ParseRunId(args);
        var status = args.Required("gate") switch
        {
            "start" => await runtime.Client.StartAsync(
                runId,
                args.Required("spec"),
                cancellationToken).ConfigureAwait(false),
            "release" => await runtime.Client.ReleaseAsync(
                runId,
                args.Required("artifact"),
                cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException("--gate must be start or release."),
        };
        await PrintStatusAsync(status, args.Has("json")).ConfigureAwait(false);
        return 0;
    }

    private async Task<int> StatusAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        var status = await runtime.Client.GetStatusAsync(ParseRunId(args), cancellationToken).ConfigureAwait(false);
        await PrintStatusAsync(status, args.Has("json")).ConfigureAwait(false);
        return 0;
    }

    private async Task<int> SpecAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(await runtime.Client.GetSpecificationAsync(
            ParseRunId(args),
            cancellationToken).ConfigureAwait(false));
        return 0;
    }

    private async Task<int> ListAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        await PrintJsonAsync(await runtime.Client.ListAsync(cancellationToken).ConfigureAwait(false));
        return 0;
    }

    private async Task<int> ShowAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        var runId = ParseRunId(args);
        var hash = args.Optional("artifact");
        if (hash is null)
        {
            var status = await runtime.Client.GetStatusAsync(runId, cancellationToken).ConfigureAwait(false);
            hash = status.FinalArtifactSha256
                ?? throw new InvalidOperationException("The run has no final artifact. Pass --artifact for a role artifact.");
        }
        await PrintJsonAsync(await runtime.Client.GetArtifactAsync(runId, hash, cancellationToken).ConfigureAwait(false));
        return 0;
    }

    private async Task<int> CancelAsync(CliArguments args, CancellationToken cancellationToken)
    {
        using var runtime = await OpenRuntimeAsync(args, cancellationToken).ConfigureAwait(false);
        var status = await runtime.Client.CancelAsync(ParseRunId(args), cancellationToken).ConfigureAwait(false);
        await PrintStatusAsync(status, args.Has("json")).ConfigureAwait(false);
        return 0;
    }

    private async Task<int> DatasetAsync(CliArguments args, CancellationToken cancellationToken)
    {
        if (args.Positionals.Count < 2)
        {
            throw new ArgumentException("dataset requires validate or export-sft.");
        }
        var input = Path.GetFullPath(args.Required("input"));
        switch (args.Positionals[1])
        {
            case "validate":
                {
                    var report = await CoordinatorDatasetTools.ValidateJsonLinesAsync(input, cancellationToken)
                        .ConfigureAwait(false);
                    await output.WriteLineAsync(
                        $"Examples: {report.ExampleCount}; training-eligible: {report.TrainingEligibleCount}; issues: {report.Issues.Count}")
                        .ConfigureAwait(false);
                    foreach (var issue in report.Issues.Take(50))
                    {
                        await error.WriteLineAsync($"Line {issue.Line} ({issue.ExampleId ?? "?"}): {issue.Message}")
                            .ConfigureAwait(false);
                    }
                    return report.IsValid ? 0 : 2;
                }
            case "export-sft":
                {
                    var count = await CoordinatorDatasetTools.ExportSftJsonLinesAsync(
                        input,
                        Path.GetFullPath(args.Required("output")),
                        requireProviderUploadRights: !args.Has("local-only"),
                        cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync($"Exported {count} approved development examples.").ConfigureAwait(false);
                    return 0;
                }
            default:
                throw new ArgumentException("dataset requires validate or export-sft.");
        }
    }

    private async Task<int> ExpertDatasetAsync(CliArguments args, CancellationToken cancellationToken)
    {
        if (args.Positionals.Count < 2)
        {
            throw new ArgumentException(
                "expert-dataset requires compile-draft, compile-teacher-manifest, verify-draft, apply-review, prepare-rights-review, prepare-rights-decision-template, compile-rights-decision, apply-rights-review, validate, coverage, or export-sft.");
        }
        var action = args.Positionals[1];
        if (action == "compile-draft")
        {
            var count = await ExpertModelDatasetDraftAuthoringTools.CompileAsync(
                Path.GetFullPath(args.Required("manifest")),
                Path.GetFullPath(args.Required("output")),
                cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"Compiled {count} draft expert-model examples; 0 are training-eligible.")
                .ConfigureAwait(false);
            return 0;
        }

        if (action == "compile-teacher-manifest")
        {
            var result = await ExpertModelTeacherGenerationManifestTools.CompileAsync(
                Path.GetFullPath(args.Required("manifest")),
                Path.GetFullPath(args.Required("capture-plan")),
                Path.GetFullPath(args.Required("candidate-catalog")),
                Path.GetFullPath(args.Required("output")),
                cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"Compiled {result.TaskCount} teacher-generation tasks for {result.RequestCount} requests; " +
                $"output SHA-256: {result.OutputSha256}. No teacher, review, training, release, model, or promotion evidence was created.")
                .ConfigureAwait(false);
            return 0;
        }

        if (action == "prepare-rights-review")
        {
            var result = await ExpertModelDatasetReviewHandoffTools.PrepareAsync(
                Path.GetFullPath(args.Required("input")),
                Path.GetFullPath(args.Required("reviewed-input")),
                Path.GetFullPath(args.Required("verification-manifest")),
                Path.GetFullPath(args.Required("verification-report")),
                Path.GetFullPath(args.Required("review-manifest")),
                ParseReviewEvidenceInputs(args.All("evidence")),
                Path.GetFullPath(args.Required("output")),
                new DaxqExpertDatasetExecutableVerifier(),
                cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"Prepared unsigned non-authorizing review package {result.PackageId} for " +
                $"{result.RowCount} rows with {result.EvidenceFileCount} evidence files; " +
                $"package SHA-256: {result.PackageSha256}. No rights, receipt, release, SFT, key, or model authority was created.")
                .ConfigureAwait(false);
            return 0;
        }

        if (action == "compile-rights-decision")
        {
            var result = await ExpertModelDatasetReviewHandoffTools.CompileDecisionAsync(
                Path.GetFullPath(args.Required("package")),
                Path.GetFullPath(args.Required("template")),
                ParseReviewEvidenceInputs(args.All("evidence")),
                Path.GetFullPath(args.Required("output")),
                new DaxqExpertDatasetExecutableVerifier(),
                cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"Compiled unsigned non-authorizing rights decision {result.DecisionId} for " +
                $"{result.RowCount} rows and {result.SourceCount} sources with {result.EvidenceFileCount} evidence files; " +
                $"decision SHA-256: {result.DecisionSha256}. No receipt, release, SFT, key, model, or execution authority was created.")
                .ConfigureAwait(false);
            return 0;
        }

        if (action == "prepare-rights-decision-template")
        {
            var result = await ExpertModelDatasetReviewHandoffTools.PrepareDecisionTemplateAsync(
                Path.GetFullPath(args.Required("package")),
                Path.GetFullPath(args.Required("output")),
                new DaxqExpertDatasetExecutableVerifier(),
                cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"Prepared unsigned package-bound rights-decision template for {result.RowCount} rows and " +
                $"{result.SourceCount} sources; package SHA-256: {result.PackageSha256}. " +
                "No rights, receipt, release, SFT, key, model, or execution authority was created.")
                .ConfigureAwait(false);
            return 0;
        }

        if (action == "apply-rights-review")
        {
            var result = await ExpertModelDatasetReviewHandoffTools.ApplyDecisionAsync(
                Path.GetFullPath(args.Required("package")),
                Path.GetFullPath(args.Required("decision")),
                Path.GetFullPath(args.Required("output")),
                new DaxqExpertDatasetExecutableVerifier(),
                cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(
                $"Applied the unsigned declarative rights decision to {result.ExampleCount} rows: " +
                $"{result.RightsElevatedCount} rights-elevated and {result.TrainingRequestedCount} opted into training; " +
                $"{result.TrainingEligibleCount} are training-eligible before authenticated receipts. " +
                $"Output SHA-256: {result.OutputSha256}.")
                .ConfigureAwait(false);
            return 0;
        }

        var input = Path.GetFullPath(args.Required("input"));
        switch (action)
        {
            case "verify-draft":
                {
                    var report = await ExpertModelDatasetReviewTools.VerifyWithExecutableVerifierAsync(
                        input,
                        Path.GetFullPath(args.Required("manifest")),
                        Path.GetFullPath(args.Required("output")),
                        new DaxqExpertDatasetExecutableVerifier(),
                        cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync(
                        $"Verified {report.ExampleCount} draft examples; all checks passed: {report.AllPassed}; " +
                        $"report SHA-256: {report.ReportSha256}").ConfigureAwait(false);
                    return report.AllPassed ? 0 : 2;
                }
            case "apply-review":
                {
                    var result = await ExpertModelDatasetReviewTools.ApplyReviewWithExecutableVerifierAsync(
                        input,
                        Path.GetFullPath(args.Required("verification-manifest")),
                        Path.GetFullPath(args.Required("verification-report")),
                        Path.GetFullPath(args.Required("review-manifest")),
                        Path.GetFullPath(args.Required("output")),
                        new DaxqExpertDatasetExecutableVerifier(),
                        cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync(
                        $"Reviewed {result.ExampleCount} examples: {result.ApprovedCount} approved, " +
                        $"{result.RejectedCount} rejected; {result.TrainingEligibleCount} are training-eligible; " +
                        $"output SHA-256: {result.OutputSha256}").ConfigureAwait(false);
                    return 0;
                }
            case "validate":
                {
                    var report = await ExpertModelDatasetTools.ValidateJsonLinesAsync(input, cancellationToken)
                        .ConfigureAwait(false);
                    await output.WriteLineAsync(
                        $"Examples: {report.ExampleCount}; training-eligible: {report.TrainingEligibleCount}; issues: {report.Issues.Count}")
                        .ConfigureAwait(false);
                    foreach (var issue in report.Issues.Take(50))
                    {
                        await error.WriteLineAsync($"Line {issue.Line} ({issue.ExampleId ?? "?"}): {issue.Message}")
                            .ConfigureAwait(false);
                    }
                    return report.IsValid ? 0 : 2;
                }
            case "coverage":
                {
                    var report = await ExpertModelDatasetTools.BuildCoverageReportAsync(input, cancellationToken)
                        .ConfigureAwait(false);
                    if (args.Has("json"))
                    {
                        await PrintJsonAsync(report).ConfigureAwait(false);
                        return 0;
                    }

                    await output.WriteLineAsync(
                        $"Examples: {report.ExampleCount}; training-eligible: {report.TrainingEligibleCount}")
                        .ConfigureAwait(false);
                    foreach (var cell in report.Cells.Take(100))
                    {
                        await output.WriteLineAsync(
                            $"{cell.Split}: {cell.TaskKind}/{cell.Domain} = {cell.ExampleCount} " +
                            $"(training-eligible {cell.TrainingEligibleCount})").ConfigureAwait(false);
                    }
                    return 0;
                }
            case "export-sft":
                {
                    var teacherLineageOptionNames = new[]
                    {
                        "teacher-lineage-admission",
                        "teacher-lineage-public-key",
                        "teacher-lineage-public-key-spki-sha256",
                        "teacher-lineage-audience",
                        "teacher-lineage-key-id",
                        "teacher-lineage-signer-role",
                    };
                    var hasTeacherLineageOptions = teacherLineageOptionNames.Any(args.Has);
                    string? teacherLineageAdmissionPath = null;
                    ExpertTeacherLineageAdmissionTrust? teacherLineageTrust = null;
                    if (hasTeacherLineageOptions)
                    {
                        teacherLineageAdmissionPath = Path.GetFullPath(
                            args.Required("teacher-lineage-admission"));
                        teacherLineageTrust = new ExpertTeacherLineageAdmissionTrust(
                            Path.GetFullPath(args.Required("teacher-lineage-public-key")),
                            args.Required("teacher-lineage-public-key-spki-sha256"),
                            args.Required("teacher-lineage-audience"),
                            args.Required("teacher-lineage-key-id"),
                            args.Required("teacher-lineage-signer-role"));
                    }
                    var count = await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
                        input,
                        Path.GetFullPath(args.Required("output")),
                        Path.GetFullPath(args.Required("receipt-set")),
                        new ExpertDatasetReviewReceiptTrust(
                            Path.GetFullPath(args.Required("receipt-public-key")),
                            args.Required("receipt-public-key-spki-sha256"),
                            args.Required("receipt-audience"),
                            args.Required("receipt-key-id"),
                            args.Required("receipt-signer-role")),
                        teacherLineageAdmissionPath,
                        teacherLineageTrust,
                        requireProviderUploadRights: !args.Has("local-only"),
                        cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync($"Exported {count} approved expert-model examples.")
                        .ConfigureAwait(false);
                    return 0;
                }
            default:
                throw new ArgumentException(
                    "expert-dataset requires compile-draft, compile-teacher-manifest, verify-draft, apply-review, prepare-rights-review, prepare-rights-decision-template, compile-rights-decision, apply-rights-review, validate, coverage, or export-sft.");
        }
    }

    private async Task PrintStatusAsync(VibeQuantRunStatusResponse status, bool asJson)
    {
        if (asJson)
        {
            await PrintJsonAsync(status).ConfigureAwait(false);
            return;
        }
        await output.WriteLineAsync($"Run: {status.RunId:D}").ConfigureAwait(false);
        await output.WriteLineAsync($"State: {status.Status}").ConfigureAwait(false);
        await output.WriteLineAsync($"Spec SHA-256: {status.SpecSha256}").ConfigureAwait(false);
        await output.WriteLineAsync($"Roles: {status.CompletedRoleCount}/5").ConfigureAwait(false);
        if (status.CancellationRequested)
        {
            await output.WriteLineAsync("Cancellation requested.").ConfigureAwait(false);
        }
        await output.WriteLineAsync(
            $"Credits: {status.ReservedCredits} reserved; {status.ChargedCredits} charged")
            .ConfigureAwait(false);
        if (status.FinalArtifactSha256 is not null)
        {
            await output.WriteLineAsync($"Final artifact SHA-256: {status.FinalArtifactSha256}")
                .ConfigureAwait(false);
        }
        if (status.SafeMessage is not null)
        {
            await output.WriteLineAsync(status.SafeMessage).ConfigureAwait(false);
        }
    }

    private Task PrintJsonAsync<T>(T value) =>
        output.WriteLineAsync(JsonSerializer.Serialize(value, CoordinatorJson.Options));

    private static Task<CoordinatorRuntime> OpenRuntimeAsync(
        CliArguments args,
        CancellationToken cancellationToken) =>
        CoordinatorRuntime.CreateAsync(args.Required("config"), cancellationToken);

    internal static Guid ParseRunId(CliArguments args) =>
        Guid.TryParse(args.Required("run"), out var runId) && runId != Guid.Empty
            ? runId
            : throw new ArgumentException("--run must be a non-empty GUID.");

    internal static async Task<IReadOnlyList<CoordinatorContextSource>> ReadSourcesAsync(
        IReadOnlyList<string> values,
        CancellationToken cancellationToken)
    {
        if (values.Count > CoordinatorValidation.MaxSourceCount)
        {
            throw new ArgumentException(
                $"Run sources exceed the {CoordinatorValidation.MaxSourceCount}-source limit.");
        }

        var sources = new List<CoordinatorContextSource>();
        var aggregateCharacters = 0;
        foreach (var value in values)
        {
            var separator = value.IndexOf('=');
            if (separator <= 0 || separator == value.Length - 1)
            {
                throw new ArgumentException("Each --source must be id=path.");
            }
            var id = value[..separator];
            var path = Path.GetFullPath(value[(separator + 1)..]);
            var content = await ReadBoundedUtf8TextAsync(
                path,
                MaxSourceFileBytes,
                CoordinatorValidation.MaxSourceContentCharacters,
                $"Source '{id}'",
                cancellationToken).ConfigureAwait(false);
            aggregateCharacters += content.Length;
            if (aggregateCharacters > CoordinatorValidation.MaxAggregateSourceCharacters)
            {
                throw new ArgumentException(
                    $"Run source content exceeds the {CoordinatorValidation.MaxAggregateSourceCharacters:N0}-character aggregate limit.");
            }
            sources.Add(new CoordinatorContextSource(
                id,
                Path.GetFileName(path),
                content,
                RetrievedAtUtc: File.GetLastWriteTimeUtc(path)));
        }
        return sources;
    }

    private static IReadOnlyList<ExpertDatasetReviewHandoffEvidenceInput> ParseReviewEvidenceInputs(
        IReadOnlyList<string> values)
    {
        var evidence = new List<ExpertDatasetReviewHandoffEvidenceInput>(values.Count);
        foreach (var value in values)
        {
            var separator = value.IndexOf('=');
            if (separator <= 0 || separator == value.Length - 1)
            {
                throw new ArgumentException("Each --evidence must be id=path.");
            }
            evidence.Add(new ExpertDatasetReviewHandoffEvidenceInput(
                value[..separator],
                Path.GetFullPath(value[(separator + 1)..])));
        }
        return evidence;
    }

    internal static async Task<string> ReadBoundedUtf8TextAsync(
        string path,
        int maxBytes,
        int maxCharacters,
        string description,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length > maxBytes)
        {
            throw new InvalidDataException($"{description} exceeds the {maxBytes:N0}-byte input limit.");
        }
        using var snapshot = new MemoryStream((int)stream.Length);
        await stream.CopyToAsync(snapshot, cancellationToken).ConfigureAwait(false);
        if (snapshot.Length > maxBytes)
        {
            throw new InvalidDataException($"{description} exceeds the {maxBytes:N0}-byte input limit.");
        }

        string content;
        try
        {
            content = StrictUtf8.GetString(snapshot.GetBuffer(), 0, checked((int)snapshot.Length));
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException($"{description} must be valid UTF-8.", exception);
        }
        if (content.Length > 0 && content[0] == '\uFEFF')
        {
            content = content[1..];
        }
        if (content.Length > maxCharacters)
        {
            throw new InvalidDataException(
                $"{description} exceeds the {maxCharacters:N0}-character input limit.");
        }
        return content;
    }

    private static async Task WriteExampleDatasetAsync(string path, CancellationToken cancellationToken)
    {
        if (File.Exists(path))
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var source = new DatasetSourceAsset(
            "synthetic-note",
            "Synthetic note",
            "Seeded synthetic evidence for workflow evaluation only.",
            "Created by hyperion init.",
            "Project-owned",
            now,
            now,
            null,
            new DatasetRights(true, true, true, false, false));
        var example = new CoordinatorDatasetExample
        {
            SchemaVersion = CoordinatorVersions.DatasetSchema,
            Id = "example-planner-001",
            Split = "development",
            ContaminationGroup = "example-volatility-family",
            Role = CoordinatorRole.Planner,
            Objective = "Plan a falsifiable research check using the synthetic note.",
            Sources = [source],
            ReferenceOutput = new CoordinatorRoleOutput
            {
                SchemaVersion = CoordinatorVersions.ArtifactSchema,
                Role = CoordinatorRole.Planner,
                Summary = "Define a deterministic synthetic test before making any market claim.",
                Claims = [new CoordinatorClaim("The source is explicitly synthetic.", [source.Id], 1m)],
                Risks = ["Synthetic behavior may not transfer to live markets."],
                Recommendations = ["Pre-register metrics and test on a separately licensed point-in-time holdout."],
                SourceIds = [source.Id],
                Decision = CoordinatorDecision.None,
            },
            RequiredConcepts = ["falsifiable test", "synthetic limitation"],
            ForbiddenConcepts = ["guaranteed profit"],
            Provenance = "Project-owned init fixture.",
            License = "Project-owned",
            Rights = new DatasetRights(true, true, true, false, false),
            ReviewStatus = "approved",
            CutoffUtc = now,
            UseForTraining = false,
        };
        await WriteIfMissingAsync(
            path,
            JsonSerializer.Serialize(example, CompactJson) + Environment.NewLine,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteExampleExpertDatasetAsync(string path, CancellationToken cancellationToken)
    {
        if (File.Exists(path))
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var rights = new DatasetRights(true, true, false, false, false);
        LlmMessage[] messages =
        [
            new("system", "Answer as a bounded DaxAlgo strategy-domain expert."),
            new("user", "Explain why a backtest must preserve an untouched outer holdout."),
            new(
                "assistant",
                "An untouched outer holdout estimates final generalisation after every design, tuning, and model-selection choice. Reusing it for iteration leaks information and invalidates that estimate.")
        ];
        var evidence = new[] { "Reviewed against the project-owned evaluation policy." };
        var example = new ExpertModelDatasetExample
        {
            SchemaVersion = CoordinatorVersions.ExpertModelDatasetSchema,
            Id = "expert-example-001",
            TaskKind = ExpertTaskKind.QuantitativeReasoning,
            Domains =
            [
                ExpertDomain.QuantitativeMath,
                ExpertDomain.ProbabilityStatistics,
                ExpertDomain.RiskManagement
            ],
            Messages = messages,
            ConversationSha256 = ExpertModelDatasetTools.ComputeConversationSha256(messages),
            Sources =
            [
                new DatasetSourceAsset(
                    "project-evaluation-policy",
                    "Project evaluation policy",
                    "Keep one outer holdout untouched by training, prompt tuning, and model selection.",
                    "Created by hyperion init.",
                    "Project-owned",
                    now,
                    now,
                    null,
                    rights)
            ],
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.HumanAuthored,
                Producer = "daxalgo-coordinator-init",
                ProducedAtUtc = now
            },
            Verification = new ExpertVerificationEvidence
            {
                Verified = true,
                Reviewer = "daxalgo-coordinator-init",
                VerifiedAtUtc = now,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    evidence,
                    [],
                    []),
                Evidence = evidence
            },
            Split = "development",
            ContaminationGroup = "expert-example-holdout-family",
            Provenance = "Project-owned init fixture.",
            License = "Project-owned",
            Rights = rights,
            ReviewStatus = "approved",
            CutoffUtc = now,
            UseForTraining = false
        };
        await WriteIfMissingAsync(
            path,
            JsonSerializer.Serialize(example, CompactJson) + Environment.NewLine,
            cancellationToken).ConfigureAwait(false);
    }

    internal static async Task WriteIfMissingAsync(
        string path,
        string content,
        CancellationToken cancellationToken)
    {
        if (File.Exists(path))
        {
            return;
        }

        var destination = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(destination)
            ?? throw new IOException("Fixture path has no parent directory.");
        Directory.CreateDirectory(parent);
        var temporary = Path.Combine(parent, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                useAsync: true))
            {
                var bytes = new UTF8Encoding(false).GetBytes(content);
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            try
            {
                File.Move(temporary, destination, overwrite: false);
            }
            catch (IOException) when (File.Exists(destination))
            {
                // Another initializer won the no-clobber race.
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private async Task PrintHelpAsync()
    {
        await output.WriteLineAsync("""
            hyperion - hosted Hyperion operator and local free-workflow CLI

              init [--config PATH] [--server URL] [--auth development|bearer]
                   [--subject ID] [--email ADDRESS] [--token-env DAXALGO_PLATFORM_ACCESS_TOKEN]
              credits --config PATH
              create --config PATH --brief FILE [--source ID=FILE] [--purpose research|strategy]
                     [--idempotency-key KEY]
              run --config PATH --brief FILE [--source ID=FILE] [--purpose research|strategy]
                  [--idempotency-key KEY]
              spec --config PATH --run ID
              approve --config PATH --run ID --gate start --spec SHA256
              status --config PATH --run ID [--json]
              list --config PATH
              show --config PATH --run ID [--artifact SHA256]
              approve --config PATH --run ID --gate release --artifact SHA256
              cancel --config PATH --run ID
              dataset validate --input FILE
              dataset export-sft --input FILE --output FILE [--local-only]
              expert-dataset compile-draft --manifest FILE --output FILE
              expert-dataset compile-teacher-manifest --manifest FILE --capture-plan FILE
                  --candidate-catalog FILE --output FILE
              expert-dataset verify-draft --input FILE --manifest FILE --output REPORT
              expert-dataset apply-review --input FILE --verification-manifest FILE
                  --verification-report FILE --review-manifest FILE --output FILE
              expert-dataset prepare-rights-review --input DRAFT --reviewed-input REVIEWED
                  --verification-manifest FILE --verification-report FILE --review-manifest FILE
                  [--evidence ID=FILE] --output PACKAGE
              expert-dataset prepare-rights-decision-template --package PACKAGE --output TEMPLATE
              expert-dataset compile-rights-decision --package PACKAGE --template FILE
                  --evidence ID=FILE [--evidence ID=FILE] --output DECISION
              expert-dataset apply-rights-review --package PACKAGE --decision FILE --output FILE
              expert-dataset validate --input FILE
              expert-dataset coverage --input FILE [--json]
              expert-dataset export-sft --input FILE --output FILE --receipt-set FILE
                  --receipt-public-key FILE --receipt-public-key-spki-sha256 SHA256
                  --receipt-audience ID --receipt-key-id ID --receipt-signer-role ID
                  [--teacher-lineage-admission FILE --teacher-lineage-public-key FILE
                   --teacher-lineage-public-key-spki-sha256 SHA256 --teacher-lineage-audience ID
                   --teacher-lineage-key-id ID --teacher-lineage-signer-role ID] [--local-only]
              workflow --help

            The platform owns identity, provider credentials, model selection, budgets, credits,
            persistence, and execution. `run` creates and queues a server job; poll `status` for output.
            Strategy purpose requires an exact signed hosted capability outside Mock mode. Released
            source still requires the Terminal's explicit compile consent and cannot be installed
            directly by this client.
            Development authentication is accepted only for a loopback server. Production uses a
            short-lived platform access token supplied through the configured environment variable.
            The local `workflow` surface uses a separate config/workspace, stores no provider secret,
            consumes no hosted credits, and produces only inert source requiring human release and
            Terminal compile consent.
            """).ConfigureAwait(false);
    }
}
