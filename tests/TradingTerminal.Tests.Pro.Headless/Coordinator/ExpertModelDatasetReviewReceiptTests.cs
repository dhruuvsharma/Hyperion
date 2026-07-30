using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Datasets;
using TradingTerminal.Ai.Coordinator.Orchestration;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Tests.Pro.Headless.Coordinator;

public sealed class ExpertModelDatasetReviewReceiptTests
{
    private const string Audience = "daxalgo-expert-sft";
    private const string KeyId = "review-test-v1";
    private const string SignerRole = "independent-corpus-reviewer";
    private const string LineageAudience = "daxalgo-teacher-lineage-review";
    private const string LineageKeyId = "teacher-lineage-test-v1";
    private const string LineageSignerRole = "independent-teacher-lineage-reviewer";
    private static readonly UTF8Encoding Utf8 = new(false);
    private static readonly JsonSerializerOptions CompactJson = new(CoordinatorJson.Options)
    {
        WriteIndented = false
    };
    private static readonly BigInteger P256Order = BigInteger.Parse(
        "00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        NumberStyles.AllowHexSpecifier,
        CultureInfo.InvariantCulture);

    [Fact]
    public async Task Valid_receipt_unlocks_export_without_changing_signed_sft_metadata()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-valid");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, key);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);
        var outputPath = workspace.PathFor("training.jsonl");

        var count = await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            outputPath,
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        count.Should().Be(1);
        var row = JsonNode.Parse((await File.ReadAllLinesAsync(outputPath)).Single())!.AsObject();
        var metadata = row["metadata"]!.AsObject();
        metadata["cutoffUtc"]!.GetValue<string>().Should().Be("2025-01-15T12:00:00.0000000Z");
        metadata.ContainsKey("receiptId").Should().BeFalse();
        metadata.ContainsKey("receiptPayloadSha256").Should().BeFalse();
        metadata.ContainsKey("receiptEnvelopeSha256").Should().BeFalse();
        metadata.ContainsKey("receiptPublicKeySpkiSha256").Should().BeFalse();
        metadata["schemaVersion"]!.GetValue<string>().Should()
            .Be(ExpertModelDatasetReviewReceiptTools.SftMetadataSchemaVersion);
        metadata["sourceCorpusSha256"]!.GetValue<string>().Should()
            .Be(receipt.Payload.SourceCorpusSha256);
        metadata["verificationEvidenceSha256"]!.GetValue<string>().Should()
            .Be(example.Verification.EvidenceSha256);
        ExpertModelDatasetReviewReceiptTools.ComputeCanonicalJsonSha256(
                UnsignedMetadata(example, receipt.Payload.SourceCorpusSha256))
            .Should().Be(receipt.Payload.SftMetadataSha256);
    }

    [Fact]
    public async Task Unicode_model_lineage_matches_python_canonical_metadata_and_exports()
    {
        const string unicode = "\u2028\u2029\U0001F642";
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var basis = CreateExample("receipt-unicode");
        var promptSha256 = new string('a', 64);
        var example = basis with
        {
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.HostedTeacher,
                Producer = "producer-" + unicode,
                ModelId = "model-" + unicode,
                ModelRevision = "revision-" + unicode,
                PromptSha256 = promptSha256,
                ProfileVersion = "profile-" + unicode,
                ProducedAtUtc = basis.Lineage.ProducedAtUtc
            }
        };
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var sourceCorpusSha256 = Sha256(await File.ReadAllBytesAsync(datasetPath));
        var metadata = ExpertModelDatasetTools.CreateUnsignedSftMetadata(
            example,
            sourceCorpusSha256);
        var metadataJson = Utf8.GetString(
            ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(metadata));
        var expectedMetadata =
            "{\"contaminationGroup\":\"family-receipt-unicode\"," +
            "\"conversationSha256\":\"" + example.ConversationSha256 + "\"," +
            "\"cutoffUtc\":\"2025-01-15T12:00:00.0000000Z\"," +
            "\"domains\":[\"QuantitativeMath\"]," +
            "\"id\":\"receipt-unicode\"," +
            "\"modelId\":\"model-" + unicode + "\"," +
            "\"modelRevision\":\"revision-" + unicode + "\"," +
            "\"origin\":\"HostedTeacher\"," +
            "\"producer\":\"producer-" + unicode + "\"," +
            "\"profileVersion\":\"profile-" + unicode + "\"," +
            "\"promptSha256\":\"" + promptSha256 + "\"," +
            "\"schemaVersion\":\"daxalgo.expert-model-sft-metadata/v2\"," +
            "\"sourceCorpusSha256\":\"" + sourceCorpusSha256 + "\"," +
            "\"sourceSchema\":\"expert-model-dataset/v1\"," +
            "\"split\":\"development\"," +
            "\"taskKind\":\"QuantitativeReasoning\"," +
            "\"verificationEvidenceSha256\":\"" +
            example.Verification.EvidenceSha256 + "\"}";

        metadataJson.Should().Be(expectedMetadata);
        var receipt = CreateReceipt(datasetPath, example, key);
        receipt.Payload.SftMetadataSha256.Should().Be(Sha256(Utf8.GetBytes(expectedMetadata)));
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        var count = await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("unicode-training.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        count.Should().Be(1);
    }

    [Fact]
    public void Sft_v2_metadata_matches_the_python_cross_language_vector()
    {
        var basis = CreateExample("sft-vector-001");
        var example = basis with
        {
            ConversationSha256 = new string('1', 64),
            Verification = basis.Verification with
            {
                EvidenceSha256 = new string('2', 64)
            }
        };
        var metadata = ExpertModelDatasetTools.CreateUnsignedSftMetadata(
            example,
            new string('3', 64));
        var canonical = Utf8.GetString(
            ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(metadata));
        var expected =
            "{\"contaminationGroup\":\"family-sft-vector-001\"," +
            "\"conversationSha256\":\"" + new string('1', 64) + "\"," +
            "\"cutoffUtc\":\"2025-01-15T12:00:00.0000000Z\"," +
            "\"domains\":[\"QuantitativeMath\"]," +
            "\"id\":\"sft-vector-001\"," +
            "\"modelId\":null,\"modelRevision\":null," +
            "\"origin\":\"HumanAuthored\",\"producer\":\"fixture-producer\"," +
            "\"profileVersion\":null,\"promptSha256\":null," +
            "\"schemaVersion\":\"daxalgo.expert-model-sft-metadata/v2\"," +
            "\"sourceCorpusSha256\":\"" + new string('3', 64) + "\"," +
            "\"sourceSchema\":\"expert-model-dataset/v1\"," +
            "\"split\":\"development\"," +
            "\"taskKind\":\"QuantitativeReasoning\"," +
            "\"verificationEvidenceSha256\":\"" + new string('2', 64) + "\"}";

        canonical.Should().Be(expected);
        Sha256(Utf8.GetBytes(canonical)).Should()
            .Be("bdfe6c2043398219d16b9f138a53cb69c4862756be425f7a5bc74e302c0f4b2d");
    }

    [Fact]
    public void Canonical_json_rejects_invalid_unicode_surrogate_sequences()
    {
        foreach (var invalid in new[] { "\uD800", "\uDC00", "a\uD800b" })
        {
            Action serialize = () =>
                ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(new { value = invalid });

            serialize.Should().Throw<CoordinatorValidationException>()
                .WithMessage("*invalid Unicode surrogate sequence*");
        }
    }

    [Fact]
    public async Task Receipt_rejects_fractional_verified_review_time()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var basis = CreateExample("receipt-fractional-review");
        var example = basis with
        {
            Verification = basis.Verification with
            {
                VerifiedAtUtc = basis.Verification.VerifiedAtUtc!.Value.AddTicks(1)
            }
        };
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, key);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("fractional-review.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("whole-second precision");
    }

    [Fact]
    public async Task Receipt_payload_uses_the_cross_language_approval_limits()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-approval-limits");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var cases = new[]
        {
            CreateReceipt(datasetPath, example, key, approvalReference: "line-one\nline-two"),
            CreateReceipt(datasetPath, example, key, approvalReference: new string('a', 501)),
            CreateReceipt(
                datasetPath,
                example,
                key,
                approvalEvidenceSizeBytes: ExpertModelDatasetReviewReceiptTools.MaxApprovalEvidenceBytes + 1)
        };

        for (var index = 0; index < cases.Length; index++)
        {
            var receiptSetPath = WriteReceiptSet(workspace, cases[index].Envelope, $"approval-{index}.jsonl");
            Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
                datasetPath,
                workspace.PathFor($"approval-{index}-output.jsonl"),
                receiptSetPath,
                Trust(keyPath, key),
                requireProviderUploadRights: true);

            (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
                .Should().Contain("approval metadata is invalid");
        }
    }

    [Fact]
    public async Task Expert_dataset_requires_exact_lowercase_status_and_ascii_identifier()
    {
        using var workspace = new TestWorkspace();
        var uppercaseStatus = CreateExample("receipt-uppercase-status") with
        {
            ReviewStatus = "Approved"
        };
        var uppercasePath = await WriteDatasetAsync(workspace, uppercaseStatus, fileName: "uppercase.jsonl");
        var uppercaseReport = await ExpertModelDatasetTools.ValidateJsonLinesAsync(uppercasePath);
        uppercaseReport.IsValid.Should().BeFalse();
        uppercaseReport.Issues.Should().Contain(issue => issue.Message.Contains("Review status"));

        var unicodeId = CreateExample("receipt-unicode-id") with
        {
            Id = "receipt-é"
        };
        var unicodePath = await WriteDatasetAsync(workspace, unicodeId, fileName: "unicode-id.jsonl");
        var unicodeReport = await ExpertModelDatasetTools.ValidateJsonLinesAsync(unicodePath);
        unicodeReport.IsValid.Should().BeFalse();
        unicodeReport.Issues.Should().Contain(issue => issue.Message.Contains("unsupported characters"));
    }

    [Fact]
    public async Task Current_verifier_rejects_the_python_v1_golden_receipt()
    {
        var fixtureDirectory = Path.Combine(AppContext.BaseDirectory, "ReviewReceipts");
        var datasetPath = Path.Combine(fixtureDirectory, "golden.corpus.jsonl");
        var receiptSetPath = Path.Combine(fixtureDirectory, "golden.receipts.jsonl");
        var publicKeyPath = Path.Combine(fixtureDirectory, "golden.public.pem");
        using var expectedDocument = JsonDocument.Parse(
            await File.ReadAllBytesAsync(Path.Combine(fixtureDirectory, "golden.expected.json")));
        var expected = expectedDocument.RootElement;

        var sourceCorpusSha256 = Sha256(await File.ReadAllBytesAsync(datasetPath));
        sourceCorpusSha256.Should().Be(expected.GetProperty("datasetSha256").GetString());
        var example = JsonSerializer.Deserialize<ExpertModelDatasetExample>(
            (await File.ReadAllLinesAsync(datasetPath)).Single(),
            CoordinatorJson.Options)!;
        var trust = new ExpertDatasetReviewReceiptTrust(
            publicKeyPath,
            expected.GetProperty("publicKeySpkiSha256").GetString()!,
            expected.GetProperty("audience").GetString()!,
            expected.GetProperty("keyId").GetString()!,
            expected.GetProperty("signerRole").GetString()!);
        Func<Task> verify = async () => await ExpertModelDatasetReviewReceiptTools.LoadAndVerifyAsync(
            receiptSetPath,
            sourceCorpusSha256,
            [new ExpertDatasetReviewReceiptSubject(
                example,
                expected.GetProperty("sftMetadataSha256").GetString()!)],
            trust,
            new FixedTimeProvider(new DateTimeOffset(2025, 2, 1, 0, 0, 0, TimeSpan.Zero)),
            CancellationToken.None);

        (await verify.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("unsupported");
    }

    [Fact]
    public async Task Receipt_set_requires_exactly_one_active_receipt_per_dataset_row()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var first = CreateExample("receipt-first");
        var second = CreateExample("receipt-second");
        var datasetPath = await WriteDatasetAsync(workspace, first, second);
        var firstReceipt = CreateReceipt(datasetPath, first, key);
        var receiptSetPath = WriteReceiptSet(workspace, firstReceipt.Envelope);
        var outputPath = workspace.PathFor("missing-receipt.jsonl");

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            outputPath,
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("missing").And.Contain(second.Id);
        File.Exists(outputPath).Should().BeFalse();

        var secondReceipt = CreateReceipt(datasetPath, second, key);
        var outOfOrderPath = workspace.PathFor("out-of-order.jsonl");
        await File.WriteAllBytesAsync(
            outOfOrderPath,
            [.. ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(secondReceipt.Envelope),
             (byte)'\n',
             .. ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(firstReceipt.Envelope),
             (byte)'\n']);
        Func<Task> outOfOrderExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("out-of-order-output.jsonl"),
            outOfOrderPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await outOfOrderExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("row order");
    }

    [Fact]
    public async Task Signed_receipt_cannot_be_substituted_after_dataset_or_label_changes()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-substitution");
        var originalPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(originalPath, example, key);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);
        var changed = example with
        {
            TaskKind = ExpertTaskKind.RiskAnalysis,
            Domains = [ExpertDomain.RiskManagement]
        };
        var changedPath = await WriteDatasetAsync(workspace, changed, fileName: "changed.jsonl");

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            changedPath,
            workspace.PathFor("substituted.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exact current fields");
    }

    [Fact]
    public async Task Signed_receipt_binds_the_exact_source_corpus_bytes()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-source-corpus");
        var originalPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(originalPath, example, key);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);
        var changedPath = workspace.PathFor("same-row-different-bytes.jsonl");
        await File.WriteAllTextAsync(
            changedPath,
            " " + await File.ReadAllTextAsync(originalPath),
            Utf8);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            changedPath,
            workspace.PathFor("same-row-different-bytes-output.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exact current fields");
    }

    [Fact]
    public async Task V2_receipt_rejects_a_v1_metadata_hash()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-v1-metadata");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var v1MetadataSha256 = ExpertModelDatasetReviewReceiptTools.ComputeCanonicalJsonSha256(
            LegacyUnsignedMetadata(example));
        var receipt = CreateReceipt(
            datasetPath,
            example,
            key,
            sftMetadataSha256: v1MetadataSha256);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("v1-metadata-output.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exact current fields");
    }

    [Fact]
    public async Task V2_receipt_rejects_mismatched_verification_evidence_binding()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-evidence-binding");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(
            datasetPath,
            example,
            key,
            verificationEvidenceSha256: new string('f', 64));
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("evidence-binding-output.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exact current fields");
    }

    [Fact]
    public async Task V2_verifier_rejects_v1_cross_pair_and_legacy_field_injection()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-contract-v2");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, key);

        var v1Envelope = receipt.Envelope with
        {
            SchemaVersion = "daxalgo.expert-model-review-receipt-envelope/v1",
            PayloadType = "daxalgo.expert-model-review-receipt/v1"
        };
        var v1Path = WriteReceiptSet(workspace, v1Envelope, "v1-envelope.jsonl");
        Func<Task> v1Export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("v1-envelope-output.jsonl"),
            v1Path,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await v1Export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("unsupported");

        var crossPairEnvelope = receipt.Envelope with
        {
            PayloadType = "daxalgo.expert-model-review-receipt/v1"
        };
        var crossPairPath = WriteReceiptSet(
            workspace,
            crossPairEnvelope,
            "cross-pair-envelope.jsonl");
        Func<Task> crossPairExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("cross-pair-output.jsonl"),
            crossPairPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await crossPairExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("unsupported");

        var payloadBytes = ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(receipt.Payload);
        var payloadNode = JsonNode.Parse(Utf8.GetString(payloadBytes))!.AsObject();
        payloadNode["datasetSha256"] = receipt.Payload.SourceCorpusSha256;
        var injectedPayloadBytes =
            ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(payloadNode);
        var injectedEnvelope = SignReceiptEnvelope(
            receipt.Envelope,
            injectedPayloadBytes,
            key);
        var injectedPath = WriteReceiptSet(
            workspace,
            injectedEnvelope,
            "legacy-field-injection.jsonl");
        Func<Task> injectedExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("legacy-field-injection-output.jsonl"),
            injectedPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        await injectedExport.Should().ThrowAsync<CoordinatorValidationException>();
    }

    [Fact]
    public async Task Signed_training_authorization_cannot_exceed_example_or_source_rights()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var rights = new DatasetRights(true, true, false, false, false);
        var example = CreateExample("receipt-rights") with
        {
            Rights = rights,
            Sources = CreateExample("receipt-rights-source").Sources
                .Select(source => source with { Rights = rights })
                .ToArray(),
            UseForTraining = false
        };
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, key, trainingAuthorized: true);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("rights.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: false);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("do not exactly match");

        var trainable = CreateExample("receipt-underclaimed");
        var trainablePath = await WriteDatasetAsync(workspace, trainable, fileName: "trainable.jsonl");
        var underclaimed = CreateReceipt(
            trainablePath,
            trainable,
            key,
            trainingAuthorized: false);
        var underclaimedSet = WriteReceiptSet(
            workspace,
            underclaimed.Envelope,
            "underclaimed.jsonl");
        Func<Task> underclaimedExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            trainablePath,
            workspace.PathFor("underclaimed-output.jsonl"),
            underclaimedSet,
            Trust(keyPath, key),
            requireProviderUploadRights: false);
        (await underclaimedExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("do not exactly match");
    }

    [Fact]
    public async Task Receipt_rejects_untrusted_or_private_key_and_high_s_signature()
    {
        using var workspace = new TestWorkspace();
        using var trustedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trustedKeyPath = WritePublicKey(workspace, trustedKey);
        var example = CreateExample("receipt-key");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var attackerReceipt = CreateReceipt(datasetPath, example, attackerKey);
        var attackerSet = WriteReceiptSet(workspace, attackerReceipt.Envelope, "attacker.jsonl");

        Func<Task> attackerExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("attacker-output.jsonl"),
            attackerSet,
            Trust(trustedKeyPath, trustedKey),
            requireProviderUploadRights: true);
        (await attackerExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("trust policy");

        var privateKeyPath = workspace.PathFor("private-key.pem");
        await File.WriteAllTextAsync(privateKeyPath, trustedKey.ExportPkcs8PrivateKeyPem(), Utf8);
        var trustedReceipt = CreateReceipt(datasetPath, example, trustedKey);
        var trustedSet = WriteReceiptSet(workspace, trustedReceipt.Envelope, "trusted.jsonl");
        Func<Task> privateKeyExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("private-key-output.jsonl"),
            trustedSet,
            Trust(privateKeyPath, trustedKey),
            requireProviderUploadRights: true);
        (await privateKeyExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exactly one public P-256 SPKI PEM block");

        var highSReceipt = CreateReceipt(datasetPath, example, trustedKey, highS: true);
        var highSSet = WriteReceiptSet(workspace, highSReceipt.Envelope, "high-s.jsonl");
        Func<Task> highSExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("high-s-output.jsonl"),
            highSSet,
            Trust(trustedKeyPath, trustedKey),
            requireProviderUploadRights: true);
        (await highSExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("low-S");
    }

    [Fact]
    public async Task Signed_noncanonical_or_expired_payload_is_rejected()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-canonical");
        var datasetPath = await WriteDatasetAsync(workspace, example);

        var noncanonical = CreateReceipt(datasetPath, example, key, noncanonicalPayload: true);
        var noncanonicalSet = WriteReceiptSet(workspace, noncanonical.Envelope, "noncanonical.jsonl");
        Func<Task> noncanonicalExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("noncanonical-output.jsonl"),
            noncanonicalSet,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await noncanonicalExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("canonical JSON");

        var expired = CreateReceipt(datasetPath, example, key, expired: true);
        var expiredSet = WriteReceiptSet(workspace, expired.Envelope, "expired.jsonl");
        Func<Task> expiredExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("expired-output.jsonl"),
            expiredSet,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await expiredExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("inactive");
    }

    [Fact]
    public async Task Receipt_set_rejects_blank_and_noncanonical_envelope_lines()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("receipt-envelope-shape");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, key);

        var noncanonicalPath = workspace.PathFor("noncanonical-envelope.jsonl");
        await File.WriteAllTextAsync(
            noncanonicalPath,
            JsonSerializer.Serialize(receipt.Envelope, CompactJson) + "\n",
            Utf8);
        Func<Task> noncanonicalExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("noncanonical-envelope-output.jsonl"),
            noncanonicalPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await noncanonicalExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("canonical JSON");

        var blankPath = workspace.PathFor("blank-line.jsonl");
        await File.WriteAllBytesAsync(
            blankPath,
            [.. ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(receipt.Envelope),
             (byte)'\n',
             (byte)'\n']);
        Func<Task> blankExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("blank-line-output.jsonl"),
            blankPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await blankExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("must not be blank");

        var noFinalLfPath = workspace.PathFor("no-final-lf.jsonl");
        await File.WriteAllBytesAsync(
            noFinalLfPath,
            ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(receipt.Envelope));
        Func<Task> noFinalLfExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("no-final-lf-output.jsonl"),
            noFinalLfPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await noFinalLfExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("final line");

        var crlfPath = workspace.PathFor("crlf.jsonl");
        await File.WriteAllBytesAsync(
            crlfPath,
            [.. ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(receipt.Envelope),
             (byte)'\r',
             (byte)'\n']);
        Func<Task> crlfExport = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("crlf-output.jsonl"),
            crlfPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);
        (await crlfExport.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("not CRLF");
    }

    [Fact]
    public void Teacher_lineage_stable_subject_matches_python_cross_language_vector()
    {
        var example = new ExpertModelDatasetExample
        {
            SchemaVersion = "expert-model-dataset/v1",
            Id = "teacher-vector-001",
            TaskKind = ExpertTaskKind.GeneralQuestionAnswering,
            Domains = [ExpertDomain.RiskManagement, ExpertDomain.CSharp],
            Messages =
            [
                new("system", "Answer exactly."),
                new("user", "What is bound?"),
                new("assistant", "The reviewed teacher subject."),
            ],
            ConversationSha256 = new string('1', 64),
            Sources =
            [
                new DatasetSourceAsset(
                    "source-vector-001",
                    "Reviewed vector",
                    "Exact source bytes.",
                    "Private vector fixture.",
                    "Internal evaluation grant",
                    DateTimeOffset.Parse("2026-01-01T11:00:00.0000000+00:00", CultureInfo.InvariantCulture),
                    DateTimeOffset.Parse("2025-12-31T13:00:00+01:00", CultureInfo.InvariantCulture),
                    "https://example.invalid/vector",
                    new DatasetRights(true, true, false, false, false)),
            ],
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.OpenWeightTeacher,
                Producer = "vector-producer",
                ModelId = "Example/Teacher",
                ModelRevision = "revision-1",
                PromptSha256 = new string('2', 64),
                ProfileVersion = "profile-v1",
                ProducedAtUtc = DateTimeOffset.Parse(
                    "2026-01-02T01:00:00+01:00",
                    CultureInfo.InvariantCulture),
            },
            Verification = new ExpertVerificationEvidence
            {
                Verified = true,
                Reviewer = "ignored-reviewer",
                VerifiedAtUtc = new DateTimeOffset(2026, 1, 2, 1, 0, 0, TimeSpan.Zero),
                EvidenceSha256 = new string('3', 64),
                Evidence = [],
                CompileSucceeded = false,
                CompileEvidence = [],
                TestsPassed = false,
                TestEvidence = [],
            },
            Split = "development",
            ContaminationGroup = "teacher-vector-group-001",
            Provenance = "Private vector fixture.",
            License = "Internal evaluation grant",
            Rights = new DatasetRights(true, true, false, false, false),
            ReviewStatus = "approved",
            CutoffUtc = DateTimeOffset.Parse("2026-01-01T13:00:00+01:00", CultureInfo.InvariantCulture),
            UseForTraining = false,
        };

        ExpertModelTeacherLineageAdmissionTools.ComputeStableSubjectSha256(example)
            .Should().Be("1514c4ea9ea0b42522a41d73efbc436817d7f0a17f60ff36bd926fae70f805c8");
    }

    [Fact]
    public async Task Open_weight_teacher_export_requires_valid_distinct_lineage_admission()
    {
        using var workspace = new TestWorkspace();
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var lineageKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var receiptKeyPath = WritePublicKey(workspace, receiptKey, "receipt-public.pem");
        var lineageKeyPath = WritePublicKey(workspace, lineageKey, "lineage-public.pem");
        var example = CreateTeacherExample("teacher-lineage-valid");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, receiptKey);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> missingAdmission = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("missing-admission.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            requireProviderUploadRights: true);
        (await missingAdmission.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("teacher-lineage admission");

        var admissionPath = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            lineageKey,
            "lineage-admission.json");
        var count = await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("teacher-training.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            admissionPath,
            LineageTrust(lineageKeyPath, lineageKey),
            requireProviderUploadRights: true);
        count.Should().Be(1);

        var sameAuthorityAdmission = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            receiptKey,
            "same-authority-admission.json");
        Func<Task> sameAuthority = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("same-authority.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            sameAuthorityAdmission,
            LineageTrust(receiptKeyPath, receiptKey),
            requireProviderUploadRights: true);
        (await sameAuthority.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("distinct signing authorities");
    }

    [Fact]
    public async Task Teacher_lineage_admission_rejects_subject_and_receipt_window_substitution()
    {
        using var workspace = new TestWorkspace();
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var lineageKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var receiptKeyPath = WritePublicKey(workspace, receiptKey, "receipt-window-public.pem");
        var lineageKeyPath = WritePublicKey(workspace, lineageKey, "lineage-window-public.pem");
        var example = CreateTeacherExample("teacher-lineage-substitution");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, receiptKey);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        var forgedSubjectAdmission = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            lineageKey,
            "forged-subject-admission.json",
            stableSubjectSha256: new string('f', 64));
        Func<Task> forgedSubject = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("forged-subject.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            forgedSubjectAdmission,
            LineageTrust(lineageKeyPath, lineageKey),
            requireProviderUploadRights: true);
        (await forgedSubject.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("exact ordered OpenWeightTeacher rows");

        var lateAdmission = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            lineageKey,
            "late-admission.json",
            activationAfterReceiptIssue: true);
        Func<Task> lateReceipt = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("late-receipt.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            lateAdmission,
            LineageTrust(lineageKeyPath, lineageKey),
            requireProviderUploadRights: true);
        (await lateReceipt.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("outside its teacher-lineage admission window");

        var shortAdmission = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            lineageKey,
            "short-admission.json",
            expireBeforeReceipt: true);
        Func<Task> overlongReceipt = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("overlong-receipt.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            shortAdmission,
            LineageTrust(lineageKeyPath, lineageKey),
            requireProviderUploadRights: true);
        (await overlongReceipt.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("outside its teacher-lineage admission window");
    }

    [Fact]
    public async Task Human_only_export_rejects_extraneous_teacher_lineage_admission()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var example = CreateExample("human-extraneous-lineage");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, key);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("human-extraneous.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            workspace.PathFor("unused-admission.json"),
            LineageTrust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("must not be supplied");
    }

    [Fact]
    public async Task Human_labeled_row_cannot_carry_a_teacher_admission_anchor()
    {
        using var workspace = new TestWorkspace();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keyPath = WritePublicKey(workspace, key);
        var teacher = CreateTeacherExample("teacher-origin-downgrade");
        var relabeled = teacher with
        {
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.HumanAuthored,
                Producer = "relabeled-fixture-producer",
                ProducedAtUtc = teacher.Lineage.ProducedAtUtc,
            },
        };
        var datasetPath = await WriteDatasetAsync(workspace, relabeled);
        var receipt = CreateReceipt(datasetPath, relabeled, key);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        Func<Task> export = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("relabeled-teacher.jsonl"),
            receiptSetPath,
            Trust(keyPath, key),
            requireProviderUploadRights: true);

        (await export.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("must not carry a teacherAdmissionSha256 anchor");
    }

    [Fact]
    public async Task Teacher_lineage_admission_rejects_untrusted_and_high_s_signatures()
    {
        using var workspace = new TestWorkspace();
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var trustedLineageKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerLineageKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var receiptKeyPath = WritePublicKey(workspace, receiptKey, "receipt-signature-public.pem");
        var trustedLineageKeyPath = WritePublicKey(
            workspace,
            trustedLineageKey,
            "trusted-lineage-public.pem");
        var example = CreateTeacherExample("teacher-lineage-signature");
        var datasetPath = await WriteDatasetAsync(workspace, example);
        var receipt = CreateReceipt(datasetPath, example, receiptKey);
        var receiptSetPath = WriteReceiptSet(workspace, receipt.Envelope);

        var attackerAdmission = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            attackerLineageKey,
            "attacker-lineage-admission.json");
        Func<Task> untrusted = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("untrusted-lineage.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            attackerAdmission,
            LineageTrust(trustedLineageKeyPath, trustedLineageKey),
            requireProviderUploadRights: true);
        (await untrusted.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("externally pinned trust policy");

        var highSAdmission = WriteTeacherLineageAdmission(
            workspace,
            datasetPath,
            example,
            receipt.Payload,
            trustedLineageKey,
            "high-s-lineage-admission.json",
            highS: true);
        Func<Task> highS = async () => await ExpertModelDatasetTools.ExportSftJsonLinesAsync(
            datasetPath,
            workspace.PathFor("high-s-lineage.jsonl"),
            receiptSetPath,
            Trust(receiptKeyPath, receiptKey),
            highSAdmission,
            LineageTrust(trustedLineageKeyPath, trustedLineageKey),
            requireProviderUploadRights: true);
        (await highS.Should().ThrowAsync<CoordinatorValidationException>()).Which.Message
            .Should().Contain("canonical low-S");
    }

    private static ExpertModelDatasetExample CreateExample(string id)
    {
        var rights = new DatasetRights(true, true, true, true, false);
        LlmMessage[] messages =
        [
            new("system", "Answer as a bounded DaxAlgo expert."),
            new("user", $"Review the exact fixture {id}."),
            new("assistant", $"The reviewed bounded result is {id}.")
        ];
        string[] evidence =
        [
            "knowledgeClass=candidate-stable",
            "verificationManifestSha256=" + new string('1', 64),
            "verificationReportSha256=" + new string('2', 64),
            "reviewManifestSha256=" + new string('3', 64)
        ];
        var producedAt = new DateTimeOffset(2025, 1, 14, 12, 0, 0, TimeSpan.Zero);
        var reviewedAt = new DateTimeOffset(2025, 1, 15, 13, 0, 0, TimeSpan.Zero);
        return new ExpertModelDatasetExample
        {
            SchemaVersion = CoordinatorVersions.ExpertModelDatasetSchema,
            Id = id,
            TaskKind = ExpertTaskKind.QuantitativeReasoning,
            Domains = [ExpertDomain.QuantitativeMath],
            Messages = messages,
            ConversationSha256 = ExpertModelDatasetTools.ComputeConversationSha256(messages),
            Sources =
            [
                new DatasetSourceAsset(
                    "source-" + id,
                    "Licensed fixture",
                    "Exact licensed fixture content.",
                    "Synthetic receipt test.",
                    "Test-only",
                    producedAt,
                    producedAt,
                    null,
                    rights)
            ],
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.HumanAuthored,
                Producer = "fixture-producer",
                ProducedAtUtc = producedAt
            },
            Verification = new ExpertVerificationEvidence
            {
                Verified = true,
                Reviewer = "independent-reviewer-001",
                VerifiedAtUtc = reviewedAt,
                Evidence = evidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(evidence, [], []),
                CompileSucceeded = false,
                CompileEvidence = [],
                TestsPassed = false,
                TestEvidence = []
            },
            Split = "development",
            ContaminationGroup = "family-" + id,
            Provenance = "Synthetic authenticated receipt test.",
            License = "Test-only",
            Rights = rights,
            ReviewStatus = "approved",
            CutoffUtc = new DateTimeOffset(2025, 1, 15, 12, 0, 0, TimeSpan.Zero),
            UseForTraining = true
        };
    }

    private static ExpertModelDatasetExample CreateTeacherExample(string id)
    {
        var basis = CreateExample(id);
        string[] evidence =
        [
            "knowledgeClass=candidate-stable",
            "teacherAdmissionSha256=" + new string('9', 64),
            "verificationManifestSha256=" + new string('1', 64),
            "verificationReportSha256=" + new string('2', 64),
            "reviewManifestSha256=" + new string('3', 64),
        ];
        return basis with
        {
            Lineage = new ExpertModelLineage
            {
                Origin = ExpertDatasetOrigin.OpenWeightTeacher,
                Producer = "teacher-materialization-producer",
                ModelId = "Example/Teacher-7B",
                ModelRevision = new string('a', 40),
                PromptSha256 = new string('b', 64),
                ProfileVersion = "teacher-profile-v2",
                ProducedAtUtc = basis.Lineage.ProducedAtUtc,
            },
            Verification = basis.Verification with
            {
                Evidence = evidence,
                EvidenceSha256 = ExpertModelDatasetTools.ComputeVerificationEvidenceSha256(
                    evidence,
                    [],
                    []),
            },
        };
    }

    private static string WriteTeacherLineageAdmission(
        TestWorkspace workspace,
        string datasetPath,
        ExpertModelDatasetExample example,
        ExpertDatasetReviewReceiptPayload receiptPayload,
        ECDsa signingKey,
        string fileName,
        string? stableSubjectSha256 = null,
        bool activationAfterReceiptIssue = false,
        bool expireBeforeReceipt = false,
        bool highS = false)
    {
        var receiptIssued = DateTimeOffset.ParseExact(
            receiptPayload.IssuedAtUtc,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        var receiptExpires = DateTimeOffset.ParseExact(
            receiptPayload.ExpiresAtUtc,
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        var notBefore = activationAfterReceiptIssue
            ? receiptIssued.AddMinutes(1)
            : receiptIssued.AddMinutes(-1);
        var expiresAt = expireBeforeReceipt
            ? notBefore.AddDays(1)
            : receiptExpires.AddDays(1);
        var datasetBytes = File.ReadAllBytes(datasetPath);
        var payload = new ExpertTeacherLineageAdmissionPayload
        {
            SchemaVersion = ExpertModelTeacherLineageAdmissionTools.PayloadSchemaVersion,
            LineageAdmissionId = "vqtlineage-" + new string('0', 64),
            Scope = ExpertModelTeacherLineageAdmissionTools.Scope,
            Decision = "admitted",
            Reusable = true,
            ReviewReceiptIssuanceAuthorized = true,
            RuntimeAttested = false,
            TeacherWeightsAttested = false,
            TeacherCorrectnessAuthorized = false,
            ReviewDecisionAuthorized = false,
            RightsAuthorized = false,
            ReleaseAuthorized = false,
            TrainingAuthorized = false,
            EvaluationAuthorized = false,
            PromotionDecisionAuthorized = false,
            DeploymentAuthorized = false,
            HostedServingAuthorized = false,
            InstallationAuthorized = false,
            VerifierExecutionAuthorized = false,
            StrategyExecutionAuthorized = false,
            ReviewerId = "teacher-lineage-authority-reviewer",
            ReviewedAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(
                receiptIssued.AddMinutes(-3)),
            IssuedAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(
                receiptIssued.AddMinutes(-2)),
            NotBeforeUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(notBefore),
            ExpiresAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(expiresAt),
            ReviewerEvidence = new ExpertTeacherLineageReviewerEvidence
            {
                Sha256 = new string('4', 64),
                SizeBytes = 1,
            },
            ReviewedCorpus = new ExpertTeacherLineageReviewedCorpus
            {
                Sha256 = Sha256(datasetBytes),
                SizeBytes = datasetBytes.LongLength,
                RecordCount = 1,
                OpenWeightTeacherRecordCount = 1,
                Subjects =
                [
                    new ExpertTeacherLineageSubject
                    {
                        ExampleId = example.Id,
                        StableSubjectSha256 = stableSubjectSha256 ??
                            ExpertModelTeacherLineageAdmissionTools.ComputeStableSubjectSha256(example),
                        KnowledgeClass = "candidate-stable",
                        TeacherAdmissionSha256 = new string('9', 64),
                    },
                ],
            },
            Materialization = new ExpertTeacherLineageMaterialization
            {
                MaterializationId = "vqtmat-" + new string('5', 64),
                MaterializationRecordSha256 = new string('6', 64),
                DraftDatasetSha256 = new string('7', 64),
                DraftDatasetSizeBytes = 1,
                DraftRecordCount = 1,
                PackageTreeSchemaVersion = ExpertModelTeacherLineageAdmissionTools.PackageTreeSchemaVersion,
                PackageTreeSha256 = new string('8', 64),
                PackageFileCount = 1,
                PackageSizeBytes = 1,
                SelectionManifestSha256 = new string('a', 64),
                CandidateSetSha256 = new string('b', 64),
                GenerationManifestSha256 = new string('c', 64),
                CandidateCatalogSha256 = new string('d', 64),
                OverlapDenySetSha256 = new string('e', 64),
                OverlapDenySetId = "deny-set-test-v1",
                OverlapScopeSha256 = new string('f', 64),
                CandidateBatchId = "vqtgen-" + new string('1', 64),
            },
            RuntimeObservation = new ExpertTeacherLineageRuntimeObservation
            {
                EvidenceStatus = "unattested-observation",
                RuntimeBindingFileSha256 = new string('2', 64),
                RuntimeBindingSha256 = new string('3', 64),
                CandidateCatalogSha256 = new string('d', 64),
                RuntimeDescriptorSha256 = new string('4', 64),
                ChatTemplateSha256 = new string('5', 64),
                ExecutionModelId = "daxalgo-teacher-sha256-" + new string('6', 64),
            },
            Statement = ExpertModelTeacherLineageAdmissionTools.Statement,
        };
        payload = payload with { LineageAdmissionId = ComputeTeacherLineageAdmissionId(payload) };
        var payloadBytes = ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(payload);
        var envelope = new ExpertTeacherLineageAdmissionEnvelope
        {
            SchemaVersion = ExpertModelTeacherLineageAdmissionTools.EnvelopeSchemaVersion,
            PayloadType = ExpertModelTeacherLineageAdmissionTools.PayloadSchemaVersion,
            PayloadEncoding = ExpertModelTeacherLineageAdmissionTools.PayloadEncoding,
            PayloadSha256 = Sha256(payloadBytes),
            Payload = Base64Url(payloadBytes),
            Algorithm = ExpertModelTeacherLineageAdmissionTools.Algorithm,
            SignatureFormat = ExpertModelTeacherLineageAdmissionTools.SignatureFormat,
            Audience = LineageAudience,
            KeyId = LineageKeyId,
            SignerRole = LineageSignerRole,
            PublicKeySpkiSha256 = SpkiSha256(signingKey),
            Signature = string.Empty,
        };
        var signature = signingKey.SignData(
            CreateTeacherLineageSignatureInput(envelope, payloadBytes),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        NormalizeSignature(signature, highS);
        envelope = envelope with { Signature = Base64Url(signature) };
        var path = workspace.PathFor(fileName);
        File.WriteAllBytes(
            path,
            [.. ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(envelope), (byte)'\n']);
        return path;
    }

    private static string ComputeTeacherLineageAdmissionId(
        ExpertTeacherLineageAdmissionPayload payload)
    {
        var zeroed = payload with { LineageAdmissionId = "vqtlineage-" + new string('0', 64) };
        var canonical = ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(zeroed);
        return "vqtlineage-" + Sha256(
            [.. Utf8.GetBytes("daxalgo-teacher-materialization-lineage-admission-id/v1\0"), .. canonical]);
    }

    private static byte[] CreateTeacherLineageSignatureInput(
        ExpertTeacherLineageAdmissionEnvelope envelope,
        byte[] payload)
    {
        using var output = new MemoryStream();
        AppendUInt64(
            output,
            Utf8.GetBytes("daxalgo-teacher-materialization-lineage-admission-signature/v1\0"));
        foreach (var value in new[]
                 {
                     envelope.SchemaVersion,
                     envelope.PayloadType,
                     envelope.PayloadEncoding,
                     envelope.Algorithm,
                     envelope.SignatureFormat,
                     envelope.Audience,
                     envelope.KeyId,
                     envelope.SignerRole,
                     envelope.PublicKeySpkiSha256,
                     envelope.PayloadSha256,
                 })
        {
            AppendUInt64(output, Utf8.GetBytes(value));
        }
        AppendUInt64(output, payload);
        return output.ToArray();
    }

    private static void AppendUInt64(Stream output, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)value.Length));
        output.Write(length);
        output.Write(value);
    }

    private static async Task<string> WriteDatasetAsync(
        TestWorkspace workspace,
        ExpertModelDatasetExample first,
        ExpertModelDatasetExample? second = null,
        string fileName = "dataset.jsonl")
    {
        var path = workspace.PathFor(fileName);
        var lines = second is null ? [first] : new[] { first, second };
        await File.WriteAllTextAsync(
            path,
            string.Join('\n', lines.Select(item => JsonSerializer.Serialize(item, CompactJson))) + "\n",
            Utf8);
        return path;
    }

    private static ReceiptFixture CreateReceipt(
        string datasetPath,
        ExpertModelDatasetExample example,
        ECDsa signingKey,
        bool trainingAuthorized = true,
        bool highS = false,
        bool noncanonicalPayload = false,
        bool expired = false,
        string? approvalReference = null,
        long? approvalEvidenceSizeBytes = null,
        string? sftMetadataSha256 = null,
        string? verificationEvidenceSha256 = null)
    {
        var now = DateTimeOffset.UtcNow;
        var issuedAt = new DateTimeOffset(
            now.UtcDateTime.Year,
            now.UtcDateTime.Month,
            now.UtcDateTime.Day,
            now.UtcDateTime.Hour,
            now.UtcDateTime.Minute,
            now.UtcDateTime.Second,
            TimeSpan.Zero).AddMinutes(-10);
        var notBefore = issuedAt.AddMinutes(1);
        var expiresAt = expired ? issuedAt.AddMinutes(2) : issuedAt.AddDays(30);
        var approvalAt = issuedAt.AddMinutes(-1);
        var sourceCorpusSha256 = Sha256(File.ReadAllBytes(datasetPath));
        var metadata = UnsignedMetadata(example, sourceCorpusSha256);
        var payload = new ExpertDatasetReviewReceiptPayload
        {
            SchemaVersion = ExpertModelDatasetReviewReceiptTools.PayloadSchemaVersion,
            ReceiptId = ExpertModelDatasetReviewReceiptTools.ReceiptIdPrefix + new string('0', 64),
            Decision = ExpertModelDatasetReviewReceiptTools.ApprovedDecision,
            SourceCorpusSha256 = sourceCorpusSha256,
            ExampleId = example.Id,
            TaskKind = example.TaskKind.ToString(),
            Domains = example.Domains.Select(domain => domain.ToString()).ToArray(),
            ConversationSha256 = example.ConversationSha256,
            VerificationEvidenceSha256 = verificationEvidenceSha256 ??
                example.Verification.EvidenceSha256,
            ReviewedAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(
                example.Verification.VerifiedAtUtc!.Value),
            Reviewer = example.Verification.Reviewer,
            ReviewKind = ExpertModelDatasetReviewReceiptTools.DeterministicTextReviewKind,
            SftMetadataSha256 = sftMetadataSha256 ??
                ExpertModelDatasetReviewReceiptTools.ComputeCanonicalJsonSha256(metadata),
            Authorizations = new ExpertDatasetReviewReceiptAuthorizations
            {
                Evaluation = true,
                Training = trainingAuthorized,
                ProviderUpload = trainingAuthorized
            },
            Approval = new ExpertDatasetReviewReceiptApproval
            {
                ApprovalId = "approval-" + example.Id,
                ActorId = "review-authority-001",
                ActorRole = SignerRole,
                Reference = approvalReference ?? "test-review-evidence",
                EvidenceSha256 = Sha256(Utf8.GetBytes("test-review-evidence")),
                EvidenceSizeBytes = approvalEvidenceSizeBytes ?? Utf8.GetByteCount("test-review-evidence"),
                ApprovedAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(approvalAt)
            },
            IssuedAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(issuedAt),
            NotBeforeUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(notBefore),
            ExpiresAtUtc = ExpertModelDatasetReviewReceiptTools.CanonicalUtc(expiresAt)
        };
        payload = payload with
        {
            ReceiptId = ExpertModelDatasetReviewReceiptTools.ComputeReceiptId(payload)
        };
        var payloadBytes = ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(payload);
        if (noncanonicalPayload)
        {
            payloadBytes = [.. payloadBytes, (byte)'\n'];
        }
        var spkiSha256 = SpkiSha256(signingKey);
        var envelope = new ExpertDatasetReviewReceiptEnvelope
        {
            SchemaVersion = ExpertModelDatasetReviewReceiptTools.EnvelopeSchemaVersion,
            PayloadType = ExpertModelDatasetReviewReceiptTools.PayloadSchemaVersion,
            PayloadEncoding = ExpertModelDatasetReviewReceiptTools.PayloadEncoding,
            PayloadSha256 = Sha256(payloadBytes),
            Payload = Base64Url(payloadBytes),
            Algorithm = ExpertModelDatasetReviewReceiptTools.Algorithm,
            SignatureFormat = ExpertModelDatasetReviewReceiptTools.SignatureFormat,
            Audience = Audience,
            KeyId = KeyId,
            SignerRole = SignerRole,
            PublicKeySpkiSha256 = spkiSha256,
            Signature = string.Empty
        };
        var signature = signingKey.SignData(
            CreateSignatureInput(envelope, payloadBytes),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        NormalizeSignature(signature, highS);
        envelope = envelope with { Signature = Base64Url(signature) };
        return new ReceiptFixture(payload, envelope);
    }

    private static object UnsignedMetadata(
        ExpertModelDatasetExample example,
        string sourceCorpusSha256) => new
        {
            schemaVersion = ExpertModelDatasetReviewReceiptTools.SftMetadataSchemaVersion,
            sourceCorpusSha256,
            verificationEvidenceSha256 = example.Verification.EvidenceSha256,
            id = example.Id,
            taskKind = example.TaskKind.ToString(),
            domains = example.Domains.Select(domain => domain.ToString()).ToArray(),
            conversationSha256 = example.ConversationSha256,
            origin = example.Lineage.Origin.ToString(),
            producer = example.Lineage.Producer,
            modelId = example.Lineage.ModelId,
            modelRevision = example.Lineage.ModelRevision,
            promptSha256 = example.Lineage.PromptSha256,
            profileVersion = example.Lineage.ProfileVersion,
            split = example.Split,
            contaminationGroup = example.ContaminationGroup,
            cutoffUtc = ExpertModelDatasetReviewReceiptTools.CanonicalSftCutoffUtc(example.CutoffUtc),
            sourceSchema = example.SchemaVersion
        };

    private static object LegacyUnsignedMetadata(ExpertModelDatasetExample example) => new
    {
        id = example.Id,
        taskKind = example.TaskKind.ToString(),
        domains = example.Domains.Select(domain => domain.ToString()).ToArray(),
        conversationSha256 = example.ConversationSha256,
        origin = example.Lineage.Origin.ToString(),
        producer = example.Lineage.Producer,
        modelId = example.Lineage.ModelId,
        modelRevision = example.Lineage.ModelRevision,
        promptSha256 = example.Lineage.PromptSha256,
        profileVersion = example.Lineage.ProfileVersion,
        split = example.Split,
        contaminationGroup = example.ContaminationGroup,
        cutoffUtc = ExpertModelDatasetReviewReceiptTools.CanonicalSftCutoffUtc(example.CutoffUtc),
        sourceSchema = example.SchemaVersion
    };

    private static ExpertDatasetReviewReceiptEnvelope SignReceiptEnvelope(
        ExpertDatasetReviewReceiptEnvelope basis,
        byte[] payload,
        ECDsa signingKey)
    {
        var envelope = basis with
        {
            PayloadSha256 = Sha256(payload),
            Payload = Base64Url(payload),
            Signature = string.Empty
        };
        var signature = signingKey.SignData(
            CreateSignatureInput(envelope, payload),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        NormalizeSignature(signature, highS: false);
        return envelope with { Signature = Base64Url(signature) };
    }

    private static byte[] CreateSignatureInput(
        ExpertDatasetReviewReceiptEnvelope envelope,
        byte[] payload)
    {
        using var output = new MemoryStream();
        Append(output, ExpertModelDatasetReviewReceiptTools.SignatureDomain);
        foreach (var value in new[]
                 {
                     envelope.SchemaVersion,
                     envelope.PayloadType,
                     envelope.PayloadEncoding,
                     envelope.Algorithm,
                     envelope.SignatureFormat,
                     envelope.Audience,
                     envelope.KeyId,
                     envelope.SignerRole,
                     envelope.PublicKeySpkiSha256,
                     envelope.PayloadSha256
                 })
        {
            Append(output, value);
        }
        Append(output, payload);
        return output.ToArray();
    }

    private static void Append(Stream output, string value) => Append(output, Utf8.GetBytes(value));

    private static void Append(Stream output, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        output.Write(length);
        output.Write(value);
    }

    private static void NormalizeSignature(byte[] signature, bool highS)
    {
        var s = new BigInteger(signature.AsSpan(32), isUnsigned: true, isBigEndian: true);
        if (s > P256Order / 2)
        {
            s = P256Order - s;
        }
        if (highS)
        {
            s = P256Order - s;
        }
        var encoded = s.ToByteArray(isUnsigned: true, isBigEndian: true);
        signature.AsSpan(32).Clear();
        encoded.CopyTo(signature.AsSpan(64 - encoded.Length));
    }

    private static string WritePublicKey(
        TestWorkspace workspace,
        ECDsa key,
        string fileName = "review-public.pem")
    {
        var path = workspace.PathFor(fileName);
        File.WriteAllText(path, key.ExportSubjectPublicKeyInfoPem(), Utf8);
        return path;
    }

    private static string WriteReceiptSet(
        TestWorkspace workspace,
        ExpertDatasetReviewReceiptEnvelope envelope,
        string fileName = "receipts.jsonl")
    {
        var path = workspace.PathFor(fileName);
        File.WriteAllBytes(
            path,
            [.. ExpertModelDatasetReviewReceiptTools.SerializeCanonicalJson(envelope), (byte)'\n']);
        return path;
    }

    private static ExpertDatasetReviewReceiptTrust Trust(string publicKeyPath, ECDsa key) =>
        new(publicKeyPath, SpkiSha256(key), Audience, KeyId, SignerRole);

    private static ExpertTeacherLineageAdmissionTrust LineageTrust(
        string publicKeyPath,
        ECDsa key) =>
        new(
            publicKeyPath,
            SpkiSha256(key),
            LineageAudience,
            LineageKeyId,
            LineageSignerRole);

    private static string SpkiSha256(ECDsa key) => Sha256(key.ExportSubjectPublicKeyInfo());

    private static string Sha256(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record ReceiptFixture(
        ExpertDatasetReviewReceiptPayload Payload,
        ExpertDatasetReviewReceiptEnvelope Envelope);

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}
