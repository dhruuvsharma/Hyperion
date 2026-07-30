from __future__ import annotations

import hashlib
import io
import inspect
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import vibe_quant_model.cli as cli_module
import vibe_quant_model.training as training_module
from vibe_quant_model.artifacts import (
    TRAINING_ARTIFACT_SCHEMA_VERSION,
    build_artifact_file_index,
    finalize_training_artifact_core,
    prepare_training_artifact_core,
    seal_training_artifact,
    validate_training_artifact,
)
from vibe_quant_model.core import (
    DOMAINS,
    MAX_SFT_BYTES,
    SFT_METADATA_SCHEMA_VERSION,
    ValidationError,
    _copy_file_snapshot,
    create_bundle,
    expert_conversation_sha256,
    sha256_file,
    summarize_sft,
    validate_bundle,
    validate_candidate_catalog,
    validate_manifest_path,
    validate_sft,
    validate_chat_template,
)
from vibe_quant_model.evaluation_authoring import EvaluationAuthoringApprovalTrust
from vibe_quant_model.training import (
    PreflightError,
    gpu_memory_preflight,
    load_training_dependencies,
)
from vibe_quant_model.runtime import (
    DIRECT_DEPENDENCY_VERSIONS,
    validate_pylock_train,
    validate_training_runtime_profile,
)
from vibe_quant_model.review_receipts import ExpertModelReviewReceiptTrust
from vibe_quant_model.trainer_provenance import TrainerProvenanceTrust


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PROFILE = ROOT / "training-runtime-profile.v1.json"
TEST_RELEASE_IDENTITY = {
    "releaseId": "vqrel-" + "a" * 64,
    "releaseSha256": "a" * 64,
    "manifestSha256": "b" * 64,
}
TEST_REVIEW_RECEIPT_TRUST = ExpertModelReviewReceiptTrust(
    Path("test-review-receipt-public.pem"),
    "c" * 64,
    "test-training-audience",
    "test-training-key",
    "test-training-reviewer",
)
TEST_EVALUATION_AUTHORING_TRUST = EvaluationAuthoringApprovalTrust(
    Path("test-evaluation-authoring-public.pem"),
    "d" * 64,
    "test-evaluation-authoring-audience",
    "test-evaluation-authoring-key",
    "test-evaluation-authoring-reviewer",
)


def _with_authenticated_release_test_double(test):
    """Isolate non-receipt harness tests behind a release-boundary double."""

    @wraps(test)
    def wrapped(*args, **kwargs):
        with mock.patch(
            "vibe_quant_model.release.validate_training_release_binding",
            return_value=(
                {
                    "corpus": {
                        "reviewReceipts": {"expiresAtUtc": "9999-12-31T23:59:59Z"}
                    },
                    "evaluation": {
                        "authoringApproval": {"expiresAtUtc": "9999-12-31T23:59:59Z"}
                    },
                },
                TEST_RELEASE_IDENTITY,
            ),
        ):
            return test(*args, **kwargs)

    return wrapped


def _training_release_arguments(root: Path) -> dict:
    return {
        "data_release_path": root / "test-authenticated-release",
        "review_receipt_trust": TEST_REVIEW_RECEIPT_TRUST,
        "evaluation_authoring_approval_trust": (TEST_EVALUATION_AUTHORING_TRUST),
    }


def _row(
    example_id: str,
    *,
    domains: list[str] | None = None,
    split: str = "development",
    group: str | None = None,
    answer: str | None = None,
    task_kind: str = "GeneralQuestionAnswering",
) -> dict:
    messages = [
        {"role": "system", "content": "Answer only with reviewed evidence."},
        {"role": "user", "content": f"Question for {example_id}?"},
        {
            "role": "assistant",
            "content": answer or f"Reviewed answer for {example_id}.",
        },
    ]
    return {
        "messages": messages,
        "metadata": {
            "id": example_id,
            "taskKind": task_kind,
            "domains": domains or ["FinanceMarkets"],
            "conversationSha256": expert_conversation_sha256(messages),
            "origin": "HumanAuthored",
            "producer": "unit-test",
            "modelId": None,
            "modelRevision": None,
            "promptSha256": None,
            "profileVersion": None,
            "split": split,
            "contaminationGroup": group or f"group-{example_id}",
            "cutoffUtc": "2025-01-15T12:00:00+00:00",
            "sourceSchema": "expert-model-dataset/v1",
        },
    }


def _write_jsonl(path: Path, *rows: dict) -> None:
    text = "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        for row in rows
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_pinned_catalog(path: Path) -> dict:
    catalog = json.loads(
        (ROOT / "candidate-catalog.v1.json").read_text(encoding="utf-8")
    )
    path.write_text(
        json.dumps(catalog, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return catalog


def _create_valid_bundle(
    root: Path,
    name: str = "bundle",
    *,
    after_snapshot=None,
    bind_release: bool = False,
) -> tuple[Path, Path, Path, Path]:
    catalog = root / f"{name}-catalog.json"
    _write_pinned_catalog(catalog)
    sft = root / f"{name}-training.jsonl"
    _write_jsonl(sft, _row(f"{name}-all-domains", domains=list(DOMAINS)))
    template = root / f"{name}-chat-template.jinja"
    template.write_text(
        "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
        encoding="utf-8",
    )
    bundle = root / name
    create_bundle(
        catalog_path=catalog,
        sft_path=sft,
        candidate_id="qwen2.5-coder-7b-instruct",
        chat_template_path=template,
        chat_template_name="reviewed-test-template-v1",
        output_directory=bundle,
        runtime_profile_path=RUNTIME_PROFILE,
        **(_training_release_arguments(root) if bind_release else {}),
        _after_snapshot=after_snapshot,
    )
    return bundle, catalog, sft, template


def _fake_training_importer():
    class FakeCuda:
        @staticmethod
        def is_available() -> bool:
            return True

        @staticmethod
        def device_count() -> int:
            return 1

        @staticmethod
        def get_device_properties(index: int):
            return SimpleNamespace(
                name="Test GPU",
                total_memory=24 * 1024**3,
                major=9,
                minor=0,
                multi_processor_count=128,
            )

        @staticmethod
        def is_bf16_supported() -> bool:
            return True

    modules = {
        name: SimpleNamespace(__version__=DIRECT_DEPENDENCY_VERSIONS[name])
        for name in training_module.TRAINING_DEPENDENCIES
    }
    modules["torch"] = SimpleNamespace(
        __version__=DIRECT_DEPENDENCY_VERSIONS["torch"],
        cuda=FakeCuda(),
        bfloat16="torch.bfloat16",
        float16="torch.float16",
        version=SimpleNamespace(cuda="12.1"),
    )
    return lambda name: modules[name]


def _locked_runtime_facts() -> dict:
    return {
        "python": {"implementation": "CPython", "major": 3, "minor": 11},
        "platform": {"system": "Linux", "machine": "x86_64"},
        "cuda": {"runtimeVersion": "12.1"},
        "directDependencies": dict(DIRECT_DEPENDENCY_VERSIONS),
    }


def _locked_runtime_host_facts() -> dict:
    facts = _locked_runtime_facts()
    return {"python": facts["python"], "platform": facts["platform"]}


def _train_synthetic_artifact(root: Path, name: str) -> tuple[Path, dict]:
    bundle, _, _, _ = _create_valid_bundle(root, name, bind_release=True)
    manifest_path = bundle / "training-run-manifest.json"

    def fake_training(manifest, dependencies, records, output_path, **kwargs) -> None:
        _write_safe_inference_files(output_path, manifest)

    with (
        mock.patch.object(training_module, "_run_training", side_effect=fake_training),
        mock.patch(
            "vibe_quant_model.runtime.runtime_facts",
            return_value=_locked_runtime_facts(),
        ),
        mock.patch(
            "vibe_quant_model.runtime.runtime_host_facts",
            return_value=_locked_runtime_host_facts(),
        ),
    ):
        result = training_module.train_from_manifest(
            manifest_path,
            smoke=True,
            importer=_fake_training_importer(),
            **_training_release_arguments(root),
        )
    return bundle / "outputs" / "adapter", result


def _write_safe_inference_files(output_path: Path, manifest: dict) -> None:
    header = b'{"adapter":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}'
    (output_path / "adapter_model.safetensors").write_bytes(
        len(header).to_bytes(8, byteorder="little") + header + b"\x00\x00"
    )
    (output_path / "adapter_config.json").write_text(
        json.dumps(
            {
                "base_model_name_or_path": manifest["baseModel"]["modelId"],
                "peft_type": "LORA",
                "task_type": "CAUSAL_LM",
                "bias": "none",
                "r": manifest["hyperparameters"]["loraR"],
                "lora_alpha": manifest["hyperparameters"]["loraAlpha"],
                "lora_dropout": manifest["hyperparameters"]["loraDropout"],
                "target_modules": manifest["hyperparameters"]["loraTargetModules"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (output_path / "tokenizer_config.json").write_text(
        json.dumps(
            {
                "model_max_length": 8192,
                "chat_template": manifest["chatTemplate"]["template"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (output_path / "tokenizer.json").write_bytes(b'{"version":"1.0"}\n')
    (output_path / "special_tokens_map.json").write_bytes(b'{"eos_token":"<eos>"}\n')


def _artifact_metadata_inputs(artifact: dict) -> dict:
    computed_fields = {
        "schemaVersion",
        "artifactSha256",
        "fileTreeSha256",
        "files",
        "trainerProvenance",
    }
    return {
        name: value for name, value in artifact.items() if name not in computed_fields
    }


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_training_receipt_guard_fails_at_the_exact_expiry(self) -> None:
        expires = datetime(2026, 8, 1, tzinfo=timezone.utc)
        training_module._ensure_receipt_authorization_active(
            expires,
            lambda: datetime(2026, 7, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(ValidationError, "expired during the run"):
            training_module._ensure_receipt_authorization_active(
                expires,
                lambda: expires,
            )

    def test_directory_publication_interrupt_cleans_owned_inode_and_preserves_races(
        self,
    ) -> None:
        for raced_replacement in (False, True):
            with self.subTest(raced_replacement=raced_replacement):
                source = self.root / f"source-{raced_replacement}"
                destination = self.root / f"destination-{raced_replacement}"
                source.mkdir()
                (source / "owned.txt").write_text("owned", encoding="utf-8")

                def rename_then_interrupt(source_path, destination_path, field):
                    os.rename(source_path, destination_path)
                    if raced_replacement:
                        source_path.mkdir()
                        (source_path / "replacement.txt").write_text(
                            "preserve", encoding="utf-8"
                        )
                    raise KeyboardInterrupt("interrupt after rename")

                with mock.patch.object(
                    training_module,
                    "_install_directory_no_clobber",
                    side_effect=rename_then_interrupt,
                ):
                    if raced_replacement:
                        with self.assertRaisesRegex(
                            ValidationError, "raced replacement preserved"
                        ):
                            training_module._publish_directory_no_clobber(
                                source,
                                destination,
                                "test publication",
                                validator=lambda path: path,
                            )
                    else:
                        with self.assertRaises(KeyboardInterrupt):
                            training_module._publish_directory_no_clobber(
                                source,
                                destination,
                                "test publication",
                                validator=lambda path: path,
                            )
                self.assertFalse(destination.exists())
                if raced_replacement:
                    self.assertEqual(
                        "preserve",
                        (source / "replacement.txt").read_text(encoding="utf-8"),
                    )
                else:
                    self.assertFalse(source.exists())

        stage = self.root / "owned-stage"
        child = stage / "artifact"
        child.mkdir(parents=True)
        stage_identity = training_module._directory_identity(stage, "test stage")
        child_identity = training_module._directory_identity(child, "test child")
        child.rename(self.root / "original-child")
        child.mkdir()
        (child / "replacement.txt").write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "raced replacement preserved"):
            training_module._cleanup_owned_stage(
                stage,
                stage_identity,
                "test stage",
                protected_children=((child, child_identity),),
            )
        self.assertEqual(
            "preserve", (child / "replacement.txt").read_text(encoding="utf-8")
        )

    def test_trainer_provenance_cli_trust_is_all_or_none(self) -> None:
        empty = SimpleNamespace(
            trainer_provenance_public_key=None,
            trainer_provenance_public_key_spki_sha256=None,
            trainer_provenance_audience=None,
            trainer_provenance_key_id=None,
            trainer_provenance_signer_role=None,
        )
        self.assertIsNone(cli_module._trainer_provenance_trust(empty))

        partial = SimpleNamespace(**vars(empty))
        partial.trainer_provenance_public_key = self.root / "trainer-public.pem"
        with self.assertRaisesRegex(ValidationError, "all five"):
            cli_module._trainer_provenance_trust(partial)

        complete = SimpleNamespace(
            trainer_provenance_public_key=self.root / "trainer-public.pem",
            trainer_provenance_public_key_spki_sha256="a" * 64,
            trainer_provenance_audience="trainer-audience",
            trainer_provenance_key_id="trainer-key-v1",
            trainer_provenance_signer_role="trainer-authority",
        )
        self.assertIsInstance(
            cli_module._trainer_provenance_trust(complete),
            TrainerProvenanceTrust,
        )
        artifact = self.root / "password-only-artifact"
        artifact.mkdir()
        with self.assertRaisesRegex(ValidationError, "without the trainer private key"):
            seal_training_artifact(
                artifact,
                {},
                trainer_private_key_password=b"unused-secret",
            )

        parser = cli_module._parser()
        command_action = next(
            action for action in parser._actions if action.dest == "command"
        )
        finalize_parser = command_action.choices["finalize-training-artifact"]
        finalize_options = {
            option
            for action in finalize_parser._actions
            for option in action.option_strings
        }
        self.assertIn("--handoff", finalize_options)
        self.assertIn("--signature", finalize_options)
        self.assertNotIn("--trainer-private-key", finalize_options)
        self.assertNotIn("--trainer-private-key-password-env", finalize_options)
        finalize_parameters = inspect.signature(
            training_module.finalize_training_artifact_from_handoff
        ).parameters
        self.assertNotIn("trainer_private_key_path", finalize_parameters)
        self.assertNotIn("trainer_private_key_password", finalize_parameters)

    def test_optional_release_consumers_require_complete_three_party_authority(
        self,
    ) -> None:
        bundle, catalog, sft, template = _create_valid_bundle(
            self.root, "authority-source"
        )
        with self.assertRaisesRegex(ValidationError, "required together"):
            create_bundle(
                catalog_path=catalog,
                sft_path=sft,
                candidate_id="qwen2.5-coder-7b-instruct",
                chat_template_path=template,
                chat_template_name="reviewed-test-template-v1",
                output_directory=self.root / "partial-authority-bundle",
                runtime_profile_path=RUNTIME_PROFILE,
                data_release_path=self.root / "release",
                review_receipt_trust=TEST_REVIEW_RECEIPT_TRUST,
            )
        with self.assertRaisesRegex(ValidationError, "required together"):
            training_module.train_from_manifest(
                bundle / "training-run-manifest.json",
                evaluation_authoring_approval_trust=(TEST_EVALUATION_AUTHORING_TRUST),
            )
        artifact = self.root / "partial-authority-artifact"
        artifact.mkdir()
        with self.assertRaisesRegex(ValidationError, "required together"):
            seal_training_artifact(
                artifact,
                {},
                review_receipt_trust=TEST_REVIEW_RECEIPT_TRUST,
            )

    def test_conversation_hash_matches_the_cross_platform_contract(self) -> None:
        messages = [
            {"role": "system", "content": "DaxAlgo expert v1"},
            {"role": "user", "content": "Price > 100? π = 3.14\nRisk: 1%"},
            {"role": "assistant", "content": "Use < & > safely. 🚀"},
        ]

        self.assertEqual(
            "83a92500a6825b04b0096f4b521a60fc8bd539e7fe0dec021b7bd19bd3149310",
            expert_conversation_sha256(messages),
        )

    def test_checked_in_catalog_pins_every_official_revision_and_rejects_placeholders(
        self,
    ) -> None:
        checked_in = validate_candidate_catalog(ROOT / "candidate-catalog.v1.json")
        self.assertEqual(
            {
                "qwen2.5-coder-7b-instruct": "c03e6d358207e414f1eca0bb1891e29f1db0e242",
                "qwen2.5-coder-14b-instruct": "aedcc2d42b622764e023cf882b6652e646b95671",
                "gpt-oss-20b": "6cee5e81ee83917806bbde320786a8fb61efebee",
                "qwen3-coder-30b-a3b-instruct": "b2cff646eb4bb1d68355c01b18ae02e7cf42d120",
            },
            {
                candidate["id"]: candidate["revision"]
                for candidate in checked_in["candidates"]
            },
        )

        placeholder = json.loads(json.dumps(checked_in))
        placeholder["candidates"][0]["revision"] = "REPLACE_WITH_40_HEX_COMMIT_SHA"
        placeholder_path = self.root / "placeholder-catalog.json"
        placeholder_path.write_text(json.dumps(placeholder), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "placeholder must be replaced"):
            validate_candidate_catalog(placeholder_path)

        pinned = self.root / "catalog.json"
        catalog = _write_pinned_catalog(pinned)
        validated = validate_candidate_catalog(pinned)

        self.assertEqual(4, len(validated["candidates"]))
        self.assertEqual(
            hashlib.sha256(pinned.read_bytes()).hexdigest(), sha256_file(pinned)
        )
        self.assertEqual(catalog, validated)

    def test_chat_template_rejects_short_and_case_insensitive_placeholders(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValidationError, "at least 64"):
            validate_chat_template("x")
        placeholder = (
            "{% for message in messages %}{{ message['role'] }}: "
            "{{ message['content'] }}{% endfor %} todo"
        )
        with self.assertRaisesRegex(ValidationError, "unresolved"):
            validate_chat_template(placeholder)
        with self.assertRaisesRegex(ValidationError, "unresolved"):
            validate_chat_template(
                placeholder.replace("todo", "replace_with_model_template")
            )

    def test_sft_validation_is_strict_and_recomputes_conversation_hash(self) -> None:
        sft = self.root / "dataset.jsonl"
        valid = _row("strict")
        _write_jsonl(sft, valid)
        self.assertEqual(1, validate_sft(sft).record_count)

        unexpected = json.loads(json.dumps(valid))
        unexpected["metadata"]["unexpected"] = True
        _write_jsonl(sft, unexpected)
        with self.assertRaisesRegex(ValidationError, "unsupported keys"):
            validate_sft(sft)

        tampered = json.loads(json.dumps(valid))
        tampered["messages"][-1]["content"] = "Changed after export."
        _write_jsonl(sft, tampered)
        with self.assertRaisesRegex(
            ValidationError, "does not match canonical message content"
        ):
            validate_sft(sft)

        hosted = _row("hosted-teacher")
        hosted["metadata"].update(
            {
                "origin": "HostedTeacher",
                "modelId": "provider/gpt-teacher",
                "modelRevision": "gpt-teacher-2026-07-27",
                "promptSha256": "a" * 64,
                "profileVersion": "expert-teacher/v1",
            }
        )
        _write_jsonl(sft, hosted)
        self.assertEqual(1, validate_sft(sft).record_count)

        hosted["metadata"]["origin"] = "OpenWeightTeacher"
        hosted["metadata"]["modelRevision"] = "main"
        _write_jsonl(sft, hosted)
        with self.assertRaisesRegex(
            ValidationError, "40-character immutable source commit"
        ):
            validate_sft(sft)

    def test_sft_validation_accepts_closed_v2_metadata_and_rejects_mixing(self) -> None:
        sft = self.root / "metadata-v2.jsonl"
        current = _row("metadata-v2")
        current["metadata"].update(
            {
                "schemaVersion": SFT_METADATA_SCHEMA_VERSION,
                "sourceCorpusSha256": "a" * 64,
                "verificationEvidenceSha256": "b" * 64,
            }
        )
        _write_jsonl(sft, current)
        self.assertEqual(1, validate_sft(sft).record_count)

        unknown = json.loads(json.dumps(current))
        unknown["metadata"]["schemaVersion"] = "daxalgo.expert-model-sft-metadata/v3"
        _write_jsonl(sft, unknown)
        with self.assertRaisesRegex(ValidationError, "metadata.schemaVersion"):
            validate_sft(sft)

        missing_binding = json.loads(json.dumps(current))
        del missing_binding["metadata"]["verificationEvidenceSha256"]
        _write_jsonl(sft, missing_binding)
        with self.assertRaisesRegex(ValidationError, "missing keys"):
            validate_sft(sft)

        _write_jsonl(sft, _row("metadata-v1"), current)
        with self.assertRaisesRegex(ValidationError, "homogeneous metadata schema"):
            validate_sft(sft)

    def test_standalone_sft_validation_is_structural_not_authorization(
        self,
    ) -> None:
        sft = self.root / "unreceipted-corpus.jsonl"

        cases = (
            ("GeneralQuestionAnswering", ["FinanceMarkets"]),
            ("RiskAnalysis", ["RiskManagement"]),
            ("CodeGeneration", ["CSharp"]),
            ("WpfUiDesign", ["WpfUiDesign"]),
        )
        for index, (task_kind, domains) in enumerate(cases):
            _write_jsonl(
                sft,
                _row(
                    f"unreceipted-{index}",
                    task_kind=task_kind,
                    domains=domains,
                ),
            )

            with self.subTest(task_kind=task_kind, domains=domains):
                self.assertEqual(1, validate_sft(sft).record_count)

    def test_private_training_snapshot_is_structural_after_release_boundary(
        self,
    ) -> None:
        row = _row(
            "snapshot-general",
            task_kind="GeneralQuestionAnswering",
            domains=list(DOMAINS),
        )
        raw = (
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        manifest = {
            "dataset": {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "recordCount": 1,
                "sourceSchemaVersions": ["expert-model-dataset/v1"],
            }
        }

        summary, records = training_module._validate_dataset_snapshot(
            raw,
            self.root / "private-training-snapshot.jsonl",
            manifest,
        )
        self.assertEqual(1, summary.record_count)
        self.assertEqual("snapshot-general", records[0]["metadata"]["id"])

    def test_unbound_bundle_cannot_train_even_in_smoke_mode(self) -> None:
        bundle, _, _, _ = _create_valid_bundle(self.root, "unbound-smoke")
        manifest_path = bundle / "training-run-manifest.json"
        with mock.patch.object(training_module, "_run_training") as runner:
            with self.assertRaisesRegex(ValidationError, "validated training release"):
                training_module.train_from_manifest(
                    manifest_path,
                    smoke=True,
                    importer=_fake_training_importer(),
                )
            runner.assert_not_called()

    def test_oversized_sft_is_rejected_before_read_or_snapshot_copy(self) -> None:
        oversized = self.root / "oversized.jsonl"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_SFT_BYTES + 1)

        with mock.patch.object(
            Path, "read_bytes", side_effect=AssertionError("must not allocate")
        ):
            with self.assertRaisesRegex(ValidationError, "exceeds"):
                validate_sft(oversized)
        with self.assertRaisesRegex(ValidationError, "exceeds"):
            sha256_file(oversized, max_bytes=MAX_SFT_BYTES)

        snapshot = self.root / "snapshot.jsonl"
        with self.assertRaisesRegex(ValidationError, "snapshot limit"):
            _copy_file_snapshot(
                oversized,
                snapshot,
                "oversized SFT",
                max_bytes=MAX_SFT_BYTES,
            )
        self.assertFalse(snapshot.exists())

    def test_split_and_domain_coverage_and_contamination_are_reported(self) -> None:
        sft = self.root / "coverage.jsonl"
        development = _row("dev", domains=["FinanceMarkets", "QuantitativeMath"])
        calibration = _row(
            "cal",
            domains=["RiskManagement"],
            split="calibration",
            group="calibration-family",
        )
        _write_jsonl(sft, development, calibration)

        coverage = summarize_sft(sft)

        self.assertEqual({"development": 1, "calibration": 1}, coverage["splitCounts"])
        self.assertEqual(1, coverage["domainCounts"]["QuantitativeMath"])
        self.assertIn("PortfolioManagement", coverage["missingDomains"])

        calibration["metadata"]["contaminationGroup"] = development["metadata"][
            "contaminationGroup"
        ]
        _write_jsonl(sft, development, calibration)
        with self.assertRaisesRegex(ValidationError, "crosses split boundary"):
            validate_sft(sft)

    def test_bundle_hashes_manifest_bindings_and_detects_tampering(self) -> None:
        catalog = self.root / "catalog.json"
        _write_pinned_catalog(catalog)
        sft = self.root / "training.jsonl"
        _write_jsonl(sft, _row("all-domains", domains=list(DOMAINS)))
        template = self.root / "chat-template.jinja"
        template.write_text(
            "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
            encoding="utf-8",
        )
        bundle = self.root / "bundle"

        created = create_bundle(
            catalog_path=catalog,
            sft_path=sft,
            candidate_id="qwen2.5-coder-7b-instruct",
            chat_template_path=template,
            chat_template_name="reviewed-test-template-v1",
            output_directory=bundle,
            runtime_profile_path=RUNTIME_PROFILE,
        )

        manifest = validate_manifest_path(bundle / "training-run-manifest.json")
        checked = validate_bundle(bundle)
        self.assertFalse(created["trainingStarted"])
        self.assertEqual(created["runId"], manifest["runId"])
        self.assertEqual(created["bundleSha256"], checked["bundleSha256"])
        self.assertEqual(list(DOMAINS), manifest["domains"])
        self.assertEqual("QLoRA-SFT", manifest["method"])
        self.assertEqual(
            DIRECT_DEPENDENCY_VERSIONS,
            validate_training_runtime_profile(RUNTIME_PROFILE)["directDependencies"],
        )
        validate_pylock_train(
            ROOT / "pylock.train.toml",
            validate_training_runtime_profile(RUNTIME_PROFILE),
        )
        self.assertEqual(
            "inputs/training-runtime-profile.json",
            manifest["trainingRuntime"]["profile"]["path"],
        )
        self.assertEqual(
            "inputs/pylock.train.toml",
            manifest["trainingRuntime"]["pylock"]["path"],
        )

        dataset_copy = bundle / "inputs" / "dataset.sft.jsonl"
        dataset_copy.write_bytes(dataset_copy.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValidationError, "does not match"):
            validate_manifest_path(bundle / "training-run-manifest.json")
        with self.assertRaisesRegex(ValidationError, "does not match"):
            validate_bundle(bundle)

        teacher_bundle = self.root / "teacher-bundle"
        with self.assertRaisesRegex(ValidationError, "student role"):
            create_bundle(
                catalog_path=catalog,
                sft_path=sft,
                candidate_id="qwen3-coder-30b-a3b-instruct",
                chat_template_path=template,
                chat_template_name="reviewed-test-template-v1",
                output_directory=teacher_bundle,
                runtime_profile_path=RUNTIME_PROFILE,
            )

    def test_bundle_snapshots_sources_and_never_clobbers_an_existing_destination(
        self,
    ) -> None:
        catalog = self.root / "catalog.json"
        _write_pinned_catalog(catalog)
        sft = self.root / "training.jsonl"
        _write_jsonl(sft, _row("snapshot-all-domains", domains=list(DOMAINS)))
        template = self.root / "template.jinja"
        template.write_text(
            "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
            encoding="utf-8",
        )

        def mutate_sources() -> None:
            catalog.write_text("{}", encoding="utf-8")
            sft.write_text("changed", encoding="utf-8")
            template.write_text("x", encoding="utf-8")

        bundle = self.root / "snapshot-bundle"
        create_bundle(
            catalog_path=catalog,
            sft_path=sft,
            candidate_id="qwen2.5-coder-7b-instruct",
            chat_template_path=template,
            chat_template_name="reviewed-test-template-v1",
            output_directory=bundle,
            runtime_profile_path=RUNTIME_PROFILE,
            _after_snapshot=mutate_sources,
        )
        validate_bundle(bundle)

        occupied = self.root / "occupied"
        occupied.mkdir()
        marker = occupied / "keep.txt"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            create_bundle(
                catalog_path=bundle / "inputs" / "candidate-catalog.json",
                sft_path=bundle / "inputs" / "dataset.sft.jsonl",
                candidate_id="qwen2.5-coder-7b-instruct",
                chat_template_path=bundle / "training-run-manifest.json",
                chat_template_name="unused",
                output_directory=occupied,
                runtime_profile_path=RUNTIME_PROFILE,
            )
        self.assertEqual("preserve", marker.read_text(encoding="utf-8"))
        self.assertFalse((self.root / ".occupied.lock").exists())

    def test_manifest_paths_are_fixed(self) -> None:
        bundle, _, _, _ = _create_valid_bundle(self.root, "fixed-paths")
        manifest_path = bundle / "training-run-manifest.json"
        original = json.loads(manifest_path.read_text(encoding="utf-8"))
        substitutions = (
            (
                ("dataset", "path"),
                "inputs/substitute.jsonl",
                "inputs/dataset.sft.jsonl",
            ),
            (
                ("candidateCatalog", "path"),
                "inputs/substitute.json",
                "inputs/candidate-catalog.json",
            ),
            (
                ("trainingRuntime", "profile", "path"),
                "inputs/substitute-runtime.json",
                "inputs/training-runtime-profile.json",
            ),
            (
                ("trainingRuntime", "pylock", "path"),
                "inputs/substitute-lock.toml",
                "inputs/pylock.train.toml",
            ),
            (("outputPath",), "outputs/substitute", "outputs/adapter"),
        )
        for keys, replacement, required in substitutions:
            manifest = json.loads(json.dumps(original))
            target = manifest
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = replacement
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, required):
                validate_manifest_path(manifest_path)

    def test_runtime_profile_and_pylock_tampering_invalidates_bundle(self) -> None:
        bundle, _, _, _ = _create_valid_bundle(self.root, "runtime-input-tamper")
        manifest_path = bundle / "training-run-manifest.json"
        for relative in (
            "inputs/training-runtime-profile.json",
            "inputs/pylock.train.toml",
        ):
            target = bundle / relative
            original = target.read_bytes()
            target.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValidationError, "does not match"):
                validate_manifest_path(manifest_path)
            with self.assertRaisesRegex(ValidationError, "does not match"):
                validate_bundle(bundle)
            target.write_bytes(original)
            validate_manifest_path(manifest_path)

    def test_bound_paths_reject_symlink_components_when_supported(self) -> None:
        clean_bundle, _, _, _ = _create_valid_bundle(self.root, "symlink-target")
        alias = self.root / "symlink-alias"
        try:
            alias.symlink_to(clean_bundle, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlinks are unavailable")
        with self.assertRaisesRegex(ValidationError, "reparse-point"):
            validate_manifest_path(alias / "training-run-manifest.json")

    @_with_authenticated_release_test_double
    def test_training_stages_cleans_failures_promotes_atomically_and_records_environment(
        self,
    ) -> None:
        bundle, _, _, _ = _create_valid_bundle(
            self.root, "training-stage", bind_release=True
        )
        manifest_path = bundle / "training-run-manifest.json"
        importer = _fake_training_importer()
        output = bundle / "outputs" / "adapter"

        with mock.patch.object(training_module, "_run_training") as runner:
            with self.assertRaisesRegex(ValidationError, "release path is required"):
                training_module.train_from_manifest(manifest_path, importer=importer)
            runner.assert_not_called()

        with (
            mock.patch.object(
                training_module,
                "_run_training",
                side_effect=RuntimeError("synthetic failure"),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=_locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=_locked_runtime_host_facts(),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                training_module.train_from_manifest(
                    manifest_path,
                    smoke=True,
                    importer=importer,
                    **_training_release_arguments(self.root),
                )
        self.assertFalse(output.exists())
        self.assertEqual([], list((bundle / "outputs").glob(".adapter.training-*")))
        self.assertFalse((bundle / "outputs" / ".adapter.lock").exists())

        source_dataset = bundle / "inputs" / "dataset.sft.jsonl"
        original_dataset_bytes = source_dataset.read_bytes()

        def fake_training(
            manifest, dependencies, records, output_path, **kwargs
        ) -> None:
            self.assertIsInstance(records, list)
            self.assertEqual("training-stage-all-domains", records[0]["metadata"]["id"])
            _write_safe_inference_files(output_path, manifest)

        def mutate_after_in_memory_capture(snapshot_path: Path) -> None:
            source_dataset.write_bytes(source_dataset.read_bytes() + b"\n")
            snapshot_path.write_bytes(b"corrupted after in-memory capture")

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=_locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=_locked_runtime_host_facts(),
            ),
        ):
            result = training_module.train_from_manifest(
                manifest_path,
                smoke=True,
                importer=importer,
                _after_in_memory_capture=mutate_after_in_memory_capture,
                **_training_release_arguments(self.root),
            )
        metadata = json.loads(
            (output / "artifact-metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(str(output), result["outputPath"])
        self.assertFalse(metadata["productionEligible"])
        self.assertEqual(
            "4.48.3",
            metadata["environment"]["dependencyVersions"]["transformers"],
        )
        self.assertEqual("bfloat16", metadata["environment"]["computeDtype"])
        self.assertEqual(
            "Test GPU", metadata["environment"]["gpu"]["devices"][0]["name"]
        )
        self.assertEqual(TRAINING_ARTIFACT_SCHEMA_VERSION, metadata["schemaVersion"])
        self.assertEqual(result["artifactSha256"], metadata["artifactSha256"])
        self.assertEqual(result["fileTreeSha256"], metadata["fileTreeSha256"])
        self.assertEqual(
            [
                "adapter_config.json",
                "adapter_model.safetensors",
                "special_tokens_map.json",
                "tokenizer.json",
                "tokenizer_config.json",
            ],
            [entry["path"] for entry in metadata["files"]],
        )
        self.assertEqual(metadata, validate_training_artifact(output))

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(["validate-artifact", str(output)])
        cli_result = json.loads(stdout.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(cli_result["valid"])
        self.assertEqual(metadata["artifactSha256"], cli_result["artifactSha256"])
        self.assertEqual(5, cli_result["fileCount"])
        self.assertFalse((bundle / "outputs" / ".adapter.lock").exists())
        source_dataset.write_bytes(original_dataset_bytes)

        with (
            mock.patch.object(training_module, "_run_training") as runner,
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=_locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=_locked_runtime_host_facts(),
            ),
        ):
            with self.assertRaisesRegex(ValidationError, "already exists"):
                training_module.train_from_manifest(
                    manifest_path,
                    smoke=True,
                    importer=importer,
                    **_training_release_arguments(self.root),
                )
            runner.assert_not_called()

    @_with_authenticated_release_test_double
    def test_smoke_training_runtime_lock_fails_before_model_construction(self) -> None:
        bundle, _, _, _ = _create_valid_bundle(
            self.root, "runtime-lock", bind_release=True
        )
        manifest_path = bundle / "training-run-manifest.json"
        importer = _fake_training_importer()
        cases = (
            ("python", {"implementation": "PyPy", "major": 3, "minor": 11}),
            ("platform", {"system": "Linux", "machine": "aarch64"}),
            ("cuda", {"runtimeVersion": "12.2"}),
            (
                "directDependencies",
                {**DIRECT_DEPENDENCY_VERSIONS, "trl": "0.15.3"},
            ),
        )
        with (
            mock.patch.object(training_module, "_run_training") as runner,
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=_locked_runtime_host_facts(),
            ),
        ):
            for section, invalid in cases:
                facts = _locked_runtime_facts()
                facts[section] = invalid
                with (
                    mock.patch(
                        "vibe_quant_model.runtime.runtime_facts", return_value=facts
                    ),
                    self.assertRaisesRegex(
                        PreflightError, "differs from the sealed profile"
                    ),
                ):
                    training_module.train_from_manifest(
                        manifest_path,
                        smoke=True,
                        importer=importer,
                        **_training_release_arguments(self.root),
                    )
            runner.assert_not_called()

    @_with_authenticated_release_test_double
    def test_runtime_host_mismatch_fails_before_optional_dependency_imports(
        self,
    ) -> None:
        bundle, _, _, _ = _create_valid_bundle(
            self.root, "runtime-host-lock", bind_release=True
        )
        manifest_path = bundle / "training-run-manifest.json"
        importer = mock.Mock(side_effect=AssertionError("dependencies must not import"))
        with mock.patch(
            "vibe_quant_model.runtime.runtime_host_facts",
            return_value={
                "python": {"implementation": "CPython", "major": 3, "minor": 12},
                "platform": {"system": "Windows", "machine": "AMD64"},
            },
        ):
            with self.assertRaisesRegex(
                PreflightError, "differs from the sealed profile"
            ):
                training_module.train_from_manifest(
                    manifest_path,
                    smoke=True,
                    importer=importer,
                    **_training_release_arguments(self.root),
                )
        importer.assert_not_called()

    @_with_authenticated_release_test_double
    def test_training_artifact_rejects_mutated_added_and_deleted_files(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-tamper")
        adapter = output / "adapter_model.safetensors"
        original = adapter.read_bytes()

        adapter.write_bytes(b"tampered adapter")
        with self.assertRaisesRegex(ValidationError, "safetensors"):
            validate_training_artifact(output)
        adapter.write_bytes(original)
        validate_training_artifact(output)

        added = output / "untracked.bin"
        added.write_bytes(b"not sealed")
        with self.assertRaisesRegex(ValidationError, "does not exactly match"):
            validate_training_artifact(output)
        added.unlink()
        validate_training_artifact(output)

        tokenizer = output / "tokenizer.json"
        tokenizer_bytes = tokenizer.read_bytes()
        tokenizer.unlink()
        with self.assertRaisesRegex(
            ValidationError, "does not exist|does not exactly match"
        ):
            validate_training_artifact(output)
        tokenizer.write_bytes(tokenizer_bytes)
        validate_training_artifact(output)

    @_with_authenticated_release_test_double
    def test_training_artifact_core_prepare_is_not_a_sealed_candidate(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-core-candidate")
        source_artifact = validate_training_artifact(output)
        staging = self.root / "artifact-core-candidate-stage"
        shutil.copytree(output, staging)
        (staging / "artifact-metadata.json").unlink()
        metadata = _artifact_metadata_inputs(source_artifact)
        metadata["mode"] = "unpromoted-candidate"
        metadata["reason"] = (
            "Training alone does not satisfy evaluation, promotion, signing, or deployment gates."
        )

        artifact_core = prepare_training_artifact_core(
            staging,
            metadata,
            **_training_release_arguments(self.root),
        )

        self.assertEqual("0" * 64, artifact_core["artifactSha256"])
        self.assertIsNone(artifact_core["trainerProvenance"])
        self.assertFalse((staging / "artifact-metadata.json").exists())
        with self.assertRaisesRegex(ValidationError, "externally pinned trust"):
            finalize_training_artifact_core(
                staging,
                artifact_core,
                None,
                trainer_provenance_trust=None,
            )
        self.assertFalse((staging / "artifact-metadata.json").exists())

    @_with_authenticated_release_test_double
    def test_training_artifact_core_finalize_rejects_live_file_drift(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-core-drift")
        source_artifact = validate_training_artifact(output)
        staging = self.root / "artifact-core-drift-stage"
        shutil.copytree(output, staging)
        (staging / "artifact-metadata.json").unlink()
        artifact_core = prepare_training_artifact_core(
            staging,
            _artifact_metadata_inputs(source_artifact),
            **_training_release_arguments(self.root),
        )
        tokenizer = staging / "tokenizer.json"
        tokenizer.write_bytes(tokenizer.read_bytes() + b" ")

        with self.assertRaisesRegex(ValidationError, "does not exactly match"):
            finalize_training_artifact_core(
                staging,
                artifact_core,
                None,
                trainer_provenance_trust=None,
            )
        self.assertFalse((staging / "artifact-metadata.json").exists())

    @_with_authenticated_release_test_double
    def test_training_artifact_core_finalize_preserves_direct_wire(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-core-parity")
        expected_artifact = validate_training_artifact(output)
        expected_bytes = (output / "artifact-metadata.json").read_bytes()
        staging = self.root / "artifact-core-parity-stage"
        shutil.copytree(output, staging)
        (staging / "artifact-metadata.json").unlink()

        artifact_core = prepare_training_artifact_core(
            staging,
            _artifact_metadata_inputs(expected_artifact),
            **_training_release_arguments(self.root),
        )
        finalized = finalize_training_artifact_core(
            staging,
            artifact_core,
            None,
            trainer_provenance_trust=None,
        )

        self.assertEqual(expected_artifact, finalized)
        self.assertEqual(
            expected_bytes,
            (staging / "artifact-metadata.json").read_bytes(),
        )

    @_with_authenticated_release_test_double
    def test_training_artifact_core_never_clobbers_existing_metadata(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-core-no-clobber")
        source_artifact = validate_training_artifact(output)
        metadata = _artifact_metadata_inputs(source_artifact)
        metadata_path = output / "artifact-metadata.json"
        original_bytes = metadata_path.read_bytes()
        with self.assertRaisesRegex(ValidationError, "already exists"):
            prepare_training_artifact_core(
                output,
                metadata,
                **_training_release_arguments(self.root),
            )
        self.assertEqual(original_bytes, metadata_path.read_bytes())

        staging = self.root / "artifact-core-no-clobber-stage"
        shutil.copytree(output, staging)
        staging_metadata_path = staging / "artifact-metadata.json"
        staging_metadata_path.unlink()
        artifact_core = prepare_training_artifact_core(
            staging,
            metadata,
            **_training_release_arguments(self.root),
        )
        sentinel = b'{"sentinel":true}\n'
        staging_metadata_path.write_bytes(sentinel)
        with self.assertRaisesRegex(ValidationError, "already exists"):
            finalize_training_artifact_core(
                staging,
                artifact_core,
                None,
                trainer_provenance_trust=None,
            )
        self.assertEqual(sentinel, staging_metadata_path.read_bytes())

    def test_training_artifact_file_index_is_independent_of_creation_order(
        self,
    ) -> None:
        first = self.root / "first-order"
        second = self.root / "second-order"
        first.mkdir()
        second.mkdir()
        files = {
            "z-last.bin": b"z",
            "m-middle.json": b"middle",
            "a-first.bin": b"a",
        }
        for relative in files:
            destination = first / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(files[relative])
        for relative in reversed(tuple(files)):
            destination = second / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(files[relative])

        first_index, first_hash = build_artifact_file_index(first)
        second_index, second_hash = build_artifact_file_index(second)

        self.assertEqual(first_index, second_index)
        self.assertEqual(first_hash, second_hash)
        self.assertEqual(
            ["a-first.bin", "m-middle.json", "z-last.bin"],
            [entry["path"] for entry in first_index],
        )

    @_with_authenticated_release_test_double
    def test_training_artifact_rejects_reparse_entries_when_supported(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-reparse")
        alias = output / "adapter-alias.bin"
        try:
            alias.symlink_to(output / "adapter_model.safetensors")
        except OSError:
            self.skipTest("file symlinks are unavailable")

        with self.assertRaisesRegex(
            ValidationError, "symbolic-link or reparse-point entry"
        ):
            validate_training_artifact(output)

    @_with_authenticated_release_test_double
    def test_training_artifact_metadata_is_strict_and_schema_is_machine_readable(
        self,
    ) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-metadata")
        metadata_path = output / "artifact-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["unsupported"] = True
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "unsupported keys"):
            validate_training_artifact(output)

        schema = json.loads(
            (ROOT / "schemas" / "training-artifact.v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            TRAINING_ARTIFACT_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )

    @_with_authenticated_release_test_double
    def test_training_artifact_rejects_unsafe_files_and_hard_links(self) -> None:
        output, _ = _train_synthetic_artifact(self.root, "artifact-safe-shape")
        metadata = validate_training_artifact(output)

        forged_candidate = self.root / "forged-candidate"
        shutil.copytree(output, forged_candidate)
        (forged_candidate / "artifact-metadata.json").unlink()
        forged_metadata = dict(metadata)
        forged_metadata["mode"] = "unpromoted-candidate"
        forged_metadata["reason"] = (
            "Training alone does not satisfy evaluation, promotion, signing, or deployment gates."
        )
        forged_metadata["dataRelease"] = {
            "releaseId": "vqrel-" + "a" * 64,
            "releaseSha256": "a" * 64,
            "manifestSha256": "b" * 64,
        }
        with self.assertRaisesRegex(ValidationError, "trainer provenance"):
            seal_training_artifact(forged_candidate, forged_metadata)
        self.assertFalse((forged_candidate / "artifact-metadata.json").exists())

        unsafe = self.root / "unsafe-artifact"
        shutil.copytree(output, unsafe)
        (unsafe / "artifact-metadata.json").unlink()
        (unsafe / "optimizer.pt").write_bytes(b"pickle-like checkpoint")
        with self.assertRaisesRegex(ValidationError, "unsupported inference files"):
            seal_training_artifact(
                unsafe,
                metadata,
                **_training_release_arguments(self.root),
            )
        self.assertFalse((unsafe / "artifact-metadata.json").exists())

        hard_linked = self.root / "hard-linked-artifact"
        shutil.copytree(output, hard_linked)
        linked_adapter = hard_linked / "adapter_model.safetensors"
        linked_adapter.unlink()
        try:
            os.link(output / "adapter_model.safetensors", linked_adapter)
        except OSError:
            self.skipTest("hard links are unavailable")
        with self.assertRaisesRegex(ValidationError, "hard-linked files"):
            validate_training_artifact(hard_linked)

    def test_dependency_and_gpu_memory_preflights_fail_closed_with_smoke_only_waiver(
        self,
    ) -> None:
        def missing(name: str):
            raise ImportError(f"no {name}")

        with self.assertRaisesRegex(PreflightError, "transformers"):
            load_training_dependencies(missing)

        class FakeCuda:
            @staticmethod
            def is_available() -> bool:
                return True

            @staticmethod
            def device_count() -> int:
                return 1

            @staticmethod
            def get_device_properties(index: int):
                self.assertEqual(0, index)
                return SimpleNamespace(total_memory=8 * 1024**3)

        fake_torch = SimpleNamespace(cuda=FakeCuda())
        no_cuda = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False))
        with self.assertRaisesRegex(PreflightError, "CUDA is unavailable"):
            gpu_memory_preflight(no_cuda, smoke=True)
        with self.assertRaisesRegex(PreflightError, "finite positive"):
            gpu_memory_preflight(fake_torch, minimum_gib=float("nan"))
        with self.assertRaisesRegex(PreflightError, "at least 16.00 GiB"):
            gpu_memory_preflight(fake_torch)
        with self.assertRaisesRegex(PreflightError, "cannot lower"):
            gpu_memory_preflight(fake_torch, minimum_gib=8)

        smoke = gpu_memory_preflight(fake_torch, smoke=True)
        self.assertTrue(smoke["memoryGateWaivedForSmoke"])
        self.assertFalse(smoke["productionEligible"])


if __name__ == "__main__":
    unittest.main()
