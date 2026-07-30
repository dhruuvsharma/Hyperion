from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import jsonschema

import vibe_quant_model.cli as cli_module
import vibe_quant_model.evaluation_suite_authoring as authoring_module
from vibe_quant_model.core import (
    ValidationError,
    canonical_json_bytes,
    expert_conversation_sha256,
)
from vibe_quant_model.evaluation_suite_authoring import (
    EVALUATION_AUTHORING_HANDOFF_SCHEMA_VERSION,
    EVALUATION_AUTHORING_MANIFEST_SCHEMA_VERSION,
    compile_evaluation_authoring_handoff,
    evaluation_authoring_handoff_id,
    validate_evaluation_authoring_handoff,
)
from vibe_quant_model.release import _verification_evidence_sha256


CUTOFF = "2025-01-15T12:00:00Z"
PRODUCED = "2025-01-14T12:00:00Z"
VERIFIED = "2025-01-16T12:00:00Z"


def _rights() -> dict[str, bool]:
    return {
        "mayStore": True,
        "mayEvaluate": True,
        "mayTrain": False,
        "mayUploadToProvider": False,
        "mayRedistribute": False,
    }


def _record(
    example_id: str,
    split: str,
    *,
    user: str | None = None,
    origin: str = "HumanAuthored",
) -> dict:
    messages = [
        {
            "role": "system",
            "content": "Answer only from independently reviewed evidence.",
        },
        {"role": "user", "content": user or f"Evaluate the bounded {example_id} case."},
        {
            "role": "assistant",
            "content": f"PRIVATE REFERENCE ANSWER FOR {example_id}",
        },
    ]
    evidence = [
        "knowledgeClass=candidate-stable",
        "Reviewed against the exact bound source.",
    ]
    lineage = {
        "origin": origin,
        "producer": "fixture-author",
        "modelId": None,
        "modelRevision": None,
        "promptSha256": None,
        "profileVersion": None,
        "producedAtUtc": PRODUCED,
    }
    if origin != "HumanAuthored":
        lineage.update(
            {
                "modelId": "fixture-model",
                "modelRevision": "fixture-revision",
                "promptSha256": "1" * 64,
                "profileVersion": "fixture-profile-v1",
            }
        )
    return {
        "schemaVersion": "expert-model-dataset/v1",
        "id": example_id,
        "taskKind": "QuantitativeReasoning",
        "domains": ["QuantitativeMath"],
        "messages": messages,
        "conversationSha256": expert_conversation_sha256(messages),
        "sources": [
            {
                "id": f"source-{example_id}",
                "title": "Reviewed source",
                "content": f"Exact source bytes for {example_id}.",
                "provenance": "Synthetic authoring-handoff fixture.",
                "license": "Test-only license",
                "retrievedAtUtc": PRODUCED,
                "availableAtUtc": PRODUCED,
                "uri": None,
                "rights": _rights(),
            }
        ],
        "lineage": lineage,
        "verification": {
            "verified": True,
            "reviewer": "fixture-reviewer",
            "verifiedAtUtc": VERIFIED,
            "evidenceSha256": _verification_evidence_sha256(evidence, [], []),
            "evidence": evidence,
            "compileSucceeded": False,
            "compileEvidence": [],
            "testsPassed": False,
            "testEvidence": [],
        },
        "split": split,
        "contaminationGroup": f"group-{example_id}",
        "provenance": "Synthetic reviewed fixture.",
        "license": "Test-only license",
        "rights": _rights(),
        "reviewStatus": "approved",
        "cutoffUtc": CUTOFF,
        "useForTraining": False,
    }


class EvaluationSuiteAuthoringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.authoring = self.root / "authoring"
        self.assets = self.authoring / "assets"
        self.assets.mkdir(parents=True)
        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed"),
        ]
        self.source = self.root / "reviewed-source.jsonl"
        self._write_source()
        self.manifest = self.authoring / "manifest.json"
        self.manifest_value = self._manifest_value()
        self._write_manifest()
        self.output = self.root / "handoff"

    def _write_source(self) -> None:
        self.source.write_text(
            "".join(
                json.dumps(record, separators=(",", ":")) + "\n"
                for record in self.records
            ),
            encoding="utf-8",
            newline="\n",
        )

    def _asset(self, task_id: str, kind: str) -> tuple[str, str]:
        relative = f"assets/{task_id}.{kind}.bin"
        path = self.authoring / relative
        if not path.exists():
            path.write_bytes(f"exact {kind} bytes for {task_id}\r\n".encode())
        return relative, hashlib.sha256(path.read_bytes()).hexdigest()

    def _task_spec(self, example_id: str) -> dict:
        task_id = f"task-{example_id}"
        context_path, context_sha = self._asset(task_id, "context")
        rubric_path, rubric_sha = self._asset(task_id, "rubric")
        verifier_path, verifier_sha = self._asset(task_id, "verifier")
        return {
            "taskId": task_id,
            "sourceExampleId": example_id,
            "contextPack": {
                "version": "reviewed-context-v1",
                "path": context_path,
                "sha256": context_sha,
            },
            "rubric": {
                "id": f"rubric-{task_id}",
                "path": rubric_path,
                "sha256": rubric_sha,
            },
            "verifier": {
                "id": f"verifier-{task_id}",
                "path": verifier_path,
                "sha256": verifier_sha,
                "requiredChecks": ["correct", "safe"],
            },
            "criticality": "critical"
            if example_id.startswith("sealed")
            else "standard",
            "maxOutputTokens": 512,
        }

    def _manifest_value(self) -> dict:
        return {
            "schemaVersion": EVALUATION_AUTHORING_MANIFEST_SCHEMA_VERSION,
            "sourceDatasetSha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "tasks": [
                self._task_spec("sealed-1"),
                self._task_spec("calibration-1"),
            ],
        }

    def _write_manifest(self) -> None:
        self.manifest.write_text(
            json.dumps(self.manifest_value, separators=(",", ":")),
            encoding="utf-8",
            newline="\n",
        )

    def _refresh_source_binding(self) -> None:
        self.manifest_value["sourceDatasetSha256"] = hashlib.sha256(
            self.source.read_bytes()
        ).hexdigest()
        self._write_manifest()

    def _compile(self, output: Path | None = None):
        return compile_evaluation_authoring_handoff(
            self.manifest,
            source_dataset_path=self.source,
            output_directory=output or self.output,
        )

    def test_cli_compiles_and_validates_answer_free_closed_package(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(
                [
                    "compile-evaluation-authoring-handoff",
                    "--manifest",
                    str(self.manifest),
                    "--source-dataset",
                    str(self.source),
                    "--output-directory",
                    str(self.output),
                ]
            )
        self.assertEqual(0, exit_code)
        created = json.loads(stdout.getvalue())
        self.assertTrue(created["created"])
        handoff_path = Path(created["handoffPath"])
        verified = validate_evaluation_authoring_handoff(
            handoff_path, source_dataset_path=self.source
        )
        self.assertEqual(created["handoffId"], verified.handoff_id)
        self.assertEqual(
            EVALUATION_AUTHORING_HANDOFF_SCHEMA_VERSION,
            verified.document["schemaVersion"],
        )
        self.assertTrue(
            all(value is False for value in verified.document["authority"].values())
        )

        package_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                self.output / "evaluation/calibration.tasks.jsonl",
                self.output / "evaluation/sealed.tasks.jsonl",
                self.output / "evaluation/task-bindings.json",
            )
        )
        self.assertNotIn("PRIVATE REFERENCE ANSWER", package_text)
        self.assertNotIn("expectedAnswer", package_text)
        bindings = json.loads(
            (self.output / "evaluation/task-bindings.json").read_text(encoding="utf-8")
        )
        for binding in bindings["bindings"]:
            self.assertFalse(Path(binding["contextPack"]["path"]).is_absolute())
            self.assertFalse(Path(binding["rubric"]["path"]).is_absolute())
            self.assertFalse(Path(binding["verifier"]["path"]).is_absolute())
        self.assertFalse(
            any(path.name == self.source.name for path in self.output.rglob("*"))
        )

        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        jsonschema.Draft202012Validator(
            json.loads(
                (
                    schema_root / "evaluation-authoring-manifest.v1.schema.json"
                ).read_text(encoding="utf-8")
            )
        ).validate(self.manifest_value)
        jsonschema.Draft202012Validator(
            json.loads(
                (schema_root / "evaluation-authoring-handoff.v1.schema.json").read_text(
                    encoding="utf-8"
                )
            )
        ).validate(verified.document)
        jsonschema.Draft202012Validator(
            json.loads(
                (schema_root / "release-task-bindings.v2.schema.json").read_text(
                    encoding="utf-8"
                )
            )
        ).validate(bindings)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(
                [
                    "validate-evaluation-authoring-handoff",
                    str(handoff_path),
                    "--source-dataset",
                    str(self.source),
                ]
            )
        self.assertEqual(0, exit_code)
        self.assertTrue(json.loads(stdout.getvalue())["valid"])

    def test_manifest_forbids_derived_field_overrides_and_incomplete_mapping(
        self,
    ) -> None:
        for field, value in (
            ("messages", []),
            ("split", "sealed"),
            ("expectedAnswer", "leak"),
            ("taskSha256", "0" * 64),
        ):
            with self.subTest(field=field):
                self.manifest_value["tasks"][0][field] = value
                self._write_manifest()
                with self.assertRaisesRegex(ValidationError, "unsupported keys"):
                    self._compile(self.root / f"override-{field}")
                self.manifest_value["tasks"][0].pop(field)
        self.manifest_value["tasks"][0]["sourceExampleId"] = "development-1"
        self._write_manifest()
        with self.assertRaisesRegex(
            ValidationError, "map every calibration and sealed"
        ):
            self._compile(self.root / "wrong-map")

    def test_training_provider_and_nonhuman_evaluation_rows_fail_closed(self) -> None:
        cases = (
            ("row training", lambda row: row["rights"].update(mayTrain=True)),
            (
                "source provider",
                lambda row: row["sources"][0]["rights"].update(
                    mayUploadToProvider=True
                ),
            ),
            (
                "nonhuman",
                lambda row: row["lineage"].update(
                    origin="OpenWeightTeacher",
                    modelId="fixture-model",
                    modelRevision="a" * 40,
                    promptSha256="1" * 64,
                    profileVersion="fixture-profile-v1",
                ),
            ),
        )
        for index, (label, mutate) in enumerate(cases):
            with self.subTest(label=label):
                original = json.loads(json.dumps(self.records))
                mutate(self.records[2])
                self._write_source()
                self._refresh_source_binding()
                pattern = (
                    "HumanAuthored"
                    if label == "nonhuman"
                    else "storage/evaluation-only"
                )
                with self.assertRaisesRegex(ValidationError, pattern):
                    self._compile(self.root / f"rights-{index}")
                self.records = original
                self._write_source()
                self._refresh_source_binding()

    def test_normalized_cross_split_and_development_prompt_overlap_fail_closed(
        self,
    ) -> None:
        self.records[1] = _record("calibration-1", "calibration", user="Price   RISK?")
        self.records[2] = _record("sealed-1", "sealed", user=" price risk? ")
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(ValidationError, "normalized user turn overlap"):
            self._compile(self.root / "cross-split-overlap")

        self.records = [
            _record("development-1", "development", user="private benchmark prompt"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed", user=" PRIVATE  benchmark prompt "),
        ]
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(ValidationError, "normalized user turn overlap"):
            self._compile(self.root / "development-overlap")

    def test_answer_and_individual_user_turn_contamination_fail_closed(self) -> None:
        self.records[0]["messages"][-1]["content"] = self.records[2]["messages"][-1][
            "content"
        ]
        self.records[0]["conversationSha256"] = expert_conversation_sha256(
            self.records[0]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(ValidationError, "reference answer"):
            self._compile(self.root / "answer-overlap")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed"),
        ]
        shared = {"role": "user", "content": "shared hidden benchmark turn"}
        for record, unique in (
            (self.records[0], "development continuation"),
            (self.records[2], "sealed continuation"),
        ):
            record["messages"] = [
                record["messages"][0],
                shared,
                {"role": "assistant", "content": "Continue with the bounded case."},
                {"role": "user", "content": unique},
                record["messages"][-1],
            ]
            record["conversationSha256"] = expert_conversation_sha256(
                record["messages"]
            )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(ValidationError, "normalized user turn overlap"):
            self._compile(self.root / "one-turn-overlap")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed"),
        ]
        answer = self.records[2]["messages"][-1]["content"]
        self.records[2]["messages"][-2]["content"] = f"Return exactly: {answer}"
        self.records[2]["conversationSha256"] = expert_conversation_sha256(
            self.records[2]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(ValidationError, "appears in a corpus prompt"):
            self._compile(self.root / "answer-in-prompt")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed"),
        ]
        answer = self.records[2]["messages"][-1]["content"]
        self.records[0]["messages"][-2]["content"] = f"Training leak: {answer}"
        self.records[0]["conversationSha256"] = expert_conversation_sha256(
            self.records[0]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(ValidationError, "appears in a corpus prompt"):
            self._compile(self.root / "answer-in-development-prompt")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed"),
        ]
        self.records[0]["messages"][1]["content"] = "PRIVATE REFERENCE ANSWER FOR"
        self.records[0]["messages"][2]["content"] = "sealed-1"
        self.records[0]["conversationSha256"] = expert_conversation_sha256(
            self.records[0]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(
            ValidationError, "across corpus message boundaries"
        ):
            self._compile(self.root / "answer-across-development-answer-boundary")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed"),
        ]
        self.records[2]["messages"][0]["content"] = "PRIVATE REFERENCE ANSWER FOR"
        self.records[2]["messages"][1]["content"] = "sealed-1"
        self.records[2]["conversationSha256"] = expert_conversation_sha256(
            self.records[2]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(
            ValidationError, "appears across the emitted corpus prompt"
        ):
            self._compile(self.root / "answer-across-prompt-boundary")

    def test_evaluation_user_turn_cannot_leak_into_development_messages(self) -> None:
        held_out_turn = self.records[2]["messages"][1]["content"]
        development = self.records[0]
        development["messages"][-1]["content"] = held_out_turn
        development["rights"]["mayTrain"] = True
        development["sources"][0]["rights"]["mayTrain"] = True
        development["useForTraining"] = True
        development["conversationSha256"] = expert_conversation_sha256(
            development["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(
            ValidationError, "appears in another corpus message"
        ):
            self._compile(self.root / "user-turn-in-development-answer")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration"),
            _record("sealed-1", "sealed", user="hidden benchmark boundary"),
        ]
        self.records[0]["messages"][0]["content"] = "hidden benchmark"
        self.records[0]["messages"][1]["content"] = "boundary"
        self.records[0]["conversationSha256"] = expert_conversation_sha256(
            self.records[0]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(
            ValidationError, "appears across other corpus messages"
        ):
            self._compile(self.root / "user-turn-across-development-boundary")

        self.records = [
            _record("development-1", "development"),
            _record("calibration-1", "calibration", user="beta x"),
            _record("sealed-1", "sealed", user="alpha beta"),
        ]
        self.records[1]["messages"][0]["content"] = "alpha"
        self.records[1]["conversationSha256"] = expert_conversation_sha256(
            self.records[1]["messages"]
        )
        self._write_source()
        self._refresh_source_binding()
        with self.assertRaisesRegex(
            ValidationError, "appears across other corpus messages"
        ):
            self._compile(self.root / "user-turn-across-evaluation-boundary")

    def test_asset_hash_escape_and_empty_inputs_fail_before_publication(self) -> None:
        self.manifest_value["tasks"][0]["verifier"]["sha256"] = "0" * 64
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "exact asset bytes"):
            self._compile(self.root / "bad-hash")
        self.manifest_value = self._manifest_value()

        self.manifest_value["tasks"][0]["rubric"]["path"] = "../outside.bin"
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "contained relative path"):
            self._compile(self.root / "escape")
        self.manifest_value = self._manifest_value()

        empty = self.assets / "empty.bin"
        empty.write_bytes(b"")
        self.manifest_value["tasks"][0]["contextPack"].update(
            path="assets/empty.bin",
            sha256=hashlib.sha256(b"").hexdigest(),
        )
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "must not be empty"):
            self._compile(self.root / "empty")

    def test_validator_rejects_asset_source_and_extra_file_drift(self) -> None:
        verified = self._compile()
        asset = next(
            path for path in self.output.rglob("*.bin") if "verifiers" in path.parts
        )
        original = asset.read_bytes()
        asset.write_bytes(original + b"drift")
        with self.assertRaisesRegex(ValidationError, "asset SHA-256|exact bound bytes"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )
        asset.write_bytes(original)

        extra = self.output / "unbound.txt"
        extra.write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "unbound extra files"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )
        extra.unlink()

        self.records[2]["messages"][-1]["content"] += " drift"
        self.records[2]["conversationSha256"] = expert_conversation_sha256(
            self.records[2]["messages"]
        )
        self._write_source()
        with self.assertRaisesRegex(ValidationError, "exact reviewed source dataset"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

    def test_validator_rejects_mid_validation_binding_and_asset_swaps(self) -> None:
        verified = self._compile()
        bindings_path = self.output / "evaluation/task-bindings.json"
        original_bindings = bindings_path.read_bytes()
        binding_document = json.loads(original_bindings)
        reformatted_bindings = (
            json.dumps(binding_document, indent=2).encode("utf-8") + b"\n"
        )
        original_derive = authoring_module.derive_evaluation_authoring_inventory

        def swap_bindings(**arguments):
            bindings_path.write_bytes(reformatted_bindings)
            return original_derive(**arguments)

        with mock.patch.object(
            authoring_module,
            "derive_evaluation_authoring_inventory",
            side_effect=swap_bindings,
        ):
            with self.assertRaisesRegex(
                ValidationError, "changed while being validated"
            ):
                validate_evaluation_authoring_handoff(
                    verified.path, source_dataset_path=self.source
                )

        bindings_path.write_bytes(original_bindings)
        rubric = next(
            path for path in self.output.rglob("*.bin") if "rubrics" in path.parts
        )
        original_rubric = rubric.read_bytes()

        def swap_rubric(**arguments):
            rubric.write_bytes(original_rubric + b"mid-validation drift")
            return original_derive(**arguments)

        with mock.patch.object(
            authoring_module,
            "derive_evaluation_authoring_inventory",
            side_effect=swap_rubric,
        ):
            with self.assertRaisesRegex(
                ValidationError, "freshly derived atomic inventory"
            ):
                validate_evaluation_authoring_handoff(
                    verified.path, source_dataset_path=self.source
                )

    def test_self_consistent_manifest_rewrite_cannot_override_derived_task(
        self,
    ) -> None:
        verified = self._compile()
        packaged_manifest = self.output / "inputs/authoring-manifest.json"
        manifest = json.loads(packaged_manifest.read_text(encoding="utf-8"))
        manifest["tasks"][0]["maxOutputTokens"] = 513
        manifest_raw = canonical_json_bytes(manifest) + b"\n"
        packaged_manifest.write_bytes(manifest_raw)

        handoff = json.loads(verified.path.read_text(encoding="utf-8"))
        handoff["authoringManifest"]["sha256"] = hashlib.sha256(
            manifest_raw
        ).hexdigest()
        handoff["authoringManifest"]["sizeBytes"] = len(manifest_raw)
        handoff["handoffId"] = evaluation_authoring_handoff_id(handoff)
        verified.path.write_bytes(canonical_json_bytes(handoff) + b"\n")

        with self.assertRaisesRegex(ValidationError, "exact answer-free task"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

    def test_numeric_authority_and_unreferenced_declared_asset_fail_closed(
        self,
    ) -> None:
        verified = self._compile()
        original_handoff = json.loads(verified.path.read_text(encoding="utf-8"))

        numeric = json.loads(json.dumps(original_handoff))
        numeric["authority"]["releaseAuthority"] = 0
        numeric["handoffId"] = evaluation_authoring_handoff_id(numeric)
        verified.path.write_bytes(canonical_json_bytes(numeric) + b"\n")
        with self.assertRaisesRegex(ValidationError, "grant no authority"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

        numeric_declaration = json.loads(json.dumps(original_handoff))
        numeric_declaration["declarations"]["sealedCustodyAttested"] = 0
        numeric_declaration["handoffId"] = evaluation_authoring_handoff_id(
            numeric_declaration
        )
        verified.path.write_bytes(canonical_json_bytes(numeric_declaration) + b"\n")
        with self.assertRaisesRegex(ValidationError, "non-authorizing declaration"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

        extra_raw = b"unreferenced verifier asset\n"
        extra_sha = hashlib.sha256(extra_raw).hexdigest()
        extra_relative = f"evaluation/verifiers/{extra_sha}.bin"
        extra_path = self.output.joinpath(*extra_relative.split("/"))
        extra_path.write_bytes(extra_raw)
        expanded = json.loads(json.dumps(original_handoff))
        expanded["assets"].append(
            {
                "kind": "verifier",
                "path": extra_relative,
                "sha256": extra_sha,
                "sizeBytes": len(extra_raw),
            }
        )
        expanded["assets"].sort(key=lambda asset: asset["path"])
        expanded["handoffId"] = evaluation_authoring_handoff_id(expanded)
        verified.path.write_bytes(canonical_json_bytes(expanded) + b"\n")
        with self.assertRaisesRegex(ValidationError, "exactly match"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

    def test_absolute_binding_and_mislabeled_content_address_fail_closed(self) -> None:
        verified = self._compile()
        bindings_path = self.output / "evaluation/task-bindings.json"
        original_bindings = json.loads(bindings_path.read_text(encoding="utf-8"))
        handoff = json.loads(verified.path.read_text(encoding="utf-8"))

        absolute = json.loads(json.dumps(original_bindings))
        relative = absolute["bindings"][0]["contextPack"]["path"]
        absolute["bindings"][0]["contextPack"]["path"] = str(
            (bindings_path.parent / relative).resolve()
        )
        absolute_raw = canonical_json_bytes(absolute) + b"\n"
        bindings_path.write_bytes(absolute_raw)
        handoff["taskBindings"]["sha256"] = hashlib.sha256(absolute_raw).hexdigest()
        handoff["taskBindings"]["sizeBytes"] = len(absolute_raw)
        handoff["handoffId"] = evaluation_authoring_handoff_id(handoff)
        verified.path.write_bytes(canonical_json_bytes(handoff) + b"\n")
        with self.assertRaisesRegex(
            ValidationError, "contained forward-slash relative path"
        ):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

        shutil.rmtree(self.output)
        verified = self._compile()
        handoff = json.loads(verified.path.read_text(encoding="utf-8"))
        asset = handoff["assets"][0]
        old_path = self.output.joinpath(*asset["path"].split("/"))
        new_relative = str(Path(asset["path"]).with_name(f"{'0' * 64}.bin")).replace(
            "\\", "/"
        )
        new_path = self.output.joinpath(*new_relative.split("/"))
        old_path.rename(new_path)
        asset["path"] = new_relative
        handoff["handoffId"] = evaluation_authoring_handoff_id(handoff)
        verified.path.write_bytes(canonical_json_bytes(handoff) + b"\n")
        with self.assertRaisesRegex(ValidationError, "content-addressed asset path"):
            validate_evaluation_authoring_handoff(
                verified.path, source_dataset_path=self.source
            )

    def test_reference_answer_matching_budget_is_bounded(self) -> None:
        with mock.patch.object(authoring_module, "MAX_REFERENCE_ANSWER_CHARACTERS", 10):
            with self.assertRaisesRegex(ValidationError, "bounded matching budget"):
                self._compile(self.root / "answer-budget")

    def test_existing_destination_is_preserved_and_identity_is_root_independent(
        self,
    ) -> None:
        first = self._compile()
        original = first.path.read_bytes()
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._compile()
        self.assertEqual(original, first.path.read_bytes())

        second_authoring = self.root / "second-authoring"
        shutil.copytree(self.authoring, second_authoring)
        second_source = self.root / "second-source.jsonl"
        shutil.copyfile(self.source, second_source)
        second_output = self.root / "second-handoff"
        second = compile_evaluation_authoring_handoff(
            second_authoring / "manifest.json",
            source_dataset_path=second_source,
            output_directory=second_output,
        )
        self.assertEqual(first.handoff_id, second.handoff_id)
        self.assertEqual(first.path.read_bytes(), second.path.read_bytes())
        self.assertEqual(
            (self.output / "evaluation/calibration.tasks.jsonl").read_bytes(),
            (second_output / "evaluation/calibration.tasks.jsonl").read_bytes(),
        )
        self.assertEqual(
            (self.output / "evaluation/sealed.tasks.jsonl").read_bytes(),
            (second_output / "evaluation/sealed.tasks.jsonl").read_bytes(),
        )

        race_output = self.root / "race-handoff"
        original_install = authoring_module._install_handoff_no_clobber

        def race_install(source: Path, destination: Path, field: str) -> None:
            destination.mkdir()
            original_install(source, destination, field)

        with mock.patch.object(
            authoring_module,
            "_install_handoff_no_clobber",
            side_effect=race_install,
        ):
            with self.assertRaisesRegex(
                ValidationError, "appeared during installation"
            ):
                self._compile(race_output)
        self.assertTrue(race_output.is_dir())
        self.assertEqual([], list(race_output.iterdir()))


if __name__ == "__main__":
    unittest.main()
