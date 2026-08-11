from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

import hyperion_model.cli as cli_module
from hyperion_model.core import ValidationError
from hyperion_model.evaluation import (
    EvaluationTaskSet,
    TransportResponse,
    evaluation_prompt_sha256,
    evaluation_task_sha256,
)
from hyperion_model.teacher_generation import (
    TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION,
    TEACHER_RUNTIME_DESCRIPTOR_SCHEMA_VERSION,
    TeacherRuntimeProbeResponse,
    capture_teacher_candidates,
    create_teacher_runtime_binding,
    derive_teacher_runtime_plan,
    teacher_candidate_sha256,
)
from hyperion_model.teacher_materialization import (
    MATERIALIZATION_RECORD_PATH,
    MATERIALIZED_DATASET_PATH,
    SELECTION_SNAPSHOT_PATH,
    TEACHER_MATERIALIZATION_SUMMARY_SCHEMA_VERSION,
    build_teacher_overlap_deny_set,
    create_teacher_overlap_deny_set,
    materialize_teacher_candidates,
    overlap_authored_message_prefix_sha256s,
    overlap_authored_messages_sha256,
    overlap_contamination_group_sha256,
    overlap_normalized_final_user_sha256,
    overlap_normalized_user_turn_sha256s,
    teacher_overlap_scope_sha256,
    validate_teacher_materialization,
    validate_teacher_selection_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 1, 4, tzinfo=timezone.utc)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TeacherMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vqtmat-tests-"))
        self.catalog_path = self.root / "candidate-catalog.json"
        shutil.copyfile(ROOT / "candidate-catalog.v1.json", self.catalog_path)
        self.model_root = self.root / "model"
        self.model_root.mkdir()
        self.template_path = self.model_root / "chat_template.jinja"
        self.template_path.write_text(
            "{% for message in messages %}{{ message['role'] }}: "
            "{{ message['content'] }}\\n{% endfor %}"
            "{% if add_generation_prompt %}assistant: {% endif %}",
            encoding="utf-8",
            newline="\n",
        )
        self.runtime_descriptor_path = self.root / "teacher-runtime.json"
        self.runtime_binding_path = self.root / "teacher-runtime-binding.json"
        self._write_json(
            self.runtime_descriptor_path,
            {
                "schemaVersion": TEACHER_RUNTIME_DESCRIPTOR_SCHEMA_VERSION,
                "candidateId": "qwen3-coder-30b-a3b-instruct",
                "profileVersion": "qwen3-local-teacher-profile-v1",
                "engineVersion": "0.10.0",
                "modelRoot": os.path.abspath(self.model_root),
                "maxModelLen": 128,
                "baseUrl": "http://127.0.0.1:8000/v1",
                "chatTemplatePath": "chat_template.jinja",
            },
        )
        self.execution_model_id = derive_teacher_runtime_plan(
            runtime_descriptor_path=self.runtime_descriptor_path,
            catalog_path=self.catalog_path,
        )["executionModelId"]
        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            create_teacher_runtime_binding(
                runtime_descriptor_path=self.runtime_descriptor_path,
                catalog_path=self.catalog_path,
                output_path=self.runtime_binding_path,
                api_key_env="VQ_TEACHER_TEST_KEY",
                transport=self._runtime_transport,
            )
        self.source_path = self.root / "source.txt"
        self.source_path.write_text(
            "The reviewed source says risk must be bounded before deployment.\n",
            encoding="utf-8",
            newline="\n",
        )
        self.generation_path = self.root / "teacher-generation.json"
        self.candidates_path = self.root / "teacher-candidates.jsonl"
        self.deny_path = self.root / "held-out-deny-set.json"
        self.calibration_path = self.root / "calibration-tasks.jsonl"
        self.sealed_path = self.root / "sealed-tasks.jsonl"
        self.selection_path = self.root / "teacher-selection.json"
        self.output_path = self.root / "materialized"
        self.generation = self._generation_manifest()
        self._write_json(self.generation_path, self.generation)
        self._capture()
        self._write_evaluation_tasks(
            self.calibration_path,
            [self._evaluation_task("calibration", "calibration-task-001")],
        )
        self._write_evaluation_tasks(
            self.sealed_path,
            [self._evaluation_task("sealed", "sealed-task-001")],
        )
        self.deny_set = self._deny_set()
        self._write_json(self.deny_path, self.deny_set)
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _write_evaluation_tasks(path: Path, tasks: list[dict]) -> None:
        path.write_text(
            "".join(
                json.dumps(task, ensure_ascii=False, separators=(",", ":")) + "\n"
                for task in tasks
            ),
            encoding="utf-8",
            newline="\n",
        )

    @staticmethod
    def _evaluation_task(split: str, task_id: str) -> dict:
        messages = [
            {"role": "system", "content": "Answer the held-out task."},
            {"role": "user", "content": f"What is the {split} deployment gate?"},
        ]
        task = {
            "schemaVersion": "daxalgo.hyperion.evaluation-task/v1",
            "taskId": task_id,
            "taskSha256": "0" * 64,
            "split": split,
            "taskKind": "GeneralQuestionAnswering",
            "domains": ["RiskManagement"],
            "messages": messages,
            "promptSha256": evaluation_prompt_sha256(messages),
            "contextPack": {"version": f"context-pack-{split}-v1", "sha256": "4" * 64},
            "verifier": {
                "id": "held-out-verifier-v1",
                "sha256": "5" * 64,
                "requiredChecks": ["exact-claim"],
            },
            "contaminationGroup": f"{split}-group-001",
            "cutoffUtc": "2025-12-31T00:00:00Z",
            "criticality": "standard",
            "maxOutputTokens": 64,
        }
        task["taskSha256"] = evaluation_task_sha256(task)
        return task

    def _generation_manifest(self) -> dict:
        return {
            "schemaVersion": TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION,
            "draftManifestSha256": hashlib.sha256(
                b"teacher-materialization-unit-test-draft"
            ).hexdigest(),
            "candidateCatalogSha256": _sha256(self.catalog_path),
            "split": "development",
            "teacher": {
                "candidateId": "qwen3-coder-30b-a3b-instruct",
                "profileVersion": "qwen3-local-teacher-profile-v1",
                "chatTemplateSha256": _sha256(self.template_path),
                "runtimeSha256": _sha256(self.runtime_descriptor_path),
            },
            "generation": {
                "temperature": 0.2,
                "topP": 0.95,
                "seeds": [17, 29],
            },
            "budget": {
                "maxRequests": 2,
                "maxPromptTokens": 100,
                "maxCompletionTokens": 256,
                "maxTotalTokens": 400,
            },
            "authority": {
                "producer": "unit-test-producer",
                "reviewer": "independent-reviewer-pending",
                "provenance": "Private development-task authoring fixture.",
                "license": "Internal evaluation grant",
                "rightsBasis": "Explicit test-only storage and evaluation authority.",
                "rights": {
                    "mayStore": True,
                    "mayEvaluate": True,
                    "mayTrain": False,
                    "mayUploadToProvider": False,
                    "mayRedistribute": False,
                },
            },
            "tokenizerPreflight": {
                "protocol": "vllm-tokenize-chat/v1",
                "maxModelLen": 128,
            },
            "tasks": [
                {
                    "taskId": "teacher-task-001",
                    "taskKind": "GeneralQuestionAnswering",
                    "domains": ["RiskManagement"],
                    "messages": [
                        {
                            "role": "system",
                            "content": "Answer concisely from the supplied evidence.",
                        },
                        {
                            "role": "user",
                            "content": "What must happen before deployment?",
                        },
                    ],
                    "contaminationGroup": "teacher-group-001",
                    "knowledgeClass": "candidate-stable",
                    "cutoffUtc": "2026-01-01T12:00:00Z",
                    "maxOutputTokens": 64,
                    "evidence": ["Expected claim: risk is bounded before deployment."],
                    "sources": [
                        {
                            "id": "source-001",
                            "title": "Reviewed risk note",
                            "contentPath": "source.txt",
                            "contentSha256": _sha256(self.source_path),
                            "provenance": "Private unit-test fixture.",
                            "license": "Internal evaluation grant",
                            "retrievedAtUtc": "2026-01-01T11:00:00Z",
                            "availableAtUtc": "2025-12-31T12:00:00Z",
                            "uri": "https://example.invalid/reviewed-risk-note",
                        }
                    ],
                }
            ],
        }

    def _response(self, url: str, requested: dict, content: str) -> TransportResponse:
        return TransportResponse(
            json.dumps(
                {
                    "model": requested["model"],
                    "choices": [
                        {
                            "message": {"role": "assistant", "content": content},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 3,
                        "total_tokens": 13,
                    },
                }
            ).encode("utf-8"),
            url,
        )

    def _runtime_transport(
        self, method, url, headers, timeout, max_response_bytes
    ) -> TeacherRuntimeProbeResponse:
        if url.endswith("/version"):
            payload = {"version": "0.10.0"}
        else:
            payload = {
                "object": "list",
                "data": [
                    {
                        "id": self.execution_model_id,
                        "root": os.path.abspath(self.model_root),
                        "max_model_len": 128,
                    }
                ],
            }
        return TeacherRuntimeProbeResponse(
            status=200,
            content_type="application/json",
            body=json.dumps(payload).encode("utf-8"),
            final_url=url,
        )

    def _capture(self, content_factory=None) -> None:
        monotonic = iter((1.0, 1.1, 2.0, 2.2)).__next__

        def transport(url, headers, body, timeout, max_bytes):
            requested = json.loads(body)
            content = (
                content_factory(requested)
                if content_factory is not None
                else f"Candidate answer for seed {requested['seed']}."
            )
            return self._response(url, requested, content)

        def tokenizer_transport(url, headers, body, timeout, max_bytes):
            payload = {
                "count": 10,
                "max_model_len": 128,
                "tokens": list(range(10)),
                "token_strs": None,
            }
            return TransportResponse(json.dumps(payload).encode("utf-8"), url)

        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            capture_teacher_candidates(
                manifest_path=self.generation_path,
                catalog_path=self.catalog_path,
                runtime_binding_path=self.runtime_binding_path,
                output_path=self.candidates_path,
                base_url="http://127.0.0.1:8000/v1",
                api_key_env="VQ_TEACHER_TEST_KEY",
                transport=transport,
                tokenizer_transport=tokenizer_transport,
                runtime_transport=self._runtime_transport,
                clock=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
                monotonic=monotonic,
            )

    def _candidate_records(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self.candidates_path.read_text(encoding="utf-8").splitlines()
        ]

    def _deny_set(self) -> dict:
        return build_teacher_overlap_deny_set(
            calibration_tasks_path=self.calibration_path,
            sealed_tasks_path=self.sealed_path,
            deny_set_id="sealed-suite-overlap-v1",
            custodian="held-out-custodian",
            created_at_utc="2026-01-01T00:00:00Z",
        )

    def _selection_manifest(self) -> dict:
        candidate = self._candidate_records()[0]
        rights = {
            "mayStore": True,
            "mayEvaluate": True,
            "mayTrain": False,
            "mayUploadToProvider": False,
            "mayRedistribute": False,
        }
        return {
            "schemaVersion": "daxalgo.hyperion.teacher-selection-manifest/v1",
            "purpose": "independent-review-draft",
            "inputs": {
                "candidateSet": {
                    "path": self.candidates_path.name,
                    "sha256": _sha256(self.candidates_path),
                },
                "generationManifest": {
                    "path": self.generation_path.name,
                    "sha256": _sha256(self.generation_path),
                },
                "candidateCatalog": {
                    "path": self.catalog_path.name,
                    "sha256": _sha256(self.catalog_path),
                },
                "overlapDenySet": {
                    "path": self.deny_path.name,
                    "sha256": _sha256(self.deny_path),
                },
            },
            "selection": {
                "selectedBy": "independent-selector",
                "selectedAtUtc": "2026-01-03T00:00:00Z",
                "basis": "Independent source-grounded correctness triage for draft review.",
                "candidates": [
                    {
                        "candidateId": candidate["candidateId"],
                        "candidateSha256": candidate["candidateSha256"],
                    }
                ],
            },
            "outputPolicy": {
                "schemaVersion": "expert-model-dataset/v1",
                "split": "development",
                "lineageOrigin": "OpenWeightTeacher",
                "reviewStatus": "draft",
                "verified": False,
                "verifiedAtUtc": None,
                "compileSucceeded": False,
                "testsPassed": False,
                "useForTraining": False,
                "rights": rights,
                "sourceRights": dict(rights),
            },
        }

    def _rewrite_selection_bindings(self) -> None:
        self.selection["inputs"]["candidateSet"]["sha256"] = _sha256(
            self.candidates_path
        )
        self.selection["inputs"]["generationManifest"]["sha256"] = _sha256(
            self.generation_path
        )
        self.selection["inputs"]["overlapDenySet"]["sha256"] = _sha256(self.deny_path)
        candidate = self._candidate_records()[0]
        self.selection["selection"]["candidates"] = [
            {
                "candidateId": candidate["candidateId"],
                "candidateSha256": candidate["candidateSha256"],
            }
        ]
        self._write_json(self.selection_path, self.selection)

    def test_materializes_exact_open_weight_non_training_draft(self) -> None:
        prepared = validate_teacher_selection_manifest(self.selection_path, now=NOW)
        package = materialize_teacher_candidates(
            selection_manifest_path=self.selection_path,
            output_directory=self.output_path,
            now=NOW,
        )
        validated = validate_teacher_materialization(
            self.output_path,
            now=NOW,
        )
        externally_validated = validate_teacher_materialization(
            self.output_path,
            selection_manifest_path=self.selection_path,
            now=NOW,
        )
        self.assertEqual(package.dataset_sha256, validated.dataset_sha256)
        self.assertEqual(validated.dataset_sha256, externally_validated.dataset_sha256)
        self.assertEqual(
            prepared.materialization_record["materializationId"],
            package.materialization_id,
        )
        self.assertEqual(1, package.record_count)

        row = json.loads(
            (self.output_path / MATERIALIZED_DATASET_PATH).read_text(encoding="utf-8")
        )
        candidate = self._candidate_records()[0]
        self.assertEqual(candidate["candidateId"], row["id"])
        self.assertEqual("OpenWeightTeacher", row["lineage"]["origin"])
        self.assertEqual(candidate["teacher"]["modelId"], row["lineage"]["modelId"])
        self.assertEqual(
            candidate["task"]["promptSha256"], row["lineage"]["promptSha256"]
        )
        self.assertEqual(candidate["output"]["text"], row["messages"][-1]["content"])
        self.assertNotIn("modelMessages", row)
        self.assertEqual("draft", row["reviewStatus"])
        self.assertFalse(row["verification"]["verified"])
        self.assertIsNone(row["verification"]["verifiedAtUtc"])
        self.assertFalse(row["useForTraining"])
        self.assertFalse(row["rights"]["mayTrain"])
        self.assertFalse(row["sources"][0]["rights"]["mayTrain"])
        self.assertNotIn("contentSha256", row["sources"][0])
        self.assertTrue(
            row["verification"]["evidence"][1].startswith("teacherAdmissionSha256=")
        )

        record = json.loads(
            (self.output_path / MATERIALIZATION_RECORD_PATH).read_text(encoding="utf-8")
        )
        self.assertEqual("unsigned", record["authenticationStatus"])
        self.assertTrue(record["requiresAuthenticatedReviewReceipts"])
        self.assertEqual(0, record["output"]["trainingEligibleCount"])
        self.assertEqual(
            candidate["sources"][0]["contentSha256"],
            record["admissions"][0]["sourceContentSha256"][0],
        )
        self.assertEqual(
            overlap_authored_messages_sha256(candidate["task"]["messages"]),
            record["admissions"][0]["authoredMessagesSha256"],
        )
        self.assertTrue((self.output_path / SELECTION_SNAPSHOT_PATH).is_file())

        for path in (
            self.selection_path,
            self.candidates_path,
            self.generation_path,
            self.catalog_path,
            self.deny_path,
            self.source_path,
        ):
            path.unlink()
        self.assertEqual(
            package.dataset_sha256,
            validate_teacher_materialization(self.output_path, now=NOW).dataset_sha256,
        )

    def test_manifest_v2_rejects_stripped_runtime_binding_linkage(self) -> None:
        records = self._candidate_records()
        for record in records:
            del record["runtimeBindingFileSha256"]
            record["candidateSha256"] = teacher_candidate_sha256(record)
        self.candidates_path.write_text(
            "".join(
                json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
                for record in records
            ),
            encoding="utf-8",
            newline="\n",
        )
        self._rewrite_selection_bindings()

        with self.assertRaisesRegex(ValidationError, "manifest v2 candidate queue"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)
        with self.assertRaisesRegex(ValidationError, "manifest v2 candidate queue"):
            materialize_teacher_candidates(
                selection_manifest_path=self.selection_path,
                output_directory=self.output_path,
                now=NOW,
            )
        self.assertFalse(self.output_path.exists())

    def test_rejects_every_held_out_overlap_dimension(self) -> None:
        candidate = self._candidate_records()[0]
        cases = {
            "authoredMessagesSha256": overlap_authored_messages_sha256(
                candidate["task"]["messages"]
            ),
            "normalizedUserTurnSha256": overlap_normalized_final_user_sha256(
                candidate["task"]["messages"]
            ),
            "contaminationGroupSha256": overlap_contamination_group_sha256(
                candidate["task"]["contaminationGroup"]
            ),
            "heldOutAssetSha256": candidate["sources"][0]["contentSha256"],
        }
        for name, denied in cases.items():
            with self.subTest(name=name):
                self.deny_set = self._deny_set()
                values = self.deny_set["entries"][name]
                if name == "authoredMessagesSha256":
                    values[0] = denied
                else:
                    values.append(denied)
                self.deny_set["entries"][name] = sorted(set(values))
                self._write_json(self.deny_path, self.deny_set)
                self.selection = self._selection_manifest()
                self._write_json(self.selection_path, self.selection)
                with self.assertRaisesRegex(ValidationError, name):
                    validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_overlap_builder_is_cross_pipeline_hash_only_and_scope_bound(self) -> None:
        document = self._deny_set()
        encoded = json.dumps(document, ensure_ascii=False)
        self.assertNotIn("What is the calibration deployment gate?", encoded)
        self.assertNotIn("calibration-task-001", encoded)
        self.assertNotIn("calibration-group-001", encoded)
        self.assertEqual(
            teacher_overlap_scope_sha256(document["scope"]),
            document["scopeSha256"],
        )

        candidate = self._candidate_records()[0]
        calibration = self._evaluation_task("calibration", "different-task-id")
        calibration["messages"] = candidate["task"]["messages"]
        calibration["promptSha256"] = evaluation_prompt_sha256(calibration["messages"])
        calibration["taskSha256"] = evaluation_task_sha256(calibration)
        self._write_evaluation_tasks(self.calibration_path, [calibration])
        self.deny_set = self._deny_set()
        self._write_json(self.deny_path, self.deny_set)
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "authoredMessagesSha256"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_overlap_normalization_and_scope_tamper_fail_closed(self) -> None:
        messages = self._candidate_records()[0]["task"]["messages"]
        variant = [dict(message) for message in messages]
        variant[-1]["content"] = "  WHAT   MUST HAPPEN BEFORE DEPLOYMENT?  "
        self.assertNotEqual(
            overlap_authored_messages_sha256(messages),
            overlap_authored_messages_sha256(variant),
        )
        self.assertEqual(
            overlap_normalized_final_user_sha256(messages),
            overlap_normalized_final_user_sha256(variant),
        )

        self.deny_set["scopeSha256"] = "0" * 64
        self._write_json(self.deny_path, self.deny_set)
        self.selection["inputs"]["overlapDenySet"]["sha256"] = _sha256(self.deny_path)
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "scopeSha256"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_held_out_conversation_prefix_and_nonfinal_user_fail_closed(self) -> None:
        held_out = self._evaluation_task("calibration", "calibration-task-001")[
            "messages"
        ]
        self.candidates_path.unlink()
        self.generation["tasks"][0]["messages"] = [
            *held_out,
            {"role": "assistant", "content": "Intermediate answer."},
            {"role": "user", "content": "A different final request."},
        ]
        self._write_json(self.generation_path, self.generation)
        self._capture()
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        candidate_messages = self._candidate_records()[0]["task"]["messages"]
        self.assertIn(
            overlap_authored_messages_sha256(held_out),
            overlap_authored_message_prefix_sha256s(candidate_messages),
        )
        with self.assertRaisesRegex(ValidationError, "authoredMessagesSha256"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.candidates_path.unlink()
        self.generation["tasks"][0]["messages"] = [
            {"role": "system", "content": "A different system instruction."},
            {
                "role": "user",
                "content": "  WHAT   IS THE CALIBRATION DEPLOYMENT GATE?  ",
            },
            {"role": "assistant", "content": "Intermediate answer."},
            {"role": "user", "content": "A different final request."},
        ]
        self._write_json(self.generation_path, self.generation)
        self._capture()
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        candidate_messages = self._candidate_records()[0]["task"]["messages"]
        self.assertFalse(
            set(overlap_authored_message_prefix_sha256s(candidate_messages))
            & set(self.deny_set["entries"]["authoredMessagesSha256"])
        )
        self.assertTrue(
            set(overlap_normalized_user_turn_sha256s(candidate_messages))
            & set(self.deny_set["entries"]["normalizedUserTurnSha256"])
        )
        with self.assertRaisesRegex(ValidationError, "normalizedUserTurnSha256"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_exact_held_out_task_file_cannot_be_a_teacher_source(self) -> None:
        self.candidates_path.unlink()
        self.source_path.write_bytes(self.calibration_path.read_bytes())
        self.generation["tasks"][0]["sources"][0]["contentSha256"] = _sha256(
            self.source_path
        )
        self._write_json(self.generation_path, self.generation)
        self._capture()
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "heldOutAssetSha256"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_overlap_builder_rejects_mixed_scope_and_no_clobber_output(self) -> None:
        mixed = self._evaluation_task("calibration", "wrong-sealed-task")
        self._write_evaluation_tasks(self.sealed_path, [mixed])
        with self.assertRaisesRegex(ValidationError, "only sealed"):
            self._deny_set()

        self._write_evaluation_tasks(
            self.sealed_path,
            [self._evaluation_task("sealed", "sealed-task-001")],
        )
        created = create_teacher_overlap_deny_set(
            calibration_tasks_path=self.calibration_path,
            sealed_tasks_path=self.sealed_path,
            output_path=self.root / "created-deny-set.json",
            deny_set_id="created-overlap-v1",
            custodian="held-out-custodian",
            created_at_utc="2026-01-01T00:00:00Z",
        )
        self.assertEqual("created-overlap-v1", created["denySetId"])
        with self.assertRaisesRegex(ValidationError, "already exists"):
            create_teacher_overlap_deny_set(
                calibration_tasks_path=self.calibration_path,
                sealed_tasks_path=self.sealed_path,
                output_path=self.root / "created-deny-set.json",
                deny_set_id="created-overlap-v1",
                custodian="held-out-custodian",
                created_at_utc="2026-01-01T00:00:00Z",
            )

    def test_overlap_scope_binds_bytes_semantics_and_entries(self) -> None:
        second = self._evaluation_task("calibration", "calibration-task-002")
        second["messages"][-1]["content"] = "What is the second calibration gate?"
        second["promptSha256"] = evaluation_prompt_sha256(second["messages"])
        second["contaminationGroup"] = "calibration-group-002"
        second["taskSha256"] = evaluation_task_sha256(second)
        first = self._evaluation_task("calibration", "calibration-task-001")
        self._write_evaluation_tasks(self.calibration_path, [first, second])
        original = self._deny_set()

        self._write_evaluation_tasks(self.calibration_path, [second, first])
        reordered = self._deny_set()
        self.assertNotEqual(
            original["scope"]["calibration"]["fileSha256"],
            reordered["scope"]["calibration"]["fileSha256"],
        )
        self.assertEqual(
            original["scope"]["calibration"]["taskSetSha256"],
            reordered["scope"]["calibration"]["taskSetSha256"],
        )
        self.assertNotEqual(original["scopeSha256"], reordered["scopeSha256"])
        for name in (
            "authoredMessagesSha256",
            "normalizedUserTurnSha256",
            "contaminationGroupSha256",
        ):
            self.assertEqual(original["entries"][name], reordered["entries"][name])
        self.assertNotEqual(
            original["entries"]["heldOutAssetSha256"],
            reordered["entries"]["heldOutAssetSha256"],
        )

        second["messages"][-1]["content"] = "What is the mutated calibration gate?"
        second["promptSha256"] = evaluation_prompt_sha256(second["messages"])
        second["taskSha256"] = evaluation_task_sha256(second)
        self._write_evaluation_tasks(self.calibration_path, [first, second])
        mutated = self._deny_set()
        self.assertNotEqual(
            original["scope"]["calibration"]["taskSetSha256"],
            mutated["scope"]["calibration"]["taskSetSha256"],
        )
        self.assertNotEqual(
            original["entries"]["authoredMessagesSha256"],
            mutated["entries"]["authoredMessagesSha256"],
        )

    def test_overlap_builder_overflow_fails_instead_of_truncating(self) -> None:
        calibration_records = tuple(
            {
                "split": "calibration",
                "messages": [{"role": "user", "content": f"calibration {index}"}],
                "contaminationGroup": f"calibration-{index}",
            }
            for index in range(10_000)
        )
        sealed_records = (
            {
                "split": "sealed",
                "messages": [{"role": "user", "content": "sealed overflow"}],
                "contaminationGroup": "sealed-overflow",
            },
        )
        task_sets = [
            EvaluationTaskSet(
                path=self.calibration_path,
                sha256="6" * 64,
                task_set_sha256="7" * 64,
                records=calibration_records,
            ),
            EvaluationTaskSet(
                path=self.sealed_path,
                sha256="8" * 64,
                task_set_sha256="9" * 64,
                records=sealed_records,
            ),
        ]
        with mock.patch(
            "hyperion_model.teacher_materialization.validate_evaluation_tasks",
            side_effect=task_sets,
        ):
            with self.assertRaisesRegex(ValidationError, "exceeds 10000"):
                build_teacher_overlap_deny_set(
                    calibration_tasks_path=self.calibration_path,
                    sealed_tasks_path=self.sealed_path,
                    deny_set_id="overflow-v1",
                    custodian="held-out-custodian",
                    created_at_utc="2026-01-01T00:00:00Z",
                )

    def test_derived_entry_overflow_never_publishes_a_deny_set(self) -> None:
        calibration_records = []
        for task_index in range(157):
            messages = []
            for turn_index in range(64):
                messages.append(
                    {
                        "role": "user",
                        "content": f"calibration {task_index} turn {turn_index}",
                    }
                )
                if turn_index != 63:
                    messages.append(
                        {
                            "role": "assistant",
                            "content": f"intermediate {task_index} turn {turn_index}",
                        }
                    )
            calibration_records.append(
                {
                    "split": "calibration",
                    "messages": messages,
                    "contaminationGroup": f"calibration-{task_index}",
                    "contextPack": {
                        "sha256": hashlib.sha256(
                            f"context-{task_index}".encode()
                        ).hexdigest()
                    },
                    "verifier": {"sha256": "a" * 64},
                }
            )
        sealed_records = (
            {
                "split": "sealed",
                "messages": [{"role": "user", "content": "sealed derived overflow"}],
                "contaminationGroup": "sealed-derived-overflow",
                "contextPack": {"sha256": "b" * 64},
                "verifier": {"sha256": "c" * 64},
            },
        )
        task_sets = [
            EvaluationTaskSet(
                path=self.calibration_path,
                sha256="6" * 64,
                task_set_sha256="7" * 64,
                records=tuple(calibration_records),
            ),
            EvaluationTaskSet(
                path=self.sealed_path,
                sha256="8" * 64,
                task_set_sha256="9" * 64,
                records=sealed_records,
            ),
        ]
        output = self.root / "derived-overflow-deny-set.json"
        with mock.patch(
            "hyperion_model.teacher_materialization.validate_evaluation_tasks",
            side_effect=task_sets,
        ):
            with self.assertRaisesRegex(ValidationError, "normalizedUserTurnSha256"):
                create_teacher_overlap_deny_set(
                    calibration_tasks_path=self.calibration_path,
                    sealed_tasks_path=self.sealed_path,
                    output_path=output,
                    deny_set_id="derived-overflow-v1",
                    custodian="held-out-custodian",
                    created_at_utc="2026-01-01T00:00:00Z",
                )
        self.assertFalse(output.exists())

    def test_selection_is_independent_ordered_and_one_per_task(self) -> None:
        records = self._candidate_records()
        self.selection["selection"]["selectedBy"] = "unit-test-producer"
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "independent"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.selection = self._selection_manifest()
        self.deny_set["custodian"] = "independent-selector"
        self._write_json(self.deny_path, self.deny_set)
        self.selection["inputs"]["overlapDenySet"]["sha256"] = _sha256(self.deny_path)
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "custodian"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.deny_set = self._deny_set()
        self._write_json(self.deny_path, self.deny_set)
        self.selection = self._selection_manifest()
        self.selection["inputs"]["overlapDenySet"]["sha256"] = _sha256(self.deny_path)
        self.selection["selection"]["candidates"] = [
            {
                "candidateId": record["candidateId"],
                "candidateSha256": record["candidateSha256"],
            }
            for record in records
        ]
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "same task"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_hash_tamper_and_package_tamper_fail_closed(self) -> None:
        self.selection["inputs"]["candidateSet"]["sha256"] = "0" * 64
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "bound file bytes"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        materialize_teacher_candidates(
            selection_manifest_path=self.selection_path,
            output_directory=self.output_path,
            now=NOW,
        )
        original = (self.output_path / MATERIALIZED_DATASET_PATH).read_bytes()
        with self.assertRaisesRegex(ValidationError, "already exists"):
            materialize_teacher_candidates(
                selection_manifest_path=self.selection_path,
                output_directory=self.output_path,
                now=NOW,
            )
        self.assertEqual(
            original, (self.output_path / MATERIALIZED_DATASET_PATH).read_bytes()
        )

        (self.output_path / MATERIALIZED_DATASET_PATH).write_bytes(original + b" ")
        with self.assertRaisesRegex(ValidationError, "does not exactly match"):
            validate_teacher_materialization(
                self.output_path,
                selection_manifest_path=self.selection_path,
                now=NOW,
            )

        (self.output_path / MATERIALIZED_DATASET_PATH).write_bytes(original)
        (self.output_path / "unexpected.txt").write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "exactly the canonical"):
            validate_teacher_materialization(
                self.output_path,
                selection_manifest_path=self.selection_path,
                now=NOW,
            )
        (self.output_path / "unexpected.txt").unlink()

        embedded_deny = self.output_path / "inputs" / "snapshot" / self.deny_path.name
        embedded_deny.write_bytes(embedded_deny.read_bytes() + b" ")
        with self.assertRaisesRegex(ValidationError, "bound file bytes"):
            validate_teacher_materialization(self.output_path, now=NOW)

    def test_containment_policy_and_temporal_boundaries_fail_closed(self) -> None:
        self.selection["inputs"]["candidateSet"]["path"] = "../outside.jsonl"
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "contained relative path"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.selection = self._selection_manifest()
        self.selection["outputPolicy"]["rights"]["mayTrain"] = True
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "storage-and-evaluation"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.selection = self._selection_manifest()
        self.selection["outputPolicy"]["verified"] = 0
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "must be a boolean"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.selection = self._selection_manifest()
        self.selection["selection"]["selectedAtUtc"] = "2026-01-05T00:00:00Z"
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "future"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.selection = self._selection_manifest()
        self.deny_set["createdAtUtc"] = "2026-01-03T00:00:01Z"
        self._write_json(self.deny_path, self.deny_set)
        self.selection["inputs"]["overlapDenySet"]["sha256"] = _sha256(self.deny_path)
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "must not follow"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_utf16_and_reserved_evidence_limits_match_corpus_boundary(self) -> None:
        shutil.rmtree(self.output_path, ignore_errors=True)
        self.candidates_path.unlink()
        huge = "😀" * 250_001
        self._capture(lambda requested: huge + str(requested["seed"]))
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "UTF-16"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

        self.candidates_path.unlink()
        self.generation["tasks"][0]["evidence"] = [
            f"Evidence {index}" for index in range(127)
        ]
        self._write_json(self.generation_path, self.generation)
        self._capture()
        self.selection = self._selection_manifest()
        self._write_json(self.selection_path, self.selection)
        with self.assertRaisesRegex(ValidationError, "leave two"):
            validate_teacher_selection_manifest(self.selection_path, now=NOW)

    def test_cli_validates_materializes_and_revalidates(self) -> None:
        stream = StringIO()
        cli_deny_path = self.root / "cli-deny-set.json"
        with redirect_stdout(stream):
            result = cli_module.main(
                [
                    "create-teacher-overlap-deny-set",
                    "--calibration-tasks",
                    str(self.calibration_path),
                    "--sealed-tasks",
                    str(self.sealed_path),
                    "--deny-set-id",
                    "cli-overlap-v1",
                    "--custodian",
                    "held-out-custodian",
                    "--created-at-utc",
                    "2026-01-01T00:00:00Z",
                    "--output",
                    str(cli_deny_path),
                ]
            )
        self.assertEqual(0, result)
        self.assertTrue(json.loads(stream.getvalue())["created"])

        stream = StringIO()
        with redirect_stdout(stream):
            result = cli_module.main(
                ["validate-teacher-selection", "--selection", str(self.selection_path)]
            )
        self.assertEqual(0, result)
        self.assertTrue(json.loads(stream.getvalue())["valid"])

        stream = StringIO()
        with redirect_stdout(stream):
            result = cli_module.main(
                [
                    "materialize-teacher-candidates",
                    "--selection",
                    str(self.selection_path),
                    "--output",
                    str(self.output_path),
                ]
            )
        self.assertEqual(0, result)
        materialized = json.loads(stream.getvalue())
        self.assertTrue(materialized["created"])
        self.assertEqual(
            TEACHER_MATERIALIZATION_SUMMARY_SCHEMA_VERSION,
            materialized["schemaVersion"],
        )

        stream = StringIO()
        with redirect_stdout(stream):
            result = cli_module.main(
                [
                    "validate-teacher-materialization",
                    str(self.output_path),
                ]
            )
        self.assertEqual(0, result)
        self.assertTrue(json.loads(stream.getvalue())["valid"])


if __name__ == "__main__":
    unittest.main()
