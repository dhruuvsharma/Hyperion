from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from vibe_quant_model.base_evaluation import (
    APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256,
    BASE_EVALUATION_PROFILE_SCHEMA_VERSION,
    BASE_EXECUTION_MODEL_PREFIX,
    BASE_MODEL_SNAPSHOT_SCHEMA_VERSION,
    BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
    build_base_evaluation_vllm_launch,
    create_base_evaluation_profile,
    load_base_model_source_lock,
    seal_base_model_snapshot,
    validate_base_evaluation_profile,
    validate_base_model_snapshot,
)
from vibe_quant_model.core import DOMAINS, ValidationError, canonical_json_bytes
from vibe_quant_model.evaluation import (
    EVALUATION_TASK_SCHEMA_VERSION,
    TransportResponse,
    capture_openai_responses,
    evaluation_prompt_sha256,
    evaluation_task_sha256,
    validate_evaluation_responses,
    validate_evaluation_tasks,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8", newline="\n")


def _write_jsonl(path: Path, *records: dict) -> None:
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
        newline="\n",
    )


def _evaluation_task(task_id: str = "base-eval-1") -> dict:
    messages = [
        {"role": "system", "content": "Answer from reviewed context only."},
        {"role": "user", "content": "Review the supplied C# risk calculation."},
    ]
    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": task_id,
        "taskSha256": "0" * 64,
        "split": "sealed",
        "taskKind": "CodeReview",
        "domains": list(DOMAINS),
        "messages": messages,
        "promptSha256": evaluation_prompt_sha256(messages),
        "contextPack": {"version": "reviewed-context-v1", "sha256": "a" * 64},
        "verifier": {
            "id": "reviewed-verifier-v1",
            "sha256": "b" * 64,
            "requiredChecks": ["correct", "safe"],
        },
        "contaminationGroup": f"group-{task_id}",
        "cutoffUtc": "2025-01-15T12:00:00Z",
        "criticality": "critical",
        "maxOutputTokens": 128,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    return task


def _safetensors() -> bytes:
    header = b'{"weight":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}'
    return len(header).to_bytes(8, "little") + header + b"\x00\x00"


class BaseEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = self.root / "candidate-catalog.json"
        shutil.copyfile(ROOT / "candidate-catalog.v1.json", self.catalog)
        self.snapshot = self.root / "model"
        self.snapshot.mkdir()
        _write_json(self.snapshot / "config.json", {"model_type": "qwen2"})
        _write_json(
            self.snapshot / "tokenizer_config.json",
            {
                "chat_template": (
                    "{% for message in messages %}{{ message['role'] }}: "
                    "{{ message['content'] }}{% endfor %}"
                )
            },
        )
        _write_json(self.snapshot / "tokenizer.json", {"version": "1.0"})
        (self.snapshot / "model.safetensors").write_bytes(_safetensors())
        source_files = []
        for path in sorted(self.snapshot.iterdir(), key=lambda item: item.name):
            raw = path.read_bytes()
            source_files.append(
                {
                    "path": path.name,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "sizeBytes": len(raw),
                }
            )
        catalog = json.loads(self.catalog.read_text(encoding="utf-8"))
        candidate = next(
            item
            for item in catalog["candidates"]
            if item["id"] == "qwen2.5-coder-7b-instruct"
        )
        self.source_lock = self.root / "base-model-source-lock.json"
        _write_json(
            self.source_lock,
            {
                "schemaVersion": BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
                "candidateCatalogSha256": hashlib.sha256(
                    self.catalog.read_bytes()
                ).hexdigest(),
                "candidates": [
                    {
                        "candidateId": candidate["id"],
                        "modelId": candidate["modelId"],
                        "revision": candidate["revision"],
                        "files": source_files,
                    }
                ],
            },
        )
        self.source_lock_patcher = mock.patch(
            "vibe_quant_model.base_evaluation.APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256",
            hashlib.sha256(
                canonical_json_bytes(
                    json.loads(self.source_lock.read_text(encoding="utf-8"))
                )
            ).hexdigest(),
        )
        self.source_lock_patcher.start()
        self.manifest = self.root / "base-model-snapshot.json"
        self.profile_path = self.root / "base-evaluation-profile.json"
        self.snapshot_record = seal_base_model_snapshot(
            snapshot_path=self.snapshot,
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
            candidate_id="qwen2.5-coder-7b-instruct",
            output_path=self.manifest,
        )
        self.profile = create_base_evaluation_profile(
            profile_id="qwen25-7b-base-v1",
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
            snapshot_manifest_path=self.manifest,
            snapshot_path=self.snapshot,
            output_path=self.profile_path,
            engine_version="0.10.0",
            container_image_digest="sha256:" + "6" * 64,
            quantization="bitsandbytes-nf4",
            compute_dtype="bfloat16",
            max_model_length=8_192,
            tensor_parallel_size=1,
            gpu_profile="l40s-48gb",
        )

    def tearDown(self) -> None:
        self.source_lock_patcher.stop()
        self.temporary.cleanup()

    def _capture(self, output: Path, *, research_only: bool = True, **kwargs) -> dict:
        tasks = kwargs.pop("tasks", self.root / "sealed.tasks.jsonl")
        if not tasks.exists():
            _write_jsonl(tasks, _evaluation_task())

        def transport(url, headers, body, timeout, max_bytes):
            request = json.loads(body)
            response = {
                "id": "chatcmpl-base-test",
                "object": "chat.completion",
                "created": 1,
                "model": request["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Reviewed."},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 2,
                    "total_tokens": 12,
                },
            }
            return TransportResponse(json.dumps(response).encode("utf-8"), url)

        monotonic_values = iter((0.0, 0.1)).__next__
        with mock.patch.dict(os.environ, {"VQ_BASE_TEST_KEY": "secret"}, clear=False):
            return capture_openai_responses(
                tasks_path=tasks,
                catalog_path=self.catalog,
                output_path=output,
                base_evaluation_profile_path=self.profile_path,
                base_model_snapshot_manifest_path=self.manifest,
                base_model_snapshot_path=self.snapshot,
                base_model_source_lock_path=self.source_lock,
                run_id="base-eval-run-1",
                base_url=kwargs.pop("base_url", "http://127.0.0.1:8000/v1"),
                api_key_env="VQ_BASE_TEST_KEY",
                seed=17,
                research_only=research_only,
                transport=kwargs.pop("transport", transport),
                clock=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
                monotonic=monotonic_values,
                **kwargs,
            )

    def test_snapshot_profile_and_vllm_launch_are_content_addressed(self) -> None:
        snapshot = validate_base_model_snapshot(
            manifest_path=self.manifest,
            snapshot_path=self.snapshot,
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
        )
        self.assertEqual(
            BASE_MODEL_SNAPSHOT_SCHEMA_VERSION, snapshot.document["schemaVersion"]
        )
        self.assertEqual(4, len(snapshot.document["files"]))
        self.assertEqual(
            hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            snapshot.manifest_sha256,
        )
        self.assertEqual(
            hashlib.sha256(
                canonical_json_bytes(
                    json.loads(self.source_lock.read_text(encoding="utf-8"))
                )
            ).hexdigest(),
            snapshot.document["sourceLockSha256"],
        )
        profile = validate_base_evaluation_profile(
            profile_path=self.profile_path,
            snapshot_manifest_path=self.manifest,
            snapshot_path=self.snapshot,
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
        )
        self.assertEqual(
            BASE_EVALUATION_PROFILE_SCHEMA_VERSION,
            profile.document["schemaVersion"],
        )
        self.assertTrue(profile.document["evaluationOnly"])
        self.assertEqual("unpromoted", profile.document["promotionStatus"])
        self.assertEqual(
            BASE_EXECUTION_MODEL_PREFIX + profile.sha256,
            profile.execution_model_id,
        )

        launch = build_base_evaluation_vllm_launch(
            profile_path=self.profile_path,
            snapshot_manifest_path=self.manifest,
            snapshot_path=self.snapshot,
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
            executable_path=sys.executable,
            port=8000,
        )
        argv = launch["argv"]
        self.assertEqual(
            profile.execution_model_id, argv[argv.index("--served-model-name") + 1]
        )
        self.assertNotIn("--enable-lora", argv)
        self.assertNotIn("--lora-modules", argv)
        self.assertFalse(launch["runtimeAttested"])
        self.assertFalse(launch["releaseEvidenceEligible"])
        self.assertEqual("1", launch["environment"]["HF_HUB_OFFLINE"])
        self.assertEqual("sha256:" + "6" * 64, launch["expectedContainerImageDigest"])

        for schema_name, version in (
            (
                "base-model-source-lock.v1.schema.json",
                BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
            ),
            ("base-model-snapshot.v1.schema.json", BASE_MODEL_SNAPSHOT_SCHEMA_VERSION),
            (
                "base-evaluation-profile.v1.schema.json",
                BASE_EVALUATION_PROFILE_SCHEMA_VERSION,
            ),
        ):
            schema = json.loads((ROOT / "schemas" / schema_name).read_text("utf-8"))
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(version, schema["properties"]["schemaVersion"]["const"])

        approved_lock = ROOT / "base-model-source-lock.v1.json"
        self.assertEqual(
            APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256,
            hashlib.sha256(
                canonical_json_bytes(
                    json.loads(approved_lock.read_text(encoding="utf-8"))
                )
            ).hexdigest(),
        )
        self.assertEqual(
            3, len(json.loads(approved_lock.read_text(encoding="utf-8"))["candidates"])
        )
        with mock.patch(
            "vibe_quant_model.base_evaluation.APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256",
            APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256,
        ):
            loaded_lock = load_base_model_source_lock(
                approved_lock, ROOT / "candidate-catalog.v1.json"
            )
        self.assertEqual(3, len(loaded_lock.document["candidates"]))

    def test_snapshot_rejects_unsafe_files_custom_code_tamper_and_no_clobber(
        self,
    ) -> None:
        source_lock_raw = self.source_lock.read_bytes()
        changed_source_lock = json.loads(source_lock_raw)
        changed_source_lock["candidates"][0]["files"][0]["sizeBytes"] += 1
        _write_json(self.source_lock, changed_source_lock)
        with self.assertRaisesRegex(ValidationError, "reviewed lock compiled"):
            validate_base_model_snapshot(
                manifest_path=self.manifest,
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
            )
        self.source_lock.write_bytes(source_lock_raw)

        with self.assertRaisesRegex(ValidationError, "already exists"):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen2.5-coder-7b-instruct",
                output_path=self.manifest,
            )

        unsafe = self.snapshot / "modeling_custom.py"
        unsafe.write_text("raise RuntimeError()", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "unsupported or executable"):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen2.5-coder-7b-instruct",
                output_path=self.root / "unsafe.json",
            )
        unsafe.unlink()

        config_path = self.snapshot / "config.json"
        original_config = config_path.read_bytes()
        _write_json(config_path, {"auto_map": {"AutoModel": "custom.Model"}})
        with self.assertRaisesRegex(ValidationError, "reviewed source lock"):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen2.5-coder-7b-instruct",
                output_path=self.root / "custom.json",
            )
        config_path.write_bytes(original_config)

        weights = self.snapshot / "model.safetensors"
        weights.write_bytes(weights.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValidationError, "data ranges"):
            validate_base_model_snapshot(
                manifest_path=self.manifest,
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
            )

    def test_snapshot_manifest_cannot_be_written_inside_snapshot(self) -> None:
        with self.assertRaisesRegex(ValidationError, "outside the immutable snapshot"):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen2.5-coder-7b-instruct",
                output_path=self.snapshot / "snapshot.json",
            )

    def test_snapshot_rejects_unknown_dtype_and_shape_range_mismatch(self) -> None:
        weights_path = self.snapshot / "model.safetensors"

        def rewrite_source_lock() -> str:
            source_lock = json.loads(self.source_lock.read_text(encoding="utf-8"))
            raw = weights_path.read_bytes()
            weight = next(
                entry
                for entry in source_lock["candidates"][0]["files"]
                if entry["path"] == "model.safetensors"
            )
            weight["sha256"] = hashlib.sha256(raw).hexdigest()
            weight["sizeBytes"] = len(raw)
            _write_json(self.source_lock, source_lock)
            return hashlib.sha256(canonical_json_bytes(source_lock)).hexdigest()

        unknown_header = b'{"weight":{"dtype":"F128","shape":[1],"data_offsets":[0,2]}}'
        weights_path.write_bytes(
            len(unknown_header).to_bytes(8, "little") + unknown_header + b"\x00\x00"
        )
        with (
            mock.patch(
                "vibe_quant_model.base_evaluation.APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256",
                rewrite_source_lock(),
            ),
            self.assertRaisesRegex(ValidationError, "reviewed safetensors dtype"),
        ):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen2.5-coder-7b-instruct",
                output_path=self.root / "unknown-dtype.json",
            )

        mismatch_header = b'{"weight":{"dtype":"F16","shape":[2],"data_offsets":[0,2]}}'
        weights_path.write_bytes(
            len(mismatch_header).to_bytes(8, "little") + mismatch_header + b"\x00\x00"
        )
        with (
            mock.patch(
                "vibe_quant_model.base_evaluation.APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256",
                rewrite_source_lock(),
            ),
            self.assertRaisesRegex(ValidationError, "does not match the tensor dtype"),
        ):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen2.5-coder-7b-instruct",
                output_path=self.root / "shape-mismatch.json",
            )

    def test_base_capture_uses_exact_profile_identity_without_verifier_leakage(
        self,
    ) -> None:
        output = self.root / "base.responses.jsonl"
        result = self._capture(output)
        tasks = validate_evaluation_tasks(self.root / "sealed.tasks.jsonl")
        response = validate_evaluation_responses(output, tasks)[0]
        self.assertTrue(result["researchOnly"])
        self.assertEqual(self.profile.execution_model_id, result["executionModelId"])
        self.assertEqual(self.profile.sha256, response["servingProfile"]["sha256"])
        self.assertEqual("unpromoted-research", response["evidenceStatus"])
        self.assertIsNone(response["dataRelease"])
        serialized = output.read_text(encoding="utf-8")
        self.assertNotIn("reviewed-verifier-v1", serialized)
        self.assertNotIn("secret", serialized)

        with self.assertRaisesRegex(ValidationError, "either a trained-adapter"):
            with mock.patch.dict(
                os.environ, {"VQ_BASE_TEST_KEY": "secret"}, clear=False
            ):
                capture_openai_responses(
                    tasks_path=self.root / "sealed.tasks.jsonl",
                    catalog_path=self.catalog,
                    output_path=self.root / "mixed.responses.jsonl",
                    serving_profile_path=self.root / "bogus-serving.json",
                    training_artifact_path=self.root / "bogus-artifact",
                    training_manifest_path=self.root / "bogus-manifest.json",
                    base_evaluation_profile_path=self.profile_path,
                    base_model_snapshot_manifest_path=self.manifest,
                    base_model_snapshot_path=self.snapshot,
                    base_model_source_lock_path=self.source_lock,
                    run_id="mixed-run",
                    base_url="http://127.0.0.1:8000/v1",
                    api_key_env="VQ_BASE_TEST_KEY",
                    seed=17,
                    research_only=True,
                )

    def test_release_bound_base_capture_requires_engine_attestation(self) -> None:
        output = self.root / "release.responses.jsonl"
        with self.assertRaisesRegex(
            ValidationError, "engine-owned runtime attestation"
        ):
            self._capture(
                output,
                research_only=False,
                data_release_path=self.root / "release",
                review_receipt_trust=object(),
            )
        self.assertFalse(output.exists())

    def test_research_capture_and_launch_remain_loopback_and_base_only(self) -> None:
        with self.assertRaisesRegex(ValidationError, "loopback"):
            self._capture(
                self.root / "remote.responses.jsonl",
                base_url="https://models.example/v1",
            )
        catalog = json.loads(self.catalog.read_text(encoding="utf-8"))
        teacher_manifest = self.root / "teacher-snapshot.json"
        with self.assertRaisesRegex(ValidationError, "student base model"):
            seal_base_model_snapshot(
                snapshot_path=self.snapshot,
                catalog_path=self.catalog,
                source_lock_path=self.source_lock,
                candidate_id="qwen3-coder-30b-a3b-instruct",
                output_path=teacher_manifest,
            )
        self.assertEqual(4, len(catalog["candidates"]))


if __name__ == "__main__":
    unittest.main()
