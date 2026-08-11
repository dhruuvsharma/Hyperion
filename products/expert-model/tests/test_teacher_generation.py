from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

import hyperion_model.cli as cli_module
import hyperion_model.teacher_generation as teacher_module
from hyperion_model.core import ValidationError
from hyperion_model.evaluation import TransportResponse
from hyperion_model.teacher_generation import (
    TEACHER_CANDIDATE_SCHEMA_VERSION,
    TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION,
    TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION_V1,
    TEACHER_RUNTIME_BINDING_EVIDENCE_STATUS,
    TEACHER_RUNTIME_BINDING_SCHEMA_VERSION,
    TEACHER_RUNTIME_DESCRIPTOR_SCHEMA_VERSION,
    TeacherRuntimeProbeResponse,
    capture_teacher_candidates,
    create_teacher_runtime_binding,
    derive_teacher_runtime_plan,
    teacher_candidate_sha256,
    validate_teacher_candidates,
    validate_teacher_generation_manifest,
    validate_teacher_runtime_binding,
)


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TeacherGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vqtgen-tests-"))
        self.catalog_path = ROOT / "candidate-catalog.v1.json"
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
        self.runtime_descriptor = {
            "schemaVersion": TEACHER_RUNTIME_DESCRIPTOR_SCHEMA_VERSION,
            "candidateId": "qwen3-coder-30b-a3b-instruct",
            "profileVersion": "qwen3-local-teacher-profile-v1",
            "engineVersion": "0.10.0",
            "modelRoot": os.path.abspath(self.model_root),
            "maxModelLen": 128,
            "baseUrl": "http://127.0.0.1:8000/v1",
            "chatTemplatePath": "chat_template.jinja",
        }
        self._write_runtime_descriptor()
        self.source_path = self.root / "source.txt"
        self.source_path.write_text(
            "The reviewed source says risk must be bounded before deployment.\n",
            encoding="utf-8",
            newline="\n",
        )
        self.manifest_path = self.root / "teacher-generation.json"
        self.output_path = self.root / "teacher-candidates.jsonl"
        self.manifest = self._manifest()
        self._write_manifest()
        self.execution_model_id = teacher_module._prepare_teacher_generation(
            self.manifest_path, self.catalog_path
        ).teacher["executionModelId"]
        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            self.runtime_binding = create_teacher_runtime_binding(
                runtime_descriptor_path=self.runtime_descriptor_path,
                catalog_path=self.catalog_path,
                output_path=self.runtime_binding_path,
                api_key_env="VQ_TEACHER_TEST_KEY",
                transport=self._runtime_transport(),
            )

    def tearDown(self) -> None:
        shutil.rmtree(self.root)

    def _manifest(self) -> dict:
        return {
            "schemaVersion": TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION,
            "draftManifestSha256": hashlib.sha256(
                b"teacher-generation-unit-test-draft"
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

    def _write_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def _write_runtime_descriptor(self) -> None:
        self.runtime_descriptor_path.write_text(
            json.dumps(self.runtime_descriptor, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def _runtime_transport(
        self,
        *,
        version: str = "0.10.0",
        model_id: str | None = None,
        model_root: str | None = None,
        max_model_len: int = 128,
        models: list[dict] | None = None,
        status: int = 200,
        content_type: str = "application/json",
        final_url: str | None = None,
        observed: list[str] | None = None,
        on_request=None,
    ):
        def transport(method, url, headers, timeout, max_bytes):
            if observed is not None:
                observed.append(url)
            if on_request is not None:
                on_request(url)
            if url.endswith("/version"):
                payload = {"version": version}
            else:
                rows = models
                if rows is None:
                    rows = [
                        {
                            "id": model_id or self.execution_model_id,
                            "root": model_root or os.path.abspath(self.model_root),
                            "max_model_len": max_model_len,
                        }
                    ]
                payload = {"object": "list", "data": rows}
            return TeacherRuntimeProbeResponse(
                status=status,
                content_type=content_type,
                body=json.dumps(payload).encode("utf-8"),
                final_url=final_url or url,
            )

        return transport

    @staticmethod
    def _write_candidate_records(path: Path, records: list[dict]) -> None:
        path.write_text(
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

    @staticmethod
    def _response(url: str, requested: dict, content: str) -> TransportResponse:
        payload = {
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
        return TransportResponse(json.dumps(payload).encode("utf-8"), url)

    def _transport(self, observed: list[dict] | None = None):
        def transport(url, headers, body, timeout, max_bytes):
            requested = json.loads(body)
            if observed is not None:
                observed.append(
                    {
                        "url": url,
                        "headers": dict(headers),
                        "request": requested,
                        "timeout": timeout,
                        "maxBytes": max_bytes,
                    }
                )
            return self._response(
                url,
                requested,
                f"Candidate answer for seed {requested['seed']}.",
            )

        return transport

    def _tokenizer_transport(
        self,
        observed: list[dict] | None = None,
        *,
        count: int = 10,
        max_model_len: int = 128,
    ):
        def transport(url, headers, body, timeout, max_bytes):
            requested = json.loads(body)
            if observed is not None:
                observed.append(
                    {
                        "url": url,
                        "headers": dict(headers),
                        "request": requested,
                        "timeout": timeout,
                        "maxBytes": max_bytes,
                    }
                )
            payload = {
                "count": count,
                "max_model_len": max_model_len,
                "tokens": list(range(count)),
                "token_strs": None,
            }
            return TransportResponse(json.dumps(payload).encode("utf-8"), url)

        return transport

    def _capture(
        self,
        transport=None,
        output_path: Path | None = None,
        tokenizer_transport=None,
        runtime_transport=None,
    ):
        monotonic = iter((1.0, 1.1, 2.0, 2.2)).__next__
        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            return capture_teacher_candidates(
                manifest_path=self.manifest_path,
                catalog_path=self.catalog_path,
                runtime_binding_path=self.runtime_binding_path,
                output_path=output_path or self.output_path,
                base_url="http://127.0.0.1:8000/v1",
                api_key_env="VQ_TEACHER_TEST_KEY",
                transport=transport or self._transport(),
                tokenizer_transport=(
                    tokenizer_transport or self._tokenizer_transport()
                ),
                runtime_transport=(runtime_transport or self._runtime_transport()),
                clock=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
                monotonic=monotonic,
            )

    def test_capture_is_source_grounded_hashed_and_unreviewed(self) -> None:
        summary = validate_teacher_generation_manifest(
            self.manifest_path, self.catalog_path
        )
        self.assertEqual(1, summary["taskCount"])
        self.assertEqual(2, summary["requestCount"])
        self.assertEqual(
            TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION,
            summary["manifestSchemaVersion"],
        )
        self.assertEqual(
            {"protocol": "vllm-tokenize-chat/v1", "maxModelLen": 128},
            summary["tokenizerPreflight"],
        )
        self.assertFalse(summary["eligibleForDataset"])
        self.assertFalse(summary["eligibleForTraining"])

        observed: list[dict] = []
        tokenized: list[dict] = []
        captured = self._capture(
            self._transport(observed),
            tokenizer_transport=self._tokenizer_transport(tokenized),
        )
        validated = validate_teacher_candidates(
            self.output_path,
            manifest_path=self.manifest_path,
            catalog_path=self.catalog_path,
        )
        self.assertEqual(captured.sha256, validated.sha256)
        self.assertEqual(2, captured.record_count)
        self.assertEqual(1, captured.task_count)
        self.assertEqual(2, captured.sample_count)
        self.assertEqual(20, captured.usage["promptTokens"])
        self.assertEqual(6, captured.usage["completionTokens"])
        self.assertEqual(26, captured.usage["totalTokens"])
        self.assertEqual(
            self.runtime_binding.file_sha256,
            captured.runtime_binding_file_sha256,
        )
        self.assertEqual(
            self.runtime_binding.file_sha256,
            captured.as_dict()["runtimeBindingFileSha256"],
        )
        self.assertEqual([17, 29], [item["request"]["seed"] for item in observed])
        self.assertEqual(1, len(tokenized))
        self.assertEqual("http://127.0.0.1:8000/tokenize", tokenized[0]["url"])
        self.assertEqual(
            {
                "model": captured.teacher["executionModelId"],
                "messages": captured.records[0]["task"]["modelMessages"],
                "add_generation_prompt": True,
                "return_token_strs": False,
            },
            tokenized[0]["request"],
        )
        self.assertEqual(
            observed[0]["headers"]["Authorization"],
            tokenized[0]["headers"]["Authorization"],
        )

        for call, record in zip(observed, captured.records, strict=True):
            request = call["request"]
            self.assertEqual("http://127.0.0.1:8000/v1/chat/completions", call["url"])
            self.assertEqual("Bearer local-secret", call["headers"]["Authorization"])
            self.assertEqual(record["teacher"]["executionModelId"], request["model"])
            self.assertEqual(record["task"]["modelMessages"], request["messages"])
            self.assertIn(
                self.source_path.read_text(encoding="utf-8").strip(),
                request["messages"][0]["content"],
            )
            self.assertIn("untrusted evidence", request["messages"][0]["content"])
            self.assertNotIn("Expected claim", json.dumps(request))
            self.assertEqual(TEACHER_CANDIDATE_SCHEMA_VERSION, record["schemaVersion"])
            self.assertEqual(
                self.runtime_binding.file_sha256,
                record["runtimeBindingFileSha256"],
            )
            self.assertEqual("stop", record["output"]["finishReason"])
            self.assertEqual("2026-01-02T00:00:00Z", record["capturedAtUtc"])
            self.assertEqual(
                {
                    "status": "unreviewed",
                    "eligibleForDataset": False,
                    "eligibleForTraining": False,
                },
                record["review"],
            )
        self.assertNotIn("local-secret", self.output_path.read_text(encoding="utf-8"))
        self.assertNotIn("tokenizerPreflight", json.dumps(captured.records))

    def test_runtime_binding_roundtrip_and_closed_schema_references(self) -> None:
        plan = derive_teacher_runtime_plan(
            runtime_descriptor_path=self.runtime_descriptor_path,
            catalog_path=self.catalog_path,
        )
        self.assertEqual("not-observed", plan["observationStatus"])
        self.assertEqual(self.execution_model_id, plan["executionModelId"])
        self.assertEqual(self.execution_model_id, plan["servedModelName"])
        self.assertEqual(
            self.manifest["teacher"], plan["capturePlanFragment"]["teacher"]
        )
        stream = StringIO()
        with redirect_stdout(stream):
            result = cli_module.main(
                [
                    "derive-teacher-runtime-plan",
                    "--runtime-descriptor",
                    str(self.runtime_descriptor_path),
                    "--catalog",
                    str(self.catalog_path),
                ]
            )
        self.assertEqual(0, result)
        cli_plan = json.loads(stream.getvalue())
        self.assertTrue(cli_plan["derived"])
        self.assertEqual("not-observed", cli_plan["observationStatus"])
        self.assertEqual(self.execution_model_id, cli_plan["executionModelId"])

        cli_binding_path = self.root / "cli-runtime-binding.json"
        with (
            mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}),
            mock.patch.object(
                teacher_module,
                "_default_teacher_runtime_transport",
                self._runtime_transport(),
            ),
        ):
            stream = StringIO()
            with redirect_stdout(stream):
                result = cli_module.main(
                    [
                        "create-teacher-runtime-binding",
                        "--runtime-descriptor",
                        str(self.runtime_descriptor_path),
                        "--catalog",
                        str(self.catalog_path),
                        "--output",
                        str(cli_binding_path),
                        "--api-key-env",
                        "VQ_TEACHER_TEST_KEY",
                    ]
                )
            self.assertEqual(0, result)
            self.assertTrue(json.loads(stream.getvalue())["created"])

            stream = StringIO()
            with redirect_stdout(stream):
                result = cli_module.main(
                    [
                        "validate-teacher-runtime-binding",
                        str(cli_binding_path),
                        "--api-key-env",
                        "VQ_TEACHER_TEST_KEY",
                    ]
                )
            self.assertEqual(0, result)
            self.assertTrue(json.loads(stream.getvalue())["valid"])

        observed: list[str] = []
        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            validated = validate_teacher_runtime_binding(
                self.runtime_binding_path,
                api_key_env="VQ_TEACHER_TEST_KEY",
                catalog_path=self.catalog_path,
                base_url="http://127.0.0.1:8000/v1",
                expected_teacher=teacher_module._prepare_teacher_generation(
                    self.manifest_path, self.catalog_path
                ).teacher,
                expected_max_model_len=128,
                transport=self._runtime_transport(observed=observed),
            )
        self.assertEqual(self.runtime_binding.file_sha256, validated.file_sha256)
        self.assertEqual(
            _sha256(self.runtime_descriptor_path),
            validated.document["teacher"]["runtimeSha256"],
        )
        self.assertEqual(
            TEACHER_RUNTIME_BINDING_EVIDENCE_STATUS,
            validated.document["evidenceStatus"],
        )
        self.assertEqual(
            [
                "http://127.0.0.1:8000/version",
                "http://127.0.0.1:8000/v1/models",
            ],
            observed,
        )

        schema_expectations = (
            (
                "teacher-runtime-descriptor.v1.schema.json",
                TEACHER_RUNTIME_DESCRIPTOR_SCHEMA_VERSION,
                set(self.runtime_descriptor),
            ),
            (
                "teacher-runtime-binding.v1.schema.json",
                TEACHER_RUNTIME_BINDING_SCHEMA_VERSION,
                {
                    "schemaVersion",
                    "bindingSha256",
                    "evidenceStatus",
                    "candidateCatalog",
                    "runtimeDescriptor",
                    "chatTemplate",
                    "teacher",
                    "runtime",
                    "endpoint",
                    "tokenizerPreflight",
                },
            ),
        )
        for schema_name, version, required in schema_expectations:
            with self.subTest(schema=schema_name):
                schema = json.loads(
                    (ROOT / "schemas" / schema_name).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    "https://json-schema.org/draft/2020-12/schema",
                    schema["$schema"],
                )
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(required, set(schema["required"]))
                self.assertEqual(
                    version, schema["properties"]["schemaVersion"]["const"]
                )
        descriptor_schema = json.loads(
            (ROOT / "schemas" / "teacher-runtime-descriptor.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            ["0.10.0", "0.26.0"],
            descriptor_schema["properties"]["engineVersion"]["enum"],
        )
        descriptor_url_pattern = descriptor_schema["properties"]["baseUrl"]["pattern"]
        binding_schema = json.loads(
            (ROOT / "schemas" / "teacher-runtime-binding.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            descriptor_url_pattern,
            binding_schema["properties"]["endpoint"]["properties"]["baseUrl"][
                "pattern"
            ],
        )
        self.assertIsNotNone(
            re.fullmatch(descriptor_url_pattern, "http://127.0.0.1:65535/v1")
        )
        for rejected_port in ("0", "65536", "99999"):
            self.assertIsNone(
                re.fullmatch(
                    descriptor_url_pattern,
                    f"http://127.0.0.1:{rejected_port}/v1",
                )
            )
        candidate_schema = json.loads(
            (ROOT / "schemas" / "teacher-candidate.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("runtimeBindingFileSha256", candidate_schema["properties"])
        self.assertNotIn("runtimeBindingFileSha256", candidate_schema["required"])

    def test_runtime_probe_rejects_identity_and_observation_drift(self) -> None:
        valid_row = {
            "id": self.execution_model_id,
            "root": os.path.abspath(self.model_root),
            "max_model_len": 128,
        }
        cases = (
            (
                "version",
                self._runtime_transport(version="0.26.0"),
                "exact vLLM version",
            ),
            (
                "model ID",
                self._runtime_transport(model_id="unreviewed-alias"),
                "executionModelId",
            ),
            (
                "multiple model cards",
                self._runtime_transport(models=[valid_row, dict(valid_row)]),
                "exactly one model",
            ),
            (
                "model root",
                self._runtime_transport(model_root=os.path.abspath(self.root)),
                "bound model root",
            ),
            (
                "maximum length",
                self._runtime_transport(max_model_len=129),
                "maximum model length",
            ),
            (
                "HTTP status",
                self._runtime_transport(status=503),
                "HTTP 503",
            ),
            (
                "content type",
                self._runtime_transport(content_type="text/json"),
                "application/json",
            ),
            (
                "redirect",
                self._runtime_transport(final_url="http://127.0.0.1:8000/redirected"),
                "redirected or changed",
            ),
        )
        for name, transport, expected_error in cases:
            with (
                self.subTest(name=name),
                mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}),
            ):
                with self.assertRaisesRegex(ValidationError, expected_error):
                    validate_teacher_runtime_binding(
                        self.runtime_binding_path,
                        api_key_env="VQ_TEACHER_TEST_KEY",
                        transport=transport,
                    )

        with mock.patch.object(
            teacher_module.json, "loads", side_effect=RecursionError("too deep")
        ):
            with self.assertRaisesRegex(ValidationError, "strict UTF-8 JSON"):
                teacher_module._runtime_json(b"{}", "teacher runtime test response")
        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            with self.assertRaisesRegex(ValidationError, "exceeds 10 bytes"):
                validate_teacher_runtime_binding(
                    self.runtime_binding_path,
                    api_key_env="VQ_TEACHER_TEST_KEY",
                    max_response_bytes=10,
                    transport=self._runtime_transport(),
                )

    def test_runtime_binding_rejects_aliases_mutation_and_clobber(self) -> None:
        original_binding = self.runtime_binding_path.read_bytes()
        probe_calls = 0

        def forbidden_probe(*args):
            nonlocal probe_calls
            probe_calls += 1
            raise AssertionError("runtime probe must not run")

        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
            with self.assertRaisesRegex(ValidationError, "already exists"):
                create_teacher_runtime_binding(
                    runtime_descriptor_path=self.runtime_descriptor_path,
                    catalog_path=self.catalog_path,
                    output_path=self.runtime_binding_path,
                    api_key_env="VQ_TEACHER_TEST_KEY",
                    transport=forbidden_probe,
                )
        self.assertEqual(0, probe_calls)
        self.assertEqual(original_binding, self.runtime_binding_path.read_bytes())

        for index, alias in enumerate(
            (
                "http://localhost:8000/v1",
                "http://127.0.0.1:8000/v1/",
                "http://[::1]:8000/v1",
                "http://127.0.0.1:0/v1",
            )
        ):
            with self.subTest(alias=alias):
                alias_root = self.root / f"alias-{index}"
                alias_root.mkdir()
                descriptor_path = alias_root / "runtime.json"
                descriptor = dict(self.runtime_descriptor)
                descriptor["baseUrl"] = alias
                descriptor_path.write_text(
                    json.dumps(descriptor) + "\n", encoding="utf-8", newline="\n"
                )
                output_path = alias_root / "binding.json"
                with mock.patch.dict(
                    os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}
                ):
                    with self.assertRaisesRegex(ValidationError, "canonical"):
                        create_teacher_runtime_binding(
                            runtime_descriptor_path=descriptor_path,
                            catalog_path=self.catalog_path,
                            output_path=output_path,
                            api_key_env="VQ_TEACHER_TEST_KEY",
                            transport=forbidden_probe,
                        )
                self.assertFalse(output_path.exists())
        self.assertEqual(0, probe_calls)

        original_descriptor = self.runtime_descriptor_path.read_bytes()
        self.runtime_descriptor_path.write_bytes(original_descriptor + b" ")
        try:
            with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
                with self.assertRaisesRegex(ValidationError, "freshly reopened"):
                    validate_teacher_runtime_binding(
                        self.runtime_binding_path,
                        api_key_env="VQ_TEACHER_TEST_KEY",
                        transport=forbidden_probe,
                    )
        finally:
            self.runtime_descriptor_path.write_bytes(original_descriptor)
        self.assertEqual(0, probe_calls)

        original_template = self.template_path.read_bytes()
        self.template_path.write_bytes(original_template + b" ")
        try:
            with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "local-secret"}):
                with self.assertRaisesRegex(ValidationError, "freshly reopened"):
                    validate_teacher_runtime_binding(
                        self.runtime_binding_path,
                        api_key_env="VQ_TEACHER_TEST_KEY",
                        transport=forbidden_probe,
                    )
        finally:
            self.template_path.write_bytes(original_template)
        self.assertEqual(0, probe_calls)

    def test_capture_reprobes_before_publication_and_rejects_input_mutation(
        self,
    ) -> None:
        observed: list[str] = []
        self._capture(runtime_transport=self._runtime_transport(observed=observed))
        self.assertEqual(
            [
                "http://127.0.0.1:8000/version",
                "http://127.0.0.1:8000/v1/models",
            ]
            * 2,
            observed,
        )

        output = self.root / "mutated-runtime-candidates.jsonl"
        original_template = self.template_path.read_bytes()
        completion_calls = 0

        def mutate_after_completion(url, headers, body, timeout, max_bytes):
            nonlocal completion_calls
            completion_calls += 1
            response = self._response(
                url,
                json.loads(body),
                f"Mutation test answer {completion_calls}.",
            )
            if completion_calls == 2:
                self.template_path.write_bytes(original_template + b" ")
            return response

        try:
            with self.assertRaisesRegex(ValidationError, "freshly reopened"):
                self._capture(mutate_after_completion, output)
        finally:
            self.template_path.write_bytes(original_template)
        self.assertEqual(2, completion_calls)
        self.assertFalse(output.exists())

    def test_capture_reprepares_sources_after_final_runtime_probe(self) -> None:
        output = self.root / "mutated-source-candidates.jsonl"
        original_source = self.source_path.read_bytes()
        completion_calls = 0
        runtime_observations: list[str] = []

        def mutate_source_after_last_completion(url, headers, body, timeout, max_bytes):
            nonlocal completion_calls
            completion_calls += 1
            response = self._response(
                url,
                json.loads(body),
                f"Source mutation answer {completion_calls}.",
            )
            if completion_calls == 2:
                self.source_path.write_text(
                    "Source bytes changed after the last completion.\n",
                    encoding="utf-8",
                    newline="\n",
                )
            return response

        try:
            with self.assertRaisesRegex(
                ValidationError, r"contentSha256.*reopened source bytes"
            ):
                self._capture(
                    mutate_source_after_last_completion,
                    output,
                    runtime_transport=self._runtime_transport(
                        observed=runtime_observations
                    ),
                )
        finally:
            self.source_path.write_bytes(original_source)
        self.assertEqual(2, completion_calls)
        self.assertEqual(
            [
                "http://127.0.0.1:8000/version",
                "http://127.0.0.1:8000/v1/models",
            ]
            * 2,
            runtime_observations,
        )
        self.assertFalse(output.exists())

    def test_runtime_binding_audit_linkage_is_batch_consistent(self) -> None:
        captured = self._capture()
        original_records = json.loads(json.dumps(captured.records))

        stripped_v2 = json.loads(json.dumps(original_records))
        for record in stripped_v2:
            del record["runtimeBindingFileSha256"]
            record["candidateSha256"] = teacher_candidate_sha256(record)
        stripped_v2_path = self.root / "stripped-v2-candidates.jsonl"
        self._write_candidate_records(stripped_v2_path, stripped_v2)
        with self.assertRaisesRegex(ValidationError, "manifest v2 candidate queue"):
            validate_teacher_candidates(
                stripped_v2_path,
                manifest_path=self.manifest_path,
                catalog_path=self.catalog_path,
            )

        historical_manifest = json.loads(json.dumps(self.manifest))
        historical_manifest["schemaVersion"] = (
            TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION_V1
        )
        del historical_manifest["draftManifestSha256"]
        del historical_manifest["candidateCatalogSha256"]
        del historical_manifest["tokenizerPreflight"]
        del historical_manifest["tasks"][0]["sources"][0]["contentSha256"]
        historical_manifest_path = self.root / "historical-manifest-v1.json"
        historical_manifest_path.write_text(
            json.dumps(historical_manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        historical_prepared = teacher_module._prepare_teacher_generation(
            historical_manifest_path, self.catalog_path
        )
        historical = json.loads(json.dumps(original_records))
        for record in historical:
            task_index = record["task"]["taskIndex"]
            task = historical_prepared.tasks[task_index]
            del record["runtimeBindingFileSha256"]
            record["batchId"] = historical_prepared.batch_id
            record["manifestSha256"] = historical_prepared.manifest_sha256
            record["teacher"] = historical_prepared.teacher
            record["task"] = task["task"]
            record["sources"] = task["sources"]
            record["capturePolicy"] = historical_prepared.capture_policy
            record["authority"] = historical_prepared.authority
            record["candidateId"] = teacher_module._candidate_id(
                record["batchId"],
                record["task"]["taskSha256"],
                record["generation"]["sampleIndex"],
                record["generation"]["seed"],
                record["output"]["sha256"],
            )
            record["candidateSha256"] = teacher_candidate_sha256(record)
        historical_path = self.root / "historical-v1-candidates.jsonl"
        self._write_candidate_records(historical_path, historical)
        validated = validate_teacher_candidates(
            historical_path,
            manifest_path=historical_manifest_path,
            catalog_path=self.catalog_path,
        )
        self.assertIsNone(validated.runtime_binding_file_sha256)
        self.assertNotIn("runtimeBindingFileSha256", validated.as_dict())

        mixed = json.loads(json.dumps(original_records))
        del mixed[1]["runtimeBindingFileSha256"]
        mixed[1]["candidateSha256"] = teacher_candidate_sha256(mixed[1])
        mixed_path = self.root / "mixed-binding-candidates.jsonl"
        self._write_candidate_records(mixed_path, mixed)
        with self.assertRaisesRegex(ValidationError, "every record or absent"):
            validate_teacher_candidates(
                mixed_path,
                manifest_path=self.manifest_path,
                catalog_path=self.catalog_path,
            )

        different = json.loads(json.dumps(original_records))
        different[1]["runtimeBindingFileSha256"] = "f" * 64
        different[1]["candidateSha256"] = teacher_candidate_sha256(different[1])
        different_path = self.root / "different-binding-candidates.jsonl"
        self._write_candidate_records(different_path, different)
        with self.assertRaisesRegex(ValidationError, "batch runtime binding"):
            validate_teacher_candidates(
                different_path,
                manifest_path=self.manifest_path,
                catalog_path=self.catalog_path,
            )

    def test_v1_remains_validation_only_and_cannot_capture(self) -> None:
        self.manifest["schemaVersion"] = TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION_V1
        del self.manifest["draftManifestSha256"]
        del self.manifest["candidateCatalogSha256"]
        del self.manifest["tokenizerPreflight"]
        del self.manifest["tasks"][0]["sources"][0]["contentSha256"]
        self.manifest["teacher"]["chatTemplateSha256"] = "1" * 64
        self.manifest["teacher"]["runtimeSha256"] = "2" * 64
        self._write_manifest()
        summary = validate_teacher_generation_manifest(
            self.manifest_path, self.catalog_path
        )
        self.assertEqual(
            TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION_V1,
            summary["manifestSchemaVersion"],
        )
        self.assertIsNone(summary["tokenizerPreflight"])

        calls = 0

        def forbidden_transport(*args):
            nonlocal calls
            calls += 1
            raise AssertionError("transport must not run")

        with self.assertRaisesRegex(ValidationError, "validation-only"):
            self._capture(
                transport=forbidden_transport,
                tokenizer_transport=forbidden_transport,
            )
        self.assertEqual(0, calls)
        self.assertFalse(self.output_path.exists())

    def test_v2_rejects_placeholder_or_ambiguous_execution_identity(self) -> None:
        cases = (
            (
                "profile TODO",
                lambda teacher: teacher.update({"profileVersion": "profile-TODO-pin"}),
                "placeholder",
            ),
            (
                "profile TBD",
                lambda teacher: teacher.update({"profileVersion": "profile-tbd-pin"}),
                "placeholder",
            ),
            (
                "profile REPLACE",
                lambda teacher: teacher.update(
                    {"profileVersion": "profile-REPLACE_commit"}
                ),
                "placeholder",
            ),
            (
                "repeated chat hash",
                lambda teacher: teacher.update({"chatTemplateSha256": "a" * 64}),
                "repeated-character placeholder",
            ),
            (
                "repeated runtime hash",
                lambda teacher: teacher.update({"runtimeSha256": "b" * 64}),
                "repeated-character placeholder",
            ),
            (
                "equal execution hashes",
                lambda teacher: teacher.update(
                    {"runtimeSha256": teacher["chatTemplateSha256"]}
                ),
                "must be distinct",
            ),
        )
        for name, mutate, expected_error in cases:
            with self.subTest(name=name):
                self.manifest = self._manifest()
                mutate(self.manifest["teacher"])
                self._write_manifest()
                with self.assertRaisesRegex(ValidationError, expected_error):
                    validate_teacher_generation_manifest(
                        self.manifest_path, self.catalog_path
                    )

    def test_v2_rejects_source_mutation_under_unchanged_manifest(self) -> None:
        original_manifest = self.manifest_path.read_bytes()
        self.source_path.write_text(
            "Mutated source bytes after manifest creation.\n",
            encoding="utf-8",
            newline="\n",
        )

        with self.assertRaisesRegex(
            ValidationError, r"contentSha256.*reopened source bytes"
        ):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)
        self.assertEqual(original_manifest, self.manifest_path.read_bytes())

    def test_v2_rejects_catalog_bytes_and_revision_substitution(self) -> None:
        catalog = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        substituted_catalog = self.root / "substituted-catalog.json"
        substituted_catalog.write_text(
            json.dumps(catalog, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        with self.assertRaisesRegex(ValidationError, "candidateCatalogSha256"):
            validate_teacher_generation_manifest(
                self.manifest_path, substituted_catalog
            )

        teacher = next(
            candidate
            for candidate in catalog["candidates"]
            if candidate["id"] == "qwen3-coder-30b-a3b-instruct"
        )
        teacher["revision"] = "a" * 40
        substituted_catalog.write_text(
            json.dumps(catalog, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.manifest["candidateCatalogSha256"] = _sha256(substituted_catalog)
        self._write_manifest()

        with self.assertRaisesRegex(
            ValidationError, "approved pinned shortlist revision"
        ):
            validate_teacher_generation_manifest(
                self.manifest_path, substituted_catalog
            )

    def test_tokenizer_preflight_rejects_untrusted_runtime_claims(self) -> None:
        cases = (
            (
                "missing field",
                {"count": 1, "max_model_len": 128},
                "must contain only",
                None,
            ),
            (
                "extra field",
                {
                    "count": 1,
                    "max_model_len": 128,
                    "tokens": [1],
                    "unexpected": True,
                },
                "must contain only",
                None,
            ),
            (
                "duplicate key",
                b'{"count":1,"count":1,"max_model_len":128,"tokens":[1]}',
                "duplicate",
                None,
            ),
            (
                "non-null token strings",
                {"count": 1, "max_model_len": 128, "tokens": [1], "token_strs": ["x"]},
                "token_strs",
                None,
            ),
            (
                "count mismatch",
                {"count": 2, "max_model_len": 128, "tokens": [1]},
                "exactly count",
                None,
            ),
            (
                "boolean token",
                {"count": 1, "max_model_len": 128, "tokens": [True]},
                r"tokens\[0\]",
                None,
            ),
            (
                "wrong context window",
                {"count": 10, "max_model_len": 129, "tokens": list(range(10))},
                "does not match",
                None,
            ),
            (
                "context overflow",
                {"count": 65, "max_model_len": 128, "tokens": list(range(65))},
                "exceeds max_model_len",
                None,
            ),
            (
                "redirect",
                {"count": 10, "max_model_len": 128, "tokens": list(range(10))},
                "redirected",
                "http://127.0.0.1:8000/other-tokenize",
            ),
        )
        for name, payload, expected_error, final_url in cases:
            with self.subTest(name=name):
                output = self.root / f"{name.replace(' ', '-')}.jsonl"
                completion_calls = 0

                def completion_transport(*args):
                    nonlocal completion_calls
                    completion_calls += 1
                    raise AssertionError("completion transport must not run")

                def tokenizer_transport(url, headers, body, timeout, max_bytes):
                    return TransportResponse(
                        (
                            payload
                            if isinstance(payload, bytes)
                            else json.dumps(payload).encode("utf-8")
                        ),
                        final_url or url,
                    )

                with self.assertRaisesRegex(ValidationError, expected_error):
                    self._capture(
                        completion_transport,
                        output,
                        tokenizer_transport=tokenizer_transport,
                    )
                self.assertEqual(0, completion_calls)
                self.assertFalse(output.exists())

    def test_tokenizer_preflight_reserves_exact_budget_before_completion(self) -> None:
        self.manifest["budget"]["maxPromptTokens"] = 19
        self._write_manifest()
        completion_calls = 0

        def completion_transport(*args):
            nonlocal completion_calls
            completion_calls += 1
            raise AssertionError("completion transport must not run")

        with self.assertRaisesRegex(
            ValidationError, "exact tokenizer preflight total 20"
        ):
            self._capture(completion_transport)
        self.assertEqual(0, completion_calls)
        self.assertFalse(self.output_path.exists())

        self.manifest = self._manifest()
        self.manifest["budget"]["maxTotalTokens"] = 147
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "preflight reservation 148"):
            self._capture(completion_transport)
        self.assertEqual(0, completion_calls)
        self.assertFalse(self.output_path.exists())

    def test_v2_manifest_rejects_statically_impossible_context(self) -> None:
        self.manifest["tokenizerPreflight"]["maxModelLen"] = 64
        self._write_manifest()
        with self.assertRaisesRegex(
            ValidationError, "cannot fit with any non-empty prompt"
        ):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

        self.manifest["tokenizerPreflight"]["maxModelLen"] = 65
        self._write_manifest()
        summary = validate_teacher_generation_manifest(
            self.manifest_path, self.catalog_path
        )
        self.assertEqual(65, summary["tokenizerPreflight"]["maxModelLen"])

    def test_completion_transport_must_preserve_exact_endpoint(self) -> None:
        def changed_endpoint(url, headers, body, timeout, max_bytes):
            response = self._response(url, json.loads(body), "Bounded answer.")
            return TransportResponse(response.body, "http://127.0.0.1:8000/v1")

        with self.assertRaisesRegex(ValidationError, "changed the endpoint URL"):
            self._capture(changed_endpoint)
        self.assertFalse(self.output_path.exists())

    def test_completion_usage_must_match_live_tokenizer_count(self) -> None:
        with self.assertRaisesRegex(ValidationError, "live tokenizer preflight count"):
            self._capture(tokenizer_transport=self._tokenizer_transport(count=9))
        self.assertFalse(self.output_path.exists())

    def test_capture_rejects_non_loopback_student_and_non_development(self) -> None:
        calls = 0

        def forbidden_transport(*args):
            nonlocal calls
            calls += 1
            raise AssertionError("transport must not run")

        with mock.patch.dict(os.environ, {"VQ_TEACHER_TEST_KEY": "secret"}):
            with self.assertRaisesRegex(ValidationError, "loopback"):
                capture_teacher_candidates(
                    manifest_path=self.manifest_path,
                    catalog_path=self.catalog_path,
                    runtime_binding_path=self.runtime_binding_path,
                    output_path=self.output_path,
                    base_url="https://models.example/v1",
                    api_key_env="VQ_TEACHER_TEST_KEY",
                    transport=forbidden_transport,
                )
        self.assertEqual(0, calls)
        self.assertFalse(self.output_path.exists())

        self.manifest["teacher"]["candidateId"] = "qwen2.5-coder-7b-instruct"
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "teacher role"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

        self.manifest = self._manifest()
        self.manifest["split"] = "calibration"
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "must be development"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

        self.manifest = self._manifest()
        self.manifest["generation"]["temperature"] = 0
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "greater than 0"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

        self.manifest = self._manifest()
        self.manifest["authority"]["rights"]["mayStore"] = 1
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "must be booleans"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

    def test_failure_never_publishes_partial_or_duplicate_candidates(self) -> None:
        calls = 0

        def fail_second(url, headers, body, timeout, max_bytes):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValidationError("simulated second-request failure")
            requested = json.loads(body)
            return self._response(url, requested, "First candidate.")

        with self.assertRaisesRegex(ValidationError, "second-request failure"):
            self._capture(fail_second)
        self.assertEqual(2, calls)
        self.assertFalse(self.output_path.exists())

        def duplicate(url, headers, body, timeout, max_bytes):
            return self._response(url, json.loads(body), "Same candidate.")

        with self.assertRaisesRegex(ValidationError, "duplicates another sample"):
            self._capture(duplicate)
        self.assertFalse(self.output_path.exists())

        def hidden_reasoning(url, headers, body, timeout, max_bytes):
            return self._response(
                url, json.loads(body), "<thinking>private trace</thinking>answer"
            )

        with self.assertRaisesRegex(ValidationError, "hidden-reasoning marker"):
            self._capture(hidden_reasoning)
        self.assertFalse(self.output_path.exists())

        def tool_call(url, headers, body, timeout, max_bytes):
            response = json.loads(self._response(url, json.loads(body), "Answer.").body)
            response["choices"][0]["message"]["tool_calls"] = [
                {"id": "call-1", "type": "function"}
            ]
            return TransportResponse(json.dumps(response).encode("utf-8"), url)

        with self.assertRaisesRegex(ValidationError, "answer-only candidate"):
            self._capture(tool_call)
        self.assertFalse(self.output_path.exists())

    def test_budget_tamper_and_no_clobber_fail_closed(self) -> None:
        self.manifest["budget"]["maxCompletionTokens"] = 5
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "maxCompletionTokens"):
            self._capture()
        self.assertFalse(self.output_path.exists())

        self.manifest = self._manifest()
        self._write_manifest()
        self._capture()
        original = self.output_path.read_bytes()
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._capture(transport=lambda *args: self.fail("transport must not run"))
        self.assertEqual(original, self.output_path.read_bytes())

        original_manifest = self.manifest_path.read_bytes()
        self.manifest_path.write_bytes(original_manifest + b" ")
        with self.assertRaisesRegex(ValidationError, "generation manifest bytes"):
            validate_teacher_candidates(
                self.output_path,
                manifest_path=self.manifest_path,
                catalog_path=self.catalog_path,
            )
        self.manifest_path.write_bytes(original_manifest)

        records = [json.loads(line) for line in original.decode("utf-8").splitlines()]
        records[0]["output"]["text"] = "Tampered candidate."
        self.output_path.write_text(
            "".join(
                json.dumps(
                    record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                + "\n"
                for record in records
            ),
            encoding="utf-8",
            newline="\n",
        )
        with self.assertRaisesRegex(ValidationError, r"output\.(?:byteCount|sha256)"):
            validate_teacher_candidates(
                self.output_path,
                manifest_path=self.manifest_path,
                catalog_path=self.catalog_path,
            )

    def test_response_and_preparation_bounds_fail_before_publication(self) -> None:
        def excessive_completion(url, headers, body, timeout, max_bytes):
            requested = json.loads(body)
            response = json.loads(
                self._response(url, requested, "Bounded answer.").body
            )
            response["usage"] = {
                "prompt_tokens": 10,
                "completion_tokens": 65,
                "total_tokens": 75,
            }
            return TransportResponse(json.dumps(response).encode("utf-8"), url)

        with self.assertRaisesRegex(ValidationError, "maxOutputTokens"):
            self._capture(excessive_completion)
        self.assertFalse(self.output_path.exists())

        with mock.patch.object(teacher_module, "MAX_TEACHER_PREPARED_SOURCE_BYTES", 1):
            with self.assertRaisesRegex(ValidationError, "in-memory preparation limit"):
                validate_teacher_generation_manifest(
                    self.manifest_path, self.catalog_path
                )

        with mock.patch.object(teacher_module, "MAX_EVALUATION_LINE_BYTES", 1):
            with self.assertRaisesRegex(ValidationError, "line-byte limit"):
                validate_teacher_generation_manifest(
                    self.manifest_path, self.catalog_path
                )

        self.manifest["tasks"][0]["sources"][0]["uri"] = "not-a-uri"
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "absolute URI"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

        self.manifest = self._manifest()
        self.manifest["tasks"][0]["sources"][0]["retrievedAtUtc"] = (
            "2026-01-01T13:00:00Z"
        )
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, r"retrievedAtUtc.*task cutoff"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)
        self.assertFalse(self.output_path.exists())

        self.manifest = self._manifest()
        self._write_manifest()
        captured = self._capture()
        records = json.loads(json.dumps(captured.records))
        records[0]["sources"][0]["retrievedAtUtc"] = "2026-01-01T13:00:00Z"
        with self.assertRaisesRegex(ValidationError, r"retrievedAtUtc.*task cutoff"):
            teacher_module._validate_candidate_record(records[0], 1)

    def test_candidate_set_rechecks_every_record_task_count(self) -> None:
        captured = self._capture()
        records = json.loads(json.dumps(captured.records))
        records[1]["task"]["taskCount"] = 2
        with self.assertRaisesRegex(ValidationError, "batch task count"):
            teacher_module._validate_candidate_records(
                records, self.output_path, captured.sha256
            )

    def test_record_validator_rejects_rehashed_semantic_tamper(self) -> None:
        captured = self._capture()
        original_records = json.loads(json.dumps(captured.records))

        cases = (
            (
                "completion",
                lambda record: record["usage"].update(
                    {"completionTokens": 65, "totalTokens": 75}
                ),
                "maxOutputTokens",
            ),
            (
                "finish",
                lambda record: record["output"].update({"finishReason": "tool_calls"}),
                "finishReason",
            ),
            (
                "timestamp",
                lambda record: record.update({"capturedAtUtc": "2025-12-01T00:00:00Z"}),
                "task cutoff",
            ),
        )
        for name, mutate, expected_error in cases:
            with self.subTest(name=name):
                records = json.loads(json.dumps(original_records))
                mutate(records[0])
                records[0]["candidateSha256"] = teacher_candidate_sha256(records[0])
                path = self.root / f"tampered-{name}.jsonl"
                path.write_text(
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
                with self.assertRaisesRegex(ValidationError, expected_error):
                    validate_teacher_candidates(
                        path,
                        manifest_path=self.manifest_path,
                        catalog_path=self.catalog_path,
                    )

    def test_source_containment_and_cli_validation(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.txt"
        outside.write_text("outside", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        self.manifest["tasks"][0]["sources"][0]["contentPath"] = f"../{outside.name}"
        self._write_manifest()
        with self.assertRaisesRegex(ValidationError, "contained relative path"):
            validate_teacher_generation_manifest(self.manifest_path, self.catalog_path)

        self.manifest = self._manifest()
        self._write_manifest()
        stream = StringIO()
        with redirect_stdout(stream):
            result = cli_module.main(
                [
                    "validate-teacher-generation",
                    "--manifest",
                    str(self.manifest_path),
                    "--catalog",
                    str(self.catalog_path),
                ]
            )
        self.assertEqual(0, result)
        self.assertTrue(json.loads(stream.getvalue())["valid"])

        self._capture()
        stream = StringIO()
        with redirect_stdout(stream):
            result = cli_module.main(
                [
                    "validate-teacher-candidates",
                    str(self.output_path),
                    "--manifest",
                    str(self.manifest_path),
                    "--catalog",
                    str(self.catalog_path),
                ]
            )
        self.assertEqual(0, result)
        cli_result = json.loads(stream.getvalue())
        self.assertTrue(cli_result["valid"])
        self.assertFalse(cli_result["eligibleForTraining"])


if __name__ == "__main__":
    unittest.main()
