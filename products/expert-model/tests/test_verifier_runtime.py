import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hyperion_model.csharp_verifier import (
    CHECK_IDS as CSHARP_CHECK_IDS,
    CSharpVerifierAuthorityTrust,
    csharp_strategy_verification_result_sha256,
)
from hyperion_model.core import ValidationError, canonical_json_bytes
from hyperion_model.evaluation import (
    EVALUATION_RESPONSE_SCHEMA_VERSION,
    EVALUATION_TASK_SCHEMA_VERSION,
    EvaluationTaskSet,
    evaluation_output_sha256,
    evaluation_prompt_sha256,
    evaluation_response_sha256,
    evaluation_task_sha256,
)
from hyperion_model.evaluation_authoring import EvaluationAuthoringApprovalTrust
from hyperion_model.review_receipts import ExpertModelReviewReceiptTrust
from hyperion_model.verifier_replay_audit import (
    _require_distinct_evaluation_authoring_signer,
)
from hyperion_model.verifier_runtime import (
    CSharpVerifierExecutionContext,
    DECLARATIVE_OUTPUT_PROFILE,
    EXECUTABLE_VERIFIER_SCHEMA_VERSION,
    EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION,
    _execute_executable_verifier,
    bind_csharp_verifier_execution_context,
    execute_release_declarative_verifiers,
    run_release_verifiers,
)
from hyperion_model.verifier_authority import (
    RESULT_SCHEMA_VERSION as CSHARP_RESULT_SCHEMA_VERSION,
    SOURCE_PROFILE as CSHARP_SOURCE_PROFILE,
)


ROOT = Path(__file__).resolve().parents[1]


def _fixture(output: str, checks: list[dict]) -> tuple[dict, dict, bytes]:
    task_id = "sealed-verifier-runtime-001"
    verifier_id = "reviewed-executable-verifier-v1"
    verifier = {
        "schemaVersion": EXECUTABLE_VERIFIER_SCHEMA_VERSION,
        "verifierId": verifier_id,
        "taskId": task_id,
        "profile": DECLARATIVE_OUTPUT_PROFILE,
        "checks": checks,
    }
    verifier_raw = canonical_json_bytes(verifier) + b"\n"
    messages = [
        {"role": "system", "content": "Return strict reviewed JSON."},
        {"role": "user", "content": "Calculate the requested metric."},
    ]
    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": task_id,
        "taskSha256": "0" * 64,
        "split": "sealed",
        "taskKind": "QuantitativeReasoning",
        "domains": ["QuantitativeMath"],
        "messages": messages,
        "promptSha256": evaluation_prompt_sha256(messages),
        "contextPack": {"version": "reviewed-context-v1", "sha256": "a" * 64},
        "verifier": {
            "id": verifier_id,
            "sha256": hashlib.sha256(verifier_raw).hexdigest(),
            "requiredChecks": [check["checkId"] for check in checks],
        },
        "contaminationGroup": "runtime-verifier-family-001",
        "cutoffUtc": "2026-01-01T00:00:00Z",
        "criticality": "critical",
        "maxOutputTokens": 256,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    response = {
        "schemaVersion": EVALUATION_RESPONSE_SCHEMA_VERSION,
        "responseSha256": "0" * 64,
        "candidateCatalogSha256": "b" * 64,
        "candidateId": "candidate-v1",
        "modelId": "model-v1",
        "modelRevision": "1" * 40,
        "servingProfile": {"id": "profile-v1", "sha256": "c" * 64},
        "targetKind": "trained-adapter",
        "executionModelId": "daxalgo-expert-sha256-" + "c" * 64,
        "runId": "run-v1",
        "dataRelease": None,
        "researchOnly": True,
        "evidenceStatus": "unpromoted-research",
        "taskId": task_id,
        "taskSha256": task["taskSha256"],
        "promptSha256": task["promptSha256"],
        "output": {
            "text": output,
            "sha256": evaluation_output_sha256(output),
            "byteCount": len(output.encode("utf-8")),
        },
        "generation": {
            "temperature": 0,
            "topP": 1,
            "seed": 17,
            "maxOutputTokens": 256,
        },
        "latencyMs": 1,
        "usage": {"promptTokens": 10, "completionTokens": 5, "totalTokens": 15},
        "finishReason": "stop",
        "capturedAtUtc": "2026-01-02T00:00:00Z",
    }
    response["responseSha256"] = evaluation_response_sha256(response)
    return task, response, verifier_raw


def _csharp_fixture(output: str) -> tuple[dict, dict, bytes]:
    task_id = "sealed-csharp-runtime-001"
    verifier_id = "reviewed-csharp-verifier-v2"
    verifier = {
        "schemaVersion": EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION,
        "verifierId": verifier_id,
        "taskId": task_id,
        "profile": CSHARP_SOURCE_PROFILE,
        "contract": {
            "symbol": "ES",
            "secType": "FUT",
            "exchange": "CME",
            "currency": "USD",
            "primaryExchange": "CME",
        },
        "cases": [
            {
                "caseId": "reference-case-1",
                "startUtc": "2026-01-02T09:30:00Z",
                "ticks": [
                    {
                        "offsetMilliseconds": 0,
                        "bid": 5000,
                        "ask": 5000.25,
                        "bidSize": 10,
                        "askSize": 12,
                    }
                ],
                "expectedTraceSha256": "d" * 64,
            }
        ],
    }
    verifier_raw = canonical_json_bytes(verifier) + b"\n"
    messages = [
        {"role": "system", "content": "Return one C# strategy source file only."},
        {"role": "user", "content": "Implement the reviewed strategy behavior."},
    ]
    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": task_id,
        "taskSha256": "0" * 64,
        "split": "sealed",
        "taskKind": "CodeGeneration",
        "domains": ["CSharp"],
        "messages": messages,
        "promptSha256": evaluation_prompt_sha256(messages),
        "contextPack": {"version": "reviewed-context-v1", "sha256": "a" * 64},
        "verifier": {
            "id": verifier_id,
            "sha256": hashlib.sha256(verifier_raw).hexdigest(),
            "requiredChecks": list(CSHARP_CHECK_IDS),
        },
        "contaminationGroup": "runtime-csharp-family-001",
        "cutoffUtc": "2026-01-01T00:00:00Z",
        "criticality": "critical",
        "maxOutputTokens": 4096,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    response = {
        "schemaVersion": EVALUATION_RESPONSE_SCHEMA_VERSION,
        "responseSha256": "0" * 64,
        "candidateCatalogSha256": "b" * 64,
        "candidateId": "candidate-v1",
        "modelId": "model-v1",
        "modelRevision": "1" * 40,
        "servingProfile": {"id": "profile-v1", "sha256": "c" * 64},
        "targetKind": "trained-adapter",
        "executionModelId": "daxalgo-expert-sha256-" + "c" * 64,
        "runId": "run-v1",
        "dataRelease": None,
        "researchOnly": True,
        "evidenceStatus": "unpromoted-research",
        "taskId": task_id,
        "taskSha256": task["taskSha256"],
        "promptSha256": task["promptSha256"],
        "output": {
            "text": output,
            "sha256": evaluation_output_sha256(output),
            "byteCount": len(output.encode("utf-8")),
        },
        "generation": {
            "temperature": 0,
            "topP": 1,
            "seed": 17,
            "maxOutputTokens": 4096,
        },
        "latencyMs": 1,
        "usage": {"promptTokens": 10, "completionTokens": 50, "totalTokens": 60},
        "finishReason": "stop",
        "capturedAtUtc": "2026-01-02T00:00:00Z",
    }
    response["responseSha256"] = evaluation_response_sha256(response)
    return task, response, verifier_raw


def _authority(marker: str) -> SimpleNamespace:
    summary = {
        "authorityId": f"daxalgo-csharp-verifier-authority-sha256-{'a' * 64}",
        "payloadSha256": marker * 64,
        "envelopeSha256": marker * 64,
        "publicKeySpkiSha256": "e" * 64,
        "notBeforeUtc": "2026-01-01T00:00:00Z",
        "expiresAtUtc": "2026-01-03T00:00:00Z",
    }
    return SimpleNamespace(
        payload={
            "verifier": {
                "image": "stable-image-binding",
                "toolchain": "stable-toolchain-binding",
                "sandbox": "stable-sandbox-binding",
            }
        },
        payload_sha256=summary["payloadSha256"],
        envelope_sha256=summary["envelopeSha256"],
        as_dict=lambda: dict(summary),
    )


def _fake_csharp_runner(
    authority: SimpleNamespace,
    captured: dict[str, bytes],
    *,
    toolchain_sha256: str = "f" * 64,
):
    def run(**kwargs):
        request_raw = Path(kwargs["request_path"]).read_bytes()
        source_raw = Path(kwargs["source_path"]).read_bytes()
        expectations_raw = Path(kwargs["expectations_path"]).read_bytes()
        request = json.loads(request_raw)
        captured.update(
            request=request_raw,
            source=source_raw,
            expectations=expectations_raw,
        )
        checks = []
        for check_id in CSHARP_CHECK_IDS:
            evidence = f"{check_id}: pass; verified by the fake signed worker"
            checks.append(
                {
                    "checkId": check_id,
                    "passed": True,
                    "evidence": evidence,
                    "evidenceSha256": hashlib.sha256(evidence.encode()).hexdigest(),
                }
            )
        result = {
            "schemaVersion": CSHARP_RESULT_SCHEMA_VERSION,
            "resultSha256": "0" * 64,
            "request": {
                "requestId": request["requestId"],
                "sha256": hashlib.sha256(request_raw).hexdigest(),
            },
            "source": {"sha256": hashlib.sha256(source_raw).hexdigest()},
            "expectations": {"sha256": hashlib.sha256(expectations_raw).hexdigest()},
            "workerResult": {
                "sha256": "9" * 64,
                "toolchainSha256": toolchain_sha256,
            },
            "verifierAuthority": authority.as_dict(),
            "image": {
                "reference": "daxalgo/verifier@sha256:" + "8" * 64,
                "digest": "sha256:" + "8" * 64,
                "imageId": "sha256:" + "7" * 64,
                "platform": "linux/amd64",
            },
            "sandboxPolicy": {
                "profile": "daxalgo-headless-strategy-sandbox/v1",
                "sha256": "6" * 64,
            },
            "checks": checks,
            "accepted": True,
        }
        result["resultSha256"] = csharp_strategy_verification_result_sha256(result)
        Path(kwargs["output_path"]).write_bytes(canonical_json_bytes(result) + b"\n")
        return result

    return run


class VerifierRuntimeTests(unittest.TestCase):
    def test_replay_audit_signer_must_differ_from_authoring_approval_signer(
        self,
    ) -> None:
        authoring_trust = EvaluationAuthoringApprovalTrust(
            Path("authoring.pem"), "2" * 64, "audience", "key", "author"
        )
        with self.assertRaisesRegex(
            ValidationError,
            "must differ from the evaluation-authoring approval signer",
        ):
            _require_distinct_evaluation_authoring_signer("2" * 64, authoring_trust)

        _require_distinct_evaluation_authoring_signer("3" * 64, authoring_trust)

    def test_release_verifier_requires_external_evaluation_authoring_trust(
        self,
    ) -> None:
        review_trust = ExpertModelReviewReceiptTrust(
            Path("review.pem"), "1" * 64, "audience", "key", "reviewer"
        )
        with self.assertRaisesRegex(
            ValidationError, "evaluation-authoring approval trust"
        ):
            run_release_verifiers(
                tasks_path=Path("tasks.jsonl"),
                responses_path=Path("responses.jsonl"),
                release_path=Path("release"),
                review_receipt_trust=review_trust,
                evaluation_authoring_approval_trust=None,  # type: ignore[arg-type]
                output_path=Path("results.jsonl"),
            )

    def test_mixed_audited_suite_still_freshly_executes_declarative_tasks(
        self,
    ) -> None:
        declarative_task, declarative_response, declarative_raw = _fixture(
            "reviewed ok",
            [{"checkId": "ok", "kind": "contains", "value": "ok"}],
        )
        csharp_task, csharp_response, csharp_raw = _csharp_fixture(
            "public sealed class ReviewedStrategy { }"
        )
        release_identity = {
            "releaseId": "vqrel-" + "1" * 64,
            "releaseSha256": "2" * 64,
            "manifestSha256": "3" * 64,
        }
        for response in (declarative_response, csharp_response):
            response["dataRelease"] = release_identity
            response["researchOnly"] = False
            response["evidenceStatus"] = "release-bound"
            response["responseSha256"] = evaluation_response_sha256(response)
        tasks = EvaluationTaskSet(
            path=Path("sealed.jsonl"),
            sha256="4" * 64,
            task_set_sha256="5" * 64,
            records=(declarative_task, csharp_task),
        )
        snapshots = {
            declarative_task["taskId"]: (Path("declarative.json"), declarative_raw),
            csharp_task["taskId"]: (Path("csharp.json"), csharp_raw),
        }
        with (
            patch("hyperion_model.release.validate_release_evaluation_task_set"),
            patch(
                "hyperion_model.verifier_runtime._release_verifier_snapshots",
                return_value=snapshots,
            ),
            patch(
                "hyperion_model.verifier_runtime._execute_csharp_executable_verifier",
                side_effect=AssertionError("audited C# task executed locally"),
            ) as csharp_executor,
        ):
            results = execute_release_declarative_verifiers(
                release_path=Path("release"),
                release={"evaluation": {"taskBindings": []}},
                release_identity=release_identity,
                tasks=tasks,
                responses=(declarative_response, csharp_response),
            )
        csharp_executor.assert_not_called()
        self.assertEqual(
            [declarative_task["taskId"]], [row["taskId"] for row in results]
        )
        self.assertTrue(results[0]["accepted"])

    def test_unpaired_unicode_surrogates_fail_as_validation_errors(self) -> None:
        with self.assertRaisesRegex(ValidationError, "valid Unicode scalar values"):
            evaluation_output_sha256("\ud800")
        with self.assertRaisesRegex(ValidationError, "valid Unicode scalar values"):
            evaluation_prompt_sha256([{"role": "user", "content": "\udfff"}])

    def test_closed_text_json_and_decimal_checks_execute_deterministically(
        self,
    ) -> None:
        output = json.dumps(
            {
                "status": "ok",
                "safe": True,
                "error": None,
                "metrics": {"volatility": 0.13559},
            },
            separators=(",", ":"),
        )
        checks = [
            {"checkId": "has-status", "kind": "contains", "value": '"status"'},
            {"checkId": "no-unsafe", "kind": "not-contains", "value": "unsafe"},
            {
                "checkId": "status-ok",
                "kind": "json-string-equals",
                "pointer": "/status",
                "value": "ok",
            },
            {
                "checkId": "safe-true",
                "kind": "json-boolean-equals",
                "pointer": "/safe",
                "value": True,
            },
            {"checkId": "error-null", "kind": "json-null", "pointer": "/error"},
            {
                "checkId": "volatility-close",
                "kind": "json-decimal-close",
                "pointer": "/metrics/volatility",
                "expected": "0.1356",
                "absoluteTolerance": "0.00002",
                "relativeTolerance": "0",
            },
        ]
        task, response, verifier = _fixture(output, checks)
        first = _execute_executable_verifier(task, response, verifier, line_number=1)
        second = _execute_executable_verifier(task, response, verifier, line_number=1)
        self.assertEqual(first, second)
        self.assertTrue(first["accepted"])
        self.assertTrue(all(check["passed"] for check in first["checks"]))
        self.assertNotIn(output, json.dumps(first))
        self.assertNotIn("0.1356", json.dumps(first))

    def test_invalid_or_duplicate_json_fails_checks_without_executing_code(
        self,
    ) -> None:
        check = {
            "checkId": "status-ok",
            "kind": "json-string-equals",
            "pointer": "/status",
            "value": "ok",
        }
        for output in ('{"status":', '{"status":"ok","status":"unsafe"}'):
            with self.subTest(output=output):
                task, response, verifier = _fixture(output, [check])
                result = _execute_executable_verifier(
                    task, response, verifier, line_number=1
                )
                self.assertFalse(result["accepted"])
                self.assertIn("reason=invalid-json", result["checks"][0]["evidence"])

    def test_json_object_exact_keys_passes_only_for_the_declared_key_set(
        self,
    ) -> None:
        check = {
            "checkId": "payload-shape",
            "kind": "json-object-exact-keys",
            "pointer": "/payload",
            "keys": ["alpha", "beta"],
        }
        cases = (
            ('{"payload":{"beta":2,"alpha":1}}', True),
            ('{"payload":{"alpha":1,"beta":2,"extra":3}}', False),
            ('{"payload":{"alpha":1}}', False),
        )
        for output, expected in cases:
            with self.subTest(output=output):
                task, response, verifier = _fixture(output, [check])
                result = _execute_executable_verifier(
                    task, response, verifier, line_number=1
                )
                self.assertEqual(expected, result["accepted"])
                reason = (
                    "json-object-keys-exact"
                    if expected
                    else "json-object-keys-mismatch"
                )
                self.assertIn(f"reason={reason}", result["checks"][0]["evidence"])

    def test_json_object_exact_keys_rejects_non_object_target(self) -> None:
        check = {
            "checkId": "payload-shape",
            "kind": "json-object-exact-keys",
            "pointer": "/payload",
            "keys": ["alpha"],
        }
        task, response, verifier = _fixture('{"payload":["alpha"]}', [check])
        result = _execute_executable_verifier(task, response, verifier, line_number=1)
        self.assertFalse(result["accepted"])
        self.assertIn("reason=json-value-not-object", result["checks"][0]["evidence"])

    def test_json_object_exact_keys_supports_root_and_unicode_keys(self) -> None:
        check = {
            "checkId": "root-shape",
            "kind": "json-object-exact-keys",
            "pointer": "",
            "keys": ["alpha", "beta-β"],
        }
        task, response, verifier = _fixture('{"beta-β":2,"alpha":1}', [check])
        result = _execute_executable_verifier(task, response, verifier, line_number=1)
        self.assertTrue(result["accepted"])
        self.assertIn("reason=json-object-keys-exact", result["checks"][0]["evidence"])

    def test_json_object_exact_keys_validation_is_closed_and_bounded(self) -> None:
        invalid_keys = (
            ([], "1 to 128 keys"),
            ("alpha", "1 to 128 keys"),
            (["beta", "alpha"], "ordinal sorted order"),
            (["alpha", "alpha"], "must not contain duplicates"),
            ([""], "must be a non-empty string"),
            ([1], "must be a non-empty string"),
            (["x" * 201], "must not exceed 200 characters"),
            ([f"key-{index:03}" for index in range(129)], "1 to 128 keys"),
        )
        for keys, error in invalid_keys:
            with self.subTest(keys=keys, error=error):
                check = {
                    "checkId": "payload-shape",
                    "kind": "json-object-exact-keys",
                    "pointer": "/payload",
                    "keys": keys,
                }
                task, response, verifier = _fixture('{"payload":{}}', [check])
                with self.assertRaisesRegex(ValidationError, error):
                    _execute_executable_verifier(
                        task, response, verifier, line_number=1
                    )

    def test_decimal_tolerance_and_pointer_fail_closed(self) -> None:
        checks = [
            {
                "checkId": "value-close",
                "kind": "json-decimal-close",
                "pointer": "/values/0",
                "expected": "10",
                "absoluteTolerance": "0.01",
                "relativeTolerance": "0",
            }
        ]
        task, response, verifier = _fixture('{"values":[10.02]}', checks)
        result = _execute_executable_verifier(task, response, verifier, line_number=1)
        self.assertFalse(result["accepted"])
        self.assertIn("outside-tolerance", result["checks"][0]["evidence"])

        checks[0]["pointer"] = "/values/01"
        task, response, verifier = _fixture('{"values":[10]}', checks)
        result = _execute_executable_verifier(task, response, verifier, line_number=1)
        self.assertFalse(result["accepted"])
        self.assertIn("json-pointer-missing", result["checks"][0]["evidence"])

    def test_schema_rejects_commands_unknown_fields_and_negative_only_contracts(
        self,
    ) -> None:
        mutations = (
            [{"checkId": "invalid-kind", "kind": [], "value": "ok"}],
            [{"checkId": "blank-value", "kind": "contains", "value": "   "}],
            [
                {
                    "checkId": "bad-pointer",
                    "kind": "json-string-equals",
                    "pointer": "/bad~2escape",
                    "value": "ok",
                }
            ],
            [
                {
                    "checkId": "unsafe-command",
                    "kind": "contains",
                    "value": "ok",
                    "command": "powershell.exe",
                }
            ],
            [{"checkId": "only-negative", "kind": "not-contains", "value": "bad"}],
            [
                {
                    "checkId": "bad-tolerance",
                    "kind": "json-decimal-close",
                    "pointer": "/value",
                    "expected": "1",
                    "absoluteTolerance": "0",
                    "relativeTolerance": "1.01",
                }
            ],
            [
                {
                    "checkId": "exponent-tolerance",
                    "kind": "json-decimal-close",
                    "pointer": "/value",
                    "expected": "1",
                    "absoluteTolerance": "0",
                    "relativeTolerance": "1e-1",
                }
            ],
        )
        for checks in mutations:
            with self.subTest(checks=checks):
                task, response, verifier = _fixture('{"value":1}', checks)
                with self.assertRaises(ValidationError):
                    _execute_executable_verifier(
                        task, response, verifier, line_number=1
                    )

    def test_verifier_bytes_and_identity_are_exactly_bound(self) -> None:
        checks = [{"checkId": "ok", "kind": "contains", "value": "ok"}]
        task, response, verifier = _fixture("ok", checks)
        with self.assertRaisesRegex(ValidationError, "bound task hash"):
            _execute_executable_verifier(task, response, verifier + b" ", line_number=1)

        document = json.loads(verifier)
        document["taskId"] = "different-task"
        forged = canonical_json_bytes(document) + b"\n"
        task["verifier"]["sha256"] = hashlib.sha256(forged).hexdigest()
        task["taskSha256"] = evaluation_task_sha256(task)
        response["taskSha256"] = task["taskSha256"]
        response["responseSha256"] = evaluation_response_sha256(response)
        with self.assertRaisesRegex(ValidationError, "identity"):
            _execute_executable_verifier(task, response, forged, line_number=1)

    def test_csharp_profile_derives_exact_inputs_and_maps_six_checks(self) -> None:
        source = "public sealed class ReviewedStrategy { }"
        task, response, verifier = _csharp_fixture(source)
        authority = _authority("1")
        captured: dict[str, bytes] = {}
        trust = CSharpVerifierAuthorityTrust(
            Path("public.pem"), "e" * 64, "audience", "key", "reviewer"
        )
        with tempfile.TemporaryDirectory() as temporary:
            context = CSharpVerifierExecutionContext(
                Path("authority.json"), trust, Path(temporary)
            )
            with (
                patch(
                    "hyperion_model.verifier_runtime.validate_csharp_verifier_authority",
                    return_value=authority,
                ),
                patch(
                    "hyperion_model.verifier_runtime.run_csharp_strategy_verification",
                    side_effect=_fake_csharp_runner(authority, captured),
                ),
            ):
                result = _execute_executable_verifier(
                    task,
                    response,
                    verifier,
                    line_number=1,
                    csharp_context=context,
                )

        self.assertTrue(result["accepted"])
        self.assertEqual(
            list(CSHARP_CHECK_IDS), [c["checkId"] for c in result["checks"]]
        )
        self.assertEqual(source.encode(), captured["source"])
        request = json.loads(captured["request"])
        expectations = json.loads(captured["expectations"])
        self.assertEqual(
            hashlib.sha256(captured["source"]).hexdigest(), request["sourceSha256"]
        )
        self.assertEqual(
            hashlib.sha256(captured["request"]).hexdigest(),
            expectations["requestSha256"],
        )
        self.assertNotIn("expectedTraceSha256", request["cases"][0])
        self.assertEqual("d" * 64, expectations["cases"][0]["traceSha256"])
        serialized = json.dumps(result)
        self.assertNotIn("d" * 64, serialized)
        self.assertNotIn(authority.payload_sha256, serialized)

    def test_csharp_profile_never_normalizes_fences_and_rejects_bad_source_preflight(
        self,
    ) -> None:
        authority = _authority("1")
        trust = CSharpVerifierAuthorityTrust(
            Path("public.pem"), "e" * 64, "audience", "key", "reviewer"
        )
        with tempfile.TemporaryDirectory() as temporary:
            context = CSharpVerifierExecutionContext(
                Path("authority.json"), trust, Path(temporary)
            )
            fenced = "```csharp\npublic sealed class Strategy {}\n```"
            task, response, verifier = _csharp_fixture(fenced)
            captured: dict[str, bytes] = {}
            with (
                patch(
                    "hyperion_model.verifier_runtime.validate_csharp_verifier_authority",
                    return_value=authority,
                ),
                patch(
                    "hyperion_model.verifier_runtime.run_csharp_strategy_verification",
                    side_effect=_fake_csharp_runner(authority, captured),
                ),
            ):
                _execute_executable_verifier(
                    task,
                    response,
                    verifier,
                    line_number=1,
                    csharp_context=context,
                )
            self.assertEqual(fenced.encode(), captured["source"])

            for invalid in ("\ufeffpublic class Strategy {}", "x" * 262_145):
                with self.subTest(length=len(invalid)):
                    task, response, verifier = _csharp_fixture(invalid)
                    with (
                        patch(
                            "hyperion_model.verifier_runtime.validate_csharp_verifier_authority",
                            return_value=authority,
                        ),
                        patch(
                            "hyperion_model.verifier_runtime.run_csharp_strategy_verification"
                        ) as runner,
                        self.assertRaisesRegex(ValidationError, "strategy source"),
                    ):
                        _execute_executable_verifier(
                            task,
                            response,
                            verifier,
                            line_number=1,
                            csharp_context=context,
                        )
                    runner.assert_not_called()

    def test_csharp_profile_requires_context_and_exact_task_contract(self) -> None:
        task, response, verifier = _csharp_fixture("public class Strategy {}")
        with self.assertRaisesRegex(ValidationError, "execution context"):
            _execute_executable_verifier(task, response, verifier, line_number=1)

        for mutation in ("taskKind", "requiredChecks", "extraField"):
            with self.subTest(mutation=mutation):
                task, response, verifier = _csharp_fixture("public class Strategy {}")
                if mutation == "taskKind":
                    task["taskKind"] = "ArchitectureDesign"
                elif mutation == "requiredChecks":
                    task["verifier"]["requiredChecks"] = list(
                        reversed(CSHARP_CHECK_IDS)
                    )
                else:
                    value = json.loads(verifier)
                    value["command"] = "dotnet"
                    verifier = canonical_json_bytes(value) + b"\n"
                    task["verifier"]["sha256"] = hashlib.sha256(verifier).hexdigest()
                task["taskSha256"] = evaluation_task_sha256(task)
                response["taskSha256"] = task["taskSha256"]
                response["responseSha256"] = evaluation_response_sha256(response)
                with self.assertRaises(ValidationError):
                    _execute_executable_verifier(
                        task, response, verifier, line_number=1
                    )

    def test_authority_renewal_is_excluded_but_runtime_drift_changes_result(
        self,
    ) -> None:
        source = "public sealed class ReviewedStrategy { }"
        task, response, verifier = _csharp_fixture(source)
        trust = CSharpVerifierAuthorityTrust(
            Path("public.pem"), "e" * 64, "audience", "key", "reviewer"
        )

        def execute(marker: str, toolchain: str) -> dict:
            authority = _authority(marker)
            with tempfile.TemporaryDirectory() as temporary:
                context = CSharpVerifierExecutionContext(
                    Path("authority.json"), trust, Path(temporary)
                )
                with (
                    patch(
                        "hyperion_model.verifier_runtime.validate_csharp_verifier_authority",
                        return_value=authority,
                    ),
                    patch(
                        "hyperion_model.verifier_runtime.run_csharp_strategy_verification",
                        side_effect=_fake_csharp_runner(
                            authority, {}, toolchain_sha256=toolchain
                        ),
                    ),
                ):
                    return _execute_executable_verifier(
                        task,
                        response,
                        verifier,
                        line_number=1,
                        csharp_context=context,
                    )

        first = execute("1", "f" * 64)
        renewed = execute("2", "f" * 64)
        drifted = execute("2", "5" * 64)
        self.assertEqual(first, renewed)
        self.assertNotEqual(first["resultSha256"], drifted["resultSha256"])

    def test_bound_context_rejects_authority_configuration_drift(self) -> None:
        trust = CSharpVerifierAuthorityTrust(
            Path("public.pem"), "e" * 64, "audience", "key", "reviewer"
        )
        context = CSharpVerifierExecutionContext(
            Path("authority.json"), trust, Path(tempfile.gettempdir())
        )
        original = _authority("1")
        changed = _authority("2")
        changed.payload["verifier"]["image"] = "changed-image-binding"
        with patch(
            "hyperion_model.verifier_runtime.validate_csharp_verifier_authority",
            return_value=original,
        ):
            bound = bind_csharp_verifier_execution_context(context)
        with (
            patch(
                "hyperion_model.verifier_runtime.validate_csharp_verifier_authority",
                return_value=changed,
            ),
            self.assertRaisesRegex(ValidationError, "execution context binding"),
        ):
            bind_csharp_verifier_execution_context(bound)

    def test_machine_readable_schema_is_closed_and_has_no_execution_primitive(
        self,
    ) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "executable-verifier.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            EXECUTABLE_VERIFIER_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        pointer_pattern = re.compile(schema["$defs"]["pointer"]["pattern"])
        for value in ("", "/status", "/~0/~1", "/" * 64):
            self.assertIsNotNone(pointer_pattern.fullmatch(value))
        for value in ("status", "/bad~2escape", "/" * 65):
            self.assertIsNone(pointer_pattern.fullmatch(value))

        relative_pattern = re.compile(schema["$defs"]["relativeTolerance"]["pattern"])
        for value in ("0", "0.0001", "1", "1.000"):
            self.assertIsNotNone(relative_pattern.fullmatch(value))
        for value in ("-0.1", "1.01", "1e-1"):
            self.assertIsNone(relative_pattern.fullmatch(value))

        text_pattern = re.compile(
            schema["$defs"]["textCheck"]["properties"]["value"]["pattern"]
        )
        self.assertIsNone(text_pattern.search(" \t\n"))
        self.assertIsNotNone(text_pattern.search(" reviewed "))
        exact_keys_ref = "#/$defs/jsonObjectExactKeysCheck"
        check_refs = {
            entry["$ref"] for entry in schema["properties"]["checks"]["items"]["oneOf"]
        }
        self.assertIn(exact_keys_ref, check_refs)
        exact_keys = schema["$defs"]["jsonObjectExactKeysCheck"]
        self.assertFalse(exact_keys["additionalProperties"])
        self.assertEqual(["checkId", "kind", "pointer", "keys"], exact_keys["required"])
        self.assertEqual(
            "json-object-exact-keys",
            exact_keys["properties"]["kind"]["const"],
        )
        self.assertEqual(
            {"$ref": "#/$defs/pointer"}, exact_keys["properties"]["pointer"]
        )
        keys_schema = exact_keys["properties"]["keys"]
        self.assertEqual(1, keys_schema["minItems"])
        self.assertEqual(128, keys_schema["maxItems"])
        self.assertTrue(keys_schema["uniqueItems"])
        self.assertEqual(
            {"type": "string", "minLength": 1, "maxLength": 200},
            keys_schema["items"],
        )
        serialized = json.dumps(schema)
        for forbidden in ("command", "script", "plugin", "regex", "executable"):
            if forbidden == "executable":
                continue
            self.assertNotIn(f'"{forbidden}"', serialized)

        csharp_schema = json.loads(
            (ROOT / "schemas" / "executable-verifier.v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(csharp_schema["additionalProperties"])
        self.assertEqual(
            EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION,
            csharp_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            CSHARP_SOURCE_PROFILE,
            csharp_schema["properties"]["profile"]["const"],
        )
        csharp_serialized = json.dumps(csharp_schema)
        for forbidden in ("command", "script", "plugin", "package", "entrypoint"):
            self.assertNotIn(f'"{forbidden}"', csharp_serialized)


if __name__ == "__main__":
    unittest.main()
