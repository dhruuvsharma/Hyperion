from __future__ import annotations

import copy
import hashlib
import importlib
import inspect
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import hyperion_model.evaluation as evaluation_module
import hyperion_model.cli as cli_module
import hyperion_model.release as release_module
import hyperion_model.verifier_runtime as verifier_runtime_module
import hyperion_model.verifier_replay_audit as replay_audit_module
import hyperion_model as hyperion_model_package
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from hyperion_model.artifacts import (
    TRAINING_ARTIFACT_V1_SCHEMA_VERSION,
    seal_training_artifact,
    training_artifact_sha256,
    validate_training_artifact,
)
from hyperion_model.base_engine_wrapper import BaseEngineActivationTrust
from hyperion_model.csharp_verifier import (
    CHECK_IDS as CSHARP_CHECK_IDS,
    CSharpVerifierAuthorityTrust,
)
from hyperion_model.core import (
    DOMAINS,
    ValidationError,
    canonical_json_bytes,
    create_bundle,
    expert_conversation_sha256,
    sha256_file,
)
from hyperion_model.deployment import (
    EXECUTION_MODEL_PREFIX,
    MODEL_READINESS_ATTESTATION_SCHEMA_VERSION,
    SERVING_PROFILE_SCHEMA_VERSION,
    compute_model_readiness_proof,
    create_model_readiness_attestation,
    create_serving_profile,
    load_serving_profile,
    validate_serving_profile,
)
from hyperion_model.evaluation import (
    BaseResponseAttestationTrust,
    EVALUATION_RESPONSE_SCHEMA_VERSION,
    EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
    EVALUATION_TASK_SCHEMA_VERSION,
    PROMOTION_POLICY_SCHEMA_VERSION,
    VERIFIER_DECISION_MANIFEST_SCHEMA_VERSION,
    VERIFIER_RESULT_SCHEMA_VERSION,
    TransportResponse,
    aggregate_promotion_evidence,
    capture_openai_responses,
    compile_verifier_results,
    evaluation_output_sha256,
    evaluation_prompt_sha256,
    evaluation_response_sha256,
    evaluation_response_set_sha256,
    evaluation_task_sha256,
    evidence_sha256,
    promotion_policy_sha256,
    validate_evaluation_responses,
    validate_evaluation_tasks,
    validate_promotion_evidence,
    validate_promotion_policy,
    validate_verifier_results,
    verifier_result_sha256,
    verifier_result_set_sha256,
)
from hyperion_model.trainer_provenance import TrainerProvenanceTrust
from hyperion_model.verifier_runtime import (
    CSharpVerifierExecutionContext,
    DECLARATIVE_OUTPUT_PROFILE,
    EXECUTABLE_VERIFIER_SCHEMA_VERSION,
    EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION,
    run_release_verifiers,
)
from hyperion_model.verifier_authority import SOURCE_PROFILE as CSHARP_SOURCE_PROFILE
from hyperion_model.verifier_replay_audit import (
    CSharpVerifierReplayAuditTrust,
    create_csharp_verifier_replay_audit,
    finalize_csharp_verifier_replay_audit,
    prepare_csharp_verifier_replay_audit_signing_bundle,
    verify_csharp_verifier_replay_audit_signing_bundle,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_jsonl(path: Path, *records: dict) -> None:
    path.write_text(
        "".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            for record in records
        ),
        encoding="utf-8",
        newline="\n",
    )


def _write_catalog(path: Path) -> dict:
    catalog = json.loads(
        (ROOT / "candidate-catalog.v1.json").read_text(encoding="utf-8")
    )
    path.write_text(json.dumps(catalog), encoding="utf-8")
    return catalog


def _sft_row(example_id: str) -> dict:
    messages = [
        {"role": "system", "content": "Answer only with reviewed evidence."},
        {"role": "user", "content": f"Question for {example_id}?"},
        {"role": "assistant", "content": f"Reviewed answer for {example_id}."},
    ]
    return {
        "messages": messages,
        "metadata": {
            "id": example_id,
            "taskKind": "GeneralQuestionAnswering",
            "domains": list(DOMAINS),
            "conversationSha256": expert_conversation_sha256(messages),
            "origin": "HumanAuthored",
            "producer": "unit-test",
            "modelId": None,
            "modelRevision": None,
            "promptSha256": None,
            "profileVersion": None,
            "split": "development",
            "contaminationGroup": f"group-{example_id}",
            "cutoffUtc": "2025-01-15T12:00:00+00:00",
            "sourceSchema": "expert-model-dataset/v1",
        },
    }


def _task(
    task_id: str, split: str, *, criticality: str = "standard", group: str | None = None
) -> dict:
    messages = [
        {"role": "system", "content": "Answer from the supplied model context only."},
        {"role": "user", "content": f"Evaluate {task_id}."},
    ]
    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": task_id,
        "taskSha256": "0" * 64,
        "split": split,
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
        "contaminationGroup": group or f"group-{task_id}",
        "cutoffUtc": "2025-01-15T12:00:00Z",
        "criticality": criticality,
        "maxOutputTokens": 128,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    return task


def _identity(response: dict) -> dict:
    return {
        "responseSchemaVersion": response["schemaVersion"],
        "targetKind": response["targetKind"],
        "executionModelId": response["executionModelId"],
        "candidateCatalogSha256": response["candidateCatalogSha256"],
        "candidateId": response["candidateId"],
        "modelId": response["modelId"],
        "modelRevision": response["modelRevision"],
        "servingProfile": response["servingProfile"],
        "runId": response["runId"],
        "seed": response["generation"]["seed"],
    }


def _policy(
    calibration_hash: str,
    sealed_hash: str,
    evidence_hash: str,
    candidate: dict,
    baseline: dict,
    *,
    data_release: dict | None = None,
    research_only: bool = True,
) -> dict:
    policy = {
        "schemaVersion": PROMOTION_POLICY_SCHEMA_VERSION,
        "policySha256": "0" * 64,
        "policyId": "reviewed-policy-v1",
        "thresholdSourceSplit": "calibration",
        "dataRelease": data_release,
        "researchOnly": research_only,
        "calibrationTaskSetSha256": calibration_hash,
        "calibrationEvidenceSha256": evidence_hash,
        "sealedTaskSetSha256": sealed_hash,
        "frozenAtUtc": "2026-01-01T00:00:00Z",
        "candidateRun": candidate,
        "baselineRun": baseline,
        "minimumTotalTasks": 1,
        "minimumCriticalTasks": 1,
        "minimumPerDomainTaskCounts": {domain: 1 for domain in DOMAINS},
        "minimumPerDomainContaminationGroupCounts": {domain: 1 for domain in DOMAINS},
        "overallAcceptedRateThreshold": 1.0,
        "perDomainAcceptedRateThresholds": {domain: 1.0 for domain in DOMAINS},
        "requireNoOverallRegression": True,
        "requireNoPerDomainRegression": True,
    }
    policy["policySha256"] = promotion_policy_sha256(policy)
    return policy


def _result(task: dict, response: dict, accepted: bool = True) -> dict:
    checks = []
    for check_id in task["verifier"]["requiredChecks"]:
        evidence = f"Reviewed evidence for {check_id}."
        checks.append(
            {
                "checkId": check_id,
                "passed": accepted,
                "evidence": evidence,
                "evidenceSha256": evidence_sha256(evidence),
            }
        )
    result = {
        "schemaVersion": VERIFIER_RESULT_SCHEMA_VERSION,
        "resultSha256": "0" * 64,
        "runId": response["runId"],
        "taskId": task["taskId"],
        "taskSha256": task["taskSha256"],
        "responseSha256": response["responseSha256"],
        "verifierId": task["verifier"]["id"],
        "verifierSha256": task["verifier"]["sha256"],
        "checks": checks,
        "accepted": accepted,
    }
    result["resultSha256"] = verifier_result_sha256(result)
    return result


def _response(task: dict, *, output: str, run_id: str = "eval-run-001") -> dict:
    response = {
        "schemaVersion": EVALUATION_RESPONSE_SCHEMA_VERSION,
        "responseSha256": "0" * 64,
        "candidateCatalogSha256": "c" * 64,
        "candidateId": "compiler-test-candidate",
        "modelId": "compiler-test-model",
        "modelRevision": "1" * 40,
        "servingProfile": {"id": "compiler-test-profile", "sha256": "d" * 64},
        "targetKind": "trained-adapter",
        "executionModelId": "daxalgo-expert-sha256-" + "d" * 64,
        "runId": run_id,
        "dataRelease": None,
        "researchOnly": True,
        "evidenceStatus": "unpromoted-research",
        "taskId": task["taskId"],
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
            "maxOutputTokens": task["maxOutputTokens"],
        },
        "latencyMs": 1,
        "usage": {"promptTokens": 10, "completionTokens": 3, "totalTokens": 13},
        "finishReason": "stop",
        "capturedAtUtc": "2026-01-02T00:00:00Z",
    }
    response["responseSha256"] = evaluation_response_sha256(response)
    return response


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog_path = self.root / "catalog.json"
        self.catalog = _write_catalog(self.catalog_path)
        self.serving_fixtures: dict[tuple[object, ...], dict] = {}
        trainer_key = ec.generate_private_key(ec.SECP256R1())
        self.trainer_private_key_path = self.root / "trainer-provenance-private.pem"
        self.trainer_public_key_path = self.root / "trainer-provenance-public.pem"
        self.trainer_private_key_path.write_bytes(
            trainer_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.trainer_public_key_path.write_bytes(
            trainer_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        trainer_spki_sha256 = hashlib.sha256(
            trainer_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        self.trainer_provenance_trust = TrainerProvenanceTrust(
            public_key_path=self.trainer_public_key_path,
            public_key_spki_sha256=trainer_spki_sha256,
            audience="training-artifact-v2",
            key_id="evaluation-fixture-trainer-key-v1",
            signer_role="isolated-evaluation-fixture-trainer",
        )
        self.trainer_provenance_now = datetime(2026, 1, 2, tzinfo=timezone.utc)

    def _trainer_signing_arguments(self) -> dict:
        return {
            "trainer_provenance_trust": self.trainer_provenance_trust,
            "trainer_private_key_path": self.trainer_private_key_path,
            "trainer_private_key_password": None,
            "trainer_id": "evaluation-fixture-trainer-01",
            "trainer_expires_at_utc": "2027-01-01T00:00:00Z",
            "trainer_provenance_now": self.trainer_provenance_now,
        }

    def test_promotion_response_attestation_trust_is_role_specific_and_fresh(
        self,
    ) -> None:
        activation_trust = BaseEngineActivationTrust(
            public_key_path=self.root / "activation.pem",
            public_key_spki_sha256="a" * 64,
            audience="base-evaluation",
            key_id="activation-v1",
            signer_role="base-runtime-launcher",
        )
        trust = BaseResponseAttestationTrust(
            activation_trust=activation_trust,
            runtime_public_key_path=self.root / "runtime.pem",
        )
        v2_records = ({"schemaVersion": EVALUATION_RESPONSE_V2_SCHEMA_VERSION},)
        v1_records = ({"schemaVersion": EVALUATION_RESPONSE_SCHEMA_VERSION},)
        task_set = mock.sentinel.task_set

        with self.assertRaisesRegex(ValidationError, "requires external"):
            evaluation_module._validate_promotion_response_attestations(
                "baseline responses", v2_records, task_set, None
            )
        with self.assertRaisesRegex(ValidationError, "cannot be supplied"):
            evaluation_module._validate_promotion_response_attestations(
                "candidate responses", v1_records, task_set, trust
            )
        with mock.patch.object(
            evaluation_module,
            "_validate_attested_base_evaluation_response_records",
            return_value=v2_records,
        ) as validate:
            evaluation_module._validate_promotion_response_attestations(
                "baseline responses", v2_records, task_set, trust
            )
        validate.assert_called_once_with(
            v2_records,
            task_set,
            activation_trust=activation_trust,
            runtime_public_key_path=trust.runtime_public_key_path,
        )

    def test_research_aggregation_rejects_unused_response_attestation_trust(
        self,
    ) -> None:
        inputs = self._paired_fixture()
        inputs["baseline_attestation_trust"] = BaseResponseAttestationTrust(
            activation_trust=BaseEngineActivationTrust(
                public_key_path=self.root / "activation.pem",
                public_key_spki_sha256="a" * 64,
                audience="base-evaluation",
                key_id="activation-v1",
                signer_role="base-runtime-launcher",
            ),
            runtime_public_key_path=self.root / "runtime.pem",
        )
        with self.assertRaisesRegex(ValidationError, "research-only aggregation"):
            aggregate_promotion_evidence(**inputs)

    def _verifier_compile_fixture(self, name: str = "compiler") -> dict:
        tasks_path = self.root / f"{name}.tasks.jsonl"
        responses_path = self.root / f"{name}.responses.jsonl"
        decisions_path = self.root / f"{name}.decisions.json"
        output_path = self.root / f"{name}.results.jsonl"
        tasks = [_task(f"{name}-z", "sealed"), _task(f"{name}-a", "sealed")]
        responses = [
            _response(task, output=f"Reviewed output for {task['taskId']}.")
            for task in tasks
        ]
        _write_jsonl(tasks_path, *tasks)
        _write_jsonl(responses_path, *responses)
        task_set = validate_evaluation_tasks(tasks_path)
        response_records = validate_evaluation_responses(responses_path, task_set)
        decisions = []
        for response in reversed(response_records):
            rejected = response["taskId"].endswith("-a")
            decisions.append(
                {
                    "taskId": response["taskId"],
                    "responseSha256": response["responseSha256"],
                    "checks": [
                        {
                            "checkId": "correct",
                            "passed": not rejected,
                            "evidence": f"Correctness evidence for {response['taskId']}.",
                        },
                        {
                            "checkId": "safe",
                            "passed": True,
                            "evidence": f"Safety evidence for {response['taskId']}.",
                        },
                    ],
                }
            )
        manifest = {
            "schemaVersion": VERIFIER_DECISION_MANIFEST_SCHEMA_VERSION,
            "inputs": {
                "taskSetSha256": task_set.task_set_sha256,
                "responseSetSha256": evaluation_response_set_sha256(response_records),
            },
            "decisions": decisions,
        }
        decisions_path.write_text(json.dumps(manifest), encoding="utf-8", newline="\n")
        return {
            "tasks_path": tasks_path,
            "responses_path": responses_path,
            "decisions_path": decisions_path,
            "output_path": output_path,
            "tasks": tasks,
            "responses": list(response_records),
            "manifest": manifest,
        }

    def _bound_release_fixture(
        self, *, provider: bool = False, csharp: bool = False
    ) -> dict:
        try:
            release_tests = importlib.import_module("test_release")
        except ModuleNotFoundError:
            release_tests = importlib.import_module("tests.test_release")
        fixture = release_tests.CorpusEvaluationReleaseTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)

        if csharp:
            csharp_record = release_tests._code_corpus_record("sealed-1")
            csharp_record["split"] = "sealed"
            fixture.sealed_record = csharp_record
            task_id = "task-sealed-1"
            _, verifier_path, context_pack_path = fixture.asset_paths[task_id]
            csharp_task = release_tests._task(
                csharp_record,
                f"verifier-{task_id}",
                hashlib.sha256(verifier_path.read_bytes()).hexdigest(),
                hashlib.sha256(context_pack_path.read_bytes()).hexdigest(),
            )
            release_tests._write_jsonl(fixture.sealed_tasks, csharp_task)
            fixture._write_bindings()

        development = release_tests._corpus_record(
            "development-1",
            "development",
            train=True,
            upload=provider,
        )
        records = [development, fixture.calibration_record, fixture.sealed_record]
        for record in records:
            record["domains"] = list(DOMAINS)
            if provider:
                record["rights"]["mayUploadToProvider"] = True
                for source in record["sources"]:
                    source["rights"]["mayUploadToProvider"] = True
        release_tests._write_jsonl(fixture.corpus_path, *records)

        for tasks_path, criticality in (
            (fixture.calibration_tasks, "standard"),
            (fixture.sealed_tasks, "critical"),
        ):
            task = json.loads(tasks_path.read_text(encoding="utf-8"))
            verifier_path = fixture.asset_paths[task["taskId"]][1]
            verifier_document = {
                "schemaVersion": EXECUTABLE_VERIFIER_SCHEMA_VERSION,
                "verifierId": task["verifier"]["id"],
                "taskId": task["taskId"],
                "profile": DECLARATIVE_OUTPUT_PROFILE,
                "checks": [
                    {
                        "checkId": "correct",
                        "kind": "contains",
                        "value": "Reviewed",
                    }
                ],
            }
            if csharp and tasks_path == fixture.sealed_tasks:
                verifier_document = {
                    "schemaVersion": EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION,
                    "verifierId": task["verifier"]["id"],
                    "taskId": task["taskId"],
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
                            "caseId": "audit-case-1",
                            "startUtc": "2025-01-21T09:30:00Z",
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
                task["taskKind"] = "CodeGeneration"
                task["domains"] = ["CSharp"]
                task["verifier"]["requiredChecks"] = list(CSHARP_CHECK_IDS)
                task["maxOutputTokens"] = 4096
            verifier_path.write_bytes(canonical_json_bytes(verifier_document) + b"\n")
            task["verifier"]["sha256"] = hashlib.sha256(
                verifier_path.read_bytes()
            ).hexdigest()
            task["domains"] = list(DOMAINS)
            task["criticality"] = criticality
            task["taskSha256"] = evaluation_task_sha256(task)
            release_tests._write_jsonl(tasks_path, task)

        sft_path = fixture.root / "dataset.sft.jsonl"
        release_tests._write_jsonl(
            sft_path,
            release_tests._sft_row(development, fixture.corpus_path),
        )
        created = fixture._create(
            purpose=(
                "provider-training-evaluation"
                if provider
                else "local-training-evaluation"
            ),
            sft_path=sft_path,
        )
        return {
            "fixture": fixture,
            "created": created,
            "release_path": Path(created["releasePath"]),
            "release_identity": {
                "releaseId": created["releaseId"],
                "releaseSha256": created["releaseSha256"],
                "manifestSha256": created["manifestSha256"],
            },
            "review_receipt_trust": fixture.review_receipt_trust,
            "evaluation_authoring_approval_trust": (
                fixture.evaluation_authoring_approval_trust
            ),
            "review_receipt_now": release_tests.VALIDATION_TIME,
            "sft_path": sft_path,
        }

    def _serving_fixture(
        self,
        candidate_index: int,
        profile_id: str,
        *,
        data_release_path: Path | None = None,
        sft_path: Path | None = None,
        review_receipt_trust=None,
        evaluation_authoring_approval_trust=None,
        review_receipt_now: datetime | None = None,
    ) -> dict:
        is_candidate = data_release_path is not None
        key = (
            candidate_index,
            profile_id,
            str(data_release_path) if data_release_path is not None else None,
            (
                review_receipt_trust.public_key_spki_sha256
                if review_receipt_trust is not None
                else None
            ),
            (
                evaluation_authoring_approval_trust.public_key_spki_sha256
                if evaluation_authoring_approval_trust is not None
                else None
            ),
        )
        if key in self.serving_fixtures:
            return self.serving_fixtures[key]
        fixture_root = self.root / f"serving-{candidate_index}-{profile_id}"
        sft = (
            sft_path or self.root / f"serving-{candidate_index}-{profile_id}.sft.jsonl"
        )
        if sft_path is None:
            _write_jsonl(sft, _sft_row(f"serving-{candidate_index}"))
        template = self.root / f"serving-{candidate_index}-{profile_id}.jinja"
        template.write_text(
            "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\\n{% endfor %}",
            encoding="utf-8",
        )
        candidate = self.catalog["candidates"][candidate_index]
        create_bundle(
            catalog_path=self.catalog_path,
            sft_path=sft,
            candidate_id=candidate["id"],
            chat_template_path=template,
            chat_template_name="reviewed-test-template-v1",
            output_directory=fixture_root,
            runtime_profile_path=Path(__file__).resolve().parents[1]
            / "training-runtime-profile.v1.json",
            data_release_path=data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            review_receipt_now=review_receipt_now,
        )
        manifest_path = fixture_root / "training-run-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        artifact_path = fixture_root / "outputs" / "adapter"
        artifact_path.mkdir(parents=True)
        header = b'{"adapter":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}'
        (artifact_path / "adapter_model.safetensors").write_bytes(
            len(header).to_bytes(8, byteorder="little") + header + b"\x00\x00"
        )
        (artifact_path / "adapter_config.json").write_text(
            json.dumps(
                {
                    "base_model_name_or_path": candidate["modelId"],
                    "peft_type": "LORA",
                    "task_type": "CAUSAL_LM",
                    "bias": "none",
                    "r": manifest["hyperparameters"]["loraR"],
                    "lora_alpha": manifest["hyperparameters"]["loraAlpha"],
                    "lora_dropout": manifest["hyperparameters"]["loraDropout"],
                    "target_modules": manifest["hyperparameters"]["loraTargetModules"],
                }
            ),
            encoding="utf-8",
        )
        (artifact_path / "tokenizer_config.json").write_text(
            json.dumps(
                {
                    "model_max_length": 8192,
                    "chat_template": manifest["chatTemplate"]["template"],
                }
            ),
            encoding="utf-8",
        )
        (artifact_path / "tokenizer.json").write_bytes(b'{"version":"1.0"}\n')
        (artifact_path / "special_tokens_map.json").write_bytes(
            b'{"eos_token":"<eos>"}\n'
        )
        artifact = seal_training_artifact(
            artifact_path,
            {
                "schemaVersion": "daxalgo.hyperion.training-artifact/v1",
                "recordedAtUtc": "2026-01-01T00:00:00Z",
                "runId": manifest["runId"],
                "mode": (
                    "unpromoted-candidate"
                    if data_release_path is not None
                    else "unpromoted-research"
                ),
                "productionEligible": False,
                "reason": (
                    "Training alone does not satisfy evaluation, promotion, signing, or deployment gates."
                    if data_release_path is not None
                    else "Research-only training cannot produce promotion-eligible evidence."
                ),
                "manifestSha256": sha256_file(manifest_path),
                "dataRelease": manifest["dataRelease"],
                "baseModel": {
                    "candidateId": candidate["id"],
                    "modelId": candidate["modelId"],
                    "revision": candidate["revision"],
                },
                "datasetSnapshot": {
                    "path": "inputs/dataset.sft.jsonl",
                    "sha256": manifest["dataset"]["sha256"],
                    "recordCount": manifest["dataset"]["recordCount"],
                },
                "environment": {
                    "python": {
                        "version": "3.11.0",
                        "implementation": "CPython",
                        "executable": "python",
                    },
                    "platform": {
                        "description": "test",
                        "system": "test",
                        "release": "test",
                        "machine": "test",
                    },
                    "dependencyVersions": {
                        name: "test-1.0"
                        for name in (
                            "torch",
                            "transformers",
                            "datasets",
                            "peft",
                            "trl",
                            "accelerate",
                            "bitsandbytes",
                            "cryptography",
                        )
                    },
                    "computeDtype": "bfloat16",
                    "gpu": {
                        "cudaAvailable": True,
                        "deviceCount": 1,
                        "largestGpuGiB": 48.0,
                        "requiredGpuGiB": 16.0,
                        "memoryGateWaivedForSmoke": False,
                        "devices": [
                            {
                                "index": 0,
                                "name": "Test GPU",
                                "totalMemoryGiB": 48.0,
                                "computeCapability": "9.0",
                                "multiProcessorCount": 100,
                            }
                        ],
                        "cudaRuntimeVersion": "12.4",
                        "productionEligible": False,
                    },
                },
            },
            data_release_path=data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            review_receipt_now=review_receipt_now,
            **(self._trainer_signing_arguments() if is_candidate else {}),
        )
        profile_path = fixture_root / "serving-profile.json"
        profile = create_serving_profile(
            profile_id=profile_id,
            artifact_path=artifact_path,
            manifest_path=manifest_path,
            output_path=profile_path,
            engine="vllm",
            engine_version="0.10.0",
            container_image_digest="sha256:" + "6" * 64,
            quantization="bitsandbytes-nf4",
            compute_dtype="bfloat16",
            max_model_length=8_192,
            tensor_parallel_size=1,
            gpu_profile="l40s-48gb",
            trainer_provenance_trust=(
                self.trainer_provenance_trust if is_candidate else None
            ),
            trainer_provenance_now=(
                self.trainer_provenance_now if is_candidate else None
            ),
        )
        result = {
            "artifact": artifact,
            "artifact_path": artifact_path,
            "manifest_path": manifest_path,
            "profile": profile,
            "profile_path": profile_path,
            "trainer_provenance_trust": (
                self.trainer_provenance_trust if is_candidate else None
            ),
            "trainer_provenance_now": (
                self.trainer_provenance_now if is_candidate else None
            ),
        }
        self.serving_fixtures[key] = result
        return result

    def _capture(
        self,
        tasks_path: Path,
        output: Path,
        transport,
        *,
        candidate_index: int = 0,
        run_id: str = "eval-run-001",
        profile_id: str = "deterministic-v1",
        base_url: str = "http://127.0.0.1/v1",
        key: str = "top-secret-value",
        data_release_path: Path | None = None,
        sft_path: Path | None = None,
        review_receipt_trust=None,
        evaluation_authoring_approval_trust=None,
        review_receipt_now: datetime | None = None,
        research_only: bool = True,
    ) -> None:
        fixture = self._serving_fixture(
            candidate_index,
            profile_id,
            data_release_path=data_release_path,
            sft_path=sft_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            review_receipt_now=review_receipt_now,
        )
        call_count = len(tasks_path.read_text(encoding="utf-8").splitlines()) * 2
        monotonic = iter(float(index) / 10 for index in range(call_count)).__next__
        with mock.patch.dict(os.environ, {"VQ_TEST_KEY": key}, clear=False):
            capture_openai_responses(
                tasks_path=tasks_path,
                catalog_path=self.catalog_path,
                output_path=output,
                serving_profile_path=fixture["profile_path"],
                training_artifact_path=fixture["artifact_path"],
                training_manifest_path=fixture["manifest_path"],
                run_id=run_id,
                base_url=base_url,
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=data_release_path,
                review_receipt_trust=review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    evaluation_authoring_approval_trust
                ),
                review_receipt_now=review_receipt_now,
                trainer_provenance_trust=fixture["trainer_provenance_trust"],
                research_only=research_only,
                transport=transport,
                clock=lambda: datetime(2026, 1, 2, tzinfo=timezone.utc),
                monotonic=monotonic,
            )

    @staticmethod
    def _transport(
        *, finish_reason: str = "stop", content: str | None = "Reviewed output."
    ):
        def transport(url, headers, body, timeout, max_bytes):
            requested = json.loads(body)
            payload = {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1,
                "model": requested["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": finish_reason,
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 3,
                    "total_tokens": 13,
                },
            }
            return TransportResponse(json.dumps(payload).encode("utf-8"), url)

        return transport

    def test_serving_profile_golden_bytes_match_cross_language_identity(self) -> None:
        golden_path = ROOT / "tests" / "fixtures" / "serving-profile.v1.golden.json"
        profile = load_serving_profile(golden_path)
        expected_sha256 = (
            "e3a16a70bfcf6a015c0d952a14f0740a99207f72e44dd618e45f949f40e8fb9f"
        )
        self.assertEqual(expected_sha256, profile.sha256)
        self.assertEqual(
            EXECUTION_MODEL_PREFIX + expected_sha256, profile.execution_model_id
        )
        self.assertEqual(
            SERVING_PROFILE_SCHEMA_VERSION, profile.document["schemaVersion"]
        )

        duplicate_path = self.root / "duplicate-profile.json"
        duplicate_path.write_text(
            golden_path.read_text(encoding="utf-8").replace(
                "{\n",
                '{\n  "profileId": "duplicate",\n',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValidationError, "duplicate object key"):
            load_serving_profile(duplicate_path)

    def test_model_readiness_proof_is_cross_language_and_hash_private(self) -> None:
        nonce = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
        profile_sha256 = "1" * 64
        proof = compute_model_readiness_proof(
            key=bytes(range(32)),
            audience="daxalgo-platform-prod",
            nonce=nonce,
            key_id="prod-hmac-v1",
            serving_profile_sha256=profile_sha256,
            artifact_sha256="2" * 64,
            artifact_tree_sha256="3" * 64,
            execution_model_id=EXECUTION_MODEL_PREFIX + profile_sha256,
        )
        self.assertEqual("viVWdrCNzGuzZm-mpZ6NExwnkWBqWvtUqXtnoJdFEqM", proof)

        fixture = self._serving_fixture(0, "attested-profile-v1")
        with self.assertRaisesRegex(ValidationError, "research-only artifacts"):
            create_model_readiness_attestation(
                profile_path=fixture["profile_path"],
                artifact_path=fixture["artifact_path"],
                manifest_path=fixture["manifest_path"],
                audience="daxalgo-platform-prod",
                nonce=nonce,
                key_id="prod-hmac-v1",
                key=bytes(range(32)),
            )

    def test_tasks_are_strict_homogeneous_and_hash_bound(self) -> None:
        path = self.root / "tasks.jsonl"
        task = _task("sealed-1", "sealed")
        _write_jsonl(path, task)
        self.assertEqual(1, len(validate_evaluation_tasks(path).records))
        bad = json.loads(json.dumps(task))
        bad["messages"].append({"role": "assistant", "content": "Leaked answer."})
        bad["promptSha256"] = evaluation_prompt_sha256(bad["messages"])
        bad["taskSha256"] = evaluation_task_sha256(bad)
        _write_jsonl(path, bad)
        with self.assertRaisesRegex(
            ValidationError, "final message must have role 'user'"
        ):
            validate_evaluation_tasks(path)

        _write_jsonl(path, _task("cal-1", "calibration"), _task("sealed-1", "sealed"))
        with self.assertRaisesRegex(ValidationError, "homogeneous"):
            self._capture(path, self.root / "mixed.jsonl", self._transport())

    def test_capture_catalog_request_secret_and_transport_guards(self) -> None:
        tasks = self.root / "sealed.jsonl"
        task = _task("sealed-1", "sealed")
        _write_jsonl(tasks, task)
        output = self.root / "responses.jsonl"
        observed: dict = {}

        def transport(url, headers, body, timeout, max_bytes):
            observed.update(headers=dict(headers), request=json.loads(body))
            return self._transport()(url, headers, body, timeout, max_bytes)

        self._capture(tasks, output, transport)
        response = validate_evaluation_responses(output, tasks)[0]
        self.assertTrue(response["researchOnly"])
        self.assertIsNone(response["dataRelease"])
        self.assertEqual("unpromoted-research", response["evidenceStatus"])
        fixture = self._serving_fixture(0, "deterministic-v1")
        self.assertEqual(
            hashlib.sha256(self.catalog_path.read_bytes()).hexdigest(),
            response["candidateCatalogSha256"],
        )
        self.assertEqual(
            fixture["profile"].sha256, response["servingProfile"]["sha256"]
        )
        self.assertEqual(
            fixture["profile"].document["profileId"], response["servingProfile"]["id"]
        )
        with mock.patch.dict(os.environ, {"VQ_TEST_KEY": "secret"}, clear=False):
            with self.assertRaisesRegex(
                ValidationError, "fully validated bound release"
            ):
                capture_openai_responses(
                    tasks_path=tasks,
                    catalog_path=self.catalog_path,
                    output_path=self.root / "missing-release.jsonl",
                    serving_profile_path=fixture["profile_path"],
                    training_artifact_path=fixture["artifact_path"],
                    training_manifest_path=fixture["manifest_path"],
                    run_id="eval-run-001",
                    base_url="http://127.0.0.1/v1",
                    api_key_env="VQ_TEST_KEY",
                    seed=17,
                    transport=transport,
                )
        self.assertEqual(
            fixture["profile"].execution_model_id, observed["request"]["model"]
        )
        self.assertTrue(observed["request"]["model"].startswith(EXECUTION_MODEL_PREFIX))
        self.assertNotIn(task["verifier"]["id"], json.dumps(observed["request"]))
        self.assertNotIn(task["contextPack"]["sha256"], json.dumps(observed["request"]))
        self.assertNotIn("top-secret-value", output.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._capture(tasks, output, transport)
        with self.assertRaisesRegex(ValidationError, "control characters"):
            self._capture(
                tasks,
                self.root / "bad-key.jsonl",
                transport,
                key="secret\nInjected: value",
            )
        with self.assertRaisesRegex(ValidationError, "visible ASCII"):
            self._capture(
                tasks, self.root / "unicode-key.jsonl", transport, key="s\u00ebcret"
            )
        with self.assertRaisesRegex(ValidationError, "loopback"):
            self._capture(
                tasks,
                self.root / "http.jsonl",
                transport,
                base_url="http://models.example/v1",
            )
        with self.assertRaisesRegex(ValidationError, "unbound research-only capture"):
            self._capture(
                tasks,
                self.root / "https-provider.jsonl",
                transport,
                base_url="https://models.example/v1",
            )

        def wrong_model(url, headers, body, timeout, max_bytes):
            payload = {
                "model": "different/model",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "x"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
            return TransportResponse(json.dumps(payload).encode(), url)

        with self.assertRaisesRegex(ValidationError, "requested model"):
            self._capture(tasks, self.root / "wrong-model.jsonl", wrong_model)
        with self.assertRaisesRegex(ValidationError, "non-empty"):
            self._capture(
                tasks, self.root / "empty-stop.jsonl", self._transport(content="")
            )

        response_limit = tasks.stat().st_size + 32
        with mock.patch.object(
            evaluation_module, "MAX_EVALUATION_BYTES", response_limit
        ):
            with self.assertRaisesRegex(ValidationError, "response output.*exceeds"):
                self._capture(tasks, self.root / "aggregate-limit.jsonl", transport)
        self.assertFalse((self.root / "aggregate-limit.jsonl").exists())
        fixture = self._serving_fixture(0, "deterministic-v1")
        mismatched_catalog = self.root / "mismatched-catalog.json"
        mismatched_catalog.write_bytes(self.catalog_path.read_bytes() + b" ")
        with mock.patch.dict(os.environ, {"VQ_TEST_KEY": "secret"}, clear=False):
            with self.assertRaisesRegex(
                ValidationError, "evaluation candidate catalog bytes"
            ):
                capture_openai_responses(
                    tasks_path=tasks,
                    catalog_path=mismatched_catalog,
                    output_path=self.root / "mismatch.jsonl",
                    serving_profile_path=fixture["profile_path"],
                    training_artifact_path=fixture["artifact_path"],
                    training_manifest_path=fixture["manifest_path"],
                    run_id="eval-run-001",
                    base_url="https://models.example/v1",
                    api_key_env="VQ_TEST_KEY",
                    seed=17,
                    transport=transport,
                )

    def test_serving_profile_is_strictly_bound_and_cli_validated(self) -> None:
        fixture = self._serving_fixture(0, "strict-profile-v1")
        loaded = load_serving_profile(fixture["profile_path"])
        self.assertEqual(
            SERVING_PROFILE_SCHEMA_VERSION, loaded.document["schemaVersion"]
        )
        self.assertEqual(
            fixture["artifact"]["artifactSha256"],
            loaded.document["trainingArtifact"]["artifactSha256"],
        )
        self.assertEqual(
            fixture["artifact"]["fileTreeSha256"],
            loaded.document["trainingArtifact"]["artifactTreeSha256"],
        )
        self.assertEqual(
            loaded,
            validate_serving_profile(
                fixture["profile_path"],
                artifact_path=fixture["artifact_path"],
                manifest_path=fixture["manifest_path"],
            ),
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(
                [
                    "validate-serving-profile",
                    str(fixture["profile_path"]),
                    "--artifact",
                    str(fixture["artifact_path"]),
                    "--manifest",
                    str(fixture["manifest_path"]),
                ]
            )
        result = json.loads(stdout.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(result["valid"])
        self.assertEqual(loaded.sha256, result["sha256"])
        self.assertEqual(loaded.execution_model_id, result["executionModelId"])

        adapter = fixture["artifact_path"] / "adapter_model.safetensors"
        adapter_bytes = adapter.read_bytes()
        adapter.write_bytes(adapter_bytes + b"tampered")
        with self.assertRaisesRegex(ValidationError, "safetensors"):
            validate_serving_profile(
                fixture["profile_path"],
                artifact_path=fixture["artifact_path"],
                manifest_path=fixture["manifest_path"],
            )
        adapter.write_bytes(adapter_bytes)

        schema = json.loads(
            (ROOT / "schemas" / "serving-profile.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            SERVING_PROFILE_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )

        relocated_artifact = self.root / "relocated-artifact"
        shutil.copytree(fixture["artifact_path"], relocated_artifact)
        validate_serving_profile(
            fixture["profile_path"],
            artifact_path=relocated_artifact,
            manifest_path=fixture["manifest_path"],
        )

        metadata_path = relocated_artifact / "artifact-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["mode"] = "smoke"
        metadata["reason"] = "Smoke mode cannot produce a production model."
        metadata["artifactSha256"] = training_artifact_sha256(metadata)
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "smoke artifacts"):
            create_serving_profile(
                profile_id="smoke-profile-v1",
                artifact_path=relocated_artifact,
                manifest_path=fixture["manifest_path"],
                output_path=self.root / "smoke-profile.json",
                engine="vllm",
                engine_version="0.10.0",
                container_image_digest="sha256:" + "6" * 64,
                quantization="bitsandbytes-nf4",
                compute_dtype="bfloat16",
                max_model_length=8_192,
                tensor_parallel_size=1,
                gpu_profile="l40s-48gb",
            )

        custom_code_artifact = self.root / "custom-code-artifact"
        shutil.copytree(fixture["artifact_path"], custom_code_artifact)
        custom_metadata_path = custom_code_artifact / "artifact-metadata.json"
        custom_metadata = json.loads(custom_metadata_path.read_text(encoding="utf-8"))
        custom_metadata_path.unlink()
        adapter_config_path = custom_code_artifact / "adapter_config.json"
        adapter_config = json.loads(adapter_config_path.read_text(encoding="utf-8"))
        adapter_config["auto_mapping"] = {"base_model_class": "unreviewed.CustomModel"}
        adapter_config_path.write_text(json.dumps(adapter_config), encoding="utf-8")
        seal_training_artifact(custom_code_artifact, custom_metadata)
        with self.assertRaisesRegex(ValidationError, "custom code mappings"):
            create_serving_profile(
                profile_id="custom-code-profile-v1",
                artifact_path=custom_code_artifact,
                manifest_path=fixture["manifest_path"],
                output_path=self.root / "custom-code-profile.json",
                engine="vllm",
                engine_version="0.10.0",
                container_image_digest="sha256:" + "6" * 64,
                quantization="bitsandbytes-nf4",
                compute_dtype="bfloat16",
                max_model_length=8_192,
                tensor_parallel_size=1,
                gpu_profile="l40s-48gb",
            )

        incompatible = json.loads(fixture["profile_path"].read_text(encoding="utf-8"))
        incompatible["runtime"]["maxModelLength"] = 32_769
        incompatible_path = self.root / "incompatible-profile.json"
        incompatible_path.write_text(json.dumps(incompatible), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "base-model capability"):
            validate_serving_profile(
                incompatible_path,
                artifact_path=fixture["artifact_path"],
                manifest_path=fixture["manifest_path"],
            )

    def _paired_fixture(
        self, *, candidate_finish: str = "stop", baseline_finish: str = "stop"
    ) -> dict:
        calibration_path = self.root / "calibration.jsonl"
        sealed_path = self.root / "sealed.jsonl"
        calibration_task = _task("calibration-1", "calibration")
        sealed_task = _task("sealed-1", "sealed", criticality="critical")
        _write_jsonl(calibration_path, calibration_task)
        _write_jsonl(sealed_path, sealed_task)
        candidate_responses = self.root / "candidate-responses.jsonl"
        baseline_responses = self.root / "baseline-responses.jsonl"
        self._capture(
            sealed_path,
            candidate_responses,
            self._transport(finish_reason=candidate_finish),
        )
        self._capture(
            sealed_path,
            baseline_responses,
            self._transport(finish_reason=baseline_finish),
            candidate_index=1,
            run_id="baseline-run-001",
            profile_id="baseline-deterministic-v1",
        )
        candidate_response = validate_evaluation_responses(
            candidate_responses, sealed_path
        )[0]
        baseline_response = validate_evaluation_responses(
            baseline_responses, sealed_path
        )[0]
        candidate_results = self.root / "candidate-results.jsonl"
        baseline_results = self.root / "baseline-results.jsonl"
        _write_jsonl(candidate_results, _result(sealed_task, candidate_response))
        _write_jsonl(baseline_results, _result(sealed_task, baseline_response))
        evidence_path = self.root / "calibration-evidence.json"
        evidence_path.write_bytes(b'{"reviewed":true}\n')
        calibration = validate_evaluation_tasks(calibration_path)
        sealed = validate_evaluation_tasks(sealed_path)
        policy = _policy(
            calibration.task_set_sha256,
            sealed.task_set_sha256,
            hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            _identity(candidate_response),
            _identity(baseline_response),
        )
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        return {
            "calibration_tasks_path": calibration_path,
            "calibration_evidence_path": evidence_path,
            "sealed_tasks_path": sealed_path,
            "responses_path": candidate_responses,
            "verifier_results_path": candidate_results,
            "baseline_responses_path": baseline_responses,
            "baseline_verifier_results_path": baseline_results,
            "policy_path": policy_path,
            "research_only": True,
        }

    def _bound_paired_fixture(
        self,
        *,
        provider: bool = False,
        csharp: bool = False,
        csharp_authority_path: Path | None = None,
        csharp_authority_trust: CSharpVerifierAuthorityTrust | None = None,
    ) -> dict:
        bound = self._bound_release_fixture(provider=provider, csharp=csharp)
        release_fixture = bound["fixture"]
        sealed_path = release_fixture.sealed_tasks
        candidate_responses = self.root / "bound-candidate-responses.jsonl"
        baseline_responses = self.root / "bound-baseline-responses.jsonl"
        capture_arguments = {
            "data_release_path": bound["release_path"],
            "sft_path": bound["sft_path"],
            "review_receipt_trust": bound["review_receipt_trust"],
            "evaluation_authoring_approval_trust": bound[
                "evaluation_authoring_approval_trust"
            ],
            "review_receipt_now": bound["review_receipt_now"],
            "research_only": False,
        }
        self._capture(
            sealed_path,
            candidate_responses,
            self._transport(),
            profile_id="bound-candidate-v1",
            **capture_arguments,
        )
        self._capture(
            sealed_path,
            baseline_responses,
            self._transport(),
            candidate_index=1,
            run_id="bound-baseline-run-001",
            profile_id="bound-baseline-v1",
            **capture_arguments,
        )
        candidate_response = validate_evaluation_responses(
            candidate_responses, sealed_path
        )[0]
        baseline_response = validate_evaluation_responses(
            baseline_responses, sealed_path
        )[0]
        candidate_results = self.root / "bound-candidate-results.jsonl"
        baseline_results = self.root / "bound-baseline-results.jsonl"
        verifier_arguments = {
            "tasks_path": sealed_path,
            "release_path": bound["release_path"],
            "review_receipt_trust": bound["review_receipt_trust"],
            "evaluation_authoring_approval_trust": bound[
                "evaluation_authoring_approval_trust"
            ],
            "review_receipt_now": bound["review_receipt_now"],
            "csharp_verifier_authority_path": csharp_authority_path,
            "csharp_verifier_authority_trust": csharp_authority_trust,
        }
        run_release_verifiers(
            responses_path=candidate_responses,
            output_path=candidate_results,
            **verifier_arguments,
        )
        run_release_verifiers(
            responses_path=baseline_responses,
            output_path=baseline_results,
            **verifier_arguments,
        )
        evidence_path = self.root / "bound-calibration-evidence.json"
        evidence_path.write_bytes(b'{"reviewed":true}\n')
        calibration = validate_evaluation_tasks(release_fixture.calibration_tasks)
        sealed = validate_evaluation_tasks(sealed_path)
        policy = _policy(
            calibration.task_set_sha256,
            sealed.task_set_sha256,
            hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            _identity(candidate_response),
            _identity(baseline_response),
            data_release=bound["release_identity"],
            research_only=False,
        )
        policy_path = self.root / "bound-policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        return {
            "inputs": {
                "calibration_tasks_path": release_fixture.calibration_tasks,
                "calibration_evidence_path": evidence_path,
                "sealed_tasks_path": sealed_path,
                "responses_path": candidate_responses,
                "verifier_results_path": candidate_results,
                "baseline_responses_path": baseline_responses,
                "baseline_verifier_results_path": baseline_results,
                "policy_path": policy_path,
                "data_release_path": bound["release_path"],
                "review_receipt_trust": bound["review_receipt_trust"],
                "evaluation_authoring_approval_trust": bound[
                    "evaluation_authoring_approval_trust"
                ],
                "review_receipt_now": bound["review_receipt_now"],
            },
            "bound": bound,
            "candidate_response": candidate_response,
            "baseline_response": baseline_response,
        }

    def test_release_bound_capture_and_promotion_aggregation_end_to_end(self) -> None:
        fixture = self._bound_paired_fixture()
        bound = fixture["bound"]
        for response in (
            fixture["candidate_response"],
            fixture["baseline_response"],
        ):
            self.assertEqual(bound["release_identity"], response["dataRelease"])
            self.assertFalse(response["researchOnly"])
            self.assertEqual("release-bound", response["evidenceStatus"])

        report = aggregate_promotion_evidence(**fixture["inputs"])
        self.assertEqual(bound["release_identity"], report["dataRelease"])
        self.assertFalse(report["researchOnly"])
        self.assertEqual("release-bound", report["evidenceStatus"])
        self.assertTrue(report["allEvidenceGatesPassed"])
        self.assertTrue(report["eligibleForPromotionReview"])
        report_path = self.root / "bound-report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual(report, validate_promotion_evidence(report_path))

        missing_trust = dict(fixture["inputs"])
        missing_trust.pop("review_receipt_trust")
        with self.assertRaisesRegex(ValidationError, "required for release-bound"):
            aggregate_promotion_evidence(**missing_trust)

        missing_authoring_trust = dict(fixture["inputs"])
        missing_authoring_trust.pop("evaluation_authoring_approval_trust")
        with self.assertRaisesRegex(
            ValidationError, "evaluation-authoring approval trust"
        ):
            aggregate_promotion_evidence(**missing_authoring_trust)

        expired_trust = dict(fixture["inputs"])
        expired_trust["review_receipt_now"] = datetime(
            2026, 1, 20, 12, 0, 2, tzinfo=timezone.utc
        )
        with self.assertRaisesRegex(ValidationError, "not currently active"):
            aggregate_promotion_evidence(**expired_trust)

        trust = bound["review_receipt_trust"]
        wrong_trust = type(trust)(
            public_key_path=trust.public_key_path,
            public_key_spki_sha256=trust.public_key_spki_sha256,
            audience="wrong-evaluation-audience",
            key_id=trust.key_id,
            signer_role=trust.signer_role,
        )
        wrong_identity = dict(fixture["inputs"])
        wrong_identity["review_receipt_trust"] = wrong_trust
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            aggregate_promotion_evidence(**wrong_identity)

        authoring_trust = bound["evaluation_authoring_approval_trust"]
        wrong_authoring = type(authoring_trust)(
            public_key_path=authoring_trust.public_key_path,
            public_key_spki_sha256=authoring_trust.public_key_spki_sha256,
            audience="wrong-authoring-audience",
            key_id=authoring_trust.key_id,
            signer_role=authoring_trust.signer_role,
        )
        wrong_authoring_identity = dict(fixture["inputs"])
        wrong_authoring_identity["evaluation_authoring_approval_trust"] = (
            wrong_authoring
        )
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            aggregate_promotion_evidence(**wrong_authoring_identity)

        serving = self._serving_fixture(
            0,
            "bound-candidate-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=trust,
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        with self.assertRaisesRegex(
            ValidationError, "required for release-bound capture"
        ):
            capture_openai_responses(
                tasks_path=bound["fixture"].sealed_tasks,
                catalog_path=self.catalog_path,
                output_path=self.root / "missing-trust.responses.jsonl",
                serving_profile_path=serving["profile_path"],
                training_artifact_path=serving["artifact_path"],
                training_manifest_path=serving["manifest_path"],
                run_id="missing-trust-run",
                base_url="http://127.0.0.1/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=bound["release_path"],
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                research_only=False,
            )
        with self.assertRaisesRegex(
            ValidationError, "evaluation-authoring approval trust"
        ):
            capture_openai_responses(
                tasks_path=bound["fixture"].sealed_tasks,
                catalog_path=self.catalog_path,
                output_path=self.root / "missing-authoring-trust.responses.jsonl",
                serving_profile_path=serving["profile_path"],
                training_artifact_path=serving["artifact_path"],
                training_manifest_path=serving["manifest_path"],
                run_id="missing-authoring-trust-run",
                base_url="http://127.0.0.1/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=bound["release_path"],
                review_receipt_trust=trust,
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                research_only=False,
            )

    def _detached_csharp_replay_fixture(self) -> dict:
        try:
            runtime_tests = importlib.import_module("test_verifier_runtime")
        except ModuleNotFoundError:
            runtime_tests = importlib.import_module("tests.test_verifier_runtime")
        authority = runtime_tests._authority("1")
        authority_trust = CSharpVerifierAuthorityTrust(
            self.root / "authority-public.pem",
            "e" * 64,
            "verifier-audience",
            "verifier-key",
            "verifier-authority",
        )
        authority_path = self.root / "authority.json"
        workspace = self.root / "detached-audit-work"
        workspace.mkdir()
        context = CSharpVerifierExecutionContext(
            authority_path, authority_trust, workspace
        )
        with self._mock_csharp_replay(authority, runtime_tests):
            fixture = self._bound_paired_fixture(
                csharp=True,
                csharp_authority_path=authority_path,
                csharp_authority_trust=authority_trust,
            )
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_key_path = self.root / "detached-audit-private.pem"
        public_key_path = self.root / "detached-audit-public.pem"
        private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = hashlib.sha256(
            private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        trust = CSharpVerifierReplayAuditTrust(
            public_key_path,
            spki,
            "promotion-replay-audience",
            "promotion-replay-key-v1",
            "promotion-replay-auditor",
        )
        live = {
            "trust": trust,
            "sealed_tasks_path": fixture["inputs"]["sealed_tasks_path"],
            "candidate_responses_path": fixture["inputs"]["responses_path"],
            "candidate_results_path": fixture["inputs"]["verifier_results_path"],
            "baseline_responses_path": fixture["inputs"]["baseline_responses_path"],
            "baseline_results_path": fixture["inputs"][
                "baseline_verifier_results_path"
            ],
            "data_release_path": fixture["inputs"]["data_release_path"],
            "review_receipt_trust": fixture["inputs"]["review_receipt_trust"],
            "evaluation_authoring_approval_trust": fixture["inputs"][
                "evaluation_authoring_approval_trust"
            ],
            "csharp_verifier_context": context,
            "review_receipt_now": fixture["inputs"]["review_receipt_now"],
            "now": fixture["inputs"]["review_receipt_now"],
        }
        decision = {
            "approval_id": "AUDIT-DETACHED-1",
            "actor_id": "independent-auditor",
            "actor_role": trust.signer_role,
            "approval_reference": "audit://AUDIT-DETACHED-1",
            "approved_at_utc": "2025-02-01T00:00:00Z",
            "replay_completed_at_utc": "2025-02-01T00:00:00Z",
            "issued_at_utc": "2025-02-01T00:00:00Z",
            "not_before_utc": "2025-02-01T00:00:00Z",
            "expires_at_utc": "2026-01-01T00:00:00Z",
        }
        return {
            "runtime_tests": runtime_tests,
            "authority": authority,
            "fixture": fixture,
            "private_key": private_key,
            "private_key_path": private_key_path,
            "public_key_path": public_key_path,
            "trust": trust,
            "live": live,
            "decision": decision,
        }

    @contextmanager
    def _mock_csharp_replay(self, authority, runtime_tests):
        with (
            mock.patch.object(
                verifier_runtime_module,
                "validate_csharp_verifier_authority",
                return_value=authority,
            ),
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=runtime_tests._fake_csharp_runner(authority, {}),
            ),
        ):
            yield

    def _write_detached_replay_signature(
        self,
        material: dict,
        bundle: dict,
        name: str,
        *,
        mode: str,
        signature_format: str,
        private_key=None,
        signing_behavior: str | None = None,
        force_high_s: bool = False,
    ) -> Path:
        request = bundle["request"]
        preimage = replay_audit_module._base64url_decode(
            request["signaturePreimage"], "test replay signature preimage", 1_000_000
        )
        digest = replay_audit_module._base64url_decode(
            request["signatureInput"], "test replay signature input", 32
        )
        key = private_key or material["private_key"]
        behavior = signing_behavior or mode
        if behavior == replay_audit_module.AUDIT_EXTERNAL_RAW_MESSAGE_MODE:
            der = key.sign(preimage, ec.ECDSA(hashes.SHA256()))
        elif behavior == replay_audit_module.AUDIT_EXTERNAL_SHA256_DIGEST_MODE:
            der = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif behavior == "double-hashed-digest":
            der = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported signing behavior")
        r, s = decode_dss_signature(der)
        order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        if force_high_s and s <= order // 2:
            s = order - s
        if signature_format == replay_audit_module.AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT:
            signature = encode_dss_signature(r, s)
        elif (
            signature_format
            == replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT
        ):
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported signature format")
        document = replay_audit_module._build_external_signature_document(
            bundle,
            signature_mode=mode,
            signature_format=signature_format,
            signature=signature,
        )
        path = self.root / f"{name}.signature.json"
        path.write_bytes(canonical_json_bytes(document) + b"\n")
        return path

    def test_signed_csharp_replay_audit_allows_only_docker_free_exact_aggregation(
        self,
    ) -> None:
        try:
            runtime_tests = importlib.import_module("test_verifier_runtime")
        except ModuleNotFoundError:
            runtime_tests = importlib.import_module("tests.test_verifier_runtime")
        authority = runtime_tests._authority("1")
        authority_trust = CSharpVerifierAuthorityTrust(
            self.root / "authority-public.pem",
            "e" * 64,
            "verifier-audience",
            "verifier-key",
            "verifier-authority",
        )
        authority_path = self.root / "authority.json"
        audit_workspace = self.root / "audit-work"
        audit_workspace.mkdir()
        context = CSharpVerifierExecutionContext(
            authority_path, authority_trust, audit_workspace
        )
        with (
            mock.patch.object(
                verifier_runtime_module,
                "validate_csharp_verifier_authority",
                return_value=authority,
            ),
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=runtime_tests._fake_csharp_runner(authority, {}),
            ),
        ):
            fixture = self._bound_paired_fixture(
                csharp=True,
                csharp_authority_path=authority_path,
                csharp_authority_trust=authority_trust,
            )

        private_key = ec.generate_private_key(ec.SECP256R1())
        private_key_path = self.root / "audit-private.pem"
        public_key_path = self.root / "audit-public.pem"
        private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        public_spki_sha256 = hashlib.sha256(
            private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        audit_path = self.root / "csharp-replay-audit.json"
        with (
            mock.patch.object(
                verifier_runtime_module,
                "validate_csharp_verifier_authority",
                return_value=authority,
            ),
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=runtime_tests._fake_csharp_runner(authority, {}),
            ),
        ):
            audit = create_csharp_verifier_replay_audit(
                output_path=audit_path,
                private_key_path=private_key_path,
                public_key_path=public_key_path,
                public_key_spki_sha256=public_spki_sha256,
                private_key_password=None,
                audience="promotion-replay-audience",
                key_id="promotion-replay-key-v1",
                signer_role="promotion-replay-auditor",
                approval_id="AUDIT-TEST-1",
                actor_id="independent-auditor",
                actor_role="promotion-replay-auditor",
                approval_reference="audit://AUDIT-TEST-1",
                approved_at_utc="2025-02-01T00:00:00Z",
                replay_completed_at_utc="2025-02-01T00:00:00Z",
                issued_at_utc="2025-02-01T00:00:00Z",
                not_before_utc="2025-02-01T00:00:00Z",
                expires_at_utc="2026-01-01T00:00:00Z",
                sealed_tasks_path=fixture["inputs"]["sealed_tasks_path"],
                candidate_responses_path=fixture["inputs"]["responses_path"],
                candidate_results_path=fixture["inputs"]["verifier_results_path"],
                baseline_responses_path=fixture["inputs"]["baseline_responses_path"],
                baseline_results_path=fixture["inputs"][
                    "baseline_verifier_results_path"
                ],
                data_release_path=fixture["inputs"]["data_release_path"],
                review_receipt_trust=fixture["inputs"]["review_receipt_trust"],
                evaluation_authoring_approval_trust=fixture["inputs"][
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=fixture["inputs"]["review_receipt_now"],
                csharp_verifier_context=context,
                now=fixture["inputs"]["review_receipt_now"],
            )
        audit_trust = CSharpVerifierReplayAuditTrust(
            public_key_path,
            public_spki_sha256,
            "promotion-replay-audience",
            "promotion-replay-key-v1",
            "promotion-replay-auditor",
        )
        audited_inputs = {
            **fixture["inputs"],
            "csharp_verifier_replay_audit_path": audit_path,
            "csharp_verifier_replay_audit_trust": audit_trust,
            "expected_csharp_verifier_replay_audit_envelope_sha256": (
                audit.envelope_sha256
            ),
            "csharp_verifier_replay_audit_now": fixture["inputs"]["review_receipt_now"],
        }
        with mock.patch.object(
            verifier_runtime_module,
            "execute_release_verifiers",
            side_effect=AssertionError("production aggregation reached Docker replay"),
        ) as full_replay:
            report = aggregate_promotion_evidence(**audited_inputs)
        full_replay.assert_not_called()
        self.assertTrue(report["eligibleForPromotionReview"])

        for name, mutation, message in (
            (
                "wrong-envelope",
                {"expected_csharp_verifier_replay_audit_envelope_sha256": "0" * 64},
                "exact SHA-256",
            ),
            (
                "missing-audit",
                {
                    "csharp_verifier_replay_audit_path": None,
                    "csharp_verifier_replay_audit_trust": None,
                    "expected_csharp_verifier_replay_audit_envelope_sha256": None,
                    "csharp_verifier_replay_audit_now": None,
                },
                "execution context",
            ),
            (
                "live-and-audit",
                {"csharp_verifier_context": context},
                "mutually exclusive",
            ),
        ):
            with self.subTest(name=name):
                changed = {**audited_inputs, **mutation}
                with self.assertRaisesRegex(ValidationError, message):
                    aggregate_promotion_evidence(**changed)

        wrong_trust = CSharpVerifierReplayAuditTrust(
            public_key_path,
            public_spki_sha256,
            "wrong-audience",
            "promotion-replay-key-v1",
            "promotion-replay-auditor",
        )
        with self.assertRaisesRegex(ValidationError, "trusted configuration"):
            aggregate_promotion_evidence(
                **{**audited_inputs, "csharp_verifier_replay_audit_trust": wrong_trust}
            )
        with self.assertRaisesRegex(ValidationError, "not active"):
            aggregate_promotion_evidence(
                **{
                    **audited_inputs,
                    "csharp_verifier_replay_audit_now": datetime(
                        2026, 1, 2, tzinfo=timezone.utc
                    ),
                }
            )

        envelope = json.loads(audit_path.read_text(encoding="utf-8"))
        signature = replay_audit_module._base64url_decode(
            envelope["signature"], "test signature", 64
        )
        order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        high_s = order - int.from_bytes(signature[32:], "big")
        envelope["signature"] = replay_audit_module._base64url_encode(
            signature[:32] + high_s.to_bytes(32, "big")
        )
        high_s_path = self.root / "high-s-replay-audit.json"
        high_s_path.write_bytes(canonical_json_bytes(envelope) + b"\n")
        with self.assertRaisesRegex(ValidationError, "low-S"):
            aggregate_promotion_evidence(
                **{
                    **audited_inputs,
                    "csharp_verifier_replay_audit_path": high_s_path,
                    "expected_csharp_verifier_replay_audit_envelope_sha256": hashlib.sha256(
                        canonical_json_bytes(envelope)
                    ).hexdigest(),
                }
            )

        future_envelope = json.loads(audit_path.read_text(encoding="utf-8"))
        future_payload = json.loads(
            replay_audit_module._base64url_decode(
                future_envelope["payload"], "test payload", 750_000
            )
        )
        future_payload["replayCompletedAtUtc"] = "2025-03-01T00:00:00Z"
        future_payload["approval"]["approvedAtUtc"] = "2025-03-01T00:00:00Z"
        future_payload["issuedAtUtc"] = "2025-03-01T00:00:00Z"
        future_payload["auditId"] = replay_audit_module.csharp_verifier_replay_audit_id(
            future_payload
        )
        future_payload_bytes = canonical_json_bytes(future_payload)
        future_envelope["payload"] = replay_audit_module._base64url_encode(
            future_payload_bytes
        )
        future_envelope["payloadSha256"] = hashlib.sha256(
            future_payload_bytes
        ).hexdigest()
        future_envelope["signature"] = ""
        future_envelope["signature"] = replay_audit_module._base64url_encode(
            replay_audit_module._sign_p1363_low_s(
                private_key,
                replay_audit_module._signature_input(
                    future_envelope, future_payload_bytes
                ),
            )
        )
        future_path = self.root / "future-issued-replay-audit.json"
        future_path.write_bytes(canonical_json_bytes(future_envelope) + b"\n")
        with self.assertRaisesRegex(ValidationError, "invalid bounded window"):
            aggregate_promotion_evidence(
                **{
                    **audited_inputs,
                    "csharp_verifier_replay_audit_path": future_path,
                    "expected_csharp_verifier_replay_audit_envelope_sha256": hashlib.sha256(
                        canonical_json_bytes(future_envelope)
                    ).hexdigest(),
                }
            )

        forged_envelope = json.loads(audit_path.read_text(encoding="utf-8"))
        payload = json.loads(
            replay_audit_module._base64url_decode(
                forged_envelope["payload"], "test payload", 750_000
            )
        )
        payload["candidate"], payload["baseline"] = (
            payload["baseline"],
            payload["candidate"],
        )
        payload["auditId"] = replay_audit_module.csharp_verifier_replay_audit_id(
            payload
        )
        payload_bytes = canonical_json_bytes(payload)
        forged_envelope["payload"] = replay_audit_module._base64url_encode(
            payload_bytes
        )
        forged_envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        forged_envelope["signature"] = ""
        forged_envelope["signature"] = replay_audit_module._base64url_encode(
            replay_audit_module._sign_p1363_low_s(
                private_key,
                replay_audit_module._signature_input(forged_envelope, payload_bytes),
            )
        )
        forged_path = self.root / "swapped-replay-audit.json"
        forged_path.write_bytes(canonical_json_bytes(forged_envelope) + b"\n")
        with self.assertRaisesRegex(ValidationError, "exact live evidence"):
            aggregate_promotion_evidence(
                **{
                    **audited_inputs,
                    "csharp_verifier_replay_audit_path": forged_path,
                    "expected_csharp_verifier_replay_audit_envelope_sha256": hashlib.sha256(
                        canonical_json_bytes(forged_envelope)
                    ).hexdigest(),
                }
            )

        raced_output = self.root / "raced-replay-audit.json"
        candidate_responses_path = Path(fixture["inputs"]["responses_path"])
        expected_binding = replay_audit_module.expected_csharp_verifier_replay_binding

        def mutate_after_binding(**kwargs):
            binding = expected_binding(**kwargs)
            candidate_responses_path.write_bytes(
                candidate_responses_path.read_bytes() + b" "
            )
            return binding

        with (
            mock.patch.object(
                verifier_runtime_module,
                "validate_csharp_verifier_authority",
                return_value=authority,
            ),
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=runtime_tests._fake_csharp_runner(authority, {}),
            ),
            mock.patch.object(
                replay_audit_module,
                "expected_csharp_verifier_replay_binding",
                side_effect=mutate_after_binding,
            ),
            self.assertRaisesRegex(ValidationError, "changed during"),
        ):
            create_csharp_verifier_replay_audit(
                output_path=raced_output,
                private_key_path=private_key_path,
                public_key_path=public_key_path,
                public_key_spki_sha256=public_spki_sha256,
                private_key_password=None,
                audience="promotion-replay-audience",
                key_id="promotion-replay-key-v1",
                signer_role="promotion-replay-auditor",
                approval_id="AUDIT-TEST-RACE",
                actor_id="independent-auditor",
                actor_role="promotion-replay-auditor",
                approval_reference="audit://AUDIT-TEST-RACE",
                approved_at_utc="2025-02-01T00:00:00Z",
                replay_completed_at_utc="2025-02-01T00:00:00Z",
                issued_at_utc="2025-02-01T00:00:00Z",
                not_before_utc="2025-02-01T00:00:00Z",
                expires_at_utc="2026-01-01T00:00:00Z",
                sealed_tasks_path=fixture["inputs"]["sealed_tasks_path"],
                candidate_responses_path=candidate_responses_path,
                candidate_results_path=fixture["inputs"]["verifier_results_path"],
                baseline_responses_path=fixture["inputs"]["baseline_responses_path"],
                baseline_results_path=fixture["inputs"][
                    "baseline_verifier_results_path"
                ],
                data_release_path=fixture["inputs"]["data_release_path"],
                review_receipt_trust=fixture["inputs"]["review_receipt_trust"],
                evaluation_authoring_approval_trust=fixture["inputs"][
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=fixture["inputs"]["review_receipt_now"],
                csharp_verifier_context=context,
                now=fixture["inputs"]["review_receipt_now"],
            )
        self.assertFalse(raced_output.exists())

    def test_detached_replay_audit_preserves_wire_modes_and_downstream_consumption(
        self,
    ) -> None:
        material = self._detached_csharp_replay_fixture()
        live = {key: value for key, value in material["live"].items() if key != "trust"}
        direct_path = self.root / "direct-replay-audit.json"
        with self._mock_csharp_replay(material["authority"], material["runtime_tests"]):
            direct = create_csharp_verifier_replay_audit(
                output_path=direct_path,
                private_key_path=material["private_key_path"],
                public_key_path=material["public_key_path"],
                public_key_spki_sha256=material["trust"].public_key_spki_sha256,
                private_key_password=None,
                audience=material["trust"].audience,
                key_id=material["trust"].key_id,
                signer_role=material["trust"].signer_role,
                **material["decision"],
                **live,
            )
        bundle_path = self.root / "replay-audit.signing-bundle.json"
        with self._mock_csharp_replay(material["authority"], material["runtime_tests"]):
            prepared = prepare_csharp_verifier_replay_audit_signing_bundle(
                output_path=bundle_path,
                trust=material["trust"],
                **material["decision"],
                **live,
            )
            verified_bundle = verify_csharp_verifier_replay_audit_signing_bundle(
                bundle_path,
                trust=material["trust"],
                **live,
            )
        self.assertEqual(prepared.bundle_id, verified_bundle.bundle_id)
        self.assertEqual(direct.payload, prepared.payload)

        direct_envelope = json.loads(direct_path.read_text(encoding="utf-8"))
        direct_signature = replay_audit_module._base64url_decode(
            direct_envelope["signature"], "direct replay-audit signature", 64
        )
        exact_signature = replay_audit_module._build_external_signature_document(
            prepared.bundle,
            signature_mode=replay_audit_module.AUDIT_EXTERNAL_RAW_MESSAGE_MODE,
            signature_format=(
                replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT
            ),
            signature=direct_signature,
        )
        exact_signature_path = self.root / "exact-replay.signature.json"
        exact_signature_path.write_bytes(canonical_json_bytes(exact_signature) + b"\n")
        exact_path = self.root / "exact-detached-replay-audit.json"
        with (
            self._mock_csharp_replay(material["authority"], material["runtime_tests"]),
            mock.patch.object(
                replay_audit_module,
                "_load_private_key",
                side_effect=AssertionError("detached APIs must not load a private key"),
            ),
        ):
            exact = finalize_csharp_verifier_replay_audit(
                signing_bundle_path=bundle_path,
                signature_path=exact_signature_path,
                output_path=exact_path,
                trust=material["trust"],
                **live,
            )
        self.assertEqual(direct_path.read_bytes(), exact_path.read_bytes())
        self.assertEqual(direct.payload, exact.payload)

        for name, mode, signature_format in (
            (
                "raw-der-high-s",
                replay_audit_module.AUDIT_EXTERNAL_RAW_MESSAGE_MODE,
                replay_audit_module.AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT,
            ),
            (
                "digest-p1363-high-s",
                replay_audit_module.AUDIT_EXTERNAL_SHA256_DIGEST_MODE,
                replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ),
        ):
            with self.subTest(name=name):
                signature_path = self._write_detached_replay_signature(
                    material,
                    prepared.bundle,
                    name,
                    mode=mode,
                    signature_format=signature_format,
                    force_high_s=True,
                )
                output = self.root / f"{name}.replay-audit.json"
                with self._mock_csharp_replay(
                    material["authority"], material["runtime_tests"]
                ):
                    finalized = finalize_csharp_verifier_replay_audit(
                        signing_bundle_path=bundle_path,
                        signature_path=signature_path,
                        output_path=output,
                        trust=material["trust"],
                        **live,
                    )
                envelope = json.loads(output.read_text(encoding="utf-8"))
                normalized = replay_audit_module._base64url_decode(
                    envelope["signature"], "normalized replay-audit signature", 64
                )
                self.assertLessEqual(
                    int.from_bytes(normalized[32:], "big"),
                    int(
                        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                        16,
                    )
                    // 2,
                )
                self.assertEqual(direct.payload, finalized.payload)

        audited_inputs = {
            **material["fixture"]["inputs"],
            "csharp_verifier_replay_audit_path": exact_path,
            "csharp_verifier_replay_audit_trust": material["trust"],
            "expected_csharp_verifier_replay_audit_envelope_sha256": (
                exact.envelope_sha256
            ),
            "csharp_verifier_replay_audit_now": material["live"]["now"],
        }
        with mock.patch.object(
            verifier_runtime_module,
            "execute_release_verifiers",
            side_effect=AssertionError("downstream aggregation reached Docker replay"),
        ) as full_replay:
            report = aggregate_promotion_evidence(**audited_inputs)
        full_replay.assert_not_called()
        self.assertTrue(report["eligibleForPromotionReview"])

        import jsonschema

        schema_root = ROOT / "schemas"
        bundle_schema = json.loads(
            (
                schema_root
                / "csharp-verifier-replay-audit-signing-bundle.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        signature_schema = json.loads(
            (
                schema_root / "csharp-verifier-replay-audit-signature.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        for schema in (bundle_schema, signature_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(bundle_schema).validate(prepared.bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(exact_signature)

        for exported in (
            "CSHARP_VERIFIER_REPLAY_AUDIT_SIGNING_BUNDLE_SCHEMA_VERSION",
            "CSHARP_VERIFIER_REPLAY_AUDIT_SIGNATURE_SCHEMA_VERSION",
            "VerifiedCSharpVerifierReplayAuditSigningBundle",
            "csharp_verifier_replay_audit_signing_bundle_id",
            "csharp_verifier_replay_audit_external_signature_id",
            "prepare_csharp_verifier_replay_audit_signing_bundle",
            "verify_csharp_verifier_replay_audit_signing_bundle",
            "finalize_csharp_verifier_replay_audit",
        ):
            self.assertIn(exported, hyperion_model_package.__all__)
            self.assertTrue(hasattr(hyperion_model_package, exported))

    def test_detached_replay_audit_rejects_signature_bundle_and_live_drift(
        self,
    ) -> None:
        material = self._detached_csharp_replay_fixture()
        live = {key: value for key, value in material["live"].items() if key != "trust"}
        bundle_path = self.root / "adversarial-replay.signing-bundle.json"
        with self._mock_csharp_replay(material["authority"], material["runtime_tests"]):
            prepared = prepare_csharp_verifier_replay_audit_signing_bundle(
                output_path=bundle_path,
                trust=material["trust"],
                **material["decision"],
                **live,
            )
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_signature = self._write_detached_replay_signature(
            material,
            prepared.bundle,
            "wrong-key",
            mode=replay_audit_module.AUDIT_EXTERNAL_RAW_MESSAGE_MODE,
            signature_format=replay_audit_module.AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT,
            private_key=wrong_key,
        )
        double_hash_signature = self._write_detached_replay_signature(
            material,
            prepared.bundle,
            "double-hash",
            mode=replay_audit_module.AUDIT_EXTERNAL_SHA256_DIGEST_MODE,
            signature_format=replay_audit_module.AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT,
            signing_behavior="double-hashed-digest",
        )
        for name, signature_path in (
            ("wrong-key", wrong_signature),
            ("double-hash", double_hash_signature),
        ):
            with (
                self.subTest(name=name),
                mock.patch.object(
                    verifier_runtime_module,
                    "run_csharp_strategy_verification",
                    side_effect=AssertionError(
                        "invalid signature reached Docker replay"
                    ),
                ) as replay,
                self.assertRaisesRegex(ValidationError, "does not verify"),
            ):
                finalize_csharp_verifier_replay_audit(
                    signing_bundle_path=bundle_path,
                    signature_path=signature_path,
                    output_path=self.root / f"{name}.audit.json",
                    trust=material["trust"],
                    **live,
                )
            replay.assert_not_called()

        order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        for name, signature_format, raw in (
            (
                "malformed-der",
                replay_audit_module.AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT,
                b"\x30\x00",
            ),
            (
                "zero-p1363",
                replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT,
                b"\x00" * 64,
            ),
            (
                "short-p1363",
                replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT,
                b"\x01" * 63,
            ),
            (
                "r-at-order",
                replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT,
                order.to_bytes(32, "big") + (1).to_bytes(32, "big"),
            ),
        ):
            with self.subTest(name=name):
                document = replay_audit_module._build_external_signature_document(
                    prepared.bundle,
                    signature_mode=(
                        replay_audit_module.AUDIT_EXTERNAL_RAW_MESSAGE_MODE
                    ),
                    signature_format=signature_format,
                    signature=raw,
                )
                with self.assertRaises(ValidationError):
                    replay_audit_module._validate_external_signature_document(
                        document,
                        signing_bundle=prepared,
                        public_key=material["private_key"].public_key(),
                    )

        tampered = copy.deepcopy(prepared.bundle)
        tampered["authority"]["review"] = 0
        tampered["bundleId"] = (
            replay_audit_module.csharp_verifier_replay_audit_signing_bundle_id(tampered)
        )
        tampered_path = self.root / "numeric-authority.signing-bundle.json"
        tampered_path.write_bytes(canonical_json_bytes(tampered) + b"\n")
        with (
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=AssertionError("invalid bundle reached Docker replay"),
            ) as replay,
            self.assertRaisesRegex(ValidationError, "only false"),
        ):
            verify_csharp_verifier_replay_audit_signing_bundle(
                tampered_path,
                trust=material["trust"],
                **live,
            )
        replay.assert_not_called()

        wrong_trust = CSharpVerifierReplayAuditTrust(
            material["public_key_path"],
            material["trust"].public_key_spki_sha256,
            "wrong-audience",
            material["trust"].key_id,
            material["trust"].signer_role,
        )
        with (
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=AssertionError("wrong trust reached Docker replay"),
            ) as replay,
            self.assertRaisesRegex(ValidationError, "externally pinned trust"),
        ):
            verify_csharp_verifier_replay_audit_signing_bundle(
                bundle_path,
                trust=wrong_trust,
                **live,
            )
        replay.assert_not_called()
        with (
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=AssertionError("expired bundle reached Docker replay"),
            ) as replay,
            self.assertRaisesRegex(ValidationError, "active"),
        ):
            verify_csharp_verifier_replay_audit_signing_bundle(
                bundle_path,
                trust=material["trust"],
                **{**live, "now": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            )
        replay.assert_not_called()

        signature_path = self._write_detached_replay_signature(
            material,
            prepared.bundle,
            "valid-drift",
            mode=replay_audit_module.AUDIT_EXTERNAL_SHA256_DIGEST_MODE,
            signature_format=replay_audit_module.AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT,
        )
        candidate_path = Path(live["candidate_responses_path"])
        original = candidate_path.read_bytes()
        candidate_path.write_bytes(original + b" ")
        try:
            with (
                self._mock_csharp_replay(
                    material["authority"], material["runtime_tests"]
                ),
                self.assertRaises(ValidationError),
            ):
                finalize_csharp_verifier_replay_audit(
                    signing_bundle_path=bundle_path,
                    signature_path=signature_path,
                    output_path=self.root / "drift.audit.json",
                    trust=material["trust"],
                    **live,
                )
        finally:
            candidate_path.write_bytes(original)

        occupied = self.root / "occupied-replay-audit.json"
        occupied.write_bytes(b"competing writer\n")
        with (
            self._mock_csharp_replay(material["authority"], material["runtime_tests"]),
            self.assertRaisesRegex(ValidationError, "already exists"),
        ):
            finalize_csharp_verifier_replay_audit(
                signing_bundle_path=bundle_path,
                signature_path=signature_path,
                output_path=occupied,
                trust=material["trust"],
                **live,
            )
        self.assertEqual(b"competing writer\n", occupied.read_bytes())

        for function in (
            prepare_csharp_verifier_replay_audit_signing_bundle,
            verify_csharp_verifier_replay_audit_signing_bundle,
            finalize_csharp_verifier_replay_audit,
        ):
            parameters = inspect.signature(function).parameters
            self.assertNotIn("private_key_path", parameters)
            self.assertNotIn("private_key_password", parameters)

    def test_detached_replay_audit_rejects_recursive_json_and_signed_size_overflow(
        self,
    ) -> None:
        material = self._detached_csharp_replay_fixture()
        live = {key: value for key, value in material["live"].items() if key != "trust"}
        bundle_path = self.root / "bounded-replay.signing-bundle.json"
        with self._mock_csharp_replay(material["authority"], material["runtime_tests"]):
            prepared = prepare_csharp_verifier_replay_audit_signing_bundle(
                output_path=bundle_path,
                trust=material["trust"],
                **material["decision"],
                **live,
            )

        recursive_json = b"[" * 5_000 + b"0" + b"]" * 5_000
        recursive_bundle = copy.deepcopy(prepared.bundle)
        recursive_bundle["payload"] = replay_audit_module._base64url_encode(
            recursive_json
        )
        recursive_bundle_path = self.root / "recursive-replay.signing-bundle.json"
        recursive_bundle_path.write_bytes(
            canonical_json_bytes(recursive_bundle) + b"\n"
        )
        with (
            mock.patch.object(
                verifier_runtime_module,
                "run_csharp_strategy_verification",
                side_effect=AssertionError("recursive JSON reached Docker replay"),
            ) as replay,
            self.assertRaisesRegex(ValidationError, "invalid JSON"),
        ):
            verify_csharp_verifier_replay_audit_signing_bundle(
                recursive_bundle_path,
                trust=material["trust"],
                **live,
            )
        replay.assert_not_called()

        recursive_envelope = copy.deepcopy(prepared.unsigned_envelope)
        recursive_envelope["payloadSha256"] = hashlib.sha256(recursive_json).hexdigest()
        recursive_envelope["payload"] = replay_audit_module._base64url_encode(
            recursive_json
        )
        recursive_envelope_path = self.root / "recursive-replay.audit.json"
        recursive_envelope_bytes = canonical_json_bytes(recursive_envelope)
        recursive_envelope_path.write_bytes(recursive_envelope_bytes + b"\n")
        with self.assertRaisesRegex(ValidationError, "invalid JSON"):
            replay_audit_module.validate_csharp_verifier_replay_audit(
                recursive_envelope_path,
                trust=material["trust"],
                expected_envelope_sha256=hashlib.sha256(
                    recursive_envelope_bytes
                ).hexdigest(),
                now=material["live"]["now"],
            )

        oversized_payload = copy.deepcopy(prepared.payload)
        binding = oversized_payload["csharpTaskBindings"][0]
        candidate = oversized_payload["candidate"]["csharpTasks"][0]
        baseline = oversized_payload["baseline"]["csharpTasks"][0]
        task_ids = [f"task-{index:06d}" for index in range(1_224)]
        oversized_payload["csharpTaskBindings"] = [
            {**binding, "taskId": task_id} for task_id in task_ids
        ]
        oversized_payload["candidate"]["csharpTasks"] = [
            {**candidate, "taskId": task_id} for task_id in task_ids
        ]
        oversized_payload["baseline"]["csharpTasks"] = [
            {**baseline, "taskId": task_id} for task_id in task_ids
        ]
        oversized_payload["approval"]["reference"] = "x" * 405
        oversized_payload["auditId"] = (
            replay_audit_module.csharp_verifier_replay_audit_id(oversized_payload)
        )
        payload_bytes = canonical_json_bytes(oversized_payload)
        self.assertLessEqual(
            len(payload_bytes), replay_audit_module.MAX_AUDIT_PAYLOAD_BYTES
        )
        unsigned_envelope = replay_audit_module._unsigned_envelope(
            payload_bytes,
            audience=material["trust"].audience,
            key_id=material["trust"].key_id,
            signer_role=material["trust"].signer_role,
            public_key_spki_sha256=material["trust"].public_key_spki_sha256,
        )
        self.assertLessEqual(
            len(canonical_json_bytes(unsigned_envelope)) + 1,
            replay_audit_module.MAX_AUDIT_BYTES,
        )
        signed_envelope = dict(unsigned_envelope)
        signed_envelope["signature"] = replay_audit_module._base64url_encode(b"\0" * 64)
        self.assertGreater(
            len(canonical_json_bytes(signed_envelope)) + 1,
            replay_audit_module.MAX_AUDIT_BYTES,
        )
        with self.assertRaisesRegex(ValidationError, "signed envelope"):
            replay_audit_module._build_signing_bundle_document(
                oversized_payload,
                audience=material["trust"].audience,
                key_id=material["trust"].key_id,
                signer_role=material["trust"].signer_role,
                public_key_spki_sha256=(material["trust"].public_key_spki_sha256),
            )

    def test_replay_audit_signed_booleans_require_exact_json_boolean_types(
        self,
    ) -> None:
        material = self._detached_csharp_replay_fixture()
        live = {key: value for key, value in material["live"].items() if key != "trust"}
        audit_path = self.root / "boolean-source.audit.json"
        with self._mock_csharp_replay(material["authority"], material["runtime_tests"]):
            created = create_csharp_verifier_replay_audit(
                output_path=audit_path,
                private_key_path=material["private_key_path"],
                public_key_path=material["public_key_path"],
                public_key_spki_sha256=material["trust"].public_key_spki_sha256,
                private_key_password=None,
                audience=material["trust"].audience,
                key_id=material["trust"].key_id,
                signer_role=material["trust"].signer_role,
                **material["decision"],
                **live,
            )
        for name, value in (("integer", 1), ("float", 1.0)):
            with self.subTest(name=name):
                envelope = json.loads(audit_path.read_text(encoding="utf-8"))
                payload = json.loads(
                    replay_audit_module._base64url_decode(
                        envelope["payload"], "test replay payload", 750_000
                    )
                )
                payload["reusable"] = value
                payload["auditId"] = (
                    replay_audit_module.csharp_verifier_replay_audit_id(payload)
                )
                payload_bytes = canonical_json_bytes(payload)
                envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
                envelope["payload"] = replay_audit_module._base64url_encode(
                    payload_bytes
                )
                envelope["signature"] = ""
                envelope["signature"] = replay_audit_module._base64url_encode(
                    replay_audit_module._sign_p1363_low_s(
                        material["private_key"],
                        replay_audit_module._signature_input(envelope, payload_bytes),
                    )
                )
                changed = self.root / f"boolean-{name}.audit.json"
                changed.write_bytes(canonical_json_bytes(envelope) + b"\n")
                with self.assertRaises(ValidationError):
                    replay_audit_module.validate_csharp_verifier_replay_audit(
                        changed,
                        trust=material["trust"],
                        expected_envelope_sha256=hashlib.sha256(
                            canonical_json_bytes(envelope)
                        ).hexdigest(),
                        now=material["live"]["now"],
                    )
        self.assertEqual(created.payload["reusable"], True)

    def test_replay_audit_publication_is_validated_before_install_and_cleanup_safe(
        self,
    ) -> None:
        rejected_output = self.root / "rejected-replay-audit.json"

        def reject_staged(_: Path) -> bytes:
            raise ValidationError("prepublication validation rejected")

        with self.assertRaisesRegex(ValidationError, "prepublication"):
            replay_audit_module._write_owned_no_clobber(
                rejected_output,
                b"invalid\n",
                prepublish_validator=reject_staged,
                precommit_validator=lambda _: b"unreachable",
                field="test replay-audit output",
            )
        self.assertFalse(rejected_output.exists())

        material = self._detached_csharp_replay_fixture()
        live = {key: value for key, value in material["live"].items() if key != "trust"}
        source = self.root / "publication-source.audit.json"
        with self._mock_csharp_replay(material["authority"], material["runtime_tests"]):
            created = create_csharp_verifier_replay_audit(
                output_path=source,
                private_key_path=material["private_key_path"],
                public_key_path=material["public_key_path"],
                public_key_spki_sha256=material["trust"].public_key_spki_sha256,
                private_key_password=None,
                audience=material["trust"].audience,
                key_id=material["trust"].key_id,
                signer_role=material["trust"].signer_role,
                **material["decision"],
                **live,
            )
        staged = self.root / ".consumer-invalid.audit.staging"
        destination = self.root / "consumer-invalid.audit.json"
        staged.write_bytes(source.read_bytes())
        os.link(staged, destination)
        with self.assertRaisesRegex(ValidationError, "hard-linked"):
            replay_audit_module.validate_csharp_verifier_replay_audit(
                destination,
                trust=material["trust"],
                expected_envelope_sha256=created.envelope_sha256,
                now=material["live"]["now"],
            )
        staged.unlink()
        verified = replay_audit_module.validate_csharp_verifier_replay_audit(
            destination,
            trust=material["trust"],
            expected_envelope_sha256=created.envelope_sha256,
            now=material["live"]["now"],
        )
        self.assertEqual(created.payload, verified.payload)

    def test_replay_audit_cli_create_and_validate_routes_bind_exact_arguments(
        self,
    ) -> None:
        verified = mock.Mock()
        verified.as_dict.return_value = {"auditId": "audit-test-v1"}
        context = object()
        review_trust = object()
        authoring_trust = object()
        create_arguments = [
            "create-csharp-verifier-replay-audit",
            "--output",
            "audit.json",
            "--private-key",
            "audit-private.pem",
            "--csharp-verifier-replay-audit-public-key",
            "audit-public.pem",
            "--csharp-verifier-replay-audit-public-key-spki-sha256",
            "1" * 64,
            "--csharp-verifier-replay-audit-audience",
            "audit-audience",
            "--csharp-verifier-replay-audit-key-id",
            "audit-key-v1",
            "--csharp-verifier-replay-audit-signer-role",
            "audit-signer",
            "--approval-id",
            "approval-v1",
            "--actor-id",
            "auditor-v1",
            "--actor-role",
            "audit-signer",
            "--approval-reference",
            "audit://approval-v1",
            "--approved-at-utc",
            "2026-07-27T08:00:00Z",
            "--replay-completed-at-utc",
            "2026-07-27T07:59:00Z",
            "--issued-at-utc",
            "2026-07-27T08:01:00Z",
            "--not-before-utc",
            "2026-07-27T08:01:00Z",
            "--expires-at-utc",
            "2026-08-27T08:01:00Z",
            "--sealed-tasks",
            "sealed.jsonl",
            "--responses",
            "candidate.responses.jsonl",
            "--verifier-results",
            "candidate.results.jsonl",
            "--baseline-responses",
            "baseline.responses.jsonl",
            "--baseline-verifier-results",
            "baseline.results.jsonl",
            "--release",
            "release.json",
            "--verifier-authority",
            "verifier-authority.json",
            "--verifier-authority-public-key",
            "verifier-authority-public.pem",
            "--verifier-authority-public-key-spki-sha256",
            "2" * 64,
            "--verifier-authority-audience",
            "verifier-audience",
            "--verifier-authority-key-id",
            "verifier-key-v1",
            "--verifier-authority-signer-role",
            "verifier-authority",
            "--review-receipt-public-key",
            "review-public.pem",
            "--review-receipt-public-key-spki-sha256",
            "3" * 64,
            "--review-receipt-audience",
            "review-audience",
            "--review-receipt-key-id",
            "review-key-v1",
            "--review-receipt-signer-role",
            "reviewer",
            "--evaluation-authoring-approval-public-key",
            "authoring-public.pem",
            "--evaluation-authoring-approval-public-key-spki-sha256",
            "4" * 64,
            "--evaluation-authoring-approval-audience",
            "authoring-audience",
            "--evaluation-authoring-approval-key-id",
            "authoring-key-v1",
            "--evaluation-authoring-approval-signer-role",
            "authoring-reviewer",
        ]
        stdout = io.StringIO()
        with (
            mock.patch.object(
                cli_module,
                "_optional_csharp_verifier_context",
                return_value=context,
            ),
            mock.patch.object(
                cli_module, "_review_receipt_trust", return_value=review_trust
            ),
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=authoring_trust,
            ),
            mock.patch.object(
                cli_module, "_promotion_attestation_trust_arguments", return_value={}
            ),
            mock.patch.object(
                cli_module,
                "create_csharp_verifier_replay_audit",
                return_value=verified,
            ) as create_audit,
            redirect_stdout(stdout),
        ):
            exit_code = cli_module.main(create_arguments)
        self.assertEqual(0, exit_code)
        self.assertTrue(json.loads(stdout.getvalue())["created"])
        created = create_audit.call_args.kwargs
        self.assertEqual(Path("audit.json"), created["output_path"])
        self.assertEqual(Path("sealed.jsonl"), created["sealed_tasks_path"])
        self.assertEqual(
            Path("baseline.results.jsonl"), created["baseline_results_path"]
        )
        self.assertEqual("2026-07-27T07:59:00Z", created["replay_completed_at_utc"])
        self.assertIs(context, created["csharp_verifier_context"])
        self.assertIs(review_trust, created["review_receipt_trust"])
        self.assertIs(
            authoring_trust,
            created["evaluation_authoring_approval_trust"],
        )

        stdout = io.StringIO()
        validate_arguments = [
            "validate-csharp-verifier-replay-audit",
            "audit.json",
            "--expected-csharp-verifier-replay-audit-envelope-sha256",
            "4" * 64,
            "--csharp-verifier-replay-audit-public-key",
            "audit-public.pem",
            "--csharp-verifier-replay-audit-public-key-spki-sha256",
            "1" * 64,
            "--csharp-verifier-replay-audit-audience",
            "audit-audience",
            "--csharp-verifier-replay-audit-key-id",
            "audit-key-v1",
            "--csharp-verifier-replay-audit-signer-role",
            "audit-signer",
        ]
        with (
            mock.patch.object(
                cli_module,
                "validate_csharp_verifier_replay_audit",
                return_value=verified,
            ) as validate_audit,
            redirect_stdout(stdout),
        ):
            exit_code = cli_module.main(validate_arguments)
        self.assertEqual(0, exit_code)
        self.assertTrue(json.loads(stdout.getvalue())["valid"])
        self.assertEqual(Path("audit.json"), validate_audit.call_args.args[0])
        validated = validate_audit.call_args.kwargs
        self.assertEqual("4" * 64, validated["expected_envelope_sha256"])
        self.assertEqual(Path("audit-public.pem"), validated["trust"].public_key_path)
        self.assertEqual("audit-audience", validated["trust"].audience)

        def remove_option_pairs(arguments: list[str], *options: str) -> list[str]:
            result = list(arguments)
            for option in options:
                index = result.index(option)
                del result[index : index + 2]
            return result

        prepare_arguments = list(create_arguments)
        prepare_arguments[0] = "prepare-csharp-verifier-replay-audit-signing-bundle"
        prepare_arguments = remove_option_pairs(prepare_arguments, "--private-key")
        with (
            mock.patch.object(
                cli_module,
                "_optional_csharp_verifier_context",
                return_value=context,
            ),
            mock.patch.object(
                cli_module, "_review_receipt_trust", return_value=review_trust
            ),
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=authoring_trust,
            ),
            mock.patch.object(
                cli_module, "_promotion_attestation_trust_arguments", return_value={}
            ),
            mock.patch.object(
                cli_module,
                "prepare_csharp_verifier_replay_audit_signing_bundle",
                return_value=verified,
            ) as prepare_audit,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(0, cli_module.main(prepare_arguments))
        self.assertNotIn("private_key_path", prepare_audit.call_args.kwargs)
        self.assertNotIn("private_key_password", prepare_audit.call_args.kwargs)
        self.assertEqual(
            Path("audit.json"), prepare_audit.call_args.kwargs["output_path"]
        )

        decision_options = (
            "--approval-id",
            "--actor-id",
            "--actor-role",
            "--approval-reference",
            "--approved-at-utc",
            "--replay-completed-at-utc",
            "--issued-at-utc",
            "--not-before-utc",
            "--expires-at-utc",
        )
        finalize_arguments = remove_option_pairs(prepare_arguments, *decision_options)
        finalize_arguments[0] = "finalize-csharp-verifier-replay-audit"
        finalize_arguments[1:1] = [
            "--signing-bundle",
            "bundle.json",
            "--signature",
            "signature.json",
        ]
        with (
            mock.patch.object(
                cli_module,
                "_optional_csharp_verifier_context",
                return_value=context,
            ),
            mock.patch.object(
                cli_module, "_review_receipt_trust", return_value=review_trust
            ),
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=authoring_trust,
            ),
            mock.patch.object(
                cli_module, "_promotion_attestation_trust_arguments", return_value={}
            ),
            mock.patch.object(
                cli_module,
                "finalize_csharp_verifier_replay_audit",
                return_value=verified,
            ) as finalize_audit,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(0, cli_module.main(finalize_arguments))
        finalized = finalize_audit.call_args.kwargs
        self.assertEqual(Path("bundle.json"), finalized["signing_bundle_path"])
        self.assertEqual(Path("signature.json"), finalized["signature_path"])
        self.assertNotIn("private_key_path", finalized)
        self.assertNotIn("private_key_password", finalized)

        parser = cli_module._parser()
        commands = next(
            action.choices
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
            and "finalize-csharp-verifier-replay-audit" in action.choices
        )
        for command in (
            "prepare-csharp-verifier-replay-audit-signing-bundle",
            "finalize-csharp-verifier-replay-audit",
        ):
            options = {
                option
                for action in commands[command]._actions
                for option in action.option_strings
            }
            self.assertNotIn("--private-key", options)
            self.assertNotIn("--private-key-password-env", options)

    def test_release_bound_aggregation_rejects_valid_but_unexecuted_results(
        self,
    ) -> None:
        fixture = self._bound_paired_fixture()
        inputs = fixture["inputs"]
        task = validate_evaluation_tasks(inputs["sealed_tasks_path"]).records[0]
        forged = _result(task, fixture["candidate_response"])
        _write_jsonl(Path(inputs["verifier_results_path"]), forged)

        with self.assertRaisesRegex(ValidationError, "fresh execution"):
            aggregate_promotion_evidence(**inputs)

    def test_executable_verifier_runner_preserves_existing_output(self) -> None:
        fixture = self._bound_paired_fixture()
        output = self.root / "existing-executable-results.jsonl"
        sentinel = b"existing immutable output\n"
        output.write_bytes(sentinel)

        with self.assertRaisesRegex(ValidationError, "already exists"):
            run_release_verifiers(
                tasks_path=fixture["inputs"]["sealed_tasks_path"],
                responses_path=fixture["inputs"]["responses_path"],
                release_path=fixture["inputs"]["data_release_path"],
                review_receipt_trust=fixture["inputs"]["review_receipt_trust"],
                evaluation_authoring_approval_trust=fixture["inputs"][
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=fixture["inputs"]["review_receipt_now"],
                output_path=output,
            )
        self.assertEqual(sentinel, output.read_bytes())

    def test_executable_verifier_runner_rejects_partial_or_unused_csharp_trust(
        self,
    ) -> None:
        fixture = self._bound_paired_fixture()
        arguments = {
            "tasks_path": fixture["inputs"]["sealed_tasks_path"],
            "responses_path": fixture["inputs"]["responses_path"],
            "release_path": fixture["inputs"]["data_release_path"],
            "review_receipt_trust": fixture["inputs"]["review_receipt_trust"],
            "evaluation_authoring_approval_trust": fixture["inputs"][
                "evaluation_authoring_approval_trust"
            ],
            "review_receipt_now": fixture["inputs"]["review_receipt_now"],
        }
        with self.assertRaisesRegex(ValidationError, "supplied together"):
            run_release_verifiers(
                output_path=self.root / "partial-csharp-context.jsonl",
                csharp_verifier_authority_path=self.root / "authority.json",
                **arguments,
            )

        trust = CSharpVerifierAuthorityTrust(
            self.root / "public.pem", "a" * 64, "audience", "key", "reviewer"
        )
        with self.assertRaisesRegex(ValidationError, "no C# verifier profile"):
            run_release_verifiers(
                output_path=self.root / "unused-csharp-context.jsonl",
                csharp_verifier_authority_path=self.root / "authority.json",
                csharp_verifier_authority_trust=trust,
                **arguments,
            )

    def test_executable_verifier_runner_detects_input_change_before_install(
        self,
    ) -> None:
        fixture = self._bound_paired_fixture()
        output = self.root / "raced-executable-results.jsonl"
        responses = Path(fixture["inputs"]["responses_path"])
        original_write = verifier_runtime_module._write_bytes_atomic_no_clobber

        def mutate_before_install(path, raw, field, *, before_install=None):
            def mutate_then_check() -> None:
                responses.write_bytes(responses.read_bytes() + b" ")
                self.assertIsNotNone(before_install)
                before_install()

            return original_write(
                path,
                raw,
                field,
                before_install=mutate_then_check,
            )

        with mock.patch.object(
            verifier_runtime_module,
            "_write_bytes_atomic_no_clobber",
            side_effect=mutate_before_install,
        ):
            with self.assertRaisesRegex(ValidationError, "changed during execution"):
                run_release_verifiers(
                    tasks_path=fixture["inputs"]["sealed_tasks_path"],
                    responses_path=responses,
                    release_path=fixture["inputs"]["data_release_path"],
                    review_receipt_trust=fixture["inputs"]["review_receipt_trust"],
                    evaluation_authoring_approval_trust=fixture["inputs"][
                        "evaluation_authoring_approval_trust"
                    ],
                    review_receipt_now=fixture["inputs"]["review_receipt_now"],
                    output_path=output,
                )
        self.assertFalse(output.exists())

    def test_release_purpose_and_endpoint_matrix(self) -> None:
        local = self._bound_release_fixture()
        provider = self._bound_release_fixture(provider=True)
        matrix = (
            ("local-loopback", local, "http://127.0.0.1/v1", True),
            ("local-provider", local, "https://models.example/v1", False),
            ("provider-loopback", provider, "http://127.0.0.1/v1", True),
            ("provider-provider", provider, "https://models.example/v1", True),
        )
        for name, bound, base_url, allowed in matrix:
            output = self.root / f"{name}.responses.jsonl"
            arguments = {
                "candidate_index": 0,
                "profile_id": f"{name}-profile-v1",
                "base_url": base_url,
                "data_release_path": bound["release_path"],
                "sft_path": bound["sft_path"],
                "review_receipt_trust": bound["review_receipt_trust"],
                "evaluation_authoring_approval_trust": bound[
                    "evaluation_authoring_approval_trust"
                ],
                "review_receipt_now": bound["review_receipt_now"],
                "research_only": False,
            }
            if allowed:
                self._capture(
                    bound["fixture"].sealed_tasks,
                    output,
                    self._transport(),
                    **arguments,
                )
                response = validate_evaluation_responses(
                    output, bound["fixture"].sealed_tasks
                )[0]
                self.assertEqual(bound["release_identity"], response["dataRelease"])
            else:
                with self.assertRaisesRegex(
                    ValidationError, "authorize provider upload"
                ):
                    self._capture(
                        bound["fixture"].sealed_tasks,
                        output,
                        self._transport(),
                        **arguments,
                    )
                self.assertFalse(output.exists())

    def test_capture_revalidates_receipt_expiry_before_each_provider_request(
        self,
    ) -> None:
        bound = self._bound_release_fixture(provider=True)
        serving = self._serving_fixture(
            0,
            "expiring-receipt-profile-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        real_validate = release_module.validate_corpus_evaluation_release_with_identity
        validation_count = 0

        def expiring_validation(*args, **kwargs):
            nonlocal validation_count
            validation_count += 1
            if validation_count == 2:
                raise ValidationError(
                    "expert-model review-receipt validity: is not currently active"
                )
            return real_validate(*args, **kwargs)

        transport = mock.Mock(side_effect=self._transport())
        output = self.root / "expired-before-request.responses.jsonl"
        with (
            mock.patch.dict(os.environ, {"VQ_TEST_KEY": "secret"}, clear=False),
            mock.patch.object(
                release_module,
                "validate_corpus_evaluation_release_with_identity",
                side_effect=expiring_validation,
            ),
            self.assertRaisesRegex(ValidationError, "not currently active"),
        ):
            capture_openai_responses(
                tasks_path=bound["fixture"].sealed_tasks,
                catalog_path=self.catalog_path,
                output_path=output,
                serving_profile_path=serving["profile_path"],
                training_artifact_path=serving["artifact_path"],
                training_manifest_path=serving["manifest_path"],
                run_id="receipt-expiry-run",
                base_url="https://models.example/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=bound["release_path"],
                review_receipt_trust=bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=bound["review_receipt_now"],
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                research_only=False,
                transport=transport,
            )

        self.assertEqual(2, validation_count)
        transport.assert_not_called()
        self.assertFalse(output.exists())

    def test_capture_revalidates_trainer_expiry_before_transport(self) -> None:
        bound = self._bound_release_fixture()
        serving = self._serving_fixture(
            0,
            "expiring-trainer-profile-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        clock = mock.Mock(
            side_effect=(
                self.trainer_provenance_now,
                datetime(2027, 1, 1, tzinfo=timezone.utc),
            )
        )
        transport = mock.Mock(side_effect=self._transport())
        output = self.root / "expired-trainer.responses.jsonl"
        with (
            mock.patch.dict(os.environ, {"VQ_TEST_KEY": "secret"}, clear=False),
            self.assertRaisesRegex(ValidationError, "not active"),
        ):
            capture_openai_responses(
                tasks_path=bound["fixture"].sealed_tasks,
                catalog_path=self.catalog_path,
                output_path=output,
                serving_profile_path=serving["profile_path"],
                training_artifact_path=serving["artifact_path"],
                training_manifest_path=serving["manifest_path"],
                run_id="trainer-expiry-run",
                base_url="http://127.0.0.1/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=bound["release_path"],
                review_receipt_trust=bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=bound["review_receipt_now"],
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                research_only=False,
                transport=transport,
                clock=clock,
            )

        self.assertEqual(2, clock.call_count)
        transport.assert_not_called()
        self.assertFalse(output.exists())

    def test_legacy_v1_candidate_is_structural_only_and_cannot_enter_serving(
        self,
    ) -> None:
        bound = self._bound_release_fixture()
        serving = self._serving_fixture(
            0,
            "legacy-v1-candidate-profile",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        metadata_path = serving["artifact_path"] / "artifact-metadata.json"
        legacy = json.loads(metadata_path.read_text(encoding="utf-8"))
        legacy["schemaVersion"] = TRAINING_ARTIFACT_V1_SCHEMA_VERSION
        legacy.pop("trainerProvenance")
        legacy["artifactSha256"] = training_artifact_sha256(legacy)
        metadata_path.write_bytes(canonical_json_bytes(legacy) + b"\n")

        self.assertEqual(legacy, validate_training_artifact(serving["artifact_path"]))
        with self.assertRaisesRegex(ValidationError, "trainer provenance trust"):
            validate_serving_profile(
                serving["profile_path"],
                artifact_path=serving["artifact_path"],
                manifest_path=serving["manifest_path"],
            )
        with self.assertRaisesRegex(ValidationError, "legacy v1 candidate"):
            validate_serving_profile(
                serving["profile_path"],
                artifact_path=serving["artifact_path"],
                manifest_path=serving["manifest_path"],
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                trainer_provenance_now=self.trainer_provenance_now,
            )

    def test_capture_revalidates_trainer_expiry_before_publication(self) -> None:
        bound = self._bound_release_fixture()
        serving = self._serving_fixture(
            0,
            "publication-expiry-trainer-profile-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        clock = mock.Mock(
            side_effect=(
                self.trainer_provenance_now,
                self.trainer_provenance_now,
                self.trainer_provenance_now,
                datetime(2027, 1, 1, tzinfo=timezone.utc),
            )
        )
        transport = mock.Mock(side_effect=self._transport())
        output = self.root / "publication-expired-trainer.responses.jsonl"
        with (
            mock.patch.dict(os.environ, {"VQ_TEST_KEY": "secret"}, clear=False),
            self.assertRaisesRegex(ValidationError, "not active"),
        ):
            capture_openai_responses(
                tasks_path=bound["fixture"].sealed_tasks,
                catalog_path=self.catalog_path,
                output_path=output,
                serving_profile_path=serving["profile_path"],
                training_artifact_path=serving["artifact_path"],
                training_manifest_path=serving["manifest_path"],
                run_id="trainer-publication-expiry-run",
                base_url="http://127.0.0.1/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=bound["release_path"],
                review_receipt_trust=bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=bound["review_receipt_now"],
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                research_only=False,
                transport=transport,
                clock=clock,
            )

        self.assertEqual(4, clock.call_count)
        transport.assert_called_once()
        self.assertFalse(output.exists())

    def test_capture_revalidates_trainer_signature_mutation_before_transport(
        self,
    ) -> None:
        bound = self._bound_release_fixture()
        serving = self._serving_fixture(
            0,
            "mutating-trainer-profile-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        clock_calls = 0

        def mutate_on_revalidation() -> datetime:
            nonlocal clock_calls
            clock_calls += 1
            if clock_calls == 2:
                metadata_path = serving["artifact_path"] / "artifact-metadata.json"
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                metadata["trainerProvenance"]["signature"] = "A" * 86
                metadata["artifactSha256"] = training_artifact_sha256(metadata)
                metadata_path.write_bytes(canonical_json_bytes(metadata) + b"\n")
            return self.trainer_provenance_now

        transport = mock.Mock(side_effect=self._transport())
        output = self.root / "mutated-trainer.responses.jsonl"
        with (
            mock.patch.dict(os.environ, {"VQ_TEST_KEY": "secret"}, clear=False),
            self.assertRaisesRegex(ValidationError, "signature"),
        ):
            capture_openai_responses(
                tasks_path=bound["fixture"].sealed_tasks,
                catalog_path=self.catalog_path,
                output_path=output,
                serving_profile_path=serving["profile_path"],
                training_artifact_path=serving["artifact_path"],
                training_manifest_path=serving["manifest_path"],
                run_id="trainer-mutation-run",
                base_url="http://127.0.0.1/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=bound["release_path"],
                review_receipt_trust=bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=bound["review_receipt_now"],
                trainer_provenance_trust=serving["trainer_provenance_trust"],
                research_only=False,
                transport=transport,
                clock=mutate_on_revalidation,
            )

        self.assertEqual(2, clock_calls)
        transport.assert_not_called()
        self.assertFalse(output.exists())

    def test_bound_candidate_readiness_revalidates_the_live_release(self) -> None:
        bound = self._bound_release_fixture()
        fixture = self._serving_fixture(
            0,
            "bound-readiness-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        nonce = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
        with self.assertRaisesRegex(ValidationError, "required together"):
            create_model_readiness_attestation(
                profile_path=fixture["profile_path"],
                artifact_path=fixture["artifact_path"],
                manifest_path=fixture["manifest_path"],
                audience="daxalgo-platform-prod",
                nonce=nonce,
                key_id="prod-hmac-v1",
                key=bytes(range(32)),
                data_release_path=bound["release_path"],
                trainer_provenance_trust=fixture["trainer_provenance_trust"],
                trainer_provenance_now=fixture["trainer_provenance_now"],
            )
        response = create_model_readiness_attestation(
            profile_path=fixture["profile_path"],
            artifact_path=fixture["artifact_path"],
            manifest_path=fixture["manifest_path"],
            audience="daxalgo-platform-prod",
            nonce=nonce,
            key_id="prod-hmac-v1",
            key=bytes(range(32)),
            data_release_path=bound["release_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
            trainer_provenance_trust=fixture["trainer_provenance_trust"],
            trainer_provenance_now=fixture["trainer_provenance_now"],
        )
        self.assertEqual(
            MODEL_READINESS_ATTESTATION_SCHEMA_VERSION, response["schemaVersion"]
        )
        self.assertEqual({"schemaVersion", "nonce", "keyId", "proof"}, set(response))
        serialized = json.dumps(response, sort_keys=True)
        self.assertNotIn(bound["release_identity"]["releaseId"], serialized)
        self.assertNotIn(fixture["artifact"]["artifactSha256"], serialized)

        release_manifest = json.loads(
            (bound["release_path"] / "release-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        evidence_path = bound["release_path"].joinpath(
            *release_manifest["approval"]["evidence"]["path"].split("/")
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValidationError, "bound file"):
            create_model_readiness_attestation(
                profile_path=fixture["profile_path"],
                artifact_path=fixture["artifact_path"],
                manifest_path=fixture["manifest_path"],
                audience="daxalgo-platform-prod",
                nonce=nonce,
                key_id="prod-hmac-v1",
                key=bytes(range(32)),
                data_release_path=bound["release_path"],
                review_receipt_trust=bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=bound["review_receipt_now"],
                trainer_provenance_trust=fixture["trainer_provenance_trust"],
                trainer_provenance_now=fixture["trainer_provenance_now"],
            )

    def test_candidate_sealing_rejects_missing_mismatched_and_tampered_release(
        self,
    ) -> None:
        local = self._bound_release_fixture()
        provider = self._bound_release_fixture(provider=True)
        fixture = self._serving_fixture(
            0,
            "sealer-source-v1",
            data_release_path=local["release_path"],
            sft_path=local["sft_path"],
            review_receipt_trust=local["review_receipt_trust"],
            evaluation_authoring_approval_trust=local[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=local["review_receipt_now"],
        )
        metadata = fixture["artifact"]

        def unsealed_copy(name: str) -> Path:
            destination = self.root / name
            shutil.copytree(fixture["artifact_path"], destination)
            (destination / "artifact-metadata.json").unlink()
            return destination

        missing = unsealed_copy("candidate-missing-release")
        with self.assertRaisesRegex(ValidationError, "validated release path"):
            seal_training_artifact(
                missing,
                metadata,
                **self._trainer_signing_arguments(),
            )

        mismatched = unsealed_copy("candidate-mismatched-release")
        with self.assertRaisesRegex(
            ValidationError, "does not match the training dataset"
        ):
            seal_training_artifact(
                mismatched,
                metadata,
                data_release_path=provider["release_path"],
                review_receipt_trust=provider["review_receipt_trust"],
                evaluation_authoring_approval_trust=provider[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=provider["review_receipt_now"],
                **self._trainer_signing_arguments(),
            )

        release_manifest = json.loads(
            (local["release_path"] / "release-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        evidence_path = local["release_path"].joinpath(
            *release_manifest["approval"]["evidence"]["path"].split("/")
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b"tampered")
        tampered = unsealed_copy("candidate-tampered-release")
        with self.assertRaisesRegex(ValidationError, "bound file"):
            seal_training_artifact(
                tampered,
                metadata,
                data_release_path=local["release_path"],
                review_receipt_trust=local["review_receipt_trust"],
                evaluation_authoring_approval_trust=local[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=local["review_receipt_now"],
                **self._trainer_signing_arguments(),
            )

    def test_paired_aggregate_is_deterministic_unpromoted_and_strictly_validated(
        self,
    ) -> None:
        inputs = self._paired_fixture()
        bound_inputs = dict(inputs)
        bound_inputs.pop("research_only")
        with self.assertRaisesRegex(ValidationError, "fully validated bound release"):
            aggregate_promotion_evidence(**bound_inputs)
        report = aggregate_promotion_evidence(**inputs)
        self.assertEqual(report, aggregate_promotion_evidence(**inputs))
        self.assertTrue(report["suiteSufficiency"]["passed"])
        self.assertTrue(report["overall"]["noRegressionPassed"])
        self.assertTrue(report["allEvidenceGatesPassed"])
        self.assertFalse(report["promotionEligible"])
        self.assertFalse(report["eligibleForPromotionReview"])
        self.assertTrue(report["researchOnly"])
        report_path = self.root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual(report, validate_promotion_evidence(report_path))
        report["overall"]["absoluteRateDelta"] = -0.5
        report_path.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "absoluteRateDelta"):
            validate_promotion_evidence(report_path)

    def test_non_stop_finish_is_recorded_but_hard_fails_evidence_gate(self) -> None:
        inputs = self._paired_fixture(candidate_finish="length")
        response = validate_evaluation_responses(
            inputs["responses_path"], inputs["sealed_tasks_path"]
        )[0]
        self.assertEqual("length", response["finishReason"])
        report = aggregate_promotion_evidence(**inputs)
        self.assertFalse(report["allFinishReasonsStop"])
        self.assertFalse(report["allEvidenceGatesPassed"])
        self.assertEqual(["sealed-1"], report["candidateNonStopTaskIds"])

    def test_suite_minimums_calibration_evidence_and_run_identity_fail_closed(
        self,
    ) -> None:
        inputs = self._paired_fixture()
        policy = json.loads(Path(inputs["policy_path"]).read_text(encoding="utf-8"))
        policy["minimumTotalTasks"] = 2
        policy["policySha256"] = promotion_policy_sha256(policy)
        Path(inputs["policy_path"]).write_text(json.dumps(policy), encoding="utf-8")
        report = aggregate_promotion_evidence(**inputs)
        self.assertFalse(report["suiteSufficiency"]["passed"])
        self.assertFalse(report["allEvidenceGatesPassed"])

        policy["minimumTotalTasks"] = 1
        policy["candidateRun"]["runId"] = "wrong-frozen-run"
        policy["policySha256"] = promotion_policy_sha256(policy)
        Path(inputs["policy_path"]).write_text(json.dumps(policy), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "run identity"):
            aggregate_promotion_evidence(**inputs)

        policy["candidateRun"]["runId"] = "eval-run-001"
        policy["policySha256"] = promotion_policy_sha256(policy)
        Path(inputs["policy_path"]).write_text(json.dumps(policy), encoding="utf-8")

        same_artifact = json.loads(json.dumps(policy))
        same_artifact["baselineRun"] = json.loads(
            json.dumps(same_artifact["candidateRun"])
        )
        same_artifact["baselineRun"]["runId"] = "baseline-run-001"
        same_artifact["baselineRun"]["servingProfile"]["id"] = "renamed-profile"
        same_artifact["policySha256"] = promotion_policy_sha256(same_artifact)
        Path(inputs["policy_path"]).write_text(
            json.dumps(same_artifact), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValidationError, "distinct model or serving artifact"
        ):
            validate_promotion_policy(inputs["policy_path"])

        different_catalog = json.loads(json.dumps(policy))
        different_catalog["baselineRun"]["candidateCatalogSha256"] = "f" * 64
        different_catalog["policySha256"] = promotion_policy_sha256(different_catalog)
        Path(inputs["policy_path"]).write_text(
            json.dumps(different_catalog), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ValidationError, "must match the candidate catalog"
        ):
            validate_promotion_policy(inputs["policy_path"])

        different_seed = json.loads(json.dumps(policy))
        different_seed["baselineRun"]["seed"] += 1
        different_seed["policySha256"] = promotion_policy_sha256(different_seed)
        Path(inputs["policy_path"]).write_text(
            json.dumps(different_seed), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValidationError, "paired comparison"):
            validate_promotion_policy(inputs["policy_path"])

        Path(inputs["policy_path"]).write_text(json.dumps(policy), encoding="utf-8")

        Path(inputs["calibration_evidence_path"]).write_text(
            "tampered", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValidationError, "SHA-256"):
            aggregate_promotion_evidence(**inputs)

    def test_response_run_binding_is_uniform(self) -> None:
        tasks_path = self.root / "sealed.jsonl"
        _write_jsonl(
            tasks_path, _task("sealed-1", "sealed"), _task("sealed-2", "sealed")
        )
        responses_path = self.root / "responses.jsonl"
        self._capture(tasks_path, responses_path, self._transport())
        records = [
            json.loads(line)
            for line in responses_path.read_text(encoding="utf-8").splitlines()
        ]
        empty_stop = json.loads(json.dumps(records))
        empty_stop[0]["output"] = {
            "text": "",
            "sha256": evaluation_output_sha256(""),
            "byteCount": 0,
        }
        empty_stop[0]["responseSha256"] = evaluation_response_sha256(empty_stop[0])
        _write_jsonl(responses_path, *empty_stop)
        with self.assertRaisesRegex(ValidationError, "non-empty"):
            validate_evaluation_responses(responses_path, tasks_path)

        records[1]["runId"] = "different-run"
        records[1]["responseSha256"] = evaluation_response_sha256(records[1])
        _write_jsonl(responses_path, *records)
        with self.assertRaisesRegex(ValidationError, "run ID"):
            validate_evaluation_responses(responses_path, tasks_path)

    def test_verifier_decision_manifest_schema_is_closed_and_bounded(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "verifier-decision-manifest.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            VERIFIER_DECISION_MANIFEST_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        self.assertFalse(schema["properties"]["inputs"]["additionalProperties"])
        self.assertEqual(100_000, schema["properties"]["decisions"]["maxItems"])
        self.assertFalse(schema["$defs"]["decision"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["check"]["additionalProperties"])
        self.assertEqual(
            200_000,
            schema["$defs"]["check"]["properties"]["evidence"]["maxLength"],
        )

    def test_cli_compiles_canonical_complete_verifier_results(self) -> None:
        fixture = self._verifier_compile_fixture("cli-compiler")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(
                [
                    "compile-verifier-results",
                    "--tasks",
                    str(fixture["tasks_path"]),
                    "--responses",
                    str(fixture["responses_path"]),
                    "--decisions",
                    str(fixture["decisions_path"]),
                    "--output",
                    str(fixture["output_path"]),
                ]
            )
        self.assertEqual(0, exit_code)
        summary = json.loads(stdout.getvalue())
        self.assertTrue(summary["created"])

        records = validate_verifier_results(
            fixture["output_path"], fixture["tasks_path"], fixture["responses_path"]
        )
        self.assertEqual(
            sorted(response["taskId"] for response in fixture["responses"]),
            [record["taskId"] for record in records],
        )
        self.assertEqual(
            b"".join(canonical_json_bytes(record) + b"\n" for record in records),
            fixture["output_path"].read_bytes(),
        )
        self.assertEqual(2, summary["recordCount"])
        self.assertEqual(
            validate_evaluation_tasks(fixture["tasks_path"]).task_set_sha256,
            summary["taskSetSha256"],
        )
        self.assertEqual(
            evaluation_response_set_sha256(fixture["responses"]),
            summary["responseSetSha256"],
        )
        self.assertEqual(
            verifier_result_set_sha256(records),
            summary["verifierResultSetSha256"],
        )
        self.assertEqual(
            fixture["output_path"].resolve(), Path(summary["outputPath"]).resolve()
        )

        by_id = {record["taskId"]: record for record in records}
        for decision in fixture["manifest"]["decisions"]:
            result = by_id[decision["taskId"]]
            self.assertEqual(
                all(check["passed"] for check in decision["checks"]),
                result["accepted"],
            )
            for authored, compiled in zip(decision["checks"], result["checks"]):
                self.assertEqual(authored["evidence"], compiled["evidence"])
                self.assertEqual(
                    evidence_sha256(authored["evidence"]),
                    compiled["evidenceSha256"],
                )
            self.assertEqual(verifier_result_sha256(result), result["resultSha256"])

    def test_human_decision_compiler_rejects_release_bound_responses(self) -> None:
        fixture = self._verifier_compile_fixture("release-bound-manual")
        release_identity = {
            "releaseId": f"vqrel-{'1' * 64}",
            "releaseSha256": "1" * 64,
            "manifestSha256": "2" * 64,
        }
        responses = []
        for response in fixture["responses"]:
            updated = json.loads(json.dumps(response))
            updated["dataRelease"] = release_identity
            updated["researchOnly"] = False
            updated["evidenceStatus"] = "release-bound"
            updated["responseSha256"] = evaluation_response_sha256(updated)
            responses.append(updated)
        _write_jsonl(fixture["responses_path"], *responses)

        with self.assertRaisesRegex(
            ValidationError, "human decisions are research-only"
        ):
            compile_verifier_results(
                tasks_path=fixture["tasks_path"],
                responses_path=fixture["responses_path"],
                decisions_path=fixture["decisions_path"],
                output_path=fixture["output_path"],
            )

    def test_cli_validate_verifier_results_rejects_deleted_result_line(self) -> None:
        fixture = self._verifier_compile_fixture("deleted-result")
        compile_verifier_results(
            tasks_path=fixture["tasks_path"],
            responses_path=fixture["responses_path"],
            decisions_path=fixture["decisions_path"],
            output_path=fixture["output_path"],
        )
        lines = fixture["output_path"].read_bytes().splitlines(keepends=True)
        self.assertEqual(2, len(lines))
        fixture["output_path"].write_bytes(lines[0])

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli_module.main(
                [
                    "validate-verifier-results",
                    str(fixture["output_path"]),
                    "--tasks",
                    str(fixture["tasks_path"]),
                    "--responses",
                    str(fixture["responses_path"]),
                ]
            )
        self.assertEqual(2, exit_code)
        self.assertEqual("", stdout.getvalue())
        self.assertIn(
            "exactly one result for every bound task and response", stderr.getvalue()
        )

    def test_complete_verifier_validation_rejects_duplicate_response_iterable(
        self,
    ) -> None:
        fixture = self._verifier_compile_fixture("duplicate-response-iterable")
        compile_verifier_results(
            tasks_path=fixture["tasks_path"],
            responses_path=fixture["responses_path"],
            decisions_path=fixture["decisions_path"],
            output_path=fixture["output_path"],
        )
        responses = tuple(fixture["responses"])
        with self.assertRaisesRegex(ValidationError, "duplicate task IDs"):
            validate_verifier_results(
                fixture["output_path"],
                fixture["tasks_path"],
                (*responses, responses[0]),
                require_complete=True,
            )

    def test_verifier_compiler_detects_input_change_before_atomic_install(self) -> None:
        fixture = self._verifier_compile_fixture("input-race")
        original_write = evaluation_module._write_bytes_atomic_no_clobber

        def mutate_before_install(path, raw, field, *, before_install=None):
            def mutate_then_check() -> None:
                fixture["decisions_path"].write_bytes(
                    fixture["decisions_path"].read_bytes() + b" "
                )
                self.assertIsNotNone(before_install)
                before_install()

            return original_write(
                path,
                raw,
                field,
                before_install=mutate_then_check,
            )

        with mock.patch.object(
            evaluation_module,
            "_write_bytes_atomic_no_clobber",
            side_effect=mutate_before_install,
        ):
            with self.assertRaisesRegex(ValidationError, "changed during compilation"):
                compile_verifier_results(
                    tasks_path=fixture["tasks_path"],
                    responses_path=fixture["responses_path"],
                    decisions_path=fixture["decisions_path"],
                    output_path=fixture["output_path"],
                )
        self.assertFalse(fixture["output_path"].exists())

    def test_cli_rejects_lone_surrogate_evidence_without_output(self) -> None:
        fixture = self._verifier_compile_fixture("surrogate-evidence")
        manifest = json.loads(json.dumps(fixture["manifest"]))
        manifest["decisions"][0]["checks"][0]["evidence"] = "\ud800"
        fixture["decisions_path"].write_text(
            json.dumps(manifest), encoding="utf-8", newline="\n"
        )

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = cli_module.main(
                [
                    "compile-verifier-results",
                    "--tasks",
                    str(fixture["tasks_path"]),
                    "--responses",
                    str(fixture["responses_path"]),
                    "--decisions",
                    str(fixture["decisions_path"]),
                    "--output",
                    str(fixture["output_path"]),
                ]
            )
        self.assertEqual(2, exit_code)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("valid Unicode scalar values", stderr.getvalue())
        self.assertFalse(fixture["output_path"].exists())

    def test_validate_responses_cli_exposes_semantic_set_hashes(self) -> None:
        fixture = self._verifier_compile_fixture("response-summary")
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(
                [
                    "validate-responses",
                    str(fixture["responses_path"]),
                    "--tasks",
                    str(fixture["tasks_path"]),
                ]
            )
        self.assertEqual(0, exit_code)
        summary = json.loads(stdout.getvalue())
        self.assertTrue(summary["valid"])
        self.assertEqual(2, summary["recordCount"])
        self.assertEqual(
            validate_evaluation_tasks(fixture["tasks_path"]).task_set_sha256,
            summary["taskSetSha256"],
        )
        self.assertEqual(
            evaluation_response_set_sha256(fixture["responses"]),
            summary["responseSetSha256"],
        )

    def test_verifier_compiler_requires_complete_exact_bindings(self) -> None:
        mutations = {
            "task-set": lambda value: value["inputs"].__setitem__(
                "taskSetSha256", "0" * 64
            ),
            "response-set": lambda value: value["inputs"].__setitem__(
                "responseSetSha256", "0" * 64
            ),
            "response-row": lambda value: value["decisions"][0].__setitem__(
                "responseSha256", "0" * 64
            ),
            "missing": lambda value: value["decisions"].pop(),
            "duplicate": lambda value: value["decisions"].append(
                json.loads(json.dumps(value["decisions"][0]))
            ),
            "unknown": lambda value: value["decisions"][0].__setitem__(
                "taskId", "unknown-task"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fixture = self._verifier_compile_fixture(f"binding-{name}")
                manifest = json.loads(json.dumps(fixture["manifest"]))
                mutate(manifest)
                fixture["decisions_path"].write_text(
                    json.dumps(manifest), encoding="utf-8", newline="\n"
                )
                with self.assertRaises(ValidationError):
                    compile_verifier_results(
                        tasks_path=fixture["tasks_path"],
                        responses_path=fixture["responses_path"],
                        decisions_path=fixture["decisions_path"],
                        output_path=fixture["output_path"],
                    )
                self.assertFalse(fixture["output_path"].exists())

        fixture = self._verifier_compile_fixture("binding-partial-responses")
        _write_jsonl(fixture["responses_path"], fixture["responses"][0])
        partial_responses = validate_evaluation_responses(
            fixture["responses_path"], fixture["tasks_path"]
        )
        manifest = json.loads(json.dumps(fixture["manifest"]))
        manifest["inputs"]["responseSetSha256"] = evaluation_response_set_sha256(
            partial_responses
        )
        manifest["decisions"] = [
            decision
            for decision in manifest["decisions"]
            if decision["taskId"] == partial_responses[0]["taskId"]
        ]
        fixture["decisions_path"].write_text(
            json.dumps(manifest), encoding="utf-8", newline="\n"
        )
        with self.assertRaises(ValidationError):
            compile_verifier_results(
                tasks_path=fixture["tasks_path"],
                responses_path=fixture["responses_path"],
                decisions_path=fixture["decisions_path"],
                output_path=fixture["output_path"],
            )
        self.assertFalse(fixture["output_path"].exists())

    def test_verifier_compiler_requires_exact_check_contract(self) -> None:
        def reorder(value: dict) -> None:
            value["decisions"][0]["checks"].reverse()

        def missing(value: dict) -> None:
            value["decisions"][0]["checks"].pop()

        def duplicate(value: dict) -> None:
            value["decisions"][0]["checks"][1]["checkId"] = "correct"

        def unknown(value: dict) -> None:
            value["decisions"][0]["checks"][0]["checkId"] = "unknown"

        def blank_evidence(value: dict) -> None:
            value["decisions"][0]["checks"][0]["evidence"] = " "

        def oversized_evidence(value: dict) -> None:
            value["decisions"][0]["checks"][0]["evidence"] = "x" * 200_001

        def unknown_field(value: dict) -> None:
            value["decisions"][0]["unexpected"] = True

        for name, mutate in {
            "reordered": reorder,
            "missing": missing,
            "duplicate": duplicate,
            "unknown": unknown,
            "blank-evidence": blank_evidence,
            "oversized-evidence": oversized_evidence,
            "unknown-field": unknown_field,
        }.items():
            with self.subTest(name=name):
                fixture = self._verifier_compile_fixture(f"checks-{name}")
                manifest = json.loads(json.dumps(fixture["manifest"]))
                mutate(manifest)
                fixture["decisions_path"].write_text(
                    json.dumps(manifest), encoding="utf-8", newline="\n"
                )
                with self.assertRaises(ValidationError):
                    compile_verifier_results(
                        tasks_path=fixture["tasks_path"],
                        responses_path=fixture["responses_path"],
                        decisions_path=fixture["decisions_path"],
                        output_path=fixture["output_path"],
                    )
                self.assertFalse(fixture["output_path"].exists())

    def test_verifier_compiler_preserves_existing_output(self) -> None:
        fixture = self._verifier_compile_fixture("no-clobber")
        sentinel = b"existing verifier results\n"
        fixture["output_path"].write_bytes(sentinel)
        with self.assertRaisesRegex(ValidationError, "already exists"):
            compile_verifier_results(
                tasks_path=fixture["tasks_path"],
                responses_path=fixture["responses_path"],
                decisions_path=fixture["decisions_path"],
                output_path=fixture["output_path"],
            )
        self.assertEqual(sentinel, fixture["output_path"].read_bytes())


if __name__ == "__main__":
    unittest.main()
