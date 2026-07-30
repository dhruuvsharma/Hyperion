from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
from base64 import urlsafe_b64decode, urlsafe_b64encode
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import vibe_quant_model.cli as cli_module
import vibe_quant_model.release as release_module
import vibe_quant_model.review_receipts as review_receipts_module
from vibe_quant_model.core import (
    DOMAINS,
    ValidationError,
    canonical_json_bytes,
    create_bundle,
    expert_conversation_sha256,
    validate_manifest_path,
)
from vibe_quant_model.evaluation_authoring import (
    EvaluationAuthoringApprovalTrust,
    create_evaluation_authoring_approval,
    derive_evaluation_authoring_inventory,
)
from vibe_quant_model.evaluation import evaluation_prompt_sha256, evaluation_task_sha256
from vibe_quant_model.release import (
    LEGACY_RELEASE_SCHEMA_VERSION,
    RELEASE_MANIFEST_PATH,
    RELEASE_SCHEMA_VERSION,
    TASK_BINDINGS_SCHEMA_VERSION,
    TASK_BINDINGS_V2_SCHEMA_VERSION,
    _validate_corpus_record,
    _validate_release_document,
    _verification_evidence_sha256,
    corpus_evaluation_release_sha256,
    create_corpus_evaluation_release,
    validate_corpus_evaluation_release,
    validate_corpus_evaluation_release_with_identity,
)
from vibe_quant_model.review_receipts import (
    ExpertModelReviewReceiptTrust,
    LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION,
    LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION,
    REVIEW_RECEIPT_ID_PREFIX,
    create_expert_model_review_receipts,
    expert_model_review_receipt_id,
    expert_model_sft_metadata,
    legacy_expert_model_sft_metadata_sha256,
)
from vibe_quant_model.teacher_lineage import (
    TeacherMaterializationLineageAdmissionTrust,
)
from vibe_quant_model.training import train_from_manifest


CUTOFF = "2025-01-15T12:00:00Z"
PRODUCED = "2025-01-14T12:00:00Z"
VERIFIED = "2025-01-16T12:00:00Z"
APPROVED = "2025-01-20T12:00:00Z"
RECEIPT_ISSUED = "2025-01-20T12:00:01Z"
RECEIPT_NOT_BEFORE = "2025-01-20T12:00:02Z"
RECEIPT_EXPIRES = "2026-01-20T12:00:02Z"
VALIDATION_TIME = datetime(2025, 2, 1, tzinfo=timezone.utc)
RECEIPT_AUDIENCE = "daxalgo-vibe-quant-release"
RECEIPT_KEY_ID = "release-review-key-2025-01"
RECEIPT_SIGNER_ROLE = "expert-review-authority"
AUTHORING_APPROVED = "2025-01-20T11:58:00Z"
AUTHORING_ISSUED = "2025-01-20T11:58:30Z"
AUTHORING_NOT_BEFORE = "2025-01-20T11:59:00Z"
AUTHORING_EXPIRES = "2026-01-20T12:01:00Z"
AUTHORING_AUDIENCE = "daxalgo-vibe-quant-evaluation-authoring"
AUTHORING_KEY_ID = "evaluation-authoring-review-key-2025-01"
AUTHORING_SIGNER_ROLE = "evaluation-authoring-reviewer"


def _rights(*, train: bool = False, upload: bool = False) -> dict:
    return {
        "mayStore": True,
        "mayEvaluate": True,
        "mayTrain": train,
        "mayUploadToProvider": upload,
        "mayRedistribute": False,
    }


def _corpus_record(
    example_id: str,
    split: str,
    *,
    train: bool = False,
    upload: bool = False,
) -> dict:
    messages = [
        {"role": "system", "content": "Answer with reviewed evidence."},
        {"role": "user", "content": f"Evaluate {example_id}."},
        {"role": "assistant", "content": f"Reviewed answer for {example_id}."},
    ]
    evidence = [
        "knowledgeClass=candidate-stable",
        "Reviewed against the bound synthetic source.",
    ]
    rights = _rights(train=train, upload=upload)
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
                "title": "Synthetic reviewed source",
                "content": f"Reviewed source bytes for {example_id}.",
                "provenance": "Synthetic release test fixture.",
                "license": "Test-only license",
                "retrievedAtUtc": PRODUCED,
                "availableAtUtc": PRODUCED,
                "uri": None,
                "rights": rights,
            }
        ],
        "lineage": {
            "origin": "HumanAuthored",
            "producer": "fixture-author",
            "modelId": None,
            "modelRevision": None,
            "promptSha256": None,
            "profileVersion": None,
            "producedAtUtc": PRODUCED,
        },
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
        "provenance": "Synthetic rights-reviewed release fixture.",
        "license": "Test-only license",
        "rights": rights,
        "reviewStatus": "approved",
        "cutoffUtc": CUTOFF,
        "useForTraining": train,
    }


def _code_corpus_record(
    example_id: str,
    *,
    task_kind: str = "CodeGeneration",
) -> dict:
    record = _corpus_record(example_id, "development")
    source = "using DaxAlgo.Sdk; public sealed class ReviewedStrategy { }"
    record["taskKind"] = task_kind
    record["domains"] = ["CSharp"]
    record["messages"][-1]["content"] = source
    record["conversationSha256"] = expert_conversation_sha256(record["messages"])
    compile_evidence = [
        "profile=daxq-sdk-abi3-source/v1",
        f"sourceSha256={hashlib.sha256(source.encode('utf-8')).hexdigest()}",
        f"compilerClosureSha256={'1' * 64}",
        f"canonicalProgramSha256={'2' * 64}",
    ]
    test_evidence = [
        f"testSpecificationSha256={'3' * 64}",
        f"executionTraceSha256={'4' * 64}",
        f"executableResultSha256={'5' * 64}",
        "vectorCount=1",
        "callbackCount=1",
    ]
    verification = record["verification"]
    verification["compileSucceeded"] = True
    verification["compileEvidence"] = compile_evidence
    verification["testsPassed"] = True
    verification["testEvidence"] = test_evidence
    verification["evidenceSha256"] = _verification_evidence_sha256(
        verification["evidence"], compile_evidence, test_evidence
    )
    return record


def _task(
    record: dict,
    verifier_id: str,
    verifier_sha256: str,
    context_pack_sha256: str,
) -> dict:
    messages = record["messages"][:-1]
    task = {
        "schemaVersion": "daxalgo.vibe-quant.evaluation-task/v1",
        "taskId": f"task-{record['id']}",
        "taskSha256": "0" * 64,
        "split": record["split"],
        "taskKind": record["taskKind"],
        "domains": record["domains"],
        "messages": messages,
        "promptSha256": evaluation_prompt_sha256(messages),
        "contextPack": {
            "version": "reviewed-context-v1",
            "sha256": context_pack_sha256,
        },
        "verifier": {
            "id": verifier_id,
            "sha256": verifier_sha256,
            "requiredChecks": ["correct"],
        },
        "contaminationGroup": record["contaminationGroup"],
        "cutoffUtc": record["cutoffUtc"],
        "criticality": "standard",
        "maxOutputTokens": 512,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    return task


def _sft_row(record: dict, corpus_path: Path) -> dict:
    source_corpus_sha256 = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    return {
        "messages": record["messages"],
        "metadata": expert_model_sft_metadata(
            record, source_corpus_sha256=source_corpus_sha256
        ),
    }


def _write_jsonl(path: Path, *records: dict) -> None:
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


class CorpusCodeEvidenceValidationTests(unittest.TestCase):
    def test_structured_daxq_evidence_is_validated_before_detached_receipts(
        self,
    ) -> None:
        record = _code_corpus_record("valid-code-evidence")

        validated = _validate_corpus_record(record, 1)

        self.assertEqual(record["id"], validated.document["id"])

    def test_every_supported_corpus_label_combination_validates_structurally(
        self,
    ) -> None:
        cases = (
            ("GeneralQuestionAnswering", ["FinanceMarkets"]),
            ("RiskAnalysis", ["RiskManagement"]),
            ("GeneralQuestionAnswering", ["CSharp"]),
            ("GeneralQuestionAnswering", ["WpfUiDesign"]),
            ("WpfUiDesign", ["FinanceMarkets"]),
        )
        for index, (task_kind, domains) in enumerate(cases):
            with self.subTest(task_kind=task_kind, domains=domains):
                record = _corpus_record(f"receipt-label-{index}", "development")
                record["taskKind"] = task_kind
                record["domains"] = domains

                self.assertEqual(
                    record["id"], _validate_corpus_record(record, 1).document["id"]
                )

    def test_arbitrary_code_evidence_is_rejected_even_when_rehashed(self) -> None:
        record = _code_corpus_record("arbitrary-code-evidence")
        verification = record["verification"]
        verification["compileEvidence"] = ["compiled successfully"]
        verification["testEvidence"] = ["tests passed"]
        verification["evidenceSha256"] = _verification_evidence_sha256(
            verification["evidence"],
            verification["compileEvidence"],
            verification["testEvidence"],
        )

        with self.assertRaisesRegex(
            ValidationError, "exactly four executable-verifier entries"
        ):
            _validate_corpus_record(record, 1)

    def test_forged_source_binding_is_rejected_even_when_rehashed(self) -> None:
        record = _code_corpus_record("forged-source-binding", task_kind="CodeRepair")
        verification = record["verification"]
        verification["compileEvidence"][1] = f"sourceSha256={'f' * 64}"
        verification["evidenceSha256"] = _verification_evidence_sha256(
            verification["evidence"],
            verification["compileEvidence"],
            verification["testEvidence"],
        )

        with self.assertRaisesRegex(ValidationError, "exact assistant source"):
            _validate_corpus_record(record, 1)

    def test_code_review_has_no_supported_executable_profile(self) -> None:
        record = _code_corpus_record("unsupported-code-review", task_kind="CodeReview")

        with self.assertRaisesRegex(
            ValidationError, "CodeReview has no supported executable verifier profile"
        ):
            _validate_corpus_record(record, 1)

    def test_executable_callback_count_uses_the_worker_wide_bound(self) -> None:
        record = _code_corpus_record("oversized-callback-count")
        verification = record["verification"]
        verification["testEvidence"][4] = "callbackCount=513"
        verification["evidenceSha256"] = _verification_evidence_sha256(
            verification["evidence"],
            verification["compileEvidence"],
            verification["testEvidence"],
        )

        with self.assertRaisesRegex(ValidationError, "executable-callback bound"):
            _validate_corpus_record(record, 1)


class CorpusEvaluationReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output_root = self.root / "releases"
        self.output_root.mkdir()
        private_key = ec.generate_private_key(ec.SECP256R1())
        self.review_private_key = private_key
        self.private_key_path = self.root / "review-private.pem"
        self.public_key_path = self.root / "review-public.pem"
        self.private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        public_spki = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.review_receipt_trust = ExpertModelReviewReceiptTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=hashlib.sha256(public_spki).hexdigest(),
            audience=RECEIPT_AUDIENCE,
            key_id=RECEIPT_KEY_ID,
            signer_role=RECEIPT_SIGNER_ROLE,
        )
        authoring_private_key = ec.generate_private_key(ec.SECP256R1())
        self.authoring_private_key_path = self.root / "authoring-private.pem"
        self.authoring_public_key_path = self.root / "authoring-public.pem"
        self.authoring_private_key_path.write_bytes(
            authoring_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.authoring_public_key_path.write_bytes(
            authoring_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        authoring_spki = authoring_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.evaluation_authoring_approval_trust = EvaluationAuthoringApprovalTrust(
            public_key_path=self.authoring_public_key_path,
            public_key_spki_sha256=hashlib.sha256(authoring_spki).hexdigest(),
            audience=AUTHORING_AUDIENCE,
            key_id=AUTHORING_KEY_ID,
            signer_role=AUTHORING_SIGNER_ROLE,
        )
        self._authoring_approval_cache: dict[str, object] = {}
        self._authoring_approval_sequence = 0
        self._receipt_cache: dict[str, Path] = {}
        self._receipt_sequence = 0
        self.calibration_record = _corpus_record("calibration-1", "calibration")
        self.sealed_record = _corpus_record("sealed-1", "sealed")
        self.corpus_path = self.root / "expert-dataset.jsonl"
        _write_jsonl(self.corpus_path, self.calibration_record, self.sealed_record)

        self.calibration_tasks = self.root / "calibration.jsonl"
        self.sealed_tasks = self.root / "sealed.jsonl"
        self.asset_paths: dict[str, tuple[Path, Path, Path]] = {}
        tasks: dict[str, dict] = {}
        for record in (self.calibration_record, self.sealed_record):
            task_id = f"task-{record['id']}"
            rubric = self.root / f"{task_id}.rubric.txt"
            verifier = self.root / f"{task_id}.verifier.json"
            context_pack = self.root / f"{task_id}.context.txt"
            rubric.write_text(f"Reviewed rubric for {task_id}.\n", encoding="utf-8")
            verifier.write_text(
                json.dumps({"id": f"verifier-{task_id}", "checks": ["correct"]}) + "\n",
                encoding="utf-8",
            )
            context_pack.write_text(
                f"Reviewed inert context for {task_id}.\n", encoding="utf-8"
            )
            verifier_hash = hashlib.sha256(verifier.read_bytes()).hexdigest()
            context_pack_hash = hashlib.sha256(context_pack.read_bytes()).hexdigest()
            tasks[record["split"]] = _task(
                record,
                f"verifier-{task_id}",
                verifier_hash,
                context_pack_hash,
            )
            self.asset_paths[task_id] = (rubric, verifier, context_pack)
        _write_jsonl(self.calibration_tasks, tasks["calibration"])
        _write_jsonl(self.sealed_tasks, tasks["sealed"])

        self.bindings_path = self.root / "bindings.json"
        self._write_bindings()
        self.approval_evidence = self.root / "approval.txt"
        self.approval_evidence.write_text(
            "Approval ticket TEST-RELEASE-1 reviewed.\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_bindings(self) -> None:
        bindings = []
        for record in (self.calibration_record, self.sealed_record):
            task_id = f"task-{record['id']}"
            rubric, verifier, context_pack = self.asset_paths[task_id]
            bindings.append(
                {
                    "taskId": task_id,
                    "sourceExampleIds": [record["id"]],
                    "contextPack": {
                        "version": "reviewed-context-v1",
                        "path": str(context_pack),
                    },
                    "rubric": {"id": f"rubric-{task_id}", "path": str(rubric)},
                    "verifier": {"id": f"verifier-{task_id}", "path": str(verifier)},
                }
            )
        self.bindings_path.write_text(
            json.dumps(
                {"schemaVersion": TASK_BINDINGS_SCHEMA_VERSION, "bindings": bindings}
            ),
            encoding="utf-8",
        )

    def _receipts_for_corpus(self, corpus_path: Path) -> Path:
        corpus_sha256 = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
        cached = self._receipt_cache.get(corpus_sha256)
        if cached is not None:
            return cached
        self._receipt_sequence += 1
        output = self.root / f"review-receipts-{self._receipt_sequence}.jsonl"
        create_expert_model_review_receipts(
            dataset_path=corpus_path,
            output_path=output,
            private_key_path=self.private_key_path,
            public_key_path=self.public_key_path,
            private_key_password=None,
            audience=RECEIPT_AUDIENCE,
            key_id=RECEIPT_KEY_ID,
            signer_role=RECEIPT_SIGNER_ROLE,
            approval_id="TEST-RECEIPTS-1",
            actor_id="fixture-review-board",
            actor_role=RECEIPT_SIGNER_ROLE,
            approval_reference="review://receipts/TEST-RECEIPTS-1",
            approval_evidence_path=self.approval_evidence,
            approved_at_utc=APPROVED,
            issued_at_utc=RECEIPT_ISSUED,
            not_before_utc=RECEIPT_NOT_BEFORE,
            expires_at_utc=RECEIPT_EXPIRES,
            now=VALIDATION_TIME,
        )
        self._receipt_cache[corpus_sha256] = output
        return output

    def _rewrite_receipts_as_legacy_v1(
        self, receipts_path: Path, corpus_path: Path
    ) -> None:
        source_corpus_sha256 = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
        records = [json.loads(line) for line in corpus_path.read_bytes().splitlines()]
        envelopes = [
            json.loads(line) for line in receipts_path.read_bytes().splitlines()
        ]
        legacy_envelopes: list[dict] = []
        for envelope, record in zip(envelopes, records, strict=True):
            payload_bytes = urlsafe_b64decode(
                envelope["payload"] + "=" * (-len(envelope["payload"]) % 4)
            )
            payload = json.loads(payload_bytes)
            payload["schemaVersion"] = LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION
            payload["datasetSha256"] = payload.pop("sourceCorpusSha256")
            self.assertEqual(source_corpus_sha256, payload["datasetSha256"])
            payload["sftMetadataSha256"] = legacy_expert_model_sft_metadata_sha256(
                record
            )
            payload["receiptId"] = REVIEW_RECEIPT_ID_PREFIX + "0" * 64
            payload["receiptId"] = expert_model_review_receipt_id(payload)
            payload_bytes = canonical_json_bytes(payload)

            legacy = dict(envelope)
            legacy["schemaVersion"] = LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION
            legacy["payloadType"] = LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION
            legacy["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
            legacy["payload"] = urlsafe_b64encode(payload_bytes).decode().rstrip("=")
            legacy["signature"] = ""
            signature = review_receipts_module._sign_p1363_low_s(
                self.review_private_key,
                review_receipts_module._signature_input(legacy, payload_bytes),
            )
            legacy["signature"] = urlsafe_b64encode(signature).decode().rstrip("=")
            legacy_envelopes.append(legacy)
        receipts_path.write_bytes(
            b"".join(
                canonical_json_bytes(envelope) + b"\n" for envelope in legacy_envelopes
            )
        )

    def _downgrade_evaluation_release_to_v3(self, release_path: Path) -> Path:
        manifest_path = release_path / RELEASE_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_bytes())
        corpus_path = release_path.joinpath(
            *manifest["corpus"]["sourceDataset"]["path"].split("/")
        )
        receipts_path = release_path.joinpath(
            *manifest["corpus"]["reviewReceipts"]["path"].split("/")
        )
        self._rewrite_receipts_as_legacy_v1(receipts_path, corpus_path)
        receipt_binding = manifest["corpus"]["reviewReceipts"]
        receipt_binding["sha256"] = hashlib.sha256(
            receipts_path.read_bytes()
        ).hexdigest()
        receipt_binding["sizeBytes"] = receipts_path.stat().st_size
        manifest["schemaVersion"] = LEGACY_RELEASE_SCHEMA_VERSION
        del manifest["corpus"]["teacherLineageAdmission"]
        release_sha256 = corpus_evaluation_release_sha256(manifest)
        manifest["releaseSha256"] = release_sha256
        manifest["releaseId"] = f"vqrel-{release_sha256}"
        manifest_path.write_bytes(canonical_json_bytes(manifest))
        legacy_path = release_path.with_name(manifest["releaseId"])
        release_path.rename(legacy_path)
        return legacy_path

    def _create_authoring_approval(
        self,
        *,
        name: str,
        source_dataset_path: Path,
        calibration_tasks_path: Path,
        sealed_tasks_path: Path,
        task_bindings_path: Path,
        trust: EvaluationAuthoringApprovalTrust | None = None,
        private_key_path: Path | None = None,
        approved_at_utc: str | None = None,
        issued_at_utc: str | None = None,
        not_before_utc: str | None = None,
        expires_at_utc: str | None = None,
    ):
        selected_trust = trust or self.evaluation_authoring_approval_trust
        return create_evaluation_authoring_approval(
            output_path=self.root / f"{name}.json",
            private_key_path=private_key_path or self.authoring_private_key_path,
            public_key_path=selected_trust.public_key_path,
            public_key_spki_sha256=selected_trust.public_key_spki_sha256,
            private_key_password=None,
            audience=selected_trust.audience,
            key_id=selected_trust.key_id,
            signer_role=selected_trust.signer_role,
            approval_id="TEST-EVALUATION-AUTHORING-1",
            actor_id="fixture-evaluation-authoring-reviewer",
            actor_role=selected_trust.signer_role,
            approval_reference="review://evaluation-authoring/TEST-1",
            approved_at_utc=(
                AUTHORING_APPROVED if approved_at_utc is None else approved_at_utc
            ),
            issued_at_utc=(
                AUTHORING_ISSUED if issued_at_utc is None else issued_at_utc
            ),
            not_before_utc=(
                AUTHORING_NOT_BEFORE if not_before_utc is None else not_before_utc
            ),
            expires_at_utc=(
                AUTHORING_EXPIRES if expires_at_utc is None else expires_at_utc
            ),
            source_dataset_path=source_dataset_path,
            calibration_tasks_path=calibration_tasks_path,
            sealed_tasks_path=sealed_tasks_path,
            task_bindings_path=task_bindings_path,
            now=VALIDATION_TIME,
        )

    def _authoring_approval_for_arguments(self, arguments: dict):
        inventory = derive_evaluation_authoring_inventory(
            source_dataset_path=arguments["corpus_path"],
            calibration_tasks_path=arguments["calibration_tasks_path"],
            sealed_tasks_path=arguments["sealed_tasks_path"],
            task_bindings_path=arguments["task_bindings_path"],
        )
        cache_identity = {
            "inventory": inventory,
            "approvedAtUtc": AUTHORING_APPROVED,
            "issuedAtUtc": AUTHORING_ISSUED,
            "notBeforeUtc": AUTHORING_NOT_BEFORE,
            "expiresAtUtc": AUTHORING_EXPIRES,
            "trust": {
                "publicKeySpkiSha256": (
                    self.evaluation_authoring_approval_trust.public_key_spki_sha256
                ),
                "audience": self.evaluation_authoring_approval_trust.audience,
                "keyId": self.evaluation_authoring_approval_trust.key_id,
                "signerRole": self.evaluation_authoring_approval_trust.signer_role,
            },
        }
        inventory_sha256 = hashlib.sha256(
            canonical_json_bytes(cache_identity)
        ).hexdigest()
        cached = self._authoring_approval_cache.get(inventory_sha256)
        if cached is not None:
            return cached
        self._authoring_approval_sequence += 1
        verified = self._create_authoring_approval(
            name=f"evaluation-authoring-{self._authoring_approval_sequence}",
            source_dataset_path=Path(arguments["corpus_path"]),
            calibration_tasks_path=Path(arguments["calibration_tasks_path"]),
            sealed_tasks_path=Path(arguments["sealed_tasks_path"]),
            task_bindings_path=Path(arguments["task_bindings_path"]),
        )
        self._authoring_approval_cache[inventory_sha256] = verified
        return verified

    def _create(self, **overrides):
        arguments = {
            "corpus_path": self.corpus_path,
            "calibration_tasks_path": self.calibration_tasks,
            "sealed_tasks_path": self.sealed_tasks,
            "task_bindings_path": self.bindings_path,
            "evaluation_authoring_approval_trust": (
                self.evaluation_authoring_approval_trust
            ),
            "approval_evidence_path": self.approval_evidence,
            "output_root": self.output_root,
            "purpose": "local-evaluation",
            "cutoff_utc": CUTOFF,
            "approval_id": "TEST-RELEASE-1",
            "reviewer_id": "fixture-release-reviewer",
            "approved_at_utc": APPROVED,
            "sft_path": None,
            "review_receipt_trust": self.review_receipt_trust,
            "now": VALIDATION_TIME,
        }
        arguments.update(overrides)
        if "evaluation_authoring_approval_path" not in arguments:
            authoring = self._authoring_approval_for_arguments(arguments)
            arguments["evaluation_authoring_approval_path"] = authoring.path
            arguments.setdefault(
                "expected_evaluation_authoring_approval_envelope_sha256",
                authoring.envelope_sha256,
            )
        if "review_receipts_path" not in arguments:
            arguments["review_receipts_path"] = self._receipts_for_corpus(
                Path(arguments["corpus_path"])
            )
        return create_corpus_evaluation_release(**arguments)

    def _validate(self, path: str | Path, **overrides):
        arguments = {
            "review_receipt_trust": self.review_receipt_trust,
            "evaluation_authoring_approval_trust": (
                self.evaluation_authoring_approval_trust
            ),
            "now": VALIDATION_TIME,
        }
        arguments.update(overrides)
        return validate_corpus_evaluation_release(path, **arguments)

    def test_release_schema_is_machine_readable_and_strict(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "corpus-evaluation-release.v4.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            RELEASE_SCHEMA_VERSION, schema["properties"]["schemaVersion"]["const"]
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertTrue(
            schema["properties"]["approval"]["properties"]["declarativeOnly"]["const"]
        )
        self.assertIn("reviewReceipts", schema["properties"]["corpus"]["required"])
        self.assertIn(
            "teacherLineageAdmission",
            schema["properties"]["corpus"]["required"],
        )
        self.assertNotIn(
            "publicKeyPath", schema["$defs"]["externalTrust"]["properties"]
        )
        self.assertIn("contextPack", schema["$defs"]["taskBinding"]["required"])
        self.assertIn(
            "authoringApproval", schema["properties"]["evaluation"]["required"]
        )
        self.assertNotIn(
            "publicKeyPath",
            schema["$defs"]["externalTrust"]["properties"],
        )

        pending: list[object] = [schema]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                reference = node.get("$ref")
                if isinstance(reference, str) and reference.startswith("#/"):
                    target = schema
                    for segment in reference[2:].split("/"):
                        self.assertIn(segment, target, reference)
                        target = target[segment]
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)

    def test_release_cli_propagates_both_external_trust_roots(self) -> None:
        review_flags = [
            "--review-receipt-public-key",
            str(self.review_receipt_trust.public_key_path),
            "--review-receipt-public-key-spki-sha256",
            self.review_receipt_trust.public_key_spki_sha256,
            "--review-receipt-audience",
            self.review_receipt_trust.audience,
            "--review-receipt-key-id",
            self.review_receipt_trust.key_id,
            "--review-receipt-signer-role",
            self.review_receipt_trust.signer_role,
        ]
        authoring_flags = [
            "--evaluation-authoring-approval-public-key",
            str(self.evaluation_authoring_approval_trust.public_key_path),
            "--evaluation-authoring-approval-public-key-spki-sha256",
            self.evaluation_authoring_approval_trust.public_key_spki_sha256,
            "--evaluation-authoring-approval-audience",
            self.evaluation_authoring_approval_trust.audience,
            "--evaluation-authoring-approval-key-id",
            self.evaluation_authoring_approval_trust.key_id,
            "--evaluation-authoring-approval-signer-role",
            self.evaluation_authoring_approval_trust.signer_role,
        ]
        approval_path = self.root / "evaluation-authoring-approval.json"
        approval_envelope_sha256 = "a" * 64
        review_receipts_path = self.root / "review-receipts.jsonl"
        release_path = self.root / "release"

        stdout = io.StringIO()
        with (
            mock.patch.object(
                cli_module,
                "create_corpus_evaluation_release",
                return_value={"created": True},
            ) as create_release,
            redirect_stdout(stdout),
        ):
            self.assertEqual(
                0,
                cli_module.main(
                    [
                        "create-release",
                        "--corpus",
                        str(self.corpus_path),
                        "--review-receipts",
                        str(review_receipts_path),
                        *review_flags,
                        *authoring_flags,
                        "--calibration-tasks",
                        str(self.calibration_tasks),
                        "--sealed-tasks",
                        str(self.sealed_tasks),
                        "--task-bindings",
                        str(self.bindings_path),
                        "--evaluation-authoring-approval",
                        str(approval_path),
                        "--expected-evaluation-authoring-approval-envelope-sha256",
                        approval_envelope_sha256,
                        "--approval-evidence",
                        str(self.approval_evidence),
                        "--output-root",
                        str(self.output_root),
                        "--purpose",
                        "local-evaluation",
                        "--cutoff-utc",
                        CUTOFF,
                        "--approval-id",
                        "TEST-RELEASE-CLI",
                        "--reviewer-id",
                        "fixture-release-reviewer",
                        "--approved-at-utc",
                        APPROVED,
                    ]
                ),
            )
        self.assertEqual(
            self.review_receipt_trust,
            create_release.call_args.kwargs["review_receipt_trust"],
        )
        self.assertEqual(
            self.evaluation_authoring_approval_trust,
            create_release.call_args.kwargs["evaluation_authoring_approval_trust"],
        )
        self.assertEqual(
            approval_path,
            create_release.call_args.kwargs["evaluation_authoring_approval_path"],
        )
        self.assertEqual(
            approval_envelope_sha256,
            create_release.call_args.kwargs[
                "expected_evaluation_authoring_approval_envelope_sha256"
            ],
        )

        stdout = io.StringIO()
        with (
            mock.patch.object(
                cli_module,
                "validate_corpus_evaluation_release",
                return_value={
                    "releaseId": "vqrel-test",
                    "releaseSha256": "b" * 64,
                    "purpose": "local-evaluation",
                },
            ) as validate_release,
            redirect_stdout(stdout),
        ):
            self.assertEqual(
                0,
                cli_module.main(
                    [
                        "validate-release",
                        str(release_path),
                        *review_flags,
                        *authoring_flags,
                    ]
                ),
            )
        self.assertEqual(
            self.review_receipt_trust,
            validate_release.call_args.kwargs["review_receipt_trust"],
        )
        self.assertEqual(
            self.evaluation_authoring_approval_trust,
            validate_release.call_args.kwargs["evaluation_authoring_approval_trust"],
        )

    def test_numeric_rights_policy_values_do_not_satisfy_boolean_contract(self) -> None:
        created = self._create()
        manifest = json.loads(
            (Path(created["releasePath"]) / RELEASE_MANIFEST_PATH).read_text(
                encoding="utf-8"
            )
        )
        for name, expected in manifest["rightsPolicy"].items():
            with self.subTest(name=name):
                numeric = json.loads(json.dumps(manifest))
                numeric["rightsPolicy"][name] = 1 if expected else 0
                release_sha256 = corpus_evaluation_release_sha256(numeric)
                numeric["releaseSha256"] = release_sha256
                numeric["releaseId"] = f"vqrel-{release_sha256}"
                with self.assertRaisesRegex(ValidationError, "rightsPolicy"):
                    _validate_release_document(numeric)

    def test_release_is_content_addressed_valid_and_never_clobbered(self) -> None:
        created = self._create()
        release_path = Path(created["releasePath"])
        release = self._validate(release_path)

        self.assertEqual(RELEASE_SCHEMA_VERSION, release["schemaVersion"])
        self.assertIsNone(release["corpus"]["teacherLineageAdmission"])
        self.assertEqual(f"vqrel-{release['releaseSha256']}", release["releaseId"])
        self.assertEqual(release["releaseId"], release_path.name)
        self.assertTrue(release["approval"]["declarativeOnly"])
        self.assertEqual(
            self.review_receipt_trust.manifest_identity(),
            release["corpus"]["reviewReceipts"]["trust"],
        )
        self.assertEqual(
            RECEIPT_EXPIRES,
            release["corpus"]["reviewReceipts"]["expiresAtUtc"],
        )
        authoring = release["evaluation"]["authoringApproval"]
        self.assertEqual(
            AUTHORING_EXPIRES,
            authoring["expiresAtUtc"],
        )
        self.assertEqual(
            self.evaluation_authoring_approval_trust.public_key_spki_sha256,
            authoring["trust"]["publicKeySpkiSha256"],
        )
        self.assertEqual(
            created["evaluationAuthoringApprovalEnvelopeSha256"],
            authoring["envelopeSha256"],
        )
        self.assertNotIn(
            str(self.public_key_path),
            json.dumps(release, sort_keys=True),
        )
        self.assertNotIn(
            str(self.authoring_public_key_path),
            json.dumps(release, sort_keys=True),
        )
        manifest_bytes = (release_path / RELEASE_MANIFEST_PATH).read_bytes()

        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._create()
        self.assertEqual(
            manifest_bytes, (release_path / RELEASE_MANIFEST_PATH).read_bytes()
        )

    def test_release_preserves_relative_binding_asset_resolution_when_snapshotting(
        self,
    ) -> None:
        document = json.loads(self.bindings_path.read_text(encoding="utf-8"))
        document["schemaVersion"] = TASK_BINDINGS_V2_SCHEMA_VERSION
        for binding in document["bindings"]:
            for kind in ("contextPack", "rubric", "verifier"):
                binding[kind]["path"] = Path(binding[kind]["path"]).name
        relative_bindings = self.root / "relative-bindings.json"
        relative_bindings.write_text(json.dumps(document), encoding="utf-8")

        created = self._create(task_bindings_path=relative_bindings)

        release = self._validate(created["releasePath"])
        self.assertEqual(RELEASE_SCHEMA_VERSION, release["schemaVersion"])
        self.assertEqual(
            {"task-calibration-1", "task-sealed-1"},
            {binding["taskId"] for binding in release["evaluation"]["taskBindings"]},
        )

    def test_v2_task_binding_runtime_limits_match_schema(self) -> None:
        document = json.loads(self.bindings_path.read_text(encoding="utf-8"))
        document["schemaVersion"] = TASK_BINDINGS_V2_SCHEMA_VERSION
        bounded_path = self.root / "bounded-bindings.json"
        bounded_path.write_text(json.dumps(document), encoding="utf-8")

        with mock.patch.object(release_module, "MAX_TASK_BINDINGS", 1):
            with self.assertRaisesRegex(ValidationError, "1 to 1 bindings"):
                release_module._load_task_binding_input(bounded_path)

        document["bindings"] = document["bindings"][:1]
        document["bindings"][0]["sourceExampleIds"].append("second-source-id")
        bounded_path.write_text(json.dumps(document), encoding="utf-8")
        with mock.patch.object(release_module, "MAX_SOURCE_EXAMPLE_IDS", 1):
            with self.assertRaisesRegex(ValidationError, "1 to 1 unique source IDs"):
                release_module._load_task_binding_input(bounded_path)

    def test_human_release_rejects_lineage_path_or_nested_trust(self) -> None:
        with self.assertRaisesRegex(ValidationError, "HumanAuthored-only"):
            self._create(
                teacher_lineage_admission_path=self.approval_evidence,
            )

        lineage_trust = TeacherMaterializationLineageAdmissionTrust(
            public_key_path=self.authoring_public_key_path,
            public_key_spki_sha256=(
                self.evaluation_authoring_approval_trust.public_key_spki_sha256
            ),
            audience="daxalgo-vibe-quant-review-receipts",
            key_id="teacher-lineage-review-key-2025-01",
            signer_role="teacher-lineage-reviewer",
        )
        nested_trust = ExpertModelReviewReceiptTrust(
            public_key_path=self.review_receipt_trust.public_key_path,
            public_key_spki_sha256=(self.review_receipt_trust.public_key_spki_sha256),
            audience=self.review_receipt_trust.audience,
            key_id=self.review_receipt_trust.key_id,
            signer_role=self.review_receipt_trust.signer_role,
            teacher_lineage_admission_trust=lineage_trust,
        )
        with self.assertRaisesRegex(ValidationError, "HumanAuthored-only"):
            self._create(review_receipt_trust=nested_trust)

    def test_v4_teacher_release_bundles_and_revalidates_exact_admission(self) -> None:
        tests_directory = str(Path(__file__).resolve().parent)
        sys.path.insert(0, tests_directory)
        try:
            import test_teacher_lineage as lineage_test_module
        finally:
            sys.path.remove(tests_directory)

        lineage_fixture = lineage_test_module.TeacherLineageTests(
            "test_round_trip_binds_one_package_and_supports_snapshot_consumer"
        )
        lineage_fixture.setUp()
        try:
            reviewed_rows = [
                self.calibration_record,
                self.sealed_record,
                *lineage_fixture.reviewed,
            ]
            lineage_fixture._write_rows(
                lineage_fixture.dataset_path,
                reviewed_rows,
            )
            admission = lineage_fixture._create()
            nested_trust = ExpertModelReviewReceiptTrust(
                public_key_path=self.review_receipt_trust.public_key_path,
                public_key_spki_sha256=(
                    self.review_receipt_trust.public_key_spki_sha256
                ),
                audience=self.review_receipt_trust.audience,
                key_id=self.review_receipt_trust.key_id,
                signer_role=self.review_receipt_trust.signer_role,
                teacher_lineage_admission_trust=lineage_fixture.trust,
            )
            receipts_path = self.root / "teacher-review-receipts.jsonl"
            create_expert_model_review_receipts(
                dataset_path=lineage_fixture.dataset_path,
                output_path=receipts_path,
                private_key_path=self.private_key_path,
                public_key_path=self.public_key_path,
                private_key_password=None,
                audience=RECEIPT_AUDIENCE,
                key_id=RECEIPT_KEY_ID,
                signer_role=RECEIPT_SIGNER_ROLE,
                approval_id="TEST-TEACHER-RECEIPTS-1",
                actor_id="fixture-teacher-review-board",
                actor_role=RECEIPT_SIGNER_ROLE,
                approval_reference="review://receipts/TEST-TEACHER-RECEIPTS-1",
                approval_evidence_path=self.approval_evidence,
                approved_at_utc="2026-01-04T00:00:03Z",
                issued_at_utc="2026-01-04T00:00:04Z",
                not_before_utc="2026-01-04T00:00:05Z",
                expires_at_utc="2027-01-04T00:00:01Z",
                teacher_lineage_admission_path=lineage_fixture.admission_path,
                teacher_materialization_path=lineage_fixture.fixture.output_path,
                teacher_runtime_binding_path=(
                    lineage_fixture.fixture.runtime_binding_path
                ),
                teacher_lineage_reviewer_evidence_path=(lineage_fixture.evidence_path),
                teacher_lineage_admission_trust=lineage_fixture.trust,
                now=datetime(2026, 1, 5, tzinfo=timezone.utc),
            )
            created = self._create(
                corpus_path=lineage_fixture.dataset_path,
                review_receipts_path=receipts_path,
                review_receipt_trust=nested_trust,
                teacher_lineage_admission_path=lineage_fixture.admission_path,
                cutoff_utc="2026-01-02T00:00:00Z",
                approved_at_utc="2026-01-05T00:00:00Z",
                now=datetime(2026, 1, 5, tzinfo=timezone.utc),
            )
            release_path = Path(created["releasePath"])
            release = self._validate(
                release_path,
                review_receipt_trust=nested_trust,
                now=datetime(2026, 1, 5, tzinfo=timezone.utc),
            )
            binding = release["corpus"]["teacherLineageAdmission"]
            self.assertEqual(
                admission.payload["lineageAdmissionId"],
                binding["lineageAdmissionId"],
            )
            self.assertEqual(
                lineage_fixture.admission_path.read_bytes(),
                release_path.joinpath(*binding["path"].split("/")).read_bytes(),
            )
            self.assertEqual(1, binding["openWeightTeacherRecordCount"])

            bundled = release_path.joinpath(*binding["path"].split("/"))
            bundled.write_bytes(bundled.read_bytes() + b"tampered")
            with self.assertRaisesRegex(ValidationError, "bound file"):
                self._validate(
                    release_path,
                    review_receipt_trust=nested_trust,
                    now=datetime(2026, 1, 5, tzinfo=timezone.utc),
                )
        finally:
            lineage_fixture.tearDown()

    def test_legacy_v3_is_structurally_valid_but_cannot_return_identity(self) -> None:
        created = self._create()
        legacy_path = self._downgrade_evaluation_release_to_v3(
            Path(created["releasePath"])
        )

        archived = self._validate(legacy_path)
        self.assertEqual(LEGACY_RELEASE_SCHEMA_VERSION, archived["schemaVersion"])
        with self.assertRaisesRegex(ValidationError, "archival-only"):
            validate_corpus_evaluation_release_with_identity(
                legacy_path,
                review_receipt_trust=self.review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    self.evaluation_authoring_approval_trust
                ),
                now=VALIDATION_TIME,
            )

    def test_legacy_v3_hosted_teacher_release_fails_before_receipt_validation(
        self,
    ) -> None:
        created = self._create()
        release_path = Path(created["releasePath"])
        manifest_path = release_path / RELEASE_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        corpus_path = release_path.joinpath(
            *manifest["corpus"]["sourceDataset"]["path"].split("/")
        )
        rows = [json.loads(line) for line in corpus_path.read_text().splitlines()]
        rows[0]["lineage"] = {
            "origin": "HostedTeacher",
            "producer": "legacy-hosted-teacher-fixture",
            "modelId": "hosted-teacher-fixture-model",
            "modelRevision": "hosted-snapshot-2025-01",
            "promptSha256": "b" * 64,
            "profileVersion": "hosted-teacher-fixture-profile-v1",
            "producedAtUtc": PRODUCED,
        }
        _write_jsonl(corpus_path, *rows)
        source = manifest["corpus"]["sourceDataset"]
        source["sha256"] = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
        source["sizeBytes"] = corpus_path.stat().st_size
        manifest["schemaVersion"] = LEGACY_RELEASE_SCHEMA_VERSION
        del manifest["corpus"]["teacherLineageAdmission"]
        release_sha256 = corpus_evaluation_release_sha256(manifest)
        manifest["releaseSha256"] = release_sha256
        manifest["releaseId"] = f"vqrel-{release_sha256}"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        legacy_path = release_path.with_name(manifest["releaseId"])
        release_path.rename(legacy_path)

        with self.assertRaisesRegex(ValidationError, "legacy v3.*all-HumanAuthored"):
            self._validate(legacy_path)

    def test_bound_bytes_and_unknown_files_fail_closed(self) -> None:
        created = self._create()
        release_path = Path(created["releasePath"])
        release = self._validate(release_path)
        rubric_path = release_path.joinpath(
            *release["evaluation"]["taskBindings"][0]["rubric"]["path"].split("/")
        )
        original = rubric_path.read_bytes()
        rubric_path.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(ValidationError, "bound file"):
            self._validate(release_path)

        rubric_path.write_bytes(original)
        (release_path / "unexpected.txt").write_text("not bound", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "unexpected"):
            self._validate(release_path)

    def test_receipt_trust_expiry_tamper_and_missing_file_fail_closed(self) -> None:
        created = self._create()
        release_path = Path(created["releasePath"])
        release = self._validate(release_path)

        other_key = ec.generate_private_key(ec.SECP256R1())
        other_public = self.root / "other-review-public.pem"
        other_public.write_bytes(
            other_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        other_spki = other_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        wrong_trust = ExpertModelReviewReceiptTrust(
            public_key_path=other_public,
            public_key_spki_sha256=hashlib.sha256(other_spki).hexdigest(),
            audience=RECEIPT_AUDIENCE,
            key_id=RECEIPT_KEY_ID,
            signer_role=RECEIPT_SIGNER_ROLE,
        )
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            self._validate(release_path, review_receipt_trust=wrong_trust)

        with self.assertRaisesRegex(ValidationError, "not currently active"):
            self._validate(
                release_path,
                now=datetime(2026, 1, 20, 12, 0, 2, tzinfo=timezone.utc),
            )

        receipt_path = release_path.joinpath(
            *release["corpus"]["reviewReceipts"]["path"].split("/")
        )
        original = receipt_path.read_bytes()
        receipt_path.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(ValidationError, "bound file"):
            self._validate(release_path)
        receipt_path.write_bytes(original)
        receipt_path.unlink()
        with self.assertRaises(ValidationError):
            self._validate(release_path)

    def test_authoring_approval_trust_expiry_tamper_and_missing_file_fail_closed(
        self,
    ) -> None:
        short_lived = self._create_authoring_approval(
            name="short-lived-authoring",
            source_dataset_path=self.corpus_path,
            calibration_tasks_path=self.calibration_tasks,
            sealed_tasks_path=self.sealed_tasks,
            task_bindings_path=self.bindings_path,
            expires_at_utc="2025-02-02T00:00:00Z",
        )
        created = self._create(
            evaluation_authoring_approval_path=short_lived.path,
            expected_evaluation_authoring_approval_envelope_sha256=(
                short_lived.envelope_sha256
            ),
        )
        release_path = Path(created["releasePath"])
        release = self._validate(release_path)

        other_key = ec.generate_private_key(ec.SECP256R1())
        other_public = self.root / "other-authoring-public.pem"
        other_public.write_bytes(
            other_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        other_spki = other_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        wrong_trust = EvaluationAuthoringApprovalTrust(
            public_key_path=other_public,
            public_key_spki_sha256=hashlib.sha256(other_spki).hexdigest(),
            audience=AUTHORING_AUDIENCE,
            key_id=AUTHORING_KEY_ID,
            signer_role=AUTHORING_SIGNER_ROLE,
        )
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            self._validate(
                release_path,
                evaluation_authoring_approval_trust=wrong_trust,
            )

        with self.assertRaisesRegex(ValidationError, "is not active"):
            self._validate(
                release_path,
                now=datetime(2025, 2, 3, tzinfo=timezone.utc),
            )

        approval_path = release_path.joinpath(
            *release["evaluation"]["authoringApproval"]["path"].split("/")
        )
        original = approval_path.read_bytes()
        approval_path.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(ValidationError, "bound file"):
            self._validate(release_path)
        approval_path.write_bytes(original)
        approval_path.unlink()
        with self.assertRaises(ValidationError):
            self._validate(release_path)

    def test_authoring_approval_binds_inventory_timeline_and_distinct_signer(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValidationError, "trusted exact SHA-256"):
            self._create(
                expected_evaluation_authoring_approval_envelope_sha256="f" * 64
            )

        original = self._authoring_approval_for_arguments(
            {
                "corpus_path": self.corpus_path,
                "calibration_tasks_path": self.calibration_tasks,
                "sealed_tasks_path": self.sealed_tasks,
                "task_bindings_path": self.bindings_path,
            }
        )
        rubric = self.asset_paths["task-calibration-1"][0]
        rubric.write_bytes(rubric.read_bytes() + b"changed after approval")
        with self.assertRaisesRegex(ValidationError, "exact live.*inventory"):
            self._create(
                evaluation_authoring_approval_path=original.path,
                expected_evaluation_authoring_approval_envelope_sha256=(
                    original.envelope_sha256
                ),
            )
        rubric.write_text("Reviewed rubric for task-calibration-1.\n", encoding="utf-8")

        late = self._create_authoring_approval(
            name="late-authoring",
            source_dataset_path=self.corpus_path,
            calibration_tasks_path=self.calibration_tasks,
            sealed_tasks_path=self.sealed_tasks,
            task_bindings_path=self.bindings_path,
            approved_at_utc="2025-01-20T12:30:00Z",
            issued_at_utc="2025-01-20T12:31:00Z",
            not_before_utc="2025-01-21T00:00:00Z",
        )
        with self.assertRaisesRegex(
            ValidationError, "must not precede.*authoring approval activation"
        ):
            self._create(
                evaluation_authoring_approval_path=late.path,
                expected_evaluation_authoring_approval_envelope_sha256=(
                    late.envelope_sha256
                ),
            )

        same_signer_trust = EvaluationAuthoringApprovalTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.review_receipt_trust.public_key_spki_sha256,
            audience=AUTHORING_AUDIENCE,
            key_id=AUTHORING_KEY_ID,
            signer_role=AUTHORING_SIGNER_ROLE,
        )
        same_signer = self._create_authoring_approval(
            name="same-signer-authoring",
            source_dataset_path=self.corpus_path,
            calibration_tasks_path=self.calibration_tasks,
            sealed_tasks_path=self.sealed_tasks,
            task_bindings_path=self.bindings_path,
            trust=same_signer_trust,
            private_key_path=self.private_key_path,
        )
        with self.assertRaisesRegex(
            ValidationError, "must differ from the expert review-receipt signer"
        ):
            self._create(
                evaluation_authoring_approval_path=same_signer.path,
                evaluation_authoring_approval_trust=same_signer_trust,
                expected_evaluation_authoring_approval_envelope_sha256=(
                    same_signer.envelope_sha256
                ),
            )

    def test_release_creation_rejects_a_receipt_set_missing_one_corpus_row(
        self,
    ) -> None:
        complete = self._receipts_for_corpus(self.corpus_path)
        lines = complete.read_bytes().splitlines(keepends=True)
        partial = self.root / "partial-review-receipts.jsonl"
        partial.write_bytes(b"".join(lines[:-1]))

        with self.assertRaisesRegex(ValidationError, "exactly one receipt"):
            self._create(review_receipts_path=partial)
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_task_verifier_must_equal_the_exact_inert_verifier_bytes(self) -> None:
        task = json.loads(self.calibration_tasks.read_text(encoding="utf-8"))
        task["verifier"]["sha256"] = "f" * 64
        task["taskSha256"] = evaluation_task_sha256(task)
        _write_jsonl(self.calibration_tasks, task)

        with self.assertRaisesRegex(ValidationError, "exact task verifier bytes"):
            self._create()
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_task_context_pack_must_equal_the_exact_inert_bytes(self) -> None:
        task = json.loads(self.calibration_tasks.read_text(encoding="utf-8"))
        task["contextPack"]["sha256"] = "f" * 64
        task["taskSha256"] = evaluation_task_sha256(task)
        _write_jsonl(self.calibration_tasks, task)

        with self.assertRaisesRegex(ValidationError, "exact task context-pack bytes"):
            self._create()
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_review_rights_and_cutoff_mismatches_fail_before_publication(self) -> None:
        self.calibration_record["reviewStatus"] = "pending"
        _write_jsonl(self.corpus_path, self.calibration_record, self.sealed_record)
        with self.assertRaisesRegex(ValidationError, "must be exactly 'approved'"):
            self._create()
        self.assertEqual([], list(self.output_root.iterdir()))

        self.calibration_record["reviewStatus"] = "approved"
        _write_jsonl(self.corpus_path, self.calibration_record, self.sealed_record)
        with self.assertRaisesRegex(ValidationError, "provider-upload rights"):
            self._create(purpose="provider-evaluation")
        self.assertEqual([], list(self.output_root.iterdir()))

        task = json.loads(self.calibration_tasks.read_text(encoding="utf-8"))
        task["cutoffUtc"] = "2025-01-14T12:00:00Z"
        task["taskSha256"] = evaluation_task_sha256(task)
        _write_jsonl(self.calibration_tasks, task)
        with self.assertRaisesRegex(ValidationError, "different cutoff"):
            self._create()
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_training_release_binds_exact_sft_rows_and_training_rights(self) -> None:
        development = _corpus_record("development-1", "development", train=True)
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        sft_path = self.root / "dataset.sft.jsonl"
        _write_jsonl(sft_path, _sft_row(development, self.corpus_path))

        created = self._create(
            purpose="local-training-evaluation",
            sft_path=sft_path,
        )
        release = self._validate(created["releasePath"])
        self.assertEqual(1, release["corpus"]["sft"]["recordCount"])
        self.assertTrue(release["rightsPolicy"]["requireTrainingForSft"])
        metadata = json.loads(sft_path.read_text())["metadata"]
        self.assertEqual(
            hashlib.sha256(self.corpus_path.read_bytes()).hexdigest(),
            metadata["sourceCorpusSha256"],
        )
        self.assertEqual(
            development["verification"]["evidenceSha256"],
            metadata["verificationEvidenceSha256"],
        )

        provider_root = self.root / "provider-releases"
        provider_root.mkdir()
        with self.assertRaisesRegex(ValidationError, "providerUpload"):
            self._create(
                purpose="provider-training-evaluation",
                sft_path=sft_path,
                output_root=provider_root,
            )
        self.assertEqual([], list(provider_root.iterdir()))

    def test_training_release_rejects_sft_source_and_evidence_substitution(
        self,
    ) -> None:
        development = _corpus_record(
            "development-source-bound", "development", train=True
        )
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        original = _sft_row(development, self.corpus_path)
        sft_path = self.root / "source-bound.sft.jsonl"
        cases = (
            ("sourceCorpusSha256", "a" * 64, "sourceCorpusSha256"),
            (
                "verificationEvidenceSha256",
                "b" * 64,
                "verificationEvidenceSha256",
            ),
        )
        for name, value, message in cases:
            with self.subTest(name=name):
                row = json.loads(json.dumps(original))
                row["metadata"][name] = value
                _write_jsonl(sft_path, row)
                with self.assertRaisesRegex(ValidationError, message):
                    self._create(
                        purpose="local-training-evaluation",
                        sft_path=sft_path,
                    )
                self.assertEqual([], list(self.output_root.iterdir()))

    def test_training_release_rejects_under_authorized_receipt(self) -> None:
        development = _corpus_record("development-under-authorized", "development")
        development["useForTraining"] = True
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        sft_path = self.root / "under-authorized.sft.jsonl"
        _write_jsonl(sft_path, _sft_row(development, self.corpus_path))

        with self.assertRaisesRegex(ValidationError, "authorizations.training"):
            self._create(
                purpose="local-training-evaluation",
                sft_path=sft_path,
            )
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_training_sft_must_preserve_corpus_order_and_exact_conversation(
        self,
    ) -> None:
        first = _corpus_record("development-first", "development", train=True)
        second = _corpus_record("development-second", "development", train=True)
        _write_jsonl(
            self.corpus_path,
            first,
            second,
            self.calibration_record,
            self.sealed_record,
        )
        sft_path = self.root / "ordered.sft.jsonl"
        _write_jsonl(
            sft_path,
            _sft_row(second, self.corpus_path),
            _sft_row(first, self.corpus_path),
        )
        with self.assertRaisesRegex(ValidationError, "exact source order"):
            self._create(purpose="local-training-evaluation", sft_path=sft_path)

        first_row = _sft_row(first, self.corpus_path)
        first_row["messages"][-1]["content"] = "substituted assistant response"
        _write_jsonl(sft_path, first_row, _sft_row(second, self.corpus_path))
        with self.assertRaisesRegex(ValidationError, "receipt-bound conversation"):
            self._create(purpose="local-training-evaluation", sft_path=sft_path)
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_training_release_requires_candidate_stable_knowledge_class(self) -> None:
        development = _corpus_record("development-1", "development", train=True)
        sft_path = self.root / "dataset.sft.jsonl"
        _write_jsonl(sft_path, _sft_row(development, self.corpus_path))

        development["verification"]["evidence"][0] = "knowledgeClass=retrieval-only"
        development["verification"]["evidenceSha256"] = _verification_evidence_sha256(
            development["verification"]["evidence"], [], []
        )
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        with self.assertRaisesRegex(ValidationError, "retrieval-only examples"):
            self._create(purpose="local-training-evaluation", sft_path=sft_path)
        self.assertEqual([], list(self.output_root.iterdir()))

        development["verification"]["evidence"] = [
            "Reviewed against the bound synthetic source."
        ]
        development["verification"]["evidenceSha256"] = _verification_evidence_sha256(
            development["verification"]["evidence"], [], []
        )
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        with self.assertRaisesRegex(ValidationError, "candidate-stable"):
            self._create(purpose="local-training-evaluation", sft_path=sft_path)
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_training_release_rejects_sft_lineage_substitution(self) -> None:
        development = _corpus_record("development-1", "development", train=True)
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        row = _sft_row(development, self.corpus_path)
        row["metadata"]["producer"] = "different-valid-producer"
        sft_path = self.root / "dataset.sft.jsonl"
        _write_jsonl(sft_path, row)

        with self.assertRaisesRegex(ValidationError, "producer.*does not match"):
            self._create(
                purpose="local-training-evaluation",
                sft_path=sft_path,
            )
        self.assertEqual([], list(self.output_root.iterdir()))

    def test_release_bound_v1_manifest_is_still_rejected_for_non_smoke_training(
        self,
    ) -> None:
        development = _corpus_record("development-1", "development", train=True)
        development["domains"] = list(DOMAINS)
        _write_jsonl(
            self.corpus_path, development, self.calibration_record, self.sealed_record
        )
        sft_path = self.root / "dataset.sft.jsonl"
        _write_jsonl(sft_path, _sft_row(development, self.corpus_path))
        created = self._create(
            purpose="local-training-evaluation",
            sft_path=sft_path,
        )

        catalog = json.loads(
            (
                Path(__file__).resolve().parents[1] / "candidate-catalog.v1.json"
            ).read_text(encoding="utf-8")
        )
        catalog_path = self.root / "catalog.json"
        catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
        template_path = self.root / "template.jinja"
        template_path.write_text(
            "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}",
            encoding="utf-8",
        )
        bundle = self.root / "training-bundle"
        create_bundle(
            catalog_path=catalog_path,
            sft_path=sft_path,
            candidate_id="qwen2.5-coder-7b-instruct",
            chat_template_path=template_path,
            chat_template_name="reviewed-test-template-v1",
            output_directory=bundle,
            runtime_profile_path=Path(__file__).resolve().parents[1]
            / "training-runtime-profile.v1.json",
            data_release_path=created["releasePath"],
            review_receipt_trust=self.review_receipt_trust,
            evaluation_authoring_approval_trust=(
                self.evaluation_authoring_approval_trust
            ),
            review_receipt_now=VALIDATION_TIME,
        )
        manifest_path = bundle / "training-run-manifest.json"
        manifest = validate_manifest_path(manifest_path)
        self.assertEqual(
            {
                "releaseId": created["releaseId"],
                "releaseSha256": created["releaseSha256"],
                "manifestSha256": created["manifestSha256"],
            },
            manifest["dataRelease"],
        )

        with self.assertRaisesRegex(ValidationError, "release path is required"):
            train_from_manifest(manifest_path, importer=lambda name: None)

        other_root = self.root / "other-releases"
        other_root.mkdir()
        other = self._create(
            purpose="local-training-evaluation",
            sft_path=sft_path,
            output_root=other_root,
            approval_id="TEST-RELEASE-2",
        )
        with self.assertRaisesRegex(
            ValidationError, "fully validated training release"
        ):
            train_from_manifest(
                manifest_path,
                data_release_path=other["releasePath"],
                review_receipt_trust=self.review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    self.evaluation_authoring_approval_trust
                ),
                review_receipt_now=VALIDATION_TIME,
                importer=lambda name: None,
            )

        with self.assertRaisesRegex(
            ValidationError, "legacy v1 manifests are restricted"
        ):
            train_from_manifest(
                manifest_path,
                data_release_path=created["releasePath"],
                review_receipt_trust=self.review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    self.evaluation_authoring_approval_trust
                ),
                review_receipt_now=VALIDATION_TIME,
                importer=lambda name: self.fail(
                    f"legacy manifest reached dependency import: {name}"
                ),
            )

    def test_manifest_identity_tampering_is_rejected(self) -> None:
        created = self._create()
        release_path = Path(created["releasePath"])
        manifest_path = release_path / RELEASE_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["approval"]["reviewerId"] = "different-reviewer"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "canonical release"):
            self._validate(release_path)

    def test_legacy_v1_and_v2_manifests_are_not_accepted_as_authenticated(
        self,
    ) -> None:
        created = self._create()
        release_path = Path(created["releasePath"])
        manifest_path = release_path / RELEASE_MANIFEST_PATH
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for version in ("v1", "v2"):
            with self.subTest(version=version):
                legacy = dict(manifest)
                legacy["schemaVersion"] = (
                    f"daxalgo.vibe-quant.corpus-evaluation-release/{version}"
                )
                manifest_path.write_text(json.dumps(legacy), encoding="utf-8")
                with self.assertRaisesRegex(ValidationError, "schemaVersion"):
                    self._validate(release_path)


if __name__ == "__main__":
    unittest.main()
