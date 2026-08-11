from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import jsonschema
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

import hyperion_model.cli as cli_module
import hyperion_model.evaluation_authoring as authoring_module
from hyperion_model.core import (
    ValidationError,
    canonical_json_bytes,
    expert_conversation_sha256,
)
from hyperion_model.evaluation import evaluation_prompt_sha256, evaluation_task_sha256
from hyperion_model.evaluation_authoring import (
    EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION,
    EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
    EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT,
    EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
    EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION,
    EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION,
    EvaluationAuthoringApprovalTrust,
    create_evaluation_authoring_approval,
    derive_evaluation_authoring_inventory,
    evaluation_authoring_approval_id,
    evaluation_authoring_approval_signature_id,
    evaluation_authoring_approval_signing_bundle_id,
    finalize_evaluation_authoring_approval,
    prepare_evaluation_authoring_approval_signing_bundle,
    validate_evaluation_authoring_approval,
    validate_evaluation_authoring_approval_for_inventory,
)
from hyperion_model.release import (
    TASK_BINDINGS_SCHEMA_VERSION,
    _verification_evidence_sha256,
)


CUTOFF = "2025-01-15T12:00:00Z"
PRODUCED = "2025-01-14T12:00:00Z"
VERIFIED = "2025-01-16T12:00:00Z"
APPROVED = "2025-01-20T12:00:00Z"
ISSUED = "2025-01-20T12:00:01Z"
NOT_BEFORE = "2025-01-20T12:00:02Z"
EXPIRES = "2026-01-20T12:00:02Z"
NOW = datetime(2025, 2, 1, tzinfo=timezone.utc)
AUDIENCE = "evaluation-release-v3"
KEY_ID = "evaluation-authoring-key-2025-01"
SIGNER_ROLE = "independent-evaluation-author"
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _rights() -> dict[str, bool]:
    return {
        "mayStore": True,
        "mayEvaluate": True,
        "mayTrain": False,
        "mayUploadToProvider": False,
        "mayRedistribute": False,
    }


def _record(example_id: str, split: str) -> dict:
    messages = [
        {"role": "system", "content": "Answer with reviewed evidence."},
        {"role": "user", "content": f"Evaluate {example_id}."},
        {"role": "assistant", "content": f"Reviewed answer for {example_id}."},
    ]
    evidence = [
        "knowledgeClass=candidate-stable",
        "Reviewed against the exact bound test source.",
    ]
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
                "provenance": "Synthetic evaluation-authoring fixture.",
                "license": "Test-only license",
                "retrievedAtUtc": PRODUCED,
                "availableAtUtc": PRODUCED,
                "uri": None,
                "rights": _rights(),
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
        "provenance": "Synthetic reviewed fixture.",
        "license": "Test-only license",
        "rights": _rights(),
        "reviewStatus": "approved",
        "cutoffUtc": CUTOFF,
        "useForTraining": False,
    }


def _task(
    record: dict,
    *,
    verifier_id: str,
    verifier_sha256: str,
    context_pack_sha256: str,
) -> dict:
    messages = record["messages"][:-1]
    task = {
        "schemaVersion": "daxalgo.hyperion.evaluation-task/v1",
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


def _write_jsonl(path: Path, *records: dict) -> None:
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class EvaluationAuthoringApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        key = ec.generate_private_key(ec.SECP256R1())
        self.private_key_object = key
        self.private_key = self.root / "authoring-private.pem"
        self.public_key = self.root / "authoring-public.pem"
        self.private_key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_key.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.trust = EvaluationAuthoringApprovalTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256=hashlib.sha256(spki).hexdigest(),
            audience=AUDIENCE,
            key_id=KEY_ID,
            signer_role=SIGNER_ROLE,
        )
        self.calibration_record = _record("calibration-1", "calibration")
        self.sealed_record = _record("sealed-1", "sealed")
        self.source_dataset = self.root / "source.jsonl"
        _write_jsonl(self.source_dataset, self.calibration_record, self.sealed_record)

        self.asset_paths: dict[str, dict[str, Path]] = {}
        tasks: dict[str, dict] = {}
        for record in (self.calibration_record, self.sealed_record):
            task_id = f"task-{record['id']}"
            context = self.root / f"{task_id}.context.txt"
            rubric = self.root / f"{task_id}.rubric.txt"
            verifier = self.root / f"{task_id}.verifier.json"
            context.write_text(f"Exact context for {task_id}.\n", encoding="utf-8")
            rubric.write_text(f"Exact rubric for {task_id}.\n", encoding="utf-8")
            verifier.write_text(
                json.dumps({"id": f"verifier-{task_id}", "expected": [1, 2, 3]}) + "\n",
                encoding="utf-8",
            )
            self.asset_paths[task_id] = {
                "contextPack": context,
                "rubric": rubric,
                "verifier": verifier,
            }
            tasks[record["split"]] = _task(
                record,
                verifier_id=f"verifier-{task_id}",
                verifier_sha256=hashlib.sha256(verifier.read_bytes()).hexdigest(),
                context_pack_sha256=hashlib.sha256(context.read_bytes()).hexdigest(),
            )
        self.tasks = tasks
        self.calibration_tasks = self.root / "calibration.jsonl"
        self.sealed_tasks = self.root / "sealed.jsonl"
        _write_jsonl(self.calibration_tasks, tasks["calibration"])
        _write_jsonl(self.sealed_tasks, tasks["sealed"])
        self.bindings = self.root / "bindings.json"
        self._write_bindings()
        self.output = self.root / "authoring-approval.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_bindings(self) -> None:
        values = []
        for record in (self.sealed_record, self.calibration_record):
            task_id = f"task-{record['id']}"
            paths = self.asset_paths[task_id]
            values.append(
                {
                    "taskId": task_id,
                    "sourceExampleIds": [record["id"]],
                    "contextPack": {
                        "version": "reviewed-context-v1",
                        "path": str(paths["contextPack"]),
                    },
                    "rubric": {
                        "id": f"rubric-{task_id}",
                        "path": str(paths["rubric"]),
                    },
                    "verifier": {
                        "id": f"verifier-{task_id}",
                        "path": str(paths["verifier"]),
                    },
                }
            )
        self.bindings.write_text(
            json.dumps(
                {"schemaVersion": TASK_BINDINGS_SCHEMA_VERSION, "bindings": values}
            ),
            encoding="utf-8",
        )

    def _arguments(self, **overrides) -> dict:
        values = {
            "output_path": self.output,
            "private_key_path": self.private_key,
            "public_key_path": self.public_key,
            "public_key_spki_sha256": self.trust.public_key_spki_sha256,
            "private_key_password": None,
            "audience": AUDIENCE,
            "key_id": KEY_ID,
            "signer_role": SIGNER_ROLE,
            "approval_id": "EVAL-AUTHORING-TEST-1",
            "actor_id": "fixture-evaluation-board",
            "actor_role": SIGNER_ROLE,
            "approval_reference": "review://evaluation/EVAL-AUTHORING-TEST-1",
            "approved_at_utc": APPROVED,
            "issued_at_utc": ISSUED,
            "not_before_utc": NOT_BEFORE,
            "expires_at_utc": EXPIRES,
            "source_dataset_path": self.source_dataset,
            "calibration_tasks_path": self.calibration_tasks,
            "sealed_tasks_path": self.sealed_tasks,
            "task_bindings_path": self.bindings,
            "now": NOW,
        }
        values.update(overrides)
        return values

    def _create(self, **overrides):
        return create_evaluation_authoring_approval(**self._arguments(**overrides))

    def _validate_live(self, path: Path, envelope_sha256: str):
        return validate_evaluation_authoring_approval_for_inventory(
            path,
            trust=self.trust,
            expected_envelope_sha256=envelope_sha256,
            source_dataset_path=self.source_dataset,
            calibration_tasks_path=self.calibration_tasks,
            sealed_tasks_path=self.sealed_tasks,
            task_bindings_path=self.bindings,
            now=NOW,
        )

    def _prepare_detached(
        self,
        name: str,
        *,
        signature_format: str,
        force_high_s: bool = False,
        signing_key=None,
        signing_mode: str = "digest",
    ) -> tuple[Path, dict, Path, dict]:
        bundle_path = self.root / f"{name}.bundle.json"
        signature_path = self.root / f"{name}.signature.json"
        arguments = self._arguments(output_path=bundle_path)
        arguments.pop("private_key_path")
        arguments.pop("private_key_password")
        prepare_evaluation_authoring_approval_signing_bundle(**arguments)
        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        key = signing_key or self.private_key_object
        signing_digest = _decode(bundle["request"]["signatureInput"])
        if signing_mode == "digest":
            der = key.sign(signing_digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif signing_mode == "raw-preimage":
            der = key.sign(
                _decode(bundle["request"]["signaturePreimage"]),
                ec.ECDSA(hashes.SHA256()),
            )
        elif signing_mode == "double-hashed-digest":
            der = key.sign(signing_digest, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported detached signing mode")
        r, s = decode_dss_signature(der)
        if force_high_s and s <= P256_ORDER // 2:
            s = P256_ORDER - s
        if (
            signature_format
            == EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT
        ):
            signature = encode_dss_signature(r, s)
        elif (
            signature_format
            == EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT
        ):
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported detached signature format")
        document = authoring_module._build_external_signature_document(
            bundle,
            bundle_bytes,
            signature_format=signature_format,
            signature=signature,
        )
        signature_path.write_bytes(canonical_json_bytes(document) + b"\n")
        return bundle_path, bundle, signature_path, document

    def _finalize_detached(
        self,
        bundle_path: Path,
        signature_path: Path,
        output_name: str,
        **overrides,
    ):
        arguments = {
            "signing_bundle_path": bundle_path,
            "signature_path": signature_path,
            "output_path": self.root / output_name,
            "public_key_path": self.public_key,
            "expected_public_key_spki_sha256": self.trust.public_key_spki_sha256,
            "expected_audience": AUDIENCE,
            "expected_key_id": KEY_ID,
            "expected_signer_role": SIGNER_ROLE,
            "source_dataset_path": self.source_dataset,
            "calibration_tasks_path": self.calibration_tasks,
            "sealed_tasks_path": self.sealed_tasks,
            "task_bindings_path": self.bindings,
            "now": NOW,
        }
        arguments.update(overrides)
        return finalize_evaluation_authoring_approval(**arguments)

    def test_create_round_trips_closed_schema_and_exact_atomic_inventory(self) -> None:
        verified = self._create()

        revalidated = self._validate_live(self.output, verified.envelope_sha256)
        self.assertEqual(verified.payload, revalidated.payload)
        self.assertEqual(
            EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
            verified.payload["schemaVersion"],
        )
        self.assertEqual(
            EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION,
            verified.envelope["schemaVersion"],
        )
        self.assertEqual(
            ["task-calibration-1", "task-sealed-1"],
            [row["taskId"] for row in verified.payload["inventory"]["taskBindings"]],
        )
        self.assertNotIn("path", json.dumps(verified.payload["inventory"]))
        self.assertTrue(verified.payload["evaluationAuthoringApproved"])
        for name in (
            "corpusReviewAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "baseSelectionAuthorized",
            "promotionDecisionAuthorized",
            "deploymentAuthorized",
            "hostedServingAuthorized",
            "installationAuthorized",
            "verifierExecutionAuthorized",
            "strategyExecutionAuthorized",
        ):
            self.assertIs(verified.payload[name], False)

        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        payload_schema = json.loads(
            (schema_root / "evaluation-authoring-approval.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        envelope_schema = json.loads(
            (
                schema_root / "evaluation-authoring-approval-envelope.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(payload_schema["additionalProperties"])
        self.assertFalse(envelope_schema["additionalProperties"])
        self.assertEqual(
            EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
            payload_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            "ieee-p1363-low-s",
            envelope_schema["properties"]["signatureFormat"]["const"],
        )

    def test_detached_der_and_p1363_high_s_round_trip_preserves_wire(self) -> None:
        direct = self._create()
        direct_unsigned = {
            key: value for key, value in direct.envelope.items() if key != "signature"
        }

        for label, signature_format in (
            ("der", EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT),
            (
                "p1363",
                EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ),
        ):
            with self.subTest(signature_format=signature_format):
                bundle_path, bundle, signature_path, external = self._prepare_detached(
                    label,
                    signature_format=signature_format,
                    force_high_s=True,
                )
                with (
                    mock.patch.object(
                        authoring_module, "_load_private_key"
                    ) as load_key,
                    mock.patch.object(authoring_module, "_sign_p1363_low_s") as sign,
                ):
                    finalized = self._finalize_detached(
                        bundle_path,
                        signature_path,
                        f"{label}.approval.json",
                    )
                load_key.assert_not_called()
                sign.assert_not_called()

                self.assertEqual(
                    EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION,
                    bundle["schemaVersion"],
                )
                self.assertEqual(
                    evaluation_authoring_approval_signing_bundle_id(bundle),
                    bundle["bundleId"],
                )
                self.assertEqual("unsigned-non-authorizing", bundle["status"])
                self.assertTrue(
                    all(value is False for value in bundle["authority"].values())
                )
                self.assertEqual(
                    EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION,
                    external["schemaVersion"],
                )
                self.assertEqual(
                    evaluation_authoring_approval_signature_id(external),
                    external["signatureId"],
                )
                preimage = _decode(bundle["request"]["signaturePreimage"])
                digest = _decode(bundle["request"]["signatureInput"])
                self.assertEqual(hashlib.sha256(preimage).digest(), digest)
                self.assertEqual(
                    digest.hex(), bundle["request"]["signatureInputSha256"]
                )

                external_bytes = _decode(external["signature"])
                if signature_format == "asn1-der":
                    _, external_s = decode_dss_signature(external_bytes)
                else:
                    external_s = int.from_bytes(external_bytes[32:], "big")
                self.assertGreater(external_s, P256_ORDER // 2)
                output_signature = _decode(finalized.envelope["signature"])
                self.assertEqual(64, len(output_signature))
                self.assertLessEqual(
                    int.from_bytes(output_signature[32:], "big"), P256_ORDER // 2
                )
                self.assertEqual(
                    direct_unsigned,
                    {
                        key: value
                        for key, value in finalized.envelope.items()
                        if key != "signature"
                    },
                )

    def test_detached_raw_preimage_signing_succeeds_and_double_hashing_fails(
        self,
    ) -> None:
        raw_bundle, _, raw_signature, _ = self._prepare_detached(
            "raw-preimage",
            signature_format=EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
            signing_mode="raw-preimage",
        )
        finalized = self._finalize_detached(
            raw_bundle,
            raw_signature,
            "raw-preimage.approval.json",
        )
        self.assertEqual(
            EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION,
            finalized.envelope["schemaVersion"],
        )

        bad_bundle, _, bad_signature, _ = self._prepare_detached(
            "double-hashed-digest",
            signature_format=EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
            signing_mode="double-hashed-digest",
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                bad_bundle,
                bad_signature,
                "double-hashed-digest.approval.json",
            )

    def test_detached_schemas_are_strict_and_match_wire_literals(self) -> None:
        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        bundle_schema = json.loads(
            (
                schema_root
                / "evaluation-authoring-approval-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_schema = json.loads(
            (
                schema_root / "evaluation-authoring-approval-signature.v1.schema.json"
            ).read_bytes()
        )
        self.assertEqual(
            EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION,
            bundle_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION,
            signature_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            "unsigned-non-authorizing",
            bundle_schema["properties"]["status"]["const"],
        )
        self.assertTrue(
            all(
                value["const"] is False
                for value in bundle_schema["properties"]["authority"][
                    "properties"
                ].values()
            )
        )
        for document in (bundle_schema, signature_schema):
            pending = [document]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(
                            False, value.get("additionalProperties"), msg=value
                        )
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)

        _, bundle, _, signature = self._prepare_detached(
            "schema-validation",
            signature_format=EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
        )
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(signature)

    def test_detached_rejects_live_input_bundle_signature_and_key_mutations(
        self,
    ) -> None:
        with (
            mock.patch.object(authoring_module, "_load_private_key") as load_key,
            mock.patch.object(authoring_module, "_sign_p1363_low_s") as sign,
        ):
            bundle_path, bundle, signature_path, signature = self._prepare_detached(
                "adversarial",
                signature_format=(
                    EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT
                ),
            )
        load_key.assert_not_called()
        sign.assert_not_called()

        original_source = self.source_dataset.read_bytes()
        self.source_dataset.write_bytes(
            original_source.replace(
                b"Synthetic reviewed fixture.", b"Synthetic changed fixture."
            )
        )
        try:
            with self.assertRaisesRegex(ValidationError, "exact live"):
                self._finalize_detached(
                    bundle_path,
                    signature_path,
                    "changed-source.approval.json",
                )
        finally:
            self.source_dataset.write_bytes(original_source)

        changed_bundle = json.loads(canonical_json_bytes(bundle))
        changed_bundle["trust"]["keyId"] = "substituted-key"
        changed_bundle["bundleId"] = evaluation_authoring_approval_signing_bundle_id(
            changed_bundle
        )
        changed_bundle_path = self.root / "changed.bundle.json"
        changed_bundle_path.write_bytes(canonical_json_bytes(changed_bundle) + b"\n")
        with self.assertRaisesRegex(ValidationError, "externally pinned trust"):
            self._finalize_detached(
                changed_bundle_path,
                signature_path,
                "changed-bundle.approval.json",
            )

        authorized_bundle = json.loads(canonical_json_bytes(bundle))
        authorized_bundle["authority"]["release"] = True
        authorized_bundle["bundleId"] = evaluation_authoring_approval_signing_bundle_id(
            authorized_bundle
        )
        authorized_bundle_path = self.root / "authorized.bundle.json"
        authorized_bundle_path.write_bytes(
            canonical_json_bytes(authorized_bundle) + b"\n"
        )
        with self.assertRaisesRegex(ValidationError, "must be false"):
            self._finalize_detached(
                authorized_bundle_path,
                signature_path,
                "authorized-bundle.approval.json",
            )

        changed_preimage_bundle = json.loads(canonical_json_bytes(bundle))
        changed_preimage = bytearray(
            _decode(changed_preimage_bundle["request"]["signaturePreimage"])
        )
        changed_preimage[-1] ^= 1
        changed_digest = hashlib.sha256(changed_preimage).digest()
        changed_preimage_bundle["request"]["signaturePreimage"] = _encode(
            bytes(changed_preimage)
        )
        changed_preimage_bundle["request"]["signatureInput"] = _encode(changed_digest)
        changed_preimage_bundle["request"]["signatureInputSha256"] = (
            changed_digest.hex()
        )
        changed_preimage_bundle["bundleId"] = (
            evaluation_authoring_approval_signing_bundle_id(changed_preimage_bundle)
        )
        changed_preimage_path = self.root / "changed-preimage.bundle.json"
        changed_preimage_path.write_bytes(
            canonical_json_bytes(changed_preimage_bundle) + b"\n"
        )
        with self.assertRaisesRegex(ValidationError, "signature preimage"):
            self._finalize_detached(
                changed_preimage_path,
                signature_path,
                "changed-preimage.approval.json",
            )

        changed_signature = json.loads(canonical_json_bytes(signature))
        changed_signature["payloadSha256"] = "f" * 64
        changed_signature["signatureId"] = evaluation_authoring_approval_signature_id(
            changed_signature
        )
        changed_signature_path = self.root / "changed.signature.json"
        changed_signature_path.write_bytes(
            canonical_json_bytes(changed_signature) + b"\n"
        )
        with self.assertRaisesRegex(ValidationError, "exact signing bundle"):
            self._finalize_detached(
                bundle_path,
                changed_signature_path,
                "changed-signature.approval.json",
            )

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        digest = _decode(bundle["request"]["signatureInput"])
        wrong_der = wrong_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        wrong_signature = authoring_module._build_external_signature_document(
            bundle,
            bundle_path.read_bytes(),
            signature_format=EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
            signature=wrong_der,
        )
        wrong_signature_path = self.root / "wrong-key.signature.json"
        wrong_signature_path.write_bytes(canonical_json_bytes(wrong_signature) + b"\n")
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                bundle_path,
                wrong_signature_path,
                "wrong-key.approval.json",
            )

        noncanonical_signature_path = self.root / "noncanonical.signature.json"
        noncanonical_signature_path.write_bytes(signature_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValidationError, "exact canonical JSON"):
            self._finalize_detached(
                bundle_path,
                noncanonical_signature_path,
                "noncanonical.approval.json",
            )

        existing = self.root / "existing-detached.approval.json"
        existing.write_bytes(b"preserve-detached")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._finalize_detached(
                bundle_path,
                signature_path,
                existing.name,
            )
        self.assertEqual(b"preserve-detached", existing.read_bytes())

    def test_detached_publication_revalidates_and_removes_only_its_output(
        self,
    ) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached(
            "publication",
            signature_format=EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT,
        )
        inventory = derive_evaluation_authoring_inventory(
            source_dataset_path=self.source_dataset,
            calibration_tasks_path=self.calibration_tasks,
            sealed_tasks_path=self.sealed_tasks,
            task_bindings_path=self.bindings,
        )
        changed_inventory = json.loads(json.dumps(inventory))
        changed_inventory["taskBindings"][0]["rubric"]["sha256"] = "f" * 64
        drift_output = self.root / "publication-drift.approval.json"
        with (
            mock.patch.object(
                authoring_module,
                "derive_evaluation_authoring_inventory",
                side_effect=(inventory, changed_inventory),
            ),
            self.assertRaisesRegex(ValidationError, "exact live"),
        ):
            self._finalize_detached(
                bundle_path,
                signature_path,
                drift_output.name,
            )
        self.assertFalse(drift_output.exists())

        output = self.root / "post-publication-failure.approval.json"
        real_validator = (
            authoring_module.validate_evaluation_authoring_approval_for_inventory
        )
        validation_count = 0

        def fail_after_install(*args, **kwargs):
            nonlocal validation_count
            validation_count += 1
            verified = real_validator(*args, **kwargs)
            if validation_count == 2:
                raise ValidationError("simulated post-publication failure")
            return verified

        with (
            mock.patch.object(
                authoring_module,
                "validate_evaluation_authoring_approval_for_inventory",
                side_effect=fail_after_install,
            ),
            self.assertRaisesRegex(ValidationError, "post-publication failure"),
        ):
            self._finalize_detached(
                bundle_path,
                signature_path,
                output.name,
            )
        self.assertEqual(2, validation_count)
        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(".*.staging")))

    def test_detached_finalization_fails_closed_if_validity_expires_during_publish(
        self,
    ) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached(
            "expiry-crossing",
            signature_format=EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
        )
        expiry = datetime.strptime(EXPIRES, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        live_times = iter((NOW, NOW, expiry))

        def controlled_clock(value, field):
            if value is not None:
                return authoring_module._validation_time(value, field)
            return next(live_times)

        output = self.root / "expiry-crossing.approval.json"
        with (
            mock.patch.object(
                authoring_module,
                "_fresh_validation_time",
                side_effect=controlled_clock,
            ),
            self.assertRaisesRegex(ValidationError, "is not active"),
        ):
            self._finalize_detached(
                bundle_path,
                signature_path,
                output.name,
                now=None,
            )
        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(".*.staging")))

    def test_inventory_rejects_source_context_rubric_and_verifier_drift(self) -> None:
        verified = self._create()
        paths = self.asset_paths["task-calibration-1"]
        cases = (
            ("source", self.source_dataset),
            ("context", paths["contextPack"]),
            ("rubric", paths["rubric"]),
            ("verifier", paths["verifier"]),
        )
        for label, path in cases:
            with self.subTest(label=label):
                original = path.read_bytes()
                path.write_bytes(original + b"drift")
                try:
                    with self.assertRaises(ValidationError):
                        self._validate_live(self.output, verified.envelope_sha256)
                finally:
                    path.write_bytes(original)

    def test_inventory_rejects_task_and_lineage_binding_drift(self) -> None:
        verified = self._create()
        original_tasks = self.calibration_tasks.read_bytes()
        changed_task = dict(self.tasks["calibration"])
        changed_task["maxOutputTokens"] = 513
        changed_task["taskSha256"] = evaluation_task_sha256(changed_task)
        _write_jsonl(self.calibration_tasks, changed_task)
        try:
            with self.assertRaisesRegex(ValidationError, "inventory"):
                self._validate_live(self.output, verified.envelope_sha256)
        finally:
            self.calibration_tasks.write_bytes(original_tasks)

        binding_document = json.loads(self.bindings.read_text(encoding="utf-8"))
        binding_document["bindings"][1]["sourceExampleIds"] = ["sealed-1"]
        self.bindings.write_text(json.dumps(binding_document), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "wrong split"):
            derive_evaluation_authoring_inventory(
                source_dataset_path=self.source_dataset,
                calibration_tasks_path=self.calibration_tasks,
                sealed_tasks_path=self.sealed_tasks,
                task_bindings_path=self.bindings,
            )

    def test_correctly_resigned_inventory_swap_does_not_validate_for_original(
        self,
    ) -> None:
        original = self._create()
        rubric = self.asset_paths["task-sealed-1"]["rubric"]
        original_rubric = rubric.read_bytes()
        rubric.write_bytes(original_rubric + b"approved revision\n")
        second_output = self.root / "second-approval.json"
        second = self._create(output_path=second_output)
        self.assertNotEqual(original.envelope_sha256, second.envelope_sha256)
        rubric.write_bytes(original_rubric)

        with self.assertRaisesRegex(ValidationError, "exact live"):
            self._validate_live(second_output, second.envelope_sha256)

    def test_exact_envelope_trust_signature_and_low_s_are_enforced(self) -> None:
        verified = self._create()
        with self.assertRaisesRegex(ValidationError, "trusted exact SHA-256"):
            validate_evaluation_authoring_approval(
                self.output,
                trust=self.trust,
                expected_envelope_sha256="0" * 64,
                now=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "trusted configuration"):
            validate_evaluation_authoring_approval(
                self.output,
                trust=replace(self.trust, audience="different-audience"),
                expected_envelope_sha256=verified.envelope_sha256,
                now=NOW,
            )

        envelope = json.loads(self.output.read_text(encoding="utf-8"))
        signature = _decode(envelope["signature"])
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        envelope["signature"] = _encode(
            r.to_bytes(32, "big") + (P256_ORDER - s).to_bytes(32, "big")
        )
        high_s = self.root / "high-s.json"
        high_s.write_bytes(canonical_json_bytes(envelope) + b"\n")
        expected = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
        with self.assertRaisesRegex(ValidationError, "low-S"):
            validate_evaluation_authoring_approval(
                high_s,
                trust=self.trust,
                expected_envelope_sha256=expected,
                now=NOW,
            )

    def test_self_consistent_payload_tampering_still_fails_signature(self) -> None:
        self._create()
        envelope = json.loads(self.output.read_text(encoding="utf-8"))
        payload = json.loads(_decode(envelope["payload"]))
        payload["approval"]["reference"] += "/tampered"
        payload["authoringApprovalId"] = evaluation_authoring_approval_id(payload)
        payload_bytes = canonical_json_bytes(payload)
        envelope["payload"] = _encode(payload_bytes)
        envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        tampered = self.root / "tampered.json"
        tampered.write_bytes(canonical_json_bytes(envelope) + b"\n")
        expected = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()

        with self.assertRaisesRegex(ValidationError, "does not verify"):
            validate_evaluation_authoring_approval(
                tampered,
                trust=self.trust,
                expected_envelope_sha256=expected,
                now=NOW,
            )

    def test_correctly_resigned_numeric_booleans_do_not_satisfy_contract(self) -> None:
        self._create()
        original = json.loads(self.output.read_text(encoding="utf-8"))
        for name, numeric in (
            ("reusable", 1),
            ("evaluationAuthoringApproved", 1),
            ("releaseAuthorized", 0),
        ):
            with self.subTest(name=name):
                envelope = dict(original)
                payload = json.loads(_decode(envelope["payload"]))
                payload[name] = numeric
                payload["authoringApprovalId"] = evaluation_authoring_approval_id(
                    payload
                )
                payload_bytes = canonical_json_bytes(payload)
                envelope["payload"] = _encode(payload_bytes)
                envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
                envelope["signature"] = _encode(
                    authoring_module._sign_p1363_low_s(
                        self.private_key_object,
                        authoring_module._signature_input(envelope, payload_bytes),
                    )
                )
                path = self.root / f"numeric-{name}.json"
                path.write_bytes(canonical_json_bytes(envelope) + b"\n")
                expected = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()

                with self.assertRaisesRegex(
                    ValidationError, "does not match the contract"
                ):
                    validate_evaluation_authoring_approval(
                        path,
                        trust=self.trust,
                        expected_envelope_sha256=expected,
                        now=NOW,
                    )

    def test_timeline_actor_role_and_active_window_are_strict(self) -> None:
        cases = (
            ({"actor_role": "release-authority"}, "actorRole"),
            ({"approved_at_utc": "2025-01-20T12:00:02Z"}, "approvedAt"),
            ({"issued_at_utc": "2025-01-20T12:00:03Z"}, "issuedAt"),
            ({"expires_at_utc": "2027-01-21T12:00:02Z"}, "366 days"),
            ({"now": datetime(2025, 1, 1, tzinfo=timezone.utc)}, "active"),
            ({"now": datetime(2026, 1, 20, 12, 0, 2, tzinfo=timezone.utc)}, "active"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ValidationError, message):
                    self._create(**overrides)

    def test_no_clobber_and_staged_live_self_validation_precede_publication(
        self,
    ) -> None:
        self.output.write_text("occupied", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._create()
        self.assertEqual("occupied", self.output.read_text(encoding="utf-8"))
        self.output.unlink()

        inventory = derive_evaluation_authoring_inventory(
            source_dataset_path=self.source_dataset,
            calibration_tasks_path=self.calibration_tasks,
            sealed_tasks_path=self.sealed_tasks,
            task_bindings_path=self.bindings,
        )
        changed = json.loads(json.dumps(inventory))
        changed["taskBindings"][0]["rubric"]["sha256"] = "f" * 64
        with mock.patch(
            "hyperion_model.evaluation_authoring.derive_evaluation_authoring_inventory",
            side_effect=(inventory, changed),
        ):
            with self.assertRaisesRegex(ValidationError, "exact live"):
                self._create()
        self.assertFalse(self.output.exists())
        self.assertEqual([], list(self.root.glob(".*.staging")))

    def test_cleanup_failure_aborts_publication_and_reports_residual_material(
        self,
    ) -> None:
        real_unlink = Path.unlink

        def fail_staging_unlink(path: Path, *args, **kwargs):
            if path.name.endswith(".staging"):
                raise OSError("simulated cleanup failure")
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", fail_staging_unlink),
            self.assertRaisesRegex(ValidationError, "residual signed material"),
        ):
            self._create()
        self.assertFalse(self.output.exists())
        residuals = list(self.root.glob(".*.staging"))
        self.assertEqual(1, len(residuals))
        residual = residuals[0]
        envelope = json.loads(residual.read_text(encoding="utf-8"))
        envelope_sha256 = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
        self._validate_live(residual, envelope_sha256)
        os.unlink(residual)

    def test_cli_create_and_validate_routes_bind_exact_inventory_and_trust(
        self,
    ) -> None:
        verified = mock.Mock()
        verified.path = self.output
        verified.as_dict.return_value = {"authoringApprovalId": "approval-test"}
        trust_flags = [
            "--evaluation-authoring-approval-public-key",
            str(self.public_key),
            "--evaluation-authoring-approval-public-key-spki-sha256",
            self.trust.public_key_spki_sha256,
            "--evaluation-authoring-approval-audience",
            AUDIENCE,
            "--evaluation-authoring-approval-key-id",
            KEY_ID,
            "--evaluation-authoring-approval-signer-role",
            SIGNER_ROLE,
        ]
        inventory_flags = [
            "--source-dataset",
            str(self.source_dataset),
            "--calibration-tasks",
            str(self.calibration_tasks),
            "--sealed-tasks",
            str(self.sealed_tasks),
            "--task-bindings",
            str(self.bindings),
        ]
        create_arguments = [
            "create-evaluation-authoring-approval",
            "--output",
            str(self.output),
            "--private-key",
            str(self.private_key),
            *trust_flags,
            "--approval-id",
            "EVAL-AUTHORING-TEST-1",
            "--actor-id",
            "fixture-evaluation-board",
            "--actor-role",
            SIGNER_ROLE,
            "--approval-reference",
            "review://evaluation/EVAL-AUTHORING-TEST-1",
            "--approved-at-utc",
            APPROVED,
            "--issued-at-utc",
            ISSUED,
            "--not-before-utc",
            NOT_BEFORE,
            "--expires-at-utc",
            EXPIRES,
            *inventory_flags,
        ]
        stdout = io.StringIO()
        with (
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=self.trust,
            ),
            mock.patch.object(
                cli_module,
                "create_evaluation_authoring_approval",
                return_value=verified,
            ) as create_approval,
            redirect_stdout(stdout),
        ):
            self.assertEqual(0, cli_module.main(create_arguments))
        self.assertTrue(json.loads(stdout.getvalue())["created"])
        created = create_approval.call_args.kwargs
        self.assertEqual(self.source_dataset, created["source_dataset_path"])
        self.assertEqual(self.public_key, created["public_key_path"])
        self.assertEqual(
            self.trust.public_key_spki_sha256,
            created["public_key_spki_sha256"],
        )

        validate_arguments = [
            "validate-evaluation-authoring-approval",
            str(self.output),
            "--expected-evaluation-authoring-approval-envelope-sha256",
            "a" * 64,
            *trust_flags,
            *inventory_flags,
        ]
        stdout = io.StringIO()
        with (
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=self.trust,
            ),
            mock.patch.object(
                cli_module,
                "validate_evaluation_authoring_approval_for_inventory",
                return_value=verified,
            ) as validate_approval,
            redirect_stdout(stdout),
        ):
            self.assertEqual(0, cli_module.main(validate_arguments))
        self.assertTrue(json.loads(stdout.getvalue())["valid"])
        validated = validate_approval.call_args.kwargs
        self.assertIs(self.trust, validated["trust"])
        self.assertEqual("a" * 64, validated["expected_envelope_sha256"])
        self.assertEqual(self.bindings, validated["task_bindings_path"])

    def test_detached_cli_routes_have_no_private_key_options_and_dispatch(
        self,
    ) -> None:
        commands = (
            "prepare-evaluation-authoring-approval-signing-bundle",
            "finalize-evaluation-authoring-approval",
        )
        for command in commands:
            with self.subTest(command=command):
                stdout = io.StringIO()
                with redirect_stdout(stdout), self.assertRaises(SystemExit) as stopped:
                    cli_module.main([command, "--help"])
                self.assertEqual(0, stopped.exception.code)
                self.assertNotIn("--private-key", stdout.getvalue())

        trust_flags = [
            "--evaluation-authoring-approval-public-key",
            str(self.public_key),
            "--evaluation-authoring-approval-public-key-spki-sha256",
            self.trust.public_key_spki_sha256,
            "--evaluation-authoring-approval-audience",
            AUDIENCE,
            "--evaluation-authoring-approval-key-id",
            KEY_ID,
            "--evaluation-authoring-approval-signer-role",
            SIGNER_ROLE,
        ]
        inventory_flags = [
            "--source-dataset",
            str(self.source_dataset),
            "--calibration-tasks",
            str(self.calibration_tasks),
            "--sealed-tasks",
            str(self.sealed_tasks),
            "--task-bindings",
            str(self.bindings),
        ]
        bundle_path = self.root / "cli.bundle.json"
        signature_path = self.root / "cli.signature.json"
        prepared = mock.Mock()
        prepared.as_dict.return_value = {"signingBundleId": "bundle-test"}
        prepare_arguments = [
            "prepare-evaluation-authoring-approval-signing-bundle",
            "--output",
            str(bundle_path),
            *trust_flags,
            "--approval-id",
            "EVAL-AUTHORING-TEST-1",
            "--actor-id",
            "fixture-evaluation-board",
            "--actor-role",
            SIGNER_ROLE,
            "--approval-reference",
            "review://evaluation/EVAL-AUTHORING-TEST-1",
            "--approved-at-utc",
            APPROVED,
            "--issued-at-utc",
            ISSUED,
            "--not-before-utc",
            NOT_BEFORE,
            "--expires-at-utc",
            EXPIRES,
            *inventory_flags,
        ]
        with (
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=self.trust,
            ),
            mock.patch.object(
                cli_module,
                "prepare_evaluation_authoring_approval_signing_bundle",
                return_value=prepared,
            ) as prepare,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(0, cli_module.main(prepare_arguments))
        self.assertEqual(bundle_path, prepare.call_args.kwargs["output_path"])
        self.assertNotIn("private_key_path", prepare.call_args.kwargs)

        finalized = mock.Mock()
        finalized.path = self.output
        finalized.as_dict.return_value = {"authoringApprovalId": "approval-test"}
        finalize_arguments = [
            "finalize-evaluation-authoring-approval",
            "--signing-bundle",
            str(bundle_path),
            "--signature",
            str(signature_path),
            "--output",
            str(self.output),
            *trust_flags,
            *inventory_flags,
        ]
        with (
            mock.patch.object(
                cli_module,
                "_evaluation_authoring_approval_trust",
                return_value=self.trust,
            ),
            mock.patch.object(
                cli_module,
                "finalize_evaluation_authoring_approval",
                return_value=finalized,
            ) as finalize,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(0, cli_module.main(finalize_arguments))
        finalized_arguments = finalize.call_args.kwargs
        self.assertEqual(bundle_path, finalized_arguments["signing_bundle_path"])
        self.assertEqual(signature_path, finalized_arguments["signature_path"])
        self.assertNotIn("private_key_path", finalized_arguments)


if __name__ == "__main__":
    unittest.main()
