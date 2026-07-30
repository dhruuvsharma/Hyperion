from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
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

import vibe_quant_model.teacher_lineage as teacher_lineage_module
import vibe_quant_model.verifier_authority as verifier_authority_module
import vibe_quant_model.review_receipts as review_receipts_module
from vibe_quant_model.cli import main as cli_main
import test_teacher_materialization as materialization_test_module
from vibe_quant_model.core import ValidationError, canonical_json_bytes
from vibe_quant_model.release import (
    _parse_expert_corpus,
    _verification_evidence_sha256,
    expert_conversation_sha256,
)
from vibe_quant_model.review_receipts import (
    create_expert_model_review_receipts,
    validate_expert_model_review_receipts,
)
from vibe_quant_model.teacher_lineage import (
    TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION,
    TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
    TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT,
    TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
    TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION,
    TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
    TEACHER_LINEAGE_SUBJECT_HASH_DOMAIN,
    TeacherMaterializationLineageAdmissionTrust,
    create_teacher_materialization_lineage_admission,
    ensure_teacher_materialization_lineage_admission_active,
    finalize_teacher_materialization_lineage_admission,
    prepare_teacher_materialization_lineage_admission_signing_bundle,
    teacher_lineage_subject_fields,
    teacher_lineage_subject_sha256,
    teacher_lineage_subjects_from_corpus,
    teacher_materialization_lineage_admission_signature_id,
    teacher_materialization_lineage_admission_signing_bundle_id,
    verify_teacher_materialization_lineage_admission,
    verify_teacher_materialization_lineage_admission_for_reviewed_corpus,
)
from vibe_quant_model.teacher_materialization import (
    MATERIALIZED_DATASET_PATH,
    materialize_teacher_candidates,
)

ROOT = Path(__file__).resolve().parents[1]
ACTIVE = datetime(2026, 1, 4, 0, 0, 3, tzinfo=timezone.utc)
EXPIRES = datetime(2027, 1, 4, 0, 0, 2, tzinfo=timezone.utc)


def _independent_subject_hash(groups: list[list[str]]) -> str:
    payload = bytearray()

    def append_integer(value: int) -> None:
        payload.extend(value.to_bytes(4, "big", signed=True))

    def append_text(value: str) -> None:
        raw = value.encode("utf-8", "strict")
        append_integer(len(raw))
        payload.extend(raw)

    append_text(TEACHER_LINEAGE_SUBJECT_HASH_DOMAIN)
    append_integer(len(groups))
    for group in groups:
        append_integer(len(group))
        for value in group:
            append_text(value)
    return hashlib.sha256(payload).hexdigest()


class TeacherLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = materialization_test_module.TeacherMaterializationTests(
            "test_materializes_exact_open_weight_non_training_draft"
        )
        self.fixture.setUp()
        materialize_teacher_candidates(
            selection_manifest_path=self.fixture.selection_path,
            output_directory=self.fixture.output_path,
            now=materialization_test_module.NOW,
        )
        self.drafts = self._read_rows(
            self.fixture.output_path / MATERIALIZED_DATASET_PATH
        )
        self.reviewed = [self._approve(row) for row in self.drafts]
        self.dataset_path = self.fixture.root / "reviewed-corpus.jsonl"
        self._write_rows(self.dataset_path, self.reviewed)
        self.evidence_path = self.fixture.root / "lineage-review-evidence.txt"
        self.evidence_path.write_bytes(b"Independent exact-lineage review accepted.\n")
        self.private_key_object = ec.generate_private_key(ec.SECP256R1())
        self.private_key_path = self.fixture.root / "lineage-private.pem"
        self.public_key_path = self.fixture.root / "lineage-public.pem"
        self.private_key_path.write_bytes(
            self.private_key_object.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_key_path.write_bytes(
            self.private_key_object.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = self.private_key_object.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.trust = TeacherMaterializationLineageAdmissionTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=hashlib.sha256(spki).hexdigest(),
            audience="daxalgo-vibe-quant-review-receipts",
            key_id="teacher-lineage-review-key-2026-01",
            signer_role="teacher-lineage-reviewer",
        )
        self.admission_path = self.fixture.root / "teacher-lineage-admission.json"

    def tearDown(self) -> None:
        self.fixture.tearDown()

    @staticmethod
    def _read_rows(path: Path) -> list[dict]:
        return [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        ]

    @staticmethod
    def _write_rows(path: Path, rows: list[dict]) -> None:
        path.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))

    @staticmethod
    def _approve(row: dict) -> dict:
        approved = copy.deepcopy(row)
        verification = approved["verification"]
        verification["verified"] = True
        verification["reviewer"] = "final-subject-reviewer"
        verification["verifiedAtUtc"] = "2026-01-03T12:00:00Z"
        verification["evidence"].append(
            "Independent final review accepted the exact materialized subject."
        )
        verification["evidenceSha256"] = _verification_evidence_sha256(
            verification["evidence"],
            verification["compileEvidence"],
            verification["testEvidence"],
        )
        approved["reviewStatus"] = "approved"
        return approved

    @staticmethod
    def _human_row() -> dict:
        messages = [
            {"role": "system", "content": "Answer from reviewed evidence."},
            {"role": "user", "content": "What is independently reviewed?"},
            {"role": "assistant", "content": "The exact corpus identity."},
        ]
        evidence = [
            "knowledgeClass=candidate-stable",
            "Independent human-authored control record.",
        ]
        rights = {
            "mayStore": True,
            "mayEvaluate": True,
            "mayTrain": False,
            "mayUploadToProvider": False,
            "mayRedistribute": False,
        }
        return {
            "schemaVersion": "expert-model-dataset/v1",
            "id": "human-control-001",
            "taskKind": "GeneralQuestionAnswering",
            "domains": ["RiskManagement"],
            "messages": messages,
            "conversationSha256": expert_conversation_sha256(messages),
            "sources": [
                {
                    "id": "human-source-001",
                    "title": "Human reviewed note",
                    "content": "The exact corpus identity is independently reviewed.",
                    "provenance": "Private unit-test fixture.",
                    "license": "Internal evaluation grant",
                    "retrievedAtUtc": "2025-12-30T12:00:00Z",
                    "availableAtUtc": "2025-12-30T12:00:00Z",
                    "uri": None,
                    "rights": dict(rights),
                }
            ],
            "lineage": {
                "origin": "HumanAuthored",
                "producer": "human-fixture-author",
                "modelId": None,
                "modelRevision": None,
                "promptSha256": None,
                "profileVersion": None,
                "producedAtUtc": "2025-12-30T12:00:00Z",
            },
            "verification": {
                "verified": True,
                "reviewer": "human-fixture-reviewer",
                "verifiedAtUtc": "2026-01-03T12:00:00Z",
                "evidenceSha256": _verification_evidence_sha256(evidence, [], []),
                "evidence": evidence,
                "compileSucceeded": False,
                "compileEvidence": [],
                "testsPassed": False,
                "testEvidence": [],
            },
            "split": "development",
            "contaminationGroup": "human-control-group-001",
            "provenance": "Private human-authored control fixture.",
            "license": "Internal evaluation grant",
            "rights": rights,
            "reviewStatus": "approved",
            "cutoffUtc": "2025-12-31T00:00:00Z",
            "useForTraining": False,
        }

    def _creation_arguments(self, **overrides):
        arguments = {
            "output_path": self.admission_path,
            "materialization_path": self.fixture.output_path,
            "runtime_binding_path": self.fixture.runtime_binding_path,
            "reviewed_dataset_path": self.dataset_path,
            "reviewer_evidence_path": self.evidence_path,
            "private_key_path": self.private_key_path,
            "private_key_password": None,
            "trust": self.trust,
            "reviewer_id": "independent-lineage-governor",
            "reviewed_at_utc": "2026-01-04T00:00:00Z",
            "issued_at_utc": "2026-01-04T00:00:01Z",
            "not_before_utc": "2026-01-04T00:00:02Z",
            "expires_at_utc": "2027-01-04T00:00:02Z",
            "now": ACTIVE,
        }
        arguments.update(overrides)
        return arguments

    def _create(self, **overrides):
        return create_teacher_materialization_lineage_admission(
            **self._creation_arguments(**overrides)
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
        bundle_path = self.fixture.root / f"{name}.bundle.json"
        signature_path = self.fixture.root / f"{name}.signature.json"
        arguments = self._creation_arguments(output_path=bundle_path)
        arguments.pop("private_key_path")
        arguments.pop("private_key_password")
        prepare_teacher_materialization_lineage_admission_signing_bundle(**arguments)
        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        key = signing_key or self.private_key_object
        signing_digest = teacher_lineage_module._base64url_decode(
            bundle["request"]["signatureInput"], "test signing digest", 32
        )
        if signing_mode == "digest":
            der = key.sign(signing_digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif signing_mode == "raw-preimage":
            preimage = teacher_lineage_module._base64url_decode(
                bundle["request"]["signaturePreimage"],
                "test signature preimage",
                teacher_lineage_module.MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_INPUT_BYTES,
            )
            der = key.sign(preimage, ec.ECDSA(hashes.SHA256()))
        elif signing_mode == "double-hashed-digest":
            der = key.sign(signing_digest, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported detached signing mode")
        r, s = decode_dss_signature(der)
        order = verifier_authority_module._P256_ORDER
        if force_high_s and s <= order // 2:
            s = order - s
        if signature_format == TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT:
            signature = encode_dss_signature(r, s)
        elif (
            signature_format
            == TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT
        ):
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported detached signature format")
        document = teacher_lineage_module._build_external_signature_document(
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
            "output_path": self.fixture.root / output_name,
            "materialization_path": self.fixture.output_path,
            "runtime_binding_path": self.fixture.runtime_binding_path,
            "reviewed_dataset_path": self.dataset_path,
            "reviewer_evidence_path": self.evidence_path,
            "trust": self.trust,
            "now": ACTIVE,
        }
        arguments.update(overrides)
        return finalize_teacher_materialization_lineage_admission(**arguments)

    def _verify_dataset_only(self, path: Path | None = None, **overrides):
        arguments = {
            "reviewed_dataset_path": self.dataset_path,
            "trust": self.trust,
            "now": ACTIVE,
        }
        arguments.update(overrides)
        return verify_teacher_materialization_lineage_admission_for_reviewed_corpus(
            path or self.admission_path,
            **arguments,
        )

    def _receipt_key(self, stem: str = "receipt") -> tuple[Path, Path, str]:
        key = ec.generate_private_key(ec.SECP256R1())
        private_path = self.fixture.root / f"{stem}-private.pem"
        public_path = self.fixture.root / f"{stem}-public.pem"
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_path, public_path, hashlib.sha256(spki).hexdigest()

    def _issue_receipts(self, **overrides):
        private_path, public_path, spki = self._receipt_key()
        approval = self.fixture.root / "receipt-approval-evidence.bin"
        approval.write_bytes(b"Independent receipt approval.\n")
        output = self.fixture.root / "review-receipts.jsonl"
        arguments = {
            "dataset_path": self.dataset_path,
            "output_path": output,
            "private_key_path": private_path,
            "public_key_path": public_path,
            "private_key_password": None,
            "audience": "daxalgo-teacher-review-receipts",
            "key_id": "teacher-receipt-key-2026-01",
            "signer_role": "teacher-receipt-reviewer",
            "approval_id": "teacher-receipt-approval-1",
            "actor_id": "teacher-receipt-actor-1",
            "actor_role": "teacher-receipt-reviewer",
            "approval_reference": "test-only exact reviewed corpus",
            "approval_evidence_path": approval,
            "approved_at_utc": "2026-01-04T00:00:02Z",
            "issued_at_utc": "2026-01-04T00:00:02Z",
            "not_before_utc": "2026-01-04T00:00:02Z",
            "expires_at_utc": "2027-01-04T00:00:02Z",
            "teacher_lineage_admission_path": self.admission_path,
            "teacher_materialization_path": self.fixture.output_path,
            "teacher_runtime_binding_path": self.fixture.runtime_binding_path,
            "teacher_lineage_reviewer_evidence_path": self.evidence_path,
            "teacher_lineage_admission_trust": self.trust,
            "now": ACTIVE,
        }
        arguments.update(overrides)
        created = create_expert_model_review_receipts(**arguments)
        return created, output, public_path, spki

    def test_round_trip_binds_one_package_and_supports_snapshot_consumer(self) -> None:
        self._write_rows(self.dataset_path, [self._human_row(), *self.reviewed])
        created = self._create()
        verified = verify_teacher_materialization_lineage_admission(
            self.admission_path,
            materialization_path=self.fixture.output_path,
            runtime_binding_path=self.fixture.runtime_binding_path,
            reviewed_dataset_path=self.dataset_path,
            reviewer_evidence_path=self.evidence_path,
            trust=self.trust,
            expected_envelope_sha256=created.envelope_sha256,
            now=ACTIVE,
        )
        self.assertEqual(created.payload, verified.payload)
        self.assertEqual(2, verified.payload["reviewedCorpus"]["recordCount"])
        self.assertEqual(
            1,
            verified.payload["reviewedCorpus"]["openWeightTeacherRecordCount"],
        )
        self.assertTrue(verified.payload["reviewReceiptIssuanceAuthorized"])
        for field in (
            "runtimeAttested",
            "teacherWeightsAttested",
            "teacherCorrectnessAuthorized",
            "reviewDecisionAuthorized",
            "rightsAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "evaluationAuthorized",
            "promotionDecisionAuthorized",
            "deploymentAuthorized",
            "hostedServingAuthorized",
            "installationAuthorized",
            "verifierExecutionAuthorized",
            "strategyExecutionAuthorized",
        ):
            self.assertFalse(verified.payload[field], field)
        self.assertEqual(
            {
                "publicKeySpkiSha256": self.trust.public_key_spki_sha256,
                "audience": self.trust.audience,
                "keyId": self.trust.key_id,
                "signerRole": self.trust.signer_role,
            },
            self.trust.manifest_identity(),
        )
        self.assertEqual(
            datetime(2026, 1, 4, tzinfo=timezone.utc),
            verified.reviewed_at_utc,
        )
        self.assertEqual(
            datetime(2026, 1, 4, 0, 0, 1, tzinfo=timezone.utc),
            verified.issued_at_utc,
        )

        parsed = _parse_expert_corpus(self.dataset_path)
        raw = self.dataset_path.read_bytes()
        self.assertEqual(
            created.payload["reviewedCorpus"]["subjects"],
            teacher_lineage_subjects_from_corpus(parsed),
        )
        with mock.patch.object(
            teacher_lineage_module,
            "_parse_expert_corpus",
            side_effect=AssertionError("dataset reopened"),
        ):
            snapshot_verified = self._verify_dataset_only(
                reviewed_corpus=parsed,
                reviewed_dataset_bytes=raw,
            )
            full_snapshot_verified = verify_teacher_materialization_lineage_admission(
                self.admission_path,
                materialization_path=self.fixture.output_path,
                runtime_binding_path=self.fixture.runtime_binding_path,
                reviewed_dataset_path=self.dataset_path,
                reviewer_evidence_path=self.evidence_path,
                trust=self.trust,
                now=ACTIVE,
                reviewed_corpus=parsed,
                reviewed_dataset_bytes=raw,
            )
        self.assertEqual(created.payload_sha256, snapshot_verified.payload_sha256)
        self.assertEqual(created.payload_sha256, full_snapshot_verified.payload_sha256)

    def test_detached_der_and_p1363_high_s_preserve_admission_wire_and_receipts(
        self,
    ) -> None:
        direct = self._create()
        direct_unsigned = {
            name: value
            for name, value in direct.envelope.items()
            if name != "signature"
        }
        finalized = None
        for label, signature_format in (
            ("der", TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT),
            (
                "p1363",
                TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ),
        ):
            with self.subTest(signature_format=signature_format):
                with (
                    mock.patch.object(
                        teacher_lineage_module, "_load_private_key"
                    ) as load_key,
                    mock.patch.object(
                        teacher_lineage_module, "_sign_p1363_low_s"
                    ) as sign,
                ):
                    bundle_path, bundle, signature_path, external = (
                        self._prepare_detached(
                            label,
                            signature_format=signature_format,
                            force_high_s=True,
                        )
                    )
                    finalized = self._finalize_detached(
                        bundle_path,
                        signature_path,
                        f"{label}.admission.json",
                    )
                load_key.assert_not_called()
                sign.assert_not_called()
                self.assertEqual(
                    TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
                    bundle["schemaVersion"],
                )
                self.assertEqual(
                    teacher_materialization_lineage_admission_signing_bundle_id(bundle),
                    bundle["bundleId"],
                )
                self.assertEqual("unsigned-non-authorizing", bundle["status"])
                self.assertTrue(
                    all(value is False for value in bundle["authority"].values())
                )
                self.assertEqual(
                    TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION,
                    external["schemaVersion"],
                )
                self.assertEqual(
                    teacher_materialization_lineage_admission_signature_id(external),
                    external["signatureId"],
                )
                preimage = teacher_lineage_module._base64url_decode(
                    bundle["request"]["signaturePreimage"],
                    "test signature preimage",
                    teacher_lineage_module.MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_INPUT_BYTES,
                )
                digest = teacher_lineage_module._base64url_decode(
                    bundle["request"]["signatureInput"],
                    "test signing digest",
                    32,
                )
                self.assertEqual(hashlib.sha256(preimage).digest(), digest)
                self.assertEqual(
                    digest.hex(), bundle["request"]["signatureInputSha256"]
                )
                external_bytes = teacher_lineage_module._base64url_decode(
                    external["signature"], "test external signature", 80
                )
                if signature_format == "asn1-der":
                    _, external_s = decode_dss_signature(external_bytes)
                else:
                    external_s = int.from_bytes(external_bytes[32:], "big")
                self.assertGreater(
                    external_s, verifier_authority_module._P256_ORDER // 2
                )
                output_signature = teacher_lineage_module._base64url_decode(
                    finalized.envelope["signature"], "test output signature", 64
                )
                self.assertLessEqual(
                    int.from_bytes(output_signature[32:], "big"),
                    verifier_authority_module._P256_ORDER // 2,
                )
                self.assertEqual(
                    direct_unsigned,
                    {
                        name: value
                        for name, value in finalized.envelope.items()
                        if name != "signature"
                    },
                )

        self.assertIsNotNone(finalized)
        created, _, _, _ = self._issue_receipts(
            teacher_lineage_admission_path=finalized.path
        )
        self.assertIsNotNone(created.teacher_lineage_admission)

    def test_detached_raw_preimage_succeeds_and_double_hashing_fails(self) -> None:
        raw_bundle, _, raw_signature, _ = self._prepare_detached(
            "raw-preimage",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
            signing_mode="raw-preimage",
        )
        finalized = self._finalize_detached(
            raw_bundle,
            raw_signature,
            "raw-preimage.admission.json",
        )
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION,
            finalized.envelope["schemaVersion"],
        )

        bad_bundle, _, bad_signature, _ = self._prepare_detached(
            "double-hashed-digest",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
            signing_mode="double-hashed-digest",
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                bad_bundle,
                bad_signature,
                "double-hashed-digest.admission.json",
            )

    def test_detached_schemas_are_closed_and_match_wire_literals(self) -> None:
        schema_root = ROOT / "schemas"
        bundle_schema = json.loads(
            (
                schema_root
                / "teacher-materialization-lineage-admission-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_schema = json.loads(
            (
                schema_root
                / "teacher-materialization-lineage-admission-signature.v1.schema.json"
            ).read_bytes()
        )
        self.assertFalse(bundle_schema["additionalProperties"])
        self.assertFalse(signature_schema["additionalProperties"])
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
            bundle_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION,
            signature_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertTrue(
            all(
                definition["const"] is False
                for definition in bundle_schema["properties"]["authority"][
                    "properties"
                ].values()
            )
        )
        _, bundle, _, signature = self._prepare_detached(
            "schema",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
        )
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(signature)

    def test_detached_bundle_signature_trust_and_live_inputs_are_revalidated(
        self,
    ) -> None:
        bundle_path, bundle, signature_path, signature = self._prepare_detached(
            "mutations",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
        )
        bundle_mutations = (
            ("authority", lambda value: value["authority"].update(training=True)),
            ("trust", lambda value: value["trust"].update(keyId="wrong-key")),
            (
                "preimage",
                lambda value: value["request"].update(signaturePreimage="AA"),
            ),
            (
                "digest",
                lambda value: value["request"].update(signatureInput="A" * 43),
            ),
        )
        for label, mutate in bundle_mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(bundle)
                mutate(changed)
                changed["bundleId"] = (
                    teacher_materialization_lineage_admission_signing_bundle_id(changed)
                )
                changed_path = self.fixture.root / f"{label}.bundle.json"
                changed_path.write_bytes(canonical_json_bytes(changed) + b"\n")
                with self.assertRaises(ValidationError):
                    self._finalize_detached(
                        changed_path,
                        signature_path,
                        f"{label}.admission.json",
                    )

        changed_signature = copy.deepcopy(signature)
        changed_signature["signingBundleSha256"] = "0" * 64
        changed_signature["signatureId"] = (
            teacher_materialization_lineage_admission_signature_id(changed_signature)
        )
        changed_signature_path = self.fixture.root / "wrong-bundle.signature.json"
        changed_signature_path.write_bytes(
            canonical_json_bytes(changed_signature) + b"\n"
        )
        with self.assertRaisesRegex(ValidationError, "exact signing bundle"):
            self._finalize_detached(
                bundle_path,
                changed_signature_path,
                "wrong-bundle.admission.json",
            )

        malformed_signatures = []
        malformed_der = copy.deepcopy(signature)
        malformed_der["signature"] = teacher_lineage_module._base64url_encode(
            b"\x30\x00"
        )
        malformed_der["signatureId"] = (
            teacher_materialization_lineage_admission_signature_id(malformed_der)
        )
        malformed_signatures.append(("malformed-der", malformed_der, "canonical"))

        zero_p1363 = copy.deepcopy(signature)
        zero_p1363["format"] = TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT
        zero_p1363["signature"] = teacher_lineage_module._base64url_encode(b"\x00" * 64)
        zero_p1363["signatureId"] = (
            teacher_materialization_lineage_admission_signature_id(zero_p1363)
        )
        malformed_signatures.append(("zero-p1363", zero_p1363, "out-of-range"))

        bad_format = copy.deepcopy(signature)
        bad_format["format"] = "unsupported"
        bad_format["signatureId"] = (
            teacher_materialization_lineage_admission_signature_id(bad_format)
        )
        malformed_signatures.append(("bad-format", bad_format, "must be"))

        bad_id = copy.deepcopy(signature)
        bad_id["signatureId"] = "vqtlineagesignature-" + "0" * 64
        malformed_signatures.append(("bad-id", bad_id, "content-derived"))

        for label, document, message in malformed_signatures:
            with self.subTest(label=label):
                path = self.fixture.root / f"{label}.signature.json"
                path.write_bytes(canonical_json_bytes(document) + b"\n")
                with self.assertRaisesRegex(ValidationError, message):
                    self._finalize_detached(
                        bundle_path,
                        path,
                        f"{label}.admission.json",
                    )

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_bundle, _, wrong_signature, _ = self._prepare_detached(
            "wrong-key",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
            signing_key=wrong_key,
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                wrong_bundle,
                wrong_signature,
                "wrong-key.admission.json",
            )

        original = self.evidence_path.read_bytes()
        self.evidence_path.write_bytes(original + b"drift")
        try:
            with self.assertRaisesRegex(ValidationError, "revalidated lineage"):
                self._finalize_detached(
                    bundle_path,
                    signature_path,
                    "drifted.admission.json",
                )
        finally:
            self.evidence_path.write_bytes(original)

    def test_detached_expiry_and_no_clobber_fail_closed(self) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached(
            "expiry",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
        )
        expired_output = self.fixture.root / "expired.admission.json"
        with self.assertRaisesRegex(ValidationError, "not active"):
            self._finalize_detached(
                bundle_path,
                signature_path,
                expired_output.name,
                now=EXPIRES,
            )
        self.assertFalse(expired_output.exists())

        occupied = self.fixture.root / "occupied.admission.json"
        occupied.write_bytes(b"existing owner\n")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._finalize_detached(
                bundle_path,
                signature_path,
                occupied.name,
            )
        self.assertEqual(b"existing owner\n", occupied.read_bytes())

        prepare_arguments = self._creation_arguments(
            output_path=self.fixture.root / "expired.bundle.json",
            now=EXPIRES,
        )
        prepare_arguments.pop("private_key_path")
        prepare_arguments.pop("private_key_password")
        with self.assertRaisesRegex(ValidationError, "not active"):
            prepare_teacher_materialization_lineage_admission_signing_bundle(
                **prepare_arguments
            )

        slow_output = self.fixture.root / "slow-expiry.bundle.json"
        slow_arguments = self._creation_arguments(
            output_path=slow_output,
            now=None,
        )
        slow_arguments.pop("private_key_path")
        slow_arguments.pop("private_key_password")
        with mock.patch.object(
            teacher_lineage_module,
            "_fresh_validation_time",
            side_effect=[ACTIVE, ACTIVE, EXPIRES],
        ):
            with self.assertRaisesRegex(ValidationError, "not active"):
                prepare_teacher_materialization_lineage_admission_signing_bundle(
                    **slow_arguments
                )
        self.assertFalse(slow_output.exists())

    def test_stable_subject_has_exact_cross_language_projection(self) -> None:
        draft = self.drafts[0]
        reviewed = self.reviewed[0]
        fields = teacher_lineage_subject_fields(reviewed)
        self.assertEqual(teacher_lineage_subject_fields(draft), fields)
        self.assertEqual("subject", fields[0][0])
        self.assertEqual("domains", fields[1][0])
        self.assertEqual(
            ["message", "message", "message", "source", "lineage"],
            [group[0] for group in fields[2:]],
        )
        self.assertEqual(
            teacher_lineage_subject_sha256(reviewed),
            _independent_subject_hash(fields),
        )

        excluded = copy.deepcopy(reviewed)
        excluded["verification"]["reviewer"] = "different-final-reviewer"
        excluded["verification"]["evidence"].append("Different review evidence.")
        excluded["rights"]["mayTrain"] = True
        excluded["sources"][0]["rights"]["mayTrain"] = True
        excluded["reviewStatus"] = "draft"
        excluded["useForTraining"] = True
        self.assertEqual(fields, teacher_lineage_subject_fields(excluded))

        reformatted = copy.deepcopy(reviewed)
        reformatted["cutoffUtc"] = "2026-01-01T12:00:00.0000000+00:00"
        reformatted["lineage"]["producedAtUtc"] = "2026-01-02T01:00:00+01:00"
        reformatted["sources"][0]["retrievedAtUtc"] = "2026-01-01T12:00:00+01:00"
        reformatted["sources"][0]["availableAtUtc"] = "2025-12-31T13:00:00+01:00"
        self.assertEqual(fields, teacher_lineage_subject_fields(reformatted))

        for mutate in (
            lambda row: row["messages"][-1].__setitem__("content", "changed"),
            lambda row: row["sources"][0].__setitem__("content", "changed"),
            lambda row: row["lineage"].__setitem__("modelRevision", "changed"),
            lambda row: row.__setitem__("provenance", "changed"),
        ):
            changed = copy.deepcopy(reviewed)
            mutate(changed)
            self.assertNotEqual(fields, teacher_lineage_subject_fields(changed))

    def test_exact_corpus_and_ordered_subject_mutations_are_rejected(self) -> None:
        self._create()
        original = self.dataset_path.read_bytes()

        rights_changed = copy.deepcopy(self.reviewed)
        rights_changed[0]["rights"]["mayTrain"] = True
        self._write_rows(self.dataset_path, rights_changed)
        with self.assertRaisesRegex(ValidationError, "reviewedCorpus"):
            self._verify_dataset_only()
        self.dataset_path.write_bytes(original)

        stable_changed = copy.deepcopy(self.reviewed)
        stable_changed[0]["messages"][-1]["content"] += " Changed."
        stable_changed[0]["conversationSha256"] = expert_conversation_sha256(
            stable_changed[0]["messages"]
        )
        self._write_rows(self.dataset_path, stable_changed)
        with self.assertRaises(ValidationError):
            self._verify_dataset_only()
        self.dataset_path.write_bytes(original)

        extra = copy.deepcopy(self.reviewed[0])
        extra["id"] = "extra-open-weight-teacher"
        extra["contaminationGroup"] = "extra-open-weight-group"
        self._write_rows(self.dataset_path, [*self.reviewed, extra])
        with self.assertRaisesRegex(ValidationError, "not present"):
            self._create(output_path=self.fixture.root / "extra.json")

        downgraded = copy.deepcopy(self.reviewed[0])
        downgraded["lineage"].update(
            {
                "origin": "HumanAuthored",
                "modelId": None,
                "modelRevision": None,
                "promptSha256": None,
                "profileVersion": None,
            }
        )
        self._write_rows(self.dataset_path, [downgraded])
        with self.assertRaisesRegex(ValidationError, "downgrades"):
            self._create(output_path=self.fixture.root / "downgraded.json")

        relabeled = copy.deepcopy(self.reviewed[0])
        relabeled["id"] = "relabeled-human-copy"
        relabeled["contaminationGroup"] = "relabeled-human-copy-group"
        relabeled["lineage"].update(
            {
                "origin": "HumanAuthored",
                "modelId": None,
                "modelRevision": None,
                "promptSha256": None,
                "profileVersion": None,
            }
        )
        self._write_rows(self.dataset_path, [self.reviewed[0], relabeled])
        with self.assertRaisesRegex(ValidationError, "duplicates"):
            self._create(output_path=self.fixture.root / "relabeled-copy.json")

        human_path = self.fixture.root / "human-only.jsonl"
        self._write_rows(human_path, [self._human_row()])
        with self.assertRaisesRegex(ValidationError, "OpenWeightTeacher"):
            self._verify_dataset_only(reviewed_dataset_path=human_path)

    def test_package_runtime_evidence_anchor_and_reviewer_drift_are_rejected(
        self,
    ) -> None:
        self._create()

        runtime = self.fixture.runtime_binding_path.read_bytes()
        self.fixture.runtime_binding_path.write_bytes(runtime + b" ")
        with self.assertRaises(ValidationError):
            verify_teacher_materialization_lineage_admission(
                self.admission_path,
                materialization_path=self.fixture.output_path,
                runtime_binding_path=self.fixture.runtime_binding_path,
                reviewed_dataset_path=self.dataset_path,
                reviewer_evidence_path=self.evidence_path,
                trust=self.trust,
                now=ACTIVE,
            )
        self.fixture.runtime_binding_path.write_bytes(runtime)

        evidence = self.evidence_path.read_bytes()
        self.evidence_path.write_bytes(evidence + b"changed\n")
        with self.assertRaisesRegex(ValidationError, "reviewerEvidence"):
            verify_teacher_materialization_lineage_admission(
                self.admission_path,
                materialization_path=self.fixture.output_path,
                runtime_binding_path=self.fixture.runtime_binding_path,
                reviewed_dataset_path=self.dataset_path,
                reviewer_evidence_path=self.evidence_path,
                trust=self.trust,
                now=ACTIVE,
            )
        self.evidence_path.write_bytes(evidence)

        added = self.fixture.output_path / "unexpected-lineage-file.bin"
        added.write_bytes(b"unexpected")
        with self.assertRaises(ValidationError):
            verify_teacher_materialization_lineage_admission(
                self.admission_path,
                materialization_path=self.fixture.output_path,
                runtime_binding_path=self.fixture.runtime_binding_path,
                reviewed_dataset_path=self.dataset_path,
                reviewer_evidence_path=self.evidence_path,
                trust=self.trust,
                now=ACTIVE,
            )
        added.unlink()

        anchors_removed = copy.deepcopy(self.reviewed)
        verification = anchors_removed[0]["verification"]
        verification["evidence"] = [
            item
            for item in verification["evidence"]
            if not item.startswith("teacherAdmissionSha256=")
        ]
        verification["evidenceSha256"] = _verification_evidence_sha256(
            verification["evidence"], [], []
        )
        self._write_rows(self.dataset_path, anchors_removed)
        with self.assertRaisesRegex(ValidationError, "teacherAdmissionSha256"):
            self._create(output_path=self.fixture.root / "anchors-removed.json")

        self._write_rows(self.dataset_path, self.reviewed)
        with self.assertRaisesRegex(ValidationError, "must differ"):
            self._create(
                output_path=self.fixture.root / "reviewer-collision.json",
                reviewer_id="independent-selector",
            )

    def test_signature_expiry_pins_and_atomic_no_clobber_are_enforced(self) -> None:
        created = self._create()
        original = self.admission_path.read_bytes()
        envelope = json.loads(original)
        signature = teacher_lineage_module._base64url_decode(
            envelope["signature"], "test signature", 64
        )
        order = verifier_authority_module._P256_ORDER
        high_s = order - int.from_bytes(signature[32:], "big")
        malleated = signature[:32] + high_s.to_bytes(32, "big")
        envelope["signature"] = teacher_lineage_module._base64url_encode(malleated)
        high_s_path = self.fixture.root / "high-s-admission.json"
        high_s_path.write_bytes(canonical_json_bytes(envelope) + b"\n")
        with self.assertRaisesRegex(ValidationError, "low-S"):
            self._verify_dataset_only(high_s_path)

        with self.assertRaisesRegex(ValidationError, "not active"):
            self._verify_dataset_only(now=EXPIRES)
        with self.assertRaisesRegex(ValidationError, "expected exact SHA-256"):
            self._verify_dataset_only(expected_envelope_sha256="0" * 64)
        wrong_trust = TeacherMaterializationLineageAdmissionTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.trust.public_key_spki_sha256,
            audience=self.trust.audience,
            key_id="wrong-lineage-key",
            signer_role=self.trust.signer_role,
        )
        with self.assertRaisesRegex(ValidationError, "externally pinned trust"):
            self._verify_dataset_only(trust=wrong_trust)

        ensure_teacher_materialization_lineage_admission_active(created, ACTIVE)
        with self.assertRaisesRegex(ValidationError, "expired"):
            ensure_teacher_materialization_lineage_admission_active(created, EXPIRES)
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._create()
        self.assertEqual(original, self.admission_path.read_bytes())

    def test_failed_final_validation_removes_only_the_created_output(self) -> None:
        original_verify = (
            teacher_lineage_module.verify_teacher_materialization_lineage_admission
        )
        failed_path = self.fixture.root / "failed-final-validation.json"
        with mock.patch.object(
            teacher_lineage_module,
            "verify_teacher_materialization_lineage_admission",
            side_effect=ValidationError("forced final validation failure"),
        ):
            with self.assertRaisesRegex(ValidationError, "forced final"):
                self._create(output_path=failed_path)
        self.assertFalse(failed_path.exists())

        raced_path = self.fixture.root / "raced-final-validation.json"
        replacement = b"concurrent replacement owner\n"

        def replace_then_fail(path, **arguments):
            destination = Path(path)
            if destination.name.endswith(".staging"):
                return original_verify(path, **arguments)
            destination.unlink()
            destination.write_bytes(replacement)
            raise ValidationError("forced raced final validation failure")

        with mock.patch.object(
            teacher_lineage_module,
            "verify_teacher_materialization_lineage_admission",
            side_effect=replace_then_fail,
        ):
            with self.assertRaisesRegex(ValidationError, "forced raced"):
                self._create(output_path=raced_path)
        self.assertEqual(replacement, raced_path.read_bytes())

    def test_cleanup_failure_aborts_signed_publication_and_reports_residual(
        self,
    ) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached(
            "cleanup",
            signature_format=TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
        )
        output = self.fixture.root / "cleanup.admission.json"
        real_unlink = Path.unlink

        def fail_staging_unlink(path: Path, *args, **kwargs):
            if path.name.endswith(".staging"):
                raise OSError("simulated cleanup failure")
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", fail_staging_unlink),
            self.assertRaisesRegex(ValidationError, "residual material"),
        ):
            self._finalize_detached(
                bundle_path,
                signature_path,
                output.name,
            )
        self.assertFalse(output.exists())
        residuals = list(self.fixture.root.glob(".*.staging"))
        self.assertEqual(1, len(residuals))
        residual = residuals[0]
        verified = verify_teacher_materialization_lineage_admission(
            residual,
            materialization_path=self.fixture.output_path,
            runtime_binding_path=self.fixture.runtime_binding_path,
            reviewed_dataset_path=self.dataset_path,
            reviewer_evidence_path=self.evidence_path,
            trust=self.trust,
            now=ACTIVE,
        )
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
            verified.payload["schemaVersion"],
        )
        real_unlink(residual)

    def test_unknown_destination_ownership_reports_residual_authority(self) -> None:
        output = self.fixture.root / "ownership-unknown.admission.json"
        original_verify = (
            teacher_lineage_module.verify_teacher_materialization_lineage_admission
        )
        real_lstat = Path.lstat

        def fail_installed_validation(path, **arguments):
            if Path(path).name.endswith(".staging"):
                return original_verify(path, **arguments)
            raise ValidationError("forced installed validation failure")

        def deny_destination_lstat(path: Path, *args, **kwargs):
            if path == output and os.path.lexists(path):
                raise PermissionError("simulated ownership lookup failure")
            return real_lstat(path, *args, **kwargs)

        with (
            mock.patch.object(
                teacher_lineage_module,
                "verify_teacher_materialization_lineage_admission",
                side_effect=fail_installed_validation,
            ),
            mock.patch.object(Path, "lstat", deny_destination_lstat),
            self.assertRaisesRegex(
                ValidationError, "ownership could not be verified.*residual material"
            ),
        ):
            self._create(output_path=output)
        self.assertTrue(output.exists())
        verified = verify_teacher_materialization_lineage_admission(
            output,
            materialization_path=self.fixture.output_path,
            runtime_binding_path=self.fixture.runtime_binding_path,
            reviewed_dataset_path=self.dataset_path,
            reviewer_evidence_path=self.evidence_path,
            trust=self.trust,
            now=ACTIVE,
        )
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
            verified.payload["schemaVersion"],
        )
        output.unlink()

    def test_live_publication_clock_rejects_expiry_after_slow_validation(self) -> None:
        admission_path = self.fixture.root / "expired-during-publication.json"
        with mock.patch.object(
            teacher_lineage_module,
            "_fresh_validation_time",
            side_effect=[ACTIVE, ACTIVE, EXPIRES],
        ):
            with self.assertRaisesRegex(ValidationError, "expired"):
                self._create(output_path=admission_path, now=None)
        self.assertFalse(admission_path.exists())

        self._create()
        receipt_path = self.fixture.root / "review-receipts.jsonl"
        with mock.patch.object(
            review_receipts_module,
            "_fresh_validation_time",
            side_effect=[ACTIVE, ACTIVE, EXPIRES],
        ):
            with self.assertRaisesRegex(
                ValidationError, "not currently active|inactive|expired"
            ):
                self._issue_receipts(now=None)
        self.assertFalse(receipt_path.exists())

    def test_two_row_materialization_allows_omission_but_rejects_reordering(
        self,
    ) -> None:
        generation = copy.deepcopy(self.fixture.generation)
        generation["budget"]["maxRequests"] = 4
        second = copy.deepcopy(generation["tasks"][0])
        second["taskId"] = "teacher-task-002"
        second["messages"][-1]["content"] = "What must happen after review?"
        second["contaminationGroup"] = "teacher-group-002"
        second["sources"][0]["id"] = "source-002"
        second["sources"][0]["title"] = "Second reviewed risk note"
        generation["tasks"].append(second)
        self.fixture.generation = generation
        self.fixture._write_json(self.fixture.generation_path, generation)
        self.fixture.candidates_path.unlink()
        monotonic = iter((1.0, 1.1, 2.0, 2.1, 3.0, 3.1, 4.0, 4.1)).__next__
        original_capture = materialization_test_module.capture_teacher_candidates

        def capture_with_longer_clock(**arguments):
            arguments["monotonic"] = monotonic
            return original_capture(**arguments)

        with mock.patch.object(
            materialization_test_module,
            "capture_teacher_candidates",
            side_effect=capture_with_longer_clock,
        ):
            self.fixture._capture()
        candidates = self.fixture._candidate_records()
        self.assertEqual(4, len(candidates))
        candidates_by_task = {}
        for candidate in candidates:
            candidates_by_task.setdefault(candidate["task"]["taskId"], candidate)
        self.assertEqual(2, len(candidates_by_task))
        selection = self.fixture._selection_manifest()
        selection["selection"]["candidates"] = [
            {
                "candidateId": candidate["candidateId"],
                "candidateSha256": candidate["candidateSha256"],
            }
            for candidate in candidates_by_task.values()
        ]
        self.fixture.selection = selection
        self.fixture._write_json(self.fixture.selection_path, selection)
        package = self.fixture.root / "materialized-two"
        materialize_teacher_candidates(
            selection_manifest_path=self.fixture.selection_path,
            output_directory=package,
            now=materialization_test_module.NOW,
        )
        drafts = self._read_rows(package / MATERIALIZED_DATASET_PATH)
        reviewed = [self._approve(row) for row in drafts]
        self.assertEqual(2, len(reviewed))

        self._write_rows(self.dataset_path, reviewed[:1])
        omitted = self._create(
            output_path=self.fixture.root / "omitted-admission.json",
            materialization_path=package,
        )
        self.assertEqual(
            1, omitted.payload["reviewedCorpus"]["openWeightTeacherRecordCount"]
        )

        self._write_rows(self.dataset_path, list(reversed(reviewed)))
        with self.assertRaisesRegex(ValidationError, "reorders"):
            self._create(
                output_path=self.fixture.root / "reordered-admission.json",
                materialization_path=package,
            )

        self._write_rows(self.dataset_path, [reviewed[0], reviewed[0]])
        with self.assertRaisesRegex(ValidationError, "duplicates"):
            self._create(
                output_path=self.fixture.root / "duplicate-admission.json",
                materialization_path=package,
            )

    def test_manifest_v1_downgrade_and_schemas_are_rejected_or_closed(self) -> None:
        generation_snapshot = (
            self.fixture.output_path
            / "inputs"
            / "snapshot"
            / self.fixture.generation_path.name
        )
        generation = json.loads(generation_snapshot.read_text(encoding="utf-8"))
        generation["schemaVersion"] = "daxalgo.vibe-quant.teacher-generation/v1"
        generation_snapshot.write_bytes(canonical_json_bytes(generation) + b"\n")
        with self.assertRaises(ValidationError):
            self._create()

        payload_schema = json.loads(
            (
                ROOT
                / "schemas/teacher-materialization-lineage-admission.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        envelope_schema = json.loads(
            (
                ROOT
                / "schemas/teacher-materialization-lineage-admission-envelope.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(payload_schema["additionalProperties"])
        self.assertFalse(envelope_schema["additionalProperties"])
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
            payload_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION,
            envelope_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertNotIn("materializationPackageIds", payload_schema["properties"])
        self.assertIn("materialization", payload_schema["required"])

    def test_review_receipts_require_and_revalidate_the_exact_lineage(self) -> None:
        self._create()
        created, output, public_path, spki = self._issue_receipts()
        self.assertIsNotNone(created.teacher_lineage_admission)
        verified = validate_expert_model_review_receipts(
            output,
            dataset_path=self.dataset_path,
            public_key_path=public_path,
            expected_public_key_spki_sha256=spki,
            expected_audience="daxalgo-teacher-review-receipts",
            expected_key_id="teacher-receipt-key-2026-01",
            expected_signer_role="teacher-receipt-reviewer",
            teacher_lineage_admission_path=self.admission_path,
            teacher_materialization_path=self.fixture.output_path,
            teacher_runtime_binding_path=self.fixture.runtime_binding_path,
            teacher_lineage_reviewer_evidence_path=self.evidence_path,
            teacher_lineage_admission_trust=self.trust,
            now=ACTIVE,
        )
        self.assertEqual(len(self.reviewed), verified.receipt_count)

        with self.assertRaisesRegex(ValidationError, "lineage admission"):
            validate_expert_model_review_receipts(
                output,
                dataset_path=self.dataset_path,
                public_key_path=public_path,
                expected_public_key_spki_sha256=spki,
                expected_audience="daxalgo-teacher-review-receipts",
                expected_key_id="teacher-receipt-key-2026-01",
                expected_signer_role="teacher-receipt-reviewer",
                now=ACTIVE,
            )

    def test_review_receipts_reject_teacher_anchor_on_relabelled_origin(self) -> None:
        relabelled = copy.deepcopy(self.reviewed[0])
        relabelled["lineage"].update(
            {
                "origin": "HumanAuthored",
                "modelId": None,
                "modelRevision": None,
                "promptSha256": None,
                "profileVersion": None,
            }
        )
        self._write_rows(self.dataset_path, [relabelled])
        with self.assertRaisesRegex(ValidationError, "teacherAdmissionSha256"):
            self._issue_receipts(
                teacher_lineage_admission_path=None,
                teacher_materialization_path=None,
                teacher_runtime_binding_path=None,
                teacher_lineage_reviewer_evidence_path=None,
                teacher_lineage_admission_trust=None,
            )

        without_lineage = {
            "teacher_lineage_admission_path": None,
            "teacher_materialization_path": None,
            "teacher_runtime_binding_path": None,
            "teacher_lineage_reviewer_evidence_path": None,
            "teacher_lineage_admission_trust": None,
        }
        with mock.patch.object(
            review_receipts_module,
            "_teacher_lineage_subjects_for_corpus",
            return_value=[],
        ):
            _, output, public_path, spki = self._issue_receipts(**without_lineage)
        with self.assertRaisesRegex(ValidationError, "teacherAdmissionSha256"):
            validate_expert_model_review_receipts(
                output,
                dataset_path=self.dataset_path,
                public_key_path=public_path,
                expected_public_key_spki_sha256=spki,
                expected_audience="daxalgo-teacher-review-receipts",
                expected_key_id="teacher-receipt-key-2026-01",
                expected_signer_role="teacher-receipt-reviewer",
                now=ACTIVE,
            )

    def test_review_receipt_lineage_signer_and_window_cannot_be_bypassed(self) -> None:
        self._create()
        with self.assertRaisesRegex(ValidationError, "must differ"):
            self._issue_receipts(
                private_key_path=self.private_key_path,
                public_key_path=self.public_key_path,
            )
        with self.assertRaisesRegex(ValidationError, "must not outlive"):
            self._issue_receipts(
                output_path=self.fixture.root / "overlong-receipts.jsonl",
                expires_at_utc="2027-01-04T00:00:03Z",
            )

    def test_cli_creates_and_fully_revalidates_lineage_admission(self) -> None:
        trust_flags = [
            "--teacher-lineage-admission-public-key",
            str(self.public_key_path),
            "--teacher-lineage-admission-public-key-spki-sha256",
            self.trust.public_key_spki_sha256,
            "--teacher-lineage-admission-audience",
            self.trust.audience,
            "--teacher-lineage-admission-key-id",
            self.trust.key_id,
            "--teacher-lineage-admission-signer-role",
            self.trust.signer_role,
        ]
        common = [
            "--materialization",
            str(self.fixture.output_path),
            "--runtime-binding",
            str(self.fixture.runtime_binding_path),
            "--reviewed-dataset",
            str(self.dataset_path),
            "--reviewer-evidence",
            str(self.evidence_path),
            *trust_flags,
        ]
        with redirect_stdout(StringIO()):
            self.assertEqual(
                0,
                cli_main(
                    [
                        "create-teacher-lineage-admission",
                        "--output",
                        str(self.admission_path),
                        *common,
                        "--private-key",
                        str(self.private_key_path),
                        "--reviewer-id",
                        "independent-lineage-governor",
                        "--reviewed-at-utc",
                        "2026-01-04T00:00:00Z",
                        "--issued-at-utc",
                        "2026-01-04T00:00:01Z",
                        "--not-before-utc",
                        "2026-01-04T00:00:02Z",
                        "--expires-at-utc",
                        "2027-01-04T00:00:02Z",
                    ]
                ),
            )

        bundle_path = self.fixture.root / "cli-lineage.bundle.json"
        signature_path = self.fixture.root / "cli-lineage.signature.json"
        detached_path = self.fixture.root / "cli-lineage.admission.json"
        authoring_flags = [
            "--reviewer-id",
            "independent-lineage-governor",
            "--reviewed-at-utc",
            "2026-01-04T00:00:00Z",
            "--issued-at-utc",
            "2026-01-04T00:00:01Z",
            "--not-before-utc",
            "2026-01-04T00:00:02Z",
            "--expires-at-utc",
            "2027-01-04T00:00:02Z",
        ]
        with redirect_stdout(StringIO()):
            self.assertEqual(
                0,
                cli_main(
                    [
                        "prepare-teacher-lineage-admission-signing-bundle",
                        "--output",
                        str(bundle_path),
                        *common,
                        *authoring_flags,
                    ]
                ),
            )
            self.assertEqual(
                0,
                cli_main(
                    [
                        "validate-teacher-lineage-admission",
                        str(self.admission_path),
                        *common,
                    ]
                ),
            )
        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        digest = teacher_lineage_module._base64url_decode(
            bundle["request"]["signatureInput"], "test CLI digest", 32
        )
        signature = self.private_key_object.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        signature_document = teacher_lineage_module._build_external_signature_document(
            bundle,
            bundle_bytes,
            signature_format=(TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT),
            signature=signature,
        )
        signature_path.write_bytes(canonical_json_bytes(signature_document) + b"\n")
        with redirect_stdout(StringIO()):
            self.assertEqual(
                0,
                cli_main(
                    [
                        "finalize-teacher-lineage-admission",
                        "--signing-bundle",
                        str(bundle_path),
                        "--signature",
                        str(signature_path),
                        "--output",
                        str(detached_path),
                        *common,
                    ]
                ),
            )
            self.assertEqual(
                0,
                cli_main(
                    [
                        "validate-teacher-lineage-admission",
                        str(detached_path),
                        *common,
                    ]
                ),
            )

        for command in (
            "prepare-teacher-lineage-admission-signing-bundle",
            "finalize-teacher-lineage-admission",
        ):
            help_output = StringIO()
            with redirect_stdout(help_output), self.assertRaises(SystemExit) as raised:
                cli_main([command, "--help"])
            self.assertEqual(0, raised.exception.code)
            self.assertNotIn("--private-key", help_output.getvalue())


if __name__ == "__main__":
    unittest.main()
