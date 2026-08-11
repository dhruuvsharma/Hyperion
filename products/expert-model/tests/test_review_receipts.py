from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from base64 import urlsafe_b64decode, urlsafe_b64encode
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

import hyperion_model.cli as cli_module
import hyperion_model.review_receipts as review_receipts_module
from hyperion_model.cli import main
from hyperion_model.core import (
    ValidationError,
    canonical_json_bytes,
    expert_conversation_sha256,
)
from hyperion_model.release import _verification_evidence_sha256
from hyperion_model.review_receipts import (
    LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION,
    LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION,
    REVIEW_RECEIPT_ID_PREFIX,
    REVIEW_RECEIPT_SCHEMA_VERSION,
    REVIEW_RECEIPT_SIGNATURE_SET_SCHEMA_VERSION,
    REVIEW_RECEIPT_SIGNING_BUNDLE_SCHEMA_VERSION,
    SFT_METADATA_SCHEMA_VERSION,
    create_expert_model_review_receipts,
    expert_model_review_receipt_id,
    expert_model_review_receipt_signature_set_id,
    expert_model_review_receipt_signing_bundle_id,
    expert_model_sft_metadata,
    expert_model_sft_metadata_sha256,
    finalize_expert_model_review_receipts,
    legacy_expert_model_sft_metadata,
    legacy_expert_model_sft_metadata_sha256,
    normalize_sft_cutoff_utc,
    prepare_expert_model_review_receipt_signing_bundle,
    validate_expert_model_review_receipts,
)
from hyperion_model.teacher_lineage import (
    VerifiedTeacherMaterializationLineageAdmission,
)


CUTOFF = "2025-01-15T12:00:00Z"
PRODUCED = "2025-01-14T12:00:00Z"
VERIFIED = "2025-01-16T12:00:00Z"
APPROVED = "2025-01-20T12:00:00Z"
ISSUED = "2025-01-20T12:00:01Z"
NOT_BEFORE = "2025-01-20T12:00:02Z"
EXPIRES = "2026-01-20T12:00:02Z"
VALIDATION_TIME = datetime(2025, 2, 1, tzinfo=timezone.utc)
AUDIENCE = "daxalgo-hyperion-training"
KEY_ID = "review-key-2025-01"
SIGNER_ROLE = "expert-review-authority"
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _rights(*, train: bool = False, upload: bool = False) -> dict:
    return {
        "mayStore": True,
        "mayEvaluate": True,
        "mayTrain": train,
        "mayUploadToProvider": upload,
        "mayRedistribute": False,
    }


def _record(
    example_id: str,
    split: str = "development",
    *,
    train: bool = True,
    upload: bool = True,
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
                "provenance": "Synthetic receipt test fixture.",
                "license": "Test-only license",
                "retrievedAtUtc": PRODUCED,
                "availableAtUtc": PRODUCED,
                "uri": None,
                "rights": dict(rights),
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
        "provenance": "Synthetic rights-reviewed receipt fixture.",
        "license": "Test-only license",
        "rights": dict(rights),
        "reviewStatus": "approved",
        "cutoffUtc": CUTOFF,
        "useForTraining": train,
    }


def _code_record(example_id: str, task_kind: str = "CodeGeneration") -> dict:
    record = _record(example_id)
    source = "using DaxAlgo.Sdk; public sealed class ReviewedStrategy { }"
    record["taskKind"] = task_kind
    record["domains"] = ["CSharp"]
    record["messages"][-1]["content"] = source
    record["conversationSha256"] = expert_conversation_sha256(record["messages"])
    compile_evidence = [
        "profile=daxq-sdk-abi3-source/v1",
        f"sourceSha256={hashlib.sha256(source.encode()).hexdigest()}",
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


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_bytes(
        b"".join(canonical_json_bytes(record) + b"\n" for record in records)
    )


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _read_envelopes(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def _resign_envelope(
    envelope: dict,
    payload: dict,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict:
    payload_bytes = canonical_json_bytes(payload)
    signed = dict(envelope)
    signed["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
    signed["payload"] = _encode(payload_bytes)
    signed["signature"] = ""
    signed["signature"] = _encode(
        review_receipts_module._sign_p1363_low_s(
            private_key,
            review_receipts_module._signature_input(signed, payload_bytes),
        )
    )
    return signed


def _resign_as_v1(
    envelope: dict,
    record: dict,
    source_corpus_sha256: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> dict:
    payload = json.loads(_decode(envelope["payload"]))
    payload["schemaVersion"] = LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION
    payload["datasetSha256"] = payload.pop("sourceCorpusSha256")
    if payload["datasetSha256"] != source_corpus_sha256:
        raise AssertionError("test receipt does not match the supplied corpus")
    payload["sftMetadataSha256"] = legacy_expert_model_sft_metadata_sha256(record)
    payload["receiptId"] = REVIEW_RECEIPT_ID_PREFIX + "0" * 64
    payload["receiptId"] = expert_model_review_receipt_id(payload)
    legacy = dict(envelope)
    legacy["schemaVersion"] = LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION
    legacy["payloadType"] = LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION
    return _resign_envelope(legacy, payload, private_key)


class ReviewReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private_key = self.root / "private.pem"
        self.public_key = self.root / "public.pem"
        key = ec.generate_private_key(ec.SECP256R1())
        self.signing_key = key
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
        self.spki_sha256 = hashlib.sha256(spki).hexdigest()
        self.evidence = self.root / "approval.txt"
        self.evidence.write_bytes(b"Fixed human approval evidence.\n")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _issue(self, records: list[dict], name: str = "receipts.jsonl", **overrides):
        dataset = self.root / f"{name}.corpus.jsonl"
        output = self.root / name
        _write_jsonl(dataset, records)
        arguments = {
            "dataset_path": dataset,
            "output_path": output,
            "private_key_path": self.private_key,
            "public_key_path": self.public_key,
            "private_key_password": None,
            "audience": AUDIENCE,
            "key_id": KEY_ID,
            "signer_role": SIGNER_ROLE,
            "approval_id": "approval-2025-01",
            "actor_id": "review-board-1",
            "actor_role": SIGNER_ROLE,
            "approval_reference": "review://approval/2025-01",
            "approval_evidence_path": self.evidence,
            "approved_at_utc": APPROVED,
            "issued_at_utc": ISSUED,
            "not_before_utc": NOT_BEFORE,
            "expires_at_utc": EXPIRES,
            "now": VALIDATION_TIME,
        }
        arguments.update(overrides)
        verified = create_expert_model_review_receipts(**arguments)
        return dataset, output, verified

    def _validate(self, dataset: Path, receipts: Path, **overrides):
        arguments = {
            "dataset_path": dataset,
            "public_key_path": self.public_key,
            "expected_public_key_spki_sha256": self.spki_sha256,
            "expected_audience": AUDIENCE,
            "expected_key_id": KEY_ID,
            "expected_signer_role": SIGNER_ROLE,
            "now": VALIDATION_TIME,
        }
        arguments.update(overrides)
        return validate_expert_model_review_receipts(receipts, **arguments)

    def _prepare_detached_inputs(
        self,
        records: list[dict],
        name: str = "detached",
        *,
        formats: tuple[str, ...] | None = None,
        force_high_s: bool = False,
    ) -> tuple[Path, Path, dict, Path, dict]:
        dataset = self.root / f"{name}.corpus.jsonl"
        bundle_path = self.root / f"{name}.signing-bundle.json"
        signature_set_path = self.root / f"{name}.signatures.json"
        _write_jsonl(dataset, records)
        prepare_expert_model_review_receipt_signing_bundle(
            dataset_path=dataset,
            output_path=bundle_path,
            public_key_path=self.public_key,
            audience=AUDIENCE,
            key_id=KEY_ID,
            signer_role=SIGNER_ROLE,
            approval_id="approval-2025-01",
            actor_id="review-board-1",
            actor_role=SIGNER_ROLE,
            approval_reference="review://approval/2025-01",
            approval_evidence_path=self.evidence,
            approved_at_utc=APPROVED,
            issued_at_utc=ISSUED,
            not_before_utc=NOT_BEFORE,
            expires_at_utc=EXPIRES,
            now=VALIDATION_TIME,
        )
        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        selected_formats = formats or tuple(
            "asn1-der" if ordinal % 2 == 0 else "ieee-p1363-fixed-64"
            for ordinal in range(len(records))
        )
        if len(selected_formats) != len(records):
            raise AssertionError("test signature formats must cover every record")
        signatures: list[tuple[str, bytes]] = []
        for request, signature_format in zip(
            bundle["requests"], selected_formats, strict=True
        ):
            signing_digest = _decode(request["signatureInput"])
            der = self.signing_key.sign(
                signing_digest,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
            r, s = decode_dss_signature(der)
            if force_high_s and s <= P256_ORDER // 2:
                s = P256_ORDER - s
            if signature_format == "asn1-der":
                signature = encode_dss_signature(r, s)
            elif signature_format == "ieee-p1363-fixed-64":
                signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            else:
                raise AssertionError("unsupported test signature format")
            signatures.append((signature_format, signature))
        authorization_preimage = review_receipts_module._bundle_authorization_preimage(
            bundle_bytes
        )
        authorization_der = self.signing_key.sign(
            hashlib.sha256(authorization_preimage).digest(),
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        authorization_r, authorization_s = decode_dss_signature(authorization_der)
        if force_high_s and authorization_s <= P256_ORDER // 2:
            authorization_s = P256_ORDER - authorization_s
        signature_set = review_receipts_module._build_signature_set_document(
            bundle,
            bundle_bytes,
            signatures,
            bundle_authorization_signature=(
                "asn1-der",
                encode_dss_signature(authorization_r, authorization_s),
            ),
        )
        signature_set_path.write_bytes(canonical_json_bytes(signature_set))
        return dataset, bundle_path, bundle, signature_set_path, signature_set

    def _finalize_detached(
        self,
        dataset: Path,
        bundle_path: Path,
        signature_set_path: Path,
        output_name: str,
        **overrides,
    ):
        arguments = {
            "dataset_path": dataset,
            "signing_bundle_path": bundle_path,
            "signature_set_path": signature_set_path,
            "output_path": self.root / output_name,
            "public_key_path": self.public_key,
            "expected_public_key_spki_sha256": self.spki_sha256,
            "expected_audience": AUDIENCE,
            "expected_key_id": KEY_ID,
            "expected_signer_role": SIGNER_ROLE,
            "approval_evidence_path": self.evidence,
            "now": VALIDATION_TIME,
        }
        arguments.update(overrides)
        return finalize_expert_model_review_receipts(**arguments)

    def _fake_lineage_admission(
        self, marker: str = "a", *, expires_at_utc: str = EXPIRES
    ) -> VerifiedTeacherMaterializationLineageAdmission:
        digest = marker * 64
        expires_at = datetime.strptime(expires_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        payload = {
            "lineageAdmissionId": f"vqtlineage-{digest}",
            "reviewedCorpus": {
                "sha256": digest,
                "sizeBytes": 1,
                "recordCount": 1,
                "openWeightTeacherRecordCount": 1,
                "subjects": [
                    {
                        "exampleId": "fake-teacher-row",
                        "stableSubjectSha256": digest,
                        "knowledgeClass": "candidate-stable",
                        "teacherAdmissionSha256": digest,
                    }
                ],
            },
            "materialization": {
                "materializationId": f"vqtmat-{digest}",
                "materializationRecordSha256": digest,
                "draftDatasetSha256": digest,
                "draftDatasetSizeBytes": 1,
                "draftRecordCount": 1,
                "packageTreeSchemaVersion": (
                    "daxalgo.hyperion.teacher-materialization-package-tree/v1"
                ),
                "packageTreeSha256": digest,
                "packageFileCount": 1,
                "packageSizeBytes": 1,
                "selectionManifestSha256": digest,
                "candidateSetSha256": digest,
                "generationManifestSha256": digest,
                "candidateCatalogSha256": digest,
                "overlapDenySetSha256": digest,
                "overlapDenySetId": "fake-deny-set",
                "overlapScopeSha256": digest,
                "candidateBatchId": f"vqtgen-{digest}",
            },
            "reviewedAtUtc": "2025-01-20T11:59:57Z",
            "issuedAtUtc": "2025-01-20T11:59:58Z",
            "notBeforeUtc": "2025-01-20T11:59:59Z",
            "expiresAtUtc": expires_at_utc,
        }
        return VerifiedTeacherMaterializationLineageAdmission(
            path=self.root / f"fake-lineage-{marker}.json",
            envelope={},
            payload=payload,
            payload_bytes=canonical_json_bytes(payload),
            payload_sha256=digest,
            envelope_sha256=digest,
            public_key_spki_sha256=digest,
            reviewed_at_utc=datetime(2025, 1, 20, 11, 59, 57, tzinfo=timezone.utc),
            issued_at_utc=datetime(2025, 1, 20, 11, 59, 58, tzinfo=timezone.utc),
            not_before_utc=datetime(2025, 1, 20, 11, 59, 59, tzinfo=timezone.utc),
            expires_at_utc=expires_at,
        )

    def test_round_trip_derives_rights_review_kinds_and_sft_hashes(self) -> None:
        text_record = _record("text-training")
        code_record = _code_record("code-training", "CodeRepair")
        evaluation_record = _record(
            "evaluation-only", "calibration", train=False, upload=False
        )
        dataset, output, created = self._issue(
            [text_record, code_record, evaluation_record]
        )
        verified = self._validate(dataset, output)

        self.assertEqual(created.receipt_set_sha256, verified.receipt_set_sha256)
        self.assertEqual(3, verified.receipt_count)
        text, code, evaluation = [item.payload for item in verified.receipts]
        self.assertEqual("deterministic-text", text["reviewKind"])
        self.assertEqual("daxq-executable", code["reviewKind"])
        self.assertEqual(
            {"evaluation": True, "training": True, "providerUpload": True},
            text["authorizations"],
        )
        self.assertEqual(
            {"evaluation": True, "training": False, "providerUpload": False},
            evaluation["authorizations"],
        )
        self.assertEqual(
            expert_model_sft_metadata_sha256(
                text_record, source_corpus_sha256=created.dataset_sha256
            ),
            text["sftMetadataSha256"],
        )
        self.assertEqual(REVIEW_RECEIPT_SCHEMA_VERSION, text["schemaVersion"])
        self.assertEqual(created.dataset_sha256, text["sourceCorpusSha256"])
        self.assertNotIn("datasetSha256", text)
        metadata = expert_model_sft_metadata(
            text_record, source_corpus_sha256=created.dataset_sha256
        )
        self.assertEqual(SFT_METADATA_SCHEMA_VERSION, metadata["schemaVersion"])
        self.assertEqual(created.dataset_sha256, metadata["sourceCorpusSha256"])
        self.assertEqual(
            text_record["verification"]["evidenceSha256"],
            metadata["verificationEvidenceSha256"],
        )
        self.assertTrue(text["receiptId"].startswith(REVIEW_RECEIPT_ID_PREFIX))
        self.assertEqual(
            "2025-01-15T12:00:00.1234567Z",
            normalize_sft_cutoff_utc("2025-01-15T07:00:00.1234567-05:00"),
        )
        for invalid_offset in (
            "2025-01-15T12:00:00+14:01",
            "2025-01-15T12:00:00-14:01",
            "2025-01-15T12:00:00+15:00",
        ):
            with (
                self.subTest(invalid_offset=invalid_offset),
                self.assertRaisesRegex(ValidationError, "invalid UTC offset"),
            ):
                normalize_sft_cutoff_utc(invalid_offset)

    def test_detached_der_and_p1363_round_trip_preserves_v2_wire(self) -> None:
        records = [_record("detached-der"), _record("detached-p1363")]
        dataset, bundle_path, bundle, signature_set_path, signature_set = (
            self._prepare_detached_inputs(records, force_high_s=True)
        )
        finalized = self._finalize_detached(
            dataset,
            bundle_path,
            signature_set_path,
            "detached.receipts.jsonl",
        )
        output = self.root / "detached.receipts.jsonl"
        verified = self._validate(dataset, output)

        self.assertEqual(
            REVIEW_RECEIPT_SIGNING_BUNDLE_SCHEMA_VERSION, bundle["schemaVersion"]
        )
        self.assertEqual(
            expert_model_review_receipt_signing_bundle_id(bundle), bundle["bundleId"]
        )
        self.assertEqual("unsigned-non-authorizing", bundle["status"])
        self.assertTrue(all(value is False for value in bundle["authority"].values()))
        self.assertEqual(
            REVIEW_RECEIPT_SIGNATURE_SET_SCHEMA_VERSION, signature_set["schemaVersion"]
        )
        self.assertEqual(
            expert_model_review_receipt_signature_set_id(signature_set),
            signature_set["signatureSetId"],
        )
        self.assertEqual(
            ["asn1-der", "ieee-p1363-fixed-64"],
            [item["format"] for item in signature_set["signatures"]],
        )
        bundle_authorization = signature_set["bundleAuthorization"]
        self.assertTrue(bundle_authorization["receiptFinalizationAuthorized"])
        self.assertTrue(
            all(
                value is False
                for name, value in bundle_authorization.items()
                if name.endswith("Authorized")
                and name != "receiptFinalizationAuthorized"
            )
        )
        _, authorization_s = decode_dss_signature(
            _decode(bundle_authorization["signature"])
        )
        self.assertGreater(authorization_s, P256_ORDER // 2)
        authorization_digest = hashlib.sha256(
            review_receipts_module._bundle_authorization_preimage(
                bundle_path.read_bytes()
            )
        ).digest()
        self.assertEqual(
            authorization_digest.hex(),
            bundle_authorization["signatureInputSha256"],
        )
        self.assertEqual(
            authorization_digest, _decode(bundle_authorization["signatureInput"])
        )
        for request in bundle["requests"]:
            preimage = _decode(request["signaturePreimage"])
            digest = _decode(request["signatureInput"])
            self.assertEqual(32, len(digest))
            self.assertEqual(hashlib.sha256(preimage).digest(), digest)
            self.assertEqual(digest.hex(), request["signatureInputSha256"])

        self.assertEqual(finalized.receipt_set_sha256, verified.receipt_set_sha256)
        self.assertEqual(2, verified.receipt_count)
        detached_envelopes = _read_envelopes(output)
        for envelope in detached_envelopes:
            signature = _decode(envelope["signature"])
            self.assertEqual(64, len(signature))
            self.assertLessEqual(int.from_bytes(signature[32:], "big"), P256_ORDER // 2)
            self.assertEqual(
                REVIEW_RECEIPT_SCHEMA_VERSION,
                json.loads(_decode(envelope["payload"]))["schemaVersion"],
            )

        _, direct_path, _ = self._issue(records, "direct-parity.jsonl")
        direct_envelopes = _read_envelopes(direct_path)
        for detached, direct in zip(detached_envelopes, direct_envelopes, strict=True):
            self.assertEqual(detached["payload"], direct["payload"])
            self.assertEqual(
                {key: value for key, value in detached.items() if key != "signature"},
                {key: value for key, value in direct.items() if key != "signature"},
            )

    def test_detached_rejects_bound_input_and_signature_mutations(self) -> None:
        records = [_record("detached-one"), _record("detached-two")]
        dataset, bundle_path, bundle, signature_set_path, signature_set = (
            self._prepare_detached_inputs(records, "detached-adversarial")
        )

        original_dataset = dataset.read_bytes()
        changed = json.loads(canonical_json_bytes(records[0]))
        changed["provenance"] = "Different but still valid provenance."
        _write_jsonl(dataset, [changed, records[1]])
        with self.assertRaisesRegex(ValidationError, "exact corpus"):
            self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                "changed-corpus.jsonl",
            )
        dataset.write_bytes(original_dataset)

        original_evidence = self.evidence.read_bytes()
        self.evidence.write_bytes(b"different approval evidence\n")
        with self.assertRaisesRegex(ValidationError, "approval"):
            self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                "changed-evidence.jsonl",
            )
        self.evidence.write_bytes(original_evidence)

        bundle_mutations: dict[str, dict] = {}
        changed_trust = json.loads(canonical_json_bytes(bundle))
        changed_trust["trust"]["keyId"] = "different-key"
        bundle_mutations["trust"] = changed_trust
        changed_approval = json.loads(canonical_json_bytes(bundle))
        changed_approval["approval"]["reference"] = "review://approval/substituted"
        bundle_mutations["approval"] = changed_approval
        changed_payload = json.loads(canonical_json_bytes(bundle))
        payload = json.loads(_decode(changed_payload["requests"][0]["payload"]))
        payload["reviewer"] = "different-reviewer"
        payload_bytes = canonical_json_bytes(payload)
        changed_payload["requests"][0]["payload"] = _encode(payload_bytes)
        changed_payload["requests"][0]["payloadSha256"] = hashlib.sha256(
            payload_bytes
        ).hexdigest()
        bundle_mutations["payload"] = changed_payload
        changed_input = json.loads(canonical_json_bytes(bundle))
        preimage = bytearray(_decode(changed_input["requests"][0]["signaturePreimage"]))
        preimage[-1] ^= 1
        digest = hashlib.sha256(preimage).digest()
        changed_input["requests"][0]["signaturePreimage"] = _encode(bytes(preimage))
        changed_input["requests"][0]["signatureInput"] = _encode(digest)
        changed_input["requests"][0]["signatureInputSha256"] = digest.hex()
        bundle_mutations["signature-input"] = changed_input
        for name, document in bundle_mutations.items():
            with self.subTest(bundle=name):
                document["bundleId"] = expert_model_review_receipt_signing_bundle_id(
                    document
                )
                mutated_bundle_path = self.root / f"mutated-{name}.bundle.json"
                mutated_bundle_path.write_bytes(canonical_json_bytes(document))
                output = self.root / f"mutated-{name}.receipts.jsonl"
                with self.assertRaises(ValidationError):
                    self._finalize_detached(
                        dataset,
                        mutated_bundle_path,
                        signature_set_path,
                        output.name,
                    )
                self.assertFalse(output.exists())

        noncanonical_bundle_path = self.root / "noncanonical-signing-bundle.json"
        noncanonical_bundle_path.write_bytes(bundle_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValidationError, "canonical JSON"):
            self._finalize_detached(
                dataset,
                noncanonical_bundle_path,
                signature_set_path,
                "noncanonical-signing-bundle.jsonl",
            )

        signature_mutations: dict[str, dict] = {}
        malformed_der = json.loads(canonical_json_bytes(signature_set))
        malformed_der["signatures"][0]["signature"] = _encode(b"\x30\x00")
        signature_mutations["malformed-der"] = malformed_der
        out_of_range = json.loads(canonical_json_bytes(signature_set))
        out_of_range["signatures"][1]["signature"] = _encode(b"\x00" * 64)
        signature_mutations["out-of-range"] = out_of_range
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_der = wrong_key.sign(
            _decode(bundle["requests"][1]["signatureInput"]),
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        wrong_r, wrong_s = decode_dss_signature(wrong_der)
        unverifiable = json.loads(canonical_json_bytes(signature_set))
        unverifiable["signatures"][1]["signature"] = _encode(
            wrong_r.to_bytes(32, "big") + wrong_s.to_bytes(32, "big")
        )
        signature_mutations["unverifiable"] = unverifiable
        wrong_bundle_der = wrong_key.sign(
            hashlib.sha256(
                review_receipts_module._bundle_authorization_preimage(
                    bundle_path.read_bytes()
                )
            ).digest(),
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        wrong_bundle_key = json.loads(canonical_json_bytes(signature_set))
        wrong_bundle_key["bundleAuthorization"]["format"] = "asn1-der"
        wrong_bundle_key["bundleAuthorization"]["signature"] = _encode(wrong_bundle_der)
        signature_mutations["wrong-bundle-key"] = wrong_bundle_key
        duplicate = json.loads(canonical_json_bytes(signature_set))
        duplicate["signatures"][1] = dict(duplicate["signatures"][0])
        duplicate["signatures"][1]["ordinal"] = 1
        signature_mutations["duplicate"] = duplicate
        missing = json.loads(canonical_json_bytes(signature_set))
        missing["signatures"] = missing["signatures"][:-1]
        signature_mutations["missing"] = missing
        reordered = json.loads(canonical_json_bytes(signature_set))
        reordered["signatures"].reverse()
        signature_mutations["reordered"] = reordered
        extra = json.loads(canonical_json_bytes(signature_set))
        extra["signatures"].append(dict(extra["signatures"][-1]))
        extra["signatures"][-1]["ordinal"] = 2
        signature_mutations["extra"] = extra
        for name, document in signature_mutations.items():
            with self.subTest(signature_set=name):
                document["signatureSetId"] = (
                    expert_model_review_receipt_signature_set_id(document)
                )
                mutated_set_path = self.root / f"mutated-{name}.signatures.json"
                mutated_set_path.write_bytes(canonical_json_bytes(document))
                output = self.root / f"mutated-{name}.jsonl"
                with self.assertRaises(ValidationError):
                    self._finalize_detached(
                        dataset,
                        bundle_path,
                        mutated_set_path,
                        output.name,
                    )
                self.assertFalse(output.exists())

        existing = self.root / "detached-existing.jsonl"
        existing.write_bytes(b"preserve-detached")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                existing.name,
            )
        self.assertEqual(b"preserve-detached", existing.read_bytes())

    def test_detached_publication_revalidation_cleans_its_output(self) -> None:
        dataset, bundle_path, _, signature_set_path, _ = self._prepare_detached_inputs(
            [_record("detached-publication")], "detached-publication"
        )
        expiry_output = self.root / "expiry-crossing.jsonl"
        expiry = datetime.strptime(EXPIRES, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        with (
            mock.patch.object(
                review_receipts_module,
                "_fresh_validation_time",
                side_effect=[VALIDATION_TIME, VALIDATION_TIME, expiry],
            ),
            self.assertRaisesRegex(ValidationError, "not currently active"),
        ):
            self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                expiry_output.name,
                now=None,
            )
        self.assertFalse(expiry_output.exists())

        lineage_output = self.root / "lineage-drift.jsonl"
        with (
            mock.patch.object(
                review_receipts_module,
                "_verify_teacher_lineage_for_receipts",
                side_effect=[None, ValidationError("simulated lineage drift")],
            ),
            self.assertRaisesRegex(ValidationError, "lineage drift"),
        ):
            self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                lineage_output.name,
            )
        self.assertFalse(lineage_output.exists())

        evidence_output = self.root / "approval-evidence-drift.jsonl"
        original_validation = (
            review_receipts_module.validate_expert_model_review_receipts
        )

        def validate_then_change_evidence(*args, **kwargs):
            verified = original_validation(*args, **kwargs)
            self.evidence.write_bytes(b"approval evidence changed after validation\n")
            return verified

        original_evidence = self.evidence.read_bytes()
        try:
            with (
                mock.patch.object(
                    review_receipts_module,
                    "validate_expert_model_review_receipts",
                    side_effect=validate_then_change_evidence,
                ),
                self.assertRaisesRegex(ValidationError, "changed during"),
            ):
                self._finalize_detached(
                    dataset,
                    bundle_path,
                    signature_set_path,
                    evidence_output.name,
                )
        finally:
            self.evidence.write_bytes(original_evidence)
        self.assertFalse(evidence_output.exists())

    def test_detached_binds_fresh_lineage_and_direct_checks_before_key_use(
        self,
    ) -> None:
        admission = self._fake_lineage_admission()
        with mock.patch.object(
            review_receipts_module,
            "_verify_teacher_lineage_for_receipts",
            return_value=admission,
        ):
            dataset, bundle_path, bundle, signature_set_path, signature_set = (
                self._prepare_detached_inputs(
                    [_record("lineage-bound")], "lineage-bound"
                )
            )
        summary = bundle["teacherLineageAdmission"]
        self.assertEqual(
            admission.payload["lineageAdmissionId"], summary["lineageAdmissionId"]
        )
        self.assertEqual(admission.payload_sha256, summary["payloadSha256"])
        self.assertEqual(admission.envelope_sha256, summary["envelopeSha256"])
        self.assertEqual(
            admission.public_key_spki_sha256, summary["publicKeySpkiSha256"]
        )
        self.assertEqual(admission.payload["reviewedCorpus"], summary["reviewedCorpus"])
        self.assertEqual(
            admission.payload["materialization"], summary["materialization"]
        )
        with mock.patch.object(
            review_receipts_module,
            "_verify_teacher_lineage_for_receipts",
            return_value=admission,
        ):
            verified = self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                "lineage-bound.receipts.jsonl",
            )
        self.assertEqual(admission, verified.teacher_lineage_admission)

        drift = self._fake_lineage_admission("b")
        drift_output = self.root / "lineage-binding-drift.jsonl"
        with (
            mock.patch.object(
                review_receipts_module,
                "_verify_teacher_lineage_for_receipts",
                return_value=drift,
            ),
            self.assertRaisesRegex(ValidationError, "freshly verified"),
        ):
            self._finalize_detached(
                dataset,
                bundle_path,
                signature_set_path,
                drift_output.name,
            )
        self.assertFalse(drift_output.exists())

        rewritten_bundle = json.loads(canonical_json_bytes(bundle))
        rewritten_bundle["teacherLineageAdmission"] = (
            review_receipts_module._teacher_lineage_admission_summary(drift)
        )
        rewritten_bundle["bundleId"] = expert_model_review_receipt_signing_bundle_id(
            rewritten_bundle
        )
        rewritten_bundle_bytes = canonical_json_bytes(rewritten_bundle)
        rewritten_bundle_path = self.root / "rewritten-lineage.bundle.json"
        rewritten_bundle_path.write_bytes(rewritten_bundle_bytes)
        reused_signatures = json.loads(canonical_json_bytes(signature_set))
        reused_signatures["signingBundleId"] = rewritten_bundle["bundleId"]
        reused_signatures["signingBundleSha256"] = hashlib.sha256(
            rewritten_bundle_bytes
        ).hexdigest()
        rewritten_authorization_digest = hashlib.sha256(
            review_receipts_module._bundle_authorization_preimage(
                rewritten_bundle_bytes
            )
        ).digest()
        reused_signatures["bundleAuthorization"]["signatureInputSha256"] = (
            rewritten_authorization_digest.hex()
        )
        reused_signatures["bundleAuthorization"]["signatureInput"] = _encode(
            rewritten_authorization_digest
        )
        reused_signatures["signatureSetId"] = (
            expert_model_review_receipt_signature_set_id(reused_signatures)
        )
        reused_signatures_path = self.root / "reused-lineage.signatures.json"
        reused_signatures_path.write_bytes(canonical_json_bytes(reused_signatures))
        reused_output = self.root / "reused-lineage.receipts.jsonl"
        with (
            mock.patch.object(
                review_receipts_module,
                "_verify_teacher_lineage_for_receipts",
                return_value=drift,
            ),
            self.assertRaisesRegex(ValidationError, "does not verify"),
        ):
            self._finalize_detached(
                dataset,
                rewritten_bundle_path,
                reused_signatures_path,
                reused_output.name,
            )
        self.assertFalse(reused_output.exists())

        with (
            mock.patch.object(
                review_receipts_module,
                "_verify_teacher_lineage_for_receipts",
                side_effect=ValidationError("unauthorized teacher lineage"),
            ),
            mock.patch.object(review_receipts_module, "_load_private_key") as load_key,
            mock.patch.object(review_receipts_module, "_sign_p1363_low_s") as sign,
            self.assertRaisesRegex(ValidationError, "unauthorized teacher lineage"),
        ):
            self._issue([_record("pre-sign-lineage")], "pre-sign-lineage.jsonl")
        load_key.assert_not_called()
        sign.assert_not_called()

        short_admission = self._fake_lineage_admission(
            "c", expires_at_utc="2025-12-31T23:59:59Z"
        )
        with (
            mock.patch.object(
                review_receipts_module,
                "_verify_teacher_lineage_for_receipts",
                return_value=short_admission,
            ),
            mock.patch.object(review_receipts_module, "_load_private_key") as load_key,
            mock.patch.object(review_receipts_module, "_sign_p1363_low_s") as sign,
            self.assertRaisesRegex(ValidationError, "must not outlive"),
        ):
            self._issue([_record("pre-sign-window")], "pre-sign-window.jsonl")
        load_key.assert_not_called()
        sign.assert_not_called()

    def test_schemas_are_machine_readable_strict_and_match_wire_literals(self) -> None:
        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        payload_v1 = json.loads(
            (schema_root / "expert-model-review-receipt.v1.schema.json").read_bytes()
        )
        payload = json.loads(
            (schema_root / "expert-model-review-receipt.v2.schema.json").read_bytes()
        )
        envelope_v1 = json.loads(
            (
                schema_root / "expert-model-review-receipt-envelope.v1.schema.json"
            ).read_bytes()
        )
        envelope = json.loads(
            (
                schema_root / "expert-model-review-receipt-envelope.v2.schema.json"
            ).read_bytes()
        )
        metadata = json.loads(
            (schema_root / "expert-model-sft-metadata.v2.schema.json").read_bytes()
        )
        signing_bundle = json.loads(
            (
                schema_root
                / "expert-model-review-receipt-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_set = json.loads(
            (
                schema_root / "expert-model-review-receipt-signature-set.v1.schema.json"
            ).read_bytes()
        )

        self.assertFalse(payload_v1["additionalProperties"])
        self.assertFalse(payload["additionalProperties"])
        self.assertNotIn("CodeReview", payload["properties"]["taskKind"]["enum"])
        self.assertIn("sourceCorpusSha256", payload["required"])
        self.assertNotIn("datasetSha256", payload["properties"])
        self.assertFalse(envelope_v1["additionalProperties"])
        self.assertFalse(envelope["additionalProperties"])
        self.assertEqual(
            "canonical-json-base64url",
            envelope["properties"]["payloadEncoding"]["const"],
        )
        self.assertEqual(
            "ieee-p1363-fixed-64-low-s",
            envelope["properties"]["signatureFormat"]["const"],
        )
        self.assertFalse(metadata["additionalProperties"])
        self.assertEqual(
            SFT_METADATA_SCHEMA_VERSION,
            metadata["properties"]["schemaVersion"]["const"],
        )
        self.assertIn("verificationEvidenceSha256", metadata["required"])
        self.assertEqual(
            REVIEW_RECEIPT_SIGNING_BUNDLE_SCHEMA_VERSION,
            signing_bundle["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            "unsigned-non-authorizing",
            signing_bundle["properties"]["status"]["const"],
        )
        self.assertTrue(
            all(
                value["const"] is False
                for value in signing_bundle["properties"]["authority"][
                    "properties"
                ].values()
            )
        )
        self.assertIn(
            "signaturePreimage",
            signing_bundle["$defs"]["request"]["required"],
        )
        self.assertIn("teacherLineageAdmission", signing_bundle["required"])
        bundle_contract = signing_bundle["properties"]["signatureContract"][
            "properties"
        ]["bundleAuthorization"]["properties"]
        self.assertEqual(
            "daxalgo-expert-model-review-receipt-signing-bundle-authorization/v1",
            bundle_contract["domain"]["const"],
        )
        self.assertEqual(
            768_000_000,
            review_receipts_module.MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES,
        )
        self.assertGreaterEqual(
            review_receipts_module.MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES,
            3 * review_receipts_module.MAX_REVIEW_RECEIPT_SET_BYTES,
        )
        self.assertEqual(
            REVIEW_RECEIPT_SIGNATURE_SET_SCHEMA_VERSION,
            signature_set["properties"]["schemaVersion"]["const"],
        )
        self.assertIn("bundleAuthorization", signature_set["required"])
        authorization_schema = signature_set["$defs"]["bundleAuthorization"]
        self.assertTrue(
            authorization_schema["properties"]["receiptFinalizationAuthorized"]["const"]
        )
        self.assertFalse(
            authorization_schema["properties"]["reviewTruthAuthorized"]["const"]
        )
        for document in (signing_bundle, signature_set):
            self.assertEqual(
                "https://json-schema.org/draft/2020-12/schema",
                document["$schema"],
            )
            pending = [document]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    if value.get("type") == "object":
                        self.assertIs(
                            False,
                            value.get("additionalProperties"),
                            msg=value,
                        )
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)

    def test_signer_rejects_invalid_rights_code_review_and_clobber(self) -> None:
        invalid_rights = _record("invalid-rights")
        invalid_rights["sources"][0]["rights"]["mayEvaluate"] = False
        with self.assertRaisesRegex(ValidationError, "storage and evaluation"):
            self._issue([invalid_rights], "invalid-rights.jsonl")

        with self.assertRaisesRegex(ValidationError, "CodeReview"):
            self._issue([_code_record("code-review", "CodeReview")], "review.jsonl")

        output = self.root / "existing.jsonl"
        output.write_bytes(b"preserve-me")
        dataset = self.root / "existing.corpus.jsonl"
        _write_jsonl(dataset, [_record("existing")])
        with self.assertRaisesRegex(ValidationError, "already exists"):
            create_expert_model_review_receipts(
                dataset_path=dataset,
                output_path=output,
                private_key_path=self.private_key,
                public_key_path=self.public_key,
                private_key_password=None,
                audience=AUDIENCE,
                key_id=KEY_ID,
                signer_role=SIGNER_ROLE,
                approval_id="approval-2025-01",
                actor_id="review-board-1",
                actor_role=SIGNER_ROLE,
                approval_reference="review://approval/2025-01",
                approval_evidence_path=self.evidence,
                approved_at_utc=APPROVED,
                issued_at_utc=ISSUED,
                not_before_utc=NOT_BEFORE,
                expires_at_utc=EXPIRES,
                now=VALIDATION_TIME,
            )
        self.assertEqual(b"preserve-me", output.read_bytes())

        with self.assertRaisesRegex(ValidationError, "printable ASCII"):
            self._issue(
                [_record("unicode-reference")],
                "unicode-reference.jsonl",
                approval_reference="review://approval/with-☃",
            )

    def test_no_clobber_race_does_not_unlink_competing_file(self) -> None:
        output = self.root / "race.jsonl"
        original_open = Path.open

        def racing_open(path: Path, mode: str = "r", *args, **kwargs):
            if path == output and mode == "xb":
                with original_open(path, "wb") as stream:
                    stream.write(b"competing-writer")
                raise FileExistsError("simulated exclusive-create race")
            return original_open(path, mode, *args, **kwargs)

        with (
            mock.patch.object(Path, "open", racing_open),
            self.assertRaises(FileExistsError),
        ):
            self._issue([_record("race-row")], output.name)
        self.assertEqual(b"competing-writer", output.read_bytes())

    def test_failed_self_validation_does_not_unlink_replacement_file(self) -> None:
        output = self.root / "replacement-race.jsonl"

        def replace_then_fail(*args, **kwargs):
            output.unlink()
            output.write_bytes(b"attacker-replacement")
            raise ValidationError("simulated post-write validation failure")

        with (
            mock.patch(
                "hyperion_model.review_receipts.validate_expert_model_review_receipts",
                side_effect=replace_then_fail,
            ),
            self.assertRaisesRegex(ValidationError, "simulated post-write"),
        ):
            self._issue([_record("replacement-race")], output.name)
        self.assertEqual(b"attacker-replacement", output.read_bytes())

    def test_public_key_requires_exactly_one_spki_pem_block(self) -> None:
        valid = self.public_key.read_bytes()
        malformed_values = (
            valid + b"trailing-junk",
            valid + self.private_key.read_bytes(),
            valid + valid,
        )
        for index, raw in enumerate(malformed_values):
            with self.subTest(index=index):
                malformed = self.root / f"malformed-public-{index}.pem"
                malformed.write_bytes(raw)
                with self.assertRaisesRegex(ValidationError, "exactly one PUBLIC KEY"):
                    self._issue(
                        [_record(f"malformed-public-{index}")],
                        f"malformed-public-{index}.jsonl",
                        public_key_path=malformed,
                    )

        padded = self.root / "whitespace-padded-public.pem"
        padded.write_bytes(b" \r\n" + valid + b"\t\n")
        _, _, verified = self._issue(
            [_record("whitespace-padded-public")],
            "whitespace-padded-public.jsonl",
            public_key_path=padded,
        )
        self.assertEqual(self.spki_sha256, verified.public_key_spki_sha256)

    def test_verifier_rejects_dataset_tamper_wrong_key_and_identity(self) -> None:
        dataset, output, _ = self._issue([_record("bound-row")])
        dataset.write_bytes(dataset.read_bytes().replace(b"}\n", b"} \n"))
        with self.assertRaisesRegex(ValidationError, "sourceCorpusSha256"):
            self._validate(dataset, output)

        _write_jsonl(dataset, [_record("bound-row")])
        other_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        other_public = self.root / "other-public.pem"
        other_public.write_bytes(
            other_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        other_spki = other_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaisesRegex(ValidationError, "pinned public key"):
            self._validate(
                dataset,
                output,
                public_key_path=other_public,
                expected_public_key_spki_sha256=hashlib.sha256(other_spki).hexdigest(),
            )
        for name, value in (
            ("expected_audience", "wrong-audience"),
            ("expected_key_id", "wrong-key"),
            ("expected_signer_role", "wrong-role"),
        ):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                self._validate(dataset, output, **{name: value})

    def test_verifier_rejects_receipts_outside_the_active_window(self) -> None:
        dataset, output, _ = self._issue([_record("active-window")])
        for current in (
            datetime(2025, 1, 20, 12, 0, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 20, 12, 0, 2, tzinfo=timezone.utc),
        ):
            with (
                self.subTest(current=current),
                self.assertRaisesRegex(ValidationError, "not currently active"),
            ):
                self._validate(dataset, output, now=current)

    def test_verifier_rejects_signature_payload_and_high_s_tampering(self) -> None:
        dataset, output, _ = self._issue([_record("signed-row")])
        original = _read_envelopes(output)[0]

        tampered = dict(original)
        signature = bytearray(_decode(tampered["signature"]))
        signature[0] ^= 1
        tampered["signature"] = _encode(bytes(signature))
        _write_jsonl(output := self.root / "bad-signature.jsonl", [tampered])
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._validate(dataset, output)

        tampered = dict(original)
        payload = json.loads(_decode(tampered["payload"]))
        payload["reviewer"] = "different-reviewer"
        payload_bytes = canonical_json_bytes(payload)
        tampered["payload"] = _encode(payload_bytes)
        tampered["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        _write_jsonl(output := self.root / "bad-payload.jsonl", [tampered])
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._validate(dataset, output)

        tampered = dict(original)
        signature = _decode(tampered["signature"])
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        high_s = P256_ORDER - s
        tampered["signature"] = _encode(
            r.to_bytes(32, "big") + high_s.to_bytes(32, "big")
        )
        _write_jsonl(output := self.root / "high-s.jsonl", [tampered])
        with self.assertRaisesRegex(ValidationError, "low-S"):
            self._validate(dataset, output)

    def test_verifier_requires_canonical_complete_ordered_jsonl(self) -> None:
        records = [_record("row-one"), _record("row-two")]
        dataset, output, _ = self._issue(records)
        lines = output.read_bytes().splitlines()

        malformed = {
            "missing.jsonl": lines[:1],
            "extra.jsonl": [*lines, lines[-1]],
            "reordered.jsonl": list(reversed(lines)),
            "blank.jsonl": [lines[0], b"", lines[1]],
        }
        for name, value in malformed.items():
            with self.subTest(name=name):
                target = self.root / name
                target.write_bytes(b"\n".join(value) + b"\n")
                with self.assertRaises(ValidationError):
                    self._validate(dataset, target)

        crlf = self.root / "crlf.jsonl"
        crlf.write_bytes(b"\r\n".join(lines) + b"\r\n")
        with self.assertRaisesRegex(ValidationError, "exactly one LF"):
            self._validate(dataset, crlf)

        noncanonical = self.root / "noncanonical.jsonl"
        noncanonical.write_bytes(
            json.dumps(json.loads(lines[0]), sort_keys=True).encode()
            + b"\n"
            + lines[1]
            + b"\n"
        )
        with self.assertRaisesRegex(ValidationError, "canonical JSON"):
            self._validate(dataset, noncanonical)

    def test_version_pairing_homogeneity_and_legacy_human_only_policy(self) -> None:
        records = [_record("version-row-one"), _record("version-row-two")]
        dataset, output, created = self._issue(records, "versioned.jsonl")
        envelopes = _read_envelopes(output)
        legacy_second = _resign_as_v1(
            envelopes[1], records[1], created.dataset_sha256, self.signing_key
        )
        mixed = self.root / "mixed-versions.jsonl"
        _write_jsonl(mixed, [envelopes[0], legacy_second])
        with self.assertRaisesRegex(ValidationError, "homogeneous"):
            self._validate(dataset, mixed)

        cross_paired = dict(envelopes[0])
        cross_paired["schemaVersion"] = LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION
        cross_path = self.root / "cross-paired.jsonl"
        _write_jsonl(cross_path, [cross_paired])
        with self.assertRaisesRegex(ValidationError, "version pair"):
            self._validate(dataset, cross_path)

        legacy_first = _resign_as_v1(
            envelopes[0], records[0], created.dataset_sha256, self.signing_key
        )
        legacy_payload = json.loads(_decode(legacy_first["payload"]))
        v2_envelope_v1_payload = _resign_envelope(
            envelopes[0], legacy_payload, self.signing_key
        )
        v2_v1_path = self.root / "v2-envelope-v1-payload.jsonl"
        _write_jsonl(v2_v1_path, [v2_envelope_v1_payload])
        with self.assertRaisesRegex(ValidationError, "decoded payload schemaVersion"):
            self._validate(dataset, v2_v1_path)

        v2_payload = json.loads(_decode(envelopes[0]["payload"]))
        v1_envelope_v2_payload = _resign_envelope(
            legacy_first, v2_payload, self.signing_key
        )
        v1_v2_path = self.root / "v1-envelope-v2-payload.jsonl"
        _write_jsonl(v1_v2_path, [v1_envelope_v2_payload])
        with self.assertRaisesRegex(ValidationError, "decoded payload schemaVersion"):
            self._validate(dataset, v1_v2_path)

        unknown = dict(envelopes[0])
        unknown["schemaVersion"] = "daxalgo.expert-model-review-receipt-envelope/v999"
        unknown_path = self.root / "unknown-version.jsonl"
        _write_jsonl(unknown_path, [unknown])
        with self.assertRaisesRegex(ValidationError, "version pair"):
            self._validate(dataset, unknown_path)

        hosted = _record("legacy-hosted")
        hosted["lineage"] = {
            "origin": "HostedTeacher",
            "producer": "hosted-test-provider",
            "modelId": "hosted-test-model",
            "modelRevision": "hosted-snapshot-2025-01",
            "promptSha256": "a" * 64,
            "profileVersion": "hosted-test-profile-v1",
            "producedAtUtc": PRODUCED,
        }
        hosted_dataset, hosted_output, hosted_created = self._issue(
            [hosted], "legacy-hosted.jsonl"
        )
        hosted_envelope = _resign_as_v1(
            _read_envelopes(hosted_output)[0],
            hosted,
            hosted_created.dataset_sha256,
            self.signing_key,
        )
        legacy_hosted_path = self.root / "legacy-hosted-v1.jsonl"
        _write_jsonl(legacy_hosted_path, [hosted_envelope])
        with self.assertRaisesRegex(ValidationError, "all-HumanAuthored"):
            self._validate(hosted_dataset, legacy_hosted_path)

    def test_cli_create_and_validate(self) -> None:
        dataset = self.root / "cli.corpus.jsonl"
        output = self.root / "cli.receipts.jsonl"
        _write_jsonl(dataset, [_record("cli-row")])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        timestamps = [
            ("--approved-at-utc", now - timedelta(seconds=3)),
            ("--issued-at-utc", now - timedelta(seconds=2)),
            ("--not-before-utc", now - timedelta(seconds=1)),
            ("--expires-at-utc", now + timedelta(days=1)),
        ]
        argv = [
            "create-review-receipts",
            "--dataset",
            str(dataset),
            "--output",
            str(output),
            "--private-key",
            str(self.private_key),
            "--public-key",
            str(self.public_key),
            "--audience",
            AUDIENCE,
            "--key-id",
            KEY_ID,
            "--signer-role",
            SIGNER_ROLE,
            "--approval-id",
            "approval-cli",
            "--actor-id",
            "review-board-cli",
            "--actor-role",
            SIGNER_ROLE,
            "--approval-reference",
            "review://approval/cli",
            "--approval-evidence",
            str(self.evidence),
        ]
        for name, value in timestamps:
            argv.extend([name, value.strftime("%Y-%m-%dT%H:%M:%SZ")])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, main(argv))
        self.assertTrue(json.loads(stdout.getvalue())["created"])

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(
                0,
                main(
                    [
                        "validate-review-receipts",
                        str(output),
                        "--dataset",
                        str(dataset),
                        "--public-key",
                        str(self.public_key),
                        "--expected-public-key-spki-sha256",
                        self.spki_sha256,
                        "--expected-audience",
                        AUDIENCE,
                        "--expected-key-id",
                        KEY_ID,
                        "--expected-signer-role",
                        SIGNER_ROLE,
                    ]
                ),
            )
        self.assertTrue(json.loads(stdout.getvalue())["valid"])

    def test_cli_detached_prepare_and_finalize_have_no_private_key_arguments(
        self,
    ) -> None:
        dataset = self.root / "cli-detached.corpus.jsonl"
        bundle_path = self.root / "cli-detached.bundle.json"
        signature_set_path = self.root / "cli-detached.signatures.json"
        output = self.root / "cli-detached.receipts.jsonl"
        _write_jsonl(dataset, [_record("cli-detached-row")])
        now = datetime.now(timezone.utc).replace(microsecond=0)
        timestamps = [
            ("--approved-at-utc", now - timedelta(seconds=3)),
            ("--issued-at-utc", now - timedelta(seconds=2)),
            ("--not-before-utc", now - timedelta(seconds=1)),
            ("--expires-at-utc", now + timedelta(days=1)),
        ]
        prepare_argv = [
            "prepare-review-receipt-signing-bundle",
            "--dataset",
            str(dataset),
            "--output",
            str(bundle_path),
            "--public-key",
            str(self.public_key),
            "--audience",
            AUDIENCE,
            "--key-id",
            KEY_ID,
            "--signer-role",
            SIGNER_ROLE,
            "--approval-id",
            "approval-cli-detached",
            "--actor-id",
            "review-board-cli",
            "--actor-role",
            SIGNER_ROLE,
            "--approval-reference",
            "review://approval/cli-detached",
            "--approval-evidence",
            str(self.evidence),
        ]
        for name, value in timestamps:
            prepare_argv.extend([name, value.strftime("%Y-%m-%dT%H:%M:%SZ")])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(0, main(prepare_argv))
        self.assertTrue(json.loads(stdout.getvalue())["prepared"])

        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        digest = _decode(bundle["requests"][0]["signatureInput"])
        signature = self.signing_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        signature_set = review_receipts_module._build_signature_set_document(
            bundle,
            bundle_bytes,
            [("asn1-der", signature)],
            bundle_authorization_signature=(
                "asn1-der",
                self.signing_key.sign(
                    hashlib.sha256(
                        review_receipts_module._bundle_authorization_preimage(
                            bundle_bytes
                        )
                    ).digest(),
                    ec.ECDSA(Prehashed(hashes.SHA256())),
                ),
            ),
        )
        signature_set_path.write_bytes(canonical_json_bytes(signature_set))
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(
                0,
                main(
                    [
                        "finalize-review-receipts",
                        "--dataset",
                        str(dataset),
                        "--signing-bundle",
                        str(bundle_path),
                        "--signature-set",
                        str(signature_set_path),
                        "--output",
                        str(output),
                        "--public-key",
                        str(self.public_key),
                        "--expected-public-key-spki-sha256",
                        self.spki_sha256,
                        "--expected-audience",
                        AUDIENCE,
                        "--expected-key-id",
                        KEY_ID,
                        "--expected-signer-role",
                        SIGNER_ROLE,
                        "--approval-evidence",
                        str(self.evidence),
                    ]
                ),
            )
        self.assertTrue(json.loads(stdout.getvalue())["created"])
        self.assertEqual(1, self._validate(dataset, output, now=now).receipt_count)

        parser = cli_module._parser()
        commands = next(
            action.choices
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
            and "finalize-review-receipts" in action.choices
        )
        for command in (
            "prepare-review-receipt-signing-bundle",
            "finalize-review-receipts",
        ):
            options = {
                option
                for action in commands[command]._actions
                for option in action.option_strings
            }
            self.assertNotIn("--private-key", options)
            self.assertNotIn("--private-key-password-env", options)


class ReviewReceiptGoldenFixtureTests(unittest.TestCase):
    FIXTURE = Path(__file__).parent / "fixtures" / "review_receipts"

    def test_public_fixture_verifies_and_matches_all_golden_hashes(self) -> None:
        dataset = self.FIXTURE / "golden.corpus.jsonl"
        receipts = self.FIXTURE / "golden.receipts.jsonl"
        public_key = self.FIXTURE / "golden.public.pem"
        metadata = self.FIXTURE / "golden.sft-metadata.json"
        expected = json.loads((self.FIXTURE / "golden.expected.json").read_bytes())

        verified = validate_expert_model_review_receipts(
            receipts,
            dataset_path=dataset,
            public_key_path=public_key,
            expected_public_key_spki_sha256=expected["publicKeySpkiSha256"],
            expected_audience=expected["audience"],
            expected_key_id=expected["keyId"],
            expected_signer_role=expected["signerRole"],
            now=datetime(2025, 2, 1, tzinfo=timezone.utc),
        )
        envelope_bytes = receipts.read_bytes()[:-1]
        payload = verified.receipts[0].payload
        row = json.loads(dataset.read_bytes())
        metadata_bytes = canonical_json_bytes(json.loads(metadata.read_bytes()))

        self.assertEqual(1, verified.receipt_count)
        self.assertEqual(expected["datasetSha256"], verified.dataset_sha256)
        self.assertEqual(expected["receiptSetSha256"], verified.receipt_set_sha256)
        self.assertEqual(
            expected["envelopeSha256"], hashlib.sha256(envelope_bytes).hexdigest()
        )
        self.assertEqual(
            expected["payloadSha256"], verified.receipts[0].envelope["payloadSha256"]
        )
        self.assertEqual(expected["receiptId"], payload["receiptId"])
        self.assertEqual(expected["sftMetadataSha256"], payload["sftMetadataSha256"])
        self.assertEqual(
            canonical_json_bytes(legacy_expert_model_sft_metadata(row)), metadata_bytes
        )
        self.assertEqual(
            expected["sftMetadataSha256"], hashlib.sha256(metadata_bytes).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
