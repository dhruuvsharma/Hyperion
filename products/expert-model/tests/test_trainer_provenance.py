from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import tempfile
import unittest
from unittest import mock
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

import hyperion_model.trainer_provenance as provenance_module
from hyperion_model.core import ValidationError, canonical_json_bytes
from hyperion_model.trainer_provenance import (
    TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION,
    TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT,
    TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
    TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE,
    TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
    TRAINER_PROVENANCE_SCHEMA_VERSION,
    TrainerProvenanceTrust,
    create_trainer_provenance,
    finalize_trainer_provenance_envelope,
    prepare_trainer_provenance_signing_bundle,
    trainer_provenance_id,
    validate_trainer_provenance_preparation_authority,
    verify_trainer_provenance_envelope,
    verify_trainer_provenance_signing_bundle,
)


RECORDED = "2026-07-29T10:00:00Z"
ISSUED = "2026-07-29T10:00:01Z"
NOT_BEFORE = "2026-07-29T10:00:02Z"
EXPIRES = "2027-07-29T10:00:02Z"
NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)
AUDIENCE = "training-artifact-v2"
KEY_ID = "trainer-provenance-key-2026-07"
SIGNER_ROLE = "isolated-model-trainer"
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

ARTIFACT_CORE_SHA256 = "1" * 64
FILE_TREE_SHA256 = "2" * 64
MANIFEST_SHA256 = "3" * 64
ENVIRONMENT_SHA256 = "4" * 64
RUN_ID = f"vqrun-{'5' * 20}"
DATA_RELEASE = {
    "releaseId": f"vqrel-{'6' * 64}",
    "releaseSha256": "6" * 64,
    "manifestSha256": "7" * 64,
}
BASE_MODEL = {
    "candidateId": "qwen-coder-7b",
    "modelId": "Qwen/Qwen2.5-Coder-7B-Instruct",
    "revision": "8" * 40,
}
DATASET_SNAPSHOT = {
    "path": "inputs/dataset.sft.jsonl",
    "sha256": "9" * 64,
    "recordCount": 123,
}


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class TrainerProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key_object, self.private_key, self.public_key, spki = (
            self._write_key_pair("trainer")
        )
        self.trust = TrainerProvenanceTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256=spki,
            audience=AUDIENCE,
            key_id=KEY_ID,
            signer_role=SIGNER_ROLE,
        )
        self.artifact_core = {
            "schemaVersion": "daxalgo.hyperion.training-artifact/v2",
            "artifactSha256": "0" * 64,
            "fileTreeSha256": FILE_TREE_SHA256,
            "recordedAtUtc": RECORDED,
            "runId": RUN_ID,
            "mode": "unpromoted-candidate",
            "productionEligible": False,
            "reason": (
                "Training alone does not satisfy evaluation, promotion, signing, "
                "or deployment gates."
            ),
            "manifestSha256": MANIFEST_SHA256,
            "dataRelease": DATA_RELEASE,
            "baseModel": BASE_MODEL,
            "datasetSnapshot": DATASET_SNAPSHOT,
            "files": [
                {
                    "path": "adapter_config.json",
                    "sha256": "a" * 64,
                    "sizeBytes": 123,
                }
            ],
            "environment": {
                "python": {"version": "3.11.9"},
                "gpu": {"name": "test-gpu"},
            },
            "trainerProvenance": None,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_key_pair(self, name: str):
        key = ec.generate_private_key(ec.SECP256R1())
        private_path = self.root / f"{name}-private.pem"
        public_path = self.root / f"{name}-public.pem"
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
        return key, private_path, public_path, hashlib.sha256(spki).hexdigest()

    def _create_arguments(self, **overrides):
        values = {
            "private_key_path": self.private_key,
            "private_key_password": None,
            "trust": self.trust,
            "artifact_core_sha256": ARTIFACT_CORE_SHA256,
            "file_tree_sha256": FILE_TREE_SHA256,
            "manifest_sha256": MANIFEST_SHA256,
            "run_id": RUN_ID,
            "recorded_at_utc": RECORDED,
            "data_release": DATA_RELEASE,
            "base_model": BASE_MODEL,
            "dataset_snapshot": DATASET_SNAPSHOT,
            "environment_sha256": ENVIRONMENT_SHA256,
            "issued_at_utc": ISSUED,
            "not_before_utc": NOT_BEFORE,
            "expires_at_utc": EXPIRES,
            "trainer_id": "trainer-worker-01",
            "now": NOW,
        }
        values.update(overrides)
        return values

    def _create(self, **overrides):
        return create_trainer_provenance(**self._create_arguments(**overrides))

    def _verify(self, envelope, **overrides):
        values = {
            "trust": self.trust,
            "expected_artifact_core_sha256": ARTIFACT_CORE_SHA256,
            "expected_file_tree_sha256": FILE_TREE_SHA256,
            "expected_manifest_sha256": MANIFEST_SHA256,
            "expected_run_id": RUN_ID,
            "expected_recorded_at_utc": RECORDED,
            "expected_data_release": DATA_RELEASE,
            "expected_base_model": BASE_MODEL,
            "expected_dataset_snapshot": DATASET_SNAPSHOT,
            "expected_environment_sha256": ENVIRONMENT_SHA256,
            "now": NOW,
        }
        values.update(overrides)
        return verify_trainer_provenance_envelope(envelope, **values)

    def _resign(self, envelope, payload):
        payload["trainerProvenanceId"] = trainer_provenance_id(payload)
        payload_bytes = canonical_json_bytes(payload)
        resigned = dict(envelope)
        resigned["payload"] = _encode(payload_bytes)
        resigned["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        resigned["signature"] = _encode(
            provenance_module._sign_p1363_low_s(
                self.private_key_object,
                provenance_module._signature_input(resigned, payload_bytes),
            )
        )
        return resigned

    def _prepare_detached(self, artifact_core=None):
        return prepare_trainer_provenance_signing_bundle(
            artifact_core=artifact_core or self.artifact_core,
            trust=self.trust,
            issued_at_utc=ISSUED,
            not_before_utc=NOT_BEFORE,
            expires_at_utc=EXPIRES,
            trainer_id="trainer-worker-01",
            now=NOW,
        )

    def _external_signature(
        self,
        bundle,
        *,
        mode=TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
        signature_format=TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT,
        signing_key=None,
        signing_behavior=None,
        force_high_s=False,
    ):
        key = signing_key or self.private_key_object
        request = bundle["request"]
        preimage = _decode(request["signaturePreimage"])
        digest = _decode(request["signatureInput"])
        behavior = signing_behavior or mode
        if behavior == TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE:
            der = key.sign(preimage, ec.ECDSA(hashes.SHA256()))
        elif behavior == TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE:
            der = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif behavior == "double-hashed-digest":
            der = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported signing behavior")
        r, s = decode_dss_signature(der)
        if force_high_s and s <= P256_ORDER // 2:
            s = P256_ORDER - s
        if signature_format == TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT:
            external = encode_dss_signature(r, s)
        elif signature_format == TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT:
            external = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported signature format")
        return provenance_module._build_external_signature_document(
            bundle,
            signature_mode=mode,
            signature_format=signature_format,
            signature=external,
        )

    def _finalize_detached(self, prepared, signature, artifact_core=None):
        return finalize_trainer_provenance_envelope(
            prepared.bundle,
            signature,
            trust=self.trust,
            expected_artifact_core=artifact_core or self.artifact_core,
            now=NOW,
        )

    def _direct_from_artifact_core(self):
        core, _, core_sha256 = provenance_module._artifact_core_document(
            self.artifact_core
        )
        bindings = provenance_module._artifact_core_bindings(core)
        return self._create(
            artifact_core_sha256=core_sha256,
            file_tree_sha256=bindings["file_tree_sha256"],
            manifest_sha256=bindings["manifest_sha256"],
            run_id=bindings["run_id"],
            recorded_at_utc=bindings["recorded_at_utc"],
            data_release=bindings["data_release"],
            base_model=bindings["base_model"],
            dataset_snapshot=bindings["dataset_snapshot"],
            environment_sha256=bindings["environment_sha256"],
        )

    def test_create_and_verify_closed_candidate_provenance(self) -> None:
        created = self._create()
        verified = self._verify(
            created.envelope,
            expected_envelope_sha256=created.envelope_sha256,
        )

        self.assertEqual(created.payload, verified.payload)
        self.assertEqual(
            TRAINER_PROVENANCE_SCHEMA_VERSION, verified.payload["schemaVersion"]
        )
        self.assertEqual(
            TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION,
            verified.envelope["schemaVersion"],
        )
        self.assertEqual(
            trainer_provenance_id(verified.payload),
            verified.payload["trainerProvenanceId"],
        )
        self.assertIs(verified.payload["trainingProduced"], True)
        for name in (
            "reusable",
            "corpusReviewAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "baseSelectionAuthorized",
            "evaluationAuthorized",
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
            (schema_root / "trainer-provenance.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        envelope_schema = json.loads(
            (schema_root / "trainer-provenance-envelope.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(payload_schema["additionalProperties"])
        self.assertFalse(envelope_schema["additionalProperties"])
        self.assertEqual(
            set(payload_schema["required"]), set(payload_schema["properties"])
        )
        self.assertEqual(
            set(envelope_schema["required"]), set(envelope_schema["properties"])
        )

    def test_self_consistent_tamper_and_exact_envelope_pin_are_rejected(self) -> None:
        created = self._create()
        with self.assertRaisesRegex(ValidationError, "trusted exact SHA-256"):
            self._verify(
                created.envelope,
                expected_envelope_sha256="0" * 64,
            )

        envelope = dict(created.envelope)
        payload = json.loads(_decode(envelope["payload"]))
        payload["trainerId"] = "tampered-trainer"
        payload["trainerProvenanceId"] = trainer_provenance_id(payload)
        payload_bytes = canonical_json_bytes(payload)
        envelope["payload"] = _encode(payload_bytes)
        envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._verify(envelope)

    def test_wrong_trust_public_key_and_private_key_pair_are_rejected(self) -> None:
        created = self._create()
        with self.assertRaisesRegex(ValidationError, "trusted configuration"):
            self._verify(
                created.envelope,
                trust=replace(self.trust, audience="wrong-audience"),
            )

        _, wrong_private, wrong_public, wrong_spki = self._write_key_pair("wrong")
        wrong_trust = replace(
            self.trust,
            public_key_path=wrong_public,
            public_key_spki_sha256=wrong_spki,
        )
        with self.assertRaisesRegex(ValidationError, "trusted configuration"):
            self._verify(created.envelope, trust=wrong_trust)
        with self.assertRaisesRegex(ValidationError, "key pair"):
            self._create(private_key_path=wrong_private)

    def test_high_s_signature_is_rejected(self) -> None:
        created = self._create()
        envelope = dict(created.envelope)
        signature = _decode(envelope["signature"])
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        envelope["signature"] = _encode(
            r.to_bytes(32, "big") + (P256_ORDER - s).to_bytes(32, "big")
        )
        with self.assertRaisesRegex(ValidationError, "low-S"):
            self._verify(envelope)

    def test_causal_active_and_maximum_validity_windows_are_enforced(self) -> None:
        creation_cases = (
            ({"recorded_at_utc": "2026-07-29T10:00:02Z"}, "recordedAt"),
            ({"issued_at_utc": "2026-07-29T10:00:03Z"}, "issuedAt"),
            ({"expires_at_utc": "2027-08-01T10:00:02Z"}, "366 days"),
            (
                {"now": datetime(2026, 7, 29, 10, 0, 1, tzinfo=timezone.utc)},
                "active",
            ),
            (
                {"now": datetime(2027, 7, 29, 10, 0, 2, tzinfo=timezone.utc)},
                "active",
            ),
        )
        for overrides, message in creation_cases:
            with self.subTest(overrides=overrides):
                with self.assertRaisesRegex(ValidationError, message):
                    self._create(**overrides)

        created = self._create()
        with self.assertRaisesRegex(ValidationError, "not active"):
            self._verify(
                created.envelope,
                now=datetime(2027, 7, 29, 10, 0, 2, tzinfo=timezone.utc),
            )

    def test_exact_artifact_binding_mismatch_is_rejected(self) -> None:
        created = self._create()
        with self.assertRaisesRegex(ValidationError, "exact expected artifact binding"):
            self._verify(
                created.envelope,
                expected_artifact_core_sha256="a" * 64,
            )

        changed_release = {
            "releaseId": f"vqrel-{'b' * 64}",
            "releaseSha256": "b" * 64,
            "manifestSha256": "c" * 64,
        }
        with self.assertRaisesRegex(ValidationError, "exact expected artifact binding"):
            self._verify(
                created.envelope,
                expected_data_release=changed_release,
            )

    def test_correctly_resigned_authority_escalation_and_extra_keys_are_rejected(
        self,
    ) -> None:
        created = self._create()
        original_payload = json.loads(_decode(created.envelope["payload"]))

        escalated = dict(original_payload)
        escalated["releaseAuthorized"] = True
        envelope = self._resign(created.envelope, escalated)
        with self.assertRaisesRegex(ValidationError, "does not match the contract"):
            self._verify(envelope)

        extended = dict(original_payload)
        extended["unboundedAuthority"] = False
        envelope = self._resign(created.envelope, extended)
        with self.assertRaisesRegex(ValidationError, "unsupported keys"):
            self._verify(envelope)

    def test_correctly_resigned_numeric_booleans_are_rejected(self) -> None:
        created = self._create()
        original_payload = json.loads(_decode(created.envelope["payload"]))
        for name, numeric in (
            ("reusable", 0),
            ("trainingProduced", 1),
            ("trainingAuthorized", 0),
        ):
            with self.subTest(name=name):
                payload = dict(original_payload)
                payload[name] = numeric
                envelope = self._resign(created.envelope, payload)
                with self.assertRaisesRegex(
                    ValidationError, "does not match the contract"
                ):
                    self._verify(envelope)

    def test_correctly_signed_noncanonical_payload_is_rejected(self) -> None:
        created = self._create()
        payload = json.loads(_decode(created.envelope["payload"]))
        payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
        envelope = dict(created.envelope)
        envelope["payload"] = _encode(payload_bytes)
        envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        envelope["signature"] = _encode(
            provenance_module._sign_p1363_low_s(
                self.private_key_object,
                provenance_module._signature_input(envelope, payload_bytes),
            )
        )
        with self.assertRaisesRegex(ValidationError, "exact canonical JSON"):
            self._verify(envelope)

    def test_detached_signing_preserves_wire_and_normalizes_supported_modes(
        self,
    ) -> None:
        direct = self._direct_from_artifact_core()
        prepared = self._prepare_detached()
        verified_bundle = verify_trainer_provenance_signing_bundle(
            prepared.bundle,
            trust=self.trust,
            expected_artifact_core=self.artifact_core,
            now=NOW,
        )
        self.assertEqual(prepared.bundle_id, verified_bundle.bundle_id)

        raw_high_s = self._external_signature(
            prepared.bundle,
            mode=TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE,
            force_high_s=True,
        )
        detached = self._finalize_detached(prepared, raw_high_s)
        self.assertEqual(direct.payload_bytes, detached.payload_bytes)
        self.assertEqual(
            {
                key: value
                for key, value in direct.envelope.items()
                if key != "signature"
            },
            {
                key: value
                for key, value in detached.envelope.items()
                if key != "signature"
            },
        )
        normalized = _decode(detached.envelope["signature"])
        self.assertLessEqual(int.from_bytes(normalized[32:], "big"), P256_ORDER // 2)

        reused_direct_signature = provenance_module._build_external_signature_document(
            prepared.bundle,
            signature_mode=TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE,
            signature_format=TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
            signature=_decode(direct.envelope["signature"]),
        )
        exact_detached = self._finalize_detached(prepared, reused_direct_signature)
        self.assertEqual(direct.envelope, exact_detached.envelope)
        self.assertEqual(direct.envelope_sha256, exact_detached.envelope_sha256)

        digest_p1363 = self._external_signature(
            prepared.bundle,
            mode=TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
            signature_format=TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
        )
        digest_detached = self._finalize_detached(prepared, digest_p1363)
        self.assertEqual(detached.payload_sha256, digest_detached.payload_sha256)

        high_s_p1363 = self._external_signature(
            prepared.bundle,
            mode=TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
            signature_format=TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
            force_high_s=True,
        )
        normalized_p1363 = self._finalize_detached(prepared, high_s_p1363)
        self.assertLessEqual(
            int.from_bytes(_decode(normalized_p1363.envelope["signature"])[32:], "big"),
            P256_ORDER // 2,
        )

        double_hashed = self._external_signature(
            prepared.bundle,
            mode=TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
            signing_behavior="double-hashed-digest",
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(prepared, double_hashed)

    def test_detached_contract_is_closed_content_addressed_and_key_free(self) -> None:
        prepared = self._prepare_detached()
        signature = self._external_signature(prepared.bundle)
        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        bundle_schema = json.loads(
            (
                schema_root / "trainer-provenance-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_schema = json.loads(
            (schema_root / "trainer-provenance-signature.v1.schema.json").read_bytes()
        )
        for schema in (bundle_schema, signature_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
        jsonschema.Draft202012Validator(bundle_schema).validate(prepared.bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(signature)

        self.assertTrue(
            all(value is False for value in prepared.bundle["authority"].values())
        )
        self.assertEqual(
            prepared.artifact_core_bytes,
            _decode(prepared.bundle["artifactCore"]),
        )
        self.assertEqual(
            hashlib.sha256(prepared.artifact_core_bytes).hexdigest(),
            prepared.bundle["artifactCoreSha256"],
        )
        self.assertEqual(
            provenance_module.trainer_provenance_signing_bundle_id(prepared.bundle),
            prepared.bundle_id,
        )
        self.assertEqual(
            provenance_module.trainer_provenance_external_signature_id(signature),
            signature["signatureId"],
        )

        for api in (
            prepare_trainer_provenance_signing_bundle,
            verify_trainer_provenance_signing_bundle,
            finalize_trainer_provenance_envelope,
            validate_trainer_provenance_preparation_authority,
        ):
            parameters = inspect.signature(api).parameters
            self.assertNotIn("private_key_path", parameters)
            self.assertNotIn("private_key_password", parameters)
        validate_trainer_provenance_preparation_authority(
            trust=self.trust,
            trainer_id="trainer-worker-01",
            expires_at_utc=EXPIRES,
            now=NOW,
        )
        with mock.patch.object(
            provenance_module,
            "_load_private_key",
            side_effect=AssertionError("detached APIs must never load a private key"),
        ):
            key_free_prepared = self._prepare_detached()
            key_free_signature = self._external_signature(key_free_prepared.bundle)
            self._finalize_detached(key_free_prepared, key_free_signature)

    def test_detached_bundle_mutations_and_live_core_drift_are_rejected(self) -> None:
        prepared = self._prepare_detached()
        signature = self._external_signature(prepared.bundle)
        mutations = (
            lambda value: value["authority"].update(training=True),
            lambda value: value["trust"].update(keyId="wrong-key"),
            lambda value: value.update(artifactCoreSha256="0" * 64),
            lambda value: value.update(artifactCore=_encode(b"{}")),
            lambda value: value["validity"].update(expiresAtUtc="2027-07-28T10:00:02Z"),
            lambda value: value["signatureContract"].update(
                acceptedModes=["sha256-digest", "raw-message"]
            ),
            lambda value: value["request"].update(
                signaturePreimage=_encode(b"wrong-preimage")
            ),
            lambda value: value["request"].update(signatureInput=_encode(b"0" * 32)),
            lambda value: value["request"].update(payload=_encode(b"{}")),
        )
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(prepared.bundle)
            mutate(changed)
            changed["bundleId"] = (
                provenance_module.trainer_provenance_signing_bundle_id(changed)
            )
            with (
                self.subTest(bundle_mutation=index),
                self.assertRaises(ValidationError),
            ):
                finalize_trainer_provenance_envelope(
                    changed,
                    signature,
                    trust=self.trust,
                    expected_artifact_core=self.artifact_core,
                    now=NOW,
                )

        changed_core = copy.deepcopy(self.artifact_core)
        changed_core["environment"]["gpu"]["name"] = "different-gpu"
        with self.assertRaisesRegex(ValidationError, "expected live artifact core"):
            verify_trainer_provenance_signing_bundle(
                prepared.bundle,
                trust=self.trust,
                expected_artifact_core=changed_core,
                now=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "expected live artifact core"):
            self._finalize_detached(prepared, signature, artifact_core=changed_core)

    def test_detached_signature_bindings_wrong_key_and_encodings_are_rejected(
        self,
    ) -> None:
        prepared = self._prepare_detached()
        signature = self._external_signature(prepared.bundle)

        changed = copy.deepcopy(signature)
        changed["payloadSha256"] = "0" * 64
        changed["signatureId"] = (
            provenance_module.trainer_provenance_external_signature_id(changed)
        )
        with self.assertRaisesRegex(ValidationError, "exact signing bundle"):
            self._finalize_detached(prepared, changed)

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_signature = self._external_signature(
            prepared.bundle, signing_key=wrong_key
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(prepared, wrong_signature)

        zero_p1363 = provenance_module._build_external_signature_document(
            prepared.bundle,
            signature_mode=TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
            signature_format=TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
            signature=b"\x00" * 64,
        )
        with self.assertRaisesRegex(ValidationError, "out-of-range"):
            self._finalize_detached(prepared, zero_p1363)

        short_p1363 = provenance_module._build_external_signature_document(
            prepared.bundle,
            signature_mode=TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
            signature_format=TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
            signature=b"\x01" * 63,
        )
        with self.assertRaisesRegex(ValidationError, "exactly 64-byte"):
            self._finalize_detached(prepared, short_p1363)

        malformed_der = provenance_module._build_external_signature_document(
            prepared.bundle,
            signature_mode=TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE,
            signature_format=TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT,
            signature=b"\x30\x00",
        )
        with self.assertRaisesRegex(ValidationError, "canonical ECDSA DER"):
            self._finalize_detached(prepared, malformed_der)

        invalid_mode = copy.deepcopy(signature)
        invalid_mode["mode"] = "double-hashed-digest"
        invalid_mode["signatureId"] = (
            provenance_module.trainer_provenance_external_signature_id(invalid_mode)
        )
        with self.assertRaisesRegex(ValidationError, "raw-message.*sha256-digest"):
            self._finalize_detached(prepared, invalid_mode)

        invalid_format = copy.deepcopy(signature)
        invalid_format["format"] = "raw"
        invalid_format["signatureId"] = (
            provenance_module.trainer_provenance_external_signature_id(invalid_format)
        )
        with self.assertRaisesRegex(ValidationError, "asn1-der.*ieee-p1363"):
            self._finalize_detached(prepared, invalid_format)

        wrong_id = copy.deepcopy(signature)
        wrong_id["signatureId"] = (
            provenance_module.TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_ID_PREFIX + "0" * 64
        )
        with self.assertRaisesRegex(ValidationError, "content-derived identity"):
            self._finalize_detached(prepared, wrong_id)

    def test_detached_preparation_preflight_reuses_direct_non_key_checks(self) -> None:
        validate_trainer_provenance_preparation_authority(
            trust=self.trust,
            trainer_id="trainer-worker-01",
            issued_at_utc=ISSUED,
            not_before_utc=NOT_BEFORE,
            expires_at_utc=EXPIRES,
            now=NOW,
        )
        cases = (
            ({"trainer_id": "unsafe trainer"}, "safe ASCII identifier"),
            ({"issued_at_utc": ISSUED, "not_before_utc": None}, "supplied together"),
            (
                {
                    "issued_at_utc": "2026-07-29T10:00:03Z",
                    "not_before_utc": NOT_BEFORE,
                },
                "issuedAt <= notBefore",
            ),
            ({"expires_at_utc": "2027-08-03T10:00:02Z"}, "366 days"),
        )
        for overrides, message in cases:
            values = {
                "trust": self.trust,
                "trainer_id": "trainer-worker-01",
                "issued_at_utc": ISSUED,
                "not_before_utc": NOT_BEFORE,
                "expires_at_utc": EXPIRES,
                "now": NOW,
            }
            values.update(overrides)
            with (
                self.subTest(overrides=overrides),
                self.assertRaisesRegex(ValidationError, message),
            ):
                validate_trainer_provenance_preparation_authority(**values)


if __name__ == "__main__":
    unittest.main()
