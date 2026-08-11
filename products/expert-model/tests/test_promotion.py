from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jsonschema
import hyperion_model.promotion as promotion_module
import hyperion_model.core as core_module
from hyperion_model.base_engine_wrapper import (
    BASE_ATTESTED_COMPLETIONS_PATH,
    BaseEngineActivationTrust,
    BaseModelEngineWrapper,
    create_base_engine_activation,
    load_base_engine_wrapper_config,
)
from hyperion_model.core import (
    ValidationError,
    canonical_json_bytes,
    validate_manifest_snapshot,
)
from hyperion_model.deployment import (
    compute_model_readiness_v2_proof,
    validate_model_readiness_v2_attestation,
)
from hyperion_model.evaluation import (
    EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
    BaseResponseAttestationTrust,
    aggregate_promotion_evidence,
    capture_openai_responses,
    evaluation_response_sha256,
    promotion_evidence_sha256,
    promotion_policy_sha256,
    validate_evaluation_responses,
    validate_promotion_evidence,
    write_json_atomic_no_clobber,
)
from hyperion_model.promotion import (
    HOSTED_DEPLOYMENT_POLICY_SCHEMA_VERSION,
    HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION,
    create_model_promotion,
    create_promoted_model_readiness_attestation,
    expert_context_query_policy_sha256,
    finalize_model_promotion,
    hosted_deployment_policy_sha256,
    model_promotion_id,
    prepare_model_promotion_signing_bundle,
    validate_hosted_deployment_policy,
    validate_model_promotion,
    verify_model_promotion_signing_bundle,
    verify_model_promotion_envelope,
)
from hyperion_model.verifier_runtime import run_release_verifiers
from hyperion_model.verifier_replay_audit import CSharpVerifierReplayAuditTrust


_NOW = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)
_PROMOTION_RECEIPT_ISSUED = "2026-01-01T00:00:00Z"
_PROMOTION_RECEIPT_NOT_BEFORE = "2026-01-01T00:00:01Z"
_PROMOTION_RECEIPT_EXPIRES = "2026-12-31T00:00:00Z"
_PROMOTION_RECEIPT_VALIDATION_TIME = datetime(2026, 2, 1, tzinfo=timezone.utc)
_PROMOTION_RELEASE_APPROVED = "2026-01-01T00:00:00Z"
_PROMOTION_AUTHORING_APPROVED = "2025-12-31T23:58:00Z"
_PROMOTION_AUTHORING_ISSUED = "2025-12-31T23:58:30Z"
_PROMOTION_AUTHORING_NOT_BEFORE = "2025-12-31T23:59:00Z"
_PROMOTION_AUTHORING_EXPIRES = "2026-12-31T23:58:30Z"
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _causally_ordered_bundle_creator(create_bundle):
    def create(**kwargs):
        created = create_bundle(**kwargs)
        manifest_path = Path(kwargs["output_directory"]) / "training-run-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["createdAtUtc"] = "2025-12-31T23:00:00Z"
        manifest["runId"] = core_module._manifest_run_id(manifest)
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return created

    return create


def _hosted_policy(
    *,
    schema_version: str = HOSTED_DEPLOYMENT_POLICY_SCHEMA_VERSION,
    execution_model_id: str = "daxalgo-expert-sha256-" + "2" * 64,
) -> dict:
    query_policy = {
        "schemaVersion": "daxalgo-expert-context-query-policy/v1",
        "topK": 1,
        "maxCharacters": 10000,
        "maxPerSource": 1,
    }
    policy = {
        "schemaVersion": schema_version,
        "policySha256": "0" * 64,
        "providerId": "daxalgo-private",
        "protocol": "openai-compatible",
        "pricing": {
            "inputUsdPerMillionTokens": "0.25",
            "outputUsdPerMillionTokens": "0.75",
            "creditsPerUsd": 100,
            "minimumChargeCredits": 1,
            "creditPricingVersion": "development-v1",
        },
        "execution": {
            "maxRequests": 8,
            "maxAttemptsPerRole": 2,
            "maxPromptTokens": 100000,
            "maxOutputTokens": 25000,
            "maxOutputTokensPerRequest": 4096,
            "maxCostUsd": "5",
            "maxResponseBytes": 1000000,
            "maxArtifactBytes": 2000000,
            "maxElapsedSeconds": 900,
            "requestTimeoutSeconds": 120,
            "requireReportedUsage": True,
            "maxActiveRunsPerAccount": 5,
            "workerPollMilliseconds": 250,
            "modelAttestationTimeoutSeconds": 10,
            "modelAttestationRefreshSeconds": 30,
            "modelAttestationTtlSeconds": 90,
        },
        "coordinator": {
            "policyVersion": "research-only/v1",
            "workflowVersion": "fixed-research/v1",
            "promptCatalogSha256": "1" * 64,
        },
        "expertContext": {
            "mode": "Pinned",
            "corpusId": "daxalgo-private",
            "corpusVersion": "2026.07.27-test",
            "packSha256": "3c273cdd7ee54f9bfd5933451c2c1530d893400e3e6595b003fda08a499b0e65",
            "queryPolicy": query_policy,
            "queryPolicySha256": expert_context_query_policy_sha256(query_policy),
            "queryMaxCharacters": 30000,
        },
    }
    if schema_version == HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION:
        policy["strategyAuthoringCapability"] = {
            "purpose": "StrategyAuthoring",
            "executionModelId": execution_model_id,
            "policyVersion": "strategy-authoring-inert/v1",
            "workflowVersion": "fixed-strategy-authoring/v1",
            "promptCatalogSha256": (
                "bb79da228ed798981334970908f4cdb8739edb1e728f67b21156adbe101cdb0b"
            ),
        }
    policy["policySha256"] = hosted_deployment_policy_sha256(policy)
    return policy


class HostedDeploymentPolicyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _validate(self, policy: dict, name: str = "hosted-policy.json") -> dict:
        policy["policySha256"] = hosted_deployment_policy_sha256(policy)
        path = self.root / name
        path.write_bytes(canonical_json_bytes(policy) + b"\n")
        return validate_hosted_deployment_policy(path)

    def _validate_without_rehash(
        self, policy: dict, name: str = "hosted-policy-invalid.json"
    ) -> dict:
        path = self.root / name
        path.write_bytes(canonical_json_bytes(policy) + b"\n")
        return validate_hosted_deployment_policy(path)

    def test_v2_requires_one_model_bound_inert_strategy_capability(self) -> None:
        policy = _hosted_policy(
            schema_version=HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION
        )

        self.assertEqual(policy, self._validate(policy, "hosted-policy-v2.json"))
        self.assertEqual(
            "StrategyAuthoring", policy["strategyAuthoringCapability"]["purpose"]
        )

        v1_with_capability = _hosted_policy()
        v1_with_capability["strategyAuthoringCapability"] = copy.deepcopy(
            policy["strategyAuthoringCapability"]
        )
        with self.assertRaisesRegex(ValidationError, "unsupported keys"):
            self._validate(v1_with_capability, "v1-with-capability.json")

        missing = copy.deepcopy(policy)
        del missing["strategyAuthoringCapability"]
        with self.assertRaisesRegex(ValidationError, "missing keys"):
            self._validate_without_rehash(missing, "v2-missing-capability.json")

        null_capability = copy.deepcopy(policy)
        null_capability["strategyAuthoringCapability"] = None
        with self.assertRaisesRegex(ValidationError, "must be an object"):
            self._validate_without_rehash(null_capability, "v2-null-capability.json")

    def test_v2_rejects_every_strategy_capability_identity_mutation(self) -> None:
        mutations = {
            "purpose": "Research",
            "executionModelId": "mutable-model-alias",
            "policyVersion": "research-only/v1",
            "workflowVersion": "fixed-research/v1",
            "promptCatalogSha256": "A" * 64,
        }
        for index, (field, value) in enumerate(mutations.items()):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                policy = _hosted_policy(
                    schema_version=HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION
                )
                policy["strategyAuthoringCapability"][field] = value
                self._validate(policy, f"v2-mutated-capability-{index}.json")

    def test_provider_and_corpus_vocabularies_match_platform_runtime_contracts(
        self,
    ) -> None:
        policy = _hosted_policy()
        policy["providerId"] = "p" + ":" * 99
        policy["expertContext"]["corpusId"] = "." + "c" * 99
        policy["expertContext"]["corpusVersion"] = "_" + "v" * 99

        self.assertEqual(policy, self._validate(policy))

        invalid_values = (
            ("providerId", "p" * 101, "100 characters"),
            ("corpusId", "corpus:private", "corpus identifier"),
            ("corpusId", "c" * 101, "100 characters"),
        )
        for field, value, message in invalid_values:
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(ValidationError, message),
            ):
                invalid = _hosted_policy()
                if field == "providerId":
                    invalid[field] = value
                else:
                    invalid["expertContext"][field] = value
                self._validate(invalid, f"invalid-{field}.json")

    def test_mutable_corpus_version_aliases_are_rejected_case_insensitively(
        self,
    ) -> None:
        for index, alias in enumerate(("latest", "Main", "MASTER", "TrUnK")):
            with (
                self.subTest(alias=alias),
                self.assertRaisesRegex(ValidationError, "immutable corpus version"),
            ):
                policy = _hosted_policy()
                policy["expertContext"]["corpusVersion"] = alias
                self._validate(policy, f"mutable-version-{index}.json")

    def test_hosted_policy_schema_uses_field_specific_identifier_contracts(
        self,
    ) -> None:
        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "hosted-deployment-policy.v1.schema.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(
            {"$ref": "#/$defs/providerId"}, schema["properties"]["providerId"]
        )
        expert = schema["properties"]["expertContext"]["properties"]
        self.assertEqual({"$ref": "#/$defs/corpusId"}, expert["corpusId"])
        self.assertEqual({"$ref": "#/$defs/corpusVersion"}, expert["corpusVersion"])
        self.assertEqual(100, schema["$defs"]["providerId"]["maxLength"])
        self.assertEqual("^[A-Za-z0-9._-]+$", schema["$defs"]["corpusId"]["pattern"])
        self.assertIn("not", schema["$defs"]["corpusVersion"])


class ModelPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError as error:  # pragma: no cover - optional dependency CI
            self.skipTest(f"optional promote dependency unavailable: {error}")

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

        try:
            evaluation_tests = importlib.import_module("test_evaluation")
        except ModuleNotFoundError:
            evaluation_tests = importlib.import_module("tests.test_evaluation")
        try:
            release_tests = importlib.import_module("test_release")
        except ModuleNotFoundError:
            release_tests = importlib.import_module("tests.test_release")
        self.evaluation = evaluation_tests.EvaluationTests()
        self.evaluation.setUp()
        self.addCleanup(self.evaluation.doCleanups)
        with (
            mock.patch.object(
                evaluation_tests,
                "create_bundle",
                side_effect=_causally_ordered_bundle_creator(
                    evaluation_tests.create_bundle
                ),
            ),
            mock.patch.multiple(
                release_tests,
                APPROVED=_PROMOTION_RELEASE_APPROVED,
                RECEIPT_ISSUED=_PROMOTION_RECEIPT_ISSUED,
                RECEIPT_NOT_BEFORE=_PROMOTION_RECEIPT_NOT_BEFORE,
                RECEIPT_EXPIRES=_PROMOTION_RECEIPT_EXPIRES,
                AUTHORING_APPROVED=_PROMOTION_AUTHORING_APPROVED,
                AUTHORING_ISSUED=_PROMOTION_AUTHORING_ISSUED,
                AUTHORING_NOT_BEFORE=_PROMOTION_AUTHORING_NOT_BEFORE,
                AUTHORING_EXPIRES=_PROMOTION_AUTHORING_EXPIRES,
                VALIDATION_TIME=_PROMOTION_RECEIPT_VALIDATION_TIME,
            ),
        ):
            paired = self.evaluation._bound_paired_fixture(provider=True)
            bound = paired["bound"]
            self.addCleanup(bound["fixture"].doCleanups)
            serving = self.evaluation._serving_fixture(
                0,
                "bound-candidate-v1",
                data_release_path=bound["release_path"],
                sft_path=bound["sft_path"],
                review_receipt_trust=bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=bound["review_receipt_now"],
            )

        report = aggregate_promotion_evidence(**paired["inputs"])
        self.report_path = self.root / "promotion-evidence.json"
        write_json_atomic_no_clobber(self.report_path, report)
        self.report = report

        self.approval_path = self.root / "approval-evidence.txt"
        self.approval_path.write_bytes(
            b"Approved by the production model review board; ticket VQ-2026-0727.\n"
        )
        self.hosted_policy_path = self.root / "hosted-policy.json"
        self.hosted_policy_path.write_bytes(
            canonical_json_bytes(_hosted_policy()) + b"\n"
        )

        private_key = ec.generate_private_key(ec.SECP256R1())
        self.private_key_path = self.root / "promotion-private.pem"
        self.private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_key_path = self.root / "promotion-public.pem"
        self.public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        inputs = dict(paired["inputs"])
        inputs.pop("research_only", None)
        self.source_arguments = {
            "promotion_evidence_path": self.report_path,
            **inputs,
            "catalog_path": self.evaluation.catalog_path,
            "serving_profile_path": serving["profile_path"],
            "artifact_path": serving["artifact_path"],
            "manifest_path": serving["manifest_path"],
            "trainer_provenance_trust": serving["trainer_provenance_trust"],
            "trainer_provenance_now": _NOW,
            "approval_evidence_path": self.approval_path,
            "hosted_deployment_policy_path": self.hosted_policy_path,
        }

        def retain_legacy_manifest_snapshot(manifest_path, **_kwargs):
            return SimpleNamespace(
                manifest_snapshot=validate_manifest_snapshot(manifest_path)
            )

        self.legacy_selection_fixture = mock.patch.object(
            promotion_module,
            "validate_base_model_selection_manifest_target",
            side_effect=retain_legacy_manifest_snapshot,
        )
        self.legacy_selection_fixture.start()
        self.addCleanup(self.legacy_selection_fixture.stop)
        self.identity_arguments = {
            "audience": "daxalgo-platform-prod",
            "key_id": "model-promotion-key-2026-07",
            "signer_role": "production-model-approver",
            "deployment_id": "hyperion-prod-eu1",
            "environment": "production",
        }

    def _create(self, name: str = "promotion.json", **overrides):
        arguments = {
            **self.identity_arguments,
            "approval_id": "approval-vq-2026-0727",
            "actor_id": "reviewer-17",
            "actor_role": self.identity_arguments["signer_role"],
            "approval_reference": "VQ-2026-0727",
            "approved_at_utc": "2026-07-27T09:00:00Z",
            "issued_at_utc": "2026-07-27T10:00:00Z",
            "not_before_utc": "2026-07-27T10:00:00Z",
            "expires_at_utc": "2026-08-27T10:00:00Z",
            "now": _NOW,
            **self.source_arguments,
        }
        arguments.update(overrides)
        return create_model_promotion(
            output_path=self.root / name,
            private_key_path=self.private_key_path,
            public_key_path=self.public_key_path,
            private_key_password=None,
            **arguments,
        )

    def _prepare(self, name: str = "promotion-signing-bundle.json", **overrides):
        arguments = {
            **self.identity_arguments,
            "approval_id": "approval-vq-2026-0727",
            "actor_id": "reviewer-17",
            "actor_role": self.identity_arguments["signer_role"],
            "approval_reference": "VQ-2026-0727",
            "approved_at_utc": "2026-07-27T09:00:00Z",
            "issued_at_utc": "2026-07-27T10:00:00Z",
            "not_before_utc": "2026-07-27T10:00:00Z",
            "expires_at_utc": "2026-08-27T10:00:00Z",
            "now": _NOW,
            **self.source_arguments,
        }
        arguments.update(overrides)
        public_key_path = arguments.pop("public_key_path", self.public_key_path)
        return prepare_model_promotion_signing_bundle(
            output_path=self.root / name,
            public_key_path=public_key_path,
            **arguments,
        )

    def _sign_bundle(
        self,
        bundle_path: Path,
        *,
        name: str = "promotion-signature.json",
        mode: str = "raw-message",
        signature_format: str = "asn1-der",
        high_s: bool = False,
    ) -> Path:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
            encode_dss_signature,
        )

        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(), password=None
        )
        if mode == "raw-message":
            signed_value = _decode_base64url(bundle["request"]["signaturePreimage"])
            algorithm = ec.ECDSA(hashes.SHA256())
        else:
            signed_value = _decode_base64url(bundle["request"]["signatureInput"])
            algorithm = ec.ECDSA(Prehashed(hashes.SHA256()))
        der = private_key.sign(signed_value, algorithm)
        r, s = decode_dss_signature(der)
        if high_s and s <= _P256_ORDER // 2:
            s = _P256_ORDER - s
        if signature_format == "ieee-p1363-fixed-64":
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            signature = encode_dss_signature(r, s)
        document = promotion_module._build_model_promotion_external_signature_document(
            bundle,
            bundle_bytes,
            signature_mode=mode,
            signature_format=signature_format,
            signature=signature,
        )
        path = self.root / name
        path.write_bytes(canonical_json_bytes(document) + b"\n")
        return path

    def _finalize(
        self,
        bundle_path: Path,
        signature_path: Path,
        *,
        name: str = "detached-promotion.json",
        **overrides,
    ):
        arguments = {
            "public_key_path": self.public_key_path,
            "expected_audience": self.identity_arguments["audience"],
            "expected_key_id": self.identity_arguments["key_id"],
            "expected_signer_role": self.identity_arguments["signer_role"],
            "expected_deployment_id": self.identity_arguments["deployment_id"],
            "expected_environment": self.identity_arguments["environment"],
            "now": _NOW,
            **self.source_arguments,
        }
        arguments.update(overrides)
        return finalize_model_promotion(
            signing_bundle_path=bundle_path,
            signature_path=signature_path,
            output_path=self.root / name,
            **arguments,
        )

    def _binding_arguments(self, **overrides) -> dict:
        arguments = dict(self.source_arguments)
        arguments.pop("approval_evidence_path")
        arguments.pop("hosted_deployment_policy_path")
        arguments.update(overrides)
        return arguments

    def test_promotion_signer_cannot_reuse_replay_audit_key(self) -> None:
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(
            self.public_key_path.read_bytes()
        )
        public_spki_sha256 = hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        replay_trust = CSharpVerifierReplayAuditTrust(
            self.public_key_path,
            public_spki_sha256,
            "replay-audience",
            "replay-key",
            "replay-auditor",
        )
        with self.assertRaisesRegex(ValidationError, "must differ"):
            self._create(csharp_verifier_replay_audit_trust=replay_trust)

    def test_promotion_signer_cannot_reuse_evaluation_authoring_key(self) -> None:
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(
            self.public_key_path.read_bytes()
        )
        public_spki_sha256 = hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        same_signer = replace(
            self.source_arguments["evaluation_authoring_approval_trust"],
            public_key_spki_sha256=public_spki_sha256,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "must differ from the evaluation-authoring approval signer",
        ):
            self._create(evaluation_authoring_approval_trust=same_signer)

    def test_promotion_signer_cannot_reuse_trainer_provenance_key(self) -> None:
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(
            self.public_key_path.read_bytes()
        )
        public_spki_sha256 = hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        same_signer = replace(
            self.source_arguments["trainer_provenance_trust"],
            public_key_spki_sha256=public_spki_sha256,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "must differ from the trainer-provenance signer",
        ):
            self._create(trainer_provenance_trust=same_signer)

    def test_bindings_retain_every_validated_authority_signer(self) -> None:
        normal = promotion_module._build_promotion_bindings(**self._binding_arguments())
        manifest_snapshot = normal.activation_inputs.manifest_snapshot
        manifest = copy.deepcopy(manifest_snapshot.document)
        base_selection_spki = "b" * 64
        corpus_admission_spki = "c" * 64
        replay_audit_spki = "d" * 64
        manifest["trainingCorpusAdmission"] = {
            "publicKeySpkiSha256": corpus_admission_spki
        }
        selected_base = SimpleNamespace(
            manifest_snapshot=replace(manifest_snapshot, document=manifest),
            selection=SimpleNamespace(
                envelope={"publicKeySpkiSha256": base_selection_spki}
            ),
        )
        replay_audit_path = self.root / "authority-replay-audit.json"
        replay_audit_path.write_bytes(b"validated replay audit\n")
        replay_audit = SimpleNamespace(
            payload={
                "replayCompletedAtUtc": "2026-07-27T08:59:58Z",
                "approval": {"approvedAtUtc": "2026-07-27T08:59:59Z"},
                "issuedAtUtc": "2026-07-27T09:00:00Z",
            },
            payload_sha256="a" * 64,
            envelope_sha256="e" * 64,
            public_key_spki_sha256=replay_audit_spki,
            expires_at_utc=datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc),
        )
        replay_trust = CSharpVerifierReplayAuditTrust(
            self.root / "authority-replay-public.pem",
            replay_audit_spki,
            "replay-audience",
            "replay-key",
            "replay-auditor",
        )

        with (
            mock.patch.object(
                promotion_module,
                "aggregate_promotion_evidence",
                return_value=self.report,
            ),
            mock.patch.object(
                promotion_module,
                "validate_base_model_selection_manifest_target",
                return_value=selected_base,
            ),
            mock.patch.object(
                promotion_module,
                "validate_serving_profile",
                return_value=normal.activation_inputs.profile,
            ),
            mock.patch.object(
                promotion_module,
                "validate_csharp_verifier_replay_audit",
                return_value=replay_audit,
            ),
        ):
            bindings = promotion_module._build_promotion_bindings(
                **self._binding_arguments(
                    base_selection_trust=SimpleNamespace(
                        public_key_spki_sha256=base_selection_spki
                    ),
                    csharp_verifier_replay_audit_path=replay_audit_path,
                    csharp_verifier_replay_audit_trust=replay_trust,
                    expected_csharp_verifier_replay_audit_envelope_sha256=(
                        replay_audit.envelope_sha256
                    ),
                )
            )

        authorities = dict(bindings.authority_signer_spki_sha256s)
        self.assertEqual(
            self.source_arguments["review_receipt_trust"].public_key_spki_sha256,
            authorities["corpus-review"],
        )
        self.assertEqual(
            self.source_arguments[
                "evaluation_authoring_approval_trust"
            ].public_key_spki_sha256,
            authorities["evaluation-authoring approval"],
        )
        self.assertEqual(base_selection_spki, authorities["base-selection"])
        self.assertEqual(corpus_admission_spki, authorities["corpus-admission"])
        self.assertEqual(
            self.source_arguments["trainer_provenance_trust"].public_key_spki_sha256,
            authorities["trainer-provenance"],
        )
        self.assertEqual(
            replay_audit_spki,
            authorities["C# verifier replay-audit"],
        )

    def test_bindings_reject_consumer_invalid_replay_audit_before_snapshot(
        self,
    ) -> None:
        replay_audit_path = self.root / "consumer-invalid-replay-audit.json"
        replay_audit_path.write_bytes(b"consumer-invalid replay audit\n")
        os.link(replay_audit_path, self.root / "consumer-invalid-replay-audit.link")
        replay_trust = CSharpVerifierReplayAuditTrust(
            self.root / "consumer-invalid-replay-public.pem",
            "d" * 64,
            "replay-audience",
            "replay-key",
            "replay-auditor",
        )

        def reject_hard_link(path, **_):
            if Path(path).stat().st_nlink != 1:
                raise ValidationError("replay audit must not be hard-linked")
            return SimpleNamespace()

        with (
            mock.patch.object(
                promotion_module,
                "validate_csharp_verifier_replay_audit",
                side_effect=reject_hard_link,
            ) as validate,
            self.assertRaisesRegex(ValidationError, "must not be hard-linked"),
        ):
            promotion_module._build_promotion_bindings(
                **self._binding_arguments(
                    csharp_verifier_replay_audit_path=replay_audit_path,
                    csharp_verifier_replay_audit_trust=replay_trust,
                    expected_csharp_verifier_replay_audit_envelope_sha256=("e" * 64),
                )
            )
        self.assertEqual(1, validate.call_count)
        self.assertEqual(replay_audit_path, Path(validate.call_args.args[0]))

    def test_trainer_signer_cannot_reuse_corpus_admission_key(self) -> None:
        normal = promotion_module._build_promotion_bindings(**self._binding_arguments())
        manifest_snapshot = normal.activation_inputs.manifest_snapshot
        manifest = copy.deepcopy(manifest_snapshot.document)
        manifest["trainingCorpusAdmission"] = {
            "publicKeySpkiSha256": self.source_arguments[
                "trainer_provenance_trust"
            ].public_key_spki_sha256
        }
        selected_base = SimpleNamespace(
            manifest_snapshot=replace(manifest_snapshot, document=manifest)
        )

        with (
            mock.patch.object(
                promotion_module,
                "validate_base_model_selection_manifest_target",
                return_value=selected_base,
            ),
            mock.patch.object(
                promotion_module,
                "validate_serving_profile",
                return_value=normal.activation_inputs.profile,
            ),
            self.assertRaisesRegex(
                ValidationError,
                "must differ from the corpus-admission signer",
            ),
        ):
            promotion_module._build_promotion_bindings(**self._binding_arguments())

    def test_create_and_validate_reject_every_bound_authority_signer(self) -> None:
        bindings = promotion_module._build_promotion_bindings(
            **self._binding_arguments()
        )
        created = self._create("authority-parity-valid.json")
        promotion_spki = created.envelope["publicKeySpkiSha256"]
        validation_arguments = {
            "public_key_path": self.public_key_path,
            "expected_audience": self.identity_arguments["audience"],
            "expected_key_id": self.identity_arguments["key_id"],
            "expected_signer_role": self.identity_arguments["signer_role"],
            "expected_deployment_id": self.identity_arguments["deployment_id"],
            "expected_environment": self.identity_arguments["environment"],
            "now": _NOW,
            **self.source_arguments,
        }
        roles = (
            "corpus-review",
            "evaluation-authoring approval",
            "base-selection",
            "corpus-admission",
            "trainer-provenance",
            "C# verifier replay-audit",
        )

        for index, role in enumerate(roles):
            invalid = replace(
                bindings,
                authority_signer_spki_sha256s=((role, promotion_spki),),
            )
            output = self.root / f"authority-create-collision-{index}.json"
            with (
                self.subTest(path="create", role=role),
                mock.patch.object(
                    promotion_module,
                    "_build_promotion_bindings",
                    return_value=invalid,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    f"must differ from the {role} signer",
                ),
            ):
                self._create(output.name)
            self.assertFalse(output.exists())

            with (
                self.subTest(path="validate", role=role),
                mock.patch.object(
                    promotion_module,
                    "_build_promotion_bindings",
                    return_value=invalid,
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    f"must differ from the {role} signer",
                ),
            ):
                validate_model_promotion(created.path, **validation_arguments)

    def test_replay_audit_timeline_must_precede_promotion_approval(self) -> None:
        audit_path = self.root / "replay-audit.json"
        audit_path.write_bytes(b"test replay audit\n")
        audit_arguments = {
            "csharp_verifier_replay_audit_path": audit_path,
            "csharp_verifier_replay_audit_trust": CSharpVerifierReplayAuditTrust(
                self.root / "replay-audit-public.pem",
                "f" * 64,
                "replay-audience",
                "replay-key",
                "replay-auditor",
            ),
            "expected_csharp_verifier_replay_audit_envelope_sha256": "e" * 64,
        }

        def replay_audit(
            replay_completed_at: str, approved_at: str, issued_at: str
        ) -> SimpleNamespace:
            return SimpleNamespace(
                payload={
                    "replayCompletedAtUtc": replay_completed_at,
                    "approval": {"approvedAtUtc": approved_at},
                    "issuedAtUtc": issued_at,
                },
                payload_sha256="a" * 64,
                envelope_sha256="b" * 64,
                public_key_spki_sha256="f" * 64,
                expires_at_utc=datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc),
            )

        boundary = replay_audit(
            "2026-07-27T08:59:58Z",
            "2026-07-27T08:59:59Z",
            "2026-07-27T09:00:00Z",
        )
        with (
            mock.patch.object(
                promotion_module,
                "aggregate_promotion_evidence",
                return_value=self.report,
            ),
            mock.patch.object(
                promotion_module,
                "validate_csharp_verifier_replay_audit",
                return_value=boundary,
            ),
        ):
            accepted = self._create("causal-replay-audit.json", **audit_arguments)
        self.assertEqual(
            boundary.envelope_sha256,
            accepted.activation_inputs.csharp_verifier_replay_audit_envelope_sha256,
        )

        postdated = replay_audit(
            "2026-07-27T08:59:59Z",
            "2026-07-27T09:00:00Z",
            "2026-07-27T09:00:01Z",
        )
        failed_output = self.root / "postdated-replay-audit.json"
        with (
            mock.patch.object(
                promotion_module,
                "aggregate_promotion_evidence",
                return_value=self.report,
            ),
            mock.patch.object(
                promotion_module,
                "validate_csharp_verifier_replay_audit",
                return_value=postdated,
            ),
            self.assertRaisesRegex(
                ValidationError,
                "audit issuedAt <= promotion approvedAt",
            ),
        ):
            self._create(failed_output.name, **audit_arguments)
        self.assertFalse(failed_output.exists())

        with (
            mock.patch.object(
                promotion_module,
                "aggregate_promotion_evidence",
                return_value=self.report,
            ),
            mock.patch.object(
                promotion_module,
                "validate_csharp_verifier_replay_audit",
                return_value=postdated,
            ),
            mock.patch.object(promotion_module, "_validate_training_timeline"),
        ):
            invalid = self._create(
                "signed-postdated-replay-audit.json", **audit_arguments
            )

        with (
            mock.patch.object(
                promotion_module,
                "aggregate_promotion_evidence",
                return_value=self.report,
            ),
            mock.patch.object(
                promotion_module,
                "validate_csharp_verifier_replay_audit",
                return_value=postdated,
            ),
            self.assertRaisesRegex(
                ValidationError,
                "audit issuedAt <= promotion approvedAt",
            ),
        ):
            validate_model_promotion(
                invalid.path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                expected_deployment_id=self.identity_arguments["deployment_id"],
                expected_environment=self.identity_arguments["environment"],
                now=_NOW,
                **self.source_arguments,
                **audit_arguments,
            )

    def test_create_and_validate_reaggregates_and_binds_every_live_input(self) -> None:
        created = self._create()
        validated = validate_model_promotion(
            created.path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            now=_NOW,
            **self.source_arguments,
        )
        self.assertEqual(created.payload_sha256, validated.payload_sha256)
        self.assertEqual(
            model_promotion_id(validated.payload), validated.payload["promotionId"]
        )
        self.assertNotIn("publicKey", validated.envelope)
        signature = _decode_base64url(validated.envelope["signature"])
        self.assertEqual(64, len(signature))
        self.assertLessEqual(int.from_bytes(signature[32:], "big"), _P256_ORDER // 2)
        readiness = create_promoted_model_readiness_attestation(
            promotion_path=created.path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_promotion_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            readiness_key_id="prod-hmac-v1",
            readiness_key=bytes(range(32)),
            now=_NOW,
            **self.source_arguments,
        )
        self.assertEqual(
            "daxalgo.hyperion.model-readiness/v2", readiness["schemaVersion"]
        )
        self.assertEqual(
            compute_model_readiness_v2_proof(
                key=bytes(range(32)),
                audience=self.identity_arguments["audience"],
                nonce=readiness["nonce"],
                key_id=readiness["keyId"],
                serving_profile_sha256=validated.payload["model"][
                    "servingProfileSha256"
                ],
                artifact_sha256=validated.payload["model"]["artifactSha256"],
                artifact_tree_sha256=validated.payload["model"]["artifactTreeSha256"],
                execution_model_id=validated.payload["model"]["executionModelId"],
                promotion_envelope_sha256=validated.envelope_sha256,
                promotion_payload_sha256=validated.payload_sha256,
                deployment_id=validated.payload["deployment"]["deploymentId"],
                provider_id=validated.payload["hostedDeploymentPolicy"]["providerId"],
                hosted_deployment_policy_sha256=validated.payload[
                    "hostedDeploymentPolicy"
                ]["policySha256"],
                expires_at_utc=validated.payload["expiresAtUtc"],
            ),
            readiness["proof"],
        )

    def test_detached_signing_round_trips_existing_promotion_wire(self) -> None:
        import inspect

        direct = self._create("direct-promotion.json")
        bundle = self._prepare()
        schemas = Path(__file__).parents[1] / "schemas"
        bundle_schema = json.loads(
            (schemas / "model-promotion-signing-bundle.v1.schema.json").read_bytes()
        )
        signature_schema = json.loads(
            (schemas / "model-promotion-signature.v1.schema.json").read_bytes()
        )
        jsonschema.Draft202012Validator.check_schema(bundle_schema)
        jsonschema.Draft202012Validator.check_schema(signature_schema)
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle.bundle)
        self.assertEqual(direct.payload, bundle.payload)
        direct_unsigned_envelope = dict(direct.envelope)
        direct_unsigned_envelope["signature"] = ""
        self.assertEqual(direct_unsigned_envelope, bundle.unsigned_envelope)
        self.assertEqual("unsigned-non-authorizing", bundle.bundle["status"])
        self.assertTrue(
            all(value is False for value in bundle.bundle["authority"].values())
        )
        self.assertNotIn(
            "private_key_path", inspect.signature(finalize_model_promotion).parameters
        )
        self.assertNotIn(
            "private_key_password",
            inspect.signature(finalize_model_promotion).parameters,
        )
        verified_bundle = verify_model_promotion_signing_bundle(
            bundle.path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            now=_NOW,
            **self.source_arguments,
        )
        self.assertEqual(bundle.bundle_id, verified_bundle.bundle_id)

        variants = (
            ("raw-message", "asn1-der", False),
            ("sha256-digest", "ieee-p1363-fixed-64", True),
        )
        finalized_outputs = []
        for index, (mode, signature_format, high_s) in enumerate(variants):
            with self.subTest(mode=mode, signature_format=signature_format):
                signature_path = self._sign_bundle(
                    bundle.path,
                    name=f"promotion-signature-{index}.json",
                    mode=mode,
                    signature_format=signature_format,
                    high_s=high_s,
                )
                jsonschema.Draft202012Validator(signature_schema).validate(
                    json.loads(signature_path.read_bytes())
                )
                finalized = self._finalize(
                    bundle.path,
                    signature_path,
                    name=f"detached-promotion-{index}.json",
                )
                self.assertEqual(bundle.payload, finalized.payload)
                self.assertEqual(
                    "daxalgo.hyperion.model-promotion-envelope/v1",
                    finalized.envelope["schemaVersion"],
                )
                self.assertEqual("ieee-p1363", finalized.envelope["signatureFormat"])
                normalized = _decode_base64url(finalized.envelope["signature"])
                self.assertEqual(64, len(normalized))
                self.assertLessEqual(
                    int.from_bytes(normalized[32:], "big"), _P256_ORDER // 2
                )
                finalized_outputs.append(finalized)
        readiness = create_promoted_model_readiness_attestation(
            promotion_path=finalized_outputs[0].path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_promotion_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            readiness_key_id="prod-hmac-v1",
            readiness_key=bytes(range(32)),
            now=_NOW,
            **self.source_arguments,
        )
        self.assertEqual(
            "daxalgo.hyperion.model-readiness/v2", readiness["schemaVersion"]
        )

    def test_detached_signature_failure_is_rejected_before_live_replay(self) -> None:
        bundle = self._prepare()
        signature_path = self._sign_bundle(bundle.path)
        document = json.loads(signature_path.read_bytes())
        signature = bytearray(_decode_base64url(document["signature"]))
        signature[-1] ^= 1
        document["signature"] = _encode_base64url(bytes(signature))
        document["signatureId"] = (
            promotion_module.model_promotion_external_signature_id(document)
        )
        signature_path.write_bytes(canonical_json_bytes(document) + b"\n")
        with (
            mock.patch.object(promotion_module, "_build_promotion_bindings") as replay,
            self.assertRaisesRegex(ValidationError, "does not verify"),
        ):
            self._finalize(bundle.path, signature_path)
        replay.assert_not_called()

    def test_detached_signature_contract_rejects_wrong_or_ambiguous_signing(
        self,
    ) -> None:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        bundle = self._prepare()
        bundle_bytes = bundle.path.read_bytes()
        document = json.loads(bundle_bytes)
        preimage = _decode_base64url(document["request"]["signaturePreimage"])
        digest = _decode_base64url(document["request"]["signatureInput"])
        private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(), password=None
        )
        cases = {
            "wrong-key": (
                "raw-message",
                "asn1-der",
                ec.generate_private_key(ec.SECP256R1()).sign(
                    preimage, ec.ECDSA(hashes.SHA256())
                ),
            ),
            "double-hashed-digest": (
                "sha256-digest",
                "asn1-der",
                private_key.sign(digest, ec.ECDSA(hashes.SHA256())),
            ),
            "out-of-range-p1363": (
                "raw-message",
                "ieee-p1363-fixed-64",
                b"\0" * 64,
            ),
        }
        for name, (mode, signature_format, signature) in cases.items():
            with self.subTest(name=name):
                signature_document = (
                    promotion_module._build_model_promotion_external_signature_document(
                        document,
                        bundle_bytes,
                        signature_mode=mode,
                        signature_format=signature_format,
                        signature=signature,
                    )
                )
                signature_path = self.root / f"rejected-{name}.json"
                signature_path.write_bytes(
                    canonical_json_bytes(signature_document) + b"\n"
                )
                with (
                    mock.patch.object(
                        promotion_module, "_build_promotion_bindings"
                    ) as replay,
                    self.assertRaises(ValidationError),
                ):
                    self._finalize(bundle.path, signature_path)
                replay.assert_not_called()

        valid_signature = self._sign_bundle(
            bundle.path, name="invalid-mode-signature.json"
        )
        invalid_mode = json.loads(valid_signature.read_bytes())
        invalid_mode["mode"] = "unspecified"
        invalid_mode["signatureId"] = (
            promotion_module.model_promotion_external_signature_id(invalid_mode)
        )
        valid_signature.write_bytes(canonical_json_bytes(invalid_mode) + b"\n")
        with (
            mock.patch.object(promotion_module, "_build_promotion_bindings") as replay,
            self.assertRaisesRegex(ValidationError, "raw-message.*sha256-digest"),
        ):
            self._finalize(bundle.path, valid_signature)
        replay.assert_not_called()

    def test_detached_finalization_rejects_live_source_drift(self) -> None:
        bundle = self._prepare()
        signature_path = self._sign_bundle(bundle.path)
        responses = Path(self.source_arguments["responses_path"])
        original = responses.read_bytes()
        try:
            responses.write_bytes(original + b" ")
            with self.assertRaises(ValidationError):
                self._finalize(bundle.path, signature_path)
        finally:
            responses.write_bytes(original)
        self.assertFalse((self.root / "detached-promotion.json").exists())

    def test_detached_bundle_rejects_recursive_payload_before_live_replay(self) -> None:
        bundle = self._prepare()
        document = json.loads(bundle.path.read_bytes())
        recursive = b'{"value":' * 10000 + b"0" + b"}" * 10000
        document["payload"] = _encode_base64url(recursive)
        bundle.path.write_bytes(canonical_json_bytes(document) + b"\n")
        with (
            mock.patch.object(promotion_module, "_build_promotion_bindings") as replay,
            self.assertRaisesRegex(ValidationError, "invalid bounded JSON"),
        ):
            verify_model_promotion_signing_bundle(
                bundle.path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                expected_deployment_id=self.identity_arguments["deployment_id"],
                expected_environment=self.identity_arguments["environment"],
                now=_NOW,
                **self.source_arguments,
            )
        replay.assert_not_called()

    def test_signing_bundle_reserves_final_signed_envelope_size(self) -> None:
        output = self.root / "oversized-promotion-signing-bundle.json"
        with (
            mock.patch.object(
                promotion_module, "MAX_PROMOTION_ENVELOPE_BYTES", new=200
            ),
            self.assertRaisesRegex(ValidationError, "exceeds its byte limit"),
        ):
            self._prepare(output.name)
        self.assertFalse(output.exists())

    def test_promotion_public_key_matches_platform_canonical_pem_contract(self) -> None:
        noncanonical = self.root / "noncanonical-promotion-public.pem"
        noncanonical.write_bytes(self.public_key_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValidationError, "canonical PEM|one PUBLIC KEY"):
            self._prepare(public_key_path=noncanonical)

    def test_promotion_consumers_reject_hard_linked_envelopes(self) -> None:
        created = self._create()
        second_link = self.root / "promotion-second-link.json"
        try:
            os.link(created.path, second_link)
        except OSError as error:
            self.skipTest(f"hard links unavailable: {error}")
        with self.assertRaisesRegex(ValidationError, "hard-linked"):
            validate_model_promotion(
                created.path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                expected_deployment_id=self.identity_arguments["deployment_id"],
                expected_environment=self.identity_arguments["environment"],
                now=_NOW,
                **self.source_arguments,
            )

    def test_production_promotion_rejects_legacy_training_manifest(self) -> None:
        self.legacy_selection_fixture.stop()
        try:
            with self.assertRaisesRegex(
                ValidationError, "requires a corpus-admitted v3 training manifest"
            ):
                self._create("legacy-manifest-rejected.json")
        finally:
            self.legacy_selection_fixture.start()

    def test_promotion_replay_failure_leaves_no_published_authority(self) -> None:
        output = self.root / "failed-promotion-publication.json"
        with mock.patch.object(
            promotion_module,
            "_validate_model_promotion",
            side_effect=ValidationError("post-write replay failed"),
        ):
            with self.assertRaisesRegex(ValidationError, "post-write replay failed"):
                self._create(output.name)
        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(f".{output.name}.*.staging")))

        created = self._create(output.name)
        self.assertEqual(output, created.path)

    def test_promotion_uses_the_selection_validated_manifest_snapshot(self) -> None:
        manifest_path = Path(self.source_arguments["manifest_path"])
        original = manifest_path.read_bytes()
        retained = validate_manifest_snapshot(manifest_path)

        def snapshot_then_mutate(path, **_kwargs):
            self.assertEqual(manifest_path, Path(path))
            manifest_path.write_bytes(original + b" ")
            return SimpleNamespace(manifest_snapshot=retained)

        arguments = dict(self.source_arguments)
        arguments.pop("approval_evidence_path")
        arguments.pop("hosted_deployment_policy_path")
        try:
            with mock.patch.object(
                promotion_module,
                "validate_base_model_selection_manifest_target",
                side_effect=snapshot_then_mutate,
            ) as validate_selection:
                bindings = promotion_module._build_promotion_bindings(**arguments)
            validate_selection.assert_called_once()
            self.assertEqual(
                retained.sha256, bindings.model["trainingRunManifestSha256"]
            )
            self.assertNotEqual(
                retained.sha256, hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            )
        finally:
            manifest_path.write_bytes(original)

    def test_promotion_rejects_noncausal_training_timestamps(self) -> None:
        arguments = dict(self.source_arguments)
        arguments.pop("approval_evidence_path")
        arguments.pop("hosted_deployment_policy_path")
        bindings = promotion_module._build_promotion_bindings(**arguments)
        invalid_timelines = {
            "manifest-after-artifact": replace(
                bindings,
                manifest_created_at=bindings.artifact_recorded_at
                + timedelta(seconds=1),
            ),
            "artifact-after-issuance": replace(
                bindings,
                artifact_recorded_at=datetime(
                    2026, 7, 27, 10, 0, 1, tzinfo=timezone.utc
                ),
            ),
            "trainer-not-before-after-approval": replace(
                bindings,
                trainer_provenance_not_before=datetime(
                    2026, 7, 27, 9, 0, 1, tzinfo=timezone.utc
                ),
            ),
        }
        for name, invalid in invalid_timelines.items():
            with (
                self.subTest(name=name),
                mock.patch.object(
                    promotion_module, "_build_promotion_bindings", return_value=invalid
                ),
                self.assertRaisesRegex(
                    ValidationError,
                    "manifestCreatedAt <= artifactRecordedAt <= trainerProvenanceIssuedAt",
                ),
            ):
                self._create(f"invalid-{name}.json")

    def test_promotion_cannot_outlive_authenticated_receipt_authority(self) -> None:
        after_authority = "2026-12-31T00:00:01Z"
        arguments = {
            "output_path": self.root / "authority-overrun.json",
            "private_key_path": self.private_key_path,
            "public_key_path": self.public_key_path,
            "private_key_password": None,
            **self.identity_arguments,
            "approval_id": "approval-vq-2026-0727",
            "actor_id": "reviewer-17",
            "actor_role": self.identity_arguments["signer_role"],
            "approval_reference": "VQ-2026-0727",
            "approved_at_utc": "2026-07-27T09:00:00Z",
            "issued_at_utc": "2026-07-27T10:00:00Z",
            "not_before_utc": "2026-07-27T10:00:00Z",
            "expires_at_utc": after_authority,
            "now": _NOW,
            **self.source_arguments,
        }
        with self.assertRaisesRegex(
            ValidationError, "earliest authenticated upstream-authority expiry"
        ):
            create_model_promotion(**arguments)
        self.assertFalse(Path(arguments["output_path"]).exists())
        self.assertEqual(
            [],
            list(self.root.glob(f".{Path(arguments['output_path']).name}.*.staging")),
        )

        with mock.patch.object(promotion_module, "_validate_authority_window"):
            invalid = create_model_promotion(
                **{**arguments, "output_path": self.root / "signed-overrun.json"}
            )
        with self.assertRaisesRegex(
            ValidationError, "earliest authenticated upstream-authority expiry"
        ):
            validate_model_promotion(
                invalid.path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                expected_deployment_id=self.identity_arguments["deployment_id"],
                expected_environment=self.identity_arguments["environment"],
                now=_NOW,
                **self.source_arguments,
            )

        boundary = create_model_promotion(
            **{
                **arguments,
                "output_path": self.root / "authority-boundary.json",
                "expires_at_utc": _PROMOTION_RECEIPT_EXPIRES,
            }
        )
        self.assertEqual(_PROMOTION_RECEIPT_EXPIRES, boundary.payload["expiresAtUtc"])

    def test_commit_unlink_failure_keeps_promotion_unpublished(self) -> None:
        output = self.root / "promotion-cleanup-failure.json"
        original_unlink = Path.unlink

        def fail_staging_cleanup(path, *args, **kwargs):
            if path.parent == output.parent and path.name.startswith(
                f".{output.name}."
            ):
                raise PermissionError("simulated post-publication cleanup failure")
            return original_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", new=fail_staging_cleanup),
            self.assertRaisesRegex(ValidationError, "residual staging"),
        ):
            self._create(output.name)

        self.assertFalse(output.exists())
        staging = list(self.root.glob(f".{output.name}.*.staging"))
        self.assertEqual(1, len(staging))
        original_unlink(staging[0])

    def test_prepublication_cleanup_failure_surfaces_residual_promotion(self) -> None:
        output = self.root / "promotion-residual-authority.json"
        original_unlink = Path.unlink

        def fail_staging_cleanup(path, *args, **kwargs):
            if path.parent == output.parent and path.name.startswith(
                f".{output.name}."
            ):
                raise PermissionError("simulated prepublication cleanup failure")
            return original_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", new=fail_staging_cleanup),
            mock.patch.object(
                promotion_module.os,
                "link",
                side_effect=OSError("simulated publication failure"),
            ),
            self.assertRaisesRegex(ValidationError, "residual staging"),
        ):
            self._create(output.name)

        self.assertFalse(output.exists())
        staging = list(self.root.glob(f".{output.name}.*.staging"))
        self.assertEqual(1, len(staging))
        original_unlink(staging[0])

    def test_signed_raw_base_baseline_flows_through_promotion_and_readiness(
        self,
    ) -> None:
        try:
            base_tests = importlib.import_module("test_base_engine_wrapper")
        except ModuleNotFoundError:
            base_tests = importlib.import_module("tests.test_base_engine_wrapper")
        try:
            evaluation_tests = importlib.import_module("test_evaluation")
        except ModuleNotFoundError:
            evaluation_tests = importlib.import_module("tests.test_evaluation")

        base = base_tests.BaseEngineWrapperTests()
        base.setUp()
        self.addCleanup(base.doCleanups)
        evaluation = evaluation_tests.EvaluationTests()
        evaluation.setUp()
        self.addCleanup(evaluation.doCleanups)
        shutil.copyfile(base.catalog, evaluation.catalog_path)
        evaluation.catalog = json.loads(
            evaluation.catalog_path.read_text(encoding="utf-8")
        )

        try:
            release_tests = importlib.import_module("test_release")
        except ModuleNotFoundError:
            release_tests = importlib.import_module("tests.test_release")
        with (
            mock.patch.object(
                evaluation_tests,
                "create_bundle",
                side_effect=_causally_ordered_bundle_creator(
                    evaluation_tests.create_bundle
                ),
            ),
            mock.patch.multiple(
                release_tests,
                APPROVED=_PROMOTION_RELEASE_APPROVED,
                RECEIPT_ISSUED=_PROMOTION_RECEIPT_ISSUED,
                RECEIPT_NOT_BEFORE=_PROMOTION_RECEIPT_NOT_BEFORE,
                RECEIPT_EXPIRES=_PROMOTION_RECEIPT_EXPIRES,
                AUTHORING_APPROVED=_PROMOTION_AUTHORING_APPROVED,
                AUTHORING_ISSUED=_PROMOTION_AUTHORING_ISSUED,
                AUTHORING_NOT_BEFORE=_PROMOTION_AUTHORING_NOT_BEFORE,
                AUTHORING_EXPIRES=_PROMOTION_AUTHORING_EXPIRES,
                VALIDATION_TIME=_PROMOTION_RECEIPT_VALIDATION_TIME,
            ),
        ):
            paired = evaluation._bound_paired_fixture(provider=True)
        bound = paired["bound"]
        capture_activation_path = base.root / "promotion-capture-activation.json"
        capture_config_path = base.root / "promotion-capture-wrapper.json"
        capture_config_value = json.loads(base.config_path.read_text(encoding="utf-8"))
        capture_config_value["activation"]["path"] = str(capture_activation_path)
        base_tests._write_json(capture_config_path, capture_config_value)
        capture_config = load_base_engine_wrapper_config(capture_config_path)
        create_base_engine_activation(
            config_path=capture_config_path,
            output_path=capture_activation_path,
            private_key_path=base.launcher_private,
            public_key_path=base.launcher_public,
            private_key_password=None,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
            issued_at_utc="2026-07-28T09:59:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-07-29T10:00:00Z",
        )
        wrapper = BaseModelEngineWrapper(
            capture_config,
            bearer_token=base.bearer,
            child_api_key="C" * 48,
            transport=base._transport,
            process_factory=base._process_factory,
            read_only_probe=lambda path: True,
            listener_ownership_probe=lambda process_id, host, port: True,
            runtime_key_isolation_probe=lambda config: True,
            clock=lambda: base.now,
        )
        self.addCleanup(wrapper.stop)
        wrapper.start(start_monitor=False)

        baseline_responses_path = evaluation.root / "attested-baseline.responses.jsonl"

        def capture_transport(url, headers, body, timeout, max_bytes):
            response = wrapper.handle_http_request(
                "POST", BASE_ATTESTED_COMPLETIONS_PATH, headers, body
            )
            self.assertEqual(200, response.status)
            return evaluation_tests.TransportResponse(response.body, url)

        activation_trust = BaseEngineActivationTrust(
            public_key_path=base.launcher_public,
            public_key_spki_sha256=base.launcher_spki,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
        )
        capture_openai_responses(
            tasks_path=paired["inputs"]["sealed_tasks_path"],
            catalog_path=base.catalog,
            output_path=baseline_responses_path,
            base_evaluation_profile_path=base.profile_path,
            base_model_snapshot_manifest_path=base.manifest,
            base_model_snapshot_path=base.snapshot,
            base_model_source_lock_path=base.source_lock,
            base_engine_wrapper_config_path=capture_config_path,
            base_engine_activation_trust=activation_trust,
            run_id="bound-attested-baseline-run-001",
            base_url="http://127.0.0.1:18090/v1",
            api_key_env="VQ_OUTER_BEARER",
            seed=17,
            data_release_path=bound["release_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
            research_only=False,
            transport=capture_transport,
            clock=lambda: base.now,
            monotonic=iter((0.0, 0.1)).__next__,
        )
        baseline_response = validate_evaluation_responses(
            baseline_responses_path, paired["inputs"]["sealed_tasks_path"]
        )[0]
        baseline_results_path = evaluation.root / "attested-baseline.results.jsonl"
        run_release_verifiers(
            tasks_path=paired["inputs"]["sealed_tasks_path"],
            responses_path=baseline_responses_path,
            release_path=bound["release_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
            output_path=baseline_results_path,
        )

        policy_path = Path(paired["inputs"]["policy_path"])
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy["baselineRun"] = evaluation_tests._identity(baseline_response)
        policy["policySha256"] = promotion_policy_sha256(policy)
        policy_path.write_bytes(canonical_json_bytes(policy) + b"\n")
        attestation_trust = BaseResponseAttestationTrust(
            activation_trust=activation_trust,
            runtime_public_key_path=base.runtime_public,
        )
        evidence_inputs = dict(paired["inputs"])
        evidence_inputs["baseline_responses_path"] = baseline_responses_path
        evidence_inputs["baseline_verifier_results_path"] = baseline_results_path
        evidence_inputs["baseline_attestation_trust"] = attestation_trust
        report = aggregate_promotion_evidence(**evidence_inputs)
        self.assertEqual(
            EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
            report["baseline"]["identity"]["responseSchemaVersion"],
        )
        report_path = evaluation.root / "attested-promotion-evidence.json"
        write_json_atomic_no_clobber(report_path, report)
        serving = evaluation._serving_fixture(
            0,
            "bound-candidate-v1",
            data_release_path=bound["release_path"],
            sft_path=bound["sft_path"],
            review_receipt_trust=bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=bound["review_receipt_now"],
        )
        source_arguments = {
            "promotion_evidence_path": report_path,
            **{
                key: value
                for key, value in evidence_inputs.items()
                if key != "research_only"
            },
            "catalog_path": evaluation.catalog_path,
            "serving_profile_path": serving["profile_path"],
            "artifact_path": serving["artifact_path"],
            "manifest_path": serving["manifest_path"],
            "trainer_provenance_trust": serving["trainer_provenance_trust"],
            "trainer_provenance_now": base.now,
            "approval_evidence_path": self.approval_path,
            "hosted_deployment_policy_path": self.hosted_policy_path,
        }
        created = create_model_promotion(
            output_path=self.root / "attested-baseline-promotion.json",
            private_key_path=self.private_key_path,
            public_key_path=self.public_key_path,
            private_key_password=None,
            **self.identity_arguments,
            approval_id="approval-vq-2026-0728",
            actor_id="reviewer-17",
            actor_role=self.identity_arguments["signer_role"],
            approval_reference="VQ-2026-0728",
            approved_at_utc="2026-07-28T09:00:00Z",
            issued_at_utc="2026-07-28T10:00:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-08-28T10:00:00Z",
            now=base.now,
            **source_arguments,
        )
        validation_arguments = {
            "public_key_path": self.public_key_path,
            "expected_audience": self.identity_arguments["audience"],
            "expected_key_id": self.identity_arguments["key_id"],
            "expected_signer_role": self.identity_arguments["signer_role"],
            "expected_deployment_id": self.identity_arguments["deployment_id"],
            "expected_environment": self.identity_arguments["environment"],
            "now": base.now,
            **source_arguments,
        }
        validated = validate_model_promotion(created.path, **validation_arguments)
        self.assertEqual(created.payload_sha256, validated.payload_sha256)
        readiness = create_promoted_model_readiness_attestation(
            promotion_path=created.path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_promotion_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            readiness_key_id="prod-hmac-v1",
            readiness_key=bytes(range(32)),
            now=base.now,
            **source_arguments,
        )
        self.assertEqual(
            "daxalgo.hyperion.model-readiness/v2", readiness["schemaVersion"]
        )

        missing_trust = dict(validation_arguments)
        missing_trust.pop("baseline_attestation_trust")
        with self.assertRaisesRegex(ValidationError, "requires external"):
            validate_model_promotion(created.path, **missing_trust)

        wrong_identity = dict(validation_arguments)
        wrong_identity["baseline_attestation_trust"] = BaseResponseAttestationTrust(
            activation_trust=BaseEngineActivationTrust(
                public_key_path=base.launcher_public,
                public_key_spki_sha256=base.launcher_spki,
                audience="wrong-audience",
                key_id="launcher-key-v1",
                signer_role="base-runtime-launcher",
            ),
            runtime_public_key_path=base.runtime_public,
        )
        with self.assertRaisesRegex(ValidationError, "pinned signer trust"):
            validate_model_promotion(created.path, **wrong_identity)

        wrong_runtime = dict(validation_arguments)
        wrong_runtime["baseline_attestation_trust"] = BaseResponseAttestationTrust(
            activation_trust=activation_trust,
            runtime_public_key_path=base.launcher_public,
        )
        with self.assertRaisesRegex(ValidationError, "pinned public key"):
            validate_model_promotion(created.path, **wrong_runtime)

        tampered = copy.deepcopy(baseline_response)
        tampered["runtimeAttestation"]["receipt"]["signature"] = "A" * 86
        tampered["responseSha256"] = evaluation_response_sha256(tampered)
        tampered_path = evaluation.root / "tampered-attested-baseline.responses.jsonl"
        tampered_path.write_bytes(canonical_json_bytes(tampered) + b"\n")
        tampered_arguments = dict(validation_arguments)
        tampered_arguments["baseline_responses_path"] = tampered_path
        with self.assertRaisesRegex(ValidationError, "signature"):
            validate_model_promotion(created.path, **tampered_arguments)

        downgraded = copy.deepcopy(baseline_response)
        downgraded["schemaVersion"] = "daxalgo.hyperion.evaluation-response/v1"
        downgraded.pop("runtimeAttestation")
        downgraded["responseSha256"] = evaluation_response_sha256(downgraded)
        downgraded_path = evaluation.root / "downgraded-baseline.responses.jsonl"
        downgraded_path.write_bytes(canonical_json_bytes(downgraded) + b"\n")
        downgraded_arguments = dict(validation_arguments)
        downgraded_arguments["baseline_responses_path"] = downgraded_path
        downgraded_arguments.pop("baseline_attestation_trust")
        with self.assertRaisesRegex(ValidationError, "raw-base response v1"):
            validate_model_promotion(created.path, **downgraded_arguments)

    def test_live_source_receipt_trust_is_required_and_revalidated(self) -> None:
        created = self._create()
        validation_arguments = {
            "public_key_path": self.public_key_path,
            "expected_audience": self.identity_arguments["audience"],
            "expected_key_id": self.identity_arguments["key_id"],
            "expected_signer_role": self.identity_arguments["signer_role"],
            "expected_deployment_id": self.identity_arguments["deployment_id"],
            "expected_environment": self.identity_arguments["environment"],
            "now": _NOW,
        }

        missing_trust = dict(self.source_arguments)
        missing_trust.pop("review_receipt_trust")
        with self.assertRaisesRegex(TypeError, "review_receipt_trust"):
            validate_model_promotion(
                created.path, **validation_arguments, **missing_trust
            )

        missing_authoring_trust = dict(self.source_arguments)
        missing_authoring_trust.pop("evaluation_authoring_approval_trust")
        with self.assertRaisesRegex(TypeError, "evaluation_authoring_approval_trust"):
            validate_model_promotion(
                created.path,
                **validation_arguments,
                **missing_authoring_trust,
            )

        trust = self.source_arguments["review_receipt_trust"]
        wrong_trust = type(trust)(
            public_key_path=trust.public_key_path,
            public_key_spki_sha256=trust.public_key_spki_sha256,
            audience="wrong-promotion-audience",
            key_id=trust.key_id,
            signer_role=trust.signer_role,
        )
        wrong_identity = dict(self.source_arguments)
        wrong_identity["review_receipt_trust"] = wrong_trust
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            validate_model_promotion(
                created.path, **validation_arguments, **wrong_identity
            )

        authoring_trust = self.source_arguments["evaluation_authoring_approval_trust"]
        same_signer = dict(self.source_arguments)
        same_signer["evaluation_authoring_approval_trust"] = replace(
            authoring_trust,
            public_key_spki_sha256=created.envelope["publicKeySpkiSha256"],
        )
        with self.assertRaisesRegex(
            ValidationError,
            "must differ from the evaluation-authoring approval signer",
        ):
            validate_model_promotion(
                created.path,
                **validation_arguments,
                **same_signer,
            )

        expired_receipt = dict(self.source_arguments)
        expired_receipt["review_receipt_now"] = datetime.fromisoformat(
            _PROMOTION_RECEIPT_EXPIRES.replace("Z", "+00:00")
        )
        with self.assertRaisesRegex(ValidationError, "not currently active"):
            validate_model_promotion(
                created.path, **validation_arguments, **expired_receipt
            )

    def test_envelope_rejects_resigned_content_hash_with_stale_or_high_s_signature(
        self,
    ) -> None:
        created = self._create()
        envelope = json.loads(created.path.read_text(encoding="utf-8"))
        payload = json.loads(_decode_base64url(envelope["payload"]))
        payload["approval"]["reference"] = "VQ-2026-0727-tampered"
        payload["promotionId"] = model_promotion_id(payload)
        payload_bytes = canonical_json_bytes(payload)
        envelope["payload"] = _encode_base64url(payload_bytes)
        envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        tampered_path = self.root / "tampered-promotion.json"
        tampered_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "signature"):
            verify_model_promotion_envelope(
                tampered_path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                now=_NOW,
            )

        envelope = json.loads(created.path.read_text(encoding="utf-8"))
        envelope["payload"] = _encode_base64url(b"{")
        envelope["payloadSha256"] = hashlib.sha256(b"{").hexdigest()
        malformed_path = self.root / "malformed-untrusted-payload.json"
        malformed_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "signature"):
            verify_model_promotion_envelope(
                malformed_path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                now=_NOW,
            )

        envelope = json.loads(created.path.read_text(encoding="utf-8"))
        signature = _decode_base64url(envelope["signature"])
        low_s = int.from_bytes(signature[32:], "big")
        envelope["signature"] = _encode_base64url(
            signature[:32] + (_P256_ORDER - low_s).to_bytes(32, "big")
        )
        high_s_path = self.root / "high-s-promotion.json"
        high_s_path.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "low-S"):
            verify_model_promotion_envelope(
                high_s_path,
                public_key_path=self.public_key_path,
                expected_audience=self.identity_arguments["audience"],
                expected_key_id=self.identity_arguments["key_id"],
                expected_signer_role=self.identity_arguments["signer_role"],
                now=_NOW,
            )

    def test_intrinsically_valid_forged_report_is_rejected_by_reaggregation(
        self,
    ) -> None:
        forged = copy.deepcopy(self.report)
        forged["candidate"]["responseSetSha256"] = "f" * 64
        forged["reportSha256"] = promotion_evidence_sha256(forged)
        forged_path = self.root / "forged-evidence.json"
        forged_path.write_text(json.dumps(forged), encoding="utf-8")
        self.assertEqual(forged, validate_promotion_evidence(forged_path))

        arguments = dict(self.source_arguments)
        arguments["promotion_evidence_path"] = forged_path
        with self.assertRaisesRegex(ValidationError, "regenerated"):
            create_model_promotion(
                output_path=self.root / "forged-promotion.json",
                private_key_path=self.private_key_path,
                public_key_path=self.public_key_path,
                private_key_password=None,
                **self.identity_arguments,
                approval_id="approval-vq-2026-0727",
                actor_id="reviewer-17",
                actor_role=self.identity_arguments["signer_role"],
                approval_reference="VQ-2026-0727",
                approved_at_utc="2026-07-27T09:00:00Z",
                issued_at_utc="2026-07-27T10:00:00Z",
                not_before_utc="2026-07-27T10:00:00Z",
                expires_at_utc="2026-08-27T10:00:00Z",
                now=_NOW,
                **arguments,
            )

    def test_raw_base_v2_candidate_cannot_become_the_served_model(self) -> None:
        forged = copy.deepcopy(self.report)
        identity = forged["candidate"]["identity"]
        identity["responseSchemaVersion"] = EVALUATION_RESPONSE_V2_SCHEMA_VERSION
        identity["targetKind"] = "raw-base"
        identity["executionModelId"] = (
            "daxalgo-base-sha256-" + identity["servingProfile"]["sha256"]
        )
        forged["reportSha256"] = promotion_evidence_sha256(forged)
        forged_path = self.root / "raw-base-candidate-evidence.json"
        forged_path.write_bytes(canonical_json_bytes(forged) + b"\n")
        arguments = dict(self.source_arguments)
        arguments["promotion_evidence_path"] = forged_path

        with (
            mock.patch.object(
                promotion_module,
                "aggregate_promotion_evidence",
                return_value=forged,
            ),
            self.assertRaisesRegex(ValidationError, "responseSchemaVersion"),
        ):
            create_model_promotion(
                output_path=self.root / "raw-base-candidate-promotion.json",
                private_key_path=self.private_key_path,
                public_key_path=self.public_key_path,
                private_key_password=None,
                **self.identity_arguments,
                approval_id="approval-vq-2026-0727",
                actor_id="reviewer-17",
                actor_role=self.identity_arguments["signer_role"],
                approval_reference="VQ-2026-0727",
                approved_at_utc="2026-07-27T09:00:00Z",
                issued_at_utc="2026-07-27T10:00:00Z",
                not_before_utc="2026-07-27T10:00:00Z",
                expires_at_utc="2026-08-27T10:00:00Z",
                now=_NOW,
                **arguments,
            )

    def test_promotion_bindings_reject_source_changes_after_stable_snapshot(
        self,
    ) -> None:
        output = self.root / "raced-promotion.json"
        responses = Path(self.source_arguments["responses_path"])
        original_aggregate = promotion_module.aggregate_promotion_evidence

        def aggregate_then_mutate(**kwargs):
            report = original_aggregate(**kwargs)
            responses.write_bytes(responses.read_bytes() + b" ")
            return report

        with mock.patch.object(
            promotion_module,
            "aggregate_promotion_evidence",
            side_effect=aggregate_then_mutate,
        ):
            with self.assertRaisesRegex(ValidationError, "changed while"):
                create_model_promotion(
                    output_path=output,
                    private_key_path=self.private_key_path,
                    public_key_path=self.public_key_path,
                    private_key_password=None,
                    **self.identity_arguments,
                    approval_id="approval-vq-2026-0727",
                    actor_id="reviewer-17",
                    actor_role=self.identity_arguments["signer_role"],
                    approval_reference="VQ-2026-0727",
                    approved_at_utc="2026-07-27T09:00:00Z",
                    issued_at_utc="2026-07-27T10:00:00Z",
                    not_before_utc="2026-07-27T10:00:00Z",
                    expires_at_utc="2026-08-27T10:00:00Z",
                    now=_NOW,
                    **self.source_arguments,
                )
        self.assertFalse(output.exists())

    def test_v2_strategy_capability_round_trips_and_is_model_bound(self) -> None:
        v1 = self._create("v1-model-identity.json")
        execution_model_id = v1.payload["model"]["executionModelId"]
        policy = _hosted_policy(
            schema_version=HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION,
            execution_model_id=execution_model_id,
        )
        self.hosted_policy_path.write_bytes(canonical_json_bytes(policy) + b"\n")

        created = self._create("strategy-capability-v2.json")
        verified = validate_model_promotion(
            created.path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            now=_NOW,
            **self.source_arguments,
        )
        self.assertEqual(
            execution_model_id,
            verified.payload["hostedDeploymentPolicy"]["strategyAuthoringCapability"][
                "executionModelId"
            ],
        )
        bundle = self._prepare("v2-signing-bundle.json")
        self.assertEqual(created.payload, bundle.payload)
        signature_path = self._sign_bundle(
            bundle.path,
            name="v2-promotion-signature.json",
            mode="sha256-digest",
            signature_format="ieee-p1363-fixed-64",
        )
        finalized = self._finalize(
            bundle.path,
            signature_path,
            name="v2-detached-promotion.json",
        )
        self.assertEqual(created.payload, finalized.payload)
        readiness = create_promoted_model_readiness_attestation(
            promotion_path=finalized.path,
            public_key_path=self.public_key_path,
            expected_audience=self.identity_arguments["audience"],
            expected_promotion_key_id=self.identity_arguments["key_id"],
            expected_signer_role=self.identity_arguments["signer_role"],
            expected_deployment_id=self.identity_arguments["deployment_id"],
            expected_environment=self.identity_arguments["environment"],
            nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            readiness_key_id="prod-hmac-v1",
            readiness_key=bytes(range(32)),
            now=_NOW,
            **self.source_arguments,
        )
        validate_model_readiness_v2_attestation(
            readiness,
            key=bytes(range(32)),
            audience=self.identity_arguments["audience"],
            expected_nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            expected_key_id="prod-hmac-v1",
            serving_profile_sha256=finalized.payload["model"]["servingProfileSha256"],
            artifact_sha256=finalized.payload["model"]["artifactSha256"],
            artifact_tree_sha256=finalized.payload["model"]["artifactTreeSha256"],
            execution_model_id=finalized.payload["model"]["executionModelId"],
            promotion_envelope_sha256=finalized.envelope_sha256,
            promotion_payload_sha256=finalized.payload_sha256,
            deployment_id=finalized.payload["deployment"]["deploymentId"],
            provider_id=finalized.payload["hostedDeploymentPolicy"]["providerId"],
            hosted_deployment_policy_sha256=finalized.payload["hostedDeploymentPolicy"][
                "policySha256"
            ],
            expires_at_utc=finalized.payload["expiresAtUtc"],
        )

        policy["strategyAuthoringCapability"]["executionModelId"] = (
            "daxalgo-expert-sha256-" + "f" * 64
        )
        policy["policySha256"] = hosted_deployment_policy_sha256(policy)
        self.hosted_policy_path.write_bytes(canonical_json_bytes(policy) + b"\n")
        with self.assertRaisesRegex(
            ValidationError, "must match model.executionModelId"
        ):
            self._create("strategy-capability-model-mismatch.json")


class ModelPromotionGoldenTests(unittest.TestCase):
    def test_readiness_v2_proof_matches_platform_cross_language_vector(self) -> None:
        proof = compute_model_readiness_v2_proof(
            key=bytes(range(32)),
            audience="daxalgo-platform-prod",
            nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            key_id="prod-hmac-v1",
            serving_profile_sha256="1" * 64,
            artifact_sha256="2" * 64,
            artifact_tree_sha256="3" * 64,
            execution_model_id="daxalgo-expert-sha256-" + "1" * 64,
            promotion_envelope_sha256="4" * 64,
            promotion_payload_sha256="5" * 64,
            deployment_id="vqdpl-prod",
            provider_id="daxalgo-private",
            hosted_deployment_policy_sha256="6" * 64,
            expires_at_utc="2027-07-27T12:00:00Z",
        )
        self.assertEqual(
            "m4z9GqfCk_HT_bmiXQrMr7fUFG3uOaDXURYkKq97r0Y",
            proof,
        )
        arguments = {
            "key": bytes(range(32)),
            "audience": "daxalgo-platform-prod",
            "expected_nonce": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            "expected_key_id": "prod-hmac-v1",
            "serving_profile_sha256": "1" * 64,
            "artifact_sha256": "2" * 64,
            "artifact_tree_sha256": "3" * 64,
            "execution_model_id": "daxalgo-expert-sha256-" + "1" * 64,
            "promotion_envelope_sha256": "4" * 64,
            "promotion_payload_sha256": "5" * 64,
            "deployment_id": "vqdpl-prod",
            "provider_id": "daxalgo-private",
            "hosted_deployment_policy_sha256": "6" * 64,
            "expires_at_utc": "2027-07-27T12:00:00Z",
        }
        attestation = {
            "schemaVersion": "daxalgo.hyperion.model-readiness/v2",
            "nonce": arguments["expected_nonce"],
            "keyId": arguments["expected_key_id"],
            "proof": proof,
        }
        self.assertEqual(
            attestation,
            validate_model_readiness_v2_attestation(attestation, **arguments),
        )
        tampered = {**attestation, "proof": "A" * 43}
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            validate_model_readiness_v2_attestation(tampered, **arguments)

    def test_python_authored_envelope_is_a_stable_cross_language_fixture(self) -> None:
        fixture_root = Path(__file__).parent / "fixtures"
        verified = verify_model_promotion_envelope(
            fixture_root / "model-promotion-envelope.v1.golden.json",
            public_key_path=fixture_root / "model-promotion-public-key.v1.golden.pem",
            expected_audience="daxalgo-platform-prod",
            expected_key_id="model-promotion-golden-v1",
            expected_signer_role="production-model-approver",
            now=_NOW,
        )
        self.assertEqual(
            "vqprom-b9adeced7080ba6e942d47d79ce76d6cdac5fa351d09c205afc3726e86effa66",
            verified.payload["promotionId"],
        )
        self.assertEqual(
            "a59717b1c319c2c3b89e28fc7244d2c6c817c400de8272b68212b940fb4d6c36",
            verified.payload_sha256,
        )
        self.assertEqual(
            "fc1b22b9a0f9c3cb3734118b8d97594d475ce240356151954b2fcc1190d222ec",
            verified.envelope_sha256,
        )
        self.assertEqual(
            "192cedb03e29200df0eaafd8136cfe0f6cfbf769f4c09db02dae843ebc59a20b",
            verified.payload["hostedDeploymentPolicy"]["policySha256"],
        )

    def test_python_authored_strategy_v2_envelope_is_a_stable_fixture(self) -> None:
        fixture_root = Path(__file__).parent / "fixtures"
        verified = verify_model_promotion_envelope(
            fixture_root
            / "model-promotion-envelope.v1.strategy-authoring-v2.golden.json",
            public_key_path=(
                fixture_root
                / "model-promotion-public-key.v1.strategy-authoring-v2.golden.pem"
            ),
            expected_audience="daxalgo-platform-prod",
            expected_key_id="model-promotion-strategy-v2-golden",
            expected_signer_role="production-model-approver",
            now=_NOW,
        )
        self.assertEqual(
            "vqprom-67606853f5bdba6f295e4e3cbbcc2a17804c9e7b92f0444f24cc445a705369da",
            verified.payload["promotionId"],
        )
        self.assertEqual(
            "f5e8b8aa7a32c65a2c634f0d686d546a5c7688a55f4ad6581f2deac63e47cebd",
            verified.payload_sha256,
        )
        self.assertEqual(
            "5d01f4a8d34fb6f843545f07fa5b4467936dce2eb3caea4ec53402048b06aa80",
            verified.envelope_sha256,
        )
        self.assertEqual(
            "9fdac22db0aa96062b6c328c4be7a2a95c13dfad2876ba21bccf1cc96a120ee8",
            verified.payload["hostedDeploymentPolicy"]["policySha256"],
        )
        self.assertEqual(
            verified.payload["model"]["executionModelId"],
            verified.payload["hostedDeploymentPolicy"]["strategyAuthoringCapability"][
                "executionModelId"
            ],
        )


if __name__ == "__main__":
    unittest.main()
