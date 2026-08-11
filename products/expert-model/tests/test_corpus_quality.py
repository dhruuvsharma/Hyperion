from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import os
import tempfile
import unittest
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

import hyperion_model.corpus_quality as quality_module
import hyperion_model.cli as cli_module
from hyperion_model.core import (
    DOMAINS,
    ORIGINS,
    TASK_KINDS,
    ValidationError,
    canonical_json_bytes,
    expert_conversation_sha256,
)
from hyperion_model.corpus_quality import (
    CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION,
    CORPUS_ADMISSION_SCHEMA_VERSION,
    CORPUS_QUALITY_POLICY_SCHEMA_VERSION,
    CORPUS_QUALITY_REPORT_SCHEMA_VERSION,
    TrainingCorpusAdmissionTrust,
    create_training_corpus_admission,
    create_training_corpus_admission_bytes,
    derive_training_corpus_quality_report,
    derive_training_corpus_quality_report_bytes,
    finalize_training_corpus_admission,
    finalize_training_corpus_admission_bytes,
    prepare_training_corpus_admission_signing_bundle,
    prepare_training_corpus_admission_signing_bundle_bytes,
    training_corpus_admission_id,
    training_corpus_admission_signature_id,
    training_corpus_admission_signing_bundle_id,
    training_corpus_quality_policy_sha256,
    training_corpus_quality_policy_violations,
    verify_training_corpus_admission,
    verify_training_corpus_admission_bytes,
    verify_training_corpus_admission_file,
)


REVIEWED = "2026-07-29T10:00:00Z"
ISSUED = "2026-07-29T10:00:01Z"
NOT_BEFORE = "2026-07-29T10:00:02Z"
EXPIRES = "2027-07-29T10:00:02Z"
NOW = datetime(2026, 8, 1, tzinfo=timezone.utc)
AUDIENCE = "released-training-corpus-admission-v1"
KEY_ID = "corpus-quality-review-key-2026-07"
SIGNER_ROLE = "independent-corpus-quality-reviewer"
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
RELEASE_SHA256 = "a" * 64
DATA_RELEASE = {
    "releaseId": f"vqrel-{RELEASE_SHA256}",
    "releaseSha256": RELEASE_SHA256,
    "manifestSha256": "b" * 64,
}


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _row(
    example_id: str,
    task_kind: str,
    domains: list[str],
    *,
    producer: str,
    group: str | None = None,
) -> dict:
    messages = [
        {"role": "system", "content": "Answer as a bounded unit-test expert."},
        {"role": "user", "content": f"Unique prompt for {example_id}."},
        {"role": "assistant", "content": f"Unique answer for {example_id}."},
    ]
    return {
        "messages": messages,
        "metadata": {
            "id": example_id,
            "taskKind": task_kind,
            "domains": domains,
            "conversationSha256": expert_conversation_sha256(messages),
            "origin": "HumanAuthored",
            "producer": producer,
            "modelId": None,
            "modelRevision": None,
            "promptSha256": None,
            "profileVersion": None,
            "split": "development",
            "contaminationGroup": group or f"group-{example_id}",
            "cutoffUtc": "2026-07-01T00:00:00Z",
            "sourceSchema": "expert-model-dataset/v1",
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))


def _fraction(value: dict[str, int]) -> tuple[int, int]:
    return value["numerator"], value["denominator"]


class TrainingCorpusQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.dataset = self.root / "dataset.sft.jsonl"
        self.rows = [
            _row(
                "code-generation",
                "CodeGeneration",
                ["CSharp", "DaxAlgoArchitecture"],
                producer="reviewer-a",
            ),
            _row(
                "code-repair",
                "CodeRepair",
                ["CSharp"],
                producer="reviewer-b",
            ),
            _row(
                "risk-analysis",
                "RiskAnalysis",
                ["RiskManagement", "FinanceMarkets", "PortfolioManagement"],
                producer="reviewer-a",
            ),
            _row(
                "quant-reasoning",
                "QuantitativeReasoning",
                ["QuantitativeMath", "ProbabilityStatistics"],
                producer="reviewer-b",
            ),
            _row(
                "wpf-design",
                "WpfUiDesign",
                ["WpfUiDesign"],
                producer="reviewer-a",
            ),
        ]
        _write_jsonl(self.dataset, self.rows)
        self.report = derive_training_corpus_quality_report(self.dataset)
        self.policy = self._policy_for(self.report)
        self.private_key_object, self.private_key, self.public_key, spki = (
            self._write_key_pair("corpus-review")
        )
        self.trust = TrainingCorpusAdmissionTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256=spki,
            audience=AUDIENCE,
            key_id=KEY_ID,
            signer_role=SIGNER_ROLE,
            quality_policy_sha256=training_corpus_quality_policy_sha256(self.policy),
        )

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

    def _policy_for(self, report: dict) -> dict:
        return {
            "schemaVersion": CORPUS_QUALITY_POLICY_SCHEMA_VERSION,
            "policyVersion": "unit-test-review.v1",
            "minimumRecordCount": report["dataset"]["recordCount"],
            "minimumTaskCounts": copy.deepcopy(report["taskCounts"]),
            "minimumDomainWeightedCounts": [
                {
                    "domain": item["domain"],
                    "weightedCount": copy.deepcopy(item["weightedCount"]),
                }
                for item in report["domainCounts"]
            ],
            "minimumDomainTaskWeightedCounts": [
                {
                    "domain": item["domain"],
                    "taskKind": item["taskKind"],
                    "weightedCount": copy.deepcopy(item["weightedCount"]),
                }
                for item in report["domainTaskCounts"]
                if item["weightedCount"]["numerator"] > 0
            ],
            "minimumDistinctContaminationGroupsByDomain": [
                {
                    "domain": item["domain"],
                    "distinctCount": item["distinctCount"],
                }
                for item in report["domainContaminationGroups"]
            ],
            "minimumDistinctContaminationGroups": report["distinctCounts"][
                "contaminationGroups"
            ],
            "minimumDistinctOrigins": report["distinctCounts"]["origins"],
            "minimumDistinctProducers": report["distinctCounts"]["producers"],
            "maximumDomainsPerRecord": report["concentration"][
                "maximumDomainsPerRecord"
            ],
            "maximumShares": {
                name: copy.deepcopy(report["concentration"][name]["share"])
                for name in (
                    "task",
                    "domainWeighted",
                    "domainTaskWeighted",
                    "contaminationGroup",
                    "origin",
                    "producer",
                )
            },
        }

    def _create(self, **overrides):
        values = {
            "dataset_path": self.dataset,
            "data_release": DATA_RELEASE,
            "quality_policy": self.policy,
            "private_key_path": self.private_key,
            "private_key_password": None,
            "trust": self.trust,
            "reviewer_id": "corpus-reviewer-01",
            "reviewed_at_utc": REVIEWED,
            "issued_at_utc": ISSUED,
            "not_before_utc": NOT_BEFORE,
            "expires_at_utc": EXPIRES,
            "now": NOW,
        }
        values.update(overrides)
        return create_training_corpus_admission(**values)

    def _verify(self, envelope: dict, **overrides):
        values = {
            "dataset_path": self.dataset,
            "expected_data_release": DATA_RELEASE,
            "trust": self.trust,
            "now": NOW,
        }
        values.update(overrides)
        return verify_training_corpus_admission(envelope, **values)

    def _prepare_detached(
        self,
        name: str,
        *,
        signature_format: str = "asn1-der",
        force_high_s: bool = False,
        signing_key=None,
        signing_mode: str = "digest",
        use_bytes: bool = False,
    ) -> tuple[Path, dict, Path, dict]:
        bundle_path = self.root / f"{name}.bundle.json"
        signature_path = self.root / f"{name}.signature.json"
        values = {
            "data_release": DATA_RELEASE,
            "quality_policy": self.policy,
            "trust": self.trust,
            "reviewer_id": "corpus-reviewer-01",
            "reviewed_at_utc": REVIEWED,
            "issued_at_utc": ISSUED,
            "not_before_utc": NOT_BEFORE,
            "expires_at_utc": EXPIRES,
            "output_path": bundle_path,
            "now": NOW,
        }
        if use_bytes:
            prepare_training_corpus_admission_signing_bundle_bytes(
                dataset_bytes=self.dataset.read_bytes(),
                dataset_source_path=self.dataset,
                **values,
            )
        else:
            prepare_training_corpus_admission_signing_bundle(
                dataset_path=self.dataset,
                **values,
            )

        bundle_bytes = bundle_path.read_bytes()
        bundle = json.loads(bundle_bytes)
        key = signing_key or self.private_key_object
        digest = _decode(bundle["request"]["signatureInput"])
        if signing_mode == "digest":
            der = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif signing_mode == "raw-preimage":
            der = key.sign(
                _decode(bundle["request"]["signaturePreimage"]),
                ec.ECDSA(hashes.SHA256()),
            )
        elif signing_mode == "double-hashed-digest":
            der = key.sign(digest, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported detached signing mode")
        r, s = decode_dss_signature(der)
        if force_high_s and s <= P256_ORDER // 2:
            s = P256_ORDER - s
        if signature_format == "asn1-der":
            external_signature = encode_dss_signature(r, s)
        elif signature_format == "ieee-p1363-fixed-64":
            external_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - test helper contract
            raise AssertionError("unsupported detached signature format")
        signature = quality_module._build_external_signature_document(
            bundle,
            bundle_bytes,
            signature_format=signature_format,
            signature=external_signature,
        )
        signature_path.write_bytes(canonical_json_bytes(signature) + b"\n")
        return bundle_path, bundle, signature_path, signature

    def _finalize_detached(
        self,
        bundle_path: Path,
        signature_path: Path,
        output_name: str,
        *,
        use_bytes: bool = False,
        **overrides,
    ):
        values = {
            "signing_bundle_path": bundle_path,
            "signature_path": signature_path,
            "output_path": self.root / output_name,
            "data_release": DATA_RELEASE,
            "quality_policy": self.policy,
            "trust": self.trust,
            "now": NOW,
        }
        values.update(overrides)
        if use_bytes:
            return finalize_training_corpus_admission_bytes(
                dataset_bytes=self.dataset.read_bytes(),
                dataset_source_path=self.dataset,
                **values,
            )
        return finalize_training_corpus_admission(
            dataset_path=self.dataset,
            **values,
        )

    def _resign(self, envelope: dict, payload: dict) -> dict:
        payload["corpusAdmissionId"] = training_corpus_admission_id(payload)
        payload_bytes = canonical_json_bytes(payload)
        resigned = dict(envelope)
        resigned["payload"] = _encode(payload_bytes)
        resigned["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        resigned["signature"] = _encode(
            quality_module._sign_p1363_low_s(
                self.private_key_object,
                quality_module._signature_input(resigned, payload_bytes),
            )
        )
        return resigned

    def test_fractional_metrics_resist_multi_label_inflation(self) -> None:
        domains = {item["domain"]: item for item in self.report["domainCounts"]}
        self.assertEqual((3, 2), _fraction(domains["CSharp"]["weightedCount"]))
        self.assertEqual(
            (1, 2), _fraction(domains["DaxAlgoArchitecture"]["weightedCount"])
        )
        self.assertEqual((1, 3), _fraction(domains["RiskManagement"]["weightedCount"]))
        weighted_total = sum(
            item["weightedCount"]["numerator"] / item["weightedCount"]["denominator"]
            for item in self.report["domainCounts"]
        )
        self.assertEqual(5, weighted_total)

        stuffed = self.root / "all-domains.sft.jsonl"
        _write_jsonl(
            stuffed,
            [_row("all-domains", "CodeGeneration", list(DOMAINS), producer="one")],
        )
        stuffed_report = derive_training_corpus_quality_report(stuffed)
        self.assertEqual(
            {(1, 8)},
            {
                _fraction(item["weightedCount"])
                for item in stuffed_report["domainCounts"]
            },
        )
        self.assertEqual(8, stuffed_report["concentration"]["maximumDomainsPerRecord"])

    def test_report_covers_all_exact_count_and_concentration_dimensions(self) -> None:
        self.assertEqual(
            CORPUS_QUALITY_REPORT_SCHEMA_VERSION, self.report["schemaVersion"]
        )
        self.assertEqual(
            sorted(TASK_KINDS), [item["taskKind"] for item in self.report["taskCounts"]]
        )
        self.assertEqual(
            sorted(DOMAINS), [item["domain"] for item in self.report["domainCounts"]]
        )
        self.assertEqual(
            len(DOMAINS) * len(TASK_KINDS), len(self.report["domainTaskCounts"])
        )
        self.assertEqual(5, len(self.report["contaminationGroupCounts"]))
        self.assertEqual(
            [{"origin": "HumanAuthored", "recordCount": 5}], self.report["originCounts"]
        )
        self.assertEqual(2, len(self.report["producerCounts"]))
        self.assertEqual(
            [
                "CSharp",
                "DaxAlgoArchitecture",
                "FinanceMarkets",
                "PortfolioManagement",
                "ProbabilityStatistics",
                "QuantitativeMath",
                "RiskManagement",
                "WpfUiDesign",
            ],
            [item["domain"] for item in self.report["domainContaminationGroups"]],
        )
        csharp_groups = next(
            item
            for item in self.report["domainContaminationGroups"]
            if item["domain"] == "CSharp"
        )
        self.assertEqual(2, csharp_groups["distinctCount"])
        self.assertEqual(
            (2, 3), _fraction(csharp_groups["maximumGroup"]["weightedShare"])
        )
        self.assertEqual(
            (3, 5), _fraction(self.report["concentration"]["producer"]["share"])
        )
        self.assertEqual(
            (1, 5),
            _fraction(self.report["concentration"]["contaminationGroup"]["share"]),
        )
        self.assertEqual(
            (), training_corpus_quality_policy_violations(self.report, self.policy)
        )

    def test_create_and_verify_exact_released_dataset_admission(self) -> None:
        created = self._create()
        verified = self._verify(
            created.envelope,
            expected_envelope_sha256=created.envelope_sha256,
        )
        self.assertEqual(created.payload, verified.payload)
        self.assertEqual(
            CORPUS_ADMISSION_SCHEMA_VERSION, verified.payload["schemaVersion"]
        )
        self.assertEqual(
            CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION,
            verified.envelope["schemaVersion"],
        )
        self.assertEqual(DATA_RELEASE, verified.payload["dataRelease"])
        self.assertEqual(self.report, verified.payload["qualityReport"])
        self.assertIs(verified.payload["corpusAdmissionAuthorized"], True)
        self.assertIs(verified.payload["reusable"], True)
        for name in (
            "rightsAuthorized",
            "reviewReceiptAuthorized",
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
            self.assertIs(verified.payload[name], False)
        signature = _decode(verified.envelope["signature"])
        self.assertEqual(64, len(signature))
        self.assertLessEqual(int.from_bytes(signature[32:], "big"), P256_ORDER // 2)

    def test_captured_bytes_and_atomic_file_publication_replay(self) -> None:
        captured = self.dataset.read_bytes()
        self.assertEqual(
            self.report,
            derive_training_corpus_quality_report_bytes(captured),
        )
        output = self.root / "corpus-admission.json"
        created = self._create(output_path=output)
        self.assertTrue(output.is_file())
        self.assertEqual(
            canonical_json_bytes(created.envelope) + b"\n", output.read_bytes()
        )
        replayed = verify_training_corpus_admission_file(
            output,
            dataset_bytes=captured,
            expected_data_release=DATA_RELEASE,
            trust=self.trust,
            expected_envelope_sha256=created.envelope_sha256,
            now=NOW,
        )
        self.assertEqual(created.payload, replayed.payload)
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._create(output_path=output)

        self.dataset.write_bytes(b"tampered after capture")
        captured_created = create_training_corpus_admission_bytes(
            dataset_bytes=captured,
            data_release=DATA_RELEASE,
            quality_policy=self.policy,
            private_key_path=self.private_key,
            private_key_password=None,
            trust=self.trust,
            reviewer_id="corpus-reviewer-01",
            reviewed_at_utc=REVIEWED,
            issued_at_utc=ISSUED,
            not_before_utc=NOT_BEFORE,
            expires_at_utc=EXPIRES,
            now=NOW,
        )
        self.assertEqual(created.payload, captured_created.payload)
        verified_snapshot = verify_training_corpus_admission_bytes(
            created.envelope,
            dataset_bytes=captured,
            expected_data_release=DATA_RELEASE,
            trust=self.trust,
            now=NOW,
        )
        self.assertEqual(created.payload, verified_snapshot.payload)

    def test_detached_der_and_p1363_high_s_preserve_exact_envelope_wire(self) -> None:
        direct = self._create()
        direct_unsigned = {
            name: value
            for name, value in direct.envelope.items()
            if name != "signature"
        }
        for label, signature_format, use_bytes in (
            ("der", "asn1-der", False),
            ("p1363", "ieee-p1363-fixed-64", True),
        ):
            with self.subTest(signature_format=signature_format):
                with (
                    mock.patch.object(quality_module, "_load_private_key") as load_key,
                    mock.patch.object(quality_module, "_sign_p1363_low_s") as sign,
                ):
                    bundle_path, bundle, signature_path, external = (
                        self._prepare_detached(
                            label,
                            signature_format=signature_format,
                            force_high_s=True,
                            use_bytes=use_bytes,
                        )
                    )
                    finalized = self._finalize_detached(
                        bundle_path,
                        signature_path,
                        f"{label}.admission.json",
                        use_bytes=use_bytes,
                    )
                load_key.assert_not_called()
                sign.assert_not_called()

                self.assertEqual(
                    training_corpus_admission_signing_bundle_id(bundle),
                    bundle["bundleId"],
                )
                self.assertEqual("unsigned-non-authorizing", bundle["status"])
                self.assertTrue(
                    all(value is False for value in bundle["authority"].values())
                )
                self.assertEqual(
                    training_corpus_admission_signature_id(external),
                    external["signatureId"],
                )
                preimage = _decode(bundle["request"]["signaturePreimage"])
                digest = _decode(bundle["request"]["signatureInput"])
                self.assertEqual(hashlib.sha256(preimage).digest(), digest)
                self.assertEqual(
                    digest.hex(), bundle["request"]["signatureInputSha256"]
                )

                external_signature = _decode(external["signature"])
                if signature_format == "asn1-der":
                    _, external_s = decode_dss_signature(external_signature)
                else:
                    external_s = int.from_bytes(external_signature[32:], "big")
                self.assertGreater(external_s, P256_ORDER // 2)
                output_signature = _decode(finalized.envelope["signature"])
                self.assertEqual(64, len(output_signature))
                self.assertLessEqual(
                    int.from_bytes(output_signature[32:], "big"),
                    P256_ORDER // 2,
                )
                self.assertEqual(
                    direct_unsigned,
                    {
                        name: value
                        for name, value in finalized.envelope.items()
                        if name != "signature"
                    },
                )
                replayed = self._verify(finalized.envelope)
                self.assertEqual(finalized.payload, replayed.payload)

    def test_detached_raw_preimage_succeeds_and_double_hashing_fails(self) -> None:
        raw_bundle, _, raw_signature, _ = self._prepare_detached(
            "raw-preimage",
            signing_mode="raw-preimage",
        )
        finalized = self._finalize_detached(
            raw_bundle,
            raw_signature,
            "raw-preimage.admission.json",
        )
        self.assertEqual(
            CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION,
            finalized.envelope["schemaVersion"],
        )

        bad_bundle, _, bad_signature, _ = self._prepare_detached(
            "double-hashed-digest",
            signing_mode="double-hashed-digest",
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                bad_bundle,
                bad_signature,
                "double-hashed-digest.admission.json",
            )

    def test_detached_schemas_are_closed_and_validate_live_instances(self) -> None:
        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        bundle_schema = json.loads(
            (
                schema_root / "training-corpus-admission-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_schema = json.loads(
            (
                schema_root / "training-corpus-admission-signature.v1.schema.json"
            ).read_bytes()
        )
        for schema in (bundle_schema, signature_schema):
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertTrue(
            all(
                definition["const"] is False
                for definition in bundle_schema["properties"]["authority"][
                    "properties"
                ].values()
            )
        )
        _, bundle, _, signature = self._prepare_detached("schema")
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(signature)

    def test_detached_bundle_and_signature_bind_every_authority_input(self) -> None:
        bundle_path, bundle, signature_path, signature = self._prepare_detached(
            "binding"
        )

        def change_payload(value: dict) -> None:
            value["request"]["payload"] = _encode(canonical_json_bytes({}))

        bundle_mutations = (
            ("authority", lambda value: value["authority"].update(training=True)),
            ("trust", lambda value: value["trust"].update(keyId="wrong-key")),
            (
                "release",
                lambda value: value["dataRelease"].update(manifestSha256="0" * 64),
            ),
            (
                "corpus-id",
                lambda value: value.update(
                    corpusAdmissionId="vqcorpusadmit-" + "0" * 64
                ),
            ),
            ("dataset", lambda value: value.update(datasetSha256="0" * 64)),
            ("report", lambda value: value.update(qualityReportSha256="0" * 64)),
            ("policy", lambda value: value.update(qualityPolicySha256="0" * 64)),
            ("payload", change_payload),
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
            with self.subTest(bundle=label):
                changed = copy.deepcopy(bundle)
                mutate(changed)
                changed["bundleId"] = training_corpus_admission_signing_bundle_id(
                    changed
                )
                changed_path = self.root / f"binding-{label}.bundle.json"
                changed_path.write_bytes(canonical_json_bytes(changed) + b"\n")
                with self.assertRaises(ValidationError):
                    self._finalize_detached(
                        changed_path,
                        signature_path,
                        f"binding-{label}.admission.json",
                    )

        bad_bundle_id = copy.deepcopy(bundle)
        bad_bundle_id["bundleId"] = "vqcorpusadmissionsigning-" + "0" * 64
        bad_bundle_path = self.root / "binding-bad-id.bundle.json"
        bad_bundle_path.write_bytes(canonical_json_bytes(bad_bundle_id) + b"\n")
        with self.assertRaisesRegex(ValidationError, "content-derived identity"):
            self._finalize_detached(
                bad_bundle_path,
                signature_path,
                "binding-bad-id.admission.json",
            )

        signature_bindings = (
            ("signingBundleId", "vqcorpusadmissionsigning-" + "0" * 64),
            ("signingBundleSha256", "0" * 64),
            ("corpusAdmissionId", "vqcorpusadmit-" + "0" * 64),
            ("datasetSha256", "0" * 64),
            ("qualityReportSha256", "0" * 64),
            ("qualityPolicySha256", "0" * 64),
            ("payloadSha256", "0" * 64),
            ("signatureInputSha256", "0" * 64),
            ("publicKeySpkiSha256", "0" * 64),
        )
        for field, replacement in signature_bindings:
            with self.subTest(signature=field):
                changed = copy.deepcopy(signature)
                changed[field] = replacement
                changed["signatureId"] = training_corpus_admission_signature_id(changed)
                changed_path = self.root / f"binding-{field}.signature.json"
                changed_path.write_bytes(canonical_json_bytes(changed) + b"\n")
                with self.assertRaisesRegex(ValidationError, "exact signing bundle"):
                    self._finalize_detached(
                        bundle_path,
                        changed_path,
                        f"binding-{field}.admission.json",
                    )

        bad_signature_id = copy.deepcopy(signature)
        bad_signature_id["signatureId"] = "vqcorpusadmissionsignature-" + "0" * 64
        bad_signature_id_path = self.root / "binding-bad-id.signature.json"
        bad_signature_id_path.write_bytes(
            canonical_json_bytes(bad_signature_id) + b"\n"
        )
        with self.assertRaisesRegex(ValidationError, "content-derived identity"):
            self._finalize_detached(
                bundle_path,
                bad_signature_id_path,
                "binding-bad-signature-id.admission.json",
            )

    def test_detached_malformed_and_wrong_signatures_fail_closed(self) -> None:
        bundle_path, _, signature_path, signature = self._prepare_detached("malformed")
        malformed: list[tuple[str, dict]] = []

        malformed_der = copy.deepcopy(signature)
        malformed_der["signature"] = _encode(b"\x30\x00")
        malformed_der["signatureId"] = training_corpus_admission_signature_id(
            malformed_der
        )
        malformed.append(("der", malformed_der))

        zero_p1363 = copy.deepcopy(signature)
        zero_p1363["format"] = "ieee-p1363-fixed-64"
        zero_p1363["signature"] = _encode(b"\x00" * 64)
        zero_p1363["signatureId"] = training_corpus_admission_signature_id(zero_p1363)
        malformed.append(("zero-p1363", zero_p1363))

        out_of_range = copy.deepcopy(signature)
        out_of_range["format"] = "ieee-p1363-fixed-64"
        out_of_range["signature"] = _encode(
            P256_ORDER.to_bytes(32, "big") + (1).to_bytes(32, "big")
        )
        out_of_range["signatureId"] = training_corpus_admission_signature_id(
            out_of_range
        )
        malformed.append(("out-of-range-p1363", out_of_range))

        bad_format = copy.deepcopy(signature)
        bad_format["format"] = "raw"
        bad_format["signatureId"] = training_corpus_admission_signature_id(bad_format)
        malformed.append(("format", bad_format))

        for label, document in malformed:
            with self.subTest(label=label):
                path = self.root / f"malformed-{label}.signature.json"
                path.write_bytes(canonical_json_bytes(document) + b"\n")
                with self.assertRaises(ValidationError):
                    self._finalize_detached(
                        bundle_path,
                        path,
                        f"malformed-{label}.admission.json",
                    )

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_bundle, _, wrong_signature, _ = self._prepare_detached(
            "wrong-key",
            signing_key=wrong_key,
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                wrong_bundle,
                wrong_signature,
                "wrong-key.admission.json",
            )
        self.assertTrue(signature_path.is_file())

    def test_detached_live_inputs_expiry_and_no_clobber_fail_closed(self) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached("live-inputs")

        original_dataset = self.dataset.read_bytes()
        mutated = copy.deepcopy(self.rows)
        mutated[0]["metadata"]["producer"] = "changed-producer"
        _write_jsonl(self.dataset, mutated)
        try:
            with self.assertRaises(ValidationError):
                self._finalize_detached(
                    bundle_path,
                    signature_path,
                    "drifted-corpus.admission.json",
                )
        finally:
            self.dataset.write_bytes(original_dataset)

        changed_release_sha = "d" * 64
        changed_release = {
            "releaseId": f"vqrel-{changed_release_sha}",
            "releaseSha256": changed_release_sha,
            "manifestSha256": "e" * 64,
        }
        with self.assertRaises(ValidationError):
            self._finalize_detached(
                bundle_path,
                signature_path,
                "drifted-release.admission.json",
                data_release=changed_release,
            )

        changed_policy = copy.deepcopy(self.policy)
        changed_policy["minimumRecordCount"] -= 1
        with self.assertRaises(ValidationError):
            self._finalize_detached(
                bundle_path,
                signature_path,
                "drifted-policy.admission.json",
                quality_policy=changed_policy,
            )

        expired = datetime(2027, 7, 29, 10, 0, 2, tzinfo=timezone.utc)
        expired_output = self.root / "expired.admission.json"
        with self.assertRaisesRegex(ValidationError, "not active"):
            self._finalize_detached(
                bundle_path,
                signature_path,
                expired_output.name,
                now=expired,
            )
        self.assertFalse(expired_output.exists())

        occupied = self.root / "occupied.admission.json"
        occupied.write_bytes(b"existing owner\n")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._finalize_detached(
                bundle_path,
                signature_path,
                occupied.name,
            )
        self.assertEqual(b"existing owner\n", occupied.read_bytes())

        expired_bundle = self.root / "expired.bundle.json"
        with self.assertRaisesRegex(ValidationError, "not active"):
            prepare_training_corpus_admission_signing_bundle(
                dataset_path=self.dataset,
                data_release=DATA_RELEASE,
                quality_policy=self.policy,
                trust=self.trust,
                reviewer_id="corpus-reviewer-01",
                reviewed_at_utc=REVIEWED,
                issued_at_utc=ISSUED,
                not_before_utc=NOT_BEFORE,
                expires_at_utc=EXPIRES,
                output_path=expired_bundle,
                now=expired,
            )
        self.assertFalse(expired_bundle.exists())

        occupied_bundle = self.root / "occupied.bundle.json"
        occupied_bundle.write_bytes(b"existing owner\n")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            prepare_training_corpus_admission_signing_bundle(
                dataset_path=self.dataset,
                data_release=DATA_RELEASE,
                quality_policy=self.policy,
                trust=self.trust,
                reviewer_id="corpus-reviewer-01",
                reviewed_at_utc=REVIEWED,
                issued_at_utc=ISSUED,
                not_before_utc=NOT_BEFORE,
                expires_at_utc=EXPIRES,
                output_path=occupied_bundle,
                now=NOW,
            )
        self.assertEqual(b"existing owner\n", occupied_bundle.read_bytes())

    def test_failed_publication_validation_preserves_raced_replacement(self) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached("publication")
        original_load = quality_module._load_corpus_admission_envelope

        failed_output = self.root / "failed-final-validation.admission.json"

        def fail_installed_validation(path: Path):
            if path.name.endswith(".staging"):
                return original_load(path)
            raise ValidationError("forced final validation failure")

        with mock.patch.object(
            quality_module,
            "_load_corpus_admission_envelope",
            side_effect=fail_installed_validation,
        ):
            with self.assertRaisesRegex(ValidationError, "forced final"):
                self._finalize_detached(
                    bundle_path,
                    signature_path,
                    failed_output.name,
                )
        self.assertFalse(failed_output.exists())

        raced_output = self.root / "raced-final-validation.admission.json"
        replacement = b"concurrent replacement owner\n"

        def replace_then_fail(path: Path):
            if path.name.endswith(".staging"):
                return original_load(path)
            path.unlink()
            path.write_bytes(replacement)
            raise ValidationError("forced raced final validation failure")

        with mock.patch.object(
            quality_module,
            "_load_corpus_admission_envelope",
            side_effect=replace_then_fail,
        ):
            with self.assertRaisesRegex(ValidationError, "forced raced"):
                self._finalize_detached(
                    bundle_path,
                    signature_path,
                    raced_output.name,
                )
        self.assertEqual(replacement, raced_output.read_bytes())

    def test_cleanup_failure_reports_valid_residual_authority(self) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached("cleanup")
        output = self.root / "cleanup.admission.json"
        real_unlink = Path.unlink

        def fail_staging_unlink(path: Path, *args, **kwargs):
            if path.name.endswith(".staging"):
                raise OSError("simulated cleanup failure")
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", fail_staging_unlink),
            self.assertRaisesRegex(ValidationError, "residual material"),
        ):
            self._finalize_detached(bundle_path, signature_path, output.name)
        self.assertFalse(output.exists())
        residuals = list(self.root.glob(".*.staging"))
        self.assertEqual(1, len(residuals))
        residual = residuals[0]
        verified = verify_training_corpus_admission_file(
            residual,
            dataset_bytes=self.dataset.read_bytes(),
            dataset_source_path=self.dataset,
            expected_data_release=DATA_RELEASE,
            trust=self.trust,
            now=NOW,
        )
        self.assertEqual(
            CORPUS_ADMISSION_SCHEMA_VERSION, verified.payload["schemaVersion"]
        )
        real_unlink(residual)

    def test_dual_cleanup_failure_reports_every_residual_authority(self) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached("dual-cleanup")
        output = self.root / "dual-cleanup.admission.json"
        real_unlink = Path.unlink

        def fail_authority_unlink(path: Path, *args, **kwargs):
            if path == output or path.name.endswith(".staging"):
                raise OSError("simulated persistent cleanup failure")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", fail_authority_unlink):
            with self.assertRaises(ValidationError) as failure:
                self._finalize_detached(bundle_path, signature_path, output.name)

        residuals = list(self.root.glob(".*.staging"))
        self.assertEqual(1, len(residuals))
        residual = residuals[0]
        self.assertIn(str(residual), str(failure.exception))
        self.assertIn(str(output), str(failure.exception))
        for path in (residual, output):
            with self.subTest(path=path):
                verified = verify_training_corpus_admission_file(
                    path,
                    dataset_bytes=self.dataset.read_bytes(),
                    dataset_source_path=self.dataset,
                    expected_data_release=DATA_RELEASE,
                    trust=self.trust,
                    now=NOW,
                )
                self.assertEqual(
                    CORPUS_ADMISSION_SCHEMA_VERSION,
                    verified.payload["schemaVersion"],
                )
            real_unlink(path)

    def test_unknown_destination_ownership_reports_residual_authority(self) -> None:
        bundle_path, _, signature_path, _ = self._prepare_detached("ownership")
        output = self.root / "ownership-unknown.admission.json"
        original_load = quality_module._load_corpus_admission_envelope
        real_lstat = Path.lstat

        def fail_installed_validation(path: Path):
            if path.name.endswith(".staging"):
                return original_load(path)
            raise ValidationError("forced installed validation failure")

        def deny_destination_lstat(path: Path, *args, **kwargs):
            if path == output and os.path.lexists(path):
                raise PermissionError("simulated ownership lookup failure")
            return real_lstat(path, *args, **kwargs)

        with (
            mock.patch.object(
                quality_module,
                "_load_corpus_admission_envelope",
                side_effect=fail_installed_validation,
            ),
            mock.patch.object(Path, "lstat", deny_destination_lstat),
            self.assertRaisesRegex(
                ValidationError,
                "ownership could not be verified.*residual material",
            ),
        ):
            self._finalize_detached(bundle_path, signature_path, output.name)
        self.assertTrue(output.exists())
        verified = verify_training_corpus_admission_file(
            output,
            dataset_bytes=self.dataset.read_bytes(),
            dataset_source_path=self.dataset,
            expected_data_release=DATA_RELEASE,
            trust=self.trust,
            now=NOW,
        )
        self.assertEqual(
            CORPUS_ADMISSION_SCHEMA_VERSION, verified.payload["schemaVersion"]
        )
        output.unlink()

    def test_live_publication_clock_rejects_expiry_crossings(self) -> None:
        expired = datetime(2027, 7, 29, 10, 0, 3, tzinfo=timezone.utc)
        direct_output = self.root / "direct-expired-during-signing.admission.json"
        direct_times = iter((NOW, expired))
        with (
            mock.patch.object(
                quality_module,
                "_fresh_validation_time",
                side_effect=direct_times,
            ),
            self.assertRaisesRegex(ValidationError, "not active"),
        ):
            self._create(output_path=direct_output)
        self.assertFalse(direct_output.exists())

        bundle_path, _, signature_path, _ = self._prepare_detached("expiry-crossing")
        detached_output = self.root / "detached-expired-during-publication.json"
        detached_times = iter((NOW, NOW, expired))
        with (
            mock.patch.object(
                quality_module,
                "_fresh_validation_time",
                side_effect=detached_times,
            ),
            self.assertRaisesRegex(ValidationError, "not active"),
        ):
            self._finalize_detached(
                bundle_path,
                signature_path,
                detached_output.name,
            )
        self.assertFalse(detached_output.exists())

    def test_detached_apis_have_no_private_key_parameters(self) -> None:
        for api in (
            prepare_training_corpus_admission_signing_bundle,
            prepare_training_corpus_admission_signing_bundle_bytes,
            finalize_training_corpus_admission,
            finalize_training_corpus_admission_bytes,
        ):
            with self.subTest(api=api.__name__):
                parameters = inspect.signature(api).parameters
                self.assertNotIn("private_key_path", parameters)
                self.assertNotIn("private_key_password", parameters)

    def test_detached_cli_routes_have_no_private_key_options(self) -> None:
        parser = cli_module._parser()
        commands = next(
            action.choices
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
            and "finalize-training-corpus-admission" in action.choices
        )
        for command in (
            "prepare-training-corpus-admission-signing-bundle",
            "finalize-training-corpus-admission",
        ):
            options = {
                option
                for action in commands[command]._actions
                for option in action.option_strings
            }
            self.assertNotIn("--private-key", options)
            self.assertNotIn("--private-key-password-env", options)

    def test_runtime_origin_bounds_match_the_strict_schemas(self) -> None:
        unsupported_origin = copy.deepcopy(self.report)
        unsupported_origin["concentration"]["origin"]["origin"] = "unsupported"
        with self.assertRaisesRegex(ValidationError, "is unsupported"):
            quality_module.validate_training_corpus_quality_report(unsupported_origin)

        excess_origins = copy.deepcopy(self.report)
        excess_origins["distinctCounts"]["origins"] = len(ORIGINS) + 1
        with self.assertRaisesRegex(ValidationError, "must be between 1 and 4"):
            quality_module.validate_training_corpus_quality_report(excess_origins)

        excess_policy_origins = copy.deepcopy(self.policy)
        excess_policy_origins["minimumDistinctOrigins"] = len(ORIGINS) + 1
        with self.assertRaisesRegex(ValidationError, "must be between 1 and 4"):
            quality_module.validate_training_corpus_quality_policy(
                excess_policy_origins
            )

    def test_validator_has_no_caller_threshold_override(self) -> None:
        parameters = inspect.signature(verify_training_corpus_admission).parameters
        self.assertNotIn("quality_policy", parameters)
        self.assertNotIn("thresholds", parameters)

        created = self._create()
        payload = json.loads(_decode(created.envelope["payload"]))
        weaker = copy.deepcopy(payload["qualityPolicy"])
        weaker["minimumRecordCount"] = 1
        payload["qualityPolicy"] = weaker
        payload["qualityPolicySha256"] = training_corpus_quality_policy_sha256(weaker)
        resigned = self._resign(created.envelope, payload)
        with self.assertRaisesRegex(
            ValidationError, "externally pinned reviewer policy"
        ):
            self._verify(resigned)

    def test_policy_failure_and_unpinned_policy_are_rejected(self) -> None:
        rejecting = copy.deepcopy(self.policy)
        rejecting["minimumRecordCount"] += 1
        rejecting_trust = replace(
            self.trust,
            quality_policy_sha256=training_corpus_quality_policy_sha256(rejecting),
        )
        with self.assertRaisesRegex(ValidationError, "rejects exact dataset"):
            self._create(quality_policy=rejecting, trust=rejecting_trust)

        with self.assertRaisesRegex(
            ValidationError, "externally pinned reviewer policy"
        ):
            self._create(trust=replace(self.trust, quality_policy_sha256="c" * 64))

    def test_dataset_and_release_drift_are_rejected(self) -> None:
        created = self._create()
        changed_release_sha = "d" * 64
        changed_release = {
            "releaseId": f"vqrel-{changed_release_sha}",
            "releaseSha256": changed_release_sha,
            "manifestSha256": "e" * 64,
        }
        with self.assertRaisesRegex(ValidationError, "exact expected release identity"):
            self._verify(created.envelope, expected_data_release=changed_release)

        mutated = copy.deepcopy(self.rows)
        mutated[0]["metadata"]["producer"] = "changed-producer"
        _write_jsonl(self.dataset, mutated)
        with self.assertRaisesRegex(ValidationError, "recomputed exact dataset report"):
            self._verify(created.envelope)

    def test_signed_authority_escalation_and_high_s_are_rejected(self) -> None:
        created = self._create()
        payload = json.loads(_decode(created.envelope["payload"]))
        payload["trainingAuthorized"] = True
        escalated = self._resign(created.envelope, payload)
        with self.assertRaisesRegex(ValidationError, "does not match the contract"):
            self._verify(escalated)

        signature = _decode(created.envelope["signature"])
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        high_s = r.to_bytes(32, "big") + (P256_ORDER - s).to_bytes(32, "big")
        malleable = dict(created.envelope)
        malleable["signature"] = _encode(high_s)
        with self.assertRaisesRegex(ValidationError, "canonical low-S"):
            self._verify(malleable)

    def test_external_trust_and_expiry_fail_closed(self) -> None:
        created = self._create()
        with self.assertRaisesRegex(ValidationError, "must be externally supplied"):
            verify_training_corpus_admission(
                created.envelope,
                dataset_path=self.dataset,
                expected_data_release=DATA_RELEASE,
                trust=None,  # type: ignore[arg-type]
                now=NOW,
            )
        with self.assertRaisesRegex(ValidationError, "is not active"):
            self._verify(
                created.envelope,
                now=datetime(2027, 7, 29, 10, 0, 2, tzinfo=timezone.utc),
            )

    def test_schemas_are_strict_and_no_approved_policy_is_checked_in(self) -> None:
        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        names = (
            "training-corpus-quality-report.v1.schema.json",
            "training-corpus-quality-policy.v1.schema.json",
            "training-corpus-admission.v1.schema.json",
            "training-corpus-admission-envelope.v1.schema.json",
        )
        for name in names:
            with self.subTest(name=name):
                schema = json.loads((schema_root / name).read_text(encoding="utf-8"))
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(
            [],
            sorted(schema_root.glob("*corpus-quality-policy*.json"))[1:],
            "only the policy schema may be checked in; no approved policy fixture",
        )


if __name__ == "__main__":
    unittest.main()
