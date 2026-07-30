from __future__ import annotations

import copy
import hashlib
import importlib
import inspect
import json
import os
import shutil
import tempfile
import unittest
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jsonschema
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

import vibe_quant_model.training as training_module
import vibe_quant_model.base_selection as base_selection_module
import vibe_quant_model.cli as cli_module
import vibe_quant_model.trainer_provenance as trainer_provenance_module
from vibe_quant_model.artifacts import training_artifact_sha256
from vibe_quant_model.base_engine_wrapper import (
    BASE_ATTESTED_COMPLETIONS_PATH,
    BaseEngineActivationTrust,
    BaseModelEngineWrapper,
    create_base_engine_activation,
    load_base_engine_wrapper_config,
)
from vibe_quant_model.base_selection import (
    BaseModelSelectionCandidateSource,
    BaseModelSelectionTrust,
    BASE_MODEL_SELECTION_ENVELOPE_SCHEMA_VERSION,
    base_model_bakeoff_matrix_id,
    base_model_selection_id,
    create_base_model_selection,
    finalize_base_model_selection,
    prepare_base_model_selection_signing_bundle,
    validate_base_model_selection,
    validate_base_model_selection_manifest_binding,
    validate_base_model_selection_manifest_target,
    validate_base_model_selection_target,
    verify_base_model_selection_envelope,
)
from vibe_quant_model.base_evaluation import (
    BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
    create_base_evaluation_profile,
    seal_base_model_snapshot,
)
from vibe_quant_model.core import (
    BUNDLE_V2_SCHEMA_VERSION,
    DOMAINS,
    MANIFEST_BUNDLE_PATH,
    MANIFEST_SCHEMA_VERSION,
    MANIFEST_V2_SCHEMA_VERSION,
    MANIFEST_V3_SCHEMA_VERSION,
    TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
    ValidationError,
    canonical_json_bytes,
    create_bundle,
    default_hyperparameters,
    validate_bundle,
    validate_manifest_path,
)
from vibe_quant_model.corpus_quality import (
    CORPUS_QUALITY_POLICY_SCHEMA_VERSION,
    TrainingCorpusAdmissionTrust,
    create_training_corpus_admission,
    derive_training_corpus_quality_report,
    training_corpus_quality_policy_sha256,
    verify_training_corpus_admission_file,
)
from vibe_quant_model.evaluation import (
    EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
    BaseResponseAttestationTrust,
    aggregate_promotion_evidence,
    capture_openai_responses,
    promotion_policy_sha256,
    validate_evaluation_responses,
)
from vibe_quant_model.deployment import create_serving_profile
from vibe_quant_model.promotion import (
    create_model_promotion,
    create_promoted_model_readiness_attestation,
    validate_model_promotion,
)
from vibe_quant_model.runtime import TRAINING_RUNTIME_PROFILE_BUNDLE_PATH
from vibe_quant_model.teacher_lineage import (
    TeacherMaterializationLineageAdmissionTrust,
)
from vibe_quant_model.trainer_provenance import TrainerProvenanceTrust
from vibe_quant_model.verifier_runtime import run_release_verifiers


ROOT = Path(__file__).resolve().parents[1]
_RELEASE_APPROVED = "2026-01-01T00:00:03Z"
_RELEASE_RECEIPT_ISSUED = "2026-01-01T00:00:04Z"
_RELEASE_RECEIPT_NOT_BEFORE = "2026-01-01T00:00:05Z"
_RELEASE_RECEIPT_EXPIRES = "2026-12-31T00:00:00Z"
_RELEASE_RECEIPT_VALIDATION_TIME = datetime(2026, 2, 1, tzinfo=timezone.utc)
_AUTHORING_APPROVED = "2026-01-01T00:00:00Z"
_AUTHORING_ISSUED = "2026-01-01T00:00:01Z"
_AUTHORING_NOT_BEFORE = "2026-01-01T00:00:02Z"
_AUTHORING_EXPIRES = "2026-12-31T00:00:00Z"
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def _encode(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


class BaseSelectionPublicationRaceTests(unittest.TestCase):
    def test_failed_installed_validation_preserves_unlinked_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "selection.json"
            replacement = b"concurrent replacement owner\n"

            def replace_then_fail(path: Path):
                path.unlink()
                path.write_bytes(replacement)
                raise ValidationError("forced raced final validation failure")

            with self.assertRaisesRegex(ValidationError, "forced raced"):
                base_selection_module._write_no_clobber(
                    destination,
                    b"owned selection\n",
                    prepublish_validator=lambda path: path,
                    installed_validator=replace_then_fail,
                )

            self.assertEqual(replacement, destination.read_bytes())


class BaseModelSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        base_tests = self._test_module("test_base_engine_wrapper")
        evaluation_tests = self._test_module("test_evaluation")
        release_tests = self._test_module("test_release")
        self.harness_tests = self._test_module("test_harness")

        self.base = base_tests.BaseEngineWrapperTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
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
            audience="base-selection-training-artifact-v2",
            key_id="base-selection-trainer-key-v1",
            signer_role="isolated-base-selection-trainer",
        )
        self.trainer_provenance_now = self.base.now
        fixed_training_time = self.base.now

        class FixedTrainingDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                if tz is None:
                    return fixed_training_time.replace(tzinfo=None)
                return fixed_training_time.astimezone(tz)

        training_datetime_patch = mock.patch.object(
            training_module, "datetime", FixedTrainingDateTime
        )
        training_datetime_patch.start()
        self.addCleanup(training_datetime_patch.stop)
        self.evaluation = evaluation_tests.EvaluationTests()
        self.evaluation.setUp()
        self.addCleanup(self.evaluation.doCleanups)
        shutil.copyfile(self.base.catalog, self.evaluation.catalog_path)
        self.evaluation.catalog = json.loads(
            self.evaluation.catalog_path.read_text(encoding="utf-8")
        )

        receipt_fixture = mock.patch.multiple(
            release_tests,
            APPROVED=_RELEASE_APPROVED,
            RECEIPT_ISSUED=_RELEASE_RECEIPT_ISSUED,
            RECEIPT_NOT_BEFORE=_RELEASE_RECEIPT_NOT_BEFORE,
            RECEIPT_EXPIRES=_RELEASE_RECEIPT_EXPIRES,
            VALIDATION_TIME=_RELEASE_RECEIPT_VALIDATION_TIME,
            AUTHORING_APPROVED=_AUTHORING_APPROVED,
            AUTHORING_ISSUED=_AUTHORING_ISSUED,
            AUTHORING_NOT_BEFORE=_AUTHORING_NOT_BEFORE,
            AUTHORING_EXPIRES=_AUTHORING_EXPIRES,
        )
        receipt_fixture.start()
        self.addCleanup(receipt_fixture.stop)
        paired = self.evaluation._bound_paired_fixture(provider=True)
        self.paired = paired
        self.bound = paired["bound"]
        self.addCleanup(self.bound["fixture"].doCleanups)
        original_source_lock = json.loads(
            self.base.source_lock.read_text(encoding="utf-8")
        )
        catalog = json.loads(self.base.catalog.read_text(encoding="utf-8"))
        students = [
            candidate
            for candidate in catalog["candidates"]
            if "student" in candidate["roles"]
        ]
        source_files = original_source_lock["candidates"][0]["files"]
        combined_source_lock = {
            "schemaVersion": BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
            "candidateCatalogSha256": hashlib.sha256(
                self.base.catalog.read_bytes()
            ).hexdigest(),
            "candidates": [
                {
                    "candidateId": candidate["id"],
                    "modelId": candidate["modelId"],
                    "revision": candidate["revision"],
                    "files": source_files,
                }
                for candidate in students
            ],
        }
        self.base.source_lock = self.base.root / "matrix-source-lock.json"
        self.base.source_lock.write_bytes(canonical_json_bytes(combined_source_lock))
        matrix_source_lock_patch = mock.patch(
            "vibe_quant_model.base_evaluation.APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256",
            hashlib.sha256(canonical_json_bytes(combined_source_lock)).hexdigest(),
        )
        matrix_source_lock_patch.start()
        self.addCleanup(matrix_source_lock_patch.stop)

        target_by_id: dict[str, dict[str, object]] = {}
        for index, candidate in enumerate(students):
            candidate_id = candidate["id"]
            manifest_path = self.base.root / f"matrix-{index}-snapshot.json"
            profile_path = self.base.root / f"matrix-{index}-profile.json"
            seal_base_model_snapshot(
                snapshot_path=self.base.snapshot,
                catalog_path=self.base.catalog,
                source_lock_path=self.base.source_lock,
                candidate_id=candidate_id,
                output_path=manifest_path,
            )
            profile = create_base_evaluation_profile(
                profile_id=f"matrix-{index}-{candidate_id}",
                catalog_path=self.base.catalog,
                source_lock_path=self.base.source_lock,
                snapshot_manifest_path=manifest_path,
                snapshot_path=self.base.snapshot,
                output_path=profile_path,
                engine_version="0.10.0",
                container_image_digest=self.base.image_digest,
                quantization=(
                    "mxfp4" if candidate_id == "gpt-oss-20b" else "bitsandbytes-nf4"
                ),
                compute_dtype="bfloat16",
                max_model_length=8_192,
                tensor_parallel_size=1,
                gpu_profile="l40s-48gb",
            )
            target_by_id[candidate_id] = {
                "manifest": manifest_path,
                "profilePath": profile_path,
                "profile": profile,
            }

        activation_trust = BaseEngineActivationTrust(
            public_key_path=self.base.launcher_public,
            public_key_spki_sha256=self.base.launcher_spki,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
        )
        candidate_trust = BaseResponseAttestationTrust(
            activation_trust=activation_trust,
            runtime_public_key_path=self.base.runtime_public,
        )
        base_config_value = json.loads(
            self.base.config_path.read_text(encoding="utf-8")
        )
        selected_id = "qwen2.5-coder-7b-instruct"
        baseline_target = target_by_id[selected_id]
        baseline_profile_path = self.base.root / "matrix-baseline-profile.json"
        baseline_profile = create_base_evaluation_profile(
            profile_id="matrix-attested-baseline",
            catalog_path=self.base.catalog,
            source_lock_path=self.base.source_lock,
            snapshot_manifest_path=baseline_target["manifest"],
            snapshot_path=self.base.snapshot,
            output_path=baseline_profile_path,
            engine_version="0.10.0",
            container_image_digest=self.base.image_digest,
            quantization="none",
            compute_dtype="bfloat16",
            max_model_length=8_192,
            tensor_parallel_size=1,
            gpu_profile="l40s-48gb",
        )
        baseline_activation_path = self.base.root / "matrix-baseline-activation.json"
        baseline_config_path = self.base.root / "matrix-baseline-wrapper.json"
        baseline_config_value = copy.deepcopy(base_config_value)
        baseline_config_value["target"] = {
            "profilePath": str(baseline_profile_path),
            "snapshotManifestPath": str(baseline_target["manifest"]),
            "snapshotPath": str(self.base.snapshot),
            "catalogPath": str(self.base.catalog),
            "sourceLockPath": str(self.base.source_lock),
            "expectedProfileSha256": baseline_profile.sha256,
        }
        baseline_config_value["activation"]["path"] = str(baseline_activation_path)
        baseline_config_value["engine"]["childPort"] = 18099
        baseline_config_value["service"]["listenPort"] = 18098
        baseline_config_path.write_bytes(canonical_json_bytes(baseline_config_value))
        create_base_engine_activation(
            config_path=baseline_config_path,
            output_path=baseline_activation_path,
            private_key_path=self.base.launcher_private,
            public_key_path=self.base.launcher_public,
            private_key_password=None,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
            issued_at_utc="2026-07-28T09:59:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-07-29T10:00:00Z",
        )
        baseline_config = load_base_engine_wrapper_config(baseline_config_path)
        self.base.profile = baseline_profile
        self.base.process = base_tests._FakeProcess()
        baseline_wrapper = BaseModelEngineWrapper(
            baseline_config,
            bearer_token=self.base.bearer,
            child_api_key="C" * 48,
            transport=self.base._transport,
            process_factory=self.base._process_factory,
            read_only_probe=lambda path: True,
            listener_ownership_probe=lambda process_id, host, port: True,
            runtime_key_isolation_probe=lambda config: True,
            clock=lambda: self.base.now,
        )
        baseline_wrapper.start(start_monitor=False)
        baseline_responses = self.evaluation.root / "matrix-baseline.responses.jsonl"

        def baseline_capture_transport(url, headers, body, timeout, max_bytes):
            response = baseline_wrapper.handle_http_request(
                "POST", BASE_ATTESTED_COMPLETIONS_PATH, headers, body
            )
            self.assertEqual(200, response.status)
            return evaluation_tests.TransportResponse(response.body, url)

        try:
            capture_openai_responses(
                tasks_path=paired["inputs"]["sealed_tasks_path"],
                catalog_path=self.base.catalog,
                output_path=baseline_responses,
                base_evaluation_profile_path=baseline_profile_path,
                base_model_snapshot_manifest_path=baseline_target["manifest"],
                base_model_snapshot_path=self.base.snapshot,
                base_model_source_lock_path=self.base.source_lock,
                base_engine_wrapper_config_path=baseline_config_path,
                base_engine_activation_trust=activation_trust,
                run_id="matrix-attested-baseline-run-001",
                base_url="http://127.0.0.1:18098/v1",
                api_key_env="VQ_OUTER_BEARER",
                seed=17,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                research_only=False,
                transport=baseline_capture_transport,
                clock=lambda: self.base.now,
                monotonic=iter((0.0, 0.1)).__next__,
            )
        finally:
            baseline_wrapper.stop()
        baseline_response = validate_evaluation_responses(
            baseline_responses, paired["inputs"]["sealed_tasks_path"]
        )[0]
        baseline_results = self.evaluation.root / "matrix-baseline.results.jsonl"
        run_release_verifiers(
            tasks_path=paired["inputs"]["sealed_tasks_path"],
            responses_path=baseline_responses,
            release_path=self.bound["release_path"],
            review_receipt_trust=self.bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=self.bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=self.bound["review_receipt_now"],
            output_path=baseline_results,
        )
        base_policy = json.loads(
            Path(paired["inputs"]["policy_path"]).read_text(encoding="utf-8")
        )
        base_policy["baselineRun"] = evaluation_tests._identity(baseline_response)
        matrix_inputs = dict(paired["inputs"])
        matrix_inputs["baseline_responses_path"] = baseline_responses
        matrix_inputs["baseline_verifier_results_path"] = baseline_results
        matrix_inputs["baseline_attestation_trust"] = candidate_trust
        candidate_sources: list[BaseModelSelectionCandidateSource] = []
        self.matrix_evidence_inputs: dict[str, dict[str, object]] = {}
        for index, candidate in enumerate(students):
            candidate_id = candidate["id"]
            target = target_by_id[candidate_id]
            activation_path = self.base.root / f"matrix-{index}-activation.json"
            config_path = self.base.root / f"matrix-{index}-wrapper.json"
            config_value = copy.deepcopy(base_config_value)
            config_value["target"] = {
                "profilePath": str(target["profilePath"]),
                "snapshotManifestPath": str(target["manifest"]),
                "snapshotPath": str(self.base.snapshot),
                "catalogPath": str(self.base.catalog),
                "sourceLockPath": str(self.base.source_lock),
                "expectedProfileSha256": target["profile"].sha256,
            }
            config_value["activation"]["path"] = str(activation_path)
            config_value["engine"]["childPort"] = 18101 + index * 2
            config_value["service"]["listenPort"] = 18100 + index * 2
            config_path.write_bytes(canonical_json_bytes(config_value))
            create_base_engine_activation(
                config_path=config_path,
                output_path=activation_path,
                private_key_path=self.base.launcher_private,
                public_key_path=self.base.launcher_public,
                private_key_password=None,
                audience="daxalgo-base-evaluation",
                key_id="launcher-key-v1",
                signer_role="base-runtime-launcher",
                issued_at_utc="2026-07-28T09:59:00Z",
                not_before_utc="2026-07-28T10:00:00Z",
                expires_at_utc="2026-07-29T10:00:00Z",
            )
            capture_config = load_base_engine_wrapper_config(config_path)
            self.base.profile = target["profile"]
            self.base.process = base_tests._FakeProcess()
            wrapper = BaseModelEngineWrapper(
                capture_config,
                bearer_token=self.base.bearer,
                child_api_key="C" * 48,
                transport=self.base._transport,
                process_factory=self.base._process_factory,
                read_only_probe=lambda path: True,
                listener_ownership_probe=lambda process_id, host, port: True,
                runtime_key_isolation_probe=lambda config: True,
                clock=lambda: self.base.now,
            )
            wrapper.start(start_monitor=False)
            candidate_responses = (
                self.evaluation.root / f"matrix-{index}.responses.jsonl"
            )

            def capture_transport(url, headers, body, timeout, max_bytes):
                response = wrapper.handle_http_request(
                    "POST", BASE_ATTESTED_COMPLETIONS_PATH, headers, body
                )
                self.assertEqual(200, response.status)
                return evaluation_tests.TransportResponse(response.body, url)

            try:
                capture_openai_responses(
                    tasks_path=paired["inputs"]["sealed_tasks_path"],
                    catalog_path=self.base.catalog,
                    output_path=candidate_responses,
                    base_evaluation_profile_path=target["profilePath"],
                    base_model_snapshot_manifest_path=target["manifest"],
                    base_model_snapshot_path=self.base.snapshot,
                    base_model_source_lock_path=self.base.source_lock,
                    base_engine_wrapper_config_path=config_path,
                    base_engine_activation_trust=activation_trust,
                    run_id=f"matrix-attested-base-run-{index + 1:03d}",
                    base_url=f"http://127.0.0.1:{18100 + index * 2}/v1",
                    api_key_env="VQ_OUTER_BEARER",
                    seed=17,
                    data_release_path=self.bound["release_path"],
                    review_receipt_trust=self.bound["review_receipt_trust"],
                    evaluation_authoring_approval_trust=self.bound[
                        "evaluation_authoring_approval_trust"
                    ],
                    review_receipt_now=self.bound["review_receipt_now"],
                    research_only=False,
                    transport=capture_transport,
                    clock=lambda: self.base.now,
                    monotonic=iter((0.0, 0.1)).__next__,
                )
            finally:
                wrapper.stop()
            candidate_response = validate_evaluation_responses(
                candidate_responses, paired["inputs"]["sealed_tasks_path"]
            )[0]
            candidate_results = self.evaluation.root / f"matrix-{index}.results.jsonl"
            run_release_verifiers(
                tasks_path=paired["inputs"]["sealed_tasks_path"],
                responses_path=candidate_responses,
                release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                output_path=candidate_results,
            )
            policy_path = self.evaluation.root / f"matrix-{index}.policy.json"
            policy = copy.deepcopy(base_policy)
            policy["candidateRun"] = evaluation_tests._identity(candidate_response)
            policy["policySha256"] = promotion_policy_sha256(policy)
            policy_path.write_bytes(canonical_json_bytes(policy) + b"\n")
            evidence_inputs = dict(matrix_inputs)
            evidence_inputs["responses_path"] = candidate_responses
            evidence_inputs["verifier_results_path"] = candidate_results
            evidence_inputs["policy_path"] = policy_path
            evidence_inputs["candidate_attestation_trust"] = candidate_trust
            report = aggregate_promotion_evidence(**evidence_inputs)
            report_path = self.root / f"matrix-{index}.evidence.json"
            report_path.write_bytes(canonical_json_bytes(report) + b"\n")
            candidate_sources.append(
                BaseModelSelectionCandidateSource(
                    candidate_id=candidate_id,
                    promotion_evidence_path=report_path,
                    responses_path=candidate_responses,
                    verifier_results_path=candidate_results,
                    policy_path=policy_path,
                    profile_path=target["profilePath"],
                    snapshot_manifest_path=target["manifest"],
                    snapshot_path=self.base.snapshot,
                    candidate_attestation_trust=candidate_trust,
                )
            )
            self.matrix_evidence_inputs[candidate_id] = evidence_inputs
            target["configPath"] = config_path
            target["activationPath"] = activation_path

        selected_target = target_by_id[selected_id]
        self.base.profile = selected_target["profile"]
        self.base.profile_path = selected_target["profilePath"]
        self.base.manifest = selected_target["manifest"]
        self.base.config_path = selected_target["configPath"]
        self.base.activation_path = selected_target["activationPath"]
        self.base.config = load_base_engine_wrapper_config(self.base.config_path)
        self.candidate_sources = tuple(candidate_sources)
        self.approval_path = self.root / "base-selection-approval.txt"
        self.approval_path.write_text(
            "Independent model board selected the exact attested base snapshot.\n",
            encoding="utf-8",
        )

        private_key = ec.generate_private_key(ec.SECP256R1())
        self.private_key_object = private_key
        self.private_key_path = self.root / "selection-private.pem"
        self.private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_key_path = self.root / "selection-public.pem"
        self.public_key_path.write_bytes(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.spki_sha256 = hashlib.sha256(spki).hexdigest()
        self.trust = BaseModelSelectionTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.spki_sha256,
            audience="daxalgo-training-prod",
            key_id="base-selection-key-2026-07",
            signer_role="base-model-approver",
        )
        self.source_arguments = {
            "candidate_sources": self.candidate_sources,
            "selected_candidate_id": selected_id,
            "calibration_tasks_path": paired["inputs"]["calibration_tasks_path"],
            "calibration_evidence_path": paired["inputs"]["calibration_evidence_path"],
            "sealed_tasks_path": paired["inputs"]["sealed_tasks_path"],
            "baseline_responses_path": baseline_responses,
            "baseline_verifier_results_path": baseline_results,
            "data_release_path": paired["inputs"]["data_release_path"],
            "review_receipt_trust": paired["inputs"]["review_receipt_trust"],
            "evaluation_authoring_approval_trust": paired["inputs"][
                "evaluation_authoring_approval_trust"
            ],
            "baseline_attestation_trust": candidate_trust,
            "catalog_path": self.base.catalog,
            "source_lock_path": self.base.source_lock,
            "approval_evidence_path": self.approval_path,
            "review_receipt_now": paired["inputs"]["review_receipt_now"],
        }
        self.selection_path = self.root / "base-selection.json"
        corpus_quality_key = ec.generate_private_key(ec.SECP256R1())
        self.corpus_admission_private_key_path = (
            self.root / "corpus-admission-private.pem"
        )
        self.corpus_admission_public_key_path = (
            self.root / "corpus-admission-public.pem"
        )
        self.corpus_admission_private_key_path.write_bytes(
            corpus_quality_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.corpus_admission_public_key_path.write_bytes(
            corpus_quality_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        corpus_quality_spki = hashlib.sha256(
            corpus_quality_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        self.corpus_quality_report = derive_training_corpus_quality_report(
            self.bound["sft_path"]
        )
        self.corpus_quality_policy = self._test_corpus_quality_policy(
            self.corpus_quality_report
        )
        self.corpus_admission_trust = TrainingCorpusAdmissionTrust(
            public_key_path=self.corpus_admission_public_key_path,
            public_key_spki_sha256=corpus_quality_spki,
            audience="base-selection-corpus-admission-v1",
            key_id="base-selection-corpus-quality-key-v1",
            signer_role="independent-test-corpus-quality-reviewer",
            quality_policy_sha256=training_corpus_quality_policy_sha256(
                self.corpus_quality_policy
            ),
        )
        self.corpus_admission_now = self.base.now
        self.corpus_admission_expires_at_utc = "2026-08-28T10:00:00Z"
        self.corpus_admission_path = self.root / "training-corpus-admission.json"
        create_training_corpus_admission(
            dataset_path=self.bound["sft_path"],
            data_release=self.bound["release_identity"],
            quality_policy=self.corpus_quality_policy,
            private_key_path=self.corpus_admission_private_key_path,
            private_key_password=None,
            trust=self.corpus_admission_trust,
            reviewer_id="test-corpus-quality-reviewer-01",
            reviewed_at_utc="2026-07-28T09:00:00Z",
            issued_at_utc="2026-07-28T09:59:58Z",
            not_before_utc="2026-07-28T09:59:59Z",
            expires_at_utc=self.corpus_admission_expires_at_utc,
            output_path=self.corpus_admission_path,
            now=self.corpus_admission_now,
        )

    @staticmethod
    def _test_corpus_quality_policy(report: dict) -> dict:
        return {
            "schemaVersion": CORPUS_QUALITY_POLICY_SCHEMA_VERSION,
            "policyVersion": "base-selection-test-only.v1",
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

    def _trainer_signing_arguments(self) -> dict:
        return {
            "trainer_provenance_trust": self.trainer_provenance_trust,
            "trainer_private_key_path": self.trainer_private_key_path,
            "trainer_private_key_password": None,
            "trainer_id": "base-selection-trainer-01",
            "trainer_expires_at_utc": "2027-07-28T10:00:05Z",
            "trainer_provenance_now": self.trainer_provenance_now,
            "corpus_admission_trust": self.corpus_admission_trust,
            "corpus_admission_now": self.corpus_admission_now,
        }

    @staticmethod
    def _test_module(name: str):
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            return importlib.import_module(f"tests.{name}")

    def _create(self, path: Path | None = None, **source_overrides):
        source_arguments = {**self.source_arguments, **source_overrides}
        return create_base_model_selection(
            output_path=path or self.selection_path,
            private_key_path=self.private_key_path,
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.spki_sha256,
            private_key_password=None,
            audience=self.trust.audience,
            key_id=self.trust.key_id,
            signer_role=self.trust.signer_role,
            approval_id="base-approval-2026-07-28",
            actor_id="base-reviewer-17",
            actor_role=self.trust.signer_role,
            approval_reference="VQ-BASE-2026-07-28",
            approved_at_utc="2026-07-28T09:00:00Z",
            issued_at_utc="2026-07-28T10:00:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-08-28T10:00:00Z",
            now=self.base.now,
            **source_arguments,
        )

    def _prepare_detached(
        self,
        name: str,
        *,
        signature_format: str = "asn1-der",
        force_high_s: bool = False,
        signing_key=None,
        signing_mode: str = "digest",
        csharp_verifier_context=None,
    ) -> tuple[Path, dict, Path, dict]:
        bundle_path = self.root / f"{name}.bundle.json"
        signature_path = self.root / f"{name}.signature.json"
        prepare_base_model_selection_signing_bundle(
            output_path=bundle_path,
            trust=self.trust,
            approval_id="base-approval-2026-07-28",
            actor_id="base-reviewer-17",
            actor_role=self.trust.signer_role,
            approval_reference="VQ-BASE-2026-07-28",
            approved_at_utc="2026-07-28T09:00:00Z",
            issued_at_utc="2026-07-28T10:00:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-08-28T10:00:00Z",
            now=self.base.now,
            csharp_verifier_context=csharp_verifier_context,
            **self.source_arguments,
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
        else:  # pragma: no cover - helper contract
            raise AssertionError("unsupported detached signing mode")
        r, s = decode_dss_signature(der)
        if force_high_s and s <= _P256_ORDER // 2:
            s = _P256_ORDER - s
        if signature_format == "asn1-der":
            external_signature = encode_dss_signature(r, s)
        elif signature_format == "ieee-p1363-fixed-64":
            external_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - helper contract
            raise AssertionError("unsupported detached signature format")
        signature = base_selection_module._build_external_signature_document(
            bundle,
            bundle_bytes,
            signature_format=signature_format,
            signature=external_signature,
        )
        signature_path.write_bytes(canonical_json_bytes(signature) + b"\n")
        return bundle_path, bundle, signature_path, signature

    def _write_detached_signature(
        self,
        bundle_path: Path,
        name: str,
        *,
        signature_format: str = "asn1-der",
        force_high_s: bool = False,
        signing_key=None,
        signing_mode: str = "digest",
    ) -> tuple[Path, dict]:
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
        else:  # pragma: no cover - helper contract
            raise AssertionError("unsupported detached signing mode")
        r, s = decode_dss_signature(der)
        if force_high_s and s <= _P256_ORDER // 2:
            s = _P256_ORDER - s
        if signature_format == "asn1-der":
            external_signature = encode_dss_signature(r, s)
        elif signature_format == "ieee-p1363-fixed-64":
            external_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:  # pragma: no cover - helper contract
            raise AssertionError("unsupported detached signature format")
        document = base_selection_module._build_external_signature_document(
            bundle,
            bundle_bytes,
            signature_format=signature_format,
            signature=external_signature,
        )
        path = self.root / f"{name}.signature.json"
        path.write_bytes(canonical_json_bytes(document) + b"\n")
        return path, document

    def _cached_selection_bindings(self, bundle: dict):
        payload = json.loads(_decode(bundle["request"]["payload"]))
        return base_selection_module._SelectionBindings(
            data_release=payload["dataRelease"],
            release_authority_expires_at_utc=payload["expiresAtUtc"],
            evaluation_matrix=payload["evaluationMatrix"],
            selected=payload["selected"],
        )

    def _finalize_detached(
        self,
        bundle_path: Path,
        signature_path: Path,
        output_name: str,
        *,
        cached_bindings: dict | None = None,
        csharp_verifier_context=None,
        **overrides,
    ):
        values = {
            "signing_bundle_path": bundle_path,
            "signature_path": signature_path,
            "output_path": self.root / output_name,
            "trust": self.trust,
            "now": self.base.now,
            "csharp_verifier_context": csharp_verifier_context,
            **self.source_arguments,
        }
        values.update(overrides)
        if cached_bindings is None:
            return finalize_base_model_selection(**values)
        with mock.patch.object(
            base_selection_module,
            "_build_selection_bindings",
            return_value=self._cached_selection_bindings(cached_bindings),
        ):
            return finalize_base_model_selection(**values)

    def _create_selected_bundle(
        self,
        name: str,
        *,
        include_corpus_admission: bool = True,
        corpus_admission_trust: TrainingCorpusAdmissionTrust | None = None,
        corpus_admission_path: Path | None = None,
        data_release_path: Path | None = None,
        sft_path: Path | None = None,
    ) -> Path:
        if not self.selection_path.exists():
            self._create()
        template = self.root / f"{name}-template.jinja"
        tokenizer_config = json.loads(
            (self.base.snapshot / "tokenizer_config.json").read_text(encoding="utf-8")
        )
        template.write_bytes(tokenizer_config["chat_template"].encode("utf-8"))
        bundle = self.root / name
        corpus_arguments = {}
        if include_corpus_admission:
            corpus_arguments = {
                "corpus_admission_path": (
                    corpus_admission_path or self.corpus_admission_path
                ),
                "corpus_admission_trust": (
                    corpus_admission_trust or self.corpus_admission_trust
                ),
                "corpus_admission_now": self.corpus_admission_now,
            }
        create_bundle(
            catalog_path=self.base.catalog,
            sft_path=sft_path or self.bound["sft_path"],
            candidate_id="qwen2.5-coder-7b-instruct",
            chat_template_path=template,
            chat_template_name="selected-snapshot-template-v1",
            output_directory=bundle,
            runtime_profile_path=ROOT / "training-runtime-profile.v1.json",
            data_release_path=data_release_path or self.bound["release_path"],
            review_receipt_trust=self.bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=self.bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=self.bound["review_receipt_now"],
            base_selection_path=self.selection_path,
            base_selection_trust=self.trust,
            base_evaluation_profile_path=self.base.profile_path,
            base_model_snapshot_manifest_path=self.base.manifest,
            base_model_snapshot_path=self.base.snapshot,
            base_model_source_lock_path=self.base.source_lock,
            base_selection_now=self.base.now,
            **corpus_arguments,
        )
        return bundle

    def test_signed_selection_replays_evidence_and_binds_exact_snapshot(self) -> None:
        created = self._create()
        validated = validate_base_model_selection(
            created.path,
            trust=self.trust,
            now=self.base.now,
            **self.source_arguments,
        )
        target = validate_base_model_selection_target(
            created.path,
            trust=self.trust,
            evaluation_authoring_approval_trust=self.bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_trust=self.bound["review_receipt_trust"],
            profile_path=self.base.profile_path,
            snapshot_manifest_path=self.base.manifest,
            snapshot_path=self.base.snapshot,
            catalog_path=self.base.catalog,
            source_lock_path=self.base.source_lock,
            now=self.base.now,
        )
        self.assertEqual(
            base_model_selection_id(validated.payload), validated.payload["selectionId"]
        )
        matrix = validated.payload["evaluationMatrix"]
        self.assertEqual(base_model_bakeoff_matrix_id(matrix), matrix["matrixId"])
        self.assertEqual(3, len(matrix["entries"]))
        catalog = json.loads(self.base.catalog.read_text(encoding="utf-8"))
        self.assertEqual(
            [
                source["id"]
                for source in catalog["candidates"]
                if "student" in source["roles"]
            ],
            matrix["requiredCandidateIds"],
        )
        self.assertEqual(created.payload_sha256, target.selection.payload_sha256)
        self.assertEqual(
            self.base.profile.sha256, validated.payload["selected"]["profileSha256"]
        )
        self.assertNotIn(str(self.base.snapshot), json.dumps(validated.envelope))
        self.assertNotIn("private", json.dumps(validated.envelope).lower())
        signature = _decode(validated.envelope["signature"])
        self.assertLessEqual(int.from_bytes(signature[32:], "big"), _P256_ORDER // 2)

    def test_selection_signer_must_differ_from_authoring_approval_signer(
        self,
    ) -> None:
        authoring_trust = self.bound["evaluation_authoring_approval_trust"]
        same_signer_trust = type(authoring_trust)(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.spki_sha256,
            audience=authoring_trust.audience,
            key_id=authoring_trust.key_id,
            signer_role=authoring_trust.signer_role,
        )
        with self.assertRaisesRegex(
            ValidationError,
            "must differ from upstream evaluation-authoring approval signer",
        ):
            self._create(
                self.root / "same-authoring-signer-selection.json",
                evaluation_authoring_approval_trust=same_signer_trust,
                review_receipt_trust=self.bound["review_receipt_trust"],
            )

        created = self._create(self.root / "distinct-authoring-signer-selection.json")
        with self.assertRaisesRegex(
            ValidationError,
            "must differ from upstream evaluation-authoring approval signer",
        ):
            validate_base_model_selection_target(
                created.path,
                trust=self.trust,
                evaluation_authoring_approval_trust=same_signer_trust,
                review_receipt_trust=self.bound["review_receipt_trust"],
                profile_path=self.base.profile_path,
                snapshot_manifest_path=self.base.manifest,
                snapshot_path=self.base.snapshot,
                catalog_path=self.base.catalog,
                source_lock_path=self.base.source_lock,
                now=self.base.now,
            )

    def test_creation_forwards_csharp_context_to_staged_validation(self) -> None:
        context = base_selection_module.CSharpVerifierExecutionContext(
            self.root / "verifier-authority.json",
            mock.sentinel.authority_trust,
            self.root,
        )
        aggregate = base_selection_module.aggregate_promotion_evidence

        def aggregate_without_csharp_execution(**kwargs):
            kwargs.pop("csharp_verifier_context")
            return aggregate(**kwargs)

        with (
            mock.patch.object(
                base_selection_module,
                "aggregate_promotion_evidence",
                side_effect=aggregate_without_csharp_execution,
            ),
            mock.patch.object(
                base_selection_module,
                "validate_base_model_selection",
                wraps=validate_base_model_selection,
            ) as staged_validation,
        ):
            self._create(csharp_verifier_context=context)

        self.assertIs(
            context,
            staged_validation.call_args.kwargs["csharp_verifier_context"],
        )

    def test_matrix_rejects_missing_duplicate_and_nonstudent_selection(self) -> None:
        with self.assertRaisesRegex(ValidationError, "baseline attestation trust"):
            self._create(
                self.root / "missing-baseline-trust.json",
                baseline_attestation_trust=None,
            )
        with self.assertRaisesRegex(ValidationError, "exactly one source"):
            self._create(
                self.root / "missing-matrix-row.json",
                candidate_sources=self.candidate_sources[:-1],
            )
        with self.assertRaisesRegex(ValidationError, "must not declare"):
            self._create(
                self.root / "duplicate-matrix-row.json",
                candidate_sources=(
                    self.candidate_sources[0],
                    self.candidate_sources[0],
                    self.candidate_sources[2],
                ),
            )
        with self.assertRaisesRegex(ValidationError, "catalog student"):
            self._create(
                self.root / "teacher-selection.json",
                selected_candidate_id="qwen3-coder-30b-a3b-instruct",
            )

    def test_matrix_canonicalizes_input_order_and_requires_passing_selection(
        self,
    ) -> None:
        canonical = self._create(self.root / "canonical-selection.json")
        reversed_selection = self._create(
            self.root / "reversed-selection.json",
            candidate_sources=tuple(reversed(self.candidate_sources)),
        )
        self.assertEqual(canonical.payload_sha256, reversed_selection.payload_sha256)
        self.assertEqual(
            canonical.payload["evaluationMatrix"]["matrixId"],
            reversed_selection.payload["evaluationMatrix"]["matrixId"],
        )

        forged = copy.deepcopy(canonical.payload)
        selected_id = forged["selected"]["candidateId"]
        selected_entry = next(
            entry
            for entry in forged["evaluationMatrix"]["entries"]
            if entry["candidateId"] == selected_id
        )
        selected_entry["eligibleForSelection"] = False
        forged["evaluationMatrix"]["matrixId"] = base_model_bakeoff_matrix_id(
            forged["evaluationMatrix"]
        )
        forged["selectionId"] = base_model_selection_id(forged)
        with self.assertRaisesRegex(ValidationError, "passed every selection gate"):
            base_selection_module._validate_selection_payload_document(forged)

    def test_downstream_rejects_correctly_signed_subset_matrix(self) -> None:
        created = self._create(self.root / "complete-selection.json")
        payload = copy.deepcopy(created.payload)
        selected_id = payload["selected"]["candidateId"]
        selected_entry = next(
            entry
            for entry in payload["evaluationMatrix"]["entries"]
            if entry["candidateId"] == selected_id
        )
        selected_entry["ordinal"] = 0
        payload["evaluationMatrix"]["requiredCandidateIds"] = [selected_id]
        payload["evaluationMatrix"]["entries"] = [selected_entry]
        payload["evaluationMatrix"]["matrixId"] = base_model_bakeoff_matrix_id(
            payload["evaluationMatrix"]
        )
        payload["selectionId"] = base_model_selection_id(payload)
        payload_bytes = canonical_json_bytes(payload)
        envelope = copy.deepcopy(created.envelope)
        envelope["payload"] = _encode(payload_bytes)
        envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
        private_key, _ = base_selection_module._load_private_key(
            self.private_key_path, None
        )
        envelope["signature"] = _encode(
            base_selection_module._sign_p1363_low_s(
                private_key,
                base_selection_module._signature_input(envelope, payload_bytes),
            )
        )
        forged_path = self.root / "signed-subset-selection.json"
        forged_path.write_bytes(
            base_selection_module._serialize_selection_envelope(envelope)
        )
        with self.assertRaisesRegex(ValidationError, "catalog student order"):
            validate_base_model_selection_target(
                forged_path,
                trust=self.trust,
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_trust=self.bound["review_receipt_trust"],
                profile_path=self.base.profile_path,
                snapshot_manifest_path=self.base.manifest,
                snapshot_path=self.base.snapshot,
                catalog_path=self.base.catalog,
                source_lock_path=self.base.source_lock,
                now=self.base.now,
            )

    def test_matrix_rejects_unattested_baseline_identity(self) -> None:
        created = self._create(self.root / "attested-baseline-selection.json")
        forged = copy.deepcopy(created.payload)
        forged["evaluationMatrix"]["shared"]["baselineRun"]["responseSchemaVersion"] = (
            "daxalgo.vibe-quant.evaluation-response/v1"
        )
        forged["evaluationMatrix"]["shared"]["baselineRun"]["targetKind"] = (
            "trained-adapter"
        )
        for entry in forged["evaluationMatrix"]["entries"]:
            entry["evaluation"]["baselineRun"] = copy.deepcopy(
                forged["evaluationMatrix"]["shared"]["baselineRun"]
            )
        forged["evaluationMatrix"]["matrixId"] = base_model_bakeoff_matrix_id(
            forged["evaluationMatrix"]
        )
        forged["selectionId"] = base_model_selection_id(forged)
        with self.assertRaisesRegex(ValidationError, "attested raw-base response-v2"):
            base_selection_module._validate_selection_payload_document(forged)

    def test_matrix_rejects_policy_family_drift(self) -> None:
        candidate_id = "qwen2.5-coder-14b-instruct"
        original_source = self.candidate_sources[1]
        policy = json.loads(original_source.policy_path.read_text(encoding="utf-8"))
        policy["policyId"] = policy["policyId"] + "-drift"
        policy["policySha256"] = promotion_policy_sha256(policy)
        policy_path = self.root / "drifted-policy.json"
        policy_path.write_bytes(canonical_json_bytes(policy) + b"\n")
        evidence_inputs = dict(self.matrix_evidence_inputs[candidate_id])
        evidence_inputs["policy_path"] = policy_path
        report = aggregate_promotion_evidence(**evidence_inputs)
        report_path = self.root / "drifted-policy-evidence.json"
        report_path.write_bytes(canonical_json_bytes(report) + b"\n")
        drifted_source = BaseModelSelectionCandidateSource(
            candidate_id=candidate_id,
            promotion_evidence_path=report_path,
            responses_path=original_source.responses_path,
            verifier_results_path=original_source.verifier_results_path,
            policy_path=policy_path,
            profile_path=original_source.profile_path,
            snapshot_manifest_path=original_source.snapshot_manifest_path,
            snapshot_path=original_source.snapshot_path,
            candidate_attestation_trust=original_source.candidate_attestation_trust,
        )
        sources = list(self.candidate_sources)
        sources[1] = drifted_source
        with self.assertRaisesRegex(ValidationError, "policy family"):
            self._create(
                self.root / "policy-family-drift.json",
                candidate_sources=tuple(sources),
            )

    def test_bakeoff_source_manifest_is_paths_only_and_strict(self) -> None:
        candidates = []
        for candidate_id, source in zip(
            (
                "qwen2.5-coder-7b-instruct",
                "qwen2.5-coder-14b-instruct",
                "gpt-oss-20b",
            ),
            self.candidate_sources,
            strict=True,
        ):
            candidates.append(
                {
                    "candidateId": candidate_id,
                    "promotionEvidencePath": str(source.promotion_evidence_path),
                    "responsesPath": str(source.responses_path),
                    "verifierResultsPath": str(source.verifier_results_path),
                    "policyPath": str(source.policy_path),
                    "profilePath": str(source.profile_path),
                    "snapshotManifestPath": str(source.snapshot_manifest_path),
                    "snapshotPath": str(source.snapshot_path),
                }
            )
        document = {
            "schemaVersion": "daxalgo.vibe-quant.base-model-selection-sources/v1",
            "selectedCandidateId": "qwen2.5-coder-7b-instruct",
            "candidates": candidates,
        }
        path = self.root / "bakeoff-sources.json"
        path.write_bytes(canonical_json_bytes(document))
        loaded, selected = cli_module._load_base_selection_candidate_sources(
            path,
            candidate_attestation_trust=(
                self.candidate_sources[0].candidate_attestation_trust
            ),
        )
        self.assertEqual(document["selectedCandidateId"], selected)
        self.assertEqual(3, len(loaded))
        self.assertNotIn("trust", path.read_text(encoding="utf-8").lower())

        document["candidates"][1]["candidateId"] = document["candidates"][0][
            "candidateId"
        ]
        path.write_bytes(canonical_json_bytes(document))
        with self.assertRaisesRegex(ValidationError, "duplicates another entry"):
            cli_module._load_base_selection_candidate_sources(
                path,
                candidate_attestation_trust=(
                    self.candidate_sources[0].candidate_attestation_trust
                ),
            )

    def test_new_schemas_preserve_runtime_specific_constraints(self) -> None:
        manifest_schema = json.loads(
            (ROOT / "schemas" / "training-run-manifest.v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        hyperparameters = manifest_schema["properties"]["hyperparameters"]
        self.assertFalse(hyperparameters["additionalProperties"])
        self.assertEqual(
            set(default_hyperparameters()), set(hyperparameters["required"])
        )
        self.assertEqual(
            list(DOMAINS), manifest_schema["properties"]["domains"]["const"]
        )

        selection_schema = json.loads(
            (ROOT / "schemas" / "base-model-selection.v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        candidate_run = selection_schema["$defs"]["candidateRun"]["allOf"][1][
            "properties"
        ]
        self.assertEqual(
            EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
            candidate_run["responseSchemaVersion"]["const"],
        )
        self.assertEqual("raw-base", candidate_run["targetKind"]["const"])
        self.assertEqual(
            "#/$defs/candidateRun",
            selection_schema["$defs"]["evaluation"]["properties"]["baselineRun"][
                "$ref"
            ],
        )

    def test_selection_rejects_wrong_trust_high_s_and_target_substitution(self) -> None:
        created = self._create()
        wrong_trust = BaseModelSelectionTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256="0" * 64,
            audience=self.trust.audience,
            key_id=self.trust.key_id,
            signer_role=self.trust.signer_role,
        )
        with self.assertRaisesRegex(
            ValidationError, "does not match the supplied public key"
        ):
            verify_base_model_selection_envelope(
                created.path, trust=wrong_trust, now=self.base.now
            )

        envelope = copy.deepcopy(created.envelope)
        signature = _decode(envelope["signature"])
        high_s = _P256_ORDER - int.from_bytes(signature[32:], "big")
        envelope["signature"] = _encode(signature[:32] + high_s.to_bytes(32, "big"))
        high_s_path = self.root / "high-s-selection.json"
        high_s_path.write_bytes(
            base_selection_module._serialize_selection_envelope(envelope)
        )
        with self.assertRaisesRegex(ValidationError, "low-S"):
            verify_base_model_selection_envelope(
                high_s_path, trust=self.trust, now=self.base.now
            )

        original = (self.base.snapshot / "model.safetensors").read_bytes()
        (self.base.snapshot / "model.safetensors").write_bytes(original + b"tamper")
        try:
            with self.assertRaisesRegex(
                ValidationError, "sealed file tree|source lock|data ranges"
            ):
                validate_base_model_selection_target(
                    created.path,
                    trust=self.trust,
                    evaluation_authoring_approval_trust=self.bound[
                        "evaluation_authoring_approval_trust"
                    ],
                    review_receipt_trust=self.bound["review_receipt_trust"],
                    profile_path=self.base.profile_path,
                    snapshot_manifest_path=self.base.manifest,
                    snapshot_path=self.base.snapshot,
                    catalog_path=self.base.catalog,
                    source_lock_path=self.base.source_lock,
                    now=self.base.now,
                )
        finally:
            (self.base.snapshot / "model.safetensors").write_bytes(original)

    def test_selection_rejects_evidence_split_view_mutation(self) -> None:
        policy_path = self.candidate_sources[0].policy_path
        original = policy_path.read_bytes()
        aggregate = base_selection_module.aggregate_promotion_evidence

        def mutate_after_snapshot(**kwargs):
            report = aggregate(**kwargs)
            policy_path.write_bytes(original + b" ")
            return report

        try:
            with mock.patch.object(
                base_selection_module,
                "aggregate_promotion_evidence",
                side_effect=mutate_after_snapshot,
            ):
                with self.assertRaisesRegex(ValidationError, "changed while"):
                    self._create(self.root / "split-view-selection.json")
        finally:
            policy_path.write_bytes(original)

    def test_selection_replay_failure_leaves_no_published_authority(self) -> None:
        output = self.root / "failed-selection-publication.json"
        with mock.patch.object(
            base_selection_module,
            "validate_base_model_selection",
            side_effect=ValidationError("post-write replay failed"),
        ):
            with self.assertRaisesRegex(ValidationError, "post-write replay failed"):
                self._create(output)
        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(f".{output.name}.*.staging")))

        created = self._create(output)
        self.assertEqual(output, created.path)

    def test_manifest_target_retains_one_validated_manifest_snapshot(self) -> None:
        bundle = self._create_selected_bundle("single-manifest-snapshot")
        manifest_path = bundle / "training-run-manifest.json"
        original = manifest_path.read_bytes()
        validate_snapshot = base_selection_module.validate_manifest_snapshot

        def snapshot_then_mutate(path):
            snapshot = validate_snapshot(path)
            manifest_path.write_bytes(original + b" ")
            return snapshot

        try:
            with mock.patch.object(
                base_selection_module,
                "validate_manifest_snapshot",
                side_effect=snapshot_then_mutate,
            ) as snapshot_manifest:
                target = validate_base_model_selection_manifest_target(
                    manifest_path,
                    trust=self.trust,
                    evaluation_authoring_approval_trust=self.bound[
                        "evaluation_authoring_approval_trust"
                    ],
                    review_receipt_trust=self.bound["review_receipt_trust"],
                    snapshot_path=self.base.snapshot,
                    expected_data_release=self.bound["release_identity"],
                )
            snapshot_manifest.assert_called_once_with(manifest_path)
            self.assertIsNotNone(target.manifest_snapshot)
            self.assertEqual(original, target.manifest_snapshot.raw)
            self.assertEqual(
                hashlib.sha256(original).hexdigest(), target.manifest_snapshot.sha256
            )
        finally:
            manifest_path.write_bytes(original)

    def test_post_publication_cleanup_failure_aborts_selection(self) -> None:
        output = self.root / "selection-cleanup-failure.json"
        original_unlink = Path.unlink

        def fail_staging_cleanup(path, *args, **kwargs):
            if path.parent == output.parent and path.name.startswith(
                f".{output.name}."
            ):
                raise PermissionError("simulated post-publication cleanup failure")
            return original_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", new=fail_staging_cleanup),
            self.assertRaisesRegex(
                ValidationError, "staging cleanup failed|residual signed authority"
            ),
        ):
            self._create(output)

        self.assertFalse(output.exists())
        staging = list(self.root.glob(f".{output.name}.*.staging"))
        self.assertEqual(1, len(staging))
        original_unlink(staging[0])

    def test_prepublication_cleanup_failure_surfaces_residual_selection(self) -> None:
        output = self.root / "selection-residual-authority.json"
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
                base_selection_module.os,
                "link",
                side_effect=OSError("simulated publication failure"),
            ),
            self.assertRaisesRegex(ValidationError, "residual signed authority"),
        ):
            self._create(output)

        self.assertFalse(output.exists())
        staging = list(self.root.glob(f".{output.name}.*.staging"))
        self.assertEqual(1, len(staging))
        original_unlink(staging[0])

    def test_selected_bundle_and_training_use_v3_and_exact_snapshot(self) -> None:
        bundle = self._create_selected_bundle("selected-training")
        manifest_path = bundle / "training-run-manifest.json"
        manifest = validate_manifest_path(manifest_path)
        authenticated = validate_base_model_selection_manifest_binding(
            manifest_path,
            trust=self.trust,
            evaluation_authoring_approval_trust=self.bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_trust=self.bound["review_receipt_trust"],
            expected_data_release=self.bound["release_identity"],
            now=self.base.now,
        )
        self.assertEqual(MANIFEST_V3_SCHEMA_VERSION, manifest["schemaVersion"])
        self.assertEqual(
            manifest["baseModelSelection"]["selectionId"],
            authenticated.payload["selectionId"],
        )
        self.assertEqual(
            10, len(json.loads((bundle / "run-bundle.json").read_text())["files"])
        )
        validate_bundle(bundle)
        captured: dict[str, object] = {}

        def fake_training(manifest, dependencies, records, output_path, **kwargs):
            captured.update(kwargs)
            self.harness_tests._write_safe_inference_files(output_path, manifest)

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
        ):
            result = training_module.train_from_manifest(
                manifest_path,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: path == self.base.snapshot,
                importer=self.harness_tests._fake_training_importer(),
                **self._trainer_signing_arguments(),
            )
        self.assertEqual(self.base.snapshot, captured["model_source_path"])
        self.assertEqual(
            manifest["baseModelSelection"]["selectionId"],
            result["baseModelSelectionId"],
        )
        artifact = bundle / "outputs" / "adapter"
        self.assertNotIn(
            str(self.base.snapshot),
            (artifact / "adapter_config.json").read_text(encoding="utf-8"),
        )

    def test_detached_trainer_handoff_finalizes_the_unchanged_candidate_wire(
        self,
    ) -> None:
        bundle = self._create_selected_bundle("detached-trainer-provenance")
        manifest_path = bundle / "training-run-manifest.json"
        output = bundle / "outputs" / "adapter"
        handoff = bundle / "outputs" / "adapter.trainer-provenance-pending"

        def fake_training(manifest, dependencies, records, output_path, **kwargs):
            self.harness_tests._write_safe_inference_files(output_path, manifest)

        signing = self._trainer_signing_arguments()
        signing.pop("trainer_private_key_path")
        signing.pop("trainer_private_key_password")
        signing["trainer_provenance_handoff_path"] = handoff
        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
            mock.patch.object(
                trainer_provenance_module,
                "_load_private_key",
                side_effect=AssertionError(
                    "detached training must not load the trainer private key"
                ),
            ),
        ):
            prepared = training_module.train_from_manifest(
                manifest_path,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: path == self.base.snapshot,
                importer=self.harness_tests._fake_training_importer(),
                **signing,
            )
        self.assertFalse(output.exists())
        self.assertEqual("unsealed-candidate-handoff", prepared["mode"])
        self.assertEqual(
            {
                "artifact",
                "trainer-provenance-signing-bundle.json",
                "training-artifact-core.json",
            },
            {path.name for path in handoff.iterdir()},
        )
        self.assertFalse((handoff / "artifact" / "artifact-metadata.json").exists())

        signing_bundle = json.loads(
            (handoff / "trainer-provenance-signing-bundle.json").read_text(
                encoding="utf-8"
            )
        )
        trainer_key = serialization.load_pem_private_key(
            self.trainer_private_key_path.read_bytes(), password=None
        )
        der_signature = trainer_key.sign(
            _decode(signing_bundle["request"]["signatureInput"]),
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        external_signature = trainer_provenance_module._build_external_signature_document(
            signing_bundle,
            signature_mode=(
                trainer_provenance_module.TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE
            ),
            signature_format=(
                trainer_provenance_module.TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT
            ),
            signature=der_signature,
        )
        signature_path = bundle / "outputs" / "trainer-provenance-signature.json"
        signature_path.write_text(
            json.dumps(external_signature, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        finalization_arguments = {
            "data_release_path": self.bound["release_path"],
            "review_receipt_trust": self.bound["review_receipt_trust"],
            "evaluation_authoring_approval_trust": self.bound[
                "evaluation_authoring_approval_trust"
            ],
            "review_receipt_now": self.bound["review_receipt_now"],
            "base_model_snapshot_path": self.base.snapshot,
            "base_selection_trust": self.trust,
            "base_selection_now": self.base.now,
            "corpus_admission_trust": self.corpus_admission_trust,
            "corpus_admission_now": self.corpus_admission_now,
            "trainer_provenance_trust": self.trainer_provenance_trust,
            "trainer_provenance_now": self.trainer_provenance_now,
            "snapshot_read_only_probe": lambda path: path == self.base.snapshot,
        }
        pending_config = handoff / "artifact" / "adapter_config.json"
        original_config = pending_config.read_bytes()
        pending_config.write_bytes(original_config + b" ")
        with self.assertRaisesRegex(ValidationError, "artifact core|file tree"):
            training_module.finalize_training_artifact_from_handoff(
                manifest_path,
                handoff,
                signature_path,
                **finalization_arguments,
            )
        self.assertFalse(output.exists())
        pending_config.write_bytes(original_config)

        expires = datetime.strptime(
            signing_bundle["validity"]["expiresAtUtc"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValidationError, "must be active|not active"):
            training_module.finalize_training_artifact_from_handoff(
                manifest_path,
                handoff,
                signature_path,
                **{
                    **finalization_arguments,
                    "trainer_provenance_now": expires,
                },
            )
        self.assertFalse(output.exists())

        real_replay = training_module._replay_candidate_training_authorities
        replay_count = 0

        def replay_with_drift(*args, **kwargs):
            nonlocal replay_count
            replay_count += 1
            replay = real_replay(*args, **kwargs)
            if replay_count == 2:
                replay = {**replay, "datasetSha256": "0" * 64}
            return replay

        with (
            mock.patch.object(
                training_module,
                "_replay_candidate_training_authorities",
                side_effect=replay_with_drift,
            ),
            self.assertRaisesRegex(ValidationError, "live training inputs changed"),
        ):
            training_module.finalize_training_artifact_from_handoff(
                manifest_path,
                handoff,
                signature_path,
                **finalization_arguments,
            )
        self.assertFalse(output.exists())

        with mock.patch.object(
            trainer_provenance_module,
            "_load_private_key",
            side_effect=AssertionError(
                "detached finalization must not load the trainer private key"
            ),
        ):
            finalized = training_module.finalize_training_artifact_from_handoff(
                manifest_path,
                handoff,
                signature_path,
                **finalization_arguments,
            )
        artifact = training_module.validate_training_artifact(
            output,
            trainer_provenance_trust=self.trainer_provenance_trust,
            trainer_provenance_now=self.trainer_provenance_now,
        )
        self.assertEqual(finalized["artifactSha256"], artifact["artifactSha256"])
        self.assertEqual(
            trainer_provenance_module.TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION,
            artifact["trainerProvenance"]["schemaVersion"],
        )
        profile = create_serving_profile(
            profile_id="detached-trainer-profile-v1",
            artifact_path=output,
            manifest_path=manifest_path,
            output_path=bundle / "detached-serving-profile.json",
            engine="vllm",
            engine_version="0.10.0",
            container_image_digest="sha256:" + "6" * 64,
            quantization="bitsandbytes-nf4",
            compute_dtype="bfloat16",
            max_model_length=8_192,
            tensor_parallel_size=1,
            gpu_profile="l40s-48gb",
            trainer_provenance_trust=self.trainer_provenance_trust,
            trainer_provenance_now=self.trainer_provenance_now,
        )
        self.assertEqual(
            artifact["artifactSha256"],
            profile.document["trainingArtifact"]["artifactSha256"],
        )
        self.assertTrue(handoff.is_dir())
        with self.assertRaisesRegex(ValidationError, "already exists"):
            training_module.finalize_training_artifact_from_handoff(
                manifest_path,
                handoff,
                signature_path,
                **finalization_arguments,
            )
        self.assertEqual(
            finalized["artifactSha256"],
            training_module.validate_training_artifact(
                output,
                trainer_provenance_trust=self.trainer_provenance_trust,
                trainer_provenance_now=self.trainer_provenance_now,
            )["artifactSha256"],
        )

    def test_selected_bundle_requires_corpus_admission(self) -> None:
        with self.assertRaisesRegex(
            ValidationError,
            "required for every selected training bundle",
        ):
            self._create_selected_bundle(
                "missing-corpus-admission",
                include_corpus_admission=False,
            )

    def test_corpus_quality_signer_must_be_independent(self) -> None:
        authorities = {
            "review": self.bound["review_receipt_trust"],
            "evaluation": self.bound["evaluation_authoring_approval_trust"],
            "base-selection": self.trust,
        }
        for name, authority in authorities.items():
            with self.subTest(name=name):
                colliding = replace(
                    self.corpus_admission_trust,
                    public_key_path=authority.public_key_path,
                    public_key_spki_sha256=authority.public_key_spki_sha256,
                )
                with self.assertRaisesRegex(
                    ValidationError,
                    "must differ from corpus review, evaluation-authoring, and "
                    "base-selection signers",
                ):
                    self._create_selected_bundle(
                        f"corpus-signer-collision-{name}",
                        corpus_admission_trust=colliding,
                    )

    def test_corpus_admission_cli_uses_one_dataset_snapshot(self) -> None:
        sft_path = self.bound["sft_path"]
        captured = sft_path.read_bytes()
        policy_path = self.root / "cli-corpus-policy.json"
        policy_path.write_bytes(
            canonical_json_bytes(self.corpus_quality_policy) + b"\n"
        )
        output_path = self.root / "cli-corpus-admission.json"
        review = self.bound["review_receipt_trust"]
        authoring = self.bound["evaluation_authoring_approval_trust"]
        corpus = self.corpus_admission_trust
        arguments = [
            "create-training-corpus-admission",
            "--sft",
            os.fspath(sft_path),
            "--release",
            os.fspath(self.bound["release_path"]),
            "--quality-policy",
            os.fspath(policy_path),
            "--private-key",
            os.fspath(self.corpus_admission_private_key_path),
            "--reviewer-id",
            "cli-corpus-reviewer-01",
            "--reviewed-at-utc",
            "2026-07-28T09:00:00Z",
            "--issued-at-utc",
            "2026-07-28T09:59:58Z",
            "--not-before-utc",
            "2026-07-28T09:59:59Z",
            "--expires-at-utc",
            self.corpus_admission_expires_at_utc,
            "--output",
            os.fspath(output_path),
            "--review-receipt-public-key",
            os.fspath(review.public_key_path),
            "--review-receipt-public-key-spki-sha256",
            review.public_key_spki_sha256,
            "--review-receipt-audience",
            review.audience,
            "--review-receipt-key-id",
            review.key_id,
            "--review-receipt-signer-role",
            review.signer_role,
            "--evaluation-authoring-approval-public-key",
            os.fspath(authoring.public_key_path),
            "--evaluation-authoring-approval-public-key-spki-sha256",
            authoring.public_key_spki_sha256,
            "--evaluation-authoring-approval-audience",
            authoring.audience,
            "--evaluation-authoring-approval-key-id",
            authoring.key_id,
            "--evaluation-authoring-approval-signer-role",
            authoring.signer_role,
            "--corpus-admission-public-key",
            os.fspath(corpus.public_key_path),
            "--corpus-admission-public-key-spki-sha256",
            corpus.public_key_spki_sha256,
            "--corpus-admission-audience",
            corpus.audience,
            "--corpus-admission-key-id",
            corpus.key_id,
            "--corpus-admission-signer-role",
            corpus.signer_role,
            "--corpus-admission-quality-policy-sha256",
            corpus.quality_policy_sha256,
        ]
        original_read = cli_module._read_file_bounded
        swapped = False

        def capture_then_swap(path, field, maximum):
            nonlocal swapped
            data = original_read(path, field, maximum)
            if Path(path) == sft_path and not swapped:
                sft_path.write_bytes(b"tampered after the CLI capture")
                swapped = True
            return data

        with (
            mock.patch.object(
                cli_module, "_read_file_bounded", side_effect=capture_then_swap
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(0, cli_module.main(arguments))
        self.assertTrue(swapped)
        self.assertEqual(b"tampered after the CLI capture", sft_path.read_bytes())
        verified = verify_training_corpus_admission_file(
            output_path,
            dataset_bytes=captured,
            expected_data_release=self.bound["release_identity"],
            trust=corpus,
            now=self.corpus_admission_now,
        )
        self.assertEqual(
            hashlib.sha256(captured).hexdigest(),
            verified.payload["dataset"]["sha256"],
        )

    def test_v2_non_smoke_training_fails_before_model_construction(self) -> None:
        bundle = self._create_selected_bundle("v2-validation-only")
        manifest_path = bundle / "training-run-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schemaVersion"] = MANIFEST_V2_SCHEMA_VERSION
        manifest.pop("trainingCorpusAdmission")
        manifest.pop("runId")
        manifest["runId"] = (
            "vqrun-" + hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()[:20]
        )
        manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
        bundle_path = bundle / "run-bundle.json"
        bundle_document = json.loads(bundle_path.read_text(encoding="utf-8"))
        files = [
            entry
            for entry in bundle_document["files"]
            if entry["path"] != TRAINING_CORPUS_ADMISSION_BUNDLE_PATH
        ]
        manifest_bytes = manifest_path.read_bytes()
        manifest_entry = next(
            entry for entry in files if entry["path"] == MANIFEST_BUNDLE_PATH
        )
        manifest_entry["sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_entry["sizeBytes"] = len(manifest_bytes)
        bundle_payload = {
            "schemaVersion": BUNDLE_V2_SCHEMA_VERSION,
            "files": files,
        }
        bundle_payload["bundleSha256"] = hashlib.sha256(
            canonical_json_bytes(bundle_payload)
        ).hexdigest()
        bundle_path.write_bytes(canonical_json_bytes(bundle_payload) + b"\n")
        validate_bundle(bundle)
        importer = mock.Mock(
            side_effect=AssertionError("model dependencies must not be constructed")
        )
        with (
            mock.patch.object(training_module, "_run_training") as runner,
            self.assertRaisesRegex(
                ValidationError,
                "selected v2 manifests are validation-only",
            ),
        ):
            training_module.train_from_manifest(
                manifest_path,
                importer=importer,
            )
        importer.assert_not_called()
        runner.assert_not_called()
        self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_detached_selection_preserves_v2_wire_and_normalizes_signatures(
        self,
    ) -> None:
        direct = self._create(self.root / "direct-parity-selection.json")
        bundle_path, bundle, high_s_path, _ = self._prepare_detached(
            "detached-parity",
            force_high_s=True,
        )
        detached = self._finalize_detached(
            bundle_path,
            high_s_path,
            "detached-parity-selection.json",
            cached_bindings=bundle,
        )
        self.assertEqual(
            BASE_MODEL_SELECTION_ENVELOPE_SCHEMA_VERSION,
            detached.envelope["schemaVersion"],
        )
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
        self.assertLessEqual(int.from_bytes(normalized[32:], "big"), _P256_ORDER // 2)

        p1363_path, _ = self._write_detached_signature(
            bundle_path,
            "detached-p1363",
            signature_format="ieee-p1363-fixed-64",
        )
        p1363 = self._finalize_detached(
            bundle_path,
            p1363_path,
            "detached-p1363-selection.json",
            cached_bindings=bundle,
        )
        self.assertEqual(detached.payload_sha256, p1363.payload_sha256)

        raw_path, _ = self._write_detached_signature(
            bundle_path,
            "detached-raw-preimage",
            signing_mode="raw-preimage",
        )
        raw = self._finalize_detached(
            bundle_path,
            raw_path,
            "detached-raw-preimage-selection.json",
            cached_bindings=bundle,
        )
        self.assertEqual(detached.payload_sha256, raw.payload_sha256)

        double_path, _ = self._write_detached_signature(
            bundle_path,
            "detached-double-hash",
            signing_mode="double-hashed-digest",
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                bundle_path,
                double_path,
                "detached-double-hash-selection.json",
                cached_bindings=bundle,
            )

    def test_detached_contract_is_closed_bound_and_private_key_free(self) -> None:
        bundle_path, bundle, signature_path, signature = self._prepare_detached(
            "detached-contract"
        )
        schema_root = ROOT / "schemas"
        bundle_schema = json.loads(
            (
                schema_root / "base-model-selection-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_schema = json.loads(
            (schema_root / "base-model-selection-signature.v1.schema.json").read_bytes()
        )
        for schema in (bundle_schema, signature_schema):
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(signature)
        self.assertTrue(all(value is False for value in bundle["authority"].values()))
        for api in (
            prepare_base_model_selection_signing_bundle,
            finalize_base_model_selection,
        ):
            parameters = inspect.signature(api).parameters
            self.assertNotIn("private_key_path", parameters)
            self.assertNotIn("private_key_password", parameters)

        parser = cli_module._parser()
        commands = next(
            action.choices
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
            and "finalize-base-model-selection" in action.choices
        )
        for command in (
            "prepare-base-model-selection-signing-bundle",
            "finalize-base-model-selection",
        ):
            options = {
                option
                for action in commands[command]._actions
                for option in action.option_strings
            }
            self.assertNotIn("--private-key", options)
            self.assertNotIn("--private-key-password-env", options)

        mutations = (
            lambda value: value["authority"].update(training=True),
            lambda value: value["trust"].update(keyId="wrong-key"),
            lambda value: value["dataRelease"].update(releaseSha256="0" * 64),
            lambda value: value.update(evaluationMatrixId="vqbasebakeoff-" + "0" * 64),
            lambda value: value.update(
                requiredCandidateIds=list(reversed(value["requiredCandidateIds"]))
            ),
            lambda value: value["selected"].update(snapshotSha256="0" * 64),
            lambda value: value["approval"].update(evidenceSha256="0" * 64),
            lambda value: value["validity"].update(expiresAtUtc="2026-08-27T10:00:00Z"),
            lambda value: value["signatureContract"].update(messageType="raw"),
            lambda value: value["request"].update(signaturePreimage=_encode(b"wrong")),
            lambda value: value["request"].update(signatureInput=_encode(b"0" * 32)),
        )
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(bundle)
            mutate(changed)
            changed["bundleId"] = (
                base_selection_module.base_model_selection_signing_bundle_id(changed)
            )
            changed_path = self.root / f"mutated-bundle-{index}.json"
            changed_path.write_bytes(canonical_json_bytes(changed) + b"\n")
            with (
                self.subTest(bundle_mutation=index),
                self.assertRaises(ValidationError),
            ):
                self._finalize_detached(
                    changed_path,
                    signature_path,
                    f"mutated-bundle-{index}.selection.json",
                    cached_bindings=bundle,
                )

        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_signature_path, _ = self._write_detached_signature(
            bundle_path,
            "wrong-detached-key",
            signing_key=wrong_key,
        )
        with self.assertRaisesRegex(ValidationError, "does not verify"):
            self._finalize_detached(
                bundle_path,
                wrong_signature_path,
                "wrong-detached-key.selection.json",
                cached_bindings=bundle,
            )

        malformed = copy.deepcopy(signature)
        malformed["signature"] = _encode(b"\x00" * 64)
        malformed["format"] = "ieee-p1363-fixed-64"
        malformed["signatureId"] = (
            base_selection_module.base_model_selection_external_signature_id(malformed)
        )
        malformed_path = self.root / "malformed-signature.json"
        malformed_path.write_bytes(canonical_json_bytes(malformed) + b"\n")
        with self.assertRaisesRegex(ValidationError, "out-of-range"):
            self._finalize_detached(
                bundle_path,
                malformed_path,
                "malformed-signature.selection.json",
                cached_bindings=bundle,
            )

        noncanonical_bundle = self.root / "noncanonical-bundle.json"
        noncanonical_bundle.write_text(
            json.dumps(bundle, indent=2) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValidationError, "exact canonical JSON"):
            self._finalize_detached(
                noncanonical_bundle,
                signature_path,
                "noncanonical-bundle.selection.json",
                cached_bindings=bundle,
            )

    def test_detached_finalization_replays_live_inputs_and_csharp_context(self) -> None:
        context = base_selection_module.CSharpVerifierExecutionContext(
            self.root / "detached-verifier-authority.json",
            mock.sentinel.authority_trust,
            self.root,
        )
        aggregate = base_selection_module.aggregate_promotion_evidence
        seen_contexts: list[object] = []

        def aggregate_without_csharp_execution(**kwargs):
            seen_contexts.append(kwargs.pop("csharp_verifier_context"))
            return aggregate(**kwargs)

        with mock.patch.object(
            base_selection_module,
            "aggregate_promotion_evidence",
            side_effect=aggregate_without_csharp_execution,
        ):
            bundle_path, _, signature_path, _ = self._prepare_detached(
                "detached-live-replay",
                csharp_verifier_context=context,
            )
            finalized = self._finalize_detached(
                bundle_path,
                signature_path,
                "detached-live-replay.selection.json",
                csharp_verifier_context=context,
            )
        self.assertEqual(
            BASE_MODEL_SELECTION_ENVELOPE_SCHEMA_VERSION,
            finalized.envelope["schemaVersion"],
        )
        self.assertTrue(seen_contexts)
        self.assertTrue(all(item is context for item in seen_contexts))

        original_approval = self.approval_path.read_bytes()
        self.approval_path.write_bytes(original_approval + b"changed")
        try:
            with self.assertRaisesRegex(ValidationError, "approval evidence"):
                self._finalize_detached(
                    bundle_path,
                    signature_path,
                    "detached-drift.selection.json",
                    cached_bindings=json.loads(bundle_path.read_bytes()),
                )
        finally:
            self.approval_path.write_bytes(original_approval)

    def test_selection_signer_is_distinct_from_every_upstream_authority(self) -> None:
        review_trust = self.bound["review_receipt_trust"]
        authoring_trust = self.bound["evaluation_authoring_approval_trust"]
        review_alias = BaseModelSelectionTrust(
            public_key_path=review_trust.public_key_path,
            public_key_spki_sha256=review_trust.public_key_spki_sha256,
            audience=self.trust.audience,
            key_id=self.trust.key_id,
            signer_role=self.trust.signer_role,
        )
        prepare_values = {
            "output_path": self.root / "colliding-review.bundle.json",
            "approval_id": "base-approval-2026-07-28",
            "actor_id": "base-reviewer-17",
            "actor_role": self.trust.signer_role,
            "approval_reference": "VQ-BASE-2026-07-28",
            "approved_at_utc": "2026-07-28T09:00:00Z",
            "issued_at_utc": "2026-07-28T10:00:00Z",
            "not_before_utc": "2026-07-28T10:00:00Z",
            "expires_at_utc": "2026-08-28T10:00:00Z",
            "now": self.base.now,
            **self.source_arguments,
        }
        with self.assertRaisesRegex(ValidationError, "upstream review-receipt signer"):
            prepare_base_model_selection_signing_bundle(
                trust=review_alias,
                **prepare_values,
            )

        lineage_trust = TeacherMaterializationLineageAdmissionTrust(
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.spki_sha256,
            audience="teacher-lineage-review",
            key_id="teacher-lineage-key-v1",
            signer_role="teacher-lineage-reviewer",
        )
        review_with_colliding_lineage = replace(
            review_trust,
            teacher_lineage_admission_trust=lineage_trust,
        )
        prepare_values["output_path"] = self.root / "colliding-lineage.bundle.json"
        prepare_values["review_receipt_trust"] = review_with_colliding_lineage
        with self.assertRaisesRegex(
            ValidationError, "upstream teacher-lineage admission signer"
        ):
            prepare_base_model_selection_signing_bundle(
                trust=self.trust,
                **prepare_values,
            )

        authoring_alias = BaseModelSelectionTrust(
            public_key_path=authoring_trust.public_key_path,
            public_key_spki_sha256=authoring_trust.public_key_spki_sha256,
            audience=self.trust.audience,
            key_id=self.trust.key_id,
            signer_role=self.trust.signer_role,
        )
        prepare_values["output_path"] = self.root / "colliding-authoring.bundle.json"
        prepare_values["review_receipt_trust"] = review_trust
        with self.assertRaisesRegex(
            ValidationError, "upstream evaluation-authoring approval signer"
        ):
            prepare_base_model_selection_signing_bundle(
                trust=authoring_alias,
                **prepare_values,
            )

        created = self._create(self.root / "consumer-separation-selection.json")
        colliding_review_trust = replace(
            review_trust,
            public_key_path=self.public_key_path,
            public_key_spki_sha256=self.spki_sha256,
        )
        with self.assertRaisesRegex(ValidationError, "upstream review-receipt signer"):
            validate_base_model_selection_target(
                created.path,
                trust=self.trust,
                evaluation_authoring_approval_trust=authoring_trust,
                review_receipt_trust=colliding_review_trust,
                profile_path=self.base.profile_path,
                snapshot_manifest_path=self.base.manifest,
                snapshot_path=self.base.snapshot,
                catalog_path=self.base.catalog,
                source_lock_path=self.base.source_lock,
                now=self.base.now,
            )
        with self.assertRaisesRegex(
            ValidationError, "upstream teacher-lineage admission signer"
        ):
            validate_base_model_selection_target(
                created.path,
                trust=self.trust,
                evaluation_authoring_approval_trust=authoring_trust,
                review_receipt_trust=review_with_colliding_lineage,
                profile_path=self.base.profile_path,
                snapshot_manifest_path=self.base.manifest,
                snapshot_path=self.base.snapshot,
                catalog_path=self.base.catalog,
                source_lock_path=self.base.source_lock,
                now=self.base.now,
            )

    def test_canonical_envelope_and_fresh_installed_clock_are_mandatory(self) -> None:
        output = self.root / "expired-at-install-selection.json"
        expired = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

        def publication_clock(value, field):
            if "installed validation" in field or value == expired:
                return expired
            return self.base.now

        with (
            mock.patch.object(
                base_selection_module,
                "_fresh_validation_time",
                side_effect=publication_clock,
            ),
            self.assertRaisesRegex(ValidationError, "not currently active"),
        ):
            self._create(output)
        self.assertFalse(output.exists())

        valid = self._create(self.root / "canonical-envelope-selection.json")
        valid.path.write_bytes(canonical_json_bytes(valid.envelope) + b"\n")
        with self.assertRaisesRegex(ValidationError, "exact pretty JSON encoding"):
            verify_base_model_selection_envelope(
                valid.path,
                trust=self.trust,
                now=self.base.now,
            )

    def test_corpus_admission_expiry_after_final_validation_publishes_no_artifact(
        self,
    ) -> None:
        bundle = self._create_selected_bundle("corpus-admission-final-expiry")
        manifest_path = bundle / "training-run-manifest.json"
        expiry = datetime.strptime(
            self.corpus_admission_expires_at_utc, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        final_validation_complete = False
        real_validate = training_module.validate_training_artifact

        def validate_then_expire(*args, **kwargs):
            nonlocal final_validation_complete
            result = real_validate(*args, **kwargs)
            final_validation_complete = True
            return result

        def corpus_clock():
            return expiry if final_validation_complete else self.corpus_admission_now

        def fake_training(manifest, dependencies, records, output_path, **kwargs):
            self.harness_tests._write_safe_inference_files(output_path, manifest)

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch.object(
                training_module,
                "validate_training_artifact",
                side_effect=validate_then_expire,
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
            self.assertRaisesRegex(
                ValidationError,
                "training corpus admission expired during the run",
            ),
        ):
            training_module.train_from_manifest(
                manifest_path,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: True,
                importer=self.harness_tests._fake_training_importer(),
                _corpus_admission_clock=corpus_clock,
                **self._trainer_signing_arguments(),
            )
        self.assertTrue(final_validation_complete)
        self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_corpus_admission_expiry_during_training_publishes_no_artifact(
        self,
    ) -> None:
        bundle = self._create_selected_bundle("corpus-admission-expiry")
        manifest_path = bundle / "training-run-manifest.json"
        expiry = datetime.strptime(
            self.corpus_admission_expires_at_utc, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        ticks = iter((self.corpus_admission_now, expiry))

        def training_with_expiry(
            manifest,
            dependencies,
            records,
            output_path,
            *,
            authorization_guard,
            **kwargs,
        ):
            authorization_guard()
            authorization_guard()

        with (
            mock.patch.object(
                training_module,
                "_run_training",
                side_effect=training_with_expiry,
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
            self.assertRaisesRegex(
                ValidationError,
                "training corpus admission expired during the run",
            ),
        ):
            training_module.train_from_manifest(
                manifest_path,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: True,
                importer=self.harness_tests._fake_training_importer(),
                _corpus_admission_clock=ticks.__next__,
                **self._trainer_signing_arguments(),
            )
        self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_signed_corpus_admission_cannot_rebind_release_or_dataset(self) -> None:
        fixture = self.bound["fixture"]
        other_release = fixture._create(
            purpose="provider-training-evaluation",
            sft_path=self.bound["sft_path"],
            approval_id="TEST-CORPUS-ADMISSION-OTHER-RELEASE",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "exact expected release identity",
        ):
            self._create_selected_bundle(
                "corpus-admission-other-release",
                data_release_path=Path(other_release["releasePath"]),
            )

        alternate_sft = self.root / "alternate-dataset.sft.jsonl"
        row = json.loads(self.bound["sft_path"].read_text(encoding="utf-8"))
        alternate_sft.write_text(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assertNotEqual(
            self.bound["sft_path"].read_bytes(), alternate_sft.read_bytes()
        )
        alternate_release = fixture._create(
            purpose="provider-training-evaluation",
            sft_path=alternate_sft,
            approval_id="TEST-CORPUS-ADMISSION-OTHER-DATASET",
        )
        with self.assertRaisesRegex(
            ValidationError,
            "exact expected release identity|recomputed exact dataset report",
        ):
            self._create_selected_bundle(
                "corpus-admission-other-dataset",
                data_release_path=Path(alternate_release["releasePath"]),
                sft_path=alternate_sft,
            )

    def test_selected_snapshot_flows_through_promotion_and_readiness(self) -> None:
        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                if tz is None:
                    return self.base.now.replace(tzinfo=None)
                return self.base.now.astimezone(tz)

        FixedDateTime.base = self.base
        with mock.patch("vibe_quant_model.core.datetime", FixedDateTime):
            bundle = self._create_selected_bundle("production-selected-training")
        manifest_path = bundle / "training-run-manifest.json"
        manifest = validate_manifest_path(manifest_path)

        def fake_training(manifest, dependencies, records, output_path, **kwargs):
            self.harness_tests._write_safe_inference_files(output_path, manifest)

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch.object(training_module, "datetime", FixedDateTime),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
        ):
            training_module.train_from_manifest(
                manifest_path,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: path == self.base.snapshot,
                importer=self.harness_tests._fake_training_importer(),
                **self._trainer_signing_arguments(),
            )
        artifact_path = bundle / "outputs" / "adapter"
        profile_path = bundle / "serving-profile.json"
        profile = create_serving_profile(
            profile_id="selected-production-profile-v1",
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
            trainer_provenance_trust=self.trainer_provenance_trust,
            trainer_provenance_now=self.trainer_provenance_now,
        )

        candidate_responses = self.root / "selected-adapter.responses.jsonl"
        task_count = len(
            Path(self.paired["inputs"]["sealed_tasks_path"])
            .read_text(encoding="utf-8")
            .splitlines()
        )
        monotonic = iter(float(index) / 10 for index in range(task_count * 2))
        with mock.patch.dict(
            os.environ, {"VQ_TEST_KEY": "selected-production-test-key"}, clear=False
        ):
            capture_openai_responses(
                tasks_path=self.paired["inputs"]["sealed_tasks_path"],
                catalog_path=self.base.catalog,
                output_path=candidate_responses,
                serving_profile_path=profile_path,
                training_artifact_path=artifact_path,
                training_manifest_path=manifest_path,
                run_id="selected-adapter-evaluation-run-001",
                base_url="http://127.0.0.1/v1",
                api_key_env="VQ_TEST_KEY",
                seed=17,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                trainer_provenance_trust=self.trainer_provenance_trust,
                research_only=False,
                transport=self.evaluation._transport(),
                clock=lambda: self.base.now,
                monotonic=monotonic.__next__,
            )
        candidate_response = validate_evaluation_responses(
            candidate_responses, self.paired["inputs"]["sealed_tasks_path"]
        )[0]
        candidate_results = self.root / "selected-adapter.results.jsonl"
        run_release_verifiers(
            tasks_path=self.paired["inputs"]["sealed_tasks_path"],
            responses_path=candidate_responses,
            release_path=self.bound["release_path"],
            review_receipt_trust=self.bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=self.bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=self.bound["review_receipt_now"],
            output_path=candidate_results,
        )

        evaluation_tests = self._test_module("test_evaluation")
        promotion_inputs = dict(self.paired["inputs"])
        promotion_inputs["responses_path"] = candidate_responses
        promotion_inputs["verifier_results_path"] = candidate_results
        policy = json.loads(
            Path(promotion_inputs["policy_path"]).read_text(encoding="utf-8")
        )
        policy["candidateRun"] = evaluation_tests._identity(candidate_response)
        policy["policySha256"] = promotion_policy_sha256(policy)
        policy_path = self.root / "selected-adapter-policy.json"
        policy_path.write_bytes(canonical_json_bytes(policy) + b"\n")
        promotion_inputs["policy_path"] = policy_path
        report = aggregate_promotion_evidence(**promotion_inputs)
        report_path = self.root / "selected-adapter-promotion-evidence.json"
        report_path.write_bytes(canonical_json_bytes(report) + b"\n")

        promotion_tests = self._test_module("test_promotion")
        approval_path = self.root / "selected-adapter-approval.txt"
        approval_path.write_text(
            "Approved after exact selected-snapshot training and evaluation.\n",
            encoding="utf-8",
        )
        hosted_policy_path = self.root / "selected-adapter-hosted-policy.json"
        hosted_policy_path.write_bytes(
            canonical_json_bytes(promotion_tests._hosted_policy()) + b"\n"
        )
        promotion_private = ec.generate_private_key(ec.SECP256R1())
        promotion_private_path = self.root / "promotion-private.pem"
        promotion_private_path.write_bytes(
            promotion_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        promotion_public_path = self.root / "promotion-public.pem"
        promotion_public_path.write_bytes(
            promotion_private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        source_arguments = {
            "promotion_evidence_path": report_path,
            **promotion_inputs,
            "catalog_path": self.base.catalog,
            "serving_profile_path": profile_path,
            "artifact_path": artifact_path,
            "manifest_path": manifest_path,
            "approval_evidence_path": approval_path,
            "hosted_deployment_policy_path": hosted_policy_path,
            "base_selection_trust": self.trust,
            "base_model_snapshot_path": self.base.snapshot,
            "trainer_provenance_trust": self.trainer_provenance_trust,
            "trainer_provenance_now": self.trainer_provenance_now,
        }
        promotion_now = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
        promotion_path = self.root / "selected-adapter-promotion.json"
        created = create_model_promotion(
            output_path=promotion_path,
            private_key_path=promotion_private_path,
            public_key_path=promotion_public_path,
            private_key_password=None,
            audience="daxalgo-platform-prod",
            key_id="promotion-key-2026-09",
            signer_role="production-model-approver",
            deployment_id="vibe-quant-prod-eu1",
            environment="production",
            approval_id="approval-vq-2026-09-01",
            actor_id="reviewer-17",
            actor_role="production-model-approver",
            approval_reference="VQ-2026-09-01",
            approved_at_utc="2026-09-01T09:00:00Z",
            issued_at_utc="2026-09-01T10:00:00Z",
            not_before_utc="2026-09-01T10:00:00Z",
            expires_at_utc="2026-10-01T10:00:00Z",
            now=promotion_now,
            **source_arguments,
        )
        validated = validate_model_promotion(
            created.path,
            public_key_path=promotion_public_path,
            expected_audience="daxalgo-platform-prod",
            expected_key_id="promotion-key-2026-09",
            expected_signer_role="production-model-approver",
            expected_deployment_id="vibe-quant-prod-eu1",
            expected_environment="production",
            now=promotion_now,
            **source_arguments,
        )
        readiness = create_promoted_model_readiness_attestation(
            promotion_path=created.path,
            public_key_path=promotion_public_path,
            expected_audience="daxalgo-platform-prod",
            expected_promotion_key_id="promotion-key-2026-09",
            expected_signer_role="production-model-approver",
            expected_deployment_id="vibe-quant-prod-eu1",
            expected_environment="production",
            nonce="ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            readiness_key_id="readiness-key-v1",
            readiness_key=bytes(range(32)),
            now=promotion_now,
            **source_arguments,
        )

        self.assertEqual(MANIFEST_V3_SCHEMA_VERSION, manifest["schemaVersion"])
        self.assertEqual(
            profile.execution_model_id, validated.payload["model"]["executionModelId"]
        )
        self.assertEqual(created.payload_sha256, validated.payload_sha256)
        self.assertEqual(
            "daxalgo.vibe-quant.model-readiness/v2", readiness["schemaVersion"]
        )
        with self.assertRaisesRegex(ValidationError, "not currently active"):
            verify_base_model_selection_envelope(
                self.selection_path, trust=self.trust, now=promotion_now
            )

    def test_training_rejects_selection_rebound_to_another_valid_release(
        self,
    ) -> None:
        bundle = self._create_selected_bundle("cross-release-rebind")
        manifest_path = bundle / "training-run-manifest.json"
        fixture = self.bound["fixture"]
        other = fixture._create(
            purpose="provider-training-evaluation",
            sft_path=self.bound["sft_path"],
            approval_id="TEST-RELEASE-SELECTION-REBIND",
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["dataRelease"] = {
            "releaseId": other["releaseId"],
            "releaseSha256": other["releaseSha256"],
            "manifestSha256": other["manifestSha256"],
        }
        manifest.pop("runId")
        manifest["runId"] = (
            "vqrun-" + hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()[:20]
        )
        manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")

        with self.assertRaisesRegex(
            ValidationError,
            "does not match (the exact expected release identity|the manifest-bound training release)",
        ):
            training_module.train_from_manifest(
                manifest_path,
                data_release_path=other["releasePath"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: True,
                importer=lambda name: self.fail(
                    f"release-rebound manifest reached dependency import: {name}"
                ),
                **self._trainer_signing_arguments(),
            )
        self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_trainer_loaders_receive_only_the_exact_snapshot_directory(self) -> None:
        calls: list[tuple[str, str, dict]] = []

        class Tokenizer:
            pad_token = None
            eos_token = "<eos>"
            name_or_path = ""
            init_kwargs: dict[str, str] = {}

            def save_pretrained(self, output):
                return None

        class Model:
            name_or_path = ""
            config = SimpleNamespace(name_or_path="")

            def save_pretrained(self, output, safe_serialization=True):
                return None

        tokenizer = Tokenizer()
        model = Model()

        class AutoTokenizer:
            @staticmethod
            def from_pretrained(source, **kwargs):
                calls.append(("tokenizer", source, kwargs))
                return tokenizer

        class AutoModel:
            @staticmethod
            def from_pretrained(source, **kwargs):
                calls.append(("model", source, kwargs))
                return model

        class SftConfig:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class Trainer:
            def __init__(self, **kwargs):
                self.model = kwargs["model"]

            def train(self):
                return None

        dependencies = {
            "torch": SimpleNamespace(
                cuda=SimpleNamespace(is_bf16_supported=lambda: True)
            ),
            "transformers": SimpleNamespace(
                BitsAndBytesConfig=lambda **kwargs: kwargs,
                AutoTokenizer=AutoTokenizer,
                AutoModelForCausalLM=AutoModel,
                TrainerCallback=object,
            ),
            "datasets": SimpleNamespace(
                Dataset=SimpleNamespace(from_list=lambda records: records)
            ),
            "peft": SimpleNamespace(LoraConfig=lambda **kwargs: kwargs),
            "trl": SimpleNamespace(SFTConfig=SftConfig, SFTTrainer=Trainer),
        }
        manifest = {
            "baseModel": {
                "modelId": "Qwen/Qwen2.5-Coder-7B-Instruct",
                "revision": "a" * 40,
            },
            "chatTemplate": {
                "template": "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}{% endfor %}"
            },
            "hyperparameters": {
                "loraR": 8,
                "loraAlpha": 16,
                "loraDropout": 0.05,
                "loraTargetModules": ["q_proj"],
                "numTrainEpochs": 1,
                "learningRate": 0.0002,
                "perDeviceTrainBatchSize": 1,
                "gradientAccumulationSteps": 1,
                "warmupRatio": 0.03,
                "weightDecay": 0.0,
                "gradientCheckpointing": True,
                "optimizer": "paged_adamw_8bit",
                "lrScheduler": "cosine",
                "maxSequenceLength": 128,
            },
            "seed": 17,
        }
        guard_calls: list[bool] = []
        training_module._run_training(
            manifest,
            dependencies,
            [{"messages": []}],
            self.root / "loader-output",
            smoke=True,
            compute_dtype="torch.bfloat16",
            authorization_guard=lambda: None,
            model_source_path=self.base.snapshot,
            integrity_guard=lambda: guard_calls.append(True),
        )
        self.assertEqual(["tokenizer", "model"], [call[0] for call in calls])
        for _, source, kwargs in calls:
            self.assertEqual(str(self.base.snapshot), source)
            self.assertNotIn("revision", kwargs)
            self.assertTrue(kwargs["local_files_only"])
            self.assertFalse(kwargs["trust_remote_code"])
        self.assertEqual(2, len(guard_calls))

    def test_legacy_real_training_and_mutated_selected_snapshot_fail_closed(
        self,
    ) -> None:
        legacy_bundle = self.root / "legacy"
        template = self.root / "legacy-template.jinja"
        template.write_text(
            "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}",
            encoding="utf-8",
        )
        create_bundle(
            catalog_path=self.base.catalog,
            sft_path=self.bound["sft_path"],
            candidate_id="qwen2.5-coder-7b-instruct",
            chat_template_path=template,
            chat_template_name="legacy-template-v1",
            output_directory=legacy_bundle,
            runtime_profile_path=ROOT / "training-runtime-profile.v1.json",
            data_release_path=self.bound["release_path"],
            review_receipt_trust=self.bound["review_receipt_trust"],
            evaluation_authoring_approval_trust=self.bound[
                "evaluation_authoring_approval_trust"
            ],
            review_receipt_now=self.bound["review_receipt_now"],
        )
        legacy_manifest = validate_manifest_path(
            legacy_bundle / "training-run-manifest.json"
        )
        self.assertEqual(MANIFEST_SCHEMA_VERSION, legacy_manifest["schemaVersion"])
        with self.assertRaisesRegex(ValidationError, "legacy v1 manifests"):
            training_module.train_from_manifest(
                legacy_bundle / "training-run-manifest.json",
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                importer=lambda name: None,
            )

        selected_bundle = self._create_selected_bundle("mutated-training")
        manifest_path = selected_bundle / "training-run-manifest.json"
        original = (self.base.snapshot / "model.safetensors").read_bytes()

        def mutate_training(manifest, dependencies, records, output_path, **kwargs):
            self.harness_tests._write_safe_inference_files(output_path, manifest)
            (self.base.snapshot / "model.safetensors").write_bytes(original + b"tamper")

        try:
            with (
                mock.patch.object(
                    training_module, "_run_training", side_effect=mutate_training
                ),
                mock.patch(
                    "vibe_quant_model.runtime.runtime_facts",
                    return_value=self.harness_tests._locked_runtime_facts(),
                ),
                mock.patch(
                    "vibe_quant_model.runtime.runtime_host_facts",
                    return_value=self.harness_tests._locked_runtime_host_facts(),
                ),
            ):
                with self.assertRaisesRegex(
                    ValidationError, "sealed file tree|source lock|data ranges"
                ):
                    training_module.train_from_manifest(
                        manifest_path,
                        data_release_path=self.bound["release_path"],
                        review_receipt_trust=self.bound["review_receipt_trust"],
                        evaluation_authoring_approval_trust=self.bound[
                            "evaluation_authoring_approval_trust"
                        ],
                        review_receipt_now=self.bound["review_receipt_now"],
                        base_model_snapshot_path=self.base.snapshot,
                        base_selection_trust=self.trust,
                        base_selection_now=self.base.now,
                        snapshot_read_only_probe=lambda path: True,
                        importer=self.harness_tests._fake_training_importer(),
                        **self._trainer_signing_arguments(),
                    )
        finally:
            (self.base.snapshot / "model.safetensors").write_bytes(original)
        self.assertFalse((selected_bundle / "outputs" / "adapter").exists())
        self.assertTrue(
            (selected_bundle / TRAINING_RUNTIME_PROFILE_BUNDLE_PATH).is_file()
        )

    def test_trainer_provenance_mutation_after_seal_publishes_no_artifact(
        self,
    ) -> None:
        bundle = self._create_selected_bundle("trainer-mutation-after-seal")
        manifest_path = bundle / "training-run-manifest.json"
        real_seal = training_module.seal_training_artifact

        def fake_training(manifest, dependencies, records, output_path, **kwargs):
            self.harness_tests._write_safe_inference_files(output_path, manifest)

        def seal_then_mutate(*args, **kwargs):
            result = real_seal(*args, **kwargs)
            metadata_path = Path(args[0]) / "artifact-metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["trainerProvenance"]["signature"] = "A" * 86
            metadata["artifactSha256"] = training_artifact_sha256(metadata)
            metadata_path.write_bytes(canonical_json_bytes(metadata) + b"\n")
            return result

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch.object(
                training_module,
                "seal_training_artifact",
                side_effect=seal_then_mutate,
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
            self.assertRaisesRegex(ValidationError, "signature"),
        ):
            training_module.train_from_manifest(
                manifest_path,
                data_release_path=self.bound["release_path"],
                review_receipt_trust=self.bound["review_receipt_trust"],
                evaluation_authoring_approval_trust=self.bound[
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=self.bound["review_receipt_now"],
                base_model_snapshot_path=self.base.snapshot,
                base_selection_trust=self.trust,
                base_selection_now=self.base.now,
                snapshot_read_only_probe=lambda path: True,
                importer=self.harness_tests._fake_training_importer(),
                **self._trainer_signing_arguments(),
            )

        self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_invalid_trainer_signing_authority_fails_before_training(self) -> None:
        bundle = self._create_selected_bundle("trainer-authority-preflight")
        manifest_path = bundle / "training-run-manifest.json"
        mismatched_key = ec.generate_private_key(ec.SECP256R1())
        mismatched_key_path = self.root / "mismatched-trainer-private.pem"
        mismatched_key_path.write_bytes(
            mismatched_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        scenarios = {
            "wrong-spki": {
                "trainer_provenance_trust": replace(
                    self.trainer_provenance_trust,
                    public_key_spki_sha256="0" * 64,
                )
            },
            "mismatched-key": {"trainer_private_key_path": mismatched_key_path},
            "wrong-password": {"trainer_private_key_password": b"wrong-password"},
            "expired": {"trainer_expires_at_utc": "2026-07-28T10:00:05Z"},
        }

        for name, overrides in scenarios.items():
            with self.subTest(name=name):
                signing = self._trainer_signing_arguments()
                signing.update(overrides)
                importer = mock.Mock(
                    side_effect=AssertionError("dependency import must not run")
                )
                with (
                    mock.patch.object(training_module, "_run_training") as runner,
                    self.assertRaises(ValidationError),
                ):
                    training_module.train_from_manifest(
                        manifest_path,
                        data_release_path=self.bound["release_path"],
                        review_receipt_trust=self.bound["review_receipt_trust"],
                        evaluation_authoring_approval_trust=self.bound[
                            "evaluation_authoring_approval_trust"
                        ],
                        review_receipt_now=self.bound["review_receipt_now"],
                        base_model_snapshot_path=self.base.snapshot,
                        base_selection_trust=self.trust,
                        base_selection_now=self.base.now,
                        snapshot_read_only_probe=lambda path: True,
                        importer=importer,
                        **signing,
                    )
                importer.assert_not_called()
                runner.assert_not_called()
                self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_selection_expiry_during_training_publishes_no_artifact(self) -> None:
        bundle = self._create_selected_bundle("selection-expiry")
        manifest_path = bundle / "training-run-manifest.json"
        expiry = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
        ticks = iter((self.base.now, expiry))

        def training_with_expiry(
            manifest,
            dependencies,
            records,
            output_path,
            *,
            authorization_guard,
            **kwargs,
        ):
            authorization_guard()
            authorization_guard()

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=training_with_expiry
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
        ):
            with self.assertRaisesRegex(
                ValidationError, "selection authorization expired"
            ):
                training_module.train_from_manifest(
                    manifest_path,
                    data_release_path=self.bound["release_path"],
                    review_receipt_trust=self.bound["review_receipt_trust"],
                    evaluation_authoring_approval_trust=self.bound[
                        "evaluation_authoring_approval_trust"
                    ],
                    review_receipt_now=self.bound["review_receipt_now"],
                    base_model_snapshot_path=self.base.snapshot,
                    base_selection_trust=self.trust,
                    base_selection_now=self.base.now,
                    snapshot_read_only_probe=lambda path: True,
                    importer=self.harness_tests._fake_training_importer(),
                    _base_selection_clock=ticks.__next__,
                    **self._trainer_signing_arguments(),
                )
        self.assertFalse((bundle / "outputs" / "adapter").exists())

    def test_selection_expiry_during_artifact_sealing_publishes_no_artifact(
        self,
    ) -> None:
        bundle = self._create_selected_bundle("selection-expiry-during-seal")
        manifest_path = bundle / "training-run-manifest.json"
        expiry = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
        expired = False
        real_seal = training_module.seal_training_artifact

        def fake_training(manifest, dependencies, records, output_path, **kwargs):
            self.harness_tests._write_safe_inference_files(output_path, manifest)

        def seal_then_expire(*args, **kwargs):
            nonlocal expired
            result = real_seal(*args, **kwargs)
            expired = True
            return result

        with (
            mock.patch.object(
                training_module, "_run_training", side_effect=fake_training
            ),
            mock.patch.object(
                training_module,
                "seal_training_artifact",
                side_effect=seal_then_expire,
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_facts",
                return_value=self.harness_tests._locked_runtime_facts(),
            ),
            mock.patch(
                "vibe_quant_model.runtime.runtime_host_facts",
                return_value=self.harness_tests._locked_runtime_host_facts(),
            ),
        ):
            with self.assertRaisesRegex(
                ValidationError, "selection authorization expired"
            ):
                training_module.train_from_manifest(
                    manifest_path,
                    data_release_path=self.bound["release_path"],
                    review_receipt_trust=self.bound["review_receipt_trust"],
                    evaluation_authoring_approval_trust=self.bound[
                        "evaluation_authoring_approval_trust"
                    ],
                    review_receipt_now=self.bound["review_receipt_now"],
                    base_model_snapshot_path=self.base.snapshot,
                    base_selection_trust=self.trust,
                    base_selection_now=self.base.now,
                    snapshot_read_only_probe=lambda path: True,
                    importer=self.harness_tests._fake_training_importer(),
                    _base_selection_clock=lambda: expiry if expired else self.base.now,
                    **self._trainer_signing_arguments(),
                )
        self.assertFalse((bundle / "outputs" / "adapter").exists())


if __name__ == "__main__":
    unittest.main()
