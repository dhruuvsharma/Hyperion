from __future__ import annotations

import hashlib
import importlib
import json
import os
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr
from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Mapping
from unittest import mock

import vibe_quant_model.cli as cli_module
import vibe_quant_model.engine_wrapper as wrapper_module
import vibe_quant_model.promotion as promotion_module
import vibe_quant_model.verifier_runtime as verifier_runtime_module
from vibe_quant_model.base_engine_wrapper import BaseEngineActivationTrust
from vibe_quant_model.base_evaluation import BaseEvaluationProfile, BaseModelSnapshot
from vibe_quant_model.base_selection import (
    BaseModelSelectionTrust,
    VerifiedBaseModelSelection,
    VerifiedBaseModelSelectionTarget,
)
from vibe_quant_model.core import (
    ValidatedManifestSnapshot,
    ValidationError,
    canonical_json_bytes,
    validate_manifest_snapshot,
)
from vibe_quant_model.deployment import (
    EXECUTION_MODEL_PREFIX,
    MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
    ServingProfile,
    validate_model_readiness_v2_attestation,
)
from vibe_quant_model.engine_wrapper import (
    CHAT_COMPLETIONS_PATH,
    ENGINE_WRAPPER_SCHEMA_VERSION,
    ENGINE_WRAPPER_V2_SCHEMA_VERSION,
    ENGINE_WRAPPER_V3_SCHEMA_VERSION,
    ENGINE_WRAPPER_V4_SCHEMA_VERSION,
    ENGINE_WRAPPER_V5_SCHEMA_VERSION,
    ENGINE_WRAPPER_V6_SCHEMA_VERSION,
    ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    READINESS_PATH,
    BaseSnapshotConfig,
    EngineConfig,
    EngineWrapperConfig,
    PromotionConfig,
    PromotedModelEngineWrapper,
    ServiceConfig,
    TransportResponse,
    WrapperState,
    load_engine_wrapper_config,
)
from vibe_quant_model.evaluation import (
    BaseResponseAttestationTrust,
    aggregate_promotion_evidence,
    write_json_atomic_no_clobber,
)
from vibe_quant_model.evaluation_authoring import EvaluationAuthoringApprovalTrust
from vibe_quant_model.promotion import (
    PromotionActivationInputs,
    VerifiedModelPromotion,
    create_model_promotion,
    create_promoted_model_readiness_attestation,
    validate_model_promotion,
)
from vibe_quant_model.review_receipts import ExpertModelReviewReceiptTrust
from vibe_quant_model.trainer_provenance import TrainerProvenanceTrust
from vibe_quant_model.verifier_authority import CSharpVerifierAuthorityTrust
from vibe_quant_model.verifier_replay_audit import (
    CSharpVerifierReplayAuditTrust,
    create_csharp_verifier_replay_audit,
)
from vibe_quant_model.verifier_runtime import CSharpVerifierExecutionContext

_NOW = "2026-07-28T10:00:00Z"
_NONCE = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"


class _FakeProcess:
    def __init__(self) -> None:
        self.pid = 4242
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise TimeoutError
        return self.returncode


class _RefusingProcess(_FakeProcess):
    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        raise TimeoutError


class _GroupAwareProcess(_FakeProcess):
    def __init__(self) -> None:
        super().__init__()
        self.group_stop_calls = 0

    def ensure_process_group_stopped(self, timeout: float) -> None:
        self.group_stop_calls += 1
        if timeout <= 0:
            raise AssertionError("process-group timeout must be positive")


class EngineWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / "vllm-test"
        self.executable.write_bytes(b"pinned vllm executable")
        self.executable.chmod(0o555)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        self.profile_path = self.root / "serving-profile.json"
        self.profile_path.write_text("{}", encoding="utf-8")
        self.promotion_path = self.root / "promotion.json"
        self.promotion_path.write_text("{}", encoding="utf-8")
        self.public_key = self.root / "public.pem"
        self.public_key.write_text("public", encoding="utf-8")
        self.review_receipt_trust = ExpertModelReviewReceiptTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256="a" * 64,
            audience="daxalgo-vibe-quant-training",
            key_id="review-key-v1",
            signer_role="expert-review-authority",
        )
        self.evaluation_authoring_approval_trust = EvaluationAuthoringApprovalTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256="7" * 64,
            audience="daxalgo-vibe-quant-evaluation-authoring",
            key_id="evaluation-authoring-key-v1",
            signer_role="evaluation-authoring-reviewer",
        )
        self.trainer_provenance_trust = TrainerProvenanceTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256="8" * 64,
            audience="daxalgo-vibe-quant-trainer-provenance",
            key_id="trainer-provenance-key-v1",
            signer_role="model-training-authority",
        )
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text("{}", encoding="utf-8")
        self.base_snapshot = self.root / "base-snapshot"
        self.base_snapshot.mkdir()
        self.base_snapshot.joinpath("config.json").write_text("{}", encoding="utf-8")
        self.base_selection_trust = BaseModelSelectionTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256="9" * 64,
            audience="daxalgo-vibe-quant-base-selection",
            key_id="base-selection-key-v1",
            signer_role="base-model-selection-authority",
        )
        self.image_digest = "sha256:" + "a" * 64
        self.profile_sha256 = "1" * 64
        self.execution_model_id = EXECUTION_MODEL_PREFIX + self.profile_sha256
        self.executable_sha256 = hashlib.sha256(b"pinned vllm executable").hexdigest()
        self.envelope_sha256 = "3" * 64
        self.payload_sha256 = "4" * 64
        self.artifact_sha256 = "5" * 64
        self.tree_sha256 = "6" * 64
        self.policy_sha256 = "7" * 64
        self.manifest_sha256 = "a" * 64
        self.base_selection_payload_sha256 = "b" * 64
        self.base_profile_sha256 = "c" * 64
        self.base_snapshot_sha256 = "d" * 64
        self.base_file_tree_sha256 = "e" * 64
        self.base_execution_model_id = "daxalgo-vq-base-" + "f" * 64
        self.bearer = "B" * 48
        self.hmac_key = bytes(range(32))

        selected_payload = {"selectionId": "vqbase-selection-test"}
        selected = VerifiedBaseModelSelection(
            path=self.root / "base-model-selection.json",
            envelope={
                "publicKeySpkiSha256": (
                    self.base_selection_trust.public_key_spki_sha256
                )
            },
            payload=selected_payload,
            payload_bytes=canonical_json_bytes(selected_payload),
            payload_sha256=self.base_selection_payload_sha256,
            envelope_sha256="0" * 64,
        )
        base_profile = BaseEvaluationProfile(
            path=self.root / "base-evaluation-profile.json",
            sha256=self.base_profile_sha256,
            execution_model_id=self.base_execution_model_id,
            document={},
        )
        base_snapshot = BaseModelSnapshot(
            manifest_path=self.root / "base-model-snapshot-manifest.json",
            manifest_sha256="1" * 64,
            snapshot_path=self.base_snapshot,
            document={
                "snapshotSha256": self.base_snapshot_sha256,
                "fileTreeSha256": self.base_file_tree_sha256,
            },
        )
        manifest_document = {
            "createdAtUtc": "2026-07-27T08:00:00Z",
            "hyperparameters": {"loraR": 64},
        }
        self.manifest_snapshot = ValidatedManifestSnapshot(
            path=self.manifest,
            raw=canonical_json_bytes(manifest_document),
            sha256=self.manifest_sha256,
            document=manifest_document,
        )
        self.selected_base = VerifiedBaseModelSelectionTarget(
            selection=selected,
            profile=base_profile,
            snapshot=base_snapshot,
            manifest_snapshot=self.manifest_snapshot,
        )

        self.profile = ServingProfile(
            path=self.profile_path,
            sha256=self.profile_sha256,
            execution_model_id=self.execution_model_id,
            document={
                "profileId": "prod-profile",
                "baseModel": {
                    "modelId": "Qwen/Qwen2.5-Coder-7B-Instruct",
                    "revision": "a" * 40,
                },
                "trainingArtifact": {
                    "artifactSha256": self.artifact_sha256,
                    "artifactTreeSha256": self.tree_sha256,
                },
                "runtime": {
                    "engine": "vllm",
                    "engineVersion": "0.10.0",
                    "containerImageDigest": self.image_digest,
                    "quantization": "bitsandbytes-nf4",
                    "computeDtype": "bfloat16",
                    "maxModelLength": 8192,
                    "tensorParallelSize": 1,
                },
            },
        )
        self.verified = self._verified(self.envelope_sha256)
        source_names = (
            "promotion_evidence_path",
            "calibration_tasks_path",
            "calibration_evidence_path",
            "sealed_tasks_path",
            "responses_path",
            "verifier_results_path",
            "baseline_responses_path",
            "baseline_verifier_results_path",
            "policy_path",
            "data_release_path",
            "catalog_path",
            "serving_profile_path",
            "artifact_path",
            "manifest_path",
            "approval_evidence_path",
            "hosted_deployment_policy_path",
        )
        sources = {name: self.manifest for name in source_names}
        sources["artifact_path"] = self.artifact
        sources["data_release_path"] = self.artifact
        sources["serving_profile_path"] = self.profile_path
        sources["manifest_path"] = self.manifest
        self.config = EngineWrapperConfig(
            path=self.root / "wrapper.json",
            promotion=PromotionConfig(
                path=self.promotion_path,
                public_key_path=self.public_key,
                review_receipt_trust=self.review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    self.evaluation_authoring_approval_trust
                ),
                trainer_provenance_trust=self.trainer_provenance_trust,
                expected_audience="daxalgo-platform-prod",
                expected_key_id="promotion-key-v1",
                expected_signer_role="production-approver",
                expected_deployment_id="vibe-quant-prod-eu1",
                expected_environment="production",
                expected_envelope_sha256=self.envelope_sha256,
                expected_serving_profile_sha256=self.profile_sha256,
                sources=sources,
            ),
            engine=EngineConfig(
                executable_path=self.executable,
                executable_sha256=self.executable_sha256,
                container_image_digest_environment="CURRENT_IMAGE_DIGEST",
                child_host="127.0.0.1",
                child_port=18081,
                startup_timeout_seconds=1,
                health_interval_seconds=1,
                integrity_interval_seconds=1,
                request_timeout_seconds=1,
                shutdown_grace_seconds=0,
                environment_allowlist=("PATH", "CUDA_VISIBLE_DEVICES"),
                child_user_id=10001,
                child_group_id=10001,
            ),
            service=ServiceConfig(
                listen_host="127.0.0.1",
                listen_port=18080,
                bearer_token_environment="OUTER_BEARER_SECRET",
                readiness_hmac_key_environment="READINESS_HMAC_SECRET",
                readiness_key_id="readiness-key-v1",
                max_request_bytes=100_000,
                max_response_bytes=100_000,
            ),
            base_snapshot=BaseSnapshotConfig(
                snapshot_path=self.base_snapshot,
                selection_trust=self.base_selection_trust,
            ),
        )
        self.environment = mock.patch.dict(
            os.environ,
            {
                "CURRENT_IMAGE_DIGEST": self.image_digest,
                "OUTER_BEARER_SECRET": self.bearer,
                "READINESS_HMAC_SECRET": "secret-must-not-reach-child",
                "CUDA_VISIBLE_DEVICES": "0",
            },
            clear=False,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.promotion_validation = mock.patch.object(
            wrapper_module, "validate_model_promotion", return_value=self.verified
        )
        self.file_hash = mock.patch.object(
            wrapper_module, "sha256_file", return_value=self.executable_sha256
        )
        self.promotion_mock = self.promotion_validation.start()
        self.file_hash.start()
        self.addCleanup(self.promotion_validation.stop)
        self.addCleanup(self.file_hash.stop)
        self.process = _FakeProcess()
        self.process_arguments: tuple[str, ...] | None = None
        self.process_environment: Mapping[str, str] | None = None
        self.process_descriptor_inode: int | None = None
        self.transport_calls: list[
            tuple[str, str, Mapping[str, str], bytes | None]
        ] = []

    def _verified(self, envelope_sha256: str) -> VerifiedModelPromotion:
        payload = {
            "promotionId": "vqprom-test",
            "dataRelease": {"releaseId": "vq-release-test"},
            "model": {
                "servingProfileSha256": self.profile_sha256,
                "artifactSha256": self.artifact_sha256,
                "artifactTreeSha256": self.tree_sha256,
                "executionModelId": self.execution_model_id,
                "containerImageDigest": self.image_digest,
                "trainingRunManifestSha256": self.manifest_sha256,
            },
            "deployment": {"deploymentId": "vibe-quant-prod-eu1"},
            "hostedDeploymentPolicy": {
                "providerId": "daxalgo-private",
                "policySha256": self.policy_sha256,
                "execution": {"maxOutputTokensPerRequest": 4096},
            },
            "notBeforeUtc": "2026-07-28T09:00:00Z",
            "expiresAtUtc": "2026-08-28T10:00:00Z",
        }
        return VerifiedModelPromotion(
            path=self.promotion_path,
            envelope={},
            payload=payload,
            payload_bytes=canonical_json_bytes(payload),
            payload_sha256=self.payload_sha256,
            envelope_sha256=envelope_sha256,
            activation_inputs=PromotionActivationInputs(
                manifest_snapshot=self.manifest_snapshot,
                selected_base=self.selected_base,
                artifact={"recordedAtUtc": "2026-07-27T09:00:00Z"},
                profile=self.profile,
                authority_expires_at_utc="2026-08-15T10:00:00Z",
                evaluation_authoring_approval_payload_sha256="1" * 64,
                evaluation_authoring_approval_envelope_sha256="2" * 64,
                trainer_provenance_payload_sha256="3" * 64,
                trainer_provenance_envelope_sha256="4" * 64,
                trainer_provenance_expires_at_utc="2026-08-20T10:00:00Z",
            ),
        )

    def _process_factory(
        self,
        executable_fd: int,
        argv: list[str] | tuple[str, ...],
        environment: Mapping[str, str],
        cwd: Path,
    ) -> _FakeProcess:
        self.process_descriptor_inode = os.fstat(executable_fd).st_ino
        self.process_arguments = tuple(argv)
        self.process_environment = dict(environment)
        self.assertEqual(self.executable.parent, cwd)
        return self.process

    def _transport(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        maximum: int,
    ) -> TransportResponse:
        self.transport_calls.append((method, url, dict(headers), body))
        self.assertEqual("Bearer " + "I" * 48, headers.get("Authorization"))
        if url.endswith("/health"):
            return TransportResponse(200, {}, b"", url)
        if url.endswith("/version"):
            return TransportResponse(
                200,
                {"Content-Type": "application/json"},
                canonical_json_bytes({"version": "0.10.0"}),
                url,
            )
        if url.endswith("/v1/models"):
            return TransportResponse(
                200,
                {"Content-Type": "application/json"},
                canonical_json_bytes(
                    {
                        "object": "list",
                        "data": [
                            {
                                "id": self.base_execution_model_id,
                                "root": os.fspath(self.base_snapshot),
                                "parent": None,
                                "max_model_len": 8192,
                            },
                            {
                                "id": self.execution_model_id,
                                "root": os.fspath(self.artifact),
                                "parent": self.base_execution_model_id,
                            },
                        ],
                    }
                ),
                url,
            )
        self.assertEqual("POST", method)
        self.assertEqual(CHAT_COMPLETIONS_PATH, "/" + url.split("/", 3)[-1])
        request = json.loads((body or b"").decode("utf-8"))
        self.assertFalse(request["stream"])
        return TransportResponse(
            200,
            {"Content-Type": "application/json"},
            canonical_json_bytes(
                {
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "model": self.execution_model_id,
                    "choices": [],
                }
            ),
            url,
        )

    def _wrapper(
        self,
        config: EngineWrapperConfig | None = None,
        **overrides: object,
    ) -> PromotedModelEngineWrapper:
        arguments = {
            "transport": self._transport,
            "process_factory": self._process_factory,
            "child_api_key": "I" * 48,
            "clock": lambda: wrapper_module.datetime.fromisoformat(
                _NOW.replace("Z", "+00:00")
            ),
            "sleeper": lambda _: None,
            "read_only_probe": lambda _: True,
            "listener_ownership_probe": lambda *_: True,
            "privilege_isolation_probe": lambda _: True,
            "child_privilege_probe": lambda *_: True,
        }
        arguments.update(overrides)
        return PromotedModelEngineWrapper(
            config or self.config,
            bearer_token=self.bearer,
            readiness_hmac_key=self.hmac_key,
            **arguments,
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.bearer}",
            "Content-Type": "application/json",
        }

    def test_default_factory_executes_opened_inode_as_isolated_child(self) -> None:
        popen = mock.Mock()
        popen.pid = 5150
        with (
            mock.patch.object(
                wrapper_module, "_opened_fd_path", return_value="/proc/self/fd/7"
            ),
            mock.patch.object(
                wrapper_module.subprocess, "Popen", return_value=popen
            ) as popen_factory,
        ):
            owned = wrapper_module._default_process_factory(
                7,
                ("/configured/vllm", "serve"),
                {"PATH": "/runtime/bin"},
                self.root,
                child_user_id=10001,
                child_group_id=10002,
            )

        self.assertEqual(5150, owned.pid)
        arguments, keywords = popen_factory.call_args
        self.assertEqual([["/configured/vllm", "serve"]], list(arguments))
        self.assertEqual("/proc/self/fd/7", keywords["executable"])
        self.assertEqual((7,), keywords["pass_fds"])
        self.assertEqual(10001, keywords["user"])
        self.assertEqual(10002, keywords["group"])
        self.assertEqual([], keywords["extra_groups"])
        self.assertEqual(0o077, keywords["umask"])
        self.assertTrue(keywords["start_new_session"])
        self.assertFalse(keywords["shell"])

    def test_default_child_privilege_probe_requires_exact_credentials(self) -> None:
        status = {
            "Uid": "10001 10001 10001 10001",
            "Gid": "10001 10001 10001 10001",
            "Groups": "",
            "NoNewPrivs": "1",
            "CapInh": "0000000000000000",
            "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000",
            "CapAmb": "0000000000000000",
        }
        with (
            mock.patch.object(wrapper_module.os, "name", "posix"),
            mock.patch.object(wrapper_module, "_proc_status", return_value=status),
        ):
            self.assertTrue(
                wrapper_module._default_child_privilege_probe(4242, self.config.engine)
            )
            status["CapEff"] = "0000000000000001"
            self.assertFalse(
                wrapper_module._default_child_privilege_probe(4242, self.config.engine)
            )
            status["CapEff"] = "0000000000000000"
            status["NoNewPrivs"] = "0"
            self.assertFalse(
                wrapper_module._default_child_privilege_probe(4242, self.config.engine)
            )

    def test_launch_is_deterministic_secret_free_and_serves_bound_requests(
        self,
    ) -> None:
        wrapper = self._wrapper()
        snapshot = wrapper.start(start_monitor=False)
        self.addCleanup(wrapper.stop)

        self.assertEqual(WrapperState.READY, wrapper.state)
        self.assertEqual(self.execution_model_id, snapshot.execution_model_id)
        self.assertIsNotNone(self.process_arguments)
        self.assertIsNotNone(self.process_descriptor_inode)
        argv = self.process_arguments or ()
        self.assertEqual(os.fspath(self.executable), argv[0])
        self.assertEqual(("serve", os.fspath(self.base_snapshot)), argv[1:3])
        served_name = argv.index("--served-model-name")
        self.assertEqual(self.base_execution_model_id, argv[served_name + 1])
        tokenizer = argv.index("--tokenizer")
        self.assertEqual(os.fspath(self.base_snapshot), argv[tokenizer + 1])
        self.assertNotIn("--revision", argv)
        self.assertNotIn(
            self.profile.document["baseModel"]["modelId"],
            argv,
        )
        self.assertIn("--enable-lora", argv)
        self.assertIn(f"{self.execution_model_id}={self.artifact}", argv)
        self.assertNotIn("--trust-remote-code", argv)
        child_environment = self.process_environment or {}
        self.assertEqual("0", child_environment["CUDA_VISIBLE_DEVICES"])
        self.assertNotIn("OUTER_BEARER_SECRET", child_environment)
        self.assertNotIn("READINESS_HMAC_SECRET", child_environment)
        self.assertNotIn("CURRENT_IMAGE_DIGEST", child_environment)
        self.assertNotIn(self.bearer, child_environment.values())
        self.assertEqual("I" * 48, child_environment["VLLM_API_KEY"])
        self.assertEqual("1", child_environment["HF_HUB_DISABLE_TELEMETRY"])
        self.assertEqual("", child_environment["VLLM_PLUGINS"])
        self.assertIn("--tokenizer", argv)
        self.assertIn("--max-loras", argv)
        self.assertIn("--max-lora-rank", argv)
        self.assertIn("64", argv)

        readiness_headers = self._headers()
        readiness_headers["Content-Type"] = "application/json; charset=utf-8"
        readiness = wrapper.handle_http_request(
            "POST",
            READINESS_PATH,
            readiness_headers,
            canonical_json_bytes(
                {
                    "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                    "audience": "daxalgo-platform-prod",
                    "nonce": _NONCE,
                }
            ),
        )
        self.assertEqual(200, readiness.status)
        readiness_value = json.loads(readiness.body)
        validate_model_readiness_v2_attestation(
            readiness_value,
            key=self.hmac_key,
            audience="daxalgo-platform-prod",
            expected_nonce=_NONCE,
            expected_key_id="readiness-key-v1",
            serving_profile_sha256=self.profile_sha256,
            artifact_sha256=self.artifact_sha256,
            artifact_tree_sha256=self.tree_sha256,
            execution_model_id=self.execution_model_id,
            promotion_envelope_sha256=self.envelope_sha256,
            promotion_payload_sha256=self.payload_sha256,
            deployment_id="vibe-quant-prod-eu1",
            provider_id="daxalgo-private",
            hosted_deployment_policy_sha256=self.policy_sha256,
            expires_at_utc="2026-08-28T10:00:00Z",
        )
        wrapper.monitor_once(validate_integrity=True)
        expected_now = wrapper_module.datetime.fromisoformat(
            _NOW.replace("Z", "+00:00")
        )
        self.assertGreaterEqual(self.promotion_mock.call_count, 3)
        for call in self.promotion_mock.call_args_list:
            self.assertIs(
                self.review_receipt_trust,
                call.kwargs["review_receipt_trust"],
            )
            self.assertIs(
                self.evaluation_authoring_approval_trust,
                call.kwargs["evaluation_authoring_approval_trust"],
            )
            self.assertEqual(expected_now, call.kwargs["review_receipt_now"])
            self.assertEqual(expected_now, call.kwargs["now"])
            self.assertIs(
                self.base_selection_trust,
                call.kwargs["base_selection_trust"],
            )
            self.assertEqual(
                self.base_snapshot,
                call.kwargs["base_model_snapshot_path"],
            )

        chat = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "model": self.execution_model_id,
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 128,
                    "temperature": 0,
                }
            ),
        )
        self.assertEqual(200, chat.status)
        self.assertEqual(self.execution_model_id, json.loads(chat.body)["model"])

    def test_signed_csharp_replay_audit_and_strategy_policy_reach_v7_activation(
        self,
    ) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError as error:  # pragma: no cover - optional dependency CI
            self.skipTest(f"optional promotion dependency unavailable: {error}")

        try:
            evaluation_tests = importlib.import_module("test_evaluation")
            promotion_tests = importlib.import_module("test_promotion")
            release_tests = importlib.import_module("test_release")
            runtime_tests = importlib.import_module("test_verifier_runtime")
        except ModuleNotFoundError:
            evaluation_tests = importlib.import_module("tests.test_evaluation")
            promotion_tests = importlib.import_module("tests.test_promotion")
            release_tests = importlib.import_module("tests.test_release")
            runtime_tests = importlib.import_module("tests.test_verifier_runtime")

        evaluation = evaluation_tests.EvaluationTests()
        evaluation.setUp()
        self.addCleanup(evaluation.doCleanups)
        authority = runtime_tests._authority("1")
        authority_path = evaluation.root / "csharp-authority.json"
        authority_trust = CSharpVerifierAuthorityTrust(
            evaluation.root / "csharp-authority-public.pem",
            "e" * 64,
            "verifier-audience",
            "verifier-key",
            "verifier-authority",
        )
        audit_workspace = evaluation.root / "csharp-audit-work"
        audit_workspace.mkdir()
        csharp_context = CSharpVerifierExecutionContext(
            authority_path,
            authority_trust,
            audit_workspace,
        )

        with (
            mock.patch.object(
                evaluation_tests,
                "create_bundle",
                side_effect=promotion_tests._causally_ordered_bundle_creator(
                    evaluation_tests.create_bundle
                ),
            ),
            mock.patch.multiple(
                release_tests,
                APPROVED=promotion_tests._PROMOTION_RELEASE_APPROVED,
                RECEIPT_ISSUED=promotion_tests._PROMOTION_RECEIPT_ISSUED,
                RECEIPT_NOT_BEFORE=promotion_tests._PROMOTION_RECEIPT_NOT_BEFORE,
                RECEIPT_EXPIRES=promotion_tests._PROMOTION_RECEIPT_EXPIRES,
                AUTHORING_APPROVED=promotion_tests._PROMOTION_AUTHORING_APPROVED,
                AUTHORING_ISSUED=promotion_tests._PROMOTION_AUTHORING_ISSUED,
                AUTHORING_NOT_BEFORE=(promotion_tests._PROMOTION_AUTHORING_NOT_BEFORE),
                AUTHORING_EXPIRES=promotion_tests._PROMOTION_AUTHORING_EXPIRES,
                VALIDATION_TIME=promotion_tests._PROMOTION_RECEIPT_VALIDATION_TIME,
            ),
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
            paired = evaluation._bound_paired_fixture(
                provider=True,
                csharp=True,
                csharp_authority_path=authority_path,
                csharp_authority_trust=authority_trust,
            )
            bound = paired["bound"]
            self.addCleanup(bound["fixture"].doCleanups)
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

            audit_private_key = ec.generate_private_key(ec.SECP256R1())
            audit_private_key_path = self.root / "csharp-audit-private.pem"
            audit_public_key_path = self.root / "csharp-audit-public.pem"
            audit_private_key_path.write_bytes(
                audit_private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            audit_public_key_path.write_bytes(
                audit_private_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            audit_spki_sha256 = hashlib.sha256(
                audit_private_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest()
            audit_path = self.root / "csharp-replay-audit.json"
            audit_now = datetime(2026, 7, 27, 8, 0, tzinfo=timezone.utc)
            audit = create_csharp_verifier_replay_audit(
                output_path=audit_path,
                private_key_path=audit_private_key_path,
                public_key_path=audit_public_key_path,
                public_key_spki_sha256=audit_spki_sha256,
                private_key_password=None,
                audience="daxalgo-csharp-replay-audit",
                key_id="csharp-replay-audit-key-v1",
                signer_role="csharp-replay-auditor",
                approval_id="csharp-replay-approval-v1",
                actor_id="independent-csharp-auditor",
                actor_role="csharp-replay-auditor",
                approval_reference="audit://csharp-replay-approval-v1",
                approved_at_utc="2026-07-27T08:00:00Z",
                replay_completed_at_utc="2026-07-27T08:00:00Z",
                issued_at_utc="2026-07-27T08:00:00Z",
                not_before_utc="2026-07-27T08:00:00Z",
                expires_at_utc="2026-12-01T00:00:00Z",
                sealed_tasks_path=paired["inputs"]["sealed_tasks_path"],
                candidate_responses_path=paired["inputs"]["responses_path"],
                candidate_results_path=paired["inputs"]["verifier_results_path"],
                baseline_responses_path=paired["inputs"]["baseline_responses_path"],
                baseline_results_path=paired["inputs"][
                    "baseline_verifier_results_path"
                ],
                data_release_path=paired["inputs"]["data_release_path"],
                review_receipt_trust=paired["inputs"]["review_receipt_trust"],
                evaluation_authoring_approval_trust=paired["inputs"][
                    "evaluation_authoring_approval_trust"
                ],
                review_receipt_now=audit_now,
                csharp_verifier_context=csharp_context,
                now=audit_now,
            )

        audit_trust = CSharpVerifierReplayAuditTrust(
            audit_public_key_path,
            audit_spki_sha256,
            "daxalgo-csharp-replay-audit",
            "csharp-replay-audit-key-v1",
            "csharp-replay-auditor",
        )
        promotion_now = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
        evidence_inputs = {
            **paired["inputs"],
            "review_receipt_now": promotion_now,
            "csharp_verifier_replay_audit_path": audit_path,
            "csharp_verifier_replay_audit_trust": audit_trust,
            "expected_csharp_verifier_replay_audit_envelope_sha256": (
                audit.envelope_sha256
            ),
            "csharp_verifier_replay_audit_now": promotion_now,
        }
        report_path = self.root / "csharp-promotion-evidence.json"
        approval_path = self.root / "csharp-promotion-approval.txt"
        hosted_policy_path = self.root / "csharp-hosted-policy.json"
        approval_path.write_bytes(b"Independent production promotion approval.\n")
        hosted_policy_path.write_bytes(
            canonical_json_bytes(
                promotion_tests._hosted_policy(
                    schema_version=(
                        promotion_module.HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION
                    ),
                    execution_model_id=serving["profile"].execution_model_id,
                )
            )
            + b"\n"
        )

        promotion_private_key = ec.generate_private_key(ec.SECP256R1())
        promotion_private_key_path = self.root / "promotion-private.pem"
        promotion_public_key_path = self.root / "promotion-public.pem"
        promotion_private_key_path.write_bytes(
            promotion_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        promotion_public_key_path.write_bytes(
            promotion_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        manifest_snapshot = validate_manifest_snapshot(serving["manifest_path"])
        self.selected_base = replace(
            self.selected_base,
            manifest_snapshot=manifest_snapshot,
        )
        source_arguments = {
            "promotion_evidence_path": report_path,
            **evidence_inputs,
            "trainer_provenance_trust": evaluation.trainer_provenance_trust,
            "trainer_provenance_now": promotion_now,
            "base_selection_trust": self.base_selection_trust,
            "base_model_snapshot_path": self.base_snapshot,
            "catalog_path": evaluation.catalog_path,
            "serving_profile_path": serving["profile_path"],
            "artifact_path": serving["artifact_path"],
            "manifest_path": serving["manifest_path"],
            "approval_evidence_path": approval_path,
            "hosted_deployment_policy_path": hosted_policy_path,
        }
        promotion_path = self.root / "signed-csharp-promotion.json"

        def unexpected_live_csharp_replay(**_: object) -> object:
            raise AssertionError("production validation attempted live C# replay")

        with (
            mock.patch.object(
                verifier_runtime_module,
                "execute_release_verifiers",
                side_effect=unexpected_live_csharp_replay,
            ),
            mock.patch.object(
                promotion_module,
                "validate_base_model_selection_manifest_target",
                return_value=self.selected_base,
            ),
        ):
            report = aggregate_promotion_evidence(**evidence_inputs)
            write_json_atomic_no_clobber(report_path, report)
            created = create_model_promotion(
                output_path=promotion_path,
                private_key_path=promotion_private_key_path,
                public_key_path=promotion_public_key_path,
                private_key_password=None,
                audience="daxalgo-platform-prod",
                key_id="model-promotion-key-2026-07",
                signer_role="production-model-approver",
                deployment_id="vibe-quant-prod-eu1",
                environment="production",
                approval_id="promotion-approval-v1",
                actor_id="production-reviewer-17",
                actor_role="production-model-approver",
                approval_reference="promotion://approval-v1",
                approved_at_utc="2026-07-27T09:00:00Z",
                issued_at_utc="2026-07-27T10:00:00Z",
                not_before_utc="2026-07-27T10:00:00Z",
                expires_at_utc="2026-08-27T10:00:00Z",
                now=promotion_now,
                **source_arguments,
            )
            validated = validate_model_promotion(
                promotion_path,
                public_key_path=promotion_public_key_path,
                expected_audience="daxalgo-platform-prod",
                expected_key_id="model-promotion-key-2026-07",
                expected_signer_role="production-model-approver",
                expected_deployment_id="vibe-quant-prod-eu1",
                expected_environment="production",
                now=promotion_now,
                **source_arguments,
            )
            self.assertEqual(created.payload_sha256, validated.payload_sha256)
            readiness = create_promoted_model_readiness_attestation(
                promotion_path=promotion_path,
                public_key_path=promotion_public_key_path,
                expected_audience="daxalgo-platform-prod",
                expected_promotion_key_id="model-promotion-key-2026-07",
                expected_signer_role="production-model-approver",
                expected_deployment_id="vibe-quant-prod-eu1",
                expected_environment="production",
                nonce=_NONCE,
                readiness_key_id="readiness-key-v1",
                readiness_key=self.hmac_key,
                now=promotion_now,
                **source_arguments,
            )
            validate_model_readiness_v2_attestation(
                readiness,
                key=self.hmac_key,
                audience="daxalgo-platform-prod",
                expected_nonce=_NONCE,
                expected_key_id="readiness-key-v1",
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
            )

            activation_inputs = validated.activation_inputs
            self.assertIsNotNone(activation_inputs)
            assert activation_inputs is not None
            self.profile = activation_inputs.profile
            self.profile_path = Path(serving["profile_path"])
            self.artifact = Path(serving["artifact_path"])
            self.manifest = Path(serving["manifest_path"])
            self.promotion_path = promotion_path
            self.public_key = promotion_public_key_path
            self.review_receipt_trust = paired["inputs"]["review_receipt_trust"]
            self.evaluation_authoring_approval_trust = paired["inputs"][
                "evaluation_authoring_approval_trust"
            ]
            self.trainer_provenance_trust = evaluation.trainer_provenance_trust
            self.profile_sha256 = self.profile.sha256
            self.execution_model_id = self.profile.execution_model_id
            self.image_digest = self.profile.document["runtime"]["containerImageDigest"]
            self.envelope_sha256 = validated.envelope_sha256
            self.payload_sha256 = validated.payload_sha256
            self.artifact_sha256 = validated.payload["model"]["artifactSha256"]
            self.tree_sha256 = validated.payload["model"]["artifactTreeSha256"]
            self.policy_sha256 = validated.payload["hostedDeploymentPolicy"][
                "policySha256"
            ]
            self.manifest_sha256 = validated.payload["model"][
                "trainingRunManifestSha256"
            ]
            self.base_execution_model_id = self.selected_base.profile.execution_model_id
            os.environ["CURRENT_IMAGE_DIGEST"] = self.image_digest

            source_fields = {
                "promotionEvidencePath": report_path,
                "calibrationTasksPath": evidence_inputs["calibration_tasks_path"],
                "calibrationEvidencePath": evidence_inputs["calibration_evidence_path"],
                "sealedTasksPath": evidence_inputs["sealed_tasks_path"],
                "responsesPath": evidence_inputs["responses_path"],
                "verifierResultsPath": evidence_inputs["verifier_results_path"],
                "baselineResponsesPath": evidence_inputs["baseline_responses_path"],
                "baselineVerifierResultsPath": evidence_inputs[
                    "baseline_verifier_results_path"
                ],
                "policyPath": evidence_inputs["policy_path"],
                "dataReleasePath": evidence_inputs["data_release_path"],
                "catalogPath": evaluation.catalog_path,
                "servingProfilePath": serving["profile_path"],
                "artifactPath": serving["artifact_path"],
                "manifestPath": serving["manifest_path"],
                "approvalEvidencePath": approval_path,
                "hostedDeploymentPolicyPath": hosted_policy_path,
            }
            wrapper_config_path = self.root / "engine-wrapper-v7.json"
            wrapper_config_path.write_bytes(
                canonical_json_bytes(
                    {
                        "schemaVersion": ENGINE_WRAPPER_V7_SCHEMA_VERSION,
                        "promotion": {
                            "path": os.fspath(promotion_path),
                            "publicKeyPath": os.fspath(promotion_public_key_path),
                            "reviewReceiptTrust": {
                                "publicKeyPath": os.fspath(
                                    self.review_receipt_trust.public_key_path
                                ),
                                "publicKeySpkiSha256": (
                                    self.review_receipt_trust.public_key_spki_sha256
                                ),
                                "audience": self.review_receipt_trust.audience,
                                "keyId": self.review_receipt_trust.key_id,
                                "signerRole": self.review_receipt_trust.signer_role,
                            },
                            "evaluationAuthoringApprovalTrust": {
                                "publicKeyPath": os.fspath(
                                    self.evaluation_authoring_approval_trust.public_key_path
                                ),
                                "publicKeySpkiSha256": (
                                    self.evaluation_authoring_approval_trust.public_key_spki_sha256
                                ),
                                "audience": (
                                    self.evaluation_authoring_approval_trust.audience
                                ),
                                "keyId": self.evaluation_authoring_approval_trust.key_id,
                                "signerRole": (
                                    self.evaluation_authoring_approval_trust.signer_role
                                ),
                            },
                            "trainerProvenanceTrust": {
                                "publicKeyPath": os.fspath(
                                    self.trainer_provenance_trust.public_key_path
                                ),
                                "publicKeySpkiSha256": (
                                    self.trainer_provenance_trust.public_key_spki_sha256
                                ),
                                "audience": self.trainer_provenance_trust.audience,
                                "keyId": self.trainer_provenance_trust.key_id,
                                "signerRole": self.trainer_provenance_trust.signer_role,
                            },
                            "teacherLineageAdmissionTrust": None,
                            "candidateAttestationTrust": None,
                            "baselineAttestationTrust": None,
                            "csharpVerifierReplayAudit": {
                                "path": os.fspath(audit_path),
                                "expectedEnvelopeSha256": audit.envelope_sha256,
                                "trust": {
                                    "publicKeyPath": os.fspath(audit_public_key_path),
                                    "publicKeySpkiSha256": audit_spki_sha256,
                                    "audience": audit_trust.audience,
                                    "keyId": audit_trust.key_id,
                                    "signerRole": audit_trust.signer_role,
                                },
                            },
                            "expectedAudience": "daxalgo-platform-prod",
                            "expectedKeyId": "model-promotion-key-2026-07",
                            "expectedSignerRole": "production-model-approver",
                            "expectedDeploymentId": "vibe-quant-prod-eu1",
                            "expectedEnvironment": "production",
                            "expectedEnvelopeSha256": validated.envelope_sha256,
                            "expectedServingProfileSha256": self.profile_sha256,
                            "sources": {
                                name: os.fspath(path)
                                for name, path in source_fields.items()
                            },
                        },
                        "engine": {
                            "executablePath": os.fspath(self.executable),
                            "executableSha256": self.executable_sha256,
                            "containerImageDigestEnvironment": ("CURRENT_IMAGE_DIGEST"),
                            "childHost": "127.0.0.1",
                            "childPort": 18081,
                            "childUserId": 10001,
                            "childGroupId": 10001,
                            "startupTimeoutSeconds": 1,
                            "healthIntervalSeconds": 1,
                            "integrityIntervalSeconds": 1,
                            "requestTimeoutSeconds": 1,
                            "shutdownGraceSeconds": 0,
                            "environmentAllowlist": ["PATH", "CUDA_VISIBLE_DEVICES"],
                        },
                        "service": {
                            "listenHost": "127.0.0.1",
                            "listenPort": 18080,
                            "bearerTokenEnvironment": "OUTER_BEARER_SECRET",
                            "readinessHmacKeyEnvironment": "READINESS_HMAC_SECRET",
                            "readinessKeyId": "readiness-key-v1",
                            "maxRequestBytes": 100000,
                            "maxResponseBytes": 100000,
                        },
                        "baseSnapshot": {
                            "snapshotPath": os.fspath(self.base_snapshot),
                            "selectionTrust": {
                                "publicKeyPath": os.fspath(
                                    self.base_selection_trust.public_key_path
                                ),
                                "publicKeySpkiSha256": (
                                    self.base_selection_trust.public_key_spki_sha256
                                ),
                                "audience": self.base_selection_trust.audience,
                                "keyId": self.base_selection_trust.key_id,
                                "signerRole": self.base_selection_trust.signer_role,
                            },
                        },
                    }
                )
            )
            loaded = load_engine_wrapper_config(wrapper_config_path)
            self.assertEqual(
                audit.envelope_sha256,
                loaded.promotion.expected_csharp_verifier_replay_audit_envelope_sha256,
            )

            with mock.patch.object(
                wrapper_module,
                "validate_model_promotion",
                side_effect=validate_model_promotion,
            ) as live_promotion_validation:
                wrapper = self._wrapper(config=loaded)
                snapshot = wrapper.start(start_monitor=False)
                self.addCleanup(wrapper.stop)
                self.assertEqual(
                    audit.payload_sha256,
                    snapshot.csharp_verifier_replay_audit_payload_sha256,
                )
                self.assertEqual(
                    audit.envelope_sha256,
                    snapshot.csharp_verifier_replay_audit_envelope_sha256,
                )
                self.assertEqual(
                    activation_inputs.evaluation_authoring_approval_payload_sha256,
                    snapshot.evaluation_authoring_approval_payload_sha256,
                )
                self.assertEqual(
                    activation_inputs.evaluation_authoring_approval_envelope_sha256,
                    snapshot.evaluation_authoring_approval_envelope_sha256,
                )
                wrapper.monitor_once(validate_integrity=True)
                self.assertEqual(WrapperState.READY, wrapper.state)
                self.assertGreaterEqual(live_promotion_validation.call_count, 3)

    def test_wrong_review_receipt_trust_fails_before_launch(self) -> None:
        wrong_trust = replace(
            self.review_receipt_trust,
            audience="wrong-review-receipt-audience",
        )
        wrong_config = replace(
            self.config,
            promotion=replace(
                self.config.promotion,
                review_receipt_trust=wrong_trust,
            ),
        )

        def reject_wrong_trust(*_: object, **arguments: object) -> object:
            self.assertIs(wrong_trust, arguments["review_receipt_trust"])
            raise ValidationError(
                "review-receipt trust: does not match externally supplied identity"
            )

        self.promotion_mock.side_effect = reject_wrong_trust
        wrapper = self._wrapper(config=wrong_config)
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertIsNone(self.process_arguments)

    def test_wrong_evaluation_authoring_trust_fails_before_launch(self) -> None:
        wrong_trust = replace(
            self.evaluation_authoring_approval_trust,
            audience="wrong-evaluation-authoring-audience",
        )
        wrong_config = replace(
            self.config,
            promotion=replace(
                self.config.promotion,
                evaluation_authoring_approval_trust=wrong_trust,
            ),
        )

        def reject_wrong_trust(*_: object, **arguments: object) -> object:
            self.assertIs(
                wrong_trust,
                arguments["evaluation_authoring_approval_trust"],
            )
            raise ValidationError(
                "evaluation-authoring approval trust: does not match externally supplied identity"
            )

        self.promotion_mock.side_effect = reject_wrong_trust
        wrapper = self._wrapper(config=wrong_config)
        with self.assertRaisesRegex(ValidationError, "externally supplied"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertIsNone(self.process_arguments)

    def test_legacy_config_and_writable_snapshot_fail_before_launch(self) -> None:
        legacy = replace(
            self.config,
            schema_version=ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        )
        with self.assertRaisesRegex(ValidationError, "engine-wrapper/v7"):
            self._wrapper(config=legacy).start(start_monitor=False)
        self.assertIsNone(self.process_arguments)

        with self.assertRaisesRegex(ValidationError, "privilege isolation"):
            self._wrapper(privilege_isolation_probe=lambda _: False).start(
                start_monitor=False
            )
        self.assertIsNone(self.process_arguments)

        with self.assertRaisesRegex(ValidationError, "read-only mount"):
            self._wrapper(read_only_probe=lambda _: False).start(start_monitor=False)
        self.assertIsNone(self.process_arguments)

        with self.assertRaisesRegex(ValidationError, "engine executable.*read-only"):
            self._wrapper(read_only_probe=lambda path: path != self.executable).start(
                start_monitor=False
            )
        self.assertIsNone(self.process_arguments)

    def test_snapshot_custody_loss_after_ready_fails_closed(self) -> None:
        custody = True
        wrapper = self._wrapper(read_only_probe=lambda _: custody)
        wrapper.start(start_monitor=False)
        custody = False

        response = wrapper.handle_http_request(
            "POST",
            READINESS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                    "audience": "daxalgo-platform-prod",
                    "nonce": _NONCE,
                }
            ),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_adapter_custody_loss_after_ready_fails_closed(self) -> None:
        artifact_read_only = True

        def read_only(path: Path) -> bool:
            return path != self.artifact or artifact_read_only

        wrapper = self._wrapper(read_only_probe=read_only)
        wrapper.start(start_monitor=False)
        artifact_read_only = False

        response = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "model": self.execution_model_id,
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 128,
                    "temperature": 0,
                }
            ),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_manifest_snapshot_hash_mismatch_fails_before_spawn(self) -> None:
        wrong_snapshot = replace(self.manifest_snapshot, sha256="f" * 64)
        inputs = self.verified.activation_inputs
        self.assertIsNotNone(inputs)
        self.promotion_mock.return_value = replace(
            self.verified,
            activation_inputs=replace(
                inputs,
                manifest_snapshot=wrong_snapshot,
                selected_base=replace(
                    self.selected_base, manifest_snapshot=wrong_snapshot
                ),
            ),
        )

        with self.assertRaisesRegex(ValidationError, "retained validated manifest"):
            self._wrapper().start(start_monitor=False)
        self.assertIsNone(self.process_arguments)

    def test_snapshot_directory_swap_after_validation_fails_before_spawn(self) -> None:
        real_open = wrapper_module._open_verified_executable

        def swap_snapshot(path: Path, expected_sha256: str) -> int:
            descriptor = real_open(path, expected_sha256)
            moved = self.root / "former-base-snapshot"
            self.base_snapshot.rename(moved)
            self.base_snapshot.mkdir()
            return descriptor

        with mock.patch.object(
            wrapper_module, "_open_verified_executable", side_effect=swap_snapshot
        ):
            wrapper = self._wrapper()
            with self.assertRaisesRegex(ValidationError, "directory identity changed"):
                wrapper.start(start_monitor=False)
        self.assertIsNone(self.process_arguments)
        self.assertEqual(WrapperState.FAILED, wrapper.state)

    def test_snapshot_validation_failure_after_child_load_kills_process(self) -> None:
        self.promotion_mock.side_effect = [
            self.verified,
            ValidationError("base-model snapshot: sealed file tree changed"),
        ]
        wrapper = self._wrapper()
        with self.assertRaisesRegex(ValidationError, "sealed file tree changed"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_response_attestation_trust_is_revalidated_on_every_activation(
        self,
    ) -> None:
        activation_trust = BaseEngineActivationTrust(
            public_key_path=self.public_key,
            public_key_spki_sha256="9" * 64,
            audience="daxalgo-base-evaluation",
            key_id="base-activation-key-v1",
            signer_role="base-model-launch-authority",
        )
        candidate_trust = BaseResponseAttestationTrust(
            activation_trust=activation_trust,
            runtime_public_key_path=self.public_key,
        )
        baseline_trust = BaseResponseAttestationTrust(
            activation_trust=replace(
                activation_trust,
                key_id="baseline-activation-key-v1",
            ),
            runtime_public_key_path=self.public_key,
        )
        config = replace(
            self.config,
            promotion=replace(
                self.config.promotion,
                candidate_attestation_trust=candidate_trust,
                baseline_attestation_trust=baseline_trust,
            ),
        )

        wrapper = self._wrapper(config=config)
        wrapper.start(start_monitor=False)
        self.addCleanup(wrapper.stop)
        wrapper.monitor_once(validate_integrity=True)

        self.assertGreaterEqual(self.promotion_mock.call_count, 3)
        for call in self.promotion_mock.call_args_list:
            self.assertIs(
                candidate_trust,
                call.kwargs["candidate_attestation_trust"],
            )
            self.assertIs(
                baseline_trust,
                call.kwargs["baseline_attestation_trust"],
            )

    def test_listener_ownership_is_required_before_any_child_http(self) -> None:
        transport = mock.Mock(side_effect=self._transport)
        ticks = iter((0.0, 0.1, 2.0, 3.0))
        wrapper = self._wrapper(
            transport=transport,
            listener_ownership_probe=lambda *_: False,
            monotonic=lambda: next(ticks, 3.0),
        )

        with self.assertRaisesRegex(ValidationError, "startup: timed out"):
            wrapper.start(start_monitor=False)
        transport.assert_not_called()
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_child_privilege_identity_is_required_before_any_child_http(self) -> None:
        transport = mock.Mock(side_effect=self._transport)
        ticks = iter((0.0, 0.1, 2.0, 3.0))
        wrapper = self._wrapper(
            transport=transport,
            child_privilege_probe=lambda *_: False,
            monotonic=lambda: next(ticks, 3.0),
        )

        with self.assertRaisesRegex(ValidationError, "startup: timed out"):
            wrapper.start(start_monitor=False)
        transport.assert_not_called()
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_listener_ownership_loss_blocks_forwarding_and_fails_closed(self) -> None:
        owned = True
        wrapper = self._wrapper(listener_ownership_probe=lambda *_: owned)
        wrapper.start(start_monitor=False)
        call_count = len(self.transport_calls)
        owned = False

        response = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "model": self.execution_model_id,
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 128,
                    "temperature": 0,
                }
            ),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(call_count, len(self.transport_calls))
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_gateway_uses_quick_checks_until_integrity_interval_expires(self) -> None:
        monotonic_value = 0.0
        wrapper = self._wrapper(monotonic=lambda: monotonic_value)
        wrapper.start(start_monitor=False)
        self.addCleanup(wrapper.stop)
        full_validations = self.promotion_mock.call_count
        request = canonical_json_bytes(
            {
                "model": self.execution_model_id,
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 128,
                "temperature": 0,
            }
        )
        readiness_request = canonical_json_bytes(
            {
                "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                "audience": "daxalgo-platform-prod",
                "nonce": _NONCE,
            }
        )

        first = wrapper.handle_http_request(
            "POST", CHAT_COMPLETIONS_PATH, self._headers(), request
        )
        self.assertEqual(200, first.status)
        self.assertEqual(full_validations, self.promotion_mock.call_count)
        readiness = wrapper.handle_http_request(
            "POST", READINESS_PATH, self._headers(), readiness_request
        )
        self.assertEqual(200, readiness.status)
        self.assertEqual(full_validations, self.promotion_mock.call_count)

        monotonic_value = 2.0
        second = wrapper.handle_http_request(
            "POST", CHAT_COMPLETIONS_PATH, self._headers(), request
        )
        self.assertEqual(200, second.status)
        self.assertEqual(full_validations + 1, self.promotion_mock.call_count)
        readiness = wrapper.handle_http_request(
            "POST", READINESS_PATH, self._headers(), readiness_request
        )
        self.assertEqual(200, readiness.status)
        self.assertEqual(full_validations + 1, self.promotion_mock.call_count)

    def test_cached_readiness_never_outlives_upstream_authority(self) -> None:
        current = wrapper_module.datetime.fromisoformat(_NOW.replace("Z", "+00:00"))
        inputs = self.verified.activation_inputs
        self.assertIsNotNone(inputs)
        self.promotion_mock.return_value = replace(
            self.verified,
            activation_inputs=replace(
                inputs, authority_expires_at_utc="2026-07-28T10:00:01Z"
            ),
        )
        wrapper = self._wrapper(clock=lambda: current)
        wrapper.start(start_monitor=False)
        current = wrapper_module.datetime.fromisoformat("2026-07-28T10:00:02+00:00")

        response = wrapper.handle_http_request(
            "POST",
            READINESS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                    "audience": "daxalgo-platform-prod",
                    "nonce": _NONCE,
                }
            ),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_expiry_during_prevalidation_prevents_process_creation(self) -> None:
        before_expiry = wrapper_module.datetime.fromisoformat(
            _NOW.replace("Z", "+00:00")
        )
        after_expiry = wrapper_module.datetime.fromisoformat(
            "2026-07-28T10:00:02+00:00"
        )
        inputs = self.verified.activation_inputs
        self.assertIsNotNone(inputs)
        self.promotion_mock.return_value = replace(
            self.verified,
            activation_inputs=replace(
                inputs, authority_expires_at_utc="2026-07-28T10:00:01Z"
            ),
        )
        clock_values = iter((before_expiry, after_expiry))
        wrapper = self._wrapper(clock=lambda: next(clock_values, after_expiry))

        with self.assertRaisesRegex(ValidationError, "is not currently valid"):
            wrapper.start(start_monitor=False)

        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertIsNone(self.process_arguments)

    def test_client_errors_do_not_kill_wrapper_or_reach_child(self) -> None:
        wrapper = self._wrapper()
        wrapper.start(start_monitor=False)
        self.addCleanup(wrapper.stop)
        call_count = len(self.transport_calls)

        unauthorized = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            {"Authorization": "Bearer wrong", "Content-Type": "application/json"},
            b"{}",
        )
        wrong_model = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "model": "base-model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 128,
                    "temperature": 0,
                }
            ),
        )
        streaming = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "model": self.execution_model_id,
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 128,
                    "temperature": 0,
                    "stream": True,
                }
            ),
        )
        bad_nonce = wrapper.handle_http_request(
            "POST",
            READINESS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                    "audience": "daxalgo-platform-prod",
                    "nonce": "A" * 42,
                }
            ),
        )
        surrogate_body = (
            '{"model":"'
            + self.execution_model_id
            + '","messages":[{"role":"user","content":"\\ud800"}],'
            '"max_tokens":128,"temperature":0}'
        ).encode("ascii")
        surrogate = wrapper.handle_http_request(
            "POST",
            CHAT_COMPLETIONS_PATH,
            self._headers(),
            surrogate_body,
        )

        self.assertEqual(401, unauthorized.status)
        self.assertEqual(400, wrong_model.status)
        self.assertEqual(400, streaming.status)
        self.assertEqual(400, bad_nonce.status)
        self.assertEqual(400, surrogate.status)
        self.assertEqual(call_count, len(self.transport_calls))
        self.assertEqual(WrapperState.READY, wrapper.state)

    def test_concurrent_stop_cannot_be_overwritten_by_ready(self) -> None:
        wrapper_holder: list[PromotedModelEngineWrapper] = []
        model_probe_count = 0

        def stop_during_final_probe(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout: float,
            maximum: int,
        ) -> TransportResponse:
            nonlocal model_probe_count
            response = self._transport(method, url, headers, body, timeout, maximum)
            if url.endswith("/v1/models"):
                model_probe_count += 1
                if model_probe_count == 2:
                    wrapper_holder[0].stop()
            return response

        wrapper = self._wrapper(transport=stop_during_final_probe)
        wrapper_holder.append(wrapper)
        with self.assertRaisesRegex(ValidationError, "stopped during post-load"):
            wrapper.start(start_monitor=False)
        self.assertNotEqual(WrapperState.READY, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_unterminated_child_is_observable_and_never_reports_stopped(self) -> None:
        self.process = _RefusingProcess()
        wrapper = self._wrapper()
        wrapper.start(start_monitor=False)

        with self.assertRaisesRegex(ValidationError, "remains alive"):
            wrapper.stop()
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)
        self.assertTrue(self.process.killed)

    def test_exited_leader_still_requires_process_group_cleanup(self) -> None:
        process = _GroupAwareProcess()
        self.process = process
        wrapper = self._wrapper()
        wrapper.start(start_monitor=False)
        process.returncode = 17

        wrapper.stop()
        self.assertEqual(WrapperState.STOPPED, wrapper.state)
        self.assertEqual(1, process.group_stop_calls)

    def test_failed_handoff_termination_cannot_preserve_stopped_state(self) -> None:
        self.process = _RefusingProcess()
        wrapper_holder: list[PromotedModelEngineWrapper] = []

        def stop_during_handoff(
            executable_fd: int,
            argv: list[str] | tuple[str, ...],
            environment: Mapping[str, str],
            cwd: Path,
        ) -> _RefusingProcess:
            self.assertGreaterEqual(executable_fd, 0)
            wrapper_holder[0].stop()
            return self.process

        wrapper = self._wrapper(process_factory=stop_during_handoff)
        wrapper_holder.append(wrapper)
        with self.assertRaisesRegex(ValidationError, "remains alive"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)

    def test_image_version_and_lora_rank_are_prelaunch_gates(self) -> None:
        with mock.patch.dict(
            os.environ, {"CURRENT_IMAGE_DIGEST": "sha256:" + "f" * 64}
        ):
            image_wrapper = self._wrapper()
            with self.assertRaisesRegex(ValidationError, "container image"):
                image_wrapper.start(start_monitor=False)
        self.assertIsNone(self.process_arguments)

        unsupported_document = dict(self.profile.document)
        unsupported_document["runtime"] = {
            **self.profile.document["runtime"],
            "engineVersion": "0.9.0",
        }
        unsupported_profile = replace(self.profile, document=unsupported_document)
        inputs = self.verified.activation_inputs
        self.assertIsNotNone(inputs)
        self.promotion_mock.return_value = replace(
            self.verified,
            activation_inputs=replace(inputs, profile=unsupported_profile),
        )
        version_wrapper = self._wrapper()
        with self.assertRaisesRegex(ValidationError, "reviewed exact argv"):
            version_wrapper.start(start_monitor=False)
        self.assertIsNone(self.process_arguments)
        self.promotion_mock.return_value = self.verified

        invalid_manifest = replace(
            self.manifest_snapshot,
            document={
                **self.manifest_snapshot.document,
                "hyperparameters": {"loraR": 7},
            },
        )
        self.promotion_mock.return_value = replace(
            self.verified,
            activation_inputs=replace(inputs, manifest_snapshot=invalid_manifest),
        )
        rank_wrapper = self._wrapper()
        with self.assertRaisesRegex(ValidationError, "supported vLLM"):
            rank_wrapper.start(start_monitor=False)
        self.assertIsNone(self.process_arguments)
        self.promotion_mock.return_value = self.verified

    def test_activation_mutation_or_child_exit_fails_closed(self) -> None:
        monotonic_value = 0.0
        wrapper = self._wrapper(monotonic=lambda: monotonic_value)
        wrapper.start(start_monitor=False)
        changed = self._verified("8" * 64)
        self.promotion_mock.return_value = changed
        monotonic_value = 2.0

        response = wrapper.handle_http_request(
            "POST",
            READINESS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                    "audience": "daxalgo-platform-prod",
                    "nonce": _NONCE,
                }
            ),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

        second = self._wrapper()
        self.promotion_mock.return_value = self.verified
        self.process = _FakeProcess()
        second.start(start_monitor=False)
        self.process.returncode = 17
        response = second.handle_http_request(
            "POST",
            READINESS_PATH,
            self._headers(),
            canonical_json_bytes(
                {
                    "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
                    "audience": "daxalgo-platform-prod",
                    "nonce": _NONCE,
                }
            ),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(WrapperState.FAILED, second.state)

    def test_wrong_child_model_identity_never_reaches_ready(self) -> None:
        def wrong_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout: float,
            maximum: int,
        ) -> TransportResponse:
            if url.endswith("/health"):
                return TransportResponse(200, {}, b"", url)
            if url.endswith("/version"):
                return TransportResponse(
                    200,
                    {"Content-Type": "application/json"},
                    canonical_json_bytes({"version": "0.10.0"}),
                    url,
                )
            return TransportResponse(
                200,
                {"Content-Type": "application/json"},
                canonical_json_bytes({"data": [{"id": "base-model"}]}),
                url,
            )

        ticks = iter((0.0, 0.1, 2.0, 3.0))
        wrapper = self._wrapper(
            transport=wrong_transport,
            monotonic=lambda: next(ticks, 3.0),
        )
        with self.assertRaisesRegex(ValidationError, "startup: timed out"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_wrong_child_version_never_reaches_ready(self) -> None:
        def wrong_version_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout: float,
            maximum: int,
        ) -> TransportResponse:
            if url.endswith("/version"):
                return TransportResponse(
                    200,
                    {"Content-Type": "application/json"},
                    canonical_json_bytes({"version": "0.26.0"}),
                    url,
                )
            return self._transport(method, url, headers, body, timeout, maximum)

        ticks = iter((0.0, 0.1, 2.0, 3.0))
        wrapper = self._wrapper(
            transport=wrong_version_transport,
            monotonic=lambda: next(ticks, 3.0),
        )
        with self.assertRaisesRegex(ValidationError, "startup: timed out"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)

    def test_wrong_child_adapter_card_never_reaches_ready(self) -> None:
        mutations = {
            "root": ("root", os.fspath(self.root / "foreign-adapter")),
            "maximum": ("max_model_len", 4096),
        }
        for name, (field_name, invalid_value) in mutations.items():
            with self.subTest(name=name):
                self.process = _FakeProcess()

                def wrong_card_transport(
                    method: str,
                    url: str,
                    headers: Mapping[str, str],
                    body: bytes | None,
                    timeout: float,
                    maximum: int,
                ) -> TransportResponse:
                    response = self._transport(
                        method, url, headers, body, timeout, maximum
                    )
                    if not url.endswith("/v1/models"):
                        return response
                    value = json.loads(response.body)
                    value["data"][1][field_name] = invalid_value
                    return replace(response, body=canonical_json_bytes(value))

                ticks = iter((0.0, 0.1, 2.0, 3.0))
                wrapper = self._wrapper(
                    transport=wrong_card_transport,
                    monotonic=lambda: next(ticks, 3.0),
                )
                with self.assertRaisesRegex(ValidationError, "startup: timed out"):
                    wrapper.start(start_monitor=False)
                self.assertEqual(WrapperState.FAILED, wrapper.state)
                self.assertTrue(self.process.terminated)

    def test_extra_child_model_identity_never_reaches_ready(self) -> None:
        def extra_transport(
            method: str,
            url: str,
            headers: Mapping[str, str],
            body: bytes | None,
            timeout: float,
            maximum: int,
        ) -> TransportResponse:
            if url.endswith("/health"):
                return TransportResponse(200, {}, b"", url)
            if url.endswith("/version"):
                return TransportResponse(
                    200,
                    {"Content-Type": "application/json"},
                    canonical_json_bytes({"version": "0.10.0"}),
                    url,
                )
            return TransportResponse(
                200,
                {"Content-Type": "application/json"},
                canonical_json_bytes(
                    {
                        "data": [
                            {"id": self.base_execution_model_id},
                            {"id": self.execution_model_id},
                            {"id": "unexpected-adapter"},
                        ]
                    }
                ),
                url,
            )

        ticks = iter((0.0, 0.1, 2.0, 3.0))
        wrapper = self._wrapper(
            transport=extra_transport,
            monotonic=lambda: next(ticks, 3.0),
        )
        with self.assertRaisesRegex(ValidationError, "startup: timed out"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)


class EngineWrapperConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / "input.json"
        self.file.write_text("{}", encoding="utf-8")
        self.directory = self.root / "directory"
        self.directory.mkdir()
        self.executable = self.root / "vllm"
        self.executable.write_text("executable", encoding="utf-8")

    def _attestation_trust_document(self, *, key_id: str) -> dict:
        return {
            "activationTrust": {
                "publicKeyPath": os.fspath(self.file),
                "publicKeySpkiSha256": "5" * 64,
                "audience": "daxalgo-base-evaluation",
                "keyId": key_id,
                "signerRole": "base-model-launch-authority",
            },
            "runtimePublicKeyPath": os.fspath(self.file),
        }

    def _document(
        self,
        *,
        schema_version: str = ENGINE_WRAPPER_SCHEMA_VERSION,
    ) -> dict:
        source_names = (
            "promotionEvidencePath",
            "calibrationTasksPath",
            "calibrationEvidencePath",
            "sealedTasksPath",
            "responsesPath",
            "verifierResultsPath",
            "baselineResponsesPath",
            "baselineVerifierResultsPath",
            "policyPath",
            "dataReleasePath",
            "catalogPath",
            "servingProfilePath",
            "artifactPath",
            "manifestPath",
            "approvalEvidencePath",
            "hostedDeploymentPolicyPath",
        )
        sources = {name: os.fspath(self.file) for name in source_names}
        sources["dataReleasePath"] = os.fspath(self.directory)
        sources["artifactPath"] = os.fspath(self.directory)
        document = {
            "schemaVersion": schema_version,
            "promotion": {
                "path": os.fspath(self.file),
                "publicKeyPath": os.fspath(self.file),
                "reviewReceiptTrust": {
                    "publicKeyPath": os.fspath(self.file),
                    "publicKeySpkiSha256": "4" * 64,
                    "audience": "daxalgo-vibe-quant-training",
                    "keyId": "review-key-v1",
                    "signerRole": "expert-review-authority",
                },
                "expectedAudience": "daxalgo-platform-prod",
                "expectedKeyId": "promotion-key-v1",
                "expectedSignerRole": "production-approver",
                "expectedDeploymentId": "vibe-quant-prod-eu1",
                "expectedEnvironment": "production",
                "expectedEnvelopeSha256": "1" * 64,
                "expectedServingProfileSha256": "2" * 64,
                "sources": sources,
            },
            "engine": {
                "executablePath": os.fspath(self.executable),
                "executableSha256": "3" * 64,
                "containerImageDigestEnvironment": "CURRENT_IMAGE_DIGEST",
                "childHost": "127.0.0.1",
                "childPort": 18081,
                "startupTimeoutSeconds": 60,
                "healthIntervalSeconds": 2,
                "integrityIntervalSeconds": 30,
                "requestTimeoutSeconds": 10,
                "shutdownGraceSeconds": 5,
                "environmentAllowlist": ["PATH", "CUDA_VISIBLE_DEVICES"],
            },
            "service": {
                "listenHost": "127.0.0.1",
                "listenPort": 18080,
                "bearerTokenEnvironment": "OUTER_BEARER_SECRET",
                "readinessHmacKeyEnvironment": "READINESS_HMAC_SECRET",
                "readinessKeyId": "readiness-key-v1",
                "maxRequestBytes": 100000,
                "maxResponseBytes": 100000,
            },
        }
        if schema_version in {
            ENGINE_WRAPPER_V2_SCHEMA_VERSION,
            ENGINE_WRAPPER_V3_SCHEMA_VERSION,
            ENGINE_WRAPPER_V4_SCHEMA_VERSION,
            ENGINE_WRAPPER_V5_SCHEMA_VERSION,
            ENGINE_WRAPPER_V6_SCHEMA_VERSION,
            ENGINE_WRAPPER_V7_SCHEMA_VERSION,
        }:
            document["promotion"].update(
                {
                    "candidateAttestationTrust": self._attestation_trust_document(
                        key_id="candidate-activation-key-v1"
                    ),
                    "baselineAttestationTrust": None,
                }
            )
        if schema_version in {
            ENGINE_WRAPPER_V3_SCHEMA_VERSION,
            ENGINE_WRAPPER_V4_SCHEMA_VERSION,
            ENGINE_WRAPPER_V5_SCHEMA_VERSION,
            ENGINE_WRAPPER_V6_SCHEMA_VERSION,
            ENGINE_WRAPPER_V7_SCHEMA_VERSION,
        }:
            document["engine"].update(
                {
                    "childUserId": 10001,
                    "childGroupId": 10001,
                }
            )
            document["baseSnapshot"] = {
                "snapshotPath": os.fspath(self.directory),
                "selectionTrust": {
                    "publicKeyPath": os.fspath(self.file),
                    "publicKeySpkiSha256": "6" * 64,
                    "audience": "daxalgo-vibe-quant-base-selection",
                    "keyId": "base-selection-key-v1",
                    "signerRole": "base-model-selection-authority",
                },
            }
        if schema_version in {
            ENGINE_WRAPPER_V4_SCHEMA_VERSION,
            ENGINE_WRAPPER_V5_SCHEMA_VERSION,
            ENGINE_WRAPPER_V6_SCHEMA_VERSION,
            ENGINE_WRAPPER_V7_SCHEMA_VERSION,
        }:
            document["promotion"]["csharpVerifierReplayAudit"] = {
                "path": os.fspath(self.file),
                "expectedEnvelopeSha256": "7" * 64,
                "trust": {
                    "publicKeyPath": os.fspath(self.file),
                    "publicKeySpkiSha256": "8" * 64,
                    "audience": "daxalgo-csharp-replay-audit",
                    "keyId": "csharp-replay-audit-key-v1",
                    "signerRole": "csharp-replay-auditor",
                },
            }
        if schema_version in {
            ENGINE_WRAPPER_V5_SCHEMA_VERSION,
            ENGINE_WRAPPER_V6_SCHEMA_VERSION,
            ENGINE_WRAPPER_V7_SCHEMA_VERSION,
        }:
            document["promotion"]["evaluationAuthoringApprovalTrust"] = {
                "publicKeyPath": os.fspath(self.file),
                "publicKeySpkiSha256": "9" * 64,
                "audience": "daxalgo-vibe-quant-evaluation-authoring",
                "keyId": "evaluation-authoring-key-v1",
                "signerRole": "evaluation-authoring-reviewer",
            }
        if schema_version in {
            ENGINE_WRAPPER_V6_SCHEMA_VERSION,
            ENGINE_WRAPPER_V7_SCHEMA_VERSION,
        }:
            document["promotion"]["trainerProvenanceTrust"] = {
                "publicKeyPath": os.fspath(self.file),
                "publicKeySpkiSha256": "a" * 64,
                "audience": "daxalgo-vibe-quant-trainer-provenance",
                "keyId": "trainer-provenance-key-v1",
                "signerRole": "model-training-authority",
            }
        if schema_version == ENGINE_WRAPPER_V7_SCHEMA_VERSION:
            document["promotion"]["teacherLineageAdmissionTrust"] = None
        return document

    def test_config_is_strict_and_matches_schema_surface(self) -> None:
        config_path = self.root / "wrapper.json"
        config_path.write_bytes(canonical_json_bytes(self._document()))
        loaded = load_engine_wrapper_config(config_path)
        self.assertEqual("1" * 64, loaded.promotion.expected_envelope_sha256)
        self.assertIsNone(loaded.promotion.candidate_attestation_trust)
        self.assertIsNone(loaded.promotion.baseline_attestation_trust)
        self.assertIsInstance(
            loaded.promotion.review_receipt_trust,
            ExpertModelReviewReceiptTrust,
        )
        self.assertEqual(
            "4" * 64,
            loaded.promotion.review_receipt_trust.public_key_spki_sha256,
        )
        self.assertEqual(
            "CURRENT_IMAGE_DIGEST", loaded.engine.container_image_digest_environment
        )

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ENGINE_WRAPPER_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        self.assertFalse(schema["additionalProperties"])
        trust_schema = schema["properties"]["promotion"]["properties"][
            "reviewReceiptTrust"
        ]
        self.assertFalse(trust_schema["additionalProperties"])
        self.assertEqual(
            {
                "publicKeyPath",
                "publicKeySpkiSha256",
                "audience",
                "keyId",
                "signerRole",
            },
            set(trust_schema["required"]),
        )
        self.assertNotIn("privateKeyPath", trust_schema["properties"])

        invalid = self._document()
        invalid["engine"]["unexpected"] = True
        config_path.write_bytes(canonical_json_bytes(invalid))
        with self.assertRaisesRegex(ValidationError, "additional"):
            load_engine_wrapper_config(config_path)

    def test_v2_config_loads_nullable_strict_response_attestation_trust(self) -> None:
        config_path = self.root / "wrapper-v2.json"
        config_path.write_bytes(
            canonical_json_bytes(
                self._document(schema_version=ENGINE_WRAPPER_V2_SCHEMA_VERSION)
            )
        )

        loaded = load_engine_wrapper_config(config_path)
        candidate = loaded.promotion.candidate_attestation_trust
        self.assertIsInstance(candidate, BaseResponseAttestationTrust)
        self.assertEqual(
            "candidate-activation-key-v1",
            candidate.activation_trust.key_id if candidate is not None else None,
        )
        self.assertEqual(self.file, candidate.runtime_public_key_path)
        self.assertIsNone(loaded.promotion.baseline_attestation_trust)

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ENGINE_WRAPPER_V2_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        promotion_schema = schema["properties"]["promotion"]
        self.assertFalse(promotion_schema["additionalProperties"])
        self.assertIn("candidateAttestationTrust", promotion_schema["required"])
        self.assertIn("baselineAttestationTrust", promotion_schema["required"])
        self.assertFalse(
            schema["$defs"]["responseAttestationTrust"]["additionalProperties"]
        )
        self.assertFalse(schema["$defs"]["signingTrust"]["additionalProperties"])

    def test_v3_config_requires_exact_snapshot_and_selection_trust(self) -> None:
        config_path = self.root / "wrapper-v3.json"
        config_path.write_bytes(
            canonical_json_bytes(
                self._document(schema_version=ENGINE_WRAPPER_V3_SCHEMA_VERSION)
            )
        )

        loaded = load_engine_wrapper_config(config_path)
        self.assertIsNotNone(loaded.base_snapshot)
        base_snapshot = loaded.base_snapshot
        self.assertEqual(self.directory, base_snapshot.snapshot_path)
        self.assertEqual(
            "base-selection-key-v1",
            base_snapshot.selection_trust.key_id,
        )
        self.assertEqual(10001, loaded.engine.child_user_id)
        self.assertEqual(10001, loaded.engine.child_group_id)

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v3.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ENGINE_WRAPPER_V3_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        self.assertIn("baseSnapshot", schema["required"])
        self.assertIn("childUserId", schema["properties"]["engine"]["required"])
        self.assertIn("childGroupId", schema["properties"]["engine"]["required"])
        self.assertFalse(schema["properties"]["baseSnapshot"]["additionalProperties"])

        missing = self._document(schema_version=ENGINE_WRAPPER_V3_SCHEMA_VERSION)
        missing.pop("baseSnapshot")
        config_path.write_bytes(canonical_json_bytes(missing))
        with self.assertRaisesRegex(ValidationError, "baseSnapshot"):
            load_engine_wrapper_config(config_path)

        missing_identity = self._document(
            schema_version=ENGINE_WRAPPER_V3_SCHEMA_VERSION
        )
        missing_identity["engine"].pop("childUserId")
        config_path.write_bytes(canonical_json_bytes(missing_identity))
        with self.assertRaisesRegex(ValidationError, "childUserId"):
            load_engine_wrapper_config(config_path)

        extra = self._document(schema_version=ENGINE_WRAPPER_V3_SCHEMA_VERSION)
        extra["baseSnapshot"]["selectionTrust"]["privateKeyPath"] = os.fspath(self.file)
        config_path.write_bytes(canonical_json_bytes(extra))
        with self.assertRaisesRegex(ValidationError, "privateKeyPath"):
            load_engine_wrapper_config(config_path)

    def test_v4_config_requires_exact_replay_audit_and_retains_v3_custody(self) -> None:
        config_path = self.root / "wrapper-v4.json"
        document = self._document(schema_version=ENGINE_WRAPPER_V4_SCHEMA_VERSION)
        config_path.write_bytes(canonical_json_bytes(document))

        loaded = load_engine_wrapper_config(config_path)
        self.assertIsNotNone(loaded.base_snapshot)
        self.assertEqual(self.file, loaded.promotion.csharp_verifier_replay_audit_path)
        self.assertEqual(
            "7" * 64,
            loaded.promotion.expected_csharp_verifier_replay_audit_envelope_sha256,
        )
        self.assertEqual(
            "csharp-replay-audit-key-v1",
            loaded.promotion.csharp_verifier_replay_audit_trust.key_id,
        )
        self.assertEqual(
            self.file,
            loaded.promotion.validation_arguments()[
                "csharp_verifier_replay_audit_path"
            ],
        )

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v4.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ENGINE_WRAPPER_V4_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        audit_schema = schema["properties"]["promotion"]["properties"][
            "csharpVerifierReplayAudit"
        ]
        self.assertFalse(audit_schema["additionalProperties"])
        self.assertEqual(
            {"path", "expectedEnvelopeSha256", "trust"},
            set(audit_schema["required"]),
        )

        for name, mutation in (
            (
                "missing",
                lambda value: value["promotion"].pop("csharpVerifierReplayAudit"),
            ),
            (
                "bad-hash",
                lambda value: value["promotion"]["csharpVerifierReplayAudit"].update(
                    expectedEnvelopeSha256="ABC"
                ),
            ),
            (
                "private-key",
                lambda value: value["promotion"]["csharpVerifierReplayAudit"][
                    "trust"
                ].update(privateKeyPath=os.fspath(self.file)),
            ),
        ):
            with self.subTest(name=name):
                invalid = self._document(
                    schema_version=ENGINE_WRAPPER_V4_SCHEMA_VERSION
                )
                mutation(invalid)
                config_path.write_bytes(canonical_json_bytes(invalid))
                with self.assertRaises(ValidationError):
                    load_engine_wrapper_config(config_path)

    def test_v5_config_requires_evaluation_authoring_trust_and_allows_no_audit(
        self,
    ) -> None:
        config_path = self.root / "wrapper-v5.json"
        document = self._document(schema_version=ENGINE_WRAPPER_V5_SCHEMA_VERSION)
        document["promotion"]["csharpVerifierReplayAudit"] = None
        config_path.write_bytes(canonical_json_bytes(document))

        loaded = load_engine_wrapper_config(config_path)
        self.assertEqual(ENGINE_WRAPPER_V5_SCHEMA_VERSION, loaded.schema_version)
        self.assertIsInstance(
            loaded.promotion.evaluation_authoring_approval_trust,
            EvaluationAuthoringApprovalTrust,
        )
        self.assertEqual(
            "9" * 64,
            loaded.promotion.evaluation_authoring_approval_trust.public_key_spki_sha256,
        )
        candidate = loaded.promotion.candidate_attestation_trust
        self.assertIsInstance(candidate, BaseResponseAttestationTrust)
        self.assertEqual(
            "candidate-activation-key-v1",
            candidate.activation_trust.key_id if candidate is not None else None,
        )
        self.assertIsNone(loaded.promotion.baseline_attestation_trust)
        self.assertEqual(10001, loaded.engine.child_user_id)
        self.assertEqual(10001, loaded.engine.child_group_id)
        self.assertIsNone(loaded.promotion.csharp_verifier_replay_audit_path)

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v5.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ENGINE_WRAPPER_V5_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        promotion_schema = schema["properties"]["promotion"]
        self.assertIn("evaluationAuthoringApprovalTrust", promotion_schema["required"])
        self.assertIn("csharpVerifierReplayAudit", promotion_schema["required"])

        for name, mutation in (
            (
                "missing",
                lambda value: value["promotion"].pop(
                    "evaluationAuthoringApprovalTrust"
                ),
            ),
            (
                "bad-hash",
                lambda value: value["promotion"][
                    "evaluationAuthoringApprovalTrust"
                ].update(publicKeySpkiSha256="A" * 64),
            ),
            (
                "private-key",
                lambda value: value["promotion"][
                    "evaluationAuthoringApprovalTrust"
                ].update(privateKeyPath=os.fspath(self.file)),
            ),
        ):
            with self.subTest(name=name):
                invalid = self._document(
                    schema_version=ENGINE_WRAPPER_V5_SCHEMA_VERSION
                )
                mutation(invalid)
                config_path.write_bytes(canonical_json_bytes(invalid))
                with self.assertRaises(ValidationError):
                    load_engine_wrapper_config(config_path)

    def test_v6_config_requires_trainer_provenance_trust(self) -> None:
        config_path = self.root / "wrapper-v6.json"
        document = self._document(schema_version=ENGINE_WRAPPER_V6_SCHEMA_VERSION)
        document["promotion"]["csharpVerifierReplayAudit"] = None
        config_path.write_bytes(canonical_json_bytes(document))

        loaded = load_engine_wrapper_config(config_path)
        self.assertEqual(ENGINE_WRAPPER_V6_SCHEMA_VERSION, loaded.schema_version)
        self.assertIsInstance(
            loaded.promotion.trainer_provenance_trust,
            TrainerProvenanceTrust,
        )
        self.assertEqual(
            "a" * 64,
            loaded.promotion.trainer_provenance_trust.public_key_spki_sha256,
        )
        self.assertIsNotNone(loaded.base_snapshot)
        self.assertEqual(10001, loaded.engine.child_user_id)
        self.assertEqual(10001, loaded.engine.child_group_id)

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v6.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            ENGINE_WRAPPER_V6_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        self.assertIn(
            "trainerProvenanceTrust",
            schema["properties"]["promotion"]["required"],
        )

        for name, mutation in (
            (
                "missing",
                lambda value: value["promotion"].pop("trainerProvenanceTrust"),
            ),
            (
                "bad-hash",
                lambda value: value["promotion"]["trainerProvenanceTrust"].update(
                    publicKeySpkiSha256="A" * 64
                ),
            ),
            (
                "private-key",
                lambda value: value["promotion"]["trainerProvenanceTrust"].update(
                    privateKeyPath=os.fspath(self.file)
                ),
            ),
        ):
            with self.subTest(name=name):
                invalid = self._document(
                    schema_version=ENGINE_WRAPPER_V6_SCHEMA_VERSION
                )
                mutation(invalid)
                config_path.write_bytes(canonical_json_bytes(invalid))
                with self.assertRaises(ValidationError):
                    load_engine_wrapper_config(config_path)

    def test_v7_config_requires_strict_nullable_teacher_lineage_trust(self) -> None:
        config_path = self.root / "wrapper-v7.json"
        document = self._document(schema_version=ENGINE_WRAPPER_V7_SCHEMA_VERSION)
        config_path.write_bytes(canonical_json_bytes(document))

        loaded = load_engine_wrapper_config(config_path)
        self.assertEqual(ENGINE_WRAPPER_V7_SCHEMA_VERSION, loaded.schema_version)
        self.assertIsNone(
            loaded.promotion.review_receipt_trust.teacher_lineage_admission_trust
        )

        lineage_trust = {
            "publicKeyPath": os.fspath(self.file),
            "publicKeySpkiSha256": "b" * 64,
            "audience": "daxalgo-vibe-quant-teacher-lineage",
            "keyId": "teacher-lineage-key-v1",
            "signerRole": "teacher-lineage-reviewer",
        }
        document["promotion"]["teacherLineageAdmissionTrust"] = lineage_trust
        config_path.write_bytes(canonical_json_bytes(document))
        populated = load_engine_wrapper_config(config_path)
        parsed_lineage = (
            populated.promotion.review_receipt_trust.teacher_lineage_admission_trust
        )
        self.assertIsNotNone(parsed_lineage)
        self.assertEqual(
            "b" * 64,
            parsed_lineage.public_key_spki_sha256,
        )
        self.assertEqual(self.file, parsed_lineage.public_key_path)

        schema = json.loads(
            (
                Path(__file__).parent.parent
                / "schemas"
                / "engine-wrapper.v7.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            "https://daxalgo.local/schemas/vibe-quant/engine-wrapper.v7.schema.json",
            schema["$id"],
        )
        self.assertEqual(
            ENGINE_WRAPPER_V7_SCHEMA_VERSION,
            schema["properties"]["schemaVersion"]["const"],
        )
        promotion_schema = schema["properties"]["promotion"]
        self.assertIn("teacherLineageAdmissionTrust", promotion_schema["required"])
        self.assertEqual(
            [{"type": "null"}, {"$ref": "#/$defs/signingTrust"}],
            promotion_schema["properties"]["teacherLineageAdmissionTrust"]["oneOf"],
        )
        self.assertFalse(schema["$defs"]["signingTrust"]["additionalProperties"])

        for name, mutation in (
            (
                "missing",
                lambda value: value["promotion"].pop("teacherLineageAdmissionTrust"),
            ),
            (
                "partial",
                lambda value: value["promotion"]["teacherLineageAdmissionTrust"].pop(
                    "signerRole"
                ),
            ),
            (
                "private-key",
                lambda value: value["promotion"]["teacherLineageAdmissionTrust"].update(
                    privateKeyPath=os.fspath(self.file)
                ),
            ),
            (
                "bad-hash",
                lambda value: value["promotion"]["teacherLineageAdmissionTrust"].update(
                    publicKeySpkiSha256="B" * 64
                ),
            ),
            (
                "receipt-signer-reuse",
                lambda value: value["promotion"]["teacherLineageAdmissionTrust"].update(
                    publicKeySpkiSha256="4" * 64
                ),
            ),
        ):
            with self.subTest(name=name):
                invalid = self._document(
                    schema_version=ENGINE_WRAPPER_V7_SCHEMA_VERSION
                )
                invalid["promotion"]["teacherLineageAdmissionTrust"] = dict(
                    lineage_trust
                )
                mutation(invalid)
                config_path.write_bytes(canonical_json_bytes(invalid))
                with self.assertRaises(ValidationError):
                    load_engine_wrapper_config(config_path)

    def test_v6_historical_config_loads_without_teacher_lineage_trust(self) -> None:
        config_path = self.root / "wrapper-v6-historical.json"
        historical = self._document(schema_version=ENGINE_WRAPPER_V6_SCHEMA_VERSION)
        config_path.write_bytes(canonical_json_bytes(historical))

        loaded = load_engine_wrapper_config(config_path)
        self.assertEqual(ENGINE_WRAPPER_V6_SCHEMA_VERSION, loaded.schema_version)
        self.assertIsNone(
            loaded.promotion.review_receipt_trust.teacher_lineage_admission_trust
        )

        historical["promotion"]["teacherLineageAdmissionTrust"] = None
        config_path.write_bytes(canonical_json_bytes(historical))
        with self.assertRaisesRegex(ValidationError, "teacherLineageAdmissionTrust"):
            load_engine_wrapper_config(config_path)

    def test_v1_and_v2_config_surfaces_remain_exact(self) -> None:
        config_path = self.root / "wrapper.json"

        v1_with_v2_trust = self._document()
        v1_with_v2_trust["promotion"]["candidateAttestationTrust"] = None
        v1_with_v2_trust["promotion"]["baselineAttestationTrust"] = None
        config_path.write_bytes(canonical_json_bytes(v1_with_v2_trust))
        with self.assertRaisesRegex(ValidationError, "additional"):
            load_engine_wrapper_config(config_path)

        missing_v2_field = self._document(
            schema_version=ENGINE_WRAPPER_V2_SCHEMA_VERSION
        )
        missing_v2_field["promotion"].pop("baselineAttestationTrust")
        config_path.write_bytes(canonical_json_bytes(missing_v2_field))
        with self.assertRaisesRegex(ValidationError, "baselineAttestationTrust"):
            load_engine_wrapper_config(config_path)

        extra_activation_field = self._document(
            schema_version=ENGINE_WRAPPER_V2_SCHEMA_VERSION
        )
        extra_activation_field["promotion"]["candidateAttestationTrust"][
            "activationTrust"
        ]["privateKeyPath"] = os.fspath(self.file)
        config_path.write_bytes(canonical_json_bytes(extra_activation_field))
        with self.assertRaisesRegex(ValidationError, "privateKeyPath"):
            load_engine_wrapper_config(config_path)

        v2_with_v3_snapshot = self._document(
            schema_version=ENGINE_WRAPPER_V2_SCHEMA_VERSION
        )
        v2_with_v3_snapshot["baseSnapshot"] = self._document(
            schema_version=ENGINE_WRAPPER_V3_SCHEMA_VERSION
        )["baseSnapshot"]
        config_path.write_bytes(canonical_json_bytes(v2_with_v3_snapshot))
        with self.assertRaisesRegex(ValidationError, "baseSnapshot"):
            load_engine_wrapper_config(config_path)

    def test_config_requires_exact_public_review_receipt_trust(self) -> None:
        config_path = self.root / "wrapper.json"

        missing = self._document()
        missing["promotion"].pop("reviewReceiptTrust")
        config_path.write_bytes(canonical_json_bytes(missing))
        with self.assertRaisesRegex(ValidationError, "reviewReceiptTrust"):
            load_engine_wrapper_config(config_path)

        wrong_hash = self._document()
        wrong_hash["promotion"]["reviewReceiptTrust"]["publicKeySpkiSha256"] = "A" * 64
        config_path.write_bytes(canonical_json_bytes(wrong_hash))
        with self.assertRaisesRegex(ValidationError, "SPKI SHA-256"):
            load_engine_wrapper_config(config_path)

        private_key = self._document()
        private_key["promotion"]["reviewReceiptTrust"]["privateKeyPath"] = os.fspath(
            self.file
        )
        config_path.write_bytes(canonical_json_bytes(private_key))
        with self.assertRaisesRegex(ValidationError, "privateKeyPath"):
            load_engine_wrapper_config(config_path)

    def test_config_rejects_secret_child_environment_and_remote_bind(self) -> None:
        config_path = self.root / "wrapper.json"
        secret = self._document()
        secret["engine"]["environmentAllowlist"] = ["API_TOKEN"]
        config_path.write_bytes(canonical_json_bytes(secret))
        with self.assertRaisesRegex(ValidationError, "secret-bearing"):
            load_engine_wrapper_config(config_path)

        injection = self._document()
        injection["engine"]["environmentAllowlist"] = ["PYTHONPATH"]
        config_path.write_bytes(canonical_json_bytes(injection))
        with self.assertRaisesRegex(ValidationError, "safe child-environment"):
            load_engine_wrapper_config(config_path)

        aliased = self._document()
        aliased["engine"]["containerImageDigestEnvironment"] = "OUTER_BEARER_SECRET"
        config_path.write_bytes(canonical_json_bytes(aliased))
        with self.assertRaisesRegex(ValidationError, "distinct environment"):
            load_engine_wrapper_config(config_path)

        remote = self._document()
        remote["service"]["listenHost"] = "0.0.0.0"
        config_path.write_bytes(canonical_json_bytes(remote))
        with self.assertRaisesRegex(ValidationError, "127.0.0.1"):
            load_engine_wrapper_config(config_path)

    def test_cli_routes_serve_promoted_model_without_printing_secrets(self) -> None:
        config_path = self.root / "wrapper.json"
        with mock.patch.object(cli_module, "serve_promoted_model") as serve:
            self.assertEqual(
                0, cli_module.main(["serve-promoted-model", os.fspath(config_path)])
            )
        serve.assert_called_once_with(config_path)


class PromotionAttestationCliTests(unittest.TestCase):
    _COMMANDS = (
        "aggregate-promotion-evidence",
        "create-model-promotion",
        "prepare-model-promotion-signing-bundle",
        "finalize-model-promotion",
        "validate-model-promotion",
        "create-model-readiness-v2",
    )
    _OPTIONS = {
        f"--{prefix}-{suffix}"
        for prefix in ("candidate", "baseline")
        for suffix in (
            "activation-public-key",
            "activation-public-key-spki-sha256",
            "activation-audience",
            "activation-key-id",
            "activation-signer-role",
            "runtime-public-key",
        )
    }
    _PRODUCTION_COMMANDS = (
        "create-model-promotion",
        "prepare-model-promotion-signing-bundle",
        "finalize-model-promotion",
        "validate-model-promotion",
        "create-model-readiness-v2",
    )
    _BASE_SELECTION_OPTIONS = {
        "--base-selection-public-key",
        "--base-selection-public-key-spki-sha256",
        "--base-selection-audience",
        "--base-selection-key-id",
        "--base-selection-signer-role",
        "--base-model-snapshot",
    }

    @staticmethod
    def _namespace(**overrides: object) -> Namespace:
        values: dict[str, object | None] = {
            f"{prefix}_{suffix}": None
            for prefix in ("candidate", "baseline")
            for suffix in (
                "activation_public_key",
                "activation_public_key_spki_sha256",
                "activation_audience",
                "activation_key_id",
                "activation_signer_role",
                "runtime_public_key",
            )
        }
        values.update(overrides)
        return Namespace(**values)

    @staticmethod
    def _aggregate_arguments() -> list[str]:
        return [
            "aggregate-promotion-evidence",
            "--calibration-tasks",
            "calibration-tasks.jsonl",
            "--calibration-evidence",
            "calibration-evidence.json",
            "--sealed-tasks",
            "sealed-tasks.jsonl",
            "--responses",
            "responses.jsonl",
            "--verifier-results",
            "verifier-results.jsonl",
            "--baseline-responses",
            "baseline-responses.jsonl",
            "--baseline-verifier-results",
            "baseline-verifier-results.jsonl",
            "--policy",
            "policy.json",
        ]

    def test_all_promotion_commands_expose_both_optional_trust_groups(self) -> None:
        parser = cli_module._parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
        )
        for command in self._COMMANDS:
            with self.subTest(command=command):
                command_parser = subparsers.choices[command]
                options = {
                    option
                    for action in command_parser._actions
                    for option in action.option_strings
                }
                self.assertLessEqual(self._OPTIONS, options)

    def test_production_commands_require_selection_trust_and_exact_snapshot(
        self,
    ) -> None:
        parser = cli_module._parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
        )
        for command in self._PRODUCTION_COMMANDS:
            with self.subTest(command=command):
                command_parser = subparsers.choices[command]
                actions = {
                    option: action
                    for action in command_parser._actions
                    for option in action.option_strings
                }
                self.assertLessEqual(self._BASE_SELECTION_OPTIONS, set(actions))
                for option in self._BASE_SELECTION_OPTIONS:
                    self.assertTrue(actions[option].required, option)

    def test_prefixed_trust_groups_are_all_or_none_and_independent(self) -> None:
        empty = cli_module._promotion_attestation_trust_arguments(self._namespace())
        self.assertEqual(
            {
                "candidate_attestation_trust": None,
                "baseline_attestation_trust": None,
            },
            empty,
        )

        candidate_public_key = Path("candidate-activation.pem")
        candidate_runtime_key = Path("candidate-runtime.pem")
        values = self._namespace(
            candidate_activation_public_key=candidate_public_key,
            candidate_activation_public_key_spki_sha256="a" * 64,
            candidate_activation_audience="daxalgo-base-evaluation",
            candidate_activation_key_id="candidate-activation-key-v1",
            candidate_activation_signer_role="base-model-launch-authority",
            candidate_runtime_public_key=candidate_runtime_key,
        )
        trusts = cli_module._promotion_attestation_trust_arguments(values)
        candidate = trusts["candidate_attestation_trust"]
        self.assertIsInstance(candidate, BaseResponseAttestationTrust)
        self.assertEqual(
            candidate_public_key, candidate.activation_trust.public_key_path
        )
        self.assertEqual(candidate_runtime_key, candidate.runtime_public_key_path)
        self.assertIsNone(trusts["baseline_attestation_trust"])

        partial = self._namespace(candidate_activation_public_key=candidate_public_key)
        with self.assertRaisesRegex(ValidationError, "all six"):
            cli_module._promotion_attestation_trust_arguments(partial)

    def test_aggregate_cli_routes_trust_and_rejects_partial_group(self) -> None:
        arguments = self._aggregate_arguments()
        complete = arguments + [
            "--baseline-activation-public-key",
            "baseline-activation.pem",
            "--baseline-activation-public-key-spki-sha256",
            "b" * 64,
            "--baseline-activation-audience",
            "daxalgo-base-evaluation",
            "--baseline-activation-key-id",
            "baseline-activation-key-v1",
            "--baseline-activation-signer-role",
            "base-model-launch-authority",
            "--baseline-runtime-public-key",
            "baseline-runtime.pem",
        ]
        with (
            mock.patch.object(
                cli_module,
                "aggregate_promotion_evidence",
                return_value={"reportSha256": "c" * 64},
            ) as aggregate,
            mock.patch.object(cli_module, "_print"),
        ):
            self.assertEqual(0, cli_module.main(complete))
        baseline = aggregate.call_args.kwargs["baseline_attestation_trust"]
        self.assertIsInstance(baseline, BaseResponseAttestationTrust)
        self.assertEqual(
            "baseline-activation-key-v1",
            baseline.activation_trust.key_id,
        )
        self.assertIsNone(aggregate.call_args.kwargs["candidate_attestation_trust"])

        partial = arguments + [
            "--candidate-activation-public-key",
            "candidate-activation.pem",
        ]
        stderr = StringIO()
        with (
            mock.patch.object(cli_module, "aggregate_promotion_evidence") as aggregate,
            redirect_stderr(stderr),
        ):
            self.assertEqual(2, cli_module.main(partial))
        aggregate.assert_not_called()
        self.assertIn("all six", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
