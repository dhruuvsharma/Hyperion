from __future__ import annotations

import copy
import hashlib
import importlib
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from base64 import urlsafe_b64decode
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping
from unittest import mock

import jsonschema
import hyperion_model.base_engine_wrapper as base_engine_wrapper_module
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509.oid import NameOID

from hyperion_model.base_engine_wrapper import (
    BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION,
    BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION,
    BASE_ATTESTED_COMPLETIONS_PATH,
    BASE_ENGINE_ACTIVATION_SIGNATURE_SCHEMA_VERSION,
    BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_SCHEMA_VERSION,
    BASE_ENGINE_ACTIVATION_SCHEMA_VERSION,
    BASE_ENGINE_WRAPPER_SCHEMA_VERSION,
    BASE_ENGINE_WRAPPER_V2_SCHEMA_VERSION,
    BASE_RUNTIME_ATTESTATION_SCHEMA_VERSION,
    BASE_RUNTIME_SIGNER_PROVIDER,
    BASE_RUNTIME_SIGNER_REQUEST_SCHEMA_VERSION,
    BASE_RUNTIME_SIGNER_RESPONSE_SCHEMA_VERSION,
    BaseEngineActivationTrust,
    BaseModelEngineWrapper,
    base_engine_activation_external_signature_id,
    create_base_engine_activation,
    finalize_base_engine_activation,
    inspect_base_runtime_attestation_envelope,
    load_base_engine_wrapper_config,
    prepare_base_engine_activation_signing_bundle,
    verify_base_engine_activation_signing_bundle,
    verify_base_runtime_attestation,
)
from hyperion_model.base_evaluation import (
    BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
    create_base_evaluation_profile,
    seal_base_model_snapshot,
)
from hyperion_model.core import DOMAINS, ValidationError, canonical_json_bytes
from hyperion_model.engine_wrapper import TransportResponse, WrapperState
from hyperion_model.evaluation import (
    EVALUATION_RESPONSE_SCHEMA_VERSION,
    EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
    EVALUATION_TASK_SCHEMA_VERSION,
    BaseResponseAttestationTrust,
    TransportResponse as CaptureTransportResponse,
    aggregate_promotion_evidence,
    capture_openai_responses,
    evaluation_prompt_sha256,
    evaluation_response_sha256,
    evaluation_task_sha256,
    validate_attested_base_evaluation_responses,
    validate_evaluation_responses,
    validate_evaluation_tasks,
)


ROOT = Path(__file__).resolve().parents[1]
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value))


def _safetensors() -> bytes:
    header = b'{"weight":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}'
    return len(header).to_bytes(8, "little") + header + b"\x00\x00"


def _evaluation_task() -> dict:
    messages = [
        {"role": "system", "content": "Answer from reviewed context only."},
        {"role": "user", "content": "Review the supplied C# risk calculation."},
    ]
    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": "base-eval-1",
        "taskSha256": "0" * 64,
        "split": "sealed",
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
        "contaminationGroup": "group-base-eval-1",
        "cutoffUtc": "2025-01-15T12:00:00Z",
        "criticality": "critical",
        "maxOutputTokens": 128,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    return task


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


class BaseEngineWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = self.root / "candidate-catalog.json"
        shutil.copyfile(ROOT / "candidate-catalog.v1.json", self.catalog)
        self.snapshot = self.root / "model"
        self.snapshot.mkdir()
        _write_json(self.snapshot / "config.json", {"model_type": "qwen2"})
        _write_json(
            self.snapshot / "tokenizer_config.json",
            {
                "chat_template": "{% for message in messages %}{{ message['role'] }}: {{ message['content'] }}\n{% endfor %}"
            },
        )
        _write_json(self.snapshot / "tokenizer.json", {"version": "1.0"})
        (self.snapshot / "model.safetensors").write_bytes(_safetensors())
        source_files = []
        for path in sorted(self.snapshot.iterdir(), key=lambda item: item.name):
            raw = path.read_bytes()
            source_files.append(
                {
                    "path": path.name,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "sizeBytes": len(raw),
                }
            )
        catalog = json.loads(self.catalog.read_text(encoding="utf-8"))
        candidate = next(
            item
            for item in catalog["candidates"]
            if item["id"] == "qwen2.5-coder-7b-instruct"
        )
        self.source_lock = self.root / "source-lock.json"
        source_lock = {
            "schemaVersion": BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION,
            "candidateCatalogSha256": hashlib.sha256(
                self.catalog.read_bytes()
            ).hexdigest(),
            "candidates": [
                {
                    "candidateId": candidate["id"],
                    "modelId": candidate["modelId"],
                    "revision": candidate["revision"],
                    "files": source_files,
                }
            ],
        }
        _write_json(self.source_lock, source_lock)
        self.source_lock_patcher = mock.patch(
            "hyperion_model.base_evaluation.APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256",
            hashlib.sha256(canonical_json_bytes(source_lock)).hexdigest(),
        )
        self.source_lock_patcher.start()
        self.addCleanup(self.source_lock_patcher.stop)
        self.manifest = self.root / "snapshot.json"
        self.profile_path = self.root / "profile.json"
        seal_base_model_snapshot(
            snapshot_path=self.snapshot,
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
            candidate_id="qwen2.5-coder-7b-instruct",
            output_path=self.manifest,
        )
        self.image_digest = "sha256:" + "6" * 64
        self.profile = create_base_evaluation_profile(
            profile_id="qwen25-7b-base-v1",
            catalog_path=self.catalog,
            source_lock_path=self.source_lock,
            snapshot_manifest_path=self.manifest,
            snapshot_path=self.snapshot,
            output_path=self.profile_path,
            engine_version="0.10.0",
            container_image_digest=self.image_digest,
            quantization="bitsandbytes-nf4",
            compute_dtype="bfloat16",
            max_model_length=8_192,
            tensor_parallel_size=1,
            gpu_profile="l40s-48gb",
        )
        self.executable = self.root / "vllm"
        self.executable.write_bytes(b"#!/usr/bin/env python3\n")
        self.package = self.root / "wrapper-package"
        self.package.mkdir()
        (self.package / "owner.py").write_text("OWNER = True\n", encoding="utf-8")
        self.launcher_private, self.launcher_public, self.launcher_spki = self._keys(
            "launcher"
        )
        self.runtime_private, self.runtime_public, self.runtime_spki = self._keys(
            "runtime"
        )
        (
            self.signer_tls_certificate,
            self.signer_tls_certificate_sha256,
        ) = self._tls_certificate()
        self.activation_path = self.root / "activation.json"
        self.config_path = self.root / "wrapper.json"
        self.bearer = "B" * 48
        _write_json(
            self.config_path,
            {
                "schemaVersion": BASE_ENGINE_WRAPPER_SCHEMA_VERSION,
                "target": {
                    "profilePath": str(self.profile_path),
                    "snapshotManifestPath": str(self.manifest),
                    "snapshotPath": str(self.snapshot),
                    "catalogPath": str(self.catalog),
                    "sourceLockPath": str(self.source_lock),
                    "expectedProfileSha256": self.profile.sha256,
                },
                "activation": {
                    "path": str(self.activation_path),
                    "publicKeyPath": str(self.launcher_public),
                    "publicKeySpkiSha256": self.launcher_spki,
                    "audience": "daxalgo-base-evaluation",
                    "keyId": "launcher-key-v1",
                    "signerRole": "base-runtime-launcher",
                },
                "runtimeSigning": {
                    "privateKeyPath": str(self.runtime_private),
                    "publicKeyPath": str(self.runtime_public),
                    "privateKeyPasswordEnvironment": None,
                    "audience": "daxalgo-base-evaluation",
                    "keyId": "runtime-key-v1",
                    "signerRole": "owned-base-engine",
                    "receiptTtlSeconds": 60,
                },
                "engine": {
                    "executablePath": str(self.executable),
                    "executableSha256": hashlib.sha256(
                        self.executable.read_bytes()
                    ).hexdigest(),
                    "containerImageDigestEnvironment": "VQ_CURRENT_IMAGE",
                    "childHost": "127.0.0.1",
                    "childPort": 18091,
                    "childUserId": 65534,
                    "childGroupId": 65534,
                    "startupTimeoutSeconds": 2,
                    "healthIntervalSeconds": 1,
                    "integrityIntervalSeconds": 300,
                    "requestTimeoutSeconds": 2,
                    "shutdownGraceSeconds": 0,
                    "environmentAllowlist": ["PATH", "CUDA_VISIBLE_DEVICES"],
                },
                "service": {
                    "listenHost": "127.0.0.1",
                    "listenPort": 18090,
                    "bearerTokenEnvironment": "VQ_OUTER_BEARER",
                    "maxRequestBytes": 100_000,
                    "maxResponseBytes": 100_000,
                    "maxAttestations": 100,
                },
            },
        )
        self.config = load_base_engine_wrapper_config(self.config_path)
        self.activation = create_base_engine_activation(
            config_path=self.config_path,
            output_path=self.activation_path,
            private_key_path=self.launcher_private,
            public_key_path=self.launcher_public,
            private_key_password=None,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
            issued_at_utc="2026-07-28T09:59:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-07-29T10:00:00Z",
            package_root=self.package,
        )
        self.environment = mock.patch.dict(
            os.environ,
            {
                "VQ_CURRENT_IMAGE": self.image_digest,
                "VQ_OUTER_BEARER": self.bearer,
                "VQ_RUNTIME_SIGNER_BEARER": "S" * 48,
                "CUDA_VISIBLE_DEVICES": "0",
                "SHOULD_NOT_REACH_CHILD_SECRET": "hidden",
            },
            clear=False,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.process = _FakeProcess()
        self.process_argv: tuple[str, ...] | None = None
        self.process_environment: Mapping[str, str] | None = None
        self.child_requests: list[dict] = []
        self.signer_requests: list[dict] = []
        self.signer_responses: list[dict] = []
        self.now = datetime(2026, 7, 28, 10, 0, 5, tzinfo=timezone.utc)

    def _keys(self, stem: str) -> tuple[Path, Path, str]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_path = self.root / f"{stem}-private.pem"
        public_path = self.root / f"{stem}-public.pem"
        private_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_key = private_key.public_key()
        public_path.write_bytes(
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_path, public_path, hashlib.sha256(spki).hexdigest()

    def _tls_certificate(self) -> tuple[Path, str]:
        private_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "runtime-signer")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
            .sign(private_key, hashes.SHA256())
        )
        path = self.root / "runtime-signer-tls-certificate.pem"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        der = certificate.public_bytes(serialization.Encoding.DER)
        return path, hashlib.sha256(der).hexdigest()

    def _tls_certificate_for_key(
        self, stem: str, private_key_path: Path
    ) -> tuple[Path, str]:
        private_key = serialization.load_pem_private_key(
            private_key_path.read_bytes(), password=None
        )
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, stem)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
            .sign(private_key, hashes.SHA256())
        )
        path = self.root / f"{stem}-certificate.pem"
        path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        der = certificate.public_bytes(serialization.Encoding.DER)
        return path, hashlib.sha256(der).hexdigest()

    def _process_factory(self, descriptor, argv, environment, working_directory):
        self.process_argv = tuple(argv)
        self.process_environment = dict(environment)
        return self.process

    def _transport(self, method, url, headers, body, timeout, max_bytes):
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
                        "data": [
                            {
                                "id": self.profile.execution_model_id,
                                "root": str(self.snapshot),
                                "max_model_len": 8_192,
                            }
                        ]
                    }
                ),
                url,
            )
        if url.endswith("/v1/chat/completions"):
            request = json.loads(body)
            self.child_requests.append(request)
            return TransportResponse(
                200,
                {"Content-Type": "application/json"},
                canonical_json_bytes(
                    {
                        "id": "chatcmpl-base",
                        "object": "chat.completion",
                        "model": self.profile.execution_model_id,
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": "Reviewed.",
                                },
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 2,
                            "total_tokens": 12,
                        },
                    }
                ),
                url,
            )
        raise AssertionError(url)

    def _external_config(
        self,
        stem: str,
        *,
        signature_format: str = "asn1-der",
        receipt_ttl_seconds: int = 60,
        runtime_overrides: Mapping[str, object] | None = None,
    ):
        activation_path = self.root / f"{stem}-activation.json"
        config_path = self.root / f"{stem}-wrapper.json"
        value = json.loads(self.config_path.read_text(encoding="utf-8"))
        value["schemaVersion"] = BASE_ENGINE_WRAPPER_V2_SCHEMA_VERSION
        value["activation"]["path"] = str(activation_path)
        value["runtimeSigning"] = {
            "provider": BASE_RUNTIME_SIGNER_PROVIDER,
            "signerEndpoint": (
                "https://127.0.0.1:18092/v1/daxalgo/base-runtime-signatures"
            ),
            "signerBearerTokenEnvironment": "VQ_RUNTIME_SIGNER_BEARER",
            "providerKeyReference": "kms://daxalgo/runtime-key/versions/1",
            "signerTlsCertificatePath": str(self.signer_tls_certificate),
            "signerTlsCertificateSha256": self.signer_tls_certificate_sha256,
            "requestTimeoutSeconds": 2,
            "maxResponseBytes": 16_384,
            "signatureFormat": signature_format,
            "publicKeyPath": str(self.runtime_public),
            "publicKeySpkiSha256": self.runtime_spki,
            "audience": "daxalgo-base-evaluation",
            "keyId": "runtime-key-v1",
            "signerRole": "owned-base-engine",
            "receiptTtlSeconds": receipt_ttl_seconds,
        }
        if runtime_overrides is not None:
            value["runtimeSigning"].update(runtime_overrides)
        _write_json(config_path, value)
        config = load_base_engine_wrapper_config(config_path)
        activation = create_base_engine_activation(
            config_path=config_path,
            output_path=activation_path,
            private_key_path=self.launcher_private,
            public_key_path=self.launcher_public,
            private_key_password=None,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
            issued_at_utc="2026-07-28T09:59:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-07-29T10:00:00Z",
            package_root=self.package,
        )
        return config_path, config, activation

    def _detached_activation_config(self, stem: str) -> tuple[Path, Path]:
        activation_path = self.root / f"{stem}-activation.json"
        config_path = self.root / f"{stem}-wrapper.json"
        value = json.loads(self.config_path.read_text(encoding="utf-8"))
        value["activation"]["path"] = str(activation_path)
        _write_json(config_path, value)
        return config_path, activation_path

    def _prepare_detached_activation(self, stem: str):
        config_path, activation_path = self._detached_activation_config(stem)
        bundle_path = self.root / f"{stem}-signing-bundle.json"
        bundle = prepare_base_engine_activation_signing_bundle(
            config_path=config_path,
            output_path=bundle_path,
            public_key_path=self.launcher_public,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
            issued_at_utc="2026-07-28T09:59:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-07-29T10:00:00Z",
            package_root=self.package,
            now=self.now,
        )
        return config_path, activation_path, bundle_path, bundle

    def _write_detached_activation_signature(
        self,
        stem: str,
        bundle,
        *,
        mode: str,
        signature_format: str,
        high_s: bool = False,
        wrong_key: bool = False,
        double_hash: bool = False,
    ) -> tuple[Path, dict]:
        private_key = (
            ec.generate_private_key(ec.SECP256R1())
            if wrong_key
            else serialization.load_pem_private_key(
                self.launcher_private.read_bytes(), password=None
            )
        )
        signature_digest = hashlib.sha256(bundle.signature_preimage).digest()
        if mode == "raw-message":
            signing_input = bundle.signature_preimage
            algorithm = ec.ECDSA(hashes.SHA256())
        else:
            signing_input = signature_digest
            algorithm = (
                ec.ECDSA(hashes.SHA256())
                if double_hash
                else ec.ECDSA(Prehashed(hashes.SHA256()))
            )
        der = private_key.sign(signing_input, algorithm)
        r, s = decode_dss_signature(der)
        if high_s and s <= P256_ORDER // 2:
            s = P256_ORDER - s
        if signature_format == "asn1-der":
            signature = encode_dss_signature(r, s)
        else:
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        document = {
            "schemaVersion": BASE_ENGINE_ACTIVATION_SIGNATURE_SCHEMA_VERSION,
            "signatureId": "vqbaseactsignature-" + "0" * 64,
            "signingBundleId": bundle.bundle_id,
            "signingBundleSha256": bundle.bundle_sha256,
            "activationId": bundle.payload["activationId"],
            "payloadSha256": bundle.payload_sha256,
            "unsignedEnvelopeSha256": bundle.unsigned_envelope_sha256,
            "signatureInputSha256": bundle.signature_input_sha256,
            "publicKeySpkiSha256": bundle.public_key_spki_sha256,
            "mode": mode,
            "format": signature_format,
            "signature": base_engine_wrapper_module._base64url_encode(signature),
        }
        document["signatureId"] = base_engine_activation_external_signature_id(document)
        path = self.root / f"{stem}-signature.json"
        path.write_bytes(canonical_json_bytes(document) + b"\n")
        return path, document

    def _finalize_detached_activation(
        self,
        *,
        config_path: Path,
        bundle_path: Path,
        signature_path: Path,
        activation_path: Path,
    ):
        return finalize_base_engine_activation(
            config_path=config_path,
            signing_bundle_path=bundle_path,
            signature_path=signature_path,
            output_path=activation_path,
            public_key_path=self.launcher_public,
            expected_audience="daxalgo-base-evaluation",
            expected_key_id="launcher-key-v1",
            expected_signer_role="base-runtime-launcher",
            package_root=self.package,
            now=self.now,
        )

    def _external_signer_transport(
        self,
        *,
        events: list[str] | None = None,
        high_s: bool = False,
        double_hash: bool = False,
        wrong_request_id: bool = False,
        wrong_digest_echo: bool = False,
        wrong_key: bool = False,
        http_status: int = 200,
        noncanonical_response: bool = False,
        oversized_response: bool = False,
        advance_after_runtime_sign_seconds: int = 0,
    ):
        runtime_key = serialization.load_pem_private_key(
            self.runtime_private.read_bytes(), password=None
        )
        wrong_runtime_key = ec.generate_private_key(ec.SECP256R1())

        def transport(method, url, headers, body, timeout, max_bytes):
            if url.endswith("/v1/daxalgo/base-runtime-signatures"):
                request = json.loads(body)
                self.signer_requests.append(request)
                if events is not None:
                    events.append(request["purpose"])
                self.assertEqual("POST", method)
                self.assertEqual(
                    BASE_RUNTIME_SIGNER_REQUEST_SCHEMA_VERSION,
                    request["schemaVersion"],
                )
                self.assertEqual("Bearer " + "S" * 48, headers["Authorization"])
                self.assertEqual("sha256-digest", request["messageType"])
                raw = urlsafe_b64decode(
                    request["signatureInput"]
                    + "=" * (-len(request["signatureInput"]) % 4)
                )
                digest = hashlib.sha256(raw).digest()
                self.assertEqual(digest.hex(), request["signatureInputSha256"])
                self.assertEqual(
                    base_engine_wrapper_module._base64url_encode(digest),
                    request["signatureInputDigest"],
                )
                key = wrong_runtime_key if wrong_key else runtime_key
                algorithm = (
                    ec.ECDSA(hashes.SHA256())
                    if double_hash
                    else ec.ECDSA(Prehashed(hashes.SHA256()))
                )
                der = key.sign(digest, algorithm)
                r, s = decode_dss_signature(der)
                if high_s and s <= P256_ORDER // 2:
                    s = P256_ORDER - s
                if request["signatureFormat"] == "asn1-der":
                    signature = encode_dss_signature(r, s)
                else:
                    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                response = {
                    "schemaVersion": BASE_RUNTIME_SIGNER_RESPONSE_SCHEMA_VERSION,
                    "requestId": (
                        "A" * 43 if wrong_request_id else request["requestId"]
                    ),
                    "purpose": request["purpose"],
                    "providerKeyReference": request["providerKeyReference"],
                    "keyId": request["keyId"],
                    "publicKeySpkiSha256": request["publicKeySpkiSha256"],
                    "algorithm": request["algorithm"],
                    "messageType": request["messageType"],
                    "signatureFormat": request["signatureFormat"],
                    "signatureInputSha256": (
                        "0" * 64
                        if wrong_digest_echo
                        else request["signatureInputSha256"]
                    ),
                    "signatureInputDigest": request["signatureInputDigest"],
                    "signature": base_engine_wrapper_module._base64url_encode(
                        signature
                    ),
                }
                self.signer_responses.append(response)
                if (
                    request["purpose"] == "runtime-attestation"
                    and advance_after_runtime_sign_seconds
                ):
                    self.now += timedelta(seconds=advance_after_runtime_sign_seconds)
                response_body = canonical_json_bytes(response)
                if noncanonical_response:
                    response_body += b"\n"
                if oversized_response:
                    response_body = b" " * (max_bytes + 1)
                return TransportResponse(
                    http_status,
                    {"Content-Type": "application/json"},
                    response_body,
                    url,
                )
            if events is not None:
                events.append(url.rsplit("/", 1)[-1])
            return self._transport(method, url, headers, body, timeout, max_bytes)

        return transport

    def _external_wrapper(self, config, transport) -> BaseModelEngineWrapper:
        wrapper = BaseModelEngineWrapper(
            config,
            bearer_token=self.bearer,
            package_root=self.package,
            child_api_key="C" * 48,
            transport=transport,
            runtime_signer_transport=transport,
            process_factory=self._process_factory,
            read_only_probe=lambda path: True,
            listener_ownership_probe=lambda process_id, host, port: True,
            runtime_key_isolation_probe=lambda config: True,
            clock=lambda: self.now,
        )
        self.addCleanup(wrapper.stop)
        return wrapper

    def _wrapper(
        self, *, config=None, read_only=True, listener_owned=True
    ) -> BaseModelEngineWrapper:
        ticks = [0]

        def advancing_monotonic() -> float:
            ticks[0] += 1
            return float(ticks[0])

        wrapper = BaseModelEngineWrapper(
            self.config if config is None else config,
            bearer_token=self.bearer,
            package_root=self.package,
            child_api_key="C" * 48,
            transport=self._transport,
            process_factory=self._process_factory,
            read_only_probe=lambda path: read_only,
            listener_ownership_probe=lambda process_id, host, port: listener_owned,
            runtime_key_isolation_probe=lambda config: True,
            clock=lambda: self.now,
            monotonic=advancing_monotonic if not listener_owned else None,
            sleeper=(lambda seconds: None) if not listener_owned else None,
        )
        self.addCleanup(wrapper.stop)
        return wrapper

    def _request(
        self, nonce: str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
    ) -> dict:
        return {
            "schemaVersion": BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION,
            "nonce": nonce,
            "evaluation": {
                "runId": "base-run-1",
                "taskId": "sealed-task-1",
                "taskSha256": "a" * 64,
                "promptSha256": "b" * 64,
                "dataRelease": {
                    "releaseId": "vqrel-" + "d" * 64,
                    "releaseSha256": "d" * 64,
                    "manifestSha256": "e" * 64,
                },
            },
            "request": {
                "model": self.profile.execution_model_id,
                "messages": [{"role": "user", "content": "Review this risk rule."}],
                "temperature": 0,
                "top_p": 1,
                "seed": 17,
                "max_tokens": 128,
                "n": 1,
            },
        }

    def test_detached_activation_raw_der_preserves_wire_and_is_consumed(
        self,
    ) -> None:
        config_path, activation_path = self._detached_activation_config("detached-raw")
        direct = create_base_engine_activation(
            config_path=config_path,
            output_path=activation_path,
            private_key_path=self.launcher_private,
            public_key_path=self.launcher_public,
            private_key_password=None,
            audience="daxalgo-base-evaluation",
            key_id="launcher-key-v1",
            signer_role="base-runtime-launcher",
            issued_at_utc="2026-07-28T09:59:00Z",
            not_before_utc="2026-07-28T10:00:00Z",
            expires_at_utc="2026-07-29T10:00:00Z",
            package_root=self.package,
        )
        direct_unsigned = dict(direct.envelope)
        direct_unsigned["signature"] = ""
        activation_path.unlink()

        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-raw")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-raw",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        finalized = self._finalize_detached_activation(
            config_path=config_path,
            bundle_path=bundle_path,
            signature_path=signature_path,
            activation_path=activation_path,
        )

        final_unsigned = dict(finalized.envelope)
        final_unsigned["signature"] = ""
        self.assertEqual(direct.payload, bundle.payload)
        self.assertEqual(direct.payload, finalized.payload)
        self.assertEqual(direct_unsigned, bundle.unsigned_envelope)
        self.assertEqual(direct_unsigned, final_unsigned)
        self.assertEqual(set(direct.envelope), set(finalized.envelope))

        config = load_base_engine_wrapper_config(config_path)
        wrapper = self._wrapper(config=config)
        snapshot = wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.READY, wrapper.state)
        self.assertEqual(finalized.payload["activationId"], snapshot.activation_id)

    def test_detached_activation_digest_p1363_high_s_normalizes(self) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-high-s")
        )
        signature_path, signature_document = self._write_detached_activation_signature(
            "detached-high-s",
            bundle,
            mode="sha256-digest",
            signature_format="ieee-p1363-fixed-64",
            high_s=True,
        )
        supplied = urlsafe_b64decode(
            signature_document["signature"]
            + "=" * (-len(signature_document["signature"]) % 4)
        )
        self.assertGreater(int.from_bytes(supplied[32:], "big"), P256_ORDER // 2)

        finalized = self._finalize_detached_activation(
            config_path=config_path,
            bundle_path=bundle_path,
            signature_path=signature_path,
            activation_path=activation_path,
        )
        normalized = urlsafe_b64decode(
            finalized.envelope["signature"]
            + "=" * (-len(finalized.envelope["signature"]) % 4)
        )
        self.assertEqual(64, len(normalized))
        self.assertLessEqual(int.from_bytes(normalized[32:], "big"), P256_ORDER // 2)

    def test_detached_activation_rejects_wrong_key_and_double_hash(self) -> None:
        cases = (
            ("wrong-key", "raw-message", "asn1-der", True, False),
            (
                "double-hash",
                "sha256-digest",
                "ieee-p1363-fixed-64",
                False,
                True,
            ),
        )
        for stem, mode, signature_format, wrong_key, double_hash in cases:
            with self.subTest(case=stem):
                config_path, activation_path, bundle_path, bundle = (
                    self._prepare_detached_activation(f"detached-{stem}")
                )
                signature_path, _ = self._write_detached_activation_signature(
                    f"detached-{stem}",
                    bundle,
                    mode=mode,
                    signature_format=signature_format,
                    wrong_key=wrong_key,
                    double_hash=double_hash,
                )
                with self.assertRaises(ValidationError):
                    self._finalize_detached_activation(
                        config_path=config_path,
                        bundle_path=bundle_path,
                        signature_path=signature_path,
                        activation_path=activation_path,
                    )
                self.assertFalse(activation_path.exists())

    def test_detached_activation_rejects_bundle_and_config_drift(self) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-bundle-drift")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-bundle-drift",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        changed_bundle = copy.deepcopy(bundle.bundle)
        changed_bundle["authority"]["release"] = True
        bundle_path.write_bytes(canonical_json_bytes(changed_bundle) + b"\n")
        with self.assertRaises(ValidationError):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )

        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-config-drift")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-config-drift",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        changed_config = json.loads(config_path.read_text(encoding="utf-8"))
        changed_config["service"]["maxRequestBytes"] -= 1
        _write_json(config_path, changed_config)
        with self.assertRaisesRegex(ValidationError, "freshly replayed"):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )

    def test_detached_activation_documents_are_canonical_and_schema_validated(
        self,
    ) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-schema")
        )
        signature_path, signature_document = self._write_detached_activation_signature(
            "detached-schema",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        bundle_schema = json.loads(
            (
                ROOT / "schemas/base-engine-activation-signing-bundle.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        signature_schema = json.loads(
            (
                ROOT / "schemas/base-engine-activation-signature.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        for schema in (bundle_schema, signature_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
        self.assertEqual(
            BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_SCHEMA_VERSION,
            bundle.bundle["schemaVersion"],
        )
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle.bundle)
        jsonschema.Draft202012Validator(signature_schema).validate(signature_document)
        self.assertEqual(
            canonical_json_bytes(bundle.bundle) + b"\n", bundle_path.read_bytes()
        )
        self.assertEqual(
            canonical_json_bytes(signature_document) + b"\n",
            signature_path.read_bytes(),
        )
        invalid_signature = dict(signature_document, unexpected=False)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(signature_schema).validate(
                invalid_signature
            )

        noncanonical_bundle = self.root / "noncanonical-activation-bundle.json"
        noncanonical_bundle.write_bytes(
            (json.dumps(bundle.bundle, indent=2) + "\n").encode("utf-8")
        )
        with self.assertRaisesRegex(ValidationError, "canonical JSON"):
            verify_base_engine_activation_signing_bundle(
                noncanonical_bundle,
                config_path=config_path,
                public_key_path=self.launcher_public,
                expected_audience="daxalgo-base-evaluation",
                expected_key_id="launcher-key-v1",
                expected_signer_role="base-runtime-launcher",
                package_root=self.package,
                now=self.now,
            )
        noncanonical_signature = self.root / "noncanonical-activation-signature.json"
        noncanonical_signature.write_bytes(
            (json.dumps(signature_document, indent=2) + "\n").encode("utf-8")
        )
        with self.assertRaisesRegex(ValidationError, "canonical JSON"):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=noncanonical_signature,
                activation_path=activation_path,
            )

    def test_detached_activation_publication_is_no_clobber_and_rejects_hardlinks(
        self,
    ) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-publication")
        )
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._prepare_detached_activation("detached-publication")

        bundle_alias = self.root / "detached-publication-bundle-alias.json"
        os.link(bundle_path, bundle_alias)
        with self.assertRaises(ValidationError):
            verify_base_engine_activation_signing_bundle(
                bundle_path,
                config_path=config_path,
                public_key_path=self.launcher_public,
                expected_audience="daxalgo-base-evaluation",
                expected_key_id="launcher-key-v1",
                expected_signer_role="base-runtime-launcher",
                package_root=self.package,
                now=self.now,
            )
        bundle_alias.unlink()

        signature_path, _ = self._write_detached_activation_signature(
            "detached-publication",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        activation_path.write_bytes(b"sentinel")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )
        self.assertEqual(b"sentinel", activation_path.read_bytes())
        activation_path.unlink()
        self._finalize_detached_activation(
            config_path=config_path,
            bundle_path=bundle_path,
            signature_path=signature_path,
            activation_path=activation_path,
        )

        activation_alias = self.root / "detached-publication-activation-alias.json"
        os.link(activation_path, activation_alias)
        wrapper = self._wrapper(config=load_base_engine_wrapper_config(config_path))
        with self.assertRaises(ValidationError):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)

    def test_detached_activation_rejects_signer_identity_collisions(self) -> None:
        config_path, _, _ = self._external_config("detached-separation-base")
        base = json.loads(config_path.read_text(encoding="utf-8"))
        activation_tls_path, activation_tls_sha256 = self._tls_certificate_for_key(
            "activation-key-tls", self.launcher_private
        )
        runtime_tls_path, runtime_tls_sha256 = self._tls_certificate_for_key(
            "runtime-key-tls", self.runtime_private
        )
        cases = {
            "activation/runtime key": {
                "publicKeyPath": str(self.launcher_public),
                "publicKeySpkiSha256": self.launcher_spki,
            },
            "key ID": {"keyId": "launcher-key-v1"},
            "signer role": {"signerRole": "base-runtime-launcher"},
            "activation/TLS key": {
                "signerTlsCertificatePath": str(activation_tls_path),
                "signerTlsCertificateSha256": activation_tls_sha256,
            },
            "runtime/TLS key": {
                "signerTlsCertificatePath": str(runtime_tls_path),
                "signerTlsCertificateSha256": runtime_tls_sha256,
            },
        }
        for index, (name, mutation) in enumerate(cases.items(), start=1):
            with self.subTest(case=name):
                candidate = copy.deepcopy(base)
                candidate["runtimeSigning"].update(mutation)
                path = self.root / f"detached-separation-{index}.json"
                _write_json(path, candidate)
                with self.assertRaisesRegex(ValidationError, "distinct"):
                    load_base_engine_wrapper_config(path)

    def test_detached_activation_interfaces_expose_no_private_key_inputs(
        self,
    ) -> None:
        forbidden = {
            "private_key_path",
            "private_key_password",
            "privateKeyPath",
            "privateKeyPassword",
        }
        for operation in (
            prepare_base_engine_activation_signing_bundle,
            finalize_base_engine_activation,
        ):
            with self.subTest(operation=operation.__name__):
                parameters = set(inspect.signature(operation).parameters)
                self.assertTrue(forbidden.isdisjoint(parameters))
                self.assertFalse(
                    any("private" in parameter.lower() for parameter in parameters)
                )

    def test_detached_activation_rejects_expiry_crossing_during_publication(
        self,
    ) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-expiry")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-expiry",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        expiry = datetime(2026, 7, 29, 10, 0, 0, tzinfo=timezone.utc)
        publication_validations = 0

        def crossing_clock(value, field):
            nonlocal publication_validations
            if field == "base-engine activation finalization output validation time":
                publication_validations += 1
                if publication_validations > 1:
                    return expiry
            return self.now

        with (
            mock.patch.object(
                base_engine_wrapper_module,
                "_fresh_validation_time",
                side_effect=crossing_clock,
            ),
            self.assertRaisesRegex(ValidationError, "not currently valid"),
        ):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )
        self.assertFalse(activation_path.exists())
        self.assertEqual([], list(self.root.glob(".*detached-expiry*.staging")))

    def test_detached_activation_rejects_expiry_during_last_live_replay(
        self,
    ) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-replay-expiry")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-replay-expiry",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        expiry = datetime(2026, 7, 29, 10, 0, 0, tzinfo=timezone.utc)

        def replay_crossing_clock(value, field):
            if field.endswith("post-replay validation time"):
                return expiry
            return self.now

        with (
            mock.patch.object(
                base_engine_wrapper_module,
                "_fresh_validation_time",
                side_effect=replay_crossing_clock,
            ),
            self.assertRaisesRegex(ValidationError, "must be active"),
        ):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )
        self.assertFalse(activation_path.exists())
        self.assertEqual([], list(self.root.glob(".*detached-replay-expiry*.staging")))

    def test_detached_activation_reloads_config_during_publication(self) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-config-race")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-config-race",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        original_verify = base_engine_wrapper_module._verify_base_engine_activation_path
        mutated = False

        def verify_then_mutate(**arguments):
            nonlocal mutated
            verified = original_verify(**arguments)
            if not mutated:
                mutated = True
                changed = json.loads(config_path.read_text(encoding="utf-8"))
                changed["service"]["maxRequestBytes"] -= 1
                _write_json(config_path, changed)
            return verified

        with (
            mock.patch.object(
                base_engine_wrapper_module,
                "_verify_base_engine_activation_path",
                side_effect=verify_then_mutate,
            ),
            self.assertRaisesRegex(ValidationError, "config changed"),
        ):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )
        self.assertFalse(activation_path.exists())
        self.assertEqual([], list(self.root.glob(".*detached-config-race*.staging")))

    def test_detached_activation_replays_package_and_output_binding(self) -> None:
        config_path, activation_path, bundle_path, bundle = (
            self._prepare_detached_activation("detached-live-binding")
        )
        signature_path, _ = self._write_detached_activation_signature(
            "detached-live-binding",
            bundle,
            mode="raw-message",
            signature_format="asn1-der",
        )
        package_file = self.package / "owner.py"
        original = package_file.read_bytes()
        package_file.write_bytes(original + b"# changed\n")
        with self.assertRaisesRegex(ValidationError, "freshly replayed"):
            self._finalize_detached_activation(
                config_path=config_path,
                bundle_path=bundle_path,
                signature_path=signature_path,
                activation_path=activation_path,
            )
        self.assertFalse(activation_path.exists())

        package_file.write_bytes(original)
        wrong_output = self.root / "unconfigured-activation.json"
        with self.assertRaisesRegex(ValidationError, "must exactly match"):
            finalize_base_engine_activation(
                config_path=config_path,
                signing_bundle_path=bundle_path,
                signature_path=signature_path,
                output_path=wrong_output,
                public_key_path=self.launcher_public,
                expected_audience="daxalgo-base-evaluation",
                expected_key_id="launcher-key-v1",
                expected_signer_role="base-runtime-launcher",
                package_root=self.package,
                now=self.now,
            )
        self.assertFalse(wrong_output.exists())

    def test_activation_envelope_rejects_historical_runtime_key_reuse(self) -> None:
        private_key = serialization.load_pem_private_key(
            self.launcher_private.read_bytes(), password=None
        )
        payload = copy.deepcopy(self.activation.payload)
        payload["runtimeSigner"]["publicKeySpkiSha256"] = self.launcher_spki
        payload["activationId"] = "vqbaseact-" + "0" * 64
        payload["activationId"] = "vqbaseact-" + (
            base_engine_wrapper_module._domain_sha256(
                base_engine_wrapper_module.BASE_ACTIVATION_ID_DOMAIN,
                payload,
            )
        )
        envelope = base_engine_wrapper_module._new_envelope(
            schema_version=(
                base_engine_wrapper_module.BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION
            ),
            signature_domain=base_engine_wrapper_module.BASE_ACTIVATION_SIGNATURE_DOMAIN,
            payload=payload,
            private_key=private_key,
            public_key_spki_sha256=self.launcher_spki,
        )
        with self.assertRaisesRegex(ValidationError, "keys must be distinct"):
            base_engine_wrapper_module.verify_base_engine_activation_envelope(
                envelope=envelope,
                trust=self.config.activation.trust,
                now=self.now,
            )

    def test_default_process_factory_drops_privileges_on_opened_inode(self) -> None:
        process = mock.Mock(pid=9191)
        environment = {"PATH": "/opt/vllm/bin", "VLLM_API_KEY": "C" * 48}
        working_directory = Path("/opt/vllm/bin")
        with (
            mock.patch(
                "hyperion_model.base_engine_wrapper._opened_fd_path",
                return_value="/proc/self/fd/17",
            ),
            mock.patch(
                "hyperion_model.base_engine_wrapper.subprocess.Popen",
                return_value=process,
            ) as popen,
        ):
            owned = base_engine_wrapper_module._default_opened_process_factory(
                17,
                ("/opt/vllm/bin/vllm", "serve"),
                environment,
                working_directory,
                child_user_id=65534,
                child_group_id=65533,
            )

        popen.assert_called_once_with(
            ["/opt/vllm/bin/vllm", "serve"],
            executable="/proc/self/fd/17",
            pass_fds=(17,),
            cwd=working_directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
            user=65534,
            group=65533,
            extra_groups=[],
            umask=0o077,
        )
        self.assertEqual(9191, owned.pid)

    def test_owned_launch_and_atomic_signed_completion(self) -> None:
        wrapper = self._wrapper()
        snapshot = wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.READY, wrapper.state)
        self.assertEqual(4242, snapshot.engine_process_id)
        self.assertIsNotNone(self.process_argv)
        assert self.process_argv is not None
        self.assertEqual(str(self.snapshot), self.process_argv[2])
        self.assertIn("--load-format", self.process_argv)
        self.assertEqual(
            "bitsandbytes",
            self.process_argv[self.process_argv.index("--load-format") + 1],
        )
        self.assertEqual(1, self.process_argv.count("--load-format"))
        self.assertIn("--disable-log-requests", self.process_argv)
        self.assertNotIn("--enable-lora", self.process_argv)
        self.assertNotIn("--trust-remote-code", self.process_argv)
        assert self.process_environment is not None
        self.assertEqual("", self.process_environment["VLLM_PLUGINS"])
        self.assertEqual("1", self.process_environment["HF_HUB_OFFLINE"])
        self.assertEqual("C" * 48, self.process_environment["VLLM_API_KEY"])
        self.assertNotIn("VQ_OUTER_BEARER", self.process_environment)
        self.assertNotIn("SHOULD_NOT_REACH_CHILD_SECRET", self.process_environment)

        request = self._request()
        response = wrapper.handle_http_request(
            "POST",
            BASE_ATTESTED_COMPLETIONS_PATH,
            {
                "Authorization": f"Bearer {self.bearer}",
                "Content-Type": "application/json",
            },
            canonical_json_bytes(request),
        )
        self.assertEqual(200, response.status)
        value = json.loads(response.body)
        self.assertEqual(
            BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION, value["schemaVersion"]
        )
        verified = verify_base_runtime_attestation(
            envelope=value["runtimeAttestation"],
            runtime_public_key_path=self.runtime_public,
            activation=self.activation,
            expected_nonce=request["nonce"],
            expected_evaluation=request["evaluation"],
            request=request["request"],
            completion=value["completion"],
            now=self.now,
        )
        self.assertEqual(
            BASE_RUNTIME_ATTESTATION_SCHEMA_VERSION,
            verified.payload["schemaVersion"],
        )
        self.assertEqual(
            BASE_ENGINE_ACTIVATION_SCHEMA_VERSION,
            self.activation.payload["schemaVersion"],
        )
        self.assertEqual(1, verified.payload["sequence"])
        self.assertEqual(
            snapshot.engine_argv_sha256, verified.payload["engine"]["argvSha256"]
        )
        self.assertEqual([request["request"]], self.child_requests)

        replay = wrapper.handle_http_request(
            "POST",
            BASE_ATTESTED_COMPLETIONS_PATH,
            {
                "Authorization": f"Bearer {self.bearer}",
                "Content-Type": "application/json",
            },
            canonical_json_bytes(request),
        )
        self.assertEqual(400, replay.status)
        self.assertEqual(WrapperState.READY, wrapper.state)

    def test_signer_loads_after_owned_child_validation_and_clears_on_stop(
        self,
    ) -> None:
        holder: dict[str, BaseModelEngineWrapper] = {}
        events: list[str] = []

        def process_factory(descriptor, argv, environment, working_directory):
            self.assertIsNone(holder["wrapper"]._runtime_private_key)
            events.append("launch")
            return self._process_factory(
                descriptor, argv, environment, working_directory
            )

        def transport(method, url, headers, body, timeout, max_bytes):
            if holder["wrapper"].state is not WrapperState.READY:
                self.assertIsNone(holder["wrapper"]._runtime_private_key)
            event = url.rsplit("/", 1)[-1]
            events.append(event)
            return self._transport(method, url, headers, body, timeout, max_bytes)

        def load_password(environment_name):
            self.assertEqual(
                [
                    "launch",
                    "health",
                    "version",
                    "models",
                    "health",
                    "version",
                    "models",
                ],
                events,
            )
            events.append("password")
            return None

        with (
            mock.patch(
                "hyperion_model.base_engine_wrapper._load_optional_password",
                side_effect=load_password,
            ),
            mock.patch(
                "hyperion_model.base_engine_wrapper._load_private_key",
                wraps=base_engine_wrapper_module._load_private_key,
            ) as private_key_loader,
        ):
            wrapper = BaseModelEngineWrapper.from_environment(
                self.config,
                package_root=self.package,
                child_api_key="C" * 48,
                transport=transport,
                process_factory=process_factory,
                read_only_probe=lambda path: True,
                listener_ownership_probe=lambda process_id, host, port: True,
                runtime_key_isolation_probe=lambda config: True,
                clock=lambda: self.now,
            )
            holder["wrapper"] = wrapper
            self.addCleanup(wrapper.stop)
            self.assertEqual([], events)
            wrapper.start(start_monitor=False)
            self.assertEqual(1, private_key_loader.call_count)
            self.assertEqual(
                [
                    "launch",
                    "health",
                    "version",
                    "models",
                    "health",
                    "version",
                    "models",
                    "password",
                ],
                events,
            )
            self.assertIsNotNone(wrapper._runtime_private_key)
            signer = wrapper._runtime_private_key
            wrapper.monitor_once(validate_integrity=True)
            self.assertIs(signer, wrapper._runtime_private_key)
            self.assertEqual(1, private_key_loader.call_count)
            self.assertEqual(1, events.count("password"))
            self.assertEqual(1, events.count("launch"))

        wrapper._runtime_private_key_password = b"residual-test-reference"
        wrapper.stop()
        self.assertIsNone(wrapper._runtime_private_key)
        self.assertIsNone(wrapper._runtime_private_key_password)

    def test_owned_child_version_mismatch_fails_before_signer_load(self) -> None:
        def transport(method, url, headers, body, timeout, max_bytes):
            if url.endswith("/version"):
                return TransportResponse(
                    200,
                    {"Content-Type": "application/json"},
                    canonical_json_bytes({"version": "0.26.0"}),
                    url,
                )
            return self._transport(method, url, headers, body, timeout, max_bytes)

        wrapper = BaseModelEngineWrapper(
            self.config,
            bearer_token=self.bearer,
            package_root=self.package,
            child_api_key="C" * 48,
            transport=transport,
            process_factory=self._process_factory,
            read_only_probe=lambda path: True,
            listener_ownership_probe=lambda process_id, host, port: True,
            runtime_key_isolation_probe=lambda config: True,
            clock=lambda: self.now,
            monotonic=iter((0.0, 1.0, 1.5, 3.0)).__next__,
            sleeper=lambda seconds: None,
        )
        self.addCleanup(wrapper.stop)
        with self.assertRaisesRegex(ValidationError, "signed vLLM version"):
            wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)
        self.assertIsNone(wrapper._runtime_private_key)

    def test_fail_closed_clears_loaded_signer_state(self) -> None:
        wrapper = self._wrapper()
        wrapper.start(start_monitor=False)
        self.assertIsNotNone(wrapper._runtime_private_key)
        wrapper._runtime_private_key_password = b"residual-test-reference"
        wrapper.fail_closed()
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertIsNone(wrapper._runtime_private_key)
        self.assertIsNone(wrapper._runtime_private_key_password)

    def test_external_signer_v2_preserves_receipt_wire_and_secret_isolation(
        self,
    ) -> None:
        _, config, activation = self._external_config("external-wire")
        events: list[str] = []
        wrapper = self._external_wrapper(
            config, self._external_signer_transport(events=events)
        )
        snapshot = wrapper.start(start_monitor=False)
        self.assertEqual(WrapperState.READY, wrapper.state)
        self.assertIsNone(wrapper._runtime_private_key)
        self.assertTrue(wrapper._runtime_signer_ready)
        self.assertEqual("S" * 48, wrapper._runtime_signer_bearer_token)
        self.assertEqual("startup-proof", events[-1])
        self.assertGreaterEqual(events.count("models"), 2)
        self.assertNotIn("VQ_RUNTIME_SIGNER_BEARER", self.process_environment)

        request = self._request()
        response = wrapper.handle_http_request(
            "POST",
            BASE_ATTESTED_COMPLETIONS_PATH,
            {
                "Authorization": f"Bearer {self.bearer}",
                "Content-Type": "application/json",
            },
            canonical_json_bytes(request),
        )
        self.assertEqual(200, response.status)
        value = json.loads(response.body)
        verified = verify_base_runtime_attestation(
            envelope=value["runtimeAttestation"],
            runtime_public_key_path=self.runtime_public,
            activation=activation,
            expected_nonce=request["nonce"],
            expected_evaluation=request["evaluation"],
            request=request["request"],
            completion=value["completion"],
            now=self.now,
        )
        self.assertEqual(1, verified.payload["sequence"])
        self.assertEqual(
            snapshot.engine_process_id, verified.payload["engine"]["processId"]
        )
        self.assertEqual(
            ["startup-proof", "runtime-attestation"],
            [
                event
                for event in events
                if event in {"startup-proof", "runtime-attestation"}
            ],
        )
        self.assertNotIn("PRIVATE KEY", response.body.decode("utf-8"))
        self.assertNotIn("S" * 48, response.body.decode("utf-8"))
        wrapper_schema = json.loads(
            (ROOT / "schemas" / "base-engine-wrapper.v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        request_schema = json.loads(
            (ROOT / "schemas" / "base-runtime-signer-request.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        response_schema = json.loads(
            (
                ROOT / "schemas" / "base-runtime-signer-response.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        for schema in (wrapper_schema, request_schema, response_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(wrapper_schema).validate(
            json.loads(config.path.read_text(encoding="utf-8"))
        )
        request_validator = jsonschema.Draft202012Validator(request_schema)
        response_validator = jsonschema.Draft202012Validator(response_schema)
        for signer_request in self.signer_requests:
            request_validator.validate(signer_request)
        for signer_response in self.signer_responses:
            response_validator.validate(signer_response)

        wrapper.stop()
        self.assertFalse(wrapper._runtime_signer_ready)
        self.assertIsNone(wrapper._runtime_signer_bearer_token)

    def test_external_signer_der_and_p1363_high_s_normalize_to_low_s(self) -> None:
        for index, signature_format in enumerate(
            ("asn1-der", "ieee-p1363-fixed-64"), start=1
        ):
            with self.subTest(signature_format=signature_format):
                self.process = _FakeProcess()
                _, config, activation = self._external_config(
                    f"external-high-s-{index}", signature_format=signature_format
                )
                wrapper = self._external_wrapper(
                    config, self._external_signer_transport(high_s=True)
                )
                wrapper.start(start_monitor=False)
                request = self._request()
                response = wrapper.handle_http_request(
                    "POST",
                    BASE_ATTESTED_COMPLETIONS_PATH,
                    {
                        "Authorization": f"Bearer {self.bearer}",
                        "Content-Type": "application/json",
                    },
                    canonical_json_bytes(request),
                )
                self.assertEqual(200, response.status)
                value = json.loads(response.body)
                wire_signature = urlsafe_b64decode(
                    value["runtimeAttestation"]["signature"] + "=="
                )
                self.assertEqual(64, len(wire_signature))
                self.assertLessEqual(
                    int.from_bytes(wire_signature[32:], "big"), P256_ORDER // 2
                )
                verify_base_runtime_attestation(
                    envelope=value["runtimeAttestation"],
                    runtime_public_key_path=self.runtime_public,
                    activation=activation,
                    expected_nonce=request["nonce"],
                    expected_evaluation=request["evaluation"],
                    request=request["request"],
                    completion=value["completion"],
                    now=self.now,
                )
                wrapper.stop()

    def test_external_signer_startup_substitution_and_double_hash_fail_closed(
        self,
    ) -> None:
        cases = {
            "wrong key": {"wrong_key": True},
            "double hash": {"double_hash": True},
            "request replay": {"wrong_request_id": True},
            "digest substitution": {"wrong_digest_echo": True},
            "HTTP failure": {"http_status": 503},
            "noncanonical response": {"noncanonical_response": True},
            "oversized response": {"oversized_response": True},
        }
        for index, (name, options) in enumerate(cases.items(), start=1):
            with self.subTest(case=name):
                self.process = _FakeProcess()
                _, config, _ = self._external_config(f"external-fail-{index}")
                wrapper = self._external_wrapper(
                    config, self._external_signer_transport(**options)
                )
                with self.assertRaises(ValidationError):
                    wrapper.start(start_monitor=False)
                self.assertEqual(WrapperState.FAILED, wrapper.state)
                self.assertTrue(self.process.terminated)
                self.assertFalse(wrapper._runtime_signer_ready)
                self.assertIsNone(wrapper._runtime_signer_bearer_token)

    def test_default_external_signer_authenticates_tls_before_sending_bearer(
        self,
    ) -> None:
        class PeerSocket:
            def getpeercert(self, *, binary_form):
                return b"substituted-certificate"

            def settimeout(self, timeout):
                pass

            def shutdown(self, how):
                pass

        class Connection:
            def __init__(self):
                self.sock = PeerSocket()
                self.requested = False

            def connect(self):
                pass

            def request(self, method, path, *, body, headers):
                self.requested = True

            def close(self):
                pass

        connection = Connection()
        expected_certificate = b"expected-certificate"
        with mock.patch.object(
            base_engine_wrapper_module.http.client,
            "HTTPSConnection",
            return_value=connection,
        ):
            with self.assertRaisesRegex(ValidationError, "pinned identity"):
                base_engine_wrapper_module._default_runtime_signer_transport(
                    "POST",
                    "https://127.0.0.1:18092/v1/daxalgo/base-runtime-signatures",
                    {"Authorization": "Bearer " + "S" * 48},
                    b"{}",
                    0.1,
                    512,
                    hashlib.sha256(expected_certificate).hexdigest(),
                )
        self.assertFalse(connection.requested)

    def test_default_external_signer_enforces_total_deadline(self) -> None:
        released = threading.Event()
        peer_certificate = b"expected-certificate"

        class Headers:
            def get_all(self, name, failobj):
                return []

        class PeerSocket:
            def getpeercert(self, *, binary_form):
                return peer_certificate

            def settimeout(self, timeout):
                pass

            def shutdown(self, how):
                released.set()

        class Response:
            status = 200
            headers = Headers()

            def read(self, maximum):
                released.wait(2)
                return b"{}"

            def getheaders(self):
                return [("Content-Type", "application/json")]

        class Connection:
            def __init__(self):
                self.sock = PeerSocket()

            def connect(self):
                pass

            def request(self, method, path, *, body, headers):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                released.set()

        started = time.monotonic()
        with mock.patch.object(
            base_engine_wrapper_module.http.client,
            "HTTPSConnection",
            return_value=Connection(),
        ):
            with self.assertRaisesRegex(ValidationError, "total deadline"):
                base_engine_wrapper_module._default_runtime_signer_transport(
                    "POST",
                    "https://127.0.0.1:18092/v1/daxalgo/base-runtime-signatures",
                    {"Authorization": "Bearer " + "S" * 48},
                    b"{}",
                    0.1,
                    512,
                    hashlib.sha256(peer_certificate).hexdigest(),
                )
        self.assertLess(time.monotonic() - started, 0.5)

    def test_external_signer_timeout_is_not_retried_and_fails_before_ready(
        self,
    ) -> None:
        _, config, _ = self._external_config("external-timeout")
        signer_attempts = 0

        def transport(method, url, headers, body, timeout, max_bytes):
            nonlocal signer_attempts
            if url.endswith("/v1/daxalgo/base-runtime-signatures"):
                signer_attempts += 1
                raise TimeoutError("simulated external signer timeout")
            return self._transport(method, url, headers, body, timeout, max_bytes)

        wrapper = self._external_wrapper(config, transport)
        with self.assertRaisesRegex(TimeoutError, "external signer timeout"):
            wrapper.start(start_monitor=False)
        self.assertEqual(1, signer_attempts)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertTrue(self.process.terminated)
        self.assertFalse(wrapper._runtime_signer_ready)
        self.assertIsNone(wrapper._runtime_signer_bearer_token)

    def test_external_signer_expiry_during_signing_returns_no_completion(self) -> None:
        _, config, _ = self._external_config("external-expiry", receipt_ttl_seconds=1)
        wrapper = self._external_wrapper(
            config,
            self._external_signer_transport(advance_after_runtime_sign_seconds=2),
        )
        wrapper.start(start_monitor=False)
        response = wrapper.handle_http_request(
            "POST",
            BASE_ATTESTED_COMPLETIONS_PATH,
            {
                "Authorization": f"Bearer {self.bearer}",
                "Content-Type": "application/json",
            },
            canonical_json_bytes(self._request()),
        )
        self.assertEqual(503, response.status)
        self.assertEqual(WrapperState.FAILED, wrapper.state)
        self.assertNotIn("completion", response.body.decode("utf-8"))
        self.assertTrue(self.process.terminated)
        self.assertIsNone(wrapper._runtime_signer_bearer_token)

    def test_external_signer_v2_rejects_private_fields_and_identity_collisions(
        self,
    ) -> None:
        config_path, _, _ = self._external_config("external-invalid-base")
        base = json.loads(config_path.read_text(encoding="utf-8"))
        malformed_certificate = self.root / "runtime-signer-tls-trailing.pem"
        malformed_certificate.write_bytes(
            self.signer_tls_certificate.read_bytes() + b"not-a-certificate\n"
        )
        cases = {
            "privateKeyPath": {"privateKeyPath": str(self.runtime_private)},
            "same secret": {"signerBearerTokenEnvironment": "VQ_OUTER_BEARER"},
            "child port": {
                "signerEndpoint": (
                    "https://127.0.0.1:18091/v1/daxalgo/base-runtime-signatures"
                )
            },
            "wrong spki": {"publicKeySpkiSha256": "0" * 64},
            "plaintext endpoint": {
                "signerEndpoint": (
                    "http://127.0.0.1:18092/v1/daxalgo/base-runtime-signatures"
                )
            },
            "wrong TLS certificate": {"signerTlsCertificateSha256": "0" * 64},
            "trailing TLS certificate data": {
                "signerTlsCertificatePath": str(malformed_certificate)
            },
        }
        for index, (name, mutation) in enumerate(cases.items(), start=1):
            with self.subTest(case=name):
                candidate = copy.deepcopy(base)
                candidate["runtimeSigning"].update(mutation)
                path = self.root / f"external-invalid-{index}.json"
                _write_json(path, candidate)
                with self.assertRaises(ValidationError):
                    load_base_engine_wrapper_config(path)

    def test_release_capture_emits_verified_v2_and_rejects_relabeling(self) -> None:
        capture_activation_path = self.root / "capture-activation.json"
        capture_config_path = self.root / "capture-wrapper.json"
        capture_config_value = json.loads(self.config_path.read_text(encoding="utf-8"))
        capture_config_value["activation"]["path"] = str(capture_activation_path)
        _write_json(capture_config_path, capture_config_value)
        capture_config = load_base_engine_wrapper_config(capture_config_path)
        capture_activation = create_base_engine_activation(
            config_path=capture_config_path,
            output_path=capture_activation_path,
            private_key_path=self.launcher_private,
            public_key_path=self.launcher_public,
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
            bearer_token=self.bearer,
            child_api_key="C" * 48,
            transport=self._transport,
            process_factory=self._process_factory,
            read_only_probe=lambda path: True,
            listener_ownership_probe=lambda process_id, host, port: True,
            runtime_key_isolation_probe=lambda config: True,
            clock=lambda: self.now,
        )
        self.addCleanup(wrapper.stop)
        wrapper.start(start_monitor=False)

        tasks_path = self.root / "capture.tasks.jsonl"
        tasks_path.write_bytes(canonical_json_bytes(_evaluation_task()) + b"\n")
        output_path = self.root / "capture.responses.jsonl"
        release_path = self.root / "release.json"
        release_identity = {
            "releaseId": "vqrel-" + "d" * 64,
            "releaseSha256": "d" * 64,
            "manifestSha256": "e" * 64,
        }
        authoring_trust = object()

        def capture_transport(url, headers, body, timeout, max_bytes):
            response = wrapper.handle_http_request(
                "POST", BASE_ATTESTED_COMPLETIONS_PATH, headers, body
            )
            self.assertEqual(200, response.status)
            return CaptureTransportResponse(response.body, url)

        def validated_release(*args, **kwargs):
            self.assertIs(
                authoring_trust,
                kwargs["evaluation_authoring_approval_trust"],
            )
            return {"purpose": "provider-training-evaluation"}, release_identity

        monotonic_values = iter((0.0, 0.1)).__next__
        with (
            mock.patch(
                "hyperion_model.release.validate_corpus_evaluation_release_with_identity",
                side_effect=validated_release,
            ),
            mock.patch("hyperion_model.release.validate_release_evaluation_task_set"),
        ):
            summary = capture_openai_responses(
                tasks_path=tasks_path,
                catalog_path=self.catalog,
                output_path=output_path,
                base_evaluation_profile_path=self.profile_path,
                base_model_snapshot_manifest_path=self.manifest,
                base_model_snapshot_path=self.snapshot,
                base_model_source_lock_path=self.source_lock,
                base_engine_wrapper_config_path=capture_config_path,
                base_engine_activation_trust=BaseEngineActivationTrust(
                    public_key_path=self.launcher_public,
                    public_key_spki_sha256=self.launcher_spki,
                    audience="daxalgo-base-evaluation",
                    key_id="launcher-key-v1",
                    signer_role="base-runtime-launcher",
                ),
                run_id="base-run-1",
                base_url="http://127.0.0.1:18090/v1",
                api_key_env="VQ_OUTER_BEARER",
                seed=17,
                data_release_path=release_path,
                review_receipt_trust=object(),
                evaluation_authoring_approval_trust=authoring_trust,
                research_only=False,
                transport=capture_transport,
                clock=lambda: self.now,
                monotonic=monotonic_values,
            )

        tasks = validate_evaluation_tasks(tasks_path)
        response = validate_evaluation_responses(output_path, tasks)[0]
        trusted_responses = validate_attested_base_evaluation_responses(
            output_path,
            tasks,
            activation_trust=BaseEngineActivationTrust(
                public_key_path=self.launcher_public,
                public_key_spki_sha256=self.launcher_spki,
                audience="daxalgo-base-evaluation",
                key_id="launcher-key-v1",
                signer_role="base-runtime-launcher",
            ),
            runtime_public_key_path=self.runtime_public,
        )
        self.assertEqual((response,), trusted_responses)
        self.assertEqual(
            EVALUATION_RESPONSE_V2_SCHEMA_VERSION, summary["schemaVersion"]
        )
        self.assertTrue(summary["runtimeAttested"])
        self.assertEqual(
            capture_activation.payload["activationId"], summary["activationId"]
        )
        self.assertEqual(
            EVALUATION_RESPONSE_V2_SCHEMA_VERSION, response["schemaVersion"]
        )
        self.assertEqual("raw-base", response["targetKind"])
        self.assertEqual(release_identity, response["dataRelease"])
        self.assertEqual(
            response["capturedAtUtc"],
            inspect_base_runtime_attestation_envelope(
                response["runtimeAttestation"]["receipt"]
            )["payload"]["issuedAtUtc"],
        )
        serialized = output_path.read_text(encoding="utf-8")
        self.assertNotIn(self.bearer, serialized)
        self.assertNotIn("PRIVATE KEY", serialized)

        try:
            evaluation_tests = importlib.import_module("test_evaluation")
        except ModuleNotFoundError:
            evaluation_tests = importlib.import_module("tests.test_evaluation")
        candidate = copy.deepcopy(response)
        candidate["schemaVersion"] = EVALUATION_RESPONSE_SCHEMA_VERSION
        candidate["servingProfile"] = {
            "id": "candidate-profile-v1",
            "sha256": "c" * 64,
        }
        candidate["targetKind"] = "trained-adapter"
        candidate["executionModelId"] = "daxalgo-expert-sha256-" + "c" * 64
        candidate["runId"] = "candidate-run-1"
        candidate.pop("runtimeAttestation")
        candidate["responseSha256"] = evaluation_response_sha256(candidate)
        candidate_path = self.root / "promotion-candidate.responses.jsonl"
        candidate_path.write_bytes(canonical_json_bytes(candidate) + b"\n")
        candidate_result = evaluation_tests._result(_evaluation_task(), candidate)
        baseline_result = evaluation_tests._result(_evaluation_task(), response)
        candidate_results_path = self.root / "promotion-candidate.results.jsonl"
        baseline_results_path = self.root / "promotion-baseline.results.jsonl"
        candidate_results_path.write_bytes(
            canonical_json_bytes(candidate_result) + b"\n"
        )
        baseline_results_path.write_bytes(canonical_json_bytes(baseline_result) + b"\n")
        calibration_path = self.root / "promotion-calibration.tasks.jsonl"
        calibration_task = evaluation_tests._task(
            "base-calibration-1", "calibration", criticality="critical"
        )
        calibration_path.write_bytes(canonical_json_bytes(calibration_task) + b"\n")
        calibration_evidence_path = self.root / "promotion-calibration-evidence.json"
        calibration_evidence_path.write_bytes(b'{"reviewed":true}\n')
        calibration = validate_evaluation_tasks(calibration_path)
        policy = evaluation_tests._policy(
            calibration.task_set_sha256,
            tasks.task_set_sha256,
            hashlib.sha256(calibration_evidence_path.read_bytes()).hexdigest(),
            evaluation_tests._identity(candidate),
            evaluation_tests._identity(response),
            data_release=release_identity,
            research_only=False,
        )
        policy_path = self.root / "promotion-policy.json"
        _write_json(policy_path, policy)
        attestation_trust = BaseResponseAttestationTrust(
            activation_trust=BaseEngineActivationTrust(
                public_key_path=self.launcher_public,
                public_key_spki_sha256=self.launcher_spki,
                audience="daxalgo-base-evaluation",
                key_id="launcher-key-v1",
                signer_role="base-runtime-launcher",
            ),
            runtime_public_key_path=self.runtime_public,
        )
        promotion_inputs = {
            "calibration_tasks_path": calibration_path,
            "calibration_evidence_path": calibration_evidence_path,
            "sealed_tasks_path": tasks_path,
            "responses_path": candidate_path,
            "verifier_results_path": candidate_results_path,
            "baseline_responses_path": output_path,
            "baseline_verifier_results_path": baseline_results_path,
            "policy_path": policy_path,
            "data_release_path": release_path,
            "review_receipt_trust": object(),
            "evaluation_authoring_approval_trust": authoring_trust,
            "baseline_attestation_trust": attestation_trust,
            "research_only": False,
        }
        with (
            mock.patch(
                "hyperion_model.release.validate_corpus_evaluation_release_with_identity",
                side_effect=validated_release,
            ),
            mock.patch("hyperion_model.release.validate_release_evaluation_task_set"),
            mock.patch(
                "hyperion_model.verifier_runtime.execute_release_verifiers",
                side_effect=((candidate_result,), (baseline_result,)),
            ),
        ):
            report = aggregate_promotion_evidence(**promotion_inputs)
        self.assertEqual(
            EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
            report["baseline"]["identity"]["responseSchemaVersion"],
        )
        self.assertTrue(report["eligibleForPromotionReview"])

        missing_attestation_trust = dict(promotion_inputs)
        missing_attestation_trust.pop("baseline_attestation_trust")
        with (
            mock.patch(
                "hyperion_model.release.validate_corpus_evaluation_release_with_identity",
                side_effect=validated_release,
            ),
            mock.patch("hyperion_model.release.validate_release_evaluation_task_set"),
            self.assertRaisesRegex(ValidationError, "requires external"),
        ):
            aggregate_promotion_evidence(**missing_attestation_trust)

        wrong_activation_trust = dict(promotion_inputs)
        wrong_activation_trust["baseline_attestation_trust"] = (
            BaseResponseAttestationTrust(
                activation_trust=BaseEngineActivationTrust(
                    public_key_path=self.launcher_public,
                    public_key_spki_sha256=self.launcher_spki,
                    audience="wrong-audience",
                    key_id="launcher-key-v1",
                    signer_role="base-runtime-launcher",
                ),
                runtime_public_key_path=self.runtime_public,
            )
        )
        with (
            mock.patch(
                "hyperion_model.release.validate_corpus_evaluation_release_with_identity",
                side_effect=validated_release,
            ),
            mock.patch("hyperion_model.release.validate_release_evaluation_task_set"),
            self.assertRaisesRegex(ValidationError, "pinned signer trust"),
        ):
            aggregate_promotion_evidence(**wrong_activation_trust)

        relabeled = json.loads(serialized)
        relabeled["candidateId"] = "forged-candidate"
        relabeled["responseSha256"] = evaluation_response_sha256(relabeled)
        relabeled_path = self.root / "relabeled.responses.jsonl"
        relabeled_path.write_bytes(canonical_json_bytes(relabeled) + b"\n")
        with self.assertRaisesRegex(ValidationError, "raw-base identity"):
            validate_evaluation_responses(relabeled_path, tasks)

        substituted = json.loads(serialized)
        substituted["runtimeAttestation"]["completion"]["id"] = "forged-completion"
        substituted["responseSha256"] = evaluation_response_sha256(substituted)
        substituted_path = self.root / "substituted.responses.jsonl"
        substituted_path.write_bytes(canonical_json_bytes(substituted) + b"\n")
        with self.assertRaisesRegex(ValidationError, "completionSha256"):
            validate_evaluation_responses(substituted_path, tasks)

        forged_signature = json.loads(serialized)
        forged_signature["runtimeAttestation"]["receipt"]["signature"] = "A" * 86
        forged_signature["responseSha256"] = evaluation_response_sha256(
            forged_signature
        )
        forged_path = self.root / "forged-signature.responses.jsonl"
        forged_path.write_bytes(canonical_json_bytes(forged_signature) + b"\n")
        validate_evaluation_responses(forged_path, tasks)
        with self.assertRaises(ValidationError):
            validate_attested_base_evaluation_responses(
                forged_path,
                tasks,
                activation_trust=BaseEngineActivationTrust(
                    public_key_path=self.launcher_public,
                    public_key_spki_sha256=self.launcher_spki,
                    audience="daxalgo-base-evaluation",
                    key_id="launcher-key-v1",
                    signer_role="base-runtime-launcher",
                ),
                runtime_public_key_path=self.runtime_public,
            )

        downgraded = json.loads(serialized)
        downgraded["schemaVersion"] = "daxalgo.hyperion.evaluation-response/v1"
        downgraded.pop("runtimeAttestation")
        downgraded["responseSha256"] = evaluation_response_sha256(downgraded)
        downgraded_path = self.root / "downgraded.responses.jsonl"
        downgraded_path.write_bytes(canonical_json_bytes(downgraded) + b"\n")
        with self.assertRaisesRegex(ValidationError, "raw-base response v1"):
            validate_evaluation_responses(downgraded_path, tasks)

    def test_receipt_rejects_request_completion_and_release_substitution(self) -> None:
        wrapper = self._wrapper()
        wrapper.start(start_monitor=False)
        request = self._request()
        response = wrapper.handle_http_request(
            "POST",
            BASE_ATTESTED_COMPLETIONS_PATH,
            {
                "Authorization": f"Bearer {self.bearer}",
                "Content-Type": "application/json",
            },
            canonical_json_bytes(request),
        )
        value = json.loads(response.body)
        changed_request = dict(request["request"])
        changed_request["seed"] = 18
        with self.assertRaisesRegex(ValidationError, "requestSha256"):
            verify_base_runtime_attestation(
                envelope=value["runtimeAttestation"],
                runtime_public_key_path=self.runtime_public,
                activation=self.activation,
                expected_nonce=request["nonce"],
                expected_evaluation=request["evaluation"],
                request=changed_request,
                completion=value["completion"],
                now=self.now,
            )
        changed_completion = dict(value["completion"])
        changed_completion["id"] = "substituted"
        with self.assertRaisesRegex(ValidationError, "completionSha256"):
            verify_base_runtime_attestation(
                envelope=value["runtimeAttestation"],
                runtime_public_key_path=self.runtime_public,
                activation=self.activation,
                expected_nonce=request["nonce"],
                expected_evaluation=request["evaluation"],
                request=request["request"],
                completion=changed_completion,
                now=self.now,
            )
        changed_evaluation = json.loads(json.dumps(request["evaluation"]))
        changed_evaluation["dataRelease"]["releaseSha256"] = "f" * 64
        with self.assertRaisesRegex(ValidationError, "evaluation"):
            verify_base_runtime_attestation(
                envelope=value["runtimeAttestation"],
                runtime_public_key_path=self.runtime_public,
                activation=self.activation,
                expected_nonce=request["nonce"],
                expected_evaluation=changed_evaluation,
                request=request["request"],
                completion=value["completion"],
                now=self.now,
            )

    def test_mutable_inputs_and_executable_tamper_fail_before_ready(self) -> None:
        mutable = self._wrapper(read_only=False)
        with self.assertRaisesRegex(ValidationError, "read-only mount"):
            mutable.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, mutable.state)

        self.executable.write_bytes(b"changed")
        tampered = self._wrapper()
        with self.assertRaisesRegex(ValidationError, "configured SHA-256"):
            tampered.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, tampered.state)

    def test_unowned_loopback_listener_never_reaches_ready(self) -> None:
        relayed = self._wrapper(listener_owned=False)
        with self.assertRaisesRegex(ValidationError, "child listener"):
            relayed.start(start_monitor=False)
        self.assertEqual(WrapperState.FAILED, relayed.state)

    def test_activation_and_runtime_signature_tamper_fail(self) -> None:
        activation = json.loads(self.activation_path.read_text(encoding="utf-8"))
        activation["signature"] = "A" * 86
        self.activation_path.write_bytes(canonical_json_bytes(activation))
        wrapper = self._wrapper()
        with self.assertRaises(ValidationError):
            wrapper.start(start_monitor=False)

    def test_unsupported_vllm_version_cannot_be_activated(self) -> None:
        profile = json.loads(self.profile_path.read_text(encoding="utf-8"))
        profile["runtime"]["engineVersion"] = "0.25.0"
        unsupported = self.root / "unsupported-profile.json"
        unsupported.write_bytes(canonical_json_bytes(profile))
        config = json.loads(self.config_path.read_text(encoding="utf-8"))
        config["target"]["profilePath"] = str(unsupported)
        config["target"]["expectedProfileSha256"] = hashlib.sha256(
            unsupported.read_bytes()
        ).hexdigest()
        config["activation"]["path"] = str(self.root / "unsupported-activation.json")
        unsupported_config = self.root / "unsupported-wrapper.json"
        unsupported_config.write_bytes(canonical_json_bytes(config))
        with self.assertRaisesRegex(ValidationError, "reviewed exact argv adapter"):
            create_base_engine_activation(
                config_path=unsupported_config,
                output_path=self.root / "unsupported-activation.json",
                private_key_path=self.launcher_private,
                public_key_path=self.launcher_public,
                private_key_password=None,
                audience="daxalgo-base-evaluation",
                key_id="launcher-key-v1",
                signer_role="base-runtime-launcher",
                issued_at_utc="2026-07-28T09:59:00Z",
                not_before_utc="2026-07-28T10:00:00Z",
                expires_at_utc="2026-07-29T10:00:00Z",
                package_root=self.package,
            )


if __name__ == "__main__":
    unittest.main()
