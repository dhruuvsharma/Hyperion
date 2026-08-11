import base64
import copy
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from unittest import mock

import jsonschema
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)

import hyperion_model as hyperion_model_package
from hyperion_model import cli as cli_module
from hyperion_model.core import ValidationError, canonical_json_bytes
from hyperion_model.csharp_verifier import (
    CLEANUP_SECONDS,
    CONTAINER_ENVIRONMENT,
    EXPECTATIONS_SCHEMA_VERSION,
    InfrastructureError,
    MAX_WORKER_RESULT_BYTES,
    MEMORY_BYTES,
    REQUEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    SANDBOX_POLICY_PROFILE,
    SOURCE_PROFILE,
    TMPFS,
    WORKER_RESULT_SCHEMA_VERSION,
    ProcessResult,
    _default_process_runner,
    csharp_strategy_reference_trace_sha256,
    csharp_strategy_verification_result_sha256,
    _run_csharp_strategy_verification as run_csharp_strategy_verification,
)
from hyperion_model.csharp_verifier import (
    run_csharp_strategy_verification as run_live_csharp_strategy_verification,
)
from hyperion_model.verifier_authority import (
    AUTHORITY_ENVELOPE_SCHEMA_VERSION,
    AUTHORITY_SCHEMA_VERSION,
    CSharpVerifierAuthorityTrust,
    RESULT_SCHEMA_VERSION_V1,
    create_csharp_verifier_authority,
    finalize_csharp_verifier_authority,
    prepare_csharp_verifier_authority_signing_bundle,
    validate_csharp_verifier_authority,
    verify_csharp_verifier_authority_signing_bundle,
)
from hyperion_model.verifier_runtime import (
    CSharpVerifierExecutionContext,
    bind_csharp_verifier_execution_context,
)
from hyperion_model import verifier_authority as verifier_authority_module


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "registry.example/daxalgo/verifier@sha256:" + "a" * 64
ENTRYPOINT = "/opt/daxalgo/bin/DaxAlgo.Platform.VerifierWorker"
CONTAINER_ID = "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
STAGE_FRAME_MAGIC = b"DAXVSTG1"
DOCKER_DAEMON_ENDPOINT = (
    "npipe:////./pipe/docker_engine"
    if os.name == "nt"
    else "unix:///var/run/docker.sock"
)


def _json_bytes(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _stage_frame(request_raw: bytes, source_raw: bytes) -> bytes:
    return b"".join(
        (
            STAGE_FRAME_MAGIC,
            len(request_raw).to_bytes(4, "big", signed=False),
            len(source_raw).to_bytes(4, "big", signed=False),
            request_raw,
            source_raw,
        )
    )


def _request(source: bytes) -> dict:
    return {
        "schemaVersion": REQUEST_SCHEMA_VERSION,
        "profile": SOURCE_PROFILE,
        "requestId": "sealed-csharp-case-001",
        "sourceSha256": hashlib.sha256(source).hexdigest(),
        "contract": {
            "symbol": "ES",
            "secType": "FUT",
            "exchange": "CME",
            "currency": "USD",
            "primaryExchange": "CME",
        },
        "cases": [
            {
                "caseId": "rising-market",
                "startUtc": "2026-01-02T09:30:00Z",
                "ticks": [
                    {
                        "offsetMilliseconds": 0,
                        "bid": 100.0,
                        "ask": 100.25,
                        "bidSize": 10,
                        "askSize": 12,
                    },
                    {
                        "offsetMilliseconds": 100,
                        "bid": 100.25,
                        "ask": 100.5,
                        "bidSize": 9,
                        "askSize": 11,
                    },
                ],
            }
        ],
    }


def _artifact(name: str, marker: str) -> dict:
    return {"name": name, "version": "9.0.0", "sha256": marker * 64}


def _diagnostic(stage: str = "compile") -> dict:
    return {
        "stage": stage,
        "code": "DAXV2001",
        "severity": "error",
        "message": "Candidate evidence failed the closed verifier policy.",
        "line": 1,
        "column": 1,
    }


def _worker_result(
    request: dict,
    request_raw: bytes,
    *,
    trace_hash: str = "d" * 64,
    accepted: bool = True,
) -> dict:
    successful_cases = [
        {
            "caseId": request["cases"][0]["caseId"],
            "succeeded": True,
            "trace": [],
            "secondTrace": [],
            "firstTraceSha256": trace_hash,
            "secondTraceSha256": trace_hash,
            "deterministic": True,
            "firstError": None,
            "secondError": None,
        }
    ]
    compile_evidence = {
        "attempted": True,
        "succeeded": True,
        "assemblySha256": "e" * 64,
        "diagnostics": [],
        "diagnosticsTruncated": False,
    }
    policy = {
        "attempted": True,
        "sourcePassed": True,
        "ilPassed": True,
        "diagnostics": [],
        "diagnosticsTruncated": False,
    }
    if not accepted:
        compile_evidence = {
            "attempted": True,
            "succeeded": False,
            "assemblySha256": None,
            "diagnostics": [_diagnostic()],
            "diagnosticsTruncated": False,
        }
        policy = {
            "attempted": True,
            "sourcePassed": True,
            "ilPassed": False,
            "diagnostics": [],
            "diagnosticsTruncated": False,
        }
        successful_cases = []
    worker_artifact = _artifact("worker", "1")
    runtime_artifact = _artifact("runtime", "2")
    core_artifact = _artifact("core", "3")
    sdk_artifact = _artifact("sdk", "4")
    roslyn_artifact = _artifact("roslyn", "5")
    compiler_closure = sorted(
        [
            _artifact("compiler-a", "6"),
            runtime_artifact,
            core_artifact,
            sdk_artifact,
        ],
        key=lambda artifact: (artifact["name"], artifact["version"]),
    )
    compiler_closure_sha256 = hashlib.sha256(
        json.dumps(compiler_closure, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schemaVersion": WORKER_RESULT_SCHEMA_VERSION,
        "request": {
            "requestId": request["requestId"],
            "sha256": hashlib.sha256(request_raw).hexdigest(),
            "valid": True,
            "diagnostics": [],
            "diagnosticsTruncated": False,
        },
        "source": {
            "sha256": request["sourceSha256"],
            "declaredSha256": request["sourceSha256"],
            "encodingValid": True,
            "hashMatched": True,
        },
        "toolchain": {
            "version": "1.0.0",
            "worker": worker_artifact,
            "runtime": runtime_artifact,
            "core": core_artifact,
            "sdk": sdk_artifact,
            "roslyn": roslyn_artifact,
            "compilerClosure": compiler_closure,
            "compilerClosureSha256": compiler_closure_sha256,
        },
        "compile": compile_evidence,
        "policy": policy,
        "cases": successful_cases,
        "completed": True,
        "accepted": accepted,
    }


def _create_test_authority(
    root: Path, toolchain: dict, now: datetime
) -> tuple[Path, CSharpVerifierAuthorityTrust, dict, object]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_path = root / "authority-private.pem"
    public_path = root / "authority-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust = CSharpVerifierAuthorityTrust(
        public_key_path=public_path,
        public_key_spki_sha256=hashlib.sha256(spki).hexdigest(),
        audience="daxalgo-csharp-verifier",
        key_id="test-authority-key",
        signer_role="independent-verifier-reviewer",
    )
    toolchain_path = root / "toolchain.json"
    toolchain_path.write_bytes(_json_bytes(toolchain))
    docker_client_path = root / (
        "docker-client.exe" if os.name == "nt" else "docker-client"
    )
    docker_client_path.write_bytes(b"test-only pinned Docker client\n")
    if os.name != "nt":
        docker_client_path.chmod(0o700)
    authority_path = root / "authority.json"
    verified = create_csharp_verifier_authority(
        output_path=authority_path,
        toolchain_path=toolchain_path,
        image_reference=IMAGE,
        image_id=IMAGE_ID,
        entrypoint=ENTRYPOINT,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=DOCKER_DAEMON_ENDPOINT,
        private_key_path=private_path,
        public_key_path=public_path,
        public_key_spki_sha256=trust.public_key_spki_sha256,
        private_key_password=None,
        audience=trust.audience,
        key_id=trust.key_id,
        signer_role=trust.signer_role,
        approval_id="approval-001",
        actor_id="reviewer-001",
        actor_role=trust.signer_role,
        approval_reference="local-test-review",
        approved_at_utc=(now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        issued_at_utc=(now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_before_utc=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at_utc=(now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        now=now,
    )
    return authority_path, trust, verified.payload, private_key


def _resign_authority(
    path: Path, private_key: object, mutate: Callable[[dict], None]
) -> dict:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    payload = json.loads(
        base64.urlsafe_b64decode(
            envelope["payload"] + "=" * ((4 - len(envelope["payload"]) % 4) % 4)
        )
    )
    mutate(payload)
    payload["authorityId"] = verifier_authority_module.csharp_verifier_authority_id(
        payload
    )
    payload_bytes = canonical_json_bytes(payload)
    envelope["payloadSha256"] = hashlib.sha256(payload_bytes).hexdigest()
    envelope["payload"] = verifier_authority_module._base64url_encode(payload_bytes)
    envelope["signature"] = verifier_authority_module._base64url_encode(
        verifier_authority_module._sign_p1363_low_s(
            private_key,
            verifier_authority_module._signature_input(envelope, payload_bytes),
        )
    )
    path.write_bytes(_json_bytes(envelope))
    return payload


def _external_authority_signature(
    bundle: Mapping[str, object],
    private_key: object,
    *,
    mode: str,
    signature_format: str,
    signing_behavior: str | None = None,
    force_high_s: bool = False,
) -> dict:
    request = bundle["request"]
    if not isinstance(request, Mapping):  # pragma: no cover - test helper contract
        raise AssertionError("signing bundle request must be an object")
    preimage = verifier_authority_module._base64url_decode(
        request["signaturePreimage"], "test signature preimage", 262_144
    )
    digest = verifier_authority_module._base64url_decode(
        request["signatureInput"], "test signature input", 32
    )
    behavior = signing_behavior or mode
    if behavior == verifier_authority_module.AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE:
        der = private_key.sign(preimage, ec.ECDSA(hashes.SHA256()))
    elif behavior == verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE:
        der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    elif behavior == "double-hashed-digest":
        der = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    else:  # pragma: no cover - test helper contract
        raise AssertionError("unsupported signing behavior")
    r, s = decode_dss_signature(der)
    if force_high_s and s <= verifier_authority_module._P256_ORDER // 2:
        s = verifier_authority_module._P256_ORDER - s
    if (
        signature_format
        == verifier_authority_module.AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT
    ):
        signature = encode_dss_signature(r, s)
    elif (
        signature_format
        == verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT
    ):
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:  # pragma: no cover - test helper contract
        raise AssertionError("unsupported signature format")
    return verifier_authority_module._build_external_signature_document(
        bundle,
        signature_mode=mode,
        signature_format=signature_format,
        signature=signature,
        bundle_bytes=_json_bytes(bundle),
    )


def _image_inspect_document() -> dict:
    return {
        "Id": IMAGE_ID,
        "Os": "linux",
        "Architecture": "amd64",
        "RepoDigests": [IMAGE],
    }


def _inspect_document() -> dict:
    return {
        "Id": CONTAINER_ID,
        "Image": IMAGE_ID,
        "Platform": "linux",
        "Config": {
            "Image": IMAGE,
            "Entrypoint": [ENTRYPOINT],
            "Cmd": ["idle", "--work", "/work"],
            "User": "65532:65532",
            "Env": CONTAINER_ENVIRONMENT,
            "Volumes": None,
        },
        "State": {"Running": False},
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true", "seccomp=builtin"],
            "NanoCpus": 1_000_000_000,
            "Memory": MEMORY_BYTES,
            "MemorySwap": MEMORY_BYTES,
            "PidsLimit": 64,
            "Ulimits": [{"Name": "nofile", "Hard": 256, "Soft": 256}],
            "Binds": None,
            "Mounts": [],
            "VolumesFrom": None,
            "Devices": [],
            "DeviceRequests": None,
            "DeviceCgroupRules": None,
            "GroupAdd": None,
            "Links": None,
            "ExtraHosts": None,
            "Tmpfs": {
                "/tmp": TMPFS["/tmp"]["option"],
                "/work": TMPFS["/work"]["option"],
            },
        },
        "Mounts": [],
    }


class FakeRunner:
    def __init__(
        self,
        worker_raw: bytes,
        inspect_document: dict | None = None,
        image_inspect_document: dict | None = None,
    ):
        self.worker_raw = worker_raw
        self.inspect_document = inspect_document or _inspect_document()
        self.image_inspect_document = (
            image_inspect_document or _image_inspect_document()
        )
        self.calls: list[tuple[str, ...]] = []
        self.raw_calls: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self.client_sha256s: list[str] = []
        self.timeouts: list[float] = []
        self.output_bounds: list[int] = []
        self.stdin_inputs: list[bytes | None] = []
        self.container_name: str | None = None
        self.timeout_on_create = False
        self.timeout_on_exec = False
        self.cleanup_returncode = 0
        self.cleanup_absence_returncode = 0
        self.cleanup_absence_stdout = b""
        self.stage_stdout = b""
        self.stage_stderr = b""
        self.verify_stderr = b""
        self.after_create = None

    def __call__(
        self,
        args: tuple[str, ...],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        stdin_bytes: bytes | None = None,
        environment: Mapping[str, str],
    ) -> ProcessResult:
        self.raw_calls.append(args)
        self.environments.append(dict(environment))
        self.client_sha256s.append(
            hashlib.sha256(Path(args[0]).read_bytes()).hexdigest()
        )
        args = ("docker", *args[1:])
        self.calls.append(args)
        self.timeouts.append(timeout_seconds)
        self.output_bounds.append(max_output_bytes)
        self.stdin_inputs.append(stdin_bytes)
        self.assert_bounds(timeout_seconds, max_output_bytes)
        if args[1:3] == ("image", "inspect"):
            return ProcessResult(0, _json_bytes([self.image_inspect_document]), b"")
        if args[1] == "create":
            name_argument = next(value for value in args if value.startswith("--name="))
            self.container_name = name_argument.split("=", 1)[1]
            self.inspect_document["Name"] = "/" + self.container_name
            if self.after_create is not None:
                self.after_create()
            if self.timeout_on_create:
                raise TimeoutError("simulated create timeout")
            return ProcessResult(0, (CONTAINER_ID + "\n").encode("ascii"), b"")
        if args[1] == "inspect":
            return ProcessResult(0, _json_bytes([self.inspect_document]), b"")
        if args[1] == "exec" and self.timeout_on_exec:
            raise TimeoutError("simulated verifier timeout")
        if args[1] == "exec" and "stage" in args:
            return ProcessResult(0, self.stage_stdout, self.stage_stderr)
        if args[1] == "exec" and "verify-stdout" in args:
            return ProcessResult(0, self.worker_raw, self.verify_stderr)
        if args[1] == "rm":
            return ProcessResult(self.cleanup_returncode, b"", b"not found")
        if args[1] == "ps":
            return ProcessResult(
                self.cleanup_absence_returncode,
                self.cleanup_absence_stdout,
                b"query failed" if self.cleanup_absence_returncode else b"",
            )
        if args[1] == "cp":
            raise AssertionError("controller must not use Docker cp")
        return ProcessResult(0, b"", b"")

    def assert_bounds(self, timeout_seconds: float, max_output_bytes: int) -> None:
        if not 0 < timeout_seconds <= 30:
            raise AssertionError("controller supplied an invalid process timeout")
        if max_output_bytes not in {262_144, MAX_WORKER_RESULT_BYTES}:
            raise AssertionError("controller supplied an invalid process output bound")


class CSharpVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_raw = b"public sealed class CandidateStrategy { }\n"
        self.request = _request(self.source_raw)
        self.request_raw = _json_bytes(self.request)
        self.trace_hash = csharp_strategy_reference_trace_sha256([], None)
        self.expectations = {
            "schemaVersion": EXPECTATIONS_SCHEMA_VERSION,
            "requestSha256": hashlib.sha256(self.request_raw).hexdigest(),
            "cases": [
                {
                    "caseId": self.request["cases"][0]["caseId"],
                    "traceSha256": self.trace_hash,
                }
            ],
        }
        self.request_path = self.root / "request.json"
        self.source_path = self.root / "source.cs"
        self.expectations_path = self.root / "expectations.json"
        self.output_path = self.root / "result.json"
        self.request_path.write_bytes(self.request_raw)
        self.source_path.write_bytes(self.source_raw)
        self.expectations_path.write_bytes(_json_bytes(self.expectations))
        self.now = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)
        self.toolchain = _worker_result(
            self.request,
            self.request_raw,
            trace_hash=self.trace_hash,
        )["toolchain"]
        (
            self.authority_path,
            self.authority_trust,
            self.authority_payload,
            self.authority_private_key,
        ) = _create_test_authority(self.root, self.toolchain, self.now)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_verifier(
        self,
        runner: FakeRunner,
        *,
        authority_path: Path | None = None,
        authority_trust: CSharpVerifierAuthorityTrust | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> dict:
        return run_csharp_strategy_verification(
            request_path=self.request_path,
            source_path=self.source_path,
            expectations_path=self.expectations_path,
            authority_path=authority_path or self.authority_path,
            authority_trust=authority_trust or self.authority_trust,
            output_path=self.output_path,
            process_runner=runner,
            clock=clock or (lambda: self.now),
        )

    def valid_runner(self, *, accepted: bool = True) -> FakeRunner:
        worker = _worker_result(
            self.request,
            self.request_raw,
            trace_hash=self.trace_hash,
            accepted=accepted,
        )
        return FakeRunner(_json_bytes(worker))

    def detached_live_arguments(self) -> dict:
        return {
            "trust": self.authority_trust,
            "toolchain_path": self.root / "toolchain.json",
            "image_reference": IMAGE,
            "image_id": IMAGE_ID,
            "entrypoint": ENTRYPOINT,
            "docker_client_path": self.root
            / ("docker-client.exe" if os.name == "nt" else "docker-client"),
            "docker_daemon_endpoint": DOCKER_DAEMON_ENDPOINT,
        }

    def prepare_detached_authority(self, name: str = "detached"):
        bundle_path = self.root / f"{name}.signing-bundle.json"
        verified = prepare_csharp_verifier_authority_signing_bundle(
            output_path=bundle_path,
            approval_id="approval-001",
            actor_id="reviewer-001",
            actor_role=self.authority_trust.signer_role,
            approval_reference="local-test-review",
            approved_at_utc=(self.now - timedelta(minutes=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            issued_at_utc=(self.now - timedelta(minutes=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            not_before_utc=self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at_utc=(self.now + timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            now=self.now,
            **self.detached_live_arguments(),
        )
        return bundle_path, verified

    def write_external_authority_signature(
        self,
        bundle: Mapping[str, object],
        name: str,
        *,
        mode: str | None = None,
        signature_format: str | None = None,
        private_key: object | None = None,
        signing_behavior: str | None = None,
        force_high_s: bool = False,
    ) -> tuple[Path, dict]:
        signature = _external_authority_signature(
            bundle,
            private_key or self.authority_private_key,
            mode=(
                mode or verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE
            ),
            signature_format=(
                signature_format
                or verifier_authority_module.AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT
            ),
            signing_behavior=signing_behavior,
            force_high_s=force_high_s,
        )
        signature_path = self.root / f"{name}.signature.json"
        signature_path.write_bytes(_json_bytes(signature))
        return signature_path, signature

    def finalize_detached_authority(
        self,
        bundle_path: Path,
        signature_path: Path,
        name: str,
        **live_overrides,
    ):
        live = self.detached_live_arguments()
        live.update(live_overrides)
        return finalize_csharp_verifier_authority(
            signing_bundle_path=bundle_path,
            signature_path=signature_path,
            output_path=self.root / f"{name}.authority.json",
            now=self.now,
            **live,
        )

    def assert_cleanup_calls(self, runner: FakeRunner, target: str) -> None:
        self.assertEqual(("docker", "rm", "-f", target), runner.calls[-2])
        self.assertEqual(
            (
                "docker",
                "ps",
                "--all",
                "--no-trunc",
                f"--filter=name=^/{runner.container_name}$",
                "--format={{.ID}}\t{{.Names}}",
            ),
            runner.calls[-1],
        )
        self.assertEqual([CLEANUP_SECONDS, CLEANUP_SECONDS], runner.timeouts[-2:])

    def test_authority_round_trip_and_exact_expiry_boundary(self) -> None:
        verified = validate_csharp_verifier_authority(
            self.authority_path,
            trust=self.authority_trust,
            now=self.now,
        )
        self.assertEqual(self.authority_payload, verified.payload)
        expires = datetime.strptime(
            self.authority_payload["expiresAtUtc"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValidationError, "is not active"):
            validate_csharp_verifier_authority(
                self.authority_path,
                trust=self.authority_trust,
                now=expires,
            )

    def test_signed_numeric_boolean_and_policy_types_are_rejected(self) -> None:
        cases = (
            ("true-int", lambda payload: payload.__setitem__("reusable", 1)),
            (
                "false-int",
                lambda payload: payload.__setitem__("reviewAuthorized", 0),
            ),
            ("true-float", lambda payload: payload.__setitem__("reusable", 1.0)),
            (
                "false-float",
                lambda payload: payload.__setitem__("reviewAuthorized", 0.0),
            ),
            (
                "policy-boolean-int",
                lambda payload: payload["verifier"]["sandboxPolicy"]["policy"].update(
                    readOnlyRoot=1
                ),
            ),
            (
                "policy-integer-float",
                lambda payload: payload["verifier"]["sandboxPolicy"]["policy"].update(
                    uid=65532.0
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(path="direct", name=name):
                authority_path = self.root / f"numeric-{name}.authority.json"
                authority_path.write_bytes(self.authority_path.read_bytes())
                _resign_authority(authority_path, self.authority_private_key, mutate)
                with self.assertRaises(ValidationError):
                    validate_csharp_verifier_authority(
                        authority_path,
                        trust=self.authority_trust,
                        now=self.now,
                    )

            with self.subTest(path="detached", name=name):
                payload = copy.deepcopy(self.authority_payload)
                mutate(payload)
                payload["authorityId"] = (
                    verifier_authority_module.csharp_verifier_authority_id(payload)
                )
                bundle = verifier_authority_module._build_signing_bundle_document(
                    payload,
                    audience=self.authority_trust.audience,
                    key_id=self.authority_trust.key_id,
                    signer_role=self.authority_trust.signer_role,
                    public_key_spki_sha256=(
                        self.authority_trust.public_key_spki_sha256
                    ),
                )
                bundle_path = self.root / f"numeric-{name}.signing-bundle.json"
                bundle_path.write_bytes(_json_bytes(bundle))
                signature_path, _ = self.write_external_authority_signature(
                    bundle, f"numeric-{name}"
                )
                with self.assertRaises(ValidationError):
                    finalize_csharp_verifier_authority(
                        signing_bundle_path=bundle_path,
                        signature_path=signature_path,
                        output_path=(
                            self.root / f"numeric-{name}.detached-authority.json"
                        ),
                        now=self.now,
                        **self.detached_live_arguments(),
                    )

    def test_detached_authority_preserves_wire_and_supported_modes(self) -> None:
        bundle_path, prepared = self.prepare_detached_authority("wire")
        verified_bundle = verify_csharp_verifier_authority_signing_bundle(
            bundle_path,
            now=self.now,
            **self.detached_live_arguments(),
        )
        self.assertEqual(prepared.bundle_id, verified_bundle.bundle_id)

        direct_envelope = json.loads(self.authority_path.read_text(encoding="utf-8"))
        direct_signature = verifier_authority_module._base64url_decode(
            direct_envelope["signature"], "direct authority signature", 64
        )
        exact_signature = verifier_authority_module._build_external_signature_document(
            prepared.bundle,
            signature_mode=(
                verifier_authority_module.AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE
            ),
            signature_format=(
                verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT
            ),
            signature=direct_signature,
            bundle_bytes=_json_bytes(prepared.bundle),
        )
        exact_signature_path = self.root / "wire-exact.signature.json"
        exact_signature_path.write_bytes(_json_bytes(exact_signature))
        exact = self.finalize_detached_authority(
            bundle_path, exact_signature_path, "wire-exact"
        )
        exact_path = self.root / "wire-exact.authority.json"
        self.assertEqual(self.authority_path.read_bytes(), exact_path.read_bytes())
        self.assertEqual(self.authority_payload, exact.payload)
        self.assertTrue(
            self.run_verifier(self.valid_runner(), authority_path=exact_path)[
                "accepted"
            ]
        )

        cases = (
            (
                "raw-der-high-s",
                verifier_authority_module.AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT,
            ),
            (
                "digest-p1363-high-s",
                verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ),
        )
        for name, mode, signature_format in cases:
            with self.subTest(name=name):
                signature_path, _ = self.write_external_authority_signature(
                    prepared.bundle,
                    name,
                    mode=mode,
                    signature_format=signature_format,
                    force_high_s=True,
                )
                finalized = self.finalize_detached_authority(
                    bundle_path, signature_path, name
                )
                envelope = json.loads(
                    (self.root / f"{name}.authority.json").read_text(encoding="utf-8")
                )
                normalized = verifier_authority_module._base64url_decode(
                    envelope["signature"], "final authority signature", 64
                )
                self.assertLessEqual(
                    int.from_bytes(normalized[32:], "big"),
                    verifier_authority_module._P256_ORDER // 2,
                )
                self.assertEqual(self.authority_payload, finalized.payload)

    def test_detached_authority_rejects_wrong_or_malformed_signatures(self) -> None:
        bundle_path, prepared = self.prepare_detached_authority("bad-signatures")
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        wrong_key_path, _ = self.write_external_authority_signature(
            prepared.bundle, "wrong-key", private_key=wrong_key
        )
        double_hash_path, _ = self.write_external_authority_signature(
            prepared.bundle,
            "double-hash",
            signing_behavior="double-hashed-digest",
        )
        malformed_documents = (
            (
                "malformed-der",
                verifier_authority_module.AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT,
                b"\x30\x00",
            ),
            (
                "zero-p1363",
                verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
                b"\x00" * 64,
            ),
            (
                "short-p1363",
                verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
                b"\x01" * 63,
            ),
            (
                "r-at-order-p1363",
                verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
                verifier_authority_module._P256_ORDER.to_bytes(32, "big")
                + (1).to_bytes(32, "big"),
            ),
            (
                "s-at-order-p1363",
                verifier_authority_module.AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
                verifier_authority_module.AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
                (1).to_bytes(32, "big")
                + verifier_authority_module._P256_ORDER.to_bytes(32, "big"),
            ),
        )
        failures = [("wrong-key", wrong_key_path), ("double-hash", double_hash_path)]
        for name, mode, signature_format, raw in malformed_documents:
            document = verifier_authority_module._build_external_signature_document(
                prepared.bundle,
                signature_mode=mode,
                signature_format=signature_format,
                signature=raw,
                bundle_bytes=_json_bytes(prepared.bundle),
            )
            path = self.root / f"{name}.signature.json"
            path.write_bytes(_json_bytes(document))
            failures.append((name, path))

        for name, signature_path in failures:
            with self.subTest(name=name):
                output = self.root / f"rejected-{name}.authority.json"
                with self.assertRaises(ValidationError):
                    finalize_csharp_verifier_authority(
                        signing_bundle_path=bundle_path,
                        signature_path=signature_path,
                        output_path=output,
                        now=self.now,
                        **self.detached_live_arguments(),
                    )
                self.assertFalse(output.exists())

        valid_path, valid = self.write_external_authority_signature(
            prepared.bundle, "invalid-contract-base"
        )
        del valid_path
        for name, field, value in (
            ("mode", "mode", "double-hashed-digest"),
            ("format", "format", "raw"),
            ("bundle", "signingBundleSha256", "0" * 64),
        ):
            with self.subTest(name=name):
                changed = copy.deepcopy(valid)
                changed[field] = value
                changed["signatureId"] = (
                    verifier_authority_module.csharp_verifier_authority_external_signature_id(
                        changed
                    )
                )
                signature_path = self.root / f"invalid-{name}.signature.json"
                signature_path.write_bytes(_json_bytes(changed))
                with self.assertRaises(ValidationError):
                    self.finalize_detached_authority(
                        bundle_path, signature_path, f"invalid-{name}"
                    )

    def test_detached_authority_contract_is_closed_key_free_and_no_clobber(
        self,
    ) -> None:
        bundle_path, prepared = self.prepare_detached_authority("contract")
        signature_path, signature = self.write_external_authority_signature(
            prepared.bundle, "contract"
        )
        schema_root = ROOT / "schemas"
        bundle_schema = json.loads(
            (
                schema_root / "csharp-verifier-authority-signing-bundle.v1.schema.json"
            ).read_bytes()
        )
        signature_schema = json.loads(
            (
                schema_root / "csharp-verifier-authority-signature.v1.schema.json"
            ).read_bytes()
        )
        for schema, instance in (
            (bundle_schema, prepared.bundle),
            (signature_schema, signature),
        ):
            jsonschema.Draft202012Validator.check_schema(schema)
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(schema["properties"]))
            jsonschema.Draft202012Validator(schema).validate(instance)
        self.assertTrue(
            all(value is False for value in prepared.bundle["authority"].values())
        )
        self.assertEqual(
            verifier_authority_module.csharp_verifier_authority_signing_bundle_id(
                prepared.bundle
            ),
            prepared.bundle_id,
        )
        self.assertEqual(
            verifier_authority_module.csharp_verifier_authority_external_signature_id(
                signature
            ),
            signature["signatureId"],
        )

        for api in (
            prepare_csharp_verifier_authority_signing_bundle,
            verify_csharp_verifier_authority_signing_bundle,
            finalize_csharp_verifier_authority,
        ):
            parameters = inspect.signature(api).parameters
            self.assertNotIn("private_key_path", parameters)
            self.assertNotIn("private_key_password", parameters)
        for exported in (
            "CSHARP_VERIFIER_AUTHORITY_SIGNING_BUNDLE_SCHEMA_VERSION",
            "CSHARP_VERIFIER_AUTHORITY_SIGNATURE_SCHEMA_VERSION",
            "CSHARP_VERIFIER_AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE",
            "CSHARP_VERIFIER_AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE",
            "CSHARP_VERIFIER_AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT",
            "CSHARP_VERIFIER_AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT",
            "VerifiedCSharpVerifierAuthoritySigningBundle",
            "csharp_verifier_authority_signing_bundle_id",
            "csharp_verifier_authority_external_signature_id",
            "prepare_csharp_verifier_authority_signing_bundle",
            "verify_csharp_verifier_authority_signing_bundle",
            "finalize_csharp_verifier_authority",
        ):
            self.assertIn(exported, hyperion_model_package.__all__)
            self.assertTrue(hasattr(hyperion_model_package, exported))

        with mock.patch.object(
            verifier_authority_module,
            "_load_private_key",
            side_effect=AssertionError("detached APIs must not load a private key"),
        ):
            verify_csharp_verifier_authority_signing_bundle(
                bundle_path,
                now=self.now,
                **self.detached_live_arguments(),
            )
            self.finalize_detached_authority(bundle_path, signature_path, "key-free")

        occupied = self.root / "occupied.authority.json"
        occupied.write_bytes(b"competing writer\n")
        with self.assertRaisesRegex(ValidationError, "already exists"):
            finalize_csharp_verifier_authority(
                signing_bundle_path=bundle_path,
                signature_path=signature_path,
                output_path=occupied,
                now=self.now,
                **self.detached_live_arguments(),
            )
        self.assertEqual(b"competing writer\n", occupied.read_bytes())

    def test_detached_authority_rejects_bundle_live_binding_and_clock_drift(
        self,
    ) -> None:
        bundle_path, prepared = self.prepare_detached_authority("bindings")
        changed_bundle = copy.deepcopy(prepared.bundle)
        first_authority = next(iter(changed_bundle["authority"]))
        changed_bundle["authority"][first_authority] = True
        changed_bundle["bundleId"] = (
            verifier_authority_module.csharp_verifier_authority_signing_bundle_id(
                changed_bundle
            )
        )
        changed_bundle_path = self.root / "changed-authority.signing-bundle.json"
        changed_bundle_path.write_bytes(_json_bytes(changed_bundle))
        with self.assertRaises(ValidationError):
            verify_csharp_verifier_authority_signing_bundle(
                changed_bundle_path,
                now=self.now,
                **self.detached_live_arguments(),
            )

        payload = json.loads(
            verifier_authority_module._base64url_decode(
                prepared.bundle["payload"], "test bundle payload", 196_608
            )
        )
        payload["verifier"]["sandboxPolicy"]["policy"]["network"] = "bridge"
        payload["verifier"]["sandboxPolicy"]["sha256"] = hashlib.sha256(
            canonical_json_bytes(payload["verifier"]["sandboxPolicy"]["policy"])
        ).hexdigest()
        payload["authorityId"] = verifier_authority_module.csharp_verifier_authority_id(
            payload
        )
        policy_bundle = verifier_authority_module._build_signing_bundle_document(
            payload,
            audience=self.authority_trust.audience,
            key_id=self.authority_trust.key_id,
            signer_role=self.authority_trust.signer_role,
            public_key_spki_sha256=self.authority_trust.public_key_spki_sha256,
        )
        policy_bundle_path = self.root / "changed-policy.signing-bundle.json"
        policy_bundle_path.write_bytes(_json_bytes(policy_bundle))
        with self.assertRaises(ValidationError):
            verify_csharp_verifier_authority_signing_bundle(
                policy_bundle_path,
                now=self.now,
                **self.detached_live_arguments(),
            )

        wrong_trust = CSharpVerifierAuthorityTrust(
            public_key_path=self.authority_trust.public_key_path,
            public_key_spki_sha256=self.authority_trust.public_key_spki_sha256,
            audience="wrong-audience",
            key_id=self.authority_trust.key_id,
            signer_role=self.authority_trust.signer_role,
        )
        with self.assertRaises(ValidationError):
            verify_csharp_verifier_authority_signing_bundle(
                bundle_path,
                trust=wrong_trust,
                now=self.now,
                **{
                    key: value
                    for key, value in self.detached_live_arguments().items()
                    if key != "trust"
                },
            )

        changed_toolchain = copy.deepcopy(self.toolchain)
        changed_toolchain["worker"]["sha256"] = "9" * 64
        changed_toolchain_path = self.root / "changed-toolchain.json"
        changed_toolchain_path.write_bytes(_json_bytes(changed_toolchain))
        changed_client_path = self.root / (
            "changed-docker.exe" if os.name == "nt" else "changed-docker"
        )
        changed_client_path.write_bytes(b"different pinned Docker client\n")
        if os.name != "nt":
            changed_client_path.chmod(0o700)
        drift_cases = (
            ("toolchain_path", changed_toolchain_path),
            ("docker_client_path", changed_client_path),
            (
                "image_reference",
                "registry.example/different/verifier@sha256:" + "d" * 64,
            ),
            ("image_id", "sha256:" + "d" * 64),
            ("entrypoint", "/opt/daxalgo/bin/OtherVerifierWorker"),
            (
                "docker_daemon_endpoint",
                (
                    "npipe:////./pipe/different_engine"
                    if os.name == "nt"
                    else "unix:///var/run/different.sock"
                ),
            ),
        )
        for field, value in drift_cases:
            with self.subTest(field=field):
                live = self.detached_live_arguments()
                live[field] = value
                with self.assertRaises(ValidationError):
                    verify_csharp_verifier_authority_signing_bundle(
                        bundle_path, now=self.now, **live
                    )

        with self.assertRaisesRegex(ValidationError, "active"):
            verify_csharp_verifier_authority_signing_bundle(
                bundle_path,
                now=self.now + timedelta(hours=1),
                **self.detached_live_arguments(),
            )

    def test_authority_publication_rejects_expiry_and_path_races(self) -> None:
        raw = self.authority_path.read_bytes()

        def validate_at(path: Path, when: datetime, *, expected_link_count: int = 1):
            return verifier_authority_module._validate_csharp_verifier_authority(
                path,
                trust=self.authority_trust,
                now=when,
                expected_link_count=expected_link_count,
            )

        expiry_output = self.root / "expiry-race.authority.json"
        with self.assertRaisesRegex(ValidationError, "active"):
            verifier_authority_module._write_no_clobber(
                expiry_output,
                raw,
                prepublish_validator=lambda path: validate_at(path, self.now),
                precommit_validator=lambda path: validate_at(
                    path,
                    self.now + timedelta(hours=1),
                    expected_link_count=2,
                ),
            )
        self.assertFalse(expiry_output.exists())

        consumer_output = self.root / "consumer-window.authority.json"
        consumer_rejected: list[bool] = []

        def validate_precommit_with_public_probe(path: Path):
            self.assertEqual(2, path.stat().st_nlink)
            with self.assertRaisesRegex(ValidationError, "hard-linked"):
                validate_csharp_verifier_authority(
                    path,
                    trust=self.authority_trust,
                    now=self.now,
                )
            consumer_rejected.append(True)
            return validate_at(path, self.now, expected_link_count=2)

        verifier_authority_module._write_no_clobber(
            consumer_output,
            raw,
            prepublish_validator=lambda path: validate_at(path, self.now),
            precommit_validator=validate_precommit_with_public_probe,
        )
        self.assertEqual([True], consumer_rejected)
        self.assertEqual(1, consumer_output.stat().st_nlink)
        validate_at(consumer_output, self.now)

        staging_output = self.root / "staging-race.authority.json"

        def replace_staging(path: Path):
            verified = validate_at(path, self.now)
            path.unlink()
            path.write_bytes(raw)
            return verified

        with self.assertRaisesRegex(ValidationError, "residual staging"):
            verifier_authority_module._write_no_clobber(
                staging_output,
                raw,
                prepublish_validator=replace_staging,
                precommit_validator=lambda path: validate_at(
                    path, self.now, expected_link_count=2
                ),
            )
        self.assertFalse(staging_output.exists())
        staging_residuals = list(self.root.glob(".*staging-race*.staging"))
        self.assertEqual(1, len(staging_residuals))
        self.assertEqual(raw, staging_residuals[0].read_bytes())
        staging_residuals[0].unlink()

        destination_output = self.root / "destination-race.authority.json"
        replacement = b"competing destination owner\n"

        def replace_destination(path: Path):
            path.unlink()
            path.write_bytes(replacement)
            raise ValidationError("forced installed validation failure")

        with self.assertRaisesRegex(ValidationError, "residual staging"):
            verifier_authority_module._write_no_clobber(
                destination_output,
                raw,
                prepublish_validator=lambda path: validate_at(path, self.now),
                precommit_validator=replace_destination,
            )
        self.assertEqual(replacement, destination_output.read_bytes())
        destination_output.unlink()

    def test_authority_hard_kill_before_commit_leaves_rejected_two_link_file(
        self,
    ) -> None:
        output = self.root / "hard-kill.authority.json"
        script = """
import os
import sys
from datetime import datetime
from pathlib import Path

from hyperion_model import verifier_authority as authority

source, output, public_key, spki, audience, key_id, role, now_text = sys.argv[1:]
trust = authority.CSharpVerifierAuthorityTrust(
    Path(public_key), spki, audience, key_id, role
)
now = datetime.fromisoformat(now_text)
raw = Path(source).read_bytes()

def validate_staged(path):
    return authority.validate_csharp_verifier_authority(
        path, trust=trust, now=now
    )

def terminate_precommit(path):
    if os.stat(path).st_nlink != 2:
        os._exit(74)
    os._exit(73)

authority._write_no_clobber(
    Path(output),
    raw,
    prepublish_validator=validate_staged,
    precommit_validator=terminate_precommit,
)
"""
        environment = dict(os.environ)
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            value for value in (str(ROOT), existing_pythonpath) if value
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(self.authority_path),
                str(output),
                str(self.authority_trust.public_key_path),
                self.authority_trust.public_key_spki_sha256,
                self.authority_trust.audience,
                self.authority_trust.key_id,
                self.authority_trust.signer_role,
                self.now.isoformat(),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertEqual(73, completed.returncode, completed.stderr.decode())
        residuals = list(self.root.glob(".*hard-kill.authority.json.*.staging"))
        self.assertEqual(1, len(residuals))
        self.assertTrue(output.exists())
        self.assertEqual(2, output.stat().st_nlink)
        self.assertEqual(
            (output.stat().st_dev, output.stat().st_ino),
            (residuals[0].stat().st_dev, residuals[0].stat().st_ino),
        )
        with self.assertRaisesRegex(ValidationError, "hard-linked"):
            validate_csharp_verifier_authority(
                output,
                trust=self.authority_trust,
                now=self.now,
            )
        residuals[0].unlink()
        output.unlink()

    def test_detached_authority_cleanup_failure_reports_valid_residual(self) -> None:
        bundle_path, prepared = self.prepare_detached_authority("cleanup")
        signature_path, _ = self.write_external_authority_signature(
            prepared.bundle, "cleanup"
        )
        output = self.root / "cleanup.authority.json"
        real_unlink = Path.unlink

        def fail_staging_unlink(path: Path, *args, **kwargs):
            if path.name.endswith(".staging"):
                raise OSError("simulated cleanup failure")
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "unlink", fail_staging_unlink),
            self.assertRaisesRegex(ValidationError, "residual staging"),
        ):
            finalize_csharp_verifier_authority(
                signing_bundle_path=bundle_path,
                signature_path=signature_path,
                output_path=output,
                now=self.now,
                **self.detached_live_arguments(),
            )
        self.assertFalse(output.exists())
        residuals = list(self.root.glob(".*cleanup.authority.json.*.staging"))
        self.assertEqual(1, len(residuals))
        validated = validate_csharp_verifier_authority(
            residuals[0], trust=self.authority_trust, now=self.now
        )
        self.assertEqual(self.authority_payload, validated.payload)
        real_unlink(residuals[0])

    def test_authority_cleanup_union_reports_both_owned_links(self) -> None:
        bundle_path, prepared = self.prepare_detached_authority("cleanup-union")
        signature_path, _ = self.write_external_authority_signature(
            prepared.bundle, "cleanup-union"
        )
        output = self.root / "cleanup-union.authority.json"
        real_unlink = Path.unlink

        def fail_owned_unlinks(path: Path, *args, **kwargs):
            if path == output or path.name.endswith(".staging"):
                raise OSError("simulated owned-link cleanup failure")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", fail_owned_unlinks):
            with self.assertRaisesRegex(
                ValidationError, "residual staging or destination paths"
            ) as failure:
                finalize_csharp_verifier_authority(
                    signing_bundle_path=bundle_path,
                    signature_path=signature_path,
                    output_path=output,
                    now=self.now,
                    **self.detached_live_arguments(),
                )
        residuals = list(self.root.glob(".*cleanup-union.authority.json.*.staging"))
        self.assertEqual(1, len(residuals))
        self.assertTrue(output.exists())
        self.assertIn(str(output), str(failure.exception))
        self.assertIn(str(residuals[0]), str(failure.exception))
        self.assertEqual(2, output.stat().st_nlink)
        real_unlink(residuals[0])
        real_unlink(output)

    def test_authority_destination_cleanup_failure_preserves_consumer_invalid_link(
        self,
    ) -> None:
        output = self.root / "destination-cleanup.authority.json"
        real_unlink = Path.unlink

        def fail_destination_unlink(path: Path, *args, **kwargs):
            if path == output:
                raise OSError("simulated destination cleanup failure")
            return real_unlink(path, *args, **kwargs)

        def fail_precommit(_: Path):
            raise ValidationError("simulated precommit failure")

        with (
            mock.patch.object(Path, "unlink", fail_destination_unlink),
            self.assertRaisesRegex(
                ValidationError, "preserved to keep the failed destination"
            ),
        ):
            verifier_authority_module._write_no_clobber(
                output,
                self.authority_path.read_bytes(),
                prepublish_validator=lambda path: validate_csharp_verifier_authority(
                    path, trust=self.authority_trust, now=self.now
                ),
                precommit_validator=fail_precommit,
            )
        residuals = list(
            self.root.glob(".*destination-cleanup.authority.json.*.staging")
        )
        self.assertEqual(1, len(residuals))
        self.assertTrue(output.exists())
        self.assertEqual(2, output.stat().st_nlink)
        with self.assertRaisesRegex(ValidationError, "hard-linked"):
            validate_csharp_verifier_authority(
                output, trust=self.authority_trust, now=self.now
            )
        real_unlink(output)
        real_unlink(residuals[0])

    def test_detached_install_replays_toolchain_and_client_bindings(self) -> None:
        bundle_path, prepared = self.prepare_detached_authority("install-replay")
        signature_path, _ = self.write_external_authority_signature(
            prepared.bundle, "install-replay"
        )
        toolchain_path = self.root / "toolchain.json"
        client_path = self.detached_live_arguments()["docker_client_path"]
        original_toolchain = toolchain_path.read_bytes()
        original_client = client_path.read_bytes()
        changed_toolchain = copy.deepcopy(self.toolchain)
        changed_toolchain["worker"]["sha256"] = "9" * 64
        mutations = (
            (
                "toolchain",
                lambda: toolchain_path.write_bytes(_json_bytes(changed_toolchain)),
            ),
            ("client", lambda: client_path.write_bytes(b"raced Docker client\n")),
        )
        real_link = os.link
        for name, mutate in mutations:
            with self.subTest(name=name):
                output = self.root / f"install-{name}.authority.json"

                def install_then_mutate(source, destination, *args, **kwargs):
                    result = real_link(source, destination, *args, **kwargs)
                    mutate()
                    return result

                try:
                    with (
                        mock.patch.object(
                            verifier_authority_module.os,
                            "link",
                            install_then_mutate,
                        ),
                        self.assertRaisesRegex(
                            ValidationError, "live bindings changed"
                        ),
                    ):
                        finalize_csharp_verifier_authority(
                            signing_bundle_path=bundle_path,
                            signature_path=signature_path,
                            output_path=output,
                            now=self.now,
                            **self.detached_live_arguments(),
                        )
                finally:
                    toolchain_path.write_bytes(original_toolchain)
                    client_path.write_bytes(original_client)
                    if os.name != "nt":
                        client_path.chmod(0o700)
                self.assertFalse(output.exists())
                self.assertEqual([], list(self.root.glob(f".*install-{name}*.staging")))

    def test_detached_finalization_rejects_expiry_crossing_install(self) -> None:
        bundle_path, prepared = self.prepare_detached_authority("expiry-crossing")
        signature_path, _ = self.write_external_authority_signature(
            prepared.bundle, "expiry-crossing"
        )
        output = self.root / "expiry-crossing.authority.json"
        validation_times = (
            self.now,
            self.now,
            self.now,
            self.now + timedelta(hours=1),
        )
        with (
            mock.patch.object(
                verifier_authority_module,
                "_fresh_validation_time",
                side_effect=validation_times,
            ),
            self.assertRaisesRegex(ValidationError, "active"),
        ):
            finalize_csharp_verifier_authority(
                signing_bundle_path=bundle_path,
                signature_path=signature_path,
                output_path=output,
                **self.detached_live_arguments(),
            )
        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(".*expiry-crossing*.staging")))

    def test_detached_bundle_prepare_and_verify_resample_expiry(self) -> None:
        bundle_path, _ = self.prepare_detached_authority("bundle-expiry-crossing")
        validation_times = (self.now, self.now + timedelta(hours=1))
        with (
            mock.patch.object(
                verifier_authority_module,
                "_fresh_validation_time",
                side_effect=validation_times,
            ),
            self.assertRaisesRegex(ValidationError, "active"),
        ):
            verify_csharp_verifier_authority_signing_bundle(
                bundle_path,
                **self.detached_live_arguments(),
            )

        output = self.root / "prepare-expiry-crossing.signing-bundle.json"
        with (
            mock.patch.object(
                verifier_authority_module,
                "_fresh_validation_time",
                side_effect=validation_times,
            ),
            self.assertRaisesRegex(ValidationError, "active"),
        ):
            prepare_csharp_verifier_authority_signing_bundle(
                output_path=output,
                approval_id="approval-001",
                actor_id="reviewer-001",
                actor_role=self.authority_trust.signer_role,
                approval_reference="local-test-review",
                approved_at_utc=(self.now - timedelta(minutes=2)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                issued_at_utc=(self.now - timedelta(minutes=1)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                not_before_utc=self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                expires_at_utc=(self.now + timedelta(hours=1)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                **self.detached_live_arguments(),
            )
        self.assertFalse(output.exists())

    def test_detached_authority_is_accepted_by_replay_context_consumer(self) -> None:
        current = datetime.now(timezone.utc).replace(microsecond=0)
        bundle_path = self.root / "replay-consumer.signing-bundle.json"
        prepared = prepare_csharp_verifier_authority_signing_bundle(
            output_path=bundle_path,
            approval_id="approval-replay-consumer",
            actor_id="reviewer-replay-consumer",
            actor_role=self.authority_trust.signer_role,
            approval_reference="test://replay-consumer",
            approved_at_utc=(current - timedelta(minutes=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            issued_at_utc=(current - timedelta(minutes=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            not_before_utc=(current - timedelta(seconds=30)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            expires_at_utc=(current + timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            now=current,
            **self.detached_live_arguments(),
        )
        signature_path, _ = self.write_external_authority_signature(
            prepared.bundle, "replay-consumer"
        )
        authority_path = self.root / "replay-consumer.authority.json"
        finalize_csharp_verifier_authority(
            signing_bundle_path=bundle_path,
            signature_path=signature_path,
            output_path=authority_path,
            now=current,
            **self.detached_live_arguments(),
        )
        workspace = self.root / "replay-consumer-workspace"
        workspace.mkdir()
        bound = bind_csharp_verifier_execution_context(
            CSharpVerifierExecutionContext(
                authority_path, self.authority_trust, workspace
            )
        )
        self.assertIsNotNone(bound.verifier_configuration_sha256)

    def test_public_execution_api_has_no_runner_or_clock_injection(self) -> None:
        parameters = inspect.signature(run_live_csharp_strategy_verification).parameters
        self.assertNotIn("process_runner", parameters)
        self.assertNotIn("clock", parameters)

    def test_detached_authority_cli_routes_are_private_key_free(self) -> None:
        parser = cli_module._parser()
        commands = next(
            action.choices
            for action in parser._actions
            if isinstance(getattr(action, "choices", None), dict)
            and "finalize-csharp-verifier-authority" in action.choices
        )
        for command in (
            "prepare-csharp-verifier-authority-signing-bundle",
            "finalize-csharp-verifier-authority",
        ):
            options = {
                option
                for action in commands[command]._actions
                for option in action.option_strings
            }
            self.assertNotIn("--private-key", options)
            self.assertNotIn("--private-key-password-env", options)

    def test_detached_authority_cli_routes_call_key_free_apis(self) -> None:
        common = [
            "--toolchain",
            str(self.root / "toolchain.json"),
            "--image",
            IMAGE,
            "--image-id",
            IMAGE_ID,
            "--entrypoint",
            ENTRYPOINT,
            "--docker-client",
            str(self.detached_live_arguments()["docker_client_path"]),
            "--docker-daemon-endpoint",
            DOCKER_DAEMON_ENDPOINT,
            "--verifier-authority-public-key",
            str(self.authority_trust.public_key_path),
            "--verifier-authority-public-key-spki-sha256",
            self.authority_trust.public_key_spki_sha256,
            "--verifier-authority-audience",
            self.authority_trust.audience,
            "--verifier-authority-key-id",
            self.authority_trust.key_id,
            "--verifier-authority-signer-role",
            self.authority_trust.signer_role,
        ]
        verified = mock.Mock()
        verified.as_dict.return_value = {"authorityId": "test-authority"}
        with (
            mock.patch.object(
                cli_module,
                "prepare_csharp_verifier_authority_signing_bundle",
                return_value=verified,
            ) as prepare,
            mock.patch.object(cli_module, "_print"),
        ):
            self.assertEqual(
                0,
                cli_module.main(
                    [
                        "prepare-csharp-verifier-authority-signing-bundle",
                        *common,
                        "--output",
                        str(self.root / "cli-bundle.json"),
                        "--approval-id",
                        "approval-001",
                        "--actor-id",
                        "reviewer-001",
                        "--actor-role",
                        self.authority_trust.signer_role,
                        "--approval-reference",
                        "test://approval-001",
                        "--approved-at-utc",
                        "2026-07-28T11:58:00Z",
                        "--issued-at-utc",
                        "2026-07-28T11:59:00Z",
                        "--not-before-utc",
                        "2026-07-28T12:00:00Z",
                        "--expires-at-utc",
                        "2026-07-28T13:00:00Z",
                    ]
                ),
            )
        prepare.assert_called_once()
        self.assertNotIn("private_key_path", prepare.call_args.kwargs)
        self.assertNotIn("private_key_password", prepare.call_args.kwargs)

        with (
            mock.patch.object(
                cli_module,
                "finalize_csharp_verifier_authority",
                return_value=verified,
            ) as finalize,
            mock.patch.object(cli_module, "_print"),
        ):
            self.assertEqual(
                0,
                cli_module.main(
                    [
                        "finalize-csharp-verifier-authority",
                        *common,
                        "--signing-bundle",
                        str(self.root / "cli-bundle.json"),
                        "--signature",
                        str(self.root / "cli-signature.json"),
                        "--output",
                        str(self.root / "cli-authority.json"),
                    ]
                ),
            )
        finalize.assert_called_once()
        self.assertNotIn("private_key_path", finalize.call_args.kwargs)
        self.assertNotIn("private_key_password", finalize.call_args.kwargs)

    def test_wrong_external_trust_and_payload_tampering_call_no_docker(self) -> None:
        wrong_trust = CSharpVerifierAuthorityTrust(
            public_key_path=self.authority_trust.public_key_path,
            public_key_spki_sha256=self.authority_trust.public_key_spki_sha256,
            audience="wrong-audience",
            key_id=self.authority_trust.key_id,
            signer_role=self.authority_trust.signer_role,
        )
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "trusted configuration"):
            self.run_verifier(runner, authority_trust=wrong_trust)
        self.assertEqual([], runner.calls)

        tampered = self.root / "tampered-authority.json"
        envelope = json.loads(self.authority_path.read_text(encoding="utf-8"))
        replacement = "A" if envelope["payload"][0] != "A" else "B"
        envelope["payload"] = replacement + envelope["payload"][1:]
        tampered.write_bytes(_json_bytes(envelope))
        runner = self.valid_runner()
        with self.assertRaises(ValidationError):
            self.run_verifier(runner, authority_path=tampered)
        self.assertEqual([], runner.calls)

    def test_high_s_signature_is_rejected_before_docker(self) -> None:
        high_s = self.root / "high-s-authority.json"
        envelope = json.loads(self.authority_path.read_text(encoding="utf-8"))
        signature = base64.urlsafe_b64decode(
            envelope["signature"] + "=" * ((4 - len(envelope["signature"]) % 4) % 4)
        )
        order = verifier_authority_module._P256_ORDER
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        malleated = r.to_bytes(32, "big") + (order - s).to_bytes(32, "big")
        envelope["signature"] = verifier_authority_module._base64url_encode(malleated)
        high_s.write_bytes(_json_bytes(envelope))
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "low-S"):
            self.run_verifier(runner, authority_path=high_s)
        self.assertEqual([], runner.calls)

    def test_wrong_curve_key_is_rejected_before_docker(self) -> None:
        wrong_key = ec.generate_private_key(ec.SECP384R1()).public_key()
        wrong_path = self.root / "wrong-curve.pem"
        wrong_path.write_bytes(
            wrong_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        spki = wrong_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        trust = CSharpVerifierAuthorityTrust(
            public_key_path=wrong_path,
            public_key_spki_sha256=hashlib.sha256(spki).hexdigest(),
            audience=self.authority_trust.audience,
            key_id=self.authority_trust.key_id,
            signer_role=self.authority_trust.signer_role,
        )
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "EC P-256"):
            self.run_verifier(runner, authority_trust=trust)
        self.assertEqual([], runner.calls)

    def test_noncanonical_and_duplicate_authority_documents_call_no_docker(
        self,
    ) -> None:
        malformed_documents = (
            b"\xef\xbb\xbf" + self.authority_path.read_bytes(),
            b'{"schemaVersion":"one","schemaVersion":"two"}\n',
            self.authority_path.read_bytes().replace(b"\n", b"\r\n"),
        )
        for index, raw in enumerate(malformed_documents):
            with self.subTest(index=index):
                path = self.root / f"malformed-authority-{index}.json"
                path.write_bytes(raw)
                runner = self.valid_runner()
                with self.assertRaises(ValidationError):
                    self.run_verifier(runner, authority_path=path)
                self.assertEqual([], runner.calls)

    def test_correctly_resigned_overlong_validity_is_rejected_before_docker(
        self,
    ) -> None:
        overlong = self.root / "overlong-authority.json"
        overlong.write_bytes(self.authority_path.read_bytes())

        def mutate(payload: dict) -> None:
            payload["expiresAtUtc"] = (self.now + timedelta(days=8)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        _resign_authority(overlong, self.authority_private_key, mutate)
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "seven days"):
            self.run_verifier(runner, authority_path=overlong)
        self.assertEqual([], runner.calls)

    def test_correctly_resigned_sandbox_weakening_is_rejected_before_docker(
        self,
    ) -> None:
        weakened = self.root / "weakened-authority.json"
        weakened.write_bytes(self.authority_path.read_bytes())

        def mutate(payload: dict) -> None:
            sandbox = payload["verifier"]["sandboxPolicy"]
            sandbox["policy"]["network"] = "bridge"
            sandbox["sha256"] = hashlib.sha256(
                canonical_json_bytes(sandbox["policy"])
            ).hexdigest()

        _resign_authority(weakened, self.authority_private_key, mutate)
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "hardcoded supported policy"):
            self.run_verifier(runner, authority_path=weakened)
        self.assertEqual([], runner.calls)

    def test_resigned_ambient_docker_runtime_substitutions_are_rejected(self) -> None:
        cases = (
            (
                "environment",
                lambda payload: payload["verifier"]["dockerRuntime"].update(
                    {"environmentPolicy": "ambient-host-environment/v1"}
                ),
                "scrubbed environment policy",
            ),
            (
                "remote-daemon",
                lambda payload: payload["verifier"]["dockerRuntime"].update(
                    {"daemonEndpoint": "tcp://127.0.0.1:2375"}
                ),
                "explicit local",
            ),
            (
                "relative-client",
                lambda payload: payload["verifier"]["dockerRuntime"]["client"].update(
                    {"path": "docker"}
                ),
                "absolute host path",
            ),
        )
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                authority = self.root / f"{name}-authority.json"
                authority.write_bytes(self.authority_path.read_bytes())
                _resign_authority(authority, self.authority_private_key, mutate)
                runner = self.valid_runner()
                with self.assertRaisesRegex(ValidationError, expected):
                    self.run_verifier(runner, authority_path=authority)
                self.assertEqual([], runner.calls)

    def test_image_authority_is_checked_before_container_creation(self) -> None:
        image_document = _image_inspect_document()
        image_document["Architecture"] = "arm64"
        runner = FakeRunner(
            _json_bytes(_worker_result(self.request, self.request_raw)),
            image_inspect_document=image_document,
        )
        with self.assertRaisesRegex(InfrastructureError, "signed authority"):
            self.run_verifier(runner)
        self.assertEqual([("docker", "image", "inspect", IMAGE)], runner.calls)
        self.assertFalse(self.output_path.exists())

    def test_correctly_resigned_repository_alias_cannot_substitute_image(self) -> None:
        aliased = self.root / "aliased-authority.json"
        aliased.write_bytes(self.authority_path.read_bytes())

        def mutate(payload: dict) -> None:
            payload["verifier"]["image"]["reference"] = (
                "registry.example/different/verifier@sha256:" + "a" * 64
            )
            payload["verifier"]["image"]["digest"] = "sha256:" + "a" * 64

        _resign_authority(aliased, self.authority_private_key, mutate)
        runner = self.valid_runner()
        with self.assertRaisesRegex(InfrastructureError, "repository digest"):
            self.run_verifier(runner, authority_path=aliased)
        self.assertEqual(1, len(runner.calls))
        self.assertEqual(("docker", "image", "inspect"), runner.calls[0][:3])
        self.assertFalse(self.output_path.exists())

    def test_worker_toolchain_drift_is_rejected_and_cleaned_up(self) -> None:
        worker = _worker_result(self.request, self.request_raw)
        worker["toolchain"]["worker"]["sha256"] = "9" * 64
        runner = FakeRunner(_json_bytes(worker))
        with self.assertRaisesRegex(InfrastructureError, "signed verifier authority"):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_authority_expiry_during_execution_prevents_publication(self) -> None:
        times = iter((self.now, self.now + timedelta(hours=2)))
        runner = self.valid_runner()
        with self.assertRaisesRegex(InfrastructureError, "expired before"):
            self.run_verifier(runner, clock=lambda: next(times))
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_authority_snapshot_is_stable_if_original_changes_after_create(
        self,
    ) -> None:
        runner = self.valid_runner()
        runner.after_create = lambda: self.authority_path.write_text(
            "{}", encoding="utf-8"
        )
        result = self.run_verifier(runner)
        self.assertTrue(result["accepted"])
        self.assertEqual(
            self.authority_payload["authorityId"],
            result["verifierAuthority"]["authorityId"],
        )

    def test_authority_hardlink_and_symlink_are_rejected_before_docker(self) -> None:
        hardlink = self.root / "authority-hardlink.json"
        os.link(self.authority_path, hardlink)
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "hard-linked"):
            self.run_verifier(runner, authority_path=hardlink)
        self.assertEqual([], runner.calls)

        authority_copy = self.root / "authority-copy.json"
        authority_copy.write_bytes(self.authority_path.read_bytes())
        symlink = self.root / "authority-link.json"
        try:
            symlink.symlink_to(authority_copy)
        except OSError:
            return
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "symbolic-link|reparse-point"):
            self.run_verifier(runner, authority_path=symlink)
        self.assertEqual([], runner.calls)

    def test_exact_docker_policy_hidden_expectations_and_result(self) -> None:
        runner = self.valid_runner()
        result = self.run_verifier(runner)
        expected_create = (
            "docker",
            "create",
            runner.calls[1][2],
            "--pull=never",
            "--platform=linux/amd64",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--security-opt=seccomp=builtin",
            "--user=65532:65532",
            "--cpus=1",
            "--memory=768m",
            "--memory-swap=768m",
            "--pids-limit=64",
            "--ulimit=nofile=256:256",
            f"--tmpfs=/tmp:{TMPFS['/tmp']['option']}",
            f"--tmpfs=/work:{TMPFS['/work']['option']}",
            f"--entrypoint={ENTRYPOINT}",
            IMAGE,
            "idle",
            "--work",
            "/work",
        )
        self.assertEqual(("docker", "image", "inspect", IMAGE), runner.calls[0])
        self.assertRegex(runner.calls[1][2], r"^--name=daxalgo-vqverify-[0-9a-f]{24}$")
        self.assertEqual(expected_create, runner.calls[1])
        self.assertEqual(("docker", "inspect", CONTAINER_ID), runner.calls[2])
        self.assertEqual(("docker", "start", CONTAINER_ID), runner.calls[3])
        expected_frame = _stage_frame(self.request_raw, self.source_raw)
        self.assertEqual(
            (
                "docker",
                "exec",
                "--interactive",
                CONTAINER_ID,
                ENTRYPOINT,
                "stage",
                "--work",
                "/work",
            ),
            runner.calls[4],
        )
        self.assertEqual(expected_frame, runner.stdin_inputs[4])
        self.assertEqual(STAGE_FRAME_MAGIC, expected_frame[:8])
        self.assertEqual(
            len(self.request_raw), int.from_bytes(expected_frame[8:12], "big")
        )
        self.assertEqual(
            len(self.source_raw), int.from_bytes(expected_frame[12:16], "big")
        )
        request_end = 16 + len(self.request_raw)
        self.assertEqual(self.request_raw, expected_frame[16:request_end])
        self.assertEqual(self.source_raw, expected_frame[request_end:])
        self.assertEqual(
            (
                "docker",
                "exec",
                CONTAINER_ID,
                ENTRYPOINT,
                "verify-stdout",
                "--request",
                "/work/request.json",
                "--source",
                "/work/source.cs",
            ),
            runner.calls[5],
        )
        self.assertEqual(MAX_WORKER_RESULT_BYTES, runner.output_bounds[5])
        self.assertTrue(
            all(
                value is None
                for index, value in enumerate(runner.stdin_inputs)
                if index != 4
            )
        )
        self.assertFalse(any(call[1] == "cp" for call in runner.calls))
        self.assertNotIn(
            self.expectations["cases"][0]["traceSha256"],
            json.dumps(runner.calls),
        )
        self.assertNotIn(
            self.expectations["cases"][0]["traceSha256"].encode("ascii"),
            expected_frame,
        )
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        docker_runtime = self.authority_payload["verifier"]["dockerRuntime"]
        signed_client = docker_runtime["client"]
        self.assertEqual(DOCKER_DAEMON_ENDPOINT, docker_runtime["daemonEndpoint"])
        self.assertTrue(all(Path(call[0]).is_absolute() for call in runner.raw_calls))
        self.assertTrue(
            all(
                Path(call[0]) != Path(signed_client["path"])
                for call in runner.raw_calls
            )
        )
        self.assertEqual(
            [signed_client["sha256"]] * len(runner.raw_calls),
            runner.client_sha256s,
        )
        expected_environment_names = {
            "DOCKER_CLI_HINTS",
            "DOCKER_CONFIG",
            "DOCKER_HOST",
            "HOME",
            "TEMP",
            "TMP",
            "TMPDIR",
        }
        for raw_call, environment in zip(
            runner.raw_calls, runner.environments, strict=True
        ):
            self.assertEqual(expected_environment_names, set(environment))
            self.assertEqual(DOCKER_DAEMON_ENDPOINT, environment["DOCKER_HOST"])
            self.assertEqual("false", environment["DOCKER_CLI_HINTS"])
            self.assertEqual(
                Path(raw_call[0]).parent,
                Path(environment["DOCKER_CONFIG"]).parent,
            )
            self.assertNotIn("PATH", environment)
            self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertTrue(result["accepted"])
        self.assertEqual(
            self.authority_payload["authorityId"],
            result["verifierAuthority"]["authorityId"],
        )
        self.assertEqual("linux/amd64", result["image"]["platform"])
        self.assertEqual(
            [
                "source-binding",
                "compile",
                "analyzers",
                "deterministic-execution",
                "reference-cases",
                "sandbox-policy",
            ],
            [check["checkId"] for check in result["checks"]],
        )
        self.assertEqual(
            csharp_strategy_verification_result_sha256(result),
            result["resultSha256"],
        )
        on_disk = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(result, on_disk)
        self.assertNotIn(self.trace_hash, json.dumps(result))

    def test_docker_client_drift_fails_before_execution(self) -> None:
        client_path = Path(
            self.authority_payload["verifier"]["dockerRuntime"]["client"]["path"]
        )
        client_path.write_bytes(b"changed before execution\n")
        runner = self.valid_runner()
        with self.assertRaisesRegex(InfrastructureError, "signed authority"):
            self.run_verifier(runner)
        self.assertEqual([], runner.calls)
        self.assertFalse(self.output_path.exists())

    def test_docker_client_drift_during_execution_fails_after_cleanup(self) -> None:
        client_path = Path(
            self.authority_payload["verifier"]["dockerRuntime"]["client"]["path"]
        )
        runner = self.valid_runner()
        runner.after_create = lambda: client_path.write_bytes(
            b"changed during execution\n"
        )
        with self.assertRaisesRegex(InfrastructureError, "signed authority"):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_historical_result_v1_hash_domain_remains_supported(self) -> None:
        current = self.run_verifier(self.valid_runner())
        legacy = copy.deepcopy(current)
        legacy["schemaVersion"] = RESULT_SCHEMA_VERSION_V1
        legacy.pop("verifierAuthority")
        legacy["workerResult"].pop("toolchainSha256")
        legacy["image"].pop("platform")
        legacy["resultSha256"] = "0" * 64
        expected = hashlib.sha256(
            b"daxalgo-hyperion-csharp-strategy-verification-result/v1\x00"
            + canonical_json_bytes(
                {key: value for key, value in legacy.items() if key != "resultSha256"}
            )
        ).hexdigest()
        legacy["resultSha256"] = expected
        self.assertEqual(
            expected,
            csharp_strategy_verification_result_sha256(legacy),
        )

    def test_request_and_source_are_snapshotted_before_mutation(self) -> None:
        runner = self.valid_runner()

        def mutate_originals() -> None:
            self.request_path.write_text("{}", encoding="utf-8")
            self.source_path.write_text("changed", encoding="utf-8")

        runner.after_create = mutate_originals
        result = self.run_verifier(runner)
        self.assertTrue(result["accepted"])
        self.assertEqual(
            _stage_frame(self.request_raw, self.source_raw),
            runner.stdin_inputs[4],
        )

    def test_default_runner_streams_bounded_stdin_without_pipe_deadlock(self) -> None:
        payload = b"x" * 1_000_000
        output = b"y" * 131_072
        script = (
            "import sys; output=b'y'*131072; "
            "sys.stdout.buffer.write(output); "
            "sys.stdout.buffer.flush(); "
            "data=sys.stdin.buffer.read(); "
            "sys.exit(0 if len(data)==1000000 else 9)"
        )
        result = _default_process_runner(
            (sys.executable, "-c", script),
            timeout_seconds=10,
            max_output_bytes=262_144,
            stdin_bytes=payload,
            environment={},
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(output, result.stdout)
        self.assertEqual(b"", result.stderr)

    def test_source_hash_duplicate_key_bom_and_hardlink_fail_before_docker(
        self,
    ) -> None:
        cases = []
        bad_request = copy.deepcopy(self.request)
        bad_request["sourceSha256"] = "0" * 64
        cases.append(
            (
                "source hash",
                _json_bytes(bad_request),
                self.source_path,
                self.expectations_path,
            )
        )
        duplicate = (
            b'{"schemaVersion":"'
            + REQUEST_SCHEMA_VERSION.encode("ascii")
            + b'","schemaVersion":"'
            + REQUEST_SCHEMA_VERSION.encode("ascii")
            + b'"}'
        )
        cases.append(("duplicate", duplicate, self.source_path, self.expectations_path))
        cases.append(
            (
                "BOM",
                b"\xef\xbb\xbf" + self.request_raw,
                self.source_path,
                self.expectations_path,
            )
        )
        for label, request_raw, source_path, expectations_path in cases:
            with self.subTest(label=label):
                self.request_path.write_bytes(request_raw)
                runner = self.valid_runner()
                with self.assertRaises(ValidationError):
                    self.run_verifier(runner)
                self.assertEqual([], runner.calls)
                self.request_path.write_bytes(self.request_raw)

        hardlink = self.root / "request-hardlink.json"
        os.link(self.request_path, hardlink)
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "hard-linked"):
            run_csharp_strategy_verification(
                request_path=hardlink,
                source_path=self.source_path,
                expectations_path=self.expectations_path,
                authority_path=self.authority_path,
                authority_trust=self.authority_trust,
                output_path=self.output_path,
                process_runner=runner,
                clock=lambda: self.now,
            )
        self.assertEqual([], runner.calls)

    def test_symlink_input_is_rejected_when_supported(self) -> None:
        link = self.root / "request-link.json"
        try:
            link.symlink_to(self.request_path)
        except OSError:
            self.skipTest("symbolic links are unavailable for this account")
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "symbolic-link|reparse-point"):
            run_csharp_strategy_verification(
                request_path=link,
                source_path=self.source_path,
                expectations_path=self.expectations_path,
                authority_path=self.authority_path,
                authority_trust=self.authority_trust,
                output_path=self.output_path,
                process_runner=runner,
                clock=lambda: self.now,
            )

    def test_inspection_rejects_policy_forgery_and_cleans_up(self) -> None:
        inspect = _inspect_document()
        inspect["HostConfig"]["NetworkMode"] = "bridge"
        runner = FakeRunner(
            _json_bytes(_worker_result(self.request, self.request_raw)), inspect
        )
        with self.assertRaisesRegex(InfrastructureError, "sandbox inspection"):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_inspection_rejects_bind_and_volume_ingress(self) -> None:
        for label in ("bind", "volume"):
            with self.subTest(label=label):
                inspect = _inspect_document()
                if label == "bind":
                    inspect["HostConfig"]["Binds"] = ["C:/host:/work"]
                else:
                    inspect["Config"]["Volumes"] = {"/work": {}}
                runner = FakeRunner(
                    _json_bytes(_worker_result(self.request, self.request_raw)),
                    inspect,
                )
                with self.assertRaisesRegex(InfrastructureError, "sandbox inspection"):
                    self.run_verifier(runner)
                self.assert_cleanup_calls(runner, CONTAINER_ID)
                self.assertFalse(self.output_path.exists())

    def test_stage_or_verify_output_ambiguity_never_publishes(self) -> None:
        for label in ("stage stdout", "stage stderr", "verify stderr"):
            with self.subTest(label=label):
                runner = self.valid_runner()
                if label == "stage stdout":
                    runner.stage_stdout = b"unexpected"
                elif label == "stage stderr":
                    runner.stage_stderr = b"unexpected"
                else:
                    runner.verify_stderr = b"unexpected"
                with self.assertRaisesRegex(InfrastructureError, "produced"):
                    self.run_verifier(runner)
                self.assert_cleanup_calls(runner, CONTAINER_ID)
                self.assertFalse(self.output_path.exists())

    def test_verify_stdout_is_bounded_before_validation(self) -> None:
        runner = self.valid_runner()
        runner.worker_raw = b"x" * (MAX_WORKER_RESULT_BYTES + 1)
        with self.assertRaisesRegex(InfrastructureError, "output byte limit"):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_forged_and_malformed_worker_results_are_infrastructure_failures(
        self,
    ) -> None:
        forged = _worker_result(self.request, self.request_raw)
        forged["source"]["sha256"] = "f" * 64
        malformed = _worker_result(self.request, self.request_raw)
        malformed["unexpected"] = True
        false_determinism = _worker_result(self.request, self.request_raw)
        false_determinism["cases"][0]["secondTrace"] = [
            {
                "sequence": 1,
                "kind": "cancel",
                "atUtc": "2026-01-02T09:30:00Z",
                "clientOrderId": "forged-second-replay",
                "contract": None,
                "side": None,
                "type": None,
                "quantity": None,
                "limitPrice": None,
                "stopPrice": None,
                "timeInForce": None,
            }
        ]
        duplicate = _json_bytes(_worker_result(self.request, self.request_raw)).replace(
            b'{"accepted":true,', b'{"accepted":true,"accepted":true,', 1
        )
        for label, raw in (
            ("forged", _json_bytes(forged)),
            ("malformed", _json_bytes(malformed)),
            ("false determinism", _json_bytes(false_determinism)),
            ("duplicate", duplicate),
        ):
            with self.subTest(label=label):
                runner = FakeRunner(raw)
                with self.assertRaises(InfrastructureError):
                    self.run_verifier(runner)
                self.assert_cleanup_calls(runner, CONTAINER_ID)
                self.assertFalse(self.output_path.exists())

    def test_timeout_is_infrastructure_and_cleanup_always_runs(self) -> None:
        runner = self.valid_runner()
        runner.timeout_on_exec = True
        with self.assertRaisesRegex(InfrastructureError, "timed out"):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_create_timeout_still_cleans_by_predeclared_name(self) -> None:
        runner = self.valid_runner()
        runner.timeout_on_create = True
        with self.assertRaisesRegex(InfrastructureError, "Docker create timed out"):
            self.run_verifier(runner)
        self.assertRegex(
            runner.container_name or "", r"^daxalgo-vqverify-[0-9a-f]{24}$"
        )
        self.assert_cleanup_calls(runner, runner.container_name or "")
        self.assertFalse(self.output_path.exists())

    def test_create_timeout_rm_failure_with_proven_absence_is_not_ambiguous(
        self,
    ) -> None:
        runner = self.valid_runner()
        runner.timeout_on_create = True
        runner.cleanup_returncode = 1
        with self.assertRaisesRegex(
            InfrastructureError, "Docker create timed out"
        ) as caught:
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, runner.container_name or "")
        self.assertFalse(
            any(
                "cleanup" in note.lower()
                for note in getattr(caught.exception, "__notes__", [])
            )
        )
        self.assertFalse(self.output_path.exists())

    def test_create_timeout_rm_failure_and_absence_ambiguity_fails_closed(self) -> None:
        runner = self.valid_runner()
        runner.timeout_on_create = True
        runner.cleanup_returncode = 1
        runner.cleanup_absence_returncode = 1
        with self.assertRaisesRegex(
            InfrastructureError, "Docker create timed out"
        ) as caught:
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, runner.container_name or "")
        self.assertTrue(
            any(
                "cleanup absence query failed" in note
                for note in getattr(caught.exception, "__notes__", [])
            )
        )
        self.assertFalse(self.output_path.exists())

    def test_cleanup_failure_never_publishes_a_result(self) -> None:
        runner = self.valid_runner()
        runner.cleanup_returncode = 1
        with self.assertRaisesRegex(InfrastructureError, "Docker cleanup failed"):
            self.run_verifier(runner)
        self.assertFalse(self.output_path.exists())

    def test_absence_query_ambiguity_never_publishes_a_result(self) -> None:
        runner = self.valid_runner()
        runner.cleanup_absence_stdout = b"not-a-valid-query-row\n"
        with self.assertRaisesRegex(InfrastructureError, "ambiguous document"):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_exact_name_still_present_never_publishes_a_result(self) -> None:
        runner = self.valid_runner()

        def report_exact_name() -> None:
            runner.cleanup_absence_stdout = (
                f"{CONTAINER_ID}\t{runner.container_name}\n".encode("ascii")
            )

        runner.after_create = report_exact_name
        with self.assertRaisesRegex(
            InfrastructureError, "exact verifier container name"
        ):
            self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_staging_cleanup_failure_never_publishes_a_result(self) -> None:
        runner = self.valid_runner()
        with mock.patch(
            "hyperion_model.csharp_verifier.shutil.rmtree",
            side_effect=OSError("simulated staging cleanup failure"),
        ):
            with self.assertRaisesRegex(
                InfrastructureError, "could not remove the verifier staging directory"
            ):
                self.run_verifier(runner)
        self.assert_cleanup_calls(runner, CONTAINER_ID)
        self.assertFalse(self.output_path.exists())

    def test_candidate_failure_is_a_negative_result_not_infrastructure(self) -> None:
        runner = self.valid_runner(accepted=False)
        result = self.run_verifier(runner)
        self.assertFalse(result["accepted"])
        self.assertTrue(result["checks"][0]["passed"])
        self.assertFalse(result["checks"][1]["passed"])
        self.assertTrue(result["checks"][-1]["passed"])
        self.assertTrue(self.output_path.exists())

    def test_reference_mismatch_is_candidate_failure_and_output_never_clobbers(
        self,
    ) -> None:
        worker = _worker_result(
            self.request,
            self.request_raw,
            trace_hash=self.trace_hash,
        )
        worker["cases"][0]["trace"] = [
            {
                "sequence": 1,
                "kind": "cancel",
                "atUtc": "2026-01-02T09:30:00.0000000Z",
                "clientOrderId": "different-trace",
                "contract": None,
                "side": None,
                "type": None,
                "quantity": None,
                "limitPrice": None,
                "stopPrice": None,
                "timeInForce": None,
            }
        ]
        worker["cases"][0]["secondTrace"] = copy.deepcopy(worker["cases"][0]["trace"])
        result = self.run_verifier(FakeRunner(_json_bytes(worker)))
        self.assertFalse(result["accepted"])
        self.assertFalse(result["checks"][4]["passed"])
        original = self.output_path.read_bytes()
        runner = self.valid_runner()
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self.run_verifier(runner)
        self.assertEqual([], runner.calls)
        self.assertEqual(original, self.output_path.read_bytes())

    def test_schemas_are_closed_and_protocol_constants_match(self) -> None:
        request_schema = json.loads(
            (
                ROOT / "schemas/csharp-strategy-verification-request.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        expectations_schema = json.loads(
            (
                ROOT
                / "schemas/csharp-strategy-verification-expectations.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        result_schema = json.loads(
            (
                ROOT / "schemas/csharp-strategy-verification-result.v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        legacy_result_schema = json.loads(
            (
                ROOT / "schemas/csharp-strategy-verification-result.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        authority_schema = json.loads(
            (ROOT / "schemas/csharp-verifier-authority.v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        authority_envelope_schema = json.loads(
            (
                ROOT / "schemas/csharp-verifier-authority-envelope.v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        worker_schema = json.loads(
            (ROOT / "schemas/csharp-strategy-worker-result.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(request_schema["additionalProperties"])
        self.assertFalse(expectations_schema["additionalProperties"])
        self.assertFalse(result_schema["additionalProperties"])
        self.assertFalse(legacy_result_schema["additionalProperties"])
        self.assertFalse(authority_schema["additionalProperties"])
        self.assertFalse(authority_envelope_schema["additionalProperties"])
        self.assertFalse(worker_schema["additionalProperties"])
        self.assertEqual(
            REQUEST_SCHEMA_VERSION,
            request_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            EXPECTATIONS_SCHEMA_VERSION,
            expectations_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            RESULT_SCHEMA_VERSION,
            result_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            AUTHORITY_SCHEMA_VERSION,
            authority_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            AUTHORITY_ENVELOPE_SCHEMA_VERSION,
            authority_envelope_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            WORKER_RESULT_SCHEMA_VERSION,
            worker_schema["properties"]["schemaVersion"]["const"],
        )
        self.assertEqual(
            SANDBOX_POLICY_PROFILE,
            result_schema["properties"]["sandboxPolicy"]["properties"]["profile"][
                "const"
            ],
        )
        self.assertEqual(6, result_schema["properties"]["checks"]["minItems"])


if __name__ == "__main__":
    unittest.main()
