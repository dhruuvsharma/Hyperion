from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import threading
import time
import urllib.parse
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .base_evaluation import BaseEvaluationProfile, validate_base_evaluation_profile
from .core import (
    ValidationError,
    _read_file_bounded,
    _reject_reparse_components,
    _validate_data_release_identity,
    canonical_json_bytes,
    load_json_document,
    sha256_file,
)
from .engine_wrapper import (
    CHAT_COMPLETIONS_PATH,
    ChildProcess,
    EngineConfig,
    ServiceResponse,
    TransportResponse,
    WrapperState,
    _default_transport,
    _error_response,
    _load_bearer_secret,
    _parse_json_bytes,
    _require_json_content_type,
)
from .review_receipts import (
    REVIEW_RECEIPT_EXTERNAL_DER_SIGNATURE_FORMAT,
    REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT,
    _base64url_decode,
    _base64url_encode,
    _load_private_key,
    _load_public_key,
    _normalize_external_signature,
    _sign_p1363_low_s,
    _verify_p1363_low_s,
)
from .verifier_authority import (
    _bounded_snapshot,
    _normalize_external_signature as _normalize_detached_external_signature,
    _read_canonical_handoff_document,
    _write_no_clobber,
)


BASE_ENGINE_WRAPPER_SCHEMA_VERSION = "daxalgo.hyperion.base-engine-wrapper/v1"
BASE_ENGINE_WRAPPER_V2_SCHEMA_VERSION = "daxalgo.hyperion.base-engine-wrapper/v2"
BASE_ENGINE_ACTIVATION_SCHEMA_VERSION = "daxalgo.hyperion.base-engine-activation/v1"
BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-engine-activation-envelope/v1"
)
BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-engine-activation-signing-bundle/v1"
)
BASE_ENGINE_ACTIVATION_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-engine-activation-signature/v1"
)
BASE_RUNTIME_ATTESTATION_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-runtime-attestation/v1"
)
BASE_RUNTIME_ATTESTATION_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-runtime-attestation-envelope/v1"
)
BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-attested-completion-request/v1"
)
BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-attested-completion-response/v1"
)
BASE_ATTESTED_COMPLETIONS_PATH = "/v1/daxalgo/base-evaluation/completions"
BASE_RUNTIME_SIGNER_REQUEST_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-runtime-signer-request/v1"
)
BASE_RUNTIME_SIGNER_RESPONSE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-runtime-signer-response/v1"
)
BASE_RUNTIME_SIGNER_PROVIDER = "external-loopback-https/v1"
BASE_RUNTIME_SIGNER_ENDPOINT_PATH = "/v1/daxalgo/base-runtime-signatures"

BASE_ACTIVATION_SIGNATURE_DOMAIN = (
    "daxalgo-hyperion-base-engine-activation-signature/v1"
)
BASE_ACTIVATION_ID_DOMAIN = "daxalgo-hyperion-base-engine-activation-id/v1"
BASE_RUNTIME_SIGNATURE_DOMAIN = (
    "daxalgo-hyperion-base-runtime-attestation-signature/v1"
)
BASE_RUNTIME_ATTESTATION_ID_DOMAIN = "daxalgo-hyperion-base-runtime-attestation-id/v1"
BASE_WRAPPER_PACKAGE_TREE_DOMAIN = "daxalgo-hyperion-base-wrapper-package-tree/v1"
BASE_ENGINE_ARGV_DOMAIN = "daxalgo-hyperion-base-engine-argv/v1"
BASE_RUNTIME_SIGNER_PROOF_DOMAIN = "daxalgo-hyperion-base-runtime-signer-proof/v1"
BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_ID_DOMAIN = (
    "daxalgo-hyperion-base-engine-activation-signing-bundle-id/v1"
)
BASE_ENGINE_ACTIVATION_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    "daxalgo-hyperion-base-engine-activation-external-signature-id/v1"
)

_PAYLOAD_ENCODING = "canonical-json-base64url"
_ALGORITHM = "ES256"
_SIGNATURE_FORMAT = "ieee-p1363-fixed-64-low-s"
_LOCAL_RUNTIME_SIGNER_PROVIDER = "local-pem/v1"
_ACTIVATION_SIGNING_STATUS = "unsigned-non-authorizing"
_ACTIVATION_SIGNING_HASH_ALGORITHM = "SHA-256"
_ACTIVATION_EXTERNAL_RAW_MESSAGE_MODE = "raw-message"
_ACTIVATION_EXTERNAL_SHA256_DIGEST_MODE = "sha256-digest"
_ACTIVATION_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
_ACTIVATION_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
_RUNTIME_SIGNER_ALGORITHM = "ES256"
_RUNTIME_SIGNER_MESSAGE_TYPE = "sha256-digest"
_RUNTIME_SIGNER_INPUT_ENCODING = "base64url"
_ACTIVATION_ID_PREFIX = "vqbaseact-"
_ACTIVATION_SIGNING_BUNDLE_ID_PREFIX = "vqbaseactsigning-"
_ACTIVATION_EXTERNAL_SIGNATURE_ID_PREFIX = "vqbaseactsignature-"
_ATTESTATION_ID_PREFIX = "vqbaseatt-"
_LOOPBACK_HOST = "127.0.0.1"
_ZERO_SHA256 = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_ACTIVATION_ID_RE = re.compile(r"^vqbaseact-[0-9a-f]{64}$")
_ACTIVATION_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqbaseactsigning-[0-9a-f]{64}$")
_ACTIVATION_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqbaseactsignature-[0-9a-f]{64}$")
_ATTESTATION_ID_RE = re.compile(r"^vqbaseatt-[0-9a-f]{64}$")
_TLS_CERTIFICATE_PEM_RE = re.compile(
    rb"\A[ \t\r\n]*-----BEGIN CERTIFICATE-----[ \t\r\n]+"
    rb"[A-Za-z0-9+/=\r\n]+"
    rb"-----END CERTIFICATE-----[ \t\r\n]*\Z"
)
_SECRET_ENVIRONMENT_RE = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE
)
_SAFE_CHILD_ENVIRONMENT_NAMES = {
    "CUDA_DEVICE_ORDER",
    "CUDA_VISIBLE_DEVICES",
    "HF_HOME",
    "HF_HUB_CACHE",
    "LANG",
    "LC_ALL",
    "NCCL_DEBUG",
    "NCCL_IB_DISABLE",
    "NCCL_P2P_DISABLE",
    "NVIDIA_DRIVER_CAPABILITIES",
    "NVIDIA_VISIBLE_DEVICES",
    "OMP_NUM_THREADS",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TOKENIZERS_PARALLELISM",
    "TORCH_HOME",
    "TRANSFORMERS_CACHE",
    "WINDIR",
}
_SUPPORTED_VLLM_ENGINE_VERSIONS = {"0.10.0", "0.26.0"}

MAX_BASE_ENGINE_WRAPPER_CONFIG_BYTES = 1_000_000
MAX_BASE_ENGINE_ACTIVATION_BYTES = 1_000_000
MAX_BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_BYTES = 4_000_000
MAX_BASE_ENGINE_ACTIVATION_EXTERNAL_SIGNATURE_BYTES = 16_000
MAX_BASE_ENGINE_ACTIVATION_SIGNATURE_INPUT_BYTES = 1_000_000
MAX_BASE_RUNTIME_ATTESTATION_BYTES = 1_000_000
MAX_BASE_RUNTIME_SIGNER_SIGNATURE_INPUT_BYTES = 256_000
MAX_BASE_RUNTIME_SIGNER_REQUEST_BYTES = 512_000
MAX_BASE_RUNTIME_SIGNER_TLS_CERTIFICATE_BYTES = 128_000
MAX_WRAPPER_PACKAGE_FILES = 1_024
MAX_WRAPPER_PACKAGE_BYTES = 64_000_000
MAX_ACTIVATION_VALIDITY = timedelta(days=7)
MAX_ATTESTATION_VALIDITY = timedelta(minutes=5)

_ACTIVATION_SIGNING_AUTHORITY_KEYS = {
    "baseEngineActivation",
    "baseSelection",
    "checkpoint",
    "corpusReview",
    "deployment",
    "evaluation",
    "evaluationAuthoring",
    "hostedServing",
    "installation",
    "promotionDecision",
    "release",
    "review",
    "strategyExecution",
    "training",
    "verifierExecution",
}
_ACTIVATION_SIGNING_BUNDLE_KEYS = {
    "schemaVersion",
    "bundleId",
    "status",
    "authority",
    "trust",
    "activationId",
    "payloadSha256",
    "payload",
    "unsignedEnvelopeSha256",
    "unsignedEnvelope",
    "validity",
    "signatureContract",
    "request",
}
_ACTIVATION_EXTERNAL_SIGNATURE_KEYS = {
    "schemaVersion",
    "signatureId",
    "signingBundleId",
    "signingBundleSha256",
    "activationId",
    "payloadSha256",
    "unsignedEnvelopeSha256",
    "signatureInputSha256",
    "publicKeySpkiSha256",
    "mode",
    "format",
    "signature",
}


def _fail(field: str, message: str) -> None:
    raise ValidationError(f"{field}: {message}")


class RequestValidationError(ValidationError):
    pass


def _request_fail(field: str, message: str) -> None:
    raise RequestValidationError(f"{field}: {message}")


def _exact_object(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(field, "must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        additional = sorted(actual - keys)
        details: list[str] = []
        if missing:
            details.append(f"missing {missing!r}")
        if additional:
            details.append(f"additional {additional!r}")
        _fail(field, "; ".join(details))
    return value


def _text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail(field, f"must be a non-empty string no longer than {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(field, "must not contain control characters")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValidationError(f"{field}: must be valid Unicode text") from error
    return value


def _safe_id(value: Any, field: str) -> str:
    identifier = _text(value, field, maximum=200)
    if _SAFE_ID_RE.fullmatch(identifier) is None:
        _fail(field, "must be a safe ASCII identifier")
    return identifier


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(field, "must be a lowercase SHA-256")
    return value


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(field, "must be an integer")
    if value < minimum or value > maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return value


def _number(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(field, "must be a number")
    number = float(value)
    if not minimum <= number <= maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return number


def _environment_name(value: Any, field: str) -> str:
    name = _text(value, field, maximum=128)
    if _ENVIRONMENT_NAME_RE.fullmatch(name) is None:
        _fail(field, "must be a valid environment-variable name")
    return name


def _runtime_signer_endpoint(value: Any, field: str) -> str:
    endpoint = _text(value, field, maximum=2_000)
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise ValidationError(
            f"{field}: must be a canonical loopback HTTPS URL"
        ) from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != _LOOPBACK_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or parsed.path != BASE_RUNTIME_SIGNER_ENDPOINT_PATH
        or parsed.query
        or parsed.fragment
        or endpoint
        != f"https://{_LOOPBACK_HOST}:{port}{BASE_RUNTIME_SIGNER_ENDPOINT_PATH}"
    ):
        _fail(field, "must be the canonical fixed-path loopback HTTPS signer URL")
    if not 1 <= port <= 65_535:
        _fail(field, "port must be between 1 and 65535")
    return endpoint


def _load_tls_certificate_identity(path: Path, field: str) -> tuple[str, str]:
    raw = _read_file_bounded(path, field, MAX_BASE_RUNTIME_SIGNER_TLS_CERTIFICATE_BYTES)
    if _TLS_CERTIFICATE_PEM_RE.fullmatch(raw) is None:
        _fail(field, "must contain exactly one PEM certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(raw.decode("ascii", errors="strict"))
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as error:
        raise ValidationError(f"{field}: invalid PEM certificate") from error
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        _fail(
            "base-engine TLS certificate cryptography",
            "requires the optional 'auth' dependency",
        )
    try:
        certificate = x509.load_der_x509_certificate(der)
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError) as error:
        raise ValidationError(f"{field}: invalid X.509 certificate") from error
    return hashlib.sha256(der).hexdigest(), hashlib.sha256(spki).hexdigest()


def _default_runtime_signer_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_seconds: float,
    max_response_bytes: int,
    tls_certificate_sha256: str,
) -> TransportResponse:
    endpoint = _runtime_signer_endpoint(url, "base-engine external runtime signer URL")
    parsed = urllib.parse.urlsplit(endpoint)
    expected_certificate_sha256 = _sha256(
        tls_certificate_sha256,
        "base-engine external runtime signer TLS certificate SHA-256",
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port,
        timeout=timeout_seconds,
        context=context,
    )
    deadline = time.monotonic() + timeout_seconds
    deadline_fired = threading.Event()

    def abort_at_deadline() -> None:
        deadline_fired.set()
        active_socket = connection.sock
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    timer = threading.Timer(timeout_seconds, abort_at_deadline)
    timer.daemon = True
    timer.start()
    try:
        connection.connect()
        active_socket = connection.sock
        if active_socket is None:
            _fail("base-engine external runtime signer", "TLS socket is unavailable")
        peer_certificate = active_socket.getpeercert(binary_form=True)
        if not peer_certificate or not secrets.compare_digest(
            hashlib.sha256(peer_certificate).hexdigest(),
            expected_certificate_sha256,
        ):
            _fail(
                "base-engine external runtime signer",
                "TLS certificate does not match the pinned identity",
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0 or deadline_fired.is_set():
            _fail("base-engine external runtime signer", "exceeded its total deadline")
        active_socket.settimeout(remaining)
        connection.request(method, parsed.path, body=body, headers=dict(headers))
        response = connection.getresponse()
        lengths = response.headers.get_all("Content-Length", failobj=[])
        if len(lengths) > 1:
            _fail(
                "base-engine external runtime signer response",
                "contains duplicate Content-Length headers",
            )
        if len(response.headers.get_all("Content-Type", failobj=[])) > 1:
            _fail(
                "base-engine external runtime signer response",
                "contains duplicate Content-Type headers",
            )
        length = lengths[0] if lengths else None
        if length is not None:
            try:
                if int(length) > max_response_bytes:
                    _fail(
                        "base-engine external runtime signer response",
                        "exceeds the configured byte limit",
                    )
            except ValueError as error:
                raise ValidationError(
                    "base-engine external runtime signer response: invalid Content-Length"
                ) from error
        response_body = response.read(max_response_bytes + 1)
        status = response.status
        response_headers = dict(response.getheaders())
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        if deadline_fired.is_set() or time.monotonic() >= deadline:
            raise ValidationError(
                "base-engine external runtime signer: exceeded its total deadline"
            ) from error
        raise ValidationError(
            f"base-engine external runtime signer request failed: {error}"
        ) from error
    finally:
        timer.cancel()
        connection.close()
    if deadline_fired.is_set() or time.monotonic() > deadline:
        _fail("base-engine external runtime signer", "exceeded its total deadline")
    if len(response_body) > max_response_bytes:
        _fail(
            "base-engine external runtime signer response",
            "exceeds the configured byte limit",
        )
    return TransportResponse(status, response_headers, response_body, endpoint)


def _absolute_path(
    value: Any,
    field: str,
    *,
    directory: bool = False,
    allow_missing: bool = False,
) -> Path:
    path = Path(_text(value, field, maximum=2_000))
    if not path.is_absolute():
        _fail(field, "must be an absolute path")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if allow_missing:
        if not absolute.parent.is_dir():
            _fail(field, "parent must be an existing directory")
    elif directory:
        if not absolute.is_dir():
            _fail(field, "must identify an existing directory")
    elif not absolute.is_file():
        _fail(field, "must identify an existing regular file")
    return absolute


def _canonical_utc(value: Any, field: str) -> datetime:
    text = _text(value, field, maximum=20)
    if len(text) != 20 or not text.endswith("Z"):
        _fail(field, "must use exact UTC second form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(field, "must be a real UTC second in form YYYY-MM-DDTHH:MM:SSZ")
    return parsed.replace(tzinfo=timezone.utc)


def _validation_time(value: datetime, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _fail(field, "must be timezone-aware")
    return value.astimezone(timezone.utc)


def _fresh_validation_time(value: datetime | None, field: str) -> datetime:
    return _validation_time(value or datetime.now(timezone.utc), field)


def _utc_second(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _frame(values: Sequence[str | bytes]) -> bytes:
    framed = bytearray()
    for value in values:
        encoded = value if isinstance(value, bytes) else value.encode("utf-8", "strict")
        if len(encoded) > 0x7FFFFFFF:
            _fail("canonical field", "exceeds the signed int32 length-prefix limit")
        framed.extend(len(encoded).to_bytes(4, "big", signed=True))
        framed.extend(encoded)
    return bytes(framed)


def _domain_sha256(domain: str, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_frame((domain, canonical_json_bytes(value)))).hexdigest()


def _handoff_content_id(
    value: Mapping[str, Any],
    *,
    identity_field: str,
    prefix: str,
    domain: str,
) -> str:
    normalized = dict(value)
    normalized[identity_field] = prefix + _ZERO_SHA256
    return (
        prefix
        + hashlib.sha256(_frame((domain, canonical_json_bytes(normalized)))).hexdigest()
    )


def base_engine_activation_signing_bundle_id(value: Mapping[str, Any]) -> str:
    return _handoff_content_id(
        value,
        identity_field="bundleId",
        prefix=_ACTIVATION_SIGNING_BUNDLE_ID_PREFIX,
        domain=BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_ID_DOMAIN,
    )


def base_engine_activation_external_signature_id(
    value: Mapping[str, Any],
) -> str:
    return _handoff_content_id(
        value,
        identity_field="signatureId",
        prefix=_ACTIVATION_EXTERNAL_SIGNATURE_ID_PREFIX,
        domain=BASE_ENGINE_ACTIVATION_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


def _signature_input(
    domain: str, envelope: Mapping[str, Any], payload_bytes: bytes
) -> bytes:
    return _frame(
        (
            domain,
            envelope["schemaVersion"],
            envelope["payloadEncoding"],
            envelope["algorithm"],
            envelope["signatureFormat"],
            envelope["publicKeySpkiSha256"],
            payload_bytes,
        )
    )


def _new_unsigned_envelope(
    *,
    schema_version: str,
    payload: Mapping[str, Any],
    public_key_spki_sha256: str,
) -> tuple[dict[str, Any], bytes]:
    payload_bytes = canonical_json_bytes(payload)
    envelope = {
        "schemaVersion": schema_version,
        "payloadEncoding": _PAYLOAD_ENCODING,
        "algorithm": _ALGORITHM,
        "signatureFormat": _SIGNATURE_FORMAT,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "payload": _base64url_encode(payload_bytes),
        "signature": "",
    }
    return envelope, payload_bytes


def _new_envelope(
    *,
    schema_version: str,
    signature_domain: str,
    payload: Mapping[str, Any],
    private_key: Any,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    envelope, payload_bytes = _new_unsigned_envelope(
        schema_version=schema_version,
        payload=payload,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    envelope["signature"] = _base64url_encode(
        _sign_p1363_low_s(
            private_key, _signature_input(signature_domain, envelope, payload_bytes)
        )
    )
    return envelope


def _verify_envelope(
    value: Any,
    *,
    field: str,
    schema_version: str,
    signature_domain: str,
    public_key_path: Path,
    expected_public_key_spki_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    envelope = _exact_object(
        value,
        {
            "schemaVersion",
            "payloadEncoding",
            "algorithm",
            "signatureFormat",
            "publicKeySpkiSha256",
            "payload",
            "signature",
        },
        field,
    )
    if envelope["schemaVersion"] != schema_version:
        _fail(f"{field}.schemaVersion", f"must be {schema_version!r}")
    if envelope["payloadEncoding"] != _PAYLOAD_ENCODING:
        _fail(f"{field}.payloadEncoding", f"must be {_PAYLOAD_ENCODING!r}")
    if envelope["algorithm"] != _ALGORITHM:
        _fail(f"{field}.algorithm", f"must be {_ALGORITHM!r}")
    if envelope["signatureFormat"] != _SIGNATURE_FORMAT:
        _fail(f"{field}.signatureFormat", f"must be {_SIGNATURE_FORMAT!r}")
    expected_spki = _sha256(
        expected_public_key_spki_sha256,
        f"{field} expected public-key SPKI SHA-256",
    )
    public_key, actual_spki = _load_public_key(public_key_path)
    if actual_spki != expected_spki or envelope["publicKeySpkiSha256"] != expected_spki:
        _fail(f"{field}.publicKeySpkiSha256", "does not match the pinned public key")
    payload_bytes = _base64url_decode(
        envelope["payload"],
        f"{field}.payload",
        max_bytes=MAX_BASE_RUNTIME_ATTESTATION_BYTES,
    )
    try:
        payload = json.loads(payload_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(
            f"{field}.payload: must be canonical UTF-8 JSON"
        ) from error
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != payload_bytes:
        _fail(f"{field}.payload", "must contain canonical JSON object bytes")
    signature = _base64url_decode(
        envelope["signature"], f"{field}.signature", exact_bytes=64
    )
    _verify_p1363_low_s(
        public_key,
        _signature_input(signature_domain, envelope, payload_bytes),
        signature,
    )
    return (
        envelope,
        payload,
        payload_bytes,
        hashlib.sha256(canonical_json_bytes(envelope)).hexdigest(),
    )


def _inspect_envelope(
    value: Any,
    *,
    field: str,
    schema_version: str,
    payload_validator: Callable[[Any], dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    envelope = _exact_object(
        value,
        {
            "schemaVersion",
            "payloadEncoding",
            "algorithm",
            "signatureFormat",
            "publicKeySpkiSha256",
            "payload",
            "signature",
        },
        field,
    )
    if envelope["schemaVersion"] != schema_version:
        _fail(f"{field}.schemaVersion", f"must be {schema_version!r}")
    if (
        envelope["payloadEncoding"] != _PAYLOAD_ENCODING
        or envelope["algorithm"] != _ALGORITHM
        or envelope["signatureFormat"] != _SIGNATURE_FORMAT
    ):
        _fail(field, "uses an unsupported signature contract")
    _sha256(envelope["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256")
    payload_bytes = _base64url_decode(
        envelope["payload"],
        f"{field}.payload",
        max_bytes=MAX_BASE_RUNTIME_ATTESTATION_BYTES,
    )
    try:
        decoded = json.loads(payload_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(
            f"{field}.payload: must be canonical UTF-8 JSON"
        ) from error
    if canonical_json_bytes(decoded) != payload_bytes:
        _fail(f"{field}.payload", "must contain canonical JSON bytes")
    payload = payload_validator(decoded)
    _base64url_decode(envelope["signature"], f"{field}.signature", exact_bytes=64)
    return (
        envelope,
        payload,
        payload_bytes,
        hashlib.sha256(canonical_json_bytes(envelope)).hexdigest(),
    )


@dataclass(frozen=True)
class BaseEngineActivationTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_key_path", Path(self.public_key_path))
        _sha256(self.public_key_spki_sha256, "activation trust public-key SPKI SHA-256")
        _safe_id(self.audience, "activation trust audience")
        _safe_id(self.key_id, "activation trust keyId")
        _safe_id(self.signer_role, "activation trust signerRole")


@dataclass(frozen=True)
class BaseTargetConfig:
    profile_path: Path
    snapshot_manifest_path: Path
    snapshot_path: Path
    catalog_path: Path
    source_lock_path: Path
    expected_profile_sha256: str


@dataclass(frozen=True)
class BaseActivationConfig:
    path: Path
    trust: BaseEngineActivationTrust


@dataclass(frozen=True)
class BaseRuntimeSigningConfig:
    provider: str
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str
    receipt_ttl_seconds: int


@dataclass(frozen=True)
class BaseLocalRuntimeSigningConfig(BaseRuntimeSigningConfig):
    private_key_path: Path
    private_key_password_environment: str | None


@dataclass(frozen=True)
class BaseExternalRuntimeSigningConfig(BaseRuntimeSigningConfig):
    signer_endpoint: str
    signer_bearer_token_environment: str
    provider_key_reference: str
    signer_tls_certificate_path: Path
    signer_tls_certificate_sha256: str
    signer_tls_public_key_spki_sha256: str
    request_timeout_seconds: float
    max_response_bytes: int
    signature_format: str


@dataclass(frozen=True)
class BaseServiceConfig:
    listen_host: str
    listen_port: int
    bearer_token_environment: str
    max_request_bytes: int
    max_response_bytes: int
    max_attestations: int


@dataclass(frozen=True)
class BaseEngineWrapperConfig:
    path: Path
    sha256: str
    target: BaseTargetConfig
    activation: BaseActivationConfig
    runtime_signing: BaseRuntimeSigningConfig
    engine: EngineConfig
    child_user_id: int
    child_group_id: int
    service: BaseServiceConfig


@dataclass(frozen=True)
class VerifiedBaseEngineActivation:
    path: Path | None
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str


@dataclass(frozen=True)
class VerifiedBaseEngineActivationSigningBundle:
    path: Path
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    unsigned_envelope: dict[str, Any]
    unsigned_envelope_bytes: bytes
    unsigned_envelope_sha256: str
    signature_preimage: bytes
    signature_input_sha256: str
    public_key_spki_sha256: str


@dataclass(frozen=True)
class VerifiedBaseRuntimeAttestation:
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str


@dataclass(frozen=True)
class BaseActivationSnapshot:
    activation_id: str
    activation_envelope_sha256: str
    activation_payload_sha256: str
    wrapper_config_sha256: str
    wrapper_package_sha256: str
    serving_profile_sha256: str
    execution_model_id: str
    source_lock_sha256: str
    snapshot_manifest_sha256: str
    snapshot_sha256: str
    file_tree_sha256: str
    engine_executable_sha256: str
    engine_version: str
    container_image_digest: str
    runtime_public_key_spki_sha256: str
    expires_at_utc: str
    serving_profile: BaseEvaluationProfile = field(repr=False, compare=False)
    engine_process_id: int = 0
    engine_argv_sha256: str = ""


class OpenedProcessFactory(Protocol):
    def __call__(
        self,
        executable_fd: int,
        argv: Sequence[str],
        environment: Mapping[str, str],
        working_directory: Path,
    ) -> ChildProcess: ...


ReadOnlyProbe = Callable[[Path], bool]
ListenerOwnershipProbe = Callable[[int, str, int], bool]
RuntimeKeyIsolationProbe = Callable[[BaseEngineWrapperConfig], bool]
Clock = Callable[[], datetime]
Monotonic = Callable[[], float]
Sleeper = Callable[[float], None]


def _load_config_document(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_file_bounded(
        path, "base-engine wrapper config", MAX_BASE_ENGINE_WRAPPER_CONFIG_BYTES
    )
    try:
        value = load_json_document(path, max_bytes=MAX_BASE_ENGINE_WRAPPER_CONFIG_BYTES)
    except ValueError as error:
        raise ValidationError(
            "base-engine wrapper config: invalid bounded JSON"
        ) from error
    if not isinstance(value, dict):
        _fail("base-engine wrapper config", "must have an object root")
    return value, raw


def load_base_engine_wrapper_config(
    path: str | os.PathLike[str],
) -> BaseEngineWrapperConfig:
    config_path = Path(os.path.abspath(os.fspath(path)))
    value, raw = _load_config_document(config_path)
    document = _exact_object(
        value,
        {
            "schemaVersion",
            "target",
            "activation",
            "runtimeSigning",
            "engine",
            "service",
        },
        "base-engine wrapper config",
    )
    schema_version = document["schemaVersion"]
    if schema_version not in {
        BASE_ENGINE_WRAPPER_SCHEMA_VERSION,
        BASE_ENGINE_WRAPPER_V2_SCHEMA_VERSION,
    }:
        _fail(
            "base-engine wrapper config.schemaVersion",
            "must be the supported v1 or v2 wrapper configuration",
        )
    target_value = _exact_object(
        document["target"],
        {
            "profilePath",
            "snapshotManifestPath",
            "snapshotPath",
            "catalogPath",
            "sourceLockPath",
            "expectedProfileSha256",
        },
        "base-engine wrapper config.target",
    )
    target = BaseTargetConfig(
        profile_path=_absolute_path(
            target_value["profilePath"], "base-engine wrapper config.target.profilePath"
        ),
        snapshot_manifest_path=_absolute_path(
            target_value["snapshotManifestPath"],
            "base-engine wrapper config.target.snapshotManifestPath",
        ),
        snapshot_path=_absolute_path(
            target_value["snapshotPath"],
            "base-engine wrapper config.target.snapshotPath",
            directory=True,
        ),
        catalog_path=_absolute_path(
            target_value["catalogPath"], "base-engine wrapper config.target.catalogPath"
        ),
        source_lock_path=_absolute_path(
            target_value["sourceLockPath"],
            "base-engine wrapper config.target.sourceLockPath",
        ),
        expected_profile_sha256=_sha256(
            target_value["expectedProfileSha256"],
            "base-engine wrapper config.target.expectedProfileSha256",
        ),
    )
    activation_value = _exact_object(
        document["activation"],
        {
            "path",
            "publicKeyPath",
            "publicKeySpkiSha256",
            "audience",
            "keyId",
            "signerRole",
        },
        "base-engine wrapper config.activation",
    )
    activation = BaseActivationConfig(
        path=_absolute_path(
            activation_value["path"],
            "base-engine wrapper config.activation.path",
            allow_missing=True,
        ),
        trust=BaseEngineActivationTrust(
            public_key_path=_absolute_path(
                activation_value["publicKeyPath"],
                "base-engine wrapper config.activation.publicKeyPath",
            ),
            public_key_spki_sha256=_sha256(
                activation_value["publicKeySpkiSha256"],
                "base-engine wrapper config.activation.publicKeySpkiSha256",
            ),
            audience=_safe_id(
                activation_value["audience"],
                "base-engine wrapper config.activation.audience",
            ),
            key_id=_safe_id(
                activation_value["keyId"], "base-engine wrapper config.activation.keyId"
            ),
            signer_role=_safe_id(
                activation_value["signerRole"],
                "base-engine wrapper config.activation.signerRole",
            ),
        ),
    )
    if schema_version == BASE_ENGINE_WRAPPER_SCHEMA_VERSION:
        signing_value = _exact_object(
            document["runtimeSigning"],
            {
                "privateKeyPath",
                "publicKeyPath",
                "privateKeyPasswordEnvironment",
                "audience",
                "keyId",
                "signerRole",
                "receiptTtlSeconds",
            },
            "base-engine wrapper config.runtimeSigning",
        )
        password_environment = signing_value["privateKeyPasswordEnvironment"]
        if password_environment is not None:
            password_environment = _environment_name(
                password_environment,
                "base-engine wrapper config.runtimeSigning.privateKeyPasswordEnvironment",
            )
        public_key_path = _absolute_path(
            signing_value["publicKeyPath"],
            "base-engine wrapper config.runtimeSigning.publicKeyPath",
        )
        public_key, public_key_spki_sha256 = _load_public_key(public_key_path)
        del public_key
        runtime_signing = BaseLocalRuntimeSigningConfig(
            provider=_LOCAL_RUNTIME_SIGNER_PROVIDER,
            private_key_path=_absolute_path(
                signing_value["privateKeyPath"],
                "base-engine wrapper config.runtimeSigning.privateKeyPath",
            ),
            public_key_path=public_key_path,
            public_key_spki_sha256=public_key_spki_sha256,
            private_key_password_environment=password_environment,
            audience=_safe_id(
                signing_value["audience"],
                "base-engine wrapper config.runtimeSigning.audience",
            ),
            key_id=_safe_id(
                signing_value["keyId"],
                "base-engine wrapper config.runtimeSigning.keyId",
            ),
            signer_role=_safe_id(
                signing_value["signerRole"],
                "base-engine wrapper config.runtimeSigning.signerRole",
            ),
            receipt_ttl_seconds=_integer(
                signing_value["receiptTtlSeconds"],
                "base-engine wrapper config.runtimeSigning.receiptTtlSeconds",
                1,
                300,
            ),
        )
    else:
        signing_value = _exact_object(
            document["runtimeSigning"],
            {
                "provider",
                "signerEndpoint",
                "signerBearerTokenEnvironment",
                "providerKeyReference",
                "signerTlsCertificatePath",
                "signerTlsCertificateSha256",
                "requestTimeoutSeconds",
                "maxResponseBytes",
                "signatureFormat",
                "publicKeyPath",
                "publicKeySpkiSha256",
                "audience",
                "keyId",
                "signerRole",
                "receiptTtlSeconds",
            },
            "base-engine wrapper config.runtimeSigning",
        )
        if signing_value["provider"] != BASE_RUNTIME_SIGNER_PROVIDER:
            _fail(
                "base-engine wrapper config.runtimeSigning.provider",
                f"must be {BASE_RUNTIME_SIGNER_PROVIDER!r}",
            )
        public_key_path = _absolute_path(
            signing_value["publicKeyPath"],
            "base-engine wrapper config.runtimeSigning.publicKeyPath",
        )
        expected_spki = _sha256(
            signing_value["publicKeySpkiSha256"],
            "base-engine wrapper config.runtimeSigning.publicKeySpkiSha256",
        )
        public_key, actual_spki = _load_public_key(public_key_path)
        del public_key
        if actual_spki != expected_spki:
            _fail(
                "base-engine wrapper config.runtimeSigning.publicKeySpkiSha256",
                "does not match the pinned public key",
            )
        signature_format = signing_value["signatureFormat"]
        if signature_format not in {
            REVIEW_RECEIPT_EXTERNAL_DER_SIGNATURE_FORMAT,
            REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT,
        }:
            _fail(
                "base-engine wrapper config.runtimeSigning.signatureFormat",
                "must be 'asn1-der' or 'ieee-p1363-fixed-64'",
            )
        tls_certificate_path = _absolute_path(
            signing_value["signerTlsCertificatePath"],
            "base-engine wrapper config.runtimeSigning.signerTlsCertificatePath",
        )
        (
            actual_certificate_sha256,
            tls_public_key_spki_sha256,
        ) = _load_tls_certificate_identity(
            tls_certificate_path,
            "base-engine wrapper config.runtimeSigning.signerTlsCertificatePath",
        )
        expected_certificate_sha256 = _sha256(
            signing_value["signerTlsCertificateSha256"],
            "base-engine wrapper config.runtimeSigning.signerTlsCertificateSha256",
        )
        if actual_certificate_sha256 != expected_certificate_sha256:
            _fail(
                "base-engine wrapper config.runtimeSigning.signerTlsCertificateSha256",
                "does not match the pinned TLS certificate",
            )
        runtime_signing = BaseExternalRuntimeSigningConfig(
            provider=BASE_RUNTIME_SIGNER_PROVIDER,
            signer_endpoint=_runtime_signer_endpoint(
                signing_value["signerEndpoint"],
                "base-engine wrapper config.runtimeSigning.signerEndpoint",
            ),
            signer_bearer_token_environment=_environment_name(
                signing_value["signerBearerTokenEnvironment"],
                "base-engine wrapper config.runtimeSigning.signerBearerTokenEnvironment",
            ),
            provider_key_reference=_text(
                signing_value["providerKeyReference"],
                "base-engine wrapper config.runtimeSigning.providerKeyReference",
                maximum=1_000,
            ),
            signer_tls_certificate_path=tls_certificate_path,
            signer_tls_certificate_sha256=expected_certificate_sha256,
            signer_tls_public_key_spki_sha256=tls_public_key_spki_sha256,
            request_timeout_seconds=_number(
                signing_value["requestTimeoutSeconds"],
                "base-engine wrapper config.runtimeSigning.requestTimeoutSeconds",
                0.1,
                30,
            ),
            max_response_bytes=_integer(
                signing_value["maxResponseBytes"],
                "base-engine wrapper config.runtimeSigning.maxResponseBytes",
                512,
                65_536,
            ),
            signature_format=signature_format,
            public_key_path=public_key_path,
            public_key_spki_sha256=expected_spki,
            audience=_safe_id(
                signing_value["audience"],
                "base-engine wrapper config.runtimeSigning.audience",
            ),
            key_id=_safe_id(
                signing_value["keyId"],
                "base-engine wrapper config.runtimeSigning.keyId",
            ),
            signer_role=_safe_id(
                signing_value["signerRole"],
                "base-engine wrapper config.runtimeSigning.signerRole",
            ),
            receipt_ttl_seconds=_integer(
                signing_value["receiptTtlSeconds"],
                "base-engine wrapper config.runtimeSigning.receiptTtlSeconds",
                1,
                300,
            ),
        )
    engine_value = _exact_object(
        document["engine"],
        {
            "executablePath",
            "executableSha256",
            "containerImageDigestEnvironment",
            "childHost",
            "childPort",
            "startupTimeoutSeconds",
            "healthIntervalSeconds",
            "integrityIntervalSeconds",
            "requestTimeoutSeconds",
            "shutdownGraceSeconds",
            "environmentAllowlist",
            "childUserId",
            "childGroupId",
        },
        "base-engine wrapper config.engine",
    )
    if engine_value["childHost"] != _LOOPBACK_HOST:
        _fail("base-engine wrapper config.engine.childHost", "must be '127.0.0.1'")
    allowlist_value = engine_value["environmentAllowlist"]
    if not isinstance(allowlist_value, list) or len(allowlist_value) > 64:
        _fail(
            "base-engine wrapper config.engine.environmentAllowlist",
            "must be an array of at most 64 names",
        )
    allowlist: list[str] = []
    for index, item in enumerate(allowlist_value):
        name = _environment_name(
            item, f"base-engine wrapper config.engine.environmentAllowlist[{index}]"
        )
        if name in allowlist:
            _fail(
                "base-engine wrapper config.engine.environmentAllowlist",
                f"contains duplicate name {name!r}",
            )
        if name not in _SAFE_CHILD_ENVIRONMENT_NAMES or _SECRET_ENVIRONMENT_RE.search(
            name
        ):
            _fail(
                "base-engine wrapper config.engine.environmentAllowlist",
                f"name {name!r} is not in the safe child-environment allowlist",
            )
        allowlist.append(name)
    image_environment = _environment_name(
        engine_value["containerImageDigestEnvironment"],
        "base-engine wrapper config.engine.containerImageDigestEnvironment",
    )
    engine = EngineConfig(
        executable_path=_absolute_path(
            engine_value["executablePath"],
            "base-engine wrapper config.engine.executablePath",
        ),
        executable_sha256=_sha256(
            engine_value["executableSha256"],
            "base-engine wrapper config.engine.executableSha256",
        ),
        container_image_digest_environment=image_environment,
        child_host=_LOOPBACK_HOST,
        child_port=_integer(
            engine_value["childPort"],
            "base-engine wrapper config.engine.childPort",
            1,
            65_535,
        ),
        startup_timeout_seconds=_number(
            engine_value["startupTimeoutSeconds"],
            "base-engine wrapper config.engine.startupTimeoutSeconds",
            1,
            3_600,
        ),
        health_interval_seconds=_number(
            engine_value["healthIntervalSeconds"],
            "base-engine wrapper config.engine.healthIntervalSeconds",
            0.1,
            60,
        ),
        integrity_interval_seconds=_number(
            engine_value["integrityIntervalSeconds"],
            "base-engine wrapper config.engine.integrityIntervalSeconds",
            1,
            3_600,
        ),
        request_timeout_seconds=_number(
            engine_value["requestTimeoutSeconds"],
            "base-engine wrapper config.engine.requestTimeoutSeconds",
            0.1,
            3_600,
        ),
        shutdown_grace_seconds=_number(
            engine_value["shutdownGraceSeconds"],
            "base-engine wrapper config.engine.shutdownGraceSeconds",
            0,
            60,
        ),
        environment_allowlist=tuple(allowlist),
    )
    child_user_id = _integer(
        engine_value["childUserId"],
        "base-engine wrapper config.engine.childUserId",
        1,
        2_147_483_647,
    )
    child_group_id = _integer(
        engine_value["childGroupId"],
        "base-engine wrapper config.engine.childGroupId",
        1,
        2_147_483_647,
    )
    service_value = _exact_object(
        document["service"],
        {
            "listenHost",
            "listenPort",
            "bearerTokenEnvironment",
            "maxRequestBytes",
            "maxResponseBytes",
            "maxAttestations",
        },
        "base-engine wrapper config.service",
    )
    if service_value["listenHost"] != _LOOPBACK_HOST:
        _fail("base-engine wrapper config.service.listenHost", "must be '127.0.0.1'")
    bearer_environment = _environment_name(
        service_value["bearerTokenEnvironment"],
        "base-engine wrapper config.service.bearerTokenEnvironment",
    )
    credential_environment = (
        runtime_signing.private_key_password_environment
        if isinstance(runtime_signing, BaseLocalRuntimeSigningConfig)
        else runtime_signing.signer_bearer_token_environment
    )
    sensitive_names = {
        bearer_environment.upper(),
        image_environment.upper(),
        *(
            [credential_environment.upper()]
            if credential_environment is not None
            else []
        ),
    }
    if len(sensitive_names) != (3 if credential_environment is not None else 2):
        _fail(
            "base-engine wrapper config",
            "image, service bearer, and signer credential values must use distinct environment variables",
        )
    if any(name.upper() in sensitive_names for name in allowlist):
        _fail(
            "base-engine wrapper config.engine.environmentAllowlist",
            "must not include wrapper secret or trusted-image variables",
        )
    service = BaseServiceConfig(
        listen_host=_LOOPBACK_HOST,
        listen_port=_integer(
            service_value["listenPort"],
            "base-engine wrapper config.service.listenPort",
            1,
            65_535,
        ),
        bearer_token_environment=bearer_environment,
        max_request_bytes=_integer(
            service_value["maxRequestBytes"],
            "base-engine wrapper config.service.maxRequestBytes",
            1_024,
            8_000_000,
        ),
        max_response_bytes=_integer(
            service_value["maxResponseBytes"],
            "base-engine wrapper config.service.maxResponseBytes",
            1_024,
            16_000_000,
        ),
        max_attestations=_integer(
            service_value["maxAttestations"],
            "base-engine wrapper config.service.maxAttestations",
            1,
            1_000_000,
        ),
    )
    if service.listen_port == engine.child_port:
        _fail("base-engine wrapper config", "outer and child ports must be distinct")
    if isinstance(runtime_signing, BaseExternalRuntimeSigningConfig):
        signer_port = urllib.parse.urlsplit(runtime_signing.signer_endpoint).port
        if signer_port in {service.listen_port, engine.child_port}:
            _fail(
                "base-engine wrapper config",
                "outer, child, and runtime-signer ports must be distinct",
            )
    if (
        activation.trust.public_key_spki_sha256
        == runtime_signing.public_key_spki_sha256
    ):
        _fail(
            "base-engine wrapper config signer separation",
            "activation and runtime-attestation keys must be distinct",
        )
    if (
        activation.trust.key_id == runtime_signing.key_id
        or activation.trust.signer_role == runtime_signing.signer_role
    ):
        _fail(
            "base-engine wrapper config signer separation",
            "activation and runtime-attestation key IDs and roles must be distinct",
        )
    if isinstance(runtime_signing, BaseExternalRuntimeSigningConfig):
        spkis = {
            activation.trust.public_key_spki_sha256,
            runtime_signing.public_key_spki_sha256,
            runtime_signing.signer_tls_public_key_spki_sha256,
        }
        if len(spkis) != 3:
            _fail(
                "base-engine wrapper config signer separation",
                "activation, runtime-attestation, and TLS keys must be distinct",
            )
    return BaseEngineWrapperConfig(
        path=config_path,
        sha256=hashlib.sha256(raw).hexdigest(),
        target=target,
        activation=activation,
        runtime_signing=runtime_signing,
        engine=engine,
        child_user_id=child_user_id,
        child_group_id=child_group_id,
        service=service,
    )


def base_wrapper_package_sha256(
    package_root: str | os.PathLike[str] | None = None,
) -> str:
    root = (
        Path(package_root)
        if package_root is not None
        else Path(__file__).resolve().parent
    )
    root = Path(os.path.abspath(os.fspath(root)))
    if not root.is_dir():
        _fail("base-engine wrapper package", "must identify an existing directory")
    entries: list[list[str]] = []
    total = 0
    for path in sorted(
        root.rglob("*.py"), key=lambda item: item.relative_to(root).as_posix()
    ):
        if len(entries) >= MAX_WRAPPER_PACKAGE_FILES:
            _fail("base-engine wrapper package", "contains too many Python files")
        resolved = _reject_reparse_components(path, "base-engine wrapper package file")
        info = os.lstat(resolved)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _fail(
                "base-engine wrapper package file", "must be a single-link regular file"
            )
        raw = _read_file_bounded(
            resolved, "base-engine wrapper package file", MAX_WRAPPER_PACKAGE_BYTES
        )
        total += len(raw)
        if total > MAX_WRAPPER_PACKAGE_BYTES:
            _fail("base-engine wrapper package", "exceeds the aggregate byte limit")
        entries.append(
            [
                path.relative_to(root).as_posix(),
                str(len(raw)),
                hashlib.sha256(raw).hexdigest(),
            ]
        )
    if not entries:
        _fail("base-engine wrapper package", "contains no Python files")
    return hashlib.sha256(
        _frame((BASE_WRAPPER_PACKAGE_TREE_DOMAIN, canonical_json_bytes(entries)))
    ).hexdigest()


def engine_argv_sha256(argv: Sequence[str]) -> str:
    if not argv:
        _fail("base-engine argv", "must not be empty")
    return hashlib.sha256(
        _frame((BASE_ENGINE_ARGV_DOMAIN, canonical_json_bytes(list(argv))))
    ).hexdigest()


def _validated_target(config: BaseEngineWrapperConfig) -> BaseEvaluationProfile:
    target = config.target
    profile = validate_base_evaluation_profile(
        profile_path=target.profile_path,
        snapshot_manifest_path=target.snapshot_manifest_path,
        snapshot_path=target.snapshot_path,
        catalog_path=target.catalog_path,
        source_lock_path=target.source_lock_path,
    )
    if profile.sha256 != target.expected_profile_sha256:
        _fail(
            "base-engine serving profile",
            "does not match the trusted expected SHA-256",
        )
    return profile


def _runtime_public_key_identity(
    config: BaseEngineWrapperConfig,
) -> tuple[Any, str]:
    public_key, public_key_spki_sha256 = _load_public_key(
        config.runtime_signing.public_key_path
    )
    if public_key_spki_sha256 != config.runtime_signing.public_key_spki_sha256:
        _fail(
            "base-engine runtime signing public key",
            "changed after the wrapper configuration was loaded",
        )
    return public_key, public_key_spki_sha256


def _activation_model(profile: BaseEvaluationProfile) -> dict[str, str]:
    snapshot = profile.document["baseModelSnapshot"]
    base_model = profile.document["baseModel"]
    return {
        "candidateCatalogSha256": profile.document["candidateCatalogSha256"],
        "candidateId": profile.document["candidateId"],
        "modelId": base_model["modelId"],
        "modelRevision": base_model["revision"],
        "servingProfileSha256": profile.sha256,
        "executionModelId": profile.execution_model_id,
        "sourceLockSha256": snapshot["sourceLockSha256"],
        "snapshotManifestSha256": snapshot["manifestSha256"],
        "snapshotSha256": snapshot["snapshotSha256"],
        "fileTreeSha256": snapshot["fileTreeSha256"],
    }


def _activation_engine(
    config: BaseEngineWrapperConfig, profile: BaseEvaluationProfile
) -> dict[str, str]:
    runtime = profile.document["runtime"]
    if runtime["engineVersion"] not in _SUPPORTED_VLLM_ENGINE_VERSIONS:
        _fail(
            "base-engine version",
            "has no reviewed exact argv adapter; supported versions are 0.10.0 and 0.26.0",
        )
    executable_sha256 = sha256_file(config.engine.executable_path)
    if executable_sha256 != config.engine.executable_sha256:
        _fail("base-engine executable", "does not match its configured SHA-256")
    return {
        "executableSha256": executable_sha256,
        "engineVersion": runtime["engineVersion"],
        "containerImageDigest": runtime["containerImageDigest"],
    }


def _validate_activation_payload(value: Any) -> dict[str, Any]:
    payload = _exact_object(
        value,
        {
            "schemaVersion",
            "activationId",
            "decision",
            "audience",
            "keyId",
            "signerRole",
            "wrapperConfigSha256",
            "wrapperPackageSha256",
            "runtimeSigner",
            "model",
            "engine",
            "issuedAtUtc",
            "notBeforeUtc",
            "expiresAtUtc",
        },
        "base-engine activation payload",
    )
    if payload["schemaVersion"] != BASE_ENGINE_ACTIVATION_SCHEMA_VERSION:
        _fail(
            "base-engine activation payload.schemaVersion",
            f"must be {BASE_ENGINE_ACTIVATION_SCHEMA_VERSION!r}",
        )
    if (
        not isinstance(payload["activationId"], str)
        or _ACTIVATION_ID_RE.fullmatch(payload["activationId"]) is None
    ):
        _fail(
            "base-engine activation payload.activationId",
            "must be a content-addressed activation ID",
        )
    if payload["decision"] != "approved-for-base-evaluation":
        _fail(
            "base-engine activation payload.decision",
            "must be 'approved-for-base-evaluation'",
        )
    _safe_id(payload["audience"], "base-engine activation payload.audience")
    _safe_id(payload["keyId"], "base-engine activation payload.keyId")
    _safe_id(payload["signerRole"], "base-engine activation payload.signerRole")
    _sha256(
        payload["wrapperConfigSha256"],
        "base-engine activation payload.wrapperConfigSha256",
    )
    _sha256(
        payload["wrapperPackageSha256"],
        "base-engine activation payload.wrapperPackageSha256",
    )
    runtime_signer = _exact_object(
        payload["runtimeSigner"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "base-engine activation payload.runtimeSigner",
    )
    _sha256(
        runtime_signer["publicKeySpkiSha256"],
        "base-engine activation payload.runtimeSigner.publicKeySpkiSha256",
    )
    _safe_id(
        runtime_signer["audience"],
        "base-engine activation payload.runtimeSigner.audience",
    )
    _safe_id(
        runtime_signer["keyId"], "base-engine activation payload.runtimeSigner.keyId"
    )
    _safe_id(
        runtime_signer["signerRole"],
        "base-engine activation payload.runtimeSigner.signerRole",
    )
    if (
        payload["keyId"] == runtime_signer["keyId"]
        or payload["signerRole"] == runtime_signer["signerRole"]
    ):
        _fail(
            "base-engine activation payload signer separation",
            "activation and runtime-attestation key IDs and roles must be distinct",
        )
    model = _exact_object(
        payload["model"],
        {
            "candidateCatalogSha256",
            "candidateId",
            "modelId",
            "modelRevision",
            "servingProfileSha256",
            "executionModelId",
            "sourceLockSha256",
            "snapshotManifestSha256",
            "snapshotSha256",
            "fileTreeSha256",
        },
        "base-engine activation payload.model",
    )
    for name in (
        "candidateCatalogSha256",
        "servingProfileSha256",
        "sourceLockSha256",
        "snapshotManifestSha256",
        "snapshotSha256",
        "fileTreeSha256",
    ):
        _sha256(model[name], f"base-engine activation payload.model.{name}")
    _safe_id(
        model["candidateId"],
        "base-engine activation payload.model.candidateId",
    )
    _text(
        model["modelId"],
        "base-engine activation payload.model.modelId",
        maximum=500,
    )
    if (
        not isinstance(model["modelRevision"], str)
        or _REVISION_RE.fullmatch(model["modelRevision"]) is None
    ):
        _fail(
            "base-engine activation payload.model.modelRevision",
            "must be a lowercase 40-character commit SHA",
        )
    _safe_id(
        model["executionModelId"],
        "base-engine activation payload.model.executionModelId",
    )
    engine = _exact_object(
        payload["engine"],
        {"executableSha256", "engineVersion", "containerImageDigest"},
        "base-engine activation payload.engine",
    )
    _sha256(
        engine["executableSha256"],
        "base-engine activation payload.engine.executableSha256",
    )
    _text(
        engine["engineVersion"],
        "base-engine activation payload.engine.engineVersion",
        maximum=100,
    )
    if (
        not isinstance(engine["containerImageDigest"], str)
        or _OCI_DIGEST_RE.fullmatch(engine["containerImageDigest"]) is None
    ):
        _fail(
            "base-engine activation payload.engine.containerImageDigest",
            "must be a lowercase sha256 OCI digest",
        )
    issued = _canonical_utc(
        payload["issuedAtUtc"], "base-engine activation payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "base-engine activation payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "base-engine activation payload.expiresAtUtc"
    )
    if issued > not_before or not_before >= expires:
        _fail(
            "base-engine activation payload validity",
            "must satisfy issuedAtUtc <= notBeforeUtc < expiresAtUtc",
        )
    if expires - not_before > MAX_ACTIVATION_VALIDITY:
        _fail(
            "base-engine activation payload validity",
            "must not exceed seven days",
        )
    identity_document = dict(payload)
    identity_document["activationId"] = _ACTIVATION_ID_PREFIX + _ZERO_SHA256
    expected_id = _ACTIVATION_ID_PREFIX + _domain_sha256(
        BASE_ACTIVATION_ID_DOMAIN, identity_document
    )
    if payload["activationId"] != expected_id:
        _fail(
            "base-engine activation payload.activationId",
            "does not match the canonical activation payload",
        )
    return payload


def _build_base_engine_activation_payload(
    *,
    config_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    audience: str,
    key_id: str,
    signer_role: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    package_root: str | os.PathLike[str] | None = None,
) -> tuple[
    BaseEngineWrapperConfig,
    dict[str, Any],
    Any,
    str,
    datetime,
    datetime,
    datetime,
]:
    config = load_base_engine_wrapper_config(config_path)
    trust = config.activation.trust
    supplied_audience = _safe_id(audience, "base-engine activation audience")
    supplied_key_id = _safe_id(key_id, "base-engine activation keyId")
    supplied_signer_role = _safe_id(signer_role, "base-engine activation signerRole")
    if (
        supplied_audience != trust.audience
        or supplied_key_id != trust.key_id
        or supplied_signer_role != trust.signer_role
    ):
        _fail(
            "base-engine activation trust",
            "does not match the wrapper config",
        )
    public_key, public_key_spki_sha256 = _load_public_key(public_key_path)
    if (
        Path(os.path.abspath(os.fspath(public_key_path))) != trust.public_key_path
        or public_key_spki_sha256 != trust.public_key_spki_sha256
    ):
        _fail(
            "base-engine activation public key",
            "does not match the pinned wrapper trust",
        )
    issued = _canonical_utc(issued_at_utc, "base-engine activation issuedAtUtc")
    not_before = _canonical_utc(not_before_utc, "base-engine activation notBeforeUtc")
    expires = _canonical_utc(expires_at_utc, "base-engine activation expiresAtUtc")
    if (
        issued > not_before
        or not_before >= expires
        or expires - not_before > MAX_ACTIVATION_VALIDITY
    ):
        _fail(
            "base-engine activation validity",
            "must satisfy issued <= not-before < expiry within seven days",
        )
    profile = _validated_target(config)
    _, runtime_spki = _runtime_public_key_identity(config)
    payload: dict[str, Any] = {
        "schemaVersion": BASE_ENGINE_ACTIVATION_SCHEMA_VERSION,
        "activationId": _ACTIVATION_ID_PREFIX + _ZERO_SHA256,
        "decision": "approved-for-base-evaluation",
        "audience": supplied_audience,
        "keyId": supplied_key_id,
        "signerRole": supplied_signer_role,
        "wrapperConfigSha256": config.sha256,
        "wrapperPackageSha256": base_wrapper_package_sha256(package_root),
        "runtimeSigner": {
            "publicKeySpkiSha256": runtime_spki,
            "audience": config.runtime_signing.audience,
            "keyId": config.runtime_signing.key_id,
            "signerRole": config.runtime_signing.signer_role,
        },
        "model": _activation_model(profile),
        "engine": _activation_engine(config, profile),
        "issuedAtUtc": _utc_second(issued),
        "notBeforeUtc": _utc_second(not_before),
        "expiresAtUtc": _utc_second(expires),
    }
    payload["activationId"] = _ACTIVATION_ID_PREFIX + _domain_sha256(
        BASE_ACTIVATION_ID_DOMAIN, payload
    )
    _validate_activation_payload(payload)
    return (
        config,
        payload,
        public_key,
        public_key_spki_sha256,
        issued,
        not_before,
        expires,
    )


def _activation_destination(
    config: BaseEngineWrapperConfig, output_path: str | os.PathLike[str]
) -> Path:
    destination = Path(os.path.abspath(os.fspath(output_path)))
    if destination != config.activation.path:
        _fail(
            "base-engine activation output",
            "must exactly match the activation path in the wrapper config",
        )
    return destination


def _serialize_activation_envelope(envelope: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(envelope, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    ).encode("utf-8", errors="strict")


def _publish_base_engine_activation(
    *,
    config: BaseEngineWrapperConfig,
    output_path: str | os.PathLike[str],
    envelope: Mapping[str, Any],
    expected_payload: Mapping[str, Any],
    package_root: str | os.PathLike[str] | None,
    now: datetime | None,
    fixed_validation_time: datetime | None = None,
    field: str,
) -> VerifiedBaseEngineActivation:
    destination = _activation_destination(config, output_path)
    serialized = _serialize_activation_envelope(envelope)
    expected_envelope_sha256 = hashlib.sha256(
        canonical_json_bytes(envelope)
    ).hexdigest()

    def reload_config(stage: str) -> BaseEngineWrapperConfig:
        live_config = load_base_engine_wrapper_config(config.path)
        if live_config.sha256 != config.sha256 or live_config != config:
            _fail(field, f"wrapper config changed {stage} publication validation")
        return live_config

    def validate(path: Path, expected_link_count: int) -> VerifiedBaseEngineActivation:
        live_config = reload_config("before")
        current = (
            _validation_time(fixed_validation_time, f"{field} validation time")
            if fixed_validation_time is not None
            else _fresh_validation_time(now, f"{field} validation time")
        )
        verified = _verify_base_engine_activation_path(
            activation_path=path,
            config=live_config,
            trust=live_config.activation.trust,
            now=current,
            package_root=package_root,
            expected_link_count=expected_link_count,
        )
        if (
            verified.payload != dict(expected_payload)
            or verified.envelope_sha256 != expected_envelope_sha256
        ):
            _fail(field, "changed during publication")
        reload_config("during")
        post_replay_time = (
            _validation_time(
                fixed_validation_time,
                f"{field} post-replay validation time",
            )
            if fixed_validation_time is not None
            else _fresh_validation_time(now, f"{field} post-replay validation time")
        )
        _ensure_activation_payload_active(
            verified.payload,
            post_replay_time,
            field,
        )
        return verified

    return _write_no_clobber(
        destination,
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field=field,
    )


def create_base_engine_activation(
    *,
    config_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    private_key_password: bytes | None,
    audience: str,
    key_id: str,
    signer_role: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    package_root: str | os.PathLike[str] | None = None,
) -> VerifiedBaseEngineActivation:
    (
        config,
        payload,
        _,
        public_key_spki_sha256,
        _,
        not_before,
        _,
    ) = _build_base_engine_activation_payload(
        config_path=config_path,
        public_key_path=public_key_path,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        package_root=package_root,
    )
    private_key, private_key_spki_sha256 = _load_private_key(
        private_key_path, private_key_password
    )
    if public_key_spki_sha256 != private_key_spki_sha256:
        _fail("base-engine activation key", "private and public keys do not match")
    envelope = _new_envelope(
        schema_version=BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION,
        signature_domain=BASE_ACTIVATION_SIGNATURE_DOMAIN,
        payload=payload,
        private_key=private_key,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    return _publish_base_engine_activation(
        config=config,
        output_path=output_path,
        envelope=envelope,
        expected_payload=payload,
        package_root=package_root,
        now=None,
        fixed_validation_time=not_before,
        field="base-engine activation output",
    )


def _ensure_activation_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> None:
    not_before = _canonical_utc(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "must be active")


def _build_base_engine_activation_signing_bundle_document(
    payload: Mapping[str, Any], *, public_key_spki_sha256: str
) -> dict[str, Any]:
    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_BASE_ENGINE_ACTIVATION_BYTES:
        _fail("base-engine activation payload", "exceeds its byte limit")
    unsigned_envelope, rebuilt_payload_bytes = _new_unsigned_envelope(
        schema_version=BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION,
        payload=payload,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if rebuilt_payload_bytes != payload_bytes:
        _fail("base-engine activation payload", "changed during bundle construction")
    unsigned_envelope_bytes = canonical_json_bytes(unsigned_envelope)
    if len(unsigned_envelope_bytes) > MAX_BASE_ENGINE_ACTIVATION_BYTES:
        _fail("base-engine activation unsigned envelope", "exceeds its byte limit")
    signature_preimage = _signature_input(
        BASE_ACTIVATION_SIGNATURE_DOMAIN,
        unsigned_envelope,
        payload_bytes,
    )
    if len(signature_preimage) > MAX_BASE_ENGINE_ACTIVATION_SIGNATURE_INPUT_BYTES:
        _fail("base-engine activation signature preimage", "exceeds its byte limit")
    signature_digest = hashlib.sha256(signature_preimage).digest()
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    unsigned_envelope_sha256 = hashlib.sha256(unsigned_envelope_bytes).hexdigest()
    bundle: dict[str, Any] = {
        "schemaVersion": BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": _ACTIVATION_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": _ACTIVATION_SIGNING_STATUS,
        "authority": {
            name: False for name in sorted(_ACTIVATION_SIGNING_AUTHORITY_KEYS)
        },
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": payload["audience"],
            "keyId": payload["keyId"],
            "signerRole": payload["signerRole"],
        },
        "activationId": payload["activationId"],
        "payloadSha256": payload_sha256,
        "payload": _base64url_encode(payload_bytes),
        "unsignedEnvelopeSha256": unsigned_envelope_sha256,
        "unsignedEnvelope": _base64url_encode(unsigned_envelope_bytes),
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
        "signatureContract": {
            "algorithm": _ALGORITHM,
            "hashAlgorithm": _ACTIVATION_SIGNING_HASH_ALGORITHM,
            "inputEncoding": "base64url",
            "acceptedModes": [
                _ACTIVATION_EXTERNAL_RAW_MESSAGE_MODE,
                _ACTIVATION_EXTERNAL_SHA256_DIGEST_MODE,
            ],
            "acceptedSignatureFormats": [
                _ACTIVATION_EXTERNAL_DER_SIGNATURE_FORMAT,
                _ACTIVATION_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "activationId": payload["activationId"],
            "payloadSha256": payload_sha256,
            "unsignedEnvelopeSha256": unsigned_envelope_sha256,
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = base_engine_activation_signing_bundle_id(bundle)
    return bundle


def _validate_base_engine_activation_signing_bundle_document(
    value: Mapping[str, Any],
    *,
    path: Path,
    bundle_sha256: str,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    now: datetime,
) -> VerifiedBaseEngineActivationSigningBundle:
    bundle = _exact_object(
        dict(value),
        _ACTIVATION_SIGNING_BUNDLE_KEYS,
        "base-engine activation signing bundle",
    )
    bundle_bytes = canonical_json_bytes(bundle)
    if len(bundle_bytes) + 1 > MAX_BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_BYTES:
        _fail("base-engine activation signing bundle", "exceeds its byte limit")
    if bundle["schemaVersion"] != BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("base-engine activation signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != _ACTIVATION_SIGNING_STATUS:
        _fail(
            "base-engine activation signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority = _exact_object(
        bundle["authority"],
        _ACTIVATION_SIGNING_AUTHORITY_KEYS,
        "base-engine activation signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"base-engine activation signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )
    expected_trust = {
        "publicKeySpkiSha256": _sha256(
            public_key_spki_sha256,
            "base-engine activation signing bundle expected public-key SPKI SHA-256",
        ),
        "audience": _safe_id(
            audience, "base-engine activation signing bundle expected audience"
        ),
        "keyId": _safe_id(
            key_id, "base-engine activation signing bundle expected keyId"
        ),
        "signerRole": _safe_id(
            signer_role, "base-engine activation signing bundle expected signerRole"
        ),
    }
    trust = _exact_object(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "base-engine activation signing bundle.trust",
    )
    if trust != expected_trust:
        _fail(
            "base-engine activation signing bundle.trust",
            "does not match externally pinned trust",
        )
    expected_contract = {
        "algorithm": _ALGORITHM,
        "hashAlgorithm": _ACTIVATION_SIGNING_HASH_ALGORITHM,
        "inputEncoding": "base64url",
        "acceptedModes": [
            _ACTIVATION_EXTERNAL_RAW_MESSAGE_MODE,
            _ACTIVATION_EXTERNAL_SHA256_DIGEST_MODE,
        ],
        "acceptedSignatureFormats": [
            _ACTIVATION_EXTERNAL_DER_SIGNATURE_FORMAT,
            _ACTIVATION_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    contract = _exact_object(
        bundle["signatureContract"],
        set(expected_contract),
        "base-engine activation signing bundle.signatureContract",
    )
    if contract != expected_contract:
        _fail(
            "base-engine activation signing bundle.signatureContract",
            "does not match the external-signing contract",
        )
    payload_bytes = _base64url_decode(
        bundle["payload"],
        "base-engine activation signing bundle.payload",
        max_bytes=MAX_BASE_ENGINE_ACTIVATION_BYTES,
    )
    payload_value = _parse_json_bytes(
        payload_bytes, "base-engine activation signing bundle payload"
    )
    if not isinstance(payload_value, dict) or canonical_json_bytes(payload_value) != (
        payload_bytes
    ):
        _fail(
            "base-engine activation signing bundle payload",
            "must contain canonical JSON object bytes",
        )
    payload = _validate_activation_payload(payload_value)
    if payload["runtimeSigner"]["publicKeySpkiSha256"] == public_key_spki_sha256:
        _fail(
            "base-engine activation signing bundle signer separation",
            "activation and runtime-attestation keys must be distinct",
        )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            bundle["payloadSha256"],
            "base-engine activation signing bundle.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "base-engine activation signing bundle.payloadSha256",
            "does not match exact payload bytes",
        )
    unsigned_envelope_bytes = _base64url_decode(
        bundle["unsignedEnvelope"],
        "base-engine activation signing bundle.unsignedEnvelope",
        max_bytes=MAX_BASE_ENGINE_ACTIVATION_BYTES,
    )
    unsigned_value = _parse_json_bytes(
        unsigned_envelope_bytes,
        "base-engine activation signing bundle unsigned envelope",
    )
    if not isinstance(unsigned_value, dict) or canonical_json_bytes(unsigned_value) != (
        unsigned_envelope_bytes
    ):
        _fail(
            "base-engine activation signing bundle unsigned envelope",
            "must contain canonical JSON object bytes",
        )
    expected_envelope, rebuilt_payload_bytes = _new_unsigned_envelope(
        schema_version=BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION,
        payload=payload,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if rebuilt_payload_bytes != payload_bytes or unsigned_value != expected_envelope:
        _fail(
            "base-engine activation signing bundle.unsignedEnvelope",
            "does not match the exact unsigned activation envelope",
        )
    unsigned_envelope_sha256 = hashlib.sha256(unsigned_envelope_bytes).hexdigest()
    if (
        _sha256(
            bundle["unsignedEnvelopeSha256"],
            "base-engine activation signing bundle.unsignedEnvelopeSha256",
        )
        != unsigned_envelope_sha256
    ):
        _fail(
            "base-engine activation signing bundle.unsignedEnvelopeSha256",
            "does not match exact unsigned envelope bytes",
        )
    expected_payload_bindings = {
        "activationId": payload["activationId"],
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
    }
    for name, expected in expected_payload_bindings.items():
        if bundle[name] != expected:
            _fail(
                f"base-engine activation signing bundle.{name}",
                "does not match the exact activation payload",
            )
    request = _exact_object(
        bundle["request"],
        {
            "activationId",
            "payloadSha256",
            "unsignedEnvelopeSha256",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "base-engine activation signing bundle.request",
    )
    expected_request_bindings = {
        "activationId": payload["activationId"],
        "payloadSha256": payload_sha256,
        "unsignedEnvelopeSha256": unsigned_envelope_sha256,
    }
    for name, expected in expected_request_bindings.items():
        if request[name] != expected:
            _fail(
                f"base-engine activation signing bundle.request.{name}",
                "does not match the exact signing bundle",
            )
    signature_preimage = _signature_input(
        BASE_ACTIVATION_SIGNATURE_DOMAIN,
        expected_envelope,
        payload_bytes,
    )
    supplied_preimage = _base64url_decode(
        request["signaturePreimage"],
        "base-engine activation signing bundle.request.signaturePreimage",
        max_bytes=MAX_BASE_ENGINE_ACTIVATION_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != signature_preimage:
        _fail(
            "base-engine activation signing bundle.request.signaturePreimage",
            "does not match the exact activation signature preimage",
        )
    signature_digest = hashlib.sha256(signature_preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "base-engine activation signing bundle.request.signatureInput",
        exact_bytes=32,
    )
    if supplied_digest != signature_digest:
        _fail(
            "base-engine activation signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "base-engine activation signing bundle.request.signatureInputSha256",
        )
        != signature_digest.hex()
    ):
        _fail(
            "base-engine activation signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or _ACTIVATION_SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id) is None
        or bundle_id != base_engine_activation_signing_bundle_id(bundle)
    ):
        _fail(
            "base-engine activation signing bundle.bundleId",
            "does not match the content-derived identity",
        )
    _ensure_activation_payload_active(
        payload, now, "base-engine activation signing bundle payload"
    )
    return VerifiedBaseEngineActivationSigningBundle(
        path=path,
        bundle=bundle,
        bundle_sha256=_sha256(
            bundle_sha256, "base-engine activation signing bundle SHA-256"
        ),
        bundle_id=bundle_id,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        unsigned_envelope=expected_envelope,
        unsigned_envelope_bytes=unsigned_envelope_bytes,
        unsigned_envelope_sha256=unsigned_envelope_sha256,
        signature_preimage=signature_preimage,
        signature_input_sha256=signature_digest.hex(),
        public_key_spki_sha256=public_key_spki_sha256,
    )


def _read_unreplayed_base_engine_activation_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    now: datetime | None,
    expected_link_count: int,
) -> tuple[VerifiedBaseEngineActivationSigningBundle, Any]:
    public_key, public_key_spki_sha256 = _load_public_key(public_key_path)
    resolved, raw, document = _read_canonical_handoff_document(
        signing_bundle_path,
        "base-engine activation signing bundle",
        MAX_BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_BYTES,
        expected_link_count=expected_link_count,
    )
    verified = _validate_base_engine_activation_signing_bundle_document(
        document,
        path=resolved,
        bundle_sha256=hashlib.sha256(raw).hexdigest(),
        public_key_spki_sha256=public_key_spki_sha256,
        audience=expected_audience,
        key_id=expected_key_id,
        signer_role=expected_signer_role,
        now=_fresh_validation_time(
            now, "base-engine activation signing-bundle verification time"
        ),
    )
    return verified, public_key


def _verify_base_engine_activation_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    config_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    package_root: str | os.PathLike[str] | None,
    now: datetime | None,
    expected_link_count: int,
) -> VerifiedBaseEngineActivationSigningBundle:
    verified, _ = _read_unreplayed_base_engine_activation_signing_bundle(
        signing_bundle_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        now=now,
        expected_link_count=expected_link_count,
    )
    payload = verified.payload
    (
        _,
        expected_payload,
        _,
        public_key_spki_sha256,
        _,
        _,
        _,
    ) = _build_base_engine_activation_payload(
        config_path=config_path,
        public_key_path=public_key_path,
        audience=expected_audience,
        key_id=expected_key_id,
        signer_role=expected_signer_role,
        issued_at_utc=payload["issuedAtUtc"],
        not_before_utc=payload["notBeforeUtc"],
        expires_at_utc=payload["expiresAtUtc"],
        package_root=package_root,
    )
    if expected_payload != payload or public_key_spki_sha256 != (
        verified.public_key_spki_sha256
    ):
        _fail(
            "base-engine activation signing bundle payload",
            "does not match freshly replayed wrapper bindings",
        )
    _ensure_activation_payload_active(
        payload,
        _fresh_validation_time(
            now, "base-engine activation signing-bundle post-replay time"
        ),
        "base-engine activation signing bundle payload",
    )
    return verified


def verify_base_engine_activation_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    config_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    package_root: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> VerifiedBaseEngineActivationSigningBundle:
    return _verify_base_engine_activation_signing_bundle(
        signing_bundle_path,
        config_path=config_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        package_root=package_root,
        now=now,
        expected_link_count=1,
    )


def prepare_base_engine_activation_signing_bundle(
    *,
    config_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    audience: str,
    key_id: str,
    signer_role: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    package_root: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> VerifiedBaseEngineActivationSigningBundle:
    (
        config,
        payload,
        _,
        public_key_spki_sha256,
        _,
        _,
        _,
    ) = _build_base_engine_activation_payload(
        config_path=config_path,
        public_key_path=public_key_path,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        package_root=package_root,
    )
    current = _fresh_validation_time(
        now, "base-engine activation signing-bundle creation time"
    )
    _ensure_activation_payload_active(
        payload, current, "base-engine activation signing bundle payload"
    )
    destination = Path(os.path.abspath(os.fspath(output_path)))
    if destination == config.activation.path:
        _fail(
            "base-engine activation signing-bundle output",
            "must differ from the final activation path",
        )
    bundle = _build_base_engine_activation_signing_bundle_document(
        payload, public_key_spki_sha256=public_key_spki_sha256
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_BASE_ENGINE_ACTIVATION_SIGNING_BUNDLE_BYTES:
        _fail("base-engine activation signing bundle", "exceeds its byte limit")
    expected_sha256 = hashlib.sha256(serialized).hexdigest()

    def validate(
        path: Path, expected_link_count: int
    ) -> VerifiedBaseEngineActivationSigningBundle:
        verified = _verify_base_engine_activation_signing_bundle(
            path,
            config_path=config_path,
            public_key_path=public_key_path,
            expected_audience=audience,
            expected_key_id=key_id,
            expected_signer_role=signer_role,
            package_root=package_root,
            now=now,
            expected_link_count=expected_link_count,
        )
        if (
            verified.bundle_sha256 != expected_sha256
            or verified.bundle != bundle
            or verified.payload != payload
        ):
            _fail(
                "base-engine activation signing-bundle output",
                "changed during publication",
            )
        return verified

    return _write_no_clobber(
        destination,
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field="base-engine activation signing-bundle output",
    )


def _validate_base_engine_activation_external_signature_document(
    value: Mapping[str, Any],
    *,
    signing_bundle: VerifiedBaseEngineActivationSigningBundle,
    public_key: Any,
) -> bytes:
    document = _exact_object(
        dict(value),
        _ACTIVATION_EXTERNAL_SIGNATURE_KEYS,
        "base-engine activation external signature",
    )
    if (
        len(canonical_json_bytes(document)) + 1
        > MAX_BASE_ENGINE_ACTIVATION_EXTERNAL_SIGNATURE_BYTES
    ):
        _fail("base-engine activation external signature", "exceeds its byte limit")
    if document["schemaVersion"] != BASE_ENGINE_ACTIVATION_SIGNATURE_SCHEMA_VERSION:
        _fail(
            "base-engine activation external signature.schemaVersion", "is unsupported"
        )
    expected = {
        "signingBundleId": signing_bundle.bundle_id,
        "signingBundleSha256": signing_bundle.bundle_sha256,
        "activationId": signing_bundle.payload["activationId"],
        "payloadSha256": signing_bundle.payload_sha256,
        "unsignedEnvelopeSha256": signing_bundle.unsigned_envelope_sha256,
        "signatureInputSha256": signing_bundle.signature_input_sha256,
        "publicKeySpkiSha256": signing_bundle.public_key_spki_sha256,
    }
    for name, expected_value in expected.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"base-engine activation external signature.{name}")
        if supplied != expected_value:
            _fail(
                f"base-engine activation external signature.{name}",
                "does not match the exact signing bundle",
            )
    signature_digest = _base64url_decode(
        signing_bundle.bundle["request"]["signatureInput"],
        "base-engine activation signing bundle.request.signatureInput",
        exact_bytes=32,
    )
    normalized = _normalize_detached_external_signature(
        document["signature"],
        signature_format=document["format"],
        signature_mode=document["mode"],
        public_key=public_key,
        signature_preimage=signing_bundle.signature_preimage,
        signature_digest=signature_digest,
        field="base-engine activation external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or _ACTIVATION_EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id) is None
        or signature_id != base_engine_activation_external_signature_id(document)
    ):
        _fail(
            "base-engine activation external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def finalize_base_engine_activation(
    *,
    config_path: str | os.PathLike[str],
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    package_root: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> VerifiedBaseEngineActivation:
    preflight_bundle, public_key = (
        _read_unreplayed_base_engine_activation_signing_bundle(
            signing_bundle_path,
            public_key_path=public_key_path,
            expected_audience=expected_audience,
            expected_key_id=expected_key_id,
            expected_signer_role=expected_signer_role,
            now=now,
            expected_link_count=1,
        )
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "base-engine activation external signature",
        MAX_BASE_ENGINE_ACTIVATION_EXTERNAL_SIGNATURE_BYTES,
    )
    normalized_signature = _validate_base_engine_activation_external_signature_document(
        signature_document,
        signing_bundle=preflight_bundle,
        public_key=public_key,
    )
    verified_bundle = _verify_base_engine_activation_signing_bundle(
        signing_bundle_path,
        config_path=config_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        package_root=package_root,
        now=now,
        expected_link_count=1,
    )
    if (
        verified_bundle.bundle_sha256 != preflight_bundle.bundle_sha256
        or verified_bundle.bundle_id != preflight_bundle.bundle_id
        or verified_bundle.payload_bytes != preflight_bundle.payload_bytes
    ):
        _fail(
            "base-engine activation signing bundle",
            "changed while the activation was finalized",
        )
    payload = verified_bundle.payload
    (
        config,
        live_payload,
        _,
        public_key_spki_sha256,
        _,
        _,
        _,
    ) = _build_base_engine_activation_payload(
        config_path=config_path,
        public_key_path=public_key_path,
        audience=expected_audience,
        key_id=expected_key_id,
        signer_role=expected_signer_role,
        issued_at_utc=payload["issuedAtUtc"],
        not_before_utc=payload["notBeforeUtc"],
        expires_at_utc=payload["expiresAtUtc"],
        package_root=package_root,
    )
    if (
        live_payload != payload
        or canonical_json_bytes(live_payload) != verified_bundle.payload_bytes
        or public_key_spki_sha256 != verified_bundle.public_key_spki_sha256
    ):
        _fail(
            "base-engine activation signing bundle payload",
            "live bindings changed while the activation was finalized",
        )
    current = _fresh_validation_time(now, "base-engine activation finalization time")
    _ensure_activation_payload_active(
        live_payload, current, "base-engine activation payload"
    )
    envelope, rebuilt_payload_bytes = _new_unsigned_envelope(
        schema_version=BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION,
        payload=live_payload,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if (
        rebuilt_payload_bytes != verified_bundle.payload_bytes
        or envelope != verified_bundle.unsigned_envelope
    ):
        _fail(
            "base-engine activation signing bundle unsigned envelope",
            "changed while the activation was finalized",
        )
    envelope["signature"] = _base64url_encode(normalized_signature)
    verified_envelope = verify_base_engine_activation_envelope(
        envelope=envelope,
        trust=config.activation.trust,
        now=current,
    )
    if verified_envelope.payload != live_payload:
        _fail("base-engine activation", "changed before publication")
    return _publish_base_engine_activation(
        config=config,
        output_path=output_path,
        envelope=envelope,
        expected_payload=live_payload,
        package_root=package_root,
        now=now,
        field="base-engine activation finalization output",
    )


def verify_base_engine_activation_envelope(
    *,
    envelope: Any,
    trust: BaseEngineActivationTrust,
    now: datetime,
) -> VerifiedBaseEngineActivation:
    verified_envelope, payload, payload_bytes, envelope_sha256 = _verify_envelope(
        envelope,
        field="base-engine activation envelope",
        schema_version=BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION,
        signature_domain=BASE_ACTIVATION_SIGNATURE_DOMAIN,
        public_key_path=trust.public_key_path,
        expected_public_key_spki_sha256=trust.public_key_spki_sha256,
    )
    payload = _validate_activation_payload(payload)
    if (
        verified_envelope["publicKeySpkiSha256"]
        == payload["runtimeSigner"]["publicKeySpkiSha256"]
    ):
        _fail(
            "base-engine activation envelope signer separation",
            "activation and runtime-attestation keys must be distinct",
        )
    if (
        payload["audience"] != trust.audience
        or payload["keyId"] != trust.key_id
        or payload["signerRole"] != trust.signer_role
    ):
        _fail("base-engine activation envelope", "does not match pinned signer trust")
    current = _validation_time(now, "base-engine activation validation time")
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "base-engine activation payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "base-engine activation payload.expiresAtUtc"
    )
    if current < not_before or current >= expires:
        _fail("base-engine activation", "is not currently valid")
    return VerifiedBaseEngineActivation(
        path=None,
        envelope=verified_envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        envelope_sha256=envelope_sha256,
    )


def _verify_base_engine_activation_path(
    *,
    activation_path: str | os.PathLike[str],
    config: BaseEngineWrapperConfig,
    trust: BaseEngineActivationTrust,
    now: datetime,
    package_root: str | os.PathLike[str] | None = None,
    expected_link_count: int,
) -> VerifiedBaseEngineActivation:
    path = Path(os.path.abspath(os.fspath(activation_path)))
    raw = _bounded_snapshot(
        path,
        "base-engine activation",
        MAX_BASE_ENGINE_ACTIVATION_BYTES,
        expected_link_count=expected_link_count,
    )
    value = _parse_json_bytes(raw, "base-engine activation")
    verified = verify_base_engine_activation_envelope(
        envelope=value,
        trust=trust,
        now=now,
    )
    payload = verified.payload
    profile = _validated_target(config)
    _, runtime_spki = _runtime_public_key_identity(config)
    expected_bindings = {
        "wrapperConfigSha256": config.sha256,
        "wrapperPackageSha256": base_wrapper_package_sha256(package_root),
        "runtimeSigner": {
            "publicKeySpkiSha256": runtime_spki,
            "audience": config.runtime_signing.audience,
            "keyId": config.runtime_signing.key_id,
            "signerRole": config.runtime_signing.signer_role,
        },
        "model": _activation_model(profile),
        "engine": _activation_engine(config, profile),
    }
    for name, expected in expected_bindings.items():
        if payload[name] != expected:
            _fail(
                f"base-engine activation payload.{name}",
                "does not match the live wrapper target",
            )
    final_raw = _bounded_snapshot(
        path,
        "base-engine activation",
        MAX_BASE_ENGINE_ACTIVATION_BYTES,
        expected_link_count=expected_link_count,
    )
    if final_raw != raw:
        _fail("base-engine activation", "changed while it was verified")
    return replace(verified, path=path)


def verify_base_engine_activation(
    *,
    activation_path: str | os.PathLike[str],
    config: BaseEngineWrapperConfig,
    trust: BaseEngineActivationTrust,
    now: datetime,
    package_root: str | os.PathLike[str] | None = None,
) -> VerifiedBaseEngineActivation:
    return _verify_base_engine_activation_path(
        activation_path=activation_path,
        config=config,
        trust=trust,
        now=now,
        package_root=package_root,
        expected_link_count=1,
    )


def _validate_evaluation_binding(value: Any, field: str) -> dict[str, Any]:
    binding = _exact_object(
        value,
        {
            "runId",
            "taskId",
            "taskSha256",
            "promptSha256",
            "dataRelease",
        },
        field,
    )
    _safe_id(binding["runId"], f"{field}.runId")
    _safe_id(binding["taskId"], f"{field}.taskId")
    _sha256(binding["taskSha256"], f"{field}.taskSha256")
    _sha256(binding["promptSha256"], f"{field}.promptSha256")
    release = _validate_data_release_identity(
        binding["dataRelease"], f"{field}.dataRelease"
    )
    if release is None:
        _fail(f"{field}.dataRelease", "must bind a release for attested capture")
    return binding


def _validate_runtime_attestation_payload(value: Any) -> dict[str, Any]:
    payload = _exact_object(
        value,
        {
            "schemaVersion",
            "attestationId",
            "decision",
            "audience",
            "keyId",
            "signerRole",
            "activation",
            "wrapperInstanceId",
            "sequence",
            "nonce",
            "evaluation",
            "requestSha256",
            "completionSha256",
            "model",
            "engine",
            "issuedAtUtc",
            "expiresAtUtc",
        },
        "base-runtime attestation payload",
    )
    if payload["schemaVersion"] != BASE_RUNTIME_ATTESTATION_SCHEMA_VERSION:
        _fail(
            "base-runtime attestation payload.schemaVersion",
            f"must be {BASE_RUNTIME_ATTESTATION_SCHEMA_VERSION!r}",
        )
    if (
        not isinstance(payload["attestationId"], str)
        or _ATTESTATION_ID_RE.fullmatch(payload["attestationId"]) is None
    ):
        _fail(
            "base-runtime attestation payload.attestationId",
            "must be a content-addressed attestation ID",
        )
    if payload["decision"] != "attested-base-completion":
        _fail(
            "base-runtime attestation payload.decision",
            "must be 'attested-base-completion'",
        )
    for name in ("audience", "keyId", "signerRole"):
        _safe_id(payload[name], f"base-runtime attestation payload.{name}")
    activation = _exact_object(
        payload["activation"],
        {"activationId", "envelopeSha256", "payloadSha256"},
        "base-runtime attestation payload.activation",
    )
    if (
        not isinstance(activation["activationId"], str)
        or _ACTIVATION_ID_RE.fullmatch(activation["activationId"]) is None
    ):
        _fail(
            "base-runtime attestation payload.activation.activationId",
            "must be a content-addressed activation ID",
        )
    _sha256(
        activation["envelopeSha256"],
        "base-runtime attestation payload.activation.envelopeSha256",
    )
    _sha256(
        activation["payloadSha256"],
        "base-runtime attestation payload.activation.payloadSha256",
    )
    instance = _base64url_decode(
        payload["wrapperInstanceId"],
        "base-runtime attestation payload.wrapperInstanceId",
        exact_bytes=32,
    )
    del instance
    _integer(
        payload["sequence"], "base-runtime attestation payload.sequence", 1, 1_000_000
    )
    nonce = _base64url_decode(
        payload["nonce"],
        "base-runtime attestation payload.nonce",
        exact_bytes=32,
    )
    del nonce
    _validate_evaluation_binding(
        payload["evaluation"], "base-runtime attestation payload.evaluation"
    )
    _sha256(
        payload["requestSha256"],
        "base-runtime attestation payload.requestSha256",
    )
    _sha256(
        payload["completionSha256"],
        "base-runtime attestation payload.completionSha256",
    )
    model = _exact_object(
        payload["model"],
        {
            "candidateCatalogSha256",
            "candidateId",
            "modelId",
            "modelRevision",
            "servingProfileSha256",
            "executionModelId",
            "sourceLockSha256",
            "snapshotManifestSha256",
            "snapshotSha256",
            "fileTreeSha256",
        },
        "base-runtime attestation payload.model",
    )
    for name in (
        "candidateCatalogSha256",
        "servingProfileSha256",
        "sourceLockSha256",
        "snapshotManifestSha256",
        "snapshotSha256",
        "fileTreeSha256",
    ):
        _sha256(model[name], f"base-runtime attestation payload.model.{name}")
    _safe_id(
        model["candidateId"],
        "base-runtime attestation payload.model.candidateId",
    )
    _text(
        model["modelId"],
        "base-runtime attestation payload.model.modelId",
        maximum=500,
    )
    if (
        not isinstance(model["modelRevision"], str)
        or _REVISION_RE.fullmatch(model["modelRevision"]) is None
    ):
        _fail(
            "base-runtime attestation payload.model.modelRevision",
            "must be a lowercase 40-character commit SHA",
        )
    _safe_id(
        model["executionModelId"],
        "base-runtime attestation payload.model.executionModelId",
    )
    engine = _exact_object(
        payload["engine"],
        {
            "wrapperConfigSha256",
            "wrapperPackageSha256",
            "executableSha256",
            "engineVersion",
            "containerImageDigest",
            "processId",
            "argvSha256",
        },
        "base-runtime attestation payload.engine",
    )
    for name in (
        "wrapperConfigSha256",
        "wrapperPackageSha256",
        "executableSha256",
        "argvSha256",
    ):
        _sha256(engine[name], f"base-runtime attestation payload.engine.{name}")
    _text(
        engine["engineVersion"],
        "base-runtime attestation payload.engine.engineVersion",
        maximum=100,
    )
    if (
        not isinstance(engine["containerImageDigest"], str)
        or _OCI_DIGEST_RE.fullmatch(engine["containerImageDigest"]) is None
    ):
        _fail(
            "base-runtime attestation payload.engine.containerImageDigest",
            "must be a lowercase sha256 OCI digest",
        )
    _integer(
        engine["processId"],
        "base-runtime attestation payload.engine.processId",
        1,
        2_147_483_647,
    )
    issued = _canonical_utc(
        payload["issuedAtUtc"], "base-runtime attestation payload.issuedAtUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "base-runtime attestation payload.expiresAtUtc"
    )
    if issued >= expires or expires - issued > MAX_ATTESTATION_VALIDITY:
        _fail(
            "base-runtime attestation payload validity",
            "must have positive validity no longer than five minutes",
        )
    identity_document = dict(payload)
    identity_document["attestationId"] = _ATTESTATION_ID_PREFIX + _ZERO_SHA256
    expected_id = _ATTESTATION_ID_PREFIX + _domain_sha256(
        BASE_RUNTIME_ATTESTATION_ID_DOMAIN, identity_document
    )
    if payload["attestationId"] != expected_id:
        _fail(
            "base-runtime attestation payload.attestationId",
            "does not match the canonical attestation payload",
        )
    return payload


def inspect_base_engine_activation_envelope(value: Any) -> dict[str, Any]:
    envelope, payload, payload_bytes, envelope_sha256 = _inspect_envelope(
        value,
        field="base-engine activation envelope",
        schema_version=BASE_ENGINE_ACTIVATION_ENVELOPE_SCHEMA_VERSION,
        payload_validator=_validate_activation_payload,
    )
    return {
        "envelope": envelope,
        "payload": payload,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "envelopeSha256": envelope_sha256,
    }


def inspect_base_runtime_attestation_envelope(value: Any) -> dict[str, Any]:
    envelope, payload, payload_bytes, envelope_sha256 = _inspect_envelope(
        value,
        field="base-runtime attestation envelope",
        schema_version=BASE_RUNTIME_ATTESTATION_ENVELOPE_SCHEMA_VERSION,
        payload_validator=_validate_runtime_attestation_payload,
    )
    return {
        "envelope": envelope,
        "payload": payload,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "envelopeSha256": envelope_sha256,
    }


def verify_base_runtime_attestation(
    *,
    envelope: Any,
    runtime_public_key_path: str | os.PathLike[str],
    activation: VerifiedBaseEngineActivation,
    expected_nonce: str,
    expected_evaluation: Mapping[str, Any],
    request: Mapping[str, Any],
    completion: Mapping[str, Any],
    now: datetime,
) -> VerifiedBaseRuntimeAttestation:
    runtime_signer = activation.payload["runtimeSigner"]
    verified_envelope, payload, payload_bytes, envelope_sha256 = _verify_envelope(
        envelope,
        field="base-runtime attestation envelope",
        schema_version=BASE_RUNTIME_ATTESTATION_ENVELOPE_SCHEMA_VERSION,
        signature_domain=BASE_RUNTIME_SIGNATURE_DOMAIN,
        public_key_path=Path(runtime_public_key_path),
        expected_public_key_spki_sha256=runtime_signer["publicKeySpkiSha256"],
    )
    payload = _validate_runtime_attestation_payload(payload)
    if (
        payload["audience"] != runtime_signer["audience"]
        or payload["keyId"] != runtime_signer["keyId"]
        or payload["signerRole"] != runtime_signer["signerRole"]
    ):
        _fail(
            "base-runtime attestation envelope", "does not match activated signer trust"
        )
    expected_activation = {
        "activationId": activation.payload["activationId"],
        "envelopeSha256": activation.envelope_sha256,
        "payloadSha256": activation.payload_sha256,
    }
    if payload["activation"] != expected_activation:
        _fail(
            "base-runtime attestation payload.activation",
            "does not match the verified engine activation",
        )
    if payload["nonce"] != expected_nonce:
        _fail("base-runtime attestation payload.nonce", "does not match the challenge")
    if payload["evaluation"] != dict(expected_evaluation):
        _fail(
            "base-runtime attestation payload.evaluation",
            "does not match the evaluation record",
        )
    if (
        payload["requestSha256"]
        != hashlib.sha256(canonical_json_bytes(request)).hexdigest()
    ):
        _fail(
            "base-runtime attestation payload.requestSha256",
            "does not match the exact model request",
        )
    if (
        payload["completionSha256"]
        != hashlib.sha256(canonical_json_bytes(completion)).hexdigest()
    ):
        _fail(
            "base-runtime attestation payload.completionSha256",
            "does not match the exact model completion",
        )
    if payload["model"] != activation.payload["model"]:
        _fail("base-runtime attestation payload.model", "does not match activation")
    expected_engine = {
        "wrapperConfigSha256": activation.payload["wrapperConfigSha256"],
        "wrapperPackageSha256": activation.payload["wrapperPackageSha256"],
        "executableSha256": activation.payload["engine"]["executableSha256"],
        "engineVersion": activation.payload["engine"]["engineVersion"],
        "containerImageDigest": activation.payload["engine"]["containerImageDigest"],
    }
    for name, expected in expected_engine.items():
        if payload["engine"][name] != expected:
            _fail(
                f"base-runtime attestation payload.engine.{name}",
                "does not match activation",
            )
    current = _validation_time(now, "base-runtime attestation validation time")
    issued = _canonical_utc(
        payload["issuedAtUtc"], "base-runtime attestation payload.issuedAtUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "base-runtime attestation payload.expiresAtUtc"
    )
    activation_expires = _canonical_utc(
        activation.payload["expiresAtUtc"],
        "base-engine activation payload.expiresAtUtc",
    )
    if current < issued or current >= expires or expires > activation_expires:
        _fail("base-runtime attestation", "is not currently valid")
    return VerifiedBaseRuntimeAttestation(
        envelope=verified_envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        envelope_sha256=envelope_sha256,
    )


def _default_read_only_probe(path: Path) -> bool:
    if os.name != "posix" or not hasattr(os, "statvfs"):
        return False
    readonly_flag = getattr(os, "ST_RDONLY", 1)
    try:
        return bool(os.statvfs(path).f_flag & readonly_flag)
    except OSError:
        return False


def _opened_fd_path(executable_fd: int) -> str:
    if os.name != "posix":
        _fail(
            "base-engine child process",
            "native Windows launch is unsupported; use the pinned POSIX container",
        )
    path = f"/proc/self/fd/{executable_fd}"
    if not Path(path).exists():
        _fail("base-engine child process", "/proc/self/fd is required")
    return path


def _default_opened_process_factory(
    executable_fd: int,
    argv: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    *,
    child_user_id: int,
    child_group_id: int,
) -> ChildProcess:
    fd_path = _opened_fd_path(executable_fd)
    process = subprocess.Popen(
        list(argv),
        executable=fd_path,
        pass_fds=(executable_fd,),
        cwd=working_directory,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        shell=False,
        start_new_session=True,
        user=child_user_id,
        group=child_group_id,
        extra_groups=[],
        umask=0o077,
    )
    return _OwnedOpenedProcess(process)


def _default_listener_ownership_probe(process_id: int, host: str, port: int) -> bool:
    if os.name != "posix" or host != _LOOPBACK_HOST or not Path("/proc").is_dir():
        return False
    try:
        if os.getpgid(process_id) != process_id:
            return False
    except OSError:
        return False
    listener_inodes: set[str] = set()
    expected_port = f"{port:04X}"
    for table_path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = table_path.read_text(
                encoding="ascii", errors="strict"
            ).splitlines()[1:]
        except (OSError, UnicodeError):
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            local_address = fields[1]
            try:
                address, encoded_port = local_address.rsplit(":", 1)
            except ValueError:
                continue
            if encoded_port != expected_port:
                continue
            if table_path.name == "tcp" and address != "0100007F":
                continue
            if table_path.name == "tcp6" and address not in {
                "00000000000000000000000001000000",
                "0000000000000000FFFF00000100007F",
            }:
                continue
            listener_inodes.add(fields[9])
    if len(listener_inodes) != 1:
        return False
    expected_socket = f"socket:[{next(iter(listener_inodes))}]"
    try:
        process_paths = tuple(Path("/proc").iterdir())
    except OSError:
        return False
    for process_path in process_paths:
        if not process_path.name.isdigit():
            continue
        candidate_pid = int(process_path.name)
        try:
            if os.getpgid(candidate_pid) != process_id:
                continue
            descriptors = tuple((process_path / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                if os.readlink(descriptor) == expected_socket:
                    return True
            except OSError:
                continue
    return False


class _OwnedOpenedProcess:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self.pid = process.pid

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._process.wait(timeout=timeout)

    def terminate(self) -> None:
        if os.name == "nt":
            self._process.terminate()
        else:
            os.killpg(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        if os.name == "nt":
            self._process.kill()
        else:
            os.killpg(self.pid, signal.SIGKILL)

    def ensure_process_group_stopped(self, timeout: float) -> None:
        if os.name == "nt":
            return
        try:
            os.killpg(self.pid, 0)
        except ProcessLookupError:
            return
        os.killpg(self.pid, signal.SIGKILL)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.killpg(self.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        _fail("base-engine process group", "remains alive after SIGKILL")


def _hash_opened_file(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1_048_576)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_verified_executable(path: Path, expected_sha256: str) -> int:
    resolved = _reject_reparse_components(path, "base-engine executable")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ValidationError(
            f"base-engine executable: cannot open safely: {error}"
        ) from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _fail("base-engine executable", "must be a single-link regular file")
        if _hash_opened_file(descriptor) != expected_sha256:
            _fail(
                "base-engine executable",
                "opened inode does not match configured SHA-256",
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@dataclass(frozen=True)
class _PathIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    links: int


def _path_identity(path: Path, field: str) -> _PathIdentity:
    resolved = _reject_reparse_components(path, field)
    info = os.lstat(resolved)
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        _fail(field, "must be a regular file or directory")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        _fail(field, "regular files must have exactly one hard link")
    return _PathIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        mode=info.st_mode,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
        links=info.st_nlink,
    )


def _load_optional_password(environment_name: str | None) -> bytes | None:
    if environment_name is None:
        return None
    value = os.environ.get(environment_name)
    if value is None:
        _fail(
            "base-engine runtime private-key password",
            f"environment variable {environment_name!r} is not set",
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValidationError(
            "base-engine runtime private-key password: must be valid UTF-8"
        ) from error
    if not 1 <= len(encoded) <= 4_096:
        _fail(
            "base-engine runtime private-key password",
            "must contain 1 through 4096 UTF-8 bytes",
        )
    return encoded


class BaseModelEngineWrapper:
    def __init__(
        self,
        config: BaseEngineWrapperConfig,
        *,
        bearer_token: str,
        runtime_private_key_password: bytes | None = None,
        child_api_key: str | None = None,
        package_root: str | os.PathLike[str] | None = None,
        transport: Callable[
            [str, str, Mapping[str, str], bytes | None, float, int], TransportResponse
        ]
        | None = None,
        runtime_signer_transport: Callable[
            [str, str, Mapping[str, str], bytes | None, float, int], TransportResponse
        ]
        | None = None,
        process_factory: OpenedProcessFactory | None = None,
        read_only_probe: ReadOnlyProbe | None = None,
        listener_ownership_probe: ListenerOwnershipProbe | None = None,
        runtime_key_isolation_probe: RuntimeKeyIsolationProbe | None = None,
        clock: Clock | None = None,
        monotonic: Monotonic | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        if not 32 <= len(bearer_token) <= 512 or any(
            ord(character) <= 32 or ord(character) >= 127 for character in bearer_token
        ):
            _fail(
                "base-engine bearer token",
                "must contain 32 through 512 visible ASCII characters",
            )
        if (
            isinstance(config.runtime_signing, BaseExternalRuntimeSigningConfig)
            and runtime_private_key_password is not None
        ):
            _fail(
                "base-engine runtime signer",
                "external signer configurations do not accept a private-key password",
            )
        self.config = config
        self._bearer_token = bearer_token
        self._runtime_private_key_password = runtime_private_key_password
        self._child_api_key = child_api_key or secrets.token_urlsafe(32)
        if not 32 <= len(self._child_api_key) <= 512 or any(
            ord(character) <= 32 or ord(character) >= 127
            for character in self._child_api_key
        ):
            _fail(
                "base-engine child API key",
                "must contain 32 through 512 visible ASCII characters",
            )
        self._package_root = (
            Path(os.path.abspath(os.fspath(package_root)))
            if package_root is not None
            else Path(__file__).resolve().parent
        )
        self._transport = transport or _default_transport
        self._runtime_signer_transport = runtime_signer_transport
        if process_factory is None:
            self._process_factory = (
                lambda descriptor, argv, environment, working_directory: (
                    _default_opened_process_factory(
                        descriptor,
                        argv,
                        environment,
                        working_directory,
                        child_user_id=config.child_user_id,
                        child_group_id=config.child_group_id,
                    )
                )
            )
        else:
            self._process_factory = process_factory
        self._read_only_probe = read_only_probe or _default_read_only_probe
        self._listener_ownership_probe = (
            listener_ownership_probe or _default_listener_ownership_probe
        )
        self._runtime_key_isolation_probe = runtime_key_isolation_probe
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic or time.monotonic
        self._sleeper = sleeper or time.sleep
        self._state = WrapperState.CREATED
        self._state_lock = threading.RLock()
        self._request_lock = threading.Lock()
        self._process: ChildProcess | None = None
        self._snapshot: BaseActivationSnapshot | None = None
        self._activation: VerifiedBaseEngineActivation | None = None
        self._runtime_private_key: Any | None = None
        self._runtime_signer_bearer_token: str | None = None
        self._runtime_signer_ready = False
        self._protected_identities: dict[Path, _PathIdentity] = {}
        self._used_nonces: set[str] = set()
        self._sequence = 0
        self._wrapper_instance_id = (
            urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        )
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._server: ThreadingHTTPServer | None = None
        self._termination_error: ValidationError | None = None

    @classmethod
    def from_environment(
        cls, config: BaseEngineWrapperConfig, **kwargs: Any
    ) -> BaseModelEngineWrapper:
        return cls(
            config,
            bearer_token=_load_bearer_secret(config.service.bearer_token_environment),
            **kwargs,
        )

    @property
    def state(self) -> WrapperState:
        with self._state_lock:
            return self._state

    @property
    def snapshot(self) -> BaseActivationSnapshot | None:
        with self._state_lock:
            return self._snapshot

    @property
    def activation(self) -> VerifiedBaseEngineActivation | None:
        with self._state_lock:
            return self._activation

    def _protected_paths(self) -> tuple[Path, ...]:
        config = self.config
        common = (
            config.path,
            config.target.profile_path,
            config.target.snapshot_manifest_path,
            config.target.snapshot_path,
            config.target.catalog_path,
            config.target.source_lock_path,
            config.activation.path,
            config.activation.trust.public_key_path,
            config.runtime_signing.public_key_path,
            config.engine.executable_path,
            self._package_root,
        )
        if isinstance(config.runtime_signing, BaseLocalRuntimeSigningConfig):
            return (*common, config.runtime_signing.private_key_path)
        return (*common, config.runtime_signing.signer_tls_certificate_path)

    def _require_read_only_inputs(self) -> None:
        for path in self._protected_paths():
            if not path.exists():
                _fail("base-engine immutable input", f"does not exist: {path}")
            if not self._read_only_probe(path):
                _fail(
                    "base-engine immutable input",
                    f"must be on a read-only mount: {path}",
                )

    def _capture_protected_identities(self) -> dict[Path, _PathIdentity]:
        self._require_read_only_inputs()
        return {
            path: _path_identity(path, "base-engine immutable input")
            for path in self._protected_paths()
        }

    def _assert_protected_identities(self) -> None:
        self._require_read_only_inputs()
        if not self._protected_identities:
            _fail("base-engine immutable inputs", "have not been captured")
        for path, expected in self._protected_identities.items():
            if _path_identity(path, "base-engine immutable input") != expected:
                _fail(
                    "base-engine immutable input", f"changed after activation: {path}"
                )

    def _require_runtime_key_isolation(self) -> None:
        if self._runtime_key_isolation_probe is not None:
            if not self._runtime_key_isolation_probe(self.config):
                _fail(
                    "base-engine runtime private key",
                    "did not pass the injected isolation probe",
                )
            return
        if os.name != "posix":
            return
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            _fail(
                "base-engine privilege isolation",
                "the production wrapper must run as root so the vLLM child can use a distinct unprivileged identity",
            )
        if self.config.child_user_id == 0 or self.config.child_user_id == os.geteuid():
            _fail(
                "base-engine child user",
                "must be a distinct non-root identity",
            )
        if isinstance(self.config.runtime_signing, BaseLocalRuntimeSigningConfig):
            private_key = _reject_reparse_components(
                self.config.runtime_signing.private_key_path,
                "base-engine runtime private key",
            )
            info = os.lstat(private_key)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                _fail(
                    "base-engine runtime private key",
                    "must be a regular file owned by the wrapper identity",
                )
            if stat.S_IMODE(info.st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
                _fail(
                    "base-engine runtime private key",
                    "must deny all group and other permissions",
                )

    def _child_environment(self) -> dict[str, str]:
        environment = {
            name: os.environ[name]
            for name in self.config.engine.environment_allowlist
            if name in os.environ
        }
        environment.update(
            {
                "HF_HUB_OFFLINE": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost",
                "VLLM_PLUGINS": "",
                "VLLM_API_KEY": self._child_api_key,
            }
        )
        forbidden = {
            self.config.service.bearer_token_environment,
            self.config.engine.container_image_digest_environment,
        }
        if isinstance(self.config.runtime_signing, BaseLocalRuntimeSigningConfig):
            if self.config.runtime_signing.private_key_password_environment is not None:
                forbidden.add(
                    self.config.runtime_signing.private_key_password_environment
                )
        else:
            forbidden.add(self.config.runtime_signing.signer_bearer_token_environment)
        for name in tuple(environment):
            if name in forbidden or (
                name != "VLLM_API_KEY" and _SECRET_ENVIRONMENT_RE.search(name)
            ):
                environment.pop(name, None)
        return environment

    def _validate_activation(self) -> BaseActivationSnapshot:
        self._require_read_only_inputs()
        self._require_runtime_key_isolation()
        verified = verify_base_engine_activation(
            activation_path=self.config.activation.path,
            config=self.config,
            trust=self.config.activation.trust,
            now=self._clock(),
            package_root=self._package_root,
        )
        runtime_public_key, runtime_spki = _runtime_public_key_identity(self.config)
        del runtime_public_key
        image_environment = self.config.engine.container_image_digest_environment
        current_image = os.environ.get(image_environment)
        if current_image is None or _OCI_DIGEST_RE.fullmatch(current_image) is None:
            _fail(
                "base-engine container-image environment variable",
                f"{image_environment!r} must contain a lowercase sha256 OCI digest",
            )
        if current_image != verified.payload["engine"]["containerImageDigest"]:
            _fail("base-engine container image", "does not match signed activation")
        profile = _validated_target(self.config)
        return BaseActivationSnapshot(
            activation_id=verified.payload["activationId"],
            activation_envelope_sha256=verified.envelope_sha256,
            activation_payload_sha256=verified.payload_sha256,
            wrapper_config_sha256=verified.payload["wrapperConfigSha256"],
            wrapper_package_sha256=verified.payload["wrapperPackageSha256"],
            serving_profile_sha256=profile.sha256,
            execution_model_id=profile.execution_model_id,
            source_lock_sha256=verified.payload["model"]["sourceLockSha256"],
            snapshot_manifest_sha256=verified.payload["model"][
                "snapshotManifestSha256"
            ],
            snapshot_sha256=verified.payload["model"]["snapshotSha256"],
            file_tree_sha256=verified.payload["model"]["fileTreeSha256"],
            engine_executable_sha256=verified.payload["engine"]["executableSha256"],
            engine_version=verified.payload["engine"]["engineVersion"],
            container_image_digest=verified.payload["engine"]["containerImageDigest"],
            runtime_public_key_spki_sha256=runtime_spki,
            expires_at_utc=verified.payload["expiresAtUtc"],
            serving_profile=profile,
        )

    def _load_runtime_signing_key(self, expected_spki: str) -> None:
        if not isinstance(self.config.runtime_signing, BaseLocalRuntimeSigningConfig):
            _fail(
                "base-engine runtime signing key", "local PEM signing is not configured"
            )
        if self._runtime_private_key is not None:
            _fail("base-engine runtime signing key", "is already loaded")
        self._assert_protected_identities()
        self._require_runtime_key_isolation()
        password = self._runtime_private_key_password
        if password is None:
            password = _load_optional_password(
                self.config.runtime_signing.private_key_password_environment
            )
        try:
            private_key, private_spki = _load_private_key(
                self.config.runtime_signing.private_key_path,
                password,
            )
        finally:
            password = None
            self._runtime_private_key_password = None
        if private_spki != expected_spki:
            _fail(
                "base-engine runtime signing key",
                "private and public keys do not match",
            )
        self._assert_protected_identities()
        self._runtime_private_key = private_key

    def _request_external_runtime_signature(
        self, *, purpose: str, signature_input: bytes
    ) -> bytes:
        signing = self.config.runtime_signing
        if not isinstance(signing, BaseExternalRuntimeSigningConfig):
            _fail("base-engine external runtime signer", "is not configured")
        token = self._runtime_signer_bearer_token
        if token is None:
            _fail("base-engine external runtime signer", "credential is unavailable")
        if purpose not in {"startup-proof", "runtime-attestation"}:
            _fail("base-engine external runtime signer purpose", "is unsupported")
        if (
            not 1
            <= len(signature_input)
            <= MAX_BASE_RUNTIME_SIGNER_SIGNATURE_INPUT_BYTES
        ):
            _fail(
                "base-engine external runtime signer input",
                "exceeds the bounded signature-input size",
            )
        request_id = _base64url_encode(secrets.token_bytes(32))
        signature_input_digest = hashlib.sha256(signature_input).digest()
        signature_input_sha256 = signature_input_digest.hex()
        digest_base64url = _base64url_encode(signature_input_digest)
        request = {
            "schemaVersion": BASE_RUNTIME_SIGNER_REQUEST_SCHEMA_VERSION,
            "requestId": request_id,
            "purpose": purpose,
            "providerKeyReference": signing.provider_key_reference,
            "keyId": signing.key_id,
            "publicKeySpkiSha256": signing.public_key_spki_sha256,
            "algorithm": _RUNTIME_SIGNER_ALGORITHM,
            "messageType": _RUNTIME_SIGNER_MESSAGE_TYPE,
            "signatureFormat": signing.signature_format,
            "signatureInputEncoding": _RUNTIME_SIGNER_INPUT_ENCODING,
            "signatureInput": _base64url_encode(signature_input),
            "signatureInputSha256": signature_input_sha256,
            "signatureInputDigest": digest_base64url,
        }
        request_bytes = canonical_json_bytes(request)
        if len(request_bytes) > MAX_BASE_RUNTIME_SIGNER_REQUEST_BYTES:
            _fail("base-engine external runtime signer request", "exceeds byte limit")
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        if self._runtime_signer_transport is None:
            response = _default_runtime_signer_transport(
                "POST",
                signing.signer_endpoint,
                request_headers,
                request_bytes,
                signing.request_timeout_seconds,
                signing.max_response_bytes,
                signing.signer_tls_certificate_sha256,
            )
        else:
            response = self._runtime_signer_transport(
                "POST",
                signing.signer_endpoint,
                request_headers,
                request_bytes,
                signing.request_timeout_seconds,
                signing.max_response_bytes,
            )
        if response.final_url != signing.signer_endpoint:
            _fail("base-engine external runtime signer", "response URL changed")
        if response.status != 200:
            _fail(
                "base-engine external runtime signer",
                f"returned HTTP {response.status}",
            )
        if len(response.body) > signing.max_response_bytes:
            _fail("base-engine external runtime signer response", "exceeds byte limit")
        _require_json_content_type(
            response.headers, "base-engine external runtime signer response"
        )
        value = _parse_json_bytes(
            response.body, "base-engine external runtime signer response"
        )
        if canonical_json_bytes(value) != response.body:
            _fail(
                "base-engine external runtime signer response",
                "must use exact canonical JSON bytes",
            )
        signed = _exact_object(
            value,
            {
                "schemaVersion",
                "requestId",
                "purpose",
                "providerKeyReference",
                "keyId",
                "publicKeySpkiSha256",
                "algorithm",
                "messageType",
                "signatureFormat",
                "signatureInputSha256",
                "signatureInputDigest",
                "signature",
            },
            "base-engine external runtime signer response",
        )
        expected = {
            "schemaVersion": BASE_RUNTIME_SIGNER_RESPONSE_SCHEMA_VERSION,
            "requestId": request_id,
            "purpose": purpose,
            "providerKeyReference": signing.provider_key_reference,
            "keyId": signing.key_id,
            "publicKeySpkiSha256": signing.public_key_spki_sha256,
            "algorithm": _RUNTIME_SIGNER_ALGORITHM,
            "messageType": _RUNTIME_SIGNER_MESSAGE_TYPE,
            "signatureFormat": signing.signature_format,
            "signatureInputSha256": signature_input_sha256,
            "signatureInputDigest": digest_base64url,
        }
        for name, expected_value in expected.items():
            if signed[name] != expected_value:
                _fail(
                    f"base-engine external runtime signer response.{name}",
                    "does not match the exact request",
                )
        public_key, public_key_spki_sha256 = _runtime_public_key_identity(self.config)
        if public_key_spki_sha256 != signing.public_key_spki_sha256:
            _fail("base-engine external runtime signer", "public key identity changed")
        return _normalize_external_signature(
            signed["signature"],
            signature_format=signing.signature_format,
            public_key=public_key,
            signature_input=signature_input,
            field="base-engine external runtime signer response.signature",
        )

    def _initialize_runtime_signer(self, snapshot: BaseActivationSnapshot) -> None:
        if self._runtime_signer_ready:
            _fail("base-engine runtime signer", "is already initialized")
        self._assert_protected_identities()
        self._require_runtime_key_isolation()
        signing = self.config.runtime_signing
        if isinstance(signing, BaseLocalRuntimeSigningConfig):
            self._load_runtime_signing_key(snapshot.runtime_public_key_spki_sha256)
        else:
            token = _load_bearer_secret(signing.signer_bearer_token_environment)
            self._runtime_signer_bearer_token = token
            proof_input = _frame(
                (
                    BASE_RUNTIME_SIGNER_PROOF_DOMAIN,
                    snapshot.activation_id,
                    snapshot.activation_envelope_sha256,
                    snapshot.wrapper_config_sha256,
                    snapshot.wrapper_package_sha256,
                    self._wrapper_instance_id,
                    str(snapshot.engine_process_id),
                    snapshot.engine_argv_sha256,
                    secrets.token_bytes(32),
                )
            )
            try:
                self._request_external_runtime_signature(
                    purpose="startup-proof", signature_input=proof_input
                )
            except BaseException:
                self._runtime_signer_bearer_token = None
                raise
        self._assert_protected_identities()
        self._runtime_signer_ready = True

    def build_child_argv(self, snapshot: BaseActivationSnapshot) -> tuple[str, ...]:
        runtime = snapshot.serving_profile.document["runtime"]
        if snapshot.engine_version not in _SUPPORTED_VLLM_ENGINE_VERSIONS:
            _fail(
                "base-engine version",
                "has no reviewed exact argv adapter; supported versions are 0.10.0 and 0.26.0",
            )
        model_path = os.fspath(self.config.target.snapshot_path)
        quantization = runtime["quantization"]
        load_format = (
            "bitsandbytes" if quantization == "bitsandbytes-nf4" else "safetensors"
        )
        argv = [
            os.fspath(self.config.engine.executable_path),
            "serve",
            model_path,
            "--served-model-name",
            snapshot.execution_model_id,
            "--tokenizer",
            model_path,
            "--host",
            self.config.engine.child_host,
            "--port",
            str(self.config.engine.child_port),
            "--dtype",
            runtime["computeDtype"],
            "--max-model-len",
            str(runtime["maxModelLength"]),
            "--tensor-parallel-size",
            str(runtime["tensorParallelSize"]),
            "--load-format",
            load_format,
            "--generation-config",
            "vllm",
            "--disable-fastapi-docs",
            "--disable-uvicorn-access-log",
        ]
        if snapshot.engine_version == "0.10.0":
            argv.append("--disable-log-requests")
        else:
            argv.extend(
                [
                    "--api-server-count",
                    "1",
                    "--tokenizer-mode",
                    "hf",
                    "--config-format",
                    "hf",
                    "--model-impl",
                    "vllm",
                    "--seed",
                    "0",
                ]
            )
        if quantization == "bitsandbytes-nf4":
            argv.extend(["--quantization", "bitsandbytes"])
        elif quantization != "none":
            argv.extend(["--quantization", quantization])
        return tuple(argv)

    def _child_url(self, path: str) -> str:
        return f"http://{self.config.engine.child_host}:{self.config.engine.child_port}{path}"

    def _require_live_process(self) -> ChildProcess:
        with self._state_lock:
            process = self._process
        if process is None or process.poll() is not None:
            _fail("base-engine child", "is not running")
        return process

    def _probe_child(self, snapshot: BaseActivationSnapshot) -> None:
        process = self._require_live_process()
        if not self._listener_ownership_probe(
            process.pid,
            self.config.engine.child_host,
            self.config.engine.child_port,
        ):
            _fail(
                "base-engine child listener",
                "is not owned by the launched vLLM process group",
            )
        timeout = self.config.engine.request_timeout_seconds
        health = self._transport(
            "GET",
            self._child_url("/health"),
            {"Authorization": f"Bearer {self._child_api_key}"},
            None,
            timeout,
            4_096,
        )
        if health.status != 200:
            _fail("base-engine child health", f"returned HTTP {health.status}")
        version = self._transport(
            "GET",
            self._child_url("/version"),
            {"Accept": "application/json"},
            None,
            timeout,
            4_096,
        )
        if version.status != 200:
            _fail("base-engine child version", f"returned HTTP {version.status}")
        _require_json_content_type(
            version.headers, "base-engine child version response"
        )
        version_value = _parse_json_bytes(
            version.body, "base-engine child version response"
        )
        if version_value != {"version": snapshot.engine_version}:
            _fail(
                "base-engine child version response",
                "does not exactly match the signed vLLM version",
            )
        models = self._transport(
            "GET",
            self._child_url("/v1/models"),
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._child_api_key}",
            },
            None,
            timeout,
            self.config.service.max_response_bytes,
        )
        if models.status != 200:
            _fail("base-engine child models", f"returned HTTP {models.status}")
        _require_json_content_type(models.headers, "base-engine child models response")
        value = _parse_json_bytes(models.body, "base-engine child models response")
        if not isinstance(value, dict) or not isinstance(value.get("data"), list):
            _fail("base-engine child models response", "must contain a data array")
        identifiers: list[str] = []
        for index, item in enumerate(value["data"]):
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                _fail(
                    f"base-engine child models response.data[{index}]",
                    "must contain a string id",
                )
            identifiers.append(item["id"])
            if item.get("root") != os.fspath(self.config.target.snapshot_path):
                _fail(
                    f"base-engine child models response.data[{index}].root",
                    "does not match the immutable local snapshot path",
                )
            if (
                item.get("max_model_len")
                != snapshot.serving_profile.document["runtime"]["maxModelLength"]
            ):
                _fail(
                    f"base-engine child models response.data[{index}].max_model_len",
                    "does not match the serving profile",
                )
        if identifiers != [snapshot.execution_model_id]:
            _fail(
                "base-engine child models response",
                "must expose only the exact raw-base execution model ID",
            )

    def _wait_for_child(self, snapshot: BaseActivationSnapshot) -> None:
        deadline = self._monotonic() + self.config.engine.startup_timeout_seconds
        last_error: Exception | None = None
        while self._monotonic() < deadline:
            self._require_live_process()
            try:
                self._probe_child(snapshot)
                return
            except ValidationError as error:
                last_error = error
            self._sleeper(min(0.25, max(0.0, deadline - self._monotonic())))
        if last_error is None:
            _fail("base-engine startup", "timed out")
        raise ValidationError(f"base-engine startup: timed out: {last_error}")

    def _same_active_snapshot(self, *, full: bool) -> BaseActivationSnapshot:
        expected = self.snapshot
        if expected is None:
            _fail("base-engine activation", "is unavailable")
        self._assert_protected_identities()
        process = self._require_live_process()
        if process.pid != expected.engine_process_id:
            _fail("base-engine child", "process identity changed")
        if not self._listener_ownership_probe(
            process.pid,
            self.config.engine.child_host,
            self.config.engine.child_port,
        ):
            _fail(
                "base-engine child listener",
                "is no longer owned by the launched vLLM process group",
            )
        image = os.environ.get(self.config.engine.container_image_digest_environment)
        if image != expected.container_image_digest:
            _fail("base-engine container image", "claim changed after activation")
        current_time = _validation_time(self._clock(), "base-engine clock")
        if current_time >= _canonical_utc(
            expected.expires_at_utc, "base-engine activation expiry"
        ):
            _fail("base-engine activation", "expired")
        if full:
            current = self._validate_activation()
            current = replace(
                current,
                engine_process_id=expected.engine_process_id,
                engine_argv_sha256=expected.engine_argv_sha256,
            )
            if current != expected:
                _fail("base-engine activation", "changed after the child was launched")
        return expected

    def start(self, *, start_monitor: bool = True) -> BaseActivationSnapshot:
        with self._state_lock:
            if self._state is not WrapperState.CREATED:
                _fail("base-engine wrapper", "can be started only once")
            self._state = WrapperState.PREVALIDATING
        descriptor: int | None = None
        try:
            snapshot = self._validate_activation()
            self._protected_identities = self._capture_protected_identities()
            descriptor = _open_verified_executable(
                self.config.engine.executable_path, snapshot.engine_executable_sha256
            )
            with self._state_lock:
                if (
                    self._stop_event.is_set()
                    or self._state is not WrapperState.PREVALIDATING
                ):
                    _fail("base-engine wrapper", "was stopped during prevalidation")
                self._state = WrapperState.STARTING
            argv = self.build_child_argv(snapshot)
            if _hash_opened_file(descriptor) != snapshot.engine_executable_sha256:
                _fail("base-engine executable", "opened inode changed before launch")
            process = self._process_factory(
                descriptor,
                argv,
                self._child_environment(),
                self.config.engine.executable_path.parent,
            )
            os.close(descriptor)
            descriptor = None
            snapshot = replace(
                snapshot,
                engine_process_id=process.pid,
                engine_argv_sha256=engine_argv_sha256(argv),
            )
            with self._state_lock:
                self._process = process
                self._snapshot = snapshot
                self._activation = verify_base_engine_activation(
                    activation_path=self.config.activation.path,
                    config=self.config,
                    trust=self.config.activation.trust,
                    now=self._clock(),
                    package_root=self._package_root,
                )
                if (
                    self._stop_event.is_set()
                    or self._state is not WrapperState.STARTING
                ):
                    _fail("base-engine wrapper", "was stopped during launch")
                self._state = WrapperState.LOADING
            self._wait_for_child(snapshot)
            with self._state_lock:
                if self._stop_event.is_set() or self._state is not WrapperState.LOADING:
                    _fail("base-engine wrapper", "was stopped while the child loaded")
                self._state = WrapperState.POST_LOAD_VALIDATING
            post_load = self._same_active_snapshot(full=True)
            self._probe_child(post_load)
            self._initialize_runtime_signer(post_load)
            self._same_active_snapshot(full=False)
            with self._state_lock:
                if (
                    self._stop_event.is_set()
                    or self._state is not WrapperState.POST_LOAD_VALIDATING
                ):
                    _fail(
                        "base-engine wrapper", "was stopped during post-load validation"
                    )
                self._state = WrapperState.READY
            if start_monitor:
                self._monitor_thread = threading.Thread(
                    target=self._monitor_loop,
                    name="hyperion-base-engine-monitor",
                    daemon=True,
                )
                self._monitor_thread.start()
            return post_load
        except Exception as error:
            if descriptor is not None:
                os.close(descriptor)
            self.fail_closed()
            if self._termination_error is not None:
                raise self._termination_error from error
            raise

    def monitor_once(self, *, validate_integrity: bool = True) -> None:
        if self.state is not WrapperState.READY:
            _fail("base-engine wrapper", "is not ready")
        snapshot = self._same_active_snapshot(full=validate_integrity)
        self._probe_child(snapshot)

    def _monitor_loop(self) -> None:
        last_integrity = self._monotonic()
        while not self._stop_event.wait(self.config.engine.health_interval_seconds):
            try:
                validate_integrity = (
                    self._monotonic() - last_integrity
                    >= self.config.engine.integrity_interval_seconds
                )
                self.monitor_once(validate_integrity=validate_integrity)
                if validate_integrity:
                    last_integrity = self._monotonic()
            except Exception:
                self.fail_closed()
                return

    def _authorize(self, headers: Mapping[str, str]) -> bool:
        authorization = next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "authorization"
            ),
            None,
        )
        if authorization is None or not authorization.startswith("Bearer "):
            return False
        import hmac

        return hmac.compare_digest(authorization[7:], self._bearer_token)

    def _strict_request_json(self, headers: Mapping[str, str], body: bytes) -> Any:
        content_type = next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "content-type"
            ),
            None,
        )
        if content_type not in {"application/json", "application/json; charset=utf-8"}:
            _request_fail("base-engine request Content-Type", "must be canonical JSON")
        if len(body) > self.config.service.max_request_bytes:
            _request_fail(
                "base-engine request body", "exceeds the configured byte limit"
            )
        try:
            return _parse_json_bytes(body, "base-engine request body")
        except ValidationError as error:
            raise RequestValidationError(str(error)) from error

    def _validate_openai_request(
        self, value: Any, snapshot: BaseActivationSnapshot
    ) -> dict[str, Any]:
        request = _exact_object(
            value,
            {"model", "messages", "temperature", "top_p", "seed", "max_tokens", "n"},
            "base-engine model request",
        )
        if request["model"] != snapshot.execution_model_id:
            _request_fail(
                "base-engine model request.model", "must match the activated raw base"
            )
        if request["temperature"] != 0 or isinstance(request["temperature"], bool):
            _request_fail("base-engine model request.temperature", "must be zero")
        if request["top_p"] != 1 or isinstance(request["top_p"], bool):
            _request_fail("base-engine model request.top_p", "must be one")
        _integer(request["seed"], "base-engine model request.seed", 0, 2_147_483_647)
        _integer(
            request["max_tokens"],
            "base-engine model request.max_tokens",
            1,
            snapshot.serving_profile.document["runtime"]["maxModelLength"],
        )
        if request["n"] != 1 or isinstance(request["n"], bool):
            _request_fail("base-engine model request.n", "must be one")
        messages = request["messages"]
        if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
            _request_fail(
                "base-engine model request.messages",
                "must contain 1 through 128 messages",
            )
        for index, message in enumerate(messages):
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                _request_fail(
                    f"base-engine model request.messages[{index}]",
                    "must contain exactly role and content",
                )
            if message["role"] not in {"system", "user", "assistant"}:
                _request_fail(
                    f"base-engine model request.messages[{index}].role",
                    "is not an accepted chat role",
                )
            content = message["content"]
            if not isinstance(content, str) or not content or len(content) > 1_000_000:
                _request_fail(
                    f"base-engine model request.messages[{index}].content",
                    "must be a non-empty bounded string",
                )
            if any(
                ord(character) < 32 and character not in {"\t", "\n", "\r"}
                for character in content
            ):
                _request_fail(
                    f"base-engine model request.messages[{index}].content",
                    "must not contain disallowed control characters",
                )
        return request

    def _validate_attested_request(
        self, value: Any, snapshot: BaseActivationSnapshot
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        request = _exact_object(
            value,
            {"schemaVersion", "nonce", "evaluation", "request"},
            "base-engine attested completion request",
        )
        if request["schemaVersion"] != BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION:
            _request_fail(
                "base-engine attested completion request.schemaVersion",
                f"must be {BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION!r}",
            )
        nonce = request["nonce"]
        if not isinstance(nonce, str) or _NONCE_RE.fullmatch(nonce) is None:
            _request_fail(
                "base-engine attested completion request.nonce",
                "must be 32-byte base64url",
            )
        try:
            decoded = urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
        except ValueError as error:
            raise RequestValidationError(
                "base-engine attested completion request.nonce: invalid base64url"
            ) from error
        if (
            len(decoded) != 32
            or urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != nonce
        ):
            _request_fail(
                "base-engine attested completion request.nonce",
                "must be canonical 32-byte base64url",
            )
        try:
            evaluation = _validate_evaluation_binding(
                request["evaluation"],
                "base-engine attested completion request.evaluation",
            )
            model_request = self._validate_openai_request(request["request"], snapshot)
        except RequestValidationError:
            raise
        except ValidationError as error:
            raise RequestValidationError(str(error)) from error
        return nonce, evaluation, model_request

    def _validate_completion(
        self, value: Any, snapshot: BaseActivationSnapshot
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            _fail("base-engine child completion", "must be an object")
        if value.get("model") != snapshot.execution_model_id:
            _fail(
                "base-engine child completion.model",
                "does not match activated raw base",
            )
        if not isinstance(value.get("choices"), list) or len(value["choices"]) != 1:
            _fail(
                "base-engine child completion.choices",
                "must contain exactly one choice",
            )
        if not isinstance(value.get("usage"), dict):
            _fail("base-engine child completion.usage", "must be an object")
        return value

    def _issue_attestation(
        self,
        *,
        nonce: str,
        evaluation: Mapping[str, Any],
        request: Mapping[str, Any],
        completion: Mapping[str, Any],
        snapshot: BaseActivationSnapshot,
    ) -> dict[str, Any]:
        activation = self.activation
        signing = self.config.runtime_signing
        if activation is None or not self._runtime_signer_ready:
            _fail("base-runtime attestation", "signing state is unavailable")
        if (
            isinstance(signing, BaseLocalRuntimeSigningConfig)
            and self._runtime_private_key is None
        ) or (
            isinstance(signing, BaseExternalRuntimeSigningConfig)
            and self._runtime_signer_bearer_token is None
        ):
            _fail("base-runtime attestation", "signer credential is unavailable")
        now = _validation_time(self._clock(), "base-runtime attestation clock")
        activation_expiry = _canonical_utc(
            activation.payload["expiresAtUtc"], "base-engine activation expiry"
        )
        expiry = min(
            now + timedelta(seconds=self.config.runtime_signing.receipt_ttl_seconds),
            activation_expiry,
        )
        if expiry <= now:
            _fail(
                "base-runtime attestation",
                "activation expires before a receipt can be issued",
            )
        self._sequence += 1
        payload: dict[str, Any] = {
            "schemaVersion": BASE_RUNTIME_ATTESTATION_SCHEMA_VERSION,
            "attestationId": _ATTESTATION_ID_PREFIX + _ZERO_SHA256,
            "decision": "attested-base-completion",
            "audience": self.config.runtime_signing.audience,
            "keyId": self.config.runtime_signing.key_id,
            "signerRole": self.config.runtime_signing.signer_role,
            "activation": {
                "activationId": activation.payload["activationId"],
                "envelopeSha256": activation.envelope_sha256,
                "payloadSha256": activation.payload_sha256,
            },
            "wrapperInstanceId": self._wrapper_instance_id,
            "sequence": self._sequence,
            "nonce": nonce,
            "evaluation": dict(evaluation),
            "requestSha256": hashlib.sha256(canonical_json_bytes(request)).hexdigest(),
            "completionSha256": hashlib.sha256(
                canonical_json_bytes(completion)
            ).hexdigest(),
            "model": activation.payload["model"],
            "engine": {
                "wrapperConfigSha256": snapshot.wrapper_config_sha256,
                "wrapperPackageSha256": snapshot.wrapper_package_sha256,
                "executableSha256": snapshot.engine_executable_sha256,
                "engineVersion": snapshot.engine_version,
                "containerImageDigest": snapshot.container_image_digest,
                "processId": snapshot.engine_process_id,
                "argvSha256": snapshot.engine_argv_sha256,
            },
            "issuedAtUtc": _utc_second(now),
            "expiresAtUtc": _utc_second(expiry),
        }
        payload["attestationId"] = _ATTESTATION_ID_PREFIX + _domain_sha256(
            BASE_RUNTIME_ATTESTATION_ID_DOMAIN, payload
        )
        _validate_runtime_attestation_payload(payload)
        envelope, payload_bytes = _new_unsigned_envelope(
            schema_version=BASE_RUNTIME_ATTESTATION_ENVELOPE_SCHEMA_VERSION,
            payload=payload,
            public_key_spki_sha256=snapshot.runtime_public_key_spki_sha256,
        )
        sized_envelope = dict(envelope)
        sized_envelope["signature"] = "A" * 86
        sized_response = canonical_json_bytes(
            {
                "schemaVersion": BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION,
                "completion": completion,
                "runtimeAttestation": sized_envelope,
            }
        )
        if len(sized_response) > self.config.service.max_response_bytes:
            _fail("base-engine attested completion response", "exceeds byte limit")
        signature_input = _signature_input(
            BASE_RUNTIME_SIGNATURE_DOMAIN, envelope, payload_bytes
        )
        if isinstance(signing, BaseLocalRuntimeSigningConfig):
            signature = _sign_p1363_low_s(self._runtime_private_key, signature_input)
        else:
            signature = self._request_external_runtime_signature(
                purpose="runtime-attestation", signature_input=signature_input
            )
        envelope["signature"] = _base64url_encode(signature)
        post_sign_time = _validation_time(
            self._clock(), "base-runtime attestation post-sign clock"
        )
        if post_sign_time < now:
            _fail("base-runtime attestation", "clock moved backwards while signing")
        verify_base_runtime_attestation(
            envelope=envelope,
            runtime_public_key_path=signing.public_key_path,
            activation=activation,
            expected_nonce=nonce,
            expected_evaluation=evaluation,
            request=request,
            completion=completion,
            now=post_sign_time,
        )
        return envelope

    def _completion_response(self, value: Any) -> ServiceResponse:
        if self.state is not WrapperState.READY:
            _fail("base-engine wrapper", "is not ready")
        with self._request_lock:
            snapshot = self._same_active_snapshot(full=False)
            nonce, evaluation, request = self._validate_attested_request(
                value, snapshot
            )
            if nonce in self._used_nonces:
                _request_fail(
                    "base-engine attested completion request.nonce",
                    "has already been used",
                )
            if len(self._used_nonces) >= self.config.service.max_attestations:
                _fail(
                    "base-runtime attestation",
                    "configured attestation limit is exhausted",
                )
            self._used_nonces.add(nonce)
            self._probe_child(snapshot)
            child_response = self._transport(
                "POST",
                self._child_url(CHAT_COMPLETIONS_PATH),
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._child_api_key}",
                },
                canonical_json_bytes(request),
                self.config.engine.request_timeout_seconds,
                self.config.service.max_response_bytes,
            )
            if child_response.status != 200:
                _fail(
                    "base-engine child completion",
                    f"returned HTTP {child_response.status}",
                )
            _require_json_content_type(
                child_response.headers, "base-engine child completion response"
            )
            completion = self._validate_completion(
                _parse_json_bytes(
                    child_response.body, "base-engine child completion response"
                ),
                snapshot,
            )
            current = self._same_active_snapshot(full=False)
            self._probe_child(current)
            envelope = self._issue_attestation(
                nonce=nonce,
                evaluation=evaluation,
                request=request,
                completion=completion,
                snapshot=current,
            )
            self._same_active_snapshot(full=False)
            if self.state is not WrapperState.READY:
                _fail("base-engine wrapper", "left READY while the receipt was signed")
            body = canonical_json_bytes(
                {
                    "schemaVersion": BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION,
                    "completion": completion,
                    "runtimeAttestation": envelope,
                }
            )
            if len(body) > self.config.service.max_response_bytes:
                _fail("base-engine attested completion response", "exceeds byte limit")
            return ServiceResponse(200, body)

    def handle_http_request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> ServiceResponse:
        if not self._authorize(headers):
            return _error_response(401, "unauthorized")
        if method != "POST":
            return _error_response(405, "method_not_allowed")
        if path != BASE_ATTESTED_COMPLETIONS_PATH:
            return _error_response(404, "not_found")
        if self.state is not WrapperState.READY:
            return _error_response(503, "not_ready")
        try:
            value = self._strict_request_json(headers, body)
            return self._completion_response(value)
        except RequestValidationError:
            return _error_response(400, "invalid_request")
        except ValidationError:
            self.fail_closed()
            return _error_response(503, "not_ready")
        except Exception:
            self.fail_closed()
            return _error_response(503, "not_ready")

    def _terminate_child(self) -> None:
        with self._state_lock:
            process = self._process
        if process is None:
            self._termination_error = None
            return
        ensure_group_stopped = getattr(process, "ensure_process_group_stopped", None)
        if process.poll() is not None:
            if callable(ensure_group_stopped):
                ensure_group_stopped(5)
            self._termination_error = None
            return
        try:
            process.terminate()
            process.wait(timeout=self.config.engine.shutdown_grace_seconds)
            if callable(ensure_group_stopped):
                ensure_group_stopped(5)
            self._termination_error = None
            return
        except (OSError, subprocess.TimeoutExpired, TimeoutError):
            pass
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired, TimeoutError) as error:
            if process.poll() is None:
                raise ValidationError(
                    "base-engine child could not be terminated and remains alive"
                ) from error
        if process.poll() is None:
            _fail("base-engine child", "could not be terminated and remains alive")
        if callable(ensure_group_stopped):
            ensure_group_stopped(5)
        self._termination_error = None

    def fail_closed(self) -> None:
        with self._state_lock:
            if self._state is not WrapperState.STOPPED:
                self._state = WrapperState.FAILED
            self._runtime_private_key = None
            self._runtime_private_key_password = None
            self._runtime_signer_bearer_token = None
            self._runtime_signer_ready = False
        self._stop_event.set()
        server = self._server
        if server is not None:
            threading.Thread(target=server.shutdown, daemon=True).start()
        try:
            self._terminate_child()
        except ValidationError as error:
            with self._state_lock:
                self._state = WrapperState.FAILED
            self._termination_error = error

    def stop(self) -> None:
        with self._state_lock:
            if self._state is WrapperState.STOPPED:
                return
            if self._state is not WrapperState.FAILED:
                self._state = WrapperState.STOPPING
            self._runtime_private_key = None
            self._runtime_private_key_password = None
            self._runtime_signer_bearer_token = None
            self._runtime_signer_ready = False
        self._stop_event.set()
        server = self._server
        if server is not None:
            if threading.current_thread() is threading.main_thread():
                threading.Thread(target=server.shutdown, daemon=True).start()
            else:
                server.shutdown()
        termination_error: ValidationError | None = None
        try:
            self._terminate_child()
        except ValidationError as error:
            termination_error = error
            self._termination_error = error
        monitor = self._monitor_thread
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=5)
        with self._state_lock:
            if termination_error is not None:
                self._state = WrapperState.FAILED
            elif self._state is not WrapperState.FAILED:
                self._state = WrapperState.STOPPED
        if termination_error is not None:
            raise termination_error

    def serve_forever(self) -> None:
        if self.state is not WrapperState.READY:
            _fail("base-engine wrapper", "must be READY before serving HTTP")
        wrapper = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = ""
            sys_version = ""

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(
                    wrapper.config.engine.request_timeout_seconds
                )

            def send_response(self, code: int, message: str | None = None) -> None:
                self.log_request(code)
                self.send_response_only(code, message)

            def send_error(
                self,
                code: int,
                message: str | None = None,
                explain: str | None = None,
            ) -> None:
                self._send(_error_response(code, "invalid_request"))

            def handle_expect_100(self) -> bool:
                self._send(_error_response(417, "expectation_failed"))
                return False

            def do_POST(self) -> None:  # noqa: N802
                if (
                    self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Encoding") is not None
                    or self.headers.get("Expect") is not None
                ):
                    self._send(_error_response(400, "invalid_request"))
                    return
                lengths = self.headers.get_all("Content-Length", failobj=[])
                if len(lengths) != 1:
                    self._send(_error_response(411, "length_required"))
                    return
                try:
                    length = int(lengths[0])
                except ValueError:
                    self._send(_error_response(400, "invalid_request"))
                    return
                if length < 0 or length > wrapper.config.service.max_request_bytes:
                    self._send(_error_response(413, "request_too_large"))
                    return
                if len(self.headers.get_all("Authorization", failobj=[])) != 1:
                    self._send(_error_response(401, "unauthorized"))
                    return
                if len(self.headers.get_all("Content-Type", failobj=[])) != 1:
                    self._send(_error_response(400, "invalid_request"))
                    return
                try:
                    body = self.rfile.read(length)
                except OSError:
                    self._send(_error_response(408, "request_timeout"))
                    return
                if len(body) != length:
                    self._send(_error_response(400, "invalid_request"))
                    return
                response = wrapper.handle_http_request(
                    "POST", self.path, dict(self.headers.items()), body
                )
                self._send(response)

            def do_GET(self) -> None:  # noqa: N802
                self._send(_error_response(405, "method_not_allowed"))

            do_HEAD = do_GET
            do_PUT = do_GET
            do_PATCH = do_GET
            do_DELETE = do_GET
            do_OPTIONS = do_GET
            do_TRACE = do_GET
            do_CONNECT = do_GET

            def _send(self, response: ServiceResponse) -> None:
                self.send_response(response.status)
                for name, value in response.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(response.body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response.body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer(
            (self.config.service.listen_host, self.config.service.listen_port), Handler
        )
        server.daemon_threads = True
        server.allow_reuse_address = False
        self._server = server
        if self.state is not WrapperState.READY:
            server.server_close()
            self._server = None
            _fail("base-engine wrapper", "left READY before the listener started")
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            server.server_close()
            self._server = None


def serve_base_evaluation_model(config_path: str | os.PathLike[str]) -> None:
    config = load_base_engine_wrapper_config(config_path)
    wrapper = BaseModelEngineWrapper.from_environment(config)
    previous_handlers: dict[int, Any] = {}
    signal_once = threading.Event()

    def request_stop(signum: int, frame: Any) -> None:
        if signal_once.is_set():
            return
        signal_once.set()
        threading.Thread(target=wrapper.stop, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        for candidate in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[candidate] = signal.getsignal(candidate)
            signal.signal(candidate, request_stop)
    try:
        wrapper.start()
        wrapper.serve_forever()
    finally:
        wrapper.stop()
        for candidate, previous in previous_handlers.items():
            signal.signal(candidate, previous)
