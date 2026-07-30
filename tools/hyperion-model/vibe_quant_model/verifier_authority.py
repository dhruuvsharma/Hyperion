from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, TypeVar

from .core import (
    ValidationError,
    _exact_keys,
    _fail,
    _reject_reparse_components,
    _sha256,
    _unique_pairs,
    canonical_json_bytes,
)


REQUEST_SCHEMA_VERSION = "daxalgo.verifier.headless-strategy-request/v1"
SOURCE_PROFILE = "daxalgo-sdk-headless-source/v1"
WORKER_RESULT_SCHEMA_VERSION = "daxalgo.verifier.headless-strategy-worker-result/v1"
RESULT_SCHEMA_VERSION_V1 = "daxalgo.vibe-quant.csharp-strategy-verification-result/v1"
RESULT_SCHEMA_VERSION = "daxalgo.vibe-quant.csharp-strategy-verification-result/v2"
SANDBOX_POLICY_PROFILE = "daxalgo.verifier.docker-sandbox-policy/v1"
VERIFIER_PLATFORM = "linux/amd64"

AUTHORITY_SCHEMA_VERSION = "daxalgo.vibe-quant.csharp-verifier-authority/v2"
AUTHORITY_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.csharp-verifier-authority-envelope/v2"
)
AUTHORITY_SCOPE = "standalone-research-evidence-only"
AUTHORITY_DECISION = "approved"
AUTHORITY_PAYLOAD_ENCODING = "canonical-json-base64url"
AUTHORITY_ALGORITHM = "ES256"
AUTHORITY_SIGNATURE_FORMAT = "ieee-p1363-low-s"
AUTHORITY_ID_PREFIX = "daxalgo-csharp-verifier-authority-sha256-"
AUTHORITY_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.csharp-verifier-authority-signing-bundle/v1"
)
AUTHORITY_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.csharp-verifier-authority-signature/v1"
)
AUTHORITY_SIGNING_BUNDLE_ID_PREFIX = (
    "daxalgo-csharp-verifier-authority-signing-bundle-sha256-"
)
AUTHORITY_EXTERNAL_SIGNATURE_ID_PREFIX = (
    "daxalgo-csharp-verifier-authority-signature-sha256-"
)
AUTHORITY_SIGNING_STATUS = "unsigned-non-authorizing"
AUTHORITY_SIGNING_HASH_ALGORITHM = "SHA-256"
AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE = "raw-message"
AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE = "sha256-digest"
AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
AUTHORITY_STATEMENT = (
    "This bounded reusable lease authorizes only standalone research verification; "
    "it grants no review, release, training, promotion, deployment, hosted, "
    "installation, compilation-consent, or execution authority outside the isolated "
    "verifier."
)

MAX_AUTHORITY_BYTES = 262_144
MAX_AUTHORITY_PAYLOAD_BYTES = 196_608
MAX_TOOLCHAIN_BYTES = 131_072
MAX_KEY_BYTES = 32_768
MAX_DOCKER_CLIENT_BYTES = 268_435_456
MAX_AUTHORITY_VALIDITY = timedelta(days=7)
MAX_AUTHORITY_SIGNING_BUNDLE_BYTES = 1_200_000
MAX_AUTHORITY_EXTERNAL_SIGNATURE_BYTES = 16_000
MAX_AUTHORITY_SIGNATURE_INPUT_BYTES = 262_144
MAX_AUTHORITY_DER_SIGNATURE_BYTES = 80

DOCKER_CLIENT_ENVIRONMENT_PROFILE = (
    "daxalgo.verifier.scrubbed-docker-client-environment/v1"
)

MEMORY_BYTES = 768 * 1024 * 1024
NOFILE_LIMIT = 256
CONTAINER_ENVIRONMENT = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
]
TMPFS = {
    "/tmp": {
        "sizeBytes": 64 * 1024 * 1024,
        "option": "rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700",
    },
    "/work": {
        "sizeBytes": 256 * 1024 * 1024,
        "option": "rw,noexec,nosuid,nodev,size=256m,uid=65532,gid=65532,mode=0700",
    },
}

_ZERO_SHA256 = "0" * 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IMAGE_RE = re.compile(r"^(?=.{1,500}$)[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_ENTRYPOINT_RE = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NPIPE_ENDPOINT_RE = re.compile(r"^npipe:////\./pipe/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_SIGNATURE_DOMAIN = b"daxalgo-csharp-verifier-authority-signature/v2\x00"
_ID_DOMAIN = b"daxalgo-csharp-verifier-authority-id/v2\x00"
_SIGNING_BUNDLE_ID_DOMAIN = (
    b"daxalgo-csharp-verifier-authority-signing-bundle-id/v1\x00"
)
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    b"daxalgo-csharp-verifier-authority-external-signature-id/v1\x00"
)
_SIGNING_BUNDLE_ID_RE = re.compile(
    r"^daxalgo-csharp-verifier-authority-signing-bundle-sha256-[0-9a-f]{64}$"
)
_EXTERNAL_SIGNATURE_ID_RE = re.compile(
    r"^daxalgo-csharp-verifier-authority-signature-sha256-[0-9a-f]{64}$"
)

_SIGNING_AUTHORITY_KEYS = {
    "csharpVerifierAuthorityIssuance",
    "review",
    "release",
    "training",
    "promotion",
    "deployment",
    "hosted",
    "installation",
    "compilationConsent",
    "verifierExecution",
    "strategyExecution",
}

_SIGNING_BUNDLE_KEYS = {
    "schemaVersion",
    "bundleId",
    "status",
    "authority",
    "trust",
    "authorityId",
    "payloadSha256",
    "payload",
    "unsignedEnvelopeSha256",
    "unsignedEnvelope",
    "validity",
    "signatureContract",
    "request",
}

_EXTERNAL_SIGNATURE_KEYS = {
    "schemaVersion",
    "signatureId",
    "signingBundleId",
    "signingBundleSha256",
    "authorityId",
    "payloadSha256",
    "unsignedEnvelopeSha256",
    "signatureInputSha256",
    "publicKeySpkiSha256",
    "mode",
    "format",
    "signature",
}

_ValidatedPublication = TypeVar("_ValidatedPublication")


@dataclass(frozen=True)
class CSharpVerifierAuthorityTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str


@dataclass(frozen=True)
class VerifiedCSharpVerifierAuthority:
    payload: dict[str, Any]
    payload_sha256: str
    envelope_sha256: str
    public_key_spki_sha256: str
    not_before_utc: datetime
    expires_at_utc: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "authorityId": self.payload["authorityId"],
            "payloadSha256": self.payload_sha256,
            "envelopeSha256": self.envelope_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "notBeforeUtc": self.payload["notBeforeUtc"],
            "expiresAtUtc": self.payload["expiresAtUtc"],
        }


@dataclass(frozen=True)
class VerifiedCSharpVerifierAuthoritySigningBundle:
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "signingBundlePath": str(self.path),
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "authorityId": self.payload["authorityId"],
            "payloadSha256": self.payload_sha256,
            "unsignedEnvelopeSha256": self.unsigned_envelope_sha256,
            "signatureInputSha256": self.signature_input_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "status": AUTHORITY_SIGNING_STATUS,
        }


def supported_sandbox_policy(entrypoint: str) -> dict[str, Any]:
    return {
        "profile": SANDBOX_POLICY_PROFILE,
        "platform": VERIFIER_PLATFORM,
        "entrypoint": entrypoint,
        "network": "none",
        "readOnlyRoot": True,
        "uid": 65532,
        "gid": 65532,
        "cpus": 1,
        "memoryBytes": MEMORY_BYTES,
        "memorySwapBytes": MEMORY_BYTES,
        "pidsLimit": 64,
        "nofileSoft": NOFILE_LIMIT,
        "nofileHard": NOFILE_LIMIT,
        "capDrop": ["ALL"],
        "noNewPrivileges": True,
        "seccomp": "docker-builtin",
        "environment": CONTAINER_ENVIRONMENT,
        "tmpfs": [
            {
                "path": path,
                "sizeBytes": TMPFS[path]["sizeBytes"],
                "options": ["rw", "noexec", "nosuid", "nodev"],
                "uid": 65532,
                "gid": 65532,
                "mode": "0700",
            }
            for path in sorted(TMPFS)
        ],
    }


def _text(value: Any, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _fail(field, f"must contain between {minimum} and {maximum} characters")
    if any(
        ord(character) < 32
        or 127 <= ord(character) <= 159
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        _fail(field, "contains a control character or unpaired surrogate")
    return value


def _identifier(value: Any, field: str) -> str:
    identifier = _text(value, field, 1, 128)
    if not _IDENTIFIER_RE.fullmatch(identifier):
        _fail(field, "contains an unsupported character")
    return identifier


def _canonical_utc(value: Any, field: str) -> datetime:
    text = _text(value, field, 20, 20)
    if not _UTC_RE.fullmatch(text):
        _fail(field, "must be canonical UTC to whole seconds")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValidationError(f"{field}: invalid UTC timestamp") from error


def _validation_time(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(field, "must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _fresh_validation_time(value: datetime | None, field: str) -> datetime:
    return _validation_time(
        value if value is not None else datetime.now(timezone.utc), field
    )


def _bounded_snapshot(
    path: Path,
    field: str,
    max_bytes: int,
    *,
    expected_link_count: int = 1,
) -> bytes:
    absolute = _reject_reparse_components(path, field)
    before = os.lstat(absolute)
    if not stat.S_ISREG(before.st_mode):
        _fail(field, f"regular file does not exist: {absolute}")
    if before.st_nlink != expected_link_count:
        if expected_link_count == 1:
            _fail(field, "hard-linked files are not accepted")
        _fail(field, f"must have exactly {expected_link_count} owned links")
    if before.st_size > max_bytes:
        _fail(field, f"exceeds the {max_bytes}-byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != expected_link_count:
            _fail(
                field,
                f"must remain a regular file with {expected_link_count} owned links",
            )
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _fail(field, "changed while it was being opened")
        raw = bytearray()
        while len(raw) <= max_bytes:
            block = os.read(descriptor, min(1_048_576, max_bytes + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > max_bytes:
            _fail(field, f"exceeds the {max_bytes}-byte limit")
        after = os.fstat(descriptor)
        if (
            after.st_nlink != expected_link_count
            or after.st_size != opened.st_size
            or getattr(after, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
        ):
            _fail(field, "changed while it was being read")
    finally:
        os.close(descriptor)
    return bytes(raw)


def _canonical_absolute_path(value: Any, field: str) -> Path:
    text = _text(value, field, 1, 1_024)
    path = Path(text)
    if not path.is_absolute():
        _fail(field, "must be an absolute host path")
    canonical = Path(os.path.abspath(os.fspath(path)))
    if os.fspath(canonical) != text:
        _fail(field, "must be a canonical absolute host path")
    return canonical


def _docker_daemon_endpoint(value: Any, field: str) -> str:
    endpoint = _text(value, field, 1, 500)
    if _NPIPE_ENDPOINT_RE.fullmatch(endpoint):
        return endpoint
    if endpoint.startswith("unix:///"):
        socket_path = endpoint.removeprefix("unix://")
        path = Path(socket_path)
        if path.is_absolute() and all(part not in {".", ".."} for part in path.parts):
            return endpoint
    _fail(field, "must be one explicit local npipe or unix socket endpoint")


def _docker_client_binding(path: Path) -> dict[str, Any]:
    absolute = _canonical_absolute_path(
        os.fspath(Path(path).absolute()), "C# verifier authority Docker client"
    )
    raw = _bounded_snapshot(
        absolute,
        "C# verifier authority Docker client",
        MAX_DOCKER_CLIENT_BYTES,
    )
    if not raw:
        _fail("C# verifier authority Docker client", "must not be empty")
    mode = os.lstat(absolute).st_mode
    if os.name != "nt" and mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0:
        _fail("C# verifier authority Docker client", "must be executable")
    return {
        "path": os.fspath(absolute),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
    }


def _parse_json(raw: bytes, field: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(field, "UTF-8 byte-order marks are not accepted")
    if b"\x00" in raw:
        _fail(field, "NUL bytes are not accepted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(
            f"{field}: invalid UTF-8 at byte {error.start}"
        ) from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda value: _fail(field, f"contains {value!r}"),
        )
    except json.JSONDecodeError as error:
        raise ValidationError(
            f"{field}: invalid JSON at line {error.lineno}, column {error.colno}: "
            f"{error.msg}"
        ) from error
    except RecursionError as error:
        raise ValidationError(f"{field}: exceeds the nesting limit") from error


def _canonical_document(raw: bytes, field: str) -> dict[str, Any]:
    value = _parse_json(raw, field)
    if not isinstance(value, dict):
        _fail(field, "root must be an object")
    if raw != canonical_json_bytes(value) + b"\n":
        _fail(field, "must use exact canonical JSON followed by one LF")
    return value


def _artifact(value: Any, field: str) -> dict[str, Any]:
    artifact = _exact_keys(value, {"name", "version", "sha256"}, field)
    _text(artifact["name"], f"{field}.name", 1, 256)
    _text(artifact["version"], f"{field}.version", 1, 128)
    _sha256(artifact["sha256"], f"{field}.sha256")
    return artifact


def validate_csharp_verifier_toolchain(
    value: Any, field: str = "C# verifier toolchain"
) -> dict[str, Any]:
    toolchain = _exact_keys(
        value,
        {
            "version",
            "worker",
            "runtime",
            "core",
            "sdk",
            "roslyn",
            "compilerClosure",
            "compilerClosureSha256",
        },
        field,
    )
    if toolchain["version"] != "1.0.0":
        _fail(f"{field}.version", "must be '1.0.0'")
    for name in ("worker", "runtime", "core", "sdk", "roslyn"):
        _artifact(toolchain[name], f"{field}.{name}")
    closure = toolchain["compilerClosure"]
    if not isinstance(closure, list) or not 1 <= len(closure) <= 64:
        _fail(f"{field}.compilerClosure", "must contain between 1 and 64 artifacts")
    names: set[str] = set()
    for index, raw in enumerate(closure):
        artifact = _artifact(raw, f"{field}.compilerClosure[{index}]")
        if artifact["name"] in names:
            _fail(
                f"{field}.compilerClosure[{index}].name",
                "duplicates an earlier compiler artifact",
            )
        names.add(artifact["name"])
    if closure != sorted(
        closure, key=lambda artifact: (artifact["name"], artifact["version"])
    ):
        _fail(f"{field}.compilerClosure", "must use deterministic name/version order")
    closure_bytes = json.dumps(
        [
            {
                "name": artifact["name"],
                "version": artifact["version"],
                "sha256": artifact["sha256"],
            }
            for artifact in closure
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_closure_sha256 = hashlib.sha256(closure_bytes).hexdigest()
    if (
        _sha256(toolchain["compilerClosureSha256"], f"{field}.compilerClosureSha256")
        != expected_closure_sha256
    ):
        _fail(
            f"{field}.compilerClosureSha256",
            "does not match the ordered compiler closure evidence",
        )
    identities = {
        (artifact["name"], artifact["version"], artifact["sha256"])
        for artifact in closure
    }
    for name in ("runtime", "core", "sdk"):
        artifact = toolchain[name]
        if (
            artifact["name"],
            artifact["version"],
            artifact["sha256"],
        ) not in identities:
            _fail(f"{field}.{name}", "is absent from the frozen compiler closure")
    return toolchain


def csharp_verifier_toolchain_sha256(toolchain: Mapping[str, Any]) -> str:
    validated = validate_csharp_verifier_toolchain(dict(toolchain))
    return hashlib.sha256(canonical_json_bytes(validated)).hexdigest()


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_keys(
        value,
        {
            "schemaVersion",
            "authorityId",
            "decision",
            "scope",
            "reusable",
            "reviewAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "promotionAuthorized",
            "deploymentAuthorized",
            "hostedAuthorized",
            "installationAuthorized",
            "issuedAtUtc",
            "notBeforeUtc",
            "expiresAtUtc",
            "verifier",
            "approval",
            "statement",
        },
        "C# verifier authority payload",
    )
    constants = {
        "schemaVersion": AUTHORITY_SCHEMA_VERSION,
        "decision": AUTHORITY_DECISION,
        "scope": AUTHORITY_SCOPE,
        "reusable": True,
        "reviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "promotionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedAuthorized": False,
        "installationAuthorized": False,
        "statement": AUTHORITY_STATEMENT,
    }
    for name, expected in constants.items():
        if isinstance(expected, bool) and type(payload[name]) is not bool:
            _fail(
                f"C# verifier authority payload.{name}",
                "must be a JSON Boolean",
            )
        if payload[name] != expected:
            _fail(
                f"C# verifier authority payload.{name}", "does not match the contract"
            )

    issued = _canonical_utc(payload["issuedAtUtc"], "authority payload.issuedAtUtc")
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "authority payload.notBeforeUtc"
    )
    expires = _canonical_utc(payload["expiresAtUtc"], "authority payload.expiresAtUtc")
    if not issued <= not_before < expires:
        _fail(
            "C# verifier authority payload validity",
            "must satisfy issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_AUTHORITY_VALIDITY:
        _fail("C# verifier authority payload validity", "must not exceed seven days")

    verifier = _exact_keys(
        payload["verifier"],
        {
            "image",
            "dockerRuntime",
            "platform",
            "entrypoint",
            "protocol",
            "toolchain",
            "toolchainSha256",
            "sandboxPolicy",
        },
        "authority payload.verifier",
    )
    image = _exact_keys(
        verifier["image"],
        {"reference", "digest", "imageId"},
        "authority payload.verifier.image",
    )
    reference = _text(
        image["reference"], "authority payload.verifier.image.reference", 1, 500
    )
    if not _IMAGE_RE.fullmatch(reference):
        _fail(
            "authority payload.verifier.image.reference",
            "must be an exact repository@sha256 reference",
        )
    digest = image["digest"]
    if not isinstance(digest, str) or not _IMAGE_ID_RE.fullmatch(digest):
        _fail(
            "authority payload.verifier.image.digest",
            "must be a sha256 digest",
        )
    if reference.rsplit("@", 1)[1] != digest:
        _fail(
            "authority payload.verifier.image.digest",
            "does not match the exact image reference",
        )
    if not isinstance(image["imageId"], str) or not _IMAGE_ID_RE.fullmatch(
        image["imageId"]
    ):
        _fail("authority payload.verifier.image.imageId", "must be a sha256 image ID")

    docker_runtime = _exact_keys(
        verifier["dockerRuntime"],
        {"client", "daemonEndpoint", "environmentPolicy"},
        "authority payload.verifier.dockerRuntime",
    )
    docker_client = _exact_keys(
        docker_runtime["client"],
        {"path", "sha256", "sizeBytes"},
        "authority payload.verifier.dockerRuntime.client",
    )
    _canonical_absolute_path(
        docker_client["path"], "authority payload.verifier.dockerRuntime.client.path"
    )
    _sha256(
        docker_client["sha256"],
        "authority payload.verifier.dockerRuntime.client.sha256",
    )
    size_bytes = docker_client["sizeBytes"]
    if (
        isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or not 1 <= size_bytes <= MAX_DOCKER_CLIENT_BYTES
    ):
        _fail(
            "authority payload.verifier.dockerRuntime.client.sizeBytes",
            f"must be between 1 and {MAX_DOCKER_CLIENT_BYTES}",
        )
    _docker_daemon_endpoint(
        docker_runtime["daemonEndpoint"],
        "authority payload.verifier.dockerRuntime.daemonEndpoint",
    )
    if docker_runtime["environmentPolicy"] != DOCKER_CLIENT_ENVIRONMENT_PROFILE:
        _fail(
            "authority payload.verifier.dockerRuntime.environmentPolicy",
            "does not match the supported scrubbed environment policy",
        )
    if verifier["platform"] != VERIFIER_PLATFORM:
        _fail("authority payload.verifier.platform", "does not match the contract")
    entrypoint = _text(
        verifier["entrypoint"], "authority payload.verifier.entrypoint", 1, 500
    )
    if not _ENTRYPOINT_RE.fullmatch(entrypoint):
        _fail("authority payload.verifier.entrypoint", "must be an absolute path")

    protocol = _exact_keys(
        verifier["protocol"],
        {
            "requestSchemaVersion",
            "sourceProfile",
            "workerResultSchemaVersion",
            "verificationResultSchemaVersion",
        },
        "authority payload.verifier.protocol",
    )
    expected_protocol = {
        "requestSchemaVersion": REQUEST_SCHEMA_VERSION,
        "sourceProfile": SOURCE_PROFILE,
        "workerResultSchemaVersion": WORKER_RESULT_SCHEMA_VERSION,
        "verificationResultSchemaVersion": RESULT_SCHEMA_VERSION,
    }
    if protocol != expected_protocol:
        _fail(
            "authority payload.verifier.protocol",
            "does not match the supported protocol",
        )

    toolchain = validate_csharp_verifier_toolchain(
        verifier["toolchain"], "authority payload.verifier.toolchain"
    )
    expected_toolchain_sha256 = csharp_verifier_toolchain_sha256(toolchain)
    if (
        _sha256(
            verifier["toolchainSha256"],
            "authority payload.verifier.toolchainSha256",
        )
        != expected_toolchain_sha256
    ):
        _fail(
            "authority payload.verifier.toolchainSha256",
            "does not match the exact toolchain",
        )

    sandbox = _exact_keys(
        verifier["sandboxPolicy"],
        {"profile", "sha256", "policy"},
        "authority payload.verifier.sandboxPolicy",
    )
    if sandbox["profile"] != SANDBOX_POLICY_PROFILE:
        _fail(
            "authority payload.verifier.sandboxPolicy.profile",
            "does not match the supported profile",
        )
    expected_policy = supported_sandbox_policy(entrypoint)
    if canonical_json_bytes(sandbox["policy"]) != canonical_json_bytes(expected_policy):
        _fail(
            "authority payload.verifier.sandboxPolicy.policy",
            "does not match the hardcoded supported policy",
        )
    expected_policy_sha256 = hashlib.sha256(
        canonical_json_bytes(expected_policy)
    ).hexdigest()
    if (
        _sha256(sandbox["sha256"], "authority payload.verifier.sandboxPolicy.sha256")
        != expected_policy_sha256
    ):
        _fail(
            "authority payload.verifier.sandboxPolicy.sha256",
            "does not match the exact supported policy",
        )

    approval = _exact_keys(
        payload["approval"],
        {"approvalId", "actorId", "actorRole", "reference", "approvedAtUtc"},
        "authority payload.approval",
    )
    for name in ("approvalId", "actorId", "actorRole"):
        _identifier(approval[name], f"authority payload.approval.{name}")
    _text(approval["reference"], "authority payload.approval.reference", 1, 500)
    approved = _canonical_utc(
        approval["approvedAtUtc"], "authority payload.approval.approvedAtUtc"
    )
    if approved > issued:
        _fail(
            "C# verifier authority payload validity",
            "must satisfy approvedAt <= issuedAt",
        )

    if payload["authorityId"] != csharp_verifier_authority_id(payload):
        _fail(
            "C# verifier authority payload.authorityId",
            "does not match the content-derived identity",
        )
    return payload


def csharp_verifier_authority_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["authorityId"] = AUTHORITY_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(_ID_DOMAIN + canonical_json_bytes(normalized)).hexdigest()
    return AUTHORITY_ID_PREFIX + digest


def _content_addressed_id(
    value: Mapping[str, Any],
    *,
    id_field: str,
    prefix: str,
    domain: bytes,
) -> str:
    normalized = dict(value)
    normalized[id_field] = prefix + _ZERO_SHA256
    digest = hashlib.sha256(domain + canonical_json_bytes(normalized)).hexdigest()
    return prefix + digest


def csharp_verifier_authority_signing_bundle_id(value: Mapping[str, Any]) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=AUTHORITY_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def csharp_verifier_authority_external_signature_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=AUTHORITY_EXTERNAL_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


def _framed(fields: Iterable[str | bytes]) -> bytes:
    framed = bytearray()
    for field in fields:
        raw = field if isinstance(field, bytes) else field.encode("utf-8")
        framed.extend(len(raw).to_bytes(8, "big", signed=False))
        framed.extend(raw)
    return bytes(framed)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: Any, field: str, max_bytes: int) -> bytes:
    if not isinstance(value, str) or not value or not _BASE64URL_RE.fullmatch(value):
        _fail(field, "must be canonical unpadded base64url")
    try:
        raw = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as error:
        raise ValidationError(f"{field}: invalid base64url") from error
    if len(raw) > max_bytes or _base64url_encode(raw) != value:
        _fail(field, "is noncanonical or exceeds its byte limit")
    return raw


def _signature_input(envelope: Mapping[str, Any], payload_bytes: bytes) -> bytes:
    return _framed(
        (
            _SIGNATURE_DOMAIN,
            envelope["schemaVersion"],
            envelope["payloadType"],
            envelope["payloadEncoding"],
            envelope["algorithm"],
            envelope["signatureFormat"],
            envelope["audience"],
            envelope["keyId"],
            envelope["signerRole"],
            envelope["publicKeySpkiSha256"],
            envelope["payloadSha256"],
            payload_bytes,
        )
    )


def _unsigned_envelope(
    payload_bytes: bytes,
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": AUTHORITY_ENVELOPE_SCHEMA_VERSION,
        "payloadType": AUTHORITY_SCHEMA_VERSION,
        "payloadEncoding": AUTHORITY_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": AUTHORITY_ALGORITHM,
        "signatureFormat": AUTHORITY_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


def _crypto_modules() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError:
        _fail(
            "C# verifier authority cryptography",
            "requires the optional 'promote' dependency",
        )
    return (
        InvalidSignature,
        hashes,
        serialization,
        ec,
        (decode_dss_signature, encode_dss_signature),
    )


def _load_public_key(path: Path) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _bounded_snapshot(path, "C# verifier authority public key", MAX_KEY_BYTES)
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        _fail("C# verifier authority public key", f"must be valid PEM: {error}")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("C# verifier authority public key", "must be EC P-256")
    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, hashlib.sha256(spki).hexdigest()


def _load_private_key(path: Path, password: bytes | None) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _bounded_snapshot(path, "C# verifier authority private key", MAX_KEY_BYTES)
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as error:
        _fail("C# verifier authority private key", f"must be valid PEM: {error}")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("C# verifier authority private key", "must be EC P-256")
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, hashlib.sha256(spki).hexdigest()


def _sign_p1363_low_s(private_key: Any, data: bytes) -> bytes:
    _, hashes, _, ec, utilities = _crypto_modules()
    decode_dss_signature, _ = utilities
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    if s > _P256_HALF_ORDER:
        s = _P256_ORDER - s
    if not (1 <= r < _P256_ORDER and 1 <= s <= _P256_HALF_ORDER):
        _fail("C# verifier authority signature", "signer returned invalid values")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_p1363_low_s(public_key: Any, data: bytes, signature: bytes) -> None:
    InvalidSignature, hashes, _, ec, utilities = _crypto_modules()
    _, encode_dss_signature = utilities
    if len(signature) != 64:
        _fail("C# verifier authority signature", "must be exactly 64-byte IEEE-P1363")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        _fail("C# verifier authority signature", "contains out-of-range values")
    if s > _P256_HALF_ORDER:
        _fail("C# verifier authority signature", "must use canonical low-S form")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        _fail(
            "C# verifier authority signature",
            "does not verify with the pinned public key",
        )


def _validate_trust(
    trust: CSharpVerifierAuthorityTrust,
) -> tuple[Any, str, str, str, str]:
    if not isinstance(trust, CSharpVerifierAuthorityTrust):
        _fail("C# verifier authority trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(Path(trust.public_key_path))
    expected_spki = _sha256(
        trust.public_key_spki_sha256,
        "C# verifier authority trust.publicKeySpkiSha256",
    )
    if actual_spki != expected_spki:
        _fail(
            "C# verifier authority trust.publicKeySpkiSha256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "C# verifier authority trust.audience"),
        _identifier(trust.key_id, "C# verifier authority trust.keyId"),
        _identifier(trust.signer_role, "C# verifier authority trust.signerRole"),
    )


def _build_authority_payload(
    *,
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
) -> dict[str, Any]:
    if _identifier(actor_role, "C# verifier authority actorRole") != signer_role:
        _fail("C# verifier authority actorRole", "must match the trusted signer role")
    toolchain_raw = _bounded_snapshot(
        Path(toolchain_path), "C# verifier authority toolchain", MAX_TOOLCHAIN_BYTES
    )
    toolchain = _canonical_document(toolchain_raw, "C# verifier authority toolchain")
    toolchain = validate_csharp_verifier_toolchain(toolchain)
    if not isinstance(image_reference, str) or not _IMAGE_RE.fullmatch(image_reference):
        _fail(
            "C# verifier authority image",
            "must be an exact repository@sha256 reference",
        )
    image_digest = image_reference.rsplit("@", 1)[1]
    if not isinstance(image_id, str) or not _IMAGE_ID_RE.fullmatch(image_id):
        _fail("C# verifier authority imageId", "must be a sha256 image ID")
    if not isinstance(entrypoint, str) or not _ENTRYPOINT_RE.fullmatch(entrypoint):
        _fail("C# verifier authority entrypoint", "must be an absolute path")
    docker_client = _docker_client_binding(Path(docker_client_path))
    daemon_endpoint = _docker_daemon_endpoint(
        docker_daemon_endpoint,
        "C# verifier authority Docker daemon endpoint",
    )
    policy = supported_sandbox_policy(entrypoint)
    policy_sha256 = hashlib.sha256(canonical_json_bytes(policy)).hexdigest()
    payload: dict[str, Any] = {
        "schemaVersion": AUTHORITY_SCHEMA_VERSION,
        "authorityId": AUTHORITY_ID_PREFIX + _ZERO_SHA256,
        "decision": AUTHORITY_DECISION,
        "scope": AUTHORITY_SCOPE,
        "reusable": True,
        "reviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "promotionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedAuthorized": False,
        "installationAuthorized": False,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "verifier": {
            "image": {
                "reference": image_reference,
                "digest": image_digest,
                "imageId": image_id,
            },
            "dockerRuntime": {
                "client": docker_client,
                "daemonEndpoint": daemon_endpoint,
                "environmentPolicy": DOCKER_CLIENT_ENVIRONMENT_PROFILE,
            },
            "platform": VERIFIER_PLATFORM,
            "entrypoint": entrypoint,
            "protocol": {
                "requestSchemaVersion": REQUEST_SCHEMA_VERSION,
                "sourceProfile": SOURCE_PROFILE,
                "workerResultSchemaVersion": WORKER_RESULT_SCHEMA_VERSION,
                "verificationResultSchemaVersion": RESULT_SCHEMA_VERSION,
            },
            "toolchain": toolchain,
            "toolchainSha256": csharp_verifier_toolchain_sha256(toolchain),
            "sandboxPolicy": {
                "profile": SANDBOX_POLICY_PROFILE,
                "sha256": policy_sha256,
                "policy": policy,
            },
        },
        "approval": {
            "approvalId": approval_id,
            "actorId": actor_id,
            "actorRole": actor_role,
            "reference": approval_reference,
            "approvedAtUtc": approved_at_utc,
        },
        "statement": AUTHORITY_STATEMENT,
    }
    payload["authorityId"] = csharp_verifier_authority_id(payload)
    return _validate_payload(payload)


def _ensure_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> None:
    not_before = _canonical_utc(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "must be active")


def _build_signing_bundle_document(
    payload: Mapping[str, Any],
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_AUTHORITY_PAYLOAD_BYTES:
        _fail("C# verifier authority payload", "exceeds its byte limit")
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) + 1 > MAX_AUTHORITY_BYTES:
        _fail("C# verifier authority unsigned envelope", "exceeds its byte limit")
    signature_preimage = _signature_input(envelope, payload_bytes)
    if len(signature_preimage) > MAX_AUTHORITY_SIGNATURE_INPUT_BYTES:
        _fail("C# verifier authority signature preimage", "exceeds its byte limit")
    signature_digest = hashlib.sha256(signature_preimage).digest()
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    unsigned_envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    bundle: dict[str, Any] = {
        "schemaVersion": AUTHORITY_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": AUTHORITY_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": AUTHORITY_SIGNING_STATUS,
        "authority": {name: False for name in sorted(_SIGNING_AUTHORITY_KEYS)},
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": audience,
            "keyId": key_id,
            "signerRole": signer_role,
        },
        "authorityId": payload["authorityId"],
        "payloadSha256": payload_sha256,
        "payload": _base64url_encode(payload_bytes),
        "unsignedEnvelopeSha256": unsigned_envelope_sha256,
        "unsignedEnvelope": _base64url_encode(envelope_bytes),
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
        "signatureContract": {
            "algorithm": AUTHORITY_ALGORITHM,
            "hashAlgorithm": AUTHORITY_SIGNING_HASH_ALGORITHM,
            "inputEncoding": "base64url",
            "acceptedModes": [
                AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE,
                AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
            ],
            "acceptedSignatureFormats": [
                AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT,
                AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "authorityId": payload["authorityId"],
            "payloadSha256": payload_sha256,
            "unsignedEnvelopeSha256": unsigned_envelope_sha256,
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = csharp_verifier_authority_signing_bundle_id(bundle)
    return bundle


def _validate_signing_bundle_document(
    value: Mapping[str, Any],
    *,
    path: Path,
    bundle_sha256: str,
    expected_payload: Mapping[str, Any],
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    now: datetime,
) -> VerifiedCSharpVerifierAuthoritySigningBundle:
    supplied = dict(value)
    bundle = _exact_keys(
        supplied, _SIGNING_BUNDLE_KEYS, "C# verifier authority signing bundle"
    )
    bundle_bytes = canonical_json_bytes(bundle)
    if len(bundle_bytes) > MAX_AUTHORITY_SIGNING_BUNDLE_BYTES:
        _fail("C# verifier authority signing bundle", "exceeds its byte limit")
    parsed_bundle = _parse_json(bundle_bytes, "C# verifier authority signing bundle")
    if not isinstance(parsed_bundle, dict) or bundle_bytes != canonical_json_bytes(
        parsed_bundle
    ):
        _fail("C# verifier authority signing bundle", "must be exact canonical JSON")
    bundle = parsed_bundle
    if bundle["schemaVersion"] != AUTHORITY_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("C# verifier authority signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != AUTHORITY_SIGNING_STATUS:
        _fail(
            "C# verifier authority signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority = _exact_keys(
        bundle["authority"],
        _SIGNING_AUTHORITY_KEYS,
        "C# verifier authority signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"C# verifier authority signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )
    bundle_trust = _exact_keys(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "C# verifier authority signing bundle.trust",
    )
    expected_trust = {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }
    if bundle_trust != expected_trust:
        _fail(
            "C# verifier authority signing bundle.trust",
            "does not match externally pinned trust",
        )
    contract = _exact_keys(
        bundle["signatureContract"],
        {
            "algorithm",
            "hashAlgorithm",
            "inputEncoding",
            "acceptedModes",
            "acceptedSignatureFormats",
        },
        "C# verifier authority signing bundle.signatureContract",
    )
    expected_contract = {
        "algorithm": AUTHORITY_ALGORITHM,
        "hashAlgorithm": AUTHORITY_SIGNING_HASH_ALGORITHM,
        "inputEncoding": "base64url",
        "acceptedModes": [
            AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE,
            AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE,
        ],
        "acceptedSignatureFormats": [
            AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT,
            AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    if contract != expected_contract:
        _fail(
            "C# verifier authority signing bundle.signatureContract",
            "does not match the contract",
        )

    expected_payload_document = _validate_payload(dict(expected_payload))
    expected_payload_bytes = canonical_json_bytes(expected_payload_document)
    payload_bytes = _base64url_decode(
        bundle["payload"],
        "C# verifier authority signing bundle.payload",
        MAX_AUTHORITY_PAYLOAD_BYTES,
    )
    if payload_bytes != expected_payload_bytes:
        _fail(
            "C# verifier authority signing bundle.payload",
            "does not match the exact freshly derived authority payload",
        )
    payload = _parse_json(payload_bytes, "C# verifier authority signing bundle payload")
    if not isinstance(payload, dict) or payload_bytes != canonical_json_bytes(payload):
        _fail("C# verifier authority signing bundle payload", "must be canonical JSON")
    payload = _validate_payload(payload)
    _ensure_payload_active(payload, now, "C# verifier authority signing bundle payload")
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            bundle["payloadSha256"],
            "C# verifier authority signing bundle.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "C# verifier authority signing bundle.payloadSha256",
            "does not match exact payload bytes",
        )

    unsigned_envelope_bytes = _base64url_decode(
        bundle["unsignedEnvelope"],
        "C# verifier authority signing bundle.unsignedEnvelope",
        MAX_AUTHORITY_BYTES,
    )
    unsigned_envelope = _parse_json(
        unsigned_envelope_bytes,
        "C# verifier authority signing bundle unsigned envelope",
    )
    if not isinstance(unsigned_envelope, dict) or unsigned_envelope_bytes != (
        canonical_json_bytes(unsigned_envelope)
    ):
        _fail(
            "C# verifier authority signing bundle unsigned envelope",
            "must be canonical JSON",
        )
    expected_envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if unsigned_envelope != expected_envelope:
        _fail(
            "C# verifier authority signing bundle.unsignedEnvelope",
            "does not match the exact unsigned authority envelope",
        )
    unsigned_envelope_sha256 = hashlib.sha256(unsigned_envelope_bytes).hexdigest()
    if (
        _sha256(
            bundle["unsignedEnvelopeSha256"],
            "C# verifier authority signing bundle.unsignedEnvelopeSha256",
        )
        != unsigned_envelope_sha256
    ):
        _fail(
            "C# verifier authority signing bundle.unsignedEnvelopeSha256",
            "does not match exact unsigned envelope bytes",
        )

    expected_payload_bindings = {
        "authorityId": payload["authorityId"],
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
    }
    for name, expected in expected_payload_bindings.items():
        if bundle[name] != expected:
            _fail(
                f"C# verifier authority signing bundle.{name}",
                "does not match the exact payload",
            )
    request = _exact_keys(
        bundle["request"],
        {
            "authorityId",
            "payloadSha256",
            "unsignedEnvelopeSha256",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "C# verifier authority signing bundle.request",
    )
    expected_request_bindings = {
        "authorityId": payload["authorityId"],
        "payloadSha256": payload_sha256,
        "unsignedEnvelopeSha256": unsigned_envelope_sha256,
    }
    for name, expected in expected_request_bindings.items():
        if request[name] != expected:
            _fail(
                f"C# verifier authority signing bundle.request.{name}",
                "does not match the exact signing bundle",
            )
    signature_preimage = _signature_input(unsigned_envelope, payload_bytes)
    supplied_preimage = _base64url_decode(
        request["signaturePreimage"],
        "C# verifier authority signing bundle.request.signaturePreimage",
        MAX_AUTHORITY_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != signature_preimage:
        _fail(
            "C# verifier authority signing bundle.request.signaturePreimage",
            "does not match the exact signature preimage",
        )
    signature_digest = hashlib.sha256(signature_preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "C# verifier authority signing bundle.request.signatureInput",
        32,
    )
    if len(supplied_digest) != 32 or supplied_digest != signature_digest:
        _fail(
            "C# verifier authority signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "C# verifier authority signing bundle.request.signatureInputSha256",
        )
        != signature_digest.hex()
    ):
        _fail(
            "C# verifier authority signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id != csharp_verifier_authority_signing_bundle_id(bundle)
    ):
        _fail(
            "C# verifier authority signing bundle.bundleId",
            "does not match the content-derived identity",
        )
    return VerifiedCSharpVerifierAuthoritySigningBundle(
        path=path,
        bundle=bundle,
        bundle_sha256=bundle_sha256,
        bundle_id=bundle_id,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        unsigned_envelope=unsigned_envelope,
        unsigned_envelope_bytes=unsigned_envelope_bytes,
        unsigned_envelope_sha256=unsigned_envelope_sha256,
        signature_preimage=signature_preimage,
        signature_input_sha256=signature_digest.hex(),
        public_key_spki_sha256=public_key_spki_sha256,
    )


def _normalize_external_signature(
    value: Any,
    *,
    signature_format: Any,
    signature_mode: Any,
    public_key: Any,
    signature_preimage: bytes,
    signature_digest: bytes,
    field: str,
) -> bytes:
    InvalidSignature, hashes, _, ec, utilities = _crypto_modules()
    decode_dss_signature, encode_dss_signature = utilities
    try:
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    except ImportError:
        _fail(
            "C# verifier authority external signature cryptography",
            "requires the optional 'verify' dependency",
        )
    if signature_format == AUTHORITY_EXTERNAL_P1363_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, 64)
        if len(signature) != 64:
            _fail(field, "must be exactly 64-byte fixed IEEE-P1363")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif signature_format == AUTHORITY_EXTERNAL_DER_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, MAX_AUTHORITY_DER_SIGNATURE_BYTES)
        try:
            r, s = decode_dss_signature(signature)
        except ValueError as error:
            raise ValidationError(f"{field}: is not canonical ECDSA DER") from error
        if encode_dss_signature(r, s) != signature:
            _fail(field, "must use canonical ECDSA DER")
    else:
        _fail(
            f"{field} format",
            "must be 'asn1-der' or 'ieee-p1363-fixed-64'",
        )
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        _fail(field, "contains out-of-range P-256 values")
    if s > _P256_HALF_ORDER:
        s = _P256_ORDER - s
    normalized = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    der = encode_dss_signature(r, s)
    if signature_mode == AUTHORITY_EXTERNAL_RAW_MESSAGE_MODE:
        signed_value = signature_preimage
        algorithm = ec.ECDSA(hashes.SHA256())
    elif signature_mode == AUTHORITY_EXTERNAL_SHA256_DIGEST_MODE:
        signed_value = signature_digest
        algorithm = ec.ECDSA(Prehashed(hashes.SHA256()))
    else:
        _fail(
            f"{field} mode",
            "must be 'raw-message' or 'sha256-digest'",
        )
    try:
        public_key.verify(der, signed_value, algorithm)
    except InvalidSignature:
        _fail(field, "does not verify with the pinned public key")
    return normalized


def _build_external_signature_document(
    bundle: Mapping[str, Any],
    bundle_bytes: bytes | None = None,
    *,
    signature_mode: str,
    signature_format: str,
    signature: bytes,
) -> dict[str, Any]:
    bundle_document = dict(bundle)
    exact_bundle_bytes = (
        bundle_bytes
        if bundle_bytes is not None
        else canonical_json_bytes(bundle_document) + b"\n"
    )
    request = bundle_document["request"]
    document: dict[str, Any] = {
        "schemaVersion": AUTHORITY_SIGNATURE_SCHEMA_VERSION,
        "signatureId": AUTHORITY_EXTERNAL_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle_document["bundleId"],
        "signingBundleSha256": hashlib.sha256(exact_bundle_bytes).hexdigest(),
        "authorityId": bundle_document["authorityId"],
        "payloadSha256": bundle_document["payloadSha256"],
        "unsignedEnvelopeSha256": bundle_document["unsignedEnvelopeSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle_document["trust"]["publicKeySpkiSha256"],
        "mode": signature_mode,
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    document["signatureId"] = csharp_verifier_authority_external_signature_id(document)
    return document


def _validate_external_signature_document(
    value: Mapping[str, Any],
    *,
    signing_bundle: VerifiedCSharpVerifierAuthoritySigningBundle,
    public_key: Any,
) -> bytes:
    document = _exact_keys(
        dict(value),
        _EXTERNAL_SIGNATURE_KEYS,
        "C# verifier authority external signature",
    )
    if len(canonical_json_bytes(document)) > MAX_AUTHORITY_EXTERNAL_SIGNATURE_BYTES:
        _fail("C# verifier authority external signature", "exceeds its byte limit")
    if document["schemaVersion"] != AUTHORITY_SIGNATURE_SCHEMA_VERSION:
        _fail(
            "C# verifier authority external signature.schemaVersion",
            "is unsupported",
        )
    bundle = signing_bundle.bundle
    expected = {
        "signingBundleId": signing_bundle.bundle_id,
        "signingBundleSha256": signing_bundle.bundle_sha256,
        "authorityId": signing_bundle.payload["authorityId"],
        "payloadSha256": signing_bundle.payload_sha256,
        "unsignedEnvelopeSha256": signing_bundle.unsigned_envelope_sha256,
        "signatureInputSha256": signing_bundle.signature_input_sha256,
        "publicKeySpkiSha256": signing_bundle.public_key_spki_sha256,
    }
    for name, expected_value in expected.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"C# verifier authority external signature.{name}")
        if supplied != expected_value:
            _fail(
                f"C# verifier authority external signature.{name}",
                "does not match the exact signing bundle",
            )
    request = bundle["request"]
    signature_digest = _base64url_decode(
        request["signatureInput"],
        "C# verifier authority signing bundle.request.signatureInput",
        32,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        signature_mode=document["mode"],
        public_key=public_key,
        signature_preimage=signing_bundle.signature_preimage,
        signature_digest=signature_digest,
        field="C# verifier authority external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id != csharp_verifier_authority_external_signature_id(document)
    ):
        _fail(
            "C# verifier authority external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _validate_envelope(
    value: Any,
    *,
    trust: CSharpVerifierAuthorityTrust,
    now: datetime,
) -> VerifiedCSharpVerifierAuthority:
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    envelope = _exact_keys(
        value,
        {
            "schemaVersion",
            "payloadType",
            "payloadEncoding",
            "payloadSha256",
            "payload",
            "algorithm",
            "signatureFormat",
            "audience",
            "keyId",
            "signerRole",
            "publicKeySpkiSha256",
            "signature",
        },
        "C# verifier authority envelope",
    )
    constants = {
        "schemaVersion": AUTHORITY_ENVELOPE_SCHEMA_VERSION,
        "payloadType": AUTHORITY_SCHEMA_VERSION,
        "payloadEncoding": AUTHORITY_PAYLOAD_ENCODING,
        "algorithm": AUTHORITY_ALGORITHM,
        "signatureFormat": AUTHORITY_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(
                f"C# verifier authority envelope.{name}",
                "does not match trusted configuration",
            )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "C# verifier authority envelope.payload",
        MAX_AUTHORITY_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            envelope["payloadSha256"],
            "C# verifier authority envelope.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "C# verifier authority envelope.payloadSha256",
            "does not match the exact payload bytes",
        )
    payload = _parse_json(payload_bytes, "C# verifier authority payload")
    if not isinstance(payload, dict) or payload_bytes != canonical_json_bytes(payload):
        _fail("C# verifier authority payload", "must be exact canonical JSON")
    payload = _validate_payload(payload)
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "C# verifier authority payload.approval.actorRole",
            "must match the trusted signer role",
        )
    signature = _base64url_decode(
        envelope["signature"], "C# verifier authority envelope.signature", 64
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "C# verifier authority payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "C# verifier authority payload.expiresAtUtc"
    )
    if now < not_before or now >= expires:
        _fail("C# verifier authority payload validity", "is not active")
    return VerifiedCSharpVerifierAuthority(
        payload=payload,
        payload_sha256=payload_sha256,
        envelope_sha256=hashlib.sha256(canonical_json_bytes(envelope)).hexdigest(),
        public_key_spki_sha256=spki,
        not_before_utc=not_before,
        expires_at_utc=expires,
    )


def _validate_csharp_verifier_authority(
    authority_path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierAuthorityTrust,
    now: datetime | None = None,
    expected_link_count: int,
) -> VerifiedCSharpVerifierAuthority:
    current = _validation_time(
        now or datetime.now(timezone.utc), "C# verifier authority validation time"
    )
    raw = _bounded_snapshot(
        Path(authority_path),
        "C# verifier authority",
        MAX_AUTHORITY_BYTES,
        expected_link_count=expected_link_count,
    )
    envelope = _canonical_document(raw, "C# verifier authority")
    return _validate_envelope(envelope, trust=trust, now=current)


def validate_csharp_verifier_authority(
    authority_path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierAuthorityTrust,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierAuthority:
    return _validate_csharp_verifier_authority(
        authority_path,
        trust=trust,
        now=now,
        expected_link_count=1,
    )


def _read_canonical_handoff_document(
    path: str | os.PathLike[str],
    field: str,
    max_bytes: int,
    *,
    expected_link_count: int = 1,
) -> tuple[Path, bytes, dict[str, Any]]:
    resolved = _reject_reparse_components(Path(path), field)
    raw = _bounded_snapshot(
        resolved,
        field,
        max_bytes,
        expected_link_count=expected_link_count,
    )
    return resolved, raw, _canonical_document(raw, field)


def _preflight_signing_bundle_payload(
    value: Mapping[str, Any],
    *,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
) -> dict[str, Any]:
    bundle = _exact_keys(
        value, _SIGNING_BUNDLE_KEYS, "C# verifier authority signing bundle"
    )
    if bundle["schemaVersion"] != AUTHORITY_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("C# verifier authority signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != AUTHORITY_SIGNING_STATUS:
        _fail(
            "C# verifier authority signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority = _exact_keys(
        bundle["authority"],
        _SIGNING_AUTHORITY_KEYS,
        "C# verifier authority signing bundle.authority",
    )
    if any(type(value) is not bool or value for value in authority.values()):
        _fail(
            "C# verifier authority signing bundle.authority",
            "must contain only false non-authorizing flags",
        )
    bundle_trust = _exact_keys(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "C# verifier authority signing bundle.trust",
    )
    if bundle_trust != {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }:
        _fail(
            "C# verifier authority signing bundle.trust",
            "does not match externally pinned trust",
        )
    payload_bytes = _base64url_decode(
        bundle["payload"],
        "C# verifier authority signing bundle.payload",
        MAX_AUTHORITY_PAYLOAD_BYTES,
    )
    payload = _parse_json(payload_bytes, "C# verifier authority signing bundle payload")
    if not isinstance(payload, dict) or payload_bytes != canonical_json_bytes(payload):
        _fail("C# verifier authority signing bundle payload", "must be canonical JSON")
    payload = _validate_payload(payload)
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "C# verifier authority signing bundle payload.approval.actorRole",
            "must match the trusted signer role",
        )
    return payload


def _rebuild_authority_payload(
    expected_payload: Mapping[str, Any],
    *,
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    signer_role: str,
) -> dict[str, Any]:
    payload = _validate_payload(dict(expected_payload))
    approval = payload["approval"]
    return _build_authority_payload(
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        signer_role=signer_role,
        approval_id=approval["approvalId"],
        actor_id=approval["actorId"],
        actor_role=approval["actorRole"],
        approval_reference=approval["reference"],
        approved_at_utc=approval["approvedAtUtc"],
        issued_at_utc=payload["issuedAtUtc"],
        not_before_utc=payload["notBeforeUtc"],
        expires_at_utc=payload["expiresAtUtc"],
    )


def _verify_csharp_verifier_authority_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    trust: CSharpVerifierAuthorityTrust,
    now: datetime | None = None,
    expected_link_count: int,
) -> VerifiedCSharpVerifierAuthoritySigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    resolved, raw, document = _read_canonical_handoff_document(
        signing_bundle_path,
        "C# verifier authority signing bundle",
        MAX_AUTHORITY_SIGNING_BUNDLE_BYTES,
        expected_link_count=expected_link_count,
    )
    current = _fresh_validation_time(
        now, "C# verifier authority signing-bundle verification time"
    )
    payload = _preflight_signing_bundle_payload(
        document,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _ensure_payload_active(
        payload, current, "C# verifier authority signing bundle payload"
    )
    expected_payload = _rebuild_authority_payload(
        payload,
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        signer_role=signer_role,
    )
    current = _fresh_validation_time(
        now,
        "C# verifier authority signing-bundle post-replay verification time",
    )
    _ensure_payload_active(
        payload, current, "C# verifier authority signing bundle payload"
    )
    return _validate_signing_bundle_document(
        document,
        path=resolved,
        bundle_sha256=hashlib.sha256(raw).hexdigest(),
        expected_payload=expected_payload,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        now=current,
    )


def verify_csharp_verifier_authority_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    trust: CSharpVerifierAuthorityTrust,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierAuthoritySigningBundle:
    return _verify_csharp_verifier_authority_signing_bundle(
        signing_bundle_path,
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        trust=trust,
        now=now,
        expected_link_count=1,
    )


def prepare_csharp_verifier_authority_signing_bundle(
    *,
    output_path: str | os.PathLike[str],
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    trust: CSharpVerifierAuthorityTrust,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierAuthoritySigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    payload = _build_authority_payload(
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        signer_role=signer_role,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    current = _fresh_validation_time(
        now, "C# verifier authority signing-bundle creation time"
    )
    _ensure_payload_active(payload, current, "C# verifier authority payload")
    bundle = _build_signing_bundle_document(
        payload,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_AUTHORITY_SIGNING_BUNDLE_BYTES:
        _fail("C# verifier authority signing bundle", "exceeds its byte limit")
    bundle_sha256 = hashlib.sha256(serialized).hexdigest()
    _validate_signing_bundle_document(
        bundle,
        path=Path(output_path),
        bundle_sha256=bundle_sha256,
        expected_payload=payload,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        now=current,
    )
    current = _fresh_validation_time(
        now,
        "C# verifier authority signing-bundle pre-publication time",
    )
    _ensure_payload_active(payload, current, "C# verifier authority payload")

    def validate_staged(
        path: Path,
    ) -> VerifiedCSharpVerifierAuthoritySigningBundle:
        verified = verify_csharp_verifier_authority_signing_bundle(
            path,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            trust=trust,
            now=now,
        )
        if verified.bundle_sha256 != bundle_sha256:
            _fail(
                "C# verifier authority signing bundle",
                "changed during publication",
            )
        return verified

    def validate_precommit(
        path: Path,
    ) -> VerifiedCSharpVerifierAuthoritySigningBundle:
        verified = _verify_csharp_verifier_authority_signing_bundle(
            path,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            trust=trust,
            now=now,
            expected_link_count=2,
        )
        if verified.bundle_sha256 != bundle_sha256:
            _fail(
                "C# verifier authority signing bundle",
                "changed during publication",
            )
        return verified

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_staged,
        precommit_validator=validate_precommit,
        field="C# verifier authority signing-bundle output",
    )


def _validate_published_authority(
    path: Path,
    *,
    expected_payload: Mapping[str, Any],
    expected_envelope_sha256: str,
    trust: CSharpVerifierAuthorityTrust,
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    replay_live_inputs: bool,
    expected_link_count: int,
    now: datetime | None,
    field: str,
) -> VerifiedCSharpVerifierAuthority:
    if replay_live_inputs:
        _, _, _, _, signer_role = _validate_trust(trust)
        live_payload = _rebuild_authority_payload(
            expected_payload,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            signer_role=signer_role,
        )
        if live_payload != expected_payload:
            _fail(field, "live bindings changed during staged publication")
    verified = _validate_csharp_verifier_authority(
        path,
        trust=trust,
        now=_fresh_validation_time(now, f"{field} validation time"),
        expected_link_count=expected_link_count,
    )
    if (
        verified.payload != expected_payload
        or verified.envelope_sha256 != expected_envelope_sha256
    ):
        _fail(field, "changed during publication")
    return verified


def ensure_csharp_verifier_authority_active(
    verified: VerifiedCSharpVerifierAuthority, now: datetime
) -> None:
    if not isinstance(verified, VerifiedCSharpVerifierAuthority):
        _fail("C# verifier authority", "must be a verified authority")
    current = _validation_time(now, "C# verifier authority publication time")
    if current < verified.not_before_utc or current >= verified.expires_at_utc:
        _fail("C# verifier authority payload validity", "expired before publication")


def _file_identity(
    path: Path,
    field: str,
    *,
    expected_link_count: int | None = None,
) -> tuple[int, int]:
    checked = _reject_reparse_components(path, field)
    current = os.lstat(checked)
    if not stat.S_ISREG(current.st_mode):
        _fail(field, "must be a regular file")
    if expected_link_count is not None and current.st_nlink != expected_link_count:
        _fail(field, f"must have exactly {expected_link_count} owned links")
    return current.st_dev, current.st_ino


def _write_no_clobber(
    path: Path,
    raw: bytes,
    *,
    prepublish_validator: Callable[[Path], _ValidatedPublication],
    precommit_validator: Callable[[Path], _ValidatedPublication],
    field: str = "C# verifier authority output",
) -> _ValidatedPublication:
    """Replay one owned file, expose it with two links, then commit by unlink."""

    destination = _reject_reparse_components(path, field, allow_missing_suffix=True)
    parent = _reject_reparse_components(destination.parent, f"{field} parent")
    if not parent.is_dir():
        _fail(f"{field} parent", "must be an existing directory")
    if os.path.lexists(destination):
        _fail(field, f"already exists: {destination}")
    staged: Path | None = None
    owned_identity: tuple[int, int] | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        owned_identity = _file_identity(
            staged,
            f"{field} staging output",
            expected_link_count=1,
        )
        prepublish_validator(staged)
        if (
            _file_identity(
                staged,
                f"{field} staging output",
                expected_link_count=1,
            )
            != owned_identity
        ):
            _fail(
                field,
                "staging path ownership changed before installation",
            )
        try:
            os.link(staged, destination)
        except FileExistsError as error:
            raise ValidationError(f"{field}: already exists: {destination}") from error
        except OSError as error:
            raise ValidationError(
                f"{field}: atomic no-clobber install failed: {error}"
            ) from error
        if (
            _file_identity(destination, field, expected_link_count=2) != owned_identity
            or _file_identity(
                staged,
                f"{field} staging output",
                expected_link_count=2,
            )
            != owned_identity
        ):
            _fail(
                field,
                "path ownership changed during installation",
            )
        verified = precommit_validator(destination)
        if (
            _file_identity(destination, field, expected_link_count=2) != owned_identity
            or _file_identity(
                staged,
                f"{field} staging output",
                expected_link_count=2,
            )
            != owned_identity
        ):
            _fail(
                field,
                "path ownership changed before commit",
            )
        # This unlink is the commit point. Until it succeeds, ordinary consumers
        # reject the destination because the owned inode has two links. Every
        # fallible validation and identity check is complete before this call.
        staged.unlink()
        return verified
    except BaseException as error:
        residuals: list[str] = []
        destination_survived = False
        candidates = [candidate for candidate in (destination, staged) if candidate]
        for candidate in candidates:
            if candidate == staged and destination_survived:
                try:
                    staging_exists = os.path.lexists(candidate)
                except OSError:
                    residuals.append(f"{candidate} (preservation inspection failed)")
                    continue
                if not staging_exists:
                    residuals.append(
                        f"{candidate} (missing while the failed destination survived)"
                    )
                    continue
                if owned_identity is None:
                    residuals.append(
                        f"{candidate} (preserved with ownership unavailable)"
                    )
                    continue
                try:
                    staging_identity = _file_identity(
                        candidate, f"{field} cleanup path"
                    )
                except (OSError, ValidationError):
                    residuals.append(
                        f"{candidate} (preserved with ownership unavailable)"
                    )
                    continue
                suffix = (
                    "preserved to keep the failed destination consumer-invalid"
                    if staging_identity == owned_identity
                    else "raced replacement preserved"
                )
                residuals.append(f"{candidate} ({suffix})")
                continue
            try:
                exists = os.path.lexists(candidate)
            except OSError:
                residuals.append(f"{candidate} (inspection failed)")
                if candidate == destination:
                    destination_survived = True
                continue
            if not exists:
                continue
            if owned_identity is None:
                residuals.append(f"{candidate} (ownership unavailable)")
                if candidate == destination:
                    destination_survived = True
                continue
            try:
                current_identity = _file_identity(candidate, f"{field} cleanup path")
            except (OSError, ValidationError):
                residuals.append(f"{candidate} (ownership unavailable)")
                if candidate == destination:
                    destination_survived = True
                continue
            if current_identity != owned_identity:
                residuals.append(f"{candidate} (raced replacement preserved)")
                continue
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
            except OSError:
                residuals.append(str(candidate))
                if candidate == destination:
                    destination_survived = True
            else:
                try:
                    if os.path.lexists(candidate):
                        residuals.append(f"{candidate} (reappeared after cleanup)")
                        if candidate == destination:
                            destination_survived = True
                except OSError:
                    residuals.append(f"{candidate} (cleanup verification failed)")
                    if candidate == destination:
                        destination_survived = True
        if residuals:
            raise ValidationError(
                f"{field}: publication failed; residual staging or destination paths "
                "require inspection: " + "; ".join(residuals)
            ) from error
        raise


def finalize_csharp_verifier_authority(
    *,
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    trust: CSharpVerifierAuthorityTrust,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierAuthority:
    verified_bundle = verify_csharp_verifier_authority_signing_bundle(
        signing_bundle_path,
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        trust=trust,
        now=now,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "C# verifier authority external signature",
        MAX_AUTHORITY_EXTERNAL_SIGNATURE_BYTES,
    )
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    current_trust = {
        "publicKeySpkiSha256": spki,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }
    if (
        verified_bundle.bundle["trust"] != current_trust
        or verified_bundle.public_key_spki_sha256 != spki
    ):
        _fail(
            "C# verifier authority signing bundle trust",
            "changed while the authority was finalized",
        )
    signature = _validate_external_signature_document(
        signature_document,
        signing_bundle=verified_bundle,
        public_key=public_key,
    )
    live_payload = _rebuild_authority_payload(
        verified_bundle.payload,
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        signer_role=signer_role,
    )
    if live_payload != verified_bundle.payload:
        _fail(
            "C# verifier authority signing bundle payload",
            "live bindings changed while the authority was finalized",
        )
    current = _fresh_validation_time(now, "C# verifier authority finalization time")
    _ensure_payload_active(live_payload, current, "C# verifier authority payload")
    payload_bytes = canonical_json_bytes(live_payload)
    if payload_bytes != verified_bundle.payload_bytes:
        _fail(
            "C# verifier authority signing bundle payload",
            "changed while the authority was finalized",
        )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    if envelope != verified_bundle.unsigned_envelope:
        _fail(
            "C# verifier authority signing bundle unsigned envelope",
            "changed while the authority was finalized",
        )
    envelope["signature"] = _base64url_encode(signature)
    _validate_envelope(envelope, trust=trust, now=current)
    serialized = canonical_json_bytes(envelope) + b"\n"
    if len(serialized) > MAX_AUTHORITY_BYTES:
        _fail("C# verifier authority", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()

    def validate_staged(path: Path) -> VerifiedCSharpVerifierAuthority:
        return _validate_published_authority(
            path,
            expected_payload=live_payload,
            expected_envelope_sha256=envelope_sha256,
            trust=trust,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            replay_live_inputs=True,
            expected_link_count=1,
            now=now,
            field="C# verifier authority finalization output",
        )

    def validate_precommit(path: Path) -> VerifiedCSharpVerifierAuthority:
        return _validate_published_authority(
            path,
            expected_payload=live_payload,
            expected_envelope_sha256=envelope_sha256,
            trust=trust,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            replay_live_inputs=True,
            expected_link_count=2,
            now=now,
            field="C# verifier authority finalization output",
        )

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_staged,
        precommit_validator=validate_precommit,
        field="C# verifier authority finalization output",
    )


def create_csharp_verifier_authority(
    *,
    output_path: str | os.PathLike[str],
    toolchain_path: str | os.PathLike[str],
    image_reference: str,
    image_id: str,
    entrypoint: str,
    docker_client_path: str | os.PathLike[str],
    docker_daemon_endpoint: str,
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    public_key_spki_sha256: str,
    private_key_password: bytes | None,
    audience: str,
    key_id: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierAuthority:
    trust = CSharpVerifierAuthorityTrust(
        public_key_path=Path(public_key_path),
        public_key_spki_sha256=public_key_spki_sha256,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _, trusted_spki, audience_value, key_id_value, signer_role_value = _validate_trust(
        trust
    )
    payload = _build_authority_payload(
        toolchain_path=toolchain_path,
        image_reference=image_reference,
        image_id=image_id,
        entrypoint=entrypoint,
        docker_client_path=docker_client_path,
        docker_daemon_endpoint=docker_daemon_endpoint,
        signer_role=signer_role_value,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    creation_time = _fresh_validation_time(now, "C# verifier authority creation time")
    _ensure_payload_active(payload, creation_time, "C# verifier authority payload")
    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    if private_spki != trusted_spki:
        _fail(
            "C# verifier authority key pair",
            "private and externally pinned public keys differ",
        )
    payload_bytes = canonical_json_bytes(payload)
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience_value,
        key_id=key_id_value,
        signer_role=signer_role_value,
        public_key_spki_sha256=trusted_spki,
    )
    envelope["signature"] = _base64url_encode(
        _sign_p1363_low_s(private_key, _signature_input(envelope, payload_bytes))
    )
    _validate_envelope(
        envelope,
        trust=trust,
        now=_fresh_validation_time(
            now, "C# verifier authority post-signing validation time"
        ),
    )
    serialized = canonical_json_bytes(envelope) + b"\n"
    if len(serialized) > MAX_AUTHORITY_BYTES:
        _fail("C# verifier authority", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()

    def validate_staged(path: Path) -> VerifiedCSharpVerifierAuthority:
        return _validate_published_authority(
            path,
            expected_payload=payload,
            expected_envelope_sha256=envelope_sha256,
            trust=trust,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            replay_live_inputs=True,
            expected_link_count=1,
            now=now,
            field="C# verifier authority output",
        )

    def validate_precommit(path: Path) -> VerifiedCSharpVerifierAuthority:
        return _validate_published_authority(
            path,
            expected_payload=payload,
            expected_envelope_sha256=envelope_sha256,
            trust=trust,
            toolchain_path=toolchain_path,
            image_reference=image_reference,
            image_id=image_id,
            entrypoint=entrypoint,
            docker_client_path=docker_client_path,
            docker_daemon_endpoint=docker_daemon_endpoint,
            replay_live_inputs=True,
            expected_link_count=2,
            now=now,
            field="C# verifier authority output",
        )

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_staged,
        precommit_validator=validate_precommit,
    )


__all__ = [
    "AUTHORITY_ENVELOPE_SCHEMA_VERSION",
    "AUTHORITY_SCHEMA_VERSION",
    "AUTHORITY_SIGNATURE_SCHEMA_VERSION",
    "AUTHORITY_SIGNING_BUNDLE_SCHEMA_VERSION",
    "CSharpVerifierAuthorityTrust",
    "DOCKER_CLIENT_ENVIRONMENT_PROFILE",
    "MAX_DOCKER_CLIENT_BYTES",
    "MEMORY_BYTES",
    "NOFILE_LIMIT",
    "REQUEST_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION_V1",
    "SANDBOX_POLICY_PROFILE",
    "SOURCE_PROFILE",
    "TMPFS",
    "VERIFIER_PLATFORM",
    "WORKER_RESULT_SCHEMA_VERSION",
    "VerifiedCSharpVerifierAuthority",
    "VerifiedCSharpVerifierAuthoritySigningBundle",
    "create_csharp_verifier_authority",
    "csharp_verifier_authority_external_signature_id",
    "csharp_verifier_authority_id",
    "csharp_verifier_authority_signing_bundle_id",
    "csharp_verifier_toolchain_sha256",
    "ensure_csharp_verifier_authority_active",
    "finalize_csharp_verifier_authority",
    "prepare_csharp_verifier_authority_signing_bundle",
    "supported_sandbox_policy",
    "validate_csharp_verifier_authority",
    "validate_csharp_verifier_toolchain",
    "verify_csharp_verifier_authority_signing_bundle",
]
