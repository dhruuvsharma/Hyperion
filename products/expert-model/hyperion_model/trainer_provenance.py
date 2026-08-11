from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import (
    DATASET_BUNDLE_PATH,
    MAX_SFT_RECORDS,
    ValidationError,
    _exact_keys,
    _fail,
    _integer,
    _load_json_object_bytes,
    _revision,
    _sha256,
    _string,
    _validate_data_release_identity,
    canonical_json_bytes,
)
from .verifier_authority import (
    _base64url_decode,
    _base64url_encode,
    _load_private_key,
    _load_public_key,
    _sign_p1363_low_s,
    _verify_p1363_low_s,
)


TRAINER_PROVENANCE_SCHEMA_VERSION = "daxalgo.hyperion.trainer-provenance/v1"
TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.trainer-provenance-envelope/v1"
)
TRAINER_PROVENANCE_SCOPE = "training-artifact-provenance-only"
TRAINER_PROVENANCE_PAYLOAD_ENCODING = "canonical-json-base64url"
TRAINER_PROVENANCE_ALGORITHM = "ES256"
TRAINER_PROVENANCE_SIGNATURE_FORMAT = "ieee-p1363-low-s"
TRAINER_PROVENANCE_ID_PREFIX = "vqtrainerprov-"
TRAINER_PROVENANCE_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.hyperion.trainer-provenance-signing-bundle/v1"
)
TRAINER_PROVENANCE_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.hyperion.trainer-provenance-signature/v1"
)
TRAINER_PROVENANCE_SIGNING_BUNDLE_ID_PREFIX = "vqtrainerprovsigning-"
TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_ID_PREFIX = "vqtrainerprovsignature-"
TRAINER_PROVENANCE_SIGNING_STATUS = "unsigned-non-authorizing"
TRAINER_PROVENANCE_SIGNING_HASH_ALGORITHM = "SHA-256"
TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE = "raw-message"
TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE = "sha256-digest"
TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
TRAINER_PROVENANCE_STATEMENT = (
    "This signed non-reusable provenance asserts only that the named trainer "
    "produced the exact bound training artifact. It grants no corpus review, "
    "release, future training, base selection, evaluation, promotion, "
    "deployment, hosted serving, installation, verifier execution, or strategy "
    "execution authority."
)

MAX_TRAINER_PROVENANCE_BYTES = 65_536
MAX_TRAINER_PROVENANCE_PAYLOAD_BYTES = 32_768
MAX_TRAINER_PROVENANCE_ARTIFACT_CORE_BYTES = 2_000_000
MAX_TRAINER_PROVENANCE_SIGNING_BUNDLE_BYTES = 4_500_000
MAX_TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_BYTES = 16_000
MAX_TRAINER_PROVENANCE_SIGNATURE_INPUT_BYTES = 100_000
MAX_TRAINER_PROVENANCE_DER_SIGNATURE_BYTES = 80
MAX_TRAINER_PROVENANCE_VALIDITY = timedelta(days=366)

_ZERO_SHA256 = "0" * 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RUN_ID_RE = re.compile(r"^vqrun-[0-9a-f]{20}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SIGNATURE_DOMAIN = b"daxalgo-trainer-provenance-signature/v1\x00"
_ID_DOMAIN = b"daxalgo-trainer-provenance-id/v1\x00"
_SIGNING_BUNDLE_ID_DOMAIN = b"daxalgo-trainer-provenance-signing-bundle-id/v1\x00"
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    b"daxalgo-trainer-provenance-external-signature-id/v1\x00"
)
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqtrainerprovsigning-[0-9a-f]{64}$")
_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqtrainerprovsignature-[0-9a-f]{64}$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_TRAINING_ARTIFACT_V2_SCHEMA_VERSION = "daxalgo.hyperion.training-artifact/v2"

_ARTIFACT_CORE_KEYS = {
    "schemaVersion",
    "artifactSha256",
    "fileTreeSha256",
    "recordedAtUtc",
    "runId",
    "mode",
    "productionEligible",
    "reason",
    "manifestSha256",
    "dataRelease",
    "baseModel",
    "datasetSnapshot",
    "files",
    "environment",
    "trainerProvenance",
}

_SIGNING_AUTHORITY_KEYS = {
    "trainerProvenanceIssuance",
    "corpusReview",
    "release",
    "training",
    "baseSelection",
    "evaluation",
    "promotionDecision",
    "deployment",
    "hostedServing",
    "installation",
    "verifierExecution",
    "strategyExecution",
}

_SIGNING_BUNDLE_KEYS = {
    "schemaVersion",
    "bundleId",
    "status",
    "authority",
    "trust",
    "trainerProvenanceId",
    "artifactCoreSha256",
    "artifactCore",
    "validity",
    "signatureContract",
    "request",
}

_EXTERNAL_SIGNATURE_KEYS = {
    "schemaVersion",
    "signatureId",
    "signingBundleId",
    "signingBundleSha256",
    "trainerProvenanceId",
    "artifactCoreSha256",
    "payloadSha256",
    "signatureInputSha256",
    "publicKeySpkiSha256",
    "mode",
    "format",
    "signature",
}

_PAYLOAD_KEYS = {
    "schemaVersion",
    "trainerProvenanceId",
    "scope",
    "reusable",
    "trainingProduced",
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
    "issuedAtUtc",
    "notBeforeUtc",
    "expiresAtUtc",
    "trainerId",
    "artifactCoreSha256",
    "fileTreeSha256",
    "manifestSha256",
    "runId",
    "recordedAtUtc",
    "dataRelease",
    "baseModel",
    "datasetSnapshot",
    "environmentSha256",
    "statement",
}

_ENVELOPE_KEYS = {
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
}


@dataclass(frozen=True)
class TrainerProvenanceTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str


@dataclass(frozen=True)
class VerifiedTrainerProvenance:
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str
    public_key_spki_sha256: str
    not_before_utc: datetime
    expires_at_utc: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "trainerProvenanceId": self.payload["trainerProvenanceId"],
            "payloadSha256": self.payload_sha256,
            "envelopeSha256": self.envelope_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "notBeforeUtc": self.payload["notBeforeUtc"],
            "expiresAtUtc": self.payload["expiresAtUtc"],
        }


@dataclass(frozen=True)
class VerifiedTrainerProvenanceSigningBundle:
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    artifact_core: dict[str, Any]
    artifact_core_bytes: bytes
    artifact_core_sha256: str
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    signature_preimage: bytes
    signature_input_sha256: str
    public_key_spki_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "trainerProvenanceId": self.payload["trainerProvenanceId"],
            "artifactCoreSha256": self.artifact_core_sha256,
            "payloadSha256": self.payload_sha256,
            "signatureInputSha256": self.signature_input_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "status": TRAINER_PROVENANCE_SIGNING_STATUS,
        }


def _object(value: Any, expected: Iterable[str], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(field, "must be an object")
    document = dict(value)
    if any(not isinstance(key, str) for key in document):
        _fail(field, "must use string keys")
    return _exact_keys(document, expected, field)


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=128)
    if not _IDENTIFIER_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _canonical_utc(value: Any, field: str) -> datetime:
    text = _string(value, field, max_length=20)
    if not _UTC_RE.fullmatch(text):
        _fail(field, "must use exact UTC second form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValidationError(f"{field}: must be a real UTC second") from error
    return parsed.replace(tzinfo=timezone.utc)


def _validation_time(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(field, "must be timezone-aware")
    return value.astimezone(timezone.utc)


def _framed(fields: Iterable[str | bytes]) -> bytes:
    framed = bytearray()
    for field in fields:
        raw = field if isinstance(field, bytes) else field.encode("utf-8")
        framed.extend(len(raw).to_bytes(8, "big", signed=False))
        framed.extend(raw)
    return bytes(framed)


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


def trainer_provenance_signing_bundle_id(value: Mapping[str, Any]) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=TRAINER_PROVENANCE_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def trainer_provenance_external_signature_id(value: Mapping[str, Any]) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
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
        "schemaVersion": TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION,
        "payloadType": TRAINER_PROVENANCE_SCHEMA_VERSION,
        "payloadEncoding": TRAINER_PROVENANCE_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": TRAINER_PROVENANCE_ALGORITHM,
        "signatureFormat": TRAINER_PROVENANCE_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


def _external_crypto_modules() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError:
        _fail(
            "trainer provenance external signature cryptography",
            "requires the optional 'promote' dependency",
        )
    return (
        InvalidSignature,
        hashes,
        ec,
        Prehashed,
        (decode_dss_signature, encode_dss_signature),
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
    InvalidSignature, hashes, ec, Prehashed, utilities = _external_crypto_modules()
    decode_dss_signature, encode_dss_signature = utilities
    if signature_format == TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, 64)
        if len(signature) != 64:
            _fail(field, "must be exactly 64-byte fixed IEEE-P1363")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif signature_format == TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT:
        signature = _base64url_decode(
            value, field, MAX_TRAINER_PROVENANCE_DER_SIGNATURE_BYTES
        )
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
    if signature_mode == TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE:
        signed_value = signature_preimage
        algorithm = ec.ECDSA(hashes.SHA256())
    elif signature_mode == TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE:
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


def _validate_trust(
    trust: TrainerProvenanceTrust,
) -> tuple[Any, str, str, str, str]:
    if not isinstance(trust, TrainerProvenanceTrust):
        _fail("trainer provenance trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(Path(trust.public_key_path))
    expected_spki = _sha256(
        trust.public_key_spki_sha256,
        "trainer provenance trust.publicKeySpkiSha256",
    )
    if actual_spki != expected_spki:
        _fail(
            "trainer provenance trust.publicKeySpkiSha256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "trainer provenance trust.audience"),
        _identifier(trust.key_id, "trainer provenance trust.keyId"),
        _identifier(trust.signer_role, "trainer provenance trust.signerRole"),
    )


def _validate_base_model(value: Any, field: str) -> dict[str, Any]:
    model = _object(value, {"candidateId", "modelId", "revision"}, field)
    _string(model["candidateId"], f"{field}.candidateId", max_length=200)
    _string(model["modelId"], f"{field}.modelId", max_length=500)
    _revision(model["revision"], f"{field}.revision")
    return model


def _validate_dataset_snapshot(value: Any, field: str) -> dict[str, Any]:
    snapshot = _object(value, {"path", "sha256", "recordCount"}, field)
    if snapshot["path"] != DATASET_BUNDLE_PATH:
        _fail(f"{field}.path", f"must be {DATASET_BUNDLE_PATH!r}")
    _sha256(snapshot["sha256"], f"{field}.sha256")
    _integer(snapshot["recordCount"], f"{field}.recordCount", 1, MAX_SFT_RECORDS)
    return snapshot


def _validate_data_release(value: Any, field: str) -> dict[str, str]:
    if isinstance(value, Mapping) and not isinstance(value, dict):
        value = dict(value)
    identity = _validate_data_release_identity(value, field, allow_none=False)
    if identity is None:  # pragma: no cover - the helper rejects this case
        _fail(field, "is required")
    return identity


def trainer_provenance_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["trainerProvenanceId"] = TRAINER_PROVENANCE_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(_ID_DOMAIN + canonical_json_bytes(normalized)).hexdigest()
    return TRAINER_PROVENANCE_ID_PREFIX + digest


def _artifact_core_document(
    value: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes, str]:
    artifact = _object(value, _ARTIFACT_CORE_KEYS, "trainer provenance artifact core")
    if artifact["schemaVersion"] != _TRAINING_ARTIFACT_V2_SCHEMA_VERSION:
        _fail(
            "trainer provenance artifact core.schemaVersion",
            "must be the v2 training artifact contract",
        )
    if artifact["mode"] != "unpromoted-candidate":
        _fail(
            "trainer provenance artifact core.mode",
            "must be an unpromoted candidate",
        )
    if artifact["productionEligible"] is not False:
        _fail(
            "trainer provenance artifact core.productionEligible",
            "must be false",
        )
    _sha256(
        artifact["artifactSha256"],
        "trainer provenance artifact core.artifactSha256",
    )
    _sha256(
        artifact["fileTreeSha256"],
        "trainer provenance artifact core.fileTreeSha256",
    )
    _sha256(
        artifact["manifestSha256"],
        "trainer provenance artifact core.manifestSha256",
    )
    run_id = _string(
        artifact["runId"], "trainer provenance artifact core.runId", max_length=100
    )
    if not _RUN_ID_RE.fullmatch(run_id):
        _fail(
            "trainer provenance artifact core.runId",
            "must be a canonical vqrun identifier",
        )
    _canonical_utc(
        artifact["recordedAtUtc"],
        "trainer provenance artifact core.recordedAtUtc",
    )
    _validate_data_release(
        artifact["dataRelease"], "trainer provenance artifact core.dataRelease"
    )
    _validate_base_model(
        artifact["baseModel"], "trainer provenance artifact core.baseModel"
    )
    _validate_dataset_snapshot(
        artifact["datasetSnapshot"],
        "trainer provenance artifact core.datasetSnapshot",
    )
    if not isinstance(artifact["files"], list):
        _fail("trainer provenance artifact core.files", "must be an array")
    if not isinstance(artifact["environment"], Mapping):
        _fail("trainer provenance artifact core.environment", "must be an object")

    normalized = dict(artifact)
    normalized["artifactSha256"] = _ZERO_SHA256
    normalized["trainerProvenance"] = None
    raw = canonical_json_bytes(normalized)
    if len(raw) > MAX_TRAINER_PROVENANCE_ARTIFACT_CORE_BYTES:
        _fail("trainer provenance artifact core", "exceeds its byte limit")
    document = _load_json_object_bytes(raw, "trainer provenance artifact core")
    if raw != canonical_json_bytes(document):
        _fail("trainer provenance artifact core", "must be exact canonical JSON")
    return document, raw, hashlib.sha256(raw).hexdigest()


def _artifact_core_bindings(artifact_core: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "artifact_core_sha256": hashlib.sha256(
            canonical_json_bytes(artifact_core)
        ).hexdigest(),
        "file_tree_sha256": artifact_core["fileTreeSha256"],
        "manifest_sha256": artifact_core["manifestSha256"],
        "run_id": artifact_core["runId"],
        "recorded_at_utc": artifact_core["recordedAtUtc"],
        "data_release": artifact_core["dataRelease"],
        "base_model": artifact_core["baseModel"],
        "dataset_snapshot": artifact_core["datasetSnapshot"],
        "environment_sha256": hashlib.sha256(
            canonical_json_bytes(artifact_core["environment"])
        ).hexdigest(),
    }


def _build_payload(
    *,
    artifact_core_sha256: str,
    file_tree_sha256: str,
    manifest_sha256: str,
    run_id: str,
    recorded_at_utc: str,
    data_release: Mapping[str, Any],
    base_model: Mapping[str, Any],
    dataset_snapshot: Mapping[str, Any],
    environment_sha256: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    trainer_id: str,
) -> dict[str, Any]:
    normalized_data_release = _validate_data_release(
        data_release, "trainer provenance dataRelease"
    )
    normalized_base_model = _validate_base_model(
        base_model, "trainer provenance baseModel"
    )
    normalized_dataset_snapshot = _validate_dataset_snapshot(
        dataset_snapshot, "trainer provenance datasetSnapshot"
    )
    payload: dict[str, Any] = {
        "schemaVersion": TRAINER_PROVENANCE_SCHEMA_VERSION,
        "trainerProvenanceId": TRAINER_PROVENANCE_ID_PREFIX + _ZERO_SHA256,
        "scope": TRAINER_PROVENANCE_SCOPE,
        "reusable": False,
        "trainingProduced": True,
        "corpusReviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "baseSelectionAuthorized": False,
        "evaluationAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "trainerId": trainer_id,
        "artifactCoreSha256": artifact_core_sha256,
        "fileTreeSha256": file_tree_sha256,
        "manifestSha256": manifest_sha256,
        "runId": run_id,
        "recordedAtUtc": recorded_at_utc,
        "dataRelease": normalized_data_release,
        "baseModel": normalized_base_model,
        "datasetSnapshot": normalized_dataset_snapshot,
        "environmentSha256": environment_sha256,
        "statement": TRAINER_PROVENANCE_STATEMENT,
    }
    payload["trainerProvenanceId"] = trainer_provenance_id(payload)
    return _validate_payload(payload)


def _ensure_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> None:
    not_before = _canonical_utc(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "must be active")


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _object(value, _PAYLOAD_KEYS, "trainer provenance payload")
    constants = {
        "schemaVersion": TRAINER_PROVENANCE_SCHEMA_VERSION,
        "scope": TRAINER_PROVENANCE_SCOPE,
        "reusable": False,
        "trainingProduced": True,
        "corpusReviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "baseSelectionAuthorized": False,
        "evaluationAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "statement": TRAINER_PROVENANCE_STATEMENT,
    }
    for name, expected in constants.items():
        if type(payload[name]) is not type(expected) or payload[name] != expected:
            _fail(f"trainer provenance payload.{name}", "does not match the contract")

    _identifier(payload["trainerId"], "trainer provenance payload.trainerId")
    for name in (
        "artifactCoreSha256",
        "fileTreeSha256",
        "manifestSha256",
        "environmentSha256",
    ):
        _sha256(payload[name], f"trainer provenance payload.{name}")
    run_id = _string(
        payload["runId"], "trainer provenance payload.runId", max_length=100
    )
    if not _RUN_ID_RE.fullmatch(run_id):
        _fail(
            "trainer provenance payload.runId", "must be a canonical vqrun identifier"
        )

    recorded = _canonical_utc(
        payload["recordedAtUtc"], "trainer provenance payload.recordedAtUtc"
    )
    issued = _canonical_utc(
        payload["issuedAtUtc"], "trainer provenance payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "trainer provenance payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "trainer provenance payload.expiresAtUtc"
    )
    if not recorded <= issued <= not_before < expires:
        _fail(
            "trainer provenance payload validity",
            "must satisfy recordedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_TRAINER_PROVENANCE_VALIDITY:
        _fail("trainer provenance payload validity", "must not exceed 366 days")

    _validate_data_release(
        payload["dataRelease"], "trainer provenance payload.dataRelease"
    )
    _validate_base_model(payload["baseModel"], "trainer provenance payload.baseModel")
    _validate_dataset_snapshot(
        payload["datasetSnapshot"], "trainer provenance payload.datasetSnapshot"
    )
    if payload["trainerProvenanceId"] != trainer_provenance_id(payload):
        _fail(
            "trainer provenance payload.trainerProvenanceId",
            "does not match the content-derived identity",
        )
    return payload


def _validate_expected_bindings(
    payload: Mapping[str, Any],
    *,
    expected_artifact_core_sha256: str,
    expected_file_tree_sha256: str,
    expected_manifest_sha256: str,
    expected_run_id: str,
    expected_recorded_at_utc: str,
    expected_data_release: Mapping[str, Any],
    expected_base_model: Mapping[str, Any],
    expected_dataset_snapshot: Mapping[str, Any],
    expected_environment_sha256: str,
) -> None:
    expected: dict[str, Any] = {
        "artifactCoreSha256": _sha256(
            expected_artifact_core_sha256,
            "expected trainer provenance artifactCoreSha256",
        ),
        "fileTreeSha256": _sha256(
            expected_file_tree_sha256,
            "expected trainer provenance fileTreeSha256",
        ),
        "manifestSha256": _sha256(
            expected_manifest_sha256,
            "expected trainer provenance manifestSha256",
        ),
        "environmentSha256": _sha256(
            expected_environment_sha256,
            "expected trainer provenance environmentSha256",
        ),
        "dataRelease": _validate_data_release(
            expected_data_release,
            "expected trainer provenance dataRelease",
        ),
        "baseModel": _validate_base_model(
            expected_base_model,
            "expected trainer provenance baseModel",
        ),
        "datasetSnapshot": _validate_dataset_snapshot(
            expected_dataset_snapshot,
            "expected trainer provenance datasetSnapshot",
        ),
    }
    run_id = _string(
        expected_run_id, "expected trainer provenance runId", max_length=100
    )
    if not _RUN_ID_RE.fullmatch(run_id):
        _fail(
            "expected trainer provenance runId", "must be a canonical vqrun identifier"
        )
    expected["runId"] = run_id
    _canonical_utc(
        expected_recorded_at_utc,
        "expected trainer provenance recordedAtUtc",
    )
    expected["recordedAtUtc"] = expected_recorded_at_utc

    for name, expected_value in expected.items():
        if payload[name] != expected_value:
            _fail(
                f"trainer provenance payload.{name}",
                "does not match the exact expected artifact binding",
            )


def _build_signing_bundle_document(
    payload: Mapping[str, Any],
    *,
    artifact_core: Mapping[str, Any],
    artifact_core_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_TRAINER_PROVENANCE_PAYLOAD_BYTES:
        _fail("trainer provenance payload", "exceeds its byte limit")
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    preimage = _signature_input(envelope, payload_bytes)
    if len(preimage) > MAX_TRAINER_PROVENANCE_SIGNATURE_INPUT_BYTES:
        _fail("trainer provenance signature preimage", "exceeds its byte limit")
    digest = hashlib.sha256(preimage).digest()
    bundle: dict[str, Any] = {
        "schemaVersion": TRAINER_PROVENANCE_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": TRAINER_PROVENANCE_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": TRAINER_PROVENANCE_SIGNING_STATUS,
        "authority": {name: False for name in sorted(_SIGNING_AUTHORITY_KEYS)},
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": audience,
            "keyId": key_id,
            "signerRole": signer_role,
        },
        "trainerProvenanceId": payload["trainerProvenanceId"],
        "artifactCoreSha256": artifact_core_sha256,
        "artifactCore": _base64url_encode(canonical_json_bytes(artifact_core)),
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
        "signatureContract": {
            "algorithm": TRAINER_PROVENANCE_ALGORITHM,
            "hashAlgorithm": TRAINER_PROVENANCE_SIGNING_HASH_ALGORITHM,
            "inputEncoding": "base64url",
            "acceptedModes": [
                TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE,
                TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
            ],
            "acceptedSignatureFormats": [
                TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT,
                TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "trainerProvenanceId": payload["trainerProvenanceId"],
            "payloadSha256": envelope["payloadSha256"],
            "payload": envelope["payload"],
            "signatureInputSha256": digest.hex(),
            "signaturePreimage": _base64url_encode(preimage),
            "signatureInput": _base64url_encode(digest),
        },
    }
    bundle["bundleId"] = trainer_provenance_signing_bundle_id(bundle)
    return bundle


def _validate_signing_bundle_document(
    value: Mapping[str, Any],
    *,
    expected_artifact_core: Mapping[str, Any],
    expected_artifact_core_bytes: bytes,
    expected_artifact_core_sha256: str,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    now: datetime,
) -> VerifiedTrainerProvenanceSigningBundle:
    supplied_bundle = _object(
        value, _SIGNING_BUNDLE_KEYS, "trainer provenance signing bundle"
    )
    bundle_bytes = canonical_json_bytes(supplied_bundle)
    if len(bundle_bytes) > MAX_TRAINER_PROVENANCE_SIGNING_BUNDLE_BYTES:
        _fail("trainer provenance signing bundle", "exceeds its byte limit")
    bundle = _load_json_object_bytes(bundle_bytes, "trainer provenance signing bundle")
    if bundle_bytes != canonical_json_bytes(bundle):
        _fail("trainer provenance signing bundle", "must be exact canonical JSON")
    if bundle["schemaVersion"] != TRAINER_PROVENANCE_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("trainer provenance signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != TRAINER_PROVENANCE_SIGNING_STATUS:
        _fail(
            "trainer provenance signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority = _object(
        bundle["authority"],
        _SIGNING_AUTHORITY_KEYS,
        "trainer provenance signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"trainer provenance signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )
    trust = _object(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "trainer provenance signing bundle.trust",
    )
    expected_trust = {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }
    if trust != expected_trust:
        _fail(
            "trainer provenance signing bundle.trust",
            "does not match externally pinned trust",
        )
    contract = _object(
        bundle["signatureContract"],
        {
            "algorithm",
            "hashAlgorithm",
            "inputEncoding",
            "acceptedModes",
            "acceptedSignatureFormats",
        },
        "trainer provenance signing bundle.signatureContract",
    )
    expected_contract = {
        "algorithm": TRAINER_PROVENANCE_ALGORITHM,
        "hashAlgorithm": TRAINER_PROVENANCE_SIGNING_HASH_ALGORITHM,
        "inputEncoding": "base64url",
        "acceptedModes": [
            TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE,
            TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE,
        ],
        "acceptedSignatureFormats": [
            TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT,
            TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    if contract != expected_contract:
        _fail(
            "trainer provenance signing bundle.signatureContract",
            "does not match the contract",
        )

    artifact_core_bytes = _base64url_decode(
        bundle["artifactCore"],
        "trainer provenance signing bundle.artifactCore",
        MAX_TRAINER_PROVENANCE_ARTIFACT_CORE_BYTES,
    )
    if artifact_core_bytes != expected_artifact_core_bytes:
        _fail(
            "trainer provenance signing bundle.artifactCore",
            "does not match the exact expected live artifact core",
        )
    artifact_core = _load_json_object_bytes(
        artifact_core_bytes, "trainer provenance signing bundle artifact core"
    )
    if artifact_core_bytes != canonical_json_bytes(artifact_core):
        _fail(
            "trainer provenance signing bundle artifact core",
            "must be exact canonical JSON",
        )
    if artifact_core != expected_artifact_core:
        _fail(
            "trainer provenance signing bundle artifact core",
            "does not match the exact expected live artifact core",
        )
    artifact_core_sha256 = hashlib.sha256(artifact_core_bytes).hexdigest()
    if (
        _sha256(
            bundle["artifactCoreSha256"],
            "trainer provenance signing bundle.artifactCoreSha256",
        )
        != artifact_core_sha256
        or artifact_core_sha256 != expected_artifact_core_sha256
    ):
        _fail(
            "trainer provenance signing bundle.artifactCoreSha256",
            "does not match the exact artifact core",
        )

    request = _object(
        bundle["request"],
        {
            "trainerProvenanceId",
            "payloadSha256",
            "payload",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "trainer provenance signing bundle.request",
    )
    payload_bytes = _base64url_decode(
        request["payload"],
        "trainer provenance signing bundle.request.payload",
        MAX_TRAINER_PROVENANCE_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            request["payloadSha256"],
            "trainer provenance signing bundle.request.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "trainer provenance signing bundle.request.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(
        payload_bytes, "trainer provenance signing bundle payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail("trainer provenance signing bundle payload", "must be canonical JSON")
    payload = _validate_payload(payload)
    _ensure_payload_active(payload, now, "trainer provenance signing bundle payload")
    bindings = _artifact_core_bindings(expected_artifact_core)
    _validate_expected_bindings(
        payload,
        expected_artifact_core_sha256=bindings["artifact_core_sha256"],
        expected_file_tree_sha256=bindings["file_tree_sha256"],
        expected_manifest_sha256=bindings["manifest_sha256"],
        expected_run_id=bindings["run_id"],
        expected_recorded_at_utc=bindings["recorded_at_utc"],
        expected_data_release=bindings["data_release"],
        expected_base_model=bindings["base_model"],
        expected_dataset_snapshot=bindings["dataset_snapshot"],
        expected_environment_sha256=bindings["environment_sha256"],
    )
    expected_payload_bindings = {
        "trainerProvenanceId": payload["trainerProvenanceId"],
        "artifactCoreSha256": payload["artifactCoreSha256"],
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
    }
    for name, expected in expected_payload_bindings.items():
        if bundle[name] != expected:
            _fail(
                f"trainer provenance signing bundle.{name}",
                "does not match the exact payload",
            )
    if request["trainerProvenanceId"] != payload["trainerProvenanceId"]:
        _fail(
            "trainer provenance signing bundle.request.trainerProvenanceId",
            "does not match the exact payload",
        )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    preimage = _signature_input(envelope, payload_bytes)
    supplied_preimage = _base64url_decode(
        request["signaturePreimage"],
        "trainer provenance signing bundle.request.signaturePreimage",
        MAX_TRAINER_PROVENANCE_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != preimage:
        _fail(
            "trainer provenance signing bundle.request.signaturePreimage",
            "does not match the exact signature preimage",
        )
    digest = hashlib.sha256(preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "trainer provenance signing bundle.request.signatureInput",
        32,
    )
    if len(supplied_digest) != 32 or supplied_digest != digest:
        _fail(
            "trainer provenance signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "trainer provenance signing bundle.request.signatureInputSha256",
        )
        != digest.hex()
    ):
        _fail(
            "trainer provenance signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id != trainer_provenance_signing_bundle_id(bundle)
    ):
        _fail(
            "trainer provenance signing bundle.bundleId",
            "does not match the content-derived identity",
        )
    return VerifiedTrainerProvenanceSigningBundle(
        bundle=bundle,
        bundle_sha256=hashlib.sha256(bundle_bytes).hexdigest(),
        bundle_id=bundle_id,
        artifact_core=artifact_core,
        artifact_core_bytes=artifact_core_bytes,
        artifact_core_sha256=artifact_core_sha256,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        signature_preimage=preimage,
        signature_input_sha256=digest.hex(),
        public_key_spki_sha256=public_key_spki_sha256,
    )


def _build_external_signature_document(
    bundle: Mapping[str, Any],
    *,
    signature_mode: str,
    signature_format: str,
    signature: bytes,
) -> dict[str, Any]:
    bundle_bytes = canonical_json_bytes(bundle)
    request = bundle["request"]
    document: dict[str, Any] = {
        "schemaVersion": TRAINER_PROVENANCE_SIGNATURE_SCHEMA_VERSION,
        "signatureId": TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "trainerProvenanceId": bundle["trainerProvenanceId"],
        "artifactCoreSha256": bundle["artifactCoreSha256"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
        "mode": signature_mode,
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    document["signatureId"] = trainer_provenance_external_signature_id(document)
    return document


def _validate_external_signature_document(
    value: Mapping[str, Any],
    *,
    signing_bundle: VerifiedTrainerProvenanceSigningBundle,
    public_key: Any,
) -> bytes:
    document = _object(
        value,
        _EXTERNAL_SIGNATURE_KEYS,
        "trainer provenance external signature",
    )
    if (
        len(canonical_json_bytes(document))
        > MAX_TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_BYTES
    ):
        _fail("trainer provenance external signature", "exceeds its byte limit")
    if document["schemaVersion"] != TRAINER_PROVENANCE_SIGNATURE_SCHEMA_VERSION:
        _fail("trainer provenance external signature.schemaVersion", "is unsupported")
    bundle = signing_bundle.bundle
    request = bundle["request"]
    expected = {
        "signingBundleId": signing_bundle.bundle_id,
        "signingBundleSha256": signing_bundle.bundle_sha256,
        "trainerProvenanceId": bundle["trainerProvenanceId"],
        "artifactCoreSha256": signing_bundle.artifact_core_sha256,
        "payloadSha256": signing_bundle.payload_sha256,
        "signatureInputSha256": signing_bundle.signature_input_sha256,
        "publicKeySpkiSha256": signing_bundle.public_key_spki_sha256,
    }
    for name, expected_value in expected.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"trainer provenance external signature.{name}")
        if supplied != expected_value:
            _fail(
                f"trainer provenance external signature.{name}",
                "does not match the exact signing bundle",
            )
    signature_digest = _base64url_decode(
        request["signatureInput"],
        "trainer provenance signing bundle.request.signatureInput",
        32,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        signature_mode=document["mode"],
        public_key=public_key,
        signature_preimage=signing_bundle.signature_preimage,
        signature_digest=signature_digest,
        field="trainer provenance external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id != trainer_provenance_external_signature_id(document)
    ):
        _fail(
            "trainer provenance external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _validate_envelope(
    value: Mapping[str, Any],
    *,
    trust: TrainerProvenanceTrust,
    expected_artifact_core_sha256: str,
    expected_file_tree_sha256: str,
    expected_manifest_sha256: str,
    expected_run_id: str,
    expected_recorded_at_utc: str,
    expected_data_release: Mapping[str, Any],
    expected_base_model: Mapping[str, Any],
    expected_dataset_snapshot: Mapping[str, Any],
    expected_environment_sha256: str,
    expected_envelope_sha256: str | None,
    now: datetime,
) -> VerifiedTrainerProvenance:
    envelope = _object(value, _ENVELOPE_KEYS, "trainer provenance envelope")
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_TRAINER_PROVENANCE_BYTES:
        _fail("trainer provenance envelope", "exceeds its byte limit")

    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    constants = {
        "schemaVersion": TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION,
        "payloadType": TRAINER_PROVENANCE_SCHEMA_VERSION,
        "payloadEncoding": TRAINER_PROVENANCE_PAYLOAD_ENCODING,
        "algorithm": TRAINER_PROVENANCE_ALGORITHM,
        "signatureFormat": TRAINER_PROVENANCE_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki,
    }
    for name, expected in constants.items():
        if type(envelope[name]) is not type(expected) or envelope[name] != expected:
            _fail(
                f"trainer provenance envelope.{name}",
                "does not match trusted configuration",
            )

    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    if (
        expected_envelope_sha256 is not None
        and _sha256(
            expected_envelope_sha256,
            "expected trainer provenance envelope SHA-256",
        )
        != envelope_sha256
    ):
        _fail(
            "trainer provenance envelope",
            "does not match the trusted exact SHA-256",
        )

    payload_bytes = _base64url_decode(
        envelope["payload"],
        "trainer provenance envelope.payload",
        MAX_TRAINER_PROVENANCE_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(envelope["payloadSha256"], "trainer provenance envelope.payloadSha256")
        != payload_sha256
    ):
        _fail(
            "trainer provenance envelope.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(payload_bytes, "trainer provenance payload")
    if payload_bytes != canonical_json_bytes(payload):
        _fail("trainer provenance payload", "must be exact canonical JSON")
    payload = _validate_payload(payload)

    signature = _base64url_decode(
        envelope["signature"], "trainer provenance envelope.signature", 64
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )

    not_before = _canonical_utc(
        payload["notBeforeUtc"], "trainer provenance payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "trainer provenance payload.expiresAtUtc"
    )
    if now < not_before or now >= expires:
        _fail("trainer provenance payload validity", "is not active")

    _validate_expected_bindings(
        payload,
        expected_artifact_core_sha256=expected_artifact_core_sha256,
        expected_file_tree_sha256=expected_file_tree_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_run_id=expected_run_id,
        expected_recorded_at_utc=expected_recorded_at_utc,
        expected_data_release=expected_data_release,
        expected_base_model=expected_base_model,
        expected_dataset_snapshot=expected_dataset_snapshot,
        expected_environment_sha256=expected_environment_sha256,
    )
    return VerifiedTrainerProvenance(
        envelope=envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        envelope_sha256=envelope_sha256,
        public_key_spki_sha256=spki,
        not_before_utc=not_before,
        expires_at_utc=expires,
    )


def verify_trainer_provenance_envelope(
    envelope: Mapping[str, Any],
    *,
    trust: TrainerProvenanceTrust,
    expected_artifact_core_sha256: str,
    expected_file_tree_sha256: str,
    expected_manifest_sha256: str,
    expected_run_id: str,
    expected_recorded_at_utc: str,
    expected_data_release: Mapping[str, Any],
    expected_base_model: Mapping[str, Any],
    expected_dataset_snapshot: Mapping[str, Any],
    expected_environment_sha256: str,
    expected_envelope_sha256: str | None = None,
    now: datetime | None = None,
) -> VerifiedTrainerProvenance:
    current = _validation_time(
        now or datetime.now(timezone.utc), "trainer provenance verification time"
    )
    return _validate_envelope(
        envelope,
        trust=trust,
        expected_artifact_core_sha256=expected_artifact_core_sha256,
        expected_file_tree_sha256=expected_file_tree_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_run_id=expected_run_id,
        expected_recorded_at_utc=expected_recorded_at_utc,
        expected_data_release=expected_data_release,
        expected_base_model=expected_base_model,
        expected_dataset_snapshot=expected_dataset_snapshot,
        expected_environment_sha256=expected_environment_sha256,
        expected_envelope_sha256=expected_envelope_sha256,
        now=current,
    )


def verify_trainer_provenance_signing_bundle(
    value: Mapping[str, Any],
    *,
    trust: TrainerProvenanceTrust,
    expected_artifact_core: Mapping[str, Any],
    now: datetime | None = None,
) -> VerifiedTrainerProvenanceSigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    artifact_core, artifact_core_bytes, artifact_core_sha256 = _artifact_core_document(
        expected_artifact_core
    )
    current = _validation_time(
        now or datetime.now(timezone.utc),
        "trainer provenance signing-bundle verification time",
    )
    return _validate_signing_bundle_document(
        value,
        expected_artifact_core=artifact_core,
        expected_artifact_core_bytes=artifact_core_bytes,
        expected_artifact_core_sha256=artifact_core_sha256,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        now=current,
    )


def prepare_trainer_provenance_signing_bundle(
    *,
    artifact_core: Mapping[str, Any],
    trust: TrainerProvenanceTrust,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    trainer_id: str,
    now: datetime | None = None,
) -> VerifiedTrainerProvenanceSigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    normalized_core, _, artifact_core_sha256 = _artifact_core_document(artifact_core)
    bindings = _artifact_core_bindings(normalized_core)
    if bindings["artifact_core_sha256"] != artifact_core_sha256:
        _fail(
            "trainer provenance artifact core",
            "changed while the signing bundle was prepared",
        )
    payload = _build_payload(
        **bindings,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        trainer_id=trainer_id,
    )
    current = _validation_time(
        now or datetime.now(timezone.utc),
        "trainer provenance signing-bundle creation time",
    )
    _ensure_payload_active(payload, current, "trainer provenance payload")
    bundle = _build_signing_bundle_document(
        payload,
        artifact_core=normalized_core,
        artifact_core_sha256=artifact_core_sha256,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    return verify_trainer_provenance_signing_bundle(
        bundle,
        trust=trust,
        expected_artifact_core=artifact_core,
        now=current,
    )


def finalize_trainer_provenance_envelope(
    signing_bundle: Mapping[str, Any],
    external_signature: Mapping[str, Any],
    *,
    trust: TrainerProvenanceTrust,
    expected_artifact_core: Mapping[str, Any],
    now: datetime | None = None,
) -> VerifiedTrainerProvenance:
    current = _validation_time(
        now or datetime.now(timezone.utc),
        "trainer provenance finalization time",
    )
    verified_bundle = verify_trainer_provenance_signing_bundle(
        signing_bundle,
        trust=trust,
        expected_artifact_core=expected_artifact_core,
        now=current,
    )
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    if spki != verified_bundle.public_key_spki_sha256:
        _fail(
            "trainer provenance signing bundle trust",
            "changed while the envelope was finalized",
        )
    signature = _validate_external_signature_document(
        external_signature,
        signing_bundle=verified_bundle,
        public_key=public_key,
    )
    live_core, live_core_bytes, live_core_sha256 = _artifact_core_document(
        expected_artifact_core
    )
    if (
        live_core_bytes != verified_bundle.artifact_core_bytes
        or live_core_sha256 != verified_bundle.artifact_core_sha256
    ):
        _fail(
            "trainer provenance artifact core",
            "changed while the envelope was finalized",
        )
    payload_bytes = verified_bundle.payload_bytes
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    envelope["signature"] = _base64url_encode(signature)
    bindings = _artifact_core_bindings(live_core)
    return _validate_envelope(
        envelope,
        trust=trust,
        expected_artifact_core_sha256=bindings["artifact_core_sha256"],
        expected_file_tree_sha256=bindings["file_tree_sha256"],
        expected_manifest_sha256=bindings["manifest_sha256"],
        expected_run_id=bindings["run_id"],
        expected_recorded_at_utc=bindings["recorded_at_utc"],
        expected_data_release=bindings["data_release"],
        expected_base_model=bindings["base_model"],
        expected_dataset_snapshot=bindings["dataset_snapshot"],
        expected_environment_sha256=bindings["environment_sha256"],
        expected_envelope_sha256=None,
        now=current,
    )


def _validate_preparation_authority(
    *,
    trainer_id: str,
    expires_at_utc: str,
    issued_at_utc: str | None,
    not_before_utc: str | None,
    current: datetime,
) -> None:
    _identifier(trainer_id, "trainer provenance trainerId")
    expires = _canonical_utc(
        expires_at_utc, "trainer provenance preflight expiresAtUtc"
    )
    if (issued_at_utc is None) != (not_before_utc is None):
        _fail(
            "trainer provenance preflight validity",
            "explicit issue and not-before times must be supplied together",
        )
    if issued_at_utc is None and not_before_utc is None:
        not_before = current.replace(microsecond=0)
    else:
        issued = _canonical_utc(
            issued_at_utc, "trainer provenance preflight issuedAtUtc"
        )
        not_before = _canonical_utc(
            not_before_utc, "trainer provenance preflight notBeforeUtc"
        )
        if issued > not_before:
            _fail(
                "trainer provenance preflight validity",
                "must satisfy issuedAt <= notBefore",
            )
    if current < not_before or current >= expires:
        _fail("trainer provenance preflight validity", "must be active")
    if expires - not_before > MAX_TRAINER_PROVENANCE_VALIDITY:
        _fail("trainer provenance preflight validity", "must not exceed 366 days")


def validate_trainer_provenance_preparation_authority(
    *,
    trust: TrainerProvenanceTrust,
    trainer_id: str,
    expires_at_utc: str,
    issued_at_utc: str | None = None,
    not_before_utc: str | None = None,
    now: datetime | None = None,
) -> None:
    """Preflight detached trainer provenance without requiring a private key."""

    _validate_trust(trust)
    current = _validation_time(
        now or datetime.now(timezone.utc), "trainer provenance preflight time"
    )
    _validate_preparation_authority(
        trainer_id=trainer_id,
        expires_at_utc=expires_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        current=current,
    )


def validate_trainer_provenance_signing_authority(
    *,
    private_key_path: str | Path,
    private_key_password: bytes | None,
    trust: TrainerProvenanceTrust,
    trainer_id: str,
    expires_at_utc: str,
    issued_at_utc: str | None = None,
    not_before_utc: str | None = None,
    now: datetime | None = None,
) -> None:
    """Preflight trainer signing authority without creating artifact provenance."""

    _, spki, _, _, _ = _validate_trust(trust)
    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    del private_key
    if private_spki != spki:
        _fail(
            "trainer provenance key pair",
            "private and externally pinned public keys differ",
        )
    current = _validation_time(
        now or datetime.now(timezone.utc), "trainer provenance preflight time"
    )
    _validate_preparation_authority(
        trainer_id=trainer_id,
        expires_at_utc=expires_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        current=current,
    )


def create_trainer_provenance(
    *,
    private_key_path: str | Path,
    private_key_password: bytes | None,
    trust: TrainerProvenanceTrust,
    artifact_core_sha256: str,
    file_tree_sha256: str,
    manifest_sha256: str,
    run_id: str,
    recorded_at_utc: str,
    data_release: Mapping[str, Any],
    base_model: Mapping[str, Any],
    dataset_snapshot: Mapping[str, Any],
    environment_sha256: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    trainer_id: str,
    now: datetime | None = None,
) -> VerifiedTrainerProvenance:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    payload = _build_payload(
        artifact_core_sha256=artifact_core_sha256,
        file_tree_sha256=file_tree_sha256,
        manifest_sha256=manifest_sha256,
        run_id=run_id,
        recorded_at_utc=recorded_at_utc,
        data_release=data_release,
        base_model=base_model,
        dataset_snapshot=dataset_snapshot,
        environment_sha256=environment_sha256,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        trainer_id=trainer_id,
    )
    current = _validation_time(
        now or datetime.now(timezone.utc), "trainer provenance creation time"
    )
    _ensure_payload_active(payload, current, "trainer provenance payload")

    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    if private_spki != spki:
        _fail(
            "trainer provenance key pair",
            "private and externally pinned public keys differ",
        )

    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_TRAINER_PROVENANCE_PAYLOAD_BYTES:
        _fail("trainer provenance payload", "exceeds its byte limit")
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    envelope["signature"] = _base64url_encode(
        _sign_p1363_low_s(private_key, _signature_input(envelope, payload_bytes))
    )
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_TRAINER_PROVENANCE_BYTES:
        _fail("trainer provenance envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    return _validate_envelope(
        envelope,
        trust=trust,
        expected_artifact_core_sha256=artifact_core_sha256,
        expected_file_tree_sha256=file_tree_sha256,
        expected_manifest_sha256=manifest_sha256,
        expected_run_id=run_id,
        expected_recorded_at_utc=recorded_at_utc,
        expected_data_release=data_release,
        expected_base_model=base_model,
        expected_dataset_snapshot=dataset_snapshot,
        expected_environment_sha256=environment_sha256,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )


__all__ = [
    "TRAINER_PROVENANCE_ALGORITHM",
    "TRAINER_PROVENANCE_ENVELOPE_SCHEMA_VERSION",
    "TRAINER_PROVENANCE_EXTERNAL_DER_SIGNATURE_FORMAT",
    "TRAINER_PROVENANCE_EXTERNAL_P1363_SIGNATURE_FORMAT",
    "TRAINER_PROVENANCE_EXTERNAL_RAW_MESSAGE_MODE",
    "TRAINER_PROVENANCE_EXTERNAL_SHA256_DIGEST_MODE",
    "TRAINER_PROVENANCE_SCHEMA_VERSION",
    "TRAINER_PROVENANCE_SIGNATURE_SCHEMA_VERSION",
    "TRAINER_PROVENANCE_SIGNING_BUNDLE_SCHEMA_VERSION",
    "TRAINER_PROVENANCE_SCOPE",
    "TrainerProvenanceTrust",
    "VerifiedTrainerProvenance",
    "VerifiedTrainerProvenanceSigningBundle",
    "create_trainer_provenance",
    "finalize_trainer_provenance_envelope",
    "prepare_trainer_provenance_signing_bundle",
    "trainer_provenance_external_signature_id",
    "trainer_provenance_id",
    "trainer_provenance_signing_bundle_id",
    "validate_trainer_provenance_preparation_authority",
    "validate_trainer_provenance_signing_authority",
    "verify_trainer_provenance_envelope",
    "verify_trainer_provenance_signing_bundle",
]
