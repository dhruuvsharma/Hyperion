"""Detached authenticated review receipts for the exact expert corpus.

``providerUpload`` is deliberately an SFT/provider-training authorization and
therefore implies ``training``. Provider evaluation instead requires a true
``evaluation`` receipt claim plus freshly rederived ``mayUploadToProvider``
rights for the row and every source in the receipt-bound corpus.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from .core import (
    DOMAINS,
    SFT_METADATA_SCHEMA_VERSION,
    TASK_KINDS,
    ValidationError,
    _exact_keys,
    _existing_directory,
    _fail,
    _integer,
    _read_file_bounded,
    _reject_constant,
    _reject_reparse_components,
    _sha256,
    _string,
    _unique_pairs,
    canonical_json_bytes,
)

if TYPE_CHECKING:
    from .release import ExpertCorpus, ExpertCorpusRecord
    from .teacher_lineage import (
        TeacherMaterializationLineageAdmissionTrust,
        VerifiedTeacherMaterializationLineageAdmission,
    )


LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.expert-model-review-receipt-envelope/v1"
)
REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.expert-model-review-receipt-envelope/v2"
)
LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION = "daxalgo.expert-model-review-receipt/v1"
REVIEW_RECEIPT_SCHEMA_VERSION = "daxalgo.expert-model-review-receipt/v2"
LEGACY_REVIEW_RECEIPT_SIGNATURE_DOMAIN = (
    "daxalgo-expert-model-review-receipt-signature/v1"
)
REVIEW_RECEIPT_SIGNATURE_DOMAIN = "daxalgo-expert-model-review-receipt-signature/v2"
LEGACY_REVIEW_RECEIPT_ID_DOMAIN = "daxalgo-expert-model-review-receipt-id/v1"
REVIEW_RECEIPT_ID_DOMAIN = "daxalgo-expert-model-review-receipt-id/v2"
REVIEW_RECEIPT_ID_PREFIX = "vqreview-"
REVIEW_RECEIPT_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.expert-model-review-receipt-signing-bundle/v1"
)
REVIEW_RECEIPT_SIGNATURE_SET_SCHEMA_VERSION = (
    "daxalgo.expert-model-review-receipt-signature-set/v1"
)
REVIEW_RECEIPT_SIGNING_BUNDLE_ID_PREFIX = "vqreviewsigning-"
REVIEW_RECEIPT_SIGNATURE_SET_ID_PREFIX = "vqreviewsignatures-"
REVIEW_RECEIPT_DECISION = "approved"
REVIEW_RECEIPT_PAYLOAD_ENCODING = "canonical-json-base64url"
REVIEW_RECEIPT_ALGORITHM = "ES256"
REVIEW_RECEIPT_SIGNATURE_FORMAT = "ieee-p1363-fixed-64-low-s"
REVIEW_RECEIPT_SIGNING_STATUS = "unsigned-non-authorizing"
REVIEW_RECEIPT_SIGNING_HASH_ALGORITHM = "SHA-256"
REVIEW_RECEIPT_SIGNING_MESSAGE_TYPE = "digest"
REVIEW_RECEIPT_SIGNING_INPUT_ENCODING = "base64url"
REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_DOMAIN = (
    "daxalgo-expert-model-review-receipt-signing-bundle-authorization/v1"
)
REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_PREIMAGE_ENCODING = (
    "utf8-domain-null-canonical-bundle"
)
REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_SCOPE = (
    "finalize-exact-review-receipt-set-only"
)
REVIEW_RECEIPT_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"

MAX_REVIEW_RECEIPT_SET_BYTES = 256_000_000
MAX_REVIEW_RECEIPT_LINE_BYTES = 256_000
MAX_REVIEW_RECEIPT_PAYLOAD_BYTES = 128_000
MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES = 768_000_000
MAX_REVIEW_RECEIPT_SIGNATURE_SET_BYTES = 64_000_000
MAX_REVIEW_RECEIPT_SIGNATURE_INPUT_BYTES = 256_000
MAX_REVIEW_RECEIPT_DER_SIGNATURE_BYTES = 80
MAX_PUBLIC_KEY_BYTES = 1_000_000
MAX_PRIVATE_KEY_BYTES = 1_000_000
MAX_APPROVAL_EVIDENCE_BYTES = 16_000_000
MAX_VALIDITY = timedelta(days=366)
CANDIDATE_STABLE_KNOWLEDGE_CLASS = "knowledgeClass=candidate-stable"

_ZERO_SHA256 = "0" * 64
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RECEIPT_ID_RE = re.compile(r"^vqreview-[0-9a-f]{64}$")
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqreviewsigning-[0-9a-f]{64}$")
_SIGNATURE_SET_ID_RE = re.compile(r"^vqreviewsignatures-[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PUBLIC_KEY_PEM_RE = re.compile(
    rb"[ \t\r\n]*-----BEGIN PUBLIC KEY-----\r?\n"
    rb"(?:[A-Za-z0-9+/=]{1,64}\r?\n)+"
    rb"-----END PUBLIC KEY-----[ \t\r\n]*"
)
_UTC_SECOND_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_OFFSET_TIMESTAMP_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,7}))?"
    r"(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})$"
)
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_SIGNING_BUNDLE_ID_DOMAIN = (
    b"daxalgo-expert-model-review-receipt-signing-bundle-id/v1\x00"
)
_SIGNATURE_SET_ID_DOMAIN = (
    b"daxalgo-expert-model-review-receipt-signature-set-id/v1\x00"
)


@dataclass(frozen=True)
class VerifiedExpertModelReviewReceipt:
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes


@dataclass(frozen=True)
class VerifiedExpertModelReviewReceiptSet:
    path: Path
    dataset_path: Path
    dataset_sha256: str
    receipt_set_sha256: str
    public_key_spki_sha256: str
    receipts: tuple[VerifiedExpertModelReviewReceipt, ...]
    teacher_lineage_admission: VerifiedTeacherMaterializationLineageAdmission | None = (
        None
    )

    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    @property
    def expires_at_utc(self) -> str:
        return min(receipt.payload["expiresAtUtc"] for receipt in self.receipts)

    def as_dict(self) -> dict[str, Any]:
        result = {
            "datasetPath": str(self.dataset_path),
            "datasetSha256": self.dataset_sha256,
            "receiptSetPath": str(self.path),
            "receiptSetSha256": self.receipt_set_sha256,
            "receiptCount": self.receipt_count,
            "expiresAtUtc": self.expires_at_utc,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
        }
        result["teacherLineageAdmission"] = (
            None
            if self.teacher_lineage_admission is None
            else self.teacher_lineage_admission.as_dict()
        )
        return result


@dataclass(frozen=True)
class VerifiedExpertModelReviewReceiptSigningBundle:
    path: Path
    dataset_path: Path
    dataset_sha256: str
    bundle_sha256: str
    bundle_id: str
    receipt_count: int
    document: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "datasetPath": str(self.dataset_path),
            "datasetSha256": self.dataset_sha256,
            "signingBundlePath": str(self.path),
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "receiptCount": self.receipt_count,
            "status": REVIEW_RECEIPT_SIGNING_STATUS,
        }


@dataclass(frozen=True)
class ExpertModelReviewReceiptTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str
    teacher_lineage_admission_trust: (
        TeacherMaterializationLineageAdmissionTrust | None
    ) = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_key_path", Path(self.public_key_path))
        _sha256(
            self.public_key_spki_sha256,
            "review-receipt trust public-key SPKI SHA-256",
        )
        _identifier(self.audience, "review-receipt trust audience")
        _identifier(self.key_id, "review-receipt trust keyId")
        _identifier(self.signer_role, "review-receipt trust signerRole")
        if self.teacher_lineage_admission_trust is not None:
            from .teacher_lineage import TeacherMaterializationLineageAdmissionTrust

            if not isinstance(
                self.teacher_lineage_admission_trust,
                TeacherMaterializationLineageAdmissionTrust,
            ):
                _fail(
                    "teacher lineage admission trust",
                    "must be a TeacherMaterializationLineageAdmissionTrust instance",
                )
            if (
                self.teacher_lineage_admission_trust.public_key_spki_sha256
                == self.public_key_spki_sha256
            ):
                _fail(
                    "teacher lineage admission trust public-key SPKI SHA-256",
                    "must differ from the review-receipt signer",
                )

    def manifest_identity(self) -> dict[str, str]:
        return {
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "audience": self.audience,
            "keyId": self.key_id,
            "signerRole": self.signer_role,
        }


def _identifier(value: Any, field: str) -> str:
    identifier = _string(value, field, max_length=200)
    if not _SAFE_ID_RE.fullmatch(identifier):
        _fail(field, "must be a safe ASCII identifier")
    return identifier


def _printable_ascii(value: Any, field: str, *, max_length: int) -> str:
    text = _string(value, field, max_length=max_length)
    if any(not 0x20 <= ord(character) <= 0x7E for character in text):
        _fail(field, "must contain printable ASCII characters only")
    return text


def _frame(values: list[str | bytes]) -> bytes:
    framed = bytearray()
    for value in values:
        encoded = value if isinstance(value, bytes) else value.encode("utf-8", "strict")
        if len(encoded) > 0x7FFFFFFF:
            _fail("canonical field", "exceeds the signed int32 length-prefix limit")
        framed.extend(len(encoded).to_bytes(4, byteorder="big", signed=True))
        framed.extend(encoded)
    return bytes(framed)


def _base64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(
    value: Any,
    field: str,
    *,
    exact_bytes: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    text = _string(value, field, max_length=(max_bytes or 1_000_000) * 2 + 16)
    if not _BASE64URL_RE.fullmatch(text) or "=" in text:
        _fail(field, "must be canonical unpadded base64url")
    try:
        decoded = urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as error:
        raise ValidationError(
            f"{field}: must be canonical unpadded base64url"
        ) from error
    if _base64url_encode(decoded) != text:
        _fail(field, "must use the canonical unpadded base64url spelling")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        _fail(field, f"must decode to exactly {exact_bytes} bytes")
    if max_bytes is not None and len(decoded) > max_bytes:
        _fail(field, f"must decode to no more than {max_bytes} bytes")
    return decoded


def _content_addressed_id(
    value: Mapping[str, Any],
    *,
    id_field: str,
    prefix: str,
    domain: bytes,
) -> str:
    normalized = dict(value)
    normalized[id_field] = prefix + _ZERO_SHA256
    return (
        prefix
        + hashlib.sha256(_frame([domain, canonical_json_bytes(normalized)])).hexdigest()
    )


def expert_model_review_receipt_signing_bundle_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=REVIEW_RECEIPT_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def expert_model_review_receipt_signature_set_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureSetId",
        prefix=REVIEW_RECEIPT_SIGNATURE_SET_ID_PREFIX,
        domain=_SIGNATURE_SET_ID_DOMAIN,
    )


def _read_canonical_json_document(
    path: str | os.PathLike[str], field: str, max_bytes: int
) -> tuple[Path, bytes, dict[str, Any]]:
    resolved = Path(os.path.abspath(os.fspath(path)))
    raw = _read_file_bounded(resolved, field, max_bytes)
    if not raw:
        _fail(field, "must not be empty")
    document = _load_json_bytes(raw, field)
    if canonical_json_bytes(document) != raw:
        _fail(field, "must contain exact canonical JSON bytes")
    return resolved, raw, document


def _load_json_bytes(raw: bytes, field: str) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(field, "UTF-8 byte-order marks are not accepted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(
            f"{field}: invalid UTF-8 at byte {error.start}"
        ) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValidationError(f"{field}: invalid bounded JSON: {error}") from error
    if not isinstance(value, dict):
        _fail(field, "must have an object root")
    return value


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
            "expert-model review-receipt cryptography",
            "requires the optional 'auth' dependency",
        )
    return (
        InvalidSignature,
        hashes,
        serialization,
        ec,
        (decode_dss_signature, encode_dss_signature),
    )


def _load_public_key(path: str | os.PathLike[str]) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _read_file_bounded(
        Path(path), "expert-model review-receipt public key", MAX_PUBLIC_KEY_BYTES
    )
    if _PUBLIC_KEY_PEM_RE.fullmatch(raw) is None:
        _fail(
            "expert-model review-receipt public key",
            "must contain exactly one PUBLIC KEY/SPKI PEM block and surrounding whitespace only",
        )
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        _fail(
            "expert-model review-receipt public key",
            f"must be a valid PEM public key: {error}",
        )
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("expert-model review-receipt public key", "must be EC P-256")
    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, hashlib.sha256(spki).hexdigest()


def _load_private_key(
    path: str | os.PathLike[str], password: bytes | None
) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _read_file_bounded(
        Path(path), "expert-model review-receipt private key", MAX_PRIVATE_KEY_BYTES
    )
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as error:
        _fail(
            "expert-model review-receipt private key",
            f"must be a valid PEM private key: {error}",
        )
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("expert-model review-receipt private key", "must be EC P-256")
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
        _fail("expert-model review-receipt signature", "has invalid P-256 values")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_p1363_low_s(public_key: Any, data: bytes, signature: bytes) -> None:
    InvalidSignature, hashes, _, ec, utilities = _crypto_modules()
    _, encode_dss_signature = utilities
    if len(signature) != 64:
        _fail(
            "expert-model review-receipt signature",
            "must be exactly 64-byte IEEE-P1363",
        )
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        _fail(
            "expert-model review-receipt signature",
            "contains out-of-range P-256 values",
        )
    if s > _P256_HALF_ORDER:
        _fail("expert-model review-receipt signature", "must use canonical low-S form")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        _fail(
            "expert-model review-receipt signature",
            "does not verify with the externally pinned public key",
        )


def _normalize_external_signature(
    value: Any,
    *,
    signature_format: Any,
    public_key: Any,
    signature_input: bytes,
    field: str,
) -> bytes:
    _, _, _, _, utilities = _crypto_modules()
    decode_dss_signature, encode_dss_signature = utilities
    if signature_format == REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, exact_bytes=64)
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif signature_format == REVIEW_RECEIPT_EXTERNAL_DER_SIGNATURE_FORMAT:
        signature = _base64url_decode(
            value, field, max_bytes=MAX_REVIEW_RECEIPT_DER_SIGNATURE_BYTES
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
    _verify_p1363_low_s(public_key, signature_input, normalized)
    return normalized


def _canonical_utc_second(value: Any, field: str) -> datetime:
    text = _string(value, field, max_length=20)
    if not _UTC_SECOND_RE.fullmatch(text):
        _fail(field, "must use canonical UTC-second form YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValidationError(f"{field}: is not a valid UTC timestamp") from error


def _validation_time(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail(field, "must include a UTC offset")
    return value.astimezone(timezone.utc)


def _fresh_validation_time(value: datetime | None, field: str) -> datetime:
    return _validation_time(value or datetime.now(timezone.utc), field)


def _normalized_utc_second(value: Any, field: str) -> str:
    text = _string(value, field, max_length=64)
    match = _OFFSET_TIMESTAMP_RE.fullmatch(text)
    if match is None:
        _fail(field, "must be an ISO-8601 offset timestamp")
    fraction = match.group("fraction") or ""
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
    except ValueError as error:
        raise ValidationError(
            f"{field}: must be an ISO-8601 offset timestamp"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(field, "must include a UTC offset")
    if parsed.microsecond != 0 or any(character != "0" for character in fraction):
        _fail(field, "must have whole-second precision for a review receipt")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_sft_cutoff_utc(value: Any) -> str:
    text = _string(value, "SFT metadata cutoffUtc", max_length=64)
    match = _OFFSET_TIMESTAMP_RE.fullmatch(text)
    if match is None:
        _fail("SFT metadata cutoffUtc", "must be an ISO-8601 offset timestamp")
    fraction = (match.group("fraction") or "").ljust(7, "0")
    offset_text = match.group("offset")
    if offset_text == "Z":
        offset = timezone.utc
    else:
        offset_hours = int(offset_text[1:3])
        offset_minutes = int(offset_text[4:6])
        if (
            offset_hours > 14
            or offset_minutes > 59
            or (offset_hours == 14 and offset_minutes != 0)
        ):
            _fail("SFT metadata cutoffUtc", "contains an invalid UTC offset")
        delta = timedelta(hours=offset_hours, minutes=offset_minutes)
        offset = timezone(delta if offset_text[0] == "+" else -delta)
    try:
        parsed = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            int(fraction[:6]),
            tzinfo=offset,
        ).astimezone(timezone.utc)
    except ValueError as error:
        raise ValidationError(
            "SFT metadata cutoffUtc: is not a valid timestamp"
        ) from error
    return (
        parsed.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{parsed.microsecond:06d}{fraction[6]}Z"
    )


def _expert_model_sft_metadata_base(record: Mapping[str, Any]) -> dict[str, Any]:
    lineage = record["lineage"]
    return {
        "id": record["id"],
        "taskKind": record["taskKind"],
        "domains": record["domains"],
        "conversationSha256": record["conversationSha256"],
        "origin": lineage["origin"],
        "producer": lineage["producer"],
        "modelId": lineage["modelId"],
        "modelRevision": lineage["modelRevision"],
        "promptSha256": lineage["promptSha256"],
        "profileVersion": lineage["profileVersion"],
        "split": record["split"],
        "contaminationGroup": record["contaminationGroup"],
        "cutoffUtc": normalize_sft_cutoff_utc(record["cutoffUtc"]),
        "sourceSchema": record["schemaVersion"],
    }


def legacy_expert_model_sft_metadata(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the unversioned metadata shape retained only for v1/v3 archives."""

    return _expert_model_sft_metadata_base(record)


def expert_model_sft_metadata(
    record: Mapping[str, Any],
    *,
    source_corpus_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": SFT_METADATA_SCHEMA_VERSION,
        "sourceCorpusSha256": _sha256(
            source_corpus_sha256, "SFT metadata sourceCorpusSha256"
        ),
        "verificationEvidenceSha256": _sha256(
            record["verification"]["evidenceSha256"],
            "SFT metadata verificationEvidenceSha256",
        ),
        **_expert_model_sft_metadata_base(record),
    }


def expert_model_sft_metadata_sha256(
    record: Mapping[str, Any],
    *,
    source_corpus_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            expert_model_sft_metadata(record, source_corpus_sha256=source_corpus_sha256)
        )
    ).hexdigest()


def _bundle_authorization_preimage(bundle_bytes: bytes) -> bytes:
    return (
        REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_DOMAIN.encode("ascii")
        + b"\x00"
        + bundle_bytes
    )


def legacy_expert_model_sft_metadata_sha256(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes(legacy_expert_model_sft_metadata(record))
    ).hexdigest()


def _derived_review_kind(record: Mapping[str, Any]) -> str:
    task_kind = record["taskKind"]
    if task_kind in {"CodeGeneration", "CodeRepair"}:
        return "daxq-executable"
    if task_kind == "CodeReview":
        _fail(
            "expert-model review receipt",
            "CodeReview cannot receive an approved receipt",
        )
    return "deterministic-text"


def _derived_authorizations(record: Mapping[str, Any]) -> dict[str, bool]:
    rights = [record["rights"], *[source["rights"] for source in record["sources"]]]
    evaluation = all(item["mayStore"] and item["mayEvaluate"] for item in rights)
    training = (
        evaluation
        and record["split"] == "development"
        and record["reviewStatus"] == "approved"
        and record["verification"]["verified"] is True
        and CANDIDATE_STABLE_KNOWLEDGE_CLASS in record["verification"]["evidence"]
        and record["useForTraining"] is True
        and all(item["mayTrain"] for item in rights)
    )
    # This claim covers SFT/provider training only. Provider evaluation combines
    # evaluation=true with the bound corpus's row/source upload rights.
    provider_upload = training and all(item["mayUploadToProvider"] for item in rights)
    return {
        "evaluation": evaluation,
        "training": training,
        "providerUpload": provider_upload,
    }


def _receipt_id_domain(schema_version: Any) -> str:
    if schema_version == REVIEW_RECEIPT_SCHEMA_VERSION:
        return REVIEW_RECEIPT_ID_DOMAIN
    if schema_version == LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION:
        return LEGACY_REVIEW_RECEIPT_ID_DOMAIN
    _fail("expert-model review-receipt payload.schemaVersion", "is unsupported")


def _receipt_signature_domain(schema_version: Any) -> str:
    if schema_version == REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION:
        return REVIEW_RECEIPT_SIGNATURE_DOMAIN
    if schema_version == LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION:
        return LEGACY_REVIEW_RECEIPT_SIGNATURE_DOMAIN
    _fail("expert-model review-receipt envelope.schemaVersion", "is unsupported")


def expert_model_review_receipt_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["receiptId"] = REVIEW_RECEIPT_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(
        _frame(
            [
                _receipt_id_domain(payload.get("schemaVersion")),
                canonical_json_bytes(normalized).decode("utf-8"),
            ]
        )
    ).hexdigest()
    return REVIEW_RECEIPT_ID_PREFIX + digest


def _signature_input(envelope: Mapping[str, Any], payload_bytes: bytes) -> bytes:
    return _frame(
        [
            _receipt_signature_domain(envelope.get("schemaVersion")),
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
        ]
    )


def _validate_approval_document(
    value: Any, field: str
) -> tuple[dict[str, Any], datetime]:
    approval = _exact_keys(
        value,
        {
            "approvalId",
            "actorId",
            "actorRole",
            "reference",
            "evidenceSha256",
            "evidenceSizeBytes",
            "approvedAtUtc",
        },
        field,
    )
    for name in ("approvalId", "actorId", "actorRole"):
        _identifier(approval[name], f"{field}.{name}")
    _printable_ascii(approval["reference"], f"{field}.reference", max_length=500)
    _sha256(approval["evidenceSha256"], f"{field}.evidenceSha256")
    _integer(
        approval["evidenceSizeBytes"],
        f"{field}.evidenceSizeBytes",
        1,
        MAX_APPROVAL_EVIDENCE_BYTES,
    )
    approved_at = _canonical_utc_second(
        approval["approvedAtUtc"], f"{field}.approvedAtUtc"
    )
    return approval, approved_at


def _validate_payload_document(
    value: Any,
    *,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("expert-model review-receipt payload", "must be an object")
    schema_version = value.get("schemaVersion")
    common_keys = {
        "schemaVersion",
        "receiptId",
        "decision",
        "exampleId",
        "taskKind",
        "domains",
        "conversationSha256",
        "verificationEvidenceSha256",
        "reviewedAtUtc",
        "reviewer",
        "reviewKind",
        "sftMetadataSha256",
        "authorizations",
        "approval",
        "issuedAtUtc",
        "notBeforeUtc",
        "expiresAtUtc",
    }
    if schema_version == REVIEW_RECEIPT_SCHEMA_VERSION:
        expected_keys = common_keys | {"sourceCorpusSha256"}
        corpus_hash_field = "sourceCorpusSha256"
    elif schema_version == LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION:
        expected_keys = common_keys | {"datasetSha256"}
        corpus_hash_field = "datasetSha256"
    else:
        _fail(
            "expert-model review-receipt payload.schemaVersion",
            "is unsupported",
        )
    payload = _exact_keys(
        value,
        expected_keys,
        "expert-model review-receipt payload",
    )
    if not isinstance(payload["receiptId"], str) or not _RECEIPT_ID_RE.fullmatch(
        payload["receiptId"]
    ):
        _fail("expert-model review-receipt payload.receiptId", "is not canonical")
    if payload["decision"] != REVIEW_RECEIPT_DECISION:
        _fail(
            "expert-model review-receipt payload.decision",
            f"must be {REVIEW_RECEIPT_DECISION!r}",
        )
    _sha256(
        payload[corpus_hash_field],
        f"expert-model review-receipt {corpus_hash_field}",
    )
    _identifier(payload["exampleId"], "expert-model review-receipt exampleId")
    task_kind = payload["taskKind"]
    if task_kind not in TASK_KINDS:
        _fail("expert-model review-receipt taskKind", "is unsupported")
    if task_kind == "CodeReview":
        _fail(
            "expert-model review-receipt taskKind",
            "CodeReview cannot receive an approved receipt",
        )
    domains = payload["domains"]
    if (
        not isinstance(domains, list)
        or not domains
        or len(domains) != len(set(domains))
        or not all(isinstance(item, str) and item in DOMAINS for item in domains)
    ):
        _fail("expert-model review-receipt domains", "are invalid")
    _sha256(
        payload["conversationSha256"],
        "expert-model review-receipt conversationSha256",
    )
    _sha256(
        payload["verificationEvidenceSha256"],
        "expert-model review-receipt verificationEvidenceSha256",
    )
    reviewed_at = _canonical_utc_second(
        payload["reviewedAtUtc"], "expert-model review-receipt reviewedAtUtc"
    )
    _identifier(payload["reviewer"], "expert-model review-receipt reviewer")
    expected_review_kind = (
        "daxq-executable"
        if task_kind in {"CodeGeneration", "CodeRepair"}
        else "deterministic-text"
    )
    if payload["reviewKind"] != expected_review_kind:
        _fail(
            "expert-model review-receipt reviewKind",
            f"must be {expected_review_kind!r} for {task_kind}",
        )
    _sha256(
        payload["sftMetadataSha256"],
        "expert-model review-receipt sftMetadataSha256",
    )
    authorizations = _exact_keys(
        payload["authorizations"],
        {"evaluation", "training", "providerUpload"},
        "expert-model review-receipt authorizations",
    )
    if any(not isinstance(enabled, bool) for enabled in authorizations.values()):
        _fail("expert-model review-receipt authorizations", "must be booleans")
    if authorizations["providerUpload"] and not authorizations["training"]:
        _fail(
            "expert-model review-receipt authorizations.providerUpload",
            "requires training authorization",
        )
    if authorizations["training"] and not authorizations["evaluation"]:
        _fail(
            "expert-model review-receipt authorizations.training",
            "requires evaluation authorization",
        )

    approval, approved_at = _validate_approval_document(
        payload["approval"], "expert-model review-receipt approval"
    )
    issued_at = _canonical_utc_second(
        payload["issuedAtUtc"], "expert-model review-receipt issuedAtUtc"
    )
    not_before = _canonical_utc_second(
        payload["notBeforeUtc"], "expert-model review-receipt notBeforeUtc"
    )
    expires_at = _canonical_utc_second(
        payload["expiresAtUtc"], "expert-model review-receipt expiresAtUtc"
    )
    if not reviewed_at <= approved_at <= issued_at <= not_before < expires_at:
        _fail(
            "expert-model review-receipt validity",
            "must satisfy reviewedAt <= approvedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires_at - not_before > MAX_VALIDITY:
        _fail("expert-model review-receipt validity", "must not exceed 366 days")
    current = _validation_time(now, "expert-model review-receipt validation time")
    if current < not_before or current >= expires_at:
        _fail("expert-model review-receipt validity", "is not currently active")
    expected_id = expert_model_review_receipt_id(payload)
    if payload["receiptId"] != expected_id:
        _fail(
            "expert-model review-receipt payload.receiptId",
            "does not match the content-derived identity",
        )
    return payload


def _validate_envelope_document(
    value: Any,
    *,
    public_key: Any,
    public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    now: datetime,
) -> VerifiedExpertModelReviewReceipt:
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
        "expert-model review-receipt envelope",
    )
    version_pair = (envelope["schemaVersion"], envelope["payloadType"])
    supported_pairs = {
        (
            LEGACY_REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION,
            LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION,
        ),
        (REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION, REVIEW_RECEIPT_SCHEMA_VERSION),
    }
    if version_pair not in supported_pairs:
        _fail(
            "expert-model review-receipt envelope version pair",
            "must be a supported matching envelope and payload schema version",
        )
    constants = {
        "payloadEncoding": REVIEW_RECEIPT_PAYLOAD_ENCODING,
        "algorithm": REVIEW_RECEIPT_ALGORITHM,
        "signatureFormat": REVIEW_RECEIPT_SIGNATURE_FORMAT,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(
                f"expert-model review-receipt envelope.{name}", f"must be {expected!r}"
            )
    audience = _identifier(envelope["audience"], "review-receipt envelope audience")
    key_id = _identifier(envelope["keyId"], "review-receipt envelope keyId")
    signer_role = _identifier(
        envelope["signerRole"], "review-receipt envelope signerRole"
    )
    if audience != _identifier(expected_audience, "expected review-receipt audience"):
        _fail(
            "review-receipt envelope audience", "does not match trusted configuration"
        )
    if key_id != _identifier(expected_key_id, "expected review-receipt keyId"):
        _fail("review-receipt envelope keyId", "does not match trusted configuration")
    if signer_role != _identifier(
        expected_signer_role, "expected review-receipt signerRole"
    ):
        _fail(
            "review-receipt envelope signerRole",
            "does not match trusted configuration",
        )
    if (
        _sha256(
            envelope["publicKeySpkiSha256"],
            "review-receipt envelope publicKeySpkiSha256",
        )
        != public_key_spki_sha256
    ):
        _fail(
            "review-receipt envelope publicKeySpkiSha256",
            "does not match the externally pinned public key",
        )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "review-receipt envelope payload",
        max_bytes=MAX_REVIEW_RECEIPT_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(envelope["payloadSha256"], "review-receipt envelope payloadSha256")
        != payload_sha256
    ):
        _fail(
            "review-receipt envelope payloadSha256",
            "does not match the exact payload bytes",
        )
    signature = _base64url_decode(
        envelope["signature"],
        "review-receipt envelope signature",
        exact_bytes=64,
    )
    _verify_p1363_low_s(
        public_key,
        _signature_input(envelope, payload_bytes),
        signature,
    )
    payload = _load_json_bytes(payload_bytes, "expert-model review-receipt payload")
    if canonical_json_bytes(payload) != payload_bytes:
        _fail("expert-model review-receipt payload", "must be exact canonical JSON")
    payload = _validate_payload_document(payload, now=now)
    if payload["schemaVersion"] != envelope["payloadType"]:
        _fail(
            "expert-model review-receipt envelope.payloadType",
            "does not match the decoded payload schemaVersion",
        )
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "expert-model review-receipt approval.actorRole",
            "must match the signed envelope signerRole",
        )
    return VerifiedExpertModelReviewReceipt(envelope, payload, payload_bytes)


def _validate_receipt_against_record(
    receipt: VerifiedExpertModelReviewReceipt,
    corpus: ExpertCorpus,
    record: ExpertCorpusRecord,
) -> None:
    payload = receipt.payload
    document = record.document
    is_current = payload["schemaVersion"] == REVIEW_RECEIPT_SCHEMA_VERSION
    corpus_hash_field = "sourceCorpusSha256" if is_current else "datasetSha256"
    expected_metadata_sha256 = (
        expert_model_sft_metadata_sha256(
            document,
            source_corpus_sha256=corpus.sha256,
        )
        if is_current
        else legacy_expert_model_sft_metadata_sha256(document)
    )
    expected = {
        corpus_hash_field: corpus.sha256,
        "exampleId": document["id"],
        "taskKind": document["taskKind"],
        "domains": document["domains"],
        "conversationSha256": document["conversationSha256"],
        "verificationEvidenceSha256": document["verification"]["evidenceSha256"],
        "reviewedAtUtc": _normalized_utc_second(
            document["verification"]["verifiedAtUtc"],
            f"reviewedAtUtc for {document['id']!r}",
        ),
        "reviewer": document["verification"]["reviewer"],
        "reviewKind": _derived_review_kind(document),
        "sftMetadataSha256": expected_metadata_sha256,
        "authorizations": _derived_authorizations(document),
    }
    for name, expected_value in expected.items():
        if payload[name] != expected_value:
            _fail(
                f"expert-model review receipt {document['id']!r}.{name}",
                "does not match the exact validated corpus row",
            )


def _teacher_lineage_subjects_for_corpus(corpus: ExpertCorpus) -> list[dict[str, str]]:
    from .teacher_lineage import teacher_lineage_subject_sha256

    subjects: list[dict[str, str]] = []
    for record in corpus.records.values():
        document = record.document
        evidence = document["verification"]["evidence"]
        is_open_weight_teacher = document["lineage"]["origin"] == "OpenWeightTeacher"
        admission_anchors = [
            item for item in evidence if item.startswith("teacherAdmissionSha256=")
        ]
        if not is_open_weight_teacher:
            if admission_anchors:
                _fail(
                    f"teacher lineage reviewed row {document['id']!r}.verification.evidence",
                    "must not carry a teacherAdmissionSha256 anchor unless its origin is OpenWeightTeacher",
                )
            continue
        knowledge = [
            item.split("=", 1)[1]
            for item in evidence
            if item.startswith("knowledgeClass=")
        ]
        admissions = [item.split("=", 1)[1] for item in admission_anchors]
        if len(knowledge) != 1:
            _fail(
                f"teacher lineage reviewed row {document['id']!r}.verification.evidence",
                "must contain exactly one knowledgeClass anchor",
            )
        if len(admissions) != 1:
            _fail(
                f"teacher lineage reviewed row {document['id']!r}.verification.evidence",
                "must contain exactly one teacherAdmissionSha256 anchor",
            )
        subjects.append(
            {
                "exampleId": document["id"],
                "stableSubjectSha256": teacher_lineage_subject_sha256(document),
                "knowledgeClass": knowledge[0],
                "teacherAdmissionSha256": _sha256(
                    admissions[0],
                    f"teacher lineage reviewed row {document['id']!r} admission SHA-256",
                ),
            }
        )
    return subjects


def _verify_teacher_lineage_for_receipts(
    corpus: ExpertCorpus,
    *,
    admission_path: str | os.PathLike[str] | None,
    materialization_path: str | os.PathLike[str] | None,
    runtime_binding_path: str | os.PathLike[str] | None,
    reviewer_evidence_path: str | os.PathLike[str] | None,
    trust: TeacherMaterializationLineageAdmissionTrust | None,
    expected_review_receipt_spki_sha256: str,
    allow_dataset_only: bool,
    now: datetime,
) -> VerifiedTeacherMaterializationLineageAdmission | None:
    from .teacher_lineage import (
        TeacherMaterializationLineageAdmissionTrust,
        verify_teacher_materialization_lineage_admission,
    )

    subjects = _teacher_lineage_subjects_for_corpus(corpus)
    inputs = (
        admission_path,
        materialization_path,
        runtime_binding_path,
        reviewer_evidence_path,
        trust,
    )
    if not subjects:
        if any(value is not None for value in inputs):
            _fail(
                "teacher lineage admission",
                "is not accepted for a corpus with no OpenWeightTeacher rows",
            )
        return None
    if admission_path is None or trust is None:
        _fail(
            "teacher lineage admission",
            "path and externally pinned trust are required for OpenWeightTeacher rows",
        )
    if not isinstance(trust, TeacherMaterializationLineageAdmissionTrust):
        _fail(
            "teacher lineage admission trust",
            "must be a TeacherMaterializationLineageAdmissionTrust instance",
        )
    if trust.public_key_spki_sha256 == _sha256(
        expected_review_receipt_spki_sha256,
        "expected review-receipt public-key SPKI SHA-256",
    ):
        _fail(
            "teacher lineage admission signer",
            "must differ from the review-receipt signer",
        )
    supporting = (
        materialization_path,
        runtime_binding_path,
        reviewer_evidence_path,
    )
    if allow_dataset_only:
        from .teacher_lineage import (
            verify_teacher_materialization_lineage_admission_for_reviewed_corpus,
        )

        if any(value is not None for value in supporting):
            _fail(
                "teacher lineage admission supporting inputs",
                "must be omitted when validating a release-bundled admission",
            )
        verified = verify_teacher_materialization_lineage_admission_for_reviewed_corpus(
            admission_path,
            reviewed_dataset_path=corpus.path,
            reviewed_corpus=corpus,
            reviewed_dataset_bytes=corpus.raw,
            trust=trust,
            now=now,
        )
    else:
        if any(value is None for value in supporting):
            _fail(
                "teacher lineage admission supporting inputs",
                "materialization, runtime binding, and reviewer evidence are required",
            )
        verified = verify_teacher_materialization_lineage_admission(
            admission_path,
            materialization_path=materialization_path,
            runtime_binding_path=runtime_binding_path,
            reviewed_dataset_path=corpus.path,
            reviewer_evidence_path=reviewer_evidence_path,
            trust=trust,
            now=now,
            reviewed_corpus=corpus,
            reviewed_dataset_bytes=corpus.raw,
        )
    reviewed = verified.payload["reviewedCorpus"]
    expected = {
        "sha256": corpus.sha256,
        "sizeBytes": corpus.byte_count,
        "recordCount": len(corpus.records),
        "openWeightTeacherRecordCount": len(subjects),
        "subjects": subjects,
    }
    if reviewed != expected:
        _fail(
            "teacher lineage admission reviewedCorpus",
            "does not match the exact in-memory corpus snapshot and ordered teacher subjects",
        )
    return verified


def _validate_receipt_lineage_window(
    receipts: list[VerifiedExpertModelReviewReceipt],
    admission: VerifiedTeacherMaterializationLineageAdmission | None,
) -> None:
    if admission is None:
        return
    for receipt in receipts:
        payload = receipt.payload
        issued = _canonical_utc_second(
            payload["issuedAtUtc"],
            f"review receipt {payload['receiptId']!r}.issuedAtUtc",
        )
        not_before = _canonical_utc_second(
            payload["notBeforeUtc"],
            f"review receipt {payload['receiptId']!r}.notBeforeUtc",
        )
        expires = _canonical_utc_second(
            payload["expiresAtUtc"],
            f"review receipt {payload['receiptId']!r}.expiresAtUtc",
        )
        if issued < admission.not_before_utc or not_before < admission.not_before_utc:
            _fail(
                f"review receipt {payload['receiptId']!r} validity",
                "must be issued and become active after the lineage admission",
            )
        if expires > admission.expires_at_utc:
            _fail(
                f"review receipt {payload['receiptId']!r}.expiresAtUtc",
                "must not outlive the lineage admission",
            )


def validate_expert_model_review_receipts(
    receipt_set_path: str | os.PathLike[str],
    *,
    dataset_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    teacher_lineage_admission_path: str | os.PathLike[str] | None = None,
    teacher_materialization_path: str | os.PathLike[str] | None = None,
    teacher_runtime_binding_path: str | os.PathLike[str] | None = None,
    teacher_lineage_reviewer_evidence_path: str | os.PathLike[str] | None = None,
    teacher_lineage_admission_trust: (
        TeacherMaterializationLineageAdmissionTrust | None
    ) = None,
    now: datetime | None = None,
    _corpus_snapshot: ExpertCorpus | None = None,
    _allow_release_bound_teacher_lineage: bool = False,
    _required_schema_version: str | None = None,
) -> VerifiedExpertModelReviewReceiptSet:
    from .release import _parse_expert_corpus

    corpus = _corpus_snapshot or _parse_expert_corpus(Path(dataset_path))
    if _corpus_snapshot is not None:
        supplied_path = Path(os.path.abspath(os.fspath(dataset_path)))
        if supplied_path != corpus.path:
            _fail(
                "expert corpus snapshot",
                "does not match the supplied dataset path",
            )
    public_key, public_key_spki_sha256 = _load_public_key(public_key_path)
    expected_spki = _sha256(
        expected_public_key_spki_sha256,
        "expected review-receipt public-key SPKI SHA-256",
    )
    if public_key_spki_sha256 != expected_spki:
        _fail(
            "review-receipt public key",
            "does not match the externally pinned SPKI SHA-256",
        )
    current = _validation_time(
        now or datetime.now(timezone.utc), "review-receipt validation time"
    )
    if _required_schema_version not in {
        None,
        LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION,
        REVIEW_RECEIPT_SCHEMA_VERSION,
    }:
        _fail("required review-receipt schema version", "is unsupported")
    receipt_path = Path(receipt_set_path)
    raw = _read_file_bounded(
        receipt_path,
        "expert-model review-receipt set",
        MAX_REVIEW_RECEIPT_SET_BYTES,
    )
    if not raw:
        _fail("expert-model review-receipt set", "must not be empty")
    dataset_records = list(corpus.records.values())
    receipts: list[VerifiedExpertModelReviewReceipt] = []
    seen_ids: set[str] = set()
    with io.BytesIO(raw) as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            field = f"expert-model review-receipt line {line_number}"
            if len(raw_line) > MAX_REVIEW_RECEIPT_LINE_BYTES:
                _fail(field, f"exceeds {MAX_REVIEW_RECEIPT_LINE_BYTES} bytes")
            if not raw_line.endswith(b"\n") or raw_line.endswith(b"\r\n"):
                _fail(field, "must end with exactly one LF byte")
            line_bytes = raw_line[:-1]
            if not line_bytes:
                _fail(field, "blank lines are not accepted")
            envelope_value = _load_json_bytes(line_bytes, field)
            if canonical_json_bytes(envelope_value) != line_bytes:
                _fail(field, "must contain exact canonical JSON")
            receipt = _validate_envelope_document(
                envelope_value,
                public_key=public_key,
                public_key_spki_sha256=public_key_spki_sha256,
                expected_audience=expected_audience,
                expected_key_id=expected_key_id,
                expected_signer_role=expected_signer_role,
                now=current,
            )
            example_id = receipt.payload["exampleId"]
            if example_id in seen_ids:
                _fail(field, f"duplicates receipt for example {example_id!r}")
            seen_ids.add(example_id)
            if line_number > len(dataset_records):
                _fail(field, "has no corresponding dataset row")
            record = dataset_records[line_number - 1]
            if record.document["id"] != example_id:
                _fail(field, "must follow the exact dataset row order")
            _validate_receipt_against_record(receipt, corpus, record)
            receipts.append(receipt)
    if len(receipts) != len(dataset_records):
        _fail(
            "expert-model review-receipt set",
            "must contain exactly one receipt for every dataset row",
        )
    receipt_versions = {receipt.payload["schemaVersion"] for receipt in receipts}
    if len(receipt_versions) != 1:
        _fail(
            "expert-model review-receipt set",
            "must use one homogeneous payload schema version",
        )
    receipt_schema_version = next(iter(receipt_versions))
    if (
        _required_schema_version is not None
        and receipt_schema_version != _required_schema_version
    ):
        _fail(
            "expert-model review-receipt set schemaVersion",
            f"must be {_required_schema_version!r}",
        )
    if receipt_schema_version == LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION:
        non_human_ids = [
            record.document["id"]
            for record in dataset_records
            if record.document["lineage"]["origin"] != "HumanAuthored"
        ]
        if non_human_ids:
            _fail(
                "legacy v1 expert-model review-receipt set",
                "is accepted only for an all-HumanAuthored corpus",
            )
    verified_lineage = _verify_teacher_lineage_for_receipts(
        corpus,
        admission_path=teacher_lineage_admission_path,
        materialization_path=teacher_materialization_path,
        runtime_binding_path=teacher_runtime_binding_path,
        reviewer_evidence_path=teacher_lineage_reviewer_evidence_path,
        trust=teacher_lineage_admission_trust,
        expected_review_receipt_spki_sha256=expected_spki,
        allow_dataset_only=_allow_release_bound_teacher_lineage,
        now=current,
    )
    _validate_receipt_lineage_window(receipts, verified_lineage)
    return VerifiedExpertModelReviewReceiptSet(
        path=Path(os.path.abspath(os.fspath(receipt_path))),
        dataset_path=corpus.path,
        dataset_sha256=corpus.sha256,
        receipt_set_sha256=hashlib.sha256(raw).hexdigest(),
        public_key_spki_sha256=public_key_spki_sha256,
        receipts=tuple(receipts),
        teacher_lineage_admission=verified_lineage,
    )


def _build_payload(
    record: ExpertCorpusRecord,
    *,
    source_corpus_sha256: str,
    approval: Mapping[str, Any],
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
) -> dict[str, Any]:
    document = record.document
    payload: dict[str, Any] = {
        "schemaVersion": REVIEW_RECEIPT_SCHEMA_VERSION,
        "receiptId": REVIEW_RECEIPT_ID_PREFIX + _ZERO_SHA256,
        "decision": REVIEW_RECEIPT_DECISION,
        "sourceCorpusSha256": source_corpus_sha256,
        "exampleId": document["id"],
        "taskKind": document["taskKind"],
        "domains": document["domains"],
        "conversationSha256": document["conversationSha256"],
        "verificationEvidenceSha256": document["verification"]["evidenceSha256"],
        "reviewedAtUtc": _normalized_utc_second(
            document["verification"]["verifiedAtUtc"],
            f"reviewedAtUtc for {document['id']!r}",
        ),
        "reviewer": document["verification"]["reviewer"],
        "reviewKind": _derived_review_kind(document),
        "sftMetadataSha256": expert_model_sft_metadata_sha256(
            document, source_corpus_sha256=source_corpus_sha256
        ),
        "authorizations": _derived_authorizations(document),
        "approval": dict(approval),
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
    }
    payload["receiptId"] = expert_model_review_receipt_id(payload)
    return payload


def _teacher_lineage_admission_summary(
    admission: VerifiedTeacherMaterializationLineageAdmission | None,
) -> dict[str, Any] | None:
    if admission is None:
        return None
    payload = admission.payload
    return {
        "lineageAdmissionId": payload["lineageAdmissionId"],
        "payloadSha256": admission.payload_sha256,
        "envelopeSha256": admission.envelope_sha256,
        "publicKeySpkiSha256": admission.public_key_spki_sha256,
        "reviewedCorpus": json.loads(canonical_json_bytes(payload["reviewedCorpus"])),
        "materialization": json.loads(canonical_json_bytes(payload["materialization"])),
        "validity": {
            "reviewedAtUtc": payload["reviewedAtUtc"],
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
    }


def _validate_requested_lineage_window(
    *,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    admission: VerifiedTeacherMaterializationLineageAdmission | None,
    field: str,
) -> None:
    if admission is None:
        return
    issued = _canonical_utc_second(issued_at_utc, f"{field}.issuedAtUtc")
    not_before = _canonical_utc_second(not_before_utc, f"{field}.notBeforeUtc")
    expires = _canonical_utc_second(expires_at_utc, f"{field}.expiresAtUtc")
    if issued < admission.not_before_utc or not_before < admission.not_before_utc:
        _fail(field, "must begin no earlier than the lineage admission")
    if expires > admission.expires_at_utc:
        _fail(field, "must not outlive the lineage admission")


def _unsigned_envelope(
    payload_bytes: bytes,
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": REVIEW_RECEIPT_ENVELOPE_SCHEMA_VERSION,
        "payloadType": REVIEW_RECEIPT_SCHEMA_VERSION,
        "payloadEncoding": REVIEW_RECEIPT_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": REVIEW_RECEIPT_ALGORITHM,
        "signatureFormat": REVIEW_RECEIPT_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


def _build_approval(
    *,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approval_evidence: bytes,
    approved_at_utc: str,
) -> dict[str, Any]:
    approval = {
        "approvalId": _identifier(approval_id, "review-receipt approvalId"),
        "actorId": _identifier(actor_id, "review-receipt actorId"),
        "actorRole": _identifier(actor_role, "review-receipt approval actorRole"),
        "reference": _printable_ascii(
            approval_reference,
            "review-receipt approval reference",
            max_length=500,
        ),
        "evidenceSha256": hashlib.sha256(approval_evidence).hexdigest(),
        "evidenceSizeBytes": len(approval_evidence),
        "approvedAtUtc": approved_at_utc,
    }
    _validate_approval_document(approval, "expert-model review-receipt approval")
    return approval


def _build_signing_bundle_document(
    corpus: ExpertCorpus,
    *,
    approval: Mapping[str, Any],
    teacher_lineage_admission: (VerifiedTeacherMaterializationLineageAdmission | None),
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
    now: datetime,
) -> dict[str, Any]:
    requests: list[dict[str, Any]] = []
    for ordinal, record in enumerate(corpus.records.values()):
        payload = _validate_payload_document(
            _build_payload(
                record,
                source_corpus_sha256=corpus.sha256,
                approval=approval,
                issued_at_utc=issued_at_utc,
                not_before_utc=not_before_utc,
                expires_at_utc=expires_at_utc,
            ),
            now=now,
        )
        payload_bytes = canonical_json_bytes(payload)
        envelope = _unsigned_envelope(
            payload_bytes,
            audience=audience,
            key_id=key_id,
            signer_role=signer_role,
            public_key_spki_sha256=public_key_spki_sha256,
        )
        signature_input = _signature_input(envelope, payload_bytes)
        requests.append(
            {
                "ordinal": ordinal,
                "exampleId": payload["exampleId"],
                "receiptId": payload["receiptId"],
                "payloadSha256": envelope["payloadSha256"],
                "payload": envelope["payload"],
                "signatureInputSha256": hashlib.sha256(signature_input).hexdigest(),
                "signaturePreimage": _base64url_encode(signature_input),
                "signatureInput": _base64url_encode(
                    hashlib.sha256(signature_input).digest()
                ),
            }
        )
    bundle: dict[str, Any] = {
        "schemaVersion": REVIEW_RECEIPT_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": REVIEW_RECEIPT_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": REVIEW_RECEIPT_SIGNING_STATUS,
        "authority": {
            "reviewReceiptIssuance": False,
            "evaluation": False,
            "training": False,
            "providerUpload": False,
        },
        "sourceCorpusSha256": corpus.sha256,
        "sourceCorpusSizeBytes": corpus.byte_count,
        "receiptCount": len(requests),
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": audience,
            "keyId": key_id,
            "signerRole": signer_role,
        },
        "approval": dict(approval),
        "teacherLineageAdmission": _teacher_lineage_admission_summary(
            teacher_lineage_admission
        ),
        "validity": {
            "issuedAtUtc": issued_at_utc,
            "notBeforeUtc": not_before_utc,
            "expiresAtUtc": expires_at_utc,
        },
        "signatureContract": {
            "algorithm": REVIEW_RECEIPT_ALGORITHM,
            "hashAlgorithm": REVIEW_RECEIPT_SIGNING_HASH_ALGORITHM,
            "messageType": REVIEW_RECEIPT_SIGNING_MESSAGE_TYPE,
            "signatureInputEncoding": REVIEW_RECEIPT_SIGNING_INPUT_ENCODING,
            "bundleAuthorization": {
                "domain": REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_DOMAIN,
                "preimageEncoding": (
                    REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_PREIMAGE_ENCODING
                ),
                "hashAlgorithm": REVIEW_RECEIPT_SIGNING_HASH_ALGORITHM,
                "messageType": REVIEW_RECEIPT_SIGNING_MESSAGE_TYPE,
                "signatureInputEncoding": REVIEW_RECEIPT_SIGNING_INPUT_ENCODING,
                "scope": REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_SCOPE,
            },
            "acceptedSignatureFormats": [
                REVIEW_RECEIPT_EXTERNAL_DER_SIGNATURE_FORMAT,
                REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "requests": requests,
    }
    bundle["bundleId"] = expert_model_review_receipt_signing_bundle_id(bundle)
    return bundle


def _validate_signing_bundle_document(
    value: Any,
    *,
    corpus: ExpertCorpus,
    approval_evidence: bytes,
    expected_public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    teacher_lineage_admission: (VerifiedTeacherMaterializationLineageAdmission | None),
    now: datetime,
) -> dict[str, Any]:
    bundle = _exact_keys(
        value,
        {
            "schemaVersion",
            "bundleId",
            "status",
            "authority",
            "sourceCorpusSha256",
            "sourceCorpusSizeBytes",
            "receiptCount",
            "trust",
            "approval",
            "teacherLineageAdmission",
            "validity",
            "signatureContract",
            "requests",
        },
        "review-receipt signing bundle",
    )
    if bundle["schemaVersion"] != REVIEW_RECEIPT_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("review-receipt signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != REVIEW_RECEIPT_SIGNING_STATUS:
        _fail(
            "review-receipt signing bundle.status",
            f"must be {REVIEW_RECEIPT_SIGNING_STATUS!r}",
        )
    authority = _exact_keys(
        bundle["authority"],
        {"reviewReceiptIssuance", "evaluation", "training", "providerUpload"},
        "review-receipt signing bundle.authority",
    )
    if any(value is not False for value in authority.values()):
        _fail(
            "review-receipt signing bundle.authority",
            "must be explicitly false because an unsigned bundle grants no authority",
        )
    if (
        _sha256(
            bundle["sourceCorpusSha256"],
            "review-receipt signing bundle.sourceCorpusSha256",
        )
        != corpus.sha256
        or _integer(
            bundle["sourceCorpusSizeBytes"],
            "review-receipt signing bundle.sourceCorpusSizeBytes",
            1,
            MAX_REVIEW_RECEIPT_SET_BYTES,
        )
        != corpus.byte_count
    ):
        _fail("review-receipt signing bundle", "does not bind the exact corpus bytes")
    receipt_count = _integer(
        bundle["receiptCount"],
        "review-receipt signing bundle.receiptCount",
        1,
        100_000,
    )
    if receipt_count != len(corpus.records):
        _fail(
            "review-receipt signing bundle.receiptCount",
            "does not match the exact corpus row count",
        )
    trust = _exact_keys(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "review-receipt signing bundle.trust",
    )
    expected_spki = _sha256(
        expected_public_key_spki_sha256,
        "expected review-receipt public-key SPKI SHA-256",
    )
    expected_trust = {
        "publicKeySpkiSha256": expected_spki,
        "audience": _identifier(expected_audience, "expected review-receipt audience"),
        "keyId": _identifier(expected_key_id, "expected review-receipt keyId"),
        "signerRole": _identifier(
            expected_signer_role, "expected review-receipt signerRole"
        ),
    }
    if trust != expected_trust:
        _fail(
            "review-receipt signing bundle.trust",
            "does not match the externally pinned trust tuple",
        )
    approval, approved_at = _validate_approval_document(
        bundle["approval"], "review-receipt signing bundle.approval"
    )
    if (
        approval["actorRole"] != expected_trust["signerRole"]
        or approval["evidenceSha256"] != hashlib.sha256(approval_evidence).hexdigest()
        or approval["evidenceSizeBytes"] != len(approval_evidence)
    ):
        _fail(
            "review-receipt signing bundle.approval",
            "does not match the signer role and exact approval-evidence bytes",
        )
    if bundle["teacherLineageAdmission"] != _teacher_lineage_admission_summary(
        teacher_lineage_admission
    ):
        _fail(
            "review-receipt signing bundle.teacherLineageAdmission",
            "does not match the freshly verified optional lineage admission",
        )
    validity = _exact_keys(
        bundle["validity"],
        {"issuedAtUtc", "notBeforeUtc", "expiresAtUtc"},
        "review-receipt signing bundle.validity",
    )
    issued_at = _canonical_utc_second(
        validity["issuedAtUtc"], "review-receipt signing bundle.validity.issuedAtUtc"
    )
    not_before = _canonical_utc_second(
        validity["notBeforeUtc"],
        "review-receipt signing bundle.validity.notBeforeUtc",
    )
    expires_at = _canonical_utc_second(
        validity["expiresAtUtc"],
        "review-receipt signing bundle.validity.expiresAtUtc",
    )
    if not approved_at <= issued_at <= not_before < expires_at:
        _fail(
            "review-receipt signing bundle.validity",
            "must satisfy approvedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires_at - not_before > MAX_VALIDITY:
        _fail("review-receipt signing bundle.validity", "must not exceed 366 days")
    _validate_requested_lineage_window(
        issued_at_utc=validity["issuedAtUtc"],
        not_before_utc=validity["notBeforeUtc"],
        expires_at_utc=validity["expiresAtUtc"],
        admission=teacher_lineage_admission,
        field="review-receipt signing bundle.validity",
    )
    current = _validation_time(now, "review-receipt signing-bundle validation time")
    if current < not_before or current >= expires_at:
        _fail("review-receipt signing bundle.validity", "is not currently active")
    signature_contract = _exact_keys(
        bundle["signatureContract"],
        {
            "algorithm",
            "hashAlgorithm",
            "messageType",
            "signatureInputEncoding",
            "bundleAuthorization",
            "acceptedSignatureFormats",
        },
        "review-receipt signing bundle.signatureContract",
    )
    expected_signature_contract = {
        "algorithm": REVIEW_RECEIPT_ALGORITHM,
        "hashAlgorithm": REVIEW_RECEIPT_SIGNING_HASH_ALGORITHM,
        "messageType": REVIEW_RECEIPT_SIGNING_MESSAGE_TYPE,
        "signatureInputEncoding": REVIEW_RECEIPT_SIGNING_INPUT_ENCODING,
        "bundleAuthorization": {
            "domain": REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_DOMAIN,
            "preimageEncoding": (
                REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_PREIMAGE_ENCODING
            ),
            "hashAlgorithm": REVIEW_RECEIPT_SIGNING_HASH_ALGORITHM,
            "messageType": REVIEW_RECEIPT_SIGNING_MESSAGE_TYPE,
            "signatureInputEncoding": REVIEW_RECEIPT_SIGNING_INPUT_ENCODING,
            "scope": REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_SCOPE,
        },
        "acceptedSignatureFormats": [
            REVIEW_RECEIPT_EXTERNAL_DER_SIGNATURE_FORMAT,
            REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    if signature_contract != expected_signature_contract:
        _fail(
            "review-receipt signing bundle.signatureContract",
            "does not match the supported detached ES256 contract",
        )
    requests = bundle["requests"]
    if not isinstance(requests, list) or len(requests) != receipt_count:
        _fail(
            "review-receipt signing bundle.requests",
            "must contain exactly one request per corpus row",
        )
    seen_receipt_ids: set[str] = set()
    for ordinal, (request_value, record) in enumerate(
        zip(requests, corpus.records.values(), strict=True)
    ):
        field = f"review-receipt signing bundle.requests[{ordinal}]"
        request = _exact_keys(
            request_value,
            {
                "ordinal",
                "exampleId",
                "receiptId",
                "payloadSha256",
                "payload",
                "signatureInputSha256",
                "signaturePreimage",
                "signatureInput",
            },
            field,
        )
        if _integer(request["ordinal"], f"{field}.ordinal", 0, 99_999) != ordinal:
            _fail(f"{field}.ordinal", "does not match exact corpus order")
        example_id = _identifier(request["exampleId"], f"{field}.exampleId")
        if example_id != record.document["id"]:
            _fail(f"{field}.exampleId", "does not match exact corpus order")
        receipt_id = request["receiptId"]
        if (
            not isinstance(receipt_id, str)
            or not _RECEIPT_ID_RE.fullmatch(receipt_id)
            or receipt_id in seen_receipt_ids
        ):
            _fail(f"{field}.receiptId", "is invalid or duplicated")
        seen_receipt_ids.add(receipt_id)
        payload_bytes = _base64url_decode(
            request["payload"],
            f"{field}.payload",
            max_bytes=MAX_REVIEW_RECEIPT_PAYLOAD_BYTES,
        )
        if (
            _sha256(request["payloadSha256"], f"{field}.payloadSha256")
            != hashlib.sha256(payload_bytes).hexdigest()
        ):
            _fail(f"{field}.payloadSha256", "does not match exact payload bytes")
        payload = _load_json_bytes(payload_bytes, f"{field}.payload")
        if canonical_json_bytes(payload) != payload_bytes:
            _fail(f"{field}.payload", "must contain canonical JSON bytes")
        payload = _validate_payload_document(payload, now=current)
        expected_payload = _build_payload(
            record,
            source_corpus_sha256=corpus.sha256,
            approval=approval,
            issued_at_utc=validity["issuedAtUtc"],
            not_before_utc=validity["notBeforeUtc"],
            expires_at_utc=validity["expiresAtUtc"],
        )
        if canonical_json_bytes(expected_payload) != payload_bytes:
            _fail(f"{field}.payload", "does not match the exact corpus and approval")
        if payload["receiptId"] != receipt_id:
            _fail(f"{field}.receiptId", "does not match the canonical payload")
        envelope = _unsigned_envelope(
            payload_bytes,
            audience=trust["audience"],
            key_id=trust["keyId"],
            signer_role=trust["signerRole"],
            public_key_spki_sha256=trust["publicKeySpkiSha256"],
        )
        signature_input = _signature_input(envelope, payload_bytes)
        supplied_signature_preimage = _base64url_decode(
            request["signaturePreimage"],
            f"{field}.signaturePreimage",
            max_bytes=MAX_REVIEW_RECEIPT_SIGNATURE_INPUT_BYTES,
        )
        if supplied_signature_preimage != signature_input:
            _fail(
                f"{field}.signaturePreimage",
                "does not match the exact envelope preimage",
            )
        signature_input_digest = hashlib.sha256(signature_input).digest()
        if (
            _sha256(request["signatureInputSha256"], f"{field}.signatureInputSha256")
            != signature_input_digest.hex()
        ):
            _fail(
                f"{field}.signatureInputSha256",
                "does not match the exact signature input",
            )
        if (
            _base64url_decode(
                request["signatureInput"],
                f"{field}.signatureInput",
                exact_bytes=32,
            )
            != signature_input_digest
        ):
            _fail(
                f"{field}.signatureInput",
                "does not match the exact SHA-256 signing digest",
            )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id != expert_model_review_receipt_signing_bundle_id(bundle)
    ):
        _fail(
            "review-receipt signing bundle.bundleId",
            "does not match the content-derived identity",
        )
    return bundle


def _build_signature_set_document(
    bundle: Mapping[str, Any],
    bundle_bytes: bytes,
    signatures: list[tuple[str, bytes]],
    *,
    bundle_authorization_signature: tuple[str, bytes],
) -> dict[str, Any]:
    if len(signatures) != len(bundle["requests"]):
        _fail("review-receipt signature set", "is incomplete")
    bundle_authorization_digest = hashlib.sha256(
        _bundle_authorization_preimage(bundle_bytes)
    ).digest()
    document: dict[str, Any] = {
        "schemaVersion": REVIEW_RECEIPT_SIGNATURE_SET_SCHEMA_VERSION,
        "signatureSetId": REVIEW_RECEIPT_SIGNATURE_SET_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "sourceCorpusSha256": bundle["sourceCorpusSha256"],
        "receiptCount": bundle["receiptCount"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
        "bundleAuthorization": {
            "scope": REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_SCOPE,
            "receiptFinalizationAuthorized": True,
            "reviewTruthAuthorized": False,
            "rightsAuthorized": False,
            "releaseAuthorized": False,
            "trainingAuthorized": False,
            "evaluationAuthorized": False,
            "providerUploadAuthorized": False,
            "promotionAuthorized": False,
            "deploymentAuthorized": False,
            "signatureInputSha256": bundle_authorization_digest.hex(),
            "signatureInput": _base64url_encode(bundle_authorization_digest),
            "format": bundle_authorization_signature[0],
            "signature": _base64url_encode(bundle_authorization_signature[1]),
        },
        "signatures": [
            {
                "ordinal": ordinal,
                "receiptId": request["receiptId"],
                "signatureInputSha256": request["signatureInputSha256"],
                "format": signature_format,
                "signature": _base64url_encode(signature),
            }
            for ordinal, (request, (signature_format, signature)) in enumerate(
                zip(bundle["requests"], signatures, strict=True)
            )
        ],
    }
    document["signatureSetId"] = expert_model_review_receipt_signature_set_id(document)
    return document


def _validate_signature_set_document(
    value: Any,
    *,
    bundle: Mapping[str, Any],
    bundle_bytes: bytes,
    public_key: Any,
) -> tuple[dict[str, Any], tuple[bytes, ...]]:
    signature_set = _exact_keys(
        value,
        {
            "schemaVersion",
            "signatureSetId",
            "signingBundleId",
            "signingBundleSha256",
            "sourceCorpusSha256",
            "receiptCount",
            "publicKeySpkiSha256",
            "bundleAuthorization",
            "signatures",
        },
        "review-receipt signature set",
    )
    if signature_set["schemaVersion"] != REVIEW_RECEIPT_SIGNATURE_SET_SCHEMA_VERSION:
        _fail("review-receipt signature set.schemaVersion", "is unsupported")
    exact_bindings = {
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "sourceCorpusSha256": bundle["sourceCorpusSha256"],
        "receiptCount": bundle["receiptCount"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
    }
    for name, expected in exact_bindings.items():
        supplied = signature_set[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"review-receipt signature set.{name}")
        elif name == "receiptCount":
            _integer(supplied, f"review-receipt signature set.{name}", 1, 100_000)
        elif not isinstance(supplied, str):
            _fail(f"review-receipt signature set.{name}", "must be a string")
        if supplied != expected:
            _fail(
                f"review-receipt signature set.{name}",
                "does not match the exact signing bundle",
            )
    bundle_authorization = _exact_keys(
        signature_set["bundleAuthorization"],
        {
            "scope",
            "receiptFinalizationAuthorized",
            "reviewTruthAuthorized",
            "rightsAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "evaluationAuthorized",
            "providerUploadAuthorized",
            "promotionAuthorized",
            "deploymentAuthorized",
            "signatureInputSha256",
            "signatureInput",
            "format",
            "signature",
        },
        "review-receipt signature set.bundleAuthorization",
    )
    expected_authority = {
        "scope": REVIEW_RECEIPT_SIGNING_BUNDLE_AUTHORIZATION_SCOPE,
        "receiptFinalizationAuthorized": True,
        "reviewTruthAuthorized": False,
        "rightsAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "evaluationAuthorized": False,
        "providerUploadAuthorized": False,
        "promotionAuthorized": False,
        "deploymentAuthorized": False,
    }
    if {
        key: value
        for key, value in bundle_authorization.items()
        if key
        not in {
            "signatureInputSha256",
            "signatureInput",
            "format",
            "signature",
        }
    } != expected_authority:
        _fail(
            "review-receipt signature set.bundleAuthorization",
            "must authorize only finalization of the exact receipt set",
        )
    bundle_authorization_digest = hashlib.sha256(
        _bundle_authorization_preimage(bundle_bytes)
    ).digest()
    if (
        _sha256(
            bundle_authorization["signatureInputSha256"],
            "review-receipt signature set.bundleAuthorization.signatureInputSha256",
        )
        != bundle_authorization_digest.hex()
        or _base64url_decode(
            bundle_authorization["signatureInput"],
            "review-receipt signature set.bundleAuthorization.signatureInput",
            exact_bytes=32,
        )
        != bundle_authorization_digest
    ):
        _fail(
            "review-receipt signature set.bundleAuthorization",
            "does not bind the exact domain-separated signing digest",
        )
    _normalize_external_signature(
        bundle_authorization["signature"],
        signature_format=bundle_authorization["format"],
        public_key=public_key,
        signature_input=_bundle_authorization_preimage(bundle_bytes),
        field="review-receipt signature set.bundleAuthorization.signature",
    )
    signatures = signature_set["signatures"]
    requests = bundle["requests"]
    if not isinstance(signatures, list) or len(signatures) != len(requests):
        _fail(
            "review-receipt signature set.signatures",
            "must contain exactly one ordered signature per request",
        )
    normalized: list[bytes] = []
    seen_receipt_ids: set[str] = set()
    for ordinal, (signature_value, request) in enumerate(
        zip(signatures, requests, strict=True)
    ):
        field = f"review-receipt signature set.signatures[{ordinal}]"
        signature = _exact_keys(
            signature_value,
            {"ordinal", "receiptId", "signatureInputSha256", "format", "signature"},
            field,
        )
        if _integer(signature["ordinal"], f"{field}.ordinal", 0, 99_999) != ordinal:
            _fail(f"{field}.ordinal", "does not match exact request order")
        receipt_id = signature["receiptId"]
        if receipt_id != request["receiptId"] or receipt_id in seen_receipt_ids:
            _fail(f"{field}.receiptId", "is duplicated or out of order")
        seen_receipt_ids.add(receipt_id)
        if (
            _sha256(signature["signatureInputSha256"], f"{field}.signatureInputSha256")
            != request["signatureInputSha256"]
        ):
            _fail(
                f"{field}.signatureInputSha256",
                "does not match the exact signing request",
            )
        signature_preimage = _base64url_decode(
            request["signaturePreimage"],
            f"review-receipt signing bundle.requests[{ordinal}].signaturePreimage",
            max_bytes=MAX_REVIEW_RECEIPT_SIGNATURE_INPUT_BYTES,
        )
        normalized.append(
            _normalize_external_signature(
                signature["signature"],
                signature_format=signature["format"],
                public_key=public_key,
                signature_input=signature_preimage,
                field=f"{field}.signature",
            )
        )
    signature_set_id = signature_set["signatureSetId"]
    if (
        not isinstance(signature_set_id, str)
        or not _SIGNATURE_SET_ID_RE.fullmatch(signature_set_id)
        or signature_set_id
        != expert_model_review_receipt_signature_set_id(signature_set)
    ):
        _fail(
            "review-receipt signature set.signatureSetId",
            "does not match the content-derived identity",
        )
    return signature_set, tuple(normalized)


def _finalize_review_receipts_from_documents(
    *,
    corpus: ExpertCorpus,
    approval_evidence: bytes,
    approval_evidence_path: str | os.PathLike[str],
    signing_bundle: Mapping[str, Any],
    signing_bundle_bytes: bytes,
    signature_set: Mapping[str, Any],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    public_key: Any,
    expected_public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    teacher_lineage_admission_path: str | os.PathLike[str] | None = None,
    teacher_materialization_path: str | os.PathLike[str] | None = None,
    teacher_runtime_binding_path: str | os.PathLike[str] | None = None,
    teacher_lineage_reviewer_evidence_path: str | os.PathLike[str] | None = None,
    teacher_lineage_admission_trust: (
        TeacherMaterializationLineageAdmissionTrust | None
    ) = None,
    now: datetime | None = None,
) -> VerifiedExpertModelReviewReceiptSet:
    current = _fresh_validation_time(now, "review-receipt finalization time")
    verified_lineage = _verify_teacher_lineage_for_receipts(
        corpus,
        admission_path=teacher_lineage_admission_path,
        materialization_path=teacher_materialization_path,
        runtime_binding_path=teacher_runtime_binding_path,
        reviewer_evidence_path=teacher_lineage_reviewer_evidence_path,
        trust=teacher_lineage_admission_trust,
        expected_review_receipt_spki_sha256=expected_public_key_spki_sha256,
        allow_dataset_only=False,
        now=current,
    )
    bundle = _validate_signing_bundle_document(
        signing_bundle,
        corpus=corpus,
        approval_evidence=approval_evidence,
        expected_public_key_spki_sha256=expected_public_key_spki_sha256,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        teacher_lineage_admission=verified_lineage,
        now=current,
    )
    _, normalized_signatures = _validate_signature_set_document(
        signature_set,
        bundle=bundle,
        bundle_bytes=signing_bundle_bytes,
        public_key=public_key,
    )
    envelope_lines: list[bytes] = []
    for request, signature in zip(
        bundle["requests"], normalized_signatures, strict=True
    ):
        payload_bytes = _base64url_decode(
            request["payload"],
            "review-receipt signing request payload",
            max_bytes=MAX_REVIEW_RECEIPT_PAYLOAD_BYTES,
        )
        envelope = _unsigned_envelope(
            payload_bytes,
            audience=expected_audience,
            key_id=expected_key_id,
            signer_role=expected_signer_role,
            public_key_spki_sha256=expected_public_key_spki_sha256,
        )
        envelope["signature"] = _base64url_encode(signature)
        _validate_envelope_document(
            envelope,
            public_key=public_key,
            public_key_spki_sha256=expected_public_key_spki_sha256,
            expected_audience=expected_audience,
            expected_key_id=expected_key_id,
            expected_signer_role=expected_signer_role,
            now=current,
        )
        envelope_lines.append(canonical_json_bytes(envelope) + b"\n")
    output = b"".join(envelope_lines)
    if len(output) > MAX_REVIEW_RECEIPT_SET_BYTES:
        _fail(
            "expert-model review-receipt set",
            f"exceeds {MAX_REVIEW_RECEIPT_SET_BYTES} bytes",
        )
    destination = Path(output_path)
    _reject_reparse_components(
        destination, "expert-model review-receipt output", allow_missing_suffix=True
    )
    _existing_directory(
        destination.parent, "expert-model review-receipt output directory"
    )
    if os.path.lexists(destination):
        _fail(
            "expert-model review-receipt output", "already exists; no file was replaced"
        )
    created_identity: tuple[int, int] | None = None
    identity_guard: int | None = None
    try:
        with destination.open("xb") as stream:
            created_stat = os.fstat(stream.fileno())
            created_identity = (created_stat.st_dev, created_stat.st_ino)
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
            if os.name == "posix":
                # Prevent immediate inode reuse from making a raced replacement
                # appear to be the file created by this publication attempt.
                identity_guard = os.dup(stream.fileno())
        verified = validate_expert_model_review_receipts(
            destination,
            dataset_path=corpus.path,
            public_key_path=public_key_path,
            expected_public_key_spki_sha256=expected_public_key_spki_sha256,
            expected_audience=expected_audience,
            expected_key_id=expected_key_id,
            expected_signer_role=expected_signer_role,
            teacher_lineage_admission_path=teacher_lineage_admission_path,
            teacher_materialization_path=teacher_materialization_path,
            teacher_runtime_binding_path=teacher_runtime_binding_path,
            teacher_lineage_reviewer_evidence_path=(
                teacher_lineage_reviewer_evidence_path
            ),
            teacher_lineage_admission_trust=teacher_lineage_admission_trust,
            now=_fresh_validation_time(now, "review-receipt final validation time"),
            _corpus_snapshot=corpus,
            _required_schema_version=REVIEW_RECEIPT_SCHEMA_VERSION,
        )
        if verified.receipt_set_sha256 != hashlib.sha256(output).hexdigest():
            _fail(
                "expert-model review-receipt output",
                "changed after exclusive publication",
            )
        publication_time = _fresh_validation_time(
            now, "review-receipt publication time"
        )
        publication_evidence = _read_file_bounded(
            Path(approval_evidence_path),
            "review-receipt approval evidence",
            MAX_APPROVAL_EVIDENCE_BYTES,
        )
        if publication_evidence != approval_evidence:
            _fail(
                "review-receipt approval evidence",
                "changed during receipt finalization",
            )
        _validate_signing_bundle_document(
            bundle,
            corpus=corpus,
            approval_evidence=publication_evidence,
            expected_public_key_spki_sha256=expected_public_key_spki_sha256,
            expected_audience=expected_audience,
            expected_key_id=expected_key_id,
            expected_signer_role=expected_signer_role,
            teacher_lineage_admission=verified.teacher_lineage_admission,
            now=publication_time,
        )
        _validate_signature_set_document(
            signature_set,
            bundle=bundle,
            bundle_bytes=signing_bundle_bytes,
            public_key=public_key,
        )
        for receipt in verified.receipts:
            _validate_payload_document(receipt.payload, now=publication_time)
        if verified.teacher_lineage_admission is not None:
            from .teacher_lineage import (
                ensure_teacher_materialization_lineage_admission_active,
            )

            ensure_teacher_materialization_lineage_admission_active(
                verified.teacher_lineage_admission,
                publication_time,
            )
        if (
            _read_file_bounded(
                destination,
                "expert-model review-receipt output",
                MAX_REVIEW_RECEIPT_SET_BYTES,
            )
            != output
        ):
            _fail(
                "expert-model review-receipt output",
                "changed during publication revalidation",
            )
        current_stat = destination.lstat()
        if (current_stat.st_dev, current_stat.st_ino) != created_identity:
            _fail(
                "expert-model review-receipt output",
                "path ownership changed after exclusive publication",
            )
        return verified
    except BaseException:
        if created_identity is not None:
            try:
                current_stat = destination.lstat()
                if (current_stat.st_dev, current_stat.st_ino) == created_identity:
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if identity_guard is not None:
            os.close(identity_guard)


def prepare_expert_model_review_receipt_signing_bundle(
    *,
    dataset_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    audience: str,
    key_id: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approval_evidence_path: str | os.PathLike[str],
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    teacher_lineage_admission_path: str | os.PathLike[str] | None = None,
    teacher_materialization_path: str | os.PathLike[str] | None = None,
    teacher_runtime_binding_path: str | os.PathLike[str] | None = None,
    teacher_lineage_reviewer_evidence_path: str | os.PathLike[str] | None = None,
    teacher_lineage_admission_trust: (
        TeacherMaterializationLineageAdmissionTrust | None
    ) = None,
    now: datetime | None = None,
) -> VerifiedExpertModelReviewReceiptSigningBundle:
    from .release import _parse_expert_corpus

    audience = _identifier(audience, "review-receipt audience")
    key_id = _identifier(key_id, "review-receipt keyId")
    signer_role = _identifier(signer_role, "review-receipt signerRole")
    actor_role = _identifier(actor_role, "review-receipt approval actorRole")
    if actor_role != signer_role:
        _fail("review-receipt approval actorRole", "must match signerRole")
    corpus = _parse_expert_corpus(Path(dataset_path))
    evidence = _read_file_bounded(
        Path(approval_evidence_path),
        "review-receipt approval evidence",
        MAX_APPROVAL_EVIDENCE_BYTES,
    )
    if not evidence:
        _fail("review-receipt approval evidence", "must not be empty")
    approval = _build_approval(
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approval_evidence=evidence,
        approved_at_utc=approved_at_utc,
    )
    current = _fresh_validation_time(now, "review-receipt signing-bundle creation time")
    public_key, public_key_spki_sha256 = _load_public_key(public_key_path)
    del public_key
    verified_lineage = _verify_teacher_lineage_for_receipts(
        corpus,
        admission_path=teacher_lineage_admission_path,
        materialization_path=teacher_materialization_path,
        runtime_binding_path=teacher_runtime_binding_path,
        reviewer_evidence_path=teacher_lineage_reviewer_evidence_path,
        trust=teacher_lineage_admission_trust,
        expected_review_receipt_spki_sha256=public_key_spki_sha256,
        allow_dataset_only=False,
        now=current,
    )
    bundle = _build_signing_bundle_document(
        corpus,
        approval=approval,
        teacher_lineage_admission=verified_lineage,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
        now=current,
    )
    _validate_signing_bundle_document(
        bundle,
        corpus=corpus,
        approval_evidence=evidence,
        expected_public_key_spki_sha256=public_key_spki_sha256,
        expected_audience=audience,
        expected_key_id=key_id,
        expected_signer_role=signer_role,
        teacher_lineage_admission=verified_lineage,
        now=current,
    )
    output = canonical_json_bytes(bundle)
    if len(output) > MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES:
        _fail(
            "review-receipt signing bundle",
            f"exceeds {MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES} bytes",
        )
    destination = Path(output_path)
    _reject_reparse_components(
        destination, "review-receipt signing-bundle output", allow_missing_suffix=True
    )
    _existing_directory(
        destination.parent, "review-receipt signing-bundle output directory"
    )
    if os.path.lexists(destination):
        _fail(
            "review-receipt signing-bundle output",
            "already exists; no file was replaced",
        )
    created_identity: tuple[int, int] | None = None
    identity_guard: int | None = None
    try:
        with destination.open("xb") as stream:
            created_stat = os.fstat(stream.fileno())
            created_identity = (created_stat.st_dev, created_stat.st_ino)
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
            if os.name == "posix":
                identity_guard = os.dup(stream.fileno())
        resolved, captured, supplied = _read_canonical_json_document(
            destination,
            "review-receipt signing bundle",
            MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES,
        )
        if captured != output:
            _fail("review-receipt signing bundle", "changed after publication")
        final_time = _fresh_validation_time(
            now, "review-receipt signing-bundle publication time"
        )
        publication_evidence = _read_file_bounded(
            Path(approval_evidence_path),
            "review-receipt approval evidence",
            MAX_APPROVAL_EVIDENCE_BYTES,
        )
        if publication_evidence != evidence:
            _fail(
                "review-receipt approval evidence",
                "changed during signing-bundle preparation",
            )
        _, publication_spki = _load_public_key(public_key_path)
        if publication_spki != public_key_spki_sha256:
            _fail(
                "expert-model review-receipt public key",
                "changed during signing-bundle preparation",
            )
        publication_lineage = _verify_teacher_lineage_for_receipts(
            corpus,
            admission_path=teacher_lineage_admission_path,
            materialization_path=teacher_materialization_path,
            runtime_binding_path=teacher_runtime_binding_path,
            reviewer_evidence_path=teacher_lineage_reviewer_evidence_path,
            trust=teacher_lineage_admission_trust,
            expected_review_receipt_spki_sha256=public_key_spki_sha256,
            allow_dataset_only=False,
            now=final_time,
        )
        validated = _validate_signing_bundle_document(
            supplied,
            corpus=corpus,
            approval_evidence=publication_evidence,
            expected_public_key_spki_sha256=public_key_spki_sha256,
            expected_audience=audience,
            expected_key_id=key_id,
            expected_signer_role=signer_role,
            teacher_lineage_admission=publication_lineage,
            now=final_time,
        )
        if (
            _read_file_bounded(
                destination,
                "review-receipt signing bundle",
                MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES,
            )
            != output
        ):
            _fail(
                "review-receipt signing bundle",
                "changed during publication revalidation",
            )
        current_stat = destination.lstat()
        if (current_stat.st_dev, current_stat.st_ino) != created_identity:
            _fail(
                "review-receipt signing-bundle output",
                "path ownership changed after exclusive publication",
            )
        return VerifiedExpertModelReviewReceiptSigningBundle(
            path=resolved,
            dataset_path=corpus.path,
            dataset_sha256=corpus.sha256,
            bundle_sha256=hashlib.sha256(captured).hexdigest(),
            bundle_id=validated["bundleId"],
            receipt_count=validated["receiptCount"],
            document=validated,
        )
    except BaseException:
        if created_identity is not None:
            try:
                current_stat = destination.lstat()
                if (current_stat.st_dev, current_stat.st_ino) == created_identity:
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if identity_guard is not None:
            os.close(identity_guard)


def finalize_expert_model_review_receipts(
    *,
    dataset_path: str | os.PathLike[str],
    signing_bundle_path: str | os.PathLike[str],
    signature_set_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    approval_evidence_path: str | os.PathLike[str],
    teacher_lineage_admission_path: str | os.PathLike[str] | None = None,
    teacher_materialization_path: str | os.PathLike[str] | None = None,
    teacher_runtime_binding_path: str | os.PathLike[str] | None = None,
    teacher_lineage_reviewer_evidence_path: str | os.PathLike[str] | None = None,
    teacher_lineage_admission_trust: (
        TeacherMaterializationLineageAdmissionTrust | None
    ) = None,
    now: datetime | None = None,
) -> VerifiedExpertModelReviewReceiptSet:
    from .release import _parse_expert_corpus

    corpus = _parse_expert_corpus(Path(dataset_path))
    evidence = _read_file_bounded(
        Path(approval_evidence_path),
        "review-receipt approval evidence",
        MAX_APPROVAL_EVIDENCE_BYTES,
    )
    if not evidence:
        _fail("review-receipt approval evidence", "must not be empty")
    public_key, actual_spki = _load_public_key(public_key_path)
    expected_spki = _sha256(
        expected_public_key_spki_sha256,
        "expected review-receipt public-key SPKI SHA-256",
    )
    if actual_spki != expected_spki:
        _fail(
            "review-receipt public key",
            "does not match the externally pinned SPKI SHA-256",
        )
    _, bundle_bytes, bundle = _read_canonical_json_document(
        signing_bundle_path,
        "review-receipt signing bundle",
        MAX_REVIEW_RECEIPT_SIGNING_BUNDLE_BYTES,
    )
    _, _, signature_set = _read_canonical_json_document(
        signature_set_path,
        "review-receipt signature set",
        MAX_REVIEW_RECEIPT_SIGNATURE_SET_BYTES,
    )
    return _finalize_review_receipts_from_documents(
        corpus=corpus,
        approval_evidence=evidence,
        approval_evidence_path=approval_evidence_path,
        signing_bundle=bundle,
        signing_bundle_bytes=bundle_bytes,
        signature_set=signature_set,
        output_path=output_path,
        public_key_path=public_key_path,
        public_key=public_key,
        expected_public_key_spki_sha256=expected_spki,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        teacher_lineage_admission_path=teacher_lineage_admission_path,
        teacher_materialization_path=teacher_materialization_path,
        teacher_runtime_binding_path=teacher_runtime_binding_path,
        teacher_lineage_reviewer_evidence_path=(teacher_lineage_reviewer_evidence_path),
        teacher_lineage_admission_trust=teacher_lineage_admission_trust,
        now=now,
    )


def create_expert_model_review_receipts(
    *,
    dataset_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    private_key_password: bytes | None,
    audience: str,
    key_id: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approval_evidence_path: str | os.PathLike[str],
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    teacher_lineage_admission_path: str | os.PathLike[str] | None = None,
    teacher_materialization_path: str | os.PathLike[str] | None = None,
    teacher_runtime_binding_path: str | os.PathLike[str] | None = None,
    teacher_lineage_reviewer_evidence_path: str | os.PathLike[str] | None = None,
    teacher_lineage_admission_trust: (
        TeacherMaterializationLineageAdmissionTrust | None
    ) = None,
    now: datetime | None = None,
) -> VerifiedExpertModelReviewReceiptSet:
    from .release import _parse_expert_corpus

    audience = _identifier(audience, "review-receipt audience")
    key_id = _identifier(key_id, "review-receipt keyId")
    signer_role = _identifier(signer_role, "review-receipt signerRole")
    actor_role = _identifier(actor_role, "review-receipt approval actorRole")
    if actor_role != signer_role:
        _fail("review-receipt approval actorRole", "must match signerRole")
    corpus = _parse_expert_corpus(Path(dataset_path))
    evidence = _read_file_bounded(
        Path(approval_evidence_path),
        "review-receipt approval evidence",
        MAX_APPROVAL_EVIDENCE_BYTES,
    )
    if not evidence:
        _fail("review-receipt approval evidence", "must not be empty")
    approval = _build_approval(
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approval_evidence=evidence,
        approved_at_utc=approved_at_utc,
    )
    current = _fresh_validation_time(now, "review-receipt creation time")
    public_key, public_key_spki_sha256 = _load_public_key(public_key_path)
    verified_lineage = _verify_teacher_lineage_for_receipts(
        corpus,
        admission_path=teacher_lineage_admission_path,
        materialization_path=teacher_materialization_path,
        runtime_binding_path=teacher_runtime_binding_path,
        reviewer_evidence_path=teacher_lineage_reviewer_evidence_path,
        trust=teacher_lineage_admission_trust,
        expected_review_receipt_spki_sha256=public_key_spki_sha256,
        allow_dataset_only=False,
        now=current,
    )
    _validate_requested_lineage_window(
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        admission=verified_lineage,
        field="expert-model review-receipt validity",
    )
    private_key, private_key_spki_sha256 = _load_private_key(
        private_key_path, private_key_password
    )
    if private_key_spki_sha256 != public_key_spki_sha256:
        _fail("review-receipt key pair", "private and public keys differ")
    bundle = _build_signing_bundle_document(
        corpus,
        approval=approval,
        teacher_lineage_admission=verified_lineage,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
        now=current,
    )
    _validate_signing_bundle_document(
        bundle,
        corpus=corpus,
        approval_evidence=evidence,
        expected_public_key_spki_sha256=public_key_spki_sha256,
        expected_audience=audience,
        expected_key_id=key_id,
        expected_signer_role=signer_role,
        teacher_lineage_admission=verified_lineage,
        now=current,
    )
    bundle_bytes = canonical_json_bytes(bundle)
    signatures = [
        (
            REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT,
            _sign_p1363_low_s(
                private_key,
                _base64url_decode(
                    request["signaturePreimage"],
                    "review-receipt signing request signaturePreimage",
                    max_bytes=MAX_REVIEW_RECEIPT_SIGNATURE_INPUT_BYTES,
                ),
            ),
        )
        for request in bundle["requests"]
    ]
    signature_set = _build_signature_set_document(
        bundle,
        bundle_bytes,
        signatures,
        bundle_authorization_signature=(
            REVIEW_RECEIPT_EXTERNAL_P1363_SIGNATURE_FORMAT,
            _sign_p1363_low_s(
                private_key, _bundle_authorization_preimage(bundle_bytes)
            ),
        ),
    )
    return _finalize_review_receipts_from_documents(
        corpus=corpus,
        approval_evidence=evidence,
        approval_evidence_path=approval_evidence_path,
        signing_bundle=bundle,
        signing_bundle_bytes=bundle_bytes,
        signature_set=signature_set,
        output_path=output_path,
        public_key_path=public_key_path,
        public_key=public_key,
        expected_public_key_spki_sha256=public_key_spki_sha256,
        expected_audience=audience,
        expected_key_id=key_id,
        expected_signer_role=signer_role,
        teacher_lineage_admission_path=teacher_lineage_admission_path,
        teacher_materialization_path=teacher_materialization_path,
        teacher_runtime_binding_path=teacher_runtime_binding_path,
        teacher_lineage_reviewer_evidence_path=(teacher_lineage_reviewer_evidence_path),
        teacher_lineage_admission_trust=teacher_lineage_admission_trust,
        now=now,
    )
