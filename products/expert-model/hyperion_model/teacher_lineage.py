from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

from .core import (
    MAX_JSON_BYTES,
    ValidationError,
    _exact_keys,
    _fail,
    _integer,
    _length_prefixed_sha256,
    _load_json_object_bytes,
    _reject_reparse_components,
    _sha256,
    _string,
    canonical_json_bytes,
)
from .evaluation import MAX_EVALUATION_BYTES
from .release import (
    MAX_CORPUS_BYTES,
    MAX_CORPUS_RECORDS,
    ExpertCorpus,
    _parse_expert_corpus,
)
from .teacher_generation import (
    MAX_TEACHER_RUNTIME_BYTES,
    TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION,
    TEACHER_RUNTIME_BINDING_EVIDENCE_STATUS,
    _load_teacher_runtime_binding_local,
    _utc_second,
)
from .teacher_materialization import (
    MATERIALIZATION_RECORD_PATH,
    MATERIALIZED_DATASET_PATH,
    MAX_MATERIALIZATION_RECORD_BYTES,
    SELECTION_SNAPSHOT_PATH,
    validate_teacher_materialization,
    validate_teacher_selection_manifest,
)
from .verifier_authority import (
    _base64url_decode,
    _base64url_encode,
    _crypto_modules,
    _load_private_key,
    _load_public_key,
    _sign_p1363_low_s,
    _verify_p1363_low_s,
)


TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-lineage-admission/v1"
)
TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-lineage-admission-envelope/v1"
)
TEACHER_LINEAGE_ADMISSION_SCOPE = (
    "exact-open-weight-teacher-materialization-lineage-for-review-receipt-issuance-only"
)
TEACHER_LINEAGE_ADMISSION_PAYLOAD_ENCODING = "canonical-json-base64url"
TEACHER_LINEAGE_ADMISSION_ALGORITHM = "ES256"
TEACHER_LINEAGE_ADMISSION_SIGNATURE_FORMAT = "ieee-p1363-fixed-64-low-s"
TEACHER_LINEAGE_ADMISSION_ID_PREFIX = "vqtlineage-"
TEACHER_LINEAGE_SUBJECT_HASH_DOMAIN = "daxalgo-hyperion-teacher-lineage-subject/v1"
TEACHER_MATERIALIZATION_PACKAGE_TREE_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-package-tree/v1"
)
TEACHER_LINEAGE_ADMISSION_STATEMENT = (
    "This signed decision admits only the exact OpenWeightTeacher materialization "
    "lineage and exact reviewed-corpus bytes for review-receipt issuance. It binds "
    "an explicitly unattested runtime observation and does not attest runtime or "
    "weight identity, correctness, rights, review correctness, release, training, "
    "evaluation, promotion, deployment, hosted serving, installation, verifier "
    "execution, or strategy execution."
)
TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-lineage-admission-signing-bundle/v1"
)
TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-lineage-admission-signature/v1"
)
TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_ID_PREFIX = "vqtlineagesigning-"
TEACHER_LINEAGE_ADMISSION_SIGNATURE_ID_PREFIX = "vqtlineagesignature-"
TEACHER_LINEAGE_ADMISSION_SIGNING_STATUS = "unsigned-non-authorizing"
TEACHER_LINEAGE_ADMISSION_SIGNING_HASH_ALGORITHM = "SHA-256"
TEACHER_LINEAGE_ADMISSION_SIGNING_MESSAGE_TYPE = "digest"
TEACHER_LINEAGE_ADMISSION_SIGNING_INPUT_ENCODING = "base64url"
TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"

MAX_TEACHER_LINEAGE_ADMISSION_PAYLOAD_BYTES = 8_000_000
MAX_TEACHER_LINEAGE_ADMISSION_BYTES = 12_000_000
MAX_TEACHER_LINEAGE_REVIEWER_EVIDENCE_BYTES = 16_000_000
MAX_TEACHER_MATERIALIZATION_PACKAGE_FILES = 100_100
MAX_TEACHER_MATERIALIZATION_PACKAGE_BYTES = 512_000_000
MAX_TEACHER_MATERIALIZATION_PACKAGE_FILE_BYTES = max(
    MAX_EVALUATION_BYTES,
    MAX_CORPUS_BYTES,
    MAX_MATERIALIZATION_RECORD_BYTES,
    MAX_JSON_BYTES,
)
MAX_TEACHER_LINEAGE_ADMISSION_VALIDITY = timedelta(days=366)
MAX_TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_BYTES = 24_000_000
MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_BYTES = 16_000
MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_INPUT_BYTES = 8_100_000
MAX_TEACHER_LINEAGE_ADMISSION_DER_SIGNATURE_BYTES = 80

_ZERO_SHA256 = "0" * 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_ADMISSION_ID_RE = re.compile(r"^vqtlineage-[0-9a-f]{64}$")
_MATERIALIZATION_ID_RE = re.compile(r"^vqtmat-[0-9a-f]{64}$")
_BATCH_ID_RE = re.compile(r"^vqtgen-[0-9a-f]{64}$")
_EXECUTION_MODEL_ID_RE = re.compile(r"^daxalgo-teacher-sha256-[0-9a-f]{64}$")
_UTC_SECOND_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_SUBJECT_TIME_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.0{1,7})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_SIGNATURE_DOMAIN = (
    b"daxalgo-teacher-materialization-lineage-admission-signature/v1\x00"
)
_ID_DOMAIN = b"daxalgo-teacher-materialization-lineage-admission-id/v1\x00"
_SIGNING_BUNDLE_ID_DOMAIN = (
    b"daxalgo-teacher-materialization-lineage-admission-signing-bundle-id/v1\x00"
)
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    b"daxalgo-teacher-materialization-lineage-admission-external-signature-id/v1\x00"
)
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqtlineagesigning-[0-9a-f]{64}$")
_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqtlineagesignature-[0-9a-f]{64}$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_Validated = TypeVar("_Validated")

_PAYLOAD_KEYS = {
    "schemaVersion",
    "lineageAdmissionId",
    "scope",
    "decision",
    "reusable",
    "reviewReceiptIssuanceAuthorized",
    "runtimeAttested",
    "teacherWeightsAttested",
    "teacherCorrectnessAuthorized",
    "reviewDecisionAuthorized",
    "rightsAuthorized",
    "releaseAuthorized",
    "trainingAuthorized",
    "evaluationAuthorized",
    "promotionDecisionAuthorized",
    "deploymentAuthorized",
    "hostedServingAuthorized",
    "installationAuthorized",
    "verifierExecutionAuthorized",
    "strategyExecutionAuthorized",
    "reviewerId",
    "reviewedAtUtc",
    "issuedAtUtc",
    "notBeforeUtc",
    "expiresAtUtc",
    "reviewerEvidence",
    "reviewedCorpus",
    "materialization",
    "runtimeObservation",
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
_RECORD_KEYS = {
    "schemaVersion",
    "id",
    "taskKind",
    "domains",
    "messages",
    "conversationSha256",
    "sources",
    "lineage",
    "verification",
    "split",
    "contaminationGroup",
    "provenance",
    "license",
    "rights",
    "reviewStatus",
    "cutoffUtc",
    "useForTraining",
}


@dataclass(frozen=True)
class TeacherMaterializationLineageAdmissionTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_key_path", Path(self.public_key_path))
        _sha256(
            self.public_key_spki_sha256,
            "teacher lineage trust public-key SPKI SHA-256",
        )
        _identifier(self.audience, "teacher lineage trust audience")
        _identifier(self.key_id, "teacher lineage trust keyId")
        _identifier(self.signer_role, "teacher lineage trust signerRole")

    def manifest_identity(self) -> dict[str, str]:
        return {
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "audience": self.audience,
            "keyId": self.key_id,
            "signerRole": self.signer_role,
        }


@dataclass(frozen=True)
class VerifiedTeacherMaterializationLineageAdmission:
    path: Path
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str
    public_key_spki_sha256: str
    reviewed_at_utc: datetime
    issued_at_utc: datetime
    not_before_utc: datetime
    expires_at_utc: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "lineageAdmissionId": self.payload["lineageAdmissionId"],
            "payloadSha256": self.payload_sha256,
            "envelopeSha256": self.envelope_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "reviewedCorpusSha256": self.payload["reviewedCorpus"]["sha256"],
            "materializationId": self.payload["materialization"]["materializationId"],
            "reviewedAtUtc": self.payload["reviewedAtUtc"],
            "issuedAtUtc": self.payload["issuedAtUtc"],
            "notBeforeUtc": self.payload["notBeforeUtc"],
            "expiresAtUtc": self.payload["expiresAtUtc"],
        }


@dataclass(frozen=True)
class VerifiedTeacherMaterializationLineageAdmissionSigningBundle:
    path: Path
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    lineage_admission_id: str
    payload_sha256: str
    public_key_spki_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "signingBundlePath": str(self.path),
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "lineageAdmissionId": self.lineage_admission_id,
            "payloadSha256": self.payload_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "status": TEACHER_LINEAGE_ADMISSION_SIGNING_STATUS,
        }


@dataclass(frozen=True)
class _PackageSnapshot:
    raw_files: Mapping[str, bytes]
    files: tuple[dict[str, Any], ...]
    tree_sha256: str
    byte_count: int


@dataclass(frozen=True)
class _DerivedTeacherLineage:
    reviewer_evidence: dict[str, Any]
    reviewed_corpus: dict[str, Any]
    materialization: dict[str, Any]
    runtime_observation: dict[str, Any]


def _identifier(value: Any, field: str) -> str:
    identifier = _string(value, field, max_length=200)
    if not _IDENTIFIER_RE.fullmatch(identifier):
        _fail(field, "must be a safe ASCII identifier")
    return identifier


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


def _optional_text(value: Any, field: str, *, maximum: int) -> str:
    if value is None:
        return ""
    return _string(value, field, max_length=maximum)


def _subject_utc_second(value: Any, field: str) -> str:
    text = _string(value, field, max_length=40)
    if not _SUBJECT_TIME_RE.fullmatch(text):
        _fail(
            field,
            "must be an offset-aware whole-second timestamp with only zero fractional digits",
        )
    parseable = re.sub(r"\.0+(?=Z|[+-])", "", text).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(parseable)
    except ValueError as error:
        raise ValidationError(f"{field}: is not a valid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:  # pragma: no cover - regex
        _fail(field, "must include a UTC offset")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def teacher_lineage_subject_fields(
    record: Mapping[str, Any],
) -> list[list[str]]:
    """Return the exact cross-language UTF-8 framing groups for one stable subject.

    The returned group order is the public v1 contract. ``verification``, row and
    source ``rights``, ``reviewStatus``, and ``useForTraining`` are deliberately
    excluded. Included timestamps are normalized to their canonical UTC-second
    instant. No JSON serialization participates in this identity.
    """

    if isinstance(record, Mapping) and not isinstance(record, dict):
        record = dict(record)
    row = _exact_keys(record, _RECORD_KEYS, "teacher lineage subject")
    lineage_value = row["lineage"]
    if not isinstance(lineage_value, dict):
        _fail("teacher lineage subject.lineage", "must be an object")
    if lineage_value.get("origin") != "OpenWeightTeacher":
        _fail(
            "teacher lineage subject.lineage.origin",
            "must be OpenWeightTeacher",
        )
    domains = row["domains"]
    if not isinstance(domains, list) or not domains:
        _fail("teacher lineage subject.domains", "must be a non-empty array")
    domain_values = [
        _string(value, f"teacher lineage subject.domains[{index}]", max_length=100)
        for index, value in enumerate(domains)
    ]

    messages = row["messages"]
    if not isinstance(messages, list) or not messages:
        _fail("teacher lineage subject.messages", "must be a non-empty array")
    message_groups: list[list[str]] = []
    for index, value in enumerate(messages):
        message = _exact_keys(
            value,
            {"role", "content"},
            f"teacher lineage subject.messages[{index}]",
        )
        message_groups.append(
            [
                "message",
                str(index),
                _string(
                    message["role"],
                    f"teacher lineage subject.messages[{index}].role",
                    max_length=20,
                ),
                _string(
                    message["content"],
                    f"teacher lineage subject.messages[{index}].content",
                    max_length=2_000_000,
                ),
            ]
        )

    sources = row["sources"]
    if not isinstance(sources, list):
        _fail("teacher lineage subject.sources", "must be an array")
    source_groups: list[list[str]] = []
    for index, value in enumerate(sources):
        source = _exact_keys(
            value,
            {
                "id",
                "title",
                "content",
                "provenance",
                "license",
                "retrievedAtUtc",
                "availableAtUtc",
                "uri",
                "rights",
            },
            f"teacher lineage subject.sources[{index}]",
        )
        uri_present = "0" if source["uri"] is None else "1"
        source_groups.append(
            [
                "source",
                str(index),
                _string(
                    source["id"],
                    f"teacher lineage subject.sources[{index}].id",
                    max_length=200,
                ),
                _string(
                    source["title"],
                    f"teacher lineage subject.sources[{index}].title",
                    max_length=500,
                ),
                _string(
                    source["content"],
                    f"teacher lineage subject.sources[{index}].content",
                    max_length=500_000,
                ),
                _string(
                    source["provenance"],
                    f"teacher lineage subject.sources[{index}].provenance",
                    max_length=2_000,
                ),
                _string(
                    source["license"],
                    f"teacher lineage subject.sources[{index}].license",
                    max_length=500,
                ),
                _subject_utc_second(
                    source["retrievedAtUtc"],
                    f"teacher lineage subject.sources[{index}].retrievedAtUtc",
                ),
                _subject_utc_second(
                    source["availableAtUtc"],
                    f"teacher lineage subject.sources[{index}].availableAtUtc",
                ),
                uri_present,
                _optional_text(
                    source["uri"],
                    f"teacher lineage subject.sources[{index}].uri",
                    maximum=2_048,
                ),
            ]
        )

    lineage = _exact_keys(
        lineage_value,
        {
            "origin",
            "producer",
            "modelId",
            "modelRevision",
            "promptSha256",
            "profileVersion",
            "producedAtUtc",
        },
        "teacher lineage subject.lineage",
    )
    lineage_group = [
        "lineage",
        "OpenWeightTeacher",
        _string(
            lineage["producer"],
            "teacher lineage subject.lineage.producer",
            max_length=500,
        ),
        _string(
            lineage["modelId"],
            "teacher lineage subject.lineage.modelId",
            max_length=500,
        ),
        _string(
            lineage["modelRevision"],
            "teacher lineage subject.lineage.modelRevision",
            max_length=200,
        ),
        _sha256(
            lineage["promptSha256"],
            "teacher lineage subject.lineage.promptSha256",
        ),
        _string(
            lineage["profileVersion"],
            "teacher lineage subject.lineage.profileVersion",
            max_length=500,
        ),
        _subject_utc_second(
            lineage["producedAtUtc"],
            "teacher lineage subject.lineage.producedAtUtc",
        ),
    ]
    subject_group = [
        "subject",
        _string(
            row["schemaVersion"],
            "teacher lineage subject.schemaVersion",
            max_length=100,
        ),
        _identifier(row["id"], "teacher lineage subject.id"),
        _string(row["taskKind"], "teacher lineage subject.taskKind", max_length=100),
        _sha256(
            row["conversationSha256"],
            "teacher lineage subject.conversationSha256",
        ),
        _string(row["split"], "teacher lineage subject.split", max_length=50),
        _identifier(
            row["contaminationGroup"],
            "teacher lineage subject.contaminationGroup",
        ),
        _string(
            row["provenance"],
            "teacher lineage subject.provenance",
            max_length=2_000,
        ),
        _string(row["license"], "teacher lineage subject.license", max_length=500),
        _subject_utc_second(row["cutoffUtc"], "teacher lineage subject.cutoffUtc"),
    ]
    return [
        subject_group,
        ["domains", *domain_values],
        *message_groups,
        *source_groups,
        lineage_group,
    ]


def teacher_lineage_subject_sha256(record: Mapping[str, Any]) -> str:
    return _length_prefixed_sha256(
        TEACHER_LINEAGE_SUBJECT_HASH_DOMAIN,
        teacher_lineage_subject_fields(record),
    )


def teacher_materialization_lineage_admission_id(
    payload: Mapping[str, Any],
) -> str:
    normalized = dict(payload)
    normalized["lineageAdmissionId"] = (
        TEACHER_LINEAGE_ADMISSION_ID_PREFIX + _ZERO_SHA256
    )
    digest = hashlib.sha256(_ID_DOMAIN + canonical_json_bytes(normalized)).hexdigest()
    return TEACHER_LINEAGE_ADMISSION_ID_PREFIX + digest


def _content_addressed_id(
    value: Mapping[str, Any],
    *,
    id_field: str,
    prefix: str,
    domain: bytes,
) -> str:
    normalized = dict(value)
    normalized[id_field] = prefix + _ZERO_SHA256
    digest = hashlib.sha256(
        _framed((domain, canonical_json_bytes(normalized)))
    ).hexdigest()
    return prefix + digest


def teacher_materialization_lineage_admission_signing_bundle_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def teacher_materialization_lineage_admission_signature_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=TEACHER_LINEAGE_ADMISSION_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


def _snapshot_file(path: Path, field: str, max_bytes: int) -> tuple[Path, bytes]:
    absolute = _reject_reparse_components(path, field)
    before = os.lstat(absolute)
    if not stat.S_ISREG(before.st_mode):
        _fail(field, "must be a regular file")
    if before.st_nlink != 1:
        _fail(field, "hard-linked files are not accepted")
    if before.st_size > max_bytes:
        _fail(field, f"exceeds the {max_bytes}-byte limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            _fail(field, "must remain a single-link regular file while opened")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _fail(field, "changed while it was being opened")
        raw = bytearray()
        while len(raw) <= max_bytes:
            block = os.read(
                descriptor,
                min(1_048_576, max_bytes + 1 - len(raw)),
            )
            if not block:
                break
            raw.extend(block)
        if len(raw) > max_bytes:
            _fail(field, f"exceeds the {max_bytes}-byte limit")
        closed_over = os.fstat(descriptor)
        if (
            closed_over.st_nlink != 1
            or closed_over.st_size != opened.st_size
            or closed_over.st_mtime_ns != opened.st_mtime_ns
        ):
            _fail(field, "changed while it was being read")
    finally:
        os.close(descriptor)
    after = os.lstat(absolute)
    if (
        (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
        or after.st_nlink != 1
        or after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
    ):
        _fail(field, "path changed while its bytes were captured")
    return absolute, bytes(raw)


def _snapshot_package_tree(path: Path) -> tuple[Path, _PackageSnapshot]:
    root = _reject_reparse_components(path, "teacher materialization package")
    if not root.is_dir():
        _fail("teacher materialization package", "must be a directory")
    raw_files: dict[str, bytes] = {}
    files: list[dict[str, Any]] = []
    total = 0
    for current, directories, names in os.walk(root, followlinks=False):
        directories.sort()
        names.sort()
        current_path = Path(current)
        for directory in directories:
            directory_path = _reject_reparse_components(
                current_path / directory,
                "teacher materialization package directory",
            )
            if not directory_path.is_dir():
                _fail(
                    "teacher materialization package directory",
                    "must remain a directory",
                )
        for name in names:
            if len(files) >= MAX_TEACHER_MATERIALIZATION_PACKAGE_FILES:
                _fail(
                    "teacher materialization package",
                    "contains too many files",
                )
            file_path = current_path / name
            try:
                relative = PurePosixPath(file_path.relative_to(root)).as_posix()
            except ValueError as error:  # pragma: no cover - os.walk stays under root
                raise ValidationError(
                    "teacher materialization package: file escaped the package root"
                ) from error
            _, raw = _snapshot_file(
                file_path,
                f"teacher materialization package file {relative!r}",
                MAX_TEACHER_MATERIALIZATION_PACKAGE_FILE_BYTES,
            )
            total += len(raw)
            if total > MAX_TEACHER_MATERIALIZATION_PACKAGE_BYTES:
                _fail(
                    "teacher materialization package",
                    "exceeds its aggregate byte limit",
                )
            raw_files[relative] = raw
            files.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "sizeBytes": len(raw),
                }
            )
    if not files:
        _fail("teacher materialization package", "must not be empty")
    tree = {
        "schemaVersion": TEACHER_MATERIALIZATION_PACKAGE_TREE_SCHEMA_VERSION,
        "files": files,
    }
    return root, _PackageSnapshot(
        raw_files=raw_files,
        files=tuple(files),
        tree_sha256=hashlib.sha256(canonical_json_bytes(tree)).hexdigest(),
        byte_count=total,
    )


def _parse_canonical_jsonl(raw: bytes, field: str) -> list[dict[str, Any]]:
    if not raw:
        _fail(field, "must not be empty")
    records: list[dict[str, Any]] = []
    position = 0
    for line_number, raw_line in enumerate(raw.splitlines(keepends=True), start=1):
        if not raw_line.endswith(b"\n") or raw_line.endswith(b"\r\n"):
            _fail(f"{field} line {line_number}", "must end with exactly one LF byte")
        line = raw_line[:-1]
        if not line:
            _fail(f"{field} line {line_number}", "must not be blank")
        value = _load_json_object_bytes(line, f"{field} line {line_number}")
        if canonical_json_bytes(value) != line:
            _fail(f"{field} line {line_number}", "must be exact canonical JSON")
        records.append(value)
        position += len(raw_line)
    if position != len(raw):
        _fail(field, "must end with exactly one LF byte per record")
    return records


def _load_canonical_record(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        _fail(
            "teacher materialization record",
            "must be canonical JSON followed by one LF",
        )
    document = _load_json_object_bytes(raw[:-1], "teacher materialization record")
    if raw != canonical_json_bytes(document) + b"\n":
        _fail(
            "teacher materialization record",
            "must be canonical JSON followed by one LF",
        )
    return document


def _anchor_pair(
    record: Mapping[str, Any],
    *,
    expected_admission_sha256: str | None,
    field: str,
) -> tuple[str, str]:
    verification = record.get("verification")
    if not isinstance(verification, Mapping):
        _fail(f"{field}.verification", "must be an object")
    evidence = verification.get("evidence")
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) for item in evidence
    ):
        _fail(f"{field}.verification.evidence", "must be a string array")
    knowledge = [item for item in evidence if item.startswith("knowledgeClass=")]
    teacher = [item for item in evidence if item.startswith("teacherAdmissionSha256=")]
    if len(knowledge) != 1 or knowledge[0] not in {
        "knowledgeClass=candidate-stable",
        "knowledgeClass=retrieval-only",
    }:
        _fail(
            f"{field}.verification.evidence",
            "must preserve exactly one supported knowledgeClass anchor",
        )
    if len(teacher) != 1:
        _fail(
            f"{field}.verification.evidence",
            "must preserve exactly one teacherAdmissionSha256 anchor",
        )
    admission_sha256 = _sha256(
        teacher[0].split("=", 1)[1],
        f"{field}.verification.evidence teacherAdmissionSha256",
    )
    if (
        expected_admission_sha256 is not None
        and admission_sha256 != expected_admission_sha256
    ):
        _fail(
            f"{field}.verification.evidence",
            "must preserve the exact materialized teacherAdmissionSha256 anchor",
        )
    return knowledge[0].split("=", 1)[1], admission_sha256


def teacher_lineage_subjects_from_corpus(
    corpus: ExpertCorpus,
) -> list[dict[str, str]]:
    """Project ordered OpenWeightTeacher identities from a validated corpus."""

    if not isinstance(corpus, ExpertCorpus):
        _fail("teacher lineage reviewed corpus", "must be a validated ExpertCorpus")
    subjects: list[dict[str, str]] = []
    for record in corpus.records.values():
        row = record.document
        lineage = row.get("lineage")
        if not isinstance(lineage, dict):  # pragma: no cover - ExpertCorpus invariant
            _fail("teacher lineage reviewed corpus.lineage", "must be an object")
        if lineage.get("origin") != "OpenWeightTeacher":
            continue
        knowledge_class, admission_sha256 = _anchor_pair(
            row,
            expected_admission_sha256=None,
            field=f"teacher lineage reviewed row {row.get('id')!r}",
        )
        subjects.append(
            {
                "exampleId": row["id"],
                "stableSubjectSha256": teacher_lineage_subject_sha256(row),
                "knowledgeClass": knowledge_class,
                "teacherAdmissionSha256": admission_sha256,
            }
        )
    if not subjects:
        _fail(
            "teacher lineage reviewed corpus",
            "must contain at least one OpenWeightTeacher row",
        )
    return subjects


def _relative_snapshot_path(relative: str) -> str:
    return PurePosixPath("inputs/snapshot", relative).as_posix()


def _derive_teacher_lineage(
    *,
    materialization_path: Path,
    runtime_binding_path: Path,
    reviewed_dataset_path: Path,
    reviewer_evidence_path: Path,
    reviewer_id: str,
    reviewed_at_utc: str,
    reviewed_corpus: ExpertCorpus | None = None,
    reviewed_dataset_bytes: bytes | None = None,
) -> _DerivedTeacherLineage:
    reviewer_id = _identifier(reviewer_id, "teacher lineage reviewerId")
    reviewed_at = _canonical_utc_second(
        reviewed_at_utc, "teacher lineage reviewedAtUtc"
    )

    package_root, package_before = _snapshot_package_tree(materialization_path)
    runtime_path, runtime_raw_before = _snapshot_file(
        runtime_binding_path,
        "teacher lineage runtime binding",
        MAX_TEACHER_RUNTIME_BYTES,
    )
    if reviewed_corpus is not None and reviewed_dataset_bytes is None:
        possible_raw = getattr(reviewed_corpus, "raw", None)
        if isinstance(possible_raw, bytes):
            reviewed_dataset_bytes = possible_raw
    if (reviewed_corpus is None) != (reviewed_dataset_bytes is None):
        _fail(
            "teacher lineage reviewed corpus snapshot",
            "must supply both a validated ExpertCorpus and its exact raw bytes",
        )
    if reviewed_corpus is None:
        dataset_path, dataset_raw_before = _snapshot_file(
            reviewed_dataset_path,
            "teacher lineage reviewed corpus",
            MAX_CORPUS_BYTES,
        )
        corpus = _parse_expert_corpus(dataset_path)
    else:
        if not isinstance(reviewed_corpus, ExpertCorpus):
            _fail(
                "teacher lineage reviewed corpus",
                "must be a validated ExpertCorpus",
            )
        if not isinstance(reviewed_dataset_bytes, bytes):
            _fail(
                "teacher lineage reviewed corpus snapshot",
                "must be exact immutable bytes",
            )
        dataset_path = Path(reviewed_dataset_path)
        if os.path.normcase(os.path.abspath(dataset_path)) != os.path.normcase(
            os.path.abspath(reviewed_corpus.path)
        ):
            _fail(
                "teacher lineage reviewed corpus path",
                "does not match the validated ExpertCorpus path",
            )
        dataset_raw_before = reviewed_dataset_bytes
        corpus = reviewed_corpus
        if (
            len(dataset_raw_before) != corpus.byte_count
            or hashlib.sha256(dataset_raw_before).hexdigest() != corpus.sha256
        ):
            _fail(
                "teacher lineage reviewed corpus snapshot",
                "does not match the validated ExpertCorpus identity",
            )
    evidence_path, evidence_raw_before = _snapshot_file(
        reviewer_evidence_path,
        "teacher lineage reviewer evidence",
        MAX_TEACHER_LINEAGE_REVIEWER_EVIDENCE_BYTES,
    )
    if not evidence_raw_before:
        _fail("teacher lineage reviewer evidence", "must not be empty")

    package = validate_teacher_materialization(package_root, now=reviewed_at)
    embedded_selection = package_root / SELECTION_SNAPSHOT_PATH
    selection = validate_teacher_selection_manifest(
        embedded_selection,
        now=reviewed_at,
    )
    runtime = _load_teacher_runtime_binding_local(runtime_path)
    package_root_after, package_after = _snapshot_package_tree(package_root)
    _, runtime_raw_after = _snapshot_file(
        runtime_path,
        "teacher lineage runtime binding",
        MAX_TEACHER_RUNTIME_BYTES,
    )
    runtime_after = _load_teacher_runtime_binding_local(runtime_path)
    if reviewed_corpus is None:
        _, dataset_raw_after = _snapshot_file(
            dataset_path,
            "teacher lineage reviewed corpus",
            MAX_CORPUS_BYTES,
        )
    else:
        dataset_raw_after = dataset_raw_before
    _, evidence_raw_after = _snapshot_file(
        evidence_path,
        "teacher lineage reviewer evidence",
        MAX_TEACHER_LINEAGE_REVIEWER_EVIDENCE_BYTES,
    )
    if package_root_after != package_root or package_before != package_after:
        _fail("teacher materialization package", "changed during lineage validation")
    if runtime_raw_before != runtime_raw_after or runtime != runtime_after:
        _fail("teacher lineage runtime binding", "changed during lineage validation")
    if (
        dataset_raw_before != dataset_raw_after
        or corpus.sha256 != hashlib.sha256(dataset_raw_before).hexdigest()
    ):
        _fail("teacher lineage reviewed corpus", "changed during lineage validation")
    if evidence_raw_before != evidence_raw_after:
        _fail("teacher lineage reviewer evidence", "changed during lineage validation")

    required_package_files = {
        MATERIALIZED_DATASET_PATH,
        MATERIALIZATION_RECORD_PATH,
        SELECTION_SNAPSHOT_PATH,
    }
    if not required_package_files.issubset(package_before.raw_files):
        _fail("teacher materialization package", "is missing canonical lineage files")
    materialization_record_raw = package_before.raw_files[MATERIALIZATION_RECORD_PATH]
    materialization_record = _load_canonical_record(materialization_record_raw)
    draft_dataset_raw = package_before.raw_files[MATERIALIZED_DATASET_PATH]
    draft_rows = _parse_canonical_jsonl(
        draft_dataset_raw, "teacher materialization draft dataset"
    )
    if package.materialization_id != materialization_record["materializationId"]:
        _fail("teacher materialization record", "changed after package validation")
    if package.dataset_sha256 != hashlib.sha256(draft_dataset_raw).hexdigest():
        _fail("teacher materialization draft dataset", "changed after validation")

    generation_binding = selection.document["inputs"]["generationManifest"]
    generation_snapshot_path = _relative_snapshot_path(generation_binding["path"])
    generation_raw = package_before.raw_files.get(generation_snapshot_path)
    if generation_raw is None:
        _fail(
            "teacher materialization generation manifest",
            "is absent from the exact package tree",
        )
    generation_document = _load_json_object_bytes(
        generation_raw, "teacher materialization generation manifest"
    )
    if (
        generation_document.get("schemaVersion")
        != TEACHER_GENERATION_MANIFEST_SCHEMA_VERSION
    ):
        _fail(
            "teacher materialization generation manifest.schemaVersion",
            "must be manifest v2; historical v1 has no runtime-binding lineage",
        )

    runtime_hashes = {
        candidate.get("runtimeBindingFileSha256") for candidate in selection.candidates
    }
    if None in runtime_hashes or len(runtime_hashes) != 1:
        _fail(
            "teacher materialization candidates.runtimeBindingFileSha256",
            "must contain one exact v2 runtime-binding file hash",
        )
    expected_runtime_file_sha256 = next(iter(runtime_hashes))
    if runtime.file_sha256 != expected_runtime_file_sha256:
        _fail(
            "teacher lineage runtime binding",
            "does not match every selected manifest-v2 candidate",
        )
    first_candidate = selection.candidates[0]
    if any(
        candidate["teacher"] != first_candidate["teacher"]
        for candidate in selection.candidates
    ):
        _fail("teacher materialization candidates", "do not share one teacher identity")
    if runtime.document["teacher"] != first_candidate["teacher"]:
        _fail(
            "teacher lineage runtime binding.teacher",
            "does not match the exact selected teacher identity",
        )
    if runtime.document["evidenceStatus"] != TEACHER_RUNTIME_BINDING_EVIDENCE_STATUS:
        _fail(
            "teacher lineage runtime binding.evidenceStatus",
            "must remain an unattested observation",
        )
    if (
        runtime.document["candidateCatalog"]["sha256"]
        != selection.document["inputs"]["candidateCatalog"]["sha256"]
    ):
        _fail(
            "teacher lineage runtime binding.candidateCatalog.sha256",
            "does not match the materialized catalog",
        )

    admissions = materialization_record["admissions"]
    if not isinstance(admissions, list) or len(admissions) != len(draft_rows):
        _fail(
            "teacher materialization record.admissions",
            "must match every materialized draft row",
        )
    admission_by_id: dict[str, Mapping[str, Any]] = {}
    draft_by_id: dict[str, tuple[int, Mapping[str, Any]]] = {}
    draft_id_by_conversation_sha256: dict[str, str] = {}
    for position, (draft, admission) in enumerate(
        zip(draft_rows, admissions, strict=True)
    ):
        example_id = draft.get("id")
        if not isinstance(example_id, str) or admission.get("exampleId") != example_id:
            _fail(
                "teacher materialization record.admissions",
                "does not follow exact draft row order",
            )
        if example_id in draft_by_id:
            _fail("teacher materialization draft dataset", "duplicates an example ID")
        admission_hash = _sha256(
            admission.get("admissionSha256"),
            f"teacher materialization admission {example_id!r}.admissionSha256",
        )
        _anchor_pair(
            draft,
            expected_admission_sha256=admission_hash,
            field=f"teacher materialization draft {example_id!r}",
        )
        conversation_sha256 = _sha256(
            draft.get("conversationSha256"),
            f"teacher materialization draft {example_id!r}.conversationSha256",
        )
        if admission.get("conversationSha256") != conversation_sha256:
            _fail(
                f"teacher materialization admission {example_id!r}",
                "does not bind the exact draft conversation",
            )
        admission_by_id[example_id] = admission
        draft_by_id[example_id] = (position, draft)
        draft_id_by_conversation_sha256[conversation_sha256] = example_id

    forbidden_reviewers: set[str] = {
        selection.document["selection"]["selectedBy"],
        selection.deny_set["custodian"],
    }
    latest_lineage_time = _utc_second(
        selection.document["selection"]["selectedAtUtc"],
        "teacher selection selectedAtUtc",
    )
    latest_lineage_time = max(
        latest_lineage_time,
        _utc_second(
            selection.deny_set["createdAtUtc"],
            "teacher overlap deny-set createdAtUtc",
        ),
    )
    for candidate in selection.candidates:
        forbidden_reviewers.add(candidate["authority"]["producer"])
        forbidden_reviewers.add(candidate["authority"]["reviewer"])
        latest_lineage_time = max(
            latest_lineage_time,
            _utc_second(candidate["capturedAtUtc"], "teacher candidate capturedAtUtc"),
        )

    subjects: list[dict[str, str]] = []
    prior_draft_position = -1
    for record in corpus.records.values():
        row = record.document
        example_id = row["id"]
        draft_match = draft_by_id.get(example_id)
        if row["lineage"]["origin"] != "OpenWeightTeacher":
            materialized_conversation_id = draft_id_by_conversation_sha256.get(
                row["conversationSha256"]
            )
            if draft_match is not None or materialized_conversation_id is not None:
                _fail(
                    f"teacher lineage reviewed row {example_id!r}.lineage.origin",
                    "downgrades or duplicates a materialized OpenWeightTeacher conversation",
                )
            continue
        if draft_match is None:
            _fail(
                f"teacher lineage reviewed row {example_id!r}",
                "is not present in the exact materialization",
            )
        draft_position, draft = draft_match
        if draft_position <= prior_draft_position:
            _fail(
                "teacher lineage reviewed corpus",
                "reorders or duplicates materialized OpenWeightTeacher rows",
            )
        prior_draft_position = draft_position
        if teacher_lineage_subject_fields(row) != teacher_lineage_subject_fields(draft):
            _fail(
                f"teacher lineage reviewed row {example_id!r}",
                "does not exactly match its stable materialized subject",
            )
        admission = admission_by_id[example_id]
        knowledge_class, admission_sha256 = _anchor_pair(
            row,
            expected_admission_sha256=admission["admissionSha256"],
            field=f"teacher lineage reviewed row {example_id!r}",
        )
        forbidden_reviewers.add(row["verification"]["reviewer"])
        latest_lineage_time = max(latest_lineage_time, record.verified_at)
        subjects.append(
            {
                "exampleId": example_id,
                "stableSubjectSha256": teacher_lineage_subject_sha256(row),
                "knowledgeClass": knowledge_class,
                "teacherAdmissionSha256": admission_sha256,
            }
        )
    if not subjects:
        _fail(
            "teacher lineage reviewed corpus",
            "must contain at least one OpenWeightTeacher row",
        )
    if reviewer_id in forbidden_reviewers:
        _fail(
            "teacher lineage reviewerId",
            "must differ from producer, selector, deny-set custodian, planned reviewer, and final reviewers",
        )
    if reviewed_at < latest_lineage_time:
        _fail(
            "teacher lineage reviewedAtUtc",
            "must not precede capture, selection, deny-set creation, or final review",
        )

    record_inputs = materialization_record["inputs"]
    materialization = {
        "materializationId": materialization_record["materializationId"],
        "materializationRecordSha256": hashlib.sha256(
            materialization_record_raw
        ).hexdigest(),
        "draftDatasetSha256": hashlib.sha256(draft_dataset_raw).hexdigest(),
        "draftDatasetSizeBytes": len(draft_dataset_raw),
        "draftRecordCount": len(draft_rows),
        "packageTreeSchemaVersion": (
            TEACHER_MATERIALIZATION_PACKAGE_TREE_SCHEMA_VERSION
        ),
        "packageTreeSha256": package_before.tree_sha256,
        "packageFileCount": len(package_before.files),
        "packageSizeBytes": package_before.byte_count,
        "selectionManifestSha256": selection.manifest_sha256,
        "candidateSetSha256": selection.candidate_set_sha256,
        "generationManifestSha256": record_inputs["generationManifestSha256"],
        "candidateCatalogSha256": record_inputs["candidateCatalogSha256"],
        "overlapDenySetSha256": selection.deny_set_sha256,
        "overlapDenySetId": selection.deny_set["denySetId"],
        "overlapScopeSha256": selection.deny_set["scopeSha256"],
        "candidateBatchId": first_candidate["batchId"],
    }
    runtime_observation = {
        "evidenceStatus": TEACHER_RUNTIME_BINDING_EVIDENCE_STATUS,
        "runtimeBindingFileSha256": runtime.file_sha256,
        "runtimeBindingSha256": runtime.document["bindingSha256"],
        "candidateCatalogSha256": runtime.document["candidateCatalog"]["sha256"],
        "runtimeDescriptorSha256": runtime.document["runtimeDescriptor"]["sha256"],
        "chatTemplateSha256": runtime.document["chatTemplate"]["sha256"],
        "executionModelId": runtime.document["teacher"]["executionModelId"],
    }
    reviewed_corpus = {
        "sha256": hashlib.sha256(dataset_raw_before).hexdigest(),
        "sizeBytes": len(dataset_raw_before),
        "recordCount": len(corpus.records),
        "openWeightTeacherRecordCount": len(subjects),
        "subjects": subjects,
    }
    reviewer_evidence = {
        "sha256": hashlib.sha256(evidence_raw_before).hexdigest(),
        "sizeBytes": len(evidence_raw_before),
    }
    return _DerivedTeacherLineage(
        reviewer_evidence=reviewer_evidence,
        reviewed_corpus=reviewed_corpus,
        materialization=materialization,
        runtime_observation=runtime_observation,
    )


def _validate_subjects(value: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 10_000:
        _fail(field, "must contain 1 to 10000 ordered subjects")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_field = f"{field}[{index}]"
        subject = _exact_keys(
            item,
            {
                "exampleId",
                "stableSubjectSha256",
                "knowledgeClass",
                "teacherAdmissionSha256",
            },
            item_field,
        )
        example_id = _identifier(subject["exampleId"], f"{item_field}.exampleId")
        if example_id in seen:
            _fail(f"{item_field}.exampleId", "duplicates an earlier subject")
        seen.add(example_id)
        knowledge_class = subject["knowledgeClass"]
        if knowledge_class not in {"candidate-stable", "retrieval-only"}:
            _fail(f"{item_field}.knowledgeClass", "is unsupported")
        result.append(
            {
                "exampleId": example_id,
                "stableSubjectSha256": _sha256(
                    subject["stableSubjectSha256"],
                    f"{item_field}.stableSubjectSha256",
                ),
                "knowledgeClass": knowledge_class,
                "teacherAdmissionSha256": _sha256(
                    subject["teacherAdmissionSha256"],
                    f"{item_field}.teacherAdmissionSha256",
                ),
            }
        )
    return result


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_keys(value, _PAYLOAD_KEYS, "teacher lineage admission payload")
    constants: dict[str, Any] = {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
        "scope": TEACHER_LINEAGE_ADMISSION_SCOPE,
        "decision": "admitted",
        "reusable": True,
        "reviewReceiptIssuanceAuthorized": True,
        "runtimeAttested": False,
        "teacherWeightsAttested": False,
        "teacherCorrectnessAuthorized": False,
        "reviewDecisionAuthorized": False,
        "rightsAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "evaluationAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "statement": TEACHER_LINEAGE_ADMISSION_STATEMENT,
    }
    for name, expected in constants.items():
        if type(payload[name]) is not type(expected) or payload[name] != expected:
            _fail(
                f"teacher lineage admission payload.{name}",
                "does not match the closed authority contract",
            )
    if not isinstance(
        payload["lineageAdmissionId"], str
    ) or not _ADMISSION_ID_RE.fullmatch(payload["lineageAdmissionId"]):
        _fail(
            "teacher lineage admission payload.lineageAdmissionId", "is not canonical"
        )
    _identifier(payload["reviewerId"], "teacher lineage admission payload.reviewerId")
    reviewed = _canonical_utc_second(
        payload["reviewedAtUtc"], "teacher lineage admission payload.reviewedAtUtc"
    )
    issued = _canonical_utc_second(
        payload["issuedAtUtc"], "teacher lineage admission payload.issuedAtUtc"
    )
    not_before = _canonical_utc_second(
        payload["notBeforeUtc"], "teacher lineage admission payload.notBeforeUtc"
    )
    expires = _canonical_utc_second(
        payload["expiresAtUtc"], "teacher lineage admission payload.expiresAtUtc"
    )
    if not reviewed <= issued <= not_before < expires:
        _fail(
            "teacher lineage admission payload validity",
            "must satisfy reviewedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_TEACHER_LINEAGE_ADMISSION_VALIDITY:
        _fail(
            "teacher lineage admission payload validity",
            "must not exceed 366 days",
        )

    evidence = _exact_keys(
        payload["reviewerEvidence"],
        {"sha256", "sizeBytes"},
        "teacher lineage admission payload.reviewerEvidence",
    )
    _sha256(evidence["sha256"], "teacher lineage admission reviewer evidence SHA-256")
    _integer(
        evidence["sizeBytes"],
        "teacher lineage admission reviewer evidence sizeBytes",
        1,
        MAX_TEACHER_LINEAGE_REVIEWER_EVIDENCE_BYTES,
    )

    corpus = _exact_keys(
        payload["reviewedCorpus"],
        {
            "sha256",
            "sizeBytes",
            "recordCount",
            "openWeightTeacherRecordCount",
            "subjects",
        },
        "teacher lineage admission payload.reviewedCorpus",
    )
    _sha256(corpus["sha256"], "teacher lineage admission reviewed corpus SHA-256")
    _integer(
        corpus["sizeBytes"],
        "teacher lineage admission reviewed corpus sizeBytes",
        1,
        MAX_CORPUS_BYTES,
    )
    _integer(
        corpus["recordCount"],
        "teacher lineage admission reviewed corpus recordCount",
        1,
        MAX_CORPUS_RECORDS,
    )
    subjects = _validate_subjects(
        corpus["subjects"], "teacher lineage admission payload.reviewedCorpus.subjects"
    )
    if _integer(
        corpus["openWeightTeacherRecordCount"],
        "teacher lineage admission reviewed corpus openWeightTeacherRecordCount",
        1,
        10_000,
    ) != len(subjects):
        _fail(
            "teacher lineage admission reviewed corpus openWeightTeacherRecordCount",
            "does not match the ordered subject count",
        )

    materialization = _exact_keys(
        payload["materialization"],
        {
            "materializationId",
            "materializationRecordSha256",
            "draftDatasetSha256",
            "draftDatasetSizeBytes",
            "draftRecordCount",
            "packageTreeSchemaVersion",
            "packageTreeSha256",
            "packageFileCount",
            "packageSizeBytes",
            "selectionManifestSha256",
            "candidateSetSha256",
            "generationManifestSha256",
            "candidateCatalogSha256",
            "overlapDenySetSha256",
            "overlapDenySetId",
            "overlapScopeSha256",
            "candidateBatchId",
        },
        "teacher lineage admission payload.materialization",
    )
    if not isinstance(materialization["materializationId"], str) or not (
        _MATERIALIZATION_ID_RE.fullmatch(materialization["materializationId"])
    ):
        _fail("teacher lineage admission materializationId", "is not canonical")
    if materialization["packageTreeSchemaVersion"] != (
        TEACHER_MATERIALIZATION_PACKAGE_TREE_SCHEMA_VERSION
    ):
        _fail(
            "teacher lineage admission materialization.packageTreeSchemaVersion",
            "does not match the package-tree contract",
        )
    for name in (
        "materializationRecordSha256",
        "draftDatasetSha256",
        "packageTreeSha256",
        "selectionManifestSha256",
        "candidateSetSha256",
        "generationManifestSha256",
        "candidateCatalogSha256",
        "overlapDenySetSha256",
        "overlapScopeSha256",
    ):
        _sha256(
            materialization[name],
            f"teacher lineage admission materialization.{name}",
        )
    _identifier(
        materialization["overlapDenySetId"],
        "teacher lineage admission materialization.overlapDenySetId",
    )
    if not isinstance(materialization["candidateBatchId"], str) or not (
        _BATCH_ID_RE.fullmatch(materialization["candidateBatchId"])
    ):
        _fail("teacher lineage admission candidateBatchId", "is not canonical")
    _integer(
        materialization["draftDatasetSizeBytes"],
        "teacher lineage admission materialization.draftDatasetSizeBytes",
        1,
        MAX_CORPUS_BYTES,
    )
    _integer(
        materialization["draftRecordCount"],
        "teacher lineage admission materialization.draftRecordCount",
        1,
        10_000,
    )
    _integer(
        materialization["packageFileCount"],
        "teacher lineage admission materialization.packageFileCount",
        1,
        MAX_TEACHER_MATERIALIZATION_PACKAGE_FILES,
    )
    _integer(
        materialization["packageSizeBytes"],
        "teacher lineage admission materialization.packageSizeBytes",
        1,
        MAX_TEACHER_MATERIALIZATION_PACKAGE_BYTES,
    )

    runtime = _exact_keys(
        payload["runtimeObservation"],
        {
            "evidenceStatus",
            "runtimeBindingFileSha256",
            "runtimeBindingSha256",
            "candidateCatalogSha256",
            "runtimeDescriptorSha256",
            "chatTemplateSha256",
            "executionModelId",
        },
        "teacher lineage admission payload.runtimeObservation",
    )
    if runtime["evidenceStatus"] != TEACHER_RUNTIME_BINDING_EVIDENCE_STATUS:
        _fail(
            "teacher lineage admission runtimeObservation.evidenceStatus",
            "must remain an unattested observation",
        )
    for name in (
        "runtimeBindingFileSha256",
        "runtimeBindingSha256",
        "candidateCatalogSha256",
        "runtimeDescriptorSha256",
        "chatTemplateSha256",
    ):
        _sha256(runtime[name], f"teacher lineage admission runtimeObservation.{name}")
    if not isinstance(runtime["executionModelId"], str) or not (
        _EXECUTION_MODEL_ID_RE.fullmatch(runtime["executionModelId"])
    ):
        _fail("teacher lineage admission executionModelId", "is not canonical")
    if runtime["candidateCatalogSha256"] != materialization["candidateCatalogSha256"]:
        _fail(
            "teacher lineage admission runtimeObservation.candidateCatalogSha256",
            "does not match the materialized candidate catalog",
        )
    if payload["lineageAdmissionId"] != teacher_materialization_lineage_admission_id(
        payload
    ):
        _fail(
            "teacher lineage admission payload.lineageAdmissionId",
            "does not match the content-derived identity",
        )
    return payload


def _build_teacher_lineage_payload(
    derived: _DerivedTeacherLineage,
    *,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
        "lineageAdmissionId": TEACHER_LINEAGE_ADMISSION_ID_PREFIX + _ZERO_SHA256,
        "scope": TEACHER_LINEAGE_ADMISSION_SCOPE,
        "decision": "admitted",
        "reusable": True,
        "reviewReceiptIssuanceAuthorized": True,
        "runtimeAttested": False,
        "teacherWeightsAttested": False,
        "teacherCorrectnessAuthorized": False,
        "reviewDecisionAuthorized": False,
        "rightsAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "evaluationAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "reviewerId": reviewer_id,
        "reviewedAtUtc": reviewed_at_utc,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "reviewerEvidence": derived.reviewer_evidence,
        "reviewedCorpus": derived.reviewed_corpus,
        "materialization": derived.materialization,
        "runtimeObservation": derived.runtime_observation,
        "statement": TEACHER_LINEAGE_ADMISSION_STATEMENT,
    }
    payload["lineageAdmissionId"] = teacher_materialization_lineage_admission_id(
        payload
    )
    return _validate_payload(payload)


def _ensure_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> tuple[datetime, datetime]:
    not_before = _canonical_utc_second(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc_second(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "is not active")
    return not_before, expires


def _framed(fields: Iterable[str | bytes]) -> bytes:
    framed = bytearray()
    for field in fields:
        raw = field if isinstance(field, bytes) else field.encode("utf-8", "strict")
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


def _unsigned_envelope(
    payload_bytes: bytes,
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
        "payloadEncoding": TEACHER_LINEAGE_ADMISSION_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": TEACHER_LINEAGE_ADMISSION_ALGORITHM,
        "signatureFormat": TEACHER_LINEAGE_ADMISSION_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


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
    if signature_format == TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, 64)
        if len(signature) != 64:
            _fail(field, "must decode to exactly 64 bytes")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif signature_format == TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT:
        signature = _base64url_decode(
            value, field, MAX_TEACHER_LINEAGE_ADMISSION_DER_SIGNATURE_BYTES
        )
        try:
            r, s = decode_dss_signature(signature)
        except ValueError as error:
            raise ValidationError(f"{field}: is not canonical ECDSA DER") from error
        if encode_dss_signature(r, s) != signature:
            _fail(field, "must use canonical ECDSA DER")
    else:
        _fail(f"{field} format", "must be 'asn1-der' or 'ieee-p1363-fixed-64'")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        _fail(field, "contains out-of-range P-256 values")
    if s > _P256_HALF_ORDER:
        s = _P256_ORDER - s
    normalized = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    _verify_p1363_low_s(public_key, signature_input, normalized)
    return normalized


def _build_signing_bundle_document(
    payload: Mapping[str, Any],
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    payload_bytes = canonical_json_bytes(payload)
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    signature_preimage = _signature_input(envelope, payload_bytes)
    signature_digest = hashlib.sha256(signature_preimage).digest()
    bundle: dict[str, Any] = {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": TEACHER_LINEAGE_ADMISSION_SIGNING_STATUS,
        "authority": {
            "teacherLineageAdmissionIssuance": False,
            "reviewReceiptIssuance": False,
            "runtimeAttestation": False,
            "teacherWeightAttestation": False,
            "rightsReview": False,
            "release": False,
            "training": False,
            "evaluation": False,
            "promotionDecision": False,
            "deployment": False,
            "hostedServing": False,
            "installation": False,
            "verifierExecution": False,
            "strategyExecution": False,
        },
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": audience,
            "keyId": key_id,
            "signerRole": signer_role,
        },
        "lineageAdmissionId": payload["lineageAdmissionId"],
        "reviewedCorpusSha256": payload["reviewedCorpus"]["sha256"],
        "materializationId": payload["materialization"]["materializationId"],
        "signatureContract": {
            "algorithm": TEACHER_LINEAGE_ADMISSION_ALGORITHM,
            "hashAlgorithm": TEACHER_LINEAGE_ADMISSION_SIGNING_HASH_ALGORITHM,
            "messageType": TEACHER_LINEAGE_ADMISSION_SIGNING_MESSAGE_TYPE,
            "signatureInputEncoding": TEACHER_LINEAGE_ADMISSION_SIGNING_INPUT_ENCODING,
            "acceptedSignatureFormats": [
                TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
                TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "lineageAdmissionId": payload["lineageAdmissionId"],
            "payloadSha256": envelope["payloadSha256"],
            "payload": envelope["payload"],
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = teacher_materialization_lineage_admission_signing_bundle_id(
        bundle
    )
    return bundle


def _validate_signing_bundle_document(
    value: Any,
    *,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    materialization_path: Path,
    runtime_binding_path: Path,
    reviewed_dataset_path: Path,
    reviewer_evidence_path: Path,
    now: datetime,
) -> dict[str, Any]:
    bundle = _exact_keys(
        value,
        {
            "schemaVersion",
            "bundleId",
            "status",
            "authority",
            "trust",
            "lineageAdmissionId",
            "reviewedCorpusSha256",
            "materializationId",
            "signatureContract",
            "request",
        },
        "teacher lineage admission signing bundle",
    )
    constants = {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "status": TEACHER_LINEAGE_ADMISSION_SIGNING_STATUS,
    }
    for name, expected in constants.items():
        if type(bundle[name]) is not type(expected) or bundle[name] != expected:
            _fail(
                f"teacher lineage admission signing bundle.{name}",
                "does not match the contract",
            )

    authority_keys = {
        "teacherLineageAdmissionIssuance",
        "reviewReceiptIssuance",
        "runtimeAttestation",
        "teacherWeightAttestation",
        "rightsReview",
        "release",
        "training",
        "evaluation",
        "promotionDecision",
        "deployment",
        "hostedServing",
        "installation",
        "verifierExecution",
        "strategyExecution",
    }
    authority = _exact_keys(
        bundle["authority"],
        authority_keys,
        "teacher lineage admission signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"teacher lineage admission signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )

    trust = _exact_keys(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "teacher lineage admission signing bundle.trust",
    )
    expected_trust = {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }
    for name, expected in expected_trust.items():
        if trust[name] != expected:
            _fail(
                f"teacher lineage admission signing bundle.trust.{name}",
                "does not match externally pinned trust",
            )

    contract = _exact_keys(
        bundle["signatureContract"],
        {
            "algorithm",
            "hashAlgorithm",
            "messageType",
            "signatureInputEncoding",
            "acceptedSignatureFormats",
        },
        "teacher lineage admission signing bundle.signatureContract",
    )
    expected_contract = {
        "algorithm": TEACHER_LINEAGE_ADMISSION_ALGORITHM,
        "hashAlgorithm": TEACHER_LINEAGE_ADMISSION_SIGNING_HASH_ALGORITHM,
        "messageType": TEACHER_LINEAGE_ADMISSION_SIGNING_MESSAGE_TYPE,
        "signatureInputEncoding": TEACHER_LINEAGE_ADMISSION_SIGNING_INPUT_ENCODING,
        "acceptedSignatureFormats": [
            TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
            TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    for name, expected in expected_contract.items():
        if type(contract[name]) is not type(expected) or contract[name] != expected:
            _fail(
                f"teacher lineage admission signing bundle.signatureContract.{name}",
                "does not match the contract",
            )

    request = _exact_keys(
        bundle["request"],
        {
            "lineageAdmissionId",
            "payloadSha256",
            "payload",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "teacher lineage admission signing bundle.request",
    )
    payload_bytes = _base64url_decode(
        request["payload"],
        "teacher lineage admission signing bundle.request.payload",
        MAX_TEACHER_LINEAGE_ADMISSION_PAYLOAD_BYTES,
    )
    if hashlib.sha256(payload_bytes).hexdigest() != _sha256(
        request["payloadSha256"],
        "teacher lineage admission signing bundle.request.payloadSha256",
    ):
        _fail(
            "teacher lineage admission signing bundle.request.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(
        payload_bytes, "teacher lineage admission signing bundle payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail(
            "teacher lineage admission signing bundle payload",
            "must be exact canonical JSON",
        )
    payload = _validate_payload(payload)
    _ensure_payload_active(
        payload, now, "teacher lineage admission signing bundle payload"
    )
    derived = _derive_teacher_lineage(
        materialization_path=materialization_path,
        runtime_binding_path=runtime_binding_path,
        reviewed_dataset_path=reviewed_dataset_path,
        reviewer_evidence_path=reviewer_evidence_path,
        reviewer_id=payload["reviewerId"],
        reviewed_at_utc=payload["reviewedAtUtc"],
    )
    for name, expected in {
        "reviewerEvidence": derived.reviewer_evidence,
        "reviewedCorpus": derived.reviewed_corpus,
        "materialization": derived.materialization,
        "runtimeObservation": derived.runtime_observation,
    }.items():
        if payload[name] != expected:
            _fail(
                f"teacher lineage admission signing bundle payload.{name}",
                "does not match the exact revalidated lineage inputs",
            )

    lineage_admission_id = payload["lineageAdmissionId"]
    for field, supplied in (
        (
            "teacher lineage admission signing bundle.lineageAdmissionId",
            bundle["lineageAdmissionId"],
        ),
        (
            "teacher lineage admission signing bundle.request.lineageAdmissionId",
            request["lineageAdmissionId"],
        ),
    ):
        if supplied != lineage_admission_id:
            _fail(field, "does not match the signed payload identity")
    if bundle["reviewedCorpusSha256"] != payload["reviewedCorpus"]["sha256"]:
        _fail(
            "teacher lineage admission signing bundle.reviewedCorpusSha256",
            "does not match the exact signed reviewed corpus",
        )
    if bundle["materializationId"] != payload["materialization"]["materializationId"]:
        _fail(
            "teacher lineage admission signing bundle.materializationId",
            "does not match the exact signed materialization",
        )

    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    expected_preimage = _signature_input(envelope, payload_bytes)
    supplied_preimage = _base64url_decode(
        request["signaturePreimage"],
        "teacher lineage admission signing bundle.request.signaturePreimage",
        MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != expected_preimage:
        _fail(
            "teacher lineage admission signing bundle.request.signaturePreimage",
            "does not match the exact admission-envelope signature preimage",
        )
    expected_digest = hashlib.sha256(expected_preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "teacher lineage admission signing bundle.request.signatureInput",
        32,
    )
    if len(supplied_digest) != 32 or supplied_digest != expected_digest:
        _fail(
            "teacher lineage admission signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "teacher lineage admission signing bundle.request.signatureInputSha256",
        )
        != expected_digest.hex()
    ):
        _fail(
            "teacher lineage admission signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id
        != teacher_materialization_lineage_admission_signing_bundle_id(bundle)
    ):
        _fail(
            "teacher lineage admission signing bundle.bundleId",
            "does not match the content-derived identity",
        )
    return bundle


def _build_external_signature_document(
    bundle: Mapping[str, Any],
    bundle_bytes: bytes,
    *,
    signature_format: str,
    signature: bytes,
) -> dict[str, Any]:
    request = bundle["request"]
    document: dict[str, Any] = {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION,
        "signatureId": TEACHER_LINEAGE_ADMISSION_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "lineageAdmissionId": bundle["lineageAdmissionId"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    document["signatureId"] = teacher_materialization_lineage_admission_signature_id(
        document
    )
    return document


def _validate_external_signature_document(
    value: Any,
    *,
    bundle: Mapping[str, Any],
    bundle_bytes: bytes,
    public_key: Any,
) -> bytes:
    document = _exact_keys(
        value,
        {
            "schemaVersion",
            "signatureId",
            "signingBundleId",
            "signingBundleSha256",
            "lineageAdmissionId",
            "payloadSha256",
            "signatureInputSha256",
            "publicKeySpkiSha256",
            "format",
            "signature",
        },
        "teacher lineage admission external signature",
    )
    if document["schemaVersion"] != TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION:
        _fail(
            "teacher lineage admission external signature.schemaVersion",
            "is unsupported",
        )
    request = bundle["request"]
    expected_bindings = {
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "lineageAdmissionId": bundle["lineageAdmissionId"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
    }
    for name, expected in expected_bindings.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"teacher lineage admission external signature.{name}")
        if supplied != expected:
            _fail(
                f"teacher lineage admission external signature.{name}",
                "does not match the exact signing bundle",
            )
    preimage = _base64url_decode(
        request["signaturePreimage"],
        "teacher lineage admission signing bundle.request.signaturePreimage",
        MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_INPUT_BYTES,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        public_key=public_key,
        signature_input=preimage,
        field="teacher lineage admission external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id
        != teacher_materialization_lineage_admission_signature_id(document)
    ):
        _fail(
            "teacher lineage admission external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _read_canonical_handoff_document(
    path: str | os.PathLike[str], field: str, max_bytes: int
) -> tuple[Path, bytes, dict[str, Any]]:
    resolved, raw = _snapshot_file(Path(path), field, max_bytes)
    if not raw:
        _fail(field, "must not be empty")
    if not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
        _fail(field, "must end with exactly one LF byte")
    document = _load_json_object_bytes(raw[:-1], field)
    if canonical_json_bytes(document) + b"\n" != raw:
        _fail(field, "must be exact canonical JSON followed by one LF byte")
    return resolved, raw, document


def _validate_trust(
    trust: TeacherMaterializationLineageAdmissionTrust,
) -> tuple[Any, str, str, str, str]:
    if not isinstance(trust, TeacherMaterializationLineageAdmissionTrust):
        _fail("teacher lineage admission trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(trust.public_key_path)
    if actual_spki != trust.public_key_spki_sha256:
        _fail(
            "teacher lineage admission trust public-key SPKI SHA-256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "teacher lineage admission trust audience"),
        _identifier(trust.key_id, "teacher lineage admission trust keyId"),
        _identifier(trust.signer_role, "teacher lineage admission trust signerRole"),
    )


def _validate_envelope(
    value: Mapping[str, Any],
    *,
    path: Path,
    trust: TeacherMaterializationLineageAdmissionTrust,
    materialization_path: Path,
    runtime_binding_path: Path,
    reviewed_dataset_path: Path,
    reviewer_evidence_path: Path,
    expected_envelope_sha256: str | None,
    now: datetime,
    verify_exact_lineage: bool = True,
    reviewed_corpus: ExpertCorpus | None = None,
    reviewed_dataset_bytes: bytes | None = None,
) -> VerifiedTeacherMaterializationLineageAdmission:
    envelope = _exact_keys(value, _ENVELOPE_KEYS, "teacher lineage admission envelope")
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_TEACHER_LINEAGE_ADMISSION_BYTES:
        _fail("teacher lineage admission envelope", "exceeds its byte limit")
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    constants = {
        "schemaVersion": TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION,
        "payloadEncoding": TEACHER_LINEAGE_ADMISSION_PAYLOAD_ENCODING,
        "algorithm": TEACHER_LINEAGE_ADMISSION_ALGORITHM,
        "signatureFormat": TEACHER_LINEAGE_ADMISSION_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(
                f"teacher lineage admission envelope.{name}",
                "does not match externally pinned trust",
            )
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    if (
        expected_envelope_sha256 is not None
        and _sha256(
            expected_envelope_sha256,
            "expected teacher lineage admission envelope SHA-256",
        )
        != envelope_sha256
    ):
        _fail(
            "teacher lineage admission envelope",
            "does not match the expected exact SHA-256",
        )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "teacher lineage admission envelope.payload",
        MAX_TEACHER_LINEAGE_ADMISSION_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            envelope["payloadSha256"],
            "teacher lineage admission envelope.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "teacher lineage admission envelope.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(
        payload_bytes, "teacher lineage admission payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail("teacher lineage admission payload", "must be exact canonical JSON")
    payload = _validate_payload(payload)
    signature = _base64url_decode(
        envelope["signature"],
        "teacher lineage admission envelope.signature",
        64,
    )
    if len(signature) != 64:
        _fail(
            "teacher lineage admission envelope.signature",
            "must be exactly 64 bytes",
        )
    _verify_p1363_low_s(
        public_key,
        _signature_input(envelope, payload_bytes),
        signature,
    )
    not_before = _canonical_utc_second(
        payload["notBeforeUtc"], "teacher lineage admission payload.notBeforeUtc"
    )
    expires = _canonical_utc_second(
        payload["expiresAtUtc"], "teacher lineage admission payload.expiresAtUtc"
    )
    if now < not_before or now >= expires:
        _fail("teacher lineage admission payload validity", "is not active")

    if verify_exact_lineage:
        derived = _derive_teacher_lineage(
            materialization_path=materialization_path,
            runtime_binding_path=runtime_binding_path,
            reviewed_dataset_path=reviewed_dataset_path,
            reviewer_evidence_path=reviewer_evidence_path,
            reviewer_id=payload["reviewerId"],
            reviewed_at_utc=payload["reviewedAtUtc"],
            reviewed_corpus=reviewed_corpus,
            reviewed_dataset_bytes=reviewed_dataset_bytes,
        )
        expected_bindings = {
            "reviewerEvidence": derived.reviewer_evidence,
            "reviewedCorpus": derived.reviewed_corpus,
            "materialization": derived.materialization,
            "runtimeObservation": derived.runtime_observation,
        }
        for name, expected in expected_bindings.items():
            if payload[name] != expected:
                _fail(
                    f"teacher lineage admission payload.{name}",
                    "does not match the exact revalidated lineage inputs",
                )
    reviewed_at = _canonical_utc_second(
        payload["reviewedAtUtc"], "teacher lineage admission payload.reviewedAtUtc"
    )
    issued_at = _canonical_utc_second(
        payload["issuedAtUtc"], "teacher lineage admission payload.issuedAtUtc"
    )
    return VerifiedTeacherMaterializationLineageAdmission(
        path=path,
        envelope=envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        envelope_sha256=envelope_sha256,
        public_key_spki_sha256=spki,
        reviewed_at_utc=reviewed_at,
        issued_at_utc=issued_at,
        not_before_utc=not_before,
        expires_at_utc=expires,
    )


def _load_envelope_file(path: Path) -> tuple[Path, dict[str, Any]]:
    resolved, raw = _snapshot_file(
        path,
        "teacher lineage admission envelope file",
        MAX_TEACHER_LINEAGE_ADMISSION_BYTES + 1,
    )
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        _fail(
            "teacher lineage admission envelope file",
            "must be exact canonical JSON followed by one LF",
        )
    envelope = _load_json_object_bytes(
        raw[:-1], "teacher lineage admission envelope file"
    )
    if raw != canonical_json_bytes(envelope) + b"\n":
        _fail(
            "teacher lineage admission envelope file",
            "must be exact canonical JSON followed by one LF",
        )
    return resolved, envelope


def verify_teacher_materialization_lineage_admission(
    admission_path: str | os.PathLike[str],
    *,
    materialization_path: str | os.PathLike[str],
    runtime_binding_path: str | os.PathLike[str],
    reviewed_dataset_path: str | os.PathLike[str],
    reviewer_evidence_path: str | os.PathLike[str],
    trust: TeacherMaterializationLineageAdmissionTrust,
    expected_envelope_sha256: str | None = None,
    now: datetime | None = None,
    reviewed_corpus: ExpertCorpus | None = None,
    reviewed_dataset_bytes: bytes | None = None,
) -> VerifiedTeacherMaterializationLineageAdmission:
    current = _validation_time(
        now or datetime.now(timezone.utc),
        "teacher lineage admission verification time",
    )
    path, envelope = _load_envelope_file(Path(admission_path))
    return _validate_envelope(
        envelope,
        path=path,
        trust=trust,
        materialization_path=Path(materialization_path),
        runtime_binding_path=Path(runtime_binding_path),
        reviewed_dataset_path=Path(reviewed_dataset_path),
        reviewer_evidence_path=Path(reviewer_evidence_path),
        expected_envelope_sha256=expected_envelope_sha256,
        now=current,
        reviewed_corpus=reviewed_corpus,
        reviewed_dataset_bytes=reviewed_dataset_bytes,
    )


def _reviewed_corpus_snapshot(
    *,
    reviewed_dataset_path: Path,
    reviewed_corpus: ExpertCorpus | None,
    reviewed_dataset_bytes: bytes | None,
) -> tuple[ExpertCorpus, bytes]:
    if reviewed_corpus is not None and reviewed_dataset_bytes is None:
        possible_raw = getattr(reviewed_corpus, "raw", None)
        if isinstance(possible_raw, bytes):
            reviewed_dataset_bytes = possible_raw
    if (reviewed_corpus is None) != (reviewed_dataset_bytes is None):
        _fail(
            "teacher lineage reviewed corpus snapshot",
            "must supply both a validated ExpertCorpus and its exact raw bytes",
        )
    if reviewed_corpus is None:
        path, raw_before = _snapshot_file(
            reviewed_dataset_path,
            "teacher lineage reviewed corpus",
            MAX_CORPUS_BYTES,
        )
        corpus = _parse_expert_corpus(path)
        _, raw_after = _snapshot_file(
            path,
            "teacher lineage reviewed corpus",
            MAX_CORPUS_BYTES,
        )
        if raw_before != raw_after:
            _fail("teacher lineage reviewed corpus", "changed during validation")
        raw = raw_before
    else:
        if not isinstance(reviewed_corpus, ExpertCorpus):
            _fail(
                "teacher lineage reviewed corpus",
                "must be a validated ExpertCorpus",
            )
        if not isinstance(reviewed_dataset_bytes, bytes):
            _fail(
                "teacher lineage reviewed corpus snapshot",
                "must be exact immutable bytes",
            )
        if os.path.normcase(os.path.abspath(reviewed_dataset_path)) != os.path.normcase(
            os.path.abspath(reviewed_corpus.path)
        ):
            _fail(
                "teacher lineage reviewed corpus path",
                "does not match the validated ExpertCorpus path",
            )
        corpus = reviewed_corpus
        raw = reviewed_dataset_bytes
    if (
        not raw
        or len(raw) != corpus.byte_count
        or (hashlib.sha256(raw).hexdigest() != corpus.sha256)
    ):
        _fail(
            "teacher lineage reviewed corpus snapshot",
            "does not match the validated ExpertCorpus identity",
        )
    return corpus, raw


def verify_teacher_materialization_lineage_admission_for_reviewed_corpus(
    admission_path: str | os.PathLike[str],
    *,
    reviewed_dataset_path: str | os.PathLike[str],
    trust: TeacherMaterializationLineageAdmissionTrust,
    expected_envelope_sha256: str | None = None,
    now: datetime | None = None,
    reviewed_corpus: ExpertCorpus | None = None,
    reviewed_dataset_bytes: bytes | None = None,
) -> VerifiedTeacherMaterializationLineageAdmission:
    """Verify a signed admission against the exact reviewed corpus only.

    Signature, external trust, validity, dataset bytes, record count, and ordered
    OpenWeightTeacher stable subjects are rechecked. Issuance callers must use the
    full verifier, which also reopens the one exact materialization package,
    runtime observation, and reviewer evidence.
    """

    current = _validation_time(
        now or datetime.now(timezone.utc),
        "teacher lineage admission verification time",
    )
    path, envelope = _load_envelope_file(Path(admission_path))
    verified = _validate_envelope(
        envelope,
        path=path,
        trust=trust,
        materialization_path=Path(),
        runtime_binding_path=Path(),
        reviewed_dataset_path=Path(reviewed_dataset_path),
        reviewer_evidence_path=Path(),
        expected_envelope_sha256=expected_envelope_sha256,
        now=current,
        verify_exact_lineage=False,
    )
    corpus, raw = _reviewed_corpus_snapshot(
        reviewed_dataset_path=Path(reviewed_dataset_path),
        reviewed_corpus=reviewed_corpus,
        reviewed_dataset_bytes=reviewed_dataset_bytes,
    )
    subjects = teacher_lineage_subjects_from_corpus(corpus)
    actual = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
        "recordCount": len(corpus.records),
        "openWeightTeacherRecordCount": len(subjects),
        "subjects": subjects,
    }
    if verified.payload["reviewedCorpus"] != actual:
        _fail(
            "teacher lineage admission payload.reviewedCorpus",
            "does not match the exact reviewed corpus and ordered teacher subjects",
        )
    return verified


def ensure_teacher_materialization_lineage_admission_active(
    verified: VerifiedTeacherMaterializationLineageAdmission,
    now: datetime,
) -> None:
    if not isinstance(verified, VerifiedTeacherMaterializationLineageAdmission):
        _fail("teacher lineage admission", "must be a verified admission")
    current = _validation_time(now, "teacher lineage admission publication time")
    if current < verified.not_before_utc or current >= verified.expires_at_utc:
        _fail(
            "teacher lineage admission payload validity", "expired before publication"
        )


def _write_no_clobber(
    path: Path,
    raw: bytes,
    *,
    prepublish_validator: Callable[[Path], _Validated],
    field: str = "teacher lineage admission output",
) -> _Validated:
    destination = _reject_reparse_components(path, field, allow_missing_suffix=True)
    parent = _reject_reparse_components(destination.parent, f"{field} parent")
    if not parent.is_dir():
        _fail(f"{field} parent", "must be an existing directory")
    if os.path.lexists(destination):
        _fail(field, f"already exists: {destination}")
    staged: Path | None = None
    published = False
    installed = False
    installed_identity: tuple[int, int] | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        prepublish_validator(staged)
        staged_stat = staged.lstat()
        installed_identity = (staged_stat.st_dev, staged_stat.st_ino)
        try:
            os.link(staged, destination)
        except FileExistsError as error:
            raise ValidationError(f"{field}: already exists: {destination}") from error
        except OSError as error:
            raise ValidationError(
                f"{field}: atomic no-clobber install failed: {error}"
            ) from error
        installed = True
        try:
            staged.unlink()
        except OSError as error:
            residual = staged
            staged = None
            owned_destination_remains = False
            try:
                destination_stat = destination.lstat()
                if (
                    destination_stat.st_dev,
                    destination_stat.st_ino,
                ) == installed_identity:
                    try:
                        destination.unlink()
                    except OSError:
                        owned_destination_remains = True
            except FileNotFoundError:
                owned_destination_remains = False
            except OSError:
                owned_destination_remains = True
            residual_locations = str(residual)
            if owned_destination_remains:
                residual_locations += f"; {destination}"
            raise ValidationError(
                f"{field}: atomic publication aborted because staging cleanup "
                "failed; residual material requires removal: "
                f"{residual_locations}"
            ) from error
        staged = None
        verified = prepublish_validator(destination)
        destination_stat = destination.lstat()
        if (destination_stat.st_dev, destination_stat.st_ino) != installed_identity:
            _fail(field, "path ownership changed after atomic publication")
        published = True
        return verified
    except BaseException:
        if installed and installed_identity is not None:
            try:
                destination_stat = destination.lstat()
                if (
                    destination_stat.st_dev,
                    destination_stat.st_ino,
                ) == installed_identity:
                    try:
                        destination.unlink()
                    except OSError as cleanup_error:
                        raise ValidationError(
                            f"{field}: validation failed and owned destination "
                            "cleanup failed; residual material requires removal: "
                            f"{destination}"
                        ) from cleanup_error
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                raise ValidationError(
                    f"{field}: validation failed and destination ownership could "
                    "not be verified; residual material requires inspection: "
                    f"{destination}"
                ) from cleanup_error
        raise
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                if not published:
                    raise ValidationError(
                        f"{field}: publication failed and staging cleanup failed; "
                        "residual material requires removal: "
                        f"{staged}"
                    ) from error


def _validate_output_location(
    output_path: str | os.PathLike[str],
    *,
    materialization_path: Path,
    input_paths: Iterable[Path],
    field: str,
) -> Path:
    output_absolute = _reject_reparse_components(
        Path(output_path), field, allow_missing_suffix=True
    )
    package_absolute = _reject_reparse_components(
        materialization_path, "teacher materialization package"
    )
    try:
        output_absolute.relative_to(package_absolute)
    except ValueError:
        pass
    else:
        _fail(field, "must not be created inside the immutable materialization package")
    normalized_inputs = {
        os.path.normcase(os.path.abspath(os.fspath(path))) for path in input_paths
    }
    if os.path.normcase(os.fspath(output_absolute)) in normalized_inputs:
        _fail(field, "must differ from every input file")
    return output_absolute


def prepare_teacher_materialization_lineage_admission_signing_bundle(
    *,
    output_path: str | os.PathLike[str],
    materialization_path: str | os.PathLike[str],
    runtime_binding_path: str | os.PathLike[str],
    reviewed_dataset_path: str | os.PathLike[str],
    reviewer_evidence_path: str | os.PathLike[str],
    trust: TeacherMaterializationLineageAdmissionTrust,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    now: datetime | None = None,
) -> VerifiedTeacherMaterializationLineageAdmissionSigningBundle:
    current = _fresh_validation_time(
        now, "teacher lineage admission signing-bundle creation time"
    )
    materialization = Path(materialization_path)
    runtime_binding = Path(runtime_binding_path)
    reviewed_dataset = Path(reviewed_dataset_path)
    reviewer_evidence = Path(reviewer_evidence_path)
    output_absolute = _validate_output_location(
        output_path,
        materialization_path=materialization,
        input_paths=(runtime_binding, reviewed_dataset, reviewer_evidence),
        field="teacher lineage admission signing-bundle output",
    )
    derived = _derive_teacher_lineage(
        materialization_path=materialization,
        runtime_binding_path=runtime_binding,
        reviewed_dataset_path=reviewed_dataset,
        reviewer_evidence_path=reviewer_evidence,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
    )
    payload = _build_teacher_lineage_payload(
        derived,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    _ensure_payload_active(
        payload, current, "teacher lineage admission signing bundle payload"
    )
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    bundle = _build_signing_bundle_document(
        payload,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    _validate_signing_bundle_document(
        bundle,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        materialization_path=materialization,
        runtime_binding_path=runtime_binding,
        reviewed_dataset_path=reviewed_dataset,
        reviewer_evidence_path=reviewer_evidence,
        now=current,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_BYTES:
        _fail("teacher lineage admission signing bundle", "exceeds its byte limit")
    bundle_sha256 = hashlib.sha256(serialized).hexdigest()

    def validate_published(
        path: Path,
    ) -> VerifiedTeacherMaterializationLineageAdmissionSigningBundle:
        publication_time = _fresh_validation_time(
            now, "teacher lineage admission signing-bundle publication time"
        )
        resolved, raw, document = _read_canonical_handoff_document(
            path,
            "teacher lineage admission signing bundle",
            MAX_TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_BYTES,
        )
        if hashlib.sha256(raw).hexdigest() != bundle_sha256:
            _fail(
                "teacher lineage admission signing bundle",
                "changed during publication",
            )
        (
            _,
            publication_spki,
            publication_audience,
            publication_key_id,
            publication_role,
        ) = _validate_trust(trust)
        validated = _validate_signing_bundle_document(
            document,
            public_key_spki_sha256=publication_spki,
            audience=publication_audience,
            key_id=publication_key_id,
            signer_role=publication_role,
            materialization_path=materialization,
            runtime_binding_path=runtime_binding,
            reviewed_dataset_path=reviewed_dataset,
            reviewer_evidence_path=reviewer_evidence,
            now=publication_time,
        )
        payload_bytes = _base64url_decode(
            validated["request"]["payload"],
            "teacher lineage admission signing bundle.request.payload",
            MAX_TEACHER_LINEAGE_ADMISSION_PAYLOAD_BYTES,
        )
        payload = _load_json_object_bytes(
            payload_bytes, "teacher lineage admission signing bundle payload"
        )
        _ensure_payload_active(
            payload,
            _fresh_validation_time(
                now,
                "teacher lineage admission signing-bundle post-validation time",
            ),
            "teacher lineage admission signing bundle payload",
        )
        return VerifiedTeacherMaterializationLineageAdmissionSigningBundle(
            path=resolved,
            bundle=validated,
            bundle_sha256=bundle_sha256,
            bundle_id=validated["bundleId"],
            lineage_admission_id=validated["lineageAdmissionId"],
            payload_sha256=validated["request"]["payloadSha256"],
            public_key_spki_sha256=publication_spki,
        )

    return _write_no_clobber(
        output_absolute,
        serialized,
        prepublish_validator=validate_published,
        field="teacher lineage admission signing-bundle output",
    )


def finalize_teacher_materialization_lineage_admission(
    *,
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    materialization_path: str | os.PathLike[str],
    runtime_binding_path: str | os.PathLike[str],
    reviewed_dataset_path: str | os.PathLike[str],
    reviewer_evidence_path: str | os.PathLike[str],
    trust: TeacherMaterializationLineageAdmissionTrust,
    now: datetime | None = None,
) -> VerifiedTeacherMaterializationLineageAdmission:
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    current = _fresh_validation_time(now, "teacher lineage admission finalization time")
    materialization = Path(materialization_path)
    runtime_binding = Path(runtime_binding_path)
    reviewed_dataset = Path(reviewed_dataset_path)
    reviewer_evidence = Path(reviewer_evidence_path)
    output_absolute = _validate_output_location(
        output_path,
        materialization_path=materialization,
        input_paths=(
            Path(signing_bundle_path),
            Path(signature_path),
            runtime_binding,
            reviewed_dataset,
            reviewer_evidence,
        ),
        field="teacher lineage admission output",
    )
    _, bundle_bytes, bundle_document = _read_canonical_handoff_document(
        signing_bundle_path,
        "teacher lineage admission signing bundle",
        MAX_TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_BYTES,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "teacher lineage admission external signature",
        MAX_TEACHER_LINEAGE_ADMISSION_SIGNATURE_BYTES,
    )
    bundle = _validate_signing_bundle_document(
        bundle_document,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        materialization_path=materialization,
        runtime_binding_path=runtime_binding,
        reviewed_dataset_path=reviewed_dataset,
        reviewer_evidence_path=reviewer_evidence,
        now=current,
    )
    signature = _validate_external_signature_document(
        signature_document,
        bundle=bundle,
        bundle_bytes=bundle_bytes,
        public_key=public_key,
    )
    payload_bytes = _base64url_decode(
        bundle["request"]["payload"],
        "teacher lineage admission signing bundle.request.payload",
        MAX_TEACHER_LINEAGE_ADMISSION_PAYLOAD_BYTES,
    )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    envelope["signature"] = _base64url_encode(signature)
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_TEACHER_LINEAGE_ADMISSION_BYTES:
        _fail("teacher lineage admission envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    _validate_envelope(
        envelope,
        path=output_absolute,
        trust=trust,
        materialization_path=materialization,
        runtime_binding_path=runtime_binding,
        reviewed_dataset_path=reviewed_dataset,
        reviewer_evidence_path=reviewer_evidence,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )

    def validate_published(
        path: Path,
    ) -> VerifiedTeacherMaterializationLineageAdmission:
        verified = verify_teacher_materialization_lineage_admission(
            path,
            materialization_path=materialization,
            runtime_binding_path=runtime_binding,
            reviewed_dataset_path=reviewed_dataset,
            reviewer_evidence_path=reviewer_evidence,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            now=_fresh_validation_time(
                now, "teacher lineage admission final validation time"
            ),
        )
        ensure_teacher_materialization_lineage_admission_active(
            verified,
            _fresh_validation_time(now, "teacher lineage admission publication time"),
        )
        return verified

    return _write_no_clobber(
        output_absolute,
        envelope_bytes + b"\n",
        prepublish_validator=validate_published,
    )


def create_teacher_materialization_lineage_admission(
    *,
    output_path: str | os.PathLike[str],
    materialization_path: str | os.PathLike[str],
    runtime_binding_path: str | os.PathLike[str],
    reviewed_dataset_path: str | os.PathLike[str],
    reviewer_evidence_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    private_key_password: bytes | None,
    trust: TeacherMaterializationLineageAdmissionTrust,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    now: datetime | None = None,
) -> VerifiedTeacherMaterializationLineageAdmission:
    current = _fresh_validation_time(now, "teacher lineage admission creation time")
    materialization = Path(materialization_path)
    runtime_binding = Path(runtime_binding_path)
    reviewed_dataset = Path(reviewed_dataset_path)
    reviewer_evidence = Path(reviewer_evidence_path)
    output_absolute = _validate_output_location(
        output_path,
        materialization_path=materialization,
        input_paths=(runtime_binding, reviewed_dataset, reviewer_evidence),
        field="teacher lineage admission output",
    )

    derived = _derive_teacher_lineage(
        materialization_path=materialization,
        runtime_binding_path=runtime_binding,
        reviewed_dataset_path=reviewed_dataset,
        reviewer_evidence_path=reviewer_evidence,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
    )
    payload = _build_teacher_lineage_payload(
        derived,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    _ensure_payload_active(payload, current, "teacher lineage admission payload")

    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    del public_key
    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    if private_spki != spki:
        _fail(
            "teacher lineage admission key pair",
            "private and externally pinned public keys differ",
        )
    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_TEACHER_LINEAGE_ADMISSION_PAYLOAD_BYTES:
        _fail("teacher lineage admission payload", "exceeds its byte limit")
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
    if len(envelope_bytes) > MAX_TEACHER_LINEAGE_ADMISSION_BYTES:
        _fail("teacher lineage admission envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()

    _validate_envelope(
        envelope,
        path=output_absolute,
        trust=trust,
        materialization_path=materialization,
        runtime_binding_path=runtime_binding,
        reviewed_dataset_path=reviewed_dataset,
        reviewer_evidence_path=reviewer_evidence,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )

    def validate_published(
        path: Path,
    ) -> VerifiedTeacherMaterializationLineageAdmission:
        verified = verify_teacher_materialization_lineage_admission(
            path,
            materialization_path=materialization,
            runtime_binding_path=runtime_binding,
            reviewed_dataset_path=reviewed_dataset,
            reviewer_evidence_path=reviewer_evidence,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            now=_fresh_validation_time(
                now, "teacher lineage admission final validation time"
            ),
        )
        ensure_teacher_materialization_lineage_admission_active(
            verified,
            _fresh_validation_time(now, "teacher lineage admission publication time"),
        )
        return verified

    return _write_no_clobber(
        output_absolute,
        envelope_bytes + b"\n",
        prepublish_validator=validate_published,
    )


__all__ = [
    "TEACHER_LINEAGE_ADMISSION_ALGORITHM",
    "TEACHER_LINEAGE_ADMISSION_ENVELOPE_SCHEMA_VERSION",
    "TEACHER_LINEAGE_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT",
    "TEACHER_LINEAGE_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT",
    "TEACHER_LINEAGE_ADMISSION_SCHEMA_VERSION",
    "TEACHER_LINEAGE_ADMISSION_SIGNATURE_SCHEMA_VERSION",
    "TEACHER_LINEAGE_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION",
    "TEACHER_LINEAGE_ADMISSION_SCOPE",
    "TEACHER_LINEAGE_SUBJECT_HASH_DOMAIN",
    "TeacherMaterializationLineageAdmissionTrust",
    "VerifiedTeacherMaterializationLineageAdmission",
    "VerifiedTeacherMaterializationLineageAdmissionSigningBundle",
    "create_teacher_materialization_lineage_admission",
    "ensure_teacher_materialization_lineage_admission_active",
    "finalize_teacher_materialization_lineage_admission",
    "prepare_teacher_materialization_lineage_admission_signing_bundle",
    "teacher_lineage_subject_fields",
    "teacher_lineage_subject_sha256",
    "teacher_lineage_subjects_from_corpus",
    "teacher_materialization_lineage_admission_id",
    "teacher_materialization_lineage_admission_signature_id",
    "teacher_materialization_lineage_admission_signing_bundle_id",
    "verify_teacher_materialization_lineage_admission",
    "verify_teacher_materialization_lineage_admission_for_reviewed_corpus",
]
