from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping

if TYPE_CHECKING:
    from .base_selection import BaseModelSelectionTrust
    from .corpus_quality import TrainingCorpusAdmissionTrust
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust
    from .review_receipts import ExpertModelReviewReceiptTrust


CATALOG_SCHEMA_VERSION = "daxalgo.hyperion.candidate-catalog/v1"
MANIFEST_SCHEMA_VERSION = "daxalgo.hyperion.training-run/v1"
MANIFEST_V2_SCHEMA_VERSION = "daxalgo.hyperion.training-run/v2"
MANIFEST_V3_SCHEMA_VERSION = "daxalgo.hyperion.training-run/v3"
BUNDLE_SCHEMA_VERSION = "daxalgo.hyperion.run-bundle/v1"
BUNDLE_V2_SCHEMA_VERSION = "daxalgo.hyperion.run-bundle/v2"
SFT_COVERAGE_SCHEMA_VERSION = "daxalgo.hyperion.sft-coverage/v1"
SOURCE_SCHEMA_VERSION = "expert-model-dataset/v1"
LEGACY_SFT_METADATA_SCHEMA_VERSION = "daxalgo.expert-model-sft-metadata/v1"
SFT_METADATA_SCHEMA_VERSION = "daxalgo.expert-model-sft-metadata/v2"
CATALOG_BUNDLE_PATH = "inputs/candidate-catalog.json"
DATASET_BUNDLE_PATH = "inputs/dataset.sft.jsonl"
MANIFEST_BUNDLE_PATH = "training-run-manifest.json"
OUTPUT_BUNDLE_PATH = "outputs/adapter"
BASE_SELECTION_BUNDLE_PATH = "inputs/base-model-selection-envelope.json"
BASE_EVALUATION_PROFILE_BUNDLE_PATH = "inputs/base-evaluation-profile.json"
BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH = "inputs/base-model-snapshot.json"
BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH = "inputs/base-model-source-lock.json"
TRAINING_CORPUS_ADMISSION_BUNDLE_PATH = "inputs/training-corpus-admission-envelope.json"

DOMAINS = (
    "CSharp",
    "DaxAlgoArchitecture",
    "QuantitativeMath",
    "ProbabilityStatistics",
    "RiskManagement",
    "PortfolioManagement",
    "FinanceMarkets",
    "WpfUiDesign",
)

TASK_KINDS = frozenset(
    {
        "GeneralQuestionAnswering",
        "CodeGeneration",
        "CodeRepair",
        "CodeReview",
        "ArchitectureDesign",
        "QuantitativeReasoning",
        "StatisticalReasoning",
        "RiskAnalysis",
        "PortfolioAnalysis",
        "MarketAnalysis",
        "WpfUiDesign",
    }
)
ORIGINS = frozenset(
    {"HumanAuthored", "OpenWeightTeacher", "HostedTeacher", "DerivedRepair"}
)
SPLITS = frozenset({"development", "calibration", "sealed"})

MAX_JSON_BYTES = 4_000_000
MAX_SFT_BYTES = 100_000_000
MAX_SFT_RECORDS = 100_000
MAX_SFT_LINE_BYTES = 8_000_000
MAX_MESSAGE_COUNT = 64
MAX_MESSAGE_CHARACTERS = 500_000
MAX_AGGREGATE_MESSAGE_CHARACTERS = 2_000_000
MAX_CHAT_TEMPLATE_BYTES = 1_000_000
MIN_CHAT_TEMPLATE_CHARACTERS = 64

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_SAFE_MODULE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_RUN_ID_RE = re.compile(r"^vqrun-[0-9a-f]{20}$")
_RELEASE_ID_RE = re.compile(r"^vqrel-[0-9a-f]{64}$")
_BASE_SELECTION_ID_RE = re.compile(r"^vqbaseselect-[0-9a-f]{64}$")
_CORPUS_ADMISSION_ID_RE = re.compile(r"^vqcorpusadmit-[0-9a-f]{64}$")
_CHAT_TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"(?:REPLACE_WITH|\bTODO\b|\bTBD\b)", re.IGNORECASE
)

_EXPECTED_CANDIDATES = {
    "qwen2.5-coder-7b-instruct": {
        "displayName": "Qwen2.5-Coder 7B Instruct",
        "modelId": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "officialSourceUrl": "https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct",
        "revision": "c03e6d358207e414f1eca0bb1891e29f1db0e242",
        "roles": ["student"],
    },
    "qwen2.5-coder-14b-instruct": {
        "displayName": "Qwen2.5-Coder 14B Instruct",
        "modelId": "Qwen/Qwen2.5-Coder-14B-Instruct",
        "officialSourceUrl": "https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct",
        "revision": "aedcc2d42b622764e023cf882b6652e646b95671",
        "roles": ["student"],
    },
    "gpt-oss-20b": {
        "displayName": "gpt-oss-20b",
        "modelId": "openai/gpt-oss-20b",
        "officialSourceUrl": "https://huggingface.co/openai/gpt-oss-20b",
        "revision": "6cee5e81ee83917806bbde320786a8fb61efebee",
        "roles": ["student"],
    },
    "qwen3-coder-30b-a3b-instruct": {
        "displayName": "Qwen3-Coder 30B-A3B Instruct",
        "modelId": "Qwen/Qwen3-Coder-30B-A3B-Instruct",
        "officialSourceUrl": "https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct",
        "revision": "b2cff646eb4bb1d68355c01b18ae02e7cf42d120",
        "roles": ["teacher", "fallback"],
    },
}


class ValidationError(ValueError):
    """Raised when a catalog, SFT export, manifest, or bundle fails closed."""


@dataclass(frozen=True)
class ValidatedManifestSnapshot:
    path: Path
    raw: bytes
    sha256: str
    document: dict[str, Any]


@dataclass(frozen=True)
class SftSummary:
    path: Path
    sha256: str
    byte_count: int
    record_count: int
    task_counts: Mapping[str, int]
    domain_counts: Mapping[str, int]
    origin_counts: Mapping[str, int]
    split_counts: Mapping[str, int]
    split_domain_counts: Mapping[tuple[str, str], int]
    source_schema_versions: tuple[str, ...]

    @property
    def missing_domains(self) -> tuple[str, ...]:
        return tuple(
            domain for domain in DOMAINS if self.domain_counts.get(domain, 0) == 0
        )

    def as_dict(self) -> dict[str, Any]:
        cells = [
            {"split": split, "domain": domain, "recordCount": count}
            for (split, domain), count in sorted(self.split_domain_counts.items())
        ]
        return {
            "schemaVersion": SFT_COVERAGE_SCHEMA_VERSION,
            "datasetSha256": self.sha256,
            "byteCount": self.byte_count,
            "recordCount": self.record_count,
            "taskCounts": dict(sorted(self.task_counts.items())),
            "domainCounts": dict(sorted(self.domain_counts.items())),
            "originCounts": dict(sorted(self.origin_counts.items())),
            "splitCounts": dict(sorted(self.split_counts.items())),
            "splitDomainCounts": cells,
            "missingDomains": list(self.missing_domains),
            "sourceSchemaVersions": list(self.source_schema_versions),
        }


def _fail(field: str, message: str) -> None:
    raise ValidationError(f"{field}: {message}")


def _exact_keys(value: Any, expected: Iterable[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(field, "must be an object")
    expected_set = set(expected)
    actual_set = set(value)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing keys {missing}")
        if extra:
            details.append(f"unsupported keys {extra}")
        _fail(field, "; ".join(details))
    return value


def _string(value: Any, field: str, *, max_length: int = 2_000) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(field, "must be a non-empty string")
    if len(value) > max_length:
        _fail(field, f"must not exceed {max_length} characters")
    return value


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(field, "must be an integer")
    if not minimum <= value <= maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return value


def _number(
    value: Any,
    field: str,
    minimum: float,
    maximum: float,
    *,
    minimum_open: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(field, "must be a finite number")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        _fail(field, "must be a finite number")
    lower_ok = number > minimum if minimum_open else number >= minimum
    if not lower_ok or number > maximum:
        comparator = "greater than" if minimum_open else "at least"
        _fail(field, f"must be {comparator} {minimum} and no more than {maximum}")
    return number


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        _fail(field, "must be a lowercase 64-character SHA-256 value")
    return value


def _validate_data_release_identity(
    value: Any,
    field: str,
    *,
    allow_none: bool = True,
) -> dict[str, str] | None:
    if value is None:
        if allow_none:
            return None
        _fail(field, "is required")
    identity = _exact_keys(
        value,
        {"releaseId", "releaseSha256", "manifestSha256"},
        field,
    )
    release_id = identity["releaseId"]
    if not isinstance(release_id, str) or not _RELEASE_ID_RE.fullmatch(release_id):
        _fail(field + ".releaseId", "must be a canonical vqrel identifier")
    release_hash = _sha256(identity["releaseSha256"], field + ".releaseSha256")
    _sha256(identity["manifestSha256"], field + ".manifestSha256")
    if release_id != f"vqrel-{release_hash}":
        _fail(field + ".releaseId", "does not match releaseSha256")
    return identity


def _revision(value: Any, field: str) -> str:
    if not isinstance(value, str):
        _fail(field, "must be a 40-character immutable source commit")
    if value.startswith("REPLACE_"):
        _fail(
            field,
            "placeholder must be replaced with the exact 40-character source commit",
        )
    if not _REVISION_RE.fullmatch(value):
        _fail(field, "must be a lowercase 40-character immutable source commit")
    return value


def _pinned_revision_label(value: Any, field: str) -> str:
    revision = _string(value, field, max_length=500)
    if (
        revision.lower() in {"main", "master", "latest", "trunk"}
        or "replace_" in revision.lower()
    ):
        _fail(field, "must not be a mutable or placeholder revision label")
    return revision


def _parse_datetime(
    value: Any,
    field: str,
    *,
    require_utc_z: bool = False,
    allow_future: bool = False,
) -> datetime:
    text = _string(value, field, max_length=64)
    if require_utc_z and not text.endswith("Z"):
        _fail(field, "must be expressed in UTC with a trailing Z")
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
    except ValueError as error:
        raise ValidationError(
            f"{field}: must be an ISO-8601 timestamp with an offset"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(field, "must include a UTC offset")
    if not allow_future and parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
        _fail(field, "must not be in the future")
    return parsed


def _reject_constant(value: str) -> None:
    raise ValidationError(f"JSON contains the non-finite numeric constant {value!r}")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def _is_reparse_or_symlink(file_stat: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return stat.S_ISLNK(file_stat.st_mode) or bool(attributes & reparse_flag)


def _reject_reparse_components(
    path: Path,
    field: str,
    *,
    allow_missing_suffix: bool = False,
) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts:
        _fail(field, "path is empty")
    current = Path(parts[0])
    components = [current]
    for part in parts[1:]:
        current /= part
        components.append(current)
    for component in components:
        try:
            component_stat = os.lstat(component)
        except FileNotFoundError:
            if allow_missing_suffix:
                return absolute
            _fail(field, f"path component does not exist: {component}")
        if _is_reparse_or_symlink(component_stat):
            _fail(
                field,
                f"symbolic-link or reparse-point component is not accepted: {component}",
            )
    return absolute


def _regular_file(path: Path, field: str) -> Path:
    absolute = _reject_reparse_components(path, field)
    file_stat = os.lstat(absolute)
    if not stat.S_ISREG(file_stat.st_mode):
        _fail(field, f"regular file does not exist: {absolute}")
    return absolute


def _read_file_bounded(path: Path, field: str, max_bytes: int) -> bytes:
    resolved = _regular_file(path, field)
    if resolved.stat().st_size > max_bytes:
        _fail(field, f"exceeds the {max_bytes}-byte limit")
    raw = bytearray()
    with resolved.open("rb") as stream:
        while len(raw) <= max_bytes:
            block = stream.read(min(1024 * 1024, max_bytes + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
    if len(raw) > max_bytes:
        _fail(field, f"exceeds the {max_bytes}-byte limit")
    return bytes(raw)


def _existing_directory(path: Path, field: str) -> Path:
    absolute = _reject_reparse_components(path, field)
    directory_stat = os.lstat(absolute)
    if not stat.S_ISDIR(directory_stat.st_mode):
        _fail(field, f"directory does not exist: {absolute}")
    return absolute


def _ensure_directory_no_reparse(path: Path, field: str) -> Path:
    absolute = _reject_reparse_components(path, field, allow_missing_suffix=True)
    absolute.mkdir(parents=True, exist_ok=True)
    return _existing_directory(absolute, field)


def _copy_file_snapshot(
    source: Path,
    destination: Path,
    field: str,
    *,
    max_bytes: int,
) -> Path:
    source_file = _regular_file(source, field)
    if source_file.stat().st_size > max_bytes:
        _fail(field, f"exceeds the {max_bytes}-byte snapshot limit")
    destination_parent = _ensure_directory_no_reparse(
        destination.parent, f"{field} snapshot directory"
    )
    snapshot = destination_parent / destination.name
    _reject_reparse_components(snapshot, f"{field} snapshot", allow_missing_suffix=True)
    try:
        with (
            source_file.open("rb") as input_stream,
            snapshot.open("xb") as output_stream,
        ):
            copied_bytes = 0
            while block := input_stream.read(1024 * 1024):
                copied_bytes += len(block)
                if copied_bytes > max_bytes:
                    _fail(field, f"exceeds the {max_bytes}-byte snapshot limit")
                output_stream.write(block)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    except FileExistsError as error:
        raise ValidationError(
            f"{field} snapshot: destination already exists"
        ) from error
    return _regular_file(snapshot, f"{field} snapshot")


@contextmanager
def _exclusive_destination_lock(destination: Path, field: str):
    absolute_destination = Path(os.path.abspath(os.fspath(destination)))
    parent = _ensure_directory_no_reparse(
        absolute_destination.parent, f"{field} parent"
    )
    lock_path = parent / f".{absolute_destination.name}.lock"
    _reject_reparse_components(lock_path, f"{field} lock", allow_missing_suffix=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except FileExistsError as error:
        raise ValidationError(
            f"{field}: exclusive lock already exists: {lock_path}"
        ) from error
    lock_stat = os.fstat(descriptor)
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        yield absolute_destination
    finally:
        os.close(descriptor)
        try:
            current_stat = os.lstat(lock_path)
        except FileNotFoundError:
            pass
        else:
            if (current_stat.st_dev, current_stat.st_ino) == (
                lock_stat.st_dev,
                lock_stat.st_ino,
            ):
                os.unlink(lock_path)


def _install_directory_no_clobber(source: Path, destination: Path, field: str) -> None:
    if os.path.lexists(destination):
        _fail(field, "already exists; immutable outputs are never overwritten")
    try:
        os.rename(source, destination)
    except OSError as error:
        if os.path.lexists(destination):
            raise ValidationError(
                f"{field}: appeared during installation; immutable outputs are never overwritten"
            ) from error
        raise


def _load_json_object_bytes(raw: bytes, field: str) -> dict[str, Any]:
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
    except json.JSONDecodeError as error:
        raise ValidationError(
            f"{field}: invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    if not isinstance(value, dict):
        _fail(field, "root must be an object")
    return value


def load_json_document(
    path: str | os.PathLike[str], *, max_bytes: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    resolved = _regular_file(Path(path), "JSON file")
    raw = _read_file_bounded(resolved, "JSON file", max_bytes)
    return _load_json_object_bytes(raw, "JSON file")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValidationError(
            f"value cannot be encoded as canonical JSON: {error}"
        ) from error


def sha256_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int | None = None,
) -> str:
    resolved = _regular_file(Path(path), "hash input")
    if max_bytes is not None and resolved.stat().st_size > max_bytes:
        _fail("hash input", f"exceeds the {max_bytes}-byte limit")
    digest = hashlib.sha256()
    total_bytes = 0
    with resolved.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total_bytes += len(block)
            if max_bytes is not None and total_bytes > max_bytes:
                _fail("hash input", f"exceeds the {max_bytes}-byte limit")
            digest.update(block)
    return digest.hexdigest()


def _length_prefixed_sha256(domain: str, groups: list[list[str]]) -> str:
    payload = bytearray()

    def append_integer(value: int) -> None:
        payload.extend(value.to_bytes(4, byteorder="big", signed=True))

    def append_text(value: str) -> None:
        encoded = value.encode("utf-8", errors="strict")
        append_integer(len(encoded))
        payload.extend(encoded)

    append_text(domain)
    append_integer(len(groups))
    for group in groups:
        append_integer(len(group))
        for value in group:
            append_text(value)
    return hashlib.sha256(payload).hexdigest()


def expert_conversation_sha256(messages: list[dict[str, str]]) -> str:
    return _length_prefixed_sha256(
        "daxalgo-expert-conversation/v1",
        [[message["role"], message["content"]] for message in messages],
    )


def _validate_messages(value: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    if not 2 <= len(value) <= MAX_MESSAGE_COUNT:
        _fail(field, f"must contain 2 to {MAX_MESSAGE_COUNT} messages")
    messages: list[dict[str, str]] = []
    aggregate = 0
    for index, raw_message in enumerate(value):
        message_field = f"{field}[{index}]"
        message = _exact_keys(raw_message, {"role", "content"}, message_field)
        role = message["role"]
        if role not in {"system", "user", "assistant"}:
            _fail(f"{message_field}.role", "must be system, user, or assistant")
        content = _string(
            message["content"],
            f"{message_field}.content",
            max_length=MAX_MESSAGE_CHARACTERS,
        )
        aggregate += len(content)
        messages.append({"role": role, "content": content})
    if aggregate > MAX_AGGREGATE_MESSAGE_CHARACTERS:
        _fail(
            field,
            f"content exceeds {MAX_AGGREGATE_MESSAGE_CHARACTERS} aggregate characters",
        )
    conversation_start = 1 if messages[0]["role"] == "system" else 0
    if len(messages) - conversation_start < 2:
        _fail(field, "must contain a user prompt followed by an assistant answer")
    expected = "user"
    for index in range(conversation_start, len(messages)):
        if messages[index]["role"] != expected:
            _fail(
                f"{field}[{index}].role",
                f"must be {expected!r} to preserve chat ordering",
            )
        expected = "assistant" if expected == "user" else "user"
    if messages[-1]["role"] != "assistant":
        _fail(field, "final message must have role 'assistant'")
    return messages


def _validate_sft_row(value: Any, line_number: int) -> tuple[dict[str, Any], str]:
    field = f"SFT line {line_number}"
    row = _exact_keys(value, {"messages", "metadata"}, field)
    messages = _validate_messages(row["messages"], f"{field}.messages")
    legacy_metadata_keys = {
        "id",
        "taskKind",
        "domains",
        "conversationSha256",
        "origin",
        "producer",
        "modelId",
        "modelRevision",
        "promptSha256",
        "profileVersion",
        "split",
        "contaminationGroup",
        "cutoffUtc",
        "sourceSchema",
    }
    raw_metadata = row["metadata"]
    if isinstance(raw_metadata, Mapping) and "schemaVersion" in raw_metadata:
        if raw_metadata.get("schemaVersion") != SFT_METADATA_SCHEMA_VERSION:
            _fail(
                f"{field}.metadata.schemaVersion",
                f"must be {SFT_METADATA_SCHEMA_VERSION!r}",
            )
        metadata_keys = legacy_metadata_keys | {
            "schemaVersion",
            "sourceCorpusSha256",
            "verificationEvidenceSha256",
        }
        metadata_schema_version = SFT_METADATA_SCHEMA_VERSION
    else:
        metadata_keys = legacy_metadata_keys
        metadata_schema_version = LEGACY_SFT_METADATA_SCHEMA_VERSION
    metadata = _exact_keys(
        raw_metadata,
        metadata_keys,
        f"{field}.metadata",
    )
    if metadata_schema_version == SFT_METADATA_SCHEMA_VERSION:
        _sha256(
            metadata["sourceCorpusSha256"],
            f"{field}.metadata.sourceCorpusSha256",
        )
        _sha256(
            metadata["verificationEvidenceSha256"],
            f"{field}.metadata.verificationEvidenceSha256",
        )
    example_id = _string(metadata["id"], f"{field}.metadata.id", max_length=200)
    if not _SAFE_ID_RE.fullmatch(example_id):
        _fail(f"{field}.metadata.id", "contains unsupported characters")
    task_kind = metadata["taskKind"]
    if task_kind not in TASK_KINDS:
        _fail(f"{field}.metadata.taskKind", "is not a supported ExpertTaskKind")
    domains = metadata["domains"]
    if not isinstance(domains, list) or not domains:
        _fail(f"{field}.metadata.domains", "must be a non-empty array")
    if len(domains) != len(set(domains)):
        _fail(f"{field}.metadata.domains", "must not contain duplicates")
    unsupported_domains = (
        sorted(set(domains) - set(DOMAINS))
        if all(isinstance(x, str) for x in domains)
        else []
    )
    if not all(isinstance(item, str) for item in domains) or unsupported_domains:
        _fail(
            f"{field}.metadata.domains",
            f"contains unsupported labels {unsupported_domains}",
        )
    conversation_hash = _sha256(
        metadata["conversationSha256"], f"{field}.metadata.conversationSha256"
    )
    actual_conversation_hash = expert_conversation_sha256(messages)
    if conversation_hash != actual_conversation_hash:
        _fail(
            f"{field}.metadata.conversationSha256",
            "does not match canonical message content",
        )
    origin = metadata["origin"]
    if origin not in ORIGINS:
        _fail(f"{field}.metadata.origin", "is not a supported ExpertDatasetOrigin")
    _string(metadata["producer"], f"{field}.metadata.producer", max_length=500)
    lineage_fields = ("modelId", "modelRevision", "promptSha256", "profileVersion")
    if origin == "HumanAuthored":
        if any(metadata[name] is not None for name in lineage_fields):
            _fail(
                f"{field}.metadata",
                "human-authored lineage must have null model fields",
            )
    else:
        _string(metadata["modelId"], f"{field}.metadata.modelId", max_length=500)
        if origin == "OpenWeightTeacher":
            _revision(metadata["modelRevision"], f"{field}.metadata.modelRevision")
        else:
            _pinned_revision_label(
                metadata["modelRevision"], f"{field}.metadata.modelRevision"
            )
        _sha256(metadata["promptSha256"], f"{field}.metadata.promptSha256")
        _string(
            metadata["profileVersion"],
            f"{field}.metadata.profileVersion",
            max_length=500,
        )
    split = metadata["split"]
    if split not in SPLITS:
        _fail(f"{field}.metadata.split", "must be development, calibration, or sealed")
    contamination_group = _string(
        metadata["contaminationGroup"],
        f"{field}.metadata.contaminationGroup",
        max_length=200,
    )
    if not _SAFE_ID_RE.fullmatch(contamination_group):
        _fail(f"{field}.metadata.contaminationGroup", "contains unsupported characters")
    _parse_datetime(metadata["cutoffUtc"], f"{field}.metadata.cutoffUtc")
    if metadata["sourceSchema"] != SOURCE_SCHEMA_VERSION:
        _fail(f"{field}.metadata.sourceSchema", f"must be {SOURCE_SCHEMA_VERSION!r}")
    return {"messages": messages, "metadata": metadata}, metadata_schema_version


def parse_sft_bytes(
    raw: bytes,
    *,
    source_path: Path,
    content_sha256: str | None = None,
) -> tuple[SftSummary, list[dict[str, Any]]]:
    byte_count = len(raw)
    if byte_count == 0:
        _fail("SFT file", "must not be empty")
    if byte_count > MAX_SFT_BYTES:
        _fail("SFT file", f"exceeds the {MAX_SFT_BYTES}-byte limit")
    digest = content_sha256 or hashlib.sha256(raw).hexdigest()
    _sha256(digest, "SFT file SHA-256")

    task_counts: Counter[str] = Counter()
    domain_counts: Counter[str] = Counter()
    origin_counts: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    split_domain_counts: Counter[tuple[str, str]] = Counter()
    ids: set[str] = set()
    content_hashes: set[str] = set()
    contamination_splits: dict[str, str] = {}
    source_schemas: set[str] = set()
    metadata_schema_versions: set[str] = set()
    record_count = 0
    records: list[dict[str, Any]] = []

    with io.BytesIO(raw) as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if line_number == 1 and raw_line.startswith(b"\xef\xbb\xbf"):
                _fail("SFT file", "UTF-8 byte-order marks are not accepted")
            if len(raw_line) > MAX_SFT_LINE_BYTES:
                _fail(
                    f"SFT line {line_number}",
                    f"exceeds the {MAX_SFT_LINE_BYTES}-byte limit",
                )
            try:
                text = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ValidationError(
                    f"SFT line {line_number}: invalid UTF-8 at byte {error.start}"
                ) from error
            if not text.strip():
                _fail(f"SFT line {line_number}", "blank lines are not accepted")
            try:
                value = json.loads(
                    text,
                    object_pairs_hook=_unique_pairs,
                    parse_constant=_reject_constant,
                )
            except json.JSONDecodeError as error:
                raise ValidationError(
                    f"SFT line {line_number}: invalid JSON at column {error.colno}: {error.msg}"
                ) from error
            row, metadata_schema_version = _validate_sft_row(value, line_number)
            metadata_schema_versions.add(metadata_schema_version)
            if len(metadata_schema_versions) != 1:
                _fail(
                    "SFT file",
                    "must use one homogeneous metadata schema version",
                )
            metadata = row["metadata"]
            example_id = metadata["id"]
            if example_id in ids:
                _fail(
                    f"SFT line {line_number}.metadata.id",
                    "duplicates an earlier example ID",
                )
            ids.add(example_id)
            content_hash = metadata["conversationSha256"]
            if content_hash in content_hashes:
                _fail(
                    f"SFT line {line_number}.metadata.conversationSha256",
                    "duplicates exact message content from an earlier example",
                )
            content_hashes.add(content_hash)
            group = metadata["contaminationGroup"]
            split = metadata["split"]
            prior_split = contamination_splits.get(group)
            if prior_split is not None and prior_split != split:
                _fail(
                    f"SFT line {line_number}.metadata.contaminationGroup",
                    f"crosses split boundary from {prior_split!r} to {split!r}",
                )
            contamination_splits[group] = split
            task_counts[metadata["taskKind"]] += 1
            origin_counts[metadata["origin"]] += 1
            split_counts[split] += 1
            for domain in metadata["domains"]:
                domain_counts[domain] += 1
                split_domain_counts[(split, domain)] += 1
            source_schemas.add(metadata["sourceSchema"])
            record_count += 1
            if record_count > MAX_SFT_RECORDS:
                _fail("SFT file", f"exceeds the {MAX_SFT_RECORDS}-record limit")
            records.append(row)

    summary = SftSummary(
        path=source_path,
        sha256=digest,
        byte_count=byte_count,
        record_count=record_count,
        task_counts=dict(task_counts),
        domain_counts=dict(domain_counts),
        origin_counts=dict(origin_counts),
        split_counts=dict(split_counts),
        split_domain_counts=dict(split_domain_counts),
        source_schema_versions=tuple(sorted(source_schemas)),
    )
    return summary, records


def validate_sft(path: str | os.PathLike[str]) -> SftSummary:
    """Validate SFT structure and byte identity, not authorization to consume it.

    Training and release boundaries separately require an active detached review
    receipt set anchored by externally supplied trust.
    """

    resolved = _regular_file(Path(path), "SFT file")
    raw = _read_file_bounded(resolved, "SFT file", MAX_SFT_BYTES)
    summary, _ = parse_sft_bytes(raw, source_path=resolved)
    return summary


def summarize_sft(path: str | os.PathLike[str]) -> dict[str, Any]:
    return validate_sft(path).as_dict()


def _validate_candidate_catalog_document(value: Any) -> dict[str, Any]:
    catalog = _exact_keys(
        value, {"schemaVersion", "catalogVersion", "candidates"}, "catalog"
    )
    if catalog["schemaVersion"] != CATALOG_SCHEMA_VERSION:
        _fail("catalog.schemaVersion", f"must be {CATALOG_SCHEMA_VERSION!r}")
    if catalog["catalogVersion"] != "1.0.0":
        _fail("catalog.catalogVersion", "must be '1.0.0'")
    candidates = catalog["candidates"]
    if not isinstance(candidates, list) or len(candidates) != len(_EXPECTED_CANDIDATES):
        _fail(
            "catalog.candidates",
            "must contain exactly the four approved shortlist entries",
        )
    seen: set[str] = set()
    for index, raw_candidate in enumerate(candidates):
        field = f"catalog.candidates[{index}]"
        candidate = _exact_keys(
            raw_candidate,
            {
                "id",
                "displayName",
                "modelId",
                "revision",
                "license",
                "licenseUrl",
                "officialSourceUrl",
                "roles",
            },
            field,
        )
        candidate_id = _string(candidate["id"], f"{field}.id", max_length=100)
        if candidate_id in seen:
            _fail(f"{field}.id", "duplicates an earlier candidate")
        seen.add(candidate_id)
        expected = _EXPECTED_CANDIDATES.get(candidate_id)
        if expected is None:
            _fail(f"{field}.id", "is not in the approved shortlist")
        for property_name in ("displayName", "modelId", "officialSourceUrl", "roles"):
            if candidate[property_name] != expected[property_name]:
                _fail(
                    f"{field}.{property_name}",
                    "does not match the approved shortlist record",
                )
        revision = _revision(candidate["revision"], f"{field}.revision")
        if revision != expected["revision"]:
            _fail(
                f"{field}.revision",
                "does not match the approved pinned shortlist revision",
            )
        if candidate["license"] != "Apache-2.0":
            _fail(f"{field}.license", "must be 'Apache-2.0'")
        if candidate["licenseUrl"] != "https://www.apache.org/licenses/LICENSE-2.0":
            _fail(
                f"{field}.licenseUrl", "must identify the official Apache-2.0 licence"
            )
    if seen != set(_EXPECTED_CANDIDATES):
        _fail(
            "catalog.candidates",
            "must contain every approved shortlist entry exactly once",
        )
    return catalog


def validate_candidate_catalog(path: str | os.PathLike[str]) -> dict[str, Any]:
    return _validate_candidate_catalog_document(load_json_document(path))


def default_hyperparameters() -> dict[str, Any]:
    return {
        "numTrainEpochs": 3.0,
        "learningRate": 0.0002,
        "perDeviceTrainBatchSize": 1,
        "gradientAccumulationSteps": 16,
        "maxSequenceLength": 4096,
        "warmupRatio": 0.03,
        "weightDecay": 0.0,
        "loraR": 64,
        "loraAlpha": 128,
        "loraDropout": 0.05,
        "loraTargetModules": [
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        "quantizationBits": 4,
        "gradientCheckpointing": True,
        "optimizer": "paged_adamw_8bit",
        "lrScheduler": "cosine",
    }


def _validate_hyperparameters(
    value: Any, field: str = "manifest.hyperparameters"
) -> dict[str, Any]:
    expected_keys = set(default_hyperparameters())
    hyperparameters = _exact_keys(value, expected_keys, field)
    _number(
        hyperparameters["numTrainEpochs"],
        f"{field}.numTrainEpochs",
        0,
        50,
        minimum_open=True,
    )
    _number(
        hyperparameters["learningRate"],
        f"{field}.learningRate",
        0,
        1,
        minimum_open=True,
    )
    _integer(
        hyperparameters["perDeviceTrainBatchSize"],
        f"{field}.perDeviceTrainBatchSize",
        1,
        256,
    )
    _integer(
        hyperparameters["gradientAccumulationSteps"],
        f"{field}.gradientAccumulationSteps",
        1,
        4096,
    )
    _integer(
        hyperparameters["maxSequenceLength"], f"{field}.maxSequenceLength", 128, 262_144
    )
    if _number(hyperparameters["warmupRatio"], f"{field}.warmupRatio", 0, 1) >= 1:
        _fail(f"{field}.warmupRatio", "must be less than 1")
    _number(hyperparameters["weightDecay"], f"{field}.weightDecay", 0, 1)
    _integer(hyperparameters["loraR"], f"{field}.loraR", 1, 1024)
    _integer(hyperparameters["loraAlpha"], f"{field}.loraAlpha", 1, 8192)
    if _number(hyperparameters["loraDropout"], f"{field}.loraDropout", 0, 1) >= 1:
        _fail(f"{field}.loraDropout", "must be less than 1")
    modules = hyperparameters["loraTargetModules"]
    if (
        not isinstance(modules, list)
        or not modules
        or len(modules) != len(set(modules))
    ):
        _fail(
            f"{field}.loraTargetModules",
            "must be a non-empty array of unique module names",
        )
    if not all(
        isinstance(module, str) and _SAFE_MODULE_RE.fullmatch(module)
        for module in modules
    ):
        _fail(f"{field}.loraTargetModules", "contains an invalid module name")
    if hyperparameters["quantizationBits"] != 4:
        _fail(f"{field}.quantizationBits", "must be 4 for QLoRA-SFT")
    if not isinstance(hyperparameters["gradientCheckpointing"], bool):
        _fail(f"{field}.gradientCheckpointing", "must be a boolean")
    if hyperparameters["optimizer"] != "paged_adamw_8bit":
        _fail(f"{field}.optimizer", "must be 'paged_adamw_8bit'")
    if hyperparameters["lrScheduler"] != "cosine":
        _fail(f"{field}.lrScheduler", "must be 'cosine'")
    return hyperparameters


def _relative_path(value: Any, field: str) -> PurePosixPath:
    text = _string(value, field, max_length=500)
    if "\\" in text:
        _fail(field, "must use forward slashes")
    pure = PurePosixPath(text)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        _fail(field, "must be a contained relative path without traversal")
    return pure


def resolve_bound_path(
    base_directory: Path,
    value: Any,
    field: str,
    *,
    allow_missing_suffix: bool = False,
) -> Path:
    pure = _relative_path(value, field)
    root = _existing_directory(base_directory, f"{field} bundle root")
    resolved = Path(os.path.abspath(os.fspath(root.joinpath(*pure.parts))))
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValidationError(f"{field}: resolves outside the bundle") from error
    return _reject_reparse_components(
        resolved,
        field,
        allow_missing_suffix=allow_missing_suffix,
    )


def validate_chat_template(value: Any, field: str = "chat template") -> str:
    template = _string(value, field, max_length=MAX_CHAT_TEMPLATE_BYTES)
    if _CHAT_TEMPLATE_PLACEHOLDER_RE.search(template):
        _fail(field, "contains an unresolved REPLACE_WITH, TODO, or TBD placeholder")
    if len(template) < MIN_CHAT_TEMPLATE_CHARACTERS:
        _fail(field, f"must contain at least {MIN_CHAT_TEMPLATE_CHARACTERS} characters")
    if not all(marker in template for marker in ("{%", "%}", "{{", "}}")):
        _fail(field, "must contain Jinja statement and expression markers")
    missing_references = [
        name for name in ("messages", "role", "content") if name not in template
    ]
    if missing_references:
        _fail(field, f"must reference {', '.join(missing_references)}")
    return template


def _manifest_run_id(manifest: Mapping[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("runId", None)
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return f"vqrun-{digest[:20]}"


def _validate_manifest_base_selection(manifest: Mapping[str, Any]) -> None:
    selection = _exact_keys(
        manifest["baseModelSelection"],
        {
            "path",
            "envelopeSha256",
            "payloadSha256",
            "selectionId",
            "expiresAtUtc",
        },
        "manifest.baseModelSelection",
    )
    if selection["path"] != BASE_SELECTION_BUNDLE_PATH:
        _fail(
            "manifest.baseModelSelection.path",
            f"must be {BASE_SELECTION_BUNDLE_PATH!r}",
        )
    _sha256(
        selection["envelopeSha256"],
        "manifest.baseModelSelection.envelopeSha256",
    )
    _sha256(
        selection["payloadSha256"],
        "manifest.baseModelSelection.payloadSha256",
    )
    if not isinstance(
        selection["selectionId"], str
    ) or not _BASE_SELECTION_ID_RE.fullmatch(selection["selectionId"]):
        _fail("manifest.baseModelSelection.selectionId", "must be canonical")
    expires_text = _string(
        selection["expiresAtUtc"],
        "manifest.baseModelSelection.expiresAtUtc",
        max_length=20,
    )
    try:
        datetime.strptime(expires_text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(
            "manifest.baseModelSelection.expiresAtUtc",
            "must use exact UTC second form YYYY-MM-DDTHH:MM:SSZ",
        )

    snapshot = _exact_keys(
        manifest["baseModelSnapshot"],
        {
            "profile",
            "manifest",
            "sourceLock",
            "snapshotSha256",
            "fileTreeSha256",
            "chatTemplateSha256",
        },
        "manifest.baseModelSnapshot",
    )
    for name, required_path in (
        ("profile", BASE_EVALUATION_PROFILE_BUNDLE_PATH),
        ("manifest", BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH),
        ("sourceLock", BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH),
    ):
        binding = _exact_keys(
            snapshot[name],
            {"path", "sha256"},
            f"manifest.baseModelSnapshot.{name}",
        )
        if binding["path"] != required_path:
            _fail(
                f"manifest.baseModelSnapshot.{name}.path",
                f"must be {required_path!r}",
            )
        _sha256(binding["sha256"], f"manifest.baseModelSnapshot.{name}.sha256")
    for name in ("snapshotSha256", "fileTreeSha256", "chatTemplateSha256"):
        _sha256(snapshot[name], f"manifest.baseModelSnapshot.{name}")
    if snapshot["chatTemplateSha256"] != manifest["chatTemplate"]["sha256"]:
        _fail(
            "manifest.baseModelSnapshot.chatTemplateSha256",
            "must match the training chat template",
        )


def _validate_manifest_corpus_admission(manifest: Mapping[str, Any]) -> None:
    admission = _exact_keys(
        manifest["trainingCorpusAdmission"],
        {
            "path",
            "envelopeSha256",
            "payloadSha256",
            "corpusAdmissionId",
            "publicKeySpkiSha256",
            "qualityPolicySha256",
            "qualityReportSha256",
            "notBeforeUtc",
            "expiresAtUtc",
        },
        "manifest.trainingCorpusAdmission",
    )
    if admission["path"] != TRAINING_CORPUS_ADMISSION_BUNDLE_PATH:
        _fail(
            "manifest.trainingCorpusAdmission.path",
            f"must be {TRAINING_CORPUS_ADMISSION_BUNDLE_PATH!r}",
        )
    for name in (
        "envelopeSha256",
        "payloadSha256",
        "publicKeySpkiSha256",
        "qualityPolicySha256",
        "qualityReportSha256",
    ):
        _sha256(admission[name], f"manifest.trainingCorpusAdmission.{name}")
    if not isinstance(
        admission["corpusAdmissionId"], str
    ) or not _CORPUS_ADMISSION_ID_RE.fullmatch(admission["corpusAdmissionId"]):
        _fail(
            "manifest.trainingCorpusAdmission.corpusAdmissionId",
            "must be canonical",
        )
    not_before = _parse_datetime(
        admission["notBeforeUtc"],
        "manifest.trainingCorpusAdmission.notBeforeUtc",
        require_utc_z=True,
    )
    expires = _parse_datetime(
        admission["expiresAtUtc"],
        "manifest.trainingCorpusAdmission.expiresAtUtc",
        require_utc_z=True,
        allow_future=True,
    )
    if not_before >= expires:
        _fail(
            "manifest.trainingCorpusAdmission validity",
            "must satisfy notBeforeUtc < expiresAtUtc",
        )


def _validate_manifest_document(value: Any) -> dict[str, Any]:
    common_keys = {
        "schemaVersion",
        "runId",
        "createdAtUtc",
        "baseModel",
        "candidateCatalog",
        "dataset",
        "method",
        "seed",
        "chatTemplate",
        "hyperparameters",
        "outputPath",
        "domains",
        "trainingRuntime",
    }
    if not isinstance(value, dict):
        _fail("manifest", "must be an object")
    schema_version = value.get("schemaVersion")
    if schema_version == MANIFEST_SCHEMA_VERSION:
        required_keys = common_keys
        optional_keys = {"dataRelease"}
    elif schema_version == MANIFEST_V2_SCHEMA_VERSION:
        required_keys = common_keys | {
            "dataRelease",
            "baseModelSelection",
            "baseModelSnapshot",
        }
        optional_keys: set[str] = set()
    elif schema_version == MANIFEST_V3_SCHEMA_VERSION:
        required_keys = common_keys | {
            "dataRelease",
            "baseModelSelection",
            "baseModelSnapshot",
            "trainingCorpusAdmission",
        }
        optional_keys = set()
    else:
        _fail(
            "manifest.schemaVersion",
            "must be one of "
            f"{MANIFEST_SCHEMA_VERSION!r}, {MANIFEST_V2_SCHEMA_VERSION!r}, "
            f"or {MANIFEST_V3_SCHEMA_VERSION!r}",
        )
    actual_keys = set(value)
    missing = sorted(required_keys - actual_keys)
    extra = sorted(actual_keys - required_keys - optional_keys)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing keys {missing}")
        if extra:
            details.append(f"unsupported keys {extra}")
        _fail("manifest", "; ".join(details))
    manifest = value
    if not isinstance(manifest["runId"], str) or not _RUN_ID_RE.fullmatch(
        manifest["runId"]
    ):
        _fail(
            "manifest.runId",
            "must have form 'vqrun-' followed by 20 lowercase hex characters",
        )
    _parse_datetime(
        manifest["createdAtUtc"], "manifest.createdAtUtc", require_utc_z=True
    )
    base_model = _exact_keys(
        manifest["baseModel"],
        {"candidateId", "modelId", "revision", "license", "officialSourceUrl"},
        "manifest.baseModel",
    )
    _string(base_model["candidateId"], "manifest.baseModel.candidateId", max_length=100)
    _string(base_model["modelId"], "manifest.baseModel.modelId", max_length=500)
    _revision(base_model["revision"], "manifest.baseModel.revision")
    _string(base_model["license"], "manifest.baseModel.license", max_length=100)
    source_url = _string(
        base_model["officialSourceUrl"],
        "manifest.baseModel.officialSourceUrl",
        max_length=500,
    )
    if not source_url.startswith("https://"):
        _fail("manifest.baseModel.officialSourceUrl", "must use HTTPS")
    catalog_binding = _exact_keys(
        manifest["candidateCatalog"], {"path", "sha256"}, "manifest.candidateCatalog"
    )
    if catalog_binding["path"] != CATALOG_BUNDLE_PATH:
        _fail("manifest.candidateCatalog.path", f"must be {CATALOG_BUNDLE_PATH!r}")
    _sha256(catalog_binding["sha256"], "manifest.candidateCatalog.sha256")
    dataset = _exact_keys(
        manifest["dataset"],
        {"path", "sha256", "format", "recordCount", "sourceSchemaVersions"},
        "manifest.dataset",
    )
    if dataset["path"] != DATASET_BUNDLE_PATH:
        _fail("manifest.dataset.path", f"must be {DATASET_BUNDLE_PATH!r}")
    _sha256(dataset["sha256"], "manifest.dataset.sha256")
    if dataset["format"] != "expert-model-sft-jsonl":
        _fail("manifest.dataset.format", "must be 'expert-model-sft-jsonl'")
    _integer(dataset["recordCount"], "manifest.dataset.recordCount", 1, MAX_SFT_RECORDS)
    if dataset["sourceSchemaVersions"] != [SOURCE_SCHEMA_VERSION]:
        _fail(
            "manifest.dataset.sourceSchemaVersions",
            f"must be [{SOURCE_SCHEMA_VERSION!r}]",
        )
    if manifest["method"] != "QLoRA-SFT":
        _fail("manifest.method", "must be 'QLoRA-SFT'")
    _integer(manifest["seed"], "manifest.seed", 0, 2_147_483_647)
    chat_template = _exact_keys(
        manifest["chatTemplate"],
        {"name", "template", "sha256"},
        "manifest.chatTemplate",
    )
    _string(chat_template["name"], "manifest.chatTemplate.name", max_length=200)
    template = validate_chat_template(
        chat_template["template"], "manifest.chatTemplate.template"
    )
    template_hash = _sha256(chat_template["sha256"], "manifest.chatTemplate.sha256")
    actual_template_hash = hashlib.sha256(template.encode("utf-8")).hexdigest()
    if template_hash != actual_template_hash:
        _fail("manifest.chatTemplate.sha256", "does not match the bound chat template")
    _validate_hyperparameters(manifest["hyperparameters"])
    if manifest["outputPath"] != OUTPUT_BUNDLE_PATH:
        _fail("manifest.outputPath", f"must be {OUTPUT_BUNDLE_PATH!r}")
    if manifest["domains"] != list(DOMAINS):
        _fail(
            "manifest.domains",
            "must list all eight required domains in canonical order",
        )
    from .runtime import (
        TRAINING_PYLOCK_BUNDLE_PATH,
        TRAINING_RUNTIME_PROFILE_BUNDLE_PATH,
    )

    training_runtime = _exact_keys(
        manifest["trainingRuntime"],
        {"profile", "pylock"},
        "manifest.trainingRuntime",
    )
    for name, required_path in (
        ("profile", TRAINING_RUNTIME_PROFILE_BUNDLE_PATH),
        ("pylock", TRAINING_PYLOCK_BUNDLE_PATH),
    ):
        binding = _exact_keys(
            training_runtime[name],
            {"path", "sha256"},
            f"manifest.trainingRuntime.{name}",
        )
        if binding["path"] != required_path:
            _fail(
                f"manifest.trainingRuntime.{name}.path",
                f"must be {required_path!r}",
            )
        _sha256(binding["sha256"], f"manifest.trainingRuntime.{name}.sha256")
    if "dataRelease" in manifest:
        data_release = _validate_data_release_identity(
            manifest["dataRelease"], "manifest.dataRelease"
        )
        if (
            schema_version
            in {
                MANIFEST_V2_SCHEMA_VERSION,
                MANIFEST_V3_SCHEMA_VERSION,
            }
            and data_release is None
        ):
            _fail("manifest.dataRelease", "is required for a selected training run")
    if schema_version in {MANIFEST_V2_SCHEMA_VERSION, MANIFEST_V3_SCHEMA_VERSION}:
        _validate_manifest_base_selection(manifest)
    if schema_version == MANIFEST_V3_SCHEMA_VERSION:
        _validate_manifest_corpus_admission(manifest)
    expected_run_id = _manifest_run_id(manifest)
    if manifest["runId"] != expected_run_id:
        _fail(
            "manifest.runId",
            f"does not match manifest content; expected {expected_run_id!r}",
        )
    return manifest


def _verify_manifest_bindings(
    manifest: dict[str, Any], base_directory: Path
) -> SftSummary:
    catalog_path = resolve_bound_path(
        base_directory,
        manifest["candidateCatalog"]["path"],
        "manifest.candidateCatalog.path",
    )
    dataset_path = resolve_bound_path(
        base_directory, manifest["dataset"]["path"], "manifest.dataset.path"
    )
    from .runtime import MAX_PYLOCK_BYTES, load_and_validate_training_runtime

    runtime_profile_path = resolve_bound_path(
        base_directory,
        manifest["trainingRuntime"]["profile"]["path"],
        "manifest.trainingRuntime.profile.path",
    )
    pylock_path = resolve_bound_path(
        base_directory,
        manifest["trainingRuntime"]["pylock"]["path"],
        "manifest.trainingRuntime.pylock.path",
    )
    for name, bound_path in (
        ("profile", runtime_profile_path),
        ("pylock", pylock_path),
    ):
        expected_hash = manifest["trainingRuntime"][name]["sha256"]
        byte_limit = MAX_PYLOCK_BYTES if name == "pylock" else MAX_JSON_BYTES
        if sha256_file(bound_path, max_bytes=byte_limit) != expected_hash:
            _fail(
                f"manifest.trainingRuntime.{name}.sha256",
                f"does not match the bound {name} bytes",
            )
    load_and_validate_training_runtime(runtime_profile_path, pylock_path)
    if (
        sha256_file(catalog_path, max_bytes=MAX_JSON_BYTES)
        != manifest["candidateCatalog"]["sha256"]
    ):
        _fail("manifest.candidateCatalog.sha256", "does not match the catalog bytes")
    catalog = validate_candidate_catalog(catalog_path)
    candidates = {candidate["id"]: candidate for candidate in catalog["candidates"]}
    selected = candidates.get(manifest["baseModel"]["candidateId"])
    if selected is None:
        _fail("manifest.baseModel.candidateId", "is absent from the bound catalog")
    if "student" not in selected["roles"]:
        _fail(
            "manifest.baseModel.candidateId",
            "must select a catalog candidate with the student role",
        )
    expected_base = {
        "candidateId": selected["id"],
        "modelId": selected["modelId"],
        "revision": selected["revision"],
        "license": selected["license"],
        "officialSourceUrl": selected["officialSourceUrl"],
    }
    if manifest["baseModel"] != expected_base:
        _fail(
            "manifest.baseModel", "does not exactly match the bound catalog candidate"
        )
    if manifest["schemaVersion"] in {
        MANIFEST_V2_SCHEMA_VERSION,
        MANIFEST_V3_SCHEMA_VERSION,
    }:
        selection_path = resolve_bound_path(
            base_directory,
            manifest["baseModelSelection"]["path"],
            "manifest.baseModelSelection.path",
        )
        if (
            sha256_file(selection_path, max_bytes=MAX_JSON_BYTES)
            != manifest["baseModelSelection"]["envelopeSha256"]
        ):
            _fail(
                "manifest.baseModelSelection.envelopeSha256",
                "does not match the bundled selection envelope",
            )
        snapshot_bindings = manifest["baseModelSnapshot"]
        bound_paths: dict[str, Path] = {}
        for name in ("profile", "manifest", "sourceLock"):
            binding = snapshot_bindings[name]
            bound_path = resolve_bound_path(
                base_directory,
                binding["path"],
                f"manifest.baseModelSnapshot.{name}.path",
            )
            if sha256_file(bound_path, max_bytes=MAX_JSON_BYTES) != binding["sha256"]:
                _fail(
                    f"manifest.baseModelSnapshot.{name}.sha256",
                    "does not match the bundled bytes",
                )
            bound_paths[name] = bound_path
        if manifest["schemaVersion"] == MANIFEST_V3_SCHEMA_VERSION:
            admission_path = resolve_bound_path(
                base_directory,
                manifest["trainingCorpusAdmission"]["path"],
                "manifest.trainingCorpusAdmission.path",
            )
            from .corpus_quality import _load_corpus_admission_envelope

            admission_envelope = _load_corpus_admission_envelope(admission_path)
            if (
                hashlib.sha256(canonical_json_bytes(admission_envelope)).hexdigest()
                != manifest["trainingCorpusAdmission"]["envelopeSha256"]
            ):
                _fail(
                    "manifest.trainingCorpusAdmission.envelopeSha256",
                    "does not match the bundled admission envelope",
                )

        from .base_evaluation import (
            load_base_evaluation_profile,
            load_base_model_snapshot_manifest,
            load_base_model_source_lock,
        )

        profile = load_base_evaluation_profile(bound_paths["profile"])
        snapshot_document, snapshot_manifest_sha256 = load_base_model_snapshot_manifest(
            bound_paths["manifest"]
        )
        source_lock = load_base_model_source_lock(
            bound_paths["sourceLock"], catalog_path
        )
        expected_snapshot = {
            "candidateCatalogSha256": manifest["candidateCatalog"]["sha256"],
            "candidateId": manifest["baseModel"]["candidateId"],
            "baseModel": {
                "modelId": manifest["baseModel"]["modelId"],
                "revision": manifest["baseModel"]["revision"],
            },
            "sourceLockSha256": source_lock.sha256,
            "manifestSha256": snapshot_manifest_sha256,
            "snapshotSha256": snapshot_document["snapshotSha256"],
            "fileTreeSha256": snapshot_document["fileTreeSha256"],
            "chatTemplateSha256": snapshot_document["chatTemplateSha256"],
        }
        if (
            snapshot_document["candidateCatalogSha256"]
            != expected_snapshot["candidateCatalogSha256"]
            or snapshot_document["candidateId"] != expected_snapshot["candidateId"]
            or snapshot_document["baseModel"] != expected_snapshot["baseModel"]
            or snapshot_document["sourceLockSha256"]
            != expected_snapshot["sourceLockSha256"]
        ):
            _fail(
                "manifest.baseModelSnapshot",
                "does not match the selected catalog candidate and source lock",
            )
        expected_profile_binding = {
            "sourceLockSha256": expected_snapshot["sourceLockSha256"],
            "manifestSha256": expected_snapshot["manifestSha256"],
            "snapshotSha256": expected_snapshot["snapshotSha256"],
            "fileTreeSha256": expected_snapshot["fileTreeSha256"],
        }
        if (
            profile.document["candidateCatalogSha256"]
            != expected_snapshot["candidateCatalogSha256"]
            or profile.document["candidateId"] != expected_snapshot["candidateId"]
            or profile.document["baseModel"] != expected_snapshot["baseModel"]
            or profile.document["baseModelSnapshot"] != expected_profile_binding
            or profile.document["chatTemplateSha256"]
            != expected_snapshot["chatTemplateSha256"]
        ):
            _fail(
                "manifest.baseModelSnapshot.profile",
                "does not match the selected snapshot manifest",
            )
        if snapshot_bindings["profile"]["sha256"] != profile.sha256:
            _fail(
                "manifest.baseModelSnapshot.profile.sha256",
                "does not match the canonical profile bytes",
            )
        for name in ("snapshotSha256", "fileTreeSha256", "chatTemplateSha256"):
            if snapshot_bindings[name] != expected_snapshot[name]:
                _fail(
                    f"manifest.baseModelSnapshot.{name}",
                    "does not match the selected snapshot manifest",
                )
    if (
        sha256_file(dataset_path, max_bytes=MAX_SFT_BYTES)
        != manifest["dataset"]["sha256"]
    ):
        _fail("manifest.dataset.sha256", "does not match the SFT bytes")
    summary = validate_sft(dataset_path)
    if summary.record_count != manifest["dataset"]["recordCount"]:
        _fail("manifest.dataset.recordCount", "does not match the SFT record count")
    if (
        list(summary.source_schema_versions)
        != manifest["dataset"]["sourceSchemaVersions"]
    ):
        _fail(
            "manifest.dataset.sourceSchemaVersions",
            "does not match the SFT source schemas",
        )
    if set(summary.split_counts) != {"development"}:
        _fail(
            "manifest.dataset",
            "training bundles may contain only development-split SFT records",
        )
    if summary.missing_domains:
        _fail(
            "manifest.dataset",
            f"lacks required domain coverage {list(summary.missing_domains)}",
        )
    return summary


def validate_manifest_snapshot(
    path: str | os.PathLike[str],
) -> ValidatedManifestSnapshot:
    manifest_path = _regular_file(Path(path), "manifest file")
    if manifest_path.name != MANIFEST_BUNDLE_PATH:
        _fail("manifest file", f"must be named {MANIFEST_BUNDLE_PATH!r}")
    raw = _read_file_bounded(manifest_path, "manifest file", MAX_JSON_BYTES)
    manifest = _validate_manifest_document(
        _load_json_object_bytes(raw, "manifest file")
    )
    _verify_manifest_bindings(manifest, manifest_path.parent)
    return ValidatedManifestSnapshot(
        path=manifest_path,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        document=manifest,
    )


def validate_manifest_path(path: str | os.PathLike[str]) -> dict[str, Any]:
    return validate_manifest_snapshot(path).document


def _write_json_exclusive(path: Path, value: Any) -> None:
    serialized = json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)


def _read_chat_template(path: Path) -> str:
    resolved = _regular_file(path, "chat template")
    raw = _read_file_bounded(resolved, "chat template", MAX_CHAT_TEMPLATE_BYTES)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(
            f"chat template: invalid UTF-8 at byte {error.start}"
        ) from error
    return validate_chat_template(text, "chat template")


def create_bundle(
    *,
    catalog_path: str | os.PathLike[str],
    sft_path: str | os.PathLike[str],
    candidate_id: str,
    chat_template_path: str | os.PathLike[str],
    chat_template_name: str,
    output_directory: str | os.PathLike[str],
    runtime_profile_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
    base_selection_path: str | os.PathLike[str] | None = None,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_evaluation_profile_path: str | os.PathLike[str] | None = None,
    base_model_snapshot_manifest_path: str | os.PathLike[str] | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    base_model_source_lock_path: str | os.PathLike[str] | None = None,
    base_selection_now: datetime | None = None,
    corpus_admission_path: str | os.PathLike[str] | None = None,
    corpus_admission_trust: TrainingCorpusAdmissionTrust | None = None,
    corpus_admission_now: datetime | None = None,
    seed: int = 17,
    hyperparameters: Mapping[str, Any] | None = None,
    _after_snapshot: Callable[[], None] | None = None,
) -> dict[str, Any]:
    source_catalog = Path(catalog_path)
    source_sft = Path(sft_path)
    _string(chat_template_name, "chat template name", max_length=200)
    _integer(seed, "seed", 0, 2_147_483_647)
    effective_hyperparameters = dict(hyperparameters or default_hyperparameters())
    _validate_hyperparameters(effective_hyperparameters, "hyperparameters")
    release_values = (
        data_release_path,
        review_receipt_trust,
        evaluation_authoring_approval_trust,
    )
    if any(value is not None for value in release_values) and not all(
        value is not None for value in release_values
    ):
        _fail(
            "training release authority",
            "the release path, review-receipt trust, and evaluation-authoring approval trust are required together",
        )
    if review_receipt_now is not None and data_release_path is None:
        _fail(
            "training release validation time",
            "cannot be supplied without the complete release authority",
        )
    selection_values = (
        base_selection_path,
        base_selection_trust,
        base_evaluation_profile_path,
        base_model_snapshot_manifest_path,
        base_model_snapshot_path,
        base_model_source_lock_path,
    )
    selected_training = all(value is not None for value in selection_values)
    if any(value is not None for value in selection_values) and not selected_training:
        _fail(
            "base-model selection",
            "the envelope, trust, profile, snapshot manifest, snapshot directory, and source lock are required together",
        )
    if selected_training and data_release_path is None:
        _fail("base-model selection", "requires a release-bound training bundle")
    admission_values = (corpus_admission_path, corpus_admission_trust)
    if any(value is not None for value in admission_values) and not all(
        value is not None for value in admission_values
    ):
        _fail(
            "training corpus admission",
            "the envelope and externally pinned trust are required together",
        )
    if selected_training and corpus_admission_path is None:
        _fail(
            "training corpus admission",
            "is required for every selected training bundle",
        )
    if not selected_training and any(value is not None for value in admission_values):
        _fail(
            "training corpus admission",
            "cannot be supplied without a complete selected training target",
        )
    if corpus_admission_now is not None and corpus_admission_path is None:
        _fail(
            "training corpus admission validation time",
            "cannot be supplied without the complete admission authority",
        )

    destination = Path(output_directory)
    with _exclusive_destination_lock(
        destination, "output directory"
    ) as locked_destination:
        if os.path.lexists(locked_destination):
            _fail(
                "output directory",
                "already exists; bundles are immutable and never overwritten",
            )
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{locked_destination.name}.staging-",
                dir=locked_destination.parent,
            )
        )
        try:
            inputs_directory = stage / "inputs"
            inputs_directory.mkdir()
            copied_catalog = _copy_file_snapshot(
                source_catalog,
                inputs_directory / "candidate-catalog.json",
                "candidate catalog",
                max_bytes=MAX_JSON_BYTES,
            )
            copied_sft = _copy_file_snapshot(
                source_sft,
                inputs_directory / "dataset.sft.jsonl",
                "SFT file",
                max_bytes=MAX_SFT_BYTES,
            )
            copied_template = _copy_file_snapshot(
                Path(chat_template_path),
                stage / ".chat-template.snapshot",
                "chat template",
                max_bytes=MAX_CHAT_TEMPLATE_BYTES,
            )
            copied_runtime_profile = _copy_file_snapshot(
                Path(runtime_profile_path),
                inputs_directory / "training-runtime-profile.json",
                "training runtime profile",
                max_bytes=MAX_JSON_BYTES,
            )
            copied_selection: Path | None = None
            copied_base_profile: Path | None = None
            copied_snapshot_manifest: Path | None = None
            copied_source_lock: Path | None = None
            copied_corpus_admission: Path | None = None
            if selected_training:
                if (
                    base_selection_path is None
                    or base_evaluation_profile_path is None
                    or base_model_snapshot_manifest_path is None
                    or base_model_source_lock_path is None
                ):
                    _fail("base-model selection", "selected inputs are unavailable")
                copied_selection = _copy_file_snapshot(
                    Path(base_selection_path),
                    stage / BASE_SELECTION_BUNDLE_PATH,
                    "base-model selection envelope",
                    max_bytes=MAX_JSON_BYTES,
                )
                copied_base_profile = _copy_file_snapshot(
                    Path(base_evaluation_profile_path),
                    stage / BASE_EVALUATION_PROFILE_BUNDLE_PATH,
                    "base-evaluation profile",
                    max_bytes=MAX_JSON_BYTES,
                )
                copied_snapshot_manifest = _copy_file_snapshot(
                    Path(base_model_snapshot_manifest_path),
                    stage / BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
                    "base-model snapshot manifest",
                    max_bytes=MAX_JSON_BYTES,
                )
                copied_source_lock = _copy_file_snapshot(
                    Path(base_model_source_lock_path),
                    stage / BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
                    "base-model source lock",
                    max_bytes=MAX_JSON_BYTES,
                )
                if corpus_admission_path is None:
                    _fail("training corpus admission", "selected input is unavailable")
                from .corpus_quality import MAX_CORPUS_ADMISSION_BYTES

                copied_corpus_admission = _copy_file_snapshot(
                    Path(corpus_admission_path),
                    stage / TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
                    "training corpus admission envelope",
                    max_bytes=MAX_CORPUS_ADMISSION_BYTES + 1,
                )
            from .runtime import (
                MAX_PYLOCK_BYTES,
                TRAINING_PYLOCK_BUNDLE_PATH,
                TRAINING_RUNTIME_PROFILE_BUNDLE_PATH,
                load_and_validate_training_runtime,
                validate_training_runtime_profile,
            )

            runtime_profile = validate_training_runtime_profile(copied_runtime_profile)
            copied_pylock = _copy_file_snapshot(
                Path(runtime_profile_path).parent
                / runtime_profile["pylock"]["fileName"],
                inputs_directory / "pylock.train.toml",
                "training runtime pylock",
                max_bytes=MAX_PYLOCK_BYTES,
            )
            load_and_validate_training_runtime(copied_runtime_profile, copied_pylock)
            if _after_snapshot is not None:
                _after_snapshot()

            catalog = validate_candidate_catalog(copied_catalog)
            summary = validate_sft(copied_sft)
            if set(summary.split_counts) != {"development"}:
                _fail(
                    "SFT file",
                    "a training bundle may contain only development-split records",
                )
            if summary.missing_domains:
                _fail(
                    "SFT file",
                    f"lacks required domain coverage {list(summary.missing_domains)}",
                )
            candidates = {
                candidate["id"]: candidate for candidate in catalog["candidates"]
            }
            selected = candidates.get(candidate_id)
            if selected is None:
                _fail("candidate ID", "is absent from the validated catalog")
            if "student" not in selected["roles"]:
                _fail(
                    "candidate ID",
                    "must select a catalog candidate with the student role",
                )
            template = _read_chat_template(copied_template)
            copied_template.unlink()

            catalog_hash = sha256_file(copied_catalog, max_bytes=MAX_JSON_BYTES)
            dataset_hash = sha256_file(copied_sft, max_bytes=MAX_SFT_BYTES)
            data_release = None
            verified_corpus_admission = None
            if data_release_path is not None:
                if review_receipt_trust is None:
                    _fail(
                        "review-receipt trust",
                        "is required when a training release is bound",
                    )
                from .release import validate_training_release_binding

                _, data_release = validate_training_release_binding(
                    data_release_path,
                    dataset_sha256=dataset_hash,
                    review_receipt_trust=review_receipt_trust,
                    evaluation_authoring_approval_trust=(
                        evaluation_authoring_approval_trust
                    ),
                    now=review_receipt_now,
                )
            if selected_training:
                if (
                    copied_corpus_admission is None
                    or corpus_admission_trust is None
                    or data_release is None
                    or review_receipt_trust is None
                    or evaluation_authoring_approval_trust is None
                    or base_selection_trust is None
                ):
                    _fail(
                        "training corpus admission",
                        "selected admission authority is unavailable",
                    )
                upstream_signers = {
                    review_receipt_trust.public_key_spki_sha256,
                    evaluation_authoring_approval_trust.public_key_spki_sha256,
                    base_selection_trust.public_key_spki_sha256,
                }
                if corpus_admission_trust.public_key_spki_sha256 in upstream_signers:
                    _fail(
                        "training corpus admission signer",
                        "must differ from corpus review, evaluation-authoring, and base-selection signers",
                    )
                from .corpus_quality import verify_training_corpus_admission_file

                verified_corpus_admission = verify_training_corpus_admission_file(
                    copied_corpus_admission,
                    dataset_bytes=_read_file_bounded(
                        copied_sft,
                        "training corpus admission dataset snapshot",
                        MAX_SFT_BYTES,
                    ),
                    dataset_source_path=copied_sft,
                    expected_data_release=data_release,
                    trust=corpus_admission_trust,
                    now=corpus_admission_now,
                )
            selected_target = None
            if selected_training:
                if (
                    copied_selection is None
                    or copied_base_profile is None
                    or copied_snapshot_manifest is None
                    or copied_source_lock is None
                    or base_selection_trust is None
                    or base_model_snapshot_path is None
                ):
                    _fail("base-model selection", "selected inputs are unavailable")
                from .base_selection import validate_base_model_selection_target

                selected_target = validate_base_model_selection_target(
                    copied_selection,
                    trust=base_selection_trust,
                    evaluation_authoring_approval_trust=(
                        evaluation_authoring_approval_trust
                    ),
                    review_receipt_trust=review_receipt_trust,
                    profile_path=copied_base_profile,
                    snapshot_manifest_path=copied_snapshot_manifest,
                    snapshot_path=base_model_snapshot_path,
                    catalog_path=copied_catalog,
                    source_lock_path=copied_source_lock,
                    now=base_selection_now,
                )
                selection_payload = selected_target.selection.payload
                selected_identity = selection_payload["selected"]
                if candidate_id != selected_identity["candidateId"]:
                    _fail(
                        "candidate ID",
                        "does not match the independently signed base-model selection",
                    )
                if data_release != selection_payload["dataRelease"]:
                    _fail(
                        "base-model selection dataRelease",
                        "does not match the validated training release",
                    )
                if (
                    hashlib.sha256(template.encode("utf-8")).hexdigest()
                    != selected_identity["chatTemplateSha256"]
                ):
                    _fail(
                        "chat template",
                        "does not match the exact selected base-model snapshot",
                    )
            created_at = (
                datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
            manifest: dict[str, Any] = {
                "schemaVersion": (
                    MANIFEST_V3_SCHEMA_VERSION
                    if selected_training
                    else MANIFEST_SCHEMA_VERSION
                ),
                "createdAtUtc": created_at,
                "baseModel": {
                    "candidateId": selected["id"],
                    "modelId": selected["modelId"],
                    "revision": selected["revision"],
                    "license": selected["license"],
                    "officialSourceUrl": selected["officialSourceUrl"],
                },
                "candidateCatalog": {
                    "path": CATALOG_BUNDLE_PATH,
                    "sha256": catalog_hash,
                },
                "dataset": {
                    "path": DATASET_BUNDLE_PATH,
                    "sha256": dataset_hash,
                    "format": "expert-model-sft-jsonl",
                    "recordCount": summary.record_count,
                    "sourceSchemaVersions": list(summary.source_schema_versions),
                },
                "method": "QLoRA-SFT",
                "seed": seed,
                "chatTemplate": {
                    "name": chat_template_name,
                    "template": template,
                    "sha256": hashlib.sha256(template.encode("utf-8")).hexdigest(),
                },
                "hyperparameters": effective_hyperparameters,
                "outputPath": OUTPUT_BUNDLE_PATH,
                "domains": list(DOMAINS),
                "trainingRuntime": {
                    "profile": {
                        "path": TRAINING_RUNTIME_PROFILE_BUNDLE_PATH,
                        "sha256": sha256_file(
                            copied_runtime_profile, max_bytes=MAX_JSON_BYTES
                        ),
                    },
                    "pylock": {
                        "path": TRAINING_PYLOCK_BUNDLE_PATH,
                        "sha256": sha256_file(
                            copied_pylock, max_bytes=MAX_PYLOCK_BYTES
                        ),
                    },
                },
                "dataRelease": data_release,
            }
            if selected_target is not None:
                if verified_corpus_admission is None:
                    _fail(
                        "training corpus admission",
                        "validated selected admission is unavailable",
                    )
                selection = selected_target.selection
                selection_payload = selection.payload
                selected_identity = selection_payload["selected"]
                manifest["baseModelSelection"] = {
                    "path": BASE_SELECTION_BUNDLE_PATH,
                    "envelopeSha256": selection.envelope_sha256,
                    "payloadSha256": selection.payload_sha256,
                    "selectionId": selection_payload["selectionId"],
                    "expiresAtUtc": selection_payload["expiresAtUtc"],
                }
                manifest["baseModelSnapshot"] = {
                    "profile": {
                        "path": BASE_EVALUATION_PROFILE_BUNDLE_PATH,
                        "sha256": selected_identity["profileSha256"],
                    },
                    "manifest": {
                        "path": BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
                        "sha256": selected_identity["snapshotManifestSha256"],
                    },
                    "sourceLock": {
                        "path": BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
                        "sha256": sha256_file(
                            copied_source_lock, max_bytes=MAX_JSON_BYTES
                        ),
                    },
                    "snapshotSha256": selected_identity["snapshotSha256"],
                    "fileTreeSha256": selected_identity["fileTreeSha256"],
                    "chatTemplateSha256": selected_identity["chatTemplateSha256"],
                }
                manifest["trainingCorpusAdmission"] = {
                    "path": TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
                    **verified_corpus_admission.as_dict(),
                }
            manifest["runId"] = _manifest_run_id(manifest)
            manifest_path = stage / MANIFEST_BUNDLE_PATH
            _write_json_exclusive(manifest_path, manifest)
            validate_manifest_path(manifest_path)
            file_entries = []
            bundle_paths = [
                CATALOG_BUNDLE_PATH,
                DATASET_BUNDLE_PATH,
                TRAINING_RUNTIME_PROFILE_BUNDLE_PATH,
                TRAINING_PYLOCK_BUNDLE_PATH,
                MANIFEST_BUNDLE_PATH,
            ]
            if selected_training:
                bundle_paths.extend(
                    (
                        BASE_SELECTION_BUNDLE_PATH,
                        BASE_EVALUATION_PROFILE_BUNDLE_PATH,
                        BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
                        BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
                        TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
                    )
                )
            for relative in bundle_paths:
                file_path = resolve_bound_path(stage, relative, "bundle file path")
                if relative == DATASET_BUNDLE_PATH:
                    file_limit = MAX_SFT_BYTES
                elif relative == TRAINING_PYLOCK_BUNDLE_PATH:
                    file_limit = MAX_PYLOCK_BYTES
                else:
                    file_limit = MAX_JSON_BYTES
                file_entries.append(
                    {
                        "path": relative,
                        "sha256": sha256_file(file_path, max_bytes=file_limit),
                        "sizeBytes": file_path.stat().st_size,
                    }
                )
            bundle_payload = {
                "schemaVersion": (
                    BUNDLE_V2_SCHEMA_VERSION
                    if selected_training
                    else BUNDLE_SCHEMA_VERSION
                ),
                "files": file_entries,
            }
            bundle = {
                **bundle_payload,
                "bundleSha256": hashlib.sha256(
                    canonical_json_bytes(bundle_payload)
                ).hexdigest(),
            }
            _write_json_exclusive(stage / "run-bundle.json", bundle)
            validate_bundle(stage)
            _install_directory_no_clobber(stage, locked_destination, "output directory")
            result = {
                "bundlePath": str(locked_destination),
                "runId": manifest["runId"],
                "manifestSha256": sha256_file(
                    locked_destination / MANIFEST_BUNDLE_PATH,
                    max_bytes=MAX_JSON_BYTES,
                ),
                "bundleSha256": bundle["bundleSha256"],
                "datasetSha256": dataset_hash,
                "candidateCatalogSha256": catalog_hash,
                "trainingStarted": False,
            }
            if selected_target is not None:
                result["baseModelSelectionId"] = selected_target.selection.payload[
                    "selectionId"
                ]
                result["corpusAdmissionId"] = verified_corpus_admission.payload[
                    "corpusAdmissionId"
                ]
            return result
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def validate_bundle(path: str | os.PathLike[str]) -> dict[str, Any]:
    root = _existing_directory(Path(path), "bundle")
    bundle_path = root / "run-bundle.json"
    bundle = _exact_keys(
        load_json_document(bundle_path),
        {"schemaVersion", "files", "bundleSha256"},
        "bundle",
    )
    if bundle["schemaVersion"] not in {
        BUNDLE_SCHEMA_VERSION,
        BUNDLE_V2_SCHEMA_VERSION,
    }:
        _fail(
            "bundle.schemaVersion",
            f"must be {BUNDLE_SCHEMA_VERSION!r} or {BUNDLE_V2_SCHEMA_VERSION!r}",
        )
    entries = bundle["files"]
    if not isinstance(entries, list) or len(entries) not in {5, 9, 10}:
        _fail(
            "bundle.files",
            "must contain five legacy, nine v2, or ten v3 training files",
        )
    validated_entries = []
    seen_paths: set[str] = set()
    for index, raw_entry in enumerate(entries):
        field = f"bundle.files[{index}]"
        entry = _exact_keys(raw_entry, {"path", "sha256", "sizeBytes"}, field)
        pure = _relative_path(entry["path"], f"{field}.path")
        relative = pure.as_posix()
        if relative in seen_paths:
            _fail(f"{field}.path", "duplicates an earlier bundle path")
        seen_paths.add(relative)
        expected_hash = _sha256(entry["sha256"], f"{field}.sha256")
        expected_size = _integer(
            entry["sizeBytes"], f"{field}.sizeBytes", 1, MAX_SFT_BYTES
        )
        file_path = resolve_bound_path(root, relative, f"{field}.path")
        if file_path.stat().st_size != expected_size:
            _fail(f"{field}.sizeBytes", "does not match the bundle file size")
        if sha256_file(file_path, max_bytes=expected_size) != expected_hash:
            _fail(f"{field}.sha256", "does not match the bundle file bytes")
        validated_entries.append(entry)
    required_paths = {
        CATALOG_BUNDLE_PATH,
        DATASET_BUNDLE_PATH,
        MANIFEST_BUNDLE_PATH,
    }
    from .runtime import (
        TRAINING_PYLOCK_BUNDLE_PATH,
        TRAINING_RUNTIME_PROFILE_BUNDLE_PATH,
    )

    required_paths.update(
        {TRAINING_RUNTIME_PROFILE_BUNDLE_PATH, TRAINING_PYLOCK_BUNDLE_PATH}
    )
    manifest = validate_manifest_path(root / MANIFEST_BUNDLE_PATH)
    if manifest["schemaVersion"] in {
        MANIFEST_V2_SCHEMA_VERSION,
        MANIFEST_V3_SCHEMA_VERSION,
    }:
        required_paths.update(
            {
                BASE_SELECTION_BUNDLE_PATH,
                BASE_EVALUATION_PROFILE_BUNDLE_PATH,
                BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
                BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
            }
        )
    if manifest["schemaVersion"] == MANIFEST_V3_SCHEMA_VERSION:
        required_paths.add(TRAINING_CORPUS_ADMISSION_BUNDLE_PATH)
    expected_bundle_schema = (
        BUNDLE_V2_SCHEMA_VERSION
        if manifest["schemaVersion"]
        in {MANIFEST_V2_SCHEMA_VERSION, MANIFEST_V3_SCHEMA_VERSION}
        else BUNDLE_SCHEMA_VERSION
    )
    if bundle["schemaVersion"] != expected_bundle_schema:
        _fail(
            "bundle.schemaVersion",
            "does not match the bound training-manifest generation",
        )
    if seen_paths != required_paths:
        _fail("bundle.files", f"must contain exactly {sorted(required_paths)}")
    payload = {"schemaVersion": bundle["schemaVersion"], "files": validated_entries}
    expected_bundle_hash = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    if _sha256(bundle["bundleSha256"], "bundle.bundleSha256") != expected_bundle_hash:
        _fail("bundle.bundleSha256", "does not match the canonical bundle index")
    return {
        "bundleSha256": bundle["bundleSha256"],
        "manifestSha256": sha256_file(
            root / MANIFEST_BUNDLE_PATH,
            max_bytes=MAX_JSON_BYTES,
        ),
        "runId": manifest["runId"],
    }
