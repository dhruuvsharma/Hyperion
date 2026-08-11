from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .core import (
    MAX_JSON_BYTES,
    ValidationError,
    _exact_keys,
    _existing_directory,
    _fail,
    _integer,
    _is_reparse_or_symlink,
    _read_file_bounded,
    _reject_constant,
    _reject_reparse_components,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _validate_candidate_catalog_document,
    _write_json_exclusive,
    canonical_json_bytes,
    sha256_file,
)
from .deployment import (
    _COMPUTE_DTYPES,
    _OCI_DIGEST_RE,
    _QUANTIZATIONS,
    _RUNTIME_CAPABILITIES,
)


BASE_MODEL_SNAPSHOT_SCHEMA_VERSION = "daxalgo.hyperion.base-model-snapshot/v1"
BASE_MODEL_FILE_TREE_SCHEMA_VERSION = "daxalgo.hyperion.base-model-file-tree/v1"
BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION = "daxalgo.hyperion.base-model-source-lock/v1"
BASE_EVALUATION_PROFILE_SCHEMA_VERSION = "daxalgo.hyperion.base-evaluation-profile/v1"
BASE_EXECUTION_MODEL_PREFIX = "daxalgo-base-sha256-"
APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256 = (
    "085da4f3847027d078c559917a0fec5ff051c6beef247dcae14ffed932aa4edc"
)

MAX_BASE_MODEL_FILES = 1_024
MAX_BASE_MODEL_ENTRIES = 1_024
MAX_BASE_MODEL_FILE_BYTES = 100_000_000_000
MAX_BASE_MODEL_TOTAL_BYTES = 250_000_000_000
MAX_BASE_MODEL_MANIFEST_BYTES = 4_000_000
MAX_BASE_MODEL_SOURCE_LOCK_BYTES = 4_000_000
MAX_BASE_EVALUATION_PROFILE_BYTES = 1_000_000
MAX_SAFETENSORS_HEADER_BYTES = 100_000_000

_ZERO_SHA256 = "0" * 64
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,99}$")
_TENSOR_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,1000}$")
_MODEL_SHARD_RE = re.compile(r"^model-(\d{5})-of-(\d{5})\.safetensors$")
_SAFETENSORS_DTYPE_BITS = {
    "BOOL": 8,
    "I8": 8,
    "U8": 8,
    "I16": 16,
    "U16": 16,
    "F16": 16,
    "BF16": 16,
    "I32": 32,
    "U32": 32,
    "F32": 32,
    "I64": 64,
    "U64": 64,
    "F64": 64,
    "F8_E4M3": 8,
    "F8_E5M2": 8,
    "F8_E8M0": 8,
}
_ALLOWED_FILES = frozenset(
    {
        "LICENSE",
        "LICENSE.txt",
        "NOTICE",
        "README.md",
        "USAGE_POLICY",
        "added_tokens.json",
        "chat_template.jinja",
        "config.json",
        "generation_config.json",
        "merges.txt",
        "model.safetensors",
        "model.safetensors.index.json",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
    }
)
_REQUIRED_FILES = frozenset({"config.json", "tokenizer.json", "tokenizer_config.json"})


@dataclass(frozen=True)
class BaseModelSnapshot:
    manifest_path: Path
    manifest_sha256: str
    snapshot_path: Path
    document: dict[str, Any]


@dataclass(frozen=True)
class BaseModelSourceLock:
    path: Path
    sha256: str
    document: dict[str, Any]


@dataclass(frozen=True)
class BaseEvaluationProfile:
    path: Path
    sha256: str
    execution_model_id: str
    document: dict[str, Any]


def _json_from_raw(raw: bytes, field: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(field, "UTF-8 byte-order marks are not accepted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        _fail(field, f"invalid UTF-8 at byte {error.start}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except RecursionError:
        _fail(field, "must not exceed 32 JSON nesting levels")
    except json.JSONDecodeError as error:
        _fail(
            field,
            f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}",
        )
    _reject_excessive_depth(value, field)
    return value


def _reject_excessive_depth(value: Any, field: str, depth: int = 1) -> None:
    if depth > 32:
        _fail(field, "must not exceed 32 JSON nesting levels")
    if isinstance(value, dict):
        for child in value.values():
            _reject_excessive_depth(child, field, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _reject_excessive_depth(child, field, depth + 1)


def _safe_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not _SAFE_ID_RE.fullmatch(text):
        _fail(field, "must be an ASCII identifier")
    return text


def _model_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _MODEL_ID_RE.fullmatch(text):
        _fail(field, "must be an ASCII model identifier")
    return text


def _version(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not _VERSION_RE.fullmatch(text):
        _fail(field, "must be an ASCII version identifier")
    return text


def _write_json_no_clobber(path: Path, value: Any, field: str) -> None:
    try:
        _write_json_exclusive(path, value)
    except FileExistsError:
        _fail(field, f"already exists: {path}")


def _load_catalog(path: str | os.PathLike[str]) -> tuple[dict[str, Any], str, bytes]:
    catalog_path = Path(path)
    raw = _read_file_bounded(catalog_path, "candidate catalog", MAX_JSON_BYTES)
    catalog = _validate_candidate_catalog_document(
        _json_from_raw(raw, "candidate catalog")
    )
    return catalog, hashlib.sha256(raw).hexdigest(), raw


def _selected_candidate(
    catalog: Mapping[str, Any], candidate_id: str
) -> dict[str, Any]:
    candidate = next(
        (item for item in catalog["candidates"] if item["id"] == candidate_id),
        None,
    )
    if candidate is None:
        _fail("candidate ID", "does not exist in the pinned candidate catalog")
    if "student" not in candidate["roles"]:
        _fail("candidate ID", "must identify a shortlisted student base model")
    return candidate


def _allowed_file_name(name: str) -> bool:
    return name in _ALLOWED_FILES or _MODEL_SHARD_RE.fullmatch(name) is not None


def _hash_regular_file(path: Path, field: str, initial_stat: os.stat_result) -> str:
    if initial_stat.st_size > MAX_BASE_MODEL_FILE_BYTES:
        _fail(field, f"exceeds the {MAX_BASE_MODEL_FILE_BYTES}-byte file limit")
    digest = sha256_file(path, max_bytes=MAX_BASE_MODEL_FILE_BYTES)
    try:
        final_stat = os.lstat(path)
    except FileNotFoundError as error:
        raise ValidationError(f"{field}: disappeared while it was hashed") from error
    initial_identity = (
        initial_stat.st_dev,
        initial_stat.st_ino,
        initial_stat.st_size,
        getattr(initial_stat, "st_mtime_ns", None),
    )
    final_identity = (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_size,
        getattr(final_stat, "st_mtime_ns", None),
    )
    if _is_reparse_or_symlink(final_stat) or initial_identity != final_identity:
        _fail(field, "changed while it was hashed")
    return digest


def build_base_model_file_index(
    snapshot_path: str | os.PathLike[str],
) -> tuple[list[dict[str, Any]], str]:
    root = _existing_directory(Path(snapshot_path), "base-model snapshot")
    files: list[dict[str, Any]] = []
    total_bytes = 0
    try:
        with os.scandir(root) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except OSError as error:
        raise ValidationError(
            f"base-model snapshot: cannot enumerate {root}: {error}"
        ) from error
    if len(entries) > MAX_BASE_MODEL_ENTRIES:
        _fail(
            "base-model snapshot",
            f"contains more than {MAX_BASE_MODEL_ENTRIES} filesystem entries",
        )
    for entry in entries:
        try:
            entry_stat = os.lstat(entry.path)
        except FileNotFoundError as error:
            raise ValidationError(
                f"base-model snapshot: entry disappeared: {entry.path}"
            ) from error
        if _is_reparse_or_symlink(entry_stat):
            _fail(
                "base-model snapshot",
                f"symbolic-link or reparse-point entry is not accepted: {entry.path}",
            )
        if stat.S_ISDIR(entry_stat.st_mode):
            _fail(
                "base-model snapshot", f"subdirectories are not accepted: {entry.path}"
            )
        if not stat.S_ISREG(entry_stat.st_mode):
            _fail(
                "base-model snapshot",
                f"non-regular filesystem entry is not accepted: {entry.path}",
            )
        if entry_stat.st_nlink != 1:
            _fail(
                "base-model snapshot",
                f"hard-linked files are not accepted: {entry.path}",
            )
        if not _allowed_file_name(entry.name):
            _fail(
                "base-model snapshot",
                f"unsupported or executable file is not accepted: {entry.name!r}",
            )
        if len(files) >= MAX_BASE_MODEL_FILES:
            _fail(
                "base-model snapshot",
                f"contains more than {MAX_BASE_MODEL_FILES} files",
            )
        total_bytes += entry_stat.st_size
        if total_bytes > MAX_BASE_MODEL_TOTAL_BYTES:
            _fail(
                "base-model snapshot",
                f"exceeds the {MAX_BASE_MODEL_TOTAL_BYTES}-byte aggregate limit",
            )
        files.append(
            {
                "path": entry.name,
                "sha256": _hash_regular_file(
                    Path(entry.path),
                    f"base-model snapshot file {entry.name!r}",
                    entry_stat,
                ),
                "sizeBytes": entry_stat.st_size,
            }
        )
    files.sort(key=lambda item: item["path"])
    if not files:
        _fail("base-model snapshot", "must contain model and tokenizer files")
    paths = {entry["path"] for entry in files}
    missing = sorted(_REQUIRED_FILES - paths)
    if missing:
        _fail("base-model snapshot", f"is missing required files {missing}")
    if not any(path.endswith(".safetensors") for path in paths):
        _fail("base-model snapshot", "must contain safetensors model weights")
    payload = {"schemaVersion": BASE_MODEL_FILE_TREE_SCHEMA_VERSION, "files": files}
    return files, hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _load_snapshot_json(root: Path, name: str, max_bytes: int) -> Any:
    return _json_from_raw(
        _read_file_bounded(root / name, f"base-model snapshot {name}", max_bytes),
        f"base-model snapshot {name}",
    )


def _validate_no_custom_code(value: Any, field: str) -> None:
    if not isinstance(value, dict):
        _fail(field, "must be an object")
    if value.get("auto_map") not in (None, {}):
        _fail(f"{field}.auto_map", "custom code mappings are not accepted")
    if value.get("trust_remote_code") not in (None, False):
        _fail(f"{field}.trust_remote_code", "custom code is not accepted")


def _validate_safetensors(path: Path, field: str) -> None:
    size = path.stat().st_size
    if size < 10:
        _fail(field, "is too short")
    with path.open("rb") as stream:
        header_length = int.from_bytes(stream.read(8), "little", signed=False)
        if header_length < 2 or header_length > min(
            MAX_SAFETENSORS_HEADER_BYTES, size - 8
        ):
            _fail(field, "has an invalid header length")
        header_raw = stream.read(header_length)
    header = _json_from_raw(header_raw, f"{field} header")
    if not isinstance(header, dict):
        _fail(field, "header must be an object")
    data_size = size - 8 - header_length
    ranges: list[tuple[int, int]] = []
    tensor_count = 0
    for name, raw_tensor in header.items():
        tensor_field = f"{field} tensor {name!r}"
        if name == "__metadata__":
            if not isinstance(raw_tensor, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in raw_tensor.items()
            ):
                _fail(tensor_field, "metadata must contain only strings")
            continue
        if not isinstance(name, str) or not _TENSOR_NAME_RE.fullmatch(name):
            _fail(f"{tensor_field}.name", "contains unsupported characters")
        tensor = _exact_keys(
            raw_tensor, {"dtype", "shape", "data_offsets"}, tensor_field
        )
        dtype_bits = _SAFETENSORS_DTYPE_BITS.get(tensor["dtype"])
        if dtype_bits is None:
            _fail(f"{tensor_field}.dtype", "is not a reviewed safetensors dtype")
        shape = tensor["shape"]
        if not isinstance(shape, list) or len(shape) > 16:
            _fail(f"{tensor_field}.shape", "must have at most 16 dimensions")
        element_count = 1
        for index, dimension in enumerate(shape):
            element_count *= _integer(
                dimension,
                f"{tensor_field}.shape[{index}]",
                0,
                10_000_000_000,
            )
            if element_count > MAX_BASE_MODEL_FILE_BYTES * 8:
                _fail(f"{tensor_field}.shape", "declares an excessive tensor size")
        offsets = tensor["data_offsets"]
        if not isinstance(offsets, list) or len(offsets) != 2:
            _fail(f"{tensor_field}.data_offsets", "must contain start and end")
        start = _integer(offsets[0], f"{tensor_field}.data_offsets[0]", 0, data_size)
        end = _integer(offsets[1], f"{tensor_field}.data_offsets[1]", start, data_size)
        expected_bits = element_count * dtype_bits
        if expected_bits % 8 != 0 or end - start != expected_bits // 8:
            _fail(
                f"{tensor_field}.data_offsets",
                "does not match the tensor dtype and shape",
            )
        ranges.append((start, end))
        tensor_count += 1
    if tensor_count < 1:
        _fail(field, "must contain at least one tensor")
    cursor = 0
    for start, end in sorted(ranges):
        if start != cursor:
            _fail(field, "tensor data ranges must be contiguous and non-overlapping")
        cursor = end
    if cursor != data_size:
        _fail(field, "tensor data ranges do not cover the data section")


def _validate_snapshot_payloads(root: Path, files: list[dict[str, Any]]) -> str:
    paths = {entry["path"] for entry in files}
    config = _load_snapshot_json(root, "config.json", MAX_JSON_BYTES)
    tokenizer_config = _load_snapshot_json(
        root, "tokenizer_config.json", MAX_JSON_BYTES
    )
    tokenizer = _load_snapshot_json(root, "tokenizer.json", 100_000_000)
    _validate_no_custom_code(config, "base-model snapshot config.json")
    _validate_no_custom_code(
        tokenizer_config, "base-model snapshot tokenizer_config.json"
    )
    _validate_no_custom_code(tokenizer, "base-model snapshot tokenizer.json")

    if "chat_template.jinja" in paths:
        template_raw = _read_file_bounded(
            root / "chat_template.jinja",
            "base-model snapshot chat_template.jinja",
            1_000_000,
        )
        try:
            template = template_raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            _fail(
                "base-model snapshot chat_template.jinja",
                f"invalid UTF-8 at byte {error.start}",
            )
        if not template.strip():
            _fail("base-model snapshot chat_template.jinja", "must not be empty")
        embedded = tokenizer_config.get("chat_template")
        if embedded is not None and embedded != template:
            _fail(
                "base-model snapshot chat template",
                "file and tokenizer configuration contain different templates",
            )
    else:
        template = tokenizer_config.get("chat_template")
        if not isinstance(template, str) or not template.strip():
            _fail(
                "base-model snapshot tokenizer_config.json.chat_template",
                "must contain the reviewed template when no template file exists",
            )
        if len(template.encode("utf-8")) > 1_000_000:
            _fail("base-model snapshot chat template", "exceeds 1000000 bytes")
    chat_template_sha256 = hashlib.sha256(template.encode("utf-8")).hexdigest()

    shards = sorted(path for path in paths if path.endswith(".safetensors"))
    if "model.safetensors" in paths and len(shards) != 1:
        _fail(
            "base-model snapshot",
            "cannot mix model.safetensors with sharded model weights",
        )
    if "model.safetensors" not in paths:
        parsed_shards: list[tuple[int, int, str]] = []
        for shard in shards:
            match = _MODEL_SHARD_RE.fullmatch(shard)
            if match is None:
                _fail("base-model snapshot", f"unsupported weight file {shard!r}")
            parsed_shards.append((int(match.group(1)), int(match.group(2)), shard))
        totals = {total for _, total, _ in parsed_shards}
        indices = [index for index, _, _ in parsed_shards]
        declared_total = next(iter(totals)) if len(totals) == 1 else -1
        one_indexed = declared_total == len(parsed_shards) and indices == list(
            range(1, declared_total + 1)
        )
        zero_indexed_inclusive = declared_total + 1 == len(
            parsed_shards
        ) and indices == list(range(0, declared_total + 1))
        if not one_indexed and not zero_indexed_inclusive:
            _fail("base-model snapshot", "safetensors shard numbering is incomplete")
        if "model.safetensors.index.json" not in paths:
            _fail("base-model snapshot", "sharded weights require an index")

    for shard in shards:
        _validate_safetensors(root / shard, f"base-model snapshot {shard}")

    if "model.safetensors.index.json" in paths:
        index = _load_snapshot_json(root, "model.safetensors.index.json", 100_000_000)
        if not isinstance(index, dict):
            _fail("base-model snapshot model index", "must be an object")
        if set(index) - {"metadata", "weight_map"}:
            _fail("base-model snapshot model index", "contains unsupported keys")
        weight_map = index.get("weight_map")
        if not isinstance(weight_map, dict) or not weight_map:
            _fail("base-model snapshot model index.weight_map", "must be non-empty")
        referenced: set[str] = set()
        for tensor_name, shard in weight_map.items():
            if not isinstance(tensor_name, str) or not _TENSOR_NAME_RE.fullmatch(
                tensor_name
            ):
                _fail(
                    "base-model snapshot model index", "contains an invalid tensor name"
                )
            if not isinstance(shard, str) or shard not in shards:
                _fail(
                    "base-model snapshot model index",
                    "references a missing or unsupported shard",
                )
            referenced.add(shard)
        if referenced != set(shards):
            _fail(
                "base-model snapshot model index",
                "must reference every safetensors shard",
            )
    return chat_template_sha256


def _validate_file_entries(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_BASE_MODEL_FILES:
        _fail(
            field,
            f"must contain 1 to {MAX_BASE_MODEL_FILES} entries",
        )
    paths: list[str] = []
    total_bytes = 0
    for index, raw_entry in enumerate(value):
        entry_field = f"{field}[{index}]"
        entry = _exact_keys(raw_entry, {"path", "sha256", "sizeBytes"}, entry_field)
        path = _string(entry["path"], f"{entry_field}.path", max_length=255)
        if not _allowed_file_name(path):
            _fail(f"{entry_field}.path", "is not an allowed base-model file")
        _sha256(entry["sha256"], f"{entry_field}.sha256")
        size_bytes = _integer(
            entry["sizeBytes"],
            f"{entry_field}.sizeBytes",
            0,
            MAX_BASE_MODEL_FILE_BYTES,
        )
        total_bytes += size_bytes
        if total_bytes > MAX_BASE_MODEL_TOTAL_BYTES:
            _fail(
                field, f"exceeds the {MAX_BASE_MODEL_TOTAL_BYTES}-byte aggregate limit"
            )
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        _fail(field, "must be unique and ordered by ordinal path")
    path_set = set(paths)
    missing = sorted(_REQUIRED_FILES - path_set)
    if missing:
        _fail(field, f"is missing required files {missing}")
    if not any(path.endswith(".safetensors") for path in path_set):
        _fail(field, "must contain safetensors model weights")
    return value


def _validate_source_lock_document(
    value: Any, catalog: Mapping[str, Any], catalog_sha256: str
) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {"schemaVersion", "candidateCatalogSha256", "candidates"},
        "base-model source lock",
    )
    if document["schemaVersion"] != BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION:
        _fail(
            "base-model source lock.schemaVersion",
            f"must be {BASE_MODEL_SOURCE_LOCK_SCHEMA_VERSION!r}",
        )
    _sha256(
        document["candidateCatalogSha256"],
        "base-model source lock.candidateCatalogSha256",
    )
    if document["candidateCatalogSha256"] != catalog_sha256:
        _fail(
            "base-model source lock.candidateCatalogSha256",
            "does not match the approved candidate catalog bytes",
        )
    candidates = document["candidates"]
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 3:
        _fail("base-model source lock.candidates", "must contain 1 to 3 students")
    seen: set[str] = set()
    for index, raw_candidate in enumerate(candidates):
        field = f"base-model source lock.candidates[{index}]"
        candidate = _exact_keys(
            raw_candidate,
            {"candidateId", "modelId", "revision", "files"},
            field,
        )
        candidate_id = _safe_id(candidate["candidateId"], f"{field}.candidateId")
        if candidate_id in seen:
            _fail(f"{field}.candidateId", "duplicates an earlier candidate")
        seen.add(candidate_id)
        selected = _selected_candidate(catalog, candidate_id)
        _model_id(candidate["modelId"], f"{field}.modelId")
        _revision(candidate["revision"], f"{field}.revision")
        if (
            candidate["modelId"] != selected["modelId"]
            or candidate["revision"] != selected["revision"]
        ):
            _fail(field, "does not match the pinned catalog candidate")
        _validate_file_entries(candidate["files"], f"{field}.files")
    return document


def load_base_model_source_lock(
    source_lock_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
) -> BaseModelSourceLock:
    lock_path = Path(source_lock_path)
    raw = _read_file_bounded(
        lock_path, "base-model source lock", MAX_BASE_MODEL_SOURCE_LOCK_BYTES
    )
    catalog, catalog_sha256, catalog_raw = _load_catalog(catalog_path)
    document = _validate_source_lock_document(
        _json_from_raw(raw, "base-model source lock"), catalog, catalog_sha256
    )
    lock_sha256 = hashlib.sha256(canonical_json_bytes(document)).hexdigest()
    if lock_sha256 != APPROVED_BASE_MODEL_SOURCE_LOCK_SHA256:
        _fail(
            "base-model source lock",
            "canonical SHA-256 is not the reviewed lock compiled into this harness",
        )
    final_raw = _read_file_bounded(
        lock_path, "base-model source lock", MAX_BASE_MODEL_SOURCE_LOCK_BYTES
    )
    if final_raw != raw:
        _fail("base-model source lock", "changed while it was validated")
    _, final_catalog_sha256, final_catalog_raw = _load_catalog(catalog_path)
    if final_catalog_sha256 != catalog_sha256 or final_catalog_raw != catalog_raw:
        _fail("candidate catalog", "changed while the source lock was validated")
    return BaseModelSourceLock(
        path=Path(os.path.abspath(os.fspath(lock_path))),
        sha256=lock_sha256,
        document=document,
    )


def _source_lock_candidate(
    source_lock: BaseModelSourceLock, candidate_id: str
) -> dict[str, Any]:
    candidate = next(
        (
            item
            for item in source_lock.document["candidates"]
            if item["candidateId"] == candidate_id
        ),
        None,
    )
    if candidate is None:
        _fail("candidate ID", "is not present in the approved base-model source lock")
    return candidate


def base_model_snapshot_sha256(document: Mapping[str, Any]) -> str:
    payload = dict(document)
    payload["snapshotSha256"] = _ZERO_SHA256
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _validate_snapshot_document(value: Any) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "schemaVersion",
            "snapshotSha256",
            "candidateCatalogSha256",
            "sourceLockSha256",
            "candidateId",
            "baseModel",
            "chatTemplateSha256",
            "fileTreeSha256",
            "files",
        },
        "base-model snapshot manifest",
    )
    if document["schemaVersion"] != BASE_MODEL_SNAPSHOT_SCHEMA_VERSION:
        _fail(
            "base-model snapshot manifest.schemaVersion",
            f"must be {BASE_MODEL_SNAPSHOT_SCHEMA_VERSION!r}",
        )
    _sha256(document["snapshotSha256"], "base-model snapshot manifest.snapshotSha256")
    _sha256(
        document["candidateCatalogSha256"],
        "base-model snapshot manifest.candidateCatalogSha256",
    )
    _sha256(
        document["sourceLockSha256"],
        "base-model snapshot manifest.sourceLockSha256",
    )
    _safe_id(document["candidateId"], "base-model snapshot manifest.candidateId")
    base_model = _exact_keys(
        document["baseModel"],
        {"modelId", "revision"},
        "base-model snapshot manifest.baseModel",
    )
    _model_id(base_model["modelId"], "base-model snapshot manifest.baseModel.modelId")
    _revision(base_model["revision"], "base-model snapshot manifest.baseModel.revision")
    _sha256(
        document["chatTemplateSha256"],
        "base-model snapshot manifest.chatTemplateSha256",
    )
    _sha256(document["fileTreeSha256"], "base-model snapshot manifest.fileTreeSha256")
    files = _validate_file_entries(
        document["files"], "base-model snapshot manifest.files"
    )
    expected_tree = hashlib.sha256(
        canonical_json_bytes(
            {"schemaVersion": BASE_MODEL_FILE_TREE_SCHEMA_VERSION, "files": files}
        )
    ).hexdigest()
    if document["fileTreeSha256"] != expected_tree:
        _fail(
            "base-model snapshot manifest.fileTreeSha256",
            "does not match the declared files",
        )
    if document["snapshotSha256"] != base_model_snapshot_sha256(document):
        _fail(
            "base-model snapshot manifest.snapshotSha256",
            "does not match the canonical manifest identity",
        )
    return document


def load_base_model_snapshot_manifest(
    manifest_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], str]:
    manifest_file = Path(manifest_path)
    raw = _read_file_bounded(
        manifest_file, "base-model snapshot manifest", MAX_BASE_MODEL_MANIFEST_BYTES
    )
    document = _validate_snapshot_document(
        _json_from_raw(raw, "base-model snapshot manifest")
    )
    final_raw = _read_file_bounded(
        manifest_file, "base-model snapshot manifest", MAX_BASE_MODEL_MANIFEST_BYTES
    )
    if final_raw != raw:
        _fail("base-model snapshot manifest", "changed while it was loaded")
    return document, hashlib.sha256(raw).hexdigest()


def seal_base_model_snapshot(
    *,
    snapshot_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    candidate_id: str,
    output_path: str | os.PathLike[str],
) -> BaseModelSnapshot:
    root = _existing_directory(Path(snapshot_path), "base-model snapshot")
    destination = _reject_reparse_components(
        Path(output_path),
        "base-model snapshot manifest output",
        allow_missing_suffix=True,
    )
    _existing_directory(
        destination.parent, "base-model snapshot manifest output directory"
    )
    if destination == root or root in destination.parents:
        _fail(
            "base-model snapshot manifest output",
            "must be outside the immutable snapshot directory",
        )
    catalog, catalog_sha256, catalog_raw = _load_catalog(catalog_path)
    candidate_id_value = _safe_id(candidate_id, "candidate ID")
    candidate = _selected_candidate(catalog, candidate_id_value)
    source_lock = load_base_model_source_lock(source_lock_path, catalog_path)
    locked_candidate = _source_lock_candidate(source_lock, candidate_id_value)
    files, file_tree_sha256 = build_base_model_file_index(root)
    if files != locked_candidate["files"]:
        _fail(
            "base-model snapshot",
            "does not match the reviewed source lock for the pinned model revision",
        )
    chat_template_sha256 = _validate_snapshot_payloads(root, files)
    document: dict[str, Any] = {
        "schemaVersion": BASE_MODEL_SNAPSHOT_SCHEMA_VERSION,
        "snapshotSha256": _ZERO_SHA256,
        "candidateCatalogSha256": catalog_sha256,
        "sourceLockSha256": source_lock.sha256,
        "candidateId": candidate_id_value,
        "baseModel": {
            "modelId": candidate["modelId"],
            "revision": candidate["revision"],
        },
        "chatTemplateSha256": chat_template_sha256,
        "fileTreeSha256": file_tree_sha256,
        "files": files,
    }
    document["snapshotSha256"] = base_model_snapshot_sha256(document)
    _validate_snapshot_document(document)
    final_files, final_tree = build_base_model_file_index(root)
    final_template = _validate_snapshot_payloads(root, final_files)
    if (
        final_files != files
        or final_tree != file_tree_sha256
        or final_template != chat_template_sha256
    ):
        _fail("base-model snapshot", "changed while its manifest was created")
    _, final_catalog_sha256, final_catalog_raw = _load_catalog(catalog_path)
    if final_catalog_sha256 != catalog_sha256 or final_catalog_raw != catalog_raw:
        _fail("candidate catalog", "changed while the snapshot manifest was created")
    final_source_lock = load_base_model_source_lock(source_lock_path, catalog_path)
    if final_source_lock.sha256 != source_lock.sha256:
        _fail("base-model source lock", "changed while the snapshot was sealed")
    _write_json_no_clobber(destination, document, "base-model snapshot manifest output")
    return validate_base_model_snapshot(
        manifest_path=destination,
        snapshot_path=root,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )


def validate_base_model_snapshot(
    *,
    manifest_path: str | os.PathLike[str],
    snapshot_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
) -> BaseModelSnapshot:
    manifest_file = Path(manifest_path)
    raw = _read_file_bounded(
        manifest_file, "base-model snapshot manifest", MAX_BASE_MODEL_MANIFEST_BYTES
    )
    document = _validate_snapshot_document(
        _json_from_raw(raw, "base-model snapshot manifest")
    )
    catalog, catalog_sha256, catalog_raw = _load_catalog(catalog_path)
    if document["candidateCatalogSha256"] != catalog_sha256:
        _fail(
            "base-model snapshot manifest.candidateCatalogSha256",
            "does not match the supplied catalog bytes",
        )
    candidate = _selected_candidate(catalog, document["candidateId"])
    if document["baseModel"] != {
        "modelId": candidate["modelId"],
        "revision": candidate["revision"],
    }:
        _fail(
            "base-model snapshot manifest.baseModel",
            "does not match the pinned catalog candidate",
        )
    source_lock = load_base_model_source_lock(source_lock_path, catalog_path)
    if document["sourceLockSha256"] != source_lock.sha256:
        _fail(
            "base-model snapshot manifest.sourceLockSha256",
            "does not match the reviewed source lock",
        )
    locked_candidate = _source_lock_candidate(source_lock, document["candidateId"])
    if document["files"] != locked_candidate["files"]:
        _fail(
            "base-model snapshot manifest.files",
            "do not match the reviewed source lock for the pinned model revision",
        )
    root = _existing_directory(Path(snapshot_path), "base-model snapshot")
    files, tree_sha256 = build_base_model_file_index(root)
    template_sha256 = _validate_snapshot_payloads(root, files)
    if files != document["files"] or tree_sha256 != document["fileTreeSha256"]:
        _fail("base-model snapshot", "does not match the sealed file tree")
    if template_sha256 != document["chatTemplateSha256"]:
        _fail("base-model snapshot chat template", "does not match the manifest")
    final_raw = _read_file_bounded(
        manifest_file, "base-model snapshot manifest", MAX_BASE_MODEL_MANIFEST_BYTES
    )
    if final_raw != raw:
        _fail("base-model snapshot manifest", "changed while it was validated")
    final_files, final_tree_sha256 = build_base_model_file_index(root)
    final_template_sha256 = _validate_snapshot_payloads(root, final_files)
    if (
        final_files != files
        or final_tree_sha256 != tree_sha256
        or final_template_sha256 != template_sha256
    ):
        _fail("base-model snapshot", "changed while it was validated")
    _, final_catalog_sha256, final_catalog_raw = _load_catalog(catalog_path)
    if final_catalog_sha256 != catalog_sha256 or final_catalog_raw != catalog_raw:
        _fail("candidate catalog", "changed while the snapshot was validated")
    final_source_lock = load_base_model_source_lock(source_lock_path, catalog_path)
    if final_source_lock.sha256 != source_lock.sha256:
        _fail("base-model source lock", "changed while the snapshot was validated")
    return BaseModelSnapshot(
        manifest_path=Path(os.path.abspath(os.fspath(manifest_file))),
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        snapshot_path=root,
        document=document,
    )


def _validate_runtime(value: Any, candidate_id: str) -> dict[str, Any]:
    runtime = _exact_keys(
        value,
        {
            "engine",
            "engineVersion",
            "containerImageDigest",
            "quantization",
            "computeDtype",
            "maxModelLength",
            "tensorParallelSize",
            "gpuProfile",
        },
        "base-evaluation profile.runtime",
    )
    if runtime["engine"] != "vllm":
        _fail("base-evaluation profile.runtime.engine", "must be 'vllm'")
    _version(runtime["engineVersion"], "base-evaluation profile.runtime.engineVersion")
    if not isinstance(
        runtime["containerImageDigest"], str
    ) or not _OCI_DIGEST_RE.fullmatch(runtime["containerImageDigest"]):
        _fail(
            "base-evaluation profile.runtime.containerImageDigest",
            "must be a lowercase sha256 OCI digest",
        )
    if runtime["quantization"] not in _QUANTIZATIONS:
        _fail("base-evaluation profile.runtime.quantization", "is unsupported")
    if runtime["computeDtype"] not in _COMPUTE_DTYPES:
        _fail("base-evaluation profile.runtime.computeDtype", "is unsupported")
    maximum_length, quantizations = _RUNTIME_CAPABILITIES[candidate_id]
    _integer(
        runtime["maxModelLength"],
        "base-evaluation profile.runtime.maxModelLength",
        128,
        maximum_length,
    )
    if runtime["quantization"] not in quantizations:
        _fail(
            "base-evaluation profile.runtime.quantization",
            "is not reviewed for this base model",
        )
    _integer(
        runtime["tensorParallelSize"],
        "base-evaluation profile.runtime.tensorParallelSize",
        1,
        64,
    )
    _safe_id(runtime["gpuProfile"], "base-evaluation profile.runtime.gpuProfile")
    return runtime


def _validate_base_evaluation_profile_document(value: Any) -> dict[str, Any]:
    profile = _exact_keys(
        value,
        {
            "schemaVersion",
            "profileId",
            "evaluationOnly",
            "promotionStatus",
            "candidateCatalogSha256",
            "candidateId",
            "baseModel",
            "baseModelSnapshot",
            "chatTemplateSha256",
            "runtime",
            "protocol",
        },
        "base-evaluation profile",
    )
    if profile["schemaVersion"] != BASE_EVALUATION_PROFILE_SCHEMA_VERSION:
        _fail(
            "base-evaluation profile.schemaVersion",
            f"must be {BASE_EVALUATION_PROFILE_SCHEMA_VERSION!r}",
        )
    _safe_id(profile["profileId"], "base-evaluation profile.profileId")
    if profile["evaluationOnly"] is not True:
        _fail("base-evaluation profile.evaluationOnly", "must be true")
    if profile["promotionStatus"] != "unpromoted":
        _fail("base-evaluation profile.promotionStatus", "must be 'unpromoted'")
    _sha256(
        profile["candidateCatalogSha256"],
        "base-evaluation profile.candidateCatalogSha256",
    )
    candidate_id = _safe_id(
        profile["candidateId"], "base-evaluation profile.candidateId"
    )
    base_model = _exact_keys(
        profile["baseModel"],
        {"modelId", "revision"},
        "base-evaluation profile.baseModel",
    )
    _model_id(base_model["modelId"], "base-evaluation profile.baseModel.modelId")
    _revision(base_model["revision"], "base-evaluation profile.baseModel.revision")
    snapshot = _exact_keys(
        profile["baseModelSnapshot"],
        {
            "sourceLockSha256",
            "manifestSha256",
            "snapshotSha256",
            "fileTreeSha256",
        },
        "base-evaluation profile.baseModelSnapshot",
    )
    for name in (
        "sourceLockSha256",
        "manifestSha256",
        "snapshotSha256",
        "fileTreeSha256",
    ):
        _sha256(snapshot[name], f"base-evaluation profile.baseModelSnapshot.{name}")
    _sha256(profile["chatTemplateSha256"], "base-evaluation profile.chatTemplateSha256")
    _validate_runtime(profile["runtime"], candidate_id)
    if profile["protocol"] != "openai-compatible":
        _fail("base-evaluation profile.protocol", "must be 'openai-compatible'")
    return profile


def load_base_evaluation_profile(
    path: str | os.PathLike[str],
) -> BaseEvaluationProfile:
    profile_path = Path(path)
    raw = _read_file_bounded(
        profile_path, "base-evaluation profile", MAX_BASE_EVALUATION_PROFILE_BYTES
    )
    document = _validate_base_evaluation_profile_document(
        _json_from_raw(raw, "base-evaluation profile")
    )
    profile_sha256 = hashlib.sha256(raw).hexdigest()
    return BaseEvaluationProfile(
        path=Path(os.path.abspath(os.fspath(profile_path))),
        sha256=profile_sha256,
        execution_model_id=BASE_EXECUTION_MODEL_PREFIX + profile_sha256,
        document=document,
    )


def _validate_profile_bindings(
    profile: Mapping[str, Any],
    snapshot: BaseModelSnapshot,
) -> None:
    manifest = snapshot.document
    expected = {
        "candidateCatalogSha256": manifest["candidateCatalogSha256"],
        "candidateId": manifest["candidateId"],
        "baseModel": manifest["baseModel"],
        "baseModelSnapshot": {
            "sourceLockSha256": manifest["sourceLockSha256"],
            "manifestSha256": snapshot.manifest_sha256,
            "snapshotSha256": manifest["snapshotSha256"],
            "fileTreeSha256": manifest["fileTreeSha256"],
        },
        "chatTemplateSha256": manifest["chatTemplateSha256"],
    }
    for name, value in expected.items():
        if profile[name] != value:
            _fail(
                f"base-evaluation profile.{name}",
                "does not match the sealed base-model snapshot",
            )


def validate_base_evaluation_profile_target(
    *,
    profile_path: str | os.PathLike[str],
    snapshot_manifest_path: str | os.PathLike[str],
    snapshot_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
) -> tuple[BaseEvaluationProfile, BaseModelSnapshot]:
    profile = load_base_evaluation_profile(profile_path)
    snapshot = validate_base_model_snapshot(
        manifest_path=snapshot_manifest_path,
        snapshot_path=snapshot_path,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )
    _validate_profile_bindings(profile.document, snapshot)
    final = load_base_evaluation_profile(profile_path)
    if final.sha256 != profile.sha256 or final.document != profile.document:
        _fail("base-evaluation profile", "changed while it was validated")
    return profile, snapshot


def validate_base_evaluation_profile(
    *,
    profile_path: str | os.PathLike[str],
    snapshot_manifest_path: str | os.PathLike[str],
    snapshot_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
) -> BaseEvaluationProfile:
    profile, _ = validate_base_evaluation_profile_target(
        profile_path=profile_path,
        snapshot_manifest_path=snapshot_manifest_path,
        snapshot_path=snapshot_path,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )
    return profile


def create_base_evaluation_profile(
    *,
    profile_id: str,
    catalog_path: str | os.PathLike[str],
    snapshot_manifest_path: str | os.PathLike[str],
    snapshot_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    engine_version: str,
    container_image_digest: str,
    quantization: str,
    compute_dtype: str,
    max_model_length: int,
    tensor_parallel_size: int,
    gpu_profile: str,
) -> BaseEvaluationProfile:
    snapshot = validate_base_model_snapshot(
        manifest_path=snapshot_manifest_path,
        snapshot_path=snapshot_path,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )
    manifest = snapshot.document
    document = {
        "schemaVersion": BASE_EVALUATION_PROFILE_SCHEMA_VERSION,
        "profileId": profile_id,
        "evaluationOnly": True,
        "promotionStatus": "unpromoted",
        "candidateCatalogSha256": manifest["candidateCatalogSha256"],
        "candidateId": manifest["candidateId"],
        "baseModel": manifest["baseModel"],
        "baseModelSnapshot": {
            "sourceLockSha256": manifest["sourceLockSha256"],
            "manifestSha256": snapshot.manifest_sha256,
            "snapshotSha256": manifest["snapshotSha256"],
            "fileTreeSha256": manifest["fileTreeSha256"],
        },
        "chatTemplateSha256": manifest["chatTemplateSha256"],
        "runtime": {
            "engine": "vllm",
            "engineVersion": engine_version,
            "containerImageDigest": container_image_digest,
            "quantization": quantization,
            "computeDtype": compute_dtype,
            "maxModelLength": max_model_length,
            "tensorParallelSize": tensor_parallel_size,
            "gpuProfile": gpu_profile,
        },
        "protocol": "openai-compatible",
    }
    _validate_base_evaluation_profile_document(document)
    _validate_profile_bindings(document, snapshot)
    destination = _reject_reparse_components(
        Path(output_path), "base-evaluation profile output", allow_missing_suffix=True
    )
    _existing_directory(destination.parent, "base-evaluation profile output directory")
    _write_json_no_clobber(destination, document, "base-evaluation profile output")
    return validate_base_evaluation_profile(
        profile_path=destination,
        snapshot_manifest_path=snapshot_manifest_path,
        snapshot_path=snapshot_path,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )


def build_base_evaluation_vllm_launch(
    *,
    profile_path: str | os.PathLike[str],
    snapshot_manifest_path: str | os.PathLike[str],
    snapshot_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    executable_path: str | os.PathLike[str],
    port: int,
) -> dict[str, Any]:
    profile = validate_base_evaluation_profile(
        profile_path=profile_path,
        snapshot_manifest_path=snapshot_manifest_path,
        snapshot_path=snapshot_path,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )
    executable = _reject_reparse_components(Path(executable_path), "vLLM executable")
    executable_stat = os.lstat(executable)
    if not stat.S_ISREG(executable_stat.st_mode):
        _fail("vLLM executable", "must be a regular file")
    port_value = _integer(port, "vLLM port", 1, 65_535)
    runtime = profile.document["runtime"]
    argv = [
        os.fspath(executable),
        "serve",
        os.fspath(Path(snapshot_path).absolute()),
        "--served-model-name",
        profile.execution_model_id,
        "--tokenizer",
        os.fspath(Path(snapshot_path).absolute()),
        "--host",
        "127.0.0.1",
        "--port",
        str(port_value),
        "--dtype",
        runtime["computeDtype"],
        "--max-model-len",
        str(runtime["maxModelLength"]),
        "--tensor-parallel-size",
        str(runtime["tensorParallelSize"]),
        "--generation-config",
        "vllm",
        "--disable-fastapi-docs",
        "--disable-uvicorn-access-log",
        "--disable-log-requests",
    ]
    quantization = runtime["quantization"]
    if quantization == "bitsandbytes-nf4":
        argv.extend(["--quantization", "bitsandbytes", "--load-format", "bitsandbytes"])
    elif quantization != "none":
        argv.extend(["--quantization", quantization])
    return {
        "schemaVersion": "daxalgo.hyperion.base-evaluation-launch/v1",
        "evaluationOnly": True,
        "promotionStatus": "unpromoted",
        "runtimeAttested": False,
        "releaseEvidenceEligible": False,
        "executionModelId": profile.execution_model_id,
        "servingProfileSha256": profile.sha256,
        "snapshotSha256": profile.document["baseModelSnapshot"]["snapshotSha256"],
        "expectedEngineVersion": runtime["engineVersion"],
        "expectedContainerImageDigest": runtime["containerImageDigest"],
        "environment": {
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        },
        "argv": argv,
        "statement": "Launch plan only. A separate engine owner must attest the live loaded snapshot before release-bound evidence is accepted.",
    }
