from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust
    from .review_receipts import ExpertModelReviewReceiptTrust
    from .trainer_provenance import TrainerProvenanceTrust, VerifiedTrainerProvenance

from .core import (
    DATASET_BUNDLE_PATH,
    MAX_SFT_RECORDS,
    ValidationError,
    _exact_keys,
    _existing_directory,
    _fail,
    _integer,
    _is_reparse_or_symlink,
    _number,
    _parse_datetime,
    _reject_constant,
    _reject_reparse_components,
    _relative_path,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _validate_data_release_identity,
    _write_json_exclusive,
    canonical_json_bytes,
    load_json_document,
    sha256_file,
)


TRAINING_ARTIFACT_V1_SCHEMA_VERSION = "daxalgo.vibe-quant.training-artifact/v1"
TRAINING_ARTIFACT_V2_SCHEMA_VERSION = "daxalgo.vibe-quant.training-artifact/v2"
TRAINING_ARTIFACT_SCHEMA_VERSION = TRAINING_ARTIFACT_V2_SCHEMA_VERSION
ARTIFACT_FILE_TREE_SCHEMA_VERSION = "daxalgo.vibe-quant.artifact-file-tree/v1"
ARTIFACT_METADATA_NAME = "artifact-metadata.json"
MAX_ARTIFACT_FILES = 1_024
MAX_ARTIFACT_ENTRIES = 2_048
MAX_ARTIFACT_FILE_BYTES = 50_000_000_000
MAX_ARTIFACT_TOTAL_BYTES = 100_000_000_000
TRAINING_DEPENDENCIES = (
    "torch",
    "transformers",
    "datasets",
    "peft",
    "trl",
    "accelerate",
    "bitsandbytes",
    "cryptography",
)

_RUN_ID_RE = re.compile(r"^vqrun-[0-9a-f]{20}$")
_COMPUTE_CAPABILITY_RE = re.compile(r"^[0-9]+\.[0-9]+$")
_ZERO_SHA256 = "0" * 64
_ALLOWED_INFERENCE_FILES = frozenset(
    {
        "README.md",
        "adapter_config.json",
        "adapter_model.safetensors",
        "added_tokens.json",
        "chat_template.jinja",
        "merges.txt",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.json",
    }
)
_REQUIRED_INFERENCE_FILES = frozenset(
    {
        "adapter_config.json",
        "adapter_model.safetensors",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
    }
)
_INFERENCE_FILE_SIZE_LIMITS = {
    "README.md": 5_000_000,
    "adapter_config.json": 4_000_000,
    "adapter_model.safetensors": MAX_ARTIFACT_FILE_BYTES,
    "added_tokens.json": 100_000_000,
    "chat_template.jinja": 1_000_000,
    "merges.txt": 100_000_000,
    "special_tokens_map.json": 4_000_000,
    "tokenizer.json": 100_000_000,
    "tokenizer_config.json": 4_000_000,
    "vocab.json": 100_000_000,
}
_SAFETENSORS_DTYPES = {"F16": 2, "BF16": 2, "F32": 4}
_MAX_SAFETENSORS_HEADER_BYTES = 100_000_000
_TENSOR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,999}$")


def _portable_relative_path(value: Any, field: str) -> str:
    pure = _relative_path(value, field)
    relative = pure.as_posix()
    if relative == ARTIFACT_METADATA_NAME:
        _fail(
            field, f"must not use the reserved metadata path {ARTIFACT_METADATA_NAME!r}"
        )
    if len(relative) > 500:
        _fail(field, "must not exceed 500 characters")
    for part in pure.parts:
        if len(part) > 255:
            _fail(field, "contains a path component longer than 255 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            _fail(field, "contains a control character")
    return relative


def _hash_regular_file(path: Path, field: str, expected_stat: os.stat_result) -> str:
    if expected_stat.st_size > MAX_ARTIFACT_FILE_BYTES:
        _fail(field, f"exceeds the {MAX_ARTIFACT_FILE_BYTES}-byte file limit")
    digest = sha256_file(path, max_bytes=MAX_ARTIFACT_FILE_BYTES)
    try:
        final_stat = os.lstat(path)
    except FileNotFoundError as error:
        raise ValidationError(
            f"{field}: file disappeared while it was hashed"
        ) from error
    initial_identity = (
        expected_stat.st_dev,
        expected_stat.st_ino,
        expected_stat.st_size,
        getattr(expected_stat, "st_mtime_ns", None),
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


def build_artifact_file_index(
    path: str | os.PathLike[str],
) -> tuple[list[dict[str, Any]], str]:
    root = _existing_directory(Path(path), "training artifact")
    files: list[dict[str, Any]] = []
    entry_count = 0
    total_bytes = 0

    def visit(directory: Path, relative_parts: tuple[str, ...]) -> None:
        nonlocal entry_count, total_bytes
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            raise ValidationError(
                f"training artifact: cannot enumerate {directory}: {error}"
            ) from error

        for entry in entries:
            entry_count += 1
            if entry_count > MAX_ARTIFACT_ENTRIES:
                _fail(
                    "training artifact",
                    f"contains more than {MAX_ARTIFACT_ENTRIES} filesystem entries",
                )
            try:
                entry_stat = os.lstat(entry.path)
            except FileNotFoundError as error:
                raise ValidationError(
                    f"training artifact: entry disappeared while it was enumerated: {entry.path}"
                ) from error
            if _is_reparse_or_symlink(entry_stat):
                _fail(
                    "training artifact",
                    f"symbolic-link or reparse-point entry is not accepted: {entry.path}",
                )

            parts = (*relative_parts, entry.name)
            relative = PurePosixPath(*parts).as_posix()
            absolute = Path(entry.path)
            if stat.S_ISDIR(entry_stat.st_mode):
                _fail(
                    "training artifact",
                    f"subdirectories are not accepted: {entry.path}",
                )
            if not stat.S_ISREG(entry_stat.st_mode):
                _fail(
                    "training artifact",
                    f"non-regular filesystem entry is not accepted: {entry.path}",
                )
            if entry_stat.st_nlink != 1:
                _fail(
                    "training artifact",
                    f"hard-linked files are not accepted: {entry.path}",
                )
            if relative == ARTIFACT_METADATA_NAME:
                continue
            relative = _portable_relative_path(
                relative, f"training artifact file {relative!r}"
            )
            if len(files) >= MAX_ARTIFACT_FILES:
                _fail(
                    "training artifact",
                    f"contains more than {MAX_ARTIFACT_FILES} files",
                )
            total_bytes += entry_stat.st_size
            if total_bytes > MAX_ARTIFACT_TOTAL_BYTES:
                _fail(
                    "training artifact",
                    f"exceeds the {MAX_ARTIFACT_TOTAL_BYTES}-byte aggregate limit",
                )
            files.append(
                {
                    "path": relative,
                    "sha256": _hash_regular_file(
                        absolute,
                        f"training artifact file {relative!r}",
                        entry_stat,
                    ),
                    "sizeBytes": entry_stat.st_size,
                }
            )

    visit(root, ())
    files.sort(key=lambda entry: entry["path"])
    if not files:
        _fail(
            "training artifact",
            "must contain at least one adapter or tokenizer output file",
        )
    payload = {"schemaVersion": ARTIFACT_FILE_TREE_SCHEMA_VERSION, "files": files}
    tree_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return files, tree_sha256


def _validate_inference_file_set(paths: list[str]) -> None:
    path_set = set(paths)
    unsupported = sorted(path_set - _ALLOWED_INFERENCE_FILES)
    if unsupported:
        _fail(
            "training artifact.files",
            f"contains unsupported inference files {unsupported[:10]}",
        )
    missing = sorted(_REQUIRED_INFERENCE_FILES - path_set)
    if missing:
        _fail(
            "training artifact.files", f"is missing required inference files {missing}"
        )
    if ("vocab.json" in path_set) != ("merges.txt" in path_set):
        _fail(
            "training artifact.files",
            "vocab.json and merges.txt must be present together",
        )


def _validate_file_index(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ARTIFACT_FILES:
        _fail(
            "training artifact.files",
            f"must contain between 1 and {MAX_ARTIFACT_FILES} entries",
        )
    files: list[dict[str, Any]] = []
    paths: list[str] = []
    total_bytes = 0
    for index, raw_entry in enumerate(value):
        field = f"training artifact.files[{index}]"
        entry = _exact_keys(raw_entry, {"path", "sha256", "sizeBytes"}, field)
        relative = _portable_relative_path(entry["path"], f"{field}.path")
        expected_hash = _sha256(entry["sha256"], f"{field}.sha256")
        size = _integer(
            entry["sizeBytes"], f"{field}.sizeBytes", 0, MAX_ARTIFACT_FILE_BYTES
        )
        file_size_limit = _INFERENCE_FILE_SIZE_LIMITS.get(relative)
        if file_size_limit is not None and size > file_size_limit:
            _fail(f"{field}.sizeBytes", "exceeds the limit for this inference file")
        total_bytes += size
        if total_bytes > MAX_ARTIFACT_TOTAL_BYTES:
            _fail(
                "training artifact.files",
                f"exceeds the {MAX_ARTIFACT_TOTAL_BYTES}-byte aggregate limit",
            )
        files.append({"path": relative, "sha256": expected_hash, "sizeBytes": size})
        paths.append(relative)
    if paths != sorted(paths):
        _fail("training artifact.files", "must be sorted by ordinal relative path")
    if len(paths) != len(set(paths)):
        _fail("training artifact.files", "must not contain duplicate paths")
    _validate_inference_file_set(paths)
    return files


def _validate_base_model(value: Any) -> dict[str, Any]:
    model = _exact_keys(
        value, {"candidateId", "modelId", "revision"}, "training artifact.baseModel"
    )
    _string(
        model["candidateId"], "training artifact.baseModel.candidateId", max_length=200
    )
    _string(model["modelId"], "training artifact.baseModel.modelId", max_length=500)
    _revision(model["revision"], "training artifact.baseModel.revision")
    return model


def _validate_dataset_snapshot(value: Any) -> dict[str, Any]:
    snapshot = _exact_keys(
        value,
        {"path", "sha256", "recordCount"},
        "training artifact.datasetSnapshot",
    )
    if snapshot["path"] != DATASET_BUNDLE_PATH:
        _fail(
            "training artifact.datasetSnapshot.path", f"must be {DATASET_BUNDLE_PATH!r}"
        )
    _sha256(snapshot["sha256"], "training artifact.datasetSnapshot.sha256")
    _integer(
        snapshot["recordCount"],
        "training artifact.datasetSnapshot.recordCount",
        1,
        MAX_SFT_RECORDS,
    )
    return snapshot


def _validate_optional_string(value: Any, field: str, *, max_length: int) -> None:
    if value is not None:
        _string(value, field, max_length=max_length)


def _validate_environment(value: Any) -> dict[str, Any]:
    environment = _exact_keys(
        value,
        {"python", "platform", "dependencyVersions", "computeDtype", "gpu"},
        "training artifact.environment",
    )
    python = _exact_keys(
        environment["python"],
        {"version", "implementation", "executable"},
        "training artifact.environment.python",
    )
    _string(
        python["version"],
        "training artifact.environment.python.version",
        max_length=100,
    )
    _string(
        python["implementation"],
        "training artifact.environment.python.implementation",
        max_length=100,
    )
    _string(
        python["executable"],
        "training artifact.environment.python.executable",
        max_length=4_096,
    )

    platform_value = _exact_keys(
        environment["platform"],
        {"description", "system", "release", "machine"},
        "training artifact.environment.platform",
    )
    for name in ("description", "system", "release", "machine"):
        _string(
            platform_value[name],
            f"training artifact.environment.platform.{name}",
            max_length=1_000,
        )

    versions = _exact_keys(
        environment["dependencyVersions"],
        set(TRAINING_DEPENDENCIES),
        "training artifact.environment.dependencyVersions",
    )
    for name in TRAINING_DEPENDENCIES:
        _string(
            versions[name],
            f"training artifact.environment.dependencyVersions.{name}",
            max_length=200,
        )
    if environment["computeDtype"] not in {"bfloat16", "float16"}:
        _fail(
            "training artifact.environment.computeDtype",
            "must be 'bfloat16' or 'float16'",
        )

    gpu = _exact_keys(
        environment["gpu"],
        {
            "cudaAvailable",
            "deviceCount",
            "largestGpuGiB",
            "requiredGpuGiB",
            "memoryGateWaivedForSmoke",
            "devices",
            "cudaRuntimeVersion",
            "productionEligible",
        },
        "training artifact.environment.gpu",
    )
    if gpu["cudaAvailable"] is not True:
        _fail("training artifact.environment.gpu.cudaAvailable", "must be true")
    device_count = _integer(
        gpu["deviceCount"],
        "training artifact.environment.gpu.deviceCount",
        1,
        256,
    )
    largest = _number(
        gpu["largestGpuGiB"],
        "training artifact.environment.gpu.largestGpuGiB",
        0,
        1_000_000,
        minimum_open=True,
    )
    _number(
        gpu["requiredGpuGiB"],
        "training artifact.environment.gpu.requiredGpuGiB",
        0,
        1_000_000,
        minimum_open=True,
    )
    if not isinstance(gpu["memoryGateWaivedForSmoke"], bool):
        _fail(
            "training artifact.environment.gpu.memoryGateWaivedForSmoke",
            "must be a boolean",
        )
    if gpu["productionEligible"] is not False:
        _fail("training artifact.environment.gpu.productionEligible", "must be false")
    _validate_optional_string(
        gpu["cudaRuntimeVersion"],
        "training artifact.environment.gpu.cudaRuntimeVersion",
        max_length=200,
    )
    devices = gpu["devices"]
    if not isinstance(devices, list) or len(devices) != device_count:
        _fail("training artifact.environment.gpu.devices", "must match deviceCount")
    sizes: list[float] = []
    for index, raw_device in enumerate(devices):
        field = f"training artifact.environment.gpu.devices[{index}]"
        device = _exact_keys(
            raw_device,
            {
                "index",
                "name",
                "totalMemoryGiB",
                "computeCapability",
                "multiProcessorCount",
            },
            field,
        )
        if _integer(device["index"], f"{field}.index", 0, 255) != index:
            _fail(f"{field}.index", "must match its ordinal device position")
        _string(device["name"], f"{field}.name", max_length=500)
        sizes.append(
            _number(
                device["totalMemoryGiB"],
                f"{field}.totalMemoryGiB",
                0,
                1_000_000,
                minimum_open=True,
            )
        )
        capability = device["computeCapability"]
        if capability is not None and (
            not isinstance(capability, str)
            or not _COMPUTE_CAPABILITY_RE.fullmatch(capability)
        ):
            _fail(f"{field}.computeCapability", "must be null or a major.minor value")
        processors = device["multiProcessorCount"]
        if processors is not None:
            _integer(processors, f"{field}.multiProcessorCount", 1, 1_000_000)
    if largest != max(sizes):
        _fail(
            "training artifact.environment.gpu.largestGpuGiB",
            "must match the largest device",
        )
    return environment


def _validate_safetensors(path: Path) -> None:
    size = path.stat().st_size
    if size < 10:
        _fail("training artifact.adapter_model.safetensors", "is too short")
    with path.open("rb") as stream:
        header_length = int.from_bytes(stream.read(8), byteorder="little", signed=False)
        if header_length < 2 or header_length > min(
            _MAX_SAFETENSORS_HEADER_BYTES, size - 8
        ):
            _fail(
                "training artifact.adapter_model.safetensors",
                "has an invalid header length",
            )
        header_raw = stream.read(header_length)
    try:
        header_text = header_raw.decode("utf-8", errors="strict")
        header = json.loads(
            header_text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(
            "training artifact.adapter_model.safetensors: has an invalid JSON header"
        ) from error
    if not isinstance(header, dict):
        _fail("training artifact.adapter_model.safetensors", "header must be an object")
    data_size = size - 8 - header_length
    ranges: list[tuple[int, int]] = []
    tensor_count = 0
    for name, raw_tensor in header.items():
        field = f"training artifact.adapter_model.safetensors tensor {name!r}"
        if name == "__metadata__":
            if not isinstance(raw_tensor, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in raw_tensor.items()
            ):
                _fail(field, "metadata must contain only string keys and values")
            continue
        if not isinstance(name, str) or not _TENSOR_NAME_RE.fullmatch(name):
            _fail(f"{field}.name", "contains unsupported characters")
        tensor = _exact_keys(raw_tensor, {"dtype", "shape", "data_offsets"}, field)
        dtype_size = _SAFETENSORS_DTYPES.get(tensor["dtype"])
        if dtype_size is None:
            _fail(f"{field}.dtype", "must be F16, BF16, or F32")
        shape = tensor["shape"]
        if not isinstance(shape, list) or len(shape) > 8:
            _fail(f"{field}.shape", "must be an array with at most 8 dimensions")
        element_count = 1
        for index, dimension in enumerate(shape):
            element_count *= _integer(
                dimension, f"{field}.shape[{index}]", 0, 10_000_000_000
            )
            if element_count > MAX_ARTIFACT_FILE_BYTES:
                _fail(f"{field}.shape", "declares an excessive tensor size")
        offsets = tensor["data_offsets"]
        if not isinstance(offsets, list) or len(offsets) != 2:
            _fail(f"{field}.data_offsets", "must contain a start and end offset")
        start = _integer(offsets[0], f"{field}.data_offsets[0]", 0, data_size)
        end = _integer(offsets[1], f"{field}.data_offsets[1]", start, data_size)
        if end - start != element_count * dtype_size:
            _fail(f"{field}.data_offsets", "does not match the tensor dtype and shape")
        ranges.append((start, end))
        tensor_count += 1
    if tensor_count < 1:
        _fail(
            "training artifact.adapter_model.safetensors",
            "must contain at least one tensor",
        )
    cursor = 0
    for start, end in sorted(ranges):
        if start != cursor:
            _fail(
                "training artifact.adapter_model.safetensors",
                "tensor data ranges must be contiguous",
            )
        cursor = end
    if cursor != data_size:
        _fail(
            "training artifact.adapter_model.safetensors",
            "tensor ranges do not cover the data section",
        )


def _validate_artifact_payloads(root: Path, artifact: Mapping[str, Any]) -> None:
    for entry in artifact["files"]:
        relative = entry["path"]
        path = root / relative
        if relative.endswith(".json"):
            document = load_json_document(
                path, max_bytes=_INFERENCE_FILE_SIZE_LIMITS[relative]
            )
            if relative == "adapter_config.json":
                if (
                    document.get("base_model_name_or_path")
                    != artifact["baseModel"]["modelId"]
                ):
                    _fail(
                        "training artifact.adapter_config.json.base_model_name_or_path",
                        "does not match the sealed base model",
                    )
        elif relative == "adapter_model.safetensors":
            _validate_safetensors(path)


def training_artifact_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload["artifactSha256"] = _ZERO_SHA256
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def training_artifact_core_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    if payload.get("schemaVersion") != TRAINING_ARTIFACT_V2_SCHEMA_VERSION:
        _fail(
            "training artifact.schemaVersion",
            "must be v2 to derive signed trainer provenance",
        )
    payload["artifactSha256"] = _ZERO_SHA256
    payload["trainerProvenance"] = None
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def verify_training_artifact_trainer_provenance(
    artifact: Mapping[str, Any],
    *,
    trust: TrainerProvenanceTrust,
    now: datetime | None = None,
) -> VerifiedTrainerProvenance:
    if artifact.get("schemaVersion") != TRAINING_ARTIFACT_V2_SCHEMA_VERSION:
        _fail("training artifact.schemaVersion", "trainer provenance requires v2")
    if artifact.get("mode") != "unpromoted-candidate":
        _fail("training artifact.mode", "trainer provenance requires a candidate")
    from .trainer_provenance import verify_trainer_provenance_envelope

    return verify_trainer_provenance_envelope(
        artifact.get("trainerProvenance"),
        trust=trust,
        expected_artifact_core_sha256=training_artifact_core_sha256(artifact),
        expected_file_tree_sha256=artifact.get("fileTreeSha256"),
        expected_manifest_sha256=artifact.get("manifestSha256"),
        expected_run_id=artifact.get("runId"),
        expected_recorded_at_utc=artifact.get("recordedAtUtc"),
        expected_data_release=artifact.get("dataRelease"),
        expected_base_model=artifact.get("baseModel"),
        expected_dataset_snapshot=artifact.get("datasetSnapshot"),
        expected_environment_sha256=hashlib.sha256(
            canonical_json_bytes(artifact.get("environment"))
        ).hexdigest(),
        now=now,
    )


def _validate_training_artifact_document(
    value: Any,
    *,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_provenance_now: datetime | None = None,
    _allow_unsealed_core: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("training artifact", "must be an object")
    base_fields = {
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
    }
    schema_version = value.get("schemaVersion")
    if schema_version == TRAINING_ARTIFACT_V1_SCHEMA_VERSION:
        expected_fields = base_fields
    elif schema_version == TRAINING_ARTIFACT_V2_SCHEMA_VERSION:
        expected_fields = base_fields | {"trainerProvenance"}
    else:
        _fail(
            "training artifact.schemaVersion",
            f"must be {TRAINING_ARTIFACT_V1_SCHEMA_VERSION!r} or "
            f"{TRAINING_ARTIFACT_V2_SCHEMA_VERSION!r}",
        )
    artifact = _exact_keys(
        value,
        expected_fields,
        "training artifact",
    )
    if _allow_unsealed_core and schema_version != TRAINING_ARTIFACT_V2_SCHEMA_VERSION:
        _fail(
            "training artifact.schemaVersion",
            "an unsealed artifact core must be v2",
        )
    artifact_hash = _sha256(
        artifact["artifactSha256"], "training artifact.artifactSha256"
    )
    tree_hash = _sha256(artifact["fileTreeSha256"], "training artifact.fileTreeSha256")
    _parse_datetime(
        artifact["recordedAtUtc"], "training artifact.recordedAtUtc", require_utc_z=True
    )
    run_id = _string(artifact["runId"], "training artifact.runId", max_length=100)
    if not _RUN_ID_RE.fullmatch(run_id):
        _fail("training artifact.runId", "must be a canonical vqrun identifier")
    if artifact["mode"] not in {
        "smoke",
        "unpromoted-research",
        "unpromoted-candidate",
    }:
        _fail(
            "training artifact.mode",
            "must be 'smoke', 'unpromoted-research', or 'unpromoted-candidate'",
        )
    if artifact["productionEligible"] is not False:
        _fail("training artifact.productionEligible", "must be false")
    expected_reason = {
        "smoke": "Smoke mode cannot produce a production model.",
        "unpromoted-research": "Research-only training cannot produce promotion-eligible evidence.",
        "unpromoted-candidate": "Training alone does not satisfy evaluation, promotion, signing, or deployment gates.",
    }[artifact["mode"]]
    if artifact["reason"] != expected_reason:
        _fail("training artifact.reason", "does not match the artifact mode")
    _sha256(artifact["manifestSha256"], "training artifact.manifestSha256")
    data_release = _validate_data_release_identity(
        artifact["dataRelease"], "training artifact.dataRelease"
    )
    if artifact["mode"] == "unpromoted-candidate" and data_release is None:
        _fail(
            "training artifact.dataRelease",
            "is required for an unpromoted candidate",
        )
    if artifact["mode"] == "unpromoted-research" and data_release is not None:
        _fail(
            "training artifact.dataRelease",
            "must be null for an unpromoted research artifact",
        )
    _validate_base_model(artifact["baseModel"])
    _validate_dataset_snapshot(artifact["datasetSnapshot"])
    files = _validate_file_index(artifact["files"])
    expected_tree_hash = hashlib.sha256(
        canonical_json_bytes(
            {"schemaVersion": ARTIFACT_FILE_TREE_SCHEMA_VERSION, "files": files}
        )
    ).hexdigest()
    if tree_hash != expected_tree_hash:
        _fail(
            "training artifact.fileTreeSha256",
            "does not match the canonical file index",
        )
    _validate_environment(artifact["environment"])
    if (
        artifact["mode"] != "smoke"
        and artifact["environment"]["gpu"]["memoryGateWaivedForSmoke"]
    ):
        _fail(
            "training artifact.environment.gpu.memoryGateWaivedForSmoke",
            "may be true only for smoke artifacts",
        )
    if _allow_unsealed_core:
        if artifact_hash != _ZERO_SHA256:
            _fail(
                "training artifact.artifactSha256",
                "must be zero in an unsealed artifact core",
            )
    elif artifact_hash != training_artifact_sha256(artifact):
        _fail(
            "training artifact.artifactSha256", "does not match the canonical metadata"
        )
    is_candidate = artifact["mode"] == "unpromoted-candidate"
    if _allow_unsealed_core:
        if artifact["trainerProvenance"] is not None:
            _fail(
                "training artifact.trainerProvenance",
                "must be null in an unsealed artifact core",
            )
        if trainer_provenance_trust is not None or trainer_provenance_now is not None:
            _fail(
                "trainer provenance trust",
                "cannot be supplied while validating an unsealed artifact core",
            )
        return artifact
    if artifact["schemaVersion"] == TRAINING_ARTIFACT_V1_SCHEMA_VERSION:
        if is_candidate and (
            trainer_provenance_trust is not None or trainer_provenance_now is not None
        ):
            _fail(
                "training artifact.schemaVersion",
                "legacy v1 candidate artifacts have no authenticated trainer provenance",
            )
        if not is_candidate and (
            trainer_provenance_trust is not None or trainer_provenance_now is not None
        ):
            _fail(
                "trainer provenance trust",
                "cannot be supplied for a legacy or non-candidate artifact",
            )
        return artifact

    provenance = artifact["trainerProvenance"]
    if not is_candidate:
        if provenance is not None:
            _fail(
                "training artifact.trainerProvenance",
                "must be null for smoke and research artifacts",
            )
        if trainer_provenance_trust is not None or trainer_provenance_now is not None:
            _fail(
                "trainer provenance trust",
                "cannot be supplied for a non-candidate artifact",
            )
        return artifact
    if trainer_provenance_trust is None:
        _fail(
            "trainer provenance trust",
            "externally pinned trust is required for a candidate artifact",
        )
    verify_training_artifact_trainer_provenance(
        artifact,
        trust=trainer_provenance_trust,
        now=trainer_provenance_now,
    )
    return artifact


def _validate_training_artifact_release_authority_arguments(
    metadata_document: Mapping[str, Any],
    *,
    data_release_path: str | os.PathLike[str] | None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None,
    review_receipt_now: datetime | None,
) -> None:
    release_values = (
        data_release_path,
        review_receipt_trust,
        evaluation_authoring_approval_trust,
    )
    if any(value is not None for value in release_values) and not all(
        value is not None for value in release_values
    ):
        _fail(
            "training artifact release authority",
            "the release path, review-receipt trust, and evaluation-authoring approval trust are required together",
        )
    if review_receipt_now is not None and data_release_path is None:
        _fail(
            "training artifact release validation time",
            "cannot be supplied without the complete release authority",
        )


def _validate_training_artifact_release_binding(
    metadata_document: Mapping[str, Any],
    *,
    data_release_path: str | os.PathLike[str] | None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None,
    review_receipt_now: datetime | None,
) -> None:
    bound_release = metadata_document.get("dataRelease")
    if (
        metadata_document.get("mode") != "unpromoted-candidate"
        and bound_release is None
    ):
        return
    if data_release_path is None:
        _fail(
            "training artifact release",
            "a fully validated release path is required to seal a candidate",
        )
    if review_receipt_trust is None:
        _fail(
            "training artifact review-receipt trust",
            "externally supplied trust is required for a bound release",
        )
    if (
        evaluation_authoring_approval_trust is None
    ):  # pragma: no cover - guarded by the authority argument validator
        _fail("training artifact release authority", "authority is unavailable")
    dataset_snapshot = metadata_document.get("datasetSnapshot")
    if not isinstance(dataset_snapshot, dict):
        _fail("training artifact.datasetSnapshot", "must be an object")
    from .release import validate_training_release_binding

    _, release_identity = validate_training_release_binding(
        data_release_path,
        dataset_sha256=dataset_snapshot.get("sha256"),
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        now=review_receipt_now,
    )
    if bound_release != release_identity:
        _fail(
            "training artifact.dataRelease",
            "does not match the fully validated training release",
        )


def _unsealed_training_artifact_metadata_path(root: Path) -> Path:
    metadata_path = root / ARTIFACT_METADATA_NAME
    _reject_reparse_components(
        metadata_path, "training artifact metadata", allow_missing_suffix=True
    )
    if os.path.lexists(metadata_path):
        _fail(
            "training artifact metadata",
            "already exists; artifacts are sealed only once",
        )
    return metadata_path


def _build_training_artifact_core(
    root: Path, metadata_document: Mapping[str, Any]
) -> dict[str, Any]:
    _unsealed_training_artifact_metadata_path(root)
    files, tree_sha256 = build_artifact_file_index(root)
    artifact_core = {
        **metadata_document,
        "schemaVersion": TRAINING_ARTIFACT_SCHEMA_VERSION,
        "artifactSha256": _ZERO_SHA256,
        "fileTreeSha256": tree_sha256,
        "files": files,
        "trainerProvenance": None,
    }
    _validate_training_artifact_document(
        artifact_core,
        _allow_unsealed_core=True,
    )
    _validate_artifact_payloads(root, artifact_core)
    return artifact_core


def prepare_training_artifact_core(
    path: str | os.PathLike[str],
    metadata: Mapping[str, Any],
    *,
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
) -> dict[str, Any]:
    root = _existing_directory(Path(path), "training artifact")
    metadata_document = copy.deepcopy(dict(metadata))
    _validate_training_artifact_release_authority_arguments(
        metadata_document,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        review_receipt_now=review_receipt_now,
    )
    _validate_training_artifact_release_binding(
        metadata_document,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        review_receipt_now=review_receipt_now,
    )
    return _build_training_artifact_core(root, metadata_document)


def finalize_training_artifact_core(
    path: str | os.PathLike[str],
    artifact_core: Mapping[str, Any],
    trainer_provenance: Mapping[str, Any] | None,
    *,
    trainer_provenance_trust: TrainerProvenanceTrust | None,
    trainer_provenance_now: datetime | None = None,
) -> dict[str, Any]:
    root = _existing_directory(Path(path), "training artifact")
    core_document = _validate_training_artifact_document(
        copy.deepcopy(dict(artifact_core)),
        _allow_unsealed_core=True,
    )
    provenance_document = copy.deepcopy(trainer_provenance)
    computed_fields = {
        "schemaVersion",
        "artifactSha256",
        "fileTreeSha256",
        "files",
        "trainerProvenance",
    }
    metadata_document = {
        name: value
        for name, value in core_document.items()
        if name not in computed_fields
    }
    current_core = _build_training_artifact_core(root, metadata_document)
    if core_document != current_core:
        _fail(
            "training artifact core",
            "does not exactly match the current artifact files and metadata",
        )
    artifact = {
        **current_core,
        "trainerProvenance": provenance_document,
    }
    artifact["artifactSha256"] = training_artifact_sha256(artifact)
    _validate_training_artifact_document(
        artifact,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    _validate_artifact_payloads(root, artifact)
    metadata_path = _unsealed_training_artifact_metadata_path(root)
    _write_json_exclusive(metadata_path, artifact)
    return validate_training_artifact(
        root,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )


def seal_training_artifact(
    path: str | os.PathLike[str],
    metadata: Mapping[str, Any],
    *,
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_private_key_path: str | os.PathLike[str] | None = None,
    trainer_private_key_password: bytes | None = None,
    trainer_id: str | None = None,
    trainer_issued_at_utc: str | None = None,
    trainer_not_before_utc: str | None = None,
    trainer_expires_at_utc: str | None = None,
    trainer_provenance_now: datetime | None = None,
) -> dict[str, Any]:
    root = _existing_directory(Path(path), "training artifact")
    metadata_document = copy.deepcopy(dict(metadata))
    _validate_training_artifact_release_authority_arguments(
        metadata_document,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        review_receipt_now=review_receipt_now,
    )
    trainer_required_values = (
        trainer_provenance_trust,
        trainer_private_key_path,
        trainer_id,
        trainer_expires_at_utc,
    )
    trainer_values = trainer_required_values + (
        trainer_issued_at_utc,
        trainer_not_before_utc,
    )
    has_trainer_provenance = any(value is not None for value in trainer_values)
    if trainer_private_key_password is not None and trainer_private_key_path is None:
        _fail(
            "training artifact trainer private-key password",
            "cannot be supplied without the trainer private key",
        )
    if has_trainer_provenance and not all(
        value is not None for value in trainer_required_values
    ):
        _fail(
            "training artifact trainer provenance",
            "trust, private key, trainer ID, and expiry are required together",
        )
    if (trainer_issued_at_utc is None) != (trainer_not_before_utc is None):
        _fail(
            "training artifact trainer provenance",
            "explicit issue and not-before times must be supplied together",
        )
    if trainer_provenance_now is not None and not has_trainer_provenance:
        _fail(
            "training artifact trainer provenance validation time",
            "cannot be supplied without the complete trainer signing authority",
        )
    is_candidate = metadata_document.get("mode") == "unpromoted-candidate"
    if is_candidate and not has_trainer_provenance:
        _fail(
            "training artifact trainer provenance",
            "a separately trusted trainer signature is required to seal a candidate",
        )
    if not is_candidate and has_trainer_provenance:
        _fail(
            "training artifact trainer provenance",
            "cannot be supplied for a smoke or research artifact",
        )
    _validate_training_artifact_release_binding(
        metadata_document,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        review_receipt_now=review_receipt_now,
    )
    artifact_core = _build_training_artifact_core(root, metadata_document)
    trainer_provenance: Mapping[str, Any] | None = None
    if is_candidate:
        if (
            trainer_provenance_trust is None
            or trainer_private_key_path is None
            or trainer_id is None
            or trainer_expires_at_utc is None
        ):  # pragma: no cover - guarded above
            _fail("training artifact trainer provenance", "authority is unavailable")
        from .trainer_provenance import create_trainer_provenance

        resolved_issued_at_utc = trainer_issued_at_utc
        resolved_not_before_utc = trainer_not_before_utc
        if resolved_issued_at_utc is None and resolved_not_before_utc is None:
            signing_time = trainer_provenance_now or datetime.now(timezone.utc)
            if not isinstance(signing_time, datetime) or signing_time.tzinfo is None:
                _fail(
                    "training artifact trainer provenance signing time",
                    "must be timezone-aware",
                )
            signing_second = signing_time.astimezone(timezone.utc).replace(
                microsecond=0
            )
            resolved_issued_at_utc = signing_second.strftime("%Y-%m-%dT%H:%M:%SZ")
            resolved_not_before_utc = resolved_issued_at_utc

        verified_provenance = create_trainer_provenance(
            private_key_path=trainer_private_key_path,
            private_key_password=trainer_private_key_password,
            trust=trainer_provenance_trust,
            artifact_core_sha256=training_artifact_core_sha256(artifact_core),
            file_tree_sha256=artifact_core["fileTreeSha256"],
            manifest_sha256=artifact_core["manifestSha256"],
            run_id=artifact_core["runId"],
            recorded_at_utc=artifact_core["recordedAtUtc"],
            data_release=artifact_core["dataRelease"],
            base_model=artifact_core["baseModel"],
            dataset_snapshot=artifact_core["datasetSnapshot"],
            environment_sha256=hashlib.sha256(
                canonical_json_bytes(artifact_core["environment"])
            ).hexdigest(),
            issued_at_utc=resolved_issued_at_utc,
            not_before_utc=resolved_not_before_utc,
            expires_at_utc=trainer_expires_at_utc,
            trainer_id=trainer_id,
            now=trainer_provenance_now,
        )
        trainer_provenance = verified_provenance.envelope
    return finalize_training_artifact_core(
        root,
        artifact_core,
        trainer_provenance,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )


def validate_training_artifact(
    path: str | os.PathLike[str],
    *,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_provenance_now: datetime | None = None,
) -> dict[str, Any]:
    root = _existing_directory(Path(path), "training artifact")
    artifact = _validate_training_artifact_document(
        load_json_document(root / ARTIFACT_METADATA_NAME),
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    _validate_artifact_payloads(root, artifact)
    actual_files, actual_tree_hash = build_artifact_file_index(root)
    if artifact["files"] != actual_files:
        _fail(
            "training artifact.files",
            "does not exactly match the current artifact file tree",
        )
    if artifact["fileTreeSha256"] != actual_tree_hash:
        _fail(
            "training artifact.fileTreeSha256",
            "does not match the current artifact file tree",
        )
    return artifact
