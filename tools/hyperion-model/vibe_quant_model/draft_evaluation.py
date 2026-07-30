from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

from .core import (
    DOMAINS,
    TASK_KINDS,
    _exact_keys,
    _fail,
    _integer,
    _parse_datetime,
    _pinned_revision_label,
    _read_file_bounded,
    _regular_file,
    _reject_reparse_components,
    canonical_json_bytes,
    load_json_document,
    resolve_bound_path,
)
from .evaluation import (
    CRITICALITIES,
    EVALUATION_TASK_SCHEMA_VERSION,
    MAX_EVALUATION_RECORDS,
    MAX_OUTPUT_TOKENS,
    MAX_REQUIRED_CHECKS,
    EvaluationTaskSet,
    _validate_eval_messages,
    _validate_identifier,
    _write_bytes_atomic_no_clobber,
    evaluation_prompt_sha256,
    evaluation_task_sha256,
    validate_evaluation_tasks,
)


DRAFT_CALIBRATION_MANIFEST_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.draft-calibration-manifest/v1"
)
MAX_DRAFT_ASSET_BYTES = 16_000_000


def _asset_sha256(root: Path, value: Any, field: str) -> str:
    asset_path = resolve_bound_path(root, value, field)
    raw = _read_file_bounded(asset_path, field, MAX_DRAFT_ASSET_BYTES)
    return hashlib.sha256(raw).hexdigest()


def _domains(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(field, "must be a non-empty array without duplicates")
    if not all(isinstance(domain, str) and domain in DOMAINS for domain in value):
        _fail(field, "contains unsupported domain labels")
    if len(value) != len(set(value)):
        _fail(field, "must be a non-empty array without duplicates")
    return value


def _required_checks(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_REQUIRED_CHECKS:
        _fail(field, f"must contain 1 to {MAX_REQUIRED_CHECKS} checks")
    checks = [
        _validate_identifier(check, f"{field}[{index}]")
        for index, check in enumerate(value)
    ]
    if len(checks) != len(set(checks)):
        _fail(field, "must not contain duplicates")
    return checks


def _compile_task(value: Any, index: int, root: Path) -> dict[str, Any]:
    field = f"draft calibration manifest.tasks[{index}]"
    source = _exact_keys(
        value,
        {
            "taskId",
            "taskKind",
            "domains",
            "messages",
            "contextPack",
            "verifier",
            "contaminationGroup",
            "cutoffUtc",
            "criticality",
            "maxOutputTokens",
        },
        field,
    )
    task_id = _validate_identifier(source["taskId"], f"{field}.taskId")
    task_kind = source["taskKind"]
    if not isinstance(task_kind, str) or task_kind not in TASK_KINDS:
        _fail(f"{field}.taskKind", "is not a supported ExpertTaskKind")
    domains = _domains(source["domains"], f"{field}.domains")
    messages = _validate_eval_messages(source["messages"], f"{field}.messages")

    context_pack = _exact_keys(
        source["contextPack"], {"version", "path"}, f"{field}.contextPack"
    )
    context_version = _pinned_revision_label(
        context_pack["version"], f"{field}.contextPack.version"
    )
    context_sha256 = _asset_sha256(
        root, context_pack["path"], f"{field}.contextPack.path"
    )

    verifier = _exact_keys(
        source["verifier"],
        {"id", "path", "requiredChecks"},
        f"{field}.verifier",
    )
    verifier_id = _validate_identifier(verifier["id"], f"{field}.verifier.id")
    verifier_sha256 = _asset_sha256(root, verifier["path"], f"{field}.verifier.path")
    checks = _required_checks(
        verifier["requiredChecks"], f"{field}.verifier.requiredChecks"
    )

    contamination_group = _validate_identifier(
        source["contaminationGroup"], f"{field}.contaminationGroup"
    )
    cutoff_utc = source["cutoffUtc"]
    _parse_datetime(cutoff_utc, f"{field}.cutoffUtc", require_utc_z=True)
    criticality = source["criticality"]
    if not isinstance(criticality, str) or criticality not in CRITICALITIES:
        _fail(f"{field}.criticality", "must be standard or critical")
    max_output_tokens = _integer(
        source["maxOutputTokens"],
        f"{field}.maxOutputTokens",
        1,
        MAX_OUTPUT_TOKENS,
    )

    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": task_id,
        "taskSha256": "0" * 64,
        "split": "calibration",
        "taskKind": task_kind,
        "domains": domains,
        "messages": messages,
        "promptSha256": evaluation_prompt_sha256(messages),
        "contextPack": {"version": context_version, "sha256": context_sha256},
        "verifier": {
            "id": verifier_id,
            "sha256": verifier_sha256,
            "requiredChecks": checks,
        },
        "contaminationGroup": contamination_group,
        "cutoffUtc": cutoff_utc,
        "criticality": criticality,
        "maxOutputTokens": max_output_tokens,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    return task


def _validate_generated_bytes(raw: bytes, parent: Path) -> None:
    staged: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=".draft-calibration.", suffix=".jsonl", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        validate_evaluation_tasks(staged)
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass


def compile_draft_calibration_tasks(
    manifest_path: str | os.PathLike[str], output_path: str | os.PathLike[str]
) -> EvaluationTaskSet:
    manifest_file = _regular_file(Path(manifest_path), "draft calibration manifest")
    manifest = _exact_keys(
        load_json_document(manifest_file),
        {"schemaVersion", "split", "tasks"},
        "draft calibration manifest",
    )
    if manifest["schemaVersion"] != DRAFT_CALIBRATION_MANIFEST_SCHEMA_VERSION:
        _fail(
            "draft calibration manifest.schemaVersion",
            f"must be {DRAFT_CALIBRATION_MANIFEST_SCHEMA_VERSION!r}",
        )
    if manifest["split"] != "calibration":
        _fail(
            "draft calibration manifest.split",
            "must be calibration; draft compilation never creates sealed tasks",
        )
    source_tasks = manifest["tasks"]
    if (
        not isinstance(source_tasks, list)
        or not 1 <= len(source_tasks) <= MAX_EVALUATION_RECORDS
    ):
        _fail(
            "draft calibration manifest.tasks",
            f"must contain 1 to {MAX_EVALUATION_RECORDS} tasks",
        )
    tasks = [
        _compile_task(task, index, manifest_file.parent)
        for index, task in enumerate(source_tasks)
    ]
    raw = b"".join(canonical_json_bytes(task) + b"\n" for task in tasks)

    destination = _reject_reparse_components(
        Path(output_path), "draft calibration task output", allow_missing_suffix=True
    )
    parent = _reject_reparse_components(
        destination.parent, "draft calibration task output parent"
    )
    if not parent.is_dir():
        _fail("draft calibration task output parent", "must be an existing directory")
    _validate_generated_bytes(raw, parent)
    _write_bytes_atomic_no_clobber(destination, raw, "draft calibration task output")
    return validate_evaluation_tasks(destination)
