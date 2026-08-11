from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .core import (
    MAX_AGGREGATE_MESSAGE_CHARACTERS,
    MAX_JSON_BYTES,
    MAX_MESSAGE_CHARACTERS,
    MAX_MESSAGE_COUNT,
    SOURCE_SCHEMA_VERSION,
    ValidationError,
    _exact_keys,
    _exclusive_destination_lock,
    _fail,
    _integer,
    _length_prefixed_sha256,
    _read_file_bounded,
    _reject_constant,
    _reject_reparse_components,
    _sha256,
    _string,
    _unique_pairs,
    _validate_messages,
    canonical_json_bytes,
    expert_conversation_sha256,
    resolve_bound_path,
)
from .evaluation import MAX_EVALUATION_BYTES, validate_evaluation_tasks
from .release import (
    MAX_AGGREGATE_SOURCE_CHARACTERS,
    MAX_CORPUS_BYTES,
    MAX_CORPUS_LINE_BYTES,
    MAX_EVIDENCE_CHARACTERS,
    MAX_EVIDENCE_ITEMS,
    MAX_SOURCE_CHARACTERS,
    MAX_SOURCE_COUNT,
    _verification_evidence_sha256,
)
from .teacher_generation import (
    _load_json_bytes,
    _utc_second,
    _validate_identifier,
    validate_teacher_candidates,
)


TEACHER_SELECTION_MANIFEST_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-selection-manifest/v1"
)
TEACHER_OVERLAP_DENY_SET_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-overlap-deny-set/v1"
)
TEACHER_ADMISSION_SCHEMA_VERSION = "daxalgo.hyperion.teacher-admission/v1"
TEACHER_MATERIALIZATION_RECORD_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-record/v1"
)
TEACHER_MATERIALIZATION_SUMMARY_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-materialization-summary/v1"
)
TEACHER_SELECTION_SUMMARY_SCHEMA_VERSION = (
    "daxalgo.hyperion.teacher-selection-summary/v1"
)

MATERIALIZED_DATASET_PATH = "expert-dataset.draft.jsonl"
MATERIALIZATION_RECORD_PATH = "teacher-materialization-record.json"
SNAPSHOT_ROOT = "inputs/snapshot"
SELECTION_SNAPSHOT_PATH = f"{SNAPSHOT_ROOT}/selection-manifest.json"
MAX_SELECTIONS = 10_000
MAX_DENY_ENTRIES = 10_000
MAX_DENY_SET_BYTES = 16_000_000
MAX_MATERIALIZATION_RECORD_BYTES = 32_000_000

_LOCKED_RIGHTS = {
    "mayStore": True,
    "mayEvaluate": True,
    "mayTrain": False,
    "mayUploadToProvider": False,
    "mayRedistribute": False,
}

_OUTPUT_POLICY = {
    "schemaVersion": SOURCE_SCHEMA_VERSION,
    "split": "development",
    "lineageOrigin": "OpenWeightTeacher",
    "reviewStatus": "draft",
    "verified": False,
    "verifiedAtUtc": None,
    "compileSucceeded": False,
    "testsPassed": False,
    "useForTraining": False,
    "rights": _LOCKED_RIGHTS,
    "sourceRights": _LOCKED_RIGHTS,
}


@dataclass(frozen=True)
class TeacherSelection:
    manifest_path: Path
    manifest_sha256: str
    document: Mapping[str, Any]
    candidates: tuple[dict[str, Any], ...]
    candidate_set_sha256: str
    deny_set: Mapping[str, Any]
    deny_set_sha256: str
    admissions: tuple[dict[str, Any], ...]
    rows: tuple[dict[str, Any], ...]
    dataset_bytes: bytes
    materialization_record: Mapping[str, Any]
    materialization_record_bytes: bytes
    snapshots: Mapping[str, bytes]

    def as_dict(self) -> dict[str, Any]:
        selection = self.document["selection"]
        return {
            "schemaVersion": TEACHER_SELECTION_SUMMARY_SCHEMA_VERSION,
            "selectionManifestSha256": self.manifest_sha256,
            "candidateSetSha256": self.candidate_set_sha256,
            "batchId": self.candidates[0]["batchId"],
            "overlapDenySetSha256": self.deny_set_sha256,
            "denySetId": self.deny_set["denySetId"],
            "selectedBy": selection["selectedBy"],
            "selectedAtUtc": selection["selectedAtUtc"],
            "recordCount": len(self.rows),
            "reviewStatus": "draft",
            "eligibleForTraining": False,
        }


@dataclass(frozen=True)
class TeacherMaterializationPackage:
    path: Path
    dataset_path: Path
    materialization_record_path: Path
    materialization_id: str
    dataset_sha256: str
    record_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": TEACHER_MATERIALIZATION_SUMMARY_SCHEMA_VERSION,
            "materializationId": self.materialization_id,
            "packagePath": str(self.path),
            "datasetPath": str(self.dataset_path),
            "materializationRecordPath": str(self.materialization_record_path),
            "datasetSha256": self.dataset_sha256,
            "recordCount": self.record_count,
            "reviewStatus": "draft",
            "eligibleForTraining": False,
        }


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le", errors="strict")) // 2


def _require_utf16_limit(value: str, maximum: int, field: str) -> None:
    if _utf16_length(value) > maximum:
        _fail(field, f"must not exceed {maximum} UTF-16 characters")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def overlap_authored_messages_sha256(messages: list[dict[str, str]]) -> str:
    return expert_conversation_sha256(messages)


def overlap_authored_message_prefix_sha256s(
    messages: list[dict[str, str]],
) -> tuple[str, ...]:
    return tuple(
        overlap_authored_messages_sha256(messages[: index + 1])
        for index, message in enumerate(messages)
        if message["role"] == "user"
    )


def _normalize_overlap_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def overlap_normalized_final_user_sha256(messages: list[dict[str, str]]) -> str:
    fingerprints = overlap_normalized_user_turn_sha256s(messages)
    if not fingerprints:
        _fail("overlap messages", "must include a user prompt")
    return fingerprints[-1]


def overlap_normalized_user_turn_sha256(content: str) -> str:
    return _length_prefixed_sha256(
        "daxalgo-hyperion-overlap-normalized-user-turn/v1",
        [[_normalize_overlap_text(content)]],
    )


def overlap_normalized_user_turn_sha256s(
    messages: list[dict[str, str]],
) -> tuple[str, ...]:
    return tuple(
        overlap_normalized_user_turn_sha256(message["content"])
        for message in messages
        if message["role"] == "user"
    )


def overlap_contamination_group_sha256(contamination_group: str) -> str:
    return _length_prefixed_sha256(
        "daxalgo-hyperion-overlap-contamination-group/v1",
        [[contamination_group]],
    )


def teacher_overlap_scope_sha256(scope: Mapping[str, Any]) -> str:
    return _length_prefixed_sha256(
        "daxalgo-hyperion-teacher-overlap-scope/v1",
        [
            [
                split,
                scope[split]["fileSha256"],
                scope[split]["taskSetSha256"],
                str(scope[split]["recordCount"]),
            ]
            for split in ("calibration", "sealed")
        ],
    )


def _read_bound_input(
    root: Path,
    value: Any,
    field: str,
    *,
    max_bytes: int,
) -> tuple[Path, bytes, dict[str, str]]:
    binding = _exact_keys(value, {"path", "sha256"}, field)
    path = resolve_bound_path(root, binding["path"], f"{field}.path")
    raw = _read_file_bounded(path, f"{field}.path", max_bytes)
    expected = _sha256(binding["sha256"], f"{field}.sha256")
    if _sha256_bytes(raw) != expected:
        _fail(f"{field}.sha256", "does not match the bound file bytes")
    return path, raw, {"path": binding["path"], "sha256": expected}


def _add_snapshot(
    snapshots: dict[str, bytes], relative_path: str, raw: bytes, field: str
) -> None:
    snapshot_path = f"{SNAPSHOT_ROOT}/{relative_path}"
    existing = snapshots.get(snapshot_path)
    if existing is not None and existing != raw:
        _fail(field, f"collides with another snapshot at {snapshot_path!r}")
    snapshots[snapshot_path] = raw


def _build_input_snapshots(
    *,
    root: Path,
    selection_raw: bytes,
    bindings: Mapping[str, Mapping[str, str]],
    paths: Mapping[str, Path],
    raw_inputs: Mapping[str, bytes],
    candidate_records: tuple[dict[str, Any], ...],
    sample_count: int,
) -> dict[str, bytes]:
    snapshots = {SELECTION_SNAPSHOT_PATH: selection_raw}
    for name, binding in bindings.items():
        relative = binding["path"]
        if relative == "selection-manifest.json":
            _fail(
                f"teacher selection manifest.inputs.{name}.path",
                "uses the reserved materialization snapshot path",
            )
        _add_snapshot(
            snapshots,
            relative,
            raw_inputs[name],
            f"teacher selection manifest.inputs.{name}",
        )
    try:
        generation = json.loads(
            raw_inputs["generationManifest"].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:  # pragma: no cover
        raise ValidationError(
            "teacher generation manifest snapshot: must be strict UTF-8 JSON"
        ) from error
    for task_index, task in enumerate(generation["tasks"]):
        candidate = candidate_records[task_index * sample_count]
        for source_index, source in enumerate(task["sources"]):
            field = (
                f"teacher generation manifest.tasks[{task_index}]."
                f"sources[{source_index}].contentPath"
            )
            source_path = resolve_bound_path(
                paths["generationManifest"].parent,
                source["contentPath"],
                field,
            )
            try:
                relative = source_path.relative_to(root).as_posix()
            except ValueError as error:  # pragma: no cover
                raise ValidationError(
                    f"{field}: resolves outside the selection root"
                ) from error
            if relative == "selection-manifest.json":
                _fail(field, "uses the reserved materialization snapshot path")
            raw = _read_file_bounded(
                source_path,
                field,
                MAX_SOURCE_CHARACTERS,
            )
            expected_hash = candidate["sources"][source_index]["contentSha256"]
            if _sha256_bytes(raw) != expected_hash:
                _fail(field, "changed after candidate validation")
            _add_snapshot(snapshots, relative, raw, field)
    return dict(sorted(snapshots.items()))


def _string_list(
    value: Any,
    field: str,
    *,
    sha256: bool,
) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_DENY_ENTRIES:
        _fail(field, f"must contain 1 to {MAX_DENY_ENTRIES} entries")
    result: list[str] = []
    for index, item in enumerate(value):
        item_field = f"{field}[{index}]"
        result.append(
            _sha256(item, item_field)
            if sha256
            else _validate_identifier(item, item_field)
        )
    if result != sorted(result):
        _fail(field, "must be in ordinal sorted order")
    if len(result) != len(set(result)):
        _fail(field, "must not contain duplicates")
    return result


def _validate_overlap_scope(value: Any) -> dict[str, Any]:
    raw_scope = _exact_keys(value, {"calibration", "sealed"}, "overlap deny set.scope")
    scope: dict[str, Any] = {}
    for split in ("calibration", "sealed"):
        field = f"overlap deny set.scope.{split}"
        raw_artifact = _exact_keys(
            raw_scope[split],
            {"fileSha256", "taskSetSha256", "recordCount"},
            field,
        )
        scope[split] = {
            "fileSha256": _sha256(raw_artifact["fileSha256"], f"{field}.fileSha256"),
            "taskSetSha256": _sha256(
                raw_artifact["taskSetSha256"], f"{field}.taskSetSha256"
            ),
            "recordCount": _integer(
                raw_artifact["recordCount"], f"{field}.recordCount", 1, MAX_DENY_ENTRIES
            ),
        }
    if scope["calibration"] == scope["sealed"]:
        _fail(
            "overlap deny set.scope", "must bind distinct calibration and sealed sets"
        )
    if sum(item["recordCount"] for item in scope.values()) > MAX_DENY_ENTRIES:
        _fail(
            "overlap deny set.scope",
            f"must not exceed {MAX_DENY_ENTRIES} total task records",
        )
    return scope


def _validate_deny_set(
    raw: bytes,
    *,
    selected_at: datetime,
    producer: str,
    selector: str,
) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("overlap deny set: must be strict UTF-8 JSON") from error
    document = _exact_keys(
        value,
        {
            "schemaVersion",
            "purpose",
            "denySetId",
            "custodian",
            "createdAtUtc",
            "scope",
            "scopeSha256",
            "entries",
        },
        "overlap deny set",
    )
    if document["schemaVersion"] != TEACHER_OVERLAP_DENY_SET_SCHEMA_VERSION:
        _fail("overlap deny set.schemaVersion", "is unsupported")
    if document["purpose"] != "held-out-overlap-exclusion":
        _fail(
            "overlap deny set.purpose",
            "must be 'held-out-overlap-exclusion'",
        )
    deny_set_id = _validate_identifier(
        document["denySetId"], "overlap deny set.denySetId"
    )
    custodian = _validate_identifier(
        document["custodian"], "overlap deny set.custodian"
    )
    if custodian in {producer, selector}:
        _fail(
            "overlap deny set.custodian",
            "must be independent from the teacher producer and candidate selector",
        )
    created_at = _utc_second(document["createdAtUtc"], "overlap deny set.createdAtUtc")
    if created_at > selected_at:
        _fail(
            "overlap deny set.createdAtUtc",
            "must not follow candidate selection",
        )
    scope = _validate_overlap_scope(document["scope"])
    scope_sha256 = _sha256(document["scopeSha256"], "overlap deny set.scopeSha256")
    if scope_sha256 != teacher_overlap_scope_sha256(scope):
        _fail(
            "overlap deny set.scopeSha256", "does not match the bound evaluation scope"
        )
    entries = _exact_keys(
        document["entries"],
        {
            "authoredMessagesSha256",
            "normalizedUserTurnSha256",
            "contaminationGroupSha256",
            "heldOutAssetSha256",
        },
        "overlap deny set.entries",
    )
    normalized_entries = {
        "authoredMessagesSha256": _string_list(
            entries["authoredMessagesSha256"],
            "overlap deny set.entries.authoredMessagesSha256",
            sha256=True,
        ),
        "normalizedUserTurnSha256": _string_list(
            entries["normalizedUserTurnSha256"],
            "overlap deny set.entries.normalizedUserTurnSha256",
            sha256=True,
        ),
        "contaminationGroupSha256": _string_list(
            entries["contaminationGroupSha256"],
            "overlap deny set.entries.contaminationGroupSha256",
            sha256=True,
        ),
        "heldOutAssetSha256": _string_list(
            entries["heldOutAssetSha256"],
            "overlap deny set.entries.heldOutAssetSha256",
            sha256=True,
        ),
    }
    expected_authored_count = sum(item["recordCount"] for item in scope.values())
    if len(normalized_entries["authoredMessagesSha256"]) != expected_authored_count:
        _fail(
            "overlap deny set.entries.authoredMessagesSha256",
            "must contain one distinct fingerprint for every bound evaluation task",
        )
    scope_file_hashes = {scope[split]["fileSha256"] for split in scope}
    if not scope_file_hashes.issubset(normalized_entries["heldOutAssetSha256"]):
        _fail(
            "overlap deny set.entries.heldOutAssetSha256",
            "must include both bound evaluation task files",
        )
    return {
        "schemaVersion": TEACHER_OVERLAP_DENY_SET_SCHEMA_VERSION,
        "purpose": "held-out-overlap-exclusion",
        "denySetId": deny_set_id,
        "custodian": custodian,
        "createdAtUtc": document["createdAtUtc"],
        "scope": scope,
        "scopeSha256": scope_sha256,
        "entries": normalized_entries,
    }


def build_teacher_overlap_deny_set(
    *,
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    deny_set_id: str,
    custodian: str,
    created_at_utc: str,
) -> dict[str, Any]:
    created_at = _utc_second(created_at_utc, "overlap deny set.createdAtUtc")
    calibration = validate_evaluation_tasks(calibration_tasks_path)
    sealed = validate_evaluation_tasks(sealed_tasks_path)
    for split, task_set in (("calibration", calibration), ("sealed", sealed)):
        if any(task["split"] != split for task in task_set.records):
            _fail(f"{split} evaluation task set", f"must contain only {split} tasks")
    authored_by_split = {
        split: {
            overlap_authored_messages_sha256(task["messages"])
            for task in task_set.records
        }
        for split, task_set in (("calibration", calibration), ("sealed", sealed))
    }
    normalized_by_split = {
        split: {
            fingerprint
            for task in task_set.records
            for fingerprint in overlap_normalized_user_turn_sha256s(task["messages"])
        }
        for split, task_set in (("calibration", calibration), ("sealed", sealed))
    }
    group_by_split = {
        split: {
            overlap_contamination_group_sha256(task["contaminationGroup"])
            for task in task_set.records
        }
        for split, task_set in (("calibration", calibration), ("sealed", sealed))
    }
    for label, values in (
        ("authored messages", authored_by_split),
        ("normalized user turns", normalized_by_split),
        ("contamination groups", group_by_split),
    ):
        if values["calibration"] & values["sealed"]:
            _fail(
                "evaluation overlap scope", f"{label} cross calibration/sealed boundary"
            )
    total_records = len(calibration.records) + len(sealed.records)
    if total_records > MAX_DENY_ENTRIES:
        _fail(
            "evaluation overlap scope",
            f"exceeds {MAX_DENY_ENTRIES} total task records",
        )
    authored = sorted(authored_by_split["calibration"] | authored_by_split["sealed"])
    if len(authored) != total_records:
        _fail("evaluation overlap scope", "contains duplicate authored task messages")
    scope = {
        "calibration": {
            "fileSha256": calibration.sha256,
            "taskSetSha256": calibration.task_set_sha256,
            "recordCount": len(calibration.records),
        },
        "sealed": {
            "fileSha256": sealed.sha256,
            "taskSetSha256": sealed.task_set_sha256,
            "recordCount": len(sealed.records),
        },
    }
    held_out_assets = {calibration.sha256, sealed.sha256}
    for task_set in (calibration, sealed):
        for task in task_set.records:
            held_out_assets.add(task["contextPack"]["sha256"])
            held_out_assets.add(task["verifier"]["sha256"])
    document = {
        "schemaVersion": TEACHER_OVERLAP_DENY_SET_SCHEMA_VERSION,
        "purpose": "held-out-overlap-exclusion",
        "denySetId": _validate_identifier(deny_set_id, "overlap deny set.denySetId"),
        "custodian": _validate_identifier(custodian, "overlap deny set.custodian"),
        "createdAtUtc": created_at_utc,
        "scope": scope,
        "scopeSha256": teacher_overlap_scope_sha256(scope),
        "entries": {
            "authoredMessagesSha256": authored,
            "normalizedUserTurnSha256": sorted(
                normalized_by_split["calibration"] | normalized_by_split["sealed"]
            ),
            "contaminationGroupSha256": sorted(
                group_by_split["calibration"] | group_by_split["sealed"]
            ),
            "heldOutAssetSha256": sorted(held_out_assets),
        },
    }
    return _validate_deny_set(
        canonical_json_bytes(document),
        selected_at=created_at,
        producer="\0",
        selector="\0",
    )


def _validate_output_policy(value: Any) -> dict[str, Any]:
    policy = _exact_keys(
        value,
        {
            "schemaVersion",
            "split",
            "lineageOrigin",
            "reviewStatus",
            "verified",
            "verifiedAtUtc",
            "compileSucceeded",
            "testsPassed",
            "useForTraining",
            "rights",
            "sourceRights",
        },
        "teacher selection manifest.outputPolicy",
    )
    for rights_name in ("rights", "sourceRights"):
        rights = _exact_keys(
            policy[rights_name],
            set(_LOCKED_RIGHTS),
            f"teacher selection manifest.outputPolicy.{rights_name}",
        )
        if any(type(rights[name]) is not bool for name in _LOCKED_RIGHTS):
            _fail(
                f"teacher selection manifest.outputPolicy.{rights_name}",
                "rights values must be booleans",
            )
    for name in ("verified", "compileSucceeded", "testsPassed", "useForTraining"):
        if type(policy[name]) is not bool:
            _fail(
                f"teacher selection manifest.outputPolicy.{name}",
                "must be a boolean",
            )
    if policy != _OUTPUT_POLICY:
        _fail(
            "teacher selection manifest.outputPolicy",
            "must emit only development/draft/unverified storage-and-evaluation rows",
        )
    return json.loads(json.dumps(policy))


def _selection_items(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SELECTIONS:
        _fail(
            "teacher selection manifest.selection.candidates",
            f"must contain 1 to {MAX_SELECTIONS} candidates",
        )
    items: list[dict[str, str]] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for index, raw_item in enumerate(value):
        field = f"teacher selection manifest.selection.candidates[{index}]"
        item = _exact_keys(raw_item, {"candidateId", "candidateSha256"}, field)
        candidate_id = item["candidateId"]
        if (
            not isinstance(candidate_id, str)
            or not candidate_id.startswith("vqtgenrow-")
            or len(candidate_id) != len("vqtgenrow-") + 64
            or any(
                character not in "0123456789abcdef" for character in candidate_id[10:]
            )
        ):
            _fail(f"{field}.candidateId", "must be a canonical teacher candidate ID")
        candidate_hash = _sha256(item["candidateSha256"], f"{field}.candidateSha256")
        if candidate_id in ids:
            _fail(f"{field}.candidateId", "duplicates an earlier selection")
        if candidate_hash in hashes:
            _fail(f"{field}.candidateSha256", "duplicates an earlier selection")
        ids.add(candidate_id)
        hashes.add(candidate_hash)
        items.append({"candidateId": candidate_id, "candidateSha256": candidate_hash})
    return items


def _validate_composed_messages(
    candidate: Mapping[str, Any], field: str
) -> list[dict[str, str]]:
    authored = [dict(message) for message in candidate["task"]["messages"]]
    if len(authored) >= MAX_MESSAGE_COUNT:
        _fail(
            field, f"must leave one of the {MAX_MESSAGE_COUNT} message slots for output"
        )
    messages = [
        *authored,
        {"role": "assistant", "content": candidate["output"]["text"]},
    ]
    for index, message in enumerate(messages):
        _require_utf16_limit(
            message["content"],
            MAX_MESSAGE_CHARACTERS,
            f"{field}[{index}].content",
        )
    if sum(_utf16_length(message["content"]) for message in messages) > (
        MAX_AGGREGATE_MESSAGE_CHARACTERS
    ):
        _fail(
            field,
            f"content exceeds {MAX_AGGREGATE_MESSAGE_CHARACTERS} aggregate UTF-16 characters",
        )
    return _validate_messages(messages, field)


def _validate_materialized_sources(
    candidate: Mapping[str, Any], field: str
) -> list[dict[str, Any]]:
    sources = candidate["sources"]
    if not 1 <= len(sources) <= MAX_SOURCE_COUNT:
        _fail(field, f"must contain 1 to {MAX_SOURCE_COUNT} sources")
    result: list[dict[str, Any]] = []
    aggregate = 0
    content_hashes: set[str] = set()
    for index, source in enumerate(sources):
        source_field = f"{field}[{index}]"
        if source["contentSha256"] in content_hashes:
            _fail(
                f"{source_field}.contentSha256",
                "duplicates another selected source snapshot",
            )
        content_hashes.add(source["contentSha256"])
        for name, maximum in (
            ("title", 500),
            ("content", MAX_SOURCE_CHARACTERS),
            ("provenance", 2_000),
            ("license", 500),
        ):
            _require_utf16_limit(source[name], maximum, f"{source_field}.{name}")
        if source["uri"] is not None:
            _require_utf16_limit(source["uri"], 2_048, f"{source_field}.uri")
        aggregate += _utf16_length(source["content"])
        result.append(
            {
                "id": source["id"],
                "title": source["title"],
                "content": source["content"],
                "provenance": source["provenance"],
                "license": source["license"],
                "retrievedAtUtc": source["retrievedAtUtc"],
                "availableAtUtc": source["availableAtUtc"],
                "uri": source["uri"],
                "rights": dict(_LOCKED_RIGHTS),
            }
        )
    if aggregate > MAX_AGGREGATE_SOURCE_CHARACTERS:
        _fail(
            field,
            f"content exceeds {MAX_AGGREGATE_SOURCE_CHARACTERS} aggregate UTF-16 characters",
        )
    return result


def _admission_binding(
    candidate: Mapping[str, Any],
    *,
    selection_manifest_sha256: str,
    candidate_set_sha256: str,
    generation_manifest_sha256: str,
    candidate_catalog_sha256: str,
    deny_set: Mapping[str, Any],
    deny_set_sha256: str,
    selected_by: str,
    selected_at_utc: str,
    basis_sha256: str,
) -> dict[str, Any]:
    authored_messages = candidate["task"]["messages"]
    binding = {
        "schemaVersion": TEACHER_ADMISSION_SCHEMA_VERSION,
        "candidateSetSha256": candidate_set_sha256,
        "generationManifestSha256": generation_manifest_sha256,
        "candidateCatalogSha256": candidate_catalog_sha256,
        "overlapDenySetSha256": deny_set_sha256,
        "overlapDenySetId": deny_set["denySetId"],
        "overlapScopeSha256": deny_set["scopeSha256"],
        "selectionManifestSha256": selection_manifest_sha256,
        "selectedBy": selected_by,
        "selectedAtUtc": selected_at_utc,
        "selectionBasisSha256": basis_sha256,
        "candidateId": candidate["candidateId"],
        "candidateSha256": candidate["candidateSha256"],
        "batchId": candidate["batchId"],
        "taskId": candidate["task"]["taskId"],
        "taskSha256": candidate["task"]["taskSha256"],
        "promptSha256": candidate["task"]["promptSha256"],
        "authoredMessagesSha256": overlap_authored_messages_sha256(authored_messages),
        "normalizedFinalUserSha256": overlap_normalized_final_user_sha256(
            authored_messages
        ),
        "contaminationGroupSha256": overlap_contamination_group_sha256(
            candidate["task"]["contaminationGroup"]
        ),
        "outputSha256": candidate["output"]["sha256"],
        "sourceContentSha256": [
            source["contentSha256"] for source in candidate["sources"]
        ],
        "executionModelId": candidate["teacher"]["executionModelId"],
        "chatTemplateSha256": candidate["teacher"]["chatTemplateSha256"],
        "runtimeSha256": candidate["teacher"]["runtimeSha256"],
    }
    return binding


def _admission_sha256(binding: Mapping[str, Any]) -> str:
    return _length_prefixed_sha256(
        "daxalgo-hyperion-teacher-admission/v1",
        [[canonical_json_bytes(binding).decode("utf-8")]],
    )


def _materialize_row(
    candidate: Mapping[str, Any],
    binding: Mapping[str, Any],
    admission_sha256: str,
) -> dict[str, Any]:
    task = candidate["task"]
    authority = candidate["authority"]
    messages = _validate_composed_messages(
        candidate, f"candidate {candidate['candidateId']}.messages"
    )
    sources = _validate_materialized_sources(
        candidate, f"candidate {candidate['candidateId']}.sources"
    )
    for name, maximum in (("provenance", 2_000), ("license", 500)):
        _require_utf16_limit(
            authority[name],
            maximum,
            f"candidate {candidate['candidateId']}.authority.{name}",
        )
    for name in ("modelId", "profileVersion"):
        _require_utf16_limit(
            candidate["teacher"][name],
            500,
            f"candidate {candidate['candidateId']}.teacher.{name}",
        )
    task_evidence = task["evidence"]
    for index, item in enumerate(task_evidence):
        if item.startswith(("knowledgeClass=", "teacherAdmissionSha256=")):
            _fail(
                f"candidate {candidate['candidateId']}.task.evidence[{index}]",
                "uses a reserved materialization evidence prefix",
            )
        _require_utf16_limit(
            item,
            MAX_EVIDENCE_CHARACTERS,
            f"candidate {candidate['candidateId']}.task.evidence[{index}]",
        )
    evidence = [
        f"knowledgeClass={task['knowledgeClass']}",
        f"teacherAdmissionSha256={admission_sha256}",
        *task_evidence,
    ]
    if len(evidence) > MAX_EVIDENCE_ITEMS:
        _fail(
            f"candidate {candidate['candidateId']}.task.evidence",
            f"must leave two of the {MAX_EVIDENCE_ITEMS} evidence slots for admission anchors",
        )
    row = {
        "schemaVersion": SOURCE_SCHEMA_VERSION,
        "id": candidate["candidateId"],
        "taskKind": task["taskKind"],
        "domains": list(task["domains"]),
        "messages": messages,
        "conversationSha256": expert_conversation_sha256(messages),
        "sources": sources,
        "lineage": {
            "origin": "OpenWeightTeacher",
            "producer": authority["producer"],
            "modelId": candidate["teacher"]["modelId"],
            "modelRevision": candidate["teacher"]["modelRevision"],
            "promptSha256": task["promptSha256"],
            "profileVersion": candidate["teacher"]["profileVersion"],
            "producedAtUtc": candidate["capturedAtUtc"],
        },
        "verification": {
            "verified": False,
            "reviewer": authority["reviewer"],
            "verifiedAtUtc": None,
            "evidenceSha256": _verification_evidence_sha256(evidence, [], []),
            "evidence": evidence,
            "compileSucceeded": False,
            "compileEvidence": [],
            "testsPassed": False,
            "testEvidence": [],
        },
        "split": "development",
        "contaminationGroup": task["contaminationGroup"],
        "provenance": authority["provenance"],
        "license": authority["license"],
        "rights": dict(_LOCKED_RIGHTS),
        "reviewStatus": "draft",
        "cutoffUtc": task["cutoffUtc"],
        "useForTraining": False,
    }
    if row["lineage"]["promptSha256"] != binding["promptSha256"]:
        _fail("teacher admission", "prompt lineage changed during materialization")
    return row


def _encode_dataset(rows: list[dict[str, Any]]) -> bytes:
    encoded_rows: list[bytes] = []
    total = 0
    for index, row in enumerate(rows):
        encoded = canonical_json_bytes(row)
        if _utf16_length(encoded.decode("utf-8")) > 2_000_000:
            _fail(
                f"materialized dataset line {index + 1}",
                "exceeds the 2,000,000-character canonical dataset line limit",
            )
        if len(encoded) + 1 > MAX_CORPUS_LINE_BYTES:
            _fail(
                f"materialized dataset line {index + 1}",
                f"exceeds {MAX_CORPUS_LINE_BYTES} UTF-8 bytes",
            )
        total += len(encoded) + 1
        if total > MAX_CORPUS_BYTES:
            _fail("materialized dataset", f"exceeds {MAX_CORPUS_BYTES} UTF-8 bytes")
        encoded_rows.append(encoded + b"\n")
    return b"".join(encoded_rows)


def _materialization_record_id(document: Mapping[str, Any]) -> str:
    payload = dict(document)
    payload["materializationId"] = "vqtmat-" + "0" * 64
    digest = _length_prefixed_sha256(
        "daxalgo-hyperion-teacher-materialization-record/v1",
        [[canonical_json_bytes(payload).decode("utf-8")]],
    )
    return f"vqtmat-{digest}"


def _build_materialization_record(
    *,
    selection_manifest_sha256: str,
    bindings: Mapping[str, Mapping[str, str]],
    candidates: tuple[dict[str, Any], ...],
    selection: Mapping[str, Any],
    deny_set: Mapping[str, Any],
    admissions: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    dataset_bytes: bytes,
) -> dict[str, Any]:
    admission_records = []
    for candidate, binding, row in zip(candidates, admissions, rows, strict=True):
        admission_records.append(
            {
                "admissionSha256": _admission_sha256(binding),
                "exampleId": row["id"],
                "candidateId": candidate["candidateId"],
                "candidateSha256": candidate["candidateSha256"],
                "batchId": candidate["batchId"],
                "taskId": candidate["task"]["taskId"],
                "taskSha256": candidate["task"]["taskSha256"],
                "promptSha256": candidate["task"]["promptSha256"],
                "authoredMessagesSha256": binding["authoredMessagesSha256"],
                "normalizedFinalUserSha256": binding["normalizedFinalUserSha256"],
                "contaminationGroupSha256": binding["contaminationGroupSha256"],
                "outputSha256": candidate["output"]["sha256"],
                "sourceContentSha256": binding["sourceContentSha256"],
                "conversationSha256": row["conversationSha256"],
                "executionModelId": binding["executionModelId"],
                "chatTemplateSha256": binding["chatTemplateSha256"],
                "runtimeSha256": binding["runtimeSha256"],
            }
        )
    document: dict[str, Any] = {
        "schemaVersion": TEACHER_MATERIALIZATION_RECORD_SCHEMA_VERSION,
        "materializationId": "vqtmat-" + "0" * 64,
        "purpose": "independent-review-draft",
        "selectionManifestSha256": selection_manifest_sha256,
        "inputs": {
            "selectionSnapshotPath": SELECTION_SNAPSHOT_PATH,
            "candidateSetSha256": bindings["candidateSet"]["sha256"],
            "generationManifestSha256": bindings["generationManifest"]["sha256"],
            "candidateCatalogSha256": bindings["candidateCatalog"]["sha256"],
            "overlapDenySetSha256": bindings["overlapDenySet"]["sha256"],
            "candidateBatchId": candidates[0]["batchId"],
            "candidateManifestSha256": candidates[0]["manifestSha256"],
        },
        "selection": {
            "selectedBy": selection["selectedBy"],
            "selectedAtUtc": selection["selectedAtUtc"],
            "basisSha256": hashlib.sha256(
                selection["basis"].encode("utf-8", errors="strict")
            ).hexdigest(),
            "candidateCount": len(candidates),
        },
        "overlap": {
            "denySetId": deny_set["denySetId"],
            "custodian": deny_set["custodian"],
            "createdAtUtc": deny_set["createdAtUtc"],
            "scopeSha256": deny_set["scopeSha256"],
            "fileSha256": bindings["overlapDenySet"]["sha256"],
        },
        "output": {
            "path": MATERIALIZED_DATASET_PATH,
            "sha256": _sha256_bytes(dataset_bytes),
            "sizeBytes": len(dataset_bytes),
            "recordCount": len(rows),
            "trainingEligibleCount": 0,
        },
        "admissions": admission_records,
        "authenticationStatus": "unsigned",
        "requiresAuthenticatedReviewReceipts": True,
        "reviewStatus": "draft",
        "eligibleForTraining": False,
    }
    document["materializationId"] = _materialization_record_id(document)
    return document


def _prepare_teacher_selection(
    manifest_path: str | os.PathLike[str],
    *,
    now: datetime | None = None,
) -> TeacherSelection:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        _fail("materialization validation time", "must include a UTC offset")
    current = current.astimezone(timezone.utc)
    manifest_file = _reject_reparse_components(
        Path(manifest_path), "teacher selection manifest"
    )
    manifest_raw, manifest_value = _load_json_bytes(
        manifest_file, "teacher selection manifest", MAX_JSON_BYTES
    )
    manifest_sha256 = _sha256_bytes(manifest_raw)
    manifest = _exact_keys(
        manifest_value,
        {"schemaVersion", "purpose", "inputs", "selection", "outputPolicy"},
        "teacher selection manifest",
    )
    if manifest["schemaVersion"] != TEACHER_SELECTION_MANIFEST_SCHEMA_VERSION:
        _fail("teacher selection manifest.schemaVersion", "is unsupported")
    if manifest["purpose"] != "independent-review-draft":
        _fail(
            "teacher selection manifest.purpose",
            "must be 'independent-review-draft'",
        )
    _validate_output_policy(manifest["outputPolicy"])
    selection = _exact_keys(
        manifest["selection"],
        {"selectedBy", "selectedAtUtc", "basis", "candidates"},
        "teacher selection manifest.selection",
    )
    selected_by = _validate_identifier(
        selection["selectedBy"], "teacher selection manifest.selection.selectedBy"
    )
    selected_at = _utc_second(
        selection["selectedAtUtc"],
        "teacher selection manifest.selection.selectedAtUtc",
    )
    if selected_at > current:
        _fail(
            "teacher selection manifest.selection.selectedAtUtc",
            "must not be in the future",
        )
    basis = _string(
        selection["basis"],
        "teacher selection manifest.selection.basis",
        max_length=2_000,
    )
    _require_utf16_limit(basis, 2_000, "teacher selection manifest.selection.basis")
    selection_items = _selection_items(selection["candidates"])
    inputs = _exact_keys(
        manifest["inputs"],
        {
            "candidateSet",
            "generationManifest",
            "candidateCatalog",
            "overlapDenySet",
        },
        "teacher selection manifest.inputs",
    )
    root = manifest_file.parent
    limits = {
        "candidateSet": MAX_EVALUATION_BYTES,
        "generationManifest": MAX_JSON_BYTES,
        "candidateCatalog": MAX_JSON_BYTES,
        "overlapDenySet": MAX_DENY_SET_BYTES,
    }
    paths: dict[str, Path] = {}
    raw_inputs: dict[str, bytes] = {}
    bindings: dict[str, dict[str, str]] = {}
    for name in limits:
        path, raw, binding = _read_bound_input(
            root,
            inputs[name],
            f"teacher selection manifest.inputs.{name}",
            max_bytes=limits[name],
        )
        paths[name] = path
        raw_inputs[name] = raw
        bindings[name] = binding
    all_paths = [manifest_file, *paths.values()]
    if len({os.path.normcase(os.fspath(path)) for path in all_paths}) != len(all_paths):
        _fail("teacher selection manifest.inputs", "must bind distinct input files")
    candidates = validate_teacher_candidates(
        paths["candidateSet"],
        manifest_path=paths["generationManifest"],
        catalog_path=paths["candidateCatalog"],
    )
    if candidates.sha256 != bindings["candidateSet"]["sha256"]:
        _fail(
            "teacher selection manifest.inputs.candidateSet.sha256",
            "changed during validation",
        )
    if candidates.manifest_sha256 != bindings["generationManifest"]["sha256"]:
        _fail(
            "teacher selection manifest.inputs.generationManifest.sha256",
            "changed during candidate validation",
        )
    if (
        candidates.teacher["candidateCatalogSha256"]
        != bindings["candidateCatalog"]["sha256"]
    ):
        _fail(
            "teacher selection manifest.inputs.candidateCatalog.sha256",
            "changed during candidate validation",
        )
    producer = candidates.records[0]["authority"]["producer"]
    if selected_by == producer:
        _fail(
            "teacher selection manifest.selection.selectedBy",
            "must be independent from the teacher producer",
        )
    planned_reviewer = candidates.records[0]["authority"]["reviewer"]
    if planned_reviewer in {producer, selected_by}:
        _fail(
            "teacher candidate authority.reviewer",
            "must be distinct from the teacher producer and candidate selector",
        )
    deny_set = _validate_deny_set(
        raw_inputs["overlapDenySet"],
        selected_at=selected_at,
        producer=producer,
        selector=selected_by,
    )
    snapshots = _build_input_snapshots(
        root=root,
        selection_raw=manifest_raw,
        bindings=bindings,
        paths=paths,
        raw_inputs=raw_inputs,
        candidate_records=candidates.records,
        sample_count=candidates.sample_count,
    )
    deny_set_sha256 = bindings["overlapDenySet"]["sha256"]
    by_id = {candidate["candidateId"]: candidate for candidate in candidates.records}
    positions = {
        candidate["candidateId"]: index
        for index, candidate in enumerate(candidates.records)
    }
    selected_candidates: list[dict[str, Any]] = []
    selected_positions: list[int] = []
    selected_tasks: set[str] = set()
    for index, item in enumerate(selection_items):
        field = f"teacher selection manifest.selection.candidates[{index}]"
        candidate = by_id.get(item["candidateId"])
        if candidate is None:
            _fail(f"{field}.candidateId", "does not exist in the bound candidate set")
        if candidate["candidateSha256"] != item["candidateSha256"]:
            _fail(f"{field}.candidateSha256", "does not match the bound candidate")
        task_sha256 = candidate["task"]["taskSha256"]
        if task_sha256 in selected_tasks:
            _fail(field, "selects more than one candidate for the same task")
        selected_tasks.add(task_sha256)
        selected_candidates.append(candidate)
        selected_positions.append(positions[candidate["candidateId"]])
    if selected_positions != sorted(selected_positions):
        _fail(
            "teacher selection manifest.selection.candidates",
            "must follow the bound candidate-file order",
        )
    deny_entries = deny_set["entries"]
    authored_denials = set(deny_entries["authoredMessagesSha256"])
    normalized_user_denials = set(deny_entries["normalizedUserTurnSha256"])
    group_denials = set(deny_entries["contaminationGroupSha256"])
    asset_denials = set(deny_entries["heldOutAssetSha256"])
    for index, candidate in enumerate(selected_candidates):
        field = f"teacher selection manifest.selection.candidates[{index}]"
        task = candidate["task"]
        overlaps: list[str] = []
        if any(
            fingerprint in authored_denials
            for fingerprint in overlap_authored_message_prefix_sha256s(task["messages"])
        ):
            overlaps.append("authoredMessagesSha256")
        if any(
            fingerprint in normalized_user_denials
            for fingerprint in overlap_normalized_user_turn_sha256s(task["messages"])
        ):
            overlaps.append("normalizedUserTurnSha256")
        if (
            overlap_contamination_group_sha256(task["contaminationGroup"])
            in group_denials
        ):
            overlaps.append("contaminationGroupSha256")
        if any(
            source["contentSha256"] in asset_denials for source in candidate["sources"]
        ):
            overlaps.append("heldOutAssetSha256")
        if overlaps:
            _fail(field, f"overlaps held-out deny set by {', '.join(overlaps)}")
        captured_at = _utc_second(candidate["capturedAtUtc"], f"{field}.capturedAtUtc")
        cutoff = _utc_second(candidate["task"]["cutoffUtc"], f"{field}.task.cutoffUtc")
        if captured_at > selected_at:
            _fail(f"{field}.capturedAtUtc", "must not follow candidate selection")
        if cutoff > selected_at:
            _fail(f"{field}.task.cutoffUtc", "must not follow candidate selection")
        for source_index, source in enumerate(candidate["sources"]):
            retrieved = _utc_second(
                source["retrievedAtUtc"],
                f"{field}.sources[{source_index}].retrievedAtUtc",
            )
            if retrieved > selected_at:
                _fail(
                    f"{field}.sources[{source_index}].retrievedAtUtc",
                    "must not follow candidate selection",
                )
    normalized_selection = {
        "selectedBy": selected_by,
        "selectedAtUtc": selection["selectedAtUtc"],
        "basis": basis,
        "candidates": selection_items,
    }
    basis_sha256 = hashlib.sha256(basis.encode("utf-8", errors="strict")).hexdigest()
    admissions: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for candidate in selected_candidates:
        binding = _admission_binding(
            candidate,
            selection_manifest_sha256=manifest_sha256,
            candidate_set_sha256=candidates.sha256,
            generation_manifest_sha256=bindings["generationManifest"]["sha256"],
            candidate_catalog_sha256=bindings["candidateCatalog"]["sha256"],
            deny_set=deny_set,
            deny_set_sha256=deny_set_sha256,
            selected_by=selected_by,
            selected_at_utc=selection["selectedAtUtc"],
            basis_sha256=basis_sha256,
        )
        admission_hash = _admission_sha256(binding)
        admissions.append(binding)
        rows.append(_materialize_row(candidate, binding, admission_hash))
    dataset_bytes = _encode_dataset(rows)
    selected_tuple = tuple(selected_candidates)
    materialization_record = _build_materialization_record(
        selection_manifest_sha256=manifest_sha256,
        bindings=bindings,
        candidates=selected_tuple,
        selection=normalized_selection,
        deny_set=deny_set,
        admissions=admissions,
        rows=rows,
        dataset_bytes=dataset_bytes,
    )
    record_bytes = canonical_json_bytes(materialization_record) + b"\n"
    if len(record_bytes) > MAX_MATERIALIZATION_RECORD_BYTES:
        _fail(
            "teacher materialization record",
            f"exceeds {MAX_MATERIALIZATION_RECORD_BYTES} UTF-8 bytes",
        )
    if (
        _read_file_bounded(manifest_file, "teacher selection manifest", MAX_JSON_BYTES)
        != manifest_raw
    ):
        _fail("teacher selection manifest", "changed while it was being validated")
    for name, limit in limits.items():
        if (
            _read_file_bounded(
                paths[name], f"teacher selection manifest.inputs.{name}.path", limit
            )
            != raw_inputs[name]
        ):
            _fail(
                f"teacher selection manifest.inputs.{name}",
                "changed while it was being validated",
            )
    normalized_manifest = {
        "schemaVersion": TEACHER_SELECTION_MANIFEST_SCHEMA_VERSION,
        "purpose": "independent-review-draft",
        "inputs": bindings,
        "selection": normalized_selection,
        "outputPolicy": json.loads(json.dumps(_OUTPUT_POLICY)),
    }
    return TeacherSelection(
        manifest_path=manifest_file,
        manifest_sha256=manifest_sha256,
        document=normalized_manifest,
        candidates=selected_tuple,
        candidate_set_sha256=candidates.sha256,
        deny_set=deny_set,
        deny_set_sha256=deny_set_sha256,
        admissions=tuple(admissions),
        rows=tuple(rows),
        dataset_bytes=dataset_bytes,
        materialization_record=materialization_record,
        materialization_record_bytes=record_bytes,
        snapshots=snapshots,
    )


def validate_teacher_selection_manifest(
    manifest_path: str | os.PathLike[str],
    *,
    now: datetime | None = None,
) -> TeacherSelection:
    return _prepare_teacher_selection(manifest_path, now=now)


def _write_exclusive(path: Path, value: bytes, field: str) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise ValidationError(f"{field}: already exists") from error


def create_teacher_overlap_deny_set(
    *,
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    deny_set_id: str,
    custodian: str,
    created_at_utc: str,
) -> dict[str, Any]:
    document = build_teacher_overlap_deny_set(
        calibration_tasks_path=calibration_tasks_path,
        sealed_tasks_path=sealed_tasks_path,
        deny_set_id=deny_set_id,
        custodian=custodian,
        created_at_utc=created_at_utc,
    )
    encoded = canonical_json_bytes(document) + b"\n"
    if len(encoded) > MAX_DENY_SET_BYTES:
        _fail("overlap deny set", f"exceeds {MAX_DENY_SET_BYTES} UTF-8 bytes")
    destination = Path(output_path)
    with _exclusive_destination_lock(destination, "overlap deny set output") as locked:
        if os.path.lexists(locked):
            _fail(
                "overlap deny set output",
                "already exists; immutable outputs are never overwritten",
            )
        _write_exclusive(locked, encoded, "overlap deny set output")
    return document


def _install_materialization_no_clobber(
    source: Path, destination: Path, field: str
) -> None:
    if os.name == "nt":
        try:
            os.rename(source, destination)
        except FileExistsError as error:
            raise ValidationError(
                f"{field}: appeared during installation; immutable outputs are never overwritten"
            ) from error
        except OSError as error:
            if os.path.lexists(destination):
                raise ValidationError(
                    f"{field}: appeared during installation; immutable outputs are never overwritten"
                ) from error
            raise
        return
    if sys.platform != "linux":
        _fail(field, "atomic no-clobber directory installation is unsupported")

    import ctypes
    import errno

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        _fail(field, "Linux renameat2 is required for atomic no-clobber installation")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_noreplace,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValidationError(
            f"{field}: appeared during installation; immutable outputs are never overwritten"
        )
    raise OSError(error_number, os.strerror(error_number), os.fspath(destination))


def _validate_package_tree(package: Path, expected_files: set[str]) -> None:
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for current, directories, files in os.walk(package, followlinks=False):
        current_path = Path(current)
        for name in directories:
            path = _reject_reparse_components(
                current_path / name, "teacher materialization package directory"
            )
            actual_directories.add(path.relative_to(package).as_posix())
        for name in files:
            path = _reject_reparse_components(
                current_path / name, "teacher materialization package file"
            )
            actual_files.add(path.relative_to(package).as_posix())
    expected_directories: set[str] = set()
    for relative in expected_files:
        parts = relative.split("/")[:-1]
        for count in range(1, len(parts) + 1):
            expected_directories.add("/".join(parts[:count]))
    if actual_files != expected_files or actual_directories != expected_directories:
        _fail(
            "teacher materialization package",
            "must contain exactly the canonical outputs and bound input snapshots",
        )


def _validate_package_against_selection(
    package_path: Path,
    prepared: TeacherSelection,
) -> TeacherMaterializationPackage:
    package = _reject_reparse_components(
        package_path, "teacher materialization package"
    )
    if not package.is_dir():
        _fail("teacher materialization package", "must be a directory")
    expected_files = {
        MATERIALIZED_DATASET_PATH,
        MATERIALIZATION_RECORD_PATH,
        *prepared.snapshots,
    }
    _validate_package_tree(package, expected_files)
    dataset_path = resolve_bound_path(
        package, MATERIALIZED_DATASET_PATH, "teacher materialization dataset"
    )
    record_path = resolve_bound_path(
        package, MATERIALIZATION_RECORD_PATH, "teacher materialization record"
    )
    dataset_bytes = _read_file_bounded(
        dataset_path, "teacher materialization dataset", MAX_CORPUS_BYTES
    )
    record_bytes = _read_file_bounded(
        record_path,
        "teacher materialization record",
        MAX_MATERIALIZATION_RECORD_BYTES,
    )
    if dataset_bytes != prepared.dataset_bytes:
        _fail(
            "teacher materialization dataset",
            "does not exactly match the selection-derived canonical dataset",
        )
    if record_bytes != prepared.materialization_record_bytes:
        _fail(
            "teacher materialization record",
            "does not exactly match the selection-derived canonical record",
        )
    for relative, expected in prepared.snapshots.items():
        snapshot_path = resolve_bound_path(
            package, relative, f"teacher materialization snapshot {relative}"
        )
        actual = _read_file_bounded(
            snapshot_path,
            f"teacher materialization snapshot {relative}",
            MAX_EVALUATION_BYTES,
        )
        if actual != expected:
            _fail(
                f"teacher materialization snapshot {relative}",
                "does not match the bound input bytes",
            )
    return TeacherMaterializationPackage(
        path=package,
        dataset_path=dataset_path,
        materialization_record_path=record_path,
        materialization_id=prepared.materialization_record["materializationId"],
        dataset_sha256=_sha256_bytes(dataset_bytes),
        record_count=len(prepared.rows),
    )


def materialize_teacher_candidates(
    *,
    selection_manifest_path: str | os.PathLike[str],
    output_directory: str | os.PathLike[str],
    now: datetime | None = None,
) -> TeacherMaterializationPackage:
    prepared = _prepare_teacher_selection(selection_manifest_path, now=now)
    destination = Path(output_directory)
    with _exclusive_destination_lock(
        destination, "teacher materialization output"
    ) as locked:
        if os.path.lexists(locked):
            _fail(
                "teacher materialization output",
                "already exists; immutable outputs are never overwritten",
            )
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{locked.name}.", suffix=".tmp", dir=locked.parent
            )
        )
        try:
            for relative, raw in prepared.snapshots.items():
                snapshot_path = staging.joinpath(*relative.split("/"))
                snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                _write_exclusive(
                    snapshot_path,
                    raw,
                    f"teacher materialization snapshot {relative}",
                )
            _write_exclusive(
                staging / MATERIALIZED_DATASET_PATH,
                prepared.dataset_bytes,
                "teacher materialization dataset",
            )
            _write_exclusive(
                staging / MATERIALIZATION_RECORD_PATH,
                prepared.materialization_record_bytes,
                "teacher materialization record",
            )
            _validate_package_against_selection(staging, prepared)
            _install_materialization_no_clobber(
                staging, locked, "teacher materialization output"
            )
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return _validate_package_against_selection(locked, prepared)


def validate_teacher_materialization(
    package_path: str | os.PathLike[str],
    *,
    selection_manifest_path: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> TeacherMaterializationPackage:
    package = _reject_reparse_components(
        Path(package_path), "teacher materialization package"
    )
    if not package.is_dir():
        _fail("teacher materialization package", "must be a directory")
    embedded_selection = resolve_bound_path(
        package,
        SELECTION_SNAPSHOT_PATH,
        "teacher materialization embedded selection",
    )
    prepared = _prepare_teacher_selection(embedded_selection, now=now)
    validated = _validate_package_against_selection(package, prepared)
    if selection_manifest_path is not None:
        external = _prepare_teacher_selection(selection_manifest_path, now=now)
        if external.manifest_sha256 != prepared.manifest_sha256:
            _fail(
                "teacher materialization external selection",
                "does not match the embedded selection snapshot",
            )
        _validate_package_against_selection(package, external)
    return validated
