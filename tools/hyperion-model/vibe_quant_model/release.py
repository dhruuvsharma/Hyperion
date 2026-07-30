from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .core import (
    DOMAINS,
    MAX_SFT_BYTES,
    MAX_SFT_LINE_BYTES,
    MAX_SFT_RECORDS,
    ORIGINS,
    SOURCE_SCHEMA_VERSION,
    SPLITS,
    TASK_KINDS,
    ValidationError,
    _copy_file_snapshot,
    _ensure_directory_no_reparse,
    _exact_keys,
    _exclusive_destination_lock,
    _fail,
    _install_directory_no_clobber,
    _is_reparse_or_symlink,
    _length_prefixed_sha256,
    _parse_datetime,
    _pinned_revision_label,
    _read_file_bounded,
    _regular_file,
    _reject_constant,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _validate_data_release_identity,
    _validate_messages,
    _write_json_exclusive,
    canonical_json_bytes,
    expert_conversation_sha256,
    load_json_document,
    resolve_bound_path,
    sha256_file,
)
from .evaluation import EvaluationTaskSet, validate_evaluation_tasks
from .evaluation_authoring import (
    MAX_EVALUATION_AUTHORING_APPROVAL_BYTES,
    EvaluationAuthoringApprovalTrust,
    validate_evaluation_authoring_approval,
    validate_evaluation_authoring_approval_for_inventory,
)
from .review_receipts import (
    LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION,
    MAX_REVIEW_RECEIPT_SET_BYTES,
    REVIEW_RECEIPT_SCHEMA_VERSION,
    SFT_METADATA_SCHEMA_VERSION,
    ExpertModelReviewReceiptTrust,
    expert_model_sft_metadata,
    legacy_expert_model_sft_metadata,
    normalize_sft_cutoff_utc,
    validate_expert_model_review_receipts,
)


RELEASE_SCHEMA_VERSION = "daxalgo.vibe-quant.corpus-evaluation-release/v4"
LEGACY_RELEASE_SCHEMA_VERSION = "daxalgo.vibe-quant.corpus-evaluation-release/v3"
TASK_BINDINGS_SCHEMA_VERSION = "daxalgo.vibe-quant.release-task-bindings/v1"
TASK_BINDINGS_V2_SCHEMA_VERSION = "daxalgo.vibe-quant.release-task-bindings/v2"
MAX_TASK_BINDINGS = 100_000
MAX_SOURCE_EXAMPLE_IDS = 100_000
_TASK_BINDINGS_V2_PATH_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$"
)
RELEASE_MANIFEST_PATH = "release-manifest.json"
CORPUS_PATH = "corpus/expert-dataset.jsonl"
REVIEW_RECEIPTS_PATH = "corpus/expert-model-review-receipts.jsonl"
TEACHER_LINEAGE_ADMISSION_PATH = "corpus/teacher-materialization-lineage-admission.json"
SFT_PATH = "corpus/dataset.sft.jsonl"
CALIBRATION_TASKS_PATH = "evaluation/calibration.tasks.jsonl"
SEALED_TASKS_PATH = "evaluation/sealed.tasks.jsonl"
EVALUATION_AUTHORING_APPROVAL_PATH = "review/evaluation-authoring-approval.json"
APPROVAL_EVIDENCE_PATH = "review/approval-evidence.bin"
CANDIDATE_STABLE_KNOWLEDGE_CLASS = "knowledgeClass=candidate-stable"
RETRIEVAL_ONLY_KNOWLEDGE_CLASS = "knowledgeClass=retrieval-only"
DAXQ_EXECUTABLE_PROFILE = "daxq-sdk-abi3-source/v1"
MAX_EXECUTABLE_VECTORS = 16
MAX_EXECUTABLE_CALLBACKS = 512

PURPOSES = frozenset(
    {
        "local-evaluation",
        "provider-evaluation",
        "local-training-evaluation",
        "provider-training-evaluation",
    }
)
TRAINING_PURPOSES = frozenset(
    {"local-training-evaluation", "provider-training-evaluation"}
)
PROVIDER_PURPOSES = frozenset({"provider-evaluation", "provider-training-evaluation"})

MAX_CORPUS_BYTES = 100_000_000
MAX_CORPUS_RECORDS = 100_000
MAX_CORPUS_LINE_BYTES = 8_000_000
MAX_RELEASE_MANIFEST_BYTES = 16_000_000
MAX_REVIEW_ASSET_BYTES = 16_000_000
MAX_SOURCE_COUNT = 64
MAX_SOURCE_CHARACTERS = 500_000
MAX_AGGREGATE_SOURCE_CHARACTERS = 2_000_000
MAX_EVIDENCE_ITEMS = 128
MAX_EVIDENCE_CHARACTERS = 2_000

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RELEASE_ID_RE = re.compile(r"^vqrel-[0-9a-f]{64}$")
_ASSET_PATH_RE = re.compile(r"^evaluation/(?:rubrics|verifiers)/[0-9a-f]{64}\.bin$")
_CONTEXT_PACK_PATH_RE = re.compile(r"^evaluation/context-packs/[0-9a-f]{64}\.bin$")


@dataclass(frozen=True)
class ExpertCorpusRecord:
    document: dict[str, Any]
    cutoff: datetime
    verified_at: datetime


@dataclass(frozen=True)
class ExpertCorpus:
    path: Path
    raw: bytes
    sha256: str
    byte_count: int
    records: Mapping[str, ExpertCorpusRecord]


def _validate_identifier(value: Any, field: str) -> str:
    identifier = _string(value, field, max_length=200)
    if not _SAFE_ID_RE.fullmatch(identifier):
        _fail(field, "contains unsupported characters")
    return identifier


def _validate_rights(value: Any, field: str) -> dict[str, bool]:
    rights = _exact_keys(
        value,
        {
            "mayStore",
            "mayEvaluate",
            "mayTrain",
            "mayUploadToProvider",
            "mayRedistribute",
        },
        field,
    )
    for name, enabled in rights.items():
        if not isinstance(enabled, bool):
            _fail(f"{field}.{name}", "must be a boolean")
    return rights


def _validate_string_list(
    value: Any, field: str, *, required: bool = False
) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE_ITEMS:
        _fail(field, f"must be an array with at most {MAX_EVIDENCE_ITEMS} entries")
    if required and not value:
        _fail(field, "must not be empty")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(
            _string(item, f"{field}[{index}]", max_length=MAX_EVIDENCE_CHARACTERS)
        )
    return result


def _verification_evidence_sha256(
    evidence: list[str],
    compile_evidence: list[str],
    test_evidence: list[str],
) -> str:
    return _length_prefixed_sha256(
        "daxalgo-expert-verification-evidence/v1",
        [evidence, compile_evidence, test_evidence],
    )


def _validate_lineage(value: Any, field: str) -> tuple[dict[str, Any], datetime]:
    lineage = _exact_keys(
        value,
        {
            "origin",
            "producer",
            "modelId",
            "modelRevision",
            "promptSha256",
            "profileVersion",
            "producedAtUtc",
        },
        field,
    )
    origin = lineage["origin"]
    if origin not in ORIGINS:
        _fail(f"{field}.origin", "is not a supported ExpertDatasetOrigin")
    _string(lineage["producer"], f"{field}.producer", max_length=500)
    produced_at = _parse_datetime(lineage["producedAtUtc"], f"{field}.producedAtUtc")
    model_fields = ("modelId", "modelRevision", "promptSha256", "profileVersion")
    if origin == "HumanAuthored":
        if any(lineage[name] is not None for name in model_fields):
            _fail(field, "human-authored lineage must have null model fields")
    else:
        _string(lineage["modelId"], f"{field}.modelId", max_length=500)
        if origin == "OpenWeightTeacher":
            _revision(lineage["modelRevision"], f"{field}.modelRevision")
        else:
            _pinned_revision_label(lineage["modelRevision"], f"{field}.modelRevision")
        _sha256(lineage["promptSha256"], f"{field}.promptSha256")
        _string(lineage["profileVersion"], f"{field}.profileVersion", max_length=500)
    return lineage, produced_at


def _validate_verification(
    value: Any,
    field: str,
    *,
    task_kind: str,
    assistant_content: str,
) -> tuple[dict[str, Any], datetime]:
    verification = _exact_keys(
        value,
        {
            "verified",
            "reviewer",
            "verifiedAtUtc",
            "evidenceSha256",
            "evidence",
            "compileSucceeded",
            "compileEvidence",
            "testsPassed",
            "testEvidence",
        },
        field,
    )
    if verification["verified"] is not True:
        _fail(f"{field}.verified", "must be true for a release")
    _validate_identifier(verification["reviewer"], f"{field}.reviewer")
    verified_at = _parse_datetime(
        verification["verifiedAtUtc"], f"{field}.verifiedAtUtc"
    )
    evidence = _validate_string_list(
        verification["evidence"], f"{field}.evidence", required=True
    )
    compile_evidence = _validate_string_list(
        verification["compileEvidence"], f"{field}.compileEvidence"
    )
    test_evidence = _validate_string_list(
        verification["testEvidence"], f"{field}.testEvidence"
    )
    if not isinstance(verification["compileSucceeded"], bool) or not isinstance(
        verification["testsPassed"], bool
    ):
        _fail(field, "compileSucceeded and testsPassed must be booleans")
    expected = _verification_evidence_sha256(evidence, compile_evidence, test_evidence)
    if _sha256(verification["evidenceSha256"], f"{field}.evidenceSha256") != expected:
        _fail(
            f"{field}.evidenceSha256", "does not match the canonical evidence content"
        )
    if verification["compileSucceeded"] and not compile_evidence:
        _fail(f"{field}.compileEvidence", "is required after successful compilation")
    if verification["testsPassed"] and not test_evidence:
        _fail(f"{field}.testEvidence", "is required after passing tests")
    code_related = task_kind in {"CodeGeneration", "CodeRepair", "CodeReview"}
    if code_related and not (
        verification["compileSucceeded"]
        and compile_evidence
        and verification["testsPassed"]
        and test_evidence
    ):
        _fail(
            field,
            "code-related release examples require passing compile and test evidence",
        )
    if code_related:
        _validate_executable_code_evidence(
            compile_evidence,
            test_evidence,
            field,
            task_kind=task_kind,
            assistant_content=assistant_content,
        )
    return verification, verified_at


def _evidence_value(items: list[str], index: int, key: str, field: str) -> str:
    prefix = f"{key}="
    if index >= len(items) or not items[index].startswith(prefix):
        _fail(field, f"must contain {key} at position {index + 1}")
    value = items[index][len(prefix) :]
    if not value:
        _fail(field, f"{key} must not be empty")
    return value


def _validate_executable_code_evidence(
    compile_evidence: list[str],
    test_evidence: list[str],
    field: str,
    *,
    task_kind: str,
    assistant_content: str,
) -> None:
    if task_kind == "CodeReview":
        _fail(field, "CodeReview has no supported executable verifier profile")
    if len(compile_evidence) != 4:
        _fail(
            f"{field}.compileEvidence",
            "must contain exactly four executable-verifier entries",
        )
    profile = _evidence_value(
        compile_evidence, 0, "profile", f"{field}.compileEvidence"
    )
    source_sha256 = _evidence_value(
        compile_evidence, 1, "sourceSha256", f"{field}.compileEvidence"
    )
    compiler_closure_sha256 = _evidence_value(
        compile_evidence, 2, "compilerClosureSha256", f"{field}.compileEvidence"
    )
    canonical_program_sha256 = _evidence_value(
        compile_evidence, 3, "canonicalProgramSha256", f"{field}.compileEvidence"
    )
    if profile != DAXQ_EXECUTABLE_PROFILE:
        _fail(f"{field}.compileEvidence", "uses an unsupported executable profile")
    expected_source_sha256 = hashlib.sha256(
        assistant_content.encode("utf-8", errors="strict")
    ).hexdigest()
    if source_sha256 != expected_source_sha256:
        _fail(f"{field}.compileEvidence", "does not bind the exact assistant source")
    _sha256(compiler_closure_sha256, f"{field}.compileEvidence.compilerClosureSha256")
    _sha256(canonical_program_sha256, f"{field}.compileEvidence.canonicalProgramSha256")

    if len(test_evidence) != 5:
        _fail(
            f"{field}.testEvidence",
            "must contain exactly five executable-verifier entries",
        )
    _sha256(
        _evidence_value(
            test_evidence, 0, "testSpecificationSha256", f"{field}.testEvidence"
        ),
        f"{field}.testEvidence.testSpecificationSha256",
    )
    _sha256(
        _evidence_value(
            test_evidence, 1, "executionTraceSha256", f"{field}.testEvidence"
        ),
        f"{field}.testEvidence.executionTraceSha256",
    )
    _sha256(
        _evidence_value(
            test_evidence, 2, "executableResultSha256", f"{field}.testEvidence"
        ),
        f"{field}.testEvidence.executableResultSha256",
    )
    vector_count_text = _evidence_value(
        test_evidence, 3, "vectorCount", f"{field}.testEvidence"
    )
    callback_count_text = _evidence_value(
        test_evidence, 4, "callbackCount", f"{field}.testEvidence"
    )
    if not re.fullmatch(r"[1-9][0-9]*", vector_count_text) or not (
        1 <= int(vector_count_text) <= MAX_EXECUTABLE_VECTORS
    ):
        _fail(
            f"{field}.testEvidence.vectorCount",
            "is outside the executable-vector bound",
        )
    if not re.fullmatch(r"[1-9][0-9]*", callback_count_text) or not (
        1 <= int(callback_count_text) <= MAX_EXECUTABLE_CALLBACKS
    ):
        _fail(
            f"{field}.testEvidence.callbackCount",
            "is outside the executable-callback bound",
        )


def _validate_source(
    value: Any,
    field: str,
    *,
    split: str,
    cutoff: datetime,
) -> dict[str, Any]:
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
        field,
    )
    _validate_identifier(source["id"], f"{field}.id")
    _string(source["title"], f"{field}.title", max_length=500)
    _string(source["content"], f"{field}.content", max_length=MAX_SOURCE_CHARACTERS)
    _string(source["provenance"], f"{field}.provenance", max_length=2_000)
    _string(source["license"], f"{field}.license", max_length=500)
    retrieved_at = _parse_datetime(source["retrievedAtUtc"], f"{field}.retrievedAtUtc")
    if source["availableAtUtc"] is None:
        if split in {"calibration", "sealed"}:
            _fail(
                f"{field}.availableAtUtc",
                "is required for calibration and sealed examples",
            )
    else:
        available_at = _parse_datetime(
            source["availableAtUtc"], f"{field}.availableAtUtc"
        )
        if available_at > cutoff:
            _fail(f"{field}.availableAtUtc", "is later than the example cutoff")
        if available_at > retrieved_at:
            _fail(f"{field}.availableAtUtc", "is later than retrieval time")
    if source["uri"] is not None:
        _string(source["uri"], f"{field}.uri", max_length=2_048)
    rights = _validate_rights(source["rights"], f"{field}.rights")
    if not rights["mayStore"] or not rights["mayEvaluate"]:
        _fail(f"{field}.rights", "must permit storage and evaluation")
    return source


def _validate_corpus_record(value: Any, line_number: int) -> ExpertCorpusRecord:
    field = f"expert corpus line {line_number}"
    record = _exact_keys(
        value,
        {
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
        },
        field,
    )
    if record["schemaVersion"] != SOURCE_SCHEMA_VERSION:
        _fail(f"{field}.schemaVersion", f"must be {SOURCE_SCHEMA_VERSION!r}")
    _validate_identifier(record["id"], f"{field}.id")
    if record["taskKind"] not in TASK_KINDS:
        _fail(f"{field}.taskKind", "is not a supported ExpertTaskKind")
    domains = record["domains"]
    if (
        not isinstance(domains, list)
        or not domains
        or len(domains) != len(set(domains))
    ):
        _fail(f"{field}.domains", "must be a non-empty array without duplicates")
    if not all(isinstance(domain, str) and domain in DOMAINS for domain in domains):
        _fail(f"{field}.domains", "contains unsupported domain labels")
    messages = _validate_messages(record["messages"], f"{field}.messages")
    if _sha256(
        record["conversationSha256"], f"{field}.conversationSha256"
    ) != expert_conversation_sha256(messages):
        _fail(
            f"{field}.conversationSha256", "does not match the canonical conversation"
        )
    split = record["split"]
    if split not in SPLITS:
        _fail(f"{field}.split", "must be development, calibration, or sealed")
    _validate_identifier(record["contaminationGroup"], f"{field}.contaminationGroup")
    _string(record["provenance"], f"{field}.provenance", max_length=2_000)
    _string(record["license"], f"{field}.license", max_length=500)
    if record["reviewStatus"] != "approved":
        _fail(f"{field}.reviewStatus", "must be exactly 'approved' for a release")
    cutoff = _parse_datetime(record["cutoffUtc"], f"{field}.cutoffUtc")
    if cutoff > datetime.now(timezone.utc):
        _fail(f"{field}.cutoffUtc", "must not be in the future")
    if not isinstance(record["useForTraining"], bool):
        _fail(f"{field}.useForTraining", "must be a boolean")
    if record["useForTraining"] and split != "development":
        _fail(f"{field}.useForTraining", "may be true only for development examples")
    rights = _validate_rights(record["rights"], f"{field}.rights")
    if not rights["mayStore"] or not rights["mayEvaluate"]:
        _fail(f"{field}.rights", "must permit storage and evaluation")
    _, produced_at = _validate_lineage(record["lineage"], f"{field}.lineage")
    verification, verified_at = _validate_verification(
        record["verification"],
        f"{field}.verification",
        task_kind=record["taskKind"],
        assistant_content=messages[-1]["content"],
    )
    candidate_stable = CANDIDATE_STABLE_KNOWLEDGE_CLASS in verification["evidence"]
    retrieval_only = RETRIEVAL_ONLY_KNOWLEDGE_CLASS in verification["evidence"]
    if candidate_stable and retrieval_only:
        _fail(
            f"{field}.verification.evidence",
            "must declare only one knowledgeClass",
        )
    if retrieval_only and (record["useForTraining"] or rights["mayTrain"]):
        _fail(
            f"{field}.rights",
            "retrieval-only examples must not request or declare training rights",
        )
    if record["useForTraining"] and not candidate_stable:
        _fail(
            f"{field}.verification.evidence",
            "training examples must declare knowledgeClass=candidate-stable",
        )
    if verified_at < produced_at:
        _fail(
            f"{field}.verification.verifiedAtUtc", "must not precede lineage production"
        )
    sources = record["sources"]
    if not isinstance(sources, list) or len(sources) > MAX_SOURCE_COUNT:
        _fail(
            f"{field}.sources",
            f"must be an array with at most {MAX_SOURCE_COUNT} entries",
        )
    source_ids: set[str] = set()
    aggregate = 0
    for index, source_value in enumerate(sources):
        source = _validate_source(
            source_value,
            f"{field}.sources[{index}]",
            split=split,
            cutoff=cutoff,
        )
        if source["id"] in source_ids:
            _fail(f"{field}.sources[{index}].id", "duplicates an earlier source ID")
        source_ids.add(source["id"])
        if retrieval_only and source["rights"]["mayTrain"]:
            _fail(
                f"{field}.sources[{index}].rights",
                "retrieval-only sources must not declare training rights",
            )
        aggregate += len(source["content"])
    if aggregate > MAX_AGGREGATE_SOURCE_CHARACTERS:
        _fail(
            f"{field}.sources",
            f"content exceeds {MAX_AGGREGATE_SOURCE_CHARACTERS} characters",
        )
    return ExpertCorpusRecord(record, cutoff, verified_at)


def _parse_expert_corpus(path: Path) -> ExpertCorpus:
    resolved = _regular_file(path, "expert corpus")
    raw = _read_file_bounded(resolved, "expert corpus", MAX_CORPUS_BYTES)
    if not raw:
        _fail("expert corpus", "must not be empty")
    records: dict[str, ExpertCorpusRecord] = {}
    content_splits: dict[str, str] = {}
    group_splits: dict[str, str] = {}
    with io.BytesIO(raw) as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if line_number == 1 and raw_line.startswith(b"\xef\xbb\xbf"):
                _fail("expert corpus", "UTF-8 byte-order marks are not accepted")
            if len(raw_line) > MAX_CORPUS_LINE_BYTES:
                _fail(
                    f"expert corpus line {line_number}",
                    f"exceeds {MAX_CORPUS_LINE_BYTES} bytes",
                )
            try:
                text = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ValidationError(
                    f"expert corpus line {line_number}: invalid UTF-8 at byte {error.start}"
                ) from error
            if not text.strip():
                _fail(
                    f"expert corpus line {line_number}", "blank lines are not accepted"
                )
            try:
                value = json.loads(
                    text,
                    object_pairs_hook=_unique_pairs,
                    parse_constant=_reject_constant,
                )
            except json.JSONDecodeError as error:
                raise ValidationError(
                    f"expert corpus line {line_number}: invalid JSON at column {error.colno}: {error.msg}"
                ) from error
            record = _validate_corpus_record(value, line_number)
            example_id = record.document["id"]
            if example_id in records:
                _fail(
                    f"expert corpus line {line_number}.id",
                    "duplicates an earlier example ID",
                )
            if len(records) >= MAX_CORPUS_RECORDS:
                _fail("expert corpus", f"exceeds {MAX_CORPUS_RECORDS} records")
            conversation_hash = record.document["conversationSha256"]
            split = record.document["split"]
            prior_content_split = content_splits.get(conversation_hash)
            if prior_content_split is not None and prior_content_split != split:
                _fail(
                    f"expert corpus line {line_number}.conversationSha256",
                    "crosses split boundary",
                )
            group = record.document["contaminationGroup"]
            prior_group_split = group_splits.get(group)
            if prior_group_split is not None and prior_group_split != split:
                _fail(
                    f"expert corpus line {line_number}.contaminationGroup",
                    "crosses split boundary",
                )
            content_splits[conversation_hash] = split
            group_splits[group] = split
            records[example_id] = record
    return ExpertCorpus(
        path=resolved,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        byte_count=len(raw),
        records=records,
    )


def _rights_policy(purpose: str) -> dict[str, bool]:
    if purpose not in PURPOSES:
        _fail("release purpose", f"must be one of {sorted(PURPOSES)}")
    return {
        "requireStorage": True,
        "requireEvaluation": True,
        "requireTrainingForSft": purpose in TRAINING_PURPOSES,
        "requireProviderUploadForReleasedContent": purpose in PROVIDER_PURPOSES,
        "requireRedistribution": False,
    }


def _validate_file_binding(
    value: Any,
    field: str,
    *,
    expected_path: str | None = None,
) -> dict[str, Any]:
    binding = _exact_keys(value, {"path", "sha256", "sizeBytes"}, field)
    path = _string(binding["path"], f"{field}.path", max_length=500)
    if expected_path is not None and path != expected_path:
        _fail(f"{field}.path", f"must be {expected_path!r}")
    _sha256(binding["sha256"], f"{field}.sha256")
    if (
        not isinstance(binding["sizeBytes"], int)
        or isinstance(binding["sizeBytes"], bool)
        or binding["sizeBytes"] < 1
    ):
        _fail(f"{field}.sizeBytes", "must be a positive integer")
    return binding


def _validate_trust_identity(value: Any, field: str) -> dict[str, str]:
    identity = _exact_keys(
        value,
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        field,
    )
    return {
        "publicKeySpkiSha256": _sha256(
            identity["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256"
        ),
        "audience": _validate_identifier(identity["audience"], f"{field}.audience"),
        "keyId": _validate_identifier(identity["keyId"], f"{field}.keyId"),
        "signerRole": _validate_identifier(
            identity["signerRole"], f"{field}.signerRole"
        ),
    }


def _validate_review_receipt_binding(value: Any, field: str) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        {"path", "sha256", "sizeBytes", "recordCount", "expiresAtUtc", "trust"},
        field,
    )
    _validate_file_binding(
        {name: binding[name] for name in ("path", "sha256", "sizeBytes")},
        field,
        expected_path=REVIEW_RECEIPTS_PATH,
    )
    if (
        not isinstance(binding["recordCount"], int)
        or isinstance(binding["recordCount"], bool)
        or not 1 <= binding["recordCount"] <= MAX_CORPUS_RECORDS
    ):
        _fail(f"{field}.recordCount", "must be a positive bounded integer")
    _parse_datetime(
        binding["expiresAtUtc"],
        f"{field}.expiresAtUtc",
        require_utc_z=True,
        allow_future=True,
    )
    _validate_trust_identity(binding["trust"], f"{field}.trust")
    return binding


def _validate_teacher_lineage_admission_binding(
    value: Any, field: str
) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        {
            "path",
            "sha256",
            "sizeBytes",
            "lineageAdmissionId",
            "payloadSha256",
            "envelopeSha256",
            "materializationId",
            "reviewedCorpusSha256",
            "reviewedCorpusRecordCount",
            "openWeightTeacherRecordCount",
            "notBeforeUtc",
            "expiresAtUtc",
            "trust",
        },
        field,
    )
    _validate_file_binding(
        {name: binding[name] for name in ("path", "sha256", "sizeBytes")},
        field,
        expected_path=TEACHER_LINEAGE_ADMISSION_PATH,
    )
    if not isinstance(binding["lineageAdmissionId"], str) or not re.fullmatch(
        r"vqtlineage-[0-9a-f]{64}", binding["lineageAdmissionId"]
    ):
        _fail(
            f"{field}.lineageAdmissionId",
            "must be a content-derived teacher lineage admission ID",
        )
    for name in (
        "payloadSha256",
        "envelopeSha256",
        "reviewedCorpusSha256",
    ):
        _sha256(binding[name], f"{field}.{name}")
    if not isinstance(binding["materializationId"], str) or not re.fullmatch(
        r"vqtmat-[0-9a-f]{64}", binding["materializationId"]
    ):
        _fail(
            f"{field}.materializationId",
            "must be a content-derived teacher materialization ID",
        )
    for name, maximum in (
        ("reviewedCorpusRecordCount", MAX_CORPUS_RECORDS),
        ("openWeightTeacherRecordCount", 10_000),
    ):
        count = binding[name]
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= maximum
        ):
            _fail(f"{field}.{name}", "must be a positive bounded integer")
    for name in ("notBeforeUtc", "expiresAtUtc"):
        _parse_datetime(
            binding[name],
            f"{field}.{name}",
            require_utc_z=True,
            allow_future=True,
        )
    _validate_trust_identity(binding["trust"], f"{field}.trust")
    return binding


def _evaluation_authoring_trust_identity(
    trust: EvaluationAuthoringApprovalTrust,
) -> dict[str, str]:
    return {
        "publicKeySpkiSha256": trust.public_key_spki_sha256,
        "audience": trust.audience,
        "keyId": trust.key_id,
        "signerRole": trust.signer_role,
    }


def _validate_evaluation_authoring_approval_binding(
    value: Any, field: str
) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        {
            "path",
            "sha256",
            "sizeBytes",
            "authoringApprovalId",
            "payloadSha256",
            "envelopeSha256",
            "notBeforeUtc",
            "expiresAtUtc",
            "trust",
        },
        field,
    )
    _validate_file_binding(
        {name: binding[name] for name in ("path", "sha256", "sizeBytes")},
        field,
        expected_path=EVALUATION_AUTHORING_APPROVAL_PATH,
    )
    _validate_identifier(binding["authoringApprovalId"], f"{field}.authoringApprovalId")
    _sha256(binding["payloadSha256"], f"{field}.payloadSha256")
    _sha256(binding["envelopeSha256"], f"{field}.envelopeSha256")
    for name in ("notBeforeUtc", "expiresAtUtc"):
        _parse_datetime(
            binding[name],
            f"{field}.{name}",
            require_utc_z=True,
            allow_future=True,
        )
    _validate_trust_identity(binding["trust"], f"{field}.trust")
    return binding


def _validate_task_file_binding(
    value: Any, field: str, *, expected_path: str
) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        {"path", "sha256", "sizeBytes", "taskSetSha256", "recordCount"},
        field,
    )
    _validate_file_binding(
        {name: binding[name] for name in ("path", "sha256", "sizeBytes")},
        field,
        expected_path=expected_path,
    )
    _sha256(binding["taskSetSha256"], f"{field}.taskSetSha256")
    if (
        not isinstance(binding["recordCount"], int)
        or isinstance(binding["recordCount"], bool)
        or not 1 <= binding["recordCount"] <= MAX_CORPUS_RECORDS
    ):
        _fail(f"{field}.recordCount", "must be a positive bounded integer")
    return binding


def _release_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload["releaseId"] = "vqrel-" + "0" * 64
    payload["releaseSha256"] = "0" * 64
    schema_version = payload.get("schemaVersion")
    domains = {
        LEGACY_RELEASE_SCHEMA_VERSION: (
            "daxalgo-vibe-quant-corpus-evaluation-release-record/v3"
        ),
        RELEASE_SCHEMA_VERSION: (
            "daxalgo-vibe-quant-corpus-evaluation-release-record/v4"
        ),
    }
    domain = domains.get(schema_version)
    if domain is None:
        _fail(
            "release.schemaVersion",
            "must be a supported corpus-evaluation release schema version",
        )
    return _length_prefixed_sha256(
        domain,
        [[canonical_json_bytes(payload).decode("utf-8")]],
    )


def corpus_evaluation_release_sha256(value: Mapping[str, Any]) -> str:
    return _release_sha256(value)


def _resolve_task_binding_asset_path(
    value: Any,
    field: str,
    *,
    schema_version: str,
    asset_root: Path,
) -> str:
    asset_path = _string(value, field, max_length=4_096)
    if schema_version == TASK_BINDINGS_V2_SCHEMA_VERSION:
        if not _TASK_BINDINGS_V2_PATH_RE.fullmatch(asset_path):
            _fail(field, "must be a canonical contained forward-slash relative path")
        return str(resolve_bound_path(asset_root, asset_path, field))
    if not Path(asset_path).is_absolute():
        return str(resolve_bound_path(asset_root, asset_path, field))
    return asset_path


def _load_task_binding_input(
    path: Path, *, relative_asset_root: Path | None = None
) -> list[dict[str, Any]]:
    document = _exact_keys(
        load_json_document(path, max_bytes=MAX_RELEASE_MANIFEST_BYTES),
        {"schemaVersion", "bindings"},
        "release task bindings",
    )
    schema_version = document["schemaVersion"]
    if schema_version not in {
        TASK_BINDINGS_SCHEMA_VERSION,
        TASK_BINDINGS_V2_SCHEMA_VERSION,
    }:
        _fail(
            "release task bindings.schemaVersion",
            f"must be {TASK_BINDINGS_SCHEMA_VERSION!r} or "
            f"{TASK_BINDINGS_V2_SCHEMA_VERSION!r}",
        )
    bindings = document["bindings"]
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= MAX_TASK_BINDINGS:
        _fail(
            "release task bindings.bindings",
            f"must contain 1 to {MAX_TASK_BINDINGS} bindings",
        )
    asset_root = path.parent if relative_asset_root is None else relative_asset_root
    if schema_version == TASK_BINDINGS_SCHEMA_VERSION:
        asset_root = Path.cwd()
    result: list[dict[str, Any]] = []
    task_ids: set[str] = set()
    for index, value in enumerate(bindings):
        field = f"release task bindings.bindings[{index}]"
        binding = _exact_keys(
            value,
            {"taskId", "sourceExampleIds", "contextPack", "rubric", "verifier"},
            field,
        )
        task_id = _validate_identifier(binding["taskId"], f"{field}.taskId")
        if task_id in task_ids:
            _fail(f"{field}.taskId", "duplicates an earlier binding")
        task_ids.add(task_id)
        source_ids = binding["sourceExampleIds"]
        if (
            not isinstance(source_ids, list)
            or not 1 <= len(source_ids) <= MAX_SOURCE_EXAMPLE_IDS
            or len(source_ids) != len(set(source_ids))
        ):
            _fail(
                f"{field}.sourceExampleIds",
                f"must contain 1 to {MAX_SOURCE_EXAMPLE_IDS} unique source IDs",
            )
        for source_index, source_id in enumerate(source_ids):
            _validate_identifier(source_id, f"{field}.sourceExampleIds[{source_index}]")
        assets: dict[str, dict[str, str]] = {}
        for kind in ("rubric", "verifier"):
            asset = _exact_keys(binding[kind], {"id", "path"}, f"{field}.{kind}")
            asset_path = _resolve_task_binding_asset_path(
                asset["path"],
                f"{field}.{kind}.path",
                schema_version=schema_version,
                asset_root=asset_root,
            )
            assets[kind] = {
                "id": _validate_identifier(asset["id"], f"{field}.{kind}.id"),
                "path": asset_path,
            }
        context_pack = _exact_keys(
            binding["contextPack"], {"version", "path"}, f"{field}.contextPack"
        )
        context_path = _resolve_task_binding_asset_path(
            context_pack["path"],
            f"{field}.contextPack.path",
            schema_version=schema_version,
            asset_root=asset_root,
        )
        result.append(
            {
                "taskId": task_id,
                "sourceExampleIds": list(source_ids),
                "contextPack": {
                    "version": _pinned_revision_label(
                        context_pack["version"], f"{field}.contextPack.version"
                    ),
                    "path": context_path,
                },
                "rubric": assets["rubric"],
                "verifier": assets["verifier"],
            }
        )
    return sorted(result, key=lambda binding: binding["taskId"])


def _snapshot_review_asset(
    source: Path, stage: Path, kind: str, task_id: str
) -> dict[str, Any]:
    task_key = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
    relative = f"evaluation/{kind}s/{task_key}.bin"
    destination = stage.joinpath(*relative.split("/"))
    snapshot = _copy_file_snapshot(
        source,
        destination,
        f"{kind} for task {task_id}",
        max_bytes=MAX_REVIEW_ASSET_BYTES,
    )
    return {
        "path": relative,
        "sha256": sha256_file(snapshot, max_bytes=MAX_REVIEW_ASSET_BYTES),
        "sizeBytes": snapshot.stat().st_size,
    }


def _snapshot_binding_assets(
    input_bindings: list[dict[str, Any]],
    stage: Path,
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for binding in input_bindings:
        task_id = binding["taskId"]
        rubric_file = _snapshot_review_asset(
            Path(binding["rubric"]["path"]), stage, "rubric", task_id
        )
        verifier_file = _snapshot_review_asset(
            Path(binding["verifier"]["path"]), stage, "verifier", task_id
        )
        context_pack_file = _snapshot_review_asset(
            Path(binding["contextPack"]["path"]), stage, "context-pack", task_id
        )
        bindings.append(
            {
                "taskId": task_id,
                "taskSha256": "0" * 64,
                "sourceExampleIds": binding["sourceExampleIds"],
                "contextPack": {
                    "version": binding["contextPack"]["version"],
                    **context_pack_file,
                },
                "rubric": {"id": binding["rubric"]["id"], **rubric_file},
                "verifier": {"id": binding["verifier"]["id"], **verifier_file},
            }
        )
    return bindings


def _binding_for_file(path: Path, relative: str, *, limit: int) -> dict[str, Any]:
    return {
        "path": relative,
        "sha256": sha256_file(path, max_bytes=limit),
        "sizeBytes": path.stat().st_size,
    }


def _binding_for_tasks(tasks: EvaluationTaskSet, relative: str) -> dict[str, Any]:
    return {
        "path": relative,
        "sha256": tasks.sha256,
        "sizeBytes": tasks.path.stat().st_size,
        "taskSetSha256": tasks.task_set_sha256,
        "recordCount": len(tasks.records),
    }


def _evaluation_authoring_inventory_from_release(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    source = document["corpus"]["sourceDataset"]
    evaluation = document["evaluation"]

    def file_inventory(binding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "sha256": binding["sha256"],
            "sizeBytes": binding["sizeBytes"],
            "recordCount": binding["recordCount"],
        }

    def task_file_inventory(binding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **file_inventory(binding),
            "taskSetSha256": binding["taskSetSha256"],
        }

    task_bindings = []
    for binding in evaluation["taskBindings"]:
        task_bindings.append(
            {
                "taskId": binding["taskId"],
                "taskSha256": binding["taskSha256"],
                "sourceExampleIds": binding["sourceExampleIds"],
                "contextPack": {
                    "version": binding["contextPack"]["version"],
                    "sha256": binding["contextPack"]["sha256"],
                    "sizeBytes": binding["contextPack"]["sizeBytes"],
                },
                "rubric": {
                    "id": binding["rubric"]["id"],
                    "sha256": binding["rubric"]["sha256"],
                    "sizeBytes": binding["rubric"]["sizeBytes"],
                },
                "verifier": {
                    "id": binding["verifier"]["id"],
                    "sha256": binding["verifier"]["sha256"],
                    "sizeBytes": binding["verifier"]["sizeBytes"],
                },
            }
        )
    return {
        "sourceDataset": file_inventory(source),
        "calibrationTasks": task_file_inventory(evaluation["calibrationTasks"]),
        "sealedTasks": task_file_inventory(evaluation["sealedTasks"]),
        "taskBindings": task_bindings,
    }


def _verify_bound_file(
    root: Path, binding: Mapping[str, Any], field: str, *, limit: int
) -> Path:
    path = resolve_bound_path(root, binding["path"], f"{field}.path")
    if path.stat().st_size != binding["sizeBytes"]:
        _fail(f"{field}.sizeBytes", "does not match the bound file")
    if sha256_file(path, max_bytes=limit) != binding["sha256"]:
        _fail(f"{field}.sha256", "does not match the bound file bytes")
    return path


def _release_validation_time(now: datetime | None) -> datetime:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        _fail("release validation time", "must include a UTC offset")
    return current.astimezone(timezone.utc)


def _parse_release_sft_rows(
    raw: bytes, *, release_schema_version: str
) -> list[dict[str, Any]]:
    if not raw:
        _fail("release SFT file", "must not be empty")
    if len(raw) > MAX_SFT_BYTES:
        _fail("release SFT file", f"exceeds {MAX_SFT_BYTES} bytes")
    metadata_keys = {
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
    if release_schema_version == RELEASE_SCHEMA_VERSION:
        metadata_keys |= {
            "schemaVersion",
            "sourceCorpusSha256",
            "verificationEvidenceSha256",
        }
    elif release_schema_version != LEGACY_RELEASE_SCHEMA_VERSION:
        _fail("release schemaVersion for SFT parsing", "is unsupported")
    rows: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    with io.BytesIO(raw) as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            field = f"release SFT line {line_number}"
            if line_number == 1 and raw_line.startswith(b"\xef\xbb\xbf"):
                _fail("release SFT file", "UTF-8 byte-order marks are not accepted")
            if len(raw_line) > MAX_SFT_LINE_BYTES:
                _fail(field, f"exceeds {MAX_SFT_LINE_BYTES} bytes")
            try:
                text = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ValidationError(
                    f"{field}: invalid UTF-8 at byte {error.start}"
                ) from error
            if not text.strip():
                _fail(field, "blank lines are not accepted")
            try:
                value = json.loads(
                    text,
                    object_pairs_hook=_unique_pairs,
                    parse_constant=_reject_constant,
                )
            except (json.JSONDecodeError, RecursionError) as error:
                raise ValidationError(
                    f"{field}: invalid bounded JSON: {error}"
                ) from error
            row = _exact_keys(value, {"messages", "metadata"}, field)
            messages = _validate_messages(row["messages"], f"{field}.messages")
            metadata = _exact_keys(row["metadata"], metadata_keys, f"{field}.metadata")
            if release_schema_version == RELEASE_SCHEMA_VERSION:
                if metadata["schemaVersion"] != SFT_METADATA_SCHEMA_VERSION:
                    _fail(
                        f"{field}.metadata.schemaVersion",
                        f"must be {SFT_METADATA_SCHEMA_VERSION!r}",
                    )
                _sha256(
                    metadata["sourceCorpusSha256"],
                    f"{field}.metadata.sourceCorpusSha256",
                )
                _sha256(
                    metadata["verificationEvidenceSha256"],
                    f"{field}.metadata.verificationEvidenceSha256",
                )
            example_id = _validate_identifier(metadata["id"], f"{field}.metadata.id")
            if example_id in identifiers:
                _fail(f"{field}.metadata.id", "duplicates an earlier SFT row")
            identifiers.add(example_id)
            if len(rows) >= MAX_SFT_RECORDS:
                _fail("release SFT file", f"exceeds {MAX_SFT_RECORDS} records")
            rows.append({"messages": messages, "metadata": metadata})
    return rows


def _require_rights(
    record: ExpertCorpusRecord, *, train: bool, provider: bool, field: str
) -> None:
    values = [("example", record.document["rights"])]
    values.extend(
        (f"source {source['id']}", source["rights"])
        for source in record.document["sources"]
    )
    for label, rights in values:
        if train and not rights["mayTrain"]:
            _fail(field, f"{label} lacks training rights")
        if provider and not rights["mayUploadToProvider"]:
            _fail(field, f"{label} lacks provider-upload rights")


def _cross_validate_release(
    document: Mapping[str, Any],
    root: Path,
    *,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    now: datetime | None,
) -> set[str]:
    current = _release_validation_time(now)
    corpus_binding = document["corpus"]["sourceDataset"]
    corpus_path = _verify_bound_file(
        root, corpus_binding, "release.corpus.sourceDataset", limit=MAX_CORPUS_BYTES
    )
    corpus = _parse_expert_corpus(corpus_path)
    if (
        corpus.sha256 != corpus_binding["sha256"]
        or corpus.byte_count != corpus_binding["sizeBytes"]
    ):
        _fail(
            "release.corpus.sourceDataset",
            "parsed corpus bytes do not match the bound file",
        )
    if len(corpus.records) != corpus_binding["recordCount"]:
        _fail("release.corpus.sourceDataset.recordCount", "does not match the corpus")
    teacher_record_count = sum(
        record.document["lineage"]["origin"] == "OpenWeightTeacher"
        for record in corpus.records.values()
    )
    non_human_record_count = sum(
        record.document["lineage"]["origin"] != "HumanAuthored"
        for record in corpus.records.values()
    )
    lineage_binding = document["corpus"].get("teacherLineageAdmission")
    lineage_trust = review_receipt_trust.teacher_lineage_admission_trust
    lineage_path: Path | None = None
    if document["schemaVersion"] == LEGACY_RELEASE_SCHEMA_VERSION:
        if non_human_record_count:
            _fail(
                "release.schemaVersion",
                "legacy v3 releases require an all-HumanAuthored corpus",
            )
        if lineage_trust is not None:
            _fail(
                "teacher lineage admission trust",
                "is not accepted for a HumanAuthored-only legacy v3 release",
            )
    elif teacher_record_count:
        if lineage_binding is None or lineage_trust is None:
            _fail(
                "release.corpus.teacherLineageAdmission",
                "and externally pinned trust are required for OpenWeightTeacher rows",
            )
        if lineage_binding["trust"] != lineage_trust.manifest_identity():
            _fail(
                "release.corpus.teacherLineageAdmission.trust",
                "does not match the externally supplied lineage trust identity",
            )
        from .teacher_lineage import MAX_TEACHER_LINEAGE_ADMISSION_BYTES

        lineage_path = _verify_bound_file(
            root,
            lineage_binding,
            "release.corpus.teacherLineageAdmission",
            limit=MAX_TEACHER_LINEAGE_ADMISSION_BYTES,
        )
    elif lineage_binding is not None or lineage_trust is not None:
        _fail(
            "release.corpus.teacherLineageAdmission",
            "must be null with no lineage trust for a HumanAuthored-only corpus",
        )
    receipt_binding = document["corpus"]["reviewReceipts"]
    if receipt_binding["trust"] != review_receipt_trust.manifest_identity():
        _fail(
            "release.corpus.reviewReceipts.trust",
            "does not match the externally supplied receipt trust identity",
        )
    receipt_path = _verify_bound_file(
        root,
        receipt_binding,
        "release.corpus.reviewReceipts",
        limit=MAX_REVIEW_RECEIPT_SET_BYTES,
    )
    verified_receipts = validate_expert_model_review_receipts(
        receipt_path,
        dataset_path=corpus_path,
        public_key_path=review_receipt_trust.public_key_path,
        expected_public_key_spki_sha256=(review_receipt_trust.public_key_spki_sha256),
        expected_audience=review_receipt_trust.audience,
        expected_key_id=review_receipt_trust.key_id,
        expected_signer_role=review_receipt_trust.signer_role,
        teacher_lineage_admission_path=lineage_path,
        teacher_lineage_admission_trust=lineage_trust,
        now=current,
        _corpus_snapshot=corpus,
        _allow_release_bound_teacher_lineage=True,
        _required_schema_version=(
            REVIEW_RECEIPT_SCHEMA_VERSION
            if document["schemaVersion"] == RELEASE_SCHEMA_VERSION
            else LEGACY_REVIEW_RECEIPT_SCHEMA_VERSION
        ),
    )
    verified_lineage = verified_receipts.teacher_lineage_admission
    if lineage_binding is not None:
        if verified_lineage is None:
            _fail(
                "release.corpus.teacherLineageAdmission",
                "did not verify for the exact released corpus",
            )
        reviewed = verified_lineage.payload["reviewedCorpus"]
        expected_lineage_binding = {
            "lineageAdmissionId": verified_lineage.payload["lineageAdmissionId"],
            "payloadSha256": verified_lineage.payload_sha256,
            "envelopeSha256": verified_lineage.envelope_sha256,
            "materializationId": verified_lineage.payload["materialization"][
                "materializationId"
            ],
            "reviewedCorpusSha256": reviewed["sha256"],
            "reviewedCorpusRecordCount": reviewed["recordCount"],
            "openWeightTeacherRecordCount": reviewed["openWeightTeacherRecordCount"],
            "notBeforeUtc": verified_lineage.payload["notBeforeUtc"],
            "expiresAtUtc": verified_lineage.payload["expiresAtUtc"],
            "trust": lineage_trust.manifest_identity(),
        }
        for name, expected in expected_lineage_binding.items():
            if lineage_binding[name] != expected:
                _fail(
                    f"release.corpus.teacherLineageAdmission.{name}",
                    "does not match the authenticated lineage admission",
                )
    if verified_receipts.receipt_set_sha256 != receipt_binding["sha256"]:
        _fail(
            "release.corpus.reviewReceipts.sha256",
            "does not match the verified receipt set",
        )
    if verified_receipts.receipt_count != receipt_binding["recordCount"]:
        _fail(
            "release.corpus.reviewReceipts.recordCount",
            "does not match the verified receipt set",
        )
    if receipt_binding["recordCount"] != corpus_binding["recordCount"]:
        _fail(
            "release.corpus.reviewReceipts.recordCount",
            "must equal the source corpus record count",
        )
    if verified_receipts.expires_at_utc != receipt_binding["expiresAtUtc"]:
        _fail(
            "release.corpus.reviewReceipts.expiresAtUtc",
            "does not match the earliest authenticated receipt expiry",
        )
    receipts_by_id = {
        receipt.payload["exampleId"]: receipt for receipt in verified_receipts.receipts
    }
    for example_id, receipt in receipts_by_id.items():
        if receipt.payload["authorizations"]["evaluation"] is not True:
            _fail(
                f"release.corpus.reviewReceipts[{example_id}].authorizations.evaluation",
                "must authorize evaluation for every released corpus row",
            )
    release_cutoff = _parse_datetime(
        document["cutoffUtc"], "release.cutoffUtc", require_utc_z=True
    )
    if any(record.cutoff > release_cutoff for record in corpus.records.values()):
        _fail("release.cutoffUtc", "precedes an included corpus cutoff")

    purpose = document["purpose"]
    training = purpose in TRAINING_PURPOSES
    provider = purpose in PROVIDER_PURPOSES
    sft_binding = document["corpus"]["sft"]
    expected_files = {
        RELEASE_MANIFEST_PATH,
        corpus_binding["path"],
        receipt_binding["path"],
    }
    if lineage_binding is not None:
        expected_files.add(lineage_binding["path"])
    if training and sft_binding is None:
        _fail("release.corpus.sft", "is required for a training release")
    if not training and sft_binding is not None:
        _fail("release.corpus.sft", "must be null for an evaluation-only release")
    if sft_binding is not None:
        sft_path = _verify_bound_file(
            root, sft_binding, "release.corpus.sft", limit=MAX_SFT_BYTES
        )
        expected_files.add(sft_binding["path"])
        raw = _read_file_bounded(sft_path, "release SFT file", MAX_SFT_BYTES)
        actual_sft_hash = hashlib.sha256(raw).hexdigest()
        if (
            actual_sft_hash != sft_binding["sha256"]
            or len(raw) != sft_binding["sizeBytes"]
        ):
            _fail(
                "release.corpus.sft",
                "parsed SFT bytes do not match the bound file",
            )
        rows = _parse_release_sft_rows(
            raw, release_schema_version=document["schemaVersion"]
        )
        if len(rows) != sft_binding["recordCount"]:
            _fail("release.corpus.sft.recordCount", "does not match the SFT file")
        expected_training_ids = [
            example_id
            for example_id, record in corpus.records.items()
            if record.document["useForTraining"]
        ]
        actual_training_ids = [row["metadata"]["id"] for row in rows]
        if actual_training_ids != expected_training_ids:
            _fail(
                "release.corpus.sft",
                "must contain every opted-in corpus row in exact source order",
            )
        for row in rows:
            metadata = row["metadata"]
            record = corpus.records[metadata["id"]]
            source = record.document
            normalized_metadata = dict(metadata)
            normalized_metadata["cutoffUtc"] = normalize_sft_cutoff_utc(
                metadata["cutoffUtc"]
            )
            expected_metadata = (
                expert_model_sft_metadata(
                    source,
                    source_corpus_sha256=corpus.sha256,
                )
                if document["schemaVersion"] == RELEASE_SCHEMA_VERSION
                else legacy_expert_model_sft_metadata(source)
            )
            for name, expected_value in expected_metadata.items():
                if normalized_metadata[name] != expected_value:
                    _fail(
                        f"release.corpus.sft[{metadata['id']}].{name}",
                        "does not match the rights-bearing corpus",
                    )
            if row["messages"] != source["messages"]:
                _fail(
                    f"release.corpus.sft[{metadata['id']}].messages",
                    "do not match the exact receipt-bound conversation",
                )
            receipt = receipts_by_id[metadata["id"]]
            actual_metadata_sha256 = hashlib.sha256(
                canonical_json_bytes(normalized_metadata)
            ).hexdigest()
            if receipt.payload["sftMetadataSha256"] != actual_metadata_sha256:
                _fail(
                    f"release.corpus.sft[{metadata['id']}].sftMetadataSha256",
                    "does not match the authenticated review receipt",
                )
            if receipt.payload["authorizations"]["training"] is not True:
                _fail(
                    f"release.corpus.reviewReceipts[{metadata['id']}].authorizations.training",
                    "must authorize every released SFT row",
                )
            if provider and (
                receipt.payload["authorizations"]["providerUpload"] is not True
            ):
                _fail(
                    f"release.corpus.reviewReceipts[{metadata['id']}].authorizations.providerUpload",
                    "must authorize every provider-training SFT row",
                )
            _require_rights(
                record,
                train=True,
                provider=provider,
                field=f"release SFT row {metadata['id']}",
            )

    evaluation = document["evaluation"]
    calibration_binding = evaluation["calibrationTasks"]
    sealed_binding = evaluation["sealedTasks"]
    calibration_path = _verify_bound_file(
        root,
        calibration_binding,
        "release.evaluation.calibrationTasks",
        limit=MAX_CORPUS_BYTES,
    )
    sealed_path = _verify_bound_file(
        root, sealed_binding, "release.evaluation.sealedTasks", limit=MAX_CORPUS_BYTES
    )
    expected_files.update({calibration_binding["path"], sealed_binding["path"]})
    calibration = validate_evaluation_tasks(calibration_path)
    sealed = validate_evaluation_tasks(sealed_path)
    if {task["split"] for task in calibration.records} != {"calibration"}:
        _fail(
            "release.evaluation.calibrationTasks", "must contain calibration tasks only"
        )
    if {task["split"] for task in sealed.records} != {"sealed"}:
        _fail("release.evaluation.sealedTasks", "must contain sealed tasks only")
    for binding, tasks, field in (
        (calibration_binding, calibration, "release.evaluation.calibrationTasks"),
        (sealed_binding, sealed, "release.evaluation.sealedTasks"),
    ):
        if (
            tasks.sha256 != binding["sha256"]
            or tasks.task_set_sha256 != binding["taskSetSha256"]
        ):
            _fail(field, "task file or semantic task-set identity does not match")
        if len(tasks.records) != binding["recordCount"]:
            _fail(f"{field}.recordCount", "does not match the task file")
    if {task["promptSha256"] for task in calibration.records} & {
        task["promptSha256"] for task in sealed.records
    }:
        _fail("release.evaluation", "calibration and sealed prompts overlap")
    if {task["contaminationGroup"] for task in calibration.records} & {
        task["contaminationGroup"] for task in sealed.records
    }:
        _fail(
            "release.evaluation", "calibration and sealed contamination groups overlap"
        )

    task_map = {
        task["taskId"]: task for task in (*calibration.records, *sealed.records)
    }
    bindings = evaluation["taskBindings"]
    if {binding["taskId"] for binding in bindings} != set(task_map):
        _fail(
            "release.evaluation.taskBindings",
            "must cover every released task exactly once",
        )
    for index, binding in enumerate(bindings):
        field = f"release.evaluation.taskBindings[{index}]"
        task = task_map[binding["taskId"]]
        if binding["taskSha256"] != task["taskSha256"]:
            _fail(f"{field}.taskSha256", "does not match the released task")
        task_cutoff = _parse_datetime(
            task["cutoffUtc"], f"{field}.taskCutoff", require_utc_z=True
        )
        if task_cutoff > release_cutoff:
            _fail(f"{field}.taskCutoff", "is later than the release cutoff")
        source_records: list[ExpertCorpusRecord] = []
        for source_id in binding["sourceExampleIds"]:
            record = corpus.records.get(source_id)
            if record is None:
                _fail(
                    f"{field}.sourceExampleIds",
                    f"references unknown corpus example {source_id!r}",
                )
            if record.document["split"] != task["split"]:
                _fail(
                    f"{field}.sourceExampleIds",
                    f"example {source_id!r} has the wrong split",
                )
            if record.cutoff != task_cutoff:
                _fail(
                    f"{field}.sourceExampleIds",
                    f"example {source_id!r} has a different cutoff",
                )
            _require_rights(
                record,
                train=False,
                provider=provider,
                field=f"released task {task['taskId']}",
            )
            source_records.append(record)
        primary = source_records[0].document
        if primary["messages"][:-1] != task["messages"]:
            _fail(
                f"{field}.sourceExampleIds[0]",
                "does not provide the exact released prompt",
            )
        if (
            primary["taskKind"] != task["taskKind"]
            or primary["domains"] != task["domains"]
        ):
            _fail(
                f"{field}.sourceExampleIds[0]",
                "task kind or domains differ from the released task",
            )
        rubric = binding["rubric"]
        verifier = binding["verifier"]
        context_pack = binding["contextPack"]
        _verify_bound_file(
            root, rubric, f"{field}.rubric", limit=MAX_REVIEW_ASSET_BYTES
        )
        _verify_bound_file(
            root, verifier, f"{field}.verifier", limit=MAX_REVIEW_ASSET_BYTES
        )
        _verify_bound_file(
            root,
            context_pack,
            f"{field}.contextPack",
            limit=MAX_REVIEW_ASSET_BYTES,
        )
        expected_files.update({rubric["path"], verifier["path"], context_pack["path"]})
        if context_pack["version"] != task["contextPack"]["version"]:
            _fail(
                f"{field}.contextPack.version",
                "does not match the task context-pack version",
            )
        if context_pack["sha256"] != task["contextPack"]["sha256"]:
            _fail(
                f"{field}.contextPack.sha256",
                "does not match the exact task context-pack bytes",
            )
        if verifier["id"] != task["verifier"]["id"]:
            _fail(f"{field}.verifier.id", "does not match the task verifier ID")
        if verifier["sha256"] != task["verifier"]["sha256"]:
            _fail(
                f"{field}.verifier.sha256",
                "does not match the exact task verifier bytes",
            )

    authoring_binding = evaluation["authoringApproval"]
    authoring_trust_identity = _evaluation_authoring_trust_identity(
        evaluation_authoring_approval_trust
    )
    if authoring_binding["trust"] != authoring_trust_identity:
        _fail(
            "release.evaluation.authoringApproval.trust",
            "does not match the externally supplied authoring-approval trust identity",
        )
    if (
        authoring_trust_identity["publicKeySpkiSha256"]
        == review_receipt_trust.public_key_spki_sha256
    ):
        _fail(
            "release evaluation-authoring approval signer",
            "must differ from the expert review-receipt signer",
        )
    authoring_path = _verify_bound_file(
        root,
        authoring_binding,
        "release.evaluation.authoringApproval",
        limit=MAX_EVALUATION_AUTHORING_APPROVAL_BYTES,
    )
    expected_files.add(authoring_binding["path"])
    verified_authoring = validate_evaluation_authoring_approval(
        authoring_path,
        trust=evaluation_authoring_approval_trust,
        expected_envelope_sha256=authoring_binding["envelopeSha256"],
        now=current,
    )
    signed_identity = {
        "authoringApprovalId": verified_authoring.payload["authoringApprovalId"],
        "payloadSha256": verified_authoring.payload_sha256,
        "envelopeSha256": verified_authoring.envelope_sha256,
        "notBeforeUtc": verified_authoring.payload["notBeforeUtc"],
        "expiresAtUtc": verified_authoring.payload["expiresAtUtc"],
    }
    manifested_identity = {name: authoring_binding[name] for name in signed_identity}
    if manifested_identity != signed_identity:
        _fail(
            "release.evaluation.authoringApproval",
            "does not match the verified signed approval identity",
        )
    if verified_authoring.payload[
        "inventory"
    ] != _evaluation_authoring_inventory_from_release(document):
        _fail(
            "release.evaluation.authoringApproval.inventory",
            "does not match the exact released evaluation-authoring inventory",
        )

    approval = document["approval"]
    evidence_path = _verify_bound_file(
        root,
        approval["evidence"],
        "release.approval.evidence",
        limit=MAX_REVIEW_ASSET_BYTES,
    )
    expected_files.add(approval["evidence"]["path"])
    if evidence_path.stat().st_size == 0:
        _fail("release.approval.evidence", "must not be empty")
    approved_at = _parse_datetime(
        approval["approvedAtUtc"], "release.approval.approvedAtUtc", require_utc_z=True
    )
    if approved_at > current:
        _fail("release.approval.approvedAtUtc", "must not be in the future")
    if approved_at < release_cutoff:
        _fail("release.approval.approvedAtUtc", "must not precede the declared cutoff")
    if approved_at < verified_authoring.not_before_utc:
        _fail(
            "release.approval.approvedAtUtc",
            "must not precede the signed evaluation-authoring approval activation",
        )
    if any(record.verified_at > approved_at for record in corpus.records.values()):
        _fail(
            "release.approval.approvedAtUtc",
            "precedes an included example verification",
        )
    return expected_files


def _validate_release_document(value: Any) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {
            "schemaVersion",
            "releaseId",
            "releaseSha256",
            "purpose",
            "cutoffUtc",
            "rightsPolicy",
            "corpus",
            "evaluation",
            "approval",
        },
        "release",
    )
    if document["schemaVersion"] not in {
        LEGACY_RELEASE_SCHEMA_VERSION,
        RELEASE_SCHEMA_VERSION,
    }:
        _fail(
            "release.schemaVersion",
            "must be a supported corpus-evaluation release schema version",
        )
    if not isinstance(document["releaseId"], str) or not _RELEASE_ID_RE.fullmatch(
        document["releaseId"]
    ):
        _fail(
            "release.releaseId",
            "must have form 'vqrel-' followed by 64 lowercase hex characters",
        )
    release_hash = _sha256(document["releaseSha256"], "release.releaseSha256")
    if document["purpose"] not in PURPOSES:
        _fail("release.purpose", f"must be one of {sorted(PURPOSES)}")
    _parse_datetime(document["cutoffUtc"], "release.cutoffUtc", require_utc_z=True)
    rights_policy = _exact_keys(
        document["rightsPolicy"],
        {
            "requireStorage",
            "requireEvaluation",
            "requireTrainingForSft",
            "requireProviderUploadForReleasedContent",
            "requireRedistribution",
        },
        "release.rightsPolicy",
    )
    expected_rights_policy = _rights_policy(document["purpose"])
    if any(
        type(rights_policy[name]) is not bool or rights_policy[name] != expected_value
        for name, expected_value in expected_rights_policy.items()
    ):
        _fail("release.rightsPolicy", "does not match the selected release purpose")
    corpus_keys = {"sourceDataset", "reviewReceipts", "sft"}
    if document["schemaVersion"] == RELEASE_SCHEMA_VERSION:
        corpus_keys.add("teacherLineageAdmission")
    corpus = _exact_keys(document["corpus"], corpus_keys, "release.corpus")
    source_binding = _exact_keys(
        corpus["sourceDataset"],
        {"path", "sha256", "sizeBytes", "recordCount"},
        "release.corpus.sourceDataset",
    )
    _validate_file_binding(
        {name: source_binding[name] for name in ("path", "sha256", "sizeBytes")},
        "release.corpus.sourceDataset",
        expected_path=CORPUS_PATH,
    )
    if (
        not isinstance(source_binding["recordCount"], int)
        or isinstance(source_binding["recordCount"], bool)
        or not 1 <= source_binding["recordCount"] <= MAX_CORPUS_RECORDS
    ):
        _fail(
            "release.corpus.sourceDataset.recordCount",
            "must be a positive bounded integer",
        )
    _validate_review_receipt_binding(
        corpus["reviewReceipts"], "release.corpus.reviewReceipts"
    )
    if (
        document["schemaVersion"] == RELEASE_SCHEMA_VERSION
        and corpus["teacherLineageAdmission"] is not None
    ):
        _validate_teacher_lineage_admission_binding(
            corpus["teacherLineageAdmission"],
            "release.corpus.teacherLineageAdmission",
        )
    if corpus["sft"] is not None:
        sft = _exact_keys(
            corpus["sft"],
            {"path", "sha256", "sizeBytes", "recordCount"},
            "release.corpus.sft",
        )
        _validate_file_binding(
            {name: sft[name] for name in ("path", "sha256", "sizeBytes")},
            "release.corpus.sft",
            expected_path=SFT_PATH,
        )
        if (
            not isinstance(sft["recordCount"], int)
            or isinstance(sft["recordCount"], bool)
            or not 1 <= sft["recordCount"] <= MAX_SFT_RECORDS
        ):
            _fail(
                "release.corpus.sft.recordCount", "must be a positive bounded integer"
            )
    evaluation = _exact_keys(
        document["evaluation"],
        {
            "calibrationTasks",
            "sealedTasks",
            "taskBindings",
            "authoringApproval",
        },
        "release.evaluation",
    )
    _validate_task_file_binding(
        evaluation["calibrationTasks"],
        "release.evaluation.calibrationTasks",
        expected_path=CALIBRATION_TASKS_PATH,
    )
    _validate_task_file_binding(
        evaluation["sealedTasks"],
        "release.evaluation.sealedTasks",
        expected_path=SEALED_TASKS_PATH,
    )
    bindings = evaluation["taskBindings"]
    if not isinstance(bindings, list) or not bindings:
        _fail("release.evaluation.taskBindings", "must be a non-empty array")
    task_ids: list[str] = []
    for index, value in enumerate(bindings):
        field = f"release.evaluation.taskBindings[{index}]"
        binding = _exact_keys(
            value,
            {
                "taskId",
                "taskSha256",
                "sourceExampleIds",
                "contextPack",
                "rubric",
                "verifier",
            },
            field,
        )
        task_ids.append(_validate_identifier(binding["taskId"], f"{field}.taskId"))
        _sha256(binding["taskSha256"], f"{field}.taskSha256")
        source_ids = binding["sourceExampleIds"]
        if (
            not isinstance(source_ids, list)
            or not source_ids
            or source_ids != sorted(set(source_ids))
        ):
            _fail(
                f"{field}.sourceExampleIds",
                "must be a non-empty sorted array without duplicates",
            )
        for source_index, source_id in enumerate(source_ids):
            _validate_identifier(source_id, f"{field}.sourceExampleIds[{source_index}]")
        for kind in ("rubric", "verifier"):
            asset = _exact_keys(
                binding[kind], {"id", "path", "sha256", "sizeBytes"}, f"{field}.{kind}"
            )
            _validate_identifier(asset["id"], f"{field}.{kind}.id")
            _validate_file_binding(
                {name: asset[name] for name in ("path", "sha256", "sizeBytes")},
                f"{field}.{kind}",
            )
            if not _ASSET_PATH_RE.fullmatch(asset["path"]):
                _fail(
                    f"{field}.{kind}.path",
                    "must use the fixed content bundle asset form",
                )
        context_pack = _exact_keys(
            binding["contextPack"],
            {"version", "path", "sha256", "sizeBytes"},
            f"{field}.contextPack",
        )
        _pinned_revision_label(context_pack["version"], f"{field}.contextPack.version")
        _validate_file_binding(
            {name: context_pack[name] for name in ("path", "sha256", "sizeBytes")},
            f"{field}.contextPack",
        )
        if not _CONTEXT_PACK_PATH_RE.fullmatch(context_pack["path"]):
            _fail(
                f"{field}.contextPack.path",
                "must use the fixed context-pack bundle asset form",
            )
    if task_ids != sorted(set(task_ids)):
        _fail("release.evaluation.taskBindings", "must be sorted by unique taskId")
    _validate_evaluation_authoring_approval_binding(
        evaluation["authoringApproval"],
        "release.evaluation.authoringApproval",
    )
    approval = _exact_keys(
        document["approval"],
        {
            "status",
            "declarativeOnly",
            "approvalId",
            "reviewerId",
            "approvedAtUtc",
            "evidence",
        },
        "release.approval",
    )
    if approval["status"] != "approved" or approval["declarativeOnly"] is not True:
        _fail("release.approval", "must be an approved declarative review record")
    _validate_identifier(approval["approvalId"], "release.approval.approvalId")
    _validate_identifier(approval["reviewerId"], "release.approval.reviewerId")
    _parse_datetime(
        approval["approvedAtUtc"], "release.approval.approvedAtUtc", require_utc_z=True
    )
    _validate_file_binding(
        approval["evidence"],
        "release.approval.evidence",
        expected_path=APPROVAL_EVIDENCE_PATH,
    )
    expected_hash = _release_sha256(document)
    if release_hash != expected_hash:
        _fail("release.releaseSha256", "does not match the canonical release")
    if document["releaseId"] != f"vqrel-{expected_hash}":
        _fail("release.releaseId", "does not match the canonical release hash")
    return document


def _enumerate_release_files(root: Path) -> set[str]:
    files: set[str] = set()

    def visit(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_stat = entry.stat(follow_symlinks=False)
                if _is_reparse_or_symlink(entry_stat):
                    _fail(
                        "release bundle",
                        f"contains symbolic-link or reparse-point entry {entry.path!r}",
                    )
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if stat.S_ISDIR(entry_stat.st_mode):
                    visit(path)
                elif stat.S_ISREG(entry_stat.st_mode):
                    files.add(relative)
                else:
                    _fail("release bundle", f"contains unsupported entry {relative!r}")

    visit(root)
    return files


def validate_corpus_evaluation_release(
    path: str | os.PathLike[str],
    *,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(review_receipt_trust, ExpertModelReviewReceiptTrust):
        _fail(
            "review-receipt trust",
            "must be an ExpertModelReviewReceiptTrust instance",
        )
    if not isinstance(
        evaluation_authoring_approval_trust, EvaluationAuthoringApprovalTrust
    ):
        _fail(
            "evaluation-authoring approval trust",
            "must be an EvaluationAuthoringApprovalTrust instance",
        )
    requested = Path(path)
    manifest_path = (
        requested / RELEASE_MANIFEST_PATH if requested.is_dir() else requested
    )
    manifest_path = _regular_file(manifest_path, "release manifest")
    if manifest_path.name != RELEASE_MANIFEST_PATH:
        _fail("release manifest", f"must be named {RELEASE_MANIFEST_PATH!r}")
    root = manifest_path.parent
    document = _validate_release_document(
        load_json_document(manifest_path, max_bytes=MAX_RELEASE_MANIFEST_BYTES)
    )
    if root.name != document["releaseId"]:
        _fail(
            "release bundle directory",
            "must be named with the content-derived releaseId",
        )
    expected_files = _cross_validate_release(
        document,
        root,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        now=now,
    )
    actual_files = _enumerate_release_files(root)
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        unexpected = sorted(actual_files - expected_files)
        _fail(
            "release bundle files",
            f"do not match the manifest; missing={missing}, unexpected={unexpected}",
        )
    return document


def validate_corpus_evaluation_release_with_identity(
    path: str | os.PathLike[str],
    *,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    requested = Path(path)
    manifest_path = (
        requested / RELEASE_MANIFEST_PATH if requested.is_dir() else requested
    )
    before = sha256_file(manifest_path, max_bytes=MAX_RELEASE_MANIFEST_BYTES)
    document = validate_corpus_evaluation_release(
        path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        now=now,
    )
    if document["schemaVersion"] != RELEASE_SCHEMA_VERSION:
        _fail(
            "release.schemaVersion",
            "legacy v3 releases are archival-only and cannot produce an authorizing identity",
        )
    after = sha256_file(manifest_path, max_bytes=MAX_RELEASE_MANIFEST_BYTES)
    if before != after:
        _fail("release manifest", "changed while the release was validated")
    identity = {
        "releaseId": document["releaseId"],
        "releaseSha256": document["releaseSha256"],
        "manifestSha256": after,
    }
    _validate_data_release_identity(identity, "release identity", allow_none=False)
    return document, identity


def validate_training_release_binding(
    path: str | os.PathLike[str],
    *,
    dataset_sha256: str,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    document, identity = validate_corpus_evaluation_release_with_identity(
        path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        now=now,
    )
    if document["purpose"] not in TRAINING_PURPOSES:
        _fail("release.purpose", "must authorize training")
    sft = document["corpus"]["sft"]
    if sft is None or sft["sha256"] != _sha256(
        dataset_sha256, "training dataset SHA-256"
    ):
        _fail("release.corpus.sft.sha256", "does not match the training dataset")
    return document, identity


def validate_release_evaluation_task_set(
    document: Mapping[str, Any],
    tasks: EvaluationTaskSet,
) -> str:
    splits = {task["split"] for task in tasks.records}
    if len(splits) != 1:
        _fail("evaluation task file", "must contain exactly one split")
    split = next(iter(splits))
    name = "calibrationTasks" if split == "calibration" else "sealedTasks"
    binding = document["evaluation"][name]
    if (
        tasks.sha256 != binding["sha256"]
        or tasks.task_set_sha256 != binding["taskSetSha256"]
        or len(tasks.records) != binding["recordCount"]
    ):
        _fail(
            f"release.evaluation.{name}",
            "does not match the supplied evaluation task set",
        )
    return split


def create_corpus_evaluation_release(
    *,
    corpus_path: str | os.PathLike[str],
    review_receipts_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    teacher_lineage_admission_path: str | os.PathLike[str] | None = None,
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    task_bindings_path: str | os.PathLike[str],
    evaluation_authoring_approval_path: str | os.PathLike[str],
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    expected_evaluation_authoring_approval_envelope_sha256: str,
    approval_evidence_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    purpose: str,
    cutoff_utc: str,
    approval_id: str,
    reviewer_id: str,
    approved_at_utc: str,
    sft_path: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(review_receipt_trust, ExpertModelReviewReceiptTrust):
        _fail(
            "review-receipt trust",
            "must be an ExpertModelReviewReceiptTrust instance",
        )
    if not isinstance(
        evaluation_authoring_approval_trust, EvaluationAuthoringApprovalTrust
    ):
        _fail(
            "evaluation-authoring approval trust",
            "must be an EvaluationAuthoringApprovalTrust instance",
        )
    current = _release_validation_time(now)
    rights_policy = _rights_policy(purpose)
    _parse_datetime(cutoff_utc, "release cutoff", require_utc_z=True)
    _validate_identifier(approval_id, "approval ID")
    _validate_identifier(reviewer_id, "reviewer ID")
    _parse_datetime(approved_at_utc, "approval time", require_utc_z=True)
    if purpose in TRAINING_PURPOSES and sft_path is None:
        _fail("SFT file", "is required for a training release")
    if purpose not in TRAINING_PURPOSES and sft_path is not None:
        _fail("SFT file", "is not accepted for an evaluation-only release")

    destination_root = _ensure_directory_no_reparse(
        Path(output_root), "release output root"
    )
    stage = Path(tempfile.mkdtemp(prefix=".vqrelease.staging-", dir=destination_root))
    try:
        corpus_snapshot = _copy_file_snapshot(
            Path(corpus_path),
            stage.joinpath(*CORPUS_PATH.split("/")),
            "expert corpus",
            max_bytes=MAX_CORPUS_BYTES,
        )
        receipt_snapshot = _copy_file_snapshot(
            Path(review_receipts_path),
            stage.joinpath(*REVIEW_RECEIPTS_PATH.split("/")),
            "expert-model review-receipt set",
            max_bytes=MAX_REVIEW_RECEIPT_SET_BYTES,
        )
        calibration_snapshot = _copy_file_snapshot(
            Path(calibration_tasks_path),
            stage.joinpath(*CALIBRATION_TASKS_PATH.split("/")),
            "calibration tasks",
            max_bytes=MAX_CORPUS_BYTES,
        )
        sealed_snapshot = _copy_file_snapshot(
            Path(sealed_tasks_path),
            stage.joinpath(*SEALED_TASKS_PATH.split("/")),
            "sealed tasks",
            max_bytes=MAX_CORPUS_BYTES,
        )
        original_bindings_snapshot = _copy_file_snapshot(
            Path(task_bindings_path),
            stage / ".task-bindings.original.json",
            "release task bindings",
            max_bytes=MAX_RELEASE_MANIFEST_BYTES,
        )
        input_bindings = _load_task_binding_input(
            original_bindings_snapshot,
            relative_asset_root=Path(task_bindings_path).resolve().parent,
        )
        bindings_snapshot = stage / ".task-bindings.snapshot.json"
        _write_json_exclusive(
            bindings_snapshot,
            {
                "schemaVersion": TASK_BINDINGS_SCHEMA_VERSION,
                "bindings": input_bindings,
            },
        )
        original_bindings_snapshot.unlink()
        authoring_approval_snapshot = _copy_file_snapshot(
            Path(evaluation_authoring_approval_path),
            stage.joinpath(*EVALUATION_AUTHORING_APPROVAL_PATH.split("/")),
            "evaluation-authoring approval",
            max_bytes=MAX_EVALUATION_AUTHORING_APPROVAL_BYTES,
        )
        evidence_snapshot = _copy_file_snapshot(
            Path(approval_evidence_path),
            stage.joinpath(*APPROVAL_EVIDENCE_PATH.split("/")),
            "approval evidence",
            max_bytes=MAX_REVIEW_ASSET_BYTES,
        )
        if evidence_snapshot.stat().st_size == 0:
            _fail("approval evidence", "must not be empty")
        sft_snapshot: Path | None = None
        if sft_path is not None:
            sft_snapshot = _copy_file_snapshot(
                Path(sft_path),
                stage.joinpath(*SFT_PATH.split("/")),
                "SFT file",
                max_bytes=MAX_SFT_BYTES,
            )

        corpus = _parse_expert_corpus(corpus_snapshot)
        teacher_record_count = sum(
            record.document["lineage"]["origin"] == "OpenWeightTeacher"
            for record in corpus.records.values()
        )
        lineage_trust = review_receipt_trust.teacher_lineage_admission_trust
        lineage_snapshot: Path | None = None
        if teacher_record_count:
            if teacher_lineage_admission_path is None or lineage_trust is None:
                _fail(
                    "teacher lineage admission",
                    "path and externally pinned trust are required for "
                    "OpenWeightTeacher rows",
                )
            from .teacher_lineage import MAX_TEACHER_LINEAGE_ADMISSION_BYTES

            lineage_snapshot = _copy_file_snapshot(
                Path(teacher_lineage_admission_path),
                stage.joinpath(*TEACHER_LINEAGE_ADMISSION_PATH.split("/")),
                "teacher lineage admission",
                max_bytes=MAX_TEACHER_LINEAGE_ADMISSION_BYTES,
            )
        elif teacher_lineage_admission_path is not None or lineage_trust is not None:
            _fail(
                "teacher lineage admission",
                "is not accepted for a HumanAuthored-only corpus",
            )
        verified_receipts = validate_expert_model_review_receipts(
            receipt_snapshot,
            dataset_path=corpus_snapshot,
            public_key_path=review_receipt_trust.public_key_path,
            expected_public_key_spki_sha256=(
                review_receipt_trust.public_key_spki_sha256
            ),
            expected_audience=review_receipt_trust.audience,
            expected_key_id=review_receipt_trust.key_id,
            expected_signer_role=review_receipt_trust.signer_role,
            teacher_lineage_admission_path=lineage_snapshot,
            teacher_lineage_admission_trust=lineage_trust,
            now=current,
            _corpus_snapshot=corpus,
            _allow_release_bound_teacher_lineage=True,
            _required_schema_version=REVIEW_RECEIPT_SCHEMA_VERSION,
        )
        calibration = validate_evaluation_tasks(calibration_snapshot)
        sealed = validate_evaluation_tasks(sealed_snapshot)
        verified_authoring = validate_evaluation_authoring_approval_for_inventory(
            authoring_approval_snapshot,
            trust=evaluation_authoring_approval_trust,
            expected_envelope_sha256=(
                expected_evaluation_authoring_approval_envelope_sha256
            ),
            source_dataset_path=corpus_snapshot,
            calibration_tasks_path=calibration_snapshot,
            sealed_tasks_path=sealed_snapshot,
            task_bindings_path=bindings_snapshot,
            now=current,
        )
        bindings_snapshot.unlink()
        task_bindings = _snapshot_binding_assets(input_bindings, stage)
        task_map = {
            task["taskId"]: task for task in (*calibration.records, *sealed.records)
        }
        for binding in task_bindings:
            task = task_map.get(binding["taskId"])
            if task is not None:
                binding["taskSha256"] = task["taskSha256"]
            binding["sourceExampleIds"] = sorted(binding["sourceExampleIds"])

        source_binding = {
            **_binding_for_file(corpus_snapshot, CORPUS_PATH, limit=MAX_CORPUS_BYTES),
            "recordCount": len(corpus.records),
        }
        receipt_binding = {
            **_binding_for_file(
                receipt_snapshot,
                REVIEW_RECEIPTS_PATH,
                limit=MAX_REVIEW_RECEIPT_SET_BYTES,
            ),
            "recordCount": verified_receipts.receipt_count,
            "expiresAtUtc": verified_receipts.expires_at_utc,
            "trust": review_receipt_trust.manifest_identity(),
        }
        lineage_binding = None
        if lineage_snapshot is not None:
            verified_lineage = verified_receipts.teacher_lineage_admission
            if verified_lineage is None:  # pragma: no cover - validator invariant
                _fail(
                    "teacher lineage admission",
                    "did not verify for the exact released corpus",
                )
            reviewed = verified_lineage.payload["reviewedCorpus"]
            lineage_binding = {
                **_binding_for_file(
                    lineage_snapshot,
                    TEACHER_LINEAGE_ADMISSION_PATH,
                    limit=MAX_TEACHER_LINEAGE_ADMISSION_BYTES,
                ),
                "lineageAdmissionId": verified_lineage.payload["lineageAdmissionId"],
                "payloadSha256": verified_lineage.payload_sha256,
                "envelopeSha256": verified_lineage.envelope_sha256,
                "materializationId": verified_lineage.payload["materialization"][
                    "materializationId"
                ],
                "reviewedCorpusSha256": reviewed["sha256"],
                "reviewedCorpusRecordCount": reviewed["recordCount"],
                "openWeightTeacherRecordCount": reviewed[
                    "openWeightTeacherRecordCount"
                ],
                "notBeforeUtc": verified_lineage.payload["notBeforeUtc"],
                "expiresAtUtc": verified_lineage.payload["expiresAtUtc"],
                "trust": lineage_trust.manifest_identity(),
            }
        sft_binding = None
        if sft_snapshot is not None:
            sft_raw = _read_file_bounded(sft_snapshot, "SFT file", MAX_SFT_BYTES)
            sft_rows = _parse_release_sft_rows(
                sft_raw, release_schema_version=RELEASE_SCHEMA_VERSION
            )
            sft_binding = {
                **_binding_for_file(sft_snapshot, SFT_PATH, limit=MAX_SFT_BYTES),
                "recordCount": len(sft_rows),
            }
        document: dict[str, Any] = {
            "schemaVersion": RELEASE_SCHEMA_VERSION,
            "releaseId": "vqrel-" + "0" * 64,
            "releaseSha256": "0" * 64,
            "purpose": purpose,
            "cutoffUtc": cutoff_utc,
            "rightsPolicy": rights_policy,
            "corpus": {
                "sourceDataset": source_binding,
                "reviewReceipts": receipt_binding,
                "teacherLineageAdmission": lineage_binding,
                "sft": sft_binding,
            },
            "evaluation": {
                "calibrationTasks": _binding_for_tasks(
                    calibration, CALIBRATION_TASKS_PATH
                ),
                "sealedTasks": _binding_for_tasks(sealed, SEALED_TASKS_PATH),
                "taskBindings": task_bindings,
                "authoringApproval": {
                    **_binding_for_file(
                        authoring_approval_snapshot,
                        EVALUATION_AUTHORING_APPROVAL_PATH,
                        limit=MAX_EVALUATION_AUTHORING_APPROVAL_BYTES,
                    ),
                    "authoringApprovalId": verified_authoring.payload[
                        "authoringApprovalId"
                    ],
                    "payloadSha256": verified_authoring.payload_sha256,
                    "envelopeSha256": verified_authoring.envelope_sha256,
                    "notBeforeUtc": verified_authoring.payload["notBeforeUtc"],
                    "expiresAtUtc": verified_authoring.payload["expiresAtUtc"],
                    "trust": _evaluation_authoring_trust_identity(
                        evaluation_authoring_approval_trust
                    ),
                },
            },
            "approval": {
                "status": "approved",
                "declarativeOnly": True,
                "approvalId": approval_id,
                "reviewerId": reviewer_id,
                "approvedAtUtc": approved_at_utc,
                "evidence": _binding_for_file(
                    evidence_snapshot,
                    APPROVAL_EVIDENCE_PATH,
                    limit=MAX_REVIEW_ASSET_BYTES,
                ),
            },
        }
        release_hash = _release_sha256(document)
        document["releaseSha256"] = release_hash
        document["releaseId"] = f"vqrel-{release_hash}"
        _write_json_exclusive(stage / RELEASE_MANIFEST_PATH, document)
        staged_document = _validate_release_document(
            load_json_document(
                stage / RELEASE_MANIFEST_PATH, max_bytes=MAX_RELEASE_MANIFEST_BYTES
            )
        )
        expected_files = _cross_validate_release(
            staged_document,
            stage,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            now=current,
        )
        actual_files = _enumerate_release_files(stage)
        if actual_files != expected_files:
            missing = sorted(expected_files - actual_files)
            unexpected = sorted(actual_files - expected_files)
            _fail(
                "release bundle files",
                f"do not match the manifest; missing={missing}, unexpected={unexpected}",
            )
        destination = destination_root / document["releaseId"]
        with _exclusive_destination_lock(
            destination, "release bundle"
        ) as locked_destination:
            if os.path.lexists(locked_destination):
                _fail(
                    "release bundle",
                    "already exists; releases are immutable and never overwritten",
                )
            _install_directory_no_clobber(stage, locked_destination, "release bundle")
            stage = locked_destination
        manifest_path = stage / RELEASE_MANIFEST_PATH
        return {
            "releasePath": str(stage),
            "releaseId": document["releaseId"],
            "releaseSha256": document["releaseSha256"],
            "manifestSha256": sha256_file(
                manifest_path, max_bytes=MAX_RELEASE_MANIFEST_BYTES
            ),
            "corpusSha256": corpus.sha256,
            "reviewReceiptSetSha256": verified_receipts.receipt_set_sha256,
            "calibrationTaskSetSha256": calibration.task_set_sha256,
            "sealedTaskSetSha256": sealed.task_set_sha256,
            "evaluationAuthoringApprovalId": verified_authoring.payload[
                "authoringApprovalId"
            ],
            "evaluationAuthoringApprovalPayloadSha256": (
                verified_authoring.payload_sha256
            ),
            "evaluationAuthoringApprovalEnvelopeSha256": (
                verified_authoring.envelope_sha256
            ),
            "evaluationAuthoringApprovalExpiresAtUtc": verified_authoring.payload[
                "expiresAtUtc"
            ],
        }
    finally:
        if stage.exists() and stage.name.startswith(".vqrelease.staging-"):
            shutil.rmtree(stage)
