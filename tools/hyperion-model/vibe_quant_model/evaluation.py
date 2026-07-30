from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping

from .base_evaluation import validate_base_evaluation_profile
from .base_engine_wrapper import (
    BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION,
    BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION,
    BASE_ATTESTED_COMPLETIONS_PATH,
    BaseEngineActivationTrust,
    inspect_base_engine_activation_envelope,
    inspect_base_runtime_attestation_envelope,
    load_base_engine_wrapper_config,
    verify_base_engine_activation,
    verify_base_engine_activation_envelope,
    verify_base_runtime_attestation,
)
from .core import (
    DOMAINS,
    MAX_JSON_BYTES,
    MAX_AGGREGATE_MESSAGE_CHARACTERS,
    MAX_MESSAGE_CHARACTERS,
    MAX_MESSAGE_COUNT,
    TASK_KINDS,
    ValidationError,
    _exact_keys,
    _fail,
    _integer,
    _length_prefixed_sha256,
    _number,
    _parse_datetime,
    _pinned_revision_label,
    _read_file_bounded,
    _reject_constant,
    _reject_reparse_components,
    _regular_file,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _validate_candidate_catalog_document,
    _validate_data_release_identity,
    canonical_json_bytes,
    load_json_document,
    sha256_file,
    validate_manifest_path,
)
from .deployment import validate_serving_profile
from .review_receipts import ExpertModelReviewReceiptTrust

if TYPE_CHECKING:
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust
    from .trainer_provenance import TrainerProvenanceTrust
    from .verifier_runtime import CSharpVerifierExecutionContext
    from .verifier_replay_audit import CSharpVerifierReplayAuditTrust


EVALUATION_TASK_SCHEMA_VERSION = "daxalgo.vibe-quant.evaluation-task/v1"
EVALUATION_RESPONSE_SCHEMA_VERSION = "daxalgo.vibe-quant.evaluation-response/v1"
EVALUATION_RESPONSE_V2_SCHEMA_VERSION = "daxalgo.vibe-quant.evaluation-response/v2"
VERIFIER_DECISION_MANIFEST_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.verifier-decision-manifest/v1"
)
VERIFIER_RESULT_SCHEMA_VERSION = "daxalgo.vibe-quant.verifier-result/v1"
PROMOTION_POLICY_SCHEMA_VERSION = "daxalgo.vibe-quant.promotion-policy/v1"
PROMOTION_EVIDENCE_SCHEMA_VERSION = "daxalgo.vibe-quant.promotion-evidence/v1"
EVALUATION_COVERAGE_SCHEMA_VERSION = "daxalgo.vibe-quant.evaluation-coverage/v1"

EVALUATION_SPLITS = frozenset({"calibration", "sealed"})
CRITICALITIES = frozenset({"standard", "critical"})
FINISH_REASONS = frozenset({"stop", "length", "content_filter", "tool_calls"})
MAX_EVALUATION_BYTES = 100_000_000
MAX_EVALUATION_RECORDS = 100_000
MAX_EVALUATION_LINE_BYTES = 8_000_000
MAX_CAPTURE_RESPONSE_BYTES = 4_000_000
MAX_OUTPUT_BYTES = 2_000_000
MAX_EVIDENCE_CHARACTERS = 200_000
MAX_REQUIRED_CHECKS = 128
MAX_OUTPUT_TOKENS = 262_144
MAX_TIMEOUT_SECONDS = 300.0

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


@dataclass(frozen=True)
class EvaluationTaskSet:
    path: Path
    sha256: str
    task_set_sha256: str
    records: tuple[dict[str, Any], ...]

    def coverage(self) -> dict[str, Any]:
        domains: Counter[str] = Counter()
        splits: Counter[str] = Counter()
        criticalities: Counter[str] = Counter()
        tasks: Counter[str] = Counter()
        for task in self.records:
            splits[task["split"]] += 1
            criticalities[task["criticality"]] += 1
            tasks[task["taskKind"]] += 1
            domains.update(task["domains"])
        return {
            "schemaVersion": EVALUATION_COVERAGE_SCHEMA_VERSION,
            "fileSha256": self.sha256,
            "taskSetSha256": self.task_set_sha256,
            "recordCount": len(self.records),
            "splitCounts": dict(sorted(splits.items())),
            "criticalityCounts": dict(sorted(criticalities.items())),
            "taskKindCounts": dict(sorted(tasks.items())),
            "domainCounts": {domain: domains.get(domain, 0) for domain in DOMAINS},
            "missingDomains": [
                domain for domain in DOMAINS if domains.get(domain, 0) == 0
            ],
        }


@dataclass(frozen=True)
class BaseResponseAttestationTrust:
    activation_trust: BaseEngineActivationTrust
    runtime_public_key_path: Path

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "runtime_public_key_path", Path(self.runtime_public_key_path)
        )


@dataclass(frozen=True)
class TransportResponse:
    body: bytes
    final_url: str


Transport = Callable[[str, Mapping[str, str], bytes, float, int], TransportResponse]


def evaluation_prompt_sha256(messages: list[dict[str, str]]) -> str:
    try:
        return _length_prefixed_sha256(
            "daxalgo-vibe-quant-evaluation-prompt/v1",
            [[message["role"], message["content"]] for message in messages],
        )
    except UnicodeEncodeError as error:
        raise ValidationError(
            "evaluation prompt: must contain only valid Unicode scalar values"
        ) from error


def evaluation_output_sha256(output: str) -> str:
    try:
        return _length_prefixed_sha256(
            "daxalgo-vibe-quant-evaluation-output/v1", [[output]]
        )
    except UnicodeEncodeError as error:
        raise ValidationError(
            "evaluation output: must contain only valid Unicode scalar values"
        ) from error


def evidence_sha256(evidence: str) -> str:
    try:
        return _length_prefixed_sha256(
            "daxalgo-vibe-quant-verifier-evidence/v1", [[evidence]]
        )
    except UnicodeEncodeError as error:
        raise ValidationError(
            "verifier evidence: must contain only valid Unicode scalar values"
        ) from error


def _task_hash_groups(task: Mapping[str, Any]) -> list[list[str]]:
    groups = [
        [
            task["schemaVersion"],
            task["taskId"],
            task["split"],
            task["taskKind"],
            task["promptSha256"],
            task["contextPack"]["version"],
            task["contextPack"]["sha256"],
            task["contaminationGroup"],
            task["cutoffUtc"],
            task["criticality"],
            str(task["maxOutputTokens"]),
        ],
        list(task["domains"]),
    ]
    groups.extend(
        [[message["role"], message["content"]] for message in task["messages"]]
    )
    groups.append([task["verifier"]["id"], task["verifier"]["sha256"]])
    groups.append(list(task["verifier"]["requiredChecks"]))
    return groups


def evaluation_task_sha256(task: Mapping[str, Any]) -> str:
    return _length_prefixed_sha256(
        "daxalgo-vibe-quant-evaluation-task-record/v1", _task_hash_groups(task)
    )


def evaluation_task_set_sha256(tasks: Iterable[Mapping[str, Any]]) -> str:
    pairs = sorted((task["taskId"], task["taskSha256"]) for task in tasks)
    return _length_prefixed_sha256(
        "daxalgo-vibe-quant-evaluation-task-set/v1",
        [[task_id, task_hash] for task_id, task_hash in pairs],
    )


def _validate_identifier(value: Any, field: str) -> str:
    identifier = _string(value, field, max_length=200)
    if not _SAFE_ID_RE.fullmatch(identifier):
        _fail(field, "contains unsupported characters")
    return identifier


def _validate_eval_messages(value: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_MESSAGE_COUNT:
        _fail(field, f"must contain 1 to {MAX_MESSAGE_COUNT} messages")
    messages: list[dict[str, str]] = []
    aggregate = 0
    for index, raw in enumerate(value):
        message = _exact_keys(raw, {"role", "content"}, f"{field}[{index}]")
        role = message["role"]
        if role not in {"system", "user", "assistant"}:
            _fail(f"{field}[{index}].role", "must be system, user, or assistant")
        content = _string(
            message["content"],
            f"{field}[{index}].content",
            max_length=MAX_MESSAGE_CHARACTERS,
        )
        aggregate += len(content)
        messages.append({"role": role, "content": content})
    if aggregate > MAX_AGGREGATE_MESSAGE_CHARACTERS:
        _fail(
            field,
            f"content exceeds {MAX_AGGREGATE_MESSAGE_CHARACTERS} aggregate characters",
        )
    start = 1 if messages[0]["role"] == "system" else 0
    if start == len(messages):
        _fail(field, "must include a user prompt")
    expected = "user"
    for index in range(start, len(messages)):
        if messages[index]["role"] != expected:
            _fail(
                f"{field}[{index}].role",
                f"must be {expected!r} to preserve chat ordering",
            )
        expected = "assistant" if expected == "user" else "user"
    if messages[-1]["role"] != "user":
        _fail(field, "final message must have role 'user'")
    return messages


def _validate_task(value: Any, line_number: int) -> dict[str, Any]:
    field = f"evaluation task line {line_number}"
    task = _exact_keys(
        value,
        {
            "schemaVersion",
            "taskId",
            "taskSha256",
            "split",
            "taskKind",
            "domains",
            "messages",
            "promptSha256",
            "contextPack",
            "verifier",
            "contaminationGroup",
            "cutoffUtc",
            "criticality",
            "maxOutputTokens",
        },
        field,
    )
    if task["schemaVersion"] != EVALUATION_TASK_SCHEMA_VERSION:
        _fail(f"{field}.schemaVersion", f"must be {EVALUATION_TASK_SCHEMA_VERSION!r}")
    _validate_identifier(task["taskId"], f"{field}.taskId")
    if task["split"] not in EVALUATION_SPLITS:
        _fail(f"{field}.split", "must be calibration or sealed")
    if task["taskKind"] not in TASK_KINDS:
        _fail(f"{field}.taskKind", "is not a supported ExpertTaskKind")
    domains = task["domains"]
    if (
        not isinstance(domains, list)
        or not domains
        or len(domains) != len(set(domains))
    ):
        _fail(f"{field}.domains", "must be a non-empty array without duplicates")
    if not all(isinstance(domain, str) and domain in DOMAINS for domain in domains):
        _fail(f"{field}.domains", "contains unsupported domain labels")
    messages = _validate_eval_messages(task["messages"], f"{field}.messages")
    prompt_hash = _sha256(task["promptSha256"], f"{field}.promptSha256")
    if prompt_hash != evaluation_prompt_sha256(messages):
        _fail(f"{field}.promptSha256", "does not match the canonical evaluation prompt")
    context_pack = _exact_keys(
        task["contextPack"], {"version", "sha256"}, f"{field}.contextPack"
    )
    _pinned_revision_label(context_pack["version"], f"{field}.contextPack.version")
    _sha256(context_pack["sha256"], f"{field}.contextPack.sha256")
    verifier = _exact_keys(
        task["verifier"], {"id", "sha256", "requiredChecks"}, f"{field}.verifier"
    )
    _validate_identifier(verifier["id"], f"{field}.verifier.id")
    _sha256(verifier["sha256"], f"{field}.verifier.sha256")
    checks = verifier["requiredChecks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_REQUIRED_CHECKS:
        _fail(
            f"{field}.verifier.requiredChecks",
            f"must contain 1 to {MAX_REQUIRED_CHECKS} checks",
        )
    if len(checks) != len(set(checks)):
        _fail(f"{field}.verifier.requiredChecks", "must not contain duplicates")
    for index, check in enumerate(checks):
        _validate_identifier(check, f"{field}.verifier.requiredChecks[{index}]")
    _validate_identifier(task["contaminationGroup"], f"{field}.contaminationGroup")
    _parse_datetime(task["cutoffUtc"], f"{field}.cutoffUtc", require_utc_z=True)
    if task["criticality"] not in CRITICALITIES:
        _fail(f"{field}.criticality", "must be standard or critical")
    _integer(task["maxOutputTokens"], f"{field}.maxOutputTokens", 1, MAX_OUTPUT_TOKENS)
    expected_hash = evaluation_task_sha256(task)
    if _sha256(task["taskSha256"], f"{field}.taskSha256") != expected_hash:
        _fail(f"{field}.taskSha256", "does not match the canonical task record")
    return task


def _parse_jsonl_bytes(
    raw: bytes | bytearray,
    label: str,
    validator: Callable[[Any, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    if not raw:
        _fail(label, "must not be empty")
    records: list[dict[str, Any]] = []
    with io.BytesIO(raw) as stream:
        for line_number, raw_line in enumerate(stream, start=1):
            if line_number == 1 and raw_line.startswith(b"\xef\xbb\xbf"):
                _fail(label, "UTF-8 byte-order marks are not accepted")
            if len(raw_line) > MAX_EVALUATION_LINE_BYTES:
                _fail(
                    f"{label} line {line_number}",
                    f"exceeds {MAX_EVALUATION_LINE_BYTES} bytes",
                )
            try:
                text = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise ValidationError(
                    f"{label} line {line_number}: invalid UTF-8 at byte {error.start}"
                ) from error
            if not text.strip():
                _fail(f"{label} line {line_number}", "blank lines are not accepted")
            try:
                value = json.loads(
                    text,
                    object_pairs_hook=_unique_pairs,
                    parse_constant=_reject_constant,
                )
            except json.JSONDecodeError as error:
                raise ValidationError(
                    f"{label} line {line_number}: invalid JSON at column {error.colno}: {error.msg}"
                ) from error
            records.append(validator(value, line_number))
            if len(records) > MAX_EVALUATION_RECORDS:
                _fail(label, f"exceeds {MAX_EVALUATION_RECORDS} records")
    return records


def _parse_json_document_bytes(raw: bytes, label: str) -> dict[str, Any]:
    if not raw:
        _fail(label, "must not be empty")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(label, "UTF-8 byte-order marks are not accepted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(
            f"{label}: invalid UTF-8 at byte {error.start}"
        ) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ValidationError(
            f"{label}: invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    if not isinstance(value, dict):
        _fail(label, "root must be an object")
    return value


def _parse_jsonl(
    path: Path, label: str, validator: Callable[[Any, int], dict[str, Any]]
) -> tuple[str, list[dict[str, Any]]]:
    resolved = _regular_file(path, label)
    raw = _read_file_bounded(resolved, label, MAX_EVALUATION_BYTES)
    return hashlib.sha256(raw).hexdigest(), _parse_jsonl_bytes(raw, label, validator)


def _evaluation_task_set_from_records(
    path: Path,
    file_hash: str,
    records: list[dict[str, Any]],
) -> EvaluationTaskSet:
    ids: set[str] = set()
    hashes: set[str] = set()
    prompts: set[str] = set()
    contamination: dict[str, str] = {}
    for index, task in enumerate(records, start=1):
        if task["taskId"] in ids:
            _fail(
                f"evaluation task line {index}.taskId", "duplicates an earlier task ID"
            )
        if task["taskSha256"] in hashes:
            _fail(
                f"evaluation task line {index}.taskSha256", "duplicates an earlier task"
            )
        if task["promptSha256"] in prompts:
            _fail(
                f"evaluation task line {index}.promptSha256",
                "duplicates an earlier prompt",
            )
        prior_split = contamination.get(task["contaminationGroup"])
        if prior_split is not None and prior_split != task["split"]:
            _fail(
                f"evaluation task line {index}.contaminationGroup",
                "crosses calibration/sealed boundary",
            )
        ids.add(task["taskId"])
        hashes.add(task["taskSha256"])
        prompts.add(task["promptSha256"])
        contamination[task["contaminationGroup"]] = task["split"]
    return EvaluationTaskSet(
        path=path,
        sha256=file_hash,
        task_set_sha256=evaluation_task_set_sha256(records),
        records=tuple(records),
    )


def validate_evaluation_tasks(path: str | os.PathLike[str]) -> EvaluationTaskSet:
    resolved = _regular_file(Path(path), "evaluation task file")
    file_hash, records = _parse_jsonl(resolved, "evaluation task file", _validate_task)
    return _evaluation_task_set_from_records(resolved, file_hash, records)


def summarize_evaluation_coverage(path: str | os.PathLike[str]) -> dict[str, Any]:
    return validate_evaluation_tasks(path).coverage()


def _response_hash_groups(response: Mapping[str, Any]) -> list[list[str]]:
    profile = response["servingProfile"]
    output = response["output"]
    generation = response["generation"]
    usage = response["usage"]
    data_release = response["dataRelease"]
    release_fields = (
        ["null"]
        if data_release is None
        else [
            data_release["releaseId"],
            data_release["releaseSha256"],
            data_release["manifestSha256"],
        ]
    )
    runtime_fields: list[str] = []
    if response["schemaVersion"] == EVALUATION_RESPONSE_V2_SCHEMA_VERSION:
        runtime_fields = [
            canonical_json_bytes(response["runtimeAttestation"]).decode("utf-8"),
        ]
    return [
        [
            response["schemaVersion"],
            response["candidateCatalogSha256"],
            response["candidateId"],
            response["modelId"],
            response["modelRevision"],
            profile["id"],
            profile["sha256"],
            response["targetKind"],
            response["executionModelId"],
            response["runId"],
            response["taskId"],
            response["taskSha256"],
            response["promptSha256"],
            output["sha256"],
            str(output["byteCount"]),
            output["text"],
            str(generation["temperature"]),
            str(generation["topP"]),
            str(generation["seed"]),
            str(generation["maxOutputTokens"]),
            str(response["latencyMs"]),
            str(usage["promptTokens"]),
            str(usage["completionTokens"]),
            str(usage["totalTokens"]),
            response["finishReason"],
            response["capturedAtUtc"],
            str(response["researchOnly"]).lower(),
            response["evidenceStatus"],
            *release_fields,
            *runtime_fields,
        ]
    ]


def evaluation_response_sha256(response: Mapping[str, Any]) -> str:
    domain = (
        "daxalgo-vibe-quant-evaluation-response-record/v2"
        if response.get("schemaVersion") == EVALUATION_RESPONSE_V2_SCHEMA_VERSION
        else "daxalgo-vibe-quant-evaluation-response-record/v1"
    )
    return _length_prefixed_sha256(
        domain,
        _response_hash_groups(response),
    )


def _validate_response(value: Any, line_number: int) -> dict[str, Any]:
    field = f"evaluation response line {line_number}"
    if not isinstance(value, dict):
        _fail(field, "must be an object")
    schema_version = value.get("schemaVersion")
    base_keys = {
        "schemaVersion",
        "responseSha256",
        "candidateCatalogSha256",
        "candidateId",
        "modelId",
        "modelRevision",
        "servingProfile",
        "targetKind",
        "executionModelId",
        "runId",
        "taskId",
        "taskSha256",
        "promptSha256",
        "output",
        "generation",
        "latencyMs",
        "usage",
        "finishReason",
        "capturedAtUtc",
        "dataRelease",
        "researchOnly",
        "evidenceStatus",
    }
    if schema_version == EVALUATION_RESPONSE_SCHEMA_VERSION:
        expected_keys = base_keys
    elif schema_version == EVALUATION_RESPONSE_V2_SCHEMA_VERSION:
        expected_keys = base_keys | {"runtimeAttestation"}
    else:
        _fail(
            f"{field}.schemaVersion",
            f"must be {EVALUATION_RESPONSE_SCHEMA_VERSION!r} or {EVALUATION_RESPONSE_V2_SCHEMA_VERSION!r}",
        )
    response = _exact_keys(
        value,
        expected_keys,
        field,
    )
    data_release = _validate_data_release_identity(
        response["dataRelease"], f"{field}.dataRelease"
    )
    if not isinstance(response["researchOnly"], bool):
        _fail(f"{field}.researchOnly", "must be a boolean")
    expected_status = (
        "unpromoted-research" if response["researchOnly"] else "release-bound"
    )
    if response["evidenceStatus"] != expected_status:
        _fail(f"{field}.evidenceStatus", "does not match researchOnly")
    if (data_release is None) is not response["researchOnly"]:
        _fail(
            f"{field}.dataRelease",
            "must be null only for explicitly research-only evidence",
        )
    _sha256(response["candidateCatalogSha256"], f"{field}.candidateCatalogSha256")
    _validate_identifier(response["candidateId"], f"{field}.candidateId")
    _string(response["modelId"], f"{field}.modelId", max_length=500)
    _revision(response["modelRevision"], f"{field}.modelRevision")
    profile = _exact_keys(
        response["servingProfile"], {"id", "sha256"}, f"{field}.servingProfile"
    )
    _validate_identifier(profile["id"], f"{field}.servingProfile.id")
    _sha256(profile["sha256"], f"{field}.servingProfile.sha256")
    if response["targetKind"] not in {"trained-adapter", "raw-base"}:
        _fail(f"{field}.targetKind", "must be 'trained-adapter' or 'raw-base'")
    expected_execution_model = (
        "daxalgo-base-sha256-"
        if response["targetKind"] == "raw-base"
        else "daxalgo-expert-sha256-"
    ) + profile["sha256"]
    if response["executionModelId"] != expected_execution_model:
        _fail(
            f"{field}.executionModelId",
            "does not match the content-addressed target profile",
        )
    if schema_version == EVALUATION_RESPONSE_V2_SCHEMA_VERSION:
        if response["targetKind"] != "raw-base":
            _fail(f"{field}.targetKind", "response v2 is reserved for 'raw-base'")
        if response["researchOnly"] is not False or data_release is None:
            _fail(
                f"{field}.runtimeAttestation",
                "is accepted only for release-bound raw-base evidence",
            )
    elif response["targetKind"] == "raw-base" and response["researchOnly"] is not True:
        _fail(
            f"{field}.targetKind",
            "raw-base response v1 is accepted only for explicit research evidence",
        )
    _validate_identifier(response["runId"], f"{field}.runId")
    _validate_identifier(response["taskId"], f"{field}.taskId")
    _sha256(response["taskSha256"], f"{field}.taskSha256")
    _sha256(response["promptSha256"], f"{field}.promptSha256")
    output = _exact_keys(
        response["output"], {"text", "sha256", "byteCount"}, f"{field}.output"
    )
    text = output["text"]
    if not isinstance(text, str) or len(text) > MAX_OUTPUT_BYTES:
        _fail(
            f"{field}.output.text",
            f"must be a string no longer than {MAX_OUTPUT_BYTES} characters",
        )
    byte_count = _integer(
        output["byteCount"], f"{field}.output.byteCount", 0, MAX_OUTPUT_BYTES
    )
    encoded_length = len(text.encode("utf-8", errors="strict"))
    if byte_count != encoded_length:
        _fail(f"{field}.output.byteCount", "does not match UTF-8 output bytes")
    if _sha256(output["sha256"], f"{field}.output.sha256") != evaluation_output_sha256(
        text
    ):
        _fail(f"{field}.output.sha256", "does not match canonical output content")
    generation = _exact_keys(
        response["generation"],
        {"temperature", "topP", "seed", "maxOutputTokens"},
        f"{field}.generation",
    )
    if _number(generation["temperature"], f"{field}.generation.temperature", 0, 0) != 0:
        _fail(
            f"{field}.generation.temperature",
            "must be zero for deterministic evaluation",
        )
    if _number(generation["topP"], f"{field}.generation.topP", 1, 1) != 1:
        _fail(f"{field}.generation.topP", "must be one for deterministic evaluation")
    _integer(generation["seed"], f"{field}.generation.seed", 0, 2_147_483_647)
    _integer(
        generation["maxOutputTokens"],
        f"{field}.generation.maxOutputTokens",
        1,
        MAX_OUTPUT_TOKENS,
    )
    _integer(response["latencyMs"], f"{field}.latencyMs", 0, 86_400_000)
    usage = _exact_keys(
        response["usage"],
        {"promptTokens", "completionTokens", "totalTokens"},
        f"{field}.usage",
    )
    prompt_tokens = _integer(
        usage["promptTokens"], f"{field}.usage.promptTokens", 0, 100_000_000
    )
    completion_tokens = _integer(
        usage["completionTokens"], f"{field}.usage.completionTokens", 0, 100_000_000
    )
    total_tokens = _integer(
        usage["totalTokens"], f"{field}.usage.totalTokens", 0, 200_000_000
    )
    if total_tokens != prompt_tokens + completion_tokens:
        _fail(
            f"{field}.usage.totalTokens",
            "must equal promptTokens plus completionTokens",
        )
    if response["finishReason"] not in FINISH_REASONS:
        _fail(f"{field}.finishReason", "is not an accepted completion finish reason")
    if response["finishReason"] == "stop" and not text.strip():
        _fail(f"{field}.output.text", "must be non-empty for a stop finish")
    _parse_datetime(
        response["capturedAtUtc"], f"{field}.capturedAtUtc", require_utc_z=True
    )
    if schema_version == EVALUATION_RESPONSE_V2_SCHEMA_VERSION:
        _validate_base_runtime_evidence(response, field)
    if _sha256(
        response["responseSha256"], f"{field}.responseSha256"
    ) != evaluation_response_sha256(response):
        _fail(f"{field}.responseSha256", "does not match the canonical response record")
    return response


def _validate_base_runtime_evidence(
    response: Mapping[str, Any], field: str
) -> dict[str, Any]:
    runtime = _exact_keys(
        response["runtimeAttestation"],
        {"activation", "receipt", "completion"},
        f"{field}.runtimeAttestation",
    )
    activation = inspect_base_engine_activation_envelope(runtime["activation"])
    receipt = inspect_base_runtime_attestation_envelope(runtime["receipt"])
    completion = runtime["completion"]
    if not isinstance(completion, dict):
        _fail(f"{field}.runtimeAttestation.completion", "must be an object")
    activation_payload = activation["payload"]
    receipt_payload = receipt["payload"]
    if (
        runtime["receipt"]["publicKeySpkiSha256"]
        != activation_payload["runtimeSigner"]["publicKeySpkiSha256"]
    ):
        _fail(
            f"{field}.runtimeAttestation.receipt.publicKeySpkiSha256",
            "does not match the activated runtime signer",
        )
    expected_activation = {
        "activationId": activation_payload["activationId"],
        "envelopeSha256": activation["envelopeSha256"],
        "payloadSha256": activation["payloadSha256"],
    }
    if receipt_payload["activation"] != expected_activation:
        _fail(
            f"{field}.runtimeAttestation.receipt",
            "does not bind the embedded activation",
        )
    model = receipt_payload["model"]
    if (
        activation_payload["model"] != model
        or model["candidateCatalogSha256"] != response["candidateCatalogSha256"]
        or model["candidateId"] != response["candidateId"]
        or model["modelId"] != response["modelId"]
        or model["modelRevision"] != response["modelRevision"]
        or model["servingProfileSha256"] != response["servingProfile"]["sha256"]
        or model["executionModelId"] != response["executionModelId"]
    ):
        _fail(
            f"{field}.runtimeAttestation.receipt model",
            "does not match the response raw-base identity",
        )
    if receipt_payload["issuedAtUtc"] != response["capturedAtUtc"]:
        _fail(
            f"{field}.capturedAtUtc",
            "does not match the signed runtime receipt issue time",
        )
    expected_evaluation = {
        "runId": response["runId"],
        "taskId": response["taskId"],
        "taskSha256": response["taskSha256"],
        "promptSha256": response["promptSha256"],
        "dataRelease": response["dataRelease"],
    }
    if receipt_payload["evaluation"] != expected_evaluation:
        _fail(
            f"{field}.runtimeAttestation.receipt evaluation",
            "does not match the response record",
        )
    if (
        receipt_payload["completionSha256"]
        != hashlib.sha256(canonical_json_bytes(completion)).hexdigest()
    ):
        _fail(
            f"{field}.runtimeAttestation.receipt completionSha256",
            "does not match the embedded completion",
        )
    output, finish_reason, usage = _parse_openai_response(
        canonical_json_bytes(completion), response["executionModelId"]
    )
    if (
        output != response["output"]["text"]
        or finish_reason != response["finishReason"]
        or usage != response["usage"]
    ):
        _fail(
            f"{field}.runtimeAttestation.completion",
            "does not match the normalized evaluation response",
        )
    return runtime


def _validate_evaluation_response_records(
    responses: list[dict[str, Any]], task_set: EvaluationTaskSet
) -> tuple[dict[str, Any], ...]:
    task_by_id = {task["taskId"]: task for task in task_set.records}
    seen: set[str] = set()
    binding: tuple[Any, ...] | None = None
    for index, response in enumerate(responses, start=1):
        task_id = response["taskId"]
        if task_id in seen:
            _fail(
                f"evaluation response line {index}.taskId",
                "duplicates an earlier response",
            )
        task = task_by_id.get(task_id)
        if task is None:
            _fail(
                f"evaluation response line {index}.taskId",
                "does not exist in the bound task set",
            )
        if (
            response["taskSha256"] != task["taskSha256"]
            or response["promptSha256"] != task["promptSha256"]
        ):
            _fail(
                f"evaluation response line {index}",
                "task or prompt hash does not match the bound task",
            )
        if response["generation"]["maxOutputTokens"] != task["maxOutputTokens"]:
            _fail(
                f"evaluation response line {index}.generation.maxOutputTokens",
                "does not match the bound task",
            )
        runtime_binding: tuple[Any, ...] = ()
        if response["schemaVersion"] == EVALUATION_RESPONSE_V2_SCHEMA_VERSION:
            runtime = _validate_base_runtime_evidence(
                response, f"evaluation response line {index}"
            )
            receipt = inspect_base_runtime_attestation_envelope(runtime["receipt"])
            expected_request = {
                "model": response["executionModelId"],
                "messages": task["messages"],
                "temperature": 0,
                "top_p": 1,
                "seed": response["generation"]["seed"],
                "max_tokens": task["maxOutputTokens"],
                "n": 1,
            }
            if (
                receipt["payload"]["requestSha256"]
                != hashlib.sha256(canonical_json_bytes(expected_request)).hexdigest()
            ):
                _fail(
                    f"evaluation response line {index}.runtimeAttestation.receipt requestSha256",
                    "does not match the task-bound model request",
                )
            activation = inspect_base_engine_activation_envelope(runtime["activation"])
            runtime_binding = (
                response["targetKind"],
                response["executionModelId"],
                activation["payload"]["activationId"],
                activation["envelopeSha256"],
                runtime["receipt"]["publicKeySpkiSha256"],
                receipt["payload"]["wrapperInstanceId"],
                receipt["payload"]["engine"]["processId"],
                receipt["payload"]["engine"]["argvSha256"],
            )
        current = (
            response["candidateCatalogSha256"],
            response["candidateId"],
            response["modelId"],
            response["modelRevision"],
            response["servingProfile"]["id"],
            response["servingProfile"]["sha256"],
            response["runId"],
            response["generation"]["seed"],
            canonical_json_bytes(response["dataRelease"]),
            response["researchOnly"],
            response["evidenceStatus"],
            response["schemaVersion"],
            *runtime_binding,
        )
        if binding is None:
            binding = current
        elif current != binding:
            _fail(
                f"evaluation response line {index}",
                "catalog, candidate, model revision, profile, run ID, seed, or release evidence differs within the run",
            )
        seen.add(task_id)
    return tuple(responses)


def validate_evaluation_responses(
    path: str | os.PathLike[str], tasks: EvaluationTaskSet | str | os.PathLike[str]
) -> tuple[dict[str, Any], ...]:
    task_set = (
        tasks
        if isinstance(tasks, EvaluationTaskSet)
        else validate_evaluation_tasks(tasks)
    )
    _, responses = _parse_jsonl(
        Path(path), "evaluation response file", _validate_response
    )
    return _validate_evaluation_response_records(responses, task_set)


def validate_attested_base_evaluation_responses(
    path: str | os.PathLike[str],
    tasks: EvaluationTaskSet | str | os.PathLike[str],
    *,
    activation_trust: BaseEngineActivationTrust,
    runtime_public_key_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], ...]:
    task_set = (
        tasks
        if isinstance(tasks, EvaluationTaskSet)
        else validate_evaluation_tasks(tasks)
    )
    responses = validate_evaluation_responses(path, task_set)
    return _validate_attested_base_evaluation_response_records(
        responses,
        task_set,
        activation_trust=activation_trust,
        runtime_public_key_path=runtime_public_key_path,
    )


def _validate_attested_base_evaluation_response_records(
    responses: tuple[dict[str, Any], ...],
    task_set: EvaluationTaskSet,
    *,
    activation_trust: BaseEngineActivationTrust,
    runtime_public_key_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], ...]:
    task_by_id = {task["taskId"]: task for task in task_set.records}
    seen_attestations: set[str] = set()
    seen_nonces: set[str] = set()
    seen_sequences: set[tuple[str, int]] = set()
    for index, response in enumerate(responses, start=1):
        field = f"attested evaluation response line {index}"
        if response["schemaVersion"] != EVALUATION_RESPONSE_V2_SCHEMA_VERSION:
            _fail(field, "must use the attested raw-base response v2 schema")
        runtime = _validate_base_runtime_evidence(response, field)
        receipt = inspect_base_runtime_attestation_envelope(runtime["receipt"])
        receipt_payload = receipt["payload"]
        issued_at = _parse_datetime(
            receipt_payload["issuedAtUtc"],
            f"{field}.runtimeAttestation.receipt.issuedAtUtc",
            require_utc_z=True,
        )
        activation = verify_base_engine_activation_envelope(
            envelope=runtime["activation"],
            trust=activation_trust,
            now=issued_at,
        )
        task = task_by_id[response["taskId"]]
        request = {
            "model": response["executionModelId"],
            "messages": task["messages"],
            "temperature": 0,
            "top_p": 1,
            "seed": response["generation"]["seed"],
            "max_tokens": task["maxOutputTokens"],
            "n": 1,
        }
        evaluation = {
            "runId": response["runId"],
            "taskId": response["taskId"],
            "taskSha256": response["taskSha256"],
            "promptSha256": response["promptSha256"],
            "dataRelease": response["dataRelease"],
        }
        verified = verify_base_runtime_attestation(
            envelope=runtime["receipt"],
            runtime_public_key_path=runtime_public_key_path,
            activation=activation,
            expected_nonce=receipt_payload["nonce"],
            expected_evaluation=evaluation,
            request=request,
            completion=runtime["completion"],
            now=issued_at,
        )
        attestation_id = verified.payload["attestationId"]
        nonce = verified.payload["nonce"]
        sequence_key = (
            verified.payload["wrapperInstanceId"],
            verified.payload["sequence"],
        )
        if attestation_id in seen_attestations or nonce in seen_nonces:
            _fail(field, "reuses an attestation identity or nonce")
        if sequence_key in seen_sequences:
            _fail(field, "reuses a wrapper sequence number")
        seen_attestations.add(attestation_id)
        seen_nonces.add(nonce)
        seen_sequences.add(sequence_key)
    return responses


def _result_hash_groups(result: Mapping[str, Any]) -> list[list[str]]:
    groups = [
        [
            result["schemaVersion"],
            result["runId"],
            result["taskId"],
            result["taskSha256"],
            result["responseSha256"],
            result["verifierId"],
            result["verifierSha256"],
            str(result["accepted"]).lower(),
        ]
    ]
    groups.extend(
        [
            [
                check["checkId"],
                str(check["passed"]).lower(),
                check["evidence"],
                check["evidenceSha256"],
            ]
            for check in result["checks"]
        ]
    )
    return groups


def verifier_result_sha256(result: Mapping[str, Any]) -> str:
    return _length_prefixed_sha256(
        "daxalgo-vibe-quant-verifier-result-record/v1", _result_hash_groups(result)
    )


def _validate_verifier_result(value: Any, line_number: int) -> dict[str, Any]:
    field = f"verifier result line {line_number}"
    result = _exact_keys(
        value,
        {
            "schemaVersion",
            "resultSha256",
            "runId",
            "taskId",
            "taskSha256",
            "responseSha256",
            "verifierId",
            "verifierSha256",
            "checks",
            "accepted",
        },
        field,
    )
    if result["schemaVersion"] != VERIFIER_RESULT_SCHEMA_VERSION:
        _fail(f"{field}.schemaVersion", f"must be {VERIFIER_RESULT_SCHEMA_VERSION!r}")
    _validate_identifier(result["runId"], f"{field}.runId")
    _validate_identifier(result["taskId"], f"{field}.taskId")
    _sha256(result["taskSha256"], f"{field}.taskSha256")
    _sha256(result["responseSha256"], f"{field}.responseSha256")
    _validate_identifier(result["verifierId"], f"{field}.verifierId")
    _sha256(result["verifierSha256"], f"{field}.verifierSha256")
    checks = result["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_REQUIRED_CHECKS:
        _fail(
            f"{field}.checks", f"must contain 1 to {MAX_REQUIRED_CHECKS} check results"
        )
    seen: set[str] = set()
    for index, raw_check in enumerate(checks):
        check = _exact_keys(
            raw_check,
            {"checkId", "passed", "evidence", "evidenceSha256"},
            f"{field}.checks[{index}]",
        )
        check_id = _validate_identifier(
            check["checkId"], f"{field}.checks[{index}].checkId"
        )
        if check_id in seen:
            _fail(f"{field}.checks[{index}].checkId", "duplicates an earlier check")
        if not isinstance(check["passed"], bool):
            _fail(f"{field}.checks[{index}].passed", "must be a boolean")
        evidence = _string(
            check["evidence"],
            f"{field}.checks[{index}].evidence",
            max_length=MAX_EVIDENCE_CHARACTERS,
        )
        if _sha256(
            check["evidenceSha256"], f"{field}.checks[{index}].evidenceSha256"
        ) != evidence_sha256(evidence):
            _fail(
                f"{field}.checks[{index}].evidenceSha256",
                "does not match canonical evidence content",
            )
        seen.add(check_id)
    if not isinstance(result["accepted"], bool):
        _fail(f"{field}.accepted", "must be a boolean")
    if result["accepted"] != all(check["passed"] for check in checks):
        _fail(f"{field}.accepted", "must equal the conjunction of every required check")
    if _sha256(
        result["resultSha256"], f"{field}.resultSha256"
    ) != verifier_result_sha256(result):
        _fail(f"{field}.resultSha256", "does not match the canonical verifier result")
    return result


def validate_verifier_results(
    path: str | os.PathLike[str],
    tasks: EvaluationTaskSet | str | os.PathLike[str],
    responses: Iterable[Mapping[str, Any]] | str | os.PathLike[str],
    *,
    require_complete: bool = False,
) -> tuple[dict[str, Any], ...]:
    task_set = (
        tasks
        if isinstance(tasks, EvaluationTaskSet)
        else validate_evaluation_tasks(tasks)
    )
    response_records = (
        tuple(responses)
        if not isinstance(responses, (str, os.PathLike))
        else validate_evaluation_responses(responses, task_set)
    )
    _, results = _parse_jsonl(
        Path(path), "verifier result file", _validate_verifier_result
    )
    _validate_verifier_result_bindings(
        results,
        task_set,
        response_records,
        require_complete=require_complete,
    )
    return tuple(results)


def _validate_verifier_result_bindings(
    results: Iterable[Mapping[str, Any]],
    task_set: EvaluationTaskSet,
    response_records: Iterable[Mapping[str, Any]],
    *,
    require_complete: bool = False,
) -> None:
    response_records = tuple(response_records)
    task_by_id = {task["taskId"]: task for task in task_set.records}
    response_by_task = {response["taskId"]: response for response in response_records}
    seen: set[str] = set()
    for index, result in enumerate(results, start=1):
        task_id = result["taskId"]
        if task_id in seen:
            _fail(
                f"verifier result line {index}.taskId", "duplicates an earlier result"
            )
        task = task_by_id.get(task_id)
        response = response_by_task.get(task_id)
        if task is None or response is None:
            _fail(
                f"verifier result line {index}.taskId",
                "does not have a bound task and response",
            )
        if result["runId"] != response["runId"]:
            _fail(
                f"verifier result line {index}.runId",
                "does not match the bound response",
            )
        if (
            result["taskSha256"] != task["taskSha256"]
            or result["responseSha256"] != response["responseSha256"]
        ):
            _fail(
                f"verifier result line {index}", "task or response hash does not match"
            )
        verifier = task["verifier"]
        if (
            result["verifierId"] != verifier["id"]
            or result["verifierSha256"] != verifier["sha256"]
        ):
            _fail(
                f"verifier result line {index}",
                "verifier identity or hash does not match the task",
            )
        actual_checks = [check["checkId"] for check in result["checks"]]
        if actual_checks != verifier["requiredChecks"]:
            _fail(
                f"verifier result line {index}.checks",
                "must exactly match requiredChecks in declared order",
            )
        seen.add(task_id)
    if require_complete:
        task_ids = set(task_by_id)
        response_ids = set(response_by_task)
        if len(response_records) != len(response_ids):
            _fail(
                "evaluation responses",
                "must not contain duplicate task IDs",
            )
        if response_ids != task_ids or len(response_records) != len(task_ids):
            _fail(
                "evaluation response file",
                "must contain exactly one response for every bound task",
            )
        if seen != task_ids:
            _fail(
                "verifier result file",
                "must contain exactly one result for every bound task and response",
            )


def _validate_verifier_decision_manifest(
    value: Any,
    *,
    task_set: EvaluationTaskSet,
    response_records: tuple[dict[str, Any], ...],
) -> tuple[dict[str, Any], ...]:
    field = "verifier decision manifest"
    manifest = _exact_keys(
        value,
        {"schemaVersion", "inputs", "decisions"},
        field,
    )
    if manifest["schemaVersion"] != VERIFIER_DECISION_MANIFEST_SCHEMA_VERSION:
        _fail(
            f"{field}.schemaVersion",
            f"must be {VERIFIER_DECISION_MANIFEST_SCHEMA_VERSION!r}",
        )
    inputs = _exact_keys(
        manifest["inputs"],
        {"taskSetSha256", "responseSetSha256"},
        f"{field}.inputs",
    )
    task_set_hash = _sha256(inputs["taskSetSha256"], f"{field}.inputs.taskSetSha256")
    response_set_hash = _sha256(
        inputs["responseSetSha256"], f"{field}.inputs.responseSetSha256"
    )
    if task_set_hash != task_set.task_set_sha256:
        _fail(f"{field}.inputs.taskSetSha256", "does not match the bound task set")
    expected_response_set_hash = evaluation_response_set_sha256(response_records)
    if response_set_hash != expected_response_set_hash:
        _fail(
            f"{field}.inputs.responseSetSha256",
            "does not match the bound response set",
        )

    decisions = manifest["decisions"]
    if (
        not isinstance(decisions, list)
        or not 1 <= len(decisions) <= MAX_EVALUATION_RECORDS
    ):
        _fail(
            f"{field}.decisions",
            f"must contain 1 to {MAX_EVALUATION_RECORDS} decisions",
        )
    validated: list[dict[str, Any]] = []
    seen: set[str] = set()
    for decision_index, raw_decision in enumerate(decisions):
        decision_field = f"{field}.decisions[{decision_index}]"
        decision = _exact_keys(
            raw_decision,
            {"taskId", "responseSha256", "checks"},
            decision_field,
        )
        task_id = _validate_identifier(decision["taskId"], f"{decision_field}.taskId")
        if task_id in seen:
            _fail(f"{decision_field}.taskId", "duplicates an earlier decision")
        _sha256(decision["responseSha256"], f"{decision_field}.responseSha256")
        checks = decision["checks"]
        if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_REQUIRED_CHECKS:
            _fail(
                f"{decision_field}.checks",
                f"must contain 1 to {MAX_REQUIRED_CHECKS} check decisions",
            )
        validated_checks: list[dict[str, Any]] = []
        check_ids: set[str] = set()
        for check_index, raw_check in enumerate(checks):
            check_field = f"{decision_field}.checks[{check_index}]"
            check = _exact_keys(
                raw_check,
                {"checkId", "passed", "evidence"},
                check_field,
            )
            check_id = _validate_identifier(check["checkId"], f"{check_field}.checkId")
            if check_id in check_ids:
                _fail(f"{check_field}.checkId", "duplicates an earlier check")
            if not isinstance(check["passed"], bool):
                _fail(f"{check_field}.passed", "must be a boolean")
            evidence = _string(
                check["evidence"],
                f"{check_field}.evidence",
                max_length=MAX_EVIDENCE_CHARACTERS,
            )
            validated_checks.append(
                {"checkId": check_id, "passed": check["passed"], "evidence": evidence}
            )
            check_ids.add(check_id)
        validated.append(
            {
                "taskId": task_id,
                "responseSha256": decision["responseSha256"],
                "checks": validated_checks,
            }
        )
        seen.add(task_id)
    return tuple(validated)


def compile_verifier_results(
    *,
    tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    decisions_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    input_paths = {
        "tasks": _regular_file(Path(tasks_path), "verifier compiler tasks input"),
        "responses": _regular_file(
            Path(responses_path), "verifier compiler responses input"
        ),
        "decisions": _regular_file(
            Path(decisions_path), "verifier compiler decisions input"
        ),
    }
    input_bytes = {
        name: _read_file_bounded(
            path,
            f"verifier compiler {name} input",
            MAX_EVALUATION_BYTES,
        )
        for name, path in input_paths.items()
    }
    input_hashes = {
        name: hashlib.sha256(raw).hexdigest() for name, raw in input_bytes.items()
    }

    def assert_inputs_unchanged() -> None:
        for name, path in input_paths.items():
            if sha256_file(path, max_bytes=MAX_EVALUATION_BYTES) != input_hashes[name]:
                _fail(
                    f"verifier compiler {name} input",
                    "changed during compilation",
                )

    task_records = _parse_jsonl_bytes(
        input_bytes["tasks"],
        "evaluation task file",
        _validate_task,
    )
    tasks = _evaluation_task_set_from_records(
        input_paths["tasks"],
        input_hashes["tasks"],
        task_records,
    )
    response_records = _parse_jsonl_bytes(
        input_bytes["responses"],
        "evaluation response file",
        _validate_response,
    )
    responses = _validate_evaluation_response_records(response_records, tasks)
    for response in responses:
        if (
            response["dataRelease"] is not None
            or response["researchOnly"] is not True
            or response["evidenceStatus"] != "unpromoted-research"
        ):
            _fail(
                "verifier compiler responses input",
                "human decisions are research-only; release-bound evidence must use executable verifier replay",
            )
    task_by_id = {task["taskId"]: task for task in tasks.records}
    response_by_task = {response["taskId"]: response for response in responses}
    task_ids = set(task_by_id)
    response_ids = set(response_by_task)
    if response_ids != task_ids:
        missing = sorted(task_ids - response_ids)
        extra = sorted(response_ids - task_ids)
        details: list[str] = []
        if missing:
            details.append(f"missing task IDs {missing}")
        if extra:
            details.append(f"unknown task IDs {extra}")
        _fail(
            "evaluation response file",
            "must contain exactly one response for every task; " + "; ".join(details),
        )

    manifest = _parse_json_document_bytes(
        input_bytes["decisions"], "verifier decision manifest file"
    )
    decisions = _validate_verifier_decision_manifest(
        manifest,
        task_set=tasks,
        response_records=responses,
    )
    decision_by_task = {decision["taskId"]: decision for decision in decisions}
    decision_ids = set(decision_by_task)
    if decision_ids != task_ids:
        missing = sorted(task_ids - decision_ids)
        extra = sorted(decision_ids - task_ids)
        details = []
        if missing:
            details.append(f"missing task IDs {missing}")
        if extra:
            details.append(f"unknown task IDs {extra}")
        _fail(
            "verifier decision manifest.decisions",
            "must contain exactly one decision for every task; " + "; ".join(details),
        )

    results: list[dict[str, Any]] = []
    output_bytes = bytearray()
    for line_number, task_id in enumerate(sorted(task_ids), start=1):
        task = task_by_id[task_id]
        response = response_by_task[task_id]
        decision = decision_by_task[task_id]
        decision_field = f"verifier decision for task {task_id!r}"
        if decision["responseSha256"] != response["responseSha256"]:
            _fail(
                f"{decision_field}.responseSha256",
                "does not match the bound response",
            )
        actual_checks = [check["checkId"] for check in decision["checks"]]
        required_checks = task["verifier"]["requiredChecks"]
        if actual_checks != required_checks:
            _fail(
                f"{decision_field}.checks",
                "must exactly match requiredChecks in declared order",
            )
        checks = [
            {
                "checkId": check["checkId"],
                "passed": check["passed"],
                "evidence": check["evidence"],
                "evidenceSha256": evidence_sha256(check["evidence"]),
            }
            for check in decision["checks"]
        ]
        result: dict[str, Any] = {
            "schemaVersion": VERIFIER_RESULT_SCHEMA_VERSION,
            "resultSha256": "0" * 64,
            "runId": response["runId"],
            "taskId": task_id,
            "taskSha256": task["taskSha256"],
            "responseSha256": response["responseSha256"],
            "verifierId": task["verifier"]["id"],
            "verifierSha256": task["verifier"]["sha256"],
            "checks": checks,
            "accepted": all(check["passed"] for check in checks),
        }
        result["resultSha256"] = verifier_result_sha256(result)
        _validate_verifier_result(result, line_number)
        encoded = canonical_json_bytes(result) + b"\n"
        if len(encoded) > MAX_EVALUATION_LINE_BYTES:
            _fail(
                f"verifier result line {line_number}",
                f"exceeds {MAX_EVALUATION_LINE_BYTES} bytes",
            )
        if len(output_bytes) + len(encoded) > MAX_EVALUATION_BYTES:
            _fail("verifier result output", f"exceeds {MAX_EVALUATION_BYTES} bytes")
        output_bytes.extend(encoded)
        results.append(result)

    parsed_results = _parse_jsonl_bytes(
        output_bytes,
        "verifier result output",
        _validate_verifier_result,
    )
    _validate_verifier_result_bindings(
        parsed_results,
        tasks,
        responses,
        require_complete=True,
    )
    assert_inputs_unchanged()
    destination = Path(output_path)
    _write_bytes_atomic_no_clobber(
        destination,
        output_bytes,
        "verifier result output",
        before_install=assert_inputs_unchanged,
    )
    installed = validate_verifier_results(
        destination,
        tasks,
        responses,
        require_complete=True,
    )
    if installed != tuple(parsed_results):
        _fail("verifier result output", "installed bytes changed during publication")
    return {
        "schemaVersion": VERIFIER_RESULT_SCHEMA_VERSION,
        "recordCount": len(installed),
        "taskSetSha256": tasks.task_set_sha256,
        "responseSetSha256": evaluation_response_set_sha256(responses),
        "verifierResultSetSha256": verifier_result_set_sha256(installed),
        "outputPath": str(destination),
    }


def _policy_hash_groups(policy: Mapping[str, Any]) -> list[list[str]]:
    payload = dict(policy)
    payload["policySha256"] = "0" * 64
    return [[canonical_json_bytes(payload).decode("utf-8")]]


def promotion_policy_sha256(policy: Mapping[str, Any]) -> str:
    return _length_prefixed_sha256(
        "daxalgo-vibe-quant-promotion-policy-record/v1", _policy_hash_groups(policy)
    )


def _validate_run_identity(value: Any, field: str) -> dict[str, Any]:
    identity = _exact_keys(
        value,
        {
            "responseSchemaVersion",
            "targetKind",
            "executionModelId",
            "candidateCatalogSha256",
            "candidateId",
            "modelId",
            "modelRevision",
            "servingProfile",
            "runId",
            "seed",
        },
        field,
    )
    if identity["responseSchemaVersion"] not in {
        EVALUATION_RESPONSE_SCHEMA_VERSION,
        EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
    }:
        _fail(f"{field}.responseSchemaVersion", "is not a supported response schema")
    if identity["targetKind"] not in {"trained-adapter", "raw-base"}:
        _fail(f"{field}.targetKind", "is not a supported evaluation target")
    _validate_identifier(identity["executionModelId"], f"{field}.executionModelId")
    if (
        identity["responseSchemaVersion"] == EVALUATION_RESPONSE_V2_SCHEMA_VERSION
        and identity["targetKind"] != "raw-base"
    ):
        _fail(
            field,
            "response schema version and target kind are not a reviewed pairing",
        )
    _sha256(identity["candidateCatalogSha256"], f"{field}.candidateCatalogSha256")
    _validate_identifier(identity["candidateId"], f"{field}.candidateId")
    _string(identity["modelId"], f"{field}.modelId", max_length=500)
    _revision(identity["modelRevision"], f"{field}.modelRevision")
    profile = _exact_keys(
        identity["servingProfile"], {"id", "sha256"}, f"{field}.servingProfile"
    )
    _validate_identifier(profile["id"], f"{field}.servingProfile.id")
    _sha256(profile["sha256"], f"{field}.servingProfile.sha256")
    expected_execution_model = (
        "daxalgo-base-sha256-"
        if identity["targetKind"] == "raw-base"
        else "daxalgo-expert-sha256-"
    ) + profile["sha256"]
    if identity["executionModelId"] != expected_execution_model:
        _fail(
            f"{field}.executionModelId",
            "does not match the target kind and serving profile",
        )
    _validate_identifier(identity["runId"], f"{field}.runId")
    _integer(identity["seed"], f"{field}.seed", 0, 2_147_483_647)
    return identity


def _run_artifact_identity(identity: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        identity["modelId"],
        identity["modelRevision"],
        identity["servingProfile"]["sha256"],
    )


def _validate_domain_minimums(
    value: Any, field: str, *, minimum: int = 1
) -> dict[str, int]:
    minimums = _exact_keys(value, set(DOMAINS), field)
    for domain in DOMAINS:
        _integer(minimums[domain], f"{field}.{domain}", minimum, MAX_EVALUATION_RECORDS)
    return minimums


def validate_promotion_policy(path: str | os.PathLike[str]) -> dict[str, Any]:
    policy = _exact_keys(
        load_json_document(path),
        {
            "schemaVersion",
            "policySha256",
            "policyId",
            "thresholdSourceSplit",
            "calibrationTaskSetSha256",
            "calibrationEvidenceSha256",
            "sealedTaskSetSha256",
            "frozenAtUtc",
            "candidateRun",
            "baselineRun",
            "minimumTotalTasks",
            "minimumCriticalTasks",
            "minimumPerDomainTaskCounts",
            "minimumPerDomainContaminationGroupCounts",
            "overallAcceptedRateThreshold",
            "perDomainAcceptedRateThresholds",
            "requireNoOverallRegression",
            "requireNoPerDomainRegression",
            "dataRelease",
            "researchOnly",
        },
        "promotion policy",
    )
    if policy["schemaVersion"] != PROMOTION_POLICY_SCHEMA_VERSION:
        _fail(
            "promotion policy.schemaVersion",
            f"must be {PROMOTION_POLICY_SCHEMA_VERSION!r}",
        )
    data_release = _validate_data_release_identity(
        policy["dataRelease"], "promotion policy.dataRelease"
    )
    if not isinstance(policy["researchOnly"], bool):
        _fail("promotion policy.researchOnly", "must be a boolean")
    if (data_release is None) is not policy["researchOnly"]:
        _fail(
            "promotion policy.dataRelease",
            "must be null only for an explicitly research-only policy",
        )
    _validate_identifier(policy["policyId"], "promotion policy.policyId")
    if policy["thresholdSourceSplit"] != "calibration":
        _fail(
            "promotion policy.thresholdSourceSplit",
            "must be 'calibration'; sealed data cannot tune thresholds",
        )
    _sha256(
        policy["calibrationTaskSetSha256"], "promotion policy.calibrationTaskSetSha256"
    )
    _sha256(
        policy["calibrationEvidenceSha256"],
        "promotion policy.calibrationEvidenceSha256",
    )
    _sha256(policy["sealedTaskSetSha256"], "promotion policy.sealedTaskSetSha256")
    _parse_datetime(
        policy["frozenAtUtc"], "promotion policy.frozenAtUtc", require_utc_z=True
    )
    candidate_run = _validate_run_identity(
        policy["candidateRun"], "promotion policy.candidateRun"
    )
    baseline_run = _validate_run_identity(
        policy["baselineRun"], "promotion policy.baselineRun"
    )
    if (
        candidate_run["candidateCatalogSha256"]
        != baseline_run["candidateCatalogSha256"]
    ):
        _fail(
            "promotion policy.baselineRun.candidateCatalogSha256",
            "must match the candidate catalog",
        )
    if candidate_run["runId"] == baseline_run["runId"]:
        _fail(
            "promotion policy.baselineRun.runId",
            "must differ from the candidate run ID",
        )
    if candidate_run["seed"] != baseline_run["seed"]:
        _fail(
            "promotion policy.baselineRun.seed",
            "must match the candidate seed for a paired comparison",
        )
    if _run_artifact_identity(candidate_run) == _run_artifact_identity(baseline_run):
        _fail(
            "promotion policy.baselineRun",
            "must identify a distinct model or serving artifact",
        )
    _integer(
        policy["minimumTotalTasks"],
        "promotion policy.minimumTotalTasks",
        1,
        MAX_EVALUATION_RECORDS,
    )
    _integer(
        policy["minimumCriticalTasks"],
        "promotion policy.minimumCriticalTasks",
        1,
        MAX_EVALUATION_RECORDS,
    )
    _validate_domain_minimums(
        policy["minimumPerDomainTaskCounts"],
        "promotion policy.minimumPerDomainTaskCounts",
    )
    _validate_domain_minimums(
        policy["minimumPerDomainContaminationGroupCounts"],
        "promotion policy.minimumPerDomainContaminationGroupCounts",
    )
    _number(
        policy["overallAcceptedRateThreshold"],
        "promotion policy.overallAcceptedRateThreshold",
        0,
        1,
        minimum_open=True,
    )
    thresholds = _exact_keys(
        policy["perDomainAcceptedRateThresholds"],
        set(DOMAINS),
        "promotion policy.perDomainAcceptedRateThresholds",
    )
    for domain in DOMAINS:
        _number(
            thresholds[domain],
            f"promotion policy.perDomainAcceptedRateThresholds.{domain}",
            0,
            1,
            minimum_open=True,
        )
    if policy["requireNoOverallRegression"] is not True:
        _fail("promotion policy.requireNoOverallRegression", "must be true")
    if policy["requireNoPerDomainRegression"] is not True:
        _fail("promotion policy.requireNoPerDomainRegression", "must be true")
    expected = promotion_policy_sha256(policy)
    if _sha256(policy["policySha256"], "promotion policy.policySha256") != expected:
        _fail("promotion policy.policySha256", "does not match the canonical policy")
    return policy


def _utc_z(now: datetime) -> str:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValidationError("capture clock must return a timezone-aware datetime")
    return (
        now.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _validate_endpoint(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(_string(base_url, "base URL", max_length=2_000))
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        _fail("base URL", "must not contain credentials, a query, or a fragment")
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        if not hostname:
            _fail("base URL", "must include a host")
    elif parsed.scheme == "http":
        if hostname not in {"localhost", "127.0.0.1", "::1"}:
            _fail("base URL", "plain HTTP is allowed only for loopback hosts")
    else:
        _fail("base URL", "must use HTTPS, or HTTP on a loopback host")
    path = parsed.path.rstrip("/")
    endpoint_path = (
        path if path.endswith("/chat/completions") else path + "/chat/completions"
    )
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, endpoint_path, "", "")
    )


def _endpoint_is_loopback(endpoint: str) -> bool:
    return (urllib.parse.urlsplit(endpoint).hostname or "").lower() in {
        "127.0.0.1",
        "::1",
    }


def _validate_attested_base_endpoint(base_url: str, listen_port: int) -> str:
    parsed = urllib.parse.urlsplit(_string(base_url, "base URL", max_length=2_000))
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port != listen_port
    ):
        _fail(
            "base URL",
            "attested raw-base capture must use the configured literal loopback wrapper port",
        )
    if parsed.path.rstrip("/") not in {"", "/v1"}:
        _fail("base URL", "attested raw-base capture accepts only the wrapper API root")
    return urllib.parse.urlunsplit(
        (
            "http",
            f"127.0.0.1:{listen_port}",
            BASE_ATTESTED_COMPLETIONS_PATH,
            "",
            "",
        )
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise ValidationError("model endpoint redirects are not accepted")


def _default_transport(
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_seconds: float,
    max_response_bytes: int,
) -> TransportResponse:
    request = urllib.request.Request(
        url, data=body, headers=dict(headers), method="POST"
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(),
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final_url = response.geturl()
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    if int(length) > max_response_bytes:
                        _fail("model response", f"exceeds {max_response_bytes} bytes")
                except ValueError as error:
                    raise ValidationError(
                        "model response Content-Length is invalid"
                    ) from error
            response_body = response.read(max_response_bytes + 1)
    except urllib.error.HTTPError as error:
        raise ValidationError(f"model endpoint returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise ValidationError(
            f"model endpoint request failed: {error.reason}"
        ) from error
    if len(response_body) > max_response_bytes:
        _fail("model response", f"exceeds {max_response_bytes} bytes")
    return TransportResponse(response_body, final_url)


def _parse_openai_response(
    raw: bytes, requested_model: str
) -> tuple[str, str, dict[str, int]]:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("model response must be strict UTF-8 JSON") from error
    if not isinstance(value, dict) or not {"model", "choices", "usage"} <= set(value):
        _fail("model response", "must contain model, choices, and usage")
    envelope = value
    if envelope["model"] != requested_model:
        _fail("model response.model", "does not exactly match the requested model")
    choices = envelope["choices"]
    if not isinstance(choices, list) or len(choices) != 1:
        _fail("model response.choices", "must contain exactly one choice")
    choice = choices[0]
    if (
        not isinstance(choice, dict)
        or "message" not in choice
        or "finish_reason" not in choice
    ):
        _fail("model response.choices[0]", "must contain message and finish_reason")
    message = choice["message"]
    if (
        not isinstance(message, dict)
        or "role" not in message
        or "content" not in message
    ):
        _fail("model response.choices[0].message", "must contain role and content")
    if message["role"] != "assistant":
        _fail("model response.choices[0].message.role", "must be assistant")
    finish_reason = choice["finish_reason"]
    if finish_reason not in FINISH_REASONS:
        _fail("model response.choices[0].finish_reason", "is not accepted")
    raw_output = message["content"]
    if raw_output is None and finish_reason != "stop":
        output = ""
    elif isinstance(raw_output, str):
        output = raw_output
    else:
        _fail(
            "model response.choices[0].message.content",
            "must be a string, or null for a non-stop finish",
        )
    if finish_reason == "stop" and not output.strip():
        _fail(
            "model response.choices[0].message.content",
            "must be non-empty for a stop finish",
        )
    if len(output) > MAX_OUTPUT_BYTES or len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        _fail(
            "model response output",
            f"exceeds {MAX_OUTPUT_BYTES} characters or UTF-8 bytes",
        )
    usage_raw = envelope["usage"]
    if not isinstance(usage_raw, dict) or not {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    } <= set(usage_raw):
        _fail(
            "model response.usage",
            "must contain prompt_tokens, completion_tokens, and total_tokens",
        )
    usage = {
        "promptTokens": _integer(
            usage_raw["prompt_tokens"],
            "model response.usage.prompt_tokens",
            0,
            100_000_000,
        ),
        "completionTokens": _integer(
            usage_raw["completion_tokens"],
            "model response.usage.completion_tokens",
            0,
            100_000_000,
        ),
        "totalTokens": _integer(
            usage_raw["total_tokens"],
            "model response.usage.total_tokens",
            0,
            200_000_000,
        ),
    }
    if usage["totalTokens"] != usage["promptTokens"] + usage["completionTokens"]:
        _fail(
            "model response.usage.total_tokens",
            "must equal prompt_tokens plus completion_tokens",
        )
    return output, finish_reason, usage


def _write_bytes_atomic_no_clobber(
    path: Path,
    raw: bytes | bytearray,
    field: str,
    *,
    before_install: Callable[[], None] | None = None,
) -> None:
    destination = _reject_reparse_components(path, field, allow_missing_suffix=True)
    parent = _reject_reparse_components(destination.parent, f"{field} parent")
    if not parent.is_dir():
        _fail(f"{field} parent", "must be an existing directory")
    if destination.exists():
        _fail(field, f"already exists: {destination}")
    staged: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if before_install is not None:
            before_install()
        try:
            os.link(staged, destination)
        except FileExistsError as error:
            raise ValidationError(f"{field}: already exists: {destination}") from error
        except OSError as error:
            raise ValidationError(
                f"{field}: atomic no-clobber install is unavailable: {error}"
            ) from error
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass


def capture_openai_responses(
    *,
    tasks_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str] | None = None,
    training_artifact_path: str | os.PathLike[str] | None = None,
    training_manifest_path: str | os.PathLike[str] | None = None,
    base_evaluation_profile_path: str | os.PathLike[str] | None = None,
    base_model_snapshot_manifest_path: str | os.PathLike[str] | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    base_model_source_lock_path: str | os.PathLike[str] | None = None,
    base_engine_wrapper_config_path: str | os.PathLike[str] | None = None,
    base_engine_activation_trust: BaseEngineActivationTrust | None = None,
    run_id: str,
    base_url: str,
    api_key_env: str,
    seed: int,
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    research_only: bool = False,
    timeout_seconds: float = 60.0,
    max_response_bytes: int = MAX_CAPTURE_RESPONSE_BYTES,
    transport: Transport | None = None,
    clock: Callable[[], datetime] | None = None,
    monotonic: Callable[[], float] | None = None,
) -> dict[str, Any]:
    tasks = validate_evaluation_tasks(tasks_path)
    clock_impl = clock or (lambda: datetime.now(timezone.utc))
    if len({task["split"] for task in tasks.records}) != 1:
        _fail(
            "evaluation task file",
            "capture requires a homogeneous calibration or sealed split",
        )
    endpoint = _validate_endpoint(base_url)
    catalog_raw = _read_file_bounded(
        Path(catalog_path), "candidate catalog", MAX_JSON_BYTES
    )
    try:
        catalog_value = json.loads(
            catalog_raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("candidate catalog: must be strict UTF-8 JSON") from error
    catalog = _validate_candidate_catalog_document(catalog_value)
    catalog_hash = hashlib.sha256(catalog_raw).hexdigest()
    adapter_inputs = (
        serving_profile_path,
        training_artifact_path,
        training_manifest_path,
    )
    base_inputs = (
        base_evaluation_profile_path,
        base_model_snapshot_manifest_path,
        base_model_snapshot_path,
        base_model_source_lock_path,
    )
    has_adapter_inputs = any(value is not None for value in adapter_inputs)
    has_base_inputs = any(value is not None for value in base_inputs)
    if has_adapter_inputs and has_base_inputs:
        _fail(
            "evaluation target",
            "must use either a trained-adapter profile or a base-evaluation profile",
        )
    if not has_adapter_inputs and not has_base_inputs:
        _fail("evaluation target", "is required")
    if has_adapter_inputs and any(value is None for value in adapter_inputs):
        _fail(
            "trained-adapter evaluation target",
            "requires serving profile, training artifact, and training manifest",
        )
    if has_base_inputs and any(value is None for value in base_inputs):
        _fail(
            "base-model evaluation target",
            "requires profile, approved source lock, snapshot manifest, and snapshot directory",
        )
    is_base_evaluation = has_base_inputs
    if is_base_evaluation and (trainer_provenance_trust is not None):
        _fail(
            "trainer provenance trust",
            "cannot be supplied for a raw-base evaluation target",
        )
    if is_base_evaluation:
        serving_profile = validate_base_evaluation_profile(
            profile_path=base_evaluation_profile_path,
            snapshot_manifest_path=base_model_snapshot_manifest_path,
            snapshot_path=base_model_snapshot_path,
            catalog_path=catalog_path,
            source_lock_path=base_model_source_lock_path,
        )
        manifest = None
        profile_mode = "base-model"
        profile_label = "base-evaluation profile"
    else:
        serving_profile = validate_serving_profile(
            serving_profile_path,
            artifact_path=training_artifact_path,
            manifest_path=training_manifest_path,
            trainer_provenance_trust=trainer_provenance_trust,
            trainer_provenance_now=(
                clock_impl() if trainer_provenance_trust is not None else None
            ),
        )
        manifest = validate_manifest_path(training_manifest_path)
        profile_mode = serving_profile.document["trainingArtifact"]["mode"]
        profile_label = "serving profile"
    profile = serving_profile.document
    base_wrapper_config = None
    base_activation = None
    attested_base_endpoint = None
    if not is_base_evaluation and (
        base_engine_wrapper_config_path is not None
        or base_engine_activation_trust is not None
    ):
        _fail(
            "base-engine runtime attestation",
            "is accepted only for a raw-base evaluation target",
        )
    if is_base_evaluation and research_only:
        if (
            base_engine_wrapper_config_path is not None
            or base_engine_activation_trust is not None
        ):
            _fail(
                "base-engine runtime attestation",
                "cannot be mixed with explicitly unbound research capture",
            )
    elif is_base_evaluation:
        if (
            base_engine_wrapper_config_path is None
            or base_engine_activation_trust is None
        ):
            _fail(
                "base-model evaluation target",
                "release-bound capture requires engine-owned runtime attestation, an owned base-engine config, and pinned activation trust",
            )
        base_wrapper_config = load_base_engine_wrapper_config(
            base_engine_wrapper_config_path
        )
        expected_paths = {
            "profile": (
                base_wrapper_config.target.profile_path,
                Path(os.path.abspath(os.fspath(base_evaluation_profile_path))),
            ),
            "snapshot manifest": (
                base_wrapper_config.target.snapshot_manifest_path,
                Path(os.path.abspath(os.fspath(base_model_snapshot_manifest_path))),
            ),
            "snapshot": (
                base_wrapper_config.target.snapshot_path,
                Path(os.path.abspath(os.fspath(base_model_snapshot_path))),
            ),
            "catalog": (
                base_wrapper_config.target.catalog_path,
                Path(os.path.abspath(os.fspath(catalog_path))),
            ),
            "source lock": (
                base_wrapper_config.target.source_lock_path,
                Path(os.path.abspath(os.fspath(base_model_source_lock_path))),
            ),
        }
        for label, (configured, supplied) in expected_paths.items():
            if configured != supplied:
                _fail(
                    f"base-engine {label}",
                    "does not match the capture target path",
                )
        if base_wrapper_config.target.expected_profile_sha256 != serving_profile.sha256:
            _fail(
                "base-engine serving profile",
                "does not match the capture target SHA-256",
            )
        if api_key_env != base_wrapper_config.service.bearer_token_environment:
            _fail(
                "API key environment variable",
                "does not match the owned base-engine wrapper config",
            )
        configured_activation_trust = base_wrapper_config.activation.trust
        if (
            Path(
                os.path.abspath(os.fspath(base_engine_activation_trust.public_key_path))
            )
            != configured_activation_trust.public_key_path
            or base_engine_activation_trust.public_key_spki_sha256
            != configured_activation_trust.public_key_spki_sha256
            or base_engine_activation_trust.audience
            != configured_activation_trust.audience
            or base_engine_activation_trust.key_id != configured_activation_trust.key_id
            or base_engine_activation_trust.signer_role
            != configured_activation_trust.signer_role
        ):
            _fail(
                "base-engine activation trust",
                "does not exactly match the trust pinned by the owned wrapper config",
            )
        attested_base_endpoint = _validate_attested_base_endpoint(
            base_url, base_wrapper_config.service.listen_port
        )
        base_activation = verify_base_engine_activation(
            activation_path=base_wrapper_config.activation.path,
            config=base_wrapper_config,
            trust=base_engine_activation_trust,
            now=clock_impl(),
        )
    if profile["candidateCatalogSha256"] != catalog_hash:
        _fail(
            f"{profile_label}.candidateCatalogSha256",
            "does not match the evaluation candidate catalog bytes",
        )
    candidate_id = profile["candidateId"]
    model_id = profile["baseModel"]["modelId"]
    model_revision = profile["baseModel"]["revision"]
    selected = next(
        (
            candidate
            for candidate in catalog["candidates"]
            if candidate["id"] == candidate_id
        ),
        None,
    )
    if selected is None:
        _fail("candidate ID", "does not exist in the pinned candidate catalog")
    if selected["modelId"] != model_id or selected["revision"] != model_revision:
        _fail(
            "candidate",
            "model ID or exact revision does not match the pinned candidate catalog",
        )
    release: dict[str, Any] | None = None
    release_identity: dict[str, str] | None = None
    if research_only:
        if not _endpoint_is_loopback(endpoint):
            _fail(
                "base URL",
                "unbound research-only capture is restricted to a loopback endpoint",
            )
        if data_release_path is not None:
            _fail("evaluation release", "cannot be supplied for research-only capture")
        if (
            review_receipt_trust is not None
            or evaluation_authoring_approval_trust is not None
            or review_receipt_now is not None
        ):
            _fail(
                "release authority trust",
                "cannot be supplied for research-only capture",
            )
        if not is_base_evaluation and profile_mode != "unpromoted-research":
            _fail(
                "serving profile.trainingArtifact.mode",
                "must be unpromoted-research for research-only capture",
            )
        if manifest is not None and manifest.get("dataRelease") is not None:
            _fail(
                "manifest.dataRelease",
                "must be null for research-only unbound capture",
            )
    else:
        if data_release_path is None:
            _fail(
                "evaluation release",
                "a fully validated bound release is required for capture",
            )
        if review_receipt_trust is None:
            _fail(
                "review-receipt trust",
                "is required for release-bound capture",
            )
        if evaluation_authoring_approval_trust is None:
            _fail(
                "evaluation-authoring approval trust",
                "is required for release-bound capture",
            )
        if not is_base_evaluation and profile_mode != "unpromoted-candidate":
            _fail(
                "serving profile.trainingArtifact.mode",
                "must be unpromoted-candidate for release-bound capture",
            )
        from .release import (
            PROVIDER_PURPOSES,
            TRAINING_PURPOSES,
            validate_corpus_evaluation_release_with_identity,
            validate_release_evaluation_task_set,
        )

        release, release_identity = validate_corpus_evaluation_release_with_identity(
            data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            now=review_receipt_now,
        )
        if not is_base_evaluation and release["purpose"] not in TRAINING_PURPOSES:
            _fail(
                "release.purpose",
                "must authorize training and evaluation for candidate capture",
            )
        if not is_base_evaluation:
            release_sft = release["corpus"]["sft"]
            if release_sft is None or (
                release_sft["sha256"] != manifest["dataset"]["sha256"]
                or release_sft["recordCount"] != manifest["dataset"]["recordCount"]
            ):
                _fail(
                    "manifest.dataset",
                    "does not match the validated release SFT",
                )
        if (
            not _endpoint_is_loopback(endpoint)
            and release["purpose"] not in PROVIDER_PURPOSES
        ):
            _fail(
                "release.purpose",
                "must authorize provider upload for a non-loopback endpoint",
            )
        validate_release_evaluation_task_set(release, tasks)
        if manifest is not None and manifest.get("dataRelease") != release_identity:
            _fail(
                "manifest.dataRelease",
                "does not match the fully validated evaluation release",
            )
    _validate_identifier(run_id, "run ID")
    _integer(seed, "seed", 0, 2_147_483_647)
    timeout = _number(
        timeout_seconds, "timeout seconds", 0, MAX_TIMEOUT_SECONDS, minimum_open=True
    )
    response_limit = _integer(
        max_response_bytes, "max response bytes", 1, MAX_CAPTURE_RESPONSE_BYTES
    )
    if not isinstance(api_key_env, str) or not _ENV_NAME_RE.fullmatch(api_key_env):
        _fail("API key environment variable", "has an invalid name")
    api_key = os.environ.get(api_key_env)
    if api_key is None or not api_key.strip():
        _fail("API key environment variable", f"{api_key_env!r} is not set")
    if any(unicodedata.category(character) == "Cc" for character in api_key):
        _fail(
            "API key environment variable",
            "value contains prohibited control characters",
        )
    if any(not 0x21 <= ord(character) <= 0x7E for character in api_key):
        _fail(
            "API key environment variable",
            "value must contain visible ASCII characters only",
        )
    transport_impl = transport or _default_transport
    monotonic_impl = monotonic or time.monotonic
    output_bytes = bytearray()
    record_count = 0
    issued_nonces: set[str] = set()

    def validate_current_base_activation() -> Any:
        if (
            base_wrapper_config is None
            or base_activation is None
            or base_engine_activation_trust is None
        ):
            _fail("base-engine runtime attestation", "validation state is unavailable")
        current = verify_base_engine_activation(
            activation_path=base_wrapper_config.activation.path,
            config=base_wrapper_config,
            trust=base_engine_activation_trust,
            now=clock_impl(),
        )
        if (
            current.envelope_sha256 != base_activation.envelope_sha256
            or current.payload_sha256 != base_activation.payload_sha256
            or current.payload != base_activation.payload
        ):
            _fail(
                "base-engine activation",
                "changed while attested responses were captured",
            )
        return current

    def validate_current_adapter_target() -> None:
        if is_base_evaluation:
            return
        current = validate_serving_profile(
            serving_profile_path,
            artifact_path=training_artifact_path,
            manifest_path=training_manifest_path,
            trainer_provenance_trust=trainer_provenance_trust,
            trainer_provenance_now=(
                clock_impl() if trainer_provenance_trust is not None else None
            ),
        )
        if (
            current.sha256 != serving_profile.sha256
            or current.document != serving_profile.document
        ):
            _fail(
                "trained-adapter evaluation target",
                "changed while responses were captured",
            )

    for task in tasks.records:
        validate_current_adapter_target()
        if not research_only:
            _, current_release_identity = (
                validate_corpus_evaluation_release_with_identity(
                    data_release_path,
                    review_receipt_trust=review_receipt_trust,
                    evaluation_authoring_approval_trust=(
                        evaluation_authoring_approval_trust
                    ),
                    now=review_receipt_now,
                )
            )
            if current_release_identity != release_identity:
                _fail(
                    "evaluation release",
                    "changed while provider responses were captured",
                )
        # Only model-visible prompt fields are sent. Context/verifier/rubric metadata remains sealed.
        model_request = {
            "model": serving_profile.execution_model_id,
            "messages": task["messages"],
            "temperature": 0,
            "top_p": 1,
            "seed": seed,
            "max_tokens": task["maxOutputTokens"],
            "n": 1,
        }
        request_endpoint = endpoint
        nonce: str | None = None
        evaluation_binding: dict[str, Any] | None = None
        if attested_base_endpoint is not None:
            validate_current_base_activation()
            nonce = secrets.token_urlsafe(32)
            if nonce in issued_nonces:
                _fail("base-engine attestation nonce", "was generated more than once")
            issued_nonces.add(nonce)
            evaluation_binding = {
                "runId": run_id,
                "taskId": task["taskId"],
                "taskSha256": task["taskSha256"],
                "promptSha256": task["promptSha256"],
                "dataRelease": release_identity,
            }
            request_body = canonical_json_bytes(
                {
                    "schemaVersion": BASE_ATTESTED_COMPLETION_REQUEST_SCHEMA_VERSION,
                    "nonce": nonce,
                    "evaluation": evaluation_binding,
                    "request": model_request,
                }
            )
            request_endpoint = attested_base_endpoint
        else:
            current_activation = None
            request_body = canonical_json_bytes(model_request)
        started = monotonic_impl()
        transport_response = transport_impl(
            request_endpoint,
            {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            request_body,
            timeout,
            response_limit,
        )
        elapsed_ms = max(0, round((monotonic_impl() - started) * 1000))
        if not isinstance(transport_response, TransportResponse):
            _fail("model transport", "must return TransportResponse with a final URL")
        if not isinstance(transport_response.body, bytes):
            _fail("model transport", "response body must be bytes")
        if attested_base_endpoint is None:
            final_url = _validate_endpoint(transport_response.final_url)
            if final_url != endpoint:
                _fail("model transport", "redirected or changed the final endpoint URL")
        elif transport_response.final_url != attested_base_endpoint:
            _fail(
                "model transport",
                "redirected or changed the final wrapper endpoint URL",
            )
        if len(transport_response.body) > response_limit:
            _fail("model response", f"exceeds {response_limit} bytes")
        runtime_attestation: dict[str, Any] | None = None
        attested_captured_at: str | None = None
        if attested_base_endpoint is not None:
            attested_response = _exact_keys(
                _parse_json_document_bytes(
                    transport_response.body,
                    "base-engine attested completion response",
                ),
                {"schemaVersion", "completion", "runtimeAttestation"},
                "base-engine attested completion response",
            )
            if (
                attested_response["schemaVersion"]
                != BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION
            ):
                _fail(
                    "base-engine attested completion response.schemaVersion",
                    f"must be {BASE_ATTESTED_COMPLETION_RESPONSE_SCHEMA_VERSION!r}",
                )
            completion = attested_response["completion"]
            if not isinstance(completion, dict):
                _fail(
                    "base-engine attested completion response.completion",
                    "must be an object",
                )
            current_activation = validate_current_base_activation()
            if nonce is None or evaluation_binding is None:
                _fail(
                    "base-engine runtime attestation", "request binding is unavailable"
                )
            receipt_time = clock_impl()
            receipt = verify_base_runtime_attestation(
                envelope=attested_response["runtimeAttestation"],
                runtime_public_key_path=base_wrapper_config.runtime_signing.public_key_path,
                activation=current_activation,
                expected_nonce=nonce,
                expected_evaluation=evaluation_binding,
                request=model_request,
                completion=completion,
                now=receipt_time,
            )
            output, finish_reason, usage = _parse_openai_response(
                canonical_json_bytes(completion),
                serving_profile.execution_model_id,
            )
            runtime_attestation = {
                "activation": current_activation.envelope,
                "receipt": receipt.envelope,
                "completion": completion,
            }
            attested_captured_at = receipt.payload["issuedAtUtc"]
        else:
            output, finish_reason, usage = _parse_openai_response(
                transport_response.body,
                serving_profile.execution_model_id,
            )
        response: dict[str, Any] = {
            "schemaVersion": (
                EVALUATION_RESPONSE_V2_SCHEMA_VERSION
                if runtime_attestation is not None
                else EVALUATION_RESPONSE_SCHEMA_VERSION
            ),
            "responseSha256": "0" * 64,
            "candidateCatalogSha256": catalog_hash,
            "candidateId": candidate_id,
            "modelId": model_id,
            "modelRevision": model_revision,
            "servingProfile": {
                "id": profile["profileId"],
                "sha256": serving_profile.sha256,
            },
            "targetKind": "raw-base" if is_base_evaluation else "trained-adapter",
            "executionModelId": serving_profile.execution_model_id,
            "runId": run_id,
            "taskId": task["taskId"],
            "taskSha256": task["taskSha256"],
            "promptSha256": task["promptSha256"],
            "dataRelease": release_identity,
            "researchOnly": research_only,
            "evidenceStatus": (
                "unpromoted-research" if research_only else "release-bound"
            ),
            "output": {
                "text": output,
                "sha256": evaluation_output_sha256(output),
                "byteCount": len(output.encode("utf-8")),
            },
            "generation": {
                "temperature": 0,
                "topP": 1,
                "seed": seed,
                "maxOutputTokens": task["maxOutputTokens"],
            },
            "latencyMs": elapsed_ms,
            "usage": usage,
            "finishReason": finish_reason,
            "capturedAtUtc": attested_captured_at or _utc_z(clock_impl()),
        }
        if runtime_attestation is not None:
            response.update(
                {
                    "runtimeAttestation": runtime_attestation,
                }
            )
        response["responseSha256"] = evaluation_response_sha256(response)
        _validate_response(response, record_count + 1)
        encoded_record = canonical_json_bytes(response) + b"\n"
        if len(output_bytes) + len(encoded_record) > MAX_EVALUATION_BYTES:
            _fail("response output", f"exceeds {MAX_EVALUATION_BYTES} bytes")
        output_bytes.extend(encoded_record)
        record_count += 1

    def validate_final_capture_inputs() -> None:
        if is_base_evaluation:
            final_profile = validate_base_evaluation_profile(
                profile_path=base_evaluation_profile_path,
                snapshot_manifest_path=base_model_snapshot_manifest_path,
                snapshot_path=base_model_snapshot_path,
                catalog_path=catalog_path,
                source_lock_path=base_model_source_lock_path,
            )
            if (
                final_profile.sha256 != serving_profile.sha256
                or final_profile.document != serving_profile.document
            ):
                _fail(
                    "base-model evaluation target",
                    "changed while responses were captured",
                )
        else:
            validate_current_adapter_target()
        if not research_only:
            _, current_release_identity = (
                validate_corpus_evaluation_release_with_identity(
                    data_release_path,
                    review_receipt_trust=review_receipt_trust,
                    evaluation_authoring_approval_trust=(
                        evaluation_authoring_approval_trust
                    ),
                    now=review_receipt_now,
                )
            )
            if current_release_identity != release_identity:
                _fail("evaluation release", "changed while responses were captured")
        if attested_base_endpoint is not None:
            validate_current_base_activation()

    _write_bytes_atomic_no_clobber(
        Path(output_path),
        output_bytes,
        "response output",
        before_install=validate_final_capture_inputs,
    )
    return {
        "schemaVersion": (
            EVALUATION_RESPONSE_V2_SCHEMA_VERSION
            if attested_base_endpoint is not None
            else EVALUATION_RESPONSE_SCHEMA_VERSION
        ),
        "recordCount": record_count,
        "taskSetSha256": tasks.task_set_sha256,
        "candidateCatalogSha256": catalog_hash,
        "servingProfileSha256": serving_profile.sha256,
        "executionModelId": serving_profile.execution_model_id,
        "dataRelease": release_identity,
        "researchOnly": research_only,
        "runtimeAttested": attested_base_endpoint is not None,
        "activationId": (
            base_activation.payload["activationId"]
            if base_activation is not None
            else None
        ),
        "outputSha256": hashlib.sha256(output_bytes).hexdigest(),
        "outputPath": str(Path(output_path)),
    }


def _run_identity_from_response(response: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "responseSchemaVersion": response["schemaVersion"],
        "targetKind": response["targetKind"],
        "executionModelId": response["executionModelId"],
        "candidateCatalogSha256": response["candidateCatalogSha256"],
        "candidateId": response["candidateId"],
        "modelId": response["modelId"],
        "modelRevision": response["modelRevision"],
        "servingProfile": response["servingProfile"],
        "runId": response["runId"],
        "seed": response["generation"]["seed"],
    }


def _record_set_sha256(
    domain: str, records: Iterable[Mapping[str, Any]], hash_field: str
) -> str:
    return _length_prefixed_sha256(
        domain,
        [
            [record["taskId"], record[hash_field]]
            for record in sorted(records, key=lambda row: row["taskId"])
        ],
    )


def evaluation_response_set_sha256(
    responses: Iterable[Mapping[str, Any]],
) -> str:
    return _record_set_sha256(
        "daxalgo-vibe-quant-evaluation-response-set/v1",
        responses,
        "responseSha256",
    )


def verifier_result_set_sha256(results: Iterable[Mapping[str, Any]]) -> str:
    return _record_set_sha256(
        "daxalgo-vibe-quant-verifier-result-set/v1",
        results,
        "resultSha256",
    )


def promotion_evidence_sha256(report: Mapping[str, Any]) -> str:
    payload = dict(report)
    payload["reportSha256"] = "0" * 64
    return _length_prefixed_sha256(
        "daxalgo-vibe-quant-promotion-evidence-report/v1",
        [[canonical_json_bytes(payload).decode("utf-8")]],
    )


def _validate_promotion_response_attestations(
    label: str,
    records: tuple[dict[str, Any], ...],
    task_set: EvaluationTaskSet,
    trust: BaseResponseAttestationTrust | None,
) -> None:
    if any(
        response["schemaVersion"] == EVALUATION_RESPONSE_V2_SCHEMA_VERSION
        for response in records
    ):
        if trust is None:
            _fail(
                label,
                "attested raw-base response v2 requires external activation and runtime signature trust",
            )
        _validate_attested_base_evaluation_response_records(
            records,
            task_set,
            activation_trust=trust.activation_trust,
            runtime_public_key_path=trust.runtime_public_key_path,
        )
    elif trust is not None:
        _fail(label, "attestation trust cannot be supplied for response v1")


def aggregate_promotion_evidence(
    *,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    research_only: bool = False,
) -> dict[str, Any]:
    replay_audit_values = (
        csharp_verifier_replay_audit_path,
        csharp_verifier_replay_audit_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256,
    )
    if any(value is not None for value in replay_audit_values) and not all(
        value is not None for value in replay_audit_values
    ):
        _fail(
            "C# verifier replay audit",
            "path, exact envelope SHA-256, and external trust must be supplied together",
        )
    replay_audit_supplied = all(value is not None for value in replay_audit_values)
    if csharp_verifier_replay_audit_now is not None and not replay_audit_supplied:
        _fail(
            "C# verifier replay-audit validation time",
            "cannot be supplied without the complete signed replay audit",
        )
    calibration = validate_evaluation_tasks(calibration_tasks_path)
    sealed = validate_evaluation_tasks(sealed_tasks_path)
    if any(task["split"] != "calibration" for task in calibration.records):
        _fail("calibration task set", "may contain only calibration tasks")
    if any(task["split"] != "sealed" for task in sealed.records):
        _fail("sealed task set", "may contain only sealed tasks")
    calibration_groups = {task["contaminationGroup"] for task in calibration.records}
    sealed_groups = {task["contaminationGroup"] for task in sealed.records}
    overlap = sorted(calibration_groups & sealed_groups)
    if overlap:
        _fail(
            "sealed task set",
            f"contamination groups overlap calibration: {overlap[:5]}",
        )
    calibration_prompts = {task["promptSha256"] for task in calibration.records}
    if calibration_prompts & {task["promptSha256"] for task in sealed.records}:
        _fail("sealed task set", "prompt content overlaps calibration")
    if {task["taskId"] for task in calibration.records} & {
        task["taskId"] for task in sealed.records
    }:
        _fail("sealed task set", "task IDs overlap calibration")
    policy = validate_promotion_policy(policy_path)
    if policy["calibrationTaskSetSha256"] != calibration.task_set_sha256:
        _fail(
            "promotion policy.calibrationTaskSetSha256",
            "does not match the supplied calibration task set",
        )
    if policy["sealedTaskSetSha256"] != sealed.task_set_sha256:
        _fail(
            "promotion policy.sealedTaskSetSha256",
            "does not match the supplied sealed task set",
        )
    release_identity: dict[str, str] | None = None
    if research_only:
        if data_release_path is not None:
            _fail(
                "evaluation release", "cannot be supplied for research-only aggregation"
            )
        if (
            review_receipt_trust is not None
            or evaluation_authoring_approval_trust is not None
            or review_receipt_now is not None
        ):
            _fail(
                "release authority trust",
                "cannot be supplied for research-only aggregation",
            )
        if (
            candidate_attestation_trust is not None
            or baseline_attestation_trust is not None
        ):
            _fail(
                "response attestation trust",
                "cannot be supplied for research-only aggregation",
            )
        if csharp_verifier_context is not None:
            _fail(
                "C# verifier execution context",
                "cannot be supplied for research-only aggregation",
            )
        if replay_audit_supplied or csharp_verifier_replay_audit_now is not None:
            _fail(
                "C# verifier replay audit",
                "cannot be supplied for research-only aggregation",
            )
        if policy["researchOnly"] is not True or policy["dataRelease"] is not None:
            _fail(
                "promotion policy.dataRelease",
                "must explicitly declare unbound research-only aggregation",
            )
    else:
        if data_release_path is None:
            _fail(
                "evaluation release",
                "a fully validated bound release is required for promotion aggregation",
            )
        if review_receipt_trust is None:
            _fail(
                "review-receipt trust",
                "is required for release-bound promotion aggregation",
            )
        if evaluation_authoring_approval_trust is None:
            _fail(
                "evaluation-authoring approval trust",
                "is required for release-bound promotion aggregation",
            )
        from .release import (
            TRAINING_PURPOSES,
            validate_corpus_evaluation_release_with_identity,
            validate_release_evaluation_task_set,
        )

        release, release_identity = validate_corpus_evaluation_release_with_identity(
            data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            now=review_receipt_now,
        )
        if release["purpose"] not in TRAINING_PURPOSES:
            _fail(
                "release.purpose",
                "must authorize training and evaluation for promotion aggregation",
            )
        validate_release_evaluation_task_set(release, calibration)
        validate_release_evaluation_task_set(release, sealed)
        if (
            policy["researchOnly"] is not False
            or policy["dataRelease"] != release_identity
        ):
            _fail(
                "promotion policy.dataRelease",
                "does not match the fully validated evaluation release",
            )
    calibration_evidence = _read_file_bounded(
        Path(calibration_evidence_path), "calibration evidence", MAX_EVALUATION_BYTES
    )
    if not calibration_evidence:
        _fail("calibration evidence", "must not be empty")
    if (
        hashlib.sha256(calibration_evidence).hexdigest()
        != policy["calibrationEvidenceSha256"]
    ):
        _fail(
            "calibration evidence", "SHA-256 does not match the frozen promotion policy"
        )

    responses = validate_evaluation_responses(responses_path, sealed)
    baseline_responses = validate_evaluation_responses(baseline_responses_path, sealed)
    for label, response_records, attestation_trust in (
        ("candidate responses", responses, candidate_attestation_trust),
        ("baseline responses", baseline_responses, baseline_attestation_trust),
    ):
        _validate_promotion_response_attestations(
            label, response_records, sealed, attestation_trust
        )
    results = validate_verifier_results(verifier_results_path, sealed, responses)
    baseline_results = validate_verifier_results(
        baseline_verifier_results_path, sealed, baseline_responses
    )
    expected_status = "unpromoted-research" if research_only else "release-bound"
    for label, response_records in (
        ("candidate responses", responses),
        ("baseline responses", baseline_responses),
    ):
        for response in response_records:
            if (
                response["dataRelease"] != release_identity
                or response["researchOnly"] is not research_only
                or response["evidenceStatus"] != expected_status
            ):
                _fail(label, "release evidence does not match the aggregation mode")
    expected_ids = {task["taskId"] for task in sealed.records}
    for label, records in (
        ("candidate responses", responses),
        ("candidate verifier results", results),
        ("baseline responses", baseline_responses),
        ("baseline verifier results", baseline_results),
    ):
        ids = {record["taskId"] for record in records}
        if len(records) != len(sealed.records) or ids != expected_ids:
            _fail(label, "must contain exactly one record for every sealed task")
    if not research_only:
        if release is None or release_identity is None or data_release_path is None:
            _fail("evaluation release", "validated release state is unavailable")
        from .verifier_runtime import (
            bind_csharp_verifier_execution_context,
            derive_release_verifier_plan,
            execute_release_declarative_verifiers,
            execute_release_verifiers,
        )

        if csharp_verifier_context is not None and replay_audit_supplied:
            _fail(
                "C# verifier replay authorization",
                "live execution context and signed replay audit are mutually exclusive",
            )

        if csharp_verifier_context is not None:
            csharp_verifier_context = bind_csharp_verifier_execution_context(
                csharp_verifier_context
            )
        if replay_audit_supplied:
            plan = derive_release_verifier_plan(
                release_path=data_release_path,
                release=release,
                tasks=sealed,
            )
            if not plan.uses_csharp:
                _fail(
                    "C# verifier replay audit",
                    "cannot be supplied when the release has no C# verifier task",
                )
            from .verifier_replay_audit import (
                validate_csharp_verifier_replay_audit_for_evidence,
            )

            validate_csharp_verifier_replay_audit_for_evidence(
                csharp_verifier_replay_audit_path,
                trust=csharp_verifier_replay_audit_trust,
                evaluation_authoring_approval_trust=(
                    evaluation_authoring_approval_trust
                ),
                expected_envelope_sha256=(
                    expected_csharp_verifier_replay_audit_envelope_sha256
                ),
                release_identity=release_identity,
                receipt_expires_at_utc=release["corpus"]["reviewReceipts"][
                    "expiresAtUtc"
                ],
                authoring_approval_expires_at_utc=release["evaluation"][
                    "authoringApproval"
                ]["expiresAtUtc"],
                sealed_tasks=sealed,
                plan=plan,
                candidate_responses_path=responses_path,
                candidate_results_path=verifier_results_path,
                candidate_responses=responses,
                candidate_results=results,
                baseline_responses_path=baseline_responses_path,
                baseline_results_path=baseline_verifier_results_path,
                baseline_responses=baseline_responses,
                baseline_results=baseline_results,
                now=csharp_verifier_replay_audit_now,
            )
            csharp_task_ids = {
                task["taskId"]
                for task in plan.document["tasks"]
                if task["profile"] == "daxalgo-sdk-headless-source/v1"
            }
            replayed_results = execute_release_declarative_verifiers(
                release_path=data_release_path,
                release=release,
                release_identity=release_identity,
                tasks=sealed,
                responses=responses,
            )
            replayed_baseline_results = execute_release_declarative_verifiers(
                release_path=data_release_path,
                release=release,
                release_identity=release_identity,
                tasks=sealed,
                responses=baseline_responses,
            )
            supplied_declarative = tuple(
                result for result in results if result["taskId"] not in csharp_task_ids
            )
            supplied_baseline_declarative = tuple(
                result
                for result in baseline_results
                if result["taskId"] not in csharp_task_ids
            )
            if supplied_declarative != replayed_results:
                _fail(
                    "candidate verifier results",
                    "declarative tasks do not match fresh release-verifier execution",
                )
            if supplied_baseline_declarative != replayed_baseline_results:
                _fail(
                    "baseline verifier results",
                    "declarative tasks do not match fresh release-verifier execution",
                )
        else:
            replayed_results = execute_release_verifiers(
                release_path=data_release_path,
                release=release,
                release_identity=release_identity,
                tasks=sealed,
                responses=responses,
                csharp_context=csharp_verifier_context,
            )
            replayed_baseline_results = execute_release_verifiers(
                release_path=data_release_path,
                release=release,
                release_identity=release_identity,
                tasks=sealed,
                responses=baseline_responses,
                csharp_context=csharp_verifier_context,
            )
            if tuple(results) != replayed_results:
                _fail(
                    "candidate verifier results",
                    "do not match fresh execution of the release-bound verifier bytes",
                )
            if tuple(baseline_results) != replayed_baseline_results:
                _fail(
                    "baseline verifier results",
                    "do not match fresh execution of the release-bound verifier bytes",
                )
        current_release, current_identity = (
            validate_corpus_evaluation_release_with_identity(
                data_release_path,
                review_receipt_trust=review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    evaluation_authoring_approval_trust
                ),
                now=review_receipt_now,
            )
        )
        if current_release != release or current_identity != release_identity:
            _fail("evaluation release", "changed during executable verifier replay")
    candidate_identity = _run_identity_from_response(responses[0])
    baseline_identity = _run_identity_from_response(baseline_responses[0])
    if candidate_identity != policy["candidateRun"]:
        _fail(
            "candidate responses",
            "run identity does not match the frozen promotion policy",
        )
    if baseline_identity != policy["baselineRun"]:
        _fail(
            "baseline responses",
            "run identity does not match the frozen promotion policy",
        )
    frozen_at = _parse_datetime(
        policy["frozenAtUtc"], "promotion policy.frozenAtUtc", require_utc_z=True
    )
    for label, response_records in (
        ("candidate", responses),
        ("baseline", baseline_responses),
    ):
        for response in response_records:
            captured_at = _parse_datetime(
                response["capturedAtUtc"],
                f"{label} response {response['taskId']}.capturedAtUtc",
                require_utc_z=True,
            )
            if captured_at < frozen_at:
                _fail(
                    f"{label} response {response['taskId']}.capturedAtUtc",
                    "precedes the frozen policy; timestamp ordering is required",
                )

    candidate_response_by_task = {
        response["taskId"]: response for response in responses
    }
    baseline_response_by_task = {
        response["taskId"]: response for response in baseline_responses
    }
    candidate_result_by_task = {result["taskId"]: result for result in results}
    baseline_result_by_task = {result["taskId"]: result for result in baseline_results}
    candidate_accepted = {
        task_id: candidate_result_by_task[task_id]["accepted"]
        and candidate_response_by_task[task_id]["finishReason"] == "stop"
        for task_id in expected_ids
    }
    baseline_accepted = {
        task_id: baseline_result_by_task[task_id]["accepted"]
        and baseline_response_by_task[task_id]["finishReason"] == "stop"
        for task_id in expected_ids
    }
    candidate_non_stop = sorted(
        task_id
        for task_id, response in candidate_response_by_task.items()
        if response["finishReason"] != "stop"
    )
    baseline_non_stop = sorted(
        task_id
        for task_id, response in baseline_response_by_task.items()
        if response["finishReason"] != "stop"
    )

    per_domain_task_counts = {
        domain: sum(1 for task in sealed.records if domain in task["domains"])
        for domain in DOMAINS
    }
    per_domain_group_counts = {
        domain: len(
            {
                task["contaminationGroup"]
                for task in sealed.records
                if domain in task["domains"]
            }
        )
        for domain in DOMAINS
    }
    critical_count = sum(
        1 for task in sealed.records if task["criticality"] == "critical"
    )
    sufficiency_passed = (
        len(sealed.records) >= policy["minimumTotalTasks"]
        and critical_count >= policy["minimumCriticalTasks"]
        and all(
            per_domain_task_counts[domain]
            >= policy["minimumPerDomainTaskCounts"][domain]
            and per_domain_group_counts[domain]
            >= policy["minimumPerDomainContaminationGroupCounts"][domain]
            for domain in DOMAINS
        )
    )
    suite_sufficiency = {
        "taskCount": len(sealed.records),
        "minimumTotalTasks": policy["minimumTotalTasks"],
        "criticalTaskCount": critical_count,
        "minimumCriticalTasks": policy["minimumCriticalTasks"],
        "perDomainTaskCounts": per_domain_task_counts,
        "minimumPerDomainTaskCounts": policy["minimumPerDomainTaskCounts"],
        "perDomainContaminationGroupCounts": per_domain_group_counts,
        "minimumPerDomainContaminationGroupCounts": policy[
            "minimumPerDomainContaminationGroupCounts"
        ],
        "passed": sufficiency_passed,
    }

    def comparison(
        task_subset: list[Mapping[str, Any]], threshold: float
    ) -> dict[str, Any]:
        task_ids = [task["taskId"] for task in task_subset]
        total = len(task_ids)
        candidate_count = sum(1 for task_id in task_ids if candidate_accepted[task_id])
        baseline_count = sum(1 for task_id in task_ids if baseline_accepted[task_id])
        candidate_rate = candidate_count / total if total else 0.0
        baseline_rate = baseline_count / total if total else 0.0
        return {
            "candidateAcceptedCount": candidate_count,
            "baselineAcceptedCount": baseline_count,
            "taskCount": total,
            "candidateAcceptedRate": candidate_rate,
            "baselineAcceptedRate": baseline_rate,
            "absoluteRateDelta": candidate_rate - baseline_rate,
            "threshold": threshold,
            "thresholdPassed": total > 0 and candidate_rate >= threshold,
            "noRegressionPassed": total > 0 and candidate_rate >= baseline_rate,
        }

    overall = comparison(list(sealed.records), policy["overallAcceptedRateThreshold"])
    domains = {
        domain: comparison(
            [task for task in sealed.records if domain in task["domains"]],
            policy["perDomainAcceptedRateThresholds"][domain],
        )
        for domain in DOMAINS
    }
    critical_failures = sorted(
        task["taskId"]
        for task in sealed.records
        if task["criticality"] == "critical" and not candidate_accepted[task["taskId"]]
    )
    threshold_gate = overall["thresholdPassed"] and all(
        metric["thresholdPassed"] for metric in domains.values()
    )
    regression_gate = overall["noRegressionPassed"] and all(
        metric["noRegressionPassed"] for metric in domains.values()
    )
    finish_gate = not candidate_non_stop and not baseline_non_stop
    gates_passed = (
        sufficiency_passed
        and threshold_gate
        and regression_gate
        and not critical_failures
        and finish_gate
    )

    candidate_response_set_hash = evaluation_response_set_sha256(responses)
    candidate_result_set_hash = verifier_result_set_sha256(results)
    baseline_response_set_hash = evaluation_response_set_sha256(baseline_responses)
    baseline_result_set_hash = verifier_result_set_sha256(baseline_results)
    report: dict[str, Any] = {
        "schemaVersion": PROMOTION_EVIDENCE_SCHEMA_VERSION,
        "reportSha256": "0" * 64,
        "evidenceOnly": True,
        "promotionStatus": "unpromoted",
        "promotionEligible": False,
        "eligibleForPromotionReview": gates_passed and not research_only,
        "dataRelease": release_identity,
        "researchOnly": research_only,
        "evidenceStatus": expected_status,
        "completeCardinality": True,
        "calibrationTaskSetSha256": calibration.task_set_sha256,
        "calibrationEvidenceSha256": policy["calibrationEvidenceSha256"],
        "sealedTaskSetSha256": sealed.task_set_sha256,
        "policySha256": policy["policySha256"],
        "candidate": {
            "identity": candidate_identity,
            "responseSetSha256": candidate_response_set_hash,
            "verifierResultSetSha256": candidate_result_set_hash,
        },
        "baseline": {
            "identity": baseline_identity,
            "responseSetSha256": baseline_response_set_hash,
            "verifierResultSetSha256": baseline_result_set_hash,
        },
        "suiteSufficiency": suite_sufficiency,
        "overall": overall,
        "domains": domains,
        "criticalFailureTaskIds": critical_failures,
        "candidateNonStopTaskIds": candidate_non_stop,
        "baselineNonStopTaskIds": baseline_non_stop,
        "zeroCriticalFailures": not critical_failures,
        "allFinishReasonsStop": finish_gate,
        "allEvidenceGatesPassed": gates_passed,
        "statement": "Evidence only. Passing gates does not promote, sign, publish, or serve a model.",
    }
    report["reportSha256"] = promotion_evidence_sha256(report)
    return report


def _validate_comparison_metric(
    value: Any, field: str, *, allow_zero_tasks: bool = False
) -> dict[str, Any]:
    metric = _exact_keys(
        value,
        {
            "candidateAcceptedCount",
            "baselineAcceptedCount",
            "taskCount",
            "candidateAcceptedRate",
            "baselineAcceptedRate",
            "absoluteRateDelta",
            "threshold",
            "thresholdPassed",
            "noRegressionPassed",
        },
        field,
    )
    total = _integer(
        metric["taskCount"],
        f"{field}.taskCount",
        0 if allow_zero_tasks else 1,
        MAX_EVALUATION_RECORDS,
    )
    candidate_count = _integer(
        metric["candidateAcceptedCount"], f"{field}.candidateAcceptedCount", 0, total
    )
    baseline_count = _integer(
        metric["baselineAcceptedCount"], f"{field}.baselineAcceptedCount", 0, total
    )
    candidate_rate = _number(
        metric["candidateAcceptedRate"], f"{field}.candidateAcceptedRate", 0, 1
    )
    baseline_rate = _number(
        metric["baselineAcceptedRate"], f"{field}.baselineAcceptedRate", 0, 1
    )
    delta = _number(metric["absoluteRateDelta"], f"{field}.absoluteRateDelta", -1, 1)
    threshold = _number(
        metric["threshold"], f"{field}.threshold", 0, 1, minimum_open=True
    )
    expected_candidate_rate = candidate_count / total if total else 0.0
    expected_baseline_rate = baseline_count / total if total else 0.0
    if abs(candidate_rate - expected_candidate_rate) > 1e-15:
        _fail(f"{field}.candidateAcceptedRate", "does not match accepted count")
    if abs(baseline_rate - expected_baseline_rate) > 1e-15:
        _fail(f"{field}.baselineAcceptedRate", "does not match accepted count")
    if abs(delta - (candidate_rate - baseline_rate)) > 1e-15:
        _fail(f"{field}.absoluteRateDelta", "does not match candidate minus baseline")
    if not isinstance(metric["thresholdPassed"], bool) or metric["thresholdPassed"] != (
        total > 0 and candidate_rate >= threshold
    ):
        _fail(f"{field}.thresholdPassed", "does not match the threshold comparison")
    if not isinstance(metric["noRegressionPassed"], bool) or metric[
        "noRegressionPassed"
    ] != (total > 0 and candidate_rate >= baseline_rate):
        _fail(f"{field}.noRegressionPassed", "does not match the baseline comparison")
    return metric


def _validate_report_run(value: Any, field: str) -> dict[str, Any]:
    run = _exact_keys(
        value, {"identity", "responseSetSha256", "verifierResultSetSha256"}, field
    )
    _validate_run_identity(run["identity"], f"{field}.identity")
    _sha256(run["responseSetSha256"], f"{field}.responseSetSha256")
    _sha256(run["verifierResultSetSha256"], f"{field}.verifierResultSetSha256")
    return run


def validate_promotion_evidence(path: str | os.PathLike[str]) -> dict[str, Any]:
    report = _exact_keys(
        load_json_document(path),
        {
            "schemaVersion",
            "reportSha256",
            "evidenceOnly",
            "promotionStatus",
            "promotionEligible",
            "eligibleForPromotionReview",
            "completeCardinality",
            "calibrationTaskSetSha256",
            "calibrationEvidenceSha256",
            "sealedTaskSetSha256",
            "policySha256",
            "candidate",
            "baseline",
            "suiteSufficiency",
            "overall",
            "domains",
            "criticalFailureTaskIds",
            "candidateNonStopTaskIds",
            "baselineNonStopTaskIds",
            "zeroCriticalFailures",
            "allFinishReasonsStop",
            "allEvidenceGatesPassed",
            "statement",
            "dataRelease",
            "researchOnly",
            "evidenceStatus",
        },
        "promotion evidence",
    )
    if report["schemaVersion"] != PROMOTION_EVIDENCE_SCHEMA_VERSION:
        _fail(
            "promotion evidence.schemaVersion",
            f"must be {PROMOTION_EVIDENCE_SCHEMA_VERSION!r}",
        )
    data_release = _validate_data_release_identity(
        report["dataRelease"], "promotion evidence.dataRelease"
    )
    if not isinstance(report["researchOnly"], bool):
        _fail("promotion evidence.researchOnly", "must be a boolean")
    expected_status = (
        "unpromoted-research" if report["researchOnly"] else "release-bound"
    )
    if report["evidenceStatus"] != expected_status:
        _fail("promotion evidence.evidenceStatus", "does not match researchOnly")
    if (data_release is None) is not report["researchOnly"]:
        _fail(
            "promotion evidence.dataRelease",
            "must be null only for explicitly research-only evidence",
        )
    if report["evidenceOnly"] is not True or report["promotionStatus"] != "unpromoted":
        _fail("promotion evidence", "must remain evidence-only and unpromoted")
    if (
        report["promotionEligible"] is not False
        or report["completeCardinality"] is not True
    ):
        _fail("promotion evidence", "must be unpromoted with complete cardinality")
    for name in (
        "calibrationTaskSetSha256",
        "calibrationEvidenceSha256",
        "sealedTaskSetSha256",
        "policySha256",
    ):
        _sha256(report[name], f"promotion evidence.{name}")
    candidate = _validate_report_run(
        report["candidate"], "promotion evidence.candidate"
    )
    baseline = _validate_report_run(report["baseline"], "promotion evidence.baseline")
    if (
        candidate["identity"]["candidateCatalogSha256"]
        != baseline["identity"]["candidateCatalogSha256"]
    ):
        _fail(
            "promotion evidence.baseline.identity.candidateCatalogSha256",
            "must match the candidate catalog",
        )
    if candidate["identity"]["runId"] == baseline["identity"]["runId"]:
        _fail(
            "promotion evidence.baseline.identity.runId",
            "must differ from the candidate run ID",
        )
    if candidate["identity"]["seed"] != baseline["identity"]["seed"]:
        _fail(
            "promotion evidence.baseline.identity.seed", "must match the candidate seed"
        )
    if _run_artifact_identity(candidate["identity"]) == _run_artifact_identity(
        baseline["identity"]
    ):
        _fail(
            "promotion evidence.baseline.identity",
            "must identify a distinct model or serving artifact",
        )
    sufficiency = _exact_keys(
        report["suiteSufficiency"],
        {
            "taskCount",
            "minimumTotalTasks",
            "criticalTaskCount",
            "minimumCriticalTasks",
            "perDomainTaskCounts",
            "minimumPerDomainTaskCounts",
            "perDomainContaminationGroupCounts",
            "minimumPerDomainContaminationGroupCounts",
            "passed",
        },
        "promotion evidence.suiteSufficiency",
    )
    task_count = _integer(
        sufficiency["taskCount"],
        "promotion evidence.suiteSufficiency.taskCount",
        1,
        MAX_EVALUATION_RECORDS,
    )
    minimum_total = _integer(
        sufficiency["minimumTotalTasks"],
        "promotion evidence.suiteSufficiency.minimumTotalTasks",
        1,
        MAX_EVALUATION_RECORDS,
    )
    critical_count = _integer(
        sufficiency["criticalTaskCount"],
        "promotion evidence.suiteSufficiency.criticalTaskCount",
        0,
        task_count,
    )
    minimum_critical = _integer(
        sufficiency["minimumCriticalTasks"],
        "promotion evidence.suiteSufficiency.minimumCriticalTasks",
        1,
        MAX_EVALUATION_RECORDS,
    )
    domain_counts = _validate_domain_minimums(
        sufficiency["perDomainTaskCounts"],
        "promotion evidence.suiteSufficiency.perDomainTaskCounts",
        minimum=0,
    )
    minimum_domain_counts = _validate_domain_minimums(
        sufficiency["minimumPerDomainTaskCounts"],
        "promotion evidence.suiteSufficiency.minimumPerDomainTaskCounts",
    )
    group_counts = _validate_domain_minimums(
        sufficiency["perDomainContaminationGroupCounts"],
        "promotion evidence.suiteSufficiency.perDomainContaminationGroupCounts",
        minimum=0,
    )
    minimum_group_counts = _validate_domain_minimums(
        sufficiency["minimumPerDomainContaminationGroupCounts"],
        "promotion evidence.suiteSufficiency.minimumPerDomainContaminationGroupCounts",
    )
    for domain in DOMAINS:
        if domain_counts[domain] > task_count:
            _fail(
                f"promotion evidence.suiteSufficiency.perDomainTaskCounts.{domain}",
                "exceeds taskCount",
            )
        if group_counts[domain] > domain_counts[domain]:
            _fail(
                f"promotion evidence.suiteSufficiency.perDomainContaminationGroupCounts.{domain}",
                "exceeds the domain task count",
            )
    expected_sufficiency = (
        task_count >= minimum_total
        and critical_count >= minimum_critical
        and all(
            domain_counts[domain] >= minimum_domain_counts[domain]
            and group_counts[domain] >= minimum_group_counts[domain]
            for domain in DOMAINS
        )
    )
    if sufficiency["passed"] is not expected_sufficiency:
        _fail(
            "promotion evidence.suiteSufficiency.passed", "does not match suite counts"
        )
    overall = _validate_comparison_metric(
        report["overall"], "promotion evidence.overall"
    )
    if overall["taskCount"] != task_count:
        _fail("promotion evidence.overall.taskCount", "does not match suite taskCount")
    domains = _exact_keys(report["domains"], set(DOMAINS), "promotion evidence.domains")
    for domain in DOMAINS:
        metric = _validate_comparison_metric(
            domains[domain],
            f"promotion evidence.domains.{domain}",
            allow_zero_tasks=True,
        )
        if metric["taskCount"] != domain_counts[domain]:
            _fail(
                f"promotion evidence.domains.{domain}.taskCount",
                "does not match suite domain count",
            )
    lists: dict[str, list[str]] = {}
    for name in (
        "criticalFailureTaskIds",
        "candidateNonStopTaskIds",
        "baselineNonStopTaskIds",
    ):
        value = report[name]
        if not isinstance(value, list) or len(value) != len(set(value)):
            _fail(f"promotion evidence.{name}", "must be an array without duplicates")
        for index, item in enumerate(value):
            _validate_identifier(item, f"promotion evidence.{name}[{index}]")
        lists[name] = value
    if len(lists["criticalFailureTaskIds"]) > critical_count:
        _fail("promotion evidence.criticalFailureTaskIds", "exceeds criticalTaskCount")
    if (
        len(lists["candidateNonStopTaskIds"]) > task_count
        or len(lists["baselineNonStopTaskIds"]) > task_count
    ):
        _fail("promotion evidence", "non-stop task IDs exceed taskCount")
    if report["zeroCriticalFailures"] is not (not lists["criticalFailureTaskIds"]):
        _fail(
            "promotion evidence.zeroCriticalFailures",
            "does not match critical failures",
        )
    finish_gate = (
        not lists["candidateNonStopTaskIds"] and not lists["baselineNonStopTaskIds"]
    )
    if report["allFinishReasonsStop"] is not finish_gate:
        _fail(
            "promotion evidence.allFinishReasonsStop",
            "does not match non-stop task lists",
        )
    evidence_gate = (
        expected_sufficiency
        and overall["thresholdPassed"]
        and overall["noRegressionPassed"]
        and all(
            metric["thresholdPassed"] and metric["noRegressionPassed"]
            for metric in domains.values()
        )
        and not lists["criticalFailureTaskIds"]
        and finish_gate
    )
    if report["allEvidenceGatesPassed"] is not evidence_gate:
        _fail(
            "promotion evidence.allEvidenceGatesPassed", "does not match evidence gates"
        )
    expected_review_eligibility = evidence_gate and not report["researchOnly"]
    if report["eligibleForPromotionReview"] is not expected_review_eligibility:
        _fail(
            "promotion evidence.eligibleForPromotionReview",
            "does not match evidence gates and research status",
        )
    _string(report["statement"], "promotion evidence.statement", max_length=1_000)
    if _sha256(
        report["reportSha256"], "promotion evidence.reportSha256"
    ) != promotion_evidence_sha256(report):
        _fail("promotion evidence.reportSha256", "does not match the canonical report")
    return report


def write_json_atomic_no_clobber(
    path: str | os.PathLike[str], value: Mapping[str, Any]
) -> None:
    _write_bytes_atomic_no_clobber(
        Path(path), canonical_json_bytes(value) + b"\n", "report output"
    )
