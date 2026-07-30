from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import unicodedata
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .core import (
    ValidationError,
    _exact_keys,
    _exclusive_destination_lock,
    _fail,
    _integer,
    _pinned_revision_label,
    _read_file_bounded,
    _reject_reparse_components,
    _sha256,
    _string,
    canonical_json_bytes,
    load_json_document,
    resolve_bound_path,
)
from .evaluation import (
    CRITICALITIES,
    EVALUATION_TASK_SCHEMA_VERSION,
    MAX_EVALUATION_BYTES,
    MAX_OUTPUT_TOKENS,
    MAX_REQUIRED_CHECKS,
    _validate_identifier,
    evaluation_prompt_sha256,
    evaluation_task_sha256,
    validate_evaluation_tasks,
)
from .evaluation_authoring import derive_evaluation_authoring_inventory
from .release import (
    MAX_CORPUS_BYTES,
    MAX_RELEASE_MANIFEST_BYTES,
    MAX_REVIEW_ASSET_BYTES,
    TASK_BINDINGS_V2_SCHEMA_VERSION,
    _load_task_binding_input,
    _parse_expert_corpus,
)
from .teacher_materialization import (
    _install_materialization_no_clobber as _install_handoff_no_clobber,
)
from .verifier_authority import _bounded_snapshot


EVALUATION_AUTHORING_MANIFEST_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.evaluation-authoring-manifest/v1"
)
EVALUATION_AUTHORING_HANDOFF_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.evaluation-authoring-handoff/v1"
)
EVALUATION_AUTHORING_HANDOFF_ID_PREFIX = "daxalgo-evaluation-authoring-handoff-sha256-"
EVALUATION_AUTHORING_HANDOFF_STATUS = "unsigned-non-authorizing"
EVALUATION_AUTHORING_HANDOFF_PURPOSE = "evaluation-authoring-review-handoff"
EVALUATION_AUTHORING_HANDOFF_STATEMENT = (
    "This unsigned handoff binds reviewed corpus declarations, derived evaluation "
    "tasks, and exact review assets only. It does not attest independent authorship "
    "or sealed custody and grants no review, signing, evaluation, release, training, "
    "promotion, deployment, hosted serving, installation, verifier execution, or "
    "strategy execution authority."
)

HANDOFF_FILE_NAME = "evaluation-authoring-handoff.json"
AUTHORING_MANIFEST_PATH = "inputs/authoring-manifest.json"
CALIBRATION_TASKS_PATH = "evaluation/calibration.tasks.jsonl"
SEALED_TASKS_PATH = "evaluation/sealed.tasks.jsonl"
TASK_BINDINGS_PATH = "evaluation/task-bindings.json"

MAX_AUTHORING_MANIFEST_BYTES = 5_000_000
MAX_HANDOFF_BYTES = 5_000_000
MAX_AUTHORING_TASKS = 10_000
MAX_REFERENCE_ANSWER_CHARACTERS = 250_000
MAX_EVALUATION_USER_TURN_CHARACTERS = 250_000
_ZERO_SHA256 = "0" * 64
_NO_AUTHORITY = {
    "signingKeyAuthority": False,
    "corpusReviewAuthority": False,
    "evaluationAuthoringApprovalAuthority": False,
    "evaluationExecutionAuthority": False,
    "trainingEligibilityAuthority": False,
    "providerUploadAuthority": False,
    "releaseAuthority": False,
    "baseSelectionAuthority": False,
    "promotionAuthority": False,
    "deploymentAuthority": False,
    "hostedServingAuthority": False,
    "installationAuthority": False,
    "verifierExecutionAuthority": False,
    "strategyExecutionAuthority": False,
}
_DECLARATIONS = {
    "finalAssistantReferenceMessageOmitted": True,
    "expectedAnswerFieldsEmittedInTaskRecords": False,
    "independentAuthorshipAttested": False,
    "sealedCustodyAttested": False,
    "signedAuthoringApprovalRequired": True,
}
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class _AnswerMatcher:
    def __init__(self, patterns: Mapping[str, str]) -> None:
        self._transitions: list[dict[str, int]] = [{}]
        self._failure = [0]
        self._terminal: list[str | None] = [None]
        self._output_link = [0]
        for pattern, owner in patterns.items():
            state = 0
            for character in pattern:
                next_state = self._transitions[state].get(character)
                if next_state is None:
                    next_state = len(self._transitions)
                    self._transitions[state][character] = next_state
                    self._transitions.append({})
                    self._failure.append(0)
                    self._terminal.append(None)
                    self._output_link.append(0)
                state = next_state
            self._terminal[state] = owner

        queue: deque[int] = deque(self._transitions[0].values())
        while queue:
            state = queue.popleft()
            for character, child in self._transitions[state].items():
                queue.append(child)
                failure = self._failure[state]
                while failure and character not in self._transitions[failure]:
                    failure = self._failure[failure]
                self._failure[child] = self._transitions[failure].get(character, 0)
                failed = self._failure[child]
                self._output_link[child] = (
                    failed
                    if self._terminal[failed] is not None
                    else self._output_link[failed]
                )

    def find(
        self,
        text: str,
        *,
        ignore_owner: str | None = None,
        ignore_owners: frozenset[str] = frozenset(),
    ) -> str | None:
        state = 0
        for character in text:
            while state and character not in self._transitions[state]:
                state = self._failure[state]
            state = self._transitions[state].get(character, 0)
            output = state
            while output:
                owner = self._terminal[output]
                if (
                    owner is not None
                    and owner != ignore_owner
                    and owner not in ignore_owners
                ):
                    return owner
                output = self._output_link[output]
        return None


@dataclass(frozen=True)
class VerifiedEvaluationAuthoringHandoff:
    path: Path
    document: dict[str, Any]
    inventory: dict[str, Any]

    @property
    def handoff_id(self) -> str:
        return self.document["handoffId"]

    def as_dict(self) -> dict[str, Any]:
        return {
            "handoffId": self.handoff_id,
            "status": self.document["status"],
            "sourceDatasetSha256": self.document["sourceDataset"]["sha256"],
            "calibrationTaskSetSha256": self.document["calibrationTasks"][
                "taskSetSha256"
            ],
            "sealedTaskSetSha256": self.document["sealedTasks"]["taskSetSha256"],
            "taskBindingCount": self.document["taskBindings"]["recordCount"],
            "assetCount": len(self.document["assets"]),
        }


@dataclass(frozen=True)
class _AuthoringTask:
    task_id: str
    source_example_id: str
    context_version: str
    context_path: Path
    context_raw: bytes
    rubric_id: str
    rubric_path: Path
    rubric_raw: bytes
    verifier_id: str
    verifier_path: Path
    verifier_raw: bytes
    required_checks: list[str]
    criticality: str
    max_output_tokens: int


def _relative_package_path(value: Any, field: str) -> str:
    text = _string(value, field, max_length=500)
    pure = Path(text)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or "\\" in text
        or any(not _SAFE_PATH_SEGMENT.fullmatch(part) for part in pure.parts)
    ):
        _fail(field, "must be a contained forward-slash relative path")
    normalized = "/".join(pure.parts)
    if normalized != text:
        _fail(field, "must use canonical forward-slash relative form")
    return normalized


def _file_binding(
    path: Path,
    relative: str,
    *,
    record_count: int | None = None,
    task_set_sha256: str | None = None,
) -> dict[str, Any]:
    raw = path.read_bytes()
    binding: dict[str, Any] = {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
    }
    if record_count is not None:
        binding["recordCount"] = record_count
    if task_set_sha256 is not None:
        binding["taskSetSha256"] = task_set_sha256
    return binding


def _source_binding(corpus: Any, raw: bytes) -> dict[str, Any]:
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
        "recordCount": len(corpus.records),
    }


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


def _load_asset(
    root: Path,
    value: Any,
    field: str,
    *,
    expected_keys: set[str],
) -> tuple[dict[str, Any], Path, bytes]:
    asset = _exact_keys(value, expected_keys, field)
    path = resolve_bound_path(root, asset["path"], f"{field}.path")
    raw = _read_file_bounded(path, field, MAX_REVIEW_ASSET_BYTES)
    if not raw:
        _fail(field, "must not be empty")
    expected_sha256 = _sha256(asset["sha256"], f"{field}.sha256")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        _fail(f"{field}.sha256", "does not match the exact asset bytes")
    return asset, path, raw


def _parse_authoring_task(value: Any, index: int, root: Path) -> _AuthoringTask:
    field = f"evaluation-authoring manifest.tasks[{index}]"
    task = _exact_keys(
        value,
        {
            "taskId",
            "sourceExampleId",
            "contextPack",
            "rubric",
            "verifier",
            "criticality",
            "maxOutputTokens",
        },
        field,
    )
    task_id = _validate_identifier(task["taskId"], f"{field}.taskId")
    source_example_id = _validate_identifier(
        task["sourceExampleId"], f"{field}.sourceExampleId"
    )
    context, context_path, context_raw = _load_asset(
        root,
        task["contextPack"],
        f"{field}.contextPack",
        expected_keys={"version", "path", "sha256"},
    )
    rubric, rubric_path, rubric_raw = _load_asset(
        root,
        task["rubric"],
        f"{field}.rubric",
        expected_keys={"id", "path", "sha256"},
    )
    verifier, verifier_path, verifier_raw = _load_asset(
        root,
        task["verifier"],
        f"{field}.verifier",
        expected_keys={"id", "path", "sha256", "requiredChecks"},
    )
    criticality = task["criticality"]
    if not isinstance(criticality, str) or criticality not in CRITICALITIES:
        _fail(f"{field}.criticality", "must be standard or critical")
    return _AuthoringTask(
        task_id=task_id,
        source_example_id=source_example_id,
        context_version=_pinned_revision_label(
            context["version"], f"{field}.contextPack.version"
        ),
        context_path=context_path,
        context_raw=context_raw,
        rubric_id=_validate_identifier(rubric["id"], f"{field}.rubric.id"),
        rubric_path=rubric_path,
        rubric_raw=rubric_raw,
        verifier_id=_validate_identifier(verifier["id"], f"{field}.verifier.id"),
        verifier_path=verifier_path,
        verifier_raw=verifier_raw,
        required_checks=_required_checks(
            verifier["requiredChecks"], f"{field}.verifier.requiredChecks"
        ),
        criticality=criticality,
        max_output_tokens=_integer(
            task["maxOutputTokens"],
            f"{field}.maxOutputTokens",
            1,
            MAX_OUTPUT_TOKENS,
        ),
    )


def _parse_authoring_manifest(
    value: Any,
    *,
    root: Path,
    resolve_assets: bool,
) -> tuple[dict[str, Any], list[_AuthoringTask] | None]:
    manifest = _exact_keys(
        value,
        {"schemaVersion", "sourceDatasetSha256", "tasks"},
        "evaluation-authoring manifest",
    )
    if manifest["schemaVersion"] != EVALUATION_AUTHORING_MANIFEST_SCHEMA_VERSION:
        _fail(
            "evaluation-authoring manifest.schemaVersion",
            f"must be {EVALUATION_AUTHORING_MANIFEST_SCHEMA_VERSION!r}",
        )
    _sha256(
        manifest["sourceDatasetSha256"],
        "evaluation-authoring manifest.sourceDatasetSha256",
    )
    tasks = manifest["tasks"]
    if not isinstance(tasks, list) or not 2 <= len(tasks) <= MAX_AUTHORING_TASKS:
        _fail(
            "evaluation-authoring manifest.tasks",
            f"must contain 2 to {MAX_AUTHORING_TASKS} tasks",
        )
    if not resolve_assets:
        task_ids: set[str] = set()
        source_ids: set[str] = set()
        for index, task_value in enumerate(tasks):
            field = f"evaluation-authoring manifest.tasks[{index}]"
            task = _exact_keys(
                task_value,
                {
                    "taskId",
                    "sourceExampleId",
                    "contextPack",
                    "rubric",
                    "verifier",
                    "criticality",
                    "maxOutputTokens",
                },
                field,
            )
            task_id = _validate_identifier(task["taskId"], f"{field}.taskId")
            source_id = _validate_identifier(
                task["sourceExampleId"], f"{field}.sourceExampleId"
            )
            if task_id in task_ids:
                _fail(f"{field}.taskId", "duplicates an earlier task")
            if source_id in source_ids:
                _fail(f"{field}.sourceExampleId", "duplicates an earlier source")
            task_ids.add(task_id)
            source_ids.add(source_id)
            for kind, keys in (
                ("contextPack", {"version", "path", "sha256"}),
                ("rubric", {"id", "path", "sha256"}),
                ("verifier", {"id", "path", "sha256", "requiredChecks"}),
            ):
                asset = _exact_keys(task[kind], keys, f"{field}.{kind}")
                _relative_package_path(asset["path"], f"{field}.{kind}.path")
                _sha256(asset["sha256"], f"{field}.{kind}.sha256")
            _pinned_revision_label(
                task["contextPack"]["version"], f"{field}.contextPack.version"
            )
            _validate_identifier(task["rubric"]["id"], f"{field}.rubric.id")
            _validate_identifier(task["verifier"]["id"], f"{field}.verifier.id")
            _required_checks(
                task["verifier"]["requiredChecks"],
                f"{field}.verifier.requiredChecks",
            )
            if task["criticality"] not in CRITICALITIES:
                _fail(f"{field}.criticality", "must be standard or critical")
            _integer(
                task["maxOutputTokens"],
                f"{field}.maxOutputTokens",
                1,
                MAX_OUTPUT_TOKENS,
            )
        return manifest, None
    parsed = [
        _parse_authoring_task(task, index, root) for index, task in enumerate(tasks)
    ]
    if len({task.task_id for task in parsed}) != len(parsed):
        _fail("evaluation-authoring manifest.tasks", "contains duplicate task IDs")
    if len({task.source_example_id for task in parsed}) != len(parsed):
        _fail(
            "evaluation-authoring manifest.tasks",
            "must map each source example at most once",
        )
    return manifest, parsed


def _normalized_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _normalized_user_turn_fingerprints(
    messages: Iterable[Mapping[str, str]],
) -> list[str]:
    return [
        hashlib.sha256(_normalized_text(message["content"]).encode("utf-8")).hexdigest()
        for message in messages
        if message["role"] == "user"
    ]


def _require_evaluation_only_row(record: Any, example_id: str) -> dict[str, Any]:
    document = record.document
    if document["split"] not in {"calibration", "sealed"}:
        _fail(
            f"evaluation-authoring source {example_id!r}",
            "must be calibration or sealed",
        )
    if document["lineage"]["origin"] != "HumanAuthored":
        _fail(
            f"evaluation-authoring source {example_id!r}.lineage.origin",
            "must declare HumanAuthored evaluation material",
        )
    rights = document["rights"]
    if (
        document["useForTraining"]
        or rights["mayTrain"]
        or rights["mayUploadToProvider"]
        or rights["mayRedistribute"]
    ):
        _fail(
            f"evaluation-authoring source {example_id!r}.rights",
            "must remain storage/evaluation-only and non-training",
        )
    for index, source in enumerate(document["sources"]):
        source_rights = source["rights"]
        if (
            source_rights["mayTrain"]
            or source_rights["mayUploadToProvider"]
            or source_rights["mayRedistribute"]
        ):
            _fail(
                f"evaluation-authoring source {example_id!r}.sources[{index}].rights",
                "must remain storage/evaluation-only and non-training",
            )
    if document["messages"][-1]["role"] != "assistant":
        _fail(
            f"evaluation-authoring source {example_id!r}.messages",
            "must end with one reference assistant answer",
        )
    return document


def _compile_task(
    authoring: _AuthoringTask, source: Mapping[str, Any]
) -> dict[str, Any]:
    messages = source["messages"][:-1]
    task = {
        "schemaVersion": EVALUATION_TASK_SCHEMA_VERSION,
        "taskId": authoring.task_id,
        "taskSha256": _ZERO_SHA256,
        "split": source["split"],
        "taskKind": source["taskKind"],
        "domains": source["domains"],
        "messages": messages,
        "promptSha256": evaluation_prompt_sha256(messages),
        "contextPack": {
            "version": authoring.context_version,
            "sha256": hashlib.sha256(authoring.context_raw).hexdigest(),
        },
        "verifier": {
            "id": authoring.verifier_id,
            "sha256": hashlib.sha256(authoring.verifier_raw).hexdigest(),
            "requiredChecks": authoring.required_checks,
        },
        "contaminationGroup": source["contaminationGroup"],
        "cutoffUtc": source["cutoffUtc"],
        "criticality": authoring.criticality,
        "maxOutputTokens": authoring.max_output_tokens,
    }
    task["taskSha256"] = evaluation_task_sha256(task)
    return task


def _asset_package_path(kind: str, raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return f"evaluation/{kind}/{digest}.bin"


def _task_binding(authoring: _AuthoringTask) -> dict[str, Any]:
    return {
        "taskId": authoring.task_id,
        "sourceExampleIds": [authoring.source_example_id],
        "contextPack": {
            "version": authoring.context_version,
            "path": _asset_package_path(
                "context-packs", authoring.context_raw
            ).removeprefix("evaluation/"),
        },
        "rubric": {
            "id": authoring.rubric_id,
            "path": _asset_package_path("rubrics", authoring.rubric_raw).removeprefix(
                "evaluation/"
            ),
        },
        "verifier": {
            "id": authoring.verifier_id,
            "path": _asset_package_path(
                "verifiers", authoring.verifier_raw
            ).removeprefix("evaluation/"),
        },
    }


def _evaluation_rows(corpus: Any) -> dict[str, Any]:
    return {
        example_id: record
        for example_id, record in corpus.records.items()
        if record.document["split"] in {"calibration", "sealed"}
    }


def _validate_manifest_against_package(
    manifest: Mapping[str, Any],
    *,
    corpus: Any,
    tasks: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
) -> None:
    task_map = {task["taskId"]: task for task in tasks}
    binding_map = {binding["taskId"]: binding for binding in bindings}
    manifest_tasks = {task["taskId"]: task for task in manifest["tasks"]}
    if set(manifest_tasks) != set(task_map) or set(manifest_tasks) != set(binding_map):
        _fail(
            "evaluation-authoring handoff authoring manifest",
            "does not cover the exact packaged task and binding inventory",
        )
    evaluation_rows = _evaluation_rows(corpus)
    if {task["sourceExampleId"] for task in manifest_tasks.values()} != set(
        evaluation_rows
    ):
        _fail(
            "evaluation-authoring handoff authoring manifest",
            "does not map every calibration and sealed source row exactly once",
        )

    for task_id, manifest_task in manifest_tasks.items():
        source_id = manifest_task["sourceExampleId"]
        source = _require_evaluation_only_row(evaluation_rows[source_id], source_id)
        binding = binding_map[task_id]
        if binding["sourceExampleIds"] != [source_id]:
            _fail(
                f"evaluation-authoring handoff binding {task_id!r}",
                "must bind exactly its one declared source example",
            )
        if (
            binding["contextPack"]["version"] != manifest_task["contextPack"]["version"]
            or binding["rubric"]["id"] != manifest_task["rubric"]["id"]
            or binding["verifier"]["id"] != manifest_task["verifier"]["id"]
        ):
            _fail(
                f"evaluation-authoring handoff binding {task_id!r}",
                "does not match the authoring manifest asset identities",
            )

        asset_values: dict[str, tuple[Path, bytes]] = {}
        for kind in ("contextPack", "rubric", "verifier"):
            path = Path(binding[kind]["path"])
            raw = _read_file_bounded(
                path,
                f"evaluation-authoring handoff binding {task_id!r}.{kind}",
                MAX_REVIEW_ASSET_BYTES,
            )
            if not raw:
                _fail(
                    f"evaluation-authoring handoff binding {task_id!r}.{kind}",
                    "must not be empty",
                )
            if hashlib.sha256(raw).hexdigest() != manifest_task[kind]["sha256"]:
                _fail(
                    f"evaluation-authoring handoff binding {task_id!r}.{kind}",
                    "does not match the authoring manifest asset SHA-256",
                )
            asset_values[kind] = (path, raw)

        authoring = _AuthoringTask(
            task_id=task_id,
            source_example_id=source_id,
            context_version=manifest_task["contextPack"]["version"],
            context_path=asset_values["contextPack"][0],
            context_raw=asset_values["contextPack"][1],
            rubric_id=manifest_task["rubric"]["id"],
            rubric_path=asset_values["rubric"][0],
            rubric_raw=asset_values["rubric"][1],
            verifier_id=manifest_task["verifier"]["id"],
            verifier_path=asset_values["verifier"][0],
            verifier_raw=asset_values["verifier"][1],
            required_checks=manifest_task["verifier"]["requiredChecks"],
            criticality=manifest_task["criticality"],
            max_output_tokens=manifest_task["maxOutputTokens"],
        )
        if _compile_task(authoring, source) != task_map[task_id]:
            _fail(
                f"evaluation-authoring handoff task {task_id!r}",
                "is not the exact answer-free task derived from the authoring manifest "
                "and reviewed source row",
            )
    _require_contamination_separation(corpus, tasks)


def _require_contamination_separation(corpus: Any, tasks: list[dict[str, Any]]) -> None:
    evaluation_ids = {
        example_id
        for example_id, record in corpus.records.items()
        if record.document["split"] in {"calibration", "sealed"}
    }
    evaluation_answers: dict[str, str] = {}
    answer_character_count = 0
    for example_id in sorted(evaluation_ids):
        answer = _normalized_text(
            corpus.records[example_id].document["messages"][-1]["content"]
        )
        if not answer:
            _fail(
                "evaluation-authoring contamination",
                f"reference answer for {example_id!r} is empty after normalization",
            )
        answer_character_count += len(answer)
        if answer_character_count > MAX_REFERENCE_ANSWER_CHARACTERS:
            _fail(
                "evaluation-authoring contamination",
                "normalized reference answers exceed the bounded matching budget",
            )
        prior = evaluation_answers.get(answer)
        if prior is not None:
            _fail(
                "evaluation-authoring contamination",
                f"normalized reference answer overlap between {prior!r} and "
                f"{example_id!r}",
            )
        evaluation_answers[answer] = example_id
    answer_matcher = _AnswerMatcher(evaluation_answers)
    for answer, owner in evaluation_answers.items():
        overlap = answer_matcher.find(answer, ignore_owner=owner)
        if overlap is not None:
            _fail(
                "evaluation-authoring contamination",
                f"normalized reference answer overlap between {overlap!r} and "
                f"{owner!r}",
            )
    for example_id, record in corpus.records.items():
        messages = record.document["messages"]
        for index, message in enumerate(messages):
            normalized = _normalized_text(message["content"])
            ignore_owner = (
                example_id
                if example_id in evaluation_ids and index == len(messages) - 1
                else None
            )
            owner = answer_matcher.find(normalized, ignore_owner=ignore_owner)
            if owner is not None:
                _fail(
                    "evaluation-authoring contamination",
                    f"reference answer for {owner!r} appears in a corpus prompt "
                    "or another corpus answer",
                )
        emitted_prompt = " ".join(
            _normalized_text(message["content"]) for message in messages[:-1]
        )
        prompt_answer_owner = answer_matcher.find(emitted_prompt)
        if prompt_answer_owner is not None:
            _fail(
                "evaluation-authoring contamination",
                f"reference answer for {prompt_answer_owner!r} appears across the "
                "emitted corpus prompt",
            )
        full_record = " ".join(
            _normalized_text(message["content"]) for message in messages
        )
        full_record_answer_owner = answer_matcher.find(
            full_record,
            ignore_owner=example_id if example_id in evaluation_ids else None,
        )
        if full_record_answer_owner is not None:
            _fail(
                "evaluation-authoring contamination",
                f"reference answer for {full_record_answer_owner!r} appears across "
                "corpus message boundaries",
            )

    prompt_owners: dict[str, tuple[str, str]] = {}
    user_owners: dict[str, tuple[str, str]] = {}
    for example_id, record in corpus.records.items():
        document = record.document
        messages = document["messages"][:-1]
        prompt = evaluation_prompt_sha256(messages)
        comparisons = [("prompt", prompt, prompt_owners)]
        comparisons.extend(
            ("normalized user turn", digest, user_owners)
            for digest in _normalized_user_turn_fingerprints(messages)
        )
        for label, digest, owners in comparisons:
            prior = owners.get(digest)
            if prior is not None and (
                example_id in evaluation_ids or prior[0] in evaluation_ids
            ):
                _fail(
                    "evaluation-authoring contamination",
                    f"{label} overlap between {prior[0]!r} ({prior[1]}) and "
                    f"{example_id!r} ({document['split']})",
                )
            owners[digest] = (example_id, document["split"])
    _require_evaluation_user_turn_separation(corpus, evaluation_ids)
    if len({task["promptSha256"] for task in tasks}) != len(tasks):
        _fail("evaluation-authoring tasks", "contain overlapping prompts")
    if len({task["contaminationGroup"] for task in tasks}) != len(tasks):
        _fail("evaluation-authoring tasks", "contain overlapping contamination groups")


def _require_evaluation_user_turn_separation(
    corpus: Any, evaluation_ids: set[str]
) -> None:
    patterns: dict[str, str] = {}
    owners: dict[str, tuple[str, int]] = {}
    origins: dict[tuple[str, int], str] = {}
    origin_tokens_by_example: dict[str, set[str]] = {}
    character_count = 0
    for example_id in sorted(evaluation_ids):
        messages = corpus.records[example_id].document["messages"][:-1]
        for index, message in enumerate(messages):
            if message["role"] != "user":
                continue
            normalized = _normalized_text(message["content"])
            if not normalized:
                _fail(
                    "evaluation-authoring contamination",
                    f"user turn for {example_id!r} is empty after normalization",
                )
            character_count += len(normalized)
            if character_count > MAX_EVALUATION_USER_TURN_CHARACTERS:
                _fail(
                    "evaluation-authoring contamination",
                    "normalized evaluation user turns exceed the bounded matching budget",
                )
            prior = patterns.get(normalized)
            if prior is not None:
                prior_example, _ = owners[prior]
                _fail(
                    "evaluation-authoring contamination",
                    f"normalized user turn overlap between {prior_example!r} and "
                    f"{example_id!r}",
                )
            token = str(len(owners))
            patterns[normalized] = token
            owners[token] = (example_id, index)
            origins[(example_id, index)] = token
            origin_tokens_by_example.setdefault(example_id, set()).add(token)

    matcher = _AnswerMatcher(patterns)
    for pattern, token in patterns.items():
        overlap = matcher.find(pattern, ignore_owner=token)
        if overlap is not None:
            prior_example, _ = owners[overlap]
            example_id, _ = owners[token]
            _fail(
                "evaluation-authoring contamination",
                f"normalized user turn overlap between {prior_example!r} and "
                f"{example_id!r}",
            )

    for example_id, record in corpus.records.items():
        messages = record.document["messages"]
        for index, message in enumerate(messages):
            token = origins.get((example_id, index))
            overlap = matcher.find(
                _normalized_text(message["content"]), ignore_owner=token
            )
            if overlap is not None:
                owner, _ = owners[overlap]
                _fail(
                    "evaluation-authoring contamination",
                    f"evaluation user turn for {owner!r} appears in another corpus "
                    "message",
                )
        aggregate = " ".join(
            _normalized_text(message["content"]) for message in messages
        )
        record_origins = frozenset(origin_tokens_by_example.get(example_id, ()))
        overlap = matcher.find(aggregate, ignore_owners=record_origins)
        if overlap is not None:
            owner, _ = owners[overlap]
            _fail(
                "evaluation-authoring contamination",
                f"evaluation user turn for {owner!r} appears across other corpus "
                "messages",
            )


def _write_jsonl(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"".join(canonical_json_bytes(record) + b"\n" for record in records)
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def evaluation_authoring_handoff_id(value: Mapping[str, Any]) -> str:
    unsigned = dict(value)
    unsigned["handoffId"] = EVALUATION_AUTHORING_HANDOFF_ID_PREFIX + _ZERO_SHA256
    return (
        EVALUATION_AUTHORING_HANDOFF_ID_PREFIX
        + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    )


def _validate_source_binding(value: Any, field: str) -> dict[str, Any]:
    binding = _exact_keys(value, {"sha256", "sizeBytes", "recordCount"}, field)
    _sha256(binding["sha256"], f"{field}.sha256")
    _integer(binding["sizeBytes"], f"{field}.sizeBytes", 1, MAX_CORPUS_BYTES)
    _integer(binding["recordCount"], f"{field}.recordCount", 1, 100_000)
    return binding


def _validate_package_file_binding(
    value: Any,
    field: str,
    *,
    max_bytes: int,
    record_count: bool,
    task_set: bool,
) -> dict[str, Any]:
    keys = {"path", "sha256", "sizeBytes"}
    if record_count:
        keys.add("recordCount")
    if task_set:
        keys.add("taskSetSha256")
    binding = _exact_keys(value, keys, field)
    _relative_package_path(binding["path"], f"{field}.path")
    _sha256(binding["sha256"], f"{field}.sha256")
    _integer(binding["sizeBytes"], f"{field}.sizeBytes", 1, max_bytes)
    if record_count:
        _integer(binding["recordCount"], f"{field}.recordCount", 1, 100_000)
    if task_set:
        _sha256(binding["taskSetSha256"], f"{field}.taskSetSha256")
    return binding


def _validate_handoff_document(value: Any) -> dict[str, Any]:
    handoff = _exact_keys(
        value,
        {
            "schemaVersion",
            "handoffId",
            "status",
            "purpose",
            "statement",
            "authority",
            "declarations",
            "sourceDataset",
            "authoringManifest",
            "calibrationTasks",
            "sealedTasks",
            "taskBindings",
            "assets",
        },
        "evaluation-authoring handoff",
    )
    constants = {
        "schemaVersion": EVALUATION_AUTHORING_HANDOFF_SCHEMA_VERSION,
        "status": EVALUATION_AUTHORING_HANDOFF_STATUS,
        "purpose": EVALUATION_AUTHORING_HANDOFF_PURPOSE,
        "statement": EVALUATION_AUTHORING_HANDOFF_STATEMENT,
    }
    for name, expected in constants.items():
        if handoff[name] != expected:
            _fail(f"evaluation-authoring handoff.{name}", f"must be {expected!r}")
    authority = _exact_keys(
        handoff["authority"],
        set(_NO_AUTHORITY),
        "evaluation-authoring handoff.authority",
    )
    if any(
        type(authority[name]) is not bool or authority[name] is not expected
        for name, expected in _NO_AUTHORITY.items()
    ):
        _fail("evaluation-authoring handoff.authority", "must grant no authority")
    declarations = _exact_keys(
        handoff["declarations"],
        set(_DECLARATIONS),
        "evaluation-authoring handoff.declarations",
    )
    if any(
        type(declarations[name]) is not bool or declarations[name] is not expected
        for name, expected in _DECLARATIONS.items()
    ):
        _fail(
            "evaluation-authoring handoff.declarations",
            "must retain every non-authorizing declaration",
        )
    _validate_source_binding(
        handoff["sourceDataset"], "evaluation-authoring handoff.sourceDataset"
    )
    _validate_package_file_binding(
        handoff["authoringManifest"],
        "evaluation-authoring handoff.authoringManifest",
        max_bytes=MAX_AUTHORING_MANIFEST_BYTES,
        record_count=False,
        task_set=False,
    )
    for name in ("calibrationTasks", "sealedTasks"):
        _validate_package_file_binding(
            handoff[name],
            f"evaluation-authoring handoff.{name}",
            max_bytes=MAX_EVALUATION_BYTES,
            record_count=True,
            task_set=True,
        )
    _validate_package_file_binding(
        handoff["taskBindings"],
        "evaluation-authoring handoff.taskBindings",
        max_bytes=MAX_RELEASE_MANIFEST_BYTES,
        record_count=True,
        task_set=False,
    )
    assets = handoff["assets"]
    if not isinstance(assets, list) or not 3 <= len(assets) <= 3 * MAX_AUTHORING_TASKS:
        _fail(
            "evaluation-authoring handoff.assets",
            "must contain the exact non-empty context, rubric, and verifier assets",
        )
    paths: set[str] = set()
    for index, value_asset in enumerate(assets):
        field = f"evaluation-authoring handoff.assets[{index}]"
        asset = _exact_keys(value_asset, {"kind", "path", "sha256", "sizeBytes"}, field)
        if asset["kind"] not in {"context-pack", "rubric", "verifier"}:
            _fail(f"{field}.kind", "must be context-pack, rubric, or verifier")
        path = _relative_package_path(asset["path"], f"{field}.path")
        expected_prefix = {
            "context-pack": "evaluation/context-packs/",
            "rubric": "evaluation/rubrics/",
            "verifier": "evaluation/verifiers/",
        }[asset["kind"]]
        if not path.startswith(expected_prefix):
            _fail(f"{field}.path", "does not match the asset kind")
        if path in paths:
            _fail(f"{field}.path", "duplicates an earlier asset")
        paths.add(path)
        asset_sha256 = _sha256(asset["sha256"], f"{field}.sha256")
        if path != f"{expected_prefix}{asset_sha256}.bin":
            _fail(f"{field}.path", "must be the exact content-addressed asset path")
        _integer(asset["sizeBytes"], f"{field}.sizeBytes", 1, MAX_REVIEW_ASSET_BYTES)
    if handoff["handoffId"] != evaluation_authoring_handoff_id(handoff):
        _fail(
            "evaluation-authoring handoff.handoffId",
            "does not match the content-derived identity",
        )
    return handoff


def _bound_package_file(
    root: Path, binding: Mapping[str, Any], field: str, limit: int
) -> tuple[Path, bytes]:
    path = resolve_bound_path(root, binding["path"], f"{field}.path")
    raw = _read_file_bounded(path, field, limit)
    if (
        len(raw) != binding["sizeBytes"]
        or hashlib.sha256(raw).hexdigest() != binding["sha256"]
    ):
        _fail(field, "does not match the exact bound bytes")
    return path, raw


def _package_files(root: Path) -> set[str]:
    result: set[str] = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        _reject_reparse_components(
            current_path, "evaluation-authoring package directory"
        )
        for directory in directories:
            _reject_reparse_components(
                current_path / directory, "evaluation-authoring package directory"
            )
        for name in files:
            path = _reject_reparse_components(
                current_path / name, "evaluation-authoring package file"
            )
            result.add(path.relative_to(root).as_posix())
    return result


def validate_evaluation_authoring_handoff(
    handoff_path: str | os.PathLike[str],
    *,
    source_dataset_path: str | os.PathLike[str],
) -> VerifiedEvaluationAuthoringHandoff:
    handoff_file = _reject_reparse_components(
        Path(handoff_path), "evaluation-authoring handoff"
    )
    if handoff_file.name != HANDOFF_FILE_NAME:
        _fail(
            "evaluation-authoring handoff",
            f"must be named {HANDOFF_FILE_NAME!r}",
        )
    root = _reject_reparse_components(
        handoff_file.parent, "evaluation-authoring handoff root"
    )
    handoff_raw = _read_file_bounded(
        handoff_file, "evaluation-authoring handoff", MAX_HANDOFF_BYTES
    )
    handoff = _validate_handoff_document(
        load_json_document(handoff_file, max_bytes=MAX_HANDOFF_BYTES)
    )

    source_path = Path(source_dataset_path)
    source_raw = _bounded_snapshot(
        source_path, "evaluation-authoring source dataset", MAX_CORPUS_BYTES
    )
    corpus = _parse_expert_corpus(source_path)
    source_binding = _source_binding(corpus, source_raw)
    if source_binding != handoff["sourceDataset"]:
        _fail(
            "evaluation-authoring handoff.sourceDataset",
            "does not match the exact reviewed source dataset",
        )

    manifest_path, manifest_raw = _bound_package_file(
        root,
        handoff["authoringManifest"],
        "evaluation-authoring handoff.authoringManifest",
        MAX_AUTHORING_MANIFEST_BYTES,
    )
    manifest, _ = _parse_authoring_manifest(
        load_json_document(manifest_path, max_bytes=MAX_AUTHORING_MANIFEST_BYTES),
        root=manifest_path.parent,
        resolve_assets=False,
    )
    if manifest["sourceDatasetSha256"] != source_binding["sha256"]:
        _fail(
            "evaluation-authoring handoff.authoringManifest",
            "binds a different source dataset",
        )

    calibration_path, calibration_raw = _bound_package_file(
        root,
        handoff["calibrationTasks"],
        "evaluation-authoring handoff.calibrationTasks",
        MAX_EVALUATION_BYTES,
    )
    sealed_path, sealed_raw = _bound_package_file(
        root,
        handoff["sealedTasks"],
        "evaluation-authoring handoff.sealedTasks",
        MAX_EVALUATION_BYTES,
    )
    bindings_path, bindings_raw = _bound_package_file(
        root,
        handoff["taskBindings"],
        "evaluation-authoring handoff.taskBindings",
        MAX_RELEASE_MANIFEST_BYTES,
    )
    calibration = validate_evaluation_tasks(calibration_path)
    sealed = validate_evaluation_tasks(sealed_path)
    for name, tasks, raw in (
        ("calibrationTasks", calibration, calibration_raw),
        ("sealedTasks", sealed, sealed_raw),
    ):
        binding = handoff[name]
        if (
            binding["recordCount"] != len(tasks.records)
            or binding["taskSetSha256"] != tasks.task_set_sha256
            or binding["sha256"] != hashlib.sha256(raw).hexdigest()
        ):
            _fail(f"evaluation-authoring handoff.{name}", "semantic identity differs")
    raw_binding_document = _exact_keys(
        load_json_document(bindings_path, max_bytes=MAX_RELEASE_MANIFEST_BYTES),
        {"schemaVersion", "bindings"},
        "evaluation-authoring handoff task bindings",
    )
    if raw_binding_document["schemaVersion"] != TASK_BINDINGS_V2_SCHEMA_VERSION:
        _fail(
            "evaluation-authoring handoff task bindings.schemaVersion",
            f"must be {TASK_BINDINGS_V2_SCHEMA_VERSION!r}",
        )
    if not isinstance(raw_binding_document["bindings"], list):
        _fail("evaluation-authoring handoff task bindings.bindings", "must be an array")
    for index, value_binding in enumerate(raw_binding_document["bindings"]):
        field = f"evaluation-authoring handoff task bindings.bindings[{index}]"
        raw_binding = _exact_keys(
            value_binding,
            {"taskId", "sourceExampleIds", "contextPack", "rubric", "verifier"},
            field,
        )
        for kind, keys in (
            ("contextPack", {"version", "path"}),
            ("rubric", {"id", "path"}),
            ("verifier", {"id", "path"}),
        ):
            raw_asset = _exact_keys(raw_binding[kind], keys, f"{field}.{kind}")
            _relative_package_path(raw_asset["path"], f"{field}.{kind}.path")
    input_bindings = _load_task_binding_input(bindings_path)
    if handoff["taskBindings"]["recordCount"] != len(input_bindings):
        _fail(
            "evaluation-authoring handoff.taskBindings.recordCount",
            "does not match the binding file",
        )
    referenced_assets: dict[str, str] = {}
    for binding in input_bindings:
        for kind, expected_kind in (
            ("contextPack", "context-pack"),
            ("rubric", "rubric"),
            ("verifier", "verifier"),
        ):
            try:
                relative = Path(binding[kind]["path"]).relative_to(root).as_posix()
            except ValueError as error:
                raise ValidationError(
                    "evaluation-authoring handoff task bindings: asset path escapes "
                    "the handoff package"
                ) from error
            prior_kind = referenced_assets.setdefault(relative, expected_kind)
            if prior_kind != expected_kind:
                _fail(
                    "evaluation-authoring handoff task bindings",
                    "reuse one asset path under different asset kinds",
                )
    declared_assets = {asset["path"]: asset for asset in handoff["assets"]}
    if {
        path: asset["kind"] for path, asset in declared_assets.items()
    } != referenced_assets:
        _fail(
            "evaluation-authoring handoff.assets",
            "must exactly match the assets referenced by task bindings",
        )
    _validate_manifest_against_package(
        manifest,
        corpus=corpus,
        tasks=[*calibration.records, *sealed.records],
        bindings=input_bindings,
    )
    if hashlib.sha256(bindings_raw).hexdigest() != handoff["taskBindings"]["sha256"]:
        _fail("evaluation-authoring handoff.taskBindings", "bytes changed")

    expected_files = {
        HANDOFF_FILE_NAME,
        handoff["authoringManifest"]["path"],
        handoff["calibrationTasks"]["path"],
        handoff["sealedTasks"]["path"],
        handoff["taskBindings"]["path"],
    }
    asset_snapshots: list[tuple[Path, bytes, str]] = []
    for index, asset in enumerate(handoff["assets"]):
        asset_path, raw = _bound_package_file(
            root,
            asset,
            f"evaluation-authoring handoff.assets[{index}]",
            MAX_REVIEW_ASSET_BYTES,
        )
        if hashlib.sha256(raw).hexdigest() != asset["sha256"]:
            _fail(
                f"evaluation-authoring handoff.assets[{index}]",
                "asset bytes changed",
            )
        expected_files.add(asset["path"])
        asset_snapshots.append(
            (asset_path, raw, f"evaluation-authoring handoff.assets[{index}]")
        )
    actual_files = _package_files(root)
    if actual_files != expected_files:
        _fail(
            "evaluation-authoring handoff package",
            "contains missing or unbound extra files",
        )

    inventory = derive_evaluation_authoring_inventory(
        source_dataset_path=source_path,
        calibration_tasks_path=calibration_path,
        sealed_tasks_path=sealed_path,
        task_bindings_path=bindings_path,
    )
    task_map = {
        task["taskId"]: task for task in (*calibration.records, *sealed.records)
    }
    expected_task_inventory = []
    for binding in input_bindings:
        task = task_map[binding["taskId"]]
        bound_assets: dict[str, dict[str, Any]] = {}
        for kind in ("contextPack", "rubric", "verifier"):
            relative = Path(binding[kind]["path"]).relative_to(root).as_posix()
            declared = declared_assets[relative]
            bound_assets[kind] = {
                "sha256": declared["sha256"],
                "sizeBytes": declared["sizeBytes"],
            }
        expected_task_inventory.append(
            {
                "taskId": binding["taskId"],
                "taskSha256": task["taskSha256"],
                "sourceExampleIds": sorted(binding["sourceExampleIds"]),
                "contextPack": {
                    "version": binding["contextPack"]["version"],
                    **bound_assets["contextPack"],
                },
                "rubric": {
                    "id": binding["rubric"]["id"],
                    **bound_assets["rubric"],
                },
                "verifier": {
                    "id": binding["verifier"]["id"],
                    **bound_assets["verifier"],
                },
            }
        )
    if (
        inventory["sourceDataset"] != handoff["sourceDataset"]
        or {
            key: inventory["calibrationTasks"][key]
            for key in ("sha256", "sizeBytes", "recordCount", "taskSetSha256")
        }
        != {
            key: handoff["calibrationTasks"][key]
            for key in ("sha256", "sizeBytes", "recordCount", "taskSetSha256")
        }
        or {
            key: inventory["sealedTasks"][key]
            for key in ("sha256", "sizeBytes", "recordCount", "taskSetSha256")
        }
        != {
            key: handoff["sealedTasks"][key]
            for key in ("sha256", "sizeBytes", "recordCount", "taskSetSha256")
        }
        or inventory["taskBindings"] != expected_task_inventory
    ):
        _fail(
            "evaluation-authoring handoff",
            "does not match the freshly derived atomic inventory",
        )
    if (
        _bounded_snapshot(
            source_path, "evaluation-authoring source dataset", MAX_CORPUS_BYTES
        )
        != source_raw
        or _bounded_snapshot(
            handoff_file, "evaluation-authoring handoff", MAX_HANDOFF_BYTES
        )
        != handoff_raw
        or _bounded_snapshot(
            manifest_path,
            "evaluation-authoring handoff authoring manifest",
            MAX_AUTHORING_MANIFEST_BYTES,
        )
        != manifest_raw
        or _bounded_snapshot(
            calibration_path,
            "evaluation-authoring handoff calibration tasks",
            MAX_EVALUATION_BYTES,
        )
        != calibration_raw
        or _bounded_snapshot(
            sealed_path,
            "evaluation-authoring handoff sealed tasks",
            MAX_EVALUATION_BYTES,
        )
        != sealed_raw
        or _bounded_snapshot(
            bindings_path,
            "evaluation-authoring handoff task bindings",
            MAX_RELEASE_MANIFEST_BYTES,
        )
        != bindings_raw
        or any(
            _bounded_snapshot(path, field, MAX_REVIEW_ASSET_BYTES) != raw
            for path, raw, field in asset_snapshots
        )
        or _package_files(root) != expected_files
    ):
        _fail("evaluation-authoring handoff", "changed while being validated")
    return VerifiedEvaluationAuthoringHandoff(handoff_file, handoff, inventory)


def compile_evaluation_authoring_handoff(
    manifest_path: str | os.PathLike[str],
    *,
    source_dataset_path: str | os.PathLike[str],
    output_directory: str | os.PathLike[str],
) -> VerifiedEvaluationAuthoringHandoff:
    manifest_file = _reject_reparse_components(
        Path(manifest_path), "evaluation-authoring manifest"
    )
    manifest_raw = _bounded_snapshot(
        manifest_file, "evaluation-authoring manifest", MAX_AUTHORING_MANIFEST_BYTES
    )
    manifest, authoring_tasks = _parse_authoring_manifest(
        load_json_document(manifest_file, max_bytes=MAX_AUTHORING_MANIFEST_BYTES),
        root=manifest_file.parent,
        resolve_assets=True,
    )
    assert authoring_tasks is not None

    source_path = Path(source_dataset_path)
    source_raw = _bounded_snapshot(
        source_path, "evaluation-authoring source dataset", MAX_CORPUS_BYTES
    )
    corpus = _parse_expert_corpus(source_path)
    source_sha256 = hashlib.sha256(source_raw).hexdigest()
    if manifest["sourceDatasetSha256"] != source_sha256:
        _fail(
            "evaluation-authoring manifest.sourceDatasetSha256",
            "does not match the exact reviewed source dataset",
        )
    evaluation_rows = _evaluation_rows(corpus)
    selected_ids = {task.source_example_id for task in authoring_tasks}
    if selected_ids != set(evaluation_rows):
        _fail(
            "evaluation-authoring manifest.tasks",
            "must map every calibration and sealed source row exactly once",
        )

    compiled: list[tuple[_AuthoringTask, dict[str, Any]]] = []
    split_counts = {"calibration": 0, "sealed": 0}
    for authoring in sorted(authoring_tasks, key=lambda item: item.task_id):
        record = evaluation_rows[authoring.source_example_id]
        source = _require_evaluation_only_row(record, authoring.source_example_id)
        task = _compile_task(authoring, source)
        compiled.append((authoring, task))
        split_counts[source["split"]] += 1
    if any(count == 0 for count in split_counts.values()):
        _fail(
            "evaluation-authoring manifest.tasks",
            "must contain at least one calibration and one sealed task",
        )
    _require_contamination_separation(corpus, [task for _, task in compiled])

    destination = _reject_reparse_components(
        Path(output_directory),
        "evaluation-authoring handoff output",
        allow_missing_suffix=True,
    )
    parent = _reject_reparse_components(
        destination.parent, "evaluation-authoring handoff output parent"
    )
    if not parent.is_dir():
        _fail(
            "evaluation-authoring handoff output parent",
            "must be an existing directory",
        )
    if destination.exists():
        _fail("evaluation-authoring handoff output", "already exists")

    stage = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", suffix=".tmp", dir=parent)
    )
    published = False
    try:
        manifest_snapshot = stage.joinpath(*AUTHORING_MANIFEST_PATH.split("/"))
        manifest_snapshot.parent.mkdir(parents=True, exist_ok=True)
        manifest_snapshot.write_bytes(manifest_raw)

        calibration_records = [
            task for _, task in compiled if task["split"] == "calibration"
        ]
        sealed_records = [task for _, task in compiled if task["split"] == "sealed"]
        calibration_path = stage.joinpath(*CALIBRATION_TASKS_PATH.split("/"))
        sealed_path = stage.joinpath(*SEALED_TASKS_PATH.split("/"))
        bindings_path = stage.joinpath(*TASK_BINDINGS_PATH.split("/"))
        _write_jsonl(calibration_path, calibration_records)
        _write_jsonl(sealed_path, sealed_records)
        bindings = {
            "schemaVersion": TASK_BINDINGS_V2_SCHEMA_VERSION,
            "bindings": [_task_binding(authoring) for authoring, _ in compiled],
        }
        _write_json(bindings_path, bindings)

        assets: dict[str, tuple[str, bytes]] = {}
        for authoring, _ in compiled:
            for kind, raw in (
                ("context-pack", authoring.context_raw),
                ("rubric", authoring.rubric_raw),
                ("verifier", authoring.verifier_raw),
            ):
                plural = {
                    "context-pack": "context-packs",
                    "rubric": "rubrics",
                    "verifier": "verifiers",
                }[kind]
                relative = _asset_package_path(plural, raw)
                assets[relative] = (kind, raw)
        asset_inventory = []
        for relative, (kind, raw) in sorted(assets.items()):
            asset_path = stage.joinpath(*relative.split("/"))
            asset_path.parent.mkdir(parents=True, exist_ok=True)
            asset_path.write_bytes(raw)
            asset_inventory.append(
                {
                    "kind": kind,
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "sizeBytes": len(raw),
                }
            )

        calibration = validate_evaluation_tasks(calibration_path)
        sealed = validate_evaluation_tasks(sealed_path)
        inventory = derive_evaluation_authoring_inventory(
            source_dataset_path=source_path,
            calibration_tasks_path=calibration_path,
            sealed_tasks_path=sealed_path,
            task_bindings_path=bindings_path,
        )
        handoff: dict[str, Any] = {
            "schemaVersion": EVALUATION_AUTHORING_HANDOFF_SCHEMA_VERSION,
            "handoffId": EVALUATION_AUTHORING_HANDOFF_ID_PREFIX + _ZERO_SHA256,
            "status": EVALUATION_AUTHORING_HANDOFF_STATUS,
            "purpose": EVALUATION_AUTHORING_HANDOFF_PURPOSE,
            "statement": EVALUATION_AUTHORING_HANDOFF_STATEMENT,
            "authority": dict(_NO_AUTHORITY),
            "declarations": dict(_DECLARATIONS),
            "sourceDataset": _source_binding(corpus, source_raw),
            "authoringManifest": _file_binding(
                manifest_snapshot, AUTHORING_MANIFEST_PATH
            ),
            "calibrationTasks": _file_binding(
                calibration_path,
                CALIBRATION_TASKS_PATH,
                record_count=len(calibration.records),
                task_set_sha256=calibration.task_set_sha256,
            ),
            "sealedTasks": _file_binding(
                sealed_path,
                SEALED_TASKS_PATH,
                record_count=len(sealed.records),
                task_set_sha256=sealed.task_set_sha256,
            ),
            "taskBindings": _file_binding(
                bindings_path,
                TASK_BINDINGS_PATH,
                record_count=len(inventory["taskBindings"]),
            ),
            "assets": asset_inventory,
        }
        handoff["handoffId"] = evaluation_authoring_handoff_id(handoff)
        handoff_path = stage / HANDOFF_FILE_NAME
        _write_json(handoff_path, handoff)
        verified = validate_evaluation_authoring_handoff(
            handoff_path, source_dataset_path=source_path
        )

        input_snapshots = [
            (path, raw)
            for authoring in authoring_tasks
            for path, raw in (
                (authoring.context_path, authoring.context_raw),
                (authoring.rubric_path, authoring.rubric_raw),
                (authoring.verifier_path, authoring.verifier_raw),
            )
        ]
        if (
            _bounded_snapshot(
                manifest_file,
                "evaluation-authoring manifest",
                MAX_AUTHORING_MANIFEST_BYTES,
            )
            != manifest_raw
            or _bounded_snapshot(
                source_path, "evaluation-authoring source dataset", MAX_CORPUS_BYTES
            )
            != source_raw
        ):
            _fail("evaluation-authoring inputs", "changed before publication")
        for path, expected in input_snapshots:
            if (
                _bounded_snapshot(
                    path, "evaluation-authoring asset", MAX_REVIEW_ASSET_BYTES
                )
                != expected
            ):
                _fail("evaluation-authoring asset", "changed before publication")
        with _exclusive_destination_lock(
            destination, "evaluation-authoring handoff output"
        ) as locked_destination:
            _install_handoff_no_clobber(
                stage,
                locked_destination,
                "evaluation-authoring handoff output",
            )
        published = True
        return VerifiedEvaluationAuthoringHandoff(
            destination / HANDOFF_FILE_NAME,
            verified.document,
            verified.inventory,
        )
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)
