from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, TypeVar

from .core import (
    ValidationError,
    _exact_keys,
    _fail,
    _integer,
    _load_json_object_bytes,
    _parse_datetime,
    _pinned_revision_label,
    _reject_reparse_components,
    _sha256,
    _string,
    canonical_json_bytes,
)
from .evaluation import (
    MAX_EVALUATION_BYTES,
    EvaluationTaskSet,
    validate_evaluation_tasks,
)
from .verifier_authority import (
    _base64url_decode,
    _base64url_encode,
    _bounded_snapshot,
    _canonical_document,
    _crypto_modules,
    _load_private_key,
    _load_public_key,
    _sign_p1363_low_s,
    _verify_p1363_low_s,
)


EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.evaluation-authoring-approval/v1"
)
EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.evaluation-authoring-approval-envelope/v1"
)
EVALUATION_AUTHORING_APPROVAL_SCOPE = "release-evaluation-authoring-only"
EVALUATION_AUTHORING_APPROVAL_DECISION = "approved"
EVALUATION_AUTHORING_APPROVAL_PAYLOAD_ENCODING = "canonical-json-base64url"
EVALUATION_AUTHORING_APPROVAL_ALGORITHM = "ES256"
EVALUATION_AUTHORING_APPROVAL_SIGNATURE_FORMAT = "ieee-p1363-low-s"
EVALUATION_AUTHORING_APPROVAL_ID_PREFIX = (
    "daxalgo-evaluation-authoring-approval-sha256-"
)
EVALUATION_AUTHORING_APPROVAL_STATEMENT = (
    "This signed approval authenticates only the exact evaluation-authoring "
    "inventory named here. It grants no corpus review, release, training, base "
    "selection, promotion decision, deployment, hosted serving, installation, "
    "verifier execution, or strategy execution authority."
)
EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.evaluation-authoring-approval-signing-bundle/v1"
)
EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.evaluation-authoring-approval-signature/v1"
)
EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_ID_PREFIX = "vqauthoringsigning-"
EVALUATION_AUTHORING_APPROVAL_SIGNATURE_ID_PREFIX = "vqauthoringsignature-"
EVALUATION_AUTHORING_APPROVAL_SIGNING_STATUS = "unsigned-non-authorizing"
EVALUATION_AUTHORING_APPROVAL_SIGNING_HASH_ALGORITHM = "SHA-256"
EVALUATION_AUTHORING_APPROVAL_SIGNING_MESSAGE_TYPE = "digest"
EVALUATION_AUTHORING_APPROVAL_SIGNING_INPUT_ENCODING = "base64url"
EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"

MAX_EVALUATION_AUTHORING_APPROVAL_BYTES = 1_000_000
MAX_EVALUATION_AUTHORING_APPROVAL_PAYLOAD_BYTES = 750_000
MAX_EVALUATION_AUTHORING_APPROVAL_VALIDITY = timedelta(days=366)
MAX_EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_BYTES = 4_000_000
MAX_EVALUATION_AUTHORING_APPROVAL_SIGNATURE_BYTES = 16_000
MAX_EVALUATION_AUTHORING_APPROVAL_SIGNATURE_INPUT_BYTES = 1_500_000
MAX_EVALUATION_AUTHORING_APPROVAL_DER_SIGNATURE_BYTES = 80

_ZERO_SHA256 = "0" * 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BOUND_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SIGNATURE_DOMAIN = b"daxalgo-evaluation-authoring-approval-signature/v1\x00"
_ID_DOMAIN = b"daxalgo-evaluation-authoring-approval-id/v1\x00"
_SIGNING_BUNDLE_ID_DOMAIN = (
    b"daxalgo-evaluation-authoring-approval-signing-bundle-id/v1\x00"
)
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    b"daxalgo-evaluation-authoring-approval-external-signature-id/v1\x00"
)
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqauthoringsigning-[0-9a-f]{64}$")
_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqauthoringsignature-[0-9a-f]{64}$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_Validated = TypeVar("_Validated")


@dataclass(frozen=True)
class EvaluationAuthoringApprovalTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str


@dataclass(frozen=True)
class VerifiedEvaluationAuthoringApproval:
    path: Path
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str
    public_key_spki_sha256: str
    not_before_utc: datetime
    expires_at_utc: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "authoringApprovalId": self.payload["authoringApprovalId"],
            "payloadSha256": self.payload_sha256,
            "envelopeSha256": self.envelope_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "notBeforeUtc": self.payload["notBeforeUtc"],
            "expiresAtUtc": self.payload["expiresAtUtc"],
        }


@dataclass(frozen=True)
class VerifiedEvaluationAuthoringApprovalSigningBundle:
    path: Path
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    authoring_approval_id: str
    payload_sha256: str
    public_key_spki_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "signingBundlePath": str(self.path),
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "authoringApprovalId": self.authoring_approval_id,
            "payloadSha256": self.payload_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "status": EVALUATION_AUTHORING_APPROVAL_SIGNING_STATUS,
        }


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=128)
    if not _IDENTIFIER_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _bound_identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _BOUND_IDENTIFIER_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _canonical_utc(value: Any, field: str) -> datetime:
    text = _string(value, field, max_length=20)
    if not _UTC_RE.fullmatch(text):
        _fail(field, "must use exact UTC second form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValidationError(f"{field}: must be a real UTC second") from error
    return parsed.replace(tzinfo=timezone.utc)


def _validation_time(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(field, "must be timezone-aware")
    return value.astimezone(timezone.utc)


def _fresh_validation_time(value: datetime | None, field: str) -> datetime:
    return _validation_time(
        value if value is not None else datetime.now(timezone.utc), field
    )


def _framed(fields: Iterable[str | bytes]) -> bytes:
    framed = bytearray()
    for field in fields:
        raw = field if isinstance(field, bytes) else field.encode("utf-8")
        framed.extend(len(raw).to_bytes(8, "big", signed=False))
        framed.extend(raw)
    return bytes(framed)


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


def evaluation_authoring_approval_signing_bundle_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def evaluation_authoring_approval_signature_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=EVALUATION_AUTHORING_APPROVAL_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


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
    if (
        signature_format
        == EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT
    ):
        signature = _base64url_decode(value, field, 64)
        if len(signature) != 64:
            _fail(field, "must decode to exactly 64 bytes")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif (
        signature_format == EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT
    ):
        signature = _base64url_decode(
            value, field, MAX_EVALUATION_AUTHORING_APPROVAL_DER_SIGNATURE_BYTES
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


def _validate_trust(
    trust: EvaluationAuthoringApprovalTrust,
) -> tuple[Any, str, str, str, str]:
    if not isinstance(trust, EvaluationAuthoringApprovalTrust):
        _fail("evaluation-authoring approval trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(Path(trust.public_key_path))
    expected_spki = _sha256(
        trust.public_key_spki_sha256,
        "evaluation-authoring approval trust.publicKeySpkiSha256",
    )
    if actual_spki != expected_spki:
        _fail(
            "evaluation-authoring approval trust.publicKeySpkiSha256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "evaluation-authoring approval trust.audience"),
        _identifier(trust.key_id, "evaluation-authoring approval trust.keyId"),
        _identifier(
            trust.signer_role, "evaluation-authoring approval trust.signerRole"
        ),
    )


def _validate_file_binding(
    value: Any,
    field: str,
    *,
    max_bytes: int,
    include_task_set: bool,
) -> dict[str, Any]:
    expected = {"sha256", "sizeBytes", "recordCount"}
    if include_task_set:
        expected.add("taskSetSha256")
    binding = _exact_keys(value, expected, field)
    _sha256(binding["sha256"], f"{field}.sha256")
    _integer(binding["sizeBytes"], f"{field}.sizeBytes", 1, max_bytes)
    _integer(binding["recordCount"], f"{field}.recordCount", 1, 100_000)
    if include_task_set:
        _sha256(binding["taskSetSha256"], f"{field}.taskSetSha256")
    return binding


def _validate_asset(value: Any, field: str, *, version: bool) -> dict[str, Any]:
    expected = {"sha256", "sizeBytes"}
    expected.add("version" if version else "id")
    asset = _exact_keys(value, expected, field)
    if version:
        _pinned_revision_label(asset["version"], f"{field}.version")
    else:
        _bound_identifier(asset["id"], f"{field}.id")
    _sha256(asset["sha256"], f"{field}.sha256")
    _integer(asset["sizeBytes"], f"{field}.sizeBytes", 1, 16_000_000)
    return asset


def _validate_inventory(value: Any) -> dict[str, Any]:
    inventory = _exact_keys(
        value,
        {
            "sourceDataset",
            "calibrationTasks",
            "sealedTasks",
            "taskBindings",
        },
        "evaluation-authoring approval payload.inventory",
    )
    _validate_file_binding(
        inventory["sourceDataset"],
        "evaluation-authoring approval payload.inventory.sourceDataset",
        max_bytes=100_000_000,
        include_task_set=False,
    )
    calibration = _validate_file_binding(
        inventory["calibrationTasks"],
        "evaluation-authoring approval payload.inventory.calibrationTasks",
        max_bytes=MAX_EVALUATION_BYTES,
        include_task_set=True,
    )
    sealed = _validate_file_binding(
        inventory["sealedTasks"],
        "evaluation-authoring approval payload.inventory.sealedTasks",
        max_bytes=MAX_EVALUATION_BYTES,
        include_task_set=True,
    )
    bindings = inventory["taskBindings"]
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 100_000:
        _fail(
            "evaluation-authoring approval payload.inventory.taskBindings",
            "must contain 1 to 100000 bindings",
        )
    task_ids: list[str] = []
    task_hashes: set[str] = set()
    for index, value_binding in enumerate(bindings):
        field = f"evaluation-authoring approval payload.inventory.taskBindings[{index}]"
        binding = _exact_keys(
            value_binding,
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
        task_ids.append(_bound_identifier(binding["taskId"], f"{field}.taskId"))
        task_hash = _sha256(binding["taskSha256"], f"{field}.taskSha256")
        if task_hash in task_hashes:
            _fail(f"{field}.taskSha256", "duplicates an earlier task")
        task_hashes.add(task_hash)
        source_ids = binding["sourceExampleIds"]
        if not isinstance(source_ids, list) or not 1 <= len(source_ids) <= 100_000:
            _fail(
                f"{field}.sourceExampleIds",
                "must contain 1 to 100000 source identifiers",
            )
        validated_source_ids = [
            _bound_identifier(source_id, f"{field}.sourceExampleIds[{source_index}]")
            for source_index, source_id in enumerate(source_ids)
        ]
        if validated_source_ids != sorted(validated_source_ids) or len(
            validated_source_ids
        ) != len(set(validated_source_ids)):
            _fail(
                f"{field}.sourceExampleIds",
                "must be unique and sorted",
            )
        _validate_asset(binding["contextPack"], f"{field}.contextPack", version=True)
        _validate_asset(binding["rubric"], f"{field}.rubric", version=False)
        _validate_asset(binding["verifier"], f"{field}.verifier", version=False)
    if task_ids != sorted(task_ids) or len(task_ids) != len(set(task_ids)):
        _fail(
            "evaluation-authoring approval payload.inventory.taskBindings",
            "must be unique and sorted by taskId",
        )
    if len(bindings) != calibration["recordCount"] + sealed["recordCount"]:
        _fail(
            "evaluation-authoring approval payload.inventory.taskBindings",
            "must cover the declared calibration and sealed task counts",
        )
    return inventory


def evaluation_authoring_approval_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["authoringApprovalId"] = (
        EVALUATION_AUTHORING_APPROVAL_ID_PREFIX + _ZERO_SHA256
    )
    digest = hashlib.sha256(_ID_DOMAIN + canonical_json_bytes(normalized)).hexdigest()
    return EVALUATION_AUTHORING_APPROVAL_ID_PREFIX + digest


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_keys(
        value,
        {
            "schemaVersion",
            "authoringApprovalId",
            "decision",
            "scope",
            "reusable",
            "evaluationAuthoringApproved",
            "corpusReviewAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "baseSelectionAuthorized",
            "promotionDecisionAuthorized",
            "deploymentAuthorized",
            "hostedServingAuthorized",
            "installationAuthorized",
            "verifierExecutionAuthorized",
            "strategyExecutionAuthorized",
            "issuedAtUtc",
            "notBeforeUtc",
            "expiresAtUtc",
            "inventory",
            "approval",
            "statement",
        },
        "evaluation-authoring approval payload",
    )
    constants = {
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
        "decision": EVALUATION_AUTHORING_APPROVAL_DECISION,
        "scope": EVALUATION_AUTHORING_APPROVAL_SCOPE,
        "reusable": True,
        "evaluationAuthoringApproved": True,
        "corpusReviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "baseSelectionAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "statement": EVALUATION_AUTHORING_APPROVAL_STATEMENT,
    }
    for name, expected in constants.items():
        if type(payload[name]) is not type(expected) or payload[name] != expected:
            _fail(
                f"evaluation-authoring approval payload.{name}",
                "does not match the contract",
            )

    issued = _canonical_utc(
        payload["issuedAtUtc"], "evaluation-authoring approval payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"],
        "evaluation-authoring approval payload.notBeforeUtc",
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "evaluation-authoring approval payload.expiresAtUtc"
    )
    approval = _exact_keys(
        payload["approval"],
        {"approvalId", "actorId", "actorRole", "reference", "approvedAtUtc"},
        "evaluation-authoring approval payload.approval",
    )
    for name in ("approvalId", "actorId", "actorRole"):
        _identifier(
            approval[name], f"evaluation-authoring approval payload.approval.{name}"
        )
    _string(
        approval["reference"],
        "evaluation-authoring approval payload.approval.reference",
        max_length=500,
    )
    approved = _canonical_utc(
        approval["approvedAtUtc"],
        "evaluation-authoring approval payload.approval.approvedAtUtc",
    )
    if not approved <= issued <= not_before < expires:
        _fail(
            "evaluation-authoring approval payload validity",
            "must satisfy approvedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_EVALUATION_AUTHORING_APPROVAL_VALIDITY:
        _fail(
            "evaluation-authoring approval payload validity",
            "must not exceed 366 days",
        )
    _validate_inventory(payload["inventory"])
    if payload["authoringApprovalId"] != evaluation_authoring_approval_id(payload):
        _fail(
            "evaluation-authoring approval payload.authoringApprovalId",
            "does not match the content-derived identity",
        )
    return payload


def _stable_corpus(path: Path) -> tuple[Any, bytes]:
    from .release import MAX_CORPUS_BYTES, _parse_expert_corpus

    raw = _bounded_snapshot(
        path, "evaluation-authoring source dataset", MAX_CORPUS_BYTES
    )
    corpus = _parse_expert_corpus(path)
    if (
        corpus.sha256 != hashlib.sha256(raw).hexdigest()
        or _bounded_snapshot(
            path, "evaluation-authoring source dataset", MAX_CORPUS_BYTES
        )
        != raw
    ):
        _fail("evaluation-authoring source dataset", "changed while being validated")
    return corpus, raw


def _stable_tasks(path: Path, field: str) -> tuple[EvaluationTaskSet, bytes]:
    raw = _bounded_snapshot(path, field, MAX_EVALUATION_BYTES)
    tasks = validate_evaluation_tasks(path)
    if (
        tasks.sha256 != hashlib.sha256(raw).hexdigest()
        or _bounded_snapshot(path, field, MAX_EVALUATION_BYTES) != raw
    ):
        _fail(field, "changed while being validated")
    return tasks, raw


def _stable_input_bindings(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    from .release import MAX_RELEASE_MANIFEST_BYTES, _load_task_binding_input

    raw = _bounded_snapshot(
        path, "evaluation-authoring task bindings", MAX_RELEASE_MANIFEST_BYTES
    )
    bindings = _load_task_binding_input(path)
    if (
        _bounded_snapshot(
            path, "evaluation-authoring task bindings", MAX_RELEASE_MANIFEST_BYTES
        )
        != raw
    ):
        _fail("evaluation-authoring task bindings", "changed while being validated")
    return bindings, raw


def _task_file_binding(tasks: EvaluationTaskSet, raw: bytes) -> dict[str, Any]:
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
        "taskSetSha256": tasks.task_set_sha256,
        "recordCount": len(tasks.records),
    }


def derive_evaluation_authoring_inventory(
    *,
    source_dataset_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    task_bindings_path: str | os.PathLike[str],
) -> dict[str, Any]:
    from .release import (
        MAX_CORPUS_BYTES,
        MAX_RELEASE_MANIFEST_BYTES,
        MAX_REVIEW_ASSET_BYTES,
    )

    source_path = Path(source_dataset_path)
    calibration_path = Path(calibration_tasks_path)
    sealed_path = Path(sealed_tasks_path)
    bindings_path = Path(task_bindings_path)
    corpus, source_raw = _stable_corpus(source_path)
    calibration, calibration_raw = _stable_tasks(
        calibration_path, "evaluation-authoring calibration tasks"
    )
    sealed, sealed_raw = _stable_tasks(sealed_path, "evaluation-authoring sealed tasks")
    input_bindings, bindings_raw = _stable_input_bindings(bindings_path)

    if {task["split"] for task in calibration.records} != {"calibration"}:
        _fail(
            "evaluation-authoring calibration tasks",
            "must contain calibration tasks only",
        )
    if {task["split"] for task in sealed.records} != {"sealed"}:
        _fail("evaluation-authoring sealed tasks", "must contain sealed tasks only")
    cross_fields = (
        ("task IDs", "taskId"),
        ("task hashes", "taskSha256"),
        ("prompts", "promptSha256"),
        ("contamination groups", "contaminationGroup"),
    )
    for label, name in cross_fields:
        if {task[name] for task in calibration.records} & {
            task[name] for task in sealed.records
        }:
            _fail(
                "evaluation-authoring task inventory",
                f"calibration and sealed {label} overlap",
            )

    task_map = {
        task["taskId"]: task for task in (*calibration.records, *sealed.records)
    }
    if {binding["taskId"] for binding in input_bindings} != set(task_map):
        _fail(
            "evaluation-authoring task bindings",
            "must cover every calibration and sealed task exactly once",
        )

    snapshots: list[tuple[Path, str, int, bytes]] = [
        (
            source_path,
            "evaluation-authoring source dataset",
            MAX_CORPUS_BYTES,
            source_raw,
        ),
        (
            calibration_path,
            "evaluation-authoring calibration tasks",
            MAX_EVALUATION_BYTES,
            calibration_raw,
        ),
        (
            sealed_path,
            "evaluation-authoring sealed tasks",
            MAX_EVALUATION_BYTES,
            sealed_raw,
        ),
        (
            bindings_path,
            "evaluation-authoring task bindings",
            MAX_RELEASE_MANIFEST_BYTES,
            bindings_raw,
        ),
    ]
    bound_tasks: list[dict[str, Any]] = []
    for index, binding in enumerate(input_bindings):
        task = task_map[binding["taskId"]]
        field = f"evaluation-authoring task bindings[{index}]"
        source_ids = sorted(binding["sourceExampleIds"])
        task_cutoff = _parse_datetime(
            task["cutoffUtc"], f"{field}.taskCutoff", require_utc_z=True
        )
        source_records = []
        for source_id in source_ids:
            record = corpus.records.get(source_id)
            if record is None:
                _fail(
                    f"{field}.sourceExampleIds",
                    f"references unknown source example {source_id!r}",
                )
            document = record.document
            if document["split"] != task["split"]:
                _fail(
                    f"{field}.sourceExampleIds",
                    f"example {source_id!r} has the wrong split",
                )
            if record.cutoff != task_cutoff:
                _fail(
                    f"{field}.sourceExampleIds",
                    f"example {source_id!r} has a different cutoff",
                )
            source_records.append(record)
        primary = source_records[0].document
        if primary["messages"][:-1] != task["messages"]:
            _fail(
                f"{field}.sourceExampleIds[0]",
                "does not provide the exact task prompt",
            )
        if (
            primary["taskKind"] != task["taskKind"]
            or primary["domains"] != task["domains"]
        ):
            _fail(
                f"{field}.sourceExampleIds[0]",
                "task kind or domains differ from the task",
            )

        assets: dict[str, dict[str, Any]] = {}
        for kind in ("contextPack", "rubric", "verifier"):
            asset_path = Path(binding[kind]["path"])
            raw = _bounded_snapshot(
                asset_path, f"{field}.{kind}", MAX_REVIEW_ASSET_BYTES
            )
            if not raw:
                _fail(f"{field}.{kind}", "must not be empty")
            snapshots.append(
                (asset_path, f"{field}.{kind}", MAX_REVIEW_ASSET_BYTES, raw)
            )
            assets[kind] = {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "sizeBytes": len(raw),
            }
        if binding["contextPack"]["version"] != task["contextPack"]["version"]:
            _fail(
                f"{field}.contextPack.version",
                "does not match the task context-pack version",
            )
        if assets["contextPack"]["sha256"] != task["contextPack"]["sha256"]:
            _fail(
                f"{field}.contextPack.sha256",
                "does not match the exact task context-pack bytes",
            )
        if binding["verifier"]["id"] != task["verifier"]["id"]:
            _fail(f"{field}.verifier.id", "does not match the task verifier ID")
        if assets["verifier"]["sha256"] != task["verifier"]["sha256"]:
            _fail(
                f"{field}.verifier.sha256",
                "does not match the exact task verifier bytes",
            )
        bound_tasks.append(
            {
                "taskId": task["taskId"],
                "taskSha256": task["taskSha256"],
                "sourceExampleIds": source_ids,
                "contextPack": {
                    "version": binding["contextPack"]["version"],
                    **assets["contextPack"],
                },
                "rubric": {"id": binding["rubric"]["id"], **assets["rubric"]},
                "verifier": {
                    "id": binding["verifier"]["id"],
                    **assets["verifier"],
                },
            }
        )

    for path, field, limit, expected in snapshots:
        if _bounded_snapshot(path, field, limit) != expected:
            _fail(field, "changed while the atomic inventory was derived")

    inventory = {
        "sourceDataset": {
            "sha256": hashlib.sha256(source_raw).hexdigest(),
            "sizeBytes": len(source_raw),
            "recordCount": len(corpus.records),
        },
        "calibrationTasks": _task_file_binding(calibration, calibration_raw),
        "sealedTasks": _task_file_binding(sealed, sealed_raw),
        "taskBindings": bound_tasks,
    }
    return _validate_inventory(inventory)


def _ensure_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> tuple[datetime, datetime]:
    not_before = _canonical_utc(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "is not active")
    return not_before, expires


def _build_authoring_payload(
    *,
    inventory: Mapping[str, Any],
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
        "authoringApprovalId": EVALUATION_AUTHORING_APPROVAL_ID_PREFIX + _ZERO_SHA256,
        "decision": EVALUATION_AUTHORING_APPROVAL_DECISION,
        "scope": EVALUATION_AUTHORING_APPROVAL_SCOPE,
        "reusable": True,
        "evaluationAuthoringApproved": True,
        "corpusReviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "baseSelectionAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "inventory": dict(inventory),
        "approval": {
            "approvalId": approval_id,
            "actorId": actor_id,
            "actorRole": actor_role,
            "reference": approval_reference,
            "approvedAtUtc": approved_at_utc,
        },
        "statement": EVALUATION_AUTHORING_APPROVAL_STATEMENT,
    }
    payload["authoringApprovalId"] = evaluation_authoring_approval_id(payload)
    return _validate_payload(payload)


def _unsigned_envelope(
    payload_bytes: bytes,
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION,
        "payloadType": EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
        "payloadEncoding": EVALUATION_AUTHORING_APPROVAL_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": EVALUATION_AUTHORING_APPROVAL_ALGORITHM,
        "signatureFormat": EVALUATION_AUTHORING_APPROVAL_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


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
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": (
            EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256
        ),
        "status": EVALUATION_AUTHORING_APPROVAL_SIGNING_STATUS,
        "authority": {
            "evaluationAuthoringApprovalIssuance": False,
            "corpusReview": False,
            "release": False,
            "training": False,
            "baseSelection": False,
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
        "authoringApprovalId": payload["authoringApprovalId"],
        "inventorySha256": hashlib.sha256(
            canonical_json_bytes(payload["inventory"])
        ).hexdigest(),
        "signatureContract": {
            "algorithm": EVALUATION_AUTHORING_APPROVAL_ALGORITHM,
            "hashAlgorithm": EVALUATION_AUTHORING_APPROVAL_SIGNING_HASH_ALGORITHM,
            "messageType": EVALUATION_AUTHORING_APPROVAL_SIGNING_MESSAGE_TYPE,
            "signatureInputEncoding": (
                EVALUATION_AUTHORING_APPROVAL_SIGNING_INPUT_ENCODING
            ),
            "acceptedSignatureFormats": [
                EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
                EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "authoringApprovalId": payload["authoringApprovalId"],
            "payloadSha256": envelope["payloadSha256"],
            "payload": envelope["payload"],
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = evaluation_authoring_approval_signing_bundle_id(bundle)
    return bundle


def _validate_signing_bundle_document(
    value: Any,
    *,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    expected_inventory: Mapping[str, Any],
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
            "authoringApprovalId",
            "inventorySha256",
            "signatureContract",
            "request",
        },
        "evaluation-authoring approval signing bundle",
    )
    constants = {
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION,
        "status": EVALUATION_AUTHORING_APPROVAL_SIGNING_STATUS,
    }
    for name, expected in constants.items():
        if type(bundle[name]) is not type(expected) or bundle[name] != expected:
            _fail(
                f"evaluation-authoring approval signing bundle.{name}",
                "does not match the contract",
            )

    authority = _exact_keys(
        bundle["authority"],
        {
            "evaluationAuthoringApprovalIssuance",
            "corpusReview",
            "release",
            "training",
            "baseSelection",
            "promotionDecision",
            "deployment",
            "hostedServing",
            "installation",
            "verifierExecution",
            "strategyExecution",
        },
        "evaluation-authoring approval signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"evaluation-authoring approval signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )

    trust = _exact_keys(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "evaluation-authoring approval signing bundle.trust",
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
                f"evaluation-authoring approval signing bundle.trust.{name}",
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
        "evaluation-authoring approval signing bundle.signatureContract",
    )
    expected_contract = {
        "algorithm": EVALUATION_AUTHORING_APPROVAL_ALGORITHM,
        "hashAlgorithm": EVALUATION_AUTHORING_APPROVAL_SIGNING_HASH_ALGORITHM,
        "messageType": EVALUATION_AUTHORING_APPROVAL_SIGNING_MESSAGE_TYPE,
        "signatureInputEncoding": EVALUATION_AUTHORING_APPROVAL_SIGNING_INPUT_ENCODING,
        "acceptedSignatureFormats": [
            EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT,
            EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    for name, expected in expected_contract.items():
        if type(contract[name]) is not type(expected) or contract[name] != expected:
            _fail(
                f"evaluation-authoring approval signing bundle.signatureContract.{name}",
                "does not match the contract",
            )

    request = _exact_keys(
        bundle["request"],
        {
            "authoringApprovalId",
            "payloadSha256",
            "payload",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "evaluation-authoring approval signing bundle.request",
    )
    payload_bytes = _base64url_decode(
        request["payload"],
        "evaluation-authoring approval signing bundle.request.payload",
        MAX_EVALUATION_AUTHORING_APPROVAL_PAYLOAD_BYTES,
    )
    if hashlib.sha256(payload_bytes).hexdigest() != _sha256(
        request["payloadSha256"],
        "evaluation-authoring approval signing bundle.request.payloadSha256",
    ):
        _fail(
            "evaluation-authoring approval signing bundle.request.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(
        payload_bytes, "evaluation-authoring approval signing bundle payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail(
            "evaluation-authoring approval signing bundle payload",
            "must be exact canonical JSON",
        )
    payload = _validate_payload(payload)
    _ensure_payload_active(
        payload, now, "evaluation-authoring approval signing bundle payload"
    )
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "evaluation-authoring approval signing bundle payload.approval.actorRole",
            "must match externally pinned signerRole",
        )
    authoring_approval_id = payload["authoringApprovalId"]
    for field, supplied in (
        (
            "evaluation-authoring approval signing bundle.authoringApprovalId",
            bundle["authoringApprovalId"],
        ),
        (
            "evaluation-authoring approval signing bundle.request.authoringApprovalId",
            request["authoringApprovalId"],
        ),
    ):
        if supplied != authoring_approval_id:
            _fail(field, "does not match the signed payload identity")
    if payload["inventory"] != dict(expected_inventory):
        _fail(
            "evaluation-authoring approval signing bundle payload.inventory",
            "does not match the exact live evaluation-authoring inventory",
        )
    inventory_sha256 = hashlib.sha256(
        canonical_json_bytes(payload["inventory"])
    ).hexdigest()
    if (
        _sha256(
            bundle["inventorySha256"],
            "evaluation-authoring approval signing bundle.inventorySha256",
        )
        != inventory_sha256
    ):
        _fail(
            "evaluation-authoring approval signing bundle.inventorySha256",
            "does not match the exact payload inventory",
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
        "evaluation-authoring approval signing bundle.request.signaturePreimage",
        MAX_EVALUATION_AUTHORING_APPROVAL_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != expected_preimage:
        _fail(
            "evaluation-authoring approval signing bundle.request.signaturePreimage",
            "does not match the exact approval-envelope signature preimage",
        )
    expected_digest = hashlib.sha256(expected_preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "evaluation-authoring approval signing bundle.request.signatureInput",
        32,
    )
    if len(supplied_digest) != 32 or supplied_digest != expected_digest:
        _fail(
            "evaluation-authoring approval signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "evaluation-authoring approval signing bundle.request.signatureInputSha256",
        )
        != expected_digest.hex()
    ):
        _fail(
            "evaluation-authoring approval signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id != evaluation_authoring_approval_signing_bundle_id(bundle)
    ):
        _fail(
            "evaluation-authoring approval signing bundle.bundleId",
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
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION,
        "signatureId": EVALUATION_AUTHORING_APPROVAL_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "authoringApprovalId": bundle["authoringApprovalId"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    document["signatureId"] = evaluation_authoring_approval_signature_id(document)
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
            "authoringApprovalId",
            "payloadSha256",
            "signatureInputSha256",
            "publicKeySpkiSha256",
            "format",
            "signature",
        },
        "evaluation-authoring approval external signature",
    )
    if (
        document["schemaVersion"]
        != EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION
    ):
        _fail(
            "evaluation-authoring approval external signature.schemaVersion",
            "is unsupported",
        )
    request = bundle["request"]
    expected_bindings = {
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "authoringApprovalId": bundle["authoringApprovalId"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
    }
    for name, expected in expected_bindings.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(
                supplied, f"evaluation-authoring approval external signature.{name}"
            )
        if supplied != expected:
            _fail(
                f"evaluation-authoring approval external signature.{name}",
                "does not match the exact signing bundle",
            )
    preimage = _base64url_decode(
        request["signaturePreimage"],
        "evaluation-authoring approval signing bundle.request.signaturePreimage",
        MAX_EVALUATION_AUTHORING_APPROVAL_SIGNATURE_INPUT_BYTES,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        public_key=public_key,
        signature_input=preimage,
        field="evaluation-authoring approval external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id != evaluation_authoring_approval_signature_id(document)
    ):
        _fail(
            "evaluation-authoring approval external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _read_canonical_handoff_document(
    path: str | os.PathLike[str], field: str, max_bytes: int
) -> tuple[Path, bytes, dict[str, Any]]:
    resolved = Path(os.path.abspath(os.fspath(path)))
    raw = _bounded_snapshot(resolved, field, max_bytes)
    if not raw:
        _fail(field, "must not be empty")
    return resolved, raw, _canonical_document(raw, field)


def _validate_envelope(
    value: Any,
    *,
    path: Path,
    trust: EvaluationAuthoringApprovalTrust,
    expected_envelope_sha256: str,
    now: datetime,
) -> VerifiedEvaluationAuthoringApproval:
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
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
        "evaluation-authoring approval envelope",
    )
    constants = {
        "schemaVersion": EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION,
        "payloadType": EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION,
        "payloadEncoding": EVALUATION_AUTHORING_APPROVAL_PAYLOAD_ENCODING,
        "algorithm": EVALUATION_AUTHORING_APPROVAL_ALGORITHM,
        "signatureFormat": EVALUATION_AUTHORING_APPROVAL_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(
                f"evaluation-authoring approval envelope.{name}",
                "does not match trusted configuration",
            )
    envelope_sha256 = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
    if (
        _sha256(
            expected_envelope_sha256,
            "expected evaluation-authoring approval envelope SHA-256",
        )
        != envelope_sha256
    ):
        _fail(
            "evaluation-authoring approval envelope",
            "does not match the trusted exact SHA-256",
        )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "evaluation-authoring approval envelope.payload",
        MAX_EVALUATION_AUTHORING_APPROVAL_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            envelope["payloadSha256"],
            "evaluation-authoring approval envelope.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "evaluation-authoring approval envelope.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(
        payload_bytes, "evaluation-authoring approval payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail("evaluation-authoring approval payload", "must be exact canonical JSON")
    payload = _validate_payload(payload)
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "evaluation-authoring approval payload.approval.actorRole",
            "must match the trusted signer role",
        )
    signature = _base64url_decode(
        envelope["signature"],
        "evaluation-authoring approval envelope.signature",
        64,
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"],
        "evaluation-authoring approval payload.notBeforeUtc",
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "evaluation-authoring approval payload.expiresAtUtc"
    )
    if now < not_before or now >= expires:
        _fail("evaluation-authoring approval payload validity", "is not active")
    return VerifiedEvaluationAuthoringApproval(
        path=Path(os.path.abspath(os.fspath(path))),
        envelope=envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        envelope_sha256=envelope_sha256,
        public_key_spki_sha256=spki,
        not_before_utc=not_before,
        expires_at_utc=expires,
    )


def validate_evaluation_authoring_approval(
    path: str | os.PathLike[str],
    *,
    trust: EvaluationAuthoringApprovalTrust,
    expected_envelope_sha256: str,
    now: datetime | None = None,
) -> VerifiedEvaluationAuthoringApproval:
    current = _fresh_validation_time(
        now, "evaluation-authoring approval validation time"
    )
    approval_path = Path(path)
    raw = _bounded_snapshot(
        approval_path,
        "evaluation-authoring approval",
        MAX_EVALUATION_AUTHORING_APPROVAL_BYTES,
    )
    envelope = _canonical_document(raw, "evaluation-authoring approval")
    return _validate_envelope(
        envelope,
        path=approval_path,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=current,
    )


def validate_evaluation_authoring_approval_for_inventory(
    path: str | os.PathLike[str],
    *,
    trust: EvaluationAuthoringApprovalTrust,
    expected_envelope_sha256: str,
    source_dataset_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    task_bindings_path: str | os.PathLike[str],
    now: datetime | None = None,
) -> VerifiedEvaluationAuthoringApproval:
    verified = validate_evaluation_authoring_approval(
        path,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=now,
    )
    expected_inventory = derive_evaluation_authoring_inventory(
        source_dataset_path=source_dataset_path,
        calibration_tasks_path=calibration_tasks_path,
        sealed_tasks_path=sealed_tasks_path,
        task_bindings_path=task_bindings_path,
    )
    if verified.payload["inventory"] != expected_inventory:
        _fail(
            "evaluation-authoring approval payload.inventory",
            "does not match the exact live evaluation-authoring inventory",
        )
    return verified


def ensure_evaluation_authoring_approval_active(
    verified: VerifiedEvaluationAuthoringApproval, now: datetime
) -> None:
    if not isinstance(verified, VerifiedEvaluationAuthoringApproval):
        _fail("evaluation-authoring approval", "must be a verified signed approval")
    current = _validation_time(now, "evaluation-authoring approval publication time")
    if current < verified.not_before_utc or current >= verified.expires_at_utc:
        _fail(
            "evaluation-authoring approval payload validity",
            "expired before publication",
        )


def _write_no_clobber(
    path: Path,
    raw: bytes,
    *,
    prepublish_validator: Callable[[Path], _Validated],
    field: str = "evaluation-authoring approval output",
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
    identity_guard: int | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            if os.name == "posix":
                # Retain the original inode through final validation so cleanup
                # cannot mistake an unlink/recreate replacement for owned output.
                identity_guard = os.dup(stream.fileno())
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
            try:
                destination_stat = destination.lstat()
                if (
                    destination_stat.st_dev,
                    destination_stat.st_ino,
                ) == installed_identity:
                    destination.unlink()
            except OSError:
                pass
            raise ValidationError(
                f"{field}: atomic publication aborted because staging cleanup "
                "failed; residual signed material requires removal: "
                f"{residual}"
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
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        try:
            if staged is not None:
                try:
                    staged.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    if not published:
                        raise ValidationError(
                            f"{field}: publication failed "
                            "and staging cleanup failed; residual signed approval "
                            f"requires removal: {staged}"
                        ) from error
                    # Publication has succeeded. Cleanup failure must not turn a
                    # durable no-clobber destination into a reported failure.
        finally:
            if identity_guard is not None:
                os.close(identity_guard)


def create_evaluation_authoring_approval(
    *,
    output_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    public_key_spki_sha256: str,
    private_key_password: bytes | None,
    audience: str,
    key_id: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    source_dataset_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    task_bindings_path: str | os.PathLike[str],
    now: datetime | None = None,
) -> VerifiedEvaluationAuthoringApproval:
    trust = EvaluationAuthoringApprovalTrust(
        public_key_path=Path(public_key_path),
        public_key_spki_sha256=public_key_spki_sha256,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    if (
        _identifier(actor_role, "evaluation-authoring approval actorRole")
        != signer_role
    ):
        _fail(
            "evaluation-authoring approval actorRole",
            "must match the trusted signer role",
        )
    inventory = derive_evaluation_authoring_inventory(
        source_dataset_path=source_dataset_path,
        calibration_tasks_path=calibration_tasks_path,
        sealed_tasks_path=sealed_tasks_path,
        task_bindings_path=task_bindings_path,
    )
    payload = _build_authoring_payload(
        inventory=inventory,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    current = _fresh_validation_time(
        now,
        "evaluation-authoring approval creation time",
    )
    _ensure_payload_active(payload, current, "evaluation-authoring approval payload")
    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    if private_spki != spki:
        _fail(
            "evaluation-authoring approval key pair",
            "private and externally pinned public keys differ",
        )
    payload_bytes = canonical_json_bytes(payload)
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
    envelope_raw = canonical_json_bytes(envelope)
    envelope_sha256 = hashlib.sha256(envelope_raw).hexdigest()
    _validate_envelope(
        envelope,
        path=Path(output_path),
        trust=trust,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )
    serialized = envelope_raw + b"\n"
    if len(serialized) > MAX_EVALUATION_AUTHORING_APPROVAL_BYTES:
        _fail("evaluation-authoring approval", "exceeds its byte limit")

    def validate_published(path: Path) -> VerifiedEvaluationAuthoringApproval:
        publication_time = _fresh_validation_time(
            now,
            "evaluation-authoring approval publication time",
        )
        return validate_evaluation_authoring_approval_for_inventory(
            path,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            source_dataset_path=source_dataset_path,
            calibration_tasks_path=calibration_tasks_path,
            sealed_tasks_path=sealed_tasks_path,
            task_bindings_path=task_bindings_path,
            now=publication_time,
        )

    verified = _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_published,
    )
    return replace(verified, path=Path(os.path.abspath(os.fspath(Path(output_path)))))


def prepare_evaluation_authoring_approval_signing_bundle(
    *,
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    source_dataset_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    task_bindings_path: str | os.PathLike[str],
    now: datetime | None = None,
) -> VerifiedEvaluationAuthoringApprovalSigningBundle:
    trust = EvaluationAuthoringApprovalTrust(
        public_key_path=Path(public_key_path),
        public_key_spki_sha256=public_key_spki_sha256,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    if (
        _identifier(actor_role, "evaluation-authoring approval actorRole")
        != signer_role
    ):
        _fail(
            "evaluation-authoring approval actorRole",
            "must match the trusted signer role",
        )
    inventory = derive_evaluation_authoring_inventory(
        source_dataset_path=source_dataset_path,
        calibration_tasks_path=calibration_tasks_path,
        sealed_tasks_path=sealed_tasks_path,
        task_bindings_path=task_bindings_path,
    )
    payload = _build_authoring_payload(
        inventory=inventory,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    current = _fresh_validation_time(
        now,
        "evaluation-authoring approval signing-bundle creation time",
    )
    _ensure_payload_active(
        payload, current, "evaluation-authoring approval signing bundle payload"
    )
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
        expected_inventory=inventory,
        now=current,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_BYTES:
        _fail("evaluation-authoring approval signing bundle", "exceeds its byte limit")
    bundle_sha256 = hashlib.sha256(serialized).hexdigest()

    def validate_published(
        path: Path,
    ) -> VerifiedEvaluationAuthoringApprovalSigningBundle:
        publication_time = _fresh_validation_time(
            now,
            "evaluation-authoring approval signing-bundle publication time",
        )
        resolved, raw, document = _read_canonical_handoff_document(
            path,
            "evaluation-authoring approval signing bundle",
            MAX_EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_BYTES,
        )
        if hashlib.sha256(raw).hexdigest() != bundle_sha256:
            _fail(
                "evaluation-authoring approval signing bundle",
                "changed during publication",
            )
        (
            _,
            publication_spki,
            publication_audience,
            publication_key_id,
            publication_role,
        ) = _validate_trust(trust)
        publication_inventory = derive_evaluation_authoring_inventory(
            source_dataset_path=source_dataset_path,
            calibration_tasks_path=calibration_tasks_path,
            sealed_tasks_path=sealed_tasks_path,
            task_bindings_path=task_bindings_path,
        )
        validated = _validate_signing_bundle_document(
            document,
            public_key_spki_sha256=publication_spki,
            audience=publication_audience,
            key_id=publication_key_id,
            signer_role=publication_role,
            expected_inventory=publication_inventory,
            now=publication_time,
        )
        return VerifiedEvaluationAuthoringApprovalSigningBundle(
            path=resolved,
            bundle=validated,
            bundle_sha256=bundle_sha256,
            bundle_id=validated["bundleId"],
            authoring_approval_id=validated["authoringApprovalId"],
            payload_sha256=validated["request"]["payloadSha256"],
            public_key_spki_sha256=publication_spki,
        )

    verified = _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_published,
        field="evaluation-authoring approval signing-bundle output",
    )
    return replace(verified, path=Path(os.path.abspath(os.fspath(Path(output_path)))))


def finalize_evaluation_authoring_approval(
    *,
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    source_dataset_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    task_bindings_path: str | os.PathLike[str],
    now: datetime | None = None,
) -> VerifiedEvaluationAuthoringApproval:
    trust = EvaluationAuthoringApprovalTrust(
        public_key_path=Path(public_key_path),
        public_key_spki_sha256=expected_public_key_spki_sha256,
        audience=expected_audience,
        key_id=expected_key_id,
        signer_role=expected_signer_role,
    )
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    current = _fresh_validation_time(
        now,
        "evaluation-authoring approval finalization time",
    )
    _, bundle_bytes, bundle_document = _read_canonical_handoff_document(
        signing_bundle_path,
        "evaluation-authoring approval signing bundle",
        MAX_EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_BYTES,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "evaluation-authoring approval external signature",
        MAX_EVALUATION_AUTHORING_APPROVAL_SIGNATURE_BYTES,
    )
    inventory = derive_evaluation_authoring_inventory(
        source_dataset_path=source_dataset_path,
        calibration_tasks_path=calibration_tasks_path,
        sealed_tasks_path=sealed_tasks_path,
        task_bindings_path=task_bindings_path,
    )
    bundle = _validate_signing_bundle_document(
        bundle_document,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        expected_inventory=inventory,
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
        "evaluation-authoring approval signing bundle.request.payload",
        MAX_EVALUATION_AUTHORING_APPROVAL_PAYLOAD_BYTES,
    )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    envelope["signature"] = _base64url_encode(signature)
    envelope_raw = canonical_json_bytes(envelope)
    envelope_sha256 = hashlib.sha256(envelope_raw).hexdigest()
    _validate_envelope(
        envelope,
        path=Path(output_path),
        trust=trust,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )
    serialized = envelope_raw + b"\n"
    if len(serialized) > MAX_EVALUATION_AUTHORING_APPROVAL_BYTES:
        _fail("evaluation-authoring approval", "exceeds its byte limit")

    def validate_published(path: Path) -> VerifiedEvaluationAuthoringApproval:
        publication_time = _fresh_validation_time(
            now,
            "evaluation-authoring approval finalization publication time",
        )
        return validate_evaluation_authoring_approval_for_inventory(
            path,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            source_dataset_path=source_dataset_path,
            calibration_tasks_path=calibration_tasks_path,
            sealed_tasks_path=sealed_tasks_path,
            task_bindings_path=task_bindings_path,
            now=publication_time,
        )

    verified = _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_published,
    )
    return replace(verified, path=Path(os.path.abspath(os.fspath(Path(output_path)))))


__all__ = [
    "EVALUATION_AUTHORING_APPROVAL_ALGORITHM",
    "EVALUATION_AUTHORING_APPROVAL_ENVELOPE_SCHEMA_VERSION",
    "EVALUATION_AUTHORING_APPROVAL_EXTERNAL_DER_SIGNATURE_FORMAT",
    "EVALUATION_AUTHORING_APPROVAL_EXTERNAL_P1363_SIGNATURE_FORMAT",
    "EVALUATION_AUTHORING_APPROVAL_SCHEMA_VERSION",
    "EVALUATION_AUTHORING_APPROVAL_SIGNATURE_SCHEMA_VERSION",
    "EVALUATION_AUTHORING_APPROVAL_SIGNING_BUNDLE_SCHEMA_VERSION",
    "EVALUATION_AUTHORING_APPROVAL_SCOPE",
    "EvaluationAuthoringApprovalTrust",
    "VerifiedEvaluationAuthoringApproval",
    "VerifiedEvaluationAuthoringApprovalSigningBundle",
    "create_evaluation_authoring_approval",
    "derive_evaluation_authoring_inventory",
    "ensure_evaluation_authoring_approval_active",
    "evaluation_authoring_approval_id",
    "evaluation_authoring_approval_signature_id",
    "evaluation_authoring_approval_signing_bundle_id",
    "finalize_evaluation_authoring_approval",
    "prepare_evaluation_authoring_approval_signing_bundle",
    "validate_evaluation_authoring_approval",
    "validate_evaluation_authoring_approval_for_inventory",
]
