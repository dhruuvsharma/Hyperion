from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .core import (
    ValidationError,
    _exact_keys,
    _fail,
    _sha256,
    _string,
    _validate_data_release_identity,
    canonical_json_bytes,
    sha256_file,
)
from .evaluation import (
    EVALUATION_RESPONSE_SCHEMA_VERSION,
    MAX_EVALUATION_BYTES,
    BaseResponseAttestationTrust,
    EvaluationTaskSet,
    _run_identity_from_response,
    _validate_run_identity,
    _validate_promotion_response_attestations,
    evaluation_response_set_sha256,
    validate_evaluation_responses,
    validate_evaluation_tasks,
    validate_verifier_results,
    verifier_result_set_sha256,
)
from .evaluation_authoring import EvaluationAuthoringApprovalTrust
from .review_receipts import ExpertModelReviewReceiptTrust
from .verifier_authority import (
    SOURCE_PROFILE as CSHARP_SOURCE_PROFILE,
    _base64url_decode,
    _base64url_encode,
    _bounded_snapshot,
    _canonical_document,
    _content_addressed_id,
    _load_private_key,
    _load_public_key,
    _normalize_external_signature,
    _read_canonical_handoff_document,
    _sign_p1363_low_s,
    _verify_p1363_low_s,
    _write_no_clobber as _write_owned_no_clobber,
)
from .verifier_runtime import (
    CSharpVerifierExecutionContext,
    ReleaseVerifierPlan,
    bind_csharp_verifier_execution_context,
    derive_release_verifier_plan,
    execute_release_verifiers,
)


AUDIT_SCHEMA_VERSION = "daxalgo.vibe-quant.csharp-verifier-replay-audit/v1"
AUDIT_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.csharp-verifier-replay-audit-envelope/v1"
)
AUDIT_SCOPE = "trained-adapter-promotion-replay-only"
AUDIT_DECISION = "verified"
AUDIT_PAYLOAD_ENCODING = "canonical-json-base64url"
AUDIT_ALGORITHM = "ES256"
AUDIT_SIGNATURE_FORMAT = "ieee-p1363-low-s"
AUDIT_ID_PREFIX = "daxalgo-csharp-verifier-replay-audit-sha256-"
AUDIT_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.csharp-verifier-replay-audit-signing-bundle/v1"
)
AUDIT_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.vibe-quant.csharp-verifier-replay-audit-signature/v1"
)
AUDIT_SIGNING_BUNDLE_ID_PREFIX = (
    "daxalgo-csharp-verifier-replay-audit-signing-bundle-sha256-"
)
AUDIT_EXTERNAL_SIGNATURE_ID_PREFIX = (
    "daxalgo-csharp-verifier-replay-audit-signature-sha256-"
)
AUDIT_SIGNING_STATUS = "unsigned-non-authorizing"
AUDIT_SIGNING_HASH_ALGORITHM = "SHA-256"
AUDIT_EXTERNAL_RAW_MESSAGE_MODE = "raw-message"
AUDIT_EXTERNAL_SHA256_DIGEST_MODE = "sha256-digest"
AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
AUDIT_STATEMENT = (
    "This signed audit authenticates one exact offline candidate-and-baseline C# "
    "verifier replay. It grants no review, release, training, base-selection, "
    "promotion-decision, deployment, hosted-serving, installation, or strategy "
    "execution authority."
)

MAX_AUDIT_BYTES = 1_000_000
MAX_AUDIT_PAYLOAD_BYTES = 750_000
MAX_AUDIT_SIGNING_BUNDLE_BYTES = 4_000_000
MAX_AUDIT_EXTERNAL_SIGNATURE_BYTES = 16_000
MAX_AUDIT_SIGNATURE_INPUT_BYTES = 1_000_000
MAX_AUDIT_VALIDITY = timedelta(days=366)
_ZERO_SHA256 = "0" * 64
_SIGNATURE_DOMAIN = b"daxalgo-csharp-verifier-replay-audit-signature/v1\x00"
_ID_DOMAIN = b"daxalgo-csharp-verifier-replay-audit-id/v1\x00"
_SIGNING_BUNDLE_ID_DOMAIN = (
    b"daxalgo-csharp-verifier-replay-audit-signing-bundle-id/v1\x00"
)
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    b"daxalgo-csharp-verifier-replay-audit-external-signature-id/v1\x00"
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SIGNING_AUTHORITY_KEYS = {
    "baseSelection",
    "csharpVerifierReplayAuditIssuance",
    "deployment",
    "hostedServing",
    "installation",
    "promotionDecision",
    "release",
    "review",
    "strategyExecution",
    "training",
    "verifierExecution",
}
_SIGNING_BUNDLE_KEYS = {
    "schemaVersion",
    "bundleId",
    "status",
    "authority",
    "trust",
    "auditId",
    "payloadSha256",
    "payload",
    "unsignedEnvelopeSha256",
    "unsignedEnvelope",
    "validity",
    "signatureContract",
    "request",
}
_EXTERNAL_SIGNATURE_KEYS = {
    "schemaVersion",
    "signatureId",
    "signingBundleId",
    "signingBundleSha256",
    "auditId",
    "payloadSha256",
    "unsignedEnvelopeSha256",
    "signatureInputSha256",
    "publicKeySpkiSha256",
    "mode",
    "format",
    "signature",
}


@dataclass(frozen=True)
class CSharpVerifierReplayAuditTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str


@dataclass(frozen=True)
class VerifiedCSharpVerifierReplayAudit:
    path: Path
    payload: dict[str, Any]
    payload_sha256: str
    envelope_sha256: str
    public_key_spki_sha256: str
    not_before_utc: datetime
    expires_at_utc: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "auditId": self.payload["auditId"],
            "payloadSha256": self.payload_sha256,
            "envelopeSha256": self.envelope_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "notBeforeUtc": self.payload["notBeforeUtc"],
            "expiresAtUtc": self.payload["expiresAtUtc"],
        }


@dataclass(frozen=True)
class VerifiedCSharpVerifierReplayAuditSigningBundle:
    path: Path
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    unsigned_envelope: dict[str, Any]
    unsigned_envelope_sha256: str
    signature_preimage: bytes
    signature_input_sha256: str
    public_key_spki_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundleId": self.bundle_id,
            "bundleSha256": self.bundle_sha256,
            "auditId": self.payload["auditId"],
            "payloadSha256": self.payload_sha256,
            "unsignedEnvelopeSha256": self.unsigned_envelope_sha256,
            "signatureInputSha256": self.signature_input_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
        }


@dataclass(frozen=True)
class _ReplayAuditBuild:
    payload: dict[str, Any]
    release_identity: dict[str, str]
    receipt_expires_at_utc: str
    authoring_approval_expires_at_utc: str
    sealed_tasks: EvaluationTaskSet
    plan: ReleaseVerifierPlan
    candidate_responses: tuple[dict[str, Any], ...]
    candidate_results: tuple[dict[str, Any], ...]
    baseline_responses: tuple[dict[str, Any], ...]
    baseline_results: tuple[dict[str, Any], ...]


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=128)
    if not _IDENTIFIER_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _canonical_utc(value: Any, field: str) -> datetime:
    text = _string(value, field, max_length=20)
    if len(text) != 20 or not text.endswith("Z"):
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
    value = bytearray()
    for field in fields:
        raw = field if isinstance(field, bytes) else field.encode("utf-8")
        value.extend(len(raw).to_bytes(8, "big", signed=False))
        value.extend(raw)
    return bytes(value)


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
        "schemaVersion": AUDIT_ENVELOPE_SCHEMA_VERSION,
        "payloadType": AUDIT_SCHEMA_VERSION,
        "payloadEncoding": AUDIT_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": AUDIT_ALGORITHM,
        "signatureFormat": AUDIT_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


def csharp_verifier_replay_audit_signing_bundle_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=AUDIT_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def csharp_verifier_replay_audit_external_signature_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=AUDIT_EXTERNAL_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


def _validate_trust(
    trust: CSharpVerifierReplayAuditTrust,
) -> tuple[Any, str, str, str, str]:
    if not isinstance(trust, CSharpVerifierReplayAuditTrust):
        _fail("C# verifier replay-audit trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(Path(trust.public_key_path))
    expected_spki = _sha256(
        trust.public_key_spki_sha256,
        "C# verifier replay-audit trust.publicKeySpkiSha256",
    )
    if actual_spki != expected_spki:
        _fail(
            "C# verifier replay-audit trust.publicKeySpkiSha256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "C# verifier replay-audit trust.audience"),
        _identifier(trust.key_id, "C# verifier replay-audit trust.keyId"),
        _identifier(trust.signer_role, "C# verifier replay-audit trust.signerRole"),
    )


def _require_distinct_evaluation_authoring_signer(
    replay_audit_spki: str,
    trust: EvaluationAuthoringApprovalTrust,
) -> None:
    if not isinstance(trust, EvaluationAuthoringApprovalTrust):
        _fail(
            "evaluation-authoring approval trust",
            "must be externally supplied for replay-audit evidence",
        )
    authoring_spki = _sha256(
        trust.public_key_spki_sha256,
        "evaluation-authoring approval trust.publicKeySpkiSha256",
    )
    if replay_audit_spki == authoring_spki:
        _fail(
            "C# verifier replay-audit signer",
            "must differ from the evaluation-authoring approval signer",
        )


def _validate_task_binding(value: Any, field: str) -> dict[str, Any]:
    binding = _exact_keys(
        value,
        {"taskId", "taskSha256", "verifierId", "verifierSha256"},
        field,
    )
    _identifier(binding["taskId"], f"{field}.taskId")
    _sha256(binding["taskSha256"], f"{field}.taskSha256")
    _identifier(binding["verifierId"], f"{field}.verifierId")
    _sha256(binding["verifierSha256"], f"{field}.verifierSha256")
    return binding


def _validate_task_evidence(value: Any, field: str) -> dict[str, Any]:
    evidence = _exact_keys(
        value,
        {"taskId", "responseSha256", "resultSha256"},
        field,
    )
    _identifier(evidence["taskId"], f"{field}.taskId")
    _sha256(evidence["responseSha256"], f"{field}.responseSha256")
    _sha256(evidence["resultSha256"], f"{field}.resultSha256")
    return evidence


def _validate_run(value: Any, field: str) -> dict[str, Any]:
    run = _exact_keys(
        value,
        {
            "identity",
            "responsesFileSha256",
            "responseSetSha256",
            "verifierResultsFileSha256",
            "verifierResultSetSha256",
            "csharpTasks",
        },
        field,
    )
    identity = run["identity"]
    _validate_run_identity(identity, f"{field}.identity")
    for name in (
        "responsesFileSha256",
        "responseSetSha256",
        "verifierResultsFileSha256",
        "verifierResultSetSha256",
    ):
        _sha256(run[name], f"{field}.{name}")
    rows = run["csharpTasks"]
    if not isinstance(rows, list) or not rows:
        _fail(f"{field}.csharpTasks", "must be a non-empty array")
    validated = [
        _validate_task_evidence(row, f"{field}.csharpTasks[{index}]")
        for index, row in enumerate(rows)
    ]
    task_ids = [row["taskId"] for row in validated]
    if task_ids != sorted(task_ids) or len(task_ids) != len(set(task_ids)):
        _fail(f"{field}.csharpTasks", "must be unique and sorted by taskId")
    return run


def csharp_verifier_replay_audit_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["auditId"] = AUDIT_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(_ID_DOMAIN + canonical_json_bytes(normalized)).hexdigest()
    return AUDIT_ID_PREFIX + digest


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _exact_keys(
        value,
        {
            "schemaVersion",
            "auditId",
            "decision",
            "scope",
            "reusable",
            "reviewAuthorized",
            "releaseAuthorized",
            "trainingAuthorized",
            "baseSelectionAuthorized",
            "promotionDecisionAuthorized",
            "deploymentAuthorized",
            "hostedServingAuthorized",
            "installationAuthorized",
            "issuedAtUtc",
            "notBeforeUtc",
            "expiresAtUtc",
            "replayCompletedAtUtc",
            "dataRelease",
            "sealedTasksFileSha256",
            "sealedTaskSetSha256",
            "csharpVerifierConfigurationSha256",
            "csharpTaskBindings",
            "candidate",
            "baseline",
            "approval",
            "statement",
        },
        "C# verifier replay-audit payload",
    )
    constants = {
        "schemaVersion": AUDIT_SCHEMA_VERSION,
        "decision": AUDIT_DECISION,
        "scope": AUDIT_SCOPE,
        "reusable": True,
        "reviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "baseSelectionAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "statement": AUDIT_STATEMENT,
    }
    for name, expected in constants.items():
        supplied = payload[name]
        if (
            type(expected) is bool
            and (type(supplied) is not bool or supplied is not expected)
        ) or (type(expected) is not bool and supplied != expected):
            _fail(
                f"C# verifier replay-audit payload.{name}",
                "does not match the contract",
            )
    _validate_data_release_identity(
        payload["dataRelease"],
        "C# verifier replay-audit payload.dataRelease",
        allow_none=False,
    )
    _sha256(
        payload["sealedTasksFileSha256"],
        "C# verifier replay-audit payload.sealedTasksFileSha256",
    )
    _sha256(
        payload["sealedTaskSetSha256"],
        "C# verifier replay-audit payload.sealedTaskSetSha256",
    )
    _sha256(
        payload["csharpVerifierConfigurationSha256"],
        "C# verifier replay-audit payload.csharpVerifierConfigurationSha256",
    )
    bindings = payload["csharpTaskBindings"]
    if not isinstance(bindings, list) or not bindings:
        _fail(
            "C# verifier replay-audit payload.csharpTaskBindings",
            "must be a non-empty array",
        )
    validated_bindings = [
        _validate_task_binding(
            binding,
            f"C# verifier replay-audit payload.csharpTaskBindings[{index}]",
        )
        for index, binding in enumerate(bindings)
    ]
    binding_ids = [binding["taskId"] for binding in validated_bindings]
    if binding_ids != sorted(binding_ids) or len(binding_ids) != len(set(binding_ids)):
        _fail(
            "C# verifier replay-audit payload.csharpTaskBindings",
            "must be unique and sorted by taskId",
        )
    candidate = _validate_run(
        payload["candidate"], "C# verifier replay-audit payload.candidate"
    )
    baseline = _validate_run(
        payload["baseline"], "C# verifier replay-audit payload.baseline"
    )
    if (
        candidate["identity"].get("responseSchemaVersion")
        != EVALUATION_RESPONSE_SCHEMA_VERSION
    ):
        _fail(
            "C# verifier replay-audit payload.candidate.identity.responseSchemaVersion",
            "must remain response v1 for a trained-adapter promotion candidate",
        )
    if candidate["identity"].get("targetKind") != "trained-adapter":
        _fail(
            "C# verifier replay-audit payload.candidate.identity.targetKind",
            "must be trained-adapter",
        )
    if baseline["identity"] == candidate["identity"]:
        _fail("C# verifier replay-audit payload.baseline.identity", "must be distinct")
    for name, run in (("candidate", candidate), ("baseline", baseline)):
        run_ids = [row["taskId"] for row in run["csharpTasks"]]
        if run_ids != binding_ids:
            _fail(
                f"C# verifier replay-audit payload.{name}.csharpTasks",
                "must cover every bound C# task exactly once",
            )
    issued = _canonical_utc(
        payload["issuedAtUtc"], "C# verifier replay-audit payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "C# verifier replay-audit payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "C# verifier replay-audit payload.expiresAtUtc"
    )
    replayed = _canonical_utc(
        payload["replayCompletedAtUtc"],
        "C# verifier replay-audit payload.replayCompletedAtUtc",
    )
    if (
        issued > not_before
        or not_before >= expires
        or expires - not_before > MAX_AUDIT_VALIDITY
    ):
        _fail(
            "C# verifier replay-audit payload validity", "has an invalid bounded window"
        )
    if replayed > issued:
        _fail(
            "C# verifier replay-audit payload.replayCompletedAtUtc",
            "must not follow issuance",
        )
    approval = _exact_keys(
        payload["approval"],
        {"approvalId", "actorId", "actorRole", "reference", "approvedAtUtc"},
        "C# verifier replay-audit payload.approval",
    )
    for name in ("approvalId", "actorId", "actorRole"):
        _identifier(approval[name], f"C# verifier replay-audit payload.approval.{name}")
    _string(
        approval["reference"],
        "C# verifier replay-audit payload.approval.reference",
        max_length=500,
    )
    approved = _canonical_utc(
        approval["approvedAtUtc"],
        "C# verifier replay-audit payload.approval.approvedAtUtc",
    )
    if replayed > approved or approved > issued:
        _fail(
            "C# verifier replay-audit approval timeline",
            "must satisfy replayCompletedAt <= approvedAt <= issuedAt <= notBeforeUtc",
        )
    expected_id = csharp_verifier_replay_audit_id(payload)
    if payload["auditId"] != expected_id:
        _fail("C# verifier replay-audit payload.auditId", "does not match its content")
    return payload


def _expected_csharp_bindings(plan: ReleaseVerifierPlan) -> list[dict[str, Any]]:
    if not isinstance(plan, ReleaseVerifierPlan):
        _fail("release verifier plan", "must be fully validated")
    bindings = [
        {
            "taskId": task["taskId"],
            "taskSha256": task["taskSha256"],
            "verifierId": task["verifierId"],
            "verifierSha256": task["verifierSha256"],
        }
        for task in plan.document["tasks"]
        if task["profile"] == CSHARP_SOURCE_PROFILE
    ]
    if not bindings:
        _fail("C# verifier replay audit", "requires at least one C# verifier task")
    return bindings


def _expected_run(
    *,
    responses_path: str | os.PathLike[str],
    results_path: str | os.PathLike[str],
    responses: tuple[dict[str, Any], ...],
    results: tuple[dict[str, Any], ...],
    csharp_task_ids: set[str],
) -> dict[str, Any]:
    response_by_task = {row["taskId"]: row for row in responses}
    result_by_task = {row["taskId"]: row for row in results}
    return {
        "identity": _run_identity_from_response(responses[0]),
        "responsesFileSha256": sha256_file(
            responses_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "responseSetSha256": evaluation_response_set_sha256(responses),
        "verifierResultsFileSha256": sha256_file(
            results_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "verifierResultSetSha256": verifier_result_set_sha256(results),
        "csharpTasks": [
            {
                "taskId": task_id,
                "responseSha256": response_by_task[task_id]["responseSha256"],
                "resultSha256": result_by_task[task_id]["resultSha256"],
            }
            for task_id in sorted(csharp_task_ids)
        ],
    }


def expected_csharp_verifier_replay_binding(
    *,
    release_identity: Mapping[str, str],
    sealed_tasks: EvaluationTaskSet,
    plan: ReleaseVerifierPlan,
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    candidate_responses: tuple[dict[str, Any], ...],
    candidate_results: tuple[dict[str, Any], ...],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    baseline_responses: tuple[dict[str, Any], ...],
    baseline_results: tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    bindings = _expected_csharp_bindings(plan)
    task_ids = {binding["taskId"] for binding in bindings}
    return {
        "dataRelease": dict(release_identity),
        "sealedTasksFileSha256": sealed_tasks.sha256,
        "sealedTaskSetSha256": sealed_tasks.task_set_sha256,
        "csharpTaskBindings": bindings,
        "candidate": _expected_run(
            responses_path=candidate_responses_path,
            results_path=candidate_results_path,
            responses=candidate_responses,
            results=candidate_results,
            csharp_task_ids=task_ids,
        ),
        "baseline": _expected_run(
            responses_path=baseline_responses_path,
            results_path=baseline_results_path,
            responses=baseline_responses,
            results=baseline_results,
            csharp_task_ids=task_ids,
        ),
    }


def _validate_envelope(
    value: Any,
    *,
    trust: CSharpVerifierReplayAuditTrust,
    expected_envelope_sha256: str,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
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
        "C# verifier replay-audit envelope",
    )
    constants = {
        "schemaVersion": AUDIT_ENVELOPE_SCHEMA_VERSION,
        "payloadType": AUDIT_SCHEMA_VERSION,
        "payloadEncoding": AUDIT_PAYLOAD_ENCODING,
        "algorithm": AUDIT_ALGORITHM,
        "signatureFormat": AUDIT_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(
                f"C# verifier replay-audit envelope.{name}",
                "does not match trusted configuration",
            )
    envelope_sha256 = hashlib.sha256(canonical_json_bytes(envelope)).hexdigest()
    if (
        _sha256(
            expected_envelope_sha256,
            "expected C# verifier replay-audit envelope SHA-256",
        )
        != envelope_sha256
    ):
        _fail(
            "C# verifier replay-audit envelope",
            "does not match the trusted exact SHA-256",
        )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "C# verifier replay-audit envelope.payload",
        MAX_AUDIT_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            envelope["payloadSha256"], "C# verifier replay-audit envelope.payloadSha256"
        )
        != payload_sha256
    ):
        _fail(
            "C# verifier replay-audit envelope.payloadSha256",
            "does not match exact payload bytes",
        )
    try:
        payload_value = json.loads(
            payload_bytes, object_pairs_hook=_unique_object_pairs
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise ValidationError(
            f"C# verifier replay-audit payload: invalid JSON: {error}"
        ) from error
    if not isinstance(payload_value, dict) or payload_bytes != canonical_json_bytes(
        payload_value
    ):
        _fail("C# verifier replay-audit payload", "must be exact canonical JSON")
    payload = _validate_payload(payload_value)
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "C# verifier replay-audit payload.approval.actorRole",
            "must match trusted signer role",
        )
    signature = _base64url_decode(
        envelope["signature"], "C# verifier replay-audit envelope.signature", 64
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "C# verifier replay-audit payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "C# verifier replay-audit payload.expiresAtUtc"
    )
    if now < not_before or now >= expires:
        _fail("C# verifier replay-audit payload validity", "is not active")
    return envelope, payload, payload_bytes, envelope_sha256


def _unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _validate_csharp_verifier_replay_audit(
    path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierReplayAuditTrust,
    expected_envelope_sha256: str,
    now: datetime | None = None,
    expected_link_count: int,
) -> VerifiedCSharpVerifierReplayAudit:
    current = _fresh_validation_time(now, "C# verifier replay-audit validation time")
    audit_path = Path(path)
    raw = _bounded_snapshot(
        audit_path,
        "C# verifier replay audit",
        MAX_AUDIT_BYTES,
        expected_link_count=expected_link_count,
    )
    envelope = _canonical_document(raw, "C# verifier replay audit")
    envelope, payload, payload_bytes, envelope_sha256 = _validate_envelope(
        envelope,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=current,
    )
    return VerifiedCSharpVerifierReplayAudit(
        path=Path(os.path.abspath(os.fspath(audit_path))),
        payload=payload,
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        envelope_sha256=envelope_sha256,
        public_key_spki_sha256=envelope["publicKeySpkiSha256"],
        not_before_utc=_canonical_utc(
            payload["notBeforeUtc"], "C# verifier replay-audit payload.notBeforeUtc"
        ),
        expires_at_utc=_canonical_utc(
            payload["expiresAtUtc"], "C# verifier replay-audit payload.expiresAtUtc"
        ),
    )


def validate_csharp_verifier_replay_audit(
    path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierReplayAuditTrust,
    expected_envelope_sha256: str,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierReplayAudit:
    return _validate_csharp_verifier_replay_audit(
        path,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=now,
        expected_link_count=1,
    )


def validate_csharp_verifier_replay_audit_for_evidence(
    path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierReplayAuditTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    expected_envelope_sha256: str,
    release_identity: Mapping[str, str],
    receipt_expires_at_utc: str,
    authoring_approval_expires_at_utc: str,
    sealed_tasks: EvaluationTaskSet,
    plan: ReleaseVerifierPlan,
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    candidate_responses: tuple[dict[str, Any], ...],
    candidate_results: tuple[dict[str, Any], ...],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    baseline_responses: tuple[dict[str, Any], ...],
    baseline_results: tuple[dict[str, Any], ...],
    now: datetime | None = None,
) -> VerifiedCSharpVerifierReplayAudit:
    verified = validate_csharp_verifier_replay_audit(
        path,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=now,
    )
    _require_distinct_evaluation_authoring_signer(
        verified.public_key_spki_sha256,
        evaluation_authoring_approval_trust,
    )
    expected = expected_csharp_verifier_replay_binding(
        release_identity=release_identity,
        sealed_tasks=sealed_tasks,
        plan=plan,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        candidate_responses=candidate_responses,
        candidate_results=candidate_results,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        baseline_responses=baseline_responses,
        baseline_results=baseline_results,
    )
    for name, expected_value in expected.items():
        if verified.payload[name] != expected_value:
            _fail(
                f"C# verifier replay-audit payload.{name}",
                "does not match the exact live evidence",
            )
    receipt_expiry = _canonical_utc(
        receipt_expires_at_utc, "review-receipt authority expiry"
    )
    authoring_expiry = _canonical_utc(
        authoring_approval_expires_at_utc,
        "evaluation-authoring approval authority expiry",
    )
    if verified.expires_at_utc > min(receipt_expiry, authoring_expiry):
        _fail(
            "C# verifier replay-audit payload.expiresAtUtc",
            "must not outlive release review and evaluation-authoring authorities",
        )
    return verified


def _build_replay_audit_payload(
    *,
    replay_audit_spki: str,
    signer_role: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    replay_completed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None,
    review_receipt_now: datetime | None,
    now: datetime | None,
) -> _ReplayAuditBuild:
    from .release import (
        TRAINING_PURPOSES,
        validate_corpus_evaluation_release_with_identity,
        validate_release_evaluation_task_set,
    )

    if _identifier(actor_role, "C# verifier replay-audit actorRole") != signer_role:
        _fail("C# verifier replay-audit actorRole", "must match trusted signer role")
    bound_context = bind_csharp_verifier_execution_context(csharp_verifier_context)
    if replay_audit_spki == bound_context.authority_trust.public_key_spki_sha256:
        _fail(
            "C# verifier replay-audit signer",
            "must differ from the executable-verifier authority signer",
        )
    _require_distinct_evaluation_authoring_signer(
        replay_audit_spki,
        evaluation_authoring_approval_trust,
    )
    source_paths = {
        "sealed tasks": sealed_tasks_path,
        "candidate responses": candidate_responses_path,
        "candidate verifier results": candidate_results_path,
        "baseline responses": baseline_responses_path,
        "baseline verifier results": baseline_results_path,
    }
    source_hashes = {
        name: sha256_file(path, max_bytes=MAX_EVALUATION_BYTES)
        for name, path in source_paths.items()
    }
    sealed = validate_evaluation_tasks(sealed_tasks_path)
    if any(task["split"] != "sealed" for task in sealed.records):
        _fail("sealed task set", "may contain only sealed tasks")
    release, release_identity = validate_corpus_evaluation_release_with_identity(
        data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        now=review_receipt_now,
    )
    if release["purpose"] not in TRAINING_PURPOSES:
        _fail(
            "release.purpose",
            "must authorize training and evaluation for a promotion replay audit",
        )
    validate_release_evaluation_task_set(release, sealed)
    plan = derive_release_verifier_plan(
        release_path=data_release_path, release=release, tasks=sealed
    )
    _expected_csharp_bindings(plan)
    candidate_responses = validate_evaluation_responses(
        candidate_responses_path, sealed
    )
    baseline_responses = validate_evaluation_responses(baseline_responses_path, sealed)
    for label, responses, attestation_trust in (
        ("candidate responses", candidate_responses, candidate_attestation_trust),
        ("baseline responses", baseline_responses, baseline_attestation_trust),
    ):
        _validate_promotion_response_attestations(
            label, responses, sealed, attestation_trust
        )
        for response in responses:
            if (
                response["dataRelease"] != release_identity
                or response["researchOnly"] is not False
                or response["evidenceStatus"] != "release-bound"
            ):
                _fail(label, "must be bound to the exact validated release")
    candidate_results = validate_verifier_results(
        candidate_results_path, sealed, candidate_responses
    )
    baseline_results = validate_verifier_results(
        baseline_results_path, sealed, baseline_responses
    )
    if tuple(candidate_results) != execute_release_verifiers(
        release_path=data_release_path,
        release=release,
        release_identity=release_identity,
        tasks=sealed,
        responses=candidate_responses,
        csharp_context=bound_context,
    ):
        _fail("candidate verifier results", "do not match fresh full-suite replay")
    if tuple(baseline_results) != execute_release_verifiers(
        release_path=data_release_path,
        release=release,
        release_identity=release_identity,
        tasks=sealed,
        responses=baseline_responses,
        csharp_context=bound_context,
    ):
        _fail("baseline verifier results", "do not match fresh full-suite replay")
    current_release, current_identity = (
        validate_corpus_evaluation_release_with_identity(
            data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            now=review_receipt_now,
        )
    )
    if current_release != release or current_identity != release_identity:
        _fail("evaluation release", "changed during C# verifier replay audit")
    binding = expected_csharp_verifier_replay_binding(
        release_identity=release_identity,
        sealed_tasks=sealed,
        plan=plan,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        candidate_responses=candidate_responses,
        candidate_results=candidate_results,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        baseline_responses=baseline_responses,
        baseline_results=baseline_results,
    )
    for name, path in source_paths.items():
        if sha256_file(path, max_bytes=MAX_EVALUATION_BYTES) != source_hashes[name]:
            _fail(name, "changed during C# verifier replay-audit creation")
    payload: dict[str, Any] = {
        "schemaVersion": AUDIT_SCHEMA_VERSION,
        "auditId": AUDIT_ID_PREFIX + _ZERO_SHA256,
        "decision": AUDIT_DECISION,
        "scope": AUDIT_SCOPE,
        "reusable": True,
        "reviewAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "baseSelectionAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "replayCompletedAtUtc": replay_completed_at_utc,
        **binding,
        "csharpVerifierConfigurationSha256": bound_context.verifier_configuration_sha256,
        "approval": {
            "approvalId": approval_id,
            "actorId": actor_id,
            "actorRole": actor_role,
            "reference": approval_reference,
            "approvedAtUtc": approved_at_utc,
        },
        "statement": AUDIT_STATEMENT,
    }
    payload["auditId"] = csharp_verifier_replay_audit_id(payload)
    payload = _validate_payload(payload)
    receipt_expiry = _canonical_utc(
        release["corpus"]["reviewReceipts"]["expiresAtUtc"],
        "review-receipt authority expiry",
    )
    authoring_expiry = _canonical_utc(
        release["evaluation"]["authoringApproval"]["expiresAtUtc"],
        "evaluation-authoring approval authority expiry",
    )
    if _canonical_utc(
        payload["expiresAtUtc"], "C# verifier replay-audit payload.expiresAtUtc"
    ) > min(receipt_expiry, authoring_expiry):
        _fail(
            "C# verifier replay-audit payload.expiresAtUtc",
            "must not outlive release review and evaluation-authoring authorities",
        )
    current = _fresh_validation_time(now, "C# verifier replay-audit creation time")
    if current < _canonical_utc(
        payload["notBeforeUtc"], "C# verifier replay-audit payload.notBeforeUtc"
    ) or current >= _canonical_utc(
        payload["expiresAtUtc"], "C# verifier replay-audit payload.expiresAtUtc"
    ):
        _fail(
            "C# verifier replay-audit payload validity", "must be active when created"
        )
    return _ReplayAuditBuild(
        payload=payload,
        release_identity=dict(release_identity),
        receipt_expires_at_utc=release["corpus"]["reviewReceipts"]["expiresAtUtc"],
        authoring_approval_expires_at_utc=release["evaluation"]["authoringApproval"][
            "expiresAtUtc"
        ],
        sealed_tasks=sealed,
        plan=plan,
        candidate_responses=tuple(candidate_responses),
        candidate_results=tuple(candidate_results),
        baseline_responses=tuple(baseline_responses),
        baseline_results=tuple(baseline_results),
    )


def _rebuild_replay_audit_payload(
    payload: Mapping[str, Any],
    *,
    replay_audit_spki: str,
    signer_role: str,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None,
    review_receipt_now: datetime | None,
    now: datetime | None,
) -> _ReplayAuditBuild:
    validated = _validate_payload(dict(payload))
    approval = validated["approval"]
    return _build_replay_audit_payload(
        replay_audit_spki=replay_audit_spki,
        signer_role=signer_role,
        approval_id=approval["approvalId"],
        actor_id=approval["actorId"],
        actor_role=approval["actorRole"],
        approval_reference=approval["reference"],
        approved_at_utc=approval["approvedAtUtc"],
        replay_completed_at_utc=validated["replayCompletedAtUtc"],
        issued_at_utc=validated["issuedAtUtc"],
        not_before_utc=validated["notBeforeUtc"],
        expires_at_utc=validated["expiresAtUtc"],
        sealed_tasks_path=sealed_tasks_path,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        csharp_verifier_context=csharp_verifier_context,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        review_receipt_now=review_receipt_now,
        now=now,
    )


def _build_signing_bundle_document(
    payload: Mapping[str, Any],
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    payload_document = _validate_payload(dict(payload))
    payload_bytes = canonical_json_bytes(payload_document)
    if len(payload_bytes) > MAX_AUDIT_PAYLOAD_BYTES:
        _fail("C# verifier replay-audit payload", "exceeds its byte limit")
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    envelope_bytes = canonical_json_bytes(envelope)
    final_envelope = dict(envelope)
    final_envelope["signature"] = _base64url_encode(b"\0" * 64)
    if len(canonical_json_bytes(final_envelope)) + 1 > MAX_AUDIT_BYTES:
        _fail("C# verifier replay-audit signed envelope", "exceeds its byte limit")
    signature_preimage = _signature_input(envelope, payload_bytes)
    if len(signature_preimage) > MAX_AUDIT_SIGNATURE_INPUT_BYTES:
        _fail("C# verifier replay-audit signature preimage", "exceeds its byte limit")
    signature_digest = hashlib.sha256(signature_preimage).digest()
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    unsigned_envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    bundle: dict[str, Any] = {
        "schemaVersion": AUDIT_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": AUDIT_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": AUDIT_SIGNING_STATUS,
        "authority": {name: False for name in sorted(_SIGNING_AUTHORITY_KEYS)},
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": audience,
            "keyId": key_id,
            "signerRole": signer_role,
        },
        "auditId": payload_document["auditId"],
        "payloadSha256": payload_sha256,
        "payload": _base64url_encode(payload_bytes),
        "unsignedEnvelopeSha256": unsigned_envelope_sha256,
        "unsignedEnvelope": _base64url_encode(envelope_bytes),
        "validity": {
            "replayCompletedAtUtc": payload_document["replayCompletedAtUtc"],
            "approvedAtUtc": payload_document["approval"]["approvedAtUtc"],
            "issuedAtUtc": payload_document["issuedAtUtc"],
            "notBeforeUtc": payload_document["notBeforeUtc"],
            "expiresAtUtc": payload_document["expiresAtUtc"],
        },
        "signatureContract": {
            "algorithm": AUDIT_ALGORITHM,
            "hashAlgorithm": AUDIT_SIGNING_HASH_ALGORITHM,
            "inputEncoding": "base64url",
            "acceptedModes": [
                AUDIT_EXTERNAL_RAW_MESSAGE_MODE,
                AUDIT_EXTERNAL_SHA256_DIGEST_MODE,
            ],
            "acceptedSignatureFormats": [
                AUDIT_EXTERNAL_DER_SIGNATURE_FORMAT,
                AUDIT_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "auditId": payload_document["auditId"],
            "payloadSha256": payload_sha256,
            "unsignedEnvelopeSha256": unsigned_envelope_sha256,
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = csharp_verifier_replay_audit_signing_bundle_id(bundle)
    return bundle


def _preflight_signing_bundle_payload(
    value: Mapping[str, Any],
    *,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
) -> dict[str, Any]:
    bundle = _exact_keys(
        value, _SIGNING_BUNDLE_KEYS, "C# verifier replay-audit signing bundle"
    )
    if bundle["schemaVersion"] != AUDIT_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("C# verifier replay-audit signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != AUDIT_SIGNING_STATUS:
        _fail(
            "C# verifier replay-audit signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority = _exact_keys(
        bundle["authority"],
        _SIGNING_AUTHORITY_KEYS,
        "C# verifier replay-audit signing bundle.authority",
    )
    if any(type(value) is not bool or value for value in authority.values()):
        _fail(
            "C# verifier replay-audit signing bundle.authority",
            "must contain only false non-authorizing flags",
        )
    expected_trust = {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }
    if (
        _exact_keys(
            bundle["trust"],
            {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
            "C# verifier replay-audit signing bundle.trust",
        )
        != expected_trust
    ):
        _fail(
            "C# verifier replay-audit signing bundle.trust",
            "does not match externally pinned trust",
        )
    payload_bytes = _base64url_decode(
        bundle["payload"],
        "C# verifier replay-audit signing bundle.payload",
        MAX_AUDIT_PAYLOAD_BYTES,
    )
    try:
        payload_value = json.loads(
            payload_bytes, object_pairs_hook=_unique_object_pairs
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise ValidationError(
            f"C# verifier replay-audit signing bundle payload: invalid JSON: {error}"
        ) from error
    if not isinstance(payload_value, dict) or payload_bytes != canonical_json_bytes(
        payload_value
    ):
        _fail(
            "C# verifier replay-audit signing bundle payload",
            "must be exact canonical JSON",
        )
    payload = _validate_payload(payload_value)
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "C# verifier replay-audit signing bundle payload.approval.actorRole",
            "must match the trusted signer role",
        )
    expected = _build_signing_bundle_document(
        payload,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if dict(bundle) != expected:
        _fail(
            "C# verifier replay-audit signing bundle",
            "does not match its canonical payload-derived contract",
        )
    return payload


def _ensure_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> None:
    not_before = _canonical_utc(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "must be active")


def _validate_signing_bundle_document(
    value: Mapping[str, Any],
    *,
    path: Path,
    raw: bytes,
    expected_payload: Mapping[str, Any],
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    now: datetime,
) -> VerifiedCSharpVerifierReplayAuditSigningBundle:
    bundle = dict(value)
    expected = _build_signing_bundle_document(
        expected_payload,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if bundle != expected:
        _fail(
            "C# verifier replay-audit signing bundle",
            "does not match the exact freshly replayed payload and contract",
        )
    bundle_bytes = canonical_json_bytes(bundle) + b"\n"
    if raw != bundle_bytes or len(raw) > MAX_AUDIT_SIGNING_BUNDLE_BYTES:
        _fail(
            "C# verifier replay-audit signing bundle",
            "must be bounded exact canonical JSON followed by one LF",
        )
    payload_bytes = _base64url_decode(
        bundle["payload"],
        "C# verifier replay-audit signing bundle.payload",
        MAX_AUDIT_PAYLOAD_BYTES,
    )
    unsigned_envelope_bytes = _base64url_decode(
        bundle["unsignedEnvelope"],
        "C# verifier replay-audit signing bundle.unsignedEnvelope",
        MAX_AUDIT_BYTES,
    )
    unsigned_envelope = json.loads(
        unsigned_envelope_bytes, object_pairs_hook=_unique_object_pairs
    )
    signature_preimage = _base64url_decode(
        bundle["request"]["signaturePreimage"],
        "C# verifier replay-audit signing bundle.request.signaturePreimage",
        MAX_AUDIT_SIGNATURE_INPUT_BYTES,
    )
    signature_digest = _base64url_decode(
        bundle["request"]["signatureInput"],
        "C# verifier replay-audit signing bundle.request.signatureInput",
        32,
    )
    if len(signature_digest) != 32:
        _fail(
            "C# verifier replay-audit signing bundle.request.signatureInput",
            "must be exactly one SHA-256 digest",
        )
    _ensure_payload_active(
        expected_payload, now, "C# verifier replay-audit signing bundle payload"
    )
    return VerifiedCSharpVerifierReplayAuditSigningBundle(
        path=Path(os.path.abspath(os.fspath(path))),
        bundle=bundle,
        bundle_sha256=hashlib.sha256(raw).hexdigest(),
        bundle_id=bundle["bundleId"],
        payload=dict(expected_payload),
        payload_bytes=payload_bytes,
        payload_sha256=bundle["payloadSha256"],
        unsigned_envelope=unsigned_envelope,
        unsigned_envelope_sha256=bundle["unsignedEnvelopeSha256"],
        signature_preimage=signature_preimage,
        signature_input_sha256=signature_digest.hex(),
        public_key_spki_sha256=public_key_spki_sha256,
    )


def _verify_csharp_verifier_replay_audit_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierReplayAuditTrust,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None,
    review_receipt_now: datetime | None,
    now: datetime | None,
    expected_link_count: int,
) -> tuple[VerifiedCSharpVerifierReplayAuditSigningBundle, _ReplayAuditBuild]:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    resolved, raw, document = _read_canonical_handoff_document(
        signing_bundle_path,
        "C# verifier replay-audit signing bundle",
        MAX_AUDIT_SIGNING_BUNDLE_BYTES,
        expected_link_count=expected_link_count,
    )
    current = _fresh_validation_time(
        now, "C# verifier replay-audit signing-bundle verification time"
    )
    payload = _preflight_signing_bundle_payload(
        document,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _ensure_payload_active(
        payload, current, "C# verifier replay-audit signing bundle payload"
    )
    build = _rebuild_replay_audit_payload(
        payload,
        replay_audit_spki=spki,
        signer_role=signer_role,
        sealed_tasks_path=sealed_tasks_path,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        csharp_verifier_context=csharp_verifier_context,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        review_receipt_now=review_receipt_now,
        now=now,
    )
    current = _fresh_validation_time(
        now, "C# verifier replay-audit signing-bundle post-replay time"
    )
    _ensure_payload_active(
        build.payload, current, "C# verifier replay-audit signing bundle payload"
    )
    verified = _validate_signing_bundle_document(
        document,
        path=resolved,
        raw=raw,
        expected_payload=build.payload,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        now=current,
    )
    return verified, build


def _read_unreplayed_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierReplayAuditTrust,
    now: datetime | None,
    expected_link_count: int,
) -> VerifiedCSharpVerifierReplayAuditSigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    resolved, raw, document = _read_canonical_handoff_document(
        signing_bundle_path,
        "C# verifier replay-audit signing bundle",
        MAX_AUDIT_SIGNING_BUNDLE_BYTES,
        expected_link_count=expected_link_count,
    )
    current = _fresh_validation_time(
        now, "C# verifier replay-audit signing-bundle preflight time"
    )
    payload = _preflight_signing_bundle_payload(
        document,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _ensure_payload_active(
        payload, current, "C# verifier replay-audit signing bundle payload"
    )
    return _validate_signing_bundle_document(
        document,
        path=resolved,
        raw=raw,
        expected_payload=payload,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        now=current,
    )


def verify_csharp_verifier_replay_audit_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    trust: CSharpVerifierReplayAuditTrust,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierReplayAuditSigningBundle:
    verified, _ = _verify_csharp_verifier_replay_audit_signing_bundle(
        signing_bundle_path,
        trust=trust,
        sealed_tasks_path=sealed_tasks_path,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        csharp_verifier_context=csharp_verifier_context,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        review_receipt_now=review_receipt_now,
        now=now,
        expected_link_count=1,
    )
    return verified


def prepare_csharp_verifier_replay_audit_signing_bundle(
    *,
    output_path: str | os.PathLike[str],
    trust: CSharpVerifierReplayAuditTrust,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    replay_completed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierReplayAuditSigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    build = _build_replay_audit_payload(
        replay_audit_spki=spki,
        signer_role=signer_role,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        replay_completed_at_utc=replay_completed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        sealed_tasks_path=sealed_tasks_path,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        csharp_verifier_context=csharp_verifier_context,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        review_receipt_now=review_receipt_now,
        now=now,
    )
    bundle = _build_signing_bundle_document(
        build.payload,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_AUDIT_SIGNING_BUNDLE_BYTES:
        _fail("C# verifier replay-audit signing bundle", "exceeds its byte limit")
    expected_sha256 = hashlib.sha256(serialized).hexdigest()

    live = {
        "trust": trust,
        "sealed_tasks_path": sealed_tasks_path,
        "candidate_responses_path": candidate_responses_path,
        "candidate_results_path": candidate_results_path,
        "baseline_responses_path": baseline_responses_path,
        "baseline_results_path": baseline_results_path,
        "data_release_path": data_release_path,
        "review_receipt_trust": review_receipt_trust,
        "evaluation_authoring_approval_trust": evaluation_authoring_approval_trust,
        "csharp_verifier_context": csharp_verifier_context,
        "candidate_attestation_trust": candidate_attestation_trust,
        "baseline_attestation_trust": baseline_attestation_trust,
        "review_receipt_now": review_receipt_now,
        "now": now,
    }

    def validate(path: Path, expected_link_count: int):
        verified, _ = _verify_csharp_verifier_replay_audit_signing_bundle(
            path, expected_link_count=expected_link_count, **live
        )
        if verified.bundle_sha256 != expected_sha256:
            _fail(
                "C# verifier replay-audit signing bundle",
                "changed during publication",
            )
        return verified

    return _write_owned_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field="C# verifier replay-audit signing-bundle output",
    )


def _build_external_signature_document(
    bundle: Mapping[str, Any],
    bundle_bytes: bytes | None = None,
    *,
    signature_mode: str,
    signature_format: str,
    signature: bytes,
) -> dict[str, Any]:
    document = dict(bundle)
    exact_bundle_bytes = (
        bundle_bytes
        if bundle_bytes is not None
        else canonical_json_bytes(document) + b"\n"
    )
    request = document["request"]
    signature_document: dict[str, Any] = {
        "schemaVersion": AUDIT_SIGNATURE_SCHEMA_VERSION,
        "signatureId": AUDIT_EXTERNAL_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": document["bundleId"],
        "signingBundleSha256": hashlib.sha256(exact_bundle_bytes).hexdigest(),
        "auditId": document["auditId"],
        "payloadSha256": document["payloadSha256"],
        "unsignedEnvelopeSha256": document["unsignedEnvelopeSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": document["trust"]["publicKeySpkiSha256"],
        "mode": signature_mode,
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    signature_document["signatureId"] = (
        csharp_verifier_replay_audit_external_signature_id(signature_document)
    )
    return signature_document


def _validate_external_signature_document(
    value: Mapping[str, Any],
    *,
    signing_bundle: VerifiedCSharpVerifierReplayAuditSigningBundle,
    public_key: Any,
) -> bytes:
    document = _exact_keys(
        value,
        _EXTERNAL_SIGNATURE_KEYS,
        "C# verifier replay-audit external signature",
    )
    if len(canonical_json_bytes(document)) > MAX_AUDIT_EXTERNAL_SIGNATURE_BYTES:
        _fail("C# verifier replay-audit external signature", "exceeds its byte limit")
    if document["schemaVersion"] != AUDIT_SIGNATURE_SCHEMA_VERSION:
        _fail(
            "C# verifier replay-audit external signature.schemaVersion",
            "is unsupported",
        )
    expected = {
        "signingBundleId": signing_bundle.bundle_id,
        "signingBundleSha256": signing_bundle.bundle_sha256,
        "auditId": signing_bundle.payload["auditId"],
        "payloadSha256": signing_bundle.payload_sha256,
        "unsignedEnvelopeSha256": signing_bundle.unsigned_envelope_sha256,
        "signatureInputSha256": signing_bundle.signature_input_sha256,
        "publicKeySpkiSha256": signing_bundle.public_key_spki_sha256,
    }
    for name, expected_value in expected.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"C# verifier replay-audit external signature.{name}")
        if supplied != expected_value:
            _fail(
                f"C# verifier replay-audit external signature.{name}",
                "does not match the exact signing bundle",
            )
    signature_digest = _base64url_decode(
        signing_bundle.bundle["request"]["signatureInput"],
        "C# verifier replay-audit signing bundle.request.signatureInput",
        32,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        signature_mode=document["mode"],
        public_key=public_key,
        signature_preimage=signing_bundle.signature_preimage,
        signature_digest=signature_digest,
        field="C# verifier replay-audit external signature.signature",
    )
    if document["signatureId"] != (
        csharp_verifier_replay_audit_external_signature_id(document)
    ):
        _fail(
            "C# verifier replay-audit external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _validate_published_replay_audit(
    path: Path,
    *,
    expected_payload: Mapping[str, Any],
    trust: CSharpVerifierReplayAuditTrust,
    expected_envelope_sha256: str,
    replay_builder: Callable[[], _ReplayAuditBuild],
    expected_link_count: int,
    now: datetime | None,
    field: str,
) -> VerifiedCSharpVerifierReplayAudit:
    rebuilt = replay_builder()
    if rebuilt.payload != expected_payload:
        _fail(field, "live evidence changed during staged publication")
    verified = _validate_csharp_verifier_replay_audit(
        path,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=_fresh_validation_time(now, f"{field} validation time"),
        expected_link_count=expected_link_count,
    )
    if verified.payload != expected_payload:
        _fail(field, "changed during publication")
    return verified


def finalize_csharp_verifier_replay_audit(
    *,
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    trust: CSharpVerifierReplayAuditTrust,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierReplayAudit:
    live = {
        "trust": trust,
        "sealed_tasks_path": sealed_tasks_path,
        "candidate_responses_path": candidate_responses_path,
        "candidate_results_path": candidate_results_path,
        "baseline_responses_path": baseline_responses_path,
        "baseline_results_path": baseline_results_path,
        "data_release_path": data_release_path,
        "review_receipt_trust": review_receipt_trust,
        "evaluation_authoring_approval_trust": evaluation_authoring_approval_trust,
        "csharp_verifier_context": csharp_verifier_context,
        "candidate_attestation_trust": candidate_attestation_trust,
        "baseline_attestation_trust": baseline_attestation_trust,
        "review_receipt_now": review_receipt_now,
        "now": now,
    }
    preflight_bundle = _read_unreplayed_signing_bundle(
        signing_bundle_path,
        trust=trust,
        now=now,
        expected_link_count=1,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "C# verifier replay-audit external signature",
        MAX_AUDIT_EXTERNAL_SIGNATURE_BYTES,
    )
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    signature = _validate_external_signature_document(
        signature_document,
        signing_bundle=preflight_bundle,
        public_key=public_key,
    )
    verified_bundle, build = _verify_csharp_verifier_replay_audit_signing_bundle(
        signing_bundle_path, expected_link_count=1, **live
    )
    if (
        verified_bundle.bundle_id != preflight_bundle.bundle_id
        or verified_bundle.bundle_sha256 != preflight_bundle.bundle_sha256
        or verified_bundle.payload != preflight_bundle.payload
    ):
        _fail(
            "C# verifier replay-audit signing bundle",
            "changed between signature preflight and live replay",
        )

    def replay_builder() -> _ReplayAuditBuild:
        return _rebuild_replay_audit_payload(
            verified_bundle.payload,
            replay_audit_spki=spki,
            signer_role=signer_role,
            **{key: value for key, value in live.items() if key not in {"trust"}},
        )

    if build.payload != verified_bundle.payload:
        _fail(
            "C# verifier replay-audit signing bundle payload",
            "live evidence changed while the audit was finalized",
        )
    current = _fresh_validation_time(now, "C# verifier replay-audit finalization time")
    _ensure_payload_active(build.payload, current, "C# verifier replay-audit payload")
    payload_bytes = canonical_json_bytes(build.payload)
    if payload_bytes != verified_bundle.payload_bytes:
        _fail(
            "C# verifier replay-audit signing bundle payload",
            "changed while the audit was finalized",
        )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    if envelope != verified_bundle.unsigned_envelope:
        _fail(
            "C# verifier replay-audit signing bundle unsigned envelope",
            "changed while the audit was finalized",
        )
    envelope["signature"] = _base64url_encode(signature)
    raw_envelope = canonical_json_bytes(envelope)
    envelope_sha256 = hashlib.sha256(raw_envelope).hexdigest()
    _validate_envelope(
        envelope,
        trust=trust,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )
    serialized = raw_envelope + b"\n"
    if len(serialized) > MAX_AUDIT_BYTES:
        _fail("C# verifier replay-audit signed envelope", "exceeds its byte limit")

    def validate(path: Path, expected_link_count: int):
        return _validate_published_replay_audit(
            path,
            expected_payload=build.payload,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            replay_builder=replay_builder,
            expected_link_count=expected_link_count,
            now=now,
            field="C# verifier replay-audit finalization output",
        )

    return _write_owned_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field="C# verifier replay-audit finalization output",
    )


def create_csharp_verifier_replay_audit(
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
    replay_completed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    sealed_tasks_path: str | os.PathLike[str],
    candidate_responses_path: str | os.PathLike[str],
    candidate_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    csharp_verifier_context: CSharpVerifierExecutionContext,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedCSharpVerifierReplayAudit:
    trust = CSharpVerifierReplayAuditTrust(
        public_key_path=Path(public_key_path),
        public_key_spki_sha256=public_key_spki_sha256,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    build = _build_replay_audit_payload(
        replay_audit_spki=spki,
        signer_role=signer_role,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        replay_completed_at_utc=replay_completed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        sealed_tasks_path=sealed_tasks_path,
        candidate_responses_path=candidate_responses_path,
        candidate_results_path=candidate_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_results_path=baseline_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        csharp_verifier_context=csharp_verifier_context,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        review_receipt_now=review_receipt_now,
        now=now,
    )
    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    if private_spki != spki:
        _fail(
            "C# verifier replay-audit key pair", "private and pinned public keys differ"
        )
    payload_bytes = canonical_json_bytes(build.payload)
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
    raw_envelope = canonical_json_bytes(envelope)
    envelope_sha256 = hashlib.sha256(raw_envelope).hexdigest()
    current = _fresh_validation_time(now, "C# verifier replay-audit signing time")
    _validate_envelope(
        envelope,
        trust=trust,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )
    serialized = raw_envelope + b"\n"
    if len(serialized) > MAX_AUDIT_BYTES:
        _fail("C# verifier replay-audit signed envelope", "exceeds its byte limit")

    def replay_builder() -> _ReplayAuditBuild:
        return _rebuild_replay_audit_payload(
            build.payload,
            replay_audit_spki=spki,
            signer_role=signer_role,
            sealed_tasks_path=sealed_tasks_path,
            candidate_responses_path=candidate_responses_path,
            candidate_results_path=candidate_results_path,
            baseline_responses_path=baseline_responses_path,
            baseline_results_path=baseline_results_path,
            data_release_path=data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
            csharp_verifier_context=csharp_verifier_context,
            candidate_attestation_trust=candidate_attestation_trust,
            baseline_attestation_trust=baseline_attestation_trust,
            review_receipt_now=review_receipt_now,
            now=now,
        )

    def validate(path: Path, expected_link_count: int):
        return _validate_published_replay_audit(
            path,
            expected_payload=build.payload,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            replay_builder=replay_builder,
            expected_link_count=expected_link_count,
            now=now,
            field="C# verifier replay-audit output",
        )

    verified = _write_owned_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field="C# verifier replay-audit output",
    )
    return replace(verified, path=Path(os.path.abspath(os.fspath(output_path))))
