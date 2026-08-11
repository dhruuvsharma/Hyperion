from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import tempfile
import unicodedata
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, TypeVar

from .base_evaluation import (
    BaseEvaluationProfile,
    BaseModelSnapshot,
    load_base_evaluation_profile,
    load_base_model_snapshot_manifest,
    load_base_model_source_lock,
    validate_base_evaluation_profile_target,
)
from .core import (
    BASE_EVALUATION_PROFILE_BUNDLE_PATH,
    BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
    BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
    BASE_SELECTION_BUNDLE_PATH,
    MANIFEST_V3_SCHEMA_VERSION,
    MAX_JSON_BYTES,
    ValidatedManifestSnapshot,
    ValidationError,
    _exact_keys,
    _fail,
    _integer,
    _read_file_bounded,
    _reject_constant,
    _reject_reparse_components,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _validate_data_release_identity,
    canonical_json_bytes,
    resolve_bound_path,
    sha256_file,
    validate_candidate_catalog,
    validate_manifest_snapshot,
)
from .evaluation import (
    EVALUATION_RESPONSE_V2_SCHEMA_VERSION,
    MAX_EVALUATION_BYTES,
    BaseResponseAttestationTrust,
    aggregate_promotion_evidence,
    validate_promotion_policy,
    validate_promotion_evidence,
)
from .evaluation_authoring import EvaluationAuthoringApprovalTrust
from .release import (
    MAX_REVIEW_ASSET_BYTES,
    validate_corpus_evaluation_release_with_identity,
)
from .review_receipts import ExpertModelReviewReceiptTrust
from .verifier_runtime import CSharpVerifierExecutionContext


BASE_MODEL_SELECTION_SCHEMA_VERSION = "daxalgo.hyperion.base-model-selection/v2"
BASE_MODEL_SELECTION_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-model-selection-envelope/v2"
)
BASE_MODEL_SELECTION_DECISION = "approved-training-base"
BASE_MODEL_SELECTION_ID_PREFIX = "vqbaseselect-"
BASE_MODEL_SELECTION_ID_DOMAIN = "daxalgo-hyperion-base-model-selection-id/v2"
BASE_MODEL_SELECTION_SIGNATURE_DOMAIN = (
    "daxalgo-hyperion-base-model-selection-signature/v2"
)
BASE_MODEL_SELECTION_STATEMENT = (
    "Authenticates a catalog-complete reviewed student bake-off and the exact chosen "
    "snapshot for training only; it is not a checkpoint, training result, promotion, "
    "deployment, or quality claim."
)
BASE_MODEL_BAKEOFF_MATRIX_ID_PREFIX = "vqbasebakeoff-"
BASE_MODEL_BAKEOFF_MATRIX_ID_DOMAIN = "daxalgo-hyperion-base-bakeoff-matrix-id/v1"
BASE_MODEL_BAKEOFF_POLICY_FAMILY_DOMAIN = (
    "daxalgo-hyperion-base-bakeoff-policy-family/v1"
)
BASE_MODEL_SELECTION_PAYLOAD_ENCODING = "base64url"
BASE_MODEL_SELECTION_ALGORITHM = "ES256"
BASE_MODEL_SELECTION_SIGNATURE_FORMAT = "ieee-p1363"
BASE_MODEL_SELECTION_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-model-selection-signing-bundle/v1"
)
BASE_MODEL_SELECTION_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-model-selection-signature/v1"
)
BASE_MODEL_SELECTION_SIGNING_BUNDLE_ID_PREFIX = "vqbaseselectionsigning-"
BASE_MODEL_SELECTION_EXTERNAL_SIGNATURE_ID_PREFIX = "vqbaseselectionsignature-"
BASE_MODEL_SELECTION_SIGNING_STATUS = "unsigned-non-authorizing"
BASE_MODEL_SELECTION_SIGNING_HASH_ALGORITHM = "SHA-256"
BASE_MODEL_SELECTION_SIGNING_MESSAGE_TYPE = "digest"
BASE_MODEL_SELECTION_SIGNING_INPUT_ENCODING = "base64url"
BASE_MODEL_SELECTION_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
BASE_MODEL_SELECTION_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
MAX_BASE_MODEL_SELECTION_ENVELOPE_BYTES = 1_000_000
MAX_BASE_MODEL_SELECTION_PAYLOAD_BYTES = 500_000
MAX_BASE_MODEL_SELECTION_SIGNING_BUNDLE_BYTES = 2_000_000
MAX_BASE_MODEL_SELECTION_EXTERNAL_SIGNATURE_BYTES = 16_000
MAX_BASE_MODEL_SELECTION_SIGNATURE_INPUT_BYTES = 1_500_000
MAX_BASE_MODEL_SELECTION_DER_SIGNATURE_BYTES = 80
MAX_SELECTION_KEY_BYTES = 1_000_000
MAX_SELECTION_VALIDITY = timedelta(days=366)

_ZERO_SHA256 = "0" * 64
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,499}$")
_SELECTION_ID_RE = re.compile(r"^vqbaseselect-[0-9a-f]{64}$")
_MATRIX_ID_RE = re.compile(r"^vqbasebakeoff-[0-9a-f]{64}$")
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqbaseselectionsigning-[0-9a-f]{64}$")
_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqbaseselectionsignature-[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_SIGNING_BUNDLE_ID_DOMAIN = (
    "daxalgo-hyperion-base-model-selection-signing-bundle-id/v1"
)
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    "daxalgo-hyperion-base-model-selection-external-signature-id/v1"
)
_Validated = TypeVar("_Validated")

_EVALUATION_HASH_FIELDS = (
    "reportSha256",
    "reportFileSha256",
    "policySha256",
    "policyFileSha256",
    "calibrationTasksFileSha256",
    "calibrationTaskSetSha256",
    "calibrationEvidenceSha256",
    "sealedTasksFileSha256",
    "sealedTaskSetSha256",
    "candidateResponsesFileSha256",
    "candidateResponseSetSha256",
    "candidateVerifierResultsFileSha256",
    "candidateVerifierResultSetSha256",
    "baselineResponsesFileSha256",
    "baselineResponseSetSha256",
    "baselineVerifierResultsFileSha256",
    "baselineVerifierResultSetSha256",
)

_SELECTED_HASH_FIELDS = (
    "candidateCatalogSha256",
    "profileSha256",
    "sourceLockSha256",
    "snapshotManifestSha256",
    "snapshotSha256",
    "fileTreeSha256",
    "chatTemplateSha256",
)

_MATRIX_SHARED_HASH_FIELDS = (
    "calibrationTasksFileSha256",
    "calibrationTaskSetSha256",
    "calibrationEvidenceSha256",
    "sealedTasksFileSha256",
    "sealedTaskSetSha256",
    "baselineResponsesFileSha256",
    "baselineResponseSetSha256",
    "baselineVerifierResultsFileSha256",
    "baselineVerifierResultSetSha256",
)


@dataclass(frozen=True)
class BaseModelSelectionTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_key_path", Path(self.public_key_path))


@dataclass(frozen=True)
class VerifiedBaseModelSelection:
    path: Path
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str


@dataclass(frozen=True)
class VerifiedBaseModelSelectionSigningBundle:
    path: Path
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    selection_id: str
    payload_sha256: str
    public_key_spki_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "signingBundlePath": str(self.path),
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "selectionId": self.selection_id,
            "evaluationMatrixId": self.bundle["evaluationMatrixId"],
            "selectedCandidateId": self.bundle["selected"]["candidateId"],
            "payloadSha256": self.payload_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "status": BASE_MODEL_SELECTION_SIGNING_STATUS,
        }


@dataclass(frozen=True)
class VerifiedBaseModelSelectionTarget:
    selection: VerifiedBaseModelSelection
    profile: BaseEvaluationProfile
    snapshot: BaseModelSnapshot
    manifest_snapshot: ValidatedManifestSnapshot | None = None


@dataclass(frozen=True)
class BaseModelSelectionCandidateSource:
    candidate_id: str
    promotion_evidence_path: Path
    responses_path: Path
    verifier_results_path: Path
    policy_path: Path
    profile_path: Path
    snapshot_manifest_path: Path
    snapshot_path: Path
    candidate_attestation_trust: BaseResponseAttestationTrust

    def __post_init__(self) -> None:
        for field in (
            "promotion_evidence_path",
            "responses_path",
            "verifier_results_path",
            "policy_path",
            "profile_path",
            "snapshot_manifest_path",
            "snapshot_path",
        ):
            object.__setattr__(self, field, Path(getattr(self, field)))


@dataclass(frozen=True)
class _SelectionBindings:
    data_release: dict[str, str]
    release_authority_expires_at_utc: str
    evaluation_matrix: dict[str, Any]
    selected: dict[str, Any]


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _SAFE_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _model_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=500)
    if not _MODEL_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII model identifier")
    return text


def _text(value: Any, field: str, *, max_length: int) -> str:
    text = _string(value, field, max_length=max_length)
    if any(unicodedata.category(character) == "Cc" for character in text):
        _fail(field, "must not contain control characters")
    return text


def _canonical_utc(value: Any, field: str) -> datetime:
    text = _string(value, field, max_length=20)
    if len(text) != 20 or not text.endswith("Z"):
        _fail(field, "must use exact UTC second form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(field, "must be a real UTC second in form YYYY-MM-DDTHH:MM:SSZ")
    return parsed.replace(tzinfo=timezone.utc)


def _validation_time(value: datetime, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _fail(field, "must be timezone-aware")
    return value.astimezone(timezone.utc)


def _fresh_validation_time(value: datetime | None, field: str) -> datetime:
    return _validation_time(
        value if value is not None else datetime.now(timezone.utc), field
    )


def _ensure_payload_active(
    payload: Mapping[str, Any], current: datetime, field: str
) -> tuple[datetime, datetime]:
    not_before = _canonical_utc(payload["notBeforeUtc"], f"{field}.notBeforeUtc")
    expires = _canonical_utc(payload["expiresAtUtc"], f"{field}.expiresAtUtc")
    if current < not_before or current >= expires:
        _fail(f"{field} validity", "is not active")
    return not_before, expires


def _framed(fields: Iterable[str | bytes]) -> bytes:
    payload = bytearray()
    for field in fields:
        encoded = (
            field
            if isinstance(field, bytes)
            else field.encode("utf-8", errors="strict")
        )
        if len(encoded) > 0xFFFFFFFF:
            _fail("canonical field", "exceeds the uint32 length-prefix limit")
        payload.extend(struct.pack(">I", len(encoded)))
        payload.extend(encoded)
    return bytes(payload)


def _base64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(
    value: Any,
    field: str,
    *,
    exact_bytes: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    text = _string(value, field, max_length=(max_bytes or 4_000_000) * 2 + 16)
    if not _BASE64URL_RE.fullmatch(text) or "=" in text:
        _fail(field, "must be canonical unpadded base64url")
    try:
        decoded = urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        _fail(field, "must be canonical unpadded base64url")
    if _base64url_encode(decoded) != text:
        _fail(field, "must use the canonical unpadded base64url spelling")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        _fail(field, f"must decode to exactly {exact_bytes} bytes")
    if max_bytes is not None and len(decoded) > max_bytes:
        _fail(field, f"must decode to no more than {max_bytes} bytes")
    return decoded


def _load_json_bytes(raw: bytes, field: str) -> dict[str, Any]:
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
    except (json.JSONDecodeError, ValidationError) as error:
        _fail(field, f"invalid JSON: {error}")
    if not isinstance(value, dict):
        _fail(field, "must contain one JSON object")
    return value


def base_model_selection_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["selectionId"] = BASE_MODEL_SELECTION_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(
        _framed((BASE_MODEL_SELECTION_ID_DOMAIN, canonical_json_bytes(normalized)))
    ).hexdigest()
    return BASE_MODEL_SELECTION_ID_PREFIX + digest


def base_model_bakeoff_matrix_id(matrix: Mapping[str, Any]) -> str:
    normalized = dict(matrix)
    normalized["matrixId"] = BASE_MODEL_BAKEOFF_MATRIX_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(
        _framed(
            (
                BASE_MODEL_BAKEOFF_MATRIX_ID_DOMAIN,
                canonical_json_bytes(normalized),
            )
        )
    ).hexdigest()
    return BASE_MODEL_BAKEOFF_MATRIX_ID_PREFIX + digest


def _content_addressed_id(
    value: Mapping[str, Any],
    *,
    id_field: str,
    prefix: str,
    domain: str,
) -> str:
    normalized = dict(value)
    normalized[id_field] = prefix + _ZERO_SHA256
    digest = hashlib.sha256(
        _framed((domain, canonical_json_bytes(normalized)))
    ).hexdigest()
    return prefix + digest


def base_model_selection_signing_bundle_id(value: Mapping[str, Any]) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=BASE_MODEL_SELECTION_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def base_model_selection_external_signature_id(value: Mapping[str, Any]) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=BASE_MODEL_SELECTION_EXTERNAL_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
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
    _string(
        identity["responseSchemaVersion"],
        f"{field}.responseSchemaVersion",
        max_length=200,
    )
    if identity["targetKind"] not in {"trained-adapter", "raw-base"}:
        _fail(f"{field}.targetKind", "is unsupported")
    _identifier(identity["executionModelId"], f"{field}.executionModelId")
    _sha256(identity["candidateCatalogSha256"], f"{field}.candidateCatalogSha256")
    _identifier(identity["candidateId"], f"{field}.candidateId")
    _model_id(identity["modelId"], f"{field}.modelId")
    _revision(identity["modelRevision"], f"{field}.modelRevision")
    profile = _exact_keys(
        identity["servingProfile"], {"id", "sha256"}, f"{field}.servingProfile"
    )
    _identifier(profile["id"], f"{field}.servingProfile.id")
    _sha256(profile["sha256"], f"{field}.servingProfile.sha256")
    _identifier(identity["runId"], f"{field}.runId")
    _integer(identity["seed"], f"{field}.seed", 0, 2_147_483_647)
    return identity


def _validate_evaluation_binding(value: Any, field: str) -> dict[str, Any]:
    evaluation = _exact_keys(
        value,
        set(_EVALUATION_HASH_FIELDS) | {"candidateRun", "baselineRun"},
        field,
    )
    for name in _EVALUATION_HASH_FIELDS:
        _sha256(evaluation[name], f"{field}.{name}")
    candidate_run = _validate_run_identity(
        evaluation["candidateRun"], f"{field}.candidateRun"
    )
    baseline_run = _validate_run_identity(
        evaluation["baselineRun"], f"{field}.baselineRun"
    )
    if (
        candidate_run["responseSchemaVersion"] != EVALUATION_RESPONSE_V2_SCHEMA_VERSION
        or candidate_run["targetKind"] != "raw-base"
    ):
        _fail(
            f"{field}.candidateRun",
            "must be an attested raw-base response-v2 run",
        )
    if (
        baseline_run["responseSchemaVersion"] != EVALUATION_RESPONSE_V2_SCHEMA_VERSION
        or baseline_run["targetKind"] != "raw-base"
    ):
        _fail(
            f"{field}.baselineRun",
            "must be an attested raw-base response-v2 run",
        )
    if (
        candidate_run["candidateCatalogSha256"]
        != baseline_run["candidateCatalogSha256"]
    ):
        _fail(
            f"{field}.baselineRun.candidateCatalogSha256",
            "must match the candidate catalog",
        )
    if candidate_run["seed"] != baseline_run["seed"]:
        _fail(f"{field}.baselineRun.seed", "must match the candidate seed")
    if candidate_run["runId"] == baseline_run["runId"]:
        _fail(f"{field}.baselineRun.runId", "must differ from the candidate run")
    return evaluation


def _validate_selected_target(
    value: Any, field: str, *, candidate_run: Mapping[str, Any]
) -> dict[str, Any]:
    selected = _exact_keys(
        value,
        set(_SELECTED_HASH_FIELDS)
        | {
            "candidateId",
            "modelId",
            "modelRevision",
            "profileId",
            "executionModelId",
        },
        field,
    )
    for name in _SELECTED_HASH_FIELDS:
        _sha256(selected[name], f"{field}.{name}")
    _identifier(selected["candidateId"], f"{field}.candidateId")
    _model_id(selected["modelId"], f"{field}.modelId")
    _revision(selected["modelRevision"], f"{field}.modelRevision")
    _identifier(selected["profileId"], f"{field}.profileId")
    _identifier(selected["executionModelId"], f"{field}.executionModelId")
    expected_selected = {
        "candidateCatalogSha256": candidate_run["candidateCatalogSha256"],
        "candidateId": candidate_run["candidateId"],
        "modelId": candidate_run["modelId"],
        "modelRevision": candidate_run["modelRevision"],
        "profileId": candidate_run["servingProfile"]["id"],
        "profileSha256": candidate_run["servingProfile"]["sha256"],
        "executionModelId": candidate_run["executionModelId"],
    }
    for name, expected in expected_selected.items():
        if selected[name] != expected:
            _fail(f"{field}.{name}", "does not match the attested candidate run")
    return selected


def _validate_evaluation_matrix(value: Any, field: str) -> dict[str, Any]:
    matrix = _exact_keys(
        value,
        {
            "matrixId",
            "candidateCatalogSha256",
            "sourceLockSha256",
            "requiredRole",
            "requiredCandidateIds",
            "policyFamilySha256",
            "policyId",
            "frozenAtUtc",
            "shared",
            "entries",
        },
        field,
    )
    if not isinstance(matrix["matrixId"], str) or not _MATRIX_ID_RE.fullmatch(
        matrix["matrixId"]
    ):
        _fail(f"{field}.matrixId", "must be canonical")
    catalog_sha256 = _sha256(
        matrix["candidateCatalogSha256"], f"{field}.candidateCatalogSha256"
    )
    source_lock_sha256 = _sha256(
        matrix["sourceLockSha256"], f"{field}.sourceLockSha256"
    )
    if matrix["requiredRole"] != "student":
        _fail(f"{field}.requiredRole", "must be 'student'")
    required_ids = matrix["requiredCandidateIds"]
    if not isinstance(required_ids, list) or not required_ids or len(required_ids) > 32:
        _fail(f"{field}.requiredCandidateIds", "must contain 1 through 32 IDs")
    for index, candidate_id in enumerate(required_ids):
        _identifier(candidate_id, f"{field}.requiredCandidateIds[{index}]")
    if len(set(required_ids)) != len(required_ids):
        _fail(f"{field}.requiredCandidateIds", "must not contain duplicates")
    _sha256(matrix["policyFamilySha256"], f"{field}.policyFamilySha256")
    _identifier(matrix["policyId"], f"{field}.policyId")
    _canonical_utc(matrix["frozenAtUtc"], f"{field}.frozenAtUtc")

    shared = _exact_keys(
        matrix["shared"],
        set(_MATRIX_SHARED_HASH_FIELDS) | {"baselineRun"},
        f"{field}.shared",
    )
    for name in _MATRIX_SHARED_HASH_FIELDS:
        _sha256(shared[name], f"{field}.shared.{name}")
    baseline_run = _validate_run_identity(
        shared["baselineRun"], f"{field}.shared.baselineRun"
    )
    if baseline_run["candidateCatalogSha256"] != catalog_sha256:
        _fail(
            f"{field}.shared.baselineRun.candidateCatalogSha256",
            "does not match the matrix catalog",
        )

    entries = matrix["entries"]
    if not isinstance(entries, list) or len(entries) != len(required_ids):
        _fail(
            f"{field}.entries",
            "must contain exactly one entry per required candidate",
        )
    for index, entry_value in enumerate(entries):
        entry_field = f"{field}.entries[{index}]"
        entry = _exact_keys(
            entry_value,
            {
                "ordinal",
                "candidateId",
                "eligibleForSelection",
                "evaluation",
                "target",
            },
            entry_field,
        )
        if entry["ordinal"] != index:
            _fail(f"{entry_field}.ordinal", "must match catalog order")
        candidate_id = _identifier(entry["candidateId"], f"{entry_field}.candidateId")
        if candidate_id != required_ids[index]:
            _fail(
                f"{entry_field}.candidateId",
                "must match the required candidate at this ordinal",
            )
        if not isinstance(entry["eligibleForSelection"], bool):
            _fail(f"{entry_field}.eligibleForSelection", "must be a boolean")
        evaluation = _validate_evaluation_binding(
            entry["evaluation"], f"{entry_field}.evaluation"
        )
        candidate_run = evaluation["candidateRun"]
        if (
            candidate_run["candidateId"] != candidate_id
            or candidate_run["candidateCatalogSha256"] != catalog_sha256
        ):
            _fail(
                f"{entry_field}.evaluation.candidateRun",
                "does not match the matrix candidate and catalog",
            )
        if evaluation["baselineRun"] != baseline_run:
            _fail(
                f"{entry_field}.evaluation.baselineRun",
                "does not match the shared baseline run",
            )
        for name in _MATRIX_SHARED_HASH_FIELDS:
            if evaluation[name] != shared[name]:
                _fail(
                    f"{entry_field}.evaluation.{name}",
                    "does not match the shared bake-off input",
                )
        target = _validate_selected_target(
            entry["target"], f"{entry_field}.target", candidate_run=candidate_run
        )
        if target["sourceLockSha256"] != source_lock_sha256:
            _fail(
                f"{entry_field}.target.sourceLockSha256",
                "does not match the shared source lock",
            )
    expected_matrix_id = base_model_bakeoff_matrix_id(matrix)
    if matrix["matrixId"] != expected_matrix_id:
        _fail(f"{field}.matrixId", "does not match the content-derived identity")
    return matrix


def _validate_selection_payload_document(value: Any) -> dict[str, Any]:
    payload = _exact_keys(
        value,
        {
            "schemaVersion",
            "selectionId",
            "decision",
            "trainingAuthorized",
            "issuedAtUtc",
            "notBeforeUtc",
            "expiresAtUtc",
            "dataRelease",
            "evaluationMatrix",
            "selected",
            "approval",
            "statement",
        },
        "base-model selection payload",
    )
    if payload["schemaVersion"] != BASE_MODEL_SELECTION_SCHEMA_VERSION:
        _fail(
            "base-model selection payload.schemaVersion",
            f"must be {BASE_MODEL_SELECTION_SCHEMA_VERSION!r}",
        )
    if not isinstance(payload["selectionId"], str) or not _SELECTION_ID_RE.fullmatch(
        payload["selectionId"]
    ):
        _fail("base-model selection payload.selectionId", "must be canonical")
    if payload["decision"] != BASE_MODEL_SELECTION_DECISION:
        _fail(
            "base-model selection payload.decision",
            f"must be {BASE_MODEL_SELECTION_DECISION!r}",
        )
    if payload["trainingAuthorized"] is not True:
        _fail("base-model selection payload.trainingAuthorized", "must be true")
    issued = _canonical_utc(
        payload["issuedAtUtc"], "base-model selection payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "base-model selection payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "base-model selection payload.expiresAtUtc"
    )
    _validate_data_release_identity(
        payload["dataRelease"],
        "base-model selection payload.dataRelease",
        allow_none=False,
    )

    matrix = _validate_evaluation_matrix(
        payload["evaluationMatrix"], "base-model selection payload.evaluationMatrix"
    )
    selected_id = (
        payload["selected"].get("candidateId")
        if isinstance(payload["selected"], dict)
        else None
    )
    selected_entry = next(
        (entry for entry in matrix["entries"] if entry["candidateId"] == selected_id),
        None,
    )
    if selected_entry is None:
        _fail(
            "base-model selection payload.selected.candidateId",
            "must identify exactly one matrix entry",
        )
    selected = _validate_selected_target(
        payload["selected"],
        "base-model selection payload.selected",
        candidate_run=selected_entry["evaluation"]["candidateRun"],
    )
    if selected != selected_entry["target"]:
        _fail(
            "base-model selection payload.selected",
            "must exactly match the selected matrix target",
        )
    if selected_entry["eligibleForSelection"] is not True:
        _fail(
            "base-model selection payload.selected",
            "must identify a matrix entry that passed every selection gate",
        )

    approval = _exact_keys(
        payload["approval"],
        {
            "approvalId",
            "actorId",
            "actorRole",
            "reference",
            "approvedAtUtc",
            "evidenceSha256",
            "evidenceSizeBytes",
        },
        "base-model selection payload.approval",
    )
    for name in ("approvalId", "actorId", "actorRole"):
        _identifier(approval[name], f"base-model selection payload.approval.{name}")
    _text(
        approval["reference"],
        "base-model selection payload.approval.reference",
        max_length=500,
    )
    approved = _canonical_utc(
        approval["approvedAtUtc"], "base-model selection payload.approval.approvedAtUtc"
    )
    _sha256(
        approval["evidenceSha256"],
        "base-model selection payload.approval.evidenceSha256",
    )
    _integer(
        approval["evidenceSizeBytes"],
        "base-model selection payload.approval.evidenceSizeBytes",
        1,
        MAX_REVIEW_ASSET_BYTES,
    )
    if not approved <= issued <= not_before < expires:
        _fail(
            "base-model selection payload validity",
            "must satisfy approvedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_SELECTION_VALIDITY:
        _fail("base-model selection payload validity", "must not exceed 366 days")
    if payload["statement"] != BASE_MODEL_SELECTION_STATEMENT:
        _fail("base-model selection payload.statement", "does not match the contract")
    expected_id = base_model_selection_id(payload)
    if payload["selectionId"] != expected_id:
        _fail(
            "base-model selection payload.selectionId",
            "does not match the content-derived identity",
        )
    return payload


def _signature_input(envelope: Mapping[str, Any], payload_bytes: bytes) -> bytes:
    return _framed(
        (
            BASE_MODEL_SELECTION_SIGNATURE_DOMAIN,
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
        "schemaVersion": BASE_MODEL_SELECTION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": BASE_MODEL_SELECTION_SCHEMA_VERSION,
        "payloadEncoding": BASE_MODEL_SELECTION_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": BASE_MODEL_SELECTION_ALGORITHM,
        "signatureFormat": BASE_MODEL_SELECTION_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


def _serialize_selection_envelope(envelope: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(envelope, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    ).encode("utf-8")


def _crypto_modules() -> tuple[Any, Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError:
        _fail(
            "base-model selection cryptography",
            "requires the optional 'promote' dependency",
        )
    return (
        InvalidSignature,
        hashes,
        serialization,
        ec,
        (decode_dss_signature, encode_dss_signature),
    )


def _load_public_key(path: str | os.PathLike[str]) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _read_file_bounded(
        Path(path), "base-model selection public key", MAX_SELECTION_KEY_BYTES
    )
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        _fail("base-model selection public key", f"must be valid PEM: {error}")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("base-model selection public key", "must be an EC P-256 public key")
    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, hashlib.sha256(spki).hexdigest()


def _load_private_key(
    path: str | os.PathLike[str], password: bytes | None
) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _read_file_bounded(
        Path(path), "base-model selection private key", MAX_SELECTION_KEY_BYTES
    )
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as error:
        _fail("base-model selection private key", f"must be valid PEM: {error}")
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("base-model selection private key", "must be an EC P-256 private key")
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, hashlib.sha256(spki).hexdigest()


def _sign_p1363_low_s(private_key: Any, data: bytes) -> bytes:
    _, hashes, _, ec, utilities = _crypto_modules()
    decode_dss_signature, _ = utilities
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    if s > _P256_HALF_ORDER:
        s = _P256_ORDER - s
    if not (1 <= r < _P256_ORDER and 1 <= s <= _P256_HALF_ORDER):
        _fail("base-model selection signature", "signer returned invalid P-256 values")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_p1363_low_s(public_key: Any, data: bytes, signature: bytes) -> None:
    InvalidSignature, hashes, _, ec, utilities = _crypto_modules()
    _, encode_dss_signature = utilities
    if len(signature) != 64:
        _fail("base-model selection signature", "must be exactly 64-byte IEEE-P1363")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        _fail("base-model selection signature", "contains out-of-range P-256 values")
    if s > _P256_HALF_ORDER:
        _fail("base-model selection signature", "must use canonical low-S form")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        _fail(
            "base-model selection signature",
            "does not verify with the pinned public key",
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
    if signature_format == BASE_MODEL_SELECTION_EXTERNAL_P1363_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, exact_bytes=64)
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif signature_format == BASE_MODEL_SELECTION_EXTERNAL_DER_SIGNATURE_FORMAT:
        signature = _base64url_decode(
            value, field, max_bytes=MAX_BASE_MODEL_SELECTION_DER_SIGNATURE_BYTES
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


def _validate_trust(trust: BaseModelSelectionTrust) -> tuple[Any, str, str, str, str]:
    if not isinstance(trust, BaseModelSelectionTrust):
        _fail("base-model selection trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(trust.public_key_path)
    expected_spki = _sha256(
        trust.public_key_spki_sha256,
        "base-model selection trust.publicKeySpkiSha256",
    )
    if actual_spki != expected_spki:
        _fail(
            "base-model selection trust.publicKeySpkiSha256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "base-model selection trust.audience"),
        _identifier(trust.key_id, "base-model selection trust.keyId"),
        _identifier(trust.signer_role, "base-model selection trust.signerRole"),
    )


def _require_distinct_upstream_signers(
    selection_spki: str,
    evaluation_authoring_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
) -> None:
    if not isinstance(evaluation_authoring_trust, EvaluationAuthoringApprovalTrust):
        _fail(
            "evaluation-authoring approval trust",
            "must be externally supplied for base-model selection",
        )
    authoring_spki = _sha256(
        evaluation_authoring_trust.public_key_spki_sha256,
        "evaluation-authoring approval trust.publicKeySpkiSha256",
    )
    if not isinstance(review_receipt_trust, ExpertModelReviewReceiptTrust):
        _fail(
            "review-receipt trust",
            "must be externally supplied for base-model selection",
        )
    review_spki = _sha256(
        review_receipt_trust.public_key_spki_sha256,
        "review-receipt trust.publicKeySpkiSha256",
    )
    upstream = {
        "evaluation-authoring approval": authoring_spki,
        "review-receipt": review_spki,
    }
    lineage_trust = review_receipt_trust.teacher_lineage_admission_trust
    if lineage_trust is not None:
        upstream["teacher-lineage admission"] = _sha256(
            lineage_trust.public_key_spki_sha256,
            "teacher-lineage admission trust.publicKeySpkiSha256",
        )
    collisions = [name for name, spki in upstream.items() if selection_spki == spki]
    if collisions:
        _fail(
            "base-model selection signer",
            "must differ from upstream " + ", ".join(collisions) + " signer",
        )


def _validate_envelope_document(
    value: Any,
    *,
    trust: BaseModelSelectionTrust,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    public_key, spki_sha256, audience, key_id, signer_role = _validate_trust(trust)
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
        "base-model selection envelope",
    )
    constants = {
        "schemaVersion": BASE_MODEL_SELECTION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": BASE_MODEL_SELECTION_SCHEMA_VERSION,
        "payloadEncoding": BASE_MODEL_SELECTION_PAYLOAD_ENCODING,
        "algorithm": BASE_MODEL_SELECTION_ALGORITHM,
        "signatureFormat": BASE_MODEL_SELECTION_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki_sha256,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(
                f"base-model selection envelope.{name}",
                "does not match trusted configuration",
            )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "base-model selection envelope.payload",
        max_bytes=MAX_BASE_MODEL_SELECTION_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            envelope["payloadSha256"], "base-model selection envelope.payloadSha256"
        )
        != payload_sha256
    ):
        _fail(
            "base-model selection envelope.payloadSha256",
            "does not match the exact decoded payload bytes",
        )
    signature = _base64url_decode(
        envelope["signature"],
        "base-model selection envelope.signature",
        exact_bytes=64,
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )
    payload = _load_json_bytes(payload_bytes, "base-model selection payload")
    if canonical_json_bytes(payload) != payload_bytes:
        _fail("base-model selection payload", "must use exact canonical JSON bytes")
    payload = _validate_selection_payload_document(payload)
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "base-model selection payload.approval.actorRole",
            "must match the signed envelope role",
        )
    current = _validation_time(now, "base-model selection validation time")
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "base-model selection payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "base-model selection payload.expiresAtUtc"
    )
    if current < not_before or current >= expires:
        _fail("base-model selection payload validity", "is not currently active")
    return envelope, payload, payload_bytes


def verify_base_model_selection_envelope(
    path: str | os.PathLike[str],
    *,
    trust: BaseModelSelectionTrust,
    now: datetime | None = None,
) -> VerifiedBaseModelSelection:
    selection_path = Path(path)
    raw = _read_file_bounded(
        selection_path,
        "base-model selection envelope",
        MAX_BASE_MODEL_SELECTION_ENVELOPE_BYTES,
    )
    envelope_value = _load_json_bytes(raw, "base-model selection envelope")
    if raw != _serialize_selection_envelope(envelope_value):
        _fail(
            "base-model selection envelope",
            "must use the exact pretty JSON encoding followed by one LF",
        )
    envelope, payload, payload_bytes = _validate_envelope_document(
        envelope_value,
        trust=trust,
        now=_fresh_validation_time(now, "base-model selection validation time"),
    )
    final_raw = _read_file_bounded(
        selection_path,
        "base-model selection envelope",
        MAX_BASE_MODEL_SELECTION_ENVELOPE_BYTES,
    )
    if final_raw != raw:
        _fail("base-model selection envelope", "changed while it was verified")
    return VerifiedBaseModelSelection(
        path=Path(os.path.abspath(os.fspath(selection_path))),
        envelope=envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        envelope_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _selected_target(
    profile: BaseEvaluationProfile, snapshot: BaseModelSnapshot
) -> dict[str, Any]:
    profile_document = profile.document
    snapshot_document = snapshot.document
    return {
        "candidateCatalogSha256": snapshot_document["candidateCatalogSha256"],
        "candidateId": snapshot_document["candidateId"],
        "modelId": snapshot_document["baseModel"]["modelId"],
        "modelRevision": snapshot_document["baseModel"]["revision"],
        "profileId": profile_document["profileId"],
        "profileSha256": profile.sha256,
        "executionModelId": profile.execution_model_id,
        "sourceLockSha256": snapshot_document["sourceLockSha256"],
        "snapshotManifestSha256": snapshot.manifest_sha256,
        "snapshotSha256": snapshot_document["snapshotSha256"],
        "fileTreeSha256": snapshot_document["fileTreeSha256"],
        "chatTemplateSha256": snapshot_document["chatTemplateSha256"],
    }


def _validate_matrix_catalog_binding(
    payload: Mapping[str, Any],
    *,
    catalog_path: str | os.PathLike[str],
    source_lock_sha256: str | None = None,
) -> None:
    path = Path(catalog_path)
    raw = _read_file_bounded(
        path, "base-model selection candidate catalog", MAX_JSON_BYTES
    )
    catalog = validate_candidate_catalog(path)
    if (
        _read_file_bounded(
            path, "base-model selection candidate catalog", MAX_JSON_BYTES
        )
        != raw
    ):
        _fail("base-model selection candidate catalog", "changed while validated")
    matrix = payload["evaluationMatrix"]
    if matrix["candidateCatalogSha256"] != hashlib.sha256(raw).hexdigest():
        _fail(
            "base-model selection evaluation matrix candidateCatalogSha256",
            "does not match the supplied catalog bytes",
        )
    students = [
        candidate
        for candidate in catalog["candidates"]
        if "student" in candidate["roles"]
    ]
    expected_ids = [candidate["id"] for candidate in students]
    if matrix["requiredCandidateIds"] != expected_ids:
        _fail(
            "base-model selection evaluation matrix requiredCandidateIds",
            "does not exactly match catalog student order and coverage",
        )
    expected_by_id = {candidate["id"]: candidate for candidate in students}
    for index, entry in enumerate(matrix["entries"]):
        expected = expected_by_id[entry["candidateId"]]
        target = entry["target"]
        if (
            target["modelId"] != expected["modelId"]
            or target["modelRevision"] != expected["revision"]
        ):
            _fail(
                f"base-model selection evaluation matrix entries[{index}].target",
                "does not match the catalog model and revision",
            )
    if (
        source_lock_sha256 is not None
        and matrix["sourceLockSha256"] != source_lock_sha256
    ):
        _fail(
            "base-model selection evaluation matrix sourceLockSha256",
            "does not match the supplied approved source lock",
        )


def validate_base_model_selection_target(
    path: str | os.PathLike[str],
    *,
    trust: BaseModelSelectionTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    profile_path: str | os.PathLike[str],
    snapshot_manifest_path: str | os.PathLike[str],
    snapshot_path: str | os.PathLike[str],
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    now: datetime | None = None,
) -> VerifiedBaseModelSelectionTarget:
    verified = verify_base_model_selection_envelope(path, trust=trust, now=now)
    _require_distinct_upstream_signers(
        verified.envelope["publicKeySpkiSha256"],
        evaluation_authoring_approval_trust,
        review_receipt_trust,
    )
    profile, snapshot = validate_base_evaluation_profile_target(
        profile_path=profile_path,
        snapshot_manifest_path=snapshot_manifest_path,
        snapshot_path=snapshot_path,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
    )
    _validate_matrix_catalog_binding(
        verified.payload,
        catalog_path=catalog_path,
        source_lock_sha256=snapshot.document["sourceLockSha256"],
    )
    expected = _selected_target(profile, snapshot)
    if verified.payload["selected"] != expected:
        _fail(
            "base-model selection payload.selected",
            "does not match the supplied profile and exact snapshot",
        )
    return VerifiedBaseModelSelectionTarget(
        selection=verified,
        profile=profile,
        snapshot=snapshot,
    )


def _validate_base_model_selection_manifest_binding(
    manifest_snapshot: ValidatedManifestSnapshot,
    *,
    trust: BaseModelSelectionTrust | None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    expected_data_release: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> VerifiedBaseModelSelection:
    path = manifest_snapshot.path
    manifest = manifest_snapshot.document
    if manifest["schemaVersion"] != MANIFEST_V3_SCHEMA_VERSION:
        _fail(
            "training manifest.schemaVersion",
            "production consumption requires a corpus-admitted v3 training manifest",
        )
    if trust is None:
        _fail(
            "base-model selection trust",
            "is required for production selection validation",
        )
    selection_path = resolve_bound_path(
        path.parent,
        manifest["baseModelSelection"]["path"],
        "manifest.baseModelSelection.path",
    )
    selection = verify_base_model_selection_envelope(
        selection_path, trust=trust, now=now
    )
    _require_distinct_upstream_signers(
        selection.envelope["publicKeySpkiSha256"],
        evaluation_authoring_approval_trust,
        review_receipt_trust,
    )
    expected_selection_binding = {
        "path": BASE_SELECTION_BUNDLE_PATH,
        "envelopeSha256": selection.envelope_sha256,
        "payloadSha256": selection.payload_sha256,
        "selectionId": selection.payload["selectionId"],
        "expiresAtUtc": selection.payload["expiresAtUtc"],
    }
    if manifest["baseModelSelection"] != expected_selection_binding:
        _fail(
            "manifest.baseModelSelection",
            "does not match the authenticated bundled selection",
        )
    if selection.payload["dataRelease"] != manifest["dataRelease"]:
        _fail(
            "base-model selection payload.dataRelease",
            "does not match the training manifest release",
        )
    if expected_data_release is not None:
        release = _validate_data_release_identity(
            expected_data_release, "expected base-model selection dataRelease"
        )
        if selection.payload["dataRelease"] != release:
            _fail(
                "base-model selection payload.dataRelease",
                "does not match the expected production release",
            )

    catalog_path = resolve_bound_path(
        path.parent,
        manifest["candidateCatalog"]["path"],
        "manifest.candidateCatalog.path",
    )
    profile_path = resolve_bound_path(
        path.parent,
        BASE_EVALUATION_PROFILE_BUNDLE_PATH,
        "manifest.baseModelSnapshot.profile.path",
    )
    snapshot_manifest_path = resolve_bound_path(
        path.parent,
        BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
        "manifest.baseModelSnapshot.manifest.path",
    )
    source_lock_path = resolve_bound_path(
        path.parent,
        BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
        "manifest.baseModelSnapshot.sourceLock.path",
    )
    profile = load_base_evaluation_profile(profile_path)
    snapshot_document, snapshot_manifest_sha256 = load_base_model_snapshot_manifest(
        snapshot_manifest_path
    )
    source_lock = load_base_model_source_lock(source_lock_path, catalog_path)
    _validate_matrix_catalog_binding(
        selection.payload,
        catalog_path=catalog_path,
        source_lock_sha256=source_lock.sha256,
    )
    expected_selected = {
        "candidateCatalogSha256": manifest["candidateCatalog"]["sha256"],
        "candidateId": manifest["baseModel"]["candidateId"],
        "modelId": manifest["baseModel"]["modelId"],
        "modelRevision": manifest["baseModel"]["revision"],
        "profileId": profile.document["profileId"],
        "profileSha256": profile.sha256,
        "executionModelId": profile.execution_model_id,
        "sourceLockSha256": source_lock.sha256,
        "snapshotManifestSha256": snapshot_manifest_sha256,
        "snapshotSha256": snapshot_document["snapshotSha256"],
        "fileTreeSha256": snapshot_document["fileTreeSha256"],
        "chatTemplateSha256": snapshot_document["chatTemplateSha256"],
    }
    if selection.payload["selected"] != expected_selected:
        _fail(
            "base-model selection payload.selected",
            "does not match the manifest-bound base-model target",
        )
    return selection


def validate_base_model_selection_manifest_binding(
    manifest_path: str | os.PathLike[str],
    *,
    trust: BaseModelSelectionTrust | None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    expected_data_release: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> VerifiedBaseModelSelection:
    """Authenticate the selection transitively bound by one manifest byte snapshot."""
    return _validate_base_model_selection_manifest_binding(
        validate_manifest_snapshot(manifest_path),
        trust=trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        review_receipt_trust=review_receipt_trust,
        expected_data_release=expected_data_release,
        now=now,
    )


def validate_base_model_selection_manifest_target(
    manifest_path: str | os.PathLike[str],
    *,
    trust: BaseModelSelectionTrust | None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    snapshot_path: str | os.PathLike[str] | None,
    expected_data_release: Mapping[str, Any] | None = None,
    target_now: datetime | None = None,
) -> VerifiedBaseModelSelectionTarget:
    """Authenticate a manifest selection and revalidate its exact external weight tree."""
    manifest_snapshot = validate_manifest_snapshot(manifest_path)
    path = manifest_snapshot.path
    manifest = manifest_snapshot.document
    manifest_time = _canonical_utc(
        manifest["createdAtUtc"], "training manifest.createdAtUtc"
    )
    binding = _validate_base_model_selection_manifest_binding(
        manifest_snapshot,
        trust=trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        review_receipt_trust=review_receipt_trust,
        expected_data_release=expected_data_release,
        now=manifest_time,
    )
    effective_target_time = target_now if target_now is not None else manifest_time
    if effective_target_time < manifest_time:
        _fail(
            "base-model selection target time",
            "must not precede the selected training manifest",
        )
    if snapshot_path is None:
        _fail(
            "base-model snapshot",
            "is required for production selection validation",
        )
    target = validate_base_model_selection_target(
        resolve_bound_path(
            path.parent,
            manifest["baseModelSelection"]["path"],
            "manifest.baseModelSelection.path",
        ),
        trust=trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        review_receipt_trust=review_receipt_trust,
        profile_path=resolve_bound_path(
            path.parent,
            BASE_EVALUATION_PROFILE_BUNDLE_PATH,
            "manifest.baseModelSnapshot.profile.path",
        ),
        snapshot_manifest_path=resolve_bound_path(
            path.parent,
            BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
            "manifest.baseModelSnapshot.manifest.path",
        ),
        snapshot_path=snapshot_path,
        catalog_path=resolve_bound_path(
            path.parent,
            manifest["candidateCatalog"]["path"],
            "manifest.candidateCatalog.path",
        ),
        source_lock_path=resolve_bound_path(
            path.parent,
            BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
            "manifest.baseModelSnapshot.sourceLock.path",
        ),
        now=effective_target_time,
    )
    if (
        target.selection.envelope_sha256 != binding.envelope_sha256
        or target.selection.payload_sha256 != binding.payload_sha256
    ):
        _fail(
            "base-model selection envelope",
            "changed between manifest and snapshot validation",
        )
    return VerifiedBaseModelSelectionTarget(
        selection=target.selection,
        profile=target.profile,
        snapshot=target.snapshot,
        manifest_snapshot=manifest_snapshot,
    )


def _approval_binding(path: str | os.PathLike[str]) -> tuple[str, int]:
    raw = _read_file_bounded(
        Path(path), "base-model selection approval evidence", MAX_REVIEW_ASSET_BYTES
    )
    if not raw:
        _fail("base-model selection approval evidence", "must not be empty")
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _validate_payload_against_bindings(
    payload: Mapping[str, Any],
    *,
    bindings: _SelectionBindings,
    approval_evidence_path: str | os.PathLike[str],
    signer_role: str,
) -> None:
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "base-model selection payload.approval.actorRole",
            "must match the signed envelope role",
        )
    if payload["dataRelease"] != bindings.data_release:
        _fail(
            "base-model selection payload.dataRelease", "does not match live evidence"
        )
    if payload["evaluationMatrix"] != bindings.evaluation_matrix:
        _fail(
            "base-model selection payload.evaluationMatrix",
            "does not match live catalog-complete evidence",
        )
    if payload["selected"] != bindings.selected:
        _fail(
            "base-model selection payload.selected", "does not match the exact target"
        )
    if _canonical_utc(
        payload["expiresAtUtc"], "base-model selection payload.expiresAtUtc"
    ) > _canonical_utc(
        bindings.release_authority_expires_at_utc,
        "base-model selection release-authority expiry",
    ):
        _fail(
            "base-model selection payload.expiresAtUtc",
            "must not outlive release review and evaluation-authoring authorities",
        )
    approval_hash, approval_size = _approval_binding(approval_evidence_path)
    if (
        payload["approval"]["evidenceSha256"] != approval_hash
        or payload["approval"]["evidenceSizeBytes"] != approval_size
    ):
        _fail(
            "base-model selection payload.approval evidence",
            "does not match the supplied bytes",
        )


def _build_selection_payload(
    *,
    bindings: _SelectionBindings,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    approval_evidence_path: str | os.PathLike[str],
    signer_role: str,
) -> dict[str, Any]:
    approval_hash, approval_size = _approval_binding(approval_evidence_path)
    payload: dict[str, Any] = {
        "schemaVersion": BASE_MODEL_SELECTION_SCHEMA_VERSION,
        "selectionId": BASE_MODEL_SELECTION_ID_PREFIX + _ZERO_SHA256,
        "decision": BASE_MODEL_SELECTION_DECISION,
        "trainingAuthorized": True,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "dataRelease": bindings.data_release,
        "evaluationMatrix": bindings.evaluation_matrix,
        "selected": bindings.selected,
        "approval": {
            "approvalId": approval_id,
            "actorId": actor_id,
            "actorRole": actor_role,
            "reference": approval_reference,
            "approvedAtUtc": approved_at_utc,
            "evidenceSha256": approval_hash,
            "evidenceSizeBytes": approval_size,
        },
        "statement": BASE_MODEL_SELECTION_STATEMENT,
    }
    payload["selectionId"] = base_model_selection_id(payload)
    payload = _validate_selection_payload_document(payload)
    _validate_payload_against_bindings(
        payload,
        bindings=bindings,
        approval_evidence_path=approval_evidence_path,
        signer_role=signer_role,
    )
    return payload


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
    preimage = _signature_input(envelope, payload_bytes)
    digest = hashlib.sha256(preimage).digest()
    matrix = payload["evaluationMatrix"]
    bundle: dict[str, Any] = {
        "schemaVersion": BASE_MODEL_SELECTION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": BASE_MODEL_SELECTION_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": BASE_MODEL_SELECTION_SIGNING_STATUS,
        "authority": {
            "baseModelSelectionIssuance": False,
            "corpusReview": False,
            "evaluationAuthoring": False,
            "release": False,
            "training": False,
            "checkpoint": False,
            "evaluation": False,
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
        "selectionId": payload["selectionId"],
        "dataRelease": payload["dataRelease"],
        "evaluationMatrixId": matrix["matrixId"],
        "candidateCatalogSha256": matrix["candidateCatalogSha256"],
        "sourceLockSha256": matrix["sourceLockSha256"],
        "requiredCandidateIds": matrix["requiredCandidateIds"],
        "selected": payload["selected"],
        "approval": payload["approval"],
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
        "signatureContract": {
            "algorithm": BASE_MODEL_SELECTION_ALGORITHM,
            "hashAlgorithm": BASE_MODEL_SELECTION_SIGNING_HASH_ALGORITHM,
            "messageType": BASE_MODEL_SELECTION_SIGNING_MESSAGE_TYPE,
            "signatureInputEncoding": BASE_MODEL_SELECTION_SIGNING_INPUT_ENCODING,
            "acceptedSignatureFormats": [
                BASE_MODEL_SELECTION_EXTERNAL_DER_SIGNATURE_FORMAT,
                BASE_MODEL_SELECTION_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "selectionId": payload["selectionId"],
            "payloadSha256": envelope["payloadSha256"],
            "payload": envelope["payload"],
            "signatureInputSha256": digest.hex(),
            "signaturePreimage": _base64url_encode(preimage),
            "signatureInput": _base64url_encode(digest),
        },
    }
    bundle["bundleId"] = base_model_selection_signing_bundle_id(bundle)
    return bundle


def _validate_signing_bundle_document(
    value: Any,
    *,
    bindings: _SelectionBindings,
    approval_evidence_path: str | os.PathLike[str],
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
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
            "selectionId",
            "dataRelease",
            "evaluationMatrixId",
            "candidateCatalogSha256",
            "sourceLockSha256",
            "requiredCandidateIds",
            "selected",
            "approval",
            "validity",
            "signatureContract",
            "request",
        },
        "base-model selection signing bundle",
    )
    if bundle["schemaVersion"] != BASE_MODEL_SELECTION_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("base-model selection signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != BASE_MODEL_SELECTION_SIGNING_STATUS:
        _fail(
            "base-model selection signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority_fields = {
        "baseModelSelectionIssuance",
        "corpusReview",
        "evaluationAuthoring",
        "release",
        "training",
        "checkpoint",
        "evaluation",
        "promotionDecision",
        "deployment",
        "hostedServing",
        "installation",
        "verifierExecution",
        "strategyExecution",
    }
    authority = _exact_keys(
        bundle["authority"],
        authority_fields,
        "base-model selection signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"base-model selection signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )
    trust = _exact_keys(
        bundle["trust"],
        {"publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "base-model selection signing bundle.trust",
    )
    expected_trust = {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
    }
    if trust != expected_trust:
        _fail(
            "base-model selection signing bundle.trust",
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
        "base-model selection signing bundle.signatureContract",
    )
    expected_contract = {
        "algorithm": BASE_MODEL_SELECTION_ALGORITHM,
        "hashAlgorithm": BASE_MODEL_SELECTION_SIGNING_HASH_ALGORITHM,
        "messageType": BASE_MODEL_SELECTION_SIGNING_MESSAGE_TYPE,
        "signatureInputEncoding": BASE_MODEL_SELECTION_SIGNING_INPUT_ENCODING,
        "acceptedSignatureFormats": [
            BASE_MODEL_SELECTION_EXTERNAL_DER_SIGNATURE_FORMAT,
            BASE_MODEL_SELECTION_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    if contract != expected_contract:
        _fail(
            "base-model selection signing bundle.signatureContract",
            "does not match the contract",
        )
    request = _exact_keys(
        bundle["request"],
        {
            "selectionId",
            "payloadSha256",
            "payload",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "base-model selection signing bundle.request",
    )
    payload_bytes = _base64url_decode(
        request["payload"],
        "base-model selection signing bundle.request.payload",
        max_bytes=MAX_BASE_MODEL_SELECTION_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            request["payloadSha256"],
            "base-model selection signing bundle.request.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "base-model selection signing bundle.request.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_bytes(
        payload_bytes, "base-model selection signing bundle payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail("base-model selection signing bundle payload", "must be canonical JSON")
    payload = _validate_selection_payload_document(payload)
    _ensure_payload_active(payload, now, "base-model selection signing bundle payload")
    _validate_payload_against_bindings(
        payload,
        bindings=bindings,
        approval_evidence_path=approval_evidence_path,
        signer_role=signer_role,
    )
    matrix = payload["evaluationMatrix"]
    expected_bindings = {
        "selectionId": payload["selectionId"],
        "dataRelease": payload["dataRelease"],
        "evaluationMatrixId": matrix["matrixId"],
        "candidateCatalogSha256": matrix["candidateCatalogSha256"],
        "sourceLockSha256": matrix["sourceLockSha256"],
        "requiredCandidateIds": matrix["requiredCandidateIds"],
        "selected": payload["selected"],
        "approval": payload["approval"],
        "validity": {
            "issuedAtUtc": payload["issuedAtUtc"],
            "notBeforeUtc": payload["notBeforeUtc"],
            "expiresAtUtc": payload["expiresAtUtc"],
        },
    }
    for name, expected in expected_bindings.items():
        if bundle[name] != expected:
            _fail(
                f"base-model selection signing bundle.{name}",
                "does not match the exact payload",
            )
    if request["selectionId"] != payload["selectionId"]:
        _fail(
            "base-model selection signing bundle.request.selectionId",
            "does not match the exact payload",
        )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    preimage = _signature_input(envelope, payload_bytes)
    supplied_preimage = _base64url_decode(
        request["signaturePreimage"],
        "base-model selection signing bundle.request.signaturePreimage",
        max_bytes=MAX_BASE_MODEL_SELECTION_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != preimage:
        _fail(
            "base-model selection signing bundle.request.signaturePreimage",
            "does not match the exact signature preimage",
        )
    digest = hashlib.sha256(preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "base-model selection signing bundle.request.signatureInput",
        exact_bytes=32,
    )
    if supplied_digest != digest:
        _fail(
            "base-model selection signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "base-model selection signing bundle.request.signatureInputSha256",
        )
        != digest.hex()
    ):
        _fail(
            "base-model selection signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id != base_model_selection_signing_bundle_id(bundle)
    ):
        _fail(
            "base-model selection signing bundle.bundleId",
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
    selected = bundle["selected"]
    document: dict[str, Any] = {
        "schemaVersion": BASE_MODEL_SELECTION_SIGNATURE_SCHEMA_VERSION,
        "signatureId": BASE_MODEL_SELECTION_EXTERNAL_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "selectionId": bundle["selectionId"],
        "evaluationMatrixId": bundle["evaluationMatrixId"],
        "candidateCatalogSha256": bundle["candidateCatalogSha256"],
        "sourceLockSha256": bundle["sourceLockSha256"],
        "selectedCandidateId": selected["candidateId"],
        "selectedSnapshotSha256": selected["snapshotSha256"],
        "selectedFileTreeSha256": selected["fileTreeSha256"],
        "approvalEvidenceSha256": bundle["approval"]["evidenceSha256"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    document["signatureId"] = base_model_selection_external_signature_id(document)
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
            "selectionId",
            "evaluationMatrixId",
            "candidateCatalogSha256",
            "sourceLockSha256",
            "selectedCandidateId",
            "selectedSnapshotSha256",
            "selectedFileTreeSha256",
            "approvalEvidenceSha256",
            "payloadSha256",
            "signatureInputSha256",
            "publicKeySpkiSha256",
            "format",
            "signature",
        },
        "base-model selection external signature",
    )
    if document["schemaVersion"] != BASE_MODEL_SELECTION_SIGNATURE_SCHEMA_VERSION:
        _fail("base-model selection external signature.schemaVersion", "is unsupported")
    request = bundle["request"]
    selected = bundle["selected"]
    expected = {
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "selectionId": bundle["selectionId"],
        "evaluationMatrixId": bundle["evaluationMatrixId"],
        "candidateCatalogSha256": bundle["candidateCatalogSha256"],
        "sourceLockSha256": bundle["sourceLockSha256"],
        "selectedCandidateId": selected["candidateId"],
        "selectedSnapshotSha256": selected["snapshotSha256"],
        "selectedFileTreeSha256": selected["fileTreeSha256"],
        "approvalEvidenceSha256": bundle["approval"]["evidenceSha256"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
    }
    for name, expected_value in expected.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"base-model selection external signature.{name}")
        if supplied != expected_value:
            _fail(
                f"base-model selection external signature.{name}",
                "does not match the exact signing bundle",
            )
    preimage = _base64url_decode(
        request["signaturePreimage"],
        "base-model selection signing bundle.request.signaturePreimage",
        max_bytes=MAX_BASE_MODEL_SELECTION_SIGNATURE_INPUT_BYTES,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        public_key=public_key,
        signature_input=preimage,
        field="base-model selection external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id != base_model_selection_external_signature_id(document)
    ):
        _fail(
            "base-model selection external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _read_canonical_handoff_document(
    path: str | os.PathLike[str], field: str, max_bytes: int
) -> tuple[Path, bytes, dict[str, Any]]:
    resolved = _reject_reparse_components(Path(path), field)
    raw = _read_file_bounded(resolved, field, max_bytes)
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        _fail(field, "must be exact canonical JSON followed by one LF")
    document = _load_json_bytes(raw[:-1], field)
    if raw != canonical_json_bytes(document) + b"\n":
        _fail(field, "must be exact canonical JSON followed by one LF")
    return resolved, raw, document


def _policy_family_identity(policy: Mapping[str, Any]) -> dict[str, str]:
    normalized = dict(policy)
    normalized["policySha256"] = _ZERO_SHA256
    normalized["candidateRun"] = None
    digest = hashlib.sha256(
        _framed(
            (
                BASE_MODEL_BAKEOFF_POLICY_FAMILY_DOMAIN,
                canonical_json_bytes(normalized),
            )
        )
    ).hexdigest()
    return {
        "policyFamilySha256": digest,
        "policyId": policy["policyId"],
        "frozenAtUtc": policy["frozenAtUtc"],
    }


def _build_selection_bindings(
    *,
    candidate_sources: Iterable[BaseModelSelectionCandidateSource],
    selected_candidate_id: str,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    baseline_attestation_trust: BaseResponseAttestationTrust,
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    review_receipt_now: datetime | None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None = None,
) -> _SelectionBindings:
    sources_value = tuple(candidate_sources)
    if not sources_value or len(sources_value) > 32:
        _fail("base-model bake-off sources", "must contain 1 through 32 candidates")
    for index, source in enumerate(sources_value):
        if not isinstance(source, BaseModelSelectionCandidateSource):
            _fail(
                f"base-model bake-off sources[{index}]",
                "must be a BaseModelSelectionCandidateSource",
            )
    chosen_candidate_id = _identifier(
        selected_candidate_id, "base-model selection selected candidate ID"
    )
    if not isinstance(baseline_attestation_trust, BaseResponseAttestationTrust):
        _fail(
            "base-model bake-off baseline attestation trust",
            "is required and must be externally supplied",
        )
    sources: dict[str, tuple[str | os.PathLike[str], int]] = {
        "calibration_tasks": (calibration_tasks_path, MAX_EVALUATION_BYTES),
        "calibration_evidence": (calibration_evidence_path, MAX_EVALUATION_BYTES),
        "sealed_tasks": (sealed_tasks_path, MAX_EVALUATION_BYTES),
        "baseline_responses": (baseline_responses_path, MAX_EVALUATION_BYTES),
        "baseline_verifier_results": (
            baseline_verifier_results_path,
            MAX_EVALUATION_BYTES,
        ),
        "catalog": (catalog_path, MAX_JSON_BYTES),
        "source_lock": (source_lock_path, MAX_JSON_BYTES),
    }
    for index, source in enumerate(sources_value):
        prefix = f"candidate_{index:02d}"
        sources.update(
            {
                f"{prefix}_promotion_evidence": (
                    source.promotion_evidence_path,
                    MAX_EVALUATION_BYTES,
                ),
                f"{prefix}_responses": (
                    source.responses_path,
                    MAX_EVALUATION_BYTES,
                ),
                f"{prefix}_verifier_results": (
                    source.verifier_results_path,
                    MAX_EVALUATION_BYTES,
                ),
                f"{prefix}_policy": (source.policy_path, MAX_JSON_BYTES),
                f"{prefix}_profile": (source.profile_path, MAX_JSON_BYTES),
                f"{prefix}_snapshot_manifest": (
                    source.snapshot_manifest_path,
                    MAX_JSON_BYTES,
                ),
            }
        )
    with tempfile.TemporaryDirectory(prefix="daxalgo-base-selection-") as name:
        snapshot_root = Path(name)
        snapshots: dict[str, Path] = {}
        source_hashes: dict[str, str] = {}
        for index, (field, (source, limit)) in enumerate(sources.items()):
            raw = _read_file_bounded(
                Path(source), f"base-model selection {field}", limit
            )
            source_hashes[field] = hashlib.sha256(raw).hexdigest()
            captured = snapshot_root / f"{index:02d}-{field}.snapshot"
            captured.write_bytes(raw)
            snapshots[field] = captured

        catalog = validate_candidate_catalog(snapshots["catalog"])
        required_ids = [
            candidate["id"]
            for candidate in catalog["candidates"]
            if "student" in candidate["roles"]
        ]
        if len(sources_value) != len(required_ids):
            _fail(
                "base-model bake-off sources",
                "must contain exactly one source for every catalog student",
            )
        declared_ids = [
            _identifier(
                source.candidate_id,
                f"base-model bake-off sources[{index}].candidateId",
            )
            for index, source in enumerate(sources_value)
        ]
        if len(set(declared_ids)) != len(declared_ids):
            _fail(
                "base-model bake-off sources",
                "must not declare a candidate more than once",
            )
        if set(declared_ids) != set(required_ids):
            missing = sorted(set(required_ids) - set(declared_ids))
            extra = sorted(set(declared_ids) - set(required_ids))
            _fail(
                "base-model bake-off source declarations",
                f"must exactly match catalog students; missing={missing}, extra={extra}",
            )
        if chosen_candidate_id not in required_ids:
            _fail(
                "base-model selection selected candidate ID",
                "must identify a catalog student",
            )

        entries_by_id: dict[str, dict[str, Any]] = {}
        common_release: dict[str, str] | None = None
        common_policy: dict[str, str] | None = None
        common_shared: dict[str, Any] | None = None
        common_source_lock_sha256: str | None = None
        targets: list[
            tuple[int, BaseModelSelectionCandidateSource, dict[str, Any]]
        ] = []
        for index, source in enumerate(sources_value):
            prefix = f"candidate_{index:02d}"
            field = f"base-model bake-off source[{index}]"
            supplied = validate_promotion_evidence(
                snapshots[f"{prefix}_promotion_evidence"]
            )
            regenerated = aggregate_promotion_evidence(
                calibration_tasks_path=snapshots["calibration_tasks"],
                calibration_evidence_path=snapshots["calibration_evidence"],
                sealed_tasks_path=snapshots["sealed_tasks"],
                responses_path=snapshots[f"{prefix}_responses"],
                verifier_results_path=snapshots[f"{prefix}_verifier_results"],
                baseline_responses_path=snapshots["baseline_responses"],
                baseline_verifier_results_path=snapshots["baseline_verifier_results"],
                policy_path=snapshots[f"{prefix}_policy"],
                data_release_path=data_release_path,
                review_receipt_trust=review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    evaluation_authoring_approval_trust
                ),
                review_receipt_now=review_receipt_now,
                candidate_attestation_trust=source.candidate_attestation_trust,
                baseline_attestation_trust=baseline_attestation_trust,
                csharp_verifier_context=csharp_verifier_context,
                research_only=False,
            )
            if canonical_json_bytes(supplied) != canonical_json_bytes(regenerated):
                _fail(
                    f"{field}.promotion evidence",
                    "does not exactly match freshly regenerated evidence",
                )
            if (
                supplied["researchOnly"]
                or supplied["evidenceStatus"] != "release-bound"
                or supplied["completeCardinality"] is not True
            ):
                _fail(
                    f"{field}.promotion evidence",
                    "must be release-bound and complete",
                )
            if supplied["dataRelease"] is None:
                _fail(f"{field}.data release", "must be release-bound")

            profile, snapshot = validate_base_evaluation_profile_target(
                profile_path=snapshots[f"{prefix}_profile"],
                snapshot_manifest_path=snapshots[f"{prefix}_snapshot_manifest"],
                snapshot_path=source.snapshot_path,
                catalog_path=snapshots["catalog"],
                source_lock_path=snapshots["source_lock"],
            )
            target = _selected_target(profile, snapshot)
            identity = supplied["candidate"]["identity"]
            if (
                identity["responseSchemaVersion"]
                != EVALUATION_RESPONSE_V2_SCHEMA_VERSION
                or identity["targetKind"] != "raw-base"
            ):
                _fail(
                    f"{field}.candidate",
                    "must be authenticated raw-base response-v2 evidence",
                )
            expected_identity = {
                "candidateCatalogSha256": target["candidateCatalogSha256"],
                "candidateId": target["candidateId"],
                "modelId": target["modelId"],
                "modelRevision": target["modelRevision"],
                "servingProfile": {
                    "id": target["profileId"],
                    "sha256": target["profileSha256"],
                },
                "executionModelId": target["executionModelId"],
            }
            for identity_field, expected in expected_identity.items():
                if identity[identity_field] != expected:
                    _fail(
                        f"{field}.candidate.{identity_field}",
                        "does not match the exact snapshot profile",
                    )
            candidate_id = identity["candidateId"]
            if candidate_id != source.candidate_id:
                _fail(
                    f"{field}.candidateId",
                    "does not match the declared source candidate",
                )
            if candidate_id in entries_by_id:
                _fail(f"{field}.candidateId", "duplicates another matrix row")

            policy = validate_promotion_policy(snapshots[f"{prefix}_policy"])
            policy_identity = _policy_family_identity(policy)
            evaluation = {
                "reportSha256": supplied["reportSha256"],
                "reportFileSha256": source_hashes[f"{prefix}_promotion_evidence"],
                "policySha256": supplied["policySha256"],
                "policyFileSha256": source_hashes[f"{prefix}_policy"],
                "calibrationTasksFileSha256": source_hashes["calibration_tasks"],
                "calibrationTaskSetSha256": supplied["calibrationTaskSetSha256"],
                "calibrationEvidenceSha256": supplied["calibrationEvidenceSha256"],
                "sealedTasksFileSha256": source_hashes["sealed_tasks"],
                "sealedTaskSetSha256": supplied["sealedTaskSetSha256"],
                "candidateResponsesFileSha256": source_hashes[f"{prefix}_responses"],
                "candidateResponseSetSha256": supplied["candidate"][
                    "responseSetSha256"
                ],
                "candidateVerifierResultsFileSha256": source_hashes[
                    f"{prefix}_verifier_results"
                ],
                "candidateVerifierResultSetSha256": supplied["candidate"][
                    "verifierResultSetSha256"
                ],
                "baselineResponsesFileSha256": source_hashes["baseline_responses"],
                "baselineResponseSetSha256": supplied["baseline"]["responseSetSha256"],
                "baselineVerifierResultsFileSha256": source_hashes[
                    "baseline_verifier_results"
                ],
                "baselineVerifierResultSetSha256": supplied["baseline"][
                    "verifierResultSetSha256"
                ],
                "candidateRun": supplied["candidate"]["identity"],
                "baselineRun": supplied["baseline"]["identity"],
            }
            shared = {name: evaluation[name] for name in _MATRIX_SHARED_HASH_FIELDS}
            shared["baselineRun"] = evaluation["baselineRun"]
            if common_release is None:
                common_release = dict(supplied["dataRelease"])
                common_policy = policy_identity
                common_shared = shared
                common_source_lock_sha256 = target["sourceLockSha256"]
            else:
                if supplied["dataRelease"] != common_release:
                    _fail(f"{field}.data release", "does not match the matrix release")
                if policy_identity != common_policy:
                    _fail(
                        f"{field}.promotion policy",
                        "does not match the matrix policy family, ID, and freeze time",
                    )
                if shared != common_shared:
                    _fail(
                        f"{field}.shared inputs",
                        "do not match the matrix suites and baseline",
                    )
                if target["sourceLockSha256"] != common_source_lock_sha256:
                    _fail(
                        f"{field}.source lock", "does not match the matrix source lock"
                    )
            entries_by_id[candidate_id] = {
                "ordinal": -1,
                "candidateId": candidate_id,
                "eligibleForSelection": bool(
                    supplied["allEvidenceGatesPassed"]
                    and supplied["eligibleForPromotionReview"]
                ),
                "evaluation": evaluation,
                "target": target,
            }
            targets.append((index, source, target))

        actual_ids = set(entries_by_id)
        expected_ids = set(required_ids)
        if actual_ids != expected_ids:
            missing = sorted(expected_ids - actual_ids)
            extra = sorted(actual_ids - expected_ids)
            _fail(
                "base-model bake-off candidate coverage",
                f"must exactly match catalog students; missing={missing}, extra={extra}",
            )
        if (
            common_release is None
            or common_policy is None
            or common_shared is None
            or common_source_lock_sha256 is None
        ):
            _fail("base-model bake-off", "did not derive complete shared inputs")
        entries: list[dict[str, Any]] = []
        for ordinal, candidate_id in enumerate(required_ids):
            entry = entries_by_id[candidate_id]
            entry["ordinal"] = ordinal
            entries.append(entry)
        selected_entry = entries_by_id[chosen_candidate_id]
        if selected_entry["eligibleForSelection"] is not True:
            _fail(
                "base-model selection selected candidate",
                "did not pass every release-bound quality and regression gate",
            )
        matrix: dict[str, Any] = {
            "matrixId": BASE_MODEL_BAKEOFF_MATRIX_ID_PREFIX + _ZERO_SHA256,
            "candidateCatalogSha256": source_hashes["catalog"],
            "sourceLockSha256": common_source_lock_sha256,
            "requiredRole": "student",
            "requiredCandidateIds": required_ids,
            **common_policy,
            "shared": common_shared,
            "entries": entries,
        }
        matrix["matrixId"] = base_model_bakeoff_matrix_id(matrix)
        matrix = _validate_evaluation_matrix(matrix, "base-model bake-off matrix")

        final_release, final_release_identity = (
            validate_corpus_evaluation_release_with_identity(
                data_release_path,
                review_receipt_trust=review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    evaluation_authoring_approval_trust
                ),
                now=review_receipt_now,
            )
        )
        if final_release_identity != common_release:
            _fail(
                "base-model bake-off data release",
                "changed while matrix bindings were derived",
            )

        for index, source, expected_target in targets:
            prefix = f"candidate_{index:02d}"
            profile, snapshot = validate_base_evaluation_profile_target(
                profile_path=snapshots[f"{prefix}_profile"],
                snapshot_manifest_path=snapshots[f"{prefix}_snapshot_manifest"],
                snapshot_path=source.snapshot_path,
                catalog_path=snapshots["catalog"],
                source_lock_path=snapshots["source_lock"],
            )
            if _selected_target(profile, snapshot) != expected_target:
                _fail(
                    f"base-model bake-off source[{index}].snapshot",
                    "changed while matrix bindings were derived",
                )

        for field, (source, limit) in sources.items():
            if sha256_file(source, max_bytes=limit) != source_hashes[field]:
                _fail(
                    f"base-model selection {field}",
                    "changed while selection bindings were derived",
                )
        release_authority_expiries = [
            final_release["corpus"]["reviewReceipts"]["expiresAtUtc"],
            final_release["evaluation"]["authoringApproval"]["expiresAtUtc"],
        ]
        teacher_lineage_admission = final_release["corpus"].get(
            "teacherLineageAdmission"
        )
        if teacher_lineage_admission is not None:
            release_authority_expiries.append(teacher_lineage_admission["expiresAtUtc"])
        return _SelectionBindings(
            data_release=common_release,
            release_authority_expires_at_utc=min(release_authority_expiries),
            evaluation_matrix=matrix,
            selected=selected_entry["target"],
        )


def _write_no_clobber(
    path: Path,
    raw: bytes,
    *,
    prepublish_validator: Callable[[Path], _Validated],
    installed_validator: Callable[[Path], _Validated] | None = None,
    field: str = "base-model selection output",
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
    residual_staging: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
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
            residual_staging = staged
            staged = None
            owned_destination_remains = False
            try:
                destination_stat = destination.lstat()
                if (
                    destination_stat.st_dev,
                    destination_stat.st_ino,
                ) == installed_identity:
                    try:
                        destination.unlink()
                    except OSError:
                        owned_destination_remains = True
            except FileNotFoundError:
                pass
            except OSError:
                owned_destination_remains = True
            residual_locations = str(residual_staging)
            if owned_destination_remains:
                residual_locations += f"; {destination}"
            raise ValidationError(
                f"{field}: atomic publication aborted because staging cleanup failed; "
                "residual signed authority requires removal: "
                f"{residual_locations}"
            ) from error
        staged = None
        validator = installed_validator or prepublish_validator
        verified = validator(destination)
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
                    try:
                        destination.unlink()
                    except OSError as cleanup_error:
                        residual_locations = "; ".join(
                            str(item)
                            for item in (residual_staging, destination)
                            if item is not None
                        )
                        raise ValidationError(
                            f"{field}: validation failed and owned destination cleanup "
                            "failed; residual signed authority requires removal: "
                            f"{residual_locations}"
                        ) from cleanup_error
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                residual_locations = "; ".join(
                    str(item)
                    for item in (residual_staging, destination)
                    if item is not None
                )
                raise ValidationError(
                    f"{field}: validation failed and destination ownership could not "
                    "be verified; residual signed authority requires inspection: "
                    f"{residual_locations}"
                ) from cleanup_error
        raise
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                if not published:
                    raise ValidationError(
                        f"{field}: publication failed and staging cleanup failed; "
                        "residual signed authority requires removal: "
                        f"{staged}"
                    ) from error


def validate_base_model_selection(
    path: str | os.PathLike[str],
    *,
    trust: BaseModelSelectionTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    candidate_sources: Iterable[BaseModelSelectionCandidateSource],
    selected_candidate_id: str,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    baseline_attestation_trust: BaseResponseAttestationTrust,
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None = None,
) -> VerifiedBaseModelSelection:
    initial_time = _fresh_validation_time(now, "base-model selection validation time")
    verified = verify_base_model_selection_envelope(path, trust=trust, now=initial_time)
    _require_distinct_upstream_signers(
        verified.envelope["publicKeySpkiSha256"],
        evaluation_authoring_approval_trust,
        review_receipt_trust,
    )
    candidate_sources_value = tuple(candidate_sources)
    bindings = _build_selection_bindings(
        candidate_sources=candidate_sources_value,
        selected_candidate_id=selected_candidate_id,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
        review_receipt_now=review_receipt_now,
        csharp_verifier_context=csharp_verifier_context,
    )
    _validate_payload_against_bindings(
        verified.payload,
        bindings=bindings,
        approval_evidence_path=approval_evidence_path,
        signer_role=verified.envelope["signerRole"],
    )
    final_time = _fresh_validation_time(
        now, "base-model selection post-replay validation time"
    )
    replayed = verify_base_model_selection_envelope(path, trust=trust, now=final_time)
    if (
        replayed.envelope_sha256 != verified.envelope_sha256
        or replayed.payload_sha256 != verified.payload_sha256
    ):
        _fail("base-model selection envelope", "changed during live evidence replay")
    return replayed


def _selection_live_arguments(
    *,
    candidate_sources: tuple[BaseModelSelectionCandidateSource, ...],
    selected_candidate_id: str,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    baseline_attestation_trust: BaseResponseAttestationTrust,
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    review_receipt_now: datetime | None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None,
) -> dict[str, Any]:
    return {
        "candidate_sources": candidate_sources,
        "selected_candidate_id": selected_candidate_id,
        "calibration_tasks_path": calibration_tasks_path,
        "calibration_evidence_path": calibration_evidence_path,
        "sealed_tasks_path": sealed_tasks_path,
        "baseline_responses_path": baseline_responses_path,
        "baseline_verifier_results_path": baseline_verifier_results_path,
        "data_release_path": data_release_path,
        "review_receipt_trust": review_receipt_trust,
        "evaluation_authoring_approval_trust": evaluation_authoring_approval_trust,
        "baseline_attestation_trust": baseline_attestation_trust,
        "catalog_path": catalog_path,
        "source_lock_path": source_lock_path,
        "approval_evidence_path": approval_evidence_path,
        "review_receipt_now": review_receipt_now,
        "csharp_verifier_context": csharp_verifier_context,
    }


def _verify_installed_selection(
    path: Path,
    *,
    trust: BaseModelSelectionTrust,
    expected_envelope_sha256: str,
    now: datetime | None,
    field: str,
) -> VerifiedBaseModelSelection:
    verified = verify_base_model_selection_envelope(
        path,
        trust=trust,
        now=_fresh_validation_time(now, f"{field} installed validation time"),
    )
    if verified.envelope_sha256 != expected_envelope_sha256:
        _fail(field, "changed during publication")
    return verified


def create_base_model_selection(
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
    candidate_sources: Iterable[BaseModelSelectionCandidateSource],
    selected_candidate_id: str,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    baseline_attestation_trust: BaseResponseAttestationTrust,
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None = None,
) -> VerifiedBaseModelSelection:
    trust = BaseModelSelectionTrust(
        public_key_path=Path(public_key_path),
        public_key_spki_sha256=public_key_spki_sha256,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
    )
    _, trusted_spki, audience_value, key_id_value, signer_role_value = _validate_trust(
        trust
    )
    _require_distinct_upstream_signers(
        trusted_spki,
        evaluation_authoring_approval_trust,
        review_receipt_trust,
    )
    candidate_sources_value = tuple(candidate_sources)
    bindings = _build_selection_bindings(
        candidate_sources=candidate_sources_value,
        selected_candidate_id=selected_candidate_id,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
        review_receipt_now=review_receipt_now,
        csharp_verifier_context=csharp_verifier_context,
    )
    payload = _build_selection_payload(
        bindings=bindings,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        approval_evidence_path=approval_evidence_path,
        signer_role=signer_role_value,
    )
    creation_time = _fresh_validation_time(now, "base-model selection creation time")
    _ensure_payload_active(payload, creation_time, "base-model selection payload")
    private_key, private_spki = _load_private_key(
        private_key_path, private_key_password
    )
    if private_spki != trusted_spki:
        _fail(
            "base-model selection key pair",
            "private and externally pinned public keys differ",
        )
    payload_bytes = canonical_json_bytes(payload)
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience_value,
        key_id=key_id_value,
        signer_role=signer_role_value,
        public_key_spki_sha256=trusted_spki,
    )
    envelope["signature"] = _base64url_encode(
        _sign_p1363_low_s(private_key, _signature_input(envelope, payload_bytes))
    )
    post_signing_time = _fresh_validation_time(
        now, "base-model selection post-signing validation time"
    )
    _validate_envelope_document(envelope, trust=trust, now=post_signing_time)
    serialized = _serialize_selection_envelope(envelope)
    if len(serialized) > MAX_BASE_MODEL_SELECTION_ENVELOPE_BYTES:
        _fail("base-model selection envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(serialized).hexdigest()
    live_arguments = _selection_live_arguments(
        candidate_sources=candidate_sources_value,
        selected_candidate_id=selected_candidate_id,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
        approval_evidence_path=approval_evidence_path,
        review_receipt_now=review_receipt_now,
        csharp_verifier_context=csharp_verifier_context,
    )

    def validate_staged(path: Path) -> VerifiedBaseModelSelection:
        validated = validate_base_model_selection(
            path,
            trust=trust,
            now=_fresh_validation_time(
                now, "base-model selection staged publication time"
            ),
            **live_arguments,
        )
        if validated.envelope_sha256 != envelope_sha256:
            _fail("base-model selection output", "changed during staged publication")
        return validated

    def validate_installed(path: Path) -> VerifiedBaseModelSelection:
        return _verify_installed_selection(
            path,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            now=now,
            field="base-model selection output",
        )

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_staged,
        installed_validator=validate_installed,
    )


def prepare_base_model_selection_signing_bundle(
    *,
    output_path: str | os.PathLike[str],
    trust: BaseModelSelectionTrust,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    candidate_sources: Iterable[BaseModelSelectionCandidateSource],
    selected_candidate_id: str,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    baseline_attestation_trust: BaseResponseAttestationTrust,
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None = None,
) -> VerifiedBaseModelSelectionSigningBundle:
    _, spki, audience, key_id, signer_role = _validate_trust(trust)
    _require_distinct_upstream_signers(
        spki, evaluation_authoring_approval_trust, review_receipt_trust
    )
    candidate_sources_value = tuple(candidate_sources)
    build_arguments = {
        "candidate_sources": candidate_sources_value,
        "selected_candidate_id": selected_candidate_id,
        "calibration_tasks_path": calibration_tasks_path,
        "calibration_evidence_path": calibration_evidence_path,
        "sealed_tasks_path": sealed_tasks_path,
        "baseline_responses_path": baseline_responses_path,
        "baseline_verifier_results_path": baseline_verifier_results_path,
        "data_release_path": data_release_path,
        "review_receipt_trust": review_receipt_trust,
        "evaluation_authoring_approval_trust": evaluation_authoring_approval_trust,
        "baseline_attestation_trust": baseline_attestation_trust,
        "catalog_path": catalog_path,
        "source_lock_path": source_lock_path,
        "review_receipt_now": review_receipt_now,
        "csharp_verifier_context": csharp_verifier_context,
    }
    bindings = _build_selection_bindings(**build_arguments)
    payload = _build_selection_payload(
        bindings=bindings,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        approval_evidence_path=approval_evidence_path,
        signer_role=signer_role,
    )
    current = _fresh_validation_time(
        now, "base-model selection signing-bundle creation time"
    )
    _ensure_payload_active(
        payload, current, "base-model selection signing bundle payload"
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
        bindings=bindings,
        approval_evidence_path=approval_evidence_path,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        now=current,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_BASE_MODEL_SELECTION_SIGNING_BUNDLE_BYTES:
        _fail("base-model selection signing bundle", "exceeds its byte limit")
    bundle_sha256 = hashlib.sha256(serialized).hexdigest()
    staged_bindings = bindings

    def validate_bundle(
        path: Path, *, replay_live_inputs: bool
    ) -> VerifiedBaseModelSelectionSigningBundle:
        nonlocal staged_bindings
        publication_time = _fresh_validation_time(
            now, "base-model selection signing-bundle publication time"
        )
        resolved, raw, document = _read_canonical_handoff_document(
            path,
            "base-model selection signing bundle",
            MAX_BASE_MODEL_SELECTION_SIGNING_BUNDLE_BYTES,
        )
        if hashlib.sha256(raw).hexdigest() != bundle_sha256:
            _fail("base-model selection signing bundle", "changed during publication")
        _, current_spki, current_audience, current_key_id, current_role = (
            _validate_trust(trust)
        )
        _require_distinct_upstream_signers(
            current_spki, evaluation_authoring_approval_trust, review_receipt_trust
        )
        if replay_live_inputs:
            staged_bindings = _build_selection_bindings(**build_arguments)
        validated = _validate_signing_bundle_document(
            document,
            bindings=staged_bindings,
            approval_evidence_path=approval_evidence_path,
            public_key_spki_sha256=current_spki,
            audience=current_audience,
            key_id=current_key_id,
            signer_role=current_role,
            now=publication_time,
        )
        return VerifiedBaseModelSelectionSigningBundle(
            path=resolved,
            bundle=validated,
            bundle_sha256=bundle_sha256,
            bundle_id=validated["bundleId"],
            selection_id=validated["selectionId"],
            payload_sha256=validated["request"]["payloadSha256"],
            public_key_spki_sha256=current_spki,
        )

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=lambda path: validate_bundle(
            path, replay_live_inputs=True
        ),
        installed_validator=lambda path: validate_bundle(
            path, replay_live_inputs=False
        ),
        field="base-model selection signing-bundle output",
    )


def finalize_base_model_selection(
    *,
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    trust: BaseModelSelectionTrust,
    candidate_sources: Iterable[BaseModelSelectionCandidateSource],
    selected_candidate_id: str,
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    baseline_attestation_trust: BaseResponseAttestationTrust,
    catalog_path: str | os.PathLike[str],
    source_lock_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    now: datetime | None = None,
    csharp_verifier_context: CSharpVerifierExecutionContext | None = None,
) -> VerifiedBaseModelSelection:
    public_key, spki, audience, key_id, signer_role = _validate_trust(trust)
    _require_distinct_upstream_signers(
        spki, evaluation_authoring_approval_trust, review_receipt_trust
    )
    _, bundle_bytes, bundle_document = _read_canonical_handoff_document(
        signing_bundle_path,
        "base-model selection signing bundle",
        MAX_BASE_MODEL_SELECTION_SIGNING_BUNDLE_BYTES,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "base-model selection external signature",
        MAX_BASE_MODEL_SELECTION_EXTERNAL_SIGNATURE_BYTES,
    )
    candidate_sources_value = tuple(candidate_sources)
    bindings = _build_selection_bindings(
        candidate_sources=candidate_sources_value,
        selected_candidate_id=selected_candidate_id,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
        review_receipt_now=review_receipt_now,
        csharp_verifier_context=csharp_verifier_context,
    )
    current = _fresh_validation_time(now, "base-model selection finalization time")
    bundle = _validate_signing_bundle_document(
        bundle_document,
        bindings=bindings,
        approval_evidence_path=approval_evidence_path,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
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
        "base-model selection signing bundle.request.payload",
        max_bytes=MAX_BASE_MODEL_SELECTION_PAYLOAD_BYTES,
    )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    envelope["signature"] = _base64url_encode(signature)
    post_signature_time = _fresh_validation_time(
        now, "base-model selection post-signature validation time"
    )
    _validate_envelope_document(envelope, trust=trust, now=post_signature_time)
    serialized = _serialize_selection_envelope(envelope)
    if len(serialized) > MAX_BASE_MODEL_SELECTION_ENVELOPE_BYTES:
        _fail("base-model selection envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(serialized).hexdigest()
    live_arguments = _selection_live_arguments(
        candidate_sources=candidate_sources_value,
        selected_candidate_id=selected_candidate_id,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        catalog_path=catalog_path,
        source_lock_path=source_lock_path,
        approval_evidence_path=approval_evidence_path,
        review_receipt_now=review_receipt_now,
        csharp_verifier_context=csharp_verifier_context,
    )

    def validate_staged(path: Path) -> VerifiedBaseModelSelection:
        validated = validate_base_model_selection(
            path,
            trust=trust,
            now=_fresh_validation_time(
                now, "base-model selection finalization publication time"
            ),
            **live_arguments,
        )
        if validated.envelope_sha256 != envelope_sha256:
            _fail("base-model selection output", "changed during staged publication")
        return validated

    def validate_installed(path: Path) -> VerifiedBaseModelSelection:
        return _verify_installed_selection(
            path,
            trust=trust,
            expected_envelope_sha256=envelope_sha256,
            now=now,
            field="base-model selection output",
        )

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_staged,
        installed_validator=validate_installed,
    )
