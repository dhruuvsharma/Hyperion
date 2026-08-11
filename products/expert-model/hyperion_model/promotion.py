from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import tempfile
import unicodedata
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifacts import (
    ARTIFACT_METADATA_NAME,
    validate_training_artifact,
    verify_training_artifact_trainer_provenance,
)
from .base_selection import (
    BaseModelSelectionTrust,
    VerifiedBaseModelSelectionTarget,
    validate_base_model_selection_manifest_target,
)
from .core import (
    MAX_JSON_BYTES,
    ValidatedManifestSnapshot,
    _exact_keys,
    _fail,
    _integer,
    _read_file_bounded,
    _reject_constant,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _validate_data_release_identity,
    canonical_json_bytes,
    load_json_document,
    sha256_file,
    validate_candidate_catalog,
)
from .deployment import (
    EXECUTION_MODEL_PREFIX,
    MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
    ServingProfile,
    compute_model_readiness_v2_proof,
    validate_model_readiness_v2_attestation,
    validate_serving_profile,
)
from .evaluation import (
    EVALUATION_RESPONSE_SCHEMA_VERSION,
    MAX_EVALUATION_BYTES,
    BaseResponseAttestationTrust,
    aggregate_promotion_evidence,
    validate_promotion_evidence,
)
from .evaluation_authoring import EvaluationAuthoringApprovalTrust
from .release import (
    MAX_REVIEW_ASSET_BYTES,
    validate_corpus_evaluation_release_with_identity,
    validate_training_release_binding,
)
from .review_receipts import ExpertModelReviewReceiptTrust
from .trainer_provenance import TrainerProvenanceTrust
from .verifier_authority import (
    _bounded_snapshot,
    _normalize_external_signature,
    _read_canonical_handoff_document,
    _write_no_clobber as _write_owned_no_clobber,
)
from .verifier_replay_audit import (
    CSharpVerifierReplayAuditTrust,
    validate_csharp_verifier_replay_audit,
)


MODEL_PROMOTION_SCHEMA_VERSION = "daxalgo.hyperion.model-promotion/v1"
MODEL_PROMOTION_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.model-promotion-envelope/v1"
)
MODEL_PROMOTION_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.hyperion.model-promotion-signing-bundle/v1"
)
MODEL_PROMOTION_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.hyperion.model-promotion-signature/v1"
)
HOSTED_DEPLOYMENT_POLICY_V1_SCHEMA_VERSION = (
    "daxalgo.hyperion.hosted-deployment-policy/v1"
)
HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION = (
    "daxalgo.hyperion.hosted-deployment-policy/v2"
)
HOSTED_DEPLOYMENT_POLICY_SCHEMA_VERSION = HOSTED_DEPLOYMENT_POLICY_V1_SCHEMA_VERSION
PROMOTION_SIGNATURE_DOMAIN = "daxalgo-hyperion-model-promotion-signature/v1"
PROMOTION_ID_DOMAIN = "daxalgo-hyperion-model-promotion-id/v1"
HOSTED_DEPLOYMENT_POLICY_V1_DOMAIN = "daxalgo-hyperion-hosted-deployment-policy/v1"
HOSTED_DEPLOYMENT_POLICY_V2_DOMAIN = "daxalgo-hyperion-hosted-deployment-policy/v2"
EXPERT_CONTEXT_QUERY_POLICY_DOMAIN = "daxalgo-hyperion-expert-context-query-policy/v1"
PROMOTION_DECISION = "approved-for-production"
PROMOTION_PAYLOAD_ENCODING = "base64url"
PROMOTION_ALGORITHM = "ES256"
PROMOTION_SIGNATURE_FORMAT = "ieee-p1363"
PROMOTION_ID_PREFIX = "vqprom-"
PROMOTION_SIGNING_BUNDLE_ID_PREFIX = "vqpromsigning-"
PROMOTION_EXTERNAL_SIGNATURE_ID_PREFIX = "vqpromsignature-"
PROMOTION_SIGNING_STATUS = "unsigned-non-authorizing"
PROMOTION_SIGNING_HASH_ALGORITHM = "SHA-256"
PROMOTION_EXTERNAL_RAW_MESSAGE_MODE = "raw-message"
PROMOTION_EXTERNAL_SHA256_DIGEST_MODE = "sha256-digest"
PROMOTION_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
PROMOTION_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
MAX_PROMOTION_ENVELOPE_BYTES = 1_000_000
MAX_PROMOTION_PAYLOAD_BYTES = 500_000
MAX_PROMOTION_SIGNING_BUNDLE_BYTES = 4_000_000
MAX_PROMOTION_EXTERNAL_SIGNATURE_BYTES = 16_000
MAX_PROMOTION_SIGNATURE_INPUT_BYTES = 1_000_000
MAX_PUBLIC_KEY_BYTES = 64_000
MAX_PRIVATE_KEY_BYTES = 1_000_000
MAX_VALIDITY = timedelta(days=366)

_ZERO_SHA256 = "0" * 64
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
_CORPUS_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_MUTABLE_CORPUS_VERSIONS = frozenset({"latest", "main", "master", "trunk"})
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_PROMOTION_ID_RE = re.compile(r"^vqprom-[0-9a-f]{64}$")
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqpromsigning-[0-9a-f]{64}$")
_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqpromsignature-[0-9a-f]{64}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_CANONICAL_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_SIGNING_BUNDLE_ID_DOMAIN = "daxalgo-hyperion-model-promotion-signing-bundle-id/v1"
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    "daxalgo-hyperion-model-promotion-external-signature-id/v1"
)
_SIGNING_AUTHORITY_KEYS = {
    "baseSelection",
    "checkpoint",
    "corpusReview",
    "csharpVerifierReplayAuditIssuance",
    "deployment",
    "evaluation",
    "evaluationAuthoring",
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
    "promotionId",
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
    "promotionId",
    "payloadSha256",
    "unsignedEnvelopeSha256",
    "signatureInputSha256",
    "publicKeySpkiSha256",
    "mode",
    "format",
    "signature",
}
_PROMOTION_LIVE_ARGUMENT_NAMES = (
    "promotion_evidence_path",
    "calibration_tasks_path",
    "calibration_evidence_path",
    "sealed_tasks_path",
    "responses_path",
    "verifier_results_path",
    "baseline_responses_path",
    "baseline_verifier_results_path",
    "policy_path",
    "data_release_path",
    "review_receipt_trust",
    "evaluation_authoring_approval_trust",
    "trainer_provenance_trust",
    "base_selection_trust",
    "base_model_snapshot_path",
    "candidate_attestation_trust",
    "baseline_attestation_trust",
    "csharp_verifier_replay_audit_path",
    "csharp_verifier_replay_audit_trust",
    "expected_csharp_verifier_replay_audit_envelope_sha256",
    "csharp_verifier_replay_audit_now",
    "catalog_path",
    "serving_profile_path",
    "artifact_path",
    "manifest_path",
    "approval_evidence_path",
    "hosted_deployment_policy_path",
    "review_receipt_now",
    "trainer_provenance_now",
)


@dataclass(frozen=True)
class PromotionActivationInputs:
    manifest_snapshot: ValidatedManifestSnapshot
    selected_base: VerifiedBaseModelSelectionTarget
    artifact: dict[str, Any]
    profile: ServingProfile
    authority_expires_at_utc: str
    evaluation_authoring_approval_payload_sha256: str
    evaluation_authoring_approval_envelope_sha256: str
    trainer_provenance_payload_sha256: str
    trainer_provenance_envelope_sha256: str
    trainer_provenance_expires_at_utc: str
    csharp_verifier_replay_audit_payload_sha256: str | None = None
    csharp_verifier_replay_audit_envelope_sha256: str | None = None


@dataclass(frozen=True)
class VerifiedModelPromotion:
    path: Path
    envelope: dict[str, Any]
    payload: dict[str, Any]
    payload_bytes: bytes
    payload_sha256: str
    envelope_sha256: str
    activation_inputs: PromotionActivationInputs | None = dataclass_field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True)
class VerifiedModelPromotionSigningBundle:
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


@dataclass(frozen=True)
class _CSharpVerifierReplayAuditTimeline:
    replay_completed_at: datetime
    approved_at: datetime
    issued_at: datetime


@dataclass(frozen=True)
class _PromotionBindings:
    data_release: dict[str, str]
    evidence: dict[str, Any]
    model: dict[str, Any]
    report: dict[str, Any]
    authority_signer_spki_sha256s: tuple[tuple[str, str], ...]
    manifest_created_at: datetime
    artifact_recorded_at: datetime
    trainer_provenance_issued_at: datetime
    trainer_provenance_not_before: datetime
    activation_inputs: PromotionActivationInputs
    csharp_verifier_replay_audit_timeline: _CSharpVerifierReplayAuditTimeline | None = (
        None
    )


def _reject_authority_signer_collision(
    signer_field: str,
    signer_spki_sha256: str,
    authority_signer_spki_sha256s: tuple[tuple[str, str], ...],
) -> None:
    for authority_role, authority_spki_sha256 in authority_signer_spki_sha256s:
        if signer_spki_sha256 == authority_spki_sha256:
            _fail(
                signer_field,
                f"must differ from the {authority_role} signer",
            )


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _SAFE_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _provider_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not _PROVIDER_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII provider identifier")
    return text


def _corpus_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not _CORPUS_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII corpus identifier")
    return text


def _corpus_version(value: Any, field: str) -> str:
    text = _corpus_id(value, field)
    if text.casefold() in _MUTABLE_CORPUS_VERSIONS:
        _fail(field, "must identify an immutable corpus version")
    return text


def _model_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _MODEL_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII model identifier")
    return text


def _profile_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", text):
        _fail(field, "must be a safe ASCII profile identifier")
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


def _canonical_decimal(value: Any, field: str, *, positive: bool = False) -> str:
    if not isinstance(value, str):
        _fail(field, "must be a canonical decimal string")
    match = _CANONICAL_DECIMAL_RE.fullmatch(value)
    if match is None or (match.group(2) is not None and match.group(2).endswith("0")):
        _fail(
            field,
            "must be canonical decimal text without leading or fractional trailing zeros",
        )
    try:
        number = Decimal(value)
    except InvalidOperation:
        _fail(field, "must be a canonical decimal string")
    if number < 0 or number > Decimal("1000000000") or (positive and number <= 0):
        qualifier = "positive and " if positive else ""
        _fail(field, f"must be {qualifier}no more than 1000000000")
    return value


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


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
    except (json.JSONDecodeError, RecursionError) as error:
        _fail(field, f"invalid bounded JSON: {error}")
    if not isinstance(value, dict):
        _fail(field, "must have an object root")
    return value


def expert_context_query_policy_sha256(policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        _framed(
            (
                EXPERT_CONTEXT_QUERY_POLICY_DOMAIN,
                str(policy["schemaVersion"]),
                str(policy["topK"]),
                str(policy["maxCharacters"]),
                str(policy["maxPerSource"]),
            )
        )
    ).hexdigest()


def _hosted_policy_fields(policy: Mapping[str, Any]) -> list[str]:
    schema_version = policy["schemaVersion"]
    if schema_version == HOSTED_DEPLOYMENT_POLICY_V1_SCHEMA_VERSION:
        domain = HOSTED_DEPLOYMENT_POLICY_V1_DOMAIN
    elif schema_version == HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION:
        domain = HOSTED_DEPLOYMENT_POLICY_V2_DOMAIN
    else:
        _fail(
            "hosted deployment policy.schemaVersion",
            "is not a supported hosted deployment policy schema",
        )
    pricing = policy["pricing"]
    execution = policy["execution"]
    coordinator = policy["coordinator"]
    expert = policy["expertContext"]
    query = expert["queryPolicy"]
    fields = [
        domain,
        schema_version,
        policy["providerId"],
        policy["protocol"],
        pricing["inputUsdPerMillionTokens"],
        pricing["outputUsdPerMillionTokens"],
        str(pricing["creditsPerUsd"]),
        str(pricing["minimumChargeCredits"]),
        pricing["creditPricingVersion"],
        str(execution["maxRequests"]),
        str(execution["maxAttemptsPerRole"]),
        str(execution["maxPromptTokens"]),
        str(execution["maxOutputTokens"]),
        str(execution["maxOutputTokensPerRequest"]),
        execution["maxCostUsd"],
        str(execution["maxResponseBytes"]),
        str(execution["maxArtifactBytes"]),
        str(execution["maxElapsedSeconds"]),
        str(execution["requestTimeoutSeconds"]),
        _bool_text(execution["requireReportedUsage"]),
        str(execution["maxActiveRunsPerAccount"]),
        str(execution["workerPollMilliseconds"]),
        str(execution["modelAttestationTimeoutSeconds"]),
        str(execution["modelAttestationRefreshSeconds"]),
        str(execution["modelAttestationTtlSeconds"]),
        coordinator["policyVersion"],
        coordinator["workflowVersion"],
        coordinator["promptCatalogSha256"],
    ]
    if schema_version == HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION:
        capability = policy["strategyAuthoringCapability"]
        fields.extend(
            [
                capability["purpose"],
                capability["executionModelId"],
                capability["policyVersion"],
                capability["workflowVersion"],
                capability["promptCatalogSha256"],
            ]
        )
    fields.extend(
        [
            expert["mode"],
            expert["corpusId"],
            expert["corpusVersion"],
            expert["packSha256"],
            query["schemaVersion"],
            str(query["topK"]),
            str(query["maxCharacters"]),
            str(query["maxPerSource"]),
            expert["queryPolicySha256"],
            str(expert["queryMaxCharacters"]),
        ]
    )
    return fields


def hosted_deployment_policy_sha256(policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(_framed(_hosted_policy_fields(policy))).hexdigest()


def _validate_hosted_deployment_policy_document(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("hosted deployment policy", "must be an object")
    schema_version = value.get("schemaVersion")
    if schema_version not in {
        HOSTED_DEPLOYMENT_POLICY_V1_SCHEMA_VERSION,
        HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION,
    }:
        _fail(
            "hosted deployment policy.schemaVersion",
            "must be a supported hosted deployment policy schema",
        )
    expected_keys = {
        "schemaVersion",
        "policySha256",
        "providerId",
        "protocol",
        "pricing",
        "execution",
        "coordinator",
        "expertContext",
    }
    if schema_version == HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION:
        expected_keys.add("strategyAuthoringCapability")
    policy = _exact_keys(
        value,
        expected_keys,
        "hosted deployment policy",
    )
    _provider_id(policy["providerId"], "hosted deployment policy.providerId")
    if policy["protocol"] != "openai-compatible":
        _fail("hosted deployment policy.protocol", "must be 'openai-compatible'")
    pricing = _exact_keys(
        policy["pricing"],
        {
            "inputUsdPerMillionTokens",
            "outputUsdPerMillionTokens",
            "creditsPerUsd",
            "minimumChargeCredits",
            "creditPricingVersion",
        },
        "hosted deployment policy.pricing",
    )
    _canonical_decimal(
        pricing["inputUsdPerMillionTokens"],
        "hosted deployment policy.pricing.inputUsdPerMillionTokens",
    )
    _canonical_decimal(
        pricing["outputUsdPerMillionTokens"],
        "hosted deployment policy.pricing.outputUsdPerMillionTokens",
    )
    _integer(
        pricing["creditsPerUsd"],
        "hosted deployment policy.pricing.creditsPerUsd",
        1,
        1_000_000_000,
    )
    _integer(
        pricing["minimumChargeCredits"],
        "hosted deployment policy.pricing.minimumChargeCredits",
        0,
        1_000_000_000,
    )
    _text(
        pricing["creditPricingVersion"],
        "hosted deployment policy.pricing.creditPricingVersion",
        max_length=100,
    )

    execution = _exact_keys(
        policy["execution"],
        {
            "maxRequests",
            "maxAttemptsPerRole",
            "maxPromptTokens",
            "maxOutputTokens",
            "maxOutputTokensPerRequest",
            "maxCostUsd",
            "maxResponseBytes",
            "maxArtifactBytes",
            "maxElapsedSeconds",
            "requestTimeoutSeconds",
            "requireReportedUsage",
            "maxActiveRunsPerAccount",
            "workerPollMilliseconds",
            "modelAttestationTimeoutSeconds",
            "modelAttestationRefreshSeconds",
            "modelAttestationTtlSeconds",
        },
        "hosted deployment policy.execution",
    )
    integer_ranges = {
        "maxRequests": (1, 100),
        "maxAttemptsPerRole": (1, 10),
        "maxPromptTokens": (1, 10_000_000),
        "maxOutputTokens": (1, 10_000_000),
        "maxOutputTokensPerRequest": (1, 1_000_000),
        "maxResponseBytes": (1, 2_000_000),
        "maxArtifactBytes": (1, 2_000_000),
        "maxElapsedSeconds": (1, 86_400),
        "requestTimeoutSeconds": (1, 3_600),
        "maxActiveRunsPerAccount": (1, 100),
        "workerPollMilliseconds": (50, 60_000),
        "modelAttestationTimeoutSeconds": (1, 60),
        "modelAttestationRefreshSeconds": (5, 300),
        "modelAttestationTtlSeconds": (10, 900),
    }
    for name, (minimum, maximum) in integer_ranges.items():
        _integer(
            execution[name],
            f"hosted deployment policy.execution.{name}",
            minimum,
            maximum,
        )
    _canonical_decimal(
        execution["maxCostUsd"],
        "hosted deployment policy.execution.maxCostUsd",
        positive=True,
    )
    if not isinstance(execution["requireReportedUsage"], bool):
        _fail(
            "hosted deployment policy.execution.requireReportedUsage",
            "must be a boolean",
        )
    if execution["maxOutputTokensPerRequest"] > execution["maxOutputTokens"]:
        _fail(
            "hosted deployment policy.execution.maxOutputTokensPerRequest",
            "must not exceed maxOutputTokens",
        )
    if execution["maxElapsedSeconds"] < (execution["requestTimeoutSeconds"] * 2 + 60):
        _fail(
            "hosted deployment policy.execution.maxElapsedSeconds",
            "must permit one timeout, recovery, and retry",
        )
    if not (
        execution["modelAttestationTimeoutSeconds"]
        < execution["modelAttestationRefreshSeconds"]
        < execution["modelAttestationTtlSeconds"]
    ):
        _fail(
            "hosted deployment policy.execution",
            "model-attestation timeout must be below refresh and refresh below TTL",
        )

    coordinator = _exact_keys(
        policy["coordinator"],
        {"policyVersion", "workflowVersion", "promptCatalogSha256"},
        "hosted deployment policy.coordinator",
    )
    _text(
        coordinator["policyVersion"],
        "hosted deployment policy.coordinator.policyVersion",
        max_length=100,
    )
    _text(
        coordinator["workflowVersion"],
        "hosted deployment policy.coordinator.workflowVersion",
        max_length=100,
    )
    _sha256(
        coordinator["promptCatalogSha256"],
        "hosted deployment policy.coordinator.promptCatalogSha256",
    )

    if schema_version == HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION:
        capability = _exact_keys(
            policy["strategyAuthoringCapability"],
            {
                "purpose",
                "executionModelId",
                "policyVersion",
                "workflowVersion",
                "promptCatalogSha256",
            },
            "hosted deployment policy.strategyAuthoringCapability",
        )
        if capability["purpose"] != "StrategyAuthoring":
            _fail(
                "hosted deployment policy.strategyAuthoringCapability.purpose",
                "must be 'StrategyAuthoring'",
            )
        execution_model_id = capability["executionModelId"]
        if not isinstance(execution_model_id, str) or not re.fullmatch(
            rf"{re.escape(EXECUTION_MODEL_PREFIX)}[0-9a-f]{{64}}",
            execution_model_id,
        ):
            _fail(
                "hosted deployment policy.strategyAuthoringCapability.executionModelId",
                "must be a canonical execution-model identity",
            )
        if capability["policyVersion"] != "strategy-authoring-inert/v1":
            _fail(
                "hosted deployment policy.strategyAuthoringCapability.policyVersion",
                "must be 'strategy-authoring-inert/v1'",
            )
        if capability["workflowVersion"] != "fixed-strategy-authoring/v1":
            _fail(
                "hosted deployment policy.strategyAuthoringCapability.workflowVersion",
                "must be 'fixed-strategy-authoring/v1'",
            )
        _sha256(
            capability["promptCatalogSha256"],
            "hosted deployment policy.strategyAuthoringCapability.promptCatalogSha256",
        )

    expert = _exact_keys(
        policy["expertContext"],
        {
            "mode",
            "corpusId",
            "corpusVersion",
            "packSha256",
            "queryPolicy",
            "queryPolicySha256",
            "queryMaxCharacters",
        },
        "hosted deployment policy.expertContext",
    )
    if expert["mode"] != "Pinned":
        _fail("hosted deployment policy.expertContext.mode", "must be 'Pinned'")
    _corpus_id(expert["corpusId"], "hosted deployment policy.expertContext.corpusId")
    _corpus_version(
        expert["corpusVersion"],
        "hosted deployment policy.expertContext.corpusVersion",
    )
    _sha256(expert["packSha256"], "hosted deployment policy.expertContext.packSha256")
    query = _exact_keys(
        expert["queryPolicy"],
        {"schemaVersion", "topK", "maxCharacters", "maxPerSource"},
        "hosted deployment policy.expertContext.queryPolicy",
    )
    if query["schemaVersion"] != "daxalgo-expert-context-query-policy/v1":
        _fail(
            "hosted deployment policy.expertContext.queryPolicy.schemaVersion",
            "must be 'daxalgo-expert-context-query-policy/v1'",
        )
    _integer(
        query["topK"], "hosted deployment policy.expertContext.queryPolicy.topK", 1, 100
    )
    _integer(
        query["maxCharacters"],
        "hosted deployment policy.expertContext.queryPolicy.maxCharacters",
        1,
        500_000,
    )
    _integer(
        query["maxPerSource"],
        "hosted deployment policy.expertContext.queryPolicy.maxPerSource",
        1,
        100,
    )
    if query["maxPerSource"] > query["topK"]:
        _fail(
            "hosted deployment policy.expertContext.queryPolicy.maxPerSource",
            "must not exceed topK",
        )
    _integer(
        expert["queryMaxCharacters"],
        "hosted deployment policy.expertContext.queryMaxCharacters",
        1,
        1_000_000,
    )
    expected_query_hash = expert_context_query_policy_sha256(query)
    if (
        _sha256(
            expert["queryPolicySha256"],
            "hosted deployment policy.expertContext.queryPolicySha256",
        )
        != expected_query_hash
    ):
        _fail(
            "hosted deployment policy.expertContext.queryPolicySha256",
            "does not match the canonical query policy",
        )
    expected_policy_hash = hosted_deployment_policy_sha256(policy)
    if (
        _sha256(policy["policySha256"], "hosted deployment policy.policySha256")
        != expected_policy_hash
    ):
        _fail(
            "hosted deployment policy.policySha256",
            "does not match the canonical hosted deployment policy",
        )
    return policy


def validate_hosted_deployment_policy(
    path: str | os.PathLike[str],
) -> dict[str, Any]:
    return _validate_hosted_deployment_policy_document(load_json_document(path))


def _promotion_id_fields(payload: Mapping[str, Any]) -> list[str]:
    release = payload["dataRelease"]
    evidence = payload["promotionEvidence"]
    model = payload["model"]
    deployment = payload["deployment"]
    approval = payload["approval"]
    policy = payload["hostedDeploymentPolicy"]
    return [
        PROMOTION_ID_DOMAIN,
        payload["schemaVersion"],
        payload["decision"],
        _bool_text(payload["productionEligible"]),
        payload["issuedAtUtc"],
        payload["notBeforeUtc"],
        payload["expiresAtUtc"],
        release["releaseId"],
        release["releaseSha256"],
        release["manifestSha256"],
        *[evidence[name] for name in _EVIDENCE_FIELDS],
        *[model[name] for name in _MODEL_FIELDS],
        deployment["deploymentId"],
        deployment["environment"],
        deployment["audience"],
        approval["approvalId"],
        approval["actorId"],
        approval["actorRole"],
        approval["reference"],
        approval["approvedAtUtc"],
        approval["evidenceSha256"],
        str(approval["evidenceSizeBytes"]),
        policy["schemaVersion"],
        policy["policySha256"],
        *(_hosted_policy_fields(policy)[2:]),
    ]


def model_promotion_id(payload: Mapping[str, Any]) -> str:
    return (
        PROMOTION_ID_PREFIX
        + hashlib.sha256(_framed(_promotion_id_fields(payload))).hexdigest()
    )


def _handoff_content_id(
    value: Mapping[str, Any],
    *,
    identity_field: str,
    prefix: str,
    domain: str,
) -> str:
    normalized = dict(value)
    normalized[identity_field] = prefix + _ZERO_SHA256
    digest = hashlib.sha256(
        _framed((domain, canonical_json_bytes(normalized)))
    ).hexdigest()
    return prefix + digest


def model_promotion_signing_bundle_id(value: Mapping[str, Any]) -> str:
    return _handoff_content_id(
        value,
        identity_field="bundleId",
        prefix=PROMOTION_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def model_promotion_external_signature_id(value: Mapping[str, Any]) -> str:
    return _handoff_content_id(
        value,
        identity_field="signatureId",
        prefix=PROMOTION_EXTERNAL_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


_EVIDENCE_FIELDS = (
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

_MODEL_FIELDS = (
    "candidateCatalogSha256",
    "candidateId",
    "modelId",
    "modelRevision",
    "trainingRunManifestSha256",
    "artifactMetadataFileSha256",
    "artifactSha256",
    "artifactTreeSha256",
    "servingProfileId",
    "servingProfileSha256",
    "executionModelId",
    "chatTemplateSha256",
    "containerImageDigest",
)


def _validate_promotion_payload_document(value: Any) -> dict[str, Any]:
    payload = _exact_keys(
        value,
        {
            "schemaVersion",
            "promotionId",
            "decision",
            "productionEligible",
            "issuedAtUtc",
            "notBeforeUtc",
            "expiresAtUtc",
            "dataRelease",
            "promotionEvidence",
            "model",
            "deployment",
            "approval",
            "hostedDeploymentPolicy",
        },
        "model promotion payload",
    )
    if payload["schemaVersion"] != MODEL_PROMOTION_SCHEMA_VERSION:
        _fail(
            "model promotion payload.schemaVersion",
            f"must be {MODEL_PROMOTION_SCHEMA_VERSION!r}",
        )
    if not isinstance(payload["promotionId"], str) or not _PROMOTION_ID_RE.fullmatch(
        payload["promotionId"]
    ):
        _fail("model promotion payload.promotionId", "must be a canonical vqprom ID")
    if payload["decision"] != PROMOTION_DECISION:
        _fail("model promotion payload.decision", f"must be {PROMOTION_DECISION!r}")
    if payload["productionEligible"] is not True:
        _fail("model promotion payload.productionEligible", "must be true")
    issued = _canonical_utc(
        payload["issuedAtUtc"], "model promotion payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "model promotion payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "model promotion payload.expiresAtUtc"
    )

    _validate_data_release_identity(
        payload["dataRelease"], "model promotion payload.dataRelease", allow_none=False
    )
    evidence = _exact_keys(
        payload["promotionEvidence"],
        set(_EVIDENCE_FIELDS),
        "model promotion payload.promotionEvidence",
    )
    for name in _EVIDENCE_FIELDS:
        _sha256(evidence[name], f"model promotion payload.promotionEvidence.{name}")

    model = _exact_keys(
        payload["model"], set(_MODEL_FIELDS), "model promotion payload.model"
    )
    for name in (
        "candidateCatalogSha256",
        "trainingRunManifestSha256",
        "artifactMetadataFileSha256",
        "artifactSha256",
        "artifactTreeSha256",
        "servingProfileSha256",
        "chatTemplateSha256",
    ):
        _sha256(model[name], f"model promotion payload.model.{name}")
    _profile_id(model["candidateId"], "model promotion payload.model.candidateId")
    _model_id(model["modelId"], "model promotion payload.model.modelId")
    _revision(model["modelRevision"], "model promotion payload.model.modelRevision")
    _profile_id(
        model["servingProfileId"], "model promotion payload.model.servingProfileId"
    )
    if (
        model["executionModelId"]
        != EXECUTION_MODEL_PREFIX + model["servingProfileSha256"]
    ):
        _fail(
            "model promotion payload.model.executionModelId",
            "must be derived from servingProfileSha256",
        )
    image_digest = model["containerImageDigest"]
    if not isinstance(image_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", image_digest
    ):
        _fail(
            "model promotion payload.model.containerImageDigest",
            "must be a lowercase SHA-256 OCI digest",
        )

    deployment = _exact_keys(
        payload["deployment"],
        {"deploymentId", "environment", "audience"},
        "model promotion payload.deployment",
    )
    for name in deployment:
        _identifier(deployment[name], f"model promotion payload.deployment.{name}")

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
        "model promotion payload.approval",
    )
    for name in ("approvalId", "actorId", "actorRole"):
        _identifier(approval[name], f"model promotion payload.approval.{name}")
    _text(
        approval["reference"],
        "model promotion payload.approval.reference",
        max_length=500,
    )
    approved = _canonical_utc(
        approval["approvedAtUtc"], "model promotion payload.approval.approvedAtUtc"
    )
    _sha256(
        approval["evidenceSha256"], "model promotion payload.approval.evidenceSha256"
    )
    _integer(
        approval["evidenceSizeBytes"],
        "model promotion payload.approval.evidenceSizeBytes",
        1,
        MAX_REVIEW_ASSET_BYTES,
    )
    if not approved <= issued <= not_before < expires:
        _fail(
            "model promotion payload validity",
            "must satisfy approvedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_VALIDITY:
        _fail("model promotion payload validity", "must not exceed 366 days")

    hosted_policy = _validate_hosted_deployment_policy_document(
        payload["hostedDeploymentPolicy"]
    )
    if hosted_policy["schemaVersion"] == HOSTED_DEPLOYMENT_POLICY_V2_SCHEMA_VERSION:
        capability = hosted_policy["strategyAuthoringCapability"]
        if capability["executionModelId"] != model["executionModelId"]:
            _fail(
                "model promotion payload.hostedDeploymentPolicy."
                "strategyAuthoringCapability.executionModelId",
                "must match model.executionModelId",
            )
    expected_id = model_promotion_id(payload)
    if payload["promotionId"] != expected_id:
        _fail(
            "model promotion payload.promotionId",
            "does not match the content-derived promotion identity",
        )
    return payload


def _signature_input(envelope: Mapping[str, Any], payload_bytes: bytes) -> bytes:
    return _framed(
        (
            PROMOTION_SIGNATURE_DOMAIN,
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
        "schemaVersion": MODEL_PROMOTION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": MODEL_PROMOTION_SCHEMA_VERSION,
        "payloadEncoding": PROMOTION_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": PROMOTION_ALGORITHM,
        "signatureFormat": PROMOTION_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": public_key_spki_sha256,
        "signature": "",
    }


def _serialize_promotion_envelope(envelope: Mapping[str, Any]) -> bytes:
    serialized = (
        json.dumps(envelope, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    ).encode("utf-8")
    if len(serialized) > MAX_PROMOTION_ENVELOPE_BYTES:
        _fail("model promotion signed envelope", "exceeds its byte limit")
    return serialized


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
            "model promotion cryptography",
            "requires the optional 'promote' dependency",
        )
    return (
        InvalidSignature,
        hashes,
        serialization,
        ec,
        (decode_dss_signature, encode_dss_signature),
    )


def _load_public_key(path: str | os.PathLike[str]) -> tuple[Any, bytes, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _read_file_bounded(
        Path(path), "model promotion public key", MAX_PUBLIC_KEY_BYTES
    )
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("model promotion public key", "must be BOM-less PEM")
    try:
        pem = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("model promotion public key", "must be valid UTF-8 PEM")
    if any(
        character == "\r" and (index + 1 >= len(pem) or pem[index + 1] != "\n")
        for index, character in enumerate(pem)
    ):
        _fail("model promotion public key", "must be canonical PEM")
    normalized = pem.replace("\r\n", "\n")
    if normalized.endswith("\n"):
        normalized = normalized[:-1]
    lines = normalized.split("\n")
    if (
        len(lines) < 3
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[-1] != "-----END PUBLIC KEY-----"
    ):
        _fail(
            "model promotion public key",
            "must contain one PUBLIC KEY PEM block",
        )
    body_lines = lines[1:-1]
    for index, line in enumerate(body_lines):
        is_last = index == len(body_lines) - 1
        if (
            not 1 <= len(line) <= 64
            or (not is_last and len(line) != 64)
            or re.fullmatch(r"[A-Za-z0-9+/=]+", line) is None
            or (not is_last and "=" in line)
        ):
            _fail("model promotion public key", "must be canonical PEM")
    body = "".join(body_lines)
    padding_index = body.find("=")
    if len(body) % 4 != 0 or (
        padding_index >= 0
        and (
            padding_index < len(body) - 2
            or any(character != "=" for character in body[padding_index:])
        )
    ):
        _fail("model promotion public key", "must be canonical PEM")
    try:
        spki = base64.b64decode(body, validate=True)
        key = serialization.load_der_public_key(spki)
    except (TypeError, ValueError, base64.binascii.Error) as error:
        _fail(
            "model promotion public key",
            f"must be a valid canonical PUBLIC KEY PEM block: {error}",
        )
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("model promotion public key", "must be an EC P-256 public key")
    canonical_spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if spki != canonical_spki:
        _fail("model promotion public key", "must use canonical P-256 SPKI bytes")
    return key, spki, hashlib.sha256(spki).hexdigest()


def _load_private_key(
    path: str | os.PathLike[str], password: bytes | None
) -> tuple[Any, str]:
    _, _, serialization, ec, _ = _crypto_modules()
    raw = _read_file_bounded(
        Path(path), "model promotion private key", MAX_PRIVATE_KEY_BYTES
    )
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as error:
        _fail(
            "model promotion private key", f"must be a valid PEM private key: {error}"
        )
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail("model promotion private key", "must be an EC P-256 private key")
    public_spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, hashlib.sha256(public_spki).hexdigest()


def _sign_p1363_low_s(private_key: Any, data: bytes) -> bytes:
    _, hashes, _, ec, utilities = _crypto_modules()
    decode_dss_signature, _ = utilities
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    if s > _P256_HALF_ORDER:
        s = _P256_ORDER - s
    if not (1 <= r < _P256_ORDER and 1 <= s <= _P256_HALF_ORDER):
        _fail("model promotion signature", "signer returned invalid P-256 values")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_p1363_low_s(public_key: Any, data: bytes, signature: bytes) -> None:
    InvalidSignature, hashes, _, ec, utilities = _crypto_modules()
    _, encode_dss_signature = utilities
    if len(signature) != 64:
        _fail("model promotion signature", "must be exactly 64-byte IEEE-P1363")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (1 <= r < _P256_ORDER and 1 <= s < _P256_ORDER):
        _fail("model promotion signature", "contains out-of-range P-256 values")
    if s > _P256_HALF_ORDER:
        _fail("model promotion signature", "must use canonical low-S form")
    try:
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        _fail("model promotion signature", "does not verify with the pinned public key")


def _validate_envelope_document(
    value: Any,
    *,
    public_key: Any,
    public_key_spki_sha256: str,
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
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
        "model promotion envelope",
    )
    constants = {
        "schemaVersion": MODEL_PROMOTION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": MODEL_PROMOTION_SCHEMA_VERSION,
        "payloadEncoding": PROMOTION_PAYLOAD_ENCODING,
        "algorithm": PROMOTION_ALGORITHM,
        "signatureFormat": PROMOTION_SIGNATURE_FORMAT,
    }
    for name, expected in constants.items():
        if envelope[name] != expected:
            _fail(f"model promotion envelope.{name}", f"must be {expected!r}")
    audience = _identifier(envelope["audience"], "model promotion envelope.audience")
    key_id = _identifier(envelope["keyId"], "model promotion envelope.keyId")
    signer_role = _identifier(
        envelope["signerRole"], "model promotion envelope.signerRole"
    )
    if audience != _identifier(expected_audience, "expected promotion audience"):
        _fail(
            "model promotion envelope.audience", "does not match trusted configuration"
        )
    if key_id != _identifier(expected_key_id, "expected promotion key ID"):
        _fail("model promotion envelope.keyId", "does not match trusted configuration")
    if signer_role != _identifier(expected_signer_role, "expected signer role"):
        _fail(
            "model promotion envelope.signerRole",
            "does not match trusted configuration",
        )
    if (
        _sha256(
            envelope["publicKeySpkiSha256"],
            "model promotion envelope.publicKeySpkiSha256",
        )
        != public_key_spki_sha256
    ):
        _fail(
            "model promotion envelope.publicKeySpkiSha256",
            "does not match the externally pinned public key",
        )
    payload_bytes = _base64url_decode(
        envelope["payload"],
        "model promotion envelope.payload",
        max_bytes=MAX_PROMOTION_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(envelope["payloadSha256"], "model promotion envelope.payloadSha256")
        != payload_sha256
    ):
        _fail(
            "model promotion envelope.payloadSha256",
            "does not match the exact decoded payload bytes",
        )
    signature = _base64url_decode(
        envelope["signature"], "model promotion envelope.signature", exact_bytes=64
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )
    payload = _load_json_bytes(payload_bytes, "model promotion payload")
    if canonical_json_bytes(payload) != payload_bytes:
        _fail("model promotion payload", "must use exact canonical JSON bytes")
    payload = _validate_promotion_payload_document(payload)
    if payload["deployment"]["audience"] != audience:
        _fail(
            "model promotion payload.deployment.audience",
            "must match the signed envelope audience",
        )
    if payload["approval"]["actorRole"] != signer_role:
        _fail(
            "model promotion payload.approval.actorRole",
            "must match the signed envelope role",
        )
    current = _validation_time(now, "model promotion validation time")
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "model promotion payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "model promotion payload.expiresAtUtc"
    )
    if current < not_before or current >= expires:
        _fail("model promotion payload validity", "is not currently active")
    return envelope, payload, payload_bytes


def _verify_model_promotion_envelope(
    path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    now: datetime | None = None,
    expected_link_count: int,
) -> VerifiedModelPromotion:
    envelope_path = Path(path)
    raw = _bounded_snapshot(
        envelope_path,
        "model promotion envelope",
        MAX_PROMOTION_ENVELOPE_BYTES,
        expected_link_count=expected_link_count,
    )
    envelope_value = _load_json_bytes(raw, "model promotion envelope")
    public_key, _, spki_sha256 = _load_public_key(public_key_path)
    envelope, payload, payload_bytes = _validate_envelope_document(
        envelope_value,
        public_key=public_key,
        public_key_spki_sha256=spki_sha256,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        now=now or datetime.now(timezone.utc),
    )
    return VerifiedModelPromotion(
        path=Path(os.path.abspath(os.fspath(envelope_path))),
        envelope=envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        envelope_sha256=hashlib.sha256(raw).hexdigest(),
    )


def verify_model_promotion_envelope(
    path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    now: datetime | None = None,
) -> VerifiedModelPromotion:
    return _verify_model_promotion_envelope(
        path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        now=now,
        expected_link_count=1,
    )


def _build_promotion_bindings(
    *,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
) -> _PromotionBindings:
    sources: dict[str, tuple[str | os.PathLike[str], int]] = {
        "promotion_evidence_path": (
            promotion_evidence_path,
            MAX_EVALUATION_BYTES,
        ),
        "calibration_tasks_path": (calibration_tasks_path, MAX_EVALUATION_BYTES),
        "calibration_evidence_path": (
            calibration_evidence_path,
            MAX_EVALUATION_BYTES,
        ),
        "sealed_tasks_path": (sealed_tasks_path, MAX_EVALUATION_BYTES),
        "responses_path": (responses_path, MAX_EVALUATION_BYTES),
        "verifier_results_path": (verifier_results_path, MAX_EVALUATION_BYTES),
        "baseline_responses_path": (
            baseline_responses_path,
            MAX_EVALUATION_BYTES,
        ),
        "baseline_verifier_results_path": (
            baseline_verifier_results_path,
            MAX_EVALUATION_BYTES,
        ),
        "policy_path": (policy_path, MAX_JSON_BYTES),
    }
    if csharp_verifier_replay_audit_path is not None:
        if (
            csharp_verifier_replay_audit_trust is None
            or expected_csharp_verifier_replay_audit_envelope_sha256 is None
        ):
            _fail(
                "C# verifier replay audit",
                "requires its exact envelope SHA-256 and external trust",
            )
        validate_csharp_verifier_replay_audit(
            csharp_verifier_replay_audit_path,
            trust=csharp_verifier_replay_audit_trust,
            expected_envelope_sha256=(
                expected_csharp_verifier_replay_audit_envelope_sha256
            ),
            now=csharp_verifier_replay_audit_now,
        )
        sources["csharp_verifier_replay_audit_path"] = (
            csharp_verifier_replay_audit_path,
            MAX_EVALUATION_BYTES,
        )
    with tempfile.TemporaryDirectory(prefix="daxalgo-promotion-evidence-") as name:
        snapshot_root = Path(name)
        snapshots: dict[str, Path] = {}
        source_hashes: dict[str, str] = {}
        for index, (field, (source, limit)) in enumerate(sources.items()):
            raw = _read_file_bounded(
                Path(source),
                f"model promotion {field}",
                limit,
            )
            source_hashes[field] = hashlib.sha256(raw).hexdigest()
            snapshot = snapshot_root / f"{index:02d}-{field}.snapshot"
            snapshot.write_bytes(raw)
            snapshots[field] = snapshot

        bindings = _build_promotion_bindings_from_evidence_snapshots(
            promotion_evidence_path=snapshots["promotion_evidence_path"],
            calibration_tasks_path=snapshots["calibration_tasks_path"],
            calibration_evidence_path=snapshots["calibration_evidence_path"],
            sealed_tasks_path=snapshots["sealed_tasks_path"],
            responses_path=snapshots["responses_path"],
            verifier_results_path=snapshots["verifier_results_path"],
            baseline_responses_path=snapshots["baseline_responses_path"],
            baseline_verifier_results_path=snapshots["baseline_verifier_results_path"],
            policy_path=snapshots["policy_path"],
            data_release_path=data_release_path,
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            trainer_provenance_trust=trainer_provenance_trust,
            base_selection_trust=base_selection_trust,
            base_model_snapshot_path=base_model_snapshot_path,
            candidate_attestation_trust=candidate_attestation_trust,
            baseline_attestation_trust=baseline_attestation_trust,
            csharp_verifier_replay_audit_path=snapshots.get(
                "csharp_verifier_replay_audit_path"
            ),
            csharp_verifier_replay_audit_trust=csharp_verifier_replay_audit_trust,
            expected_csharp_verifier_replay_audit_envelope_sha256=(
                expected_csharp_verifier_replay_audit_envelope_sha256
            ),
            csharp_verifier_replay_audit_now=csharp_verifier_replay_audit_now,
            catalog_path=catalog_path,
            serving_profile_path=serving_profile_path,
            artifact_path=artifact_path,
            manifest_path=manifest_path,
            review_receipt_now=review_receipt_now,
            trainer_provenance_now=trainer_provenance_now,
        )
        for field, (source, limit) in sources.items():
            if sha256_file(source, max_bytes=limit) != source_hashes[field]:
                _fail(
                    f"model promotion {field}",
                    "changed while promotion bindings were derived",
                )
        if csharp_verifier_replay_audit_path is not None:
            validate_csharp_verifier_replay_audit(
                csharp_verifier_replay_audit_path,
                trust=csharp_verifier_replay_audit_trust,
                expected_envelope_sha256=(
                    expected_csharp_verifier_replay_audit_envelope_sha256
                ),
                now=csharp_verifier_replay_audit_now,
            )
        return bindings


def _build_promotion_bindings_from_evidence_snapshots(
    *,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
) -> _PromotionBindings:
    if not isinstance(trainer_provenance_trust, TrainerProvenanceTrust):
        _fail("trainer provenance trust", "must be externally supplied")
    supplied = validate_promotion_evidence(promotion_evidence_path)
    regenerated = aggregate_promotion_evidence(
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        responses_path=responses_path,
        verifier_results_path=verifier_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        policy_path=policy_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        review_receipt_now=review_receipt_now,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        csharp_verifier_replay_audit_path=csharp_verifier_replay_audit_path,
        csharp_verifier_replay_audit_trust=csharp_verifier_replay_audit_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=(
            expected_csharp_verifier_replay_audit_envelope_sha256
        ),
        csharp_verifier_replay_audit_now=csharp_verifier_replay_audit_now,
        research_only=False,
    )
    if canonical_json_bytes(supplied) != canonical_json_bytes(regenerated):
        _fail(
            "model promotion evidence",
            "does not exactly match evidence regenerated from the supplied source sets",
        )
    if (
        supplied["researchOnly"]
        or supplied["evidenceStatus"] != "release-bound"
        or not supplied["allEvidenceGatesPassed"]
        or not supplied["eligibleForPromotionReview"]
    ):
        _fail("model promotion evidence", "is not eligible for production review")

    release, release_identity = validate_corpus_evaluation_release_with_identity(
        data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        now=review_receipt_now,
    )
    if release["purpose"] != "provider-training-evaluation":
        _fail(
            "release.purpose",
            "must be 'provider-training-evaluation' for hosted production promotion",
        )
    if supplied["dataRelease"] != release_identity:
        _fail("model promotion evidence.dataRelease", "does not match the live release")

    artifact = validate_training_artifact(
        artifact_path,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    trainer_provenance = verify_training_artifact_trainer_provenance(
        artifact,
        trust=trainer_provenance_trust,
        now=trainer_provenance_now,
    )
    artifact_time = _canonical_utc(
        artifact["recordedAtUtc"], "training artifact.recordedAtUtc"
    )
    selected_base = validate_base_model_selection_manifest_target(
        manifest_path,
        trust=base_selection_trust,
        snapshot_path=base_model_snapshot_path,
        expected_data_release=release_identity,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        review_receipt_trust=review_receipt_trust,
        target_now=artifact_time,
    )
    manifest_snapshot = selected_base.manifest_snapshot
    if manifest_snapshot is None:  # pragma: no cover - internal contract
        _fail("training manifest snapshot", "was not retained after validation")
    manifest = manifest_snapshot.document
    manifest_time = _canonical_utc(
        manifest["createdAtUtc"], "training manifest.createdAtUtc"
    )
    _, training_release_identity = validate_training_release_binding(
        data_release_path,
        dataset_sha256=manifest["dataset"]["sha256"],
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        now=review_receipt_now,
    )
    if (
        training_release_identity != release_identity
        or manifest.get("dataRelease") != release_identity
    ):
        _fail("training manifest.dataRelease", "does not match the promoted release")
    manifest_sha256 = manifest_snapshot.sha256

    catalog = validate_candidate_catalog(catalog_path)
    catalog_sha256 = sha256_file(catalog_path, max_bytes=MAX_JSON_BYTES)
    if catalog_sha256 != manifest["candidateCatalog"]["sha256"]:
        _fail("candidate catalog", "does not match the training manifest")

    profile = validate_serving_profile(
        serving_profile_path,
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        manifest_snapshot=manifest_snapshot,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    if (
        artifact["mode"] != "unpromoted-candidate"
        or artifact["productionEligible"] is not False
    ):
        _fail("training artifact", "must be an unpromoted candidate before promotion")
    if artifact["dataRelease"] != release_identity:
        _fail("training artifact.dataRelease", "does not match the promoted release")

    identity = supplied["candidate"]["identity"]
    expected_identity = {
        "responseSchemaVersion": EVALUATION_RESPONSE_SCHEMA_VERSION,
        "targetKind": "trained-adapter",
        "executionModelId": profile.execution_model_id,
        "candidateCatalogSha256": profile.document["candidateCatalogSha256"],
        "candidateId": profile.document["candidateId"],
        "modelId": profile.document["baseModel"]["modelId"],
        "modelRevision": profile.document["baseModel"]["revision"],
        "servingProfile": {
            "id": profile.document["profileId"],
            "sha256": profile.sha256,
        },
    }
    for name, expected in expected_identity.items():
        if identity[name] != expected:
            _fail(
                f"model promotion evidence.candidate.identity.{name}",
                "does not match the exact serving candidate",
            )
    selected = next(
        (
            candidate
            for candidate in catalog["candidates"]
            if candidate["id"] == profile.document["candidateId"]
        ),
        None,
    )
    if (
        selected is None
        or selected["modelId"] != profile.document["baseModel"]["modelId"]
        or selected["revision"] != profile.document["baseModel"]["revision"]
    ):
        _fail("candidate catalog", "does not contain the exact promoted model identity")

    evidence = {
        "reportSha256": supplied["reportSha256"],
        "reportFileSha256": sha256_file(
            promotion_evidence_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "policySha256": supplied["policySha256"],
        "policyFileSha256": sha256_file(policy_path, max_bytes=MAX_JSON_BYTES),
        "calibrationTasksFileSha256": sha256_file(
            calibration_tasks_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "calibrationTaskSetSha256": supplied["calibrationTaskSetSha256"],
        "calibrationEvidenceSha256": supplied["calibrationEvidenceSha256"],
        "sealedTasksFileSha256": sha256_file(
            sealed_tasks_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "sealedTaskSetSha256": supplied["sealedTaskSetSha256"],
        "candidateResponsesFileSha256": sha256_file(
            responses_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "candidateResponseSetSha256": supplied["candidate"]["responseSetSha256"],
        "candidateVerifierResultsFileSha256": sha256_file(
            verifier_results_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "candidateVerifierResultSetSha256": supplied["candidate"][
            "verifierResultSetSha256"
        ],
        "baselineResponsesFileSha256": sha256_file(
            baseline_responses_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "baselineResponseSetSha256": supplied["baseline"]["responseSetSha256"],
        "baselineVerifierResultsFileSha256": sha256_file(
            baseline_verifier_results_path, max_bytes=MAX_EVALUATION_BYTES
        ),
        "baselineVerifierResultSetSha256": supplied["baseline"][
            "verifierResultSetSha256"
        ],
    }
    model = {
        "candidateCatalogSha256": catalog_sha256,
        "candidateId": profile.document["candidateId"],
        "modelId": profile.document["baseModel"]["modelId"],
        "modelRevision": profile.document["baseModel"]["revision"],
        "trainingRunManifestSha256": manifest_sha256,
        "artifactMetadataFileSha256": sha256_file(
            Path(artifact_path) / ARTIFACT_METADATA_NAME, max_bytes=MAX_JSON_BYTES
        ),
        "artifactSha256": artifact["artifactSha256"],
        "artifactTreeSha256": artifact["fileTreeSha256"],
        "servingProfileId": profile.document["profileId"],
        "servingProfileSha256": profile.sha256,
        "executionModelId": profile.execution_model_id,
        "chatTemplateSha256": profile.document["chatTemplateSha256"],
        "containerImageDigest": profile.document["runtime"]["containerImageDigest"],
    }
    replay_audit = None
    if csharp_verifier_replay_audit_path is not None:
        if (
            csharp_verifier_replay_audit_trust is None
            or expected_csharp_verifier_replay_audit_envelope_sha256 is None
        ):
            _fail(
                "C# verifier replay audit",
                "path, exact envelope SHA-256, and external trust must be supplied together",
            )
        replay_audit = validate_csharp_verifier_replay_audit(
            csharp_verifier_replay_audit_path,
            trust=csharp_verifier_replay_audit_trust,
            expected_envelope_sha256=(
                expected_csharp_verifier_replay_audit_envelope_sha256
            ),
            now=csharp_verifier_replay_audit_now,
        )
    receipt_expiry = _canonical_utc(
        release["corpus"]["reviewReceipts"]["expiresAtUtc"],
        "authenticated review-receipt authority expiry",
    )
    authoring_approval = release["evaluation"]["authoringApproval"]
    authoring_expiry = _canonical_utc(
        authoring_approval["expiresAtUtc"],
        "authenticated evaluation-authoring approval expiry",
    )
    authority_expiry = min(
        receipt_expiry,
        authoring_expiry,
        trainer_provenance.expires_at_utc,
    )
    teacher_lineage_admission = release["corpus"].get("teacherLineageAdmission")
    if teacher_lineage_admission is not None:
        authority_expiry = min(
            authority_expiry,
            _canonical_utc(
                teacher_lineage_admission["expiresAtUtc"],
                "authenticated teacher-lineage admission expiry",
            ),
        )
    if replay_audit is not None:
        authority_expiry = min(authority_expiry, replay_audit.expires_at_utc)
    upstream_authority_signers = [
        (
            "corpus-review",
            release["corpus"]["reviewReceipts"]["trust"]["publicKeySpkiSha256"],
        ),
        (
            "evaluation-authoring approval",
            authoring_approval["trust"]["publicKeySpkiSha256"],
        ),
    ]
    if teacher_lineage_admission is not None:
        upstream_authority_signers.append(
            (
                "teacher-lineage admission",
                teacher_lineage_admission["trust"]["publicKeySpkiSha256"],
            )
        )
    if base_selection_trust is not None:
        upstream_authority_signers.append(
            (
                "base-selection",
                selected_base.selection.envelope["publicKeySpkiSha256"],
            )
        )
    corpus_admission = manifest.get("trainingCorpusAdmission")
    if corpus_admission is not None:
        upstream_authority_signers.append(
            (
                "corpus-admission",
                corpus_admission["publicKeySpkiSha256"],
            )
        )
    if replay_audit is not None:
        upstream_authority_signers.append(
            (
                "C# verifier replay-audit",
                replay_audit.public_key_spki_sha256,
            )
        )
    validated_upstream_authority_signers = tuple(upstream_authority_signers)
    _reject_authority_signer_collision(
        "trainer provenance signer",
        trainer_provenance.public_key_spki_sha256,
        validated_upstream_authority_signers,
    )
    authority_signer_spki_sha256s = (
        *validated_upstream_authority_signers,
        ("trainer-provenance", trainer_provenance.public_key_spki_sha256),
    )
    return _PromotionBindings(
        data_release=release_identity,
        evidence=evidence,
        model=model,
        report=supplied,
        authority_signer_spki_sha256s=authority_signer_spki_sha256s,
        manifest_created_at=manifest_time,
        artifact_recorded_at=artifact_time,
        trainer_provenance_issued_at=_canonical_utc(
            trainer_provenance.payload["issuedAtUtc"],
            "trainer provenance payload.issuedAtUtc",
        ),
        trainer_provenance_not_before=trainer_provenance.not_before_utc,
        activation_inputs=PromotionActivationInputs(
            manifest_snapshot=manifest_snapshot,
            selected_base=selected_base,
            artifact=artifact,
            profile=profile,
            authority_expires_at_utc=authority_expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
            evaluation_authoring_approval_payload_sha256=authoring_approval[
                "payloadSha256"
            ],
            evaluation_authoring_approval_envelope_sha256=authoring_approval[
                "envelopeSha256"
            ],
            trainer_provenance_payload_sha256=trainer_provenance.payload_sha256,
            trainer_provenance_envelope_sha256=trainer_provenance.envelope_sha256,
            trainer_provenance_expires_at_utc=(
                trainer_provenance.expires_at_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            ),
            csharp_verifier_replay_audit_payload_sha256=(
                replay_audit.payload_sha256 if replay_audit is not None else None
            ),
            csharp_verifier_replay_audit_envelope_sha256=(
                replay_audit.envelope_sha256 if replay_audit is not None else None
            ),
        ),
        csharp_verifier_replay_audit_timeline=(
            _CSharpVerifierReplayAuditTimeline(
                replay_completed_at=_canonical_utc(
                    replay_audit.payload["replayCompletedAtUtc"],
                    "C# verifier replay-audit payload.replayCompletedAtUtc",
                ),
                approved_at=_canonical_utc(
                    replay_audit.payload["approval"]["approvedAtUtc"],
                    "C# verifier replay-audit payload.approval.approvedAtUtc",
                ),
                issued_at=_canonical_utc(
                    replay_audit.payload["issuedAtUtc"],
                    "C# verifier replay-audit payload.issuedAtUtc",
                ),
            )
            if replay_audit is not None
            else None
        ),
    )


def _approval_binding(path: str | os.PathLike[str]) -> tuple[str, int]:
    raw = _read_file_bounded(
        Path(path), "model promotion approval evidence", MAX_REVIEW_ASSET_BYTES
    )
    if not raw:
        _fail("model promotion approval evidence", "must not be empty")
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _validate_full_bindings(
    verified: VerifiedModelPromotion,
    *,
    bindings: _PromotionBindings,
    hosted_policy: Mapping[str, Any],
    approval_evidence_path: str | os.PathLike[str],
    expected_deployment_id: str,
    expected_environment: str,
) -> None:
    payload = verified.payload
    _reject_authority_signer_collision(
        "model promotion signer",
        verified.envelope["publicKeySpkiSha256"],
        bindings.authority_signer_spki_sha256s,
    )
    _validate_training_timeline(payload, bindings)
    _validate_authority_window(payload, bindings)
    if payload["dataRelease"] != bindings.data_release:
        _fail(
            "model promotion payload.dataRelease", "does not match live release bytes"
        )
    if payload["promotionEvidence"] != bindings.evidence:
        _fail(
            "model promotion payload.promotionEvidence",
            "does not match regenerated live evidence",
        )
    if payload["model"] != bindings.model:
        _fail("model promotion payload.model", "does not match live model bytes")
    if payload["hostedDeploymentPolicy"] != hosted_policy:
        _fail(
            "model promotion payload.hostedDeploymentPolicy",
            "does not match the supplied hosted policy",
        )
    if payload["deployment"]["deploymentId"] != _identifier(
        expected_deployment_id, "expected deployment ID"
    ):
        _fail(
            "model promotion payload.deploymentId", "does not match trusted deployment"
        )
    if payload["deployment"]["environment"] != _identifier(
        expected_environment, "expected deployment environment"
    ):
        _fail(
            "model promotion payload.environment", "does not match trusted environment"
        )
    evidence_sha256, evidence_size = _approval_binding(approval_evidence_path)
    if (
        payload["approval"]["evidenceSha256"] != evidence_sha256
        or payload["approval"]["evidenceSizeBytes"] != evidence_size
    ):
        _fail(
            "model promotion payload.approval evidence",
            "does not match the supplied approval evidence bytes",
        )


def _validate_training_timeline(
    payload: Mapping[str, Any], bindings: _PromotionBindings
) -> None:
    approval_time = _canonical_utc(
        payload["approval"]["approvedAtUtc"],
        "model promotion payload.approval.approvedAtUtc",
    )
    issued_time = _canonical_utc(
        payload["issuedAtUtc"], "model promotion payload.issuedAtUtc"
    )
    if not (
        bindings.manifest_created_at
        <= bindings.artifact_recorded_at
        <= bindings.trainer_provenance_issued_at
        <= bindings.trainer_provenance_not_before
        <= approval_time
        <= issued_time
    ):
        _fail(
            "model promotion training timeline",
            "must satisfy manifestCreatedAt <= artifactRecordedAt <= "
            "trainerProvenanceIssuedAt <= trainerProvenanceNotBefore <= "
            "approvedAt <= issuedAt",
        )
    replay_audit_timeline = bindings.csharp_verifier_replay_audit_timeline
    if replay_audit_timeline is not None and not (
        replay_audit_timeline.replay_completed_at
        <= replay_audit_timeline.approved_at
        <= replay_audit_timeline.issued_at
        <= approval_time
    ):
        _fail(
            "model promotion C# verifier replay-audit timeline",
            "must satisfy replayCompletedAt <= audit approvedAt <= audit issuedAt "
            "<= promotion approvedAt",
        )


def _validate_authority_window(
    payload: Mapping[str, Any], bindings: _PromotionBindings
) -> None:
    promotion_expires = _canonical_utc(
        payload["expiresAtUtc"], "model promotion payload.expiresAtUtc"
    )
    authority_expires = _canonical_utc(
        bindings.activation_inputs.authority_expires_at_utc,
        "earliest authenticated upstream-authority expiry",
    )
    if promotion_expires > authority_expires:
        _fail(
            "model promotion payload.expiresAtUtc",
            "must not outlive the earliest authenticated upstream-authority expiry",
        )


def _validate_model_promotion(
    path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
    expected_link_count: int,
) -> VerifiedModelPromotion:
    if not isinstance(
        evaluation_authoring_approval_trust, EvaluationAuthoringApprovalTrust
    ):
        _fail(
            "evaluation-authoring approval trust",
            "must be externally supplied",
        )
    if not isinstance(trainer_provenance_trust, TrainerProvenanceTrust):
        _fail("trainer provenance trust", "must be externally supplied")
    verified = _verify_model_promotion_envelope(
        path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        now=now,
        expected_link_count=expected_link_count,
    )
    if (
        csharp_verifier_replay_audit_trust is not None
        and verified.envelope["publicKeySpkiSha256"]
        == csharp_verifier_replay_audit_trust.public_key_spki_sha256
    ):
        _fail(
            "model promotion signer",
            "must differ from the C# verifier replay-audit signer",
        )
    if (
        verified.envelope["publicKeySpkiSha256"]
        == evaluation_authoring_approval_trust.public_key_spki_sha256
    ):
        _fail(
            "model promotion signer",
            "must differ from the evaluation-authoring approval signer",
        )
    if (
        verified.envelope["publicKeySpkiSha256"]
        == trainer_provenance_trust.public_key_spki_sha256
    ):
        _fail(
            "model promotion signer",
            "must differ from the trainer-provenance signer",
        )
    bindings = _build_promotion_bindings(
        promotion_evidence_path=promotion_evidence_path,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        responses_path=responses_path,
        verifier_results_path=verifier_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        policy_path=policy_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        trainer_provenance_trust=trainer_provenance_trust,
        base_selection_trust=base_selection_trust,
        base_model_snapshot_path=base_model_snapshot_path,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        csharp_verifier_replay_audit_path=csharp_verifier_replay_audit_path,
        csharp_verifier_replay_audit_trust=csharp_verifier_replay_audit_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=(
            expected_csharp_verifier_replay_audit_envelope_sha256
        ),
        csharp_verifier_replay_audit_now=csharp_verifier_replay_audit_now,
        catalog_path=catalog_path,
        serving_profile_path=serving_profile_path,
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        review_receipt_now=review_receipt_now,
        trainer_provenance_now=trainer_provenance_now,
    )
    hosted_policy = validate_hosted_deployment_policy(hosted_deployment_policy_path)
    _validate_full_bindings(
        verified,
        bindings=bindings,
        hosted_policy=hosted_policy,
        approval_evidence_path=approval_evidence_path,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
    )
    return replace(verified, activation_inputs=bindings.activation_inputs)


def validate_model_promotion(
    path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedModelPromotion:
    return _validate_model_promotion(
        path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        promotion_evidence_path=promotion_evidence_path,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        responses_path=responses_path,
        verifier_results_path=verifier_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        policy_path=policy_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        trainer_provenance_trust=trainer_provenance_trust,
        base_selection_trust=base_selection_trust,
        base_model_snapshot_path=base_model_snapshot_path,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        csharp_verifier_replay_audit_path=csharp_verifier_replay_audit_path,
        csharp_verifier_replay_audit_trust=csharp_verifier_replay_audit_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=(
            expected_csharp_verifier_replay_audit_envelope_sha256
        ),
        csharp_verifier_replay_audit_now=csharp_verifier_replay_audit_now,
        catalog_path=catalog_path,
        serving_profile_path=serving_profile_path,
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        approval_evidence_path=approval_evidence_path,
        hosted_deployment_policy_path=hosted_deployment_policy_path,
        review_receipt_now=review_receipt_now,
        trainer_provenance_now=trainer_provenance_now,
        now=now,
        expected_link_count=1,
    )


def create_promoted_model_readiness_attestation(
    *,
    promotion_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_promotion_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    nonce: str,
    readiness_key_id: str,
    readiness_key: bytes,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Create a v2 readiness response only after full live promotion validation."""
    verified = validate_model_promotion(
        promotion_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_promotion_key_id,
        expected_signer_role=expected_signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        promotion_evidence_path=promotion_evidence_path,
        calibration_tasks_path=calibration_tasks_path,
        calibration_evidence_path=calibration_evidence_path,
        sealed_tasks_path=sealed_tasks_path,
        responses_path=responses_path,
        verifier_results_path=verifier_results_path,
        baseline_responses_path=baseline_responses_path,
        baseline_verifier_results_path=baseline_verifier_results_path,
        policy_path=policy_path,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        trainer_provenance_trust=trainer_provenance_trust,
        base_selection_trust=base_selection_trust,
        base_model_snapshot_path=base_model_snapshot_path,
        candidate_attestation_trust=candidate_attestation_trust,
        baseline_attestation_trust=baseline_attestation_trust,
        csharp_verifier_replay_audit_path=csharp_verifier_replay_audit_path,
        csharp_verifier_replay_audit_trust=csharp_verifier_replay_audit_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=(
            expected_csharp_verifier_replay_audit_envelope_sha256
        ),
        csharp_verifier_replay_audit_now=csharp_verifier_replay_audit_now,
        catalog_path=catalog_path,
        serving_profile_path=serving_profile_path,
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        approval_evidence_path=approval_evidence_path,
        hosted_deployment_policy_path=hosted_deployment_policy_path,
        review_receipt_now=review_receipt_now,
        trainer_provenance_now=trainer_provenance_now,
        now=now,
    )
    payload = verified.payload
    proof = compute_model_readiness_v2_proof(
        key=readiness_key,
        audience=expected_audience,
        nonce=nonce,
        key_id=readiness_key_id,
        serving_profile_sha256=payload["model"]["servingProfileSha256"],
        artifact_sha256=payload["model"]["artifactSha256"],
        artifact_tree_sha256=payload["model"]["artifactTreeSha256"],
        execution_model_id=payload["model"]["executionModelId"],
        promotion_envelope_sha256=verified.envelope_sha256,
        promotion_payload_sha256=verified.payload_sha256,
        deployment_id=payload["deployment"]["deploymentId"],
        provider_id=payload["hostedDeploymentPolicy"]["providerId"],
        hosted_deployment_policy_sha256=payload["hostedDeploymentPolicy"][
            "policySha256"
        ],
        expires_at_utc=payload["expiresAtUtc"],
    )
    attestation = {
        "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
        "nonce": nonce,
        "keyId": readiness_key_id,
        "proof": proof,
    }
    return validate_model_readiness_v2_attestation(
        attestation,
        key=readiness_key,
        audience=expected_audience,
        expected_nonce=nonce,
        expected_key_id=readiness_key_id,
        serving_profile_sha256=payload["model"]["servingProfileSha256"],
        artifact_sha256=payload["model"]["artifactSha256"],
        artifact_tree_sha256=payload["model"]["artifactTreeSha256"],
        execution_model_id=payload["model"]["executionModelId"],
        promotion_envelope_sha256=verified.envelope_sha256,
        promotion_payload_sha256=verified.payload_sha256,
        deployment_id=payload["deployment"]["deploymentId"],
        provider_id=payload["hostedDeploymentPolicy"]["providerId"],
        hosted_deployment_policy_sha256=payload["hostedDeploymentPolicy"][
            "policySha256"
        ],
        expires_at_utc=payload["expiresAtUtc"],
    )


def _build_model_promotion_payload(
    *,
    public_key_path: str | os.PathLike[str],
    audience: str,
    key_id: str,
    signer_role: str,
    deployment_id: str,
    environment: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    live_arguments: Mapping[str, Any],
    now: datetime | None,
) -> tuple[dict[str, Any], Any, str]:
    audience = _identifier(audience, "model promotion audience")
    _identifier(key_id, "model promotion key ID")
    signer_role = _identifier(signer_role, "model promotion signer role")
    actor_role = _identifier(actor_role, "model promotion actor role")
    if actor_role != signer_role:
        _fail("model promotion actor role", "must match signer role")
    evaluation_trust = live_arguments["evaluation_authoring_approval_trust"]
    trainer_trust = live_arguments["trainer_provenance_trust"]
    replay_trust = live_arguments["csharp_verifier_replay_audit_trust"]
    if not isinstance(evaluation_trust, EvaluationAuthoringApprovalTrust):
        _fail(
            "evaluation-authoring approval trust",
            "must be externally supplied",
        )
    if not isinstance(trainer_trust, TrainerProvenanceTrust):
        _fail("trainer provenance trust", "must be externally supplied")
    public_key, _, promotion_spki_sha256 = _load_public_key(public_key_path)
    if (
        replay_trust is not None
        and promotion_spki_sha256 == replay_trust.public_key_spki_sha256
    ):
        _fail(
            "model promotion signer",
            "must differ from the C# verifier replay-audit signer",
        )
    if promotion_spki_sha256 == evaluation_trust.public_key_spki_sha256:
        _fail(
            "model promotion signer",
            "must differ from the evaluation-authoring approval signer",
        )
    if promotion_spki_sha256 == trainer_trust.public_key_spki_sha256:
        _fail(
            "model promotion signer",
            "must differ from the trainer-provenance signer",
        )
    bindings = _build_promotion_bindings(
        promotion_evidence_path=live_arguments["promotion_evidence_path"],
        calibration_tasks_path=live_arguments["calibration_tasks_path"],
        calibration_evidence_path=live_arguments["calibration_evidence_path"],
        sealed_tasks_path=live_arguments["sealed_tasks_path"],
        responses_path=live_arguments["responses_path"],
        verifier_results_path=live_arguments["verifier_results_path"],
        baseline_responses_path=live_arguments["baseline_responses_path"],
        baseline_verifier_results_path=live_arguments["baseline_verifier_results_path"],
        policy_path=live_arguments["policy_path"],
        data_release_path=live_arguments["data_release_path"],
        review_receipt_trust=live_arguments["review_receipt_trust"],
        evaluation_authoring_approval_trust=evaluation_trust,
        trainer_provenance_trust=trainer_trust,
        base_selection_trust=live_arguments["base_selection_trust"],
        base_model_snapshot_path=live_arguments["base_model_snapshot_path"],
        candidate_attestation_trust=live_arguments["candidate_attestation_trust"],
        baseline_attestation_trust=live_arguments["baseline_attestation_trust"],
        csharp_verifier_replay_audit_path=live_arguments[
            "csharp_verifier_replay_audit_path"
        ],
        csharp_verifier_replay_audit_trust=replay_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=live_arguments[
            "expected_csharp_verifier_replay_audit_envelope_sha256"
        ],
        csharp_verifier_replay_audit_now=live_arguments[
            "csharp_verifier_replay_audit_now"
        ],
        catalog_path=live_arguments["catalog_path"],
        serving_profile_path=live_arguments["serving_profile_path"],
        artifact_path=live_arguments["artifact_path"],
        manifest_path=live_arguments["manifest_path"],
        review_receipt_now=live_arguments["review_receipt_now"],
        trainer_provenance_now=live_arguments["trainer_provenance_now"],
    )
    _reject_authority_signer_collision(
        "model promotion signer",
        promotion_spki_sha256,
        bindings.authority_signer_spki_sha256s,
    )
    hosted_policy = validate_hosted_deployment_policy(
        live_arguments["hosted_deployment_policy_path"]
    )
    approval_sha256, approval_size = _approval_binding(
        live_arguments["approval_evidence_path"]
    )
    payload: dict[str, Any] = {
        "schemaVersion": MODEL_PROMOTION_SCHEMA_VERSION,
        "promotionId": PROMOTION_ID_PREFIX + _ZERO_SHA256,
        "decision": PROMOTION_DECISION,
        "productionEligible": True,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "dataRelease": bindings.data_release,
        "promotionEvidence": bindings.evidence,
        "model": bindings.model,
        "deployment": {
            "deploymentId": deployment_id,
            "environment": environment,
            "audience": audience,
        },
        "approval": {
            "approvalId": approval_id,
            "actorId": actor_id,
            "actorRole": actor_role,
            "reference": approval_reference,
            "approvedAtUtc": approved_at_utc,
            "evidenceSha256": approval_sha256,
            "evidenceSizeBytes": approval_size,
        },
        "hostedDeploymentPolicy": hosted_policy,
    }
    payload["promotionId"] = model_promotion_id(payload)
    payload = _validate_promotion_payload_document(payload)
    _validate_training_timeline(payload, bindings)
    _validate_authority_window(payload, bindings)
    current = _validation_time(
        now or datetime.now(timezone.utc), "model promotion creation time"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "model promotion payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "model promotion payload.expiresAtUtc"
    )
    if current < not_before or current >= expires:
        _fail("model promotion payload validity", "must be active when it is created")
    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_PROMOTION_PAYLOAD_BYTES:
        _fail("model promotion payload", "exceeds its byte limit")
    return payload, public_key, promotion_spki_sha256


def _build_model_promotion_signing_bundle_document(
    payload: Mapping[str, Any],
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    payload_document = _validate_promotion_payload_document(dict(payload))
    payload_bytes = canonical_json_bytes(payload_document)
    if len(payload_bytes) > MAX_PROMOTION_PAYLOAD_BYTES:
        _fail("model promotion payload", "exceeds its byte limit")
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
    _serialize_promotion_envelope(final_envelope)
    signature_preimage = _signature_input(envelope, payload_bytes)
    if len(signature_preimage) > MAX_PROMOTION_SIGNATURE_INPUT_BYTES:
        _fail("model promotion signature preimage", "exceeds its byte limit")
    signature_digest = hashlib.sha256(signature_preimage).digest()
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    unsigned_envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    bundle: dict[str, Any] = {
        "schemaVersion": MODEL_PROMOTION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": PROMOTION_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": PROMOTION_SIGNING_STATUS,
        "authority": {name: False for name in sorted(_SIGNING_AUTHORITY_KEYS)},
        "trust": {
            "publicKeySpkiSha256": public_key_spki_sha256,
            "audience": audience,
            "keyId": key_id,
            "signerRole": signer_role,
        },
        "promotionId": payload_document["promotionId"],
        "payloadSha256": payload_sha256,
        "payload": _base64url_encode(payload_bytes),
        "unsignedEnvelopeSha256": unsigned_envelope_sha256,
        "unsignedEnvelope": _base64url_encode(envelope_bytes),
        "validity": {
            "approvedAtUtc": payload_document["approval"]["approvedAtUtc"],
            "issuedAtUtc": payload_document["issuedAtUtc"],
            "notBeforeUtc": payload_document["notBeforeUtc"],
            "expiresAtUtc": payload_document["expiresAtUtc"],
        },
        "signatureContract": {
            "algorithm": PROMOTION_ALGORITHM,
            "hashAlgorithm": PROMOTION_SIGNING_HASH_ALGORITHM,
            "inputEncoding": "base64url",
            "acceptedModes": [
                PROMOTION_EXTERNAL_RAW_MESSAGE_MODE,
                PROMOTION_EXTERNAL_SHA256_DIGEST_MODE,
            ],
            "acceptedSignatureFormats": [
                PROMOTION_EXTERNAL_DER_SIGNATURE_FORMAT,
                PROMOTION_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "promotionId": payload_document["promotionId"],
            "payloadSha256": payload_sha256,
            "unsignedEnvelopeSha256": unsigned_envelope_sha256,
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = model_promotion_signing_bundle_id(bundle)
    return bundle


def _validate_model_promotion_signing_bundle_document(
    value: Mapping[str, Any],
    *,
    path: Path,
    raw: bytes,
    expected_payload: Mapping[str, Any],
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    now: datetime,
) -> VerifiedModelPromotionSigningBundle:
    bundle = _exact_keys(
        dict(value), _SIGNING_BUNDLE_KEYS, "model promotion signing bundle"
    )
    if bundle["schemaVersion"] != MODEL_PROMOTION_SIGNING_BUNDLE_SCHEMA_VERSION:
        _fail("model promotion signing bundle.schemaVersion", "is unsupported")
    if bundle["status"] != PROMOTION_SIGNING_STATUS:
        _fail(
            "model promotion signing bundle.status",
            "does not match the non-authorizing contract",
        )
    authority = _exact_keys(
        bundle["authority"],
        _SIGNING_AUTHORITY_KEYS,
        "model promotion signing bundle.authority",
    )
    if any(
        type(authorized) is not bool or authorized for authorized in authority.values()
    ):
        _fail(
            "model promotion signing bundle.authority",
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
            "model promotion signing bundle.trust",
        )
        != expected_trust
    ):
        _fail(
            "model promotion signing bundle.trust",
            "does not match externally pinned trust",
        )
    payload_document = _validate_promotion_payload_document(dict(expected_payload))
    if payload_document["deployment"]["deploymentId"] != _identifier(
        expected_deployment_id, "expected deployment ID"
    ):
        _fail(
            "model promotion signing bundle deployment ID",
            "does not match trusted deployment",
        )
    if payload_document["deployment"]["environment"] != _identifier(
        expected_environment, "expected deployment environment"
    ):
        _fail(
            "model promotion signing bundle environment",
            "does not match trusted environment",
        )
    if payload_document["deployment"]["audience"] != audience:
        _fail(
            "model promotion signing bundle audience",
            "does not match the exact payload",
        )
    if payload_document["approval"]["actorRole"] != signer_role:
        _fail(
            "model promotion signing bundle signer role",
            "does not match the exact payload",
        )
    not_before = _canonical_utc(
        payload_document["notBeforeUtc"],
        "model promotion signing bundle payload.notBeforeUtc",
    )
    expires = _canonical_utc(
        payload_document["expiresAtUtc"],
        "model promotion signing bundle payload.expiresAtUtc",
    )
    if now < not_before or now >= expires:
        _fail("model promotion signing bundle payload validity", "must be active")
    expected = _build_model_promotion_signing_bundle_document(
        payload_document,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_key_spki_sha256,
    )
    if bundle != expected:
        _fail(
            "model promotion signing bundle",
            "does not match its exact payload-derived contract",
        )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if raw != serialized or len(raw) > MAX_PROMOTION_SIGNING_BUNDLE_BYTES:
        _fail(
            "model promotion signing bundle",
            "must be bounded exact canonical JSON followed by one LF",
        )
    bundle_id = bundle["bundleId"]
    if not isinstance(bundle_id, str) or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id):
        _fail(
            "model promotion signing bundle.bundleId",
            "must be a canonical content-derived ID",
        )
    payload_bytes = _base64url_decode(
        bundle["payload"],
        "model promotion signing bundle.payload",
        max_bytes=MAX_PROMOTION_PAYLOAD_BYTES,
    )
    if payload_bytes != canonical_json_bytes(payload_document):
        _fail(
            "model promotion signing bundle.payload",
            "does not match the exact canonical payload",
        )
    unsigned_envelope_bytes = _base64url_decode(
        bundle["unsignedEnvelope"],
        "model promotion signing bundle.unsignedEnvelope",
        max_bytes=MAX_PROMOTION_ENVELOPE_BYTES,
    )
    unsigned_envelope = _load_json_bytes(
        unsigned_envelope_bytes,
        "model promotion signing bundle unsigned envelope",
    )
    if unsigned_envelope_bytes != canonical_json_bytes(unsigned_envelope):
        _fail(
            "model promotion signing bundle unsigned envelope",
            "must be exact canonical JSON",
        )
    signature_preimage = _base64url_decode(
        bundle["request"]["signaturePreimage"],
        "model promotion signing bundle.request.signaturePreimage",
        max_bytes=MAX_PROMOTION_SIGNATURE_INPUT_BYTES,
    )
    signature_digest = _base64url_decode(
        bundle["request"]["signatureInput"],
        "model promotion signing bundle.request.signatureInput",
        exact_bytes=32,
    )
    return VerifiedModelPromotionSigningBundle(
        path=Path(os.path.abspath(os.fspath(path))),
        bundle=bundle,
        bundle_sha256=hashlib.sha256(raw).hexdigest(),
        bundle_id=bundle_id,
        payload=payload_document,
        payload_bytes=payload_bytes,
        payload_sha256=bundle["payloadSha256"],
        unsigned_envelope=unsigned_envelope,
        unsigned_envelope_sha256=bundle["unsignedEnvelopeSha256"],
        signature_preimage=signature_preimage,
        signature_input_sha256=signature_digest.hex(),
        public_key_spki_sha256=public_key_spki_sha256,
    )


def _read_unreplayed_model_promotion_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    now: datetime | None,
    expected_link_count: int,
) -> VerifiedModelPromotionSigningBundle:
    _, _, spki = _load_public_key(public_key_path)
    audience = _identifier(expected_audience, "expected promotion audience")
    key_id = _identifier(expected_key_id, "expected promotion key ID")
    signer_role = _identifier(expected_signer_role, "expected promotion signer role")
    resolved, raw, document = _read_canonical_handoff_document(
        signing_bundle_path,
        "model promotion signing bundle",
        MAX_PROMOTION_SIGNING_BUNDLE_BYTES,
        expected_link_count=expected_link_count,
    )
    supplied = _exact_keys(
        document, _SIGNING_BUNDLE_KEYS, "model promotion signing bundle"
    )
    payload_bytes = _base64url_decode(
        supplied["payload"],
        "model promotion signing bundle.payload",
        max_bytes=MAX_PROMOTION_PAYLOAD_BYTES,
    )
    payload = _load_json_bytes(payload_bytes, "model promotion signing bundle payload")
    if payload_bytes != canonical_json_bytes(payload):
        _fail(
            "model promotion signing bundle payload",
            "must be exact canonical JSON",
        )
    current = _validation_time(
        now or datetime.now(timezone.utc),
        "model promotion signing-bundle verification time",
    )
    return _validate_model_promotion_signing_bundle_document(
        supplied,
        path=resolved,
        raw=raw,
        expected_payload=payload,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        now=current,
    )


def _validate_model_promotion_signing_bundle_live(
    verified: VerifiedModelPromotionSigningBundle,
    *,
    expected_deployment_id: str,
    expected_environment: str,
    live_arguments: Mapping[str, Any],
) -> None:
    evaluation_trust = live_arguments["evaluation_authoring_approval_trust"]
    trainer_trust = live_arguments["trainer_provenance_trust"]
    replay_trust = live_arguments["csharp_verifier_replay_audit_trust"]
    if not isinstance(evaluation_trust, EvaluationAuthoringApprovalTrust):
        _fail(
            "evaluation-authoring approval trust",
            "must be externally supplied",
        )
    if not isinstance(trainer_trust, TrainerProvenanceTrust):
        _fail("trainer provenance trust", "must be externally supplied")
    if (
        replay_trust is not None
        and verified.public_key_spki_sha256 == replay_trust.public_key_spki_sha256
    ):
        _fail(
            "model promotion signer",
            "must differ from the C# verifier replay-audit signer",
        )
    if verified.public_key_spki_sha256 == evaluation_trust.public_key_spki_sha256:
        _fail(
            "model promotion signer",
            "must differ from the evaluation-authoring approval signer",
        )
    if verified.public_key_spki_sha256 == trainer_trust.public_key_spki_sha256:
        _fail(
            "model promotion signer",
            "must differ from the trainer-provenance signer",
        )
    bindings = _build_promotion_bindings(
        promotion_evidence_path=live_arguments["promotion_evidence_path"],
        calibration_tasks_path=live_arguments["calibration_tasks_path"],
        calibration_evidence_path=live_arguments["calibration_evidence_path"],
        sealed_tasks_path=live_arguments["sealed_tasks_path"],
        responses_path=live_arguments["responses_path"],
        verifier_results_path=live_arguments["verifier_results_path"],
        baseline_responses_path=live_arguments["baseline_responses_path"],
        baseline_verifier_results_path=live_arguments["baseline_verifier_results_path"],
        policy_path=live_arguments["policy_path"],
        data_release_path=live_arguments["data_release_path"],
        review_receipt_trust=live_arguments["review_receipt_trust"],
        evaluation_authoring_approval_trust=evaluation_trust,
        trainer_provenance_trust=trainer_trust,
        base_selection_trust=live_arguments["base_selection_trust"],
        base_model_snapshot_path=live_arguments["base_model_snapshot_path"],
        candidate_attestation_trust=live_arguments["candidate_attestation_trust"],
        baseline_attestation_trust=live_arguments["baseline_attestation_trust"],
        csharp_verifier_replay_audit_path=live_arguments[
            "csharp_verifier_replay_audit_path"
        ],
        csharp_verifier_replay_audit_trust=replay_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=live_arguments[
            "expected_csharp_verifier_replay_audit_envelope_sha256"
        ],
        csharp_verifier_replay_audit_now=live_arguments[
            "csharp_verifier_replay_audit_now"
        ],
        catalog_path=live_arguments["catalog_path"],
        serving_profile_path=live_arguments["serving_profile_path"],
        artifact_path=live_arguments["artifact_path"],
        manifest_path=live_arguments["manifest_path"],
        review_receipt_now=live_arguments["review_receipt_now"],
        trainer_provenance_now=live_arguments["trainer_provenance_now"],
    )
    hosted_policy = validate_hosted_deployment_policy(
        live_arguments["hosted_deployment_policy_path"]
    )
    unsigned_verified = VerifiedModelPromotion(
        path=verified.path,
        envelope=verified.unsigned_envelope,
        payload=verified.payload,
        payload_bytes=verified.payload_bytes,
        payload_sha256=verified.payload_sha256,
        envelope_sha256=verified.unsigned_envelope_sha256,
    )
    _validate_full_bindings(
        unsigned_verified,
        bindings=bindings,
        hosted_policy=hosted_policy,
        approval_evidence_path=live_arguments["approval_evidence_path"],
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
    )


def _verify_model_promotion_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    live_arguments: Mapping[str, Any],
    now: datetime | None,
    expected_link_count: int,
) -> VerifiedModelPromotionSigningBundle:
    verified = _read_unreplayed_model_promotion_signing_bundle(
        signing_bundle_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        now=now,
        expected_link_count=expected_link_count,
    )
    _validate_model_promotion_signing_bundle_live(
        verified,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        live_arguments=live_arguments,
    )
    current = _validation_time(
        now or datetime.now(timezone.utc),
        "model promotion signing-bundle post-replay time",
    )
    not_before = _canonical_utc(
        verified.payload["notBeforeUtc"],
        "model promotion signing bundle payload.notBeforeUtc",
    )
    expires = _canonical_utc(
        verified.payload["expiresAtUtc"],
        "model promotion signing bundle payload.expiresAtUtc",
    )
    if current < not_before or current >= expires:
        _fail("model promotion signing bundle payload validity", "must be active")
    return verified


def verify_model_promotion_signing_bundle(
    signing_bundle_path: str | os.PathLike[str],
    *,
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedModelPromotionSigningBundle:
    live_arguments = dict(locals())
    return _verify_model_promotion_signing_bundle(
        signing_bundle_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        live_arguments=live_arguments,
        now=now,
        expected_link_count=1,
    )


def prepare_model_promotion_signing_bundle(
    *,
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    audience: str,
    key_id: str,
    signer_role: str,
    deployment_id: str,
    environment: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedModelPromotionSigningBundle:
    live_arguments = dict(locals())
    payload, _, spki = _build_model_promotion_payload(
        public_key_path=public_key_path,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        deployment_id=deployment_id,
        environment=environment,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        live_arguments=live_arguments,
        now=now,
    )
    bundle = _build_model_promotion_signing_bundle_document(
        payload,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_PROMOTION_SIGNING_BUNDLE_BYTES:
        _fail("model promotion signing bundle", "exceeds its byte limit")
    expected_sha256 = hashlib.sha256(serialized).hexdigest()

    def validate(path: Path, expected_link_count: int):
        verified = _verify_model_promotion_signing_bundle(
            path,
            public_key_path=public_key_path,
            expected_audience=audience,
            expected_key_id=key_id,
            expected_signer_role=signer_role,
            expected_deployment_id=deployment_id,
            expected_environment=environment,
            live_arguments=live_arguments,
            now=now,
            expected_link_count=expected_link_count,
        )
        if verified.bundle_sha256 != expected_sha256:
            _fail("model promotion signing bundle", "changed during publication")
        return verified

    return _write_owned_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field="model promotion signing-bundle output",
    )


def _build_model_promotion_external_signature_document(
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
        "schemaVersion": MODEL_PROMOTION_SIGNATURE_SCHEMA_VERSION,
        "signatureId": PROMOTION_EXTERNAL_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": document["bundleId"],
        "signingBundleSha256": hashlib.sha256(exact_bundle_bytes).hexdigest(),
        "promotionId": document["promotionId"],
        "payloadSha256": document["payloadSha256"],
        "unsignedEnvelopeSha256": document["unsignedEnvelopeSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": document["trust"]["publicKeySpkiSha256"],
        "mode": signature_mode,
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    signature_document["signatureId"] = model_promotion_external_signature_id(
        signature_document
    )
    return signature_document


def _validate_model_promotion_external_signature_document(
    value: Mapping[str, Any],
    *,
    signing_bundle: VerifiedModelPromotionSigningBundle,
    public_key: Any,
) -> bytes:
    document = _exact_keys(
        dict(value),
        _EXTERNAL_SIGNATURE_KEYS,
        "model promotion external signature",
    )
    if len(canonical_json_bytes(document)) > MAX_PROMOTION_EXTERNAL_SIGNATURE_BYTES:
        _fail("model promotion external signature", "exceeds its byte limit")
    if document["schemaVersion"] != MODEL_PROMOTION_SIGNATURE_SCHEMA_VERSION:
        _fail("model promotion external signature.schemaVersion", "is unsupported")
    expected = {
        "signingBundleId": signing_bundle.bundle_id,
        "signingBundleSha256": signing_bundle.bundle_sha256,
        "promotionId": signing_bundle.payload["promotionId"],
        "payloadSha256": signing_bundle.payload_sha256,
        "unsignedEnvelopeSha256": signing_bundle.unsigned_envelope_sha256,
        "signatureInputSha256": signing_bundle.signature_input_sha256,
        "publicKeySpkiSha256": signing_bundle.public_key_spki_sha256,
    }
    for name, expected_value in expected.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"model promotion external signature.{name}")
        if supplied != expected_value:
            _fail(
                f"model promotion external signature.{name}",
                "does not match the exact signing bundle",
            )
    signature_digest = _base64url_decode(
        signing_bundle.bundle["request"]["signatureInput"],
        "model promotion signing bundle.request.signatureInput",
        exact_bytes=32,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        signature_mode=document["mode"],
        public_key=public_key,
        signature_preimage=signing_bundle.signature_preimage,
        signature_digest=signature_digest,
        field="model promotion external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id != model_promotion_external_signature_id(document)
    ):
        _fail(
            "model promotion external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _promotion_validation_arguments(
    *,
    public_key_path: str | os.PathLike[str],
    audience: str,
    key_id: str,
    signer_role: str,
    deployment_id: str,
    environment: str,
    live_arguments: Mapping[str, Any],
) -> dict[str, Any]:
    arguments = {name: live_arguments[name] for name in _PROMOTION_LIVE_ARGUMENT_NAMES}
    arguments.update(
        {
            "public_key_path": public_key_path,
            "expected_audience": audience,
            "expected_key_id": key_id,
            "expected_signer_role": signer_role,
            "expected_deployment_id": deployment_id,
            "expected_environment": environment,
        }
    )
    return arguments


def _publish_model_promotion(
    *,
    output_path: str | os.PathLike[str],
    serialized: bytes,
    expected_payload: Mapping[str, Any],
    expected_envelope_sha256: str,
    validation_arguments: Mapping[str, Any],
    now: datetime | None,
    field: str,
) -> VerifiedModelPromotion:
    def validate(path: Path, expected_link_count: int) -> VerifiedModelPromotion:
        verified = _validate_model_promotion(
            path,
            **validation_arguments,
            now=now,
            expected_link_count=expected_link_count,
        )
        if (
            verified.payload != expected_payload
            or verified.envelope_sha256 != expected_envelope_sha256
        ):
            _fail(field, "changed during publication")
        return verified

    return _write_owned_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=lambda path: validate(path, 1),
        precommit_validator=lambda path: validate(path, 2),
        field=field,
    )


def finalize_model_promotion(
    *,
    signing_bundle_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_audience: str,
    expected_key_id: str,
    expected_signer_role: str,
    expected_deployment_id: str,
    expected_environment: str,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedModelPromotion:
    live_arguments = dict(locals())
    preflight_bundle = _read_unreplayed_model_promotion_signing_bundle(
        signing_bundle_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        now=now,
        expected_link_count=1,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "model promotion external signature",
        MAX_PROMOTION_EXTERNAL_SIGNATURE_BYTES,
        expected_link_count=1,
    )
    public_key, _, spki = _load_public_key(public_key_path)
    signature = _validate_model_promotion_external_signature_document(
        signature_document,
        signing_bundle=preflight_bundle,
        public_key=public_key,
    )
    verified_bundle = _verify_model_promotion_signing_bundle(
        signing_bundle_path,
        public_key_path=public_key_path,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        expected_deployment_id=expected_deployment_id,
        expected_environment=expected_environment,
        live_arguments=live_arguments,
        now=now,
        expected_link_count=1,
    )
    if (
        verified_bundle.bundle_id != preflight_bundle.bundle_id
        or verified_bundle.bundle_sha256 != preflight_bundle.bundle_sha256
        or verified_bundle.payload != preflight_bundle.payload
    ):
        _fail(
            "model promotion signing bundle",
            "changed between signature preflight and live replay",
        )
    payload_bytes = canonical_json_bytes(verified_bundle.payload)
    if payload_bytes != verified_bundle.payload_bytes:
        _fail(
            "model promotion signing bundle payload",
            "changed while the promotion was finalized",
        )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=_identifier(expected_audience, "expected promotion audience"),
        key_id=_identifier(expected_key_id, "expected promotion key ID"),
        signer_role=_identifier(expected_signer_role, "expected promotion signer role"),
        public_key_spki_sha256=spki,
    )
    if envelope != verified_bundle.unsigned_envelope:
        _fail(
            "model promotion signing bundle unsigned envelope",
            "changed while the promotion was finalized",
        )
    envelope["signature"] = _base64url_encode(signature)
    current = _validation_time(
        now or datetime.now(timezone.utc), "model promotion finalization time"
    )
    _validate_envelope_document(
        envelope,
        public_key=public_key,
        public_key_spki_sha256=spki,
        expected_audience=expected_audience,
        expected_key_id=expected_key_id,
        expected_signer_role=expected_signer_role,
        now=current,
    )
    serialized = _serialize_promotion_envelope(envelope)
    envelope_sha256 = hashlib.sha256(serialized).hexdigest()
    validation_arguments = _promotion_validation_arguments(
        public_key_path=public_key_path,
        audience=expected_audience,
        key_id=expected_key_id,
        signer_role=expected_signer_role,
        deployment_id=expected_deployment_id,
        environment=expected_environment,
        live_arguments=live_arguments,
    )
    return _publish_model_promotion(
        output_path=output_path,
        serialized=serialized,
        expected_payload=verified_bundle.payload,
        expected_envelope_sha256=envelope_sha256,
        validation_arguments=validation_arguments,
        now=now,
        field="model promotion finalization output",
    )


def create_model_promotion(
    *,
    output_path: str | os.PathLike[str],
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    private_key_password: bytes | None,
    audience: str,
    key_id: str,
    signer_role: str,
    deployment_id: str,
    environment: str,
    approval_id: str,
    actor_id: str,
    actor_role: str,
    approval_reference: str,
    approved_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    promotion_evidence_path: str | os.PathLike[str],
    calibration_tasks_path: str | os.PathLike[str],
    calibration_evidence_path: str | os.PathLike[str],
    sealed_tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    verifier_results_path: str | os.PathLike[str],
    baseline_responses_path: str | os.PathLike[str],
    baseline_verifier_results_path: str | os.PathLike[str],
    policy_path: str | os.PathLike[str],
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None,
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None,
    csharp_verifier_replay_audit_path: str | os.PathLike[str] | None = None,
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None,
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None,
    csharp_verifier_replay_audit_now: datetime | None = None,
    catalog_path: str | os.PathLike[str],
    serving_profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    approval_evidence_path: str | os.PathLike[str],
    hosted_deployment_policy_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    now: datetime | None = None,
) -> VerifiedModelPromotion:
    live_arguments = dict(locals())
    payload, public_key, public_spki_sha256 = _build_model_promotion_payload(
        public_key_path=public_key_path,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        deployment_id=deployment_id,
        environment=environment,
        approval_id=approval_id,
        actor_id=actor_id,
        actor_role=actor_role,
        approval_reference=approval_reference,
        approved_at_utc=approved_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        live_arguments=live_arguments,
        now=now,
    )
    private_key, private_spki_sha256 = _load_private_key(
        private_key_path, private_key_password
    )
    if private_spki_sha256 != public_spki_sha256:
        _fail(
            "model promotion key pair",
            "private and externally pinned public keys differ",
        )
    payload_bytes = canonical_json_bytes(payload)
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=public_spki_sha256,
    )
    envelope["signature"] = _base64url_encode(
        _sign_p1363_low_s(private_key, _signature_input(envelope, payload_bytes))
    )
    current = _validation_time(
        now or datetime.now(timezone.utc), "model promotion signing time"
    )
    _validate_envelope_document(
        envelope,
        public_key=public_key,
        public_key_spki_sha256=public_spki_sha256,
        expected_audience=audience,
        expected_key_id=key_id,
        expected_signer_role=signer_role,
        now=current,
    )
    serialized = _serialize_promotion_envelope(envelope)
    envelope_sha256 = hashlib.sha256(serialized).hexdigest()
    validation_arguments = _promotion_validation_arguments(
        public_key_path=public_key_path,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        deployment_id=deployment_id,
        environment=environment,
        live_arguments=live_arguments,
    )
    return _publish_model_promotion(
        output_path=output_path,
        serialized=serialized,
        expected_payload=payload,
        expected_envelope_sha256=envelope_sha256,
        validation_arguments=validation_arguments,
        now=now,
        field="model promotion output",
    )
