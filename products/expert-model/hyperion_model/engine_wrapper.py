from __future__ import annotations

import errno
import hmac
import hashlib
import http.client
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import threading
import time
import urllib.parse
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, Sequence

from .core import (
    ValidationError,
    _reject_reparse_components,
    canonical_json_bytes,
    load_json_document,
    sha256_file,
)
from .deployment import (
    MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
    ServingProfile,
    compute_model_readiness_v2_proof,
    validate_model_readiness_v2_attestation,
)
from .review_receipts import ExpertModelReviewReceiptTrust

if TYPE_CHECKING:
    from .base_selection import BaseModelSelectionTrust
    from .evaluation import BaseResponseAttestationTrust
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust
    from .trainer_provenance import TrainerProvenanceTrust
    from .verifier_replay_audit import CSharpVerifierReplayAuditTrust


def validate_model_promotion(*args: Any, **kwargs: Any) -> Any:
    """Resolve promotion validation lazily to keep runtime primitives acyclic."""
    from .promotion import validate_model_promotion as validate

    return validate(*args, **kwargs)


ENGINE_WRAPPER_V1_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v1"
ENGINE_WRAPPER_V2_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v2"
ENGINE_WRAPPER_V3_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v3"
ENGINE_WRAPPER_V4_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v4"
ENGINE_WRAPPER_V5_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v5"
ENGINE_WRAPPER_V6_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v6"
ENGINE_WRAPPER_V7_SCHEMA_VERSION = "daxalgo.hyperion.engine-wrapper/v7"
# Backward-compatible public name for callers that author the established v1 wire format.
ENGINE_WRAPPER_SCHEMA_VERSION = ENGINE_WRAPPER_V1_SCHEMA_VERSION
READINESS_PATH = "/v1/daxalgo/readiness/attest"
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
MAX_ENGINE_WRAPPER_CONFIG_BYTES = 1_000_000

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_ENVIRONMENT_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
_SECRET_ENVIRONMENT_RE = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE
)
_LOOPBACK_HOST = "127.0.0.1"
_SAFE_CHILD_ENVIRONMENT_NAMES = {
    "CUDA_DEVICE_ORDER",
    "CUDA_VISIBLE_DEVICES",
    "HF_HOME",
    "HF_HUB_CACHE",
    "LANG",
    "LC_ALL",
    "NCCL_DEBUG",
    "NCCL_IB_DISABLE",
    "NCCL_P2P_DISABLE",
    "NVIDIA_DRIVER_CAPABILITIES",
    "NVIDIA_VISIBLE_DEVICES",
    "OMP_NUM_THREADS",
    "PATH",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "TOKENIZERS_PARALLELISM",
    "TORCH_HOME",
    "TRANSFORMERS_CACHE",
    "WINDIR",
}
_VLLM_LORA_RANKS = {1, 8, 16, 32, 64, 128, 256, 320, 512}
_SUPPORTED_VLLM_ENGINE_VERSIONS = {"0.10.0", "0.26.0"}

_SOURCE_FIELDS = {
    "promotionEvidencePath": "promotion_evidence_path",
    "calibrationTasksPath": "calibration_tasks_path",
    "calibrationEvidencePath": "calibration_evidence_path",
    "sealedTasksPath": "sealed_tasks_path",
    "responsesPath": "responses_path",
    "verifierResultsPath": "verifier_results_path",
    "baselineResponsesPath": "baseline_responses_path",
    "baselineVerifierResultsPath": "baseline_verifier_results_path",
    "policyPath": "policy_path",
    "dataReleasePath": "data_release_path",
    "catalogPath": "catalog_path",
    "servingProfilePath": "serving_profile_path",
    "artifactPath": "artifact_path",
    "manifestPath": "manifest_path",
    "approvalEvidencePath": "approval_evidence_path",
    "hostedDeploymentPolicyPath": "hosted_deployment_policy_path",
}


class WrapperState(str, Enum):
    CREATED = "created"
    PREVALIDATING = "prevalidating"
    STARTING = "starting"
    LOADING = "loading"
    POST_LOAD_VALIDATING = "post-load-validating"
    READY = "ready"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True)
class PromotionConfig:
    path: Path
    public_key_path: Path
    review_receipt_trust: ExpertModelReviewReceiptTrust
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None
    trainer_provenance_trust: TrainerProvenanceTrust | None
    expected_audience: str
    expected_key_id: str
    expected_signer_role: str
    expected_deployment_id: str
    expected_environment: str
    expected_envelope_sha256: str
    expected_serving_profile_sha256: str
    sources: Mapping[str, Path]
    candidate_attestation_trust: BaseResponseAttestationTrust | None = None
    baseline_attestation_trust: BaseResponseAttestationTrust | None = None
    csharp_verifier_replay_audit_path: Path | None = None
    csharp_verifier_replay_audit_trust: CSharpVerifierReplayAuditTrust | None = None
    expected_csharp_verifier_replay_audit_envelope_sha256: str | None = None

    def validation_arguments(self) -> dict[str, Any]:
        return {
            **self.sources,
            "candidate_attestation_trust": self.candidate_attestation_trust,
            "baseline_attestation_trust": self.baseline_attestation_trust,
            "csharp_verifier_replay_audit_path": (
                self.csharp_verifier_replay_audit_path
            ),
            "csharp_verifier_replay_audit_trust": (
                self.csharp_verifier_replay_audit_trust
            ),
            "expected_csharp_verifier_replay_audit_envelope_sha256": (
                self.expected_csharp_verifier_replay_audit_envelope_sha256
            ),
        }


@dataclass(frozen=True)
class EngineConfig:
    executable_path: Path
    executable_sha256: str
    container_image_digest_environment: str
    child_host: str
    child_port: int
    startup_timeout_seconds: float
    health_interval_seconds: float
    integrity_interval_seconds: float
    request_timeout_seconds: float
    shutdown_grace_seconds: float
    environment_allowlist: tuple[str, ...]
    child_user_id: int | None = None
    child_group_id: int | None = None


@dataclass(frozen=True)
class ServiceConfig:
    listen_host: str
    listen_port: int
    bearer_token_environment: str
    readiness_hmac_key_environment: str
    readiness_key_id: str
    max_request_bytes: int
    max_response_bytes: int


@dataclass(frozen=True)
class BaseSnapshotConfig:
    snapshot_path: Path
    selection_trust: BaseModelSelectionTrust


@dataclass(frozen=True)
class EngineWrapperConfig:
    path: Path
    promotion: PromotionConfig
    engine: EngineConfig
    service: ServiceConfig
    base_snapshot: BaseSnapshotConfig | None = None
    schema_version: str = ENGINE_WRAPPER_V7_SCHEMA_VERSION


@dataclass(frozen=True)
class ActivationSnapshot:
    promotion_envelope_sha256: str
    promotion_payload_sha256: str
    promotion_id: str
    serving_profile_sha256: str
    artifact_sha256: str
    artifact_tree_sha256: str
    execution_model_id: str
    deployment_id: str
    provider_id: str
    hosted_deployment_policy_sha256: str
    not_before_utc: str
    expires_at_utc: str
    upstream_authority_expires_at_utc: str
    evaluation_authoring_approval_payload_sha256: str
    evaluation_authoring_approval_envelope_sha256: str
    trainer_provenance_payload_sha256: str
    trainer_provenance_envelope_sha256: str
    trainer_provenance_expires_at_utc: str
    csharp_verifier_replay_audit_payload_sha256: str | None
    csharp_verifier_replay_audit_envelope_sha256: str | None
    max_lora_rank: int
    max_output_tokens_per_request: int
    executable_sha256: str
    engine_version: str
    training_manifest_sha256: str
    base_selection_id: str
    base_selection_payload_sha256: str
    base_profile_sha256: str
    base_execution_model_id: str
    base_snapshot_sha256: str
    base_file_tree_sha256: str
    base_snapshot_directory_identity: tuple[int, int, int, int]
    artifact_directory_identity: tuple[int, int, int, int]
    serving_profile: ServingProfile = field(repr=False, compare=False)


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


@dataclass(frozen=True)
class ServiceResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(
        default_factory=lambda: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        }
    )


class ChildProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


Transport = Callable[
    [str, str, Mapping[str, str], bytes | None, float, int], TransportResponse
]
ProcessFactory = Callable[[int, Sequence[str], Mapping[str, str], Path], ChildProcess]
Clock = Callable[[], datetime]
Monotonic = Callable[[], float]
Sleeper = Callable[[float], None]
ReadOnlyProbe = Callable[[Path], bool]
ListenerOwnershipProbe = Callable[[int, str, int], bool]
PrivilegeIsolationProbe = Callable[[EngineConfig], bool]
ChildPrivilegeProbe = Callable[[int, EngineConfig], bool]


def _fail(field: str, message: str) -> None:
    raise ValidationError(f"{field}: {message}")


class RequestValidationError(ValidationError):
    pass


def _request_fail(field: str, message: str) -> None:
    raise RequestValidationError(f"{field}: {message}")


def _exact_object(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(field, "must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        additional = sorted(actual - keys)
        details = []
        if missing:
            details.append(f"missing {missing!r}")
        if additional:
            details.append(f"additional {additional!r}")
        _fail(field, "; ".join(details))
    return value


def _text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail(field, f"must be a non-empty string no longer than {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(field, "must not contain control characters")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValidationError(f"{field}: must be valid Unicode text") from error
    return value


def _safe_id(value: Any, field: str) -> str:
    text = _text(value, field, maximum=200)
    if not _SAFE_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(field, "must be an integer")
    if value < minimum or value > maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return value


def _number(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(field, "must be a number")
    number = float(value)
    if number < minimum or number > maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return number


def _absolute_path(value: Any, field: str, *, directory: bool = False) -> Path:
    text = _text(value, field, maximum=2_000)
    path = Path(text)
    if not path.is_absolute():
        _fail(field, "must be an absolute path")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if directory:
        if not absolute.is_dir():
            _fail(field, "must identify an existing directory")
    elif not absolute.is_file():
        _fail(field, "must identify an existing regular file")
    return absolute


def _environment_name(value: Any, field: str) -> str:
    name = _text(value, field, maximum=128)
    if not _ENVIRONMENT_NAME_RE.fullmatch(name):
        _fail(field, "must be a valid environment-variable name")
    return name


def _validate_json_depth(value: Any, depth: int = 1) -> None:
    if depth > 24:
        _fail("engine wrapper config", "must not exceed 24 JSON nesting levels")
    if isinstance(value, dict):
        for child in value.values():
            _validate_json_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_depth(child, depth + 1)


def _response_attestation_trust(
    value: Any,
    field: str,
) -> BaseResponseAttestationTrust | None:
    from .base_engine_wrapper import BaseEngineActivationTrust
    from .evaluation import BaseResponseAttestationTrust

    if value is None:
        return None
    trust_value = _exact_object(
        value,
        {"activationTrust", "runtimePublicKeyPath"},
        field,
    )
    activation_value = _exact_object(
        trust_value["activationTrust"],
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        f"{field}.activationTrust",
    )
    return BaseResponseAttestationTrust(
        activation_trust=BaseEngineActivationTrust(
            public_key_path=_absolute_path(
                activation_value["publicKeyPath"],
                f"{field}.activationTrust.publicKeyPath",
            ),
            public_key_spki_sha256=_text(
                activation_value["publicKeySpkiSha256"],
                f"{field}.activationTrust.publicKeySpkiSha256",
                maximum=64,
            ),
            audience=_safe_id(
                activation_value["audience"],
                f"{field}.activationTrust.audience",
            ),
            key_id=_safe_id(
                activation_value["keyId"],
                f"{field}.activationTrust.keyId",
            ),
            signer_role=_safe_id(
                activation_value["signerRole"],
                f"{field}.activationTrust.signerRole",
            ),
        ),
        runtime_public_key_path=_absolute_path(
            trust_value["runtimePublicKeyPath"],
            f"{field}.runtimePublicKeyPath",
        ),
    )


def _base_selection_trust(value: Any, field: str) -> BaseModelSelectionTrust:
    from .base_selection import BaseModelSelectionTrust

    trust = _exact_object(
        value,
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        field,
    )
    spki_sha256 = _text(
        trust["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256", maximum=64
    )
    if not _SHA256_RE.fullmatch(spki_sha256):
        _fail(f"{field}.publicKeySpkiSha256", "must be a lowercase SHA-256")
    return BaseModelSelectionTrust(
        public_key_path=_absolute_path(
            trust["publicKeyPath"], f"{field}.publicKeyPath"
        ),
        public_key_spki_sha256=spki_sha256,
        audience=_safe_id(trust["audience"], f"{field}.audience"),
        key_id=_safe_id(trust["keyId"], f"{field}.keyId"),
        signer_role=_safe_id(trust["signerRole"], f"{field}.signerRole"),
    )


def _csharp_verifier_replay_audit_trust(
    value: Any, field: str
) -> CSharpVerifierReplayAuditTrust:
    from .verifier_replay_audit import CSharpVerifierReplayAuditTrust

    trust = _exact_object(
        value,
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        field,
    )
    spki_sha256 = _text(
        trust["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256", maximum=64
    )
    if not _SHA256_RE.fullmatch(spki_sha256):
        _fail(f"{field}.publicKeySpkiSha256", "must be a lowercase SHA-256")
    return CSharpVerifierReplayAuditTrust(
        public_key_path=_absolute_path(
            trust["publicKeyPath"], f"{field}.publicKeyPath"
        ),
        public_key_spki_sha256=spki_sha256,
        audience=_safe_id(trust["audience"], f"{field}.audience"),
        key_id=_safe_id(trust["keyId"], f"{field}.keyId"),
        signer_role=_safe_id(trust["signerRole"], f"{field}.signerRole"),
    )


def _evaluation_authoring_approval_trust(
    value: Any, field: str
) -> EvaluationAuthoringApprovalTrust:
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust

    trust = _exact_object(
        value,
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        field,
    )
    spki_sha256 = _text(
        trust["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256", maximum=64
    )
    if not _SHA256_RE.fullmatch(spki_sha256):
        _fail(f"{field}.publicKeySpkiSha256", "must be a lowercase SHA-256")
    return EvaluationAuthoringApprovalTrust(
        public_key_path=_absolute_path(
            trust["publicKeyPath"], f"{field}.publicKeyPath"
        ),
        public_key_spki_sha256=spki_sha256,
        audience=_safe_id(trust["audience"], f"{field}.audience"),
        key_id=_safe_id(trust["keyId"], f"{field}.keyId"),
        signer_role=_safe_id(trust["signerRole"], f"{field}.signerRole"),
    )


def _trainer_provenance_trust(value: Any, field: str) -> TrainerProvenanceTrust:
    from .trainer_provenance import TrainerProvenanceTrust

    trust = _exact_object(
        value,
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        field,
    )
    spki_sha256 = _text(
        trust["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256", maximum=64
    )
    if not _SHA256_RE.fullmatch(spki_sha256):
        _fail(f"{field}.publicKeySpkiSha256", "must be a lowercase SHA-256")
    return TrainerProvenanceTrust(
        public_key_path=_absolute_path(
            trust["publicKeyPath"], f"{field}.publicKeyPath"
        ),
        public_key_spki_sha256=spki_sha256,
        audience=_safe_id(trust["audience"], f"{field}.audience"),
        key_id=_safe_id(trust["keyId"], f"{field}.keyId"),
        signer_role=_safe_id(trust["signerRole"], f"{field}.signerRole"),
    )


def _teacher_lineage_admission_trust(value: Any, field: str) -> Any:
    from .teacher_lineage import TeacherMaterializationLineageAdmissionTrust

    trust = _exact_object(
        value,
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        field,
    )
    spki_sha256 = _text(
        trust["publicKeySpkiSha256"], f"{field}.publicKeySpkiSha256", maximum=64
    )
    if not _SHA256_RE.fullmatch(spki_sha256):
        _fail(f"{field}.publicKeySpkiSha256", "must be a lowercase SHA-256")
    return TeacherMaterializationLineageAdmissionTrust(
        public_key_path=_absolute_path(
            trust["publicKeyPath"], f"{field}.publicKeyPath"
        ),
        public_key_spki_sha256=spki_sha256,
        audience=_safe_id(trust["audience"], f"{field}.audience"),
        key_id=_safe_id(trust["keyId"], f"{field}.keyId"),
        signer_role=_safe_id(trust["signerRole"], f"{field}.signerRole"),
    )


def load_engine_wrapper_config(
    path: str | os.PathLike[str],
) -> EngineWrapperConfig:
    config_path = Path(os.path.abspath(os.fspath(path)))
    try:
        value = load_json_document(
            config_path, max_bytes=MAX_ENGINE_WRAPPER_CONFIG_BYTES
        )
    except ValidationError:
        raise
    except ValueError as error:
        raise ValidationError(
            "engine wrapper config: invalid bounded JSON number"
        ) from error
    _validate_json_depth(value)
    if not isinstance(value, dict):
        _fail("engine wrapper config", "must be an object")
    schema_version = value.get("schemaVersion")
    root_fields = {"schemaVersion", "promotion", "engine", "service"}
    if schema_version in {
        ENGINE_WRAPPER_V3_SCHEMA_VERSION,
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        root_fields.add("baseSnapshot")
    document = _exact_object(value, root_fields, "engine wrapper config")
    schema_version = document["schemaVersion"]
    if schema_version not in {
        ENGINE_WRAPPER_V1_SCHEMA_VERSION,
        ENGINE_WRAPPER_V2_SCHEMA_VERSION,
        ENGINE_WRAPPER_V3_SCHEMA_VERSION,
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        _fail(
            "engine wrapper config.schemaVersion",
            "must be one of "
            f"{ENGINE_WRAPPER_V1_SCHEMA_VERSION!r} or "
            f"{ENGINE_WRAPPER_V2_SCHEMA_VERSION!r}, "
            f"{ENGINE_WRAPPER_V3_SCHEMA_VERSION!r}, or "
            f"{ENGINE_WRAPPER_V4_SCHEMA_VERSION!r}, or "
            f"{ENGINE_WRAPPER_V5_SCHEMA_VERSION!r}, or "
            f"{ENGINE_WRAPPER_V6_SCHEMA_VERSION!r}, or "
            f"{ENGINE_WRAPPER_V7_SCHEMA_VERSION!r}",
        )

    promotion_fields = {
        "path",
        "publicKeyPath",
        "reviewReceiptTrust",
        "expectedAudience",
        "expectedKeyId",
        "expectedSignerRole",
        "expectedDeploymentId",
        "expectedEnvironment",
        "expectedEnvelopeSha256",
        "expectedServingProfileSha256",
        "sources",
    }
    if schema_version in {
        ENGINE_WRAPPER_V2_SCHEMA_VERSION,
        ENGINE_WRAPPER_V3_SCHEMA_VERSION,
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        promotion_fields.update(
            {"candidateAttestationTrust", "baselineAttestationTrust"}
        )
    if schema_version in {
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        promotion_fields.add("csharpVerifierReplayAudit")
    if schema_version in {
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        promotion_fields.add("evaluationAuthoringApprovalTrust")
    if schema_version in {
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        promotion_fields.add("trainerProvenanceTrust")
    if schema_version == ENGINE_WRAPPER_V7_SCHEMA_VERSION:
        promotion_fields.add("teacherLineageAdmissionTrust")
    promotion_value = _exact_object(
        document["promotion"],
        promotion_fields,
        "engine wrapper config.promotion",
    )
    review_receipt_trust_value = _exact_object(
        promotion_value["reviewReceiptTrust"],
        {"publicKeyPath", "publicKeySpkiSha256", "audience", "keyId", "signerRole"},
        "engine wrapper config.promotion.reviewReceiptTrust",
    )
    sources_value = _exact_object(
        promotion_value["sources"],
        set(_SOURCE_FIELDS),
        "engine wrapper config.promotion.sources",
    )
    sources = {
        argument: _absolute_path(
            sources_value[name],
            f"engine wrapper config.promotion.sources.{name}",
            directory=name in {"dataReleasePath", "artifactPath"},
        )
        for name, argument in _SOURCE_FIELDS.items()
    }
    replay_audit_path = None
    replay_audit_trust = None
    replay_audit_envelope_sha256 = None
    if schema_version in {
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        replay_audit_raw = promotion_value["csharpVerifierReplayAudit"]
        if replay_audit_raw is not None:
            replay_audit_value = _exact_object(
                replay_audit_raw,
                {"path", "expectedEnvelopeSha256", "trust"},
                "engine wrapper config.promotion.csharpVerifierReplayAudit",
            )
            replay_audit_path = _absolute_path(
                replay_audit_value["path"],
                "engine wrapper config.promotion.csharpVerifierReplayAudit.path",
            )
            replay_audit_envelope_sha256 = _text(
                replay_audit_value["expectedEnvelopeSha256"],
                "engine wrapper config.promotion.csharpVerifierReplayAudit.expectedEnvelopeSha256",
                maximum=64,
            )
            if not _SHA256_RE.fullmatch(replay_audit_envelope_sha256):
                _fail(
                    "engine wrapper config.promotion.csharpVerifierReplayAudit.expectedEnvelopeSha256",
                    "must be a lowercase SHA-256",
                )
            replay_audit_trust = _csharp_verifier_replay_audit_trust(
                replay_audit_value["trust"],
                "engine wrapper config.promotion.csharpVerifierReplayAudit.trust",
            )
        elif schema_version == ENGINE_WRAPPER_V4_SCHEMA_VERSION:
            _fail(
                "engine wrapper config.promotion.csharpVerifierReplayAudit",
                "must be an object for engine-wrapper/v4",
            )
    authoring_trust = None
    if schema_version in {
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        authoring_trust = _evaluation_authoring_approval_trust(
            promotion_value["evaluationAuthoringApprovalTrust"],
            "engine wrapper config.promotion.evaluationAuthoringApprovalTrust",
        )
    trainer_trust = None
    if schema_version in {
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        trainer_trust = _trainer_provenance_trust(
            promotion_value["trainerProvenanceTrust"],
            "engine wrapper config.promotion.trainerProvenanceTrust",
        )
    teacher_lineage_trust = None
    if schema_version == ENGINE_WRAPPER_V7_SCHEMA_VERSION:
        raw_teacher_lineage_trust = promotion_value["teacherLineageAdmissionTrust"]
        if raw_teacher_lineage_trust is not None:
            teacher_lineage_trust = _teacher_lineage_admission_trust(
                raw_teacher_lineage_trust,
                "engine wrapper config.promotion.teacherLineageAdmissionTrust",
            )
    promotion = PromotionConfig(
        path=_absolute_path(
            promotion_value["path"], "engine wrapper config.promotion.path"
        ),
        public_key_path=_absolute_path(
            promotion_value["publicKeyPath"],
            "engine wrapper config.promotion.publicKeyPath",
        ),
        review_receipt_trust=ExpertModelReviewReceiptTrust(
            public_key_path=_absolute_path(
                review_receipt_trust_value["publicKeyPath"],
                "engine wrapper config.promotion.reviewReceiptTrust.publicKeyPath",
            ),
            public_key_spki_sha256=_text(
                review_receipt_trust_value["publicKeySpkiSha256"],
                "engine wrapper config.promotion.reviewReceiptTrust.publicKeySpkiSha256",
                maximum=64,
            ),
            audience=_safe_id(
                review_receipt_trust_value["audience"],
                "engine wrapper config.promotion.reviewReceiptTrust.audience",
            ),
            key_id=_safe_id(
                review_receipt_trust_value["keyId"],
                "engine wrapper config.promotion.reviewReceiptTrust.keyId",
            ),
            signer_role=_safe_id(
                review_receipt_trust_value["signerRole"],
                "engine wrapper config.promotion.reviewReceiptTrust.signerRole",
            ),
            teacher_lineage_admission_trust=teacher_lineage_trust,
        ),
        evaluation_authoring_approval_trust=authoring_trust,
        trainer_provenance_trust=trainer_trust,
        expected_audience=_safe_id(
            promotion_value["expectedAudience"],
            "engine wrapper config.promotion.expectedAudience",
        ),
        expected_key_id=_safe_id(
            promotion_value["expectedKeyId"],
            "engine wrapper config.promotion.expectedKeyId",
        ),
        expected_signer_role=_safe_id(
            promotion_value["expectedSignerRole"],
            "engine wrapper config.promotion.expectedSignerRole",
        ),
        expected_deployment_id=_safe_id(
            promotion_value["expectedDeploymentId"],
            "engine wrapper config.promotion.expectedDeploymentId",
        ),
        expected_environment=_safe_id(
            promotion_value["expectedEnvironment"],
            "engine wrapper config.promotion.expectedEnvironment",
        ),
        expected_envelope_sha256=_text(
            promotion_value["expectedEnvelopeSha256"],
            "engine wrapper config.promotion.expectedEnvelopeSha256",
            maximum=64,
        ),
        expected_serving_profile_sha256=_text(
            promotion_value["expectedServingProfileSha256"],
            "engine wrapper config.promotion.expectedServingProfileSha256",
            maximum=64,
        ),
        sources=sources,
        candidate_attestation_trust=(
            _response_attestation_trust(
                promotion_value["candidateAttestationTrust"],
                "engine wrapper config.promotion.candidateAttestationTrust",
            )
            if schema_version
            in {
                ENGINE_WRAPPER_V2_SCHEMA_VERSION,
                ENGINE_WRAPPER_V3_SCHEMA_VERSION,
                ENGINE_WRAPPER_V4_SCHEMA_VERSION,
                ENGINE_WRAPPER_V5_SCHEMA_VERSION,
                ENGINE_WRAPPER_V6_SCHEMA_VERSION,
                ENGINE_WRAPPER_V7_SCHEMA_VERSION,
            }
            else None
        ),
        baseline_attestation_trust=(
            _response_attestation_trust(
                promotion_value["baselineAttestationTrust"],
                "engine wrapper config.promotion.baselineAttestationTrust",
            )
            if schema_version
            in {
                ENGINE_WRAPPER_V2_SCHEMA_VERSION,
                ENGINE_WRAPPER_V3_SCHEMA_VERSION,
                ENGINE_WRAPPER_V4_SCHEMA_VERSION,
                ENGINE_WRAPPER_V5_SCHEMA_VERSION,
                ENGINE_WRAPPER_V6_SCHEMA_VERSION,
                ENGINE_WRAPPER_V7_SCHEMA_VERSION,
            }
            else None
        ),
        csharp_verifier_replay_audit_path=replay_audit_path,
        csharp_verifier_replay_audit_trust=replay_audit_trust,
        expected_csharp_verifier_replay_audit_envelope_sha256=(
            replay_audit_envelope_sha256
        ),
    )
    if not _SHA256_RE.fullmatch(promotion.expected_envelope_sha256):
        _fail(
            "engine wrapper config.promotion.expectedEnvelopeSha256",
            "must be a lowercase SHA-256",
        )
    if not _SHA256_RE.fullmatch(promotion.expected_serving_profile_sha256):
        _fail(
            "engine wrapper config.promotion.expectedServingProfileSha256",
            "must be a lowercase SHA-256",
        )

    engine_fields = {
        "executablePath",
        "executableSha256",
        "containerImageDigestEnvironment",
        "childHost",
        "childPort",
        "startupTimeoutSeconds",
        "healthIntervalSeconds",
        "integrityIntervalSeconds",
        "requestTimeoutSeconds",
        "shutdownGraceSeconds",
        "environmentAllowlist",
    }
    if schema_version in {
        ENGINE_WRAPPER_V3_SCHEMA_VERSION,
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        engine_fields.update({"childUserId", "childGroupId"})
    engine_value = _exact_object(
        document["engine"],
        engine_fields,
        "engine wrapper config.engine",
    )
    executable_hash = _text(
        engine_value["executableSha256"],
        "engine wrapper config.engine.executableSha256",
        maximum=64,
    )
    if not _SHA256_RE.fullmatch(executable_hash):
        _fail(
            "engine wrapper config.engine.executableSha256",
            "must be a lowercase SHA-256",
        )
    if engine_value["childHost"] != _LOOPBACK_HOST:
        _fail("engine wrapper config.engine.childHost", "must be '127.0.0.1'")
    allowlist_value = engine_value["environmentAllowlist"]
    if not isinstance(allowlist_value, list) or len(allowlist_value) > 64:
        _fail(
            "engine wrapper config.engine.environmentAllowlist",
            "must be an array of at most 64 names",
        )
    allowlist: list[str] = []
    for index, item in enumerate(allowlist_value):
        name = _environment_name(
            item, f"engine wrapper config.engine.environmentAllowlist[{index}]"
        )
        if name in allowlist:
            _fail(
                "engine wrapper config.engine.environmentAllowlist",
                f"contains duplicate name {name!r}",
            )
        if _SECRET_ENVIRONMENT_RE.search(name):
            _fail(
                "engine wrapper config.engine.environmentAllowlist",
                f"secret-bearing name {name!r} is not accepted",
            )
        if name not in _SAFE_CHILD_ENVIRONMENT_NAMES:
            _fail(
                "engine wrapper config.engine.environmentAllowlist",
                f"name {name!r} is not in the safe child-environment allowlist",
            )
        allowlist.append(name)
    engine = EngineConfig(
        executable_path=_absolute_path(
            engine_value["executablePath"],
            "engine wrapper config.engine.executablePath",
        ),
        executable_sha256=executable_hash,
        container_image_digest_environment=_environment_name(
            engine_value["containerImageDigestEnvironment"],
            "engine wrapper config.engine.containerImageDigestEnvironment",
        ),
        child_host=_LOOPBACK_HOST,
        child_port=_integer(
            engine_value["childPort"],
            "engine wrapper config.engine.childPort",
            1,
            65_535,
        ),
        startup_timeout_seconds=_number(
            engine_value["startupTimeoutSeconds"],
            "engine wrapper config.engine.startupTimeoutSeconds",
            1,
            3_600,
        ),
        health_interval_seconds=_number(
            engine_value["healthIntervalSeconds"],
            "engine wrapper config.engine.healthIntervalSeconds",
            0.1,
            60,
        ),
        integrity_interval_seconds=_number(
            engine_value["integrityIntervalSeconds"],
            "engine wrapper config.engine.integrityIntervalSeconds",
            1,
            300,
        ),
        request_timeout_seconds=_number(
            engine_value["requestTimeoutSeconds"],
            "engine wrapper config.engine.requestTimeoutSeconds",
            0.1,
            600,
        ),
        shutdown_grace_seconds=_number(
            engine_value["shutdownGraceSeconds"],
            "engine wrapper config.engine.shutdownGraceSeconds",
            0,
            60,
        ),
        environment_allowlist=tuple(allowlist),
        child_user_id=(
            _integer(
                engine_value["childUserId"],
                "engine wrapper config.engine.childUserId",
                1,
                2_147_483_647,
            )
            if schema_version
            in {
                ENGINE_WRAPPER_V3_SCHEMA_VERSION,
                ENGINE_WRAPPER_V4_SCHEMA_VERSION,
                ENGINE_WRAPPER_V5_SCHEMA_VERSION,
                ENGINE_WRAPPER_V6_SCHEMA_VERSION,
                ENGINE_WRAPPER_V7_SCHEMA_VERSION,
            }
            else None
        ),
        child_group_id=(
            _integer(
                engine_value["childGroupId"],
                "engine wrapper config.engine.childGroupId",
                1,
                2_147_483_647,
            )
            if schema_version
            in {
                ENGINE_WRAPPER_V3_SCHEMA_VERSION,
                ENGINE_WRAPPER_V4_SCHEMA_VERSION,
                ENGINE_WRAPPER_V5_SCHEMA_VERSION,
                ENGINE_WRAPPER_V6_SCHEMA_VERSION,
                ENGINE_WRAPPER_V7_SCHEMA_VERSION,
            }
            else None
        ),
    )

    service_value = _exact_object(
        document["service"],
        {
            "listenHost",
            "listenPort",
            "bearerTokenEnvironment",
            "readinessHmacKeyEnvironment",
            "readinessKeyId",
            "maxRequestBytes",
            "maxResponseBytes",
        },
        "engine wrapper config.service",
    )
    if service_value["listenHost"] != _LOOPBACK_HOST:
        _fail("engine wrapper config.service.listenHost", "must be '127.0.0.1'")
    bearer_environment = _environment_name(
        service_value["bearerTokenEnvironment"],
        "engine wrapper config.service.bearerTokenEnvironment",
    )
    hmac_environment = _environment_name(
        service_value["readinessHmacKeyEnvironment"],
        "engine wrapper config.service.readinessHmacKeyEnvironment",
    )
    wrapper_environment_names = {
        bearer_environment.upper(),
        hmac_environment.upper(),
        engine.container_image_digest_environment.upper(),
    }
    if len(wrapper_environment_names) != 3:
        _fail(
            "engine wrapper config",
            "container-image, bearer, and HMAC values must use distinct environment variables",
        )
    if bearer_environment in allowlist or hmac_environment in allowlist:
        _fail(
            "engine wrapper config.engine.environmentAllowlist",
            "must not include wrapper bearer or HMAC secret variables",
        )
    if engine.container_image_digest_environment in allowlist:
        _fail(
            "engine wrapper config.engine.environmentAllowlist",
            "must not include the trusted current-image variable",
        )
    service = ServiceConfig(
        listen_host=_LOOPBACK_HOST,
        listen_port=_integer(
            service_value["listenPort"],
            "engine wrapper config.service.listenPort",
            1,
            65_535,
        ),
        bearer_token_environment=bearer_environment,
        readiness_hmac_key_environment=hmac_environment,
        readiness_key_id=_safe_id(
            service_value["readinessKeyId"],
            "engine wrapper config.service.readinessKeyId",
        ),
        max_request_bytes=_integer(
            service_value["maxRequestBytes"],
            "engine wrapper config.service.maxRequestBytes",
            1_024,
            8_000_000,
        ),
        max_response_bytes=_integer(
            service_value["maxResponseBytes"],
            "engine wrapper config.service.maxResponseBytes",
            1_024,
            16_000_000,
        ),
    )
    if service.listen_port == engine.child_port:
        _fail("engine wrapper config", "outer and child ports must be distinct")
    base_snapshot = None
    if schema_version in {
        ENGINE_WRAPPER_V3_SCHEMA_VERSION,
        ENGINE_WRAPPER_V4_SCHEMA_VERSION,
        ENGINE_WRAPPER_V5_SCHEMA_VERSION,
        ENGINE_WRAPPER_V6_SCHEMA_VERSION,
        ENGINE_WRAPPER_V7_SCHEMA_VERSION,
    }:
        base_snapshot_value = _exact_object(
            document["baseSnapshot"],
            {"snapshotPath", "selectionTrust"},
            "engine wrapper config.baseSnapshot",
        )
        base_snapshot = BaseSnapshotConfig(
            snapshot_path=_absolute_path(
                base_snapshot_value["snapshotPath"],
                "engine wrapper config.baseSnapshot.snapshotPath",
                directory=True,
            ),
            selection_trust=_base_selection_trust(
                base_snapshot_value["selectionTrust"],
                "engine wrapper config.baseSnapshot.selectionTrust",
            ),
        )
    return EngineWrapperConfig(
        config_path,
        promotion,
        engine,
        service,
        base_snapshot,
        schema_version=schema_version,
    )


def _load_bearer_secret(environment_name: str) -> str:
    value = os.environ.get(environment_name)
    if value is None:
        _fail("bearer-token environment variable", f"{environment_name!r} is not set")
    if not 32 <= len(value) <= 512 or any(
        ord(character) <= 32 or ord(character) >= 127 for character in value
    ):
        _fail(
            "bearer-token environment variable",
            "must contain 32 through 512 visible non-space ASCII characters",
        )
    return value


def _load_hmac_secret(environment_name: str) -> bytes:
    value = os.environ.get(environment_name)
    if value is None:
        _fail("readiness-key environment variable", f"{environment_name!r} is not set")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value) or len(value) > 1_024:
        _fail(
            "readiness-key environment variable",
            "must contain canonical unpadded base64url",
        )
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ValidationError(
            "readiness-key environment variable: must contain canonical unpadded base64url"
        ) from error
    if urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        _fail(
            "readiness-key environment variable",
            "must contain canonical unpadded base64url",
        )
    if not 32 <= len(decoded) <= 512:
        _fail(
            "readiness-key environment variable",
            "must decode to 32 through 512 bytes",
        )
    return decoded


def _default_read_only_probe(path: Path) -> bool:
    if os.name != "posix" or not hasattr(os, "statvfs"):
        return False
    try:
        return bool(os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1))
    except OSError:
        return False


def _directory_identity(path: Path, field: str) -> tuple[int, int, int, int]:
    try:
        value = os.lstat(path)
    except OSError as error:
        raise ValidationError(
            f"{field}: cannot inspect directory identity: {error}"
        ) from error
    if not stat.S_ISDIR(value.st_mode):
        _fail(field, "must remain a directory")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_mtime_ns)


def _validation_time(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        _fail(field, "must be timezone-aware UTC")
    return value.astimezone(timezone.utc)


def _canonical_utc(value: str, field: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as error:
        raise ValidationError(f"{field}: must be canonical UTC text") from error
    return parsed.replace(tzinfo=timezone.utc)


def _parse_json_bytes(raw: bytes, field: str, *, maximum_depth: int = 32) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(field, "UTF-8 byte-order marks are not accepted")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(field, f"duplicate object key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        _fail(field, f"non-finite number {value!r} is not accepted")

    def parse_integer(value: str) -> int:
        if len(value) > 100:
            _fail(field, "integer is excessively large")
        return int(value)

    def parse_float(value: str) -> float:
        if len(value) > 100:
            _fail(field, "number is excessively large")
        number = float(value)
        if not math.isfinite(number):
            _fail(field, "non-finite numbers are not accepted")
        return number

    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
            parse_int=parse_integer,
            parse_float=parse_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError(f"{field}: must be strict UTF-8 JSON") from error

    def check_depth(child: Any, depth: int) -> None:
        if depth > maximum_depth:
            _fail(field, f"must not exceed {maximum_depth} JSON nesting levels")
        if isinstance(child, dict):
            for key, item in child.items():
                try:
                    key.encode("utf-8", errors="strict")
                except UnicodeEncodeError as error:
                    raise ValidationError(
                        f"{field}: object keys must be valid Unicode text"
                    ) from error
                check_depth(item, depth + 1)
        elif isinstance(child, list):
            for item in child:
                check_depth(item, depth + 1)
        elif isinstance(child, str):
            try:
                child.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise ValidationError(
                    f"{field}: strings must be valid Unicode text"
                ) from error

    check_depth(value, 1)
    return value


def _default_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_seconds: float,
    max_response_bytes: int,
) -> TransportResponse:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != _LOOPBACK_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        _fail("child engine URL", "must be a direct loopback HTTP URL")
    path = parsed.path or "/"
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port, timeout=timeout_seconds
    )
    try:
        connection.request(method, path, body=body, headers=dict(headers))
        response = connection.getresponse()
        lengths = response.headers.get_all("Content-Length", failobj=[])
        if len(lengths) > 1:
            _fail("child engine response", "contains duplicate Content-Length headers")
        if len(response.headers.get_all("Content-Type", failobj=[])) > 1:
            _fail("child engine response", "contains duplicate Content-Type headers")
        length = lengths[0] if lengths else None
        if length is not None:
            try:
                if int(length) > max_response_bytes:
                    _fail("child engine response", "exceeds the configured byte limit")
            except ValueError as error:
                raise ValidationError(
                    "child engine response: invalid Content-Length"
                ) from error
        response_body = response.read(max_response_bytes + 1)
        status = response.status
        response_headers = dict(response.getheaders())
    except (OSError, http.client.HTTPException) as error:
        raise ValidationError(f"child engine request failed: {error}") from error
    finally:
        connection.close()
    if len(response_body) > max_response_bytes:
        _fail("child engine response", "exceeds the configured byte limit")
    return TransportResponse(status, response_headers, response_body, url)


def _opened_fd_path(executable_fd: int) -> str:
    if os.name != "posix":
        _fail(
            "child engine process",
            "native Windows launch is unsupported; run the wrapper in its pinned POSIX container",
        )
    path = f"/proc/self/fd/{executable_fd}"
    if not Path(path).exists():
        _fail("child engine process", "/proc/self/fd is required")
    return path


def _default_process_factory(
    executable_fd: int,
    argv: Sequence[str],
    environment: Mapping[str, str],
    working_directory: Path,
    *,
    child_user_id: int,
    child_group_id: int,
) -> ChildProcess:
    fd_path = _opened_fd_path(executable_fd)
    process = subprocess.Popen(
        list(argv),
        executable=fd_path,
        pass_fds=(executable_fd,),
        cwd=working_directory,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        shell=False,
        start_new_session=True,
        user=child_user_id,
        group=child_group_id,
        extra_groups=[],
        umask=0o077,
    )
    return _OwnedPopen(process)


def _default_listener_ownership_probe(process_id: int, host: str, port: int) -> bool:
    if os.name != "posix" or host != _LOOPBACK_HOST or not Path("/proc").is_dir():
        return False
    try:
        if os.getpgid(process_id) != process_id:
            return False
    except OSError:
        return False
    listener_inodes: set[str] = set()
    expected_port = f"{port:04X}"
    for table_path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = table_path.read_text(
                encoding="ascii", errors="strict"
            ).splitlines()[1:]
        except (OSError, UnicodeError):
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                address, encoded_port = fields[1].rsplit(":", 1)
            except ValueError:
                continue
            if encoded_port != expected_port:
                continue
            if table_path.name == "tcp" and address != "0100007F":
                continue
            if table_path.name == "tcp6" and address not in {
                "00000000000000000000000001000000",
                "0000000000000000FFFF00000100007F",
            }:
                continue
            listener_inodes.add(fields[9])
    if len(listener_inodes) != 1:
        return False
    expected_socket = f"socket:[{next(iter(listener_inodes))}]"
    try:
        process_paths = tuple(Path("/proc").iterdir())
    except OSError:
        return False
    for process_path in process_paths:
        if not process_path.name.isdigit():
            continue
        candidate_pid = int(process_path.name)
        try:
            if os.getpgid(candidate_pid) != process_id:
                continue
            descriptors = tuple((process_path / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                if os.readlink(descriptor) == expected_socket:
                    return True
            except OSError:
                continue
    return False


def _default_privilege_isolation_probe(config: EngineConfig) -> bool:
    if (
        os.name != "posix"
        or not hasattr(os, "geteuid")
        or not hasattr(os, "getegid")
        or os.geteuid() != 0
    ):
        return False
    if not (
        config.child_user_id is not None
        and config.child_group_id is not None
        and config.child_user_id not in {0, os.geteuid()}
        and config.child_group_id not in {0, os.getegid()}
    ):
        return False
    status = _proc_status(os.getpid())
    return status.get("NoNewPrivs") == "1"


def _proc_status(process_id: int) -> dict[str, str]:
    if os.name != "posix":
        return {}
    try:
        lines = (
            Path(f"/proc/{process_id}/status")
            .read_text(encoding="ascii", errors="strict")
            .splitlines()
        )
    except (OSError, UnicodeError):
        return {}
    result: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition(":")
        if separator:
            result[name] = value.strip()
    return result


def _default_child_privilege_probe(process_id: int, config: EngineConfig) -> bool:
    if (
        os.name != "posix"
        or config.child_user_id is None
        or config.child_group_id is None
    ):
        return False
    status = _proc_status(process_id)
    expected_user = str(config.child_user_id)
    expected_group = str(config.child_group_id)
    if status.get("Uid", "").split() != [expected_user] * 4:
        return False
    if status.get("Gid", "").split() != [expected_group] * 4:
        return False
    if status.get("Groups", "").split():
        return False
    if status.get("NoNewPrivs") != "1":
        return False
    try:
        return all(
            int(status.get(name, "-1"), 16) == 0
            for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        )
    except ValueError:
        return False


def _hash_opened_file(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1_048_576)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_verified_executable(path: Path, expected_sha256: str) -> int:
    resolved = _reject_reparse_components(path, "engine executable")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise ValidationError(
            f"engine executable: cannot open safely: {error}"
        ) from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _fail("engine executable", "must be a single-link regular file")
        if os.name == "posix":
            if info.st_uid != os.geteuid():
                _fail("engine executable", "must be owned by the wrapper identity")
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                _fail("engine executable", "must deny group and other write bits")
            if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                _fail(
                    "engine executable",
                    "must not carry set-user-ID or set-group-ID bits",
                )
            if not info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                _fail("engine executable", "must carry an execute permission bit")
            if hasattr(os, "getxattr"):
                try:
                    capabilities = os.getxattr(descriptor, "security.capability")
                except OSError as error:
                    unsupported = {
                        errno.ENODATA,
                        errno.ENOTSUP,
                        getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                    }
                    if error.errno not in unsupported:
                        raise ValidationError(
                            f"engine executable: cannot inspect file capabilities: {error}"
                        ) from error
                else:
                    if capabilities:
                        _fail(
                            "engine executable",
                            "must not carry Linux file capabilities",
                        )
        if _hash_opened_file(descriptor) != expected_sha256:
            _fail("engine executable", "opened inode does not match configured SHA-256")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


class _OwnedPopen:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self.pid = process.pid

    def poll(self) -> int | None:
        return self._process.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._process.wait(timeout=timeout)

    def terminate(self) -> None:
        if os.name == "nt":
            self._process.terminate()
        else:
            os.killpg(self.pid, signal.SIGTERM)

    def kill(self) -> None:
        if os.name == "nt":
            self._process.kill()
        else:
            os.killpg(self.pid, signal.SIGKILL)

    def ensure_process_group_stopped(self, timeout: float) -> None:
        if os.name == "nt":
            return
        try:
            os.killpg(self.pid, 0)
        except ProcessLookupError:
            return
        os.killpg(self.pid, signal.SIGKILL)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                os.killpg(self.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        _fail("child engine process group", "remains alive after SIGKILL")


def _error_response(status: int, code: str) -> ServiceResponse:
    return ServiceResponse(status, canonical_json_bytes({"error": {"code": code}}))


def _require_json_content_type(headers: Mapping[str, str], field: str) -> None:
    content_type = next(
        (value for name, value in headers.items() if name.lower() == "content-type"),
        None,
    )
    if content_type not in {
        "application/json",
        "application/json; charset=utf-8",
    }:
        _fail(field, "must use the canonical JSON Content-Type")


class PromotedModelEngineWrapper:
    def __init__(
        self,
        config: EngineWrapperConfig,
        *,
        bearer_token: str,
        readiness_hmac_key: bytes,
        child_api_key: str | None = None,
        transport: Transport | None = None,
        process_factory: ProcessFactory | None = None,
        read_only_probe: ReadOnlyProbe | None = None,
        listener_ownership_probe: ListenerOwnershipProbe | None = None,
        privilege_isolation_probe: PrivilegeIsolationProbe | None = None,
        child_privilege_probe: ChildPrivilegeProbe | None = None,
        clock: Clock | None = None,
        monotonic: Monotonic | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        if not 32 <= len(bearer_token) <= 512:
            _fail("bearer token", "must contain 32 through 512 characters")
        if (
            not isinstance(readiness_hmac_key, bytes)
            or not 32 <= len(readiness_hmac_key) <= 512
        ):
            _fail("readiness HMAC key", "must contain 32 through 512 bytes")
        self.config = config
        self._bearer_token = bearer_token
        self._readiness_hmac_key = readiness_hmac_key
        self._child_api_key = child_api_key or secrets.token_urlsafe(32)
        if not 32 <= len(self._child_api_key) <= 512 or any(
            ord(character) <= 32 or ord(character) >= 127
            for character in self._child_api_key
        ):
            _fail(
                "child API key", "must contain 32 through 512 visible ASCII characters"
            )
        self._transport = transport or _default_transport
        if process_factory is None:
            child_user_id = config.engine.child_user_id
            child_group_id = config.engine.child_group_id
            if child_user_id is None or child_group_id is None:
                _fail(
                    "engine wrapper child identity",
                    "is absent from the production v3 configuration",
                )
            self._process_factory = (
                lambda descriptor, argv, environment, working_directory: (
                    _default_process_factory(
                        descriptor,
                        argv,
                        environment,
                        working_directory,
                        child_user_id=child_user_id,
                        child_group_id=child_group_id,
                    )
                )
            )
        else:
            self._process_factory = process_factory
        self._read_only_probe = read_only_probe or _default_read_only_probe
        self._listener_ownership_probe = (
            listener_ownership_probe or _default_listener_ownership_probe
        )
        self._privilege_isolation_probe = (
            privilege_isolation_probe or _default_privilege_isolation_probe
        )
        self._child_privilege_probe = (
            child_privilege_probe or _default_child_privilege_probe
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic or time.monotonic
        self._sleeper = sleeper or time.sleep
        self._state = WrapperState.CREATED
        self._state_lock = threading.RLock()
        self._integrity_lock = threading.Lock()
        self._last_full_validation_monotonic: float | None = None
        self._process: ChildProcess | None = None
        self._snapshot: ActivationSnapshot | None = None
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._server: ThreadingHTTPServer | None = None
        self._termination_error: ValidationError | None = None

    @classmethod
    def from_environment(
        cls, config: EngineWrapperConfig, **kwargs: Any
    ) -> PromotedModelEngineWrapper:
        return cls(
            config,
            bearer_token=_load_bearer_secret(config.service.bearer_token_environment),
            readiness_hmac_key=_load_hmac_secret(
                config.service.readiness_hmac_key_environment
            ),
            **kwargs,
        )

    @property
    def state(self) -> WrapperState:
        with self._state_lock:
            return self._state

    @property
    def snapshot(self) -> ActivationSnapshot | None:
        with self._state_lock:
            return self._snapshot

    def _validate_activation(self) -> ActivationSnapshot:
        promotion = self.config.promotion
        base_snapshot = self.config.base_snapshot
        if (
            self.config.schema_version != ENGINE_WRAPPER_V7_SCHEMA_VERSION
            or base_snapshot is None
            or promotion.evaluation_authoring_approval_trust is None
            or promotion.trainer_provenance_trust is None
        ):
            _fail(
                "engine wrapper config.schemaVersion",
                "production activation requires engine-wrapper/v7 with an exact base snapshot, evaluation-authoring approval trust, trainer-provenance trust, and an explicit nullable teacher-lineage admission trust",
            )
        if not self._privilege_isolation_probe(self.config.engine):
            _fail(
                "engine wrapper privilege isolation",
                "must launch the child under a distinct unprivileged UID and GID",
            )
        self._require_executable_custody()
        artifact_path = promotion.sources["artifact_path"]
        immutable_directories = {
            "base-model snapshot": base_snapshot.snapshot_path,
            "training artifact": artifact_path,
        }
        initial_identities: dict[str, tuple[int, int, int, int]] = {}
        for input_field, path in immutable_directories.items():
            if not self._read_only_probe(path):
                _fail(
                    input_field,
                    "must be held on a read-only mount for production activation",
                )
            initial_identities[input_field] = _directory_identity(path, input_field)
        current = _validation_time(self._clock(), "engine wrapper clock")
        verified = validate_model_promotion(
            promotion.path,
            public_key_path=promotion.public_key_path,
            expected_audience=promotion.expected_audience,
            expected_key_id=promotion.expected_key_id,
            expected_signer_role=promotion.expected_signer_role,
            expected_deployment_id=promotion.expected_deployment_id,
            expected_environment=promotion.expected_environment,
            review_receipt_trust=promotion.review_receipt_trust,
            evaluation_authoring_approval_trust=(
                promotion.evaluation_authoring_approval_trust
            ),
            trainer_provenance_trust=promotion.trainer_provenance_trust,
            base_selection_trust=base_snapshot.selection_trust,
            base_model_snapshot_path=base_snapshot.snapshot_path,
            review_receipt_now=current,
            trainer_provenance_now=current,
            now=current,
            **promotion.validation_arguments(),
        )
        if verified.envelope_sha256 != promotion.expected_envelope_sha256:
            _fail(
                "model promotion envelope",
                "does not match the trusted expected SHA-256",
            )
        payload = verified.payload
        model = payload["model"]
        activation_inputs = verified.activation_inputs
        if activation_inputs is None:
            _fail(
                "model promotion validation",
                "did not retain its exact activation inputs",
            )
        selected_base = activation_inputs.selected_base
        manifest_snapshot = activation_inputs.manifest_snapshot
        if model["trainingRunManifestSha256"] != manifest_snapshot.sha256:
            _fail(
                "model promotion payload.model.trainingRunManifestSha256",
                "does not match the retained validated manifest snapshot",
            )
        profile = activation_inputs.profile
        upstream_authority_expires = _canonical_utc(
            activation_inputs.authority_expires_at_utc,
            "model promotion upstream authority expiry",
        )
        if current >= upstream_authority_expires:
            _fail("model promotion upstream authority", "is no longer active")
        if profile.sha256 != promotion.expected_serving_profile_sha256:
            _fail(
                "serving profile",
                "does not match the trusted expected SHA-256",
            )
        runtime = profile.document["runtime"]
        if runtime["engine"] != "vllm":
            _fail("serving profile.runtime.engine", "must be 'vllm'")
        engine_version = runtime["engineVersion"]
        if engine_version not in _SUPPORTED_VLLM_ENGINE_VERSIONS:
            _fail(
                "serving profile.runtime.engineVersion",
                "has no reviewed exact argv adapter; supported versions are 0.10.0 and 0.26.0",
            )
        image_environment = self.config.engine.container_image_digest_environment
        current_image_digest = os.environ.get(image_environment)
        if current_image_digest is None:
            _fail(
                "container-image environment variable",
                f"{image_environment!r} is not set",
            )
        if not _OCI_DIGEST_RE.fullmatch(current_image_digest):
            _fail(
                "container-image environment variable",
                "must contain a lowercase sha256 OCI digest",
            )
        if runtime["containerImageDigest"] != current_image_digest:
            _fail(
                "engine wrapper container image",
                "does not match the signed serving profile",
            )
        final_identities: dict[str, tuple[int, int, int, int]] = {}
        for input_field, path in immutable_directories.items():
            if not self._read_only_probe(path):
                _fail(
                    input_field, "lost read-only custody during activation validation"
                )
            final_identities[input_field] = _directory_identity(path, input_field)
            if final_identities[input_field] != initial_identities[input_field]:
                _fail(
                    input_field,
                    "directory identity changed during activation validation",
                )
        manifest = manifest_snapshot.document
        max_lora_rank = manifest["hyperparameters"]["loraR"]
        if max_lora_rank not in _VLLM_LORA_RANKS:
            _fail(
                "training manifest.hyperparameters.loraR",
                "is not a supported vLLM maximum LoRA rank",
            )
        expected_model = {
            "servingProfileSha256": profile.sha256,
            "artifactSha256": profile.document["trainingArtifact"]["artifactSha256"],
            "artifactTreeSha256": profile.document["trainingArtifact"][
                "artifactTreeSha256"
            ],
            "executionModelId": profile.execution_model_id,
            "containerImageDigest": runtime["containerImageDigest"],
        }
        for name, expected in expected_model.items():
            if model[name] != expected:
                _fail(
                    f"model promotion payload.model.{name}",
                    "does not match the exact runtime candidate",
                )
        executable_hash = sha256_file(self.config.engine.executable_path)
        if executable_hash != self.config.engine.executable_sha256:
            _fail("engine executable", "does not match its configured SHA-256")
        return ActivationSnapshot(
            promotion_envelope_sha256=verified.envelope_sha256,
            promotion_payload_sha256=verified.payload_sha256,
            promotion_id=payload["promotionId"],
            serving_profile_sha256=profile.sha256,
            artifact_sha256=model["artifactSha256"],
            artifact_tree_sha256=model["artifactTreeSha256"],
            execution_model_id=model["executionModelId"],
            deployment_id=payload["deployment"]["deploymentId"],
            provider_id=payload["hostedDeploymentPolicy"]["providerId"],
            hosted_deployment_policy_sha256=payload["hostedDeploymentPolicy"][
                "policySha256"
            ],
            not_before_utc=payload["notBeforeUtc"],
            expires_at_utc=payload["expiresAtUtc"],
            upstream_authority_expires_at_utc=(
                activation_inputs.authority_expires_at_utc
            ),
            evaluation_authoring_approval_payload_sha256=(
                activation_inputs.evaluation_authoring_approval_payload_sha256
            ),
            evaluation_authoring_approval_envelope_sha256=(
                activation_inputs.evaluation_authoring_approval_envelope_sha256
            ),
            trainer_provenance_payload_sha256=(
                activation_inputs.trainer_provenance_payload_sha256
            ),
            trainer_provenance_envelope_sha256=(
                activation_inputs.trainer_provenance_envelope_sha256
            ),
            trainer_provenance_expires_at_utc=(
                activation_inputs.trainer_provenance_expires_at_utc
            ),
            csharp_verifier_replay_audit_payload_sha256=(
                activation_inputs.csharp_verifier_replay_audit_payload_sha256
            ),
            csharp_verifier_replay_audit_envelope_sha256=(
                activation_inputs.csharp_verifier_replay_audit_envelope_sha256
            ),
            max_lora_rank=max_lora_rank,
            max_output_tokens_per_request=payload["hostedDeploymentPolicy"][
                "execution"
            ]["maxOutputTokensPerRequest"],
            executable_sha256=executable_hash,
            engine_version=engine_version,
            training_manifest_sha256=model["trainingRunManifestSha256"],
            base_selection_id=selected_base.selection.payload["selectionId"],
            base_selection_payload_sha256=selected_base.selection.payload_sha256,
            base_profile_sha256=selected_base.profile.sha256,
            base_execution_model_id=selected_base.profile.execution_model_id,
            base_snapshot_sha256=selected_base.snapshot.document["snapshotSha256"],
            base_file_tree_sha256=selected_base.snapshot.document["fileTreeSha256"],
            base_snapshot_directory_identity=final_identities["base-model snapshot"],
            artifact_directory_identity=final_identities["training artifact"],
            serving_profile=profile,
        )

    def _revalidate_same_activation(self) -> ActivationSnapshot:
        current = self._validate_activation()
        expected = self.snapshot
        if expected is None or current != expected:
            _fail("engine activation", "changed after the child was launched")
        self._last_full_validation_monotonic = self._monotonic()
        return current

    def _require_executable_custody(self) -> None:
        if not self._read_only_probe(self.config.engine.executable_path):
            _fail(
                "engine executable",
                "must remain on a read-only mount under wrapper custody",
            )

    def _require_model_custody(self, snapshot: ActivationSnapshot) -> None:
        base_snapshot = self.config.base_snapshot
        if base_snapshot is None:
            _fail("base-model snapshot", "is absent from the production configuration")
        inputs = (
            (
                "base-model snapshot",
                base_snapshot.snapshot_path,
                snapshot.base_snapshot_directory_identity,
            ),
            (
                "training artifact",
                self.config.promotion.sources["artifact_path"],
                snapshot.artifact_directory_identity,
            ),
        )
        for input_field, path, expected_identity in inputs:
            if not self._read_only_probe(path):
                _fail(input_field, "lost read-only mount custody")
            if _directory_identity(path, input_field) != expected_identity:
                _fail(input_field, "directory identity changed after validation")

    def _child_environment(self) -> dict[str, str]:
        environment = {
            name: os.environ[name]
            for name in self.config.engine.environment_allowlist
            if name in os.environ
        }
        environment.update(
            {
                "HF_HUB_OFFLINE": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "VLLM_PLUGINS": "",
                "NO_PROXY": "127.0.0.1,localhost",
                "no_proxy": "127.0.0.1,localhost",
            }
        )
        for name in tuple(environment):
            if name in {
                self.config.service.bearer_token_environment,
                self.config.service.readiness_hmac_key_environment,
                self.config.engine.container_image_digest_environment,
            } or _SECRET_ENVIRONMENT_RE.search(name):
                environment.pop(name, None)
        environment["VLLM_API_KEY"] = self._child_api_key
        return environment

    def build_child_argv(self, snapshot: ActivationSnapshot) -> tuple[str, ...]:
        runtime = snapshot.serving_profile.document["runtime"]
        base_snapshot = self.config.base_snapshot
        if base_snapshot is None:
            _fail("base-model snapshot", "is absent from the production configuration")
        self._require_model_custody(snapshot)
        artifact_path = self.config.promotion.sources["artifact_path"]
        if "=" in os.fspath(artifact_path):
            _fail(
                "training artifact path", "must not contain '=' for vLLM LoRA binding"
            )
        if snapshot.engine_version not in _SUPPORTED_VLLM_ENGINE_VERSIONS:
            _fail(
                "engine version",
                "has no reviewed exact argv adapter; supported versions are 0.10.0 and 0.26.0",
            )
        quantization = runtime["quantization"]
        load_format = (
            "bitsandbytes" if quantization == "bitsandbytes-nf4" else "safetensors"
        )
        argv = [
            os.fspath(self.config.engine.executable_path),
            "serve",
            os.fspath(base_snapshot.snapshot_path),
            "--served-model-name",
            snapshot.base_execution_model_id,
            "--host",
            self.config.engine.child_host,
            "--port",
            str(self.config.engine.child_port),
            "--dtype",
            runtime["computeDtype"],
            "--max-model-len",
            str(runtime["maxModelLength"]),
            "--tensor-parallel-size",
            str(runtime["tensorParallelSize"]),
            "--enable-lora",
            "--lora-modules",
            f"{snapshot.execution_model_id}={artifact_path}",
            "--tokenizer",
            os.fspath(base_snapshot.snapshot_path),
            "--max-loras",
            "1",
            "--max-lora-rank",
            str(snapshot.max_lora_rank),
            "--load-format",
            load_format,
            "--generation-config",
            "vllm",
            "--disable-fastapi-docs",
            "--disable-uvicorn-access-log",
        ]
        if snapshot.engine_version == "0.10.0":
            argv.append("--disable-log-requests")
        else:
            argv.extend(
                [
                    "--api-server-count",
                    "1",
                    "--tokenizer-mode",
                    "hf",
                    "--config-format",
                    "hf",
                    "--model-impl",
                    "vllm",
                    "--seed",
                    "0",
                ]
            )
        if quantization == "bitsandbytes-nf4":
            argv.extend(["--quantization", "bitsandbytes"])
        elif quantization != "none":
            argv.extend(["--quantization", quantization])
        return tuple(argv)

    def _child_url(self, path: str) -> str:
        return f"http://{self.config.engine.child_host}:{self.config.engine.child_port}{path}"

    def _require_live_process(self) -> ChildProcess:
        with self._state_lock:
            process = self._process
        if process is None or process.poll() is not None:
            _fail("child engine", "is not running")
        return process

    def _probe_child(self, snapshot: ActivationSnapshot) -> None:
        process = self._require_live_process()
        if not self._child_privilege_probe(process.pid, self.config.engine):
            _fail(
                "child engine privilege isolation",
                "does not match the configured unprivileged UID/GID/capability boundary",
            )
        if not self._listener_ownership_probe(
            process.pid,
            self.config.engine.child_host,
            self.config.engine.child_port,
        ):
            _fail(
                "child engine listener",
                "is not owned by the launched vLLM process group",
            )
        limit = self.config.service.max_response_bytes
        timeout = self.config.engine.request_timeout_seconds
        health = self._transport(
            "GET",
            self._child_url("/health"),
            {"Authorization": f"Bearer {self._child_api_key}"},
            None,
            timeout,
            4_096,
        )
        if health.status != 200:
            _fail("child engine health", f"returned HTTP {health.status}")
        version = self._transport(
            "GET",
            self._child_url("/version"),
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._child_api_key}",
            },
            None,
            timeout,
            4_096,
        )
        if version.status != 200:
            _fail("child engine version", f"returned HTTP {version.status}")
        _require_json_content_type(version.headers, "child engine version response")
        version_value = _parse_json_bytes(version.body, "child engine version response")
        if version_value != {"version": snapshot.engine_version}:
            _fail(
                "child engine version response",
                "does not exactly match the signed vLLM version",
            )
        models = self._transport(
            "GET",
            self._child_url("/v1/models"),
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {self._child_api_key}",
            },
            None,
            timeout,
            limit,
        )
        if models.status != 200:
            _fail("child engine models", f"returned HTTP {models.status}")
        _require_json_content_type(models.headers, "child engine models response")
        value = _parse_json_bytes(models.body, "child engine models response")
        if not isinstance(value, dict) or not isinstance(value.get("data"), list):
            _fail("child engine models response", "must contain a data array")
        cards: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(value["data"]):
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                _fail(
                    f"child engine models response.data[{index}]",
                    "must contain a string id",
                )
            identifier = item["id"]
            if identifier in cards:
                _fail("child engine models response", "contains a duplicate model ID")
            cards[identifier] = item
        expected_identifiers = {
            snapshot.base_execution_model_id,
            snapshot.execution_model_id,
        }
        if (
            len(cards) != len(expected_identifiers)
            or set(cards) != expected_identifiers
        ):
            _fail(
                "child engine models response",
                "must expose exactly the selected raw base and promoted adapter IDs",
            )
        runtime = snapshot.serving_profile.document["runtime"]
        base_snapshot = self.config.base_snapshot
        if base_snapshot is None:  # pragma: no cover - guarded by activation
            _fail("base-model snapshot", "is absent")
        base_card = cards[snapshot.base_execution_model_id]
        if base_card.get("root") != os.fspath(base_snapshot.snapshot_path):
            _fail(
                "child engine base model card.root",
                "does not match the immutable local snapshot path",
            )
        if base_card.get("parent") is not None:
            _fail("child engine base model card.parent", "must be null")
        adapter_card = cards[snapshot.execution_model_id]
        if adapter_card.get("root") != os.fspath(
            self.config.promotion.sources["artifact_path"]
        ):
            _fail(
                "child engine adapter model card.root",
                "does not match the immutable promoted artifact path",
            )
        if adapter_card.get("parent") != snapshot.base_execution_model_id:
            _fail(
                "child engine adapter model card.parent",
                "does not match the selected raw base model ID",
            )
        if base_card.get("max_model_len") != runtime["maxModelLength"]:
            _fail(
                "child engine base model card.max_model_len",
                "does not match the signed serving profile",
            )
        adapter_maximum = adapter_card.get("max_model_len")
        if adapter_maximum is not None and adapter_maximum != runtime["maxModelLength"]:
            _fail(
                "child engine adapter model card.max_model_len",
                "conflicts with the signed serving profile",
            )

    def _wait_for_child(self, snapshot: ActivationSnapshot) -> None:
        deadline = self._monotonic() + self.config.engine.startup_timeout_seconds
        last_error: Exception | None = None
        while self._monotonic() < deadline:
            self._require_live_process()
            try:
                self._probe_child(snapshot)
                return
            except ValidationError as error:
                last_error = error
            self._sleeper(min(0.25, max(0.0, deadline - self._monotonic())))
        if last_error is None:
            _fail("child engine startup", "timed out")
        raise ValidationError(f"child engine startup: timed out: {last_error}")

    def _require_active_time(self, snapshot: ActivationSnapshot) -> None:
        current = _validation_time(self._clock(), "engine wrapper clock")
        not_before = _canonical_utc(
            snapshot.not_before_utc, "engine activation not-before time"
        )
        expires = _canonical_utc(snapshot.expires_at_utc, "engine activation expiry")
        authority_expires = _canonical_utc(
            snapshot.upstream_authority_expires_at_utc,
            "engine upstream authority expiry",
        )
        if current < not_before or current >= min(expires, authority_expires):
            _fail("engine activation", "is not currently valid")

    def _quick_same_active_snapshot(self) -> ActivationSnapshot:
        expected = self.snapshot
        if expected is None:
            _fail("engine activation", "is unavailable")
        self._require_model_custody(expected)
        process = self._require_live_process()
        if not self._child_privilege_probe(process.pid, self.config.engine):
            _fail(
                "child engine privilege isolation",
                "changed after activation",
            )
        if not self._listener_ownership_probe(
            process.pid,
            self.config.engine.child_host,
            self.config.engine.child_port,
        ):
            _fail(
                "child engine listener",
                "is no longer owned by the launched vLLM process group",
            )
        self._require_active_time(expected)
        return expected

    def _same_active_snapshot(self, *, full: bool) -> ActivationSnapshot:
        expected = self._quick_same_active_snapshot()
        if full:
            with self._integrity_lock:
                self._quick_same_active_snapshot()
                current = self._revalidate_same_activation()
                self._quick_same_active_snapshot()
                return current
        last_full = self._last_full_validation_monotonic
        if (
            last_full is None
            or self._monotonic() - last_full
            >= self.config.engine.integrity_interval_seconds
        ):
            with self._integrity_lock:
                expected = self._quick_same_active_snapshot()
                last_full = self._last_full_validation_monotonic
                if (
                    last_full is None
                    or self._monotonic() - last_full
                    >= self.config.engine.integrity_interval_seconds
                ):
                    expected = self._revalidate_same_activation()
                    self._quick_same_active_snapshot()
        return expected

    def start(self, *, start_monitor: bool = True) -> ActivationSnapshot:
        with self._state_lock:
            if self._state is not WrapperState.CREATED:
                _fail("engine wrapper", "can be started only once")
            self._state = WrapperState.PREVALIDATING
        descriptor: int | None = None
        try:
            snapshot = self._validate_activation()
            descriptor = _open_verified_executable(
                self.config.engine.executable_path, snapshot.executable_sha256
            )
            with self._state_lock:
                if (
                    self._stop_event.is_set()
                    or self._state is not WrapperState.PREVALIDATING
                ):
                    _fail("engine wrapper", "was stopped during prevalidation")
                self._state = WrapperState.STARTING
            argv = self.build_child_argv(snapshot)
            if _hash_opened_file(descriptor) != snapshot.executable_sha256:
                _fail("engine executable", "opened inode changed before launch")
            self._require_executable_custody()
            self._require_model_custody(snapshot)
            self._require_active_time(snapshot)
            process = self._process_factory(
                descriptor,
                argv,
                self._child_environment(),
                self.config.engine.executable_path.parent,
            )
            os.close(descriptor)
            descriptor = None
            with self._state_lock:
                self._process = process
                if (
                    self._stop_event.is_set()
                    or self._state is not WrapperState.STARTING
                ):
                    _fail("engine wrapper", "was stopped during launch")
                self._snapshot = snapshot
                self._state = WrapperState.LOADING
            self._wait_for_child(snapshot)
            with self._state_lock:
                if self._stop_event.is_set() or self._state is not WrapperState.LOADING:
                    _fail("engine wrapper", "was stopped while the child loaded")
                self._state = WrapperState.POST_LOAD_VALIDATING
            post_load = self._same_active_snapshot(full=True)
            self._probe_child(post_load)
            with self._state_lock:
                if (
                    self._stop_event.is_set()
                    or self._state is not WrapperState.POST_LOAD_VALIDATING
                ):
                    _fail("engine wrapper", "was stopped during post-load validation")
                self._state = WrapperState.READY
            if start_monitor:
                self._monitor_thread = threading.Thread(
                    target=self._monitor_loop,
                    name="hyperion-engine-monitor",
                    daemon=True,
                )
                self._monitor_thread.start()
            return post_load
        except Exception as error:
            self.fail_closed()
            if self._termination_error is not None:
                raise self._termination_error from error
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def monitor_once(self, *, validate_integrity: bool = True) -> None:
        snapshot = self.snapshot
        if self.state is not WrapperState.READY or snapshot is None:
            _fail("engine wrapper", "is not ready")
        self._probe_child(snapshot)
        if validate_integrity:
            self._same_active_snapshot(full=True)

    def _monitor_loop(self) -> None:
        last_integrity = self._monotonic()
        while not self._stop_event.wait(self.config.engine.health_interval_seconds):
            try:
                validate_integrity = (
                    self._monotonic() - last_integrity
                    >= self.config.engine.integrity_interval_seconds
                )
                self.monitor_once(validate_integrity=validate_integrity)
                if validate_integrity:
                    last_integrity = self._monotonic()
            except Exception:
                self.fail_closed()
                return

    def _authorize(self, headers: Mapping[str, str]) -> bool:
        authorization = next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "authorization"
            ),
            None,
        )
        if authorization is None or not authorization.startswith("Bearer "):
            return False
        supplied = authorization[7:]
        return hmac.compare_digest(supplied, self._bearer_token)

    def _strict_request_json(self, headers: Mapping[str, str], body: bytes) -> Any:
        content_type = next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "content-type"
            ),
            None,
        )
        if content_type not in {
            "application/json",
            "application/json; charset=utf-8",
        }:
            _fail(
                "request Content-Type",
                "must be 'application/json' with optional canonical UTF-8 charset",
            )
        if len(body) > self.config.service.max_request_bytes:
            _fail("request body", "exceeds the configured byte limit")
        return _parse_json_bytes(body, "request body")

    def _readiness_response(self, value: Any) -> ServiceResponse:
        if not isinstance(value, dict):
            _request_fail("readiness request", "must be an object")
        required = {"schemaVersion", "audience", "nonce"}
        if set(value) != required:
            _request_fail(
                "readiness request", "must contain exactly the required fields"
            )
        request = value
        if request["schemaVersion"] != MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION:
            _request_fail(
                "readiness request.schemaVersion",
                f"must be {MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION!r}",
            )
        if request["audience"] != self.config.promotion.expected_audience:
            _request_fail(
                "readiness request.audience", "does not match trusted configuration"
            )
        nonce = request["nonce"]
        if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce):
            _request_fail(
                "readiness request.nonce", "must be canonical unpadded base64url"
            )
        try:
            nonce_bytes = urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
        except ValueError as error:
            raise RequestValidationError(
                "readiness request.nonce: must be canonical unpadded base64url"
            ) from error
        if (
            len(nonce_bytes) != 32
            or urlsafe_b64encode(nonce_bytes).decode("ascii").rstrip("=") != nonce
        ):
            _request_fail(
                "readiness request.nonce", "must decode canonically to exactly 32 bytes"
            )
        current = self._same_active_snapshot(full=False)
        self._probe_child(current)
        proof = compute_model_readiness_v2_proof(
            key=self._readiness_hmac_key,
            audience=self.config.promotion.expected_audience,
            nonce=request["nonce"],
            key_id=self.config.service.readiness_key_id,
            serving_profile_sha256=current.serving_profile_sha256,
            artifact_sha256=current.artifact_sha256,
            artifact_tree_sha256=current.artifact_tree_sha256,
            execution_model_id=current.execution_model_id,
            promotion_envelope_sha256=current.promotion_envelope_sha256,
            promotion_payload_sha256=current.promotion_payload_sha256,
            deployment_id=current.deployment_id,
            provider_id=current.provider_id,
            hosted_deployment_policy_sha256=current.hosted_deployment_policy_sha256,
            expires_at_utc=current.expires_at_utc,
        )
        response = {
            "schemaVersion": MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
            "nonce": request["nonce"],
            "keyId": self.config.service.readiness_key_id,
            "proof": proof,
        }
        validate_model_readiness_v2_attestation(
            response,
            key=self._readiness_hmac_key,
            audience=self.config.promotion.expected_audience,
            expected_nonce=request["nonce"],
            expected_key_id=self.config.service.readiness_key_id,
            serving_profile_sha256=current.serving_profile_sha256,
            artifact_sha256=current.artifact_sha256,
            artifact_tree_sha256=current.artifact_tree_sha256,
            execution_model_id=current.execution_model_id,
            promotion_envelope_sha256=current.promotion_envelope_sha256,
            promotion_payload_sha256=current.promotion_payload_sha256,
            deployment_id=current.deployment_id,
            provider_id=current.provider_id,
            hosted_deployment_policy_sha256=current.hosted_deployment_policy_sha256,
            expires_at_utc=current.expires_at_utc,
        )
        self._quick_same_active_snapshot()
        if self.state is not WrapperState.READY:
            _fail("engine wrapper", "left READY while the proof was created")
        return ServiceResponse(200, canonical_json_bytes(response))

    def _chat_response(self, value: Any) -> ServiceResponse:
        if not isinstance(value, dict):
            _request_fail("chat completion request", "must be an object")
        required = {"model", "messages", "max_tokens", "temperature"}
        allowed = required | {"stream"}
        if not required <= set(value) or not set(value) <= allowed:
            _request_fail(
                "chat completion request",
                "must contain exactly model, messages, max_tokens, temperature, and optional stream",
            )
        snapshot = self.snapshot
        if snapshot is None:
            _fail("engine wrapper", "has no active model")
        if value.get("model") != snapshot.execution_model_id:
            _request_fail(
                "chat completion request.model",
                "must exactly match the promoted execution model ID",
            )
        if value.get("stream", False) is not False:
            _request_fail("chat completion request.stream", "streaming is not accepted")
        max_tokens = value["max_tokens"]
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or not 1 <= max_tokens <= snapshot.max_output_tokens_per_request
        ):
            _request_fail(
                "chat completion request.max_tokens",
                "is outside the signed per-request output limit",
            )
        temperature = value["temperature"]
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not 0 <= float(temperature) <= 2
        ):
            _request_fail(
                "chat completion request.temperature",
                "must be a number from 0 through 2",
            )
        messages = value["messages"]
        if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
            _request_fail(
                "chat completion request.messages",
                "must contain 1 through 128 messages",
            )
        for index, message in enumerate(messages):
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                _request_fail(
                    f"chat completion request.messages[{index}]",
                    "must contain exactly role and content",
                )
            if message["role"] not in {"system", "user", "assistant"}:
                _request_fail(
                    f"chat completion request.messages[{index}].role",
                    "is not an accepted chat role",
                )
            content = message["content"]
            if not isinstance(content, str) or not content or len(content) > 1_000_000:
                _request_fail(
                    f"chat completion request.messages[{index}].content",
                    "must be a non-empty bounded string",
                )
            if any(
                ord(character) < 32 and character not in {"\t", "\n", "\r"}
                for character in content
            ):
                _request_fail(
                    f"chat completion request.messages[{index}].content",
                    "must not contain disallowed control characters",
                )
        request = dict(value)
        request["stream"] = False
        current = self._same_active_snapshot(full=False)
        child_response = self._transport(
            "POST",
            self._child_url(CHAT_COMPLETIONS_PATH),
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self._child_api_key}",
            },
            canonical_json_bytes(request),
            self.config.engine.request_timeout_seconds,
            self.config.service.max_response_bytes,
        )
        _require_json_content_type(
            child_response.headers, "child chat completion response"
        )
        response_value = _parse_json_bytes(
            child_response.body, "child chat completion response"
        )
        if not isinstance(response_value, dict):
            _fail("child chat completion response", "must be an object")
        if child_response.status == 200:
            if response_value.get("model") != current.execution_model_id:
                _fail(
                    "child chat completion response.model",
                    "does not match the promoted execution model ID",
                )
        elif child_response.status not in {400, 409, 413, 422, 429}:
            _fail(
                "child chat completion response",
                f"returned unsafe HTTP status {child_response.status}",
            )
        self._same_active_snapshot(full=False)
        if self.state is not WrapperState.READY:
            _fail("engine wrapper", "left READY while the response was buffered")
        body = canonical_json_bytes(response_value)
        if len(body) > self.config.service.max_response_bytes:
            _fail("child chat completion response", "exceeds the configured byte limit")
        return ServiceResponse(child_response.status, body)

    def handle_http_request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> ServiceResponse:
        if not self._authorize(headers):
            return _error_response(401, "unauthorized")
        if method != "POST":
            return _error_response(405, "method_not_allowed")
        if path not in {READINESS_PATH, CHAT_COMPLETIONS_PATH}:
            return _error_response(404, "not_found")
        if self.state is not WrapperState.READY:
            return _error_response(503, "not_ready")
        try:
            value = self._strict_request_json(headers, body)
        except ValidationError:
            return _error_response(400, "invalid_request")
        try:
            if path == READINESS_PATH:
                return self._readiness_response(value)
            return self._chat_response(value)
        except RequestValidationError:
            return _error_response(400, "invalid_request")
        except ValidationError:
            self.fail_closed()
            return _error_response(503, "not_ready")
        except Exception:
            self.fail_closed()
            return _error_response(503, "not_ready")

    def _terminate_child(self) -> None:
        with self._state_lock:
            process = self._process
        if process is None:
            self._termination_error = None
            return
        ensure_group_stopped = getattr(process, "ensure_process_group_stopped", None)
        if process.poll() is not None:
            if callable(ensure_group_stopped):
                ensure_group_stopped(5)
            self._termination_error = None
            return
        try:
            process.terminate()
            process.wait(timeout=self.config.engine.shutdown_grace_seconds)
            if callable(ensure_group_stopped):
                ensure_group_stopped(5)
            self._termination_error = None
            return
        except (OSError, subprocess.TimeoutExpired, TimeoutError):
            pass
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired, TimeoutError) as error:
            if process.poll() is None:
                raise ValidationError(
                    "child engine could not be terminated and remains alive"
                ) from error
        if process.poll() is None:
            _fail("child engine", "could not be terminated and remains alive")
        if callable(ensure_group_stopped):
            ensure_group_stopped(5)
        self._termination_error = None

    def fail_closed(self) -> None:
        with self._state_lock:
            if self._state is not WrapperState.STOPPED:
                self._state = WrapperState.FAILED
        self._stop_event.set()
        server = self._server
        if server is not None:
            threading.Thread(target=server.shutdown, daemon=True).start()
        try:
            self._terminate_child()
        except ValidationError as error:
            with self._state_lock:
                self._state = WrapperState.FAILED
            self._termination_error = error

    def stop(self) -> None:
        with self._state_lock:
            if self._state is WrapperState.STOPPED:
                return
            if self._state is not WrapperState.FAILED:
                self._state = WrapperState.STOPPING
        self._stop_event.set()
        server = self._server
        if server is not None:
            if threading.current_thread() is threading.main_thread():
                threading.Thread(target=server.shutdown, daemon=True).start()
            else:
                server.shutdown()
        termination_error: ValidationError | None = None
        try:
            self._terminate_child()
        except ValidationError as error:
            termination_error = error
            self._termination_error = error
        monitor = self._monitor_thread
        if monitor is not None and monitor is not threading.current_thread():
            monitor.join(timeout=5)
        with self._state_lock:
            if termination_error is not None:
                self._state = WrapperState.FAILED
            elif self._state is not WrapperState.FAILED:
                self._state = WrapperState.STOPPED
        if termination_error is not None:
            raise termination_error

    def serve_forever(self) -> None:
        if self.state is not WrapperState.READY:
            _fail("engine wrapper", "must be READY before serving HTTP")
        wrapper = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = ""
            sys_version = ""

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(
                    wrapper.config.engine.request_timeout_seconds
                )

            def send_response(self, code: int, message: str | None = None) -> None:
                self.log_request(code)
                self.send_response_only(code, message)

            def send_error(
                self,
                code: int,
                message: str | None = None,
                explain: str | None = None,
            ) -> None:
                self._send(_error_response(code, "invalid_request"))

            def handle_expect_100(self) -> bool:
                self._send(_error_response(417, "expectation_failed"))
                return False

            def do_POST(self) -> None:  # noqa: N802
                if (
                    self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Encoding") is not None
                    or self.headers.get("Expect") is not None
                ):
                    self._send(_error_response(400, "invalid_request"))
                    return
                lengths = self.headers.get_all("Content-Length", failobj=[])
                if len(lengths) != 1:
                    self._send(_error_response(411, "length_required"))
                    return
                try:
                    length = int(lengths[0])
                except ValueError:
                    self._send(_error_response(400, "invalid_request"))
                    return
                if length < 0 or length > wrapper.config.service.max_request_bytes:
                    self._send(_error_response(413, "request_too_large"))
                    return
                if len(self.headers.get_all("Authorization", failobj=[])) != 1:
                    self._send(_error_response(401, "unauthorized"))
                    return
                if not wrapper._authorize(
                    {"Authorization": self.headers.get("Authorization", "")}
                ):
                    self._send(_error_response(401, "unauthorized"))
                    return
                if len(self.headers.get_all("Content-Type", failobj=[])) != 1:
                    self._send(_error_response(400, "invalid_request"))
                    return
                try:
                    body = self.rfile.read(length)
                except OSError:
                    self._send(_error_response(408, "request_timeout"))
                    return
                if len(body) != length:
                    self._send(_error_response(400, "invalid_request"))
                    return
                response = wrapper.handle_http_request(
                    "POST", self.path, dict(self.headers.items()), body
                )
                self._send(response)

            def do_GET(self) -> None:  # noqa: N802
                self._send(_error_response(405, "method_not_allowed"))

            do_HEAD = do_GET
            do_PUT = do_GET
            do_PATCH = do_GET
            do_DELETE = do_GET
            do_OPTIONS = do_GET
            do_TRACE = do_GET
            do_CONNECT = do_GET

            def _send(self, response: ServiceResponse) -> None:
                self.send_response(response.status)
                for name, value in response.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(response.body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(response.body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        server = ThreadingHTTPServer(
            (self.config.service.listen_host, self.config.service.listen_port), Handler
        )
        server.daemon_threads = True
        server.allow_reuse_address = False
        self._server = server
        if self.state is not WrapperState.READY:
            server.server_close()
            self._server = None
            _fail("engine wrapper", "left READY before the HTTP listener started")
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            server.server_close()
            self._server = None


def serve_promoted_model(config_path: str | os.PathLike[str]) -> None:
    config = load_engine_wrapper_config(config_path)
    wrapper = PromotedModelEngineWrapper.from_environment(config)
    previous_handlers: dict[int, Any] = {}
    signal_once = threading.Event()

    def request_stop(signum: int, frame: Any) -> None:
        if signal_once.is_set():
            return
        signal_once.set()
        threading.Thread(target=wrapper.stop, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        for candidate in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[candidate] = signal.getsignal(candidate)
            signal.signal(candidate, request_stop)
    try:
        wrapper.start()
        wrapper.serve_forever()
    finally:
        wrapper.stop()
        for candidate, previous in previous_handlers.items():
            signal.signal(candidate, previous)
