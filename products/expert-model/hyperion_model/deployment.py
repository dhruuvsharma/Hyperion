from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import struct
import unicodedata
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust
    from .trainer_provenance import TrainerProvenanceTrust

from .artifacts import validate_training_artifact
from .core import (
    MAX_JSON_BYTES,
    ValidatedManifestSnapshot,
    _exact_keys,
    _existing_directory,
    _fail,
    _integer,
    _read_file_bounded,
    _reject_constant,
    _reject_reparse_components,
    _revision,
    _sha256,
    _string,
    _unique_pairs,
    _write_json_exclusive,
    load_json_document,
    sha256_file,
    validate_manifest_path,
)
from .review_receipts import ExpertModelReviewReceiptTrust


SERVING_PROFILE_SCHEMA_VERSION = "daxalgo.hyperion.serving-profile/v1"
MODEL_READINESS_ATTESTATION_SCHEMA_VERSION = "daxalgo.hyperion.model-readiness/v1"
MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION = "daxalgo.hyperion.model-readiness/v2"
EXECUTION_MODEL_PREFIX = "daxalgo-expert-sha256-"
MAX_SERVING_PROFILE_BYTES = 1_000_000

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_READINESS_V2_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_QUANTIZATIONS = frozenset({"none", "bitsandbytes-nf4", "awq", "gptq", "mxfp4"})
_COMPUTE_DTYPES = frozenset({"float16", "bfloat16", "float32"})
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,99}$")
_RUNTIME_CAPABILITIES = {
    "qwen2.5-coder-7b-instruct": (32_768, frozenset({"none", "bitsandbytes-nf4"})),
    "qwen2.5-coder-14b-instruct": (32_768, frozenset({"none", "bitsandbytes-nf4"})),
    "gpt-oss-20b": (131_072, frozenset({"mxfp4"})),
    "qwen3-coder-30b-a3b-instruct": (262_144, frozenset({"none", "bitsandbytes-nf4"})),
}


@dataclass(frozen=True)
class ServingProfile:
    path: Path
    sha256: str
    execution_model_id: str
    document: dict[str, Any]


def _base64url_decode(
    value: Any, field: str, *, exact_bytes: int | None = None
) -> bytes:
    text = _string(value, field, max_length=512)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        _fail(field, "must be unpadded base64url")
    try:
        decoded = urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        _fail(field, "must be unpadded base64url")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        _fail(field, f"must decode to exactly {exact_bytes} bytes")
    if _base64url_encode(decoded) != text:
        _fail(field, "must use the canonical unpadded base64url spelling")
    return decoded


def _base64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _attestation_payload(fields: tuple[str, ...]) -> bytes:
    payload = bytearray()
    for field in fields:
        encoded = field.encode("utf-8")
        payload.extend(struct.pack(">I", len(encoded)))
        payload.extend(encoded)
    return bytes(payload)


def compute_model_readiness_proof(
    *,
    key: bytes,
    audience: str,
    nonce: str,
    key_id: str,
    serving_profile_sha256: str,
    artifact_sha256: str,
    artifact_tree_sha256: str,
    execution_model_id: str,
) -> str:
    """Compute the legacy v1 evaluation-only proof; production uses v2."""
    if not isinstance(key, bytes) or len(key) < 32:
        _fail("model readiness key", "must contain at least 32 bytes")
    audience_value = _safe_id(audience, "model readiness audience")
    key_id_value = _safe_id(key_id, "model readiness key ID")
    _base64url_decode(nonce, "model readiness nonce", exact_bytes=32)
    profile_hash = _sha256(serving_profile_sha256, "serving-profile SHA-256")
    artifact_hash = _sha256(artifact_sha256, "training-artifact SHA-256")
    tree_hash = _sha256(artifact_tree_sha256, "artifact-tree SHA-256")
    if execution_model_id != EXECUTION_MODEL_PREFIX + profile_hash:
        _fail("execution model ID", "must be derived from the serving-profile SHA-256")
    payload = _attestation_payload(
        (
            MODEL_READINESS_ATTESTATION_SCHEMA_VERSION,
            audience_value,
            nonce,
            key_id_value,
            profile_hash,
            artifact_hash,
            tree_hash,
            execution_model_id,
        )
    )
    return _base64url_encode(hmac.digest(key, payload, "sha256"))


def compute_model_readiness_v2_proof(
    *,
    key: bytes,
    audience: str,
    nonce: str,
    key_id: str,
    serving_profile_sha256: str,
    artifact_sha256: str,
    artifact_tree_sha256: str,
    execution_model_id: str,
    promotion_envelope_sha256: str,
    promotion_payload_sha256: str,
    deployment_id: str,
    provider_id: str,
    hosted_deployment_policy_sha256: str,
    expires_at_utc: str,
) -> str:
    """Compute the production proof bound to one authenticated promotion."""
    if not isinstance(key, bytes) or len(key) < 32:
        _fail("model readiness key", "must contain at least 32 bytes")
    audience_value = _readiness_v2_id(audience, "model readiness audience")
    key_id_value = _readiness_v2_id(key_id, "model readiness key ID")
    deployment_value = _readiness_v2_id(deployment_id, "model readiness deployment ID")
    provider_value = _readiness_v2_id(provider_id, "model readiness provider ID")
    _base64url_decode(nonce, "model readiness nonce", exact_bytes=32)
    profile_hash = _sha256(serving_profile_sha256, "serving-profile SHA-256")
    artifact_hash = _sha256(artifact_sha256, "training-artifact SHA-256")
    tree_hash = _sha256(artifact_tree_sha256, "artifact-tree SHA-256")
    envelope_hash = _sha256(promotion_envelope_sha256, "promotion-envelope SHA-256")
    payload_hash = _sha256(promotion_payload_sha256, "promotion-payload SHA-256")
    policy_hash = _sha256(
        hosted_deployment_policy_sha256, "hosted-deployment-policy SHA-256"
    )
    if execution_model_id != EXECUTION_MODEL_PREFIX + profile_hash:
        _fail("execution model ID", "must be derived from the serving-profile SHA-256")
    if not isinstance(expires_at_utc, str) or len(expires_at_utc) != 20:
        _fail(
            "model readiness promotion expiry",
            "must use exact UTC second form YYYY-MM-DDTHH:MM:SSZ",
        )
    try:
        datetime.strptime(expires_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(
            "model readiness promotion expiry",
            "must be a real UTC second in form YYYY-MM-DDTHH:MM:SSZ",
        )
    payload = _attestation_payload(
        (
            MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION,
            audience_value,
            nonce,
            key_id_value,
            profile_hash,
            artifact_hash,
            tree_hash,
            execution_model_id,
            envelope_hash,
            payload_hash,
            deployment_value,
            provider_value,
            policy_hash,
            expires_at_utc,
        )
    )
    return _base64url_encode(hmac.digest(key, payload, "sha256"))


def validate_model_readiness_v2_attestation(
    value: Any,
    *,
    key: bytes,
    audience: str,
    expected_nonce: str,
    expected_key_id: str,
    serving_profile_sha256: str,
    artifact_sha256: str,
    artifact_tree_sha256: str,
    execution_model_id: str,
    promotion_envelope_sha256: str,
    promotion_payload_sha256: str,
    deployment_id: str,
    provider_id: str,
    hosted_deployment_policy_sha256: str,
    expires_at_utc: str,
) -> dict[str, str]:
    """Validate a strict v2 response against one trusted promotion challenge."""
    attestation = _exact_keys(
        value,
        {"schemaVersion", "nonce", "keyId", "proof"},
        "model readiness v2 attestation",
    )
    if attestation["schemaVersion"] != MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION:
        _fail(
            "model readiness v2 attestation.schemaVersion",
            f"must be {MODEL_READINESS_ATTESTATION_V2_SCHEMA_VERSION!r}",
        )
    _base64url_decode(expected_nonce, "expected model readiness nonce", exact_bytes=32)
    if attestation["nonce"] != expected_nonce:
        _fail("model readiness v2 attestation.nonce", "does not match the challenge")
    key_id = _readiness_v2_id(
        attestation["keyId"], "model readiness v2 attestation.keyId"
    )
    if key_id != _readiness_v2_id(expected_key_id, "expected model readiness key ID"):
        _fail(
            "model readiness v2 attestation.keyId",
            "does not match trusted configuration",
        )
    proof_bytes = _base64url_decode(
        attestation["proof"], "model readiness v2 attestation.proof", exact_bytes=32
    )
    expected_proof = compute_model_readiness_v2_proof(
        key=key,
        audience=audience,
        nonce=expected_nonce,
        key_id=expected_key_id,
        serving_profile_sha256=serving_profile_sha256,
        artifact_sha256=artifact_sha256,
        artifact_tree_sha256=artifact_tree_sha256,
        execution_model_id=execution_model_id,
        promotion_envelope_sha256=promotion_envelope_sha256,
        promotion_payload_sha256=promotion_payload_sha256,
        deployment_id=deployment_id,
        provider_id=provider_id,
        hosted_deployment_policy_sha256=hosted_deployment_policy_sha256,
        expires_at_utc=expires_at_utc,
    )
    if not hmac.compare_digest(
        proof_bytes, _base64url_decode(expected_proof, "expected readiness proof")
    ):
        _fail("model readiness v2 attestation.proof", "does not verify")
    return attestation


def create_model_readiness_attestation(
    *,
    profile_path: str | os.PathLike[str],
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    audience: str,
    nonce: str,
    key_id: str,
    key: bytes,
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_provenance_now: datetime | None = None,
) -> dict[str, str]:
    """Build a legacy v1 local-evaluation proof after revalidating local bytes."""
    profile = validate_serving_profile(
        profile_path,
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    artifact = profile.document["trainingArtifact"]
    release_values = (
        data_release_path,
        review_receipt_trust,
        evaluation_authoring_approval_trust,
    )
    if any(value is not None for value in release_values) and not all(
        value is not None for value in release_values
    ):
        _fail(
            "model readiness release authority",
            "the release path, review-receipt trust, and evaluation-authoring approval trust are required together",
        )
    if review_receipt_now is not None and data_release_path is None:
        _fail(
            "model readiness release validation time",
            "cannot be supplied without the complete release authority",
        )
    if artifact["mode"] != "unpromoted-candidate":
        _fail(
            "serving profile.trainingArtifact.mode",
            "research-only artifacts cannot produce readiness attestations",
        )
    if data_release_path is None:
        _fail(
            "model readiness release",
            "a fully validated release path is required",
        )
    if review_receipt_trust is None:
        _fail(
            "model readiness review-receipt trust",
            "is required with data_release_path",
        )
    if evaluation_authoring_approval_trust is None:
        _fail(
            "model readiness evaluation-authoring approval trust",
            "is required with data_release_path",
        )
    manifest = validate_manifest_path(manifest_path)
    from .release import validate_training_release_binding

    release, release_identity = validate_training_release_binding(
        data_release_path,
        dataset_sha256=manifest["dataset"]["sha256"],
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        now=review_receipt_now,
    )
    if release["purpose"] != "local-training-evaluation":
        _fail(
            "model readiness release",
            "legacy v1 is limited to local evaluation; production requires promotion-bound v2",
        )
    if manifest.get("dataRelease") != release_identity:
        _fail(
            "training manifest.dataRelease",
            "does not match the fully validated readiness release",
        )
    proof = compute_model_readiness_proof(
        key=key,
        audience=audience,
        nonce=nonce,
        key_id=key_id,
        serving_profile_sha256=profile.sha256,
        artifact_sha256=artifact["artifactSha256"],
        artifact_tree_sha256=artifact["artifactTreeSha256"],
        execution_model_id=profile.execution_model_id,
    )
    return {
        "schemaVersion": MODEL_READINESS_ATTESTATION_SCHEMA_VERSION,
        "nonce": nonce,
        "keyId": key_id,
        "proof": proof,
    }


def _safe_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not _SAFE_ID_RE.fullmatch(text):
        _fail(
            field,
            "must start with an ASCII letter or digit and contain only letters, digits, '.', '_', or '-'",
        )
    return text


def _readiness_v2_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _READINESS_V2_ID_RE.fullmatch(text):
        _fail(field, "must be a safe ASCII identifier")
    return text


def _text(value: Any, field: str, *, max_length: int) -> str:
    text = _string(value, field, max_length=max_length)
    if any(unicodedata.category(character) == "Cc" for character in text):
        _fail(field, "must not contain control characters")
    return text


def _model_id(value: Any, field: str) -> str:
    text = _string(value, field, max_length=200)
    if not _MODEL_ID_RE.fullmatch(text):
        _fail(field, "must be an ASCII model identifier")
    return text


def _version(value: Any, field: str) -> str:
    text = _string(value, field, max_length=100)
    if not _VERSION_RE.fullmatch(text):
        _fail(field, "must be an ASCII version identifier")
    return text


def _reject_excessive_json_depth(value: Any, depth: int = 1) -> None:
    if depth > 32:
        _fail("serving profile", "must not exceed 32 JSON nesting levels")
    if isinstance(value, dict):
        for child in value.values():
            _reject_excessive_json_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _reject_excessive_json_depth(child, depth + 1)


def _validate_serving_profile_document(value: Any) -> dict[str, Any]:
    profile = _exact_keys(
        value,
        {
            "schemaVersion",
            "profileId",
            "candidateCatalogSha256",
            "candidateId",
            "baseModel",
            "trainingArtifact",
            "chatTemplateSha256",
            "runtime",
            "protocol",
        },
        "serving profile",
    )
    if profile["schemaVersion"] != SERVING_PROFILE_SCHEMA_VERSION:
        _fail(
            "serving profile.schemaVersion",
            f"must be {SERVING_PROFILE_SCHEMA_VERSION!r}",
        )
    _safe_id(profile["profileId"], "serving profile.profileId")
    _sha256(profile["candidateCatalogSha256"], "serving profile.candidateCatalogSha256")
    _safe_id(profile["candidateId"], "serving profile.candidateId")

    base_model = _exact_keys(
        profile["baseModel"], {"modelId", "revision"}, "serving profile.baseModel"
    )
    _model_id(base_model["modelId"], "serving profile.baseModel.modelId")
    _revision(base_model["revision"], "serving profile.baseModel.revision")

    artifact = _exact_keys(
        profile["trainingArtifact"],
        {"mode", "trainingRunManifestSha256", "artifactSha256", "artifactTreeSha256"},
        "serving profile.trainingArtifact",
    )
    if artifact["mode"] not in {"unpromoted-candidate", "unpromoted-research"}:
        _fail(
            "serving profile.trainingArtifact.mode",
            "must be 'unpromoted-candidate' or 'unpromoted-research'",
        )
    _sha256(
        artifact["trainingRunManifestSha256"],
        "serving profile.trainingArtifact.trainingRunManifestSha256",
    )
    _sha256(
        artifact["artifactSha256"], "serving profile.trainingArtifact.artifactSha256"
    )
    _sha256(
        artifact["artifactTreeSha256"],
        "serving profile.trainingArtifact.artifactTreeSha256",
    )
    _sha256(profile["chatTemplateSha256"], "serving profile.chatTemplateSha256")

    runtime = _exact_keys(
        profile["runtime"],
        {
            "engine",
            "engineVersion",
            "containerImageDigest",
            "quantization",
            "computeDtype",
            "maxModelLength",
            "tensorParallelSize",
            "gpuProfile",
        },
        "serving profile.runtime",
    )
    _safe_id(runtime["engine"], "serving profile.runtime.engine")
    _version(runtime["engineVersion"], "serving profile.runtime.engineVersion")
    if not isinstance(
        runtime["containerImageDigest"], str
    ) or not _OCI_DIGEST_RE.fullmatch(runtime["containerImageDigest"]):
        _fail(
            "serving profile.runtime.containerImageDigest",
            "must be a lowercase sha256 OCI digest",
        )
    if runtime["quantization"] not in _QUANTIZATIONS:
        _fail("serving profile.runtime.quantization", "is unsupported")
    if runtime["computeDtype"] not in _COMPUTE_DTYPES:
        _fail("serving profile.runtime.computeDtype", "is unsupported")
    _integer(
        runtime["maxModelLength"],
        "serving profile.runtime.maxModelLength",
        128,
        262_144,
    )
    _integer(
        runtime["tensorParallelSize"],
        "serving profile.runtime.tensorParallelSize",
        1,
        64,
    )
    _safe_id(runtime["gpuProfile"], "serving profile.runtime.gpuProfile")
    if profile["protocol"] != "openai-compatible":
        _fail("serving profile.protocol", "must be 'openai-compatible'")
    return profile


def load_serving_profile(path: str | os.PathLike[str]) -> ServingProfile:
    profile_path = Path(path)
    raw = _read_file_bounded(profile_path, "serving profile", MAX_SERVING_PROFILE_BYTES)
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("serving profile", "UTF-8 byte-order marks are not accepted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        _fail("serving profile", f"invalid UTF-8 at byte {error.start}")
    try:
        value = json.loads(
            text, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
        )
    except RecursionError:
        _fail("serving profile", "must not exceed 32 JSON nesting levels")
    except json.JSONDecodeError as error:
        _fail(
            "serving profile",
            f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}",
        )
    _reject_excessive_json_depth(value)
    document = _validate_serving_profile_document(value)
    profile_sha256 = hashlib.sha256(raw).hexdigest()
    return ServingProfile(
        path=Path(os.path.abspath(os.fspath(profile_path))),
        sha256=profile_sha256,
        execution_model_id=EXECUTION_MODEL_PREFIX + profile_sha256,
        document=document,
    )


def _load_training_inputs(
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    *,
    manifest_snapshot: ValidatedManifestSnapshot | None = None,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_provenance_now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    artifact_root = _existing_directory(Path(artifact_path), "training artifact")
    if manifest_snapshot is None:
        manifest_sha256_before = sha256_file(manifest_path, max_bytes=MAX_JSON_BYTES)
        manifest = validate_manifest_path(manifest_path)
        manifest_file = Path(os.path.abspath(os.fspath(manifest_path)))
        manifest_sha256 = sha256_file(manifest_file, max_bytes=MAX_JSON_BYTES)
        if manifest_sha256_before != manifest_sha256:
            _fail(
                "training manifest",
                "changed while its serving-profile bindings were validated",
            )
    else:
        supplied_manifest = Path(os.path.abspath(os.fspath(manifest_path)))
        if supplied_manifest != manifest_snapshot.path:
            _fail(
                "training manifest snapshot",
                "does not belong to the supplied manifest path",
            )
        manifest = manifest_snapshot.document
        manifest_sha256 = manifest_snapshot.sha256
    artifact = validate_training_artifact(
        artifact_root,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    manifest_base_model = {
        "candidateId": manifest["baseModel"]["candidateId"],
        "modelId": manifest["baseModel"]["modelId"],
        "revision": manifest["baseModel"]["revision"],
    }
    if artifact["baseModel"] != manifest_base_model:
        _fail(
            "training artifact.baseModel",
            "does not match the supplied training manifest",
        )
    if artifact["manifestSha256"] != manifest_sha256:
        _fail(
            "training artifact.manifestSha256",
            "does not match the supplied training manifest",
        )
    if artifact["runId"] != manifest["runId"]:
        _fail(
            "training artifact.runId", "does not match the supplied training manifest"
        )
    if artifact["dataRelease"] != manifest.get("dataRelease"):
        _fail(
            "training artifact.dataRelease",
            "does not match the supplied training manifest",
        )
    if artifact["datasetSnapshot"] != {
        "path": manifest["dataset"]["path"],
        "sha256": manifest["dataset"]["sha256"],
        "recordCount": manifest["dataset"]["recordCount"],
    }:
        _fail(
            "training artifact.datasetSnapshot",
            "does not match the supplied training manifest",
        )
    if artifact["mode"] == "smoke":
        _fail("training artifact.mode", "smoke artifacts cannot be used for evaluation")
    if artifact["mode"] == "unpromoted-candidate" and trainer_provenance_trust is None:
        _fail(
            "trainer provenance trust",
            "externally pinned trust is required for a candidate artifact",
        )
    _validate_inference_configuration(artifact_root, manifest)
    return artifact, manifest, manifest_sha256


def _validate_inference_configuration(root: Path, manifest: Mapping[str, Any]) -> None:
    adapter = load_json_document(root / "adapter_config.json", max_bytes=MAX_JSON_BYTES)
    expected_adapter = {
        "base_model_name_or_path": manifest["baseModel"]["modelId"],
        "peft_type": "LORA",
        "task_type": "CAUSAL_LM",
        "bias": "none",
        "r": manifest["hyperparameters"]["loraR"],
        "lora_alpha": manifest["hyperparameters"]["loraAlpha"],
        "lora_dropout": manifest["hyperparameters"]["loraDropout"],
    }
    for name, expected in expected_adapter.items():
        if adapter.get(name) != expected:
            _fail(
                f"training artifact.adapter_config.json.{name}",
                "does not match the training manifest",
            )
    target_modules = adapter.get("target_modules")
    if not isinstance(target_modules, list) or sorted(target_modules) != sorted(
        manifest["hyperparameters"]["loraTargetModules"]
    ):
        _fail(
            "training artifact.adapter_config.json.target_modules",
            "does not match the training manifest",
        )
    if adapter.get("auto_mapping") not in (None, {}):
        _fail(
            "training artifact.adapter_config.json.auto_mapping",
            "custom code mappings are not accepted",
        )

    tokenizer = load_json_document(
        root / "tokenizer_config.json", max_bytes=MAX_JSON_BYTES
    )
    if tokenizer.get("auto_map") not in (None, {}):
        _fail(
            "training artifact.tokenizer_config.json.auto_map",
            "custom tokenizer code is not accepted",
        )
    template_path = root / "chat_template.jinja"
    if template_path.exists():
        template_bytes = _read_file_bounded(
            template_path, "training artifact chat template", MAX_JSON_BYTES
        )
        template_sha256 = hashlib.sha256(template_bytes).hexdigest()
    else:
        template = tokenizer.get("chat_template")
        if not isinstance(template, str):
            _fail(
                "training artifact.tokenizer_config.json.chat_template",
                "must preserve the reviewed template",
            )
        template_sha256 = hashlib.sha256(template.encode("utf-8")).hexdigest()
    if template_sha256 != manifest["chatTemplate"]["sha256"]:
        _fail("training artifact chat template", "does not match the training manifest")


def _validate_training_bindings(
    profile: Mapping[str, Any],
    artifact: Mapping[str, Any],
    manifest: Mapping[str, Any],
    manifest_sha256: str,
) -> None:
    expected_base_model = {
        "candidateId": profile["candidateId"],
        "modelId": profile["baseModel"]["modelId"],
        "revision": profile["baseModel"]["revision"],
    }
    if artifact["baseModel"] != expected_base_model:
        _fail(
            "serving profile.baseModel",
            "does not match the sealed artifact and training manifest",
        )
    if profile["candidateCatalogSha256"] != manifest["candidateCatalog"]["sha256"]:
        _fail(
            "serving profile.candidateCatalogSha256",
            "does not match the training manifest",
        )
    if profile["chatTemplateSha256"] != manifest["chatTemplate"]["sha256"]:
        _fail(
            "serving profile.chatTemplateSha256", "does not match the training manifest"
        )
    expected_artifact_identity = {
        "mode": artifact["mode"],
        "trainingRunManifestSha256": manifest_sha256,
        "artifactSha256": artifact["artifactSha256"],
        "artifactTreeSha256": artifact["fileTreeSha256"],
    }
    if profile["trainingArtifact"] != expected_artifact_identity:
        _fail(
            "serving profile.trainingArtifact",
            "does not match the sealed training artifact",
        )

    runtime = profile["runtime"]
    maximum_length, quantizations = _RUNTIME_CAPABILITIES[profile["candidateId"]]
    if runtime["maxModelLength"] > maximum_length:
        _fail(
            "serving profile.runtime.maxModelLength",
            "exceeds the reviewed base-model capability",
        )
    if runtime["maxModelLength"] < manifest["hyperparameters"]["maxSequenceLength"]:
        _fail(
            "serving profile.runtime.maxModelLength",
            "is below the training sequence length",
        )
    if runtime["quantization"] not in quantizations:
        _fail(
            "serving profile.runtime.quantization",
            "is not reviewed for this base model",
        )


def validate_serving_profile(
    profile_path: str | os.PathLike[str],
    *,
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    manifest_snapshot: ValidatedManifestSnapshot | None = None,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_provenance_now: datetime | None = None,
) -> ServingProfile:
    profile = load_serving_profile(profile_path)
    artifact, manifest, manifest_sha256 = _load_training_inputs(
        artifact_path,
        manifest_path,
        manifest_snapshot=manifest_snapshot,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    _validate_training_bindings(profile.document, artifact, manifest, manifest_sha256)
    return profile


def create_serving_profile(
    *,
    profile_id: str,
    artifact_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    engine: str,
    engine_version: str,
    container_image_digest: str,
    quantization: str,
    compute_dtype: str,
    max_model_length: int,
    tensor_parallel_size: int,
    gpu_profile: str,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_provenance_now: datetime | None = None,
) -> ServingProfile:
    artifact, manifest, manifest_sha256 = _load_training_inputs(
        artifact_path,
        manifest_path,
        trainer_provenance_trust=trainer_provenance_trust,
        trainer_provenance_now=trainer_provenance_now,
    )
    document = {
        "schemaVersion": SERVING_PROFILE_SCHEMA_VERSION,
        "profileId": profile_id,
        "candidateCatalogSha256": manifest["candidateCatalog"]["sha256"],
        "candidateId": manifest["baseModel"]["candidateId"],
        "baseModel": {
            "modelId": manifest["baseModel"]["modelId"],
            "revision": manifest["baseModel"]["revision"],
        },
        "trainingArtifact": {
            "mode": artifact["mode"],
            "trainingRunManifestSha256": manifest_sha256,
            "artifactSha256": artifact["artifactSha256"],
            "artifactTreeSha256": artifact["fileTreeSha256"],
        },
        "chatTemplateSha256": manifest["chatTemplate"]["sha256"],
        "runtime": {
            "engine": engine,
            "engineVersion": engine_version,
            "containerImageDigest": container_image_digest,
            "quantization": quantization,
            "computeDtype": compute_dtype,
            "maxModelLength": max_model_length,
            "tensorParallelSize": tensor_parallel_size,
            "gpuProfile": gpu_profile,
        },
        "protocol": "openai-compatible",
    }
    _validate_serving_profile_document(document)
    _validate_training_bindings(document, artifact, manifest, manifest_sha256)

    destination = Path(output_path)
    _reject_reparse_components(
        destination, "serving profile output", allow_missing_suffix=True
    )
    _existing_directory(destination.parent, "serving profile output directory")
    _write_json_exclusive(destination, document)
    profile = load_serving_profile(destination)
    if profile.document != document:
        _fail("serving profile output", "does not match the validated serving profile")
    return profile
