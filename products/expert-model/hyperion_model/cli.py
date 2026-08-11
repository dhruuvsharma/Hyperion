from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .artifacts import validate_training_artifact
from .base_evaluation import (
    build_base_evaluation_vllm_launch,
    create_base_evaluation_profile,
    seal_base_model_snapshot,
    validate_base_evaluation_profile,
    validate_base_model_snapshot,
)
from .base_engine_wrapper import (
    BaseEngineActivationTrust,
    create_base_engine_activation,
    finalize_base_engine_activation,
    load_base_engine_wrapper_config,
    prepare_base_engine_activation_signing_bundle,
    serve_base_evaluation_model,
    verify_base_engine_activation,
)
from .base_selection import (
    BaseModelSelectionCandidateSource,
    BaseModelSelectionTrust,
    create_base_model_selection,
    finalize_base_model_selection,
    prepare_base_model_selection_signing_bundle,
    validate_base_model_selection,
)
from .core import (
    MAX_JSON_BYTES,
    MAX_SFT_BYTES,
    ValidationError,
    _read_file_bounded,
    create_bundle,
    default_hyperparameters,
    load_json_document,
    sha256_file,
    summarize_sft,
    validate_bundle,
    validate_candidate_catalog,
    validate_manifest_path,
    validate_sft,
)
from .corpus_quality import (
    TrainingCorpusAdmissionTrust,
    create_training_corpus_admission_bytes,
    derive_training_corpus_quality_report,
    finalize_training_corpus_admission_bytes,
    prepare_training_corpus_admission_signing_bundle_bytes,
    training_corpus_quality_policy_sha256,
    validate_training_corpus_quality_policy,
    verify_training_corpus_admission_file,
)
from .training import (
    PreflightError,
    finalize_training_artifact_from_handoff,
    train_from_manifest,
)
from .deployment import create_serving_profile, validate_serving_profile
from .engine_wrapper import serve_promoted_model
from .draft_evaluation import compile_draft_calibration_tasks
from .evaluation import (
    MAX_CAPTURE_RESPONSE_BYTES,
    BaseResponseAttestationTrust,
    aggregate_promotion_evidence,
    capture_openai_responses,
    compile_verifier_results,
    evaluation_response_set_sha256,
    summarize_evaluation_coverage,
    validate_attested_base_evaluation_responses,
    validate_evaluation_responses,
    validate_evaluation_tasks,
    validate_promotion_policy,
    validate_promotion_evidence,
    validate_verifier_results,
    write_json_atomic_no_clobber,
)
from .evaluation_authoring import (
    EvaluationAuthoringApprovalTrust,
    create_evaluation_authoring_approval,
    finalize_evaluation_authoring_approval,
    prepare_evaluation_authoring_approval_signing_bundle,
    validate_evaluation_authoring_approval_for_inventory,
)
from .evaluation_suite_authoring import (
    compile_evaluation_authoring_handoff,
    validate_evaluation_authoring_handoff,
)
from .verifier_runtime import CSharpVerifierExecutionContext, run_release_verifiers
from .csharp_verifier import (
    InfrastructureError,
    run_csharp_strategy_verification,
)
from .verifier_authority import (
    CSharpVerifierAuthorityTrust,
    create_csharp_verifier_authority,
    finalize_csharp_verifier_authority,
    prepare_csharp_verifier_authority_signing_bundle,
    validate_csharp_verifier_authority,
)
from .verifier_replay_audit import (
    CSharpVerifierReplayAuditTrust,
    create_csharp_verifier_replay_audit,
    finalize_csharp_verifier_replay_audit,
    prepare_csharp_verifier_replay_audit_signing_bundle,
    validate_csharp_verifier_replay_audit,
)
from .teacher_generation import (
    capture_teacher_candidates,
    create_teacher_runtime_binding,
    derive_teacher_runtime_plan,
    validate_teacher_candidates,
    validate_teacher_generation_manifest,
    validate_teacher_runtime_binding,
)
from .teacher_materialization import (
    create_teacher_overlap_deny_set,
    materialize_teacher_candidates,
    validate_teacher_materialization,
    validate_teacher_selection_manifest,
)
from .teacher_lineage import (
    TeacherMaterializationLineageAdmissionTrust,
    create_teacher_materialization_lineage_admission,
    finalize_teacher_materialization_lineage_admission,
    prepare_teacher_materialization_lineage_admission_signing_bundle,
    verify_teacher_materialization_lineage_admission,
)
from .release import (
    PURPOSES,
    create_corpus_evaluation_release,
    validate_corpus_evaluation_release,
    validate_training_release_binding,
)
from .review_receipts import (
    ExpertModelReviewReceiptTrust,
    create_expert_model_review_receipts,
    finalize_expert_model_review_receipts,
    prepare_expert_model_review_receipt_signing_bundle,
    validate_expert_model_review_receipts,
)
from .promotion import (
    create_model_promotion,
    create_promoted_model_readiness_attestation,
    finalize_model_promotion,
    prepare_model_promotion_signing_bundle,
    validate_model_promotion,
)
from .trainer_provenance import TrainerProvenanceTrust


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _add_promotion_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--promotion-evidence", type=Path, required=True)
    parser.add_argument("--calibration-tasks", type=Path, required=True)
    parser.add_argument("--calibration-evidence", type=Path, required=True)
    parser.add_argument("--sealed-tasks", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--verifier-results", type=Path, required=True)
    parser.add_argument("--baseline-responses", type=Path, required=True)
    parser.add_argument("--baseline-verifier-results", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--serving-profile", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--base-model-snapshot", type=Path, required=True)
    parser.add_argument("--approval-evidence", type=Path, required=True)
    parser.add_argument("--hosted-deployment-policy", type=Path, required=True)


def _promotion_source_arguments(args: argparse.Namespace) -> dict[str, Path]:
    return {
        "promotion_evidence_path": args.promotion_evidence,
        "calibration_tasks_path": args.calibration_tasks,
        "calibration_evidence_path": args.calibration_evidence,
        "sealed_tasks_path": args.sealed_tasks,
        "responses_path": args.responses,
        "verifier_results_path": args.verifier_results,
        "baseline_responses_path": args.baseline_responses,
        "baseline_verifier_results_path": args.baseline_verifier_results,
        "policy_path": args.policy,
        "data_release_path": args.release,
        "catalog_path": args.catalog,
        "serving_profile_path": args.serving_profile,
        "artifact_path": args.artifact,
        "manifest_path": args.manifest,
        "base_model_snapshot_path": args.base_model_snapshot,
        "approval_evidence_path": args.approval_evidence,
        "hosted_deployment_policy_path": args.hosted_deployment_policy,
    }


_BASE_SELECTION_SOURCES_SCHEMA_VERSION = (
    "daxalgo.hyperion.base-model-selection-sources/v1"
)
_BASE_SELECTION_SOURCE_KEYS = {
    "candidateId",
    "promotionEvidencePath",
    "responsesPath",
    "verifierResultsPath",
    "policyPath",
    "profilePath",
    "snapshotManifestPath",
    "snapshotPath",
}
_SAFE_BASE_SELECTION_CANDIDATE_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
)


def _add_base_selection_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bakeoff-sources",
        type=Path,
        required=True,
        help=(
            "JSON manifest containing the selected candidate ID and one evidence/snapshot "
            "source for every catalog student"
        ),
    )
    parser.add_argument("--calibration-tasks", type=Path, required=True)
    parser.add_argument("--calibration-evidence", type=Path, required=True)
    parser.add_argument("--sealed-tasks", type=Path, required=True)
    parser.add_argument("--baseline-responses", type=Path, required=True)
    parser.add_argument("--baseline-verifier-results", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--base-model-source-lock", type=Path, required=True)
    parser.add_argument("--approval-evidence", type=Path, required=True)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(
                f"base-model bake-off sources manifest: duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _load_base_selection_candidate_sources(
    path: Path,
    *,
    candidate_attestation_trust: BaseResponseAttestationTrust,
) -> tuple[tuple[BaseModelSelectionCandidateSource, ...], str]:
    manifest_path = Path(path)
    try:
        with manifest_path.open("rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
    except OSError:
        raise
    if len(raw) > MAX_JSON_BYTES:
        raise ValidationError(
            "base-model bake-off sources manifest: exceeds the maximum JSON size"
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValidationError(
            "base-model bake-off sources manifest: UTF-8 byte-order marks are not accepted"
        )
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValidationError(
            "base-model bake-off sources manifest: invalid UTF-8 JSON"
        ) from error
    if not isinstance(document, dict):
        raise ValidationError("base-model bake-off sources manifest: must be an object")
    expected_root_keys = {"schemaVersion", "selectedCandidateId", "candidates"}
    if set(document) != expected_root_keys:
        raise ValidationError(
            "base-model bake-off sources manifest: must contain exactly "
            "schemaVersion, selectedCandidateId, and candidates"
        )
    if document["schemaVersion"] != _BASE_SELECTION_SOURCES_SCHEMA_VERSION:
        raise ValidationError(
            "base-model bake-off sources manifest.schemaVersion: unsupported value"
        )
    selected_candidate_id = document["selectedCandidateId"]
    if not isinstance(selected_candidate_id, str) or not (
        _SAFE_BASE_SELECTION_CANDIDATE_ID_RE.fullmatch(selected_candidate_id)
    ):
        raise ValidationError(
            "base-model bake-off sources manifest.selectedCandidateId: invalid candidate ID"
        )
    candidates = document["candidates"]
    if not isinstance(candidates, list) or not candidates or len(candidates) > 32:
        raise ValidationError(
            "base-model bake-off sources manifest.candidates: must contain 1 through 32 entries"
        )

    parent = manifest_path.resolve(strict=False).parent
    seen: set[str] = set()
    sources: list[BaseModelSelectionCandidateSource] = []

    def resolve_source_path(value: Any, field: str) -> Path:
        if not isinstance(value, str) or not value or len(value) > 32_767:
            raise ValidationError(f"{field}: must be a non-empty path string")
        try:
            source_path = Path(value)
        except (OSError, ValueError) as error:
            raise ValidationError(f"{field}: invalid path") from error
        if not source_path.is_absolute():
            source_path = parent / source_path
        return source_path.resolve(strict=False)

    for index, entry in enumerate(candidates):
        field = f"base-model bake-off sources manifest.candidates[{index}]"
        if not isinstance(entry, dict):
            raise ValidationError(f"{field}: must be an object")
        if set(entry) != _BASE_SELECTION_SOURCE_KEYS:
            raise ValidationError(f"{field}: contains missing or unexpected fields")
        candidate_id = entry["candidateId"]
        if not isinstance(candidate_id, str) or not (
            _SAFE_BASE_SELECTION_CANDIDATE_ID_RE.fullmatch(candidate_id)
        ):
            raise ValidationError(f"{field}.candidateId: invalid candidate ID")
        if candidate_id in seen:
            raise ValidationError(f"{field}.candidateId: duplicates another entry")
        seen.add(candidate_id)
        sources.append(
            BaseModelSelectionCandidateSource(
                candidate_id=candidate_id,
                promotion_evidence_path=resolve_source_path(
                    entry["promotionEvidencePath"], f"{field}.promotionEvidencePath"
                ),
                responses_path=resolve_source_path(
                    entry["responsesPath"], f"{field}.responsesPath"
                ),
                verifier_results_path=resolve_source_path(
                    entry["verifierResultsPath"], f"{field}.verifierResultsPath"
                ),
                policy_path=resolve_source_path(
                    entry["policyPath"], f"{field}.policyPath"
                ),
                profile_path=resolve_source_path(
                    entry["profilePath"], f"{field}.profilePath"
                ),
                snapshot_manifest_path=resolve_source_path(
                    entry["snapshotManifestPath"], f"{field}.snapshotManifestPath"
                ),
                snapshot_path=resolve_source_path(
                    entry["snapshotPath"], f"{field}.snapshotPath"
                ),
                candidate_attestation_trust=candidate_attestation_trust,
            )
        )
    return tuple(sources), selected_candidate_id


def _base_selection_source_arguments(args: argparse.Namespace) -> dict[str, Any]:
    candidate_attestation_trust = _response_attestation_trust(args, prefix="candidate")
    if candidate_attestation_trust is None:  # argparse requires this trust surface
        raise ValidationError(
            "candidate response-attestation trust: externally pinned trust is required"
        )
    candidate_sources, selected_candidate_id = _load_base_selection_candidate_sources(
        args.bakeoff_sources,
        candidate_attestation_trust=candidate_attestation_trust,
    )
    return {
        "candidate_sources": candidate_sources,
        "selected_candidate_id": selected_candidate_id,
        "calibration_tasks_path": args.calibration_tasks,
        "calibration_evidence_path": args.calibration_evidence,
        "sealed_tasks_path": args.sealed_tasks,
        "baseline_responses_path": args.baseline_responses,
        "baseline_verifier_results_path": args.baseline_verifier_results,
        "data_release_path": args.release,
        "catalog_path": args.catalog,
        "source_lock_path": args.base_model_source_lock,
        "approval_evidence_path": args.approval_evidence,
    }


def _add_review_receipt_trust_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument("--review-receipt-public-key", type=Path, required=required)
    parser.add_argument("--review-receipt-public-key-spki-sha256", required=required)
    parser.add_argument("--review-receipt-audience", required=required)
    parser.add_argument("--review-receipt-key-id", required=required)
    parser.add_argument("--review-receipt-signer-role", required=required)
    _add_teacher_lineage_admission_trust_arguments(parser)


def _add_teacher_lineage_admission_trust_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument("--teacher-lineage-admission-public-key", type=Path)
    parser.add_argument("--teacher-lineage-admission-public-key-spki-sha256")
    parser.add_argument("--teacher-lineage-admission-audience")
    parser.add_argument("--teacher-lineage-admission-key-id")
    parser.add_argument("--teacher-lineage-admission-signer-role")


def _teacher_lineage_admission_trust(
    args: argparse.Namespace,
) -> TeacherMaterializationLineageAdmissionTrust | None:
    values = (
        getattr(args, "teacher_lineage_admission_public_key", None),
        getattr(args, "teacher_lineage_admission_public_key_spki_sha256", None),
        getattr(args, "teacher_lineage_admission_audience", None),
        getattr(args, "teacher_lineage_admission_key_id", None),
        getattr(args, "teacher_lineage_admission_signer_role", None),
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            "teacher-lineage admission trust: all five externally pinned trust options are required together"
        )
    return TeacherMaterializationLineageAdmissionTrust(*values)


def _review_receipt_trust(
    args: argparse.Namespace,
) -> ExpertModelReviewReceiptTrust | None:
    values = (
        args.review_receipt_public_key,
        args.review_receipt_public_key_spki_sha256,
        args.review_receipt_audience,
        args.review_receipt_key_id,
        args.review_receipt_signer_role,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            "review-receipt trust: all five externally pinned trust options are required together"
        )
    return ExpertModelReviewReceiptTrust(
        *values,
        teacher_lineage_admission_trust=_teacher_lineage_admission_trust(args),
    )


def _add_evaluation_authoring_approval_trust_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument(
        "--evaluation-authoring-approval-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--evaluation-authoring-approval-public-key-spki-sha256",
        required=required,
    )
    parser.add_argument("--evaluation-authoring-approval-audience", required=required)
    parser.add_argument("--evaluation-authoring-approval-key-id", required=required)
    parser.add_argument(
        "--evaluation-authoring-approval-signer-role", required=required
    )


def _evaluation_authoring_approval_trust(
    args: argparse.Namespace,
) -> EvaluationAuthoringApprovalTrust | None:
    values = (
        args.evaluation_authoring_approval_public_key,
        args.evaluation_authoring_approval_public_key_spki_sha256,
        args.evaluation_authoring_approval_audience,
        args.evaluation_authoring_approval_key_id,
        args.evaluation_authoring_approval_signer_role,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            "evaluation-authoring approval trust: all five externally pinned "
            "trust options are required together"
        )
    return EvaluationAuthoringApprovalTrust(*values)


def _add_trainer_provenance_trust_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument("--trainer-provenance-public-key", type=Path, required=required)
    parser.add_argument(
        "--trainer-provenance-public-key-spki-sha256", required=required
    )
    parser.add_argument("--trainer-provenance-audience", required=required)
    parser.add_argument("--trainer-provenance-key-id", required=required)
    parser.add_argument("--trainer-provenance-signer-role", required=required)


def _trainer_provenance_trust(
    args: argparse.Namespace,
) -> TrainerProvenanceTrust | None:
    values = (
        args.trainer_provenance_public_key,
        args.trainer_provenance_public_key_spki_sha256,
        args.trainer_provenance_audience,
        args.trainer_provenance_key_id,
        args.trainer_provenance_signer_role,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            "trainer provenance trust: all five externally pinned trust options "
            "are required together"
        )
    return TrainerProvenanceTrust(*values)


def _add_evaluation_authoring_inventory_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument("--source-dataset", type=Path, required=True)
    parser.add_argument("--calibration-tasks", type=Path, required=True)
    parser.add_argument("--sealed-tasks", type=Path, required=True)
    parser.add_argument("--task-bindings", type=Path, required=True)


def _add_base_selection_trust_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument("--base-selection-public-key", type=Path, required=required)
    parser.add_argument("--base-selection-public-key-spki-sha256", required=required)
    parser.add_argument("--base-selection-audience", required=required)
    parser.add_argument("--base-selection-key-id", required=required)
    parser.add_argument("--base-selection-signer-role", required=required)


def _base_selection_trust(args: argparse.Namespace) -> BaseModelSelectionTrust | None:
    values = (
        args.base_selection_public_key,
        args.base_selection_public_key_spki_sha256,
        args.base_selection_audience,
        args.base_selection_key_id,
        args.base_selection_signer_role,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            "base-model selection trust: all five externally pinned trust options "
            "are required together"
        )
    return BaseModelSelectionTrust(*values)


def _add_corpus_admission_trust_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument("--corpus-admission-public-key", type=Path, required=required)
    parser.add_argument("--corpus-admission-public-key-spki-sha256", required=required)
    parser.add_argument("--corpus-admission-audience", required=required)
    parser.add_argument("--corpus-admission-key-id", required=required)
    parser.add_argument("--corpus-admission-signer-role", required=required)
    parser.add_argument("--corpus-admission-quality-policy-sha256", required=required)


def _corpus_admission_trust(
    args: argparse.Namespace,
) -> TrainingCorpusAdmissionTrust | None:
    values = (
        args.corpus_admission_public_key,
        args.corpus_admission_public_key_spki_sha256,
        args.corpus_admission_audience,
        args.corpus_admission_key_id,
        args.corpus_admission_signer_role,
        args.corpus_admission_quality_policy_sha256,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            "training corpus admission trust: all six externally pinned trust "
            "options are required together"
        )
    return TrainingCorpusAdmissionTrust(*values)


def _training_release_identity_for_sft(
    *,
    sft_sha256: str,
    release_path: Path,
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
) -> dict[str, str]:
    _, identity = validate_training_release_binding(
        release_path,
        dataset_sha256=sft_sha256,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
    )
    return identity


def _require_corpus_admission_signer_separation(
    corpus_trust: TrainingCorpusAdmissionTrust,
    review_trust: ExpertModelReviewReceiptTrust,
    authoring_trust: EvaluationAuthoringApprovalTrust,
) -> None:
    upstream_signers = {
        review_trust.public_key_spki_sha256,
        authoring_trust.public_key_spki_sha256,
    }
    teacher_lineage_trust = review_trust.teacher_lineage_admission_trust
    if teacher_lineage_trust is not None:
        upstream_signers.add(teacher_lineage_trust.public_key_spki_sha256)
    if corpus_trust.public_key_spki_sha256 in upstream_signers:
        raise ValidationError(
            "training corpus admission signer: must differ from corpus review, "
            "teacher-lineage, and evaluation-authoring signers"
        )


def _add_csharp_verifier_authority_trust_arguments(
    parser: argparse.ArgumentParser,
    *,
    required: bool,
) -> None:
    parser.add_argument("--verifier-authority-public-key", type=Path, required=required)
    parser.add_argument(
        "--verifier-authority-public-key-spki-sha256", required=required
    )
    parser.add_argument("--verifier-authority-audience", required=required)
    parser.add_argument("--verifier-authority-key-id", required=required)
    parser.add_argument("--verifier-authority-signer-role", required=required)


def _add_optional_csharp_verifier_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verifier-authority", type=Path)
    _add_csharp_verifier_authority_trust_arguments(parser, required=False)


def _add_csharp_verifier_replay_audit_trust_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument(
        "--csharp-verifier-replay-audit-public-key",
        type=Path,
        required=required,
    )
    parser.add_argument(
        "--csharp-verifier-replay-audit-public-key-spki-sha256",
        required=required,
    )
    parser.add_argument("--csharp-verifier-replay-audit-audience", required=required)
    parser.add_argument("--csharp-verifier-replay-audit-key-id", required=required)
    parser.add_argument("--csharp-verifier-replay-audit-signer-role", required=required)


def _add_optional_csharp_verifier_replay_audit_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument("--csharp-verifier-replay-audit", type=Path)
    parser.add_argument("--expected-csharp-verifier-replay-audit-envelope-sha256")
    _add_csharp_verifier_replay_audit_trust_arguments(parser, required=False)


def _csharp_verifier_replay_audit_trust(
    args: argparse.Namespace,
) -> CSharpVerifierReplayAuditTrust:
    return CSharpVerifierReplayAuditTrust(
        public_key_path=args.csharp_verifier_replay_audit_public_key,
        public_key_spki_sha256=(
            args.csharp_verifier_replay_audit_public_key_spki_sha256
        ),
        audience=args.csharp_verifier_replay_audit_audience,
        key_id=args.csharp_verifier_replay_audit_key_id,
        signer_role=args.csharp_verifier_replay_audit_signer_role,
    )


def _add_csharp_verifier_replay_audit_live_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument("--sealed-tasks", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--verifier-results", type=Path, required=True)
    parser.add_argument("--baseline-responses", type=Path, required=True)
    parser.add_argument("--baseline-verifier-results", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--verifier-authority", type=Path, required=True)
    _add_csharp_verifier_authority_trust_arguments(parser, required=True)
    _add_review_receipt_trust_arguments(parser, required=True)
    _add_evaluation_authoring_approval_trust_arguments(parser, required=True)
    _add_promotion_attestation_trust_arguments(parser)


def _optional_csharp_verifier_replay_audit_arguments(
    args: argparse.Namespace,
) -> dict[str, Any]:
    values = (
        args.csharp_verifier_replay_audit,
        args.expected_csharp_verifier_replay_audit_envelope_sha256,
        args.csharp_verifier_replay_audit_public_key,
        args.csharp_verifier_replay_audit_public_key_spki_sha256,
        args.csharp_verifier_replay_audit_audience,
        args.csharp_verifier_replay_audit_key_id,
        args.csharp_verifier_replay_audit_signer_role,
    )
    if all(value is None for value in values):
        return {}
    if any(value is None for value in values):
        raise ValidationError(
            "C# verifier replay audit: path, exact envelope SHA-256, and all five "
            "externally pinned trust options are required together"
        )
    return {
        "csharp_verifier_replay_audit_path": args.csharp_verifier_replay_audit,
        "expected_csharp_verifier_replay_audit_envelope_sha256": (
            args.expected_csharp_verifier_replay_audit_envelope_sha256
        ),
        "csharp_verifier_replay_audit_trust": (
            _csharp_verifier_replay_audit_trust(args)
        ),
    }


def _csharp_verifier_authority_trust(
    args: argparse.Namespace,
) -> CSharpVerifierAuthorityTrust:
    return CSharpVerifierAuthorityTrust(
        public_key_path=args.verifier_authority_public_key,
        public_key_spki_sha256=(args.verifier_authority_public_key_spki_sha256),
        audience=args.verifier_authority_audience,
        key_id=args.verifier_authority_key_id,
        signer_role=args.verifier_authority_signer_role,
    )


def _optional_csharp_verifier_authority(
    args: argparse.Namespace,
) -> tuple[Path | None, CSharpVerifierAuthorityTrust | None]:
    values = (
        args.verifier_authority,
        args.verifier_authority_public_key,
        args.verifier_authority_public_key_spki_sha256,
        args.verifier_authority_audience,
        args.verifier_authority_key_id,
        args.verifier_authority_signer_role,
    )
    if all(value is None for value in values):
        return None, None
    if any(value is None for value in values):
        raise ValidationError(
            "C# verifier execution context: the authority path and all five "
            "externally pinned trust options are required together"
        )
    return args.verifier_authority, _csharp_verifier_authority_trust(args)


def _optional_csharp_verifier_context(
    args: argparse.Namespace,
    *,
    workspace_parent: Path | None = None,
) -> CSharpVerifierExecutionContext | None:
    authority_path, trust = _optional_csharp_verifier_authority(args)
    if authority_path is None or trust is None:
        return None
    return CSharpVerifierExecutionContext(
        authority_path=authority_path,
        authority_trust=trust,
        workspace_parent=workspace_parent or Path(tempfile.gettempdir()),
    )


def _add_base_selection_target_arguments(
    parser: argparse.ArgumentParser, *, required: bool
) -> None:
    parser.add_argument("--base-selection", type=Path, required=required)
    parser.add_argument("--base-evaluation-profile", type=Path, required=required)
    parser.add_argument("--base-model-snapshot-manifest", type=Path, required=required)
    parser.add_argument("--base-model-snapshot", type=Path, required=required)
    parser.add_argument("--base-model-source-lock", type=Path, required=required)
    _add_base_selection_trust_arguments(parser, required=required)


def _add_base_activation_trust_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--activation-public-key", type=Path, required=True)
    parser.add_argument("--activation-public-key-spki-sha256", required=True)
    parser.add_argument("--activation-audience", required=True)
    parser.add_argument("--activation-key-id", required=True)
    parser.add_argument("--activation-signer-role", required=True)


def _base_activation_trust(args: argparse.Namespace) -> BaseEngineActivationTrust:
    return BaseEngineActivationTrust(
        public_key_path=args.activation_public_key,
        public_key_spki_sha256=args.activation_public_key_spki_sha256,
        audience=args.activation_audience,
        key_id=args.activation_key_id,
        signer_role=args.activation_signer_role,
    )


def _add_response_attestation_trust_arguments(
    parser: argparse.ArgumentParser,
    *,
    prefix: str,
    required: bool = False,
) -> None:
    parser.add_argument(
        f"--{prefix}-activation-public-key", type=Path, required=required
    )
    parser.add_argument(
        f"--{prefix}-activation-public-key-spki-sha256", required=required
    )
    parser.add_argument(f"--{prefix}-activation-audience", required=required)
    parser.add_argument(f"--{prefix}-activation-key-id", required=required)
    parser.add_argument(f"--{prefix}-activation-signer-role", required=required)
    parser.add_argument(f"--{prefix}-runtime-public-key", type=Path, required=required)


def _response_attestation_trust(
    args: argparse.Namespace,
    *,
    prefix: str,
) -> BaseResponseAttestationTrust | None:
    attribute_prefix = prefix.replace("-", "_")
    values = (
        getattr(args, f"{attribute_prefix}_activation_public_key"),
        getattr(args, f"{attribute_prefix}_activation_public_key_spki_sha256"),
        getattr(args, f"{attribute_prefix}_activation_audience"),
        getattr(args, f"{attribute_prefix}_activation_key_id"),
        getattr(args, f"{attribute_prefix}_activation_signer_role"),
        getattr(args, f"{attribute_prefix}_runtime_public_key"),
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValidationError(
            f"{prefix} response-attestation trust: all six activation and runtime "
            "public-key options are required together"
        )
    return BaseResponseAttestationTrust(
        activation_trust=BaseEngineActivationTrust(
            public_key_path=values[0],
            public_key_spki_sha256=values[1],
            audience=values[2],
            key_id=values[3],
            signer_role=values[4],
        ),
        runtime_public_key_path=values[5],
    )


def _promotion_attestation_trust_arguments(
    args: argparse.Namespace,
) -> dict[str, BaseResponseAttestationTrust | None]:
    return {
        "candidate_attestation_trust": _response_attestation_trust(
            args, prefix="candidate"
        ),
        "baseline_attestation_trust": _response_attestation_trust(
            args, prefix="baseline"
        ),
    }


def _add_promotion_attestation_trust_arguments(
    parser: argparse.ArgumentParser,
    *,
    candidate_required: bool = False,
    baseline_required: bool = False,
) -> None:
    _add_response_attestation_trust_arguments(
        parser, prefix="candidate", required=candidate_required
    )
    _add_response_attestation_trust_arguments(
        parser, prefix="baseline", required=baseline_required
    )


def _csharp_verifier_replay_audit_live_arguments(
    args: argparse.Namespace, *, workspace_parent: Path
) -> dict[str, Any]:
    context = _optional_csharp_verifier_context(args, workspace_parent=workspace_parent)
    if context is None:  # pragma: no cover - argparse requires the group
        raise ValidationError(
            "C# verifier replay audit: live verifier authority is required"
        )
    return {
        "sealed_tasks_path": args.sealed_tasks,
        "candidate_responses_path": args.responses,
        "candidate_results_path": args.verifier_results,
        "baseline_responses_path": args.baseline_responses,
        "baseline_results_path": args.baseline_verifier_results,
        "data_release_path": args.release,
        "review_receipt_trust": _review_receipt_trust(args),
        "evaluation_authoring_approval_trust": (
            _evaluation_authoring_approval_trust(args)
        ),
        "csharp_verifier_context": context,
        **_promotion_attestation_trust_arguments(args),
    }


def _private_key_password(environment_name: str | None) -> bytes | None:
    if environment_name is None:
        return None
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", environment_name):
        raise ValidationError("private-key password environment variable: invalid name")
    value = os.environ.get(environment_name)
    if value is None:
        raise ValidationError(
            f"private-key password environment variable: {environment_name!r} is not set"
        )
    if not value:
        raise ValidationError(
            f"private-key password environment variable: {environment_name!r} is empty"
        )
    return value.encode("utf-8", errors="strict")


def _hmac_key(environment_name: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", environment_name):
        raise ValidationError("readiness-key environment variable: invalid name")
    value = os.environ.get(environment_name)
    if value is None:
        raise ValidationError(
            f"readiness-key environment variable: {environment_name!r} is not set"
        )
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value) or len(value) > 1024:
        raise ValidationError(
            "readiness-key environment variable: must contain canonical unpadded base64url"
        )
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ValidationError(
            "readiness-key environment variable: must contain canonical unpadded base64url"
        ) from error
    if urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValidationError(
            "readiness-key environment variable: must contain canonical unpadded base64url"
        )
    if not 32 <= len(decoded) <= 512:
        raise ValidationError(
            "readiness-key environment variable: must decode to 32 through 512 bytes"
        )
    return decoded


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hyperion-model",
        description="Offline Hyperion model candidate and QLoRA-SFT run harness.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog = subparsers.add_parser(
        "validate-catalog", help="strictly validate a pinned candidate catalog"
    )
    catalog.add_argument("catalog", type=Path)

    sft = subparsers.add_parser(
        "validate-sft", help="strictly validate ExpertModelDatasetTools SFT JSONL"
    )
    sft.add_argument("sft", type=Path)

    coverage = subparsers.add_parser(
        "summarize-coverage", help="emit machine-readable SFT coverage"
    )
    coverage.add_argument("sft", type=Path)

    corpus_quality = subparsers.add_parser(
        "summarize-corpus-quality",
        help="derive deterministic anti-inflation quality evidence for exact SFT bytes",
    )
    corpus_quality.add_argument("sft", type=Path)

    corpus_policy = subparsers.add_parser(
        "validate-corpus-quality-policy",
        help="validate reviewer-selected corpus thresholds and emit their exact hash",
    )
    corpus_policy.add_argument("policy", type=Path)

    create_corpus_admission = subparsers.add_parser(
        "create-training-corpus-admission",
        help="sign one exact released corpus and its reviewer-selected quality policy",
    )
    create_corpus_admission.add_argument("--sft", type=Path, required=True)
    create_corpus_admission.add_argument("--release", type=Path, required=True)
    create_corpus_admission.add_argument("--quality-policy", type=Path, required=True)
    create_corpus_admission.add_argument("--private-key", type=Path, required=True)
    create_corpus_admission.add_argument("--private-key-password-env")
    create_corpus_admission.add_argument("--reviewer-id", required=True)
    create_corpus_admission.add_argument("--reviewed-at-utc", required=True)
    create_corpus_admission.add_argument("--issued-at-utc", required=True)
    create_corpus_admission.add_argument("--not-before-utc", required=True)
    create_corpus_admission.add_argument("--expires-at-utc", required=True)
    create_corpus_admission.add_argument("--output", type=Path, required=True)
    _add_review_receipt_trust_arguments(create_corpus_admission, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        create_corpus_admission, required=True
    )
    _add_corpus_admission_trust_arguments(create_corpus_admission, required=True)

    prepare_corpus_admission = subparsers.add_parser(
        "prepare-training-corpus-admission-signing-bundle",
        help="prepare one non-authorizing corpus-admission request for external signing",
    )
    prepare_corpus_admission.add_argument("--sft", type=Path, required=True)
    prepare_corpus_admission.add_argument("--release", type=Path, required=True)
    prepare_corpus_admission.add_argument("--quality-policy", type=Path, required=True)
    prepare_corpus_admission.add_argument("--reviewer-id", required=True)
    prepare_corpus_admission.add_argument("--reviewed-at-utc", required=True)
    prepare_corpus_admission.add_argument("--issued-at-utc", required=True)
    prepare_corpus_admission.add_argument("--not-before-utc", required=True)
    prepare_corpus_admission.add_argument("--expires-at-utc", required=True)
    prepare_corpus_admission.add_argument("--output", type=Path, required=True)
    _add_review_receipt_trust_arguments(prepare_corpus_admission, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        prepare_corpus_admission, required=True
    )
    _add_corpus_admission_trust_arguments(prepare_corpus_admission, required=True)

    finalize_corpus_admission = subparsers.add_parser(
        "finalize-training-corpus-admission",
        help="finalize the unchanged corpus-admission envelope from an external signature",
    )
    finalize_corpus_admission.add_argument("--signing-bundle", type=Path, required=True)
    finalize_corpus_admission.add_argument("--signature", type=Path, required=True)
    finalize_corpus_admission.add_argument("--sft", type=Path, required=True)
    finalize_corpus_admission.add_argument("--release", type=Path, required=True)
    finalize_corpus_admission.add_argument("--quality-policy", type=Path, required=True)
    finalize_corpus_admission.add_argument("--output", type=Path, required=True)
    _add_review_receipt_trust_arguments(finalize_corpus_admission, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        finalize_corpus_admission, required=True
    )
    _add_corpus_admission_trust_arguments(finalize_corpus_admission, required=True)

    validate_corpus_admission = subparsers.add_parser(
        "validate-training-corpus-admission",
        help="verify a signed admission against exact released SFT bytes and external trust",
    )
    validate_corpus_admission.add_argument("admission", type=Path)
    validate_corpus_admission.add_argument("--sft", type=Path, required=True)
    validate_corpus_admission.add_argument("--release", type=Path, required=True)
    _add_review_receipt_trust_arguments(validate_corpus_admission, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        validate_corpus_admission, required=True
    )
    _add_corpus_admission_trust_arguments(validate_corpus_admission, required=True)

    manifest = subparsers.add_parser(
        "validate-manifest", help="validate a manifest and every bound input"
    )
    manifest.add_argument("manifest", type=Path)

    bundle = subparsers.add_parser(
        "validate-bundle", help="validate all bundle hashes and bindings"
    )
    bundle.add_argument("bundle", type=Path)

    create = subparsers.add_parser(
        "create-bundle", help="create an immutable hashed run bundle without training"
    )
    create.add_argument("--catalog", type=Path, required=True)
    create.add_argument("--sft", type=Path, required=True)
    create.add_argument("--candidate-id", required=True)
    create.add_argument("--chat-template-file", type=Path, required=True)
    create.add_argument("--chat-template-name", required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument(
        "--runtime-profile",
        type=Path,
        required=True,
        help="sealed training runtime profile; its sibling pylock.train.toml is snapshotted and bound",
    )
    create.add_argument("--release", type=Path)
    create.add_argument("--corpus-admission", type=Path)
    _add_review_receipt_trust_arguments(create, required=False)
    _add_evaluation_authoring_approval_trust_arguments(create, required=False)
    _add_base_selection_target_arguments(create, required=False)
    _add_corpus_admission_trust_arguments(create, required=False)
    create.add_argument("--seed", type=int, default=17)
    create.add_argument("--epochs", type=float, default=3.0)
    create.add_argument("--learning-rate", type=float, default=0.0002)
    create.add_argument("--batch-size", type=int, default=1)
    create.add_argument("--gradient-accumulation-steps", type=int, default=16)
    create.add_argument("--max-sequence-length", type=int, default=4096)
    create.add_argument("--warmup-ratio", type=float, default=0.03)
    create.add_argument("--weight-decay", type=float, default=0.0)
    create.add_argument("--lora-r", type=int, default=64)
    create.add_argument("--lora-alpha", type=int, default=128)
    create.add_argument("--lora-dropout", type=float, default=0.05)
    create.add_argument("--lora-target-module", action="append", dest="lora_modules")

    train = subparsers.add_parser(
        "train", help="run local-only QLoRA-SFT after strict preflight"
    )
    train.add_argument("manifest", type=Path)
    train.add_argument("--release", type=Path, required=True)
    _add_review_receipt_trust_arguments(train, required=True)
    _add_evaluation_authoring_approval_trust_arguments(train, required=True)
    train.add_argument("--base-model-snapshot", type=Path)
    _add_base_selection_trust_arguments(train, required=False)
    _add_corpus_admission_trust_arguments(train, required=False)
    _add_trainer_provenance_trust_arguments(train, required=False)
    train.add_argument("--trainer-private-key", type=Path)
    train.add_argument(
        "--trainer-provenance-handoff",
        type=Path,
        help="sibling pending-package path for external trainer-provenance signing",
    )
    train.add_argument(
        "--trainer-private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    train.add_argument("--trainer-id")
    train.add_argument("--trainer-expires-at-utc")
    train.add_argument("--minimum-gpu-memory-gib", type=float, default=16.0)
    train.add_argument(
        "--smoke",
        action="store_true",
        help="waive the production memory floor for a one-step artifact marked non-production",
    )

    finalize_training = subparsers.add_parser(
        "finalize-training-artifact",
        help="seal a pending candidate with an external trainer-provenance signature",
    )
    finalize_training.add_argument("manifest", type=Path)
    finalize_training.add_argument("--handoff", type=Path, required=True)
    finalize_training.add_argument("--signature", type=Path, required=True)
    finalize_training.add_argument("--release", type=Path, required=True)
    _add_review_receipt_trust_arguments(finalize_training, required=True)
    _add_evaluation_authoring_approval_trust_arguments(finalize_training, required=True)
    finalize_training.add_argument("--base-model-snapshot", type=Path, required=True)
    _add_base_selection_trust_arguments(finalize_training, required=True)
    _add_corpus_admission_trust_arguments(finalize_training, required=True)
    _add_trainer_provenance_trust_arguments(finalize_training, required=True)

    artifact = subparsers.add_parser(
        "validate-artifact",
        help="validate sealed training metadata and every adapter/tokenizer file",
    )
    artifact.add_argument("artifact", type=Path)
    _add_trainer_provenance_trust_arguments(artifact, required=False)

    serving_profile = subparsers.add_parser(
        "validate-serving-profile",
        help="validate a serving profile and its exact manifest/artifact bindings",
    )
    serving_profile.add_argument("profile", type=Path)
    serving_profile.add_argument("--artifact", type=Path, required=True)
    serving_profile.add_argument("--manifest", type=Path, required=True)
    _add_trainer_provenance_trust_arguments(serving_profile, required=False)

    create_profile = subparsers.add_parser(
        "create-serving-profile",
        help="derive and write an immutable serving profile from a sealed training artifact",
    )
    create_profile.add_argument("--profile-id", required=True)
    create_profile.add_argument("--artifact", type=Path, required=True)
    create_profile.add_argument("--manifest", type=Path, required=True)
    create_profile.add_argument("--output", type=Path, required=True)
    create_profile.add_argument("--engine", required=True)
    create_profile.add_argument("--engine-version", required=True)
    create_profile.add_argument("--container-image-digest", required=True)
    create_profile.add_argument(
        "--quantization",
        choices=("none", "bitsandbytes-nf4", "awq", "gptq", "mxfp4"),
        required=True,
    )
    create_profile.add_argument(
        "--compute-dtype",
        choices=("float16", "bfloat16", "float32"),
        required=True,
    )
    create_profile.add_argument("--max-model-length", type=int, required=True)
    create_profile.add_argument("--tensor-parallel-size", type=int, required=True)
    create_profile.add_argument("--gpu-profile", required=True)
    _add_trainer_provenance_trust_arguments(create_profile, required=False)

    seal_base_snapshot = subparsers.add_parser(
        "seal-base-model-snapshot",
        help="hash and seal an offline safe base-model snapshot",
    )
    seal_base_snapshot.add_argument("--snapshot", type=Path, required=True)
    seal_base_snapshot.add_argument("--catalog", type=Path, required=True)
    seal_base_snapshot.add_argument("--source-lock", type=Path, required=True)
    seal_base_snapshot.add_argument("--candidate-id", required=True)
    seal_base_snapshot.add_argument("--output", type=Path, required=True)

    validate_base_snapshot = subparsers.add_parser(
        "validate-base-model-snapshot",
        help="revalidate every file in a sealed base-model snapshot",
    )
    validate_base_snapshot.add_argument("manifest", type=Path)
    validate_base_snapshot.add_argument("--snapshot", type=Path, required=True)
    validate_base_snapshot.add_argument("--catalog", type=Path, required=True)
    validate_base_snapshot.add_argument("--source-lock", type=Path, required=True)

    create_base_profile = subparsers.add_parser(
        "create-base-evaluation-profile",
        help="derive an immutable evaluation-only profile from sealed base-model bytes",
    )
    create_base_profile.add_argument("--profile-id", required=True)
    create_base_profile.add_argument("--catalog", type=Path, required=True)
    create_base_profile.add_argument("--source-lock", type=Path, required=True)
    create_base_profile.add_argument("--snapshot", type=Path, required=True)
    create_base_profile.add_argument("--snapshot-manifest", type=Path, required=True)
    create_base_profile.add_argument("--output", type=Path, required=True)
    create_base_profile.add_argument("--engine-version", required=True)
    create_base_profile.add_argument("--container-image-digest", required=True)
    create_base_profile.add_argument(
        "--quantization",
        choices=("none", "bitsandbytes-nf4", "awq", "gptq", "mxfp4"),
        required=True,
    )
    create_base_profile.add_argument(
        "--compute-dtype",
        choices=("float16", "bfloat16", "float32"),
        required=True,
    )
    create_base_profile.add_argument("--max-model-length", type=int, required=True)
    create_base_profile.add_argument("--tensor-parallel-size", type=int, required=True)
    create_base_profile.add_argument("--gpu-profile", required=True)

    validate_base_profile = subparsers.add_parser(
        "validate-base-evaluation-profile",
        help="validate a base profile and its exact catalog/snapshot bindings",
    )
    validate_base_profile.add_argument("profile", type=Path)
    validate_base_profile.add_argument("--catalog", type=Path, required=True)
    validate_base_profile.add_argument("--source-lock", type=Path, required=True)
    validate_base_profile.add_argument("--snapshot", type=Path, required=True)
    validate_base_profile.add_argument("--snapshot-manifest", type=Path, required=True)

    base_launch = subparsers.add_parser(
        "base-evaluation-launch",
        help="emit the offline loopback vLLM launch contract for a sealed base profile",
    )
    base_launch.add_argument("profile", type=Path)
    base_launch.add_argument("--catalog", type=Path, required=True)
    base_launch.add_argument("--source-lock", type=Path, required=True)
    base_launch.add_argument("--snapshot", type=Path, required=True)
    base_launch.add_argument("--snapshot-manifest", type=Path, required=True)
    base_launch.add_argument("--executable", type=Path, required=True)
    base_launch.add_argument("--port", type=int, required=True)

    create_base_activation = subparsers.add_parser(
        "create-base-engine-activation",
        help="sign a bounded raw-base engine activation for one exact wrapper config",
    )
    create_base_activation.add_argument("--config", type=Path, required=True)
    create_base_activation.add_argument("--output", type=Path, required=True)
    create_base_activation.add_argument("--private-key", type=Path, required=True)
    create_base_activation.add_argument("--public-key", type=Path, required=True)
    create_base_activation.add_argument("--private-key-password-env")
    create_base_activation.add_argument("--audience", required=True)
    create_base_activation.add_argument("--key-id", required=True)
    create_base_activation.add_argument("--signer-role", required=True)
    create_base_activation.add_argument("--issued-at-utc", required=True)
    create_base_activation.add_argument("--not-before-utc", required=True)
    create_base_activation.add_argument("--expires-at-utc", required=True)

    prepare_base_activation = subparsers.add_parser(
        "prepare-base-engine-activation-signing-bundle",
        help=(
            "derive the exact live activation and emit a non-authorizing "
            "detached-signing bundle"
        ),
    )
    prepare_base_activation.add_argument("--config", type=Path, required=True)
    prepare_base_activation.add_argument("--output", type=Path, required=True)
    prepare_base_activation.add_argument("--public-key", type=Path, required=True)
    prepare_base_activation.add_argument("--audience", required=True)
    prepare_base_activation.add_argument("--key-id", required=True)
    prepare_base_activation.add_argument("--signer-role", required=True)
    prepare_base_activation.add_argument("--issued-at-utc", required=True)
    prepare_base_activation.add_argument("--not-before-utc", required=True)
    prepare_base_activation.add_argument("--expires-at-utc", required=True)

    finalize_base_activation = subparsers.add_parser(
        "finalize-base-engine-activation",
        help=(
            "verify an external launcher signature, replay the live wrapper bindings, "
            "and publish the existing activation-v1 envelope"
        ),
    )
    finalize_base_activation.add_argument("--config", type=Path, required=True)
    finalize_base_activation.add_argument("--signing-bundle", type=Path, required=True)
    finalize_base_activation.add_argument("--signature", type=Path, required=True)
    finalize_base_activation.add_argument("--output", type=Path, required=True)
    finalize_base_activation.add_argument("--public-key", type=Path, required=True)
    finalize_base_activation.add_argument("--expected-audience", required=True)
    finalize_base_activation.add_argument("--expected-key-id", required=True)
    finalize_base_activation.add_argument("--expected-signer-role", required=True)

    validate_base_activation = subparsers.add_parser(
        "validate-base-engine-activation",
        help="verify the signed activation and every live raw-base wrapper binding",
    )
    validate_base_activation.add_argument("config", type=Path)

    serve_base = subparsers.add_parser(
        "serve-base-evaluation-model",
        help="own a sealed raw-base child and issue local- or externally signed receipts",
    )
    serve_base.add_argument("config", type=Path)

    compile_calibration = subparsers.add_parser(
        "compile-draft-calibration-tasks",
        help="compile a private draft manifest into canonical calibration-task JSONL",
    )
    compile_calibration.add_argument("--manifest", type=Path, required=True)
    compile_calibration.add_argument("--output", type=Path, required=True)

    compile_authoring_handoff = subparsers.add_parser(
        "compile-evaluation-authoring-handoff",
        help=(
            "derive paired evaluation tasks and an unsigned exact-asset handoff "
            "from reviewed corpus rows"
        ),
    )
    compile_authoring_handoff.add_argument("--manifest", type=Path, required=True)
    compile_authoring_handoff.add_argument("--source-dataset", type=Path, required=True)
    compile_authoring_handoff.add_argument(
        "--output-directory", type=Path, required=True
    )

    validate_authoring_handoff = subparsers.add_parser(
        "validate-evaluation-authoring-handoff",
        help="revalidate an unsigned evaluation-authoring handoff and exact assets",
    )
    validate_authoring_handoff.add_argument("handoff", type=Path)
    validate_authoring_handoff.add_argument(
        "--source-dataset", type=Path, required=True
    )

    eval_tasks = subparsers.add_parser(
        "validate-eval-tasks", help="strictly validate calibration/sealed task JSONL"
    )
    eval_tasks.add_argument("tasks", type=Path)

    eval_coverage = subparsers.add_parser(
        "summarize-eval-coverage", help="emit deterministic evaluation coverage"
    )
    eval_coverage.add_argument("tasks", type=Path)

    responses = subparsers.add_parser(
        "validate-responses", help="validate task-bound response JSONL"
    )
    responses.add_argument("responses", type=Path)
    responses.add_argument("--tasks", type=Path, required=True)

    attested_responses = subparsers.add_parser(
        "validate-attested-base-responses",
        help="cryptographically verify historical task-bound raw-base response v2 JSONL",
    )
    attested_responses.add_argument("responses", type=Path)
    attested_responses.add_argument("--tasks", type=Path, required=True)
    attested_responses.add_argument("--runtime-public-key", type=Path, required=True)
    _add_base_activation_trust_arguments(attested_responses)

    verifier_results = subparsers.add_parser(
        "validate-verifier-results", help="validate ingested verifier evidence"
    )
    verifier_results.add_argument("results", type=Path)
    verifier_results.add_argument("--tasks", type=Path, required=True)
    verifier_results.add_argument("--responses", type=Path, required=True)

    compile_results = subparsers.add_parser(
        "compile-verifier-results",
        help="compile research-only human decisions into canonical verifier-result JSONL",
    )
    compile_results.add_argument("--tasks", type=Path, required=True)
    compile_results.add_argument("--responses", type=Path, required=True)
    compile_results.add_argument("--decisions", type=Path, required=True)
    compile_results.add_argument("--output", type=Path, required=True)

    run_verifiers = subparsers.add_parser(
        "run-verifiers",
        help="execute closed declarative or signed headless C# verifiers from a release",
    )
    run_verifiers.add_argument("--tasks", type=Path, required=True)
    run_verifiers.add_argument("--responses", type=Path, required=True)
    run_verifiers.add_argument("--release", type=Path, required=True)
    run_verifiers.add_argument("--output", type=Path, required=True)
    _add_optional_csharp_verifier_arguments(run_verifiers)
    _add_review_receipt_trust_arguments(run_verifiers, required=True)
    _add_evaluation_authoring_approval_trust_arguments(run_verifiers, required=True)

    create_csharp_authority = subparsers.add_parser(
        "create-csharp-verifier-authority",
        help="sign one bounded standalone C# verifier configuration lease",
    )
    create_csharp_authority.add_argument("--toolchain", type=Path, required=True)
    create_csharp_authority.add_argument("--image", required=True)
    create_csharp_authority.add_argument("--image-id", required=True)
    create_csharp_authority.add_argument("--entrypoint", required=True)
    create_csharp_authority.add_argument("--docker-client", type=Path, required=True)
    create_csharp_authority.add_argument("--docker-daemon-endpoint", required=True)
    create_csharp_authority.add_argument("--output", type=Path, required=True)
    create_csharp_authority.add_argument("--private-key", type=Path, required=True)
    create_csharp_authority.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    _add_csharp_verifier_authority_trust_arguments(
        create_csharp_authority, required=True
    )
    create_csharp_authority.add_argument("--approval-id", required=True)
    create_csharp_authority.add_argument("--actor-id", required=True)
    create_csharp_authority.add_argument("--actor-role", required=True)
    create_csharp_authority.add_argument("--approval-reference", required=True)
    create_csharp_authority.add_argument("--approved-at-utc", required=True)
    create_csharp_authority.add_argument("--issued-at-utc", required=True)
    create_csharp_authority.add_argument("--not-before-utc", required=True)
    create_csharp_authority.add_argument("--expires-at-utc", required=True)

    prepare_csharp_authority = subparsers.add_parser(
        "prepare-csharp-verifier-authority-signing-bundle",
        help=(
            "derive the exact verifier authority and emit a non-authorizing "
            "provider-neutral signing request"
        ),
    )
    prepare_csharp_authority.add_argument("--toolchain", type=Path, required=True)
    prepare_csharp_authority.add_argument("--image", required=True)
    prepare_csharp_authority.add_argument("--image-id", required=True)
    prepare_csharp_authority.add_argument("--entrypoint", required=True)
    prepare_csharp_authority.add_argument("--docker-client", type=Path, required=True)
    prepare_csharp_authority.add_argument("--docker-daemon-endpoint", required=True)
    prepare_csharp_authority.add_argument("--output", type=Path, required=True)
    _add_csharp_verifier_authority_trust_arguments(
        prepare_csharp_authority, required=True
    )
    prepare_csharp_authority.add_argument("--approval-id", required=True)
    prepare_csharp_authority.add_argument("--actor-id", required=True)
    prepare_csharp_authority.add_argument("--actor-role", required=True)
    prepare_csharp_authority.add_argument("--approval-reference", required=True)
    prepare_csharp_authority.add_argument("--approved-at-utc", required=True)
    prepare_csharp_authority.add_argument("--issued-at-utc", required=True)
    prepare_csharp_authority.add_argument("--not-before-utc", required=True)
    prepare_csharp_authority.add_argument("--expires-at-utc", required=True)

    finalize_csharp_authority = subparsers.add_parser(
        "finalize-csharp-verifier-authority",
        help=(
            "verify an external authority signature, replay every live binding, "
            "and publish the existing authority-v2 envelope"
        ),
    )
    finalize_csharp_authority.add_argument("--signing-bundle", type=Path, required=True)
    finalize_csharp_authority.add_argument("--signature", type=Path, required=True)
    finalize_csharp_authority.add_argument("--toolchain", type=Path, required=True)
    finalize_csharp_authority.add_argument("--image", required=True)
    finalize_csharp_authority.add_argument("--image-id", required=True)
    finalize_csharp_authority.add_argument("--entrypoint", required=True)
    finalize_csharp_authority.add_argument("--docker-client", type=Path, required=True)
    finalize_csharp_authority.add_argument("--docker-daemon-endpoint", required=True)
    finalize_csharp_authority.add_argument("--output", type=Path, required=True)
    _add_csharp_verifier_authority_trust_arguments(
        finalize_csharp_authority, required=True
    )

    validate_csharp_authority = subparsers.add_parser(
        "validate-csharp-verifier-authority",
        help="validate a signed standalone C# verifier configuration lease",
    )
    validate_csharp_authority.add_argument("authority", type=Path)
    _add_csharp_verifier_authority_trust_arguments(
        validate_csharp_authority, required=True
    )

    create_replay_audit = subparsers.add_parser(
        "create-csharp-verifier-replay-audit",
        help="freshly replay both release-bound runs and sign the exact C# evidence",
    )
    create_replay_audit.add_argument("--output", type=Path, required=True)
    create_replay_audit.add_argument("--private-key", type=Path, required=True)
    create_replay_audit.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    _add_csharp_verifier_replay_audit_trust_arguments(
        create_replay_audit, required=True
    )
    create_replay_audit.add_argument("--approval-id", required=True)
    create_replay_audit.add_argument("--actor-id", required=True)
    create_replay_audit.add_argument("--actor-role", required=True)
    create_replay_audit.add_argument("--approval-reference", required=True)
    create_replay_audit.add_argument("--approved-at-utc", required=True)
    create_replay_audit.add_argument("--replay-completed-at-utc", required=True)
    create_replay_audit.add_argument("--issued-at-utc", required=True)
    create_replay_audit.add_argument("--not-before-utc", required=True)
    create_replay_audit.add_argument("--expires-at-utc", required=True)
    _add_csharp_verifier_replay_audit_live_arguments(create_replay_audit)

    prepare_replay_audit = subparsers.add_parser(
        "prepare-csharp-verifier-replay-audit-signing-bundle",
        help=(
            "freshly replay both runs and emit a non-authorizing external-signing "
            "bundle for the existing audit-v1 envelope"
        ),
    )
    prepare_replay_audit.add_argument("--output", type=Path, required=True)
    _add_csharp_verifier_replay_audit_trust_arguments(
        prepare_replay_audit, required=True
    )
    prepare_replay_audit.add_argument("--approval-id", required=True)
    prepare_replay_audit.add_argument("--actor-id", required=True)
    prepare_replay_audit.add_argument("--actor-role", required=True)
    prepare_replay_audit.add_argument("--approval-reference", required=True)
    prepare_replay_audit.add_argument("--approved-at-utc", required=True)
    prepare_replay_audit.add_argument("--replay-completed-at-utc", required=True)
    prepare_replay_audit.add_argument("--issued-at-utc", required=True)
    prepare_replay_audit.add_argument("--not-before-utc", required=True)
    prepare_replay_audit.add_argument("--expires-at-utc", required=True)
    _add_csharp_verifier_replay_audit_live_arguments(prepare_replay_audit)

    finalize_replay_audit = subparsers.add_parser(
        "finalize-csharp-verifier-replay-audit",
        help=(
            "verify an external signature, freshly replay both runs, and publish "
            "the existing audit-v1 envelope"
        ),
    )
    finalize_replay_audit.add_argument("--signing-bundle", type=Path, required=True)
    finalize_replay_audit.add_argument("--signature", type=Path, required=True)
    finalize_replay_audit.add_argument("--output", type=Path, required=True)
    _add_csharp_verifier_replay_audit_trust_arguments(
        finalize_replay_audit, required=True
    )
    _add_csharp_verifier_replay_audit_live_arguments(finalize_replay_audit)

    validate_replay_audit = subparsers.add_parser(
        "validate-csharp-verifier-replay-audit",
        help="validate one exact externally trusted C# verifier replay audit",
    )
    validate_replay_audit.add_argument("audit", type=Path)
    validate_replay_audit.add_argument(
        "--expected-csharp-verifier-replay-audit-envelope-sha256", required=True
    )
    _add_csharp_verifier_replay_audit_trust_arguments(
        validate_replay_audit, required=True
    )

    csharp_verifier = subparsers.add_parser(
        "verify-csharp-strategy",
        help="run the isolated headless DaxAlgo SDK strategy verifier",
    )
    csharp_verifier.add_argument("--request", type=Path, required=True)
    csharp_verifier.add_argument("--source", type=Path, required=True)
    csharp_verifier.add_argument("--expectations", type=Path, required=True)
    csharp_verifier.add_argument("--authority", type=Path, required=True)
    _add_csharp_verifier_authority_trust_arguments(csharp_verifier, required=True)
    csharp_verifier.add_argument("--output", type=Path, required=True)

    policy = subparsers.add_parser(
        "validate-promotion-policy",
        help="validate frozen calibration-derived thresholds",
    )
    policy.add_argument("policy", type=Path)

    capture = subparsers.add_parser(
        "capture-responses",
        help="capture OpenAI-compatible responses without verifier leakage",
    )
    capture.add_argument("--tasks", type=Path, required=True)
    capture.add_argument("--catalog", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--serving-profile", type=Path, required=True)
    capture.add_argument("--artifact", type=Path, required=True)
    capture.add_argument("--manifest", type=Path, required=True)
    capture.add_argument("--run-id", required=True)
    capture.add_argument("--base-url", required=True)
    capture.add_argument(
        "--api-key-env",
        required=True,
        help="environment variable name; key values are never accepted as arguments",
    )
    capture.add_argument("--seed", type=int, required=True)
    capture.add_argument("--release", type=Path)
    _add_review_receipt_trust_arguments(capture, required=False)
    _add_evaluation_authoring_approval_trust_arguments(capture, required=False)
    _add_trainer_provenance_trust_arguments(capture, required=False)
    capture.add_argument(
        "--research-only-unbound",
        action="store_true",
        help="capture explicit unpromoted research evidence without a release",
    )
    capture.add_argument("--timeout-seconds", type=float, default=60.0)
    capture.add_argument(
        "--max-response-bytes", type=int, default=MAX_CAPTURE_RESPONSE_BYTES
    )

    base_capture = subparsers.add_parser(
        "capture-base-responses",
        help="capture explicit research-only responses from a sealed raw-base target",
    )
    base_capture.add_argument("--tasks", type=Path, required=True)
    base_capture.add_argument("--catalog", type=Path, required=True)
    base_capture.add_argument("--source-lock", type=Path, required=True)
    base_capture.add_argument("--output", type=Path, required=True)
    base_capture.add_argument("--base-evaluation-profile", type=Path, required=True)
    base_capture.add_argument("--snapshot", type=Path, required=True)
    base_capture.add_argument("--snapshot-manifest", type=Path, required=True)
    base_capture.add_argument("--run-id", required=True)
    base_capture.add_argument("--base-url", required=True)
    base_capture.add_argument(
        "--api-key-env",
        required=True,
        help="environment variable name; key values are never accepted as arguments",
    )
    base_capture.add_argument("--seed", type=int, required=True)
    base_capture.add_argument("--timeout-seconds", type=float, default=60.0)
    base_capture.add_argument(
        "--max-response-bytes", type=int, default=MAX_CAPTURE_RESPONSE_BYTES
    )

    attested_base_capture = subparsers.add_parser(
        "capture-attested-base-responses",
        help="capture release-bound raw-base responses with signed runtime receipts",
    )
    attested_base_capture.add_argument("--tasks", type=Path, required=True)
    attested_base_capture.add_argument("--catalog", type=Path, required=True)
    attested_base_capture.add_argument("--source-lock", type=Path, required=True)
    attested_base_capture.add_argument("--output", type=Path, required=True)
    attested_base_capture.add_argument(
        "--base-evaluation-profile", type=Path, required=True
    )
    attested_base_capture.add_argument("--snapshot", type=Path, required=True)
    attested_base_capture.add_argument("--snapshot-manifest", type=Path, required=True)
    attested_base_capture.add_argument("--wrapper-config", type=Path, required=True)
    attested_base_capture.add_argument("--run-id", required=True)
    attested_base_capture.add_argument("--base-url", required=True)
    attested_base_capture.add_argument(
        "--api-key-env",
        required=True,
        help="environment variable name; key values are never accepted as arguments",
    )
    attested_base_capture.add_argument("--seed", type=int, required=True)
    attested_base_capture.add_argument("--release", type=Path, required=True)
    _add_review_receipt_trust_arguments(attested_base_capture, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        attested_base_capture, required=True
    )
    _add_base_activation_trust_arguments(attested_base_capture)
    attested_base_capture.add_argument("--timeout-seconds", type=float, default=60.0)
    attested_base_capture.add_argument(
        "--max-response-bytes", type=int, default=MAX_CAPTURE_RESPONSE_BYTES
    )

    derive_teacher_runtime = subparsers.add_parser(
        "derive-teacher-runtime-plan",
        help="derive the exact teacher served-model identity without probing or writing",
    )
    derive_teacher_runtime.add_argument(
        "--runtime-descriptor", type=Path, required=True
    )
    derive_teacher_runtime.add_argument("--catalog", type=Path, required=True)

    create_teacher_binding = subparsers.add_parser(
        "create-teacher-runtime-binding",
        help="bind reviewed teacher runtime inputs to one observed loopback vLLM",
    )
    create_teacher_binding.add_argument(
        "--runtime-descriptor", type=Path, required=True
    )
    create_teacher_binding.add_argument("--catalog", type=Path, required=True)
    create_teacher_binding.add_argument("--output", type=Path, required=True)
    create_teacher_binding.add_argument(
        "--api-key-env",
        required=True,
        help="environment variable name; key values are never accepted as arguments",
    )
    create_teacher_binding.add_argument("--timeout-seconds", type=float, default=30.0)
    create_teacher_binding.add_argument(
        "--max-response-bytes", type=int, default=1_000_000
    )

    validate_teacher_binding = subparsers.add_parser(
        "validate-teacher-runtime-binding",
        help="rehash teacher runtime inputs and reprobe the exact loopback vLLM",
    )
    validate_teacher_binding.add_argument("binding", type=Path)
    validate_teacher_binding.add_argument(
        "--api-key-env",
        required=True,
        help="environment variable name; key values are never accepted as arguments",
    )
    validate_teacher_binding.add_argument("--timeout-seconds", type=float, default=30.0)
    validate_teacher_binding.add_argument(
        "--max-response-bytes", type=int, default=1_000_000
    )

    teacher_manifest = subparsers.add_parser(
        "validate-teacher-generation",
        help="validate a development-only teacher generation manifest",
    )
    teacher_manifest.add_argument("--manifest", type=Path, required=True)
    teacher_manifest.add_argument("--catalog", type=Path, required=True)

    teacher_capture = subparsers.add_parser(
        "capture-teacher-candidates",
        help="capture an immutable unreviewed teacher-candidate queue from loopback",
    )
    teacher_capture.add_argument("--manifest", type=Path, required=True)
    teacher_capture.add_argument("--catalog", type=Path, required=True)
    teacher_capture.add_argument("--runtime-binding", type=Path, required=True)
    teacher_capture.add_argument("--output", type=Path, required=True)
    teacher_capture.add_argument("--base-url", required=True)
    teacher_capture.add_argument(
        "--api-key-env",
        required=True,
        help="environment variable name; key values are never accepted as arguments",
    )
    teacher_capture.add_argument("--timeout-seconds", type=float, default=60.0)
    teacher_capture.add_argument(
        "--max-response-bytes", type=int, default=MAX_CAPTURE_RESPONSE_BYTES
    )

    teacher_candidates = subparsers.add_parser(
        "validate-teacher-candidates",
        help="validate an immutable unreviewed teacher-candidate JSONL queue",
    )
    teacher_candidates.add_argument("candidates", type=Path)
    teacher_candidates.add_argument("--manifest", type=Path, required=True)
    teacher_candidates.add_argument("--catalog", type=Path, required=True)

    teacher_deny_set = subparsers.add_parser(
        "create-teacher-overlap-deny-set",
        help="create a hash-only overlap deny set from bound calibration and sealed tasks",
    )
    teacher_deny_set.add_argument("--calibration-tasks", type=Path, required=True)
    teacher_deny_set.add_argument("--sealed-tasks", type=Path, required=True)
    teacher_deny_set.add_argument("--deny-set-id", required=True)
    teacher_deny_set.add_argument("--custodian", required=True)
    teacher_deny_set.add_argument("--created-at-utc", required=True)
    teacher_deny_set.add_argument("--output", type=Path, required=True)

    teacher_selection = subparsers.add_parser(
        "validate-teacher-selection",
        help="validate independent candidate selection and held-out overlap exclusion",
    )
    teacher_selection.add_argument("--selection", type=Path, required=True)

    teacher_materialize = subparsers.add_parser(
        "materialize-teacher-candidates",
        help="materialize selected candidates as an immutable non-training draft package",
    )
    teacher_materialize.add_argument("--selection", type=Path, required=True)
    teacher_materialize.add_argument("--output", type=Path, required=True)

    teacher_materialization = subparsers.add_parser(
        "validate-teacher-materialization",
        help="self-contained rederivation and validation of a teacher draft package",
    )
    teacher_materialization.add_argument("package", type=Path)
    teacher_materialization.add_argument(
        "--selection",
        type=Path,
        help="optional external selection snapshot to cross-check",
    )

    create_teacher_lineage = subparsers.add_parser(
        "create-teacher-lineage-admission",
        help="sign one exact reviewed OpenWeightTeacher materialization lineage",
    )
    create_teacher_lineage.add_argument("--output", type=Path, required=True)
    create_teacher_lineage.add_argument("--materialization", type=Path, required=True)
    create_teacher_lineage.add_argument("--runtime-binding", type=Path, required=True)
    create_teacher_lineage.add_argument("--reviewed-dataset", type=Path, required=True)
    create_teacher_lineage.add_argument("--reviewer-evidence", type=Path, required=True)
    create_teacher_lineage.add_argument("--private-key", type=Path, required=True)
    create_teacher_lineage.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    _add_teacher_lineage_admission_trust_arguments(create_teacher_lineage)
    create_teacher_lineage.add_argument("--reviewer-id", required=True)
    create_teacher_lineage.add_argument("--reviewed-at-utc", required=True)
    create_teacher_lineage.add_argument("--issued-at-utc", required=True)
    create_teacher_lineage.add_argument("--not-before-utc", required=True)
    create_teacher_lineage.add_argument("--expires-at-utc", required=True)

    prepare_teacher_lineage = subparsers.add_parser(
        "prepare-teacher-lineage-admission-signing-bundle",
        help=(
            "prepare a canonical non-authorizing teacher-lineage admission "
            "bundle for an external KMS or HSM"
        ),
    )
    prepare_teacher_lineage.add_argument("--output", type=Path, required=True)
    prepare_teacher_lineage.add_argument("--materialization", type=Path, required=True)
    prepare_teacher_lineage.add_argument("--runtime-binding", type=Path, required=True)
    prepare_teacher_lineage.add_argument("--reviewed-dataset", type=Path, required=True)
    prepare_teacher_lineage.add_argument(
        "--reviewer-evidence", type=Path, required=True
    )
    _add_teacher_lineage_admission_trust_arguments(prepare_teacher_lineage)
    prepare_teacher_lineage.add_argument("--reviewer-id", required=True)
    prepare_teacher_lineage.add_argument("--reviewed-at-utc", required=True)
    prepare_teacher_lineage.add_argument("--issued-at-utc", required=True)
    prepare_teacher_lineage.add_argument("--not-before-utc", required=True)
    prepare_teacher_lineage.add_argument("--expires-at-utc", required=True)

    finalize_teacher_lineage = subparsers.add_parser(
        "finalize-teacher-lineage-admission",
        help=(
            "verify one externally produced signature and publish the unchanged "
            "teacher-lineage admission envelope"
        ),
    )
    finalize_teacher_lineage.add_argument("--signing-bundle", type=Path, required=True)
    finalize_teacher_lineage.add_argument("--signature", type=Path, required=True)
    finalize_teacher_lineage.add_argument("--output", type=Path, required=True)
    finalize_teacher_lineage.add_argument("--materialization", type=Path, required=True)
    finalize_teacher_lineage.add_argument("--runtime-binding", type=Path, required=True)
    finalize_teacher_lineage.add_argument(
        "--reviewed-dataset", type=Path, required=True
    )
    finalize_teacher_lineage.add_argument(
        "--reviewer-evidence", type=Path, required=True
    )
    _add_teacher_lineage_admission_trust_arguments(finalize_teacher_lineage)

    validate_teacher_lineage = subparsers.add_parser(
        "validate-teacher-lineage-admission",
        help="verify one signed admission against the exact materialization and corpus",
    )
    validate_teacher_lineage.add_argument("admission", type=Path)
    validate_teacher_lineage.add_argument("--materialization", type=Path, required=True)
    validate_teacher_lineage.add_argument("--runtime-binding", type=Path, required=True)
    validate_teacher_lineage.add_argument(
        "--reviewed-dataset", type=Path, required=True
    )
    validate_teacher_lineage.add_argument(
        "--reviewer-evidence", type=Path, required=True
    )
    _add_teacher_lineage_admission_trust_arguments(validate_teacher_lineage)

    evidence = subparsers.add_parser(
        "aggregate-promotion-evidence", help="produce unpromoted sealed-set evidence"
    )
    evidence.add_argument("--calibration-tasks", type=Path, required=True)
    evidence.add_argument("--calibration-evidence", type=Path, required=True)
    evidence.add_argument("--sealed-tasks", type=Path, required=True)
    evidence.add_argument("--responses", type=Path, required=True)
    evidence.add_argument("--verifier-results", type=Path, required=True)
    evidence.add_argument("--baseline-responses", type=Path, required=True)
    evidence.add_argument("--baseline-verifier-results", type=Path, required=True)
    evidence.add_argument("--policy", type=Path, required=True)
    evidence.add_argument("--release", type=Path)
    _add_review_receipt_trust_arguments(evidence, required=False)
    _add_evaluation_authoring_approval_trust_arguments(evidence, required=False)
    _add_promotion_attestation_trust_arguments(evidence)
    _add_optional_csharp_verifier_arguments(evidence)
    _add_optional_csharp_verifier_replay_audit_arguments(evidence)
    evidence.add_argument(
        "--research-only-unbound",
        action="store_true",
        help="aggregate explicit unpromoted research evidence without a release",
    )
    evidence.add_argument("--output", type=Path)

    validate_evidence = subparsers.add_parser(
        "validate-promotion-evidence",
        help="strictly validate a deterministic promotion evidence report",
    )
    validate_evidence.add_argument("report", type=Path)

    create_authoring_approval = subparsers.add_parser(
        "create-evaluation-authoring-approval",
        help="sign one exact evaluation-authoring inventory without release authority",
    )
    create_authoring_approval.add_argument("--output", type=Path, required=True)
    create_authoring_approval.add_argument("--private-key", type=Path, required=True)
    create_authoring_approval.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    _add_evaluation_authoring_approval_trust_arguments(
        create_authoring_approval, required=True
    )
    create_authoring_approval.add_argument("--approval-id", required=True)
    create_authoring_approval.add_argument("--actor-id", required=True)
    create_authoring_approval.add_argument("--actor-role", required=True)
    create_authoring_approval.add_argument("--approval-reference", required=True)
    create_authoring_approval.add_argument("--approved-at-utc", required=True)
    create_authoring_approval.add_argument("--issued-at-utc", required=True)
    create_authoring_approval.add_argument("--not-before-utc", required=True)
    create_authoring_approval.add_argument("--expires-at-utc", required=True)
    _add_evaluation_authoring_inventory_arguments(create_authoring_approval)

    prepare_authoring_approval = subparsers.add_parser(
        "prepare-evaluation-authoring-approval-signing-bundle",
        help=(
            "prepare a canonical non-authorizing evaluation-authoring approval "
            "bundle for an external KMS or HSM"
        ),
    )
    prepare_authoring_approval.add_argument("--output", type=Path, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        prepare_authoring_approval, required=True
    )
    prepare_authoring_approval.add_argument("--approval-id", required=True)
    prepare_authoring_approval.add_argument("--actor-id", required=True)
    prepare_authoring_approval.add_argument("--actor-role", required=True)
    prepare_authoring_approval.add_argument("--approval-reference", required=True)
    prepare_authoring_approval.add_argument("--approved-at-utc", required=True)
    prepare_authoring_approval.add_argument("--issued-at-utc", required=True)
    prepare_authoring_approval.add_argument("--not-before-utc", required=True)
    prepare_authoring_approval.add_argument("--expires-at-utc", required=True)
    _add_evaluation_authoring_inventory_arguments(prepare_authoring_approval)

    finalize_authoring_approval = subparsers.add_parser(
        "finalize-evaluation-authoring-approval",
        help=(
            "verify one externally produced signature and publish the unchanged "
            "evaluation-authoring approval envelope"
        ),
    )
    finalize_authoring_approval.add_argument(
        "--signing-bundle", type=Path, required=True
    )
    finalize_authoring_approval.add_argument("--signature", type=Path, required=True)
    finalize_authoring_approval.add_argument("--output", type=Path, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        finalize_authoring_approval, required=True
    )
    _add_evaluation_authoring_inventory_arguments(finalize_authoring_approval)

    validate_authoring_approval = subparsers.add_parser(
        "validate-evaluation-authoring-approval",
        help="verify a signed approval against one exact live authoring inventory",
    )
    validate_authoring_approval.add_argument("approval", type=Path)
    validate_authoring_approval.add_argument(
        "--expected-evaluation-authoring-approval-envelope-sha256",
        required=True,
    )
    _add_evaluation_authoring_approval_trust_arguments(
        validate_authoring_approval, required=True
    )
    _add_evaluation_authoring_inventory_arguments(validate_authoring_approval)

    create_release = subparsers.add_parser(
        "create-release",
        help="freeze a rights-reviewed corpus, evaluation tasks, rubrics, and verifier assets",
    )
    create_release.add_argument("--corpus", type=Path, required=True)
    create_release.add_argument("--review-receipts", type=Path, required=True)
    create_release.add_argument("--teacher-lineage-admission", type=Path)
    _add_review_receipt_trust_arguments(create_release, required=True)
    _add_evaluation_authoring_approval_trust_arguments(create_release, required=True)
    create_release.add_argument("--sft", type=Path)
    create_release.add_argument("--calibration-tasks", type=Path, required=True)
    create_release.add_argument("--sealed-tasks", type=Path, required=True)
    create_release.add_argument("--task-bindings", type=Path, required=True)
    create_release.add_argument(
        "--evaluation-authoring-approval", type=Path, required=True
    )
    create_release.add_argument(
        "--expected-evaluation-authoring-approval-envelope-sha256",
        required=True,
    )
    create_release.add_argument("--approval-evidence", type=Path, required=True)
    create_release.add_argument("--output-root", type=Path, required=True)
    create_release.add_argument(
        "--purpose", choices=tuple(sorted(PURPOSES)), required=True
    )
    create_release.add_argument("--cutoff-utc", required=True)
    create_release.add_argument("--approval-id", required=True)
    create_release.add_argument("--reviewer-id", required=True)
    create_release.add_argument("--approved-at-utc", required=True)

    validate_release = subparsers.add_parser(
        "validate-release",
        help="validate an immutable rights-reviewed corpus/evaluation release bundle",
    )
    validate_release.add_argument("release", type=Path)
    _add_review_receipt_trust_arguments(validate_release, required=True)
    _add_evaluation_authoring_approval_trust_arguments(validate_release, required=True)

    create_receipts = subparsers.add_parser(
        "create-review-receipts",
        help="validate a corpus and issue one signed review receipt per row",
    )
    create_receipts.add_argument("--dataset", type=Path, required=True)
    create_receipts.add_argument("--output", type=Path, required=True)
    create_receipts.add_argument("--private-key", type=Path, required=True)
    create_receipts.add_argument("--public-key", type=Path, required=True)
    create_receipts.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    create_receipts.add_argument("--audience", required=True)
    create_receipts.add_argument("--key-id", required=True)
    create_receipts.add_argument("--signer-role", required=True)
    create_receipts.add_argument("--approval-id", required=True)
    create_receipts.add_argument("--actor-id", required=True)
    create_receipts.add_argument("--actor-role", required=True)
    create_receipts.add_argument("--approval-reference", required=True)
    create_receipts.add_argument("--approval-evidence", type=Path, required=True)
    create_receipts.add_argument("--approved-at-utc", required=True)
    create_receipts.add_argument("--issued-at-utc", required=True)
    create_receipts.add_argument("--not-before-utc", required=True)
    create_receipts.add_argument("--expires-at-utc", required=True)
    create_receipts.add_argument("--teacher-lineage-admission", type=Path)
    create_receipts.add_argument("--teacher-materialization", type=Path)
    create_receipts.add_argument("--teacher-runtime-binding", type=Path)
    create_receipts.add_argument("--teacher-lineage-reviewer-evidence", type=Path)
    _add_teacher_lineage_admission_trust_arguments(create_receipts)

    prepare_receipt_signing = subparsers.add_parser(
        "prepare-review-receipt-signing-bundle",
        help=(
            "prepare a canonical non-authorizing review-receipt bundle for an "
            "external KMS or HSM"
        ),
    )
    prepare_receipt_signing.add_argument("--dataset", type=Path, required=True)
    prepare_receipt_signing.add_argument("--output", type=Path, required=True)
    prepare_receipt_signing.add_argument("--public-key", type=Path, required=True)
    prepare_receipt_signing.add_argument("--audience", required=True)
    prepare_receipt_signing.add_argument("--key-id", required=True)
    prepare_receipt_signing.add_argument("--signer-role", required=True)
    prepare_receipt_signing.add_argument("--approval-id", required=True)
    prepare_receipt_signing.add_argument("--actor-id", required=True)
    prepare_receipt_signing.add_argument("--actor-role", required=True)
    prepare_receipt_signing.add_argument("--approval-reference", required=True)
    prepare_receipt_signing.add_argument(
        "--approval-evidence", type=Path, required=True
    )
    prepare_receipt_signing.add_argument("--approved-at-utc", required=True)
    prepare_receipt_signing.add_argument("--issued-at-utc", required=True)
    prepare_receipt_signing.add_argument("--not-before-utc", required=True)
    prepare_receipt_signing.add_argument("--expires-at-utc", required=True)
    prepare_receipt_signing.add_argument("--teacher-lineage-admission", type=Path)
    prepare_receipt_signing.add_argument("--teacher-materialization", type=Path)
    prepare_receipt_signing.add_argument("--teacher-runtime-binding", type=Path)
    prepare_receipt_signing.add_argument(
        "--teacher-lineage-reviewer-evidence", type=Path
    )
    _add_teacher_lineage_admission_trust_arguments(prepare_receipt_signing)

    finalize_receipts = subparsers.add_parser(
        "finalize-review-receipts",
        help=(
            "verify externally produced signatures and publish canonical review "
            "receipts"
        ),
    )
    finalize_receipts.add_argument("--dataset", type=Path, required=True)
    finalize_receipts.add_argument("--signing-bundle", type=Path, required=True)
    finalize_receipts.add_argument("--signature-set", type=Path, required=True)
    finalize_receipts.add_argument("--output", type=Path, required=True)
    finalize_receipts.add_argument("--public-key", type=Path, required=True)
    finalize_receipts.add_argument("--expected-public-key-spki-sha256", required=True)
    finalize_receipts.add_argument("--expected-audience", required=True)
    finalize_receipts.add_argument("--expected-key-id", required=True)
    finalize_receipts.add_argument("--expected-signer-role", required=True)
    finalize_receipts.add_argument("--approval-evidence", type=Path, required=True)
    finalize_receipts.add_argument("--teacher-lineage-admission", type=Path)
    finalize_receipts.add_argument("--teacher-materialization", type=Path)
    finalize_receipts.add_argument("--teacher-runtime-binding", type=Path)
    finalize_receipts.add_argument("--teacher-lineage-reviewer-evidence", type=Path)
    _add_teacher_lineage_admission_trust_arguments(finalize_receipts)

    validate_receipts = subparsers.add_parser(
        "validate-review-receipts",
        help="verify canonical detached review receipts against an exact corpus",
    )
    validate_receipts.add_argument("receipts", type=Path)
    validate_receipts.add_argument("--dataset", type=Path, required=True)
    validate_receipts.add_argument("--public-key", type=Path, required=True)
    validate_receipts.add_argument("--expected-public-key-spki-sha256", required=True)
    validate_receipts.add_argument("--expected-audience", required=True)
    validate_receipts.add_argument("--expected-key-id", required=True)
    validate_receipts.add_argument("--expected-signer-role", required=True)
    validate_receipts.add_argument("--teacher-lineage-admission", type=Path)
    validate_receipts.add_argument("--teacher-materialization", type=Path)
    validate_receipts.add_argument("--teacher-runtime-binding", type=Path)
    validate_receipts.add_argument("--teacher-lineage-reviewer-evidence", type=Path)
    _add_teacher_lineage_admission_trust_arguments(validate_receipts)

    create_base_selection = subparsers.add_parser(
        "create-base-model-selection",
        help=(
            "replay a catalog-complete attested raw-base bake-off and sign the exact "
            "approved training snapshot"
        ),
    )
    create_base_selection.add_argument("--output", type=Path, required=True)
    create_base_selection.add_argument("--private-key", type=Path, required=True)
    create_base_selection.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    _add_base_selection_trust_arguments(create_base_selection, required=True)
    create_base_selection.add_argument("--approval-id", required=True)
    create_base_selection.add_argument("--actor-id", required=True)
    create_base_selection.add_argument("--actor-role", required=True)
    create_base_selection.add_argument("--approval-reference", required=True)
    create_base_selection.add_argument("--approved-at-utc", required=True)
    create_base_selection.add_argument("--issued-at-utc", required=True)
    create_base_selection.add_argument("--not-before-utc", required=True)
    create_base_selection.add_argument("--expires-at-utc", required=True)
    _add_base_selection_source_arguments(create_base_selection)
    _add_review_receipt_trust_arguments(create_base_selection, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        create_base_selection, required=True
    )
    _add_promotion_attestation_trust_arguments(
        create_base_selection, candidate_required=True, baseline_required=True
    )
    _add_optional_csharp_verifier_arguments(create_base_selection)

    prepare_base_selection = subparsers.add_parser(
        "prepare-base-model-selection-signing-bundle",
        help=(
            "replay a catalog-complete bake-off and emit a non-authorizing "
            "provider-neutral selection signing request"
        ),
    )
    prepare_base_selection.add_argument("--output", type=Path, required=True)
    _add_base_selection_trust_arguments(prepare_base_selection, required=True)
    prepare_base_selection.add_argument("--approval-id", required=True)
    prepare_base_selection.add_argument("--actor-id", required=True)
    prepare_base_selection.add_argument("--actor-role", required=True)
    prepare_base_selection.add_argument("--approval-reference", required=True)
    prepare_base_selection.add_argument("--approved-at-utc", required=True)
    prepare_base_selection.add_argument("--issued-at-utc", required=True)
    prepare_base_selection.add_argument("--not-before-utc", required=True)
    prepare_base_selection.add_argument("--expires-at-utc", required=True)
    _add_base_selection_source_arguments(prepare_base_selection)
    _add_review_receipt_trust_arguments(prepare_base_selection, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        prepare_base_selection, required=True
    )
    _add_promotion_attestation_trust_arguments(
        prepare_base_selection, candidate_required=True, baseline_required=True
    )
    _add_optional_csharp_verifier_arguments(prepare_base_selection)

    finalize_base_selection = subparsers.add_parser(
        "finalize-base-model-selection",
        help=(
            "verify an externally produced selection signature, replay every live "
            "binding, and publish the existing selection-v2 envelope"
        ),
    )
    finalize_base_selection.add_argument("--signing-bundle", type=Path, required=True)
    finalize_base_selection.add_argument("--signature", type=Path, required=True)
    finalize_base_selection.add_argument("--output", type=Path, required=True)
    _add_base_selection_trust_arguments(finalize_base_selection, required=True)
    _add_base_selection_source_arguments(finalize_base_selection)
    _add_review_receipt_trust_arguments(finalize_base_selection, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        finalize_base_selection, required=True
    )
    _add_promotion_attestation_trust_arguments(
        finalize_base_selection, candidate_required=True, baseline_required=True
    )
    _add_optional_csharp_verifier_arguments(finalize_base_selection)

    validate_base_selection = subparsers.add_parser(
        "validate-base-model-selection",
        help=(
            "verify a signed base choice and freshly replay every catalog student "
            "evidence/snapshot binding"
        ),
    )
    validate_base_selection.add_argument("selection", type=Path)
    _add_base_selection_trust_arguments(validate_base_selection, required=True)
    _add_base_selection_source_arguments(validate_base_selection)
    _add_review_receipt_trust_arguments(validate_base_selection, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        validate_base_selection, required=True
    )
    _add_promotion_attestation_trust_arguments(
        validate_base_selection, candidate_required=True, baseline_required=True
    )
    _add_optional_csharp_verifier_arguments(validate_base_selection)

    create_promotion = subparsers.add_parser(
        "create-model-promotion",
        help="reaggregate evidence, bind deployment inputs, and sign a production promotion",
    )
    create_promotion.add_argument("--output", type=Path, required=True)
    create_promotion.add_argument("--private-key", type=Path, required=True)
    create_promotion.add_argument("--public-key", type=Path, required=True)
    create_promotion.add_argument(
        "--private-key-password-env",
        help="environment variable name; password values are never accepted as arguments",
    )
    create_promotion.add_argument("--audience", required=True)
    create_promotion.add_argument("--key-id", required=True)
    create_promotion.add_argument("--signer-role", required=True)
    create_promotion.add_argument("--deployment-id", required=True)
    create_promotion.add_argument("--environment", required=True)
    create_promotion.add_argument("--approval-id", required=True)
    create_promotion.add_argument("--actor-id", required=True)
    create_promotion.add_argument("--actor-role", required=True)
    create_promotion.add_argument("--approval-reference", required=True)
    create_promotion.add_argument("--approved-at-utc", required=True)
    create_promotion.add_argument("--issued-at-utc", required=True)
    create_promotion.add_argument("--not-before-utc", required=True)
    create_promotion.add_argument("--expires-at-utc", required=True)
    _add_promotion_source_arguments(create_promotion)
    _add_review_receipt_trust_arguments(create_promotion, required=True)
    _add_evaluation_authoring_approval_trust_arguments(create_promotion, required=True)
    _add_trainer_provenance_trust_arguments(create_promotion, required=True)
    _add_base_selection_trust_arguments(create_promotion, required=True)
    _add_promotion_attestation_trust_arguments(create_promotion)
    _add_optional_csharp_verifier_replay_audit_arguments(create_promotion)

    prepare_promotion = subparsers.add_parser(
        "prepare-model-promotion-signing-bundle",
        help=(
            "reaggregate every live promotion binding and emit a non-authorizing "
            "detached-signing bundle"
        ),
    )
    prepare_promotion.add_argument("--output", type=Path, required=True)
    prepare_promotion.add_argument("--public-key", type=Path, required=True)
    prepare_promotion.add_argument("--audience", required=True)
    prepare_promotion.add_argument("--key-id", required=True)
    prepare_promotion.add_argument("--signer-role", required=True)
    prepare_promotion.add_argument("--deployment-id", required=True)
    prepare_promotion.add_argument("--environment", required=True)
    prepare_promotion.add_argument("--approval-id", required=True)
    prepare_promotion.add_argument("--actor-id", required=True)
    prepare_promotion.add_argument("--actor-role", required=True)
    prepare_promotion.add_argument("--approval-reference", required=True)
    prepare_promotion.add_argument("--approved-at-utc", required=True)
    prepare_promotion.add_argument("--issued-at-utc", required=True)
    prepare_promotion.add_argument("--not-before-utc", required=True)
    prepare_promotion.add_argument("--expires-at-utc", required=True)
    _add_promotion_source_arguments(prepare_promotion)
    _add_review_receipt_trust_arguments(prepare_promotion, required=True)
    _add_evaluation_authoring_approval_trust_arguments(prepare_promotion, required=True)
    _add_trainer_provenance_trust_arguments(prepare_promotion, required=True)
    _add_base_selection_trust_arguments(prepare_promotion, required=True)
    _add_promotion_attestation_trust_arguments(prepare_promotion)
    _add_optional_csharp_verifier_replay_audit_arguments(prepare_promotion)

    finalize_promotion = subparsers.add_parser(
        "finalize-model-promotion",
        help=(
            "verify an external promotion signature, replay every live binding, "
            "and publish the existing promotion-v1 envelope"
        ),
    )
    finalize_promotion.add_argument("--signing-bundle", type=Path, required=True)
    finalize_promotion.add_argument("--signature", type=Path, required=True)
    finalize_promotion.add_argument("--output", type=Path, required=True)
    finalize_promotion.add_argument("--public-key", type=Path, required=True)
    finalize_promotion.add_argument("--expected-audience", required=True)
    finalize_promotion.add_argument("--expected-key-id", required=True)
    finalize_promotion.add_argument("--expected-signer-role", required=True)
    finalize_promotion.add_argument("--expected-deployment-id", required=True)
    finalize_promotion.add_argument("--expected-environment", required=True)
    _add_promotion_source_arguments(finalize_promotion)
    _add_review_receipt_trust_arguments(finalize_promotion, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        finalize_promotion, required=True
    )
    _add_trainer_provenance_trust_arguments(finalize_promotion, required=True)
    _add_base_selection_trust_arguments(finalize_promotion, required=True)
    _add_promotion_attestation_trust_arguments(finalize_promotion)
    _add_optional_csharp_verifier_replay_audit_arguments(finalize_promotion)

    validate_promotion = subparsers.add_parser(
        "validate-model-promotion",
        help="verify a signed promotion and every live evidence/model binding",
    )
    validate_promotion.add_argument("promotion", type=Path)
    validate_promotion.add_argument("--public-key", type=Path, required=True)
    validate_promotion.add_argument("--expected-audience", required=True)
    validate_promotion.add_argument("--expected-key-id", required=True)
    validate_promotion.add_argument("--expected-signer-role", required=True)
    validate_promotion.add_argument("--expected-deployment-id", required=True)
    validate_promotion.add_argument("--expected-environment", required=True)
    _add_promotion_source_arguments(validate_promotion)
    _add_review_receipt_trust_arguments(validate_promotion, required=True)
    _add_evaluation_authoring_approval_trust_arguments(
        validate_promotion, required=True
    )
    _add_trainer_provenance_trust_arguments(validate_promotion, required=True)
    _add_base_selection_trust_arguments(validate_promotion, required=True)
    _add_promotion_attestation_trust_arguments(validate_promotion)
    _add_optional_csharp_verifier_replay_audit_arguments(validate_promotion)

    readiness_v2 = subparsers.add_parser(
        "create-model-readiness-v2",
        help="fully revalidate one signed promotion and emit its bound readiness proof",
    )
    readiness_v2.add_argument("promotion", type=Path)
    readiness_v2.add_argument("--public-key", type=Path, required=True)
    readiness_v2.add_argument("--expected-audience", required=True)
    readiness_v2.add_argument("--expected-promotion-key-id", required=True)
    readiness_v2.add_argument("--expected-signer-role", required=True)
    readiness_v2.add_argument("--expected-deployment-id", required=True)
    readiness_v2.add_argument("--expected-environment", required=True)
    readiness_v2.add_argument("--nonce", required=True)
    readiness_v2.add_argument("--readiness-key-id", required=True)
    readiness_v2.add_argument(
        "--hmac-key-env",
        required=True,
        help="environment variable containing a canonical base64url key; values are never arguments",
    )
    _add_promotion_source_arguments(readiness_v2)
    _add_review_receipt_trust_arguments(readiness_v2, required=True)
    _add_evaluation_authoring_approval_trust_arguments(readiness_v2, required=True)
    _add_trainer_provenance_trust_arguments(readiness_v2, required=True)
    _add_base_selection_trust_arguments(readiness_v2, required=True)
    _add_promotion_attestation_trust_arguments(readiness_v2)
    _add_optional_csharp_verifier_replay_audit_arguments(readiness_v2)

    serve_promoted = subparsers.add_parser(
        "serve-promoted-model",
        help="own a promoted vLLM child and expose an authenticated fail-closed gateway",
    )
    serve_promoted.add_argument("config", type=Path)
    return parser


def _create(args: argparse.Namespace) -> dict[str, Any]:
    parameters = default_hyperparameters()
    parameters.update(
        {
            "numTrainEpochs": args.epochs,
            "learningRate": args.learning_rate,
            "perDeviceTrainBatchSize": args.batch_size,
            "gradientAccumulationSteps": args.gradient_accumulation_steps,
            "maxSequenceLength": args.max_sequence_length,
            "warmupRatio": args.warmup_ratio,
            "weightDecay": args.weight_decay,
            "loraR": args.lora_r,
            "loraAlpha": args.lora_alpha,
            "loraDropout": args.lora_dropout,
        }
    )
    if args.lora_modules:
        parameters["loraTargetModules"] = args.lora_modules
    return create_bundle(
        catalog_path=args.catalog,
        sft_path=args.sft,
        candidate_id=args.candidate_id,
        chat_template_path=args.chat_template_file,
        chat_template_name=args.chat_template_name,
        output_directory=args.output,
        runtime_profile_path=args.runtime_profile,
        data_release_path=args.release,
        review_receipt_trust=_review_receipt_trust(args),
        evaluation_authoring_approval_trust=(
            _evaluation_authoring_approval_trust(args)
        ),
        base_selection_path=args.base_selection,
        base_selection_trust=_base_selection_trust(args),
        base_evaluation_profile_path=args.base_evaluation_profile,
        base_model_snapshot_manifest_path=args.base_model_snapshot_manifest,
        base_model_snapshot_path=args.base_model_snapshot,
        base_model_source_lock_path=args.base_model_source_lock,
        corpus_admission_path=args.corpus_admission,
        corpus_admission_trust=_corpus_admission_trust(args),
        seed=args.seed,
        hyperparameters=parameters,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-catalog":
            catalog = validate_candidate_catalog(args.catalog)
            _print(
                {
                    "valid": True,
                    "schemaVersion": catalog["schemaVersion"],
                    "candidateCount": len(catalog["candidates"]),
                    "sha256": sha256_file(args.catalog, max_bytes=MAX_JSON_BYTES),
                }
            )
        elif args.command == "validate-sft":
            summary = validate_sft(args.sft)
            _print({"valid": True, **summary.as_dict()})
        elif args.command == "summarize-coverage":
            _print(summarize_sft(args.sft))
        elif args.command == "summarize-corpus-quality":
            _print(derive_training_corpus_quality_report(args.sft))
        elif args.command == "validate-corpus-quality-policy":
            policy = validate_training_corpus_quality_policy(
                load_json_document(args.policy)
            )
            _print(
                {
                    "valid": True,
                    "schemaVersion": policy["schemaVersion"],
                    "policyVersion": policy["policyVersion"],
                    "qualityPolicySha256": training_corpus_quality_policy_sha256(
                        policy
                    ),
                }
            )
        elif args.command in {
            "create-training-corpus-admission",
            "prepare-training-corpus-admission-signing-bundle",
            "finalize-training-corpus-admission",
            "validate-training-corpus-admission",
        }:
            review_trust = _review_receipt_trust(args)
            authoring_trust = _evaluation_authoring_approval_trust(args)
            corpus_trust = _corpus_admission_trust(args)
            if (
                review_trust is None or authoring_trust is None or corpus_trust is None
            ):  # pragma: no cover - argparse requires every trust value
                raise ValidationError(
                    "training corpus admission: complete external trust is required"
                )
            _require_corpus_admission_signer_separation(
                corpus_trust, review_trust, authoring_trust
            )
            dataset_bytes = _read_file_bounded(
                args.sft, "training corpus admission dataset", MAX_SFT_BYTES
            )
            release_identity = _training_release_identity_for_sft(
                sft_sha256=hashlib.sha256(dataset_bytes).hexdigest(),
                release_path=args.release,
                review_receipt_trust=review_trust,
                evaluation_authoring_approval_trust=authoring_trust,
            )
            if args.command == "create-training-corpus-admission":
                verified = create_training_corpus_admission_bytes(
                    dataset_bytes=dataset_bytes,
                    dataset_source_path=args.sft,
                    data_release=release_identity,
                    quality_policy=load_json_document(args.quality_policy),
                    private_key_path=args.private_key,
                    private_key_password=_private_key_password(
                        args.private_key_password_env
                    ),
                    trust=corpus_trust,
                    reviewer_id=args.reviewer_id,
                    reviewed_at_utc=args.reviewed_at_utc,
                    issued_at_utc=args.issued_at_utc,
                    not_before_utc=args.not_before_utc,
                    expires_at_utc=args.expires_at_utc,
                    output_path=args.output,
                )
                _print(
                    {
                        "created": True,
                        **verified.as_dict(),
                        "outputPath": str(args.output),
                    }
                )
            elif args.command == "prepare-training-corpus-admission-signing-bundle":
                verified_bundle = (
                    prepare_training_corpus_admission_signing_bundle_bytes(
                        dataset_bytes=dataset_bytes,
                        dataset_source_path=args.sft,
                        data_release=release_identity,
                        quality_policy=load_json_document(args.quality_policy),
                        trust=corpus_trust,
                        reviewer_id=args.reviewer_id,
                        reviewed_at_utc=args.reviewed_at_utc,
                        issued_at_utc=args.issued_at_utc,
                        not_before_utc=args.not_before_utc,
                        expires_at_utc=args.expires_at_utc,
                        output_path=args.output,
                    )
                )
                _print(
                    {
                        "prepared": True,
                        **verified_bundle.as_dict(),
                        "outputPath": str(args.output),
                    }
                )
            elif args.command == "finalize-training-corpus-admission":
                verified = finalize_training_corpus_admission_bytes(
                    signing_bundle_path=args.signing_bundle,
                    signature_path=args.signature,
                    output_path=args.output,
                    dataset_bytes=dataset_bytes,
                    dataset_source_path=args.sft,
                    data_release=release_identity,
                    quality_policy=load_json_document(args.quality_policy),
                    trust=corpus_trust,
                )
                _print(
                    {
                        "finalized": True,
                        **verified.as_dict(),
                        "outputPath": str(args.output),
                    }
                )
            else:
                verified = verify_training_corpus_admission_file(
                    args.admission,
                    dataset_bytes=dataset_bytes,
                    dataset_source_path=args.sft,
                    expected_data_release=release_identity,
                    trust=corpus_trust,
                )
                _print({"valid": True, **verified.as_dict()})
        elif args.command == "validate-manifest":
            manifest = validate_manifest_path(args.manifest)
            _print(
                {
                    "valid": True,
                    "runId": manifest["runId"],
                    "sha256": sha256_file(args.manifest, max_bytes=MAX_JSON_BYTES),
                }
            )
        elif args.command == "validate-bundle":
            _print({"valid": True, **validate_bundle(args.bundle)})
        elif args.command == "create-bundle":
            _print(_create(args))
        elif args.command == "train":
            _print(
                train_from_manifest(
                    args.manifest,
                    minimum_gpu_memory_gib=args.minimum_gpu_memory_gib,
                    smoke=args.smoke,
                    data_release_path=args.release,
                    review_receipt_trust=_review_receipt_trust(args),
                    evaluation_authoring_approval_trust=(
                        _evaluation_authoring_approval_trust(args)
                    ),
                    base_model_snapshot_path=args.base_model_snapshot,
                    base_selection_trust=_base_selection_trust(args),
                    corpus_admission_trust=_corpus_admission_trust(args),
                    trainer_provenance_trust=_trainer_provenance_trust(args),
                    trainer_private_key_path=args.trainer_private_key,
                    trainer_private_key_password=_private_key_password(
                        args.trainer_private_key_password_env
                    ),
                    trainer_provenance_handoff_path=(args.trainer_provenance_handoff),
                    trainer_id=args.trainer_id,
                    trainer_expires_at_utc=args.trainer_expires_at_utc,
                )
            )
        elif args.command == "finalize-training-artifact":
            _print(
                finalize_training_artifact_from_handoff(
                    args.manifest,
                    args.handoff,
                    args.signature,
                    data_release_path=args.release,
                    review_receipt_trust=_review_receipt_trust(args),
                    evaluation_authoring_approval_trust=(
                        _evaluation_authoring_approval_trust(args)
                    ),
                    base_model_snapshot_path=args.base_model_snapshot,
                    base_selection_trust=_base_selection_trust(args),
                    corpus_admission_trust=_corpus_admission_trust(args),
                    trainer_provenance_trust=_trainer_provenance_trust(args),
                )
            )
        elif args.command == "validate-artifact":
            artifact = validate_training_artifact(
                args.artifact,
                trainer_provenance_trust=_trainer_provenance_trust(args),
            )
            _print(
                {
                    "valid": True,
                    "runId": artifact["runId"],
                    "artifactSha256": artifact["artifactSha256"],
                    "fileTreeSha256": artifact["fileTreeSha256"],
                    "fileCount": len(artifact["files"]),
                }
            )
        elif args.command == "validate-serving-profile":
            profile = validate_serving_profile(
                args.profile,
                artifact_path=args.artifact,
                manifest_path=args.manifest,
                trainer_provenance_trust=_trainer_provenance_trust(args),
            )
            _print(
                {
                    "valid": True,
                    "profileId": profile.document["profileId"],
                    "sha256": profile.sha256,
                    "executionModelId": profile.execution_model_id,
                }
            )
        elif args.command == "create-serving-profile":
            profile = create_serving_profile(
                profile_id=args.profile_id,
                artifact_path=args.artifact,
                manifest_path=args.manifest,
                output_path=args.output,
                engine=args.engine,
                engine_version=args.engine_version,
                container_image_digest=args.container_image_digest,
                quantization=args.quantization,
                compute_dtype=args.compute_dtype,
                max_model_length=args.max_model_length,
                tensor_parallel_size=args.tensor_parallel_size,
                gpu_profile=args.gpu_profile,
                trainer_provenance_trust=_trainer_provenance_trust(args),
            )
            _print(
                {
                    "created": True,
                    "profileId": profile.document["profileId"],
                    "sha256": profile.sha256,
                    "executionModelId": profile.execution_model_id,
                    "outputPath": str(profile.path),
                }
            )
        elif args.command == "seal-base-model-snapshot":
            snapshot = seal_base_model_snapshot(
                snapshot_path=args.snapshot,
                catalog_path=args.catalog,
                source_lock_path=args.source_lock,
                candidate_id=args.candidate_id,
                output_path=args.output,
            )
            _print(
                {
                    "created": True,
                    "candidateId": snapshot.document["candidateId"],
                    "snapshotSha256": snapshot.document["snapshotSha256"],
                    "fileTreeSha256": snapshot.document["fileTreeSha256"],
                    "manifestSha256": snapshot.manifest_sha256,
                    "fileCount": len(snapshot.document["files"]),
                    "outputPath": str(snapshot.manifest_path),
                }
            )
        elif args.command == "validate-base-model-snapshot":
            snapshot = validate_base_model_snapshot(
                manifest_path=args.manifest,
                snapshot_path=args.snapshot,
                catalog_path=args.catalog,
                source_lock_path=args.source_lock,
            )
            _print(
                {
                    "valid": True,
                    "candidateId": snapshot.document["candidateId"],
                    "snapshotSha256": snapshot.document["snapshotSha256"],
                    "fileTreeSha256": snapshot.document["fileTreeSha256"],
                    "manifestSha256": snapshot.manifest_sha256,
                    "fileCount": len(snapshot.document["files"]),
                }
            )
        elif args.command == "create-base-evaluation-profile":
            profile = create_base_evaluation_profile(
                profile_id=args.profile_id,
                catalog_path=args.catalog,
                source_lock_path=args.source_lock,
                snapshot_manifest_path=args.snapshot_manifest,
                snapshot_path=args.snapshot,
                output_path=args.output,
                engine_version=args.engine_version,
                container_image_digest=args.container_image_digest,
                quantization=args.quantization,
                compute_dtype=args.compute_dtype,
                max_model_length=args.max_model_length,
                tensor_parallel_size=args.tensor_parallel_size,
                gpu_profile=args.gpu_profile,
            )
            _print(
                {
                    "created": True,
                    "profileId": profile.document["profileId"],
                    "sha256": profile.sha256,
                    "executionModelId": profile.execution_model_id,
                    "outputPath": str(profile.path),
                }
            )
        elif args.command == "validate-base-evaluation-profile":
            profile = validate_base_evaluation_profile(
                profile_path=args.profile,
                snapshot_manifest_path=args.snapshot_manifest,
                snapshot_path=args.snapshot,
                catalog_path=args.catalog,
                source_lock_path=args.source_lock,
            )
            _print(
                {
                    "valid": True,
                    "profileId": profile.document["profileId"],
                    "sha256": profile.sha256,
                    "executionModelId": profile.execution_model_id,
                }
            )
        elif args.command == "base-evaluation-launch":
            _print(
                build_base_evaluation_vllm_launch(
                    profile_path=args.profile,
                    snapshot_manifest_path=args.snapshot_manifest,
                    snapshot_path=args.snapshot,
                    catalog_path=args.catalog,
                    source_lock_path=args.source_lock,
                    executable_path=args.executable,
                    port=args.port,
                )
            )
        elif args.command == "create-base-engine-activation":
            activation = create_base_engine_activation(
                config_path=args.config,
                output_path=args.output,
                private_key_path=args.private_key,
                public_key_path=args.public_key,
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=args.audience,
                key_id=args.key_id,
                signer_role=args.signer_role,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
            )
            _print(
                {
                    "created": True,
                    "activationId": activation.payload["activationId"],
                    "payloadSha256": activation.payload_sha256,
                    "envelopeSha256": activation.envelope_sha256,
                    "outputPath": str(activation.path),
                }
            )
        elif args.command == "prepare-base-engine-activation-signing-bundle":
            verified_bundle = prepare_base_engine_activation_signing_bundle(
                config_path=args.config,
                output_path=args.output,
                public_key_path=args.public_key,
                audience=args.audience,
                key_id=args.key_id,
                signer_role=args.signer_role,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
            )
            _print(
                {
                    "created": True,
                    "bundleId": verified_bundle.bundle_id,
                    "bundleSha256": verified_bundle.bundle_sha256,
                    "activationId": verified_bundle.payload["activationId"],
                    "payloadSha256": verified_bundle.payload_sha256,
                    "signatureInputSha256": (verified_bundle.signature_input_sha256),
                    "outputPath": str(verified_bundle.path),
                }
            )
        elif args.command == "finalize-base-engine-activation":
            activation = finalize_base_engine_activation(
                config_path=args.config,
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                public_key_path=args.public_key,
                expected_audience=args.expected_audience,
                expected_key_id=args.expected_key_id,
                expected_signer_role=args.expected_signer_role,
            )
            _print(
                {
                    "created": True,
                    "activationId": activation.payload["activationId"],
                    "payloadSha256": activation.payload_sha256,
                    "envelopeSha256": activation.envelope_sha256,
                    "outputPath": str(activation.path),
                }
            )
        elif args.command == "validate-base-engine-activation":
            config = load_base_engine_wrapper_config(args.config)
            activation = verify_base_engine_activation(
                activation_path=config.activation.path,
                config=config,
                trust=config.activation.trust,
                now=datetime.now(timezone.utc),
            )
            _print(
                {
                    "valid": True,
                    "activationId": activation.payload["activationId"],
                    "payloadSha256": activation.payload_sha256,
                    "envelopeSha256": activation.envelope_sha256,
                }
            )
        elif args.command == "serve-base-evaluation-model":
            serve_base_evaluation_model(args.config)
        elif args.command == "compile-draft-calibration-tasks":
            tasks = compile_draft_calibration_tasks(args.manifest, args.output)
            _print(
                {
                    "created": True,
                    "outputPath": str(tasks.path),
                    **tasks.coverage(),
                }
            )
        elif args.command == "compile-evaluation-authoring-handoff":
            handoff = compile_evaluation_authoring_handoff(
                args.manifest,
                source_dataset_path=args.source_dataset,
                output_directory=args.output_directory,
            )
            _print(
                {
                    "created": True,
                    "handoffPath": str(handoff.path),
                    **handoff.as_dict(),
                }
            )
        elif args.command == "validate-evaluation-authoring-handoff":
            handoff = validate_evaluation_authoring_handoff(
                args.handoff,
                source_dataset_path=args.source_dataset,
            )
            _print({"valid": True, **handoff.as_dict()})
        elif args.command == "validate-eval-tasks":
            tasks = validate_evaluation_tasks(args.tasks)
            _print({"valid": True, **tasks.coverage()})
        elif args.command == "summarize-eval-coverage":
            _print(summarize_evaluation_coverage(args.tasks))
        elif args.command == "validate-responses":
            tasks = validate_evaluation_tasks(args.tasks)
            records = validate_evaluation_responses(args.responses, tasks)
            _print(
                {
                    "valid": True,
                    "recordCount": len(records),
                    "taskSetSha256": tasks.task_set_sha256,
                    "responseSetSha256": evaluation_response_set_sha256(records),
                }
            )
        elif args.command == "validate-attested-base-responses":
            tasks = validate_evaluation_tasks(args.tasks)
            records = validate_attested_base_evaluation_responses(
                args.responses,
                tasks,
                activation_trust=_base_activation_trust(args),
                runtime_public_key_path=args.runtime_public_key,
            )
            _print(
                {
                    "valid": True,
                    "runtimeSignaturesVerified": True,
                    "recordCount": len(records),
                    "taskSetSha256": tasks.task_set_sha256,
                    "responseSetSha256": evaluation_response_set_sha256(records),
                }
            )
        elif args.command == "validate-verifier-results":
            records = validate_verifier_results(
                args.results,
                args.tasks,
                args.responses,
                require_complete=True,
            )
            _print({"valid": True, "recordCount": len(records)})
        elif args.command == "compile-verifier-results":
            _print(
                {
                    "created": True,
                    **compile_verifier_results(
                        tasks_path=args.tasks,
                        responses_path=args.responses,
                        decisions_path=args.decisions,
                        output_path=args.output,
                    ),
                }
            )
        elif args.command == "run-verifiers":
            verifier_authority, verifier_authority_trust = (
                _optional_csharp_verifier_authority(args)
            )
            _print(
                {
                    "created": True,
                    **run_release_verifiers(
                        tasks_path=args.tasks,
                        responses_path=args.responses,
                        release_path=args.release,
                        review_receipt_trust=_review_receipt_trust(args),
                        evaluation_authoring_approval_trust=(
                            _evaluation_authoring_approval_trust(args)
                        ),
                        output_path=args.output,
                        csharp_verifier_authority_path=verifier_authority,
                        csharp_verifier_authority_trust=verifier_authority_trust,
                    ),
                }
            )
        elif args.command == "create-csharp-verifier-authority":
            verified = create_csharp_verifier_authority(
                output_path=args.output,
                toolchain_path=args.toolchain,
                image_reference=args.image,
                image_id=args.image_id,
                entrypoint=args.entrypoint,
                docker_client_path=args.docker_client,
                docker_daemon_endpoint=args.docker_daemon_endpoint,
                private_key_path=args.private_key,
                public_key_path=args.verifier_authority_public_key,
                public_key_spki_sha256=(args.verifier_authority_public_key_spki_sha256),
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=args.verifier_authority_audience,
                key_id=args.verifier_authority_key_id,
                signer_role=args.verifier_authority_signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "prepare-csharp-verifier-authority-signing-bundle":
            verified_bundle = prepare_csharp_verifier_authority_signing_bundle(
                output_path=args.output,
                trust=_csharp_verifier_authority_trust(args),
                toolchain_path=args.toolchain,
                image_reference=args.image,
                image_id=args.image_id,
                entrypoint=args.entrypoint,
                docker_client_path=args.docker_client,
                docker_daemon_endpoint=args.docker_daemon_endpoint,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
            )
            _print({"created": True, **verified_bundle.as_dict()})
        elif args.command == "finalize-csharp-verifier-authority":
            verified = finalize_csharp_verifier_authority(
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                trust=_csharp_verifier_authority_trust(args),
                toolchain_path=args.toolchain,
                image_reference=args.image,
                image_id=args.image_id,
                entrypoint=args.entrypoint,
                docker_client_path=args.docker_client,
                docker_daemon_endpoint=args.docker_daemon_endpoint,
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "validate-csharp-verifier-authority":
            verified = validate_csharp_verifier_authority(
                args.authority,
                trust=_csharp_verifier_authority_trust(args),
            )
            _print({"valid": True, **verified.as_dict()})
        elif args.command == "create-csharp-verifier-replay-audit":
            verified = create_csharp_verifier_replay_audit(
                output_path=args.output,
                private_key_path=args.private_key,
                public_key_path=args.csharp_verifier_replay_audit_public_key,
                public_key_spki_sha256=(
                    args.csharp_verifier_replay_audit_public_key_spki_sha256
                ),
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=args.csharp_verifier_replay_audit_audience,
                key_id=args.csharp_verifier_replay_audit_key_id,
                signer_role=args.csharp_verifier_replay_audit_signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                replay_completed_at_utc=args.replay_completed_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                **_csharp_verifier_replay_audit_live_arguments(
                    args, workspace_parent=args.output.parent
                ),
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "prepare-csharp-verifier-replay-audit-signing-bundle":
            verified = prepare_csharp_verifier_replay_audit_signing_bundle(
                output_path=args.output,
                trust=_csharp_verifier_replay_audit_trust(args),
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                replay_completed_at_utc=args.replay_completed_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                **_csharp_verifier_replay_audit_live_arguments(
                    args, workspace_parent=args.output.parent
                ),
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "finalize-csharp-verifier-replay-audit":
            verified = finalize_csharp_verifier_replay_audit(
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                trust=_csharp_verifier_replay_audit_trust(args),
                **_csharp_verifier_replay_audit_live_arguments(
                    args, workspace_parent=args.output.parent
                ),
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "validate-csharp-verifier-replay-audit":
            verified = validate_csharp_verifier_replay_audit(
                args.audit,
                trust=_csharp_verifier_replay_audit_trust(args),
                expected_envelope_sha256=(
                    args.expected_csharp_verifier_replay_audit_envelope_sha256
                ),
            )
            _print({"valid": True, **verified.as_dict()})
        elif args.command == "verify-csharp-strategy":
            result = run_csharp_strategy_verification(
                request_path=args.request,
                source_path=args.source,
                expectations_path=args.expectations,
                authority_path=args.authority,
                authority_trust=_csharp_verifier_authority_trust(args),
                output_path=args.output,
            )
            _print(
                {
                    "created": True,
                    "accepted": result["accepted"],
                    "resultSha256": result["resultSha256"],
                    "outputPath": str(args.output),
                }
            )
        elif args.command == "validate-promotion-policy":
            policy = validate_promotion_policy(args.policy)
            _print(
                {
                    "valid": True,
                    "policyId": policy["policyId"],
                    "policySha256": policy["policySha256"],
                }
            )
        elif args.command == "capture-responses":
            _print(
                capture_openai_responses(
                    tasks_path=args.tasks,
                    catalog_path=args.catalog,
                    output_path=args.output,
                    serving_profile_path=args.serving_profile,
                    training_artifact_path=args.artifact,
                    training_manifest_path=args.manifest,
                    run_id=args.run_id,
                    base_url=args.base_url,
                    api_key_env=args.api_key_env,
                    seed=args.seed,
                    data_release_path=args.release,
                    review_receipt_trust=_review_receipt_trust(args),
                    evaluation_authoring_approval_trust=(
                        _evaluation_authoring_approval_trust(args)
                    ),
                    trainer_provenance_trust=_trainer_provenance_trust(args),
                    research_only=args.research_only_unbound,
                    timeout_seconds=args.timeout_seconds,
                    max_response_bytes=args.max_response_bytes,
                )
            )
        elif args.command == "capture-base-responses":
            _print(
                capture_openai_responses(
                    tasks_path=args.tasks,
                    catalog_path=args.catalog,
                    output_path=args.output,
                    base_evaluation_profile_path=args.base_evaluation_profile,
                    base_model_snapshot_manifest_path=args.snapshot_manifest,
                    base_model_snapshot_path=args.snapshot,
                    base_model_source_lock_path=args.source_lock,
                    run_id=args.run_id,
                    base_url=args.base_url,
                    api_key_env=args.api_key_env,
                    seed=args.seed,
                    research_only=True,
                    timeout_seconds=args.timeout_seconds,
                    max_response_bytes=args.max_response_bytes,
                )
            )
        elif args.command == "capture-attested-base-responses":
            _print(
                capture_openai_responses(
                    tasks_path=args.tasks,
                    catalog_path=args.catalog,
                    output_path=args.output,
                    base_evaluation_profile_path=args.base_evaluation_profile,
                    base_model_snapshot_manifest_path=args.snapshot_manifest,
                    base_model_snapshot_path=args.snapshot,
                    base_model_source_lock_path=args.source_lock,
                    base_engine_wrapper_config_path=args.wrapper_config,
                    base_engine_activation_trust=_base_activation_trust(args),
                    run_id=args.run_id,
                    base_url=args.base_url,
                    api_key_env=args.api_key_env,
                    seed=args.seed,
                    data_release_path=args.release,
                    review_receipt_trust=_review_receipt_trust(args),
                    evaluation_authoring_approval_trust=(
                        _evaluation_authoring_approval_trust(args)
                    ),
                    research_only=False,
                    timeout_seconds=args.timeout_seconds,
                    max_response_bytes=args.max_response_bytes,
                )
            )
        elif args.command == "derive-teacher-runtime-plan":
            _print(
                {
                    "derived": True,
                    **derive_teacher_runtime_plan(
                        runtime_descriptor_path=args.runtime_descriptor,
                        catalog_path=args.catalog,
                    ),
                }
            )
        elif args.command == "create-teacher-runtime-binding":
            binding = create_teacher_runtime_binding(
                runtime_descriptor_path=args.runtime_descriptor,
                catalog_path=args.catalog,
                output_path=args.output,
                api_key_env=args.api_key_env,
                timeout_seconds=args.timeout_seconds,
                max_response_bytes=args.max_response_bytes,
            )
            _print({"created": True, **binding.as_dict()})
        elif args.command == "validate-teacher-runtime-binding":
            binding = validate_teacher_runtime_binding(
                args.binding,
                api_key_env=args.api_key_env,
                timeout_seconds=args.timeout_seconds,
                max_response_bytes=args.max_response_bytes,
            )
            _print({"valid": True, **binding.as_dict()})
        elif args.command == "validate-teacher-generation":
            _print(
                {
                    "valid": True,
                    **validate_teacher_generation_manifest(args.manifest, args.catalog),
                }
            )
        elif args.command == "capture-teacher-candidates":
            candidates = capture_teacher_candidates(
                manifest_path=args.manifest,
                catalog_path=args.catalog,
                runtime_binding_path=args.runtime_binding,
                output_path=args.output,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
                timeout_seconds=args.timeout_seconds,
                max_response_bytes=args.max_response_bytes,
            )
            _print({"created": True, **candidates.as_dict()})
        elif args.command == "validate-teacher-candidates":
            candidates = validate_teacher_candidates(
                args.candidates,
                manifest_path=args.manifest,
                catalog_path=args.catalog,
            )
            _print({"valid": True, **candidates.as_dict()})
        elif args.command == "create-teacher-overlap-deny-set":
            deny_set = create_teacher_overlap_deny_set(
                calibration_tasks_path=args.calibration_tasks,
                sealed_tasks_path=args.sealed_tasks,
                output_path=args.output,
                deny_set_id=args.deny_set_id,
                custodian=args.custodian,
                created_at_utc=args.created_at_utc,
            )
            _print(
                {
                    "created": True,
                    "schemaVersion": deny_set["schemaVersion"],
                    "denySetId": deny_set["denySetId"],
                    "scopeSha256": deny_set["scopeSha256"],
                    "fileSha256": sha256_file(args.output),
                    "entryCounts": {
                        name: len(values)
                        for name, values in deny_set["entries"].items()
                    },
                }
            )
        elif args.command == "validate-teacher-selection":
            selection = validate_teacher_selection_manifest(args.selection)
            _print({"valid": True, **selection.as_dict()})
        elif args.command == "materialize-teacher-candidates":
            package = materialize_teacher_candidates(
                selection_manifest_path=args.selection,
                output_directory=args.output,
            )
            _print({"created": True, **package.as_dict()})
        elif args.command == "validate-teacher-materialization":
            package = validate_teacher_materialization(
                args.package,
                selection_manifest_path=args.selection,
            )
            _print({"valid": True, **package.as_dict()})
        elif args.command == "create-teacher-lineage-admission":
            trust = _teacher_lineage_admission_trust(args)
            if trust is None:  # argparse accepts the all-or-none trust surface
                raise ValidationError(
                    "teacher-lineage admission trust: externally pinned trust is required"
                )
            admission = create_teacher_materialization_lineage_admission(
                output_path=args.output,
                materialization_path=args.materialization,
                runtime_binding_path=args.runtime_binding,
                reviewed_dataset_path=args.reviewed_dataset,
                reviewer_evidence_path=args.reviewer_evidence,
                private_key_path=args.private_key,
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                trust=trust,
                reviewer_id=args.reviewer_id,
                reviewed_at_utc=args.reviewed_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
            )
            _print({"created": True, **admission.as_dict()})
        elif args.command == "prepare-teacher-lineage-admission-signing-bundle":
            trust = _teacher_lineage_admission_trust(args)
            if trust is None:
                raise ValidationError(
                    "teacher-lineage admission trust: externally pinned trust is required"
                )
            bundle = prepare_teacher_materialization_lineage_admission_signing_bundle(
                output_path=args.output,
                materialization_path=args.materialization,
                runtime_binding_path=args.runtime_binding,
                reviewed_dataset_path=args.reviewed_dataset,
                reviewer_evidence_path=args.reviewer_evidence,
                trust=trust,
                reviewer_id=args.reviewer_id,
                reviewed_at_utc=args.reviewed_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
            )
            _print({"prepared": True, **bundle.as_dict()})
        elif args.command == "finalize-teacher-lineage-admission":
            trust = _teacher_lineage_admission_trust(args)
            if trust is None:
                raise ValidationError(
                    "teacher-lineage admission trust: externally pinned trust is required"
                )
            admission = finalize_teacher_materialization_lineage_admission(
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                materialization_path=args.materialization,
                runtime_binding_path=args.runtime_binding,
                reviewed_dataset_path=args.reviewed_dataset,
                reviewer_evidence_path=args.reviewer_evidence,
                trust=trust,
            )
            _print({"created": True, **admission.as_dict()})
        elif args.command == "validate-teacher-lineage-admission":
            trust = _teacher_lineage_admission_trust(args)
            if trust is None:  # argparse accepts the all-or-none trust surface
                raise ValidationError(
                    "teacher-lineage admission trust: externally pinned trust is required"
                )
            admission = verify_teacher_materialization_lineage_admission(
                args.admission,
                materialization_path=args.materialization,
                runtime_binding_path=args.runtime_binding,
                reviewed_dataset_path=args.reviewed_dataset,
                reviewer_evidence_path=args.reviewer_evidence,
                trust=trust,
            )
            _print({"valid": True, **admission.as_dict()})
        elif args.command == "aggregate-promotion-evidence":
            csharp_context = _optional_csharp_verifier_context(
                args,
                workspace_parent=(
                    args.output.parent if args.output is not None else None
                ),
            )
            report = aggregate_promotion_evidence(
                calibration_tasks_path=args.calibration_tasks,
                calibration_evidence_path=args.calibration_evidence,
                sealed_tasks_path=args.sealed_tasks,
                responses_path=args.responses,
                verifier_results_path=args.verifier_results,
                baseline_responses_path=args.baseline_responses,
                baseline_verifier_results_path=args.baseline_verifier_results,
                policy_path=args.policy,
                data_release_path=args.release,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                csharp_verifier_context=csharp_context,
                research_only=args.research_only_unbound,
                **_promotion_attestation_trust_arguments(args),
                **_optional_csharp_verifier_replay_audit_arguments(args),
            )
            if args.output is not None:
                write_json_atomic_no_clobber(args.output, report)
            _print(report)
        elif args.command == "validate-promotion-evidence":
            report = validate_promotion_evidence(args.report)
            _print({"valid": True, "reportSha256": report["reportSha256"]})
        elif args.command == "create-evaluation-authoring-approval":
            authoring_trust = _evaluation_authoring_approval_trust(args)
            if authoring_trust is None:  # pragma: no cover - argparse requires it
                raise ValidationError(
                    "evaluation-authoring approval trust: externally pinned trust "
                    "is required"
                )
            verified = create_evaluation_authoring_approval(
                output_path=args.output,
                private_key_path=args.private_key,
                public_key_path=authoring_trust.public_key_path,
                public_key_spki_sha256=(authoring_trust.public_key_spki_sha256),
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=authoring_trust.audience,
                key_id=authoring_trust.key_id,
                signer_role=authoring_trust.signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                source_dataset_path=args.source_dataset,
                calibration_tasks_path=args.calibration_tasks,
                sealed_tasks_path=args.sealed_tasks,
                task_bindings_path=args.task_bindings,
            )
            _print(
                {
                    "created": True,
                    **verified.as_dict(),
                    "outputPath": str(verified.path),
                }
            )
        elif args.command == "prepare-evaluation-authoring-approval-signing-bundle":
            authoring_trust = _evaluation_authoring_approval_trust(args)
            if authoring_trust is None:  # pragma: no cover - argparse requires it
                raise ValidationError(
                    "evaluation-authoring approval trust: externally pinned trust "
                    "is required"
                )
            verified = prepare_evaluation_authoring_approval_signing_bundle(
                output_path=args.output,
                public_key_path=authoring_trust.public_key_path,
                public_key_spki_sha256=(authoring_trust.public_key_spki_sha256),
                audience=authoring_trust.audience,
                key_id=authoring_trust.key_id,
                signer_role=authoring_trust.signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                source_dataset_path=args.source_dataset,
                calibration_tasks_path=args.calibration_tasks,
                sealed_tasks_path=args.sealed_tasks,
                task_bindings_path=args.task_bindings,
            )
            _print({"prepared": True, **verified.as_dict()})
        elif args.command == "finalize-evaluation-authoring-approval":
            authoring_trust = _evaluation_authoring_approval_trust(args)
            if authoring_trust is None:  # pragma: no cover - argparse requires it
                raise ValidationError(
                    "evaluation-authoring approval trust: externally pinned trust "
                    "is required"
                )
            verified = finalize_evaluation_authoring_approval(
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                public_key_path=authoring_trust.public_key_path,
                expected_public_key_spki_sha256=(
                    authoring_trust.public_key_spki_sha256
                ),
                expected_audience=authoring_trust.audience,
                expected_key_id=authoring_trust.key_id,
                expected_signer_role=authoring_trust.signer_role,
                source_dataset_path=args.source_dataset,
                calibration_tasks_path=args.calibration_tasks,
                sealed_tasks_path=args.sealed_tasks,
                task_bindings_path=args.task_bindings,
            )
            _print(
                {
                    "created": True,
                    **verified.as_dict(),
                    "outputPath": str(verified.path),
                }
            )
        elif args.command == "validate-evaluation-authoring-approval":
            verified = validate_evaluation_authoring_approval_for_inventory(
                args.approval,
                trust=_evaluation_authoring_approval_trust(args),
                expected_envelope_sha256=(
                    args.expected_evaluation_authoring_approval_envelope_sha256
                ),
                source_dataset_path=args.source_dataset,
                calibration_tasks_path=args.calibration_tasks,
                sealed_tasks_path=args.sealed_tasks,
                task_bindings_path=args.task_bindings,
            )
            _print({"valid": True, **verified.as_dict()})
        elif args.command == "create-release":
            _print(
                create_corpus_evaluation_release(
                    corpus_path=args.corpus,
                    review_receipts_path=args.review_receipts,
                    teacher_lineage_admission_path=(args.teacher_lineage_admission),
                    review_receipt_trust=_review_receipt_trust(args),
                    evaluation_authoring_approval_path=(
                        args.evaluation_authoring_approval
                    ),
                    evaluation_authoring_approval_trust=(
                        _evaluation_authoring_approval_trust(args)
                    ),
                    expected_evaluation_authoring_approval_envelope_sha256=(
                        args.expected_evaluation_authoring_approval_envelope_sha256
                    ),
                    sft_path=args.sft,
                    calibration_tasks_path=args.calibration_tasks,
                    sealed_tasks_path=args.sealed_tasks,
                    task_bindings_path=args.task_bindings,
                    approval_evidence_path=args.approval_evidence,
                    output_root=args.output_root,
                    purpose=args.purpose,
                    cutoff_utc=args.cutoff_utc,
                    approval_id=args.approval_id,
                    reviewer_id=args.reviewer_id,
                    approved_at_utc=args.approved_at_utc,
                )
            )
        elif args.command == "validate-release":
            release = validate_corpus_evaluation_release(
                args.release,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
            )
            _print(
                {
                    "valid": True,
                    "releaseId": release["releaseId"],
                    "releaseSha256": release["releaseSha256"],
                    "purpose": release["purpose"],
                }
            )
        elif args.command == "create-review-receipts":
            verified = create_expert_model_review_receipts(
                dataset_path=args.dataset,
                output_path=args.output,
                private_key_path=args.private_key,
                public_key_path=args.public_key,
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=args.audience,
                key_id=args.key_id,
                signer_role=args.signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approval_evidence_path=args.approval_evidence,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                teacher_lineage_admission_path=args.teacher_lineage_admission,
                teacher_materialization_path=args.teacher_materialization,
                teacher_runtime_binding_path=args.teacher_runtime_binding,
                teacher_lineage_reviewer_evidence_path=(
                    args.teacher_lineage_reviewer_evidence
                ),
                teacher_lineage_admission_trust=(
                    _teacher_lineage_admission_trust(args)
                ),
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "prepare-review-receipt-signing-bundle":
            verified = prepare_expert_model_review_receipt_signing_bundle(
                dataset_path=args.dataset,
                output_path=args.output,
                public_key_path=args.public_key,
                audience=args.audience,
                key_id=args.key_id,
                signer_role=args.signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approval_evidence_path=args.approval_evidence,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                teacher_lineage_admission_path=args.teacher_lineage_admission,
                teacher_materialization_path=args.teacher_materialization,
                teacher_runtime_binding_path=args.teacher_runtime_binding,
                teacher_lineage_reviewer_evidence_path=(
                    args.teacher_lineage_reviewer_evidence
                ),
                teacher_lineage_admission_trust=(
                    _teacher_lineage_admission_trust(args)
                ),
            )
            _print({"prepared": True, **verified.as_dict()})
        elif args.command == "finalize-review-receipts":
            verified = finalize_expert_model_review_receipts(
                dataset_path=args.dataset,
                signing_bundle_path=args.signing_bundle,
                signature_set_path=args.signature_set,
                output_path=args.output,
                public_key_path=args.public_key,
                expected_public_key_spki_sha256=(args.expected_public_key_spki_sha256),
                expected_audience=args.expected_audience,
                expected_key_id=args.expected_key_id,
                expected_signer_role=args.expected_signer_role,
                approval_evidence_path=args.approval_evidence,
                teacher_lineage_admission_path=args.teacher_lineage_admission,
                teacher_materialization_path=args.teacher_materialization,
                teacher_runtime_binding_path=args.teacher_runtime_binding,
                teacher_lineage_reviewer_evidence_path=(
                    args.teacher_lineage_reviewer_evidence
                ),
                teacher_lineage_admission_trust=(
                    _teacher_lineage_admission_trust(args)
                ),
            )
            _print({"created": True, **verified.as_dict()})
        elif args.command == "validate-review-receipts":
            verified = validate_expert_model_review_receipts(
                args.receipts,
                dataset_path=args.dataset,
                public_key_path=args.public_key,
                expected_public_key_spki_sha256=(args.expected_public_key_spki_sha256),
                expected_audience=args.expected_audience,
                expected_key_id=args.expected_key_id,
                expected_signer_role=args.expected_signer_role,
                teacher_lineage_admission_path=args.teacher_lineage_admission,
                teacher_materialization_path=args.teacher_materialization,
                teacher_runtime_binding_path=args.teacher_runtime_binding,
                teacher_lineage_reviewer_evidence_path=(
                    args.teacher_lineage_reviewer_evidence
                ),
                teacher_lineage_admission_trust=(
                    _teacher_lineage_admission_trust(args)
                ),
            )
            _print({"valid": True, **verified.as_dict()})
        elif args.command == "create-base-model-selection":
            csharp_context = _optional_csharp_verifier_context(
                args, workspace_parent=args.output.parent
            )
            verified = create_base_model_selection(
                output_path=args.output,
                private_key_path=args.private_key,
                public_key_path=args.base_selection_public_key,
                public_key_spki_sha256=(args.base_selection_public_key_spki_sha256),
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=args.base_selection_audience,
                key_id=args.base_selection_key_id,
                signer_role=args.base_selection_signer_role,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                baseline_attestation_trust=_response_attestation_trust(
                    args, prefix="baseline"
                ),
                csharp_verifier_context=csharp_context,
                **_base_selection_source_arguments(args),
            )
            _print(
                {
                    "created": True,
                    "selectionId": verified.payload["selectionId"],
                    "payloadSha256": verified.payload_sha256,
                    "envelopeSha256": verified.envelope_sha256,
                    "outputPath": str(verified.path),
                }
            )
        elif args.command == "prepare-base-model-selection-signing-bundle":
            csharp_context = _optional_csharp_verifier_context(
                args, workspace_parent=args.output.parent
            )
            verified_bundle = prepare_base_model_selection_signing_bundle(
                output_path=args.output,
                trust=_base_selection_trust(args),
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                baseline_attestation_trust=_response_attestation_trust(
                    args, prefix="baseline"
                ),
                csharp_verifier_context=csharp_context,
                **_base_selection_source_arguments(args),
            )
            _print({"created": True, **verified_bundle.as_dict()})
        elif args.command == "finalize-base-model-selection":
            csharp_context = _optional_csharp_verifier_context(
                args, workspace_parent=args.output.parent
            )
            verified = finalize_base_model_selection(
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                trust=_base_selection_trust(args),
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                baseline_attestation_trust=_response_attestation_trust(
                    args, prefix="baseline"
                ),
                csharp_verifier_context=csharp_context,
                **_base_selection_source_arguments(args),
            )
            _print(
                {
                    "created": True,
                    "selectionId": verified.payload["selectionId"],
                    "payloadSha256": verified.payload_sha256,
                    "envelopeSha256": verified.envelope_sha256,
                    "outputPath": str(verified.path),
                }
            )
        elif args.command == "validate-base-model-selection":
            csharp_context = _optional_csharp_verifier_context(
                args, workspace_parent=args.selection.parent
            )
            verified = validate_base_model_selection(
                args.selection,
                trust=_base_selection_trust(args),
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                baseline_attestation_trust=_response_attestation_trust(
                    args, prefix="baseline"
                ),
                csharp_verifier_context=csharp_context,
                **_base_selection_source_arguments(args),
            )
            _print(
                {
                    "valid": True,
                    "selectionId": verified.payload["selectionId"],
                    "payloadSha256": verified.payload_sha256,
                    "envelopeSha256": verified.envelope_sha256,
                }
            )
        elif args.command == "create-model-promotion":
            verified = create_model_promotion(
                output_path=args.output,
                private_key_path=args.private_key,
                public_key_path=args.public_key,
                private_key_password=_private_key_password(
                    args.private_key_password_env
                ),
                audience=args.audience,
                key_id=args.key_id,
                signer_role=args.signer_role,
                deployment_id=args.deployment_id,
                environment=args.environment,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                trainer_provenance_trust=_trainer_provenance_trust(args),
                base_selection_trust=_base_selection_trust(args),
                **_promotion_source_arguments(args),
                **_promotion_attestation_trust_arguments(args),
                **_optional_csharp_verifier_replay_audit_arguments(args),
            )
            _print(
                {
                    "created": True,
                    "promotionId": verified.payload["promotionId"],
                    "payloadSha256": verified.payload_sha256,
                    "envelopeSha256": verified.envelope_sha256,
                    "outputPath": str(verified.path),
                }
            )
        elif args.command == "prepare-model-promotion-signing-bundle":
            verified_bundle = prepare_model_promotion_signing_bundle(
                output_path=args.output,
                public_key_path=args.public_key,
                audience=args.audience,
                key_id=args.key_id,
                signer_role=args.signer_role,
                deployment_id=args.deployment_id,
                environment=args.environment,
                approval_id=args.approval_id,
                actor_id=args.actor_id,
                actor_role=args.actor_role,
                approval_reference=args.approval_reference,
                approved_at_utc=args.approved_at_utc,
                issued_at_utc=args.issued_at_utc,
                not_before_utc=args.not_before_utc,
                expires_at_utc=args.expires_at_utc,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                trainer_provenance_trust=_trainer_provenance_trust(args),
                base_selection_trust=_base_selection_trust(args),
                **_promotion_source_arguments(args),
                **_promotion_attestation_trust_arguments(args),
                **_optional_csharp_verifier_replay_audit_arguments(args),
            )
            _print(
                {
                    "created": True,
                    "bundleId": verified_bundle.bundle_id,
                    "bundleSha256": verified_bundle.bundle_sha256,
                    "promotionId": verified_bundle.payload["promotionId"],
                    "payloadSha256": verified_bundle.payload_sha256,
                    "signatureInputSha256": (verified_bundle.signature_input_sha256),
                    "outputPath": str(verified_bundle.path),
                }
            )
        elif args.command == "finalize-model-promotion":
            verified = finalize_model_promotion(
                signing_bundle_path=args.signing_bundle,
                signature_path=args.signature,
                output_path=args.output,
                public_key_path=args.public_key,
                expected_audience=args.expected_audience,
                expected_key_id=args.expected_key_id,
                expected_signer_role=args.expected_signer_role,
                expected_deployment_id=args.expected_deployment_id,
                expected_environment=args.expected_environment,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                trainer_provenance_trust=_trainer_provenance_trust(args),
                base_selection_trust=_base_selection_trust(args),
                **_promotion_source_arguments(args),
                **_promotion_attestation_trust_arguments(args),
                **_optional_csharp_verifier_replay_audit_arguments(args),
            )
            _print(
                {
                    "created": True,
                    "promotionId": verified.payload["promotionId"],
                    "payloadSha256": verified.payload_sha256,
                    "envelopeSha256": verified.envelope_sha256,
                    "outputPath": str(verified.path),
                }
            )
        elif args.command == "validate-model-promotion":
            verified = validate_model_promotion(
                args.promotion,
                public_key_path=args.public_key,
                expected_audience=args.expected_audience,
                expected_key_id=args.expected_key_id,
                expected_signer_role=args.expected_signer_role,
                expected_deployment_id=args.expected_deployment_id,
                expected_environment=args.expected_environment,
                review_receipt_trust=_review_receipt_trust(args),
                evaluation_authoring_approval_trust=(
                    _evaluation_authoring_approval_trust(args)
                ),
                trainer_provenance_trust=_trainer_provenance_trust(args),
                base_selection_trust=_base_selection_trust(args),
                **_promotion_source_arguments(args),
                **_promotion_attestation_trust_arguments(args),
                **_optional_csharp_verifier_replay_audit_arguments(args),
            )
            _print(
                {
                    "valid": True,
                    "promotionId": verified.payload["promotionId"],
                    "payloadSha256": verified.payload_sha256,
                    "envelopeSha256": verified.envelope_sha256,
                }
            )
        elif args.command == "create-model-readiness-v2":
            _print(
                create_promoted_model_readiness_attestation(
                    promotion_path=args.promotion,
                    public_key_path=args.public_key,
                    expected_audience=args.expected_audience,
                    expected_promotion_key_id=args.expected_promotion_key_id,
                    expected_signer_role=args.expected_signer_role,
                    expected_deployment_id=args.expected_deployment_id,
                    expected_environment=args.expected_environment,
                    nonce=args.nonce,
                    readiness_key_id=args.readiness_key_id,
                    readiness_key=_hmac_key(args.hmac_key_env),
                    review_receipt_trust=_review_receipt_trust(args),
                    evaluation_authoring_approval_trust=(
                        _evaluation_authoring_approval_trust(args)
                    ),
                    trainer_provenance_trust=_trainer_provenance_trust(args),
                    base_selection_trust=_base_selection_trust(args),
                    **_promotion_source_arguments(args),
                    **_promotion_attestation_trust_arguments(args),
                    **_optional_csharp_verifier_replay_audit_arguments(args),
                )
            )
        elif args.command == "serve-promoted-model":
            serve_promoted_model(args.config)
        else:  # pragma: no cover - argparse owns this branch
            parser.error("unknown command")
    except (ValidationError, PreflightError, InfrastructureError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0
