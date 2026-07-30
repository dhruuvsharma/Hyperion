from __future__ import annotations

import hashlib
import importlib
import inspect
import json
import math
import os
import platform
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from .base_selection import BaseModelSelectionTrust
    from .corpus_quality import TrainingCorpusAdmissionTrust
    from .evaluation_authoring import EvaluationAuthoringApprovalTrust
    from .review_receipts import ExpertModelReviewReceiptTrust
    from .trainer_provenance import TrainerProvenanceTrust

from .artifacts import (
    TRAINING_ARTIFACT_SCHEMA_VERSION,
    TRAINING_DEPENDENCIES,
    finalize_training_artifact_core,
    prepare_training_artifact_core,
    seal_training_artifact,
    validate_training_artifact,
)
from .core import (
    DATASET_BUNDLE_PATH,
    BASE_EVALUATION_PROFILE_BUNDLE_PATH,
    BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
    BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
    BASE_SELECTION_BUNDLE_PATH,
    MANIFEST_BUNDLE_PATH,
    MANIFEST_V2_SCHEMA_VERSION,
    MANIFEST_V3_SCHEMA_VERSION,
    MAX_JSON_BYTES,
    MAX_SFT_BYTES,
    TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
    ValidationError,
    _copy_file_snapshot,
    _ensure_directory_no_reparse,
    _exclusive_destination_lock,
    _install_directory_no_clobber,
    _load_json_object_bytes,
    _read_file_bounded,
    _reject_reparse_components,
    _write_json_exclusive,
    canonical_json_bytes,
    load_json_document,
    parse_sft_bytes,
    resolve_bound_path,
    sha256_file,
    validate_manifest_path,
)
from .runtime import (
    RuntimeLockError,
    installed_direct_dependency_versions,
    validate_runtime_environment,
    validate_runtime_host,
    validate_training_runtime_profile,
)


PRODUCTION_MINIMUM_GPU_GIB = 16.0
TRAINER_PROVENANCE_HANDOFF_ARTIFACT_DIRECTORY = "artifact"
TRAINER_PROVENANCE_HANDOFF_ARTIFACT_CORE_NAME = "training-artifact-core.json"
TRAINER_PROVENANCE_SIGNING_BUNDLE_NAME = "trainer-provenance-signing-bundle.json"


class PreflightError(RuntimeLockError):
    """Raised before model construction when the local trainer is unsafe to start."""


def load_training_dependencies(
    importer: Callable[[str], Any] = importlib.import_module,
) -> dict[str, Any]:
    loaded: dict[str, Any] = {}
    failures: list[str] = []
    for name in TRAINING_DEPENDENCIES:
        try:
            loaded[name] = importer(name)
        except Exception as error:  # optional native packages can fail while importing
            failures.append(f"{name} ({type(error).__name__}: {error})")
    if failures:
        raise PreflightError(
            "training dependencies are unavailable: "
            + "; ".join(failures)
            + ". Install this package with the '[train]' extra in a reviewed Python 3.11+ environment."
        )
    return loaded


def gpu_memory_preflight(
    torch_module: Any,
    *,
    minimum_gib: float = PRODUCTION_MINIMUM_GPU_GIB,
    smoke: bool = False,
) -> dict[str, Any]:
    if not math.isfinite(minimum_gib) or minimum_gib <= 0:
        raise PreflightError("minimum GPU memory must be a finite positive number")
    if not smoke and minimum_gib < PRODUCTION_MINIMUM_GPU_GIB:
        raise PreflightError(
            f"production-candidate training cannot lower the {PRODUCTION_MINIMUM_GPU_GIB:g} GiB floor"
        )
    cuda = getattr(torch_module, "cuda", None)
    available = bool(cuda is not None and cuda.is_available())
    if not available:
        raise PreflightError("CUDA is unavailable; QLoRA-SFT requires a CUDA GPU")
    device_count = int(cuda.device_count())
    if device_count <= 0:
        raise PreflightError("CUDA reported no visible devices")
    devices = []
    sizes = []
    for index in range(device_count):
        properties = cuda.get_device_properties(index)
        size = float(properties.total_memory) / (1024**3)
        sizes.append(size)
        major = getattr(properties, "major", None)
        minor = getattr(properties, "minor", None)
        devices.append(
            {
                "index": index,
                "name": str(getattr(properties, "name", "unknown")),
                "totalMemoryGiB": round(size, 3),
                "computeCapability": (
                    f"{major}.{minor}"
                    if isinstance(major, int) and isinstance(minor, int)
                    else None
                ),
                "multiProcessorCount": getattr(
                    properties, "multi_processor_count", None
                ),
            }
        )
    if any(not math.isfinite(size) or size <= 0 for size in sizes):
        raise PreflightError("CUDA reported an invalid device-memory size")
    largest = max(sizes, default=0.0)
    if largest < minimum_gib and not smoke:
        raise PreflightError(
            f"largest visible GPU has {largest:.2f} GiB; at least {minimum_gib:.2f} GiB is required"
        )
    return {
        "cudaAvailable": True,
        "deviceCount": device_count,
        "largestGpuGiB": round(largest, 3),
        "requiredGpuGiB": minimum_gib,
        "memoryGateWaivedForSmoke": largest < minimum_gib and smoke,
        "devices": devices,
        "cudaRuntimeVersion": getattr(
            getattr(torch_module, "version", None), "cuda", None
        ),
        "productionEligible": False,
    }


def _dependency_versions(dependencies: dict[str, Any]) -> dict[str, str]:
    try:
        return installed_direct_dependency_versions(dependencies)
    except RuntimeLockError as error:
        raise PreflightError(str(error)) from error


def _ensure_receipt_authorization_active(
    expires_at: datetime,
    now: Callable[[], datetime],
) -> None:
    current = now()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValidationError("training receipt clock: must include a UTC offset")
    if current.astimezone(timezone.utc) >= expires_at:
        raise ValidationError(
            "training review-receipt authorization expired during the run"
        )


def _ensure_selection_authorization_active(
    expires_at: datetime,
    now: Callable[[], datetime],
) -> None:
    current = now()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValidationError("base-model selection clock: must include a UTC offset")
    if current.astimezone(timezone.utc) >= expires_at:
        raise ValidationError(
            "base-model selection authorization expired during the run"
        )


def _ensure_corpus_admission_active(
    expires_at: datetime,
    now: Callable[[], datetime],
) -> None:
    current = now()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValidationError(
            "training corpus admission clock: must include a UTC offset"
        )
    if current.astimezone(timezone.utc) >= expires_at:
        raise ValidationError("training corpus admission expired during the run")


def _snapshot_tree_is_read_only(root: Path) -> bool:
    try:
        paths = [root, *root.rglob("*")]
        return all(not (path.stat().st_mode & 0o222) for path in paths)
    except OSError:
        return False


def _run_training(
    manifest: dict[str, Any],
    dependencies: dict[str, Any],
    records: list[dict[str, Any]],
    output_path: Path,
    *,
    smoke: bool,
    compute_dtype: Any,
    authorization_guard: Callable[[], None],
    model_source_path: Path | None = None,
    integrity_guard: Callable[[], None] | None = None,
) -> None:
    torch = dependencies["torch"]
    transformers = dependencies["transformers"]
    datasets = dependencies["datasets"]
    peft = dependencies["peft"]
    trl = dependencies["trl"]
    authorization_guard()
    model_id = manifest["baseModel"]["modelId"]
    revision = manifest["baseModel"]["revision"]
    model_source = str(model_source_path) if model_source_path is not None else model_id
    source_arguments: dict[str, Any] = {
        "local_files_only": True,
        "trust_remote_code": False,
    }
    if model_source_path is None:
        source_arguments["revision"] = revision
    quantization = transformers.BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=compute_dtype,
        bnb_4bit_use_double_quant=True,
    )
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        model_source,
        **source_arguments,
    )
    tokenizer.chat_template = manifest["chatTemplate"]["template"]
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = transformers.AutoModelForCausalLM.from_pretrained(
        model_source,
        **source_arguments,
        quantization_config=quantization,
        device_map="auto",
    )
    if integrity_guard is not None:
        integrity_guard()
    for target in (tokenizer, model, getattr(model, "config", None)):
        if target is not None and hasattr(target, "name_or_path"):
            try:
                target.name_or_path = model_id
            except (AttributeError, TypeError):
                pass
    if hasattr(tokenizer, "init_kwargs") and isinstance(tokenizer.init_kwargs, dict):
        tokenizer.init_kwargs["name_or_path"] = model_id
    parameters = manifest["hyperparameters"]
    peft_config = peft.LoraConfig(
        r=parameters["loraR"],
        lora_alpha=parameters["loraAlpha"],
        lora_dropout=parameters["loraDropout"],
        target_modules=parameters["loraTargetModules"],
        bias="none",
        task_type="CAUSAL_LM",
    )
    train_dataset = datasets.Dataset.from_list(records)
    bf16 = bool(torch.cuda.is_bf16_supported())
    config_arguments: dict[str, Any] = {
        "output_dir": str(output_path),
        "num_train_epochs": 1.0 if smoke else parameters["numTrainEpochs"],
        "learning_rate": parameters["learningRate"],
        "per_device_train_batch_size": parameters["perDeviceTrainBatchSize"],
        "gradient_accumulation_steps": parameters["gradientAccumulationSteps"],
        "warmup_ratio": parameters["warmupRatio"],
        "weight_decay": parameters["weightDecay"],
        "gradient_checkpointing": parameters["gradientCheckpointing"],
        "optim": parameters["optimizer"],
        "lr_scheduler_type": parameters["lrScheduler"],
        "seed": manifest["seed"],
        "data_seed": manifest["seed"],
        "bf16": bf16,
        "fp16": not bf16,
        "report_to": [],
        "save_strategy": "no",
        "logging_steps": 1 if smoke else 10,
        "max_steps": 1 if smoke else -1,
        "packing": False,
    }
    sft_signature = inspect.signature(trl.SFTConfig).parameters
    length_key = "max_length" if "max_length" in sft_signature else "max_seq_length"
    config_arguments[length_key] = parameters["maxSequenceLength"]
    sft_config = trl.SFTConfig(**config_arguments)
    trainer_arguments: dict[str, Any] = {
        "model": model,
        "args": sft_config,
        "train_dataset": train_dataset,
        "peft_config": peft_config,
    }

    class ReceiptAuthorizationCallback(transformers.TrainerCallback):
        def on_step_begin(self, args, state, control, **kwargs):
            authorization_guard()
            return control

        def on_epoch_begin(self, args, state, control, **kwargs):
            authorization_guard()
            return control

    trainer_arguments["callbacks"] = [ReceiptAuthorizationCallback()]
    trainer_signature = inspect.signature(trl.SFTTrainer).parameters
    trainer_arguments[
        "processing_class" if "processing_class" in trainer_signature else "tokenizer"
    ] = tokenizer
    trainer = trl.SFTTrainer(**trainer_arguments)
    authorization_guard()
    trainer.train()
    authorization_guard()
    trainer.model.save_pretrained(str(output_path), safe_serialization=True)
    tokenizer.save_pretrained(str(output_path))
    if integrity_guard is not None:
        integrity_guard()


def _sanitize_and_reject_snapshot_path_leaks(
    output_path: Path,
    *,
    snapshot_path: Path,
    model_id: str,
) -> None:
    adapter_config_path = output_path / "adapter_config.json"
    adapter_config = load_json_document(adapter_config_path)
    base_reference = adapter_config.get("base_model_name_or_path")
    accepted_references = {
        model_id,
        str(snapshot_path),
        os.fspath(snapshot_path),
        snapshot_path.as_posix(),
    }
    if base_reference not in accepted_references:
        raise ValidationError(
            "training adapter_config.json.base_model_name_or_path: does not identify "
            "the selected snapshot or its public model ID"
        )
    adapter_config["base_model_name_or_path"] = model_id
    adapter_config_path.write_bytes(canonical_json_bytes(adapter_config))

    forbidden = {
        str(snapshot_path),
        os.fspath(snapshot_path),
        snapshot_path.as_posix(),
        json.dumps(str(snapshot_path), ensure_ascii=False)[1:-1],
    }
    forbidden.discard(model_id)
    for path in output_path.iterdir():
        if not path.is_file() or path.suffix.lower() not in {
            ".json",
            ".md",
            ".jinja",
            ".txt",
        }:
            continue
        raw = _read_file_bounded(path, f"training output {path.name}", 100_000_000)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValidationError(
                f"training output {path.name}: invalid UTF-8 at byte {error.start}"
            ) from error
        if any(value and value in text for value in forbidden):
            raise ValidationError(
                f"training output {path.name}: leaks the private base-model snapshot path"
            )


def _validate_dataset_snapshot(
    snapshot_bytes: bytes,
    snapshot_path: Path,
    manifest: dict[str, Any],
) -> tuple[Any, list[dict[str, Any]]]:
    actual_hash = hashlib.sha256(snapshot_bytes).hexdigest()
    if actual_hash != manifest["dataset"]["sha256"]:
        raise ValidationError(
            "manifest.dataset.sha256: private training snapshot does not match the manifest"
        )
    summary, records = parse_sft_bytes(
        snapshot_bytes,
        source_path=snapshot_path,
        content_sha256=actual_hash,
    )
    if summary.record_count != manifest["dataset"]["recordCount"]:
        raise ValidationError(
            "manifest.dataset.recordCount: private training snapshot does not match"
        )
    if (
        list(summary.source_schema_versions)
        != manifest["dataset"]["sourceSchemaVersions"]
    ):
        raise ValidationError(
            "manifest.dataset.sourceSchemaVersions: private training snapshot does not match"
        )
    if set(summary.split_counts) != {"development"} or summary.missing_domains:
        raise ValidationError(
            "manifest.dataset: private training snapshot fails split or domain coverage"
        )
    return summary, records


def _artifact_metadata(
    *,
    manifest: dict[str, Any],
    manifest_sha256: str,
    dependency_versions: dict[str, str],
    dataset_sha256: str,
    dataset_record_count: int,
    compute_dtype: Any,
    gpu: dict[str, Any],
    smoke: bool,
) -> dict[str, Any]:
    dtype_name = str(compute_dtype)
    if dtype_name.startswith("torch."):
        dtype_name = dtype_name.removeprefix("torch.")
    mode = "smoke" if smoke else "unpromoted-candidate"
    reason = {
        "smoke": "Smoke mode cannot produce a production model.",
        "unpromoted-research": "Research-only training cannot produce promotion-eligible evidence.",
        "unpromoted-candidate": "Training alone does not satisfy evaluation, promotion, signing, or deployment gates.",
    }[mode]
    return {
        "schemaVersion": TRAINING_ARTIFACT_SCHEMA_VERSION,
        "recordedAtUtc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "runId": manifest["runId"],
        "mode": mode,
        "productionEligible": False,
        "reason": reason,
        "manifestSha256": manifest_sha256,
        "dataRelease": manifest.get("dataRelease"),
        "baseModel": {
            "candidateId": manifest["baseModel"]["candidateId"],
            "modelId": manifest["baseModel"]["modelId"],
            "revision": manifest["baseModel"]["revision"],
        },
        "datasetSnapshot": {
            "path": DATASET_BUNDLE_PATH,
            "sha256": dataset_sha256,
            "recordCount": dataset_record_count,
        },
        "environment": {
            "python": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "executable": sys.executable,
            },
            "platform": {
                "description": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "dependencyVersions": dependency_versions,
            "computeDtype": dtype_name,
            "gpu": gpu,
        },
    }


def _directory_identity(path: Path, field: str) -> tuple[int, int]:
    checked = _ensure_directory_no_reparse(path, field)
    stat = checked.lstat()
    return stat.st_dev, stat.st_ino


@dataclass
class _DirectoryOwnership:
    identity: tuple[int, int]
    descriptor: int | None

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = None
        if descriptor is not None:
            os.close(descriptor)


def _capture_directory_ownership(path: Path, field: str) -> _DirectoryOwnership:
    checked = _ensure_directory_no_reparse(path, field)
    initial_identity = _directory_identity(checked, field)
    if os.name == "nt":
        return _DirectoryOwnership(initial_identity, None)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(checked, flags)
    except OSError as error:
        raise ValidationError(
            f"{field}: cannot open directory ownership guard: {error}"
        ) from error
    try:
        descriptor_stat = os.fstat(descriptor)
        descriptor_identity = descriptor_stat.st_dev, descriptor_stat.st_ino
        if (
            descriptor_identity != initial_identity
            or _directory_identity(checked, field) != descriptor_identity
        ):
            raise ValidationError(f"{field}: path ownership changed while opening")
        return _DirectoryOwnership(descriptor_identity, descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def _publish_directory_no_clobber(
    source: Path,
    destination: Path,
    field: str,
    *,
    validator: Callable[[Path], Any],
) -> Any:
    """Install one owned directory, replay it in place, and clean only our inode."""

    source_ownership = _capture_directory_ownership(
        source, f"{field} staging directory"
    )
    source_identity = source_ownership.identity
    try:
        validator(source)
    except BaseException:
        source_ownership.close()
        raise
    try:
        _install_directory_no_clobber(source, destination, field)
        if _directory_identity(destination, field) != source_identity:
            raise ValidationError(
                f"{field}: path ownership changed during installation"
            )
        verified = validator(destination)
        if _directory_identity(destination, field) != source_identity:
            raise ValidationError(f"{field}: path ownership changed after validation")
        return verified
    except BaseException as error:
        residuals: list[str] = []
        for candidate in (source, destination):
            try:
                exists = os.path.lexists(candidate)
            except OSError:
                residuals.append(f"{candidate} (inspection failed)")
                continue
            if not exists:
                continue
            try:
                current_identity = _directory_identity(candidate, field)
            except (OSError, ValidationError):
                residuals.append(f"{candidate} (ownership unavailable)")
                continue
            if current_identity != source_identity:
                residuals.append(f"{candidate} (raced replacement preserved)")
                continue
            try:
                shutil.rmtree(candidate)
            except FileNotFoundError:
                continue
            except OSError:
                residuals.append(str(candidate))
            else:
                try:
                    if os.path.lexists(candidate):
                        residuals.append(f"{candidate} (reappeared after cleanup)")
                except OSError:
                    residuals.append(f"{candidate} (cleanup verification failed)")
        if residuals:
            raise ValidationError(
                f"{field}: publication failed; residual pending or signed paths "
                f"require inspection: {'; '.join(residuals)}"
            ) from error
        raise
    finally:
        source_ownership.close()


def _cleanup_owned_stage(
    stage: Path,
    stage_ownership: _DirectoryOwnership,
    field: str,
    *,
    protected_children: tuple[tuple[Path, _DirectoryOwnership], ...] = (),
) -> None:
    try:
        if not os.path.lexists(stage):
            return
        residuals: list[str] = []
        try:
            current_stage_identity = _directory_identity(stage, field)
        except (OSError, ValidationError):
            residuals.append(f"{stage} (ownership unavailable)")
        else:
            if current_stage_identity != stage_ownership.identity:
                residuals.append(f"{stage} (raced replacement preserved)")
        if not residuals:
            for child, child_ownership in protected_children:
                if not os.path.lexists(child):
                    continue
                try:
                    current_identity = _directory_identity(child, f"{field} child")
                except (OSError, ValidationError):
                    residuals.append(f"{child} (ownership unavailable)")
                else:
                    if current_identity != child_ownership.identity:
                        residuals.append(f"{child} (raced replacement preserved)")
        if residuals:
            raise ValidationError(
                f"{field}: cleanup withheld; residual paths require inspection: "
                f"{'; '.join(residuals)}"
            )
        try:
            shutil.rmtree(stage)
        except OSError as error:
            raise ValidationError(
                f"{field}: cleanup failed; residual path requires removal: {stage}"
            ) from error
    finally:
        for _, child_ownership in reversed(protected_children):
            child_ownership.close()
        stage_ownership.close()


def _exact_pretty_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
    ).encode("utf-8")


def _load_exact_handoff_json(path: Path, field: str, max_bytes: int) -> dict[str, Any]:
    raw = _read_file_bounded(path, field, max_bytes)
    document = _load_json_object_bytes(raw, field)
    if raw != _exact_pretty_json_bytes(document):
        raise ValidationError(f"{field}: must use the exact canonical handoff encoding")
    return document


def _replay_candidate_training_authorities(
    manifest_path: str | os.PathLike[str],
    *,
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_now: datetime | None,
    base_model_snapshot_path: str | os.PathLike[str],
    base_selection_trust: BaseModelSelectionTrust,
    base_selection_now: datetime | None,
    corpus_admission_trust: TrainingCorpusAdmissionTrust,
    corpus_admission_now: datetime | None,
    trainer_provenance_trust: TrainerProvenanceTrust,
    snapshot_read_only_probe: Callable[[Path], bool],
) -> dict[str, Any]:
    """Freshly replay every candidate-training authority without importing ML code."""

    path = Path(manifest_path)
    manifest = validate_manifest_path(path)
    if manifest["schemaVersion"] != MANIFEST_V3_SCHEMA_VERSION:
        raise ValidationError(
            "trainer provenance handoff: finalization requires a selected v3 manifest"
        )
    bound_release = manifest.get("dataRelease")
    if bound_release is None:
        raise ValidationError("trainer provenance handoff: data release is unavailable")

    from .release import validate_training_release_binding

    _, release_identity = validate_training_release_binding(
        data_release_path,
        dataset_sha256=manifest["dataset"]["sha256"],
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        now=review_receipt_now,
    )
    if release_identity != bound_release:
        raise ValidationError(
            "trainer provenance handoff: release does not match the manifest"
        )

    source_dataset = resolve_bound_path(
        path.parent,
        manifest["dataset"]["path"],
        "manifest.dataset.path",
    )
    dataset_bytes = _read_file_bounded(
        source_dataset,
        "trainer provenance handoff dataset",
        MAX_SFT_BYTES,
    )
    admission_path = resolve_bound_path(
        path.parent,
        manifest["trainingCorpusAdmission"]["path"],
        "manifest.trainingCorpusAdmission.path",
    )
    from .corpus_quality import verify_training_corpus_admission_file

    admission = verify_training_corpus_admission_file(
        admission_path,
        dataset_bytes=dataset_bytes,
        dataset_source_path=source_dataset,
        expected_data_release=bound_release,
        trust=corpus_admission_trust,
        expected_envelope_sha256=manifest["trainingCorpusAdmission"]["envelopeSha256"],
        now=corpus_admission_now,
    )
    if manifest["trainingCorpusAdmission"] != {
        "path": TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
        **admission.as_dict(),
    }:
        raise ValidationError(
            "trainer provenance handoff: corpus admission does not match the manifest"
        )

    model_source_path = Path(os.path.abspath(os.fspath(base_model_snapshot_path)))
    if not snapshot_read_only_probe(model_source_path):
        raise ValidationError(
            "trainer provenance handoff: base-model snapshot must remain read-only"
        )
    selection_path = resolve_bound_path(
        path.parent,
        manifest["baseModelSelection"]["path"],
        "manifest.baseModelSelection.path",
    )
    from .base_selection import validate_base_model_selection_target

    selected_target = validate_base_model_selection_target(
        selection_path,
        trust=base_selection_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
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
        snapshot_path=model_source_path,
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
        now=base_selection_now,
    )
    selection = selected_target.selection
    if selection.payload["dataRelease"] != bound_release:
        raise ValidationError(
            "trainer provenance handoff: selection release does not match the manifest"
        )
    if manifest["baseModelSelection"] != {
        "path": BASE_SELECTION_BUNDLE_PATH,
        "envelopeSha256": selection.envelope_sha256,
        "payloadSha256": selection.payload_sha256,
        "selectionId": selection.payload["selectionId"],
        "expiresAtUtc": selection.payload["expiresAtUtc"],
    }:
        raise ValidationError(
            "trainer provenance handoff: selection does not match the manifest"
        )

    upstream_signers = {
        review_receipt_trust.public_key_spki_sha256,
        evaluation_authoring_approval_trust.public_key_spki_sha256,
        base_selection_trust.public_key_spki_sha256,
    }
    teacher_lineage_trust = review_receipt_trust.teacher_lineage_admission_trust
    if teacher_lineage_trust is not None:
        upstream_signers.add(teacher_lineage_trust.public_key_spki_sha256)
    if admission.public_key_spki_sha256 in upstream_signers:
        raise ValidationError(
            "training corpus admission signer: must differ from corpus review, "
            "teacher-lineage, evaluation-authoring, and base-selection signers"
        )
    upstream_signers.add(admission.public_key_spki_sha256)
    if trainer_provenance_trust.public_key_spki_sha256 in upstream_signers:
        raise ValidationError(
            "trainer provenance signer: must differ from corpus review, "
            "teacher-lineage, evaluation-authoring, base-selection, and "
            "corpus-admission signers"
        )

    output_path = resolve_bound_path(
        path.parent,
        manifest["outputPath"],
        "manifest.outputPath",
        allow_missing_suffix=True,
    )
    return {
        "manifest": manifest,
        "manifestSha256": sha256_file(path, max_bytes=MAX_JSON_BYTES),
        "datasetSha256": hashlib.sha256(dataset_bytes).hexdigest(),
        "dataRelease": release_identity,
        "corpusAdmission": admission.as_dict(),
        "selectionEnvelopeSha256": selection.envelope_sha256,
        "selectionPayloadSha256": selection.payload_sha256,
        "selectedSnapshot": selected_target.snapshot.document,
        "selectedProfile": selected_target.profile.document,
        "outputPath": str(output_path),
        "trainerPublicKeySpkiSha256": (trainer_provenance_trust.public_key_spki_sha256),
    }


def _validate_artifact_core_against_replay(
    artifact_core: dict[str, Any], replay: dict[str, Any]
) -> None:
    manifest = replay["manifest"]
    expected = {
        "runId": manifest["runId"],
        "manifestSha256": replay["manifestSha256"],
        "dataRelease": replay["dataRelease"],
        "baseModel": {
            "candidateId": manifest["baseModel"]["candidateId"],
            "modelId": manifest["baseModel"]["modelId"],
            "revision": manifest["baseModel"]["revision"],
        },
        "datasetSnapshot": {
            "path": DATASET_BUNDLE_PATH,
            "sha256": replay["datasetSha256"],
            "recordCount": manifest["dataset"]["recordCount"],
        },
        "mode": "unpromoted-candidate",
        "productionEligible": False,
    }
    for name, expected_value in expected.items():
        if artifact_core.get(name) != expected_value:
            raise ValidationError(
                f"trainer provenance handoff artifact core.{name}: does not match "
                "the freshly replayed training inputs"
            )


def _validate_trainer_provenance_handoff(
    handoff_path: Path,
    *,
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    review_receipt_now: datetime | None,
    trainer_provenance_trust: TrainerProvenanceTrust,
    trainer_provenance_now: datetime | None,
) -> dict[str, Any]:
    root = _ensure_directory_no_reparse(handoff_path, "trainer provenance handoff")
    expected_names = {
        TRAINER_PROVENANCE_HANDOFF_ARTIFACT_DIRECTORY,
        TRAINER_PROVENANCE_HANDOFF_ARTIFACT_CORE_NAME,
        TRAINER_PROVENANCE_SIGNING_BUNDLE_NAME,
    }
    actual_names = {entry.name for entry in os.scandir(root)}
    if actual_names != expected_names:
        raise ValidationError(
            "trainer provenance handoff: must contain exactly the pending artifact, "
            "artifact core, and signing bundle"
        )
    artifact_path = _ensure_directory_no_reparse(
        root / TRAINER_PROVENANCE_HANDOFF_ARTIFACT_DIRECTORY,
        "trainer provenance pending artifact",
    )
    from .trainer_provenance import (
        MAX_TRAINER_PROVENANCE_ARTIFACT_CORE_BYTES,
        MAX_TRAINER_PROVENANCE_SIGNING_BUNDLE_BYTES,
        verify_trainer_provenance_signing_bundle,
    )

    core_path = _reject_reparse_components(
        root / TRAINER_PROVENANCE_HANDOFF_ARTIFACT_CORE_NAME,
        "trainer provenance handoff artifact core",
    )
    artifact_core = _load_exact_handoff_json(
        core_path,
        "trainer provenance handoff artifact core",
        MAX_TRAINER_PROVENANCE_ARTIFACT_CORE_BYTES + 1,
    )
    rebuilt_core = prepare_training_artifact_core(
        artifact_path,
        artifact_core,
        data_release_path=data_release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=evaluation_authoring_approval_trust,
        review_receipt_now=review_receipt_now,
    )
    if artifact_core != rebuilt_core:
        raise ValidationError(
            "trainer provenance handoff artifact core: does not match the current "
            "pending artifact tree"
        )
    bundle_path = _reject_reparse_components(
        root / TRAINER_PROVENANCE_SIGNING_BUNDLE_NAME,
        "trainer provenance signing bundle",
    )
    bundle = _load_exact_handoff_json(
        bundle_path,
        "trainer provenance signing bundle",
        MAX_TRAINER_PROVENANCE_SIGNING_BUNDLE_BYTES + 1,
    )
    verified_bundle = verify_trainer_provenance_signing_bundle(
        bundle,
        trust=trainer_provenance_trust,
        expected_artifact_core=rebuilt_core,
        now=trainer_provenance_now,
    )
    return {
        "artifactPath": artifact_path,
        "artifactCore": rebuilt_core,
        "bundle": bundle,
        "verifiedBundle": verified_bundle,
    }


def train_from_manifest(
    manifest_path: str | os.PathLike[str],
    *,
    minimum_gpu_memory_gib: float = PRODUCTION_MINIMUM_GPU_GIB,
    smoke: bool = False,
    data_release_path: str | os.PathLike[str] | None = None,
    review_receipt_trust: ExpertModelReviewReceiptTrust | None = None,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust | None = None,
    review_receipt_now: datetime | None = None,
    base_model_snapshot_path: str | os.PathLike[str] | None = None,
    base_selection_trust: BaseModelSelectionTrust | None = None,
    base_selection_now: datetime | None = None,
    corpus_admission_trust: TrainingCorpusAdmissionTrust | None = None,
    corpus_admission_now: datetime | None = None,
    trainer_provenance_trust: TrainerProvenanceTrust | None = None,
    trainer_private_key_path: str | os.PathLike[str] | None = None,
    trainer_private_key_password: bytes | None = None,
    trainer_provenance_handoff_path: str | os.PathLike[str] | None = None,
    trainer_id: str | None = None,
    trainer_issued_at_utc: str | None = None,
    trainer_not_before_utc: str | None = None,
    trainer_expires_at_utc: str | None = None,
    trainer_provenance_now: datetime | None = None,
    snapshot_read_only_probe: Callable[[Path], bool] = _snapshot_tree_is_read_only,
    importer: Callable[[str], Any] = importlib.import_module,
    _after_snapshot: Callable[[], None] | None = None,
    _after_in_memory_capture: Callable[[Path], None] | None = None,
    _after_base_snapshot_validation: Callable[[Path], None] | None = None,
    _base_selection_clock: Callable[[], datetime] | None = None,
    _corpus_admission_clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    path = Path(manifest_path)
    manifest = validate_manifest_path(path)
    manifest_version = manifest["schemaVersion"]
    v2_manifest = manifest_version == MANIFEST_V2_SCHEMA_VERSION
    v3_manifest = manifest_version == MANIFEST_V3_SCHEMA_VERSION
    selected_manifest = v2_manifest or v3_manifest
    if v2_manifest and not smoke:
        raise ValidationError(
            "manifest.schemaVersion: selected v2 manifests are validation-only and "
            "restricted to explicit non-production smoke runs; candidate training "
            "requires a v3 manifest with an authenticated corpus admission"
        )
    candidate_run = v3_manifest and not smoke
    trainer_required_values = (
        trainer_provenance_trust,
        trainer_id,
        trainer_expires_at_utc,
    )
    trainer_values = trainer_required_values + (
        trainer_private_key_path,
        trainer_provenance_handoff_path,
        trainer_issued_at_utc,
        trainer_not_before_utc,
    )
    has_trainer_provenance = any(value is not None for value in trainer_values)
    direct_trainer_signing = trainer_private_key_path is not None
    detached_trainer_signing = trainer_provenance_handoff_path is not None
    if direct_trainer_signing and detached_trainer_signing:
        raise ValidationError(
            "trainer provenance: direct private-key signing and detached handoff "
            "are mutually exclusive"
        )
    if trainer_private_key_password is not None and trainer_private_key_path is None:
        raise ValidationError(
            "trainer provenance private-key password: cannot be supplied without "
            "the trainer private key"
        )
    if has_trainer_provenance and (
        not all(value is not None for value in trainer_required_values)
        or not (direct_trainer_signing or detached_trainer_signing)
    ):
        raise ValidationError(
            "trainer provenance: trust, trainer ID, expiry, and exactly one of a "
            "private key or detached handoff path are required together"
        )
    if (trainer_issued_at_utc is None) != (trainer_not_before_utc is None):
        raise ValidationError(
            "trainer provenance: explicit issue and not-before times must be "
            "supplied together"
        )
    if trainer_provenance_now is not None and not has_trainer_provenance:
        raise ValidationError(
            "trainer provenance validation time: cannot be supplied without the "
            "complete trainer signing authority"
        )
    release_values = (
        data_release_path,
        review_receipt_trust,
        evaluation_authoring_approval_trust,
    )
    if any(value is not None for value in release_values) and not all(
        value is not None for value in release_values
    ):
        raise ValidationError(
            "training release authority: the release path, review-receipt trust, "
            "and evaluation-authoring approval trust are required together"
        )
    if review_receipt_now is not None and data_release_path is None:
        raise ValidationError(
            "training release validation time: cannot be supplied without the "
            "complete release authority"
        )
    if candidate_run and not has_trainer_provenance:
        raise ValidationError(
            "trainer provenance: direct signing or a detached signing handoff is "
            "required for every non-smoke candidate run"
        )
    if not candidate_run and has_trainer_provenance:
        raise ValidationError(
            "trainer provenance: cannot be supplied for a smoke or legacy run"
        )
    if not selected_manifest and (
        base_model_snapshot_path is not None or base_selection_trust is not None
    ):
        raise ValidationError(
            "base-model selection: cannot be supplied for a legacy v1 smoke manifest"
        )
    if v3_manifest and corpus_admission_trust is None:
        raise ValidationError(
            "training corpus admission trust: externally pinned trust is required "
            "for a selected v3 manifest"
        )
    if not v3_manifest and corpus_admission_trust is not None:
        raise ValidationError(
            "training corpus admission trust: cannot be supplied for a v1 or v2 "
            "smoke manifest"
        )
    if corpus_admission_now is not None and corpus_admission_trust is None:
        raise ValidationError(
            "training corpus admission validation time: cannot be supplied without "
            "the externally pinned admission trust"
        )
    if _corpus_admission_clock is not None and corpus_admission_trust is None:
        raise ValidationError(
            "training corpus admission clock: cannot be supplied without the "
            "externally pinned admission trust"
        )
    bound_release = manifest.get("dataRelease")
    if bound_release is None:
        if data_release_path is not None:
            raise ValidationError(
                "manifest.dataRelease: a release path cannot bind an unbound manifest"
            )
        raise ValidationError(
            "manifest.dataRelease: a validated training release with active "
            "authenticated review receipts is required for every training run, "
            "including smoke mode"
        )
    else:
        if data_release_path is None:
            raise ValidationError(
                "training release: the manifest-bound release path is required"
            )
        if review_receipt_trust is None:
            raise ValidationError(
                "review-receipt trust: externally supplied trust is required "
                "for the manifest-bound training release"
            )
        if evaluation_authoring_approval_trust is None:
            raise ValidationError(
                "evaluation-authoring approval trust: externally supplied trust "
                "is required for the manifest-bound training release"
            )
        from .release import validate_training_release_binding

        release, release_identity = validate_training_release_binding(
            data_release_path,
            dataset_sha256=manifest["dataset"]["sha256"],
            review_receipt_trust=review_receipt_trust,
            evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
            now=review_receipt_now,
        )
        if release_identity != bound_release:
            raise ValidationError(
                "manifest.dataRelease: does not match the fully validated training release"
            )
        receipt_expires_at = datetime.strptime(
            release["corpus"]["reviewReceipts"]["expiresAtUtc"],
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=timezone.utc)
        authoring_expires_at = datetime.strptime(
            release["evaluation"]["authoringApproval"]["expiresAtUtc"],
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=timezone.utc)
        release_authority_expires_at = min(receipt_expires_at, authoring_expires_at)
        if review_receipt_now is not None:

            def receipt_clock() -> datetime:
                return review_receipt_now

        else:

            def receipt_clock() -> datetime:
                return datetime.now(timezone.utc)

        def receipt_authorization_guard() -> None:
            _ensure_receipt_authorization_active(
                release_authority_expires_at, receipt_clock
            )

    source_dataset = resolve_bound_path(
        path.parent,
        manifest["dataset"]["path"],
        "manifest.dataset.path",
    )
    verified_corpus_admission = None
    corpus_admission_path: Path | None = None
    if v3_manifest:
        if corpus_admission_trust is None:  # pragma: no cover - guarded above
            raise ValidationError("training corpus admission trust is unavailable")
        corpus_admission_path = resolve_bound_path(
            path.parent,
            manifest["trainingCorpusAdmission"]["path"],
            "manifest.trainingCorpusAdmission.path",
        )
        from .corpus_quality import verify_training_corpus_admission_file

        verified_corpus_admission = verify_training_corpus_admission_file(
            corpus_admission_path,
            dataset_bytes=_read_file_bounded(
                source_dataset,
                "training corpus admission dataset",
                MAX_SFT_BYTES,
            ),
            dataset_source_path=source_dataset,
            expected_data_release=bound_release,
            trust=corpus_admission_trust,
            expected_envelope_sha256=manifest["trainingCorpusAdmission"][
                "envelopeSha256"
            ],
            now=corpus_admission_now,
        )
        expected_corpus_admission_binding = {
            "path": TRAINING_CORPUS_ADMISSION_BUNDLE_PATH,
            **verified_corpus_admission.as_dict(),
        }
        if manifest["trainingCorpusAdmission"] != expected_corpus_admission_binding:
            raise ValidationError(
                "manifest.trainingCorpusAdmission: does not match the verified "
                "signed admission"
            )
        admission_expires_at = verified_corpus_admission.expires_at_utc
        if _corpus_admission_clock is not None:

            def corpus_admission_clock() -> datetime:
                return _corpus_admission_clock()

        elif corpus_admission_now is not None:

            def corpus_admission_clock() -> datetime:
                return corpus_admission_now

        else:

            def corpus_admission_clock() -> datetime:
                return datetime.now(timezone.utc)

        def corpus_admission_authorization_guard() -> None:
            _ensure_corpus_admission_active(
                admission_expires_at, corpus_admission_clock
            )

    else:

        def corpus_admission_authorization_guard() -> None:
            return None

    if not selected_manifest and not smoke:
        raise ValidationError(
            "manifest.schemaVersion: legacy v1 manifests are restricted to explicit "
            "non-production smoke runs; real training requires a signed v3 base-model "
            "selection and authenticated corpus admission"
        )

    selected_target = None
    model_source_path: Path | None = None
    selection_path: Path | None = None
    selection_target_arguments: dict[str, Any] | None = None
    if selected_manifest:
        if base_model_snapshot_path is None:
            raise ValidationError(
                "base-model snapshot: the manifest-selected immutable snapshot directory is required"
            )
        if base_selection_trust is None:
            raise ValidationError(
                "base-model selection trust: externally pinned trust is required"
            )
        if v3_manifest:
            if verified_corpus_admission is None:  # pragma: no cover - guarded above
                raise ValidationError(
                    "training corpus admission: validated state is unavailable"
                )
            admission_upstream_signers = {
                review_receipt_trust.public_key_spki_sha256,
                evaluation_authoring_approval_trust.public_key_spki_sha256,
                base_selection_trust.public_key_spki_sha256,
            }
            teacher_lineage_trust = review_receipt_trust.teacher_lineage_admission_trust
            if teacher_lineage_trust is not None:
                admission_upstream_signers.add(
                    teacher_lineage_trust.public_key_spki_sha256
                )
            if (
                verified_corpus_admission.public_key_spki_sha256
                in admission_upstream_signers
            ):
                raise ValidationError(
                    "training corpus admission signer: must differ from corpus "
                    "review, teacher-lineage, evaluation-authoring, and base-selection signers"
                )
        if candidate_run:
            if trainer_provenance_trust is None:  # pragma: no cover - guarded above
                raise ValidationError("trainer provenance: trust is unavailable")
            upstream_signers = {
                review_receipt_trust.public_key_spki_sha256,
                evaluation_authoring_approval_trust.public_key_spki_sha256,
                base_selection_trust.public_key_spki_sha256,
            }
            teacher_lineage_trust = review_receipt_trust.teacher_lineage_admission_trust
            if teacher_lineage_trust is not None:
                upstream_signers.add(teacher_lineage_trust.public_key_spki_sha256)
            if verified_corpus_admission is not None:
                upstream_signers.add(verified_corpus_admission.public_key_spki_sha256)
            if trainer_provenance_trust.public_key_spki_sha256 in upstream_signers:
                raise ValidationError(
                    "trainer provenance signer: must differ from corpus review, "
                    "teacher-lineage, evaluation-authoring, base-selection, and corpus-admission signers"
                )
            from .trainer_provenance import (
                validate_trainer_provenance_preparation_authority,
                validate_trainer_provenance_signing_authority,
            )

            authority_arguments = {
                "trust": trainer_provenance_trust,
                "trainer_id": trainer_id,
                "expires_at_utc": trainer_expires_at_utc,
                "issued_at_utc": trainer_issued_at_utc,
                "not_before_utc": trainer_not_before_utc,
                "now": trainer_provenance_now,
            }
            if direct_trainer_signing:
                validate_trainer_provenance_signing_authority(
                    private_key_path=trainer_private_key_path,
                    private_key_password=trainer_private_key_password,
                    **authority_arguments,
                )
            else:
                validate_trainer_provenance_preparation_authority(**authority_arguments)
        model_source_path = Path(os.path.abspath(os.fspath(base_model_snapshot_path)))
        if not snapshot_read_only_probe(model_source_path):
            raise ValidationError(
                "base-model snapshot: must be held under read-only custody for training"
            )
        from .base_selection import validate_base_model_selection_target

        selection_path = resolve_bound_path(
            path.parent,
            manifest["baseModelSelection"]["path"],
            "manifest.baseModelSelection.path",
        )
        selection_target_arguments = {
            "trust": base_selection_trust,
            "evaluation_authoring_approval_trust": (
                evaluation_authoring_approval_trust
            ),
            "review_receipt_trust": review_receipt_trust,
            "profile_path": resolve_bound_path(
                path.parent,
                BASE_EVALUATION_PROFILE_BUNDLE_PATH,
                "manifest.baseModelSnapshot.profile.path",
            ),
            "snapshot_manifest_path": resolve_bound_path(
                path.parent,
                BASE_MODEL_SNAPSHOT_MANIFEST_BUNDLE_PATH,
                "manifest.baseModelSnapshot.manifest.path",
            ),
            "snapshot_path": model_source_path,
            "catalog_path": resolve_bound_path(
                path.parent,
                manifest["candidateCatalog"]["path"],
                "manifest.candidateCatalog.path",
            ),
            "source_lock_path": resolve_bound_path(
                path.parent,
                BASE_MODEL_SOURCE_LOCK_BUNDLE_PATH,
                "manifest.baseModelSnapshot.sourceLock.path",
            ),
            "now": base_selection_now,
        }
        selected_target = validate_base_model_selection_target(
            selection_path, **selection_target_arguments
        )
        model_source_path = selected_target.snapshot.snapshot_path
        selection_target_arguments["snapshot_path"] = model_source_path
        selection = selected_target.selection
        if selection.payload["dataRelease"] != bound_release:
            raise ValidationError(
                "base-model selection payload.dataRelease: does not match the "
                "manifest-bound training release"
            )
        expected_selection_binding = {
            "path": BASE_SELECTION_BUNDLE_PATH,
            "envelopeSha256": selection.envelope_sha256,
            "payloadSha256": selection.payload_sha256,
            "selectionId": selection.payload["selectionId"],
            "expiresAtUtc": selection.payload["expiresAtUtc"],
        }
        if manifest["baseModelSelection"] != expected_selection_binding:
            raise ValidationError(
                "manifest.baseModelSelection: does not match the verified signed selection"
            )
        selection_expires_at = datetime.strptime(
            selection.payload["expiresAtUtc"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        if _base_selection_clock is not None:

            def selection_clock() -> datetime:
                return _base_selection_clock()

        elif base_selection_now is not None:

            def selection_clock() -> datetime:
                return base_selection_now

        else:

            def selection_clock() -> datetime:
                return datetime.now(timezone.utc)

        def selection_authorization_guard() -> None:
            _ensure_selection_authorization_active(
                selection_expires_at, selection_clock
            )

        if _after_base_snapshot_validation is not None:
            _after_base_snapshot_validation(model_source_path)
    else:

        def selection_authorization_guard() -> None:
            return None

    def authorization_guard() -> None:
        receipt_authorization_guard()
        selection_authorization_guard()
        corpus_admission_authorization_guard()

    def base_integrity_guard() -> None:
        authorization_guard()
        if not selected_manifest:
            return
        if (
            selection_path is None
            or selection_target_arguments is None
            or model_source_path is None
            or selected_target is None
        ):
            raise ValidationError(
                "base-model selection: validated state is unavailable"
            )
        if not snapshot_read_only_probe(model_source_path):
            raise ValidationError(
                "base-model snapshot: lost read-only custody during training"
            )
        current_target = validate_base_model_selection_target(
            selection_path, **selection_target_arguments
        )
        if (
            current_target.selection.envelope_sha256
            != selected_target.selection.envelope_sha256
            or current_target.snapshot.document != selected_target.snapshot.document
            or current_target.profile.document != selected_target.profile.document
        ):
            raise ValidationError(
                "base-model selection: changed while the training run was active"
            )

    runtime_profile_path = resolve_bound_path(
        path.parent,
        manifest["trainingRuntime"]["profile"]["path"],
        "manifest.trainingRuntime.profile.path",
    )
    runtime_profile = validate_training_runtime_profile(runtime_profile_path)
    validate_runtime_host(runtime_profile, error_type=PreflightError)
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    dependencies = load_training_dependencies(importer)
    dependency_versions = _dependency_versions(dependencies)
    validate_runtime_environment(
        runtime_profile,
        dependencies,
        dependency_versions=dependency_versions,
        error_type=PreflightError,
    )
    torch = dependencies["torch"]
    gpu = gpu_memory_preflight(torch, minimum_gib=minimum_gpu_memory_gib, smoke=smoke)
    compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    output_path = resolve_bound_path(
        path.parent,
        manifest["outputPath"],
        "manifest.outputPath",
        allow_missing_suffix=True,
    )
    handoff_path: Path | None = None
    if detached_trainer_signing:
        if trainer_provenance_handoff_path is None:  # pragma: no cover - guarded above
            raise ValidationError("trainer provenance handoff path is unavailable")
        handoff_path = Path(os.path.abspath(os.fspath(trainer_provenance_handoff_path)))
        _reject_reparse_components(
            handoff_path,
            "trainer provenance handoff",
            allow_missing_suffix=True,
        )
        if handoff_path.parent != output_path.parent:
            raise ValidationError(
                "trainer provenance handoff: must be a sibling of the manifest-bound "
                "training output"
            )
        if handoff_path == output_path:
            raise ValidationError(
                "trainer provenance handoff: must differ from the final training output"
            )
    with _exclusive_destination_lock(output_path, "training output") as locked_output:
        if os.path.lexists(locked_output):
            raise ValidationError(
                "manifest.outputPath: already exists; training outputs are never overwritten"
            )
        if handoff_path is not None and os.path.lexists(handoff_path):
            raise ValidationError(
                "trainer provenance handoff: already exists; pending outputs are never overwritten"
            )
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{locked_output.name}.training-",
                dir=locked_output.parent,
            )
        )
        stage_ownership = _capture_directory_ownership(
            stage, "training staging directory"
        )
        staged_output_ownership: _DirectoryOwnership | None = None
        try:
            private_inputs = stage / "private-inputs"
            private_inputs.mkdir()
            manifest_snapshot = _copy_file_snapshot(
                path,
                private_inputs / MANIFEST_BUNDLE_PATH,
                "training manifest",
                max_bytes=MAX_JSON_BYTES,
            )
            if load_json_document(manifest_snapshot) != manifest:
                raise ValidationError("training manifest: changed after validation")
            manifest_sha256 = sha256_file(manifest_snapshot, max_bytes=MAX_JSON_BYTES)
            dataset_snapshot = _copy_file_snapshot(
                source_dataset,
                private_inputs / "dataset.sft.jsonl",
                "training dataset",
                max_bytes=MAX_SFT_BYTES,
            )
            corpus_admission_snapshot: Path | None = None
            if v3_manifest:
                if corpus_admission_path is None:  # pragma: no cover - guarded above
                    raise ValidationError(
                        "training corpus admission: source path is unavailable"
                    )
                from .corpus_quality import MAX_CORPUS_ADMISSION_BYTES

                corpus_admission_snapshot = _copy_file_snapshot(
                    corpus_admission_path,
                    private_inputs / "training-corpus-admission-envelope.json",
                    "training corpus admission envelope",
                    max_bytes=MAX_CORPUS_ADMISSION_BYTES + 1,
                )
            if _after_snapshot is not None:
                _after_snapshot()
            dataset_snapshot_bytes = _read_file_bounded(
                dataset_snapshot,
                "private training snapshot",
                MAX_SFT_BYTES,
            )
            summary, records = _validate_dataset_snapshot(
                dataset_snapshot_bytes,
                dataset_snapshot,
                manifest,
            )
            if v3_manifest:
                if (
                    corpus_admission_snapshot is None
                    or corpus_admission_trust is None
                    or verified_corpus_admission is None
                ):  # pragma: no cover - guarded above
                    raise ValidationError(
                        "training corpus admission: captured validation state is unavailable"
                    )
                captured_corpus_admission = verify_training_corpus_admission_file(
                    corpus_admission_snapshot,
                    dataset_bytes=dataset_snapshot_bytes,
                    dataset_source_path=dataset_snapshot,
                    expected_data_release=bound_release,
                    trust=corpus_admission_trust,
                    expected_envelope_sha256=manifest["trainingCorpusAdmission"][
                        "envelopeSha256"
                    ],
                    now=corpus_admission_now,
                )
                if (
                    captured_corpus_admission.as_dict()
                    != verified_corpus_admission.as_dict()
                ):
                    raise ValidationError(
                        "training corpus admission: changed after initial validation"
                    )
            if _after_in_memory_capture is not None:
                _after_in_memory_capture(dataset_snapshot)

            staged_output = stage / "artifact"
            staged_output.mkdir()
            staged_output_ownership = _capture_directory_ownership(
                staged_output, "training artifact staging directory"
            )
            _run_training(
                manifest,
                dependencies,
                records,
                staged_output,
                smoke=smoke,
                compute_dtype=compute_dtype,
                authorization_guard=authorization_guard,
                model_source_path=model_source_path,
                integrity_guard=base_integrity_guard if selected_manifest else None,
            )
            if selected_manifest:
                if model_source_path is None:
                    raise ValidationError(
                        "base-model snapshot: validated state is unavailable"
                    )
                _sanitize_and_reject_snapshot_path_leaks(
                    staged_output,
                    snapshot_path=model_source_path,
                    model_id=manifest["baseModel"]["modelId"],
                )
                base_integrity_guard()
            artifact_metadata = _artifact_metadata(
                manifest=manifest,
                manifest_sha256=manifest_sha256,
                dependency_versions=dependency_versions,
                dataset_sha256=summary.sha256,
                dataset_record_count=summary.record_count,
                compute_dtype=compute_dtype,
                gpu=gpu,
                smoke=smoke,
            )
            detached_bundle = None
            if detached_trainer_signing:
                if (
                    handoff_path is None
                    or trainer_provenance_trust is None
                    or trainer_id is None
                    or trainer_expires_at_utc is None
                ):  # pragma: no cover - guarded above
                    raise ValidationError(
                        "trainer provenance handoff authority is unavailable"
                    )
                artifact_core = prepare_training_artifact_core(
                    staged_output,
                    artifact_metadata,
                    data_release_path=data_release_path,
                    review_receipt_trust=review_receipt_trust,
                    evaluation_authoring_approval_trust=(
                        evaluation_authoring_approval_trust
                    ),
                    review_receipt_now=review_receipt_now,
                )
                resolved_issued_at_utc = trainer_issued_at_utc
                resolved_not_before_utc = trainer_not_before_utc
                if resolved_issued_at_utc is None and resolved_not_before_utc is None:
                    signing_time = trainer_provenance_now or datetime.now(timezone.utc)
                    if getattr(signing_time, "tzinfo", None) is None:
                        raise ValidationError(
                            "trainer provenance signing time: must be timezone-aware"
                        )
                    signing_second = signing_time.astimezone(timezone.utc).replace(
                        microsecond=0
                    )
                    resolved_issued_at_utc = signing_second.strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    resolved_not_before_utc = resolved_issued_at_utc
                from .trainer_provenance import (
                    prepare_trainer_provenance_signing_bundle,
                )

                detached_bundle = prepare_trainer_provenance_signing_bundle(
                    artifact_core=artifact_core,
                    trust=trainer_provenance_trust,
                    issued_at_utc=resolved_issued_at_utc,
                    not_before_utc=resolved_not_before_utc,
                    expires_at_utc=trainer_expires_at_utc,
                    trainer_id=trainer_id,
                    now=trainer_provenance_now,
                )
                shutil.rmtree(private_inputs)
                _write_json_exclusive(
                    stage / TRAINER_PROVENANCE_HANDOFF_ARTIFACT_CORE_NAME,
                    artifact_core,
                )
                _write_json_exclusive(
                    stage / TRAINER_PROVENANCE_SIGNING_BUNDLE_NAME,
                    detached_bundle.bundle,
                )

                def validate_handoff(location: Path) -> dict[str, Any]:
                    verified = _validate_trainer_provenance_handoff(
                        location,
                        data_release_path=data_release_path,
                        review_receipt_trust=review_receipt_trust,
                        evaluation_authoring_approval_trust=(
                            evaluation_authoring_approval_trust
                        ),
                        review_receipt_now=review_receipt_now,
                        trainer_provenance_trust=trainer_provenance_trust,
                        trainer_provenance_now=trainer_provenance_now,
                    )
                    if (
                        verified["artifactCore"] != artifact_core
                        or verified["verifiedBundle"].bundle_id
                        != detached_bundle.bundle_id
                    ):
                        raise ValidationError(
                            "trainer provenance handoff: changed during publication"
                        )
                    base_integrity_guard()
                    return verified

                with _exclusive_destination_lock(
                    handoff_path, "trainer provenance handoff"
                ) as locked_handoff:
                    if os.path.lexists(locked_handoff):
                        raise ValidationError(
                            "trainer provenance handoff: already exists; pending "
                            "outputs are never overwritten"
                        )
                    _publish_directory_no_clobber(
                        stage,
                        locked_handoff,
                        "trainer provenance handoff",
                        validator=validate_handoff,
                    )
                metadata = artifact_core
            else:
                metadata = seal_training_artifact(
                    staged_output,
                    artifact_metadata,
                    data_release_path=data_release_path,
                    review_receipt_trust=review_receipt_trust,
                    evaluation_authoring_approval_trust=(
                        evaluation_authoring_approval_trust
                    ),
                    review_receipt_now=review_receipt_now,
                    trainer_provenance_trust=trainer_provenance_trust,
                    trainer_private_key_path=trainer_private_key_path,
                    trainer_private_key_password=trainer_private_key_password,
                    trainer_id=trainer_id,
                    trainer_issued_at_utc=trainer_issued_at_utc,
                    trainer_not_before_utc=trainer_not_before_utc,
                    trainer_expires_at_utc=trainer_expires_at_utc,
                    trainer_provenance_now=trainer_provenance_now,
                )

                def validate_sealed_output(location: Path) -> dict[str, Any]:
                    validated = validate_training_artifact(
                        location,
                        trainer_provenance_trust=trainer_provenance_trust,
                        trainer_provenance_now=(
                            (trainer_provenance_now or datetime.now(timezone.utc))
                            if candidate_run
                            else None
                        ),
                    )
                    if (
                        validated["artifactSha256"] != metadata["artifactSha256"]
                        or validated["fileTreeSha256"] != metadata["fileTreeSha256"]
                    ):
                        raise ValidationError(
                            "training artifact: changed after provenance sealing"
                        )
                    base_integrity_guard()
                    return validated

                _publish_directory_no_clobber(
                    staged_output,
                    locked_output,
                    "training output",
                    validator=validate_sealed_output,
                )
        finally:
            protected_children = (
                ((staged_output, staged_output_ownership),)
                if staged_output_ownership is not None
                else ()
            )
            _cleanup_owned_stage(
                stage,
                stage_ownership,
                "training staging directory",
                protected_children=protected_children,
            )

    mode = "smoke" if smoke else "unpromoted-candidate"
    if detached_bundle is not None and handoff_path is not None:
        result = {
            "runId": manifest["runId"],
            "mode": "unsealed-candidate-handoff",
            "productionEligible": False,
            "finalOutputPath": str(output_path),
            "handoffPath": str(handoff_path),
            "artifactCoreSha256": detached_bundle.artifact_core_sha256,
            "fileTreeSha256": metadata["fileTreeSha256"],
            **detached_bundle.as_dict(),
            "gpuPreflight": gpu,
        }
    else:
        result = {
            "runId": manifest["runId"],
            "outputPath": str(output_path),
            "mode": mode,
            "productionEligible": False,
            "artifactSha256": metadata["artifactSha256"],
            "fileTreeSha256": metadata["fileTreeSha256"],
            "gpuPreflight": gpu,
        }
    if selected_target is not None:
        result["baseModelSelectionId"] = selected_target.selection.payload[
            "selectionId"
        ]
    if verified_corpus_admission is not None:
        result["corpusAdmissionId"] = verified_corpus_admission.payload[
            "corpusAdmissionId"
        ]
    return result


def finalize_training_artifact_from_handoff(
    manifest_path: str | os.PathLike[str],
    handoff_path: str | os.PathLike[str],
    external_signature_path: str | os.PathLike[str],
    *,
    data_release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    base_model_snapshot_path: str | os.PathLike[str],
    base_selection_trust: BaseModelSelectionTrust,
    corpus_admission_trust: TrainingCorpusAdmissionTrust,
    trainer_provenance_trust: TrainerProvenanceTrust,
    review_receipt_now: datetime | None = None,
    base_selection_now: datetime | None = None,
    corpus_admission_now: datetime | None = None,
    trainer_provenance_now: datetime | None = None,
    snapshot_read_only_probe: Callable[[Path], bool] = _snapshot_tree_is_read_only,
) -> dict[str, Any]:
    """Finalize one pending candidate without loading a private signing key."""

    replay_arguments = {
        "data_release_path": data_release_path,
        "review_receipt_trust": review_receipt_trust,
        "evaluation_authoring_approval_trust": (evaluation_authoring_approval_trust),
        "review_receipt_now": review_receipt_now,
        "base_model_snapshot_path": base_model_snapshot_path,
        "base_selection_trust": base_selection_trust,
        "base_selection_now": base_selection_now,
        "corpus_admission_trust": corpus_admission_trust,
        "corpus_admission_now": corpus_admission_now,
        "trainer_provenance_trust": trainer_provenance_trust,
        "snapshot_read_only_probe": snapshot_read_only_probe,
    }
    initial_replay = _replay_candidate_training_authorities(
        manifest_path, **replay_arguments
    )
    output_path = Path(initial_replay["outputPath"])
    pending_path = Path(os.path.abspath(os.fspath(handoff_path)))
    if pending_path.parent != output_path.parent or pending_path == output_path:
        raise ValidationError(
            "trainer provenance handoff: must be the sibling pending output for "
            "the manifest-bound final artifact"
        )
    handoff_arguments = {
        "data_release_path": data_release_path,
        "review_receipt_trust": review_receipt_trust,
        "evaluation_authoring_approval_trust": (evaluation_authoring_approval_trust),
        "review_receipt_now": review_receipt_now,
        "trainer_provenance_trust": trainer_provenance_trust,
        "trainer_provenance_now": trainer_provenance_now,
    }
    initial_handoff = _validate_trainer_provenance_handoff(
        pending_path, **handoff_arguments
    )
    artifact_core = initial_handoff["artifactCore"]
    _validate_artifact_core_against_replay(artifact_core, initial_replay)

    from .trainer_provenance import (
        MAX_TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_BYTES,
        finalize_trainer_provenance_envelope,
    )

    signature_path = _reject_reparse_components(
        Path(external_signature_path),
        "trainer provenance external signature",
    )
    external_signature = _load_exact_handoff_json(
        signature_path,
        "trainer provenance external signature",
        MAX_TRAINER_PROVENANCE_EXTERNAL_SIGNATURE_BYTES + 1,
    )
    with _exclusive_destination_lock(output_path, "training output") as locked_output:
        if os.path.lexists(locked_output):
            raise ValidationError(
                "manifest.outputPath: already exists; training outputs are never overwritten"
            )
        current_replay = _replay_candidate_training_authorities(
            manifest_path, **replay_arguments
        )
        if current_replay != initial_replay:
            raise ValidationError(
                "trainer provenance handoff: live training inputs changed before "
                "finalization"
            )
        current_handoff = _validate_trainer_provenance_handoff(
            pending_path, **handoff_arguments
        )
        if (
            current_handoff["artifactCore"] != artifact_core
            or current_handoff["verifiedBundle"].bundle_id
            != initial_handoff["verifiedBundle"].bundle_id
        ):
            raise ValidationError(
                "trainer provenance handoff: pending material changed before finalization"
            )
        verified_provenance = finalize_trainer_provenance_envelope(
            current_handoff["bundle"],
            external_signature,
            trust=trainer_provenance_trust,
            expected_artifact_core=artifact_core,
            now=trainer_provenance_now,
        )

        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{locked_output.name}.finalizing-",
                dir=locked_output.parent,
            )
        )
        stage_ownership = _capture_directory_ownership(
            stage, "training finalization staging directory"
        )
        staged_output_ownership: _DirectoryOwnership | None = None
        try:
            staged_output = stage / "artifact"
            shutil.copytree(
                current_handoff["artifactPath"],
                staged_output,
                symlinks=True,
            )
            staged_output_ownership = _capture_directory_ownership(
                staged_output, "training finalization artifact staging directory"
            )
            finalized = finalize_training_artifact_core(
                staged_output,
                artifact_core,
                verified_provenance.envelope,
                trainer_provenance_trust=trainer_provenance_trust,
                trainer_provenance_now=trainer_provenance_now,
            )
            post_copy_replay = _replay_candidate_training_authorities(
                manifest_path, **replay_arguments
            )
            if post_copy_replay != initial_replay:
                raise ValidationError(
                    "trainer provenance handoff: live training inputs changed during "
                    "finalization"
                )

            def validate_final_output(location: Path) -> dict[str, Any]:
                validated = validate_training_artifact(
                    location,
                    trainer_provenance_trust=trainer_provenance_trust,
                    trainer_provenance_now=(
                        trainer_provenance_now or datetime.now(timezone.utc)
                    ),
                )
                if (
                    validated["artifactSha256"] != finalized["artifactSha256"]
                    or validated["fileTreeSha256"] != finalized["fileTreeSha256"]
                ):
                    raise ValidationError(
                        "trainer provenance handoff: finalized artifact changed during "
                        "publication"
                    )
                installed_replay = _replay_candidate_training_authorities(
                    manifest_path, **replay_arguments
                )
                if installed_replay != initial_replay:
                    raise ValidationError(
                        "trainer provenance handoff: live training inputs changed during "
                        "publication"
                    )
                return validated

            installed = _publish_directory_no_clobber(
                staged_output,
                locked_output,
                "training output",
                validator=validate_final_output,
            )
        finally:
            protected_children = (
                ((staged_output, staged_output_ownership),)
                if staged_output_ownership is not None
                else ()
            )
            _cleanup_owned_stage(
                stage,
                stage_ownership,
                "training finalization staging directory",
                protected_children=protected_children,
            )

    return {
        "runId": installed["runId"],
        "outputPath": str(output_path),
        "mode": installed["mode"],
        "productionEligible": False,
        "artifactSha256": installed["artifactSha256"],
        "fileTreeSha256": installed["fileTreeSha256"],
        "trainerProvenanceId": verified_provenance.payload["trainerProvenanceId"],
        "trainerProvenanceEnvelopeSha256": verified_provenance.envelope_sha256,
        "signingBundleId": initial_handoff["verifiedBundle"].bundle_id,
    }
