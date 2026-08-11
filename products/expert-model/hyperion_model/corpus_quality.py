from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from pathlib import Path
from typing import Any, TypeVar

from .core import (
    DOMAINS,
    MAX_SFT_BYTES,
    MAX_SFT_RECORDS,
    ORIGINS,
    TASK_KINDS,
    ValidationError,
    _exact_keys,
    _fail,
    _integer,
    _load_json_object_bytes,
    _read_file_bounded,
    _reject_reparse_components,
    _regular_file,
    _sha256,
    _string,
    _validate_data_release_identity,
    canonical_json_bytes,
    parse_sft_bytes,
)
from .verifier_authority import (
    _base64url_decode,
    _base64url_encode,
    _crypto_modules,
    _load_private_key,
    _load_public_key,
    _sign_p1363_low_s,
    _verify_p1363_low_s,
)


CORPUS_QUALITY_REPORT_SCHEMA_VERSION = (
    "daxalgo.hyperion.training-corpus-quality-report/v1"
)
CORPUS_QUALITY_POLICY_SCHEMA_VERSION = (
    "daxalgo.hyperion.training-corpus-quality-policy/v1"
)
CORPUS_ADMISSION_SCHEMA_VERSION = "daxalgo.hyperion.training-corpus-admission/v1"
CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION = (
    "daxalgo.hyperion.training-corpus-admission-envelope/v1"
)
CORPUS_ADMISSION_SCOPE = "exact-released-training-corpus-admission-only"
CORPUS_ADMISSION_PAYLOAD_ENCODING = "canonical-json-base64url"
CORPUS_ADMISSION_ALGORITHM = "ES256"
CORPUS_ADMISSION_SIGNATURE_FORMAT = "ieee-p1363-low-s"
CORPUS_ADMISSION_ID_PREFIX = "vqcorpusadmit-"
CORPUS_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION = (
    "daxalgo.hyperion.training-corpus-admission-signing-bundle/v1"
)
CORPUS_ADMISSION_SIGNATURE_SCHEMA_VERSION = (
    "daxalgo.hyperion.training-corpus-admission-signature/v1"
)
CORPUS_ADMISSION_SIGNING_BUNDLE_ID_PREFIX = "vqcorpusadmissionsigning-"
CORPUS_ADMISSION_SIGNATURE_ID_PREFIX = "vqcorpusadmissionsignature-"
CORPUS_ADMISSION_SIGNING_STATUS = "unsigned-non-authorizing"
CORPUS_ADMISSION_SIGNING_HASH_ALGORITHM = "SHA-256"
CORPUS_ADMISSION_SIGNING_MESSAGE_TYPE = "digest"
CORPUS_ADMISSION_SIGNING_INPUT_ENCODING = "base64url"
CORPUS_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT = "asn1-der"
CORPUS_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT = "ieee-p1363-fixed-64"
CORPUS_ADMISSION_STATEMENT = (
    "This signed decision authorizes only the reviewer-selected corpus quality "
    "floor for the exact released dataset and report. It does not establish "
    "rights, review-receipt validity, release, training execution, evaluation, "
    "promotion, deployment, hosted serving, installation, verifier execution, "
    "or strategy execution authority."
)

MAX_CORPUS_ADMISSION_BYTES = 1_000_000
MAX_CORPUS_ADMISSION_PAYLOAD_BYTES = 750_000
MAX_CORPUS_ADMISSION_VALIDITY = timedelta(days=366)
MAX_CORPUS_ADMISSION_SIGNING_BUNDLE_BYTES = 4_000_000
MAX_CORPUS_ADMISSION_SIGNATURE_BYTES = 16_000
MAX_CORPUS_ADMISSION_SIGNATURE_INPUT_BYTES = 1_500_000
MAX_CORPUS_ADMISSION_DER_SIGNATURE_BYTES = 80
MAX_RATIONAL_COMPONENT = 1_000_000_000

_ZERO_SHA256 = "0" * 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_POLICY_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_SIGNATURE_DOMAIN = b"daxalgo-training-corpus-admission-signature/v1\x00"
_ID_DOMAIN = b"daxalgo-training-corpus-admission-id/v1\x00"
_SIGNING_BUNDLE_ID_DOMAIN = (
    b"daxalgo-training-corpus-admission-signing-bundle-id/v1\x00"
)
_EXTERNAL_SIGNATURE_ID_DOMAIN = (
    b"daxalgo-training-corpus-admission-external-signature-id/v1\x00"
)
_CORPUS_ADMISSION_ID_RE = re.compile(r"^vqcorpusadmit-[0-9a-f]{64}$")
_SIGNING_BUNDLE_ID_RE = re.compile(r"^vqcorpusadmissionsigning-[0-9a-f]{64}$")
_EXTERNAL_SIGNATURE_ID_RE = re.compile(r"^vqcorpusadmissionsignature-[0-9a-f]{64}$")
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)
_P256_HALF_ORDER = _P256_ORDER // 2
_Validated = TypeVar("_Validated")

_DATASET_KEYS = {
    "sha256",
    "byteCount",
    "recordCount",
    "sourceSchemaVersions",
}
_REPORT_KEYS = {
    "schemaVersion",
    "dataset",
    "taskCounts",
    "domainCounts",
    "domainTaskCounts",
    "domainContaminationGroups",
    "contaminationGroupCounts",
    "originCounts",
    "producerCounts",
    "distinctCounts",
    "concentration",
}
_POLICY_KEYS = {
    "schemaVersion",
    "policyVersion",
    "minimumRecordCount",
    "minimumTaskCounts",
    "minimumDomainWeightedCounts",
    "minimumDomainTaskWeightedCounts",
    "minimumDistinctContaminationGroupsByDomain",
    "minimumDistinctContaminationGroups",
    "minimumDistinctOrigins",
    "minimumDistinctProducers",
    "maximumDomainsPerRecord",
    "maximumShares",
}
_PAYLOAD_KEYS = {
    "schemaVersion",
    "corpusAdmissionId",
    "scope",
    "decision",
    "reusable",
    "corpusAdmissionAuthorized",
    "rightsAuthorized",
    "reviewReceiptAuthorized",
    "releaseAuthorized",
    "trainingAuthorized",
    "evaluationAuthorized",
    "promotionDecisionAuthorized",
    "deploymentAuthorized",
    "hostedServingAuthorized",
    "installationAuthorized",
    "verifierExecutionAuthorized",
    "strategyExecutionAuthorized",
    "reviewedAtUtc",
    "issuedAtUtc",
    "notBeforeUtc",
    "expiresAtUtc",
    "reviewerId",
    "dataRelease",
    "dataset",
    "qualityReport",
    "qualityReportSha256",
    "qualityPolicy",
    "qualityPolicySha256",
    "statement",
}
_ENVELOPE_KEYS = {
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
}


@dataclass(frozen=True)
class TrainingCorpusAdmissionTrust:
    public_key_path: Path
    public_key_spki_sha256: str
    audience: str
    key_id: str
    signer_role: str
    quality_policy_sha256: str


@dataclass(frozen=True)
class VerifiedTrainingCorpusAdmission:
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
            "corpusAdmissionId": self.payload["corpusAdmissionId"],
            "payloadSha256": self.payload_sha256,
            "envelopeSha256": self.envelope_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "qualityPolicySha256": self.payload["qualityPolicySha256"],
            "qualityReportSha256": self.payload["qualityReportSha256"],
            "notBeforeUtc": self.payload["notBeforeUtc"],
            "expiresAtUtc": self.payload["expiresAtUtc"],
        }


@dataclass(frozen=True)
class VerifiedTrainingCorpusAdmissionSigningBundle:
    path: Path
    bundle: dict[str, Any]
    bundle_sha256: str
    bundle_id: str
    corpus_admission_id: str
    payload_sha256: str
    public_key_spki_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "signingBundlePath": str(self.path),
            "signingBundleSha256": self.bundle_sha256,
            "signingBundleId": self.bundle_id,
            "corpusAdmissionId": self.corpus_admission_id,
            "payloadSha256": self.payload_sha256,
            "publicKeySpkiSha256": self.public_key_spki_sha256,
            "qualityPolicySha256": self.bundle["qualityPolicySha256"],
            "qualityReportSha256": self.bundle["qualityReportSha256"],
            "status": CORPUS_ADMISSION_SIGNING_STATUS,
        }


def _object(value: Any, expected: Iterable[str], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail(field, "must be an object")
    document = dict(value)
    if any(not isinstance(key, str) for key in document):
        _fail(field, "must use string keys")
    return _exact_keys(document, expected, field)


def _identifier(value: Any, field: str) -> str:
    text = _string(value, field, max_length=128)
    if not _IDENTIFIER_RE.fullmatch(text):
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


def _fraction_dict(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def _fraction(value: Any, field: str, *, maximum_one: bool = False) -> Fraction:
    item = _object(value, {"numerator", "denominator"}, field)
    numerator = _integer(
        item["numerator"], f"{field}.numerator", 0, MAX_RATIONAL_COMPONENT
    )
    denominator = _integer(
        item["denominator"], f"{field}.denominator", 1, MAX_RATIONAL_COMPONENT
    )
    result = Fraction(numerator, denominator)
    if result.numerator != numerator or result.denominator != denominator:
        _fail(field, "must use canonical lowest terms")
    if maximum_one and result > 1:
        _fail(field, "must not exceed one")
    return result


def _validate_dataset(value: Any, field: str) -> dict[str, Any]:
    dataset = _object(value, _DATASET_KEYS, field)
    _sha256(dataset["sha256"], f"{field}.sha256")
    _integer(dataset["byteCount"], f"{field}.byteCount", 1, MAX_SFT_BYTES)
    _integer(dataset["recordCount"], f"{field}.recordCount", 1, MAX_SFT_RECORDS)
    schemas = dataset["sourceSchemaVersions"]
    if not isinstance(schemas, list) or not schemas:
        _fail(f"{field}.sourceSchemaVersions", "must be a non-empty array")
    normalized = [
        _string(item, f"{field}.sourceSchemaVersions", max_length=200)
        for item in schemas
    ]
    if normalized != sorted(set(normalized)):
        _fail(
            f"{field}.sourceSchemaVersions",
            "must be unique and sorted",
        )
    return dataset


def _validate_task_counts(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    expected = sorted(TASK_KINDS)
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _object(raw, {"taskKind", "recordCount"}, f"{field}[{index}]")
        name = item["taskKind"]
        if name not in TASK_KINDS:
            _fail(f"{field}[{index}].taskKind", "is unsupported")
        _integer(
            item["recordCount"],
            f"{field}[{index}].recordCount",
            0,
            MAX_SFT_RECORDS,
        )
        names.append(name)
    if names != expected:
        _fail(field, "must contain every task kind exactly once in sorted order")
    return value


def _validate_domain_counts(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    expected = sorted(DOMAINS)
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _object(
            raw,
            {"domain", "labelCount", "weightedCount"},
            f"{field}[{index}]",
        )
        name = item["domain"]
        if name not in DOMAINS:
            _fail(f"{field}[{index}].domain", "is unsupported")
        _integer(
            item["labelCount"],
            f"{field}[{index}].labelCount",
            0,
            MAX_SFT_RECORDS,
        )
        _fraction(item["weightedCount"], f"{field}[{index}].weightedCount")
        names.append(name)
    if names != expected:
        _fail(field, "must contain every domain exactly once in sorted order")
    return value


def _validate_domain_task_counts(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    expected = sorted((domain, task) for domain in DOMAINS for task in TASK_KINDS)
    names: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        item = _object(
            raw,
            {"domain", "taskKind", "labelCount", "weightedCount"},
            f"{field}[{index}]",
        )
        domain = item["domain"]
        task = item["taskKind"]
        if domain not in DOMAINS or task not in TASK_KINDS:
            _fail(f"{field}[{index}]", "uses an unsupported domain or task kind")
        _integer(
            item["labelCount"],
            f"{field}[{index}].labelCount",
            0,
            MAX_SFT_RECORDS,
        )
        _fraction(item["weightedCount"], f"{field}[{index}].weightedCount")
        names.append((domain, task))
    if names != expected:
        _fail(
            field,
            "must contain every domain/task cell exactly once in sorted order",
        )
    return value


def _validate_domain_contamination_groups(
    value: Any, field: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _object(
            raw,
            {"domain", "distinctCount", "maximumGroup"},
            f"{field}[{index}]",
        )
        domain = item["domain"]
        if domain not in DOMAINS:
            _fail(f"{field}[{index}].domain", "is unsupported")
        distinct_count = _integer(
            item["distinctCount"],
            f"{field}[{index}].distinctCount",
            0,
            MAX_SFT_RECORDS,
        )
        maximum = item["maximumGroup"]
        if distinct_count == 0:
            if maximum is not None:
                _fail(
                    f"{field}[{index}].maximumGroup",
                    "must be null when the domain has no groups",
                )
        else:
            maximum = _object(
                maximum,
                {
                    "contaminationGroup",
                    "labelCount",
                    "weightedCount",
                    "weightedShare",
                },
                f"{field}[{index}].maximumGroup",
            )
            _string(
                maximum["contaminationGroup"],
                f"{field}[{index}].maximumGroup.contaminationGroup",
                max_length=200,
            )
            _integer(
                maximum["labelCount"],
                f"{field}[{index}].maximumGroup.labelCount",
                1,
                MAX_SFT_RECORDS,
            )
            _fraction(
                maximum["weightedCount"],
                f"{field}[{index}].maximumGroup.weightedCount",
            )
            _fraction(
                maximum["weightedShare"],
                f"{field}[{index}].maximumGroup.weightedShare",
                maximum_one=True,
            )
        names.append(domain)
    if names != sorted(DOMAINS):
        _fail(field, "must contain every domain exactly once in sorted order")
    return value


def _validate_named_counts(
    value: Any,
    field: str,
    *,
    name_key: str,
    allowed: set[str] | frozenset[str] | None = None,
    max_name_length: int,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail(field, "must be a non-empty array")
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _object(raw, {name_key, "recordCount"}, f"{field}[{index}]")
        name = _string(
            item[name_key], f"{field}[{index}].{name_key}", max_length=max_name_length
        )
        if allowed is not None and name not in allowed:
            _fail(f"{field}[{index}].{name_key}", "is unsupported")
        _integer(
            item["recordCount"],
            f"{field}[{index}].recordCount",
            1,
            MAX_SFT_RECORDS,
        )
        names.append(name)
    if names != sorted(set(names)):
        _fail(field, f"must use unique, sorted {name_key} values")
    return value


def _validate_concentration(value: Any, field: str) -> dict[str, Any]:
    concentration = _object(
        value,
        {
            "maximumDomainsPerRecord",
            "multiDomainRecordCount",
            "task",
            "domainWeighted",
            "domainTaskWeighted",
            "contaminationGroup",
            "origin",
            "producer",
        },
        field,
    )
    _integer(
        concentration["maximumDomainsPerRecord"],
        f"{field}.maximumDomainsPerRecord",
        1,
        len(DOMAINS),
    )
    _integer(
        concentration["multiDomainRecordCount"],
        f"{field}.multiDomainRecordCount",
        0,
        MAX_SFT_RECORDS,
    )

    task = _object(
        concentration["task"], {"taskKind", "recordCount", "share"}, f"{field}.task"
    )
    if task["taskKind"] not in TASK_KINDS:
        _fail(f"{field}.task.taskKind", "is unsupported")
    _integer(task["recordCount"], f"{field}.task.recordCount", 1, MAX_SFT_RECORDS)
    _fraction(task["share"], f"{field}.task.share", maximum_one=True)

    domain = _object(
        concentration["domainWeighted"],
        {"domain", "weightedCount", "share"},
        f"{field}.domainWeighted",
    )
    if domain["domain"] not in DOMAINS:
        _fail(f"{field}.domainWeighted.domain", "is unsupported")
    _fraction(domain["weightedCount"], f"{field}.domainWeighted.weightedCount")
    _fraction(domain["share"], f"{field}.domainWeighted.share", maximum_one=True)

    cell = _object(
        concentration["domainTaskWeighted"],
        {"domain", "taskKind", "weightedCount", "share"},
        f"{field}.domainTaskWeighted",
    )
    if cell["domain"] not in DOMAINS or cell["taskKind"] not in TASK_KINDS:
        _fail(f"{field}.domainTaskWeighted", "uses an unsupported cell")
    _fraction(cell["weightedCount"], f"{field}.domainTaskWeighted.weightedCount")
    _fraction(cell["share"], f"{field}.domainTaskWeighted.share", maximum_one=True)

    for name, name_key, maximum in (
        ("contaminationGroup", "contaminationGroup", 200),
        ("origin", "origin", 200),
        ("producer", "producer", 500),
    ):
        item = _object(
            concentration[name],
            {name_key, "recordCount", "share"},
            f"{field}.{name}",
        )
        _string(item[name_key], f"{field}.{name}.{name_key}", max_length=maximum)
        if name == "origin" and item[name_key] not in ORIGINS:
            _fail(f"{field}.{name}.{name_key}", "is unsupported")
        _integer(item["recordCount"], f"{field}.{name}.recordCount", 1, MAX_SFT_RECORDS)
        _fraction(item["share"], f"{field}.{name}.share", maximum_one=True)
    return concentration


def validate_training_corpus_quality_report(value: Any) -> dict[str, Any]:
    report = _object(value, _REPORT_KEYS, "corpus quality report")
    if report["schemaVersion"] != CORPUS_QUALITY_REPORT_SCHEMA_VERSION:
        _fail("corpus quality report.schemaVersion", "does not match the contract")
    _validate_dataset(report["dataset"], "corpus quality report.dataset")
    _validate_task_counts(report["taskCounts"], "corpus quality report.taskCounts")
    _validate_domain_counts(
        report["domainCounts"], "corpus quality report.domainCounts"
    )
    _validate_domain_task_counts(
        report["domainTaskCounts"], "corpus quality report.domainTaskCounts"
    )
    _validate_domain_contamination_groups(
        report["domainContaminationGroups"],
        "corpus quality report.domainContaminationGroups",
    )
    _validate_named_counts(
        report["contaminationGroupCounts"],
        "corpus quality report.contaminationGroupCounts",
        name_key="contaminationGroup",
        max_name_length=200,
    )
    _validate_named_counts(
        report["originCounts"],
        "corpus quality report.originCounts",
        name_key="origin",
        allowed=ORIGINS,
        max_name_length=200,
    )
    _validate_named_counts(
        report["producerCounts"],
        "corpus quality report.producerCounts",
        name_key="producer",
        max_name_length=500,
    )
    distinct = _object(
        report["distinctCounts"],
        {"contaminationGroups", "origins", "producers"},
        "corpus quality report.distinctCounts",
    )
    for name in ("contaminationGroups", "origins", "producers"):
        _integer(
            distinct[name],
            f"corpus quality report.distinctCounts.{name}",
            1,
            len(ORIGINS) if name == "origins" else MAX_SFT_RECORDS,
        )
    _validate_concentration(
        report["concentration"], "corpus quality report.concentration"
    )
    return report


def _max_integer_entry(counts: Mapping[str, int]) -> tuple[str, int]:
    return min(counts.items(), key=lambda item: (-item[1], item[0]))


def _max_fraction_entry(counts: Mapping[Any, Fraction]) -> tuple[Any, Fraction]:
    highest = max(counts.values())
    key = min(name for name, count in counts.items() if count == highest)
    return key, highest


def derive_training_corpus_quality_report_bytes(
    dataset_bytes: bytes,
    *,
    source_path: str | Path = "captured-dataset.sft.jsonl",
) -> dict[str, Any]:
    if not isinstance(dataset_bytes, bytes):
        _fail("corpus quality dataset bytes", "must be an immutable byte snapshot")
    summary, records = parse_sft_bytes(
        dataset_bytes,
        source_path=Path(source_path),
    )

    task_counts: Counter[str] = Counter()
    domain_labels: Counter[str] = Counter()
    domain_weights: dict[str, Fraction] = {domain: Fraction(0) for domain in DOMAINS}
    domain_task_labels: Counter[tuple[str, str]] = Counter()
    domain_task_weights: dict[tuple[str, str], Fraction] = {
        (domain, task): Fraction(0) for domain in DOMAINS for task in TASK_KINDS
    }
    domain_group_labels: dict[tuple[str, str], int] = Counter()
    domain_group_weights: dict[tuple[str, str], Fraction] = {}
    group_counts: Counter[str] = Counter()
    origin_counts: Counter[str] = Counter()
    producer_counts: Counter[str] = Counter()
    maximum_domains = 0
    multi_domain_count = 0

    for row in records:
        metadata = row["metadata"]
        task = metadata["taskKind"]
        domains = metadata["domains"]
        weight = Fraction(1, len(domains))
        task_counts[task] += 1
        group_counts[metadata["contaminationGroup"]] += 1
        origin_counts[metadata["origin"]] += 1
        producer_counts[metadata["producer"]] += 1
        maximum_domains = max(maximum_domains, len(domains))
        if len(domains) > 1:
            multi_domain_count += 1
        for domain in domains:
            domain_labels[domain] += 1
            domain_weights[domain] += weight
            domain_task_labels[(domain, task)] += 1
            domain_task_weights[(domain, task)] += weight
            group_key = (domain, metadata["contaminationGroup"])
            domain_group_labels[group_key] += 1
            domain_group_weights[group_key] = (
                domain_group_weights.get(group_key, Fraction(0)) + weight
            )

    total = summary.record_count
    task_name, task_count = _max_integer_entry(task_counts)
    domain_name, domain_count = _max_fraction_entry(domain_weights)
    cell_name, cell_count = _max_fraction_entry(domain_task_weights)
    group_name, group_count = _max_integer_entry(group_counts)
    origin_name, origin_count = _max_integer_entry(origin_counts)
    producer_name, producer_count = _max_integer_entry(producer_counts)
    domain_groups: list[dict[str, Any]] = []
    for domain in sorted(DOMAINS):
        group_weights = {
            group: weight
            for (group_domain, group), weight in domain_group_weights.items()
            if group_domain == domain
        }
        if not group_weights:
            domain_groups.append(
                {"domain": domain, "distinctCount": 0, "maximumGroup": None}
            )
            continue
        group, group_weight = _max_fraction_entry(group_weights)
        domain_groups.append(
            {
                "domain": domain,
                "distinctCount": len(group_weights),
                "maximumGroup": {
                    "contaminationGroup": group,
                    "labelCount": domain_group_labels[(domain, group)],
                    "weightedCount": _fraction_dict(group_weight),
                    "weightedShare": _fraction_dict(
                        group_weight / domain_weights[domain]
                    ),
                },
            }
        )

    report: dict[str, Any] = {
        "schemaVersion": CORPUS_QUALITY_REPORT_SCHEMA_VERSION,
        "dataset": {
            "sha256": summary.sha256,
            "byteCount": summary.byte_count,
            "recordCount": total,
            "sourceSchemaVersions": list(summary.source_schema_versions),
        },
        "taskCounts": [
            {"taskKind": task, "recordCount": task_counts[task]}
            for task in sorted(TASK_KINDS)
        ],
        "domainCounts": [
            {
                "domain": domain,
                "labelCount": domain_labels[domain],
                "weightedCount": _fraction_dict(domain_weights[domain]),
            }
            for domain in sorted(DOMAINS)
        ],
        "domainTaskCounts": [
            {
                "domain": domain,
                "taskKind": task,
                "labelCount": domain_task_labels[(domain, task)],
                "weightedCount": _fraction_dict(domain_task_weights[(domain, task)]),
            }
            for domain, task in sorted(domain_task_weights)
        ],
        "domainContaminationGroups": domain_groups,
        "contaminationGroupCounts": [
            {"contaminationGroup": name, "recordCount": count}
            for name, count in sorted(group_counts.items())
        ],
        "originCounts": [
            {"origin": name, "recordCount": count}
            for name, count in sorted(origin_counts.items())
        ],
        "producerCounts": [
            {"producer": name, "recordCount": count}
            for name, count in sorted(producer_counts.items())
        ],
        "distinctCounts": {
            "contaminationGroups": len(group_counts),
            "origins": len(origin_counts),
            "producers": len(producer_counts),
        },
        "concentration": {
            "maximumDomainsPerRecord": maximum_domains,
            "multiDomainRecordCount": multi_domain_count,
            "task": {
                "taskKind": task_name,
                "recordCount": task_count,
                "share": _fraction_dict(Fraction(task_count, total)),
            },
            "domainWeighted": {
                "domain": domain_name,
                "weightedCount": _fraction_dict(domain_count),
                "share": _fraction_dict(domain_count / total),
            },
            "domainTaskWeighted": {
                "domain": cell_name[0],
                "taskKind": cell_name[1],
                "weightedCount": _fraction_dict(cell_count),
                "share": _fraction_dict(cell_count / total),
            },
            "contaminationGroup": {
                "contaminationGroup": group_name,
                "recordCount": group_count,
                "share": _fraction_dict(Fraction(group_count, total)),
            },
            "origin": {
                "origin": origin_name,
                "recordCount": origin_count,
                "share": _fraction_dict(Fraction(origin_count, total)),
            },
            "producer": {
                "producer": producer_name,
                "recordCount": producer_count,
                "share": _fraction_dict(Fraction(producer_count, total)),
            },
        },
    }
    return validate_training_corpus_quality_report(report)


def derive_training_corpus_quality_report(
    dataset_path: str | Path,
) -> dict[str, Any]:
    resolved = _regular_file(Path(dataset_path), "corpus quality dataset")
    raw = _read_file_bounded(resolved, "corpus quality dataset", MAX_SFT_BYTES)
    return derive_training_corpus_quality_report_bytes(raw, source_path=resolved)


def training_corpus_quality_report_sha256(report: Mapping[str, Any]) -> str:
    validated = validate_training_corpus_quality_report(report)
    return hashlib.sha256(canonical_json_bytes(validated)).hexdigest()


def _validate_minimum_task_counts(value: Any, field: str) -> list[dict[str, Any]]:
    return _validate_task_counts(value, field)


def _validate_minimum_domain_counts(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    expected = sorted(DOMAINS)
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _object(raw, {"domain", "weightedCount"}, f"{field}[{index}]")
        if item["domain"] not in DOMAINS:
            _fail(f"{field}[{index}].domain", "is unsupported")
        _fraction(item["weightedCount"], f"{field}[{index}].weightedCount")
        names.append(item["domain"])
    if names != expected:
        _fail(field, "must contain every domain exactly once in sorted order")
    return value


def _validate_minimum_domain_task_counts(
    value: Any, field: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    names: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        item = _object(
            raw,
            {"domain", "taskKind", "weightedCount"},
            f"{field}[{index}]",
        )
        if item["domain"] not in DOMAINS or item["taskKind"] not in TASK_KINDS:
            _fail(f"{field}[{index}]", "uses an unsupported domain or task kind")
        _fraction(item["weightedCount"], f"{field}[{index}].weightedCount")
        names.append((item["domain"], item["taskKind"]))
    if names != sorted(set(names)):
        _fail(field, "must use unique domain/task cells in sorted order")
    return value


def _validate_minimum_domain_group_counts(
    value: Any, field: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        _fail(field, "must be an array")
    names: list[str] = []
    for index, raw in enumerate(value):
        item = _object(raw, {"domain", "distinctCount"}, f"{field}[{index}]")
        if item["domain"] not in DOMAINS:
            _fail(f"{field}[{index}].domain", "is unsupported")
        _integer(
            item["distinctCount"],
            f"{field}[{index}].distinctCount",
            0,
            MAX_SFT_RECORDS,
        )
        names.append(item["domain"])
    if names != sorted(DOMAINS):
        _fail(field, "must contain every domain exactly once in sorted order")
    return value


def validate_training_corpus_quality_policy(value: Any) -> dict[str, Any]:
    policy = _object(value, _POLICY_KEYS, "corpus quality policy")
    if policy["schemaVersion"] != CORPUS_QUALITY_POLICY_SCHEMA_VERSION:
        _fail("corpus quality policy.schemaVersion", "does not match the contract")
    version = _string(
        policy["policyVersion"], "corpus quality policy.policyVersion", max_length=64
    )
    if not _POLICY_VERSION_RE.fullmatch(version):
        _fail("corpus quality policy.policyVersion", "must be a safe version label")
    _integer(
        policy["minimumRecordCount"],
        "corpus quality policy.minimumRecordCount",
        1,
        MAX_SFT_RECORDS,
    )
    _validate_minimum_task_counts(
        policy["minimumTaskCounts"],
        "corpus quality policy.minimumTaskCounts",
    )
    _validate_minimum_domain_counts(
        policy["minimumDomainWeightedCounts"],
        "corpus quality policy.minimumDomainWeightedCounts",
    )
    _validate_minimum_domain_task_counts(
        policy["minimumDomainTaskWeightedCounts"],
        "corpus quality policy.minimumDomainTaskWeightedCounts",
    )
    _validate_minimum_domain_group_counts(
        policy["minimumDistinctContaminationGroupsByDomain"],
        "corpus quality policy.minimumDistinctContaminationGroupsByDomain",
    )
    for name in (
        "minimumDistinctContaminationGroups",
        "minimumDistinctOrigins",
        "minimumDistinctProducers",
    ):
        _integer(
            policy[name],
            f"corpus quality policy.{name}",
            1,
            len(ORIGINS) if name == "minimumDistinctOrigins" else MAX_SFT_RECORDS,
        )
    _integer(
        policy["maximumDomainsPerRecord"],
        "corpus quality policy.maximumDomainsPerRecord",
        1,
        len(DOMAINS),
    )
    maximum_shares = _object(
        policy["maximumShares"],
        {
            "task",
            "domainWeighted",
            "domainTaskWeighted",
            "contaminationGroup",
            "origin",
            "producer",
        },
        "corpus quality policy.maximumShares",
    )
    for name, value in maximum_shares.items():
        _fraction(
            value,
            f"corpus quality policy.maximumShares.{name}",
            maximum_one=True,
        )
    return policy


def training_corpus_quality_policy_sha256(policy: Mapping[str, Any]) -> str:
    validated = validate_training_corpus_quality_policy(policy)
    return hashlib.sha256(canonical_json_bytes(validated)).hexdigest()


def training_corpus_quality_policy_violations(
    report: Mapping[str, Any], policy: Mapping[str, Any]
) -> tuple[str, ...]:
    report = validate_training_corpus_quality_report(report)
    policy = validate_training_corpus_quality_policy(policy)
    violations: list[str] = []
    record_count = report["dataset"]["recordCount"]
    minimum_records = policy["minimumRecordCount"]
    if record_count < minimum_records:
        violations.append(f"recordCount {record_count} < {minimum_records}")

    actual_tasks = {
        item["taskKind"]: item["recordCount"] for item in report["taskCounts"]
    }
    for item in policy["minimumTaskCounts"]:
        actual = actual_tasks[item["taskKind"]]
        if actual < item["recordCount"]:
            violations.append(
                f"task {item['taskKind']} {actual} < {item['recordCount']}"
            )

    actual_domains = {
        item["domain"]: _fraction(item["weightedCount"], "report domain weight")
        for item in report["domainCounts"]
    }
    for item in policy["minimumDomainWeightedCounts"]:
        minimum = _fraction(item["weightedCount"], "policy domain weight")
        actual = actual_domains[item["domain"]]
        if actual < minimum:
            violations.append(f"domain {item['domain']} {actual} < {minimum}")

    actual_cells = {
        (item["domain"], item["taskKind"]): _fraction(
            item["weightedCount"], "report domain-task weight"
        )
        for item in report["domainTaskCounts"]
    }
    for item in policy["minimumDomainTaskWeightedCounts"]:
        minimum = _fraction(item["weightedCount"], "policy domain-task weight")
        key = (item["domain"], item["taskKind"])
        actual = actual_cells[key]
        if actual < minimum:
            violations.append(f"domainTask {key[0]}/{key[1]} {actual} < {minimum}")

    actual_domain_groups = {
        item["domain"]: item["distinctCount"]
        for item in report["domainContaminationGroups"]
    }
    for item in policy["minimumDistinctContaminationGroupsByDomain"]:
        actual = actual_domain_groups[item["domain"]]
        if actual < item["distinctCount"]:
            violations.append(
                f"domain groups {item['domain']} {actual} < {item['distinctCount']}"
            )

    distinct = report["distinctCounts"]
    for report_name, policy_name in (
        ("contaminationGroups", "minimumDistinctContaminationGroups"),
        ("origins", "minimumDistinctOrigins"),
        ("producers", "minimumDistinctProducers"),
    ):
        if distinct[report_name] < policy[policy_name]:
            violations.append(
                f"distinct {report_name} {distinct[report_name]} < {policy[policy_name]}"
            )

    actual_max_domains = report["concentration"]["maximumDomainsPerRecord"]
    if actual_max_domains > policy["maximumDomainsPerRecord"]:
        violations.append(
            "maximumDomainsPerRecord "
            f"{actual_max_domains} > {policy['maximumDomainsPerRecord']}"
        )

    for name in (
        "task",
        "domainWeighted",
        "domainTaskWeighted",
        "contaminationGroup",
        "origin",
        "producer",
    ):
        actual = _fraction(
            report["concentration"][name]["share"],
            f"report concentration {name}",
            maximum_one=True,
        )
        maximum = _fraction(
            policy["maximumShares"][name],
            f"policy maximum share {name}",
            maximum_one=True,
        )
        if actual > maximum:
            violations.append(f"maximum share {name} {actual} > {maximum}")
    return tuple(violations)


def _validate_data_release(value: Any, field: str) -> dict[str, str]:
    if isinstance(value, Mapping) and not isinstance(value, dict):
        value = dict(value)
    identity = _validate_data_release_identity(value, field, allow_none=False)
    if identity is None:  # pragma: no cover - the helper rejects this case
        _fail(field, "is required")
    return identity


def training_corpus_admission_id(payload: Mapping[str, Any]) -> str:
    normalized = dict(payload)
    normalized["corpusAdmissionId"] = CORPUS_ADMISSION_ID_PREFIX + _ZERO_SHA256
    digest = hashlib.sha256(_ID_DOMAIN + canonical_json_bytes(normalized)).hexdigest()
    return CORPUS_ADMISSION_ID_PREFIX + digest


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


def training_corpus_admission_signing_bundle_id(
    value: Mapping[str, Any],
) -> str:
    return _content_addressed_id(
        value,
        id_field="bundleId",
        prefix=CORPUS_ADMISSION_SIGNING_BUNDLE_ID_PREFIX,
        domain=_SIGNING_BUNDLE_ID_DOMAIN,
    )


def training_corpus_admission_signature_id(value: Mapping[str, Any]) -> str:
    return _content_addressed_id(
        value,
        id_field="signatureId",
        prefix=CORPUS_ADMISSION_SIGNATURE_ID_PREFIX,
        domain=_EXTERNAL_SIGNATURE_ID_DOMAIN,
    )


def _validate_payload(value: Any) -> dict[str, Any]:
    payload = _object(value, _PAYLOAD_KEYS, "corpus admission payload")
    constants = {
        "schemaVersion": CORPUS_ADMISSION_SCHEMA_VERSION,
        "scope": CORPUS_ADMISSION_SCOPE,
        "decision": "admitted",
        "reusable": True,
        "corpusAdmissionAuthorized": True,
        "rightsAuthorized": False,
        "reviewReceiptAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "evaluationAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "statement": CORPUS_ADMISSION_STATEMENT,
    }
    for name, expected in constants.items():
        if type(payload[name]) is not type(expected) or payload[name] != expected:
            _fail(f"corpus admission payload.{name}", "does not match the contract")

    _identifier(payload["reviewerId"], "corpus admission payload.reviewerId")
    reviewed = _canonical_utc(
        payload["reviewedAtUtc"], "corpus admission payload.reviewedAtUtc"
    )
    issued = _canonical_utc(
        payload["issuedAtUtc"], "corpus admission payload.issuedAtUtc"
    )
    not_before = _canonical_utc(
        payload["notBeforeUtc"], "corpus admission payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "corpus admission payload.expiresAtUtc"
    )
    if not reviewed <= issued <= not_before < expires:
        _fail(
            "corpus admission payload validity",
            "must satisfy reviewedAt <= issuedAt <= notBefore < expiresAt",
        )
    if expires - not_before > MAX_CORPUS_ADMISSION_VALIDITY:
        _fail("corpus admission payload validity", "must not exceed 366 days")

    _validate_data_release(
        payload["dataRelease"], "corpus admission payload.dataRelease"
    )
    dataset = _validate_dataset(payload["dataset"], "corpus admission payload.dataset")
    report = validate_training_corpus_quality_report(payload["qualityReport"])
    report_sha256 = training_corpus_quality_report_sha256(report)
    if (
        _sha256(
            payload["qualityReportSha256"],
            "corpus admission payload.qualityReportSha256",
        )
        != report_sha256
    ):
        _fail(
            "corpus admission payload.qualityReportSha256",
            "does not match the exact report",
        )
    if report["dataset"] != dataset:
        _fail("corpus admission payload.dataset", "does not match the quality report")

    policy = validate_training_corpus_quality_policy(payload["qualityPolicy"])
    policy_sha256 = training_corpus_quality_policy_sha256(policy)
    if (
        _sha256(
            payload["qualityPolicySha256"],
            "corpus admission payload.qualityPolicySha256",
        )
        != policy_sha256
    ):
        _fail(
            "corpus admission payload.qualityPolicySha256",
            "does not match the exact policy",
        )
    violations = training_corpus_quality_policy_violations(report, policy)
    if violations:
        _fail(
            "corpus admission payload.decision",
            "quality policy is not satisfied: " + "; ".join(violations),
        )
    if payload["corpusAdmissionId"] != training_corpus_admission_id(payload):
        _fail(
            "corpus admission payload.corpusAdmissionId",
            "does not match the content-derived identity",
        )
    return payload


def _framed(fields: Iterable[str | bytes]) -> bytes:
    framed = bytearray()
    for field in fields:
        raw = field if isinstance(field, bytes) else field.encode("utf-8")
        framed.extend(len(raw).to_bytes(8, "big", signed=False))
        framed.extend(raw)
    return bytes(framed)


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
    if signature_format == CORPUS_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT:
        signature = _base64url_decode(value, field, 64)
        if len(signature) != 64:
            _fail(field, "must decode to exactly 64 bytes")
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
    elif signature_format == CORPUS_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT:
        signature = _base64url_decode(
            value, field, MAX_CORPUS_ADMISSION_DER_SIGNATURE_BYTES
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
    trust: TrainingCorpusAdmissionTrust,
) -> tuple[Any, str, str, str, str, str]:
    if not isinstance(trust, TrainingCorpusAdmissionTrust):
        _fail("corpus admission trust", "must be externally supplied")
    public_key, actual_spki = _load_public_key(Path(trust.public_key_path))
    expected_spki = _sha256(
        trust.public_key_spki_sha256,
        "corpus admission trust.publicKeySpkiSha256",
    )
    if actual_spki != expected_spki:
        _fail(
            "corpus admission trust.publicKeySpkiSha256",
            "does not match the supplied public key",
        )
    return (
        public_key,
        actual_spki,
        _identifier(trust.audience, "corpus admission trust.audience"),
        _identifier(trust.key_id, "corpus admission trust.keyId"),
        _identifier(trust.signer_role, "corpus admission trust.signerRole"),
        _sha256(
            trust.quality_policy_sha256,
            "corpus admission trust.qualityPolicySha256",
        ),
    )


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


def _build_corpus_admission_payload(
    *,
    dataset_bytes: bytes,
    dataset_source_path: str | Path,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    trusted_policy_sha256: str,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
    report = derive_training_corpus_quality_report_bytes(
        dataset_bytes, source_path=dataset_source_path
    )
    policy = validate_training_corpus_quality_policy(quality_policy)
    policy_sha256 = training_corpus_quality_policy_sha256(policy)
    if policy_sha256 != trusted_policy_sha256:
        _fail(
            "corpus quality policy",
            "does not match the externally pinned reviewer policy",
        )
    violations = training_corpus_quality_policy_violations(report, policy)
    if violations:
        _fail(
            "corpus quality policy", "rejects exact dataset: " + "; ".join(violations)
        )
    release = _validate_data_release(data_release, "corpus admission dataRelease")
    payload: dict[str, Any] = {
        "schemaVersion": CORPUS_ADMISSION_SCHEMA_VERSION,
        "corpusAdmissionId": CORPUS_ADMISSION_ID_PREFIX + _ZERO_SHA256,
        "scope": CORPUS_ADMISSION_SCOPE,
        "decision": "admitted",
        "reusable": True,
        "corpusAdmissionAuthorized": True,
        "rightsAuthorized": False,
        "reviewReceiptAuthorized": False,
        "releaseAuthorized": False,
        "trainingAuthorized": False,
        "evaluationAuthorized": False,
        "promotionDecisionAuthorized": False,
        "deploymentAuthorized": False,
        "hostedServingAuthorized": False,
        "installationAuthorized": False,
        "verifierExecutionAuthorized": False,
        "strategyExecutionAuthorized": False,
        "reviewedAtUtc": reviewed_at_utc,
        "issuedAtUtc": issued_at_utc,
        "notBeforeUtc": not_before_utc,
        "expiresAtUtc": expires_at_utc,
        "reviewerId": reviewer_id,
        "dataRelease": release,
        "dataset": report["dataset"],
        "qualityReport": report,
        "qualityReportSha256": training_corpus_quality_report_sha256(report),
        "qualityPolicy": policy,
        "qualityPolicySha256": policy_sha256,
        "statement": CORPUS_ADMISSION_STATEMENT,
    }
    payload["corpusAdmissionId"] = training_corpus_admission_id(payload)
    return _validate_payload(payload), report, policy, release


def _unsigned_envelope(
    payload_bytes: bytes,
    *,
    audience: str,
    key_id: str,
    signer_role: str,
    public_key_spki_sha256: str,
) -> dict[str, Any]:
    return {
        "schemaVersion": CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": CORPUS_ADMISSION_SCHEMA_VERSION,
        "payloadEncoding": CORPUS_ADMISSION_PAYLOAD_ENCODING,
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": _base64url_encode(payload_bytes),
        "algorithm": CORPUS_ADMISSION_ALGORITHM,
        "signatureFormat": CORPUS_ADMISSION_SIGNATURE_FORMAT,
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
        "schemaVersion": CORPUS_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "bundleId": CORPUS_ADMISSION_SIGNING_BUNDLE_ID_PREFIX + _ZERO_SHA256,
        "status": CORPUS_ADMISSION_SIGNING_STATUS,
        "authority": {
            "corpusAdmissionIssuance": False,
            "rights": False,
            "reviewReceipt": False,
            "release": False,
            "training": False,
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
            "qualityPolicySha256": payload["qualityPolicySha256"],
        },
        "corpusAdmissionId": payload["corpusAdmissionId"],
        "dataRelease": payload["dataRelease"],
        "datasetSha256": payload["dataset"]["sha256"],
        "qualityReportSha256": payload["qualityReportSha256"],
        "qualityPolicySha256": payload["qualityPolicySha256"],
        "signatureContract": {
            "algorithm": CORPUS_ADMISSION_ALGORITHM,
            "hashAlgorithm": CORPUS_ADMISSION_SIGNING_HASH_ALGORITHM,
            "messageType": CORPUS_ADMISSION_SIGNING_MESSAGE_TYPE,
            "signatureInputEncoding": CORPUS_ADMISSION_SIGNING_INPUT_ENCODING,
            "acceptedSignatureFormats": [
                CORPUS_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
                CORPUS_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT,
            ],
        },
        "request": {
            "corpusAdmissionId": payload["corpusAdmissionId"],
            "payloadSha256": envelope["payloadSha256"],
            "payload": envelope["payload"],
            "signatureInputSha256": signature_digest.hex(),
            "signaturePreimage": _base64url_encode(signature_preimage),
            "signatureInput": _base64url_encode(signature_digest),
        },
    }
    bundle["bundleId"] = training_corpus_admission_signing_bundle_id(bundle)
    return bundle


def _validate_signing_bundle_document(
    value: Any,
    *,
    public_key_spki_sha256: str,
    audience: str,
    key_id: str,
    signer_role: str,
    trusted_policy_sha256: str,
    expected_report: Mapping[str, Any],
    expected_policy: Mapping[str, Any],
    expected_data_release: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    bundle = _object(
        value,
        {
            "schemaVersion",
            "bundleId",
            "status",
            "authority",
            "trust",
            "corpusAdmissionId",
            "dataRelease",
            "datasetSha256",
            "qualityReportSha256",
            "qualityPolicySha256",
            "signatureContract",
            "request",
        },
        "corpus admission signing bundle",
    )
    constants = {
        "schemaVersion": CORPUS_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION,
        "status": CORPUS_ADMISSION_SIGNING_STATUS,
    }
    for name, expected in constants.items():
        if type(bundle[name]) is not type(expected) or bundle[name] != expected:
            _fail(
                f"corpus admission signing bundle.{name}",
                "does not match the contract",
            )

    authority = _object(
        bundle["authority"],
        {
            "corpusAdmissionIssuance",
            "rights",
            "reviewReceipt",
            "release",
            "training",
            "evaluation",
            "promotionDecision",
            "deployment",
            "hostedServing",
            "installation",
            "verifierExecution",
            "strategyExecution",
        },
        "corpus admission signing bundle.authority",
    )
    for name, authorized in authority.items():
        if type(authorized) is not bool or authorized:
            _fail(
                f"corpus admission signing bundle.authority.{name}",
                "must be false because the bundle is non-authorizing",
            )

    trust = _object(
        bundle["trust"],
        {
            "publicKeySpkiSha256",
            "audience",
            "keyId",
            "signerRole",
            "qualityPolicySha256",
        },
        "corpus admission signing bundle.trust",
    )
    expected_trust = {
        "publicKeySpkiSha256": public_key_spki_sha256,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "qualityPolicySha256": trusted_policy_sha256,
    }
    for name, expected in expected_trust.items():
        if trust[name] != expected:
            _fail(
                f"corpus admission signing bundle.trust.{name}",
                "does not match externally pinned trust",
            )

    contract = _object(
        bundle["signatureContract"],
        {
            "algorithm",
            "hashAlgorithm",
            "messageType",
            "signatureInputEncoding",
            "acceptedSignatureFormats",
        },
        "corpus admission signing bundle.signatureContract",
    )
    expected_contract = {
        "algorithm": CORPUS_ADMISSION_ALGORITHM,
        "hashAlgorithm": CORPUS_ADMISSION_SIGNING_HASH_ALGORITHM,
        "messageType": CORPUS_ADMISSION_SIGNING_MESSAGE_TYPE,
        "signatureInputEncoding": CORPUS_ADMISSION_SIGNING_INPUT_ENCODING,
        "acceptedSignatureFormats": [
            CORPUS_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT,
            CORPUS_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT,
        ],
    }
    if contract != expected_contract:
        _fail(
            "corpus admission signing bundle.signatureContract",
            "does not match the contract",
        )

    request = _object(
        bundle["request"],
        {
            "corpusAdmissionId",
            "payloadSha256",
            "payload",
            "signatureInputSha256",
            "signaturePreimage",
            "signatureInput",
        },
        "corpus admission signing bundle.request",
    )
    payload_bytes = _base64url_decode(
        request["payload"],
        "corpus admission signing bundle.request.payload",
        MAX_CORPUS_ADMISSION_PAYLOAD_BYTES,
    )
    if len(payload_bytes) > MAX_CORPUS_ADMISSION_PAYLOAD_BYTES:
        _fail(
            "corpus admission signing bundle.request.payload", "exceeds its byte limit"
        )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(
            request["payloadSha256"],
            "corpus admission signing bundle.request.payloadSha256",
        )
        != payload_sha256
    ):
        _fail(
            "corpus admission signing bundle.request.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(
        payload_bytes, "corpus admission signing bundle payload"
    )
    if payload_bytes != canonical_json_bytes(payload):
        _fail("corpus admission signing bundle payload", "must be exact canonical JSON")
    payload = _validate_payload(payload)
    _ensure_payload_active(payload, now, "corpus admission signing bundle payload")

    report = validate_training_corpus_quality_report(expected_report)
    policy = validate_training_corpus_quality_policy(expected_policy)
    release = _validate_data_release(
        expected_data_release, "expected corpus admission dataRelease"
    )
    expected_policy_sha256 = training_corpus_quality_policy_sha256(policy)
    if expected_policy_sha256 != trusted_policy_sha256:
        _fail(
            "corpus admission signing bundle quality policy",
            "does not match externally pinned trust",
        )
    expected_material = {
        "dataRelease": release,
        "dataset": report["dataset"],
        "qualityReport": report,
        "qualityReportSha256": training_corpus_quality_report_sha256(report),
        "qualityPolicy": policy,
        "qualityPolicySha256": expected_policy_sha256,
    }
    for name, expected in expected_material.items():
        if payload[name] != expected:
            _fail(
                f"corpus admission signing bundle payload.{name}",
                "does not match the exact live corpus admission input",
            )

    explicit_bindings = {
        "corpusAdmissionId": payload["corpusAdmissionId"],
        "dataRelease": release,
        "datasetSha256": report["dataset"]["sha256"],
        "qualityReportSha256": expected_material["qualityReportSha256"],
        "qualityPolicySha256": expected_policy_sha256,
    }
    for name, expected in explicit_bindings.items():
        if bundle[name] != expected:
            _fail(
                f"corpus admission signing bundle.{name}",
                "does not match the exact payload",
            )
    admission_id = bundle["corpusAdmissionId"]
    if not isinstance(admission_id, str) or not _CORPUS_ADMISSION_ID_RE.fullmatch(
        admission_id
    ):
        _fail("corpus admission signing bundle.corpusAdmissionId", "is invalid")
    for name in ("datasetSha256", "qualityReportSha256", "qualityPolicySha256"):
        _sha256(bundle[name], f"corpus admission signing bundle.{name}")
    if request["corpusAdmissionId"] != admission_id:
        _fail(
            "corpus admission signing bundle.request.corpusAdmissionId",
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
        "corpus admission signing bundle.request.signaturePreimage",
        MAX_CORPUS_ADMISSION_SIGNATURE_INPUT_BYTES,
    )
    if supplied_preimage != preimage:
        _fail(
            "corpus admission signing bundle.request.signaturePreimage",
            "does not match the exact signature preimage",
        )
    digest = hashlib.sha256(preimage).digest()
    supplied_digest = _base64url_decode(
        request["signatureInput"],
        "corpus admission signing bundle.request.signatureInput",
        32,
    )
    if supplied_digest != digest:
        _fail(
            "corpus admission signing bundle.request.signatureInput",
            "does not match the exact SHA-256 signing digest",
        )
    if (
        _sha256(
            request["signatureInputSha256"],
            "corpus admission signing bundle.request.signatureInputSha256",
        )
        != digest.hex()
    ):
        _fail(
            "corpus admission signing bundle.request.signatureInputSha256",
            "does not match the exact SHA-256 signing digest",
        )
    bundle_id = bundle["bundleId"]
    if (
        not isinstance(bundle_id, str)
        or not _SIGNING_BUNDLE_ID_RE.fullmatch(bundle_id)
        or bundle_id != training_corpus_admission_signing_bundle_id(bundle)
    ):
        _fail(
            "corpus admission signing bundle.bundleId",
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
        "schemaVersion": CORPUS_ADMISSION_SIGNATURE_SCHEMA_VERSION,
        "signatureId": CORPUS_ADMISSION_SIGNATURE_ID_PREFIX + _ZERO_SHA256,
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "corpusAdmissionId": bundle["corpusAdmissionId"],
        "datasetSha256": bundle["datasetSha256"],
        "qualityReportSha256": bundle["qualityReportSha256"],
        "qualityPolicySha256": bundle["qualityPolicySha256"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
        "format": signature_format,
        "signature": _base64url_encode(signature),
    }
    document["signatureId"] = training_corpus_admission_signature_id(document)
    return document


def _validate_external_signature_document(
    value: Any,
    *,
    bundle: Mapping[str, Any],
    bundle_bytes: bytes,
    public_key: Any,
) -> bytes:
    document = _object(
        value,
        {
            "schemaVersion",
            "signatureId",
            "signingBundleId",
            "signingBundleSha256",
            "corpusAdmissionId",
            "datasetSha256",
            "qualityReportSha256",
            "qualityPolicySha256",
            "payloadSha256",
            "signatureInputSha256",
            "publicKeySpkiSha256",
            "format",
            "signature",
        },
        "corpus admission external signature",
    )
    if document["schemaVersion"] != CORPUS_ADMISSION_SIGNATURE_SCHEMA_VERSION:
        _fail("corpus admission external signature.schemaVersion", "is unsupported")
    request = bundle["request"]
    expected_bindings = {
        "signingBundleId": bundle["bundleId"],
        "signingBundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "corpusAdmissionId": bundle["corpusAdmissionId"],
        "datasetSha256": bundle["datasetSha256"],
        "qualityReportSha256": bundle["qualityReportSha256"],
        "qualityPolicySha256": bundle["qualityPolicySha256"],
        "payloadSha256": request["payloadSha256"],
        "signatureInputSha256": request["signatureInputSha256"],
        "publicKeySpkiSha256": bundle["trust"]["publicKeySpkiSha256"],
    }
    for name, expected in expected_bindings.items():
        supplied = document[name]
        if name.endswith("Sha256"):
            _sha256(supplied, f"corpus admission external signature.{name}")
        if supplied != expected:
            _fail(
                f"corpus admission external signature.{name}",
                "does not match the exact signing bundle",
            )
    preimage = _base64url_decode(
        request["signaturePreimage"],
        "corpus admission signing bundle.request.signaturePreimage",
        MAX_CORPUS_ADMISSION_SIGNATURE_INPUT_BYTES,
    )
    normalized = _normalize_external_signature(
        document["signature"],
        signature_format=document["format"],
        public_key=public_key,
        signature_input=preimage,
        field="corpus admission external signature.signature",
    )
    signature_id = document["signatureId"]
    if (
        not isinstance(signature_id, str)
        or not _EXTERNAL_SIGNATURE_ID_RE.fullmatch(signature_id)
        or signature_id != training_corpus_admission_signature_id(document)
    ):
        _fail(
            "corpus admission external signature.signatureId",
            "does not match the content-derived identity",
        )
    return normalized


def _read_canonical_handoff_document(
    path: str | os.PathLike[str], field: str, max_bytes: int
) -> tuple[Path, bytes, dict[str, Any]]:
    resolved = _regular_file(Path(path), field)
    raw = _read_file_bounded(resolved, field, max_bytes)
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        _fail(field, "must be exact canonical JSON followed by one LF")
    document = _load_json_object_bytes(raw[:-1], field)
    if raw != canonical_json_bytes(document) + b"\n":
        _fail(field, "must be exact canonical JSON followed by one LF")
    return resolved, raw, document


def _validate_envelope(
    value: Mapping[str, Any],
    *,
    trust: TrainingCorpusAdmissionTrust,
    expected_report: Mapping[str, Any],
    expected_data_release: Mapping[str, Any],
    expected_envelope_sha256: str | None,
    now: datetime,
) -> VerifiedTrainingCorpusAdmission:
    envelope = _object(value, _ENVELOPE_KEYS, "corpus admission envelope")
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_CORPUS_ADMISSION_BYTES:
        _fail("corpus admission envelope", "exceeds its byte limit")

    public_key, spki, audience, key_id, signer_role, trusted_policy_sha256 = (
        _validate_trust(trust)
    )
    constants = {
        "schemaVersion": CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION,
        "payloadType": CORPUS_ADMISSION_SCHEMA_VERSION,
        "payloadEncoding": CORPUS_ADMISSION_PAYLOAD_ENCODING,
        "algorithm": CORPUS_ADMISSION_ALGORITHM,
        "signatureFormat": CORPUS_ADMISSION_SIGNATURE_FORMAT,
        "audience": audience,
        "keyId": key_id,
        "signerRole": signer_role,
        "publicKeySpkiSha256": spki,
    }
    for name, expected in constants.items():
        if type(envelope[name]) is not type(expected) or envelope[name] != expected:
            _fail(
                f"corpus admission envelope.{name}",
                "does not match trusted configuration",
            )

    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    if (
        expected_envelope_sha256 is not None
        and _sha256(
            expected_envelope_sha256,
            "expected corpus admission envelope SHA-256",
        )
        != envelope_sha256
    ):
        _fail("corpus admission envelope", "does not match the trusted exact SHA-256")

    payload_bytes = _base64url_decode(
        envelope["payload"],
        "corpus admission envelope.payload",
        MAX_CORPUS_ADMISSION_PAYLOAD_BYTES,
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    if (
        _sha256(envelope["payloadSha256"], "corpus admission envelope.payloadSha256")
        != payload_sha256
    ):
        _fail(
            "corpus admission envelope.payloadSha256",
            "does not match exact payload bytes",
        )
    payload = _load_json_object_bytes(payload_bytes, "corpus admission payload")
    if payload_bytes != canonical_json_bytes(payload):
        _fail("corpus admission payload", "must be exact canonical JSON")
    payload = _validate_payload(payload)

    signature = _base64url_decode(
        envelope["signature"], "corpus admission envelope.signature", 64
    )
    _verify_p1363_low_s(
        public_key, _signature_input(envelope, payload_bytes), signature
    )

    not_before = _canonical_utc(
        payload["notBeforeUtc"], "corpus admission payload.notBeforeUtc"
    )
    expires = _canonical_utc(
        payload["expiresAtUtc"], "corpus admission payload.expiresAtUtc"
    )
    if now < not_before or now >= expires:
        _fail("corpus admission payload validity", "is not active")

    release = _validate_data_release(
        expected_data_release, "expected corpus admission dataRelease"
    )
    if payload["dataRelease"] != release:
        _fail(
            "corpus admission payload.dataRelease",
            "does not match the exact expected release identity",
        )
    report = validate_training_corpus_quality_report(expected_report)
    if payload["qualityReport"] != report or payload["dataset"] != report["dataset"]:
        _fail(
            "corpus admission payload.qualityReport",
            "does not match the recomputed exact dataset report",
        )
    if payload["qualityReportSha256"] != training_corpus_quality_report_sha256(report):
        _fail(
            "corpus admission payload.qualityReportSha256",
            "does not match the recomputed exact dataset report",
        )
    if payload["qualityPolicySha256"] != trusted_policy_sha256:
        _fail(
            "corpus admission payload.qualityPolicySha256",
            "does not match the externally pinned reviewer policy",
        )
    return VerifiedTrainingCorpusAdmission(
        envelope=envelope,
        payload=payload,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        envelope_sha256=envelope_sha256,
        public_key_spki_sha256=spki,
        not_before_utc=not_before,
        expires_at_utc=expires,
    )


def verify_training_corpus_admission(
    envelope: Mapping[str, Any],
    *,
    dataset_path: str | Path,
    expected_data_release: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    expected_envelope_sha256: str | None = None,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    resolved = _regular_file(Path(dataset_path), "corpus admission dataset")
    dataset_bytes = _read_file_bounded(
        resolved, "corpus admission dataset", MAX_SFT_BYTES
    )
    return verify_training_corpus_admission_bytes(
        envelope,
        dataset_bytes=dataset_bytes,
        dataset_source_path=resolved,
        expected_data_release=expected_data_release,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=now,
    )


def verify_training_corpus_admission_bytes(
    envelope: Mapping[str, Any],
    *,
    dataset_bytes: bytes,
    expected_data_release: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    dataset_source_path: str | Path = "captured-dataset.sft.jsonl",
    expected_envelope_sha256: str | None = None,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    current = _validation_time(
        now or datetime.now(timezone.utc), "corpus admission verification time"
    )
    report = derive_training_corpus_quality_report_bytes(
        dataset_bytes, source_path=dataset_source_path
    )
    return _validate_envelope(
        envelope,
        trust=trust,
        expected_report=report,
        expected_data_release=expected_data_release,
        expected_envelope_sha256=expected_envelope_sha256,
        now=current,
    )


def _load_corpus_admission_envelope(path: Path) -> dict[str, Any]:
    raw = _read_file_bounded(
        path,
        "corpus admission envelope file",
        MAX_CORPUS_ADMISSION_BYTES + 1,
    )
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        _fail(
            "corpus admission envelope file",
            "must be exact canonical JSON followed by one LF",
        )
    document = _load_json_object_bytes(raw[:-1], "corpus admission envelope file")
    if raw != canonical_json_bytes(document) + b"\n":
        _fail(
            "corpus admission envelope file",
            "must be exact canonical JSON followed by one LF",
        )
    return document


def verify_training_corpus_admission_file(
    envelope_path: str | Path,
    *,
    dataset_bytes: bytes,
    expected_data_release: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    dataset_source_path: str | Path = "captured-dataset.sft.jsonl",
    expected_envelope_sha256: str | None = None,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    envelope = _load_corpus_admission_envelope(Path(envelope_path))
    return verify_training_corpus_admission_bytes(
        envelope,
        dataset_bytes=dataset_bytes,
        dataset_source_path=dataset_source_path,
        expected_data_release=expected_data_release,
        trust=trust,
        expected_envelope_sha256=expected_envelope_sha256,
        now=now,
    )


def _write_no_clobber(
    path: Path,
    raw: bytes,
    *,
    prepublish_validator: Callable[[Path], _Validated],
    field: str = "corpus admission output",
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
            residual = staged
            residual_staging = residual
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
                owned_destination_remains = False
            except OSError:
                owned_destination_remains = True
            residual_locations = str(residual)
            if owned_destination_remains:
                residual_locations += f"; {destination}"
            raise ValidationError(
                f"{field}: atomic publication aborted because staging cleanup "
                "failed; residual material requires removal: "
                f"{residual_locations}"
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
                    try:
                        destination.unlink()
                    except OSError as cleanup_error:
                        residual_locations = "; ".join(
                            str(item)
                            for item in (residual_staging, destination)
                            if item is not None
                        )
                        raise ValidationError(
                            f"{field}: validation failed and owned destination "
                            "cleanup failed; residual material requires removal: "
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
                    f"{field}: validation failed and destination ownership could "
                    "not be verified; residual material requires inspection: "
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
                        "residual material requires removal: "
                        f"{staged}"
                    ) from error


def create_training_corpus_admission(
    *,
    dataset_path: str | Path,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    private_key_path: str | Path,
    private_key_password: bytes | None,
    trust: TrainingCorpusAdmissionTrust,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    output_path: str | Path | None = None,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    resolved_dataset = _regular_file(
        Path(dataset_path), "corpus admission source dataset"
    )
    dataset_bytes = _read_file_bounded(
        resolved_dataset, "corpus admission source dataset", MAX_SFT_BYTES
    )
    return create_training_corpus_admission_bytes(
        dataset_bytes=dataset_bytes,
        dataset_source_path=resolved_dataset,
        data_release=data_release,
        quality_policy=quality_policy,
        private_key_path=private_key_path,
        private_key_password=private_key_password,
        trust=trust,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        output_path=output_path,
        now=now,
    )


def create_training_corpus_admission_bytes(
    *,
    dataset_bytes: bytes,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    private_key_path: str | Path,
    private_key_password: bytes | None,
    trust: TrainingCorpusAdmissionTrust,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    dataset_source_path: str | Path = "captured-dataset.sft.jsonl",
    output_path: str | Path | None = None,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    _, spki, audience, key_id, signer_role, trusted_policy_sha256 = _validate_trust(
        trust
    )
    payload, report, _, release = _build_corpus_admission_payload(
        dataset_bytes=dataset_bytes,
        dataset_source_path=dataset_source_path,
        data_release=data_release,
        quality_policy=quality_policy,
        trusted_policy_sha256=trusted_policy_sha256,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    current = _fresh_validation_time(now, "corpus admission creation time")
    _ensure_payload_active(payload, current, "corpus admission payload")

    private_key, private_spki = _load_private_key(
        Path(private_key_path), private_key_password
    )
    if private_spki != spki:
        _fail(
            "corpus admission key pair",
            "private and externally pinned public keys differ",
        )
    payload_bytes = canonical_json_bytes(payload)
    if len(payload_bytes) > MAX_CORPUS_ADMISSION_PAYLOAD_BYTES:
        _fail("corpus admission payload", "exceeds its byte limit")
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
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_CORPUS_ADMISSION_BYTES:
        _fail("corpus admission envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    post_signing_time = _fresh_validation_time(
        now, "corpus admission post-signing validation time"
    )
    verified = _validate_envelope(
        envelope,
        trust=trust,
        expected_report=report,
        expected_data_release=release,
        expected_envelope_sha256=envelope_sha256,
        now=post_signing_time,
    )
    if output_path is None:
        return verified

    def validate_published(path: Path) -> VerifiedTrainingCorpusAdmission:
        publication_time = _fresh_validation_time(
            now, "corpus admission publication time"
        )
        published_envelope = _load_corpus_admission_envelope(path)
        return _validate_envelope(
            published_envelope,
            trust=trust,
            expected_report=report,
            expected_data_release=release,
            expected_envelope_sha256=envelope_sha256,
            now=publication_time,
        )

    return _write_no_clobber(
        Path(output_path),
        envelope_bytes + b"\n",
        prepublish_validator=validate_published,
    )


def prepare_training_corpus_admission_signing_bundle(
    *,
    dataset_path: str | Path,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    output_path: str | Path,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmissionSigningBundle:
    resolved_dataset = _regular_file(
        Path(dataset_path), "corpus admission signing source dataset"
    )
    dataset_bytes = _read_file_bounded(
        resolved_dataset, "corpus admission signing source dataset", MAX_SFT_BYTES
    )
    return prepare_training_corpus_admission_signing_bundle_bytes(
        dataset_bytes=dataset_bytes,
        dataset_source_path=resolved_dataset,
        data_release=data_release,
        quality_policy=quality_policy,
        trust=trust,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        output_path=output_path,
        now=now,
    )


def prepare_training_corpus_admission_signing_bundle_bytes(
    *,
    dataset_bytes: bytes,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    reviewer_id: str,
    reviewed_at_utc: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str,
    output_path: str | Path,
    dataset_source_path: str | Path = "captured-dataset.sft.jsonl",
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmissionSigningBundle:
    _, spki, audience, key_id, signer_role, trusted_policy_sha256 = _validate_trust(
        trust
    )
    payload, report, policy, release = _build_corpus_admission_payload(
        dataset_bytes=dataset_bytes,
        dataset_source_path=dataset_source_path,
        data_release=data_release,
        quality_policy=quality_policy,
        trusted_policy_sha256=trusted_policy_sha256,
        reviewer_id=reviewer_id,
        reviewed_at_utc=reviewed_at_utc,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
    )
    current = _fresh_validation_time(
        now, "corpus admission signing-bundle creation time"
    )
    _ensure_payload_active(payload, current, "corpus admission signing bundle payload")
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
        trusted_policy_sha256=trusted_policy_sha256,
        expected_report=report,
        expected_policy=policy,
        expected_data_release=release,
        now=current,
    )
    serialized = canonical_json_bytes(bundle) + b"\n"
    if len(serialized) > MAX_CORPUS_ADMISSION_SIGNING_BUNDLE_BYTES:
        _fail("corpus admission signing bundle", "exceeds its byte limit")
    bundle_sha256 = hashlib.sha256(serialized).hexdigest()

    def validate_published(
        path: Path,
    ) -> VerifiedTrainingCorpusAdmissionSigningBundle:
        publication_time = _fresh_validation_time(
            now, "corpus admission signing-bundle publication time"
        )
        resolved, raw, document = _read_canonical_handoff_document(
            path,
            "corpus admission signing bundle",
            MAX_CORPUS_ADMISSION_SIGNING_BUNDLE_BYTES,
        )
        if hashlib.sha256(raw).hexdigest() != bundle_sha256:
            _fail("corpus admission signing bundle", "changed during publication")
        (
            _,
            publication_spki,
            publication_audience,
            publication_key_id,
            publication_role,
            publication_policy_sha256,
        ) = _validate_trust(trust)
        validated = _validate_signing_bundle_document(
            document,
            public_key_spki_sha256=publication_spki,
            audience=publication_audience,
            key_id=publication_key_id,
            signer_role=publication_role,
            trusted_policy_sha256=publication_policy_sha256,
            expected_report=report,
            expected_policy=policy,
            expected_data_release=release,
            now=publication_time,
        )
        return VerifiedTrainingCorpusAdmissionSigningBundle(
            path=resolved,
            bundle=validated,
            bundle_sha256=bundle_sha256,
            bundle_id=validated["bundleId"],
            corpus_admission_id=validated["corpusAdmissionId"],
            payload_sha256=validated["request"]["payloadSha256"],
            public_key_spki_sha256=publication_spki,
        )

    return _write_no_clobber(
        Path(output_path),
        serialized,
        prepublish_validator=validate_published,
        field="corpus admission signing-bundle output",
    )


def finalize_training_corpus_admission(
    *,
    signing_bundle_path: str | Path,
    signature_path: str | Path,
    output_path: str | Path,
    dataset_path: str | Path,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    resolved_dataset = _regular_file(
        Path(dataset_path), "corpus admission finalization source dataset"
    )
    dataset_bytes = _read_file_bounded(
        resolved_dataset, "corpus admission finalization source dataset", MAX_SFT_BYTES
    )
    return finalize_training_corpus_admission_bytes(
        signing_bundle_path=signing_bundle_path,
        signature_path=signature_path,
        output_path=output_path,
        dataset_bytes=dataset_bytes,
        dataset_source_path=resolved_dataset,
        data_release=data_release,
        quality_policy=quality_policy,
        trust=trust,
        now=now,
    )


def finalize_training_corpus_admission_bytes(
    *,
    signing_bundle_path: str | Path,
    signature_path: str | Path,
    output_path: str | Path,
    dataset_bytes: bytes,
    data_release: Mapping[str, Any],
    quality_policy: Mapping[str, Any],
    trust: TrainingCorpusAdmissionTrust,
    dataset_source_path: str | Path = "captured-dataset.sft.jsonl",
    now: datetime | None = None,
) -> VerifiedTrainingCorpusAdmission:
    public_key, spki, audience, key_id, signer_role, trusted_policy_sha256 = (
        _validate_trust(trust)
    )
    current = _fresh_validation_time(now, "corpus admission finalization time")
    _, bundle_bytes, bundle_document = _read_canonical_handoff_document(
        signing_bundle_path,
        "corpus admission signing bundle",
        MAX_CORPUS_ADMISSION_SIGNING_BUNDLE_BYTES,
    )
    _, _, signature_document = _read_canonical_handoff_document(
        signature_path,
        "corpus admission external signature",
        MAX_CORPUS_ADMISSION_SIGNATURE_BYTES,
    )
    report = derive_training_corpus_quality_report_bytes(
        dataset_bytes, source_path=dataset_source_path
    )
    policy = validate_training_corpus_quality_policy(quality_policy)
    policy_sha256 = training_corpus_quality_policy_sha256(policy)
    if policy_sha256 != trusted_policy_sha256:
        _fail(
            "corpus admission finalization quality policy",
            "does not match externally pinned trust",
        )
    violations = training_corpus_quality_policy_violations(report, policy)
    if violations:
        _fail(
            "corpus admission finalization quality policy",
            "rejects exact dataset: " + "; ".join(violations),
        )
    release = _validate_data_release(data_release, "corpus admission dataRelease")
    bundle = _validate_signing_bundle_document(
        bundle_document,
        public_key_spki_sha256=spki,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        trusted_policy_sha256=trusted_policy_sha256,
        expected_report=report,
        expected_policy=policy,
        expected_data_release=release,
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
        "corpus admission signing bundle.request.payload",
        MAX_CORPUS_ADMISSION_PAYLOAD_BYTES,
    )
    envelope = _unsigned_envelope(
        payload_bytes,
        audience=audience,
        key_id=key_id,
        signer_role=signer_role,
        public_key_spki_sha256=spki,
    )
    envelope["signature"] = _base64url_encode(signature)
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > MAX_CORPUS_ADMISSION_BYTES:
        _fail("corpus admission envelope", "exceeds its byte limit")
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    _validate_envelope(
        envelope,
        trust=trust,
        expected_report=report,
        expected_data_release=release,
        expected_envelope_sha256=envelope_sha256,
        now=current,
    )

    def validate_published(path: Path) -> VerifiedTrainingCorpusAdmission:
        publication_time = _fresh_validation_time(
            now, "corpus admission finalization publication time"
        )
        published_envelope = _load_corpus_admission_envelope(path)
        return _validate_envelope(
            published_envelope,
            trust=trust,
            expected_report=report,
            expected_data_release=release,
            expected_envelope_sha256=envelope_sha256,
            now=publication_time,
        )

    return _write_no_clobber(
        Path(output_path),
        envelope_bytes + b"\n",
        prepublish_validator=validate_published,
    )


__all__ = [
    "CORPUS_ADMISSION_ALGORITHM",
    "CORPUS_ADMISSION_ENVELOPE_SCHEMA_VERSION",
    "CORPUS_ADMISSION_EXTERNAL_DER_SIGNATURE_FORMAT",
    "CORPUS_ADMISSION_EXTERNAL_P1363_SIGNATURE_FORMAT",
    "CORPUS_ADMISSION_SCHEMA_VERSION",
    "CORPUS_ADMISSION_SIGNATURE_SCHEMA_VERSION",
    "CORPUS_ADMISSION_SIGNING_BUNDLE_SCHEMA_VERSION",
    "CORPUS_ADMISSION_SCOPE",
    "CORPUS_QUALITY_POLICY_SCHEMA_VERSION",
    "CORPUS_QUALITY_REPORT_SCHEMA_VERSION",
    "TrainingCorpusAdmissionTrust",
    "VerifiedTrainingCorpusAdmission",
    "VerifiedTrainingCorpusAdmissionSigningBundle",
    "create_training_corpus_admission",
    "create_training_corpus_admission_bytes",
    "derive_training_corpus_quality_report",
    "derive_training_corpus_quality_report_bytes",
    "finalize_training_corpus_admission",
    "finalize_training_corpus_admission_bytes",
    "prepare_training_corpus_admission_signing_bundle",
    "prepare_training_corpus_admission_signing_bundle_bytes",
    "training_corpus_admission_id",
    "training_corpus_admission_signature_id",
    "training_corpus_admission_signing_bundle_id",
    "training_corpus_quality_policy_sha256",
    "training_corpus_quality_policy_violations",
    "training_corpus_quality_report_sha256",
    "validate_training_corpus_quality_policy",
    "validate_training_corpus_quality_report",
    "verify_training_corpus_admission",
    "verify_training_corpus_admission_bytes",
    "verify_training_corpus_admission_file",
]
