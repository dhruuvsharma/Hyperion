from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Any, Iterable, Mapping

from .core import (
    ValidationError,
    _exact_keys,
    _fail,
    _read_file_bounded,
    _reject_reparse_components,
    _regular_file,
    _reject_constant,
    _sha256,
    _string,
    _unique_pairs,
    canonical_json_bytes,
    resolve_bound_path,
    sha256_file,
)
from .csharp_verifier import (
    CHECK_IDS as CSHARP_CHECK_IDS,
    MAX_RESULT_BYTES as MAX_CSHARP_RESULT_BYTES,
    CSharpVerifierAuthorityTrust,
    csharp_strategy_verification_result_sha256,
    prepare_csharp_strategy_verification_inputs,
    run_csharp_strategy_verification,
)
from .evaluation import (
    MAX_EVALUATION_BYTES,
    MAX_EVALUATION_LINE_BYTES,
    MAX_REQUIRED_CHECKS,
    EvaluationTaskSet,
    _evaluation_task_set_from_records,
    _parse_json_document_bytes,
    _parse_jsonl_bytes,
    _validate_evaluation_response_records,
    _validate_response,
    _validate_task,
    _validate_verifier_result,
    _validate_verifier_result_bindings,
    _write_bytes_atomic_no_clobber,
    evaluation_response_set_sha256,
    evidence_sha256,
    validate_verifier_results,
    verifier_result_set_sha256,
    verifier_result_sha256,
    VERIFIER_RESULT_SCHEMA_VERSION,
)
from .evaluation_authoring import EvaluationAuthoringApprovalTrust
from .review_receipts import ExpertModelReviewReceiptTrust
from .verifier_authority import (
    RESULT_SCHEMA_VERSION as CSHARP_RESULT_SCHEMA_VERSION,
    SOURCE_PROFILE as CSHARP_SOURCE_PROFILE,
    validate_csharp_verifier_authority,
)


EXECUTABLE_VERIFIER_SCHEMA_VERSION = "daxalgo.vibe-quant.executable-verifier/v1"
EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION = "daxalgo.vibe-quant.executable-verifier/v2"
DECLARATIVE_OUTPUT_PROFILE = "declarative-output/v1"
RELEASE_VERIFIER_PLAN_SCHEMA_VERSION = "daxalgo.vibe-quant.release-verifier-plan/v1"

MAX_EXECUTABLE_VERIFIER_BYTES = 1_000_000
MAX_CHECK_VALUE_CHARACTERS = 32_000
MAX_JSON_POINTER_CHARACTERS = 1_024
MAX_JSON_POINTER_SEGMENTS = 64
MAX_JSON_OBJECT_KEYS = 128
MAX_JSON_OBJECT_KEY_CHARACTERS = 200
MAX_DECIMAL_CHARACTERS = 128
MAX_DECIMAL_DIGITS = 100
MAX_DECIMAL_ADJUSTED_EXPONENT = 1_000

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
_RELATIVE_TOLERANCE_RE = re.compile(r"^(?:0(?:\.[0-9]+)?|1(?:\.0+)?)$")
_TEXT_KINDS = frozenset({"contains", "not-contains", "equals", "sha256"})
_JSON_KINDS = frozenset(
    {
        "json-string-equals",
        "json-boolean-equals",
        "json-null",
        "json-decimal-close",
        "json-object-exact-keys",
    }
)


@dataclass(frozen=True)
class CSharpVerifierExecutionContext:
    authority_path: Path
    authority_trust: CSharpVerifierAuthorityTrust
    workspace_parent: Path
    verifier_configuration_sha256: str | None = None


@dataclass(frozen=True)
class ReleaseVerifierPlan:
    document: dict[str, Any]
    sha256: str
    uses_csharp: bool


def _csharp_verifier_configuration_sha256(authority: Any) -> str:
    verifier = authority.payload.get("verifier")
    if not isinstance(verifier, dict):
        _fail("C# verifier authority", "does not contain a verifier configuration")
    return hashlib.sha256(
        b"daxalgo-vibe-quant-csharp-verifier-configuration/v1\x00"
        + canonical_json_bytes(verifier)
    ).hexdigest()


def bind_csharp_verifier_execution_context(
    context: CSharpVerifierExecutionContext,
) -> CSharpVerifierExecutionContext:
    if not isinstance(context, CSharpVerifierExecutionContext):
        _fail("C# verifier execution context", "must be externally supplied")
    authority = validate_csharp_verifier_authority(
        context.authority_path,
        trust=context.authority_trust,
    )
    configuration_sha256 = _csharp_verifier_configuration_sha256(authority)
    if (
        context.verifier_configuration_sha256 is not None
        and context.verifier_configuration_sha256 != configuration_sha256
    ):
        _fail(
            "C# verifier authority configuration",
            "does not match the execution context binding",
        )
    return replace(
        context,
        verifier_configuration_sha256=configuration_sha256,
    )


def _identifier(value: Any, field: str) -> str:
    identifier = _string(value, field, max_length=200)
    if not _IDENTIFIER_RE.fullmatch(identifier):
        _fail(field, "contains unsupported characters")
    return identifier


def _json_pointer(value: Any, field: str) -> str:
    if not isinstance(value, str):
        _fail(field, "must be a string")
    if len(value) > MAX_JSON_POINTER_CHARACTERS:
        _fail(field, f"must not exceed {MAX_JSON_POINTER_CHARACTERS} characters")
    if value and not value.startswith("/"):
        _fail(field, "must be empty or use RFC 6901 slash-prefixed form")
    segments = value.split("/")[1:] if value else []
    if len(segments) > MAX_JSON_POINTER_SEGMENTS:
        _fail(field, f"must not exceed {MAX_JSON_POINTER_SEGMENTS} segments")
    for segment in segments:
        index = 0
        while index < len(segment):
            if segment[index] == "~":
                if index + 1 >= len(segment) or segment[index + 1] not in {"0", "1"}:
                    _fail(field, "contains an invalid RFC 6901 escape")
                index += 2
            else:
                index += 1
    return value


def _bounded_decimal(value: str, field: str, *, nonnegative: bool = False) -> Decimal:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_DECIMAL_CHARACTERS
        or not _DECIMAL_RE.fullmatch(value)
    ):
        _fail(field, "must be a bounded finite JSON-decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValidationError(f"{field}: must be a valid decimal") from error
    if not parsed.is_finite():
        _fail(field, "must be finite")
    digits = len(parsed.as_tuple().digits)
    adjusted = parsed.adjusted() if parsed else 0
    if digits > MAX_DECIMAL_DIGITS or abs(adjusted) > MAX_DECIMAL_ADJUSTED_EXPONENT:
        _fail(field, "exceeds the bounded decimal precision or exponent")
    if nonnegative and parsed < 0:
        _fail(field, "must be nonnegative")
    return parsed


def _validated_check(value: Any, index: int) -> dict[str, Any]:
    field = f"executable verifier.checks[{index}]"
    if not isinstance(value, dict):
        _fail(field, "must be an object")
    kind = value.get("kind")
    if not isinstance(kind, str):
        _fail(f"{field}.kind", "must be a string")
    if kind in {"contains", "not-contains", "equals"}:
        check = _exact_keys(value, {"checkId", "kind", "value"}, field)
        _string(check["value"], f"{field}.value", max_length=MAX_CHECK_VALUE_CHARACTERS)
    elif kind == "sha256":
        check = _exact_keys(value, {"checkId", "kind", "value"}, field)
        _sha256(check["value"], f"{field}.value")
    elif kind == "json-string-equals":
        check = _exact_keys(value, {"checkId", "kind", "pointer", "value"}, field)
        _json_pointer(check["pointer"], f"{field}.pointer")
        _string(check["value"], f"{field}.value", max_length=MAX_CHECK_VALUE_CHARACTERS)
    elif kind == "json-boolean-equals":
        check = _exact_keys(value, {"checkId", "kind", "pointer", "value"}, field)
        _json_pointer(check["pointer"], f"{field}.pointer")
        if not isinstance(check["value"], bool):
            _fail(f"{field}.value", "must be a boolean")
    elif kind == "json-null":
        check = _exact_keys(value, {"checkId", "kind", "pointer"}, field)
        _json_pointer(check["pointer"], f"{field}.pointer")
    elif kind == "json-object-exact-keys":
        check = _exact_keys(value, {"checkId", "kind", "pointer", "keys"}, field)
        _json_pointer(check["pointer"], f"{field}.pointer")
        keys = check["keys"]
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JSON_OBJECT_KEYS:
            _fail(
                f"{field}.keys",
                f"must contain 1 to {MAX_JSON_OBJECT_KEYS} keys",
            )
        for key_index, key in enumerate(keys):
            key_field = f"{field}.keys[{key_index}]"
            if not isinstance(key, str) or not key:
                _fail(key_field, "must be a non-empty string")
            if len(key) > MAX_JSON_OBJECT_KEY_CHARACTERS:
                _fail(
                    key_field,
                    f"must not exceed {MAX_JSON_OBJECT_KEY_CHARACTERS} characters",
                )
        if keys != sorted(keys):
            _fail(f"{field}.keys", "must be in ordinal sorted order")
        if len(keys) != len(set(keys)):
            _fail(f"{field}.keys", "must not contain duplicates")
    elif kind == "json-decimal-close":
        check = _exact_keys(
            value,
            {
                "checkId",
                "kind",
                "pointer",
                "expected",
                "absoluteTolerance",
                "relativeTolerance",
            },
            field,
        )
        _json_pointer(check["pointer"], f"{field}.pointer")
        _bounded_decimal(check["expected"], f"{field}.expected")
        _bounded_decimal(
            check["absoluteTolerance"],
            f"{field}.absoluteTolerance",
            nonnegative=True,
        )
        relative = _bounded_decimal(
            check["relativeTolerance"],
            f"{field}.relativeTolerance",
            nonnegative=True,
        )
        if not _RELATIVE_TOLERANCE_RE.fullmatch(check["relativeTolerance"]):
            _fail(
                f"{field}.relativeTolerance",
                "must use a non-exponent decimal form between zero and one",
            )
        if relative > 1:
            _fail(f"{field}.relativeTolerance", "must not exceed one")
    else:
        supported = sorted(_TEXT_KINDS | _JSON_KINDS)
        _fail(f"{field}.kind", f"must be one of {supported}")
    _identifier(check["checkId"], f"{field}.checkId")
    return dict(check)


def _validate_declarative_executable_verifier(
    value: Any,
    task: Mapping[str, Any],
) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {"schemaVersion", "verifierId", "taskId", "profile", "checks"},
        "executable verifier",
    )
    if document["schemaVersion"] != EXECUTABLE_VERIFIER_SCHEMA_VERSION:
        _fail(
            "executable verifier.schemaVersion",
            f"must be {EXECUTABLE_VERIFIER_SCHEMA_VERSION!r}",
        )
    verifier_id = _identifier(document["verifierId"], "executable verifier.verifierId")
    task_id = _identifier(document["taskId"], "executable verifier.taskId")
    if document["profile"] != DECLARATIVE_OUTPUT_PROFILE:
        _fail(
            "executable verifier.profile",
            f"must be {DECLARATIVE_OUTPUT_PROFILE!r}",
        )
    if verifier_id != task["verifier"]["id"] or task_id != task["taskId"]:
        _fail("executable verifier", "identity does not match the bound task")
    values = document["checks"]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_REQUIRED_CHECKS:
        _fail(
            "executable verifier.checks",
            f"must contain 1 to {MAX_REQUIRED_CHECKS} checks",
        )
    checks = [_validated_check(value, index) for index, value in enumerate(values)]
    check_ids = [check["checkId"] for check in checks]
    if check_ids != task["verifier"]["requiredChecks"]:
        _fail(
            "executable verifier.checks",
            "must exactly match the task requiredChecks in declared order",
        )
    if all(check["kind"] == "not-contains" for check in checks):
        _fail(
            "executable verifier.checks",
            "must contain at least one positive output assertion",
        )
    return {**document, "checks": checks}


def _validate_csharp_executable_verifier(
    value: Any,
    task: Mapping[str, Any],
) -> dict[str, Any]:
    document = _exact_keys(
        value,
        {"schemaVersion", "verifierId", "taskId", "profile", "contract", "cases"},
        "executable verifier",
    )
    if document["schemaVersion"] != EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION:
        _fail(
            "executable verifier.schemaVersion",
            f"must be {EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION!r}",
        )
    verifier_id = _identifier(document["verifierId"], "executable verifier.verifierId")
    task_id = _identifier(document["taskId"], "executable verifier.taskId")
    if document["profile"] != CSHARP_SOURCE_PROFILE:
        _fail(
            "executable verifier.profile",
            f"must be {CSHARP_SOURCE_PROFILE!r}",
        )
    if verifier_id != task["verifier"]["id"] or task_id != task["taskId"]:
        _fail("executable verifier", "identity does not match the bound task")
    if task["taskKind"] not in {"CodeGeneration", "CodeRepair"}:
        _fail(
            "executable verifier.profile",
            "is restricted to CodeGeneration or CodeRepair tasks",
        )
    if task["verifier"]["requiredChecks"] != list(CSHARP_CHECK_IDS):
        _fail(
            "executable verifier required checks",
            "must exactly match the fixed C# verifier checks in declared order",
        )
    if not isinstance(document["contract"], dict):
        _fail("executable verifier.contract", "must be an object")
    if not isinstance(document["cases"], list):
        _fail("executable verifier.cases", "must be an array")
    prepare_csharp_strategy_verification_inputs(
        request_id="executable-verifier-profile-validation",
        source_text="public sealed class ProfileValidationPlaceholder {}",
        contract=document["contract"],
        cases=document["cases"],
    )
    return dict(document)


def _validate_executable_verifier(
    raw: bytes,
    task: Mapping[str, Any],
) -> dict[str, Any]:
    value = _parse_json_document_bytes(raw, "executable verifier")
    schema_version = value.get("schemaVersion")
    if schema_version == EXECUTABLE_VERIFIER_SCHEMA_VERSION:
        return _validate_declarative_executable_verifier(value, task)
    if schema_version == EXECUTABLE_VERIFIER_V2_SCHEMA_VERSION:
        return _validate_csharp_executable_verifier(value, task)
    _fail(
        "executable verifier.schemaVersion",
        "must be a supported v1 or v2 executable-verifier schema",
    )


def _parse_output_json(text: str) -> tuple[Any | None, str | None]:
    try:
        return (
            json.loads(
                text,
                object_pairs_hook=_unique_pairs,
                parse_int=Decimal,
                parse_float=Decimal,
                parse_constant=_reject_constant,
            ),
            None,
        )
    except (json.JSONDecodeError, ValidationError, RecursionError):
        return None, "invalid-json"


_MISSING = object()


def _resolve_pointer(document: Any, pointer: str) -> Any:
    current = document
    if not pointer:
        return current
    for encoded in pointer.split("/")[1:]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                return _MISSING
            index = int(token)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _bounded_actual_decimal(value: Any) -> Decimal | None:
    if not isinstance(value, Decimal) or not value.is_finite():
        return None
    digits = len(value.as_tuple().digits)
    adjusted = value.adjusted() if value else 0
    if digits > MAX_DECIMAL_DIGITS or abs(adjusted) > MAX_DECIMAL_ADJUSTED_EXPONENT:
        return None
    return value


def _evaluate_check(
    check: Mapping[str, Any],
    output: str,
    parsed_json: Any | None,
    json_error: str | None,
) -> tuple[bool, str]:
    kind = check["kind"]
    if kind == "contains":
        passed = check["value"] in output
        return passed, "matched" if passed else "required-text-missing"
    if kind == "not-contains":
        passed = check["value"] not in output
        return passed, "absent" if passed else "forbidden-text-present"
    if kind == "equals":
        passed = output == check["value"]
        return passed, "equal" if passed else "text-mismatch"
    if kind == "sha256":
        passed = (
            hashlib.sha256(output.encode("utf-8", errors="strict")).hexdigest()
            == check["value"]
        )
        return passed, "equal" if passed else "sha256-mismatch"
    if json_error is not None:
        return False, json_error
    actual = _resolve_pointer(parsed_json, check["pointer"])
    if actual is _MISSING:
        return False, "json-pointer-missing"
    if kind == "json-string-equals":
        passed = isinstance(actual, str) and actual == check["value"]
        return passed, "equal" if passed else "json-string-mismatch"
    if kind == "json-boolean-equals":
        passed = isinstance(actual, bool) and actual is check["value"]
        return passed, "equal" if passed else "json-boolean-mismatch"
    if kind == "json-null":
        passed = actual is None
        return passed, "null" if passed else "json-value-not-null"
    if kind == "json-object-exact-keys":
        if not isinstance(actual, dict):
            return False, "json-value-not-object"
        passed = sorted(actual) == check["keys"]
        return passed, (
            "json-object-keys-exact" if passed else "json-object-keys-mismatch"
        )
    actual_decimal = _bounded_actual_decimal(actual)
    if actual_decimal is None:
        return False, "json-decimal-missing-or-out-of-bounds"
    expected = _bounded_decimal(check["expected"], "executable verifier expected")
    absolute = _bounded_decimal(
        check["absoluteTolerance"],
        "executable verifier absolute tolerance",
        nonnegative=True,
    )
    relative = _bounded_decimal(
        check["relativeTolerance"],
        "executable verifier relative tolerance",
        nonnegative=True,
    )
    with localcontext() as context:
        context.prec = 256
        context.Emax = 5_000
        context.Emin = -5_000
        difference = abs(actual_decimal - expected)
        allowed = max(absolute, relative * abs(expected))
    passed = difference <= allowed
    return passed, "within-tolerance" if passed else "outside-tolerance"


def _execute_declarative_executable_verifier(
    task: Mapping[str, Any],
    response: Mapping[str, Any],
    verifier: Mapping[str, Any],
    *,
    line_number: int,
) -> dict[str, Any]:
    output = response["output"]["text"]
    needs_json = any(check["kind"] in _JSON_KINDS for check in verifier["checks"])
    parsed_json, json_error = _parse_output_json(output) if needs_json else (None, None)
    checks: list[dict[str, Any]] = []
    for check in verifier["checks"]:
        passed, reason = _evaluate_check(check, output, parsed_json, json_error)
        evidence = (
            f"executor={DECLARATIVE_OUTPUT_PROFILE};kind={check['kind']};"
            f"outcome={'pass' if passed else 'fail'};reason={reason}"
        )
        checks.append(
            {
                "checkId": check["checkId"],
                "passed": passed,
                "evidence": evidence,
                "evidenceSha256": evidence_sha256(evidence),
            }
        )
    result: dict[str, Any] = {
        "schemaVersion": VERIFIER_RESULT_SCHEMA_VERSION,
        "resultSha256": "0" * 64,
        "runId": response["runId"],
        "taskId": task["taskId"],
        "taskSha256": task["taskSha256"],
        "responseSha256": response["responseSha256"],
        "verifierId": task["verifier"]["id"],
        "verifierSha256": task["verifier"]["sha256"],
        "checks": checks,
        "accepted": all(check["passed"] for check in checks),
    }
    result["resultSha256"] = verifier_result_sha256(result)
    return _validate_verifier_result(result, line_number)


def _csharp_request_id(
    task: Mapping[str, Any],
    response: Mapping[str, Any],
) -> str:
    identity = {
        "domain": "daxalgo-vibe-quant-release-csharp-request/v1",
        "taskSha256": task["taskSha256"],
        "responseSha256": response["responseSha256"],
        "verifierSha256": task["verifier"]["sha256"],
    }
    return (
        "release-csharp-sha256-"
        + hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    )


def _write_private_snapshot(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _execute_csharp_executable_verifier(
    task: Mapping[str, Any],
    response: Mapping[str, Any],
    verifier: Mapping[str, Any],
    *,
    line_number: int,
    context: CSharpVerifierExecutionContext,
) -> dict[str, Any]:
    if not isinstance(context, CSharpVerifierExecutionContext):
        _fail(
            "C# verifier execution context",
            "must be externally supplied for the C# release verifier profile",
        )
    if not isinstance(context.authority_trust, CSharpVerifierAuthorityTrust):
        _fail("C# verifier authority trust", "must be externally supplied")
    workspace_parent = _reject_reparse_components(
        Path(context.workspace_parent), "C# verifier workspace parent"
    )
    if not workspace_parent.is_dir():
        _fail("C# verifier workspace parent", "must be an existing directory")

    authority = validate_csharp_verifier_authority(
        context.authority_path,
        trust=context.authority_trust,
    )
    configuration_sha256 = _csharp_verifier_configuration_sha256(authority)
    if (
        context.verifier_configuration_sha256 is not None
        and configuration_sha256 != context.verifier_configuration_sha256
    ):
        _fail(
            "C# verifier authority configuration",
            "changed across the release verification run",
        )
    request_raw, source_raw, expectations_raw = (
        prepare_csharp_strategy_verification_inputs(
            request_id=_csharp_request_id(task, response),
            source_text=response["output"]["text"],
            contract=verifier["contract"],
            cases=verifier["cases"],
        )
    )
    with tempfile.TemporaryDirectory(
        prefix=".release-csharp-verifier-", dir=workspace_parent
    ) as temporary:
        root = Path(temporary)
        request_path = root / "request.json"
        source_path = root / "source.cs"
        expectations_path = root / "expectations.json"
        result_path = root / "result.json"
        _write_private_snapshot(request_path, request_raw)
        _write_private_snapshot(source_path, source_raw)
        _write_private_snapshot(expectations_path, expectations_raw)
        standalone = run_csharp_strategy_verification(
            request_path=request_path,
            source_path=source_path,
            expectations_path=expectations_path,
            authority_path=context.authority_path,
            authority_trust=context.authority_trust,
            output_path=result_path,
        )
        installed = _read_file_bounded(
            result_path,
            "C# strategy verification result",
            MAX_CSHARP_RESULT_BYTES,
        )
        if installed != canonical_json_bytes(standalone) + b"\n":
            _fail("C# strategy verification result", "published bytes changed")

    current_authority = validate_csharp_verifier_authority(
        context.authority_path,
        trust=context.authority_trust,
    )
    if (
        current_authority.payload_sha256 != authority.payload_sha256
        or current_authority.envelope_sha256 != authority.envelope_sha256
        or standalone.get("verifierAuthority") != authority.as_dict()
    ):
        _fail("C# verifier authority", "changed during release verification")
    if standalone.get("schemaVersion") != CSHARP_RESULT_SCHEMA_VERSION:
        _fail("C# strategy verification result.schemaVersion", "is unsupported")
    if standalone.get("resultSha256") != csharp_strategy_verification_result_sha256(
        standalone
    ):
        _fail("C# strategy verification result.resultSha256", "does not match")

    request_sha256 = hashlib.sha256(request_raw).hexdigest()
    source_sha256 = hashlib.sha256(source_raw).hexdigest()
    expectations_sha256 = hashlib.sha256(expectations_raw).hexdigest()
    expected_bindings = {
        "request": {
            "requestId": _csharp_request_id(task, response),
            "sha256": request_sha256,
        },
        "source": {"sha256": source_sha256},
        "expectations": {"sha256": expectations_sha256},
    }
    for name, expected in expected_bindings.items():
        if standalone.get(name) != expected:
            _fail(
                f"C# strategy verification result.{name}",
                "does not match the derived release input",
            )

    standalone_checks = standalone.get("checks")
    if not isinstance(standalone_checks, list) or [
        check.get("checkId") for check in standalone_checks
    ] != list(CSHARP_CHECK_IDS):
        _fail(
            "C# strategy verification result.checks",
            "must contain the fixed checks in canonical order",
        )
    stable = {
        "request": request_sha256,
        "source": source_sha256,
        "expectations": expectations_sha256,
        "toolchain": standalone["workerResult"]["toolchainSha256"],
        "imageDigest": standalone["image"]["digest"],
        "imageId": standalone["image"]["imageId"],
        "platform": standalone["image"]["platform"],
        "sandbox": standalone["sandboxPolicy"]["sha256"],
        "configuration": configuration_sha256,
    }
    checks: list[dict[str, Any]] = []
    for check in standalone_checks:
        if not isinstance(check.get("passed"), bool):
            _fail("C# strategy verification result.checks", "contains invalid outcome")
        detail = _string(
            check.get("evidence"),
            "C# strategy verification result.checks.evidence",
            max_length=MAX_CHECK_VALUE_CHARACTERS,
        )
        detail_sha256 = hashlib.sha256(detail.encode("utf-8")).hexdigest()
        if check.get("evidenceSha256") != detail_sha256:
            _fail(
                "C# strategy verification result.checks.evidenceSha256",
                "does not match the evidence text",
            )
        evidence = (
            f"executor={CSHARP_SOURCE_PROFILE};outcome="
            f"{'pass' if check['passed'] else 'fail'};request={stable['request']};"
            f"source={stable['source']};expectations={stable['expectations']};"
            f"toolchain={stable['toolchain']};image-digest={stable['imageDigest']};"
            f"image-id={stable['imageId']};platform={stable['platform']};"
            f"sandbox={stable['sandbox']};configuration={stable['configuration']};"
            f"detail={detail_sha256}"
        )
        checks.append(
            {
                "checkId": check["checkId"],
                "passed": check["passed"],
                "evidence": evidence,
                "evidenceSha256": evidence_sha256(evidence),
            }
        )
    accepted = all(check["passed"] for check in checks)
    if standalone.get("accepted") is not accepted:
        _fail("C# strategy verification result.accepted", "contradicts its checks")
    result: dict[str, Any] = {
        "schemaVersion": VERIFIER_RESULT_SCHEMA_VERSION,
        "resultSha256": "0" * 64,
        "runId": response["runId"],
        "taskId": task["taskId"],
        "taskSha256": task["taskSha256"],
        "responseSha256": response["responseSha256"],
        "verifierId": task["verifier"]["id"],
        "verifierSha256": task["verifier"]["sha256"],
        "checks": checks,
        "accepted": accepted,
    }
    result["resultSha256"] = verifier_result_sha256(result)
    return _validate_verifier_result(result, line_number)


def _execute_executable_verifier(
    task: Mapping[str, Any],
    response: Mapping[str, Any],
    verifier_raw: bytes,
    *,
    line_number: int,
    csharp_context: CSharpVerifierExecutionContext | None = None,
) -> dict[str, Any]:
    actual_sha256 = hashlib.sha256(verifier_raw).hexdigest()
    if actual_sha256 != task["verifier"]["sha256"]:
        _fail("executable verifier", "bytes do not match the bound task hash")
    verifier = _validate_executable_verifier(verifier_raw, task)
    if verifier["profile"] == DECLARATIVE_OUTPUT_PROFILE:
        if csharp_context is not None:
            _fail(
                "C# verifier execution context",
                "cannot be supplied to a declarative verifier task",
            )
        return _execute_declarative_executable_verifier(
            task, response, verifier, line_number=line_number
        )
    if csharp_context is None:
        _fail(
            "C# verifier execution context",
            "is required for the C# release verifier profile",
        )
    return _execute_csharp_executable_verifier(
        task,
        response,
        verifier,
        line_number=line_number,
        context=csharp_context,
    )


def _release_root(path: str | os.PathLike[str]) -> Path:
    requested = Path(path)
    manifest = requested / "release-manifest.json" if requested.is_dir() else requested
    return _regular_file(manifest, "release manifest").parent


def _release_verifier_snapshots(
    *,
    release_path: str | os.PathLike[str],
    release: Mapping[str, Any],
    tasks: EvaluationTaskSet,
) -> dict[str, tuple[Path, bytes]]:
    root = _release_root(release_path)
    bindings = {
        binding["taskId"]: binding for binding in release["evaluation"]["taskBindings"]
    }
    snapshots: dict[str, tuple[Path, bytes]] = {}
    for task in tasks.records:
        task_id = task["taskId"]
        binding = bindings.get(task_id)
        if binding is None:
            _fail(
                "release executable verifier", f"missing task binding for {task_id!r}"
            )
        verifier = binding["verifier"]
        if (
            binding["taskSha256"] != task["taskSha256"]
            or verifier["id"] != task["verifier"]["id"]
            or verifier["sha256"] != task["verifier"]["sha256"]
        ):
            _fail("release executable verifier", "task or verifier binding changed")
        path = resolve_bound_path(
            root,
            verifier["path"],
            f"release verifier for task {task_id}",
        )
        path = _regular_file(path, f"release verifier for task {task_id}")
        raw = _read_file_bounded(
            path,
            f"release verifier for task {task_id}",
            MAX_EXECUTABLE_VERIFIER_BYTES,
        )
        if (
            len(raw) != verifier["sizeBytes"]
            or hashlib.sha256(raw).hexdigest() != verifier["sha256"]
        ):
            _fail(
                f"release verifier for task {task_id}",
                "bytes do not match the fully validated release binding",
            )
        snapshots[task_id] = (path, raw)
    return snapshots


def derive_release_verifier_plan(
    *,
    release_path: str | os.PathLike[str],
    release: Mapping[str, Any],
    tasks: EvaluationTaskSet,
) -> ReleaseVerifierPlan:
    """Derive the exact, non-executing verifier inventory for a release task set."""
    from .release import validate_release_evaluation_task_set

    validate_release_evaluation_task_set(release, tasks)
    snapshots = _release_verifier_snapshots(
        release_path=release_path,
        release=release,
        tasks=tasks,
    )
    task_by_id = {task["taskId"]: task for task in tasks.records}
    plan_tasks: list[dict[str, Any]] = []
    uses_csharp = False
    for task_id in sorted(task_by_id):
        task = task_by_id[task_id]
        verifier = _validate_executable_verifier(snapshots[task_id][1], task)
        profile = verifier["profile"]
        uses_csharp = uses_csharp or profile == CSHARP_SOURCE_PROFILE
        plan_tasks.append(
            {
                "taskId": task_id,
                "taskSha256": task["taskSha256"],
                "verifierId": task["verifier"]["id"],
                "verifierSha256": task["verifier"]["sha256"],
                "profile": profile,
            }
        )
    document = {
        "schemaVersion": RELEASE_VERIFIER_PLAN_SCHEMA_VERSION,
        "taskSetSha256": tasks.task_set_sha256,
        "tasks": plan_tasks,
    }
    sha256 = hashlib.sha256(
        b"daxalgo-vibe-quant-release-verifier-plan/v1\x00"
        + canonical_json_bytes(document)
    ).hexdigest()
    return ReleaseVerifierPlan(
        document=document, sha256=sha256, uses_csharp=uses_csharp
    )


def execute_release_verifiers(
    *,
    release_path: str | os.PathLike[str],
    release: Mapping[str, Any],
    release_identity: Mapping[str, str],
    tasks: EvaluationTaskSet,
    responses: Iterable[Mapping[str, Any]],
    csharp_context: CSharpVerifierExecutionContext | None = None,
) -> tuple[dict[str, Any], ...]:
    from .release import validate_release_evaluation_task_set

    validate_release_evaluation_task_set(release, tasks)
    response_records = tuple(responses)
    for response in response_records:
        if (
            response["dataRelease"] != release_identity
            or response["researchOnly"] is not False
            or response["evidenceStatus"] != "release-bound"
        ):
            _fail(
                "executable verifier response",
                "must be bound to the exact validated release",
            )
    response_by_task = {response["taskId"]: response for response in response_records}
    snapshots = _release_verifier_snapshots(
        release_path=release_path,
        release=release,
        tasks=tasks,
    )
    task_by_id = {task["taskId"]: task for task in tasks.records}
    verifier_profiles = {
        task_id: _validate_executable_verifier(
            snapshots[task_id][1], task_by_id[task_id]
        )["profile"]
        for task_id in sorted(task_by_id)
    }
    uses_csharp = any(
        profile == CSHARP_SOURCE_PROFILE for profile in verifier_profiles.values()
    )
    if uses_csharp and csharp_context is None:
        _fail(
            "C# verifier execution context",
            "is required when a release contains the C# verifier profile",
        )
    if not uses_csharp and csharp_context is not None:
        _fail(
            "C# verifier execution context",
            "cannot be supplied when a release has no C# verifier profile",
        )
    if csharp_context is not None:
        csharp_context = bind_csharp_verifier_execution_context(csharp_context)
    results: list[dict[str, Any]] = []
    for line_number, task_id in enumerate(sorted(task_by_id), start=1):
        response = response_by_task.get(task_id)
        if response is None:
            _fail(
                "executable verifier responses",
                f"missing response for task {task_id!r}",
            )
        results.append(
            _execute_executable_verifier(
                task_by_id[task_id],
                response,
                snapshots[task_id][1],
                line_number=line_number,
                csharp_context=(
                    csharp_context
                    if verifier_profiles[task_id] == CSHARP_SOURCE_PROFILE
                    else None
                ),
            )
        )
    _validate_verifier_result_bindings(
        results,
        tasks,
        response_records,
        require_complete=True,
    )
    return tuple(results)


def execute_release_declarative_verifiers(
    *,
    release_path: str | os.PathLike[str],
    release: Mapping[str, Any],
    release_identity: Mapping[str, str],
    tasks: EvaluationTaskSet,
    responses: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Freshly execute only non-C# tasks in a mixed audited release suite."""
    from .release import validate_release_evaluation_task_set

    validate_release_evaluation_task_set(release, tasks)
    response_records = tuple(responses)
    for response in response_records:
        if (
            response["dataRelease"] != release_identity
            or response["researchOnly"] is not False
            or response["evidenceStatus"] != "release-bound"
        ):
            _fail(
                "declarative verifier response",
                "must be bound to the exact validated release",
            )
    response_by_task = {response["taskId"]: response for response in response_records}
    snapshots = _release_verifier_snapshots(
        release_path=release_path,
        release=release,
        tasks=tasks,
    )
    task_by_id = {task["taskId"]: task for task in tasks.records}
    results: list[dict[str, Any]] = []
    csharp_count = 0
    for line_number, task_id in enumerate(sorted(task_by_id), start=1):
        task = task_by_id[task_id]
        verifier_raw = snapshots[task_id][1]
        profile = _validate_executable_verifier(verifier_raw, task)["profile"]
        if profile == CSHARP_SOURCE_PROFILE:
            csharp_count += 1
            continue
        response = response_by_task.get(task_id)
        if response is None:
            _fail(
                "declarative verifier responses",
                f"missing response for task {task_id!r}",
            )
        results.append(
            _execute_executable_verifier(
                task,
                response,
                verifier_raw,
                line_number=line_number,
                csharp_context=None,
            )
        )
    if csharp_count == 0:
        _fail(
            "C# verifier replay audit",
            "cannot be used when the release has no C# verifier task",
        )
    return tuple(results)


def _snapshot_task_and_response_inputs(
    tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
) -> tuple[
    dict[str, Path],
    dict[str, bytes],
    dict[str, str],
    EvaluationTaskSet,
    tuple[dict[str, Any], ...],
]:
    paths = {
        "tasks": _regular_file(Path(tasks_path), "executable verifier tasks input"),
        "responses": _regular_file(
            Path(responses_path), "executable verifier responses input"
        ),
    }
    raw = {
        name: _read_file_bounded(
            path,
            f"executable verifier {name} input",
            MAX_EVALUATION_BYTES,
        )
        for name, path in paths.items()
    }
    hashes = {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}
    task_records = _parse_jsonl_bytes(
        raw["tasks"], "evaluation task file", _validate_task
    )
    tasks = _evaluation_task_set_from_records(
        paths["tasks"], hashes["tasks"], task_records
    )
    response_records = _parse_jsonl_bytes(
        raw["responses"], "evaluation response file", _validate_response
    )
    responses = _validate_evaluation_response_records(response_records, tasks)
    return paths, raw, hashes, tasks, responses


def run_release_verifiers(
    *,
    tasks_path: str | os.PathLike[str],
    responses_path: str | os.PathLike[str],
    release_path: str | os.PathLike[str],
    review_receipt_trust: ExpertModelReviewReceiptTrust,
    evaluation_authoring_approval_trust: EvaluationAuthoringApprovalTrust,
    output_path: str | os.PathLike[str],
    review_receipt_now: datetime | None = None,
    csharp_verifier_authority_path: str | os.PathLike[str] | None = None,
    csharp_verifier_authority_trust: CSharpVerifierAuthorityTrust | None = None,
) -> dict[str, Any]:
    if not isinstance(review_receipt_trust, ExpertModelReviewReceiptTrust):
        _fail(
            "review-receipt trust",
            "must be supplied for release-bound executable verification",
        )
    if not isinstance(
        evaluation_authoring_approval_trust, EvaluationAuthoringApprovalTrust
    ):
        _fail(
            "evaluation-authoring approval trust",
            "must be supplied for release-bound executable verification",
        )
    if (csharp_verifier_authority_path is None) != (
        csharp_verifier_authority_trust is None
    ):
        _fail(
            "C# verifier execution context",
            "authority path and external trust must be supplied together",
        )
    destination = _reject_reparse_components(
        Path(output_path), "verifier result output", allow_missing_suffix=True
    )
    output_parent = _reject_reparse_components(
        destination.parent, "verifier result output parent"
    )
    if not output_parent.is_dir():
        _fail("verifier result output parent", "must be an existing directory")
    csharp_context = None
    if csharp_verifier_authority_path is not None:
        csharp_context = CSharpVerifierExecutionContext(
            authority_path=Path(csharp_verifier_authority_path),
            authority_trust=csharp_verifier_authority_trust,
            workspace_parent=output_parent,
        )
    from .release import validate_corpus_evaluation_release_with_identity

    paths, _, hashes, tasks, responses = _snapshot_task_and_response_inputs(
        tasks_path, responses_path
    )
    release, release_identity = validate_corpus_evaluation_release_with_identity(
        release_path,
        review_receipt_trust=review_receipt_trust,
        evaluation_authoring_approval_trust=(evaluation_authoring_approval_trust),
        now=review_receipt_now,
    )
    results = execute_release_verifiers(
        release_path=release_path,
        release=release,
        release_identity=release_identity,
        tasks=tasks,
        responses=responses,
        csharp_context=csharp_context,
    )
    output = bytearray()
    for line_number, result in enumerate(results, start=1):
        encoded = canonical_json_bytes(result) + b"\n"
        if len(encoded) > MAX_EVALUATION_LINE_BYTES:
            _fail(
                f"verifier result line {line_number}",
                f"exceeds {MAX_EVALUATION_LINE_BYTES} bytes",
            )
        if len(output) + len(encoded) > MAX_EVALUATION_BYTES:
            _fail("verifier result output", f"exceeds {MAX_EVALUATION_BYTES} bytes")
        output.extend(encoded)

    def assert_inputs_unchanged() -> None:
        for name, path in paths.items():
            if sha256_file(path, max_bytes=MAX_EVALUATION_BYTES) != hashes[name]:
                _fail(f"executable verifier {name} input", "changed during execution")
        current_release, current_identity = (
            validate_corpus_evaluation_release_with_identity(
                release_path,
                review_receipt_trust=review_receipt_trust,
                evaluation_authoring_approval_trust=(
                    evaluation_authoring_approval_trust
                ),
                now=review_receipt_now,
            )
        )
        if current_release != release or current_identity != release_identity:
            _fail("evaluation release", "changed during executable verification")

    assert_inputs_unchanged()
    _write_bytes_atomic_no_clobber(
        destination,
        output,
        "verifier result output",
        before_install=assert_inputs_unchanged,
    )
    installed = validate_verifier_results(
        destination,
        tasks,
        responses,
        require_complete=True,
    )
    if installed != results:
        _fail("verifier result output", "installed bytes changed during publication")
    return {
        "schemaVersion": VERIFIER_RESULT_SCHEMA_VERSION,
        "recordCount": len(installed),
        "taskSetSha256": tasks.task_set_sha256,
        "responseSetSha256": evaluation_response_set_sha256(responses),
        "verifierResultSetSha256": verifier_result_set_sha256(installed),
        "releaseId": release_identity["releaseId"],
        "outputPath": str(destination),
    }
