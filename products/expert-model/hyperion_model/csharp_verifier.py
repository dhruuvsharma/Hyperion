from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .core import (
    ValidationError,
    _exact_keys,
    _fail,
    _reject_reparse_components,
    _sha256,
    _unique_pairs,
    canonical_json_bytes,
)
from .verifier_authority import (
    CONTAINER_ENVIRONMENT,
    DOCKER_CLIENT_ENVIRONMENT_PROFILE,
    MAX_DOCKER_CLIENT_BYTES,
    MEMORY_BYTES,
    NOFILE_LIMIT,
    REQUEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION_V1,
    SANDBOX_POLICY_PROFILE,
    SOURCE_PROFILE,
    TMPFS,
    VERIFIER_PLATFORM,
    WORKER_RESULT_SCHEMA_VERSION,
    CSharpVerifierAuthorityTrust,
    csharp_verifier_toolchain_sha256,
    ensure_csharp_verifier_authority_active,
    supported_sandbox_policy,
    validate_csharp_verifier_authority,
)


EXPECTATIONS_SCHEMA_VERSION = "daxalgo.verifier.headless-strategy-expectations/v1"

MAX_REQUEST_BYTES = 1_048_576
MAX_SOURCE_BYTES = 262_144
MAX_EXPECTATIONS_BYTES = 65_536
MAX_WORKER_RESULT_BYTES = 8_388_608
MAX_DOCKER_OUTPUT_BYTES = 262_144
MAX_RESULT_BYTES = 262_144
WALL_CLOCK_SECONDS = 30.0
CLEANUP_SECONDS = 5.0
STAGE_FRAME_MAGIC = b"DAXVSTG1"
MAX_STAGE_FRAME_BYTES = (
    len(STAGE_FRAME_MAGIC) + 8 + MAX_REQUEST_BYTES + MAX_SOURCE_BYTES
)

MAX_CASES = 8
MAX_TICKS_PER_CASE = 2_048
MAX_TOTAL_TICKS = 8_192
MAX_TRACE_ENTRIES = 64
MAX_OFFSET_MILLISECONDS = 7 * 24 * 60 * 60 * 1_000
MAX_PRICE = Decimal("1000000000000")
MAX_QUOTE_SIZE = 1_000_000_000_000

CONTAINER_REQUEST_PATH = "/work/request.json"
CONTAINER_SOURCE_PATH = "/work/source.cs"
CONTAINER_WORK_PATH = "/work"

CHECK_IDS = (
    "source-binding",
    "compile",
    "analyzers",
    "deterministic-execution",
    "reference-cases",
    "sandbox-policy",
)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IMAGE_RE = re.compile(r"^(?=.{1,500}$)[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_ENTRYPOINT_RE = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,7})?Z$"
)


class InfrastructureError(RuntimeError):
    """Raised when verification infrastructure cannot produce trusted evidence."""


class _ProcessTimeoutError(TimeoutError):
    pass


class _ProcessOutputLimitError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


ProcessRunner = Callable[..., ProcessResult]


@dataclass(frozen=True)
class _DockerRuntimeSession:
    source_client_path: Path
    source_client_sha256: str
    source_client_size: int
    client_command: str
    daemon_endpoint: str
    environment: Mapping[str, str]
    config_directory: Path


def _text(value: Any, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _fail(field, f"must contain between {minimum} and {maximum} characters")
    if any(
        ord(character) < 32
        or 127 <= ord(character) <= 159
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        _fail(field, "contains a control character or unpaired surrogate")
    return value


def _identifier(value: Any, field: str) -> str:
    identifier = _text(value, field, 1, 128)
    if not _IDENTIFIER_RE.fullmatch(identifier):
        _fail(field, "contains an unsupported character")
    return identifier


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        _fail(field, "must be a boolean")
    return value


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(field, "must be an exact integer")
    if not minimum <= value <= maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return value


def _number(value: Any, field: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        _fail(field, "must be a finite JSON number")
    number = Decimal(value)
    if not number.is_finite():
        _fail(field, "must be finite")
    return number


def _parse_json(raw: bytes, field: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail(field, "UTF-8 byte-order marks are not accepted")
    if b"\x00" in raw:
        _fail(field, "NUL bytes are not accepted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(
            f"{field}: invalid UTF-8 at byte {error.start}"
        ) from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_float=Decimal,
            parse_constant=lambda value: _fail(
                field, f"contains non-finite numeric constant {value!r}"
            ),
        )
    except json.JSONDecodeError as error:
        raise ValidationError(
            f"{field}: invalid JSON at line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error
    except RecursionError as error:
        raise ValidationError(f"{field}: exceeds the nesting limit") from error


def _parse_json_object(raw: bytes, field: str) -> dict[str, Any]:
    value = _parse_json(raw, field)
    if not isinstance(value, dict):
        _fail(field, "root must be an object")
    return value


def _read_input_snapshot(
    path: str | os.PathLike[str], field: str, max_bytes: int
) -> tuple[Path, bytes]:
    absolute = _reject_reparse_components(Path(path), field)
    before = os.lstat(absolute)
    if not stat.S_ISREG(before.st_mode):
        _fail(field, f"regular file does not exist: {absolute}")
    if before.st_nlink != 1:
        _fail(field, "hard-linked files are not accepted")
    if before.st_size > max_bytes:
        _fail(field, f"exceeds the {max_bytes}-byte limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            _fail(field, "must remain a single-link regular file while opened")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            _fail(field, "changed while it was being opened")
        raw = bytearray()
        while len(raw) <= max_bytes:
            block = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > max_bytes:
            _fail(field, f"exceeds the {max_bytes}-byte limit")
        after = os.fstat(descriptor)
        if (
            after.st_nlink != 1
            or after.st_size != opened.st_size
            or getattr(after, "st_mtime_ns", None)
            != getattr(opened, "st_mtime_ns", None)
        ):
            _fail(field, "changed while it was being read")
    finally:
        os.close(descriptor)
    return absolute, bytes(raw)


def _require_local_daemon_endpoint(endpoint: str) -> None:
    if os.name == "nt":
        if not endpoint.startswith("npipe:////./pipe/"):
            raise InfrastructureError(
                "signed Docker daemon endpoint is not a local Windows named pipe"
            )
    elif not endpoint.startswith("unix:///"):
        raise InfrastructureError(
            "signed Docker daemon endpoint is not a local Unix socket"
        )


def _require_empty_private_directory(path: Path, field: str) -> None:
    absolute = _reject_reparse_components(path, field)
    file_stat = os.lstat(absolute)
    if not stat.S_ISDIR(file_stat.st_mode):
        raise InfrastructureError(f"{field} is not a directory")
    try:
        with os.scandir(absolute) as entries:
            if next(entries, None) is not None:
                raise InfrastructureError(f"{field} is not empty")
    except OSError as error:
        raise InfrastructureError(f"could not inspect {field}") from error


def _validate_docker_client_snapshot(
    path: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    field: str,
) -> bytes:
    try:
        _, raw = _read_input_snapshot(path, field, MAX_DOCKER_CLIENT_BYTES)
    except (OSError, ValidationError) as error:
        raise InfrastructureError(f"{field} could not be authenticated") from error
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise InfrastructureError(f"{field} did not match the signed authority")
    if os.name != "nt":
        mode = os.lstat(path).st_mode
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0:
            raise InfrastructureError(f"{field} is not executable")
    return raw


def _prepare_docker_runtime_session(
    binding: Mapping[str, Any], stage: Path
) -> _DockerRuntimeSession:
    if binding.get("environmentPolicy") != DOCKER_CLIENT_ENVIRONMENT_PROFILE:
        raise InfrastructureError("signed Docker environment policy is unsupported")
    client = binding["client"]
    source_path = Path(client["path"])
    expected_sha256 = client["sha256"]
    expected_size = client["sizeBytes"]
    _require_local_daemon_endpoint(binding["daemonEndpoint"])
    raw = _validate_docker_client_snapshot(
        source_path,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        field="signed Docker client",
    )

    suffix = source_path.suffix if os.name == "nt" else ""
    private_client = stage / f"docker-client{suffix}"
    _write_snapshot(private_client, raw)
    if os.name != "nt":
        os.chmod(private_client, stat.S_IRUSR | stat.S_IXUSR)
    _validate_docker_client_snapshot(
        private_client,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        field="private Docker client snapshot",
    )

    directories = {
        name: stage / name for name in ("docker-config", "docker-home", "docker-temp")
    }
    for directory in directories.values():
        directory.mkdir(mode=stat.S_IRWXU)
    _require_empty_private_directory(
        directories["docker-config"], "private Docker configuration directory"
    )
    environment = {
        "DOCKER_CLI_HINTS": "false",
        "DOCKER_CONFIG": os.fspath(directories["docker-config"]),
        "DOCKER_HOST": binding["daemonEndpoint"],
        "HOME": os.fspath(directories["docker-home"]),
        "TEMP": os.fspath(directories["docker-temp"]),
        "TMP": os.fspath(directories["docker-temp"]),
        "TMPDIR": os.fspath(directories["docker-temp"]),
    }
    return _DockerRuntimeSession(
        source_client_path=source_path,
        source_client_sha256=expected_sha256,
        source_client_size=expected_size,
        client_command=os.fspath(private_client),
        daemon_endpoint=binding["daemonEndpoint"],
        environment=environment,
        config_directory=directories["docker-config"],
    )


def _require_docker_runtime_session(session: _DockerRuntimeSession) -> None:
    _validate_docker_client_snapshot(
        Path(session.client_command),
        expected_sha256=session.source_client_sha256,
        expected_size=session.source_client_size,
        field="private Docker client snapshot",
    )
    _require_empty_private_directory(
        session.config_directory, "private Docker configuration directory"
    )


def _require_signed_docker_client_unchanged(session: _DockerRuntimeSession) -> None:
    _validate_docker_client_snapshot(
        session.source_client_path,
        expected_sha256=session.source_client_sha256,
        expected_size=session.source_client_size,
        field="signed Docker client",
    )


def _validate_source(raw: bytes) -> str:
    if not raw:
        _fail("strategy source", "must not be empty")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("strategy source", "UTF-8 byte-order marks are not accepted")
    if b"\x00" in raw:
        _fail("strategy source", "NUL bytes are not accepted")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(
            f"strategy source: invalid UTF-8 at byte {error.start}"
        ) from error
    return hashlib.sha256(raw).hexdigest()


def _validate_request(raw: bytes) -> dict[str, Any]:
    request = _exact_keys(
        _parse_json_object(raw, "verification request"),
        {
            "schemaVersion",
            "profile",
            "requestId",
            "sourceSha256",
            "contract",
            "cases",
        },
        "verification request",
    )
    if request["schemaVersion"] != REQUEST_SCHEMA_VERSION:
        _fail(
            "verification request.schemaVersion",
            f"must be {REQUEST_SCHEMA_VERSION!r}",
        )
    if request["profile"] != SOURCE_PROFILE:
        _fail("verification request.profile", f"must be {SOURCE_PROFILE!r}")
    _identifier(request["requestId"], "verification request.requestId")
    _sha256(request["sourceSha256"], "verification request.sourceSha256")

    contract = _exact_keys(
        request["contract"],
        {"symbol", "secType", "exchange", "currency", "primaryExchange"},
        "verification request.contract",
    )
    for name, maximum in (
        ("symbol", 64),
        ("secType", 32),
        ("exchange", 64),
        ("currency", 16),
        ("primaryExchange", 64),
    ):
        _text(contract[name], f"verification request.contract.{name}", 1, maximum)

    cases = request["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        _fail(
            "verification request.cases",
            f"must contain between 1 and {MAX_CASES} cases",
        )
    case_ids: set[str] = set()
    total_ticks = 0
    for case_index, raw_case in enumerate(cases):
        case_field = f"verification request.cases[{case_index}]"
        case = _exact_keys(raw_case, {"caseId", "startUtc", "ticks"}, case_field)
        case_id = _identifier(case["caseId"], f"{case_field}.caseId")
        if case_id in case_ids:
            _fail(f"{case_field}.caseId", "duplicates an earlier case ID")
        case_ids.add(case_id)
        start_utc = _text(case["startUtc"], f"{case_field}.startUtc", 20, 40)
        if not _UTC_RE.fullmatch(start_utc):
            _fail(f"{case_field}.startUtc", "must be a UTC timestamp ending in Z")
        try:
            parsed = datetime.fromisoformat(start_utc[:-1] + "+00:00")
        except ValueError as error:
            raise ValidationError(
                f"{case_field}.startUtc: invalid timestamp"
            ) from error
        if parsed.tzinfo != timezone.utc or not 2000 <= parsed.year <= 2100:
            _fail(f"{case_field}.startUtc", "must be a bounded UTC timestamp")

        ticks = case["ticks"]
        if not isinstance(ticks, list) or not 1 <= len(ticks) <= MAX_TICKS_PER_CASE:
            _fail(
                f"{case_field}.ticks",
                f"must contain between 1 and {MAX_TICKS_PER_CASE} ticks",
            )
        total_ticks += len(ticks)
        previous_offset = -1
        for tick_index, raw_tick in enumerate(ticks):
            tick_field = f"{case_field}.ticks[{tick_index}]"
            tick = _exact_keys(
                raw_tick,
                {"offsetMilliseconds", "bid", "ask", "bidSize", "askSize"},
                tick_field,
            )
            offset = _integer(
                tick["offsetMilliseconds"],
                f"{tick_field}.offsetMilliseconds",
                0,
                MAX_OFFSET_MILLISECONDS,
            )
            if offset <= previous_offset:
                _fail(
                    f"{tick_field}.offsetMilliseconds",
                    "must be strictly greater than the preceding tick offset",
                )
            previous_offset = offset
            bid = _number(tick["bid"], f"{tick_field}.bid")
            ask = _number(tick["ask"], f"{tick_field}.ask")
            if bid <= 0 or bid > MAX_PRICE or ask < bid or ask > MAX_PRICE:
                _fail(f"{tick_field}.bid", "bid/ask are outside supported bounds")
            _integer(tick["bidSize"], f"{tick_field}.bidSize", 0, MAX_QUOTE_SIZE)
            _integer(tick["askSize"], f"{tick_field}.askSize", 0, MAX_QUOTE_SIZE)
    if total_ticks > MAX_TOTAL_TICKS:
        _fail(
            "verification request.cases",
            f"must not exceed {MAX_TOTAL_TICKS} aggregate ticks",
        )
    return request


def _validate_expectations(
    raw: bytes, request: Mapping[str, Any], request_sha256: str
) -> dict[str, Any]:
    expectations = _exact_keys(
        _parse_json_object(raw, "verification expectations"),
        {"schemaVersion", "requestSha256", "cases"},
        "verification expectations",
    )
    if expectations["schemaVersion"] != EXPECTATIONS_SCHEMA_VERSION:
        _fail(
            "verification expectations.schemaVersion",
            f"must be {EXPECTATIONS_SCHEMA_VERSION!r}",
        )
    bound_hash = _sha256(
        expectations["requestSha256"],
        "verification expectations.requestSha256",
    )
    if bound_hash != request_sha256:
        _fail(
            "verification expectations.requestSha256",
            "does not match the exact verification request bytes",
        )
    values = expectations["cases"]
    if not isinstance(values, list) or len(values) != len(request["cases"]):
        _fail(
            "verification expectations.cases",
            "must exactly match the request case count",
        )
    for index, value in enumerate(values):
        field = f"verification expectations.cases[{index}]"
        case = _exact_keys(value, {"caseId", "traceSha256"}, field)
        case_id = _identifier(case["caseId"], f"{field}.caseId")
        expected_case_id = request["cases"][index]["caseId"]
        if case_id != expected_case_id:
            _fail(f"{field}.caseId", "does not match request order and identity")
        _sha256(case["traceSha256"], f"{field}.traceSha256")
    return expectations


def prepare_csharp_strategy_verification_inputs(
    *,
    request_id: str,
    source_text: str,
    contract: Mapping[str, Any],
    cases: Sequence[Mapping[str, Any]],
) -> tuple[bytes, bytes, bytes]:
    """Build the exact source-bound request and host-only expectations snapshots."""

    _identifier(request_id, "verification request.requestId")
    if not isinstance(source_text, str):
        _fail("strategy source", "must be a string")
    try:
        source_raw = source_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValidationError(
            f"strategy source: contains an unpaired surrogate at character {error.start}"
        ) from error
    if len(source_raw) > MAX_SOURCE_BYTES:
        _fail("strategy source", f"exceeds the {MAX_SOURCE_BYTES}-byte limit")
    source_sha256 = _validate_source(source_raw)

    request_cases: list[dict[str, Any]] = []
    expectation_cases: list[dict[str, Any]] = []
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes, bytearray)):
        _fail("verification cases", "must be an ordered sequence")
    for index, raw_case in enumerate(cases):
        field = f"verification cases[{index}]"
        case = _exact_keys(
            raw_case,
            {"caseId", "startUtc", "ticks", "expectedTraceSha256"},
            field,
        )
        request_cases.append(
            {
                "caseId": case["caseId"],
                "startUtc": case["startUtc"],
                "ticks": case["ticks"],
            }
        )
        expectation_cases.append(
            {
                "caseId": case["caseId"],
                "traceSha256": _sha256(
                    case["expectedTraceSha256"], f"{field}.expectedTraceSha256"
                ),
            }
        )

    request_document = {
        "schemaVersion": REQUEST_SCHEMA_VERSION,
        "profile": SOURCE_PROFILE,
        "requestId": request_id,
        "sourceSha256": source_sha256,
        "contract": dict(contract),
        "cases": request_cases,
    }
    request_raw = canonical_json_bytes(request_document)
    if len(request_raw) > MAX_REQUEST_BYTES:
        _fail("verification request", f"exceeds the {MAX_REQUEST_BYTES}-byte limit")
    request = _validate_request(request_raw)
    request_sha256 = hashlib.sha256(request_raw).hexdigest()

    expectations_document = {
        "schemaVersion": EXPECTATIONS_SCHEMA_VERSION,
        "requestSha256": request_sha256,
        "cases": expectation_cases,
    }
    expectations_raw = canonical_json_bytes(expectations_document)
    if len(expectations_raw) > MAX_EXPECTATIONS_BYTES:
        _fail(
            "verification expectations",
            f"exceeds the {MAX_EXPECTATIONS_BYTES}-byte limit",
        )
    _validate_expectations(expectations_raw, request, request_sha256)
    return request_raw, source_raw, expectations_raw


def _validate_image(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or not _IMAGE_RE.fullmatch(value):
        _fail(
            "verifier image",
            "must be an immutable repository@sha256:<64 lowercase hex> reference",
        )
    repository, digest = value.rsplit("@", 1)
    if (
        ":" in repository.rsplit("/", 1)[-1]
        or "//" in repository
        or any(part in {"", ".", ".."} for part in repository.split("/"))
    ):
        _fail(
            "verifier image",
            "must not contain a mutable tag or malformed repository path",
        )
    return value, digest


def _validate_entrypoint(value: Any) -> str:
    if not isinstance(value, str) or not _ENTRYPOINT_RE.fullmatch(value):
        _fail("verifier entrypoint", "must be one fixed absolute container path")
    if any(part in {".", ".."} for part in value.split("/")):
        _fail("verifier entrypoint", "must not contain traversal segments")
    return value


def _docker_create_args(
    docker_client: str, image: str, entrypoint: str, container_name: str
) -> tuple[str, ...]:
    return (
        docker_client,
        "create",
        f"--name={container_name}",
        "--pull=never",
        f"--platform={VERIFIER_PLATFORM}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--security-opt=seccomp=builtin",
        "--user=65532:65532",
        "--cpus=1",
        "--memory=768m",
        "--memory-swap=768m",
        "--pids-limit=64",
        f"--ulimit=nofile={NOFILE_LIMIT}:{NOFILE_LIMIT}",
        f"--tmpfs=/tmp:{TMPFS['/tmp']['option']}",
        f"--tmpfs=/work:{TMPFS['/work']['option']}",
        f"--entrypoint={entrypoint}",
        image,
        "idle",
        "--work",
        CONTAINER_WORK_PATH,
    )


def _docker_image_inspect_args(docker_client: str, image: str) -> tuple[str, ...]:
    return (docker_client, "image", "inspect", image)


def _validate_image_inspect(
    document: Mapping[str, Any], *, image: str, expected_image_id: str
) -> None:
    failures: list[str] = []
    if document.get("Id") != expected_image_id:
        failures.append("image ID")
    if document.get("Os") != "linux":
        failures.append("image OS")
    if document.get("Architecture") != "amd64":
        failures.append("image architecture")
    repo_digests = document.get("RepoDigests")
    if (
        not isinstance(repo_digests, list)
        or not 1 <= len(repo_digests) <= 64
        or len(set(repo_digests)) != len(repo_digests)
        or any(
            not isinstance(value, str) or not _IMAGE_RE.fullmatch(value)
            for value in repo_digests
        )
        or image not in repo_digests
    ):
        failures.append("repository digest")
    if failures:
        raise InfrastructureError(
            "Docker image inspection did not match signed authority: "
            + ", ".join(failures)
        )


def _stage_frame(request_raw: bytes, source_raw: bytes) -> bytes:
    if not 1 <= len(request_raw) <= MAX_REQUEST_BYTES:
        raise InfrastructureError("staged request is outside the ingress byte bound")
    if not 1 <= len(source_raw) <= MAX_SOURCE_BYTES:
        raise InfrastructureError("staged source is outside the ingress byte bound")
    return b"".join(
        (
            STAGE_FRAME_MAGIC,
            len(request_raw).to_bytes(4, "big", signed=False),
            len(source_raw).to_bytes(4, "big", signed=False),
            request_raw,
            source_raw,
        )
    )


def _default_process_runner(
    args: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    stdin_bytes: bytes | None = None,
    environment: Mapping[str, str],
) -> ProcessResult:
    if not 0 < max_output_bytes <= MAX_WORKER_RESULT_BYTES:
        raise InfrastructureError("Docker output bound is invalid")
    if stdin_bytes is not None and (
        not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STAGE_FRAME_BYTES
    ):
        raise InfrastructureError("Docker input exceeded its byte limit")
    if not isinstance(environment, Mapping) or any(
        not isinstance(name, str)
        or not name
        or not isinstance(value, str)
        or "\x00" in name
        or "\x00" in value
        for name, value in environment.items()
    ):
        raise InfrastructureError("Docker process environment is invalid")
    try:
        process = subprocess.Popen(
            list(args),
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            env=dict(environment),
        )
    except OSError as error:
        raise InfrastructureError("could not launch the Docker client") from error

    stdout = bytearray()
    stderr = bytearray()
    total = 0
    lock = threading.Lock()
    exceeded = threading.Event()
    input_errors: list[OSError] = []

    def read_stream(stream: Any, destination: bytearray) -> None:
        nonlocal total
        try:
            while block := stream.read(16 * 1024):
                with lock:
                    remaining = max_output_bytes - total
                    if remaining > 0:
                        destination.extend(block[:remaining])
                    total += len(block)
                    if total > max_output_bytes:
                        exceeded.set()
                        return
        finally:
            stream.close()

    def write_stdin(stream: Any, raw: bytes) -> None:
        try:
            remaining = memoryview(raw)
            while remaining:
                written = stream.write(remaining)
                if written is None or written <= 0:
                    raise OSError("Docker input pipe stopped accepting bytes")
                remaining = remaining[written:]
            stream.flush()
        except BrokenPipeError:
            pass
        except OSError as error:
            input_errors.append(error)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    if process.stdout is None or process.stderr is None:
        process.kill()
        raise InfrastructureError("Docker output pipes were unavailable")
    threads = (
        threading.Thread(
            target=read_stream, args=(process.stdout, stdout), daemon=True
        ),
        threading.Thread(
            target=read_stream, args=(process.stderr, stderr), daemon=True
        ),
    )
    for thread in threads:
        thread.start()
    input_thread: threading.Thread | None = None
    if stdin_bytes is not None:
        if process.stdin is None:
            process.kill()
            raise InfrastructureError("Docker input pipe was unavailable")
        input_thread = threading.Thread(
            target=write_stdin,
            args=(process.stdin, stdin_bytes),
            daemon=True,
        )
        input_thread.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    while process.poll() is None:
        if exceeded.is_set():
            process.kill()
            break
        if time.monotonic() >= deadline:
            timed_out = True
            process.kill()
            break
        time.sleep(0.01)
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    for thread in threads:
        thread.join(timeout=1.0)
    if input_thread is not None:
        input_thread.join(timeout=1.0)
    if timed_out:
        raise _ProcessTimeoutError("process exceeded its wall-clock deadline")
    if exceeded.is_set():
        raise _ProcessOutputLimitError("process output exceeded its byte limit")
    if input_thread is not None and input_thread.is_alive():
        raise InfrastructureError("Docker input pipe did not terminate")
    if input_errors:
        raise InfrastructureError(
            "could not write bounded Docker input"
        ) from input_errors[0]
    return ProcessResult(process.returncode, bytes(stdout), bytes(stderr))


def _normalize_process_result(
    value: Any, field: str, max_output_bytes: int
) -> ProcessResult:
    try:
        returncode = value.returncode
        stdout = value.stdout
        stderr = value.stderr
    except AttributeError as error:
        raise InfrastructureError(
            f"{field} runner returned an invalid result"
        ) from error
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", errors="replace")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", errors="replace")
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
    ):
        raise InfrastructureError(f"{field} runner returned invalid process fields")
    if len(stdout) + len(stderr) > max_output_bytes:
        raise InfrastructureError(f"{field} exceeded the Docker output byte limit")
    return ProcessResult(returncode, stdout, stderr)


def _invoke(
    runner: ProcessRunner,
    session: _DockerRuntimeSession,
    args: Sequence[str],
    field: str,
    *,
    deadline: float | None,
    timeout_seconds: float | None = None,
    require_success: bool = True,
    stdin_bytes: bytes | None = None,
    max_output_bytes: int = MAX_DOCKER_OUTPUT_BYTES,
) -> ProcessResult:
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or not 0 < max_output_bytes <= MAX_WORKER_RESULT_BYTES
    ):
        raise AssertionError("a valid process output bound is required")
    if stdin_bytes is not None and (
        not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > MAX_STAGE_FRAME_BYTES
    ):
        raise InfrastructureError(f"{field} input exceeded its byte limit")
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InfrastructureError(
                "verification exceeded the 30-second wall-clock limit"
            )
        effective_timeout = remaining
    elif timeout_seconds is not None:
        effective_timeout = timeout_seconds
    else:
        raise AssertionError("a process timeout is required")
    try:
        _require_docker_runtime_session(session)
        raw = runner(
            tuple(args),
            timeout_seconds=effective_timeout,
            max_output_bytes=max_output_bytes,
            stdin_bytes=stdin_bytes,
            environment=dict(session.environment),
        )
    except (_ProcessTimeoutError, subprocess.TimeoutExpired, TimeoutError) as error:
        raise InfrastructureError(f"{field} timed out") from error
    except _ProcessOutputLimitError as error:
        raise InfrastructureError(f"{field} exceeded its output byte limit") from error
    except InfrastructureError:
        raise
    except Exception as error:
        raise InfrastructureError(f"{field} process runner failed") from error
    _require_docker_runtime_session(session)
    result = _normalize_process_result(raw, field, max_output_bytes)
    if require_success and result.returncode != 0:
        evidence = hashlib.sha256(result.stderr).hexdigest()[:16]
        raise InfrastructureError(
            f"{field} failed with exit code {result.returncode} "
            f"(stderr evidence {evidence})"
        )
    return result


def _inspect_json(raw: bytes) -> dict[str, Any]:
    value = _parse_json(raw, "Docker inspect output")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise InfrastructureError("Docker inspect returned an unexpected document")
    return value[0]


def _empty(value: Any) -> bool:
    return value is None or value == [] or value == {}


def _tmpfs_option_map(value: Any, field: str) -> dict[str, str | None]:
    if not isinstance(value, str):
        raise InfrastructureError(f"{field} was not a string")
    parsed: dict[str, str | None] = {}
    for item in value.split(","):
        key, separator, option_value = item.partition("=")
        if not key or key in parsed:
            raise InfrastructureError(f"{field} contained duplicate or blank options")
        parsed[key] = option_value if separator else None
    return parsed


def _tmpfs_size_matches(value: str | None, expected: int) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    if lowered.isdigit():
        return int(lowered) == expected
    multipliers = {"k": 1024, "m": 1024**2, "g": 1024**3}
    if len(lowered) >= 2 and lowered[-1] in multipliers and lowered[:-1].isdigit():
        return int(lowered[:-1]) * multipliers[lowered[-1]] == expected
    return False


def _validate_inspect(
    document: Mapping[str, Any],
    *,
    container_id: str,
    image: str,
    expected_image_id: str,
    entrypoint: str,
    container_name: str,
) -> str:
    try:
        config = document["Config"]
        host = document["HostConfig"]
        state = document["State"]
    except KeyError as error:
        raise InfrastructureError(
            "Docker inspect omitted required policy fields"
        ) from error
    if (
        not isinstance(config, dict)
        or not isinstance(host, dict)
        or not isinstance(state, dict)
    ):
        raise InfrastructureError("Docker inspect policy fields had invalid shapes")

    failures: list[str] = []
    if document.get("Id") != container_id:
        failures.append("container identity")
    if document.get("Name") != f"/{container_name}":
        failures.append("container name")
    image_id = document.get("Image")
    if (
        not isinstance(image_id, str)
        or not _IMAGE_ID_RE.fullmatch(image_id)
        or image_id != expected_image_id
    ):
        failures.append("image identity")
    if document.get("Platform") != "linux":
        failures.append("container platform")
    if config.get("Image") != image:
        failures.append("pinned image reference")
    if config.get("Entrypoint") != [entrypoint]:
        failures.append("fixed entrypoint")
    if config.get("Cmd") != ["idle", "--work", CONTAINER_WORK_PATH]:
        failures.append("fixed idle command")
    if config.get("User") != "65532:65532":
        failures.append("uid/gid")
    if config.get("Env") != CONTAINER_ENVIRONMENT:
        failures.append("environment")
    if not _empty(config.get("Volumes")):
        failures.append("image volumes")
    if state.get("Running") is not False:
        failures.append("pre-start state")
    if host.get("NetworkMode") != "none":
        failures.append("network")
    if host.get("ReadonlyRootfs") is not True:
        failures.append("read-only root")
    if host.get("Privileged") is not False:
        failures.append("privileged mode")
    if host.get("CapDrop") != ["ALL"] or not _empty(host.get("CapAdd")):
        failures.append("capabilities")
    security = host.get("SecurityOpt")
    if security not in (
        ["no-new-privileges", "seccomp=builtin"],
        ["no-new-privileges:true", "seccomp=builtin"],
    ):
        failures.append("security policy")
    if host.get("NanoCpus") != 1_000_000_000:
        failures.append("CPU limit")
    if host.get("Memory") != MEMORY_BYTES or host.get("MemorySwap") != MEMORY_BYTES:
        failures.append("memory limit")
    if host.get("PidsLimit") != 64:
        failures.append("PID limit")
    if host.get("Ulimits") != [
        {"Name": "nofile", "Hard": NOFILE_LIMIT, "Soft": NOFILE_LIMIT}
    ]:
        failures.append("file-descriptor limit")
    for key in (
        "Binds",
        "Mounts",
        "VolumesFrom",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "GroupAdd",
        "Links",
        "ExtraHosts",
    ):
        if not _empty(host.get(key)):
            failures.append(key)
    if not _empty(document.get("Mounts")):
        failures.append("persistent mounts")

    actual_tmpfs = host.get("Tmpfs")
    if not isinstance(actual_tmpfs, dict) or set(actual_tmpfs) != set(TMPFS):
        failures.append("tmpfs paths")
    else:
        for path, expected in TMPFS.items():
            options = _tmpfs_option_map(actual_tmpfs[path], f"tmpfs {path}")
            if set(options) != {
                "rw",
                "noexec",
                "nosuid",
                "nodev",
                "size",
                "uid",
                "gid",
                "mode",
            }:
                failures.append(f"tmpfs {path} options")
                continue
            if (
                options["rw"] is not None
                or options["noexec"] is not None
                or options["nosuid"] is not None
                or options["nodev"] is not None
                or options["uid"] != "65532"
                or options["gid"] != "65532"
                or options["mode"] not in {"0700", "700"}
                or not _tmpfs_size_matches(options["size"], expected["sizeBytes"])
            ):
                failures.append(f"tmpfs {path} policy")
    if failures:
        raise InfrastructureError(
            "created container failed sandbox inspection: " + ", ".join(failures)
        )
    assert isinstance(image_id, str)
    return image_id


def _artifact(value: Any, field: str) -> dict[str, Any]:
    artifact = _exact_keys(value, {"name", "version", "sha256"}, field)
    _text(artifact["name"], f"{field}.name", 1, 256)
    _text(artifact["version"], f"{field}.version", 1, 128)
    _sha256(artifact["sha256"], f"{field}.sha256")
    return artifact


def _diagnostics(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 128:
        _fail(field, "must be an array containing no more than 128 diagnostics")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_field = f"{field}[{index}]"
        diagnostic = _exact_keys(
            raw,
            {"stage", "code", "severity", "message", "line", "column"},
            item_field,
        )
        _text(diagnostic["stage"], f"{item_field}.stage", 1, 64)
        _text(diagnostic["code"], f"{item_field}.code", 1, 64)
        if diagnostic["severity"] not in {"info", "warning", "error"}:
            _fail(f"{item_field}.severity", "is unsupported")
        _text(diagnostic["message"], f"{item_field}.message", 1, 32_768)
        for name in ("line", "column"):
            if diagnostic[name] is not None:
                _integer(diagnostic[name], f"{item_field}.{name}", 1, 10_000_000)
        result.append(diagnostic)

    def ordering(item: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            item["stage"],
            item["code"],
            item["severity"],
            -1 if item["line"] is None else item["line"],
            -1 if item["column"] is None else item["column"],
            item["message"],
        )

    ordered = sorted(result, key=ordering)
    if result != ordered:
        _fail(field, "must use the worker's deterministic diagnostic order")
    if len({ordering(item) for item in result}) != len(result):
        _fail(field, "must not contain duplicate diagnostics")
    return result


def _runtime_error(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    error = _exact_keys(value, {"code", "type", "message"}, field)
    _text(error["code"], f"{field}.code", 1, 64)
    _text(error["type"], f"{field}.type", 1, 256)
    _text(error["message"], f"{field}.message", 1, 512)
    return error


def _trace_contract(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    contract = _exact_keys(
        value,
        {"symbol", "secType", "exchange", "currency", "primaryExchange"},
        field,
    )
    for name, maximum in (
        ("symbol", 64),
        ("secType", 32),
        ("exchange", 64),
        ("currency", 16),
        ("primaryExchange", 64),
    ):
        _text(contract[name], f"{field}.{name}", 1, maximum)
    return contract


def _trace(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_TRACE_ENTRIES:
        _fail(field, f"must contain no more than {MAX_TRACE_ENTRIES} entries")
    result: list[dict[str, Any]] = []
    previous_sequence = -1
    for index, raw in enumerate(value):
        item_field = f"{field}[{index}]"
        entry = _exact_keys(
            raw,
            {
                "sequence",
                "kind",
                "atUtc",
                "clientOrderId",
                "contract",
                "side",
                "type",
                "quantity",
                "limitPrice",
                "stopPrice",
                "timeInForce",
            },
            item_field,
        )
        sequence = _integer(
            entry["sequence"],
            f"{item_field}.sequence",
            1,
            MAX_TRACE_ENTRIES,
        )
        if sequence != index + 1 or sequence <= previous_sequence:
            _fail(f"{item_field}.sequence", "must be consecutive from one")
        previous_sequence = sequence
        kind = _text(entry["kind"], f"{item_field}.kind", 1, 64)
        if kind not in {"place", "cancel"}:
            _fail(f"{item_field}.kind", "must be 'place' or 'cancel'")
        _text(entry["atUtc"], f"{item_field}.atUtc", 20, 40)
        client_order_id = _text(
            entry["clientOrderId"], f"{item_field}.clientOrderId", 1, 256
        )
        if not client_order_id.strip():
            _fail(f"{item_field}.clientOrderId", "must not be blank")
        contract = _trace_contract(entry["contract"], f"{item_field}.contract")
        for name in ("side", "type", "timeInForce"):
            if entry[name] is not None:
                _text(entry[name], f"{item_field}.{name}", 1, 64)
        if entry["quantity"] is not None:
            _integer(
                entry["quantity"],
                f"{item_field}.quantity",
                1,
                MAX_QUOTE_SIZE,
            )
        for name in ("limitPrice", "stopPrice"):
            if entry[name] is not None:
                number = _number(entry[name], f"{item_field}.{name}")
                if abs(number) > MAX_PRICE:
                    _fail(f"{item_field}.{name}", "is outside supported bounds")
        if kind == "place":
            if (
                contract is None
                or entry["side"] is None
                or entry["type"] is None
                or entry["quantity"] is None
                or entry["timeInForce"] is None
            ):
                _fail(item_field, "place trace evidence is incomplete")
        elif any(
            entry[name] is not None
            for name in (
                "contract",
                "side",
                "type",
                "quantity",
                "limitPrice",
                "stopPrice",
                "timeInForce",
            )
        ):
            _fail(item_field, "cancel trace evidence contains place-only fields")
        result.append(entry)
    return result


def csharp_strategy_reference_trace_sha256(
    trace: Any,
    error: Any,
) -> str:
    """Hash one validated replay without trusting a worker-supplied trace hash."""

    validated_trace = _trace(trace, "reference trace")
    validated_error = _runtime_error(error, "reference trace error")

    def decimal_text(value: Any) -> str | None:
        if value is None:
            return None
        number = Decimal(value)
        if number == 0:
            return "0"
        return format(number.normalize(), "f")

    normalized_trace = []
    for entry in validated_trace:
        normalized_trace.append(
            {
                "sequence": entry["sequence"],
                "kind": entry["kind"],
                "atUtc": entry["atUtc"],
                "clientOrderId": entry["clientOrderId"],
                "contract": entry["contract"],
                "side": entry["side"],
                "type": entry["type"],
                "quantity": entry["quantity"],
                "limitPrice": decimal_text(entry["limitPrice"]),
                "stopPrice": decimal_text(entry["stopPrice"]),
                "timeInForce": entry["timeInForce"],
            }
        )
    payload = {
        "schemaVersion": "daxalgo.verifier.headless-strategy-reference-trace/v1",
        "trace": normalized_trace,
        "error": validated_error,
    }
    domain = b"daxalgo-verifier-headless-strategy-reference-trace/v1\x00"
    return hashlib.sha256(domain + canonical_json_bytes(payload)).hexdigest()


def _validate_worker_result(
    raw: bytes,
    *,
    request: Mapping[str, Any],
    request_sha256: str,
    source_sha256: str,
) -> dict[str, Any]:
    worker = _exact_keys(
        _parse_json_object(raw, "worker result"),
        {
            "schemaVersion",
            "request",
            "source",
            "toolchain",
            "compile",
            "policy",
            "cases",
            "completed",
            "accepted",
        },
        "worker result",
    )
    if worker["schemaVersion"] != WORKER_RESULT_SCHEMA_VERSION:
        _fail(
            "worker result.schemaVersion",
            f"must be {WORKER_RESULT_SCHEMA_VERSION!r}",
        )
    request_evidence = _exact_keys(
        worker["request"],
        {"requestId", "sha256", "valid", "diagnostics", "diagnosticsTruncated"},
        "worker result.request",
    )
    _identifier(request_evidence["requestId"], "worker result.request.requestId")
    _sha256(request_evidence["sha256"], "worker result.request.sha256")
    _boolean(request_evidence["valid"], "worker result.request.valid")
    request_diagnostics = _diagnostics(
        request_evidence["diagnostics"], "worker result.request.diagnostics"
    )
    _boolean(
        request_evidence["diagnosticsTruncated"],
        "worker result.request.diagnosticsTruncated",
    )
    if (
        request_evidence["requestId"] != request["requestId"]
        or request_evidence["sha256"] != request_sha256
        or request_evidence["valid"] is not True
        or request_diagnostics
        or request_evidence["diagnosticsTruncated"] is not False
    ):
        raise InfrastructureError(
            "worker request evidence did not match the host snapshot"
        )

    source = _exact_keys(
        worker["source"],
        {"sha256", "declaredSha256", "encodingValid", "hashMatched"},
        "worker result.source",
    )
    _sha256(source["sha256"], "worker result.source.sha256")
    _sha256(source["declaredSha256"], "worker result.source.declaredSha256")
    _boolean(source["encodingValid"], "worker result.source.encodingValid")
    _boolean(source["hashMatched"], "worker result.source.hashMatched")
    if (
        source["sha256"] != source_sha256
        or source["declaredSha256"] != request["sourceSha256"]
        or source["encodingValid"] is not True
        or source["hashMatched"] is not True
    ):
        raise InfrastructureError(
            "worker source evidence did not match the host snapshot"
        )

    toolchain = _exact_keys(
        worker["toolchain"],
        {
            "version",
            "worker",
            "runtime",
            "core",
            "sdk",
            "roslyn",
            "compilerClosure",
            "compilerClosureSha256",
        },
        "worker result.toolchain",
    )
    if toolchain["version"] != "1.0.0":
        _fail("worker result.toolchain.version", "must be '1.0.0'")
    for name in ("worker", "runtime", "core", "sdk", "roslyn"):
        _artifact(toolchain[name], f"worker result.toolchain.{name}")
    closure = toolchain["compilerClosure"]
    if not isinstance(closure, list) or not 1 <= len(closure) <= 64:
        _fail(
            "worker result.toolchain.compilerClosure",
            "must contain between 1 and 64 artifacts",
        )
    closure_names: set[str] = set()
    for index, value in enumerate(closure):
        artifact = _artifact(value, f"worker result.toolchain.compilerClosure[{index}]")
        if artifact["name"] in closure_names:
            _fail(
                f"worker result.toolchain.compilerClosure[{index}].name",
                "duplicates an earlier compiler artifact",
            )
        closure_names.add(artifact["name"])
    closure_sha256 = _sha256(
        toolchain["compilerClosureSha256"],
        "worker result.toolchain.compilerClosureSha256",
    )
    expected_closure_sha256 = hashlib.sha256(
        json.dumps(
            [
                {
                    "name": artifact["name"],
                    "version": artifact["version"],
                    "sha256": artifact["sha256"],
                }
                for artifact in closure
            ],
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if closure_sha256 != expected_closure_sha256:
        _fail(
            "worker result.toolchain.compilerClosureSha256",
            "does not match the ordered compiler closure evidence",
        )
    expected_order = sorted(
        closure, key=lambda artifact: (artifact["name"], artifact["version"])
    )
    if closure != expected_order:
        _fail(
            "worker result.toolchain.compilerClosure",
            "must use deterministic name/version order",
        )
    closure_identities = {
        (artifact["name"], artifact["version"], artifact["sha256"])
        for artifact in closure
    }
    for name in ("runtime", "core", "sdk"):
        identity = toolchain[name]
        if (
            identity["name"],
            identity["version"],
            identity["sha256"],
        ) not in closure_identities:
            _fail(
                f"worker result.toolchain.{name}",
                "is absent from the frozen compiler closure",
            )

    compile_evidence = _exact_keys(
        worker["compile"],
        {
            "attempted",
            "succeeded",
            "assemblySha256",
            "diagnostics",
            "diagnosticsTruncated",
        },
        "worker result.compile",
    )
    attempted = _boolean(
        compile_evidence["attempted"], "worker result.compile.attempted"
    )
    compiled = _boolean(
        compile_evidence["succeeded"], "worker result.compile.succeeded"
    )
    if compile_evidence["assemblySha256"] is not None:
        _sha256(
            compile_evidence["assemblySha256"],
            "worker result.compile.assemblySha256",
        )
    compile_diagnostics = _diagnostics(
        compile_evidence["diagnostics"], "worker result.compile.diagnostics"
    )
    compile_truncated = _boolean(
        compile_evidence["diagnosticsTruncated"],
        "worker result.compile.diagnosticsTruncated",
    )
    if compile_truncated and len(compile_diagnostics) != 128:
        _fail(
            "worker result.compile.diagnosticsTruncated",
            "requires a full 128-item bounded diagnostic list",
        )
    if compiled and (not attempted or compile_evidence["assemblySha256"] is None):
        _fail("worker result.compile", "successful compilation lacks assembly evidence")
    if not compiled and compile_evidence["assemblySha256"] is not None:
        _fail("worker result.compile", "failed compilation cannot identify an assembly")
    if not attempted and compiled:
        _fail(
            "worker result.compile", "cannot succeed when compilation was not attempted"
        )
    if not compiled and not compile_diagnostics:
        _fail(
            "worker result.compile.diagnostics",
            "must explain a candidate compile failure",
        )

    policy = _exact_keys(
        worker["policy"],
        {
            "attempted",
            "sourcePassed",
            "ilPassed",
            "diagnostics",
            "diagnosticsTruncated",
        },
        "worker result.policy",
    )
    policy_attempted = _boolean(policy["attempted"], "worker result.policy.attempted")
    source_passed = _boolean(
        policy["sourcePassed"], "worker result.policy.sourcePassed"
    )
    il_passed = _boolean(policy["ilPassed"], "worker result.policy.ilPassed")
    policy_diagnostics = _diagnostics(
        policy["diagnostics"], "worker result.policy.diagnostics"
    )
    policy_truncated = _boolean(
        policy["diagnosticsTruncated"],
        "worker result.policy.diagnosticsTruncated",
    )
    if policy_truncated and len(policy_diagnostics) != 128:
        _fail(
            "worker result.policy.diagnosticsTruncated",
            "requires a full 128-item bounded diagnostic list",
        )
    if not policy_attempted and (source_passed or il_passed):
        _fail(
            "worker result.policy", "cannot pass when policy analysis was not attempted"
        )
    if compiled and (not source_passed or not il_passed) and not policy_diagnostics:
        _fail(
            "worker result.policy.diagnostics",
            "must explain a candidate policy failure",
        )

    raw_cases = worker["cases"]
    if not isinstance(raw_cases, list) or len(raw_cases) > len(request["cases"]):
        _fail("worker result.cases", "contains an invalid case count")
    cases: list[dict[str, Any]] = []
    for index, raw_case in enumerate(raw_cases):
        field = f"worker result.cases[{index}]"
        case = _exact_keys(
            raw_case,
            {
                "caseId",
                "succeeded",
                "trace",
                "secondTrace",
                "firstTraceSha256",
                "secondTraceSha256",
                "deterministic",
                "firstError",
                "secondError",
            },
            field,
        )
        case_id = _identifier(case["caseId"], f"{field}.caseId")
        if case_id != request["cases"][index]["caseId"]:
            raise InfrastructureError(
                "worker case identity/order did not match the request"
            )
        succeeded = _boolean(case["succeeded"], f"{field}.succeeded")
        trace = _trace(case["trace"], f"{field}.trace")
        second_trace = _trace(case["secondTrace"], f"{field}.secondTrace")
        first_hash = _sha256(case["firstTraceSha256"], f"{field}.firstTraceSha256")
        second_hash = _sha256(case["secondTraceSha256"], f"{field}.secondTraceSha256")
        deterministic = _boolean(case["deterministic"], f"{field}.deterministic")
        first_error = _runtime_error(case["firstError"], f"{field}.firstError")
        second_error = _runtime_error(case["secondError"], f"{field}.secondError")
        first_reference_hash = csharp_strategy_reference_trace_sha256(
            trace,
            first_error,
        )
        second_reference_hash = csharp_strategy_reference_trace_sha256(
            second_trace,
            second_error,
        )
        case["_referenceTraceSha256"] = first_reference_hash
        if deterministic != (first_hash == second_hash):
            _fail(f"{field}.deterministic", "does not match the two trace identities")
        if deterministic != (first_reference_hash == second_reference_hash):
            _fail(
                f"{field}.deterministic",
                "does not match the host-derived identities of both returned replays",
            )
        if succeeded != (
            deterministic and first_error is None and second_error is None
        ):
            _fail(f"{field}.succeeded", "does not match runtime error evidence")
        cases.append(case)

    completed = _boolean(worker["completed"], "worker result.completed")
    accepted = _boolean(worker["accepted"], "worker result.accepted")
    if not completed:
        raise InfrastructureError("worker did not complete verification")
    expected_accepted = (
        attempted
        and compiled
        and policy_attempted
        and source_passed
        and il_passed
        and len(cases) == len(request["cases"])
        and all(case["succeeded"] and case["deterministic"] for case in cases)
    )
    if accepted != expected_accepted:
        raise InfrastructureError("worker accepted flag contradicted its evidence")
    return worker


def _evidence(check_id: str, passed: bool, detail: str) -> dict[str, Any]:
    if check_id not in CHECK_IDS:
        raise AssertionError("unknown verification check")
    text = f"{check_id}: {'pass' if passed else 'fail'}; {detail}"
    return {
        "checkId": check_id,
        "passed": passed,
        "evidence": text,
        "evidenceSha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _sandbox_policy(entrypoint: str) -> dict[str, Any]:
    return supported_sandbox_policy(entrypoint)


def csharp_strategy_verification_result_sha256(
    result: Mapping[str, Any],
) -> str:
    payload = dict(result)
    payload.pop("resultSha256", None)
    schema_version = payload.get("schemaVersion")
    domains = {
        RESULT_SCHEMA_VERSION_V1: (
            b"daxalgo-hyperion-csharp-strategy-verification-result/v1\x00"
        ),
        RESULT_SCHEMA_VERSION: (
            b"daxalgo-hyperion-csharp-strategy-verification-result/v2\x00"
        ),
    }
    domain = domains.get(schema_version)
    if domain is None:
        _fail("C# strategy verification result.schemaVersion", "is unsupported")
    return hashlib.sha256(domain + canonical_json_bytes(payload)).hexdigest()


def _write_no_clobber(path: Path, raw: bytes) -> None:
    destination = _reject_reparse_components(
        path, "verification output", allow_missing_suffix=True
    )
    parent = _reject_reparse_components(
        destination.parent, "verification output parent"
    )
    if not parent.is_dir():
        _fail("verification output parent", "must be an existing directory")
    if os.path.lexists(destination):
        _fail("verification output", f"already exists: {destination}")
    staged: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".staging", dir=parent
        )
        staged = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(staged, destination)
        except FileExistsError as error:
            raise ValidationError(
                f"verification output: already exists: {destination}"
            ) from error
        except OSError as error:
            raise ValidationError(
                f"verification output: atomic no-clobber install failed: {error}"
            ) from error
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass


def _write_snapshot(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(
        path,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
    )


def _container_absence_query_args(
    docker_client: str, container_name: str
) -> tuple[str, ...]:
    return (
        docker_client,
        "ps",
        "--all",
        "--no-trunc",
        f"--filter=name=^/{container_name}$",
        "--format={{.ID}}\t{{.Names}}",
    )


def _require_exact_container_name_absent(raw: bytes, container_name: str) -> None:
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise InfrastructureError(
            "Docker cleanup absence query returned non-ASCII output"
        ) from error
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not _CONTAINER_ID_RE.fullmatch(fields[0]):
            raise InfrastructureError(
                "Docker cleanup absence query returned an ambiguous document"
            )
        names = {name.removeprefix("/") for name in fields[1].split(",") if name}
        if not names or container_name not in names:
            raise InfrastructureError(
                "Docker cleanup absence query returned an ambiguous document"
            )
        raise InfrastructureError(
            "Docker cleanup left the exact verifier container name present"
        )


def _cleanup_container(
    runner: ProcessRunner,
    session: _DockerRuntimeSession,
    *,
    container_name: str,
    container_id: str | None,
) -> None:
    target = container_id if container_id is not None else container_name
    removal_failure: InfrastructureError | None = None
    try:
        cleanup = _invoke(
            runner,
            session,
            (session.client_command, "rm", "-f", target),
            "Docker cleanup",
            deadline=None,
            timeout_seconds=CLEANUP_SECONDS,
            require_success=False,
        )
        if cleanup.returncode != 0:
            evidence = hashlib.sha256(cleanup.stderr).hexdigest()[:16]
            removal_failure = InfrastructureError(
                "Docker cleanup failed with exit code "
                f"{cleanup.returncode} (stderr evidence {evidence})"
            )
    except InfrastructureError as error:
        removal_failure = error

    try:
        absence = _invoke(
            runner,
            session,
            _container_absence_query_args(session.client_command, container_name),
            "Docker cleanup absence query",
            deadline=None,
            timeout_seconds=CLEANUP_SECONDS,
        )
        if absence.stderr:
            raise InfrastructureError(
                "Docker cleanup absence query returned ambiguous diagnostics"
            )
        _require_exact_container_name_absent(absence.stdout, container_name)
    except InfrastructureError as error:
        if removal_failure is not None:
            error.add_note(str(removal_failure))
        raise

    # Once Docker returned a validated ID, a failed removal by that immutable identity
    # remains ambiguous even when the reusable name is no longer present.
    if container_id is not None and removal_failure is not None:
        raise removal_failure


def _remove_staging_directory(stage: Path) -> None:
    try:
        shutil.rmtree(stage)
    except FileNotFoundError:
        return
    except OSError as error:
        raise InfrastructureError(
            "could not remove the verifier staging directory"
        ) from error
    if os.path.lexists(stage):
        raise InfrastructureError("verifier staging directory remained after cleanup")


def _run_csharp_strategy_verification(
    *,
    request_path: str | os.PathLike[str],
    source_path: str | os.PathLike[str],
    expectations_path: str | os.PathLike[str],
    authority_path: str | os.PathLike[str],
    authority_trust: CSharpVerifierAuthorityTrust,
    output_path: str | os.PathLike[str],
    process_runner: ProcessRunner | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Run the signed-authority headless verifier and emit one immutable decision."""

    time_source = clock or (lambda: datetime.now(timezone.utc))
    authority = validate_csharp_verifier_authority(
        authority_path,
        trust=authority_trust,
        now=time_source(),
    )
    verifier_binding = authority.payload["verifier"]
    pinned_image, image_digest = _validate_image(verifier_binding["image"]["reference"])
    if image_digest != verifier_binding["image"]["digest"]:
        _fail("C# verifier authority image digest", "does not match its reference")
    expected_image_id = verifier_binding["image"]["imageId"]
    fixed_entrypoint = _validate_entrypoint(verifier_binding["entrypoint"])
    sandbox = _sandbox_policy(fixed_entrypoint)
    sandbox_sha256 = hashlib.sha256(canonical_json_bytes(sandbox)).hexdigest()
    signed_sandbox = verifier_binding["sandboxPolicy"]
    if (
        signed_sandbox["profile"] != SANDBOX_POLICY_PROFILE
        or signed_sandbox["sha256"] != sandbox_sha256
        or signed_sandbox["policy"] != sandbox
    ):
        _fail(
            "C# verifier authority sandbox policy",
            "does not match the hardcoded controller policy",
        )
    expected_toolchain = verifier_binding["toolchain"]
    expected_toolchain_sha256 = csharp_verifier_toolchain_sha256(expected_toolchain)
    if expected_toolchain_sha256 != verifier_binding["toolchainSha256"]:
        _fail(
            "C# verifier authority toolchain",
            "does not match its signed identity",
        )

    _, request_raw = _read_input_snapshot(
        request_path, "verification request", MAX_REQUEST_BYTES
    )
    _, source_raw = _read_input_snapshot(
        source_path, "strategy source", MAX_SOURCE_BYTES
    )
    _, expectations_raw = _read_input_snapshot(
        expectations_path, "verification expectations", MAX_EXPECTATIONS_BYTES
    )
    request = _validate_request(request_raw)
    request_sha256 = hashlib.sha256(request_raw).hexdigest()
    source_sha256 = _validate_source(source_raw)
    if source_sha256 != request["sourceSha256"]:
        _fail(
            "verification request.sourceSha256",
            "does not match the exact strategy source bytes",
        )
    expectations = _validate_expectations(expectations_raw, request, request_sha256)
    expectations_sha256 = hashlib.sha256(expectations_raw).hexdigest()

    destination = _reject_reparse_components(
        Path(output_path), "verification output", allow_missing_suffix=True
    )
    parent = _reject_reparse_components(
        destination.parent, "verification output parent"
    )
    if not parent.is_dir():
        _fail("verification output parent", "must be an existing directory")
    if os.path.lexists(destination):
        _fail("verification output", f"already exists: {destination}")

    runner = process_runner or _default_process_runner
    container_name = f"daxalgo-vqverify-{secrets.token_hex(12)}"
    create_attempted = False
    container_id: str | None = None
    result: dict[str, Any] | None = None
    encoded_result: bytes | None = None
    failure: Exception | None = None
    cleanup_failure: InfrastructureError | None = None
    runtime_integrity_failure: InfrastructureError | None = None
    staging_cleanup_failure: InfrastructureError | None = None
    try:
        stage = Path(tempfile.mkdtemp(prefix=".csharp-verifier-", dir=parent))
    except OSError as error:
        raise InfrastructureError(
            "could not create the verifier staging directory"
        ) from error
    try:
        session = _prepare_docker_runtime_session(
            verifier_binding["dockerRuntime"], stage
        )
    except Exception:
        _remove_staging_directory(stage)
        raise
    deadline = time.monotonic() + WALL_CLOCK_SECONDS
    try:
        image_inspection = _invoke(
            runner,
            session,
            _docker_image_inspect_args(session.client_command, pinned_image),
            "Docker image inspect",
            deadline=deadline,
        )
        if image_inspection.stderr:
            raise InfrastructureError("Docker image inspect produced stderr")
        try:
            _validate_image_inspect(
                _inspect_json(image_inspection.stdout),
                image=pinned_image,
                expected_image_id=expected_image_id,
            )
        except ValidationError as error:
            raise InfrastructureError(
                "Docker image inspect returned invalid JSON"
            ) from error

        staged_request = stage / "request.json"
        staged_source = stage / "source.cs"
        try:
            _write_snapshot(staged_request, request_raw)
            _write_snapshot(staged_source, source_raw)
            staged_request_raw = _read_input_snapshot(
                staged_request, "staged verification request", MAX_REQUEST_BYTES
            )[1]
            if staged_request_raw != request_raw:
                raise InfrastructureError("staged request snapshot changed")
            staged_source_raw = _read_input_snapshot(
                staged_source, "staged strategy source", MAX_SOURCE_BYTES
            )[1]
            if staged_source_raw != source_raw:
                raise InfrastructureError("staged source snapshot changed")
            ingress_frame = _stage_frame(staged_request_raw, staged_source_raw)
        except (OSError, ValidationError) as error:
            raise InfrastructureError(
                "could not establish immutable input snapshots"
            ) from error

        create_attempted = True
        created = _invoke(
            runner,
            session,
            _docker_create_args(
                session.client_command, pinned_image, fixed_entrypoint, container_name
            ),
            "Docker create",
            deadline=deadline,
        )
        try:
            container_text = created.stdout.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise InfrastructureError(
                "Docker create returned a non-ASCII container identity"
            ) from error
        if not _CONTAINER_ID_RE.fullmatch(container_text):
            raise InfrastructureError("Docker create returned an invalid container ID")
        container_id = container_text

        inspected = _invoke(
            runner,
            session,
            (session.client_command, "inspect", container_id),
            "Docker inspect",
            deadline=deadline,
        )
        try:
            image_id = _validate_inspect(
                _inspect_json(inspected.stdout),
                container_id=container_id,
                image=pinned_image,
                expected_image_id=expected_image_id,
                entrypoint=fixed_entrypoint,
                container_name=container_name,
            )
        except ValidationError as error:
            raise InfrastructureError("Docker inspect returned invalid JSON") from error
        _invoke(
            runner,
            session,
            (session.client_command, "start", container_id),
            "Docker start",
            deadline=deadline,
        )
        staged = _invoke(
            runner,
            session,
            (
                session.client_command,
                "exec",
                "--interactive",
                container_id,
                fixed_entrypoint,
                "stage",
                "--work",
                CONTAINER_WORK_PATH,
            ),
            "Docker verifier input staging",
            deadline=deadline,
            stdin_bytes=ingress_frame,
        )
        if staged.stdout or staged.stderr:
            raise InfrastructureError("Docker verifier input staging produced output")
        verified = _invoke(
            runner,
            session,
            (
                session.client_command,
                "exec",
                container_id,
                fixed_entrypoint,
                "verify-stdout",
                "--request",
                CONTAINER_REQUEST_PATH,
                "--source",
                CONTAINER_SOURCE_PATH,
            ),
            "Docker verifier execution",
            deadline=deadline,
            max_output_bytes=MAX_WORKER_RESULT_BYTES,
        )
        if verified.stderr:
            raise InfrastructureError("Docker verifier execution produced stderr")
        worker_raw = verified.stdout
        try:
            worker = _validate_worker_result(
                worker_raw,
                request=request,
                request_sha256=request_sha256,
                source_sha256=source_sha256,
            )
        except ValidationError as error:
            raise InfrastructureError(
                "worker result failed strict validation"
            ) from error
        if worker["toolchain"] != expected_toolchain:
            raise InfrastructureError(
                "worker toolchain did not match the signed verifier authority"
            )
        actual_toolchain_sha256 = csharp_verifier_toolchain_sha256(worker["toolchain"])
        if actual_toolchain_sha256 != expected_toolchain_sha256:
            raise InfrastructureError(
                "worker toolchain hash did not match the signed verifier authority"
            )

        compile_passed = worker["compile"]["succeeded"] is True
        analyzers_passed = (
            worker["policy"]["sourcePassed"] is True
            and worker["policy"]["ilPassed"] is True
        )
        case_results = worker["cases"]
        deterministic_passed = len(case_results) == len(request["cases"]) and all(
            case["succeeded"] and case["deterministic"] for case in case_results
        )
        reference_passed = len(case_results) == len(expectations["cases"]) and all(
            case["caseId"] == expected["caseId"]
            and case["_referenceTraceSha256"] == expected["traceSha256"]
            for case, expected in zip(case_results, expectations["cases"], strict=True)
        )
        checks = [
            _evidence(
                "source-binding",
                True,
                "worker request and source identities matched exact host snapshots",
            ),
            _evidence(
                "compile",
                compile_passed,
                "worker compilation succeeded"
                if compile_passed
                else "worker compilation rejected the candidate",
            ),
            _evidence(
                "analyzers",
                analyzers_passed,
                "source and IL policy analyzers passed"
                if analyzers_passed
                else "source or IL policy analyzer rejected the candidate",
            ),
            _evidence(
                "deterministic-execution",
                deterministic_passed,
                f"{len(case_results)} ordered case replay(s) completed deterministically"
                if deterministic_passed
                else "ordered case execution or deterministic replay failed",
            ),
            _evidence(
                "reference-cases",
                reference_passed,
                f"{len(expectations['cases'])} hidden reference case identity/identities matched"
                if reference_passed
                else "one or more hidden reference case identities did not match",
            ),
            _evidence(
                "sandbox-policy",
                True,
                "pre-start container inspection matched the pinned sandbox policy",
            ),
        ]
        result = {
            "schemaVersion": RESULT_SCHEMA_VERSION,
            "resultSha256": "0" * 64,
            "request": {
                "requestId": request["requestId"],
                "sha256": request_sha256,
            },
            "source": {"sha256": source_sha256},
            "expectations": {"sha256": expectations_sha256},
            "workerResult": {
                "sha256": hashlib.sha256(worker_raw).hexdigest(),
                "toolchainSha256": actual_toolchain_sha256,
            },
            "verifierAuthority": authority.as_dict(),
            "image": {
                "reference": pinned_image,
                "digest": image_digest,
                "imageId": image_id,
                "platform": VERIFIER_PLATFORM,
            },
            "sandboxPolicy": {
                "profile": SANDBOX_POLICY_PROFILE,
                "sha256": sandbox_sha256,
            },
            "checks": checks,
            "accepted": all(check["passed"] for check in checks),
        }
        result["resultSha256"] = csharp_strategy_verification_result_sha256(result)
        encoded_result = canonical_json_bytes(result) + b"\n"
        if len(encoded_result) > MAX_RESULT_BYTES:
            raise InfrastructureError("verification result exceeded its byte limit")
    except Exception as error:
        failure = error
    finally:
        if create_attempted:
            try:
                _cleanup_container(
                    runner,
                    session,
                    container_name=container_name,
                    container_id=container_id,
                )
            except InfrastructureError as error:
                cleanup_failure = error
        try:
            _require_docker_runtime_session(session)
            _require_signed_docker_client_unchanged(session)
        except InfrastructureError as error:
            runtime_integrity_failure = error
        try:
            _remove_staging_directory(stage)
        except InfrastructureError as error:
            staging_cleanup_failure = error

    if failure is not None:
        if cleanup_failure is not None:
            failure.add_note(str(cleanup_failure))
        if runtime_integrity_failure is not None:
            failure.add_note(str(runtime_integrity_failure))
        if staging_cleanup_failure is not None:
            failure.add_note(str(staging_cleanup_failure))
        raise failure
    if cleanup_failure is not None:
        if runtime_integrity_failure is not None:
            cleanup_failure.add_note(str(runtime_integrity_failure))
        if staging_cleanup_failure is not None:
            cleanup_failure.add_note(str(staging_cleanup_failure))
        raise cleanup_failure
    if runtime_integrity_failure is not None:
        if staging_cleanup_failure is not None:
            runtime_integrity_failure.add_note(str(staging_cleanup_failure))
        raise runtime_integrity_failure
    if staging_cleanup_failure is not None:
        raise staging_cleanup_failure
    if result is None or encoded_result is None:
        raise InfrastructureError("verification ended without a result")
    try:
        ensure_csharp_verifier_authority_active(authority, time_source())
    except ValidationError as error:
        raise InfrastructureError(
            "signed verifier authority expired before result publication"
        ) from error
    _write_no_clobber(destination, encoded_result)
    return result


def run_csharp_strategy_verification(
    *,
    request_path: str | os.PathLike[str],
    source_path: str | os.PathLike[str],
    expectations_path: str | os.PathLike[str],
    authority_path: str | os.PathLike[str],
    authority_trust: CSharpVerifierAuthorityTrust,
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Run the sanctioned live-Docker verifier with the live UTC authority clock."""

    return _run_csharp_strategy_verification(
        request_path=request_path,
        source_path=source_path,
        expectations_path=expectations_path,
        authority_path=authority_path,
        authority_trust=authority_trust,
        output_path=output_path,
        process_runner=None,
        clock=None,
    )


__all__ = [
    "EXPECTATIONS_SCHEMA_VERSION",
    "CSharpVerifierAuthorityTrust",
    "InfrastructureError",
    "ProcessResult",
    "REQUEST_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "SANDBOX_POLICY_PROFILE",
    "SOURCE_PROFILE",
    "WORKER_RESULT_SCHEMA_VERSION",
    "csharp_strategy_verification_result_sha256",
    "csharp_strategy_reference_trace_sha256",
    "prepare_csharp_strategy_verification_inputs",
    "run_csharp_strategy_verification",
]
