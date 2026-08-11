from __future__ import annotations

import platform
import sys
import tomllib
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Mapping

from .core import (
    ValidationError,
    _exact_keys,
    _fail,
    _read_file_bounded,
    _regular_file,
    _sha256,
    _string,
    load_json_document,
    sha256_file,
)


TRAINING_RUNTIME_PROFILE_SCHEMA_VERSION = (
    "daxalgo.hyperion.training-runtime-profile/v1"
)
TRAINING_RUNTIME_PROFILE_BUNDLE_PATH = "inputs/training-runtime-profile.json"
TRAINING_PYLOCK_BUNDLE_PATH = "inputs/pylock.train.toml"
TRAINING_PYLOCK_FILE_NAME = "pylock.train.toml"
TRAINING_PYLOCK_SHA256 = (
    "9e55bffe81d66a1f85bbacb6f910cac5fc01f0bfff99b4418fa53188784b3e72"
)
MAX_PYLOCK_BYTES = 20_000_000
DIRECT_DEPENDENCY_VERSIONS = {
    "accelerate": "1.2.1",
    "bitsandbytes": "0.45.2",
    "cryptography": "48.0.0",
    "datasets": "3.2.0",
    "peft": "0.14.0",
    "torch": "2.5.1+cu121",
    "transformers": "4.48.3",
    "trl": "0.15.2",
}
_EXPECTED_RUNTIME = {
    "python": {"implementation": "CPython", "major": 3, "minor": 11},
    "platform": {
        "system": "Linux",
        "machine": "x86_64",
        "manylinux": "manylinux_2_28",
    },
    "cuda": {"runtimeVersion": "12.1"},
}


class RuntimeLockError(RuntimeError):
    """Raised when a trainer does not exactly match its sealed runtime lock."""


def _validate_profile_document(value: Any) -> dict[str, Any]:
    profile = _exact_keys(
        value,
        {"schemaVersion", "python", "platform", "cuda", "directDependencies", "pylock"},
        "training runtime profile",
    )
    if profile["schemaVersion"] != TRAINING_RUNTIME_PROFILE_SCHEMA_VERSION:
        _fail(
            "training runtime profile.schemaVersion",
            f"must be {TRAINING_RUNTIME_PROFILE_SCHEMA_VERSION!r}",
        )
    for section in ("python", "platform", "cuda"):
        actual = _exact_keys(
            profile[section],
            set(_EXPECTED_RUNTIME[section]),
            f"training runtime profile.{section}",
        )
        if actual != _EXPECTED_RUNTIME[section]:
            _fail(
                f"training runtime profile.{section}",
                f"must exactly equal {_EXPECTED_RUNTIME[section]!r}",
            )
    dependencies = _exact_keys(
        profile["directDependencies"],
        set(DIRECT_DEPENDENCY_VERSIONS),
        "training runtime profile.directDependencies",
    )
    if dependencies != DIRECT_DEPENDENCY_VERSIONS:
        _fail(
            "training runtime profile.directDependencies",
            "must exactly equal the sealed direct dependency versions",
        )
    pylock = _exact_keys(
        profile["pylock"],
        {"fileName", "sha256"},
        "training runtime profile.pylock",
    )
    if pylock["fileName"] != TRAINING_PYLOCK_FILE_NAME:
        _fail(
            "training runtime profile.pylock.fileName",
            f"must be {TRAINING_PYLOCK_FILE_NAME!r}",
        )
    if (
        _sha256(pylock["sha256"], "training runtime profile.pylock.sha256")
        != TRAINING_PYLOCK_SHA256
    ):
        _fail(
            "training runtime profile.pylock.sha256",
            "does not match the reviewed pylock SHA-256",
        )
    return profile


def validate_training_runtime_profile(path: str | Path) -> dict[str, Any]:
    return _validate_profile_document(load_json_document(Path(path)))


def validate_pylock_train(path: str | Path, profile: Mapping[str, Any]) -> None:
    lock_path = _regular_file(Path(path), "training runtime pylock")
    if (
        sha256_file(lock_path, max_bytes=MAX_PYLOCK_BYTES)
        != profile["pylock"]["sha256"]
    ):
        _fail("training runtime pylock", "does not match the runtime profile SHA-256")
    try:
        lock = tomllib.loads(
            _read_file_bounded(
                lock_path, "training runtime pylock", MAX_PYLOCK_BYTES
            ).decode("utf-8", errors="strict")
        )
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValidationError(
            f"training runtime pylock: invalid TOML: {error}"
        ) from error
    if lock.get("lock-version") != "1.0":
        _fail(
            "training runtime pylock.lock-version", "must be PEP-751 lock version '1.0'"
        )
    if lock.get("requires-python") != ">=3.11":
        _fail("training runtime pylock.requires-python", "must be '>=3.11'")
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        _fail(
            "training runtime pylock.packages", "must contain PEP-751 package entries"
        )
    direct: dict[str, str] = {}
    for index, package in enumerate(packages):
        field = f"training runtime pylock.packages[{index}]"
        if not isinstance(package, dict):
            _fail(field, "must be an object")
        if "sdist" in package:
            _fail(field, "must not permit source distributions")
        name = _string(package.get("name"), f"{field}.name", max_length=200)
        version = _string(package.get("version"), f"{field}.version", max_length=200)
        wheels = package.get("wheels")
        if not isinstance(wheels, list) or not wheels:
            _fail(field, "must contain one or more binary wheel entries")
        for wheel_index, wheel in enumerate(wheels):
            wheel_field = f"{field}.wheels[{wheel_index}]"
            if not isinstance(wheel, dict):
                _fail(wheel_field, "must be an object")
            url = _string(wheel.get("url"), f"{wheel_field}.url", max_length=4_000)
            if not url.startswith("https://") or not url.endswith(".whl"):
                _fail(wheel_field, "must be an HTTPS binary wheel URL")
            hashes = wheel.get("hashes")
            if not isinstance(hashes, dict) or set(hashes) != {"sha256"}:
                _fail(wheel_field + ".hashes", "must contain exactly one SHA-256 hash")
            _sha256(hashes["sha256"], wheel_field + ".hashes.sha256")
        if name in DIRECT_DEPENDENCY_VERSIONS:
            if name in direct:
                _fail(field, f"duplicates direct dependency {name!r}")
            direct[name] = version
    if direct != DIRECT_DEPENDENCY_VERSIONS:
        _fail(
            "training runtime pylock.packages",
            "does not exactly pin every sealed direct dependency version",
        )


def load_and_validate_training_runtime(
    profile_path: str | Path,
    pylock_path: str | Path,
) -> dict[str, Any]:
    profile = validate_training_runtime_profile(profile_path)
    validate_pylock_train(pylock_path, profile)
    return profile


def installed_direct_dependency_versions(
    dependencies: Mapping[str, Any],
) -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in DIRECT_DEPENDENCY_VERSIONS:
        module = dependencies[name]
        version = getattr(module, "__version__", None)
        if not isinstance(version, str) or not version.strip():
            try:
                version = importlib_metadata.version(name)
            except importlib_metadata.PackageNotFoundError as error:
                raise RuntimeLockError(
                    f"training dependency {name!r} does not expose an installed version"
                ) from error
        versions[name] = version
    return versions


def runtime_host_facts() -> dict[str, Any]:
    return {
        "python": {
            "implementation": platform.python_implementation(),
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
        },
        "platform": {"system": platform.system(), "machine": platform.machine()},
    }


def validate_runtime_host(
    profile: Mapping[str, Any],
    *,
    facts: Mapping[str, Any] | None = None,
    error_type: type[Exception] = RuntimeLockError,
) -> dict[str, Any]:
    observed = dict(facts or runtime_host_facts())
    expected = {
        "python": profile["python"],
        "platform": {
            "system": profile["platform"]["system"],
            "machine": profile["platform"]["machine"],
        },
    }
    for section, required in expected.items():
        if observed.get(section) != required:
            raise error_type(
                f"training runtime {section} differs from the sealed profile; "
                f"expected {required!r}, observed {observed.get(section)!r}"
            )
    return observed


def runtime_facts(
    dependencies: Mapping[str, Any],
    dependency_versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    torch = dependencies["torch"]
    return {
        **runtime_host_facts(),
        "cuda": {
            "runtimeVersion": getattr(getattr(torch, "version", None), "cuda", None)
        },
        "directDependencies": dict(
            dependency_versions or installed_direct_dependency_versions(dependencies)
        ),
    }


def validate_runtime_environment(
    profile: Mapping[str, Any],
    dependencies: Mapping[str, Any],
    *,
    dependency_versions: Mapping[str, str] | None = None,
    facts: Mapping[str, Any] | None = None,
    error_type: type[Exception] = RuntimeLockError,
) -> dict[str, Any]:
    observed = dict(facts or runtime_facts(dependencies, dependency_versions))
    expected = {
        "python": profile["python"],
        "platform": {
            "system": profile["platform"]["system"],
            "machine": profile["platform"]["machine"],
        },
        "cuda": profile["cuda"],
        "directDependencies": profile["directDependencies"],
    }
    for section, required in expected.items():
        if observed.get(section) != required:
            raise error_type(
                f"training runtime {section} differs from the sealed profile; "
                f"expected {required!r}, observed {observed.get(section)!r}"
            )
    return observed
