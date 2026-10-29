from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (
    ROOT
    / "products"
    / "htt"
    / "research"
    / "hyperion-terminal-transformer-research-paper.tex"
)
OUTPUT = (
    ROOT
    / "products"
    / "htt"
    / "research"
    / "hyperion-terminal-transformer-research-paper.pdf"
)
BUILD_DIR = ROOT / "tmp" / "pdfs" / "htt-latex-build"
PINNED_TECTONIC = ROOT / "tmp" / "tectonic-0.17.0" / "tectonic.exe"
SOURCE_DATE_EPOCH = "1786156800"  # 2026-08-08T00:00:00Z


def find_tectonic() -> str:
    configured = os.environ.get("TECTONIC")
    if configured:
        candidate = Path(configured).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        raise FileNotFoundError(f"TECTONIC does not point to a file: {candidate}")

    on_path = shutil.which("tectonic")
    if on_path:
        return on_path

    if PINNED_TECTONIC.is_file():
        return str(PINNED_TECTONIC)

    raise FileNotFoundError(
        "Tectonic was not found. Install Tectonic 0.17.0 and place it on PATH, "
        "or set TECTONIC to the compiler executable."
    )


def validate_log(log_path: Path) -> None:
    log = log_path.read_text(encoding="utf-8", errors="replace")
    fatal_patterns = {
        "undefined citation": r"Citation [`'][^`']+['`] on page .* undefined",
        "undefined reference": r"Reference [`'][^`']+['`] on page .* undefined",
        "undefined control sequence": r"Undefined control sequence",
        "missing character": r"Missing character:",
    }
    failures = [
        label for label, pattern in fatal_patterns.items() if re.search(pattern, log)
    ]

    overfull = [
        float(value)
        for value in re.findall(r"Overfull \\hbox \(([0-9.]+)pt too wide\)", log)
    ]
    if overfull and max(overfull) > 5.0:
        failures.append(f"overfull box wider than 5pt ({max(overfull):.2f}pt)")

    if failures:
        raise RuntimeError("LaTeX validation failed: " + ", ".join(failures))


def build() -> None:
    compiler = find_tectonic()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    command = [
        compiler,
        "--keep-logs",
        "--keep-intermediates",
        "--outdir",
        str(BUILD_DIR),
        str(SOURCE),
    ]
    subprocess.run(command, cwd=SOURCE.parent, env=environment, check=True)

    built_pdf = BUILD_DIR / f"{SOURCE.stem}.pdf"
    log_path = BUILD_DIR / f"{SOURCE.stem}.log"
    if not built_pdf.is_file() or not log_path.is_file():
        raise RuntimeError(
            "Tectonic completed without producing the expected PDF and log"
        )

    validate_log(log_path)
    shutil.copy2(built_pdf, OUTPUT)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    build()
