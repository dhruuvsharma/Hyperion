from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import hyperion_model.cli as cli_module
from hyperion_model.core import DOMAINS, ValidationError, canonical_json_bytes
from hyperion_model.draft_evaluation import (
    DRAFT_CALIBRATION_MANIFEST_SCHEMA_VERSION,
    compile_draft_calibration_tasks,
)
from hyperion_model.evaluation import validate_evaluation_tasks


class DraftCalibrationCompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.context_bytes = b"private context\r\nwith exact bytes\x00\xff"
        self.verifier_bytes = b'{"kind":"deterministic"}\r\n'
        (self.assets / "context.pack").write_bytes(self.context_bytes)
        (self.assets / "verifier.bin").write_bytes(self.verifier_bytes)

    def _manifest(self, *, split: str = "calibration") -> dict:
        return {
            "schemaVersion": DRAFT_CALIBRATION_MANIFEST_SCHEMA_VERSION,
            "split": split,
            "tasks": [
                {
                    "taskId": "draft-all-domains-001",
                    "taskKind": "QuantitativeReasoning",
                    "domains": list(DOMAINS),
                    "messages": [
                        {
                            "role": "system",
                            "content": "Answer only from the supplied private context.",
                        },
                        {"role": "user", "content": "Evaluate the reviewed scenario."},
                    ],
                    "contextPack": {
                        "version": "private-context-2026-07-28-v1",
                        "path": "assets/context.pack",
                    },
                    "verifier": {
                        "id": "deterministic-review-v1",
                        "path": "assets/verifier.bin",
                        "requiredChecks": ["correct", "safe"],
                    },
                    "contaminationGroup": "draft-all-domains-001",
                    "cutoffUtc": "2025-01-15T12:00:00Z",
                    "criticality": "critical",
                    "maxOutputTokens": 256,
                }
            ],
        }

    def _write_manifest(self, value: dict, name: str = "draft.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8", newline="\n")
        return path

    def test_cli_compiles_canonical_all_domain_calibration_output(self) -> None:
        manifest = self._write_manifest(self._manifest())
        output = self.root / "calibration.tasks.jsonl"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = cli_module.main(
                [
                    "compile-draft-calibration-tasks",
                    "--manifest",
                    str(manifest),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(0, exit_code)
        result = json.loads(stdout.getvalue())
        self.assertTrue(result["created"])
        self.assertEqual([], result["missingDomains"])
        task_set = validate_evaluation_tasks(output)
        self.assertEqual({"calibration": 1}, task_set.coverage()["splitCounts"])
        task = task_set.records[0]
        self.assertEqual(
            hashlib.sha256(self.context_bytes).hexdigest(),
            task["contextPack"]["sha256"],
        )
        self.assertEqual(
            hashlib.sha256(self.verifier_bytes).hexdigest(),
            task["verifier"]["sha256"],
        )
        self.assertEqual(canonical_json_bytes(task) + b"\n", output.read_bytes())

    def test_unknown_manifest_fields_fail_closed(self) -> None:
        value = self._manifest()
        value["unexpected"] = True
        output = self.root / "unknown.tasks.jsonl"
        with self.assertRaisesRegex(ValidationError, "unsupported keys"):
            compile_draft_calibration_tasks(self._write_manifest(value), output)
        self.assertFalse(output.exists())

    def test_asset_paths_cannot_escape_manifest_directory(self) -> None:
        outside = self.root.parent / f"outside-{self.root.name}.bin"
        outside.write_bytes(b"outside")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        for field in ("contextPack", "verifier"):
            with self.subTest(field=field):
                value = self._manifest()
                value["tasks"][0][field]["path"] = f"../{outside.name}"
                output = self.root / f"escape-{field}.tasks.jsonl"
                with self.assertRaisesRegex(ValidationError, "contained relative path"):
                    compile_draft_calibration_tasks(
                        self._write_manifest(value, f"escape-{field}.json"), output
                    )
                self.assertFalse(output.exists())

    def test_existing_output_is_preserved_atomically(self) -> None:
        manifest = self._write_manifest(self._manifest())
        output = self.root / "existing.tasks.jsonl"
        sentinel = b"existing private draft\n"
        output.write_bytes(sentinel)
        with self.assertRaisesRegex(ValidationError, "already exists"):
            compile_draft_calibration_tasks(manifest, output)
        self.assertEqual(sentinel, output.read_bytes())

    def test_draft_compiler_refuses_sealed_split(self) -> None:
        manifest = self._write_manifest(self._manifest(split="sealed"))
        output = self.root / "sealed.tasks.jsonl"
        with self.assertRaisesRegex(ValidationError, "never creates sealed tasks"):
            compile_draft_calibration_tasks(manifest, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
