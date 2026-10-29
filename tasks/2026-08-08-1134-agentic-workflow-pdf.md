# Agentic workflow PDF

Status: complete

Date: 2026-08-08

## Objective

Create a polished, implementation-accurate PDF that explains how the Hyperion Free Strategy
Workflow coordinates its five fixed roles, validates durable artifacts, performs bounded fresh-run
repair, routes user-owned provider credentials, and preserves the Terminal authority boundary.

## Scope

- Base claims on the implemented workflow contracts, manifest, tests, and agentic-gauntlet design.
- Use diagrams to make role visibility, state transitions, process gates, repair lineage, BYOK
  routing, and the deferred Terminal verification boundary understandable.
- Distinguish current process-integrity evidence from compilation, functional correctness,
  profitability, and live-trading safety.
- Keep `public/` read-only and do not access external Terminal repositories.

## Deliverables

- Reproducible PDF builder under `products/free-strategy-workflow/tools/`.
- Final PDF under `output/pdf/`.
- Rendered page QA under `tmp/pdfs/` only.

## Verification

- Built `output/pdf/hyperion-free-cli-agentic-workflow.pdf` successfully from the repository-owned
  ReportLab builder.
- PDF inspection passed: 17 letter-size pages, 187,806 bytes, 14 clickable reference annotations,
  26 outline entries, embedded primary fonts, no encryption, no empty pages, and no out-of-bounds
  extracted characters.
- Rendered every page through Poppler at 150 DPI and visually inspected the complete paper. The
  final render has no clipping, overlapping content, broken diagrams, or unreadable glyphs.
- Required-content extraction passed for all five roles, the first and last gauntlet checks, exact
  non-guarantee fields, deep-research comparison, bounded repair, and the proposed Terminal gate.
- `python -m ruff check products/free-strategy-workflow/tools/build_agentic_workflow_pdf.py`: passed.
- `python -m ruff format --check products/free-strategy-workflow/tools/build_agentic_workflow_pdf.py`:
  passed.
- `git diff --check`: passed. Existing unrelated line-ending warnings remain informational.
- Final PDF SHA-256:
  `35e4349a6b7ceb813a335ba0be01c16974efd175dd58182028f1d930d622532b`.
- `git -C public status --short`: clean; no shared-core change.
- .NET tests were not rerun because this task adds documentation and a standalone PDF builder only.
