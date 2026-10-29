# HTT LaTeX mathematical monograph
Status: complete

## Goal
Replace the presentation-oriented HTT PDF pipeline with direct LaTeX and expand the paper into a
submission-quality mathematical design study with explicit notation, assumptions, derivations,
dimensional checks, and worked HTT-1.5B-r0 substitutions.

## User findings to address
- Display mathematics is currently rendered as monospace code rather than typeset equations.
- Many abbreviations are presented with code typography despite not being source identifiers.
- Existing derivations are too short for a research-project submission.

## Boundaries
- Preserve evidence honesty: the architecture is prospective, and no checkpoint or benchmark result
  may be implied.
- Use code typography only for literal schemas, enum values, API members, paths, and commands.
- Treat every parameter, compute, memory, objective, calibration, and statistical formula as a
  derivation with assumptions and unit checks, not merely a final number.
- Keep `public/` pinned and read-only and do not touch any external Terminal repository.
- Keep the final PDF at its established canonical product path.

## Plan
1. Audit mathematical coverage, notation, abbreviations, and the available TeX toolchain.
2. Author a direct LaTeX source, bibliography, vector figures, and reproducible compiler wrapper.
3. Expand and verify the mathematical derivations and numerical substitutions.
4. Compile, render every page, inspect the complete paper, and validate references, links, metadata,
   warnings, source hygiene, and both worktrees.

## Initial decisions
- Direct LaTeX is the canonical paper source; Markdown is retained as the earlier narrative source
  until the LaTeX monograph passes full verification.
- Tectonic is the local compiler because no TeX engine is installed on the host. The source remains
  standard LaTeX and can also be compiled by a conventional TeX Live toolchain.
- Use standard mathematical environments (`align`, `equation`, `gather`, `cases`, matrices),
  `booktabs`/`longtable` tables, TikZ vector diagrams, `hyperref`, and numeric citations.
- Include an explicit notation table and abbreviation glossary near the front of the paper.

## Verification

- Compiled the canonical LaTeX source with Tectonic 0.17.0 into a 29-page letter-size PDF.
- The paper contains 92 labeled equations (the equation counter reaches 156), 10 tables, four TikZ
  vector diagrams, a notation table, an abbreviation glossary, and 56 bibliography entries.
- The compiler log contained no overfull or underfull boxes, undefined citations or
  references, undefined control sequences, or missing-character warnings.
- Rendered all 29 pages at 120 DPI, reviewed both complete contact sheets, and inspected the title,
  glossary, architecture, retrieval, evaluation, ablation, and final-reference pages at full size.
- `pdfinfo`, `pdffonts`, text extraction, and `pypdf` checks confirmed 29 nonblank pages, embedded
  fonts, 131 link annotations, 38 outline roots, and no broken internal destinations.
- Two consecutive builds produced byte-identical output with SHA-256
  `7C60FECAB2E3AE5AC6FABE25E8686F19E512609EF04447B8E6E15D469DE640CB`.
- `python -m ruff check products/htt/tools/build_research_paper.py` passed.
- `python -m ruff format --check products/htt/tools/build_research_paper.py` passed.
- The shared-core `public/` worktree remained clean.

## Remaining submission metadata

- The byline and affiliation remain the neutral placeholders `Hyperion Research` and `Independent
  research project`. Replace them with the submitter's exact details before external submission.
- The paper intentionally reports a prospective architecture and protocol, not trained-model or
  benchmark results.
