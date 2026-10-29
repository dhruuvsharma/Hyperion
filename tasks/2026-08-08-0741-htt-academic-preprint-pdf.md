# HTT academic preprint PDF
Status: complete

## Goal
Reformat the Hyperion Terminal Transformer research paper as a polished academic preprint suitable
for submission as a research project, using arXiv:2512.04695 as the visual-format reference without
copying its claims or implying conference acceptance.

## Boundaries
- Preserve the paper's evidence labels and do not turn proposed architecture, derived budgets, or
  target metrics into measured results.
- Do not claim peer review, conference publication, trained weights, benchmark results, or production
  readiness.
- Keep `public/` pinned and read-only, and preserve compatibility-sensitive code and wire identities.
- Use repository-local HTT source and tooling; keep the canonical deliverable under
  `products/htt/research/`.
- Use the reference paper only for publication conventions such as page geometry, typography,
  hierarchy, captions, citations, and appendices.

## Plan
1. Inspect the complete reference layout and audit the current HTT source/builder.
2. Adapt the canonical source metadata and ReportLab builder to an academic preprint format.
3. Generate the PDF, render every page, and correct all layout defects.
4. Validate PDF metadata/text/page count, links, builder quality, and both worktrees.

## Initial findings
- The reference is the 30-page US-letter paper `TRINITY: An Evolved LLM Coordinator`, published at
  ICLR 2026. Its conference banner must not be reproduced for HTT.
- The reference uses a restrained one-column academic layout with a compact title block, centered
  abstract, numbered sections, full-width figures/tables, author-year references, running header,
  and centered page number.
- The current HTT artifact is a 35-page A4 approval-style report with a designed cover. The same
  11,346-word technical source can be retained while the presentation and submission framing change.

## Verification
- Generated a 29-page US-letter PDF with the academic 5.5-inch text measure, compact title/byline,
  narrow abstract, justified serif body, numbered hierarchy, booktabs-style tables, full-width
  diagrams, running preprint header, centered page numbers, appendices, references, and bookmarks.
- Rendered and visually inspected every page after the final build. No clipping, overlap, orphaned
  captions, broken list markers, unreadable tables, or malformed glyphs remain.
- PDF metadata reports the full title, `Hyperion Research` author, prospective-protocol subject, and
  an unencrypted 612 x 792 point document. All 29 pages contain the running preprint header.
- All 55 bibliography URLs are unique clickable URI annotations. All 55 numbered references are
  cited; there are no missing or uncited entries.
- The PDF contains 41 outline entries. Minimum extracted page content is 195 words, which catches
  accidental blank pages while allowing the short final repository-source page.
- `python -m ruff check products/htt/tools/build_research_paper.py` passed.
- `python -m ruff format --check products/htt/tools/build_research_paper.py` passed.
- `git diff --check` passed. `git -C public status --short` is clean.
- Temporary reference downloads, extracted text, renders, contact sheets, and local Python/Ruff
  caches were sent to the Windows Recycle Bin after verification.

## Result
- Replaced the designed approval-report cover with an honest academic-preprint presentation and did
  not reproduce the reference paper's conference-acceptance banner or arXiv overlay.
- Reframed internal approval language as a prospective research protocol and added explicit
  no-checkpoint/no-results disclosures to the source, title page, and abstract.
- Added an introduction, numbered table captions, publication-style figure captions, clickable
  references, cross-platform font fallbacks, and caption-safe figure flow.
- Corrected the task-adapter matrix dimensions, separated core and optional parser-state parameter
  totals, included final and QK normalization terms in the derived budget, and softened claims that
  exceeded the cited evidence.

## Submission note
- The current byline is `Hyperion Research / Independent research project`. Confirm the submitting
  author's exact name, affiliation, contact, contribution, funding, and conflict disclosures before
  a formal external submission.
- This is a design study and evaluation protocol, not an empirical model paper. A venue requiring a
  trained checkpoint or benchmark results will require the preregistered experiments first.
