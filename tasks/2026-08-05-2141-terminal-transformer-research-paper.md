# Hyperion Terminal Transformer Research Paper
Status: complete

## Goal
Produce a research-first, approval-ready PDF that proposes a from-scratch, low-parameter, high-efficiency transformer architecture specialized exclusively for Hyperion Terminal strategy authoring and visualizer authoring.

## Hypothesis (files/symbols)
- The paper should narrow the model's knowledge and output space instead of pursuing a general-purpose assistant.
- The design should combine evidence-backed mechanisms only where their interactions can be tested independently.
- Current Hyperion coordinator, retrieval, verifier, promotion, and serving boundaries remain authoritative; this task changes documentation only.
- Proposed deliverables, later organized under the HTT product home: `products/htt/research/hyperion-terminal-transformer-research-paper.md` and `products/htt/research/hyperion-terminal-transformer-research-paper.pdf`.

## Questions and answers
- The requested deliverable is a research paper and PDF for human approval, not implementation or training.
- "Best accuracy" will be treated as an optimization target to validate experimentally, never as an unevidenced claim.
- The model is restricted to Terminal strategy building and visualizer building; unrelated general knowledge is out of scope.

## Plan
1. Review current primary sources on efficient transformer, code-model, retrieval, distillation, and verification architectures.
2. Derive a purpose-built architecture, parameter/compute budgets, training curriculum, and evaluation gates.
3. Write the paper with equations, diagrams, comparisons, risks, and an experiment matrix.
4. Generate, render, inspect, and validate the PDF.

## Blast radius
- Documentation, task memory, PDF-generation support, and final PDF only.
- No runtime, training, Platform, Terminal, or `public/` source changes.

## Build filter
- PDF generation and render verification only.

## Tests to run
- Source/reference completeness and link checks.
- PDF metadata/page/text extraction checks.
- Full-page PNG rendering and visual inspection.
- Root and `public/` status review to preserve unrelated work.

## Findings (cache narrow reads here)
- Reviewed and resolved 55 primary arXiv sources covering transformer blocks, normalization, position encoding, GQA, exact attention kernels, local/global attention, small code models, tokenization, FIM, retrieval, data curation, distillation, verification, RLVR, calibration, quantization, and alternative architectures.
- Proposed `HTT-1.5B-r0`: a 32-layer, 2,048-wide decoder with 16 query / 4 KV heads, 5,632-wide SwiGLU, tied 32,768-token vocabulary, 8K normal admission and 32K trained ceiling, and `[local, local, local, global] x 8` attention.
- Derived approximately 1.524B stored parameters and 1.517B active parameters with one deterministic rank-64 task lane. Derived a 0.6875 GiB BF16 hybrid KV cache at 32K, versus 8 GiB for full 16-head MHA.
- Kept current private Terminal APIs, topology, and policy in signed versioned retrieval. Stable language/numerical/visualization skills may enter weights; authority, tools, hidden tests, and release remain outside the model.
- Preserved the current inert strategy artifact and human release/compile-consent boundary. The visualizer IR is explicitly proposed future work and cannot express executable, network, filesystem, process, broker, package, or credential behavior.
- Clean-sheet random initialization is an experiment, not a presumed winner. The program requires a continued-pretraining baseline, parameter-matched dense controls, small scaling pilots, and sealed functional evidence.

## Diff summary
- Added the approval-ready Markdown research paper with architecture, derivations, diagrams, corpus/training design, constrained decoding, retrieval, verifier/evaluation scorecard, serving, ablations, risks, roadmap, appendices, and 55 references.
- Added the generated 35-page A4 PDF, now organized under `products/htt/research/`.
- No runtime, training, Platform, Terminal, or `public/` source was modified.

## Verification
- All 55 cited arXiv identifiers resolved through the arXiv API; reference definitions are unique, complete, and all are cited.
- PDF metadata is present; `pdfinfo` reports 35 A4 pages, no encryption, and no JavaScript.
- `pypdf` / `pdfplumber` extracted 96,895 characters with no empty pages; expected architecture, parameter, visualizer IR, figure, and reference markers are present.
- `pdftoppm` rendered all 35 pages at 120 DPI. Three full contact sheets and high-resolution architecture/formula/table pages were visually inspected with no clipping, overlap, broken glyphs, or pagination defects.
- The PDF contains embedded Arial/Consolas subsets for document content and 42 top-level outline objects/bookmark groups.
- `git diff --check` passed. Root status contains only this task, paper source, and PDF; `public/` status is clean.

## Risks / deferred
- Architecture quality cannot be established without corpus approval, controlled ablations, training runs, and sealed evaluation evidence.
- "Terminal-only knowledge" is specified as corpus minimization plus operational capability confinement; literal absence of all outside latent knowledge cannot be proven.
- Full pretraining, a visualizer artifact contract/compiler, model weights, production hardware qualification, quantization promotion, and deployment remain deferred pending human approval and later gates.
