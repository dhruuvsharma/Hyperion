# Kimi K3 handbook and architecture refresh
Status: active

## Goal
Verify the latest official Kimi K3 paper and source materials as of 5 August 2026, apply only
evidence-supported improvements to Hyperion's target architecture, and publish a detailed,
well-labelled ML-engineering handbook as synchronized Markdown, DOCX, and PDF artifacts.

## Hypothesis (files/symbols)
- `docs/research/kimi-k3-adoption-notes.md` should hold the paper-specific claim and adoption audit.
- `docs/architecture/hyperion-frontier-architecture.md` should remain the canonical target design.
- `docs/engineering/hyperion-llm-coordinator-handbook.md` and
  `tools/docs/build_hyperion_handbook.py` should remain the source and generator for the team handoff.
- Existing generated diagrams and document styles should be extended, not replaced wholesale.

## Questions and answers
- Repository boundary: change, commit, and push only `D:\Github\Hyperion`; keep `public/` pinned and
  read-only.
- Evidence boundary: Kimi K3 paper/repository/model-card claims are literature inputs, not reproduced
  Hyperion results. No trained checkpoint or production deployment may be claimed.
- Licence/access: record provenance and permission requirements; do not bypass controls or infer
  undisclosed implementation details.
- Publication: the user explicitly authorized commit and push to the private Hyperion repository.

## Plan
1. Audit the live worktree, current handbook/architecture, and latest official Kimi K3 sources.
2. Update the Kimi adoption record, target architecture, handbook, and labelled diagrams.
3. Rebuild and visually inspect every DOCX/PDF page; run accessibility and structural checks.
4. Run scoped repository checks, commit and push, then verify hosted CI.

## Blast radius
- Private documentation, document-generation code/assets, generated DOCX/PDF, and this task record.
- Hosted/local closure test-harness hardening is limited to the observed scheduling defects;
  production runtime, signed wire, model weight, checkpoint, secret, and `public/` code remain out
  of scope.

## Build filter
- Documentation builder and document/PDF QA, plus focused and full Platform API tests for any
  hosted-closure test-harness hardening.
- Full model/runtime suites remain required once before publication; repeat only affected closure
  suites after a test-only determinism change.

## Tests to run
- Primary-source version/date/claim audit and URL checks.
- Markdown hierarchy, local-link, provenance, placeholder, and evidence-status checks.
- Builder lint/compile; DOCX ZIP, structure, image-alt-text, table, and accessibility audits.
- PDF metadata/font/text checks and visual inspection of every page.
- Git diff/EOL/UTF-8/boundary/status checks and private-repository hosted CI after push.

## Findings (cache narrow reads here)
- The starting Hyperion worktree was clean at root commit
  `8d65f6c0012061c3ad11dc2cdd8b12675004b948`; the separately pinned, clean, read-only `public/`
  submodule is `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05`.
- The broader expert-model goal remains externally blocked; the existing task record reports no
  trained weights, checkpoint, accepted benchmark, or production deployment.
- The refreshed Kimi K3 source set is still arXiv `2607.24653v1`, official repository commit
  `7c5be9599120d7993748de66a76128614f15f210`, and public model-card revision
  `9f62e4e9fffbd0a83ddd60e1c209d828994b3569`. The arXiv page now exposes the arXiv-issued DOI
  `10.48550/arXiv.2607.24653` with DataCite registration pending and no journal reference.
- The 47-page arXiv PDF SHA-256 is
  `936a7a3b655947b014ba96b8a790c3cdb6ea8b37eea514e4b7b52655e20af0f8`; the later, non-identical
  official-repository report SHA-256 is
  `1f2978d89a9d7f138f6d6ae5f17fd6890dc673abeaea7fca96c1eca432c75ce8`. Their main architecture and
  post-training claims agree, but claims now cite the exact reviewed revision.
- Directly transferable K3 lessons are effort/budget contracts, hidden outcome verification,
  typed provider/transcript capabilities, cache-aware admission/failover, and resumable sandbox
  lifecycle. Routed specialists, structured judge scorepads, QAT/draft acceptance, and serving
  policies require controlled evaluation. KDA, Attention Residuals, Stable LatentMoE, Quantile
  Balancing, SiTU-GLU, and related backbone changes remain equal-compute pretraining research.
- Full K3 is not a small-cluster student: the reviewed public snapshot is about 1.42 TiB across 96
  shards before runtime or training state. QLoRA cannot retrofit its backbone mechanisms, and no
  reported K3 gain is represented as a Hyperion result.
- The handbook is now version 1.2 with seven labelled diagrams and a 49-page PDF. Diagram status
  badges distinguish tested repository infrastructure from target, research, and externally blocked
  work; labelled arrows state the records that cross each boundary.
- Private CI run `30943868102` passed the complete Python job on its first attempt. Its Windows job
  first exposed a signal-session latency assertion that measured database mutation time as well as
  post-commit revocation latency (`2.5823993s` against a `2s` bound). Attempt 2 passed that test but
  exposed a different race: the real Vibe Quant background worker could take a manually claimed run
  before the test, because a `60s` idle poll does not delay the worker's first claim.
- The manual-lease race reproduced locally once in 20 focused runs. The adjacent credit-reservation
  test uses the same slow-poll assumption and reproduced twice in 20 focused runs. Existing tests
  already remove `VibeQuantWorker` when they own claims manually, so the bounded closure is to reuse
  that helper at both affected factories. The signal test retains its post-mutation `3s` receive
  cancellation as the bounded liveness assertion and drops the redundant `2s` wall-clock check,
  which included database work and queued-frame drain time. No production change is justified.
- A subsequent full local solution run kept Platform green at 150/150 but exposed an independent VM
  fixture ambiguity: the real 25ms OnBar watchdog legitimately beat the 100,000-instruction limit
  under concurrent-project scheduler load. The VM project passed 41/41 alone. The instruction-budget
  assertion now injects a frozen monotonic clock, isolating that budget class without changing the
  production watchdog order or limits; the dedicated timeout assertions retain advancing/real clocks.
- The next parallel solution run passed that budget assertion and again kept Platform green, then
  exposed order-dependent JIT warm-up in the indicator zero-allocation test: measurement exercised
  SMA and ATR although setup had warmed only EMA and RSI. The fixture now warms all four measured
  indicator branches before sampling current-thread allocations; the hot-path implementation is
  unchanged.

## Diff summary
- Updated `docs/research/kimi-k3-adoption-notes.md` with exact live revisions, hashes, DOI status,
  paper-page traceability, ablation limits, and a mechanism-by-mechanism Hyperion decision ledger.
- Updated `docs/architecture/hyperion-frontier-architecture.md` with provider capability mapping,
  restricted continuation state, structured judge records, cache-aware admission/failover,
  acceptance-aware draft evaluation, and the explicit K3 adoption boundary.
- Updated the Markdown/DOCX/PDF engineering handbook to version 1.2, including K3 traceability,
  verifier residual limits, seven accessible figures, current metadata, and en-GB document language.
- Extended `tools/docs/build_hyperion_handbook.py` and its README to generate the seven native,
  status-labelled diagrams, substantive figure descriptions, source/version guards, and accurate
  Word core/extended properties.
- Hardened four test fixtures exposed by parallel closure: two Vibe Quant factories now explicitly
  remove the background worker when the test owns queue state, signal revocation keeps its `3s`
  bounded receive without a redundant pre-commit `2s` wall-clock assertion, the instruction-budget
  fixture uses a frozen test clock, and the allocation fixture warms every measured indicator path.
- No production runtime, signed wire, model artifact, secret, checkpoint, or `public/` file changed.

## Verification
- Live K3 source/revision/hash/DOI and page-reference audit: passed; a separate read-only audit found
  no remaining claim error or training/deployment overstatement.
- Builder: Ruff lint and Python compilation passed; the source-metadata guard and DOCX build passed.
- DOCX: ZIP/XML integrity passed; 114 headings without hierarchy gaps, 17 fixed-layout/repeating-header
  tables, seven inline images, seven matched captions, and substantive image descriptions. The
  accessibility audit reports zero high, medium, or low findings. Core timestamps, 49-page extended
  statistics, builder identity, and en-GB defaults are current.
- PDF: tagged, unencrypted PDF 1.7; 49 Letter pages; en-GB root language; five embedded/subset Unicode
  fonts; seven 283-ppi images; 114 bookmarks; required version, source hashes, evidence boundaries,
  and verifier residual-limit text present. All 49 pages and all seven source diagrams were visually
  inspected without clipping, overlap, missing content, or orphaned captions. The metadata-only
  regeneration produced zero pixel-hash differences across all 49 rendered pages.
- Final artifact SHA-256 values are
  `d9d10512712b16c9b284bf5c9adb1795aeda7ffd675626fe9a0fd52851b37aef` (DOCX) and
  `ac4a5a13a82abd328aa31d205692e9e084be8cae907fa1e70514a709db989c77` (PDF).
- Python model-tool closure: `494 passed, 5 skipped` in 19m14s; Ruff check/format passed across 47
  files; compileall and CLI discovery passed.
- Named .NET closure: restore and Release build passed with six known source/shared XML/nullability
  warnings and zero errors; all 541 tests passed (44 Contracts, 41 VM, 41 Compiler, 47 VerifierWorker,
  150 Platform API, and 218 coordinator headless). `dotnet format Hyperion.slnx
  --verify-no-changes --no-restore --exclude public` passed.
- Post-hardening closure: the three affected Platform tests passed 60/60 across 20 rebuilt runs and
  the full Platform project passed 150/150; the two affected VM tests passed 40/40 across 20 rebuilt
  runs and the VM project passed 41/41. The final parallel solution run passed all 541 tests with the
  same suite counts above, and full solution formatting verification passed again.
- Shared context structural `check` passed. The byte-oriented generator check is affected by global
  `core.autocrlf=true`: all 88 generated shard working files differ raw but match their index blobs
  through Git filters. A CRLF-normalized generator comparison still identifies 16 genuinely stale
  shared shards; they are recorded below and were not regenerated in this read-only submodule.
- Root/shared diff checks, strict UTF-8 without BOM, LF/final-newline/trailing-whitespace checks,
  untracked secret/key/model-weight screening, clean pinned submodule status, and private GitHub
  repository visibility passed.
- Hosted private-repository CI run `30943868102`: Python passed; Windows attempt 1 exposed the
  redundant signal deadline and attempt 2 exposed the worker-claim race. A new run for the bounded
  test-harness closure is pending publication.

## Risks / deferred
- The pinned shared Core context requires an upstream refresh for six index shards (`Charts`, `Core`,
  `Pipeline`, `Shell`, `Tests`, `UI`) and ten symbol shards (`Core-Backtesting`, `Core-Configuration`,
  `Core-MarketData`, `Core-Research`, `Core-Strategies`, `Infrastructure-Backtest`,
  `Infrastructure-Plugins`, `Login`, `MarketData`, `UI.Core`). Hyperion keeps `public/` read-only, so
  this slice does not mutate or repoint that submodule.
- Kimi K3 source claims may change after the accessed date; acquisition and experiment execution
  require a fresh source/version check.
- Production training, independent review, KMS/HSM custody, accepted evaluation, and deployment are
  outside this documentation slice and remain evidence-gated.
