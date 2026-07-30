# Hyperion extraction and ML-engineer handoff
Status: complete

## Goal
Create an independent private `Hyperion` repository under `D:\Github`, move the complete Vibe Quant
expert-model coordinator and its dependency/test closure into it from the last pushed revisions,
brand the system Hyperion without breaking signed compatibility surfaces, add Kimi K3 research and
cluster recommendations, produce a detailed Word/PDF engineering handbook, verify, commit, and push.

## Hypothesis (files/symbols)
- Core implementation: the three coordinator projects, CLI, Python model harness, hosted Platform
  feature, isolated verifier worker, DAXQ verification closure, relevant tests, and Terminal adapter.
- Stable signed schema IDs, hashes, namespaces, database fields, and API versions must remain legacy
  compatibility identifiers; repository/product/solution/operator surfaces can use Hyperion now.
- A pinned public submodule is safer than copying the concurrent dirty public worktree.

## Questions and answers
- Source snapshot: Pro `003685a92e7ddba9e4149d3bb545f4ce82446f3e`; public
  `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05`.
- GitHub owner: authenticated account `dhruuvsharma`; repository visibility must be private.
- Training evidence: no model weights, checkpoint, conforming training run, accepted benchmark, or
  production deployment exists yet.
- Kimi paper: verify “Kimi K3” from primary sources before incorporating any method or licence claim.

## Plan
1. Complete source/dependency and Kimi K3 primary-source audits.
2. Extract, brand, and independently wire the private Hyperion repository.
3. Run scoped .NET, Python, schema, CLI, formatting, boundary, and hygiene closure.
4. Author and visually verify the Markdown/DOCX/PDF engineer handbook.
5. Commit, push, and verify the private remote.

## Blast radius
- New repository only: `D:\Github\Hyperion` and `github.com/dhruuvsharma/Hyperion`.
- The original Pro checkout and its dirty `public/` submodule are read-only extraction sources.
- The new `public/` submodule is pinned and read-only.

## Build filter
- `Hyperion.slnx` for the complete extracted .NET closure.
- `tools/hyperion-model` for the Python package, schemas, CLI, and tests.

## Tests to run
- .NET restore/build/test for the named Hyperion solution and isolated verifier.
- Full Python tests, Ruff check/format, compileall, schema/reference validation, and CLI discovery.
- Git boundary/status, secret/weight, text hygiene, submodule pin, DOCX/PDF structural and visual QA.

## Findings (cache narrow reads here)
- The live source checkout acquired extensive unrelated edits after the prior push. Extraction uses
  committed object data only; no live dirty bytes are copied.
- Internal `VibeQuant`, `DaxAlgo`, and `TradingTerminal` names occur in signed wire formats and
  compatibility contracts. Hyperion branding is additive at repository, solution, package,
  executable, and documentation surfaces.
- Kimi K3 is a real 27 July 2026 preprint (`arXiv:2607.24653v1`). The reviewed official snapshot
  reports 2.78T total and 104.2B active parameters per token; its 96 published safetensor shards are
  about 1.42 TiB before runtime overhead. It is not a practical base for the proposed small cluster.
- Hyperion adopts K3's useful system ideas as research directions: domain-by-effort specialists,
  explicit reasoning budgets, independent hidden verification, harness diversity, resumable partial
  rollouts, structured transcripts, dynamic scheduling, and later multi-teacher consolidation.
  Architecture/pretraining mechanisms such as KDA, Attention Residuals, Stable LatentMoE, MoonEP,
  and deployment quantisation remain ablation research rather than QLoRA features.
- Kimi K3 weights use a custom licence, not a standard permissive/OSI licence. Commercial thresholds,
  attribution, and current licence text require legal review before any use.
- The first hosted CI run (`30584887558`) passed the complete Windows/.NET job but exposed five
  Linux-only Python failures. One test incorrectly supplied a host-managed symlink as the attested
  vLLM executable; the other four demonstrated that POSIX may immediately recycle an inode after
  unlink/recreate, defeating cleanup code that retained only `(st_dev, st_ino)` after closing its
  final descriptor.
- The replacement run (`30586966703`) passed all Linux tests, then exposed an undeclared Ruff-policy
  dependency when newly released Ruff 0.16.1 expanded the effective rule set. The project now states
  its intended `E4`, `E7`, `E9`, and `F` lint baseline explicitly instead of inheriting tool defaults.

## Diff summary
- Created the private `dhruuvsharma/Hyperion` repository and independent `Hyperion.slnx`; pinned the
  shared Core/SDK as the read-only `public/` submodule at `ae19c5eb7a`.
- Exported the coordinator/contracts/client, Hyperion CLI, DAXQ verification closure, hosted Platform
  integration, isolated verifier, Python model/evidence harness, tests, and bounded Terminal adapter
  from committed Pro snapshot `003685a92e`; no live dirty source bytes were copied.
- Added Hyperion product/CLI/package/UI/OpenAPI branding while retaining legacy signed schema IDs,
  domains, routes, namespaces, configuration keys, persistence names, and compatibility aliases.
- Added CI, provenance, operator/research documentation, a pinned primary-source Kimi K3 review, five
  native diagrams, and the 22-section engineering handbook in Markdown, Word, and PDF.
- Added the reproducible handbook builder at `tools/docs/build_hyperion_handbook.py`.
- Canonicalized the trusted Python executable fixture without weakening production symlink/reparse
  rejection. Added descriptor-backed POSIX ownership guards to all audited file-publication, lock,
  and training-directory cleanup paths, plus direct unlink/recreate regression coverage. Windows
  delete/rename behavior remains unchanged.
- Made the Ruff lint contract explicit in `tools/hyperion-model/pyproject.toml` so CI does not change
  policy merely because the hosted runner resolves a newer Ruff release.

## Verification
- `dotnet build Hyperion.slnx --no-restore`: passed with 0 warnings and 0 errors.
- `dotnet test Hyperion.slnx --no-build --no-restore`: 537/537 passed across Contracts 44, VM 41,
  Compiler 41, Platform API 150, VerifierWorker 43, and coordinator headless 218.
- Final formatter repair was limited to three extracted root files; the final root/Platform check
  `dotnet format Hyperion.slnx --verify-no-changes --no-restore --exclude public` passes. The full
  command still reports pre-existing formatting in 11 files inside the pinned read-only submodule.
- Final full Python closure after portability hardening: 494 passed, 0 failed, and 5 expected Windows
  POSIX/symlink-capability skips. Focused stable-tree modules passed 123/123 and 58/58; the Linux
  harness passed 34/34, six direct file-publication regressions passed on Windows and Linux, and
  three POSIX lock/directory regressions passed on Linux. Ruff check/format and diff checks passed.
  The earlier compileall, all 113 Draft 2020-12 schemas, 2,029
  references, and 87 CLI help surfaces remain green. The host is Windows/Python 3.12.6, not the
  sealed training runtime.
- The explicit lint baseline passes under both local Ruff 0.15.11 and hosted-version Ruff 0.16.1;
  both formatter checks also pass without rewriting any source.
- Hosted run `30584887558` completed with its .NET build, 537 tests, and scoped formatter green; its
  failed Python job supplied the Linux portability evidence above. A fresh hosted run on the pushed
  closure commits is the final publication gate and will be recorded in the repository issue.
- Verifier container build passed from digest-pinned bases as `hyperion-verifier:closure`; the final
  manifest-list digest was `sha256:3c4b925818db94661241918ac9e0eccd0f2121d2a39374d6e2030ae0f0bae21e`.
- The handbook is a tagged 40-page Letter PDF with embedded subset fonts. DOCX heading, table geometry,
  image, section, field, and accessibility audits passed (0 high/medium findings; 25 low raw-URL
  source-label advisories). Every rendered page was visually inspected with no clipping or overflow.
- Staged diff check, strict UTF-8/no-BOM/final-newline checks, declared line-ending policy, JSON parse,
  weight/private-key/token scan, large-file scan, submodule cleanliness, and private-remote visibility
  passed. No model weight, checkpoint, private key, credential, or production evidence is tracked.

## Risks / deferred
- Real data rights, independent review, production signer custody, conforming GPU infrastructure,
  training, benchmark acceptance, and deployment remain external milestones.
- The bounded Terminal/WPF adapter is retained as integration source but is not part of the standalone
  Hyperion solution; production desktop authentication still needs an isolated account/device/session
  authority rather than secrets in a full-trust plugin host.
- Verifier evidence retains its documented limits: the caller selects image/entrypoint under signed
  authority, Docker daemon/runtime/kernel/builtin-seccomp state is not independently attested, and a
  privileged or same-user host retains narrow output path-swap power.
- Descriptor guards prevent inode-reuse misidentification while an ownership decision is active;
  they do not remove the documented same-user/privileged-host swap window after a completed check.
