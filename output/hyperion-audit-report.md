# Hyperion — Full Technical & Research Audit Report

**Date:** 2026-09-01
**Root:** `D:\Github\Hyperion`
**Method:** Nine parallel read-only audit agents covering every document, source file, schema, test suite, and the pinned `public/` submodule, then synthesized into this single report. No files were modified.

---

## 1. Executive summary

Hyperion is a **private, evidence-gated LLM coordinator and expert-model portfolio** for **strategy authoring**, extracted from the (now out-of-scope) DaxAlgo Terminal Pro at commit `003685a92e7ddba9e4149d3bb545f4ce82446f3e`. Its shared Core/SDK dependency is pinned as a **read-only** git submodule (`public/`) at `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05` (upstream: `dhruuvsharma/DaxAlgo-Terminal`, AGPL-3.0 open-core WPF terminal).

The system is **not** an autonomous trading system. It is a governed portfolio of:
1. a **multi-role coordinator** (C#, five fixed roles: Planner → Evidence Analyst → Critic → Synthesizer → Risk Judge) producing *inert* strategy source;
2. an **offline model-evidence harness** (Python, `vibe_quant_model`) for corpus/review/release/training/evaluation/promotion/serving with heavy cryptographic signing;
3. a **constrained C# verifier** (DAXQ) for sandboxed strategy execution;
4. a **hosted platform** (ASP.NET Core) providing billing, marketplace, entitlement licensing, and hosted model deployment.

The single most important, deliberately-repeated claim across the entire repository is the **evidence boundary**: *substantial infrastructure is implemented and tested (553 .NET tests, 494 Python tests, 113 schemas with 2,029 resolved references), but no rights-approved training corpus, no real signing custody, no conforming training run, no checkpoint, no benchmark superiority, and no production deployment yet exists.* The project is unusually disciplined about separating "infrastructure passes tests" from "model-quality or security evidence exists."

---

## 2. Repository map and provenance

| Path | Purpose |
|---|---|
| `products/` | User-facing product homes (HTT, Hyperion CLI, Free Strategy Workflow, Expert Model) |
| `src/windows/AI/Hyperion.FreeStrategyWorkflow` | Local/BYOK provider-neutral inert strategy workflow |
| `src/windows/AI/TradingTerminal.Ai.Coordinator*` | Coordinator contracts, engine, strict API client |
| `src/windows/Tools/Hyperion.Cli` | The .NET `hyperion` operator CLI |
| `tools/hyperion-model` | Python training/eval/review/verifier/promotion/serving harness |
| `platform/` | Hosted API, credit authority, workers, integration tests |
| `src/windows/AI/DaxAlgo.Daxq.*` | Restricted executable-verification closure (Contracts/Vm/Compiler) |
| `public/` | Pinned shared Core/SDK submodule (read-only) |
| `docs/` | Architecture, engineering handbook (MD/DOCX/PDF), guides, research |
| `tasks/` | Durable implementation records (16 files) |
| `tests/` | C#/.NET test projects |

### Provenance
- Independently initialized **30 July 2026**, exported from *committed* Git objects (not the dirty working tree).
- Private origin: `dhruuvsharma/DaxAlgo-Terminal-Pro` @ `003685a92…`.
- Shared origin: `dhruuvsharma/DaxAlgo-Terminal` @ `ae19c5eb7…` (retained as `public/`).
- Extraction scope documented in `docs/architecture/source-provenance.md`: 40 coordinator/CLI files, 28 Python modules + 19 test modules + 113 schemas + manifest locks, 12 coordinator test files, 15 verifier-worker files, the hosted Platform solution, the DAXQ closure, a bounded Terminal adapter, and the original docs. Draft/rehearsal/private-key/weight material was deliberately excluded.

### Legacy naming is a compatibility contract, not an error
Branding is "additive only." `TradingTerminal`, `DaxAlgo`, `VibeQuant`, and `daxalgo.vibe-quant.*` wire/schema IDs persist wherever changing them would invalidate signed payloads, hashes, or existing clients (Python package import name `vibe_quant_model`, API route `/api/v1/vibe-quant`, schema namespace `daxalgo.vibe-quant.*`, content-ID prefixes `vq*`). Global text-rename is explicitly prohibited.

---

## 3. Architecture — three planes

The docs define a clean three-plane separation (handbook §1.2):

| Plane | Responsibility | Implementation |
|---|---|---|
| Coordination | Objective + bounded evidence → role outputs → inert artifact + human release | C# contracts/coordinator/client/CLI/hosted API |
| Model-evidence | Govern corpus, teacher capture, base selection, training, evaluation, artifact sealing, promotion, readiness | Python package + 113 JSON schemas |
| Execution-safety | Evaluate a small allowed C# strategy surface without loading submitted code into the host | Python controller + signed authority + Docker protocol + .NET verifier worker |

Planes exchange **immutable, content-addressed records**, and a passing record in one plane does not silently grant authority in another.

### 3.1 Coordinator (the coordination plane)
`ResearchCoordinator` (`src/windows/AI/TradingTerminal.Ai.Coordinator/Orchestration/ResearchCoordinator.cs`) is a small explicit C# state machine, not open-ended multi-agent conversation. Roles are a fixed, hard-coded list; each role must return one `coordinator-role-output/v1` JSON object; the strategy Synthesizer additionally returns a strict inert source draft. State path: `AwaitingStartApproval → Ready → Running → AwaitingReleaseApproval → Completed`, plus `NeedsRevision/Rejected/Cancelled/Failed/BudgetExhausted`.

Two **mandatory human gates bind exact hashes**: start approval binds the server-created `specSha256` (objective, source hashes, provider/model/budget, policy/workflow versions, credit ceiling, prompt-catalog hash); release approval binds the exact final artifact SHA-256. "An approval is an authenticated statement about exact bytes, not a generic button click."

**Durable state:** `SqliteCoordinatorStore` — current snapshot + append-only event sequence; optimistic-concurrency versioning; each event carries a `previous_sha256` forming a per-run hash chain; `GetVerifiedAsync` re-walks the whole chain on every read to verify sequence contiguity, hash linkage, projection version, and snapshot hash. Artifacts live in `ContentAddressedArtifactStore` (`sha256/xx/full.json`), re-hashed on every read, with hash-collision and path-escape guards.

**Prompt catalog pins itself:** `CoordinatorPromptCatalog` computes its SHA-256 at static-init and throws `InvalidOperationException` on drift against hard-coded `CoordinatorVersions.ResearchPromptCatalogSha256`/`StrategyPromptCatalogSha256`.

**LLM providers (`Models/`):** `OpenAiCompatibleLlmProvider` (Chat Completions), `AnthropicMessagesLlmProvider`, `GoogleGeminiLlmProvider`, `ReplayLlmProvider` (strict hash-keyed replay, no live fallback), `DeterministicMockLlmProvider` (network-free smoke). Each does bounded UTF-8 reads, `finish_reason == stop` enforcement, token-usage validation, and **credential-leak detection** (rejects any response that echoes the configured API key).

### 3.2 Model-evidence plane (Python harness)
Package `vibe_quant_model` (`tools/hyperion-model`), console scripts `hyperion-model` / `hyperion` / legacy `vibe-quant-model`. Base package is **standard-library only**; `auth`/`promote` extras pull `cryptography`; `train` extra is sealed to CPython 3.11 / Linux x86_64 / CUDA 12.1. **86 CLI subcommands** across catalog/SFT, corpus quality/admission, bundles/manifests/training, serving profiles/readiness, base-evaluation, evaluation authoring, C# verifier authority/audit, teacher pipeline, reviews/releases/selection/promotion.

Staged training ladder (verified SFT → DPO → verifiable-RL → distillation → routing), with the explicit initial objective "reliable instruction following, bounded DaxAlgo reasoning, and repair quality — not simulated profitability." Rewards never include PnL/Sharpe/backtest rank.

Key evidence gates: per-row review receipts (`expert-model-review-receipt/v2`), rights-reviewed release (`corpus-evaluation-release/v4`), evaluation-authoring approval, corpus-quality admission, signed base selection (`base-model-selection/v2`), trainer provenance (`trainer-provenance/v1`), promotion (`model-promotion/v1`), readiness (`model-readiness/v2` HMAC), and serving (`engine-wrapper` v7 only). Every authority is time-bounded (receipts/promotion ≤366 days; verifier authority ≤7 days) and enforces **signer separation**.

### 3.3 Execution-safety plane (DAXQ + headless C# verifier)
Two complementary sandboxes:

1. **DAXQ** (`DaxAlgo.Daxq.Contracts/Vm/Compiler`) — a `sealed-bytecode` strategy format. C# source is Roslyn-compiled, pass­ed through a policy scan + IL-subset lowering verifier, emitted as DQXP plaintext, diversified per-release (opcode/host re-encoding + constant negation via a 32-byte seed), AES-256-GCM encrypted, ES256-signed, and ZIP-packed. A `DaxqProgram.TryLoad` static verifier re-validates bytecode before execution. Two engines: `DaxqReferenceVm` (deterministic managed oracle) and `DaxqNativeVm` (native DLL with ES256 license-evidence + integrity gate). A `DaxqBacktestParityGate` proves the human-reviewed source produces bit-identical signals to the shipped sealed bytecode against a canonical reference dataset.

2. **Headless C# verifier worker** (`platform/src/DaxAlgo.Platform.VerifierWorker`) — compiles one candidate `IBacktestStrategy` against frozen Core/SDK assemblies, enforces source + IL denylists (no `System.*`, reflection, crypto, threading, P/Invoke, `calli`, async-void, finalizers), runs each case twice for determinism, and executes in a collectible `AssemblyLoadContext` or a self-spawned replay child process with emptied environment, time/memory/trace bounds, and result re-hashing. Emits exactly six ordered checks: `source-binding`, `compile`, `analyzers`, `deterministic-execution`, `reference-cases`, `sandbox-policy`. The platform/promotion path consumes a separately signed `csharp-verifier-replay-audit/v1` to avoid shipping a Docker socket into serving-time authority.

---

## 4. Hosted platform (`platform/`)

An ASP.NET Core (net9.0) private backend — a "distribution platform foundation," explicitly *not* a live customer service; production is fail-closed to `Development`/`InMemory`/`Mock`/`Disabled` defaults. Projects: `DaxAlgo.Platform.Api`, `DaxAlgo.Platform.SignalWorker`, `DaxAlgo.Platform.VerifierWorker`.

### Features
- **VibeQuant (Hyperion) coordinator hosting:** credit-reserving job state machine (`VibeQuantService`) with Serializable transactions, fenced worker leases/expiry, cancellation registry, idempotency keys, and exact `specSha256`/readiness checks. Provider dispatch gated by an HMAC-nonce `ReadinessGatedLlmProvider`.
- **Model promotion/readiness:** `VibeQuantModelPromotionVerifier` validates ES256-signed, canonical-JSON promotion envelopes with self-hashing IDs, SPKI-pinned public keys, and exact binding to the pinned serving profile. `VibeQuantModelReadinessService` performs a nonce/HMAC readiness proof against the serving endpoint and fails the API closed when not ready.
- **Billing (Stripe):** canonical plan catalog (Basic `0`, Professional `7900` USD/mo; legacy Intermediate `49` migrated), webhook idempotency inbox with Serializable DB receipt, grace policy (`PastDueGraceDays`), subscription reconciliation worker, and development billing gated in dev only.
- **Marketplace:** source preflight scanner → isolated digest-pinned Docker build worker → scan evidence + **undeclared-capability rejection** → content-key provisioning (A256KW) → quarantine → review (approval requires source + declared-behavior + diff reviewed) → in-toto DSSE attestation → approved artifact store promotion. Ordering/commerce (free vs. Stripe Connect express accounts, fees, payouts), grants/licenses, and revocation.
- **DAXQ licensing:** P-256 device-proof challenges, ECDH + HKDF session key derivation, A256KW content-key wrap, signed run-tokens with heartbeat re-validation, signed download grants, and a monotonic signed revocation feed.
- **Signal sessions (Tier-3):** `ServerSignal` class, HMAC session tokens, WebSocket streaming of Docker-isolated DAXQ run frames (`long/short/flat`, finite strength).
- **Authentication:** dev identity (trusting `X-Dev-Subject`, dev-only) and Google managed identity (manual RS256 JWT, `kid` pinning, JWKS cache/backoff, strict `aud`/`azp`). Real Auth0/OIDC is a documented production blocker.
- **Persistence:** EF model (`PlatformDbContext`) over InMemory or PostgreSQL (`.sql` bootstrap, no EF migrations), with schema-level CHECKs (SHA-256 regex, ISO currency, monotonic revocation sequence) and a `LegacyPlanTierMigration` (Plan 1→2).

### Entitlement licensing
`EntitlementLeaseService` emits 7-day-max offline leases (HMAC dev / software ES256 / Azure Key Vault ES256 P1363), re-checking entitlement after signing to avoid TOCTOU. `MarketplaceLicenseCryptography` implements RFC 3394 A256KW with constant-time integrity and zeroized intermediates; signing and content-wrapping keys are separated and name-enforced.

---

## 5. Free Strategy Workflow (local / BYOK)

`Hyperion.FreeStrategyWorkflow` + `hyperion workflow` CLI reproduce the coordinator's bounded five-role authoring shape while the user supplies their own model (Ollama, OpenAI-compatible, Anthropic, Gemini, custom). It is deliberately **inert**: produces `coordinator-strategy-source/v1` with `RequiresHumanRelease=true`, `RequiresTerminalCompileConsent=true`, `InstallEligible=false`; no compile/test/backtest/install/trade. `maximum initial sources = 58` (6 reserved for repair lineage), `maximum repair rounds = 2`, and a `workflow gauntlet` that reports 8 deterministic process-integrity checks with explicit `SemanticCorrectnessGuaranteed=false` and `CompilationVerification/FunctionalVerification = "not-run-by-free-workflow"`. Provider credentials are env-var names only, never values/endpoints in the run spec (`FreeStrategyExternalProvider` keeps `Endpoint: null`).

---

## 6. Products & research

- **HTT (Hyperion Terminal Transformer, `products/htt`)** — a *prospective* ~1.52B-param decoder-only model (`HTT-1.5B-r0`) for exactly two artifact families (strategy source + visualizer specs). Research-preprint only; explicit "no checkpoint, no results" disclosures; parameter/memory budgets are derived estimates; backtest profit excluded from reward. Delivered as academic preprint and a LaTeX mathematical monograph (29 pages, 92 equations, 56 refs).
- **Hyperion CLI (`products/hyperion-cli`)** — single `hyperion` entry point for hosted ops + local workflow.
- **Expert Model (`products/expert-model`)** — the offline governed training/eval/promotion/serving harness (1,511-line README).
- **Kimi K3 adoption notes (`docs/research/kimi-k3-adoption-notes.md`)** — primary-source review of `arXiv:2607.24653v1` (~2.78T total / 104.2B active params, ~1.42 TiB weights). Concluded as a **research-ideas source**, not a small-cluster student; backbone mechanisms (KDA, Stable LatentMoE, Muon, MoonEP) are equal-compute research only; the harness must never repeat the "2.5× scaling" claim as a local gain (no isolated ablations).

---

## 7. Security & trust model

- **Crypto:** ES256 (P-256) ECDSA, SHA-256, canonical low-S IEEE-P1363, domain-separated length-prefixed preimages, canonical JSON (Disallow unmapped members), constant-time comparisons, zeroized secrets.
- **Detached prepare/sign/finalize** custody seams for every authority family (external KMS/HSM intended; repo supplies protocols, not a deployed KMS/HSM).
- **Signer separation** enforced per family (review receipts ≠ teacher-lineage ≠ authoring-approval ≠ base-selection ≠ trainer-provenance ≠ promotion ≠ replay-audit).
- **Boundaries & non-goals documented honestly:** hashes/signatures prove byte identity and claim-auditability, **not** truth, correctness, reviewer honesty, licence legality, GPU tensor/weight identity, or hardware attestation. Residual limits are explicit: caller-selected image/entrypoint, unattested Docker daemon, path-swap races, no general sandbox claim, no hardware-backed attestation (HMAC/replay audit are operational trust signals).

---

## 8. Build, test, and CI topology

- **Solutions:** `Hyperion.slnx` (main) and `platform/DaxAlgo.Platform.slnx`. SDK pinned to `9.0.305` (root + platform `global.json`).
- **TFMs:** repo default `net9.0-windows7.0` (`UseWPF=false`); coordinator/contracts/FreeWorkflow/Daxq-core and platform are `net9.0`.
- **Build output redirection:** `C:\DaxAlgoBuild\<repo>\...` (off-drive, to avoid filling the small D: drive). DuckDB natives trimmed to `win-x64` only (~313 MB → dead weight otherwise).
- **CI (`.github/workflows/ci.yml`):** two jobs — `dotnet` (windows-latest, restore/build/test `Hyperion.slnx` + `dotnet format --verify-no-changes`) and `python` (ubuntu-latest, Python 3.11, pytest + ruff + compileall + help surface).
- **Tests:** 452 method-level .NET tests across 41 files (208 in the headless Pro suite, 124 platform API, 97 DAXQ, 23 verifier worker) plus 21 orphaned `Tests.Pro/Authoring` methods with no csproj; ~499 Python `unittest` methods (~30k lines), all offline/GPU-free/Docker-free with injected doubles; symlink/inode and optional-dependency paths self-skip. Public submodule has its own CI (build/test, release, NuGet OIDC trusted publishing, template smoke).
- **Verification claims in README (“553 .NET, 494 Python, 113 schemas / 2029 refs”)** include theory case expansions and are not independently re-run by this audit.

---

## 9. Current evidence status (the crux)

**Built & verified in-repo:** coordinator workflows, durable hash-chained state, OpenAI-compatible + replay providers, dataset/review/release gates, retrieval packs, evaluation + promotion evidence, runtime wrappers, detached signing handoffs, hosted API integration, isolated C# verifier, DAXQ closure, and the digest-pinned verifier Docker build.

**Not established (explicitly, everywhere):** a rights-approved training corpus; authenticated per-row review receipts; a real signed base selection/bake-off; a conforming GPU-cluster run (host is GTX 1650 4 GiB / Windows / Python 3.12.6); trained weights / checkpoint; benchmark superiority; production KMS/HSM custody; production deployment. The oldest umbrella task (`2026-07-27-1911-expert-model-coordinator.md`) remains **blocked**; the free-user Terminal plan (`2026-08-06-1134-…`) is **paused** awaiting product approval.

---

## 10. Findings, inconsistencies & recommendations

### Findings
1. **Unusually strong evidence discipline.** Synthetic vs. real material is labeled at every layer; golden test vectors are authored regression fixtures, not production evidence; `test_corpus_quality.py` actively asserts no approved production policy is checked in.
2. **Fail-closed, defense-in-depth security posture** across coordinator, platform, verifier, and DAXQ.
3. **Deliberate inertness** of generated strategy artifacts prevents the coordinator/CLI from ever being an autonomous trading/order path.

### Documentation inconsistencies
- `products/README.md` lists only three products but omits the substantial `products/expert-model/` tree (1,511-line README + full Python harness).
- `products/htt/README.md` references the harness as "under `tools/hyperion-model`" while the actual Python harness is at `tools/hyperion-model` but the `expert-model` product README describes a `hyperion_model` package — path/package-name drift vs. the reorganized layout; the HTT research paper's "Repository sources consulted" cites pre-reorganization paths.
- `schema.sql` allows `execution_class` value `source_open`/`sealed_bytecode`/`restricted_only` that the application only normalizes to `restricted_only`/`server_signal`.

### Risks / blockers (from docs, guide §11 and handbook §20)
1. No real .NET-10-LTS/Auth0-JWT/PostgreSQL atomic-credit/encrypted-object-storage production gates are closed, and "local SQLite/mock/replay success closes none of these by itself."
2. Detached-signing seams are custody integration points only — no KMS/HSM IAM, quorum, audit, rotation/revocation, honest clock, or path-swap protection.
3. Verifier evidence assumes an uncompromised Docker daemon/seccomp/host; no hardware attestation.
4. Kimi K3 licence has notice-retention/attribution conditions that a permission owner must record.

### Recommendations (non-exhaustive)
1. Reconcile the product map so `expert-model` is either listed or explicitly marked internal/private, and refresh stale path references in `products/htt`.
2. Re-verify the "553/494" test counts from a clean CI run before quoting them as current.
3. Treat every "implemented" claim as a contract/validator claim until a conforming training/evaluation/promotion evidence chain exists; keep synthetic fixtures labeled as such.
4. For any real training run, follow the sealed trainer profile (CPython 3.11 / Linux x86_64 / CUDA 12.1, PEP-751 wheel lock) exactly; nothing on the current host establishes conformance.

---

## Appendix — key file references

- Coordinator engine: `src/windows/AI/TradingTerminal.Ai.Coordinator/Orchestration/ResearchCoordinator.cs`
- Durable store: `src/windows/AI/TradingTerminal.Ai.Coordinator/Persistence/SqliteCoordinatorStore.cs`, `ContentAddressedArtifactStore.cs`
- CLI: `src/windows/Tools/Hyperion.Cli/Program.cs`, `CliApplication.cs`
- Free workflow: `src/windows/AI/Hyperion.FreeStrategyWorkflow/FreeStrategyWorkflowRunner.cs`
- Python harness: `tools/hyperion-model/vibe_quant_model/{cli,core,training,promotion,release,csharp_verifier,engine_wrapper,deployment}.py`
- Schemas: `tools/hyperion-model/schemas/` (113 files)
- Platform: `platform/src/DaxAlgo.Platform.Api/{Program.cs,Features/VibeQuant/*,Features/Marketplace/*,Features/Billing/*,Features/Entitlements/*}`
- Verifier worker: `platform/src/DaxAlgo.Platform.VerifierWorker/HeadlessStrategyVerifier.cs`
- DAXQ: `src/windows/AI/DaxAlgo.Daxq.{Contracts,Vm}/`, `src/windows/Tools/DaxAlgo.Daxq.Compiler/`
- Docs: `docs/architecture/hyperion-frontier-architecture.md`, `docs/engineering/hyperion-llm-coordinator-handbook.md`, `docs/research/{kimi-k3-adoption-notes,hyperion-expert-model}.md`
- Records: `tasks/` (16 files)