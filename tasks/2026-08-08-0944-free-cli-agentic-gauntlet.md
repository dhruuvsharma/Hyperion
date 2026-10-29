# Free CLI agentic gauntlet
Status: complete

## Goal
Evolve the existing local/BYOK strategy CLI from a fixed five-role generation pass into a
provider-portable, evidence-grounded workflow whose output is never presented as verified unless it
passes deterministic gates. Research current agent-loop patterns first, then implement the smallest
safe foundation for bounded critique, repair lineage, and additional user-owned provider APIs.

## User outcome
- Free users can supply a provider API key through a dedicated environment variable and generate
  inert Terminal strategy source without consuming hosted Hyperion credits.
- The CLI explains what was checked and refuses to claim 100% semantic correctness, profitability,
  or safety from probabilistic model review alone.
- Failed review or later compiler diagnostics can seed a new, hash-bound repair run without
  inheriting the parent run's approvals.

## Boundaries
- Keep `public/` pinned and read-only.
- Do not modify or inspect any external Terminal repository.
- Never persist, print, hash, or place provider secret values into a run, artifact, error, or log.
- Generated source remains inert. Compilation, registration, backtesting, installation, and trading
  remain separate explicit authorities.
- Preserve hosted policy, entitlements, credits, signing, and wire compatibility.

## Plan
1. Compare ReAct, Reflexion, Self-Refine, tree search/LATS, debate, deep-research, test-and-repair,
   and validation-gauntlet patterns using primary sources.
2. Audit the existing free-workflow, CLI provider boundary, role state machine, and tests.
3. Implement a bounded repair-lineage and deterministic gauntlet foundation plus the first native
   BYOK provider adapters that fit the existing authority boundary.
4. Add focused conformance/security/lifecycle tests and update product/CLI documentation.
5. Run focused and broad checks, review both worktrees, and record deferred Terminal compiler work.

## Initial research decision
Use ReAct only as the outer state-machine shape, Reflexion-style diagnostics only as ephemeral input
to a new repair run, and external deterministic gates as the acceptance oracle. Self-critique,
multi-agent debate, deep-research fan-out, and tree search do not establish correctness by themselves
and are not default paths. Cap repairs now; repeated diagnostic-fingerprint and no-improvement stops
belong to the future Terminal-owned deterministic verifier.

## Implemented
- Added `workflow gauntlet`, which verifies the event chain/profile, exact approvals, every role CAS
  artifact, approving Risk Judge output, reproducible final source, and inert authority flags. Its
  report explicitly says compilation, functional behavior, and semantic correctness were not proven.
- Added `workflow revise`, which creates at most two fresh runs from exact parent outputs, a reviewed
  change request, and optional diagnostics. Loaded lineage recursively cross-checks the actual parent
  run, sources, provider, role artifacts, decision, final hash, root objective, and depth.
- Added pinned BYOK profiles for Ollama, OpenAI-compatible providers, native Anthropic Messages, and
  native Gemini `generateContent`. Built-in origins/auth slots are fixed; custom origins use a full
  SHA-256-derived secret slot; redirects, proxies, cookies, and ambient credentials are disabled.
- Added exact-secret echo rejection, native finish-reason normalization, Gemini thinking-token
  accounting, protocol mismatch rejection, and an explicit OpenAI o-series incompatibility guard.
- Added the primary-source comparison and implemented/deferred architecture in
  `products/free-strategy-workflow/planning/agentic-gauntlet-design.md`.

## Deferred and honest limits
- No probabilistic loop can guarantee 100% correct, profitable, or safe strategy code. Compilation,
  deterministic tests, property/metamorphic checks, and sandbox execution remain Terminal-owned work
  after separate consent.
- Native OpenAI Responses support is deferred; the current OpenAI Chat Completions profile rejects
  o-series models documented as incompatible with its bounded request shape.
- Provider capability fingerprints, a run-bound egress/rights receipt, hardened app-local workspace
  lifecycle, and diagnostic-fingerprint/no-improvement stops remain Terminal integration work.
- A crash after remote dispatch but before durable completion may leave external billing ambiguous;
  exactly-once provider execution requires provider-backed idempotency evidence.

## Verification
- `dotnet test Hyperion.slnx --no-restore`: passed, 576 tests.
- Final task-focused provider/workflow/CLI/dataset tests: passed, 59 tests.
- Scoped `dotnet format` completed; `git diff --check` passed.
- `workflow.v1.json` parsed successfully after the final edits.
- `python -m ruff check .`: passed.
- `python -m ruff format --check .`: passed (47 files already formatted).
- `python -m pytest tests`: attempted twice; the broad untouched Python suite produced no failure
  output but exceeded both the 120-second and 300-second command limits, so it is not claimed green.
- `git -C public status --short`: clean; no shared-core source change.
