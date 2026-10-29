# SDK impact review for the free agentic workflow

Status: complete

Date: 2026-08-08

## Objective

Review the updated public SDK and related shared-core changes against the implemented Hyperion Free
Strategy Workflow. Identify required compatibility changes, recommended hardening, and unaffected
areas without modifying the pinned `public/` submodule or the current implementation.

## Scope

- Compare the pinned public commit with the current public remote commit using an isolated,
  read-only temporary Git database.
- Trace SDK and authoring-contract changes into workflow sources, prompts, strategy artifacts,
  downstream compiler assumptions, documentation, and focused tests.
- Run non-mutating compatibility checks where practical.
- Do not access any external Terminal working tree and do not implement fixes during this review.

## Findings

### Reviewed SDK state

- Hyperion still pins `public/` at `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05`; the worktree is clean.
- Read-only remote inspection found public `main` at
  `a87ad803e27f6fa99a341261b38bf782e3362993`.
- The new public surface ships `DaxAlgo.Sdk` `0.3.0`, `DaxAlgo.Templates` `0.3.0`, the
  `daxalgo-sandbox-authoring/1` machine contract, `DaxAlgo.Sdk.IStrategyKernel`,
  `DaxAlgo.Sdk.IVisualizer`, capability-scoped contexts, `DAX3001`, a non-relaxable Sandbox IL scan,
  and sandbox strategy/visualizer templates.
- NuGet lists both `DaxAlgo.Sdk` and `DaxAlgo.Templates` `0.3.0`. The SDK package contains its analyzer
  under `analyzers/dotnet/cs/`; the template package contains both sandbox templates. The public guide
  still says `0.3.0` is unpublished and is now stale on that point.
- Canonical JSON for the documented Hyperion machine contract has SHA-256
  `f78efbf01b52151112e71d3fa09df37a48e9c448c9e9a35a179b66c1cbb50379` under the review's sorted,
  separator-free JSON canonicalization. Hyperion must specify its canonicalization before binding it.

### Required before new runs claim SDK 0.3.0 compatibility

1. **Adopt the public pin deliberately.** The two public project paths referenced directly by
   Hyperion remain present at the remote commit, but the current pinned checkout does not contain the
   new authoring contract or analyzer. Updating the parent submodule pointer is separate implementation
   work; no source may be changed inside `public/`.
2. **Version the generation profile instead of mutating v1.** Current new runs bind
   `free-strategy-authoring-inert/v1`, `fixed-free-strategy-authoring/v1`, prompt hash
   `bb79...db0b`, artifact `coordinator-strategy-source/v1`, and compiler profile
   `terminal-authored-strategy/v1`. Existing run hashes and persisted artifacts depend on those values.
   Add a new sandbox strategy workflow/policy/prompt/artifact/compiler profile and retain v1 readers.
3. **Bind a trusted authoring contract.** Today an SDK is merely an optional user source; zero-source
   runs are valid, and every source is rendered as untrusted data. New runs need an immutable trusted
   profile containing contract ID, package, version, contract hash, unit kind, template/scaffold
   profile, analyzer ID, and allowed capability surface. It should be separate from the 58 user-source
   allowance and hash-bound to the specification and portable artifact.
4. **Rewrite the role contract and prompt catalog.** The Synthesizer currently receives only “complete
   inert C# source.” The SDK requires a strategy implementing `DaxAlgo.Sdk.IStrategyKernel`, declared
   `StrategyParameterSchema` and `StrategyDataRequirement`, `OnStartAsync`, only consumed callbacks,
   `context.Clock`, instance-local mutable state, `IMarketDataView`, `IParameters`, virtual-book target
   intents, mediated bounded alerts, and no forbidden API/host wiring. Risk and critique prompts must
   inspect those exact constraints while remaining advisory. The prompt hash and workflow version must
   change together.
5. **Replace the legacy mock fixture.** `DeterministicMockLlmProvider` emits `IBacktestStrategy` with
   `Contract`, `IOrderRouter`, order events, and tick callbacks. That is not the new SDK contract and
   includes authority the sandbox deliberately removes.
6. **Version the artifact/handoff.** The current artifact records generic `.cs` files and
   `terminal-authored-strategy/v1`, but not the SDK contract/version/hash or unit kind. SDK 0.3.0 also
   requires at least one direct public-interface unit test. Use a fixed trusted scaffold and distinct
   source/test file roles or arrays; do not feed test files into the legacy `StrategyScript` compilation
   list and do not ask the model to generate project files.
7. **Wire the downstream Terminal gate to the real sandbox controls.** Keep compiler execution outside
   the model loop, but exact intake must select SDK 0.3.0, require an analyzer-clean build (`DAX3001`),
   run the direct tests, apply `PluginPolicyScanProfile.Sandbox`, and then continue through the already
   designed functional/property/sandbox/registration gates. Process integrity must continue to say
   compilation and functional verification were not run by the free workflow.
8. **Treat an SDK upgrade as a new root run.** Repair intentionally inherits the parent's non-repair
   sources and provider profile byte-for-byte, and the CLI has no source replacement on `revise`.
   Preserve this property: an SDK/profile change invalidates compatibility and requires `create`, not
   a repair child with inherited approvals.
9. **Type and bind compiler diagnostics used for repair.** Replace arbitrary repair text with a
   structured envelope that identifies the parent artifact, SDK/compiler/analyzer profile, and exact
   diagnostics. This preserves the existing immutable repair lineage while preventing diagnostics
   from an unrelated build or SDK profile from being treated as authoritative.

### Recommended follow-up

- Add a separate versioned visualizer workflow or explicit `unitKind`; do not silently broaden the
  current strategy artifact. The new `IVisualizer` has no book, auto-runs, and needs a different output
  and test contract. This can replace the current documentation statement that visualizer authoring is
  only research once implementation exists.
- Extend the process gauntlet's versioned profile/lineage checks to include the authoring-contract and
  scaffold hashes. Do not represent the Risk Judge as an analyzer or formal verifier.
- Add compatibility tests for trusted contract injection, user override rejection, prompt hashing,
  SDK/profile drift, new-root enforcement, source/test separation, a safe SDK 0.3.0 fixture, `DAX3001`
  failure fixtures, Sandbox IL rejection, and exact Terminal handoff.
- Refresh the workflow README, manifest, integration plan, gauntlet design, and illustrated PDF only
  after the new executable contract is implemented.

### Unaffected foundations

- BYOK provider profiles and secret handling.
- Serial five-role scheduling, request/token/byte/time/cost limits, retry ceilings, and cancellation.
- Hash-chained SQLite state, content-addressed artifacts, exact start/release approvals, and fresh-run
  repair lineage.
- The no-model-tools boundary and the honest semantic/non-profitability guarantee boundary.
- The legacy DAXQ/expert-model compiler can remain a separately versioned path; it should not be
  silently redefined as the new SDK 0.3.0 sandbox compiler.

## Verification

- `git -C public status --short`: clean.
- `git ls-remote` confirmed remote public `main` at `a87ad803...`; the comparison was performed in an
  isolated OS-temporary bare repository and worktree, without moving the pinned submodule.
- Both Hyperion direct public project references exist at the remote commit.
- Remote SDK analyzer/policy tests: passed, 98 tests.
- Remote sandbox strategy/visualizer sample tests: passed, 2 tests.
- Current Hyperion workflow/provider/CLI focused suite: passed, 59 tests against the pinned public
  commit. This establishes the existing baseline, not SDK 0.3.0 integration.
- No implementation, manifest, documentation, or submodule change was made by this review.
