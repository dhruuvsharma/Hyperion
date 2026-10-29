# Product layout and free strategy workflow
Status: complete

## Goal
Organize the user-facing Hyperion product surfaces into clear homes for HTT, the Hyperion CLI, and a free provider-neutral strategy-authoring workflow that can be called by the Terminal without granting generated source execution authority.

## Decisions
- Use one new top-level `products/` directory so product deliverables do not create several unrelated root folders.
- Add `products/hyperion-cli/` as the product home while retaining the build project at its compatibility-sensitive source path.
- Move the HTT paper source and PDF into `products/htt/research/`; keep the broader model factory in `tools/hyperion-model` because moving it would disrupt established schemas and automation.
- Add `products/free-strategy-workflow/` for the product guide and declarative manifest, with the provider-neutral .NET library under the established `src/windows/AI/` source tree.
- Reuse the fixed five-role strategy prompts, strict artifacts, durable store, and existing `ILlmProvider` boundary. Do not duplicate private Hyperion code into `public/`.
- Keep hosted and local provider authority separate. Local configuration may name a credential environment variable but never stores its value.

## Plan
1. Audit path dependencies and current provider/workflow contracts.
2. Create the product layout and update project/document references.
3. Implement the free strategy workflow library and isolated CLI commands.
4. Run focused and broad checks; document limitations and Terminal integration boundary.

## Blast radius
- Product layout, solution/project references, CLI, coordinator-facing workflow wrapper, tests, and documentation.
- No change to `public/`, hosted billing/credit authority, model-training code, or generated-source execution policy.

## Tests
- New free-workflow unit tests with a deterministic provider.
- CLI config/help and no-secret persistence tests.
- Existing coordinator/CLI tests.
- `dotnet test Hyperion.slnx --no-restore` if focused checks pass.
- Root and `public/` worktree review.

## Findings
- Root clutter was primarily ignored build/render scratch. Existing source, platform, model-harness, and `public/` paths are compatibility-sensitive, so the product-facing reorganization uses one `products/` index instead of disruptive source moves.
- The existing coordinator already supplied the fixed Planner, Evidence Analyst, Critic, Synthesizer, and Risk Judge roles, strict inert strategy artifact, durable hash-chained store, bounded provider calls, and separate start/release approvals.
- Hosted execution remains Professional/credit controlled. The free offering is a local/BYOK workflow and does not create a zero-credit hosted bypass.
- The local provider seam can wrap Terminal-owned native clients without persisting their endpoint or credential secret; the CLI directly supports deterministic mock and HTTPS/loopback OpenAI-compatible endpoints.
- Restart review identified a persisted-approval failure window. `workflow start` is now idempotent for Ready/Running runs, and provider mismatch is rejected before approval state changes.

## Diff summary
- Added product homes for HTT, Hyperion CLI, and the Free Strategy Workflow; moved the HTT paper source/PDF under `products/htt/research/` and removed the obsolete root `output/` namespace.
- A later repository-organization task brand-aligned the internal CLI project path to
  `src/windows/Tools/Hyperion.Cli/Hyperion.Cli.csproj` without changing its legacy namespace,
  assembly identity, commands, or wire contracts.
- Added `Hyperion.FreeStrategyWorkflow`, its exact versioned manifest, external provider adapter, durable workspace, free-profile enforcement, and fail-closed artifact loading.
- Added isolated `hyperion workflow` init/create/start/status/show/release commands, explicit remote-data-egress consent, environment-only secret lookup, mock rehearsal, and restart-safe execution.
- Added manifest/profile, approval, provider mismatch, hosted-boundary, integrity, CLI configuration/help, and end-to-end mock lifecycle tests.
- Updated the repository map, coordinator guide, engineering handbook map, and product documentation.

## Verification
- `dotnet restore Hyperion.slnx`: passed.
- Focused free-workflow/CLI suite: 23/23 passed.
- `dotnet test Hyperion.slnx --no-restore`: 553/553 passed. One earlier allocation-sensitive test failed once under concurrent verification, then passed in isolation and in two complete reruns.
- `python -m pytest tests`: 494 passed, 5 expected Windows capability skips.
- `python -m ruff check .`: passed.
- `python -m ruff format --check .`: 47 files already formatted.
- `git diff --check`: passed; only line-ending conversion notices were reported.
- `public/` worktree: clean.

## Risks / deferred
- Full Terminal UI wiring is outside this standalone repository; this task provides a stable library/CLI boundary and inert artifact contract for that integration.
- Third-party provider quality and charges remain the user's/provider's responsibility; free refers to the workflow, not external inference.
- Local workspaces and CLI review output contain plaintext user/model content and require private storage, log protection, and user-directed retention.
- Visualizer authoring, automatic compile/fix, and HTT training remain separate future work. Compiler feedback must start a new hash-bound workflow run.
