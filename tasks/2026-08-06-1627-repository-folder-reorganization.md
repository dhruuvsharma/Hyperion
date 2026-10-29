# Repository folder reorganization
Status: complete

## Goal
Make the standalone Hyperion repository easy to navigate by organizing product deliverables, private
source, manifests, planning documents, and generated scratch without changing wire identities,
hosted authority, or the pinned shared core.

## Boundaries
- `public/` is pinned and read-only.
- Preserve existing dirty/user work and all legacy namespaces, assembly identities, signed schema
  IDs, and wire identifiers.
- Do not access or modify any external Terminal repository.
- Prefer reference-safe path moves over namespace or product refactors.
- Remove only confirmed generated scratch; preserve ambiguous ignored content.

## Plan
1. Inventory top-level/product/source/test/scratch folders and every reference to candidate paths.
2. Select the smallest coherent target layout and record the move map.
3. Move files/directories, update project/solution/docs/test references, and clean confirmed scratch.
4. Run focused and full checks, audit both worktrees, and document preserved/deferred items.

## Initial findings
- The root already has sensible category folders; most visible clutter is ignored build/scratch data.
- Product guides are separated under `products/`, but the manifest and integration plan can be grouped
  more clearly and the CLI source still uses a legacy DaxAlgo path despite producing `hyperion`.
- The free-workflow source path is already product-named and should not be moved without a concrete
  navigation benefit.

## Approved move map
- `src/windows/Tools/DaxAlgo.Coordinator.Cli/` → `src/windows/Tools/Hyperion.Cli/` and
  `DaxAlgo.Coordinator.Cli.csproj` → `Hyperion.Cli.csproj`; preserve assembly and namespaces.
- `products/free-strategy-workflow/workflow.v1.json` → `manifests/workflow.v1.json`.
- `products/free-strategy-workflow/terminal-integration-plan.md` →
  `planning/terminal-integration-plan.md`.
- Promote the unique HTT PDF builder from ignored scratch to
  `products/htt/tools/build_research_paper.py`, bound to the canonical product source/PDF paths.
- Keep `Hyperion.FreeStrategyWorkflow`, coordinator, verifier, platform, model-harness, tests, and
  dated task records in their established locations.

## Verification
- `dotnet restore Hyperion.slnx` passed, and `dotnet sln Hyperion.slnx list` resolves the renamed
  `src/windows/Tools/Hyperion.Cli/Hyperion.Cli.csproj` project.
- Focused CLI/free-workflow boundary tests passed: 23/23.
- `dotnet test Hyperion.slnx --no-restore` passed: 553/553.
- The promoted PDF builder parses, passes Ruff, and passes Ruff formatting; the relocated workflow
  manifest parses as JSON and all canonical product files exist.
- `git diff --check` passed and the stale-path scan found no references outside this task's recorded
  historical move map.
- `git -C public status --short` is clean.

## Cleanup
- Sent 718 MiB across 15 confirmed generated directories to the Windows Recycle Bin: `tmp/`, local
  platform `bin`/`obj` outputs, and Python/Ruff caches.
- Preserved the only reusable scratch artifact by promoting the HTT PDF builder before cleanup.
- Did not touch the pinned `public/` worktree or generated outputs outside this repository.

## Result
- Product-facing deliverables now have a single navigation map under `products/`.
- The CLI source path and project filename are Hyperion-branded while compatibility-sensitive
  assembly output, namespaces, commands, and wire identifiers remain unchanged.
- Free-workflow manifests and planning documents are grouped by purpose, and HTT research contains
  separate canonical research and tooling directories.

## Risks / deferred
- Broadly reparenting coordinator, platform, verifier, or model-harness projects would create a large
  compatibility/CI/Docker blast radius and is not justified solely by visual cleanliness.
- Generated handbook DOCX/PDF siblings were not refreshed; the canonical Markdown handbook is the
  updated source of truth for the new path map.
