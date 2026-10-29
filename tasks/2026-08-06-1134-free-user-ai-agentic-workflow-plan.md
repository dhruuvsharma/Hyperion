# Free-user AI agentic workflow plan
Status: paused

## Goal
Define the free-user Terminal experience that integrates Hyperion's local/BYOK five-role strategy
workflow with existing provider setup and the editable strategy workspace, while preserving exact
approval, data-egress, compile, registration, and execution boundaries.

## Assumption
- Interpret the user's “ali” as “AI”. The plan will cover the Terminal UI and CLI fallback as part
  of that experience; adjust the label if the user intended a different acronym.

## Scope
- Product journey, state model, architecture, provider eligibility, context/evidence assembly,
  storage and privacy, safety gates, evaluation, delivery phases, and acceptance criteria.
- Strategies only for v1. Visualizer generation and HTT model training remain separate work.
- Planning artifacts only in this task; do not implement Terminal or provider changes yet.

## Boundaries
- `public/` remains pinned and read-only. Reuse its contracts from a private integration layer; do
  not copy Hyperion code into it.
- Do not alter hosted entitlement, credit, provider, or signing authority.
- Free means local/BYOK with no Hyperion workflow credits; third-party inference may cost money.
- Generated output remains inert until exact release, import, separate compile consent, policy scan,
  and registration consent.

## Plan
1. Audit existing authoring, provider, context-pack, coordinator, storage, and handoff seams.
2. Design one free-user flow shared conceptually by Terminal UI and the diagnostic CLI.
3. Define v1/v2 provider policy, security and privacy rules, evaluation gates, and phased delivery.
4. Publish the draft product/technical plan for user approval before implementation.

## Current findings
- Hyperion already has a durable local five-role runner, exact start/release approvals, inert source
  artifact, mock/OpenAI-compatible CLI path, and an application-owned external-provider seam.
- The pinned public core already has a mature direct-chat strategy builder, context/skill packs,
  local/API/installed-CLI providers, compile/auto-fix, and a provider-neutral `ImportDraft` seam.
- The guided Hyperion workflow should be an additional governed mode, not a duplicate of the direct
  chat loop. It should import released source into the same editor without compiling automatically.
- The extracted private Terminal shell sources are reference-only here and are not part of a
  buildable project in `Hyperion.slnx`; downstream UI wiring must be planned separately.
- The public direct-chat provider contract is codegen-specific and its session compiles/auto-fixes;
  it must not be used as the five-role model boundary. A text-only adapter is required.
- Installed Claude/Codex-style CLIs are not v1-eligible: the existing launcher inherits process
  context and does not prove a no-tools authority profile. A separate constrained provider host is
  required before those routes can enter the guided workflow.
- The desktop host also needs progress/cancellation, run listing, Risk Judge access, retention/purge,
  an adapter/configuration fingerprint, and a run-bound remote-egress/rights receipt.

## Draft deliverable
- Added `products/free-strategy-workflow/planning/terminal-integration-plan.md` with the recommended product
  modes, user journey, architecture/state diagrams, component boundaries, provider policy, context
  contract, privacy/cost controls, evaluation gates, phased roadmap, acceptance criteria, and product
  decisions for approval.
- Linked the draft from the Free Strategy Workflow product guide.

## Verification
- Three independent read-only audits covered Terminal integration seams, provider/process boundaries,
  and free-tier evaluation/privacy/cost requirements.
- Draft sections, product-guide link, and Markdown whitespace were checked successfully.
- `git diff --check` passed with only existing line-ending conversion notices.
- `public/` worktree remained clean. No code or runtime behavior changed, so no new test run was needed
  for this planning-only slice; the preceding implementation task remains verified at 553 .NET and
  494 Python tests.

## Risks / decisions awaiting approval
- Confirm whether “ali” meant AI, UI, CLI, or another product term.
- Decide the first supported remote provider set after the provider-capability and no-tools policy is
  approved.
- Recommended v1 is loopback plus remote OpenAI-compatible BYOK; native Anthropic follows its own
  adapter conformance, and installed agent CLIs wait for the constrained provider host.
- Recommended UI label is `Guided Agent Team · Free · use your own AI`.

## Pause note
- Paused at the user's request on 2026-08-06 so repository folder organization can be completed
  before workflow planning continues. The draft remains intact and unapproved.
