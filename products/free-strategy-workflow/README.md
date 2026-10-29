# Free Strategy Workflow

The illustrated system paper is available as
[Hyperion Free CLI Agentic Workflow](../../output/pdf/hyperion-free-cli-agentic-workflow.pdf).

See the [draft Terminal integration plan](planning/terminal-integration-plan.md) for the proposed free-user
Guided Agent Team experience, provider policy, delivery phases, and acceptance criteria.

The Free Strategy Workflow gives Basic/free Terminal users the same bounded five-role authoring
shape used by Hyperion while allowing a model client they already control. It does not include HTT's
future weights, efficiency, calibration, retrieval pack, or quality guarantees.

"Free" means Hyperion charges no workflow credits and requires no Professional AI entitlement for
this local path. A remote provider may still charge the user. Local Ollama can use a loopback
OpenAI-compatible endpoint without a provider key.

## Workflow

1. **Planner** turns the brief into a bounded strategy specification.
2. **Evidence analyst** extracts only supplied SDK, quantitative, and risk constraints.
3. **Critic** challenges invented APIs, lookahead, unsafe behavior, and weak controls.
4. **Synthesizer** emits a complete inert C# strategy draft.
5. **Risk judge** approves, requests revision, or rejects the exact draft.

The engine is durable: SQLite stores a hash-chained run record and a content-addressed store keeps
role and strategy artifacts. Provider calls are bounded by request, token, byte, time, and declared
cost budgets.

## Provider boundary

The library at `src/windows/AI/Hyperion.FreeStrategyWorkflow` accepts any `ILlmProvider` through the
versioned `external-adapter/v1` local profile. This is the Terminal integration seam for an existing
Anthropic, installed-agent-CLI, or other provider client. Endpoints and credentials remain owned by
the caller and are excluded from the run specification.

The CLI exposes pinned profiles for local Ollama, OpenAI, OpenRouter, Groq, Mistral, DeepSeek,
Anthropic, and Gemini. Anthropic Messages and Gemini `generateContent` use dedicated native
adapters; the other named remote profiles use their pinned OpenAI-compatible origins. An explicitly
enabled custom OpenAI-compatible profile is also available. Each remote profile fixes its protocol,
origin, authentication scheme, and dedicated credential slot so a config cannot redirect one
provider's key to another origin.

The pinned OpenAI profile uses the constrained Chat Completions compatibility adapter and rejects
o-series model IDs; a native OpenAI Responses adapter is not implemented. Choose a model compatible
with the selected route rather than assuming every vendor model shares one wire format.

Creating a remote-provider config requires explicit data-egress consent because the brief and every
supplied source are sent to that provider. Users must review the provider's retention, training-use,
region, and pricing policy themselves.

## Authority boundary

The workflow has no browser, filesystem, compiler, package, broker, order, or execution tool. Its
result is `coordinator-strategy-source/v1` with exact hashes and these fixed properties:

- `deliveryState = inert-source/v1`;
- `requiresHumanRelease = true`;
- `requiresTerminalCompileConsent = true`;
- `installEligible = false`.

Start approval binds the exact run specification. Release approval binds the exact final artifact.
The Terminal must still show the source, obtain compile consent, compile through its own restricted
authoring pipeline, and apply its existing registration consent. Compiler diagnostics require a new
hash-bound workflow run; repaired bytes never inherit an earlier approval.

## Local data handling

The local workspace contains the brief, supplied sources, role outputs, approvals, and generated
source in plaintext SQLite and content-addressed files. CLI review commands also emit reviewed
specifications or artifacts to standard output. Use a private workspace outside a source checkout,
protect terminal/CI logs, and remove the workspace according to the user's retention choice. The
provider endpoint and credential environment-variable *name* are hash-bound in OpenAI-compatible
runs; the credential secret value is never written to the config, run, workspace, or output. A live
HTTP response that echoes the exact configured secret into completion text or request identity is
rejected before persistence.

An embedding Terminal owns equivalent storage, log-redaction, retention, and remote-data-egress
consent before it constructs an `external-adapter/v1` provider.

## CLI flow

```text
hyperion workflow init   --config workflow.json --profile mock
# Or use a local OpenAI-compatible model:
hyperion workflow init   --config workflow.json --profile ollama --model MODEL
# Or a pinned remote provider (set its documented DAXALGO_LLM_* variable before start):
hyperion workflow init   --config workflow.json --profile anthropic --model MODEL `
  --input-price PRICE --output-price PRICE --allow-provider-egress
hyperion workflow create --config workflow.json --workspace PATH --brief brief.md --source sdk=SDK.md
hyperion workflow start  --config workflow.json --workspace PATH --run RUN_ID --spec SHA256 --actor USER
hyperion workflow gauntlet --config workflow.json --workspace PATH --run RUN_ID
hyperion workflow show   --config workflow.json --workspace PATH --run RUN_ID
hyperion workflow release --config workflow.json --workspace PATH --run RUN_ID --artifact SHA256 --actor USER
```

The mock profile provides a network-free rehearsal. A named remote profile requires positive
declared prices and `--allow-provider-egress`; set its fixed `DAXALGO_LLM_*` variable before
`workflow start`. A custom origin additionally requires `--allow-custom-provider` and receives an
origin-derived credential variable that cannot be selected for another origin. The config never
contains the secret itself. See [workflow.v1.json](manifests/workflow.v1.json) for the distributable
workflow manifest.

`workflow gauntlet` checks the durable event chain, exact start approval, complete role artifacts,
Risk Judge approval, final-artifact lineage, and inert authority flags. It deliberately reports
compilation and functional verification as not run. When human review, the Risk Judge, or a later
Terminal compiler finds a defect, `workflow revise --run PARENT_ID --request FILE [--diagnostics
FILE]` creates a fresh lineage-bound run. At most two repair rounds are allowed and each needs new
start and release approvals. Initial runs reserve six of the 64 source slots for this lineage. A
repair is rejected before creation if inherited evidence plus the exact parent outputs and repair
inputs exceed the bounded source-context limits.

After an unclean process exit, repeat the exact `workflow start` command while the run remains
`Ready` or `Running`. It resumes the same hash-bound run instead of creating a second approval or
run. Explicit cancellation is terminal.

## Explicit limitations

- This slice generates strategies only; the proposed HTT visualizer IR remains research work.
- Model quality depends on the selected provider and supplied evidence.
- The bounded revision loop does not compile or execute code; deterministic compiler/test repair
  remains a future Terminal-owned gate with separate consent.
- A crash after remote dispatch but before durable completion can leave provider billing ambiguous;
  bounded recovery is conservative but cannot promise exactly-once behavior without provider support.
- Full Terminal UI wiring is a consumer of the library and is not present in this standalone repo.
- The local workflow is not a zero-credit hosted service and does not change hosted entitlements.
