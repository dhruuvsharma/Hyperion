# Hyperion coordinator operator and data guide

Hyperion is a private hosted workflow with two versioned purposes. Legacy Vibe Quant names remain
where they are part of a signed wire contract or compatibility surface.
Research turns a bounded brief and fixed reference sources into a reviewable decision memo. The
strategy-authoring purpose turns the same bounded inputs into an untrusted, inert C# source
artifact. Mock authorizes that purpose for rehearsal; Live requires a signed hosted-policy v2
capability bound to the exact execution model, policy, workflow, and prompt catalog. The desktop
calls the private platform API, the platform owns the provider
connection and integer-credit ledger, and a durable worker runs approved jobs asynchronously. The
desktop never supplies a provider endpoint or key and is never the authority for identity,
entitlement, budgets, credits, job state, or artifacts.

It is deliberately not an autonomous trading agent. Neither purpose has tools, browser, shell,
compiler, plugin loader, market connection, broker access, or order path. Strategy artifacts cannot
be installed or executed and still require the Terminal's separate explicit compile consent.

> **Implementation status — 2026-07-28:** the repository now has the hosted API, account-scoped
> integer-credit module, server execution adapter, isolated HTTP client, and remote CLI. It is not
> production-available: identity is development-only; run rows have expiring fenced leases and
> heartbeats, but no production outbox, poison handling, or multi-instance PostgreSQL proof; and run
> execution still uses server-local SQLite/filesystem storage. Mock, live-adapter, replay, and dataset
> mechanics are private development infrastructure, not a customer deployment model. Hosted-policy
> v1 remains Research-only; v2 can authorize only the exact inert StrategyAuthoring profile. No real
> v2 production promotion or remotely authenticated Terminal deployment exists.

## 1. Hosted safety and workflow contract

The fixed workflow is:

1. `Planner` decomposes the objective and identifies evidence gaps.
2. `EvidenceAnalyst` derives findings from the supplied sources.
3. `Critic` challenges assumptions, causality, leakage, bias, and feasibility.
4. `Synthesizer` writes the research memo or, only for the strategy purpose, a bounded multi-file C# draft.
5. `RiskJudge` returns `Approve`, `Revise`, or `Reject` after reviewing that exact output.
6. An authenticated human approves the exact final memo or inert source artifact before the run becomes
   `Completed`.

Every role must return one `coordinator-role-output/v1` JSON object. The strategy Synthesizer alone
must additionally return the strict source draft. Only after Risk Judge approval does the server
derive `coordinator-strategy-source/v1`, binding the objective, evidence IDs, role artifacts, file
paths, file hashes, inert delivery state, and required consent flags. Claims cite only IDs from the
submitted source set. The model is instructed to treat source content as untrusted data and ignore
embedded instructions; this is not a prompt-injection boundary. Review source packs and keep every
model output untrusted. Model-written code remains inert text.

Two authenticated human gates are mandatory:

- Start approval binds the exact server-created run specification SHA-256, including objective,
  source hashes, server-selected provider/model and budgets, policy/workflow versions, credit
  reservation ceiling, and deterministic prompt-catalog hash. The reviewer must inspect that server
  client-reviewable specification and echo its `spec_sha256`; a mismatched or stale hash is rejected.
- Release approval binds the exact final artifact SHA-256. Changing the artifact or specification
  requires a new approval; an approval is never transferable between runs.

The product lifecycle is:

1. The desktop obtains an Auth0 access token and the platform resolves its subject to a canonical
   account with a current Professional entitlement.
2. `GET /api/v1/vibe-quant/credits` returns the server-owned integer balance and policy version.
3. `POST /api/v1/vibe-quant/runs` accepts the objective, bounded source pack, optional purpose, and an idempotency key.
   The server assigns the run, account, provider, model, budgets, versions, maximum credit
   reservation, and immutable specification hash.
4. The customer reads the safe, client-reviewable specification and approves that exact hash through
   `POST /api/v1/vibe-quant/runs/{run_id}/start`.
5. In one serializable PostgreSQL transaction the platform rechecks entitlement and policy, reserves
   whole credits without allowing a negative available balance, records the approval, and enqueues a
   durable job. The API returns `202 Accepted`; it does not run inference on the request thread.
6. A platform worker leases the job, records heartbeats and invocation dispatch boundaries, uses the
   server-owned provider credential, and checkpoints role outputs. The desktop polls
   `GET /api/v1/vibe-quant/runs/{run_id}` or reconnects later.
7. Cancellation records durable intent; the worker observes it between calls and cancels an active
   request when the provider supports cancellation. It is not represented as an instant undo.
8. The current foundation charges only confirmed successful role outputs and releases the rest.
   Ambiguous/provider failures cost the customer zero; a production policy change requires durable
   dispatch evidence, reconciliation, a new pricing-policy version, and explicit review.
9. The customer reads the synthesized artifact through its run-scoped SHA-256 route, verifies the returned
   SHA-256, and approves that exact hash through the release endpoint.

Artifact retrieval before release is the human-review preview. The bytes do not prove approval by
themselves. The Terminal consumer requires `Completed` status, the matching final artifact hash, and
the exact human release before source-only import; compilation remains a separate local-consent step.

These routes are implemented in the development API. Create and administrative grants require an
`Idempotency-Key`; start/release/cancel are currently exact-hash/state idempotent. Production must
persist idempotency for every mutation. Account and actor identity
come only from validated access-token claims and server-side roles. Request DTOs do not accept
customer-provided `owner`, `actor`, provider URL, provider key, secret-variable name, replay path,
model price, credit charge, or internal prompt text.

The worker revalidates stored policy, workflow, provider-adapter, and prompt-catalog versions before
dispatch. A deployment must either drain incompatible jobs or route them to a compatible worker;
silently rendering an approved specification with new instructions is forbidden. The catalog hash
includes the renderer format and structural tokens, and runtime and approved evaluation export use
the same LF-normalized renderer.

Production authorization is server-side. Role policy decides whether the same account may perform
both gates or whether separation of duties is required; every decision records the authenticated
account, subject, role, reason, correlation ID, specification/artifact hash, policy version, and time
in an append-only audit trail.

The state path is normally:

`AwaitingStartApproval → Ready (queued) → Running → AwaitingReleaseApproval → Completed`

Other terminal or intervention states are `NeedsRevision`, `Rejected`, `Cancelled`, `Failed`, and
`BudgetExhausted`. Insufficient credits return HTTP `402`. None silently continues; an authenticated
operator inspects the durable run and creates a corrected run where appropriate. Model-written code
remains inert text throughout.

## 2. Hosted persistence and integer credits

The production module owns six kinds of durable state:

| Authority | Production record |
|---|---|
| Identity and access | Canonical account, Auth0 issuer/subject, Professional entitlement, roles, and policy version |
| Run specification | Objective, source-object hashes, server-selected model/budgets, workflow/prompt versions, maximum credit reservation, and specification SHA-256 |
| Job execution | PostgreSQL job lease, attempt, heartbeat, cancellation request, invocation boundary, usage, safe failure, and idempotency keys |
| Credits | Append-only integer grants, reservations, settlements, releases, expiries, adjustments, and balance projection |
| Artifacts | Immutable encrypted object, opaque ID, media type, byte length, SHA-256, retention class, and access audit |
| Review | Start/release decisions bound to exact hashes, authenticated actor, reason, policy version, correlation ID, and timestamp |

PostgreSQL is authoritative for workflow state, job leasing, credit movements, and audit references.
Encrypted immutable object storage holds source packs, role outputs, and final artifacts. The database
does not embed provider credentials or large source/artifact bodies. Every object read is account
scoped and hash verified; short-lived grants never make the object store an authorization authority.

Customer credits are non-negative integers. They are a versioned product allowance, not provider
tokens, money, or a displayed conversion from provider USD cost. Provider price and measured token
usage remain private operational data used for policy, margin, abuse control, and reconciliation.
Credits enter the ledger only through idempotent server grants backed by an entitlement, verified
commerce event, or reasoned administrative adjustment; a customer request cannot mint them.
The projected invariant is:

`available = granted + net_adjustments - expired - active_reserved - spent`

No API accepts a client-calculated balance or charge. Run creation spends nothing. Start approval
atomically reserves at most the server-declared maximum; a duplicate idempotent approval returns the
original result and cannot reserve twice. Settlement converts part or all of that reservation into a
final whole-credit charge by moving it from `active_reserved` to `spent`, and the remainder returns
to `available`. The ledger never permits a negative
available balance. Expiry, refunds, goodwill adjustments, and administrator corrections are explicit
ledger movements with reason codes rather than edits to historical rows.

Before each provider request the worker checks both the approved run budget and remaining reservation.
After a response it records provider-reported usage plus conservative locally observed bounds. The
current development policy bills confirmed successful role outputs only and refunds failed or
ambiguous dispatches. Customer cancellation stops future dispatch but cannot erase provider work.
Before production, durable dispatch receipts and reconciliation must define any stricter ambiguity
policy; discrepancies must alert an operator and never silently rewrite financial history.

Every provider attempt can receive the objective, source pack, and earlier role outputs. Production
therefore requires explicit upload rights for the complete payload, encryption in transit and at rest,
region and retention controls, deletion/export procedures, subprocessor disclosure, and access logs.
Customer runs are never training data by default. Training eligibility follows the separate consent
and dataset-rights process in sections 6–9.

## 3. Implemented development slice: hosted API and client

The repository now follows the hosted boundary in code:

- `TradingTerminal.Ai.Coordinator.Contracts` contains platform-neutral workflow types, hashing, and strict JSON.
- `TradingTerminal.Ai.Coordinator.Client` contains safe DTOs and the bounded HTTP client; it has no SQLite or provider-engine reference.
- `DaxAlgo.Platform.Api` owns Professional authorization, provider policy, account-scoped runs, integer credits, and asynchronous execution.
- `TradingTerminal.Ai.Coordinator` is the private server execution engine.
- `DaxAlgo.Coordinator.Cli` is the `hyperion` entry point: hosted-API and offline dataset commands
  retain the hosted boundary, while `workflow` uses a separate local config/workspace for the free
  inert strategy workflow.
- `Hyperion.FreeStrategyWorkflow` composes the fixed roles, provider boundary, durable store, and
  hash-bound approvals locally without hosted credits or execution authority. Its process gauntlet
  verifies exact lineage and authority flags, and its bounded revision contract creates at most two
  fresh repair runs with fresh approvals; neither path compiles or executes source.

This is still a development foundation, not a customer deployment. Development identity headers, an
in-process polling worker, and per-run server-side SQLite/filesystem artifacts remain. Production
requires Auth0, reviewed PostgreSQL migrations, leased jobs, object storage, KMS/secrets,
reconciliation, rate limits, telemetry, and a supported .NET 10 LTS closure.

Build the named closures from the repository root:

```powershell
dotnet build platform/DaxAlgo.Platform.slnx
dotnet build TradingTerminal.Pro.slnx
```

For a local rehearsal, run the platform on loopback in Development, then initialize the client:

```powershell
dotnet run --project platform/src/DaxAlgo.Platform.Api/DaxAlgo.Platform.Api.csproj --urls http://127.0.0.1:5080

$demoRoot = Join-Path (Get-Location) 'tmp\vibe-quant-demo'
hyperion init --config "$demoRoot\coordinator-client.json" `
  --server http://127.0.0.1:5080 --auth development --subject local-reviewer
```

When invoking from source, replace `hyperion` with:

```powershell
dotnet run --project src/windows/Tools/Hyperion.Cli/Hyperion.Cli.csproj --
```

`init` refuses to overwrite its config and creates example brief, source, and dataset files. Its
configuration contains only the platform origin and authentication mode:

```json
{
  "schemaVersion": "vibe-quant-client/v1",
  "serverBaseUrl": "http://127.0.0.1:5080",
  "authentication": {
    "mode": "development",
    "accessTokenEnvironmentVariable": null,
    "developmentSubject": "local-reviewer",
    "developmentEmail": "local-reviewer@development.invalid"
  }
}
```

Development headers work only on loopback. Bootstrap the profile, assign a current Professional
subscription, and grant test credits through the server-side workflow in the
[platform README](../../platform/README.md). The CLI cannot mint credits or choose a provider.

A future production config uses `--auth bearer --server https://<platform-origin> --token-env
DAXALGO_PLATFORM_ACCESS_TOKEN`. That dedicated variable holds a short-lived platform token, never an
LLM-provider credential.

## 4. Hosted development workflow

The implemented prefix is `/api/v1/vibe-quant`. The normal sequence is:

```powershell
$config = "$demoRoot\coordinator-client.json"
hyperion credits --config $config
hyperion create --config $config `
  --brief "$demoRoot\coordinator-examples\brief.md" `
  --source "observation=$demoRoot\coordinator-examples\source.txt" `
  --idempotency-key demo-run-001
hyperion spec --config $config --run <RUN_ID>
hyperion approve --config $config --run <RUN_ID> --gate start --spec <SPEC_SHA256>
hyperion status --config $config --run <RUN_ID>
hyperion show --config $config --run <RUN_ID> --artifact <FINAL_SHA256>
hyperion approve --config $config --run <RUN_ID> --gate release --artifact <FINAL_SHA256>
```

Add `--purpose strategy` for a Mock rehearsal or a Live deployment whose signed promotion carries
the exact hosted-policy v2 strategy capability; research remains the default.
`create` returns a safe immutable specification. It contains source metadata and content hashes, not
source bodies; verify those hashes against the submitted files. Inspect the credit ceiling,
policy/model profile, and opaque execution-profile binding. `run` performs create plus start
approval and queues server work; it never executes locally or approves release. Poll `status`; there
is no desktop-facing `resume` command.

| Command | Hosted effect |
|---|---|
| `credits` | Read available, reserved, and consumed credits plus pricing-policy version. |
| `create` | Submit a bounded brief/source pack and optional `research` or signed-policy-authorized `strategy` purpose; provider and credit authority are rejected. |
| `spec` | Read the safe specification and exact start-approval hash. |
| `approve --gate start` | Echo the specification hash and reserve the declared maximum. |
| `status` | Read safe state, role progress, credits, and artifact hash. |
| `list` | List up to 100 runs owned by the authenticated account. |
| `show` | Download and verify the artifact run, role, schema, and SHA-256. |
| `approve --gate release` | Bind release to the exact final artifact hash. |
| `cancel` | Record cancellation; dispatched provider work is not an instant undo. |

Start, release, and cancel are state/hash-idempotent in this single-service foundation. `create` and
administrative grants additionally require `Idempotency-Key`. Production must persist idempotency
for every mutation and require optimistic versions before multi-instance rollout.

The client rejects inconsistent JSON, verifies source/run/artifact hashes, caps create requests at
8 MB, and caps responses at 4 MB. A brief is limited to 20,000 characters; each source to 500,000;
one run to 64 sources and 2,000,000 aggregate source characters. URI and licence metadata are
separately bounded. Input is strict UTF-8.

Start atomically moves the quoted maximum from available to reserved. The current policy bills only
confirmed successful role outputs using provider-reported usage and the tariff frozen at creation;
unused credits return to available. Authentication failures, rate limits, invalid output, and
ambiguous failures charge the customer zero while the platform absorbs uncertain cost. Durable
dispatch receipts and reconciliation are required before changing that ambiguity policy.

## 5. Server provider boundary, internal engine, and language choice

Only the server worker contacts an LLM provider. Endpoint, credential binding, prices, timeout, live
secret, and egress policy stay internal. The public specification exposes a safe provider/model
profile, operational limits without USD cost, a whole-credit ceiling, policy versions, and a
nonce-keyed opaque execution-profile binding. The full internal spec has a separate private hash.

The engine supports deterministic mock, strict replay, and an OpenAI-compatible adapter for internal
tests. SQLite, filesystem artifacts, replay fixtures, and provider adapters are server-side
development mechanics for hosted runs. Hosted CLI config never contains provider keys, endpoints,
prices, workspaces, owners, or approval actors. The separate local free-workflow CLI provides fixed
profiles for Ollama, OpenAI, OpenRouter, Groq, Mistral, DeepSeek, native Anthropic Messages, and
native Gemini `generateContent`, plus an explicitly enabled custom OpenAI-compatible route. A remote
profile binds its official origin, protocol, authentication scheme, declared prices, and dedicated
credential environment-variable *name*; it never stores the credential value, uses hosted credits,
or changes hosted policy. Custom origins receive slots containing the canonical origin's full
SHA-256. Successful responses that echo the configured secret into persisted text or request
identity are rejected. The OpenAI profile uses the Chat Completions compatibility route and rejects
o-series models; a native Responses route remains deferred. Remote provider use requires explicit
data-egress consent, and HTTP redirects, cookies, ambient credentials, and system proxies are
disabled.

Live development mode also requires a server-owned serving-profile path and exact raw-file SHA-256.
Hosted-policy v1 authorizes Research only. Hosted-policy v2 additionally requires one closed
`StrategyAuthoring` capability binding the promoted execution-model ID and exact inert
policy/workflow/prompt-catalog tuple. Missing, null, additional, or tampered capability identities
fail closed; changing the policy invalidates promotion, readiness, and queued execution bindings.
Startup validates the strict profile, candidate/runtime compatibility, and derives the internal
`daxalgo-expert-sha256-<profile-hash>` model ID; a configured mutable alias is rejected. The public
specification exposes only the reviewed profile name. A separate private readiness client sends a
fresh nonce and requires a hash-private HMAC proof bound to the profile, adapter metadata/tree, and
execution model. The helper also revalidates the live rights-reviewed training release and exact SFT
binding before issuing a proof. The cached proof expires: start approval, worker claim, and every
provider dispatch fail closed while it is absent or stale, before customer credits can be consumed.
Health exposes only availability. Production must protect the dedicated attestation key and add
DNS/egress allowlisting or mTLS. The model-server side still needs a trusted engine-owning wrapper
that validates and rehashes the exact read-only artifact before and after engine load; the supplied
Python helper must not be exposed by an unrelated sidecar. HMAC proves possession by that trusted
wrapper, not hardware state.

The coordinator remains C# because this is orchestration and account infrastructure, not model
training. Workflow contracts, hashes, cancellation, ASP.NET Core, EF transactions, entitlements, and
credits already share one typed .NET runtime. Python would add another deployment, RPC/auth boundary,
duplicated schemas, and hash-parity risk without improving the provider API calls.

Python is appropriate for offline evaluation, fine-tuning, tokenizer experiments, or a stateless
specialist worker. Such a worker must not own identity, entitlements, credits, approvals, or the
authoritative run ledger.

## 6. What “training” means

For the first release, training means evaluating and improving the workflow:

- prompts and role instructions;
- source selection and retrieval;
- structured-output validation;
- policy and budget settings;
- model/provider choice; and
- human review rubrics.

It does not mean online learning, autonomous self-modification, or base-model training. Optional
supervised fine-tuning or preference optimisation comes later, only if a stable benchmark shows a
repeated error that prompt, retrieval, tool-schema, or evaluator changes do not fix. Start with a
small router or critic rather than a base model. Re-run the sealed Arena before promoting any tuned
candidate.

Customer runs are never training data by default and the production job worker must not feed them
into an evaluation or training corpus. User prompts and strategy code can be confidential even when
they contain no API key. Any later fine-tuning corpus needs specific opt-in consent, redaction,
tenant separation, provider-compatible rights, lineage, and a documented retention/revocation and
derived-model response path. Do not collect or export hidden chain-of-thought; use approved task
inputs, typed decisions/tool calls, final artifacts, critiques, corrections, and expert labels.

The coordinator does not train model weights during a hosted run. A separate Pro-private offline
harness can perform reviewed QLoRA-SFT and seal a safe inference artifact; it never runs by default,
downloads a model, uploads private data, or promotes its own output. If evaluation justifies tuning:

1. Freeze the Arena version and keep calibration/sealed jobs out of training.
2. Complete independent row review, issue the detached ES256 receipt set, and use `expert-dataset
   export-sft` with `--receipt-set`, `--receipt-public-key`,
   `--receipt-public-key-spki-sha256`, `--receipt-audience`, `--receipt-key-id`, and
   `--receipt-signer-role`; add `--local-only` only for a trainer that never uploads the file.
   Structural dataset/SFT validation alone cannot authorize export or consumption.
3. Freeze the rights-bearing corpus, receipt set and externally pinned trust identity, exact SFT,
   calibration/sealed tasks, inert rubrics/verifiers, task lineage, and declarative approval evidence
   with `vibe-quant-model create-release` (release v2). Treat the release hash as identity, not as
   proof that a licence claim or reviewer identity is truthful. Receipt validity is at most 366 days;
   issue a newly reviewed receipt set and release after expiry rather than editing an immutable one.
4. Create the hash-bound offline bundle with an exact candidate commit and reviewed chat template;
   train only from its immutable private snapshots on an approved GPU.
5. Seal only the safe PEFT/safetensors adapter and tokenizer files. Reject checkpoints, pickle,
   custom code, links, unknown files, and any adapter or chat-template binding that differs from the
   manifest.
6. Compare the candidate with the unchanged baseline on calibration, then once on the sealed Arena;
   reject it on any critical safety failure even if its average score improves.
7. Derive the evaluation serving profile from the sealed artifact and original manifest, then capture
   responses through its content-addressed execution ID. A production registry must separately bind
   the signed promotion evidence and model-server startup attestation.
8. Register the accepted model and internal provider economics in a reviewed server-side provider
   policy, deploy a compatible worker, and create a new run/start approval. Never mutate an approved
   run to point at tuned weights, and never expose its endpoint or credential to the desktop.

## 7. Evaluation dataset contract

The private Vibe Quant Arena should begin with 25–40 complete jobs. A balanced 32-job release is:

- 6 research/evidence jobs;
- 8 strategy generation or repair jobs;
- 8 experiment/backtest-design jobs;
- 5 risk/governance jobs; and
- 5 interruption, retry, and operations jobs.

Each job needs a locked source pack, allowed-capability policy, budget, expected artifact schemas,
deterministic checks, expert rubric, critical-failure rules, and provenance. Use an expert-only and a
single-agent baseline alongside the coordinator. Run stochastic candidates at least three times and
report track-level scores, critical failures, latency, token/cost use, and uncertainty—not P&L alone.

Dataset rows are role-level examples, not whole jobs. One five-role Arena job can contribute up to
five rows only after each reference output is separately reviewed and rights-cleared; all rows from
that job remain in the same contamination group and split.

`coordinator-dataset/v1` is newline-delimited JSON. Its exact example fields are:

| Field | Meaning |
|---|---|
| `schemaVersion` | Exactly `coordinator-dataset/v1`. |
| `id` | Stable, unique, non-semantic example ID. |
| `split` | Exactly `development`, `calibration`, or `sealed`. |
| `contaminationGroup` | Shared strategy, document/company, instrument/window, template, or generated-variant family. |
| `role` | One implemented coordinator role. |
| `objective` | Prompt objective for that role. |
| `sources` | Zero or more source assets, using the exact nested fields below. |
| `priorOutputs` | Earlier validated role outputs supplied to this role; empty for `Planner`. |
| `referenceOutput` | Approved `coordinator-role-output/v1` object for the same role and known source IDs. |
| `requiredConcepts` | Concepts a scorer expects the answer to cover. |
| `forbiddenConcepts` | Concepts whose presence indicates an error or prohibited claim. |
| `provenance` | Human-readable origin and transformation trail for the example. |
| `license` | Dataset/example licence or internal agreement reference. |
| `rights` | Example-level `mayStore`, `mayEvaluate`, `mayTrain`, `mayUploadToProvider`, and `mayRedistribute`. |
| `reviewStatus` | Must be `approved` for a valid release. |
| `cutoffUtc` | Point-in-time cutoff used to exclude later information. |
| `useForTraining` | Explicit training opt-in; valid only on `development`. |

Each item in `sources` has exactly `id`, `title`, `content`, `provenance`, `license`,
`retrievedAtUtc`, nullable `availableAtUtc`, nullable `uri`, and `rights`. The rights object has
exactly `mayStore`, `mayEvaluate`, `mayTrain`, `mayUploadToProvider`, and `mayRedistribute`.
`availableAtUtc` is the time the information could actually have been known; it is not interchangeable
with a reporting-period or event date. It is required for calibration and sealed rows and may be null
only in development data where point-in-time availability is genuinely inapplicable.

Every `priorOutputs` item and `referenceOutput` uses this exact nested shape: `schemaVersion`, `role`,
`summary`, arrays `claims`, `risks`, `recommendations`, and `sourceIds`, plus `decision`. Each claim
has `statement`, `evidenceSourceIds`, and numeric `confidence` from 0 through 1. Use the emitted enum
names (`Planner`, `EvidenceAnalyst`, `Critic`, `Synthesizer`, `RiskJudge`; and `None`, `Approve`,
`Revise`, `Reject`). `priorOutputs` must be the complete ordered workflow prefix before the row's
role. Copy the generated `coordinator-examples/dataset.jsonl` as the safest authoring template rather
than composing JSON from memory.

The intended internal dataset-maintenance commands are:

```powershell
hyperion dataset validate --input "$demoRoot\arena\release.jsonl"
hyperion dataset export-sft --input "$demoRoot\arena\release.jsonl" --output "$demoRoot\out\sft.jsonl"
hyperion expert-dataset export-sft --input <reviewed-expert-dataset.jsonl> `
  --output <expert.sft.jsonl> `
  --receipt-set <review-receipts.jsonl> --receipt-public-key <reviewer-public-key.pem> `
  --receipt-public-key-spki-sha256 <64-lowercase-hex> --receipt-audience <review-audience> `
  --receipt-key-id <review-key-id> --receipt-signer-role <independent-reviewer-role>
```

The fixture created by `init` is a schema/template check, not training data: it has
`useForTraining=false` and no provider-upload right. An export therefore legitimately contains
zero rows until a separately reviewed development example explicitly opts in and carries the
required rights.

`dataset validate` currently fails on an unsupported schema, missing required values, duplicate
example/source IDs, invalid splits, non-approved review status, training flags outside development,
missing example/source storage or evaluation rights, requested training without example/source
training rights, future cutoff/retrieval timestamps, a source unavailable at the cutoff, an invalid
prior-output role/order/schema/source citation, an invalid reference-output role/schema/source citation,
the same objective plus source-content multiset across splits (independent of source IDs and order),
or a contamination group crossing splits. It does not yet detect
near-duplicates, secrets, personal data, licence expiry, chronological market overlap, or semantic
leakage; those remain mandatory release-review checks.

Validation uses strict UTF-8 and caps one JSONL input at 100 MB, 100,000 non-empty examples,
2,000,000 characters per line, and 10,000 reported issues. Each example also uses the run source
ceilings of 64 sources, 500,000 characters per source, and 2,000,000 aggregate source characters.

`requiredConcepts` and `forbiddenConcepts` are rubric inputs for an external Arena scorer; this CLI
only validates that their arrays exist and does not score or enforce their contents.

`dataset export-sft` re-runs validation and emits only examples that are approved development data,
set `useForTraining=true`, and have `mayTrain=true` on both the example and every source. An export
intended for an external provider additionally requires `mayUploadToProvider=true` on the example
and every source by default; one eligible row without that right fails the whole export before output
is written. Pass `--local-only` only for an offline local trainer to waive that upload-right check.
Validation, rights checks, and emitted rows all use one parsed input snapshot, so replacing the source
file during export cannot substitute different rows between those phases.

The separate `expert-dataset export-sft` path also requires one active authenticated receipt per
dataset row, in exact order, verified against the externally pinned public-key/SPKI/audience/key/role
trust policy. Receipt-derived training authorization must agree with the row's approved development
state and training rights. Provider export additionally requires receipt-derived provider-upload
authorization as well as provider-upload rights on the example and every source.
Reconcile the printed exported count and final file hash against the approved release manifest.
Output is JSONL containing `messages` (`system`, `user`, `assistant`) plus metadata
`id`, `contaminationGroup`, `cutoffUtc`, `sourceSchema`, `policyVersion`, `workflowVersion`, and
`promptCatalogSha256`. The
exported system/output contract is shared with the executable prompt catalog to reduce
training/serving drift.
The SFT output is LF-normalized, written through a temporary file, and capped at 100 MB; a failed
validation, rights check, cancellation, or size check leaves any existing destination unchanged.

The exporters do not redact, obtain consent, resolve licence ancestry, or create a corpus release.
Inputs must already be sanitized and lawfully approved. For the expert exporter, a valid receipt
authenticates the stated decision and exact bytes, not the underlying legal or semantic truth. Treat
exported JSONL as a sensitive derived artifact: bind expert output to a separately reviewed release-v2
identity and other output to its reviewed manifest/hash. A successful training export does not grant
redistribution; sharing still requires `mayRedistribute=true` through the full lineage. The generic
exporter atomically replaces its requested output, while the expert exporter refuses to overwrite an
existing destination; both reject using the input path as output.

## 8. Splits and leakage control

For a 32-job Arena, use 18 development, 6 calibration, and 8 sealed jobs. With so few tasks,
publish confidence intervals and per-task outcomes rather than treating one aggregate score as
precise. Keep every related variant in one split by grouping on task family, strategy/template,
source document and company, instrument, and time window. Never tune prompts, select models, or fit
thresholds on sealed results. Rotate contaminated tasks into development and refresh a portion of the
sealed set on a declared cadence.

Market experiments need a separate chronological split discipline:

- create expanding walk-forward development folds;
- purge examples whose labels extend across a boundary;
- use a purge of at least the maximum label horizon plus completeness grace and execution latency;
- add a lookback embargo where raw feature windows overlap;
- fit scalers, clipping, thresholds, and feature selection on each training fold only; and
- touch one later outer holdout once, after the recipe is frozen.

Public finance benchmarks can detect regressions but are not trustworthy sealed tests because they
may appear in model pre-training. External providers can also contaminate a private benchmark unless
their no-training/retention terms cover the submitted tasks.

## 9. Source acquisition and rights

The example and every source carry the five on-wire booleans `mayStore`, `mayEvaluate`, `mayTrain`,
`mayUploadToProvider`, and `mayRedistribute`, alongside `license` and `provenance` strings. Set each
example boolean to the most restrictive value inherited from every parent asset. The external source
register must additionally retain the raw-byte SHA-256, agreement ID, attribution, permitted
transformations, territory, expiry/revocation, and deletion obligations; those details are not yet
first-class dataset fields. Revocation or expiry invalidates descendants even when an older JSONL row
still says `true`.

Practical source examples:

| Source | Appropriate use and constraint |
|---|---|
| [SEC EDGAR APIs and filings](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) | No API key; public filing content is reusable. Identify the client, stay at or below SEC's current 10 requests/second limit, and retain accession plus acceptance/retrieval time. |
| [US Treasury Fiscal Data API](https://fiscaldata.treasury.gov/api-documentation/) | Open for commercial and non-commercial reuse. Pin endpoint/version, record date, retrieval time, and raw hash. |
| [ECB SDMX 2.1 Data Portal](https://data.ecb.europa.eu/help/api/overview) | Cite ECB, reproduce accurately, disclose transformations, and review third-party series/paid-product notices. |
| [FRED/ALFRED API](https://fred.stlouisfed.org/docs/api/terms_of_use.html) | API key required; rights are series-specific. Allowlist reviewed series and retain real-time/vintage fields rather than using revised “latest” data. |
| [TAT-QA](https://github.com/NExTplusplus/TAT-QA) | Dataset is CC BY 4.0 and code is MIT; retain attribution. Use as a public regression set, not a sealed benchmark. |
| [FinQA](https://github.com/czyssrs/FinQA) | MIT repository over public financial reports; public and previously affected by a documented leakage bug. Supplementary regression only. |
| Databento `GLBX.MDP3` or `XNAS.ITCH` | Named candidates for a one-source commercial market pilot. Obtain the applicable exchange entitlement and written rights for retention, internal evaluation, ML training, derived weights, provider upload, geography, and deletion. Do not redistribute raw data without an express licence. |
| RavenPack or LSEG machine-readable news | Named point-in-time news candidates only when a task truly needs news. Contract separately for article/event retention, ML use, provider upload, derived artifacts, and redistribution; do not infer those rights from terminal access. |

Broker credentials, a paid subscription, or a keyless public endpoint do not automatically grant
training, provider-upload, or redistribution rights. Do not scrape publisher news. If news becomes a
required modality, procure a point-in-time commercial source with explicit raw-text/event and ML
rights.

## 10. Market data is a separate evidence class

Synthetic data is sufficient to test coordinator state, prompts, schema compliance, retries, policy,
and reproducibility. Real market data is required only to claim economic validity. Start with one
licensed instrument/source pilot; add markets only when the task requires generalisation.

A causal market-data manifest must identify at least:

- instrument and venue;
- event, ingest/receive, and availability timestamps;
- source and source-connection epoch;
- native and canonical sequence/trade/order identifiers where available;
- event type and quote/trade/depth fields, including aggressor semantics;
- corrections, resets, drops, and approximate-time flags;
- instrument metadata, tick/contract/session-calendar versions;
- shard byte length and SHA-256; and
- licence/entitlement, permitted uses, retrieval/capture host, and transform revision.

OHLCV or L1 is enough for tasks that use only those modalities. L2/MBO and full news text are not
general coordinator prerequisites. Conversely, a single-timestamp tick file with no source epoch,
sequence, availability clock, side semantics, or completeness proof is not made train-ready by
putting it in Parquet.

Economic evaluation must add corporate actions or futures rolls, realistic spreads, fees, slippage,
latency, fill assumptions, capacity, and negative results. Use cost-adjusted out-of-sample evidence
and multiple-testing controls; never optimise the coordinator against headline P&L alone.

## 11. Production isolation, blockers, and promotion

The signed Live capability authorizes hosted inert source generation only. It grants no compilation,
installation, execution, broker access, live-order, or release authority. Generated-code compilation,
strategy loading, hostile-code backtests, unrestricted tools, plugin registration, and broker/order
capabilities remain deferred. The existing in-process authoring smoke test is not an isolation
boundary: a timeout can leave a runaway task inside the host process.

Before any autonomous experiment feature is enabled, compilation and execution must move to a
restricted disposable worker with bounded CPU, memory, wall time, filesystem, and no network by
default. Only declared, hashed artifacts may leave that worker. Release remains human-approved, and
live orders remain outside this coordinator's authority.

The hosted product remains **no-go** until all of these blockers have closure evidence:

1. The platform and relevant client closure run on supported .NET 10 LTS and pass upgrade,
   dependency, installer, and clean-environment qualification.
2. Auth0 JWT validation, issuer/audience pinning, canonical account mapping, Professional
   entitlement checks, server-side roles, and authenticated audit actors replace all development
   identity labels.
3. PostgreSQL migrations provide atomic integer-credit reservation/settlement, idempotent commands,
   a durable job queue, SKIP LOCKED-style leasing, heartbeats, cancellation, retries, recovery, and
   version-compatible rolling deployments.
4. Encrypted object storage provides tenant-scoped immutable sources/artifacts, hash verification,
   retention, deletion/export, backup/restore, access audit, and short-lived access grants.
5. Provider credentials and endpoints live in a production secret manager or workload identity with
   restricted egress, rotation, redaction, and provider-usage reconciliation; no client-supplied key
   or bring-your-own-provider product path exists.
6. Per-account and global rate limits, request/source/artifact ceilings, abuse controls, integer-credit
   policy/versioning, spend caps, and operational kill switches are tested fail-closed.
7. Logs, metrics, traces, queue-age/heartbeat alerts, credit/provider reconciliation, SLOs, pager
   ownership, incident runbooks, and privacy-safe support diagnostics are operating in staging.
8. Arena schema, rights, consent, split, leakage, sealed-set, and SFT-export tests pass; customer runs
   remain excluded from training unless a separately governed dataset row explicitly opts in.
9. Start approval and release approval bind exact server hashes, and no App, broker, market-data,
   compiler, backtest, plugin, or order dependency has entered the coordinator closure.

Local SQLite, mock, live-adapter, and replay success is useful development evidence for the workflow
engine, but it closes none of these hosted-service gates by itself.
