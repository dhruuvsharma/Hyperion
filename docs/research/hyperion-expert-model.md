# Hyperion expert model: research, training, and serving plan

Date: 2026-07-27; updated 2026-07-31
Status: implementation in progress; checkpoint training has not yet run

Hyperion is the product and repository name. Legacy Vibe Quant identifiers remain in signed schemas,
routes, persisted records, and compatibility code where changing them would invalidate evidence.

## Decision

Build a verified expert-model portfolio, not an autonomous trading oracle and not one model forced
to perform every role. The canonical target design is
[`docs/architecture/hyperion-frontier-architecture.md`](../architecture/hyperion-frontier-architecture.md).

The first student bake-off should compare:

1. `Qwen/Qwen2.5-Coder-7B-Instruct` and `Qwen/Qwen2.5-Coder-14B-Instruct` for the strongest practical code-first baseline.
2. `openai/gpt-oss-20b` for a reasoning-heavy, memory-efficient alternative.

The frozen four-model production catalog remains the first controlled bake-off. In parallel, maintain
a challenger registry spanning practical Qwen3/Qwen3-Coder models, Qwen3.5-9B, Devstral Small 2,
Falcon-H1-34B, gpt-oss-20b, and hardware-appropriate successors. Use a domain-calibrated council of
hosted or downloadable frontier teachers—including GPT-5.6, Gemini, Claude, Kimi K3, Qwen, DeepSeek,
GLM, Llama, MiniMax, and gpt-oss-120b candidates—rather than granting one teacher universal
authority. Payment, gating, custom licensing, and separately negotiated permission are acquisition
metadata managed by the user; they are not architectural exclusions.

Treat verified teacher-output SFT as a small calibration-gated pilot, not an assumed improvement:
competent coding students can regress under answer imitation. If it passes, test DPO; if executable
C#/numeric work stalls, compare RLOO and GRPO with compiler, tests, numerical oracles, and risk
invariants. Introduce on-policy/multi-teacher distillation only when authorised probabilities or
logits exist. Do not begin with full-parameter training, raw backtest-return rewards, undisclosed
teacher internals, or autonomous code execution.

The production shape is:

```text
signed-in Terminal
    -> private Platform API and credit reservation
    -> explicit C# coordinator state machine
    -> private, versioned DaxAlgo retrieval pack
    -> small coding expert
    -> compiler + tests + analyzers + risk invariants
    -> bounded repair loop
    -> larger-model fallback when gates fail
    -> exact-artifact human approval
```

Stable skills belong in the weights: C#, quantitative mathematics, probability and statistics, finance, risk, portfolio construction, and WPF/MVVM reasoning. Mutable or proprietary facts belong in retrieval: current DaxAlgo APIs, project topology, symbols, policies, examples, and edition boundaries. This limits stale architecture knowledge and reduces private-code memorisation risk.

## What exists now

| Capability | Current state |
|---|---|
| Hosted coordinator | Implemented: private, fixed Planner -> Evidence Analyst -> Critic -> Synthesizer -> Risk Judge workflow. |
| Server credits | Implemented: authenticated account ledger, reservation, confirmed-usage settlement, refund, and tenant isolation. |
| Provider boundary | Implemented: bounded mock/replay and OpenAI-compatible server inference. |
| Local strategy builder | Implemented separately under `public/`: local/BYOK codegen with compile/fix/smoke loops. It is intentionally not the hosted coordinator. |
| Expert corpus | Implemented foundation: separate rights-aware, domain-labelled chat examples, lineage/content hashes, deterministic draft checks, hash-bound row review, coverage reporting, receipt-gated SFT export, and immutable release-v4 corpus/evaluation releases. Each release binds exact tasks, expected values, lineage, context packs, rubrics, verifiers, declarative release evidence, a detached authenticated review-receipt set, and a separately signed evaluation-authoring approval with external trust and no downstream authority. Current receipt v2 and SFT metadata v2 carry the exact source-corpus and freshly rederived row-evidence SHA-256 identities; release v4 requires their homogeneous pairing. When the corpus contains `OpenWeightTeacher` rows, release v4 additionally bundles and revalidates the exact independently signed teacher-lineage admission. Legacy v1 receipts/SFT plus release v3 remain Python archival validation only for corpora whose every row is `HumanAuthored`; they cannot return a downstream authorization identity. Each receipt uses an independently pinned ES256 P-256 reviewer identity and binds one exact row plus its derived authorizations; author-controlled task and domain labels cannot bypass either gate. A provider-neutral prepare/sign/finalize handoff now keeps the receipt private key outside the model tool: its unsigned bundle binds the exact source corpus, approval evidence, optional lineage admission, trust tuple, ordered v2 payloads, raw signature preimages, and SHA-256 digests; the external signer authorizes only finalization by signing both a domain-separated exact-bundle preimage and every row preimage. Finalization accepts externally produced DER or P1363 signatures, canonicalizes low-S, revalidates all inputs, and emits the unchanged receipt-v2 wire format. The evaluation-authoring approval now has a separate provider-neutral prepare/sign/finalize path: its content-addressed non-authorizing bundle carries the exact existing payload, unsigned envelope fields, trust tuple, raw preimage, and digest; one external DER/P1363 signature is sufficient because the approval envelope itself covers every material inventory, validity, authority, and trust field. Finalization freshly rederives the complete live inventory and emits the unchanged approval-v1 wire. These are custody integration seams, not KMS/HSM provisioning, signer-identity, review, suite-correctness, or sealed-custody attestations. No production corpus rows, approval, or signing service exists yet. |
| Teacher candidate capture and admission | Implemented foundation: a development-only manifest selects the pinned open-weight teacher, binds runtime/chat-template/source/prompt identities, requires several unique seeds and aggregate budgets, and sends source-grounded prompts only to a literal-loopback endpoint. A passive runtime workflow first derives the exact plan fragment from bounded descriptor/template/catalog bytes, then requires an already-open vLLM server to report the derived execution ID, reviewed version, root string, and context limit before creating an `unattested-observation` binding. Manifest-v2 capture requires and freshly revalidates that binding before tokenization and after generation, records its exact file hash on every candidate, and still enforces exact prompt reservation and completion-usage agreement before atomic publication. An independent custodian derives a hash-only deny-set from the exact calibration/sealed task artifacts; a separate selector then admits at most one candidate per task using every exact conversation prefix, every normalized user turn, contamination-family fingerprints, and exact held-out task/context/verifier asset hashes. Materialization emits a self-contained immutable OpenWeightTeacher draft package whose record remains explicitly unsigned. A separate low-S ES256 lineage authority now revalidates one exact package, manifest-v2 runtime observation, reviewer evidence, and final reviewed corpus; it signs the ordered stable teacher subjects and authorizes only receipt issuance. A provider-neutral prepare/finalize handoff exposes the exact raw admission-envelope preimage and its SHA-256 digest to an external signer, accepts DER or P1363, normalizes valid high-S signatures, and emits the unchanged admission-v1 wire without loading a private key. Its unsigned bundle grants no authority, while a valid bundle/signature pair is admission-equivalent sensitive material. Receipt creation, C# SFT export, release v4, and downstream consumers require the independent admission and receipt signers together. No real candidates or admission have been issued. |
| Offline training harness | Implemented foundation: strict cross-platform SFT validation, four exact upstream commits, hash-bound QLoRA run bundles, private training snapshots, staged/no-clobber outputs, GPU gates, safe PEFT/safetensors inference packages, and a manifest-bound PEP 751 wheel lock for CPython 3.11/Linux x86_64/CUDA 12.1. Non-smoke training requires a release-bound manifest v3 carrying an independently signed ES256 base-model selection v2 and a separately trusted signed exact-corpus admission, plus a distinct externally pinned trainer signer. The corpus admission has a provider-neutral prepare/sign/finalize seam over its unchanged admission-v1 wire. Trainer provenance now has its own post-training detached seam: training can publish only an unsealed pending safe-inference tree plus an external artifact core and content-addressed non-authorizing bundle; the bundle exposes the unchanged provenance-envelope raw preimage and SHA-256 digest, an external signer returns DER or fixed P1363, and finalization freshly replays the live release/receipt/authoring/selection/corpus/snapshot/trainer chain and pending tree before installing the unchanged artifact-v2 wire. Neither unsigned handoff is authority, while each valid bundle/signature pair is replayable exact finalization material. Manifest v1 and selected manifest v2 remain explicit-smoke only. Candidate artifact v2 embeds a low-S ES256 provenance envelope over the exact artifact core/tree, manifest, release, selected model, dataset, and environment; it is revalidated immediately before and after no-clobber installation. Legacy artifact v1 remains structurally parseable but cannot enter candidate serving or promotion. No real admission, selection, trainer key, run bundle, or training run exists yet. |
| Artifact, promotion, and serving identity | Implemented foundation: canonical adapter/tree/manifest identities, strict safe-file validation, candidate-aware runtime profiles, shared Python/C# golden profiles, content-addressed execution IDs, and a dedicated ES256 production-promotion record. The raw-base path separately compiles an approved per-file source lock, rehashes the complete local snapshot, rejects executable/custom-code and unsafe model shapes, and derives an evaluation-only base profile without fabricating LoRA provenance. Candidate profile creation and capture reauthenticate active trainer provenance before every transport and before publication. Promotion retains one validated manifest snapshot, reauthenticates selection plus trainer trust, separates the trainer from upstream/promotion signers, enforces artifact <= trainer issue <= trainer activation <= approval <= promotion issue, and caps authority at the earliest receipt, teacher-lineage, authoring, audit, or trainer expiry. Engine-wrapper v7 carries an explicit nullable teacher-lineage trust beside trainer, authoring, and audit custody and periodically revalidates the full activation; v1-v6 remain parseable but cannot launch. It still launches the promoted LoRA from the opened executable inode and exact snapshot path, verifies the child privilege/listener/model identities, and cannot outlive any authenticated upstream authority. A provider-neutral detached promotion handoff now preserves the same promotion-v1 payload/envelope and downstream readiness, engine-wrapper, and Platform consumers while moving the private key outside the tool; its unsigned bundle is non-authorizing, but a valid bundle/signature pair is replayable exact-finalization material. No production promotion or real checkpoint deployment has been issued. |
| Private evaluation harness | Implemented foundation: strict calibration/sealed tasks, immutable context/verifier bindings, rights-reviewed release identities, artifact/profile-derived OpenAI-compatible capture, source-locked raw-base research capture, release-bound raw-base response-v2 capture with signed request/completion receipts, historical signature verification, a wrapper-config-v2 pinned-TLS loopback seam for externally custodied runtime signing, a research-only human-decision compiler, closed declarative exact-text/JSON-shape/value/decimal checks, and a signed-authority single-source Core/SDK profile. The wrapper authenticates the exact TLS leaf before exposing its bearer credential, verifies a domain-separated startup proof only after the owned child passes post-load checks, uses one bounded no-retry request under a hard total deadline per receipt, and locally verifies and low-S-normalizes each returned signature without changing activation-v1, receipt-v1, or response-v2. Release-bound aggregation freshly replays exact candidate and baseline verifier assets before paired baseline, suite-sufficiency, critical-failure, and no-regression gates. A separate ES256 audit now converts one exact full offline candidate/baseline replay into bounded C#-only non-executing validation for promotion/readiness/activation; mixed suites still freshly run every declarative task, while raw-base selection remains live, attested, catalog-complete, and unaudited. A second private eight-task strict-JSON calibration draft spans every required domain with executable declarative verifiers, but remains unreviewed, non-sealed, and non-authorizing. Candidate and baseline response trust remains external, the served candidate remains response-v1 `trained-adapter`, and raw-base v2 remains forbidden as that candidate. No reviewed private suite, real signer broker, real candidate responses, or signed selection/audit exists yet. |
| Private retrieval packs | Implemented hosted foundation: reviewed source-byte hashes, immutable corpus and algorithm versions, canonical UTF-8/LF chunks, deterministic integer-only selection, tenant/pack/query/policy bindings, provider-upload rights enforcement, startup-pinned server activation, private execution-spec freezing, and public-v1 source isolation. No production corpus pack is activated yet. |
| Expert checkpoint | Not implemented: no accepted base revision, adapter, training run, or benchmark result exists yet. |
| Hosted strategy generation | Implemented signed-routing foundation: a separate versioned strategy purpose produces a hash-bound multi-file C# source artifact only after the fixed Risk Judge approves it. Mock authorizes rehearsal; hosted-policy v1 remains Research-only; v2 can authorize Live only through one exact model-bound inert policy/workflow/prompt tuple. The Terminal accepts Mock or OpenAI-compatible exact specifications, quotes, starts, polls, previews, requires exact human release, recovers compare-and-swap conflicts, and imports source-only into the local compile flow. The artifact remains inert and non-installable, while credits are settled through the existing server ledger. Production remote authentication, a real v2 promotion/model activation, integration with the standalone headless verifier, and installation remain unimplemented. |
| Headless SDK C# verifier | Implemented bounded slice: one strict UTF-8 source file defining one public `IBacktestStrategy` is compiled against the actual frozen Core/SDK assemblies and replayed over bounded tick traces. An externally pinned ES256 lease is the sole source of the exact repository digest/config image ID, linux/amd64 platform, entrypoint, complete toolchain, protocol, and hardcoded sandbox; host-only expectations never enter the container. The host independently derives semantic identities from both returned replay traces and errors. The lease is reusable for at most seven days, not one-shot replay protection; its operator trust tuple/signing clock remain trusted, Docker client/environment/daemon/kernel/resolved builtin seccomp bytes are not independently attested, and output publication retains a narrow privileged-host path-swap limit. Direct result v2 remains standalone, while executable-verifier v2 now maps the same six checks into release-bound offline scoring and raw-base selection without granting review, release, training, promotion, or deployment authority by itself. |
| Untrusted execution isolation | Implemented restricted slices: exact DAXQ source can be lowered to the allowlisted reference VM, while the separate headless SDK profile runs each compiled single-file strategy replay in a fresh killable worker child inside the resource-bounded container. WPF/XAML, projects, packages, full plugins, and arbitrary/general-purpose code execution remain unsupported. |

Base-model selection v2 now also has a provider-neutral prepare/sign/finalize seam. Preparation freshly replays the complete reviewed student matrix and exact selected source-lock/profile/snapshot tree, then emits a content-addressed, authority-false bundle containing the unchanged selection payload, trust tuple, raw envelope preimage, and its SHA-256 digest. An external signer returns one canonical DER or fixed P1363 ES256 signature; one signature is sufficient because the existing envelope preimage already covers the full matrix, selected snapshot, release, approval evidence binding, validity, and trust. Finalization accepts either raw-message or prehashed-digest provider semantics, rejects double hashing and malformed/range-invalid signatures, normalizes valid high-S input to the existing low-S P1363 wire, freshly replays every live binding, and publishes only the canonical unchanged selection-v2 envelope. The bundle alone grants no authority, while a valid bundle/signature pair is replayable finalization-equivalent sensitive material. This is not KMS/HSM provisioning, IAM/quorum/audit or reviewer-identity attestation, revocation, honest-clock proof, sealed snapshot custody, image/entrypoint/seccomp provenance, or protection from privileged/same-user path swaps. Selection, corpus-review, optional teacher-lineage, and evaluation-authoring signers must remain distinct. No real selection bundle, signature, approval, or authority is supplied.

Launcher activation now has the same provider-neutral custody boundary without changing the activation-v1 payload or envelope accepted by the wrapper, response-v2 capture, selection, promotion, or replay consumers. Preparation accepts only the exact live wrapper config, public launcher identity, and validity window, then emits a content-addressed authority-false bundle containing the canonical activation payload, unsigned envelope, raw ES256 preimage, and SHA-256 digest. An external provider signs the raw message or prehashed digest and returns canonical DER or fixed P1363; private-key-free finalization verifies and low-S-normalizes it, rederives the config/package, sealed model target, runtime signer, and executable bindings, rechecks validity during staged no-clobber publication, and emits the unchanged activation-v1 wire. The bundle alone grants no authority, while a valid bundle/signature pair is replayable exact-activation finalization material until expiry. This is a custody integration seam, not KMS/HSM IAM, quorum, audit, signer-identity, rotation/revocation, honest-clock, immutable-input, or privileged-host-path attestation, and no real launcher signer or activation is supplied.

The existing credit work should not be rebuilt. The next dependency is real evidence: capture and
independently filter real teacher candidates, run deterministic and subject-matter review over the
resulting drafts, issue one independent exact-lineage admission and authenticated row receipts
through their detached signing handoffs, approve a release with authoritative user-managed
permission records, run the raw-base bake-off, sign the reviewed student/snapshot choice through the
implemented detached selection contract, independently validate the sealed training lock on
suitable server GPUs, establish actual production KMS/HSM custody and reviewer policy, and measure
the resulting checkpoint against the strongest baseline.

## Why this distillation approach

Classic knowledge distillation trains a smaller model to reproduce a larger model or ensemble. For modern LLMs there are three materially different methods:

1. **Sequence-level or teacher-trace distillation.** A teacher produces candidate answers. Deterministic tools and humans retain only correct outputs, then the student is trained with SFT. This needs no teacher logits and is the lowest-complexity pilot, but it has an explicit stop/go gate because competent coders may regress.
2. **Preference distillation.** Passing and failing candidates form preference or binary-feedback data. DPO, SimPO, or KTO improves selection after the SFT baseline is stable.
3. **Logit/on-policy distillation.** The student learns from teacher probability distributions, often on student-generated sequences. This can be stronger but needs white-box teacher access, compatible tokenisation, and significantly more compute.

The evidence favours starting with verified traces:

- Distilling Step-by-Step and Orca show that richer teacher supervision can improve smaller models, but both also warn indirectly against learning only superficial answer style.
- DeepSeek-R1 reports strong small-model results from curated teacher samples and explicitly found distilled small models stronger than applying its RL recipe directly to those small bases.
- Qwen2.5-Coder used large-scale rejection sampling and execution feedback. Magicoder and SelfCodeAlign likewise show that diverse synthetic code tasks become useful when grounded in code and filtered by verification.
- SWE-RL reports that reinforcement learning improved software reasoning while its SFT comparison degraded on average. A July 2026 coding-curriculum preprint likewise reports verified-answer SFT regressions for competent Qwen2.5-Coder students while RLVR improved the hard slice. The latter is one new preprint, so it is a stop/go warning rather than a sole policy basis.
- Phi-4-Mini-Reasoning demonstrates a staged distilled-training, SFT, rollout-DPO, and RLVR recipe; s1 and OpenThoughts support selecting frontier tasks for difficulty, diversity, and quality rather than maximizing imitation volume.
- DistiLLM and GKD are later options when trace SFT plateaus and a compatible white-box teacher is economically justified.

Hidden chain-of-thought is not required and must not be collected from hosted providers. Store concise assumptions, decisions, code, tests, and verification evidence instead.

## Candidate bake-off

The implemented production shortlist happens to use permissively licensed weights, but permission is
not a technical-ranking filter. Every base, teacher, dataset, paper/code implementation, and service
still records its exact source, acquired revision, price/terms snapshot, accountable permission
owner, data policy, and derived-artifact lineage. Paid, gated, or custom-licensed candidates remain
eligible when the user supplies authorised access.

| Candidate | Useful facts | Role in the bake-off |
|---|---|---|
| Qwen2.5-Coder 7B | Apache-2.0, 7.61B parameters, code-specialised, 32K in the pinned config (the model card documents longer-context scaling), C# included in published multilingual evaluation. | Primary low-cost student. |
| Qwen2.5-Coder 14B | Apache-2.0, 14.7B parameters, same code family. | Quality step-up if 7B misses sealed gates. |
| gpt-oss-20b | Apache-2.0, 21B total/3.6B active, MXFP4 inference within 16 GB per its model card, officially fine-tunable. | Reasoning-heavy alternative for quant/risk tasks. |
| [Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B) | Apache-2.0, 8.2B dense, 32K native context, thinking/non-thinking modes, and supported by vLLM 0.8.5 or newer. | Immediate modern student challenger with the lowest integration risk. |
| [Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B) | Apache-2.0, 9.65B and 262K native context; its current card still calls for main/nightly serving support and it is multimodal. | Shadow challenger only until a new source lock and pinned runtime lane pass review. |
| Qwen3-Coder 30B-A3B | Apache-2.0, 30.5B total/3.3B active, native 256K. | Strong teacher, fallback, or higher-cost production tier. |
| [Qwen3-Coder-Next](https://huggingface.co/Qwen/Qwen3-Coder-Next) | Apache-2.0, 80B total/3B active, native 256K; the full 80B weight set must still be stored and loaded, so active parameters are not a VRAM claim. | Offline teacher candidate, not the small student. |
| [Devstral Small 24B](https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512) | Apache-2.0, agentic coding focus, single-4090-class deployment claimed by its card. | Comparison candidate if repository-agent behaviour matters. |
| [Granite Code 8B](https://huggingface.co/ibm-granite/granite-8b-code-instruct-128k) | Apache-2.0 and unusually clear provenance positioning. | Conservative licensing/provenance fallback. |

Do not select from public Python-only scores. Run the same private C# and DaxAlgo suite against every candidate, on the intended quantisation and serving stack.

## Corpus contract

Each example must carry:

- immutable ID, schema version, split, contamination group, cutoff time, and content hash;
- one task kind and one or more domain labels;
- complete chat messages ending in the reviewed assistant answer;
- source provenance, licence, storage/evaluation/training/provider-upload rights;
- teacher/base identity and prompt hash when model-generated;
- deterministic verification type, pass result, evidence hash, and reviewer status;
- an explicit training opt-in, valid only for development data.

Required domain labels are:

- C# and .NET;
- private DaxAlgo architecture and SDK usage;
- quantitative mathematics;
- probability and statistics;
- risk management;
- portfolio management;
- markets and finance;
- WPF UI and MVVM design.

Recommended task kinds include strategy specification, C# implementation, compile repair, architecture navigation, quantitative derivation, risk review, portfolio review, WPF/MVVM implementation, and adversarial safety review.

The safest data sources are project-owned examples, authored SDK documentation, reviewed synthetic tasks from open-weight teachers, compiler/test failures and repairs, and finance material with explicit ML-training rights. Customer prompts and strategy code remain excluded by default. No source is usable merely because it is publicly readable.

Group related prompts, source documents, repositories, instruments, time windows, and derived variants into the same contamination group. Development, calibration, and sealed data must not share a group or exact content. Keep the sealed set inaccessible to training, prompt tuning, model selection, and teacher generation.

Draft authoring uses `expert-dataset compile-draft` with a strict JSON manifest and separate source-evidence files; authors do not hand-write the canonical JSONL or either evidence hash. The manifest must explicitly declare its private storage/evaluation-only authority and basis. The compiler derives the final records, injects a hash-bound `candidate-stable` or `retrieval-only` knowledge marker, and forces `development`, `draft`, unverified, non-training, non-uploadable, and non-redistributable state before running the canonical validator. Training export and release validation require the candidate-stable marker, while retrieval-only records cannot declare training rights. The initial private seed under `tmp/vibe-quant-model/corpus/` contains one draft in each required domain and marks current proprietary architecture/UI material as retrieval-only. It is an authoring and review queue, not an SFT dataset or release: independent correctness and ML-training-rights review must occur before any row can be approved or exported.

`expert-dataset verify-draft` executes allowlisted deterministic text checks (`contains`, `not-contains`, `equals`, and exact assistant SHA-256) against the exact dataset bytes and emits a v2 content-hashed review report that explicitly marks unsupported profiles. For C# `CodeGeneration` and `CodeRepair`, the optional fixed `daxq-sdk-abi3-source/v1` profile also treats the exact assistant response as source, compiles and lowers it without loading the submitted assembly, and runs only verified DAXQ bytecode against bounded declarative numeric vectors in a constrained child process. `expert-dataset apply-review` freshly repeats the same work, requires a separate row-complete human decision manifest bound to the dataset, verifier manifest, and report, and replaces code compile/test claims with the fresh structured evidence. Failed or unsupported checks cannot be approved, reports cannot be substituted, existing outputs are not replaced, every source/example right is preserved, and `useForTraining` remains false. Code review, general C#, WPF/XAML, projects, packages, commands, and executable test code remain unsupported by this workflow.

The formerly manual rights transition is now an explicit unsigned handoff. `prepare-rights-review` embeds and freshly replays the exact draft, reviewed corpus, verification inputs/report, review manifest, and supplied evidence while inventorying every row and source. `prepare-rights-decision-template` replays that package and creates a versioned editable deny-default draft bound to the exact package ID, raw package hash, and reviewed corpus; normal closed JSON formatting is accepted, but duplicate or unknown properties fail. After an independent reviewer completes every decision and evidence reference, `compile-rights-decision` rechecks those bindings, embeds the cited evidence, and derives the canonical decision; `apply-rights-review` freshly replays the package again and can elevate only approved, verified, candidate-stable development rows with complete source closure. Retrieval-only rows cannot gain downstream rights, provider upload implies training rights, and pre-existing reserved anchors, stale chronology, incomplete inventories, changed bytes, cross-package substitution, and existing outputs fail closed. These artifacts remain unsigned declarations: they do not authenticate the reviewer, prove evidence or legal-rights truth, create a receipt, or make any row training-eligible. The exact final corpus still requires authenticated per-row receipts before SFT export or release.

The separate `verify-csharp-strategy` command provides a narrow headless SDK slice. It accepts one source file, compiles against the actual `TradingTerminal.Core` and `DaxAlgo.Sdk`, and replays host-declared tick cases twice with every replay in a fresh worker process. Before any Docker call it authenticates a canonical ES256/P-256 authority v2 against an externally pinned public-key SPKI, audience, key ID, and signer role. That lease is the sole source of the exact repository digest/config image ID, linux/amd64 platform, entrypoint, full worker/runtime/Core/SDK/Roslyn closure, protocol, hardcoded sandbox, absolute Docker client path/hash/size, explicit local daemon endpoint, and scrubbed environment policy. The authority issuer supplies the image identity and entrypoint; its signature authenticates that reviewed choice but does not independently discover image provenance or prove entrypoint correctness. The host authenticates and privately snapshots the client, invokes only that snapshot with the signed endpoint and empty private configuration/home/temp state, inspects the image and container identities, compares the returned toolchain exactly, independently derives semantic identities from both returned replay traces and errors, and rechecks client identity and expiry before publishing result v2. Ambient `PATH`, `DOCKER_CONTEXT`, user configuration, and other Docker overrides never enter the client process. The container receives the request and source but never the expectations, and the host derives exactly six checks: `source-binding`, `compile`, `analyzers`, `deterministic-execution`, `reference-cases`, and `sandbox-policy`. The lease is reusable within its maximum seven-day validity rather than one-shot. Its protected operator trust tuple and signing clock remain trusted; the endpoint name does not attest the daemon/socket owner, runtime, kernel, or resolved builtin seccomp bytes. A compromised daemon or privileged host can still fabricate runtime claims, and narrow same-user or privileged validate/open path-swap races remain around the private client snapshot and output publication. Independent runtime/daemon attestation plus stronger immutable or handle-relative host custody remain production requirements.

The closed `executable-verifier/v2` profile reuses that controller for exact release-bound `CodeGeneration` and `CodeRepair` response scoring. A reviewed release asset carries only the contract, ordered ticks, and hidden trace hashes; the runtime derives the request ID and exact source/request/expectation byte bindings from the response, requires a live external authority/trust tuple, and maps the six checks one-for-one into canonical verifier results. Stable authority-configuration, toolchain, image, platform, sandbox, request, source, and expectation identities enter the evidence; renewable lease-envelope metadata does not, so equivalent lease renewal preserves the result and runtime drift changes it. `run-verifiers` and raw-base selection-v2 still require fresh full replay. For production promotion, a separate independent ES256 replay-audit signer authenticates the exact release/task/verifier subset, stable C# configuration, candidate/baseline run and file/set identities, and every covered response/result row after both complete suites are freshly executed. Promotion, readiness, and engine-wrapper v7 validate that exact pinned audit without Docker and freshly execute any declarative rows in a mixed suite. Audit and live execution are mutually exclusive; the audit expiry caps the promotion, while its narrow scope, false authority flags, and signed statement grant no review, release, RLVR, training, base-selection, promotion-decision, checkpoint, deployment, hosted, installation, or strategy-execution authority. Its external trust tuple and signer-supplied replay, approval, and issuance clocks remain trusted; ordering and activation gates reject future-dated use but cannot prevent deliberate backdating by that signer. WPF/XAML, projects, packages, full plugins, arbitrary/general-purpose code, and installation remain outside the profile.

Replay-audit signing now also has a provider-neutral detached custody seam. Preparation performs the same complete candidate/baseline replay and emits a content-addressed all-false bundle over the unchanged audit-v1 payload, unsigned envelope, trust tuple, raw ES256 preimage, and SHA-256 digest without accepting a private key. Finalization accepts external raw-message or prehashed-digest DER/fixed-P1363 signatures, normalizes valid high-S input, freshly repeats the entire live release/evidence/verifier-authority replay and validity ceiling, and publishes the unchanged low-S audit-v1 envelope. The bundle alone is non-authorizing, but a valid bundle/signature pair is replayable exact-audit finalization material until expiry. This seam does not provision KMS/HSM IAM/quorum/audit/rotation/revocation, prove signer identity or honest clocks, attest the Docker daemon/runtime/kernel/builtin seccomp implementation, close privileged or same-user path swaps, or create real model-quality evidence.

After draft review, an independent reviewer can issue one detached canonical JSONL receipt per exact
row. The current v2 receipt envelope is ES256 over P-256 with a canonical low-S IEEE-P1363 signature;
its payload binds the exact source-corpus bytes, row, conversation, freshly rederived verification
evidence, unsigned SFT metadata v2, review decision, approval evidence, and derived
evaluation/training/provider-upload authorizations. Metadata v2 carries its schema plus the same
source-corpus and row-evidence identities, and its complete canonical hash is signed by the receipt.
SFT export and release-v4 creation rederive those bindings from one captured corpus snapshot and
verify the receipt set against an externally pinned reviewer public key, SPKI SHA-256, audience, key
ID, and signer role. An `OpenWeightTeacher` row additionally requires an active, separately signed
teacher-lineage admission over its exact stable subject and reviewed corpus; a human-authored-only
corpus rejects extraneous lineage inputs. Python retains homogeneous receipt/SFT v1 solely to
validate archival release-v3 bundles whose every row is `HumanAuthored`; current issuance, C# export,
release v4, and every identity-returning downstream path require v2. Receipts are active for no more
than 366 days; immutable releases do not survive their expiry, so a re-review requires a newly issued
receipt set and release rather than mutation. Structural SFT validation is not an authorization
boundary. Corpus and evidence hashes prove byte identity, not correctness, source/evidence
availability, honest review, real-world signer identity, or legal rights. The current eight-row seed
still has only text checks and no real independent human decision or receipt: its passing v2 report
establishes deterministic checklist conformance, not semantic truth, legal rights, reviewer identity,
provider upload, or production training/evaluation authorization.

The separate `compile-draft-calibration-tasks` path freezes a private calibration authoring manifest, hashes contained context/verifier bytes, derives the canonical prompt/task identities, and refuses sealed output. The original eight-task prose-rubric seed and a second eight-task strict-JSON batch each cover every required domain. The second batch binds a closed declarative executable verifier for every task, including exact root-object keys and typed or bounded-decimal values. Both remain unreviewed calibration-only draft material; neither establishes a sealed or withheld benchmark, signed authoring approval, release, model response, verifier result, threshold, policy, or promotion evidence.

The source-corpus draft contract now has a v2 form with an explicit per-row development,
calibration, or sealed label; v1 remains development-only, and teacher capture rejects v2
calibration/sealed rows. The separate evaluation-authoring handoff accepts only approved, verified,
declaratively human-authored calibration/sealed rows that retain storage/evaluation-only rights. A
closed manifest maps every such row once and cannot supply messages, answers, split, domain, cutoff,
or task hashes. The compiler derives both canonical task sets without the terminal assistant
reference answer, rejects normalized prompt leakage into development or across evaluation splits,
copies exact content-addressed context/rubric/verifier assets, and atomically emits an unsigned
package whose authority is entirely false. Validation replays the derivation and rejects source,
manifest, task, binding, asset, or package-closure drift. Its v2 task bindings use only canonical
package-relative asset paths; legacy v1 release bindings retain their historical absolute or
current-working-directory-relative semantics. The handoff omits the source corpus, and its emitted
task records omit terminal reference messages; exact reviewer-authored context, rubric, or verifier
assets may still contain expected-value material. Bounded normalized matching rejects
reference-answer substrings and shared user turns elsewhere in the reviewed corpus. This removes unsupported canonical-JSONL
editing; it does not prove human identity, answer correctness, semantic non-leakage beyond those exact
checks, genuine independent authorship, secret custody, withholding, or approval. Those claims still
require external governance, authenticated row receipts, and the separately signed
evaluation-authoring approval.

## Training recipe

### Phase A - baseline before tuning

1. Freeze the private evaluation schema and first sealed set.
2. Freeze two comparisons: standardized decoding for controlled comparison, and each model's documented recommended decoding under the same token, latency, repair, and credit ceilings. Qwen3 warns that greedy thinking-mode decoding can loop or degrade.
3. Record quality, failure category, first-pass compile rate, repair success, latency, throughput, peak memory, and internal cost.
4. Select the quality/credit Pareto frontier; do not assume the smallest or newest model wins.

The harness can now represent this pre-tuning run without pretending the base model is a trained
adapter. The approved source lock binds every selected student inference file to the exact pinned
commit, while the snapshot and base profile bind the locally loaded bytes and runtime plan. Initial
captures remain explicit loopback-only research evidence. The separate base engine owner now permits
release-bound attested response-v2 capture. Wrapper config v2 replaces the production local-PEM
dependency with a pinned-TLS literal-loopback signer contract: it keeps only the public identity,
exact TLS-certificate identity, and broker credential; authenticates the HTTPS peer before sending
that credential; proves signing after post-load child validation; enforces a hard total deadline; and verifies every exact
digest signature locally before emitting the unchanged receipt-v1 wire. Config v1 remains a
development/compatibility PEM route. The seam does not deploy or attest KMS/HSM custody, IAM, quorum,
audit, signer identity, key lifecycle, TLS-key-to-process/hardware ownership, or provider processing; the activation
signer's separate private-key custody is also unchanged. Selection v2 freshly replays one row for every catalog
student, derives completeness from catalog roles, requires a shared attested raw-base-v2 baseline,
enforces common release/suite/seed/source-lock/policy-family inputs, and binds the exact passing
profile/snapshot. One matrix represents one frozen comparison condition. The research plan's
controlled and recommended-decoding experiments, latency/throughput/memory measurements, and
quality-per-credit Pareto decision still require separate reviewed evidence; the matrix does not
manufacture those experiments. Selection v2 supplies one authenticated input; only manifest v3 with
that selection and a separately trusted signed exact-corpus admission may enter non-smoke training.
No actual bake-off, corpus admission, or selection has been issued.

### Phase B - verified teacher data

1. Use an open-weight teacher to generate several structured candidates for each development task.
2. Compile C#, run focused tests and analyzers, validate SDK/API use, check public/Pro boundaries, and apply risk invariants.
3. For numeric tasks, use executable reference calculations and tolerances.
4. For UI tasks, compile XAML and enforce MVVM/lifecycle rubrics.
5. Preserve every candidate and verifier outcome for later preference/RLVR work, but admit at most one independently passing answer per task to SFT after human review. Store concise rationale, never hidden chain-of-thought.
6. Keep a general coding replay slice to reduce catastrophic forgetting.

The implemented capture stage covers step 1 and the immutable input/output lineage needed for later
review. A read-only derivation step now turns one exact local runtime descriptor, chat-template file,
and catalog into the execution ID and capture-plan fragment without claiming an observation. The
subsequent no-launch binding step queries an already-open canonical loopback vLLM `/version` and
single-card `/v1/models` surface, then capture rehashes the bound local inputs and repeats those probes
before tokenization and after generation. Manifest v2 live capture also tokenizes each exact
source-grounded chat through the same vLLM root before any completion, requires the live maximum model length to match the manifest, rejects
prompt-plus-output overflow, reserves exact prompt and worst-case completion budgets, and rejects
completion usage that disagrees with the preflight. Historical v1 manifests remain validation-only.
The admission stage independently binds selected candidates to exact queue, generation,
catalog, and held-out-overlap inputs, then derives canonical OpenWeightTeacher drafts without granting
verification, review, rights elevation, or training eligibility. It rejects calibration/sealed
inputs, provider endpoints, partial batches, duplicate samples, hidden-reasoning tags, multiple
answers per task, exact authored-message-prefix or normalized-user-turn reuse, contamination-family
overlap, and exact withheld task/context/verifier assets used as teacher sources. The deny-set scope
binds the byte and semantic identities of both withheld task sets, and the package
snapshots every input needed for self-contained revalidation. A separate exact-lineage authority now
reopens that package, the passive runtime binding, final reviewed corpus, and reviewer evidence before
signing the ordered stable teacher subjects. The authority permits receipt issuance only; Python receipt
creation performs the full replay, while C# SFT export and release/downstream consumers verify the signed
envelope against the exact already-read corpus. One v1 admission binds one materialization package. Release
v4 bundles the signed admission, not the source package, runtime binding, or reviewer evidence; legacy v3
remains valid only for human-authored corpora. Steps 2-6, real candidate filtering, a real admission/receipts,
and a training-authorized release remain pending.
The runtime/template hashes now derive from exact local descriptor/template bytes and the maximum
length must agree across descriptor, binding, model card, manifest, and tokenizer responses. This is
stronger configuration consistency, not teacher-engine attestation. The same local endpoint reports
version, model-card identity, tokenization, completion, and total usage, so their agreement and the
non-persisted token vectors are not proof of the loaded tokenizer or weights; literal loopback also
does not prove that an operator-controlled
service cannot proxy externally, and a development label cannot prove absence from the withheld
suites. Production use therefore requires an egress-isolated, independently pinned teacher runtime
with external tokenizer/context-window evidence. The reviewer-signed admission authenticates the
reviewer's exact lineage decision, not the selected runtime, weights, image, entrypoint, process,
isolation, correctness, rights, or reviewer identity. Its caller-selected source paths and narrow
validate/open host path-swap windows remain operational trust limits. Receipt and SFT gates reject a
non-teacher row that retains a teacher-admission anchor, and full admission rejects an exact
materialized conversation copied under a relabelled ID. An actor who removes the anchor and relabels
the row before authenticated pre-review provenance exists cannot be detected from the final corpus
alone; production must authenticate that materialization-to-review handoff. The bound deny-set closes
the mechanical cross-pipeline admission check, but hashes do not anonymize low-entropy prompts and
custodian authorship, independent completeness, and withheld-suite secrecy still require external
governance and later authenticated review.

### Phase C - adapter training

1. Run a small QLoRA/LoRA SFT pilot on verified development examples and stop if calibration quality regresses.
2. Pin the base revision, tokenizer, chat template, dataset hash, complete training environment, seed, hyperparameters, and adapter hash.
3. Evaluate checkpoints on calibration data; touch the sealed set only for the final promotion decision.
4. For executable C#/numeric work, prefer RLVR after a stalled/regressing SFT pilot once the isolated verifier exists. Never optimize profit, Sharpe, or backtest rank.
5. Use SimPO or DPO for matched same-prompt pass/fail or qualitative-risk candidates, and KTO only when reliable binary labels exist without natural pairs.
6. Consider GKD/DistiLLM only after the simpler pipeline plateaus and a genuinely stronger white-box teacher justifies the compute/tokenizer coupling.
7. Quantise last and rerun the full suite because quantisation and KV-cache limits can change both quality and latency.

The current harness now snapshots a wheel-only PEP 751 lock and strict runtime profile into every
run bundle. Training, including smoke mode, rejects a different Python implementation/minor,
OS/architecture, CUDA runtime, or direct dependency version before GPU probing or model
construction. Non-smoke training additionally authenticates the selection before parsing its
payload. Manifest v3 also requires a separately trusted low-S ES256 corpus-admission envelope over
the exact release, SFT bytes, deterministic quality report, and reviewer-selected policy. The report
uses exact rational domain weights to prevent multi-label inflation and covers task, domain,
domain/task, per-domain contamination-family diversity, global concentration, origin, producer, and
maximum-label dimensions. The repository supplies no approved policy or numerical minimum: an
external reviewer must select and pin the policy hash, and that signer must differ from corpus
review, evaluation authoring, base selection, and the trainer. Manifest v2 remains validation and
explicit-smoke only. Training revalidates the signed admission from private captured dataset bytes
before model construction and carries its expiry through final sealing. The admission is reusable
only for the exact release, dataset, policy, and validity window; it is not a one-shot token. This proves declared
structural policy conformance, not semantic quality, honest labels, or verifier-supported code; the
current SFT contract has no source-verification field.

Training also revalidates the exact read-only snapshot before/after model loading and before
publication, passes that local directory to both model loaders without a revision/cache lookup, and
rejects any private snapshot path leaked into the adapter package. Final metadata records the
observed dtype and GPU facts while its manifest hash transitively binds the selection and corpus
admission. Promotion and readiness now
authenticate that manifest-bound selection again with externally pinned trust and validate the exact
external snapshot at the historical manifest-creation and artifact-recording times. Engine-wrapper
v7 repeats the complete check before launch, after load, during integrity monitoring, and before
readiness. This closes the software-path selection bypass, but the selected profile has not yet been
installed or exercised on the target server image and is not evidence of a successful training run.

Raw profit, Sharpe, or backtest rank must never be the training reward. Those invite leakage and overfitting. Finance checks use point-in-time inputs, walk-forward splits, realistic costs and slippage, parameter robustness, no-lookahead invariants, and one untouched outer holdout.

## Evaluation and promotion gate

The benchmark must score the final system, not only the model:

| Slice | Deterministic evidence |
|---|---|
| C# generation and repair | Compilation, required tests, analyzers, bounded repair count. |
| DaxAlgo architecture | Correct symbols/references, private/public boundary, no invented APIs, current retrieval citations. |
| Quant/probability | Executable reference values, tolerance checks, derivation rubric, unit consistency. |
| Risk/portfolio | Hard constraints, scenario coverage, position/portfolio distinction, no guaranteed-return claims. |
| Finance strategy design | Point-in-time data use, no lookahead, realistic fees/slippage, falsifiable hypothesis. |
| WPF/MVVM | XAML compile, binding checks, disposal/lifecycle rules, no business logic in views. |
| Safety/security | No secrets, broker/order authority, unrestricted process/network access, or cross-tenant context. |
| Operations | p50/p95 latency, tokens per second, GPU memory, queue time, failure/retry rate, credits per accepted artifact. |

The signed headless C# release profile now supplies the narrow single-source strategy slice of this
evidence table to offline response scoring and raw-base selection. Its signed replay audit permits
exact C# evidence to be revalidated without Docker at promotion/readiness/activation while mixed
declarative rows still execute locally. It does not establish the broader project/test/WPF coverage,
verifier correctness, Docker-daemon attestation, or any model-quality result.

Verifier-authority signing also has a provider-neutral detached custody seam. Preparation takes the
same live toolchain, caller-selected digest-pinned image and absolute entrypoint, pinned Docker client
and local daemon endpoint, approval statement, and public trust as direct issuance, but no private key
or password; it exposes the exact existing authority-v2 raw preimage and one SHA-256 digest. An
external service signs one mode, and finalization verifies DER or fixed P1363 input, normalizes valid
high-S signatures, freshly replays the live bindings and lease clock, and emits the unchanged low-S
envelope consumed by verifier and replay-audit code. The unsigned bundle is non-authorizing, while a
valid bundle/signature pair is finalization-equivalent sensitive material. This seam neither proves
the selected image or entrypoint is correct nor attests the Docker daemon/socket owner, runtime,
kernel, daemon-resolved builtin seccomp policy, or honest time. It does not provision KMS/HSM IAM,
quorum, audit, rotation, or revocation, and same-user or privileged host path swaps remain possible
without stronger custody. No real authority, execution, replay audit, or model-quality evidence has
been issued.

Initial thresholds are calibration targets, not claims of achieved performance. Promotion requires:

- zero critical safety, tenancy, order-execution, or open-core-boundary failures on the sealed suite;
- no material domain regression versus the strongest baseline;
- a statistically defensible improvement in accepted-artifact rate or quality per credit;
- reproducibility across at least three seeds where training stochasticity matters;
- unchanged results after the production quantisation and serving configuration is frozen;
- human approval of the exact model/adapter/evaluation hashes.

Public benchmarks such as SWE-bench, LiveCodeBench/Multi-LCB, and MultiPL-E are useful smoke checks. They do not replace the private C#, SDK, quant, risk, and WPF suite. Add a rolling post-cutoff shadow suite beside immutable calibration/sealed releases; report confidence intervals clustered by contamination group, accepted artifact per fixed credit budget, routing/escalation recall and false escalation, and model/retrieval/repair/fallback ablations. Hidden verifier cases and mutation testing are required before scaling generated code so hard-coded or weak-oracle passes do not become training rewards.

The private harness now makes this gate machine-checkable without claiming that it has been passed. The unsigned evaluation-authoring handoff first derives answer-free paired task sets and exact asset bindings from the reviewed source rows, while explicitly declining to attest author identity or sealed custody. A content-addressed release-v4 then binds the rights-bearing corpus, mandatory exact detached receipt set plus external trust identity, optional exact SFT export, calibration and sealed task bytes plus semantic task-set identities, inert rubrics/verifiers, task-to-corpus lineage, cutoff, and approval evidence. A teacher-backed release also bundles the exact signed lineage admission and rejects missing, extraneous, reordered, or mismatched stable subjects; legacy v3 is human-authored only. The lineage admission's detached preparation route exposes the exact existing envelope preimage plus its SHA-256 digest without loading a private key; finalization accepts canonical DER or fixed P1363, normalizes low-S, freshly rederives the package/runtime/corpus/evidence chain, and emits the unchanged admission-v1 envelope. Its unsigned bundle grants no authority, while a valid bundle/signature pair is admission-equivalent sensitive material. A separate low-S ES256 evaluation-authoring envelope signs that exact corpus/task/lineage/context/rubric/verifier inventory, is pinned by full external trust and exact envelope hash, remains authority-false for release/training/promotion/deployment/execution, and uses a signer distinct from corpus review. Its detached preparation path exposes the exact raw signature preimage plus one SHA-256 digest without loading a private key; finalization accepts canonical DER or fixed P1363, normalizes low-S, repins trust, rederives every source/task/binding/asset byte, rechecks live validity, and publishes the same approval-v1 envelope. The unsigned bundle grants no authority; once it is paired with a valid signature, the pair is approval-equivalent sensitive material because finalization needs no further authorization, although downstream consumers accept only the finalized envelope. Consumers revalidate every applicable signed authority and cap downstream validity at their earliest expiry. Before non-smoke training, a separately trusted quality reviewer admits the exact release, SFT bytes, derived report, and reviewer-selected policy. Its provider-neutral handoff exposes the existing admission-envelope preimage plus one SHA-256 digest, accepts DER or fixed P1363 without any private-key option, normalizes valid high-S input, rechecks live validity and every bound byte, and emits the unchanged admission-v1 envelope. The unsigned quality bundle is non-authorizing, but its valid bundle/signature pair is finalization-equivalent sensitive material; the handoff does not provision or attest reviewer identity, KMS/HSM IAM, quorum, audit, rotation/revocation, honest clocks, sealed custody, or privileged host paths. The release approval remains declarative: it joins those independently authenticated inputs but does not prove legal rights, reviewer identity, expected-value correctness, semantic coverage, verifier quality, loaded teacher weights, runtime identity, or isolation. After response capture, a strict authoring manifest must bind the complete semantic task and response sets, every response hash, and every required check in order; the compiler derives canonical evidence, acceptance, and result hashes from exact input snapshots, rehashes all inputs before no-clobber publication, and makes complete-set validation the CLI default. It does not run verifier code or authenticate the person supplying the decisions. A frozen policy then binds the calibration evidence hash, sealed task-set hash, minimum task/critical/domain/contamination-group coverage, and exact candidate/baseline catalog, model, revision, serving profile, run, and seed. Candidate and baseline responses must cover the same sealed tasks; non-stop completions, critical failures, absolute-threshold misses, or overall/per-domain regressions fail the evidence gate. Reports remain explicitly unpromoted even when every gate passes.

Production authorization is a separate step. The promotion command re-runs aggregation from the exact calibration, sealed, candidate, baseline, release, artifact, and approval inputs and refuses a merely self-consistent edited report. It requires manifest v3, authenticates the bundled selection and embedded artifact-v2 trainer provenance with independently pinned trust, retains one validated manifest byte snapshot, and rehashes the selected external snapshot. Trainer provenance binds the exact manifest and therefore the bundled corpus-admission identity, but promotion does not reinterpret its thresholds or turn that admission into a promotion authority. The trainer signer must differ from teacher-lineage review, corpus review, evaluation authoring, corpus admission, base selection, replay audit, and promotion signers. Causality is manifest <= artifact <= trainer issue <= trainer activation <= approval <= promotion issue, and promotion cannot outlive trainer provenance or any earlier authenticated teacher-lineage/receipt/authoring/audit expiry. Selection and corpus-admission expiry are historical training authorizations, not serving leases. The command signs canonical payload bytes with a separately pinned P-256 key, a fixed low-S IEEE-P1363 signature, explicit audience/role/deployment identities, and a maximum 366-day validity window. Platform can therefore cap readiness using the signed promotion expiry without outliving upstream authority. The command replay-validates a staged record before atomic no-clobber publication. This authenticates exact signed statements and byte identity; it does not prove honest GPU execution, loaded tensors or hardware, legal declarations, corpus or verifier quality, real-world signer identity, uncompromised trainer/key custody, or honest signing clocks.

The promotion decision now also has a provider-neutral detached custody seam over that unchanged promotion-v1 consumer contract. Preparation accepts no private key, freshly derives the complete live payload, and emits a content-addressed all-false bundle containing the exact payload, unsigned envelope, public trust tuple, raw ES256 preimage, and SHA-256 digest. Finalization accepts external raw-message or prehashed-digest signatures in canonical DER or fixed P1363, rejects wrong-key, double-hashed, malformed, range-invalid, expired, or live-drifted inputs before publication, normalizes valid high-S signatures, and repeats every live binding at staging and destination precommit before producing the existing low-S P1363 envelope consumed by readiness, the engine wrapper, and Platform. The bundle alone is non-authorizing, while a valid bundle/signature pair is replayable exact-promotion finalization material until expiry. The seam provisions no KMS/HSM IAM, quorum, audit, signer identity, rotation/revocation, honest clocks, immutable evidence custody, or privileged/same-user path protection, and no real promotion has been issued.

Base-model selection is a separate pre-training authorization. Pairwise promotion evidence remains the scoring primitive, but selection v2 snapshots and freshly regenerates exactly one release-bound attested raw-base-v2 row for every catalog student. It rejects omissions, duplicates, extra or teacher/fallback rows, unequal releases/suites/baselines/seeds/source locks/policy families, an unauthenticated response-v1 baseline, and any selected row that missed a quality or regression gate. Non-selected complete rows may fail quality gates so the matrix can honestly retain weaker candidates. The signed authority binds the catalog-ordered matrix identity, every evidence file/set hash, exact chosen profile/snapshot, and reviewed rationale with independently pinned ES256 trust. The paths-only CLI source manifest carries no keys or trust decisions; candidate and baseline runtime trust remains external. Downstream target and manifest validators re-derive student order, model IDs, revisions, catalog bytes, and source-lock identity instead of trusting only the signed list. The trainer does not need the sealed suite: it verifies the signed envelope and exact bundled profile/source-lock/snapshot identities against the external read-only weight tree. Promotion, readiness, and activation do not trust the manifest hash alone; they authenticate the same selection envelope and exact snapshot again. The selection authorizes only that training input; it is explicitly not a checkpoint, promotion, deployment, or quality claim. No production selection-v1 migration is required because no real selection has been issued; pair-only v1 is rejected by production consumers.

The provider-neutral selection handoff preserves that exact v2 consumer contract: prepare emits only a closed authority-false request, an external provider signs either the decoded raw preimage or its decoded prehashed digest, and finalize freshly replays the complete live matrix before producing the same canonical low-S envelope. The bundle/signature pair is replayable finalization-equivalent sensitive material, not an additional selection or review authority, and neither detached API accepts a private key.

## Coordinator and serving design

Use a small explicit C# state machine, not a free-form multi-agent conversation. Anthropic's production guidance distinguishes routing, orchestrator-workers, and evaluator-optimizer workflows; DaxAlgo naturally fits routing plus evaluator-optimizer because compiler/test feedback is objective.

Proposed routing policy:

- send routine in-domain generation/repair to the small expert;
- retrieve only account-authorised, version-pinned DaxAlgo context;
- run deterministic checks after every candidate;
- allow a small bounded repair loop;
- escalate unknown APIs, multi-project changes, repeated failures, low confidence, or high-risk finance decisions to the larger coordinator;
- require human approval before release;
- keep model-written code inert until a restricted compilation/backtest worker is separately approved.

Serve the accepted checkpoint behind a private OpenAI-compatible endpoint. The existing platform provider adapter and credit ledger can then be reused. The implemented serving profile pins model and adapter/tree/manifest hashes, tokenizer/chat template, candidate-aware context limit and quantisation, serving image, and hardware class; its raw SHA-256 becomes the internal execution model ID while clients see only the reviewed profile name. Live Platform activation additionally requires the independently signed, time-bounded promotion record and recomputes its exact hosted-policy identity from active server configuration. Policy v1 is Research-only; policy v2 additionally binds one exact model-specific inert StrategyAuthoring tuple without granting compile, install, execution, broker, live-order, or release authority. An expiring nonce/HMAC readiness-v2 proof binds the hidden profile, artifact/tree, execution model, promotion envelope/payload, deployment, provider, hosted policy, and promotion expiry before credits are reserved, jobs are claimed, and every provider call is dispatched. Each frozen execution is also bound to the exact active endpoint, credential reference, attestation configuration, and signed deployment identity, so same-model rotations fail and refund unstarted work without exposing private hashes. Temporary readiness loss leaves current-activation reservations intact, while completed artifacts and release decisions remain available without reconstructing or calling a retired provider.

The implemented engine-owning wrapper requires config v7 for every production activation. V7 requires independent evaluation-authoring and trainer-provenance trust, carries explicit nullable teacher-lineage trust for human-only versus teacher-backed releases, permits a null replay audit only for an all-declarative suite, and requires the exact bound audit whenever C# rows are present. When present, it pins the audit path, exact envelope SHA-256, and independent public trust, retains its authenticated payload/envelope hashes in the activation snapshot, and revalidates the audit without Docker before launch and throughout service life. The wrapper also authenticates promotion and selected-base trust, revalidates the exact external snapshot under POSIX read-only mount custody, verifies the pinned executable/version plus the orchestrator-asserted image digest, and launches one deterministic loopback vLLM/LoRA child using the snapshot directory for both model and tokenizer. No mutable model ID, revision, or cache lookup participates. It requires exactly the selected raw-base and promoted-adapter IDs after load, repeats full validation, and only then serves readiness proofs or completions. Config v1-v6 remains parseable for migration but cannot launch. Production still needs protected signer management, a genuinely digest-pinned POSIX image, read-only model storage, external TLS plus DNS/egress controls or mTLS, secret injection, supervision, telemetry, and rollback. The receipt, evaluation-authoring, teacher-lineage, corpus-admission, base-selection, trainer-provenance, verifier-authority, replay-audit, and promotion workflows now have provider-neutral detached signing seams; their direct PEM paths remain local workflow conveniences rather than production key management. The trainer flow deliberately holds no output lock while the external signer acts; its pending artifact subtree has no consumer-authoritative `artifact-metadata.json` and cannot enter any consumer, while the package root retains the non-authorizing core and signing bundle. These handoffs do not close provider IAM/quorum/audit, reviewer or trainer identity, revocation, honest-clock, immutable pending/sealed custody, or privileged host path-swap requirements. HMAC, replay audit, teacher-lineage admission, corpus-quality admission, and the image-digest environment assertion are operational trust signals, not hardware-backed attestation.

For self-hosted economics, set internal input/output tariffs from measured GPU time, utilisation, energy/cloud cost, queue overhead, and target margin. Credits remain server-owned integer product units. The desktop never supplies a model, endpoint, credential, price, token count, or charge.

## Delivery phases

1. **Corpus/evaluation foundation (tooling implemented; content pending):** versioned expert examples, rights validation, immutable corpus/evaluation releases, domain coverage, SFT export, sealed-eval format, artifact/profile-bound capture, paired evidence gates, and signed-authority single-source headless SDK scoring through release-bound aggregation and raw-base selection. A real reviewed sealed suite is still absent.
2. **Candidate baseline and selection (catalog-complete contract implemented; evidence pending):** install all three reviewed student snapshots and the pinned vLLM runtime on suitable server GPUs, deploy the separate-identity owner with protected activation-key custody, a governed external runtime-signing broker, and denied egress, optionally evaluate additional research challengers outside the production shortlist, run controlled/recommended-decoding comparisons, then issue one independent selection-v2 authority over the complete catalog matrix and exact passing snapshot. Trusted response-v2 propagation and the training binding are implemented; no real broker, evidence, or selection exists.
3. **Teacher pipeline (authoring/capture/materialization/lineage-admission foundation implemented):** a one-way fail-closed compiler now derives manifest-v2 capture intent from the source-grounded private draft plus an explicit raw-hash-bound runtime plan, removes the terminal reference answer from every task, rejects those answers from every emitted string value, preserves storage/evaluation-only authority, and binds the raw draft/catalog plus every source byte. A passive Python bridge derives that plan fragment from exact descriptor/template/catalog bytes, requires an already-open canonical loopback vLLM server to expose the derived execution ID and matching reviewed runtime fields, and makes fresh binding revalidation mandatory before and after capture. Candidate rows retain the exact binding-file hash. Source-grounded multi-seed generation, live tokenizer/context-window preflight, exact independent selection, held-out overlap exclusion, immutable OpenWeightTeacher draft materialization, provider-neutral detached exact-lineage admission and receipt signing, C# SFT export, and release-v4/downstream enforcement are implemented. The unsigned receipt bundle is non-authorizing; the signature set's domain-separated exact-bundle signature grants only finalization of that receipt set, and its explicit authority ceiling denies review truth, rights, release, training, evaluation, provider upload, promotion, and deployment. The separate lineage bundle is likewise non-authorizing, but its one admission-envelope signature already covers the complete lineage payload and trust tuple, so no second bundle-authorization signature is needed. These handoff artifacts let an external service sign the exact admission and receipt preimages without giving this process the private key, but they do not provision or attest that service. The manifest is unsigned intent and the runtime binding is explicitly unattested; the reviewer-signed admission authenticates one exact lineage decision but does not independently attest loaded weights/template, image, entrypoint, process ownership, correctness, rights, hardware, or isolation. No real candidate, admission, receipt, or release has been issued. Real server capture, independently attested runtime evidence, integration of compiler/test/risk filtering, subject-matter review, authenticated evidence, and production authorization remain pending.
4. **Adapter training:** issue the independently reviewed exact-corpus admission through its detached custody seam, then run a small stop/go QLoRA SFT pilot, reviewed release-bound verifier rewards for executable tasks if later authorized, matched preference tuning where appropriate, quantisation, and multi-seed evaluation. The headless release scorer is evaluation evidence, not yet an RLVR reward.
5. **Model registry and serving (activation foundation implemented):** signed exact-hash promotion, historical selection-window verification, exact selected-snapshot propagation, trainer-provenance reauthentication, promotion-bound credit/readiness gates, signed teacher-lineage/evaluation-authoring and offline C# replay-audit consumption, and a fail-closed v7 vLLM owner/gateway are implemented; real deployment, production key custody, privileged immutable storage, TLS/network controls, telemetry, reconciliation, and rollback remain.
6. **Strategy-authoring workflow (signed routing foundation implemented):** the hosted purpose, strict source-artifact schema, fixed-role review, exact release gate, API client verification, credit settlement, and Terminal/WPF preview plus source-only import are implemented for inert Mock and signed-policy-authorized OpenAI-compatible specifications. V1 promotions remain Research-only; v2 requires the exact model-bound inert capability and invalidates stale activation bindings when it changes. Production remote authentication, a real reviewed v2 promotion/model, authority-safe integration of the standalone headless verifier, and installation remain pending.

The model is complete only when an exact checkpoint is reproducible, the sealed promotion report passes, the server deployment is hash-pinned, credit settlement is reconciled, and the Terminal can request and receive a reviewed strategy artifact without gaining provider or execution authority.

## Primary sources

- Hinton et al., [Distilling the Knowledge in a Neural Network](https://arxiv.org/abs/1503.02531).
- Hsieh et al., [Distilling Step-by-Step](https://arxiv.org/abs/2305.02301).
- Mukherjee et al., [Orca](https://arxiv.org/abs/2306.02707).
- Gu et al., [MiniLLM / GKD](https://arxiv.org/abs/2306.13649).
- Ko et al., [DistiLLM](https://arxiv.org/abs/2402.03898).
- DeepSeek, [DeepSeek-R1 repository and report](https://github.com/deepseek-ai/DeepSeek-R1).
- Hui et al., [Qwen2.5-Coder technical report](https://arxiv.org/abs/2409.12186).
- Wei et al., [SelfCodeAlign](https://arxiv.org/abs/2410.24198).
- Wei et al., [Magicoder](https://arxiv.org/abs/2312.02120).
- Roziere et al., [CodeRL](https://arxiv.org/abs/2207.01780).
- Hu et al., [LoRA](https://arxiv.org/abs/2106.09685) and Dettmers et al., [QLoRA](https://arxiv.org/abs/2305.14314).
- Rafailov et al., [Direct Preference Optimization](https://arxiv.org/abs/2305.18290).
- Meng et al., [SimPO](https://arxiv.org/abs/2405.14734) and Ethayarajh et al., [KTO](https://arxiv.org/abs/2402.01306).
- Lambert et al., [Tulu 3](https://arxiv.org/abs/2411.15124).
- [SWE-RL: Advancing LLM Reasoning via Reinforcement Learning on Open Software Evolution](https://arxiv.org/abs/2502.18449).
- [Phi-4-Mini-Reasoning](https://arxiv.org/abs/2504.21233), [s1: Simple test-time scaling](https://arxiv.org/abs/2501.19393), and [OpenThoughts: Data Recipes for Reasoning Models](https://arxiv.org/abs/2506.04178).
- [Understanding Knowledge Distillation in Post-Training: When It Helps and When It Fails](https://arxiv.org/abs/2606.22942) and [Compete Then Collaborate](https://arxiv.org/abs/2607.08255). The latter is treated as a fresh single-preprint warning, not a standalone policy basis.
- [Qwen3 technical report](https://arxiv.org/abs/2505.09388) and [Qwen3-Coder-Next technical report](https://arxiv.org/abs/2603.00729).
- Jimenez et al., [SWE-bench](https://arxiv.org/abs/2310.06770), Jain et al., [LiveCodeBench](https://arxiv.org/abs/2403.07974), and [Multi-LCB](https://arxiv.org/abs/2606.20517).
- [LiveCodeBench Pro](https://arxiv.org/abs/2506.11928) for continuously refreshed hard programming evaluation.
- [Qwen2.5-Coder 7B](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct), [Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B), [Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B), [Qwen3-Coder 30B-A3B](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct), [Qwen3-Coder-Next](https://huggingface.co/Qwen/Qwen3-Coder-Next), [Devstral Small 2 24B](https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512), and [gpt-oss-20b](https://huggingface.co/openai/gpt-oss-20b) official model cards.
- vLLM, [serve CLI contract](https://docs.vllm.ai/en/latest/cli/serve/).
- Python Packaging Authority, [PEP 751 dependency lock-file format](https://peps.python.org/pep-0751/), and Astral, [`uv pip compile`](https://docs.astral.sh/uv/pip/compile/).
- Hugging Face, pinned [TRL 0.15.2](https://pypi.org/project/trl/0.15.2/) and [Transformers 4.48.3](https://pypi.org/project/transformers/4.48.3/) package metadata used for the sealed trainer roots.
- Anthropic, [Building effective agents](https://www.anthropic.com/research/building-effective-agents).
- LMSYS, [RouteLLM](https://github.com/lm-sys/RouteLLM).
- OpenAI, [model optimisation](https://developers.openai.com/api/docs/guides/model-optimization), [supervised fine-tuning and distillation](https://developers.openai.com/api/docs/guides/supervised-fine-tuning), and [evaluation guidance](https://developers.openai.com/api/docs/guides/evals).
- AWS KMS, [`Sign`](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html); Azure Key Vault, [`sign`](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign?view=rest-keyvault-keys-2025-07-01); Google Cloud KMS, [`asymmetricSign`](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign); and IETF, [RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4), for provider digest modes and DER/P1363 ECDSA response handling. None of the reviewed provider pages documents a P-256 low-S guarantee, so the local finalizer validates, normalizes, and re-verifies every signature.

OpenAI's current documentation states that its fine-tuning and legacy Evals platforms are being wound down/deprecated. The durable design therefore keeps training and evaluation provider-independent and treats hosted APIs as optional teachers or inference endpoints, subject to current contractual rights.
