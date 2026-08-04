# Hyperion frontier expert-model architecture

Date: 5 August 2026
Status: target architecture; implementation is staged and evidence-gated
Audience: ML research, data, platform, inference, evaluation, security, and product engineering

## 1. Decision

Hyperion will be a **verified expert-model system**, not one monolithic model and not an
unconstrained autonomous trading agent. The target combines:

1. a portfolio of hosted and self-hosted teachers, students, critics, judges, and embedding models;
2. a governed, retrieval-aware corpus for C#, UI engineering, DaxAlgo architecture, mathematics,
   probability, risk, portfolio management, quantitative finance, and strategy research;
3. a staged distillation and post-training factory whose strongest rewards are executable and
   independently verified;
4. a durable coordinator that plans, retrieves, delegates, executes tools, critiques, verifies, and
   requests human release through explicit state transitions;
5. a pluggable inference fabric selected by measured quality, latency, throughput, memory, and cost;
6. a topology-aware GPU cluster that starts with small-model adapter training and scales only when
   evidence justifies distributed complexity; and
7. a signed evidence chain from source and model snapshot through training, evaluation, promotion,
   activation, user charge, and rollback.

Licensing, payment, gated access, and contractual permission do **not** exclude a technically useful
candidate. They are recorded as acquisition and provenance fields whose owner is the user or a
delegated procurement/legal operator. Hyperion does not bypass access controls or invent details that
are absent from an authorised source. A closed model can be a teacher, judge, or benchmark opponent;
undisclosed internals cannot be represented as a reproducible Hyperion architecture.

> Evidence boundary: this document describes the target. The repository currently implements much
> of the coordinator, evidence, training-harness, verifier, promotion, and serving infrastructure,
> but it contains no rights-approved production corpus, conforming training run, trained Hyperion
> checkpoint, accepted quality result, or production deployment.

## 2. Why the architecture is a portfolio

No single current model simultaneously gives Hyperion the best C# generation, quantitative
reasoning, private-architecture grounding, tool use, long-context retrieval, local economics,
determinism, and independent criticism. A portfolio lets each model be used where evidence shows it
is strongest while a stable protocol preserves safety and reproducibility.

| Role | Purpose | Typical candidates | Authority ceiling |
|---|---|---|---|
| Hosted frontier teacher | Generate difficult solutions, critiques, tool trajectories, and contrastive examples | GPT-5.6 Sol/Terra/Luna, Gemini 3.1 Pro, Claude Fable 5, Kimi K3 API | Supplies proposals and labels; never self-approves corpus or release |
| Open-weight large teacher | Reproducible local generation, logits where available, specialist rollout, and benchmark opposition | Kimi K3, Qwen3.5 large MoE, GLM-5/5.2, DeepSeek R1/V3 family, Llama 4, gpt-oss-120b, MiniMax-M2.5 | Same evidence ceiling; weights do not confer correctness |
| Trainable student | Low-cost, private, bounded serving inside Hyperion | gpt-oss-20b, Qwen3/Qwen3-Coder small and active-sparse variants, Qwen3.5-9B, Devstral Small 2, Falcon-H1-34B | Produces drafts and tool actions under coordinator and verifier policy |
| Specialist adapter | Improve one governed domain or effort level | C#/DAXQ, UI, quantitative math, risk, portfolio, research/tool-use adapters | Routed only after domain-specific sealed acceptance |
| Critic/judge | Find errors, compare candidates, estimate uncertainty, and enforce rubrics | Diverse model family from the generator plus deterministic checks | Cannot replace executable verification or human release |
| Router | Choose provider, student, adapter, effort, and fallback from task features and live capacity | Rule baseline followed by calibrated learned router | Cannot route around policy, budget, readiness, or entitlement |
| Embedding/reranker | Retrieve source evidence and detect near-duplicates/contamination | Versioned local embedding model, sparse index, cross-encoder reranker | Retrieval evidence only; never turns retrieved text into trusted truth |

The initial production catalog remains deliberately small and pinned. The broader inventory below is
the challenger and research registry; adding a candidate to it does not silently authorize training,
promotion, or serving.

## 3. Requirements and domain boundary

### 3.1 What the student must know

Hyperion needs depth in a bounded set of knowledge classes:

- modern C#/.NET, Roslyn, async/concurrency, memory, testing, serialization, networking, security,
  desktop UI patterns, WPF/Avalonia, accessibility, and maintainable API design;
- the exact current DaxAlgo/Hyperion architecture, compatibility surfaces, schemas, protocols,
  invariants, coding conventions, and build/test workflows, supplied through versioned retrieval;
- algebra, calculus, linear algebra, optimisation, numerical methods, probability, statistics,
  stochastic processes, time-series analysis, causal reasoning, and uncertainty calibration;
- market microstructure, order types, transaction costs, slippage, data quality, survivorship and
  look-ahead bias, regime change, and backtest design;
- position sizing, drawdown, exposure, liquidity, leverage, concentration, tail and scenario risk;
- portfolio construction, covariance estimation, factor models, constraints, rebalancing, and
  risk-adjusted evaluation; and
- research discipline: falsifiable hypotheses, source provenance, leakage controls, robustness,
  limitations, and explicit separation of observed evidence from inference.

The student does not need encyclopaedic recall of unrelated topics. General language capability is
retained because it supports instruction following and transfer, but volatile private facts live in
retrieval rather than repeatedly baked into weights.

### 3.2 Knowledge placement rule

| Knowledge type | Preferred location | Reason |
|---|---|---|
| Stable programming, mathematics, and finance concepts | Base model plus reviewed SFT/preference data | Reused frequently and changes slowly |
| Current private architecture and product policy | Signed, versioned retrieval pack | Changes often; must be revocable and source-citable |
| Executable behaviour and restricted strategy surface | Tools, schemas, compiler, verifier, and policy | Deterministic enforcement is stronger than memorisation |
| User/project context | Per-run bounded context | Tenant isolation, freshness, deletion, and least privilege |
| Sealed evaluation answers and hidden verifier cases | Independent evaluation custody only | Prevents leakage and reward hacking |
| Model/provider prices and capacity | Server-side live catalog | Operational state is not model knowledge |

## 4. Seven-plane target architecture

### 4.1 Governance and control plane

The control plane owns identities, tenants, entitlements, model/provider registry, budget and credit
policy, run state, approvals, queues, immutable manifests, audit events, promotion, activation, and
rollback. Every mutable choice resolves to a versioned object before execution. Clients may request
an objective and public evidence; they cannot select an unapproved endpoint, artifact, price,
retrieval pack, or verifier authority.

### 4.2 Data and knowledge plane

The data plane ingests only attributable source objects. Each object records origin, exact bytes,
hash, collection time, knowledge class, permission/licence record, confidentiality, tenant, retention,
review state, and contamination group. It produces four distinct products:

1. a versioned retrieval corpus and hybrid sparse/dense index;
2. reviewed SFT conversations and tool trajectories;
3. preference or ranking pairs with explicit rubric and reviewer lineage; and
4. sealed calibration, development, and promotion suites held outside training access.

Near-duplicate and semantic-cluster assignment happens before splitting. Time, repository, author,
task family, and derivation groups stay in one split. Generated examples retain every teacher,
prompt, sampling, tool, environment, verifier, selector, and human-review identity.

### 4.3 Model factory plane

The factory resolves exact base/tokenizer/template snapshots, runs raw-base bake-offs, prepares
reviewed datasets, trains adapters or full checkpoints, executes verifier-grounded post-training,
quantizes deployment candidates, and publishes only content-addressed safe artifacts. It never
promotes its own output.

### 4.4 Coordinator and agent-runtime plane

The runtime turns one approved objective into a durable typed graph. A deterministic controller owns
budgets and terminal states; models propose plans and actions inside that controller. Each event binds
the observation, role, model/adapter, prompt or state hash, visible response, tool call, tool result,
environment revision, latency, token/cost usage, and verifier outcome. A process crash can resume an
explicit interrupted state without pretending an uncertain provider/tool call never occurred.

### 4.5 Verification and evaluation plane

Deterministic checks run before model judging: schema validation, compilation, static policy, unit and
property tests, numerical tolerances, DAXQ/C# replay, risk invariants, source-citation checks, and
artifact hash validation. Diverse model judges and human reviewers cover qualities that cannot be
fully mechanised. Hidden cases, mutation tests, limited submissions, and independent replay audit
test the verifier itself.

### 4.6 Inference fabric

An engine-neutral gateway serves pinned model profiles through vLLM first, benchmarks SGLang for
prefix-heavy agent traffic, and may adopt TensorRT-LLM for stable NVIDIA deployments. llama.cpp or
another CPU/edge runtime is a compatibility lane, not the main server baseline. The fabric owns
continuous batching, cache admission, structured decoding, quantized artifact identity, streaming,
cancellation, observability, overload, and fallback.

### 4.7 Cluster and operations plane

A dedicated scheduler assigns training, rollout, evaluation, and serving to qualified GPU resources.
Central immutable storage holds governed datasets and model artifacts; workers stage hash-verified
read-only inputs on local NVMe. Secrets and signing keys stay outside model workers. Metrics bind
software, topology, GPU power/temperature/errors, memory, collectives, queue time, tokens, cost, and
quality evidence to each run.

## 5. Model and mechanism registry

### 5.1 Registry contract

The online model landscape is unbounded and continuously changing. Hyperion therefore maintains a
dated registry rather than claiming a permanent exhaustive list. Every record requires:

- provider, family, exact model/revision, release/card date, source URL, source snapshot/hash, and
  last verified date;
- access mode: API, downloadable weight, gated download, licensed package, or research description;
- owner for account, payment, licence/permission, attribution, acceptable-use, and renewal;
- modality, context/output limits, total and active parameters where disclosed, architecture facts,
  tokenizer/template, tool protocol, reasoning/effort modes, and output constraints;
- supported precision/quantization, measured VRAM/RAM/disk, runtime compatibility, throughput,
  latency, energy, queue behaviour, and expected credit cost;
- allowed Hyperion roles, data-handling class, geographic/retention constraints, and fallback; and
- evidence state: discovered, source-reviewed, acquisition-ready, smoke-tested, benchmarked,
  selected, trained, promoted, activated, retired, or rejected with reason.

An unknown or undisclosed field stays `unknown`; it is never inferred from benchmark performance.
Licence or cost can affect an operator's acquisition decision but is not a technical-ranking penalty.

### 5.2 Current frontier inventory

The following is a source-reviewed architecture inventory as of 5 August 2026, not a promotion list.

| Family | Publicly disclosed design/useful fact | Hyperion use | Adoption state |
|---|---|---|---|
| OpenAI GPT-5.6 Sol/Terra/Luna | Official portfolio exposes different quality/latency roles, reasoning effort, tools, persisted state, and caching; internals are undisclosed | API teacher, critic, judge, agent-trajectory source | Integrate through provider adapter; measure each role |
| OpenAI gpt-oss-20b/120b | MoE open weights; official guidance places 20b near a 16 GB MXFP4 footprint and 120b on roughly one 80 GB GPU; Harmony format and expert-module tuning matter | 20b student/baseline; 120b local teacher | 20b first-tier candidate; 120b hardware-gated |
| Moonshot Kimi K3 | 2.78T total/104.2B active, KDA plus Gated MLA, Stable LatentMoE, native vision, 1M context, effort specialists, long agent rollouts, and deployment-aware low precision are reported | API/open teacher; system-design source; small ablation research | Teacher evaluation; full model not a small-cluster student |
| Qwen3/Qwen3-Coder | Dense 0.6B-32B and active-sparse variants; thinking/non-thinking modes, tool use, long context, and executable agent training across practical sizes | Primary local student/teacher family and code specialist | Immediate expanded bake-off after runtime validation |
| Qwen3.5 large MoE | Hybrid Gated DeltaNet/full attention, MoE, early-fusion multimodality, MTP, and very long context in the reviewed 397B-A17B card | Large teacher; hybrid-attention and MTP ablations | Hardware/API evaluation; pretraining research |
| DeepSeek V3/R1/V3.2 line | MLA/DeepSeekMoE, multi-token prediction, FP8, auxiliary-loss-free balancing, sparse-attention experiments; R1 demonstrates cold-start plus RL and distillation | Reasoning teacher, verifier-RL reference, architecture ablations | Teacher/evaluation now; mechanisms require research runs |
| GLM-5/5.2 line | Large MoE, sparse-attention/IndexShare disclosures, long context, asynchronous RL, effort controls, and MTP improvements are reported | Large coding/agent teacher and sparse-attention research | Version-pinned evaluation; claims need reproduction |
| Meta Llama 4 Scout/Maverick | Native early-fusion multimodal MoE and iRoPE; Scout/Maverick activate a smaller parameter subset; very-long-context claims are vendor-reported | Open teacher/challenger; multimodal and iRoPE research | Hardware-gated evaluation |
| Google Gemini 3.1 Pro | Official card exposes native text/audio/image/video/code-repository reasoning and long context; internals are undisclosed | Multimodal/long-context API teacher and judge | Provider adapter and data-policy review |
| Anthropic Claude Fable 5 | Official release emphasises long-horizon coding, vision, files, and long-context work; internals are undisclosed and availability is version-sensitive | Coding/agent teacher and independent critic | Provider adapter and version-pinned evaluation |
| MiniMax-M2.5 | Official material emphasises large-scale environment RL, process rewards, agent/tool trajectories, and task-completion-time evaluation | Open agent teacher and post-training reference | Exact artifact/runtime evaluation |
| Devstral Small 2 24B | 24B code/agent model with long-context tool-oriented positioning in the official model card | Trainable code-agent challenger | Small-cluster bake-off |
| Falcon-H1-34B | Transformer-Mamba hybrid base with mainstream runtime support | Hybrid recurrent-attention challenger | Evaluate after instruct/post-training plan is defined |

Primary claims and links are collected in section 16. Benchmark tables from different vendors are
not compared directly because prompts, tools, sampling, budgets, hardware, and scoring differ.

### 5.3 Mechanism adoption ledger

| Mechanism | Value hypothesis | Hyperion decision | Proof required |
|---|---|---|---|
| Dense decoder transformer | Simplest training, tuning, serving, and debugging baseline | Keep at least one dense student in every bake-off | Quality/cost baseline and multi-seed stability |
| Sparse MoE | More capacity per active FLOP | Use existing small active-sparse bases; do not build MoE first | Router balance, expert utilisation, all-to-all cost, quality per joule |
| GQA/MLA/latent KV | Reduce KV memory and long-context cost | Prefer supported upstream implementations | Exact engine compatibility and quality/latency/memory curves |
| Sparse attention/IndexShare | Lower long-context compute | Research only until public implementation and task evidence exist | Recall at distance, short-context non-regression, kernel stability |
| DeltaNet/KDA/recurrent linear attention | Better long-context scaling and persistent state | Small pretraining ablations; not a LoRA retrofit | Controlled dense-attention comparison at equal data/compute |
| Transformer-Mamba hybrid | Linear recurrent path plus selective full attention | Evaluate Falcon-H1; optionally pretrain a small ablation | Code/math quality, retrieval, state drift, runtime coverage |
| Multi-token prediction | Training signal and speculative/inference opportunity | Use only where base/runtime supports it; pretraining ablation otherwise | Acceptance, quality parity, real latency/throughput benefit |
| Early-fusion multimodality | UI screenshot, chart, PDF, and code-repository reasoning | Use hosted/open teachers first; defer student multimodal pretraining | Modality-specific sealed tests and privacy handling |
| RoPE scaling/YaRN/iRoPE | Extend context without full retraining | Conditional runtime profile, never a marketing number | Length-stratified dependency tasks, perplexity, memory, latency |
| FP8/MXFP4/MXFP8/QAT | Reduce training/serving cost | Use upstream-supported formats after exact-artifact evaluation | Accuracy and verifier parity, kernel/hardware portability, rollback |
| Attention Residuals/Stable LatentMoE/Muon variants | Potential scaling, optimisation, and expert-routing gains | Kimi-inspired small-model research track | Isolated ablations before combined-scale claims |

### 5.4 Kimi K3 adoption boundary

The 5 August 2026 recheck found no arXiv revision after `2607.24653v1`; Moonshot's official
repository remains at `7c5be9599120d7993748de66a76128614f15f210`, and the public model snapshot
remains `9f62e4e9fffbd0a83ddd60e1c209d828994b3569`. Hyperion uses the following explicit
decision boundary rather than treating the K3 report as one indivisible recipe.

| K3 source area | Hyperion decision | Why | Required proof |
|---|---|---|---|
| Effort-conditioned specialists, per-task budgets, outcome-state rewards, hidden verifiers | Adopt in the target workflow and experiment contracts | Fits the existing authority and evaluation model without changing a student backbone | Budget-conditioned quality/cost curves, hidden-case stability, reward-hacking audit |
| Scope-aware options, indexed tool calls, preserved continuation state | Adopt as provider-capability and transcript requirements, not as a copied template | Prevents silent semantic loss across providers while keeping private state separate from human rationale | Round-trip parity, field-level retention/deletion, provider-policy and privacy review |
| Cache-pressure throttling, cache-aware affinity, request-class budgets, resumable sandboxes | Adopt as operations targets at measured Hyperion scale | Protects short work and preserves long-running state without assuming K3-scale hardware | Load/failover tests, bounded re-prefill, starvation and recovery evidence |
| Routed effort/domain adapters, structured judge scorepads, quantization-consistent training/serving, acceptance-aware draft models | Controlled evaluation | Each depends on the selected base, runtime, data, and independent quality evidence | Frozen baselines, verifier parity, calibration, acceptance, latency, memory, rollback |
| KDA, Attention Residuals, Stable LatentMoE, Quantile Balancing, SiTU-GLU, per-head Muon, MoonEP | Equal-compute pretraining research only | These change the backbone, optimiser, or distributed system and cannot be faithfully added by QLoRA | Isolated multi-seed ablations, topology telemetry, quality per token/cost/joule |
| Full 2.78T/104.2B-active K3 training on the proposed small cluster | Reject as the student plan | The public compressed snapshot alone is about 1.42 TiB before runtime or training state | A separately funded large-cluster plan would require its own capacity and custody review |

These rows change the target architecture and experiment backlog; they do not claim a Hyperion K3
integration, copied implementation, trained specialist, reproduced benchmark, or production runtime.

## 6. Data and retrieval design

### 6.1 Corpus lanes

Hyperion keeps source material, training examples, preferences, trajectories, and evaluation cases in
separate stores and schemas. Suggested target mix is a measurement input, not a fixed quota:

| Lane | Examples | Verification |
|---|---|---|
| C# and platform engineering | compilation, refactors, diagnostics, tests, APIs, persistence, concurrency | compiler, analyzers, unit/property tests, API contract checks |
| UI engineering | WPF/Avalonia layouts, state, accessibility, interaction, visual contracts | compile, accessibility rules, deterministic screenshot/interaction tests |
| DaxAlgo architecture | routed source-grounded questions, change plans, compatibility and protocol decisions | exact source citations, dependency/context checks, build/test gates |
| Mathematics/probability | derivations, proofs, numerical calculations, simulation | symbolic/numeric oracle, tolerances, invariant/property tests |
| Quantitative finance | features, estimators, execution costs, leakage-resistant experiments | causal/time split, code replay, statistical and data-lineage audit |
| Risk and portfolio | limits, sizing, covariance/factors, scenarios, constraints | deterministic constraint/risk engine and scenario tests |
| Agent/tool use | repository tasks, terminal/tool calls, recovery, structured outputs | pinned sandbox, tool schema, terminal state, final verifier |
| Safety/refusal | prohibited execution, missing evidence, uncertainty, escalation | policy cases, mutation tests, human/security review |

Difficulty, domain, language/runtime, task family, reasoning type, effort, tool need, expected output,
and verifier are explicit labels. Curriculum starts with clean short tasks, adds multi-step and
cross-domain cases, then long-context/agent trajectories only when earlier gates are stable.

### 6.2 Retrieval pipeline

1. resolve the run's approved corpus/version and tenant boundary;
2. apply metadata and access filters before semantic retrieval;
3. combine lexical search with dense retrieval;
4. rerank a bounded candidate set and diversify near-duplicates;
5. expand only graph/document neighbours explicitly linked to selected evidence;
6. construct a token-budgeted context with stable source IDs and exact excerpts;
7. require claims to cite those IDs; and
8. store retrieval query, index/version, candidates, scores, selected chunks, and context hash.

The model may state that evidence is missing. It must not fill a private-architecture gap from
memorised or retrieved-but-unauthorised text.

## 7. Training and distillation ladder

Each stage must beat the frozen raw base and strongest relevant baseline on predeclared sealed
criteria without unacceptable domain, safety, latency, or cost regression. A later technique is not
started merely because an earlier job completed.

### Stage 0: raw-base and retrieval bake-off

Evaluate unmodified candidates with and without the same retrieval pack. This separates base-model
ability from retrieval quality and gives a stop/go threshold before training expense.

### Stage 1: verified supervised fine-tuning

Train QLoRA/LoRA adapters first on reviewed human examples and verified teacher sequences. Retain
both accepted and rejected attempts in provenance. For gpt-oss MoE students, target supported expert
projections as well as attention according to the official recipe. Compare teacher-answer imitation
against solution-plus-verification trajectories; coding students can regress when trained on weak or
style-mismatched answers.

### Stage 2: preference optimisation

After SFT is stable, test DPO first because it avoids an online reward-model/PPO stack. SimPO, KTO,
or another objective is a controlled challenger when its data assumptions match. Preference pairs
must expose rubric, tie/abstention, confidence, teacher/human identities, and leakage group. Judge
agreement alone is not ground truth.

### Stage 3: reinforcement learning with verifiable rewards

Pilot RLOO and GRPO under identical tasks, sampling, KL policy, compute, and evaluator. Reward exact
compiler/test/numeric/tool/risk outcomes, bounded format compliance, and cost/length penalties. Log
group composition, zero-variance groups, KL, entropy, response length, reward components, invalid
actions, and verifier reliability. Do not use backtest PnL, Sharpe, or public benchmark rank as a
direct reward.

Process reward models can provide auxiliary credit assignment, but executable outcomes dominate
where available. DAPO/large asynchronous RL systems are later pilots after small-scale correctness,
reward-hacking audits, and reproducible gains.

For long-horizon or non-verifiable work, bind a per-task token/tool/time budget and require a
structured judge record: inspected outcome, rubric identity, criterion scores, evidence references,
and verbosity guard. Judge output never overrides deterministic failure or human release.

### Stage 4: on-policy and multi-teacher distillation

Route each prompt to teachers that passed a domain-specific calibration suite. Preserve disagreements
and teacher provenance rather than averaging them away. Use student-generated prefixes/trajectories
to reduce train/serve mismatch. Token-level on-policy distillation requires authorised teacher logits
or probabilities; hosted text alone supports sequence-level SFT or ranking, not the same objective.

### Stage 5: specialist routing and consolidation

Train separate C#/architecture, quant/math, risk/portfolio, UI, and research/tool-use adapters, each
at measured effort levels. Start with deterministic routing and adapter isolation. A learned router
must beat rules on calibration, abstention, cost, and worst-domain quality. Adapter merging or
multi-teacher consolidation is allowed only after every source specialist passes its own frozen gate
and the merged model proves no specialist regression.

### Stage 6: architecture/pretraining research

KDA/DeltaNet, sparse attention, Attention Residuals, Stable LatentMoE, MTP, early-fusion vision,
Muon variants, and novel expert balancing are pretraining changes. They cannot be faithfully added
to an existing Qwen/gpt-oss model with QLoRA. Test them in small controlled models at equal data,
tokens, wall time, and hardware before considering a larger foundation-model run.

## 8. Coordinator and agent runtime

### 8.1 Typed role graph

The current five-role workflow remains the safe baseline. The target runtime generalises it to a
bounded graph whose nodes have explicit input/output schemas and authority:

- **Planner** decomposes the objective, success criteria, dependencies, budget, and stop conditions.
- **Retriever/Researcher** obtains permitted evidence and reports source/coverage gaps.
- **Architect/Quant analyst** develops equations, assumptions, experiment design, and risk model.
- **Coder/UI specialist** produces inert source or design artifacts.
- **Executor/Tester** invokes approved tools inside a pinned environment.
- **Critic** searches for logical, statistical, architectural, security, and usability defects.
- **Risk judge** evaluates policy and residual risk but cannot falsify deterministic evidence.
- **Synthesizer** reconciles verified results into the final deliverable.
- **Human releaser** approves exact final bytes and any capability escalation.

The planner may request parallel specialists, but the controller enforces a maximum graph width,
depth, requests, tokens, tool calls, elapsed time, cost, and artifact size. Every loop has an explicit
progress predicate and attempt limit. A model cannot create a new role, tool, endpoint, or budget.

### 8.2 Routing

Routing inputs include domain labels, estimated difficulty, modality, context length, tool need,
privacy class, latency target, credit budget, availability, historical calibrated quality, and live
queue/KV pressure. The router selects model, adapter, effort, sampling profile, context policy, and
fallback. It emits a reason code and confidence; low confidence or high risk invokes a stronger model
or human review. Provider/model identity is frozen into the invocation before charging.

Effort is a provider capability, not a universal string. The registry records the supported levels,
token semantics, defaults, and mapping for each exact revision. A request for an unsupported level
fails or follows an explicitly evaluated fallback; Hyperion never silently maps K3's
`low`/`high`/`max`, another provider's `medium`/`xhigh`, or an internal token budget onto each other.

### 8.3 Tools and environments

Every tool has a versioned JSON schema, capability class, allowed roles, filesystem/network scope,
timeout, byte/result limits, idempotency semantics, audit redaction policy, and verifier. Read tools,
mutation tools, execution tools, signing, deployment, and trading authority are separate. Generated
strategy source remains inert; it cannot install itself, access a broker, or place an order.

The normalized transcript keeps user-visible response, indexed tool calls, typed arguments, tool
results, scope, and provider extension state distinct. Global session options, one-request options,
and dynamically introduced tools are separately versioned so a cache or replay cannot apply an
option outside its scope. Provider-native templates such as K3's XTML remain behind adapters; they
are not copied into the cross-provider contract.

### 8.4 Memory

Hyperion uses four explicit memory classes:

1. immutable run/event memory for recovery and audit;
2. versioned retrieval memory for shared/private knowledge; and
3. optional user-approved summaries with source lineage, expiry, tenant, and deletion; and
4. restricted provider continuation state required for multi-turn fidelity, encrypted and isolated
   by tenant, provider, model revision, purpose, and expiry.

Hidden chain-of-thought is not required for audit. Store visible rationale, claims, sources, tool
events, decisions, and verifier results. A provider such as Kimi K3 may require its complete prior
assistant message, including reasoning and tool state, for compatible continuation; that state is
not human rationale, ordinary logging, a corpus row, or training data. Retain it only when the
provider contract and privacy policy permit it, and measure a stateless or compaction fallback.

## 9. Evaluation and promotion

### 9.1 Scorecard

| Dimension | Measures |
|---|---|
| Correctness | compile/test/pass rate, numeric tolerance, exact constraints, source-grounded claims |
| Robustness | mutation tests, paraphrase/scaffold variants, seeds, adversarial and out-of-distribution cases |
| Calibration | confidence/error curves, abstention quality, selective risk, judge disagreement |
| Agent quality | tool selection/arguments, valid state transitions, recovery, attempts, completion time |
| Safety | forbidden capability attempts, secret/privacy leakage, risk-limit violations, unsafe imports |
| Efficiency | tokens, tool calls, latency percentiles, GPU seconds, energy, memory, throughput, credit cost |
| Human utility | correctness, clarity, maintainability, review burden, edit distance to accepted artifact |

Report pass@1 and pass@k separately, with bootstrap confidence intervals or paired uncertainty where
appropriate. A benchmark score is not comparable across changed prompts, tools, budgets, sampling,
environment, or verifier. Public suites such as SWE-bench, LiveCodeBench, IFEval, ToolSandbox,
tau-bench, HELM-style scenario reporting, and later OSWorld/WebArena are diagnostic lanes; Hyperion's
promotion gate is a sealed domain suite with exact environment and evidence identities.

### 9.2 Promotion rule

A candidate can be promoted only when it:

1. beats the frozen raw base and strongest currently promoted baseline on predeclared primary gates;
2. stays within domain-specific non-inferiority margins on every protected slice;
3. passes verifier mutation/reward-hacking and contamination audits;
4. meets latency, memory, throughput, energy, reliability, and credit-economics budgets;
5. reproduces across required seeds/hardware or explains an approved deterministic exception;
6. has independent replay plus human safety/quality review; and
7. binds the exact model, adapter, quantization, tokenizer/template, engine, image, arguments, policy,
   retrieval release, and evaluation report in a signed activation envelope.

## 10. Inference architecture

### 10.1 Engine lanes

| Lane | Default use | Decision |
|---|---|---|
| vLLM | First self-hosted baseline with PagedAttention, continuous batching, distributed serving | Adopt first and pin image/engine/model arguments |
| SGLang | Prefix-heavy agent workflows, structured generation, cache reuse | Benchmark against vLLM on actual traffic |
| TensorRT-LLM | Mature NVIDIA-only, throughput-critical stable models | Pilot after architecture/quantization freezes |
| llama.cpp/CPU edge | Development, compatibility, low-rate local/offline cases | Optional non-production-quality lane unless promoted separately |

The gateway owns a common request/response envelope while preserving provider-specific tool and
reasoning fields in versioned extensions. Unsupported fields fail closed rather than silently
changing semantics.

### 10.2 Performance features

- continuous batching and chunked prefill are controlled by latency-class queues;
- prefix/KV caching keys include model, adapter, template, policy, retrieval/context, and privacy
  identity; tenant-private cache entries are never shared;
- cache-aware affinity may pin a session to a primary worker/cluster plus a bounded failover target;
  failover cost and cold re-prefill are measured rather than hidden;
- separate admission budgets protect short inference, long context, rollout, training, and sealed
  evaluation from one another using queue, active-request, memory, and KV-pressure signals;
- speculative decoding, Medusa, or EAGLE is a measured pilot whose acceptance, tail latency, memory,
  and output-distribution parity must pass; when a compatible MTP/draft path exists, compare an
  acceptance-rate-oriented objective with ordinary KL training;
- FlashAttention is consumed through supported framework/runtime paths before custom kernels;
- AWQ, GPTQ, SmoothQuant, FP8, and MXFP formats are separate promoted artifacts, not runtime flags
  applied to an unmeasured checkpoint;
- prefill/decode disaggregation is deferred until traffic and network measurements show a benefit;
- overload returns bounded queue/retry signals and never silently routes private work to an
  unapproved provider; and
- canary, shadow, rollback, and kill-switch paths operate on immutable activation IDs.

## 11. Small-cluster architecture

### 11.1 Compute tiers

| Tier | Intended work | Typical strategy |
|---|---|---|
| A: one or two GPUs | 4B-14B dense and roughly 20B active-sparse QLoRA/SFT, evaluation, development serving | Single-node data path; avoid distributed complexity |
| B: four to eight homogeneous GPUs | 24B-70B adapters, larger context, parallel seeds, verifiable-RL rollouts | FSDP first; data parallel across jobs; measure before model parallel |
| C: multi-node fast fabric | 100B+ models, larger full fine-tunes, MoE/expert parallelism, pretraining research | Megatron/DeepSpeed/context/expert parallel only after topology qualification |

Actual fit depends on precision, active/total weights, sequence length, activations, optimizer,
attention implementation, batch/accumulation, checkpointing, KV cache, and runtime. Marketing
parameter counts are not capacity plans.

### 11.2 Scheduler and distributed stack

Use Slurm for a dedicated small cluster, with one scheduler owning the GPUs. Use PyTorch FSDP and
TorchTitan as the first distributed-training baseline. Add DeepSpeed ZeRO/offload only when measured
memory or throughput requires it. Megatron Core and expert/context parallelism belong to Tier C.
TRL is the first post-training implementation; veRL, OpenRLHF, NeMo RL, and Ray become candidates
when disaggregated rollout/training throughput—not correctness—is the bottleneck. Kubernetes,
Volcano/Kueue, and the NVIDIA GPU Operator are an alternative service/multi-tenant profile, not a
second competing scheduler on the same pool.

### 11.3 Hardware qualification

Before training, inventory every GPU/serial/VRAM, CPU/NUMA, RAM, PCIe/NVLink, NIC, NVMe, firmware,
driver, CUDA, kernel, container runtime, power, cooling, and clock. Run sustained burn-in,
`nvidia-smi topo -m`, CUDA peer-to-peer tests, and `nccl-tests`; retain the bandwidth/latency matrix.
Keep tensor/expert parallel groups inside fast NVLink domains and prefer data/pipeline parallelism
across slower links. Record ECC/Xid, throttling, power, temperature, clocks, OOM, and collective
failures with the run.

Use 10 GbE only for management, artifact distribution, and independent single-node jobs; it is not
a distributed-training fabric. Require measured 25 GbE or faster for any cross-node collective, and
prefer qualified 100 GbE/RDMA for Tier C or sustained model/expert parallel work. Enable
RDMA/RoCE/InfiniBand only after fabric, MTU, congestion, isolation, and failure tests. Central object
storage and registry are backed up and optionally object-locked. Local NVMe is a disposable verified
cache, not authority.

### 11.4 Workload isolation

Separate queues and capacity reservations for interactive inference, long-context inference,
teacher capture, training, RL rollout, sealed evaluation, and adversarial verification. Training
cannot starve paid inference; serving cannot reuse sealed evaluation data; verifier workers cannot
read corpus/model secrets. Adversarial agent execution moves to microVM or separate-host isolation
with immutable images, bounded files, denied-by-default egress, and explicit teardown.

## 12. Credits and service economics

Credits are integer product units owned by the server. A quote freezes the approved model/adapter,
effort, maximum input/output/tool budget, retrieval policy, and price version. Start reserves the
maximum; completion settles trusted measured usage; eligible failure/cancellation refunds by policy.
The client cannot report its own tokens, price, model, readiness, or settlement.

Internal cost models use measured GPU seconds, reserved capacity, energy/cloud cost, storage and
network, provider charges, queue overhead, failed/retried work, verifier/human-review cost, and target
margin. Quality routing may spend a more expensive teacher during offline data generation while a
small promoted student serves users. Every credit tier has an explicit quality/latency/effort SLA.

## 13. Security, provenance, and permission operations

The user's willingness to obtain permissions changes procurement policy, not the need for
reproducibility and custody. For every external model, dataset, paper/code implementation, or service:

1. record the authoritative source and exact acquired revision/bytes;
2. record price, licence/contract/terms snapshot, attribution, usage restrictions, data retention,
   geographic constraints, and the accountable permission owner;
3. acquire it through authorised credentials or vendor channels; never bypass access controls;
4. scan weights/code/images and produce SBOM, vulnerability, signature, and hash records;
5. isolate untrusted remote code and custom kernels; prefer safe weights and reviewed code;
6. bind any derived corpus/checkpoint to its upstream sources and permissions; and
7. support expiry, revocation, replacement, deletion, and model/data lineage queries.

Permission status never substitutes for technical evidence. Conversely, a custom or commercial
licence is not a reason to discard a technically superior candidate when the owner has secured the
required access.

## 14. Implementation sequence

### Phase 1: expand evidence, not production authority

- add the registry fields and challenger set without changing signed production catalog semantics;
- build domain-labelled sealed calibration suites and retrieval/no-retrieval raw-base comparisons;
- add provider adapters for selected hosted teachers with data/retention controls; and
- establish reproducible vLLM profiles for gpt-oss-20b and practical Qwen3/Qwen3-Coder challengers.

### Phase 2: first expert student

- run reviewed QLoRA SFT on the best raw base;
- compare against the unchanged raw base and retrieval baseline across multiple seeds;
- test DPO only if SFT passes; and
- promote nothing unless correctness, safety, efficiency, and independent replay gates pass.

### Phase 3: verifiable reasoning and specialists

- add compiler/test/math/risk outcome rewards and compare RLOO with GRPO;
- train isolated C#/architecture, quant/math, risk/portfolio, UI, and agent/tool adapters;
- introduce calibrated routing and low/high/max effort profiles; and
- capture immutable trajectories with persistent sandbox/resume state.

### Phase 4: multi-teacher and cluster scale-out

- route teachers by measured domain strength and retain disagreements;
- test on-policy distillation only where authorised logits/probabilities exist;
- qualify the homogeneous cluster, Slurm, FSDP, NCCL topology, storage, and failure recovery; and
- evaluate larger open teachers and inference optimisations under exact profiles.

### Phase 5: architecture research

- pretrain small controlled DeltaNet/KDA, sparse-attention, Mamba-hybrid, MTP, MoE, and multimodal
  ablations at equal compute/data;
- reproduce vendor claims before scaling;
- choose architecture changes only on Hyperion-domain quality per cost/joule; and
- consider larger foundation pretraining only after data scale, cluster telemetry, and evaluation
  reliability justify it.

## 15. Definition of done

The expert-model program is complete only when current evidence proves all of the following:

- an approved, versioned corpus and sealed evaluation release exist with contamination controls;
- a catalog-complete raw-base selection is independently signed;
- an exact training run is reproducible from pinned inputs/runtime and produces a safe artifact;
- the candidate beats the raw base and promoted baseline on predeclared domain gates without
  protected-slice regression;
- reward/verifier reliability, safety, calibration, efficiency, and cluster failure tests pass;
- independent replay, human review, promotion, activation, and rollback records bind exact bytes;
- serving is hash-pinned, observable, capacity-tested, and reconciles credits correctly; and
- the Terminal receives a reviewed inert strategy artifact without gaining provider, signing,
  installation, broker, or execution authority.

Passing infrastructure tests alone does not satisfy these conditions.

## 16. Primary sources

All online sources below were accessed 31 July 2026 and the Kimi K3 sources were rechecked 5 August
2026. Version-sensitive claims must be rechecked before an experiment or purchase.

### 16.1 Models and architecture

- OpenAI, [latest model guide](https://developers.openai.com/api/docs/guides/latest-model) and
  [gpt-oss repository](https://github.com/openai/gpt-oss).
- Moonshot AI, [Kimi K3 paper](https://arxiv.org/abs/2607.24653),
  [official repository](https://github.com/MoonshotAI/Kimi-K3), and
  [technical article](https://www.kimi.com/blog/kimi-k3).
- Qwen, [Qwen3](https://github.com/QwenLM/Qwen3),
  [Qwen3-Coder](https://github.com/QwenLM/Qwen3-Coder), and
  [Qwen3.5-397B-A17B model card](https://huggingface.co/Qwen/Qwen3.5-397B-A17B).
- DeepSeek, [DeepSeek-V3](https://github.com/deepseek-ai/DeepSeek-V3),
  [DeepSeek-R1](https://github.com/deepseek-ai/DeepSeek-R1), and
  [DeepSeek-V3.2-Exp](https://github.com/deepseek-ai/DeepSeek-V3.2-Exp).
- Z.ai, [GLM-5 repository](https://github.com/zai-org/GLM-5) and
  [GLM-5.2 article](https://z.ai/blog/glm-5.2).
- Meta, [Llama 4 announcement and architecture summary](https://ai.meta.com/blog/llama-4-multimodal-intelligence/).
- Google DeepMind, [Gemini 3.1 Pro model card](https://deepmind.google/models/model-cards/gemini-3-1-pro/).
- Anthropic, [Claude Fable 5 and Mythos 5 announcement](https://www.anthropic.com/news/claude-fable-5-mythos-5).
- MiniMax, [MiniMax-M2.5 model card](https://huggingface.co/MiniMaxAI/MiniMax-M2.5).
- TII, [Falcon-H1-34B model card](https://huggingface.co/tiiuae/Falcon-H1-34B-Base) and
  [technical report](https://arxiv.org/abs/2507.22448).
- Mistral, [Devstral Small 2 24B model card](https://huggingface.co/mistralai/Devstral-Small-2-24B-Instruct-2512).

### 16.2 Distillation and post-training

- Hinton et al., [Distilling the Knowledge in a Neural Network](https://arxiv.org/abs/1503.02531).
- Ouyang et al., [InstructGPT](https://arxiv.org/abs/2203.02155), and Rafailov et al.,
  [Direct Preference Optimization](https://arxiv.org/abs/2305.18290).
- Dettmers et al., [QLoRA](https://arxiv.org/abs/2305.14314).
- Ahmadian et al., [RLOO](https://arxiv.org/abs/2402.14740), and DeepSeek,
  [DeepSeekMath/GRPO](https://arxiv.org/abs/2402.03300).
- DeepSeek, [DeepSeek-R1](https://arxiv.org/abs/2501.12948), and Open-Reasoner-Zero,
  [RL with verifiable rewards](https://arxiv.org/abs/2503.24290).
- OpenAI, [Let's Verify Step by Step](https://arxiv.org/abs/2305.20050) and
  [Training Verifiers](https://arxiv.org/abs/2110.14168).
- Agarwal et al., [GKD](https://arxiv.org/abs/2306.13649), and Gu et al.,
  [MiniLLM](https://arxiv.org/abs/2306.08543).
- Wan et al., [DPO/large-scale reasoning optimisation (DAPO)](https://arxiv.org/abs/2503.14476).

### 16.3 Agents and evaluation

- Yao et al., [ReAct](https://arxiv.org/abs/2210.03629).
- Jimenez et al., [SWE-bench](https://arxiv.org/abs/2310.06770), and Yang et al.,
  [SWE-agent](https://arxiv.org/abs/2405.15793).
- Zhou et al., [tau-bench](https://arxiv.org/abs/2406.12045), and Wu et al.,
  [ToolSandbox](https://arxiv.org/abs/2408.04682).
- Liang et al., [HELM](https://arxiv.org/abs/2211.09110), Zhou et al.,
  [IFEval](https://arxiv.org/abs/2311.07911), and Jain et al.,
  [LiveCodeBench](https://arxiv.org/abs/2403.07974).
- Zhou et al., [WebArena](https://arxiv.org/abs/2307.13854), and Xie et al.,
  [OSWorld](https://arxiv.org/abs/2404.07972).

### 16.4 Inference and cluster systems

- Kwon et al., [vLLM/PagedAttention](https://arxiv.org/abs/2309.06180), and
  [vLLM repository](https://github.com/vllm-project/vllm).
- Zheng et al., [SGLang](https://arxiv.org/abs/2312.07104), and
  [SGLang repository](https://github.com/sgl-project/sglang).
- NVIDIA, [TensorRT-LLM](https://github.com/NVIDIA/TensorRT-LLM).
- Dao et al., [FlashAttention](https://arxiv.org/abs/2205.14135) and
  [FlashAttention-2](https://arxiv.org/abs/2307.08691).
- Leviathan et al., [speculative decoding](https://arxiv.org/abs/2211.17192),
  [Medusa](https://arxiv.org/abs/2401.10774), and
  [EAGLE](https://arxiv.org/abs/2401.15077).
- PyTorch, [FSDP](https://docs.pytorch.org/docs/stable/fsdp.html) and
  [TorchTitan](https://github.com/pytorch/torchtitan).
- Rajbhandari et al., [ZeRO](https://arxiv.org/abs/1910.02054), and NVIDIA,
  [Megatron-LM](https://github.com/NVIDIA/Megatron-LM).
- Hugging Face, [TRL](https://github.com/huggingface/trl); ByteDance,
  [veRL](https://github.com/verl-project/verl); OpenRLHF,
  [OpenRLHF](https://github.com/OpenRLHF/OpenRLHF); NVIDIA,
  [NeMo RL](https://github.com/NVIDIA-NeMo/RL); and Anyscale,
  [Ray](https://github.com/ray-project/ray).
- SchedMD, [Slurm](https://slurm.schedmd.com/documentation.html); NVIDIA,
  [NCCL guide](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/) and
  [nccl-tests](https://github.com/NVIDIA/nccl-tests).
