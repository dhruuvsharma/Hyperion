# Hyperion Terminal Transformer

## A narrow, efficient model for strategy and visualizer artifact authoring

**Architecture identifier:** HTT-1.5B-r0  
**Author:** Dhruv Sharma (dhruvsha.info@gmail.com)  
**Affiliation:** Independent research project  
**Document status:** Research project preprint; prospective architecture; no trained checkpoint  
**Date:** 8 August 2026  
**System boundary:** Hyperion private model and coordinator; Terminal strategy and visualizer authoring only

---

## Abstract

This paper proposes the Hyperion Terminal Transformer (HTT), a clean-sheet, approximately 1.52 billion parameter decoder-only language model for exactly two artifact families: Terminal trading-strategy source and Terminal visualizer specifications. It is not a general assistant, an autonomous trading agent, a broker interface, a market forecaster, or a replacement for the Hyperion coordinator. Its purpose is to turn a bounded objective and versioned Terminal evidence into an inert artifact that can be checked by deterministic systems and released only by a human. HTT is prospective work: no checkpoint has been trained or evaluated.

The proposed backbone combines mechanisms drawn from primary research: pre-normalized transformer blocks, RMSNorm, rotary position encoding, SwiGLU feed-forward layers, grouped-query attention, exact IO-aware attention kernels, and a mixture of local and global attention layers. The model uses a small, domain-trained vocabulary, tied input/output embeddings, two deterministic low-rank task lanes, grammar-constrained generation, selective retrieval, compiler and execution feedback, calibrated verifier reranking, and abstention. Their combination is a research hypothesis, not experimental evidence: every important choice is paired with an ablation, stop condition, and sealed evaluation requirement.

The reference configuration has 32 layers, hidden width 2,048, 16 query heads, 4 key/value heads, head dimension 128, SwiGLU width 5,632, a 32,768-token vocabulary, and a 32,768-token maximum context. Eight layers use global attention and twenty-four use a 4,096-token sliding window. The core model plus both task lanes is approximately 1.523 billion parameters; enabling the optional parser-state table raises the stored total to approximately 1.524 billion. One active lane touches approximately 1.516 billion parameters, or 1.517 billion with parser-state features. At 32K context, BF16 key/value cache is approximately 0.688 GiB for the hybrid schedule rather than 8 GiB for full multi-head attention. These are derived budgets, not measured deployment results.

Accuracy is defined operationally as sealed functional correctness, not prose similarity or benchmark reputation. A candidate succeeds only if it emits a schema-valid artifact, compiles against the exact Terminal SDK, avoids prohibited capabilities, passes deterministic and hidden behavioral tests, remains calibrated under version shift, and meets latency and memory gates on the intended hardware. The paper therefore recommends a staged evidence program: corpus governance and tokenizer study, small scaling pilots, verified pretraining, supervised distillation, optional preference optimization for style, reinforcement learning with verifiable rewards, quantization-aware evaluation, and independent promotion. No claim of best accuracy, production readiness, or absence of outside knowledge is made before those experiments.

## 1. Introduction and contributions

Terminal artifact authoring is a constrained program-synthesis problem: a useful system must follow exact SDK and schema contracts, remain within a restricted capability surface, and produce outputs that deterministic tools can evaluate. A general-purpose model may carry unnecessary parameters and knowledge while still failing those domain-specific checks. This motivates a narrow model whose quality is measured by executable correctness and calibrated abstention rather than open-domain fluency.

We present HTT-1.5B-r0 as a **research baseline**, not as a production model. The proposed work comprises dataset and tokenizer design, parameter-matched pilots, and sealed evaluation planning. It does not constitute authorization for full pretraining, customer-data use, model promotion, deployment, strategy installation, live trading, or a change to the current `public/` shared-core boundary.

The proposal makes six design commitments.

1. Keep Hyperion's coordinator and deterministic controls outside the model. HTT is the bounded student policy inside that system.
2. Train stable programming, numerical, strategy-DSL, and visualization grammar into weights; retrieve changing private Terminal facts at run time.
3. Use a dense 1.5B decoder as the first reproducible baseline. Do not begin with mixture-of-experts, state-space, byte-latent, ternary-weight, or dynamic-depth complexity.
4. Separate strategy and visualizer behavior with deterministic task identity and small residual adapters. Never let a learned router choose a more permissive lane.
5. Generate constrained artifacts and select them with compilers, sandboxes, tests, and calibrated verifiers. Do not optimize directly for backtest profit.
6. Treat every architectural benefit as a hypothesis until reproduced under identical Hyperion data, compute, and evaluation.

### 1.1 Success definition

The research program is successful only when a frozen HTT artifact beats parameter-matched dense and public small-code-model baselines on a preregistered scorecard while satisfying all hard safety gates. The primary accuracy measure is sealed functional pass@1 after deterministic selection. Secondary measures include compile-at-1, repair success, visual fidelity, accessibility, evidence correctness, calibration, selective-risk curves, latency, throughput, peak memory, and energy per accepted artifact.

### 1.2 Evidence labels used in this paper

Every material statement belongs to one of four classes:

- **Implemented boundary:** behavior already represented by Hyperion contracts or documentation.
- **Source-reported result:** a finding reported by a cited paper, not reproduced by Hyperion.
- **Derived estimate:** arithmetic from the proposed dimensions, not a benchmark.
- **Research hypothesis:** a design choice requiring an ablation and sealed evidence.

These labels prevent a source paper's benchmark result from becoming an implied Hyperion result.

## 2. Scope, non-goals, and threat boundary

### 2.1 Allowed purposes

HTT accepts one server-selected purpose:

- `STRATEGY`: author or repair inert C# or DAXQ strategy artifacts within the restricted Terminal strategy surface.
- `VISUALIZER`: author or repair a declarative Terminal visualizer specification that a deterministic compiler may later translate into an approved renderer.

The model may explain the fields and diagnostics of the artifact it is producing, but it is not an open-domain question-answering model. Requests for news, biography, general coding, portfolio advice, discretionary trade calls, broker operations, credential handling, or arbitrary desktop automation are rejected before inference or mapped to an explicit refusal schema.

### 2.2 Existing strategy boundary

The existing coordinator strategy artifact is inert `CoordinatorStrategySource`. It binds the objective, evidence identifiers, role outputs, exact file hashes, and source bundle. Current contracts bound a bundle to 1 through 16 C# files, at most 200,000 characters per file and 1,000,000 aggregate characters. Release and Terminal compilation require separate human consent; the generated bundle is not installation-eligible by itself. The restricted DAXQ authoring surface exposes numerical data and actions such as indicator access, parameters, bars, time index, deterministic random access, logging, initialization, `OnBar`, and `OnTick`. Those contracts remain authoritative.

### 2.3 Proposed visualizer boundary

No equivalent hosted visualizer artifact contract is currently implemented. HTT therefore does not propose arbitrary WPF, browser, shader, or package execution. It proposes a future `hyperion-terminal-visualizer/v1` declarative intermediate representation (IR), explicitly outside the current implementation. The IR contains data-source declarations, allowlisted transforms, panes, series, scales, axes, legends, interactions, accessibility labels, update bounds, and fallback behavior. It contains no network, filesystem, reflection, process, package, native-code, broker, or credential field. A deterministic compiler would emit an approved WPF or web-chart implementation only after schema, lineage, screenshot, interaction, accessibility, and performance checks.

### 2.4 Non-goals

HTT is not designed to:

- predict future prices or guarantee strategy performance;
- recommend capital allocation or execute an order;
- ingest unrestricted web pages or customer repositories;
- write arbitrary applications or plugins;
- interpret screenshots with a native vision encoder in version 1;
- retain user prompts, market data, or generated artifacts in its weights;
- expose hidden chain-of-thought as an audit record;
- replace deterministic compilers, policy checks, verifiers, or human approval.

### 2.5 What "only knows the Terminal" can honestly mean

An executable code model cannot literally contain zero outside knowledge. C#, mathematics, JSON, chart vocabulary, and natural-language instructions carry general regularities; tokenization and teacher data can also leak facts. Absence of arbitrary knowledge is not directly provable from weights. Hyperion can instead establish a defensible operational property:

1. training admissions include only approved domain, language, mathematics, safety, and synthetic artifact records;
2. current private facts remain revocable retrieval evidence rather than weight memory;
3. the request schema exposes only two purposes and allowlisted tools;
4. constrained decoding exposes only the artifact grammar;
5. out-of-domain probes are measured, rejected, and included in promotion gates;
6. the served model has no unrestricted network, filesystem, broker, or package authority.

This is **capability confinement**, not a metaphysical claim about every latent association.

## 3. Terminal task model

### 3.1 Common request envelope

Each request is bound to exact identities before it reaches HTT:

| Field | Purpose |
|---|---|
| purpose | Server-selected `STRATEGY` or `VISUALIZER` |
| objective | Bounded human goal and acceptance criteria |
| Terminal target | Product, SDK, schema, compiler, and renderer versions |
| evidence set | Authorized chunk IDs, hashes, rights, retrieval timestamp, and rank |
| policy set | Allowed artifact fields, APIs, tools, budgets, and prohibited capabilities |
| work state | Current artifact, diagnostics, test failures, and remaining attempt budget |
| output contract | Exact JSON schema and grammar version |

No model-produced value may override these fields.

### 3.2 Strategy task families

The strategy lane is trained and evaluated on:

- specification normalization and ambiguity detection;
- strategy skeleton generation;
- indicator and rolling-window composition;
- entry, exit, sizing, and state-machine logic within allowed APIs;
- deterministic numeric edge cases, warm-up, missing data, and session boundaries;
- compilation repair from exact diagnostics;
- prohibited-API refusal and safe substitution;
- explanation of parameters and assumptions;
- mutation and regression repair;
- inert source packaging with exact evidence references.

Backtest profit, Sharpe ratio, or win rate cannot be a model reward. They are unstable, exploitable, regime-dependent, and can encourage leakage. Behavioral rewards concern conformance to a declared strategy under controlled data.

### 3.3 Visualizer task families

The visualizer lane is trained and evaluated on:

- mapping a data contract to panes, scales, and series;
- candlestick, line, histogram, footprint, order-book, heatmap, surface, and annotation specifications;
- windowed aggregation and derived-indicator transforms;
- deterministic colors, legends, tooltips, zoom, selection, and linked cursors;
- missing, sparse, delayed, or high-rate data behavior;
- accessibility names, contrast, non-color encodings, keyboard interaction, and reduced-motion fallbacks;
- screenshot, geometry, interaction, and frame-time repair;
- refusal of unsupported data, renderers, or executable extensions.

### 3.4 Artifact state machine

```text
Bound request
    |
    v
Retrieve version-pinned evidence ----> evidence gap? ----> abstain / ask for evidence
    |
    v
Generate constrained artifact candidates
    |
    v
Schema + policy + static validation
    |
    +---- invalid ----> bounded repair loop
    |
    v
Compile / render in isolated tool lane
    |
    +---- failed -----> bounded repair loop
    |
    v
Behavior, screenshot, accessibility, and hidden tests
    |
    v
Calibrated verifier rerank and risk threshold
    |
    +---- uncertain --> abstain / human review
    |
    v
Inert artifact + evidence receipt
    |
    v
Separate human release and Terminal compile consent
```

## 4. Transformer foundations

This section derives the baseline so later modifications are explicit.

### 4.1 Token representation

For a token sequence `t_1 ... t_n`, the tokenizer maps each token to an integer. A tied embedding matrix `E in R^(V x d)` produces

```text
x_i^0 = E[t_i] + e_role + e_task + e_schema + e_grammar(i)
```

where `V` is vocabulary size, `d` is hidden width, role and task identities are server supplied, schema identifies the output contract, and the optional grammar state comes from a deterministic parser. Position is not added here because rotary position encoding modifies query and key vectors.

### 4.2 Scaled dot-product attention

For hidden states `X in R^(n x d)`, one attention head projects

```text
Q = X W_Q,  K = X W_K,  V = X W_V
A = softmax((Q K^T) / sqrt(d_h) + M)
O = A V
```

`d_h` is head width and `M` contains causal and locality masks. The factor `sqrt(d_h)` prevents dot-product variance from growing with head width, which would push softmax into saturated regions. Causal masking sets scores for future positions to negative infinity.

With `h_q` query heads, multi-head output is

```text
MHA(X) = Concat(head_1, ..., head_hq) W_O.
```

The original Transformer established this parallel attention plus feed-forward pattern [1]. HTT remains decoder-only because both target artifacts are autoregressive structured generation tasks.

### 4.3 Grouped-query attention

Ordinary multi-head attention assigns a distinct key and value head to each query head. Multi-query attention shares one key/value head. Grouped-query attention (GQA) uses `h_kv` key/value heads, each shared by `g = h_q / h_kv` query heads [5]. HTT uses `h_q=16`, `h_kv=4`, and `g=4`.

For one layer, ignoring bias because HTT has none:

```text
P_attn = d*(h_q*d_h) + 2*d*(h_kv*d_h) + (h_q*d_h)*d.
```

Since `h_q*d_h = d`, this becomes

```text
P_attn = 2*d^2 + 2*d*h_kv*d_h.
```

GQA reduces the stored key/value width without reducing query-head diversity. Ainslie et al. reported quality close to multi-head attention and speed close to multi-query attention in their conversion experiments [5]; Hyperion must reproduce the trade-off from random initialization.

### 4.4 Rotary position encoding

RoPE rotates pairs of query and key coordinates by a position-dependent angle [4]. For coordinate pair `m` at position `p`:

```text
R(p, theta_m) = [[cos(p*theta_m), -sin(p*theta_m)],
                 [sin(p*theta_m),  cos(p*theta_m)]]
q'_p,m = R(p, theta_m) q_p,m
k'_p,m = R(p, theta_m) k_p,m
```

Because `R(p)^T R(r) = R(r-p)`, the attention dot product depends on relative displacement:

```text
(q'_p)^T k'_r = q_p^T R(r-p) k_r.
```

This gives a useful relative-position structure without learned absolute tables. Context extension is still an experiment: changing the RoPE base or scaling after training can damage short-context behavior and must be length-stratified.

### 4.5 RMS normalization and pre-normalization

RMSNorm scales a vector without subtracting its mean [2]:

```text
rms(x) = sqrt((1/d) * sum_j x_j^2 + epsilon)
RMSNorm(x) = gamma .* x / rms(x).
```

HTT uses pre-normalization:

```text
u = x + Attention(RMSNorm(x))
y = u + SwiGLU(RMSNorm(u)).
```

Pre-normalization provides a direct residual path. RMSNorm removes LayerNorm's recentering operation; the source paper reported comparable performance and runtime reductions in its tested models [2], but HTT must measure its own kernels.

HTT also applies RMS normalization independently to each query and key head immediately before RoPE. QK-Norm bounds query/key scale and is included because recent small models such as Qwen3 use it [35]. Its value must be tested against ordinary pre-RMSNorm.

### 4.6 SwiGLU feed-forward layer

The gated feed-forward network is

```text
SwiGLU(x) = (swish(x W_gate) .* (x W_up)) W_down
swish(z) = z * sigmoid(beta*z), with beta=1 by default.
```

It has three matrices, so

```text
P_ffn = 3*d*d_ff.
```

Shazeer reported GLU variants, including SwiGLU, improving held-out language-model perplexity at matched compute in the studied settings [3]. HTT uses `d_ff=5632`, close to the parameter-matched `8d/3` rule rounded for efficient tensor dimensions.

### 4.7 Training objective

The base causal objective for sequence `x_1 ... x_T` is

```text
L_NTP = -sum_t w_t log p_theta(x_t | x_<t, c),
```

where `c` is the immutable task/evidence envelope. Prompt, retrieved evidence, tool results, padding, and rejected output regions receive `w_t=0`; approved target artifacts and structured visible planning fields receive task-balanced weights. Loss is reported per task, length, grammar state, SDK version, and artifact region, not only as a global average.

## 5. Proposed HTT-1.5B-r0 architecture

### 5.1 Canonical dimensions

| Component | Proposed value | Rationale | Required comparison |
|---|---:|---|---|
| Decoder layers | 32 | Depth for compositional repair at moderate width | 24 and 36 layers at matched parameters |
| Hidden width | 2,048 | Efficient common kernel width | 1,792 and 2,304 variants |
| Query heads | 16 | 128-dimensional heads | 16-head MHA and 8-head variants |
| Key/value heads | 4 | 4:1 GQA | 1, 2, 8, and 16 KV heads |
| Head width | 128 | Candidate RoPE/attention kernel shape | 64 and 128 at matched width |
| SwiGLU width | 5,632 | Near `8d/3`, tensor-friendly | 5,504 and 6,144 |
| Vocabulary | 32,768 | Domain efficiency and smaller tied embedding | 16K, 48K, and public 150K tokenizer |
| Maximum context | 32,768 | Repository/evidence repair ceiling | 8K and 16K operating points |
| Local window | 4,096 | Keeps most layers inexpensive | 2K, 8K, and all-global |
| Global schedule | Every fourth layer | Accuracy-oriented hybrid hypothesis | Every sixth layer and learned routing |
| Task adapters | rank 64 in top 12 layers | Cheap deterministic specialization | shared trunk only; full separate heads |
| Numeric format | BF16 training baseline | Stable reference artifact | FP8 only after parity study |

### 5.2 Block diagram

```text
32K domain tokenizer + immutable request identities
                       |
                       v
               tied token embedding
                       |
      +----------------+----------------+
      |  32 decoder blocks             |
      |                                |
      |  RMSNorm -> QK-Norm -> RoPE     |
      |  -> 16Q/4KV causal attention    |
      |  -> residual                    |
      |  RMSNorm -> SwiGLU -> residual  |
      |                                |
      |  layers 1-3 local, 4 global     |
      |  repeated eight times           |
      +----------------+----------------+
                       |
       top 12 blocks: deterministic rank-64 lane
               STRATEGY or VISUALIZER
                       |
                       v
             final RMSNorm + tied logits
                       |
                       v
        schema/grammar mask -> candidate artifact
                       |
                       v
       compiler / renderer / tests / verifier
```

### 5.3 Local/global attention schedule

Layers follow `[L, L, L, G]` repeated eight times. A local layer at position `i` attends to at most the previous 4,096 tokens. A global layer attends to the full causal prefix. Mistral demonstrated sliding-window attention and rolling KV buffers in a 7B code-capable model [8]; Gemma 3 later used interleaved local and global layers to reduce KV cost [36]. HTT selects a more frequent 3:1 schedule than Gemma 3's reported 5:1 pattern because exact cross-file references and repair diagnostics are accuracy-sensitive. The 5:1 schedule is a mandatory efficiency ablation.

The normal serving admission target is 8K. A request may use 16K or the 32K ceiling only when retrieval and dependency analysis show that the task needs it. Training likewise begins at 8K and extends only the winning checkpoint on genuinely long examples. The maximum is a capability ceiling, not the default cost paid by every request.

Local layers can communicate beyond one window through depth: after `k` consecutive local layers, information can theoretically propagate across approximately `k*W` prior positions, although attenuation and optimization may make the effective span smaller. Global layers provide direct long-range checkpoints.

At context `N=32768`, the fraction of attention score positions relative to all-global attention is

```text
R_scores = (8*N + 24*W) / (32*N)
         = (8*32768 + 24*4096) / (32*32768)
         = 0.34375.
```

Thus the schedule evaluates 65.625% fewer attention-score positions than 32 full-context layers at the maximum length. This is not a 65.625% reduction in whole-model FLOPs: projections and SwiGLU remain unchanged, kernels have fixed overhead, and short sequences see a smaller benefit.

### 5.4 Task lanes

The request purpose is known, so learned expert routing adds unnecessary uncertainty. The top twelve blocks include one residual low-rank adapter after attention and one after the feed-forward sublayer:

```text
Adapter_tau(x) = s_tau * B_tau sigma(A_tau x)
A_tau in R^(r x d), B_tau in R^(d x r), r=64
x' = x + Adapter_tau(RMSNorm(x)).
```

Only the server-selected lane `tau` is active. `STRATEGY` and `VISUALIZER` weights are separate; the trunk and vocabulary are shared. Each lane has

```text
P_lane = 12 layers * 2 positions * 2*d*r
       = 12 * 2 * 2 * 2048 * 64
       = 6,291,456 parameters.
```

Adapters are initialized near zero so the initial network matches the shared trunk. A lane cannot grant capability: output schema, retrieval, tools, policy, and human release remain external.

### 5.5 Optional parser-state embedding

A deterministic incremental parser can expose one of up to 512 grammar states. A learned table `G in R^(512 x 2048)` adds 1,048,576 parameters. This feature may help the network distinguish, for example, a property name from a numeric expression, but inference-time token masking already guarantees syntax. The parser-state embedding is therefore an ablation, while grammar masking is mandatory.

### 5.6 Why a dense baseline

Sparse mixture-of-experts can increase total capacity for a fixed active parameter budget, but it introduces routing stability, expert collapse, load balancing, distributed communication, larger artifact storage, and more difficult quantization and rollback. A narrow two-purpose model obtains deterministic specialization with 12.6M total adapter parameters instead. Mixture-of-Depths [9], state-space hybrids, byte-latent models [37], and ternary-weight models [38] remain valuable challengers only after the dense reference is reproducible.

### 5.7 No native vision tower in version 1

Visualizer authoring is a structured code/specification task. A native image encoder would add parameters, multimodal data rights, new prompt-injection surfaces, and a less deterministic serving path. Visual quality is evaluated outside HTT with deterministic rendering, pixel and geometry metrics, accessibility checks, an optional separately governed vision judge, and human review. A later screenshot-to-repair model must compete against this tool-mediated baseline.

## 6. Derived parameter and memory budget

### 6.1 Parameter derivation

Let `V=32768`, `d=2048`, `L=32`, `h_q=16`, `h_kv=4`, `d_h=128`, and `d_ff=5632`.

```text
Tied embedding/output:
P_embed = V*d
        = 32768*2048
        = 67,108,864

Attention per layer:
P_attn = d^2 + 2*d*(h_kv*d_h) + d^2
       = 2048^2 + 2*2048*(4*128) + 2048^2
       = 10,485,760

SwiGLU per layer:
P_ffn = 3*d*d_ff
      = 3*2048*5632
      = 34,603,008

Two RMSNorm scales per layer:
P_norm = 2*d = 4,096

Shared per-head QK-Norm scales per layer:
P_qknorm = 2*d_h = 256

All blocks:
P_blocks = 32*(P_attn + P_ffn + P_norm + P_qknorm)
         = 1,442,979,840

Base plus tied embedding and final RMSNorm:
P_base_plain = P_blocks + P_embed + d
             = 1,510,090,752

Small role/task/schema embeddings:
P_identity_small ~= 32,768

Core base with identity features:
P_base_core ~= 1,510,123,520 (approximately 1.510B)

Optional parser-state table:
P_parser = 512*2048 = 1,048,576

Two task lanes:
P_lanes = 2*6,291,456 = 12,582,912

Core stored total:
P_total_core ~= 1,522,706,432 (approximately 1.523B)

Parser-enabled stored total:
P_total_parser ~= 1,523,755,008 (approximately 1.524B)

Active core with one lane:
P_active_core ~= 1,516,414,976 (approximately 1.516B)

Parser-enabled active total:
P_active_parser ~= 1,517,463,552 (approximately 1.517B).
```

This estimate assumes one shared 128-element normalization scale for all query heads and one for all key heads in each layer. Per-head QK-Norm, learned adapter scales, bias choices, or padding rows would change the count. The build manifest must report the executable count from the model graph.

### 6.2 Vocabulary savings

At width 2,048, replacing a 151,646-token tied vocabulary like the Qwen2.5-Coder family [11] with 32,768 tokens saves

```text
(151646 - 32768)*2048 = 243,462,144 parameters.
```

This comparison isolates embedding size only. A smaller vocabulary may create longer sequences, so the tokenizer study must measure tokens per artifact, compile correctness, and latency rather than celebrating parameter count alone.

### 6.3 Weight storage lower bounds

Ignoring scales, metadata, alignment, runtime workspaces, and duplicated buffers:

| Format | Approximate decimal GB | Approximate GiB | Status |
|---|---:|---:|---|
| BF16, 2 bytes/parameter | 3.047 | 2.838 | Reference inference/training weights only |
| INT8, 1 byte/parameter | 1.524 | 1.419 | Requires exact-artifact quality test |
| INT4, 0.5 byte/parameter | 0.762 | 0.710 | Lower bound; group scales and runtime add memory |

A 4 GB GPU is not declared a production target. INT4 weights plus an int8 KV cache may fit arithmetically at some contexts, but CUDA context, kernels, activations, temporary buffers, allocator fragmentation, and host transfer must be measured. The recommended initial serving qualification is 8 GB or more; full pretraining requires substantially larger multi-GPU resources.

### 6.4 KV-cache derivation

For `L` layers, context `N`, `h_kv` key/value heads, head width `d_h`, and `b` bytes per value:

```text
M_KV = 2 * L * N * h_kv * d_h * b.
```

At BF16, `b=2`. Full multi-head attention with 16 KV heads at 32K requires 8 GiB. Full-context GQA with 4 KV heads requires 2 GiB. The hybrid schedule stores eight global layers at 32K and twenty-four rolling local layers at 4K:

```text
M_hybrid = 2*h_kv*d_h*b*(8*32768 + 24*4096)
         = 738,197,504 bytes
         = 0.6875 GiB.
```

| Active context | Hybrid BF16 KV cache |
|---:|---:|
| 8,192 | 0.3125 GiB |
| 16,384 | 0.4375 GiB |
| 32,768 | 0.6875 GiB |

The serving manifest must bind KV precision, page size, maximum sequence count, and eviction policy. PagedAttention can reduce fragmentation and enable non-contiguous cache management [26], but it does not change the mathematical bytes per live token.

## 7. Domain tokenizer and sequence protocol

### 7.1 Tokenizer objectives

The tokenizer is trained only from admitted corpus partitions and frozen before pretraining. A byte-fallback BPE or unigram tokenizer with 32,768 entries should optimize a weighted objective:

```text
J_tok = mean(tokens/character)
      + lambda_1 * identifier_fragmentation
      + lambda_2 * numeric_fragmentation
      + lambda_3 * invalid_byte_rate
      + lambda_4 * vocabulary_memory.
```

Byte fallback guarantees representation of unusual identifiers without an unknown token. Reserved tokens encode roles, purpose, schema, evidence boundaries, repository/file boundaries, fill-in-the-middle (FIM) spans, tool calls/results, diagnostics, candidate boundaries, refusal, and end-of-artifact. Public small code-model reports provide precedent for repository and FIM markers [11, 12]; HTT must establish their value through its own ablations.

SantaCoder used a 49,152-entry raw-byte BPE with digit splitting [51], while the Qwen2.5-Coder 1.5B configuration retained a much larger inherited vocabulary [11]. HTT compares these design directions rather than assuming the smallest embedding wins.

### 7.2 Numeric handling

Trading strategies contain decimals, signs, dates, time spans, enum-like constants, and indicator periods. Tokenizer candidates must be stratified on:

- exact round-trip for source bytes;
- common C# numeric literals and suffixes;
- decimal and scientific notation;
- time and session expressions;
- camelCase, PascalCase, namespaces, and generic types;
- JSON property names and schema enumerations;
- DAXQ operations and indicator names.

No custom numeric embedding is adopted without showing better arithmetic and exact-literal copying than byte-fallback tokens.

### 7.3 Sequence packing

Training records are packed only across compatible rights, purpose, schema, SDK version, and contamination group boundaries. Attention is blocked across examples. Each record preserves file order and repository dependency order when available. DeepSeek-Coder reported repository-level training with dependency-aware file ordering [12]; Hyperion should compare dependency order with lexical and randomized controls.

### 7.4 FIM and repair protocol

At least three supervised layouts are mixed:

```text
left-to-right:  objective + evidence -> complete artifact
FIM:            prefix + suffix -> missing region
diagnostic:     artifact + compiler/test diagnostic -> patch or replacement
```

The model never edits a live file directly. It returns an inert full artifact or bounded patch representation whose base hash is checked by the coordinator.

The starting FIM rate is 50% of eligible code examples, with 0%, 50%, and 80% ablations. FIM is bounded within a file so training does not create impossible cross-file holes. Bavarian et al. reported that 50% FIM added infilling without harming left-to-right behavior in their experiments and that high, but not 100%, rates remained viable [53]. DeepSeek-Coder used 50% FIM [12], while CodeGemma used higher rates [52]; neither establishes the Hyperion optimum.

## 8. Constrained artifact generation

### 8.1 Layered constraints

Generation uses four distinct controls:

1. **Envelope schema:** exact JSON object and closed field set.
2. **Language grammar:** JSON, visualizer IR, DAXQ, or a safe C# subset.
3. **Semantic policy:** allowlisted APIs, types, transforms, sizes, and data feeds.
4. **Behavioral verification:** compile, execute/render, and hidden tests.

Grammar constraints cannot prove semantic correctness. SynCode reported eliminating JSON syntax errors and sharply reducing syntax errors for tested programming languages [22], but HTT retains all later gates.

### 8.2 Strategy artifact shape

The current strategy result remains `coordinator-strategy-source/v1`. The model-facing candidate may contain:

```text
schemaVersion
purpose
objectiveHash
evidenceIds[]
assumptions[]
files[{path, language, content, sha256}]
parameterManifest[]
expectedDiagnostics[]
testIntent[]
abstentionReason?
```

The coordinator recomputes all hashes and discards model-supplied authority fields. Source is inert until human release and separate Terminal compile consent.

### 8.3 Proposed visualizer IR

The future `hyperion-terminal-visualizer/v1` shape is intentionally non-executable:

```text
metadata:       id, title, description, schemaVersion, targetRenderer
inputs:         Bars | L1 | L2 | Trades | Derived, with exact version and fields
transforms:     allowlisted window, aggregate, indicator, regression, quantile
layout:         panes, grid, sizing bounds, linked axes
series:         type, input bindings, transforms, scale, style, z-order
interactions:   tooltip, crosshair, zoom, pan, selection, keyboard
accessibility:  names, descriptions, contrast, non-color encoding, reduced motion
performance:    update rate, point budget, aggregation and degradation policy
fallbacks:      missing/sparse/delayed data, unsupported renderer
provenance:     evidence IDs, input lineage, compiler version
```

Forbidden keys include URL, socket, file path, command, assembly, reflection, native library, package, script, credential, broker action, and dynamic type. The deterministic compiler owns all renderer code.

### 8.4 Candidate generation and selection

For each request, HTT may generate `K` bounded candidates, usually 4 at research time and 1 or 2 at low-latency serving. Candidate `i` receives a feature vector from deterministic tools and a learned verifier:

```text
s_i = a*logp_i/length_i
    + b*schema_i
    + c*compile_i
    + d*public_tests_i
    + e*verifier_i
    - f*policy_violations_i
    - g*latency_i.
```

Hard failures are never rescued by a high learned score. LEVER reported gains from combining execution information and learned verification on four code datasets [23]; Hyperion requires an independently trained verifier, near-miss mutants, calibration, and sealed tests.

### 8.5 Abstention

Acceptance uses calibrated probability of sealed-equivalent success, not the model's prose confidence. On held-out calibration data, choose threshold `tau` such that estimated risk among accepted artifacts is below the approved ceiling:

```text
coverage(tau) = count(p_i >= tau) / count(all)
risk(tau) = mean(1 - y_i | p_i >= tau).
```

Report the whole risk-coverage curve, expected calibration error, Brier score, and performance after SDK/version shift. Self-reported confidence often degrades on new tasks [29], so tool outcomes dominate.

## 9. Knowledge placement and retrieval

### 9.1 Placement rule

HTT divides knowledge by stability and authority.

| Knowledge class | Location | Reason |
|---|---|---|
| C#, JSON, bounded mathematics, visualization grammar | Model weights | Stable compositional skill used across tasks |
| DAXQ language fundamentals and safe idioms | Model weights plus compiler | Stable skill, deterministically checked |
| Current private Terminal APIs, topology, conventions | Signed retrieval pack | Changes, must be revocable and source-citable |
| Policy, entitlement, purpose, budgets | Coordinator and policy service | Authority cannot be delegated to weights |
| User brief and current artifact | Per-run context | Private and transient |
| Market data | Separately licensed per-run evidence/tool | Time-sensitive and rights-constrained |
| Compiler, renderer, tests, static policy | Deterministic tools | Stronger than memorization |
| Sealed answers and hidden verifier cases | Independent evaluation custody | Prevents leakage and reward hacking |

This placement follows the existing Hyperion architecture: current private architecture belongs in versioned retrieval, while executable behavior belongs in tools and schemas.

### 9.2 Selective retrieval pipeline

```text
Request and current artifact
          |
          v
Deterministic need-to-retrieve features
          |
   +------+------+
   |             |
 no need      retrieve
   |             |
   |       metadata and access filter
   |             |
   |       sparse + dense retrieval
   |             |
   |       version-aware reranker
   |             |
   |       duplicate/contradiction check
   |             |
   +------> bounded evidence context
                  |
                  v
       artifact with evidence IDs
```

Metadata and authorization filters run before semantic search. Retrieval combines lexical symbols, schema IDs, and diagnostics with dense similarity; a cross-encoder reranks only allowed chunks. Every selected chunk binds corpus version, source hash, availability time, rights, product/SDK version, and retrieval score. RepoCoder reported gains from iterative retrieval for repository completion [16], Repoformer reported large serving savings from selective retrieval [17], and RAFT reported gains from training with relevant documents plus distractors [18]. These are useful patterns, not proof for Terminal artifacts.

### 9.3 Retrieval training

Training examples include:

- correct current evidence;
- obsolete but plausible API versions as hard distractors;
- evidence gaps requiring abstention;
- conflicting sources with an explicit precedence rule;
- cases that require no retrieval;
- iterative repair where diagnostics change the next query;
- exact citations to evidence IDs rather than invented URLs.

Retrieval recall is evaluated separately from generation. A generator cannot compensate for missing authoritative evidence by hallucinating an API.

### 9.4 Context budgeting

The coordinator allocates a token budget before dispatch:

```text
B_total = B_system + B_objective + B_state + B_evidence + B_output + B_margin.
```

Evidence chunks are selected by marginal expected utility under `B_evidence`, with diversity and version constraints. Extremely long repositories are not dumped into context. The model receives interfaces, relevant examples, diagnostics, and dependency neighborhoods. Retrieved private text is not automatically eligible for training.

## 10. Corpus design and governance

### 10.1 Admission before scale

Small code models can be strong when trained on high-quality curated data: Phi and Phi-3 emphasize textbook-quality and synthetic data [31, 32], while StarCoder2 reports a 3B model outperforming its earlier 15B model on most studied benchmarks after data and training improvements [21]. These results motivate curation; they do not establish that synthetic volume is safe or that public-code benchmarks predict Terminal quality.

Every record must carry:

- content and normalized hashes;
- source and immutable locator;
- creator/owner, licence, consent, and permitted uses;
- capture and availability timestamps;
- private/public/retrieval-only/sealed knowledge class;
- Terminal, SDK, schema, compiler, renderer, and policy versions;
- purpose, task family, difficulty, and language;
- teacher identity, prompt, generation parameters, and parent IDs for synthetic data;
- compiler/test/verifier versions and outcomes;
- contamination family and split;
- review, release, receipt, admission, and exclusion state.

No secret, credential, private signing key, customer artifact, review evidence, production prompt, hidden test, model checkpoint, or unlicensed market data is admitted.

### 10.2 Corpus lanes

| Lane | Examples | Dominant checks |
|---|---|---|
| Language substrate | Minimal C#, JSON, schemas, numeric expressions | parse, compile, exact round-trip |
| Strategy primitives | State, indicators, parameters, warm-up, sessions | compiler, numeric and property tests |
| Strategy composition | Multi-file artifacts and repairs | hidden behavior, mutation, policy |
| Visualization primitives | panes, scales, series, transforms, accessibility | schema, render, geometry |
| Visualization composition | linked views, high-rate data, degradation | screenshot, interaction, frame-time |
| Retrieval use | current evidence, distractors, citations | recall, provenance, contradiction |
| Tool repair | diagnostics to corrected artifact | exact error removal, no regression |
| Safety/refusal | prohibited APIs, missing authority, injection | refusal, policy, no side effects |
| Negative mutants | near-correct syntax and behavior | verifier discrimination |

### 10.3 Deduplication and split isolation

Deduplication occurs before splitting and after every synthetic generation round:

1. byte and normalized exact hashes;
2. token MinHash / locality-sensitive similarity;
3. syntax-tree fingerprints with identifier normalization;
4. data-flow and visualizer-graph similarity;
5. shared template, repository, teacher prompt, and lineage grouping.

Lee et al. reported that deduplication reduced memorized training emission and found material train-validation overlap in common language-model data [20]. Hyperion must use semantic and lineage grouping because minor identifier changes do not create independent strategy tasks.

Splits are:

- `train`: admitted records only;
- `development`: visible tasks for model and harness iteration;
- `calibration`: threshold and uncertainty fitting, never gradient training;
- `sealed`: hidden promotion comparison;
- `future`: SDK- and time-forward evaluation acquired after the training cutoff.

### 10.4 Synthetic data rules

Synthetic examples are accepted only after deterministic validation and provenance capture. A teacher may propose an artifact, structured plan, counterexample, or repair, but cannot approve its own output. A record is rejected when teacher rationale and artifact disagree, tests are weak, source rights are missing, or the example is a near-duplicate of evaluation.

Synthetic fixtures are harness evidence, not evidence that HTT learned or improved. ReST-EM showed that repeated generation and verified filtering can improve problem-solving models [41], but weak tests can amplify a teacher's blind spots. Each round therefore preserves rejected near-misses, adds mutant tests, and is evaluated on untouched future groups.

### 10.5 Data mixture

Start with an explicit mixture, then optimize it using small proxy models. DoReMi reported that proxy-learned domain weights improved average performance and training efficiency in its broad setting [19]. For HTT, the mixture controller minimizes worst-slice development loss subject to safety floors:

```text
min_alpha max_k normalized_loss_k(alpha)
subject to alpha_k >= floor_k, sum_k alpha_k = 1.
```

Rare refusal, numerical edge, accessibility, and obsolete-API cases receive minimum floors so average code volume cannot erase them.

The initial high-level hypothesis is 70% code, 20% target technical text, and 10% quantitative mathematics, compared against 80/15/5 and 60/25/15. Qwen2.5-Coder reported its 70/20/10 mix outperforming two more code-heavy mixes in that model's ablation [11]; this is only a starting prior. Within the 70% code lane, the proposed allocation is 30 points reviewed strategy artifacts/repairs, 15 C#/XAML or declarative visualizers, 10 DAXQ/JSON/schema artifacts, and 15 rights-clean general C#/.NET, tests, diffs, and compiler-driven repairs.

## 11. Training program

### 11.1 Stage -1: preregistration and stop conditions

Before GPU training, freeze:

- architecture candidates and parameter-matching rules;
- tokenizer candidates;
- train/development/calibration/sealed lineage groups;
- primary and secondary metrics;
- maximum compute and carbon/energy reporting method;
- minimum improvement and confidence interval;
- safety gates and automatic stop conditions;
- who may unseal results and approve the next stage.

Scaling-law papers show that model size, data, and compute must be balanced [33, 34], but their broad-web optima are not automatically valid for a narrow code domain. Hyperion estimates its own curves using 60M, 180M, 450M, and 900M pilots before committing to 1.5B. Deep-and-thin small models are a useful prior from MobileLLM [54], not a Terminal result.

### 11.2 Stage 0: tokenizer and architecture pilots

Train small parameter-matched models on identical shuffled token streams. Compare:

- 16K, 32K, and 48K vocabularies;
- dense, GQA, and local/global attention;
- QK-Norm on/off;
- parser-state embedding on/off;
- shared trunk versus task adapters;
- 8K, 16K, and progressive 32K context.

Stop any candidate that loses on sealed-like functional slices, has unstable loss, or lacks supported kernels on target hardware.

### 11.3 Stage 1: clean-sheet causal pretraining

If the preregistered data and pilot gates pass, initialize HTT randomly and train only on admitted records. Random initialization is the clearest way to avoid inheriting a broad base model's unknown pretraining corpus. It is also expensive and risky: a 1.5B narrow corpus may undertrain language fluency or overfit templates. Stable Code reported that a generally pretrained initialization remained ahead of scratch training at equal code-token points in its comparison [39], although the initialized model had already consumed far more total pretraining compute. Therefore compare HTT with continued pretraining of an eligible public small-code model under the same interface, data rights, retrieval, tools, and evaluation. "From scratch" is a design option, not a presumed quality advantage.

The base objective is task-balanced next-token prediction. Use BF16 master training, exact attention kernels, gradient accumulation, activation checkpointing, and deterministic checkpoint manifests. Store optimizer, scheduler, data-order, tokenizer, code, container, CUDA/kernel, and RNG identities. A checkpoint is not promotable evidence.

### 11.4 Stage 2: repository, FIM, and diagnostic curriculum

Curriculum increases difficulty only after lower stages are stable:

1. single-expression and schema fragments;
2. complete single-file artifacts;
3. FIM and localized repair;
4. multi-file dependency-ordered artifacts;
5. retrieval with current evidence;
6. obsolete-version distractors and contradiction;
7. compiler, test, screenshot, and accessibility repair;
8. long-context cross-file and cross-pane dependencies.

Context increases from 8K to 16K to 32K only when tasks require the added span. Report short-context regression after each increase.

### 11.5 Stage 3: verified supervised fine-tuning and distillation

Teachers produce a closed target with:

- normalized objective and assumptions;
- evidence IDs used;
- short visible implementation plan;
- artifact;
- expected tool calls and diagnostic interpretation;
- uncertainty or abstention.

Do not retain private hidden chain-of-thought. Distillation targets are concise structured decisions whose claims can be checked against the artifact. Distilling Step-by-Step reported that rationale supervision allowed a much smaller model to outperform a large teacher on a studied benchmark [40], but classification rationales are not executable evidence. Hyperion admits a teacher sample only after independent compilation, tests, policy, and review.

The supervised loss is region weighted:

```text
L_SFT = lambda_a L_artifact
      + lambda_p L_plan
      + lambda_e L_evidence
      + lambda_r L_refusal
      + lambda_d L_diagnostic.
```

Weights are chosen from development gradients and slice performance, never from sealed results.

### 11.6 Stage 4: preference optimization for subjective quality

Direct Preference Optimization (DPO) provides a simple pairwise objective [42]:

```text
L_DPO = -log sigmoid(beta * [
  log pi(y_w|x) - log pi_ref(y_w|x)
  - log pi(y_l|x) + log pi_ref(y_l|x)]) .
```

Use it only when both candidates have equal deterministic correctness and differ in readability, minimality, idiom, visual clarity, or explanation. A human preference can never promote code that fails a hard test. Compare DPO with no-preference tuning and report regression by functional slice.

### 11.7 Stage 5: reinforcement learning with verifiable rewards

Only after SFT is stable, compare RLOO [14] and GRPO [15] under equal samples and compute. A candidate reward is lexicographic: policy and schema failures terminate with zero or negative reward; accepted candidates then combine test coverage and efficiency.

```text
R = R_hard
  + w_c*compile
  + w_t*hidden_behavior
  + w_m*mutation_score
  + w_v*visual_checks
  + w_e*evidence_correctness
  - w_l*token_and_tool_cost
  - w_r*repair_attempts.
```

Do not reward backtest profitability. Hidden tests are rate-limited and independently held. Public feedback is informative enough for development but not detailed enough to reconstruct hidden cases. Process-supervision research reported gains over outcome-only supervision on MATH [25]; Hyperion uses checkable intermediate artifact states and tool receipts, not private reasoning transcripts.

For a group of `G` candidates in GRPO-style normalization:

```text
A_i = (R_i - mean(R_1...R_G)) / (std(R_1...R_G) + epsilon).
```

Advantages are clipped and a KL term limits drift from the approved reference. Reward components, verifier versions, and all tool outputs are persisted for audit.

### 11.8 Stage 6: verified self-training

Run a small number of offline generate-verify-deduplicate-SFT rounds. New examples enter only when they add a new contamination family, diagnostic, API combination, or visual composition and pass stronger tests than the generator observed. Preserve failures to train the verifier and improve test coverage. Stop when future-set gains flatten or template similarity rises.

### 11.9 Multi-token prediction decision

Multi-token prediction trains auxiliary heads for several future tokens [10]:

```text
L_MTP = -sum_t sum_j lambda_j log p_j(x_(t+j) | x_<=t).
```

The source reported code gains and self-speculative speedups at larger scales, but smaller models in its sweep could be worse and benefits grew with scale. HTT-1.5B therefore uses next-token prediction by default. A two-head MTP pilot is permitted only if a 450M and 900M study shows better functional pass@1 without reducing trunk depth.

## 12. Verification and evaluation architecture

### 12.1 Independent evidence path

```text
               +---------------------+
request ------>| HTT candidate policy |---- candidates -----+
               +---------------------+                     |
                                                            v
sealed cases --> independent harness --> deterministic checks --> verifier
       |                                      |                   |
       |                                      v                   v
       +------------------------------ evidence ledger <--- calibration
                                                    |
                                                    v
                                         promotion decision
```

The model, trainer, and coordinator cannot write sealed labels or alter verifier policy. A verifier result is evidence, not authority to release or deploy.

### 12.2 Hard strategy gates

Every strategy candidate must pass:

1. closed envelope schema and exact hash recomputation;
2. parse and compile against the pinned SDK;
3. allowlisted namespace/type/member and source/IL policy;
4. resource-limited isolated execution;
5. deterministic examples and property tests;
6. edge cases for warm-up, missing data, numerical bounds, sessions, and state reset;
7. metamorphic tests such as irrelevant-symbol rename and scale-preserving transforms where applicable;
8. mutation tests that prove the suite detects changed conditions, signs, windows, and state transitions;
9. prohibited capability and prompt-injection tests;
10. exact evidence and version compatibility.

HumanEval+ found large accuracy drops and ranking changes after greatly expanding tests [28]. Generated tests can increase coverage, as explored by CodeT [55], but may share generator blind spots. Hyperion treats generated or thin public test suites as development feedback, never final correctness.

### 12.3 Hard visualizer gates

Every visualizer candidate must pass:

1. closed IR schema and prohibited-field scan;
2. data lineage, type, unit, and transform validation;
3. deterministic compilation for the pinned renderer;
4. reference geometry and pixel-difference thresholds across fixed datasets and sizes;
5. axis, label, legend, tooltip, linked-cursor, zoom, and selection tests;
6. missing, sparse, delayed, burst, and high-cardinality input tests;
7. accessibility tree, contrast, keyboard, non-color, and reduced-motion checks;
8. frame-time, allocation, point-budget, and degradation tests;
9. snapshot mutation score;
10. independent human design review for release candidates.

Pixel identity alone is not correctness: anti-aliasing and renderer versions vary, while a visually similar chart can bind the wrong data. Use structural geometry and data-pixel correspondence alongside perceptual metrics.

### 12.4 Primary scorecard

Hard gates are binary. Among candidates that pass all gates, compare:

| Dimension | Primary metric | Required slices |
|---|---|---|
| Functional accuracy | sealed accepted pass@1 | purpose, difficulty, SDK, length, task family |
| Candidate utility | pass@K and selected pass@1 | K=1,2,4,8 with total-cost reporting |
| Compilation | compile-at-1; repair success by attempt | diagnostic family and version |
| Strategy behavior | property and hidden-test pass | numeric, state, time, missing data |
| Visual fidelity | geometry/data binding plus perceptual delta | renderer, resolution, theme, density |
| Safety | prohibited-capability false accept | adversarial category |
| Evidence | correct citation and version use | retrieval-needed/no-retrieval/conflict |
| Calibration | Brier, ECE, risk at coverage | in-domain and shifted versions |
| Efficiency | p50/p95 time-to-first-token and tokens/s | batch, context, output length |
| Memory | peak weights, KV, workspace | precision and concurrency |
| Stability | mean, standard deviation, confidence interval | at least 3 seeds for critical pilots |

### 12.5 Baselines

At minimum compare:

- deterministic templates and compiler auto-fix;
- one dense HTT-size transformer with full attention and no adapters;
- HTT-1.5B-r0;
- an adapted public 1.5B to 3B code model under the same retrieval and verifier;
- the existing coordinator with its approved hosted provider, where policy allows;
- single candidate versus verifier-selected candidates;
- retrieval off, always on, and selective;
- constrained versus unconstrained decoding.

Do not compare models with different context, evidence, tools, attempt budgets, or hidden-test exposure and attribute the difference to architecture.

### 12.6 Contamination and future evaluation

Search training, teacher, retrieval, and generated corpora against evaluation using exact hashes, token similarity, AST/graph fingerprints, prompt lineage, and semantic clusters. LiveCodeBench illustrates the value of continuously collected post-cutoff code tasks [30]. Hyperion maintains private future SDK/schema tasks and rotates them; a public rolling suite eventually becomes trainable and cannot remain sealed forever.

### 12.7 Statistical decision rule

For binary paired outcomes, report paired bootstrap confidence intervals and McNemar tests. Preregister a smallest meaningful improvement, for example an absolute `+2.0` percentage points in sealed accepted pass@1 with no hard-gate regression. Correct for multiple architecture comparisons or reserve a final untouched confirmation set. Efficiency wins require identical hardware, runtime, batch policy, precision, and thermal conditions.

## 13. Inference and serving design

### 13.1 Request path

The served artifact identity binds weights, tokenizer, task lane, quantization, runtime, kernels, context policy, retrieval pack, output grammar, verifier, and threshold. A change to any identity requires compatibility evaluation.

```text
Policy/auth -> retrieve -> prefix/cache admission -> HTT decode
     -> grammar mask -> tool loop -> candidate selection -> inert artifact
```

The desktop cannot select a private checkpoint, bypass readiness, or supply an arbitrary adapter.

### 13.2 Exact attention kernels

FlashAttention is an exact IO-aware algorithm that tiles attention to avoid materializing the full score matrix [6]. FlashAttention-2 improved parallelism and work partitioning and reported substantial throughput gains on tested A100 configurations [7]. It does not remove quadratic arithmetic. HTT requires an SDPA-compatible exact fallback and verifies logits/artifacts across kernel versions within declared tolerances.

### 13.3 Quantization profiles

Keep BF16 master and reference-serving artifacts. Candidate deployment profiles are:

- W8A8 or INT8 when target hardware has strong kernels;
- W4A16 weight-only AWQ or GPTQ for memory-constrained inference;
- optional quantization-aware training only after post-training quantization fails a measured slice.

GPTQ [43], AWQ [44], and SmoothQuant [45] report strong large-model compression results. Small narrow models and exact numeric/code tokens may be more sensitive. Promotion requires float-versus-quantized parity for compile, hidden behavior, visual data binding, refusal, calibration, and long-context exact copying. Weight quantization does not shrink KV cache; GQA and local layers remain important.

### 13.4 Batching and cache management

Use continuous batching only within compatible artifact identities and privacy isolation. Paged KV allocation reduces fragmentation [26]. Cache prefixes only when policy, tenant isolation, evidence hash, task lane, model artifact, and grammar identity match. Never share user or private-evidence prefixes across unauthorized principals. Zeroize released blocks according to the serving threat model.

### 13.5 Speculative decoding

Speculative decoding can preserve the target distribution while accepting tokens proposed by a cheaper draft model [27]. Because HTT itself is small and grammar masking is strict, draft overhead may outweigh savings. Evaluate only after measuring real output lengths and acceptance; bind the draft artifact and rejection sampler to the serving manifest.

### 13.6 Operational targets, not claims

Initial research gates should be expressed as hardware-specific targets rather than promises:

- no out-of-memory at approved context and concurrency;
- p95 latency and throughput measured after warm-up;
- zero artifact divergence across repeated deterministic runs;
- bounded repair attempts and tool time;
- quantized accepted pass@1 within the preregistered non-inferiority margin;
- graceful admission control under KV pressure;
- rollback to the last ready artifact.

## 14. Ablation and research matrix

### 14.1 Mandatory architecture ablations

| ID | Question | Control | Variant | Primary decision metric |
|---|---|---|---|---|
| A1 | Does GQA preserve accuracy? | 16 KV heads | 8, 4, 2, 1 | pass@1 vs KV/latency Pareto |
| A2 | Does hybrid attention lose exact recall? | all-global | 3:1 and 5:1 local/global | long-context functional pass@1 |
| A3 | Is 32K necessary? | 8K | 16K and 32K | context-dependent gain per GiB |
| A4 | Does QK-Norm help? | off | on | stability and final pass@1 |
| A5 | Does parser state help? | mask only | embedding plus mask | correctness at equal latency |
| A6 | Do task lanes help? | shared trunk | top-6, top-12, all-layer rank 64 | per-purpose gain and interference |
| A7 | Is 32K vocabulary optimal? | 32K | 16K, 48K, 150K public | tokens, quality, end-to-end latency |
| A8 | Does dependency ordering help? | randomized files | lexical and dependency order | repository repair accuracy |
| A9 | Does selective RAG help? | no/always retrieval | learned or rule selective | quality, provenance, latency |
| A10 | Does constrained decoding help? | unconstrained | envelope, grammar, semantic masks | pass@1 and decode overhead |

### 14.2 Training ablations

| ID | Question | Comparison |
|---|---|---|
| T1 | Is clean-sheet training worthwhile? | random-init HTT vs adapted public small code model |
| T2 | Does synthetic curation help beyond more raw data? | verified synthetic mix vs token-matched admitted raw mix |
| T3 | Does FIM improve repair without generation regression? | 0%, 25%, 50% FIM mixture |
| T4 | Do obsolete-version distractors improve grounding? | current-only vs current plus hard distractors |
| T5 | Does structured plan distillation help? | artifact only vs short checked plan plus artifact |
| T6 | Does DPO add subjective value safely? | SFT vs DPO on equal-correctness pairs |
| T7 | Which RLVR algorithm is stable? | no RL vs RLOO vs GRPO at equal samples |
| T8 | Does self-training generalize? | before/after each verified round on untouched future groups |

### 14.3 Deferred challengers

These experiments cannot replace the reference until they win under the same evidence path:

- Mixture-of-Depths token routing [9]; risk: important syntax tokens skipped and routing hard to inspect.
- Mamba or Mamba-2/attention hybrid [46, 47]; risk: exact arbitrary recall and runtime maturity.
- DeltaNet hybrid [48]; risk: young kernels and unproven Terminal behavior.
- Byte Latent Transformer [37]; risk: tokenizer-free stack complexity and limited tooling.
- BitNet b1.58 [38]; risk: ternary training/runtime support and small-model numeric fidelity.
- Sparse mixture-of-experts [49, 50]; risk: high total parameters, routing, communication, and storage.
- Multi-token prediction [10]; risk: source reports weaker behavior at small scale.
- Native vision repair; risk: data rights, parameters, injection surface, and nondeterminism.

## 15. Failure modes and mitigations

| Failure | Why it matters | Prevention/detection | Response |
|---|---|---|---|
| Hallucinated Terminal API | Can compile against wrong version or fail later | versioned retrieval, allowlist, compiler | reject and retrieve/repair |
| Semantically wrong but compiling strategy | Syntax is not behavior | property, mutation, hidden tests | reject; add counterexample |
| Backtest reward hacking | Encourages leakage/overfit | never use profit as training reward | quarantine experiment |
| Visual chart bound to wrong series | Can look plausible while misleading | data-pixel/geometry lineage tests | reject and repair |
| Out-of-domain response | Violates narrow product purpose | request gate, refusal corpus, artifact grammar | refuse and audit |
| Prompt injection in evidence | Retrieved text may demand authority | provenance, instruction/data separation, policy | ignore/quarantine source |
| Stale retrieval | Old APIs can be plausible | availability/version filters and conflict checks | abstain or request evidence |
| Corpus leakage | Inflates evaluation | lineage dedup and independent sealed custody | invalidate run |
| Memorized private/customer text | Privacy and rights breach | admission controls, canaries, extraction probes | block promotion and investigate |
| Verifier co-adaptation | Generator exploits shared blind spot | independent training, mutants, future tests | rotate verifier/tests |
| Quantization regression | Rare tokens or numbers change | exact artifact parity and slice gates | use higher precision |
| Long-context lost reference | Local attention misses dependency | global layers, retrieval, exact-copy tests | dense fallback or shorter context |
| Adapter lane confusion | Wrong task behavior | server-selected lane and schema | fail closed |
| Model produces authority fields | Attempts to self-approve | coordinator recomputes/ignores fields | reject and log |
| Denial by long output/tool loops | Cost and capacity risk | token, candidate, attempt, tool budgets | terminate safely |

### 15.1 Security test categories

Promotion includes prompt injection, Unicode/confusable, path traversal, code fence escape, schema smuggling, reflection/dynamic load, network and filesystem access, process start, native interop, unsafe code, resource exhaustion, infinite loop, decompression/regex bombs, deserialization, package addition, evidence spoofing, hash mismatch, cross-tenant cache, and diagnostic-injection cases.

### 15.2 Privacy test categories

Use approved canaries to measure exact and approximate extraction, membership-inference risk, cross-request leakage, prefix-cache isolation, log redaction, artifact retention, deletion, teacher-provider exposure, and quantized-artifact parity. Never probe with real secrets.

### 15.3 Model card limitation statement

The final model card must say: HTT is a code/specification generator for bounded Terminal purposes. Passing a verifier does not prove profitability, regulatory suitability, market robustness, or safety for live capital. It must not be used outside the declared SDK, policy, retrieval, compiler, and human-release path.

## 16. Implementation roadmap and decision gates

### Gate 0: protocol review

Review or revise purpose, artifact boundaries, corpus rights policy, architecture candidates, target hardware, evaluation ownership, and maximum research budget.

### Gate 1: data and tokenizer readiness

Required evidence:

- admitted, licensed, deduplicated corpus with lineage;
- no sealed/retrieval-only contamination;
- tokenizer study with exact round-trip and sequence efficiency;
- executable strategy and visualizer test harnesses;
- preregistered metrics and stop conditions.

### Gate 2: small-pilot architecture selection

Train at least three seeds for critical 180M/450M candidates. Select dimensions from functional and efficiency Pareto fronts. Reject the proposed 1.5B shape if local/global attention, task lanes, or vocabulary do not earn their complexity.

### Gate 3: scaling authorization

Fit domain scaling curves, estimate full-run tokens/compute/time, confirm checkpoint and recovery, execute a short end-to-end rehearsal, and obtain explicit budget approval. A pilot does not silently authorize full pretraining.

### Gate 4: frozen model evaluation

Freeze the selected checkpoint, tokenizer, runtime, precision, retrieval pack, grammar, verifier, and thresholds. Evaluate development and calibration first. Only an independent operator unseals the final suite.

### Gate 5: promotion and shadow serving

Promotion requires signed evidence, no hard-gate regression, accepted risk threshold, rollback artifact, startup attestation, and human approval. Shadow mode produces inert artifacts without customer release. Production authorization remains server-side and separate.

### Gate 6: constrained rollout

Begin with low-risk Mock/research purposes, strict capacity, logging, and human review. Expand only from monitored evidence. Model, retrieval, verifier, quantization, and runtime updates each create a new artifact identity.

## 17. Reproducibility and readiness checklist

The reviewer should decide:

- [ ] The two-purpose boundary is correct and complete.
- [ ] The proposed visualizer IR is acceptable as future work and clearly not implemented today.
- [ ] A clean-sheet 1.5B baseline is worth comparing with adapted public small-code models.
- [ ] The 32-layer, 2,048-width, 16Q/4KV, 5,632-FFN shape is an acceptable starting hypothesis.
- [ ] The 3:1 local/global schedule may enter pilots, with all-global as the accuracy control.
- [ ] The 32K domain vocabulary and 32K maximum context may enter tokenizer/context pilots.
- [ ] Stable skills may enter weights while current private Terminal facts remain retrieval-only.
- [ ] Training data rights, provenance, deduplication, and sealed custody are mandatory gates.
- [ ] Compiler, renderer, policy, hidden tests, verifier, calibration, and abstention define accuracy.
- [ ] Backtest profitability is excluded from training reward and model-quality claims.
- [ ] No full pretraining, promotion, or deployment occurs without a separate governance decision.

## 18. Conclusion

The preferred low-parameter architecture should not be the one with the largest collection of fashionable mechanisms. For Hyperion, the research hypothesis is that it will be the smallest reproducible model that places stable skills in weights, changing private facts in retrieval, authority in the coordinator, syntax in constrained decoding, semantics in compilers and tests, uncertainty in calibrated selection, and release in human hands.

HTT-1.5B-r0 is therefore deliberately conservative in its backbone and aggressive in its system constraints. Pre-RMSNorm, RoPE, SwiGLU, moderate GQA, exact attention kernels, and tied embeddings are drawn from prior work, but their combination has not been validated for HTT. The local/global schedule and deterministic task lanes address the specific cost and interference of 32K two-purpose generation, but remain hypotheses. MoE, dynamic depth, state-space, byte-latent, ternary, multi-token, speculative, and native-vision mechanisms are experiments, not assumed improvements.

The next research deliverable is not a production checkpoint. It is a governed corpus manifest, tokenizer report, executable evaluation harness, and small-model ablation report. Only those results can determine whether the proposed architecture is genuinely accurate, fast, parameter-efficient, and safely narrow for the Terminal.

## Appendix A. Formula sheet

### A.1 Parameter model

For tied embeddings, GQA, SwiGLU, two normalization scales, and `L` layers:

```text
P_total ~= Vd + L[2d^2 + 2d*h_kv*d_h + 3d*d_ff + 2d]
          + P_identity + P_adapters.
```

When `h_q*d_h=d` and `d_ff approximately 8d/3`:

```text
P_block approximately (10 + 2*h_kv/h_q)d^2.
```

For MHA, `h_kv/h_q=1`, giving about `12d^2`. For 4:1 GQA it is about `10.5d^2`.

### A.2 Training compute estimate

A common dense-transformer lower-order planning approximation is

```text
F_train approximately 6 * P_active * T_tokens FLOPs.
```

It hides sequence-length, attention, embedding, checkpointing, padding, optimizer, sparsity, and hardware-utilization effects. Hyperion must use profiler measurements from pilots for budget approval, especially because hybrid attention changes the sequence term.

### A.3 Attention and KV scaling

```text
Full score work per layer approximately N^2 * h_q * d_h.
Local score work per layer approximately N * W * h_q * d_h.
KV bytes = 2 * tokens * h_kv * d_h * bytes_per_value * layers.
```

### A.4 Perplexity

For average token negative log likelihood `L_bar`:

```text
perplexity = exp(L_bar).
```

Perplexity is useful for optimization and slice diagnosis but not a substitute for functional artifact accuracy.

### A.5 Pass@k

If `n` candidates contain `c` correct and `k <= n`, the unbiased estimator used in code-generation studies is

```text
pass@k = 1 - C(n-c, k) / C(n, k).
```

For production, report selected pass@1 and total cost because users receive one artifact, not an oracle-selected set.

### A.6 Calibration

For predicted success `p_i` and binary outcome `y_i`:

```text
Brier = (1/N) sum_i (p_i - y_i)^2.
```

Expected calibration error bins predictions and weights the absolute difference between mean confidence and empirical accuracy. Report bin choices and a reliability diagram.

## Appendix B. Proposed visualizer IR validation rules

1. `schemaVersion` is exactly `hyperion-terminal-visualizer/v1`.
2. All objects are closed; unknown properties fail validation.
3. Every input is an allowlisted feed with exact field types and units.
4. Every transform is pure, bounded, deterministic, and allowlisted.
5. Transform graphs are acyclic and have declared warm-up and missing-data behavior.
6. Every series references existing inputs/transforms, pane, and scale.
7. Axis domains, logarithmic constraints, time zones, and units are explicit.
8. Style values come from bounded enums/ranges or approved theme tokens.
9. Every interactive element has keyboard and accessibility metadata.
10. Point counts, update rate, memory, and degradation behavior are bounded.
11. Network, filesystem, process, reflection, package, broker, script, and native-code concepts are unrepresentable.
12. Evidence and compiler identities are recomputed outside the model.
13. The compiled artifact is deterministic for the same IR, data fixture, renderer, fonts, and environment.
14. Output remains inert until separate human review and release.

## Appendix C. Minimum sealed suite composition

The first sealed suite should contain no fewer than the preregistered statistical power analysis requires, with balanced lineage groups across:

- greenfield, completion, repair, and refusal;
- C# and DAXQ strategy forms;
- single-file and multi-file dependencies;
- common indicators and rare numeric/state edge cases;
- current, obsolete, missing, and conflicting evidence;
- 1K, 4K, 8K, 16K, and 32K meaningful contexts;
- line/candle/histogram/footprint/order-book/heatmap/surface visualizers;
- light/dark, resolution, density, delayed/missing/burst data, and accessibility;
- direct, obfuscated, nested, and retrieved prompt injection;
- at least one future Terminal SDK/schema revision unseen during training.

Each family includes valid tasks, near-correct mutants, and impossible/underspecified cases where abstention is correct.

## Appendix D. Source decision ledger

| Mechanism/source | Source-reported signal | HTT decision |
|---|---|---|
| Transformer [1] | Parallel attention/FFN sequence modeling | Adopt decoder-only baseline |
| RMSNorm [2] | Comparable source-task quality with simpler normalization | Adopt, reproduce kernels |
| SwiGLU [3] | Better source-task perplexity at matched compute | Adopt tensor-rounded width |
| RoPE [4] | Relative displacement in attention | Adopt at trained length |
| GQA [5] | Source-task quality near MHA, decoding near MQA | Adopt 4:1; ablate |
| FlashAttention/2 [6,7] | Exact attention with lower IO and faster source runs | Adopt supported exact kernels |
| Mistral/Gemma local attention [8,36] | Reduced long-context cache/compute in source models | Adopt 3:1 research hypothesis |
| Mixture-of-Depths [9] | Fixed-compute token routing in source experiments | Defer |
| Multi-token prediction [10] | Larger-model code/speed gains; small-model caveat | Defer pending scale pilots |
| Qwen2.5-Coder [11] | Small code models, GQA, FIM/repository tokens | Use as comparator/design evidence |
| DeepSeek-Coder [12] | Repository and dependency-aware code training | Adopt data-layout experiment |
| RAG [13] | Explicit non-parametric memory and provenance | Adopt for changing facts |
| RLOO/GRPO [14,15] | Simpler RL alternatives in source settings | Compare only after SFT |
| RepoCoder/Repoformer/RAFT [16-18] | Iterative/selective/domain retrieval benefits | Adopt controlled retrieval study |
| DoReMi [19] | Proxy data-mixture optimization | Adopt small proxy experiment |
| Dedup [20] | Less memorized emission and leakage | Mandatory governance |
| StarCoder2 [21] | Data improvements can outweigh size | Use as curation evidence |
| SynCode [22] | Grammar-constrained syntax improvements | Adopt, retain semantic checks |
| LEVER [23] | Execution-aware verification gains | Adopt independent verifier study |
| Verifier/process supervision [24,25] | Candidate verification/process labels helped source tasks | Adopt checkable states, not hidden CoT |
| PagedAttention [26] | Cache paging/serving utilization | Adopt if runtime qualifies |
| Speculative decoding [27] | Exact-distribution speedup | Optional serving experiment |
| HumanEval+ [28] | Stronger tests changed scores/rankings | Mandate expanded domain tests |
| Calibration [29] | Self-assessment shifts and multiple-sample effects | Calibrate on tool outcomes |
| LiveCodeBench [30] | Post-cutoff rolling evaluation | Maintain future Terminal suite |
| Phi family [31,32] | Curated/synthetic small-model results | Motivate, do not extrapolate |
| Scaling laws [33,34] | Compute/data/model balance | Fit domain-specific pilots |
| Qwen3 [35] | Modern small dense baseline and QK-Norm | Comparator; ablate QK-Norm |
| BLT/BitNet [37,38] | New efficiency routes | Deferred challengers |
| Textbooks/Distillation [31,40] | Curated code and rationale distillation signals | Verified synthetic/SFT pilots |
| ReST-EM/DPO [41,42] | Self-training and preference methods | Later controlled stages |
| GPTQ/AWQ/SmoothQuant [43-45] | Quantized deployment evidence | Exact-artifact parity study |

## References

[1] Vaswani, A. et al. "Attention Is All You Need." NeurIPS, 2017. https://arxiv.org/abs/1706.03762

[2] Zhang, B. and Sennrich, R. "Root Mean Square Layer Normalization." NeurIPS, 2019. https://arxiv.org/abs/1910.07467

[3] Shazeer, N. "GLU Variants Improve Transformer." 2020. https://arxiv.org/abs/2002.05202

[4] Su, J. et al. "RoFormer: Enhanced Transformer with Rotary Position Embedding." 2021. https://arxiv.org/abs/2104.09864

[5] Ainslie, J. et al. "GQA: Training Generalized Multi-Query Transformer Models from Multi-Head Checkpoints." EMNLP, 2023. https://arxiv.org/abs/2305.13245

[6] Dao, T. et al. "FlashAttention: Fast and Memory-Efficient Exact Attention with IO-Awareness." NeurIPS, 2022. https://arxiv.org/abs/2205.14135

[7] Dao, T. "FlashAttention-2: Faster Attention with Better Parallelism and Work Partitioning." 2023. https://arxiv.org/abs/2307.08691

[8] Jiang, A. Q. et al. "Mistral 7B." 2023. https://arxiv.org/abs/2310.06825

[9] Raposo, D. et al. "Mixture-of-Depths: Dynamically Allocating Compute in Transformer-Based Language Models." 2024. https://arxiv.org/abs/2404.02258

[10] Gloeckle, F. et al. "Better & Faster Large Language Models via Multi-token Prediction." 2024. https://arxiv.org/abs/2404.19737

[11] Hui, B. et al. "Qwen2.5-Coder Technical Report." 2024. https://arxiv.org/abs/2409.12186

[12] Guo, D. et al. "DeepSeek-Coder: When the Large Language Model Meets Programming - The Rise of Code Intelligence." 2024. https://arxiv.org/abs/2401.14196

[13] Lewis, P. et al. "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." NeurIPS, 2020. https://arxiv.org/abs/2005.11401

[14] Ahmadian, A. et al. "Back to Basics: Revisiting REINFORCE Style Optimization for Learning from Human Feedback in LLMs." 2024. https://arxiv.org/abs/2402.14740

[15] Shao, Z. et al. "DeepSeekMath: Pushing the Limits of Mathematical Reasoning in Open Language Models." 2024. https://arxiv.org/abs/2402.03300

[16] Zhang, S. et al. "RepoCoder: Repository-Level Code Completion Through Iterative Retrieval and Generation." 2023. https://arxiv.org/abs/2303.12570

[17] Wu, D. et al. "Repoformer: Selective Retrieval for Repository-Level Code Completion." ICML, 2024. https://arxiv.org/abs/2403.10059

[18] Zhang, T. et al. "RAFT: Adapting Language Model to Domain Specific RAG." 2024. https://arxiv.org/abs/2403.10131

[19] Xie, S. M. et al. "DoReMi: Optimizing Data Mixtures Speeds Up Language Model Pretraining." NeurIPS, 2023. https://arxiv.org/abs/2305.10429

[20] Lee, K. et al. "Deduplicating Training Data Makes Language Models Better." ACL, 2022. https://arxiv.org/abs/2107.06499

[21] Lozhkov, A. et al. "StarCoder 2 and The Stack v2: The Next Generation." 2024. https://arxiv.org/abs/2402.19173

[22] Ugare, S. et al. "SynCode: LLM Generation with Grammar Augmentation." 2024. https://arxiv.org/abs/2403.01632

[23] Ni, A. et al. "LEVER: Learning to Verify Language-to-Code Generation with Execution." ICML, 2023. https://arxiv.org/abs/2302.08468

[24] Cobbe, K. et al. "Training Verifiers to Solve Math Word Problems." 2021. https://arxiv.org/abs/2110.14168

[25] Lightman, H. et al. "Let's Verify Step by Step." ICLR, 2024. https://arxiv.org/abs/2305.20050

[26] Kwon, W. et al. "Efficient Memory Management for Large Language Model Serving with PagedAttention." SOSP, 2023. https://arxiv.org/abs/2309.06180

[27] Leviathan, Y. et al. "Fast Inference from Transformers via Speculative Decoding." ICML, 2023. https://arxiv.org/abs/2211.17192

[28] Liu, J. et al. "Is Your Code Generated by ChatGPT Really Correct? Rigorous Evaluation of Large Language Models for Code Generation." NeurIPS, 2023. https://arxiv.org/abs/2305.01210

[29] Kadavath, S. et al. "Language Models (Mostly) Know What They Know." 2022. https://arxiv.org/abs/2207.05221

[30] Jain, N. et al. "LiveCodeBench: Holistic and Contamination Free Evaluation of Large Language Models for Code." 2024. https://arxiv.org/abs/2403.07974

[31] Gunasekar, S. et al. "Textbooks Are All You Need." 2023. https://arxiv.org/abs/2306.11644

[32] Abdin, M. et al. "Phi-3 Technical Report: A Highly Capable Language Model Locally on Your Phone." 2024. https://arxiv.org/abs/2404.14219

[33] Kaplan, J. et al. "Scaling Laws for Neural Language Models." 2020. https://arxiv.org/abs/2001.08361

[34] Hoffmann, J. et al. "Training Compute-Optimal Large Language Models." NeurIPS, 2022. https://arxiv.org/abs/2203.15556

[35] Yang, A. et al. "Qwen3 Technical Report." 2025. https://arxiv.org/abs/2505.09388

[36] Gemma Team. "Gemma 3 Technical Report." 2025. https://arxiv.org/abs/2503.19786

[37] Pagnoni, A. et al. "Byte Latent Transformer: Patches Scale Better Than Tokens." 2024. https://arxiv.org/abs/2412.09871

[38] Ma, S. et al. "The Era of 1-bit LLMs: All Large Language Models are in 1.58 Bits." 2024. https://arxiv.org/abs/2402.17764

[39] Pinnaparaju, N. et al. "Stable Code Technical Report." 2024. https://arxiv.org/abs/2404.01226

[40] Hsieh, C.-Y. et al. "Distilling Step-by-Step! Outperforming Larger Language Models with Less Training Data and Smaller Model Sizes." ACL, 2023. https://arxiv.org/abs/2305.02301

[41] Singh, A. et al. "Beyond Human Data: Scaling Self-Training for Problem-Solving with Language Models." TMLR, 2024. https://arxiv.org/abs/2312.06585

[42] Rafailov, R. et al. "Direct Preference Optimization: Your Language Model is Secretly a Reward Model." NeurIPS, 2023. https://arxiv.org/abs/2305.18290

[43] Frantar, E. et al. "GPTQ: Accurate Post-Training Quantization for Generative Pre-trained Transformers." ICLR, 2023. https://arxiv.org/abs/2210.17323

[44] Lin, J. et al. "AWQ: Activation-aware Weight Quantization for LLM Compression and Acceleration." MLSys, 2024. https://arxiv.org/abs/2306.00978

[45] Xiao, G. et al. "SmoothQuant: Accurate and Efficient Post-Training Quantization for Large Language Models." ICML, 2023. https://arxiv.org/abs/2211.10438

[46] Gu, A. and Dao, T. "Mamba: Linear-Time Sequence Modeling with Selective State Spaces." 2023. https://arxiv.org/abs/2312.00752

[47] Dao, T. and Gu, A. "Transformers are SSMs: Generalized Models and Efficient Algorithms Through Structured State Space Duality." ICML, 2024. https://arxiv.org/abs/2405.21060

[48] Yang, S. et al. "Parallelizing Linear Transformers with the Delta Rule over Sequence Length." NeurIPS, 2024. https://arxiv.org/abs/2406.06484

[49] Shazeer, N. et al. "Outrageously Large Neural Networks: The Sparsely-Gated Mixture-of-Experts Layer." ICLR, 2017. https://arxiv.org/abs/1701.06538

[50] Fedus, W. et al. "Switch Transformers: Scaling to Trillion Parameter Models with Simple and Efficient Sparsity." JMLR, 2022. https://arxiv.org/abs/2101.03961

[51] Allal, L. B. et al. "SantaCoder: Don't Reach for the Stars!" 2023. https://arxiv.org/abs/2301.03988

[52] CodeGemma Team. "CodeGemma: Open Code Models Based on Gemma." 2024. https://arxiv.org/abs/2406.11409

[53] Bavarian, M. et al. "Efficient Training of Language Models to Fill in the Middle." 2022. https://arxiv.org/abs/2207.14255

[54] Liu, Z. et al. "MobileLLM: Optimizing Sub-billion Parameter Language Models for On-Device Use Cases." 2024. https://arxiv.org/abs/2402.14905

[55] Chen, B. et al. "CodeT: Code Generation with Generated Tests." ICLR, 2023. https://arxiv.org/abs/2207.10397

## Repository sources consulted

- `AGENTS.md`
- `README.md`
- `docs/architecture/hyperion-frontier-architecture.md`
- `docs/engineering/hyperion-llm-coordinator-handbook.md`
- `docs/guides/hyperion-coordinator.md`
- `docs/research/kimi-k3-adoption-notes.md`
- `src/windows/AI/TradingTerminal.Ai.Coordinator.Contracts/Contracts/CoordinatorStrategyArtifacts.cs`
- `src/windows/Tools/DaxAlgo.Daxq.Compiler/Authoring/DaxqAuthoringContracts.cs`
- read-only shared-core chart and strategy-builder documentation under `public/`

Repository sources describe implementation and governance boundaries; they are not empirical evidence that HTT has been trained or evaluated.
