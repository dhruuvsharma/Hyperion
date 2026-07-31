# Hyperion frontier architecture synthesis
Status: complete

## Goal
Expand Hyperion's target architecture using the strongest applicable public model, training,
post-training, agent, inference, evaluation, and cluster designs available online as of 31 July
2026. Treat licence, payment, and permission as user-managed acquisition metadata rather than an
architectural exclusion, while preserving source provenance and honest implementation status.

## Hypothesis (files/symbols)
- The canonical architecture should be a new source-controlled design under `docs/architecture/`.
- `docs/research/hyperion-expert-model.md`, the Kimi K3 note, README, and the engineering handbook
  must route to the same target architecture and evidence boundaries.
- The existing document builder can regenerate the Word/PDF handoff after Markdown and diagram
  updates without changing runtime code or signed compatibility surfaces.

## Questions and answers
- Scope: architecture and engineer handoff only; do not pretend every proposed mechanism is already
  implemented.
- Research breadth: include public primary-source designs and paid/permissioned model services where
  technically useful. No access-control bypass or unsupported reconstruction of private details.
- Licence policy: record provenance, terms, cost, and permission owner for reproducibility; do not
  reject a candidate solely because it is commercial, custom-licensed, or permissioned.
- Training evidence: no Hyperion weights, checkpoint, benchmark acceptance, or deployment exists yet.

## Plan
1. Audit current Hyperion architecture and public frontier sources.
2. Define the target model portfolio, data/training stack, agent runtime, inference fabric, and GPU
   cluster architecture with staged adoption decisions.
3. Update Markdown, diagrams, Word, and PDF from one synchronized source.
4. Run source, document, visual, boundary, Git, and CI closure; commit and push to private Hyperion.

## Blast radius
- `D:\Github\Hyperion` only.
- Documentation, diagrams, document builder, generated DOCX/PDF, and this task record.
- `public/` remains a pinned read-only submodule; no Pro or shared-core code is copied or edited.

## Build filter
- Documentation builder and document/PDF QA.
- Existing Markdown/link/source checks and any focused builder tests.
- Full runtime test suites only if implementation code changes.

## Tests to run
- Primary-source URL and claim audit with accessed dates.
- Markdown structure/link checks and no-placeholder scan.
- Rebuild DOCX/PDF; structural, accessibility, page, font, and text checks.
- Render and visually inspect every final page.
- Git diff/EOL/UTF-8/boundary/status checks; hosted CI after push.

## Findings (cache narrow reads here)
- The target must be a governed model portfolio, not one universal checkpoint: hosted frontier
  teachers, large downloadable teachers, small-cluster students, domain/effort adapters, routers,
  critics/judges, embeddings, and rerankers all retain separate authority ceilings.
- Source review covered GPT-5.6/gpt-oss, Kimi K3, Qwen3/Qwen3-Coder/Qwen3.5, DeepSeek V3/R1,
  GLM-5/5.2, Llama 4, Gemini 3.1 Pro, Claude Fable 5, MiniMax-M2.5, Devstral Small 2, Falcon-H1,
  SFT/DPO/RLOO/GRPO/RLVR/on-policy distillation, coding/tool-agent evaluation, vLLM/SGLang/
  TensorRT-LLM, FSDP/ZeRO/Megatron, TRL/veRL/OpenRLHF/NeMo RL/Ray, Slurm, and NCCL.
- Kimi K3 has a live arXiv paper and official repository/article. Its KDA, Gated MLA, Stable
  LatentMoE, effort-specialist, long-agent-rollout, and deployment-aware-precision disclosures are
  source claims and research inputs; the full model is not a small-cluster student.
- Paid, gated, custom-licensed, or separately permissioned candidates remain technically eligible.
  Hyperion records the user-designated acquisition/permission owner, terms snapshot, price,
  attribution, data policy, exact revision, and expiry rather than using licence class as a ranking
  filter. Undisclosed/private internals remain unknown and access controls are not bypassed.
- The staged training decision is raw-base/retrieval bake-off -> verified SFT -> DPO if SFT passes ->
  matched RLOO/GRPO with executable rewards -> routed specialists -> on-policy/multi-teacher work
  only with authorised probabilities/logits -> equal-compute pretraining ablations.
- The current repository still has no approved production corpus, conforming training run, trained
  checkpoint, accepted model-quality result, or production deployment.
- Independent closure found and resolved one medium documentation conflict: 10 GbE is now limited
  to management, artifact distribution, and independent single-node jobs; measured 25 GbE or faster
  is required for cross-node collectives, with qualified 100 GbE/RDMA preferred for Tier C or
  sustained model/expert parallel work. Both final audits found no remaining high or medium issue.

## Diff summary
- Added `docs/architecture/hyperion-frontier-architecture.md` as the canonical target architecture.
- Expanded the engineering handbook with the model portfolio, permission-managed registry,
  distillation/RL ladder, bounded agent graph, evaluation scorecard, inference fabric, cluster tiers,
  and implementation phases; synchronized the expert-model and Kimi K3 research notes and README.
- Added a sixth native handbook diagram for the frontier model factory and updated the document
  builder to support variable-height layered diagrams, descriptive hyperlink labels, and version 1.1.
- Rebuilt and published the synchronized DOCX/PDF handoff. No runtime, schema, signed wire, model
  weight, checkpoint, secret, or `public/` file changed.

## Verification
- Primary-source audit: all 111 unique cited URLs resolved successfully on 31 July 2026.
- Markdown audit: six scoped files are strict UTF-8/LF with valid heading hierarchy; all 15 local
  links resolve; no mojibake, placeholder, secret-like token, weight/checkpoint, or diff-whitespace
  finding.
- Document build: builder completed; DOCX ZIP integrity passed; six images are inline with alt text;
  heading, image, and section audits passed. Accessibility is 0 high, 0 medium, 0 low.
- PDF: 46 Letter pages, tagged, unencrypted, 1,015,904 bytes; all five font rows are embedded and all
  six diagrams are present. Text extraction retained the sampled architecture and final network-tier
  terms; no page has anomalously low text. Pages 1-32 remained pixel-identical after the final audit
  correction, and pages 33-46 were independently reinspected at original render detail with no
  clipping, overflow, missing image, blank page, broken flow, or unreadable table.
- Python model-tool regression: 494 passed and five expected Windows POSIX/symlink-capability tests
  skipped in 515.51 seconds. The edited builder passes Ruff lint and `py_compile`.
- `python -m ruff format --check tools/docs/build_hyperion_handbook.py` still reports the builder's
  pre-existing whole-file formatter drift (a mechanical rewrite would touch 327 lines); it was not
  applied because it is unrelated churn. The model-tool package formatter was not affected.
- `git diff --check`, declared LF policy, clean pinned `public/` status, exact submodule pointer
  `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05`, and secret/weight scans passed.

## Risks / deferred
- "All online information" is unbounded and continuously changing. The architecture will use a
  dated, extensible evidence registry and representative frontier families rather than claim a
  permanently exhaustive internet inventory.
- Paid/private implementation details that are not publicly documented remain unknown until the
  user supplies authorized material.
- The broader online inventory changes continuously; refresh source/model/framework records before
  acquisition or experiment execution.
- Runtime registry/schema/provider/training implementation is a later slice. This architecture and
  passing infrastructure tests do not constitute a trained model milestone.
