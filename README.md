# Hyperion

Hyperion is a private, evidence-gated LLM coordinator and expert-model portfolio for strategy
authoring. It combines a durable multi-role coordinator, provenance- and review-aware corpus
tooling, hosted and downloadable teacher integration, small-model distillation/training and
evaluation infrastructure, signed promotion/readiness contracts, a constrained C# verifier, and a
hosted execution adapter.

This repository was extracted from DaxAlgo Terminal Pro at commit
`003685a92e7ddba9e4149d3bb545f4ce82446f3e`. Its shared Core/SDK dependency is pinned as the
`public/` submodule at `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05`. The original checkout is
not a development target for Hyperion after this extraction.

## Current evidence status

- Implemented: coordinator workflows, durable state, OpenAI-compatible and replay providers,
  dataset/review/release gates, retrieval packs, evaluation and promotion evidence, runtime wrappers,
  detached signing handoffs, hosted API integration, and the isolated C# verifier.
- Verified in this repository: 541 .NET tests, 494 Python tests (plus five expected Windows
  POSIX/symlink-capability skips), 113 schemas with 2,029 resolved references, all CLI help surfaces, and
  the digest-pinned verifier Docker build.
- Not yet established: a rights-approved training corpus, production signing custody, a conforming
  GPU-cluster run, trained weights, a checkpoint, benchmark superiority, or production deployment.

## Repository map

| Path | Purpose |
|---|---|
| `src/windows/AI/TradingTerminal.Ai.Coordinator*` | Coordinator contracts, engine, and strict API client (legacy namespaces retained) |
| `src/windows/Tools/DaxAlgo.Coordinator.Cli` | The .NET `hyperion` operator CLI |
| `tools/hyperion-model` | Python training, evaluation, review, verifier, promotion, and serving harness |
| `platform/` | Hosted API, credit authority, worker, verifier worker, and integration tests |
| `src/windows/AI/DaxAlgo.Daxq.*` | Restricted executable-verification dependency closure |
| `public/` | Pinned shared Core/SDK submodule; read-only from Hyperion |
| `docs/engineering/` | ML-engineer handbook in Markdown, Word, and PDF |
| `tasks/` | Durable implementation records |

## Bootstrap

```powershell
git submodule update --init --recursive
dotnet restore Hyperion.slnx
dotnet test Hyperion.slnx --no-restore

cd tools/hyperion-model
python -m venv .venv
.venv\Scripts\python -m pip install -e .[auth,promote] pytest ruff jsonschema
.venv\Scripts\python -m pytest tests
.venv\Scripts\hyperion --help
```

The Python import package and signed schema IDs intentionally retain legacy `vibe_quant_model` and
`daxalgo.vibe-quant.*` names. They are compatibility surfaces, not the product name. See the
engineer handbook for the migration policy, security model, cluster plan, and Kimi K3 research.

## Documentation

- [Frontier expert-model architecture](docs/architecture/hyperion-frontier-architecture.md)
- [Hyperion engineering handbook](docs/engineering/hyperion-llm-coordinator-handbook.md)
  ([Word](docs/engineering/hyperion-llm-coordinator-handbook.docx),
  [PDF](docs/engineering/hyperion-llm-coordinator-handbook.pdf))
- [Coordinator operator and data guide](docs/guides/hyperion-coordinator.md)
- [Expert-model research and serving plan](docs/research/hyperion-expert-model.md)
- [Kimi K3 review and Hyperion adoption notes](docs/research/kimi-k3-adoption-notes.md)
