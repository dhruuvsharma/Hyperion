# Hyperion products

This directory is the user-facing product map. Build-oriented source remains under `src/`, `tools/`,
and `platform/` so existing project references, wire identities, and release automation stay stable.

| Product | Purpose | Implementation state |
|---|---|---|
| [HTT](htt/README.md) | Narrow Hyperion Terminal Transformer research and future model artifacts | Research paper complete; no trained weights |
| [Hyperion CLI](hyperion-cli/README.md) | One command-line entry point for hosted operations and isolated local workflows | Hosted and free-workflow commands implemented |
| [Free Strategy Workflow](free-strategy-workflow/README.md) | Local/BYOK five-role strategy authoring with other model providers | Provider-neutral library, external-adapter seam, and CLI path implemented |

`public/` remains a pinned read-only shared-core submodule. Product code in this repository is never
copied into that submodule.
