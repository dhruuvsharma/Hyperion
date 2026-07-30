# Hyperion source provenance

Hyperion was independently initialized on 30 July 2026. The initial private source snapshot was
exported from committed Git objects, not from the concurrently dirty working tree.

| Layer | Source | Pinned revision | Treatment |
|---|---|---|---|
| Private coordinator and Platform | `dhruuvsharma/DaxAlgo-Terminal-Pro` | `003685a92e7ddba9e4149d3bb545f4ce82446f3e` | Selected coordinator, model, verifier, hosted, DAXQ, test, and documentation files copied into this private repository. |
| Shared Core/SDK | `dhruuvsharma/DaxAlgo-Terminal` | `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05` | Retained as the read-only `public/` Git submodule; not copied into Hyperion history. |

Initial extraction scope:

- 40 coordinator/contracts/client/CLI files;
- the complete Python model system: 28 package files, 19 test files, 113 schemas, fixtures, and
  pinned candidate/runtime manifests;
- 12 coordinator test files plus shared test assembly support;
- 15 verifier-worker files and its focused tests;
- the hosted Platform source/test solution needed to preserve the exact credit, persistence,
  promotion, readiness, and worker integration;
- the DAXQ Contracts/VM/Compiler verification dependency closure and tests;
- the bounded Terminal hosted-authoring adapter snapshot; and
- the original coordinator operator/research documents and historical task record.

Ignored local `tmp/vibe-quant-model` material, caches, build output, private keys, credentials, and
model weights were deliberately excluded. The ignored source tree contained draft/rehearsal data,
not an authorized training release or trained checkpoint.

Visible Hyperion branding is additive. Legacy namespaces, API paths, database field names, schema
IDs, signature domains, prompt hashes, and serialized values remain unchanged when their bytes are
part of a compatibility or trust contract. A future rename of those values requires a separately
versioned migration with dual-read/dual-verify tests; global text replacement is prohibited.
