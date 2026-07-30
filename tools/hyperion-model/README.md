# Hyperion model harness

Hyperion is the product name. Use the `hyperion-model` command for new model work. The
`vibe_quant_model` import package, legacy `vibe-quant-model` command alias, schema IDs, and signed
payload vocabulary remain supported compatibility surfaces. Use `hyperion` for the .NET coordinator.

This Pro-private Python 3.11+ tool structurally validates `ExpertModelDatasetTools` SFT JSONL,
verifies authenticated corpus-review receipts and separately signed exact teacher-materialization
lineage, binds a signed exact-corpus quality admission, freezes a reviewed model candidate and
QLoRA-SFT recipe, signs an evidence-bound raw-base selection, creates a hash-bound run bundle, and
records offline calibration/sealed evaluation evidence. It also captures source-grounded, multi-seed
open-weight teacher candidates into an explicitly unreviewed and non-training review queue.
Structural validation, coverage, and unbound research commands use only the Python standard library.
Signed admission/receipt issuance and every receipt-bound consumer require the optional `auth`
cryptography dependency; promotion environments use `promote`, and the sealed trainer lock pins the
same dependency.

Production-candidate training is narrower than the validators: it is sealed to CPython 3.11 on
Linux x86_64, CUDA 12.1, and the exact wheel-only PEP 751 environment in `pylock.train.toml`.
`training-runtime-profile.v1.json` binds that lock's SHA-256 and direct dependency versions. A run
on Windows, another Python minor, another CUDA runtime, or different installed versions fails before
GPU probing or model construction; smoke runs do not bypass this identity check.

The checked-in candidate catalog pins all four shortlisted models to immutable 40-character commits
verified against their official Hugging Face metadata on 2026-07-27. Catalog validation remains
offline: it never resolves a branch, tag, or `main` and never contacts a model host. Re-verify the
licence, commit, and provider terms before approving a real run; the pins are reproducibility
identities, not a model-selection or deployment approval.

## Safe sequence

From this directory, create a Python 3.11+ environment and install the local package:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
```

1. Complete independent per-row review and issue a detached receipt set before exporting
   training-approved development examples through `ExpertModelDatasetTools`. For any
   `OpenWeightTeacher` row, first obtain a separately signed exact-materialization lineage admission;
   the admission signer and receipt signer must be distinct. Do not assemble SFT rows by hand and do
   not include calibration or sealed examples in a training bundle. `validate-sft` is deliberately
   structural only: it cannot attest review, rights, approval, or authorization.
2. Copy `candidate-catalog.v1.json` under `../../tmp/vibe-quant-model/`, independently review the
   pinned immutable commits and licences, then validate the copied bytes:

   ```powershell
   .venv\Scripts\vibe-quant-model validate-catalog ..\..\tmp\vibe-quant-model\candidates.pinned.json
   ```

3. Validate the exported bytes and inspect both structural coverage and the deterministic
   anti-inflation corpus-quality report. A separately trusted reviewer must select and sign the exact
   policy thresholds for the exact released SFT bytes; the repository contains no approved policy or
   numerical production minima. The report uses exact rational weights for multi-domain rows and
   exposes task/domain/domain-task coverage, contamination-family diversity and concentration,
   origins, producers, and maximum labels per row. The admission signer, policy hash, release,
   dataset, report, and expiry are externally pinned and revalidated before training.

   ```powershell
   .venv\Scripts\vibe-quant-model validate-sft <expert.sft.jsonl>
   .venv\Scripts\vibe-quant-model summarize-coverage <expert.sft.jsonl>
   .venv\Scripts\vibe-quant-model summarize-corpus-quality <expert.sft.jsonl>
   .venv\Scripts\vibe-quant-model validate-corpus-quality-policy <reviewed-policy.json>
   ```

4. Run one release-bound raw-base comparison for every catalog `student` through the attested owner,
   then independently review the complete bake-off and issue a short-lived base-model selection v2.
   `--bakeoff-sources` accepts a strict
   `daxalgo.vibe-quant.base-model-selection-sources/v1` path manifest with the selected candidate ID
   and one evidence/response/result/policy/profile/snapshot source per student. Paths are operational
   inputs only: candidate and baseline launcher/runtime trust remain externally pinned. Creation
   freshly replays every row, derives completeness from the validated catalog, requires a common
   release, calibration set, sealed set, seed, source lock, policy family, and attested raw-base-v2
   baseline, and permits only a passing row to be selected.
   The signed matrix and exact target authorize only that base as a training input; they are not a
   checkpoint, promotion, deployment, or quality claim. Independently run
   `validate-base-model-selection` with the same live sources and pinned trust. No real selection is
   checked in; v1 pair-only selections cannot authorize production training.

5. Obtain the exact chat template from the already reviewed, locally installed model/tokenizer,
   save it as UTF-8, and review it. It must be a substantive Jinja template referencing
   `messages`, `role`, and `content`; placeholders such as `REPLACE_WITH`, `TODO`, and `TBD` are
   rejected case-insensitively. Independently review the checked-in runtime profile and pylock, then
   create the manifest-v3 bundle. This snapshots and hash-binds the catalog, SFT, runtime profile,
   complete wheel lock, template, signed corpus admission, signed selection, selected profile,
   snapshot manifest, and source lock before writing the manifest; it does **not** copy model weights or train. The selected
   candidate and chat template must match exactly. An adjacent exclusive lock and no-clobber install
   prevent concurrent writers or replacement of an existing bundle.

   ```powershell
   .venv\Scripts\vibe-quant-model create-bundle `
     --catalog ..\..\tmp\vibe-quant-model\candidates.pinned.json `
     --sft <expert.sft.jsonl> `
     --candidate-id qwen2.5-coder-7b-instruct `
     --chat-template-file <reviewed-template.jinja> `
     --chat-template-name <reviewed-name-and-version> `
     --runtime-profile .\training-runtime-profile.v1.json `
     --release <vqrel-training-evaluation-directory> `
     --review-receipt-public-key <reviewer-public-key.pem> `
     --review-receipt-public-key-spki-sha256 <64-lowercase-hex> `
     --review-receipt-audience <review-audience> `
     --review-receipt-key-id <review-key-id> `
     --review-receipt-signer-role <independent-reviewer-role> `
     --evaluation-authoring-approval-public-key <authoring-reviewer-public-key.pem> `
     --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> `
     --evaluation-authoring-approval-audience <authoring-audience> `
     --evaluation-authoring-approval-key-id <authoring-key-id> `
     --evaluation-authoring-approval-signer-role <authoring-reviewer-role> `
     --corpus-admission <signed-corpus-admission-envelope.json> `
     --corpus-admission-public-key <corpus-reviewer-public-key.pem> `
     --corpus-admission-public-key-spki-sha256 <64-lowercase-hex> `
     --corpus-admission-audience <corpus-admission-audience> `
     --corpus-admission-key-id <corpus-admission-key-id> `
     --corpus-admission-signer-role <corpus-quality-reviewer-role> `
     --corpus-admission-quality-policy-sha256 <64-lowercase-hex> `
     --base-selection <signed-selection-envelope.json> `
     --base-evaluation-profile <selected-profile.json> `
     --base-model-snapshot-manifest <selected-snapshot-manifest.json> `
     --base-model-snapshot <external-selected-snapshot-directory> `
     --base-model-source-lock .\base-model-source-lock.v1.json `
     --base-selection-public-key <selection-reviewer-public-key.pem> `
     --base-selection-public-key-spki-sha256 <64-lowercase-hex> `
     --base-selection-audience <selection-audience> `
     --base-selection-key-id <selection-key-id> `
     --base-selection-signer-role <selection-reviewer-role> `
     --output ..\..\tmp\vibe-quant-model\runs\run-001
   .venv\Scripts\vibe-quant-model validate-bundle ..\..\tmp\vibe-quant-model\runs\run-001
   ```

6. Review the bundle and manifest before building the training image. Generate the committed lock
   only with its recorded `uv 0.11.32` command; install that lock inside the matching Linux/CUDA
   image, then install this package without resolving another dependency graph. Training is
   local/offline only (`local_files_only` plus forced Hub, datasets, and Transformers offline modes).
   It requires the exact selected snapshot through an external read-only directory and fails before
   model construction unless the signed selection, snapshot, sealed runtime, and visible CUDA GPU
   with at least 16 GiB all match:

   ```bash
   uv venv --python 3.11 .venv
   uv pip sync pylock.train.toml --python .venv/bin/python --strict
   uv pip install --python .venv/bin/python --no-deps -e .
   .venv/bin/vibe-quant-model train \
     ../../tmp/vibe-quant-model/runs/run-001/training-run-manifest.json \
     --release <vqrel-training-evaluation-directory> \
     --review-receipt-public-key <reviewer-public-key.pem> \
     --review-receipt-public-key-spki-sha256 <64-lowercase-hex> \
     --review-receipt-audience <review-audience> \
     --review-receipt-key-id <review-key-id> \
     --review-receipt-signer-role <independent-reviewer-role> \
     --evaluation-authoring-approval-public-key <authoring-reviewer-public-key.pem> \
     --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> \
     --evaluation-authoring-approval-audience <authoring-audience> \
     --evaluation-authoring-approval-key-id <authoring-key-id> \
     --evaluation-authoring-approval-signer-role <authoring-reviewer-role> \
     --base-model-snapshot <external-selected-snapshot-directory> \
     --base-selection-public-key <selection-reviewer-public-key.pem> \
     --base-selection-public-key-spki-sha256 <64-lowercase-hex> \
     --base-selection-audience <selection-audience> \
     --base-selection-key-id <selection-key-id> \
     --base-selection-signer-role <selection-reviewer-role> \
     --corpus-admission-public-key <corpus-reviewer-public-key.pem> \
     --corpus-admission-public-key-spki-sha256 <64-lowercase-hex> \
     --corpus-admission-audience <corpus-admission-audience> \
     --corpus-admission-key-id <corpus-admission-key-id> \
     --corpus-admission-signer-role <corpus-quality-reviewer-role> \
     --corpus-admission-quality-policy-sha256 <64-lowercase-hex> \
     --trainer-provenance-public-key <trainer-public-key.pem> \
     --trainer-provenance-public-key-spki-sha256 <64-lowercase-hex> \
     --trainer-provenance-audience <trainer-audience> \
     --trainer-provenance-key-id <trainer-key-id> \
     --trainer-provenance-signer-role <trainer-role> \
     --trainer-private-key <trainer-private-key.pem> \
     --trainer-id <trainer-instance-id> \
     --trainer-expires-at-utc <UTC-second>
   ```

For production custody, `--trainer-provenance-handoff <sibling-directory>` replaces
`--trainer-private-key`. Training still preflights the pinned trainer trust, ID, expiry, and signer
separation before model construction, but after optimization it publishes only a closed pending
package: the safe inference tree has no `artifact-metadata.json`, while the sibling artifact-core and
content-addressed signing bundle remain outside that tree. The bundle exposes the exact existing raw
ES256 preimage and its SHA-256 digest. An external service signs either the decoded raw message or the
decoded prehashed digest and returns the closed DER/P1363 signature document. Run
`finalize-training-artifact` with that package, signature, original manifest/release, immutable base
snapshot, and every existing review/authoring/selection/corpus/trainer trust input. Finalization
freshly replays them, copies and rehashes the pending tree, normalizes valid high-S signatures, embeds
the unchanged low-S provenance-v1 envelope, and only then installs the unchanged artifact-v2 wire.

`train --smoke` is the only memory-gate waiver. Legacy manifest v1 and selected manifest v2 are
accepted only for explicit smoke paths; every non-smoke run requires manifest v3, its signed
selection, and the separately signed corpus admission. Smoke is limited to
one step and writes an explicit `productionEligible: false` artifact marker. Lowering
`--minimum-gpu-memory-gib` without smoke mode is rejected. Normal training artifacts are also marked
unpromoted: training alone is never a model promotion claim. Training re-snapshots and hash-verifies
the bound dataset and external model tree, loads both tokenizer and model from that exact local
directory without a mutable revision/cache lookup, gives the trainer only
records parsed from the single verified in-memory byte capture via `Dataset.from_list` (the trainer
never reopens a dataset path), writes into a same-filesystem staging directory, and atomically
    installs the adapter only after training and metadata creation succeed. Failure removes staging output; an
    exclusive output lock prevents concurrent or overwrite attempts. Detached mode holds no output lock
    while an external signer acts and its pending package is not a training artifact or serving input. A
    non-smoke candidate is sealed as
artifact v2 with a separately pinned low-S ES256 trainer-provenance envelope over its exact core
metadata, file tree, manifest, release, model, dataset, and environment identities. The envelope is
issued and activated from the live post-training sealing clock rather than a launch-time prediction,
active for at most 366 days, grants no review, release, future-training, evaluation, promotion,
deployment, installation, or execution authority, and is revalidated with the live clock immediately
before no-clobber installation. Final metadata records the actual
dependency versions, Python/platform, compute dtype, and visible GPU facts after they match the
manifest-bound lock; neither the lock nor that evidence is a promotion report. The final inference
package is deliberately narrow: PEFT is exported with
safe serialization, training checkpoints stay out of the package, and only the reviewed root-level
adapter/tokenizer files are accepted. Pickle, Python, native-library, archive, nested, linked, and
unknown files are rejected; safetensors structure and JSON are validated.

7. After a non-smoke artifact is reviewed, derive its serving profile from the sealed artifact and
   original manifest. The profile binds the candidate catalog, base commit, adapter/tree, chat
   template, serving image digest, runtime, quantisation, hardware class, and native context limit.
   Its raw-byte SHA-256 becomes the private execution model ID. This is an evaluation identity, not
   a production promotion or signature.

   ```powershell
   .venv\Scripts\vibe-quant-model create-serving-profile `
     --profile-id <reviewed-profile-id> `
     --artifact ..\..\tmp\vibe-quant-model\runs\run-001\outputs\adapter `
     --manifest ..\..\tmp\vibe-quant-model\runs\run-001\training-run-manifest.json `
     --engine vllm --engine-version <exact-version> `
     --container-image-digest sha256:<64-lowercase-hex> `
     --quantization bitsandbytes-nf4 --compute-dtype bfloat16 `
     --max-model-length 8192 --tensor-parallel-size 1 --gpu-profile <reviewed-profile> `
     --output ..\..\tmp\vibe-quant-model\profiles\profile.json
    ```

## Base-model evaluation before tuning

The initial student bake-off does not fabricate a training manifest or empty LoRA. The checked-in
`base-model-source-lock.v1.json` freezes the reviewed root inference files for Qwen2.5-Coder 7B,
Qwen2.5-Coder 14B, and gpt-oss-20b at the catalog commits, including every exact SHA-256 and byte
size. Its canonical SHA-256 is compiled into the validator. A base snapshot is accepted only when its
complete root file set exactly matches that lock; linked, nested, executable/custom-code, pickle,
unknown, malformed JSON, invalid safetensors, incomplete shards, and model/template drift fail
closed. The seal is relocatable but content-addressed and rehashes the full snapshot before and
after validation.

`seal-base-model-snapshot` creates the immutable snapshot manifest.
`create-base-evaluation-profile` then binds the catalog, approved source lock, exact snapshot/tree,
chat template, vLLM/container/runtime, quantisation, context limit, and GPU profile. The raw profile
hash derives a separate `daxalgo-base-sha256-*` execution ID. `base-evaluation-launch` emits the
offline loopback vLLM argument/environment contract; it does not start or attest a process.

`capture-base-responses` sends the same verifier-free deterministic
requests as trained-adapter capture and revalidates the full target again before publishing. This
path is deliberately loopback-only and unpromoted.

Release-bound capture uses a separate owner. `create-base-engine-activation` signs one short-lived
activation that binds the wrapper package, exact base profile/source lock/snapshot tree, runtime
signer, vLLM executable/version, and asserted image digest. `serve-base-evaluation-model` then
requires all protected inputs on read-only mounts, opens and hashes the executable inode before
launch, drops the vLLM child to the configured non-root UID/GID, proves that the configured loopback
listener belongs to that owned process group, and allows only the reviewed vLLM 0.10.0 or 0.26.0
argument adapters. Wrapper config v2 keeps the runtime private key outside this process. It pins the
public key and SPKI identity plus one authenticated literal-loopback signer endpoint, provider key
reference, bearer-token environment, exact leaf TLS-certificate hash, signature encoding, total
deadline, and response-size ceiling. The wrapper authenticates the pinned HTTPS peer before sending
the bearer credential. Only after the owned child passes post-load health, signed-version,
model-identity, and immutable-input checks does it request and locally verify a domain-separated
startup proof. The bearer token is never copied into the child environment. Config v1 remains a local development/compatibility path:
its wrapper-owned PEM must have no group/other permissions and is loaded only after the same checks.

Each v2 signing request is canonical JSON and binds a fresh request ID, purpose, provider/key/public
identity, exact raw preimage, and independently recomputable SHA-256 digest. The wrapper makes one
bounded request with no retry, requires an exact canonical response and matching echoes, converts DER
or fixed P1363 to the existing low-S P1363 wire form, and verifies the signature locally. A startup
timeout, substitution, wrong key, accidental double hash, malformed response, or receipt that expires
while signing, TLS substitution, or a slow-drip response beyond the total deadline fails closed. Activation-v1, runtime-attestation-v1, and evaluation-response-v2 wires
and all downstream consumers remain unchanged.

Production launcher-activation custody can also keep its private key outside this process. Run
`prepare-base-engine-activation-signing-bundle` with the exact wrapper config, public launcher
identity, and validity window used by direct creation. Preparation accepts no private key or
password and emits a closed, content-addressed, all-false bundle containing the unchanged
activation-v1 payload, unsigned envelope, trust tuple, raw ES256 preimage, and its SHA-256 digest.
There is deliberately no local detached-signing command: an external KMS/HSM adapter signs either
the decoded raw preimage with ECDSA/SHA-256 or the decoded digest with prehashed ECDSA/SHA-256 and
returns canonical DER or fixed 64-byte P1363. `finalize-base-engine-activation` accepts no private
key, verifies and low-S-normalizes that signature, freshly replays the wrapper config/package,
sealed target, runtime signer, and executable bindings, and no-clobber publishes the unchanged
activation-v1 envelope. Existing wrapper, capture, response-v2, selection, and promotion consumers
remain unchanged; `create-base-engine-activation` remains the local-PEM compatibility route.

The unsigned bundle grants no authority, but a matching valid bundle/signature pair is replayable
exact-activation finalization material until expiry and requires protected custody. This seam does
not provision KMS/HSM IAM, quorum, audit, signer identity, rotation, revocation, honest clocks,
immutable input custody, or privileged/same-user path-swap protection, and it creates no real
activation or signing service.

`capture-attested-base-responses` accepts only the configured literal wrapper endpoint and trust
identity. Every deterministic task gets a fresh nonce and an ES256 receipt binding the activation,
release, task, exact request, exact completion, model identity, process, and argv. The verified
receipt and exact completion are hash-bound into evaluation-response v2. Use
`validate-attested-base-responses` for historical cryptographic verification; ordinary
`validate-responses` is structural. Promotion aggregation accepts response v2 only with the matching
candidate- or baseline-specific launcher trust and runtime public key, then re-verifies every
historical signature from the already parsed response snapshot. Trust is rejected for response v1
and research-only aggregation. Promotion policy identity binds response schema, target kind, and
execution model to prevent silent v2-to-v1 downgrade. Attested raw-base v2 may be the candidate only
for the separate pre-training base-selection decision; the production serving candidate must still
be response-v1 `trained-adapter`.

`create-base-model-selection` authenticates and freshly regenerates the paired evidence for every
catalog student. Pairwise scoring remains unchanged, but the v2 authority canonicalizes the rows in
catalog order, rejects missing, duplicate, extra, or teacher/fallback substitutions, and binds the
complete matrix identity. Non-selected rows may fail quality gates—otherwise a bake-off could not
compare weaker candidates—but every row must be complete, release-bound, response-v2 attested, and
comparable through the same suites, baseline, seed, source lock, and policy family. The chosen row
must pass every quality/regression gate and exactly match its profile/snapshot. Both sides of every
comparison require externally pinned response-v2 activation/runtime trust; an unauthenticated
response-v1 baseline is rejected. `create-bundle`
validates that target against the external snapshot and writes manifest v3 with the exact signed
corpus admission; `train` authenticates both envelopes again and revalidates the captured dataset and
read-only snapshot before loading, after loading, and before publication. The trainer does not
receive the sealed evaluation suite. Selection or corpus-admission expiry
aborts training and prevents artifact publication. Promotion, validation, readiness, and production
activation authenticate the same manifest-bound selection with externally pinned trust and rehash
the exact external snapshot. Candidate serving-profile creation, capture, promotion, readiness, and
engine activation also require the separately pinned trainer-provenance trust. No real bake-off,
selection, trainer signature, or training run has been completed.

Production base-selection custody can keep its private key outside this process. Run
`prepare-base-model-selection-signing-bundle` with the same complete live bake-off, release,
approval evidence, public-key trust, receipt trust, evaluation-authoring trust, candidate/baseline
attestation trust, and, where applicable, the optional C# verifier context used by direct creation.
Preparation accepts no private-key option and publishes one canonical, content-addressed
`unsigned-non-authorizing` bundle containing the exact selection-v2 payload, trust tuple, matrix and
target summaries, raw ES256 envelope-signature preimage, and its SHA-256 digest.

A raw-message signing adapter base64url-decodes `request.signaturePreimage` and asks the external
service to apply ECDSA P-256 with SHA-256 to those exact bytes. A prehashed KMS/HSM adapter instead
base64url-decodes the 32-byte `request.signatureInput` and submits it with ECDSA-SHA-256 prehashed
semantics. Sign exactly one mode: never hash `signatureInput` again, and never sign either base64url
text value as text. The adapter returns a closed
`base-model-selection-signature.v1.schema.json` document bound to the exact bundle bytes, complete
matrix and selected snapshot/tree identities, approval evidence, payload, signature input, and
public-key SPKI hash. It derives `signatureId` with the exported
`base_model_selection_external_signature_id` helper after every other signature-document field is
final.

`finalize-base-model-selection` accepts canonical ASN.1 DER (`format=asn1-der`) or fixed 64-byte
P1363 (`format=ieee-p1363-fixed-64`), verifies the
external signature and all bundle bindings without a private key, normalizes a mathematically valid
high-S signature, and publishes the unchanged selection-v2 envelope with its required low-S P1363
signature. Finalization freshly replays the complete catalog matrix, release authorities, approval
evidence, profiles, source lock, snapshots, attestations, and optional live C# verifier before
no-clobber publication. Existing `validate-base-model-selection`, manifest-v3, training, promotion,
readiness, and activation consumers continue to accept only that unchanged finalized selection-v2
wire; they do not consume either handoff schema.

One external signature is sufficient because the existing selection-envelope preimage already
authenticates the exact catalog-complete matrix, selected snapshot, release, approval, validity, and
external trust tuple. No material bundle-only field grants authority, so a second bundle-authorization
signature would add no authority coverage. The unsigned bundle alone grants none of the all-false
issuance, review, release, training, checkpoint, evaluation, promotion, deployment, serving,
installation, verifier-execution, or strategy-execution authorities. Once paired with its valid
signature, however, the two files are selection-finalization-equivalent sensitive material. They can
be replayed to publish the same envelope at another unused path while the exact live inputs and
validity window still pass; no-clobber installation is not a one-use-token guarantee.

This provider-neutral seam does not provision or attest KMS/HSM custody, IAM, signer quorum, audit
logging, reviewer identity or honesty, key rotation or revocation, clock honesty, protected storage,
or legal/model-quality review. Every input and output path remains caller-selected; same-user or
privileged validate/open/link/unlink swaps, copying, and custody failures remain host-level limits.
Operators must protect both handoff files and independently enforce those controls. The direct
`create-base-model-selection` PEM route remains a local convenience. No real bundle, external
signature, selection, model, training result, promotion, or deployment evidence is supplied here.

The detached command sequence is:

```powershell
.venv\Scripts\vibe-quant-model prepare-base-model-selection-signing-bundle --help
# Sign the decoded signaturePreimage as a raw message, or signatureInput as a prehashed digest.
.venv\Scripts\vibe-quant-model finalize-base-model-selection --help
.venv\Scripts\vibe-quant-model validate-base-model-selection --help
```

There is deliberately no local detached-signing subcommand: the middle operation belongs to the
external provider adapter, which emits the closed signature document without exposing its private
key to this tool.

Preparation requires the approval identity and validity fields used by direct creation. Finalization
requires `--signing-bundle`, `--signature`, and `--output`; both commands require the exact same live
`--bakeoff-sources`, calibration/sealed inputs, shared baseline, release, catalog, source lock,
approval evidence, public selection trust, upstream trust, and candidate/baseline attestation trust.
Use each command's help output for the exhaustive all-or-none trust-option groups.

This is process and supply-chain evidence, not GPU-tensor, driver, hardware, or TEE attestation.
The OCI digest remains a signed launcher assertion because vLLM exposes no loaded-weight digest
endpoint. Production therefore still requires a genuinely pinned image/runtime, separate wrapper
and child identities, protected launcher signing custody, a deployed and independently governed
KMS/HSM broker behind the v2 loopback seam, network-namespace egress denial, supervision, and external
TLS or mTLS. The repository does not provision that broker, provider IAM/quorum/audit, key lifecycle,
or proof that the pinned TLS key is held by a particular process or hardware module. No real broker,
credential, base run, or promotion evidence has been
created.

## Authenticated production promotion

Install `.[auth]` in isolated review/release/evaluation environments and `.[promote]` in the
promotion environment. Both extras supply `cryptography`; the production trainer receives the exact
version through its sealed wheel lock. `create-model-promotion --help` lists the local PEM convenience
path, `prepare-model-promotion-signing-bundle --help` and `finalize-model-promotion --help` list the
detached-custody path, and `validate-model-promotion --help` lists the corresponding live validation
inputs.

Creation accepts only an active `provider-training-evaluation` release. It independently
reaggregates calibration/sealed candidate and baseline evidence from the supplied source files,
requires every evidence gate to pass, and exactly binds the release, candidate catalog, immutable
model revision, training manifest, sealed artifact/tree, serving profile, execution model ID,
container image, trainer-provenance envelope, approval-evidence bytes, deployment identity, and
hosted-deployment policy. The trainer signer must differ from teacher-lineage review, corpus review,
evaluation authoring, corpus admission, base selection, C# replay audit, and promotion signers. Promotion enforces
artifact recording <=
trainer issue <= trainer activation <= approval <= promotion issue, and cannot outlive trainer
provenance. The
training manifest must be v3: promotion authenticates its signed base selection, verifies both
historical timestamps fall inside the selection window, retains one validated manifest byte snapshot
through all downstream bindings, revalidates the exact external snapshot, and requires manifest
creation <= artifact recording <= approval <= issue before it can publish. A self-consistent edited
evidence report is insufficient. The hosted policy strictly pins provider,
protocol, canonical decimal pricing, execution/cost/resource limits, coordinator versions and
prompt catalog, plus the exact expert-context corpus, pack, and query policy.

Hosted-deployment policy v1 is preserved byte-for-byte and authorizes Research only in Platform.
Policy v2 retains that Research tuple and requires one closed `strategyAuthoringCapability` binding
`StrategyAuthoring`, the promoted execution-model ID, and the exact inert policy, workflow, and
prompt-catalog SHA-256. The outer promotion/envelope remains v1, while its promotion ID, signature,
readiness proof, and activation already bind the changed hosted-policy hash. A v2 capability grants
hosted source authoring only: it is not compilation, installation, execution, broker, live-order, or
release authority. Older consumers reject v2 fail-closed and must be deployed before v2 promotions
are issued.

When a sealed release contains the headless C# profile, production aggregation requires a separate
signed `csharp-verifier-replay-audit/v1`. Audit creation freshly executes the complete candidate and
baseline suites under one stable verifier configuration, then signs the exact release, sealed task
file/set, ordered C# task/verifier bindings, both run identities, both response/result files and
sets, and each covered C# response/result row. Its external key, SPKI, audience, key ID, role, and
exact envelope hash are independently pinned. Serving-time aggregation authenticates those bindings
without Docker while still freshly executing every declarative task in a mixed suite. Live C#
execution and audit substitution are mutually exclusive; missing, partial, expired, swapped, or
unused audits fail closed. Raw-base selection continues to require live full-suite replay and has no
audit input.

Production replay-audit custody can keep its private key outside this process. Run
`prepare-csharp-verifier-replay-audit-signing-bundle` with the same decision, evidence, live
verifier authority, and external trust inputs used by direct creation. Preparation accepts no
private key or password, freshly executes both complete suites, and emits a closed,
content-addressed, all-false bundle containing the exact existing audit-v1 payload, unsigned
envelope, trust tuple, raw ES256 signature preimage, and its SHA-256 digest. An external signer may
sign either the decoded raw preimage or decoded prehashed digest and return canonical DER or fixed
P1363. `finalize-csharp-verifier-replay-audit` accepts no private key, normalizes valid high-S input
to the existing low-S P1363 wire, freshly repeats every live release/evidence/authority replay and
validity check, and publishes the unchanged audit-v1 envelope. The unsigned bundle grants no
authority, while a valid bundle/signature pair is replayable audit-finalization material until
expiry and must be protected accordingly.

Production promotion custody has the same provider-neutral boundary. Run
`prepare-model-promotion-signing-bundle` with the exact decision, deployment, evidence, model,
approval, policy, upstream trust, and public promotion identity used by direct creation. It accepts
no private key or password, freshly derives every live binding, and emits a closed,
content-addressed, all-false bundle containing the exact existing promotion-v1 payload, unsigned
envelope, trust tuple, raw ES256 signature preimage, and its SHA-256 digest. There is deliberately no
local detached-signing command. An external KMS/HSM adapter must sign either the decoded raw
preimage with ECDSA/SHA-256 or the decoded digest with prehashed ECDSA/SHA-256, then return canonical
DER or fixed 64-byte P1363 in the closed signature document. `finalize-model-promotion` accepts no
private key, verifies the signature before expensive replay, normalizes valid high-S input to the
existing low-S P1363 wire, freshly repeats every live binding and validity check, and publishes the
unchanged promotion-v1 envelope. The unsigned bundle grants no authority; a matching valid
bundle/signature pair is replayable exact-promotion finalization material until expiry and therefore
requires protected custody. This seam does not provision KMS/HSM IAM, quorum, audit, signer
identity, rotation, revocation, honest clocks, immutable evidence custody, or privileged/same-user
path-swap protection, and it creates no real approval or promotion.

The output is a strict v1 envelope carrying canonical JSON payload bytes as unpadded base64url. It
uses P-256 ECDSA/SHA-256 (`ES256`) with an exact 64-byte IEEE-P1363 `r || s` signature in canonical
low-S form. Every signed field is unsigned 4-byte big-endian length-prefixed, and the exact payload bytes are
authenticated before they are parsed. The public key is never embedded: validation requires an
externally pinned, BOM-less, canonical single-block P-256 SPKI PEM no larger than 64,000 bytes, plus
exact audience, key ID, signer role, deployment, and environment configuration; this matches the
Platform consumer contract. Private-key passwords may be supplied only through the named environment variable;
neither keys nor passwords are emitted. Approval, issue, activation, and expiry use exact UTC-second
timestamps, must be ordered, must be active at signing/validation, and may span at most 366 days.
The signed promotion expiry must also be no later than the earliest authenticated review-receipt,
teacher-lineage admission, evaluation-authoring approval, and any required C# replay-audit expiry.
That makes the promotion expiry consumed by Platform a complete authority
ceiling rather than leaving a shorter receipt lifetime visible only inside the Python wrapper.
The signed envelope is fully replay-validated in a same-directory staging file and installed with an
atomic no-clobber link. The destination remains deliberately consumer-invalid with two owned links
until all destination replay and identity checks pass; unlinking the staging link is the commit
point. A commit-unlink failure removes the destination when possible and reports any preserved
staging/destination paths for operator inspection, so merely creating the destination link is never
reported as successful publication.

Promotion-bound model readiness uses `daxalgo.vibe-quant.model-readiness/v2`. Its HMAC proof binds
the serving profile, artifact and tree, execution model, exact promotion envelope and payload,
deployment, provider, hosted-policy identity, and signed promotion expiry. The v1 readiness helper
is restricted to local evaluation and is not a production-promotion proof.
`create-model-readiness-v2` first repeats the full signature, live-source, release, model, approval,
policy, selected-base trust, and exact-snapshot validation. It accepts only the HMAC-key environment-variable name; the environment value
must be canonical unpadded base64url decoding to at least 32 bytes.

`serve-promoted-model <config>` is the production-foundation vLLM owner and authenticated gateway.
Config v1 through v6 remain parseable only for migration diagnostics; production activation rejects
them before process creation. Strict config v7 retains response-attestation trust, requires the exact
external base-snapshot directory plus externally pinned selection trust, and requires independent
evaluation-authoring approval and trainer-provenance trust. It also carries explicit nullable
teacher-lineage trust: teacher-backed releases require it, while human-only releases reject it. It
pins the expected promotion-envelope and serving-profile
hashes, executable bytes, trusted promotion identities, live source paths, and a distinct non-root
child UID/GID. The
current OCI image digest, outer Bearer token, and readiness HMAC key are read from named environment
variables; their values are never command arguments, child environment values, responses, or logs.
Config v7 permits a null replay audit only for an all-declarative suite. C# release rows require the
exact replay-audit path, envelope hash, and independent public trust. The activation snapshot retains
the authenticated teacher-lineage, authoring-approval, and trainer-provenance hashes/expiry and, when
present, audit payload/envelope hashes; every
periodic full revalidation reopens the same pinned authorities.
The wrapper requires POSIX read-only mount custody for both the selected base snapshot and promoted
adapter, captures both directory identities, opens and hashes the single-link executable inode, and
launches that opened inode with `shell=False` under the configured child identity. The exact selected
snapshot is used for both model and tokenizer; no model-ID, revision, or cache resolution occurs.
Only reviewed vLLM 0.10.0 and 0.26.0 argument adapters are accepted. Startup proves that the child
process has the configured UID/GID, empty supplementary groups, zero inherited/permitted/effective/
ambient capabilities, and inherited `no_new_privs`; the executable must be wrapper-owned, free of
set-ID/file capabilities and group/other writes, and held on a read-only mount. Startup then proves
that the child process group owns the configured loopback listener, requires `/health` and an exact live `/version`,
and validates the base and adapter model-card IDs, roots, parent relationship, and signed maximum
length from `/v1/models`; vLLM's adapter card may inherit that length by returning null.

Full promotion, artifact, retained-manifest, selection, and snapshot validation runs before launch,
again after load, and at the bounded integrity interval. Chat and readiness requests use bounded
custody, upstream-authority expiry, process-privilege, and listener-ownership checks; the first
request after a stale interval performs one serialized full revalidation. Readiness can therefore
never outlive the signed promotion or the earliest authenticated receipt, teacher-lineage admission,
authoring-approval, and applicable replay-audit expiry.
Mutation,
expiry, child or descendant-process drift, failed health, listener substitution, or model identity
drift permanently removes readiness and terminates the owned process group.

The deterministic launch also binds the selected snapshot tokenizer, one LoRA only, the validated manifest's
supported maximum LoRA rank, `generation-config=vllm`, and disabled FastAPI documentation, request
logging, Uvicorn access logging, plugin discovery, and Hugging Face telemetry. A fresh internal
`VLLM_API_KEY` is generated per wrapper process
and supplied only to the child and direct loopback `/v1/*` calls. This prevents another local caller
from bypassing the outer model gate; it is separate from both externally injected secrets.

The outer service exposes only authenticated `POST /v1/daxalgo/readiness/attest` and
`POST /v1/chat/completions`. Readiness challenges are strict v2 audience/32-byte nonce objects. Chat
requests must select the promoted execution model ID and must be non-streaming; responses are fully
buffered, bounded, strict JSON whose model ID is checked again. The accepted request surface is
exactly `model`, `messages`, `max_tokens`, `temperature`, and optional `stream: false`, with bounded
roles, content, temperature, and the signed hosted-policy output-token limit. Both outer and child listeners are
restricted to `127.0.0.1`, and child calls use direct HTTP without environment proxies. Put an
independently configured TLS-terminating reverse proxy in front if remote access is required; never
bind this service directly to a remote interface.

The default real child-process owner is POSIX-container only. Native Windows vLLM launch fails
closed because `CREATE_NEW_PROCESS_GROUP` cannot guarantee complete descendant cleanup; use the
digest-pinned Linux/OCI runtime. Injected process/transport implementations remain available for
network-free, GPU-free unit tests on Windows.

Shutdown is deliberately fail-closed and does not drain active inference leases: readiness is removed
and the child is terminated. Deployment orchestration must stop Platform traffic/leases first, then
signal the wrapper. SIGINT and SIGTERM are handled so the isolated child process is not orphaned.

## Draft corpus verification and review

The Pro coordinator CLI provides a separate pre-release acceptance gate for canonical expert-corpus
drafts. `expert-dataset verify-draft` runs an exact, bounded manifest of allowlisted text checks and,
for C# `CodeGeneration` or `CodeRepair`, can run the fixed `daxq-sdk-abi3-source/v1` verifier. That
profile compiles the exact assistant response as data, lowers only the allowlisted DAXQ numeric
subset, and executes verified bytecode against inline declarative numeric vectors in a bounded child
process; it never loads the submitted managed assembly. The v2 verification report explicitly marks
code rows without a supported executable profile as unsupported and failed. `expert-dataset apply-review` freshly repeats
the checks and executable verification before accepting a row-complete human decision manifest bound
to the exact dataset, verifier manifest, and report. It replaces code compile/test claims with fresh
structured evidence, never elevates example or source rights, always leaves `useForTraining=false`,
refuses failed-check approvals, and does not replace an existing report or dataset. `CodeReview`,
general C#, WPF/XAML, projects, packages, commands, and executable test code remain unsupported by
this draft-review workflow. The standalone verifier below is deliberately not wired into
`verify-draft` or `apply-review`.

Rights review is a separate, unsigned four-step handoff. `expert-dataset prepare-rights-review`
freshly replays the exact draft verification and human review, then emits a content-addressed package
containing the exact draft, reviewed corpus, verification manifest/report, review manifest, supplied
review evidence, complete ordered row/source inventories, and an intentionally incomplete
deny-downstream-rights worksheet. `expert-dataset prepare-rights-decision-template` freshly replays
the package and emits a versioned, unsigned, all-false-authority editable draft bound to its exact
package ID, raw package hash, and reviewed corpus. The reviewer fills every row/source decision and
immutable evidence reference; ordinary closed JSON formatting and property order are accepted, while
duplicate or unknown properties fail closed. `expert-dataset compile-rights-decision` replays the
package again, verifies every draft binding, embeds the supplied evidence bytes, derives the canonical
decision ID, and leaves every downstream-authority flag false. `expert-dataset apply-rights-review` repeats the replay,
requires UTC whole-second chronology after the packaged content review, rejects reserved evidence
anchors, and changes only row/source rights, `useForTraining`, and hash anchors for the exact package,
decision, and cited evidence.

```powershell
hyperion expert-dataset prepare-rights-review --input <draft.jsonl> `
  --reviewed-input <reviewed.jsonl> --verification-manifest <verification-manifest.json> `
  --verification-report <verification-report.json> --review-manifest <review-manifest.json> `
  [--evidence <id>=<file>] --output <review-package.json>
hyperion expert-dataset prepare-rights-decision-template `
  --package <review-package.json> --output <decision-template.json>
hyperion expert-dataset compile-rights-decision --package <review-package.json> `
  --template <completed-decision-template.json> --evidence <id>=<file> `
  --output <rights-decision.json>
hyperion expert-dataset apply-rights-review --package <review-package.json> `
  --decision <rights-decision.json> --output <rights-reviewed.jsonl>
```

Only approved, verified, `candidate-stable` development rows can receive downstream rights or request
training use. Provider upload requires training rights, row grants require matching source closure,
and `retrieval-only` rows remain non-training. The package, template, compiled decision, and resulting
rights declarations are not signatures, receipts, legal findings, or reviewer authentication. Their
hashes prove byte identity only. The resulting corpus remains zero training-eligible until exactly one
valid authenticated review receipt exists for every final row; receipt-gated SFT export and release
validation remain unchanged.

Neither local DAXQ approval nor an unsigned rights decision is by itself a release or training
authorization. The flattened corpus hashes
and task/domain labels can be chosen or copied by an author and therefore do not authenticate that
review or execution occurred. An independent reviewer must issue exactly one detached canonical
JSONL receipt per dataset row. Each current v2 envelope carries an ES256 P-256 low-S IEEE-P1363
signature; its payload binds the exact row, source-corpus bytes, conversation, freshly rederived
verification evidence, unsigned SFT metadata v2, derived evaluation/training/provider-upload
authorizations, review decision, and approval evidence. Metadata v2 repeats the exact source-corpus
and row-evidence SHA-256 identities, so a detached SFT row cannot silently lose those bindings.
Consumers verify against an externally supplied public key and pinned SPKI hash, audience, key ID,
and signer role; no key is embedded in a receipt set or release. These hashes identify exact bytes
and structures only: they do not prove correctness, evidence truth or availability, reviewer
identity or honesty, legal rights, or source availability.

For a corpus containing any `OpenWeightTeacher` row, receipt issuance and validation also require the
signed teacher-lineage admission, its separate externally pinned trust, the exact materialization
package, passive runtime binding, and lineage-reviewer evidence. Python reopens all four inputs and
the final corpus in one full verification path, requires distinct admission and receipt SPKIs, and
contains every receipt's issuance/not-before/expiry window within the admission window. A
human-authored-only corpus requires none of these inputs and rejects any extraneous lineage path or
trust. Python retains homogeneous receipt-v1 plus SFT-metadata-v1 validation only for archival
release-v3 bundles whose every row is `HumanAuthored`; current issuance, C# export, release v4, and
all identity-returning authorization paths require v2. Mixed versions and teacher-origin legacy
receipts are rejected.

Receipt validity is time-bounded (at most 366 days). A release remains immutable, so an expired
receipt set makes it ineligible for training, normal evaluation, promotion evidence, readiness, or
provider use; issue a newly reviewed receipt set and a new release rather than editing an old one.
The current private seed has only text checks and no real independent human decision/receipt, so it
still has no production, provider-upload, evaluation, or training authorization.

The receipt issuer keeps the private key outside the corpus and release. Its password, when used,
is supplied only through an environment-variable name:

```powershell
.venv\Scripts\vibe-quant-model create-review-receipts `
  --dataset <reviewed-expert-dataset.jsonl> --output <review-receipts.jsonl> `
  --private-key <independent-reviewer-private-key.pem> `
  --public-key <independent-reviewer-public-key.pem> `
  --private-key-password-env <OPTIONAL_PASSWORD_ENV> `
  --audience <review-audience> --key-id <review-key-id> `
  --signer-role <independent-reviewer-role> `
  --approval-id <stable-approval-id> --actor-id <stable-reviewer-id> `
  --actor-role <independent-reviewer-role> --approval-reference <human-review-reference> `
  --approval-evidence <immutable-human-review-evidence> `
  --approved-at-utc <utc-second> --issued-at-utc <utc-second> `
  --not-before-utc <utc-second> --expires-at-utc <utc-second>
.venv\Scripts\vibe-quant-model validate-review-receipts <review-receipts.jsonl> `
  --dataset <reviewed-expert-dataset.jsonl> --public-key <independent-reviewer-public-key.pem> `
  --expected-public-key-spki-sha256 <64-lowercase-hex> `
  --expected-audience <review-audience> --expected-key-id <review-key-id> `
  --expected-signer-role <independent-reviewer-role>
```

Production custody can keep the receipt-signing key outside this process. The detached path first
publishes one canonical, content-addressed, explicitly non-authorizing signing bundle. Each ordered
request contains the exact raw ES256 preimage and its one-time SHA-256 digest, so an external adapter
can use either a raw-message API or a pre-hashed KMS/HSM API without reconstructing the receipt
contract. The adapter also signs the bundle's domain-separated exact-byte authorization preimage;
this prevents bundle-only approval or teacher-lineage fields from being changed while reusing valid
row signatures. That preimage is the bundle-declared ASCII domain, one NUL byte, and the exact
canonical bundle file bytes, hashed exactly once with SHA-256 for digest-mode signing. It returns the closed
`expert-model-review-receipt-signature-set.v1.schema.json` document bound to the exact bundle bytes,
ordered receipt IDs, and signing-input hashes. `finalize-review-receipts` accepts canonical DER or
64-byte P1363 signatures, validates their P-256 values, normalizes a valid high-S result to the
receipt contract's low-S P1363 form, and verifies it with the externally pinned public key.

```powershell
.venv\Scripts\vibe-quant-model prepare-review-receipt-signing-bundle `
  --dataset <reviewed-expert-dataset.jsonl> --output <signing-bundle.json> `
  --public-key <versioned-review-public-key.pem> `
  --audience <review-audience> --key-id <review-key-id> `
  --signer-role <independent-reviewer-role> `
  --approval-id <stable-approval-id> --actor-id <stable-reviewer-id> `
  --actor-role <independent-reviewer-role> --approval-reference <human-review-reference> `
  --approval-evidence <immutable-human-review-evidence> `
  --approved-at-utc <utc-second> --issued-at-utc <utc-second> `
  --not-before-utc <utc-second> --expires-at-utc <utc-second>
.venv\Scripts\vibe-quant-model finalize-review-receipts `
  --dataset <reviewed-expert-dataset.jsonl> --signing-bundle <signing-bundle.json> `
  --signature-set <external-signatures.json> --output <review-receipts.jsonl> `
  --public-key <versioned-review-public-key.pem> `
  --expected-public-key-spki-sha256 <64-lowercase-hex> `
  --expected-audience <review-audience> --expected-key-id <review-key-id> `
  --expected-signer-role <independent-reviewer-role> `
  --approval-evidence <immutable-human-review-evidence>
```

Preparation and finalization both reopen the exact corpus and approval evidence and revalidate the
optional teacher-lineage package, external trust, row order/count, derived v2 payloads, and live
validity. Final publication is no-clobber and emits the same receipt-v2 JSONL consumed by C#, release
v4, training, evaluation, promotion, and activation. The unsigned bundle grants no authority; the
signature set authorizes only finalizing that exact receipt set and explicitly denies review-truth,
rights, release, training, evaluation, provider-upload, promotion, and deployment authority. Neither
handoff artifact is itself a receipt. This workflow does not provision a KMS/HSM, authenticate the
human reviewer, enforce provider IAM or quorum policy, attest the signing service, or manage key
rotation/revocation. The direct PEM command remains a local workflow convenience.

For teacher-backed receipt creation or validation, append
`--teacher-lineage-admission`, `--teacher-materialization`, `--teacher-runtime-binding`,
`--teacher-lineage-reviewer-evidence`, and the five
`--teacher-lineage-admission-public-key`,
`--teacher-lineage-admission-public-key-spki-sha256`,
`--teacher-lineage-admission-audience`, `--teacher-lineage-admission-key-id`, and
`--teacher-lineage-admission-signer-role` trust options. The C# `expert-dataset export-sft` surface similarly requires
`--teacher-lineage-admission`, `--teacher-lineage-public-key`,
`--teacher-lineage-public-key-spki-sha256`, `--teacher-lineage-audience`,
`--teacher-lineage-key-id`, and `--teacher-lineage-signer-role`. It verifies the
admission signature, signer separation, validity, exact reviewed dataset, and ordered stable teacher
subjects against the same already-read corpus bytes before receipt-gated export; it does not replay
the source materialization/runtime/evidence package.

The private seed inputs live under `../../tmp/vibe-quant-model/corpus/`; its verification report lives
under `../../tmp/vibe-quant-model/reports/`. Passing checklist assertions means only that the exact
answer contains the reviewed claims. It is not independent correctness review, legal or ML-training
rights approval, or a substitute for the evaluation verifiers below.

## Standalone headless SDK C# strategy verifier

`verify-csharp-strategy` is an implemented, separate research/evidence command for one strict UTF-8
C# source file. The file must define exactly one public headless `IBacktestStrategy`; it is compiled
against the actual frozen `TradingTerminal.Core` and `DaxAlgo.Sdk` assemblies and replayed over
bounded, host-declared tick traces. Each case is executed twice, with every replay in a fresh child
process of the fixed worker apphost. The only strategy effects retained as evidence are bounded order
traces and bounded runtime errors.

`create-csharp-verifier-authority` issues a canonical ES256/P-256 v2 lease after an independent signer
reviews the exact `repository@sha256` image plus config image ID, linux/amd64 platform, absolute
entrypoint, complete worker/runtime/Core/SDK/Roslyn compiler closure, protocol versions, full sandbox
policy, absolute Docker client path/content hash/size, explicit local daemon endpoint, and scrubbed
client-environment policy. `verify-csharp-strategy` accepts no unsigned image, entrypoint, client, or
daemon fallback: it requires that lease plus an externally pinned public-key SPKI, audience, key ID,
and signer role before the first Docker call. It authenticates and privately snapshots the client,
invokes only that snapshot against the signed endpoint with an empty private Docker configuration,
home, and temporary directory, inspects the exact local repository digest/image/platform, compares
the worker's complete toolchain with the signed identity, and rechecks client identity and lease
expiry before publishing a result-v2 authority lineage.

Production custody can keep the authority private key outside this process. Run
`prepare-csharp-verifier-authority-signing-bundle` with the same toolchain, image, image ID,
entrypoint, Docker client, daemon endpoint, approval fields, and public trust used by direct creation.
Preparation accepts no private key or password and emits a closed, non-authorizing bundle containing
the exact existing authority-v2 envelope preimage and its one SHA-256 digest. An external service may
sign either the decoded raw preimage or the decoded prehashed digest. Then run
`finalize-csharp-verifier-authority` with the unchanged live inputs, bundle, and external signature.
Finalization accepts canonical DER or fixed 64-byte P1363, normalizes a valid high-S signature to the
required low-S form, freshly revalidates every live binding and validity boundary, and no-clobber
publishes the same authority-v2 envelope accepted by existing verifier and replay-audit consumers.
The unsigned bundle grants no authority, but a valid bundle/signature pair is replayable
finalization-equivalent sensitive material.

The authority issuer supplies the image identity and entrypoint. The signature authenticates that
reviewed selection; it does not independently discover image provenance or prove that the chosen
entrypoint is correct.

The sandbox enforces a read-only root, no network, no added capabilities, no-new-privileges, a
non-root user, bounded CPU/memory/PIDs, and bounded `tmpfs` work areas. Exact request and source
snapshots enter through the `DAXVSTG1` length-bounded binary stdin frame; the worker returns only
bounded exact result JSON on stdout. Expectations and expected trace hashes stay host-only and are
never staged into the container.

The authority is a reusable configuration lease for at most seven days, not a one-shot request
nonce. Its protected operator trust tuple and signing process remain in the trusted computing base,
and its timestamps are not externally time-attested. The controller supplies only `DOCKER_HOST`,
`DOCKER_CONFIG`, `DOCKER_CLI_HINTS`, `HOME`, and private temporary-directory variables; ambient
`PATH`, `DOCKER_CONTEXT`, user configuration, and other Docker overrides are absent. This authenticates
the selected client bytes and endpoint name, not the daemon/socket owner, container runtime, kernel,
or resolved builtin seccomp policy. A compromised daemon or privileged host can still fabricate
runtime claims, and a same-user or privileged actor retains narrow validate/open path-swap races
against the client snapshot and strict output publication. Production therefore still requires
independent runtime/daemon attestation and stronger handle-relative or immutable host custody.
The detached handoff does not change those limits: it authenticates the reviewer's caller-selected
image and entrypoint but does not discover their correctness; attest the Docker daemon/socket owner,
kernel, container runtime, or daemon-resolved builtin seccomp profile; provide an honest clock; or
provision KMS/HSM IAM, quorum, audit, rotation, or revocation. It also cannot close same-user or
privileged path-swap races. No real verifier authority or verification evidence is supplied here.

One immutable result reports exactly six checks: `source-binding`, `compile`, `analyzers`,
`deterministic-execution`, `reference-cases`, and `sandbox-policy`. The worker returns both bounded
replay traces and errors; the host derives both semantic identities and rejects a worker
determinism claim that disagrees with those returned replays. Source and IL policy analysis,
fresh-process replay, result/hash validation, hidden host expectation comparison, and guaranteed
container cleanup all fail closed.

`executable-verifier/v2` now makes that exact profile available to `run-verifiers`, release-bound
promotion-evidence aggregation, and the signed raw-base selection-v2 bake-off. The release asset
contains only the contract, ordered tick cases, and host-only expected trace hashes. The runner treats
the exact response text as UTF-8 C# source without fence stripping or normalization, derives the
source-bound request and expectations snapshots, and requires the authority path plus all five
external trust fields at execution time. Authority paths and keys never enter the release. Canonical
verifier evidence binds stable request/source/expectations, authority configuration, toolchain,
image, platform, and sandbox identities while excluding renewable lease-envelope metadata; a changed
runtime identity therefore changes the result, while an equivalent fresh lease does not.

Direct verification remains an offline evaluation/selection capability. Production promotion,
readiness, and engine-wrapper v7 consume only the separately signed exact replay audit; they never
receive a Docker client, socket, image, execution context, or live seven-day verifier lease. Mixed
suites continue to replay declarative tasks locally. The audit signer must differ from the verifier
authority and promotion signers, its expiry caps the promotion, and its explicit false authority
flags grant no review, release, training, base-selection, promotion-decision, deployment, hosted,
installation, or strategy-execution authority. Its trust tuple and signer-supplied replay, approval,
and issuance clocks remain in the trusted computing base: strict ordering and activation checks reject
future-dated use but cannot prevent deliberate backdating by that signer. The result is still not consumed by `apply-review`
or RLVR and grants no release, training, checkpoint, deployment, strategy-installation, or execution
authority. WPF/XAML,
multi-file or project builds, NuGet/package restore, full SDK plugins, arbitrary/general-purpose code
execution, commands, and installation remain unsupported.
The detached custody seam does not provision KMS/HSM IAM, quorum, audit, key rotation/revocation,
or real-world signer identity; attest honest clocks, Docker daemon/socket ownership, runtime,
kernel, or resolved builtin seccomp bytes; or close same-user/privileged path-swap races. It creates
no real replay audit or model evidence.

## Teacher candidate capture

The Pro coordinator CLI provides the one-way authoring step before capture. `expert-dataset compile-teacher-manifest` accepts one exact `daxalgo.expert-model-dataset-draft/v1` manifest, a closed `daxalgo.vibe-quant.teacher-capture-plan/v1`, and the pinned candidate catalog. The plan binds the raw draft and catalog SHA-256 values and explicitly declares the teacher/runtime/template identities, sampling policy, tokenizer limit, aggregate budgets, and ordered per-task output limits. The compiler derives task, source, cutoff, and storage/evaluation-only authority fields from the draft, removes exactly the terminal reference answer, rejects that answer in every emitted string value, and records the raw draft/catalog hashes plus every source-byte hash in manifest v2. It rechecks every input and atomically creates a BOM-less output without replacing an existing file. Python validation requires the same raw catalog bytes and exact four approved model revisions and reopens every source at its declared hash before capture. The manifest is unsigned intent: without the original draft and plan, Python cannot independently prove that a supplied v2 file came from this compiler or rederive its draft lineage. The compiler cannot infer or attest a runtime, elevate rights, capture a response, or create review, training, release, checkpoint, or promotion evidence.

`derive-teacher-runtime-plan` closes the operator bootstrap without contacting a model server. It validates a strict local runtime descriptor plus the exact catalog, hashes the descriptor bytes as `runtimeSha256`, hashes the bounded BOM-less UTF-8 chat-template bytes from the declared model root, derives the content-addressed execution model ID, and prints the exact capture-plan fragment and vLLM served-model name with `observationStatus: not-observed`. The descriptor permits only the reviewed vLLM versions, one canonical `http://127.0.0.1:<port>/v1` root, an exact maximum length, and a relative template path. It does not prove that any server exists.

After vLLM is launched with that served-model name, `create-teacher-runtime-binding` reopens the descriptor, template, and catalog, then directly queries `/version` and `/v1/models` without proxies or redirects. It requires HTTP JSON, the exact reviewed version, exactly one model card, the derived execution ID, the bound root string, and the bound maximum length before publishing a canonical no-clobber `unattested-observation` binding. The descriptor must be contained by the binding output directory; the template remains under the separately declared model root. `validate-teacher-runtime-binding` always rehashes those inputs and repeats both live probes.

`validate-teacher-generation` and `capture-teacher-candidates` implement the first, deliberately
narrow teacher-data stage. A strict development-only manifest selects the catalog's pinned teacher,
binds the chat-template and runtime hashes, declares multiple unique seeds and aggregate request/token
budgets, records storage/evaluation-only authority, and snapshots contained BOM-less UTF-8 source
files. Manifest v2 also declares the reviewed vLLM tokenize-chat protocol and exact expected maximum
model length. Capture constructs the exact source-grounded model messages, hashes the prompt, task,
teacher, manifest, output, candidate, and batch lineage, and publishes one canonical JSONL queue only
after every requested sample succeeds and the complete queue revalidates. Manifest v1 remains
readable for historical queue validation but cannot authorize a new live capture.
Queue validation always reopens the supplied manifest, catalog, and source snapshots and requires
their exact live identities; self-consistent rehashed JSONL alone is insufficient.

Capture now requires the exact runtime-binding file, exact catalog, manifest, and canonical base URL. It reopens every local input and probes the endpoint before tokenization, records the binding-file SHA-256 on every candidate, then reopens the full manifest/catalog/source preparation and reprobes again after all completions and before atomic publication. Candidate rows without that field remain validation-only compatible only with historical manifest v1; every manifest-v2 queue requires one consistent binding-file hash. The endpoint must be the literal loopback address `127.0.0.1`; redirects and proxies are disabled by the transport. Before any completion, capture submits every exact source-grounded chat to
the same vLLM root's `/tokenize` route with the generation prompt enabled. The response must contain a
bounded token-ID list matching its count and the manifest's exact `maxModelLen`; every prompt plus its
requested completion must fit. Exact prompt usage and the worst-case completion reservation must fit
the aggregate budgets before the first completion is sent, and every completion's reported prompt
usage must equal the preflight count. Configure the server to return the exact content-addressed
execution model ID derived by manifest validation. Supply only the API-key environment-variable name.
Every response must end normally with positive token usage, and duplicate samples, hidden-reasoning
tags, token-accounting drift, budget overruns, malformed responses, or an existing output path abort
without publishing a partial queue.

```powershell
.venv\Scripts\vibe-quant-model derive-teacher-runtime-plan `
  --runtime-descriptor <teacher-runtime.json> --catalog candidate-catalog.v1.json
.venv\Scripts\vibe-quant-model create-teacher-runtime-binding `
  --runtime-descriptor <teacher-runtime.json> --catalog candidate-catalog.v1.json `
  --output <teacher-runtime-binding.json> --api-key-env <LOCAL_TEACHER_API_KEY_ENV>
.venv\Scripts\vibe-quant-model validate-teacher-runtime-binding `
  <teacher-runtime-binding.json> --api-key-env <LOCAL_TEACHER_API_KEY_ENV>
.venv\Scripts\vibe-quant-model validate-teacher-generation `
  --manifest <teacher-generation.json> --catalog candidate-catalog.v1.json
.venv\Scripts\vibe-quant-model capture-teacher-candidates `
  --manifest <teacher-generation.json> --catalog candidate-catalog.v1.json `
  --runtime-binding <teacher-runtime-binding.json> `
  --output <teacher-candidates.jsonl> --base-url http://127.0.0.1:8000/v1 `
  --api-key-env <LOCAL_TEACHER_API_KEY_ENV>
.venv\Scripts\vibe-quant-model validate-teacher-candidates <teacher-candidates.jsonl> `
  --manifest <teacher-generation.json> --catalog candidate-catalog.v1.json
.venv\Scripts\vibe-quant-model create-teacher-overlap-deny-set `
  --calibration-tasks <calibration.jsonl> --sealed-tasks <sealed.jsonl> `
  --deny-set-id <id> --custodian <independent-custodian> `
  --created-at-utc <UTC-second> --output <overlap-deny-set.json>
.venv\Scripts\vibe-quant-model validate-teacher-selection `
  --selection <teacher-selection.json>
.venv\Scripts\vibe-quant-model materialize-teacher-candidates `
  --selection <teacher-selection.json> --output <immutable-draft-package-directory>
.venv\Scripts\vibe-quant-model validate-teacher-materialization `
  <immutable-draft-package-directory>
.venv\Scripts\vibe-quant-model create-teacher-lineage-admission `
  --output <teacher-lineage-admission.json> `
  --materialization <immutable-draft-package-directory> `
  --runtime-binding <teacher-runtime-binding.json> `
  --reviewed-dataset <reviewed-expert-dataset.jsonl> `
  --reviewer-evidence <immutable-lineage-review-evidence> `
  --private-key <lineage-reviewer-private-key.pem> `
  --teacher-lineage-admission-public-key <lineage-reviewer-public-key.pem> `
  --teacher-lineage-admission-public-key-spki-sha256 <64-lowercase-hex> `
  --teacher-lineage-admission-audience <lineage-audience> `
  --teacher-lineage-admission-key-id <lineage-key-id> `
  --teacher-lineage-admission-signer-role <independent-lineage-reviewer-role> `
  --reviewer-id <stable-lineage-reviewer-id> `
  --reviewed-at-utc <UTC> --issued-at-utc <UTC> `
  --not-before-utc <UTC> --expires-at-utc <UTC>
.venv\Scripts\vibe-quant-model prepare-teacher-lineage-admission-signing-bundle `
  --output <teacher-lineage-signing-bundle.json> `
  --materialization <immutable-draft-package-directory> `
  --runtime-binding <teacher-runtime-binding.json> `
  --reviewed-dataset <reviewed-expert-dataset.jsonl> `
  --reviewer-evidence <immutable-lineage-review-evidence> `
  --teacher-lineage-admission-public-key <lineage-reviewer-public-key.pem> `
  --teacher-lineage-admission-public-key-spki-sha256 <64-lowercase-hex> `
  --teacher-lineage-admission-audience <lineage-audience> `
  --teacher-lineage-admission-key-id <lineage-key-id> `
  --teacher-lineage-admission-signer-role <independent-lineage-reviewer-role> `
  --reviewer-id <stable-lineage-reviewer-id> `
  --reviewed-at-utc <UTC> --issued-at-utc <UTC> `
  --not-before-utc <UTC> --expires-at-utc <UTC>
.venv\Scripts\vibe-quant-model finalize-teacher-lineage-admission `
  --signing-bundle <teacher-lineage-signing-bundle.json> `
  --signature <external-lineage-signature.json> `
  --output <teacher-lineage-admission.json> `
  --materialization <immutable-draft-package-directory> `
  --runtime-binding <teacher-runtime-binding.json> `
  --reviewed-dataset <reviewed-expert-dataset.jsonl> `
  --reviewer-evidence <immutable-lineage-review-evidence> `
  --teacher-lineage-admission-public-key <lineage-reviewer-public-key.pem> `
  --teacher-lineage-admission-public-key-spki-sha256 <64-lowercase-hex> `
  --teacher-lineage-admission-audience <lineage-audience> `
  --teacher-lineage-admission-key-id <lineage-key-id> `
  --teacher-lineage-admission-signer-role <independent-lineage-reviewer-role>
.venv\Scripts\vibe-quant-model validate-teacher-lineage-admission `
  <teacher-lineage-admission.json> `
  --materialization <immutable-draft-package-directory> `
  --runtime-binding <teacher-runtime-binding.json> `
  --reviewed-dataset <reviewed-expert-dataset.jsonl> `
  --reviewer-evidence <immutable-lineage-review-evidence> `
  --teacher-lineage-admission-public-key <lineage-reviewer-public-key.pem> `
  --teacher-lineage-admission-public-key-spki-sha256 <64-lowercase-hex> `
  --teacher-lineage-admission-audience <lineage-audience> `
  --teacher-lineage-admission-key-id <lineage-key-id> `
  --teacher-lineage-admission-signer-role <independent-lineage-reviewer-role>
```

The selection manifest binds the exact candidate queue, generation manifest, candidate catalog, and
a separately held overlap deny-set by contained path and SHA-256. The custodian-side builder validates
the exact calibration and sealed task files, binds both their byte and semantic task-set identities,
and emits no prompt text, task IDs, or plaintext contamination groups. Selection compares every
candidate conversation prefix ending in a user turn against the shared exact authored-message hashes,
compares every user turn through a conservative NFKC/case/whitespace-normalized hash, and checks the
hashed contamination-group identity. Exact calibration/sealed task files plus every bound context-pack
and verifier hash are also denied as teacher sources. Its selector must differ from the teacher
producer and planned reviewer; the deny-set custodian must also be separate. Selection is limited to
one candidate per source task, retains queue order, and no selector-controlled field can change
lineage, rights, split, verification, or training eligibility.

Materialization reopens and validates all four bound inputs, appends only the selected answer to the
authored conversation, preserves exact open-weight teacher lineage and embedded sources, and emits an
all-or-nothing package containing `expert-dataset.draft.jsonl`, a content-addressed admission record,
and exact snapshots of the selection, queue, manifests, deny-set, and source files. The package
rederives and revalidates without the original working files, rejects extra or changed content, and is
published with atomic no-clobber semantics on Windows and Linux. Every row is
`development`/`draft`/unverified, has storage/evaluation-only row and source
rights, and remains ineligible for training. The admission hash preserved in verification evidence
binds candidate, task, prompt, output, source, runtime/template, selection, and deny-set identities.
Run the C# `expert-dataset validate` command over the generated JSONL before the existing
`verify-draft` and `apply-review` workflow.

Neither the queue nor the materialization package's internal admission record is a signed review, SFT
export, release, or training authorization. That record explicitly remains `unsigned`. The separate
teacher-materialization lineage admission v1 reopens exactly one package, one passive runtime binding,
one reviewer-evidence file, and the final reviewed corpus; signs the ordered stable teacher subjects;
and authorizes only subsequent receipt issuance. Independent correctness and rights review, fresh
deterministic/executable verification, and one valid detached review receipt per final corpus row are
still required before authenticated release consumption. No real lineage authority artifact,
admission, receipt, or release has been issued.

Production lineage signing can use the provider-neutral prepare/finalize handoff instead of loading a
private key in this process. The bundle's `signaturePreimage` is the exact message for services that
apply SHA-256 themselves; `signatureInput` is its already computed SHA-256 digest for services that
accept a prehashed digest. Sign exactly one of those provider modes, never hash `signatureInput`
again. The external signature document accepts canonical ASN.1 DER or fixed 64-byte P1363 and uses
`teacher_materialization_lineage_admission_signature_id` as the normative content-ID derivation;
finalization normalizes a valid high-S result and publishes the unchanged low-S admission-v1
envelope. The unsigned bundle alone grants no authority, but a valid bundle/signature pair is
admission-equivalent sensitive material because no additional authorization is needed to finalize
it. The handoff does not provision KMS/HSM custody, IAM/quorum/audit policy, reviewer identity,
rotation/revocation, honest clocks, or immutable host custody. All paths remain caller-selected and
same-user or privileged validate/open/unlink swaps remain a host-level limit.

The binding replaces free-form capture-time runtime/template/endpoint values with exact local bytes and repeatable live observations, but it is deliberately unsigned and machine-labelled `unattested-observation`. The model-card root is only a server assertion: neither the binding, its probes, nor the later reviewer-signed lineage admission independently proves model-weight bytes, catalog revision, loaded template, caller-selected image or entrypoint, process ownership, executable identity, dependencies, daemon, kernel, GPU, hardware, clock honesty, egress isolation, correctness, rights, or reviewer identity. The signature authenticates the reviewer's decision over the selected bytes; it does not transform those bytes into independent runtime attestation. A substituted or dishonest endpoint can lie consistently to `/version`, `/v1/models`, `/tokenize`, and completion calls. Admission inputs remain caller-selected paths, and a same-user or privileged actor retains narrow validate/open path-swap opportunities. Receipt and SFT gates reject a non-teacher row that retains a teacher-admission anchor, and full admission rejects an exact materialized conversation copied under a relabelled ID. If an actor removes the anchor and relabels the row before authenticated pre-review provenance exists, the final corpus alone cannot reveal that origin change; production must authenticate the materialization-to-review handoff. Completion and total budgets are applied to the server's usage assertions, while
the independent response-byte limit only bounds the resulting exposure. Token IDs are structurally
checked live but are not persisted as attestation evidence. A loopback address also cannot prove that
an operator-controlled process will not proxy content elsewhere, so run the reviewed open-weight
server in an egress-isolated environment and independently pin its image, weights, tokenizer, launch
arguments, and loaded context limit. Known reasoning tags and nonempty response metadata are rejected
as defense in depth, but text scanning cannot prove answer-only behavior.
Strict cross-seed output diversity is intentional: identical answers invalidate the atomic batch
rather than silently creating duplicate review work. The materializer now requires a separately held
overlap deny-set, but its custodian, selector identity, and selection basis remain declarative until
the later authenticated review boundary. The scope hash binds the exact declared calibration and
sealed artifacts and the task count makes missing exact-message fingerprints fail closed. It cannot
prove custodian authorship, independent completeness, or that a withheld suite stayed secret. Prompt
fingerprints are identifiers, not anonymization, and low-entropy prompts remain guessable.

## Rights-reviewed data releases

Before training or private evaluation, `create-release` freezes a release-v4 rights-bearing
`expert-model-dataset/v1` corpus, its exact detached review-receipt set and trust identity, exact
calibration/sealed task, context-pack, rubric, verifier, and approval-evidence bytes. A teacher-backed
v4 release additionally snapshots the exact signed lineage admission and revalidates its distinct
trust, validity, reviewed-corpus identity, and ordered stable subjects against the same corpus
snapshot. It does not bundle the source materialization package, runtime binding, or lineage-reviewer
evidence. Human-authored-only v4 releases require a null lineage binding and reject extraneous
lineage trust; legacy v3 remains archival-validation-compatible only when every corpus row is
`HumanAuthored`. It cannot return a downstream authorization identity. Release v4 requires a
homogeneous receipt-v2 set and, when present, SFT metadata v2; v3 requires the matching homogeneous
v1 contracts. Before that signed boundary, `compile-evaluation-authoring-handoff` consumes one exact
approved, verified, declaratively `HumanAuthored` corpus plus a closed manifest that names only
source IDs and contained assets. It derives both task files from the corpus, strips each final
assistant reference answer, rejects development/evaluation or calibration/sealed contamination,
snapshots content-addressed context/rubric/verifier bytes, and publishes one no-clobber package. Its
handoff is unsigned and explicitly attests neither independent authorship nor sealed custody; every
authority flag is false. The emitted task bindings use v2 canonical contained relative asset paths,
resolved against the bindings file, so the package remains relocatable. The release also embeds one
separately signed evaluation-authoring approval whose exact externally pinned
envelope covers the corpus lineage, task bytes and semantic identities, expected values, context
packs, rubrics, and verifiers without granting release, training, promotion, deployment, or execution authority. A strict
task-bindings JSON document maps every task to one or more corpus example IDs plus inert
context-pack/rubric/verifier files. Each binding has exactly `taskId`, `sourceExampleIds`, a
`contextPack` object containing `version` and `path`, and `rubric`/`verifier` objects containing `id`
and `path`. New portable packages use `daxalgo.vibe-quant.release-task-bindings/v2`, whose paths must
be canonical contained relative paths resolved against the bindings file. Legacy v1 remains accepted
for existing releases: absolute paths retain their original meaning and relative paths retain the
historical current-working-directory meaning. Ambiguous v1 relative documents should be migrated to
v2 rather than moved.

The example below includes the conditional teacher-lineage arguments. Omit the admission path and all
five lineage-trust arguments together for a human-authored-only corpus.

Production evaluation-authoring custody can keep its private key outside this process. The detached
path publishes one canonical, content-addressed `unsigned-non-authorizing` bundle containing the
exact approval-v1 payload, unsigned envelope fields, pinned trust tuple, raw ES256 signature
preimage, and its SHA-256 digest. A raw-message signer signs the decoded `signaturePreimage`; a
digest-mode KMS/HSM signs the decoded 32-byte `signatureInput` with ECDSA-SHA-256 pre-hashed
semantics. The external adapter returns one closed
`evaluation-authoring-approval-signature.v1.schema.json` document bound to the exact bundle ID and
bytes, approval/payload/signature-input hashes, and public-key SPKI hash. Finalization accepts
canonical DER or fixed 64-byte P1363, normalizes a valid high-S signature to the approval contract's
low-S P1363 form, reopens the public key and complete live inventory, and emits the unchanged
approval-v1 envelope consumed downstream.

Adapters derive `signatureId` after populating every other signature-document field: temporarily set
it to `vqauthoringsignature-` plus 64 zeroes, encode that object with the tool's canonical JSON, then
SHA-256 the two-field framing of (1) ASCII
`daxalgo-evaluation-authoring-approval-external-signature-id/v1` plus one NUL byte and (2) those
canonical bytes. Each field is prefixed by its unsigned 8-byte big-endian byte length. Replace the
zero suffix with the lowercase digest. The exported
`evaluation_authoring_approval_signature_id` helper is the normative implementation.

The unsigned bundle alone grants no authority. Once paired with a valid external signature, the two
handoff files are approval-equivalent sensitive material because deterministic finalization needs no
additional authorization, even though downstream consumers accept only the finalized envelope. A
separate bundle-authorization signature is unnecessary because the one envelope signature already
covers every material approval, inventory, validity, authority, and trust field; fields outside that
signed payload must never be treated as approved. This handoff does not provision a KMS/HSM, establish
reviewer identity, enforce IAM/quorum/audit policy, prove suite correctness or sealed custody, manage
rotation/revocation, attest clocks, or close privileged host path-swap races. The direct PEM command
remains a local workflow convenience.

```powershell
.venv\Scripts\vibe-quant-model compile-evaluation-authoring-handoff `
  --manifest <evaluation-authoring-manifest.json> `
  --source-dataset <reviewed-expert-dataset.jsonl> `
  --output-directory <new-evaluation-authoring-handoff-directory>
.venv\Scripts\vibe-quant-model validate-evaluation-authoring-handoff `
  <new-evaluation-authoring-handoff-directory/evaluation-authoring-handoff.json> `
  --source-dataset <reviewed-expert-dataset.jsonl>
.venv\Scripts\vibe-quant-model create-evaluation-authoring-approval `
  --output <evaluation-authoring-approval.json> `
  --private-key <authoring-private-key.pem> `
  --evaluation-authoring-approval-public-key <authoring-public-key.pem> `
  --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> `
  --evaluation-authoring-approval-audience <authoring-audience> `
  --evaluation-authoring-approval-key-id <authoring-key-id> `
  --evaluation-authoring-approval-signer-role <independent-authoring-reviewer-role> `
  --approval-id <stable-authoring-approval-id> `
  --actor-id <stable-authoring-reviewer-id> `
  --actor-role <independent-authoring-reviewer-role> `
  --approval-reference <review-reference> `
  --approved-at-utc <UTC> --issued-at-utc <UTC> `
  --not-before-utc <UTC> --expires-at-utc <UTC> `
  --source-dataset <expert-dataset.jsonl> `
  --calibration-tasks <calibration.tasks.jsonl> `
  --sealed-tasks <sealed.tasks.jsonl> `
  --task-bindings <reviewed-bindings.json>
.venv\Scripts\vibe-quant-model prepare-evaluation-authoring-approval-signing-bundle `
  --output <evaluation-authoring-signing-bundle.json> `
  --evaluation-authoring-approval-public-key <authoring-public-key.pem> `
  --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> `
  --evaluation-authoring-approval-audience <authoring-audience> `
  --evaluation-authoring-approval-key-id <authoring-key-id> `
  --evaluation-authoring-approval-signer-role <independent-authoring-reviewer-role> `
  --approval-id <stable-authoring-approval-id> `
  --actor-id <stable-authoring-reviewer-id> `
  --actor-role <independent-authoring-reviewer-role> `
  --approval-reference <review-reference> `
  --approved-at-utc <UTC> --issued-at-utc <UTC> `
  --not-before-utc <UTC> --expires-at-utc <UTC> `
  --source-dataset <expert-dataset.jsonl> `
  --calibration-tasks <calibration.tasks.jsonl> `
  --sealed-tasks <sealed.tasks.jsonl> `
  --task-bindings <reviewed-bindings.json>
.venv\Scripts\vibe-quant-model finalize-evaluation-authoring-approval `
  --signing-bundle <evaluation-authoring-signing-bundle.json> `
  --signature <external-authoring-signature.json> `
  --output <evaluation-authoring-approval.json> `
  --evaluation-authoring-approval-public-key <authoring-public-key.pem> `
  --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> `
  --evaluation-authoring-approval-audience <authoring-audience> `
  --evaluation-authoring-approval-key-id <authoring-key-id> `
  --evaluation-authoring-approval-signer-role <independent-authoring-reviewer-role> `
  --source-dataset <expert-dataset.jsonl> `
  --calibration-tasks <calibration.tasks.jsonl> `
  --sealed-tasks <sealed.tasks.jsonl> `
  --task-bindings <reviewed-bindings.json>
.venv\Scripts\vibe-quant-model create-release `
  --corpus <expert-dataset.jsonl> `
  --review-receipts <review-receipts.jsonl> `
  --review-receipt-public-key <reviewer-public-key.pem> `
  --review-receipt-public-key-spki-sha256 <64-lowercase-hex> `
  --review-receipt-audience <review-audience> `
  --review-receipt-key-id <review-key-id> `
  --review-receipt-signer-role <independent-reviewer-role> `
  --teacher-lineage-admission <teacher-lineage-admission.json> `
  --teacher-lineage-admission-public-key <lineage-reviewer-public-key.pem> `
  --teacher-lineage-admission-public-key-spki-sha256 <64-lowercase-hex> `
  --teacher-lineage-admission-audience <lineage-audience> `
  --teacher-lineage-admission-key-id <lineage-key-id> `
  --teacher-lineage-admission-signer-role <independent-lineage-reviewer-role> `
  --evaluation-authoring-approval <evaluation-authoring-approval.json> `
  --expected-evaluation-authoring-approval-envelope-sha256 <64-lowercase-hex> `
  --evaluation-authoring-approval-public-key <authoring-public-key.pem> `
  --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> `
  --evaluation-authoring-approval-audience <authoring-audience> `
  --evaluation-authoring-approval-key-id <authoring-key-id> `
  --evaluation-authoring-approval-signer-role <independent-authoring-reviewer-role> `
  --calibration-tasks <calibration.tasks.jsonl> `
  --sealed-tasks <sealed.tasks.jsonl> `
  --task-bindings <reviewed-bindings.json> `
  --approval-evidence <approval-record> `
  --purpose local-evaluation `
  --cutoff-utc 2025-01-15T12:00:00Z `
  --approval-id <stable-approval-id> `
  --reviewer-id <stable-reviewer-id> `
  --approved-at-utc 2025-01-20T12:00:00Z `
  --output-root ..\..\tmp\vibe-quant-model\releases
.venv\Scripts\vibe-quant-model validate-release <vqrel-directory> `
  --review-receipt-public-key <reviewer-public-key.pem> `
  --review-receipt-public-key-spki-sha256 <64-lowercase-hex> `
  --review-receipt-audience <review-audience> `
  --review-receipt-key-id <review-key-id> `
  --review-receipt-signer-role <independent-reviewer-role> `
  --teacher-lineage-admission-public-key <lineage-reviewer-public-key.pem> `
  --teacher-lineage-admission-public-key-spki-sha256 <64-lowercase-hex> `
  --teacher-lineage-admission-audience <lineage-audience> `
  --teacher-lineage-admission-key-id <lineage-key-id> `
  --teacher-lineage-admission-signer-role <independent-lineage-reviewer-role> `
  --evaluation-authoring-approval-public-key <authoring-public-key.pem> `
  --evaluation-authoring-approval-public-key-spki-sha256 <64-lowercase-hex> `
  --evaluation-authoring-approval-audience <authoring-audience> `
  --evaluation-authoring-approval-key-id <authoring-key-id> `
  --evaluation-authoring-approval-signer-role <independent-authoring-reviewer-role>
```

Training purposes additionally require `--sft` and hash-bound
`knowledgeClass=candidate-stable` verification evidence on every training row. A
`knowledgeClass=retrieval-only` row or source cannot declare training rights. Provider purposes
require provider-upload rights on every example and source whose content is released to that provider. Creation snapshots before
validation, rejects links/reparse points, derives `vqrel-<full-sha256>` from the canonical manifest,
and exclusively installs that directory without replacement. Context packs, rubrics, verifiers,
and approval evidence remain inert bytes; this tool never imports or executes them.

The release approval remains deliberately marked `declarativeOnly: true`: it joins corpus review and
evaluation-authoring approval without borrowing either signer's authority. The signed authoring
approval authenticates one exact evaluation inventory, but signatures cannot prove expected-value
correctness, semantic coverage, verifier quality, legal rights, or the real-world identity of a
reviewer. Lineage, receipt, authoring, selection, replay-audit, and promotion signers remain
separated. The teacher-lineage admission itself does not authorize correctness, rights, release,
training, evaluation, promotion, deployment, serving, installation, verifier execution, or strategy
execution.

Every Python release-bound command that accepts review-receipt trust also accepts the five
`--teacher-lineage-admission-*` trust arguments. They are required together for a teacher-backed
release and rejected for a human-only release. Downstream consumers derive the admission file from
the validated release; they do not accept a second caller-selected admission path that could diverge
from the bundled envelope.

Release paths are locators, not trusted evidence. Every real non-smoke training run, candidate
artifact seal, normal response capture, promotion aggregation, and readiness proof must fully
revalidate the live bound release-v4, receipt set, applicable teacher-lineage admission, and
evaluation-authoring approval with externally
supplied trust; their
manifests and evidence bind its `releaseId`, canonical `releaseSha256`, and raw release-manifest
`manifestSha256`. Consumption cannot outlive the earliest applicable lineage, receipt, or
authoring-approval expiry. Capture revalidates
immediately before every provider request; training checks authorization before model setup,
before and during training at epoch/step boundaries, after training, and again before artifact
sealing. Production CLI and engine-wrapper paths always use the live UTC clock, so expiry aborts
consumption and prevents publication of a candidate artifact.
Smoke training and explicitly selected unbound research flows remain unpromoted research, and their
promotion reports are never eligible for promotion review.

## Commands and formats

- `validate-catalog`: enforces the four approved official model records, Apache-2.0 licence/source
  URLs, unique roles, and exact immutable revisions.
- `validate-sft`: structurally enforces strict UTF-8/JSON, exact fields, message order, the shared
  length-prefixed UTF-8 content-hash contract, model lineage, schemas, splits, domains, unique
  IDs/content, and contamination boundaries. It never grants review, rights, or consumption
  authorization.
- `summarize-coverage`: prints a machine-readable coverage report.
- `summarize-corpus-quality` / `validate-corpus-quality-policy`: derive exact rational structural
  evidence and validate a reviewer-selected policy without supplying any repository-owned minima.
- `create-training-corpus-admission` /
  `prepare-training-corpus-admission-signing-bundle` /
  `finalize-training-corpus-admission` / `validate-training-corpus-admission`: sign or reauthenticate
  one exact released SFT report and reviewer-selected policy with separate external trust. The direct
  create route is a local PEM convenience. The detached prepare/finalize routes accept no private-key
  option: preparation emits the exact raw admission-envelope preimage and its one SHA-256 digest, and
  finalization accepts an externally produced DER or fixed P1363 signature, verifies it without
  double hashing, canonicalizes valid high-S input to low-S, freshly revalidates every live input, and
  emits the unchanged admission-v1 envelope. One signature is sufficient because that preimage covers
  every material release, corpus, report, policy, validity, trust, and authority field. The unsigned
  bundle grants no authority, but a valid bundle/signature pair is finalization-equivalent sensitive
  material. The authority is reusable only for the exact release, dataset, policy, and validity
  window; it is not a one-shot token. It grants no rights, release, training execution, evaluation,
  promotion, deployment, hosted-serving, installation, verifier-execution, or strategy-execution
  authority. This is a provider-neutral custody seam, not KMS/HSM provisioning or attestation of IAM,
  reviewer identity, quorum, audit logging, key lifecycle, honest clocks, sealed storage, or
  caller-selected host paths and privileged/same-user path swaps.
- `create-bundle`: creates a new immutable bundle and manifest without training; existing output is
  never overwritten, and only a catalog entry carrying the `student` role may be selected. A real
  training bundle binds a fully validated corpus/evaluation release, signed corpus admission,
  signed base-model selection, and exact selected profile/source-lock/snapshot identities. Unselected
  manifest-v1 and historical selected manifest-v2 bundles are
  retained only for smoke and explicit legacy fixtures. Every bundle also snapshots the reviewed
  training-runtime profile and its complete hashed wheel lock; model weights stay external.
- `validate-manifest` and `validate-bundle`: byte-check all referenced inputs and cross-bind the
  selected catalog candidate, SFT coverage, runtime profile, and pylock. Catalog, dataset, runtime,
  lock, and output paths are fixed, and every existing path component must be free of symbolic links
  and Windows reparse points.
- `train`: requires and revalidates the bound release, signed corpus admission, signed selection,
  and separately trusted trainer authority for non-smoke training. It supports mutually exclusive
  direct PEM sealing or a private-key-free pending signing handoff,
  rejects legacy manifest v1 outside explicit smoke, and loads both tokenizer and model only from
  the exact external read-only snapshot. It then lazily imports `transformers`, `datasets`, `peft`, `trl`, `accelerate`,
  `bitsandbytes`, and PyTorch only after artifact validation. Exact interpreter, OS/architecture,
  CUDA, and direct dependency versions must match the sealed runtime before GPU probing and
  local-only QLoRA-SFT.
- `finalize-training-artifact`: accepts only the pending package and an external signature, not a
  private key or password. It replays the exact live release, receipts, optional teacher lineage,
  evaluation-authoring approval, base selection/snapshot, corpus admission, trainer trust, pending
  core/tree, and active validity before and after staged publication. The unsigned bundle grants no
  authority, but its valid signature pair is replayable exact-artifact finalization material and must
  be protected accordingly. This handoff does not provision or attest KMS/HSM IAM, quorum, audit,
  trainer identity, revocation, honest clocks, immutable pending storage, or privileged/same-user
  caller-selected path custody; those remain production controls.
- `validate-artifact`: rehashes every allowed adapter/tokenizer file and validates the canonical
  metadata, manifest identity, environment evidence, safetensors layout, safe inference shape, and
  externally pinned trainer provenance for candidate artifact v2. Historical v1 remains
  structurally parseable but cannot enter a production consumer.
- `create-serving-profile` and `validate-serving-profile`: derive or revalidate the exact
  manifest/artifact/runtime identity. Smoke artifacts, incompatible candidate context lengths or
  quantisation, mutable aliases, changed files, custom-code mappings, and unreviewed file shapes fail
  closed. Candidate profiles require active trainer trust; content-identical artifacts may be
  relocated into immutable storage.
- `seal-base-model-snapshot`, `validate-base-model-snapshot`,
  `create-base-evaluation-profile`, and `validate-base-evaluation-profile`: bind a raw student
  baseline to the compiled approved source lock, exact local model/tokenizer bytes, reviewed chat
  template, and runtime profile without inventing adapter provenance. The launch helper is an
  explicit research-only plan, not a live-process attestation.
- `compile-draft-calibration-tasks`: compile a strict private authoring manifest into canonical
  calibration JSONL. Context-pack and verifier assets must be contained relative paths; their exact
  bytes are hashed, prompt/task hashes are derived, the generated set is revalidated, and an existing
  output is never replaced. This draft-only path cannot create sealed tasks and does not create a
  release, approval, verifier result, response capture, or promotion evidence.
- `compile-evaluation-authoring-handoff` and `validate-evaluation-authoring-handoff`: derive and
  revalidate paired calibration/sealed tasks and a closed exact-asset package from reviewed
  evaluation corpus rows. V1 maps every evaluation row exactly once, derives prompt/split/domain/
  cutoff identities rather than accepting overrides, omits reference answers, requires non-training
  rights, rejects cross-split and development prompt leakage, and publishes atomically without
  replacing an existing directory. The unsigned handoff does not prove author identity, review
  truth, expected-value correctness, asset quality, independent custody, withholding, or any
  downstream authorization.

  The private structured-calibration draft under
  `../../tmp/vibe-quant-model/evaluation/structured-calibration/` contains one strict-JSON task for
  each required domain. Every task binds an exact root-object key set plus typed string, boolean, or
  bounded-decimal checks. It remains unreviewed, calibration-only, non-sealed, and non-authorizing;
  the expected outputs and verifier assets are not a withheld benchmark or model-quality evidence.
- `derive-teacher-runtime-plan`, `create-teacher-runtime-binding`, and
  `validate-teacher-runtime-binding`: derive the exact execution identity without network access,
  then create or freshly revalidate an explicitly unattested observation of one exact loopback vLLM
  version, model card, root string, and context limit.
- `validate-teacher-generation`, `capture-teacher-candidates`, and
  `validate-teacher-candidates`: validate a development-only teacher plan, require the exact freshly
  probed runtime binding, capture every source-bound seeded candidate, and revalidate the immutable
  review queue. Exact binding/teacher/runtime/template, prompt/task/source/output, usage, latency,
  authority, and batch identities are retained. Capture is all-or-nothing and cannot emit dataset-
  or training-eligible records.
- `create-teacher-overlap-deny-set`, `validate-teacher-selection`,
  `materialize-teacher-candidates`, and `validate-teacher-materialization`: derive a hash-only deny-set
  from the exact calibration/sealed tasks, bind independent selection to it plus the exact queue,
  source manifest, and catalog, then derive a self-contained immutable canonical
  `expert-model-dataset/v1` draft package. The selector cannot override lineage or policy; the
  package's internal admission record remains unsigned, unverified, storage/evaluation-only, and
  receipt-gated before any training use.
- `create-teacher-lineage-admission`,
  `prepare-teacher-lineage-admission-signing-bundle`,
  `finalize-teacher-lineage-admission`, and `validate-teacher-lineage-admission`: revalidate one
  exact materialization package, passive runtime binding, reviewer-evidence file, and final corpus;
  sign locally or through a provider-neutral detached handoff; authenticate the ordered stable
  teacher subjects under separate low-S ES256 trust; and authorize only receipt issuance. The two
  detached routes expose no private-key option. V1 binds one package and does not attest runtime,
  weights, image, entrypoint, process, isolation, correctness, rights, review correctness, or any
  downstream authority.
- `validate-eval-tasks` and `summarize-eval-coverage`: validate strict calibration/sealed JSONL.
  Every task ends with a user message and binds the prompt, immutable context-pack version/hash,
  reviewed verifier, required checks, contamination group, cutoff, criticality, and output limit
  with length-prefixed UTF-8 hashes. Exact prompts and contamination families cannot cross the two
  splits. A capture file must contain one homogeneous split.
- `capture-responses`: call an OpenAI-compatible `chat/completions` endpoint with deterministic
  sampling and capture exact catalog, candidate, 40-character revision, serving-profile, run, task,
  prompt, output, usage, latency, and finish bindings. `--catalog`, `--serving-profile`, `--artifact`,
  and `--manifest` are required; candidate/model/revision/profile hashes are derived rather than
  trusted from command-line assertions. Requests use the content-addressed execution model ID and
  the returned response model must match it. Supply only an environment-variable **name** through
  `--api-key-env`; key values must be
  visible ASCII, are never accepted as arguments, and are never persisted.
  Endpoints must use HTTPS, except loopback HTTP; redirects, environment proxies, oversized
  responses, aggregate output beyond the evaluation-file limit, malformed output, and overwrite are
  rejected. Sealed verifier IDs, hashes, rubrics, context hashes, and criticality are not included
  in model requests. `length` and `content_filter` finishes are recorded for audit but are hard
  evidence-gate failures; only a non-empty `stop` response is accepted for scoring.
  Normal captures must match a fully validated release task set. Explicit unbound research captures
  carry `researchOnly: true` and `evidenceStatus: unpromoted-research`.
- `capture-base-responses`: capture a loopback-only, explicitly research-only raw-base run from the
  exact sealed source-lock/profile identity. Full snapshot/profile/catalog bytes are revalidated
  before publication.
- `create-base-engine-activation`, `prepare-base-engine-activation-signing-bundle`,
  `finalize-base-engine-activation`, `validate-base-engine-activation`, and
  `serve-base-evaluation-model`: locally sign or externally finalize, verify, and run the exact
  read-only raw-base owner. The config
  pins separate wrapper/child identities, the runtime signer, vLLM executable/version/image claim,
  inner/outer ports, bounded service limits, and the exact sealed target. Wrapper config v2 uses the
  pinned-TLS loopback external-signer contract; v1 retains local-PEM compatibility. Native Windows
  serving is rejected; the production path is a locked-down POSIX container.
- `capture-attested-base-responses` and `validate-attested-base-responses`: create release-bound
  response-v2 records with atomic asymmetric per-completion receipts, then cryptographically verify
  the historical activation and receipt signatures plus task/request/completion/release bindings.
  Promotion commands expose independent all-or-none candidate/baseline launcher/runtime trust
  groups and reverify v2 records before aggregation, signing, validation, or readiness issuance.
- `create-base-model-selection`, `prepare-base-model-selection-signing-bundle`,
  `finalize-base-model-selection`, and `validate-base-model-selection`: load the strict paths-only
  `--bakeoff-sources` manifest, freshly replay exactly one release-bound attested raw-base-v2 row for
  every catalog student, require an attested raw-base-v2 shared baseline, enforce common
  suites/seed/source-lock/policy family, and bind the catalog-ordered matrix plus exact passing target
  and approval bytes in selection v2. Missing,
  duplicate, extra, incomparable, expired, drifted, or pair-only v1 authority fails closed. The
  decision authorizes a training base only; it grants no checkpoint, promotion, deployment, or
  quality status. The detached routes expose no private-key option and publish the same v2 consumer
  wire after external DER/P1363 signing and complete live finalization replay.
- `validate-responses` and `validate-verifier-results`: reject duplicate or cross-bound records.
  Generic response validation is structural and reports the semantic task-set and response-set
  hashes needed for independent review; it does not authenticate response-v2 signatures. CLI result
  validation requires exactly one response and result for every bound task.
- `compile-verifier-results`: compile one strict, row-complete human decision manifest into the
  unchanged canonical verifier-result JSONL for explicit unbound research captures only. The
  manifest must bind those exact semantic task and response sets, every task and response, each
  response hash, and the required checks in declared order. Run, task, verifier, evidence,
  acceptance, and result hashes are derived from exact input byte snapshots; all three inputs are
  rehashed immediately before atomic installation. Output is sorted and installed without
  replacement. Evidence remains inert text. This command does not execute a verifier or model
  output, authenticate a reviewer, establish that a decision is correct, or produce release-bound
  evidence.
- `run-verifiers`: execute each exact release-bound verifier asset through either the inert
  `declarative-output/v1` profile or the signed `daxalgo-sdk-headless-source/v1` C# profile in
  `executable-verifier/v2`. Declarative checks remain limited to exact text containment/absence,
  whole-output equality or SHA-256, strict duplicate-free JSON object-key/string/boolean/null
  assertions, and bounded decimal comparisons through RFC 6901 pointers. The C# profile has no command, image,
  entrypoint, key, package, plugin, or network field; it accepts only the fixed contract/case shape and
  obtains the complete execution identity from a live signed authority plus external trust. The
  runner requires a fully validated release and release-bound responses, derives canonical results
  without exposing expected values, revalidates task/response/release inputs immediately before
  atomic no-clobber publication, and fails closed on missing, partial, unused, expired, or drifted C#
  authority; unknown fields or profiles; malformed JSON; ambiguous pointers; non-finite or oversized
  decimals; negative-only check sets; or incomplete task coverage. Runtime validation also enforces
  bounds and cross-field invariants that JSON Schema cannot completely express.
- `create-csharp-verifier-authority` / `prepare-csharp-verifier-authority-signing-bundle` /
  `finalize-csharp-verifier-authority` / `validate-csharp-verifier-authority`: issue locally, prepare
  and finalize through a private-key-free provider-neutral handoff, or validate the externally
  pinned, short-lived research-only image/entrypoint/toolchain/sandbox lease.
- `create-csharp-verifier-replay-audit` /
  `prepare-csharp-verifier-replay-audit-signing-bundle` /
  `finalize-csharp-verifier-replay-audit` / `validate-csharp-verifier-replay-audit`: freshly execute
  both exact release-bound suites under one authority configuration; sign locally or through a
  private-key-free provider-neutral handoff; bind the complete C# subset and paired file/set
  identities with an independent key; or validate one exact pinned audit without invoking Docker.
  Direct creation or detached finalization is the only path that converts live C# replay into this
  bounded non-executing production-validation input.
- `verify-csharp-strategy`: run the same signed-authority headless Core/SDK single-source strategy
  verifier directly against bounded tick cases and host-only expected trace hashes. Its result-v2 is
  also the trusted execution source for the release-bound v2 profile; direct results alone remain
  standalone and unpromoted.
- `validate-promotion-policy`: validate thresholds and suite-sufficiency minimums frozen from a
  hash-bound calibration task set and evidence file. The policy also binds the exact sealed task set
  plus candidate and reviewed strongest-baseline catalog/model/revision/profile/run/seed identities.
  Paired runs must use the same catalog bytes and seed, distinct run IDs, and distinct model
  revisions or serving-profile content hashes; changing labels alone cannot create a baseline.
  It structurally requires calibration-sourced thresholds and candidate/baseline captures after the
  freeze timestamp. Timestamp checks enforce declared ordering; hashes and timestamps do **not**
  cryptographically prove when a policy was authored or prevent deliberate backdating.
- `aggregate-promotion-evidence`: require a bounded calibration-evidence file with the frozen hash,
  plus exactly one candidate response/result and one strongest-baseline response/result for every
  task in the same sealed set. It rejects calibration/sealed contamination overlap, checks minimum
  total/critical/per-domain task and contamination-group coverage, applies zero-critical-failure and
  overall/every-domain accepted-rate gates, and requires no overall or per-domain regression against
  the paired baseline. For release-bound evidence it freshly reruns the exact verifier bytes for
  both candidate and baseline and rejects any supplied result that differs. For an exact externally
  pinned C# replay audit, only its covered C# rows use authenticated non-executing validation; every
  declarative row is still freshly rerun. Canonicalized human decisions therefore cannot enter the
  production evidence path. Non-stop finishes in either run
  fail the gate. Response v2 additionally requires fresh role-specific launcher/runtime signature
  verification; response v1 and research aggregation reject unused attestation trust. The
  deterministic report binds both exact run identities and response/result-set
  hashes and is always `evidenceOnly: true`,
  `promotionStatus: unpromoted`, and `promotionEligible: false`; passing gates only makes it eligible
  for independent promotion review when the report is release-bound. Explicit research-only reports
  remain ineligible even when every evidence gate passes.
- `validate-promotion-evidence`: strictly validates every runtime field, nested metric, relationship,
  and the zero-sentinel length-prefixed report hash.
- `create-model-promotion`: reaggregate all live evidence, bind every release/model/deployment input,
  sign one immutable production envelope with an external P-256 key pair, and immediately revalidate
  the written bytes. A promoted candidate must remain response-v1 `trained-adapter`; raw-base v2 may
  supply the paired baseline only. Existing outputs are never replaced.
- `prepare-model-promotion-signing-bundle` and `finalize-model-promotion`: derive the same exact
  promotion payload without a private key, export raw-message plus prehashed-digest signing inputs,
  verify the provider-produced DER/fixed-P1363 signature, freshly replay every live binding, and
  publish the unchanged promotion-v1 consumer wire through the owned no-clobber commit protocol.
- `validate-model-promotion`: authenticate exact payload bytes with the externally pinned public key,
  enforce strict payload/policy/time semantics, then independently reaggregate and compare every
  live evidence and model binding.
- `create-model-readiness-v2`: revalidate the complete active promotion and live inputs before
  emitting the four-field promotion-bound readiness response for one 32-byte nonce challenge.
- `serve-promoted-model`: own one exact promoted vLLM process, post-load revalidate it, and expose the
  bounded authenticated readiness/chat gateway only while that child remains healthy and unchanged.
- `create-review-receipts` and `validate-review-receipts`: issue current v2 or verify a homogeneous
  exact-order detached canonical JSONL receipt set using ES256 P-256 low-S P1363 signatures, a pinned
  reviewer public key/SPKI identity, and active validity times. V2 binds the exact source-corpus and
  row-evidence identities into both the receipt and SFT metadata. Teacher-backed rows additionally
  require the full materialization/runtime/evidence replay plus the independently signed lineage
  admission; legacy v1 is Python archival validation only for all-`HumanAuthored` release-v3 data.
- `create-evaluation-authoring-approval`,
  `prepare-evaluation-authoring-approval-signing-bundle`,
  `finalize-evaluation-authoring-approval`, and `validate-evaluation-authoring-approval`: sign or
  reauthenticate one exact corpus/task/lineage/context/rubric/verifier inventory with a pinned
  independent ES256 authority and active bounded validity window. Prepare/finalize keeps the private
  key behind an external signer while preserving the existing approval-v1 wire; its handoff files
  remain non-authorizing. The unsigned suite handoff must still be independently reviewed and signed
  through this separate boundary before release use.
- `create-release` and `validate-release`: freeze and revalidate a release-v4 private
  rights-bearing corpus, mandatory receipt-set and signed evaluation-authoring approval trust,
  conditional signed teacher-lineage admission, optional exact SFT export, raw evaluation task files plus semantic task-set identities,
  task-to-corpus lineage, rubric/verifier assets, cutoff, and declarative approval under a no-clobber content-derived
  release identity. The release bundles the admission envelope, not its source package/runtime/evidence;
  legacy v3 is archival-validation-only for all-`HumanAuthored` corpora and cannot return an
  authorizing release identity. Release-bound promotion additionally
  requires every sealed verifier asset to pass the closed executable profile.

The authoritative machine-readable schemas are under `schemas/`. The runtime validator adds
cross-file hash, catalog-candidate, chat-template, split, and domain checks that JSON Schema alone
cannot express.

## Explicit non-goals

This Python tool does not download models or data, manufacture training rows, train by default,
upload private material, automatically author evaluation verifiers, execute arbitrary verifier code,
provision deployment infrastructure, terminate public TLS, manage production keys, decide that a
model deserves approval, integrate with the Terminal, execute generated code outside the bounded
single-source headless strategy verifier, or place orders. It can explicitly execute only the closed
declarative verifier profile and the signed-authority Core/SDK release profile, capture reviewed sealed
tasks and aggregate supplied evidence, but it never uses sealed results to tune thresholds. Hashes
demonstrate byte identity, not data rights, correctness, safety, model quality, or remote endpoint
attestation. A promotion envelope records and authenticates an already-authorized decision; it does
not manufacture one. The wrapper trusts the orchestrator-supplied current-image-digest environment
value and still requires a genuinely digest-pinned image, immutable/read-only model inputs, external
TLS for remote access, production secret injection, and an independent supervisor. A dependency
lock proves byte selection and environment equality; it does not approve package licences,
vulnerability posture, or target-hardware compatibility.

Run the standard-library tests without installing training dependencies:

```powershell
.venv\Scripts\python -m unittest discover -s tests -v
```
