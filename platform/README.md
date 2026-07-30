# DaxAlgo distribution platform foundation

This directory is the current .NET 9 development foundation for the private account, entitlement,
billing, marketplace, and hosted Hyperion modules. It is deliberately separate from the
desktop solution and public submodule. The API runs locally with no secrets, identity tenant, billing
account, PostgreSQL server, production-grade outbox/worker, object storage, or model-provider
connection. Production is blocked and targets supported .NET 10 LTS; nothing in this README
represents a live customer service.

## Run locally

From this directory:

```powershell
dotnet run --project src/DaxAlgo.Platform.Api
```

The launch profile binds to `http://127.0.0.1:5088` in Development. Currently implemented endpoints
include:

- `GET /health` for the API/database health check.
- `GET /openapi/v1.json` for native ASP.NET Core OpenAPI.
- `GET /api/v1/plans` for the authenticated canonical plan catalog.
- `/api/v1/profiles`, `/api/v1/devices`, and `/api/v1/entitlements` for product accounts,
  device registration, projected access, and offline lease issuance.
- `/api/v1/catalog`, `/api/v1/submissions`, and `/api/v1/orders` for authenticated marketplace
  state. Submission and publisher operations require a current Professional entitlement.
- `/v1/devices/challenges` and `/v1/marketplace/licenses/{id}` for single-use P-256 device proofs,
  entitlement-gated DAXQ content-key release, and licensing heartbeats. Signed download grants and
  the monotonic signed revocation feed also live under `/v1/marketplace`.
- `/api/v1/vibe-quant/credits` and `/api/v1/vibe-quant/runs` for the Professional hosted coordinator;
  run subroutes expose safe specs, start/cancel/release approvals, and hash-addressed artifacts.
- `POST /api/v1/admin/vibe-quant/credits/grants` for idempotent `platform-admin` allocations.
- `POST /api/v1/billing/webhooks` for provider-neutral billing events.

The development identity adapter authenticates requests carrying `X-Dev-Subject`. Optional
`X-Dev-Email`, `X-Dev-Name`, and comma-separated `X-Dev-Roles` headers populate identity
claims; the `platform-admin` role can decide submitted marketplace listings. Development billing
webhooks require `X-Development-Webhook: accepted`. These adapters are rejected outside the
Development and Testing environments.

The plan catalog is fixed by server code: Basic is USD 0, Intermediate is USD 49/month, and
Professional is USD 79/month. `Billing:PriceIds:IntermediateMonthly` and
`Billing:PriceIds:ProfessionalMonthly` configure the allowlisted provider Price IDs. Verified
billing events carry a Price ID; event- or client-supplied tier names are ignored and unknown Price
IDs are rejected.

Each account can keep at most two active device registrations. Revoked IDs cannot be reactivated.
An authenticated account can request a lease only for one of its active devices. Version 1 leases
carry normalized state and edition, product-account/device binding, issuer/audience, issue,
not-before and expiry times, plus signing key/algorithm metadata. Lease duration is capped at seven
days. DAXQ-capable registrations additionally store a validated P-256 public key and SHA-256
fingerprint; the private device key never reaches the platform.

## Hosted Hyperion development foundation and production target

The customer coordinator belongs in this private platform as a C# ASP.NET Core module plus a worker
role. C# keeps the existing typed workflow, hashes, cancellation semantics, OpenAPI contracts, and
PostgreSQL transactions in one runtime and lets credit reservation and job enqueue commit atomically.
Python may later run an isolated specialist or training worker behind a versioned, idempotent job
protocol; it must not own account authorization, the credit ledger, or direct writes to platform
tables.

The development API implements `/api/v1/vibe-quant` credits, run creation/listing, immutable
specifications, start/cancel/release approvals, and hash-addressed artifact reads. The production
lifecycle is:

1. An Auth0 bearer token resolves to a canonical account with a current Professional entitlement.
2. `GET /api/v1/vibe-quant/credits` returns a server-owned whole-credit balance and policy version.
3. `POST /api/v1/vibe-quant/runs` accepts an objective and bounded source pack with an idempotency key. The
   server selects the provider/model and bounded policy, then returns an immutable specification and
   maximum credit reservation.
4. Start approval echoes the exact specification hash. One serializable PostgreSQL transaction
   reserves integer credits, records approval, and enqueues a durable job; the API returns
   `202 Accepted`.
5. A worker leases and heartbeats the job, uses a server-owned provider credential, checkpoints role
   outputs, observes cancellation, and settles confirmed usage against the reservation. Unused credits
   are released. The current policy charges ambiguous or failed provider work to the platform, not the
   customer; any future policy requires durable dispatch evidence, reconciliation, and a new version.
6. The authenticated client polls status, retrieves immutable artifacts by run-scoped SHA-256, and binds
   release approval to the exact synthesized artifact hash.

Credits are product units, not currency, provider tokens, or a client-visible USD conversion. The
append-only ledger records grants, reservations, settlement, releases, expiries, and reasoned
adjustments and never permits a negative available balance. Grants originate only from server policy,
verified commerce/entitlement projections, or reasoned administrative action. Public DTOs never
contain provider URLs, credentials, secret-variable names, internal prices/prompts, replay paths, or
client-supplied owner/actor identities.

The hosted routes, safe HTTP client, remote coordinator CLI, account-scoped run/credit module, and
asynchronous server adapter are implemented for development. The active WPF shell is not yet wired to
the client. Per-run SQLite/filesystem storage, mock/live-adapter execution, replay fixtures, in-process
polling, development identity, and the in-memory test database are private development mechanics, not
a customer deployment model.

## Persistence

The default `Storage:Provider` is `InMemory`, which keeps local runs and tests self-contained.
For PostgreSQL:

1. Apply [schema.sql](src/DaxAlgo.Platform.Api/Persistence/schema.sql) to an empty database.
2. Set `Storage__Provider=Postgres`.
3. Supply `Storage__ConnectionString` through the deployment secret store.

Entity Framework Core provides the shared persistence model, while PostgreSQL constraints enforce
profile identity, device identity, catalog slugs, verified-review uniqueness, and billing-event
idempotency. DAXQ licensing adds schema-owned releases, licenses, KMS-wrapped content keys,
single-use proof challenges, one-row-per-challenge release audit, and a monotonic revocation
sequence. Serializable registration transactions plus an in-process account gate enforce the
two-active-device limit. The application never embeds a connection string or other deployment
secret.

The development model includes module-owned wallets, append-only credit movements, run rows, frozen
pricing/specification data, durable cancellation intent, and expiring fenced worker leases with
heartbeats. Production still needs reviewed migrations for command receipts, provider-invocation
boundaries, durable outbox/jobs, audit records, and reconciliation. Encrypted object storage—not
PostgreSQL rows—holds source packs and generated artifacts. Job leasing, credit movement, and the
approval transition must share durable transaction boundaries; in-memory queues and local SQLite are
not production alternatives.

## Provider seams

`IManagedIdentityProvider`, `IBillingProvider`, `IEntitlementLeaseSigningProvider`, and
`IMarketplaceLicenseCryptographyProvider` isolate managed identity, checkout/webhook behavior,
lease signing, DAXQ ES256 signing, and content-key unwrap. Development/Testing can select software
signing and wrapping; the Azure provider uses versioned KMS/HSM keys for ES256 and A256KW unwrap.
The software marketplace provider is rejected outside Development and Testing. A production
deployment must provision the independently named marketplace signing/content-wrapping keys and
select `azure-kms`; it must also add real managed-OIDC/Auth0 and production billing configuration.

The matching public desktop wire contract is
[EntitlementLeaseWireDto.cs](../public/src/windows/Core/TradingTerminal.Core/Accounts/EntitlementLeaseWireDto.cs).
The encoded signed payload is authoritative; typed outer fields are only early compatibility hints.
After signature validation, Core's typed `OfflineEntitlementLease` independently caps lifetime at
seven days and carries the authenticated device/not-before claims. The access evaluator compares the
expected local device ID before granting offline access.

Webhook processing verifies the provider payload before entering an idempotent inbox. The
`billing_webhook_receipts` primary key is the cross-instance guarantee; the in-process keyed gate
also makes development and in-memory tests deterministic. Unknown verified event types are safely
acknowledged and recorded.

The Hyperion development module uses a server-only model-provider adapter selected by policy. Its endpoint,
credential, token prices, egress rules, and reconciliation data come from protected deployment
configuration. Live mode additionally pins a serving profile and requires a fresh, private
nonce/HMAC readiness proof before credit reservation, job claim, and every provider dispatch. The
proof response contains no model or artifact hashes. Provider and attestation secrets never cross the
API boundary or enter run specifications, logs, or artifacts. Production still needs a trusted
engine-owning proof endpoint plus DNS/egress allowlisting or mTLS; the helper alone is not readiness.
Signed hosted-policy v1 remains Research-only. Hosted-policy v2 can additionally authorize the exact
model-bound inert StrategyAuthoring policy/workflow/prompt tuple. That capability is included in the
hosted-policy hash already bound by promotion, readiness, and execution activation; it grants no
compile, install, execution, broker, live-order, or release authority.

## Verify

```powershell
dotnet build DaxAlgo.Platform.slnx --configuration Release
dotnet test DaxAlgo.Platform.slnx --configuration Release
```

The tests use a unique in-memory database and exercise health/OpenAPI, authorization, canonical
prices, trusted Price-ID projection, paid-through cancellation, trial denial, two-device policy,
revocation, seven-day device-bound leases, webhook replay, Professional publisher policy, and the
marketplace submission-to-review flow. DAXQ coverage includes RFC 3394 vectors, proof-bound and
idempotent content-key release, release audit, lapse/revocation/device denials, signed heartbeats,
download grants, and monotonic rollback-protected revocations. Hosted Hyperion tests cover credit conservation, entitlement
and tenant isolation, retries, competing starts, failed-work refunds, active cancellation, lease
recovery/fencing, artifact access, serving-profile identity, hash-private readiness leases, and safe
transport contracts. No PostgreSQL instance or external provider is contacted.

## Production blockers and deliberately deferred work

- Upgrade and qualify the platform and relevant client closure on supported .NET 10 LTS.
- Real Auth0/managed OIDC tenant configuration and token validation.
- Real Stripe checkout, webhook-signature verification, refunds, tax, seller commission, and payouts.
- Production marketplace signing/content-wrapping key provisioning, access policy, rotation, and
  operational revocation-feed monitoring.
- Reviewed PostgreSQL migrations and production guards; durable outbox/job leasing, heartbeats,
  cancellation, retries, poison handling, and reconciliation workers.
- Encrypted immutable object storage with tenant authorization, hash verification, retention,
  deletion/export, backup/restore, and access audit.
- Secret/workload-identity integration, provider egress controls and rotation, per-account/global rate
  limits, abuse/spend controls, and fail-closed operational kill switches.
- Production image/IaC, health/readiness, redacted logs/metrics/traces, queue and credit alerts, SLOs,
  pager ownership, incident runbooks, and privacy/legal approval.
- Production-grade hosted Hyperion migrations, cross-instance command idempotency and concurrency,
  durable outbox/worker poison handling, immutable object storage, provider reconciliation, desktop
  WPF integration, and staged load/failure/security evidence.
- Artifact quarantine, malware review, object-storage enforcement of signed download grants, and
  publication delivery.
- Independent services; the current boundaries are modules inside one deployable API until scale or
  isolation requirements justify extraction.
