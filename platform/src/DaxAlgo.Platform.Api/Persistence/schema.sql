CREATE TABLE IF NOT EXISTS profiles (
    "Id" uuid PRIMARY KEY,
    "Subject" varchar(200) NOT NULL UNIQUE,
    "Email" varchar(320) NOT NULL,
    "DisplayName" varchar(120) NOT NULL,
    "CreatedAt" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    "AccountId" uuid PRIMARY KEY REFERENCES profiles ("Id"),
    "Provider" varchar(40) NOT NULL,
    "ProviderSubscriptionId" varchar(200) NOT NULL,
    "Plan" integer NOT NULL,
    "Status" varchar(32) NOT NULL,
    "CurrentPeriodEnd" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL,
    UNIQUE ("Provider", "ProviderSubscriptionId")
);

CREATE TABLE IF NOT EXISTS subscription_plan_migration_audit_events (
    "MigrationKey" varchar(100) NOT NULL,
    "AccountId" uuid NOT NULL,
    "ProviderSubscriptionId" varchar(200) NOT NULL,
    "CurrentPeriodEnd" timestamptz NOT NULL,
    "PreviousPlan" integer NOT NULL,
    "NewPlan" integer NOT NULL,
    "OccurredAt" timestamptz NOT NULL,
    PRIMARY KEY ("MigrationKey", "AccountId")
);

CREATE TABLE IF NOT EXISTS registered_devices (
    "AccountId" uuid NOT NULL REFERENCES profiles ("Id") ON DELETE CASCADE,
    "DeviceId" uuid NOT NULL,
    "DisplayName" varchar(120) NOT NULL,
    "RegisteredAt" timestamptz NOT NULL,
    "LastSeenAt" timestamptz NOT NULL,
    "RevokedAt" timestamptz,
    PRIMARY KEY ("AccountId", "DeviceId")
);

ALTER TABLE registered_devices
    ADD COLUMN IF NOT EXISTS "PublicKeySpki" varchar(512),
    ADD COLUMN IF NOT EXISTS "FingerprintSha256" char(64);

CREATE TABLE IF NOT EXISTS catalog_items (
    "Id" uuid PRIMARY KEY,
    "PublisherAccountId" uuid NOT NULL REFERENCES profiles ("Id"),
    "Slug" varchar(100) NOT NULL UNIQUE,
    "Title" varchar(160) NOT NULL,
    "Description" varchar(4000) NOT NULL,
    "Version" varchar(40) NOT NULL,
    "PriceInCents" bigint NOT NULL CHECK ("PriceInCents" BETWEEN 0 AND 1000000),
    "PriceMode" varchar(32) NOT NULL CHECK ("PriceMode" IN ('OneTime', 'Subscription')),
    "Currency" char(3) NOT NULL CHECK ("Currency" ~ '^[A-Z]{3}$'),
    "TemplateCopyJson" text NOT NULL,
    "MediaJson" text NOT NULL,
    "Status" varchar(32) NOT NULL,
    "CreatedAt" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS marketplace_submissions (
    "Id" uuid PRIMARY KEY,
    "PublisherAccountId" uuid NOT NULL REFERENCES profiles ("Id"),
    "Slug" varchar(100) NOT NULL,
    "Title" varchar(160) NOT NULL,
    "Description" varchar(4000) NOT NULL,
    "Version" varchar(40) NOT NULL,
    "PriceInCents" bigint NOT NULL CHECK ("PriceInCents" BETWEEN 0 AND 1000000),
    "PriceMode" varchar(32) NOT NULL CHECK ("PriceMode" IN ('OneTime', 'Subscription')),
    "Currency" char(3) NOT NULL CHECK ("Currency" ~ '^[A-Z]{3}$'),
    "SourceSha256" char(64) NOT NULL CHECK ("SourceSha256" ~ '^[0-9a-f]{64}$'),
    "SourceQuarantineUri" varchar(2000) NOT NULL,
    "ReferenceDatasetSha256" char(64) NOT NULL
        CHECK ("ReferenceDatasetSha256" ~ '^[0-9a-f]{64}$'),
    "ReferenceDatasetQuarantineUri" varchar(2000) NOT NULL,
    "LicenseExpression" varchar(100) NOT NULL,
    "DeclaredCapabilitiesJson" text NOT NULL,
    "RequestedExecutionClass" varchar(32) NOT NULL DEFAULT 'restricted_only'
        CHECK ("RequestedExecutionClass" IN ('restricted_only', 'server_signal')),
    "PreviousApprovedSourceSha256" char(64)
        CHECK ("PreviousApprovedSourceSha256" IS NULL
            OR "PreviousApprovedSourceSha256" ~ '^[0-9a-f]{64}$'),
    "SourceDiffSummaryJson" text,
    "DiversificationSeedSha256" char(64)
        CHECK ("DiversificationSeedSha256" IS NULL
            OR "DiversificationSeedSha256" ~ '^[0-9a-f]{64}$'),
    "BuildPolicyVersion" varchar(100),
    "BuildDiagnosticsJson" text,
    "ScanEvidenceJson" text,
    "ParityStatisticsJson" text,
    "ParityStatisticsSha256" char(64)
        CHECK ("ParityStatisticsSha256" IS NULL
            OR "ParityStatisticsSha256" ~ '^[0-9a-f]{64}$'),
    "ListingMetricsJson" text,
    "ListingMetricsSha256" char(64)
        CHECK ("ListingMetricsSha256" IS NULL
            OR "ListingMetricsSha256" ~ '^[0-9a-f]{64}$'),
    "SbomSha256" char(64)
        CHECK ("SbomSha256" IS NULL OR "SbomSha256" ~ '^[0-9a-f]{64}$'),
    "SbomQuarantineUri" varchar(2000),
    "ArtifactSha256" char(64)
        CHECK ("ArtifactSha256" IS NULL OR "ArtifactSha256" ~ '^[0-9a-f]{64}$'),
    "ArtifactQuarantineUri" varchar(2000),
    "ContentKeyId" varchar(128),
    "KmsWrappedContentKey" bytea,
    "ContentKeyWrappingAlgorithm" varchar(32),
    "CatalogItemId" uuid,
    "ReleaseId" uuid,
    "SourceReview" varchar(32) NOT NULL
        CHECK ("SourceReview" IN ('Pending', 'Passed', 'Failed')),
    "DeclaredBehaviorReview" varchar(32) NOT NULL
        CHECK ("DeclaredBehaviorReview" IN ('Pending', 'Passed', 'Failed')),
    "DiffReview" varchar(32) NOT NULL
        CHECK ("DiffReview" IN ('Pending', 'Passed', 'Failed')),
    "Status" varchar(32) NOT NULL,
    "ReviewNotes" varchar(1000),
    "CreatedAt" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL
);

ALTER TABLE marketplace_submissions
    ADD COLUMN IF NOT EXISTS "RequestedExecutionClass" varchar(32)
        NOT NULL DEFAULT 'restricted_only';

DO $$
DECLARE
    constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'marketplace_submissions'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%RequestedExecutionClass%'
    LOOP
        EXECUTE format(
            'ALTER TABLE marketplace_submissions DROP CONSTRAINT %I',
            constraint_name);
    END LOOP;

    ALTER TABLE marketplace_submissions
        ADD CONSTRAINT ck_marketplace_submissions_execution_class
        CHECK ("RequestedExecutionClass" IN ('restricted_only', 'server_signal'));
END $$;

CREATE TABLE IF NOT EXISTS marketplace_orders (
    "Id" uuid PRIMARY KEY,
    "BuyerAccountId" uuid NOT NULL REFERENCES profiles ("Id"),
    "CatalogItemId" uuid NOT NULL REFERENCES catalog_items ("Id"),
    "ReleaseId" uuid NOT NULL,
    "AmountInCents" bigint NOT NULL CHECK ("AmountInCents" >= 0),
    "PriceMode" varchar(32) NOT NULL CHECK ("PriceMode" IN ('OneTime', 'Subscription')),
    "Currency" char(3) NOT NULL CHECK ("Currency" ~ '^[A-Z]{3}$'),
    "ApplicationFeeInCents" bigint NOT NULL CHECK ("ApplicationFeeInCents" >= 0),
    "ReserveInCents" bigint NOT NULL CHECK ("ReserveInCents" >= 0),
    "SellerProceedsInCents" bigint NOT NULL CHECK ("SellerProceedsInCents" >= 0),
    "CommercialPolicyVersion" varchar(100) NOT NULL,
    "PayoutDelayDays" integer NOT NULL CHECK ("PayoutDelayDays" BETWEEN 0 AND 90),
    "AutomaticTaxEnabled" boolean NOT NULL,
    "TaxHandling" varchar(100) NOT NULL,
    "MerchantOfRecord" varchar(100) NOT NULL,
    "Status" varchar(32) NOT NULL,
    "ProviderCheckoutId" varchar(200),
    "CheckoutUrl" varchar(1000),
    "ProviderSubscriptionId" varchar(200),
    "CreatedAt" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS marketplace_reviews (
    "Id" uuid PRIMARY KEY,
    "CatalogItemId" uuid NOT NULL REFERENCES catalog_items ("Id") ON DELETE CASCADE,
    "AuthorAccountId" uuid NOT NULL REFERENCES profiles ("Id"),
    "Rating" integer NOT NULL CHECK ("Rating" BETWEEN 1 AND 5),
    "Body" varchar(2000) NOT NULL,
    "Status" varchar(32) NOT NULL,
    "CreatedAt" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL,
    UNIQUE ("CatalogItemId", "AuthorAccountId")
);

CREATE TABLE IF NOT EXISTS billing_webhook_receipts (
    "Provider" varchar(40) NOT NULL,
    "EventId" varchar(200) NOT NULL,
    "ProcessedAt" timestamptz NOT NULL,
    PRIMARY KEY ("Provider", "EventId")
);

CREATE SCHEMA IF NOT EXISTS marketplace;
CREATE SCHEMA IF NOT EXISTS entitlements;

CREATE TABLE IF NOT EXISTS marketplace.publisher (
    account_id uuid PRIMARY KEY REFERENCES profiles ("Id"),
    connect_account_id varchar(200),
    status varchar(32) NOT NULL
        CHECK (status IN ('NotStarted', 'Pending', 'Complete', 'Restricted')),
    details_submitted boolean NOT NULL,
    charges_enabled boolean NOT NULL,
    payouts_enabled boolean NOT NULL,
    terms_version varchar(100),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS marketplace.strategy_release (
    id uuid PRIMARY KEY,
    catalog_item_id uuid NOT NULL REFERENCES catalog_items ("Id"),
    submission_id uuid NOT NULL REFERENCES marketplace_submissions ("Id"),
    version varchar(40) NOT NULL,
    status varchar(32) NOT NULL CHECK (status IN ('Quarantined', 'Approved', 'Revoked')),
    artifact_blob_uri varchar(2000) NOT NULL,
    execution_class text NOT NULL DEFAULT 'restricted_only'
        CHECK (execution_class IN ('source_open', 'sealed_bytecode', 'server_signal', 'restricted_only')),
    vm_abi_version integer CHECK (vm_abi_version IS NULL OR vm_abi_version > 0),
    content_key_id varchar(128)
        CHECK (content_key_id IS NULL OR content_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    cipher_sha256 char(64) NOT NULL CHECK (cipher_sha256 ~ '^[0-9a-f]{64}$'),
    diversify_seed_id varchar(200),
    diversification_seed_sha256 char(64) NOT NULL
        CHECK (diversification_seed_sha256 ~ '^[0-9a-f]{64}$'),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_sha256 char(64) NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    parity_statistics_json text NOT NULL,
    parity_statistics_sha256 char(64) NOT NULL
        CHECK (parity_statistics_sha256 ~ '^[0-9a-f]{64}$'),
    listing_metrics_json text NOT NULL,
    listing_metrics_sha256 char(64) NOT NULL
        CHECK (listing_metrics_sha256 ~ '^[0-9a-f]{64}$'),
    scan_evidence_json text NOT NULL,
    sbom_sha256 char(64) NOT NULL CHECK (sbom_sha256 ~ '^[0-9a-f]{64}$'),
    sbom_blob_uri varchar(2000) NOT NULL,
    attestation_blob_uri varchar(2000),
    attestation_sha256 char(64)
        CHECK (attestation_sha256 IS NULL OR attestation_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    approved_at timestamptz
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_marketplace_order_release'
          AND conrelid = 'marketplace_orders'::regclass
    ) THEN
        ALTER TABLE marketplace_orders
            ADD CONSTRAINT fk_marketplace_order_release
            FOREIGN KEY ("ReleaseId")
            REFERENCES marketplace.strategy_release (id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS entitlements."grant" (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES profiles ("Id"),
    catalog_item_id uuid NOT NULL REFERENCES catalog_items ("Id"),
    order_id uuid NOT NULL REFERENCES marketplace_orders ("Id"),
    grant_type varchar(40) NOT NULL
        CHECK (grant_type IN ('MarketplaceLicense', 'MarketplaceSubscription')),
    status varchar(32) NOT NULL CHECK (status IN ('Active', 'Revoked', 'Expired')),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz,
    updated_at timestamptz NOT NULL,
    CHECK (valid_until > valid_from)
);

CREATE TABLE IF NOT EXISTS marketplace.license (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES profiles ("Id"),
    release_id uuid NOT NULL REFERENCES marketplace.strategy_release (id),
    grant_id uuid NOT NULL REFERENCES entitlements."grant" (id),
    status varchar(32) NOT NULL CHECK (status IN ('Active', 'Revoked')),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (valid_until > valid_from)
);

CREATE TABLE IF NOT EXISTS marketplace.signal_session (
    id uuid PRIMARY KEY,
    license_id uuid NOT NULL REFERENCES marketplace.license (id),
    account_id uuid NOT NULL REFERENCES profiles ("Id"),
    device_id uuid NOT NULL,
    release_id uuid NOT NULL REFERENCES marketplace.strategy_release (id),
    started_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    ended_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (account_id, device_id)
        REFERENCES registered_devices ("AccountId", "DeviceId")
);

CREATE TABLE IF NOT EXISTS entitlements.content_key (
    content_key_id varchar(128) PRIMARY KEY
        CHECK (content_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    release_id uuid NOT NULL REFERENCES marketplace.strategy_release (id),
    kms_wrapped_key bytea NOT NULL,
    alg varchar(32) NOT NULL CHECK (alg = 'A256KW'),
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_strategy_release_content_key'
          AND conrelid = 'marketplace.strategy_release'::regclass
    ) THEN
        ALTER TABLE marketplace.strategy_release
            ADD CONSTRAINT fk_strategy_release_content_key
            FOREIGN KEY (content_key_id)
            REFERENCES entitlements.content_key (content_key_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS marketplace.content_key_release (
    id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL UNIQUE,
    license_id uuid NOT NULL REFERENCES marketplace.license (id),
    account_id uuid NOT NULL REFERENCES profiles ("Id"),
    device_id uuid NOT NULL,
    release_id uuid NOT NULL REFERENCES marketplace.strategy_release (id),
    released_at timestamptz NOT NULL DEFAULT now(),
    session_pubkey_sha256 char(64) NOT NULL
        CHECK (session_pubkey_sha256 ~ '^[0-9a-f]{64}$'),
    ttl_seconds integer NOT NULL CHECK (ttl_seconds > 0)
);

CREATE TABLE IF NOT EXISTS entitlements.revocation (
    seq bigserial PRIMARY KEY,
    target_type text NOT NULL
        CHECK (target_type IN ('account', 'license', 'release', 'content_root', 'publisher_key')),
    target_id varchar(200) NOT NULL,
    reason varchar(500) NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS entitlements.device_proof_challenge (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES profiles ("Id"),
    license_id uuid NOT NULL REFERENCES marketplace.license (id),
    release_id uuid NOT NULL REFERENCES marketplace.strategy_release (id),
    device_id uuid NOT NULL,
    operation varchar(32) NOT NULL
        CHECK (operation IN ('content_key', 'heartbeat', 'download_grant', 'signal_session')),
    binding_sha256 char(64) NOT NULL,
    nonce varchar(100) NOT NULL,
    idempotency_key varchar(100) NOT NULL,
    request_sha256 char(64) NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    response_json text,
    version bigint NOT NULL DEFAULT 0,
    UNIQUE (account_id, operation, idempotency_key)
);

DO $$
DECLARE
    constraint_name text;
BEGIN
    FOR constraint_name IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'entitlements.device_proof_challenge'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) LIKE '%operation%'
    LOOP
        EXECUTE format(
            'ALTER TABLE entitlements.device_proof_challenge DROP CONSTRAINT %I',
            constraint_name);
    END LOOP;

    ALTER TABLE entitlements.device_proof_challenge
        ADD CONSTRAINT ck_device_proof_challenge_operation
        CHECK (operation IN (
            'content_key', 'heartbeat', 'download_grant', 'signal_session'));
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_content_key_release_challenge'
          AND conrelid = 'marketplace.content_key_release'::regclass
    ) THEN
        ALTER TABLE marketplace.content_key_release
            ADD CONSTRAINT fk_content_key_release_challenge
            FOREIGN KEY (challenge_id)
            REFERENCES entitlements.device_proof_challenge (id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS vibe_quant_credit_wallets (
    "AccountId" uuid PRIMARY KEY REFERENCES profiles ("Id"),
    "AvailableCredits" bigint NOT NULL CHECK ("AvailableCredits" >= 0),
    "ReservedCredits" bigint NOT NULL CHECK ("ReservedCredits" >= 0),
    "ConsumedCredits" bigint NOT NULL CHECK ("ConsumedCredits" >= 0),
    "UpdatedAt" timestamptz NOT NULL,
    "Version" bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS vibe_quant_runs (
    "Id" uuid PRIMARY KEY,
    "AccountId" uuid NOT NULL REFERENCES profiles ("Id"),
    "IdempotencyKey" varchar(100) NOT NULL,
    "RequestSha256" char(64) NOT NULL,
    "SpecSha256" char(64) NOT NULL,
    "SpecJson" text NOT NULL,
    "ExecutionSpecJson" text NOT NULL,
    "ExecutionSpecSha256" char(64) NOT NULL,
    "ExecutionProfileBinding" char(64) NOT NULL,
    "ExecutionBindingNonce" varchar(64) NOT NULL,
    "Status" varchar(40) NOT NULL,
    "UsageJson" text NOT NULL,
    "CompletedRoleCount" integer NOT NULL,
    "ReservedCredits" bigint NOT NULL CHECK ("ReservedCredits" >= 0),
    "ChargedCredits" bigint NOT NULL CHECK ("ChargedCredits" >= 0),
    "CreditRatePerUsd" bigint NOT NULL CHECK ("CreditRatePerUsd" > 0),
    "MinimumChargeCredits" bigint NOT NULL CHECK ("MinimumChargeCredits" >= 0),
    "BillableCostUsd" numeric(18,8) NOT NULL CHECK ("BillableCostUsd" >= 0),
    "CreditsSettled" boolean NOT NULL,
    "CancellationRequested" boolean NOT NULL,
    "CancellationRequestedAt" timestamptz,
    "WorkerLeaseId" uuid,
    "WorkerLeaseExpiresAt" timestamptz,
    "WorkerLeaseDurationSeconds" integer NOT NULL CHECK ("WorkerLeaseDurationSeconds" > 0),
    "ExecutionAttempt" integer NOT NULL CHECK ("ExecutionAttempt" >= 0),
    "FinalArtifactSha256" char(64),
    "SafeMessage" varchar(1000),
    "CreatedAt" timestamptz NOT NULL,
    "UpdatedAt" timestamptz NOT NULL,
    "Version" bigint NOT NULL,
    UNIQUE ("AccountId", "IdempotencyKey")
);

CREATE TABLE IF NOT EXISTS vibe_quant_credit_ledger (
    "Id" uuid PRIMARY KEY,
    "AccountId" uuid NOT NULL REFERENCES profiles ("Id"),
    "RunId" uuid REFERENCES vibe_quant_runs ("Id"),
    "Kind" varchar(32) NOT NULL,
    "AvailableDelta" bigint NOT NULL,
    "ReservedDelta" bigint NOT NULL,
    "ConsumedDelta" bigint NOT NULL,
    "AvailableAfter" bigint NOT NULL CHECK ("AvailableAfter" >= 0),
    "ReservedAfter" bigint NOT NULL CHECK ("ReservedAfter" >= 0),
    "ConsumedAfter" bigint NOT NULL CHECK ("ConsumedAfter" >= 0),
    "IdempotencyKey" varchar(160) NOT NULL,
    "Reference" varchar(500) NOT NULL,
    "PricingVersion" varchar(100) NOT NULL,
    "CreatedAt" timestamptz NOT NULL,
    UNIQUE ("AccountId", "IdempotencyKey")
);

CREATE INDEX IF NOT EXISTS ix_orders_buyer ON marketplace_orders ("BuyerAccountId");
CREATE UNIQUE INDEX IF NOT EXISTS ux_orders_provider_checkout
    ON marketplace_orders ("ProviderCheckoutId");
CREATE INDEX IF NOT EXISTS ix_orders_provider_subscription
    ON marketplace_orders ("ProviderSubscriptionId");
CREATE INDEX IF NOT EXISTS ix_reviews_catalog ON marketplace_reviews ("CatalogItemId");
CREATE INDEX IF NOT EXISTS ix_submissions_publisher ON marketplace_submissions ("PublisherAccountId");
CREATE INDEX IF NOT EXISTS ix_submissions_source_sha256
    ON marketplace_submissions ("SourceSha256");
CREATE INDEX IF NOT EXISTS ix_submissions_diversification_seed_sha256
    ON marketplace_submissions ("DiversificationSeedSha256");
CREATE UNIQUE INDEX IF NOT EXISTS ux_submissions_release_id
    ON marketplace_submissions ("ReleaseId");
CREATE INDEX IF NOT EXISTS ix_devices_account_revoked
    ON registered_devices ("AccountId", "RevokedAt");
CREATE UNIQUE INDEX IF NOT EXISTS ux_marketplace_publisher_connect_account
    ON marketplace.publisher (connect_account_id);
CREATE INDEX IF NOT EXISTS ix_strategy_release_catalog_created
    ON marketplace.strategy_release (catalog_item_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS ux_strategy_release_catalog_version
    ON marketplace.strategy_release (catalog_item_id, version);
CREATE UNIQUE INDEX IF NOT EXISTS ux_strategy_release_submission
    ON marketplace.strategy_release (submission_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_strategy_release_diversification_seed
    ON marketplace.strategy_release (diversification_seed_sha256);
CREATE UNIQUE INDEX IF NOT EXISTS ux_entitlement_grant_order
    ON entitlements."grant" (order_id);
CREATE INDEX IF NOT EXISTS ix_entitlement_grant_account_catalog
    ON entitlements."grant" (account_id, catalog_item_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_marketplace_license_account_release
    ON marketplace.license (account_id, release_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_marketplace_license_grant
    ON marketplace.license (grant_id);
CREATE INDEX IF NOT EXISTS ix_content_key_release_license_released
    ON marketplace.content_key_release (license_id, released_at);
CREATE INDEX IF NOT EXISTS ix_signal_session_license_ended
    ON marketplace.signal_session (license_id, ended_at);
CREATE INDEX IF NOT EXISTS ix_signal_session_device_ended
    ON marketplace.signal_session (account_id, device_id, ended_at);
CREATE INDEX IF NOT EXISTS ix_revocation_target
    ON entitlements.revocation (target_type, target_id);
CREATE INDEX IF NOT EXISTS ix_device_proof_challenge_expires
    ON entitlements.device_proof_challenge (expires_at);
CREATE INDEX IF NOT EXISTS ix_vibe_quant_runs_account_updated
    ON vibe_quant_runs ("AccountId", "UpdatedAt");
CREATE INDEX IF NOT EXISTS ix_vibe_quant_runs_status_created
    ON vibe_quant_runs ("Status", "CreatedAt");
CREATE INDEX IF NOT EXISTS ix_vibe_quant_runs_status_lease
    ON vibe_quant_runs ("Status", "WorkerLeaseExpiresAt");
CREATE INDEX IF NOT EXISTS ix_vibe_quant_credit_ledger_account_created
    ON vibe_quant_credit_ledger ("AccountId", "CreatedAt");
