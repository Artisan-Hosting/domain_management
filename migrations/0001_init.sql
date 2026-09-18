-- ais_domains initial schema.
--
-- Unlike ais_auth (whose migrations/ are applied by hand), this service runs
-- its own migrations through `sqlx::migrate!` at startup, so this file is
-- applied automatically and must stay idempotent-safe under re-runs of the
-- whole directory.
--
-- Money is stored in minor units (cents) as BIGINT. No floats anywhere near
-- a charge. `cost` is what Cloudflare bills us, `price` is what the customer
-- pays; both are frozen on the order at quote time.

CREATE TABLE IF NOT EXISTS domains (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  fqdn             VARCHAR(253)    NOT NULL,
  org_id           VARCHAR(64)     NOT NULL,
  runner_id        VARCHAR(64)     NULL,
  -- purchased: bought through us and living in our Cloudflare account.
  -- byo:       customer's registrar, they point records at us.
  -- imported:  was a line in /etc/acme-sh/domains.txt before this service.
  source           ENUM('purchased','byo','imported') NOT NULL,
  status           VARCHAR(32)     NOT NULL,
  cf_zone_id       VARCHAR(64)     NULL,
  -- Where _acme-challenge.<fqdn> must CNAME to. Purchased/BYO domains get a
  -- per-domain target so concurrent issuances cannot stack TXT records on
  -- one name; imported domains keep the shared _acme-challenge.<alias zone>
  -- the acme.sh script used, and issuance through it is serialized.
  challenge_target VARCHAR(253)    NOT NULL,
  expires_at       TIMESTAMP       NULL DEFAULT NULL,
  auto_renew       TINYINT(1)      NOT NULL DEFAULT 1,
  last_error       TEXT            NULL,
  created_by       VARCHAR(64)     NULL,
  created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY domains_fqdn (fqdn),
  KEY domains_org (org_id),
  KEY domains_runner (runner_id),
  KEY domains_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- A quote is a price we are willing to honour for a few minutes. CreateOrder
-- reads it, and the register job re-checks the live price anyway before
-- spending anything.
CREATE TABLE IF NOT EXISTS domain_quotes (
  id               CHAR(36)        NOT NULL PRIMARY KEY,
  fqdn             VARCHAR(253)    NOT NULL,
  org_id           VARCHAR(64)     NOT NULL,
  user_id          VARCHAR(64)     NOT NULL,
  cost_cents       BIGINT          NOT NULL,
  price_cents      BIGINT          NOT NULL,
  currency         CHAR(3)         NOT NULL,
  tier             VARCHAR(32)     NOT NULL,
  created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at       TIMESTAMP       NOT NULL,
  KEY domain_quotes_fqdn (fqdn),
  KEY domain_quotes_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS domain_orders (
  id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  fqdn                     VARCHAR(253)    NOT NULL,
  org_id                   VARCHAR(64)     NOT NULL,
  user_id                  VARCHAR(64)     NOT NULL,
  quote_id                 CHAR(36)        NULL,
  cost_cents               BIGINT          NOT NULL,
  price_cents              BIGINT          NOT NULL,
  currency                 CHAR(3)         NOT NULL,
  state                    VARCHAR(32)     NOT NULL,
  cf_workflow_state        VARCHAR(32)     NULL,
  -- UNIQUE: one order per PaymentIntent, so a webhook Stripe delivers twice
  -- (which it will) cannot produce two registrations.
  stripe_payment_intent_id VARCHAR(128)    NULL,
  stripe_refund_id         VARCHAR(128)    NULL,
  domain_id                BIGINT UNSIGNED NULL,
  runner_id                VARCHAR(64)     NULL,
  invite_email             VARCHAR(255)    NULL,
  last_error               TEXT            NULL,
  created_at               TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at               TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY domain_orders_pi (stripe_payment_intent_id),
  KEY domain_orders_org (org_id),
  KEY domain_orders_state (state),
  KEY domain_orders_fqdn (fqdn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The records this service owns. Anything not listed here is the customer's
-- business; the reconcile job only compares these.
CREATE TABLE IF NOT EXISTS managed_dns_records (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id    BIGINT UNSIGNED NOT NULL,
  purpose      ENUM('edge_a','edge_aaaa','www','acme_alias') NOT NULL,
  record_type  VARCHAR(16)     NOT NULL,
  name         VARCHAR(253)    NOT NULL,
  content      VARCHAR(512)    NOT NULL,
  cf_record_id VARCHAR(64)     NULL,
  drifted      TINYINT(1)      NOT NULL DEFAULT 0,
  checked_at   TIMESTAMP       NULL DEFAULT NULL,
  created_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY managed_dns_unique (domain_id, purpose, name, content(191)),
  KEY managed_dns_domain (domain_id),
  CONSTRAINT managed_dns_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS certificates (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id   BIGINT UNSIGNED NOT NULL,
  key_type    ENUM('ecc','rsa') NOT NULL,
  serial      VARCHAR(128)    NULL,
  not_before  TIMESTAMP       NULL DEFAULT NULL,
  not_after   TIMESTAMP       NULL DEFAULT NULL,
  renew_after TIMESTAMP       NULL DEFAULT NULL,
  fail_count  INT             NOT NULL DEFAULT 0,
  last_error  TEXT            NULL,
  issued_at   TIMESTAMP       NULL DEFAULT NULL,
  updated_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY certificates_domain_key (domain_id, key_type),
  KEY certificates_renew (renew_after),
  CONSTRAINT certificates_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhosts (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id      BIGINT UNSIGNED NOT NULL,
  runner_id      VARCHAR(64)     NOT NULL,
  template       VARCHAR(128)    NOT NULL,
  rendered_sha256 CHAR(64)       NULL,
  file_path      VARCHAR(512)    NOT NULL,
  enabled        TINYINT(1)      NOT NULL DEFAULT 1,
  updated_at     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY vhosts_domain (domain_id),
  CONSTRAINT vhosts_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Cloudflare account invites, each scoped to a single zone. A member here can
-- edit that zone's DNS and nothing else -- no registrar, no transfers, no
-- billing (those roles are account-wide and we never grant them).
CREATE TABLE IF NOT EXISTS domain_members (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id    BIGINT UNSIGNED NOT NULL,
  email        VARCHAR(255)    NOT NULL,
  cf_member_id VARCHAR(64)     NULL,
  role         VARCHAR(64)     NOT NULL,
  status       ENUM('pending','accepted','removed') NOT NULL DEFAULT 'pending',
  invited_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY domain_members_unique (domain_id, email),
  CONSTRAINT domain_members_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Durable work queue. Claimed with SELECT ... FOR UPDATE SKIP LOCKED so more
-- than one worker (or a restarted process) cannot run the same job twice --
-- which matters most for `register`, where a double run means a double charge.
CREATE TABLE IF NOT EXISTS jobs (
  id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  kind          VARCHAR(48)     NOT NULL,
  domain_id     BIGINT UNSIGNED NULL,
  order_id      BIGINT UNSIGNED NULL,
  payload       JSON            NULL,
  state         VARCHAR(24)     NOT NULL DEFAULT 'queued',
  attempts      INT             NOT NULL DEFAULT 0,
  next_run_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  locked_by     VARCHAR(64)     NULL,
  locked_until  TIMESTAMP       NULL DEFAULT NULL,
  last_error    TEXT            NULL,
  created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  -- At most one *live* job of a kind per domain/order, so a retry storm
  -- cannot queue fifty issuances for the same name. The key is NULL once a
  -- job reaches a terminal state, and MySQL does not collide NULLs in a
  -- unique index -- which is what lets the history pile up freely while
  -- still blocking a second queued/running twin.
  dedupe_key    VARCHAR(160) GENERATED ALWAYS AS (
                  IF(state IN ('queued','running'),
                     CONCAT(kind, ':', IFNULL(domain_id, 0), ':', IFNULL(order_id, 0)),
                     NULL)
                ) STORED,
  KEY jobs_claim (state, next_run_at),
  KEY jobs_domain (domain_id),
  KEY jobs_order (order_id),
  UNIQUE KEY jobs_dedupe (dedupe_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS releases (
  release_id      VARCHAR(64) NOT NULL PRIMARY KEY,
  file_count      INT         NOT NULL DEFAULT 0,
  manifest_sha256 CHAR(64)    NULL,
  status          VARCHAR(24) NOT NULL,
  last_error      TEXT        NULL,
  created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_log (
  id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  actor     VARCHAR(128)    NOT NULL,
  org_id    VARCHAR(64)     NULL,
  action    VARCHAR(64)     NOT NULL,
  target    VARCHAR(253)    NULL,
  detail    JSON            NULL,
  at        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY audit_log_actor (actor),
  KEY audit_log_action (action),
  KEY audit_log_at (at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
