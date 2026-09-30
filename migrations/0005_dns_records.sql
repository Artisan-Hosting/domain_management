-- Caller-facing DNS record CRUD (ListDnsRecords / CreateDnsRecord /
-- UpdateDnsRecord / DeleteDnsRecord), scoped to one owned domain.
--
-- Deliberately separate from `managed_dns_records`: that table is this
-- service's own edge/challenge bookkeeping with a fixed purpose enum and
-- automatic reconciliation, while this one is an index of records a caller
-- asked us to create on their behalf, so ownership ("this row belongs to
-- this domain") is enforced locally. Cloudflare stays authoritative for the
-- record's actual content -- this table exists so ListDnsRecords does not
-- have to hit Cloudflare on every call, and so a delete can be scoped to a
-- domain without trusting a bare Cloudflare record id from the wire.
CREATE TABLE IF NOT EXISTS domain_dns_records (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id    BIGINT UNSIGNED NOT NULL,
  cf_record_id VARCHAR(64) NOT NULL,
  record_type  VARCHAR(16) NOT NULL,
  name         VARCHAR(253) NOT NULL,
  content      VARCHAR(512) NOT NULL,
  ttl          INT UNSIGNED NOT NULL DEFAULT 1,
  proxied      TINYINT(1) NOT NULL DEFAULT 0,
  created_by   VARCHAR(64) NULL DEFAULT NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY domain_dns_records_cf (domain_id, cf_record_id),
  KEY domain_dns_records_domain (domain_id),
  CONSTRAINT domain_dns_records_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
