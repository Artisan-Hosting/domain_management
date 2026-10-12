-- Kaelum tenants (served to Kaelum by the TenantSource gRPC service, see project_Kaelum/docs/06-TENANT-SOURCE-SPEC.md).
--
-- A tenant's hostnames are the domains rows that point at it via kaelum_endpoint_id, so they keep going through the
-- normal domain lifecycle. `suspension` is a manual override; when NULL the organization's Billing standing decides.
-- Apply by hand, like every migration here.
CREATE TABLE IF NOT EXISTS kaelum_tenants (
  endpoint_id     VARCHAR(64)  NOT NULL PRIMARY KEY,
  organization_id VARCHAR(64)  NOT NULL,
  project_id      VARCHAR(64)  NOT NULL,
  suspension      VARCHAR(255) NULL,
  created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY kaelum_tenants_org (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE domains
  ADD COLUMN kaelum_endpoint_id VARCHAR(64) NULL,
  ADD KEY domains_kaelum_endpoint (kaelum_endpoint_id);
