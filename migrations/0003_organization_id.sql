-- Resource taxonomy: rename org_id -> organization_id everywhere it appears.
--
-- Pure renames (RENAME COLUMN preserves type/nullability/default), applied
-- automatically via sqlx::migrate! like 0001/0002 -- no idempotency guards
-- needed here, sqlx tracks which migrations have already run.
--
-- Note for the coordinated rollout: existing rows carry ais_auth's OLD
-- org_id values (a stringified bigint, e.g. "42"). ais_auth's own contract
-- migration (see ais_auth/migrations_manual/0004_org_uuid_contract.sql)
-- replaces those with real UUIDs -- this service's `organization_id` column
-- is just along for the ride and does not, by itself, remap old values to
-- the new UUIDs. Any domain/order/quote row assigned to an organization
-- before that cutover will need its organization_id backfilled against
-- ais_auth's org_id -> organization_id mapping as a separate, explicit step;
-- this migration only renames the column, it does not attempt that
-- cross-service backfill.
ALTER TABLE domains RENAME COLUMN org_id TO organization_id;
ALTER TABLE domain_quotes RENAME COLUMN org_id TO organization_id;
ALTER TABLE domain_orders RENAME COLUMN org_id TO organization_id;
ALTER TABLE audit_log RENAME COLUMN org_id TO organization_id;
