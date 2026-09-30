-- BYO ownership proof (Phase 7's `AddDomain`/`VerifyDomainNow`): a domain a
-- customer claims to own is not accepted until they prove it by creating a
-- `_ais-domains-verify.<fqdn>` TXT record carrying this token. Purchased and
-- imported domains never set these -- ownership isn't in question for a
-- domain we bought or one that was already in domains.txt.
ALTER TABLE domains
  ADD COLUMN ownership_token    VARCHAR(64) NULL DEFAULT NULL,
  ADD COLUMN ownership_verified TINYINT(1)  NOT NULL DEFAULT 0;
