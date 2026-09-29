-- Subdomain awareness.
--
-- `staging.example.com` is a site of its own -- its own runner, often its own
-- organization -- but it is issued and renewed under `example.com`'s
-- wildcard. Until now it was folded into the parent's record as one more
-- name, which is why it could never be listed, assigned or attached on its
-- own.
--
-- The link is a plain self-reference. NULL means a top-level unit (an apex,
-- or a customer's own subdomain on a shared zone); a value means "this host
-- is covered by that domain's certificate".
ALTER TABLE domains
  ADD COLUMN parent_id BIGINT UNSIGNED NULL DEFAULT NULL,
  ADD KEY domains_parent (parent_id);
