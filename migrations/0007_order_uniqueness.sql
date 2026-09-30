-- One order per quote, and one live order per name.
--
-- Until now two submits of the same quote (a double click, a retried request)
-- each created an order and each created a PaymentIntent, and nothing stopped
-- two customers ordering the same name at once. `create_order` turns a
-- duplicate-key error on either index into "return the order that already
-- exists" (same quote) or "already being bought" (same name).
--
-- `live_fqdn` is NULL once an order is failed or refunded, so a name whose
-- purchase fell through can be ordered again; MySQL does not collide NULLs in
-- a unique index (the same trick `jobs.dedupe_key` uses). A `completed` order
-- keeps holding its name, which also keeps an already-bought domain from
-- being bought twice. Apply by hand, like every migration here; it fails if
-- existing rows already violate either key, which is worth knowing before
-- going live.
ALTER TABLE domain_orders
  ADD COLUMN live_fqdn VARCHAR(253)
    GENERATED ALWAYS AS (IF(state IN ('failed', 'refunded'), NULL, fqdn)) STORED,
  ADD UNIQUE KEY domain_orders_quote (quote_id),
  ADD UNIQUE KEY domain_orders_live_fqdn (live_fqdn);
