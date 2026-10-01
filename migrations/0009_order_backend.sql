-- Where a purchased domain's traffic should go once it is live.
--
-- An order may already name the app (`runner_id`) it is for. These two say which node and port that app
-- answers on, as the caller saw them when ordering, so the worker can attach the vhost the moment the
-- domain finishes instead of waiting for someone to come back and press a button. Both NULL means "record
-- the domain and stop", which is what every order did before. Apply by hand, like every migration here.
ALTER TABLE domain_orders
  ADD COLUMN backend_node_id VARCHAR(64) NULL AFTER runner_id,
  ADD COLUMN backend_port    INT UNSIGNED NULL AFTER backend_node_id;
