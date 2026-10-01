-- Names nobody may claim on the free zone (see src/reserved.rs).
--
-- Edited by a Super through the API, never by customers. One row per rule; `kind` picks which of the
-- other columns mean anything:
--   exact  -> `prefix` holds the whole label
--   prefix -> `prefix` holds the start of the label
--   range  -> `prefix`, then `digits` ASCII digits whose value is min_value..=max_value
-- The first row an operator adds is the customer-id range:
--   INSERT INTO reserved_names (kind, prefix, digits, min_value, max_value, note)
--   VALUES ('range', 'c', 8, 0, 99999999, 'customer ids: c00000000-c99999999');
-- Apply by hand, like every migration here.
CREATE TABLE reserved_names (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  kind        ENUM('exact', 'prefix', 'range') NOT NULL,
  prefix      VARCHAR(63) NOT NULL,
  -- 0 and 0 for the kinds that do not use them, so the unique key below also catches a duplicate exact/prefix
  digits      TINYINT UNSIGNED NOT NULL DEFAULT 0,
  min_value   BIGINT UNSIGNED NOT NULL DEFAULT 0,
  max_value   BIGINT UNSIGNED NOT NULL DEFAULT 0,
  note        VARCHAR(255) NOT NULL DEFAULT '',
  created_by  VARCHAR(64) NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- the same rule twice only hides which row to delete
  UNIQUE KEY reserved_names_rule (kind, prefix, digits, min_value, max_value),
  CHECK ((kind <> 'range') OR (digits BETWEEN 1 AND 18 AND min_value <= max_value))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
