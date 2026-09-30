-- Tracking for vhosts applied through the freeform escape hatch
-- (ValidateFreeformVhost / ApplyFreeformVhost), for a config the structured
-- Backend + extras shape in vhost::render cannot express.
--
-- Kept separate from `vhosts` rather than adding a third `origin` value:
-- `vhosts.origin` ('adopted' vs 'generated') already carries different
-- lifecycle semantics per value, and a freeform submission is neither -- it
-- is ours to update again (unlike 'adopted'), but never ours to silently
-- regenerate from a template (unlike 'generated'). One row per domain: a
-- second ApplyFreeformVhost on the same domain updates this row in place,
-- the same way the file itself is updated in place.
CREATE TABLE IF NOT EXISTS freeform_vhosts (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id    BIGINT UNSIGNED NOT NULL,
  -- Path relative to the tree root, matching `vhosts.source_path`'s shape.
  source_path  VARCHAR(512) NOT NULL,
  -- The exact text last applied (before the applied-header stamp), so a
  -- later re-validate/re-apply can diff against what is actually on disk
  -- and a hand edit after the fact shows up as drift.
  body         MEDIUMTEXT NOT NULL,
  sha256       CHAR(64) NOT NULL,
  applied_by   VARCHAR(64) NULL DEFAULT NULL,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY freeform_vhosts_domain (domain_id),
  CONSTRAINT freeform_vhosts_domain_fk FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
