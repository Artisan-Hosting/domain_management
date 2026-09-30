//! The freeform escape hatch: raw nginx text in, validated and mechanically
//! normalized, staged and `nginx -t`'d, and only then applied.
//!
//! For a config the structured [`super::render::VhostSpec`] (plus its
//! extras) cannot express -- arbitrary directives, third-party modules,
//! anything genuinely bespoke. `nginx -t` against a staged copy is the only
//! authority on validity; the lint pass below only adds cross-tree checks
//! `nginx -t` cannot make (a `server_name` collision elsewhere in the tree,
//! say), and the correction pass only ever makes purely mechanical,
//! non-semantic changes -- never anything that could reorder or change what
//! a directive does. Anything beyond that mechanical scope stays a reported
//! finding for the caller (or a future AI-assisted corrector) to resolve.
//!
//! Applying stamps [`crate::inventory::nginx::FREEFORM_MANAGED_HEADER`]
//! rather than [`crate::inventory::nginx::MANAGED_HEADER`]: this service
//! "owns" the file in the sense that calling `apply` again on the same
//! domain updates it in place, but the structured [`super::render::write`]
//! path must never touch it, exactly like a genuinely hand-written file.
//!
//! Both [`validate`] and [`apply`] run entirely inline in the gRPC handler
//! (subsystem 2 of the three described in the crate root doc) -- there is
//! no job here, and there shouldn't be one. The work is local filesystem
//! plus one `nginx -t` subprocess call, sub-second, and idempotent by
//! construction: a failed `apply` leaves nothing behind for a retry to
//! trip over. That is the same "can this be retried for free" test
//! [`crate::grpc::service`]'s module doc uses to decide what belongs in the
//! future async job worker (subsystem 3) instead -- a domain purchase
//! fails that test, this module passes it easily.

use std::path::{Path, PathBuf};

use crate::config::{Config, snippet_slug};
use crate::error::{Error, Result};
use crate::inventory::model::{Finding, Severity};
use crate::inventory::nginx::FREEFORM_MANAGED_HEADER;
use crate::inventory::{certs, domains_txt, model, nginx};
use crate::publish::stage::{self, Stage};

use super::render::write_atomic;

#[derive(Debug, Clone)]
pub struct LintFinding {
    pub code: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ValidateOutcome {
    pub nginx_ok: bool,
    pub nginx_output: String,
    pub new_findings: Vec<LintFinding>,
    /// The mechanically-normalized text, or empty if normalization changed
    /// nothing.
    pub corrected: String,
}

#[derive(Debug, Clone)]
pub struct ApplyOutcome {
    pub applied: bool,
    pub diff: String,
    /// The exact text written (post-normalization) -- what the caller
    /// should persist alongside the domain for drift tracking.
    pub body: String,
    pub validation: ValidateOutcome,
}

/// Validates `server_block` for `fqdn`: stages a copy of the live tree,
/// writes the (mechanically-normalized) submission into it, and runs
/// `nginx -t`. Never touches the live tree.
pub async fn validate(config: &Config, fqdn: &str, server_block: &str) -> Result<ValidateOutcome> {
    let stage = Stage::create(config, &format!("freeform-{}", snippet_slug(fqdn)))?;
    let before = scan_findings(config, &stage.tree)?;

    let normalized = normalize(config, fqdn, server_block);
    let corrected = if normalized == server_block { String::new() } else { normalized.clone() };
    let final_text = if corrected.is_empty() { server_block.to_owned() } else { normalized };

    let target = staged_path(config, &stage, fqdn);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Io(std::io::Error::other(format!("creating {}: {e}", parent.display()))))?;
    }
    std::fs::write(&target, &final_text)
        .map_err(|e| Error::Io(std::io::Error::other(format!("writing {}: {e}", target.display()))))?;

    let (nginx_ok, nginx_output) = match stage::nginx_test(config, &stage).await {
        Ok(()) => (true, String::new()),
        Err(err) => (false, err.to_string()),
    };

    // A lint diff on top of an already-invalid config is noise -- nginx -t
    // failing is the thing to fix first.
    let new_findings = if nginx_ok {
        let after = scan_findings(config, &stage.tree)?;
        diff_findings(&before, &after)
    } else {
        Vec::new()
    };

    Ok(ValidateOutcome { nginx_ok, nginx_output, new_findings, corrected })
}

/// Validates, then -- if valid and not a dry run -- writes into the live
/// tree, stamped with [`FREEFORM_MANAGED_HEADER`]. Re-applying to the same
/// domain updates the file in place.
pub async fn apply(config: &Config, fqdn: &str, server_block: &str, dry_run: bool) -> Result<ApplyOutcome> {
    let validation = validate(config, fqdn, server_block).await?;
    if !validation.nginx_ok {
        return Err(Error::Invalid(format!(
            "{fqdn}: nginx rejected the freeform config:\n{}",
            validation.nginx_output
        )));
    }

    let body = if validation.corrected.is_empty() { server_block.to_owned() } else { validation.corrected.clone() };

    if dry_run {
        return Ok(ApplyOutcome { applied: false, diff: String::new(), body, validation });
    }

    let path = config.vhost_path_for(fqdn);
    let previous = std::fs::read_to_string(&path).ok();
    let stamped = format!("# {FREEFORM_MANAGED_HEADER} -- {fqdn}, applied via ApplyFreeformVhost\n{body}");

    write_atomic(&path, &stamped)?;

    let diff = match &previous {
        Some(prev) if prev != &stamped => unified_diff(prev, &stamped),
        _ => String::new(),
    };

    Ok(ApplyOutcome { applied: true, diff, body, validation })
}

fn staged_path(config: &Config, stage: &Stage, fqdn: &str) -> PathBuf {
    stage.tree.join(&config.tree.sites_dir).join(snippet_slug(fqdn))
}

fn scan_findings(config: &Config, tree_root: &Path) -> Result<Vec<Finding>> {
    let nginx_index = nginx::scan_tree(tree_root, &config.tree.snippets_dir)?;
    let cert_dirs = certs::scan(&tree_root.join(&config.tree.certs_dir))?;
    // No domains.txt entry is relevant to a freeform lint diff -- a
    // nonexistent path scans as empty rather than erroring.
    let domain_list = domains_txt::scan(Path::new("/nonexistent/ais-domains-freeform-lint"))?;

    let inventory = model::build(
        tree_root,
        &config.tree.certs_dir,
        nginx_index,
        cert_dirs,
        domain_list,
        chrono::Utc::now().timestamp(),
        config.acme.renew_before_days,
    );

    Ok(inventory.findings)
}

/// Findings present after the submission that were not present before it.
fn diff_findings(before: &[Finding], after: &[Finding]) -> Vec<LintFinding> {
    let seen: std::collections::BTreeSet<(&'static str, &str)> =
        before.iter().map(|f| (f.code.as_str(), f.subject.as_str())).collect();

    after
        .iter()
        .filter(|f| !seen.contains(&(f.code.as_str(), f.subject.as_str())))
        .map(|f| LintFinding {
            code: f.code.as_str().to_owned(),
            severity: match f.severity {
                Severity::Info => "info",
                Severity::Warn => "warn",
                Severity::Error => "error",
            }
            .to_owned(),
            message: f.message.clone(),
        })
        .collect()
}

/// Mechanical, non-semantic normalization only: fixing a mismatched
/// cert-snippet include slug (this service is the authority on what it
/// should be), re-indenting by brace depth, and appending an obviously
/// missing trailing semicolon. Never touches brace balance or anything that
/// could reorder or change what a directive does -- that stays a reported
/// finding, not an auto-fix.
fn normalize(config: &Config, fqdn: &str, text: &str) -> String {
    let slug_fixed = fix_snippet_include(config, fqdn, text);
    reindent_and_terminate(&slug_fixed)
}

fn fix_snippet_include(config: &Config, fqdn: &str, text: &str) -> String {
    let snippets_dir = &config.tree.snippets_dir;
    let correct_slug = snippet_slug(fqdn);
    let prefix = format!("{snippets_dir}/");
    const SUFFIX: &str = "_cert.conf;";

    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let indent = &line[..line.len() - trimmed.len()];
            if let Some(rest) = trimmed.strip_prefix("include ") {
                let rest = rest.trim_end();
                if let Some(name) = rest.strip_prefix(prefix.as_str()).and_then(|s| s.strip_suffix(SUFFIX)) {
                    if name != correct_slug {
                        return format!("{indent}include {prefix}{correct_slug}{SUFFIX}");
                    }
                }
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Re-indents by brace depth (four spaces per level) and appends a trailing
/// semicolon to a line that plainly needs one. Skips any line containing
/// `#`, since a trailing comment makes "does this line need a semicolon"
/// ambiguous without a real parser -- safer to leave those alone.
fn reindent_and_terminate(text: &str) -> String {
    let mut out = String::new();
    let mut depth: i32 = 0;

    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            out.push('\n');
            continue;
        }

        let this_depth = if trimmed.starts_with('}') { (depth - 1).max(0) } else { depth };
        let indent = "    ".repeat(this_depth as usize);

        let needs_semicolon = !trimmed.contains('#')
            && !trimmed.ends_with('{')
            && !trimmed.ends_with('}')
            && !trimmed.ends_with(';');

        if needs_semicolon {
            out.push_str(&format!("{indent}{trimmed};\n"));
        } else {
            out.push_str(&format!("{indent}{trimmed}\n"));
        }

        let opens = trimmed.matches('{').count() as i32;
        let closes = trimmed.matches('}').count() as i32;
        depth = (depth + opens - closes).max(0);
    }

    out
}

/// A minimal LCS-based unified-style diff: `-` for a removed line, `+` for
/// an added one, unmarked for context. Good enough for a vhost-sized file;
/// not meant as a general-purpose diff utility.
fn unified_diff(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let (n, m) = (old_lines.len(), new_lines.len());

    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old_lines[i] == new_lines[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if old_lines[i] == new_lines[j] {
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str(&format!("-{}\n", old_lines[i]));
            i += 1;
        } else {
            out.push_str(&format!("+{}\n", new_lines[j]));
            j += 1;
        }
    }
    while i < n {
        out.push_str(&format!("-{}\n", old_lines[i]));
        i += 1;
    }
    while j < m {
        out.push_str(&format!("+{}\n", new_lines[j]));
        j += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mismatched_snippet_slug_is_corrected() {
        let config = Config::default();
        let text = "server {\n    include snippets/wrongdomain_cert.conf;\n}";
        let fixed = fix_snippet_include(&config, "example.com", text);
        assert!(fixed.contains("include snippets/example_cert.conf;"), "{fixed}");
    }

    #[test]
    fn a_correct_snippet_slug_is_left_alone() {
        let config = Config::default();
        let text = "server {\n    include snippets/example_cert.conf;\n}";
        let fixed = fix_snippet_include(&config, "example.com", text);
        assert_eq!(fixed, text);
    }

    #[test]
    fn reindent_fixes_depth_and_adds_missing_semicolons() {
        let text = "server {\nlisten 443 ssl http2\nserver_name example.com;\n}";
        let out = reindent_and_terminate(text);
        assert_eq!(out, "server {\n    listen 443 ssl http2;\n    server_name example.com;\n}\n");
    }

    #[test]
    fn a_line_with_a_comment_is_never_auto_terminated() {
        let text = "server {\n    listen 443 # trailing comment, ambiguous\n}";
        let out = reindent_and_terminate(text);
        assert!(out.contains("listen 443 # trailing comment, ambiguous\n"), "{out}");
    }

    #[test]
    fn unified_diff_marks_only_the_changed_lines() {
        let old = "a\nb\nc\n";
        let new = "a\nx\nc\n";
        let diff = unified_diff(old, new);
        assert_eq!(diff, "-b\n+x\n");
    }
}
