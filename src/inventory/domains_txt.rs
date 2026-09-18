//! Reading `/etc/acme-sh/domains.txt` exactly as the `certs` script read it.
//!
//! The rules are copied deliberately, down to the trimming: this file decided
//! what got renewed for years, so the inventory has to agree with production
//! about what was in it. A line this parser skips is a domain that was never
//! being renewed, and that is a finding, not a detail.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainsTxt {
    pub path: String,
    pub entries: Vec<DomainsTxtEntry>,
    /// Lines that are neither blank, a comment, nor a plausible hostname.
    /// They were silently fed to acme.sh before; here they are visible.
    pub unusable: Vec<UnusableLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainsTxtEntry {
    pub fqdn: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusableLine {
    pub line: usize,
    pub content: String,
    pub reason: String,
}

/// Parses the file. A missing file is empty, not an error: a system that
/// never had one is a perfectly good starting point.
pub fn scan(path: &Path) -> Result<DomainsTxt> {
    let mut out = DomainsTxt {
        path: path.to_string_lossy().into_owned(),
        entries: Vec::new(),
        unusable: Vec::new(),
    };

    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return Ok(out),
    };

    let mut seen = std::collections::HashSet::new();

    for (index, line) in raw.lines().enumerate() {
        let number = index + 1;
        // `sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'` from the script.
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let candidate = trimmed.to_ascii_lowercase();

        if let Some(reason) = implausible(&candidate) {
            out.unusable.push(UnusableLine {
                line: number,
                content: trimmed.to_owned(),
                reason: reason.to_owned(),
            });
            continue;
        }

        if !seen.insert(candidate.clone()) {
            out.unusable.push(UnusableLine {
                line: number,
                content: trimmed.to_owned(),
                reason: "duplicate of an earlier line".to_owned(),
            });
            continue;
        }

        out.entries.push(DomainsTxtEntry { fqdn: candidate, line: number });
    }

    Ok(out)
}

/// Rejects what could never have been a domain. Kept loose on purpose -- the
/// job is to catch stray shell fragments and notes, not to enforce a spec.
fn implausible(candidate: &str) -> Option<&'static str> {
    if candidate.contains(char::is_whitespace) {
        return Some("contains whitespace");
    }
    if !candidate.contains('.') {
        return Some("no dot, so not a fully qualified name");
    }
    if candidate.starts_with('*') {
        // The script issued `domain` + `*.domain` for every entry, so a
        // wildcard written out here was always redundant.
        return Some("wildcard entry: issuance already covers *.<domain>");
    }
    if candidate.starts_with('.') || candidate.ends_with('.') {
        return Some("leading or trailing dot");
    }
    if candidate.contains("://") || candidate.contains('/') {
        return Some("looks like a URL rather than a hostname");
    }
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Some("contains characters a hostname cannot");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> DomainsTxt {
        let path = std::env::temp_dir().join(format!(
            "ais_domains_txt_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, content).unwrap();
        let parsed = scan(&path).unwrap();
        std::fs::remove_file(&path).ok();
        parsed
    }

    #[test]
    fn reads_the_same_lines_the_script_did() {
        let parsed = parse("  example.com  \n\n# a comment\n\texample.net\n");

        let names: Vec<&str> = parsed.entries.iter().map(|e| e.fqdn.as_str()).collect();
        assert_eq!(names, vec!["example.com", "example.net"]);
        assert!(parsed.unusable.is_empty());
    }

    #[test]
    fn line_numbers_survive_so_findings_can_point_at_the_file() {
        let parsed = parse("# header\nexample.com\n\nexample.net\n");
        assert_eq!(parsed.entries[0].line, 2);
        assert_eq!(parsed.entries[1].line, 4);
    }

    #[test]
    fn junk_is_surfaced_rather_than_dropped() {
        let parsed = parse("example.com\nnot a domain\nhttps://example.org/path\nlocalhost\n*.example.dev\n");

        assert_eq!(parsed.entries.len(), 1);
        let reasons: Vec<&str> = parsed.unusable.iter().map(|u| u.reason.as_str()).collect();
        assert_eq!(reasons.len(), 4, "every skipped line must be accounted for: {reasons:?}");
    }

    #[test]
    fn duplicates_are_reported_once_and_kept_once() {
        let parsed = parse("example.com\nEXAMPLE.COM\nexample.com\n");

        assert_eq!(parsed.entries.len(), 1, "case-insensitive: one domain, not three");
        assert_eq!(parsed.unusable.len(), 2);
    }

    #[test]
    fn a_missing_file_is_empty_not_fatal() {
        let parsed = scan(Path::new("/nonexistent/domains.txt")).unwrap();
        assert!(parsed.entries.is_empty());
    }
}
