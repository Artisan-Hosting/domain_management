//! Cross-referencing the collectors into one picture, and naming what is wrong.
//!
//! Each collector on its own is a list of facts. The value is in the joins:
//! a certificate no vhost references, a name being served that nothing
//! renews, two files claiming the same hostname. Those only appear when the
//! three sources are laid over each other.
//!
//! Every finding is descriptive. Nothing here decides to change anything --
//! that is the plan file's job, and a person's.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::certs::{CertDir, CertEntry};
use super::domains_txt::DomainsTxt;
use super::nginx::NginxIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    /// A certificate directory nothing serves. Renewed forever, used by nobody.
    CertWithoutVhost,
    /// A vhost pointing at a certificate file that is not there. This one is
    /// usually already an outage.
    VhostWithoutCert,
    CertExpired,
    CertExpiring,
    /// The certificate does not cover the name the vhost serves.
    CertNameMismatch,
    /// Two server blocks claim the same name; nginx serves the first it
    /// loaded and says nothing at runtime.
    DuplicateServerName,
    /// In `domains.txt`, but nothing serves it and no certificate exists.
    DomainsTxtOnly,
    /// Served over TLS, but absent from `domains.txt` -- so renewal was
    /// never happening for it.
    VhostOnly,
    /// A private key readable by more than its owner.
    KeyPermissions,
    /// The scanner declined to interpret the file. Never touched, never adopted.
    UnparsedFile,
    /// A certificate directory we could not read: an empty directory, a
    /// half-copied pair, a PEM that will not parse. Distinct from
    /// `unparsed_file`, which is about nginx config.
    CertUnreadable,
    /// A certificate exists, and no snippet links it to anything. It renews
    /// on schedule and nothing can serve it -- the manual step after
    /// issuance that used to get forgotten.
    CertWithoutSnippet,
    /// A `.conf` in the tree that no `include` reaches, so none of it is live.
    UnreferencedConfig,
    /// A line in `domains.txt` that was never a usable domain.
    DomainsTxtUnusable,
    /// Only with `--check-dns`.
    DnsMismatch,
    MissingChallengeCname,
}

impl FindingCode {
    pub fn severity(self) -> Severity {
        match self {
            // Already broken, or about to be.
            FindingCode::VhostWithoutCert
            | FindingCode::CertExpired
            | FindingCode::CertNameMismatch
            | FindingCode::KeyPermissions => Severity::Error,

            // Working today, wrong in a way that bites later.
            FindingCode::CertExpiring
            | FindingCode::DuplicateServerName
            | FindingCode::VhostOnly
            | FindingCode::UnparsedFile
            | FindingCode::CertUnreadable
            | FindingCode::CertWithoutSnippet
            | FindingCode::DnsMismatch
            | FindingCode::MissingChallengeCname => Severity::Warn,

            // Tidiness.
            FindingCode::CertWithoutVhost
            | FindingCode::DomainsTxtOnly
            | FindingCode::UnreferencedConfig
            | FindingCode::DomainsTxtUnusable => Severity::Info,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FindingCode::CertWithoutVhost => "cert_without_vhost",
            FindingCode::VhostWithoutCert => "vhost_without_cert",
            FindingCode::CertExpired => "cert_expired",
            FindingCode::CertExpiring => "cert_expiring",
            FindingCode::CertNameMismatch => "cert_name_mismatch",
            FindingCode::DuplicateServerName => "duplicate_server_name",
            FindingCode::DomainsTxtOnly => "domains_txt_only",
            FindingCode::VhostOnly => "vhost_only",
            FindingCode::KeyPermissions => "key_permissions",
            FindingCode::UnparsedFile => "unparsed_file",
            FindingCode::CertUnreadable => "cert_unreadable",
            FindingCode::CertWithoutSnippet => "cert_without_snippet",
            FindingCode::UnreferencedConfig => "unreferenced_config",
            FindingCode::DomainsTxtUnusable => "domains_txt_unusable",
            FindingCode::DnsMismatch => "dns_mismatch",
            FindingCode::MissingChallengeCname => "missing_challenge_cname",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    /// What it is about: a domain, a file path, a certificate directory.
    pub subject: String,
    pub message: String,
    /// Where the conclusion came from, so it can be checked by hand.
    pub evidence: Vec<String>,
}

/// One registrable domain and everything found under it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    /// The name this is managed as -- what a certificate would be issued for.
    /// See [`issuance_unit`]: on a shared zone this is the customer's own
    /// subdomain, not the registrable domain everyone shares.
    pub fqdn: String,
    /// Every name seen under it, across vhosts and certificates.
    pub names: BTreeSet<String>,
    /// `domains.txt`, `vhost:<path>`, `cert:<dir>` -- how we know about it.
    pub found_in: BTreeSet<String>,
    pub vhost_files: BTreeSet<String>,
    pub cert_dirs: BTreeSet<String>,
    /// Distinct `proxy_pass` targets, the raw material for guessing which
    /// project a domain belongs to.
    pub upstreams: BTreeSet<String>,
    pub serves_tls: bool,
    pub in_domains_txt: bool,
    /// Soonest expiry across its certificates, unix seconds.
    pub expires_at: Option<i64>,
    /// Filled in by `--check-cloudflare`: the zone we already hold for this
    /// domain, if any. Absent means "not checked" as much as "not there".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare_zone_id: Option<String>,
    /// Set when this is a hostname living under another record's certificate
    /// (`staging.artisanhosting.net` under `artisanhosting.net`): the parent's
    /// `fqdn`. Such a host is its own record so it can be assigned to its own
    /// organization or runner, but it is issued and renewed as part of the
    /// parent, which is why certificate facts are inherited from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub findings: Vec<FindingCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub scanned_at: i64,
    pub tree_root: String,
    pub nginx: NginxIndex,
    pub certs: Vec<CertDir>,
    pub domains_txt: DomainsTxt,
    pub domains: Vec<DomainRecord>,
    pub findings: Vec<Finding>,
}

impl Inventory {
    pub fn findings_of(&self, code: FindingCode) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.code == code)
    }

    pub fn counts_by_code(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.code.as_str()).or_insert(0) += 1;
        }
        counts
    }
}

/// Builds the cross-referenced view.
///
/// `now` is passed in rather than read from the clock so expiry findings are
/// testable and a scan is reproducible.
pub fn build(
    tree_root: &Path,
    certs_dir_name: &str,
    nginx: NginxIndex,
    certs: Vec<CertDir>,
    domains_txt: DomainsTxt,
    now: i64,
    renew_before_days: i64,
) -> Inventory {
    let mut findings = Vec::new();
    let mut domains: BTreeMap<String, DomainRecord> = BTreeMap::new();

    // What the previous system managed as a unit: every line of domains.txt
    // and every certificate directory. Served names attach to these rather
    // than to their registrable domain.
    let mut units: BTreeSet<String> = BTreeSet::new();
    for entry in &domains_txt.entries {
        if registrable_domain(&entry.fqdn).is_some() {
            units.insert(entry.fqdn.to_ascii_lowercase());
        }
    }
    for cert_dir in &certs {
        units.insert(cert_dir.implied_fqdn.to_ascii_lowercase());
        for entry in &cert_dir.entries {
            for san in &entry.sans {
                // A wildcard SAN names its parent as the unit; the apex SAN
                // names it directly.
                if let Some(parent) = san.strip_prefix("*.") {
                    units.insert(parent.to_ascii_lowercase());
                }
            }
        }
    }

    // --- what each config file said ------------------------------------
    for file in &nginx.files {
        if let Some(error) = &file.parse_error {
            findings.push(Finding {
                code: FindingCode::UnparsedFile,
                severity: FindingCode::UnparsedFile.severity(),
                subject: file.path.clone(),
                message: format!("not interpreted ({error}); left untouched"),
                evidence: vec![format!("sha256 {}", file.sha256)],
            });
        } else if file.unreferenced {
            findings.push(Finding {
                code: FindingCode::UnreferencedConfig,
                severity: FindingCode::UnreferencedConfig.severity(),
                subject: file.path.clone(),
                message: "no include reaches this file, so none of it is live".to_owned(),
                evidence: Vec::new(),
            });
        }
    }

    // --- server blocks --------------------------------------------------
    // name -> the files claiming it, for duplicate detection.
    let mut claims: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // Which record a vhost *file* belongs to. `vhosts.source_path` is unique,
    // so a file can be recorded against one domain only; when a file serves
    // several records the unit itself wins (it is the one whose certificate
    // the file uses), then the first host by name.
    let mut file_owner: BTreeMap<&str, (bool, String)> = BTreeMap::new();
    for server in &nginx.servers {
        for name in server.real_names() {
            let bare = name.trim_start_matches("*.").to_ascii_lowercase();
            if registrable_domain(&bare).is_none() {
                continue;
            }
            let unit = issuance_unit(&bare, &units);
            // `false` sorts first, so a unit beats any host.
            let candidate = if host_parent(&bare, &unit).is_some() {
                (true, bare)
            } else {
                (false, unit)
            };
            file_owner
                .entry(server.file.as_str())
                .and_modify(|current| {
                    if candidate < *current {
                        *current = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }

    for server in &nginx.servers {
        for name in server.real_names() {
            let bare = name.trim_start_matches("*.").to_ascii_lowercase();
            claims
                .entry(bare.clone())
                .or_default()
                .push(format!("{}:{}", server.file, server.line_start));

            if registrable_domain(&bare).is_none() {
                continue;
            }
            let unit = issuance_unit(&bare, &units);

            // A real host under a known unit is a record of its own rather
            // than a name on its parent's -- that folding is what made
            // `staging.<zone>` invisible while `<zone>` looked fine.
            let parent = host_parent(&bare, &unit).map(str::to_owned);
            let key = if parent.is_some() { bare.clone() } else { unit.clone() };

            let record = domains.entry(key.clone()).or_insert_with(|| {
                let mut record = empty_record(&key);
                record.parent = parent.clone();
                record
            });

            record.names.insert(bare.clone());
            record.found_in.insert(format!("vhost:{}", server.file));
            if file_owner.get(server.file.as_str()).is_some_and(|(_, owner)| *owner == key) {
                record.vhost_files.insert(server.file.clone());
            }
            record.upstreams.extend(server.proxy_passes.iter().cloned());
            record.serves_tls |= server.is_tls();
        }

        // Does every certificate this vhost points at actually exist? There
        // are normally two (ECDSA and RSA), and they usually come from a
        // snippet -- so the evidence names the snippet and line, which is
        // where the fix goes, not the vhost.
        for cert_ref in &server.ssl_certificates {
            if resolve_cert_path(tree_root, certs_dir_name, &cert_ref.path).is_none() {
                let subject = server
                    .real_names()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| server.file.clone());
                findings.push(Finding {
                    code: FindingCode::VhostWithoutCert,
                    severity: FindingCode::VhostWithoutCert.severity(),
                    subject,
                    message: format!("ssl_certificate {} does not exist", cert_ref.path),
                    evidence: vec![
                        format!("{}:{}", cert_ref.from_file, cert_ref.line),
                        format!("served by {}:{}", server.file, server.line_start),
                    ],
                });
            }
        }
    }

    for (name, locations) in &claims {
        if locations.len() > 1 {
            findings.push(Finding {
                code: FindingCode::DuplicateServerName,
                severity: FindingCode::DuplicateServerName.severity(),
                subject: name.clone(),
                // Reported, never auto-fixed: only a person knows which of
                // the two was meant, and guessing takes a site down.
                message: format!(
                    "claimed by {} server blocks; nginx serves whichever loaded first",
                    locations.len()
                ),
                evidence: locations.clone(),
            });
        }
    }

    // --- certificates ---------------------------------------------------
    let renew_threshold = now + renew_before_days * 86_400;

    for cert_dir in &certs {
        let covered: BTreeSet<String> = cert_dir
            .entries
            .iter()
            .flat_map(|entry| entry.sans.iter())
            .map(|san| san.trim_start_matches("*.").to_ascii_lowercase())
            .collect();

        let names: BTreeSet<String> = if covered.is_empty() {
            // Unreadable certificate: fall back to the directory name so it
            // is still attached to a domain rather than vanishing.
            [cert_dir.implied_fqdn.to_ascii_lowercase()].into_iter().collect()
        } else {
            covered
        };

        for name in &names {
            if registrable_domain(name).is_none() {
                continue;
            }
            let unit = issuance_unit(name, &units);
            let record = domains.entry(unit.clone()).or_insert_with(|| empty_record(&unit));

            record.names.insert(name.clone());
            record.found_in.insert(format!("cert:{}", cert_dir.dir));
            record.cert_dirs.insert(cert_dir.dir.clone());

            for entry in &cert_dir.entries {
                record.expires_at = Some(match record.expires_at {
                    Some(existing) => existing.min(entry.not_after),
                    None => entry.not_after,
                });
            }
        }

        for problem in &cert_dir.problems {
            findings.push(Finding {
                code: FindingCode::CertUnreadable,
                severity: FindingCode::CertUnreadable.severity(),
                subject: cert_dir.dir.clone(),
                message: problem.clone(),
                evidence: Vec::new(),
            });
        }

        for entry in &cert_dir.entries {
            if entry.not_after < now {
                findings.push(expiry_finding(FindingCode::CertExpired, cert_dir, entry, now));
            } else if entry.not_after < renew_threshold {
                findings.push(expiry_finding(FindingCode::CertExpiring, cert_dir, entry, now));
            }

            if let Some(mode) = entry.key_mode {
                if mode & 0o077 != 0 {
                    findings.push(Finding {
                        code: FindingCode::KeyPermissions,
                        severity: FindingCode::KeyPermissions.severity(),
                        subject: cert_dir.dir.clone(),
                        message: format!("{} is mode {:o}, expected 600", entry.key_path, mode),
                        evidence: vec![entry.key_path.clone()],
                    });
                }
            }
        }

        // Is there a snippet linking this certificate to anything at all?
        // Without one, no vhost can reach it however well it renews.
        let marker = format!("/_.{}/", cert_dir.implied_fqdn);
        let linked = nginx.snippets.iter().any(|snippet| {
            snippet.cert_paths.iter().any(|path| path.contains(&marker))
        });

        if !linked {
            findings.push(Finding {
                code: FindingCode::CertWithoutSnippet,
                severity: FindingCode::CertWithoutSnippet.severity(),
                subject: cert_dir.implied_fqdn.clone(),
                message: format!(
                    "no snippet links this certificate; nothing can serve it until one includes {}",
                    cert_dir.dir
                ),
                evidence: vec![cert_dir.dir.clone()],
            });
        }

        // Nothing serves any name this certificate covers.
        let served = names.iter().any(|name| claims.contains_key(name));
        if !served {
            findings.push(Finding {
                code: FindingCode::CertWithoutVhost,
                severity: FindingCode::CertWithoutVhost.severity(),
                subject: cert_dir.dir.clone(),
                message: "no server block serves any name this certificate covers".to_owned(),
                evidence: names.iter().cloned().collect(),
            });
        }
    }

    // A vhost whose certificates do not cover the name it serves.
    //
    // Judged across *all* of them: a name covered by the RSA certificate but
    // not the ECDSA one still fails for half the clients, so every
    // certificate in effect has to cover it.
    for server in &nginx.servers {
        if server.stream {
            continue;
        }

        let resolved: Vec<(&super::nginx::CertRef, &CertEntry)> = server
            .ssl_certificates
            .iter()
            .filter_map(|cert_ref| {
                let path = resolve_cert_path(tree_root, certs_dir_name, &cert_ref.path)?;
                entry_for_path(&certs, &path).map(|entry| (cert_ref, entry))
            })
            .collect();

        if resolved.is_empty() {
            continue;
        }

        for name in server.real_names() {
            let bare = name.trim_start_matches("*.");
            for (cert_ref, entry) in &resolved {
                if !entry.covers(bare) {
                    findings.push(Finding {
                        code: FindingCode::CertNameMismatch,
                        severity: FindingCode::CertNameMismatch.severity(),
                        subject: bare.to_ascii_lowercase(),
                        message: format!(
                            "served by {} but the {} certificate covers [{}]",
                            server.file,
                            entry.key_type,
                            entry.sans.join(", ")
                        ),
                        evidence: vec![
                            format!("{}:{}", cert_ref.from_file, cert_ref.line),
                            cert_ref.path.clone(),
                        ],
                    });
                }
            }
        }
    }

    // --- domains.txt ----------------------------------------------------
    for entry in &domains_txt.entries {
        if registrable_domain(&entry.fqdn).is_none() {
            continue;
        }
        let unit = issuance_unit(&entry.fqdn, &units);
        let record = domains.entry(unit.clone()).or_insert_with(|| empty_record(&unit));
        record.names.insert(entry.fqdn.clone());
        record.found_in.insert("domains.txt".to_owned());
        record.in_domains_txt = true;
    }

    for line in &domains_txt.unusable {
        findings.push(Finding {
            code: FindingCode::DomainsTxtUnusable,
            severity: FindingCode::DomainsTxtUnusable.severity(),
            subject: format!("{}:{}", domains_txt.path, line.line),
            message: format!("{}: {}", line.reason, line.content),
            evidence: Vec::new(),
        });
    }

    // --- hosts inherit their parent's certificate ------------------------
    // A host is served from its parent's wildcard, so what covers and renews
    // it is the parent's: the same certificate directories and expiry.
    let parents: BTreeMap<String, (BTreeSet<String>, Option<i64>)> = domains
        .values()
        .filter(|record| record.parent.is_none())
        .map(|record| (record.fqdn.clone(), (record.cert_dirs.clone(), record.expires_at)))
        .collect();
    for record in domains.values_mut() {
        let Some((cert_dirs, expires_at)) = record.parent.as_ref().and_then(|p| parents.get(p)) else {
            continue;
        };
        record.cert_dirs = cert_dirs.clone();
        record.expires_at = *expires_at;
    }

    // --- the two joins that matter most ---------------------------------
    for record in domains.values_mut() {
        // Renewal is per certificate, and a host has none of its own: the
        // parent's record says whether it is being renewed.
        if record.parent.is_some() {
            continue;
        }

        if record.in_domains_txt && record.vhost_files.is_empty() && record.cert_dirs.is_empty() {
            findings.push(Finding {
                code: FindingCode::DomainsTxtOnly,
                severity: FindingCode::DomainsTxtOnly.severity(),
                subject: record.fqdn.clone(),
                message: "listed for renewal but nothing serves it and no certificate exists"
                    .to_owned(),
                evidence: Vec::new(),
            });
        }

        if !record.in_domains_txt && record.serves_tls {
            findings.push(Finding {
                code: FindingCode::VhostOnly,
                severity: FindingCode::VhostOnly.severity(),
                // The one most worth acting on: it is being served over TLS
                // and nothing was ever renewing it.
                subject: record.fqdn.clone(),
                message: "served over TLS but absent from domains.txt, so renewal never ran for it"
                    .to_owned(),
                evidence: record.vhost_files.iter().cloned().collect(),
            });
        }
    }

    // Attach findings to the domains they concern.
    for finding in &findings {
        if registrable_domain(&finding.subject).is_some() {
            // The host itself if it has a record, and always its unit: a
            // mismatch on `staging.` is also a fact about the certificate.
            let unit = issuance_unit(&finding.subject, &units);
            let subject = finding.subject.to_ascii_lowercase();
            for key in [&subject, &unit] {
                if let Some(record) = domains.get_mut(key) {
                    if !record.findings.contains(&finding.code) {
                        record.findings.push(finding.code);
                    }
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.subject.cmp(&b.subject))
    });

    Inventory {
        scanned_at: now,
        tree_root: tree_root.to_string_lossy().into_owned(),
        nginx,
        certs,
        domains_txt,
        domains: domains.into_values().collect(),
        findings,
    }
}

fn empty_record(fqdn: &str) -> DomainRecord {
    DomainRecord {
        fqdn: fqdn.to_owned(),
        names: BTreeSet::new(),
        found_in: BTreeSet::new(),
        vhost_files: BTreeSet::new(),
        cert_dirs: BTreeSet::new(),
        upstreams: BTreeSet::new(),
        serves_tls: false,
        in_domains_txt: false,
        expires_at: None,
        cloudflare_zone_id: None,
        parent: None,
        findings: Vec::new(),
    }
}

/// The parent unit when `name` is a real host under it, as opposed to the
/// unit itself or its `www`.
///
/// `www.shop.example.com` belongs to `shop.example.com` and is the same site;
/// `staging.example.com` under `example.com` is a different site that merely
/// shares a certificate.
pub fn host_parent<'a>(name: &str, unit: &'a str) -> Option<&'a str> {
    if name == unit || name.strip_prefix("www.") == Some(unit) {
        None
    } else {
        Some(unit)
    }
}

fn expiry_finding(code: FindingCode, dir: &CertDir, entry: &CertEntry, now: i64) -> Finding {
    let days = entry.expires_in_days(now);
    Finding {
        code,
        severity: code.severity(),
        subject: dir.implied_fqdn.clone(),
        message: if days < 0 {
            format!("{} certificate expired {} day(s) ago", entry.key_type, -days)
        } else {
            format!("{} certificate expires in {days} day(s)", entry.key_type)
        },
        evidence: vec![entry.cert_path.clone()],
    }
}

/// The name a certificate would be issued for -- the unit this service
/// manages a domain as.
///
/// **Not the registrable domain**, and the difference matters on a hosting
/// platform. A shared zone routinely carries one customer per subdomain:
/// grouping `shop.example.com` and `blog.example.com` under `example.com`
/// would put two unrelated tenants in one record and offer to attach them to
/// one organization.
///
/// So the unit is taken from what the old system actually managed -- the
/// entries in `domains.txt` and the `_.<name>` certificate directories --
/// and a served name attaches to the longest of those that covers it.
/// Coverage is one label deep, because that is exactly what the wildcard in
/// those certificates reaches.
///
/// With nothing to attach to, the name is its own unit, less a leading
/// `www.` so an apex and its `www` do not become two records.
pub fn issuance_unit(name: &str, candidates: &BTreeSet<String>) -> String {
    let name = name.trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();

    if candidates.contains(&name) {
        return name;
    }

    let covering = candidates
        .iter()
        .filter(|candidate| is_one_label_below(&name, candidate))
        // Longest wins: with both `example.com` and `shop.example.com`
        // known, `www.shop.example.com` belongs to the latter.
        .max_by_key(|candidate| candidate.len());

    if let Some(candidate) = covering {
        return candidate.clone();
    }

    name.strip_prefix("www.").unwrap_or(&name).to_owned()
}

/// True when `name` sits exactly one label below `parent`, which is the reach
/// of a `*.parent` wildcard.
fn is_one_label_below(name: &str, parent: &str) -> bool {
    match name.strip_suffix(parent) {
        Some(prefix) => {
            prefix.ends_with('.') && prefix.trim_end_matches('.').split('.').count() == 1
        }
        None => false,
    }
}

/// The registrable domain, via the public suffix list.
///
/// `www.example.co.uk` gives `example.co.uk`, not `co.uk` -- getting this
/// wrong would file every UK customer under one record.
pub fn registrable_domain(name: &str) -> Option<String> {
    let cleaned = name
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if cleaned.is_empty() || !cleaned.contains('.') {
        return None;
    }

    psl::domain_str(&cleaned).map(str::to_owned)
}

/// Finds a certificate file referenced by a config, allowing for the tree
/// being scanned somewhere other than where nginx will read it.
///
/// Production configs carry absolute paths (`/mnt/nginx_local/certs/...`).
/// When the scan runs against a copy, those paths do not exist, so a path
/// containing the certificate directory is also tried relative to the tree
/// being scanned.
fn resolve_cert_path(tree_root: &Path, certs_dir_name: &str, raw: &str) -> Option<PathBuf> {
    let direct = PathBuf::from(raw);
    if direct.is_absolute() && direct.exists() {
        return Some(direct);
    }

    if !direct.is_absolute() {
        let joined = tree_root.join(raw);
        if joined.exists() {
            return Some(joined);
        }
    }

    let marker = format!("/{certs_dir_name}/");
    if let Some(position) = raw.find(&marker) {
        let tail = &raw[position + 1..];
        let remapped = tree_root.join(tail);
        if remapped.exists() {
            return Some(remapped);
        }
    }

    None
}

fn entry_for_path<'a>(certs: &'a [CertDir], path: &Path) -> Option<&'a CertEntry> {
    let file_name = path.file_name()?.to_string_lossy().into_owned();
    let dir_name = path.parent()?.file_name()?.to_string_lossy().into_owned();

    certs
        .iter()
        .find(|dir| dir.dir == dir_name)?
        .entries
        .iter()
        .find(|entry| entry.cert_path.ends_with(&file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains_respect_multi_label_suffixes() {
        assert_eq!(registrable_domain("www.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("*.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("EXAMPLE.COM.").as_deref(), Some("example.com"));
        // The reason psl is in here at all.
        assert_eq!(
            registrable_domain("shop.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain(""), None);
    }

    fn units(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_shared_zone_keeps_its_tenants_apart() {
        // The reason this is not grouped by registrable domain: two customers
        // on one zone must not land in the same record, where attaching one
        // to an organization would attach the other too.
        let known = units(&["shop.example.com", "blog.example.com"]);

        assert_eq!(issuance_unit("shop.example.com", &known), "shop.example.com");
        assert_eq!(issuance_unit("blog.example.com", &known), "blog.example.com");
        assert_eq!(
            issuance_unit("www.shop.example.com", &known),
            "shop.example.com",
            "a www of a known unit belongs to that unit, via its wildcard"
        );
    }

    #[test]
    fn a_wildcard_reaches_exactly_one_label() {
        let known = units(&["example.com"]);

        assert_eq!(issuance_unit("shop.example.com", &known), "example.com");
        assert_eq!(
            issuance_unit("a.b.example.com", &known),
            "a.b.example.com",
            "two labels down is past what *.example.com covers, so it is its own unit"
        );
    }

    #[test]
    fn the_longest_known_unit_wins() {
        let known = units(&["example.com", "shop.example.com"]);
        assert_eq!(issuance_unit("www.shop.example.com", &known), "shop.example.com");
    }

    #[test]
    fn with_nothing_known_a_name_is_its_own_unit_apart_from_www() {
        let known = BTreeSet::new();

        assert_eq!(issuance_unit("legacy.example.org", &known), "legacy.example.org");
        assert_eq!(
            issuance_unit("www.example.org", &known),
            "example.org",
            "an apex and its www are one site, not two"
        );
        assert_eq!(issuance_unit("*.example.org", &known), "example.org");
    }

    #[test]
    fn severity_puts_outages_above_tidiness() {
        assert_eq!(FindingCode::VhostWithoutCert.severity(), Severity::Error);
        assert_eq!(FindingCode::VhostOnly.severity(), Severity::Warn);
        assert_eq!(FindingCode::CertWithoutVhost.severity(), Severity::Info);
        assert!(Severity::Error > Severity::Warn && Severity::Warn > Severity::Info);
    }

    #[test]
    fn finding_codes_serialize_as_the_documented_strings() {
        // These strings land in the plan file, the database and the API, so
        // renaming a variant must not quietly change them.
        assert_eq!(FindingCode::VhostOnly.as_str(), "vhost_only");
        assert_eq!(
            serde_json::to_string(&FindingCode::CertWithoutVhost).unwrap(),
            "\"cert_without_vhost\""
        );
    }
}
