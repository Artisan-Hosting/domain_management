//! The migration plan: what a scan proposes, and what a person decides.
//!
//! `scan` writes this file; you edit it; `apply` reads it back. That shape is
//! deliberate. Attaching a hundred half-remembered domains to organizations
//! is a judgement call per domain, and a judgement call belongs in a file you
//! can read, diff, share and re-run -- not in a terminal prompt answered once
//! at 1am.
//!
//! Two rules hold the whole thing together:
//!
//! * **Suggestions are never actions.** `suggested` is what the scanner
//!   guessed and why; `assign` is what will actually happen. They start equal
//!   and diverge the moment you disagree.
//! * **Nothing is quarantined unless `confirm` is `true`.** The scanner
//!   proposes candidates; it never ticks the box.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::model::{FindingCode, Inventory};
use crate::error::{Error, Result};

/// Bumped to 2 for the resource-taxonomy migration: every `org_id` field in
/// this file's JSON shape (`OrgEntry`, `RunnerEntry`, `Suggestion`,
/// `Assignment`, `RunnerOrgAssignment`) is now `organization_id`, and its
/// values are UUID strings rather than ais_auth's old stringified bigint --
/// an existing plan.json from before this change will not parse (the
/// deny-by-default schema_version check below is exactly what catches that,
/// rather than silently misreading the old field names as absent).
pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: u32,
    pub generated_at: String,
    pub tree_root: String,
    /// Inlined so the valid ids are in front of you while editing, instead of
    /// in another window.
    pub catalog: Catalog,
    pub domains: Vec<PlanDomain>,
    /// Optional: fixes to `ais_auth`'s own runner→org table, applied with an
    /// elevated token. Nothing here runs unless `apply` is true.
    #[serde(default)]
    pub runner_org_assignments: Vec<RunnerOrgAssignment>,
    /// Candidates for the attic. `confirm` starts false on every one.
    #[serde(default)]
    pub quarantine: Vec<QuarantineItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub organizations: Vec<OrgEntry>,
    #[serde(default)]
    pub runners: Vec<RunnerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgEntry {
    pub organization_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerEntry {
    /// The 8-hex id the platform knows a project by:
    /// `sha256("{branch}-{repo}-{user}")[..8]`.
    pub runner_id: String,
    /// Present only when Portal's repo catalog was reachable. Without it,
    /// name-based suggestions cannot be made -- ids alone say nothing about
    /// which domain belongs where.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Record it and attach it as `assign` says.
    Import,
    /// Leave it alone entirely. Nothing is written for this domain.
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Something concrete tied them together, like a runner id in the upstream.
    High,
    /// A name matched a repo.
    Medium,
    /// A weak signal; look before accepting.
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDomain {
    pub fqdn: String,
    /// How this domain came to exist for us. Everything a scan finds is
    /// `imported` by definition.
    pub source: String,
    pub found_in: Vec<String>,
    /// What the scanner guessed, and why. Read-only: editing it changes
    /// nothing, `assign` is the field with teeth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<Suggestion>,
    /// What will actually be recorded. Both fields may stay null -- a domain
    /// with no organization is a normal, durable state.
    pub assign: Assignment,
    pub action: Action,
    #[serde(default)]
    pub vhosts: Vec<PlanVhost>,
    #[serde(default)]
    pub certs: Vec<PlanCert>,
    #[serde(default)]
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    pub confidence: Confidence,
    pub why: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Assignment {
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub runner_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanVhost {
    /// Relative to the tree root.
    pub path: String,
    /// Record the file as adopted: shown in the dashboard, never rewritten.
    pub adopt: bool,
    pub server_names: Vec<String>,
    /// True when the file carries our managed header, meaning we wrote it.
    #[serde(default)]
    pub managed: bool,
    /// What the file looked like at scan time. Recorded so a later hand edit
    /// to a file we generated shows up as drift instead of being silently
    /// overwritten on the next render.
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCert {
    pub key_type: String,
    pub dir: String,
    /// RFC 3339, so the file is readable without converting timestamps.
    pub not_after: String,
    pub covers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerOrgAssignment {
    pub runner_id: String,
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_organization_id: Option<String>,
    /// Off by default: this writes to another service's table.
    #[serde(default)]
    pub apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    /// Relative to the tree root.
    pub path: String,
    pub reason: String,
    /// The tick. Nothing moves while this is false.
    #[serde(default)]
    pub confirm: bool,
}

impl Plan {
    pub fn load(raw: &str) -> Result<Self> {
        let plan: Plan = crate::config::parse_json(raw)
            .map_err(|e| Error::Invalid(format!("plan file: {e}")))?;

        if plan.schema_version != SCHEMA_VERSION {
            return Err(Error::Invalid(format!(
                "plan schema_version {} is not the {SCHEMA_VERSION} this build understands",
                plan.schema_version
            )));
        }

        Ok(plan)
    }

    pub fn to_json(&self) -> Result<String> {
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Invalid(format!("serializing plan: {e}")))?;
        json.push('\n');
        Ok(json)
    }

    /// One-screen summary, for `plan show` and for the end of a scan.
    pub fn summary(&self) -> String {
        let importing = self.domains.iter().filter(|d| d.action == Action::Import).count();
        let skipping = self.domains.len() - importing;
        let assigned = self
            .domains
            .iter()
            .filter(|d| d.assign.organization_id.is_some())
            .count();
        let suggested_only = self
            .domains
            .iter()
            .filter(|d| d.assign.organization_id.is_none() && d.suggested.as_ref().is_some_and(|s| s.organization_id.is_some()))
            .count();
        let confirmed_quarantine = self.quarantine.iter().filter(|q| q.confirm).count();

        format!(
            "{} domain(s): {importing} to import, {skipping} skipped, {assigned} with an organization\n\
             {suggested_only} more have a suggested organization waiting for you to accept it\n\
             {} quarantine candidate(s), {confirmed_quarantine} confirmed\n\
             {} runner org assignment(s), {} enabled",
            self.domains.len(),
            self.quarantine.len(),
            self.runner_org_assignments.len(),
            self.runner_org_assignments.iter().filter(|a| a.apply).count(),
        )
    }
}

/// Builds a plan from a scan.
///
/// The catalog may be empty (no `ais_auth` reachable, no token); the plan is
/// still useful, it simply has nothing to suggest.
pub fn from_inventory(inventory: &Inventory, catalog: Catalog) -> Plan {
    let mut domains = Vec::with_capacity(inventory.domains.len());

    for record in &inventory.domains {
        let suggestion = suggest(record, &catalog);

        // The assignment starts as the suggestion: accepting the scanner's
        // guess should be "change nothing", and disagreeing should be the
        // edit. Anything unsuggested stays null, which is a fine end state.
        let assign = Assignment {
            organization_id: suggestion.as_ref().and_then(|s| s.organization_id.clone()),
            runner_id: suggestion.as_ref().and_then(|s| s.runner_id.clone()),
        };

        let vhosts = record
            .vhost_files
            .iter()
            .map(|path| {
                let file = inventory.nginx.files.iter().find(|file| &file.path == path);
                PlanVhost {
                    path: path.clone(),
                    adopt: true,
                    server_names: server_names_for(inventory, path),
                    managed: file.is_some_and(|file| file.managed),
                    sha256: file.map(|file| file.sha256.clone()).unwrap_or_default(),
                }
            })
            .collect();

        let certs = inventory
            .certs
            .iter()
            .filter(|dir| record.cert_dirs.contains(&dir.dir))
            .flat_map(|dir| {
                dir.entries.iter().map(|entry| PlanCert {
                    key_type: entry.key_type.clone(),
                    dir: dir.dir.clone(),
                    not_after: rfc3339(entry.not_after),
                    covers: entry.sans.clone(),
                })
            })
            .collect();

        domains.push(PlanDomain {
            fqdn: record.fqdn.clone(),
            source: "imported".to_owned(),
            found_in: record.found_in.iter().cloned().collect(),
            suggested: suggestion,
            assign,
            action: Action::Import,
            vhosts,
            certs,
            findings: record.findings.iter().map(|code| code.as_str().to_owned()).collect(),
        });
    }

    // Certificate directories nothing serves: proposed, never ticked.
    let quarantine = inventory
        .findings_of(FindingCode::CertWithoutVhost)
        .map(|finding| QuarantineItem {
            path: format!("certs/{}", finding.subject),
            reason: FindingCode::CertWithoutVhost.as_str().to_owned(),
            confirm: false,
        })
        .collect();

    Plan {
        schema_version: SCHEMA_VERSION,
        generated_at: rfc3339(inventory.scanned_at),
        tree_root: inventory.tree_root.clone(),
        catalog,
        domains,
        runner_org_assignments: Vec::new(),
        quarantine,
    }
}

fn server_names_for(inventory: &Inventory, path: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    for server in inventory.nginx.servers.iter().filter(|s| s.file == path) {
        names.extend(server.real_names().cloned());
    }
    names.into_iter().collect()
}

/// Guesses which project and organization a domain belongs to.
///
/// Ordered strongest first, and it stops at the first thing that actually
/// means something. A weak guess presented confidently is worse than no
/// guess at all, because it gets accepted without being read.
fn suggest(record: &super::model::DomainRecord, catalog: &Catalog) -> Option<Suggestion> {
    // 1. A runner id appearing verbatim in an upstream or a file path. Ids
    //    are 8 hex characters and do not turn up by accident.
    let haystack: Vec<String> = record
        .upstreams
        .iter()
        .chain(record.vhost_files.iter())
        .map(|value| value.to_ascii_lowercase())
        .collect();

    for runner in &catalog.runners {
        let id = runner.runner_id.to_ascii_lowercase();
        if id.len() >= 6 && haystack.iter().any(|value| value.contains(&id)) {
            return Some(Suggestion {
                organization_id: runner.organization_id.clone(),
                runner_id: Some(runner.runner_id.clone()),
                confidence: Confidence::High,
                why: format!("runner id {} appears in this domain's vhost or upstream", runner.runner_id),
            });
        }
    }

    // 2. A repo name matching a label of the domain.
    let labels: BTreeSet<String> = record
        .names
        .iter()
        .flat_map(|name| name.split('.'))
        .map(normalize)
        .filter(|label| label.len() > 2)
        .collect();

    for runner in &catalog.runners {
        let Some(repo) = runner.repo.as_ref() else { continue };
        let normalized = normalize(repo);
        if normalized.len() > 2 && labels.contains(&normalized) {
            return Some(Suggestion {
                organization_id: runner.organization_id.clone(),
                runner_id: Some(runner.runner_id.clone()),
                confidence: Confidence::Medium,
                why: format!("a label of this domain matches the repo name '{repo}'"),
            });
        }
    }

    // 3. When there is exactly one organization, it is the only answer
    //    available -- worth offering, clearly marked as weak.
    if catalog.organizations.len() == 1 {
        let org = &catalog.organizations[0];
        return Some(Suggestion {
            organization_id: Some(org.organization_id.clone()),
            runner_id: None,
            confidence: Confidence::Low,
            why: format!("'{}' is the only organization that exists", org.name),
        });
    }

    None
}

/// Lowercase alphanumerics only, so `acme-web`, `acme_web` and `acmeweb` all
/// compare equal.
fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn rfc3339(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::model::DomainRecord;
    use std::collections::BTreeSet;

    fn record(fqdn: &str) -> DomainRecord {
        DomainRecord {
            fqdn: fqdn.to_owned(),
            names: [fqdn.to_owned()].into_iter().collect(),
            found_in: BTreeSet::new(),
            vhost_files: BTreeSet::new(),
            cert_dirs: BTreeSet::new(),
            upstreams: BTreeSet::new(),
            serves_tls: true,
            in_domains_txt: true,
            expires_at: None,
            cloudflare_zone_id: None,
            findings: Vec::new(),
        }
    }

    fn catalog() -> Catalog {
        Catalog {
            organizations: vec![
                OrgEntry { organization_id: "4".to_owned(), name: "Acme Corp".to_owned() },
                OrgEntry { organization_id: "9".to_owned(), name: "Other Ltd".to_owned() },
            ],
            runners: vec![RunnerEntry {
                runner_id: "ab12cd34".to_owned(),
                repo: Some("acme-web".to_owned()),
                branch: Some("main".to_owned()),
                organization_id: Some("4".to_owned()),
            }],
        }
    }

    #[test]
    fn a_runner_id_in_the_upstream_is_the_strongest_signal() {
        let mut domain = record("example.com");
        domain.upstreams.insert("http://unix:/run/ab12cd34.sock".to_owned());

        let suggestion = suggest(&domain, &catalog()).unwrap();
        assert_eq!(suggestion.confidence, Confidence::High);
        assert_eq!(suggestion.runner_id.as_deref(), Some("ab12cd34"));
        assert_eq!(suggestion.organization_id.as_deref(), Some("4"), "the runner's org comes with it");
    }

    #[test]
    fn a_repo_name_matching_a_label_is_a_medium_guess() {
        let mut domain = record("acme-web.com");
        domain.names.insert("acmeweb.com".to_owned());

        let suggestion = suggest(&domain, &catalog()).unwrap();
        assert_eq!(suggestion.confidence, Confidence::Medium);
        assert_eq!(suggestion.runner_id.as_deref(), Some("ab12cd34"));
    }

    #[test]
    fn nothing_is_suggested_when_there_is_nothing_to_go_on() {
        let domain = record("unrelated-name.com");
        assert!(
            suggest(&domain, &catalog()).is_none(),
            "two organizations and no match means no honest guess exists"
        );
    }

    #[test]
    fn a_single_organization_is_offered_weakly() {
        let mut only = catalog();
        only.organizations.truncate(1);
        only.runners.clear();

        let suggestion = suggest(&record("unrelated.com"), &only).unwrap();
        assert_eq!(suggestion.confidence, Confidence::Low);
        assert_eq!(suggestion.organization_id.as_deref(), Some("4"));
        assert!(suggestion.runner_id.is_none());
    }

    #[test]
    fn short_labels_do_not_match_repos() {
        // `www`, `api`, `dev` would otherwise glue themselves to any repo
        // with a short name.
        let mut small = catalog();
        small.runners[0].repo = Some("ui".to_owned());
        small.organizations.truncate(2);

        let mut domain = record("ui.com");
        domain.names.insert("ui.com".to_owned());

        assert!(suggest(&domain, &small).is_none());
    }

    #[test]
    fn a_plan_round_trips_through_json_with_comments() {
        let plan = Plan {
            schema_version: SCHEMA_VERSION,
            generated_at: "2026-09-17T00:00:00Z".to_owned(),
            tree_root: "/mnt/nginx_local".to_owned(),
            catalog: catalog(),
            domains: vec![PlanDomain {
                fqdn: "example.com".to_owned(),
                source: "imported".to_owned(),
                found_in: vec!["domains.txt".to_owned()],
                suggested: None,
                assign: Assignment { organization_id: Some("4".to_owned()), runner_id: None },
                action: Action::Import,
                vhosts: Vec::new(),
                certs: Vec::new(),
                findings: vec!["vhost_only".to_owned()],
            }],
            runner_org_assignments: Vec::new(),
            quarantine: Vec::new(),
        };

        let json = plan.to_json().unwrap();
        let annotated = format!("// notes from review\n{json}");

        // Operators annotate these files while working through them; a
        // comment must not break `apply`.
        let parsed = Plan::load(&annotated).unwrap();
        assert_eq!(parsed.domains[0].assign.organization_id.as_deref(), Some("4"));
        assert_eq!(parsed.domains[0].action, Action::Import);
    }

    #[test]
    fn a_plan_from_a_future_schema_is_refused() {
        let json = r#"{"schema_version": 99, "generated_at": "", "tree_root": "",
                       "catalog": {}, "domains": []}"#;
        assert!(Plan::load(json).is_err(), "an unknown schema must not be half-applied");
    }

    #[test]
    fn omitted_optional_fields_still_load() {
        // What a hand-trimmed plan looks like.
        let json = r#"{
            "schema_version": 2,
            "generated_at": "2026-09-17T00:00:00Z",
            "tree_root": "/mnt/nginx_local",
            "catalog": {},
            "domains": [
                { "fqdn": "example.com", "source": "imported", "found_in": [],
                  "assign": {}, "action": "skip" }
            ]
        }"#;

        let plan = Plan::load(json).unwrap();
        assert_eq!(plan.domains[0].action, Action::Skip);
        assert!(plan.domains[0].assign.organization_id.is_none());
        assert!(plan.quarantine.is_empty());
    }
}
