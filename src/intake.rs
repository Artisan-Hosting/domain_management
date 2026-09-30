//! Taking a hostname from a person: what it is, and what it needs.
//!
//! `AddDomain` is one request that means four different things depending on
//! what already exists -- the name is already ours, it is already being served
//! from the edge's configs, it sits under a domain an organization owns, or it
//! is brand new. The decisions that need the database or Cloudflare live in
//! the gRPC handler; everything that is just *about the name* lives here, where
//! it can be tested without either.

use std::net::IpAddr;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::inventory::model::registrable_domain;

/// A DNS record that has to exist for a name to work, in the shape both the
/// Cloudflare writer and the "here is what to add" instructions need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSpec {
    pub record_type: &'static str,
    pub name: String,
    pub content: String,
    pub note: String,
}

/// Cleans up what a person typed into something safe to use as a key.
///
/// Strict on purpose. The result becomes a filename (`sites-enabled/<slug>`),
/// an nginx `server_name` and a DNS record name, so anything that would be
/// surprising in any of those is refused here rather than escaped later.
pub fn normalize(input: &str) -> Result<String> {
    let name = input.trim().trim_end_matches('.').to_ascii_lowercase();

    if name.is_empty() {
        return Err(Error::Invalid("no domain name given".to_owned()));
    }
    if name.contains("://") || name.contains('/') {
        return Err(Error::Invalid(format!(
            "{input:?} looks like a URL; give just the hostname, e.g. staging.example.com"
        )));
    }
    if name.starts_with("*.") {
        return Err(Error::Invalid(
            "wildcards are not added directly; add the domain and its subdomains are covered by its certificate"
                .to_owned(),
        ));
    }
    if name.parse::<IpAddr>().is_ok() {
        return Err(Error::Invalid("an IP address is not a domain name".to_owned()));
    }
    if name.len() > 253 {
        return Err(Error::Invalid("a domain name is at most 253 characters".to_owned()));
    }

    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !ok {
            return Err(Error::Invalid(format!("{label:?} is not a valid domain label in {name}")));
        }
    }

    // Also rejects public suffixes (`co.uk`) and single labels (`localhost`),
    // neither of which is something a customer can own.
    if registrable_domain(&name).is_none() {
        return Err(Error::Invalid(format!("{name} is not a registrable domain name")));
    }

    Ok(name)
}

/// The domains above `fqdn`, nearest first, stopping at the registrable
/// domain -- never climbing into a public suffix.
///
/// `a.b.example.com` gives `b.example.com`, `example.com`; `www.example.co.uk`
/// gives `example.co.uk`, not `co.uk`.
pub fn ancestors(fqdn: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = fqdn;

    while let Some((_, rest)) = current.split_once('.') {
        if registrable_domain(rest).is_none() {
            break;
        }
        out.push(rest.to_owned());
        current = rest;
    }

    out
}

/// Is this the registrable domain itself, as opposed to something under it?
/// Only an apex can have a Cloudflare zone of its own to create.
pub fn is_apex(fqdn: &str) -> bool {
    registrable_domain(fqdn).as_deref() == Some(fqdn)
}

/// The records that point `fqdn` at the edge, plus -- when the name is not
/// already covered by a certificate we hold -- the `_acme-challenge` CNAME
/// renewals will need.
///
/// Empty edge addresses is an error rather than an empty list: with nothing to
/// point at, "here are the records to add" would be a blank page that looks
/// like success.
pub fn required_records(config: &Config, fqdn: &str, needs_challenge: bool) -> Result<Vec<RecordSpec>> {
    if config.dns.edge_ipv4.is_empty() && config.dns.edge_ipv6.is_empty() {
        return Err(Error::Config(
            "dns.edge_ipv4 / dns.edge_ipv6 are not set, so there is nothing to point a domain at".to_owned(),
        ));
    }

    let mut records = Vec::new();

    for ip in &config.dns.edge_ipv4 {
        records.push(RecordSpec {
            record_type: "A",
            name: fqdn.to_owned(),
            content: ip.clone(),
            note: "Points the name at the edge. Leave it DNS-only (grey cloud) if you proxy through Cloudflare."
                .to_owned(),
        });
    }
    for ip in &config.dns.edge_ipv6 {
        records.push(RecordSpec {
            record_type: "AAAA",
            name: fqdn.to_owned(),
            content: ip.clone(),
            note: "IPv6 address of the edge.".to_owned(),
        });
    }

    if needs_challenge {
        records.push(RecordSpec {
            record_type: "CNAME",
            name: format!("_acme-challenge.{fqdn}"),
            content: config.challenge_target_for(fqdn),
            note: "Lets us issue and renew the certificate without access to your DNS.".to_owned(),
        });
    }

    Ok(records)
}

/// A record already present in the zone at a name we are about to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingRecord {
    pub record_type: String,
    pub name: String,
    pub content: String,
}

/// What writing `desired` into a zone would do, decided *before* anything is
/// written.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DnsPlan {
    /// Missing, and safe to create.
    pub create: Vec<RecordSpec>,
    /// Already there, exactly as wanted. Nothing to do.
    pub present: Vec<RecordSpec>,
    /// Something else already lives at the name. One entry per problem, in
    /// words. If there is any, **nothing** is written: half a hostname's
    /// records is worse than none, and overwriting is not ours to decide.
    pub conflicts: Vec<String>,
}

/// Compares what we want against what the zone already holds.
///
/// Create-only by design. `cloudflare::dns::upsert` exists for records this
/// service owns outright (the edge A record of a domain it manages); a name a
/// person is adding may already point somewhere for a reason we cannot see,
/// and repointing it silently would take that site down.
pub fn plan_dns(desired: &[RecordSpec], existing: &[ExistingRecord]) -> DnsPlan {
    let mut plan = DnsPlan::default();

    for spec in desired {
        let same_name: Vec<&ExistingRecord> = existing
            .iter()
            .filter(|r| r.name.eq_ignore_ascii_case(&spec.name))
            .collect();

        if same_name
            .iter()
            .any(|r| r.record_type == spec.record_type && r.content.eq_ignore_ascii_case(&spec.content))
        {
            plan.present.push(spec.clone());
            continue;
        }

        // A CNAME cannot share a name with anything, and an A cannot share a
        // name with a CNAME.
        let address = matches!(spec.record_type, "A" | "AAAA");
        let clash = same_name.iter().find(|r| {
            if address {
                // A different address of the same family is a different
                // destination; the other family is a separate record set.
                r.record_type == "CNAME" || r.record_type == spec.record_type
            } else {
                true
            }
        });

        match clash {
            Some(other) => plan.conflicts.push(format!(
                "{} already has a {} record ({}), and we need {} {}",
                spec.name, other.record_type, other.content, spec.record_type, spec.content
            )),
            None => plan.create.push(spec.clone()),
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        let mut config = Config::default();
        config.dns.edge_ipv4 = vec!["203.0.113.10".to_owned()];
        config.dns.edge_ipv6 = vec!["2001:db8::10".to_owned()];
        config
    }

    #[test]
    fn a_typed_name_is_cleaned_up() {
        assert_eq!(normalize("  Staging.ArtisanHosting.NET. ").unwrap(), "staging.artisanhosting.net");
    }

    #[test]
    fn things_that_are_not_hostnames_are_refused() {
        for bad in [
            "",
            "https://staging.example.com",
            "example.com/path",
            "*.example.com",
            "192.0.2.1",
            "localhost",
            "co.uk",
            "exa mple.com",
            "-bad.example.com",
            "under_score.example.com",
            "double..dot.example.com",
        ] {
            assert!(normalize(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn ancestors_stop_at_the_registrable_domain() {
        assert_eq!(ancestors("a.b.example.com"), vec!["b.example.com", "example.com"]);
        assert_eq!(ancestors("staging.artisanhosting.net"), vec!["artisanhosting.net"]);
        assert_eq!(ancestors("www.example.co.uk"), vec!["example.co.uk"], "never climbs to co.uk");
        assert!(ancestors("example.com").is_empty());
    }

    #[test]
    fn an_apex_is_recognised() {
        assert!(is_apex("example.com"));
        assert!(is_apex("example.co.uk"));
        assert!(!is_apex("staging.example.com"));
    }

    #[test]
    fn a_covered_subdomain_needs_only_the_edge_records() {
        let records = required_records(&config(), "staging.example.com", false).unwrap();
        let kinds: Vec<_> = records.iter().map(|r| (r.record_type, r.name.as_str())).collect();
        assert_eq!(kinds, vec![("A", "staging.example.com"), ("AAAA", "staging.example.com")]);
    }

    #[test]
    fn an_uncovered_name_also_needs_the_challenge_cname() {
        let config = config();
        let records = required_records(&config, "example.org", true).unwrap();
        let cname = records.iter().find(|r| r.record_type == "CNAME").expect("challenge CNAME");
        assert_eq!(cname.name, "_acme-challenge.example.org");
        assert_eq!(cname.content, config.challenge_target_for("example.org"));
    }

    #[test]
    fn with_no_edge_address_configured_it_says_so_instead_of_returning_nothing() {
        let err = required_records(&Config::default(), "example.com", false).unwrap_err();
        assert!(err.to_string().contains("edge_ipv4"), "{err}");
    }

    fn spec(record_type: &'static str, name: &str, content: &str) -> RecordSpec {
        RecordSpec { record_type, name: name.to_owned(), content: content.to_owned(), note: String::new() }
    }
    fn have(record_type: &str, name: &str, content: &str) -> ExistingRecord {
        ExistingRecord { record_type: record_type.to_owned(), name: name.to_owned(), content: content.to_owned() }
    }

    #[test]
    fn an_empty_zone_gets_everything_created() {
        let desired = [spec("A", "staging.example.com", "203.0.113.10")];
        let plan = plan_dns(&desired, &[]);
        assert_eq!(plan.create.len(), 1);
        assert!(plan.conflicts.is_empty() && plan.present.is_empty());
    }

    #[test]
    fn a_record_that_is_already_right_is_left_alone() {
        let desired = [spec("A", "staging.example.com", "203.0.113.10")];
        let plan = plan_dns(&desired, &[have("A", "Staging.Example.com", "203.0.113.10")]);
        assert!(plan.create.is_empty() && plan.conflicts.is_empty());
        assert_eq!(plan.present.len(), 1);
    }

    #[test]
    fn a_name_pointing_somewhere_else_is_a_conflict_not_an_overwrite() {
        let desired = [spec("A", "staging.example.com", "203.0.113.10")];
        let plan = plan_dns(&desired, &[have("A", "staging.example.com", "198.51.100.7")]);
        assert!(plan.create.is_empty(), "must not offer to create beside or over it");
        assert_eq!(plan.conflicts.len(), 1);
        assert!(plan.conflicts[0].contains("198.51.100.7"), "{:?}", plan.conflicts);
    }

    #[test]
    fn a_cname_at_the_name_blocks_the_address_records() {
        let desired = [spec("A", "staging.example.com", "203.0.113.10")];
        let plan = plan_dns(&desired, &[have("CNAME", "staging.example.com", "elsewhere.example.net")]);
        assert_eq!(plan.conflicts.len(), 1);
    }

    #[test]
    fn an_ipv6_record_does_not_clash_with_an_ipv4_one() {
        let desired = [spec("AAAA", "staging.example.com", "2001:db8::10")];
        let plan = plan_dns(&desired, &[have("A", "staging.example.com", "198.51.100.7")]);
        assert_eq!(plan.create.len(), 1);
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn a_stale_txt_at_the_challenge_name_blocks_the_cname() {
        let desired = [spec("CNAME", "_acme-challenge.staging.example.com", "t.acme.example.net")];
        let plan = plan_dns(&desired, &[have("TXT", "_acme-challenge.staging.example.com", "old")]);
        assert_eq!(plan.conflicts.len(), 1);
    }
}
