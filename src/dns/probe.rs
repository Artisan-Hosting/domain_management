//! Resolver-backed DNS checks.

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::proto::rr::rdata::TXT;
use hickory_resolver::{Resolver, TokioResolver};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct Probe {
    resolver: TokioResolver,
}

impl Probe {
    /// A resolver aimed at the given servers. Public resolvers are the right
    /// default for gating checks: what matters is what the world sees, not
    /// what this host's `/etc/resolv.conf` happens to cache.
    pub fn with_servers(servers: &[String]) -> Result<Self> {
        let ips = parse_servers(servers)?;
        if ips.is_empty() {
            return Err(Error::Dns("no resolvers configured".to_owned()));
        }

        let config =
            ResolverConfig::from_name_servers(ips.into_iter().map(NameServerConfig::udp_and_tcp).collect());

        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|e| Error::Dns(format!("building resolver: {e}")))?;

        Ok(Self { resolver })
    }

    /// Every A and AAAA address for a name. An empty vector means the name
    /// resolved to nothing, which is different from a lookup failure.
    pub async fn addresses(&self, name: &str) -> Result<Vec<IpAddr>> {
        match self.resolver.lookup_ip(fqdn(name)).await {
            Ok(lookup) => Ok(lookup.iter().collect()),
            Err(err) if is_no_records(&err) => Ok(Vec::new()),
            Err(err) => Err(Error::Dns(format!("{name}: {err}"))),
        }
    }

    pub async fn cname(&self, name: &str) -> Result<Option<String>> {
        let lookup = match self.resolver.lookup(fqdn(name), RecordType::CNAME).await {
            Ok(lookup) => lookup,
            Err(err) if is_no_records(&err) => return Ok(None),
            Err(err) => return Err(Error::Dns(format!("{name} CNAME: {err}"))),
        };

        Ok(lookup
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::CNAME(cname) => Some(cname.0.to_utf8()),
                _ => None,
            }))
    }

    pub async fn txt(&self, name: &str) -> Result<Vec<String>> {
        let lookup = match self.resolver.lookup(fqdn(name), RecordType::TXT).await {
            Ok(lookup) => lookup,
            Err(err) if is_no_records(&err) => return Ok(Vec::new()),
            Err(err) => return Err(Error::Dns(format!("{name} TXT: {err}"))),
        };

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt_to_string(txt)),
                _ => None,
            })
            .collect())
    }

    /// The authoritative nameservers for a zone, by name.
    ///
    /// Used to aim a second resolver at the servers that will actually answer
    /// the CA, rather than trusting a recursive resolver's cache.
    pub async fn nameservers(&self, zone: &str) -> Result<Vec<String>> {
        let lookup = match self.resolver.lookup(fqdn(zone), RecordType::NS).await {
            Ok(lookup) => lookup,
            Err(err) if is_no_records(&err) => return Ok(Vec::new()),
            Err(err) => return Err(Error::Dns(format!("{zone} NS: {err}"))),
        };

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(ns.0.to_utf8()),
                _ => None,
            })
            .collect())
    }

    /// The old `ip_matches`: does the name resolve to one of our edge IPs?
    /// An empty expectation list means "don't gate", matching the old
    /// `EXPECTED_IPS` being unset.
    pub async fn resolves_to_edge(&self, name: &str, expected: &[IpAddr]) -> Result<bool> {
        if expected.is_empty() {
            return Ok(true);
        }

        let found = self.addresses(name).await?;
        Ok(found.iter().any(|ip| expected.contains(ip)))
    }

    /// The old `alias_cname_ok`: is `_acme-challenge.<domain>` pointed at the
    /// target we write TXT records to? Compared without the trailing dot and
    /// case-insensitively, since resolvers differ on both.
    pub async fn challenge_cname_ok(&self, domain: &str, expected_target: &str) -> Result<bool> {
        let name = format!("_acme-challenge.{domain}");
        let Some(actual) = self.cname(&name).await? else {
            return Ok(false);
        };

        Ok(normalize(&actual) == normalize(expected_target))
    }

    /// Waits for `value` to show up in the TXT records at `name`.
    ///
    /// Called against the alias zone's authoritative nameservers before
    /// telling the CA to validate: if the record has not propagated, the CA
    /// sees NXDOMAIN and burns a failed validation.
    pub async fn wait_for_txt(&self, name: &str, value: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_secs(2);

        loop {
            match self.txt(name).await {
                Ok(values) if values.iter().any(|found| found == value) => return Ok(()),
                Ok(_) => {}
                // A transient resolver error here is normal while a record is
                // still spreading; only the deadline ends the wait.
                Err(_) => {}
            }

            if Instant::now() >= deadline {
                return Err(Error::Dns(format!(
                    "TXT {name} did not carry the expected value within {}s",
                    timeout.as_secs()
                )));
            }

            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(15));
        }
    }
}

/// Accepts `1.1.1.1` and `1.1.1.1:53` alike -- the port is discarded, since
/// DNS over anything but 53 is not something this service does.
fn parse_servers(servers: &[String]) -> Result<Vec<IpAddr>> {
    let mut out = Vec::with_capacity(servers.len());

    for server in servers {
        out.push(parse_server(server)?);
    }

    Ok(out)
}

/// Accepts `1.1.1.1`, `1.1.1.1:53`, `2606:4700:4700::1111` and
/// `[2606:4700:4700::1111]:53`.
///
/// A bare IPv6 address is tried first and on purpose: it is full of colons,
/// and splitting on the last one turns a valid address into nonsense.
fn parse_server(server: &str) -> Result<IpAddr> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(ip);
    }

    let host = match server.strip_prefix('[') {
        // [v6]:port -- the brackets exist precisely to disambiguate this.
        Some(rest) => rest.split_once(']').map(|(host, _)| host),
        None => match server.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                Some(host)
            }
            _ => None,
        },
    };

    host.and_then(|host| host.parse::<IpAddr>().ok())
        .ok_or_else(|| Error::Dns(format!("resolver {server:?}: not an IP address")))
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') { name.to_owned() } else { format!("{name}.") }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn txt_to_string(txt: &TXT) -> String {
    // A TXT record is a list of character-strings; a long ACME value is split
    // across several and has to be rejoined before comparing.
    txt.txt_data
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

/// NXDOMAIN and NoRecordsFound are answers, not failures: the name simply is
/// not there yet, which is the normal state while waiting on a customer.
fn is_no_records(err: &NetError) -> bool {
    err.is_no_records_found() || err.is_nx_domain()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_strings_accept_bare_ips_and_host_port() {
        let parsed = parse_servers(&[
            "1.1.1.1".to_owned(),
            "8.8.8.8:53".to_owned(),
            "2606:4700:4700::1111".to_owned(),
            "[2606:4700:4700::1001]:53".to_owned(),
        ])
        .unwrap();

        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0], "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed[1], "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(parsed[2], "2606:4700:4700::1111".parse::<IpAddr>().unwrap());
        assert_eq!(parsed[3], "2606:4700:4700::1001".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn a_bad_resolver_is_a_config_error_not_a_panic() {
        assert!(parse_servers(&["not-an-ip".to_owned()]).is_err());
    }

    #[test]
    fn names_are_compared_without_trailing_dot_or_case() {
        assert_eq!(
            normalize("_acme-challenge.Artisanhosting.NET."),
            "_acme-challenge.artisanhosting.net"
        );
    }
}
