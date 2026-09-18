//! The DNS-01 issuance flow.

use artisan_middleware::dusa_collection_utils::core::logger::LogLevel;
use artisan_middleware::dusa_collection_utils::log;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize};
use std::time::Duration;

use super::{IssuedCert, KeyType};
use crate::cloudflare::{CfSuite, dns};
use crate::config::Config;
use crate::dns::probe::Probe;
use crate::error::{Error, Result};

pub struct Issuer {
    config: Config,
    cf: CfSuite,
    /// Public resolvers: used to find the alias zone's nameservers, and as a
    /// fallback if that lookup fails.
    public: Probe,
}

impl Issuer {
    pub fn new(config: Config, cf: CfSuite) -> Result<Self> {
        let public = Probe::with_servers(&config.dns.resolvers)?;
        Ok(Self { config, cf, public })
    }

    /// Issues both key types for `fqdn` (plus its wildcard) and returns them
    /// in memory. Nothing touches disk here -- the caller installs the set
    /// only if every key type succeeded, so a domain never ends up with a
    /// fresh certificate of one type beside a stale one of the other.
    pub async fn issue_pair(
        &self,
        account: &Account,
        fqdn: &str,
        challenge_target: &str,
    ) -> Result<Vec<IssuedCert>> {
        let authoritative = self.authoritative_probe().await;
        let mut issued = Vec::with_capacity(KeyType::ALL.len());

        for key_type in KeyType::ALL {
            log!(LogLevel::Info, "issuing {key_type} certificate for {fqdn}");
            issued.push(
                self.issue_one(account, fqdn, challenge_target, key_type, &authoritative)
                    .await?,
            );
        }

        Ok(issued)
    }

    async fn issue_one(
        &self,
        account: &Account,
        fqdn: &str,
        challenge_target: &str,
        key_type: KeyType,
        authoritative: &Probe,
    ) -> Result<IssuedCert> {
        // Apex and wildcard on one certificate, as the old script did.
        let identifiers = vec![
            Identifier::Dns(fqdn.to_owned()),
            Identifier::Dns(format!("*.{fqdn}")),
        ];

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| Error::Acme(format!("{fqdn}: creating order: {e}")))?;

        // Record ids are collected as we go so cleanup can run on every exit
        // path, including the failures. Left-behind TXT records are what make
        // the *next* attempt fail mysteriously.
        let mut written_records: Vec<String> = Vec::new();

        let result = self
            .solve_and_finalize(
                &mut order,
                fqdn,
                challenge_target,
                key_type,
                authoritative,
                &mut written_records,
            )
            .await;

        let failures = dns::remove_challenge_txt(
            &self.cf.challenge,
            &self.config.acme.alias_zone_id,
            &written_records,
        )
        .await;
        if !failures.is_empty() {
            // Worth shouting about but not worth failing a successful
            // issuance over: the records are harmless until the next run.
            log!(
                LogLevel::Warn,
                "{fqdn}: could not clean up {} challenge record(s): {}",
                failures.len(),
                failures.join(", ")
            );
        }

        result
    }

    async fn solve_and_finalize(
        &self,
        order: &mut instant_acme::Order,
        fqdn: &str,
        challenge_target: &str,
        key_type: KeyType,
        authoritative: &Probe,
        written_records: &mut Vec<String>,
    ) -> Result<IssuedCert> {
        let mut pending_values = Vec::new();

        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz =
                    result.map_err(|e| Error::Acme(format!("{fqdn}: authorization: {e}")))?;

                match authz.status {
                    AuthorizationStatus::Pending => {}
                    // Already valid from an earlier order for the same name:
                    // no challenge to solve, and re-solving would only cost
                    // another round trip.
                    AuthorizationStatus::Valid => continue,
                    other => {
                        return Err(Error::Acme(format!(
                            "{fqdn}: authorization in unusable state {other:?}"
                        )));
                    }
                }

                let challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    Error::Acme(format!("{fqdn}: no dns-01 challenge offered"))
                })?;

                let value = challenge.key_authorization().dns_value();

                // The TXT record goes on the alias target, not on the
                // customer's `_acme-challenge` name -- that name is a CNAME
                // pointing here. This is what keeps the everyday credential
                // scoped to one zone we own.
                let record_id = dns::add_challenge_txt(
                    &self.cf.challenge,
                    &self.config.acme.alias_zone_id,
                    challenge_target,
                    &value,
                )
                .await?;
                written_records.push(record_id);
                pending_values.push(value);
            }
        }

        // Wait for every value to be visible on the alias zone's own
        // nameservers before telling the CA to look. An apex + wildcard order
        // produces two values at the same name, and both have to be there.
        for value in &pending_values {
            authoritative
                .wait_for_txt(
                    challenge_target,
                    value,
                    Duration::from_secs(self.config.acme.propagation_timeout_secs),
                )
                .await?;
        }

        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz =
                    result.map_err(|e| Error::Acme(format!("{fqdn}: authorization: {e}")))?;
                if authz.status != AuthorizationStatus::Pending {
                    continue;
                }
                let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    Error::Acme(format!("{fqdn}: no dns-01 challenge offered"))
                })?;
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| Error::Acme(format!("{fqdn}: signalling readiness: {e}")))?;
            }
        }

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| Error::Acme(format!("{fqdn}: waiting for validation: {e}")))?;
        if status != OrderStatus::Ready {
            return Err(Error::Acme(format!(
                "{fqdn}: order ended in {status:?} rather than ready"
            )));
        }

        // Our own key and CSR rather than instant-acme's convenience path,
        // which would generate an ECDSA key every time -- the RSA half of the
        // pair is the whole reason this is explicit.
        let key_pair = generate_key(key_type)?;
        let mut params = CertificateParams::new(vec![fqdn.to_owned(), format!("*.{fqdn}")])
            .map_err(|e| Error::Acme(format!("{fqdn}: certificate parameters: {e}")))?;
        params.distinguished_name = DistinguishedName::new();

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| Error::Acme(format!("{fqdn}: building CSR: {e}")))?;

        order
            .finalize_csr(csr.der())
            .await
            .map_err(|e| Error::Acme(format!("{fqdn}: finalizing order: {e}")))?;

        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| Error::Acme(format!("{fqdn}: collecting certificate: {e}")))?;

        Ok(IssuedCert {
            key_type,
            cert_pem,
            key_pem: key_pair.serialize_pem(),
        })
    }

    /// A resolver aimed at the alias zone's authoritative nameservers.
    ///
    /// Checking propagation against a public recursive resolver is misleading
    /// in both directions: it can cache a negative answer for a name we just
    /// created, and it can answer from a different edge than the CA will ask.
    /// Falls back to the configured public resolvers if the NS lookup fails,
    /// since a slightly weaker check beats no check.
    async fn authoritative_probe(&self) -> Probe {
        let zone = &self.config.acme.alias_zone;

        match self.nameserver_addresses(zone).await {
            Ok(servers) if !servers.is_empty() => match Probe::with_servers(&servers) {
                Ok(probe) => return probe,
                Err(err) => log!(
                    LogLevel::Warn,
                    "cannot use {zone} nameservers ({err}); falling back to public resolvers"
                ),
            },
            Ok(_) => log!(
                LogLevel::Warn,
                "no nameservers found for {zone}; falling back to public resolvers"
            ),
            Err(err) => log!(
                LogLevel::Warn,
                "nameserver lookup for {zone} failed ({err}); falling back to public resolvers"
            ),
        }

        self.public.clone()
    }

    async fn nameserver_addresses(&self, zone: &str) -> Result<Vec<String>> {
        let mut addresses = Vec::new();

        for ns in self.public.nameservers(zone).await? {
            for ip in self.public.addresses(&ns).await? {
                addresses.push(ip.to_string());
            }
        }

        Ok(addresses)
    }
}

fn generate_key(key_type: KeyType) -> Result<KeyPair> {
    match key_type {
        KeyType::Ecc => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
        KeyType::Rsa => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_4096),
    }
    .map_err(|e| Error::Acme(format!("generating {key_type} key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_and_rsa_keys_both_generate() {
        // Guards the feature flags as much as the code: RSA generation needs
        // rcgen's aws_lc_rs backend, and without it this is a runtime error
        // rather than a compile error.
        let ecc = generate_key(KeyType::Ecc).unwrap();
        assert!(ecc.serialize_pem().contains("PRIVATE KEY"));

        let rsa = generate_key(KeyType::Rsa).unwrap();
        assert!(rsa.serialize_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn csr_covers_apex_and_wildcard() {
        let key = generate_key(KeyType::Ecc).unwrap();
        let mut params =
            CertificateParams::new(vec!["example.com".to_owned(), "*.example.com".to_owned()])
                .unwrap();
        params.distinguished_name = DistinguishedName::new();

        let csr = params.serialize_request(&key).unwrap();
        assert!(!csr.der().is_empty());
    }
}
