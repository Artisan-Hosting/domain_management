//! Configuration and secrets.
//!
//! Two sources, deliberately separate:
//!
//! * **`ais_domains.json`** -- everything an operator may want to look at or
//!   change: bind addresses, the nginx tree layout, pricing, guardrails.
//!   Checked into config management, safe to read. JSON rather than TOML,
//!   matching the direction the platform is moving; `//` and `/* */`
//!   comments are stripped before parsing so the file can still explain
//!   itself.
//! * **The env file** (default `/opt/artisan/etc/ais_domains.env`, mode 0600)
//!   -- credentials only. Same shape as the `/etc/acme-sh/cloudflare.env` the
//!   `certs` script sourced, so the existing file's `CF_*` lines can be moved
//!   over as-is. Nothing here is ever written to the database or logged.
//!
//! The Cloudflare credentials are split by blast radius rather than kept as
//! one god token: only [`Secrets::cf_registrar_token`] can spend money, and
//! only [`Secrets::cf_challenge_token`] is needed for routine certificate
//! renewals -- that one is scoped to the alias zone alone, so a leak of the
//! token used every hour cannot touch a customer's zone.
//!
//! [`Config`] and [`Secrets`] are the substrate all three subsystems load
//! from (see the crate root doc): the CLI calls [`Config::load`]/
//! [`Secrets::load`] fresh on every invocation, while the gRPC service
//! loads them once in `main.rs::run` and holds them for the process's
//! lifetime -- the future job worker is handed a *clone* of that same
//! pair rather than reloading the files itself, so a config edit takes
//! effect on the next restart for every subsystem at once, never for one
//! and not the others.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::{Path, PathBuf}};

use crate::error::{Error, Result};

pub const DEFAULT_CONFIG_PATH: &str = "/opt/artisan/etc/ais_domains.json";
pub const DEFAULT_ENV_PATH: &str = "/opt/artisan/etc/ais_domains.env";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub grpc: Grpc,
    pub auth: Auth,
    pub billing: Billing,
    pub acme: Acme,
    pub cloudflare: Cloudflare,
    pub dns: Dns,
    pub tree: Tree,
    pub publish: Publish,
    pub pricing: Pricing,
    pub purchasing: Purchasing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grpc {
    /// Private-network bind only. Portal is the sole public entry point, the
    /// same arrangement ais_auth and ais_secretserver have.
    pub bind: String,
    pub reflection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Auth {
    /// ais_auth's `AccountInternal` gRPC address. `https://` is mutual TLS (the
    /// only thing a real ais_auth accepts); `http://` is plaintext. Portal
    /// defaults to `https://10.2.0.2:50051` for the same service.
    pub grpc_addr: String,
    /// How long a validated token stays cached before it is re-checked.
    pub token_cache_secs: u64,
}

/// The `Billing` service's gRPC address -- the sole source of Stripe
/// integration on this platform now, so this service never holds a Stripe
/// key of its own. See `src/billing.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Billing {
    /// `https://` is mutual TLS (this service presents its `ais_domain`
    /// certificate); `http://` is plaintext, for a local Billing run without
    /// TLS only. Defaults to `https://` so a deployment that forgets to
    /// configure this fails to connect rather than quietly sending charges
    /// and refunds in the clear.
    pub grpc_addr: String,
}

impl Default for Billing {
    fn default() -> Self {
        Self { grpc_addr: "https://127.0.0.1:50061".to_owned() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Acme {
    /// `true` points at Let's Encrypt staging -- the old `STAGING=1`.
    pub staging: bool,
    pub contact_email: String,
    pub account_key_path: PathBuf,
    /// Zone that holds every `_acme-challenge` TXT record. The
    /// challenge-alias trick from the `certs` script: customer zones only
    /// ever hold a CNAME, so the token that writes TXT records needs access
    /// to this one zone and nothing else.
    pub alias_zone: String,
    pub alias_zone_id: String,
    /// Subdomain of `alias_zone` under which per-domain targets are minted,
    /// e.g. `acme` gives `<hash>.acme.artisanhosting.net`.
    pub alias_subdomain: String,
    /// What imported domains already CNAME to. Left as the bare
    /// `_acme-challenge.<alias_zone>` the acme.sh script used; issuance
    /// through this shared target is serialized.
    pub legacy_challenge_target: String,
    pub renew_before_days: i64,
    /// Give up waiting for a TXT record to show up on the alias zone's
    /// authoritative nameservers.
    pub propagation_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cloudflare {
    pub api_base: String,
    /// Role granted to a customer invited to their own domain's zone.
    /// `Domain DNS` is the narrowest one that still lets them manage records;
    /// no domain-scoped role can reach the registrar, transfers or billing.
    pub member_role: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// The edge IPs customer domains must resolve to. Replaces the
    /// `EXPECTED_IPS` env var the `certs` script gated on.
    pub edge_ipv4: Vec<String>,
    pub edge_ipv6: Vec<String>,
    /// Resolvers used to check a BYO customer's records from outside.
    pub resolvers: Vec<String>,
    pub verify_interval_secs: u64,
    /// Stop chasing a BYO domain whose records never appeared.
    pub verify_give_up_hours: u64,
    pub reconcile_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tree {
    /// The nginx tree that gets published, as it lives on the publisher.
    /// `SOURCE_TREE` in the agent's environment.
    pub root: PathBuf,
    /// Where that same tree lands on an edge, and therefore what absolute
    /// paths inside the configs refer to. A snippet says
    /// `/etc/nginx/certs/_.example.com/ecc.pem`, which on the publisher is
    /// `<root>/certs/_.example.com/ecc.pem` -- without this, every
    /// certificate reference looks broken when scanned from the publisher.
    pub deployed_root: PathBuf,
    /// Certificate directory inside the tree. Keeps the `_.<domain>` naming
    /// the existing nginx configs and the agent already expect.
    pub certs_dir: String,
    /// Where vhosts live. Files here have no extension by convention
    /// (`sites-enabled/artisanhosting`, not `artisanhosting.conf`).
    pub sites_dir: String,
    /// Where the per-zone `*_cert.conf` snippets live. Each one links a
    /// vhost to its ECDSA and RSA certificates, and is shared by every vhost
    /// on that zone.
    pub snippets_dir: String,
    pub nginx_bin: PathBuf,
    pub work_root: PathBuf,
    pub keep_stage: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Publish {
    pub bucket: String,
    /// Key prefix inside the bucket, e.g. `nginx`. Releases land at
    /// `<prefix>/releases/<id>/tree/...` with the pointer at `<prefix>/latest`.
    pub prefix: String,
    pub endpoint: String,
    pub region: String,
    /// Coalesce a burst of changes into one release.
    pub debounce_secs: u64,
    pub keep_releases: usize,
    /// Publish to a throwaway prefix and skip the `latest` pointer. Phase 1
    /// runs this way beside the Go publisher until the manifests match.
    pub shadow_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pricing {
    pub markup_percent: f64,
    pub min_margin_cents: i64,
    /// Refuse to sell anything above this, whatever the registry says.
    pub max_price_cents: i64,
    pub currency: String,
    /// Only these TLDs are sellable. Cloudflare's API beta also rejects
    /// plenty on its own (`extension_not_supported_via_api`), but that is a
    /// moving target and this list is ours.
    pub tld_allowlist: Vec<String>,
    pub quote_ttl_secs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Purchasing {
    /// Kill switch. Ships `false`: nothing can be bought until someone turns
    /// it on deliberately.
    pub enabled: bool,
    pub orders_per_org_per_day: i64,
    pub monthly_cap_cents: i64,
    /// Charge the customer's saved card this many days before registry expiry.
    pub renewal_charge_days_before: i64,
    /// If the renewal charge has not cleared by this many days before expiry,
    /// stop auto-renewing and alert an admin.
    pub renewal_giveup_days_before: i64,
    /// Registration is refused (and the customer refunded) if Cloudflare's
    /// price at registration time is more than this many cents above the cost
    /// the order was quoted on. The price is re-checked right before the
    /// purchase because a registration can't be refunded once it succeeds.
    pub max_cost_drift_cents: i64,
    /// How long an order may wait for its payment before it is cancelled and
    /// failed. The customer can simply quote and order again.
    pub payment_window_secs: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            grpc: Grpc::default(),
            auth: Auth::default(),
            billing: Billing::default(),
            acme: Acme::default(),
            cloudflare: Cloudflare::default(),
            dns: Dns::default(),
            tree: Tree::default(),
            publish: Publish::default(),
            pricing: Pricing::default(),
            purchasing: Purchasing::default(),
        }
    }
}

impl Default for Grpc {
    fn default() -> Self {
        Self { bind: "0.0.0.0:50055".to_owned(), reflection: true }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self { grpc_addr: "https://10.2.0.2:50051".to_owned(), token_cache_secs: 60 }
    }
}

impl Default for Acme {
    fn default() -> Self {
        Self {
            staging: true,
            contact_email: String::new(),
            account_key_path: PathBuf::from("/opt/artisan/etc/ais_domains_acme.key"),
            alias_zone: "artisanhosting.net".to_owned(),
            alias_zone_id: String::new(),
            alias_subdomain: "acme".to_owned(),
            legacy_challenge_target: "_acme-challenge.artisanhosting.net".to_owned(),
            renew_before_days: 30,
            propagation_timeout_secs: 300,
        }
    }
}

impl Default for Cloudflare {
    fn default() -> Self {
        Self {
            api_base: "https://api.cloudflare.com/client/v4".to_owned(),
            member_role: "Domain DNS".to_owned(),
            timeout_secs: 30,
        }
    }
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            edge_ipv4: Vec::new(),
            edge_ipv6: Vec::new(),
            resolvers: vec!["1.1.1.1:53".to_owned(), "8.8.8.8:53".to_owned()],
            verify_interval_secs: 120,
            verify_give_up_hours: 24 * 7,
            reconcile_interval_secs: 3600,
        }
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/mnt/nginx_local"),
            deployed_root: PathBuf::from("/etc/nginx"),
            certs_dir: "certs".to_owned(),
            sites_dir: "sites-enabled".to_owned(),
            snippets_dir: "snippets".to_owned(),
            nginx_bin: PathBuf::from("/sbin/nginx"),
            work_root: PathBuf::from("/opt/nginx-publisher"),
            keep_stage: false,
        }
    }
}

impl Default for Publish {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            prefix: "nginx".to_owned(),
            endpoint: String::new(),
            region: "auto".to_owned(),
            debounce_secs: 60,
            keep_releases: 10,
            shadow_mode: true,
        }
    }
}

impl Default for Pricing {
    fn default() -> Self {
        Self {
            markup_percent: 20.0,
            min_margin_cents: 300,
            max_price_cents: 10_000,
            currency: "USD".to_owned(),
            tld_allowlist: vec![
                "com".to_owned(),
                "net".to_owned(),
                "org".to_owned(),
                "dev".to_owned(),
                "app".to_owned(),
                "io".to_owned(),
            ],
            quote_ttl_secs: 600,
        }
    }
}

impl Default for Purchasing {
    fn default() -> Self {
        Self {
            enabled: false,
            orders_per_org_per_day: 5,
            monthly_cap_cents: 50_000,
            renewal_charge_days_before: 30,
            renewal_giveup_days_before: 7,
            max_cost_drift_cents: 100,
            payment_window_secs: 3600,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH));
        if !path.exists() {
            // Defaults are deliberately safe to boot with: staging ACME,
            // shadow publishing, purchasing off.
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
        parse_json(&raw).map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))
    }

    /// `<tree root>/<certs dir>/_.<domain>` -- the layout the existing nginx
    /// configs and the R2 agent already read.
    pub fn cert_dir_for(&self, fqdn: &str) -> PathBuf {
        self.tree.root.join(&self.tree.certs_dir).join(format!("_.{fqdn}"))
    }

    /// `<work_root>/stage/<release id>` -- where a release is assembled and
    /// tested before any of it leaves the host.
    pub fn work_stage_dir(&self, release_id: &str) -> PathBuf {
        self.tree.work_root.join("stage").join(release_id)
    }

    /// Vhost file for a domain. No extension, matching the convention in
    /// `sites-enabled`.
    pub fn vhost_path_for(&self, fqdn: &str) -> PathBuf {
        self.tree.root.join(&self.tree.sites_dir).join(snippet_slug(fqdn))
    }

    /// The certificate snippet for a domain: the file that links a vhost to
    /// its ECDSA and RSA pair. One per zone, shared by every vhost on it.
    pub fn snippet_path_for(&self, fqdn: &str) -> PathBuf {
        self.tree
            .root
            .join(&self.tree.snippets_dir)
            .join(format!("{}_cert.conf", snippet_slug(fqdn)))
    }

    /// The certificate directory as a *deployed* config must spell it, which
    /// is not where it sits on the publisher.
    pub fn deployed_cert_dir_for(&self, fqdn: &str) -> PathBuf {
        self.tree.deployed_root.join(&self.tree.certs_dir).join(format!("_.{fqdn}"))
    }

    pub fn acme_directory_url(&self) -> &'static str {
        if self.acme.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        }
    }

    /// Per-domain challenge target, so two issuances running at once cannot
    /// stack TXT records on one name or delete each other's during cleanup.
    /// Imported domains keep whatever target they were migrated with.
    pub fn challenge_target_for(&self, fqdn: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(fqdn.as_bytes());
        let label = hex::encode(&digest[..8]);
        format!("{label}.{}.{}", self.acme.alias_subdomain, self.acme.alias_zone)
    }
}

/// The naming convention the existing snippets follow: `artisanhosting.net`
/// becomes `artisanhosting`, `pierced-by-bugg.com` becomes `piercedbybugg`.
/// A subdomain keeps its full shape so `shop.example.com` and
/// `blog.example.com` cannot collide on one file.
pub fn snippet_slug(fqdn: &str) -> String {
    let trimmed = fqdn.trim_end_matches('.').to_ascii_lowercase();

    // Drop only the public suffix, keeping every label that identifies the
    // site itself.
    let stem = match psl::suffix_str(&trimmed) {
        Some(suffix) => trimmed.trim_end_matches(suffix).trim_end_matches('.').to_owned(),
        None => trimmed,
    };

    let slug: String = stem
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect::<String>()
        .replace('.', "_");

    if slug.is_empty() { "domain".to_owned() } else { slug }
}

/// Parses JSON that may carry `//` and `/* */` comments.
///
/// Shared with the inventory plan files, which operators edit by hand and
/// annotate as they work through them -- a comment someone left in a plan
/// should not make `apply` fall over.
pub fn parse_json<T: serde::de::DeserializeOwned>(raw: &str) -> std::result::Result<T, String> {
    let stripped = json_comments::StripComments::new(raw.as_bytes());
    serde_json::from_reader(stripped).map_err(|e| e.to_string())
}

/// Credentials. Never logged, never stored, never returned over gRPC.
#[derive(Clone)]
pub struct Secrets {
    pub database_url: String,
    pub cf_account_id: String,
    /// The only credential that can spend money.
    pub cf_registrar_token: String,
    /// Zone + DNS edit across the account: creates zones, writes edge records.
    pub cf_zones_token: String,
    /// DNS edit on the alias zone only: the one used on every renewal.
    pub cf_challenge_token: String,
    /// Account member management: customer invites.
    pub cf_members_token: String,
    pub r2_access_key_id: String,
    pub r2_secret_access_key: String,
}

impl std::fmt::Debug for Secrets {
    // Derived Debug on a struct full of tokens is how tokens end up in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// Loads the env file (if present) and then the process environment,
    /// which wins. Missing values are empty rather than fatal: `ais_domains
    /// issue` needs the Cloudflare challenge token and nothing else, and
    /// should not demand every other credential just to run. (Stripe
    /// credentials live in the `Billing` service now, not here -- see
    /// `src/billing.rs` and `Config::billing`.)
    pub fn load(env_path: Option<&Path>) -> Result<Self> {
        let path = env_path.unwrap_or_else(|| Path::new(DEFAULT_ENV_PATH));
        let file_vars = if path.exists() { parse_env_file(path)? } else { HashMap::new() };

        let get = |key: &str| -> String {
            std::env::var(key)
                .ok()
                .or_else(|| file_vars.get(key).cloned())
                .unwrap_or_default()
        };

        Ok(Self {
            database_url: get("DATABASE_URL"),
            // CF_Account_ID is the spelling acme.sh's dns_cf plugin uses, so
            // an existing cloudflare.env can be dropped in unchanged.
            cf_account_id: first_non_empty(&[get("CF_ACCOUNT_ID"), get("CF_Account_ID")]),
            cf_registrar_token: get("CF_REGISTRAR_TOKEN"),
            cf_zones_token: get("CF_ZONES_TOKEN"),
            cf_challenge_token: first_non_empty(&[get("CF_CHALLENGE_TOKEN"), get("CF_Token")]),
            cf_members_token: get("CF_MEMBERS_TOKEN"),
            r2_access_key_id: get("R2_ACCESS_KEY_ID"),
            r2_secret_access_key: get("R2_SECRET_ACCESS_KEY"),
        })
    }

    /// Checked at startup for the parts of the service that are switched on,
    /// so a missing token surfaces as one clear line at boot instead of a
    /// failed job at 3am.
    pub fn require(&self, keys: &[(&str, &str)]) -> Result<()> {
        let missing: Vec<&str> = keys
            .iter()
            .filter(|(_, value)| value.is_empty())
            .map(|(name, _)| *name)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(Error::Config(format!("missing credentials: {}", missing.join(", "))))
        }
    }
}

fn first_non_empty(candidates: &[String]) -> String {
    candidates.iter().find(|v| !v.is_empty()).cloned().unwrap_or_default()
}

/// `KEY=value` lines, with `export ` prefixes and surrounding quotes
/// tolerated -- the shape `set -a; . cloudflare.env; set +a` accepted.
fn parse_env_file(path: &Path) -> Result<HashMap<String, String>> {
    let raw = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("reading {}: {e}", path.display())))?;
    let mut out = HashMap::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(key.trim().to_owned(), value.to_owned());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_targets_are_per_domain_and_stable() {
        let config = Config::default();
        let a = config.challenge_target_for("example.com");
        let b = config.challenge_target_for("example.net");

        assert_ne!(a, b, "two domains must not share a challenge target");
        assert_eq!(a, config.challenge_target_for("example.com"), "must be stable");
        assert!(a.ends_with(".acme.artisanhosting.net"));
    }

    #[test]
    fn snippet_slugs_match_the_existing_naming() {
        // The files already in snippets/: artisanhosting_cert.conf,
        // artisanstudio_cert.conf, piercedbybugg_cert.conf.
        assert_eq!(snippet_slug("artisanhosting.net"), "artisanhosting");
        assert_eq!(snippet_slug("artisanstudio.net"), "artisanstudio");
        assert_eq!(snippet_slug("pierced-by-bugg.com"), "piercedbybugg");
        // A subdomain keeps its labels, so two tenants on one zone get two
        // snippets rather than fighting over one.
        assert_eq!(snippet_slug("shop.example.co.uk"), "shop_example");
        assert_eq!(snippet_slug("blog.example.co.uk"), "blog_example");
    }

    #[test]
    fn deployed_paths_differ_from_publisher_paths() {
        let config = Config::default();
        assert_eq!(
            config.cert_dir_for("example.com"),
            PathBuf::from("/mnt/nginx_local/certs/_.example.com"),
            "where it lives while we work on it"
        );
        assert_eq!(
            config.deployed_cert_dir_for("example.com"),
            PathBuf::from("/etc/nginx/certs/_.example.com"),
            "how a config has to spell it"
        );
        assert_eq!(
            config.snippet_path_for("example.com"),
            PathBuf::from("/mnt/nginx_local/snippets/example_cert.conf"),
        );
    }

    #[test]
    fn cert_dir_keeps_the_legacy_layout() {
        let config = Config::default();
        assert_eq!(
            config.cert_dir_for("example.com"),
            PathBuf::from("/mnt/nginx_local/certs/_.example.com"),
        );
    }

    #[test]
    fn the_shipped_example_config_parses() {
        // Catches the classic drift where a field is renamed in the struct
        // and the example everyone copies keeps the old spelling. Also proves
        // the comment stripping works on the real file.
        let raw = include_str!("../ais_domains.json.example");
        let config: Config = parse_json(raw).expect("example config must parse");

        assert_eq!(config.tree.root, PathBuf::from("/mnt/nginx_local"));
        assert!(config.acme.staging, "the example must ship pointing at staging");
        assert!(!config.purchasing.enabled, "the example must ship with purchasing off");
        assert!(config.publish.shadow_mode, "the example must ship in shadow mode");
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        // `deny_unknown_fields` is what turns a typo into an error at boot
        // instead of a setting that silently does nothing.
        let result: std::result::Result<Config, String> =
            parse_json(r#"{"tree": {"rooot": "/mnt/nginx_local"}}"#);
        assert!(result.is_err(), "a misspelled key must not be ignored");
    }

    #[test]
    fn env_file_parsing_tolerates_export_and_quotes() {
        let dir = std::env::temp_dir().join("ais_domains_env_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.env");
        std::fs::write(
            &path,
            "# comment\nexport CF_Token=\"abc123\"\nCF_Account_ID='acct'\nEMPTY=\n",
        )
        .unwrap();

        let vars = parse_env_file(&path).unwrap();
        assert_eq!(vars.get("CF_Token").map(String::as_str), Some("abc123"));
        assert_eq!(vars.get("CF_Account_ID").map(String::as_str), Some("acct"));
        assert_eq!(vars.get("EMPTY").map(String::as_str), Some(""));

        std::fs::remove_file(&path).unwrap();
    }
}
