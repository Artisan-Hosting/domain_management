//! End-to-end scan against a tree shaped like the real one.
//!
//! The fixture is deliberately messy, because the tree this has to survive is
//! messy: a vhost pointing at a certificate that is not there, two files
//! claiming the same hostname, a certificate nothing serves, a config file no
//! `include` reaches, a private key with the wrong mode, a file with
//! unbalanced braces, a name served over TLS that renewal never knew about,
//! and a `domains.txt` line for a site that no longer exists.
//!
//! Every one of those is something that has actually happened to somebody.

use ais_domains::config::Config;
use ais_domains::inventory::model::{FindingCode, Inventory};
use ais_domains::inventory::plan;
use ais_domains::inventory::{certs, domains_txt, model, nginx};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Roughly "now" for the fixture, so expiry findings are deterministic.
const NOW: i64 = 1_789_000_000;
const DAY: i64 = 86_400;

struct Fixture {
    root: PathBuf,
    config: Config,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A self-signed certificate covering `names`, expiring `expires_in_days`
/// from [`NOW`]. Real DER, so the scanner's x509 path is genuinely exercised
/// rather than mocked.
fn certificate(names: &[&str], expires_in_days: i64) -> (String, String) {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256};
    use time::OffsetDateTime;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.not_before = OffsetDateTime::from_unix_timestamp(NOW - 30 * DAY).unwrap();
    params.not_after = OffsetDateTime::from_unix_timestamp(NOW + expires_in_days * DAY).unwrap();

    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn fixture(name: &str) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "ais_domains_scan_{name}_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let tree = root.join("tree");

    // The real entry point: everything comes in through sites-enabled, and
    // the files there have no extension.
    write(
        &tree.join("nginx.conf"),
        "events {}\nhttp {\n    include sites-enabled/*;\n}\n",
    );

    write(
        &tree.join("snippets/ssl-params.conf"),
        "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;\n",
    );

    // One snippet per zone, carrying both key types, written with the
    // deployed /etc/nginx paths -- not where the scan is reading them from.
    write(
        &tree.join("snippets/artisanhosting_cert.conf"),
        "#ssl_certificate /etc/nginx/certs/_.artisanhosting.net_acme_client_cert/fullchain.pem;\n\n\
         ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/ecc.pem;\n\
         ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/ecc.key;\n\n\
         ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/rsa.pem;\n\
         ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/rsa.key;\n",
    );

    // A snippet pointing at a certificate that is not on disk at all.
    write(
        &tree.join("snippets/legacyclient_cert.conf"),
        "ssl_certificate     /etc/nginx/certs/_.legacy-client.example/ecc.pem;\n\
         ssl_certificate_key /etc/nginx/certs/_.legacy-client.example/ecc.key;\n",
    );

    // The healthy site, shaped exactly like sites-enabled/artisanhosting.
    write(
        &tree.join("sites-enabled/artisanhosting"),
        "server {\n\
             access_log /var/log/nginx/access.log otel_json;\n\
             listen 443 ssl http2;\n\
             server_name www.artisanhosting.net artisanhosting.net;\n\n\
             include snippets/artisanhosting_cert.conf;\n\
             include snippets/ssl-params.conf;\n\n\
             location / {\n\
                 proxy_pass http://artisan_release;\n\
                 proxy_set_header Host $host;\n\
             }\n\
         }\n\n\
         upstream artisan_release {\n\
             random;\n\
             server ahpn-2973453917896704.ah.internal:8093 max_fails=10 fail_timeout=10s;\n\
         }\n",
    );

    // A second file claiming a name the first one already serves.
    write(
        &tree.join("sites-enabled/artisanhosting_staging"),
        "server {\n    listen 443 ssl http2;\n    server_name artisanhosting.net;\n\
         include snippets/artisanhosting_cert.conf;\n\
         location / { proxy_pass http://10.1.0.9:9090; }\n}\n",
    );

    // Serving TLS for a name nothing renews, from a certificate that is not
    // there -- and the certificate line lives in the snippet, not here.
    write(
        &tree.join("sites-enabled/legacy_client"),
        "server {\n    listen 443 ssl http2;\n    server_name legacy-client.example;\n\
         include snippets/legacyclient_cert.conf;\n\
         location / { proxy_pass http://10.1.0.7:3000; }\n}\n",
    );

    write(
        &tree.join("sites-enabled/artisanhosting_redirect"),
        "server {\n    listen 80;\n    server_name artisanhosting.net;\n\
         brotli on;\n\
         return 301 https://artisanhosting.net$request_uri;\n}\n",
    );

    // Someone was mid-edit when they got pulled away.
    write(
        &tree.join("sites-enabled/half_edited"),
        "server {\n    server_name half.example;\n    location / { proxy_pass http://127.0.0.1:1;\n",
    );

    // Disabled the old way: moved out of sites-enabled, never deleted.
    write(
        &tree.join("sites-available/retired"),
        "server { listen 443 ssl http2; server_name retired.example; }\n",
    );

    // The good certificates behind the healthy site. Both key types, because
    // the snippet names both -- a snippet listing an RSA certificate that was
    // never issued stops nginx from starting at all.
    for key_type in ["ecc", "rsa"] {
        let (cert_pem, key_pem) = certificate(&["artisanhosting.net", "*.artisanhosting.net"], 60);
        write(&tree.join(format!("certs/_.artisanhosting.net/{key_type}.pem")), &cert_pem);
        write(&tree.join(format!("certs/_.artisanhosting.net/{key_type}.key")), &key_pem);
    }

    // An expired certificate no snippet links and no vhost serves, with a
    // world-readable key.
    let (orphan_pem, orphan_key) = certificate(&["orphan.example", "*.orphan.example"], -5);
    write(&tree.join("certs/_.orphan.example/ecc.pem"), &orphan_pem);
    let orphan_key_path = tree.join("certs/_.orphan.example/ecc.key");
    write(&orphan_key_path, &orphan_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&orphan_key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    write(
        &root.join("domains.txt"),
        "# renewal list\nartisanhosting.net\ngone.example\nnot a domain\n",
    );

    let mut config = Config::default();
    config.tree.root = tree;
    config.tree.work_root = root.join("work");

    Fixture { root, config }
}

fn scan(fixture: &Fixture) -> Inventory {
    let tree = &fixture.config.tree.root;
    let nginx_index = nginx::scan_tree(tree, &fixture.config.tree.snippets_dir).unwrap();
    let cert_dirs = certs::scan(&tree.join(&fixture.config.tree.certs_dir)).unwrap();
    let domain_list = domains_txt::scan(&fixture.root.join("domains.txt")).unwrap();

    model::build(
        tree,
        &fixture.config.tree.certs_dir,
        nginx_index,
        cert_dirs,
        domain_list,
        NOW,
        fixture.config.acme.renew_before_days,
    )
}

fn codes(inventory: &Inventory) -> BTreeSet<&'static str> {
    inventory.findings.iter().map(|f| f.code.as_str()).collect()
}

#[test]
fn the_scan_finds_every_problem_the_fixture_contains() {
    let fixture = fixture("findings");
    let inventory = scan(&fixture);

    let found = codes(&inventory);
    let expected: BTreeSet<&str> = [
        "cert_expired",
        "cert_without_snippet",
        "cert_without_vhost",
        "domains_txt_only",
        "domains_txt_unusable",
        "duplicate_server_name",
        "key_permissions",
        "unparsed_file",
        "unreferenced_config",
        "vhost_only",
        "vhost_without_cert",
    ]
    .into_iter()
    .collect();

    assert_eq!(found, expected, "finding set drifted");
}

#[test]
fn a_name_served_without_renewal_is_named() {
    // The finding most worth having: TLS is being served for a hostname that
    // was never in the renewal list, so nothing was keeping it alive.
    let fixture = fixture("vhost_only");
    let inventory = scan(&fixture);

    let subjects: Vec<&str> = inventory
        .findings_of(FindingCode::VhostOnly)
        .map(|f| f.subject.as_str())
        .collect();

    assert!(subjects.contains(&"legacy-client.example"), "{subjects:?}");
    assert!(
        !subjects.contains(&"artisanhosting.net"),
        "artisanhosting.net is in domains.txt and must not be flagged"
    );
}

#[test]
fn a_missing_certificate_is_an_error_not_a_note() {
    let fixture = fixture("missing_cert");
    let inventory = scan(&fixture);

    let finding = inventory
        .findings_of(FindingCode::VhostWithoutCert)
        .find(|f| f.subject == "legacy-client.example")
        .expect("the vhost pointing at a missing certificate must be found");

    assert_eq!(finding.subject, "legacy-client.example");
    assert_eq!(finding.severity, model::Severity::Error);
    // The evidence points at the *snippet* -- where the line actually is and
    // where the fix goes -- and then at the vhost it affects.
    assert!(
        finding.evidence[0].starts_with("snippets/legacyclient_cert.conf:"),
        "{:?}",
        finding.evidence
    );
    assert!(finding.evidence[1].contains("sites-enabled/legacy_client"), "{:?}", finding.evidence);
}

#[test]
fn the_duplicate_hostname_names_both_files() {
    let fixture = fixture("duplicate");
    let inventory = scan(&fixture);

    let finding = inventory
        .findings_of(FindingCode::DuplicateServerName)
        .find(|f| f.subject == "artisanhosting.net")
        .expect("artisanhosting.net is claimed by three server blocks");

    // Reported with every location, never auto-fixed: only a person knows
    // which one was meant.
    assert!(finding.evidence.len() >= 2, "{:?}", finding.evidence);
    assert!(
        finding.evidence.iter().any(|e| e.contains("artisanhosting_staging")),
        "{:?}",
        finding.evidence
    );
}

#[test]
fn a_half_edited_file_is_reported_and_contributes_nothing() {
    let fixture = fixture("unparsed");
    let inventory = scan(&fixture);

    let unparsed: Vec<&str> = inventory
        .findings_of(FindingCode::UnparsedFile)
        .map(|f| f.subject.as_str())
        .collect();
    assert!(unparsed.contains(&"sites-enabled/half_edited"), "{unparsed:?}");

    // Nothing from it may leak into the picture -- and, because includes are
    // expanded inline, its unclosed block must not swallow the files parsed
    // after it either.
    assert!(
        !inventory.nginx.servers.iter().any(|s| s.file == "sites-enabled/half_edited"),
        "a file we could not read must contribute no server blocks"
    );
    assert!(
        inventory.nginx.servers.iter().any(|s| s.file == "sites-enabled/legacy_client"),
        "one broken file must not cost us the rest of the tree"
    );
    assert!(
        !inventory.domains.iter().any(|d| d.fqdn == "half.example"),
        "and no domains"
    );
}

#[test]
fn the_healthy_domain_is_not_flagged_as_expiring() {
    let fixture = fixture("healthy");
    let inventory = scan(&fixture);

    let example = inventory
        .domains
        .iter()
        .find(|d| d.fqdn == "artisanhosting.net")
        .expect("artisanhosting.net must be in the inventory");

    assert!(example.serves_tls);
    assert!(example.in_domains_txt);
    assert_eq!(example.vhost_files.len(), 3, "apex, staging and redirect all serve it");
    assert!(example.cert_dirs.contains("_.artisanhosting.net"));
    assert!(example.upstreams.contains("http://artisan_release"));
    assert!(
        !example.findings.contains(&FindingCode::CertExpiring),
        "60 days out is not expiring"
    );
}

#[test]
fn adoption_does_not_queue_a_re_issue() {
    // The rate-limit trap: adopting a working system must not look like a
    // hundred certificates that all need renewing today.
    let fixture = fixture("no_reissue");
    let inventory = scan(&fixture);

    let example = inventory.domains.iter().find(|d| d.fqdn == "artisanhosting.net").unwrap();
    let expires_at = example.expires_at.expect("expiry read from the certificate on disk");
    let renew_after = expires_at - fixture.config.acme.renew_before_days * DAY;

    assert!(
        renew_after > NOW,
        "renewal must sit in the future, not trigger on adoption"
    );
}

#[test]
fn the_plan_suggests_nothing_it_cannot_justify() {
    let fixture = fixture("plan");
    let inventory = scan(&fixture);

    // No catalog: ais_auth unreachable, or no token given.
    let plan = plan::from_inventory(&inventory, plan::Catalog::default());

    assert!(
        plan.domains.iter().all(|d| d.suggested.is_none()),
        "with nothing to match against, every suggestion would be a guess"
    );
    assert!(
        plan.domains.iter().all(|d| d.assign.organization_id.is_none()),
        "and nothing may be pre-assigned"
    );

    // The orphan certificate is offered for quarantine, unticked.
    let orphan = plan
        .quarantine
        .iter()
        .find(|q| q.path.contains("_.orphan.example"))
        .expect("the orphan certificate directory is a quarantine candidate");
    assert!(!orphan.confirm, "the scanner never ticks the box");
}

#[test]
fn the_plan_round_trips_and_keeps_its_shape() {
    let fixture = fixture("roundtrip");
    let inventory = scan(&fixture);
    let plan = plan::from_inventory(&inventory, plan::Catalog::default());

    let json = plan.to_json().unwrap();
    let reloaded = plan::Plan::load(&json).unwrap();

    assert_eq!(reloaded.domains.len(), plan.domains.len());
    assert_eq!(reloaded.quarantine.len(), plan.quarantine.len());

    // The fields an operator edits must all be present in the emitted file,
    // or the instructions in the README are a lie.
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let first = &value["domains"][0];
    for key in ["fqdn", "assign", "action", "found_in", "vhosts", "certs", "findings"] {
        assert!(!first[key].is_null(), "plan domains must carry `{key}`: {first}");
    }
    assert!(value["catalog"].is_object());
    assert_eq!(value["schema_version"], plan::SCHEMA_VERSION);
}
