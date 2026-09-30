//! The freeform escape hatch, end to end, against the three real
//! hand-written vhosts that motivated it: a multi-backend node-id upstream
//! with CORS/OPTIONS handling, a bare static IP:port backend, and an HTTPS
//! backend with a self-signed cert plus a websocket location.
//!
//! Like `attach_vhost.rs`, `nginx -t` is stood in for by a stub script --
//! this exercises the staging/apply pipeline and this service's own lint
//! pass, not real nginx syntax checking.

use ais_domains::config::Config;
use ais_domains::inventory::nginx::FREEFORM_MANAGED_HEADER;
use ais_domains::vhost::freeform;
use std::path::{Path, PathBuf};

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

fn fixture(name: &str, nginx_ok: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "ais_domains_freeform_{name}_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let tree = root.join("tree");

    write(&tree.join("nginx.conf"), "events {}\nhttp {\n    include sites-enabled/*;\n}\n");
    write(&tree.join("snippets/ssl-params.conf"), "ssl_protocols TLSv1.2 TLSv1.3;\n");
    std::fs::create_dir_all(tree.join("sites-enabled")).unwrap();

    let nginx = root.join("fake-nginx");
    std::fs::write(
        &nginx,
        if nginx_ok {
            "#!/bin/sh\necho 'test is successful' >&2\nexit 0\n"
        } else {
            "#!/bin/sh\necho 'emerg: unexpected \"}\" in config' >&2\nexit 1\n"
        },
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nginx, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut config = Config::default();
    config.tree.root = tree;
    config.tree.work_root = root.join("work");
    config.tree.nginx_bin = nginx;

    Fixture { root, config }
}

const ARTISANHOSTING: &str = r#"
server {
    listen 443 ssl http2;
    server_name www.artisanhosting.net artisanhosting.net;
    include snippets/artisanhosting_cert.conf;
    include snippets/ssl-params.conf;
    location / {
        add_header 'Access-Control-Allow-Origin' '*';
        if ($request_method = 'OPTIONS') { return 204; }
        proxy_pass http://artisan_release;
        proxy_set_header Host $host;
    }
}
upstream artisan_release {
    random;
    server ahpn-2973453917896704.ah.internal:8093 max_fails=10 fail_timeout=10s;
    server ahpn-3091229306929152.ah.internal:8093 max_fails=10 fail_timeout=10s;
}
"#;

const DYWNOTARY: &str = r#"
server {
    listen 443 ssl http2;
    server_name dywnotary.com;
    include snippets/dywnotary_cert.conf;
    include snippets/ssl-params.conf;
    location / {
        proxy_pass http://10.4.1.2:4000;
        proxy_set_header Host $host;
    }
}
"#;

const ARTISANSTUDIO_ANALYTICS: &str = r#"
server {
    listen 443 ssl http2;
    server_name analytics.artisanstudio.net;
    include snippets/artisanstudio_cert.conf;
    include snippets/ssl-params.conf;
    location / {
        proxy_pass https://192.168.0.30:443;
        proxy_ssl_verify off;
        add_header Content-Security-Policy "frame-ancestors 'self'" always;
    }
    location /live/websocket {
        proxy_pass https://192.168.0.30:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_ssl_verify off;
    }
    location ~ /\. {
        deny all;
    }
}
"#;

#[tokio::test]
async fn all_three_real_configs_validate_against_an_accepting_nginx() {
    for (name, fqdn, body) in [
        ("artisanhosting", "artisanhosting.net", ARTISANHOSTING),
        ("dywnotary", "dywnotary.com", DYWNOTARY),
        ("artisanstudio-analytics", "analytics.artisanstudio.net", ARTISANSTUDIO_ANALYTICS),
    ] {
        let f = fixture(name, true);
        let outcome = freeform::validate(&f.config, fqdn, body).await.unwrap();
        assert!(outcome.nginx_ok, "{name}: {}", outcome.nginx_output);
    }
}

#[tokio::test]
async fn a_config_nginx_rejects_reports_the_diagnostic_and_no_new_findings() {
    let f = fixture("broken", false);
    let broken = "server {\n    listen 443 ssl http2;\n    server_name example.com\n"; // no closing brace
    let outcome = freeform::validate(&f.config, "example.com", broken).await.unwrap();

    assert!(!outcome.nginx_ok);
    assert!(outcome.nginx_output.contains("emerg"), "{}", outcome.nginx_output);
    assert!(outcome.new_findings.is_empty(), "a lint diff on an invalid config is noise");
}

#[tokio::test]
async fn applying_stamps_the_freeform_header_and_is_never_touched_by_the_structured_path() {
    let f = fixture("apply", true);

    let outcome = freeform::apply(&f.config, "dywnotary.com", DYWNOTARY, false).await.unwrap();
    assert!(outcome.applied);

    let path = f.config.vhost_path_for("dywnotary.com");
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains(FREEFORM_MANAGED_HEADER), "{on_disk}");
    assert!(on_disk.contains("proxy_pass http://10.4.1.2:4000;"), "{on_disk}");
}

#[tokio::test]
async fn a_dry_run_apply_writes_nothing() {
    let f = fixture("dry-run", true);

    let outcome = freeform::apply(&f.config, "dywnotary.com", DYWNOTARY, true).await.unwrap();
    assert!(!outcome.applied);

    let path = f.config.vhost_path_for("dywnotary.com");
    assert!(!path.exists(), "a dry run must never touch the live tree");
}

#[tokio::test]
async fn re_applying_to_the_same_domain_updates_the_same_file_in_place() {
    let f = fixture("re-apply", true);
    let path = f.config.vhost_path_for("dywnotary.com");

    freeform::apply(&f.config, "dywnotary.com", DYWNOTARY, false).await.unwrap();
    let first = std::fs::read_to_string(&path).unwrap();

    let changed = DYWNOTARY.replace("10.4.1.2:4000", "10.4.1.2:4001");
    let outcome = freeform::apply(&f.config, "dywnotary.com", &changed, false).await.unwrap();
    let second = std::fs::read_to_string(&path).unwrap();

    assert!(outcome.applied);
    assert_ne!(first, second);
    assert!(second.contains("10.4.1.2:4001"));
    assert!(!outcome.diff.is_empty(), "a real content change should produce a non-empty diff");
}

#[tokio::test]
async fn an_invalid_submission_is_never_applied() {
    let f = fixture("invalid-apply", false);
    let broken = "server {\n    listen 443 ssl http2;\n    server_name example.com\n";

    let err = freeform::apply(&f.config, "example.com", broken, false).await.unwrap_err();
    assert!(err.to_string().contains("nginx rejected"), "{err}");
    assert!(!f.config.vhost_path_for("example.com").exists());
}
