//! Attaching a domain to a runner's deployed instances, end to end.
//!
//! The workflow this covers: a repo is on some nodes, each instance's config
//! names a port, the caller sends `(node id, port)` for each, and what comes
//! out is a vhost pointing at `ahpn-<node id>.ah.internal:<port>` -- balanced
//! across them when there is more than one -- plus the certificate snippet
//! that links the pair.
//!
//! The part worth testing hardest is the failure: a vhost that does not pass
//! `nginx -t` must leave the tree exactly as it was, because a tree that
//! cannot be published takes every *other* domain down with it.

use ais_domains::config::Config;
use ais_domains::vhost::render::{Backend, VhostOutcome, VhostSpec};
use ais_domains::vhost::snippet::SnippetOutcome;
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

/// `nginx_ok` decides whether the stub nginx accepts the tree.
fn fixture(name: &str, nginx_ok: bool, with_certs: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "ais_domains_attach_{name}_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let tree = root.join("tree");

    write(&tree.join("nginx.conf"), "events {}\nhttp {\n    include sites-enabled/*;\n}\n");
    write(&tree.join("snippets/ssl-params.conf"), "ssl_protocols TLSv1.2 TLSv1.3;\n");
    std::fs::create_dir_all(tree.join("sites-enabled")).unwrap();

    if with_certs {
        // Issuance would have put these here, along with the snippet.
        for key_type in ["ecc", "rsa"] {
            write(
                &tree.join(format!("certs/_.example.com/{key_type}.pem")),
                "-----BEGIN CERTIFICATE-----\n",
            );
            write(
                &tree.join(format!("certs/_.example.com/{key_type}.key")),
                "-----BEGIN PRIVATE KEY-----\n",
            );
        }
    }

    let nginx = root.join("fake-nginx");
    std::fs::write(
        &nginx,
        if nginx_ok {
            "#!/bin/sh\necho 'test is successful' >&2\nexit 0\n"
        } else {
            "#!/bin/sh\necho 'emerg: cannot load certificate' >&2\nexit 1\n"
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

fn spec(backends: Vec<Backend>) -> VhostSpec {
    let mut spec = VhostSpec::new("example.com", "ab12cd34", backends);
    spec.extra_names = vec!["www.example.com".to_owned()];
    spec
}

#[tokio::test]
async fn attaching_two_instances_writes_a_balanced_vhost_and_its_snippet() {
    let f = fixture("balanced", true, true);

    let outcome = ais_domains::vhost::attach(
        &f.config,
        &spec(vec![
            Backend::Node { node_id: "2973453917896704".to_owned(), port: 8093 },
            Backend::Node { node_id: "3091229306929152".to_owned(), port: 8093 },
        ]),
    )
    .await
    .unwrap();

    assert!(matches!(outcome.snippet, SnippetOutcome::Created(_)));
    assert!(matches!(outcome.vhost, VhostOutcome::Created(_)));

    let vhost = std::fs::read_to_string(f.config.vhost_path_for("example.com")).unwrap();
    assert!(vhost.contains("server_name example.com www.example.com;"));
    assert!(vhost.contains("include snippets/example_cert.conf;"));
    assert!(vhost.contains("server ahpn-2973453917896704.ah.internal:8093 max_fails=10 fail_timeout=10s;"));
    assert!(vhost.contains("server ahpn-3091229306929152.ah.internal:8093 max_fails=10 fail_timeout=10s;"));
    assert!(vhost.contains("random;"), "two instances get balanced");

    // The snippet points at the deployed paths, not the publisher's.
    let snippet = std::fs::read_to_string(f.config.snippet_path_for("example.com")).unwrap();
    assert!(snippet.contains("/etc/nginx/certs/_.example.com/ecc.pem"));
    assert!(snippet.contains("/etc/nginx/certs/_.example.com/rsa.pem"));
}

#[tokio::test]
async fn scaling_out_rewrites_the_upstream_only() {
    let f = fixture("scale", true, true);
    let one = vec![Backend::Node { node_id: "node1".to_owned(), port: 8093 }];

    ais_domains::vhost::attach(&f.config, &spec(one.clone())).await.unwrap();
    let before = std::fs::read_to_string(f.config.vhost_path_for("example.com")).unwrap();
    assert!(!before.contains("random;"));

    let mut two = one;
    two.push(Backend::Node { node_id: "node2".to_owned(), port: 8093 });
    let outcome = ais_domains::vhost::attach(&f.config, &spec(two)).await.unwrap();

    assert!(matches!(outcome.vhost, VhostOutcome::Updated(_)));
    assert!(
        matches!(outcome.snippet, SnippetOutcome::Unchanged(_)),
        "the certificate did not change, so neither did its snippet"
    );

    let after = std::fs::read_to_string(f.config.vhost_path_for("example.com")).unwrap();
    assert!(after.contains("random;"));
    assert!(after.contains("ahpn-node2.ah.internal:8093"));
}

#[tokio::test]
async fn a_vhost_nginx_rejects_leaves_no_trace() {
    let f = fixture("rejected", false, true);

    let err = ais_domains::vhost::attach(
        &f.config,
        &spec(vec![Backend::Node { node_id: "node1".to_owned(), port: 8093 }]),
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("config test failed"), "{err}");
    assert!(
        !f.config.vhost_path_for("example.com").exists(),
        "a vhost that would break the tree must not be left in it"
    );
}

#[tokio::test]
async fn a_rejected_rewrite_restores_what_was_there() {
    // The worse case: the domain was already serving, and re-attaching it
    // with a bad set of instances must not cost it its working vhost.
    let f = fixture("restore", true, true);
    let good = vec![Backend::Node { node_id: "node1".to_owned(), port: 8093 }];
    ais_domains::vhost::attach(&f.config, &spec(good)).await.unwrap();

    let working = std::fs::read_to_string(f.config.vhost_path_for("example.com")).unwrap();

    // nginx now rejects everything.
    std::fs::write(
        &f.config.tree.nginx_bin,
        "#!/bin/sh\necho 'emerg: bad config' >&2\nexit 1\n",
    )
    .unwrap();

    let err = ais_domains::vhost::attach(
        &f.config,
        &spec(vec![Backend::Node { node_id: "node9".to_owned(), port: 9999 }]),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("config test failed"), "{err}");

    assert_eq!(
        std::fs::read_to_string(f.config.vhost_path_for("example.com")).unwrap(),
        working,
        "the vhost that was serving traffic must come back byte for byte"
    );
}

#[tokio::test]
async fn attaching_before_the_certificate_exists_says_so() {
    let f = fixture("nocert", true, false);

    let err = ais_domains::vhost::attach(
        &f.config,
        &spec(vec![Backend::Node { node_id: "node1".to_owned(), port: 8093 }]),
    )
    .await
    .unwrap_err();

    // Refused before anything is written, with the reason a person can act on.
    assert!(err.to_string().contains("no certificate yet"), "{err}");
    assert!(err.to_string().contains("ecc.pem and rsa.pem"), "{err}");
    assert!(!f.config.vhost_path_for("example.com").exists());
    assert!(!f.config.snippet_path_for("example.com").exists());
}

#[tokio::test]
async fn a_hand_written_vhost_survives_an_attach() {
    let f = fixture("handwritten", true, true);
    let path = f.config.vhost_path_for("example.com");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    // The real thing: CORS rules and OPTIONS handling no template reproduces.
    let original = "server {\n    listen 443 ssl http2;\n    server_name example.com;\n\
                    include snippets/example_cert.conf;\n\
                    location / {\n        add_header 'Access-Control-Allow-Origin' '*';\n\
                    if ($request_method = 'OPTIONS') { return 204; }\n\
                    proxy_pass http://10.1.0.5:8080;\n    }\n}\n";
    std::fs::write(&path, original).unwrap();

    let outcome = ais_domains::vhost::attach(
        &f.config,
        &spec(vec![Backend::Node { node_id: "node1".to_owned(), port: 8093 }]),
    )
    .await
    .unwrap();

    match &outcome.vhost {
        VhostOutcome::HandWritten { would_be, .. } => {
            assert!(would_be.contains("ahpn-node1.ah.internal:8093"));
        }
        other => panic!("a hand-written vhost must not be replaced: {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}
