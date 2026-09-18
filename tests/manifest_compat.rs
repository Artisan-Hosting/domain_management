//! The release manifest must stay byte-identical to what `legacy/issuer`
//! produced, because the Go `nginx-r2-agent` on every edge parses it and is
//! not being changed in this phase.
//!
//! Rather than assert against a copy of the format, this runs the original
//! Python block from the script (lines 84-106 of `legacy/issuer`) over the
//! same fixture tree and compares the two outputs. If someone reorders a
//! field or changes the indentation, this fails.
//!
//! Skipped, not failed, when `python3` is unavailable, so the suite still
//! runs on a machine without it.

use ais_domains::publish::manifest::Manifest;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Verbatim from `legacy/issuer`. Do not "clean this up" -- its value is that
/// it is the code that actually ran in production.
const ISSUER_PYTHON: &str = r#"
import json, os, hashlib, sys, time, platform
tree_dir, release_id, manifest_path = sys.argv[1:]
files = []
for root, _, fs in os.walk(tree_dir):
    for f in fs:
        p = os.path.join(root, f)
        rel = os.path.relpath(p, tree_dir).replace("\\","/")
        h = hashlib.sha256()
        with open(p, "rb") as fp:
            for chunk in iter(lambda: fp.read(1024*1024), b""):
                h.update(chunk)
        files.append({"path": rel, "sha256": h.hexdigest(), "bytes": os.path.getsize(p)})
manifest = {
    "release_id": release_id,
    "created_unix": int(time.time()),
    "platform": platform.platform(),
    "file_count": len(files),
    "files": sorted(files, key=lambda x: x["path"]),
}
with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
"#;

fn have_python() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn fixture_tree(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ais_domains_compat_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    std::fs::create_dir_all(dir.join("certs/_.example.com")).unwrap();
    std::fs::create_dir_all(dir.join("certs/_.another-example.net")).unwrap();
    std::fs::create_dir_all(dir.join("sites")).unwrap();

    std::fs::write(dir.join("nginx.conf"), b"events {}\nhttp { include sites/*.conf; }\n").unwrap();
    std::fs::write(dir.join("sites/example.com.conf"), b"server { listen 443 ssl; }\n").unwrap();
    std::fs::write(dir.join("certs/_.example.com/ecc.pem"), b"-----BEGIN CERTIFICATE-----\n").unwrap();
    std::fs::write(dir.join("certs/_.example.com/ecc.key"), b"-----BEGIN PRIVATE KEY-----\n").unwrap();
    std::fs::write(dir.join("certs/_.example.com/rsa.pem"), b"-----BEGIN CERTIFICATE-----\nrsa\n").unwrap();
    std::fs::write(dir.join("certs/_.example.com/rsa.key"), b"-----BEGIN PRIVATE KEY-----\nrsa\n").unwrap();
    // A megabyte-plus file, so the chunked hashing path is exercised on both
    // sides rather than only the single-read one.
    std::fs::write(dir.join("certs/_.another-example.net/bundle.pem"), vec![b'x'; 1024 * 1024 + 7]).unwrap();

    dir
}

/// Returns the script's output both parsed and as the exact bytes it wrote.
fn python_manifest(tree: &Path, release_id: &str) -> (serde_json::Value, String) {
    let script = tree.parent().unwrap().join("issuer_manifest.py");
    std::fs::write(&script, ISSUER_PYTHON).unwrap();
    let out_path = tree.parent().unwrap().join("python_manifest.json");

    let status = Command::new("python3")
        .arg(&script)
        .arg(tree)
        .arg(release_id)
        .arg(&out_path)
        .status()
        .expect("running the original manifest script");
    assert!(status.success(), "the original manifest script failed");

    let raw = std::fs::read_to_string(&out_path).unwrap();
    (serde_json::from_str(&raw).unwrap(), raw)
}

#[test]
fn manifest_matches_the_original_issuer_script() {
    if !have_python() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let release_id = "2026-09-17T12-34-56Z";
    let tree = fixture_tree("match");

    let (theirs, _) = python_manifest(&tree, release_id);
    let ours: serde_json::Value =
        serde_json::from_str(&Manifest::build(&tree, release_id, 1_758_000_000).unwrap().to_json().unwrap())
            .unwrap();

    assert_eq!(ours["release_id"], theirs["release_id"]);
    assert_eq!(ours["file_count"], theirs["file_count"]);
    // Every path, hash and size must agree -- this is what the agent acts on.
    assert_eq!(ours["files"], theirs["files"], "file entries differ from the script's");

    // `created_unix` and `platform` are informational and differ by
    // construction (different clock reading, different platform string), but
    // both must still be present and of the right type.
    assert!(ours["created_unix"].is_i64() && theirs["created_unix"].is_i64());
    assert!(ours["platform"].is_string() && theirs["platform"].is_string());

    std::fs::remove_dir_all(&tree).ok();
}

#[test]
fn serialization_is_byte_identical_once_the_variable_fields_agree() {
    if !have_python() {
        eprintln!("skipping: python3 not available");
        return;
    }

    let release_id = "2026-09-17T12-34-56Z";
    let tree = fixture_tree("bytes");

    // Compared against the bytes the script actually wrote -- not against a
    // re-serialization of them, which would sort the keys and hide exactly
    // the kind of ordering drift this test exists to catch.
    let (theirs, theirs_text) = python_manifest(&tree, release_id);
    let created_unix = theirs["created_unix"].as_i64().unwrap();
    let platform = theirs["platform"].as_str().unwrap().to_owned();

    let mut ours = Manifest::build(&tree, release_id, created_unix).unwrap();
    // The only two fields that cannot match by construction: a different
    // clock reading and a different way of naming the platform.
    ours.platform = platform;

    assert_eq!(
        ours.to_json().unwrap(),
        theirs_text,
        "manifest serialization drifted from the script's output"
    );

    std::fs::remove_dir_all(&tree).ok();
}
