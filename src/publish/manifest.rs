//! The release manifest.
//!
//! **This format is a contract**, not an internal detail: the Go
//! `nginx-r2-agent` on every edge reads it to decide what to download. The
//! field names, their order, and the two-space indentation all match the
//! Python block in the old `issuer` script (lines 84-106 of
//! `legacy/issuer`), so a release published by this service is
//! indistinguishable from one published by the script it replaces.
//!
//! `src/publish/tests.rs` pins that: it runs the original Python against a
//! fixture tree and compares.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub release_id: String,
    pub created_unix: i64,
    pub platform: String,
    pub file_count: usize,
    pub files: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

impl Manifest {
    /// Walks `tree` and hashes every file.
    ///
    /// Entries are sorted by path, as the script's
    /// `sorted(files, key=lambda x: x["path"])` did -- a manifest whose order
    /// depended on directory iteration would produce a different file on
    /// every run for an unchanged tree.
    pub fn build(tree: &Path, release_id: &str, created_unix: i64) -> Result<Self> {
        let mut files = Vec::new();
        collect(tree, tree, &mut files)?;
        files.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self {
            release_id: release_id.to_owned(),
            created_unix,
            platform: platform_string(),
            file_count: files.len(),
            files,
        })
    }

    /// Serialized exactly as the script wrote it: two-space indent, no
    /// trailing newline (Python's `json.dump` adds none).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::Publish(format!("serializing manifest: {e}")))
    }

    pub fn sha256(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.to_json()?.as_bytes())))
    }
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<ManifestEntry>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::Publish(format!("reading {}: {e}", dir.display())))?;

    for entry in entries {
        let entry = entry.map_err(|e| Error::Publish(format!("reading {}: {e}", dir.display())))?;
        let path = entry.path();
        // `os.walk` follows the tree but lists only files; symlinks to files
        // are hashed by content, which is what file_type().is_file() gives us
        // here too since it follows links via metadata below.
        let meta = std::fs::metadata(&path)
            .map_err(|e| Error::Publish(format!("stat {}: {e}", path.display())))?;

        if meta.is_dir() {
            collect(root, &path, out)?;
            continue;
        }
        if !meta.is_file() {
            continue;
        }

        out.push(ManifestEntry {
            path: relative_path(root, &path)?,
            sha256: hash_file(&path)?,
            bytes: meta.len(),
        });
    }

    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|e| Error::Publish(format!("{} is not under {}: {e}", path.display(), root.display())))?;

    // The script normalized Windows separators; on Linux this is a no-op, but
    // keeping it means the two implementations cannot disagree.
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn hash_file(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|e| Error::Publish(format!("opening {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    // 1 MiB at a time, as the script did -- certificates are small but the
    // tree can hold anything.
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| Error::Publish(format!("reading {}: {e}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Stands in for Python's `platform.platform()`. Informational only -- the
/// agent does not act on it -- so an equivalent string is enough.
fn platform_string() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(release) => format!("{}-{}-{}", capitalize(os), release.trim(), arch),
        Err(_) => format!("{}-{}", capitalize(os), arch),
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

pub fn release_id(now: chrono::DateTime<chrono::Utc>) -> String {
    // `date -u +'%Y-%m-%dT%H-%M-%SZ'` from the script. Colons are avoided
    // because the id becomes part of an object key.
    now.format("%Y-%m-%dT%H-%M-%SZ").to_string()
}

/// Where a release's files live in the bucket.
///
/// Mirrors the layout `issuer` published and the agent reads:
/// `<prefix>/releases/<id>/tree/...`, `<prefix>/releases/<id>/manifest.json`,
/// and the pointer at `<prefix>/latest`.
///
/// NOTE: confirm against `internal/r2sync/r2sync.go` in the agent source on
/// the publisher host before the first non-shadow publish. The layout here is
/// taken from the script; the Go rewrite is assumed to have kept it, and a
/// mismatch means edges silently keep serving the previous release.
pub struct Keys {
    prefix: String,
}

impl Keys {
    pub fn new(prefix: &str) -> Self {
        Self { prefix: prefix.trim_matches('/').to_owned() }
    }

    fn join(&self, rest: &str) -> String {
        if self.prefix.is_empty() {
            rest.to_owned()
        } else {
            format!("{}/{}", self.prefix, rest)
        }
    }

    pub fn tree_file(&self, release_id: &str, relative: &str) -> String {
        self.join(&format!("releases/{release_id}/tree/{relative}"))
    }

    pub fn manifest(&self, release_id: &str) -> String {
        self.join(&format!("releases/{release_id}/manifest.json"))
    }

    pub fn latest(&self) -> String {
        self.join("latest")
    }

    pub fn release_prefix(&self, release_id: &str) -> String {
        self.join(&format!("releases/{release_id}/"))
    }

    pub fn releases_prefix(&self) -> String {
        self.join("releases/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_tree() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ais_domains_manifest_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(dir.join("certs/_.example.com")).unwrap();
        std::fs::write(dir.join("nginx.conf"), b"events {}\n").unwrap();
        std::fs::write(dir.join("certs/_.example.com/ecc.pem"), b"cert\n").unwrap();
        std::fs::write(dir.join("certs/_.example.com/ecc.key"), b"key\n").unwrap();
        dir
    }

    #[test]
    fn entries_are_sorted_and_counted() {
        let tree = fixture_tree();
        let manifest = Manifest::build(&tree, "2026-09-17T00-00-00Z", 1_758_000_000).unwrap();

        assert_eq!(manifest.file_count, 3);
        assert_eq!(manifest.files.len(), 3);
        let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "certs/_.example.com/ecc.key",
                "certs/_.example.com/ecc.pem",
                "nginx.conf"
            ]
        );

        std::fs::remove_dir_all(&tree).ok();
    }

    #[test]
    fn hashes_match_sha256_of_content() {
        let tree = fixture_tree();
        let manifest = Manifest::build(&tree, "r", 0).unwrap();

        let entry = manifest.files.iter().find(|f| f.path == "nginx.conf").unwrap();
        assert_eq!(entry.sha256, hex::encode(Sha256::digest(b"events {}\n")));
        assert_eq!(entry.bytes, 10);

        std::fs::remove_dir_all(&tree).ok();
    }

    #[test]
    fn json_field_order_matches_the_script() {
        let manifest = Manifest {
            release_id: "r".to_owned(),
            created_unix: 1,
            platform: "Linux".to_owned(),
            file_count: 1,
            files: vec![ManifestEntry {
                path: "a".to_owned(),
                sha256: "b".to_owned(),
                bytes: 2,
            }],
        };

        let json = manifest.to_json().unwrap();
        let order: Vec<usize> = ["release_id", "created_unix", "platform", "file_count", "files"]
            .iter()
            .map(|key| json.find(key).expect("key present"))
            .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "field order drifted: {json}");

        // Two-space indent, as `json.dump(..., indent=2)` produces.
        assert!(json.contains("\n  \"release_id\""), "{json}");
        assert!(json.contains("\n      \"path\""), "{json}");
    }

    #[test]
    fn keys_match_the_published_layout() {
        let keys = Keys::new("nginx");
        assert_eq!(
            keys.tree_file("2026-01-01T00-00-00Z", "certs/_.example.com/ecc.pem"),
            "nginx/releases/2026-01-01T00-00-00Z/tree/certs/_.example.com/ecc.pem"
        );
        assert_eq!(
            keys.manifest("2026-01-01T00-00-00Z"),
            "nginx/releases/2026-01-01T00-00-00Z/manifest.json"
        );
        assert_eq!(keys.latest(), "nginx/latest");
    }

    #[test]
    fn release_ids_are_filename_safe() {
        let id = release_id(
            chrono::DateTime::parse_from_rfc3339("2026-09-17T12:34:56Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        assert_eq!(id, "2026-09-17T12-34-56Z");
        assert!(!id.contains(':'), "colons break object keys and paths");
    }
}
