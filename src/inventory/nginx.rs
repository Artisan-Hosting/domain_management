//! A tolerant scanner for the nginx tree.
//!
//! Not a parser: it does not build an AST, validate directives, or attempt to
//! understand nginx semantics. It walks the config the way a person skimming
//! it would -- find the `server` blocks, note what each one serves, which
//! certificate it points at, and where it sends traffic -- and shrugs at
//! everything else.
//!
//! That is a deliberate trade. The `nginx-config` crate builds a real AST,
//! and a real AST means a hard failure the first time it meets a directive
//! from a module it does not know. This has to run against a tree nobody has
//! catalogued, written over years, so it is built to degrade instead: a file
//! it cannot make structural sense of is reported as `unparsed_file` and then
//! left strictly alone -- never adopted, never rewritten, never quarantined
//! automatically.
//!
//! **Includes are expanded inline**, as nginx does them, and that is not a
//! detail. In this tree a vhost does not name its certificate; it says
//! `include snippets/artisanhosting_cert.conf;` and the certificate lines
//! live in that snippet, shared by every site on the zone. A scanner that
//! treated an include as "another file to visit later" would parse those
//! lines outside any `server` block and conclude that not one vhost in the
//! fleet has a certificate.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// How deep `include` chains may nest before we assume a cycle.
const MAX_INCLUDE_DEPTH: usize = 16;

/// Marks a file this service generated from a structured [`crate::vhost::render::VhostSpec`].
/// Only files carrying it are ever rewritten by that structured path;
/// everything else is somebody's handiwork.
pub const MANAGED_HEADER: &str = "managed by ais_domains";

/// Marks a file applied through [`crate::vhost::freeform`]. Deliberately does
/// not contain [`MANAGED_HEADER`] as a substring: a freeform submission is
/// "owned" in the sense that the freeform API can update it again, but the
/// structured `render::write()` path must never touch it, exactly like a
/// genuinely hand-written file.
pub const FREEFORM_MANAGED_HEADER: &str = "applied via ais_domains freeform vhost";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxIndex {
    pub files: Vec<ConfigFile>,
    pub servers: Vec<ServerBlock>,
    /// The `snippets/` directory read on its own terms, whether or not
    /// anything includes each file. A certificate with no snippet pointing at
    /// it cannot be served by anything, and that is invisible from the
    /// include graph alone.
    pub snippets: Vec<SnippetFile>,
}

/// A file in `snippets/`, indexed for the certificates it names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetFile {
    pub path: String,
    /// `ssl_certificate` paths as written, regardless of block context.
    pub cert_paths: Vec<String>,
    pub managed: bool,
    /// Vhost files whose `include` pulls this snippet in.
    pub included_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    /// Relative to the tree root when it lives inside it; absolute otherwise.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    /// True when the file carries [`MANAGED_HEADER`].
    pub managed: bool,
    /// How it was reached: `None` for the entry point or for a file nothing
    /// includes, otherwise the file that `include`d it.
    pub included_from: Option<String>,
    /// Set when the structure did not hold together. Its servers are
    /// discarded, because a file with unbalanced braces cannot be read
    /// reliably and guessing is worse than admitting ignorance.
    pub parse_error: Option<String>,
    /// Nothing includes this file, so none of it is in effect.
    pub unreferenced: bool,
}

/// A certificate path as a config actually gives it, with where it was said.
///
/// The provenance matters: almost every certificate line in this tree comes
/// from a shared snippet, so "which file do I edit" is a different question
/// from "which vhost is affected".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRef {
    pub path: String,
    /// The file the directive was written in -- usually a snippet, not the
    /// vhost.
    pub from_file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerBlock {
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
    pub server_names: Vec<String>,
    pub listens: Vec<String>,
    /// Every `ssl_certificate` in effect, snippets included. There are
    /// normally two -- ECDSA and RSA -- and nginx serves whichever the
    /// handshake asks for.
    pub ssl_certificates: Vec<CertRef>,
    pub ssl_certificate_keys: Vec<CertRef>,
    /// Snippets this block pulled in, in order.
    pub includes: Vec<String>,
    /// Every `proxy_pass` found in the block, nested `location`s included.
    pub proxy_passes: Vec<String>,
    pub root: Option<String>,
    /// Serves no content of its own -- a redirect or a fixed response.
    pub redirect_only: bool,
    /// A `server` inside a `stream` block: layer 4, no `server_name`, not a
    /// vhost.
    pub stream: bool,
}

impl ServerBlock {
    pub fn is_tls(&self) -> bool {
        !self.ssl_certificates.is_empty()
            || self.listens.iter().any(|l| l.contains("ssl") || l.contains("443"))
    }

    /// Server names excluding nginx's catch-alls, which are not domains.
    pub fn real_names(&self) -> impl Iterator<Item = &String> {
        self.server_names.iter().filter(|name| name.as_str() != "_" && !name.is_empty())
    }
}

/// Scans the tree starting from `nginx.conf`, following `include` directives.
///
/// Following includes rather than globbing matters twice over: a file in the
/// tree that nothing includes is *not* live, and the certificate lines only
/// make sense in the context of the `server` block that pulled them in.
pub fn scan_tree(tree_root: &Path, snippets_dir: &str) -> Result<NginxIndex> {
    let entry = tree_root.join("nginx.conf");

    let mut scanner = Scanner {
        tree_root: tree_root.to_path_buf(),
        index: NginxIndex { files: Vec::new(), servers: Vec::new(), snippets: Vec::new() },
        visited: HashSet::new(),
    };

    if entry.exists() {
        // `scan_file` rewinds the context after any file whose structure did
        // not close, so an unbalanced snippet costs that snippet and nothing
        // else.
        let mut ctx = ParseCtx::default();
        scanner.scan_file(&entry, None, 0, &mut ctx)?;
    }

    scanner.collect_unreferenced(tree_root)?;
    scanner.index.snippets = scan_snippets(tree_root, snippets_dir, &scanner.index.servers);

    Ok(scanner.index)
}

/// Reads `snippets/` directly.
///
/// Deliberately independent of the include graph: the question this answers
/// is "does a snippet linking this certificate exist at all", which is the
/// step that gets forgotten when a certificate is issued by hand.
fn scan_snippets(tree_root: &Path, snippets_dir: &str, servers: &[ServerBlock]) -> Vec<SnippetFile> {
    let dir = tree_root.join(snippets_dir);
    let mut out = Vec::new();

    let Ok(entries) = std::fs::read_dir(&dir) else { return out };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else { continue };

        let relative = path
            .strip_prefix(tree_root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());

        let cert_paths = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let rest = line.strip_prefix("ssl_certificate")?;
                // `ssl_certificate_key` is the key half; the directory is the
                // same either way, so one of the two is enough.
                if rest.starts_with("_key") {
                    return None;
                }
                Some(rest.trim().trim_end_matches(';').trim().to_owned())
            })
            .filter(|value| !value.is_empty())
            .collect();

        let included_by = servers
            .iter()
            .filter(|server| {
                server.includes.iter().any(|pattern| {
                    // `include snippets/artisanhosting_cert.conf;`
                    relative.ends_with(pattern.trim_start_matches('/'))
                        || pattern.ends_with(&relative)
                })
            })
            .map(|server| server.file.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        out.push(SnippetFile {
            path: relative,
            cert_paths,
            managed: raw.contains(MANAGED_HEADER),
            included_by,
        });
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

struct Scanner {
    tree_root: PathBuf,
    index: NginxIndex,
    visited: HashSet<PathBuf>,
}

/// Parse state carried *across* files, so an include picks up where the
/// including file left off.
#[derive(Default)]
struct ParseCtx {
    /// (block name, line it opened on)
    stack: Vec<(String, usize)>,
    current: Option<ServerBlock>,
    /// True while inside a `stream { }` block.
    in_stream: bool,
}

impl Scanner {
    fn scan_file(
        &mut self,
        path: &Path,
        included_from: Option<&Path>,
        depth: usize,
        ctx: &mut ParseCtx,
    ) -> Result<()> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if depth > MAX_INCLUDE_DEPTH {
            return Err(Error::Nginx(format!(
                "include nesting deeper than {MAX_INCLUDE_DEPTH} at {}",
                path.display()
            )));
        }

        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) => {
                self.index.files.push(ConfigFile {
                    path: self.display_path(path),
                    sha256: String::new(),
                    bytes: 0,
                    managed: false,
                    included_from: included_from.map(|p| self.display_path(p)),
                    parse_error: Some(format!("unreadable: {err}")),
                    unreferenced: false,
                });
                return Ok(());
            }
        };

        let file_label = self.display_path(path);
        let already_seen = !self.visited.insert(canonical);

        self.index.files.push(ConfigFile {
            path: file_label.clone(),
            sha256: sha256_of(raw.as_bytes()),
            bytes: raw.len() as u64,
            managed: raw.contains(MANAGED_HEADER),
            included_from: included_from.map(|p| self.display_path(p)),
            parse_error: None,
            unreferenced: false,
        });

        if already_seen && included_from.is_none() {
            // Re-entered through a cycle with no new context to add.
            return Ok(());
        }

        let file_index = self.index.files.len() - 1;
        let servers_before = self.index.servers.len();
        // Where the parse state stood before this file touched it. Includes
        // share context by design, so a file that opens a block it never
        // closes would otherwise corrupt every file parsed after it -- and
        // one half-edited snippet would take the whole tree down with it.
        let stack_at_entry = ctx.stack.len();
        let had_server = ctx.current.is_some();

        let outcome = self.parse(&raw, &file_label, path, depth, ctx);

        let structural_error = match outcome {
            Err(message) => Some(message),
            Ok(()) if ctx.stack.len() != stack_at_entry => {
                let (name, line) = ctx
                    .stack
                    .last()
                    .cloned()
                    .unwrap_or_else(|| ("?".to_owned(), 0));
                Some(format!("unclosed '{name}' block opened on line {line}"))
            }
            Ok(()) => None,
        };

        if let Some(message) = structural_error {
            self.index.files[file_index].parse_error = Some(message);
            // Anything this file produced is suspect; drop it and rewind the
            // context to exactly where the file found it, so the rest of the
            // tree parses as though the include had not happened.
            self.index.servers.truncate(servers_before);
            ctx.stack.truncate(stack_at_entry);
            if !had_server {
                ctx.current = None;
            }
        }

        Ok(())
    }

    /// The scanner proper. Errors are structural only.
    fn parse(
        &mut self,
        raw: &str,
        file_label: &str,
        path: &Path,
        depth: usize,
        ctx: &mut ParseCtx,
    ) -> std::result::Result<(), String> {
        let depth_at_entry = ctx.stack.len();

        let mut token = String::new();
        let mut args: Vec<String> = Vec::new();
        let mut line = 1usize;
        let mut in_comment = false;
        let mut quote: Option<char> = None;

        for c in raw.chars() {
            if c == '\n' {
                line += 1;
                in_comment = false;
                continue;
            }
            if in_comment {
                continue;
            }

            if let Some(q) = quote {
                if c == q {
                    quote = None;
                } else {
                    token.push(c);
                }
                continue;
            }

            match c {
                '#' => in_comment = true,
                '"' | '\'' => quote = Some(c),
                '{' => {
                    flush(&mut token, &mut args);
                    let name = args.first().cloned().unwrap_or_default();

                    if name == "stream" {
                        ctx.in_stream = true;
                    }

                    // `upstream` blocks contain `server` *directives*; only a
                    // top-level `server` block is a vhost.
                    if name == "server" && !ctx.stack.iter().any(|(n, _)| n == "server") {
                        ctx.current = Some(ServerBlock {
                            file: file_label.to_owned(),
                            line_start: line,
                            line_end: line,
                            server_names: Vec::new(),
                            listens: Vec::new(),
                            ssl_certificates: Vec::new(),
                            ssl_certificate_keys: Vec::new(),
                            includes: Vec::new(),
                            proxy_passes: Vec::new(),
                            root: None,
                            redirect_only: false,
                            stream: ctx.in_stream,
                        });
                    }

                    ctx.stack.push((name, line));
                    args.clear();
                }
                '}' => {
                    flush(&mut token, &mut args);
                    args.clear();

                    match ctx.stack.pop() {
                        Some((name, _)) => {
                            if name == "stream" {
                                ctx.in_stream = false;
                            }
                            if name == "server" {
                                if let Some(mut server) = ctx.current.take() {
                                    server.line_end = line;
                                    self.index.servers.push(server);
                                }
                            }
                        }
                        None => return Err(format!("unexpected '}}' on line {line}")),
                    }
                }
                ';' => {
                    flush(&mut token, &mut args);
                    self.apply_directive(&args, line, file_label, path, depth, ctx)?;
                    args.clear();
                }
                c if c.is_whitespace() => flush(&mut token, &mut args),
                c => token.push(c),
            }
        }

        flush(&mut token, &mut args);

        // Closing more than was opened is caught here; leaving something
        // open is caught by the caller, which also knows how to rewind.
        if ctx.stack.len() < depth_at_entry {
            return Err("a block was closed that this file did not open".to_owned());
        }

        Ok(())
    }

    fn apply_directive(
        &mut self,
        args: &[String],
        line: usize,
        file_label: &str,
        path: &Path,
        depth: usize,
        ctx: &mut ParseCtx,
    ) -> std::result::Result<(), String> {
        let Some(name) = args.first() else { return Ok(()) };

        if name == "include" {
            let Some(pattern) = args.get(1) else { return Ok(()) };

            if let Some(server) = ctx.current.as_mut() {
                server.includes.push(pattern.clone());
            }

            // Expanded here and now, in this context, exactly as nginx does
            // it -- which is how a snippet's ssl_certificate lines end up
            // attached to the server block that pulled them in.
            for target in self.resolve_include(pattern) {
                if let Err(err) = self.scan_file(&target, Some(path), depth + 1, ctx) {
                    return Err(err.to_string());
                }
            }
            return Ok(());
        }

        let Some(server) = ctx.current.as_mut() else { return Ok(()) };

        match name.as_str() {
            // `server_name a.com b.com;` -- one directive, many names.
            "server_name" => server.server_names.extend(args[1..].iter().cloned()),
            "listen" => server.listens.push(args[1..].join(" ")),
            "ssl_certificate" => {
                if let Some(value) = args.get(1) {
                    server.ssl_certificates.push(CertRef {
                        path: value.clone(),
                        from_file: file_label.to_owned(),
                        line,
                    });
                }
            }
            "ssl_certificate_key" => {
                if let Some(value) = args.get(1) {
                    server.ssl_certificate_keys.push(CertRef {
                        path: value.clone(),
                        from_file: file_label.to_owned(),
                        line,
                    });
                }
            }
            "proxy_pass" => {
                if let Some(target) = args.get(1) {
                    server.proxy_passes.push(target.clone());
                }
            }
            "root" => server.root = args.get(1).cloned(),
            "return" | "rewrite" => server.redirect_only = true,
            _ => {}
        }

        Ok(())
    }

    /// Resolves an `include` argument, expanding globs.
    ///
    /// Relative paths resolve against the tree root (nginx's prefix), as
    /// nginx reads them -- not against the including file's directory.
    fn resolve_include(&self, pattern: &str) -> Vec<PathBuf> {
        let joined = if pattern.starts_with('/') {
            PathBuf::from(pattern)
        } else {
            self.tree_root.join(pattern)
        };

        if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') {
            return if joined.exists() { vec![joined] } else { Vec::new() };
        }

        match glob::glob(&joined.to_string_lossy()) {
            Ok(paths) => {
                let mut found: Vec<PathBuf> = paths.flatten().filter(|p| p.is_file()).collect();
                // nginx includes glob matches in sorted order; matching that
                // keeps "which duplicate wins" reproducible.
                found.sort();
                found
            }
            Err(_) => Vec::new(),
        }
    }

    /// Config files nothing includes.
    ///
    /// Limited to the directories where a config file exists to be included
    /// -- sites and snippets. Elsewhere in the tree an unreferenced file is
    /// usually an asset, not a mistake. Extensions are not assumed: the
    /// vhosts in this fleet are named `artisanhosting`, not
    /// `artisanhosting.conf`.
    fn collect_unreferenced(&mut self, tree_root: &Path) -> Result<()> {
        for dir in ["sites-enabled", "sites-available", "sites", "snippets", "streams-enabled", "conf.d"] {
            let dir_path = tree_root.join(dir);
            if !dir_path.is_dir() {
                continue;
            }

            let entries = match std::fs::read_dir(&dir_path) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
                if self.visited.contains(&canonical) {
                    continue;
                }

                let raw = std::fs::read_to_string(&path).unwrap_or_default();
                self.index.files.push(ConfigFile {
                    path: self.display_path(&path),
                    sha256: sha256_of(raw.as_bytes()),
                    bytes: raw.len() as u64,
                    managed: raw.contains(MANAGED_HEADER),
                    included_from: None,
                    parse_error: None,
                    unreferenced: true,
                });
            }
        }

        Ok(())
    }

    fn display_path(&self, path: &Path) -> String {
        path.strip_prefix(&self.tree_root)
            .map(|relative| relative.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned())
    }
}

fn flush(token: &mut String, args: &mut Vec<String>) {
    if !token.is_empty() {
        args.push(std::mem::take(token));
    }
}

fn sha256_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tree(PathBuf);

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tree(name: &str) -> Tree {
        let root = std::env::temp_dir().join(format!(
            "ais_domains_nginx_{name}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Tree(root)
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn a_snippet_include_attaches_its_certificates_to_the_vhost() {
        // The shape this fleet actually uses: the vhost names no certificate,
        // a shared snippet carries both, and the snippet is included from
        // inside the server block.
        let t = tree("snippet");
        write(&t.0, "nginx.conf", "events {}\nhttp { include sites-enabled/*; }\n");
        write(
            &t.0,
            "snippets/artisanhosting_cert.conf",
            "ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/ecc.pem;\n\
             ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/ecc.key;\n\
             ssl_certificate     /etc/nginx/certs/_.artisanhosting.net/rsa.pem;\n\
             ssl_certificate_key /etc/nginx/certs/_.artisanhosting.net/rsa.key;\n",
        );
        write(
            &t.0,
            "sites-enabled/artisanhosting",
            "server {\n    listen 443 ssl http2;\n    server_name www.artisanhosting.net artisanhosting.net;\n\
             \n    include snippets/artisanhosting_cert.conf;\n    include snippets/ssl-params.conf;\n\
             \n    location / { proxy_pass http://artisan_release; }\n}\n",
        );
        write(&t.0, "snippets/ssl-params.conf", "ssl_protocols TLSv1.2 TLSv1.3;\n");

        let index = scan_tree(&t.0, "snippets").unwrap();

        assert_eq!(index.servers.len(), 1);
        let server = &index.servers[0];
        assert_eq!(
            server.server_names,
            vec!["www.artisanhosting.net", "artisanhosting.net"]
        );
        assert_eq!(
            server.ssl_certificates.len(),
            2,
            "both the ECDSA and RSA certificates are in effect"
        );
        assert_eq!(server.ssl_certificate_keys.len(), 2);
        // And it knows the certificate came from the snippet, not the vhost.
        assert_eq!(
            server.ssl_certificates[0].from_file,
            "snippets/artisanhosting_cert.conf"
        );
        assert!(server.is_tls());
        assert_eq!(server.includes.len(), 2);
    }

    #[test]
    fn one_snippet_serves_many_vhosts() {
        let t = tree("shared");
        write(&t.0, "nginx.conf", "events {}\nhttp { include sites-enabled/*; }\n");
        write(
            &t.0,
            "snippets/artisanstudio_cert.conf",
            "ssl_certificate     /etc/nginx/certs/_.artisanstudio.net/ecc.pem;\n\
             ssl_certificate_key /etc/nginx/certs/_.artisanstudio.net/ecc.key;\n",
        );
        for n in 1..=3 {
            write(
                &t.0,
                &format!("sites-enabled/link{n}_artisanstudio"),
                &format!(
                    "server {{\n    listen 443 ssl http2;\n    server_name link{n}.artisanstudio.net;\n\
                     include snippets/artisanstudio_cert.conf;\n\
                     location / {{ proxy_pass http://10.4.1.2:401{n}; }}\n}}\n"
                ),
            );
        }

        let index = scan_tree(&t.0, "snippets").unwrap();

        assert_eq!(index.servers.len(), 3);
        for server in &index.servers {
            assert_eq!(
                server.ssl_certificates.len(),
                1,
                "each vhost gets the shared snippet's certificate, once"
            );
        }
        // The snippet is visited once per include, and recorded each time
        // with the file that pulled it in.
        let snippet_visits = index
            .files
            .iter()
            .filter(|f| f.path == "snippets/artisanstudio_cert.conf")
            .count();
        assert_eq!(snippet_visits, 3);
    }

    #[test]
    fn vhosts_without_a_conf_extension_are_found() {
        // `sites-enabled/artisanhosting`, not `artisanhosting.conf`.
        let t = tree("noext");
        write(&t.0, "nginx.conf", "events {}\nhttp { include sites-enabled/*; }\n");
        write(&t.0, "sites-enabled/artisanhosting", "server { server_name a.com; }\n");

        let index = scan_tree(&t.0, "snippets").unwrap();
        assert_eq!(index.servers.len(), 1);
        assert_eq!(index.servers[0].server_names, vec!["a.com"]);
    }

    #[test]
    fn a_file_nothing_includes_is_marked_unreferenced() {
        let t = tree("orphan");
        write(&t.0, "nginx.conf", "events {}\nhttp { include sites-enabled/*; }\n");
        write(&t.0, "sites-enabled/live", "server { server_name live.com; }\n");
        // Not matched by the glob above, so none of it is in effect.
        write(&t.0, "sites-available/retired", "server { server_name retired.com; }\n");
        write(&t.0, "snippets/unused_cert.conf", "ssl_certificate /etc/nginx/certs/_.x/ecc.pem;\n");

        let index = scan_tree(&t.0, "snippets").unwrap();

        let unreferenced: Vec<&str> = index
            .files
            .iter()
            .filter(|f| f.unreferenced)
            .map(|f| f.path.as_str())
            .collect();
        assert!(unreferenced.contains(&"sites-available/retired"), "{unreferenced:?}");
        assert!(unreferenced.contains(&"snippets/unused_cert.conf"), "{unreferenced:?}");
        assert!(!unreferenced.contains(&"sites-enabled/live"));
    }

    #[test]
    fn stream_servers_are_not_mistaken_for_vhosts() {
        let t = tree("stream");
        write(
            &t.0,
            "nginx.conf",
            "events {}\nstream {\n  upstream db { server 10.0.0.1:5432; }\n\
             server { listen 5432; proxy_pass db; }\n}\n\
             http { server { listen 443 ssl; server_name a.com; } }\n",
        );

        let index = scan_tree(&t.0, "snippets").unwrap();

        let stream_servers: Vec<&ServerBlock> = index.servers.iter().filter(|s| s.stream).collect();
        assert_eq!(stream_servers.len(), 1, "the layer-4 server is marked as such");
        assert!(stream_servers[0].real_names().next().is_none());

        let vhosts: Vec<&ServerBlock> = index.servers.iter().filter(|s| !s.stream).collect();
        assert_eq!(vhosts.len(), 1);
        assert_eq!(vhosts[0].server_names, vec!["a.com"]);
    }

    #[test]
    fn upstream_blocks_are_not_mistaken_for_servers() {
        let t = tree("upstream");
        write(
            &t.0,
            "nginx.conf",
            "events {}\nhttp {\n  upstream backend {\n    server 10.1.0.5:8080;\n    server 10.1.0.6:8080;\n  }\n\
             server { server_name real.com; location / { proxy_pass http://backend; } }\n}\n",
        );

        let index = scan_tree(&t.0, "snippets").unwrap();
        assert_eq!(index.servers.len(), 1);
        assert_eq!(index.servers[0].server_names, vec!["real.com"]);
    }

    #[test]
    fn unknown_directives_and_comments_do_not_derail_it() {
        let t = tree("tolerant");
        write(
            &t.0,
            "nginx.conf",
            "events {}\nhttp {\n# server { server_name commented-out.com; }\n\
             server {\n  access_log /var/log/nginx/access.log otel_json;\n\
             server_name real.com;   # trailing } and a quote \"\n\
             some_future_directive alpha beta;\n\
             add_header Content-Security-Policy \"default-src 'self'; script-src 'unsafe-inline'\";\n\
             location / { proxy_pass http://127.0.0.1:9000; }\n}\n}\n",
        );

        let index = scan_tree(&t.0, "snippets").unwrap();
        assert_eq!(index.servers.len(), 1, "a commented-out server is not a server");
        assert_eq!(index.servers[0].server_names, vec!["real.com"]);
        assert_eq!(index.servers[0].proxy_passes, vec!["http://127.0.0.1:9000"]);
    }

    #[test]
    fn an_unbalanced_file_is_reported_and_contributes_nothing() {
        let t = tree("unbalanced");
        write(
            &t.0,
            "nginx.conf",
            "events {}\nhttp {\n  server {\n    server_name broken.com;\n    location / { proxy_pass http://127.0.0.1:1;\n  }\n",
        );

        let index = scan_tree(&t.0, "snippets").unwrap();

        assert!(
            index.files.iter().any(|f| f.parse_error.is_some()),
            "structure must be reported, not guessed at"
        );
        assert!(
            index.servers.is_empty(),
            "nothing from a file we could not read structurally may be used"
        );
    }

    #[test]
    fn a_missing_include_is_not_fatal() {
        let t = tree("missing_include");
        write(
            &t.0,
            "nginx.conf",
            "events {}\nhttp {\n server {\n  server_name a.com;\n  include snippets/not_there.conf;\n }\n}\n",
        );

        let index = scan_tree(&t.0, "snippets").unwrap();
        assert_eq!(index.servers.len(), 1, "nginx would complain; we simply note nothing");
        assert!(index.servers[0].ssl_certificates.is_empty());
    }

    #[test]
    fn redirect_only_vhosts_are_flagged() {
        let t = tree("redirect");
        write(
            &t.0,
            "nginx.conf",
            "events {}\nhttp { server { listen 80; server_name old.example.com; return 301 https://example.com$request_uri; } }\n",
        );

        let index = scan_tree(&t.0, "snippets").unwrap();
        assert!(index.servers[0].redirect_only);
        assert!(index.servers[0].proxy_passes.is_empty());
    }
}
