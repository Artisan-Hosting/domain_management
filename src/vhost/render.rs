//! Assembling a vhost from a runner's deployed instances, or from a small,
//! closed set of extras layered on top.
//!
//! A node-id instance is addressed as `ahpn-<node id>.ah.internal:<port>` --
//! the node id with the internal domain glued on, and the port out of that
//! instance's config. The caller knows both (it is the one that placed the
//! repo on the node and read its config), so it sends them and this renders
//! the result. A static instance is a raw `host:port` the caller already
//! knows is reachable -- the escape hatch for a project whose config this
//! service cannot natively parse.
//!
//! When a runner has more than one instance, they become members of one
//! upstream and nginx balances across them. That is the same shape the
//! hand-written `artisan_release` block already uses, down to the
//! `max_fails`/`fail_timeout` tuning, because those values encode operational
//! experience this code has no business quietly changing.
//!
//! Extras (`extra_headers`, `cors`, `extra_locations`) cover the recurring
//! hand-written patterns -- CORS/OPTIONS handling, a websocket location, a
//! deny-hidden-files location -- without opening a second freeform path in
//! disguise. Anything genuinely arbitrary falls through to
//! [`super::freeform`] instead.
//!
//! What is *not* rendered here: the certificate lines. Those live in the
//! snippet (`super::snippet`), shared by every vhost on the zone, and the
//! vhost only includes it.

use serde::{Deserialize, Serialize};

use crate::config::{Config, snippet_slug};
use crate::error::{Error, Result};
use crate::inventory::nginx::MANAGED_HEADER;

/// The internal domain every node answers on.
const NODE_DOMAIN: &str = "ah.internal";

/// Failure tuning copied from the existing `artisan_release` upstream.
const MAX_FAILS: u32 = 10;
const FAIL_TIMEOUT: &str = "10s";

/// One deployed instance of a runner, or a raw address given by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Backend {
    /// A runner's instance. Becomes `ahpn-<node_id>.ah.internal:<port>`.
    Node { node_id: String, port: u16 },
    /// A raw address the caller already knows is reachable -- the port
    /// override for a config this service cannot derive from a runner's
    /// deployment.
    Static {
        host: String,
        port: u16,
        tls: bool,
        /// Only meaningful when `tls` is set. `true` emits
        /// `proxy_ssl_verify off;`, for a backend with a self-signed or
        /// otherwise unverifiable certificate. Defaults false (verify) --
        /// deliberately named so the safe value is also the zero value.
        insecure_skip_verify: bool,
    },
}

impl Backend {
    pub fn address(&self) -> String {
        match self {
            Backend::Node { node_id, port } => format!("ahpn-{node_id}.{NODE_DOMAIN}:{port}"),
            Backend::Static { host, port, .. } => {
                if host.contains(':') && !host.starts_with('[') {
                    // A literal IPv6 address; nginx's `server` directive
                    // needs it bracketed to tell the address apart from the
                    // port that follows.
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            }
        }
    }

    fn tls(&self) -> bool {
        matches!(self, Backend::Static { tls: true, .. })
    }

    fn wants_skip_tls_verify(&self) -> bool {
        matches!(self, Backend::Static { tls: true, insecure_skip_verify: true, .. })
    }

    /// Rejects anything that would not survive being written into a config
    /// file. This string is about to become part of something nginx executes,
    /// and both the node id and the static host arrive over the wire.
    fn validate(&self) -> Result<()> {
        match self {
            Backend::Node { node_id, port } => {
                if node_id.is_empty() {
                    return Err(Error::Invalid("a backend has no node id".to_owned()));
                }
                if !node_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    return Err(Error::Invalid(format!(
                        "node id {node_id:?} is not a hostname label; refusing to write it into a config"
                    )));
                }
                if *port == 0 {
                    return Err(Error::Invalid(format!("node {node_id} has port 0, which is not a port")));
                }
            }
            Backend::Static { host, port, .. } => {
                if host.is_empty() {
                    return Err(Error::Invalid("a static backend has no host".to_owned()));
                }
                if !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
                {
                    return Err(Error::Invalid(format!(
                        "host {host:?} is not a safe address; refusing to write it into a config"
                    )));
                }
                if *port == 0 {
                    return Err(Error::Invalid(format!("static backend {host} has port 0, which is not a port")));
                }
            }
        }
        Ok(())
    }
}

/// A `name: value` header line, rendered as `add_header name value;`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

/// The CORS/OPTIONS-preflight shape already hand-written on every
/// CORS-enabled vhost in the fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsPolicy {
    pub allow_origin: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub expose_headers: String,
}

/// A small, closed set of recurring extra-location shapes. Deliberately not
/// raw directive text -- add a variant when a new recurring pattern shows
/// up; anything genuinely arbitrary belongs in [`super::freeform`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationKind {
    /// `proxy_http_version 1.1;` plus `Upgrade`/`Connection` headers,
    /// proxied to the same upstream as `location /`.
    Websocket,
    /// `deny all;` -- the hidden-files-block pattern.
    DenyAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraLocation {
    pub path: String,
    pub kind: LocationKind,
}

#[derive(Debug, Clone)]
pub struct VhostSpec {
    pub fqdn: String,
    /// Extra names to serve, `www.<fqdn>` being the usual one.
    pub extra_names: Vec<String>,
    /// The project this serves, for the comment header and the upstream name.
    pub runner_id: String,
    pub backends: Vec<Backend>,
    /// Also emit the port-80 server that redirects to HTTPS.
    pub http_redirect: bool,
    /// Extra `add_header` lines in `location /`.
    pub extra_headers: Vec<HeaderEntry>,
    pub cors: Option<CorsPolicy>,
    pub extra_locations: Vec<ExtraLocation>,
}

impl VhostSpec {
    pub fn new(fqdn: &str, runner_id: &str, backends: Vec<Backend>) -> Self {
        Self {
            fqdn: fqdn.to_owned(),
            extra_names: Vec::new(),
            runner_id: runner_id.to_owned(),
            backends,
            http_redirect: true,
            extra_headers: Vec::new(),
            cors: None,
            extra_locations: Vec::new(),
        }
    }

    pub fn server_names(&self) -> Vec<String> {
        let mut names = vec![self.fqdn.clone()];
        names.extend(self.extra_names.iter().cloned());
        names
    }

    /// The upstream block's name.
    ///
    /// A short hash of the domain is appended because upstream names share
    /// one namespace across the whole `http` block: `shop.example.com` and
    /// `shop.example.net` both slug to `shop_example`, and the second one to
    /// load would silently redefine the first.
    pub fn upstream_name(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.fqdn.as_bytes());
        format!("ais_{}_{}", snippet_slug(&self.fqdn), hex::encode(&digest[..2]))
    }

    fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            return Err(Error::Invalid(format!(
                "{}: no instances given, so there is nothing to proxy to",
                self.fqdn
            )));
        }

        for backend in &self.backends {
            backend.validate()?;
        }

        // Two entries for one address is either a mistake or a caller sending
        // the same instance twice; either way nginx would weight it double.
        let mut seen = std::collections::BTreeSet::new();
        for backend in &self.backends {
            if !seen.insert(backend.address()) {
                return Err(Error::Invalid(format!(
                    "{}: instance {} appears twice",
                    self.fqdn,
                    backend.address()
                )));
            }
        }

        // nginx picks the proxy_pass scheme once per location; an upstream
        // cannot mix a plaintext member with a TLS one.
        let tls_count = self.backends.iter().filter(|b| b.tls()).count();
        if tls_count != 0 && tls_count != self.backends.len() {
            return Err(Error::Invalid(format!(
                "{}: cannot mix TLS and non-TLS backends in one upstream -- \
                 nginx chooses the proxy_pass scheme once per location",
                self.fqdn
            )));
        }

        Ok(())
    }

    fn tls(&self) -> bool {
        self.backends.first().map(Backend::tls).unwrap_or(false)
    }

    /// Whether any backend asked for `proxy_ssl_verify off;`. Only
    /// meaningful alongside `tls()`.
    fn skip_tls_verify(&self) -> bool {
        self.backends.iter().any(Backend::wants_skip_tls_verify)
    }
}

/// Renders the vhost file.
pub fn render(config: &Config, spec: &VhostSpec) -> Result<String> {
    spec.validate()?;

    let upstream = spec.upstream_name();
    let snippets = &config.tree.snippets_dir;
    let slug = snippet_slug(&spec.fqdn);
    let names = spec.server_names().join(" ");
    let scheme = if spec.tls() { "https" } else { "http" };

    let mut out = String::new();
    out.push_str(&format!(
        "# {MANAGED_HEADER} -- {} -> runner {}\n\
         # Rendered from the runner's deployed instances. Hand edits are\n\
         # overwritten; to change where this points, re-attach the domain.\n\n",
        spec.fqdn, spec.runner_id
    ));

    if spec.http_redirect {
        out.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {names};\n    return 301 https://$host$request_uri;\n}}\n\n"
        ));
    }

    out.push_str(&format!(
        "server {{\n\
         \x20   access_log /var/log/nginx/access.log otel_json;\n\
         \x20   error_log /var/log/nginx/error.log warn;\n\
         \x20   listen 443 ssl http2;\n\
         \x20   server_name {names};\n\n\
         \x20   include {snippets}/{slug}_cert.conf;\n\
         \x20   include {snippets}/ssl-params.conf;\n\n\
         \x20   location / {{\n"
    ));

    if let Some(cors) = &spec.cors {
        out.push_str(&format!(
            "\x20       add_header 'Access-Control-Allow-Origin' '{}';\n\
             \x20       add_header 'Access-Control-Allow-Methods' '{}';\n\
             \x20       add_header 'Access-Control-Allow-Headers' '{}';\n\
             \x20       add_header 'Access-Control-Expose-Headers' '{}';\n\n\
             \x20       if ($request_method = 'OPTIONS') {{\n\
             \x20           return 204;\n\
             \x20       }}\n\n",
            cors.allow_origin, cors.allow_methods, cors.allow_headers, cors.expose_headers
        ));
    }

    for header in &spec.extra_headers {
        out.push_str(&format!("\x20       add_header '{}' '{}';\n", header.name, header.value));
    }
    if !spec.extra_headers.is_empty() {
        out.push('\n');
    }

    out.push_str(&format!(
        "\x20       proxy_pass {scheme}://{upstream};\n\
         \x20       proxy_set_header Host $host;\n\
         \x20       proxy_set_header X-Real-IP $remote_addr;\n\
         \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
         \x20       proxy_set_header X-Forwarded-Proto $scheme;\n"
    ));
    if spec.tls() && spec.skip_tls_verify() {
        out.push_str("\x20       proxy_ssl_verify off;\n");
    }
    out.push_str("\x20   }\n");

    for location in &spec.extra_locations {
        out.push_str(&render_extra_location(location, &scheme, &upstream, spec.tls() && spec.skip_tls_verify()));
    }

    out.push_str("}\n\n");

    out.push_str(&format!("upstream {upstream} {{\n"));
    if spec.backends.len() > 1 {
        // Only meaningful with something to choose between.
        out.push_str("    random;\n");
    }
    for backend in &spec.backends {
        out.push_str(&format!(
            "    server {} max_fails={MAX_FAILS} fail_timeout={FAIL_TIMEOUT};\n",
            backend.address()
        ));
    }
    out.push_str("}\n");

    Ok(out)
}

fn render_extra_location(location: &ExtraLocation, scheme: &str, upstream: &str, skip_verify: bool) -> String {
    let path = &location.path;
    match location.kind {
        LocationKind::Websocket => format!(
            "\n\x20   location {path} {{\n\
             \x20       proxy_pass {scheme}://{upstream};\n\
             \x20       proxy_http_version 1.1;\n\
             \x20       proxy_set_header Upgrade $http_upgrade;\n\
             \x20       proxy_set_header Connection \"upgrade\";\n\
             \x20       proxy_set_header Host $host;\n\
             \x20       proxy_set_header X-Real-IP $remote_addr;\n\
             \x20       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
             {}\
             \x20   }}\n",
            if skip_verify { "\x20       proxy_ssl_verify off;\n" } else { "" }
        ),
        LocationKind::DenyAll => format!("\n\x20   location {path} {{\n\x20       deny all;\n\x20   }}\n"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VhostOutcome {
    Created(std::path::PathBuf),
    Updated(std::path::PathBuf),
    Unchanged(std::path::PathBuf),
    /// Someone wrote this vhost by hand -- or it was applied through the
    /// freeform path -- and it is left alone either way.
    HandWritten { path: std::path::PathBuf, would_be: String },
}

impl VhostOutcome {
    pub fn path(&self) -> &std::path::Path {
        match self {
            VhostOutcome::Created(path)
            | VhostOutcome::Updated(path)
            | VhostOutcome::Unchanged(path) => path,
            VhostOutcome::HandWritten { path, .. } => path,
        }
    }
}

/// Writes the vhost, refusing to touch a file this service did not write
/// itself through this exact structured path.
///
/// The adopted vhosts in this tree carry CORS headers, `OPTIONS` handling and
/// per-site quirks that no template reproduces. Replacing one because a
/// domain was re-attached would quietly drop all of it. A file applied
/// through [`super::freeform`] carries its own, different marker for the
/// same reason: this service "owns" it in the sense that the freeform API
/// can update it again, but the structured generator here never may --
/// clobbering a carefully hand-crafted freeform submission on a later
/// `AttachDomain` call would be exactly the same mistake as clobbering a
/// hand-written one.
pub fn write(config: &Config, spec: &VhostSpec) -> Result<VhostOutcome> {
    let path = config.vhost_path_for(&spec.fqdn);
    let desired = render(config, spec)?;

    if let Ok(existing) = std::fs::read_to_string(&path) {
        if !existing.contains(MANAGED_HEADER) {
            return Ok(VhostOutcome::HandWritten { path, would_be: desired });
        }
        if existing == desired {
            return Ok(VhostOutcome::Unchanged(path));
        }

        write_atomic(&path, &desired)?;
        return Ok(VhostOutcome::Updated(path));
    }

    write_atomic(&path, &desired)?;
    Ok(VhostOutcome::Created(path))
}

pub(crate) fn write_atomic(path: &std::path::Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Io(std::io::Error::other(format!("creating {}: {e}", parent.display())))
        })?;
    }

    let tmp = path.with_extension("ais-tmp");
    std::fs::write(&tmp, contents)
        .map_err(|e| Error::Io(std::io::Error::other(format!("writing {}: {e}", tmp.display()))))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        Error::Io(std::io::Error::other(format!("installing {}: {e}", path.display())))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(node: &str, port: u16) -> Backend {
        Backend::Node { node_id: node.to_owned(), port }
    }

    fn spec(backends: Vec<Backend>) -> VhostSpec {
        let mut spec = VhostSpec::new("artisanhosting.net", "ab12cd34", backends);
        spec.extra_names = vec!["www.artisanhosting.net".to_owned()];
        spec
    }

    #[test]
    fn a_node_id_becomes_the_internal_address() {
        assert_eq!(
            backend("2973453917896704", 8093).address(),
            "ahpn-2973453917896704.ah.internal:8093",
            "this is the form the existing upstreams use"
        );
    }

    #[test]
    fn a_static_backend_becomes_a_bare_host_port() {
        let b = Backend::Static {
            host: "10.4.1.2".to_owned(),
            port: 4000,
            tls: false,
            insecure_skip_verify: false,
        };
        assert_eq!(b.address(), "10.4.1.2:4000");
    }

    #[test]
    fn a_static_https_backend_renders_the_scheme_and_verify_directive() {
        let config = Config::default();
        let b = Backend::Static {
            host: "192.168.0.30".to_owned(),
            port: 443,
            tls: true,
            insecure_skip_verify: true,
        };
        let mut spec = VhostSpec::new("analytics.artisanstudio.net", "r1", vec![b]);
        spec.extra_locations = vec![ExtraLocation {
            path: "/live/websocket".to_owned(),
            kind: LocationKind::Websocket,
        }];
        let rendered = render(&config, &spec).unwrap();

        assert!(rendered.contains("proxy_pass https://"), "{rendered}");
        assert!(rendered.contains("proxy_ssl_verify off;"), "{rendered}");
        assert!(rendered.contains("location /live/websocket {"), "{rendered}");
        assert!(rendered.contains("proxy_http_version 1.1;"), "{rendered}");
    }

    #[test]
    fn mixing_tls_and_plain_backends_in_one_upstream_is_refused() {
        let config = Config::default();
        let mixed = VhostSpec::new(
            "example.com",
            "r1",
            vec![
                backend("n1", 8080),
                Backend::Static { host: "10.0.0.1".to_owned(), port: 443, tls: true, insecure_skip_verify: false },
            ],
        );
        let err = render(&config, &mixed).unwrap_err();
        assert!(err.to_string().contains("cannot mix TLS and non-TLS backends"), "{err}");
    }

    #[test]
    fn a_cors_policy_renders_the_hand_written_shape() {
        let config = Config::default();
        let mut spec = spec(vec![backend("n1", 8093)]);
        spec.cors = Some(CorsPolicy {
            allow_origin: "*".to_owned(),
            allow_methods: "GET, POST, OPTIONS".to_owned(),
            allow_headers: "DNT,User-Agent".to_owned(),
            expose_headers: "Content-Length,Content-Range".to_owned(),
        });
        let rendered = render(&config, &spec).unwrap();

        assert!(rendered.contains("add_header 'Access-Control-Allow-Origin' '*';"), "{rendered}");
        assert!(rendered.contains("if ($request_method = 'OPTIONS') {"), "{rendered}");
        assert!(rendered.contains("return 204;"), "{rendered}");
    }

    #[test]
    fn a_deny_all_location_renders() {
        let config = Config::default();
        let mut spec = spec(vec![backend("n1", 8093)]);
        spec.extra_locations = vec![ExtraLocation { path: "~ /\\.".to_owned(), kind: LocationKind::DenyAll }];
        let rendered = render(&config, &spec).unwrap();
        assert!(rendered.contains("location ~ /\\. {"), "{rendered}");
        assert!(rendered.contains("deny all;"), "{rendered}");
    }

    #[test]
    fn one_instance_renders_a_single_member_upstream() {
        let config = Config::default();
        let rendered = render(&config, &spec(vec![backend("2973453917896704", 8093)])).unwrap();

        assert!(rendered.contains("server_name artisanhosting.net www.artisanhosting.net;"));
        assert!(rendered.contains("include snippets/artisanhosting_cert.conf;"));
        assert!(rendered.contains("include snippets/ssl-params.conf;"));
        assert!(rendered.contains("server ahpn-2973453917896704.ah.internal:8093 max_fails=10 fail_timeout=10s;"));
        assert!(
            !rendered.contains("random;"),
            "a balancing method with one member is noise"
        );
        assert!(rendered.contains(MANAGED_HEADER));
    }

    #[test]
    fn several_instances_become_a_balanced_upstream() {
        let config = Config::default();
        let rendered = render(
            &config,
            &spec(vec![
                backend("2973453917896704", 8093),
                backend("3091229306929152", 8093),
            ]),
        )
        .unwrap();

        assert!(rendered.contains("random;"), "more than one member gets a method");
        assert_eq!(
            rendered.matches("max_fails=10 fail_timeout=10s;").count(),
            2,
            "both instances are members"
        );
    }

    #[test]
    fn the_upstream_name_cannot_collide_across_zones() {
        // Both slug to `shop_example`; the one loaded second would otherwise
        // redefine the first, silently.
        let com = VhostSpec::new("shop.example.com", "r1", vec![backend("n1", 80)]);
        let net = VhostSpec::new("shop.example.net", "r2", vec![backend("n2", 80)]);

        assert_ne!(com.upstream_name(), net.upstream_name());
        assert!(com.upstream_name().starts_with("ais_shop_example_"));
    }

    #[test]
    fn the_redirect_server_can_be_turned_off() {
        let config = Config::default();
        let mut with_redirect = spec(vec![backend("n1", 8080)]);
        assert!(render(&config, &with_redirect).unwrap().contains("return 301 https://"));

        with_redirect.http_redirect = false;
        let plain = render(&config, &with_redirect).unwrap();
        assert!(!plain.contains("return 301"));
        assert!(!plain.contains("listen 80;"));
    }

    #[test]
    fn a_node_id_that_is_not_a_hostname_is_refused() {
        let config = Config::default();

        // This would otherwise be written verbatim into a file nginx runs.
        let injected = spec(vec![backend("n1; } server { listen 8080", 80)]);
        let err = render(&config, &injected).unwrap_err();
        assert!(err.to_string().contains("not a hostname label"), "{err}");

        let zero_port = spec(vec![backend("n1", 0)]);
        assert!(render(&config, &zero_port).is_err());
    }

    #[test]
    fn a_domain_with_no_instances_is_refused() {
        let config = Config::default();
        let err = render(&config, &spec(Vec::new())).unwrap_err();
        assert!(err.to_string().contains("nothing to proxy to"), "{err}");
    }

    #[test]
    fn the_same_instance_twice_is_refused() {
        let config = Config::default();
        let doubled = spec(vec![backend("n1", 8080), backend("n1", 8080)]);
        let err = render(&config, &doubled).unwrap_err();
        assert!(err.to_string().contains("appears twice"), "{err}");
    }

    #[test]
    fn a_hand_written_vhost_is_never_replaced() {
        let root = std::env::temp_dir().join(format!(
            "ais_domains_vhost_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::default();
        config.tree.root = root.clone();

        let path = config.vhost_path_for("artisanhosting.net");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // The real file: CORS headers, OPTIONS handling, none of it reproducible.
        let original = "server {\n    add_header 'Access-Control-Allow-Origin' '*';\n}\n";
        std::fs::write(&path, original).unwrap();

        let outcome = write(&config, &spec(vec![backend("n1", 8080)])).unwrap();
        assert!(matches!(outcome, VhostOutcome::HandWritten { .. }), "{outcome:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_freeform_applied_vhost_is_also_never_replaced_by_the_structured_path() {
        let root = std::env::temp_dir().join(format!(
            "ais_domains_vhost_freeform_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::default();
        config.tree.root = root.clone();

        let path = config.vhost_path_for("artisanhosting.net");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = format!(
            "# {} -- artisanhosting.net, applied via ApplyFreeformVhost\nserver {{\n    listen 443;\n}}\n",
            crate::inventory::nginx::FREEFORM_MANAGED_HEADER
        );
        std::fs::write(&path, &original).unwrap();

        let outcome = write(&config, &spec(vec![backend("n1", 8080)])).unwrap();
        assert!(matches!(outcome, VhostOutcome::HandWritten { .. }), "{outcome:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rewriting_our_own_vhost_is_idempotent() {
        let root = std::env::temp_dir().join(format!(
            "ais_domains_vhost2_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut config = Config::default();
        config.tree.root = root.clone();

        let first = write(&config, &spec(vec![backend("n1", 8080)])).unwrap();
        assert!(matches!(first, VhostOutcome::Created(_)));

        let again = write(&config, &spec(vec![backend("n1", 8080)])).unwrap();
        assert!(matches!(again, VhostOutcome::Unchanged(_)), "{again:?}");

        // Scaling out rewrites it.
        let scaled = write(&config, &spec(vec![backend("n1", 8080), backend("n2", 8080)])).unwrap();
        assert!(matches!(scaled, VhostOutcome::Updated(_)), "{scaled:?}");
        assert!(std::fs::read_to_string(scaled.path()).unwrap().contains("random;"));

        std::fs::remove_dir_all(&root).ok();
    }
}
