//! Hostname + port allowlist for the builder-VM egress proxy.
//!
//! Hostnames the builder VM is allowed to dial during
//! dependency installs and no-NIC flake builds:
//!
//! - `pypi.org` — the Python package index API.
//! - `files.pythonhosted.org` — pypi's CDN for the actual sdists +
//!   wheels.
//! - `registry.npmjs.org` — the npm metadata + tarball registry.
//! - `crates.io` — crates.io sparse-index metadata redirects and API
//!   endpoints Cargo may hit during vendoring.
//! - `index.crates.io` — the sparse registry index host used by modern
//!   Cargo when resolving crates.io dependencies.
//! - `static.crates.io` — the crate tarball CDN for the actual
//!   `.crate` downloads during vendoring.
//! - `objects.githubusercontent.com` — GitHub's release-asset CDN,
//!   reachable as a transitive fetch when a Python lockfile pins a
//!   git-based dep.
//! - `cache.nixos.org` — the public binary cache Nix uses for
//!   substitutes during builder-VM flake builds.
//! - `github.com` — pinned flake input archives such as
//!   `github.com/NixOS/nixpkgs/archive/<rev>.tar.gz`.
//! - `codeload.github.com` — GitHub archive downloads redirect here,
//!   so flake input tarballs must be admitted on this host as well.
//! - `api.github.com` — flake metadata resolution for GitHub-backed
//!   inputs when Nix cannot satisfy it from the local lock/cache.
//! - `cdn.kernel.org` — pinned Linux kernel source tarballs used by
//!   the builder kernel derivations.
//!
//! Everything else fails closed: the proxy returns HTTP 403 and
//! tears the socket down without ever establishing a tunnel.
//!
//! ## Port policy
//!
//! Only port 443 is allowed. The four allowlisted hostnames serve
//! HTTPS exclusively; an installer that asks for port 80 / 21 /
//! 22 against any of them is either misconfigured or attempting a
//! protocol downgrade. Rejecting non-443 surfaces that loudly
//! rather than letting the connection through and discovering
//! the protocol error inside the TLS / pip layer.
//!
//! Future extension: when registry-mirror support lands,
//! the allowlist will move from hard-coded to manifest-driven.
//!
//! ## Hostname matching
//!
//! Exact match only. No wildcards — `pypi.org` does NOT
//! cover `pkg.pypi.org`, `*.pythonhosted.org` does NOT cover
//! `mirror.pythonhosted.org`. We enforce exactly the four listed
//! hostnames; a future "subdomain wildcard" extension is a
//! deliberate policy change.
//!
//! Comparison is case-insensitive (DNS is case-insensitive per
//! RFC 4343); we lowercase the candidate before comparing to the
//! lowercase static list.

/// The allowed hostnames, lowercased. Order doesn't matter;
/// the matcher walks the slice with `.iter().any()`.
pub const PRODUCTION_HOSTNAMES: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "crates.io",
    "index.crates.io",
    "static.crates.io",
    "objects.githubusercontent.com",
    "cache.nixos.org",
    "github.com",
    "codeload.github.com",
    "api.github.com",
    "cdn.kernel.org",
];

/// Only port the proxy permits — the allowlisted hosts serve
/// HTTPS exclusively. See module docs for the rationale on
/// rejecting other ports.
pub const ALLOWED_PORT: u16 = 443;

/// Compiled allowlist. Owns its hostnames so a runtime override
/// (gated behind `interactive` in `main.rs`) can supply a different
/// list per-test without mutating a global.
#[derive(Debug, Clone)]
pub struct Allowlist {
    hosts: Vec<String>,
    port: u16,
}

impl Allowlist {
    /// Build the production allowlist — the four allowed
    /// hostnames + port 443. This is what `main.rs` constructs
    /// when the `interactive` feature is **off** (i.e., the binary
    /// shipped inside the builder VM). No env-var override; the
    /// allowlist is baked into the binary.
    pub fn production() -> Self {
        Self {
            hosts: PRODUCTION_HOSTNAMES.iter().map(|s| s.to_string()).collect(),
            port: ALLOWED_PORT,
        }
    }

    /// Build a custom allowlist from `hosts` + `port`. Intended
    /// only for tests (the `interactive` feature in `main.rs` reads
    /// `MVM_EGRESS_ALLOWLIST` and feeds it through here).
    ///
    /// Empty `hosts` returns an allowlist that refuses everything;
    /// useful as a smoke test that the matcher fails-closed when
    /// the override is unset.
    pub fn from_parts(hosts: Vec<String>, port: u16) -> Self {
        Self {
            hosts: hosts.into_iter().map(|h| h.to_lowercase()).collect(),
            port,
        }
    }

    /// Returns `true` iff `host:port` is on the allowlist. `host`
    /// is matched case-insensitively against the stored hostnames.
    /// `port` must equal the allowlist's `port` exactly.
    pub fn is_allowed(&self, host: &str, port: u16) -> bool {
        if port != self.port {
            return false;
        }
        let candidate = host.to_lowercase();
        self.hosts.iter().any(|h| h == &candidate)
    }

    /// Test helper: returns the configured port. Production code
    /// doesn't need this; it lets tests assert the port boundary
    /// without reaching into the struct.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Test helper: returns the list of allowed hostnames in
    /// insertion order.
    pub fn hostnames(&self) -> &[String] {
        &self.hosts
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_allowlist_contains_builder_install_and_flake_hosts() {
        let a = Allowlist::production();
        assert_eq!(
            a.hostnames().len(),
            12,
            "builder allowlist should stay explicit"
        );
        assert!(a.is_allowed("pypi.org", 443));
        assert!(a.is_allowed("files.pythonhosted.org", 443));
        assert!(a.is_allowed("registry.npmjs.org", 443));
        assert!(a.is_allowed("crates.io", 443));
        assert!(a.is_allowed("index.crates.io", 443));
        assert!(a.is_allowed("static.crates.io", 443));
        assert!(a.is_allowed("objects.githubusercontent.com", 443));
        assert!(a.is_allowed("cache.nixos.org", 443));
        assert!(a.is_allowed("github.com", 443));
        assert!(a.is_allowed("codeload.github.com", 443));
        assert!(a.is_allowed("api.github.com", 443));
        assert!(a.is_allowed("cdn.kernel.org", 443));
    }

    #[test]
    fn production_allowlist_rejects_evil_example_com() {
        let a = Allowlist::production();
        assert!(!a.is_allowed("evil.example.com", 443));
    }

    #[test]
    fn production_allowlist_rejects_typosquat_subdomain() {
        // No wildcard match — `pypi.org.evil.com` must not slip
        // through a sloppy `ends_with` check.
        let a = Allowlist::production();
        assert!(!a.is_allowed("pypi.org.evil.com", 443));
        assert!(!a.is_allowed("evil.com.pypi.org", 443));
    }

    #[test]
    fn production_allowlist_rejects_subdomain_of_allowed_host() {
        // Exact match only — `mirror.pypi.org` is NOT covered by
        // `pypi.org`. The closed list is the policy; future
        // wildcards are a deliberate change.
        let a = Allowlist::production();
        assert!(!a.is_allowed("mirror.pypi.org", 443));
        assert!(!a.is_allowed("foo.files.pythonhosted.org", 443));
    }

    #[test]
    fn production_allowlist_rejects_non_443_port() {
        // HTTPS-only. Port 80 (HTTP), 21 (FTP), 22 (SSH) all
        // refused — even against an allowed hostname.
        let a = Allowlist::production();
        assert!(!a.is_allowed("pypi.org", 80));
        assert!(!a.is_allowed("pypi.org", 21));
        assert!(!a.is_allowed("pypi.org", 22));
        assert!(!a.is_allowed("pypi.org", 8443));
    }

    #[test]
    fn allowlist_match_is_case_insensitive() {
        // DNS is case-insensitive per RFC 4343 — uppercase host
        // in a CONNECT line still matches the lowercase allowlist.
        let a = Allowlist::production();
        assert!(a.is_allowed("PYPI.ORG", 443));
        assert!(a.is_allowed("PyPI.Org", 443));
        assert!(a.is_allowed("Registry.NPMjs.Org", 443));
    }

    #[test]
    fn empty_allowlist_refuses_everything() {
        let a = Allowlist::from_parts(vec![], 443);
        assert!(!a.is_allowed("pypi.org", 443));
        assert!(!a.is_allowed("anything.example.com", 443));
    }

    #[test]
    fn custom_allowlist_with_one_host() {
        let a = Allowlist::from_parts(vec!["example.org".to_string()], 443);
        assert!(a.is_allowed("example.org", 443));
        assert!(!a.is_allowed("pypi.org", 443));
        // Production hostnames aren't implicitly merged in.
        assert_eq!(a.hostnames(), &["example.org".to_string()]);
    }

    #[test]
    fn custom_allowlist_lowercases_input_hostnames() {
        // from_parts() canonicalizes — a hand-built allowlist
        // with uppercase entries still matches uppercase inputs.
        let a = Allowlist::from_parts(vec!["Example.Org".to_string()], 443);
        assert!(a.is_allowed("example.org", 443));
        assert!(a.is_allowed("EXAMPLE.ORG", 443));
    }

    #[test]
    fn allowed_port_constant_is_443() {
        // Lock the contract: the allowlisted hosts are HTTPS-only.
        // If a future change opens port 80 we want this test to
        // flag the constant change explicitly.
        assert_eq!(ALLOWED_PORT, 443);
        assert_eq!(Allowlist::production().port(), 443);
    }

    #[test]
    fn empty_hostname_is_rejected() {
        // Defensive: an empty Host: header / SNI shouldn't
        // accidentally match an empty entry. Production
        // hostnames are non-empty by construction.
        let a = Allowlist::production();
        assert!(!a.is_allowed("", 443));
    }
}
