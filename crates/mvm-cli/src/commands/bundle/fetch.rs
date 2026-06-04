//! `mvmctl bundle fetch <SOURCE>` — verify a `.mvmpkg` archive
//! against the local trust store.
//!
//! `SOURCE` is either a path on disk or an `https://` URL. HTTPS
//! downloads use the workspace's existing reqwest-blocking helper
//! ([`crate::http::download_file`]) with the system trust store
//! via rustls + webpki-roots. Plain `http://` URLs are refused by
//! default — the trust model (Ed25519 signature) catches a tampered
//! bundle, but plain HTTP makes traffic observable, and consumers
//! often have no idea they typed the wrong scheme. `--allow-http`
//! opts in explicitly with a loud launch-time warning.
//!
//! Scope for this commit is download + verify. Extracting the
//! verified bundle into the local template registry (replacing
//! the manifest-path-hash keying with bundle-sha256 directories)
//! is its own follow-up — it interacts with the existing
//! `~/.mvm/templates/<hash>/...` flow and deserves a separate
//! commit.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::bundle::{FsTrustStore, bundle_sha256, read_and_verify_bundle};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Local path to a `.mvmpkg` archive, or an `https://` URL
    /// (HTTP is opt-in via `--allow-http`).
    #[arg(value_name = "SOURCE")]
    pub source: String,
    /// Override the trust store directory. Defaults to
    /// `~/.mvm/trusted-publishers/`.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Output the verified manifest as JSON instead of a
    /// human-readable summary.
    #[arg(long)]
    pub json: bool,
    /// Allow plain-HTTP downloads. The Ed25519 signature still
    /// catches tampering, but HTTP exposes traffic metadata
    /// (e.g. which bundle a host is pulling). Off by default.
    #[arg(long)]
    pub allow_http: bool,
}

/// Parsed source — file path or URL. Kept narrow so the dispatch
/// fn below stays a small `match`.
#[derive(Debug, PartialEq, Eq)]
enum BundleSource {
    /// Path on the local filesystem.
    File(PathBuf),
    /// `https://…` URL — verified TLS at the wire layer.
    HttpsUrl(String),
    /// `http://…` URL — refused unless `--allow-http` is set.
    HttpUrl(String),
}

impl BundleSource {
    /// Parse a user-supplied string into the right variant.
    ///
    /// Scheme detection is intentionally tiny — no URL crate dep
    /// for this. An `https://` prefix wins; an `http://` prefix
    /// wins next; anything else is a file path. (A relative path
    /// that happens to begin with `https//` without the colon is
    /// a file path, as intended.)
    fn parse(s: &str) -> Self {
        if s.starts_with("https://") {
            Self::HttpsUrl(s.to_string())
        } else if s.starts_with("http://") {
            Self::HttpUrl(s.to_string())
        } else {
            Self::File(PathBuf::from(s))
        }
    }
}

/// Pub variant of [`load_archive_bytes`] for sibling subcommands
/// (`mvmctl bundle install`) that reuse the same source-parsing +
/// transport rules. Parses `source` into a [`BundleSource`] and
/// dispatches.
pub(in crate::commands) fn load_bundle_bytes(source: &str, allow_http: bool) -> Result<Vec<u8>> {
    let parsed = BundleSource::parse(source);
    load_archive_bytes(&parsed, allow_http)
}

/// Load the archive bytes, honouring the source's transport
/// rules. HTTPS downloads write to a temp file (via
/// `crate::http::download_file`) and read back — the temp file is
/// in a `tempfile::NamedTempFile` so it's cleaned on drop even if
/// verification fails.
fn load_archive_bytes(src: &BundleSource, allow_http: bool) -> Result<Vec<u8>> {
    match src {
        BundleSource::File(path) => std::fs::read(path)
            .with_context(|| format!("reading bundle archive at {}", path.display())),
        BundleSource::HttpsUrl(url) => download_to_bytes(url),
        BundleSource::HttpUrl(url) => {
            if !allow_http {
                anyhow::bail!(
                    "refusing to fetch over plain HTTP: {url}\n   \
                     The Ed25519 signature still catches tampering, but HTTP exposes traffic \
                     metadata. Pass --allow-http to override (with a launch-time warning), or \
                     use the https:// URL if the publisher offers one."
                );
            }
            crate::ui::warn(&format!(
                "⚠ Downloading bundle over plain HTTP from {url}\n   \
                 Signature verification still applies; traffic metadata is visible to anyone \
                 on the wire."
            ));
            download_to_bytes(url)
        }
    }
}

fn download_to_bytes(url: &str) -> Result<Vec<u8>> {
    // Write to a temp file then read back. Two passes is fine for
    // v1 — bundles are modest in size, and the second read covers
    // the disk-cache-warm path the verifier would walk anyway.
    let tmp = tempfile::NamedTempFile::new().context("creating temp file for bundle download")?;
    crate::http::download_file(url, tmp.path())
        .with_context(|| format!("downloading bundle from {url}"))?;
    std::fs::read(tmp.path())
        .with_context(|| format!("reading downloaded bundle from {}", tmp.path().display()))
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let source = BundleSource::parse(&args.source);
    let bytes = load_archive_bytes(&source, args.allow_http)?;

    let trust = match args.trust_store {
        Some(p) => FsTrustStore::new(p),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?,
    };

    let verified = read_and_verify_bundle(&bytes, &trust)
        .with_context(|| format!("verifying bundle from {}", args.source))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&verified.manifest)?);
    } else {
        let summary = BundleSummary {
            bundle_sha256: bundle_sha256(&bytes),
            key_id: verified.key_id.0.clone(),
            publisher: verified.manifest.publisher.clone(),
            arch: verified.manifest.arch.clone(),
            profile: verified.manifest.profile.clone(),
            workload_label: verified.manifest.workload_label.clone(),
            artifact_count: verified.manifest.artifacts.len(),
            has_verity: verified.manifest.verity.is_some(),
        };
        summary.render();
    }
    Ok(())
}

struct BundleSummary {
    bundle_sha256: String,
    key_id: String,
    publisher: String,
    arch: String,
    profile: Option<String>,
    workload_label: Option<String>,
    artifact_count: usize,
    has_verity: bool,
}

impl BundleSummary {
    fn render(&self) {
        println!("Bundle verified");
        println!("  sha256:    {}", self.bundle_sha256);
        println!("  key_id:    {}", self.key_id);
        println!("  publisher: {}", self.publisher);
        println!("  arch:      {}", self.arch);
        if let Some(p) = &self.profile {
            println!("  profile:   {p}");
        }
        if let Some(l) = &self.workload_label {
            println!("  label:     {l}");
        }
        println!("  artifacts: {}", self.artifact_count);
        println!(
            "  verity:    {}",
            if self.has_verity { "yes" } else { "no" }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_url() {
        let s = BundleSource::parse("https://registry.example.com/foo.mvmpkg");
        assert_eq!(
            s,
            BundleSource::HttpsUrl("https://registry.example.com/foo.mvmpkg".to_string())
        );
    }

    #[test]
    fn parse_http_url() {
        let s = BundleSource::parse("http://registry.example.com/foo.mvmpkg");
        assert_eq!(
            s,
            BundleSource::HttpUrl("http://registry.example.com/foo.mvmpkg".to_string())
        );
    }

    #[test]
    fn parse_relative_file_path() {
        let s = BundleSource::parse("./bundles/foo.mvmpkg");
        assert_eq!(s, BundleSource::File(PathBuf::from("./bundles/foo.mvmpkg")));
    }

    #[test]
    fn parse_absolute_file_path() {
        let s = BundleSource::parse("/tmp/foo.mvmpkg");
        assert_eq!(s, BundleSource::File(PathBuf::from("/tmp/foo.mvmpkg")));
    }

    #[test]
    fn parse_scheme_lookalike_is_still_a_path() {
        // A path that happens to begin with "https" but no "://"
        // separator is a file path, not a URL. This protects against
        // accidental misinterpretation of cwd-relative names.
        let s = BundleSource::parse("https-mirror/foo.mvmpkg");
        assert_eq!(
            s,
            BundleSource::File(PathBuf::from("https-mirror/foo.mvmpkg"))
        );
    }

    #[test]
    fn parse_scheme_is_case_sensitive() {
        // Match the conventional URL grammar — lowercase only. An
        // uppercase prefix is more likely a filename than a real
        // URL on a filesystem.
        let s = BundleSource::parse("HTTPS://registry.example.com/foo");
        assert_eq!(
            s,
            BundleSource::File(PathBuf::from("HTTPS://registry.example.com/foo"))
        );
    }

    #[test]
    fn load_archive_bytes_refuses_http_without_allow_http() {
        let src = BundleSource::HttpUrl("http://example.com/foo.mvmpkg".to_string());
        let err = load_archive_bytes(&src, false).expect_err("must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing to fetch over plain HTTP"),
            "got: {msg}"
        );
        // The escape hatch hint should appear in the same message so
        // users know exactly how to recover.
        assert!(msg.contains("--allow-http"), "got: {msg}");
    }

    #[test]
    fn load_archive_bytes_reads_a_local_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello-bundle").unwrap();
        let src = BundleSource::File(tmp.path().to_path_buf());
        let bytes = load_archive_bytes(&src, false).expect("reads");
        assert_eq!(bytes, b"hello-bundle");
    }
}
