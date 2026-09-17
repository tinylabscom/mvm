//! `mvmctl bundle install <SOURCE>` — verify a `.mvmpkg` archive
//! and extract it into the local bundle registry so subsequent
//! `mvmctl up <bundle-sha256>` calls can launch from it.
//!
//! Reuses the source-parsing + transport rules from
//! [`super::fetch::BundleSource`] (local path, `https://` URL, or `oci://`
//! registry reference; plain HTTP refused unless `--allow-http`; a tag
//! reference refused under `--prod`). After verification
//! the archive is atomically installed under
//! `~/.mvm/bundles/<bundle_sha256>/` via
//! [`mvm_core::plan::BundleRegistry::install`]; the archive bytes are
//! also written to `<bundle_sha256>.mvmpkg` so the
//! `FsBundleResolver` admit-time path finds them too.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::{BundleRegistry, FsTrustStore};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;
use super::fetch::{LoadOptions, load_bundle};
use super::registry::display_reference;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Local path to a `.mvmpkg` archive, an `https://` URL, or an
    /// `oci://<registry>/<repository>:<tag>` or `@sha256:<digest>`
    /// registry reference (HTTP is opt-in via `--allow-http`).
    #[arg(value_name = "SOURCE")]
    pub source: String,
    /// Override the trust store directory. Defaults to
    /// `~/.mvm/trusted-publishers/`.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Override the bundle registry root. Defaults to
    /// `~/.mvm/bundles/`.
    #[arg(long, value_name = "DIR")]
    pub registry: Option<PathBuf>,
    /// Allow plain-HTTP downloads and registries. The Ed25519 signature
    /// still catches tampering, but HTTP exposes traffic metadata. Off
    /// by default.
    #[arg(long)]
    pub allow_http: bool,
    /// Production mode. Refuses `--allow-http` for every source. For an
    /// `oci://` source, also refuses a tag instead of a digest and a registry
    /// the OCI registry policy does not allow, before contacting it. Paths
    /// and `https://` URLs are not restricted further; every source must
    /// still pass the signature check.
    #[arg(long)]
    pub prod: bool,
    /// Overwrite an existing install with the same bundle_sha256
    /// instead of erroring. Bundles are content-addressed so a
    /// matching sha256 means the contents are byte-identical
    /// anyway; `--force` just makes that explicit.
    #[arg(long)]
    pub force: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let loaded = load_bundle(
        &args.source,
        LoadOptions {
            allow_http: args.allow_http,
            prod: args.prod,
        },
    )
    .with_context(|| format!("loading bundle archive from {}", args.source))?;
    let bytes = loaded.bytes;

    let trust = match args.trust_store {
        Some(p) => FsTrustStore::new(p),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?,
    };
    let registry = match args.registry {
        Some(p) => BundleRegistry::new(p),
        None => BundleRegistry::default_path()
            .context("resolving default bundle registry root (~/.mvm/bundles/)")?,
    };

    let installed = registry
        .install(&bytes, &trust, args.force)
        .with_context(|| format!("installing bundle from {}", args.source))?;

    let source = audit_source(&args.source, loaded.resolved.as_ref());
    mvm_core::audit_emit!(
        BundleInstall,
        "bundle_sha256={},key_id={},source={}",
        installed.sha256,
        installed.manifest.key_id.0,
        source,
    );

    println!(
        "Installed bundle {} ({} artifacts, publisher key_id={})",
        installed.sha256,
        installed.manifest.artifacts.len(),
        installed.manifest.key_id.0,
    );
    println!("  registry root: {}", installed.root.display());
    if let Some(resolved) = &loaded.resolved {
        println!("  source:        {}", display_reference(resolved));
    }
    println!(
        "  launch with:   mvmctl machine run --manifest {}",
        installed.sha256
    );
    Ok(())
}

/// The source as the audit entry records it: the digest-pinned reference for
/// a registry pull, and a URL without userinfo, query or fragment, which is
/// where a signed download link would carry its credentials.
fn audit_source(source: &str, resolved: Option<&mvm_fs::oci::ImageReference>) -> String {
    if let Some(resolved) = resolved {
        return display_reference(resolved);
    }
    match mvm_http::Url::parse(source) {
        Ok(mut url) if matches!(url.scheme(), "http" | "https") => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        _ => source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_source_records_the_resolved_digest_for_a_registry_pull() {
        let resolved: mvm_fs::oci::ImageReference =
            format!("registry.example/team/app@sha256:{}", "a".repeat(64))
                .parse()
                .expect("reference");
        assert_eq!(
            audit_source("oci://registry.example/team/app:v1", Some(&resolved)),
            format!("oci://registry.example/team/app@sha256:{}", "a".repeat(64))
        );
    }

    #[test]
    fn audit_source_strips_credentials_from_a_url() {
        assert_eq!(
            audit_source("https://user:pw@cdn.example/app.mvmpkg?sig=secret#x", None),
            "https://cdn.example/app.mvmpkg"
        );
        assert_eq!(audit_source("./app.mvmpkg", None), "./app.mvmpkg");
    }
}
