//! `mvmctl bundle install <SOURCE>` — verify a `.mvmpkg` archive
//! and extract it into the local bundle registry so subsequent
//! `mvmctl machine run --manifest <bundle-sha256>` calls can launch from it.
//!
//! The same install backs `--manifest <app.mvmpkg>` on `mvmctl run` and
//! `mvmctl machine run` ([`settle_manifest_archive`]): the archive is verified
//! and installed, and the run continues as a launch of its bundle sha256.
//!
//! Reuses the source-parsing + transport rules from
//! [`super::fetch::BundleSource`] (local path, `https://` URL, or `oci://`
//! registry reference; plain HTTP refused unless `--allow-http`; a tag
//! reference refused under `--prod`). The archive is streamed into
//! `~/.mvm/bundles/<bundle_sha256>/` by
//! [`mvm_core::plan::BundleRegistry::install_file`], each artifact hashed on
//! its way in and the directory promoted only once all of them verified; the
//! archive is also copied to `<bundle_sha256>.mvmpkg` so the
//! `FsBundleResolver` admit-time path finds it too. Nothing reads the archive
//! into memory whole.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::bundle::{
    BundleInstallError, BundleRegistry, FsTrustStore, InstalledBundle, verify_bundle_file,
};
use mvm_core::user_config::MvmConfig;
use mvm_fs::oci::ImageReference;

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
    let trust = trust_store(args.trust_store)?;
    let registry = bundle_registry(args.registry)?;

    let installed = install_archive(
        ArchiveInstall {
            source: &args.source,
            archive: loaded.path(),
            resolved: loaded.resolved.as_ref(),
            on_existing: if args.force {
                OnExisting::Replace
            } else {
                OnExisting::Refuse
            },
        },
        &trust,
        &registry,
    )?
    .bundle;

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

fn trust_store(dir: Option<PathBuf>) -> Result<FsTrustStore> {
    match dir {
        Some(p) => Ok(FsTrustStore::new(p)),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)"),
    }
}

fn bundle_registry(root: Option<PathBuf>) -> Result<BundleRegistry> {
    match root {
        Some(p) => Ok(BundleRegistry::new(p)),
        None => BundleRegistry::default_path()
            .context("resolving default bundle registry root (~/.mvm/bundles/)"),
    }
}

/// What an install does when the registry already holds the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnExisting {
    /// Refuse, so `bundle install` tells the user it was already there.
    Refuse,
    /// Replace the extracted tree (`bundle install --force`).
    Replace,
    /// Keep it. The archive that just verified hashes to the installed
    /// sha256, so the registry already holds exactly these bytes.
    Reuse,
}

struct ArchiveInstall<'a> {
    /// Where the bytes came from, as the user named it.
    source: &'a str,
    archive: &'a Path,
    /// The digest-pinned reference a registry pull resolved to.
    resolved: Option<&'a ImageReference>,
    on_existing: OnExisting,
}

struct Installed {
    bundle: InstalledBundle,
    /// The registry already held this bundle and nothing was written.
    reused: bool,
}

/// Verify an archive against `trust` and install it into `registry`.
///
/// Verification runs on every path, a reuse included: the registry checks the
/// signature, the publisher key and every artifact hash before it looks for
/// an existing install. Only a fresh install is audited, because only a fresh
/// install changes what the registry can boot.
fn install_archive(
    request: ArchiveInstall<'_>,
    trust: &FsTrustStore,
    registry: &BundleRegistry,
) -> Result<Installed> {
    let force = request.on_existing == OnExisting::Replace;
    let bundle = match registry.install_file(request.archive, trust, force) {
        Ok(bundle) => bundle,
        Err(BundleInstallError::AlreadyInstalled { bundle_sha256 })
            if request.on_existing == OnExisting::Reuse =>
        {
            let bundle = registry
                .find(&bundle_sha256)?
                .with_context(|| format!("bundle {bundle_sha256} vanished from the registry"))?;
            return Ok(Installed {
                bundle,
                reused: true,
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("installing bundle from {}", request.source));
        }
    };

    let source = audit_source(request.source, request.resolved);
    mvm_core::audit_emit!(
        BundleInstall,
        "bundle_sha256={},key_id={},source={}",
        bundle.sha256,
        bundle.manifest.key_id.0,
        source,
    );
    Ok(Installed {
        bundle,
        reused: false,
    })
}

/// Turn a run's `--manifest <app.mvmpkg>` into the bundle sha256 the boot path
/// resolves, verifying and installing the archive on the way.
///
/// After this returns, `manifest` holds a strict 64-character bundle address,
/// so the launch is exactly a `--manifest <bundle-sha256>` launch: the same
/// plan synthesis, signing, and admit-time bundle re-verification. A manifest
/// that is not an archive is left alone.
///
/// The archive is verified against the default trust store before anything is
/// written, and a refusal carries the verifier's own error, so an unsigned,
/// tampered, or unknown-publisher archive never reaches a backend. A dry run
/// verifies and stops there; it installs nothing.
pub(in crate::commands) fn settle_manifest_archive(
    manifest: &mut Option<String>,
    dry_run: bool,
) -> Result<()> {
    let Some(arg) = manifest.as_deref() else {
        return Ok(());
    };
    if !mvm_client::launch::manifest_ref::is_bundle_archive(std::path::Path::new(arg)) {
        return Ok(());
    }
    let loaded = load_bundle(arg, LoadOptions::default())?;
    let trust = trust_store(None)?;
    // Timed from here, after the archive is local: verification is the cost a
    // launch from a signed artifact pays on every run, and the launch sample
    // reports it beside the boot so the two are never folded together.
    let verify_started = std::time::Instant::now();
    let sha256 = if dry_run {
        let sha256 = verify_bundle_file(loaded.path(), &trust)
            .with_context(|| format!("verifying bundle archive {arg}"))?
            .bundle_sha256;
        eprintln!("[mvm] verified {arg} as bundle {sha256} (dry run: not installed)");
        sha256
    } else {
        let installed = install_archive(
            ArchiveInstall {
                source: arg,
                archive: loaded.path(),
                resolved: None,
                on_existing: OnExisting::Reuse,
            },
            &trust,
            &bundle_registry(None)?,
        )?;
        let bundle = installed.bundle;
        if installed.reused {
            eprintln!(
                "[mvm] verified {arg}: bundle {} is already installed",
                bundle.sha256
            );
        } else {
            eprintln!(
                "[mvm] verified {arg} and installed it as bundle {} (publisher key_id={})",
                bundle.sha256, bundle.manifest.key_id.0
            );
        }
        bundle.sha256
    };
    mvm_core::launch_trace::record_bundle_verify(verify_started.elapsed());
    *manifest = Some(sha256);
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
    use mvm_core::plan::bundle::bundle_sha256;

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

    use ed25519_dalek::SigningKey;
    use mvm_core::arch::GuestArch;
    use mvm_core::plan::bundle::{
        ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, key_id_from_pubkey,
        sha256_hex, write_bundle,
    };
    use mvm_core::util::test_env::TestEnv;

    const ROOTFS: &[u8] = b"rootfs-payload-for-the-run-path";

    /// An isolated `MVM_HOME` holding a publisher key and, when `trusted`,
    /// that key enrolled in the default trust store.
    struct Host {
        _env: TestEnv,
        home: tempfile::TempDir,
        key: SigningKey,
    }

    impl Host {
        fn new(trusted: bool) -> Self {
            let home = tempfile::tempdir().expect("mvm home");
            let mut env = TestEnv::new();
            env.isolate_mvm_home(home.path());
            let key = SigningKey::from_bytes(&[7; 32]);
            if trusted {
                let trust = home.path().join("trusted-publishers");
                std::fs::create_dir_all(&trust).expect("trust store");
                let key_id = key_id_from_pubkey(&key.verifying_key());
                std::fs::write(
                    trust.join(format!("{}.pub", key_id.0)),
                    key.verifying_key().to_bytes(),
                )
                .expect("enrol publisher");
            }
            Self {
                _env: env,
                home,
                key,
            }
        }

        /// A signed kernel + rootfs bundle for this host's arch, written to
        /// `app.mvmpkg` in a directory of its own.
        fn archive(&self) -> (tempfile::TempDir, std::path::PathBuf, Vec<u8>) {
            let kernel = b"kernel-payload".to_vec();
            let artifact = |name: &str, role, path: &str, bytes: &[u8]| BundleArtifact {
                name: name.to_string(),
                role,
                path: path.to_string(),
                sha256: sha256_hex(bytes),
                size_bytes: bytes.len() as u64,
            };
            let manifest = BundleManifest {
                schema_version: BUNDLE_SCHEMA_VERSION,
                publisher: "run-path-test".to_string(),
                key_id: key_id_from_pubkey(&self.key.verifying_key()),
                arch: GuestArch::host().to_string(),
                kernel_version: None,
                profile: None,
                workload_label: Some("run-path".to_string()),
                created_at: "2026-10-04T00:00:00Z".to_string(),
                labels: Default::default(),
                artifacts: vec![
                    artifact(
                        "vmlinux",
                        ArtifactRole::Kernel,
                        "artifacts/vmlinux",
                        &kernel,
                    ),
                    artifact(
                        "rootfs.ext4",
                        ArtifactRole::Rootfs,
                        "artifacts/rootfs.ext4",
                        ROOTFS,
                    ),
                ],
                members: Vec::new(),
                verity: None,
                resources: None,
            };
            let bytes = write_bundle(
                &manifest,
                &self.key,
                vec![
                    ("artifacts/vmlinux".to_string(), kernel),
                    ("artifacts/rootfs.ext4".to_string(), ROOTFS.to_vec()),
                ],
            )
            .expect("write bundle");
            let dir = tempfile::tempdir().expect("archive dir");
            let path = dir.path().join("app.mvmpkg");
            std::fs::write(&path, &bytes).expect("write archive");
            (dir, path, bytes)
        }

        fn registry(&self) -> BundleRegistry {
            BundleRegistry::new(self.home.path().join("bundles"))
        }

        fn installed(&self) -> Vec<String> {
            match std::fs::read_dir(self.home.path().join("bundles")) {
                Ok(entries) => entries
                    .map(|entry| {
                        entry
                            .expect("entry")
                            .file_name()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .filter(|name| name.len() == 64)
                    .collect(),
                Err(_) => Vec::new(),
            }
        }
    }

    fn settle(path: &std::path::Path, dry_run: bool) -> (Option<String>, Result<()>) {
        let mut manifest = Some(path.display().to_string());
        let result = settle_manifest_archive(&mut manifest, dry_run);
        (manifest, result)
    }

    #[test]
    fn a_signed_archive_is_installed_and_becomes_its_bundle_address() {
        let host = Host::new(true);
        let (_dir, path, bytes) = host.archive();

        let (manifest, result) = settle(&path, false);
        result.expect("a signed archive settles");
        // The launch sample reads this to put the artifact launch in its own
        // lane; an archive that verified without recording it would be
        // measured as a prepared launch that never verified anything.
        assert!(
            mvm_core::launch_trace::recorded_acquisition()
                .bundle_verify_us
                .is_some(),
            "a settled archive must record its verification"
        );

        let sha = bundle_sha256(&bytes);
        assert_eq!(manifest.as_deref(), Some(sha.as_str()));
        assert!(host.registry().find(&sha).expect("find").is_some());
        assert!(host.registry().archive_path(&sha).is_file());
        // The address the run now carries is the one `--manifest <sha>`
        // boots: the launch resolver accepts it as an installed bundle.
        let resolved = mvm_client::launch::manifest_ref::resolve_manifest_arg(&sha)
            .expect("the installed bundle resolves on the boot path");
        assert!(matches!(
            resolved,
            mvm_client::launch::manifest_ref::ManifestArgRef::Slot { slot_hash } if slot_hash == sha
        ));
    }

    #[test]
    fn an_archive_already_installed_is_verified_again_and_reused() {
        let host = Host::new(true);
        let (_dir, path, bytes) = host.archive();
        settle(&path, false).1.expect("first install");

        let (manifest, result) = settle(&path, false);

        result.expect("an installed archive is reused, not refused");
        assert_eq!(manifest, Some(bundle_sha256(&bytes)));
        assert_eq!(host.installed().len(), 1);
    }

    #[test]
    fn a_tampered_archive_is_refused_and_nothing_is_installed() {
        let host = Host::new(true);
        let (_dir, path, mut bytes) = host.archive();
        let at = bytes
            .windows(ROOTFS.len())
            .position(|window| window == ROOTFS)
            .expect("the rootfs payload is stored uncompressed");
        bytes[at] ^= 0xff;
        std::fs::write(&path, &bytes).expect("rewrite archive");

        let (manifest, result) = settle(&path, false);

        let err = result.expect_err("a tampered artifact must be refused");
        assert!(
            format!("{err:#}").contains("sha256 mismatch"),
            "the refusal carries the verifier's error: {err:#}"
        );
        assert_eq!(manifest, Some(path.display().to_string()));
        assert!(host.installed().is_empty());
    }

    #[test]
    fn an_archive_from_an_unknown_publisher_is_refused() {
        let host = Host::new(false);
        let (_dir, path, _) = host.archive();

        let (_, result) = settle(&path, false);

        let err = result.expect_err("an unknown publisher must be refused");
        assert!(
            format!("{err:#}").contains("trust store has no entry for key_id"),
            "the refusal names the missing key: {err:#}"
        );
        assert!(host.installed().is_empty());
    }

    /// The trust store is keyed by `key_id`, so the file it hands back is the
    /// only link from the id an archive declares to the key that must have
    /// signed it. A store entry for the archive's id holding some other key is
    /// a misfiled or substituted key, and the run refuses rather than trusting
    /// whichever key happens to sit under that name.
    #[test]
    fn an_archive_whose_key_id_is_enrolled_under_another_key_is_refused() {
        let host = Host::new(false);
        let declared = key_id_from_pubkey(&host.key.verifying_key());
        let substituted = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let trust = host.home.path().join("trusted-publishers");
        std::fs::create_dir_all(&trust).expect("trust store");
        std::fs::write(
            trust.join(format!("{}.pub", declared.0)),
            substituted.to_bytes(),
        )
        .expect("misfile a key");
        let (_dir, path, _) = host.archive();

        let (manifest, result) = settle(&path, false);

        let err = result.expect_err("an archive must verify under its own key");
        assert!(
            format!("{err:#}").contains("but trust store entry is for"),
            "the refusal names the key mismatch: {err:#}"
        );
        assert_eq!(manifest, Some(path.display().to_string()));
        assert!(host.installed().is_empty());
    }

    #[test]
    fn an_unsigned_archive_is_refused() {
        let host = Host::new(true);
        let dir = tempfile::tempdir().expect("archive dir");
        let path = dir.path().join("app.mvmpkg");
        std::fs::write(&path, b"not a signed bundle").expect("write archive");

        let (_, result) = settle(&path, false);

        result.expect_err("bytes without a signed manifest must be refused");
        assert!(host.installed().is_empty());
    }

    #[test]
    fn a_dry_run_verifies_without_installing() {
        let host = Host::new(true);
        let (_dir, path, bytes) = host.archive();

        let (manifest, result) = settle(&path, true);

        result.expect("a signed archive verifies");
        assert_eq!(manifest, Some(bundle_sha256(&bytes)));
        assert!(host.installed().is_empty());
    }

    #[test]
    fn a_manifest_that_is_not_an_archive_is_left_alone() {
        let _host = Host::new(true);
        for arg in [
            "e".repeat(64),
            "./mvm.toml".to_string(),
            "./project".to_string(),
        ] {
            let mut manifest = Some(arg.clone());
            settle_manifest_archive(&mut manifest, false).expect("nothing to settle");
            assert_eq!(manifest, Some(arg));
        }
        let mut none = None;
        settle_manifest_archive(&mut none, false).expect("no manifest");
        assert_eq!(none, None);
    }

    #[test]
    fn bundle_install_still_refuses_a_second_install_without_force() {
        let host = Host::new(true);
        let (_dir, path, _bytes) = host.archive();
        let trust = trust_store(None).expect("trust store");
        let install = |on_existing| {
            install_archive(
                ArchiveInstall {
                    source: "./app.mvmpkg",
                    archive: &path,
                    resolved: None,
                    on_existing,
                },
                &trust,
                &host.registry(),
            )
        };
        assert!(!install(OnExisting::Refuse).expect("first install").reused);

        let err = install(OnExisting::Refuse)
            .err()
            .expect("a second install without --force is refused");
        assert!(format!("{err:#}").contains("already installed"), "{err:#}");
        assert!(
            !install(OnExisting::Replace)
                .expect("--force replaces")
                .reused
        );
    }
}
