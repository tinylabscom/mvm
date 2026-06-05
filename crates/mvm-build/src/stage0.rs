//! Stage 0 bootstrap — materializes a host directory tree from
//! Alpine Linux's official minirootfs tarball, layered with our
//! `init.sh` and mountpoint stubs. libkrun mounts that directory
//! as the guest root over virtiofs (`krun_set_root`), boots
//! libkrunfw's bundled kernel, and runs our `init` (set via
//! `krun_set_exec`). The init script uses Alpine's `apk-tools` to
//! `apk add nix` from Alpine's signed package repos, then runs
//! `nix build` against the in-repo `nix/images/builder-vm` flake,
//! emitting kernel + rootfs.ext4 on the `/out` virtio-fs share.
//!
//! Bootstrap surface:
//!
//! 1. **`init.sh`** (embedded via `include_str!`) — the PID-1
//!    shell script the kernel-cmdline `init=/init` resolves to.
//! 2. **Alpine minirootfs** (~4 MiB compressed) — fetched once from
//!    Alpine's official mirror, SHA-256 verified, AND PGP-verified
//!    against Alpine's release-signing key (Natanael Copa,
//!    embedded as [`ALPINE_RELEASE_KEY_ASC`]). The tarball provides
//!    busybox, `apk-tools`, libc, ca-certificates, and the standard
//!    `/etc/apk/keys/` chain. See [`ALPINE_MINIROOTFS_AARCH64`] /
//!    [`ALPINE_MINIROOTFS_X86_64`].
//!
//! Per-run, [`materialize_root_dir`] re-verifies the cached
//! tarball (SHA-256 + PGP) and extracts it into a caller-supplied
//! directory, then writes [`INIT_SCRIPT`] to `init` (mode 0755).
//! The supervisor hands that directory to libkrun via
//! `krun_set_root` and `krun_set_exec` with `argv[0] = "/init"`.
//!
//! # Trust model
//!
//! The Alpine tarball is hash-pinned in source AND PGP-verified
//! against an embedded Alpine release-signing key. Both checks
//! fail-closed:
//!
//! - SHA-256 catches tampering by anyone with cached-file write
//!   access between fetch and extraction.
//! - PGP catches a malicious upstream mirror that signs with the
//!   wrong key (or doesn't sign at all). The expected key
//!   fingerprint is also pinned in source as
//!   [`ALPINE_RELEASE_KEY_FINGERPRINT`] — even if someone tampered
//!   with [`ALPINE_RELEASE_KEY_ASC`], the fingerprint check would
//!   fail the verification.
//!
//! Subsequent in-VM `apk add` calls inherit Alpine's own signature
//! verification (signed APKINDEX + signed packages against keys
//! shipped under `/etc/apk/keys/`).

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;

/// PID-1 shell script. Compiled into the binary so a fresh `mvmctl`
/// can always emit it without consulting the cache or the network.
pub const INIT_SCRIPT: &str = include_str!("stage0/init.sh");

/// Alpine release version we pin to. Single source of truth for
/// the URL builders below. Bump together with the per-arch
/// SHA-256 pins.
pub const ALPINE_VERSION: &str = "3.22.4";
/// Major.minor of [`ALPINE_VERSION`]. Used to build the `apk`
/// repository URLs the in-VM init writes to
/// `/etc/apk/repositories`. Bump in lockstep with
/// [`ALPINE_VERSION`].
pub const ALPINE_BRANCH: &str = "v3.22";

/// Alpine's release-signing PGP key (Natanael Copa,
/// `ncopa@alpinelinux.org`). Source:
/// `https://alpinelinux.org/keys/ncopa.asc`.
///
/// Vendored in-tree so a fresh `mvmctl dev up` doesn't need to
/// fetch the key from the network (which would itself be an
/// unverified channel). The expected fingerprint is also pinned
/// in [`ALPINE_RELEASE_KEY_FINGERPRINT`]; on verification we
/// confirm the parsed key matches that fingerprint, so swapping
/// the embedded bytes would fail-close too.
pub const ALPINE_RELEASE_KEY_ASC: &[u8] = include_bytes!("stage0/alpine-ncopa-release-key.asc");

/// Expected fingerprint of [`ALPINE_RELEASE_KEY_ASC`]. RSA primary
/// key, uppercase hex (40 chars, no spaces). Bump only when Alpine
/// rotates the release-signing key — a multi-year cadence.
pub const ALPINE_RELEASE_KEY_FINGERPRINT: &str = "0482D84022F52DF1C4E7CD43293ACD0907D9495A";

/// One downloadable bootstrap asset, pinned by upstream URL +
/// SHA-256, optionally with a PGP detached-signature URL. The
/// cache key is [`Self::cache_filename`].
#[derive(Debug, Clone, Copy)]
pub struct BootstrapAsset {
    /// Where the file lands inside [`stage0_cache_dir`].
    pub cache_filename: &'static str,
    /// Upstream URL. Pinned to a specific version; never moves.
    pub url: &'static str,
    /// SHA-256 of the byte stream at [`Self::url`]. Hex (64 chars).
    pub sha256_hex: &'static str,
    /// Optional URL of an armored PGP detached signature
    /// (`.asc`) over [`Self::url`]'s bytes. When `Some`, the
    /// signature is fetched alongside the file, cached at
    /// `<cache_filename>.asc`, and verified against
    /// [`ALPINE_RELEASE_KEY_ASC`] on every fetch + every
    /// re-materialize.
    pub signature_url: Option<&'static str>,
    /// File mode the asset gets on disk (and inside the root dir).
    pub mode: u32,
}

/// Alpine minirootfs for aarch64-linux guests. Tarball + gzip,
/// ~4 MiB. Includes busybox, apk-tools, libc, ca-certificates,
/// and `/etc/apk/keys/` (Alpine's signing keys for `apk-tools`'s
/// signature verification on subsequent `apk add` calls).
///
/// Pinned in lockstep with [`ALPINE_VERSION`] above. Bump both
/// constants together when refreshing.
pub const ALPINE_MINIROOTFS_AARCH64: BootstrapAsset = BootstrapAsset {
    cache_filename: "alpine-minirootfs-aarch64.tar.gz",
    url: "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.4-aarch64.tar.gz",
    sha256_hex: "fc11cf987b37b2e57969cea7e0b8df0777e572d41fe20731630c1e926a8a07a2",
    signature_url: Some(
        "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.4-aarch64.tar.gz.asc",
    ),
    mode: 0o644,
};

/// Alpine minirootfs for x86_64-linux guests. Same shape as
/// [`ALPINE_MINIROOTFS_AARCH64`]; used on Linux KVM hosts (the
/// supported non-macOS path).
pub const ALPINE_MINIROOTFS_X86_64: BootstrapAsset = BootstrapAsset {
    cache_filename: "alpine-minirootfs-x86_64.tar.gz",
    url: "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.4-x86_64.tar.gz",
    sha256_hex: "0737c622ddefa7c91767ce8ab5dd4722f265cd580b21332ec5f22cfe54a84251",
    signature_url: Some(
        "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.4-x86_64.tar.gz.asc",
    ),
    mode: 0o644,
};

/// Every downloadable asset Stage 0 needs on an aarch64-linux
/// guest. (Host is macOS aarch64 in practice; the guest arch is
/// what matters for the asset selection.)
pub const ASSETS_AARCH64: &[&BootstrapAsset] = &[&ALPINE_MINIROOTFS_AARCH64];

/// Every downloadable asset Stage 0 needs on an x86_64-linux
/// guest. Linux KVM host path.
pub const ASSETS_X86_64: &[&BootstrapAsset] = &[&ALPINE_MINIROOTFS_X86_64];

/// Select the right asset table for the host's target arch. The
/// macOS aarch64 host boots aarch64 Linux guests; the Linux x86_64
/// host boots x86_64 Linux guests. Other host arches aren't
/// supported and return an empty slice.
pub fn assets_for_host_arch() -> &'static [&'static BootstrapAsset] {
    #[cfg(target_arch = "aarch64")]
    {
        ASSETS_AARCH64
    }
    #[cfg(target_arch = "x86_64")]
    {
        ASSETS_X86_64
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        &[]
    }
}

/// Resolve the Alpine minirootfs asset that matches the host's
/// target arch.
pub fn alpine_minirootfs_for_host_arch() -> Option<&'static BootstrapAsset> {
    #[cfg(target_arch = "aarch64")]
    {
        Some(&ALPINE_MINIROOTFS_AARCH64)
    }
    #[cfg(target_arch = "x86_64")]
    {
        Some(&ALPINE_MINIROOTFS_X86_64)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        None
    }
}

// ============================================================================
// Plan 160 — nix-tarball seed (the busybox/static-Nix replacement for the
// Alpine minirootfs seed). The official Nix release tarball is a
// self-contained `/nix/store` (nix + bash + curl + xz + nss-cacert) — no
// apk, no Alpine, no external busybox, **no PGP** (SHA-256 pin only; the
// hash is the binding integrity check, same as the Alpine tarball's).
// ============================================================================

/// Nix release we seed from. Bump in lockstep with the SHA-256 pins below.
pub const NIX_SEED_VERSION: &str = "2.31.1";

/// Official Nix release tarball for aarch64-linux guests (~23 MiB). When
/// extracted, its `store/` IS a populated `/nix/store` carrying the `nix`
/// binary + its runtime closure. `signature_url: None` — SHA-256 only.
pub const NIX_SEED_AARCH64: BootstrapAsset = BootstrapAsset {
    cache_filename: "nix-seed-aarch64.tar.xz",
    url: "https://releases.nixos.org/nix/nix-2.31.1/nix-2.31.1-aarch64-linux.tar.xz",
    sha256_hex: "4ae8cb26dada33765f3068d185b36dcfe23efba2ba678048b70d36d8b1553850",
    signature_url: None,
    mode: 0o644,
};

/// Official Nix release tarball for x86_64-linux guests (Linux KVM path).
pub const NIX_SEED_X86_64: BootstrapAsset = BootstrapAsset {
    cache_filename: "nix-seed-x86_64.tar.xz",
    url: "https://releases.nixos.org/nix/nix-2.31.1/nix-2.31.1-x86_64-linux.tar.xz",
    sha256_hex: "75f18f5d567bb8c7b5d62155f8c852e62ffac0c81acda02f52b998281e3603ce",
    signature_url: None,
    mode: 0o644,
};

/// The nix-seed asset table for the host's target arch (parallel to
/// [`assets_for_host_arch`]; one asset, fed to [`prepare_assets`]).
pub fn nix_seed_assets_for_host_arch() -> &'static [&'static BootstrapAsset] {
    #[cfg(target_arch = "aarch64")]
    {
        &[&NIX_SEED_AARCH64]
    }
    #[cfg(target_arch = "x86_64")]
    {
        &[&NIX_SEED_X86_64]
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        &[]
    }
}

/// Resolve the nix-seed tarball asset for the host's target arch.
pub fn nix_seed_for_host_arch() -> Option<&'static BootstrapAsset> {
    #[cfg(target_arch = "aarch64")]
    {
        Some(&NIX_SEED_AARCH64)
    }
    #[cfg(target_arch = "x86_64")]
    {
        Some(&NIX_SEED_X86_64)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        None
    }
}

/// Which Stage 0 seed to use: the legacy Alpine minirootfs (`alpine`,
/// default) or the nix tarball (`nix`, plan 160). Selected by
/// `MVM_STAGE0_SEED`; unknown values warn + fall back to `alpine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage0Seed {
    Alpine,
    Nix,
}

impl Stage0Seed {
    pub fn from_env() -> Self {
        match std::env::var("MVM_STAGE0_SEED").ok().as_deref() {
            Some(v) if v.eq_ignore_ascii_case("nix") => Stage0Seed::Nix,
            Some(other) if !other.is_empty() && !other.eq_ignore_ascii_case("alpine") => {
                eprintln!("mvm: unrecognized MVM_STAGE0_SEED={other:?}; using `alpine`");
                Stage0Seed::Alpine
            }
            _ => Stage0Seed::Alpine,
        }
    }
}

/// `~/.cache/mvm/stage0/`. Materialized by [`prepare_assets`].
pub fn stage0_cache_dir() -> PathBuf {
    // Honors MVM_CACHE_DIR / XDG_CACHE_HOME (parallel sessions isolate
    // via MVM_CACHE_DIR) instead of the old hardcoded $HOME/.cache/mvm.
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join("stage0")
}

/// Path on disk where the detached signature for `asset` is
/// cached, relative to `cache_dir`. Mirrors `<cache_filename>.asc`
/// next to the data.
fn signature_cache_path_in(cache_dir: &Path, asset: &BootstrapAsset) -> PathBuf {
    cache_dir.join(format!("{}.asc", asset.cache_filename))
}

/// Ensure every entry in `assets` is present in the cache dir
/// with the matching SHA-256 (and PGP signature when applicable).
/// Missing assets are fetched via `reqwest::blocking::get`;
/// mismatched ones are re-fetched (the existing file is moved
/// aside before the new one writes, so an interrupted download
/// never leaves a half-trusted file in place).
///
/// Network access only happens on first run (or after a manual
/// cache prune). Subsequent invocations short-circuit on the
/// per-file sha256 check.
pub fn prepare_assets(assets: &[&BootstrapAsset]) -> Result<Vec<VendorBlobReport>> {
    prepare_assets_in(&stage0_cache_dir(), assets)
}

/// Like [`prepare_assets`] but takes the cache directory
/// explicitly. Production callers go through [`prepare_assets`];
/// tests use this to avoid mutating the `HOME` env var.
///
/// Returns one [`VendorBlobReport`] per asset describing whether it
/// was freshly fetched or revalidated from cache, its verified
/// SHA-256, and its PGP verdict. The host caller turns each into a
/// `LocalAuditKind::VendorBlobFetched` audit entry (Plan 93 Phase 3)
/// so every supply-chain trust decision is auditable. `mvm-build`
/// stays audit-free; the caller (in `mvm-cli`) owns the emit.
pub fn prepare_assets_in(
    cache_dir: &Path,
    assets: &[&BootstrapAsset],
) -> Result<Vec<VendorBlobReport>> {
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating {}", cache_dir.display()))?;

    let mut reports = Vec::with_capacity(assets.len());
    for asset in assets {
        let target = cache_dir.join(asset.cache_filename);
        let sig_target = signature_cache_path_in(cache_dir, asset);

        let cache_hit = target.is_file()
            && verify_sha256(&target, asset.sha256_hex)?
            && (asset.signature_url.is_none() || sig_target.is_file());

        if cache_hit {
            // Belt + suspenders: also re-verify the PGP signature
            // on every prepare. A tampered cached file with the
            // wrong signature fails here, not at extract time.
            if asset.signature_url.is_some() {
                let data = std::fs::read(&target)
                    .with_context(|| format!("reading cached {}", target.display()))?;
                let sig = std::fs::read(&sig_target)
                    .with_context(|| format!("reading cached {}", sig_target.display()))?;
                verify_alpine_pgp_signature(&data, &sig).with_context(|| {
                    format!("verifying cached PGP signature for {}", target.display())
                })?;
            }
            reports.push(VendorBlobReport::for_asset(
                asset,
                blob_size(&target),
                VendorBlobOutcome::CacheRevalidated,
            ));
            continue;
        }

        fetch_to(&target, asset).with_context(|| format!("fetching {}", asset.url))?;
        if let Some(sig_url) = asset.signature_url {
            fetch_signature(&sig_target, sig_url).with_context(|| format!("fetching {sig_url}"))?;
            let data =
                std::fs::read(&target).with_context(|| format!("reading {}", target.display()))?;
            let sig = std::fs::read(&sig_target)
                .with_context(|| format!("reading {}", sig_target.display()))?;
            verify_alpine_pgp_signature(&data, &sig).with_context(|| {
                format!(
                    "verifying PGP signature for {} against embedded Alpine key",
                    target.display()
                )
            })?;
        }
        reports.push(VendorBlobReport::for_asset(
            asset,
            blob_size(&target),
            VendorBlobOutcome::Fetched,
        ));
    }
    Ok(reports)
}

/// Best-effort on-disk size of a freshly verified blob, for the
/// `bytes=` field of the audit report. A stat failure degrades to 0
/// rather than failing the (already successful) verification.
fn blob_size(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// PGP verdict recorded for a vendored-blob fetch/revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorBlobPgp {
    /// Carried a detached signature that verified against the
    /// embedded Alpine signing key.
    Verified,
    /// No `signature_url` (nothing to verify).
    None,
    /// Reserved for emitting a failed-verification report before
    /// propagating the error; `prepare_assets_in` itself bails on a
    /// bad signature rather than returning this.
    Failed,
}

impl VendorBlobPgp {
    pub fn as_str(self) -> &'static str {
        match self {
            VendorBlobPgp::Verified => "verified",
            VendorBlobPgp::None => "none",
            VendorBlobPgp::Failed => "failed",
        }
    }
}

/// Whether a vendored blob was freshly downloaded or re-validated
/// from the on-disk cache during this `prepare_assets` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendorBlobOutcome {
    Fetched,
    CacheRevalidated,
}

impl VendorBlobOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            VendorBlobOutcome::Fetched => "fetched",
            VendorBlobOutcome::CacheRevalidated => "cache_revalidated",
        }
    }
}

/// One vendored-blob supply-chain event, returned by
/// [`prepare_assets`]. The host caller renders each into a
/// `LocalAuditKind::VendorBlobFetched` audit entry (Plan 93 Phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorBlobReport {
    pub url: &'static str,
    pub sha256_hex: &'static str,
    pub pgp: VendorBlobPgp,
    pub bytes: u64,
    pub outcome: VendorBlobOutcome,
}

impl VendorBlobReport {
    fn for_asset(asset: &BootstrapAsset, bytes: u64, outcome: VendorBlobOutcome) -> Self {
        Self {
            url: asset.url,
            sha256_hex: asset.sha256_hex,
            pgp: if asset.signature_url.is_some() {
                VendorBlobPgp::Verified
            } else {
                VendorBlobPgp::None
            },
            bytes,
            outcome,
        }
    }

    /// The `detail` string for the blob's `VendorBlobFetched` audit
    /// entry: space-separated `key=value` pairs, matching the Stage 0
    /// sibling kinds. Pure — unit-tested without any network fetch.
    pub fn audit_detail(&self) -> String {
        format!(
            "url={} sha256={} pgp={} bytes={} outcome={}",
            self.url,
            self.sha256_hex,
            self.pgp.as_str(),
            self.bytes,
            self.outcome.as_str()
        )
    }
}

/// Mountpoint stubs (extra to whatever Alpine ships) the in-VM
/// init script needs before it can mount the virtio-fs shares.
/// Alpine's minirootfs already includes /proc, /sys, /dev, /tmp,
/// /run, /etc, /bin, /sbin, /usr, /var — we add /work and /out
/// for the virtio-fs mounts and /nix because Nix expects it.
const ROOT_DIR_EXTRA_STUBS: &[&str] = &["work", "out", "nix", "mvm-bins"];

/// Materialize a Stage 0 guest root at `dest` from the embedded
/// init script and the cached Alpine minirootfs tarball. The
/// supervisor hands `dest` to libkrun via `krun_set_root`, which
/// mounts it as the guest root over virtiofs, and via
/// `krun_set_exec` with `entry_path = "/init"`.
///
/// Idempotent over a clean `dest`. Caller is responsible for
/// making sure `dest` is empty (or doesn't exist) — the function
/// creates the directory tree from scratch.
///
/// Caller must have already run [`prepare_assets`] so the Alpine
/// tarball + signature are present in the cache dir. This
/// function re-verifies both before extraction (defense in depth
/// against a tampered cache between fetch and extract).
pub fn materialize_root_dir(dest: &Path) -> Result<()> {
    materialize_root_dir_in(&stage0_cache_dir(), dest)
}

/// Like [`materialize_root_dir`] but reads the cached Alpine
/// tarball from `cache_dir` instead of [`stage0_cache_dir`]. Used
/// by tests so they don't have to mutate `HOME`.
pub fn materialize_root_dir_in(cache_dir: &Path, dest: &Path) -> Result<()> {
    let asset = alpine_minirootfs_for_host_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "Stage 0 has no Alpine minirootfs asset pinned for this host's target arch \
             (expected aarch64 or x86_64)"
        )
    })?;
    let tarball = cache_dir.join(asset.cache_filename);
    if !tarball.is_file() {
        bail!(
            "Stage 0 asset missing: {} (run `prepare_assets` first)",
            tarball.display()
        );
    }
    if !verify_sha256(&tarball, asset.sha256_hex)? {
        bail!(
            "Stage 0 asset sha256 mismatch at {} — refusing to extract a tampered tarball. \
             Delete it and re-run `prepare_assets`.",
            tarball.display()
        );
    }
    if asset.signature_url.is_some() {
        let sig_path = signature_cache_path_in(cache_dir, asset);
        if !sig_path.is_file() {
            bail!(
                "Stage 0 PGP signature missing: {} (run `prepare_assets` first)",
                sig_path.display()
            );
        }
        let data =
            std::fs::read(&tarball).with_context(|| format!("reading {}", tarball.display()))?;
        let sig =
            std::fs::read(&sig_path).with_context(|| format!("reading {}", sig_path.display()))?;
        verify_alpine_pgp_signature(&data, &sig).with_context(|| {
            format!(
                "verifying PGP signature for {} before extraction",
                tarball.display()
            )
        })?;
    }

    std::fs::create_dir_all(dest)
        .with_context(|| format!("creating Stage 0 root dir {}", dest.display()))?;

    extract_alpine_tarball(&tarball, dest)
        .with_context(|| format!("extracting {} into {}", tarball.display(), dest.display()))?;

    for stub in ROOT_DIR_EXTRA_STUBS {
        let p = dest.join(stub);
        std::fs::create_dir_all(&p)
            .with_context(|| format!("creating Stage 0 stub dir {}", p.display()))?;
    }

    write_file_mode(&dest.join("init"), INIT_SCRIPT.as_bytes(), 0o755)
        .context("writing Stage 0 /init")?;

    Ok(())
}

/// Materialize a Stage 0 guest root from the **nix tarball seed** (plan
/// 160). Parallel to [`materialize_root_dir`], but lays down the official
/// Nix release tarball's `/nix/store` + the embedded `stage0-init` binary
/// as `/init` — no Alpine, no apk, no shell `init.sh`. `stage0_init` is the
/// extracted host-vm binary's bytes (the caller pulls it from
/// `mvm_cli::host_binaries`); `mvm-build` can't reach the embed table
/// itself (mvm-cli depends on mvm-build, not the reverse).
pub fn materialize_nix_seed(dest: &Path, stage0_init: &[u8]) -> Result<()> {
    materialize_nix_seed_in(&stage0_cache_dir(), dest, stage0_init)
}

/// Like [`materialize_nix_seed`] but reads the cached tarball from
/// `cache_dir` (tests).
pub fn materialize_nix_seed_in(cache_dir: &Path, dest: &Path, stage0_init: &[u8]) -> Result<()> {
    let asset = nix_seed_for_host_arch().ok_or_else(|| {
        anyhow::anyhow!(
            "Stage 0 has no nix-seed tarball pinned for this host's target arch \
             (expected aarch64 or x86_64)"
        )
    })?;
    let tarball = cache_dir.join(asset.cache_filename);
    if !tarball.is_file() {
        bail!(
            "Stage 0 nix-seed asset missing: {} (run `prepare_assets` first)",
            tarball.display()
        );
    }
    if !verify_sha256(&tarball, asset.sha256_hex)? {
        bail!(
            "Stage 0 nix-seed sha256 mismatch at {} — refusing to extract a tampered \
             tarball. Delete it and re-run `prepare_assets`.",
            tarball.display()
        );
    }

    std::fs::create_dir_all(dest)
        .with_context(|| format!("creating Stage 0 root dir {}", dest.display()))?;

    // The tarball is `nix-<ver>-<arch>-linux/{install,store/,.reginfo}`.
    // Strip the top-level component so `store/` lands at `<dest>/nix/store/`.
    extract_nix_store_tarball(&tarball, &dest.join("nix")).with_context(|| {
        format!(
            "extracting nix seed {} into {}/nix",
            tarball.display(),
            dest.display()
        )
    })?;

    // Virtio-fs mount targets the init needs. `/nix` already exists from the
    // extraction above.
    for stub in ["work", "out", "mvm-bins"] {
        let p = dest.join(stub);
        std::fs::create_dir_all(&p)
            .with_context(|| format!("creating Stage 0 stub dir {}", p.display()))?;
    }

    // The seed's PID 1 is the embedded `stage0-init` binary (not a shell
    // script). `krun_set_exec` runs `/init`.
    write_file_mode(&dest.join("init"), stage0_init, 0o755)
        .context("writing Stage 0 /init (stage0-init binary)")?;

    Ok(())
}

/// Extract the official Nix release tarball into `nix_dir` (= `<root>/nix`),
/// stripping the leading `nix-<ver>-<arch>-linux/` component so `store/`
/// lands at `<nix_dir>/store/`. The install scripts come along harmlessly;
/// the guest never runs them.
///
/// First cut: shells to the host `tar` for the xz decode (macOS bsdtar +
/// GNU tar both handle `.tar.xz` + `--strip-components`) to avoid adding an
/// in-process lzma dependency. A pure-Rust xz decoder (matching the Alpine
/// path's in-process extraction) is a plan-160 polish follow-up.
fn extract_nix_store_tarball(tarball: &Path, nix_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(nix_dir).with_context(|| format!("creating {}", nix_dir.display()))?;
    let status = std::process::Command::new("tar")
        .arg("-xJf")
        .arg(tarball)
        .arg("-C")
        .arg(nix_dir)
        .arg("--strip-components=1")
        .status()
        .with_context(|| format!("spawning tar to extract {}", tarball.display()))?;
    if !status.success() {
        bail!(
            "tar exited {} extracting nix seed {}",
            status.code().unwrap_or(-1),
            tarball.display()
        );
    }
    Ok(())
}

/// Verify a detached OpenPGP signature over `data` against
/// [`ALPINE_RELEASE_KEY_ASC`]. Returns `Ok(())` only when:
///
/// 1. The embedded key parses cleanly.
/// 2. The signing key's primary fingerprint matches
///    [`ALPINE_RELEASE_KEY_FINGERPRINT`].
/// 3. The signature parses cleanly and verifies against `data`.
///
/// Any failure returns an `Err` that describes which step
/// failed.
fn verify_alpine_pgp_signature(data: &[u8], sig_armor: &[u8]) -> Result<()> {
    use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
    use pgp::types::KeyDetails;

    let (key, _headers) = SignedPublicKey::from_armor_single(Cursor::new(ALPINE_RELEASE_KEY_ASC))
        .context("parsing embedded Alpine release-signing key")?;

    let got_fpr = format!("{:X}", key.fingerprint());
    let want_fpr = ALPINE_RELEASE_KEY_FINGERPRINT.to_ascii_uppercase();
    // Normalise: pgp may format with spaces; canonicalise by
    // stripping non-hex characters.
    let got_canonical: String = got_fpr.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if got_canonical.to_ascii_uppercase() != want_fpr {
        bail!(
            "embedded Alpine release-signing key fingerprint {got_canonical} does not match the \
             pinned fingerprint {want_fpr} — refusing to verify with the wrong key. This means \
             `crates/mvm-build/src/stage0/alpine-ncopa-release-key.asc` and the \
             `ALPINE_RELEASE_KEY_FINGERPRINT` constant have drifted."
        );
    }

    let (sig, _headers) = DetachedSignature::from_armor_single(Cursor::new(sig_armor))
        .context("parsing detached signature .asc")?;

    sig.verify(&key, data)
        .context("Alpine tarball signature failed PGP verification against embedded release key")?;

    Ok(())
}

/// Extract Alpine's tar.gz minirootfs into `dest`, preserving
/// permissions but not ownership (everything ends up owned by
/// the calling host user; libkrun's virtio-fs proxy handles
/// uid mapping at access time).
fn extract_alpine_tarball(tarball: &Path, dest: &Path) -> Result<()> {
    let f =
        std::fs::File::open(tarball).with_context(|| format!("opening {}", tarball.display()))?;
    let gz = GzDecoder::new(f);
    let mut archive = Archive::new(gz);
    archive.set_preserve_permissions(true);
    // Don't preserve ownership — the macOS host doesn't have the
    // numeric uids/gids Alpine's tarball references. Files end up
    // owned by the current user; libkrun + virtiofsd remap inside
    // the guest.
    archive.set_unpack_xattrs(false);
    archive
        .unpack(dest)
        .with_context(|| format!("unpacking tarball into {}", dest.display()))?;
    Ok(())
}

fn write_file_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f =
        std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    set_mode(path, mode)?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {} -> {:o}", path.display(), mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn verify_sha256(path: &Path, expected_hex: &str) -> Result<bool> {
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(path)
        .with_context(|| format!("opening {} for sha256 check", path.display()))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let got = hex::encode(hasher.finalize());
    Ok(got.eq_ignore_ascii_case(expected_hex))
}

fn fetch_to(target: &Path, asset: &BootstrapAsset) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("target {} has no parent", target.display()))?;
    let staging = parent.join(format!(
        ".{}.staging.{}",
        asset.cache_filename,
        std::process::id()
    ));

    eprintln!("[mvm] downloading {} -> {}", asset.url, target.display());
    let resp = reqwest::blocking::get(asset.url)
        .with_context(|| format!("GET {}", asset.url))?
        .error_for_status()
        .with_context(|| format!("GET {} returned non-success status", asset.url))?;
    let bytes = resp
        .bytes()
        .with_context(|| format!("reading body from {}", asset.url))?;

    let got_hex = hex::encode(Sha256::digest(&bytes));
    if !got_hex.eq_ignore_ascii_case(asset.sha256_hex) {
        bail!(
            "sha256 mismatch fetching {asset_url}: expected {want}, got {got}. \
             Either the upstream byte stream drifted or the pinned hash needs an update.",
            asset_url = asset.url,
            want = asset.sha256_hex,
            got = got_hex,
        );
    }

    {
        let mut out = std::fs::File::create(&staging)
            .with_context(|| format!("creating staging file {}", staging.display()))?;
        out.write_all(&bytes)
            .with_context(|| format!("writing {}", staging.display()))?;
    }
    set_mode(&staging, asset.mode)?;
    std::fs::rename(&staging, target).with_context(|| {
        format!(
            "atomic-rename {} -> {}",
            staging.display(),
            target.display()
        )
    })?;
    Ok(())
}

/// Fetch a detached `.asc` signature. Same staging-dir + atomic
/// rename pattern as [`fetch_to`]; no SHA-256 check because the
/// signature derives its trust from the embedded PGP key, not from
/// a pinned hash.
fn fetch_signature(target: &Path, url: &str) -> Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("target {} has no parent", target.display()))?;
    let name = target
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("target {} has no file name", target.display()))?;
    let staging = parent.join(format!(
        ".{}.staging.{}",
        name.to_string_lossy(),
        std::process::id()
    ));

    eprintln!("[mvm] downloading {url} -> {}", target.display());
    let resp = reqwest::blocking::get(url)
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url} returned non-success status"))?;
    let bytes = resp
        .bytes()
        .with_context(|| format!("reading body from {url}"))?;

    {
        let mut out = std::fs::File::create(&staging)
            .with_context(|| format!("creating staging file {}", staging.display()))?;
        out.write_all(&bytes)
            .with_context(|| format!("writing {}", staging.display()))?;
    }
    set_mode(&staging, 0o644)?;
    std::fs::rename(&staging, target).with_context(|| {
        format!(
            "atomic-rename {} -> {}",
            staging.display(),
            target.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_script_is_embedded_and_nonempty() {
        assert!(!INIT_SCRIPT.is_empty());
        assert!(
            INIT_SCRIPT.contains("#!/bin/sh"),
            "init script has a shebang"
        );
        assert!(
            INIT_SCRIPT.contains("ip link set eth0 up"),
            "init script brings eth0 up explicitly (the udhcpc-ENETDOWN bug fix)"
        );
        assert!(
            INIT_SCRIPT.contains("apk"),
            "init script invokes apk (Alpine package manager)"
        );
    }

    // ---------------- VendorBlobReport (Plan 93 Phase 3) ----------------

    #[test]
    fn vendor_blob_pgp_and_outcome_wire_strings() {
        assert_eq!(VendorBlobPgp::Verified.as_str(), "verified");
        assert_eq!(VendorBlobPgp::None.as_str(), "none");
        assert_eq!(VendorBlobPgp::Failed.as_str(), "failed");
        assert_eq!(VendorBlobOutcome::Fetched.as_str(), "fetched");
        assert_eq!(
            VendorBlobOutcome::CacheRevalidated.as_str(),
            "cache_revalidated"
        );
    }

    #[test]
    fn vendor_blob_report_for_signed_asset_records_verified_pgp() {
        // Every shipped bootstrap asset carries a signature, so a
        // report built from one must record `pgp=verified`.
        let asset = ASSETS_AARCH64[0];
        let report = VendorBlobReport::for_asset(asset, 1024, VendorBlobOutcome::Fetched);
        assert_eq!(report.pgp, VendorBlobPgp::Verified);
        assert_eq!(report.url, asset.url);
        assert_eq!(report.sha256_hex, asset.sha256_hex);
        assert_eq!(report.bytes, 1024);
        assert_eq!(report.outcome, VendorBlobOutcome::Fetched);
    }

    #[test]
    fn vendor_blob_audit_detail_shape_is_space_separated_kv() {
        let report = VendorBlobReport {
            url: "https://example.test/alpine.tar.gz",
            sha256_hex: "abc123",
            pgp: VendorBlobPgp::Verified,
            bytes: 4096,
            outcome: VendorBlobOutcome::CacheRevalidated,
        };
        assert_eq!(
            report.audit_detail(),
            "url=https://example.test/alpine.tar.gz sha256=abc123 \
             pgp=verified bytes=4096 outcome=cache_revalidated"
        );
    }

    /// Regression for the 2026-05-21 `mvmctl dev up` failure where
    /// `nix build` exited 1 and the init's error handler then
    /// printed `/init: line 156: can't create /dev/null: nonexistent
    /// directory` — masking the real nix-build error because the
    /// `tail … 2>/dev/null` redirect tried to open a missing
    /// `/dev/null` in libkrun's set_root container mode.
    ///
    /// Two invariants this PR establishes:
    ///   1. The script `mknod`s `/dev/null` early so subsequent
    ///      `2>/dev/null` redirects in any other tool still work.
    ///   2. The script's own error handlers never use `2>/dev/null`
    ///      themselves — even if (1) fails for some other reason,
    ///      the nix-build error reaches the console.
    #[test]
    fn init_script_protects_against_missing_dev_null() {
        assert!(
            INIT_SCRIPT.contains("mknod /dev/null c 1 3"),
            "init script must mknod /dev/null with major=1 minor=3 to \
             survive libkrun set_root quirks where /dev/null is absent"
        );
        assert!(
            INIT_SCRIPT.contains("[ -c /dev/null ]"),
            "init script must gate the mknod on `[ -c /dev/null ]` so \
             a well-populated /dev doesn't trip the mknod"
        );
        // Comments (lines starting with `#` after optional leading
        // whitespace) reference the bad pattern by name to explain
        // why it's avoided. The test only cares about live code.
        for (i, line) in INIT_SCRIPT.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            assert!(
                !line.contains("2>/dev/null"),
                "init script line {} uses `2>/dev/null` in live code:\n\
                 \n  {}\n\n\
                 That's the pattern that masked the real nix-build \
                 failure when /dev/null was missing in libkrun \
                 set_root mode — replace with an `[ -r FILE ]` guard.",
                i + 1,
                line
            );
        }
    }

    /// Catch a regression in the boot-time /dev probe — if it
    /// disappears, the next debugging session loses its primary
    /// diagnostic for /dev/null absence.
    #[test]
    fn init_script_logs_dev_probe_at_boot() {
        assert!(
            INIT_SCRIPT.contains("/dev probe:"),
            "init script must log a /dev probe so we can see whether \
             /dev/null was already there or had to be mknod'd"
        );
    }

    /// Regression for the 2026-05-25 `mvmctl dev up` failure where
    /// the Stage 0 nix build OOM-killed the slim Linux kernel
    /// compile at `HOSTCC scripts/basic/fixdep`. With Alpine nix's
    /// default `max-jobs = auto`, four heavy derivations
    /// (mvm-host-vm-init, mvm-egress-proxy, mvm-guest-agent, linux)
    /// ran concurrently and the combined build working set exceeded
    /// the guest RAM envelope. Serializing derivations with
    /// `--max-jobs 1` keeps peak memory under the per-derivation
    /// ~5-6 GiB observation recorded in `libkrun_builder.rs`. (The
    /// store moved off the in-RAM tmpfs onto a virtio-blk ext4 disk in
    /// the persistent-store cutover, but the compiles still need the
    /// headroom, so the cap stays.)
    #[test]
    fn init_script_caps_nix_derivation_parallelism() {
        assert!(
            INIT_SCRIPT.contains("--max-jobs 1"),
            "init script must serialize Stage 0 nix derivations \
             (`--max-jobs 1`) so parallel kernel + Rust build working \
             sets don't blow the guest RAM envelope"
        );
    }

    /// The persistent-store cutover (replacing the in-RAM tmpfs `/nix`
    /// with a host-backed ext4 virtio-blk image) so a `dev up`
    /// rebuild reuses the slim kernel + Rust toolchain closure instead
    /// of recompiling it every time. Pins the load-bearing shape of the
    /// init script's new `/nix` provisioning.
    #[test]
    fn init_script_mounts_persistent_ext4_nix_store() {
        // The throwaway tmpfs `/nix` is gone. (Other tmpfs mounts —
        // /tmp, /run — remain, so assert specifically on `/nix`.)
        assert!(
            !INIT_SCRIPT.contains("tmpfs /nix"),
            "init script must no longer mount a tmpfs over /nix"
        );
        // e2fsprogs gives mkfs.ext4, installed before /nix is mounted.
        assert!(
            INIT_SCRIPT.contains("add e2fsprogs"),
            "init script must apk-add e2fsprogs for first-boot mkfs.ext4"
        );
        // Format-vs-mount is decided by PROBING for an ext4 superblock
        // with e2fsck (in the e2fsprogs CORE package — dumpe2fs is not),
        // never by try-mount-then-reformat. A geometry-EINVAL on a disk
        // that already holds a store must not be read as "blank" and
        // wipe the warm cache (that was the store-losing bug). Pin the
        // probe so a refactor can't reintroduce blind reformatting.
        assert!(
            INIT_SCRIPT.contains("e2fsck -fy \"$NIX_DEV\""),
            "init script must probe for an existing ext4 store with e2fsck before formatting"
        );
        assert!(
            INIT_SCRIPT.contains("PROBE_RC") && INIT_SCRIPT.contains("-ge 8"),
            "init script must format only when the probe finds no superblock (e2fsck rc >= 8)"
        );
        // First boot formats the sparse disk with an explicit 4K block
        // count SIZED UNDER the device: libkrunfw's Stage 0 kernel
        // over-reports the virtio-blk size, so a fs sized to the kernel
        // view reads back too large next boot and `mount` EINVALs. The
        // margin (`- 2048`) keeps the fs strictly inside the real device.
        assert!(
            INIT_SCRIPT.contains("mkfs.ext4 -F -q -b 4096"),
            "init script must format the store disk with an explicit 4K block count"
        );
        assert!(
            INIT_SCRIPT.contains("SECTORS / 8 - 2048"),
            "init script must size the fs under the kernel-reported device (over-report margin)"
        );
        assert!(
            INIT_SCRIPT.contains("/sys/class/block/"),
            "init script must read the device size from /sys/class/block"
        );
        // Mount the detected device at /nix as ext4 (case-sensitive,
        // the property the tmpfs originally provided).
        assert!(
            INIT_SCRIPT.contains("mount -t ext4 \"$NIX_DEV\" /nix"),
            "init script must mount the persistent ext4 store at /nix"
        );
    }

    #[test]
    fn cache_dir_is_under_home() {
        let path = stage0_cache_dir();
        let s = path.to_string_lossy();
        assert!(s.contains(".cache/mvm/stage0"), "got {s}");
    }

    #[test]
    fn verify_sha256_matches_real_content() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("data");
        std::fs::write(&path, b"hello").unwrap();
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(&path, expected).unwrap());
        let wrong = "0".repeat(64);
        assert!(!verify_sha256(&path, &wrong).unwrap());
    }

    #[test]
    fn alpine_assets_table_covers_both_supported_arches() {
        assert_eq!(ASSETS_AARCH64.len(), 1);
        assert_eq!(ASSETS_X86_64.len(), 1);
        assert!(ASSETS_AARCH64[0].url.contains("aarch64"));
        assert!(ASSETS_X86_64[0].url.contains("x86_64"));
        assert!(ASSETS_AARCH64[0].url.starts_with("https://"));
        assert!(ASSETS_X86_64[0].url.starts_with("https://"));
        // Every asset has a PGP signature URL.
        assert!(ASSETS_AARCH64[0].signature_url.is_some());
        assert!(ASSETS_X86_64[0].signature_url.is_some());
    }

    #[test]
    fn alpine_version_and_branch_match() {
        // ALPINE_VERSION (e.g. "3.22.4") must share the major.minor
        // with ALPINE_BRANCH (e.g. "v3.22"). The URL in each asset
        // embeds the branch directory; init.sh writes the branch to
        // /etc/apk/repositories. Drift between them is a footgun.
        let trimmed_branch = ALPINE_BRANCH.trim_start_matches('v');
        assert!(
            ALPINE_VERSION.starts_with(&format!("{trimmed_branch}.")),
            "ALPINE_VERSION {ALPINE_VERSION} does not match ALPINE_BRANCH {ALPINE_BRANCH}"
        );
        for asset in [&ALPINE_MINIROOTFS_AARCH64, &ALPINE_MINIROOTFS_X86_64] {
            assert!(
                asset.url.contains(&format!("/{ALPINE_BRANCH}/")),
                "asset URL {} does not embed ALPINE_BRANCH {ALPINE_BRANCH}",
                asset.url
            );
            assert!(
                asset.url.contains(ALPINE_VERSION),
                "asset URL {} does not embed ALPINE_VERSION {ALPINE_VERSION}",
                asset.url
            );
            let sig_url = asset.signature_url.expect("sig url present");
            assert!(
                sig_url.ends_with(".asc"),
                "signature URL {sig_url} should end with .asc"
            );
            assert!(
                sig_url.starts_with(asset.url),
                "signature URL {sig_url} should sit next to data URL {}",
                asset.url
            );
        }
    }

    #[test]
    fn alpine_assets_sha256_pins_are_well_formed() {
        for asset in [&ALPINE_MINIROOTFS_AARCH64, &ALPINE_MINIROOTFS_X86_64] {
            assert_eq!(
                asset.sha256_hex.len(),
                64,
                "{} sha256 is not 64 chars",
                asset.cache_filename
            );
            assert!(
                asset.sha256_hex.chars().all(|c| c.is_ascii_hexdigit()),
                "{} sha256 contains non-hex chars",
                asset.cache_filename
            );
        }
    }

    #[test]
    fn host_arch_dispatch_picks_one_asset() {
        // The cfg-selected asset must match exactly one of the
        // per-arch tables. We can't assert which one (depends on
        // the test runner's arch) but we can assert it's not None.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            let picked = alpine_minirootfs_for_host_arch().expect("supported host arch");
            assert!(!picked.url.is_empty());
            assert_eq!(picked.sha256_hex.len(), 64);
        }
    }

    /// Embedded Alpine release-signing key is a non-empty armored
    /// PGP public key, and its primary fingerprint matches
    /// [`ALPINE_RELEASE_KEY_FINGERPRINT`].
    #[test]
    fn embedded_alpine_key_parses_and_matches_pinned_fingerprint() {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::types::KeyDetails;
        assert!(!ALPINE_RELEASE_KEY_ASC.is_empty());
        let armor_head = std::str::from_utf8(&ALPINE_RELEASE_KEY_ASC[..40]).unwrap();
        assert!(
            armor_head.contains("PGP PUBLIC KEY"),
            "embedded key looks like armored PGP: {armor_head}"
        );
        let (key, _) =
            SignedPublicKey::from_armor_single(std::io::Cursor::new(ALPINE_RELEASE_KEY_ASC))
                .expect("parse Alpine release key");
        let canonical: String = format!("{:X}", key.fingerprint())
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        assert_eq!(
            canonical.to_ascii_uppercase(),
            ALPINE_RELEASE_KEY_FINGERPRINT.to_ascii_uppercase(),
            "embedded key fingerprint matches pin"
        );
    }

    /// A garbage byte string passed to the PGP verifier is
    /// rejected with a clear error.
    #[test]
    fn verify_alpine_pgp_signature_rejects_garbage() {
        let err = verify_alpine_pgp_signature(b"data", b"not a real signature")
            .expect_err("garbage signature must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("detached signature") || msg.contains("Alpine") || msg.contains(".asc"),
            "error mentions signature parsing: {msg}"
        );
    }

    /// Materializing without first calling `prepare_assets` (Alpine
    /// tarball missing from cache) is rejected with a clear error.
    #[test]
    fn materialize_root_dir_rejects_missing_tarball() {
        let dir = TempDir::new().unwrap();
        // Empty cache dir (no tarball staged).
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let root = dir.path().join("stage0-root");

        let err = materialize_root_dir_in(&cache, &root).expect_err("missing asset should fail");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("Stage 0 asset missing") || msg.contains("alpine-minirootfs"),
            "error names the missing asset: {msg}"
        );
    }

    /// A tampered cached tarball (bytes don't match the pinned
    /// sha256) is rejected before extraction.
    #[test]
    fn materialize_root_dir_rejects_tampered_tarball() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        // Write garbage under both expected filenames — sha256
        // will not match the pinned hex for either arch.
        std::fs::write(
            cache.join("alpine-minirootfs-aarch64.tar.gz"),
            b"not actually an alpine tarball",
        )
        .unwrap();
        std::fs::write(
            cache.join("alpine-minirootfs-x86_64.tar.gz"),
            b"not actually an alpine tarball",
        )
        .unwrap();

        let root = dir.path().join("stage0-root");
        let err = materialize_root_dir_in(&cache, &root).expect_err("tampered tarball should fail");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("sha256 mismatch") || msg.contains("tampered"),
            "error names the tampering: {msg}"
        );
    }
}
