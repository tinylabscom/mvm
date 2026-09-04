//! Stage 0 bootstrap — materializes a host directory tree from the
//! **official Nix release tarball** (a self-contained `/nix/store` with
//! `nix` + `bash` + `curl` + `xz` + `nss-cacert`), layered with the
//! embedded `stage0-init` PID-1 binary. The builder materializes that seed as
//! an ext4 root, boots libkrunfw's bundled kernel explicitly, and runs `/init`.
//! `stage0-init` then runs `nix build` against the in-repo
//! `nix/images/builder-vm` flake, emitting kernel + rootfs.ext4 on the
//! raw output transport disk.
//!
//! **One userland — busybox, everywhere.** The seed carries nix + a static
//! busybox (its closure's shell) + CA certs; there is no Alpine, no `apk`,
//! no external dependency. This replaced the former Alpine minirootfs seed,
//! which existed only to `apk add nix` and pulled the heavy `pgp` crate for
//! its release-key verification.
//!
//! [`materialize_root_dir`] re-verifies the cached tarball (SHA-256) before
//! use. The extracted root is cached under `<dest>` with a marker bound to the
//! tarball hash and embedded `stage0-init` hash, so the common path avoids
//! re-decompressing the full seed tarball.
//!
//! # Trust model
//!
//! The Nix tarball is **hash-pinned in source** ([`NIX_SEED_AARCH64`] /
//! [`NIX_SEED_X86_64`]) — the SHA-256 is the binding integrity check
//! (fail-closed at fetch and at extract). This is the same pin model the
//! Alpine tarball used; the PGP layer is gone because the hash pin already
//! guarantees byte-exact content for the pinned version, and the seed is
//! itself an upstream-published artifact like Alpine's was. See the
//! bootstrap-trust-model ADR.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// Scratch payload baked into the tightly packed Stage 0 ext4 root and removed
/// by PID 1 before it creates the small amount of mutable bootstrap state.
pub const ROOT_RUNTIME_RESERVE_PATH: &str = "/.mvm-stage0-root-reserve";
pub const ROOT_RUNTIME_RESERVE_BYTES: usize = 8 << 20;

const ROOT_MARKER_FILE: &str = ".mvm-stage0-root";
const ROOT_MARKER_SCHEMA_VERSION: u32 = 1;

/// Copy a non-empty artifact through an explicit userspace buffer.
///
/// Stage 0 copies from its ext4-backed Nix store to the output staging tree.
/// Bootstrap artifacts use ordinary reads and writes and reject an empty
/// source before it can be reported as successfully emitted.
pub fn copy_nonempty_file(src: &Path, dst: &Path) -> Result<u64> {
    let mut input = std::io::BufReader::new(
        std::fs::File::open(src).with_context(|| format!("open {} for copy", src.display()))?,
    );
    let mut output = std::io::BufWriter::new(
        std::fs::File::create(dst).with_context(|| format!("create {} for copy", dst.display()))?,
    );
    let mut buffer = [0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let read = input
            .read(&mut buffer)
            .with_context(|| format!("read {}", src.display()))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .with_context(|| format!("write {}", dst.display()))?;
        copied = copied.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    output
        .flush()
        .with_context(|| format!("flush {}", dst.display()))?;
    if copied == 0 {
        let _ = std::fs::remove_file(dst);
        bail!(
            "copy {} -> {} produced an empty artifact",
            src.display(),
            dst.display()
        );
    }
    Ok(copied)
}

/// One downloadable bootstrap asset, pinned by upstream URL + SHA-256.
/// The cache key is [`Self::cache_filename`].
#[derive(Debug, Clone, Copy)]
pub struct BootstrapAsset {
    /// Where the file lands inside [`stage0_cache_dir`].
    pub cache_filename: &'static str,
    /// Upstream URL. Pinned to a specific version; never moves.
    pub url: &'static str,
    /// SHA-256 of the byte stream at [`Self::url`]. Hex (64 chars). This is
    /// the binding integrity check (fail-closed at fetch + at extract).
    pub sha256_hex: &'static str,
    /// File mode the asset gets on disk (and inside the root dir).
    pub mode: u32,
}

// ============================================================================
// nix-tarball seed (the busybox/static-Nix replacement for the Alpine
// minirootfs seed). The official Nix release tarball is a self-contained
// `/nix/store` (nix + bash + curl + xz + nss-cacert) — no apk, no Alpine, no
// external busybox, **no PGP** (SHA-256 pin only; the hash is the binding
// integrity check, same as the Alpine tarball's).
// ============================================================================

/// Nix release we seed from. Bump in lockstep with the SHA-256 pins below.
///
/// 2.31.1 was the outlier that computed a divergent flake-input narHash vs the
/// committed flake.locks, breaking every fresh builder-VM build since the
/// nix-seed Stage 0 cutover. 2.34.7 computes the lock-matching narHash (verified
/// against the same nixpkgs rev the locks pin).
pub const NIX_SEED_VERSION: &str = "2.34.7";

/// Official Nix release tarball for aarch64-linux guests (~23 MiB). When
/// extracted, its `store/` IS a populated `/nix/store` carrying the `nix`
/// binary + its runtime closure. `signature_url: None` — SHA-256 only.
pub const NIX_SEED_AARCH64: BootstrapAsset = BootstrapAsset {
    cache_filename: "nix-seed-aarch64.tar.xz",
    url: "https://releases.nixos.org/nix/nix-2.34.7/nix-2.34.7-aarch64-linux.tar.xz",
    sha256_hex: "f1cee64ae7a02330c6421924c28f597c41813f2214ff108622087d8056378b08",
    mode: 0o644,
};

/// Official Nix release tarball for x86_64-linux guests (Linux KVM path).
pub const NIX_SEED_X86_64: BootstrapAsset = BootstrapAsset {
    cache_filename: "nix-seed-x86_64.tar.xz",
    url: "https://releases.nixos.org/nix/nix-2.34.7/nix-2.34.7-x86_64-linux.tar.xz",
    sha256_hex: "eafe5042404e818505e28c5ca3d0885f3ec45c31f955489a25bb38258f87560e",
    mode: 0o644,
};

/// The Stage 0 asset table for the host's target arch (one nix-seed
/// asset, fed to [`prepare_assets`]). Empty on unsupported arches.
pub fn assets_for_host_arch() -> &'static [&'static BootstrapAsset] {
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
pub fn asset_for_host_arch() -> Option<&'static BootstrapAsset> {
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

/// `<mvm_home>/cache/stage0/`. Materialized by [`prepare_assets`].
pub fn stage0_cache_dir() -> PathBuf {
    // Honors MVM_HOME so parallel sessions isolate their Stage 0 assets.
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join("stage0")
}

/// Ensure every entry in `assets` is present in the cache dir
/// with the matching SHA-256.
/// Missing assets are fetched via `mvm_http::blocking::get`;
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
/// was freshly fetched or revalidated from cache and its verified
/// SHA-256. The host caller turns each into a
/// `LocalAuditKind::VendorBlobFetched` audit entry so every
/// supply-chain trust decision is auditable. `mvm-build`
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

        if target.is_file() && verify_sha256(&target, asset.sha256_hex)? {
            reports.push(VendorBlobReport::for_asset(
                asset,
                blob_size(&target),
                VendorBlobOutcome::CacheRevalidated,
            ));
            continue;
        }

        fetch_to(&target, asset).with_context(|| format!("fetching {}", asset.url))?;
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
/// `LocalAuditKind::VendorBlobFetched` audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorBlobReport {
    pub url: &'static str,
    pub sha256_hex: &'static str,
    pub bytes: u64,
    pub outcome: VendorBlobOutcome,
}

impl VendorBlobReport {
    fn for_asset(asset: &BootstrapAsset, bytes: u64, outcome: VendorBlobOutcome) -> Self {
        Self {
            url: asset.url,
            sha256_hex: asset.sha256_hex,
            bytes,
            outcome,
        }
    }

    /// The `detail` string for the blob's `VendorBlobFetched` audit
    /// entry: space-separated `key=value` pairs, matching the Stage 0
    /// sibling kinds. Pure — unit-tested without any network fetch.
    ///
    /// The seed is SHA-256-pinned only — the hash is the binding
    /// integrity check (no detached signature, no PGP layer; see the
    /// bootstrap-trust-model ADR), so the detail carries no `pgp=` field.
    pub fn audit_detail(&self) -> String {
        format!(
            "url={} sha256={} bytes={} outcome={}",
            self.url,
            self.sha256_hex,
            self.bytes,
            self.outcome.as_str()
        )
    }
}

/// Materialize a Stage 0 guest root from the **nix tarball seed**. Lays
/// down the official Nix release tarball's `/nix/store` + the
/// embedded `stage0-init` binary as `/init` — no Alpine, no apk, no shell
/// `init.sh`. The builder turns `dest` into an ext4 root and boots it with
/// `init=/init`. `stage0_init` is the
/// extracted host-vm binary's bytes (the caller pulls it from
/// `mvm_cli::host_binaries`); `mvm-build` can't reach the embed table
/// itself (mvm-cli depends on mvm-build, not the reverse).
pub fn materialize_root_dir(dest: &Path, stage0_init: &[u8]) -> Result<()> {
    materialize_root_dir_in(&stage0_cache_dir(), dest, stage0_init)
}

/// Like [`materialize_root_dir`] but reads the cached tarball from
/// `cache_dir` (tests don't have to mutate `HOME`).
pub fn materialize_root_dir_in(cache_dir: &Path, dest: &Path, stage0_init: &[u8]) -> Result<()> {
    let asset = asset_for_host_arch().ok_or_else(|| {
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

    let expected_marker = root_marker_content(asset, stage0_init);
    if stage0_root_matches(dest, &expected_marker, stage0_init)? {
        return Ok(());
    }

    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .with_context(|| format!("clearing stale Stage 0 root dir {}", dest.display()))?;
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
    write_root_marker(dest, &expected_marker)?;

    Ok(())
}

fn stage0_root_matches(dest: &Path, expected_marker: &str, stage0_init: &[u8]) -> Result<bool> {
    if !dest.is_dir() {
        return Ok(false);
    }
    let marker_path = dest.join(ROOT_MARKER_FILE);
    let Ok(marker) = std::fs::read_to_string(&marker_path) else {
        return Ok(false);
    };
    if marker != expected_marker {
        return Ok(false);
    }
    if !dest.join("nix/store").is_dir() {
        return Ok(false);
    }
    for stub in ["work", "out", "mvm-bins"] {
        if !dest.join(stub).is_dir() {
            return Ok(false);
        }
    }
    let init_path = dest.join("init");
    let init = match std::fs::read(&init_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", init_path.display()));
        }
    };
    Ok(init_hash_hex(&init) == init_hash_hex(stage0_init))
}

fn root_marker_content(asset: &BootstrapAsset, stage0_init: &[u8]) -> String {
    format!(
        "schema_version={ROOT_MARKER_SCHEMA_VERSION}\n\
         nix_seed_cache_filename={}\n\
         nix_seed_sha256={}\n\
         stage0_init_sha256={}\n",
        asset.cache_filename,
        asset.sha256_hex,
        init_hash_hex(stage0_init)
    )
}

fn write_root_marker(dest: &Path, marker: &str) -> Result<()> {
    let path = dest.join(ROOT_MARKER_FILE);
    let staging = dest.join(format!(".{ROOT_MARKER_FILE}.{}.tmp", std::process::id()));
    std::fs::write(&staging, marker).with_context(|| format!("writing {}", staging.display()))?;
    set_mode(&staging, 0o644)?;
    std::fs::rename(&staging, &path)
        .with_context(|| format!("atomic-rename {} -> {}", staging.display(), path.display()))?;
    Ok(())
}

fn init_hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Extract the official Nix release tarball into `nix_dir` (= `<root>/nix`),
/// stripping the leading `nix-<ver>-<arch>-linux/` component so `store/`
/// lands at `<nix_dir>/store/`. The install scripts come along harmlessly;
/// the guest never runs them.
///
/// In-process: `lzma-rs` decodes the `.xz` stream (pure Rust — no host `tar`,
/// no liblzma C dep) and the `tar` crate unpacks it. We unpack the whole
/// archive (preserving the nix store's symlinks/modes via the crate's own
/// path-safety checks) then [`lift_single_top_level`] hoists the one
/// `nix-<ver>-<arch>-linux/` wrapper dir's children up one level — the
/// equivalent of `tar --strip-components=1`, but without re-implementing
/// per-entry symlink/hardlink rewriting.
fn extract_nix_store_tarball(tarball: &Path, nix_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(nix_dir).with_context(|| format!("creating {}", nix_dir.display()))?;

    match extract_nix_store_tarball_with_native_tar(tarball, nix_dir) {
        Ok(()) => return Ok(()),
        Err(native_err) => {
            if !dir_is_empty(nix_dir)? {
                std::fs::remove_dir_all(nix_dir)
                    .with_context(|| format!("clearing partial extract {}", nix_dir.display()))?;
                std::fs::create_dir_all(nix_dir)
                    .with_context(|| format!("recreating {}", nix_dir.display()))?;
            }
            tracing::debug!(
                error = %native_err,
                tarball = %tarball.display(),
                "native tar Stage 0 extraction failed; falling back to pure Rust extractor"
            );
        }
    }

    extract_nix_store_tarball_pure_rust(tarball, nix_dir)
}

fn extract_nix_store_tarball_with_native_tar(tarball: &Path, nix_dir: &Path) -> Result<()> {
    let output = Command::new("tar")
        .arg("-xJf")
        .arg(tarball)
        .arg("-C")
        .arg(nix_dir)
        .arg("--strip-components")
        .arg("1")
        .output()
        .with_context(|| "spawning tar for Stage 0 nix seed extraction")?;
    if !output.status.success() {
        bail!(
            "tar -xJf {} exited {}: {}",
            tarball.display(),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn extract_nix_store_tarball_pure_rust(tarball: &Path, nix_dir: &Path) -> Result<()> {
    let f =
        std::fs::File::open(tarball).with_context(|| format!("opening {}", tarball.display()))?;
    let mut tar_bytes = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::BufReader::new(f), &mut tar_bytes)
        .map_err(|e| anyhow::anyhow!("xz-decompressing {}: {e}", tarball.display()))?;

    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    archive.set_preserve_permissions(true);
    // The macOS host doesn't carry the numeric uids/gids the tarball
    // references; files land owned by the current user before ext4
    // materialization. xattrs aren't needed for the store.
    archive.set_unpack_xattrs(false);
    archive
        .unpack(nix_dir)
        .with_context(|| format!("unpacking nix seed into {}", nix_dir.display()))?;

    lift_single_top_level(nix_dir).with_context(|| {
        format!(
            "stripping the nix-seed wrapper dir under {}",
            nix_dir.display()
        )
    })
}

fn dir_is_empty(dir: &Path) -> Result<bool> {
    let mut entries =
        std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    Ok(entries.next().is_none())
}

/// Hoist the children of the single top-level directory in `dir` up into
/// `dir`, then remove the now-empty wrapper. Equivalent to
/// `tar --strip-components=1` for an archive that wraps everything in one
/// top-level component (the Nix tarball's `nix-<ver>-<arch>-linux/`).
/// Fails closed if `dir` doesn't contain exactly one directory entry.
fn lift_single_top_level(dir: &Path) -> Result<()> {
    let mut top_levels: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    if top_levels.len() != 1 {
        bail!(
            "expected one top-level dir in the nix seed, found {} under {}",
            top_levels.len(),
            dir.display()
        );
    }
    let wrapper = top_levels.pop().unwrap();
    if !wrapper.is_dir() {
        bail!(
            "nix seed top-level entry {} is not a directory",
            wrapper.display()
        );
    }
    // Same-filesystem renames — cheap even for the full store closure.
    for child in
        std::fs::read_dir(&wrapper).with_context(|| format!("reading {}", wrapper.display()))?
    {
        let child = child?.path();
        let name = child
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("child {} has no file name", child.display()))?;
        std::fs::rename(&child, dir.join(name))
            .with_context(|| format!("moving {} up into {}", child.display(), dir.display()))?;
    }
    std::fs::remove_dir(&wrapper).with_context(|| format!("rmdir {}", wrapper.display()))?;
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
    let resp = mvm_http::blocking::get(asset.url)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn buffered_artifact_copy_follows_symlinks_and_rejects_empty_sources() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("config.real");
        let link = temp.path().join("config");
        let copied = temp.path().join("copied.config");
        std::fs::write(&source, b"CONFIG_BLK_DEV_DM=y\nCONFIG_DM_VERITY=y\n").unwrap();
        symlink(&source, &link).unwrap();

        assert_eq!(
            copy_nonempty_file(&link, &copied).unwrap(),
            std::fs::metadata(&source).unwrap().len()
        );
        assert_eq!(
            std::fs::read(&copied).unwrap(),
            std::fs::read(&source).unwrap()
        );

        let empty = temp.path().join("empty");
        let empty_copy = temp.path().join("empty-copy");
        std::fs::write(&empty, b"").unwrap();
        let error = copy_nonempty_file(&empty, &empty_copy).unwrap_err();
        assert!(error.to_string().contains("empty artifact"));
        assert!(!empty_copy.exists());
    }

    // ---------------- VendorBlobReport ----------------

    #[test]
    fn vendor_blob_outcome_wire_strings() {
        assert_eq!(VendorBlobOutcome::Fetched.as_str(), "fetched");
        assert_eq!(
            VendorBlobOutcome::CacheRevalidated.as_str(),
            "cache_revalidated"
        );
    }

    #[test]
    fn vendor_blob_report_for_asset_carries_url_and_hash() {
        let asset = &NIX_SEED_AARCH64;
        let report = VendorBlobReport::for_asset(asset, 1024, VendorBlobOutcome::Fetched);
        assert_eq!(report.url, asset.url);
        assert_eq!(report.sha256_hex, asset.sha256_hex);
        assert_eq!(report.bytes, 1024);
        assert_eq!(report.outcome, VendorBlobOutcome::Fetched);
    }

    #[test]
    fn vendor_blob_audit_detail_shape_is_space_separated_kv() {
        // SHA-256 pin only — no `pgp=` field (the hash is the binding
        // integrity check; see the bootstrap-trust-model ADR).
        let report = VendorBlobReport {
            url: "https://example.test/nix-seed.tar.xz",
            sha256_hex: "abc123",
            bytes: 4096,
            outcome: VendorBlobOutcome::CacheRevalidated,
        };
        assert_eq!(
            report.audit_detail(),
            "url=https://example.test/nix-seed.tar.xz sha256=abc123 \
             bytes=4096 outcome=cache_revalidated"
        );
    }

    #[test]
    fn cache_dir_is_under_home() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = TempDir::new().unwrap();
        env.set("MVM_HOME", tmp.path());
        let path = stage0_cache_dir();
        let s = path.to_string_lossy();
        assert!(s.ends_with("/cache/stage0"), "got {s}");
        assert!(path.starts_with(tmp.path()), "got {s}");
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

    /// In-process xz decode + `--strip-components=1` lift: build a `.tar.xz`
    /// that wraps everything in one `nix-<ver>-<arch>-linux/` dir (the shape
    /// of the official Nix release tarball), extract it, and assert the
    /// wrapper is stripped so `store/` lands at `<nix_dir>/store/`.
    #[test]
    fn extract_nix_store_tarball_decodes_xz_and_strips_wrapper() {
        let dir = TempDir::new().unwrap();

        // Build the inner tar: a +x file under store/ and a sibling .reginfo,
        // both under the single `nix-2.31.1-test-linux/` wrapper.
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let foo = b"#!/bin/sh\necho hi\n";
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(foo.len() as u64);
            h.set_mode(0o755);
            builder
                .append_data(
                    &mut h,
                    "nix-2.31.1-test-linux/store/abc-foo/bin/foo",
                    &foo[..],
                )
                .unwrap();
            let reg = b"reginfo";
            let mut h2 = tar::Header::new_gnu();
            h2.set_entry_type(tar::EntryType::Regular);
            h2.set_size(reg.len() as u64);
            h2.set_mode(0o644);
            builder
                .append_data(&mut h2, "nix-2.31.1-test-linux/.reginfo", &reg[..])
                .unwrap();
            builder.finish().unwrap();
        }

        // xz-compress it (round-trip through the same crate stage0 decodes with).
        let mut xz_bytes = Vec::new();
        lzma_rs::xz_compress(&mut std::io::Cursor::new(&tar_bytes), &mut xz_bytes).unwrap();
        let tarball = dir.path().join("seed.tar.xz");
        std::fs::write(&tarball, &xz_bytes).unwrap();

        let nix_dir = dir.path().join("root/nix");
        extract_nix_store_tarball(&tarball, &nix_dir).unwrap();

        let foo_path = nix_dir.join("store/abc-foo/bin/foo");
        assert!(
            foo_path.is_file(),
            "extracted file at {}",
            foo_path.display()
        );
        assert_eq!(std::fs::read(&foo_path).unwrap(), b"#!/bin/sh\necho hi\n");
        assert!(
            nix_dir.join(".reginfo").is_file(),
            "sibling top-level file lifted"
        );
        assert!(
            !nix_dir.join("nix-2.31.1-test-linux").exists(),
            "the nix-<ver>-<arch>-linux wrapper dir was stripped"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&foo_path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o755,
                "executable bit preserved through extract"
            );
        }
    }

    // ---------------- nix-tarball seed asset table ----------------

    #[test]
    fn nix_seed_table_covers_both_supported_arches() {
        assert!(NIX_SEED_AARCH64.url.contains("aarch64"));
        assert!(NIX_SEED_X86_64.url.contains("x86_64"));
        assert!(
            NIX_SEED_AARCH64
                .url
                .starts_with("https://releases.nixos.org/")
        );
        assert!(
            NIX_SEED_X86_64
                .url
                .starts_with("https://releases.nixos.org/")
        );
        // The pinned version must appear in both URLs and the cache names.
        for asset in [&NIX_SEED_AARCH64, &NIX_SEED_X86_64] {
            assert!(
                asset.url.contains(NIX_SEED_VERSION),
                "asset URL {} does not embed NIX_SEED_VERSION {NIX_SEED_VERSION}",
                asset.url
            );
            assert!(
                asset.url.ends_with(".tar.xz"),
                "nix seed URL {} should be a .tar.xz",
                asset.url
            );
        }
    }

    #[test]
    fn nix_seed_sha256_pins_are_well_formed() {
        for asset in [&NIX_SEED_AARCH64, &NIX_SEED_X86_64] {
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
        // The cfg-selected asset must match the host's arch. We can't
        // assert which one (depends on the test runner's arch) but on a
        // supported arch it must resolve to exactly one nix-seed asset.
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            let picked = asset_for_host_arch().expect("supported host arch");
            assert!(!picked.url.is_empty());
            assert_eq!(picked.sha256_hex.len(), 64);
            assert_eq!(assets_for_host_arch().len(), 1);
        }
    }

    /// Materializing without first calling `prepare_assets` (the nix-seed
    /// tarball is missing from the cache) is rejected with a clear error.
    #[test]
    fn materialize_root_dir_rejects_missing_tarball() {
        let dir = TempDir::new().unwrap();
        // Empty cache dir (no tarball staged).
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        let root = dir.path().join("stage0-root");

        let err = materialize_root_dir_in(&cache, &root, b"fake-init-elf")
            .expect_err("missing asset should fail");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("nix-seed asset missing") || msg.contains("nix-seed"),
            "error names the missing asset: {msg}"
        );
    }

    /// A tampered cached tarball (bytes don't match the pinned sha256) is
    /// rejected before extraction.
    #[test]
    fn materialize_root_dir_rejects_tampered_tarball() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        // Write garbage under both expected filenames — sha256 will not
        // match the pinned hex for either arch.
        std::fs::write(
            cache.join("nix-seed-aarch64.tar.xz"),
            b"not a real nix seed",
        )
        .unwrap();
        std::fs::write(cache.join("nix-seed-x86_64.tar.xz"), b"not a real nix seed").unwrap();

        let root = dir.path().join("stage0-root");
        let err = materialize_root_dir_in(&cache, &root, b"fake-init-elf")
            .expect_err("tampered tarball should fail");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("sha256 mismatch") || msg.contains("tampered"),
            "error names the tampering: {msg}"
        );
    }

    #[test]
    fn stage0_root_marker_reuses_matching_materialized_root() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("nix/store")).unwrap();
        for stub in ["work", "out", "mvm-bins"] {
            std::fs::create_dir_all(root.join(stub)).unwrap();
        }
        let init = b"stage0-init-v1";
        std::fs::write(root.join("init"), init).unwrap();
        let marker = root_marker_content(&NIX_SEED_X86_64, init);
        write_root_marker(&root, &marker).unwrap();

        assert!(
            stage0_root_matches(&root, &marker, init).unwrap(),
            "matching marker and init hash should reuse root"
        );
    }

    #[test]
    fn stage0_root_marker_rejects_stale_init_hash() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("nix/store")).unwrap();
        for stub in ["work", "out", "mvm-bins"] {
            std::fs::create_dir_all(root.join(stub)).unwrap();
        }
        let old_init = b"stage0-init-v1";
        let new_init = b"stage0-init-v2";
        std::fs::write(root.join("init"), old_init).unwrap();
        let marker = root_marker_content(&NIX_SEED_X86_64, old_init);
        write_root_marker(&root, &marker).unwrap();

        assert!(
            !stage0_root_matches(&root, &marker, new_init).unwrap(),
            "changed embedded stage0-init must invalidate cached root"
        );
    }

    #[test]
    fn stage0_root_marker_rejects_incomplete_root() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("nix/store")).unwrap();
        std::fs::create_dir_all(root.join("work")).unwrap();
        std::fs::create_dir_all(root.join("out")).unwrap();
        let init = b"stage0-init-v1";
        std::fs::write(root.join("init"), init).unwrap();
        let marker = root_marker_content(&NIX_SEED_X86_64, init);
        write_root_marker(&root, &marker).unwrap();

        assert!(
            !stage0_root_matches(&root, &marker, init).unwrap(),
            "missing mvm-bins stub must invalidate cached root"
        );
    }
}
