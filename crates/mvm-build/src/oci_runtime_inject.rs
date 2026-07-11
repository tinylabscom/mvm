//! Inject the mvm guest runtime into an OCI-unpacked rootfs.
//!
//! An arbitrary OCI image (alpine, debian, a language base) ships none
//! of the mvm runtime: no guest agent, no `/init` that brings the agent
//! up, no `/mvm/runtime` overlay mount point. Without those, a microVM
//! booted from the image has no vsock control plane — `run --image`
//! boots a kernel that can't be talked to and times out at
//! `wait_for_agent`.
//!
//! This module is the host-side fix. It runs against the unpacked OCI
//! tree *before* it is sealed into `rootfs.ext4`, baking in:
//!
//! - `/init`, `/usr/local/bin/mvm-guest-agent`,
//!   `/usr/local/bin/mvm-guest-netinit`,
//!   `/usr/local/bin/mvm-guest-netd`, and
//!   `/usr/local/bin/mvm-egress-client` — the cross-compiled guest binaries.
//!   `/init` is a static Rust PID 1, not a shell script, so the source OCI image
//!   does not need `/bin/sh`, busybox, coreutils, or its own init system.
//! - `/usr/lib/mvm/wrappers/oci-entrypoint` plus `/etc/mvm/entrypoint`
//!   when the OCI config declares Entrypoint/Cmd. The wrapper is a static
//!   binary that execs the declared argv directly; it never shells out.
//! - `/mvm/runtime` — the overlay mount point. On Firecracker the host
//!   attaches a verity-sealed overlay here; the injected `/init` prefers
//!   the overlay-resident agent and falls back to the baked one, exactly
//!   like a mkGuest rootfs. When no overlay attaches, the baked binaries are
//!   used.
//! - `/etc/mvm/{name,variant}` — the minimal markers the agent reads.
//!
//! Because the mount point + overlay-preferring `/init` are genuinely
//! present after injection, the rootfs can carry an honest
//! `overlay_aware: true` sidecar ([`crate::builder_vm::GuestSidecar::for_oci_run`])
//! and pass `admit_overlay_aware` without scoping the gate off.
//!
//! Everything here is plain host filesystem I/O against the staging
//! directory — no VM, no nix. The builder-VM materialize step copies the
//! staging tree (now carrying the injected runtime) into the ext4 as-is.

use std::io;
use std::path::{Path, PathBuf};

/// The cross-compiled guest binaries to bake into the rootfs. Produced
/// on the host by [`crate::guest_agent_build`] (source-checkout
/// `cargo-zigbuild`) or unpacked from the published runtime overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvmRuntimeBinaries {
    /// Static OCI PID 1 (`mvm-oci-init`), installed as `/init`.
    pub oci_init: PathBuf,
    /// Static guest agent binary (`mvm-guest-agent`).
    pub agent: PathBuf,
    /// Static guest netinit binary (`mvm-guest-netinit`).
    pub netinit: PathBuf,
    /// Static guest network tunnel daemon (`mvm-guest-netd`).
    pub netd: PathBuf,
    /// Static guest egress shim (`mvm-egress-client`).
    pub egress_client: PathBuf,
    /// Static OCI entrypoint runner (`mvm-oci-entrypoint`).
    pub entrypoint_runner: PathBuf,
    /// Static verity initramfs PID 1 (`mvm-verity-init`). NOT baked into the
    /// rootfs — it goes into the separate `rootfs.initrd` cpio via
    /// [`crate::verity_initrd`]. Carried here so the guest-binary resolver
    /// (cache / source-checkout / embedded) produces it alongside the rootfs
    /// set; `inject_mvm_runtime` deliberately ignores it.
    pub verity_init: PathBuf,
}

/// Shell-free runtime config for an OCI image's declared Entrypoint/Cmd.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OciEntrypointConfig {
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

/// Where the injected guest binaries land inside the rootfs.
const AGENT_DEST: &str = "usr/local/bin/mvm-guest-agent";
const NETINIT_DEST: &str = "usr/local/bin/mvm-guest-netinit";
const NETD_DEST: &str = "usr/local/bin/mvm-guest-netd";
const EGRESS_CLIENT_DEST: &str = "usr/local/bin/mvm-egress-client";
const ENTRYPOINT_RUNNER_DEST: &str = "usr/lib/mvm/wrappers/oci-entrypoint";
const ENTRYPOINT_MARKER_DEST: &str = "etc/mvm/entrypoint";
const OCI_ENTRYPOINT_CONFIG_DEST: &str = "etc/mvm/oci-entrypoint.json";
/// The measured verb-trust policy the guest agent reads at
/// `/etc/mvm/verb-trust.json`. Written only into a sealed rootfs so the
/// require-grant requirement is intrinsic to the dm-verity-hashed data,
/// fail-closed even if the host omits the require-grant cmdline token.
const VERB_TRUST_DEST: &str = "etc/mvm/verb-trust.json";

/// Inject the mvm runtime into the OCI-unpacked `rootfs_dir`.
///
/// Idempotent: re-running overwrites the injected files. Returns the
/// paths created (the `/init` and the runtime binary destinations) so the
/// caller can log/verify them.
pub fn inject_mvm_runtime(
    rootfs_dir: &Path,
    bins: &MvmRuntimeBinaries,
    entrypoint: Option<&OciEntrypointConfig>,
    sealed: bool,
) -> Result<InjectedPaths, io::Error> {
    if !rootfs_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "OCI rootfs staging dir does not exist: {}",
                rootfs_dir.display()
            ),
        ));
    }

    // Mount points must exist on disk before a read-only root boot; PID 1
    // cannot create them once the root is served by a read-only virtiofs device.
    for (rel, mode) in [
        ("proc", 0o755),
        ("sys", 0o755),
        ("dev", 0o755),
        ("dev/pts", 0o755),
        ("dev/shm", 0o1777),
        ("run", 0o755),
        ("tmp", 0o1777),
        ("mvm/runtime", 0o755),
        ("usr/lib/mvm/wrappers", 0o755),
    ] {
        ensure_dir(rootfs_dir, rel, mode)?;
    }
    let runtime_dir = rootfs_dir.join("mvm").join("runtime");

    // Minimal markers the agent reads. `variant=dev` keeps the
    // interactive/console surface enabled (a plain `run --image` is a dev
    // surface); a `--prod` run bakes `variant=prod` so the sealed agent
    // links no console/exec and the runtime gate refuses interactive access.
    let etc_mvm = rootfs_dir.join("etc").join("mvm");
    std::fs::create_dir_all(&etc_mvm)?;
    let variant: &[u8] = if sealed { b"prod\n" } else { b"dev\n" };
    write_file(&etc_mvm.join("variant"), variant, 0o644)?;
    write_file(&etc_mvm.join("name"), b"oci\n", 0o644)?;

    // Bake the require-grant policy into the sealed rootfs so it rides inside
    // the verity-hashed data — the guest ORs it with the cmdline token, so a
    // host that forgets the token still lands fail-closed. Dev stays absent
    // (permissive default).
    if sealed {
        let policy = mvm_core::plan::VerbTrustPolicy {
            version: mvm_core::plan::VERB_TRUST_POLICY_VERSION,
            require_grant: true,
            grant_key_source: mvm_core::plan::GrantKeySource::LaunchProvisioned,
        };
        let policy_json = serde_json::to_vec(&policy).map_err(io::Error::other)?;
        write_file(&rootfs_dir.join(VERB_TRUST_DEST), &policy_json, 0o444)?;
    }

    // Baked guest binaries.
    let bin_dir = rootfs_dir.join("usr").join("local").join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let agent_dest = rootfs_dir.join(AGENT_DEST);
    let netinit_dest = rootfs_dir.join(NETINIT_DEST);
    let netd_dest = rootfs_dir.join(NETD_DEST);
    let egress_client_dest = rootfs_dir.join(EGRESS_CLIENT_DEST);
    copy_exec(&bins.agent, &agent_dest)?;
    copy_exec(&bins.netinit, &netinit_dest)?;
    copy_exec(&bins.netd, &netd_dest)?;
    copy_exec(&bins.egress_client, &egress_client_dest)?;
    let entrypoint_runner_dest = rootfs_dir.join(ENTRYPOINT_RUNNER_DEST);
    copy_file_with_mode(&bins.entrypoint_runner, &entrypoint_runner_dest, 0o555)?;
    if let Some(entrypoint) = entrypoint
        && !entrypoint.argv.is_empty()
    {
        let entrypoint_json = serde_json::to_vec(entrypoint).map_err(io::Error::other)?;
        write_file(
            &rootfs_dir.join(OCI_ENTRYPOINT_CONFIG_DEST),
            &entrypoint_json,
            0o644,
        )?;
        write_file(
            &rootfs_dir.join(ENTRYPOINT_MARKER_DEST),
            b"/usr/lib/mvm/wrappers/oci-entrypoint\n",
            0o644,
        )?;
    }

    // PID 1. This is a static binary, not a shell script, so arbitrary OCI
    // images do not need busybox/coreutils/shell in their rootfs.
    let init_dest = rootfs_dir.join("init");
    copy_exec(&bins.oci_init, &init_dest)?;

    Ok(InjectedPaths {
        init: init_dest,
        agent: agent_dest,
        netinit: netinit_dest,
        netd: netd_dest,
        egress_client: egress_client_dest,
        entrypoint_runner: entrypoint_runner_dest,
        runtime_mount_point: runtime_dir,
    })
}

/// Paths written by [`inject_mvm_runtime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedPaths {
    pub init: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub netd: PathBuf,
    pub egress_client: PathBuf,
    pub entrypoint_runner: PathBuf,
    pub runtime_mount_point: PathBuf,
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    set_mode(path, mode)
}

fn ensure_dir(rootfs_dir: &Path, rel: &str, mode: u32) -> Result<(), io::Error> {
    let path = rootfs_dir.join(rel);
    std::fs::create_dir_all(&path)?;
    set_mode(&path, mode)
}

fn copy_exec(src: &Path, dst: &Path) -> Result<(), io::Error> {
    copy_file_with_mode(src, dst, 0o755)
}

fn copy_file_with_mode(src: &Path, dst: &Path, mode: u32) -> Result<(), io::Error> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove an existing destination first so a read-only (0444) cached
    // binary from a prior inject doesn't reject the overwrite.
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)?;
    set_mode(dst, mode)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_bins(dir: &Path) -> MvmRuntimeBinaries {
        let oci_init = dir.join("oci-init.bin");
        let agent = dir.join("agent.bin");
        let netinit = dir.join("netinit.bin");
        let netd = dir.join("netd.bin");
        let egress_client = dir.join("egress-client.bin");
        let entrypoint_runner = dir.join("entrypoint-runner.bin");
        let verity_init = dir.join("verity-init.bin");
        std::fs::write(&oci_init, b"\x7fELF-oci-init").unwrap();
        std::fs::write(&agent, b"\x7fELF-agent").unwrap();
        std::fs::write(&netinit, b"\x7fELF-netinit").unwrap();
        std::fs::write(&netd, b"\x7fELF-netd").unwrap();
        std::fs::write(&egress_client, b"\x7fELF-egress-client").unwrap();
        std::fs::write(&entrypoint_runner, b"\x7fELF-entrypoint-runner").unwrap();
        std::fs::write(&verity_init, b"\x7fELF-verity-init").unwrap();
        MvmRuntimeBinaries {
            oci_init,
            agent,
            netinit,
            netd,
            egress_client,
            entrypoint_runner,
            verity_init,
        }
    }

    #[test]
    fn inject_writes_init_binaries_and_mount_point() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        let entrypoint = OciEntrypointConfig {
            argv: vec![
                "/app/server".to_string(),
                "--port".to_string(),
                "8080".to_string(),
            ],
            env: vec!["FOO=bar".to_string()],
            working_dir: Some("/app".to_string()),
        };

        let injected = inject_mvm_runtime(&root, &bins, Some(&entrypoint), false).expect("inject");

        // /init is the injected static binary, not a shell script that would
        // require `/bin/sh` or busybox from the source OCI image.
        assert_eq!(std::fs::read(&injected.init).unwrap(), b"\x7fELF-oci-init");
        assert!(is_executable(&injected.init));
        // Binaries copied to the baked path, executable, content-equal.
        assert_eq!(std::fs::read(&injected.agent).unwrap(), b"\x7fELF-agent");
        assert!(is_executable(&injected.agent));
        assert_eq!(
            std::fs::read(&injected.netinit).unwrap(),
            b"\x7fELF-netinit"
        );
        assert!(is_executable(&injected.netinit));
        assert_eq!(std::fs::read(&injected.netd).unwrap(), b"\x7fELF-netd");
        assert!(is_executable(&injected.netd));
        assert_eq!(
            std::fs::read(&injected.egress_client).unwrap(),
            b"\x7fELF-egress-client"
        );
        assert!(is_executable(&injected.egress_client));
        assert_eq!(
            std::fs::read(&injected.entrypoint_runner).unwrap(),
            b"\x7fELF-entrypoint-runner"
        );
        assert!(is_executable(&injected.entrypoint_runner));
        assert_eq!(
            std::fs::metadata(&injected.entrypoint_runner)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/mvm/entrypoint")).unwrap(),
            "/usr/lib/mvm/wrappers/oci-entrypoint\n"
        );
        let written_entrypoint: OciEntrypointConfig = serde_json::from_slice(
            &std::fs::read(root.join("etc/mvm/oci-entrypoint.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written_entrypoint, entrypoint);
        // Overlay mount point exists on disk.
        assert!(injected.runtime_mount_point.is_dir());
        assert!(root.join("mvm/runtime").is_dir());
        for rel in ["proc", "sys", "dev/pts", "dev/shm", "run", "tmp"] {
            assert!(root.join(rel).is_dir(), "{rel} mountpoint exists");
        }
        // Markers.
        assert_eq!(
            std::fs::read_to_string(root.join("etc/mvm/variant")).unwrap(),
            "dev\n"
        );
    }

    #[test]
    fn inject_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins, None, false).expect("first inject");
        // A second inject (e.g. cache reuse) must not error on existing files.
        let second = inject_mvm_runtime(&root, &bins, None, false).expect("second inject");
        assert!(is_executable(&second.agent));
        assert!(is_executable(&second.netd));
        assert!(is_executable(&second.egress_client));
        assert!(!root.join("etc/mvm/entrypoint").exists());
    }

    #[test]
    fn inject_rejects_missing_rootfs_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());
        let err = inject_mvm_runtime(&tmp.path().join("nope"), &bins, None, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn sealed_inject_writes_prod_variant() {
        // A `--prod` OCI run bakes `variant=prod`; the dev run keeps `dev`.
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());

        let dev_root = tmp.path().join("dev-rootfs");
        std::fs::create_dir_all(&dev_root).unwrap();
        inject_mvm_runtime(&dev_root, &bins, None, false).expect("dev inject");
        assert_eq!(
            std::fs::read_to_string(dev_root.join("etc/mvm/variant")).unwrap(),
            "dev\n"
        );

        let prod_root = tmp.path().join("prod-rootfs");
        std::fs::create_dir_all(&prod_root).unwrap();
        inject_mvm_runtime(&prod_root, &bins, None, true).expect("prod inject");
        assert_eq!(
            std::fs::read_to_string(prod_root.join("etc/mvm/variant")).unwrap(),
            "prod\n"
        );
    }

    #[test]
    fn sealed_inject_bakes_require_grant_policy() {
        // A `--prod` OCI run bakes `/etc/mvm/verb-trust.json` into the rootfs
        // before the dm-verity seal, so require-grant is intrinsic to the
        // measured image. The dev run must leave the file absent (permissive).
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());

        let dev_root = tmp.path().join("dev-rootfs");
        std::fs::create_dir_all(&dev_root).unwrap();
        inject_mvm_runtime(&dev_root, &bins, None, false).expect("dev inject");
        assert!(
            !dev_root.join("etc/mvm/verb-trust.json").exists(),
            "dev inject must not bake a require-grant policy"
        );

        let prod_root = tmp.path().join("prod-rootfs");
        std::fs::create_dir_all(&prod_root).unwrap();
        inject_mvm_runtime(&prod_root, &bins, None, true).expect("prod inject");
        let policy_path = prod_root.join("etc/mvm/verb-trust.json");
        assert!(
            policy_path.is_file(),
            "sealed inject writes verb-trust.json"
        );
        assert_eq!(
            std::fs::metadata(&policy_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444,
            "verb-trust.json is read-only (0444)"
        );
        let policy: mvm_core::plan::VerbTrustPolicy =
            serde_json::from_slice(&std::fs::read(&policy_path).unwrap())
                .expect("verb-trust.json round-trips");
        assert!(policy.require_grant);
        assert_eq!(policy.version, mvm_core::plan::VERB_TRUST_POLICY_VERSION);
        assert_eq!(
            policy.grant_key_source,
            mvm_core::plan::GrantKeySource::LaunchProvisioned
        );
        // Byte-for-byte identical to what mkGuest bakes for sealed block images.
        assert_eq!(
            std::fs::read(&policy_path).unwrap(),
            br#"{"version":1,"require_grant":true,"grant_key_source":"launch_provisioned"}"#
        );
    }

    #[cfg(unix)]
    fn is_executable(p: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    fn is_executable(_p: &Path) -> bool {
        true
    }
}
