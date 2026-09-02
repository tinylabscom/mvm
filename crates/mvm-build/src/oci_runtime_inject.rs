//! Inject the mvm guest runtime into an OCI-unpacked rootfs.
//!
//! An arbitrary OCI image (alpine, debian, a language base) ships none
//! of the mvm runtime: no guest agent, no `/init` that brings the agent
//! up, no `/mvm/runtime` overlay mount point. Without those, a microVM
//! booted from the image has no vsock control plane.
//!
//! This module is the host-side fix. It runs against the unpacked OCI
//! tree *before* it is sealed into `rootfs.ext4`, baking in:
//!
//! - the entrypoint wrapper and mount points, so the
//!   source OCI image does not need `/bin/sh`, busybox, or its own init.
//! - `/usr/lib/mvm/wrappers/oci-entrypoint` plus `/etc/mvm/entrypoint`
//!   when the OCI config declares Entrypoint/Cmd.
//! - `/mvm/runtime`, the shared runtime overlay mount point.
//! - `/mvm/sdk`, the reserved read-only SDK sidecar mount point.
//! - `/etc/mvm/{name,variant}` and, for sealed boots,
//!   `/etc/mvm/verb-trust.json`.
//! - `/etc/{passwd,group}` entries naming the workload uid, and the
//!   `/home/mvm-worker` mount point, which is what `mk-guest.nix` already
//!   bakes into the images mvm builds itself. The workload root is mounted
//!   read-only, so a boot-time write cannot stand in for either.
//! - For rootfs-only launch shapes, baked guest binaries under
//!   `/usr/local/bin/`.
//!
//! Runtime-lean launch shapes intentionally do *not* bake the guest runtime
//! helpers into the OCI rootfs; those binaries must come from the shared
//! read-only runtime overlay.

use std::io;
use std::path::{Path, PathBuf};

/// The cross-compiled guest binaries to bake into the rootfs. Produced on the
/// host by [`crate::guest_agent_build`] or unpacked from the published runtime
/// overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvmRuntimeBinaries {
    /// Static guest agent binary (`mvm-guest-agent`).
    pub agent: PathBuf,
    /// Static guest netinit binary (`mvm-guest-netinit`).
    pub netinit: PathBuf,
    /// Static guest egress shim (`mvm-egress-client`).
    pub egress_client: PathBuf,
    /// Static OCI entrypoint runner (`mvm-oci-entrypoint`).
    pub entrypoint_runner: PathBuf,
}

/// Version tag on the digest encoding itself. Bump only when the *framing*
/// below changes (field order, separators), which would otherwise make two
/// different encodings collide. Not a content epoch — content is covered by
/// the bytes.
const CONTENT_DIGEST_FRAMING: &str = "mvm-runtime-id-v1";

/// Version of host-side injection behavior that cannot be inferred from the
/// injected files or their destination paths. Bumping this invalidates cached
/// rootfs images when interpretation changes, such as preserving image `Env`
/// even when the image declares no command.
pub const INJECT_SEMANTICS_VERSION: &str = "2";

impl MvmRuntimeBinaries {
    /// The four artifacts in a fixed order, tagged with the name each is
    /// digested under.
    ///
    /// One place defines the set, so [`content_digest`](Self::content_digest)
    /// and any caller that wants to stat the same files cannot disagree about
    /// what "the injected runtime" is.
    pub fn artifacts(&self) -> [(&'static str, &Path); 4] {
        [
            ("agent", self.agent.as_path()),
            ("netinit", self.netinit.as_path()),
            ("egress_client", self.egress_client.as_path()),
            ("entrypoint_runner", self.entrypoint_runner.as_path()),
        ]
    }

    /// Digest over the bytes of every artifact injected into a rootfs, plus
    /// the injection layout that is not itself a file.
    ///
    /// This is the rootfs cache identity. It is derived from the artifacts
    /// that actually get copied in, so a rebuilt agent or egress shim
    /// invalidates every cached rootfs without anyone remembering to say so.
    /// The layout component ([`INJECT_DIRS`] + [`INJECT_DESTS`]) covers the
    /// part of the injection a byte digest cannot see: a mountpoint added or a
    /// destination moved changes what a sealed image can do at boot.
    pub fn content_digest(&self) -> Result<String, io::Error> {
        self.content_digest_with_shape(&inject_shape_bytes())
    }

    /// [`Self::content_digest`] with the layout component supplied, so a test
    /// can vary it without re-deriving the artifact encoding.
    fn content_digest_with_shape(&self, shape: &[u8]) -> Result<String, io::Error> {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();
        h.update(CONTENT_DIGEST_FRAMING.as_bytes());
        h.update([0u8]);

        for (name, path) in self.artifacts() {
            let bytes = std::fs::read(path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("read runtime artifact {name} at {}: {e}", path.display()),
                )
            })?;
            // The prepared-cold launch lane forbids `artifact_hash`, and its
            // premise is that a sample which hashed nothing passes. A digest
            // that read five megabytes without saying so would leave that
            // probe blind to the one thing it is named for.
            mvm_core::launch_trace::record_artifact_bytes_hashed(bytes.len() as u64);

            h.update(name.as_bytes());
            h.update([0u8]);
            // Framing hygiene, not load-bearing today: the field set is fixed
            // in order, count and tag, so no artifact's content can forge a
            // neighbouring field's framing and there is no mutation of this
            // line a test can catch. It keeps the encoding unambiguous if the
            // set ever becomes variable-length.
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(&bytes);
            h.update([0u8]);
        }

        h.update(shape);

        Ok(hex::encode(h.finalize()))
    }
}

/// The injection layout, serialized. Split from [`MvmRuntimeBinaries::
/// content_digest`] so the layout's contribution is independently testable —
/// a test that re-derived the whole encoding inline would pass no matter what
/// the production digest folded in.
fn inject_shape_bytes() -> Vec<u8> {
    let mut out = b"inject-shape\0".to_vec();
    out.extend_from_slice(INJECT_SEMANTICS_VERSION.as_bytes());
    out.push(0);
    for (rel, mode) in INJECT_DIRS {
        out.extend_from_slice(rel.as_bytes());
        out.push(0);
        out.extend_from_slice(&mode.to_le_bytes());
    }
    for dest in INJECT_DESTS {
        out.extend_from_slice(dest.as_bytes());
        out.push(0);
    }
    out
}

/// The image's declared runtime config. Defined by the guest crate that reads
/// it back, so the writer and the reader cannot drift apart.
pub use mvm_agentd::workload_env::ImageRuntimeConfig;

const AGENT_DEST: &str = "usr/local/bin/mvm-guest-agent";
const NETINIT_DEST: &str = "usr/local/bin/mvm-guest-netinit";
const EGRESS_CLIENT_DEST: &str = "usr/local/bin/mvm-egress-client";
const ENTRYPOINT_RUNNER_DEST: &str = "usr/lib/mvm/wrappers/oci-entrypoint";
const ENTRYPOINT_MARKER_DEST: &str = "etc/mvm/entrypoint";
const IMAGE_RUNTIME_CONFIG_DEST: &str = mvm_agentd::workload_env::CONFIG_REL_PATH;
const VERB_TRUST_DEST: &str = "etc/mvm/verb-trust.json";

/// The workload's home, relative to the rootfs root.
const WORKLOAD_HOME_REL: &str = mvm_agentd::guest_mount::WORKLOAD_HOME_REL;

/// Directories `inject_mvm_runtime` creates in the target rootfs, with their
/// modes. Named rather than inline so [`MvmRuntimeBinaries::content_digest`]
/// can fold the layout into the identity: a rootfs sealed before a mountpoint
/// was added cannot create it at boot, so changing this table must invalidate
/// already-materialized images.
const INJECT_DIRS: &[(&str, u32)] = &[
    ("proc", 0o755),
    ("sys", 0o755),
    ("dev", 0o755),
    ("dev/pts", 0o755),
    ("dev/shm", 0o1777),
    ("run", 0o755),
    ("tmp", 0o1777),
    ("mnt", 0o755),
    ("data", 0o755),
    ("work", 0o755),
    ("mvm/runtime", 0o755),
    ("mvm/sdk", 0o755),
    ("usr/lib/mvm/wrappers", 0o755),
    // The mount point the guest lays a writable tmpfs over. It has to exist
    // in the image because the root it lives in is read-only by the time any
    // guest code runs.
    (WORKLOAD_HOME_REL, 0o755),
];

/// Every destination path `inject_mvm_runtime` writes, in a fixed order.
/// Folded into the content digest alongside [`INJECT_DIRS`] so a moved
/// destination re-materializes stale images.
const INJECT_DESTS: &[&str] = &[
    AGENT_DEST,
    NETINIT_DEST,
    EGRESS_CLIENT_DEST,
    ENTRYPOINT_RUNNER_DEST,
    ENTRYPOINT_MARKER_DEST,
    IMAGE_RUNTIME_CONFIG_DEST,
    VERB_TRUST_DEST,
    "etc/mvm/variant",
    "etc/mvm/name",
    "etc/passwd",
    "etc/group",
];

/// Inject the mvm runtime into the OCI-unpacked `rootfs_dir`.
///
/// Idempotent: re-running overwrites the injected files. Returns the paths
/// written so the caller can verify the resulting rootfs shape.
pub fn inject_mvm_runtime(
    rootfs_dir: &Path,
    bins: &MvmRuntimeBinaries,
    entrypoint: Option<&ImageRuntimeConfig>,
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

    for (rel, mode) in INJECT_DIRS {
        ensure_dir(rootfs_dir, rel, *mode)?;
    }
    let runtime_dir = rootfs_dir.join("mvm").join("runtime");

    // Name the workload uid inside the image's own account databases. The
    // guest cannot do this for itself: every workload root is mounted
    // read-only, so the boot-time equivalent silently no-ops and the image is
    // left with a uid `getpwuid` cannot resolve — `whoami` fails, `ls -l`
    // prints digits, and an interactive shell greets you as `I have no name!`.
    // Appends only, and never over an entry the image already claims.
    mvm_agentd::workload_identity::provision_in(
        rootfs_dir,
        mvm_agentd::guest_mount::WORKLOAD_HOME,
    )?;

    let etc_mvm = rootfs_dir.join("etc").join("mvm");
    std::fs::create_dir_all(&etc_mvm)?;
    let variant: &[u8] = if sealed { b"prod\n" } else { b"dev\n" };
    write_file(&etc_mvm.join("variant"), variant, 0o644)?;
    write_file(&etc_mvm.join("name"), b"oci\n", 0o644)?;

    if sealed {
        let policy = mvm_core::plan::VerbTrustPolicy {
            version: mvm_core::plan::VERB_TRUST_POLICY_VERSION,
            require_grant: true,
            grant_key_source: mvm_core::plan::GrantKeySource::LaunchProvisioned,
        };
        let policy_json = serde_json::to_vec(&policy).map_err(io::Error::other)?;
        write_file(&rootfs_dir.join(VERB_TRUST_DEST), &policy_json, 0o444)?;
    }

    // The runtime overlay is the single source of the guest binaries, so the
    // rootfs must not carry a copy of any of them. An image that shipped its
    // own is stripped here rather than left to shadow the overlay.
    let agent_dest = rootfs_dir.join(AGENT_DEST);
    let netinit_dest = rootfs_dir.join(NETINIT_DEST);
    let egress_client_dest = rootfs_dir.join(EGRESS_CLIENT_DEST);
    let _ = std::fs::remove_file(&agent_dest);
    let _ = std::fs::remove_file(&netinit_dest);
    let _ = std::fs::remove_file(&egress_client_dest);

    let entrypoint_runner_dest = rootfs_dir.join(ENTRYPOINT_RUNNER_DEST);
    copy_file_with_mode(&bins.entrypoint_runner, &entrypoint_runner_dest, 0o555)?;

    if let Some(entrypoint) = entrypoint.filter(|config| !config.is_empty()) {
        // Written whenever the image declares anything at all. Gating this on
        // a non-empty argv threw away the image's `Env` and `WorkingDir`
        // alongside the absent command, and the interactive console reads
        // this file too.
        let entrypoint_json = serde_json::to_vec(entrypoint).map_err(io::Error::other)?;
        write_file(
            &rootfs_dir.join(IMAGE_RUNTIME_CONFIG_DEST),
            &entrypoint_json,
            0o644,
        )?;
        // The marker is what makes the agent *run* something, so it stays
        // gated on there being something to run.
        if !entrypoint.argv.is_empty() {
            write_file(
                &rootfs_dir.join(ENTRYPOINT_MARKER_DEST),
                b"/usr/lib/mvm/wrappers/oci-entrypoint\n",
                0o644,
            )?;
        }
    }

    Ok(InjectedPaths {
        agent: agent_dest,
        netinit: netinit_dest,
        egress_client: egress_client_dest,
        entrypoint_runner: entrypoint_runner_dest,
        runtime_mount_point: runtime_dir,
    })
}

/// Paths written by [`inject_mvm_runtime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedPaths {
    pub agent: PathBuf,
    pub netinit: PathBuf,
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

fn copy_file_with_mode(src: &Path, dst: &Path, mode: u32) -> Result<(), io::Error> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
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

    /// The identity must come from the artifacts' bytes, not their paths.
    /// A rebuilt binary at an unchanged path is exactly the case the old
    /// hand-bumped epoch constant existed to catch by hand.
    #[test]
    fn content_digest_tracks_bytes_not_paths() {
        let dir = tempfile::tempdir().unwrap();
        let bins = fake_bins(dir.path());
        let before = bins.content_digest().unwrap();

        // Same length, different bytes: the length prefix must not be what
        // carries this assertion, or a path-only digest would still pass.
        std::fs::write(&bins.agent, b"\x7fELF-AGENT").unwrap();
        let after = bins.content_digest().unwrap();
        assert_eq!(
            std::fs::metadata(&bins.agent).unwrap().len(),
            b"\x7fELF-agent".len() as u64,
            "the perturbation must not change the artifact's length"
        );

        assert_ne!(
            before, after,
            "a rebuilt artifact at the same path must not keep the old identity"
        );
    }

    #[test]
    fn content_digest_is_stable_for_unchanged_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let bins = fake_bins(dir.path());
        assert_eq!(
            bins.content_digest().unwrap(),
            bins.content_digest().unwrap(),
            "identical bytes must reuse the cached rootfs, not re-materialize it"
        );
    }

    /// Every artifact in the set must be covered.
    ///
    /// The field list here is written out deliberately rather than taken from
    /// [`MvmRuntimeBinaries::artifacts`]: driving the test from the same
    /// function it is checking would let a dropped artifact pass, because the
    /// test would simply stop looking at it too. Adding a seventh injected
    /// binary fails to compile here until it is added to both.
    #[test]
    fn content_digest_covers_every_injected_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let bins = fake_bins(dir.path());
        let baseline = bins.content_digest().unwrap();

        let MvmRuntimeBinaries {
            agent,
            netinit,
            egress_client,
            entrypoint_runner,
        } = &bins;
        let every_field = [
            ("agent", agent),
            ("netinit", netinit),
            ("egress_client", egress_client),
            ("entrypoint_runner", entrypoint_runner),
        ];

        for (name, path) in every_field {
            let original = std::fs::read(path).unwrap();
            // Flip a byte in place. Appending would change the length, and the
            // length prefix alone would then satisfy the assertion without the
            // artifact's content ever being covered.
            let mut perturbed = original.clone();
            let last = perturbed.len() - 1;
            perturbed[last] ^= 0xFF;
            std::fs::write(path, &perturbed).unwrap();

            assert_ne!(
                baseline,
                bins.content_digest().unwrap(),
                "changing {name} must change the runtime identity"
            );

            std::fs::write(path, &original).unwrap();
        }

        assert_eq!(
            baseline,
            bins.content_digest().unwrap(),
            "restoring every artifact must restore the identity"
        );
    }

    /// Length is covered separately, now that every content test holds it
    /// constant on purpose.
    #[test]
    fn content_digest_tracks_artifact_length() {
        let dir = tempfile::tempdir().unwrap();
        let bins = fake_bins(dir.path());
        let before = bins.content_digest().unwrap();

        let mut longer = std::fs::read(&bins.agent).unwrap();
        longer.push(b'!');
        std::fs::write(&bins.agent, &longer).unwrap();

        assert_ne!(before, bins.content_digest().unwrap());
    }

    /// A length prefix per artifact stops content sliding between adjacent
    /// fields from colliding.
    #[test]
    fn content_digest_distinguishes_shifted_content_between_artifacts() {
        let dir_a = tempfile::tempdir().unwrap();
        let a = fake_bins(dir_a.path());
        std::fs::write(&a.agent, b"AB").unwrap();
        std::fs::write(&a.netinit, b"CD").unwrap();

        let dir_b = tempfile::tempdir().unwrap();
        let b = fake_bins(dir_b.path());
        std::fs::write(&b.agent, b"CD").unwrap();
        std::fs::write(&b.netinit, b"AB").unwrap();

        assert_ne!(
            a.content_digest().unwrap(),
            b.content_digest().unwrap(),
            "the same bytes split differently across artifacts must not collide"
        );
    }

    /// A missing artifact must name itself; this runs on the cache-gate path
    /// where the alternative is an opaque "No such file or directory".
    #[test]
    fn content_digest_names_a_missing_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let bins = fake_bins(dir.path());
        std::fs::remove_file(&bins.egress_client).unwrap();

        let err = bins
            .content_digest()
            .expect_err("a missing artifact must not digest");
        let msg = err.to_string();
        assert!(
            msg.contains("egress_client") && msg.contains("mvm-egress-client")
                || msg.contains("egress_client") && msg.contains("egress-client"),
            "error should name the artifact and its path: {msg}"
        );
    }

    /// The injection layout is not a file, so the byte digest cannot see it.
    /// A sealed rootfs built before a mountpoint existed cannot create it at
    /// boot, so the layout has to be part of the identity.
    ///
    /// Checked through the same seam production uses, so dropping the fold
    /// from `content_digest` fails here. An earlier version of this test
    /// re-derived the whole encoding inline and passed under exactly that bug.
    #[test]
    fn content_digest_covers_the_injection_layout() {
        let dir = tempfile::tempdir().unwrap();
        let bins = fake_bins(dir.path());

        assert_eq!(
            bins.content_digest().unwrap(),
            bins.content_digest_with_shape(&inject_shape_bytes())
                .unwrap(),
            "content_digest must fold in the real injection layout"
        );
        assert_ne!(
            bins.content_digest().unwrap(),
            bins.content_digest_with_shape(b"a-different-layout")
                .unwrap(),
            "a changed injection layout must change the identity"
        );
    }

    /// The serialized layout must actually mention every table entry, or the
    /// seam above would be satisfied by a constant.
    #[test]
    fn inject_shape_bytes_mentions_every_dir_and_dest() {
        let shape = inject_shape_bytes();
        assert!(
            shape
                .windows(INJECT_SEMANTICS_VERSION.len())
                .any(|window| window == INJECT_SEMANTICS_VERSION.as_bytes()),
            "layout digest omits the host-side injection semantics version"
        );
        for (rel, _) in INJECT_DIRS {
            assert!(
                shape.windows(rel.len()).any(|w| w == rel.as_bytes()),
                "layout digest omits directory {rel}"
            );
        }
        for dest in INJECT_DESTS {
            assert!(
                shape.windows(dest.len()).any(|w| w == dest.as_bytes()),
                "layout digest omits destination {dest}"
            );
        }
    }

    fn fake_bins(dir: &Path) -> MvmRuntimeBinaries {
        let agent = dir.join("agent.bin");
        let netinit = dir.join("netinit.bin");
        let egress_client = dir.join("egress-client.bin");
        let entrypoint_runner = dir.join("entrypoint-runner.bin");
        std::fs::write(&agent, b"\x7fELF-agent").unwrap();
        std::fs::write(&netinit, b"\x7fELF-netinit").unwrap();
        std::fs::write(&egress_client, b"\x7fELF-egress-client").unwrap();
        std::fs::write(&entrypoint_runner, b"\x7fELF-entrypoint-runner").unwrap();
        MvmRuntimeBinaries {
            agent,
            netinit,
            egress_client,
            entrypoint_runner,
        }
    }

    /// The reported bug: `machine run --image rust:latest -it` landed in a
    /// shell with no image `PATH`. `rust:latest` declares `Cmd` *and* `Env`,
    /// but every consumer read the file only when there was an entrypoint to
    /// run — and the interactive console did not read it at all.
    #[test]
    fn an_image_declaring_env_and_no_command_still_gets_its_config_written() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        let config = ImageRuntimeConfig {
            argv: Vec::new(),
            env: vec!["PATH=/usr/local/cargo/bin".to_string()],
            working_dir: None,
        };
        inject_mvm_runtime(&root, &bins, Some(&config), false).expect("inject");

        let written: ImageRuntimeConfig = serde_json::from_slice(
            &std::fs::read(root.join(IMAGE_RUNTIME_CONFIG_DEST)).expect("config written"),
        )
        .expect("config parses");
        assert_eq!(written, config);
        // Nothing to run, so nothing claims the entrypoint contract.
        assert!(!root.join(ENTRYPOINT_MARKER_DEST).exists());
    }

    #[test]
    fn an_image_declaring_nothing_gets_no_config_at_all() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins, Some(&ImageRuntimeConfig::default()), false)
            .expect("inject");

        assert!(!root.join(IMAGE_RUNTIME_CONFIG_DEST).exists());
        assert!(!root.join(ENTRYPOINT_MARKER_DEST).exists());
    }

    /// The second half of the reported bug: the shell greeted the operator as
    /// `I have no name!`. Every workload root is mounted read-only, so the
    /// guest cannot name its own uid at boot — the entry has to be baked in,
    /// exactly as `mk-guest.nix` does for the images mvm builds itself.
    #[test]
    fn inject_names_the_workload_uid_in_the_images_account_databases() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        std::fs::write(root.join("etc/group"), "root:x:0:\n").unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins, None, false).expect("inject");

        let passwd = std::fs::read_to_string(root.join("etc/passwd")).unwrap();
        assert!(
            passwd.contains(&format!(
                "mvm-worker:x:{}:{}:",
                mvm_agentd::guest_mount::WORKLOAD_UID,
                mvm_agentd::guest_mount::WORKLOAD_GID
            )),
            "uid not named: {passwd}"
        );
        assert!(
            passwd.contains(mvm_agentd::guest_mount::WORKLOAD_HOME),
            "entry must point at the home the guest mounts: {passwd}"
        );
        // The image's own accounts are untouched.
        assert!(passwd.starts_with("root:x:0:0:root:/root:/bin/bash\n"));
        assert!(
            std::fs::read_to_string(root.join("etc/group"))
                .unwrap()
                .contains("mvm-worker:x:901:")
        );
    }

    /// A `scratch` image ships no account databases at all; creating them is
    /// what makes the identity resolvable there.
    #[test]
    fn inject_creates_account_databases_an_image_does_not_ship() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins, None, false).expect("inject");

        assert!(
            std::fs::read_to_string(root.join("etc/passwd"))
                .unwrap()
                .contains("mvm-worker:x:901:")
        );
    }

    /// An image that already claims the uid or the name wins; nothing is
    /// rewritten, uid 0 least of all.
    #[test]
    fn inject_leaves_an_image_that_already_claims_the_identity_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let existing = "root:x:0:0:root:/root:/bin/sh\nsomeone:x:901:901::/home/someone:/bin/sh\n";
        std::fs::write(root.join("etc/passwd"), existing).unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins, None, false).expect("inject");

        assert_eq!(
            std::fs::read_to_string(root.join("etc/passwd")).unwrap(),
            existing
        );
    }

    /// The home is a *mount point*: the guest lays a writable tmpfs over it,
    /// which needs no write to the read-only root but does need the directory
    /// to already be there.
    #[test]
    fn inject_creates_the_home_mount_point_the_guest_mounts_over() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins, None, false).expect("inject");

        assert!(
            root.join(mvm_agentd::guest_mount::WORKLOAD_HOME_REL)
                .is_dir()
        );
    }

    /// Baking new files into the rootfs changes what a materialized image
    /// contains, so an image sealed before they existed has to re-materialize
    /// rather than boot without them.
    #[test]
    fn the_account_databases_and_home_are_folded_into_the_content_digest() {
        for name in [
            "etc/passwd",
            "etc/group",
            mvm_agentd::guest_mount::WORKLOAD_HOME_REL,
        ] {
            assert!(
                INJECT_DESTS.contains(&name) || INJECT_DIRS.iter().any(|(rel, _)| *rel == name),
                "{name} is written but not folded into the identity"
            );
        }
    }

    #[test]
    fn inject_writes_the_entrypoint_runner_and_bakes_no_guest_binaries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        let entrypoint = ImageRuntimeConfig {
            argv: vec![
                "/app/server".to_string(),
                "--port".to_string(),
                "8080".to_string(),
            ],
            env: vec!["FOO=bar".to_string()],
            working_dir: Some("/app".to_string()),
        };

        let injected = inject_mvm_runtime(&root, &bins, Some(&entrypoint), false).expect("inject");

        // The overlay is the single source of the guest binaries, so none of
        // them is baked into the tree and no rootfs `/init` is written: the
        // universal initramfs supplies PID 1.
        assert!(!root.join("init").exists());
        assert!(!injected.agent.exists());
        assert!(!injected.netinit.exists());
        assert!(!injected.egress_client.exists());
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
        let written_entrypoint: ImageRuntimeConfig =
            serde_json::from_slice(&std::fs::read(root.join(IMAGE_RUNTIME_CONFIG_DEST)).unwrap())
                .unwrap();
        assert_eq!(written_entrypoint, entrypoint);
        assert!(injected.runtime_mount_point.is_dir());
        assert!(root.join("mvm/runtime").is_dir());
        assert!(
            root.join("mvm/sdk").is_dir(),
            "the sealed root must carry the reserved SDK mountpoint"
        );
        for rel in [
            "proc", "sys", "dev/pts", "dev/shm", "run", "tmp", "mnt", "data", "work",
        ] {
            assert!(root.join(rel).is_dir(), "{rel} mountpoint exists");
        }
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
        let second = inject_mvm_runtime(&root, &bins, None, false).expect("second inject");
        // Re-running must leave the same shape: the entrypoint wrapper present,
        // the guest binaries still absent (the overlay supplies them), and no
        // entrypoint marker for an image that declared no command.
        assert!(is_executable(&second.entrypoint_runner));
        assert!(!second.agent.exists());
        assert!(!second.egress_client.exists());
        assert!(second.runtime_mount_point.is_dir());
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
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());

        let dev_root = tmp.path().join("dev-rootfs");
        std::fs::create_dir_all(&dev_root).unwrap();
        inject_mvm_runtime(&dev_root, &bins, None, false).expect("dev inject");
        assert!(!dev_root.join("etc/mvm/verb-trust.json").exists());

        let prod_root = tmp.path().join("prod-rootfs");
        std::fs::create_dir_all(&prod_root).unwrap();
        inject_mvm_runtime(&prod_root, &bins, None, true).expect("prod inject");
        let policy_path = prod_root.join("etc/mvm/verb-trust.json");
        assert!(policy_path.is_file());
        assert_eq!(
            std::fs::metadata(&policy_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        let policy: mvm_core::plan::VerbTrustPolicy =
            serde_json::from_slice(&std::fs::read(&policy_path).unwrap()).unwrap();
        assert!(policy.require_grant);
        assert_eq!(policy.version, mvm_core::plan::VERB_TRUST_POLICY_VERSION);
        assert_eq!(
            policy.grant_key_source,
            mvm_core::plan::GrantKeySource::LaunchProvisioned
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
