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
/// even when the image declares no command, or writing every injected file as
/// a fresh root-owned inode rather than into whatever the image left there.
pub const INJECT_SEMANTICS_VERSION: &str = "3";

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
    for tree in INJECT_TREES {
        out.extend_from_slice(b"tree:");
        out.extend_from_slice(tree.as_bytes());
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

/// Directory trees that exist only to hold injected files, so everything
/// beneath them belongs to the runtime rather than to the image.
///
/// [`INJECT_DESTS`] names the files written today; these cover the names a
/// later one will use, and the parent directories the writes create along the
/// way — `/etc/mvm` is made by `create_dir_all` and so appears in neither
/// table above.
const INJECT_TREES: &[&str] = &["etc/mvm", "mvm", "usr/lib/mvm"];

/// The guest paths this module owns in a materialized image: every injected
/// file and mount point, the directories on the way to them, and the trees
/// that hold nothing else.
///
/// An OCI layer may name any of them in its tar headers — `/etc/passwd` most
/// of all — and the owner it declares is otherwise applied to the built
/// image's inodes. The account databases a guest resolves uids through, the
/// wrapper it boots and the trust policy it enforces are the runtime's, not
/// the image's, so the materializer hands this set to the ext4 writer and a
/// declared owner never reaches them.
///
/// The directories leading to an injected path are claimed as well, one node
/// each: an image that owned `/etc` could rename its own file over
/// `/etc/passwd` wherever the root is writable. Their other contents keep the
/// owners the layers declared.
///
/// Derived from the same tables the injection itself walks, so a destination
/// added there is claimed here without a second edit.
#[must_use]
pub fn injected_root_owned_paths() -> mvm_fs::ownership::RootOwnedPaths {
    let mut claimed = mvm_fs::ownership::RootOwnedPaths::none();
    for tree in INJECT_TREES {
        claimed = claimed.with_tree(tree);
    }
    for rel in INJECT_DIRS
        .iter()
        .map(|(rel, _mode)| *rel)
        .chain(INJECT_DESTS.iter().copied())
    {
        for claimed_rel in Path::new(rel).ancestors() {
            if claimed_rel.as_os_str().is_empty() {
                continue;
            }
            claimed = claimed.with_path(claimed_rel);
        }
    }
    claimed
}

/// Refuse layer nodes the unpack deferred to the image writer at a path this
/// module owns.
///
/// A deferred node is one the host tree could not hold — a device node on
/// macOS, the loser of a case-insensitive name collision — and the image
/// writer lays it *over* whatever the walk found at that path. At an injected
/// path that would replace the runtime's file with the layer's: a symlink at
/// `/etc/passwd` pointing into a directory the image owns is exactly the
/// account-database takeover [`injected_root_owned_paths`] exists to stop, and
/// forcing the symlink itself to root would not stop it.
pub fn refuse_layer_nodes_at_injected_paths(nodes: &[mvm_fs::ext4::Node]) -> io::Result<()> {
    let claimed = injected_root_owned_paths();
    // Compared as a path, not a string: the unpacker spells a guest path as the
    // tar header did, `./etc//passwd/` included.
    match nodes.iter().find(|node| claimed.claims_path(node.path())) {
        Some(node) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the image places {} at a path mvm injects into every rootfs, in a form the \
                 host filesystem could not hold; refusing to let a layer replace it",
                node.path()
            ),
        )),
        None => Ok(()),
    }
}

/// Every path the injection writes through, relative to the rootfs root.
fn injected_write_paths() -> impl Iterator<Item = &'static str> {
    INJECT_DIRS
        .iter()
        .map(|(rel, _mode)| *rel)
        .chain(INJECT_DESTS.iter().copied())
        .chain(INJECT_TREES.iter().copied())
}

/// Refuse a tree in which the injection would write through a path the image
/// shaped.
///
/// The injection runs on the host, as the invoking user, before the tree is
/// sealed. A layer is free to ship `/etc/passwd`, `/etc`, `/tmp` or `/mvm` as
/// a symbolic link, and the unpacker keeps the link target as written —
/// absolute, or climbing out with `..`. Writing through it would read and
/// rewrite a file outside the rootfs; even a target inside it would move the
/// injected file to a path the image's own owners govern.
///
/// A host filesystem that folds names — the macOS default folds case and some
/// non-ASCII letters — does the same with an alias: an image that ships
/// `etc/Mvm/` and no `etc/mvm/` has the injection's `etc/mvm/verb-trust.json`
/// land in the image's directory, and the guest, which does not fold, never
/// sees `/etc/mvm` at all. Every component therefore has to be on disk under
/// exactly the name the injection uses.
///
/// A non-regular file where a regular one is written (a directory, a FIFO a
/// read would block on) is refused for the same reason: the injection must
/// create what it claims, not adopt what it finds. The mvm-only trees are
/// exempt from that last check because [`clear_mvm_only_trees`] empties them
/// before anything is written.
fn refuse_unsafe_injection_paths(rootfs_dir: &Path) -> io::Result<()> {
    for rel in injected_write_paths() {
        if let Some((at, what)) = first_shaped_component(rootfs_dir, Path::new(rel))? {
            return Err(shaped_path_error(&at, what));
        }
    }
    Ok(())
}

/// Refuse a non-regular file at an injected destination outside the mvm-only
/// trees. Runs after those trees are cleared.
fn refuse_non_regular_destinations(rootfs_dir: &Path) -> io::Result<()> {
    for dest in INJECT_DESTS {
        match std::fs::symlink_metadata(rootfs_dir.join(dest)) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Err(shaped_path_error(Path::new(dest), "is not a regular file"));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn shaped_path_error(rel: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the image's /{} {what}, and mvm writes its own file there; refusing to inject \
             through a path the image shaped",
            rel.display()
        ),
    )
}

const IS_A_SYMLINK: &str = "is a symbolic link";
const IS_AN_ALIAS: &str =
    "resolves on this host only by folding its name onto a differently spelled entry";

/// The first component of `rel` under `root` that is a symbolic link, or that
/// the host resolves to an entry spelled differently, as a path relative to
/// `root` with the reason. Stops at the first component that does not exist:
/// nothing beneath it can be shaped yet.
fn first_shaped_component(root: &Path, rel: &Path) -> io::Result<Option<(PathBuf, &'static str)>> {
    let mut walked = PathBuf::new();
    for component in rel.components() {
        let parent = root.join(&walked);
        walked.push(component);
        match std::fs::symlink_metadata(root.join(&walked)) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Ok(Some((walked, IS_A_SYMLINK)));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        }
        if !directory_lists_exactly(&parent, component.as_os_str())? {
            return Ok(Some((walked, IS_AN_ALIAS)));
        }
    }
    Ok(None)
}

/// Whether `dir` holds an entry whose name is byte-for-byte `name`.
fn directory_lists_exactly(dir: &Path, name: &std::ffi::OsStr) -> io::Result<bool> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        names.push(entry?.file_name());
    }
    Ok(lists_exactly(names, name))
}

/// The comparison [`directory_lists_exactly`] makes, over names already read.
/// Byte equality, deliberately: any folding here would reintroduce the alias
/// the check exists to catch.
fn lists_exactly(
    names: impl IntoIterator<Item = std::ffi::OsString>,
    name: &std::ffi::OsStr,
) -> bool {
    names.into_iter().any(|listed| listed.as_os_str() == name)
}

/// Empty the trees only mvm writes, so nothing the image shipped there — an
/// entrypoint marker, a runtime config, hooks, probes — survives next to what
/// the injection writes. A tree is recreated with an explicit mode, so the
/// result does not depend on the host's umask.
fn clear_mvm_only_trees(rootfs_dir: &Path) -> io::Result<()> {
    for tree in INJECT_TREES {
        let path = rootfs_dir.join(tree);
        match std::fs::symlink_metadata(&path) {
            // Removing a directory never follows a link inside it, and the
            // tree's own path was checked not to be one.
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&path)?,
            Ok(_) => std::fs::remove_file(&path)?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        ensure_dir(rootfs_dir, tree, 0o755)?;
    }
    Ok(())
}

/// Every path the injection always writes, which must exist afterwards under
/// exactly its own spelling.
fn always_written_paths() -> impl Iterator<Item = &'static str> {
    INJECT_DIRS
        .iter()
        .map(|(rel, _mode)| *rel)
        .chain(INJECT_TREES.iter().copied())
        .chain(ACCOUNT_DATABASES)
        .chain([ENTRYPOINT_RUNNER_DEST, "etc/mvm/variant", "etc/mvm/name"])
}

/// Check the tree after injection the way the image writer will read it: by
/// listing each directory. Every path the injection always writes has to be
/// listed under its exact spelling, and no path it may write can resolve
/// through a link or an alias. This is the backstop for the refusal made
/// before injection — a write that landed anywhere else fails here, not in
/// the guest.
fn verify_injected_spelling(rootfs_dir: &Path) -> io::Result<()> {
    for rel in injected_write_paths() {
        if let Some((at, what)) = first_shaped_component(rootfs_dir, Path::new(rel))? {
            return Err(shaped_path_error(&at, what));
        }
    }
    for rel in always_written_paths() {
        let mut dir = rootfs_dir.to_path_buf();
        for component in Path::new(rel).components() {
            if !directory_lists_exactly(&dir, component.as_os_str())? {
                return Err(io::Error::other(format!(
                    "injection wrote /{rel}, but {} does not list {:?} under that spelling",
                    dir.display(),
                    component.as_os_str()
                )));
            }
            dir.push(component);
        }
    }
    Ok(())
}

/// Inject the mvm runtime into the OCI-unpacked `rootfs_dir`.
///
/// Idempotent: re-running overwrites the injected files. Returns the paths
/// written so the caller can verify the resulting rootfs shape.
///
/// Every file it writes is a fresh inode: whatever the image left at that
/// path — a hard link shared with an image file, extended attributes such as
/// an ACL granting another account write access, a permissive mode — is
/// replaced rather than written into. A tree the image shaped so that a write
/// would land somewhere else is refused (see
/// [`refuse_unsafe_injection_paths`]).
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

    refuse_unsafe_injection_paths(rootfs_dir)?;
    clear_mvm_only_trees(rootfs_dir)?;
    refuse_non_regular_destinations(rootfs_dir)?;

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
    //
    // Provisioning appends in place, so each database the image shipped is
    // first moved onto a fresh inode: an image file hard-linked to it would
    // otherwise receive the append, and the layer's mode and extended
    // attributes would survive it.
    for database in ACCOUNT_DATABASES {
        let path = rootfs_dir.join(database);
        if path.exists() {
            reseat_file(&path, 0o644)?;
        }
    }
    mvm_agentd::workload_identity::provision_in(
        rootfs_dir,
        mvm_agentd::guest_mount::WORKLOAD_HOME,
    )?;
    for database in ACCOUNT_DATABASES {
        set_mode(&rootfs_dir.join(database), 0o644)?;
    }

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
    remove_if_present(&agent_dest)?;
    remove_if_present(&netinit_dest)?;
    remove_if_present(&egress_client_dest)?;

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

    verify_injected_spelling(rootfs_dir)?;

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

/// The account databases a guest resolves uids through. Both are in
/// [`INJECT_DESTS`]; named here because they are the two whose contents the
/// injection keeps from the image.
const ACCOUNT_DATABASES: [&str; 2] = ["etc/passwd", "etc/group"];

/// Write `contents` to `path` as a new inode with `mode`, never into the one
/// already there.
///
/// Truncating in place would keep the old inode's extended attributes and any
/// hard link an image file shares with it. `create_new` also refuses to follow
/// a symbolic link that appeared at `path`, so the write cannot land outside
/// the tree however the path came to be shaped.
pub(crate) fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    remove_if_present(path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)?;
    drop(file);
    set_mode(path, mode)
}

/// Replace the regular file at `path` with a fresh inode holding the same
/// bytes, under `mode`.
fn reseat_file(path: &Path, mode: u32) -> Result<(), io::Error> {
    let contents = std::fs::read(path)?;
    write_file(path, &contents, mode)
}

fn remove_if_present(path: &Path) -> Result<(), io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
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
    remove_if_present(dst)?;
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

    /// The claim set is derived from the tables the injection itself walks, so
    /// a destination added to either is claimed without a second edit. This
    /// asserts the derivation rather than restating the list, which a second
    /// copy of the list would not.
    #[test]
    fn every_injected_destination_and_directory_is_claimed() {
        let claimed = injected_root_owned_paths();
        for dest in INJECT_DESTS {
            assert!(
                claimed.claims(&format!("/{dest}")),
                "{dest} must be claimed"
            );
        }
        for (dir, _mode) in INJECT_DIRS {
            assert!(claimed.claims(&format!("/{dir}")), "{dir} must be claimed");
        }
        for tree in INJECT_TREES {
            assert!(
                claimed.claims(&format!("/{tree}/anything-beneath-it")),
                "{tree} must be claimed to its leaves"
            );
        }
    }

    /// The account databases a guest resolves its uid through are the whole
    /// point: a layer that names them must not get to own them.
    #[test]
    fn the_account_databases_and_trust_policy_are_claimed() {
        let claimed = injected_root_owned_paths();
        for path in [
            "/etc/passwd",
            "/etc/group",
            "/etc/mvm/verb-trust.json",
            "/usr/lib/mvm/wrappers/oci-entrypoint",
        ] {
            assert!(claimed.claims(path), "{path} must be claimed");
        }
        assert!(
            !claimed.claims("/etc/hosts"),
            "a path the injection never writes stays the image's own"
        );
    }

    /// The directories on the way to an injected file are claimed, one node
    /// each, and only that: `/usr/local/bin` is the runtime's, the image's
    /// own programs in it are not.
    #[test]
    fn the_directories_leading_to_an_injected_path_are_claimed_alone() {
        let claimed = injected_root_owned_paths();
        for dir in ["/etc", "/usr", "/usr/local", "/usr/local/bin", "/home"] {
            assert!(claimed.claims(dir), "{dir} must be claimed");
        }
        for image_path in ["/usr/local/bin/app", "/home/app", "/etc/hosts"] {
            assert!(
                !claimed.claims(image_path),
                "{image_path} is the image's own"
            );
        }
        assert!(
            !claimed.paths().any(|path| path == "/"),
            "the root is not an ancestor the table names"
        );
    }

    /// A root holding the files an image layer could leave at injected paths,
    /// plus the scratch directory outside it that a hostile link points into.
    struct ShapedRoot {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        outside: PathBuf,
        bins: MvmRuntimeBinaries,
    }

    fn shaped_root() -> ShapedRoot {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let bins = fake_bins(tmp.path());
        ShapedRoot {
            _tmp: tmp,
            root,
            outside,
            bins,
        }
    }

    fn refusal(shaped: &ShapedRoot) -> io::Error {
        inject_mvm_runtime(&shaped.root, &shaped.bins, None, false)
            .expect_err("a tree the image shaped must be refused")
    }

    /// The account database as a link out of the rootfs: injecting through it
    /// would read a host file into the image and append to it on the host.
    #[test]
    fn a_symlinked_account_database_is_refused_and_its_target_untouched() {
        let shaped = shaped_root();
        let host_file = shaped.outside.join("host-secret");
        std::fs::write(&host_file, b"host bytes\n").unwrap();
        std::os::unix::fs::symlink(&host_file, shaped.root.join("etc/passwd")).unwrap();

        let err = refusal(&shaped);

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("/etc/passwd"), "{err}");
        assert_eq!(std::fs::read(&host_file).unwrap(), b"host bytes\n");
    }

    /// A link *inside* the rootfs is refused too: the file would land at a
    /// path the image's own owners govern, not at the one mvm claims.
    #[test]
    fn a_symlink_into_the_image_at_an_injected_path_is_refused() {
        let shaped = shaped_root();
        std::fs::create_dir_all(shaped.root.join("srv")).unwrap();
        std::fs::write(shaped.root.join("srv/group"), b"").unwrap();
        std::os::unix::fs::symlink("../srv/group", shaped.root.join("etc/group")).unwrap();

        assert!(refusal(&shaped).to_string().contains("/etc/group"));
    }

    /// `/etc` itself as a link: every injected file under it would be written
    /// wherever it points.
    #[test]
    fn a_symlinked_parent_directory_is_refused_before_anything_is_written() {
        let shaped = shaped_root();
        std::fs::remove_dir(shaped.root.join("etc")).unwrap();
        std::os::unix::fs::symlink(&shaped.outside, shaped.root.join("etc")).unwrap();

        let err = refusal(&shaped);

        assert!(err.to_string().contains("/etc "), "{err}");
        assert_eq!(
            std::fs::read_dir(&shaped.outside).unwrap().count(),
            0,
            "nothing was written through the link"
        );
        assert!(
            !shaped.root.join("mvm").exists(),
            "the refusal comes before the first write"
        );
    }

    /// A mount point as a link: creating it and setting its mode would chmod
    /// whatever directory it names.
    #[test]
    fn a_symlinked_mount_point_is_refused_and_its_target_mode_kept() {
        let shaped = shaped_root();
        std::fs::set_permissions(&shaped.outside, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&shaped.outside, shaped.root.join("tmp")).unwrap();

        assert!(refusal(&shaped).to_string().contains("/tmp"));
        assert_eq!(
            std::fs::metadata(&shaped.outside)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
    }

    /// Whatever the image shipped inside a tree only mvm writes is gone after
    /// injection: an entrypoint marker of its own, a runtime config, hooks, a
    /// link where the provenance mark goes. Only mvm-authored content remains,
    /// and a link there is removed, never followed.
    #[test]
    fn image_content_in_an_mvm_only_tree_is_cleared() {
        let shaped = shaped_root();
        let outside_mark = shaped.outside.join("mark");
        std::fs::write(&outside_mark, b"host bytes").unwrap();
        for dir in ["mvm", "etc/mvm/hooks", "usr/lib/mvm/wrappers"] {
            std::fs::create_dir_all(shaped.root.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(&outside_mark, shaped.root.join("mvm/provenance.json")).unwrap();
        for (path, body) in [
            ("etc/mvm/entrypoint", "/bin/sh\n"),
            ("etc/mvm/image-runtime.json", "{}"),
            ("etc/mvm/agent.json", "{}"),
            ("etc/mvm/hooks/before_start", "#!/bin/sh\n"),
            ("usr/lib/mvm/wrappers/image-tool", "x"),
        ] {
            std::fs::write(shaped.root.join(path), body).unwrap();
        }

        inject_mvm_runtime(&shaped.root, &shaped.bins, None, false).expect("inject");

        for gone in [
            "mvm/provenance.json",
            "etc/mvm/entrypoint",
            "etc/mvm/image-runtime.json",
            "etc/mvm/agent.json",
            "etc/mvm/hooks",
            "usr/lib/mvm/wrappers/image-tool",
        ] {
            assert!(
                std::fs::symlink_metadata(shaped.root.join(gone)).is_err(),
                "/{gone} is the image's, and must not survive"
            );
        }
        assert_eq!(std::fs::read(&outside_mark).unwrap(), b"host bytes");
        assert!(shaped.root.join(ENTRYPOINT_RUNNER_DEST).is_file());
    }

    /// The trees the injection creates do not take their mode from the host
    /// umask.
    #[test]
    fn the_mvm_only_trees_are_created_with_an_explicit_mode() {
        let shaped = shaped_root();
        std::fs::create_dir_all(shaped.root.join("etc/mvm")).unwrap();
        std::fs::set_permissions(
            shaped.root.join("etc/mvm"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();

        inject_mvm_runtime(&shaped.root, &shaped.bins, None, false).expect("inject");

        for tree in INJECT_TREES {
            assert_eq!(
                std::fs::metadata(shaped.root.join(tree))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o755,
                "/{tree}"
            );
        }
    }

    /// Whether `dir`'s filesystem resolves `alias` to an entry created as
    /// `real` — the macOS default does for case, and for some non-ASCII
    /// letters. Leaves `dir` as it found it.
    fn folds(dir: &Path, real: &str, alias: &str) -> bool {
        let probe = dir.join(real);
        std::fs::write(&probe, b"").unwrap();
        let folded = std::fs::symlink_metadata(dir.join(alias)).is_ok();
        std::fs::remove_file(&probe).unwrap();
        folded
    }

    /// The names `dir` lists, read directly rather than through the check
    /// under test.
    fn listing(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// Plant `planted_rel`, whose component `alias` inside `parent_rel` is
    /// another spelling of mvm's `mvm_name`, and inject. On a host that folds
    /// the two names the injection must refuse, naming the fold; on one that
    /// does not they are distinct entries, nothing aliases, and injection
    /// writes mvm's own spelling beside the image's.
    fn injection_refuses_the_alias(
        parent_rel: &str,
        alias: &str,
        mvm_name: &str,
        planted_rel: &str,
    ) {
        let shaped = shaped_root();
        let parent = shaped.root.join(parent_rel);
        std::fs::create_dir_all(&parent).unwrap();
        // The image ships only its own spelling.
        if listing(&parent).iter().any(|name| name == mvm_name) {
            std::fs::remove_dir_all(parent.join(mvm_name)).unwrap();
        }
        let aliases = folds(&parent, alias, mvm_name);
        let planted = shaped.root.join(planted_rel);
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, b"image\n").unwrap();

        let result = inject_mvm_runtime(&shaped.root, &shaped.bins, None, true);

        if aliases {
            let err = result.expect_err("an alias of an injected path must be refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(err.to_string().contains("folding its name"), "{err}");
        } else {
            eprintln!(
                "host filesystem does not fold {alias:?} onto {mvm_name:?}; the refusal is \
                 proven by lists_exactly_is_byte_equality instead"
            );
            result.expect("distinct names on a non-folding filesystem");
            assert!(listing(&parent).iter().any(|name| name == mvm_name));
        }
    }

    /// The reported case: `etc/Mvm/` and no `etc/mvm/`. On a folding host the
    /// sealed trust policy would have landed in the image's directory and the
    /// guest would have had no `/etc/mvm/verb-trust.json` at all.
    #[test]
    fn an_ascii_case_alias_of_an_injected_directory_is_refused() {
        injection_refuses_the_alias("etc", "Mvm", "mvm", "etc/Mvm/verb-trust.json");
    }

    /// Folding is not only ASCII case: U+017F LATIN SMALL LETTER LONG S folds
    /// to `s`.
    #[test]
    fn a_non_ascii_fold_alias_of_an_account_database_is_refused() {
        injection_refuses_the_alias("etc", "pa\u{17f}swd", "passwd", "etc/pa\u{17f}swd");
    }

    /// A parent directory aliases just as well: `Etc/` receives every file
    /// mvm writes under `/etc`.
    #[test]
    fn a_case_alias_of_a_parent_directory_is_refused() {
        injection_refuses_the_alias("", "Etc", "etc", "Etc/hosts");
    }

    /// The comparison itself, independent of what the host filesystem folds:
    /// only a byte-identical name counts as listed.
    #[test]
    fn lists_exactly_is_byte_equality() {
        let listed = |names: &[&str], want: &str| {
            lists_exactly(
                names.iter().map(std::ffi::OsString::from),
                std::ffi::OsStr::new(want),
            )
        };
        assert!(listed(&["passwd", "group"], "passwd"));
        assert!(!listed(&["Mvm"], "mvm"));
        assert!(!listed(&["Etc"], "etc"));
        assert!(!listed(&["pa\u{17f}swd"], "passwd"));
        // NFD and NFC spellings of the same name are different bytes.
        assert!(!listed(&["cafe\u{301}"], "caf\u{e9}"));
        assert!(!listed(&[], "passwd"));
    }

    /// The check the refusal makes, on a host tree: a component that resolves
    /// only by folding is reported, one listed exactly is not.
    #[test]
    fn first_shaped_component_reports_an_alias_only_when_the_host_folds() {
        let shaped = shaped_root();
        std::fs::create_dir_all(shaped.root.join("usr/lib/Mvm")).unwrap();
        let found =
            first_shaped_component(&shaped.root, Path::new("usr/lib/mvm/wrappers")).unwrap();
        if folds(&shaped.root.join("usr/lib"), "Probe", "probe") {
            assert_eq!(found, Some((PathBuf::from("usr/lib/mvm"), IS_AN_ALIAS)));
        } else {
            assert_eq!(found, None);
        }
        assert_eq!(
            first_shaped_component(&shaped.root, Path::new("usr/lib")).unwrap(),
            None
        );
    }

    /// A guest binary the image shipped is stripped; one that cannot be
    /// removed is an error, not a silent skip that leaves the image's copy
    /// shadowing the runtime overlay.
    #[test]
    fn a_guest_binary_the_injection_cannot_strip_is_an_error() {
        let shaped = shaped_root();
        let bin_dir = shaped.root.join("usr/local/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(shaped.root.join(AGENT_DEST), b"image's own agent").unwrap();
        std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let removable = std::fs::write(bin_dir.join("probe"), b"").is_ok();

        let result = inject_mvm_runtime(&shaped.root, &shaped.bins, None, false);

        std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        if removable {
            eprintln!("SKIPPED: this user can write a 0555 directory, so removal cannot fail");
            return;
        }
        let err = result.expect_err("an unremovable image binary must fail the injection");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(shaped.root.join(AGENT_DEST).exists());
    }

    /// A directory where the account database goes cannot be adopted; a FIFO
    /// there would block the read forever.
    #[test]
    fn a_non_regular_file_at_an_injected_destination_is_refused() {
        let shaped = shaped_root();
        std::fs::create_dir_all(shaped.root.join("etc/passwd")).unwrap();

        let err = refusal(&shaped);

        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    fn inode_of(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).unwrap().ino()
    }

    /// A layer can hard-link an image file to `/etc/passwd`. Writing in place
    /// would put the image file on the account database's inode; the
    /// injection writes a new one, and the image file keeps its own bytes.
    #[test]
    fn an_account_database_hard_linked_to_an_image_file_is_given_its_own_inode() {
        let shaped = shaped_root();
        let passwd = shaped.root.join("etc/passwd");
        std::fs::write(&passwd, "root:x:0:0:root:/root:/bin/sh\n").unwrap();
        std::fs::create_dir_all(shaped.root.join("srv")).unwrap();
        let linked = shaped.root.join("srv/accounts");
        std::fs::hard_link(&passwd, &linked).unwrap();

        inject_mvm_runtime(&shaped.root, &shaped.bins, None, false).expect("inject");

        assert_ne!(inode_of(&passwd), inode_of(&linked));
        assert_eq!(
            std::fs::read_to_string(&linked).unwrap(),
            "root:x:0:0:root:/root:/bin/sh\n",
            "the image file is not the account database"
        );
        assert!(
            std::fs::read_to_string(&passwd)
                .unwrap()
                .contains("mvm-worker:x:901:")
        );
    }

    /// Even an image that already names the workload identity, where
    /// provisioning writes nothing, gets a fresh database inode.
    #[test]
    fn an_account_database_provisioning_leaves_alone_is_still_reseated() {
        let shaped = shaped_root();
        let passwd = shaped.root.join("etc/passwd");
        let existing = "root:x:0:0:root:/root:/bin/sh\napp:x:901:901::/app:/bin/sh\n";
        std::fs::write(&passwd, existing).unwrap();
        let linked = shaped.root.join("etc/passwd-link");
        std::fs::hard_link(&passwd, &linked).unwrap();

        inject_mvm_runtime(&shaped.root, &shaped.bins, None, false).expect("inject");

        assert_ne!(inode_of(&passwd), inode_of(&linked));
        assert_eq!(std::fs::read_to_string(&passwd).unwrap(), existing);
    }

    /// A layer's mode and extended attributes on an injected file — a
    /// world-writable `/etc/group`, an attribute the image writer would carry
    /// into the guest — do not survive injection.
    #[test]
    fn an_injected_file_keeps_neither_the_layers_mode_nor_its_xattrs() {
        let shaped = shaped_root();
        let group = shaped.root.join("etc/group");
        std::fs::write(&group, "root:x:0:\n").unwrap();
        std::fs::set_permissions(&group, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::fs::create_dir_all(shaped.root.join("etc/mvm")).unwrap();
        let variant = shaped.root.join("etc/mvm/variant");
        std::fs::write(&variant, b"prod\n").unwrap();
        // Skip the xattr half where the host filesystem cannot hold one.
        let planted = xattr::set(&group, "user.mvm.planted", b"layer").is_ok()
            && xattr::set(&variant, "user.mvm.planted", b"layer").is_ok();
        // Every host this runs on in practice holds user attributes; macOS
        // always does, so the half below is never skipped there.
        #[cfg(target_os = "macos")]
        assert!(planted, "APFS must hold a user extended attribute");
        if !planted {
            eprintln!(
                "SKIPPED the extended-attribute half: this host filesystem refused a user \
                 attribute"
            );
        }

        inject_mvm_runtime(&shaped.root, &shaped.bins, None, false).expect("inject");

        assert_eq!(
            std::fs::metadata(&group).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        if planted {
            for path in [&group, &variant] {
                assert_eq!(
                    xattr::get(path, "user.mvm.planted").unwrap(),
                    None,
                    "{} kept the layer's attribute",
                    path.display()
                );
            }
        }
        assert_eq!(std::fs::read_to_string(&variant).unwrap(), "dev\n");
    }

    fn symlink_node(path: &str) -> mvm_fs::ext4::Node {
        mvm_fs::ext4::Node::Symlink {
            path: path.to_string(),
            target: "/srv/owned-by-the-image".to_string(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }
    }

    /// A deferred node is laid over what the walk found. At an injected path
    /// it would replace the runtime's file with the layer's, so it is refused
    /// — at a claimed file, and anywhere beneath a claimed tree.
    #[test]
    fn a_deferred_layer_node_at_an_injected_path_is_refused() {
        for path in [
            "/etc/passwd",
            "/etc/group",
            "/etc/mvm/anything",
            "/mvm/runtime",
        ] {
            let err = refuse_layer_nodes_at_injected_paths(&[symlink_node(path)])
                .expect_err("a layer must not replace an injected path");
            assert!(err.to_string().contains(path), "{err}");
        }
    }

    #[test]
    fn a_deferred_layer_node_elsewhere_is_admitted() {
        assert!(
            refuse_layer_nodes_at_injected_paths(&[
                symlink_node("/srv/current"),
                // Beneath a mount point, which claims only itself.
                symlink_node("/tmp/cache"),
            ])
            .is_ok()
        );
        assert!(refuse_layer_nodes_at_injected_paths(&[]).is_ok());
    }

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
        for tree in INJECT_TREES {
            let tagged = format!("tree:{tree}");
            assert!(
                shape.windows(tagged.len()).any(|w| w == tagged.as_bytes()),
                "layout digest omits tree {tree}"
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
