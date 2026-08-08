//! Contract for kernel-backed immutable snapshot providers.
//!
//! A reflink or a copied directory is not an immutable publication: a later
//! writer can still change the source inode. The warm-claim fast path therefore
//! depends on this narrower capability rather than on [`super::snapshot_store`]
//! alone. Platform implementations must publish the bytes into a backing store
//! whose read view cannot be modified after sealing, and must materialize only
//! from that read view.
//!
//! This module intentionally contains no platform FFI. The platform adapters
//! belong behind this contract and are enabled only after their live privilege,
//! mount, cleanup, and tamper tests exist. Until then the explicit unsupported
//! implementation keeps warm admission fail-closed.

use std::io;
use std::path::Path;

use crate::clone::CloneStrategy;
use crate::snapshot_store::SnapshotId;

/// A snapshot provider whose sealed read view is immutable to the claim path.
///
/// Implementations must complete all expensive hashing and publication work in
/// [`TrustedSnapshotBackend::seal`]. `materialize` is the hot operation and may
/// not rehash the published bytes; its trust comes from the backend's sealed
/// read view, not from a mutable sidecar or a permission bit.
pub trait TrustedSnapshotBackend: Send + Sync {
    /// Stage source bytes under `id` before the publication is sealed.
    fn stage(&self, id: &SnapshotId, source: &Path) -> io::Result<()>;

    /// Publish the staged bytes into the backend's immutable read view.
    fn seal(&self, id: &SnapshotId) -> io::Result<()>;

    /// Verify that the sealed publication is available and carries the
    /// host-authenticated content manifest expected by the checkpoint. This is
    /// a lightweight claim-time proof; it must not hash the payload.
    fn validate(
        &self,
        id: &SnapshotId,
        manifest_digest: &str,
        trusted_signer: &[u8; 32],
    ) -> io::Result<()>;

    /// Materialize the sealed bytes at `dst` without claim-time hashing.
    fn materialize(&self, id: &SnapshotId, dst: &Path) -> io::Result<CloneStrategy>;

    /// Reclaim a sealed publication after no leases can reference it.
    fn remove(&self, id: &SnapshotId) -> io::Result<()>;

    /// Stable backend name for capability and refusal telemetry.
    fn name(&self) -> &'static str;
}

/// Explicit fail-closed backend used when the host has no validated immutable
/// snapshot provider. It performs no filesystem mutation.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedTrustedSnapshotBackend;

impl UnsupportedTrustedSnapshotBackend {
    fn unsupported(operation: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("trusted snapshot backend is unavailable for {operation}"),
        )
    }
}

impl TrustedSnapshotBackend for UnsupportedTrustedSnapshotBackend {
    fn stage(&self, _id: &SnapshotId, _source: &Path) -> io::Result<()> {
        Err(Self::unsupported("stage"))
    }

    fn seal(&self, _id: &SnapshotId) -> io::Result<()> {
        Err(Self::unsupported("seal"))
    }

    fn validate(
        &self,
        _id: &SnapshotId,
        _manifest_digest: &str,
        _trusted_signer: &[u8; 32],
    ) -> io::Result<()> {
        Err(Self::unsupported("validate"))
    }

    fn materialize(&self, _id: &SnapshotId, _dst: &Path) -> io::Result<CloneStrategy> {
        Err(Self::unsupported("materialize"))
    }

    fn remove(&self, _id: &SnapshotId) -> io::Result<()> {
        Err(Self::unsupported("remove"))
    }

    fn name(&self) -> &'static str {
        "unsupported"
    }
}

/// Construct the platform immutable backend when it has been explicitly
/// enabled and compiled for a supported host.
pub fn platform_backend(root: impl AsRef<Path>) -> io::Result<Box<dyn TrustedSnapshotBackend>> {
    #[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
    {
        if let Some(socket) =
            std::env::var_os("MVM_APFS_SNAPSHOT_HELPER_SOCKET").filter(|socket| !socket.is_empty())
        {
            return Ok(Box::new(apfs::ApfsTrustedSnapshotHelperBackend::new(
                root, socket,
            )?));
        }
        Ok(Box::new(apfs::ApfsTrustedSnapshotBackend::new(root)?))
    }
    #[cfg(not(all(target_os = "macos", feature = "trusted-apfs")))]
    {
        let _ = root;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no validated immutable snapshot backend is enabled",
        ))
    }
}

/// Run the privileged APFS snapshot helper.
///
/// The helper is intentionally separate from the unprivileged client. It
/// authenticates the peer UID, requires effective UID 0, and restricts every
/// request to `allowed_root` before invoking an APFS operation.
#[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
pub fn serve_apfs_snapshot_helper(
    socket: impl AsRef<Path>,
    allowed_root: impl AsRef<Path>,
    allowed_uid: u32,
) -> io::Result<()> {
    apfs::serve_helper(socket.as_ref(), allowed_root.as_ref(), allowed_uid)
}

/// The helper is unavailable on hosts without the opt-in Apple provider.
#[cfg(not(all(target_os = "macos", feature = "trusted-apfs")))]
pub fn serve_apfs_snapshot_helper(
    _socket: impl AsRef<Path>,
    _allowed_root: impl AsRef<Path>,
    _allowed_uid: u32,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "APFS snapshot helper is only available on macOS with trusted-apfs",
    ))
}

#[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
mod apfs {
    #![allow(unsafe_code)]

    use super::{CloneStrategy, Path, SnapshotId, TrustedSnapshotBackend, io};
    use crate::clone::reflink_or_copy_dir;
    use crate::snapshot_store::{FsSnapshotStore, SnapshotStore};
    use serde::{Deserialize, Serialize};
    use std::ffi::CString;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const MNT_READ_ONLY: u32 = 0x0000_0001;
    const MNT_NOEXEC: u32 = 0x0000_0004;
    const MNT_NOSUID: u32 = 0x0000_0008;
    const MNT_NODEV: u32 = 0x0000_0010;
    const MNT_DONTBROWSE: u32 = 0x0010_0000;
    const MNT_NOFOLLOW: u32 = 0x0800_0000;
    const UNMOUNT_FORCE: libc::c_int = 0x0000_0001;
    const MOUNT_FLAGS: u32 =
        MNT_READ_ONLY | MNT_NOEXEC | MNT_NOSUID | MNT_NODEV | MNT_DONTBROWSE | MNT_NOFOLLOW;
    const MAX_FRAME: usize = 64 * 1024;

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(tag = "op", deny_unknown_fields)]
    enum HelperRequest {
        Seal {
            snapshot_root: PathBuf,
            id: String,
        },
        Validate {
            snapshot_root: PathBuf,
            id: String,
            manifest_digest: String,
            trusted_signer: [u8; 32],
        },
        Materialize {
            snapshot_root: PathBuf,
            id: String,
            destination: PathBuf,
        },
        Remove {
            snapshot_root: PathBuf,
            id: String,
        },
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct HelperResponse {
        ok: bool,
        strategy: Option<String>,
        error: Option<String>,
        error_kind: Option<String>,
    }

    /// Serve one-request-per-connection APFS operations until the process is
    /// terminated by its service manager.
    pub fn serve_helper(socket: &Path, allowed_root: &Path, allowed_uid: u32) -> io::Result<()> {
        // SAFETY: geteuid has no pointer arguments and cannot invalidate Rust
        // references or memory.
        if unsafe { libc::geteuid() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "APFS snapshot helper must run as root",
            ));
        }
        let allowed_root = allowed_root.canonicalize()?;
        if !allowed_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APFS helper allow-root is not a directory",
            ));
        }
        let parent = socket.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APFS helper socket has no parent",
            )
        })?;
        if !parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "APFS helper socket parent does not exist",
            ));
        }
        if socket.exists() {
            let metadata = fs::symlink_metadata(socket)?;
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "APFS helper socket path is not a socket",
                ));
            }
            fs::remove_file(socket)?;
        }
        let listener = UnixListener::bind(socket)?;
        set_socket_owner(socket, allowed_uid)?;

        for connection in listener.incoming() {
            let mut stream = connection?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            let response = match peer_uid(&stream) {
                Ok(uid) if uid == allowed_uid => match read_request(&mut stream) {
                    Ok(request) => match process_request(request, &allowed_root) {
                        Ok(response) => response,
                        Err(error) => error_response(error),
                    },
                    Err(error) => error_response(error),
                },
                Ok(_) => error_response(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "APFS helper peer UID is not authorized",
                )),
                Err(error) => error_response(error),
            };
            write_response(&mut stream, &response)?;
        }
        Ok(())
    }

    fn process_request(request: HelperRequest, allowed_root: &Path) -> io::Result<HelperResponse> {
        match request {
            HelperRequest::Seal { snapshot_root, id } => {
                let root = authorized_snapshot_root(&snapshot_root, allowed_root)?;
                let id = checked_snapshot_id(&id)?;
                let backend = ApfsTrustedSnapshotBackend::new(root)?;
                backend.seal(&id)?;
                Ok(ok_response(None))
            }
            HelperRequest::Validate {
                snapshot_root,
                id,
                manifest_digest,
                trusted_signer,
            } => {
                let root = authorized_snapshot_root(&snapshot_root, allowed_root)?;
                let id = checked_snapshot_id(&id)?;
                let backend = ApfsTrustedSnapshotBackend::new(root)?;
                backend.validate(&id, &manifest_digest, &trusted_signer)?;
                Ok(ok_response(None))
            }
            HelperRequest::Materialize {
                snapshot_root,
                id,
                destination,
            } => {
                let root = authorized_snapshot_root(&snapshot_root, allowed_root)?;
                let destination = authorized_destination(&destination, allowed_root)?;
                let id = checked_snapshot_id(&id)?;
                let backend = ApfsTrustedSnapshotBackend::new(root)?;
                let strategy = backend.materialize(&id, &destination)?;
                let strategy = match strategy {
                    CloneStrategy::Reflink => "reflink",
                    CloneStrategy::Copied => "copied",
                };
                Ok(ok_response(Some(strategy.to_owned())))
            }
            HelperRequest::Remove { snapshot_root, id } => {
                let root = authorized_snapshot_root(&snapshot_root, allowed_root)?;
                let id = checked_snapshot_id(&id)?;
                let backend = ApfsTrustedSnapshotBackend::new(root)?;
                backend.remove(&id)?;
                Ok(ok_response(None))
            }
        }
    }

    fn authorized_snapshot_root(path: &Path, allowed_root: &Path) -> io::Result<PathBuf> {
        let path = path.canonicalize()?;
        ensure_below(&path, allowed_root)?;
        if !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APFS snapshot root is not a directory",
            ));
        }
        Ok(path)
    }

    fn authorized_destination(path: &Path, allowed_root: &Path) -> io::Result<PathBuf> {
        let resolved = if path.exists() {
            path.canonicalize()?
        } else {
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "materialize destination has no parent",
                )
            })?;
            parent.canonicalize()?.join(path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "materialize destination has no name",
                )
            })?)
        };
        ensure_below(resolved.parent().unwrap_or(&resolved), allowed_root)?;
        Ok(resolved)
    }

    fn ensure_below(path: &Path, root: &Path) -> io::Result<()> {
        if path.strip_prefix(root).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "APFS helper path is outside its configured allow-root",
            ));
        }
        Ok(())
    }

    fn checked_snapshot_id(id: &str) -> io::Result<SnapshotId> {
        ensure_id_is_safe(id)?;
        Ok(SnapshotId::new(id))
    }

    fn read_request(stream: &mut UnixStream) -> io::Result<HelperRequest> {
        let body = read_frame(stream)?;
        serde_json::from_slice(&body).map_err(invalid_data)
    }

    fn write_response(stream: &mut UnixStream, response: &HelperResponse) -> io::Result<()> {
        let body = serde_json::to_vec(response).map_err(invalid_data)?;
        write_frame(stream, &body)
    }

    fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
        let mut length_bytes = [0; 4];
        stream.read_exact(&mut length_bytes)?;
        let length = usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid helper frame length")
        })?;
        if length > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "helper frame exceeds limit",
            ));
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        Ok(body)
    }

    fn write_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
        let length = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "helper frame too large"))?;
        stream.write_all(&length.to_be_bytes())?;
        stream.write_all(body)
    }

    fn ok_response(strategy: Option<String>) -> HelperResponse {
        HelperResponse {
            ok: true,
            strategy,
            error: None,
            error_kind: None,
        }
    }

    fn error_response(error: io::Error) -> HelperResponse {
        HelperResponse {
            ok: false,
            strategy: None,
            error: Some(error.to_string()),
            error_kind: Some(
                match error.kind() {
                    io::ErrorKind::Unsupported => "unsupported",
                    io::ErrorKind::PermissionDenied => "permission-denied",
                    _ => "io",
                }
                .to_owned(),
            ),
        }
    }

    fn invalid_data(error: impl std::fmt::Display) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }

    fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: both pointers refer to writable stack values and the socket
        // descriptor remains valid for the duration of the libc call.
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }

    fn set_socket_owner(path: &Path, uid: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        // SAFETY: the path is the socket just created by this process and the
        // UID was supplied by the service manager's explicit configuration.
        let rc = unsafe { libc::chown(c_path(path)?.as_ptr(), uid, libc::gid_t::MAX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    static MOUNT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" {
        fn fs_snapshot_create(fd: RawFd, name: *const libc::c_char, flags: u32) -> libc::c_int;
        fn fs_snapshot_mount(
            fd: RawFd,
            name: *const libc::c_char,
            mountpoint: *const libc::c_char,
            flags: u32,
        ) -> libc::c_int;
        fn fs_snapshot_delete(fd: RawFd, name: *const libc::c_char, flags: u32) -> libc::c_int;
        fn unmount(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int;
    }

    /// Apple APFS-backed trusted snapshot provider.
    pub struct ApfsTrustedSnapshotBackend {
        root: PathBuf,
        staging: FsSnapshotStore,
    }

    /// Unprivileged client for the authenticated APFS helper boundary.
    pub struct ApfsTrustedSnapshotHelperBackend {
        root: PathBuf,
        staging: FsSnapshotStore,
        socket: PathBuf,
    }

    impl ApfsTrustedSnapshotHelperBackend {
        pub(super) fn new(root: impl AsRef<Path>, socket: impl Into<PathBuf>) -> io::Result<Self> {
            let root = root.as_ref().canonicalize()?;
            let staging = FsSnapshotStore::new(&root)?;
            Ok(Self {
                root,
                staging,
                socket: socket.into(),
            })
        }

        fn request(&self, request: &HelperRequest) -> io::Result<HelperResponse> {
            let mut stream = UnixStream::connect(&self.socket)?;
            if peer_uid(&stream)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "APFS helper server is not root",
                ));
            }
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            let body = serde_json::to_vec(request).map_err(invalid_data)?;
            write_frame(&mut stream, &body)?;
            let response = read_frame(&mut stream)?;
            serde_json::from_slice(&response).map_err(invalid_data)
        }

        fn check_response(response: HelperResponse) -> io::Result<Option<String>> {
            if response.ok {
                return Ok(response.strategy);
            }
            let kind = match response.error_kind.as_deref() {
                Some("unsupported") => io::ErrorKind::Unsupported,
                Some("permission-denied") => io::ErrorKind::PermissionDenied,
                _ => io::ErrorKind::Other,
            };
            Err(io::Error::new(
                kind,
                response
                    .error
                    .unwrap_or_else(|| "APFS helper rejected request".to_owned()),
            ))
        }
    }

    impl TrustedSnapshotBackend for ApfsTrustedSnapshotHelperBackend {
        fn stage(&self, id: &SnapshotId, source: &Path) -> io::Result<()> {
            self.staging.create(id, source)
        }

        fn seal(&self, id: &SnapshotId) -> io::Result<()> {
            let request = HelperRequest::Seal {
                snapshot_root: self.root.clone(),
                id: id.id().to_owned(),
            };
            Self::check_response(self.request(&request)?).map(|_| ())
        }

        fn validate(
            &self,
            id: &SnapshotId,
            manifest_digest: &str,
            trusted_signer: &[u8; 32],
        ) -> io::Result<()> {
            let request = HelperRequest::Validate {
                snapshot_root: self.root.clone(),
                id: id.id().to_owned(),
                manifest_digest: manifest_digest.to_owned(),
                trusted_signer: *trusted_signer,
            };
            Self::check_response(self.request(&request)?).map(|_| ())
        }

        fn materialize(&self, id: &SnapshotId, destination: &Path) -> io::Result<CloneStrategy> {
            let request = HelperRequest::Materialize {
                snapshot_root: self.root.clone(),
                id: id.id().to_owned(),
                destination: destination.to_owned(),
            };
            let strategy = Self::check_response(self.request(&request)?)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "APFS helper omitted clone strategy",
                )
            })?;
            match strategy.as_str() {
                "reflink" => Ok(CloneStrategy::Reflink),
                "copied" => Ok(CloneStrategy::Copied),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "APFS helper returned an unknown clone strategy",
                )),
            }
        }

        fn remove(&self, id: &SnapshotId) -> io::Result<()> {
            let request = HelperRequest::Remove {
                snapshot_root: self.root.clone(),
                id: id.id().to_owned(),
            };
            Self::check_response(self.request(&request)?).map(|_| ())
        }

        fn name(&self) -> &'static str {
            "apfs-helper"
        }
    }

    impl ApfsTrustedSnapshotBackend {
        /// Open an APFS provider rooted on the volume containing root.
        pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
            fs::create_dir_all(root.as_ref())?;
            let root = root.as_ref().canonicalize()?;
            let staging = FsSnapshotStore::new(&root)?;
            Ok(Self { root, staging })
        }

        fn snapshot_name(id: &SnapshotId) -> io::Result<CString> {
            ensure_id_is_safe(id.id())?;
            CString::new(format!("mvm-{}", id.id())).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "snapshot id contains NUL")
            })
        }

        fn volume_root(&self) -> io::Result<PathBuf> {
            volume_mount_point(&self.root)
        }
    }

    impl TrustedSnapshotBackend for ApfsTrustedSnapshotBackend {
        fn stage(&self, id: &SnapshotId, source: &Path) -> io::Result<()> {
            self.staging.create(id, source)
        }

        fn seal(&self, id: &SnapshotId) -> io::Result<()> {
            let staged = self.staging.root().join(id.id());
            let directory = fs::File::open(&staged)?;
            directory.sync_all()?;
            let volume_root = self.volume_root()?;
            let volume = fs::File::open(volume_root)?;
            let name = Self::snapshot_name(id)?;
            // SAFETY: the descriptor and NUL-terminated name remain valid for
            // the duration of the kernel call.
            let rc = unsafe { fs_snapshot_create(volume.as_raw_fd(), name.as_ptr(), 0) };
            if rc != 0 {
                return Err(platform_error("seal", io::Error::last_os_error()));
            }
            // The live staging tree is not the trusted read view. Remove it so
            // later claims cannot accidentally use a mutable copy.
            fs::remove_dir_all(staged)
        }

        fn validate(
            &self,
            id: &SnapshotId,
            manifest_digest: &str,
            trusted_signer: &[u8; 32],
        ) -> io::Result<()> {
            let volume_root = self.volume_root()?;
            let volume = fs::File::open(&volume_root)?;
            let relative_root = self.root.strip_prefix(&volume_root).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snapshot root is not below its volume mount point",
                )
            })?;
            let name = Self::snapshot_name(id)?;
            let sequence = MOUNT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let mountpoint = self.root.join(".mvm-trusted-mounts").join(format!(
                "validate-{}-{}-{}",
                id.id(),
                std::process::id(),
                sequence
            ));
            fs::create_dir_all(&mountpoint)?;
            let mountpoint_c = c_path(&mountpoint)?;
            // SAFETY: the descriptor and C strings remain valid for the
            // duration of the kernel call; the mountpoint was created above.
            let rc = unsafe {
                fs_snapshot_mount(
                    volume.as_raw_fd(),
                    name.as_ptr(),
                    mountpoint_c.as_ptr(),
                    MOUNT_FLAGS,
                )
            };
            if rc != 0 {
                let error = platform_error("validate", io::Error::last_os_error());
                let _ = fs::remove_dir_all(&mountpoint);
                return Err(error);
            }
            let content = mountpoint.join(relative_root).join(id.id()).join("content");
            let verification = verify_manifest(&content, manifest_digest, trusted_signer);
            let unmount_result = unmount_path(&mountpoint);
            let cleanup_result = fs::remove_dir(&mountpoint);
            verification.and(unmount_result).and(cleanup_result)
        }

        fn materialize(&self, id: &SnapshotId, destination: &Path) -> io::Result<CloneStrategy> {
            let volume_root = self.volume_root()?;
            let volume = fs::File::open(&volume_root)?;
            let name = Self::snapshot_name(id)?;
            let sequence = MOUNT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let mountpoint = self.root.join(".mvm-trusted-mounts").join(format!(
                "{}-{}-{}",
                id.id(),
                std::process::id(),
                sequence
            ));
            fs::create_dir_all(&mountpoint)?;
            let mountpoint_c = c_path(&mountpoint)?;
            // SAFETY: the descriptor and C strings remain valid for the
            // duration of the kernel call; the mountpoint was created above.
            let rc = unsafe {
                fs_snapshot_mount(
                    volume.as_raw_fd(),
                    name.as_ptr(),
                    mountpoint_c.as_ptr(),
                    MOUNT_FLAGS,
                )
            };
            if rc != 0 {
                let error = platform_error("mount", io::Error::last_os_error());
                let _ = fs::remove_dir_all(&mountpoint);
                return Err(error);
            }

            let result = (|| {
                let relative_root = self.root.strip_prefix(&volume_root).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "snapshot root is not below its volume mount point",
                    )
                })?;
                let source = mountpoint.join(relative_root).join(id.id()).join("content");
                reflink_or_copy_dir(&source, destination)
            })();
            let unmount_result = unmount_path(&mountpoint);
            let cleanup_result = fs::remove_dir(&mountpoint);
            result.and_then(|strategy| {
                unmount_result?;
                cleanup_result?;
                Ok(strategy)
            })
        }

        fn remove(&self, id: &SnapshotId) -> io::Result<()> {
            let volume_root = self.volume_root()?;
            let volume = fs::File::open(volume_root)?;
            let name = Self::snapshot_name(id)?;
            // SAFETY: the descriptor and NUL-terminated name remain valid for
            // the duration of the kernel call.
            let rc = unsafe { fs_snapshot_delete(volume.as_raw_fd(), name.as_ptr(), 0) };
            if rc != 0 {
                return Err(platform_error("remove", io::Error::last_os_error()));
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "apfs"
        }
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    fn ensure_id_is_safe(id: &str) -> io::Result<()> {
        if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot id contains an invalid path component",
            ));
        }
        Ok(())
    }

    fn verify_manifest(
        content: &Path,
        expected_digest: &str,
        trusted_signer: &[u8; 32],
    ) -> io::Result<()> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ManifestSignature {
            manifest_digest: String,
            signature: String,
            pubkey: String,
        }

        let raw = fs::read(content.join("checkpoint-manifest.sig"))?;
        let sidecar: ManifestSignature = serde_json::from_slice(&raw).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("parse manifest signature: {error}"),
            )
        })?;
        if sidecar.manifest_digest != expected_digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trusted snapshot manifest digest does not match checkpoint",
            ));
        }
        let pubkey = hex::decode(sidecar.pubkey)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if pubkey.as_slice() != trusted_signer {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted snapshot manifest signer is not the host signer",
            ));
        }
        let signer = ed25519_dalek::VerifyingKey::from_bytes(trusted_signer).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decode manifest signer: {error}"),
            )
        })?;
        let signature_bytes = hex::decode(sidecar.signature)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        let signature =
            ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decode manifest signature: {error}"),
                )
            })?;
        let mut message = b"mvm.checkpoint.manifest.v1\0".to_vec();
        message.extend_from_slice(expected_digest.as_bytes());
        ed25519_dalek::Verifier::verify(&signer, &message, &signature).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "trusted snapshot manifest signature is invalid",
            )
        })
    }

    fn volume_mount_point(path: &Path) -> io::Result<PathBuf> {
        let path_c = c_path(path)?;
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: stats points to writable storage and the path pointer is
        // valid for the duration of the syscall.
        let rc = unsafe { libc::statfs(path_c.as_ptr(), stats.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: statfs initialized the structure on success.
        let stats = unsafe { stats.assume_init() };
        let end = stats
            .f_mntonname
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(stats.f_mntonname.len());
        let bytes = stats.f_mntonname[..end]
            .iter()
            .map(|&byte| u8::try_from(byte).unwrap_or_default())
            .collect::<Vec<_>>();
        PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)).canonicalize()
    }

    fn unmount_path(path: &Path) -> io::Result<()> {
        let path_c = c_path(path)?;
        // SAFETY: the path is the exact mountpoint created by this module.
        let rc = unsafe { unmount(path_c.as_ptr(), UNMOUNT_FORCE) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn platform_error(operation: &str, error: io::Error) -> io::Error {
        match error.raw_os_error() {
            Some(libc::EPERM | libc::EACCES | libc::ENOTSUP | libc::EOPNOTSUPP) => io::Error::new(
                io::ErrorKind::Unsupported,
                format!("APFS {operation} is unavailable: {error}"),
            ),
            _ => error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_fails_closed_without_creating_paths() {
        let backend = UnsupportedTrustedSnapshotBackend;
        let id = SnapshotId::new("checkpoint-1");
        let source = Path::new("/does-not-exist/source");
        let destination = Path::new("/does-not-exist/destination");

        for result in [
            backend.stage(&id, source).map(|_| CloneStrategy::Copied),
            backend.seal(&id).map(|_| CloneStrategy::Copied),
            backend
                .validate(&id, "sha256:missing", &[0; 32])
                .map(|_| CloneStrategy::Copied),
            backend.materialize(&id, destination),
            backend.remove(&id).map(|_| CloneStrategy::Copied),
        ] {
            assert!(matches!(
                result,
                Err(error) if error.kind() == io::ErrorKind::Unsupported
            ));
        }
        assert_eq!(backend.name(), "unsupported");
    }

    #[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
    #[test]
    fn opt_in_platform_backend_constructs_without_mounting() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = platform_backend(tmp.path()).unwrap();
        assert_eq!(backend.name(), "apfs");
    }

    #[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
    #[test]
    #[ignore = "requires explicit APFS snapshot privilege on the Apple host"]
    fn apfs_live_publish_mutate_materialize_and_remove_witness() {
        if std::env::var("MVM_TRUSTED_APFS_LIVE").as_deref() != Ok("1") {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let store_root = tmp.path().join("store");
        let destination = tmp.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("memory.bin"), vec![0x5a; 1024 * 1024]).unwrap();

        let backend = platform_backend(&store_root).unwrap();
        let id = SnapshotId::new("live-apfs-witness");
        backend.stage(&id, &source).unwrap();
        match backend.seal(&id) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Unsupported => return,
            Err(error) => panic!("unexpected APFS seal failure: {error}"),
        }
        assert!(!store_root.join(id.id()).exists());

        std::fs::write(source.join("memory.bin"), b"mutated-source").unwrap();
        backend.materialize(&id, &destination).unwrap();
        assert_eq!(
            std::fs::metadata(destination.join("memory.bin"))
                .unwrap()
                .len(),
            1024 * 1024
        );
        backend.remove(&id).unwrap();
    }
}
