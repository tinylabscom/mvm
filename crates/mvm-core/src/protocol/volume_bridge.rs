//! Volume-bridge wire protocol: guest FUSE server ↔ host storage backend.
//!
//! Firecracker has no virtio-fs, so distributed volumes (S3 / NFS / FUSE
//! host-side backends) reach the guest through a FUSE-over-vsock bridge:
//! the guest runs a FUSE server (fuser) that proxies filesystem ops over
//! vsock to a host-side backend. This module is the wire contract both
//! sides code against.
//!
//! **Direction.** This is the *reverse* of the host→guest FS RPC in
//! `mvm-agentd::fs_rpc`: here the **guest originates** requests
//! ([`VolumeBridgeRequest`]) and the **host answers**
//! ([`VolumeBridgeResponse`]).
//!
//! # Provisional contract
//!
//! This contract is **provisional pending the Phase 0 latency spike**
//! (mvmd plan 59, issue tinylabscom/mvmd#184). In particular the payload
//! encoding (JSON header + raw trailer, below) may change based on the
//! spike's findings. Freeze fixtures against
//! [`VOLUME_BRIDGE_PROTOCOL_VERSION`] and expect a bump before GA.
//!
//! # Node identity
//!
//! Files and directories are identified by a `(node, generation)` pair
//! ([`NodeRef`]), mirroring FUSE inode semantics: the kernel addresses
//! inodes by a `u64` node id, and node ids may be **reused** after the
//! kernel forgets an inode. The `generation` counter disambiguates two
//! lifetimes of the same node id — a backend must never answer a request
//! carrying a stale generation as if it addressed the current inode
//! (respond with [`VolumeBridgeErrorKind::StaleNode`] instead). Node id
//! `1` is the volume root, per FUSE convention.
//!
//! # Framing
//!
//! Every frame is:
//!
//! ```text
//!   header_len:  u32 BE   (4 bytes; max [`MAX_HEADER_SIZE`])
//!   header:      bytes    (header_len bytes; UTF-8 JSON — one
//!                          VolumeBridgeRequest / VolumeBridgeResponse)
//!   payload:     bytes    (raw; present iff the header declares
//!                          payload_len > 0; max [`MAX_PAYLOAD_SIZE`])
//! ```
//!
//! Bulk data is **never** JSON- or base64-encoded: a
//! [`VolumeBridgeRequest::Write`] declares `payload_len` in its header
//! and ships the bytes as a raw trailer immediately after the JSON;
//! a [`VolumeBridgeResponse::ReadData`] does the same for read results.
//! Every other variant has an implicit `payload_len` of 0 and no
//! trailer. The receiver learns the trailer length from the parsed
//! header ([`VolumeBridgeRequest::payload_len`] /
//! [`VolumeBridgeResponse::payload_len`]), so framing is
//! self-describing without a fixed binary header.
//!
//! Sync [`encode_request`]/[`decode_request`] (and response twins) are
//! always available; async tokio helpers ([`read_request`],
//! [`write_request`], [`read_response`], [`write_response`]) are gated
//! behind the `hostd-transport` feature, mirroring the hostd IPC
//! transport in `protocol.rs`, so the default `mvm-core` build stays
//! runtime-free.
//!
//! # Serde shape
//!
//! Both enums are internally tagged (`"type"`) with snake_case
//! variants. Note: serde does not support `deny_unknown_fields` on
//! internally tagged enums, so — unlike the externally tagged
//! host↔guest vsock types — unknown fields inside a variant are
//! ignored rather than rejected. Revisit alongside the Phase 0
//! encoding decision if strictness is required.

// `anyhow` is used by both the sync codecs and the gated async helpers.
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Wire-protocol version for the volume bridge (guest FUSE server ↔
/// host storage backend).
///
/// **Provisional** — see the module docs: the Phase 0 latency spike
/// (mvmd plan 59, tinylabscom/mvmd#184) may change the payload
/// encoding, which would bump this. Bump policy otherwise follows
/// [`super::PROTOCOL_VERSION`]: any change a peer at the previous
/// version can't parse or safely ignore requires a bump; new
/// `#[serde(default)]` fields do not.
pub const VOLUME_BRIDGE_PROTOCOL_VERSION: u32 = 1;

/// Maximum size of the JSON header of one frame (64 KiB). Headers
/// carry only op metadata and bounded names — never bulk data — so
/// this is generous.
pub const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Absolute ceiling on one frame's raw payload trailer (16 MiB).
/// This is the transport-level DoS bound; per-op limits are tighter
/// and negotiated via [`VolumeBridgeCaps`].
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

// ============================================================================
// Node identity
// ============================================================================

/// FUSE-style node identity: `u64` node id + `u64` generation.
///
/// FUSE addresses inodes by node id, and ids may be reused once the
/// kernel forgets an inode; the generation counter distinguishes the
/// two lifetimes so a reused id can never alias a stale handle. Node
/// id `1` is the volume root (FUSE convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRef {
    /// FUSE node id (`1` = volume root).
    pub node: u64,
    /// Lifetime disambiguator for reused node ids.
    pub generation: u64,
}

impl NodeRef {
    /// The volume root (`node = 1`, FUSE convention) in generation 0.
    pub const ROOT: NodeRef = NodeRef {
        node: 1,
        generation: 0,
    };
}

/// Type of a node, as reported in [`NodeAttr`] and [`DirEntry`].
/// `Other` covers sockets, FIFOs, and devices (which the bridge does
/// not support creating).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// Stat-style attributes of one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttr {
    /// Size in bytes (0 for directories).
    pub size: u64,
    pub kind: NodeKind,
    /// Unix permission bits (e.g. `0o644`) — type bits excluded,
    /// `kind` carries the type.
    pub perm: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Access time, nanoseconds since the Unix epoch.
    pub atime_unix_ns: i64,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_unix_ns: i64,
    /// Status-change time, nanoseconds since the Unix epoch.
    pub ctime_unix_ns: i64,
}

/// The mutable-attribute subset a [`VolumeBridgeRequest::Setattr`] may
/// change. Every field is optional; `None` means "leave unchanged".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetattrChanges {
    /// Truncate/extend to this size.
    #[serde(default)]
    pub size: Option<u64>,
    /// New permission bits (type bits excluded).
    #[serde(default)]
    pub mode: Option<u32>,
    /// New access time, nanoseconds since the Unix epoch.
    #[serde(default)]
    pub atime_unix_ns: Option<i64>,
    /// New modification time, nanoseconds since the Unix epoch.
    #[serde(default)]
    pub mtime_unix_ns: Option<i64>,
}

/// One entry in a [`VolumeBridgeResponse::Dirents`] listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirEntry {
    /// Node id of the entry (generation is only established by a
    /// subsequent `Lookup`, matching FUSE readdir semantics).
    pub node: u64,
    /// Bare entry name (no directory components).
    pub name: String,
    pub kind: NodeKind,
    /// Opaque continuation cookie: pass as `offset` of the next
    /// `Readdir` to resume after this entry.
    pub next_offset: u64,
}

// ============================================================================
// Requests (guest → host)
// ============================================================================

/// One guest-originated filesystem op. Internally tagged
/// (`"type"`, snake_case) — see the module docs for the frame layout.
///
/// Expected response per variant:
///
/// | Request | Success response |
/// |---|---|
/// | `Lookup`, `Create`, `Mkdir` | [`VolumeBridgeResponse::Entry`] |
/// | `Getattr`, `Setattr` | [`VolumeBridgeResponse::Attr`] |
/// | `Readdir` | [`VolumeBridgeResponse::Dirents`] |
/// | `Read` | [`VolumeBridgeResponse::ReadData`] (+ raw trailer) |
/// | `Write` (+ raw trailer) | [`VolumeBridgeResponse::Written`] |
/// | `Unlink`, `Rmdir`, `Rename`, `Flush`, `Fsync`, `Release` | [`VolumeBridgeResponse::Done`] |
/// | `Statfs` | [`VolumeBridgeResponse::Statfs`] |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VolumeBridgeRequest {
    /// Resolve `name` under `parent` to a node + attributes.
    Lookup { parent: NodeRef, name: String },
    /// Fetch attributes of `node`.
    Getattr { node: NodeRef },
    /// Apply the `Some` fields of `changes` to `node`; respond with
    /// the post-change attributes.
    Setattr {
        node: NodeRef,
        changes: SetattrChanges,
    },
    /// List entries of directory `node`, resuming at continuation
    /// cookie `offset` (0 = start), returning at most `max_entries`
    /// (further capped by [`VolumeBridgeCaps::max_readdir_entries`]).
    Readdir {
        node: NodeRef,
        offset: u64,
        max_entries: u32,
    },
    /// Read up to `size` bytes of `node` at byte `offset`. `size` is
    /// capped by [`VolumeBridgeCaps::max_read_bytes`].
    Read {
        node: NodeRef,
        offset: u64,
        size: u32,
    },
    /// Write `payload_len` bytes to `node` at byte `offset`. The
    /// bytes are the frame's raw trailer — never inline JSON.
    /// `payload_len` is capped by [`VolumeBridgeCaps::max_write_bytes`].
    Write {
        node: NodeRef,
        offset: u64,
        payload_len: u32,
    },
    /// Create a regular file `name` under `parent` with permission
    /// bits `mode`; respond with its entry.
    Create {
        parent: NodeRef,
        name: String,
        mode: u32,
    },
    /// Create directory `name` under `parent` with permission bits
    /// `mode`; respond with its entry.
    Mkdir {
        parent: NodeRef,
        name: String,
        mode: u32,
    },
    /// Remove file `name` under `parent`.
    Unlink { parent: NodeRef, name: String },
    /// Remove empty directory `name` under `parent`.
    Rmdir { parent: NodeRef, name: String },
    /// Rename `parent`/`name` to `new_parent`/`new_name`.
    Rename {
        parent: NodeRef,
        name: String,
        new_parent: NodeRef,
        new_name: String,
    },
    /// Flush cached writes of `node` (FUSE flush — once per file
    /// handle close).
    Flush { node: NodeRef },
    /// Durably sync `node`. `datasync = true` syncs data only
    /// (fdatasync semantics).
    Fsync { node: NodeRef, datasync: bool },
    /// Drop the backend's per-open state for `node` (FUSE release).
    Release { node: NodeRef },
    /// Filesystem-level statistics for the volume containing `node`.
    Statfs { node: NodeRef },
}

impl VolumeBridgeRequest {
    /// Length of the raw payload trailer this header declares.
    /// Non-zero only for `Write`.
    pub fn payload_len(&self) -> usize {
        match self {
            VolumeBridgeRequest::Write { payload_len, .. } => *payload_len as usize,
            _ => 0,
        }
    }
}

// ============================================================================
// Responses (host → guest)
// ============================================================================

/// One host answer. Internally tagged (`"type"`, snake_case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VolumeBridgeResponse {
    /// A resolved / created node: identity + attributes
    /// (Lookup / Create / Mkdir).
    Entry { node: NodeRef, attr: NodeAttr },
    /// Attributes only (Getattr / Setattr).
    Attr { attr: NodeAttr },
    /// Directory listing chunk. `end = true` means no further
    /// entries exist past the last returned cookie.
    Dirents { entries: Vec<DirEntry>, end: bool },
    /// Read result: `payload_len` raw bytes follow as the frame's
    /// trailer — never inline JSON. `eof = true` means the read
    /// reached end-of-file (the trailer may be shorter than the
    /// requested size).
    ReadData { payload_len: u32, eof: bool },
    /// Write result: bytes durably accepted by the backend.
    Written { size: u32 },
    /// Success with no payload (Unlink / Rmdir / Rename / Flush /
    /// Fsync / Release).
    Done,
    /// statvfs-style volume statistics.
    Statfs {
        /// Total blocks (`frsize` units).
        blocks: u64,
        /// Free blocks.
        bfree: u64,
        /// Free blocks available to unprivileged callers.
        bavail: u64,
        /// Total inodes.
        files: u64,
        /// Free inodes.
        ffree: u64,
        /// Preferred I/O block size.
        bsize: u32,
        /// Maximum filename length.
        namelen: u32,
        /// Fundamental block size (unit of `blocks`/`bfree`/`bavail`).
        frsize: u32,
    },
    /// Op failed. `kind` is closed so the guest maps to errno
    /// without parsing `message` (see
    /// [`VolumeBridgeErrorKind::errno`]).
    Error {
        kind: VolumeBridgeErrorKind,
        message: String,
    },
}

impl VolumeBridgeResponse {
    /// Length of the raw payload trailer this header declares.
    /// Non-zero only for `ReadData`.
    pub fn payload_len(&self) -> usize {
        match self {
            VolumeBridgeResponse::ReadData { payload_len, .. } => *payload_len as usize,
            _ => 0,
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Class of error in [`VolumeBridgeResponse::Error`]. Closed enum
/// (mirrors `FsErrorKind` in the host→guest FS RPC) so the guest FUSE
/// server can branch / map to errno without parsing message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeBridgeErrorKind {
    /// Node or name doesn't exist.
    NotFound,
    /// Backend policy or filesystem permission refused the op.
    PermissionDenied,
    /// Target name already exists where the op required absence.
    AlreadyExists,
    /// A directory op addressed a non-directory.
    NotADirectory,
    /// A file op addressed a directory.
    IsADirectory,
    /// `Rmdir` on a non-empty directory.
    DirectoryNotEmpty,
    /// The volume (or this attachment) is read-only.
    ReadOnly,
    /// The backend is out of space or quota.
    NoSpace,
    /// A per-op cap ([`VolumeBridgeCaps`]) was exceeded — the guest
    /// should split the op, not retry it as-is.
    CapExceeded,
    /// Malformed request (bad name, bad offset, empty setattr, …).
    InvalidArgument,
    /// Name exceeds the backend's limit.
    NameTooLong,
    /// The `(node, generation)` pair refers to a forgotten inode
    /// lifetime — see the module docs on node identity.
    StaleNode,
    /// The backend does not implement this op.
    Unsupported,
    /// Underlying I/O or backend transport error (see `message`).
    Io,
}

impl VolumeBridgeErrorKind {
    /// Linux errno the guest FUSE server should surface for this
    /// kind (the guest is always Linux). Values are the asm-generic
    /// constants, hardcoded so `mvm-core` needs no libc dependency.
    /// The mapping is deliberately lossy in one direction only:
    /// distinct kinds may share an errno, but every kind has one.
    pub fn errno(self) -> i32 {
        match self {
            VolumeBridgeErrorKind::NotFound => 2,           // ENOENT
            VolumeBridgeErrorKind::PermissionDenied => 13,  // EACCES
            VolumeBridgeErrorKind::AlreadyExists => 17,     // EEXIST
            VolumeBridgeErrorKind::NotADirectory => 20,     // ENOTDIR
            VolumeBridgeErrorKind::IsADirectory => 21,      // EISDIR
            VolumeBridgeErrorKind::DirectoryNotEmpty => 39, // ENOTEMPTY
            VolumeBridgeErrorKind::ReadOnly => 30,          // EROFS
            VolumeBridgeErrorKind::NoSpace => 28,           // ENOSPC
            VolumeBridgeErrorKind::CapExceeded => 7,        // E2BIG
            VolumeBridgeErrorKind::InvalidArgument => 22,   // EINVAL
            VolumeBridgeErrorKind::NameTooLong => 36,       // ENAMETOOLONG
            VolumeBridgeErrorKind::StaleNode => 116,        // ESTALE
            VolumeBridgeErrorKind::Unsupported => 38,       // ENOSYS
            VolumeBridgeErrorKind::Io => 5,                 // EIO
        }
    }
}

// ============================================================================
// Caps
// ============================================================================

/// Per-op limits the host backend enforces (mirrors the `Caps`
/// pattern in `mvm-agentd::fs_rpc`). The host wires
/// [`VolumeBridgeCaps::production`] at boot; tests construct tighter
/// caps to exercise `CapExceeded` branches. A future handshake may
/// ship these to the guest so it sizes ops to fit — hence the serde
/// derives and `#[serde(default)]` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeBridgeCaps {
    /// Max bytes one `Read` may request.
    #[serde(default = "VolumeBridgeCaps::default_max_read_bytes")]
    pub max_read_bytes: u32,
    /// Max bytes one `Write` may carry.
    #[serde(default = "VolumeBridgeCaps::default_max_write_bytes")]
    pub max_write_bytes: u32,
    /// Max entries one `Readdir` returns.
    #[serde(default = "VolumeBridgeCaps::default_max_readdir_entries")]
    pub max_readdir_entries: u32,
}

impl VolumeBridgeCaps {
    const fn default_max_read_bytes() -> u32 {
        1024 * 1024 // 1 MiB — matches the FUSE default max_read/max_write
    }

    const fn default_max_write_bytes() -> u32 {
        1024 * 1024
    }

    const fn default_max_readdir_entries() -> u32 {
        4096
    }

    /// Production limits. Both read and write fit comfortably under
    /// [`MAX_PAYLOAD_SIZE`].
    pub const fn production() -> Self {
        Self {
            max_read_bytes: Self::default_max_read_bytes(),
            max_write_bytes: Self::default_max_write_bytes(),
            max_readdir_entries: Self::default_max_readdir_entries(),
        }
    }
}

impl Default for VolumeBridgeCaps {
    fn default() -> Self {
        Self::production()
    }
}

// ============================================================================
// Framing — sync codecs (always available)
// ============================================================================

/// Serialize `header` + validate + assemble one frame:
/// `[4-byte BE header_len][header JSON][raw payload]`.
fn encode_frame<H: WireHeader>(header: &H, payload: &[u8]) -> Result<Vec<u8>> {
    let declared = header.declared_payload_len();
    if declared != payload.len() {
        bail!(
            "{} declares payload_len {declared} but {} payload bytes were supplied",
            H::KIND,
            payload.len()
        );
    }
    if payload.len() > MAX_PAYLOAD_SIZE {
        bail!(
            "{} payload {} bytes exceeds maximum {MAX_PAYLOAD_SIZE}",
            H::KIND,
            payload.len()
        );
    }
    let header_json =
        serde_json::to_vec(header).with_context(|| format!("Failed to serialize {}", H::KIND))?;
    if header_json.len() > MAX_HEADER_SIZE {
        bail!(
            "{} header {} bytes exceeds maximum {MAX_HEADER_SIZE}",
            H::KIND,
            header_json.len()
        );
    }
    let header_len = u32::try_from(header_json.len())
        .expect("header length fits u32: bounded by MAX_HEADER_SIZE above");
    let mut frame = Vec::with_capacity(4 + header_json.len() + payload.len());
    frame.extend_from_slice(&header_len.to_be_bytes());
    frame.extend_from_slice(&header_json);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Parse one frame out of `buf`. Returns the header, its raw payload
/// trailer, and the number of bytes consumed (so callers can decode
/// back-to-back frames from one buffer).
fn decode_frame<H: WireHeader>(buf: &[u8]) -> Result<(H, Vec<u8>, usize)> {
    if buf.len() < 4 {
        bail!(
            "Frame truncated: {} bytes, need 4-byte length prefix",
            buf.len()
        );
    }
    let header_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if header_len > MAX_HEADER_SIZE {
        bail!("Header size {header_len} exceeds maximum {MAX_HEADER_SIZE}");
    }
    let header_end = 4 + header_len;
    let Some(header_json) = buf.get(4..header_end) else {
        bail!(
            "Frame truncated: header declares {header_len} bytes, only {} available",
            buf.len() - 4
        );
    };
    let header: H = serde_json::from_slice(header_json)
        .with_context(|| format!("Failed to deserialize {}", H::KIND))?;
    let payload_len = header.declared_payload_len();
    if payload_len > MAX_PAYLOAD_SIZE {
        bail!("Payload size {payload_len} exceeds maximum {MAX_PAYLOAD_SIZE}");
    }
    let payload_end = header_end + payload_len;
    let Some(payload) = buf.get(header_end..payload_end) else {
        bail!(
            "Frame truncated: header declares payload_len {payload_len}, only {} available",
            buf.len() - header_end
        );
    };
    Ok((header, payload.to_vec(), payload_end))
}

/// Internal unifier so the request/response codecs share one
/// implementation. Not part of the wire contract.
trait WireHeader: Serialize + DeserializeOwned {
    /// Human-readable type name for error messages.
    const KIND: &'static str;
    /// Raw-trailer length this header declares.
    fn declared_payload_len(&self) -> usize;
}

impl WireHeader for VolumeBridgeRequest {
    const KIND: &'static str = "VolumeBridgeRequest";
    fn declared_payload_len(&self) -> usize {
        self.payload_len()
    }
}

impl WireHeader for VolumeBridgeResponse {
    const KIND: &'static str = "VolumeBridgeResponse";
    fn declared_payload_len(&self) -> usize {
        self.payload_len()
    }
}

/// Encode one request frame. `payload` must match the header's
/// declared `payload_len` (empty for every variant except `Write`).
pub fn encode_request(request: &VolumeBridgeRequest, payload: &[u8]) -> Result<Vec<u8>> {
    encode_frame(request, payload)
}

/// Decode one request frame from a byte slice. Returns the header,
/// its raw payload, and the bytes consumed.
pub fn decode_request(buf: &[u8]) -> Result<(VolumeBridgeRequest, Vec<u8>, usize)> {
    decode_frame(buf)
}

/// Encode one response frame. `payload` must match the header's
/// declared `payload_len` (empty for every variant except `ReadData`).
pub fn encode_response(response: &VolumeBridgeResponse, payload: &[u8]) -> Result<Vec<u8>> {
    encode_frame(response, payload)
}

/// Decode one response frame from a byte slice. Returns the header,
/// its raw payload, and the bytes consumed.
pub fn decode_response(buf: &[u8]) -> Result<(VolumeBridgeResponse, Vec<u8>, usize)> {
    decode_frame(buf)
}

// ============================================================================
// Framing — async tokio helpers (feature: hostd-transport)
//
// Gated like the hostd IPC transport in `protocol.rs` so the default
// `mvm-core` build carries no tokio (xtask check-core-runtime-free).
// ============================================================================

#[cfg(feature = "hostd-transport")]
async fn read_wire_frame<H: WireHeader, R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(H, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .with_context(|| "Failed to read frame header length")?;
    let header_len = u32::from_be_bytes(len_buf) as usize;
    if header_len > MAX_HEADER_SIZE {
        bail!("Header size {header_len} exceeds maximum {MAX_HEADER_SIZE}");
    }
    let mut header_json = vec![0u8; header_len];
    reader
        .read_exact(&mut header_json)
        .await
        .with_context(|| "Failed to read frame header")?;
    let header: H = serde_json::from_slice(&header_json)
        .with_context(|| format!("Failed to deserialize {}", H::KIND))?;
    let payload_len = header.declared_payload_len();
    if payload_len > MAX_PAYLOAD_SIZE {
        bail!("Payload size {payload_len} exceeds maximum {MAX_PAYLOAD_SIZE}");
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .with_context(|| "Failed to read frame payload")?;
    }
    Ok((header, payload))
}

#[cfg(feature = "hostd-transport")]
async fn write_wire_frame<H: WireHeader, W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    header: &H,
    payload: &[u8],
) -> Result<()> {
    // Reuse the sync encoder so header/payload validation exists in
    // exactly one place; one write_all keeps the frame contiguous.
    let frame = encode_frame(header, payload)?;
    writer
        .write_all(&frame)
        .await
        .with_context(|| "Failed to write frame")?;
    writer
        .flush()
        .await
        .with_context(|| "Failed to flush frame")?;
    Ok(())
}

/// Read one framed [`VolumeBridgeRequest`] plus its raw payload
/// (empty for every variant except `Write`).
#[cfg(feature = "hostd-transport")]
pub async fn read_request<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(VolumeBridgeRequest, Vec<u8>)> {
    read_wire_frame(reader).await
}

/// Write one framed [`VolumeBridgeRequest`]. `payload` must match the
/// header's declared `payload_len`.
#[cfg(feature = "hostd-transport")]
pub async fn write_request<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    request: &VolumeBridgeRequest,
    payload: &[u8],
) -> Result<()> {
    write_wire_frame(writer, request, payload).await
}

/// Read one framed [`VolumeBridgeResponse`] plus its raw payload
/// (empty for every variant except `ReadData`).
#[cfg(feature = "hostd-transport")]
pub async fn read_response<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(VolumeBridgeResponse, Vec<u8>)> {
    read_wire_frame(reader).await
}

/// Write one framed [`VolumeBridgeResponse`]. `payload` must match
/// the header's declared `payload_len`.
#[cfg(feature = "hostd-transport")]
pub async fn write_response<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &VolumeBridgeResponse,
    payload: &[u8],
) -> Result<()> {
    write_wire_frame(writer, response, payload).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn attr_fixture() -> NodeAttr {
        NodeAttr {
            size: 4096,
            kind: NodeKind::File,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            atime_unix_ns: 1_700_000_000_000_000_000,
            mtime_unix_ns: 1_700_000_000_000_000_001,
            ctime_unix_ns: 1_700_000_000_000_000_002,
        }
    }

    fn node(n: u64) -> NodeRef {
        NodeRef {
            node: n,
            generation: 7,
        }
    }

    fn all_request_variants() -> Vec<VolumeBridgeRequest> {
        vec![
            VolumeBridgeRequest::Lookup {
                parent: NodeRef::ROOT,
                name: "data.bin".into(),
            },
            VolumeBridgeRequest::Getattr { node: node(2) },
            VolumeBridgeRequest::Setattr {
                node: node(2),
                changes: SetattrChanges {
                    size: Some(0),
                    mode: Some(0o600),
                    atime_unix_ns: None,
                    mtime_unix_ns: Some(1_700_000_000_000_000_000),
                },
            },
            VolumeBridgeRequest::Readdir {
                node: NodeRef::ROOT,
                offset: 0,
                max_entries: 128,
            },
            VolumeBridgeRequest::Read {
                node: node(2),
                offset: 4096,
                size: 65536,
            },
            VolumeBridgeRequest::Write {
                node: node(2),
                offset: 0,
                payload_len: 11,
            },
            VolumeBridgeRequest::Create {
                parent: NodeRef::ROOT,
                name: "new.txt".into(),
                mode: 0o644,
            },
            VolumeBridgeRequest::Mkdir {
                parent: NodeRef::ROOT,
                name: "subdir".into(),
                mode: 0o755,
            },
            VolumeBridgeRequest::Unlink {
                parent: NodeRef::ROOT,
                name: "old.txt".into(),
            },
            VolumeBridgeRequest::Rmdir {
                parent: NodeRef::ROOT,
                name: "empty".into(),
            },
            VolumeBridgeRequest::Rename {
                parent: NodeRef::ROOT,
                name: "a".into(),
                new_parent: node(3),
                new_name: "b".into(),
            },
            VolumeBridgeRequest::Flush { node: node(2) },
            VolumeBridgeRequest::Fsync {
                node: node(2),
                datasync: true,
            },
            VolumeBridgeRequest::Release { node: node(2) },
            VolumeBridgeRequest::Statfs {
                node: NodeRef::ROOT,
            },
        ]
    }

    fn all_response_variants() -> Vec<VolumeBridgeResponse> {
        vec![
            VolumeBridgeResponse::Entry {
                node: node(2),
                attr: attr_fixture(),
            },
            VolumeBridgeResponse::Attr {
                attr: attr_fixture(),
            },
            VolumeBridgeResponse::Dirents {
                entries: vec![DirEntry {
                    node: 2,
                    name: "data.bin".into(),
                    kind: NodeKind::File,
                    next_offset: 1,
                }],
                end: true,
            },
            VolumeBridgeResponse::ReadData {
                payload_len: 5,
                eof: false,
            },
            VolumeBridgeResponse::Written { size: 11 },
            VolumeBridgeResponse::Done,
            VolumeBridgeResponse::Statfs {
                blocks: 1000,
                bfree: 500,
                bavail: 400,
                files: 100,
                ffree: 50,
                bsize: 4096,
                namelen: 255,
                frsize: 4096,
            },
            VolumeBridgeResponse::Error {
                kind: VolumeBridgeErrorKind::NotFound,
                message: "no such node".into(),
            },
        ]
    }

    const ALL_ERROR_KINDS: [VolumeBridgeErrorKind; 14] = [
        VolumeBridgeErrorKind::NotFound,
        VolumeBridgeErrorKind::PermissionDenied,
        VolumeBridgeErrorKind::AlreadyExists,
        VolumeBridgeErrorKind::NotADirectory,
        VolumeBridgeErrorKind::IsADirectory,
        VolumeBridgeErrorKind::DirectoryNotEmpty,
        VolumeBridgeErrorKind::ReadOnly,
        VolumeBridgeErrorKind::NoSpace,
        VolumeBridgeErrorKind::CapExceeded,
        VolumeBridgeErrorKind::InvalidArgument,
        VolumeBridgeErrorKind::NameTooLong,
        VolumeBridgeErrorKind::StaleNode,
        VolumeBridgeErrorKind::Unsupported,
        VolumeBridgeErrorKind::Io,
    ];

    // ---- serde round-trips ----

    #[test]
    fn every_request_variant_roundtrips() {
        let variants = all_request_variants();
        // Guard: keep this fixture list in sync with the enum.
        assert_eq!(variants.len(), 15, "fixture list must cover every variant");
        for req in variants {
            let json = serde_json::to_string(&req).unwrap();
            let parsed: VolumeBridgeRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, req, "roundtrip drift for {json}");
        }
    }

    #[test]
    fn every_response_variant_roundtrips() {
        let variants = all_response_variants();
        assert_eq!(variants.len(), 8, "fixture list must cover every variant");
        for resp in variants {
            let json = serde_json::to_string(&resp).unwrap();
            let parsed: VolumeBridgeResponse = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, resp, "roundtrip drift for {json}");
        }
    }

    #[test]
    fn requests_are_internally_tagged_snake_case() {
        let json = serde_json::to_string(&VolumeBridgeRequest::Getattr { node: node(2) }).unwrap();
        assert_eq!(
            json,
            r#"{"type":"getattr","node":{"node":2,"generation":7}}"#
        );

        let json = serde_json::to_string(&VolumeBridgeRequest::Readdir {
            node: NodeRef::ROOT,
            offset: 0,
            max_entries: 16,
        })
        .unwrap();
        assert!(json.starts_with(r#"{"type":"readdir","#), "got: {json}");
    }

    #[test]
    fn responses_are_internally_tagged_snake_case() {
        let json = serde_json::to_string(&VolumeBridgeResponse::Done).unwrap();
        assert_eq!(json, r#"{"type":"done"}"#);

        let json = serde_json::to_string(&VolumeBridgeResponse::ReadData {
            payload_len: 5,
            eof: true,
        })
        .unwrap();
        assert_eq!(json, r#"{"type":"read_data","payload_len":5,"eof":true}"#);
    }

    #[test]
    fn unknown_variant_is_rejected() {
        let err = serde_json::from_str::<VolumeBridgeRequest>(r#"{"type":"symlink","node":1}"#)
            .unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "expected unknown-variant rejection, got: {err}"
        );
    }

    #[test]
    fn setattr_changes_fields_default_to_none() {
        // Forward-compat: an empty changes object parses with every
        // field unchanged.
        let parsed: SetattrChanges = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, SetattrChanges::default());
    }

    // ---- error enum stability ----

    #[test]
    fn error_kind_wire_strings_are_frozen() {
        let expected = [
            "not_found",
            "permission_denied",
            "already_exists",
            "not_a_directory",
            "is_a_directory",
            "directory_not_empty",
            "read_only",
            "no_space",
            "cap_exceeded",
            "invalid_argument",
            "name_too_long",
            "stale_node",
            "unsupported",
            "io",
        ];
        for (kind, want) in ALL_ERROR_KINDS.iter().zip(expected) {
            let json = serde_json::to_string(kind).unwrap();
            assert_eq!(
                json,
                format!("\"{want}\""),
                "wire string drift for {kind:?}"
            );
            let parsed: VolumeBridgeErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *kind);
        }
    }

    #[test]
    fn error_kind_errno_mapping_is_stable() {
        let expected: [(VolumeBridgeErrorKind, i32); 14] = [
            (VolumeBridgeErrorKind::NotFound, 2),
            (VolumeBridgeErrorKind::PermissionDenied, 13),
            (VolumeBridgeErrorKind::AlreadyExists, 17),
            (VolumeBridgeErrorKind::NotADirectory, 20),
            (VolumeBridgeErrorKind::IsADirectory, 21),
            (VolumeBridgeErrorKind::DirectoryNotEmpty, 39),
            (VolumeBridgeErrorKind::ReadOnly, 30),
            (VolumeBridgeErrorKind::NoSpace, 28),
            (VolumeBridgeErrorKind::CapExceeded, 7),
            (VolumeBridgeErrorKind::InvalidArgument, 22),
            (VolumeBridgeErrorKind::NameTooLong, 36),
            (VolumeBridgeErrorKind::StaleNode, 116),
            (VolumeBridgeErrorKind::Unsupported, 38),
            (VolumeBridgeErrorKind::Io, 5),
        ];
        for (kind, errno) in expected {
            assert_eq!(kind.errno(), errno, "errno drift for {kind:?}");
        }
    }

    // ---- caps ----

    #[test]
    fn caps_default_is_production_and_fits_wire_ceiling() {
        let caps = VolumeBridgeCaps::default();
        assert_eq!(caps, VolumeBridgeCaps::production());
        assert_eq!(caps.max_read_bytes, 1024 * 1024);
        assert_eq!(caps.max_write_bytes, 1024 * 1024);
        assert_eq!(caps.max_readdir_entries, 4096);
        assert!((caps.max_read_bytes as usize) <= MAX_PAYLOAD_SIZE);
        assert!((caps.max_write_bytes as usize) <= MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn caps_deserialize_with_missing_fields() {
        let caps: VolumeBridgeCaps = serde_json::from_str(r#"{"max_read_bytes":512}"#).unwrap();
        assert_eq!(caps.max_read_bytes, 512);
        assert_eq!(
            caps.max_write_bytes,
            VolumeBridgeCaps::production().max_write_bytes
        );
        assert_eq!(
            caps.max_readdir_entries,
            VolumeBridgeCaps::production().max_readdir_entries
        );
    }

    // ---- sync framing ----

    #[test]
    fn write_request_frame_carries_raw_payload_after_json_header() {
        let payload = b"hello world";
        let req = VolumeBridgeRequest::Write {
            node: node(2),
            offset: 0,
            payload_len: payload.len() as u32,
        };
        let frame = encode_request(&req, payload).unwrap();

        // Layout: 4-byte BE header length, then exactly that much
        // JSON, then the raw payload bytes verbatim.
        let header_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        let header_json = &frame[4..4 + header_len];
        assert!(serde_json::from_slice::<VolumeBridgeRequest>(header_json).is_ok());
        // Bulk bytes are the raw trailer — not JSON/base64 inside the header.
        assert!(!header_json.windows(payload.len()).any(|w| w == payload));
        assert_eq!(&frame[4 + header_len..], payload);

        let (decoded, decoded_payload, consumed) = decode_request(&frame).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded_payload, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn read_response_frame_roundtrips_with_raw_payload() {
        let payload = [0u8, 159, 146, 150, 255]; // non-UTF-8 bytes on purpose
        let resp = VolumeBridgeResponse::ReadData {
            payload_len: payload.len() as u32,
            eof: true,
        };
        let frame = encode_response(&resp, &payload).unwrap();
        let (decoded, decoded_payload, consumed) = decode_response(&frame).unwrap();
        assert_eq!(decoded, resp);
        assert_eq!(decoded_payload, payload);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn payloadless_frames_roundtrip() {
        for req in all_request_variants() {
            if req.payload_len() > 0 {
                continue;
            }
            let frame = encode_request(&req, &[]).unwrap();
            let (decoded, payload, consumed) = decode_request(&frame).unwrap();
            assert_eq!(decoded, req);
            assert!(payload.is_empty());
            assert_eq!(consumed, frame.len());
        }
        for resp in all_response_variants() {
            if resp.payload_len() > 0 {
                continue;
            }
            let frame = encode_response(&resp, &[]).unwrap();
            let (decoded, payload, consumed) = decode_response(&frame).unwrap();
            assert_eq!(decoded, resp);
            assert!(payload.is_empty());
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn encode_rejects_payload_length_mismatch() {
        let req = VolumeBridgeRequest::Write {
            node: node(2),
            offset: 0,
            payload_len: 10,
        };
        let err = encode_request(&req, b"short").unwrap_err();
        assert!(
            err.to_string().contains("declares payload_len"),
            "got: {err}"
        );

        // Payload supplied for a payloadless variant is equally a bug.
        let err = encode_request(&VolumeBridgeRequest::Flush { node: node(2) }, b"x").unwrap_err();
        assert!(
            err.to_string().contains("declares payload_len"),
            "got: {err}"
        );
    }

    #[test]
    fn decode_rejects_oversized_header_length() {
        let bogus_len = (MAX_HEADER_SIZE as u32) + 1;
        let mut buf = bogus_len.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 32]);
        let err = decode_request(&buf).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn decode_rejects_oversized_declared_payload() {
        // A header that legitimately parses but declares a payload
        // beyond the wire ceiling must be refused before allocation.
        let header = format!(
            r#"{{"type":"write","node":{{"node":2,"generation":7}},"offset":0,"payload_len":{}}}"#,
            MAX_PAYLOAD_SIZE + 1
        );
        let mut buf = (header.len() as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(header.as_bytes());
        let err = decode_request(&buf).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let payload = b"0123456789";
        let req = VolumeBridgeRequest::Write {
            node: node(2),
            offset: 0,
            payload_len: payload.len() as u32,
        };
        let frame = encode_request(&req, payload).unwrap();
        let err = decode_request(&frame[..frame.len() - 3]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {err}");
    }

    #[test]
    fn decode_consumes_back_to_back_frames() {
        let first = encode_request(&VolumeBridgeRequest::Getattr { node: node(2) }, &[]).unwrap();
        let second = encode_request(
            &VolumeBridgeRequest::Write {
                node: node(2),
                offset: 8,
                payload_len: 3,
            },
            b"abc",
        )
        .unwrap();
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let (_, _, consumed) = decode_request(&stream).unwrap();
        assert_eq!(consumed, first.len());
        let (decoded, payload, consumed2) = decode_request(&stream[consumed..]).unwrap();
        assert_eq!(consumed2, second.len());
        assert_eq!(payload, b"abc");
        assert!(matches!(
            decoded,
            VolumeBridgeRequest::Write { offset: 8, .. }
        ));
    }

    // ---- async framing (feature-gated like the hostd transport) ----

    #[cfg(feature = "hostd-transport")]
    #[tokio::test]
    async fn async_request_roundtrip_with_raw_payload() {
        let payload = b"raw write body \x00\xff";
        let req = VolumeBridgeRequest::Write {
            node: node(2),
            offset: 1024,
            payload_len: payload.len() as u32,
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &req, payload).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let (decoded, decoded_payload) = read_request(&mut cursor).await.unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded_payload, payload);
    }

    #[cfg(feature = "hostd-transport")]
    #[tokio::test]
    async fn async_response_roundtrip_with_and_without_payload() {
        let payload = b"read result bytes";
        let resp = VolumeBridgeResponse::ReadData {
            payload_len: payload.len() as u32,
            eof: false,
        };
        let mut buf = Vec::new();
        write_response(&mut buf, &resp, payload).await.unwrap();
        // A second, payloadless frame on the same stream.
        write_response(&mut buf, &VolumeBridgeResponse::Done, &[])
            .await
            .unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let (first, first_payload) = read_response(&mut cursor).await.unwrap();
        assert_eq!(first, resp);
        assert_eq!(first_payload, payload);
        let (second, second_payload) = read_response(&mut cursor).await.unwrap();
        assert_eq!(second, VolumeBridgeResponse::Done);
        assert!(second_payload.is_empty());
    }

    #[cfg(feature = "hostd-transport")]
    #[tokio::test]
    async fn async_read_rejects_oversized_header() {
        let bogus_len = (MAX_HEADER_SIZE as u32) + 1;
        let mut buf = bogus_len.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 64]);
        let mut cursor = std::io::Cursor::new(buf);
        let err = read_request(&mut cursor).await.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }
}
