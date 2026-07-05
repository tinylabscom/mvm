//! Read-only FUSE server for a virtio-fs **root** device.
//!
//! The in-house VMM serves the unpacked+injected OCI directory to the guest as
//! a virtiofs root (Plan-223 dev tier). virtio-fs carries the **FUSE** protocol
//! over its virtqueues: the guest kernel's fuse client sends `fuse_in_header` +
//! op body, and this server replies with `fuse_out_header` + op body. This
//! module is the protocol server, **decoupled from the virtio-mmio transport**
//! (which hands us request bytes and takes response bytes) so it is unit-testable
//! against a host directory with no VM.
//!
//! Scope: **read-only**. A microVM rootfs is never written through the root fs
//! (writable state goes to a separate tmpfs/volume), so the write opcodes are
//! answered `EROFS`. That keeps the server small and the trust surface minimal.
//!
//! Correctness of the exact wire layout is ultimately witnessed by a live guest
//! mount on the in-house HVF backend; these unit tests pin the server's internal
//! encode/decode + path resolution.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

// ---- FUSE protocol constants (uapi/linux/fuse.h) ---------------------------

const FUSE_KERNEL_VERSION: u32 = 7;
// Minor we advertise. 31 is widely supported and predates the large post-7.36
// init-struct growth, keeping `fuse_init_out` at its classic 64-byte size.
const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

// Opcodes we handle (others → ENOSYS/EROFS).
const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_READLINK: u32 = 5;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_RELEASE: u32 = 18;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FLUSH: u32 = 25;
const FUSE_STATFS: u32 = 17;

// errno (negated in fuse_out_header.error).
const ENOENT: i32 = 2;
const EROFS: i32 = 30;
const ENOSYS: i32 = 38;
const ENOTDIR: i32 = 20;

// d_type for fuse_dirent (matches DT_*).
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;

const ROOT_INO: u64 = 1;

// S_IF* mode bits (the guest interprets these).
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

// ---- little-endian write helpers (safe; no `unsafe`, no zerocopy dep) ------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// `fuse_in_header` is a fixed 40-byte prefix on every request.
struct InHeader {
    opcode: u32,
    unique: u64,
    nodeid: u64,
}

impl InHeader {
    const LEN: usize = 40;
    fn parse(b: &[u8]) -> Option<InHeader> {
        if b.len() < Self::LEN {
            return None;
        }
        Some(InHeader {
            // len @0, opcode @4, unique @8, nodeid @16 (uid/gid/pid/pad follow)
            opcode: rd_u32(b, 4),
            unique: rd_u64(b, 8),
            nodeid: rd_u64(b, 16),
        })
    }
}

/// Encode a `fuse_out_header` (16 bytes) + `body` into one response buffer.
fn reply(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    put_u32(&mut out, (16 + body.len()) as u32); // len
    out.extend_from_slice(&error.to_le_bytes()); // error (i32)
    put_u64(&mut out, unique); // unique
    out.extend_from_slice(body);
    out
}

/// A resolved inode: the host path plus the cached kind, for a read-only tree.
struct Inode {
    path: PathBuf,
}

/// Read-only FUSE server over a host directory. `nodeid` 1 is the root; new
/// inodes are minted on LOOKUP and remembered so later ops can resolve them.
pub struct FuseServer {
    inodes: HashMap<u64, Inode>,
    by_path: HashMap<PathBuf, u64>,
    next_ino: u64,
}

impl FuseServer {
    pub fn new(root: impl Into<PathBuf>) -> FuseServer {
        let root = root.into();
        let mut inodes = HashMap::new();
        let mut by_path = HashMap::new();
        inodes.insert(ROOT_INO, Inode { path: root.clone() });
        by_path.insert(root, ROOT_INO);
        FuseServer {
            inodes,
            by_path,
            next_ino: 2,
        }
    }

    fn intern(&mut self, path: PathBuf) -> u64 {
        if let Some(&ino) = self.by_path.get(&path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inodes.insert(ino, Inode { path: path.clone() });
        self.by_path.insert(path, ino);
        ino
    }

    fn path_of(&self, nodeid: u64) -> Option<&Path> {
        self.inodes.get(&nodeid).map(|i| i.path.as_path())
    }

    /// Handle one FUSE request (header + body) and produce its reply bytes.
    pub fn dispatch(&mut self, req: &[u8]) -> Vec<u8> {
        let Some(h) = InHeader::parse(req) else {
            return reply(0, -ENOSYS, &[]);
        };
        let body = &req[InHeader::LEN.min(req.len())..];
        match h.opcode {
            FUSE_INIT => self.op_init(h.unique, body),
            FUSE_GETATTR => self.op_getattr(h.unique, h.nodeid),
            FUSE_LOOKUP => self.op_lookup(h.unique, h.nodeid, body),
            FUSE_READLINK => self.op_readlink(h.unique, h.nodeid),
            FUSE_OPEN | FUSE_OPENDIR => self.op_open(h.unique),
            FUSE_READ => self.op_read(h.unique, h.nodeid, body),
            FUSE_READDIR => self.op_readdir(h.unique, h.nodeid, body),
            FUSE_RELEASE | FUSE_RELEASEDIR | FUSE_FLUSH | FUSE_FORGET => reply(h.unique, 0, &[]),
            FUSE_STATFS => self.op_statfs(h.unique),
            // Everything else — every write op — is refused: read-only root.
            _ => reply(h.unique, -EROFS, &[]),
        }
    }

    fn op_init(&mut self, unique: u64, body: &[u8]) -> Vec<u8> {
        // fuse_init_in: major, minor, max_readahead, flags (we only need major).
        let their_minor = if body.len() >= 8 { rd_u32(body, 4) } else { 0 };
        let minor = their_minor.min(FUSE_KERNEL_MINOR_VERSION);
        // fuse_init_out (classic 64-byte layout, minor <= 35).
        let mut b = Vec::new();
        put_u32(&mut b, FUSE_KERNEL_VERSION); // major
        put_u32(&mut b, minor); // minor
        put_u32(&mut b, 0); // max_readahead (0 = accept kernel default)
        put_u32(&mut b, 0); // flags (negotiate nothing extra)
        b.extend_from_slice(&0u16.to_le_bytes()); // max_background
        b.extend_from_slice(&0u16.to_le_bytes()); // congestion_threshold
        put_u32(&mut b, 1 << 20); // max_write (1 MiB)
        put_u32(&mut b, 1); // time_gran (1 ns)
        b.extend_from_slice(&0u16.to_le_bytes()); // max_pages
        b.extend_from_slice(&0u16.to_le_bytes()); // map_alignment
        b.resize(64, 0); // unused tail
        reply(unique, 0, &b)
    }

    fn op_getattr(&mut self, unique: u64, nodeid: u64) -> Vec<u8> {
        let Some(path) = self.path_of(nodeid).map(Path::to_path_buf) else {
            return reply(unique, -ENOENT, &[]);
        };
        match encode_attr_out(nodeid, &path) {
            Some(attr) => reply(unique, 0, &attr),
            None => reply(unique, -ENOENT, &[]),
        }
    }

    fn op_lookup(&mut self, unique: u64, parent: u64, body: &[u8]) -> Vec<u8> {
        let Some(parent_path) = self.path_of(parent).map(Path::to_path_buf) else {
            return reply(unique, -ENOENT, &[]);
        };
        // body is the NUL-terminated child name.
        let name = cstr(body);
        // Refuse names that could escape the served root.
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return reply(unique, -ENOENT, &[]);
        }
        let child = parent_path.join(name);
        if std::fs::symlink_metadata(&child).is_err() {
            return reply(unique, -ENOENT, &[]);
        }
        let ino = self.intern(child.clone());
        match encode_entry_out(ino, &child) {
            Some(entry) => reply(unique, 0, &entry),
            None => reply(unique, -ENOENT, &[]),
        }
    }

    fn op_readlink(&mut self, unique: u64, nodeid: u64) -> Vec<u8> {
        let Some(path) = self.path_of(nodeid).map(Path::to_path_buf) else {
            return reply(unique, -ENOENT, &[]);
        };
        match std::fs::read_link(&path) {
            Ok(t) => reply(unique, 0, t.to_string_lossy().as_bytes()),
            Err(_) => reply(unique, -ENOENT, &[]),
        }
    }

    fn op_open(&mut self, unique: u64) -> Vec<u8> {
        // fuse_open_out: fh(u64), open_flags(u32), padding(u32). fh 0 is fine —
        // we resolve by nodeid on every READ, so no per-fh state is needed.
        let mut b = Vec::new();
        put_u64(&mut b, 0);
        put_u32(&mut b, 0);
        put_u32(&mut b, 0);
        reply(unique, 0, &b)
    }

    fn op_read(&mut self, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let Some(path) = self.path_of(nodeid).map(Path::to_path_buf) else {
            return reply(unique, -ENOENT, &[]);
        };
        // fuse_read_in: fh(u64) @0, offset(u64) @8, size(u32) @16, ...
        if body.len() < 20 {
            return reply(unique, -ENOSYS, &[]);
        }
        let offset = rd_u64(body, 8);
        let size = rd_u32(body, 16) as usize;
        match read_range(&path, offset, size) {
            Ok(data) => reply(unique, 0, &data),
            Err(e) => reply(unique, -e, &[]),
        }
    }

    fn op_readdir(&mut self, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let Some(path) = self.path_of(nodeid).map(Path::to_path_buf) else {
            return reply(unique, -ENOENT, &[]);
        };
        if body.len() < 20 {
            return reply(unique, -ENOSYS, &[]);
        }
        let offset = rd_u64(body, 8);
        let size = rd_u32(body, 16) as usize;
        let entries = match self.dir_entries(&path) {
            Ok(e) => e,
            Err(e) => return reply(unique, -e, &[]),
        };
        // Encode fuse_dirent records starting after `offset` (an opaque cursor:
        // we use the entry index), stopping before `size` is exceeded.
        let mut b = Vec::new();
        for (idx, (name, ino, dtype)) in entries.iter().enumerate() {
            let next = (idx as u64) + 1;
            if (idx as u64) < offset {
                continue;
            }
            let rec = encode_dirent(*ino, next, *dtype, name);
            if b.len() + rec.len() > size {
                break;
            }
            b.extend_from_slice(&rec);
        }
        reply(unique, 0, &b)
    }

    fn op_statfs(&mut self, unique: u64) -> Vec<u8> {
        // fuse_kstatfs: blocks, bfree, bavail, files, ffree, bsize, namelen,
        // frsize, padding, spare[6]. A benign read-only answer.
        let mut b = Vec::new();
        for v in [0u64, 0, 0, 0, 0] {
            put_u64(&mut b, v);
        }
        put_u32(&mut b, 4096); // bsize
        put_u32(&mut b, 255); // namelen
        put_u32(&mut b, 4096); // frsize
        b.resize(80, 0);
        reply(unique, 0, &b)
    }

    fn dir_entries(&self, path: &Path) -> Result<Vec<(String, u64, u32)>, i32> {
        let md = std::fs::symlink_metadata(path).map_err(|_| ENOENT)?;
        if !md.is_dir() {
            return Err(ENOTDIR);
        }
        let mut out = vec![
            (".".to_string(), ROOT_INO, DT_DIR),
            ("..".to_string(), ROOT_INO, DT_DIR),
        ];
        let rd = std::fs::read_dir(path).map_err(|_| ENOENT)?;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let ft = e.file_type().map_err(|_| ENOENT)?;
            let dt = if ft.is_dir() {
                DT_DIR
            } else if ft.is_symlink() {
                DT_LNK
            } else {
                DT_REG
            };
            // A stable synthetic inode number for readdir listing (LOOKUP mints
            // the authoritative one). Hash the path for determinism.
            out.push((name, stable_ino(&e.path()), dt));
        }
        Ok(out)
    }
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn stable_ino(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    // Keep it nonzero and out of the reserved low range.
    h.finish() | (1 << 62)
}

fn read_range(path: &Path, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path).map_err(|_| ENOENT)?;
    f.seek(SeekFrom::Start(offset)).map_err(|_| ENOENT)?;
    let mut buf = vec![0u8; size];
    let n = f.read(&mut buf).map_err(|_| ENOENT)?;
    buf.truncate(n);
    Ok(buf)
}

/// `fuse_attr` (88 bytes) for `path`, or None if it can't be stat'd.
fn encode_attr(ino: u64, path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::symlink_metadata(path).ok()?;
    let kind = if md.is_dir() {
        S_IFDIR
    } else if md.file_type().is_symlink() {
        S_IFLNK
    } else {
        S_IFREG
    };
    let perm = (md.mode() & 0o7777) as u32;
    let mut b = Vec::new();
    put_u64(&mut b, ino); // ino
    put_u64(&mut b, md.len()); // size
    put_u64(&mut b, md.len().div_ceil(512)); // blocks
    for _ in 0..3 {
        put_u64(&mut b, 0); // atime/mtime/ctime (sec) — zeroed (determinism)
    }
    for _ in 0..3 {
        put_u32(&mut b, 0); // *nsec
    }
    put_u32(&mut b, kind | perm); // mode
    put_u32(&mut b, md.nlink() as u32); // nlink
    put_u32(&mut b, 0); // uid
    put_u32(&mut b, 0); // gid
    put_u32(&mut b, 0); // rdev
    put_u32(&mut b, 4096); // blksize
    put_u32(&mut b, 0); // flags
    Some(b)
}

/// `fuse_attr_out`: attr_valid(u64) + attr_valid_nsec(u32) + dummy(u32) + attr.
fn encode_attr_out(ino: u64, path: &Path) -> Option<Vec<u8>> {
    let attr = encode_attr(ino, path)?;
    let mut b = Vec::new();
    put_u64(&mut b, 0); // attr_valid
    put_u32(&mut b, 0); // attr_valid_nsec
    put_u32(&mut b, 0); // dummy
    b.extend_from_slice(&attr);
    Some(b)
}

/// `fuse_entry_out`: nodeid, generation, entry_valid, attr_valid,
/// entry_valid_nsec, attr_valid_nsec, attr.
fn encode_entry_out(ino: u64, path: &Path) -> Option<Vec<u8>> {
    let attr = encode_attr(ino, path)?;
    let mut b = Vec::new();
    put_u64(&mut b, ino); // nodeid
    put_u64(&mut b, 0); // generation
    put_u64(&mut b, 0); // entry_valid
    put_u64(&mut b, 0); // attr_valid
    put_u32(&mut b, 0); // entry_valid_nsec
    put_u32(&mut b, 0); // attr_valid_nsec
    b.extend_from_slice(&attr);
    Some(b)
}

/// One `fuse_dirent`: ino(u64), off(u64), namelen(u32), type(u32), name, padded
/// to 8 bytes.
fn encode_dirent(ino: u64, next_off: u64, dtype: u32, name: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_u64(&mut b, ino);
    put_u64(&mut b, next_off);
    put_u32(&mut b, name.len() as u32);
    put_u32(&mut b, dtype);
    b.extend_from_slice(name.as_bytes());
    while b.len() % 8 != 0 {
        b.push(0);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a FUSE request: 40-byte in_header + body.
    fn request(opcode: u32, unique: u64, nodeid: u64, body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        put_u32(&mut b, (InHeader::LEN + body.len()) as u32); // len
        put_u32(&mut b, opcode);
        put_u64(&mut b, unique);
        put_u64(&mut b, nodeid);
        put_u32(&mut b, 0); // uid
        put_u32(&mut b, 0); // gid
        put_u32(&mut b, 0); // pid
        put_u32(&mut b, 0); // padding/total_extlen
        b.extend_from_slice(body);
        b
    }

    /// Split a reply into (error, body).
    fn parse_reply(r: &[u8]) -> (i32, Vec<u8>) {
        let len = rd_u32(r, 0) as usize;
        let error = i32::from_le_bytes(r[4..8].try_into().unwrap());
        (error, r[16..len].to_vec())
    }

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(d.path().join("hello"), b"hi from virtiofs\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("hosts", d.path().join("etc/localhost")).unwrap();
        d
    }

    #[test]
    fn init_negotiates_and_caps_the_minor_version() {
        let d = tempfile::tempdir().unwrap();
        let mut fs = FuseServer::new(d.path());
        let mut init_in = Vec::new();
        put_u32(&mut init_in, 7); // their major
        put_u32(&mut init_in, 99); // their minor (higher than ours)
        put_u32(&mut init_in, 0);
        put_u32(&mut init_in, 0);
        let (err, body) = parse_reply(&fs.dispatch(&request(FUSE_INIT, 1, 0, &init_in)));
        assert_eq!(err, 0);
        assert_eq!(rd_u32(&body, 0), FUSE_KERNEL_VERSION);
        assert_eq!(
            rd_u32(&body, 4),
            FUSE_KERNEL_MINOR_VERSION,
            "minor capped to ours"
        );
        assert_eq!(body.len(), 64, "classic fuse_init_out layout");
    }

    #[test]
    fn lookup_then_getattr_then_read_round_trip() {
        let d = tree();
        let mut fs = FuseServer::new(d.path());
        // LOOKUP /hello under root.
        let (err, ent) = parse_reply(&fs.dispatch(&request(FUSE_LOOKUP, 2, ROOT_INO, b"hello\0")));
        assert_eq!(err, 0);
        let ino = rd_u64(&ent, 0); // fuse_entry_out.nodeid
        assert!(ino >= 2);
        // GETATTR on it → regular file with the right size.
        let (err, attr_out) = parse_reply(&fs.dispatch(&request(FUSE_GETATTR, 3, ino, &[])));
        assert_eq!(err, 0);
        // fuse_attr_out: 16-byte prefix, then fuse_attr; mode @ fuse_attr+60
        // (6×u64 ts/size/blocks/ino + 3×u32 nsec).
        let mode = rd_u32(&attr_out, 16 + 60);
        assert_eq!(mode & S_IFREG, S_IFREG, "hello is a regular file");
        // READ the whole file.
        let mut read_in = Vec::new();
        put_u64(&mut read_in, 0); // fh
        put_u64(&mut read_in, 0); // offset
        put_u32(&mut read_in, 4096); // size
        put_u32(&mut read_in, 0); // read_flags
        put_u64(&mut read_in, 0); // lock_owner
        put_u32(&mut read_in, 0); // flags
        put_u32(&mut read_in, 0); // padding
        let (err, data) = parse_reply(&fs.dispatch(&request(FUSE_READ, 4, ino, &read_in)));
        assert_eq!(err, 0);
        assert_eq!(data, b"hi from virtiofs\n");
    }

    #[test]
    fn lookup_missing_is_enoent_and_traversal_is_refused() {
        let d = tree();
        let mut fs = FuseServer::new(d.path());
        let (err, _) = parse_reply(&fs.dispatch(&request(FUSE_LOOKUP, 1, ROOT_INO, b"nope\0")));
        assert_eq!(err, -ENOENT);
        // `..` and embedded-slash names can't escape the served root.
        for bad in [&b"..\0"[..], &b"../etc\0"[..], &b"a/b\0"[..]] {
            let (err, _) = parse_reply(&fs.dispatch(&request(FUSE_LOOKUP, 1, ROOT_INO, bad)));
            assert_eq!(err, -ENOENT, "traversal name {bad:?} refused");
        }
    }

    #[test]
    fn readdir_lists_dot_dotdot_and_children() {
        let d = tree();
        let mut fs = FuseServer::new(d.path());
        let mut rd_in = Vec::new();
        put_u64(&mut rd_in, 0); // fh
        put_u64(&mut rd_in, 0); // offset
        put_u32(&mut rd_in, 4096); // size
        put_u32(&mut rd_in, 0); // read_flags
        put_u64(&mut rd_in, 0); // lock_owner
        put_u32(&mut rd_in, 0); // flags
        put_u32(&mut rd_in, 0); // padding
        let (err, body) = parse_reply(&fs.dispatch(&request(FUSE_READDIR, 5, ROOT_INO, &rd_in)));
        assert_eq!(err, 0);
        // Walk the fuse_dirent records and collect names.
        let mut names = Vec::new();
        let mut off = 0usize;
        while off + 24 <= body.len() {
            let namelen = rd_u32(&body, off + 16) as usize;
            let name = String::from_utf8_lossy(&body[off + 24..off + 24 + namelen]).into_owned();
            names.push(name);
            let rec = (24 + namelen).div_ceil(8) * 8;
            off += rec;
        }
        assert!(names.contains(&".".to_string()));
        assert!(names.contains(&"..".to_string()));
        assert!(names.contains(&"etc".to_string()));
        assert!(names.contains(&"hello".to_string()));
    }

    #[test]
    fn readlink_returns_the_target() {
        let d = tree();
        let mut fs = FuseServer::new(d.path());
        // LOOKUP etc, then etc/localhost.
        let (_, etc) = parse_reply(&fs.dispatch(&request(FUSE_LOOKUP, 1, ROOT_INO, b"etc\0")));
        let etc_ino = rd_u64(&etc, 0);
        let (_, link) =
            parse_reply(&fs.dispatch(&request(FUSE_LOOKUP, 2, etc_ino, b"localhost\0")));
        let link_ino = rd_u64(&link, 0);
        let (err, target) = parse_reply(&fs.dispatch(&request(FUSE_READLINK, 3, link_ino, &[])));
        assert_eq!(err, 0);
        assert_eq!(target, b"hosts");
    }

    #[test]
    fn write_opcodes_are_refused_read_only() {
        let d = tree();
        let mut fs = FuseServer::new(d.path());
        const FUSE_WRITE: u32 = 16;
        const FUSE_MKDIR: u32 = 9;
        const FUSE_UNLINK: u32 = 10;
        for op in [FUSE_WRITE, FUSE_MKDIR, FUSE_UNLINK] {
            let (err, _) = parse_reply(&fs.dispatch(&request(op, 1, ROOT_INO, b"x\0")));
            assert_eq!(err, -EROFS, "opcode {op} must be refused read-only");
        }
    }
}
