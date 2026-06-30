//! Builder-VM file transfer over the guest↔host vsock channel.
//!
//! The in-house VMM (HVF on macOS, KVM on Linux) has no virtio-fs and no
//! writable host-shared disk — only virtio-blk + vsock. So the builder VM moves
//! files the way everything moves under the vsock-only guest channel: over vsock.
//! The host streams the source tree (and host binaries) *into* the builder guest,
//! and the guest streams
//! the built artifacts *back*. No host directory is ever live-mounted into the
//! guest, and the host never parses a guest-authored filesystem image.
//!
//! Wire format: a framed stream. Each regular file is a length-prefixed JSON
//! header ([`Frame::File`] — relative path, unix mode, byte length) immediately
//! followed by exactly `len` content bytes; a [`Frame::End`] marker closes the
//! tree. Framing reuses the 4-byte big-endian length prefix the rest of the vsock
//! protocol uses.
//!
//! **Security.** The receiver is the trust boundary: when the host receives the
//! guest's `/out`, the guest is *untrusted*. [`receive_into`] therefore admits
//! only `Component::Normal` path segments — no `..`, absolute paths, prefixes, or
//! root-dir — so a hostile sender cannot escape the destination root, mirroring
//! the OCI unpacker's no-path-escape discipline (a defense-in-depth `starts_with`
//! check backs it up). Per-file and per-header size caps bound memory.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Cap on a single frame's JSON header (paths are short; this is generous).
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Cap on a single transferred file (a built kernel/rootfs is the large case).
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// One framed message on the transfer stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Frame {
    /// A regular file: `len` content bytes follow this header on the stream.
    File {
        /// Path relative to the tree root. Sanitized on receive.
        rel_path: String,
        /// Unix permission bits (low 12) to set on the written file.
        mode: u32,
        /// Content length in bytes that immediately follow this header.
        len: u64,
    },
    /// End of the tree — no more files.
    End,
}

/// Stream every regular file under `src` to `out` as framed messages, then an
/// [`Frame::End`]. Directories are implicit (recreated from the file paths);
/// symlinks and other non-regular entries are skipped (the builder tree is
/// plain files). Paths are stored relative to `src`.
pub fn send_dir<W: Write>(out: &mut W, src: &Path) -> Result<()> {
    send_dir_inner(out, src, src)?;
    write_frame(out, &Frame::End)
}

fn send_dir_inner<W: Write>(out: &mut W, root: &Path, dir: &Path) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    // Deterministic order so a transfer is reproducible.
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            send_dir_inner(out, root, &path)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .with_context(|| format!("{} not under {}", path.display(), root.display()))?
                .to_string_lossy()
                .into_owned();
            let meta = entry.metadata()?;
            write_frame(
                out,
                &Frame::File {
                    rel_path: rel,
                    mode: unix_mode(&meta),
                    len: meta.len(),
                },
            )?;
            let mut f =
                std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
            std::io::copy(&mut f, out).with_context(|| format!("stream {}", path.display()))?;
        }
        // non-regular (symlink, fifo, …): skipped — not part of the build tree.
    }
    Ok(())
}

/// Receive a framed tree into `dest_root`, sanitizing every path. Returns the
/// number of files written. Fails closed on an unsafe path, an oversize file, or
/// a short content read — the partial tree is left for the caller to discard.
pub fn receive_into<R: Read>(input: &mut R, dest_root: &Path) -> Result<u64> {
    std::fs::create_dir_all(dest_root)
        .with_context(|| format!("create dest root {}", dest_root.display()))?;
    let mut written = 0u64;
    loop {
        match read_frame(input)? {
            Frame::End => break,
            Frame::File {
                rel_path,
                mode,
                len,
            } => {
                if len > MAX_FILE_BYTES {
                    bail!("transferred file {rel_path:?} exceeds the {MAX_FILE_BYTES}-byte cap");
                }
                let dest = safe_join(dest_root, &rel_path)?;
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create {}", parent.display()))?;
                }
                let mut f = std::fs::File::create(&dest)
                    .with_context(|| format!("create {}", dest.display()))?;
                let mut limited = input.take(len);
                let copied = std::io::copy(&mut limited, &mut f)
                    .with_context(|| format!("write {}", dest.display()))?;
                if copied != len {
                    bail!("short content for {rel_path:?}: got {copied} of {len} bytes");
                }
                set_unix_mode(&dest, mode)?;
                written += 1;
            }
        }
    }
    Ok(written)
}

/// Join `rel` under `root`, admitting only `Component::Normal` segments. Any
/// `..`, absolute path, prefix, or root-dir component is refused — a hostile
/// sender cannot escape `root`. The trailing `starts_with` is belt-and-braces.
fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    let mut out = root.to_path_buf();
    let mut had_segment = false;
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(seg) => {
                out.push(seg);
                had_segment = true;
            }
            Component::CurDir => {} // `.` is harmless; ignore
            other => bail!("unsafe path component {other:?} in transferred path {rel:?}"),
        }
    }
    if !had_segment {
        bail!("empty transferred path");
    }
    if !out.starts_with(root) {
        bail!("transferred path {rel:?} escapes the destination root");
    }
    Ok(out)
}

fn write_frame<W: Write>(out: &mut W, frame: &Frame) -> Result<()> {
    write_msg(out, frame)
}

fn read_frame<R: Read>(input: &mut R) -> Result<Frame> {
    read_msg(input)
}

/// Write a length-prefixed JSON message (4-byte big-endian length + JSON body) —
/// the shared framing for the transfer file headers and the build-session control
/// messages built on top of them.
pub fn write_msg<W: Write, T: Serialize>(out: &mut W, msg: &T) -> Result<()> {
    let body = serde_json::to_vec(msg).context("encode framed message")?;
    let len: u32 = body.len().try_into().context("framed message too large")?;
    out.write_all(&len.to_be_bytes())?;
    out.write_all(&body)?;
    Ok(())
}

/// Read one length-prefixed JSON message. The cap bounds a hostile header.
pub fn read_msg<R: Read, T: DeserializeOwned>(input: &mut R) -> Result<T> {
    let mut len_buf = [0u8; 4];
    input
        .read_exact(&mut len_buf)
        .context("read framed message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HEADER_BYTES {
        bail!("framed message header {len} exceeds the {MAX_HEADER_BYTES}-byte cap");
    }
    let mut body = vec![0u8; len];
    input
        .read_exact(&mut body)
        .context("read framed message body")?;
    serde_json::from_slice(&body).context("decode framed message")
}

#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn set_unix_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
        .with_context(|| format!("chmod {}", path.display()))
}

#[cfg(not(unix))]
fn set_unix_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A directory tree (nested) round-trips byte-for-byte, preserving content
    /// and unix mode, through a single stream.
    #[test]
    fn round_trips_a_nested_tree() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("a/b")).unwrap();
        std::fs::write(src.path().join("top.txt"), b"hello").unwrap();
        std::fs::write(src.path().join("a/mid.bin"), vec![7u8; 4096]).unwrap();
        std::fs::write(src.path().join("a/b/deep"), b"deep!").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                src.path().join("a/b/deep"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        let mut buf = Vec::new();
        send_dir(&mut buf, src.path()).unwrap();

        let dst = tempfile::tempdir().unwrap();
        let n = receive_into(&mut Cursor::new(buf), dst.path()).unwrap();
        assert_eq!(n, 3, "three regular files");

        assert_eq!(std::fs::read(dst.path().join("top.txt")).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(dst.path().join("a/mid.bin")).unwrap(),
            vec![7u8; 4096]
        );
        assert_eq!(
            std::fs::read(dst.path().join("a/b/deep")).unwrap(),
            b"deep!"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dst.path().join("a/b/deep"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o755, "mode preserved");
        }
    }

    /// An empty file transfers (zero content bytes, no desync).
    #[test]
    fn empty_file_round_trips() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("empty"), b"").unwrap();
        std::fs::write(src.path().join("after"), b"x").unwrap();
        let mut buf = Vec::new();
        send_dir(&mut buf, src.path()).unwrap();
        let dst = tempfile::tempdir().unwrap();
        receive_into(&mut Cursor::new(buf), dst.path()).unwrap();
        assert_eq!(std::fs::read(dst.path().join("empty")).unwrap(), b"");
        assert_eq!(std::fs::read(dst.path().join("after")).unwrap(), b"x");
    }

    /// Adversarial: a `..` traversal in a received path is refused — the file is
    /// NOT written outside the destination root.
    #[test]
    fn parent_dir_traversal_is_refused() {
        let frame = Frame::File {
            rel_path: "../escape.txt".into(),
            mode: 0o644,
            len: 5,
        };
        let mut stream = Vec::new();
        write_frame(&mut stream, &frame).unwrap();
        stream.extend_from_slice(b"PWNED");
        // no End needed — it fails before that

        let dst = tempfile::tempdir().unwrap();
        let err = receive_into(&mut Cursor::new(stream), dst.path()).unwrap_err();
        assert!(
            err.to_string().contains("unsafe path component"),
            "got: {err}"
        );
        // The escape target must not exist.
        assert!(!dst.path().parent().unwrap().join("escape.txt").exists());
    }

    /// Adversarial: an absolute path is refused (it would escape via the root).
    #[test]
    fn absolute_path_is_refused() {
        let frame = Frame::File {
            rel_path: "/etc/passwd".into(),
            mode: 0o644,
            len: 1,
        };
        let mut stream = Vec::new();
        write_frame(&mut stream, &frame).unwrap();
        stream.extend_from_slice(b"x");
        let dst = tempfile::tempdir().unwrap();
        let err = receive_into(&mut Cursor::new(stream), dst.path()).unwrap_err();
        assert!(
            err.to_string().contains("unsafe path component"),
            "got: {err}"
        );
    }

    /// Adversarial: a `..` buried mid-path (after a normal segment) is refused.
    #[test]
    fn embedded_parent_dir_is_refused() {
        let frame = Frame::File {
            rel_path: "a/../../b".into(),
            mode: 0o644,
            len: 0,
        };
        let mut stream = Vec::new();
        write_frame(&mut stream, &frame).unwrap();
        let dst = tempfile::tempdir().unwrap();
        let err = receive_into(&mut Cursor::new(stream), dst.path()).unwrap_err();
        assert!(err.to_string().contains("unsafe path component"));
    }

    /// An over-cap file length in the header is refused before any content read.
    #[test]
    fn oversize_file_is_refused() {
        let frame = Frame::File {
            rel_path: "huge".into(),
            mode: 0o644,
            len: MAX_FILE_BYTES + 1,
        };
        let mut stream = Vec::new();
        write_frame(&mut stream, &frame).unwrap();
        let dst = tempfile::tempdir().unwrap();
        let err = receive_into(&mut Cursor::new(stream), dst.path()).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }
}
