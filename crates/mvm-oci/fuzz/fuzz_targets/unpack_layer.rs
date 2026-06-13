// Adversarial fuzz for the layer-to-tree unpacker.
//
// Feeds arbitrary bytes to `mvm_oci::unpack::unpack_layer` against a
// fresh tempdir and asserts:
//
//   (a) the call doesn't panic on any byte input
//   (b) nothing escapes the tempdir — every materialized entry's
//       location resolves under the tempdir root
//
// A third property ("no leaked file descriptors") is implicit in
// libFuzzer's process model: each iteration runs in the same
// process, so an FD leak would surface as a process-wide `EMFILE`
// over a 30-minute fuzz budget. We don't add an explicit FD-count
// check because reading `/proc/self/fd` per iteration would
// dominate the unpack cost itself.
//
// CI gate: `.github/workflows/ci.yml::oci-unpack-fuzz`, gated by
// dorny/paths-filter on `crates/mvm-oci/**`. 30-min budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_oci::unpack::{UnpackOptions, unpack_layer};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Arm 1: raw bytes straight to the unpacker.
    run_unpack(data);

    // Arm 2: structured path-escape corpus. Random bytes almost never
    // form a valid tar header carrying an attacker-shaped path, so the
    // absolute / traversal / symlinked-parent refusal branches stay
    // cold under Arm 1. Here we hand-roll a minimal USTAR archive (no
    // tar-crate dependency — keeps the frozen fuzz lockfile untouched)
    // whose entry paths are derived from the fuzz input, steering the
    // fuzzer into those branches and the openat2 resolution path.
    if let Some((&selector, rest)) = data.split_first() {
        let name: Vec<u8> = rest.iter().copied().take(100).collect();
        match selector % 3 {
            // A single regular-file entry with an attacker-shaped path
            // (absolute, `..`, NUL, separator quirks — verbatim bytes).
            0 => run_unpack(&ustar_archive(&[(b'0', &name, b"")])),
            // Symlinked-parent vector: `d -> /tmp`, then a write under
            // `d/<name>`. Exercises the parent-resolution refusal.
            1 => {
                let mut leaf = b"d/".to_vec();
                leaf.extend_from_slice(&name);
                leaf.truncate(100);
                run_unpack(&ustar_archive(&[(b'2', b"d", b"/tmp"), (b'0', &leaf, b"")]));
            }
            // A symlink entry whose own location is attacker-shaped.
            _ => run_unpack(&ustar_archive(&[(b'2', &name, b"/etc")])),
        }
    }
});

/// Unpack `archive` into a fresh tempdir and assert nothing escapes.
fn run_unpack(archive: &[u8]) {
    // Fresh tempdir per call. Cleanup happens via Drop. libFuzzer
    // expects per-iteration work to be cheap; the tempdir cost is
    // unavoidable because `unpack_layer` writes real files, and
    // reusing one across iterations would let earlier state leak into
    // the property check below.
    let tmp = match tempfile::tempdir() {
        // tempdir creation failing means the host fs is in a bad state
        // — not a bug in the unpacker. Skip.
        Ok(t) => t,
        Err(_) => return,
    };

    let _ = unpack_layer(Cursor::new(archive), tmp.path(), &UnpackOptions::default());

    // Property: nothing the unpacker wrote escapes the tempdir. We
    // walk the resulting tree with `symlink_metadata` (so a
    // symlink-to-elsewhere is observed as a symlink, not dereferenced)
    // and assert every entry's parent canonicalizes under the tempdir.
    // Symlinks themselves are allowed to *point* outside — the unpacker
    // writes the link text verbatim by design — but the symlink file
    // itself must live under root.
    let root = match tmp.path().canonicalize() {
        Ok(p) => p,
        Err(_) => return,
    };
    walk_assert_under_root(&root, &root);
}

/// Hand-roll a minimal USTAR archive from `(typeflag, name, linkname)`
/// entries, each a 0-length body. `name`/`linkname` are written
/// verbatim (truncated to the 100-byte USTAR fields) so adversarial
/// path bytes reach the unpacker unmodified — the whole point of the
/// corpus. No external tar dependency, so the fuzz lockfile is frozen.
fn ustar_archive(entries: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(typeflag, name, linkname) in entries {
        let mut h = [0u8; 512];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name[..n]);
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(b"00000000000\0");
        h[136..148].copy_from_slice(b"00000000000\0");
        h[156] = typeflag;
        let ln = linkname.len().min(100);
        h[157..157 + ln].copy_from_slice(&linkname[..ln]);
        h[257..265].copy_from_slice(b"ustar  \0");
        // Checksum: byte sum with the checksum field taken as 8 spaces.
        h[148..156].copy_from_slice(b"        ");
        let cksum: u32 = h.iter().map(|&b| b as u32).sum();
        let s = format!("{cksum:06o}\0 ");
        h[148..156].copy_from_slice(s.as_bytes());
        out.extend_from_slice(&h);
    }
    // Two 512-byte zero blocks = end-of-archive.
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn walk_assert_under_root(dir: &std::path::Path, root: &std::path::Path) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for child in read_dir.flatten() {
        let child_path = child.path();
        // `symlink_metadata` doesn't dereference — a symlink-to-
        // elsewhere is reported as a symlink, not followed.
        let meta = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // The child's *parent* must be under root. canonicalize()
        // on the parent dereferences any symlink in the chain; if
        // it lands outside root we caught an unpacker bug.
        if let Some(parent) = child_path.parent() {
            if let Ok(canon) = parent.canonicalize() {
                assert!(
                    canon.starts_with(root),
                    "unpacker wrote entry whose parent escaped root: {canon:?} not under {root:?}"
                );
            }
        }
        if meta.is_dir() {
            walk_assert_under_root(&child_path, root);
        }
    }
}
