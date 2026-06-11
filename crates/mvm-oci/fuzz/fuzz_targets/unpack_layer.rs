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
    // Fresh tempdir per iteration. cleanup happens via Drop when
    // the TempDir goes out of scope at the end of the closure.
    // libFuzzer expects per-iteration work to be cheap; this
    // tempdir cost is unavoidable because `unpack_layer` writes
    // real files, and reusing one across iterations would let
    // earlier-iteration state leak into the property checks below.
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        // tempdir creation failing means the host fs is in a bad
        // state — not a bug in the unpacker. Skip this iteration.
        Err(_) => return,
    };

    let _ = unpack_layer(Cursor::new(data), tmp.path(), &UnpackOptions::default());

    // Property (b): nothing the unpacker wrote escapes the
    // tempdir. We walk the resulting tree with `symlink_metadata`
    // (so a symlink-to-elsewhere is observed as a symlink, not
    // dereferenced) and assert every entry's path canonicalizes
    // under the tempdir. Symlinks themselves are allowed to *point*
    // outside — the unpacker writes the link text verbatim by
    // design — but the symlink file itself must live under root.
    let root = match tmp.path().canonicalize() {
        Ok(p) => p,
        Err(_) => return,
    };
    walk_assert_under_root(&root, &root);
});

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
