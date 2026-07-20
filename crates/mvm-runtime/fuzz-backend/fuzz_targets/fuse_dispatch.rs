// Fuzz the virtio-fs FUSE-server request parser.
//
// The `VirtioFs` device hands guest-supplied bytes straight to
// `FuseServer::dispatch`. The guest is untrusted, so a byte pattern that panics
// the parser is a guest-triggerable **host** DoS. This target asserts:
//
//   (a) `dispatch` never panics on any input, and
//   (b) every reply is a well-formed `fuse_out_header` whose `len` matches the
//       reply length.
//
// Path-confinement (a symlink in the served tree can't disclose host files) is a
// structural property enforced by `real_path_under_root` + `O_NOFOLLOW` and is
// pinned by a unit test; this target focuses on the parse/DoS surface.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_runtime::vmm::virtio_fs::FuseServer;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().expect("tempdir");
    // A small served tree so LOOKUP/READ/READDIR reach real inodes.
    let _ = std::fs::create_dir_all(dir.path().join("etc"));
    let _ = std::fs::write(dir.path().join("etc/hosts"), b"127.0.0.1 localhost\n");
    let _ = std::fs::write(dir.path().join("bin"), b"#!/x\n");
    let mut fs = FuseServer::new(dir.path());

    // Arm 1: raw bytes straight to the parser (exercises the header parse + the
    // short-buffer guards).
    check_reply(&fs.dispatch(data));

    // Arm 2: a well-formed 40-byte `fuse_in_header` carrying a fuzz-chosen opcode
    // (0..=255) + root nodeid, then the rest as the op body. Random bytes almost
    // never form a valid header, so this steers the fuzzer into the op handlers
    // and their per-op body reads.
    if let Some((&op_sel, rest)) = data.split_first() {
        let mut req = vec![0u8; 40];
        let total = 40 + rest.len();
        req[0..4].copy_from_slice(&(total as u32).to_le_bytes()); // len
        req[4..8].copy_from_slice(&u32::from(op_sel).to_le_bytes()); // opcode
        req[16..24].copy_from_slice(&1u64.to_le_bytes()); // nodeid = root
        req.extend_from_slice(rest);
        check_reply(&fs.dispatch(&req));
    }
});

fn check_reply(reply: &[u8]) {
    // Every reply is at least a `fuse_out_header`, and its `len` field is
    // consistent with the actual reply length.
    assert!(
        reply.len() >= 16,
        "reply shorter than a fuse_out_header: {}",
        reply.len()
    );
    let len = u32::from_le_bytes(reply[0..4].try_into().unwrap()) as usize;
    assert_eq!(
        len,
        reply.len(),
        "fuse_out_header.len must equal reply length"
    );
}
