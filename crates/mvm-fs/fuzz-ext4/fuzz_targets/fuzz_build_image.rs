// Fuzz the pure-Rust ext4 writer's one entrypoint, `build_image`.
//
// The writer is `#![forbid(unsafe_code)]`, so no input can corrupt host
// memory; this harness guards the next line of defense — that no
// caller-influenced node set makes it panic (a DoS on the run path) and that
// every image it *does* produce satisfies the structural invariants a valid
// ext4 must hold. Malformed / impossible trees must return `Err`, never abort.
//
// To reach the layout + emit code (not just bail at the first missing parent),
// the harness synthesizes any missing ancestor directories before building.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use mvm_fs::ext4::{BLOCK_SIZE, Node, build_image};

// Caps keep the fuzzer from OOMing on adversarial sizes while still exercising
// multi-node, multi-block trees.
const MAX_NODES: u32 = 64;
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_SEGMENTS: u32 = 4;
const MAX_SEG_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(nodes) = gen_nodes(&mut u) else {
        return;
    };
    if let Ok(img) = build_image(nodes) {
        let bs = BLOCK_SIZE as usize;
        // A real ext4 image is a whole number of blocks, has room for at least
        // the superblock block plus one more, and carries the 0xEF53 magic
        // (little-endian) at superblock offset 0x38.
        assert_eq!(img.len() % bs, 0, "image must be block-aligned");
        assert!(img.len() >= 2 * bs, "image too small to be valid");
        assert_eq!(
            &img[1024 + 0x38..1024 + 0x3A],
            &[0x53, 0xEF],
            "superblock magic missing"
        );
    }
});

fn gen_nodes(u: &mut Unstructured) -> arbitrary::Result<Vec<Node>> {
    let count = u.int_in_range(0..=MAX_NODES)?;
    let mut nodes: Vec<Node> = Vec::new();
    for _ in 0..count {
        let path = gen_path(u)?;
        match u8::arbitrary(u)? % 3 {
            0 => nodes.push(Node::Dir {
                path,
                mode: u16::arbitrary(u)?,
                xattrs: Vec::new(),
            }),
            1 => {
                let want = u.int_in_range(0..=MAX_FILE_BYTES)?;
                let take = want.min(u.len());
                let data = u.bytes(take)?.to_vec();
                nodes.push(Node::File {
                    path,
                    mode: u16::arbitrary(u)?,
                    data,
                    xattrs: Vec::new(),
                });
            }
            _ => {
                let target = gen_segment(u)?;
                nodes.push(Node::Symlink { path, target });
            }
        }
    }
    Ok(with_ancestor_dirs(nodes))
}

// Build a `/`-rooted path of a few short alphanumeric segments. An empty
// segment list yields "/", which `build_image` treats as the (implicit) root
// and rejects as a duplicate — still a no-panic path.
fn gen_path(u: &mut Unstructured) -> arbitrary::Result<String> {
    let segs = u.int_in_range(0..=MAX_SEGMENTS)?;
    let mut p = String::new();
    for _ in 0..segs {
        p.push('/');
        p.push_str(&gen_segment(u)?);
    }
    if p.is_empty() {
        p.push('/');
    }
    Ok(p)
}

fn gen_segment(u: &mut Unstructured) -> arbitrary::Result<String> {
    let len = u.int_in_range(1..=MAX_SEG_LEN)?;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        // Keep bytes in a safe printable range and never emit '/' or NUL.
        let c = b"abcdefghijklmnopqrstuvwxyz0123456789._-"[u.choose_index(39)?];
        s.push(c as char);
    }
    Ok(s)
}

// Ensure every ancestor directory of every node exists, so most inputs reach
// the layout/emit code instead of bailing at `MissingParent`. Ancestors are
// added as directories only when no node already claims that path.
fn with_ancestor_dirs(nodes: Vec<Node>) -> Vec<Node> {
    use std::collections::BTreeSet;
    let claimed: BTreeSet<String> = nodes.iter().map(node_path).collect();
    let mut extra: BTreeSet<String> = BTreeSet::new();
    for n in &nodes {
        let p = node_path(n);
        let mut idx = p.len();
        while let Some(slash) = p[..idx].rfind('/') {
            if slash == 0 {
                break;
            }
            let anc = p[..slash].to_string();
            if !claimed.contains(&anc) {
                extra.insert(anc);
            }
            idx = slash;
        }
    }
    let mut out = nodes;
    for path in extra {
        out.push(Node::Dir {
            path,
            mode: 0o755,
            xattrs: Vec::new(),
        });
    }
    out
}

fn node_path(n: &Node) -> String {
    // `FileFromHost` is matched but never generated here, deliberately. This
    // target feeds the writer arbitrary *bytes*; that variant carries a host
    // path the emit pass opens, so fuzzing it would exercise the filesystem
    // rather than the parser and would let a generated path escape the corpus.
    // The eager `File` variant covers the same layout arithmetic.
    match n {
        Node::Dir { path, .. }
        | Node::File { path, .. }
        | Node::FileFromHost { path, .. }
        | Node::Symlink { path, .. } => path.clone(),
    }
}
