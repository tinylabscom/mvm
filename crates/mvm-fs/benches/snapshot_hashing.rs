//! Criterion benchmarks for snapshot content hashing.
//!
//! Measures `hash::hash_source` (the whole-tree manifest hash behind
//! `FsSnapshotStore::create_content_addressed`) as a function of tree size
//! and of position in a reflink CoW chain, where each generation differs
//! from its parent by a few blocks but still pays the full-tree hashing bill.

#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

/// Deterministic incompressible-ish payload: a xorshift stream, so the bytes
/// differ per position and no filesystem-level dedup or compression can make
/// the fixture cheaper to hash than real content.
#[cfg(unix)]
fn fill_pattern(buf: &mut [u8], mut state: u64) {
    for byte in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state >> 32) as u8;
    }
}

/// Build a directory tree of `files` files, each `file_size` bytes, spread
/// across ten subdirectories.
#[cfg(unix)]
fn make_tree(root: &Path, files: usize, file_size: usize, seed: u64) {
    for d in 0..10 {
        std::fs::create_dir_all(root.join(format!("dir{d:02}"))).unwrap();
    }
    let mut payload = vec![0u8; file_size];
    for i in 0..files {
        fill_pattern(&mut payload, seed.wrapping_add(i as u64));
        let dir = format!("dir{:02}", i % 10);
        std::fs::write(root.join(&dir).join(format!("file{i:04}.bin")), &payload).unwrap();
    }
}

/// Write one large blob. `sparse` leaves a long interior zero run as real
/// holes, the shape of a memory snapshot whose free guest RAM never dirtied.
#[cfg(unix)]
fn make_blob(path: &Path, size: usize, sparse: bool) {
    let mut file = std::fs::File::create(path).unwrap();
    if sparse {
        let edge = 1024 * 1024;
        let mut buf = vec![0u8; edge];
        fill_pattern(&mut buf, 0x5eed);
        file.write_all(&buf).unwrap();
        file.seek(SeekFrom::Start((size - edge) as u64)).unwrap();
        fill_pattern(&mut buf, 0x5eef);
        file.write_all(&buf).unwrap();
    } else {
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        let mut written = 0;
        while written < size {
            let n = buf.len().min(size - written);
            fill_pattern(&mut buf[..n], 0xb10b_u64.wrapping_add(written as u64));
            file.write_all(&buf[..n]).unwrap();
            written += n;
        }
    }
}

/// Mutate a cloned tree the way a paused child differs from its parent: a few
/// small files rewritten wholesale and a handful of in-place block writes in
/// the large blob. Sizes stay fixed — a few blocks, not a new tree.
#[cfg(unix)]
fn mutate_clone(root: &Path, generation: u32) {
    for i in 0..4 {
        let path = root
            .join(format!("dir{:02}", i))
            .join(format!("file{i:04}.bin"));
        let mut bytes = std::fs::read(&path).unwrap();
        let head = 4096.min(bytes.len());
        fill_pattern(&mut bytes[..head], generation as u64);
        std::fs::write(&path, &bytes).unwrap();
    }
    let blob = root.join("memory.bin");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&blob)
        .unwrap();
    let mut block = [0u8; 4096];
    for b in 0..8u64 {
        fill_pattern(&mut block, (generation as u64) << 8 | b);
        file.seek(SeekFrom::Start(2 * 1024 * 1024 + b * 3 * 1024 * 1024))
            .unwrap();
        file.write_all(&block).unwrap();
    }
}

#[cfg(unix)]
fn bench_tree_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_hash_tree_scaling");
    for (files, file_size) in [(500, 4 * 1024), (2000, 4 * 1024), (200, 256 * 1024)] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("tree");
        make_tree(&root, files, file_size, 7);
        let total_mib = (files * file_size) as f64 / (1024.0 * 1024.0);
        group.bench_function(
            BenchmarkId::new("hash_source", format!("{files}files_{total_mib:.0}MiB")),
            |b| b.iter(|| mvm_fs::hash::hash_source(&root).unwrap()),
        );
    }
    group.finish();
}

#[cfg(unix)]
fn bench_blob_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_hash_blob_scaling");
    group.sample_size(10);
    for (size_mib, sparse) in [(64, false), (256, false), (512, true)] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        make_blob(&root.join("memory.bin"), size_mib * 1024 * 1024, sparse);
        let label = if sparse { "sparse" } else { "dense" };
        group.bench_function(
            BenchmarkId::new("v1_hash_source", format!("{size_mib}MiB_{label}")),
            |b| b.iter(|| mvm_fs::hash::hash_source(&root).unwrap()),
        );
        group.bench_function(
            BenchmarkId::new("v2_manifest_full", format!("{size_mib}MiB_{label}")),
            |b| b.iter(|| mvm_fs::manifest::Manifest::compute(&root).unwrap()),
        );
    }
    group.finish();
}

/// The CoW-chain case: each generation is a reflink clone of its parent plus
/// a few blocks of delta. v1 hashing pays the full tree every time — depth
/// does not shrink the bill. v2 derives each generation from its parent's
/// manifest; where the filesystem proves CoW sharing (Linux reflink),
/// unchanged chunks are reused by reference instead of rehashed.
#[cfg(unix)]
fn bench_chain_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_hash_chain_depth");
    group.sample_size(10);
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("parent");
    std::fs::create_dir_all(&parent).unwrap();
    make_tree(&parent, 200, 256 * 1024, 11);
    make_blob(&parent.join("memory.bin"), 128 * 1024 * 1024, true);

    group.bench_function("v1_hash_source/depth0_parent", |b| {
        b.iter(|| mvm_fs::hash::hash_source(&parent).unwrap())
    });
    group.bench_function("v2_manifest_full/depth0_parent", |b| {
        b.iter(|| mvm_fs::manifest::Manifest::compute(&parent).unwrap())
    });

    let mut current = parent;
    let mut current_manifest = mvm_fs::manifest::Manifest::compute(&current).unwrap();
    for depth in 1..=4u32 {
        let child = tmp.path().join(format!("child{depth}"));
        mvm_fs::clone::reflink_or_copy_dir(&current, &child).unwrap();
        mutate_clone(&child, depth);
        let (derived, stats) =
            mvm_fs::manifest::Manifest::compute_from_base(&child, &current_manifest, &current)
                .unwrap();
        assert_eq!(
            derived.root_digest(),
            mvm_fs::manifest::Manifest::compute(&child)
                .unwrap()
                .root_digest(),
            "derived and full ids must agree at every depth"
        );
        eprintln!(
            "chain depth {depth}: chunks={} reused={} zero={} hashed={}",
            stats.chunks, stats.chunks_reused, stats.chunks_zero, stats.chunks_hashed
        );
        group.bench_function(
            BenchmarkId::new("v1_hash_source", format!("depth{depth}")),
            |b| b.iter(|| mvm_fs::hash::hash_source(&child).unwrap()),
        );
        {
            let base_manifest = current_manifest.clone();
            let base_tree = current.clone();
            let child_path = child.clone();
            group.bench_function(
                BenchmarkId::new("v2_manifest_delta", format!("depth{depth}")),
                |b| {
                    b.iter(|| {
                        mvm_fs::manifest::Manifest::compute_from_base(
                            &child_path,
                            &base_manifest,
                            &base_tree,
                        )
                        .unwrap()
                    })
                },
            );
        }
        current = child;
        current_manifest = derived;
    }
    group.finish();
}

#[cfg(unix)]
criterion_group!(
    benches,
    bench_tree_scaling,
    bench_blob_scaling,
    bench_chain_depth
);
#[cfg(unix)]
criterion_main!(benches);

#[cfg(not(unix))]
fn main() {}
