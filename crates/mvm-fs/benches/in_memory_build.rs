//! Criterion benchmarks for the in-memory / streamed build paths.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use mvm_fs::oci::layer::verify_and_unpack_layer_file;
use mvm_fs::oci::{LayerDescriptor, UnpackOptions};
use mvm_fs::rootfs::{MaterializeOptions, build_ext4_pure};
use sha2::Digest;

fn make_fixture_tree(root: &Path, files: usize, file_size: usize) {
    for d in 0..10 {
        std::fs::create_dir_all(root.join(format!("dir{d:02}"))).unwrap();
    }
    let payload = vec![0xabu8; file_size];
    for i in 0..files {
        let dir = format!("dir{:02}", i % 10);
        std::fs::write(root.join(&dir).join(format!("file{i:04}.bin")), &payload).unwrap();
    }
}

fn bench_build_ext4_pure(c: &mut Criterion) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("rootfs");
    make_fixture_tree(&root, 100, 64 * 1024);
    let options = MaterializeOptions::default();

    c.bench_function("build_ext4_pure_100_files_64k", |b| {
        b.iter(|| build_ext4_pure(&root, &options).unwrap())
    });
}

fn gzip_tar_layer(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(*name).unwrap();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, *bytes).unwrap();
    }
    let raw = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&raw).unwrap();
    encoder.finish().unwrap()
}

fn bench_verify_and_unpack_layer_file(c: &mut Criterion) {
    let layer_bytes = gzip_tar_layer(&[("bench.txt", &[0xabu8; 256 * 1024])]);
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&layer_bytes)));
    let layer = LayerDescriptor {
        digest,
        size: layer_bytes.len() as u64,
        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("verify_and_unpack_layer_file_256k", |b| {
        b.iter_batched(
            || {
                let tmp = tempfile::tempdir().unwrap();
                let cache = tmp.path().join("layer.tar.gz");
                let unpacked = tmp.path().join("unpacked");
                std::fs::create_dir_all(&unpacked).unwrap();
                std::fs::write(&cache, &layer_bytes).unwrap();
                (tmp, cache, unpacked)
            },
            |(_tmp, cache, unpacked)| {
                rt.block_on(verify_and_unpack_layer_file(
                    &layer,
                    &cache,
                    &unpacked,
                    &UnpackOptions::default(),
                    &HashSet::new(),
                ))
                .unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_build_ext4_pure,
    bench_verify_and_unpack_layer_file
);
criterion_main!(benches);
