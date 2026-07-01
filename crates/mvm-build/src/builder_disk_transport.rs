//! Disk-only job/artifact transport for the in-house-VMM builder.
//!
//! The libkrun/vz builder moves the job in and the artifacts out over virtio-fs
//! shares (host directories). The in-house VMM has no virtio-fs, and the host is
//! macOS — which can neither format nor read an ext4 — so the transport must
//! never require host-side access to a guest filesystem.
//!
//! The transport is therefore a **tar written raw onto a disk image**, no
//! filesystem on the transport disks:
//!
//! - Input: the host packs `{job, work, mvm-bins}` into a tar and writes it,
//!   zero-padded to the disk size, at the input image. The guest reads the raw
//!   disk and `tar x`.
//! - Output: the guest packs its artifacts into a tar written raw onto the output
//!   disk; the host reads the raw disk and `tar x` here.
//!
//! Both sides only ever run `tar`. tar's end-of-archive marker (two zero blocks)
//! stops extraction before the disk's zero padding, so a fixed-size disk carrying
//! a shorter archive round-trips cleanly.

use std::path::Path;

use anyhow::{Context, Result};

/// virtio-blk serves whole 512-byte sectors; transport images are sized up to a
/// sector boundary so the guest sees an exact capacity.
const SECTOR: u64 = 512;

/// One named tree placed in the transport tar. `name` is the archive prefix the
/// guest mounts/binds (e.g. `"job"`, `"work"`, `"mvm-bins"`); `src` is the host
/// directory whose contents are archived under `name/`.
pub struct InputTree<'a> {
    pub name: &'a str,
    pub src: &'a Path,
}

/// Round `n` up to the next 512-byte sector.
fn sector_round_up(n: u64) -> u64 {
    n.div_ceil(SECTOR) * SECTOR
}

/// Pack `inputs` into a tar and write it at `out_image`, zero-padded to at least
/// `min_disk_size` (rounded up to a sector). `min_disk_size` is a floor: the disk
/// always grows to hold the archive, so the inputs never overflow it.
pub fn pack_input_disk(
    inputs: &[InputTree<'_>],
    out_image: &Path,
    min_disk_size: u64,
) -> Result<()> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        for tree in inputs {
            b.append_dir_all(tree.name, tree.src)
                .with_context(|| format!("archive '{}' from {}", tree.name, tree.src.display()))?;
        }
        b.finish().context("finish input tar")?;
    }
    let disk_size = sector_round_up(min_disk_size.max(buf.len() as u64));
    std::fs::write(out_image, &buf).with_context(|| format!("write {}", out_image.display()))?;
    // Extend (sparsely) to the sector-aligned capacity so the trailing bytes past
    // the tar EOF marker are zeros.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(out_image)
        .with_context(|| format!("open {} to size", out_image.display()))?;
    f.set_len(disk_size)
        .with_context(|| format!("size input disk to {disk_size}"))?;
    Ok(())
}

/// Create an empty, zeroed output disk of `size` bytes (sector-aligned) for the
/// guest to write its artifact tar onto.
pub fn create_output_disk(image: &Path, size: u64) -> Result<()> {
    let f = std::fs::File::create(image).with_context(|| format!("create {}", image.display()))?;
    f.set_len(sector_round_up(size))
        .with_context(|| format!("size output disk {}", image.display()))?;
    Ok(())
}

/// Read the raw output disk the guest wrote (a tar, zero-padded) and extract it
/// into `dest`. Extraction stops at the tar EOF marker, ignoring the disk's
/// trailing zeros.
pub fn read_output_disk(disk_image: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    let f = std::fs::File::open(disk_image)
        .with_context(|| format!("open {}", disk_image.display()))?;
    let mut ar = tar::Archive::new(f);
    ar.unpack(dest)
        .with_context(|| format!("extract output tar into {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sector_round_up_snaps_to_512() {
        assert_eq!(sector_round_up(0), 0);
        assert_eq!(sector_round_up(1), 512);
        assert_eq!(sector_round_up(512), 512);
        assert_eq!(sector_round_up(513), 1024);
    }

    #[test]
    fn input_pack_then_output_read_round_trips_the_trees() {
        // Both directions use the same tar-on-a-raw-disk format, so packing an
        // input disk and reading it back as an "output" disk exercises the whole
        // codec: files land under their tree name, disk padding is ignored.
        let dir = tempfile::tempdir().unwrap();
        let job = dir.path().join("job");
        let work = dir.path().join("work");
        fs::create_dir_all(&job).unwrap();
        fs::create_dir_all(work.join("sub")).unwrap();
        fs::write(job.join("cmd.sh"), b"#!/bin/sh\nnix build\n").unwrap();
        fs::write(work.join("flake.nix"), b"{ }").unwrap();
        fs::write(work.join("sub/dep.txt"), b"dep").unwrap();

        let image = dir.path().join("input.img");
        pack_input_disk(
            &[
                InputTree {
                    name: "job",
                    src: &job,
                },
                InputTree {
                    name: "work",
                    src: &work,
                },
            ],
            &image,
            1 << 20, // 1 MiB min
        )
        .unwrap();

        // Sized to (at least) the requested minimum, sector-aligned.
        let len = fs::metadata(&image).unwrap().len();
        assert!(len >= (1 << 20));
        assert_eq!(len % SECTOR, 0);

        let dest = dir.path().join("out");
        read_output_disk(&image, &dest).unwrap();
        assert_eq!(
            fs::read_to_string(dest.join("job/cmd.sh")).unwrap(),
            "#!/bin/sh\nnix build\n"
        );
        assert_eq!(
            fs::read_to_string(dest.join("work/flake.nix")).unwrap(),
            "{ }"
        );
        assert_eq!(
            fs::read_to_string(dest.join("work/sub/dep.txt")).unwrap(),
            "dep"
        );
    }

    #[test]
    fn disk_grows_past_the_floor_to_hold_larger_inputs() {
        // A 512-byte floor can't hold a 4 KiB file's tar; the disk grows to fit.
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big");
        fs::create_dir_all(&big).unwrap();
        fs::write(big.join("blob"), vec![7u8; 4096]).unwrap();
        let image = dir.path().join("grown.img");
        pack_input_disk(
            &[InputTree {
                name: "big",
                src: &big,
            }],
            &image,
            512,
        )
        .unwrap();
        let len = fs::metadata(&image).unwrap().len();
        assert!(len >= 4096, "disk grew to hold the 4 KiB blob, got {len}");
        assert_eq!(len % SECTOR, 0);
        // And it still round-trips.
        let dest = dir.path().join("x");
        read_output_disk(&image, &dest).unwrap();
        assert_eq!(fs::read(dest.join("big/blob")).unwrap(), vec![7u8; 4096]);
    }

    #[test]
    fn create_output_disk_is_sector_aligned_and_zeroed() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("out.img");
        create_output_disk(&image, 1000).unwrap();
        let bytes = fs::read(&image).unwrap();
        assert_eq!(bytes.len() as u64 % SECTOR, 0);
        assert!(bytes.iter().all(|&b| b == 0));
    }
}
