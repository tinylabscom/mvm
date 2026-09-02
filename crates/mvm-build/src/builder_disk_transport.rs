//! Disk-only job/artifact transport for the builder VM.
//!
//! A Rootfs-image libkrun builder VM — the common `machine build` / `machine
//! run --flake` case — moves the job in and the artifacts out this way. So
//! does the hvf VMM, which has no virtio-fs at all; since its host is macOS,
//! which can neither format nor read an ext4, the transport must never
//! require host-side access to a guest filesystem.
//!
//! The transport is therefore a **tar written raw onto a disk image**, no
//! filesystem on the transport disks:
//!
//! - Input: the host packs `{job, work, mvm-bins}` — plus, when the resolved
//!   builder image carries one, an optional seeded Nix store closure NAR under
//!   `closure-seed/` — into a tar and writes it, zero-padded to the disk size,
//!   at the input image. The guest reads the raw disk and `tar x`.
//! - Output: the guest packs its artifacts into a tar written raw onto the output
//!   disk; the host reads the raw disk and `tar x` here.
//!
//! Both sides only ever run `tar`. tar's end-of-archive marker (two zero blocks)
//! stops extraction before the disk's zero padding, so a fixed-size disk carrying
//! a shorter archive round-trips cleanly.

use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result};

/// virtio-blk serves whole 512-byte sectors; transport images are sized up to a
/// sector boundary so the guest sees an exact capacity.
const SECTOR: u64 = 512;

/// Floor for an input disk. [`pack_input_disk`] grows past it to hold the
/// archive, so this only matters when the inputs are small — it keeps a
/// persistent session's disk from shrinking to nothing between dispatches,
/// which would change the capacity a running guest already read.
pub const INPUT_DISK_MIN_BYTES: u64 = 16 << 20;

/// Capacity for an output disk. Has to hold a whole guest image tar — a
/// `rootfs.ext4` plus a kernel — since the guest writes the archive raw and
/// cannot grow the device it was handed.
pub const OUTPUT_DISK_BYTES: u64 = 8192 << 20;

/// Archive directory the optional seeded-closure NAR rides under, mirroring
/// the guest's `/closure-seed` mount point
/// (`mvm-host-vm-init`'s `CLOSURE_SEED_NAR` contract). Kept in sync with the
/// guest by convention, same as `job`/`work`/`mvm-bins` above.
const CLOSURE_SEED_TAR_DIR: &str = "closure-seed";

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
///
/// `closure_nar`, when `Some`, is a single file (a builder pack's optional
/// seeded Nix store closure) archived at `closure-seed/<file name>` alongside
/// the input trees. `None` — the common case until a pack carries a closure —
/// packs exactly the trees, unchanged from before this parameter existed.
pub fn pack_input_disk(
    inputs: &[InputTree<'_>],
    closure_nar: Option<&Path>,
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
        if let Some(nar) = closure_nar {
            // The guest imports a fixed path (`/closure-seed/<CLOSURE_FILE>`), so
            // the tar entry name comes from `CLOSURE_FILE` regardless of what the
            // source NAR happens to be called — otherwise a differently-named
            // source silently lands the guest import a no-op.
            let name = format!(
                "{CLOSURE_SEED_TAR_DIR}/{}",
                crate::builder_pack::CLOSURE_FILE
            );
            b.append_path_with_name(nar, &name)
                .with_context(|| format!("archive closure NAR from {}", nar.display()))?;
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

/// Rewrite a **already-attached** input disk in place, for one dispatch of a
/// persistent builder.
///
/// [`pack_input_disk`] sizes the file to its contents with `set_len`, which is
/// right before boot and wrong afterwards. A running VM's `DiskImage` captured
/// the file's length **once, when it opened it**, and zero-fills every guest
/// read past that offset. Grow the file mid-session and the guest sees a
/// truncated archive — `tar` stops at whatever it finds, which is not an error
/// it can report as one. So this never changes the length: it writes within the
/// capacity the VM booted with, and refuses when the archive will not fit rather
/// than producing a disk that reads as silently short.
///
/// Only the `job` tree is repacked in practice. `work` and `mvm-bins` were
/// bind-mounted by the guest at boot and are never re-read, so re-archiving a
/// large workspace on every dispatch would cost real time for no effect.
///
/// The trailing bytes of the previous dispatch's archive are left alone.
/// `tar::Builder::finish` writes the end-of-archive marker (two zero blocks),
/// and extraction stops there, so stale tail bytes are unreachable as archive
/// content — the same property that lets a fixed-size disk carry a short
/// archive at boot.
pub fn repack_input_disk_in_place(inputs: &[InputTree<'_>], image: &Path) -> Result<()> {
    let capacity = std::fs::metadata(image)
        .with_context(|| format!("stat {} to learn its capacity", image.display()))?
        .len();
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        for tree in inputs {
            b.append_dir_all(tree.name, tree.src)
                .with_context(|| format!("archive '{}' from {}", tree.name, tree.src.display()))?;
        }
        b.finish().context("finish dispatch input tar")?;
    }
    if buf.len() as u64 > capacity {
        anyhow::bail!(
            "dispatch inputs are {} bytes but the attached input disk holds {capacity}; \
             the guest reads zeros past its booted capacity, so a larger archive would \
             extract as silently truncated rather than fail",
            buf.len()
        );
    }
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(image)
        .with_context(|| format!("open {} to repack", image.display()))?;
    f.write_all_at(&buf, 0)
        .with_context(|| format!("write dispatch inputs to {}", image.display()))?;
    // The guest reads this device on the next frame it is sent. Without the
    // flush the write can still be in the host's page cache while the guest's
    // pread races it, and the failure looks like a corrupt archive.
    f.sync_data()
        .with_context(|| format!("flush {}", image.display()))?;
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
            None,
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
    fn closure_nar_when_present_rides_the_input_disk_under_closure_seed() {
        let dir = tempfile::tempdir().unwrap();
        let job = dir.path().join("job");
        fs::create_dir_all(&job).unwrap();
        fs::write(job.join("cmd.sh"), b"#!/bin/sh\n").unwrap();
        // Source deliberately NOT named `nix-closure.nar` — the tar entry name
        // must still come from `CLOSURE_FILE` so the guest finds it.
        let nar = dir.path().join("some-source.nar");
        fs::write(&nar, b"pretend-nar-bytes").unwrap();

        let image = dir.path().join("input.img");
        pack_input_disk(
            &[InputTree {
                name: "job",
                src: &job,
            }],
            Some(&nar),
            &image,
            1 << 20,
        )
        .unwrap();

        let dest = dir.path().join("out");
        read_output_disk(&image, &dest).unwrap();
        assert_eq!(
            fs::read(dest.join("closure-seed/nix-closure.nar")).unwrap(),
            b"pretend-nar-bytes"
        );
    }

    #[test]
    fn no_closure_nar_means_no_closure_seed_entry() {
        // The common case today: a builder image with no seeded closure packs
        // exactly the input trees, with no `closure-seed/` directory at all —
        // zero behavior change from before this parameter existed.
        let dir = tempfile::tempdir().unwrap();
        let job = dir.path().join("job");
        fs::create_dir_all(&job).unwrap();
        fs::write(job.join("cmd.sh"), b"#!/bin/sh\n").unwrap();

        let image = dir.path().join("input.img");
        pack_input_disk(
            &[InputTree {
                name: "job",
                src: &job,
            }],
            None,
            &image,
            1 << 20,
        )
        .unwrap();

        let dest = dir.path().join("out");
        read_output_disk(&image, &dest).unwrap();
        assert!(!dest.join("closure-seed").exists());
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
            None,
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

    /// The invariant a running VM depends on: its `DiskImage` captured the
    /// file's length when it opened it and zero-fills reads past that offset,
    /// so a repack that changed the length would be read as a short archive.
    #[test]
    fn repacking_in_place_never_changes_the_disk_length() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("job-1");
        fs::create_dir_all(&first).unwrap();
        fs::write(first.join("cmd.sh"), vec![b'a'; 4096]).unwrap();
        let image = dir.path().join("in.img");
        pack_input_disk(
            &[InputTree {
                name: "job",
                src: &first,
            }],
            None,
            &image,
            64 * 1024,
        )
        .unwrap();
        let capacity = fs::metadata(&image).unwrap().len();

        // A second dispatch with a much smaller payload.
        let second = dir.path().join("job-2");
        fs::create_dir_all(&second).unwrap();
        fs::write(second.join("cmd.sh"), b"echo hi").unwrap();
        repack_input_disk_in_place(
            &[InputTree {
                name: "job",
                src: &second,
            }],
            &image,
        )
        .unwrap();

        assert_eq!(
            fs::metadata(&image).unwrap().len(),
            capacity,
            "the attached disk's length must not move under the running guest"
        );
        // And the new payload is what extracts — the previous dispatch's longer
        // archive is past the end-of-archive marker and unreachable.
        let dest = dir.path().join("x");
        read_output_disk(&image, &dest).unwrap();
        assert_eq!(fs::read(dest.join("job/cmd.sh")).unwrap(), b"echo hi");
    }

    /// Refusing is the whole point: a too-large archive written into a fixed
    /// capacity extracts as silently truncated, which no layer below reports.
    #[test]
    fn repacking_refuses_inputs_larger_than_the_booted_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("job-small");
        fs::create_dir_all(&small).unwrap();
        fs::write(small.join("cmd.sh"), b"x").unwrap();
        let image = dir.path().join("in.img");
        pack_input_disk(
            &[InputTree {
                name: "job",
                src: &small,
            }],
            None,
            &image,
            SECTOR,
        )
        .unwrap();
        let capacity = fs::metadata(&image).unwrap().len();

        let big = dir.path().join("job-big");
        fs::create_dir_all(&big).unwrap();
        fs::write(big.join("cmd.sh"), vec![b'z'; 512 * 1024]).unwrap();
        let err = repack_input_disk_in_place(
            &[InputTree {
                name: "job",
                src: &big,
            }],
            &image,
        )
        .expect_err("an oversized dispatch payload must refuse");

        assert!(
            err.to_string().contains("input disk holds"),
            "the refusal must name the capacity: {err}"
        );
        assert_eq!(
            fs::metadata(&image).unwrap().len(),
            capacity,
            "a refused repack must not have resized the disk on its way out"
        );
    }
}
