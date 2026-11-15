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

use std::collections::BTreeSet;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{Context, Result};

use crate::builder_job_contract::{
    BOOT_TIMINGS_FILE, INIT_LIFECYCLE_LOG, NIX_STDERR_LOG, NIX_STDOUT_LOG, RESULT_FILE,
};

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

/// Flat output files emitted by the Nix FlakeImage builder script.
///
/// This contract belongs to the Nix producer. Yocto and future producers keep
/// their own bounded input/output contracts and converge later on a verified
/// template revision.
pub const NIX_FLAKE_OUTPUT_MEMBERS: &[&str] = &[
    "rootfs.ext4",
    "vmlinux",
    "initrd",
    "rootfs-closure-paths",
    "manifest.json",
    "mvm-meta.json",
    RESULT_FILE,
    BOOT_TIMINGS_FILE,
    NIX_STDERR_LOG,
    NIX_STDOUT_LOG,
    INIT_LIFECYCLE_LOG,
];

const MAX_NIX_KERNEL_BYTES: u64 = 512 << 20;
const MAX_NIX_ROOTFS_BYTES: u64 = 7 << 30;
const MAX_NIX_LOG_BYTES: u64 = 256 << 20;
const MAX_NIX_METADATA_BYTES: u64 = 16 << 20;
const TAR_BLOCK_BYTES: usize = 512;

/// File name of the closure NAR inside a builder pack and inside the input disk.
pub const CLOSURE_FILE: &str = "nix-closure.nar";

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

/// Archive each input tree under its name, storing a symbolic link as a link.
///
/// The archiver follows links by default, which reads whatever a link names
/// on the host. An input tree can be an image's unpacked rootfs, whose links
/// the image chose — an absolute or climbing target would put a host file
/// into the guest.
fn append_input_trees<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    inputs: &[InputTree<'_>],
) -> Result<()> {
    builder.follow_symlinks(false);
    for tree in inputs {
        builder
            .append_dir_all(tree.name, tree.src)
            .with_context(|| format!("archive '{}' from {}", tree.name, tree.src.display()))?;
    }
    Ok(())
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
        append_input_trees(&mut b, inputs)?;
        if let Some(nar) = closure_nar {
            // The NAR is one file named by the caller, and may itself be a
            // link to it; that is the one path archived by what it names.
            b.follow_symlinks(true);
            // The guest imports a fixed path (`/closure-seed/<CLOSURE_FILE>`), so
            // the tar entry name comes from `CLOSURE_FILE` regardless of what the
            // source NAR happens to be called — otherwise a differently-named
            // source silently lands the guest import a no-op.
            let name = format!("{CLOSURE_SEED_TAR_DIR}/{CLOSURE_FILE}");
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
        append_input_trees(&mut b, inputs)?;
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

/// Extract a Nix FlakeImage result through its fixed flat-file contract.
///
/// The destination and each output member are created exclusively. Links,
/// devices, nested paths, duplicates, oversized members, concatenated archives,
/// and non-zero bytes after the tar terminator are refused. Files written before
/// a later refusal remain as diagnostic evidence.
pub fn read_nix_flake_output_disk(disk_image: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir(dest).with_context(|| format!("create fresh {}", dest.display()))?;
    let mut file = std::fs::File::open(disk_image)
        .with_context(|| format!("open {}", disk_image.display()))?;
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;

    loop {
        let header_bytes = read_tar_block(&mut file, "read Nix FlakeImage output header")?;
        if header_bytes.iter().all(|byte| *byte == 0) {
            let end = read_tar_block(&mut file, "read Nix FlakeImage output end marker")?;
            anyhow::ensure!(
                end.iter().all(|byte| *byte == 0),
                "Nix FlakeImage output has an incomplete tar terminator"
            );
            break;
        }
        verify_tar_checksum(&header_bytes)?;
        let header = tar::Header::from_byte_slice(&header_bytes);
        let path = header
            .path()
            .context("decode Nix FlakeImage output path")?
            .into_owned();
        let size = header.size().context("read output member size")?;
        if path == Path::new(".") || path == Path::new("./") {
            anyhow::ensure!(
                header.entry_type().is_dir() && size == 0,
                "Nix FlakeImage output root entry is not a directory"
            );
            continue;
        }
        let name = nix_flake_member_name(&path)?;
        anyhow::ensure!(
            NIX_FLAKE_OUTPUT_MEMBERS.contains(&name.as_str()),
            "undeclared Nix FlakeImage output member: {name}"
        );
        anyhow::ensure!(
            header.entry_type().is_file(),
            "Nix FlakeImage output member is not a regular file: {name}"
        );
        anyhow::ensure!(
            seen.insert(name.clone()),
            "duplicate Nix FlakeImage output member: {name}"
        );
        anyhow::ensure!(
            size <= nix_flake_member_limit(&name),
            "Nix FlakeImage output member exceeds its size limit: {name}"
        );
        total = total
            .checked_add(size)
            .context("Nix FlakeImage output size overflow")?;
        anyhow::ensure!(
            total <= OUTPUT_DISK_BYTES,
            "Nix FlakeImage output exceeds disk capacity"
        );

        let output_path = dest.join(&name);
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .with_context(|| format!("create Nix FlakeImage output member {name}"))?;
        let copied = std::io::copy(&mut (&mut file).take(size), &mut output)
            .with_context(|| format!("extract Nix FlakeImage output member {name}"))?;
        anyhow::ensure!(
            copied == size,
            "Nix FlakeImage output member was truncated: {name}"
        );
        let padding =
            (TAR_BLOCK_BYTES as u64 - size % TAR_BLOCK_BYTES as u64) % TAR_BLOCK_BYTES as u64;
        if padding != 0 {
            let mut bytes = [0_u8; TAR_BLOCK_BYTES];
            let padding = usize::try_from(padding).expect("tar padding fits one block");
            file.read_exact(&mut bytes[..padding])
                .context("read Nix FlakeImage output member padding")?;
            anyhow::ensure!(
                bytes[..padding].iter().all(|byte| *byte == 0),
                "Nix FlakeImage output member has non-zero padding: {name}"
            );
        }
    }

    let mut trailing = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut trailing)
            .context("read Nix FlakeImage output padding")?;
        if count == 0 {
            break;
        }
        anyhow::ensure!(
            trailing[..count].iter().all(|byte| *byte == 0),
            "Nix FlakeImage output has non-zero trailing data"
        );
    }
    Ok(())
}

fn nix_flake_member_limit(name: &str) -> u64 {
    match name {
        "rootfs.ext4" => MAX_NIX_ROOTFS_BYTES,
        "vmlinux" | "initrd" => MAX_NIX_KERNEL_BYTES,
        NIX_STDERR_LOG | NIX_STDOUT_LOG | INIT_LIFECYCLE_LOG => MAX_NIX_LOG_BYTES,
        _ => MAX_NIX_METADATA_BYTES,
    }
}

fn read_tar_block(reader: &mut impl Read, context: &'static str) -> Result<[u8; TAR_BLOCK_BYTES]> {
    let mut bytes = [0_u8; TAR_BLOCK_BYTES];
    reader.read_exact(&mut bytes).context(context)?;
    Ok(bytes)
}

fn verify_tar_checksum(bytes: &[u8; TAR_BLOCK_BYTES]) -> Result<()> {
    const CHECKSUM: std::ops::Range<usize> = 148..156;

    let expected = tar::Header::from_byte_slice(bytes)
        .cksum()
        .context("decode Nix FlakeImage output header checksum")?;
    let actual = bytes[..CHECKSUM.start]
        .iter()
        .chain(std::iter::repeat_n(&b' ', CHECKSUM.len()))
        .chain(bytes[CHECKSUM.end..].iter())
        .map(|byte| u64::from(*byte))
        .sum::<u64>();
    anyhow::ensure!(
        actual == u64::from(expected),
        "Nix FlakeImage output header checksum mismatch"
    );
    Ok(())
}

fn nix_flake_member_name(path: &Path) -> Result<String> {
    use std::path::Component;

    let mut components = path.components();
    let first = match components.next() {
        Some(Component::CurDir) => components.next(),
        other => other,
    };
    let Some(Component::Normal(name)) = first else {
        anyhow::bail!(
            "Nix FlakeImage output member is not flat: {}",
            path.display()
        );
    };
    anyhow::ensure!(
        components.next().is_none(),
        "Nix FlakeImage output member is not flat: {}",
        path.display()
    );
    name.to_str()
        .context("Nix FlakeImage output member name is not UTF-8")
        .map(str::to_owned)
}

/// Add search permission for group and others to each directory in `dirs`,
/// leaving every other bit as it was.
///
/// The host packs `mvm-bins` from its payload cache, which it keeps at 0700,
/// and the archive carries that mode into the guest. A guest helper that runs
/// under its own uid and is executed from that tree, such as the Stage 0 egress
/// client, then fails with `EACCES` at exec. The binaries inside are already
/// 0755, so search permission on the directories leading to them is all the
/// helper needs; read permission is not added, so the tree stays unlistable.
pub fn grant_search(dirs: &[&Path]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for dir in dirs {
        let mode = std::fs::metadata(dir)
            .with_context(|| format!("stat {}", dir.display()))?
            .permissions()
            .mode();
        let wanted = mode | 0o011;
        if wanted != mode {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(wanted))
                .with_context(|| format!("grant search on {}", dir.display()))?;
        }
    }
    Ok(())
}

/// Stream `source` as a raw tar archive onto an already-sized output disk.
///
/// This is the guest-side inverse of [`read_output_disk`]. It deliberately
/// leaves the device length unchanged: the VMM fixed that capacity when it
/// attached the disk, and tar's end marker makes any bytes after this archive
/// unreachable to the reader.
pub fn write_output_disk(source: &Path, disk_image: &Path) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(disk_image)
        .with_context(|| format!("open output disk {}", disk_image.display()))?;
    {
        let mut archive = tar::Builder::new(&file);
        archive
            .append_dir_all(".", source)
            .with_context(|| format!("archive output tree from {}", source.display()))?;
        archive.finish().context("finish output tar")?;
    }
    file.sync_data()
        .with_context(|| format!("flush output disk {}", disk_image.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write as _;

    fn nix_output_tar(path: &Path, members: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let mut archive = tar::Builder::new(file);
        for (name, body) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(body.len() as u64);
            header.set_mode(0o600);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            archive.append(&header, *body).unwrap();
        }
        archive.finish().unwrap();
    }

    fn nix_output_header(path: &Path, name: &str, size: u64, kind: tar::EntryType) {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_size(size);
        header.set_mode(0o600);
        header.set_entry_type(kind);
        header.set_cksum();
        let mut file = fs::File::create(path).unwrap();
        file.write_all(header.as_bytes()).unwrap();
        file.write_all(&[0; 1024]).unwrap();
    }

    fn nix_output_raw_entry(path: &Path, name: &str, body: &[u8], kind: tar::EntryType) {
        assert!(name.len() < 100);
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o600);
        header.set_entry_type(kind);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut file = fs::File::create(path).unwrap();
        file.write_all(header.as_bytes()).unwrap();
        file.write_all(body).unwrap();
        let padding = (TAR_BLOCK_BYTES - body.len() % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
        file.write_all(&vec![0; padding]).unwrap();
        file.write_all(&[0; 1024]).unwrap();
    }

    #[test]
    fn sector_round_up_snaps_to_512() {
        assert_eq!(sector_round_up(0), 0);
        assert_eq!(sector_round_up(1), 512);
        assert_eq!(sector_round_up(512), 512);
        assert_eq!(sector_round_up(513), 1024);
    }

    /// The input archive stores a link as a link. Following it would put the
    /// bytes of whatever the link names on the host into the guest's input.
    #[test]
    fn input_pack_archives_a_symlink_as_a_link_not_its_host_target() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("host-secret");
        fs::write(&secret, b"host bytes").unwrap();
        let work = dir.path().join("work");
        fs::create_dir_all(&work).unwrap();
        std::os::unix::fs::symlink(&secret, work.join("k")).unwrap();
        let disk = dir.path().join("input.img");

        pack_input_disk(
            &[InputTree {
                name: "work",
                src: &work,
            }],
            None,
            &disk,
            INPUT_DISK_MIN_BYTES,
        )
        .unwrap();

        let mut archive = tar::Archive::new(fs::File::open(&disk).unwrap());
        let mut saw_link = false;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new("work/k") {
                assert_eq!(entry.header().entry_type(), tar::EntryType::Symlink);
                assert_eq!(entry.link_name().unwrap().unwrap(), secret);
                saw_link = true;
            }
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).unwrap();
            assert!(
                !body.windows(10).any(|w| w == b"host bytes"),
                "the link's host target was read into the archive"
            );
        }
        assert!(saw_link);
    }

    /// The host's payload cache is 0700 and the archive carries that mode, so
    /// an unpacked `mvm-bins` is not searchable by a guest helper's uid until
    /// search permission is granted. Read permission stays off.
    #[test]
    fn a_0700_bins_tree_unpacks_unsearchable_until_search_is_granted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let bins = dir.path().join("payload");
        fs::create_dir_all(&bins).unwrap();
        fs::write(bins.join("mvm-egress-client"), b"\x7fELF").unwrap();
        fs::set_permissions(
            bins.join("mvm-egress-client"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(&bins, fs::Permissions::from_mode(0o700)).unwrap();
        let disk = dir.path().join("input.img");
        pack_input_disk(
            &[InputTree {
                name: "mvm-bins",
                src: &bins,
            }],
            None,
            &disk,
            INPUT_DISK_MIN_BYTES,
        )
        .unwrap();

        let staged = dir.path().join("staged");
        read_output_disk(&disk, &staged).unwrap();
        let unpacked = staged.join("mvm-bins");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&unpacked), 0o700);

        grant_search(&[&staged, &unpacked]).unwrap();
        assert_eq!(mode(&unpacked), 0o711);
        assert_eq!(mode(&staged) & 0o011, 0o011);
        assert_eq!(mode(&unpacked.join("mvm-egress-client")), 0o755);
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
    fn output_writer_round_trips_without_changing_attached_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let image = dir.path().join("output.img");
        let extracted = dir.path().join("extracted");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("result"), b"ok\n").unwrap();
        fs::write(source.join("nested/artifact"), b"bytes").unwrap();
        create_output_disk(&image, 1 << 20).unwrap();
        let capacity = fs::metadata(&image).unwrap().len();

        write_output_disk(&source, &image).unwrap();
        assert_eq!(fs::metadata(&image).unwrap().len(), capacity);
        read_output_disk(&image, &extracted).unwrap();
        assert_eq!(fs::read(extracted.join("result")).unwrap(), b"ok\n");
        assert_eq!(
            fs::read(extracted.join("nested/artifact")).unwrap(),
            b"bytes"
        );
    }

    #[test]
    fn strict_nix_output_extracts_the_real_producer_contract() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("output.img");
        let members = NIX_FLAKE_OUTPUT_MEMBERS
            .iter()
            .map(|name| (*name, name.as_bytes()))
            .collect::<Vec<_>>();
        nix_output_tar(&image, &members);
        let original_len = fs::metadata(&image).unwrap().len();
        fs::OpenOptions::new()
            .write(true)
            .open(&image)
            .unwrap()
            .set_len(original_len + 4096)
            .unwrap();

        let output = dir.path().join("strict");
        read_nix_flake_output_disk(&image, &output).unwrap();
        for name in NIX_FLAKE_OUTPUT_MEMBERS {
            assert_eq!(fs::read(output.join(name)).unwrap(), name.as_bytes());
        }
    }

    #[test]
    fn strict_nix_output_accepts_the_guest_tars_curdir_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("output.img");
        nix_output_raw_entry(&image, "./rootfs.ext4", b"rootfs", tar::EntryType::Regular);
        let output = dir.path().join("out");
        read_nix_flake_output_disk(&image, &output).unwrap();
        assert_eq!(fs::read(output.join("rootfs.ext4")).unwrap(), b"rootfs");
    }

    #[test]
    fn strict_nix_output_accepts_the_init_generated_lifecycle_log() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("output.img");
        nix_output_tar(&image, &[(INIT_LIFECYCLE_LOG, b"stage=cmd_sh\n")]);
        let output = dir.path().join("out");
        read_nix_flake_output_disk(&image, &output).unwrap();
        assert_eq!(
            fs::read(output.join(INIT_LIFECYCLE_LOG)).unwrap(),
            b"stage=cmd_sh\n"
        );
    }

    #[test]
    fn strict_nix_output_refuses_preexisting_destination_and_member_state() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("output.img");
        nix_output_tar(&image, &[("rootfs.ext4", b"rootfs")]);
        let output = dir.path().join("out");
        fs::create_dir(&output).unwrap();
        std::os::unix::fs::symlink("/tmp", output.join("rootfs.ext4")).unwrap();
        let error = read_nix_flake_output_disk(&image, &output).unwrap_err();
        assert!(error.to_string().contains("fresh"), "{error:#}");
    }

    #[test]
    fn strict_nix_output_refuses_undeclared_nested_duplicate_and_link_members() {
        for (name, expected) in [
            ("unexpected", "undeclared"),
            ("nested/rootfs.ext4", "not flat"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let image = dir.path().join("output.img");
            nix_output_tar(&image, &[(name, b"bytes")]);
            let error = read_nix_flake_output_disk(&image, &dir.path().join("out")).unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }

        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("duplicate.img");
        nix_output_tar(&image, &[("rootfs.ext4", b"one"), ("rootfs.ext4", b"two")]);
        let error = read_nix_flake_output_disk(&image, &dir.path().join("duplicate")).unwrap_err();
        assert!(error.to_string().contains("duplicate"), "{error:#}");

        let image = dir.path().join("link.img");
        nix_output_header(&image, "rootfs.ext4", 0, tar::EntryType::Symlink);
        let error = read_nix_flake_output_disk(&image, &dir.path().join("links")).unwrap_err();
        assert!(error.to_string().contains("regular file"), "{error:#}");
    }

    #[test]
    fn strict_nix_output_checks_size_before_writing_and_retains_prior_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("oversize.img");
        nix_output_header(
            &image,
            "manifest.json",
            MAX_NIX_METADATA_BYTES + 1,
            tar::EntryType::Regular,
        );
        let output = dir.path().join("oversize");
        let error = read_nix_flake_output_disk(&image, &output).unwrap_err();
        assert!(error.to_string().contains("size limit"), "{error:#}");
        assert!(!output.join("manifest.json").exists());

        let image = dir.path().join("partial.img");
        nix_output_tar(
            &image,
            &[("rootfs.ext4", b"evidence"), ("unexpected", b"bad")],
        );
        let output = dir.path().join("partial");
        let error = read_nix_flake_output_disk(&image, &output).unwrap_err();
        assert!(error.to_string().contains("undeclared"), "{error:#}");
        assert_eq!(fs::read(output.join("rootfs.ext4")).unwrap(), b"evidence");
    }

    #[test]
    fn strict_nix_output_rejects_extensions_before_reading_their_bodies() {
        for kind in [tar::EntryType::new(b'x'), tar::EntryType::new(b'L')] {
            let dir = tempfile::tempdir().unwrap();
            let image = dir.path().join("extension.img");
            nix_output_header(&image, "manifest.json", OUTPUT_DISK_BYTES, kind);
            let output = dir.path().join("out");
            let error = read_nix_flake_output_disk(&image, &output).unwrap_err();
            assert!(error.to_string().contains("regular file"), "{error:#}");
            assert!(!output.join("manifest.json").exists());
        }
    }

    #[test]
    fn strict_nix_output_accepts_an_image_sized_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("initrd.img");
        let initrd = vec![0x5a; 17 << 20];
        nix_output_tar(&image, &[("initrd", &initrd)]);
        let output = dir.path().join("out");
        read_nix_flake_output_disk(&image, &output).unwrap();
        assert_eq!(fs::metadata(output.join("initrd")).unwrap().len(), 17 << 20);
    }

    #[test]
    fn generic_output_transport_still_accepts_non_flake_shell_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("verity.img");
        nix_output_tar(
            &image,
            &[("rootfs.verity", b"tree"), ("rootfs.roothash", b"digest")],
        );
        let output = dir.path().join("out");
        read_output_disk(&image, &output).unwrap();
        assert_eq!(fs::read(output.join("rootfs.verity")).unwrap(), b"tree");
        assert_eq!(fs::read(output.join("rootfs.roothash")).unwrap(), b"digest");
    }

    #[test]
    fn strict_nix_output_refuses_nonzero_trailing_data() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("trailing.img");
        nix_output_tar(&image, &[("manifest.json", b"{}")]);
        fs::OpenOptions::new()
            .append(true)
            .open(&image)
            .unwrap()
            .write_all(b"another archive")
            .unwrap();
        let error = read_nix_flake_output_disk(&image, &dir.path().join("out")).unwrap_err();
        assert!(error.to_string().contains("non-zero trailing"), "{error:#}");
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
