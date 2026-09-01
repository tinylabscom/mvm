//! How a persistent builder session moves a job in and its artifacts out when
//! the guest has no virtio-fs.
//!
//! A share-backed session needs none of this: `/job` and `/out` are the same
//! host directory the guest writes into, so staging a file *is* delivering it.
//! A disk-backed one exchanges the same payloads as raw tars on two block
//! devices — [`crate::builder_disk_transport`] is the codec, and this module is
//! the per-dispatch lifetime on top of it.
//!
//! The ordering that makes rewriting a disk under a running guest safe is not
//! locking: the host finishes writing before it sends `Run`, and dispatches
//! serialize behind the supervisor's mutex, so no guest read ever straddles a
//! host write.

use std::path::{Path, PathBuf};

use crate::persistent_builder::{ARTIFACT_SUBDIR, artifact_dir_for};

/// The raw block devices a disk-backed session exchanges jobs and artifacts
/// over, in place of virtio-fs shares.
///
/// The two travel together because neither is usable alone: the host writes a
/// job onto the input disk and reads that job's artifacts off the output disk,
/// so a record carrying one and not the other describes no working session.
///
/// Absent on a session whose guest mounts shares — today the libkrun
/// persistent builder, whose VMM has virtio-fs and still uses it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionDiskTransport {
    /// Rewritten with the next job's payload before each `Run`. Read-only to
    /// the guest, which re-extracts only its `job` member per dispatch.
    pub input_disk: PathBuf,
    /// The guest writes each dispatch's artifact tar here; the host reads it
    /// back after that dispatch's `Result`.
    pub output_disk: PathBuf,
}

/// The in-guest directory a dispatch's `cmd.sh` must copy artifacts into.
///
/// The two transports collect from different places, and a script pointed at
/// the wrong one succeeds while producing nothing the host can read:
///
/// - **Shares**: `/job` and `/out` are the same host directory, so writing to
///   `/job/<job_id>/out` puts bytes exactly where [`artifact_dir_for`] looks.
/// - **Disks**: `/job` is a bind onto the guest's own input stage and is never
///   read back. The guest tars `/out` — and only `/out` — onto the output
///   disk, so that is the one directory whose contents survive the boundary.
pub fn guest_artifact_dir(transport: Option<&SessionDiskTransport>, job_id: &str) -> String {
    match transport {
        Some(_) => format!("/{ARTIFACT_SUBDIR}"),
        None => format!("/job/{job_id}/{ARTIFACT_SUBDIR}"),
    }
}

/// Rewrite the input disk so it carries exactly this dispatch's job payload.
///
/// Only the `job` member is written: `work`, `mvm-bins` and the closure seed
/// were packed at boot and are bind-mounted in the guest, so re-sending a large
/// workspace tree per dispatch would cost real time for no effect.
///
/// The disk never shrinks. Its capacity was read by the guest's virtio-blk
/// driver at boot and cannot be renegotiated, so the current file length is the
/// floor every repack pads back up to.
pub fn repack_dispatch_input(
    transport: &SessionDiskTransport,
    session_job_dir: &Path,
    job_id: &str,
) -> std::io::Result<()> {
    let floor = std::fs::metadata(&transport.input_disk)?.len();
    let job_sub = session_job_dir.join(job_id);
    crate::builder_disk_transport::pack_input_disk(
        &[crate::builder_disk_transport::InputTree {
            // Archived under the job id so the guest resolves the same
            // `/job/<job_id>/cmd.sh` the `Run` frame's relpath names.
            name: &format!("job/{job_id}"),
            src: &job_sub,
        }],
        None,
        &transport.input_disk,
        floor,
    )
    .map_err(std::io::Error::other)
}

/// Extract the artifact tar the guest wrote for this dispatch into the host
/// path [`artifact_dir_for`] names, so a disk-backed session presents the same
/// on-disk layout a share-backed one does and every caller downstream is
/// unchanged.
pub fn read_dispatch_artifacts(
    transport: &SessionDiskTransport,
    session_job_dir: &Path,
    job_id: &str,
) -> std::io::Result<PathBuf> {
    let dest = artifact_dir_for(session_job_dir, job_id);
    crate::builder_disk_transport::read_output_disk(&transport.output_disk, &dest)
        .map_err(std::io::Error::other)?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport_at(dir: &Path) -> SessionDiskTransport {
        SessionDiskTransport {
            input_disk: dir.join("input.img"),
            output_disk: dir.join("output.img"),
        }
    }

    #[test]
    fn guest_artifact_dir_follows_what_each_transport_collects() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let t = transport_at(scratch.path());
        // Disks: the guest tars `/out` and nothing else.
        assert_eq!(guest_artifact_dir(Some(&t), "job-1"), "/out");
        // Shares: `/job` and `/out` are one host directory, and the host
        // reads the per-dispatch subdir under it.
        assert_eq!(guest_artifact_dir(None, "job-1"), "/job/job-1/out");
    }

    #[test]
    fn a_repacked_input_disk_carries_only_this_dispatch_under_its_job_id() {
        // What the guest does on `Run` is `tar xf <dev> -C <stage> job`, then
        // resolves `/job/<job_id>/cmd.sh`. So the archive has to name the job
        // id, and must not drag along a previous dispatch — whose `out/` holds
        // a whole rootfs image by the time the next build starts.
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().join("jobs");
        let t = transport_at(scratch.path());
        crate::builder_disk_transport::create_output_disk(&t.input_disk, 1 << 20)
            .expect("seed the input disk");

        for id in ["old-job", "new-job"] {
            let sub = job_dir.join(id);
            std::fs::create_dir_all(sub.join("out")).unwrap();
            std::fs::write(sub.join("cmd.sh"), format!("#!/bin/sh\necho {id}\n")).unwrap();
        }
        std::fs::write(
            job_dir.join("old-job").join("out").join("rootfs.ext4"),
            vec![0u8; 4096],
        )
        .unwrap();

        repack_dispatch_input(&t, &job_dir, "new-job").expect("repack");

        let dest = scratch.path().join("unpacked");
        crate::builder_disk_transport::read_output_disk(&t.input_disk, &dest).expect("read back");
        assert!(dest.join("job/new-job/cmd.sh").is_file());
        assert!(
            !dest.join("job/old-job").exists(),
            "a repack must not carry the previous dispatch's artifacts"
        );
    }

    #[test]
    fn a_repacked_input_disk_never_shrinks_below_its_boot_capacity() {
        // The guest's virtio-blk driver read this device's capacity at boot and
        // cannot renegotiate it. A repack that shortened the file would leave
        // the guest reading past the end of it.
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().join("jobs");
        std::fs::create_dir_all(job_dir.join("j1")).unwrap();
        std::fs::write(job_dir.join("j1").join("cmd.sh"), b"#!/bin/sh\n").unwrap();
        let t = transport_at(scratch.path());
        crate::builder_disk_transport::create_output_disk(&t.input_disk, 8 << 20)
            .expect("seed a large input disk");
        let boot_len = std::fs::metadata(&t.input_disk).unwrap().len();

        repack_dispatch_input(&t, &job_dir, "j1").expect("repack");

        assert_eq!(
            std::fs::metadata(&t.input_disk).unwrap().len(),
            boot_len,
            "the disk shrank under the guest's feet"
        );
    }

    #[test]
    fn read_dispatch_artifacts_lands_them_where_artifact_dir_for_looks() {
        // This is what makes every caller downstream transport-blind: after the
        // read, a disk-backed session presents the same on-disk layout a
        // share-backed one does.
        let scratch = tempfile::tempdir().expect("tempdir");
        let job_dir = scratch.path().join("jobs");
        let t = transport_at(scratch.path());

        // Stand in for the guest: a tar of `/out`'s contents, written raw.
        let guest_out = scratch.path().join("guest-out");
        std::fs::create_dir_all(&guest_out).unwrap();
        std::fs::write(guest_out.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(guest_out.join("rootfs.ext4"), b"rootfs").unwrap();
        crate::builder_disk_transport::pack_input_disk(
            &[crate::builder_disk_transport::InputTree {
                name: ".",
                src: &guest_out,
            }],
            None,
            &t.output_disk,
            1 << 20,
        )
        .expect("write the output disk");

        let dest = read_dispatch_artifacts(&t, &job_dir, "j1").expect("read back");
        assert_eq!(dest, artifact_dir_for(&job_dir, "j1"));
        assert_eq!(std::fs::read(dest.join("vmlinux")).unwrap(), b"kernel");
        assert_eq!(std::fs::read(dest.join("rootfs.ext4")).unwrap(), b"rootfs");
    }
}
