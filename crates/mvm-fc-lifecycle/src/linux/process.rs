use std::fs::File;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use mvm_vmm::host::process_liveness::{GuardedSignal, RetainedProcess};

use super::files::{bounded_read, object, open_at, open_path, trusted_file};
use crate::core::{Evidence, Processes};
use crate::identity::{cmdline_binds, path_is_valid, same_evidence, same_pin};
use crate::protocol::{Operation, Status};
use crate::{Error, FIRECRACKER, Result};

pub(crate) struct LinuxProcesses;

pub(crate) struct LinuxHandle {
    process: RetainedProcess,
    pins: Pins,
}

struct Pins {
    directory: File,
    socket: File,
    executable: File,
}

impl Pins {
    fn validate(&self, expected: &Evidence, fresh: &Evidence) -> Result<()> {
        same_pin(
            &expected.directory,
            &object(&self.directory.metadata()?),
            &fresh.directory,
        )?;
        same_pin(
            &expected.socket,
            &object(&self.socket.metadata()?),
            &fresh.socket,
        )?;
        same_pin(
            &expected.executable,
            &object(&self.executable.metadata()?),
            &fresh.executable,
        )?;
        Ok(())
    }
}

impl LinuxProcesses {
    fn snapshot(&self, handle: &RetainedProcess, expected: &Evidence) -> Result<(Evidence, Pins)> {
        if !path_is_valid(&expected.state_dir)
            || !path_is_valid(&expected.api_socket)
            || std::path::Path::new(&expected.api_socket).parent()
                != Some(std::path::Path::new(&expected.state_dir))
        {
            return Err(Error::Refused);
        }
        let trusted = trusted_file(FIRECRACKER)?;
        // Only these two kernel proc links are intentionally followed.
        let executable = File::open(format!("/proc/{}/exe", expected.pid))?;
        if object(&trusted.metadata()?) != object(&executable.metadata()?)
            || std::fs::read_link(format!("/proc/{}/exe", expected.pid))?
                != std::path::Path::new(FIRECRACKER)
        {
            return Err(Error::Refused);
        }
        let status = bounded_read(File::open(format!("/proc/{}/status", expected.pid))?)?;
        let status = std::str::from_utf8(&status).map_err(|_| Error::Refused)?;
        if !status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .is_some_and(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.len() == 5 && fields[1..].iter().all(|uid| *uid == "0")
            })
        {
            return Err(Error::Refused);
        }
        let cmdline = bounded_read(File::open(format!("/proc/{}/cmdline", expected.pid))?)?;
        if !cmdline_binds(&cmdline, &expected.api_socket) {
            return Err(Error::Refused);
        }
        let directory = open_path(
            &expected.state_dir,
            Some(expected.owner_uid),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let dm = directory.metadata()?;
        if dm.uid() != expected.owner_uid || dm.mode() & 0o6022 != 0 {
            return Err(Error::Refused);
        }
        let name = std::path::Path::new(&expected.api_socket)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Error::Refused)?;
        let socket = open_at(&directory, name, libc::O_PATH, 0)?;
        let sm = socket.metadata()?;
        if !sm.file_type().is_socket() || ![0, expected.owner_uid].contains(&sm.uid()) {
            return Err(Error::Refused);
        }
        let boot_id = String::from_utf8(bounded_read(File::open(
            "/proc/sys/kernel/random/boot_id",
        )?)?)
        .map_err(|_| Error::Refused)?
        .trim()
        .to_string();
        if boot_id.len() != 36 {
            return Err(Error::Refused);
        }
        let evidence = Evidence {
            pid: expected.pid,
            start_ticks: handle.start_ticks(),
            owner_uid: expected.owner_uid,
            state_dir: expected.state_dir.clone(),
            api_socket: expected.api_socket.clone(),
            directory: object(&dm),
            socket: object(&sm),
            executable: object(&trusted.metadata()?),
            boot_id,
        };
        Ok((
            evidence,
            Pins {
                directory,
                socket,
                executable: trusted,
            },
        ))
    }

    fn checked(&self, handle: &LinuxHandle, evidence: &Evidence, stop: bool) -> Result<Status> {
        let accept = |path: &std::path::Path| {
            path == std::path::Path::new(FIRECRACKER)
                && self
                    .snapshot(&handle.process, evidence)
                    .and_then(|(current, _fresh_pins)| {
                        same_evidence(evidence, &current)?;
                        handle.pins.validate(evidence, &current)
                    })
                    .is_ok()
        };
        let result = if stop {
            handle.process.signal(libc::SIGTERM, &accept)?
        } else {
            handle.process.check(&accept)?
        };
        match result {
            GuardedSignal::Sent => Ok(if stop {
                Status::StopRequested
            } else {
                Status::Running
            }),
            GuardedSignal::Exited => Ok(Status::Exited),
            GuardedSignal::Refused(_) => Err(Error::Refused),
        }
    }
}

impl Processes for LinuxProcesses {
    type Handle = LinuxHandle;
    fn capture(&self, operation: &Operation) -> Result<(Self::Handle, Evidence)> {
        let Operation::Register {
            pid,
            owner_uid,
            state_dir,
            api_socket,
        } = operation
        else {
            return Err(Error::Protocol);
        };
        let handle = RetainedProcess::open(*pid)?;
        let empty = crate::core::Object {
            dev: 0,
            ino: 0,
            uid: 0,
            mode: 0,
        };
        let (evidence, pins) = self.snapshot(
            &handle,
            &Evidence {
                pid: *pid,
                start_ticks: handle.start_ticks(),
                owner_uid: *owner_uid,
                state_dir: state_dir.clone(),
                api_socket: api_socket.clone(),
                directory: empty.clone(),
                socket: empty.clone(),
                executable: empty,
                boot_id: String::new(),
            },
        )?;
        let handle = LinuxHandle {
            process: handle,
            pins,
        };
        if self.validate(&handle, &evidence)? != Status::Running {
            return Err(Error::Refused);
        }
        Ok((handle, evidence))
    }
    fn validate(&self, handle: &Self::Handle, evidence: &Evidence) -> Result<Status> {
        self.checked(handle, evidence, false)
    }
    fn stop(&self, handle: &Self::Handle, evidence: &Evidence) -> Result<Status> {
        self.checked(handle, evidence, true)
    }
}
