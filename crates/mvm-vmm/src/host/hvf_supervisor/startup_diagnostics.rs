//! Best-effort startup observations, never capability or readiness evidence.
//! The wire contains only single-byte enum codes. Unknown bytes are discarded,
//! and neither raw helper output nor configuration enters a diagnostic report.

use std::fs::File;
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};

const DIAGNOSTICS_FD: &str = "MVM_HVF_STARTUP_DIAGNOSTICS_FD";
const MAX_BYTES: usize = 256;
static ADOPTION_ATTEMPTED: AtomicBool = AtomicBool::new(false);

fn claim_adoption(guard: &AtomicBool) -> bool {
    !guard.swap(true, Ordering::AcqRel)
}

fn parse_inherited_fd(value: &str) -> Option<libc::c_int> {
    value.parse().ok().filter(|fd| *fd > 2)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum StartupStage {
    #[default]
    Unknown = 0,
    SignCheck = 161,
    SigningLock = 162,
    Signing = 163,
    Reexec = 164,
    ConfigRead = 165,
    ConfigParse = 166,
    StatusPublish = 167,
    StartupInputs = 168,
    CapturePolicy = 169,
    CaptureSetup = 170,
    PidPublish = 171,
    PidPublished = 172,
}

impl StartupStage {
    fn decode(byte: u8) -> Option<Self> {
        match byte {
            161 => Some(Self::SignCheck),
            162 => Some(Self::SigningLock),
            163 => Some(Self::Signing),
            164 => Some(Self::Reexec),
            165 => Some(Self::ConfigRead),
            166 => Some(Self::ConfigParse),
            167 => Some(Self::StatusPublish),
            168 => Some(Self::StartupInputs),
            169 => Some(Self::CapturePolicy),
            170 => Some(Self::CaptureSetup),
            171 => Some(Self::PidPublish),
            172 => Some(Self::PidPublished),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartupSummary {
    pub stage: StartupStage,
}

impl StartupSummary {
    fn observe(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if let Some(stage) = StartupStage::decode(*byte) {
                self.stage = stage;
            }
        }
    }

    pub fn child_status(self, status: Option<ExitStatus>) -> String {
        match status {
            Some(status) => self.exited(status),
            None => format!("startup stage={:?}; child exit=not-observed", self.stage),
        }
    }

    /// Format only typed observations and the OS child status, never helper data.
    pub fn exited(self, status: ExitStatus) -> String {
        match (status.code(), status.signal()) {
            (Some(code), _) => format!("startup stage={:?}; child exit_code={code}", self.stage),
            (_, Some(signal)) => format!("startup stage={:?}; child signal={signal}", self.stage),
            _ => format!("startup stage={:?}; child status=unknown", self.stage),
        }
    }

    /// Captured before the launcher's timeout kill; not a preexisting crash.
    pub fn timed_out(self) -> String {
        format!(
            "startup stage={:?}; child exit=not-observed-at-deadline; timeout cleanup=kill-requested",
            self.stage
        )
    }
}

pub struct StartupDiagnostics {
    reader: PipeReader,
    writer: Option<PipeWriter>,
    summary: StartupSummary,
    remaining: usize,
}

fn nonblocking(fd: libc::c_int) -> io::Result<()> {
    // SAFETY: fcntl operates on an owned, live pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl StartupDiagnostics {
    pub fn new() -> io::Result<Self> {
        let (reader, writer) = io::pipe()?;
        nonblocking(reader.as_raw_fd())?;
        nonblocking(writer.as_raw_fd())?;
        Ok(Self {
            reader,
            writer: Some(writer),
            summary: StartupSummary::default(),
            remaining: MAX_BYTES,
        })
    }

    /// Use before the existing resource-bounds wrapper. This never bypasses it.
    /// Descriptor handoff works on the native, unwrapped macOS launch. A scope
    /// wrapper may discard pre-exec hooks; that launch then has no diagnostics,
    /// not permission to skip resource bounds or to claim readiness.
    pub fn configure(command: &mut Command, diagnostics: Option<&Self>) {
        // Never adopt a descriptor number supplied by the launcher's environment.
        command.env_remove(DIAGNOSTICS_FD);
        if let Some(writer) = diagnostics.and_then(|diagnostics| diagnostics.writer.as_ref()) {
            let fd = writer.as_raw_fd();
            command.env(DIAGNOSTICS_FD, fd.to_string());
            crate::host::restore_image::inherit_descriptors(command, vec![fd]);
        }
    }

    pub fn launched(&mut self) {
        self.writer.take();
    }

    /// Bounded nonblocking drain: EOF is not required, even if another process
    /// inherited a writer. No bytes are retained after enum decoding.
    pub fn snapshot(&mut self) -> StartupSummary {
        let mut bytes = [0; MAX_BYTES];
        while self.remaining != 0 {
            match self.reader.read(&mut bytes[..self.remaining]) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    self.summary.observe(&bytes[..count]);
                    self.remaining -= count;
                }
            }
        }
        self.summary
    }
}

pub struct StartupReporter(Option<File>);

impl StartupReporter {
    /// Adopt only the dedicated write-only pipe, before reading configuration.
    /// CLOEXEC prevents leaking it to signing helpers; reexec readmits it alone.
    ///
    /// Only the first invocation per exec attempts adoption, even if it fails.
    /// Later invocations return an inert reporter without inspecting the FD.
    ///
    /// # Safety
    ///
    /// On the first invocation, any open descriptor above stderr named by the
    /// environment must have been transferred exclusively to this process for
    /// diagnostics, with no other owner or concurrent use/close. The launcher
    /// must keep it distinct from all other inherited descriptors. Missing,
    /// malformed, reserved, or closed descriptors are ignored. Descriptor shape
    /// checks do not prove ownership. Call at process startup before opening or
    /// adopting other FDs.
    pub unsafe fn inherited() -> Self {
        if !claim_adoption(&ADOPTION_ATTEMPTED) {
            return Self(None);
        }
        let fd = std::env::var(DIAGNOSTICS_FD)
            .ok()
            .and_then(|value| parse_inherited_fd(&value));
        // SAFETY: the caller guarantees exclusive inherited ownership.
        Self(fd.and_then(|fd| unsafe { Self::adopt(fd) }))
    }

    /// The caller transfers exclusive ownership if this descriptor is accepted.
    /// Rejected descriptors are not closed. Shape checks establish only type.
    unsafe fn adopt(fd: libc::c_int) -> Option<File> {
        Self::validate_fd(fd)?;
        // SAFETY: valid descriptor; close it in unrelated exec children.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return None;
        }
        nonblocking(fd).ok()?;
        // SAFETY: caller transfers exclusive ownership, independently of fstat.
        Some(unsafe { File::from_raw_fd(fd) })
    }

    fn validate_fd(fd: libc::c_int) -> Option<()> {
        if fd <= 2 {
            return None;
        }
        // SAFETY: query the inherited descriptor without dereferencing it.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat initializes stat on success.
        if flags < 0
            || flags & libc::O_ACCMODE != libc::O_WRONLY
            || unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0
        {
            return None;
        }
        // SAFETY: fstat succeeded above.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO {
            return None;
        }
        Some(())
    }

    pub fn stage(&mut self, stage: StartupStage) {
        if let Some(file) = &mut self.0 {
            let _ = file.write(&[stage as u8]);
        }
    }

    pub fn configure_reexec(&self, command: &mut Command) {
        command.env_remove(DIAGNOSTICS_FD);
        if let Some(file) = &self.0 {
            let fd = file.as_raw_fd();
            command.env(DIAGNOSTICS_FD, fd.to_string());
            crate::host::restore_image::inherit_descriptors(command, vec![fd]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    const FAKE_CHILD: &str = "MVM_HVF_DIAGNOSTICS_TEST_CHILD";
    const FAKE_TEST: &str = "host::hvf_supervisor::startup_diagnostics::tests::fake_helper";
    const FAKE_SYNC_FD: &str = "MVM_HVF_DIAGNOSTICS_TEST_SYNC_FD";
    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);

    struct FixtureChild {
        child: std::process::Child,
        reaped: bool,
    }

    impl FixtureChild {
        fn spawn(command: &mut Command) -> Self {
            Self {
                child: command.spawn().expect("spawn diagnostic fixture"),
                reaped: false,
            }
        }

        fn wait(&mut self) -> ExitStatus {
            let status = crate::host::process_exit::wait_for_test_child(
                &mut self.child,
                std::time::Instant::now() + FIXTURE_TIMEOUT,
            )
            .expect("wait for diagnostic fixture")
            .expect("diagnostic fixture must exit within its deadline");
            self.reaped = true;
            status
        }
    }

    impl Drop for FixtureChild {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.child.kill();
                let _ = crate::host::process_exit::wait_for_test_child(
                    &mut self.child,
                    std::time::Instant::now() + FIXTURE_TIMEOUT,
                );
            }
        }
    }

    fn bound_sync(stream: &UnixStream) {
        stream.set_read_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(FIXTURE_TIMEOUT)).unwrap();
    }

    #[test]
    fn fake_helper() {
        use std::os::unix::process::CommandExt;

        let Ok(mode) = std::env::var(FAKE_CHILD) else {
            return;
        };
        // SAFETY: this fake child receives a distinct pipe end exclusively from
        // StartupDiagnostics::configure, before it opens any other descriptors.
        let mut reporter = unsafe { StartupReporter::inherited() };
        if mode == "hold" {
            let sync_fd = std::env::var(FAKE_SYNC_FD).unwrap().parse().unwrap();
            // SAFETY: the held-child fixture transfers a separate socket end
            // exclusively to this exec, with no other owner in this process.
            let mut sync = unsafe { UnixStream::from_raw_fd(sync_fd) };
            // SAFETY: sync owns this live descriptor; keep unrelated execs out.
            assert_eq!(
                unsafe { libc::fcntl(sync_fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
            bound_sync(&sync);
            let fd = reporter.0.as_ref().unwrap().as_raw_fd();
            // SAFETY: duplicate the owned writer into a high slot in this
            // isolated helper, where no other tests allocate descriptors.
            let closed = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
            assert!(closed >= 64);
            // SAFETY: close only the duplicate just created; no File owns it.
            assert_eq!(unsafe { libc::close(closed) }, 0);
            assert!(StartupReporter::validate_fd(closed).is_none());
            let probe = format!("test -e /dev/fd/{fd}");
            let mut unrelated = mvm_core::env_hygiene::helper_command("/bin/sh");
            unrelated.args(["-c", &probe]);
            let status = FixtureChild::spawn(&mut unrelated).wait();
            assert!(!status.success(), "unrelated exec must not inherit writer");
            reporter.stage(StartupStage::SigningLock);
            sync.write_all(&[0x1e]).unwrap();
            let mut release = [0];
            sync.read_exact(&mut release).unwrap();
            drop(reporter);
            std::process::exit(23);
        }
        if mode == "reexec" {
            reporter.stage(StartupStage::Reexec);
            let mut command =
                mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
            command
                .args(["--exact", FAKE_TEST, "--nocapture"])
                .env(FAKE_CHILD, "exit");
            reporter.configure_reexec(&mut command);
            let error = command.exec();
            panic!("fake helper reexec failed: {error}");
        }
        reporter.stage(StartupStage::ConfigParse);
        eprintln!("SENTINEL_PRIVATE_PAYLOAD argv=/private/path secret=value");
        println!("SENTINEL_PRIVATE_PAYLOAD");
        drop(reporter);
        std::process::exit(23);
    }

    #[test]
    fn fake_process_preserves_the_write_only_seam_across_reexec() {
        let mut diagnostics = StartupDiagnostics::new().unwrap();
        let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
        command
            .args(["--exact", FAKE_TEST, "--nocapture"])
            .env(FAKE_CHILD, "reexec")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(super::super::protected_supervisor_stderr());
        StartupDiagnostics::configure(&mut command, Some(&diagnostics));
        let mut child = FixtureChild::spawn(&mut command);
        diagnostics.launched();
        let status = child.wait();
        assert_eq!(
            diagnostics.snapshot().exited(status),
            "startup stage=ConfigParse; child exit_code=23"
        );
    }

    #[test]
    fn early_exit_reports_only_last_typed_stage_and_actual_code_or_signal() {
        let mut summary = StartupSummary::default();
        summary.observe(&[StartupStage::SignCheck as u8, StartupStage::Signing as u8]);
        assert_eq!(
            summary.exited(ExitStatus::from_raw(23 << 8)),
            "startup stage=Signing; child exit_code=23"
        );
        assert_eq!(
            summary.exited(ExitStatus::from_raw(libc::SIGTERM)),
            format!("startup stage=Signing; child signal={}", libc::SIGTERM)
        );
    }

    #[test]
    fn unknown_and_sentinel_payload_are_not_retained_or_reported() {
        let mut summary = StartupSummary::default();
        summary.observe(&[StartupStage::ConfigParse as u8, 255, 0]);
        summary.observe(b"SENTINEL_PRIVATE_PAYLOAD argv=/private/path secret=value\n");
        assert_eq!(summary.stage, StartupStage::ConfigParse);
        assert_eq!(
            summary.exited(ExitStatus::from_raw(2 << 8)),
            "startup stage=ConfigParse; child exit_code=2"
        );
        assert!(!summary.timed_out().contains("SENTINEL"));
    }

    #[test]
    fn timeout_snapshot_does_not_wait_for_an_unrelated_writer_or_require_eof() {
        let mut diagnostics = StartupDiagnostics::new().unwrap();
        let mut writer = diagnostics.writer.as_ref().unwrap().try_clone().unwrap();
        diagnostics.launched();
        writer
            .write_all(&[StartupStage::SigningLock as u8])
            .unwrap();
        let summary = diagnostics.snapshot();
        assert_eq!(summary.stage, StartupStage::SigningLock);
        assert_eq!(
            summary.timed_out(),
            "startup stage=SigningLock; child exit=not-observed-at-deadline; timeout cleanup=kill-requested"
        );
        writer.write_all(&[255; MAX_BYTES - 1]).unwrap();
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SigningLock);
        writer
            .write_all(&[StartupStage::PidPublished as u8])
            .unwrap();
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SigningLock);
        writer
            .write_all(&[StartupStage::ConfigParse as u8])
            .unwrap();
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SigningLock);
    }

    #[test]
    fn real_child_retains_writer_without_blocking_snapshot_or_leaking_to_exec() {
        let mut diagnostics = StartupDiagnostics::new().unwrap();
        let (mut sync, child_sync) = UnixStream::pair().unwrap();
        bound_sync(&sync);
        let mut command = mvm_core::env_hygiene::helper_command(std::env::current_exe().unwrap());
        command
            .args(["--exact", FAKE_TEST, "--nocapture"])
            .env(FAKE_CHILD, "hold")
            .env(FAKE_SYNC_FD, child_sync.as_raw_fd().to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(super::super::protected_supervisor_stderr());
        StartupDiagnostics::configure(&mut command, Some(&diagnostics));
        crate::host::restore_image::inherit_descriptors(&mut command, vec![child_sync.as_raw_fd()]);
        let mut child = FixtureChild::spawn(&mut command);
        drop(child_sync);
        diagnostics.launched();
        // Dedicated socket event with a deadline, independent of harness output.
        let mut byte = [0];
        sync.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x1e]);
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SigningLock);
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SigningLock);
        sync.write_all(b"X").unwrap();
        assert_eq!(child.wait().code(), Some(23));
    }

    #[test]
    fn descriptor_validation_rejects_invalid_read_only_read_write_and_non_fifo() {
        use std::os::fd::IntoRawFd;

        // SAFETY: these are invalid or reserved descriptors and cannot be adopted.
        for fd in [-1, 0, 1, 2, libc::c_int::MAX] {
            assert!(unsafe { StartupReporter::adopt(fd) }.is_none());
        }
        let (reader, writer) = io::pipe().unwrap();
        let read_only = reader.into_raw_fd();
        let regular = tempfile::tempfile().unwrap().into_raw_fd();
        let scratch = tempfile::tempdir().unwrap();
        let write_only = File::create(scratch.path().join("regular"))
            .unwrap()
            .into_raw_fd();
        for fd in [read_only, regular, write_only] {
            // SAFETY: into_raw_fd above transferred exclusive ownership to this
            // test. Validation rejects these shapes without taking ownership.
            assert!(unsafe { StartupReporter::adopt(fd) }.is_none());
            // SAFETY: rejected adoption did not close or own this descriptor.
            let retained = unsafe { File::from_raw_fd(fd) };
            assert!(retained.metadata().is_ok());
            drop(retained);
        }
        drop(writer);
    }

    #[test]
    fn malformed_or_reserved_fd_numbers_are_not_candidates_for_adoption() {
        for value in ["", "garbage", "1.0", "-1", "0", "1", "2", "2147483648"] {
            assert!(parse_inherited_fd(value).is_none(), "{value}");
        }
        assert_eq!(parse_inherited_fd("37"), Some(37));
    }

    #[test]
    fn guard_allows_only_one_adoption_attempt() {
        let guard = AtomicBool::new(false);
        assert!(claim_adoption(&guard));
        assert!(!claim_adoption(&guard));
        assert!(!claim_adoption(&guard));
    }

    #[test]
    fn a_single_snapshot_cannot_accept_a_valid_stage_beyond_the_lifetime_cap() {
        let mut diagnostics = StartupDiagnostics::new().unwrap();
        let mut writer = diagnostics.writer.take().unwrap();
        writer.write_all(&[StartupStage::SignCheck as u8]).unwrap();
        writer.write_all(&[255; MAX_BYTES - 1]).unwrap();
        writer
            .write_all(&[StartupStage::PidPublished as u8])
            .unwrap();
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SignCheck);
        writer
            .write_all(&[StartupStage::ConfigParse as u8])
            .unwrap();
        assert_eq!(diagnostics.snapshot().stage, StartupStage::SignCheck);
    }

    #[test]
    fn reporter_drop_closes_its_exclusively_owned_writer() {
        use std::os::fd::IntoRawFd;

        let (mut reader, writer) = io::pipe().unwrap();
        nonblocking(reader.as_raw_fd()).unwrap();
        let fd = writer.into_raw_fd();
        // SAFETY: into_raw_fd transfers the sole writer to adoption.
        let reporter = StartupReporter(unsafe { StartupReporter::adopt(fd) });
        assert!(reporter.0.is_some());
        assert_eq!(
            reader.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(reporter);
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn absent_exit_observation_never_invents_an_exit_code() {
        let summary = StartupSummary {
            stage: StartupStage::SignCheck,
        };
        assert_eq!(
            summary.child_status(None),
            "startup stage=SignCheck; child exit=not-observed"
        );
    }
}
