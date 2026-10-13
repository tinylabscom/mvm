//! The identity a VM's endpoint pid file records, and the check that a pid
//! read back from it still names that process before anything signals it.
//!
//! The pid file outlives the process it names. Once that process exits its
//! pid can be handed to anything, and the file sits on disk where it can be
//! edited. So the file records the process's start time beside its pid, taken
//! from the live child right after the spawn, and a pid is only signalled
//! while the process holding it reports that same start time. A recycled pid
//! started later; a pid written by hand has no matching record.

/// What the pid file holds: the endpoint's pid and when that process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointPid {
    pub pid: libc::pid_t,
    pub started: Option<u64>,
}

impl EndpointPid {
    /// The record for a child this process just spawned.
    pub fn of_child(pid: u32) -> Self {
        let pid = pid as libc::pid_t;
        Self {
            pid,
            started: process_start(pid),
        }
    }

    /// The pid file's text: the pid, then the start time when one was read.
    pub fn render(&self) -> String {
        match self.started {
            Some(started) => format!("{} {started}", self.pid),
            None => self.pid.to_string(),
        }
    }

    /// Parse a pid file. The first field is the pid, so a reader that only
    /// wants the pid keeps working on either shape.
    pub fn parse(text: &str) -> Option<Self> {
        let mut fields = text.split_whitespace();
        let pid = fields.next()?.parse().ok()?;
        let started = fields.next().and_then(|field| field.parse().ok());
        Some(Self { pid, started })
    }

    /// Whether the live process at this pid is the one recorded: same pid,
    /// same start time. A record without a start time, or a process whose
    /// start time cannot be read, is never confirmed.
    pub fn is_live_and_ours(&self) -> bool {
        self.pid > 0
            && self
                .started
                .is_some_and(|started| process_start(self.pid) == Some(started))
    }
}

/// When the process `pid` started, in a unit fixed per platform, or `None`
/// when it is gone or cannot be read.
#[cfg(target_os = "linux")]
fn process_start(pid: libc::pid_t) -> Option<u64> {
    if pid <= 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is parenthesised and may itself hold spaces or
    // parentheses, so fields are counted from the last `)`. `starttime` is
    // field 22; the field after the `)` is field 3.
    let after_name = &stat[stat.rfind(')')? + 1..];
    after_name.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn process_start(pid: libc::pid_t) -> Option<u64> {
    if pid <= 0 {
        return None;
    }
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is writable for `size` bytes, the size passed, and
    // `proc_pidinfo` writes at most that many.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: `proc_pidinfo` filled the whole struct, as `written` confirms.
    let info = unsafe { info.assume_init() };
    Some(info.pbi_start_tvsec.saturating_mul(1_000_000) + info.pbi_start_tvusec)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_start(_pid: libc::pid_t) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep")
    }

    fn stop(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_recorded_child_is_confirmed_while_it_lives() {
        let child = sleeper();
        let record = EndpointPid::of_child(child.id());
        assert!(record.started.is_some(), "the start time is readable");
        assert_eq!(EndpointPid::parse(&record.render()), Some(record));
        assert!(record.is_live_and_ours());
        stop(child);
    }

    #[test]
    fn another_process_under_a_recorded_pid_is_not_confirmed() {
        let child = sleeper();
        let real = EndpointPid::of_child(child.id());
        // The same pid with a different start time is what a recycled pid
        // looks like.
        let recycled = EndpointPid {
            started: real.started.map(|started| started + 1),
            ..real
        };
        assert!(!recycled.is_live_and_ours());
        stop(child);
    }

    #[test]
    fn a_bare_pid_is_never_confirmed() {
        let child = sleeper();
        let bare = EndpointPid::parse(&child.id().to_string()).unwrap();
        assert_eq!(bare.started, None);
        assert!(
            !bare.is_live_and_ours(),
            "a hand-written pid proves nothing"
        );
        stop(child);
    }

    #[test]
    fn nonsense_is_not_a_record() {
        assert_eq!(EndpointPid::parse(""), None);
        assert_eq!(EndpointPid::parse("not-a-pid"), None);
        assert!(
            !EndpointPid {
                pid: 0,
                started: Some(1)
            }
            .is_live_and_ours()
        );
        assert!(
            !EndpointPid {
                pid: -1,
                started: Some(1)
            }
            .is_live_and_ours()
        );
    }
}
