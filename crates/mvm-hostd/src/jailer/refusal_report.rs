//! Name the system call a seccomp filter refused before the process dies of it.
//!
//! The filter's default action is `SECCOMP_RET_TRAP`, which raises `SIGSYS`.
//! With the default disposition that kills the process on the spot, so its log
//! ends at the last healthy line and the death surfaces much later as a closed
//! socket somewhere else. This handler writes one line to stderr first — the
//! process, the architecture and number of the refused call, and the self-test
//! probe that was running if there was one — and then lets the process die of
//! `SIGSYS` exactly as before.
//!
//! It changes reporting only. The refused call never runs: a trapped system
//! call is skipped by the kernel, and the handler never returns to the code
//! that made it. The handler is installed with `SA_RESETHAND`, so the default
//! action is back in place by the time it re-raises.

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::jailer::JailerError;

/// The process name written at the head of a refusal line.
static ROLE: Label = Label::new();
/// The self-test probe currently running, if any.
static PROBE: Label = Label::new();

/// A `&'static str` that a signal handler can read without locking.
///
/// Stored as a pointer to a leaked `&'static str` rather than as a separate
/// pointer and length, so a reader can never pair one label's pointer with
/// another's length. Each `set` leaks one fat pointer; labels are set a handful
/// of times per process, at startup.
struct Label(AtomicPtr<&'static str>);

impl Label {
    const fn new() -> Self {
        Self(AtomicPtr::new(std::ptr::null_mut()))
    }

    fn set(&self, value: &'static str) {
        self.0
            .store(Box::into_raw(Box::new(value)), Ordering::Release);
    }

    fn clear(&self) {
        self.0.store(std::ptr::null_mut(), Ordering::Release);
    }

    fn get(&self) -> Option<&'static str> {
        let ptr = self.0.load(Ordering::Acquire);
        // SAFETY: a non-null pointer was produced by `Box::into_raw` in `set`
        // and is never freed, so it is valid for the life of the process.
        (!ptr.is_null()).then(|| unsafe { *ptr })
    }
}

/// Marks a self-test probe as running until dropped, so a refusal during it
/// is attributed to the probe by name.
#[must_use = "the probe is only labelled while the guard is alive"]
pub(crate) struct ProbeLabel(());

impl ProbeLabel {
    pub(crate) fn enter(name: &'static str) -> Self {
        PROBE.set(name);
        Self(())
    }
}

impl Drop for ProbeLabel {
    fn drop(&mut self) {
        PROBE.clear();
    }
}

/// Install the `SIGSYS` handler that names a refused call. Called before the
/// filter is installed, so it covers the first call the filter refuses.
pub(crate) fn install(role: &'static str) -> Result<(), JailerError> {
    ROLE.set(role);
    // SAFETY: an all-zero `sigaction` is a valid starting value; every field
    // the kernel reads is set below.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = report_refusal as *const () as libc::sighandler_t;
    action.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
    // SAFETY: `action.sa_mask` is a valid signal set to initialise, and
    // `action` is a fully initialised `sigaction` for the duration of the call.
    let rc = unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut())
    };
    if rc != 0 {
        return Err(JailerError::SeccompInstall(format!(
            "install the SIGSYS refusal reporter: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// `si_code` for a `SIGSYS` raised by a seccomp filter.
const SYS_SECCOMP: libc::c_int = 1;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

/// The `SIGSYS` arm of the kernel's `siginfo_t` union on the 64-bit targets
/// this crate supports. The `libc` crate does not expose these fields, and
/// `repr(C)` places `call_addr` at the same eight-byte-aligned offset the
/// kernel does.
#[repr(C)]
struct SigsysInfo {
    signo: libc::c_int,
    errno: libc::c_int,
    code: libc::c_int,
    call_addr: *mut c_void,
    syscall: libc::c_int,
    arch: libc::c_uint,
}

// The kernel's layout on x86_64 and aarch64: three `int`s, padding to the
// pointer, the pointer at 16, then `_syscall` and `_arch`. The whole arm lies
// inside the 128-byte `siginfo_t` the kernel hands the handler.
const _: () = assert!(std::mem::size_of::<SigsysInfo>() == 32);
const _: () = assert!(std::mem::align_of::<SigsysInfo>() == 8);
const _: () = assert!(std::mem::offset_of!(SigsysInfo, call_addr) == 16);
const _: () = assert!(std::mem::offset_of!(SigsysInfo, syscall) == 24);
const _: () = assert!(std::mem::offset_of!(SigsysInfo, arch) == 28);
const _: () = assert!(std::mem::size_of::<SigsysInfo>() <= std::mem::size_of::<libc::siginfo_t>());

/// The refused call as `(architecture, number)`, or `None` for a `SIGSYS`
/// that was sent rather than raised by the filter.
///
/// # Safety
/// `info` must be the `siginfo_t` the kernel passed to an `SA_SIGINFO`
/// handler for `SIGSYS`.
unsafe fn refused_call(info: *const libc::siginfo_t) -> Option<(u32, i64)> {
    if info.is_null() {
        return None;
    }
    // SAFETY: per the caller's contract `info` points at a kernel-filled
    // `siginfo_t`, which is larger than and laid out as a prefix of
    // `SigsysInfo` for a seccomp `SIGSYS`.
    let fields = unsafe { &*info.cast::<SigsysInfo>() };
    (fields.code == SYS_SECCOMP).then_some((fields.arch, i64::from(fields.syscall)))
}

/// Async-signal-safe: a fixed stack buffer, `write(2)`, `sigprocmask`,
/// `raise` and `_exit` only.
extern "C" fn report_refusal(_signo: libc::c_int, info: *mut libc::siginfo_t, _: *mut c_void) {
    let mut line = Line::new();
    line.push(ROLE.get().unwrap_or("confined process"));
    // SAFETY: the kernel passes this handler the `siginfo_t` for the `SIGSYS`
    // it is delivering.
    match unsafe { refused_call(info) } {
        Some((arch, nr)) => {
            line.push(": seccomp refused ");
            match arch {
                AUDIT_ARCH_X86_64 => line.push("x86_64"),
                AUDIT_ARCH_AARCH64 => line.push("aarch64"),
                other => {
                    line.push("audit-arch ");
                    line.push_decimal(i64::from(other));
                }
            }
            line.push(" syscall ");
            line.push_decimal(nr);
        }
        None => line.push(": SIGSYS that no seccomp filter raised"),
    }
    if let Some(probe) = PROBE.get() {
        line.push(" during self-test probe \"");
        line.push(probe);
        line.push("\"");
    }
    line.push(
        "; stopping. If the call is legitimate, add a reviewed entry to \
         CONFINED_ROLE_SYSCALLS in mvm_hostd::jailer::seccomp\n",
    );
    line.write_to_stderr();

    // SA_RESETHAND has already restored the default action. Unblock the
    // signal this handler is running under and raise it again, so the
    // process dies of SIGSYS — the status its parent reports — whether or not
    // the filter lets `raise` through: a refused `tgkill` is itself trapped,
    // and the kernel delivers that SIGSYS with the default action.
    // SAFETY: async-signal-safe calls on a valid, locally owned signal set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGSYS);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(libc::SIGSYS);
        libc::_exit(128 + libc::SIGSYS);
    }
}

/// A bounded line assembled without allocating. Overlong input is truncated,
/// which only ever shortens the diagnostic.
struct Line {
    buf: [u8; 512],
    len: usize,
}

impl Line {
    const fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    fn push(&mut self, text: &str) {
        let room = self.buf.len() - self.len;
        let take = text.len().min(room);
        self.buf[self.len..self.len + take].copy_from_slice(&text.as_bytes()[..take]);
        self.len += take;
    }

    fn push_decimal(&mut self, value: i64) {
        if value < 0 {
            self.push("-");
        }
        let mut digits = [0u8; 20];
        let mut n = value.unsigned_abs();
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        // Digits are ASCII, so this is always valid UTF-8.
        if let Ok(text) = std::str::from_utf8(&digits[start..]) {
            self.push(text);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn write_to_stderr(&self) {
        let mut rest = self.as_bytes();
        while !rest.is_empty() {
            // SAFETY: `rest` is a live slice of this buffer; `write` reads at
            // most `rest.len()` bytes from it.
            let written = unsafe { libc::write(2, rest.as_ptr().cast(), rest.len()) };
            if written > 0 {
                rest = &rest[written as usize..];
            } else if written < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {
                continue;
            } else {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_formats_text_and_numbers_without_allocating() {
        let mut line = Line::new();
        line.push("syscall ");
        line.push_decimal(0);
        line.push(" ");
        line.push_decimal(435);
        line.push(" ");
        line.push_decimal(-1);
        assert_eq!(line.as_bytes(), b"syscall 0 435 -1");
    }

    #[test]
    fn an_overlong_line_is_truncated_rather_than_overrun() {
        let mut line = Line::new();
        for _ in 0..100 {
            line.push("0123456789");
        }
        assert_eq!(line.as_bytes().len(), 512);
    }

    #[test]
    fn a_probe_label_lasts_exactly_as_long_as_its_guard() {
        assert_eq!(PROBE.get(), None);
        {
            let _probe = ProbeLabel::enter("unit-test-probe");
            assert_eq!(PROBE.get(), Some("unit-test-probe"));
        }
        assert_eq!(PROBE.get(), None);
    }

    #[test]
    fn a_sigsys_the_filter_did_not_raise_names_no_call() {
        // SAFETY: an all-zero siginfo is a valid value.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        info.si_signo = libc::SIGSYS;
        // SAFETY: `info` is a valid siginfo_t.
        assert_eq!(unsafe { refused_call(&info) }, None);
        // SAFETY: a null pointer is handled explicitly.
        assert_eq!(unsafe { refused_call(std::ptr::null()) }, None);
    }
}
