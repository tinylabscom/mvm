//! Validation and application seam for the workload guest hostname.
//!
//! Both cold boot and warm restore converge here, so the validation and syscall
//! cannot drift between the kernel-cmdline and identity-handshake paths.

#[cfg(any(target_os = "linux", test))]
pub(crate) fn cmdline_value_from<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn provision_from<F>(cmdline: &str, set_hostname: F) -> Result<bool, String>
where
    F: FnOnce(&str) -> std::io::Result<()>,
{
    let Some(hostname) = cmdline_value_from(cmdline, "mvm.hostname") else {
        return Ok(false);
    };
    provision_with(hostname, set_hostname)?;
    Ok(true)
}

fn provision_with<F>(hostname: &str, set_hostname: F) -> Result<(), String>
where
    F: FnOnce(&str) -> std::io::Result<()>,
{
    mvm_core::naming::validate_vm_name(hostname)
        .map_err(|error| format!("invalid guest hostname {hostname:?}: {error}"))?;
    set_hostname(hostname).map_err(|error| format!("sethostname({hostname:?}) failed: {error}"))
}

/// Validate and install a host-delivered workload hostname.
///
/// A resumed guest already carries the hostname it was paused with, and the
/// agent holds no `CAP_SYS_ADMIN` to set one, so naming the current hostname is
/// a no-op rather than a `sethostname` the kernel would refuse.
pub fn provision(hostname: &str) -> Result<(), String> {
    provision_with(hostname, |name| {
        set_unless_current(
            name,
            current_kernel_hostname().as_deref(),
            set_kernel_hostname,
        )
    })
}

fn set_unless_current<F>(hostname: &str, current: Option<&str>, set: F) -> std::io::Result<()>
where
    F: FnOnce(&str) -> std::io::Result<()>,
{
    if current == Some(hostname) {
        return Ok(());
    }
    set(hostname)
}

fn current_kernel_hostname() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    Some(raw.trim_end().to_owned())
}

#[cfg(target_os = "linux")]
pub(crate) fn set_kernel_hostname(hostname: &str) -> std::io::Result<()> {
    // SAFETY: `hostname` is a valid byte slice for the duration of the call;
    // the kernel copies exactly `len` bytes and needs no trailing NUL.
    let result = unsafe { libc::sethostname(hostname.as_ptr().cast(), hostname.len()) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_kernel_hostname(_hostname: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sethostname is only provisioned on Linux guests",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_hostname_token_is_applied_before_the_workload_starts() {
        let mut applied = None;

        let found = provision_from(
            "console=ttyS0 mvm.hostname=build-worker-7 panic=1",
            |hostname| {
                applied = Some(hostname.to_string());
                Ok(())
            },
        )
        .expect("valid hostname is applied");

        assert!(found);
        assert_eq!(applied.as_deref(), Some("build-worker-7"));
    }

    #[test]
    fn a_malformed_hostname_token_is_rejected_without_calling_sethostname() {
        let mut called = false;

        let error = provision_from("mvm.hostname=UPPERCASE", |_hostname| {
            called = true;
            Ok(())
        })
        .expect_err("uppercase hostname must be rejected");

        assert!(!called);
        assert!(error.contains("hostname"), "unexpected error: {error}");
    }

    #[test]
    fn a_missing_hostname_token_keeps_legacy_boots_compatible() {
        let mut called = false;

        let found = provision_from("console=ttyS0 panic=1", |_hostname| {
            called = true;
            Ok(())
        })
        .expect("missing hostname is not malformed");

        assert!(!found);
        assert!(!called);
    }

    #[test]
    fn naming_the_current_hostname_does_not_call_sethostname() {
        let mut called = false;
        set_unless_current("worker-1", Some("worker-1"), |_| {
            called = true;
            Ok(())
        })
        .expect("the current hostname is already in place");
        assert!(!called);

        set_unless_current("worker-2", Some("worker-1"), |_| {
            called = true;
            Ok(())
        })
        .expect("a different hostname is set");
        assert!(called);
    }

    #[test]
    fn a_sethostname_failure_is_reported() {
        let error = provision_from("mvm.hostname=worker-1", |_hostname| {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        })
        .expect_err("sethostname failure must be visible");

        assert!(error.contains("worker-1"), "unexpected error: {error}");
        assert!(
            error.contains("Operation not permitted"),
            "unexpected error: {error}"
        );
    }
}
