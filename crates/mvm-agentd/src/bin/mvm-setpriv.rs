//! Minimal privilege-drop and exec helper for the guest PID 1.
//!
//! The helper implements the small flag surface emitted by mkGuest:
//! numeric real/effective/saved uid and gid replacement, supplementary-group
//! clearing, no-new-privileges, and the allowlisted inheritable/ambient
//! capabilities used by the loopback DNS, egress, and restore-time agent.
//! It intentionally has no shell, NSS lookup, or configuration-file parser.

use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    reuid: u32,
    regid: u32,
    clear_groups: bool,
    no_new_privs: bool,
    capabilities: u32,
    securebits_keep_caps: bool,
    command: OsString,
    command_args: Vec<OsString>,
}

fn parse_args<I>(args: I) -> Result<Invocation, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut reuid = None;
    let mut regid = None;
    let mut clear_groups = false;
    let mut no_new_privs = false;
    let mut capabilities = 0;
    let mut securebits_keep_caps = false;
    let mut command = None;
    let mut command_args = Vec::new();
    let mut after_separator = false;

    for arg in args {
        if after_separator {
            if command.is_none() {
                command = Some(arg);
            } else {
                command_args.push(arg);
            }
            continue;
        }

        if arg == OsStr::new("--") {
            after_separator = true;
            continue;
        }

        let text = arg
            .to_str()
            .ok_or_else(|| "options must be valid UTF-8".to_string())?;
        if let Some(value) = text.strip_prefix("--reuid=") {
            if reuid.is_some() {
                return Err("duplicate --reuid option".to_string());
            }
            reuid = Some(parse_uid("--reuid", value)?);
        } else if let Some(value) = text.strip_prefix("--regid=") {
            if regid.is_some() {
                return Err("duplicate --regid option".to_string());
            }
            regid = Some(parse_uid("--regid", value)?);
        } else if text == "--clear-groups" {
            if clear_groups {
                return Err("duplicate --clear-groups option".to_string());
            }
            clear_groups = true;
        } else if text == "--no-new-privs" {
            if no_new_privs {
                return Err("duplicate --no-new-privs option".to_string());
            }
            no_new_privs = true;
        } else if text == "--securebits=keep-caps" {
            if securebits_keep_caps {
                return Err("duplicate --securebits option".to_string());
            }
            securebits_keep_caps = true;
        } else if let Some(value) = text
            .strip_prefix("--inh-caps=+")
            .or_else(|| text.strip_prefix("--ambient-caps=+"))
        {
            capabilities |= parse_capability(value)?;
        } else {
            return Err(format!("unsupported option {text:?}"));
        }
    }

    if !after_separator {
        return Err("missing separator".to_string());
    }
    let command = command.ok_or_else(|| "missing command after separator".to_string())?;
    let reuid = reuid.ok_or_else(|| "missing reuid".to_string())?;
    let regid = regid.ok_or_else(|| "missing regid".to_string())?;
    if !clear_groups {
        return Err("missing clear-groups".to_string());
    }
    if !no_new_privs {
        return Err("missing no-new-privs".to_string());
    }

    Ok(Invocation {
        reuid,
        regid,
        clear_groups,
        no_new_privs,
        capabilities,
        securebits_keep_caps,
        command,
        command_args,
    })
}

fn parse_capability(value: &str) -> Result<u32, String> {
    let number = match value {
        "kill" => Ok(CAP_KILL),
        "net_bind_service" => Ok(CAP_NET_BIND_SERVICE),
        "sys_time" => Ok(CAP_SYS_TIME),
        _ => Err(format!("unsupported capability {value:?}")),
    }?;
    Ok(1u32 << number)
}

fn parse_uid(name: &str, value: &str) -> Result<u32, String> {
    if value.is_empty() {
        return Err(format!("{name} requires a numeric value"));
    }
    value
        .parse::<u32>()
        .map_err(|_| format!("{name} value {value:?} is not a valid uid/gid"))
}

#[cfg(target_os = "linux")]
fn apply_privileges(invocation: &Invocation) -> Result<(), String> {
    if (invocation.capabilities != 0 || invocation.securebits_keep_caps) && invocation.reuid != 0 {
        prctl(PR_SET_KEEPCAPS, 1, "prctl(PR_SET_KEEPCAPS) failed")?;
    }
    if invocation.clear_groups {
        let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
        if rc != 0 {
            return last_error("setgroups(clear) failed");
        }
    }

    let gid = invocation.regid as libc::gid_t;
    let rc = unsafe { libc::setresgid(gid, gid, gid) };
    if rc != 0 {
        return last_error("setresgid failed");
    }

    let uid = invocation.reuid as libc::uid_t;
    let rc = unsafe { libc::setresuid(uid, uid, uid) };
    if rc != 0 {
        return last_error("setresuid failed");
    }

    if invocation.capabilities != 0 {
        set_capabilities(invocation.capabilities)?;
        raise_ambient_capabilities(invocation.capabilities)?;
    } else {
        drop_all_capabilities()?;
    }

    if invocation.no_new_privs {
        prctl(PR_SET_NO_NEW_PRIVS, 1, "prctl(PR_SET_NO_NEW_PRIVS) failed")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn prctl(option: libc::c_int, arg: libc::c_ulong, message: &str) -> Result<(), String> {
    let rc = unsafe { libc::prctl(option, arg, 0, 0, 0) };
    if rc == 0 { Ok(()) } else { last_error(message) }
}

#[cfg(target_os = "linux")]
fn raise_ambient_capabilities(capabilities: u32) -> Result<(), String> {
    for capability in [CAP_KILL, CAP_NET_BIND_SERVICE, CAP_SYS_TIME] {
        if capabilities & (1u32 << capability) == 0 {
            continue;
        }
        let rc = unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                capability as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return last_error("prctl(PR_CAP_AMBIENT_RAISE) failed");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn last_error(message: &str) -> Result<(), String> {
    Err(format!("{message}: {}", std::io::Error::last_os_error()))
}

#[cfg(target_os = "linux")]
fn set_capabilities(capabilities: u32) -> Result<(), String> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return last_error("capget failed");
    }

    data[0] = CapData {
        effective: capabilities,
        permitted: capabilities,
        inheritable: capabilities,
    };
    data[1] = CapData::default();
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return last_error("capset(requested capabilities) failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_all_capabilities() -> Result<(), String> {
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return last_error("capset(drop all) failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::pid_t,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

// Layout contract with linux/capability.h `__user_cap_header_struct` and
// `__user_cap_data_struct`. Both are passed to capset(2)/capget(2) by
// pointer; the kernel reads each capability word by offset. A mismatch
// therefore writes the wrong word rather than returning an error, and the
// failure direction is not symmetric — a shifted read can leave a
// capability set that should have been cleared.
//
// Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof, not read off the
// Rust definitions. `pid_t` is i32 on every Linux target mvm builds for;
// compiling this file for both x86_64 and aarch64 is what establishes it.
#[cfg(target_os = "linux")]
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<CapHeader>() == 8);
    assert!(align_of::<CapHeader>() == 4);
    assert!(offset_of!(CapHeader, version) == 0);
    assert!(offset_of!(CapHeader, pid) == 4);

    assert!(size_of::<CapData>() == 12);
    assert!(align_of::<CapData>() == 4);
    assert!(offset_of!(CapData, effective) == 0);
    assert!(offset_of!(CapData, permitted) == 4);
    assert!(offset_of!(CapData, inheritable) == 8);
};

#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_KILL: u32 = 5;
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_SYS_TIME: u32 = 25;
#[cfg(target_os = "linux")]
const PR_SET_KEEPCAPS: libc::c_int = 8;
#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT: libc::c_int = 47;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

fn main() {
    let invocation = parse_args(std::env::args_os().skip(1)).unwrap_or_else(|error| {
        eprintln!("mvm-setpriv: {error}");
        std::process::exit(2);
    });

    #[cfg(target_os = "linux")]
    if let Err(error) = apply_privileges(&invocation) {
        eprintln!("mvm-setpriv: {error}");
        std::process::exit(126);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = invocation;
        eprintln!("mvm-setpriv runs inside Linux guests only");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let error = Command::new(&invocation.command)
            .args(&invocation.command_args)
            .exec();
        eprintln!("mvm-setpriv: exec {:?} failed: {error}", invocation.command);
        std::process::exit(127);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_workload_privilege_drop() {
        let invocation = parse_args(args(&[
            "--reuid=990",
            "--regid=990",
            "--clear-groups",
            "--no-new-privs",
            "--",
            "/mvm/runtime/agent",
        ]))
        .expect("valid invocation");
        assert_eq!(invocation.reuid, 990);
        assert_eq!(invocation.regid, 990);
        assert_eq!(invocation.capabilities, 0);
        assert_eq!(invocation.command, OsString::from("/mvm/runtime/agent"));
    }

    #[test]
    fn parses_loopback_capability_drop() {
        let invocation = parse_args(args(&[
            "--reuid=990",
            "--regid=990",
            "--clear-groups",
            "--no-new-privs",
            "--inh-caps=+net_bind_service",
            "--ambient-caps=+net_bind_service",
            "--",
            "/mvm/runtime/addon-dns",
            "--zone",
            "/run/mvm/zone.json",
        ]))
        .expect("valid invocation");
        assert_ne!(invocation.capabilities & (1u32 << CAP_NET_BIND_SERVICE), 0);
        assert_eq!(invocation.command_args.len(), 2);
    }

    #[test]
    fn parses_restore_capabilities_and_keep_caps() {
        let invocation = parse_args(args(&[
            "--reuid=990",
            "--regid=990",
            "--clear-groups",
            "--securebits=keep-caps",
            "--no-new-privs",
            "--inh-caps=+kill",
            "--ambient-caps=+kill",
            "--inh-caps=+sys_time",
            "--ambient-caps=+sys_time",
            "--",
            "/mvm/runtime/agent",
        ]))
        .expect("valid restore invocation");
        assert!(invocation.securebits_keep_caps);
        assert_ne!(invocation.capabilities & (1u32 << CAP_KILL), 0);
        assert_ne!(invocation.capabilities & (1u32 << CAP_SYS_TIME), 0);
    }

    #[test]
    fn rejects_unknown_option() {
        let error = parse_args(args(&["--bounding-set=-all"])).unwrap_err();
        assert!(error.contains("unsupported option"));
    }

    #[test]
    fn rejects_missing_security_flags() {
        let error =
            parse_args(args(&["--reuid=990", "--regid=990", "--", "/bin/true"])).unwrap_err();
        assert!(error.contains("clear-groups"));
    }

    #[test]
    fn rejects_invalid_uid() {
        let error = parse_args(args(&[
            "--reuid=not-a-uid",
            "--regid=990",
            "--clear-groups",
            "--no-new-privs",
            "--",
            "/bin/true",
        ]))
        .unwrap_err();
        assert!(error.contains("not a valid uid/gid"));
    }
}
