//! Opt-in high-bit capability witness, not a production service identity.
//!
//! The synthetic identity uses uid/gid 989 only as non-root test credentials.
//! It does not change the egress identity or grant high capabilities to egress.

use super::{CAP_NET_BIND_SERVICE, ServiceIdentity, privilege_tests::privileged};

/// Requires Linux root with CAP_PERFMON and CAP_BPF in its permitted and
/// bounding sets; uid 0 alone is insufficient.
#[test]
#[ignore = "requires privileged Linux with CAP_PERFMON and CAP_BPF available"]
fn high_capability_identity_survives_self_exec() {
    const CHILD: &str = "MVM_HIGH_CAPABILITY_PROBE_CHILD";
    let mask = (1u64 << CAP_NET_BIND_SERVICE) | (1u64 << 38) | (1u64 << 39);
    let status = std::fs::read_to_string("/proc/self/status").expect("read own status");
    let capability_set = |name: &str| {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .expect("capability set is present");
        u64::from_str_radix(value.trim(), 16).expect("capability mask is hexadecimal")
    };
    if std::env::var_os(CHILD).is_some() {
        // SAFETY: getuid and getgid have no preconditions.
        assert_eq!(unsafe { libc::getuid() }, 989);
        assert_eq!(unsafe { libc::getgid() }, 989);
        for set in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"] {
            assert_eq!(capability_set(set), mask, "{set} after self exec");
        }
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        return;
    }
    assert!(
        privileged(),
        "set MVM_GUEST_PRIVILEGED_TESTS=1 and run as root"
    );
    for set in ["CapPrm", "CapBnd"] {
        assert_eq!(
            capability_set(set) & mask,
            mask,
            "Linux host lacks requested high capabilities in {set}; not a validated probe"
        );
    }
    let executable = std::env::current_exe().expect("own test executable");
    let output = crate::guest_bootstrap::guest_helper_command(
        &executable,
        ServiceIdentity::new(989, 989, mask),
    )
    .args([
        "--exact",
        "guest_mount::high_capability_tests::high_capability_identity_survives_self_exec",
        "--ignored",
        "--nocapture",
    ])
    .env(CHILD, "1")
    .output()
    .expect("assume high-capability identity and self exec");
    assert!(output.status.success(), "{output:?}");
}
