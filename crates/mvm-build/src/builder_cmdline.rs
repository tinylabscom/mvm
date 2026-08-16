//! Refuse a builder kernel command line the guest kernel would truncate.
//!
//! The workload path already refuses an overlong cmdline
//! (`mvm_vmm::host::cmdline::cmdline_overflow`, called from the workload
//! runner's backend). The builder paths did not: `libkrun_builder`'s
//! `append_cmdline_token` and `qemu_builder`'s `format!` both assemble a
//! command line and hand it straight to the VMM with no length check. The
//! kernel copies at most `COMMAND_LINE_SIZE` bytes and drops the rest without
//! a diagnostic, and what it drops is whatever was appended last — for a
//! builder that is `mvm.vsock_egress`, the egress port, and the host epoch.
//! A guest then boots with no egress and no clock, and the only symptom is a
//! build that cannot reach the network.

/// Return `cmdline` unchanged, or the reason it cannot be used.
///
/// Wraps the workload path's check so both tiers answer to one limit; there is
/// no separate builder limit to drift. Returns a plain `String` error so each
/// builder maps it into its own error type rather than this helper picking one.
pub fn checked_builder_cmdline(cmdline: String) -> Result<String, String> {
    match mvm_vmm::host::cmdline::cmdline_overflow(&cmdline) {
        Some(problem) => Err(format!("refusing to start builder VM: {problem}")),
        None => Ok(cmdline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_builder_cmdline_passes_through_unchanged() {
        let cmdline = "console=hvc0 root=/dev/vda mvm.vsock_egress=1".to_string();
        assert_eq!(
            checked_builder_cmdline(cmdline.clone()).expect("short cmdline is fine"),
            cmdline
        );
    }

    #[test]
    fn a_cmdline_past_the_kernel_limit_refuses_the_builder() {
        let err = checked_builder_cmdline("x".repeat(4096))
            .expect_err("an overlong cmdline must refuse the boot");
        assert!(err.contains("builder VM"), "{err}");
    }

    #[test]
    fn the_builder_answers_to_the_same_limit_as_the_workload() {
        // 2047 bytes + the NUL fits; 2048 does not. Pinned against the
        // workload path rather than a second copy of the constant.
        assert!(checked_builder_cmdline("x".repeat(2047)).is_ok());
        assert!(checked_builder_cmdline("x".repeat(2048)).is_err());
    }
}
