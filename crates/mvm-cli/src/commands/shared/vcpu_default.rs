//! The default vCPU count, resolved through the client facade.
//!
//! The resolution itself lives in `mvm-client` beside the other
//! drive-a-machine surface: `xtask check-cli-runtime-surface` keeps `mvm-cli`
//! from reaching into `mvm-runtime` directly, and backend auto-detection is
//! exactly the kind of call that rule is protecting.

/// vCPUs to give a guest when the caller does not say. See
/// [`mvm_client::default_vcpus`] for why this is not a constant.
pub(crate) fn default_vcpus() -> u32 {
    mvm_client::default_vcpus()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_default_is_the_facade_default() {
        // One resolution, not two: a second copy here would drift from the
        // backend the launch path actually selects.
        assert_eq!(default_vcpus(), mvm_client::default_vcpus());
    }

    #[test]
    fn the_default_is_stable_across_calls() {
        assert_eq!(default_vcpus(), default_vcpus());
    }
}
