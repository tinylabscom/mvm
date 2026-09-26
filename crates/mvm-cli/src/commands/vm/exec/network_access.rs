//! Whether a run could reach the network at all, and the one line that says
//! so when a run without it fails.
//!
//! A run with no egress grant, no secret and no published port starts no
//! network endpoint, so the guest has no channel to ask for a destination on
//! and the host records no refusal to report. The workload's own error —
//! `Could not resolve host` — is then the only signal, and it does not say
//! that the run was offline by default. One line after the output does.

use crate::commands::vm::host_notices::NoticeSink;

/// Printed once, after the output of a failed run that had no network.
pub(super) const NO_NETWORK_HINT: &str = "this run had no network access (the default); if the \
     workload needed it, allow destinations with --allow-host HOST:PORT";

/// A run's network reach, as the endpoint's spawn decision sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NetworkAccess {
    /// No egress, no peer route, no secret: nothing leaves the guest.
    None,
    /// Something was granted, so refusals are reported where they happen.
    Granted,
}

impl NetworkAccess {
    /// The reach of a run admitted under `policy`, with or without secrets.
    ///
    /// The same test the runner applies before spawning the endpoint: a
    /// secret-free policy that admits nothing outbound gets no endpoint. A
    /// transient run publishes no port, so ingress never grants reach here.
    pub(super) fn of_run(
        policy: &mvm_core::network_policy::NetworkPolicy,
        has_secrets: bool,
    ) -> Self {
        if has_secrets || policy.admits_outbound() {
            Self::Granted
        } else {
            Self::None
        }
    }

    /// The `network` field of `run --json`.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Granted => "granted",
        }
    }

    /// The hint for a run that exited with `exit_code`: only an offline run
    /// that failed gets one.
    pub(super) fn exit_hint(self, exit_code: i32) -> Option<&'static str> {
        (self == Self::None && exit_code != 0).then_some(NO_NETWORK_HINT)
    }

    /// Print [`Self::exit_hint`], if there is one.
    pub(super) fn announce_exit(self, exit_code: i32, sink: &dyn NoticeSink) {
        if let Some(hint) = self.exit_hint(exit_code) {
            sink.line(hint);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vm::host_notices::Captured;
    use mvm_core::network_policy::{HostPort, NetworkPolicy};

    #[test]
    fn a_run_with_no_grant_and_no_secret_has_no_network() {
        assert_eq!(
            NetworkAccess::of_run(&NetworkPolicy::deny_all(), false),
            NetworkAccess::None
        );
    }

    #[test]
    fn an_allow_list_or_a_secret_grants_network() {
        let allowed = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        assert_eq!(
            NetworkAccess::of_run(&allowed, false),
            NetworkAccess::Granted
        );
        assert_eq!(
            NetworkAccess::of_run(&NetworkPolicy::deny_all(), true),
            NetworkAccess::Granted
        );
    }

    #[test]
    fn only_an_offline_run_that_failed_is_told() {
        assert_eq!(NetworkAccess::None.exit_hint(6), Some(NO_NETWORK_HINT));
        assert_eq!(
            NetworkAccess::None.exit_hint(0),
            None,
            "success says nothing"
        );
        assert_eq!(
            NetworkAccess::Granted.exit_hint(6),
            None,
            "a run with network reports its refusals instead"
        );
    }

    #[test]
    fn the_hint_is_one_line_naming_the_flag() {
        let sink = Captured::default();
        NetworkAccess::None.announce_exit(1, &sink);
        assert_eq!(
            sink.lines(),
            [
                "this run had no network access (the default); if the workload needed it, \
                 allow destinations with --allow-host HOST:PORT"
            ]
        );
        let quiet = Captured::default();
        NetworkAccess::None.announce_exit(0, &quiet);
        NetworkAccess::Granted.announce_exit(1, &quiet);
        assert!(quiet.lines().is_empty());
    }

    #[test]
    fn the_json_label_names_both_states() {
        assert_eq!(NetworkAccess::None.label(), "none");
        assert_eq!(NetworkAccess::Granted.label(), "granted");
    }
}
