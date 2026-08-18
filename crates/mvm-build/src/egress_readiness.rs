//! Whether a builder guest may proceed once its egress client has been forked.
//!
//! Every builder tier — Stage 0 and the persistent builder VM — boots with a
//! virtio-vsock device and no NIC, so `nix build` reaches the network only
//! through the guest-local proxy `mvm-egress-client` binds. If that proxy never
//! comes up, every fetch fails with a connection error naming the *proxy*, and
//! the build spends minutes arriving at a diagnosis that points at the wrong
//! layer. The decision to stop is therefore made here, once, and shared by both
//! guest inits rather than reimplemented per binary.

use std::time::Duration;

/// The guest-local address `mvm-egress-client` binds.
pub const EGRESS_PROXY_LISTEN_ADDR: &str = mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN;

/// How long a guest init waits for that listener before giving up.
///
/// Re-exported from `mvm-core` rather than defined here: the egress client
/// bounds its own connect retries by the same number, and two copies would let
/// the client outlive the window its supervisor waits.
pub const EGRESS_PROXY_READY_TIMEOUT: Duration = mvm_core::guest_netd::EGRESS_PROXY_READY_TIMEOUT;

/// How the readiness wait ended. Separated from the waiting so the decision —
/// the part that has to be right — is a pure function over this enum rather
/// than something only a booted guest can exercise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressProbe {
    /// The loopback proxy accepted a connection.
    Ready,
    /// `mvm-egress-client` exited before it bound the listener; the string is
    /// its termination, as rendered by the caller.
    ClientExited(String),
    /// The deadline passed with a live client and no listener.
    TimedOut,
    /// No egress client could be started at all.
    ClientMissing(String),
    /// The guest has no FlowMux identity, so the egress client cannot
    /// authenticate its session and will refuse to bind.
    IdentityMissing(String),
    /// The compiled-in listen address does not parse.
    BadListenAddr(String),
}

/// Decide whether the guest may proceed to its build.
///
/// Anything other than a bound proxy is fatal: a builder guest with no NIC and
/// no proxy has no network at all, so continuing only defers the failure and
/// misattributes it.
pub fn egress_readiness_outcome(probe: EgressProbe) -> Result<(), String> {
    let no_nic = "this guest has no NIC and reaches the network only through that proxy";
    match probe {
        EgressProbe::Ready => Ok(()),
        EgressProbe::ClientExited(how) => Err(format!(
            "mvm-egress-client exited before binding the local egress proxy at \
             {EGRESS_PROXY_LISTEN_ADDR} ({how}); {no_nic}"
        )),
        EgressProbe::TimedOut => Err(format!(
            "mvm-egress-client did not bind the local egress proxy at {} within {}s; {no_nic}",
            EGRESS_PROXY_LISTEN_ADDR,
            EGRESS_PROXY_READY_TIMEOUT.as_secs()
        )),
        EgressProbe::ClientMissing(where_looked) => Err(format!(
            "no mvm-egress-client to bind the local egress proxy at \
             {EGRESS_PROXY_LISTEN_ADDR} (looked at {where_looked}); {no_nic}"
        )),
        EgressProbe::IdentityMissing(why) => Err(format!(
            "no FlowMux identity for this boot ({why}), so mvm-egress-client \
             cannot authenticate its session to the host endpoint; {no_nic}"
        )),
        EgressProbe::BadListenAddr(addr) => {
            Err(format!("invalid local egress proxy address {addr}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_egress_proxy_lets_the_build_proceed() {
        assert_eq!(egress_readiness_outcome(EgressProbe::Ready), Ok(()));
    }

    #[test]
    fn an_egress_client_that_exited_aborts_the_build_and_names_itself() {
        let err = egress_readiness_outcome(EgressProbe::ClientExited("exit code 1".into()))
            .expect_err("a dead egress client must abort the build");
        assert!(err.contains("mvm-egress-client"), "{err}");
        assert!(err.contains("exit code 1"), "{err}");
        assert!(err.contains(EGRESS_PROXY_LISTEN_ADDR), "{err}");
    }

    #[test]
    fn an_egress_proxy_that_never_binds_aborts_the_build() {
        let err = egress_readiness_outcome(EgressProbe::TimedOut)
            .expect_err("an unbound proxy must abort the build");
        assert!(err.contains("did not bind"), "{err}");
        assert!(err.contains(EGRESS_PROXY_LISTEN_ADDR), "{err}");
    }

    #[test]
    fn a_missing_egress_client_aborts_rather_than_booting_networkless() {
        let err = egress_readiness_outcome(EgressProbe::ClientMissing(
            "/mvm-bins/mvm-egress-client".into(),
        ))
        .expect_err("a missing egress client must abort the build");
        assert!(err.contains("/mvm-bins/mvm-egress-client"), "{err}");
    }

    #[test]
    fn a_boot_without_an_identity_names_the_identity_and_not_the_network() {
        let err = egress_readiness_outcome(EgressProbe::IdentityMissing(
            "no attached disk carries the ext4 label mvm-identity".into(),
        ))
        .expect_err("a guest with no identity must abort the build");
        assert!(err.contains("FlowMux identity"), "{err}");
        assert!(err.contains("mvm-identity"), "{err}");
    }

    #[test]
    fn an_unparseable_listen_addr_aborts_rather_than_skipping_the_wait() {
        let err = egress_readiness_outcome(EgressProbe::BadListenAddr("not-an-addr".into()))
            .expect_err("a bad listen addr must abort the build");
        assert!(err.contains("not-an-addr"), "{err}");
    }

    #[test]
    fn every_refusal_says_why_a_builder_guest_cannot_carry_on() {
        for probe in [
            EgressProbe::ClientExited("signal 9".into()),
            EgressProbe::TimedOut,
            EgressProbe::ClientMissing("/x".into()),
            EgressProbe::IdentityMissing("no drive".into()),
        ] {
            let err = egress_readiness_outcome(probe.clone()).expect_err("must refuse");
            assert!(
                err.contains("no NIC"),
                "{probe:?} must explain the no-NIC posture: {err}"
            );
        }
    }
}
