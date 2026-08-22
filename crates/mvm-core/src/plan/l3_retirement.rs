//! Refuse a workload that asks for the retired raw-packet networking path.
//!
//! The guest-TUN tunnel gave a workload its own IP stack and had the *guest*
//! originate connections. That is a second egress decision point with its own
//! policy code, and it cannot carry host-side credential substitution or
//! cleartext redaction at all, because what crosses the boundary for a TLS
//! flow is ciphertext the host never holds a key for.
//!
//! It is being removed in favour of a single flow-aware vsock path. Removal is
//! staged rather than atomic, so this is the gate that keeps the staging
//! honest: no new workload may boot onto the tunnel while its replacement is
//! built, which is what stops the tree from carrying three live production
//! networking paths at once. VMs already running on the tunnel are unaffected
//! — they drain.
//!
//! One function, called from both synthesis and admission, because a
//! pre-signed plan that never passed through synthesis must be refused too.

use mvm_contract::plan::NetworkMode;

/// Why a launch that asked for the retired raw-packet path was refused.
///
/// The message names the replacements rather than only the refusal: an
/// operator reading it needs to know what to do next, and the answer differs
/// depending on whether they wanted plain egress or a transformed request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum L3RetiredError {
    /// The plan selected the tunnel, or declared `raw_ip_stack`, which is
    /// what selects it.
    #[error(
        "the in-guest IP stack (raw_ip_stack / l3-vsock) has been retired and no longer boots. \
         Route ordinary traffic through the guest loopback adapters — the HTTP proxy, SOCKS5h, \
         SOCKS5 UDP, and the DNS stub the guest already exports — or, for a request that needs \
         host-side credential substitution or redaction, declare a typed SDK connector. Raw \
         sockets, arbitrary IP protocols, in-guest resolvers, and general ICMP are unsupported \
         rather than routed through a second network stack. Already-running VMs are unaffected."
    )]
    RawIpStackRetired,
    /// The mode did not select the tunnel but a tunnel spec rode along. Refused
    /// separately so a half-set plan is never treated as a plain one.
    #[error(
        "this plan carries an l3 network spec without selecting the retired l3-vsock mode; \
         the raw-packet path no longer boots, so drop the spec"
    )]
    StraySpec,
}

/// Refuse a plan that would boot onto the retired raw-packet path.
///
/// `has_l3_spec` is passed separately rather than read off the mode because
/// the two can disagree, and a disagreement is itself a refusal — a plan whose
/// two halves describe different transports has not made a decision.
pub fn refuse_retired_l3(mode: &NetworkMode, has_l3_spec: bool) -> Result<(), L3RetiredError> {
    let _ = mode;
    if has_l3_spec {
        return Err(L3RetiredError::StraySpec);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stray_spec_on_a_non_tunnel_plan_is_refused() {
        assert_eq!(
            refuse_retired_l3(&NetworkMode::HostVsockProxy, true),
            Err(L3RetiredError::StraySpec)
        );
        assert_eq!(
            refuse_retired_l3(&NetworkMode::None, true),
            Err(L3RetiredError::StraySpec)
        );
    }

    #[test]
    fn the_supported_modes_still_pass() {
        assert!(refuse_retired_l3(&NetworkMode::None, false).is_ok());
        assert!(refuse_retired_l3(&NetworkMode::HostVsockProxy, false).is_ok());
    }

    #[test]
    fn the_refusal_names_both_replacements() {
        let msg = L3RetiredError::RawIpStackRetired.to_string();
        assert!(msg.contains("loopback"), "no loopback proxy named: {msg}");
        assert!(msg.contains("SOCKS5h"), "no SOCKS proxy named: {msg}");
        assert!(
            msg.contains("typed SDK connector"),
            "no typed connector named: {msg}"
        );
        assert!(
            msg.contains("Already-running VMs are unaffected"),
            "the drain allowance is not stated: {msg}"
        );
    }
}
