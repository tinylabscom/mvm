//! The per-VM network endpoint: the substitution endpoint and its proxy pipeline, FlowMux, TLS termination, runtime approval and the ingress transform.

pub mod accept_loop;
pub mod audit_start;
pub mod epoch_admission;
pub mod flowmux;
/// Host substitution endpoint request preparation (placeholder -> real
/// credential, binding-checked). The forward leg + the guest-facing
/// listener are separate transport steps.
/// The witness-only egress-gate probe: asks the running gate to decide
/// probe samples, observing enforcement without substituting or forwarding.
pub(crate) mod gate_probe;
mod ingress_transform;
/// The per-VM substitution endpoint subprocess library half: the
/// stdin config contract + store-opening/service assembly. The
/// `mvm-network-endpoint` bin is the process wrapper.
pub mod network_endpoint;
pub mod network_endpoint_proxy;
pub mod reversible_replacement;
pub mod runtime_approval;
/// Termination of an admitted FlowMux flow to a host carrying a bound secret:
/// TLS under the per-VM CA, request framing, and the hand-off to substitution.
pub mod terminator;

/// A guest-supplied destination host as every endpoint decision sees it: its
/// canonical identity, an IPv6 address bracketed so `{host}:{port}` parses
/// back. Applied once where a destination enters the endpoint (a FlowMux
/// `OpenTcp` target or `UdpSend` address, a typed request URL through
/// [`canonical_url`]), so the gate, routes, secret bindings, transform
/// profiles and audit all compare one host.
/// `None` when the host names no destination (its identity is empty); the
/// entry point refuses it.
pub(crate) fn canonical_target_host(host: &str) -> Option<String> {
    let host = mvm_core::policy::network_policy::canonical_host(host);
    if host.is_empty() {
        None
    } else if host.contains(':') {
        Some(format!("[{host}]"))
    } else {
        Some(host)
    }
}

/// `url` with its host in canonical form ([`canonical_target_host`]), so every
/// later check and the forward leg see one spelling of the destination;
/// `None` when its host names no destination. A URL whose host is already
/// canonical, or that does not parse or has no host, is returned untouched;
/// the request path refuses an unparseable one.
pub(crate) fn canonical_url(url: String) -> Option<String> {
    let Ok(mut parsed) = url::Url::parse(&url) else {
        return Some(url);
    };
    let Some(host) = parsed.host_str() else {
        return Some(url);
    };
    let canonical = canonical_target_host(host)?;
    if canonical == host {
        return Some(url);
    }
    parsed.set_host(Some(&canonical)).ok()?;
    Some(parsed.into())
}
