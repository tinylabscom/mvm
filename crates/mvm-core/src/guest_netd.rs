//! Shared guest loopback-egress helpers.
//!
//! The guest loopback forwarder sends requests over vsock to the host
//! egress broker. Cooperative apps are pointed at it via the standard proxy
//! environment variables; loopback is excluded via `NO_PROXY` so the app's
//! traffic to the local daemon (and to localhost) is not itself proxied. This
//! module builds that env set deterministically.

/// Loopback hosts excluded from proxying, so an app's calls to the local
/// daemon and to localhost are not themselves routed through the broker.
pub const NO_PROXY_LOOPBACK: &str = "localhost,127.0.0.1,::1";

/// Loopback listen address of the in-guest egress proxy. The cooperative
/// workload's proxy environment (built by [`proxy_env_vars`]) points here, and
/// the in-guest proxy daemon binds it. Callers that must name a scheme dial
/// [`DEFAULT_EGRESS_PROXY_URL`] instead.
pub const DEFAULT_EGRESS_PROXY_LISTEN: &str = "127.0.0.1:1080";

/// How long a guest init waits for [`DEFAULT_EGRESS_PROXY_LISTEN`] to be bound
/// before declaring the guest networkless.
///
/// Lives here because two crates need the same number and must not drift: the
/// guest init that *waits* for the proxy, and the egress client that retries
/// its connect to the host endpoint before it can bind. A client permitted to
/// retry for longer than its supervisor will wait would be killed mid-retry
/// and diagnosed as having exited, which is how a lost startup race reads as a
/// broken client.
pub const EGRESS_PROXY_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// SOCKS5h URL form of [`DEFAULT_EGRESS_PROXY_LISTEN`], used where a workload's
/// `ALL_PROXY` / `HTTP_PROXY` must carry a scheme.
pub const DEFAULT_EGRESS_PROXY_URL: &str = "socks5h://127.0.0.1:1080";
/// Loopback listen address of the in-guest DNS stub.
pub const DEFAULT_DNS_STUB_LISTEN: &str = "127.0.0.1:53";
/// Loopback listen address of the in-guest ICMP mediator.
///
/// A workload cannot open a FlowMux session of its own — the guest signing key
/// is root-only — so `ping` asks this instead, and the process holding the
/// identity performs the echo. Declared beside the proxy and the DNS stub
/// because the three are one allocation decision: a guest loopback port that
/// two of them want is a collision nobody sees until a boot.
pub const ICMP_MEDIATOR_LISTEN: &str = "127.0.0.1:1081";
/// First-line marker selecting DNS on the shared host egress stream.
pub const DNS_FRAME_LINE: &str = "MVM_DNS/1";
/// First-line marker selecting ICMP echo on the shared host egress stream.
/// A NIC-less guest cannot originate ICMP, so the host echoes for it; see
/// [`mvm_core::icmp_wire`] for the request/reply contract.
pub const ICMP_FRAME_LINE: &str = "MVM_ICMP/1";

/// The host's connect-result acknowledgement on the raw-egress stream.
///
/// The in-guest proxy dials the host, writes the `"host:port\n"` target line,
/// then waits for this one byte before answering its own client. The host emits
/// it only after the outbound `connect` resolves — `Ok` once the tunnel is live,
/// `Fail` when the target was refused or unreachable — so the guest reply
/// (`200` / SOCKS success on `Ok`, `502` / SOCKS failure on `Fail`) is truthful
/// instead of assuming success the moment the stream opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectAck {
    /// The host connected to the admitted destination; tunnel bytes follow.
    Ok,
    /// The host refused or could not reach the destination; nothing follows.
    Fail,
}

impl ConnectAck {
    /// The single byte written on the wire.
    pub fn as_byte(self) -> u8 {
        match self {
            ConnectAck::Ok => 0x01,
            ConnectAck::Fail => 0x00,
        }
    }

    /// Parse a wire byte back into an ack. Any byte outside the two defined
    /// codes is rejected so a desynchronised stream never reads a tunnel data
    /// byte as a spurious `Ok`.
    pub fn from_byte(byte: u8) -> Option<ConnectAck> {
        if byte == ConnectAck::Ok.as_byte() {
            Some(ConnectAck::Ok)
        } else if byte == ConnectAck::Fail.as_byte() {
            Some(ConnectAck::Fail)
        } else {
            None
        }
    }
}

/// Directory the guest init installs mediated tool replacements into.
///
/// Part of the same contract as [`proxy_env_vars`]: a NIC-less guest reaches
/// the network through host-mediated stand-ins, and some of those are programs
/// rather than environment variables. It lives on the `/run` tmpfs because the
/// workload rootfs is read-only under verity — the stand-in cannot be written
/// into the image, and on a busybox image `/bin/ping` is a symlink to the
/// multi-call binary, so it cannot be mounted over either.
pub const MEDIATED_TOOLS_BIN: &str = "/run/mvm/bin";

/// Build the standard proxy environment for a cooperative app, pointing it at
/// the in-guest loopback proxy at `proxy_addr` (e.g. `127.0.0.1:3128`). Both
/// upper- and lower-case variants are emitted because tooling is inconsistent
/// about which it reads. `NO_PROXY` excludes loopback.
pub fn proxy_env_vars(proxy_addr: &str) -> Vec<(String, String)> {
    let url = format!("http://{proxy_addr}");
    // `ALL_PROXY` advertises SOCKS5h, not HTTP. The same listener serves both —
    // it dispatches on the first byte — but the two differ for TLS: a client
    // pointed at an HTTP proxy for an `https://` URL may send the request in
    // absolute-URI form, which this proxy refuses rather than forward, because
    // forwarding it would put the request line and headers on the wire in
    // cleartext. SOCKS has no such form; it tunnels from the first byte.
    //
    // Naming SOCKS here lets every client that understands `ALL_PROXY` take the
    // form that works, and matches [`DEFAULT_EGRESS_PROXY_URL`], which already
    // described the endpoint that way.
    let socks_url = format!("socks5h://{proxy_addr}");
    let mut env = Vec::with_capacity(8);
    for key in ["HTTP_PROXY", "HTTPS_PROXY"] {
        env.push((key.to_string(), url.clone()));
        env.push((key.to_lowercase(), url.clone()));
    }
    env.push(("ALL_PROXY".to_string(), socks_url.clone()));
    env.push(("all_proxy".to_string(), socks_url));
    env.push(("NO_PROXY".to_string(), NO_PROXY_LOOPBACK.to_string()));
    env.push(("no_proxy".to_string(), NO_PROXY_LOOPBACK.to_string()));
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn proxy_env_points_http_and_https_at_the_local_proxy() {
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        assert_eq!(
            env.get("HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:3128")
        );
        // SOCKS5h, deliberately: it tunnels TLS from the first byte, where an
        // HTTP proxy would be asked for the absolute-URI form this endpoint
        // refuses.
        assert_eq!(
            env.get("ALL_PROXY").map(String::as_str),
            Some("socks5h://127.0.0.1:3128")
        );
    }

    #[test]
    fn all_proxy_names_socks_while_the_http_vars_name_http() {
        // The difference is deliberate and is the whole point: one listener
        // serves both, but only the SOCKS form tunnels TLS from the first
        // byte. Collapsing them back to one scheme would reintroduce the
        // absolute-URI request the endpoint refuses.
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        assert_eq!(
            env.get("ALL_PROXY").map(String::as_str),
            Some("socks5h://127.0.0.1:3128")
        );
        assert_eq!(
            env.get("all_proxy").map(String::as_str),
            Some("socks5h://127.0.0.1:3128")
        );
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:3128"),
            "the HTTP vars keep the http scheme; only ALL_PROXY names SOCKS"
        );
    }

    #[test]
    fn no_proxy_excludes_loopback() {
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        let no_proxy = env.get("NO_PROXY").map(String::as_str).unwrap_or_default();
        assert!(no_proxy.contains("127.0.0.1"));
        assert!(no_proxy.contains("localhost"));
    }

    #[test]
    fn socks5h_url_wraps_the_listen_addr() {
        assert_eq!(
            DEFAULT_EGRESS_PROXY_URL,
            format!("socks5h://{DEFAULT_EGRESS_PROXY_LISTEN}")
        );
    }

    #[test]
    fn dns_stub_constants_are_stable() {
        assert_eq!(DEFAULT_DNS_STUB_LISTEN, "127.0.0.1:53");
        assert_eq!(DNS_FRAME_LINE, "MVM_DNS/1");
    }

    #[test]
    fn lower_and_upper_case_variants_both_present() {
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        for key in ["http_proxy", "https_proxy", "all_proxy", "no_proxy"] {
            assert!(env.contains_key(key), "missing {key}");
        }
    }

    #[test]
    fn connect_ack_roundtrips_through_its_wire_byte() {
        assert_eq!(
            ConnectAck::from_byte(ConnectAck::Ok.as_byte()),
            Some(ConnectAck::Ok)
        );
        assert_eq!(
            ConnectAck::from_byte(ConnectAck::Fail.as_byte()),
            Some(ConnectAck::Fail)
        );
    }

    #[test]
    fn connect_ack_ok_and_fail_are_distinct_bytes() {
        assert_ne!(ConnectAck::Ok.as_byte(), ConnectAck::Fail.as_byte());
    }

    #[test]
    fn connect_ack_rejects_unknown_bytes_fail_closed() {
        assert_eq!(ConnectAck::from_byte(0x02), None);
        assert_eq!(ConnectAck::from_byte(0xff), None);
    }
}
