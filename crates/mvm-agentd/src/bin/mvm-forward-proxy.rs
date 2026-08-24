//! The guest's loopback forward proxy, as its own process.
//!
//! A workload holding secret placeholders has `HTTP_PROXY` pointed at
//! `127.0.0.1:18080`; this relays each request to the host substitution
//! endpoint, which resolves the placeholder, authorizes the destination and
//! makes the real connection. It is the only egress a secret-bearing workload
//! has: that launch deliberately does not start the vsock egress client, so the
//! substitution endpoint owns the port and nothing contends for it.
//!
//! Its own process, and a privileged one, because relaying means opening an
//! authenticated FlowMux session, which means reading the guest signing key —
//! root-only at mode 0400, so that a workload cannot authenticate as its own
//! guest. Served from inside `mvm-guest-agent` it could not: the agent runs the
//! workload's own uid, and every relay failed on that read and answered `502`.
//!
//! Deliberately not behind the `addons` feature and deliberately blocking: the
//! whole proxy is `std`, and a tokio runtime here would put an async closure in
//! a process that exists to move one request at a time.

fn main() -> std::process::ExitCode {
    // Matches the timeout the agent used when it owned this listener.
    const RELAY_TIMEOUT_SECS: u64 = 30;

    if let Err(error) = mvm_agentd::forward_proxy::start_forward_proxy(RELAY_TIMEOUT_SECS) {
        eprintln!("mvm-forward-proxy: {error:#}");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}
