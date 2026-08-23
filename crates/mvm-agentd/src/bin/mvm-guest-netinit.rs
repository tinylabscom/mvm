//! `mvm-guest-netinit` — guest-side network defense.
//!
//! Run as PID >1, uid 0 inside every microVM at boot, before the
//! main `mvm-guest-agent` is forked under setpriv. Installs kernel
//! blackhole routes for `mvm_core::network_policy::MANDATORY_DENY_RANGES`
//! over a synchronous `NETLINK_ROUTE` socket — the defense layer that
//! catches:
//!
//! - The macOS Apple Container path where `mvm` has no host firewall.
//! - Any backend where the host iptables/nftables rules don't apply.
//! - Legitimate uid-0 dev workloads that don't actively try to
//!   defeat the routes.
//!
//! ## Exit codes
//!
//! - 0 — every IPv4 entry installed successfully (or the only
//!   failures were on entries the kernel doesn't support, which is
//!   surfaced in the report's `failed` array with `reason` carrying
//!   the kernel message).
//! - 1 — one or more routes failed to install. `/init` should
//!   fail-closed and refuse to fork the workload.
//! - 2 — could not open/bind the `NETLINK_ROUTE` socket (kernel built
//!   without netlink, or some other systemic failure). Same
//!   fail-closed behaviour at `/init`.
//!
//! ## Output
//!
//! Single line to stdout: the marker
//! [`mvm_agentd::netinit::REPORT_MARKER`] (`__MVM_NETINIT_REPORT__`)
//! followed by a space and the JSON-encoded [`Report`]. The
//! kernel console captures stdout; the host scrape
//! (`firecracker.log`, libkrun console output) greps for the
//! marker and emits one `LocalAuditKind::NetworkMandatoryDeny`
//! audit event per workload from the parsed Report. The marker
//! exists so a noisy console (kernel boot messages, agent
//! startup logs) doesn't bury the line — `grep
//! '__MVM_NETINIT_REPORT__'` is the canonical extraction.
//!
//! ## Platform
//!
//! Linux-only: the module gates on `#[cfg(target_os = "linux")]`.
//! On macOS the binary compiles to a stub that prints
//! "not supported on this host" and exits non-zero — the macOS
//! CLI build doesn't ship the bin, but cargo still builds the
//! workspace and we don't want a compilation break.
//!
//! [`Report`]: mvm_agentd::netinit::Report

#[cfg(target_os = "linux")]
fn main() {
    // Every supported workload network surface terminates on guest loopback.
    // Assign the address as well as raising the link before any unprivileged
    // proxy, DNS stub, or declared-ingress target attempts to bind it.
    if let Err(error) = mvm_agentd::guest_net::configure_loopback() {
        eprintln!(
            "mvm-guest-netinit: loopback configuration failed: {error} \
             (continuing — guest-local network adapters may be unavailable)"
        );
    }

    // Bring the guest network up FIRST — eth0 link-up → DHCP → static fallback —
    // before layering the mandatory-deny blackhole routes on top. The workload
    // guest's `/init` brings up only loopback; nothing else configures eth0, so
    // without this the guest gets no network at all (the libkrun
    // `NET_FLAG_DHCP_CLIENT` does not configure the interface here). This is the
    // same shared bring-up the builder VM init uses. Best-effort: a failure
    // (e.g. a network:None workload with no eth0) logs and continues to the
    // blackhole install — a no-egress guest is degraded, not a hard failure.
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    match mvm_agentd::guest_net::configure_guest_network("eth0", &cmdline, "192.168.127.2") {
        Ok(mvm_agentd::guest_net::GuestNetwork::Configured) => {}
        // Not a failure. Every workload backend boots the guest with a
        // virtio-vsock device and no net device at all, so eth0 is *supposed*
        // to be absent here — egress leaves over vsock to the host-side
        // substitution endpoint. Reporting the invariant as a bring-up failure
        // the guest is "continuing" past described a healthy sealed workload
        // as a degraded one, and sent people looking for broken networking
        // that was working as designed.
        Ok(mvm_agentd::guest_net::GuestNetwork::NoInterface) => {
            eprintln!(
                "mvm-guest-netinit: no eth0 — this guest is NIC-less by design; \
                 egress leaves over vsock"
            );
        }
        Err(e) => {
            eprintln!(
                "mvm-guest-netinit: guest network bring-up failed: {e} \
                 (continuing — guest may have no egress)"
            );
        }
    }

    let report = match mvm_agentd::netinit::install_mandatory_deny_via_netlink() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mvm-guest-netinit: netlink socket open failed: {e}");
            // Exit 2 distinguishes systemic netlink failure from
            // per-route failures so `/init` can branch (the
            // systemic case usually means a kernel feature is
            // missing, not a transient install error).
            std::process::exit(2);
        }
    };

    // Write the report as a single line to stdout, prefixed with
    // the canonical marker so the host-side console-scrape can
    // grep for it. The marker + JSON shape is the contract every
    // audit consumer parses; see `mvm_agentd::netinit::REPORT_MARKER`
    // for the load-bearing string.
    match serde_json::to_string(&report) {
        Ok(json) => println!("{} {json}", mvm_agentd::netinit::REPORT_MARKER),
        Err(e) => {
            // serializing a `Report` from our own types shouldn't
            // fail in practice; if it does the binary still needs
            // to exit with a clear code so /init can react.
            eprintln!("mvm-guest-netinit: serialize report failed: {e}");
            std::process::exit(1);
        }
    }

    if report.has_failures() {
        // Exit 1: per-route failures recorded in the report. /init
        // reads the JSON to surface which entries failed.
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "mvm-guest-netinit: not supported on this host \
         (AF_NETLINK is Linux-only; this binary ships in the runtime \
         overlay for Linux microVM guests only)"
    );
    std::process::exit(2);
}
