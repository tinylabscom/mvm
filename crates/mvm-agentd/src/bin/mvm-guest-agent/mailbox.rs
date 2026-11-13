//! Mailbox listener glue: bind the reserved mailbox vsock port and forward the
//! workload's outbox message to each host connection.
//!
//! Opt-in and launch-asserted, like telemetry: the listener binds only when
//! the kernel cmdline carries `mvm.mailbox=1`, which the host sets only for a
//! signed plan that carries a mailbox grant. Otherwise no thread starts and no
//! port is held. Vsock-only; the container tier has none.

use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::Ordering;

use mvm_agentd::mailbox_outbox::{
    MAILBOX_CMDLINE_TOKEN, MAILBOX_HOLD, MAILBOX_IO_TIMEOUT, OUTBOX_PATH, bound_socket_io,
    forward_outbox, peer_gone, wait_for_outbox,
};
use mvm_contract::protocol::mailbox::MAILBOX_PORT;

use crate::globals::SHUTDOWN_REQUESTED;
use crate::telemetry::cmdline_asserts;
use crate::transport::{accept_vsock, bind_vsock_listener, unix_transport_selected};

/// Spawn the mailbox listener on a boot that asserts one. Called after PID-1
/// activation; a bind failure is logged and abandoned, never boot-fatal.
pub(crate) fn init_mailbox() {
    let asserted = std::fs::read_to_string("/proc/cmdline")
        .map(|cmdline| cmdline_asserts(&cmdline, MAILBOX_CMDLINE_TOKEN))
        .unwrap_or(false);
    if !asserted || unix_transport_selected() {
        return;
    }
    let _ = mvm_agentd::detached::spawn_named("mailbox-listener", || {
        match bind_vsock_listener(MAILBOX_PORT) {
            Ok(fd) => accept_loop(fd),
            Err(e) => eprintln!(
                "mvm-guest-agent: mailbox listener bind failed (port {MAILBOX_PORT}): {e}"
            ),
        }
    });
}

/// The host re-dials an idle guest forever, so only the first few refusals
/// and then one in a hundred are logged.
fn logs_refusal(refused: u32) -> bool {
    refused < 3 || refused.is_multiple_of(100)
}

/// One host connection at a time, each answered from the outbox.
fn accept_loop(listener_fd: RawFd) {
    let mut refused = 0u32;
    while !SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
        let Some(cfd) = accept_vsock(listener_fd, "mailbox") else {
            continue;
        };
        // SAFETY: `cfd` is the just-accepted connection fd, owned here and
        // closed on drop.
        let mut stream = unsafe { std::fs::File::from_raw_fd(cfd) };
        // Hold an idle connection until a message is spooled, the host hangs
        // up, or the hold ends, so an idle guest is dialed once per hold.
        if !wait_for_outbox(
            Path::new(OUTBOX_PATH),
            MAILBOX_HOLD,
            std::time::Duration::from_millis(50),
            || peer_gone(cfd) || SHUTDOWN_REQUESTED.load(Ordering::Acquire),
        ) {
            continue;
        }
        let _ = bound_socket_io(cfd, MAILBOX_IO_TIMEOUT);
        if let Err(refusal) = forward_outbox(&mut stream, Path::new(OUTBOX_PATH)) {
            if logs_refusal(refused) {
                eprintln!("mvm-guest-agent: mailbox frame not delivered: {refusal}");
            }
            refused = refused.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_guest_logs_a_bounded_number_of_refusals() {
        assert_eq!((0..1000).filter(|&n| logs_refusal(n)).count(), 3 + 10 - 1);
    }

    #[test]
    fn only_the_exact_token_asserts_a_mailbox() {
        assert!(cmdline_asserts(
            "console=ttyS0 mvm.mailbox=1",
            MAILBOX_CMDLINE_TOKEN
        ));
        assert!(!cmdline_asserts("mvm.mailbox=0", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("xmvm.mailbox=1", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("console=ttyS0", MAILBOX_CMDLINE_TOKEN));
    }
}
