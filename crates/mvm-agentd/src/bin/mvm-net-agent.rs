//! `mvm-net-agent` — the in-guest L3 tunnel agent.
//!
//! Creates `mvm0` as a point-to-point TUN device, opens a control and a data
//! connection to the host gateway over AF_VSOCK, applies the configuration
//! the host assigns, drops every capability it no longer needs, and then
//! moves one IP packet per framed message in each direction.
//!
//! `mvm0` is the guest's only route to anywhere: this mode runs on backends
//! that present no network device at all. If the tunnel cannot be
//! established or later drops, the interface goes down and stays down —
//! there is no fallback to a NIC, to host networking, or to another mode.

fn main() {
    let code = run();
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    match linux::main_loop() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("mvm-net-agent: {err}");
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> i32 {
    // The workspace builds on macOS dev hosts; the agent only ever runs in a
    // Linux guest. Exit with a clear message rather than an obscure failure.
    eprintln!("mvm-net-agent: the L3 tunnel agent runs in a Linux guest only");
    1
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    use anyhow::{Context, Result};
    use mvm_agentd::l3::{KernelConfigurator, LinuxTun, NetAgent};
    use mvm_agentd::vsock::connect_host_vsock;
    use mvm_protocol::l3::{GUEST_INTERFACE, L3_CONTROL_PORT, data_port, limits};

    /// How long to wait for the host gateway's listeners at boot. The
    /// supervisor binds them before it starts the VM, so this only absorbs
    /// scheduling skew.
    const CONNECT_TIMEOUT_SECS: u64 = 10;

    /// Poll timeout. Bounds how long a shutdown takes to be noticed and
    /// paces the heartbeat; it is not a latency floor for packets, which
    /// wake the poll immediately.
    const POLL_TIMEOUT_MS: libc::c_int = 1000;

    /// Heartbeats per this many poll timeouts.
    const HEARTBEAT_EVERY_POLLS: u32 = 15;

    pub(super) fn main_loop() -> Result<()> {
        let tun = LinuxTun::create(GUEST_INTERFACE)
            .with_context(|| format!("creating {GUEST_INTERFACE}"))?;
        tun.set_nonblocking(true)
            .context("setting the tun device non-blocking")?;
        let tun_fd = tun.as_raw_fd();

        let mut control = connect_host_vsock(L3_CONTROL_PORT, CONNECT_TIMEOUT_SECS)
            .context("connecting the tunnel control channel")?;
        let mut data = connect_host_vsock(data_port(0), CONNECT_TIMEOUT_SECS)
            .context("connecting the tunnel data channel")?;
        let data_fd = data.as_raw_fd();
        let control_fd = control.as_raw_fd();

        let mut agent = NetAgent::new(tun, KernelConfigurator);
        agent.handshake(&mut control).context("tunnel handshake")?;
        set_nonblocking(data_fd).context("setting the data channel non-blocking")?;
        set_nonblocking(control_fd).context("setting the control channel non-blocking")?;

        // One reusable read buffer; the steady state allocates nothing.
        let mut rx = vec![0u8; limits::MAX_WIRE_LEN];
        let mut control_rx = vec![0u8; limits::MAX_WIRE_LEN];
        let mut polls_since_heartbeat = 0u32;

        loop {
            let mut fds = [
                libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: data_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: control_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `fds` is a live, correctly-sized array of pollfd we own.
            let rc =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_TIMEOUT_MS) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                agent.fail_closed();
                return Err(err).context("poll on the tunnel fds");
            }

            // Either channel closing means the session is over. There is
            // nothing to reconnect to: a new session is the host's to open.
            if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0
                || fds[2].revents & (libc::POLLHUP | libc::POLLERR) != 0
            {
                agent.fail_closed();
                return Ok(());
            }

            if fds[0].revents & libc::POLLIN != 0 {
                agent
                    .pump_tun_to_transport(&mut data)
                    .context("forwarding guest packets")?;
            }

            if fds[1].revents & libc::POLLIN != 0 {
                match data.read(&mut rx) {
                    Ok(0) => {
                        agent.fail_closed();
                        return Ok(());
                    }
                    Ok(n) => {
                        agent
                            .ingest_transport_bytes(&rx[..n])
                            .context("delivering host packets")?;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        agent.fail_closed();
                        return Err(err).context("reading the tunnel data channel");
                    }
                }
            }

            if fds[2].revents & libc::POLLIN != 0 {
                match control.read(&mut control_rx) {
                    Ok(0) => {
                        agent.fail_closed();
                        return Ok(());
                    }
                    Ok(n) => {
                        agent
                            .handle_control_frame(&control_rx[..n])
                            .context("handling a host control message")?;
                        if !agent.state().network_available() {
                            return Ok(());
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        agent.fail_closed();
                        return Err(err).context("reading the tunnel control channel");
                    }
                }
            }

            if rc == 0 {
                polls_since_heartbeat += 1;
                if polls_since_heartbeat >= HEARTBEAT_EVERY_POLLS {
                    polls_since_heartbeat = 0;
                    if agent.send_heartbeat(&mut control).is_err() {
                        // A dead control channel is a dead session.
                        agent.fail_closed();
                        return Ok(());
                    }
                }
            }
        }
    }

    fn set_nonblocking(fd: libc::c_int) -> std::io::Result<()> {
        // SAFETY: `fd` is owned by a live stream in the caller.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: same fd; F_SETFL takes an int.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
