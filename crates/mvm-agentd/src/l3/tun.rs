//! The guest's TUN device, behind a trait.
//!
//! `mvm0` is created with `IFF_TUN | IFF_NO_PI`: a layer-3, point-to-point
//! interface with no Ethernet header, no MAC address, no ARP, and no
//! packet-information prefix. What we read from the fd is an IP packet and
//! nothing else, which is exactly what the tunnel frames.
//!
//! The trait exists so the whole agent — handshake, configuration, packet
//! pump, shutdown — runs in ordinary unprivileged tests against
//! [`MemoryTun`], with only the ioctl bodies excluded.

use std::io;

/// A layer-3 tunnel device.
pub trait TunDevice: Send {
    /// Read one complete IP packet. Returns the byte count written into
    /// `buf`. A TUN read is packet-atomic: one read is one packet, and a
    /// packet larger than `buf` is truncated by the kernel rather than
    /// split, so `buf` must be at least MTU-sized.
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write one complete IP packet.
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;

    /// Interface name, for diagnostics.
    fn name(&self) -> &str;
}

/// Errors creating or configuring the device.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// `/dev/net/tun` is missing. Almost always a kernel without
    /// `CONFIG_TUN`, which is why the message says so.
    #[error("/dev/net/tun is unavailable: {0} (guest kernel needs CONFIG_TUN)")]
    DeviceUnavailable(io::Error),
    /// `TUNSETIFF` failed.
    #[error("creating tun interface {name:?} failed: {source}")]
    CreateFailed { name: String, source: io::Error },
    /// The name did not fit `IFNAMSIZ`.
    #[error("interface name {0:?} is too long")]
    NameTooLong(String),
    /// An ioctl configuring addresses, MTU, flags, or routes failed.
    #[error("configuring {what} on {name:?} failed: {source}")]
    ConfigureFailed {
        what: &'static str,
        name: String,
        source: io::Error,
    },
    /// This platform has no TUN support in this build.
    #[error("tun devices are only supported on Linux guests")]
    Unsupported,
}

/// An in-memory device for tests: whatever is written to the guest side is
/// readable as if the guest kernel had produced it, and vice versa.
///
/// Deliberately not `cfg(test)` — the unprivileged end-to-end test lives in
/// another crate and needs to construct one.
#[derive(Debug, Default)]
pub struct MemoryTun {
    name: String,
    /// Packets the agent will read, as though the guest stack emitted them.
    outbound: std::collections::VecDeque<Vec<u8>>,
    /// Packets the agent wrote, as though delivered to the guest stack.
    delivered: Vec<Vec<u8>>,
}

impl MemoryTun {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outbound: std::collections::VecDeque::new(),
            delivered: Vec::new(),
        }
    }

    /// Queue a packet for the agent to read, as if the guest stack sent it.
    pub fn push_outbound(&mut self, packet: Vec<u8>) {
        self.outbound.push_back(packet);
    }

    /// Everything the agent wrote back into the guest.
    pub fn delivered(&self) -> &[Vec<u8>] {
        &self.delivered
    }

    pub fn take_delivered(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.delivered)
    }

    pub fn outbound_pending(&self) -> usize {
        self.outbound.len()
    }
}

impl TunDevice for MemoryTun {
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.outbound.pop_front() {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            // Mirrors a non-blocking device with nothing to read, so the
            // pump's empty-queue path is the same shape in tests and in
            // production.
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.delivered.push(packet.to_vec());
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxTun;

#[cfg(target_os = "linux")]
mod linux {
    use super::{TunDevice, TunError};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;

    const TUN_PATH: &str = "/dev/net/tun";

    // linux/if_tun.h. IFF_TUN selects layer 3; IFF_NO_PI drops the 4-byte
    // packet-information prefix so a read is exactly one IP packet.
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    // _IOW('T', 202, int). Widened through the shared helper because
    // `libc::Ioctl` is `c_int` on musl and `c_ulong` on glibc — a bare
    // constant compiles for one and not the other.
    const TUNSETIFF: libc::Ioctl = crate::guest_net::target_ioctl_request(0x4004_54ca);

    #[repr(C)]
    struct IfReqFlags {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    /// A real `/dev/net/tun` device.
    pub struct LinuxTun {
        file: File,
        name: String,
    }

    impl LinuxTun {
        /// Create `name` as a layer-3, no-PI tunnel and return the open fd.
        ///
        /// The fd is the only handle the agent keeps: after this returns,
        /// the process no longer needs `CAP_NET_ADMIN` for I/O, which is
        /// what makes the privilege drop possible.
        pub fn create(name: &str) -> Result<Self, TunError> {
            let encoded = crate::guest_net::encode_iface_name(name)
                .map_err(|_| TunError::NameTooLong(name.to_string()))?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(TUN_PATH)
                .map_err(TunError::DeviceUnavailable)?;

            let mut req = IfReqFlags {
                name: encoded,
                flags: IFF_TUN | IFF_NO_PI,
                _pad: [0u8; 22],
            };
            // SAFETY: `req` is a correctly-shaped `ifreq` for TUNSETIFF and
            // outlives the call; the fd is open for read/write.
            let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
            if rc < 0 {
                return Err(TunError::CreateFailed {
                    name: name.to_string(),
                    source: io::Error::last_os_error(),
                });
            }
            Ok(Self {
                file,
                name: name.to_string(),
            })
        }

        /// The raw fd, for callers that need to poll it.
        pub fn as_raw_fd(&self) -> libc::c_int {
            self.file.as_raw_fd()
        }

        /// Put the fd in non-blocking mode so the pump can interleave TUN
        /// and vsock readiness without a thread per direction.
        pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            let fd = self.file.as_raw_fd();
            // SAFETY: `fd` is owned by `self.file` and open.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let updated = if nonblocking {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            // SAFETY: same fd; F_SETFL takes an int argument.
            if unsafe { libc::fcntl(fd, libc::F_SETFL, updated) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl TunDevice for LinuxTun {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.file.read(buf)
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.file.write_all(packet)
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    /// Layout contract with `linux/if.h`'s `ifreq`. TUNSETIFF reads the
    /// name and flags by offset, so a mismatch would silently create the
    /// wrong kind of device rather than fail.
    const _: () = {
        use core::mem::{offset_of, size_of};
        assert!(offset_of!(IfReqFlags, name) == 0);
        assert!(offset_of!(IfReqFlags, flags) == libc::IFNAMSIZ);
        assert!(size_of::<IfReqFlags>() >= libc::IFNAMSIZ + 2);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_tun_round_trips_a_packet_in_each_direction() {
        let mut tun = MemoryTun::new("mvm0");
        tun.push_outbound(vec![0x45, 0, 0, 20]);
        let mut buf = [0u8; 1500];
        let n = tun.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x45, 0, 0, 20]);

        tun.write_packet(&[0x45, 0, 0, 40]).unwrap();
        assert_eq!(tun.delivered(), &[vec![0x45, 0, 0, 40]]);
    }

    #[test]
    fn an_empty_memory_tun_reports_would_block_like_a_real_device() {
        let mut tun = MemoryTun::new("mvm0");
        let mut buf = [0u8; 1500];
        let err = tun.read_packet(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn packets_are_read_in_the_order_the_stack_produced_them() {
        let mut tun = MemoryTun::new("mvm0");
        for i in 0..3u8 {
            tun.push_outbound(vec![0x45, i]);
        }
        let mut buf = [0u8; 64];
        for i in 0..3u8 {
            let n = tun.read_packet(&mut buf).unwrap();
            assert_eq!(buf[..n], [0x45, i]);
        }
        assert_eq!(tun.outbound_pending(), 0);
    }

    #[test]
    fn taking_delivered_packets_clears_the_buffer() {
        let mut tun = MemoryTun::new("mvm0");
        tun.write_packet(&[1, 2, 3]).unwrap();
        assert_eq!(tun.take_delivered(), vec![vec![1, 2, 3]]);
        assert!(tun.delivered().is_empty());
    }

    #[test]
    fn the_device_reports_its_name() {
        assert_eq!(MemoryTun::new("mvm0").name(), "mvm0");
    }
}
