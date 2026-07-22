//! Guest-side TUN device helpers for the shared network tunnel.
//!
//! This module is the guest-side data-plane device after the shared
//! `HELLO` / `HELLO_ACK` / `CONFIG` bootstrap:
//! - open the guest's `/dev/net/tun`,
//! - bind it to the host-authored interface name (`mvm-net0` by default),
//! - exchange raw IP packets through ordinary blocking `Read` / `Write`.
//!
//! The device side stays isolated from the live packet pump so both remain
//! independently testable.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};

/// Blocking packet device abstraction used by the tunnel relay helpers.
pub trait PacketDevice {
    fn interface_name(&self) -> &str;
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize>;
}

/// Blocking guest TUN device.
#[derive(Debug)]
pub struct GuestTunDevice {
    interface_name: String,
    file: File,
}

impl GuestTunDevice {
    /// Open `/dev/net/tun` and bind it to the given interface name.
    #[cfg(target_os = "linux")]
    pub fn open_named(interface_name: &str) -> Result<Self> {
        let name = crate::guest_net::encode_iface_name(interface_name)
            .map_err(anyhow::Error::msg)
            .with_context(|| "validate tunnel interface name")?;
        let file = File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .with_context(|| "open /dev/net/tun")?;

        bind_named_tun(&file, name)
            .with_context(|| format!("bind guest tunnel interface {interface_name}"))?;
        Ok(Self {
            interface_name: interface_name.to_string(),
            file,
        })
    }

    /// Non-Linux hosts compile the workspace but cannot create guest TUNs.
    #[cfg(not(target_os = "linux"))]
    pub fn open_named(interface_name: &str) -> Result<Self> {
        crate::guest_net::encode_iface_name(interface_name)
            .map_err(anyhow::Error::msg)
            .with_context(|| "validate tunnel interface name")?;
        bail!("guest tunnel devices are only supported on Linux guests")
    }
}

impl PacketDevice for GuestTunDevice {
    fn interface_name(&self) -> &str {
        &self.interface_name
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.file
            .read(buf)
            .with_context(|| format!("read packet from {}", self.interface_name))
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize> {
        self.file
            .write(packet)
            .with_context(|| format!("write packet to {}", self.interface_name))
    }
}

impl GuestTunDevice {
    pub fn into_file(self) -> File {
        self.file
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

// `libc::TUNSETIFF` is `Ioctl`-typed, which is `u64` on gnu/64-bit but `i32`
// on musl — the `as u64` normalizes it and is not redundant on every target.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)]
const TUNSETIFF_REQUEST: libc::Ioctl = target_ioctl_request(libc::TUNSETIFF as u64);

#[cfg(target_os = "linux")]
const fn target_ioctl_request(request: u64) -> libc::Ioctl {
    assert!(request <= target_ioctl_request_max());
    request as libc::Ioctl
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
const fn target_ioctl_request_max() -> u64 {
    libc::Ioctl::MAX as u64
}

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const fn target_ioctl_request_max() -> u64 {
    libc::Ioctl::MAX
}

#[cfg(target_os = "linux")]
fn bind_named_tun(file: &File, interface_name: [libc::c_char; libc::IFNAMSIZ]) -> Result<()> {
    // SAFETY: `ifreq` is repr(C); zero-init + union assignment is the standard
    // tuntap ioctl pattern, and the fd comes from an owned open of /dev/net/tun.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name = interface_name;
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    let fd = std::os::fd::AsRawFd::as_raw_fd(file);
    // SAFETY: `fd` is a valid tun device fd and `ifr` points to initialized storage.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF_REQUEST, &ifr) };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_named_rejects_oversize_interface_names_before_os_work() {
        let over = "a".repeat(libc::IFNAMSIZ);
        let err = GuestTunDevice::open_named(&over).expect_err("oversize name rejected");
        assert!(err.to_string().contains("interface name"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::unnecessary_cast)]
    fn tun_ioctl_request_fits_target_request_type() {
        assert_eq!(TUNSETIFF_REQUEST as u64, libc::TUNSETIFF as u64);
    }
}
