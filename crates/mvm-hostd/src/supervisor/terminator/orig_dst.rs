//! Recover the original destination of a connection the host nft `nat` chain
//! REDIRECTed to the terminator. The getsockopt path is Linux-only; the
//! pure parser is host-portable so it stays unit-testable everywhere.
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "linux")]
use std::net::{SocketAddr, TcpStream};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;

#[cfg(target_os = "linux")]
pub fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: getsockopt writes a sockaddr_in into `addr` and the written length
    // into `len`; both out-params are valid for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SocketAddr::V4(sockaddr_in_to_v4(&addr)))
}

// Used by original_dst (Linux) and by the unit test (all platforms).
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn sockaddr_in_to_v4(a: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
        u16::from_be(a.sin_port),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_network_order_sockaddr_in() {
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        a.sin_port = 443u16.to_be();
        a.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(203, 0, 113, 7)).to_be();
        let v4 = sockaddr_in_to_v4(&a);
        assert_eq!(
            v4,
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 7), 443)
        );
    }
}
