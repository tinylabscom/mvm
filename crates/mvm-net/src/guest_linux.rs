//! Linux executor for the guest transparent networking bridge.
//!
//! The generic executor is testable without Linux privileges. The real system
//! implementation is compiled only on Linux and owns the narrow unsafe surface
//! required for `/dev/net/tun`, network ioctls, and AF_VSOCK.

#![cfg_attr(target_os = "linux", allow(unsafe_code))]

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::net::Ipv4Addr;
#[cfg(all(target_os = "linux", feature = "wire-json"))]
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

use crate::guest::{GuestBridgeConfig, GuestBridgeOperation, InterfaceName, Ipv4Cidr};
#[cfg(all(target_os = "linux", feature = "wire-json"))]
use crate::guest_packet::GuestPacketTranslator;
#[cfg(all(target_os = "linux", feature = "wire-json"))]
use crate::guest_pump::{
    GuestAuthority, GuestBridgePump, GuestPumpLoop, GuestPumpWait, run_guest_pump_loop,
};
use crate::guest_pump::{GuestPacketRead, GuestPacketSink, GuestPacketSource};
#[cfg(feature = "wire-json")]
use crate::guest_pump::{GuestPumpError, GuestPumpLoopConfig, GuestPumpRunStats};
#[cfg(all(target_os = "linux", feature = "wire-json"))]
use crate::proto::{Capability, EndpointRole, Hello, NetMessage};
#[cfg(feature = "wire-json")]
use crate::wire_json::JsonWireConfig;
#[cfg(all(target_os = "linux", feature = "wire-json"))]
use crate::wire_json::LengthPrefixedJsonAuthority;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestBridgeExecError {
    UnsupportedPlatform,
    OperationFailed {
        operation: &'static str,
        reason: String,
    },
    MissingTunHandle,
    MissingAuthorityHandle,
}

impl fmt::Display for GuestBridgeExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "guest transparent networking executor is Linux-only")
            }
            Self::OperationFailed { operation, reason } => {
                write!(f, "{operation} failed: {reason}")
            }
            Self::MissingTunHandle => write!(f, "guest bridge plan did not open a TUN device"),
            Self::MissingAuthorityHandle => {
                write!(
                    f,
                    "guest bridge plan did not connect to the vsock authority"
                )
            }
        }
    }
}

impl std::error::Error for GuestBridgeExecError {}

pub trait GuestBridgeSystem {
    type Tun;
    type Authority;

    fn open_tun(&mut self, name: &InterfaceName) -> Result<Self::Tun, GuestBridgeExecError>;

    fn assign_address(
        &mut self,
        name: &InterfaceName,
        address: Ipv4Addr,
        link: Ipv4Cidr,
    ) -> Result<(), GuestBridgeExecError>;

    fn bring_interface_up(&mut self, name: &InterfaceName) -> Result<(), GuestBridgeExecError>;

    fn install_default_route(
        &mut self,
        name: &InterfaceName,
        gateway: Ipv4Addr,
    ) -> Result<(), GuestBridgeExecError>;

    fn write_resolver(
        &mut self,
        path: &Path,
        backup_path: &Path,
        nameserver: Ipv4Addr,
    ) -> Result<(), GuestBridgeExecError>;

    fn connect_vsock_authority(
        &mut self,
        port: u32,
    ) -> Result<Self::Authority, GuestBridgeExecError>;
}

#[derive(Debug)]
pub struct GuestBridgeRuntime<Tun, Authority> {
    pub tun: Tun,
    pub authority: Authority,
}

pub fn start_guest_bridge<S>(
    system: &mut S,
    config: &GuestBridgeConfig,
) -> Result<GuestBridgeRuntime<S::Tun, S::Authority>, GuestBridgeExecError>
where
    S: GuestBridgeSystem,
{
    let mut tun = None;
    let mut authority = None;
    for operation in config.operation_plan() {
        match operation {
            GuestBridgeOperation::OpenTun { name } => {
                tun = Some(system.open_tun(&name)?);
            }
            GuestBridgeOperation::AssignAddress {
                name,
                address,
                link,
            } => {
                system.assign_address(&name, address, link)?;
            }
            GuestBridgeOperation::BringInterfaceUp { name } => {
                system.bring_interface_up(&name)?;
            }
            GuestBridgeOperation::InstallDefaultRoute { name, gateway } => {
                system.install_default_route(&name, gateway)?;
            }
            GuestBridgeOperation::WriteResolver {
                path,
                backup_path,
                nameserver,
            } => {
                system.write_resolver(&path, &backup_path, nameserver)?;
            }
            GuestBridgeOperation::ConnectVsockAuthority { port } => {
                authority = Some(system.connect_vsock_authority(port)?);
            }
        }
    }

    Ok(GuestBridgeRuntime {
        tun: tun.ok_or(GuestBridgeExecError::MissingTunHandle)?,
        authority: authority.ok_or(GuestBridgeExecError::MissingAuthorityHandle)?,
    })
}

pub fn resolver_contents(nameserver: Ipv4Addr) -> String {
    format!("nameserver {nameserver}\n")
}

#[derive(Debug)]
pub struct TunPacketIo<T> {
    inner: T,
}

impl<T> TunPacketIo<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> GuestPacketSource for TunPacketIo<T>
where
    T: Read,
{
    type Error = io::Error;

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<GuestPacketRead, Self::Error> {
        loop {
            match self.inner.read(buffer) {
                Ok(0) => return Ok(GuestPacketRead::Closed),
                Ok(bytes) => return Ok(GuestPacketRead::Packet { bytes }),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    return Ok(GuestPacketRead::WouldBlock);
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl<T> GuestPacketSink for TunPacketIo<T>
where
    T: Write,
{
    type Error = io::Error;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        self.inner.write_all(packet)
    }
}

#[cfg(feature = "wire-json")]
pub const DEFAULT_GUEST_RUNNER_POLL_TIMEOUT_MILLIS: i32 = 1_000;

#[cfg(feature = "wire-json")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxGuestBridgeRunnerConfig {
    pump_loop_config: GuestPumpLoopConfig,
    json_wire_config: JsonWireConfig,
    idle_poll_timeout_millis: i32,
    write_poll_timeout_millis: i32,
}

#[cfg(feature = "wire-json")]
impl LinuxGuestBridgeRunnerConfig {
    pub fn builder() -> LinuxGuestBridgeRunnerConfigBuilder {
        LinuxGuestBridgeRunnerConfigBuilder::default()
    }

    pub fn pump_loop_config(&self) -> &GuestPumpLoopConfig {
        &self.pump_loop_config
    }

    pub fn json_wire_config(&self) -> &JsonWireConfig {
        &self.json_wire_config
    }

    pub const fn idle_poll_timeout_millis(&self) -> i32 {
        self.idle_poll_timeout_millis
    }

    pub const fn write_poll_timeout_millis(&self) -> i32 {
        self.write_poll_timeout_millis
    }
}

#[cfg(feature = "wire-json")]
impl Default for LinuxGuestBridgeRunnerConfig {
    fn default() -> Self {
        Self {
            pump_loop_config: GuestPumpLoopConfig::default(),
            json_wire_config: JsonWireConfig::default(),
            idle_poll_timeout_millis: DEFAULT_GUEST_RUNNER_POLL_TIMEOUT_MILLIS,
            write_poll_timeout_millis: DEFAULT_GUEST_RUNNER_POLL_TIMEOUT_MILLIS,
        }
    }
}

#[cfg(feature = "wire-json")]
#[derive(Debug, Clone)]
pub struct LinuxGuestBridgeRunnerConfigBuilder {
    pump_loop_config: GuestPumpLoopConfig,
    json_wire_config: JsonWireConfig,
    idle_poll_timeout_millis: i32,
    write_poll_timeout_millis: i32,
}

#[cfg(feature = "wire-json")]
impl Default for LinuxGuestBridgeRunnerConfigBuilder {
    fn default() -> Self {
        let config = LinuxGuestBridgeRunnerConfig::default();
        Self {
            pump_loop_config: config.pump_loop_config,
            json_wire_config: config.json_wire_config,
            idle_poll_timeout_millis: config.idle_poll_timeout_millis,
            write_poll_timeout_millis: config.write_poll_timeout_millis,
        }
    }
}

#[cfg(feature = "wire-json")]
impl LinuxGuestBridgeRunnerConfigBuilder {
    pub fn pump_loop_config(mut self, pump_loop_config: GuestPumpLoopConfig) -> Self {
        self.pump_loop_config = pump_loop_config;
        self
    }

    pub fn json_wire_config(mut self, json_wire_config: JsonWireConfig) -> Self {
        self.json_wire_config = json_wire_config;
        self
    }

    pub fn idle_poll_timeout_millis(mut self, idle_poll_timeout_millis: i32) -> Self {
        self.idle_poll_timeout_millis = idle_poll_timeout_millis;
        self
    }

    pub fn write_poll_timeout_millis(mut self, write_poll_timeout_millis: i32) -> Self {
        self.write_poll_timeout_millis = write_poll_timeout_millis;
        self
    }

    pub fn build(self) -> Result<LinuxGuestBridgeRunnerConfig, LinuxGuestBridgeRunError> {
        if self.idle_poll_timeout_millis <= 0 {
            return Err(LinuxGuestBridgeRunError::InvalidConfig(
                "idle_poll_timeout_millis must be positive",
            ));
        }
        if self.write_poll_timeout_millis <= 0 {
            return Err(LinuxGuestBridgeRunError::InvalidConfig(
                "write_poll_timeout_millis must be positive",
            ));
        }
        Ok(LinuxGuestBridgeRunnerConfig {
            pump_loop_config: self.pump_loop_config,
            json_wire_config: self.json_wire_config,
            idle_poll_timeout_millis: self.idle_poll_timeout_millis,
            write_poll_timeout_millis: self.write_poll_timeout_millis,
        })
    }
}

#[cfg(feature = "wire-json")]
#[derive(Debug)]
pub enum LinuxGuestBridgeRunError {
    Bridge(GuestBridgeExecError),
    Pump(GuestPumpError),
    Io {
        operation: &'static str,
        reason: String,
    },
    InvalidConfig(&'static str),
}

#[cfg(feature = "wire-json")]
impl fmt::Display for LinuxGuestBridgeRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bridge(err) => write!(f, "{err}"),
            Self::Pump(err) => write!(f, "{err}"),
            Self::Io { operation, reason } => write!(f, "{operation} failed: {reason}"),
            Self::InvalidConfig(reason) => {
                write!(f, "invalid guest bridge runner config: {reason}")
            }
        }
    }
}

#[cfg(feature = "wire-json")]
impl std::error::Error for LinuxGuestBridgeRunError {}

#[cfg(feature = "wire-json")]
impl From<GuestBridgeExecError> for LinuxGuestBridgeRunError {
    fn from(value: GuestBridgeExecError) -> Self {
        Self::Bridge(value)
    }
}

#[cfg(feature = "wire-json")]
impl From<GuestPumpError> for LinuxGuestBridgeRunError {
    fn from(value: GuestPumpError) -> Self {
        Self::Pump(value)
    }
}

#[cfg(all(feature = "wire-json", not(target_os = "linux")))]
pub fn run_linux_guest_bridge(
    _config: &GuestBridgeConfig,
    _runner_config: LinuxGuestBridgeRunnerConfig,
) -> Result<GuestPumpRunStats, LinuxGuestBridgeRunError> {
    Err(LinuxGuestBridgeRunError::Bridge(
        GuestBridgeExecError::UnsupportedPlatform,
    ))
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
pub fn run_linux_guest_bridge(
    config: &GuestBridgeConfig,
    runner_config: LinuxGuestBridgeRunnerConfig,
) -> Result<GuestPumpRunStats, LinuxGuestBridgeRunError> {
    let runtime = start_linux_guest_bridge(config)?;
    run_started_linux_guest_bridge(runtime, runner_config)
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
pub fn run_started_linux_guest_bridge(
    runtime: GuestBridgeRuntime<std::fs::File, std::fs::File>,
    runner_config: LinuxGuestBridgeRunnerConfig,
) -> Result<GuestPumpRunStats, LinuxGuestBridgeRunError> {
    let GuestBridgeRuntime { tun, authority } = runtime;
    let tun_sink = tun
        .try_clone()
        .map_err(|err| run_io_failed("clone_tun", err))?;

    set_nonblocking(tun.as_raw_fd(), "set_tun_nonblocking")?;
    set_nonblocking(authority.as_raw_fd(), "set_authority_nonblocking")?;

    let tun_fd = tun.as_raw_fd();
    let authority_fd = authority.as_raw_fd();
    let write_poll_timeout_millis = runner_config.write_poll_timeout_millis;
    let mut source = TunPacketIo::new(LinuxPolledIo::new(tun, write_poll_timeout_millis));
    let mut sink = TunPacketIo::new(LinuxPolledIo::new(tun_sink, write_poll_timeout_millis));
    let authority = LengthPrefixedJsonAuthority::with_config(
        LinuxPolledIo::new(authority, write_poll_timeout_millis),
        runner_config.json_wire_config,
    );
    let mut pump = GuestBridgePump::new(GuestPacketTranslator::default(), authority);
    send_guest_hello(pump.authority_mut())?;

    let mut pump_loop = GuestPumpLoop::new(runner_config.pump_loop_config);
    let mut wait =
        LinuxGuestPumpWait::new(tun_fd, authority_fd, runner_config.idle_poll_timeout_millis);
    run_guest_pump_loop(&mut pump_loop, &mut pump, &mut source, &mut sink, &mut wait)
        .map_err(Into::into)
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
fn send_guest_hello<A>(authority: &mut A) -> Result<(), LinuxGuestBridgeRunError>
where
    A: GuestAuthority,
{
    let capabilities = vec![
        Capability::Dns,
        Capability::Tcp,
        Capability::Udp,
        Capability::IcmpEcho,
    ];
    authority
        .send_message(NetMessage::Hello(Hello::new(
            EndpointRole::Guest,
            capabilities,
        )))
        .map_err(|err| LinuxGuestBridgeRunError::Pump(GuestPumpError::Authority(err.to_string())))
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
#[derive(Debug)]
struct LinuxPolledIo<T> {
    inner: T,
    write_poll_timeout_millis: i32,
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
impl<T> LinuxPolledIo<T> {
    fn new(inner: T, write_poll_timeout_millis: i32) -> Self {
        Self {
            inner,
            write_poll_timeout_millis,
        }
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
impl<T> Read for LinuxPolledIo<T>
where
    T: Read,
{
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
impl<T> Write for LinuxPolledIo<T>
where
    T: Write + AsRawFd,
{
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            match self.inner.write(buffer) {
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    poll_writable(self.inner.as_raw_fd(), self.write_poll_timeout_millis)?;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
#[derive(Debug)]
struct LinuxGuestPumpWait {
    tun_fd: RawFd,
    authority_fd: RawFd,
    idle_poll_timeout_millis: i32,
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
impl LinuxGuestPumpWait {
    fn new(tun_fd: RawFd, authority_fd: RawFd, idle_poll_timeout_millis: i32) -> Self {
        Self {
            tun_fd,
            authority_fd,
            idle_poll_timeout_millis,
        }
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
impl GuestPumpWait for LinuxGuestPumpWait {
    type Error = io::Error;

    fn wait_for_activity(&mut self) -> Result<(), Self::Error> {
        poll_readable_pair(
            self.tun_fd,
            self.authority_fd,
            self.idle_poll_timeout_millis,
        )
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
fn set_nonblocking(fd: RawFd, operation: &'static str) -> Result<(), LinuxGuestBridgeRunError> {
    // SAFETY: `fd` is an open Linux fd owned by the bridge runtime.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(run_io_failed(operation, io::Error::last_os_error()));
    }
    // SAFETY: `fd` is valid and flags preserve the existing file status bits.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(run_io_failed(operation, io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
fn poll_writable(fd: RawFd, timeout_millis: i32) -> io::Result<()> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    poll_one(&mut pollfd, timeout_millis)?;
    if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(io::Error::from(ErrorKind::BrokenPipe));
    }
    Ok(())
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
fn poll_readable_pair(tun_fd: RawFd, authority_fd: RawFd, timeout_millis: i32) -> io::Result<()> {
    let mut pollfds = [
        libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: authority_fd,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `pollfds` points to two initialized pollfd entries.
        let rc = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                timeout_millis,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        if rc > 0 {
            if pollfds
                .iter()
                .any(|pollfd| pollfd.revents & libc::POLLNVAL != 0)
            {
                return Err(io::Error::from(ErrorKind::BrokenPipe));
            }
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
fn poll_one(pollfd: &mut libc::pollfd, timeout_millis: i32) -> io::Result<()> {
    loop {
        // SAFETY: `pollfd` points to one initialized pollfd entry.
        let rc = unsafe { libc::poll(pollfd, 1, timeout_millis) };
        if rc == 0 {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        if rc > 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(all(feature = "wire-json", target_os = "linux"))]
fn run_io_failed(operation: &'static str, err: io::Error) -> LinuxGuestBridgeRunError {
    LinuxGuestBridgeRunError::Io {
        operation,
        reason: err.to_string(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::path::Path;

    use super::{
        GuestBridgeExecError, GuestBridgeSystem, InterfaceName, Ipv4Addr, Ipv4Cidr,
        resolver_contents,
    };

    const TUN_DEVICE: &str = "/dev/net/tun";
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const HOST_CID: u32 = 2;
    const AF_VSOCK: libc::c_int = 40;

    fn operation_failed(
        operation: &'static str,
        reason: impl Into<String>,
    ) -> GuestBridgeExecError {
        GuestBridgeExecError::OperationFailed {
            operation,
            reason: reason.into(),
        }
    }

    pub struct LinuxGuestBridgeSystem;

    impl LinuxGuestBridgeSystem {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for LinuxGuestBridgeSystem {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GuestBridgeSystem for LinuxGuestBridgeSystem {
        type Tun = File;
        type Authority = File;

        fn open_tun(&mut self, name: &InterfaceName) -> Result<Self::Tun, GuestBridgeExecError> {
            open_tun(name)
        }

        fn assign_address(
            &mut self,
            name: &InterfaceName,
            address: Ipv4Addr,
            link: Ipv4Cidr,
        ) -> Result<(), GuestBridgeExecError> {
            assign_address(name, address, link)
        }

        fn bring_interface_up(&mut self, name: &InterfaceName) -> Result<(), GuestBridgeExecError> {
            bring_interface_up(name)
        }

        fn install_default_route(
            &mut self,
            name: &InterfaceName,
            gateway: Ipv4Addr,
        ) -> Result<(), GuestBridgeExecError> {
            install_default_route(name, gateway)
        }

        fn write_resolver(
            &mut self,
            path: &Path,
            backup_path: &Path,
            nameserver: Ipv4Addr,
        ) -> Result<(), GuestBridgeExecError> {
            write_resolver(path, backup_path, nameserver)
        }

        fn connect_vsock_authority(
            &mut self,
            port: u32,
        ) -> Result<Self::Authority, GuestBridgeExecError> {
            connect_vsock_authority(port)
        }
    }

    fn open_tun(name: &InterfaceName) -> Result<File, GuestBridgeExecError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_DEVICE)
            .map_err(|e| operation_failed("open_tun", e.to_string()))?;
        let mut ifr = ifreq_for(name)?;
        // SAFETY: `file` owns a valid fd for /dev/net/tun; `ifr` is a fully
        // initialized ifreq with a NUL-padded interface name and valid TUN flags.
        let rc = unsafe {
            ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
            libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as libc::Ioctl, &mut ifr)
        };
        if rc < 0 {
            return Err(operation_failed(
                "open_tun",
                io::Error::last_os_error().to_string(),
            ));
        }
        Ok(file)
    }

    fn assign_address(
        name: &InterfaceName,
        address: Ipv4Addr,
        link: Ipv4Cidr,
    ) -> Result<(), GuestBridgeExecError> {
        with_inet_socket("assign_address", |sock| {
            set_ifaddr(sock, name, libc::SIOCSIFADDR, address, "SIOCSIFADDR")?;
            set_ifaddr(
                sock,
                name,
                libc::SIOCSIFNETMASK,
                prefix_to_netmask(link.prefix()),
                "SIOCSIFNETMASK",
            )
        })
    }

    fn bring_interface_up(name: &InterfaceName) -> Result<(), GuestBridgeExecError> {
        with_inet_socket("bring_interface_up", |sock| {
            let mut ifr = ifreq_for(name)?;
            // SAFETY: `ifr` points to initialized writable memory and `sock`
            // is an owned AF_INET control socket.
            let rc = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::Ioctl, &mut ifr) };
            if rc < 0 {
                return Err(last_os("SIOCGIFFLAGS"));
            }
            // SAFETY: SIOCGIFFLAGS initialized `ifru_flags`; assigning the same
            // union field with additional flags is the expected Linux ABI use.
            unsafe {
                let flags = ifr.ifr_ifru.ifru_flags;
                ifr.ifr_ifru.ifru_flags =
                    flags | (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            }
            // SAFETY: `ifr` carries a valid interface name and flags for
            // SIOCSIFFLAGS; `sock` is the AF_INET control socket.
            let rc = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::Ioctl, &ifr) };
            if rc < 0 {
                return Err(last_os("SIOCSIFFLAGS"));
            }
            Ok(())
        })
    }

    fn install_default_route(
        name: &InterfaceName,
        gateway: Ipv4Addr,
    ) -> Result<(), GuestBridgeExecError> {
        with_inet_socket("install_default_route", |sock| {
            // SAFETY: rtentry is a C POD struct where zero is the kernel's
            // expected base state before filling route fields.
            let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
            // SAFETY: rt_dst, rt_genmask, and rt_gateway are sockaddr fields
            // inside this owned rtentry and can hold an IPv4 sockaddr_in.
            unsafe {
                set_sockaddr_in(&mut rt.rt_dst, Ipv4Addr::new(0, 0, 0, 0));
                set_sockaddr_in(&mut rt.rt_genmask, Ipv4Addr::new(0, 0, 0, 0));
                set_sockaddr_in(&mut rt.rt_gateway, gateway);
            }
            rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
            let dev = std::ffi::CString::new(name.as_str())
                .map_err(|e| operation_failed("SIOCADDRT", e.to_string()))?;
            rt.rt_dev = dev.as_ptr().cast_mut();
            // SAFETY: `rt` points to a fully initialized rtentry and `rt_dev`
            // points at `dev`, which lives for the duration of the ioctl.
            let rc = unsafe { libc::ioctl(sock, libc::SIOCADDRT as libc::Ioctl, &rt) };
            if rc < 0 {
                return Err(last_os("SIOCADDRT"));
            }
            Ok(())
        })
    }

    fn write_resolver(
        path: &Path,
        backup_path: &Path,
        nameserver: Ipv4Addr,
    ) -> Result<(), GuestBridgeExecError> {
        if let Some(parent) = backup_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| operation_failed("write_resolver", e.to_string()))?;
        }
        if path.exists() && !backup_path.exists() {
            std::fs::copy(path, backup_path)
                .map_err(|e| operation_failed("write_resolver", e.to_string()))?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| operation_failed("write_resolver", e.to_string()))?;
        }
        std::fs::write(path, resolver_contents(nameserver))
            .map_err(|e| operation_failed("write_resolver", e.to_string()))
    }

    fn connect_vsock_authority(port: u32) -> Result<File, GuestBridgeExecError> {
        // SAFETY: socket(2) returns either a valid fd or -1; both paths are
        // handled before ownership is transferred to UnixStream.
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(operation_failed(
                "connect_vsock_authority",
                io::Error::last_os_error().to_string(),
            ));
        }
        let addr = libc::sockaddr_vm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: HOST_CID,
            svm_zero: [0; 4],
        };
        // SAFETY: `addr` is a fully initialized sockaddr_vm and `fd` is a
        // socket(AF_VSOCK, SOCK_STREAM) owned by this function.
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            close_fd(fd);
            return Err(operation_failed("connect_vsock_authority", err.to_string()));
        }
        // SAFETY: connect succeeded, so `fd` is a valid owned stream fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn with_inet_socket(
        operation: &'static str,
        f: impl FnOnce(RawFd) -> Result<(), GuestBridgeExecError>,
    ) -> Result<(), GuestBridgeExecError> {
        // SAFETY: socket(2) returns either a valid fd or -1; both paths are
        // handled, and the valid fd is closed exactly once before return.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(operation_failed(
                operation,
                io::Error::last_os_error().to_string(),
            ));
        }
        let result = f(sock);
        close_fd(sock);
        result
    }

    fn set_ifaddr(
        sock: RawFd,
        name: &InterfaceName,
        request: libc::Ioctl,
        address: Ipv4Addr,
        operation: &'static str,
    ) -> Result<(), GuestBridgeExecError> {
        let mut ifr = ifreq_for(name)?;
        // SAFETY: `ifru_addr` is the sockaddr field for SIOCSIFADDR and
        // SIOCSIFNETMASK. It points into `ifr`, which is initialized and owned.
        unsafe {
            set_sockaddr_in(&mut ifr.ifr_ifru.ifru_addr, address);
        }
        // SAFETY: `ifr` is initialized for the requested interface and address;
        // `sock` is an AF_INET control socket.
        let rc = unsafe { libc::ioctl(sock, request, &ifr) };
        if rc < 0 {
            return Err(last_os(operation));
        }
        Ok(())
    }

    fn ifreq_for(name: &InterfaceName) -> Result<libc::ifreq, GuestBridgeExecError> {
        // SAFETY: ifreq is a C POD request struct where zero is the expected
        // base state before setting the interface name and request-specific union.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (idx, byte) in name.as_str().bytes().enumerate() {
            ifr.ifr_name[idx] = byte as libc::c_char;
        }
        Ok(ifr)
    }

    unsafe fn set_sockaddr_in(dst: *mut libc::sockaddr, address: Ipv4Addr) {
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: caller guarantees `dst` points at a sockaddr-sized field in an
        // initialized kernel request struct. sockaddr_in is 16 bytes on Linux.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sin as *const libc::sockaddr_in as *const u8,
                dst as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }
    }

    fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
        if prefix == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }
        Ipv4Addr::from(u32::MAX << (32 - prefix))
    }

    fn close_fd(fd: RawFd) {
        // SAFETY: caller passes an owned fd that has not yet been closed.
        unsafe {
            libc::close(fd);
        }
    }

    fn last_os(operation: &'static str) -> GuestBridgeExecError {
        operation_failed(operation, io::Error::last_os_error().to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn prefix_to_netmask_handles_boundaries() {
            assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
            assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
            assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use std::net::Ipv4Addr;
    use std::path::Path;

    use super::{GuestBridgeExecError, GuestBridgeSystem, InterfaceName, Ipv4Cidr};

    #[derive(Debug)]
    pub struct UnsupportedHandle;

    pub struct LinuxGuestBridgeSystem;

    impl LinuxGuestBridgeSystem {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for LinuxGuestBridgeSystem {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GuestBridgeSystem for LinuxGuestBridgeSystem {
        type Tun = UnsupportedHandle;
        type Authority = UnsupportedHandle;

        fn open_tun(&mut self, _name: &InterfaceName) -> Result<Self::Tun, GuestBridgeExecError> {
            Err(GuestBridgeExecError::UnsupportedPlatform)
        }

        fn assign_address(
            &mut self,
            _name: &InterfaceName,
            _address: Ipv4Addr,
            _link: Ipv4Cidr,
        ) -> Result<(), GuestBridgeExecError> {
            Err(GuestBridgeExecError::UnsupportedPlatform)
        }

        fn bring_interface_up(
            &mut self,
            _name: &InterfaceName,
        ) -> Result<(), GuestBridgeExecError> {
            Err(GuestBridgeExecError::UnsupportedPlatform)
        }

        fn install_default_route(
            &mut self,
            _name: &InterfaceName,
            _gateway: Ipv4Addr,
        ) -> Result<(), GuestBridgeExecError> {
            Err(GuestBridgeExecError::UnsupportedPlatform)
        }

        fn write_resolver(
            &mut self,
            _path: &Path,
            _backup_path: &Path,
            _nameserver: Ipv4Addr,
        ) -> Result<(), GuestBridgeExecError> {
            Err(GuestBridgeExecError::UnsupportedPlatform)
        }

        fn connect_vsock_authority(
            &mut self,
            _port: u32,
        ) -> Result<Self::Authority, GuestBridgeExecError> {
            Err(GuestBridgeExecError::UnsupportedPlatform)
        }
    }
}

pub use linux::LinuxGuestBridgeSystem;

pub fn start_linux_guest_bridge(
    config: &GuestBridgeConfig,
) -> Result<
    GuestBridgeRuntime<
        <LinuxGuestBridgeSystem as GuestBridgeSystem>::Tun,
        <LinuxGuestBridgeSystem as GuestBridgeSystem>::Authority,
    >,
    GuestBridgeExecError,
> {
    let mut system = LinuxGuestBridgeSystem::new();
    start_guest_bridge(&mut system, config)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockTun;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockAuthority;

    #[derive(Default)]
    struct MockSystem {
        calls: Vec<String>,
        fail_at: Option<&'static str>,
    }

    impl MockSystem {
        fn fail(operation: &'static str) -> Self {
            Self {
                calls: Vec::new(),
                fail_at: Some(operation),
            }
        }

        fn record(&mut self, operation: &'static str) -> Result<(), GuestBridgeExecError> {
            self.calls.push(operation.to_string());
            if self.fail_at == Some(operation) {
                return Err(GuestBridgeExecError::OperationFailed {
                    operation,
                    reason: "injected".to_string(),
                });
            }
            Ok(())
        }
    }

    impl GuestBridgeSystem for MockSystem {
        type Tun = MockTun;
        type Authority = MockAuthority;

        fn open_tun(&mut self, _name: &InterfaceName) -> Result<Self::Tun, GuestBridgeExecError> {
            self.record("open_tun")?;
            Ok(MockTun)
        }

        fn assign_address(
            &mut self,
            _name: &InterfaceName,
            _address: Ipv4Addr,
            _link: Ipv4Cidr,
        ) -> Result<(), GuestBridgeExecError> {
            self.record("assign_address")
        }

        fn bring_interface_up(
            &mut self,
            _name: &InterfaceName,
        ) -> Result<(), GuestBridgeExecError> {
            self.record("bring_interface_up")
        }

        fn install_default_route(
            &mut self,
            _name: &InterfaceName,
            _gateway: Ipv4Addr,
        ) -> Result<(), GuestBridgeExecError> {
            self.record("install_default_route")
        }

        fn write_resolver(
            &mut self,
            _path: &Path,
            _backup_path: &Path,
            _nameserver: Ipv4Addr,
        ) -> Result<(), GuestBridgeExecError> {
            self.record("write_resolver")
        }

        fn connect_vsock_authority(
            &mut self,
            _port: u32,
        ) -> Result<Self::Authority, GuestBridgeExecError> {
            self.record("connect_vsock_authority")?;
            Ok(MockAuthority)
        }
    }

    #[test]
    fn executor_applies_guest_bridge_plan_in_order() {
        let mut system = MockSystem::default();
        let runtime = start_guest_bridge(&mut system, &GuestBridgeConfig::default()).unwrap();

        assert_eq!(runtime.tun, MockTun);
        assert_eq!(runtime.authority, MockAuthority);
        assert_eq!(
            system.calls,
            [
                "open_tun",
                "assign_address",
                "bring_interface_up",
                "install_default_route",
                "write_resolver",
                "connect_vsock_authority"
            ]
        );
    }

    #[test]
    fn executor_fails_closed_and_stops_on_first_failed_operation() {
        let mut system = MockSystem::fail("install_default_route");
        let err = start_guest_bridge(&mut system, &GuestBridgeConfig::default()).unwrap_err();

        assert!(matches!(
            err,
            GuestBridgeExecError::OperationFailed {
                operation: "install_default_route",
                ..
            }
        ));
        assert_eq!(
            system.calls,
            [
                "open_tun",
                "assign_address",
                "bring_interface_up",
                "install_default_route"
            ]
        );
    }

    #[test]
    fn resolver_contents_points_at_synthetic_gateway() {
        assert_eq!(
            resolver_contents(Ipv4Addr::new(198, 18, 0, 1)),
            "nameserver 198.18.0.1\n"
        );
    }

    #[test]
    fn tun_packet_io_reads_one_packet_from_stream() {
        let mut tun = TunPacketIo::new(Cursor::new(vec![1, 2, 3, 4]));
        let mut buffer = [0u8; 8];

        assert_eq!(
            tun.read_packet(&mut buffer).unwrap(),
            GuestPacketRead::Packet { bytes: 4 }
        );
        assert_eq!(&buffer[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn tun_packet_io_reports_would_block_without_error() {
        let mut tun = TunPacketIo::new(WouldBlockIo);
        let mut buffer = [0u8; 8];

        assert_eq!(
            tun.read_packet(&mut buffer).unwrap(),
            GuestPacketRead::WouldBlock
        );
    }

    #[test]
    fn tun_packet_io_reports_closed_stream() {
        let mut tun = TunPacketIo::new(Cursor::new(Vec::new()));
        let mut buffer = [0u8; 8];

        assert_eq!(
            tun.read_packet(&mut buffer).unwrap(),
            GuestPacketRead::Closed
        );
    }

    #[test]
    fn tun_packet_io_writes_complete_packet() {
        let mut tun = TunPacketIo::new(Cursor::new(Vec::new()));

        tun.write_packet(&[5, 6, 7, 8]).unwrap();

        assert_eq!(tun.into_inner().into_inner(), vec![5, 6, 7, 8]);
    }

    #[cfg(feature = "wire-json")]
    #[test]
    fn runner_config_rejects_non_positive_poll_timeouts() {
        assert!(matches!(
            LinuxGuestBridgeRunnerConfig::builder()
                .idle_poll_timeout_millis(0)
                .build(),
            Err(LinuxGuestBridgeRunError::InvalidConfig(_))
        ));
        assert!(matches!(
            LinuxGuestBridgeRunnerConfig::builder()
                .write_poll_timeout_millis(0)
                .build(),
            Err(LinuxGuestBridgeRunError::InvalidConfig(_))
        ));
    }

    #[cfg(all(feature = "wire-json", not(target_os = "linux")))]
    #[test]
    fn runner_reports_unsupported_platform_on_non_linux() {
        assert!(matches!(
            run_linux_guest_bridge(
                &GuestBridgeConfig::default(),
                LinuxGuestBridgeRunnerConfig::default()
            ),
            Err(LinuxGuestBridgeRunError::Bridge(
                GuestBridgeExecError::UnsupportedPlatform
            ))
        ));
    }

    struct WouldBlockIo;

    impl Read for WouldBlockIo {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    impl Write for WouldBlockIo {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
