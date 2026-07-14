//! Transparent vsock networking primitives for mvm.
//!
//! The crate starts with the shared wire protocol. Guest TUN bridging, host
//! flow handling, TLS transformation, and plugin execution will live here as
//! concrete modules as those layers land.

#![deny(unsafe_code)]

#[cfg(feature = "guest")]
pub mod guest;

#[cfg(feature = "guest-linux-runner")]
pub mod guest_netd;

#[cfg(feature = "guest")]
pub mod guest_packet;

#[cfg(feature = "guest")]
pub mod guest_pump;

#[cfg(feature = "guest-linux")]
pub mod guest_linux;

#[cfg(feature = "host")]
pub mod host;

#[cfg(feature = "host")]
pub mod stream_transform;

#[cfg(feature = "host-tls")]
pub mod host_tls;

#[cfg(feature = "host-netd")]
pub mod host_netd;

#[cfg(feature = "host-runner")]
pub mod host_runner;

#[cfg(feature = "proto")]
pub mod proto;

#[cfg(feature = "wire-json")]
pub mod wire_json;
