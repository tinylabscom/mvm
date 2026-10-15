//! Experimental manual-registration lifecycle service. No default integration.

#[cfg(any(target_os = "linux", test))]
mod admission;
#[cfg(any(target_os = "linux", test))]
mod core;
#[cfg(any(target_os = "linux", test))]
mod durable;
#[cfg(any(target_os = "linux", test))]
mod identity;
#[cfg(target_os = "linux")]
mod linux;
pub mod protocol;
#[cfg(any(target_os = "linux", all(test, unix)))]
mod transport;

pub const EXECUTABLE: &str = "/usr/libexec/mvm/mvm-fc-lifecycle";
pub const SOCKET: &str = "/run/mvm/fc-lifecycle.sock";
pub const REGISTRY: &str = "/var/lib/mvm/fc-lifecycle";
pub const FIRECRACKER: &str = "/usr/bin/firecracker";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("request refused")]
    Refused,
    #[error("resource limit reached")]
    Limit,
    #[error("unsupported platform or kernel")]
    Unsupported,
    #[error("invalid protocol")]
    Protocol,
    #[error("lifecycle I/O failed")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Serve only at the fixed installed locations. Calling this never installs files.
pub fn serve_experimental() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::serve()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Unsupported)
    }
}

/// One bounded request to the fixed service, authenticating its kernel identity.
pub fn request(request: &protocol::Request) -> Result<protocol::Response> {
    #[cfg(target_os = "linux")]
    {
        linux::request(request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        Err(Error::Unsupported)
    }
}
