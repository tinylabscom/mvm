//! The `MvmClient` facade: one trait fronting local microVM operations
//! (in-process) and a remote `mvmd` fleet (REST), so a caller drives either
//! target through the same calls. The remote implementation is a courier with
//! no enforcement authority — every security decision is made by the authority
//! that owns the path (the local host, or mvmd), never by this client.

pub mod client;
pub mod connect;
pub mod dto;
pub mod error;
#[cfg(feature = "remote")]
pub mod gateway;
pub mod mock;

pub use client::MvmClient;
pub use connect::{Target, connect};
pub use error::{MvmError, Result};
