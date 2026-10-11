//! Durable agent-session service operations. Admission and boot retain the existing
//! development-session contract; this is not a sealed VM restore API.

mod dto;
mod operations;

pub use dto::*;
pub use operations::AgentSessions;
