//! Display input authority, route, and interruption cleanup for client callers.
//!
//! Admission and delivery stay in the host implementation. Commands and host
//! embedders reach that implementation through this client facade.

pub use mvm_hostd::display::{DisplayAuthority, DisplayAuthorityError};
pub use mvm_hostd::stream::{DisplayInputRoute, DisplayInputRouteError};
pub use mvm_runtime::interrupt_cleanup::on_interrupt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_machine_name_is_refused_before_loading_authority() {
        let Err(DisplayAuthorityError::Authority(error)) = DisplayAuthority::load("bad/name")
        else {
            panic!("an invalid machine name cannot load display authority");
        };
        assert!(error.to_string().contains("invalid machine name"));
    }
}
