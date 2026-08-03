//! Canonical host-wide machine inventory for non-CLI consumers.
//!
//! Issue #2078 moves the persisted-spec × live-backend join out of
//! `mvm-cli::commands::machine::list` so `mvmctl machine ls` and local UI
//! surfaces such as mvm-studio consume one typed inventory contract.
