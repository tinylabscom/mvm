//! Supervisor-side workload exit-code capture.
//!
//! The whole convention — file name, path, reader, and the `capture_once`
//! writer — lives in `mvm-core::exit_capture` so every host-side capture site
//! shares one implementation. This module re-exports it under the historical
//! `mvm_hostd::exit_capture` path the supervisor binary imports.

pub use mvm_core::exit_capture::{WORKLOAD_EXIT_FILE, capture_once, exit_file_path, read_captured};
