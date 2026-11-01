//! Pure destination intent validation only. No output collection or receipt
//! publication is implemented here.
pub mod destination;
pub use mvm_hostd::audit::output_audit::{OutputOutcome, OutputRecord};
