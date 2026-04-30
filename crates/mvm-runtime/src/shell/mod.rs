//! Shell command execution — production (`exec`) and test mock (`mock`).
//!
//! `mvm_runtime::shell::*` flattens the production interface up to this level
//! so callers can keep using `shell::run_in_vm`, `shell::run_in_vm_stdout`,
//! `shell::replace_process`, etc. The test mock lives at `shell::mock`.

pub mod exec;
pub mod mock;

pub use exec::*;
