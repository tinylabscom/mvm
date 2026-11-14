//! Shell command execution — production (`exec`) and test mock (`mock`).
//!
//! `mvm::shell::*` flattens the production interface up to this level
//! so callers can keep using `shell::run_in_vm`, `shell::run_in_vm_stdout`,
//! `shell::replace_process`, etc. The test mock lives at `shell::mock`.

pub mod exec;
pub mod mock;

#[cfg(unix)]
pub use exec::replace_process;
pub use exec::{
    run_host, run_host_visible, run_in_vm, run_in_vm_capture, run_in_vm_stdout, run_in_vm_visible,
    run_on_vm, run_on_vm_capture, run_on_vm_visible, shell_quote,
};
