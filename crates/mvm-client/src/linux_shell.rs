//! Commands run inside the host's Linux environment.

pub use mvm_runtime::linux_env::default_env_runs_on_host;
pub use mvm_runtime::shell::{run_in_vm, run_in_vm_stdout};
