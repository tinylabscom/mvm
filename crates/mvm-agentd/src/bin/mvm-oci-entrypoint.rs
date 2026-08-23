//! Shell-free OCI entrypoint runner.
//!
//! The guest agent validates and executes this binary through the normal
//! `/etc/mvm/entrypoint` contract. This runner then execs the OCI image's
//! configured Entrypoint/Cmd argv directly, without `/bin/sh -c`.
//!
//! It resolves the environment through `mvm_agentd::workload_env`, the same
//! resolver the interactive console uses, so a workload and a shell opened
//! against it see the same `PATH`, the same image vars, and the same working
//! directory.

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use mvm_agentd::workload_env::{ImageRuntimeConfig, WorkloadEnvironment};

    pub fn main() {
        let config = match ImageRuntimeConfig::load() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("mvm-oci-entrypoint: {e}");
                std::process::exit(127);
            }
        };
        if config.argv.is_empty() {
            eprintln!("mvm-oci-entrypoint: OCI image declares no Entrypoint or Cmd");
            std::process::exit(127);
        }

        // No `.inherit()`: a non-interactive workload starts from the image's
        // declaration alone, not from whatever PID 1 happened to export.
        let resolved = WorkloadEnvironment::builder().image(&config).build();

        let mut command = Command::new(&config.argv[0]);
        command.args(&config.argv[1..]);
        command.env_clear();
        command.envs(resolved.vars());
        command.current_dir(resolved.working_dir());

        let err = command.exec();
        eprintln!(
            "mvm-oci-entrypoint: exec {:?}: {err}",
            config.argv.first().map(String::as_str)
        );
        std::process::exit(127);
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-oci-entrypoint is Linux-only");
    std::process::exit(1);
}
