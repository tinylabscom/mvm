//! Shell-free OCI entrypoint runner.
//!
//! The guest agent validates and executes this binary through the normal
//! `/etc/mvm/entrypoint` contract. This runner then execs the OCI image's
//! configured Entrypoint/Cmd argv directly, without `/bin/sh -c`.

#[cfg(target_os = "linux")]
mod linux {
    use serde::Deserialize;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    const CONFIG_PATH: &str = "/etc/mvm/oci-entrypoint.json";

    #[derive(Debug, Deserialize)]
    struct OciEntrypointConfig {
        argv: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        working_dir: Option<String>,
    }

    pub fn main() {
        let config = match read_config() {
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

        let mut command = Command::new(&config.argv[0]);
        command.args(&config.argv[1..]);
        command.env_clear();
        let mut has_path = false;
        for item in &config.env {
            if let Some((key, value)) = item.split_once('=') {
                if key == "PATH" {
                    has_path = true;
                }
                command.env(key, value);
            }
        }
        if !has_path {
            command.env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            );
        }
        if let Some(dir) = &config.working_dir
            && !dir.is_empty()
        {
            command.current_dir(dir);
        }

        let err = command.exec();
        eprintln!(
            "mvm-oci-entrypoint: exec {:?}: {err}",
            config.argv.first().map(String::as_str)
        );
        std::process::exit(127);
    }

    fn read_config() -> Result<OciEntrypointConfig, String> {
        let bytes = std::fs::read(CONFIG_PATH).map_err(|e| format!("read {CONFIG_PATH}: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {CONFIG_PATH}: {e}"))
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
