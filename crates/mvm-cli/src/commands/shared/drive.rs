//! Drive-file builders — convert CLI inputs into `microvm::DriveFile` entries
//! that get baked into the config drive.

use anyhow::Result;

use mvm_runtime::vm::microvm;

/// Convert port mappings into a `DriveFile` for the config drive.
/// Writes `export MVM_PORT_MAP="3333:3000,3334:3002"`.
pub fn ports_to_drive_file(
    ports: &[mvm_runtime::config::PortMapping],
) -> Option<microvm::DriveFile> {
    if ports.is_empty() {
        return None;
    }
    let map_str = ports
        .iter()
        .map(|p| format!("{}:{}", p.host, p.guest))
        .collect::<Vec<_>>()
        .join(",");
    Some(microvm::DriveFile {
        name: "mvm-ports.env".to_string(),
        content: format!("export MVM_PORT_MAP=\"{}\"\n", map_str),
        mode: 0o444,
    })
}

/// Convert env var specs ("KEY=VALUE") into a `DriveFile` for the config drive.
pub fn env_vars_to_drive_file(env_vars: &[String]) -> Option<microvm::DriveFile> {
    if env_vars.is_empty() {
        return None;
    }
    let content = env_vars
        .iter()
        .map(|kv| format!("export {}", kv))
        .collect::<Vec<_>>()
        .join("\n");
    Some(microvm::DriveFile {
        name: "mvm-env.env".to_string(),
        content: format!("{}\n", content),
        mode: 0o444,
    })
}

/// Read all regular files from a directory into `DriveFile` entries.
pub fn read_dir_to_drive_files(dir: &str, default_mode: u32) -> Result<Vec<microvm::DriveFile>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(microvm::DriveFile {
                name: entry.file_name().to_string_lossy().to_string(),
                content: std::fs::read_to_string(entry.path())?,
                mode: default_mode,
            });
        }
    }
    Ok(files)
}
