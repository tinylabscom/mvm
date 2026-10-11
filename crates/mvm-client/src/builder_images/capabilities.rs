use anyhow::{Context, Result};

/// A resolved config is an optional capability witness; an explicitly
/// incompatible witness must never boot a verity-sealed workload.
pub fn workload_config_carries_dm_verity(config: &str) -> Option<bool> {
    if !config
        .lines()
        .any(|line| line.starts_with("CONFIG_") || line.starts_with("# CONFIG_"))
    {
        return None;
    }
    Some(
        config.lines().any(|line| line == "CONFIG_BLK_DEV_DM=y")
            && config.lines().any(|line| line == "CONFIG_DM_VERITY=y"),
    )
}

pub fn assert_workload_kernel_supports_verity(kernel_path: &str) -> Result<()> {
    std::fs::metadata(kernel_path)
        .with_context(|| format!("read resolved workload kernel {kernel_path}"))?;
    let config_path = std::path::Path::new(kernel_path).with_file_name("config");
    let capability = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|config| workload_config_carries_dm_verity(&config));
    if capability == Some(false) {
        anyhow::bail!(
            "resolved workload kernel {kernel_path} has a config without CONFIG_BLK_DEV_DM=y \
             and CONFIG_DM_VERITY=y, but the workload boots verity-sealed. This kernel cannot \
             back a sealed workload"
        );
    }
    Ok(())
}
