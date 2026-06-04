use crate::ir::Resources;

/// VM resource declaration.
pub fn resources(cpu_cores: u16, memory_mb: u32, rootfs_size_mb: u32) -> Resources {
    Resources {
        cpu_cores,
        memory_mb,
        rootfs_size_mb,
    }
}
