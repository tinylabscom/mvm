//! Machine-readable pool status output types.

#[derive(serde::Serialize)]
pub(super) struct PoolStatus {
    pub(super) idle: usize,
    pub(super) claimed: usize,
    pub(super) parked: usize,
    pub(super) dead: usize,
    pub(super) standbys: Vec<PoolStatusEntry>,
}

#[derive(serde::Serialize)]
pub(super) struct PoolStatusEntry {
    pub(super) id: String,
    pub(super) state: &'static str,
    pub(super) pid: u32,
    pub(super) kernel_sha256: String,
    pub(super) vcpus: u8,
    pub(super) mem_mib: u32,
    /// The image half of the compat key: sha256 of the rootfs the parent
    /// booted. Every standby carries one, since a parent is only ever spawned
    /// for a resolved launch shape; absent marks a record predating that.
    pub(super) image_sha256: Option<String>,
}
