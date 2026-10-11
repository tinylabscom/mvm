//! Strict presentation inputs translated into authoritative volume requests.

use super::{
    AccessMode, AttachmentRecord, AttachmentRequest, CreateBlockVolumeRequest, LocalVolumeService,
    VolumeRecord, VolumeService,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct NameRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub name: String,
    pub capacity_mib: u32,
    #[serde(default)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct MountRequest {
    pub vm: String,
    pub volume: String,
    pub guest_path: String,
    #[serde(default)]
    pub host: Option<PathBuf>,
    #[serde(default)]
    pub access: AccessMode,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct MachineRequest {
    pub vm: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DetachRequest {
    pub vm: String,
    pub guest_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SnapshotRequest {
    pub name: String,
    pub snapshot: String,
}

/// The same host-encryption diagnostic used by imperative volume mounting.
pub fn service() -> LocalVolumeService {
    LocalVolumeService::with_host_encryption_probe(super::probe_from_fn(
        super::require_host_path_encrypted,
    ))
}

pub fn create(request: &CreateRequest) -> Result<VolumeRecord> {
    let mut builder =
        CreateBlockVolumeRequest::builder(&request.name)?.capacity_mib(request.capacity_mib);
    if let Some(root) = &request.root {
        builder = builder.root(root);
    }
    service().create_block_volume(&builder.build()?)
}

/// Translate wire fields into the same registration/profile/cache sequence as
/// an imperative mount. No caller-supplied admitted profile or lease is accepted.
pub fn mount(request: &MountRequest) -> Result<AttachmentRecord> {
    let attachment = AttachmentRequest::builder(&request.vm, &request.volume)?
        .guest_path(&request.guest_path)
        .access(request.access)
        .profile(super::registration_profile(&request.vm)?)
        .build()?;
    let service = service();
    match &request.host {
        Some(host) => {
            let cache = crate::workspace_apply::cache::MountImageCache::new()?;
            service.mount_host_snapshot(&attachment, host, &cache)
        }
        None => service.prepare_attachment(&attachment),
    }
}
