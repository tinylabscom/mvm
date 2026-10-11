//! Compatibility adapter for the client-owned verified image cache.

use anyhow::Result;
use mvm_client::workspace_apply::cache;

pub(crate) struct MountImageCache(cache::MountImageCache);

impl MountImageCache {
    pub(crate) fn new() -> Result<Self> {
        #[cfg(test)]
        let cache = cache::MountImageCache::with_encryption_probe(|_| Ok(()))?;
        #[cfg(not(test))]
        let cache = cache::MountImageCache::with_encryption_probe(
            crate::doctor::require_local_volume_host_path_encrypted,
        )?;
        Ok(Self(cache))
    }
}

impl std::ops::Deref for MountImageCache {
    type Target = cache::MountImageCache;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
