//! Host state of the critical-systems profile beneath an mvm home.

use std::path::{Path, PathBuf};

/// Admitted topology generations, one directory per tenant: `<mvm_home>/topologies`.
pub fn topologies_dir_at(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join("topologies")
}

/// Host-held state cells, one directory per tenant: `<mvm_home>/state-cells`.
pub fn state_cells_dir_at(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join("state-cells")
}

/// Host-held liveness deadlines, one file per tenant: `<mvm_home>/liveness`.
pub fn liveness_dir_at(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join("liveness")
}
