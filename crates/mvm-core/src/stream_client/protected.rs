//! Protected console routing metadata. Payloads live only in encrypted generations.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const RUN_FILENAME: &str = "protected-run.json";
pub const GENERATIONS_DIRECTORY: &str = "generations";

/// Selects the current boot without mixing sequence spaces from earlier boots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRun {
    pub version: u32,
    pub run: String,
    pub persists: bool,
}

impl ProtectedRun {
    pub fn directory(&self, root: &Path) -> io::Result<PathBuf> {
        if self.version != 1
            || self.run.is_empty()
            || self.run.len() > 64
            || !self.run.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protected capture routing",
            ));
        }
        Ok(root.join(GENERATIONS_DIRECTORY).join(&self.run))
    }

    pub fn publish(&self, root: &Path) -> io::Result<()> {
        self.directory(root)?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        crate::util::atomic_io::atomic_write(&root.join(RUN_FILENAME), &bytes)
            .map_err(io::Error::other)
    }

    pub fn read(root: &Path) -> io::Result<Option<Self>> {
        let bytes = match std::fs::read(root.join(RUN_FILENAME)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let run: Self = serde_json::from_slice(&bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protected capture routing",
            )
        })?;
        run.directory(root)?;
        Ok(Some(run))
    }
}

/// Consult the launcher's explicit requirement even when owner setup failed
/// before publishing a run. Missing capture must not resurrect a legacy log.
pub fn required(state: &Path) -> io::Result<bool> {
    let bytes = match std::fs::read(state.join("supervisor.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid supervisor capture requirement",
        )
    })?;
    Ok(config.get("console_capture").is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_roundtrip_and_traversal_refusal() {
        let root = tempfile::tempdir().unwrap();
        let run = ProtectedRun {
            version: 1,
            run: "123-456".into(),
            persists: true,
        };
        run.publish(root.path()).unwrap();
        assert_eq!(
            ProtectedRun::read(root.path()).unwrap().unwrap().run,
            run.run
        );
        for value in ["../escape", "/absolute", "", "a/b"] {
            assert!(
                ProtectedRun {
                    run: value.into(),
                    ..run.clone()
                }
                .directory(root.path())
                .is_err()
            );
        }
    }
}
