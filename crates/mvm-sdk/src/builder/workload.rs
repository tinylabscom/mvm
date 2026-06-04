use std::collections::BTreeMap;

use crate::ir::{App, Volume, Workload};

use crate::error::BuildError;

use super::SCHEMA_VERSION;

/// Start declaring a workload with the given id.
pub fn workload(id: impl Into<String>) -> WorkloadBuilder {
    WorkloadBuilder {
        id: id.into(),
        apps: Vec::new(),
        volumes: Vec::new(),
    }
}

#[must_use = "WorkloadBuilder is lazy — call .build() to produce a Workload"]
pub struct WorkloadBuilder {
    id: String,
    apps: Vec<App>,
    volumes: Vec<Volume>,
}

impl WorkloadBuilder {
    pub fn app(mut self, app: App) -> Self {
        self.apps.push(app);
        self
    }

    pub fn volume(mut self, volume: Volume) -> Self {
        self.volumes.push(volume);
        self
    }

    pub fn build(self) -> Result<Workload, BuildError> {
        if self.apps.is_empty() {
            return Err(BuildError::EmptyWorkload);
        }
        Ok(Workload {
            schema_version: SCHEMA_VERSION.to_string(),
            id: self.id,
            apps: self.apps,
            volumes: self.volumes,
            extensions: BTreeMap::new(),
        })
    }
}
