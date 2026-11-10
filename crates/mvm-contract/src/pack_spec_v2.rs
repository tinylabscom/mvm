//! Closed, neutral authoring for a composable application and its runtime requests.
//!
//! Version 1 retains its existing Nix semantics. This contract describes what
//! runs, not resolved bytes, grants, a build result or signing authority.

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::pack_spec::{
    CopyOperation, PackIdentity, PackResources, PackSource, PackTarget, relative_path,
};

/// The separate composition contract; v1 is never silently interpreted as v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposablePackSchema {
    #[serde(rename = "mvm.pack-spec/v2")]
    V2,
}

/// An explicit opt-in to a production build. Empty by design: locks and
/// publisher grants are resolved outside authored configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Production {}

/// Development is the default; production is selected explicitly by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    Development,
    Production,
}

/// One application, one entrypoint, and reusable runtime references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ComposablePackWire", deny_unknown_fields)]
pub struct ComposablePackSpec {
    pub schema: ComposablePackSchema,
    pub identity: PackIdentity,
    pub target: PackTarget,
    pub source: PackSource,
    /// Ordered `runtime/name[@version]` requests, not executable images.
    pub runtimes: Vec<String>,
    /// Source-relative inputs staged only below `/srv/app`.
    pub copy: Vec<CopyOperation>,
    /// Literal argv owned by this application, never by a runtime layer.
    pub entrypoint: Vec<String>,
    pub resources: PackResources,
    /// A caller cannot select production unless this table is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production: Option<Production>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposablePackWire {
    schema: ComposablePackSchema,
    identity: PackIdentity,
    target: PackTarget,
    source: PackSource,
    runtimes: Vec<String>,
    copy: Vec<CopyOperation>,
    entrypoint: Vec<String>,
    resources: PackResources,
    #[serde(default)]
    production: Option<Production>,
}

impl TryFrom<ComposablePackWire> for ComposablePackSpec {
    type Error = ComposablePackError;

    fn try_from(wire: ComposablePackWire) -> Result<Self, Self::Error> {
        let spec = Self {
            schema: wire.schema,
            identity: wire.identity,
            target: wire.target,
            source: wire.source,
            runtimes: wire.runtimes,
            copy: wire.copy,
            entrypoint: wire.entrypoint,
            resources: wire.resources,
            production: wire.production,
        };
        spec.validate()?;
        Ok(spec)
    }
}

/// Refusals do not echo source contents or author-supplied paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComposablePackError {
    #[error("invalid pack identity")]
    Identity,
    #[error("unsafe local source or application copy path")]
    Path,
    #[error("invalid, duplicate or excessive runtime reference")]
    Runtime,
    #[error("application entrypoint must start with one absolute executable")]
    Entrypoint,
    #[error("CPU and memory requests must be positive")]
    Resources,
    #[error("production requires an explicit [production] table")]
    ProductionNotSelected,
    #[error("could not serialize composable pack")]
    Serialization,
}

impl ComposablePackSpec {
    /// Validate a directly constructed value as strictly as a deserialized one.
    ///
    /// # Errors
    ///
    /// Refuses unknown authority, ambiguous runtime names and unsafe paths.
    pub fn validate(&self) -> Result<(), ComposablePackError> {
        self.identity
            .validate()
            .map_err(|_| ComposablePackError::Identity)?;
        if self.identity.version.contains('+') {
            return Err(ComposablePackError::Identity);
        }
        let PackSource::Local { path } = &self.source;
        relative_path(path, true).map_err(|_| ComposablePackError::Path)?;
        if self.runtimes.len() > 16 {
            return Err(ComposablePackError::Runtime);
        }
        let mut names = BTreeSet::new();
        for runtime in &self.runtimes {
            let (coordinate, version) = runtime
                .split_once('@')
                .map_or((runtime.as_str(), None), |(name, version)| {
                    (name, Some(version))
                });
            let identity = PackIdentity {
                name: coordinate.into(),
                version: version.unwrap_or("0.0.0").into(),
            };
            if !coordinate.starts_with("runtime/")
                || version.is_some_and(|version| version.contains('+'))
                || identity.validate().is_err()
                || !names.insert(coordinate)
            {
                return Err(ComposablePackError::Runtime);
            }
        }
        if self.copy.len() > 1024 {
            return Err(ComposablePackError::Path);
        }
        for copy in &self.copy {
            relative_path(&copy.source, true).map_err(|_| ComposablePackError::Path)?;
            let Some(destination) = copy.destination.strip_prefix("/srv/app/") else {
                return Err(ComposablePackError::Path);
            };
            relative_path(destination, false).map_err(|_| ComposablePackError::Path)?;
        }
        if self.entrypoint.len() > 128
            || self.entrypoint.iter().map(String::len).sum::<usize>() > 16 * 1024
            || self.entrypoint.first().is_none_or(|executable| {
                !executable.starts_with('/')
                    || executable.starts_with("//")
                    || relative_path(executable.trim_start_matches('/'), false).is_err()
            })
            || self
                .entrypoint
                .iter()
                .any(|argument| argument.is_empty() || argument.chars().any(char::is_control))
        {
            return Err(ComposablePackError::Entrypoint);
        }
        if self.resources.cpu_cores == 0 || self.resources.memory_mb == 0 {
            return Err(ComposablePackError::Resources);
        }
        Ok(())
    }

    /// Check authored mode intent; this does not resolve or authorize a build.
    ///
    /// # Errors
    ///
    /// Production requires explicit authored intent and a separate frozen lock.
    pub fn check_mode_request(&self, mode: BuildMode) -> Result<(), ComposablePackError> {
        self.validate()?;
        if mode == BuildMode::Production && self.production.is_none() {
            return Err(ComposablePackError::ProductionNotSelected);
        }
        Ok(())
    }

    /// Deterministic authored representation; not a lock or signature.
    ///
    /// # Errors
    ///
    /// Refuses an invalid directly constructed spec or serialization failure.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ComposablePackError> {
        self.validate()?;
        let mut value =
            serde_json::to_value(self).map_err(|_| ComposablePackError::Serialization)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).map_err(|_| ComposablePackError::Serialization)
    }
}
