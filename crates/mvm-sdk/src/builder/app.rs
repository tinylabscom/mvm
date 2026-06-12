use std::collections::BTreeMap;

use crate::ir::{
    App, Dependencies, Entrypoint, EnvValue, Image, Mount, Network, Resources, Source,
};

use crate::error::BuildError;

/// Start declaring an app within the workload.
pub fn app(name: impl Into<String>) -> AppBuilder {
    AppBuilder {
        name: name.into(),
        source: None,
        image: None,
        entrypoints: Vec::new(),
        env: BTreeMap::new(),
        mounts: Vec::new(),
        network: None,
        resources: None,
        dependencies: None,
    }
}

#[must_use = "AppBuilder is lazy — call .build() to produce an App"]
pub struct AppBuilder {
    name: String,
    source: Option<Source>,
    image: Option<Image>,
    entrypoints: Vec<Entrypoint>,
    env: BTreeMap<String, EnvValue>,
    mounts: Vec<Mount>,
    network: Option<Network>,
    resources: Option<Resources>,
    dependencies: Option<Dependencies>,
}

impl AppBuilder {
    pub fn source(mut self, source: Source) -> Self {
        self.source = Some(source);
        self
    }

    pub fn image(mut self, image: Image) -> Self {
        self.image = Some(image);
        self
    }

    /// Add an entrypoint. Single-entrypoint apps call this once; multi-
    /// function apps call it multiple times
    /// with `Entrypoint::Function` variants whose `primary` flags are
    /// validator-checked downstream.
    pub fn entrypoint(mut self, ep: Entrypoint) -> Self {
        self.entrypoints.push(ep);
        self
    }

    pub fn resources(mut self, r: Resources) -> Self {
        self.resources = Some(r);
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: EnvValue) -> Self {
        self.env.insert(key.into(), value);
        self
    }

    pub fn mount(mut self, m: Mount) -> Self {
        self.mounts.push(m);
        self
    }

    pub fn network(mut self, n: Network) -> Self {
        self.network = Some(n);
        self
    }

    pub fn dependencies(mut self, d: Dependencies) -> Self {
        self.dependencies = Some(d);
        self
    }

    pub fn build(self) -> Result<App, BuildError> {
        let source = self.source.ok_or(BuildError::MissingField {
            name: self.name.clone(),
            field: "source",
        })?;
        let image = self.image.ok_or(BuildError::MissingField {
            name: self.name.clone(),
            field: "image",
        })?;
        let resources = self.resources.ok_or(BuildError::MissingField {
            name: self.name.clone(),
            field: "resources",
        })?;
        if self.entrypoints.is_empty() {
            return Err(BuildError::MissingField {
                name: self.name,
                field: "entrypoint",
            });
        }
        Ok(App {
            name: self.name,
            source,
            image,
            entrypoints: self.entrypoints,
            env: self.env,
            mounts: self.mounts,
            network: self.network,
            resources,
            dependencies: self.dependencies,
            threat_tier: Default::default(),
            addons: vec![],
            // `hooks` is a four-phase struct
            // of `Vec<HookCmd>` that defaults to all-empty (and
            // serializes as `{}` thanks to per-field
            // `skip_serializing_if = "Vec::is_empty"`). Builders
            // that need to declare hooks use `App::with_hooks` (or
            // the addon-aware merge path) downstream.
            hooks: Default::default(),
            files: Vec::new(),
        })
    }
}
