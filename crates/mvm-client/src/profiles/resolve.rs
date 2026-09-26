//! Turning a profile reference into an ordered list of layers, then one
//! policy.
//!
//! A profile's parents (`extends`, in order, depth first) come before it, and
//! a diamond is applied once. The groups every profile in the chain selects
//! are gathered into one set — a child's `groups.exclude` can drop a group a
//! parent included, unless that group is `required` — and applied first, in
//! the order they were included. Then each profile's matching `[[when]]`
//! blocks and its `[overrides]` follow, parents first.
//!
//! A cycle is an error that names the loop; so is a chain deeper than
//! [`MAX_EXTENDS_DEPTH`].

use std::path::{Path, PathBuf};

use mvm_contract::protocol::vm_backend::BackendKind;

use super::merge::{Layer, ResolvedPolicy, merge_layers};
use super::model::{GroupFile, HostArch, HostOs, PolicyBody, ProfileFile, WhenBlock};
use super::source::{LayerOrigin, Loaded, PolicyError, PolicyRef, PolicyStore};

/// The deepest `extends` chain accepted.
pub const MAX_EXTENDS_DEPTH: usize = 10;

/// What `[[when]]` predicates are matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Platform {
    pub os: Option<HostOs>,
    pub arch: Option<HostArch>,
    /// The backend the run will boot on, when it is known.
    pub backend: Option<BackendKind>,
}

impl Platform {
    /// This host, booting on `backend`.
    #[must_use]
    pub fn current(backend: Option<BackendKind>) -> Self {
        Self {
            os: HostOs::current(),
            arch: HostArch::current(),
            backend,
        }
    }

    fn matches(&self, when: &WhenBlock) -> bool {
        fn any<T: PartialEq + Clone>(wanted: &super::model::OneOrMany<T>, have: Option<T>) -> bool {
            let wanted = wanted.to_vec();
            wanted.is_empty() || have.is_some_and(|have| wanted.contains(&have))
        }
        any(&when.os, self.os) && any(&when.arch, self.arch) && any(&when.backend, self.backend)
    }
}

/// Which policy a run uses, before anything is loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySelection {
    /// `--policy NAME|PATH`: the user named it.
    Profile(PolicyRef),
    /// The project's `mvm.toml` `[policy]` table.
    Project {
        /// The manifest file, for relative references and error messages.
        manifest: PathBuf,
        profile: Option<String>,
        include: Vec<String>,
    },
}

impl PolicySelection {
    /// Precedence: an explicit `--policy` wins; otherwise the project's
    /// `[policy]` table, if it says anything; otherwise none.
    ///
    /// # Errors
    ///
    /// A `--policy` value that is not a valid reference.
    pub fn choose(
        cli: Option<&str>,
        project: Option<(PathBuf, &mvm_core::manifest::ManifestPolicy)>,
    ) -> Result<Option<Self>, PolicyError> {
        if let Some(raw) = cli {
            let reference =
                PolicyRef::parse(raw).map_err(|reason| PolicyError::new("--policy", reason))?;
            return Ok(Some(PolicySelection::Profile(reference)));
        }
        Ok(project.and_then(|(manifest, section)| {
            (!section.is_empty()).then(|| PolicySelection::Project {
                manifest,
                profile: section.profile.clone(),
                include: section.include.clone(),
            })
        }))
    }
}

/// Resolve `selection` on `platform`.
///
/// # Errors
///
/// Anything [`merge_layers`] refuses, plus unknown or malformed references,
/// cycles, a chain deeper than [`MAX_EXTENDS_DEPTH`], and a required group a
/// profile tries to exclude.
pub fn resolve(
    store: &PolicyStore,
    selection: &PolicySelection,
    platform: Platform,
) -> Result<ResolvedPolicy, PolicyError> {
    let mut walker = Walker {
        store,
        platform,
        stack: Vec::new(),
        visited: Vec::new(),
        groups: Vec::new(),
        overrides: Vec::new(),
    };
    match selection {
        PolicySelection::Profile(reference) => {
            let root = store.load_profile(reference, None, LayerOrigin::User, "--policy")?;
            walker.walk(root, 0)?;
        }
        PolicySelection::Project {
            manifest,
            profile,
            include,
        } => {
            let label = format!("[policy] in {}", manifest.display());
            let virtual_root = ProfileFile {
                extends: super::model::OneOrMany::Many(profile.iter().cloned().collect()),
                groups: super::model::GroupSelection {
                    include: include.clone(),
                    exclude: Vec::new(),
                },
                ..ProfileFile::default()
            };
            walker.walk(
                Loaded {
                    doc: virtual_root,
                    file: Some(manifest.clone()),
                    label,
                    identity: format!("project:{}", manifest.display()),
                    origin: LayerOrigin::Project,
                },
                0,
            )?;
        }
    }
    let mut layers: Vec<Layer> = walker.groups.into_iter().map(|g| g.layer).collect();
    layers.extend(walker.overrides);
    merge_layers(&layers)
}

/// Resolve a single file that is a profile or, failing that, a group, as a
/// user-authored layer. What `mvmctl policy validate PATH` checks.
///
/// # Errors
///
/// The profile's resolution error, or — when the file is not a profile — the
/// group's.
pub fn resolve_file(
    store: &PolicyStore,
    path: &Path,
    platform: Platform,
) -> Result<ResolvedPolicy, PolicyError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        PolicyError::new(path.display().to_string(), format!("reading: {error}"))
    })?;
    if toml::from_str::<ProfileFile>(&text).is_ok() {
        return resolve(
            store,
            &PolicySelection::Profile(PolicyRef::Path(path.to_path_buf())),
            platform,
        );
    }
    let group = store.load_group(
        &PolicyRef::Path(path.to_path_buf()),
        None,
        LayerOrigin::User,
        "file",
    )?;
    let layers = vec![group_layer(&group)];
    merge_layers(&layers)
}

struct SelectedGroup {
    identity: String,
    required: bool,
    label: String,
    layer: Layer,
}

struct Walker<'a> {
    store: &'a PolicyStore,
    platform: Platform,
    stack: Vec<(String, String)>,
    visited: Vec<String>,
    groups: Vec<SelectedGroup>,
    overrides: Vec<Layer>,
}

fn group_layer(group: &Loaded<GroupFile>) -> Layer {
    Layer {
        label: group.label.clone(),
        file: group.file.clone(),
        origin: group.origin,
        body: group.doc.body(),
    }
}

fn base_dir(file: Option<&Path>) -> Option<&Path> {
    file.and_then(Path::parent)
}

impl Walker<'_> {
    fn walk(&mut self, profile: Loaded<ProfileFile>, depth: usize) -> Result<(), PolicyError> {
        if let Some(position) = self
            .stack
            .iter()
            .position(|(id, _)| *id == profile.identity)
        {
            let mut chain: Vec<&str> = self.stack[position..]
                .iter()
                .map(|(_, label)| label.as_str())
                .collect();
            chain.push(&profile.label);
            return Err(PolicyError::new(
                &profile.label,
                format!("extends forms a cycle: {}", chain.join(" -> ")),
            )
            .in_file(profile.file.as_deref())
            .at_key("extends"));
        }
        if depth > MAX_EXTENDS_DEPTH {
            return Err(PolicyError::new(
                &profile.label,
                format!("extends is nested deeper than {MAX_EXTENDS_DEPTH} levels"),
            )
            .in_file(profile.file.as_deref())
            .at_key("extends"));
        }
        if self.visited.contains(&profile.identity) {
            return Ok(());
        }
        self.stack
            .push((profile.identity.clone(), profile.label.clone()));
        let base = base_dir(profile.file.as_deref()).map(Path::to_path_buf);
        for parent in profile.doc.extends.to_vec() {
            let reference = PolicyRef::parse(&parent).map_err(|reason| {
                PolicyError::new(&profile.label, reason)
                    .in_file(profile.file.as_deref())
                    .at_key("extends")
            })?;
            let loaded = self
                .store
                .load_profile(&reference, base.as_deref(), profile.origin, &profile.label)
                .map_err(|error| with_file(error, &profile, "extends"))?;
            self.walk(loaded, depth + 1)?;
        }
        self.stack.pop();
        self.visited.push(profile.identity.clone());

        self.select(
            &profile,
            &profile.doc.groups.include,
            &profile.doc.groups.exclude,
            "groups",
        )?;
        let mut conditional = Vec::new();
        for (index, when) in profile.doc.when.iter().enumerate() {
            if !self.platform.matches(when) {
                continue;
            }
            self.select(
                &profile,
                &when.include,
                &when.exclude,
                &format!("when[{index}]"),
            )?;
            if !when.overrides.is_empty() {
                conditional.push(Layer {
                    label: format!("{} when[{index}]", profile.label),
                    file: profile.file.clone(),
                    origin: profile.origin,
                    body: when.overrides.clone(),
                });
            }
        }
        if !profile.doc.overrides.is_empty() {
            self.overrides.push(Layer {
                label: format!("{} overrides", profile.label),
                file: profile.file.clone(),
                origin: profile.origin,
                body: profile.doc.overrides.clone(),
            });
        }
        self.overrides.extend(conditional);
        Ok(())
    }

    fn select(
        &mut self,
        profile: &Loaded<ProfileFile>,
        include: &[String],
        exclude: &[String],
        key: &str,
    ) -> Result<(), PolicyError> {
        let base = base_dir(profile.file.as_deref()).map(Path::to_path_buf);
        for raw in include {
            let group =
                self.load_group(profile, raw, base.as_deref(), &format!("{key}.include"))?;
            if self.groups.iter().any(|g| g.identity == group.identity) {
                continue;
            }
            self.groups.push(SelectedGroup {
                identity: group.identity.clone(),
                required: group.doc.required,
                label: group.label.clone(),
                layer: group_layer(&group),
            });
        }
        for raw in exclude {
            let group =
                self.load_group(profile, raw, base.as_deref(), &format!("{key}.exclude"))?;
            let Some(position) = self
                .groups
                .iter()
                .position(|g| g.identity == group.identity)
            else {
                continue;
            };
            if self.groups[position].required {
                return Err(PolicyError::new(
                    &profile.label,
                    format!(
                        "{} is required and cannot be excluded",
                        self.groups[position].label
                    ),
                )
                .in_file(profile.file.as_deref())
                .at_key(format!("{key}.exclude")));
            }
            self.groups.remove(position);
        }
        Ok(())
    }

    fn load_group(
        &self,
        profile: &Loaded<ProfileFile>,
        raw: &str,
        base: Option<&Path>,
        key: &str,
    ) -> Result<Loaded<GroupFile>, PolicyError> {
        let reference = PolicyRef::parse(raw).map_err(|reason| {
            PolicyError::new(&profile.label, reason)
                .in_file(profile.file.as_deref())
                .at_key(key)
        })?;
        self.store
            .load_group(&reference, base, profile.origin, &profile.label)
            .map_err(|error| with_file(error, profile, key))
    }
}

/// Attach the referring file and key to an error raised while loading what
/// it references, unless the error already names a file of its own.
fn with_file(error: PolicyError, profile: &Loaded<ProfileFile>, key: &str) -> PolicyError {
    if error.file.is_some() {
        return error;
    }
    error.in_file(profile.file.as_deref()).at_key(key)
}

/// Resolve nothing: the policy of a run that selects none.
#[must_use]
pub fn empty() -> ResolvedPolicy {
    ResolvedPolicy::empty()
}

/// A single body as one user-authored layer, validated through the same
/// merge a profile goes through. Used for a resolved manifest read back from
/// disk: whatever edited it, it is checked again.
///
/// # Errors
///
/// Whatever [`merge_layers`] refuses.
pub fn revalidate(
    label: &str,
    file: Option<&Path>,
    body: PolicyBody,
) -> Result<ResolvedPolicy, PolicyError> {
    merge_layers(&[Layer {
        label: label.to_string(),
        file: file.map(Path::to_path_buf),
        origin: LayerOrigin::User,
        body,
    }])
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod tests;
