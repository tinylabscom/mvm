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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::merge::{Layer, ResolvedPolicy, merge_layers};
use super::model::{GroupFile, HostArch, HostOs, PolicyBody, ProfileFile, WhenBlock};
use super::source::{DocFormat, LayerOrigin, Loaded, PolicyError, PolicyRef, PolicyStore};

/// The deepest `extends` chain accepted.
pub const MAX_EXTENDS_DEPTH: usize = 10;

/// One dependency captured from the same bytes the resolver parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPolicyDocument {
    /// Resolver identity for de-duplication and cycle checks.
    pub identity: String,
    /// Absolute source path, retained only as provenance.
    pub file: PathBuf,
    /// Trust origin at the time of resolution.
    pub origin: LayerOrigin,
    /// Shape used to parse the captured text.
    pub kind: PolicyDocumentKind,
    /// SHA-256 digest of the exact UTF-8 bytes parsed.
    pub sha256: String,
    /// Exact parsed source; do not reread `file` to re-admit this snapshot.
    pub text: String,
}

/// The document shape used when interpreting captured source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDocumentKind {
    /// A profile or an inherited parent.
    Profile,
    /// A selected or excluded group.
    Group,
}

/// An inline profile and the exact transitive documents used to resolve it.
///
/// This is a capture for future persistent admission, not an admitted or
/// signed policy. The host must still apply current ceilings at each start.
#[derive(Debug, Clone)]
pub struct FrozenPolicyResolution {
    /// Original inline profile, including conditional and composition rules.
    pub authored: ProfileFile,
    /// Resolved policy for this platform at capture time, not an admission.
    pub resolved: ResolvedPolicy,
    /// Every referenced document the resolver read, including excluded groups.
    pub dependencies: Vec<FrozenPolicyDocument>,
}

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
            os: match std::env::consts::OS {
                "linux" => Some(HostOs::Linux),
                "macos" => Some(HostOs::Macos),
                _ => None,
            },
            arch: match std::env::consts::ARCH {
                "x86_64" => Some(HostArch::X86_64),
                "aarch64" => Some(HostArch::Aarch64),
                _ => None,
            },
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

/// A project's contribution to a launch's policy, read from its `mvm.toml`:
/// the `[policy]` table (a profile and extra groups) and the
/// `[network] allow_hosts` list. Applied the same way by every verb that
/// names the project — `run`, `machine run` and `machine create` — so "add it
/// to mvm.toml" means the same thing whichever one runs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectPolicy {
    /// The manifest file, for relative references and error messages.
    pub manifest: PathBuf,
    /// `[policy] profile`.
    pub profile: Option<String>,
    /// `[policy] include`.
    pub include: Vec<String>,
    /// `[network] allow_hosts`.
    pub allow_hosts: Vec<String>,
}

impl ProjectPolicy {
    /// What `manifest` (read from `path`) contributes.
    #[must_use]
    pub fn from_manifest(path: &Path, manifest: &mvm_core::manifest::Manifest) -> Self {
        Self {
            manifest: path.to_path_buf(),
            profile: manifest.policy.profile.clone(),
            include: manifest.policy.include.clone(),
            allow_hosts: manifest.network.allow_hosts.clone(),
        }
    }

    /// Whether the project contributes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profile.is_none() && self.include.is_empty() && self.allow_hosts.is_empty()
    }
}

/// Which policy a launch uses, before anything is loaded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySelection {
    /// `--policy NAME|PATH`, lowest precedence first: each entry composes over
    /// the ones before it, so the last one wins the conflicts the merge rules
    /// adjudicate (its denies and bounds beat an earlier entry's allows).
    /// When non-empty, the entries replace the project's `[policy]` table;
    /// the project's `[network] allow_hosts` still applies.
    pub profiles: Vec<PolicyRef>,
    /// The project the launch names, if any.
    pub project: Option<ProjectPolicy>,
}

impl PolicySelection {
    /// One named profile and nothing else.
    #[must_use]
    pub fn profile(reference: PolicyRef) -> Self {
        Self {
            profiles: vec![reference],
            project: None,
        }
    }

    /// The selection for a launch: `--policy` (one or many, in order) if
    /// given, the project's contribution if it has one, or `None` when
    /// neither says anything.
    ///
    /// # Errors
    ///
    /// A `--policy` value that is not a valid reference.
    pub fn for_launch(
        cli: &[String],
        project: Option<ProjectPolicy>,
    ) -> Result<Option<Self>, PolicyError> {
        let profiles = cli
            .iter()
            .map(|raw| PolicyRef::parse(raw).map_err(|reason| PolicyError::new("--policy", reason)))
            .collect::<Result<Vec<_>, _>>()?;
        let project = project.filter(|p| !p.is_empty());
        if profiles.is_empty() && project.is_none() {
            return Ok(None);
        }
        Ok(Some(Self { profiles, project }))
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
    let mut walker = Walker::new(store, platform);
    for reference in &selection.profiles {
        match store.load_profile(reference, None, LayerOrigin::User, "--policy") {
            Ok(root) => walker.walk(root, 0)?,
            // A root reference may name a group rather than a profile —
            // runtime packs ship only pack/group.toml, and a group's name or
            // path composes as one group layer. When both shapes fail, the
            // profile error is the more specific report.
            Err(profile_error) => {
                match store.load_group(reference, None, LayerOrigin::User, "--policy") {
                    Ok(group) => {
                        if !walker.groups.iter().any(|g| g.identity == group.identity) {
                            walker.groups.push(SelectedGroup {
                                identity: group.identity.clone(),
                                required: group.doc.required,
                                label: group.label.clone(),
                                layer: group_layer(&group),
                            });
                        }
                    }
                    Err(_) => return Err(profile_error),
                }
            }
        }
    }
    if let Some(project) = &selection.project {
        // An explicit --policy replaces the project's [policy] table; the
        // project's own network needs still apply.
        let replaced = !selection.profiles.is_empty();
        let virtual_root = ProfileFile {
            extends: super::model::OneOrMany::Many(if replaced {
                Vec::new()
            } else {
                project.profile.iter().cloned().collect()
            }),
            groups: super::model::GroupSelection {
                include: if replaced {
                    Vec::new()
                } else {
                    project.include.clone()
                },
                exclude: Vec::new(),
            },
            overrides: PolicyBody {
                network: super::model::NetworkSection {
                    allow: project.allow_hosts.clone(),
                    ..super::model::NetworkSection::default()
                },
                ..PolicyBody::default()
            },
            ..ProfileFile::default()
        };
        walker.walk(
            Loaded {
                doc: virtual_root,
                file: Some(project.manifest.clone()),
                source_text: None,
                label: format!("project {}", project.manifest.display()),
                identity: format!("project:{}", project.manifest.display()),
                origin: LayerOrigin::Project,
            },
            0,
        )?;
    }
    walker.finish()
}

/// Resolve an in-memory user-authored profile through the host's composition rules.
///
/// Names and absolute paths use the usual [`PolicyStore`] trust checks. An inline
/// profile has no file directory, so its own relative references and share
/// sources are refused instead of resolving against the process's working
/// directory. File-backed parents and groups retain their own relative bases.
///
/// # Errors
///
/// Invalid references, relative root paths, and any merge refusal are errors.
pub fn resolve_authored(
    store: &PolicyStore,
    profile: ProfileFile,
    platform: Platform,
) -> Result<ResolvedPolicy, PolicyError> {
    Ok(resolve_authored_inner(store, profile, platform, false)?.resolved)
}

/// Resolve an inline profile and capture every loaded dependency from its
/// parsed bytes. No later filesystem read is used to construct the capture.
///
/// # Errors
///
/// Invalid references, relative source paths, conflicting repeated reads,
/// and any merge refusal are errors.
pub fn resolve_authored_snapshot(
    store: &PolicyStore,
    profile: ProfileFile,
    platform: Platform,
) -> Result<FrozenPolicyResolution, PolicyError> {
    resolve_authored_inner(store, profile, platform, true)
}

fn resolve_authored_inner(
    store: &PolicyStore,
    profile: ProfileFile,
    platform: Platform,
    capture: bool,
) -> Result<FrozenPolicyResolution, PolicyError> {
    fn check_reference(raw: &str, key: &str) -> Result<(), PolicyError> {
        if matches!(PolicyRef::parse(raw), Ok(PolicyRef::Path(path)) if path.is_relative()) {
            return Err(PolicyError::new(
                "inline policy",
                "a relative policy path needs a source file; use a name or absolute path",
            )
            .at_key(key));
        }
        Ok(())
    }
    for parent in profile.extends.to_vec() {
        check_reference(&parent, "extends")?;
    }
    for raw in &profile.groups.include {
        check_reference(raw, "groups.include")?;
    }
    for raw in &profile.groups.exclude {
        check_reference(raw, "groups.exclude")?;
    }
    for (index, when) in profile.when.iter().enumerate() {
        for raw in &when.include {
            check_reference(raw, &format!("when[{index}].include"))?;
        }
        for raw in &when.exclude {
            check_reference(raw, &format!("when[{index}].exclude"))?;
        }
    }
    let mut walker = Walker::new(store, platform);
    walker.capture_dependencies = capture;
    let authored = profile.clone();
    walker.walk(
        Loaded {
            doc: profile,
            file: None,
            source_text: None,
            label: "inline policy".into(),
            identity: "sdk:inline".into(),
            origin: LayerOrigin::User,
        },
        0,
    )?;
    let dependencies = std::mem::take(&mut walker.dependencies);
    Ok(FrozenPolicyResolution {
        authored,
        resolved: walker.finish()?,
        dependencies,
    })
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
    if DocFormat::for_path(path)
        .parse::<ProfileFile>(&text)
        .is_ok()
    {
        return resolve(
            store,
            &PolicySelection::profile(PolicyRef::Path(path.to_path_buf())),
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
    dependencies: Vec<FrozenPolicyDocument>,
    capture_dependencies: bool,
    groups: Vec<SelectedGroup>,
    overrides: Vec<Layer>,
    backend_conditioned: bool,
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
    fn new(store: &PolicyStore, platform: Platform) -> Walker<'_> {
        Walker {
            store,
            platform,
            stack: Vec::new(),
            visited: Vec::new(),
            dependencies: Vec::new(),
            capture_dependencies: false,
            groups: Vec::new(),
            overrides: Vec::new(),
            backend_conditioned: false,
        }
    }

    fn finish(self) -> Result<ResolvedPolicy, PolicyError> {
        let mut layers: Vec<Layer> = self.groups.into_iter().map(|g| g.layer).collect();
        layers.extend(self.overrides);
        let mut resolved = merge_layers(&layers)?;
        resolved.backend_conditioned = self.backend_conditioned;
        Ok(resolved)
    }

    fn capture<T>(
        &mut self,
        loaded: &Loaded<T>,
        kind: PolicyDocumentKind,
    ) -> Result<(), PolicyError> {
        if !self.capture_dependencies {
            return Ok(());
        }
        let (Some(file), Some(text)) = (&loaded.file, &loaded.source_text) else {
            return Ok(());
        };
        if !file.is_absolute() {
            return Err(PolicyError::new(
                &loaded.label,
                "capturing a policy dependency requires an absolute source path",
            )
            .in_file(Some(file)));
        }
        let sha256 = hex::encode(Sha256::digest(text.as_bytes()));
        if let Some(previous) = self
            .dependencies
            .iter()
            .find(|document| document.identity == loaded.identity && document.kind == kind)
        {
            if previous.sha256 != sha256 {
                return Err(PolicyError::new(
                    &loaded.label,
                    "policy dependency changed during resolution; retry with stable source files",
                )
                .in_file(Some(file)));
            }
            return Ok(());
        }
        self.dependencies.push(FrozenPolicyDocument {
            identity: loaded.identity.clone(),
            file: file.clone(),
            origin: loaded.origin,
            kind,
            sha256,
            text: text.clone(),
        });
        Ok(())
    }

    fn walk(&mut self, profile: Loaded<ProfileFile>, depth: usize) -> Result<(), PolicyError> {
        self.capture(&profile, PolicyDocumentKind::Profile)?;
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
            if !when.backend.is_empty() {
                self.backend_conditioned = true;
            }
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
        self.overrides.extend(conditional);
        if !profile.doc.overrides.is_empty() {
            self.overrides.push(Layer {
                label: format!("{} overrides", profile.label),
                file: profile.file.clone(),
                origin: profile.origin,
                body: profile.doc.overrides.clone(),
            });
        }
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
            self.capture(&group, PolicyDocumentKind::Group)?;
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
            self.capture(&group, PolicyDocumentKind::Group)?;
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
