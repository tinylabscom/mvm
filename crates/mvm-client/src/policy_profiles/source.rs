//! Where policy documents come from: references, origins, and loading.
//!
//! A reference names a profile or group one of three ways:
//!
//! - a **path** — starts with `/`, `./` or `../`, or ends in `.toml`; a
//!   relative path resolves against the file that names it;
//! - a **name** — looked up in the user's policy directory
//!   (`mvm_core::config::policy_profiles_dir` / `policy_groups_dir`) and then
//!   among the built-ins;
//! - a **pack** — `namespace/name[@version]`, reserved for signed packs and
//!   refused until they exist.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::builtin;
use super::model::{GroupFile, ProfileFile};

/// Who authored a layer. Escape hatches are honoured only in [`User`]
/// layers.
///
/// [`User`]: LayerOrigin::User
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerOrigin {
    /// Shipped inside `mvmctl`.
    Builtin,
    /// The user's policy directory, or a file the user named on the command
    /// line.
    User,
    /// Reached from a project's `mvm.toml` `[policy]` table: repository
    /// content, not the operator's own authoring.
    Project,
    /// A signed pack profile. Reserved: pack references are refused today.
    Pack,
}

impl LayerOrigin {
    /// Display spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LayerOrigin::Builtin => "built-in",
            LayerOrigin::User => "user",
            LayerOrigin::Project => "project",
            LayerOrigin::Pack => "pack",
        }
    }
}

/// A policy error that names the file, the layer, and the offending key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.render())]
pub struct PolicyError {
    /// The file the layer came from, when it came from one.
    pub file: Option<PathBuf>,
    /// The layer, e.g. ``profile `agent` `` or ``group `registries` (built-in)``.
    pub layer: String,
    /// The offending key, e.g. `network.allow`.
    pub key: Option<String>,
    /// What is wrong.
    pub message: String,
}

impl PolicyError {
    pub(crate) fn new(layer: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            file: None,
            layer: layer.into(),
            key: None,
            message: message.into(),
        }
    }

    #[must_use]
    pub(crate) fn in_file(mut self, file: Option<&Path>) -> Self {
        self.file = file.map(Path::to_path_buf);
        self
    }

    #[must_use]
    pub(crate) fn at_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    fn render(&self) -> String {
        let mut out = String::new();
        if let Some(file) = &self.file {
            out.push_str(&format!("{}: ", file.display()));
        }
        out.push_str(&self.layer);
        if let Some(key) = &self.key {
            out.push_str(&format!(": `{key}`"));
        }
        out.push_str(": ");
        out.push_str(&self.message);
        out
    }
}

/// A parsed profile or group reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRef {
    /// A name, looked up in the user directory then the built-ins.
    Name(String),
    /// A file.
    Path(PathBuf),
    /// `namespace/name[@version]`.
    Pack {
        namespace: String,
        name: String,
        version: Option<String>,
    },
}

/// Longest accepted profile or group name.
const MAX_NAME_LEN: usize = 64;

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

impl PolicyRef {
    /// Parse a reference as written on the command line or in a file.
    ///
    /// # Errors
    ///
    /// An empty reference, or a name with characters a name cannot hold.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("a policy reference is empty".to_string());
        }
        let looks_like_path = raw.starts_with('/')
            || raw.starts_with("./")
            || raw.starts_with("../")
            || raw.ends_with(".toml");
        if looks_like_path {
            return Ok(PolicyRef::Path(PathBuf::from(raw)));
        }
        if let Some((namespace, rest)) = raw.split_once('/') {
            let (name, version) = match rest.split_once('@') {
                Some((name, version)) => (name, Some(version.to_string())),
                None => (rest, None),
            };
            if !is_valid_name(namespace) || !is_valid_name(name) {
                return Err(format!(
                    "{raw:?} is neither a name, a path (start it with ./ or end it in .toml), \
                     nor a pack reference (namespace/name[@version])"
                ));
            }
            return Ok(PolicyRef::Pack {
                namespace: namespace.to_string(),
                name: name.to_string(),
                version,
            });
        }
        if !is_valid_name(raw) {
            return Err(format!(
                "{raw:?} is not a valid name: use lowercase letters, digits, `-` and `_`, \
                 or give a path (start it with ./ or end it in .toml)"
            ));
        }
        Ok(PolicyRef::Name(raw.to_string()))
    }
}

/// A document together with where it came from.
#[derive(Debug, Clone)]
pub struct Loaded<T> {
    pub doc: T,
    /// The file, for a user- or project-authored document.
    pub file: Option<PathBuf>,
    /// Human label, e.g. ``profile `agent-apis` (built-in)``.
    pub label: String,
    /// A stable identity for cycle detection and de-duplication.
    pub identity: String,
    pub origin: LayerOrigin,
}

/// The directories names resolve in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStore {
    profiles_dir: PathBuf,
    groups_dir: PathBuf,
}

impl PolicyStore {
    /// The user's configured policy directory.
    #[must_use]
    pub fn from_config() -> Self {
        Self {
            profiles_dir: mvm_core::config::policy_profiles_dir(),
            groups_dir: mvm_core::config::policy_groups_dir(),
        }
    }

    /// A store rooted at `dir` (with `profiles/` and `groups/` beneath it).
    #[must_use]
    pub fn at(dir: impl AsRef<Path>) -> Self {
        Self {
            profiles_dir: dir.as_ref().join("profiles"),
            groups_dir: dir.as_ref().join("groups"),
        }
    }

    /// The directory user profiles live in.
    #[must_use]
    pub fn profiles_dir(&self) -> &Path {
        &self.profiles_dir
    }

    /// The directory user groups live in.
    #[must_use]
    pub fn groups_dir(&self) -> &Path {
        &self.groups_dir
    }

    /// Load the profile `reference` names.
    ///
    /// `base` is the directory a relative path resolves against, and
    /// `path_origin` the origin a file reached by path gets (a file named on
    /// the command line is the user's; one reached from a project is the
    /// project's). A named profile gets the origin of where it was found.
    ///
    /// # Errors
    ///
    /// A pack reference, an unknown name, or a file that does not parse.
    pub fn load_profile(
        &self,
        reference: &PolicyRef,
        base: Option<&Path>,
        path_origin: LayerOrigin,
        referrer: &str,
    ) -> Result<Loaded<ProfileFile>, PolicyError> {
        self.load(
            Kind::Profile,
            reference,
            base,
            path_origin,
            referrer,
            builtin::profile,
        )
    }

    /// Load the group `reference` names. See [`load_profile`](Self::load_profile).
    ///
    /// # Errors
    ///
    /// A pack reference, an unknown name, or a file that does not parse.
    pub fn load_group(
        &self,
        reference: &PolicyRef,
        base: Option<&Path>,
        path_origin: LayerOrigin,
        referrer: &str,
    ) -> Result<Loaded<GroupFile>, PolicyError> {
        self.load(
            Kind::Group,
            reference,
            base,
            path_origin,
            referrer,
            builtin::group,
        )
    }

    fn load<T: serde::de::DeserializeOwned>(
        &self,
        kind: Kind,
        reference: &PolicyRef,
        base: Option<&Path>,
        path_origin: LayerOrigin,
        referrer: &str,
        builtin: fn(&str) -> Option<&'static str>,
    ) -> Result<Loaded<T>, PolicyError> {
        match reference {
            PolicyRef::Pack {
                namespace, name, ..
            } => Err(PolicyError::new(
                referrer,
                format!(
                    "{} `{namespace}/{name}` is a pack reference; packs are not yet supported",
                    kind.noun()
                ),
            )),
            PolicyRef::Path(path) => {
                let path = match base {
                    Some(base) if path.is_relative() => base.join(path),
                    _ => path.clone(),
                };
                let identity = std::fs::canonicalize(&path)
                    .unwrap_or_else(|_| path.clone())
                    .display()
                    .to_string();
                let doc = read_toml(&path, kind, referrer)?;
                Ok(Loaded {
                    doc,
                    label: format!("{} {}", kind.noun(), path.display()),
                    file: Some(path),
                    identity,
                    origin: path_origin,
                })
            }
            PolicyRef::Name(name) => {
                let user_file = kind.dir(self).join(format!("{name}.toml"));
                if user_file.is_file() {
                    let doc = read_toml(&user_file, kind, referrer)?;
                    return Ok(Loaded {
                        doc,
                        label: format!("{} `{name}`", kind.noun()),
                        file: Some(user_file),
                        identity: format!("user:{}:{name}", kind.noun()),
                        origin: LayerOrigin::User,
                    });
                }
                let text = builtin(name).ok_or_else(|| {
                    PolicyError::new(
                        referrer,
                        format!(
                            "no {} named `{name}`: not in {} and not built in",
                            kind.noun(),
                            kind.dir(self).display()
                        ),
                    )
                })?;
                let label = format!("{} `{name}` (built-in)", kind.noun());
                let doc = toml::from_str(text).map_err(|error| {
                    PolicyError::new(&label, format!("built-in document does not parse: {error}"))
                })?;
                Ok(Loaded {
                    doc,
                    label,
                    file: None,
                    identity: format!("builtin:{}:{name}", kind.noun()),
                    origin: LayerOrigin::Builtin,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Profile,
    Group,
}

impl Kind {
    fn noun(self) -> &'static str {
        match self {
            Kind::Profile => "profile",
            Kind::Group => "group",
        }
    }

    fn dir(self, store: &PolicyStore) -> &Path {
        match self {
            Kind::Profile => &store.profiles_dir,
            Kind::Group => &store.groups_dir,
        }
    }
}

fn read_toml<T: serde::de::DeserializeOwned>(
    path: &Path,
    kind: Kind,
    referrer: &str,
) -> Result<T, PolicyError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        PolicyError::new(
            referrer,
            format!("reading {} {}: {error}", kind.noun(), path.display()),
        )
    })?;
    toml::from_str(&text).map_err(|error| {
        PolicyError::new(
            format!("{} {}", kind.noun(), path.display()),
            error.message(),
        )
        .in_file(Some(path))
        .at_key(error_key(&error))
    })
}

/// The key a TOML error points at, best effort: the parser reports a span,
/// and the offending key is the identifier that span covers.
fn error_key(error: &toml::de::Error) -> String {
    let message = error.message();
    for marker in ["unknown field `", "missing field `", "unknown variant `"] {
        if let Some(rest) = message.split(marker).nth(1)
            && let Some(key) = rest.split('`').next()
        {
            return key.to_string();
        }
    }
    "(document)".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_parse_into_names_paths_and_packs() {
        assert_eq!(
            PolicyRef::parse("dev-network"),
            Ok(PolicyRef::Name("dev-network".into()))
        );
        assert_eq!(
            PolicyRef::parse("./agent.toml"),
            Ok(PolicyRef::Path("./agent.toml".into()))
        );
        assert_eq!(
            PolicyRef::parse("policies/agent.toml"),
            Ok(PolicyRef::Path("policies/agent.toml".into()))
        );
        assert_eq!(
            PolicyRef::parse("/etc/p.toml"),
            Ok(PolicyRef::Path("/etc/p.toml".into()))
        );
        assert_eq!(
            PolicyRef::parse("acme/agent@1.2"),
            Ok(PolicyRef::Pack {
                namespace: "acme".into(),
                name: "agent".into(),
                version: Some("1.2".into())
            })
        );
        assert!(PolicyRef::parse("").is_err());
        assert!(PolicyRef::parse("Has Spaces").is_err());
        assert!(PolicyRef::parse("a/b/c").is_err());
    }

    #[test]
    fn a_pack_reference_is_refused_as_not_yet_supported() {
        let store = PolicyStore::at(tempfile::tempdir().unwrap().path());
        let err = store
            .load_profile(
                &PolicyRef::parse("acme/agent").unwrap(),
                None,
                LayerOrigin::User,
                "--policy",
            )
            .unwrap_err();
        assert!(err.message.contains("packs are not yet supported"), "{err}");
    }

    #[test]
    fn a_user_profile_shadows_a_built_in_of_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::at(dir.path());
        std::fs::create_dir_all(store.profiles_dir()).unwrap();
        std::fs::write(
            store.profiles_dir().join("default.toml"),
            "description = \"mine\"\n",
        )
        .unwrap();
        let loaded = store
            .load_profile(
                &PolicyRef::Name("default".into()),
                None,
                LayerOrigin::User,
                "--policy",
            )
            .unwrap();
        assert_eq!(loaded.origin, LayerOrigin::User);
        assert_eq!(loaded.doc.description.as_deref(), Some("mine"));

        let builtin = PolicyStore::at(tempfile::tempdir().unwrap().path())
            .load_profile(
                &PolicyRef::Name("default".into()),
                None,
                LayerOrigin::User,
                "--policy",
            )
            .unwrap();
        assert_eq!(builtin.origin, LayerOrigin::Builtin);
    }

    #[test]
    fn an_unknown_name_and_a_malformed_file_name_what_went_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let store = PolicyStore::at(dir.path());
        let err = store
            .load_group(
                &PolicyRef::Name("nope".into()),
                None,
                LayerOrigin::User,
                "profile `x`",
            )
            .unwrap_err();
        assert!(err.to_string().contains("no group named `nope`"), "{err}");

        let file = dir.path().join("bad.toml");
        std::fs::write(&file, "[network]\nallowed = [\"x\"]\n").unwrap();
        let err = store
            .load_group(
                &PolicyRef::Path(file.clone()),
                None,
                LayerOrigin::User,
                "--policy",
            )
            .unwrap_err();
        assert_eq!(err.file.as_deref(), Some(file.as_path()));
        assert_eq!(err.key.as_deref(), Some("allowed"));
        let rendered = err.to_string();
        assert!(
            rendered.contains("bad.toml") && rendered.contains("`allowed`"),
            "{rendered}"
        );
    }

    #[test]
    fn a_relative_path_resolves_against_the_referring_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.toml"), "description = \"base\"\n").unwrap();
        let loaded = PolicyStore::at(dir.path())
            .load_profile(
                &PolicyRef::parse("./base.toml").unwrap(),
                Some(dir.path()),
                LayerOrigin::Project,
                "profile x",
            )
            .unwrap();
        assert_eq!(loaded.origin, LayerOrigin::Project);
        assert_eq!(loaded.doc.description.as_deref(), Some("base"));
    }
}
