//! The instruction-file trust policy.
//!
//! [`InstructionTrustPolicy`] is one TOML file exactly as written, with
//! `deny_unknown_fields` everywhere so a misspelt key is an error rather than
//! a silently absent restriction. [`EffectivePolicy`] is what verification
//! actually runs under: the user's policy (authoritative) merged with a
//! project's policy, which may only tighten it.
//!
//! The merge, in one place:
//!
//! | input | enforcement | includes | publishers | blocklist |
//! |---|---|---|---|---|
//! | no policy at all | `audit` | defaults | none | none |
//! | user only | user's, default `deny` | user's or defaults | user's | user's |
//! | user + project | the stricter of the two | union | user's, narrowed to those the project also lists | union |
//! | project only | project's, capped at `warn` | project's or defaults | project's | project's |
//!
//! A project policy with no user policy is *advisory*: a repository cannot be
//! allowed to declare which publishers vouch for its own files and then have
//! that declaration refuse or admit a boot on the operator's behalf.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use globset::{GlobBuilder, GlobMatcher, GlobSet, GlobSetBuilder};
use mvm_core::plan::bundle::{KeyId, TrustStore, key_id_from_pubkey};
use serde::{Deserialize, Serialize};

use super::identity::{WORKFLOW_DIR_PREFIX, parse_workflow_identity, workflow_identity};

/// Instruction files an agent reads, matched when a policy names none.
///
/// Relative to each scanned root; `**/` matches at any depth including the
/// root itself. Matching is case-insensitive, because a case-insensitive host
/// filesystem serves `claude.md` to an agent that asked for `CLAUDE.md`.
pub const DEFAULT_INCLUDES: &[&str] = &[
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/AGENTS.md",
    "**/AGENT.md",
    "**/GEMINI.md",
    "**/SKILL.md",
    "**/.claude/**/*.md",
    "**/.cursor/rules/**",
    "**/.cursorrules",
];

/// The OIDC issuer GitHub Actions mints keyless signing certificates under.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// What a failed verification does to the boot.
///
/// Ordered by strictness, so "the stricter of two" is `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Enforcement {
    /// Record each verdict in the audit chain and say nothing.
    Audit,
    /// Print each failure and boot anyway; still recorded.
    Warn,
    /// Refuse the boot if any instruction file fails verification.
    Deny,
}

impl Enforcement {
    /// The enforcement a policy gets when it names none.
    pub const DEFAULT: Enforcement = Enforcement::Deny;

    /// The TOML spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Enforcement::Audit => "audit",
            Enforcement::Warn => "warn",
            Enforcement::Deny => "deny",
        }
    }
}

/// One instruction trust policy file, as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct InstructionTrustPolicy {
    /// `deny` (the default when a policy exists), `warn`, or `audit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<Enforcement>,
    /// Globs selecting instruction files, relative to each scanned root.
    /// Omitted means the built-in list; an empty list selects nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub includes: Option<Vec<String>>,
    /// Who may sign an instruction file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub publishers: Vec<Publisher>,
    /// File digests refused whoever signed them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocklist: Vec<BlockedDigest>,
}

/// A publisher whose signature makes an instruction file trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum Publisher {
    /// A CI workflow signing keylessly through Sigstore.
    ///
    /// The signing certificate names the workflow file bound to the ref it ran
    /// under; `repository` and `workflow` must match exactly, `ref` is a glob.
    Keyless {
        /// Unique name, used in reports and audit entries.
        name: String,
        /// OIDC issuer, e.g. `https://token.actions.githubusercontent.com`.
        issuer: String,
        /// `owner/repo` of the workflow that signs.
        repository: String,
        /// The signing workflow file, e.g. `.github/workflows/sign-instructions.yml`.
        workflow: String,
        /// Glob over the git ref the workflow ran under, e.g. `refs/heads/main`
        /// or `refs/tags/v*`. `*` does not cross `/`; use `**` for that.
        #[serde(rename = "ref")]
        git_ref: String,
    },
    /// An Ed25519 key, named by exactly one of `key_id` or `public_key`.
    Keyed {
        /// Unique name, used in reports and audit entries.
        name: String,
        /// A key enrolled with `mvmctl trust add` (32 lowercase hex).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_id: Option<String>,
        /// The 32-byte public key itself, as 64 hex characters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
    },
}

impl Publisher {
    /// The publisher's name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Publisher::Keyless { name, .. } | Publisher::Keyed { name, .. } => name,
        }
    }
}

/// A file digest refused regardless of who signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BlockedDigest {
    /// SHA-256 of the file, as 64 hex characters, optionally `sha256:`-prefixed.
    pub sha256: String,
    /// Why it is blocked; shown when a file is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Why a policy could not be used.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The file exists but could not be read.
    #[error("reading instruction trust policy {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file is not a valid policy document.
    #[error("parsing instruction trust policy {}: {message}", path.display())]
    Parse { path: PathBuf, message: String },
    /// The document parsed but says something that cannot be enforced.
    #[error("instruction trust policy {}: {reason}", path.display())]
    Invalid { path: PathBuf, reason: String },
}

impl InstructionTrustPolicy {
    /// Parse a policy document.
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Render the policy as TOML.
    #[must_use]
    pub fn to_toml_string(&self) -> String {
        toml::to_string_pretty(self).expect("an instruction trust policy always serializes")
    }

    /// Read the policy at `path`; `Ok(None)` when no file is there.
    pub fn load(path: &Path) -> Result<Option<LoadedPolicy>, PolicyError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(PolicyError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let policy = Self::from_toml_str(&text).map_err(|error| PolicyError::Parse {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        Ok(Some(LoadedPolicy {
            path: path.to_path_buf(),
            policy,
        }))
    }
}

/// A policy together with the file it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPolicy {
    pub path: PathBuf,
    pub policy: InstructionTrustPolicy,
}

/// Where the effective policy's authority came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOrigin {
    /// Neither a user nor a project policy exists: record only.
    Builtin,
    /// The user's policy alone.
    User,
    /// The user's policy, tightened by a project policy.
    UserAndProject,
    /// A project policy with no user policy above it: warnings only.
    ProjectAdvisory,
}

impl PolicyOrigin {
    /// The audit-label spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyOrigin::Builtin => "builtin",
            PolicyOrigin::User => "user",
            PolicyOrigin::UserAndProject => "user+project",
            PolicyOrigin::ProjectAdvisory => "project-advisory",
        }
    }

    /// Whether an operator wrote any policy at all.
    #[must_use]
    pub fn is_configured(self) -> bool {
        !matches!(self, PolicyOrigin::Builtin)
    }
}

/// A keyless publisher's identity constraint, validated.
#[derive(Debug, Clone)]
pub struct KeylessPattern {
    pub issuer: String,
    pub repository: String,
    pub workflow: String,
    pub ref_pattern: String,
    ref_matcher: GlobMatcher,
}

impl KeylessPattern {
    /// The certificate identity this publisher accepts, with the ref as the
    /// pattern it is: what an operator compares against a signer.
    #[must_use]
    pub fn identity_pattern(&self) -> String {
        workflow_identity(&self.repository, &self.workflow, &self.ref_pattern)
    }

    /// Whether a certificate issued by `issuer` to `san` is this publisher.
    #[must_use]
    pub fn matches(&self, issuer: &str, san: &str) -> bool {
        let Some(identity) = parse_workflow_identity(san) else {
            return false;
        };
        issuer == self.issuer
            // GitHub owner and repository names are case-insensitive; the
            // certificate carries whichever case the repository was created in.
            && identity.repository.eq_ignore_ascii_case(&self.repository)
            && identity.workflow == self.workflow
            && self.ref_matcher.is_match(identity.git_ref)
    }
}

/// What a publisher's signature is checked against.
#[derive(Debug, Clone)]
pub enum PublisherTrust {
    Keyless(KeylessPattern),
    Keyed { key_id: KeyId, key: VerifyingKey },
}

/// A publisher that passed validation.
#[derive(Debug, Clone)]
pub struct ResolvedPublisher {
    pub name: String,
    pub trust: PublisherTrust,
}

/// The policy verification runs under.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    origin: PolicyOrigin,
    enforcement: Enforcement,
    include_patterns: Vec<String>,
    includes: GlobSet,
    publishers: Vec<ResolvedPublisher>,
    blocklist: BTreeMap<String, Option<String>>,
    sources: Vec<PathBuf>,
    notes: Vec<String>,
}

impl EffectivePolicy {
    /// Merge a user policy and a project policy under the rules in the
    /// module documentation. Keyed publishers named by `key_id` are resolved
    /// through `trust_store`.
    pub fn merge(
        user: Option<LoadedPolicy>,
        project: Option<LoadedPolicy>,
        trust_store: &dyn TrustStore,
    ) -> Result<Self, PolicyError> {
        match (user, project) {
            (None, None) => Ok(Self::builtin()),
            (Some(user), None) => Self::from_user(&user, trust_store),
            (Some(user), Some(project)) => Self::tightened(&user, &project, trust_store),
            (None, Some(project)) => Self::advisory(&project, trust_store),
        }
    }

    /// No policy anywhere: find the default files and record what they are.
    #[must_use]
    pub fn builtin() -> Self {
        let include_patterns: Vec<String> =
            DEFAULT_INCLUDES.iter().map(|s| (*s).to_string()).collect();
        Self {
            origin: PolicyOrigin::Builtin,
            enforcement: Enforcement::Audit,
            includes: compile_includes(&include_patterns)
                .expect("the built-in include globs compile"),
            include_patterns,
            publishers: Vec::new(),
            blocklist: BTreeMap::new(),
            sources: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn from_user(user: &LoadedPolicy, trust_store: &dyn TrustStore) -> Result<Self, PolicyError> {
        let validated = Validated::of(user, trust_store)?;
        Ok(Self {
            origin: PolicyOrigin::User,
            enforcement: user.policy.enforcement.unwrap_or(Enforcement::DEFAULT),
            includes: validated.includes,
            include_patterns: validated.include_patterns,
            publishers: validated.publishers,
            blocklist: validated.blocklist,
            sources: vec![user.path.clone()],
            notes: Vec::new(),
        })
    }

    fn tightened(
        user: &LoadedPolicy,
        project: &LoadedPolicy,
        trust_store: &dyn TrustStore,
    ) -> Result<Self, PolicyError> {
        let base = Validated::of(user, trust_store)?;
        let extra = Validated::of(project, trust_store)?;
        let mut notes = Vec::new();

        let user_enforcement = user.policy.enforcement.unwrap_or(Enforcement::DEFAULT);
        let enforcement = match project.policy.enforcement {
            Some(requested) if requested < user_enforcement => {
                notes.push(format!(
                    "project policy {} asks for `{}`, weaker than the user policy's `{}`; ignored",
                    project.path.display(),
                    requested.as_str(),
                    user_enforcement.as_str()
                ));
                user_enforcement
            }
            Some(requested) => requested,
            None => user_enforcement,
        };

        let mut include_patterns = base.include_patterns;
        for pattern in extra.include_patterns {
            if !include_patterns.contains(&pattern) {
                include_patterns.push(pattern);
            }
        }
        let includes =
            compile_includes(&include_patterns).map_err(|reason| PolicyError::Invalid {
                path: project.path.clone(),
                reason,
            })?;

        let publishers = narrow_publishers(user, project, base.publishers, &mut notes);

        let mut blocklist = base.blocklist;
        for (digest, reason) in extra.blocklist {
            blocklist.entry(digest).or_insert(reason);
        }

        Ok(Self {
            origin: PolicyOrigin::UserAndProject,
            enforcement,
            include_patterns,
            includes,
            publishers,
            blocklist,
            sources: vec![user.path.clone(), project.path.clone()],
            notes,
        })
    }

    fn advisory(project: &LoadedPolicy, trust_store: &dyn TrustStore) -> Result<Self, PolicyError> {
        let validated = Validated::of(project, trust_store)?;
        let requested = project.policy.enforcement.unwrap_or(Enforcement::DEFAULT);
        let enforcement = requested.min(Enforcement::Warn);
        let notes = vec![format!(
            "no user instruction trust policy; the project policy {} is advisory, so its \
             findings warn and never refuse a boot. Write a user policy with \
             `mvmctl trust instructions init` to enforce it",
            project.path.display()
        )];
        Ok(Self {
            origin: PolicyOrigin::ProjectAdvisory,
            enforcement,
            includes: validated.includes,
            include_patterns: validated.include_patterns,
            publishers: validated.publishers,
            blocklist: validated.blocklist,
            sources: vec![project.path.clone()],
            notes,
        })
    }

    /// Where this policy's authority came from.
    #[must_use]
    pub fn origin(&self) -> PolicyOrigin {
        self.origin
    }

    /// What a failed verification does.
    #[must_use]
    pub fn enforcement(&self) -> Enforcement {
        self.enforcement
    }

    /// The include globs, as written.
    #[must_use]
    pub fn include_patterns(&self) -> &[String] {
        &self.include_patterns
    }

    /// Whether `relative` (a path relative to a scanned root) is an
    /// instruction file under this policy.
    #[must_use]
    pub fn includes(&self, relative: &Path) -> bool {
        self.includes.is_match(relative)
    }

    /// The trusted publishers.
    #[must_use]
    pub fn publishers(&self) -> &[ResolvedPublisher] {
        &self.publishers
    }

    /// The reason a digest is blocked, if it is. `Some(None)` is a blocked
    /// digest with no stated reason.
    #[must_use]
    pub fn blocked(&self, sha256_hex: &str) -> Option<Option<&str>> {
        self.blocklist.get(sha256_hex).map(Option::as_deref)
    }

    /// The blocked digests, lowercase hex.
    pub fn blocked_digests(&self) -> impl Iterator<Item = &str> {
        self.blocklist.keys().map(String::as_str)
    }

    /// The policy files this was built from.
    #[must_use]
    pub fn sources(&self) -> &[PathBuf] {
        &self.sources
    }

    /// Things the merge ignored or downgraded, for the operator.
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// A serializable view of the policy, for display.
    #[must_use]
    pub fn summary(&self) -> PolicySummary {
        PolicySummary {
            origin: self.origin,
            sources: self.sources.clone(),
            enforcement: self.enforcement,
            includes: self.include_patterns.clone(),
            publishers: self
                .publishers
                .iter()
                .map(|p| match &p.trust {
                    PublisherTrust::Keyless(pattern) => PublisherSummary::Keyless {
                        name: p.name.clone(),
                        issuer: pattern.issuer.clone(),
                        identity: pattern.identity_pattern(),
                    },
                    PublisherTrust::Keyed { key_id, .. } => PublisherSummary::Keyed {
                        name: p.name.clone(),
                        key_id: key_id.0.clone(),
                    },
                })
                .collect(),
            blocklist: self
                .blocklist
                .iter()
                .map(|(sha256, reason)| BlockedDigest {
                    sha256: sha256.clone(),
                    reason: reason.clone(),
                })
                .collect(),
            notes: self.notes.clone(),
        }
    }

    /// Record something the operator should be told about this policy.
    pub(crate) fn push_note(&mut self, note: String) {
        self.notes.push(note);
    }
}

/// What the effective policy is, in a form that serializes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySummary {
    pub origin: PolicyOrigin,
    pub sources: Vec<PathBuf>,
    pub enforcement: Enforcement,
    pub includes: Vec<String>,
    pub publishers: Vec<PublisherSummary>,
    pub blocklist: Vec<BlockedDigest>,
    pub notes: Vec<String>,
}

/// One trusted publisher, for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PublisherSummary {
    /// The certificate identity accepted, with the ref as a pattern.
    Keyless {
        name: String,
        issuer: String,
        identity: String,
    },
    Keyed {
        name: String,
        key_id: String,
    },
}

/// Keep the user's publishers the project also lists, when it lists any.
///
/// A project naming publishers is asking for fewer signers to be trusted,
/// which is a restriction and honoured. A project entry the user does not
/// trust would be an addition, which is not, and is reported instead.
fn narrow_publishers(
    user: &LoadedPolicy,
    project: &LoadedPolicy,
    resolved_user: Vec<ResolvedPublisher>,
    notes: &mut Vec<String>,
) -> Vec<ResolvedPublisher> {
    if project.policy.publishers.is_empty() {
        return resolved_user;
    }
    for entry in &project.policy.publishers {
        if !user.policy.publishers.contains(entry) {
            notes.push(format!(
                "project publisher `{}` in {} is not trusted by the user policy; ignored",
                entry.name(),
                project.path.display()
            ));
        }
    }
    user.policy
        .publishers
        .iter()
        .zip(resolved_user)
        .filter(|(raw, _)| project.policy.publishers.contains(raw))
        .map(|(_, resolved)| resolved)
        .collect()
}

/// One policy file's contents after validation.
struct Validated {
    include_patterns: Vec<String>,
    includes: GlobSet,
    publishers: Vec<ResolvedPublisher>,
    blocklist: BTreeMap<String, Option<String>>,
}

impl Validated {
    fn of(loaded: &LoadedPolicy, trust_store: &dyn TrustStore) -> Result<Self, PolicyError> {
        let invalid = |reason: String| PolicyError::Invalid {
            path: loaded.path.clone(),
            reason,
        };
        let include_patterns: Vec<String> = match &loaded.policy.includes {
            Some(patterns) => patterns.clone(),
            None => DEFAULT_INCLUDES.iter().map(|s| (*s).to_string()).collect(),
        };
        let includes = compile_includes(&include_patterns).map_err(invalid)?;

        let mut names = std::collections::BTreeSet::new();
        let mut publishers = Vec::with_capacity(loaded.policy.publishers.len());
        for publisher in &loaded.policy.publishers {
            if !names.insert(publisher.name()) {
                return Err(invalid(format!(
                    "publisher name `{}` is used twice",
                    publisher.name()
                )));
            }
            publishers.push(resolve_publisher(publisher, trust_store).map_err(invalid)?);
        }

        let mut blocklist = BTreeMap::new();
        for entry in &loaded.policy.blocklist {
            let digest = normalize_digest(&entry.sha256).map_err(invalid)?;
            blocklist.insert(digest, entry.reason.clone());
        }
        Ok(Self {
            include_patterns,
            includes,
            publishers,
            blocklist,
        })
    }
}

/// Compile include globs. A pattern must be relative and must not climb out
/// of the root it is matched against.
fn compile_includes(patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if pattern.trim().is_empty() {
            return Err("an include pattern is empty".to_string());
        }
        if pattern.starts_with('/') || pattern.split('/').any(|part| part == "..") {
            return Err(format!(
                "include `{pattern}` must be relative to the scanned root and stay inside it"
            ));
        }
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .case_insensitive(true)
            .build()
            .map_err(|error| format!("include `{pattern}` is not a valid glob: {error}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| format!("include patterns do not compile: {error}"))
}

fn resolve_publisher(
    publisher: &Publisher,
    trust_store: &dyn TrustStore,
) -> Result<ResolvedPublisher, String> {
    let trust = match publisher {
        Publisher::Keyless {
            name,
            issuer,
            repository,
            workflow,
            git_ref,
        } => PublisherTrust::Keyless(keyless_pattern(
            name, issuer, repository, workflow, git_ref,
        )?),
        Publisher::Keyed {
            name,
            key_id,
            public_key,
        } => {
            let (key_id, key) =
                keyed_key(name, key_id.as_deref(), public_key.as_deref(), trust_store)?;
            PublisherTrust::Keyed { key_id, key }
        }
    };
    if publisher.name().trim().is_empty() {
        return Err("a publisher has an empty name".to_string());
    }
    Ok(ResolvedPublisher {
        name: publisher.name().to_string(),
        trust,
    })
}

fn keyless_pattern(
    name: &str,
    issuer: &str,
    repository: &str,
    workflow: &str,
    git_ref: &str,
) -> Result<KeylessPattern, String> {
    if !issuer.starts_with("https://") {
        return Err(format!("publisher `{name}`: issuer must be an https URL"));
    }
    let valid_repository = repository
        .split_once('/')
        .is_some_and(|(owner, repo)| !owner.is_empty() && !repo.is_empty() && !repo.contains('/'));
    if !valid_repository || repository.contains(['*', '?', '[', '@']) {
        return Err(format!(
            "publisher `{name}`: repository must be an exact `owner/repo`"
        ));
    }
    if !workflow.starts_with(WORKFLOW_DIR_PREFIX)
        || workflow.len() == WORKFLOW_DIR_PREFIX.len()
        || workflow.contains(['*', '?', '[', '@'])
    {
        return Err(format!(
            "publisher `{name}`: workflow must be an exact path under `{WORKFLOW_DIR_PREFIX}`"
        ));
    }
    if !git_ref.starts_with("refs/") {
        return Err(format!(
            "publisher `{name}`: ref must be a full git ref pattern such as `refs/heads/main`"
        ));
    }
    let ref_matcher = GlobBuilder::new(git_ref)
        .literal_separator(true)
        .build()
        .map_err(|error| {
            format!("publisher `{name}`: ref `{git_ref}` is not a valid glob: {error}")
        })?
        .compile_matcher();
    Ok(KeylessPattern {
        issuer: issuer.to_string(),
        repository: repository.to_string(),
        workflow: workflow.to_string(),
        ref_pattern: git_ref.to_string(),
        ref_matcher,
    })
}

fn keyed_key(
    name: &str,
    key_id: Option<&str>,
    public_key: Option<&str>,
    trust_store: &dyn TrustStore,
) -> Result<(KeyId, VerifyingKey), String> {
    match (key_id, public_key) {
        (Some(_), Some(_)) | (None, None) => Err(format!(
            "publisher `{name}`: a keyed publisher names exactly one of `key_id` or `public_key`"
        )),
        (Some(id), None) => {
            let id = KeyId(id.to_string());
            if !id.is_well_formed() {
                return Err(format!(
                    "publisher `{name}`: key_id must be 32 lowercase hex characters"
                ));
            }
            let key = trust_store.lookup(&id).ok_or_else(|| {
                format!(
                    "publisher `{name}`: key_id {} is not enrolled; add it with `mvmctl trust add`",
                    id.0
                )
            })?;
            Ok((id, key))
        }
        (None, Some(hex_key)) => {
            let bytes: [u8; 32] = hex::decode(hex_key.trim())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    format!("publisher `{name}`: public_key must be 64 hex characters (32 bytes)")
                })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                format!("publisher `{name}`: public_key is not a valid Ed25519 key")
            })?;
            Ok((key_id_from_pubkey(&key), key))
        }
    }
}

/// Normalize a blocklist digest to bare lowercase hex.
fn normalize_digest(raw: &str) -> Result<String, String> {
    let hex_part = raw.trim().strip_prefix("sha256:").unwrap_or(raw.trim());
    if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "blocklist digest `{raw}` is not a SHA-256 (64 hex characters)"
        ));
    }
    Ok(hex_part.to_ascii_lowercase())
}

/// The policy document's JSON Schema, pretty-printed.
#[cfg(feature = "schema")]
#[must_use]
pub fn json_schema_pretty() -> String {
    let schema = schemars::schema_for!(InstructionTrustPolicy);
    serde_json::to_string_pretty(&schema).expect("a JSON Schema always serializes")
}

/// Where the committed schema lives, relative to the workspace root.
pub const SCHEMA_PATH: &str = "schema/instruction-trust-policy-v0.json";

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
