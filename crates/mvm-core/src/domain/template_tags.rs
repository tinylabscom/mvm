//! Template tags + aliases — A6 of the filesystem-volumes plan.
//!
//! Tags and aliases are persisted alongside a template's revision
//! catalog rather than embedded in `TemplateRevision` so the
//! per-build wire shape stays stable. A single `tags.json` per
//! template holds:
//!
//! - **tags** — set of free-form labels for filtering / discovery
//!   (`mvmctl template ls --tag <tag>`). Tenant-controlled, so
//!   they go through the same `mvm-core::crypto::policy::InputValidator`
//!   discipline as sandbox tags.
//! - **aliases** — name → revision_hash pointers (`latest`,
//!   `stable`, etc.). Resolution happens at `mvmctl up` /
//!   `mvmctl exec` time via [`resolve_alias`]. Setting an alias
//!   that already exists is a deliberate move — the old target is
//!   silently overwritten, mirroring `git tag -f`'s "movable
//!   pointer" semantics.
//!
//! # Disk format
//!
//! ```text
//! ~/.mvm/templates/<template-id>/tags.json     mode 0600
//! ```
//!
//! Atomic writes via the existing `util::atomic_io::atomic_write`
//! helper. Missing files are treated as "no tags / no aliases" —
//! the same forgiving shape as the VM-name registry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Maximum number of tags per template. Defends against unbounded
/// growth in the persisted JSON; matches the `MAX_TAGS` cap on
/// sandbox-side tags so the discipline is uniform.
pub const MAX_TEMPLATE_TAGS: usize = 32;

/// Maximum number of aliases per template. Aliases are pointers,
/// not labels — 32 is far more than `latest` / `stable` / `vN`
/// shapes need but cheap to allow.
pub const MAX_TEMPLATE_ALIASES: usize = 32;

/// Persistent tag + alias catalog for one template.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TemplateTags {
    #[serde(default)]
    pub tags: BTreeSet<String>,
    /// `alias` → `revision_hash`. The alias is the user-visible
    /// label; the revision_hash is whatever `TemplateRevision`
    /// the alias should resolve to.
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
}

impl TemplateTags {
    /// Returns the file path where this template's tag catalog
    /// lives. Doesn't create it.
    pub fn path_for(template_id: &str) -> PathBuf {
        PathBuf::from(super::template::template_dir(template_id)).join("tags.json")
    }

    /// Load the catalog from disk. Missing files yield an empty
    /// catalog — matches the VmNameRegistry forgiving shape so
    /// callers that "look up tags" don't have to special-case
    /// "never had any."
    pub fn load(template_id: &str) -> Result<Self> {
        let path = Self::path_for(template_id);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let parsed: Self =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        Ok(parsed)
    }

    /// Atomic write of the catalog. Creates the parent dir if
    /// missing, sets file mode 0600 on the rendered file.
    pub fn save(&self, template_id: &str) -> Result<()> {
        let path = Self::path_for(template_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent of {}", path.display()))?;
        }
        let json = serde_json::to_vec_pretty(self).context("serialize template_tags")?;
        crate::util::atomic_io::atomic_write(&path, &json)
            .with_context(|| format!("atomic_write {}", path.display()))?;
        // atomic_write doesn't take a mode argument; tighten in place.
        // Tag/alias files are not secret on their own (they're
        // metadata), but `~/.mvm` is mode 0700 anyway and 0600 keeps
        // the discipline uniform with snapshot files.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)
                .with_context(|| format!("chmod 0600 {}", path.display()))?;
        }
        Ok(())
    }

    /// Add `tag` to the catalog. Validates against the standard
    /// template-name charset rules + the per-template count cap.
    /// No-op when the tag is already present.
    pub fn add_tag(&mut self, tag: &str) -> Result<()> {
        validate_tag_or_alias(tag).context("invalid tag")?;
        if !self.tags.contains(tag) && self.tags.len() >= MAX_TEMPLATE_TAGS {
            bail!(
                "template already has the maximum {MAX_TEMPLATE_TAGS} tags; \
                 remove one before adding another"
            );
        }
        self.tags.insert(tag.to_string());
        Ok(())
    }

    /// Remove `tag`. Returns `true` if the tag was present.
    pub fn remove_tag(&mut self, tag: &str) -> bool {
        self.tags.remove(tag)
    }

    /// Set (or move) `alias` → `revision_hash`. Validates the
    /// alias name + the revision-hash shape (lower-case hex, 8-64
    /// chars). Existing aliases are overwritten silently —
    /// callers depending on detect-overwrite semantics check
    /// `aliases.contains_key` before calling.
    pub fn set_alias(&mut self, alias: &str, revision_hash: &str) -> Result<()> {
        validate_tag_or_alias(alias).context("invalid alias")?;
        validate_revision_hash(revision_hash).context("invalid revision_hash")?;
        let is_new = !self.aliases.contains_key(alias);
        if is_new && self.aliases.len() >= MAX_TEMPLATE_ALIASES {
            bail!(
                "template already has the maximum {MAX_TEMPLATE_ALIASES} aliases; \
                 remove one before adding another"
            );
        }
        self.aliases
            .insert(alias.to_string(), revision_hash.to_string());
        Ok(())
    }

    /// Remove `alias`. Returns `true` if the alias was present.
    pub fn remove_alias(&mut self, alias: &str) -> bool {
        self.aliases.remove(alias).is_some()
    }
}

/// Resolve `alias` for `template_id` to a revision_hash. Returns
/// `None` when the catalog is missing, the alias is unknown, or
/// the catalog can't be parsed (treat the latter as "no resolution"
/// rather than a hard error so a corrupt tags.json doesn't block
/// `mvmctl up`).
pub fn resolve_alias(template_id: &str, alias: &str) -> Option<String> {
    let catalog = TemplateTags::load(template_id).ok()?;
    catalog.aliases.get(alias).cloned()
}

/// Parse an `<template_id>@<alias>` reference. Returns the
/// (template_id, alias) split if `@` is present; `None` when the
/// raw arg is just a template name. Used by `mvmctl up --manifest`
/// to decide whether to consult the alias catalog.
pub fn split_aliased_ref(raw: &str) -> Option<(&str, &str)> {
    let (id, alias) = raw.split_once('@')?;
    if id.is_empty() || alias.is_empty() {
        return None;
    }
    Some((id, alias))
}

/// Charset + length validator shared by tag and alias names.
///
/// Mirrors `validate_template_name`'s rules (lowercase alphanumeric
/// plus `-`/`_`, 1–63 chars, must not start with a punctuation char)
/// so a tag/alias is always a legal segment in a future
/// `template@alias` URL-shaped form.
fn validate_tag_or_alias(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 63 {
        bail!("must be 1-63 characters, got {}", s.len());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        bail!(
            "must be lowercase alphanumeric + hyphens/underscores: {:?}",
            s
        );
    }
    if s.starts_with('-') || s.starts_with('_') {
        bail!("must not start with a hyphen or underscore: {:?}", s);
    }
    Ok(())
}

fn validate_revision_hash(s: &str) -> Result<()> {
    if s.len() < 8 || s.len() > 64 {
        bail!("revision_hash length {} outside [8, 64]", s.len());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    {
        bail!(
            "revision_hash must be lowercase hex (matches sha256-prefix shape): {:?}",
            s
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test guard that overrides `MVM_DATA_DIR` to a tempdir so
    /// concurrent tests don't share `~/.mvm/templates/...` state.
    struct DataDirGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
        _tmp: tempfile::TempDir,
    }

    static DATA_DIR_LOCK: Mutex<()> = Mutex::new(());

    impl DataDirGuard {
        fn new() -> Self {
            let g = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var("MVM_DATA_DIR").ok();
            unsafe {
                std::env::set_var("MVM_DATA_DIR", tmp.path());
            }
            DataDirGuard {
                _guard: g,
                prev,
                _tmp: tmp,
            }
        }
    }

    impl Drop for DataDirGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("MVM_DATA_DIR", v),
                    None => std::env::remove_var("MVM_DATA_DIR"),
                }
            }
        }
    }

    #[test]
    fn validate_tag_or_alias_accepts_typical_names() {
        for s in ["latest", "v1", "v1-2-3", "stable", "rc", "a_b_c", "0123"] {
            validate_tag_or_alias(s).unwrap_or_else(|e| panic!("{s:?}: {e}"));
        }
    }

    #[test]
    fn validate_tag_or_alias_rejects_bad_names() {
        for s in [
            "",
            "-leading",
            "_leading",
            "Upper",
            "with space",
            "weird?",
            "x".repeat(64).as_str(),
        ] {
            assert!(validate_tag_or_alias(s).is_err(), "should reject {s:?}",);
        }
    }

    #[test]
    fn validate_revision_hash_accepts_hex_in_range() {
        for s in ["abc12345", "0123456789abcdef", &"a".repeat(64)] {
            validate_revision_hash(s).unwrap_or_else(|e| panic!("{s:?}: {e}"));
        }
    }

    #[test]
    fn validate_revision_hash_rejects_uppercase() {
        assert!(validate_revision_hash("ABC12345").is_err());
        assert!(validate_revision_hash("aBc12345").is_err());
    }

    #[test]
    fn validate_revision_hash_rejects_too_short_or_long() {
        assert!(validate_revision_hash("short").is_err());
        assert!(validate_revision_hash(&"a".repeat(65)).is_err());
    }

    #[test]
    fn validate_revision_hash_rejects_non_hex() {
        assert!(validate_revision_hash("nothex01").is_err());
    }

    #[test]
    fn template_tags_default_is_empty() {
        let t = TemplateTags::default();
        assert!(t.tags.is_empty());
        assert!(t.aliases.is_empty());
    }

    #[test]
    fn add_tag_inserts_and_dedupes() {
        let mut t = TemplateTags::default();
        t.add_tag("latest").unwrap();
        t.add_tag("latest").unwrap();
        t.add_tag("v1").unwrap();
        assert_eq!(t.tags.len(), 2);
        assert!(t.tags.contains("latest"));
        assert!(t.tags.contains("v1"));
    }

    #[test]
    fn add_tag_validates_charset() {
        let mut t = TemplateTags::default();
        assert!(t.add_tag("BAD").is_err());
        assert!(t.add_tag("with space").is_err());
        assert!(t.add_tag("-leading").is_err());
    }

    #[test]
    fn add_tag_caps_count() {
        let mut t = TemplateTags::default();
        for i in 0..MAX_TEMPLATE_TAGS {
            t.add_tag(&format!("tag-{i}")).unwrap();
        }
        // Re-adding an existing tag is fine.
        t.add_tag("tag-0").unwrap();
        // A new one beyond the cap is rejected.
        let err = t.add_tag("one-too-many").unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn remove_tag_returns_true_only_when_present() {
        let mut t = TemplateTags::default();
        t.add_tag("latest").unwrap();
        assert!(t.remove_tag("latest"));
        assert!(!t.remove_tag("latest"));
    }

    #[test]
    fn set_alias_stores_pointer_and_overwrites_silently() {
        let mut t = TemplateTags::default();
        t.set_alias("latest", "abc12345").unwrap();
        assert_eq!(
            t.aliases.get("latest").map(String::as_str),
            Some("abc12345")
        );
        // Move `latest` to a new revision (canonical "git tag -f" shape).
        t.set_alias("latest", "def67890").unwrap();
        assert_eq!(
            t.aliases.get("latest").map(String::as_str),
            Some("def67890")
        );
    }

    #[test]
    fn set_alias_validates_both_sides() {
        let mut t = TemplateTags::default();
        assert!(t.set_alias("BAD", "abc12345").is_err());
        assert!(t.set_alias("ok", "NOT-HEX!").is_err());
    }

    #[test]
    fn set_alias_caps_count() {
        let mut t = TemplateTags::default();
        for i in 0..MAX_TEMPLATE_ALIASES {
            t.set_alias(&format!("a-{i}"), "abc12345").unwrap();
        }
        // Existing alias updates are always fine, even past the cap.
        t.set_alias("a-0", "def67890").unwrap();
        let err = t.set_alias("one-too-many", "abc12345").unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }

    #[test]
    fn remove_alias_returns_true_only_when_present() {
        let mut t = TemplateTags::default();
        t.set_alias("latest", "abc12345").unwrap();
        assert!(t.remove_alias("latest"));
        assert!(!t.remove_alias("latest"));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let _g = DataDirGuard::new();
        let mut t = TemplateTags::default();
        t.add_tag("latest").unwrap();
        t.add_tag("v1").unwrap();
        t.set_alias("stable", "abc12345").unwrap();
        t.save("python-3.12").unwrap();

        let loaded = TemplateTags::load("python-3.12").unwrap();
        assert_eq!(loaded, t);
    }

    #[test]
    fn load_missing_returns_empty() {
        let _g = DataDirGuard::new();
        let loaded = TemplateTags::load("never-saved").unwrap();
        assert_eq!(loaded, TemplateTags::default());
    }

    #[test]
    fn save_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _g = DataDirGuard::new();
        let t = TemplateTags::default();
        t.save("perms-test").unwrap();
        let path = TemplateTags::path_for("perms-test");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn save_then_modify_then_save_replaces_atomically() {
        let _g = DataDirGuard::new();
        let mut t = TemplateTags::default();
        t.add_tag("v1").unwrap();
        t.save("atomic-test").unwrap();

        t.add_tag("v2").unwrap();
        t.save("atomic-test").unwrap();

        let loaded = TemplateTags::load("atomic-test").unwrap();
        assert_eq!(loaded.tags.len(), 2);
        assert!(loaded.tags.contains("v1"));
        assert!(loaded.tags.contains("v2"));
    }

    #[test]
    fn unknown_field_in_persisted_json_is_rejected() {
        let _g = DataDirGuard::new();
        let path = TemplateTags::path_for("schema-test");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"tags":[],"aliases":{},"smuggled":1}"#).unwrap();
        // load() surfaces parse errors via anyhow::Error.
        let err = TemplateTags::load("schema-test").unwrap_err();
        assert!(
            err.to_string().contains("unknown field")
                || err
                    .source()
                    .map(|s| s.to_string().contains("unknown field"))
                    .unwrap_or(false),
            "expected unknown-field rejection, got: {err}"
        );
    }

    #[test]
    fn resolve_alias_returns_revision_hash() {
        let _g = DataDirGuard::new();
        let mut t = TemplateTags::default();
        t.set_alias("stable", "abc12345").unwrap();
        t.save("res-test").unwrap();
        assert_eq!(
            resolve_alias("res-test", "stable"),
            Some("abc12345".to_string())
        );
    }

    #[test]
    fn resolve_alias_returns_none_for_missing_template() {
        let _g = DataDirGuard::new();
        assert!(resolve_alias("never-saved", "stable").is_none());
    }

    #[test]
    fn resolve_alias_returns_none_for_unknown_alias() {
        let _g = DataDirGuard::new();
        let mut t = TemplateTags::default();
        t.set_alias("stable", "abc12345").unwrap();
        t.save("partial-aliases").unwrap();
        assert!(resolve_alias("partial-aliases", "latest").is_none());
    }

    #[test]
    fn split_aliased_ref_recognises_at_form() {
        assert_eq!(
            split_aliased_ref("python@latest"),
            Some(("python", "latest"))
        );
        assert_eq!(split_aliased_ref("a@b@c"), Some(("a", "b@c")));
    }

    #[test]
    fn split_aliased_ref_returns_none_for_plain_or_malformed() {
        assert_eq!(split_aliased_ref("python"), None);
        assert_eq!(split_aliased_ref("@latest"), None);
        assert_eq!(split_aliased_ref("python@"), None);
        assert_eq!(split_aliased_ref(""), None);
    }
}
