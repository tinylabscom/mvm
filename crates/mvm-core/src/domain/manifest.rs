//! User-facing manifest file (`mvm.toml` or `Mvmfile.toml`) — the
//! "what to build and how to size it" primitive that drives the
//! template flow per plan 38 (manifest-driven template DX).
//!
//! A manifest is identified by its canonical filesystem path. The
//! registry slot for its build artifacts will live at
//! `~/.mvm/templates/<sha256(canonical_manifest_path)>/`. The
//! optional `name` field is a display label / S3 channel hint —
//! NOT the registry key.
//!
//! Schema (v1):
//! ```toml
//! flake = "."
//! profile = "default"
//! vcpus = 2
//! mem = "1024M"
//! data_disk = "0"
//! name = "openclaw"   # optional, display only
//! ```
//!
//! Boundary: build inputs + dev sizing only. No `role` (the flake's
//! profile selects role variants), no `[network]` (runtime policy
//! lives in `mvmctl up` flags / `~/.mvm/config.toml` / mvmd tenant
//! config), no dependencies (Nix owns build deps; mvmd owns runtime
//! deps).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::naming::{validate_flake_ref, validate_template_name};
use crate::util::parse_human_size;

/// Filenames recognised as manifests, in discovery preference order.
/// `mvm.toml` is preferred; `Mvmfile.toml` is accepted so the legacy
/// `mvmctl build` flow folds into the same parser/schema. If both
/// exist in one directory the discovery layer errors.
pub const MANIFEST_FILENAMES: &[&str] = &["mvm.toml", "Mvmfile.toml"];

/// Highest manifest schema version this build understands. Future
/// fields are additive via `#[serde(default)]`; bumping this signals
/// breaking changes that older mvmctl versions must reject.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Floor for `mem`. Below this Firecracker guests don't reliably
/// boot; we'd rather fail loudly at parse time than have a confusing
/// runtime error.
const MIN_MEM_MIB: u32 = 64;

fn default_schema_version() -> u32 {
    MANIFEST_SCHEMA_VERSION
}

fn default_flake() -> String {
    ".".to_string()
}

fn default_profile() -> String {
    "default".to_string()
}

fn default_vcpus() -> u8 {
    2
}

fn default_mem() -> String {
    "1024M".to_string()
}

fn default_data_disk() -> String {
    "0".to_string()
}

/// User-facing manifest file. One per project directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Nix flake reference. `"."` resolves to the directory the
    /// manifest lives in. Any flake ref form is accepted (path,
    /// `github:owner/repo`, `git+https://…`, etc.).
    #[serde(default = "default_flake")]
    pub flake: String,

    /// Flake package selector — picks `packages.<system>.<profile>`
    /// out of the flake's outputs.
    #[serde(default = "default_profile")]
    pub profile: String,

    /// Firecracker host-side vCPU count.
    #[serde(default = "default_vcpus")]
    pub vcpus: u8,

    /// Human-readable memory size (`512M`, `1G`, `1024`, …).
    #[serde(default = "default_mem")]
    pub mem: String,

    /// Human-readable data disk size; `"0"` means no data disk.
    #[serde(default = "default_data_disk")]
    pub data_disk: String,

    /// Optional display name used in `template list` output and as
    /// the S3 channel key for `template push`/`pull`. NOT the
    /// registry key — the registry uses the manifest's canonical
    /// path hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Manifest {
    /// Parse a manifest from TOML text and validate semantically.
    /// Validation runs immediately so broken manifests fail before
    /// any I/O (e.g. before `nix build` is invoked).
    pub fn from_toml_str(text: &str) -> Result<Self> {
        let m: Self = toml::from_str(text).context("Failed to parse manifest TOML")?;
        m.validate()?;
        Ok(m)
    }

    /// Read and parse a manifest at a file path.
    pub fn read_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest at {}", path.display()))?;
        Self::from_toml_str(&text)
    }

    /// Validate the manifest's contents.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version > MANIFEST_SCHEMA_VERSION {
            return Err(anyhow!(
                "manifest declares schema_version={}; this mvmctl supports {}; upgrade mvmctl",
                self.schema_version,
                MANIFEST_SCHEMA_VERSION
            ));
        }
        if self.flake.trim().is_empty() {
            return Err(anyhow!("manifest field `flake` must not be empty"));
        }
        validate_flake_ref(&self.flake)
            .with_context(|| format!("invalid `flake` field: {:?}", self.flake))?;
        if self.vcpus == 0 {
            return Err(anyhow!("manifest field `vcpus` must be >= 1"));
        }
        let mem = parse_human_size(&self.mem)
            .with_context(|| format!("invalid `mem` field: {:?}", self.mem))?;
        if mem < MIN_MEM_MIB {
            return Err(anyhow!(
                "manifest field `mem` must be >= {MIN_MEM_MIB} MiB (got {mem} MiB)"
            ));
        }
        let _ = parse_human_size(&self.data_disk)
            .with_context(|| format!("invalid `data_disk` field: {:?}", self.data_disk))?;
        if let Some(name) = self.name.as_deref() {
            validate_template_name(name)
                .with_context(|| format!("invalid `name` field: {:?}", name))?;
        }
        Ok(())
    }

    /// Memory in MiB, parsed from the human-readable string.
    pub fn mem_mib(&self) -> Result<u32> {
        parse_human_size(&self.mem).with_context(|| format!("invalid `mem` field: {:?}", self.mem))
    }

    /// Data disk in MiB.
    pub fn data_disk_mib(&self) -> Result<u32> {
        parse_human_size(&self.data_disk)
            .with_context(|| format!("invalid `data_disk` field: {:?}", self.data_disk))
    }
}

/// If exactly one of `mvm.toml` / `Mvmfile.toml` exists in `dir`,
/// return its path. If both exist, error (ambiguous). If neither,
/// return `None`.
pub fn manifest_in_dir(dir: &Path) -> Result<Option<PathBuf>> {
    let candidates: Vec<PathBuf> = MANIFEST_FILENAMES
        .iter()
        .filter_map(|name| {
            let p = dir.join(name);
            if p.is_file() { Some(p) } else { None }
        })
        .collect();
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(Some(
            candidates.into_iter().next().expect("len checked above"),
        )),
        _ => Err(anyhow!(
            "found both mvm.toml and Mvmfile.toml in {}; pick one",
            dir.display()
        )),
    }
}

/// Walk upward from `start` looking for a manifest. Stops at the
/// first directory containing one, at a `.git` boundary, or at the
/// filesystem root. Returns the (canonicalised) manifest path or
/// `None` if none found before a stop condition.
pub fn discover_manifest_from_dir(start: &Path) -> Result<Option<PathBuf>> {
    let mut cur: PathBuf = std::fs::canonicalize(start)
        .with_context(|| format!("Failed to canonicalize {}", start.display()))?;
    loop {
        if let Some(p) = manifest_in_dir(&cur)? {
            return Ok(Some(p));
        }
        // .git marks a project boundary — don't escape upward.
        if cur.join(".git").exists() {
            return Ok(None);
        }
        match cur.parent() {
            Some(parent) if parent != cur => cur = parent.to_path_buf(),
            _ => return Ok(None),
        }
    }
}

/// Resolve a `--mvm-config <path>` argument: file paths are used
/// directly; directories are resolved via `manifest_in_dir`.
pub fn resolve_manifest_config_path(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    if path.is_dir() {
        return manifest_in_dir(path)?
            .ok_or_else(|| anyhow!("no mvm.toml or Mvmfile.toml found in {}", path.display()));
    }
    Err(anyhow!("manifest path does not exist: {}", path.display()))
}

/// Canonical registry key for a manifest at `path`:
/// `sha256(canonical_absolute_path)` as 64-char hex. Resolves
/// symlinks so two access paths to the same file hash to the same
/// key.
pub fn canonical_key_for_path(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize {}", path.display()))?;
    let bytes = canonical
        .as_os_str()
        .to_str()
        .ok_or_else(|| anyhow!("canonical path contains non-UTF-8: {:?}", canonical))?
        .as_bytes();
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Slot directory for a given canonical-path-hash:
/// `~/.mvm/templates/<slot_hash>/`. Reuses
/// `crate::template::templates_base_dir()` so legacy and modern
/// slots share the same base. Documented in plan 38 §3.
pub fn slot_dir(slot_hash: &str) -> String {
    format!("{}/{}", crate::template::templates_base_dir(), slot_hash)
}

/// Path to a slot's persisted manifest record:
/// `<slot>/manifest.json`.
pub fn slot_manifest_path(slot_hash: &str) -> String {
    format!("{}/manifest.json", slot_dir(slot_hash))
}

/// Combined helper: canonicalise `path`, hash it, return the slot
/// directory path. Errors if `path` can't be canonicalised.
pub fn slot_dir_for_manifest_path(path: &Path) -> Result<String> {
    let key = canonical_key_for_path(path)?;
    Ok(slot_dir(&key))
}

/// True if `name` looks like a modern slot directory name —
/// 64 lowercase hex characters. Used to distinguish hash-keyed
/// slots from legacy name-keyed slots during migration (plan 38
/// §8a "Migration strategy").
pub fn is_slot_hash_dirname(name: &str) -> bool {
    name.len() == 64
        && name
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Build provenance recorded alongside each slot's persisted
/// manifest. Defined in plan 38 §3 / §7c. Ties the artifacts back
/// to the build environment without introducing a new signing
/// scheme.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    /// `mvmctl` (workspace) version that wrote this slot.
    pub toolchain_version: String,
    /// SHA-256 (or similar) digest of the sealed-signed builder
    /// image used. `None` for builds done outside that pipeline.
    /// Populated when plan 36 is in use.
    #[serde(default)]
    pub builder_image_digest: Option<String>,
    /// Host arch + OS, e.g. `"x86_64-linux"`, `"aarch64-darwin"`.
    pub host_arch: String,
    /// ISO-8601 UTC timestamp when this slot was last written.
    pub built_at: String,
    /// Workload IR hash when the manifest was emitted by mvmforge.
    /// `None` for hand-written manifests.
    #[serde(default)]
    pub ir_hash: Option<String>,
}

impl Provenance {
    /// Provenance for a build happening *now* on the current host.
    /// `built_at` is filled with a UTC ISO-8601 timestamp via
    /// `crate::util::time::utc_now()`. `builder_image_digest` and
    /// `ir_hash` default to `None`; callers populate them when
    /// they have the data.
    pub fn current() -> Self {
        Self {
            toolchain_version: env!("CARGO_PKG_VERSION").to_string(),
            builder_image_digest: None,
            host_arch: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            built_at: crate::util::time::utc_now(),
            ir_hash: None,
        }
    }
}

/// Slot-resident JSON record that persists what `template build`
/// stored about a slot. Lives at
/// `~/.mvm/templates/<sha256(canonical_manifest_path)>/manifest.json`
/// per plan 38 §3.
///
/// Coexists with the legacy name-keyed `TemplateSpec` for the
/// duration of the refactor. The runtime layer migrates to this
/// type in a subsequent slice; for now it's pure addition.
///
/// Sizing fields are stored numeric (already parsed from the
/// `Manifest`'s human-readable strings) so the slot record is
/// self-contained and doesn't need to re-parse on every read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedManifest {
    #[serde(default = "default_persisted_schema_version")]
    pub schema_version: u32,

    /// Absolute, canonicalised path to the source `mvm.toml` /
    /// `Mvmfile.toml`. Identifies the slot for migration / display.
    pub manifest_path: String,

    /// `sha256(canonical_manifest_path)` — the slot directory key.
    /// Stored alongside `manifest_path` for cheap lookups without
    /// re-canonicalising on every read.
    pub manifest_hash: String,

    /// Resolved flake reference (verbatim from `Manifest::flake`).
    pub flake_ref: String,

    /// Selected flake profile.
    pub profile: String,

    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,

    /// Display name from the manifest (NOT the registry key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// VM backend the slot was built on. Used by §7b's
    /// "warn on backend mismatch at boot" check. Free-form string
    /// matching `AnyBackend::name()`.
    pub backend: String,

    pub provenance: Provenance,

    pub created_at: String,
    pub updated_at: String,
}

fn default_persisted_schema_version() -> u32 {
    MANIFEST_SCHEMA_VERSION
}

impl PersistedManifest {
    /// Build a `PersistedManifest` from a parsed `Manifest`, the
    /// (canonical) source path, the chosen backend name, and a
    /// `Provenance` block. Numeric sizing fields are parsed out of
    /// the manifest's human-readable strings here so the slot
    /// record is self-contained.
    pub fn from_manifest(
        manifest: &Manifest,
        canonical_path: &Path,
        backend: &str,
        provenance: Provenance,
    ) -> Result<Self> {
        let manifest_path = canonical_path
            .to_str()
            .ok_or_else(|| anyhow!("manifest path is not valid UTF-8: {:?}", canonical_path))?
            .to_string();
        let manifest_hash = canonical_key_for_path(canonical_path)?;
        let mem_mib = manifest.mem_mib()?;
        let data_disk_mib = manifest.data_disk_mib()?;
        let now = provenance.built_at.clone();
        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            manifest_path,
            manifest_hash,
            flake_ref: manifest.flake.clone(),
            profile: manifest.profile.clone(),
            vcpus: manifest.vcpus,
            mem_mib,
            data_disk_mib,
            name: manifest.name.clone(),
            backend: backend.to_string(),
            provenance,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Produce an updated copy with `updated_at` and `provenance`
    /// refreshed (used on rebuild). `created_at` is preserved.
    pub fn touch(self, provenance: Provenance) -> Self {
        let updated_at = provenance.built_at.clone();
        Self {
            updated_at,
            provenance,
            ..self
        }
    }

    /// Atomically write `<slot_dir>/manifest.json`
    /// (write-temp-then-rename via `tempfile::NamedTempFile::persist`).
    /// Crash mid-write leaves either the previous file or no
    /// change — never a half-written file. Plan 38 §7b "Atomic
    /// slot writes".
    pub fn write_to_slot(&self, slot_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(slot_dir)
            .with_context(|| format!("Failed to create slot dir {}", slot_dir.display()))?;
        let dst = slot_dir.join("manifest.json");
        let json =
            serde_json::to_string_pretty(self).context("Failed to serialise PersistedManifest")?;
        let mut tmp = tempfile::NamedTempFile::new_in(slot_dir).with_context(|| {
            format!(
                "Failed to create tempfile inside slot dir {}",
                slot_dir.display()
            )
        })?;
        use std::io::Write;
        tmp.write_all(json.as_bytes())
            .context("Failed to write persisted manifest body")?;
        tmp.persist(&dst).map_err(|e| {
            anyhow!(
                "Failed to atomically replace {}: {}",
                dst.display(),
                e.error
            )
        })?;
        Ok(())
    }

    /// Read `<slot_dir>/manifest.json` and deserialise.
    pub fn read_from_slot(slot_dir: &Path) -> Result<Self> {
        let path = slot_dir.join("manifest.json");
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&body)
            .with_context(|| format!("Failed to parse persisted manifest at {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write fixture");
    }

    fn minimal_manifest_toml() -> &'static str {
        r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            data_disk = "0"
        "#
    }

    #[test]
    fn parse_minimal_manifest_succeeds() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).expect("parses");
        assert_eq!(m.flake, ".");
        assert_eq!(m.profile, "default");
        assert_eq!(m.vcpus, 2);
        assert_eq!(m.mem, "1024M");
        assert_eq!(m.data_disk, "0");
        assert!(m.name.is_none());
        assert_eq!(m.schema_version, MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn parse_with_name_succeeds() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1G"
            data_disk = "0"
            name = "openclaw"
        "#;
        let m = Manifest::from_toml_str(toml).expect("parses");
        assert_eq!(m.name.as_deref(), Some("openclaw"));
    }

    #[test]
    fn parse_uses_defaults_for_omitted_fields() {
        let m = Manifest::from_toml_str("").expect("parses");
        assert_eq!(m.flake, ".");
        assert_eq!(m.profile, "default");
        assert_eq!(m.vcpus, 2);
        assert_eq!(m.mem, "1024M");
        assert_eq!(m.data_disk, "0");
    }

    #[test]
    fn schema_version_too_new_rejected() {
        let toml = format!(
            r#"
                schema_version = {}
                flake = "."
                profile = "default"
                vcpus = 2
                mem = "1024M"
            "#,
            MANIFEST_SCHEMA_VERSION + 1
        );
        let err = Manifest::from_toml_str(&toml).expect_err("rejects too-new schema");
        let msg = format!("{err:#}");
        assert!(msg.contains("schema_version"));
        assert!(msg.contains("upgrade mvmctl"));
    }

    #[test]
    fn empty_flake_rejected() {
        let toml = r#"
            flake = ""
            profile = "default"
            vcpus = 2
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects empty flake");
        assert!(format!("{err:#}").contains("flake"));
    }

    #[test]
    fn shell_meta_in_flake_rejected() {
        let toml = r#"
            flake = ". ; rm -rf /"
            profile = "default"
            vcpus = 2
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects shell meta");
        assert!(format!("{err:#}").contains("flake"));
    }

    #[test]
    fn zero_vcpus_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 0
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects 0 vcpus");
        assert!(format!("{err:#}").contains("vcpus"));
    }

    #[test]
    fn too_small_mem_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "32M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects <64M mem");
        assert!(format!("{err:#}").contains("mem"));
    }

    #[test]
    fn unparseable_mem_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "potato"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects junk mem");
        assert!(format!("{err:#}").contains("mem"));
    }

    #[test]
    fn invalid_name_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            name = "has/slash"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects bad name");
        assert!(format!("{err:#}").contains("name"));
    }

    #[test]
    fn mem_mib_and_data_disk_mib_convert() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).unwrap();
        assert_eq!(m.mem_mib().unwrap(), 1024);
        assert_eq!(m.data_disk_mib().unwrap(), 0);
    }

    #[test]
    fn serde_skips_omitted_name() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("\"name\""));
    }

    #[test]
    fn manifest_in_dir_finds_mvm_toml() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let p = manifest_in_dir(tmp.path()).unwrap().expect("found");
        assert_eq!(p.file_name().unwrap(), "mvm.toml");
    }

    #[test]
    fn manifest_in_dir_finds_mvmfile_toml() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "Mvmfile.toml", minimal_manifest_toml());
        let p = manifest_in_dir(tmp.path()).unwrap().expect("found");
        assert_eq!(p.file_name().unwrap(), "Mvmfile.toml");
    }

    #[test]
    fn manifest_in_dir_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        assert!(manifest_in_dir(tmp.path()).unwrap().is_none());
    }

    #[test]
    fn manifest_in_dir_errors_when_both_present() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        write(tmp.path(), "Mvmfile.toml", minimal_manifest_toml());
        let err = manifest_in_dir(tmp.path()).expect_err("ambiguous");
        let msg = format!("{err:#}");
        assert!(msg.contains("both") || msg.contains("pick one"));
    }

    #[test]
    fn discover_walks_up_to_manifest() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        // Mark tmp as a project boundary so the walk stops here on
        // hosts whose tmpdir parent has its own manifest.
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let nested = tmp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let p = discover_manifest_from_dir(&nested).unwrap().expect("found");
        assert_eq!(p.file_name().unwrap(), "mvm.toml");
    }

    #[test]
    fn discover_stops_at_git_boundary() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let nested = tmp.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        // No manifest anywhere in tmp; .git stops the walk at tmp.
        let result = discover_manifest_from_dir(&nested).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn resolve_config_path_accepts_file() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let path = tmp.path().join("mvm.toml");
        let resolved = resolve_manifest_config_path(&path).unwrap();
        assert_eq!(resolved, path);
    }

    #[test]
    fn resolve_config_path_accepts_directory() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let resolved = resolve_manifest_config_path(tmp.path()).unwrap();
        assert_eq!(resolved.file_name().unwrap(), "mvm.toml");
    }

    #[test]
    fn resolve_config_path_errors_on_missing() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("nope.toml");
        assert!(resolve_manifest_config_path(&missing).is_err());
    }

    #[test]
    fn resolve_config_path_errors_on_empty_directory() {
        let tmp = TempDir::new().unwrap();
        // Directory exists but contains no manifest.
        assert!(resolve_manifest_config_path(tmp.path()).is_err());
    }

    #[test]
    fn canonical_key_stable_across_relative_paths() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let direct = canonical_key_for_path(&tmp.path().join("mvm.toml")).unwrap();
        let via_dot = canonical_key_for_path(&tmp.path().join("./mvm.toml")).unwrap();
        assert_eq!(direct, via_dot);
        assert_eq!(direct.len(), 64);
    }

    #[test]
    fn canonical_key_differs_between_files() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        write(tmp1.path(), "mvm.toml", minimal_manifest_toml());
        write(tmp2.path(), "mvm.toml", minimal_manifest_toml());
        let k1 = canonical_key_for_path(&tmp1.path().join("mvm.toml")).unwrap();
        let k2 = canonical_key_for_path(&tmp2.path().join("mvm.toml")).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn read_file_parses_and_validates() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let m = Manifest::read_file(&tmp.path().join("mvm.toml")).unwrap();
        assert_eq!(m.flake, ".");
    }

    #[test]
    fn read_file_propagates_validation_error() {
        let tmp = TempDir::new().unwrap();
        write(
            tmp.path(),
            "mvm.toml",
            r#"
                flake = ""
                vcpus = 2
                mem = "1024M"
            "#,
        );
        assert!(Manifest::read_file(&tmp.path().join("mvm.toml")).is_err());
    }

    // ----- Slot path helpers -----------------------------------------

    #[test]
    fn slot_dir_has_templates_base_and_hash() {
        let s = slot_dir("abcd1234");
        assert!(s.contains("/templates/abcd1234"), "got {s}");
    }

    #[test]
    fn slot_manifest_path_is_under_slot_dir() {
        let p = slot_manifest_path("abcd1234");
        assert!(p.ends_with("/abcd1234/manifest.json"), "got {p}");
    }

    #[test]
    fn slot_dir_for_manifest_path_combines_canonical_key_and_slot_dir() {
        let tmp = TempDir::new().unwrap();
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let key = canonical_key_for_path(&tmp.path().join("mvm.toml")).unwrap();
        let dir = slot_dir_for_manifest_path(&tmp.path().join("mvm.toml")).unwrap();
        assert_eq!(dir, slot_dir(&key));
    }

    #[test]
    fn is_slot_hash_dirname_recognises_64_hex() {
        let key = "0123456789abcdef".repeat(4);
        assert_eq!(key.len(), 64);
        assert!(is_slot_hash_dirname(&key));
    }

    #[test]
    fn is_slot_hash_dirname_rejects_legacy_names() {
        assert!(!is_slot_hash_dirname("openclaw"));
        assert!(!is_slot_hash_dirname("agent-foo"));
        assert!(!is_slot_hash_dirname(""));
        // Wrong length.
        assert!(!is_slot_hash_dirname(&"a".repeat(63)));
        assert!(!is_slot_hash_dirname(&"a".repeat(65)));
        // Right length, wrong charset.
        assert!(!is_slot_hash_dirname(&"X".repeat(64)));
        assert!(!is_slot_hash_dirname(&"g".repeat(64))); // beyond hex range
    }

    // ----- Provenance ------------------------------------------------

    #[test]
    fn provenance_current_populates_required_fields() {
        let p = Provenance::current();
        assert!(!p.toolchain_version.is_empty());
        assert!(p.host_arch.contains('-'), "{}", p.host_arch);
        assert!(p.built_at.ends_with('Z'));
        assert!(p.builder_image_digest.is_none());
        assert!(p.ir_hash.is_none());
    }

    #[test]
    fn provenance_serde_roundtrip_with_optional_fields() {
        let p = Provenance {
            toolchain_version: "0.13.0".to_string(),
            builder_image_digest: Some("sha256:deadbeef".to_string()),
            host_arch: "x86_64-linux".to_string(),
            built_at: "2026-04-30T12:00:00Z".to_string(),
            ir_hash: Some("sha256:cafef00d".to_string()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn provenance_deserialises_when_optional_fields_omitted() {
        let json = r#"{
            "toolchain_version": "0.13.0",
            "host_arch": "aarch64-darwin",
            "built_at": "2026-04-30T12:00:00Z"
        }"#;
        let p: Provenance = serde_json::from_str(json).unwrap();
        assert!(p.builder_image_digest.is_none());
        assert!(p.ir_hash.is_none());
    }

    // ----- PersistedManifest -----------------------------------------

    fn fixture_persisted(tmp: &TempDir) -> PersistedManifest {
        write(tmp.path(), "mvm.toml", minimal_manifest_toml());
        let manifest = Manifest::read_file(&tmp.path().join("mvm.toml")).unwrap();
        let canonical = std::fs::canonicalize(tmp.path().join("mvm.toml")).unwrap();
        PersistedManifest::from_manifest(
            &manifest,
            &canonical,
            "firecracker",
            Provenance {
                toolchain_version: "0.13.0".to_string(),
                builder_image_digest: None,
                host_arch: "x86_64-linux".to_string(),
                built_at: "2026-04-30T12:00:00Z".to_string(),
                ir_hash: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn persisted_from_manifest_populates_numeric_sizing() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        assert_eq!(p.vcpus, 2);
        assert_eq!(p.mem_mib, 1024);
        assert_eq!(p.data_disk_mib, 0);
        assert_eq!(p.flake_ref, ".");
        assert_eq!(p.profile, "default");
        assert_eq!(p.backend, "firecracker");
        assert_eq!(p.schema_version, MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn persisted_from_manifest_sets_canonical_path_and_hash() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        let expected_hash = canonical_key_for_path(&tmp.path().join("mvm.toml")).unwrap();
        assert_eq!(p.manifest_hash, expected_hash);
        // canonicalised path is absolute and ends with mvm.toml.
        assert!(p.manifest_path.ends_with("mvm.toml"));
        assert!(std::path::Path::new(&p.manifest_path).is_absolute());
    }

    #[test]
    fn persisted_from_manifest_initialises_created_and_updated_to_built_at() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        assert_eq!(p.created_at, "2026-04-30T12:00:00Z");
        assert_eq!(p.updated_at, p.created_at);
        assert_eq!(p.provenance.built_at, p.created_at);
    }

    #[test]
    fn persisted_serde_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        let json = serde_json::to_string_pretty(&p).unwrap();
        let back: PersistedManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn persisted_skips_serialising_omitted_name() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        assert!(p.name.is_none());
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("\"name\""));
    }

    #[test]
    fn persisted_with_name_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1G"
            data_disk = "0"
            name = "openclaw"
        "#;
        write(tmp.path(), "mvm.toml", toml);
        let manifest = Manifest::read_file(&tmp.path().join("mvm.toml")).unwrap();
        let canonical = std::fs::canonicalize(tmp.path().join("mvm.toml")).unwrap();
        let p = PersistedManifest::from_manifest(
            &manifest,
            &canonical,
            "firecracker",
            Provenance::current(),
        )
        .unwrap();
        assert_eq!(p.name.as_deref(), Some("openclaw"));
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"name\":\"openclaw\""));
    }

    #[test]
    fn touch_preserves_created_at_and_advances_updated_at_and_provenance() {
        let tmp = TempDir::new().unwrap();
        let original = fixture_persisted(&tmp);
        let new_provenance = Provenance {
            toolchain_version: "0.14.0".to_string(),
            builder_image_digest: Some("sha256:newer".to_string()),
            host_arch: original.provenance.host_arch.clone(),
            built_at: "2026-05-01T08:00:00Z".to_string(),
            ir_hash: None,
        };
        let touched = original.clone().touch(new_provenance.clone());
        assert_eq!(touched.created_at, original.created_at);
        assert_eq!(touched.updated_at, "2026-05-01T08:00:00Z");
        assert_eq!(touched.provenance, new_provenance);
        assert_eq!(touched.flake_ref, original.flake_ref);
        assert_eq!(touched.manifest_hash, original.manifest_hash);
    }

    // ----- Atomic write / read --------------------------------------

    #[test]
    fn write_then_read_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        let slot = tmp.path().join("slot");
        p.write_to_slot(&slot).unwrap();
        let back = PersistedManifest::read_from_slot(&slot).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn write_creates_slot_dir_if_missing() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        let slot = tmp.path().join("nested/under/slot");
        assert!(!slot.exists());
        p.write_to_slot(&slot).unwrap();
        assert!(slot.join("manifest.json").is_file());
    }

    #[test]
    fn write_replaces_existing_manifest_atomically() {
        let tmp = TempDir::new().unwrap();
        let original = fixture_persisted(&tmp);
        let slot = tmp.path().join("slot");
        original.write_to_slot(&slot).unwrap();

        // Mutate and rewrite — second write must replace the file
        // wholesale, not append.
        let new_provenance = Provenance {
            toolchain_version: "0.14.0".to_string(),
            builder_image_digest: None,
            host_arch: original.provenance.host_arch.clone(),
            built_at: "2026-05-01T00:00:00Z".to_string(),
            ir_hash: None,
        };
        let touched = original.clone().touch(new_provenance.clone());
        touched.write_to_slot(&slot).unwrap();

        let back = PersistedManifest::read_from_slot(&slot).unwrap();
        assert_eq!(back.updated_at, "2026-05-01T00:00:00Z");
        assert_eq!(back.provenance, new_provenance);
        assert_eq!(back.created_at, original.created_at);
    }

    #[test]
    fn write_does_not_leave_tempfile_after_success() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        let slot = tmp.path().join("slot");
        p.write_to_slot(&slot).unwrap();
        // Only `manifest.json` should remain — the temp file is
        // renamed by `persist`, not deleted.
        let entries: Vec<String> = std::fs::read_dir(&slot)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(entries, vec!["manifest.json"]);
    }

    #[test]
    fn read_errors_when_manifest_missing() {
        let tmp = TempDir::new().unwrap();
        let slot = tmp.path().join("empty-slot");
        std::fs::create_dir_all(&slot).unwrap();
        assert!(PersistedManifest::read_from_slot(&slot).is_err());
    }
}
