//! User-facing manifest file (`mvm.toml` or `Mvmfile.toml`) — the
//! "what to build and how to size it" primitive that drives the
//! manifest-driven template flow.
//!
//! A manifest is identified by its canonical filesystem path. The
//! registry slot for its build artifacts will live at
//! `~/.mvm/templates/<sha256(canonical_manifest_path)>/`. The
//! optional `name` field is a display label / S3 channel hint —
//! NOT the registry key.
//!
//! Schema (v1):
//! ```toml
//! # Source selector — exactly one of `flake` / `image` (both omitted
//! # defaults to the flake "."). Setting both is a parse error.
//! flake = "."             # OR: image = "alpine:3.20"
//! profile = "default"
//! vcpus = 2
//! mem = "1024M"
//! data_disk = "0"
//! name = "openclaw"       # optional, display only
//! ```
//!
//! The schema is strict: unknown keys are rejected (`deny_unknown_fields`),
//! and `image` is mutually exclusive with `flake`. Read the resolved flake
//! via [`Manifest::flake_ref`]; check the source kind via
//! [`Manifest::is_image_source`].
//!
//! Boundary: build inputs + dev sizing only. No `role` (the flake's
//! profile selects role variants), no `[network]` (runtime policy
//! lives in `mvmctl up` flags / `~/.mvm/config.toml` / mvmd tenant
//! config), no dependencies (Nix owns build deps; mvmd owns runtime
//! deps).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use mvm_contract::policy::network_policy::AiPolicy;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::naming::{validate_flake_ref, validate_template_name};
use crate::util::parse_human_size;

/// Filenames recognised as manifests, in discovery preference order.
/// `mvm.toml` is preferred; `Mvmfile.toml` is accepted so the legacy
/// `mvmctl build` flow folds into the same parser/schema. If both
/// exist in one directory the discovery layer errors.
pub const MANIFEST_FILENAMES: &[&str] = &["mvm.toml", "Mvmfile.toml"];

/// Highest manifest schema version this build understands. Additive
/// fields ride `#[serde(default)]`; bumping this signals breaking
/// changes older mvmctl versions must reject. v1 carries the `flake`/
/// `image` source selectors (mutually exclusive) and is strict
/// (`deny_unknown_fields`); there is no pre-release schema to migrate from.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Floor for `mem`. Below this Firecracker guests don't reliably
/// boot; we'd rather fail loudly at parse time than have a confusing
/// runtime error.
const MIN_MEM_MIB: u32 = 64;

fn default_schema_version() -> u32 {
    MANIFEST_SCHEMA_VERSION
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

/// Conservative validation for an `image` source selector. The full
/// OCI reference grammar is enforced downstream by the OCI client; here
/// we only reject empty/whitespace/shell-meta so a manifest value can
/// never be interpolated into a command line (the same safety intent as
/// `validate_flake_ref`).
fn validate_image_ref(image: &str) -> Result<()> {
    let img = image.trim();
    if img.is_empty() {
        return Err(anyhow!("`image` must not be empty"));
    }
    if img.chars().any(char::is_whitespace) {
        return Err(anyhow!("`image` must not contain whitespace: {image:?}"));
    }
    const SHELL_META: &[char] = &[
        ';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\\', '\'', '"',
    ];
    if let Some(c) = img.chars().find(|c| SHELL_META.contains(c)) {
        return Err(anyhow!(
            "`image` contains disallowed character {c:?}: {image:?}"
        ));
    }
    Ok(())
}

/// User-facing manifest file. One per project directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Nix flake reference (source selector). `"."` resolves to the
    /// directory the manifest lives in; any flake ref form is accepted
    /// (path, `github:owner/repo`, `git+https://…`). Mutually exclusive
    /// with [`image`](Self::image); when both are omitted the source
    /// defaults to the flake `"."`. Read the resolved value via
    /// [`flake_ref`](Self::flake_ref).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flake: Option<String>,

    /// OCI image reference (source selector), e.g. `alpine:3.20` or a
    /// `registry/repo@sha256:…` digest pin. Mutually exclusive with
    /// [`flake`](Self::flake) — setting both is a parse error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Path to a pre-built `wasm32-wasip1` module (source selector). This
    /// bypasses the Nix/OCI build path and runs the module directly under
    /// the wasm backend. Mutually exclusive with `flake` and `image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm: Option<String>,

    /// Flake package selector — picks `packages.<system>.<profile>`
    /// out of the flake's outputs.
    #[serde(default = "default_profile")]
    pub profile: String,

    /// Host-side CPU count. `vcpus` remains an accepted alias so
    /// older manifests keep parsing.
    #[serde(default = "default_vcpus", alias = "vcpus")]
    pub cpus: u8,

    /// Human-readable memory size (`512M`, `1G`, `1024`, …). Acts as
    /// the *cap* on guest memory; when [`mem_initial`](Self::mem_initial)
    /// is also set, this is the upper bound the balloon can deflate to.
    #[serde(default = "default_mem")]
    pub mem: String,

    /// Optional initial host commitment (e.g. `256M`, `1G`). When set,
    /// opts the workload into virtio-balloon: the backend attaches a
    /// balloon device pre-inflated to `mem - mem_initial`, so the host
    /// commits only this amount at boot. The reclaim controller can
    /// adjust the balloon over the VM's life. Must parse to a value
    /// strictly between zero and `mem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_initial: Option<String>,

    /// Machine-oriented network default. `false` keeps the deny-all
    /// posture; `true` requests the dev-tier preset. `[network]`
    /// narrows it further with explicit allow-hosts.
    #[serde(default)]
    pub net: bool,

    /// Optional machine-oriented host allow-list. Empty means "no
    /// narrowing beyond `net`".
    #[serde(default, skip_serializing_if = "ManifestNetwork::is_empty")]
    pub network: ManifestNetwork,

    /// Optional development-only machine hints.
    #[serde(default, skip_serializing_if = "ManifestDev::is_empty")]
    pub dev: ManifestDev,

    /// Optional workload permission set — the project's default grants.
    /// Empty means the project declares none, and each dimension then resolves
    /// its own way: an absent egress grant is deny-all, an absent CPU grant is
    /// uncapped.
    #[serde(default, skip_serializing_if = "ManifestGrants::is_empty")]
    pub grants: ManifestGrants,

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
    ///
    /// Relative paths in the `wasm` field are resolved against the manifest's
    /// parent directory before validation, so a module referenced as
    /// `target/wasm32-wasip1/release/foo.wasm` is found next to `mvm.toml`.
    pub fn read_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest at {}", path.display()))?;
        let mut manifest: Self = toml::from_str(&text).context("Failed to parse manifest TOML")?;
        if let Some(wasm) = manifest.wasm.take() {
            let wasm_path = std::path::Path::new(&wasm);
            let resolved = if wasm_path.is_absolute() {
                wasm_path.to_path_buf()
            } else {
                path.parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(wasm_path)
            };
            manifest.wasm = Some(resolved.display().to_string());
        }
        manifest.validate()?;
        Ok(manifest)
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
        // Exactly one source selector among `flake`, `image`, and `wasm`.
        let image = self.image.as_deref();
        let flake = self.flake.as_deref();
        let wasm = self.wasm.as_deref();
        match (image, flake, wasm) {
            (Some(_), None, None) => {
                validate_image_ref(image.unwrap())
                    .with_context(|| format!("invalid `image` field: {image:?}"))?;
            }
            (None, Some(_), None) => {
                let flake = self.flake_ref();
                if flake.trim().is_empty() {
                    return Err(anyhow!("manifest field `flake` must not be empty"));
                }
                validate_flake_ref(flake)
                    .with_context(|| format!("invalid `flake` field: {flake:?}"))?;
            }
            (None, None, Some(wasm)) => {
                if wasm.trim().is_empty() {
                    return Err(anyhow!("manifest field `wasm` must not be empty"));
                }
                let path = std::path::Path::new(wasm);
                if !path.is_file() {
                    return Err(anyhow!(
                        "manifest field `wasm` must point to an existing file: {wasm:?}"
                    ));
                }
            }
            (None, None, None) => {
                // Default flake source — explicit, or the default "." when omitted.
                let flake = self.flake_ref();
                if flake.trim().is_empty() {
                    return Err(anyhow!("manifest field `flake` must not be empty"));
                }
                validate_flake_ref(flake)
                    .with_context(|| format!("invalid `flake` field: {flake:?}"))?;
            }
            _ => {
                return Err(anyhow!(
                    "manifest fields `image`, `flake`, and `wasm` are mutually exclusive                      source selectors; set exactly one"
                ));
            }
        }
        if self.cpus == 0 {
            return Err(anyhow!("manifest field `cpus` must be >= 1"));
        }
        let mem = parse_human_size(&self.mem)
            .with_context(|| format!("invalid `mem` field: {:?}", self.mem))?;
        if mem < MIN_MEM_MIB {
            return Err(anyhow!(
                "manifest field `mem` must be >= {MIN_MEM_MIB} MiB (got {mem} MiB)"
            ));
        }
        if let Some(mi) = self.mem_initial.as_deref() {
            let mi_mib = parse_human_size(mi)
                .with_context(|| format!("invalid `mem_initial` field: {mi:?}"))?;
            if mi_mib == 0 {
                return Err(anyhow!(
                    "manifest field `mem_initial` must be > 0 when set; \
                     omit it to opt out of virtio-balloon"
                ));
            }
            if mi_mib >= mem {
                return Err(anyhow!(
                    "manifest field `mem_initial` ({mi_mib} MiB) must be \
                     strictly less than `mem` ({mem} MiB); the balloon needs \
                     a non-zero inflation target"
                ));
            }
        }
        let _ = parse_human_size(&self.data_disk)
            .with_context(|| format!("invalid `data_disk` field: {:?}", self.data_disk))?;
        for entry in &self.network.allow_hosts {
            parse_allow_host(entry)?;
        }
        // Two authored allow-lists are two answers to one question, and
        // whichever the enforcement path happens to read becomes the real
        // policy. Refuse the ambiguity instead of picking a winner silently.
        if !self.network.allow_hosts.is_empty() && !self.grants.allow_hosts.is_empty() {
            return Err(anyhow!(
                "manifest declares an egress allow-list in both `[network].allow_hosts` and \
                 `[grants].allow_hosts`; keep exactly one — `[grants]` is the granted form \
                 the egress gate enforces"
            ));
        }
        self.grants.to_grants()?;
        for cmd in &self.dev.init {
            if cmd.trim().is_empty() {
                return Err(anyhow!(
                    "manifest field `dev.init` must not contain empty commands"
                ));
            }
        }
        for volume in &self.dev.volumes {
            validate_volume_spec(volume)?;
        }
        if let Some(name) = self.name.as_deref() {
            validate_template_name(name)
                .with_context(|| format!("invalid `name` field: {:?}", name))?;
        }
        Ok(())
    }

    /// Resolved flake source reference: the explicit `flake` value, or
    /// the default `"."` when `flake` is omitted. Always the flake the
    /// build should use when `image` is not the selected source.
    pub fn flake_ref(&self) -> &str {
        self.flake.as_deref().unwrap_or(".")
    }

    /// True when this manifest selects an OCI image as its build source
    /// rather than a Nix flake or a wasm module.
    pub fn is_image_source(&self) -> bool {
        self.image.is_some()
    }

    /// True when this manifest selects a wasm module as its build source.
    pub fn is_wasm_source(&self) -> bool {
        self.wasm.is_some()
    }

    /// Typed machine-oriented view of the manifest. Only image-backed
    /// manifests produce one; flake-backed manifests return `None`.
    pub fn machine_workflow(&self) -> Option<ManifestMachineWorkflow> {
        Some(ManifestMachineWorkflow {
            image: self.image.clone()?,
            net: self.net,
            allow_hosts: self.network.allow_hosts.clone(),
            ai: self.network.ai.clone(),
            init: self.dev.init.clone(),
            volumes: self.dev.volumes.clone(),
            cpus: u32::from(self.cpus),
            mem: self.mem.clone(),
            mem_initial: self.mem_initial.clone(),
            // `validate` already rejected a malformed `[grants]`, and every
            // constructor runs it, so this cannot fail on a parsed manifest.
            grants: self.grants.to_grants().unwrap_or_default(),
        })
    }

    /// Memory cap in MiB, parsed from the human-readable string.
    pub fn mem_mib(&self) -> Result<u32> {
        parse_human_size(&self.mem).with_context(|| format!("invalid `mem` field: {:?}", self.mem))
    }

    /// Initial host commitment in MiB, when the workload opted into
    /// virtio-balloon. Returns `Ok(None)` when the field is unset
    /// (legacy "commit `mem` at boot" behaviour).
    pub fn mem_initial_mib(&self) -> Result<Option<u32>> {
        match self.mem_initial.as_deref() {
            Some(s) => parse_human_size(s)
                .map(Some)
                .with_context(|| format!("invalid `mem_initial` field: {s:?}")),
            None => Ok(None),
        }
    }

    /// Data disk in MiB.
    pub fn data_disk_mib(&self) -> Result<u32> {
        parse_human_size(&self.data_disk)
            .with_context(|| format!("invalid `data_disk` field: {:?}", self.data_disk))
    }
}

fn parse_allow_host(entry: &str) -> Result<crate::network_policy::HostPort> {
    if let Some((host, port)) = entry.rsplit_once(':')
        && port.chars().all(|ch| ch.is_ascii_digit())
    {
        return format!("{host}:{port}")
            .parse()
            .with_context(|| format!("invalid allow_hosts entry: {entry:?}"));
    }
    let host = entry.trim();
    if host.is_empty() {
        return Err(anyhow!("invalid allow_hosts entry: {entry:?}"));
    }
    Ok(crate::network_policy::HostPort::new(host, 443))
}

fn looks_like_volume_mode_typo(tail: &str) -> bool {
    !tail.is_empty()
        && tail.len() <= 8
        && !tail.contains('/')
        && tail.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn validate_volume_spec(spec: &str) -> Result<()> {
    let (host, rest) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("volume must be 'host:guest[:mode]', got {spec:?}"))?;
    if host.is_empty() {
        return Err(anyhow!("volume host path must not be empty: {spec:?}"));
    }
    let guest = match rest.rsplit_once(':') {
        Some((path, "ro" | "rw")) => path,
        Some((_, tail)) if looks_like_volume_mode_typo(tail) => {
            return Err(anyhow!(
                "volume mode must be 'ro' or 'rw' when present, got {tail:?} in {spec:?}"
            ));
        }
        _ => rest,
    };
    if guest.is_empty() {
        return Err(anyhow!("volume guest path must not be empty: {spec:?}"));
    }
    if !guest.starts_with('/') {
        return Err(anyhow!(
            "volume guest path must be absolute (start with '/'): {spec:?}"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestNetwork {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Optional AI egress metering and budget policy for this workload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<AiPolicy>,
}

impl ManifestNetwork {
    fn is_empty(&self) -> bool {
        self.allow_hosts.is_empty() && self.ai.is_none()
    }
}

/// The `[grants]` table: what this project's workload is permitted to consume
/// or reach, in the manifest's own human-readable spelling.
///
/// Kept separate from [`mvm_contract::grants::Grants`] because the wire type is
/// a tagged union tuned for a signed payload, and a TOML author should not have
/// to write `cpu = { unit = "share", millicores = 1500 }`. [`to_grants`] is the
/// one conversion.
///
/// [`to_grants`]: ManifestGrants::to_grants
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestGrants {
    /// CPU share in thousandths of one host core (`1500` = 1.5 cores). This is
    /// a share of host CPU *time*, not the `cpus` count the guest sees — the
    /// two are independent and a workload may hold four vCPUs bounded to half
    /// a core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_millicores: Option<u32>,
    /// Deterministic executed-instruction budget. A different unit from
    /// `cpu_millicores`, not a finer one; setting both is a parse error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_fuel: Option<u64>,
    /// Wall-clock bound in seconds. Must be positive: zero means "no time
    /// allowed", which is not expressible, and the legacy encoding it
    /// resembles reads zero as *unbounded* — the exact inversion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_secs: Option<u32>,
    /// Outbound destinations as `HOST[:PORT]`, port defaulting to 443. An
    /// entry here is what the egress gate ends up enforcing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
}

impl ManifestGrants {
    fn is_empty(&self) -> bool {
        self.cpu_millicores.is_none()
            && self.cpu_fuel.is_none()
            && self.wall_clock_secs.is_none()
            && self.allow_hosts.is_empty()
    }

    /// Convert to the typed permission set the plan carries.
    pub fn to_grants(&self) -> Result<mvm_contract::grants::Grants> {
        use mvm_contract::grants::{CpuGrant, EgressGrant, Grants, WallClockGrant};

        let cpu = match (self.cpu_millicores, self.cpu_fuel) {
            (Some(_), Some(_)) => {
                return Err(anyhow!(
                    "manifest fields `grants.cpu_millicores` and `grants.cpu_fuel` are \
                     different units, not different precisions; set exactly one"
                ));
            }
            (Some(millicores), None) => {
                if millicores == 0 {
                    return Err(anyhow!(
                        "manifest field `grants.cpu_millicores` must be > 0; omit it to leave \
                         CPU uncapped"
                    ));
                }
                Some(CpuGrant::Share { millicores })
            }
            (None, Some(instructions)) => Some(CpuGrant::Fuel { instructions }),
            (None, None) => None,
        };

        let wall_clock = match self.wall_clock_secs {
            None => None,
            Some(secs) => Some(WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(secs).ok_or_else(|| {
                    anyhow!(
                        "manifest field `grants.wall_clock_secs` must be > 0; omit it to leave \
                         the workload unbounded"
                    )
                })?,
            }),
        };

        let egress = if self.allow_hosts.is_empty() {
            None
        } else {
            Some(EgressGrant {
                allow: self
                    .allow_hosts
                    .iter()
                    .map(|entry| {
                        parse_allow_host(entry).with_context(|| {
                            format!("invalid `grants.allow_hosts` entry: {entry:?}")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
        };

        Ok(Grants {
            cpu,
            wall_clock,
            egress,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestDev {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
}

impl ManifestDev {
    fn is_empty(&self) -> bool {
        self.init.is_empty() && self.volumes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestMachineWorkflow {
    pub image: String,
    pub net: bool,
    pub allow_hosts: Vec<String>,
    pub ai: Option<AiPolicy>,
    pub init: Vec<String>,
    pub volumes: Vec<String>,
    pub cpus: u32,
    pub mem: String,
    pub mem_initial: Option<String>,
    /// The project's declared permission set, already in the typed form the
    /// signed plan carries. Every dimension may be absent.
    pub grants: mvm_contract::grants::Grants,
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

/// Registry key for an already-canonical manifest identity:
/// `sha256(identity)` as 64-char hex.
pub fn key_for_manifest_identity(identity: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(identity.as_bytes());
    hex::encode(hasher.finalize())
}

/// Canonical registry key for a manifest at `path`:
/// `sha256(canonical_absolute_path)` as 64-char hex. Resolves
/// symlinks so two access paths to the same file hash to the same
/// key.
pub fn canonical_key_for_path(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize {}", path.display()))?;
    let identity = canonical
        .as_os_str()
        .to_str()
        .ok_or_else(|| anyhow!("canonical path contains non-UTF-8: {:?}", canonical))?;
    Ok(key_for_manifest_identity(identity))
}

/// Slot directory for a given canonical-path-hash:
/// `~/.mvm/templates/<slot_hash>/`. Reuses
/// `crate::template::templates_base_dir()` so legacy and modern
/// slots share the same base.
pub fn slot_dir(slot_hash: &str) -> String {
    format!("{}/{}", crate::template::templates_base_dir(), slot_hash)
}

/// Path to a slot's persisted manifest record:
/// `<slot>/manifest.json`.
pub fn slot_manifest_path(slot_hash: &str) -> String {
    format!("{}/manifest.json", slot_dir(slot_hash))
}

/// Per-slot artifacts root: `<slot>/artifacts`. Holds all revision
/// directories under `revisions/<revision_hash>/`.
pub fn slot_artifacts_dir(slot_hash: &str) -> String {
    format!("{}/artifacts", slot_dir(slot_hash))
}

/// Container directory for revision subdirs:
/// `<slot>/artifacts/revisions`.
pub fn slot_revisions_dir(slot_hash: &str) -> String {
    format!("{}/revisions", slot_artifacts_dir(slot_hash))
}

/// Specific revision directory:
/// `<slot>/artifacts/revisions/<revision_hash>`. The kernel,
/// rootfs, fc-base.json, and revision.json live here.
pub fn slot_revision_dir(slot_hash: &str, revision_hash: &str) -> String {
    format!("{}/{}", slot_revisions_dir(slot_hash), revision_hash)
}

/// Symlink at the slot root pointing at the active revision.
/// Targets a relative path (`artifacts/revisions/<revision_hash>`)
/// so the symlink is portable across host filesystems.
pub fn slot_current_symlink(slot_hash: &str) -> String {
    format!("{}/current", slot_dir(slot_hash))
}

/// Snapshot directory inside a revision:
/// `<slot>/artifacts/revisions/<revision_hash>/snapshot`.
pub fn slot_snapshot_dir(slot_hash: &str, revision_hash: &str) -> String {
    format!("{}/snapshot", slot_revision_dir(slot_hash, revision_hash))
}

/// Combined helper: canonicalise `path`, hash it, return the slot
/// directory path. Errors if `path` can't be canonicalised.
pub fn slot_dir_for_manifest_path(path: &Path) -> Result<String> {
    let key = canonical_key_for_path(path)?;
    Ok(slot_dir(&key))
}

/// True if `name` looks like a modern slot directory name —
/// 64 lowercase hex characters. Used to distinguish hash-keyed
/// slots from legacy name-keyed slots during migration.
pub fn is_slot_hash_dirname(name: &str) -> bool {
    name.len() == 64
        && name
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Build provenance recorded alongside each slot's persisted
/// manifest. Ties the artifacts back to the build environment without
/// introducing a new signing scheme.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    /// `mvmctl` (workspace) version that wrote this slot.
    pub toolchain_version: String,
    /// SHA-256 (or similar) digest of the sealed-signed builder
    /// image used. `None` for builds done outside that pipeline.
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
/// `~/.mvm/templates/<sha256(canonical_manifest_path)>/manifest.json`.
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
    /// Initial host commitment in MiB when the source manifest opted
    /// into virtio-balloon (`mem_initial = "256M"`). `None` keeps the
    /// historical commit-mem_mib-at-boot shape. Backward-compat:
    /// missing field deserialises to `None` so older slot records
    /// keep working without a rebuild.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_initial_mib: Option<u32>,
    pub data_disk_mib: u32,

    /// Display name from the manifest (NOT the registry key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// VM backend the slot was built on. Drives the "warn on backend
    /// mismatch at boot" check. Free-form string matching
    /// `AnyBackend::name()`.
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
        let mem_initial_mib = manifest.mem_initial_mib()?;
        let data_disk_mib = manifest.data_disk_mib()?;
        let now = provenance.built_at.clone();
        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            manifest_path,
            manifest_hash,
            flake_ref: manifest.flake_ref().to_string(),
            profile: manifest.profile.clone(),
            vcpus: manifest.cpus,
            mem_mib,
            mem_initial_mib,
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
    /// change — never a half-written file.
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
    use crate::util::test_env::TestEnv;
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
        assert_eq!(m.flake_ref(), ".");
        assert_eq!(m.profile, "default");
        assert_eq!(m.cpus, 2);
        assert_eq!(m.mem, "1024M");
        assert_eq!(m.data_disk, "0");
        assert!(!m.net);
        assert!(m.network.allow_hosts.is_empty());
        assert!(m.dev.init.is_empty());
        assert!(m.dev.volumes.is_empty());
        assert!(m.name.is_none());
        assert_eq!(m.schema_version, MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn parse_network_ai_policy_round_trips() {
        let toml = r#"
            image = "oci:alpine"
            profile = "default"
            vcpus = 2
            mem = "1024M"
            data_disk = "0"
            [network]
            allow_hosts = ["api.openai.com:443"]
            [network.ai]
            metering = true
            [network.ai.budget]
            max_total_tokens = 1_000_000
        "#;
        let m = Manifest::from_toml_str(toml).expect("parses");
        let ai = m.network.ai.clone().expect("ai policy present");
        assert!(ai.metering);
        let budget = ai.budget.expect("budget present");
        assert_eq!(budget.max_total_tokens, Some(1_000_000));

        // The machine workflow projection preserves the policy.
        let workflow = m.machine_workflow().expect("machine workflow");
        assert_eq!(workflow.ai.as_ref(), Some(&ai));
    }

    #[test]
    fn unknown_field_rejected() {
        // schema-v2 is strict: an unrecognised key is a typo or a
        // newer-schema field, never silently ignored.
        let toml = r#"
            flake = "."
            vcpus = 2
            mem = "1024M"
            netwrok = "off"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects unknown key");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("netwrok") || msg.contains("unknown"),
            "msg was {msg}"
        );
    }

    #[test]
    fn image_and_flake_are_mutually_exclusive() {
        let toml = r#"
            flake = "."
            image = "alpine:3.20"
            vcpus = 2
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects both source selectors");
        let msg = format!("{err:#}");
        assert!(msg.contains("mutually exclusive"), "msg was {msg}");
    }

    #[test]
    fn image_only_parses_and_is_image_source() {
        let toml = r#"
            image = "alpine:3.20"
            cpus = 2
            mem = "1024M"
        "#;
        let m = Manifest::from_toml_str(toml).expect("image-only parses");
        assert_eq!(m.image.as_deref(), Some("alpine:3.20"));
        assert!(m.is_image_source());
        // flake_ref still resolves to the default but is not the source.
        assert_eq!(m.flake_ref(), ".");
    }

    #[test]
    fn neither_source_defaults_to_flake_dot() {
        let m = Manifest::from_toml_str("").expect("empty parses");
        assert!(m.image.is_none());
        assert!(!m.is_image_source());
        assert_eq!(m.flake_ref(), ".");
    }

    #[test]
    fn shell_meta_in_image_rejected() {
        let toml = r#"
            image = "alpine:3.20 ; rm -rf /"
            cpus = 2
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects shell meta in image");
        assert!(format!("{err:#}").contains("image"));
    }

    #[test]
    fn empty_image_rejected() {
        let toml = r#"
            image = ""
            cpus = 2
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects empty image");
        assert!(format!("{err:#}").contains("image"));
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
        assert_eq!(m.flake_ref(), ".");
        assert_eq!(m.profile, "default");
        assert_eq!(m.cpus, 2);
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
    fn zero_cpus_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            cpus = 0
            mem = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects 0 cpus");
        assert!(format!("{err:#}").contains("cpus"));
    }

    #[test]
    fn legacy_vcpus_alias_still_parses() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).expect("parses");
        assert_eq!(m.cpus, 2);
    }

    #[test]
    fn machine_fields_parse_and_project() {
        let toml = r#"
            image = "python:3.12-alpine"
            cpus = 4
            mem = "8G"
            mem_initial = "512M"
            net = true

            [network]
            allow_hosts = ["api.example.com", "db.example.com:5432"]

            [dev]
            init = ["pip install -r requirements.txt"]
            volumes = ["./src:/work:rw", "./cache:/cache"]
        "#;
        let m = Manifest::from_toml_str(toml).expect("parses");
        let workflow = m.machine_workflow().expect("image-backed machine workflow");
        assert!(m.net);
        assert_eq!(m.network.allow_hosts.len(), 2);
        assert_eq!(m.dev.init, vec!["pip install -r requirements.txt"]);
        assert_eq!(m.dev.volumes, vec!["./src:/work:rw", "./cache:/cache"]);
        assert_eq!(workflow.cpus, 4);
        assert_eq!(workflow.mem, "8G");
        assert_eq!(workflow.mem_initial.as_deref(), Some("512M"));
        assert_eq!(workflow.allow_hosts, m.network.allow_hosts);
    }

    #[test]
    fn a_grants_table_becomes_typed_workflow_grants() {
        let toml = r#"
            image = "alpine:3.20"

            [grants]
            cpu_millicores = 1500
            wall_clock_secs = 600
            allow_hosts = ["api.example.com:443", "db.internal"]
        "#;
        let workflow = Manifest::from_toml_str(toml)
            .expect("parses")
            .machine_workflow()
            .expect("image-backed machine workflow");
        assert_eq!(
            workflow.grants.cpu,
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 })
        );
        assert_eq!(
            workflow.grants.wall_clock,
            Some(mvm_contract::grants::WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(600).expect("nonzero")
            })
        );
        assert_eq!(
            workflow.grants.egress.expect("egress granted").allow,
            vec![
                crate::network_policy::HostPort::new("api.example.com", 443),
                // A bare host defaults to 443, matching `[network].allow_hosts`.
                crate::network_policy::HostPort::new("db.internal", 443),
            ]
        );
    }

    #[test]
    fn a_manifest_without_a_grants_table_grants_nothing() {
        let workflow = Manifest::from_toml_str("image = \"alpine:3.20\"")
            .expect("parses")
            .machine_workflow()
            .expect("image-backed machine workflow");
        assert_eq!(workflow.grants, mvm_contract::grants::Grants::default());
    }

    #[test]
    fn two_egress_allow_lists_are_refused_rather_than_silently_ranked() {
        // Two authored answers to one question; whichever the enforcement path
        // read would become the real policy.
        let err = Manifest::from_toml_str(
            r#"
            image = "alpine:3.20"

            [network]
            allow_hosts = ["a.example.com"]

            [grants]
            allow_hosts = ["b.example.com"]
        "#,
        )
        .expect_err("two allow-lists must not parse");
        assert!(format!("{err:#}").contains("both"), "got: {err:#}");
    }

    #[test]
    fn a_zero_wall_clock_grant_is_refused_not_read_as_unbounded() {
        // The legacy `exec_secs` encoding reads zero as *unbounded*, so a user
        // writing 0 to mean "no time allowed" would get the exact inversion.
        let err =
            Manifest::from_toml_str("image = \"alpine:3.20\"\n[grants]\nwall_clock_secs = 0\n")
                .expect_err("zero seconds must not parse");
        assert!(
            format!("{err:#}").contains("wall_clock_secs"),
            "got: {err:#}"
        );
    }

    #[test]
    fn cpu_millicores_and_cpu_fuel_are_units_not_precisions() {
        let err = Manifest::from_toml_str(
            "image = \"alpine:3.20\"\n[grants]\ncpu_millicores = 1500\ncpu_fuel = 100\n",
        )
        .expect_err("two CPU units must not parse");
        assert!(format!("{err:#}").contains("exactly one"), "got: {err:#}");
    }

    #[test]
    fn an_unknown_grants_key_is_refused() {
        let err = Manifest::from_toml_str("image = \"alpine:3.20\"\n[grants]\ncpu_limt = 1500\n")
            .expect_err("a misspelled key must not be silently dropped");
        assert!(format!("{err:#}").contains("cpu_limt"), "got: {err:#}");
    }

    #[test]
    fn machine_workflow_is_none_for_flake_manifests() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).expect("parses");
        assert!(m.machine_workflow().is_none());
    }

    #[test]
    fn invalid_allow_hosts_entry_is_rejected() {
        let toml = r#"
            image = "alpine:3.20"
            cpus = 2
            mem = "1024M"

            [network]
            allow_hosts = [":443", "db.example.com:notaport"]
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects invalid allow_hosts");
        assert!(format!("{err:#}").contains("allow_hosts"));
    }

    #[test]
    fn invalid_dev_volume_mode_is_rejected() {
        let toml = r#"
            image = "alpine:3.20"
            cpus = 2
            mem = "1024M"

            [dev]
            volumes = ["./src:/work:bogus"]
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects invalid volume mode");
        assert!(format!("{err:#}").contains("volume mode"));
    }

    #[test]
    fn dev_volume_guest_path_must_be_absolute() {
        let toml = r#"
            image = "alpine:3.20"
            cpus = 2
            mem = "1024M"

            [dev]
            volumes = ["./src:work"]
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects relative guest path");
        assert!(format!("{err:#}").contains("guest path"));
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
    fn mem_initial_absent_means_no_balloon_opt_in() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).unwrap();
        assert!(m.mem_initial.is_none());
        assert!(m.mem_initial_mib().unwrap().is_none());
    }

    #[test]
    fn mem_initial_set_parses_and_validates() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            mem_initial = "256M"
        "#;
        let m = Manifest::from_toml_str(toml).expect("parses");
        assert_eq!(m.mem_initial.as_deref(), Some("256M"));
        assert_eq!(m.mem_initial_mib().unwrap(), Some(256));
    }

    #[test]
    fn mem_initial_zero_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            mem_initial = "0"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects zero mem_initial");
        let msg = format!("{err:#}");
        assert!(msg.contains("mem_initial"), "msg was {msg}");
    }

    #[test]
    fn mem_initial_at_least_mem_rejected() {
        // mem_initial >= mem leaves no headroom for the balloon to inflate.
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            mem_initial = "1024M"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects >=mem mem_initial");
        let msg = format!("{err:#}");
        assert!(msg.contains("strictly less than"), "msg was {msg}");
    }

    #[test]
    fn mem_initial_unparseable_rejected() {
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            mem_initial = "spuds"
        "#;
        let err = Manifest::from_toml_str(toml).expect_err("rejects junk mem_initial");
        assert!(format!("{err:#}").contains("mem_initial"));
    }

    #[test]
    fn serde_skips_omitted_mem_initial() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("mem_initial"));
    }

    #[test]
    fn serde_skips_omitted_name() {
        let m = Manifest::from_toml_str(minimal_manifest_toml()).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("\"name\""));
        assert!(!json.contains("\"network\""));
        assert!(!json.contains("\"auth\""));
        assert!(!json.contains("\"dev\""));
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
    fn manifest_identity_key_hashes_non_filesystem_identities() {
        let key = key_for_manifest_identity("abc");
        assert_eq!(
            key,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let synthetic = key_for_manifest_identity("<flake-slot>/github:tinylabscom/mvm#default");
        assert_eq!(synthetic.len(), 64);
        assert!(synthetic.chars().all(|c| c.is_ascii_hexdigit()));
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
        assert_eq!(m.flake_ref(), ".");
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
    fn slot_artifact_paths_have_expected_layout() {
        let h = "abcd1234";
        let r = "rev789";
        assert!(slot_artifacts_dir(h).ends_with("/abcd1234/artifacts"));
        assert!(slot_revisions_dir(h).ends_with("/abcd1234/artifacts/revisions"));
        assert!(
            slot_revision_dir(h, r).ends_with("/abcd1234/artifacts/revisions/rev789"),
            "got {}",
            slot_revision_dir(h, r)
        );
        assert!(slot_current_symlink(h).ends_with("/abcd1234/current"));
        assert!(
            slot_snapshot_dir(h, r).ends_with("/abcd1234/artifacts/revisions/rev789/snapshot"),
            "got {}",
            slot_snapshot_dir(h, r)
        );
    }

    #[test]
    fn slot_revision_dir_is_inside_slot_revisions_dir() {
        let h = "deadbeef";
        let r = "abc123";
        let revs = slot_revisions_dir(h);
        let one = slot_revision_dir(h, r);
        assert!(one.starts_with(&revs));
    }

    #[test]
    fn slot_dir_for_manifest_path_combines_canonical_key_and_slot_dir() {
        // Both helpers resolve MVM_HOME independently. Hold the shared env
        // guard so another parallel test cannot change that process-wide
        // input between the two calls.
        let _env = TestEnv::new();
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
        // Minimal manifest fixture has no `mem_initial` set.
        assert_eq!(p.mem_initial_mib, None);
        assert_eq!(p.data_disk_mib, 0);
        assert_eq!(p.flake_ref, ".");
        assert_eq!(p.profile, "default");
        assert_eq!(p.backend, "firecracker");
        assert_eq!(p.schema_version, MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn persisted_from_manifest_carries_mem_initial_when_set() {
        let tmp = TempDir::new().unwrap();
        let toml = r#"
            flake = "."
            profile = "default"
            vcpus = 2
            mem = "1024M"
            mem_initial = "256M"
        "#;
        write(tmp.path(), "mvm.toml", toml);
        let manifest = Manifest::read_file(&tmp.path().join("mvm.toml")).unwrap();
        let canonical = std::fs::canonicalize(tmp.path().join("mvm.toml")).unwrap();
        let p = PersistedManifest::from_manifest(
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
        .unwrap();
        assert_eq!(p.mem_initial_mib, Some(256));
        // Schema-skip rule: a None mem_initial_mib must NOT serialise
        // (older verifiers don't know the field). A Some value MUST
        // serialise — verifiers need to see the balloon opt-in.
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"mem_initial_mib\":256"), "got: {json}");
    }

    #[test]
    fn persisted_manifest_serde_skips_omitted_mem_initial() {
        let tmp = TempDir::new().unwrap();
        let p = fixture_persisted(&tmp);
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            !json.contains("mem_initial_mib"),
            "field with None value must not appear in JSON: {json}"
        );
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
