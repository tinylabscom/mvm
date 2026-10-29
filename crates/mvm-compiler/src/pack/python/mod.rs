//! Resolving a pack's `uv.lock` to the exact wheels its target installs.
//!
//! Resolution is pure: it reads the lockfile text and the spec, and decides
//! which wheel of every reached package the target interpreter takes. Nothing
//! is downloaded or built here. The result is a [`PythonEnvironment`] the
//! generated flake installs at build time, each wheel a fixed-output fetch
//! pinned by the lockfile's sha256, so the image carries the installed
//! packages and the guest needs no installer and no network.
//!
//! Only what can be decided exactly for one target is accepted. A package
//! that comes from anywhere but a registry, a marker over a variable the
//! target does not fix, a `requires-python` the interpreter does not satisfy,
//! and a package with no wheel for the target are refused by name; nothing is
//! built from an sdist.

mod marker;
mod uv_lock;
mod version;
mod wheel;

use marker::MarkerTarget;
use mvm_contract::pack_spec::{PackSpec, PackTarget};
use serde::{Deserialize, Serialize};
use uv_lock::{Package, UvLock};
use version::{SpecifierSet, Version};
use wheel::{TagPriority, WheelName, normalize_name};

pub use marker::MarkerError;
pub use wheel::MAX_GLIBC_MINOR;

/// The uv manifest and lockfile a Python dependency must name.
pub const UV_MANIFEST: &str = "pyproject.toml";
pub const UV_LOCKFILE: &str = "uv.lock";

/// The resolved environment, as recorded in the workload and written beside
/// the generated flake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonEnvironment {
    /// The nixpkgs attribute of the interpreter, such as `python312`.
    pub interpreter: String,
    /// One wheel per installed distribution, sorted by name.
    pub wheels: Vec<LockedWheel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedWheel {
    pub name: String,
    pub version: String,
    pub filename: String,
    pub url: String,
    /// Lowercase hex, without the `sha256:` prefix.
    pub sha256: String,
}

/// The CPython a pack runs its dependencies on, named by a runtime package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpreter {
    attribute: String,
    minor: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum PythonError {
    #[error(
        "Python dependencies must be uv's `{UV_MANIFEST}` and `{UV_LOCKFILE}` at the source root; got {tool} with {manifest:?} and {lockfile:?}"
    )]
    UnsupportedShape {
        tool: String,
        manifest: String,
        lockfile: String,
    },
    #[error(
        "Python dependencies need a runtime package naming the CPython minor version, such as python312"
    )]
    NoInterpreter,
    #[error("Python dependencies need exactly one interpreter package; the spec names {}", .0.join(", "))]
    MultipleInterpreters(Vec<String>),
    #[error("uv.lock is not valid TOML: {0}")]
    LockSyntax(String),
    #[error("uv.lock format version {0} is not supported; this compiler reads version 1")]
    LockVersion(u32),
    #[error("uv.lock requires-python {0:?} is not a valid version specifier")]
    RequiresPythonSyntax(String),
    #[error("uv.lock requires Python {requires:?}, which {interpreter} does not satisfy")]
    RequiresPython {
        requires: String,
        interpreter: String,
    },
    #[error(
        "uv.lock requires Python {requires:?}, which {interpreter} satisfies only for some patch releases; the pack does not pin the patch"
    )]
    RequiresPythonPatch {
        requires: String,
        interpreter: String,
    },
    #[error(
        "uv.lock has no project package with source `{{ virtual = \".\" }}` or `{{ editable = \".\" }}`"
    )]
    NoProject,
    #[error("uv.lock has more than one project package: {}", .0.join(", "))]
    MultipleProjects(Vec<String>),
    #[error("uv.lock names dependency {package}{} but does not lock it", .version.as_ref().map(|v| format!(" {v}")).unwrap_or_default())]
    MissingPackage {
        package: String,
        version: Option<String>,
    },
    #[error("uv.lock has several versions of {package} and a dependency on it does not say which")]
    AmbiguousDependency { package: String },
    #[error("uv.lock names extra {extra:?} of {package}, which it does not define")]
    MissingExtra { package: String, extra: String },
    #[error("the dependency on {package} has marker {marker:?}, and {reason}")]
    Marker {
        package: String,
        marker: String,
        reason: MarkerError,
    },
    #[error("{package} comes from {kind}; only registry packages can be installed into a pack")]
    UnsupportedSource { package: String, kind: String },
    #[error("{package} is locked at several versions for one target: {}", .versions.join(", "))]
    ConflictingVersions {
        package: String,
        versions: Vec<String>,
    },
    #[error("{package} has no locked version")]
    MissingVersion { package: String },
    #[error("{package}'s wheel {filename:?} {reason}")]
    InvalidWheel {
        package: String,
        filename: String,
        reason: String,
    },
    #[error(
        "{package} {version} has no wheel for {interpreter} on {target} (manylinux, glibc 2.{MAX_GLIBC_MINOR} or older); packages are never built from source"
    )]
    NoCompatibleWheel {
        package: String,
        version: String,
        interpreter: String,
        target: String,
    },
}

impl Interpreter {
    /// The single runtime package named `python3NN`.
    pub fn from_spec(spec: &PackSpec) -> Result<Self, PythonError> {
        let found: Vec<Self> = spec
            .packages
            .iter()
            .filter_map(|package| Self::from_attribute(&package.name))
            .collect();
        match <[Self; 1]>::try_from(found) {
            Ok([interpreter]) => Ok(interpreter),
            Err(found) if found.is_empty() => Err(PythonError::NoInterpreter),
            Err(found) => Err(PythonError::MultipleInterpreters(
                found.into_iter().map(|i| i.attribute).collect(),
            )),
        }
    }

    fn from_attribute(name: &str) -> Option<Self> {
        let digits = name.strip_prefix("python3")?;
        if digits.is_empty() || digits.len() > 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self {
            attribute: name.to_string(),
            minor: digits.parse().ok()?,
        })
    }

    fn label(&self) -> String {
        format!("CPython 3.{}", self.minor)
    }
}

/// Resolve `lock` for `interpreter` on `target`.
pub fn resolve(
    lock: &str,
    interpreter: &Interpreter,
    target: PackTarget,
) -> Result<PythonEnvironment, PythonError> {
    let lock = UvLock::parse(lock)?;
    check_requires_python(lock.requires_python.as_deref(), interpreter)?;
    let marker_target = MarkerTarget {
        python_minor: interpreter.minor,
        machine: machine(target),
    };
    let priority = TagPriority::new(interpreter.minor, target);
    let selector = Selector {
        priority: &priority,
        interpreter,
        target,
    };
    let mut wheels = lock
        .runtime_packages(marker_target)?
        .into_iter()
        .map(|package| selector.select(package))
        .collect::<Result<Vec<_>, _>>()?;
    wheels.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(PythonEnvironment {
        interpreter: interpreter.attribute.clone(),
        wheels,
    })
}

fn machine(target: PackTarget) -> &'static str {
    match target {
        PackTarget::X86_64Linux => "x86_64",
        PackTarget::Aarch64Linux => "aarch64",
    }
}

fn target_name(target: PackTarget) -> &'static str {
    match target {
        PackTarget::X86_64Linux => "x86_64-linux",
        PackTarget::Aarch64Linux => "aarch64-linux",
    }
}

/// The interpreter's patch release is whatever the pinned nixpkgs ships, so
/// `requires-python` must hold for every patch of its minor version.
fn check_requires_python(
    requires: Option<&str>,
    interpreter: &Interpreter,
) -> Result<(), PythonError> {
    let Some(requires) = requires else {
        return Ok(());
    };
    let set = SpecifierSet::parse(requires)
        .ok_or_else(|| PythonError::RequiresPythonSyntax(requires.to_string()))?;
    let lowest = set.contains(&Version::python(interpreter.minor, 0));
    let highest = set.contains(&Version::python(interpreter.minor, u64::from(u32::MAX)));
    match (lowest, highest) {
        (true, true) => Ok(()),
        (false, false) => Err(PythonError::RequiresPython {
            requires: requires.to_string(),
            interpreter: interpreter.label(),
        }),
        _ => Err(PythonError::RequiresPythonPatch {
            requires: requires.to_string(),
            interpreter: interpreter.label(),
        }),
    }
}

struct Selector<'a> {
    priority: &'a TagPriority,
    interpreter: &'a Interpreter,
    target: PackTarget,
}

impl Selector<'_> {
    /// The best wheel of `package` for the target. Every listed wheel must
    /// name this package and version; the chosen one must be an https URL
    /// pinned by sha256.
    fn select(&self, package: &Package) -> Result<LockedWheel, PythonError> {
        let version = package
            .version
            .as_deref()
            .ok_or_else(|| PythonError::MissingVersion {
                package: package.name.clone(),
            })?;
        let mut best: Option<(Candidate, &uv_lock::Wheel)> = None;
        for wheel in &package.wheels {
            let filename = wheel_filename(package, wheel)?;
            let name = self.parse(package, version, &filename)?;
            let Some(rank) = self.priority.rank(&name) else {
                continue;
            };
            let candidate = Candidate {
                rank,
                build: name.build.map(|(number, _)| number),
                filename,
            };
            if best.as_ref().is_none_or(|(b, _)| candidate.beats(b)) {
                best = Some((candidate, wheel));
            }
        }
        let (candidate, wheel) = best.ok_or_else(|| PythonError::NoCompatibleWheel {
            package: package.name.clone(),
            version: version.to_string(),
            interpreter: self.interpreter.label(),
            target: target_name(self.target).to_string(),
        })?;
        let invalid = |reason: &str| PythonError::InvalidWheel {
            package: package.name.clone(),
            filename: candidate.filename.clone(),
            reason: reason.to_string(),
        };
        let url = wheel.url.clone().unwrap_or_default();
        if !url.starts_with("https://") {
            return Err(invalid("is not fetched over https"));
        }
        let sha256 = wheel
            .hash
            .as_deref()
            .and_then(sha256_hex)
            .ok_or_else(|| invalid("has no sha256 hash"))?;
        Ok(LockedWheel {
            name: package.name.clone(),
            version: version.to_string(),
            filename: candidate.filename,
            url,
            sha256,
        })
    }

    fn parse(
        &self,
        package: &Package,
        version: &str,
        filename: &str,
    ) -> Result<WheelName, PythonError> {
        let invalid = |reason: String| PythonError::InvalidWheel {
            package: package.name.clone(),
            filename: filename.to_string(),
            reason,
        };
        let name = WheelName::parse(filename).map_err(invalid)?;
        if normalize_name(&name.distribution) != normalize_name(&package.name) {
            return Err(invalid(format!(
                "is for distribution {:?}",
                name.distribution
            )));
        }
        if Version::parse(version).as_ref() != Some(&name.version) {
            return Err(invalid(format!("is not version {version}")));
        }
        Ok(name)
    }
}

/// A compatible wheel, ordered by tag rank, then the higher build number,
/// then filename so the choice never depends on lockfile order.
struct Candidate {
    rank: usize,
    build: Option<u64>,
    filename: String,
}

impl Candidate {
    fn beats(&self, other: &Self) -> bool {
        (self.rank, std::cmp::Reverse(self.build), &self.filename)
            < (other.rank, std::cmp::Reverse(other.build), &other.filename)
    }
}

/// The last path segment of the wheel's URL, percent-decoded.
fn wheel_filename(package: &Package, wheel: &uv_lock::Wheel) -> Result<String, PythonError> {
    let url = wheel
        .url
        .as_deref()
        .ok_or_else(|| PythonError::InvalidWheel {
            package: package.name.clone(),
            filename: String::new(),
            reason: "has no URL".to_string(),
        })?;
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let segment = path.rsplit('/').next().unwrap_or(path);
    percent_decode(segment).ok_or_else(|| PythonError::InvalidWheel {
        package: package.name.clone(),
        filename: segment.to_string(),
        reason: "has a malformed URL escape".to_string(),
    })
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn sha256_hex(hash: &str) -> Option<String> {
    let hex = hash.strip_prefix("sha256:")?;
    (hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| hex.to_string())
}

#[cfg(test)]
mod tests;
