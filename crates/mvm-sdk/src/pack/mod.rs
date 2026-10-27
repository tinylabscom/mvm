//! Rust authoring for `mvm.pack-spec/v1`.
//!
//! A thin fluent builder over [`mvm_contract::pack_spec`]: it assembles the
//! same closed [`PackSpec`] the Python, TypeScript and Kotlin builders emit,
//! and validates it with the contract's own validator. Resolution, locking
//! and compilation are not implemented here: with the `compiler` feature the
//! shared Rust path (`mvm_compiler::pack`) is re-exported below, so a Rust
//! program authors, locks and compiles through this one module. Signing stays
//! out of the SDK.
//!
//! ```
//! use mvm_sdk::pack::{Package, PackTarget, pack};
//!
//! let spec = pack("acme/hello", "1.0.0")
//!     .target(PackTarget::Aarch64Linux)
//!     .source(".")
//!     .package("busybox")
//!     .copy("hello.txt", "/app/hello.txt")
//!     .entrypoint(["cat", "/app/hello.txt"])
//!     .resources(1, 128)
//!     .build()
//!     .expect("a valid pack");
//! assert_eq!(spec.identity.name, "acme/hello");
//! # let _ = Package::build("pkg-config");
//! ```
//!
//! Failures are structured: [`PackBuildError::code`] is the same stable
//! string every language SDK reports for the same mistake.

pub use mvm_contract::ir::PythonTool;
pub use mvm_contract::pack_spec::{
    CopyOperation, DependencyFiles, PackIdentity, PackResources, PackSource, PackSpec,
    PackSpecError, PackSpecSchema, PackTarget, PackageRequest, PackageScope,
};

/// Locked pack compilation, re-exported from the shared compiler.
///
/// `lock_pack` records what a spec resolves to against its current source
/// tree; `compile_frozen` renders only what a still-current lock describes.
/// Both, the `PackInput` they take and the `PackError` they fail with, are
/// owned by `mvm-compiler`; the SDK holds no second implementation.
///
/// Requires the `compiler` feature.
#[cfg(feature = "compiler")]
pub use mvm_compiler::pack::{LOCK_FILE, PackError, PackInput, compile_frozen, lock_pack};

/// Start a pack named `namespace/name` at a SemVer 2.0 `version`.
pub fn pack(name: impl Into<String>, version: impl Into<String>) -> PackBuilder {
    PackBuilder {
        identity: PackIdentity {
            name: name.into(),
            version: version.into(),
        },
        target: None,
        source: None,
        packages: Vec::new(),
        dependencies: Vec::new(),
        copy: Vec::new(),
        entrypoint: None,
        resources: None,
    }
}

/// A generic package request. A bare name converts to an unversioned runtime
/// package; nothing about a package implies a language runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package(PackageRequest);

impl Package {
    /// A package present in the guest.
    pub fn runtime(name: impl Into<String>) -> Self {
        Self::scoped(name, PackageScope::Runtime)
    }

    /// A package needed only while building.
    pub fn build(name: impl Into<String>) -> Self {
        Self::scoped(name, PackageScope::Build)
    }

    fn scoped(name: impl Into<String>, scope: PackageScope) -> Self {
        Self(PackageRequest {
            name: name.into(),
            version: None,
            scope,
        })
    }

    /// Request an exact version spelling rather than leaving selection to
    /// resolution.
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.0.version = Some(version.into());
        self
    }
}

impl From<&str> for Package {
    fn from(name: &str) -> Self {
        Self::runtime(name)
    }
}

impl From<String> for Package {
    fn from(name: String) -> Self {
        Self::runtime(name)
    }
}

/// Language dependency files, referenced relative to the source tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependencies(DependencyFiles);

impl Dependencies {
    /// A Python manifest and the lockfile `tool` produced from it.
    pub fn python(
        tool: PythonTool,
        manifest: impl Into<String>,
        lockfile: impl Into<String>,
    ) -> Self {
        Self(DependencyFiles::Python {
            tool,
            manifest: manifest.into(),
            lockfile: lockfile.into(),
        })
    }
}

/// Structured authoring failure. The message carries no file contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackBuildError {
    #[error("pack is missing required field `{0}`")]
    Missing(&'static str),
    #[error("{0}")]
    Invalid(#[from] PackSpecError),
}

impl PackBuildError {
    /// Stable, language-neutral failure code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing",
            Self::Invalid(error) => match error {
                PackSpecError::Identity => "identity",
                PackSpecError::Package => "package",
                PackSpecError::Path => "path",
                PackSpecError::Entrypoint => "entrypoint",
                PackSpecError::Resources => "resources",
                PackSpecError::Serialization => "serialization",
            },
        }
    }

    /// The missing field, when the failure is a missing field.
    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::Missing(field) => Some(field),
            Self::Invalid(_) => None,
        }
    }
}

/// Fluent PackSpec builder. Calls that add (`package`, `dependencies`,
/// `copy`) append in call order, which is semantic; calls that set replace.
#[derive(Debug, Clone)]
pub struct PackBuilder {
    identity: PackIdentity,
    target: Option<PackTarget>,
    source: Option<String>,
    packages: Vec<PackageRequest>,
    dependencies: Vec<DependencyFiles>,
    copy: Vec<CopyOperation>,
    entrypoint: Option<Vec<String>>,
    resources: Option<PackResources>,
}

impl PackBuilder {
    /// The guest target. Required; never inferred from the author's host.
    pub fn target(mut self, target: PackTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// The local source tree, relative to the spec's directory (`.` for the
    /// directory itself).
    pub fn source(mut self, path: impl Into<String>) -> Self {
        self.source = Some(path.into());
        self
    }

    pub fn package(mut self, package: impl Into<Package>) -> Self {
        self.packages.push(package.into().0);
        self
    }

    pub fn dependencies(mut self, dependencies: Dependencies) -> Self {
        self.dependencies.push(dependencies.0);
        self
    }

    /// Copy a source-relative file or tree to a guest-absolute destination.
    pub fn copy(mut self, source: impl Into<String>, destination: impl Into<String>) -> Self {
        self.copy.push(CopyOperation {
            source: source.into(),
            destination: destination.into(),
        });
        self
    }

    /// Literal argv; no shell splitting or evaluation.
    pub fn entrypoint<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoint = Some(argv.into_iter().map(Into::into).collect());
        self
    }

    /// Advisory CPU cores and binary MiB of memory.
    pub fn resources(mut self, cpu_cores: u16, memory_mib: u32) -> Self {
        self.resources = Some(PackResources {
            cpu_cores,
            memory_mb: memory_mib,
        });
        self
    }

    /// Assemble and validate the spec.
    pub fn build(self) -> Result<PackSpec, PackBuildError> {
        let spec = PackSpec {
            schema: PackSpecSchema::V1,
            identity: self.identity,
            target: self.target.ok_or(PackBuildError::Missing("target"))?,
            source: PackSource::Local {
                path: self.source.ok_or(PackBuildError::Missing("source"))?,
            },
            packages: self.packages,
            dependencies: self.dependencies,
            copy: self.copy,
            entrypoint: self
                .entrypoint
                .ok_or(PackBuildError::Missing("entrypoint"))?,
            resources: self.resources.ok_or(PackBuildError::Missing("resources"))?,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// [`Self::build`], then the canonical JSON every SDK emits for it.
    pub fn to_canonical_json(self) -> Result<Vec<u8>, PackBuildError> {
        Ok(self.build()?.canonical_json()?)
    }
}

#[cfg(test)]
mod tests;
