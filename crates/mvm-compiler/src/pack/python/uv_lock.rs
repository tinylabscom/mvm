//! Reading a `uv.lock` and walking the project's runtime dependency graph for
//! one target.
//!
//! The walk starts at the project itself (the one package whose source is
//! `{ virtual = "." }` or `{ editable = "." }`), follows `dependencies` and
//! the optional-dependency sets named by edge `extra`s, prunes edges whose
//! marker is false for the target, and never reads `dev-dependencies`. The
//! project is not installed: the application runs from its own tree.

use super::PythonError;
use super::marker::{self, MarkerTarget};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The lockfile format revision this reader understands.
const LOCK_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub(super) struct UvLock {
    version: u32,
    #[serde(rename = "requires-python")]
    pub requires_python: Option<String>,
    #[serde(default)]
    package: Vec<Package>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Package {
    pub name: String,
    pub version: Option<String>,
    source: toml::Table,
    #[serde(default)]
    dependencies: Vec<Dependency>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: BTreeMap<String, Vec<Dependency>>,
    #[serde(default)]
    pub wheels: Vec<Wheel>,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    name: String,
    version: Option<String>,
    source: Option<toml::Table>,
    #[serde(default)]
    extra: Vec<String>,
    marker: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Wheel {
    pub url: Option<String>,
    pub hash: Option<String>,
}

/// Where a locked package comes from.
#[derive(Debug, PartialEq, Eq)]
enum Origin {
    Registry,
    /// The project being packed, at the lockfile's own directory.
    Project,
    /// Anything else, named by its source kind (`git`, `url`, `path`, ...).
    Other(String),
}

impl Package {
    fn origin(&self) -> Origin {
        let local_root =
            |key: &str| self.source.get(key).and_then(toml::Value::as_str) == Some(".");
        if self.source.len() == 1 && self.source.contains_key("registry") {
            Origin::Registry
        } else if self.source.len() == 1 && (local_root("virtual") || local_root("editable")) {
            Origin::Project
        } else {
            let kinds: Vec<&str> = self.source.keys().map(String::as_str).collect();
            Origin::Other(kinds.join(", "))
        }
    }

    fn label(&self) -> String {
        match &self.version {
            Some(version) => format!("{} {version}", self.name),
            None => self.name.clone(),
        }
    }
}

impl UvLock {
    pub(super) fn parse(text: &str) -> Result<Self, PythonError> {
        let lock: Self =
            toml::from_str(text).map_err(|e| PythonError::LockSyntax(e.to_string()))?;
        if lock.version != LOCK_VERSION {
            return Err(PythonError::LockVersion(lock.version));
        }
        Ok(lock)
    }

    /// The registry packages the project needs on `target`, each once, in
    /// lockfile order.
    pub(super) fn runtime_packages(
        &self,
        target: MarkerTarget,
    ) -> Result<Vec<&Package>, PythonError> {
        let root = self.root()?;
        let mut reached = BTreeSet::new();
        let mut expanded = BTreeSet::new();
        let mut queue = VecDeque::from([(root, None::<&str>)]);
        while let Some((index, extra)) = queue.pop_front() {
            if !expanded.insert((index, extra)) {
                continue;
            }
            for dependency in self.edges(index, extra)? {
                if !applies(dependency, target)? {
                    continue;
                }
                let next = self.resolve(dependency)?;
                reached.insert(next);
                queue.push_back((next, None));
                queue.extend(dependency.extra.iter().map(|e| (next, Some(e.as_str()))));
            }
        }
        let packages: Vec<&Package> = reached.into_iter().map(|i| &self.package[i]).collect();
        for package in &packages {
            let kind = match package.origin() {
                Origin::Registry => continue,
                Origin::Project => "the project itself".to_string(),
                Origin::Other(kind) => kind,
            };
            return Err(PythonError::UnsupportedSource {
                package: package.label(),
                kind,
            });
        }
        refuse_duplicate_names(&packages)?;
        Ok(packages)
    }

    fn root(&self) -> Result<usize, PythonError> {
        let roots: Vec<usize> = (0..self.package.len())
            .filter(|&i| self.package[i].origin() == Origin::Project)
            .collect();
        match roots.as_slice() {
            [root] => Ok(*root),
            [] => Err(PythonError::NoProject),
            _ => Err(PythonError::MultipleProjects(
                roots
                    .iter()
                    .map(|&i| self.package[i].name.clone())
                    .collect(),
            )),
        }
    }

    fn edges(&self, index: usize, extra: Option<&str>) -> Result<&[Dependency], PythonError> {
        let package = &self.package[index];
        match extra {
            None => Ok(&package.dependencies),
            Some(extra) => package
                .optional_dependencies
                .get(extra)
                .map(Vec::as_slice)
                .ok_or_else(|| PythonError::MissingExtra {
                    package: package.label(),
                    extra: extra.to_string(),
                }),
        }
    }

    /// The one package an edge names. A bare name is enough when the lock
    /// holds a single package by that name; otherwise the edge's version and
    /// source must single one out.
    fn resolve(&self, dependency: &Dependency) -> Result<usize, PythonError> {
        let candidates: Vec<usize> = (0..self.package.len())
            .filter(|&i| {
                let package = &self.package[i];
                package.name == dependency.name
                    && dependency
                        .version
                        .as_ref()
                        .is_none_or(|v| package.version.as_ref() == Some(v))
                    && dependency
                        .source
                        .as_ref()
                        .is_none_or(|s| &package.source == s)
            })
            .collect();
        match candidates.as_slice() {
            [index] => Ok(*index),
            [] => Err(PythonError::MissingPackage {
                package: dependency.name.clone(),
                version: dependency.version.clone(),
            }),
            _ => Err(PythonError::AmbiguousDependency {
                package: dependency.name.clone(),
            }),
        }
    }
}

fn applies(dependency: &Dependency, target: MarkerTarget) -> Result<bool, PythonError> {
    let Some(text) = &dependency.marker else {
        return Ok(true);
    };
    marker::evaluate(text, target).map_err(|reason| PythonError::Marker {
        package: dependency.name.clone(),
        marker: text.clone(),
        reason,
    })
}

/// Two versions of one distribution cannot share a site-packages directory.
fn refuse_duplicate_names(packages: &[&Package]) -> Result<(), PythonError> {
    let mut versions: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for package in packages {
        versions
            .entry(&package.name)
            .or_default()
            .push(package.version.clone().unwrap_or_default());
    }
    match versions
        .into_iter()
        .find(|(_, versions)| versions.len() > 1)
    {
        Some((name, versions)) => Err(PythonError::ConflictingVersions {
            package: name.to_string(),
            versions,
        }),
        None => Ok(()),
    }
}
