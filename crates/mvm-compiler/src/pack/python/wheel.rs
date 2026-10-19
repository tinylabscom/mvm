//! Wheel filenames and the tags a pack target's interpreter accepts.
//!
//! The accepted tags and their priority follow the CPython ordering pip uses
//! (`packaging.tags.sys_tags`), restricted to glibc manylinux platforms: a
//! pack runs on the glibc of mvm's pinned nixpkgs, never on musl, and a plain
//! `linux_*` wheel makes no portability promise at all.

use super::version::Version;
use mvm_contract::pack_spec::PackTarget;
use std::collections::HashMap;

/// Newest glibc a selected wheel may require: the glibc of the nixpkgs mvm
/// pins (nixos-25.11 ships glibc 2.40). A pack's flake follows that nixpkgs,
/// so every wheel is patched against, and runs on, exactly this glibc. Raise
/// it when the pin moves to a newer glibc.
pub const MAX_GLIBC_MINOR: u32 = 40;

/// The longest filename accepted. A wheel is fetched into a store path named
/// after it, and store path names are capped at 211 bytes.
const MAX_FILENAME_LEN: usize = 200;

/// A parsed `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WheelName {
    pub distribution: String,
    pub version: Version,
    /// The build tag's leading number and its remainder, which order builds
    /// of the same version.
    pub build: Option<(u64, String)>,
    python: Vec<String>,
    abi: Vec<String>,
    platform: Vec<String>,
}

impl WheelName {
    pub(crate) fn parse(filename: &str) -> Result<Self, String> {
        if filename.len() > MAX_FILENAME_LEN {
            return Err(format!("is longer than {MAX_FILENAME_LEN} bytes"));
        }
        if let Some(bad) = filename
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-')))
        {
            return Err(format!("contains {bad:?}"));
        }
        let stem = filename
            .strip_suffix(".whl")
            .ok_or_else(|| "does not end in .whl".to_string())?;
        let parts: Vec<&str> = stem.split('-').collect();
        let (distribution, version, build, tags) = match parts.as_slice() {
            [distribution, version, python, abi, platform] => {
                (*distribution, *version, None, [*python, *abi, *platform])
            }
            [distribution, version, build, python, abi, platform] => (
                *distribution,
                *version,
                Some(parse_build(build)?),
                [*python, *abi, *platform],
            ),
            _ => return Err("does not have five or six dash-separated fields".to_string()),
        };
        if distribution.is_empty()
            || !distribution
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        {
            return Err(format!(
                "has a malformed distribution name {distribution:?}"
            ));
        }
        let version = Version::parse(version)
            .ok_or_else(|| format!("has a malformed version {version:?}"))?;
        let [python, abi, platform] = tags.map(split_tags);
        Ok(Self {
            distribution: distribution.to_string(),
            version,
            build,
            python: python?,
            abi: abi?,
            platform: platform?,
        })
    }

    /// Every concrete tag the filename's compressed tag sets expand to.
    fn tags(&self) -> impl Iterator<Item = String> + '_ {
        self.python.iter().flat_map(move |python| {
            self.abi.iter().flat_map(move |abi| {
                self.platform
                    .iter()
                    .map(move |platform| format!("{python}-{abi}-{platform}"))
            })
        })
    }
}

fn parse_build(build: &str) -> Result<(u64, String), String> {
    let digits = build
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(build.len());
    let number = build[..digits]
        .parse()
        .map_err(|_| format!("has a build tag {build:?} that does not start with a digit"))?;
    Ok((number, build[digits..].to_string()))
}

fn split_tags(field: &str) -> Result<Vec<String>, String> {
    field
        .split('.')
        .map(|tag| {
            if tag.is_empty() || !tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                Err(format!("has a malformed tag set {field:?}"))
            } else {
                Ok(tag.to_string())
            }
        })
        .collect()
}

/// PEP 503 normalization: lowercase, runs of `-`, `_` and `.` become `-`.
pub(crate) fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut separator = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            separator = true;
            continue;
        }
        if separator && !out.is_empty() {
            out.push('-');
        }
        separator = false;
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Ranks every tag the target interpreter accepts; a lower rank is preferred.
pub(crate) struct TagPriority {
    ranks: HashMap<String, usize>,
}

impl TagPriority {
    pub(crate) fn new(python_minor: u32, target: PackTarget) -> Self {
        let platforms = platforms(target);
        let cpython = format!("cp3{python_minor}");
        let mut ordered: Vec<(String, String, String)> = Vec::new();
        for abi in [cpython.clone(), "abi3".to_string(), "none".to_string()] {
            for platform in &platforms {
                ordered.push((cpython.clone(), abi.clone(), platform.clone()));
            }
        }
        for minor in (2..python_minor).rev() {
            for platform in &platforms {
                ordered.push((format!("cp3{minor}"), "abi3".to_string(), platform.clone()));
            }
        }
        let generic = generic_python_tags(python_minor);
        for python in &generic {
            for platform in &platforms {
                ordered.push((python.clone(), "none".to_string(), platform.clone()));
            }
        }
        ordered.push((cpython, "none".to_string(), "any".to_string()));
        for python in generic {
            ordered.push((python, "none".to_string(), "any".to_string()));
        }
        let mut ranks = HashMap::with_capacity(ordered.len());
        for (rank, (python, abi, platform)) in ordered.into_iter().enumerate() {
            ranks
                .entry(format!("{python}-{abi}-{platform}"))
                .or_insert(rank);
        }
        Self { ranks }
    }

    /// The best rank among the wheel's tags, or `None` when the target
    /// accepts none of them.
    pub(crate) fn rank(&self, wheel: &WheelName) -> Option<usize> {
        wheel
            .tags()
            .filter_map(|tag| self.ranks.get(&tag).copied())
            .min()
    }
}

/// `py3NN`, `py3`, then `py3(NN-1)` down to `py30`.
fn generic_python_tags(python_minor: u32) -> Vec<String> {
    let mut tags = vec![format!("py3{python_minor}"), "py3".to_string()];
    tags.extend((0..python_minor).rev().map(|minor| format!("py3{minor}")));
    tags
}

/// manylinux platforms from the glibc ceiling down to the architecture's
/// oldest, newest first, each legacy alias right after the glibc it names.
fn platforms(target: PackTarget) -> Vec<String> {
    let (arch, oldest_minor) = match target {
        PackTarget::X86_64Linux => ("x86_64", 5),
        PackTarget::Aarch64Linux => ("aarch64", 17),
    };
    let mut platforms = Vec::new();
    for minor in (oldest_minor..=MAX_GLIBC_MINOR).rev() {
        platforms.push(format!("manylinux_2_{minor}_{arch}"));
        let legacy = match (minor, target) {
            (17, _) => Some("manylinux2014"),
            (12, PackTarget::X86_64Linux) => Some("manylinux2010"),
            (5, PackTarget::X86_64Linux) => Some("manylinux1"),
            _ => None,
        };
        if let Some(legacy) = legacy {
            platforms.push(format!("{legacy}_{arch}"));
        }
    }
    platforms
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86: PackTarget = PackTarget::X86_64Linux;
    const ARM: PackTarget = PackTarget::Aarch64Linux;

    fn rank(target: PackTarget, filename: &str) -> Option<usize> {
        let wheel = WheelName::parse(filename).unwrap_or_else(|e| panic!("{filename} {e}"));
        TagPriority::new(12, target).rank(&wheel)
    }

    fn assert_preferred(target: PackTarget, order: &[&str]) {
        let ranks: Vec<usize> = order
            .iter()
            .map(|name| rank(target, name).unwrap_or_else(|| panic!("{name} is compatible")))
            .collect();
        for (pair, names) in ranks.windows(2).zip(order.windows(2)) {
            assert!(pair[0] < pair[1], "{} before {}", names[0], names[1]);
        }
    }

    #[test]
    fn cpython_tags_rank_in_pip_order() {
        assert_preferred(
            X86,
            &[
                "x-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
                "x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
                "x-1.0-cp312-abi3-manylinux_2_28_x86_64.whl",
                "x-1.0-cp312-none-manylinux_2_28_x86_64.whl",
                "x-1.0-cp311-abi3-manylinux_2_28_x86_64.whl",
                "x-1.0-cp38-abi3-manylinux_2_28_x86_64.whl",
                "x-1.0-py312-none-manylinux_2_28_x86_64.whl",
                "x-1.0-py3-none-manylinux_2_28_x86_64.whl",
                "x-1.0-py311-none-manylinux_2_28_x86_64.whl",
                "x-1.0-cp312-none-any.whl",
                "x-1.0-py312-none-any.whl",
                "x-1.0-py3-none-any.whl",
                "x-1.0-py30-none-any.whl",
            ],
        );
    }

    #[test]
    fn compressed_tag_sets_take_their_best_member() {
        assert_eq!(
            rank(X86, "x-1.0-py2.py3-none-any.whl"),
            rank(X86, "x-1.0-py3-none-any.whl")
        );
        assert_eq!(
            rank(
                X86,
                "x-1.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
            ),
            rank(X86, "x-1.0-cp312-cp312-manylinux_2_28_x86_64.whl")
        );
    }

    #[test]
    fn legacy_manylinux_aliases_rank_with_the_glibc_they_name() {
        assert_preferred(
            X86,
            &[
                "x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
                "x-1.0-cp312-cp312-manylinux2014_x86_64.whl",
                "x-1.0-cp312-cp312-manylinux_2_16_x86_64.whl",
                "x-1.0-cp312-cp312-manylinux2010_x86_64.whl",
                "x-1.0-cp312-cp312-manylinux1_x86_64.whl",
            ],
        );
        assert!(rank(ARM, "x-1.0-cp312-cp312-manylinux2014_aarch64.whl").is_some());
        assert!(rank(ARM, "x-1.0-cp312-cp312-manylinux2010_aarch64.whl").is_none());
        assert!(rank(ARM, "x-1.0-cp312-cp312-manylinux_2_16_aarch64.whl").is_none());
    }

    #[test]
    fn the_glibc_ceiling_is_the_pinned_nixpkgs_glibc() {
        let at = format!("x-1.0-cp312-cp312-manylinux_2_{MAX_GLIBC_MINOR}_x86_64.whl");
        let above = format!(
            "x-1.0-cp312-cp312-manylinux_2_{}_x86_64.whl",
            MAX_GLIBC_MINOR + 1
        );
        assert!(rank(X86, &at).is_some());
        assert!(rank(X86, &above).is_none());
    }

    #[test]
    fn other_systems_libcs_and_architectures_are_never_accepted() {
        for name in [
            "x-1.0-cp312-cp312-musllinux_1_2_x86_64.whl",
            "x-1.0-cp312-cp312-linux_x86_64.whl",
            "x-1.0-cp312-cp312-win_amd64.whl",
            "x-1.0-cp312-cp312-macosx_11_0_arm64.whl",
            "x-1.0-cp312-cp312-manylinux_2_17_aarch64.whl",
            "x-1.0-cp313-cp313-manylinux_2_17_x86_64.whl",
            "x-1.0-cp312-cp312t-manylinux_2_17_x86_64.whl",
            "x-1.0-pp310-pypy310_pp73-manylinux_2_17_x86_64.whl",
            "x-1.0-py2-none-any.whl",
        ] {
            assert_eq!(rank(X86, name), None, "{name}");
        }
        assert!(rank(ARM, "x-1.0-cp312-cp312-manylinux_2_17_aarch64.whl").is_some());
        assert!(rank(ARM, "x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl").is_none());
    }

    #[test]
    fn filenames_parse_with_and_without_build_tags() {
        let plain = WheelName::parse("PySocks-1.7.1-py3-none-any.whl").unwrap();
        assert_eq!(plain.distribution, "PySocks");
        assert_eq!(plain.version, Version::parse("1.7.1").unwrap());
        assert_eq!(plain.build, None);
        let built = WheelName::parse("x-1.0-2b-py3-none-any.whl").unwrap();
        assert_eq!(built.build, Some((2, "b".into())));
    }

    #[test]
    fn malformed_filenames_are_refused() {
        for name in [
            "x-1.0-py3-none-any.zip",
            "x-1.0-py3-none.whl",
            "x-1.0-a-b-py3-none-any.whl",
            "x-1.0-b2-py3-none-any.whl",
            "x-1.0-py3--any.whl",
            "x-not.a.version-py3-none-any.whl",
            "x y-1.0-py3-none-any.whl",
            "x-1!0-py3-none-any.whl",
            "x-1.0-py3-none-any$.whl",
            "-1.0-py3-none-any.whl",
        ] {
            assert!(WheelName::parse(name).is_err(), "{name}");
        }
        let long = format!("{}-1.0-py3-none-any.whl", "x".repeat(MAX_FILENAME_LEN));
        assert!(WheelName::parse(&long).is_err());
    }

    #[test]
    fn names_normalize_per_pep_503() {
        assert_eq!(normalize_name("PySocks"), "pysocks");
        assert_eq!(normalize_name("charset_normalizer"), "charset-normalizer");
        assert_eq!(normalize_name("Foo.__Bar-baz"), "foo-bar-baz");
    }
}
