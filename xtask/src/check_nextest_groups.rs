//! `xtask check-nextest-groups`
//!
//! cargo-nextest overrides in `.config/nextest.toml` name a package and a
//! filter expression that limits which tests run in a concurrency group. If a
//! module moves between packages or a test module is renamed, the filter can
//! silently match nothing and the cap stops applying. This lint pins every
//! override by running `cargo nextest list -E '<filter>'` and rejecting empty
//! matches or packages that no longer exist in the workspace.

use anyhow::{Context, Result, bail};
use nextest_metadata::ListCommand as NextestList;
use std::collections::HashSet;
use std::path::Path;

/// Parsed nextest override entry.
#[derive(Debug)]
struct OverrideFilter {
    profile: String,
    filter: String,
    test_group: String,
}

pub fn run(workspace: &Path) -> Result<()> {
    let config_path = workspace.join(".config").join("nextest.toml");
    if !config_path.is_file() {
        bail!("nextest config not found at {}", config_path.display());
    }

    let config_text = std::fs::read_to_string(&config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let config: toml::Value = config_text
        .parse()
        .with_context(|| format!("parsing {}", config_path.display()))?;

    let workspace_members = load_workspace_members(workspace)?;
    let overrides = extract_overrides(&config)?;

    if overrides.is_empty() {
        eprintln!("check-nextest-groups: no profile overrides found");
        return Ok(());
    }

    let mut failures = Vec::new();
    for ov in &overrides {
        if let Some(failure) = check_override(ov, &workspace_members, |filter| {
            list_matching_tests(workspace, filter)
        }) {
            failures.push(failure);
        } else {
            eprintln!(
                "check-nextest-groups: profile '{}' test-group '{}' matches at least one test",
                ov.profile, ov.test_group
            );
        }
    }

    if failures.is_empty() {
        eprintln!("check-nextest-groups: all override filters match at least one test");
        Ok(())
    } else {
        for f in &failures {
            eprintln!("check-nextest-groups: {f}");
        }
        bail!(
            "check-nextest-groups: {} nextest override filter(s) are invalid",
            failures.len()
        );
    }
}

fn check_override(
    ov: &OverrideFilter,
    workspace_members: &HashSet<String>,
    mut list: impl FnMut(&str) -> Result<usize>,
) -> Option<String> {
    if let Some(pkg) = package_in_filter(&ov.filter)
        && !workspace_members.contains(&pkg)
    {
        return Some(format!(
            "profile '{}' override for test-group '{}' references unknown package '{}'",
            ov.profile, ov.test_group, pkg
        ));
    }

    match list(&ov.filter) {
        Ok(0) => Some(format!(
            "profile '{}' override for test-group '{}' matches no tests: filter='{}'",
            ov.profile, ov.test_group, ov.filter
        )),
        Ok(_) => None,
        // `{e:#}` and not `{e}`: the interesting part of a list failure is
        // always the cause chain — the compiler diagnostic or the binary that
        // refused to enumerate — and the outer context alone names only the
        // filter, which is the one thing the reader already has.
        Err(e) => Some(format!(
            "profile '{}' override for test-group '{}' failed to list tests: {e:#}",
            ov.profile, ov.test_group
        )),
    }
}

fn load_workspace_members(workspace: &Path) -> Result<HashSet<String>> {
    let manifest = workspace.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let value: toml::Value = text
        .parse()
        .with_context(|| format!("parsing {}", manifest.display()))?;

    let members = value
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .context("workspace.members is not an array")?;

    let mut set = HashSet::new();
    for m in members {
        if let Some(s) = m.as_str() {
            let crate_toml = workspace.join(s).join("Cargo.toml");
            if crate_toml.is_file() {
                let name = package_name_from_manifest(&crate_toml)?;
                set.insert(name);
            }
        }
    }
    Ok(set)
}

fn package_name_from_manifest(path: &Path) -> Result<String> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: toml::Value = text
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;
    value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
        .with_context(|| format!("package.name missing in {}", path.display()))
}

fn extract_overrides(config: &toml::Value) -> Result<Vec<OverrideFilter>> {
    let mut overrides = Vec::new();

    if let Some(profiles) = config.get("profile")
        && let Some(table) = profiles.as_table()
    {
        for (profile_name, profile_value) in table {
            if let Some(arr) = profile_value.get("overrides").and_then(|v| v.as_array()) {
                for entry in arr {
                    let filter = entry
                        .get("filter")
                        .and_then(|f| f.as_str())
                        .context("override filter is missing or not a string")?;
                    let test_group = entry
                        .get("test-group")
                        .and_then(|g| g.as_str())
                        .context("override test-group is missing or not a string")?;
                    overrides.push(OverrideFilter {
                        profile: profile_name.clone(),
                        filter: filter.to_string(),
                        test_group: test_group.to_string(),
                    });
                }
            }
        }
    }

    Ok(overrides)
}

fn package_in_filter(filter: &str) -> Option<String> {
    let rest = filter.strip_prefix("package(")?;
    let end = rest.find(')')?;
    Some(rest[..end].to_string())
}

fn list_matching_tests(workspace: &Path, filter: &str) -> Result<usize> {
    let current_dir = workspace
        .as_os_str()
        .to_str()
        .with_context(|| format!("workspace path is not UTF-8: {}", workspace.display()))?;
    let summary = NextestList::new()
        .current_dir(current_dir)
        .add_arg("--workspace")
        .add_arg("-E")
        .add_arg(filter)
        .exec()
        .with_context(|| format!("cargo nextest list failed for filter '{filter}'"))?;
    Ok(summary.test_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_in_filter_extracts_simple_package() {
        assert_eq!(
            package_in_filter("package(mvm-vmm) and test(/foo/)"),
            Some("mvm-vmm".to_string())
        );
    }

    #[test]
    fn package_in_filter_returns_none_without_package_clause() {
        assert_eq!(package_in_filter("test(/foo/)"), None);
    }

    #[test]
    fn extract_overrides_reads_profiles_and_overrides() {
        let config: toml::Value = r#"
[test-groups]
serial = { max-threads = 1 }

[[profile.default.overrides]]
filter = 'package(mvm-core) and test(/foo/)'
test-group = "serial"

[[profile.ci.overrides]]
filter = 'package(mvm-hostd) and binary(bar)'
test-group = "serial"
"#
        .parse()
        .unwrap();

        let overrides = extract_overrides(&config).unwrap();
        assert_eq!(overrides.len(), 2);
        let by_profile: std::collections::HashMap<_, _> = overrides
            .iter()
            .map(|o| (o.profile.as_str(), o.filter.as_str()))
            .collect();
        assert_eq!(
            by_profile.get("default").copied(),
            Some("package(mvm-core) and test(/foo/)")
        );
        assert_eq!(
            by_profile.get("ci").copied(),
            Some("package(mvm-hostd) and binary(bar)")
        );
        assert!(overrides.iter().all(|o| o.test_group == "serial"));
    }

    #[test]
    fn extract_overrides_missing_filter_is_an_error() {
        let config: toml::Value = r#"
[[profile.default.overrides]]
test-group = "serial"
"#
        .parse()
        .unwrap();

        assert!(extract_overrides(&config).is_err());
    }

    #[test]
    fn load_workspace_members_finds_this_workspace() {
        let members =
            load_workspace_members(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
                .unwrap();
        assert!(members.contains("mvm-core"));
        assert!(members.contains("mvm-vmm"));
        assert!(members.contains("mvm-hostd"));
    }

    #[test]
    fn check_override_fails_for_unknown_package() {
        let members = ["mvm-core".to_string()].into_iter().collect();
        let ov = OverrideFilter {
            profile: "default".to_string(),
            filter: "package(mvm-vmm) and test(/foo/)".to_string(),
            test_group: "serial".to_string(),
        };
        let failure = check_override(&ov, &members, |_| Ok(1));
        assert!(failure.is_some());
        assert!(failure.unwrap().contains("unknown package 'mvm-vmm'"));
    }

    #[test]
    fn check_override_fails_when_filter_matches_zero_tests() {
        let members = ["mvm-core".to_string()].into_iter().collect();
        let ov = OverrideFilter {
            profile: "default".to_string(),
            filter: "package(mvm-core) and test(/foo/)".to_string(),
            test_group: "serial".to_string(),
        };
        let failure = check_override(&ov, &members, |_| Ok(0));
        assert!(failure.is_some());
        assert!(failure.unwrap().contains("matches no tests"));
    }

    #[test]
    fn check_override_succeeds_when_filter_matches_tests() {
        let members = ["mvm-core".to_string()].into_iter().collect();
        let ov = OverrideFilter {
            profile: "default".to_string(),
            filter: "package(mvm-core) and test(/foo/)".to_string(),
            test_group: "serial".to_string(),
        };
        assert!(check_override(&ov, &members, |_| Ok(3)).is_none());
    }

    #[test]
    fn check_override_fails_when_list_command_errors() {
        let members = ["mvm-core".to_string()].into_iter().collect();
        let ov = OverrideFilter {
            profile: "default".to_string(),
            filter: "package(mvm-core) and test(/foo/)".to_string(),
            test_group: "serial".to_string(),
        };
        let failure = check_override(&ov, &members, |_| Err(anyhow::anyhow!("boom")));
        assert!(failure.is_some());
        assert!(failure.unwrap().contains("failed to list tests"));
    }
}
