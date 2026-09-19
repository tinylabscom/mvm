//! `xtask check-runtime-overlay-version`
//!
//! Three Nix-built images carry a `VERSION` file: the verity-sealed
//! `/mvm/runtime` overlay, the SDK sidecar, and the universal initramfs. Each
//! host-side resolver (`mvm_fs::overlay`, `mvm_fs::initramfs`) **fails closed
//! on a version mismatch**: it accepts only an artifact whose `VERSION` equals
//! the running mvmctl's semver. A stale pin therefore does not warn — the
//! overlay silently never loads, and the initramfs is refused at boot.
//!
//! All three take their version from one pin, `nix/images/version.nix`. This
//! gate asserts that pin equals the workspace `[workspace.package].version`,
//! and that every image flake writing a `VERSION` binds its version to that
//! pin rather than to a literal of its own — a literal is how the initramfs
//! came to say `0.18.0` under a `0.18.0-rc.2` workspace.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// The one version pin the image flakes share.
const VERSION_PIN: &str = "nix/images/version.nix";

/// The expression every consuming flake must bind its version to.
const PIN_IMPORT: &str = "import ../version.nix";

/// Each image flake that writes a `VERSION`, with the binding it uses.
const PIN_CONSUMERS: &[(&str, &str)] = &[
    ("nix/images/runtime-overlay/flake.nix", "overlayVersion"),
    ("nix/images/initramfs/flake.nix", "initramfsVersion"),
];

pub fn run(workspace: &Path) -> Result<()> {
    let cargo = std::fs::read_to_string(workspace.join("Cargo.toml"))
        .context("reading workspace Cargo.toml")?;
    let pin = std::fs::read_to_string(workspace.join(VERSION_PIN))
        .with_context(|| format!("reading {VERSION_PIN}"))?;

    let ws_ver = parse_workspace_version(&cargo)
        .context("could not find [workspace.package] version in Cargo.toml")?;
    let pin_ver = parse_version_pin(&pin)
        .with_context(|| format!("{VERSION_PIN} must hold exactly one quoted version string"))?;

    let mut problems = Vec::new();
    if ws_ver != pin_ver {
        problems.push(format!(
            "{VERSION_PIN} pins {pin_ver}, but the workspace version is {ws_ver}. The overlay and \
             initramfs resolvers accept only an artifact whose VERSION equals the running \
             mvmctl's, so a stale pin makes every image built from this tree unusable. Set \
             {VERSION_PIN} to \"{ws_ver}\"."
        ));
    }
    for (flake_path, binding) in PIN_CONSUMERS {
        let flake = std::fs::read_to_string(workspace.join(flake_path))
            .with_context(|| format!("reading {flake_path}"))?;
        if let Some(problem) = consumer_problem(flake_path, binding, &flake) {
            problems.push(problem);
        }
    }

    if !problems.is_empty() {
        bail!(
            "check-runtime-overlay-version:\n  - {}",
            problems.join("\n  - ")
        );
    }

    eprintln!(
        "check-runtime-overlay-version: clean (overlay, SDK sidecar and initramfs pinned to \
         workspace version {ws_ver} through {VERSION_PIN})"
    );
    Ok(())
}

/// Why `flake` does not take its version from the shared pin, if it does not.
fn consumer_problem(flake_path: &str, binding: &str, flake: &str) -> Option<String> {
    match parse_binding(flake, binding) {
        None => Some(format!(
            "{flake_path} has no `{binding}` binding; it must be `{binding} = {PIN_IMPORT};`"
        )),
        Some(rhs) if rhs == PIN_IMPORT => None,
        Some(rhs) => Some(format!(
            "{flake_path} binds `{binding} = {rhs};`; it must be `{binding} = {PIN_IMPORT};` so \
             its VERSION follows the workspace version"
        )),
    }
}

/// Extract `version = "X"` from the `[workspace.package]` table. Returns
/// the first `version` key inside that section (TOML one-value-per-key).
fn parse_workspace_version(cargo_toml: &str) -> Option<String> {
    let mut in_workspace_package = false;
    for line in cargo_toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_workspace_package = t == "[workspace.package]";
            continue;
        }
        if in_workspace_package
            && let Some(rest) = t.strip_prefix("version")
            && let Some(rest) = rest.trim_start().strip_prefix('=')
        {
            return extract_first_quoted(rest);
        }
    }
    None
}

/// The version string in the pin file: its single non-comment line, which
/// must be one double-quoted string and nothing else.
fn parse_version_pin(pin: &str) -> Option<String> {
    let mut values = pin
        .lines()
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('#'));
    let line = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let inner = line.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.is_empty() && !inner.contains('"')).then(|| inner.to_string())
}

/// The right-hand side of the `name = <rhs>;` Nix binding, without the `;`.
fn parse_binding(flake: &str, name: &str) -> Option<String> {
    for line in flake.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(name)
            && let Some(rest) = rest.trim_start().strip_prefix('=')
        {
            let rhs = rest.trim();
            let rhs = rhs.split_once(';').map_or(rhs, |(value, _)| value);
            return Some(rhs.trim().to_string());
        }
    }
    None
}

/// The first double-quoted run in `s` (tolerates trailing `;`, commas, or
/// comments after the closing quote).
fn extract_first_quoted(s: &str) -> Option<String> {
    let after = s.trim_start().strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_workspace_package_version() {
        let toml = "[workspace]\nmembers = []\n\n[workspace.package]\nedition = \"2024\"\nversion = \"0.16.1\"\n\n[workspace.dependencies]\nversion = \"9.9.9\"\n";
        assert_eq!(parse_workspace_version(toml).as_deref(), Some("0.16.1"));
    }

    #[test]
    fn workspace_version_ignores_other_tables() {
        // A `version` key in `[package]` must not shadow the workspace one.
        let toml = "[package]\nversion = \"1.2.3\"\n\n[workspace.package]\nversion = \"0.16.1\"\n";
        assert_eq!(parse_workspace_version(toml).as_deref(), Some("0.16.1"));
    }

    #[test]
    fn parses_the_pin_past_its_comments() {
        let pin = "# The mvmctl version.\n#\n\"0.18.0-rc.2\"\n";
        assert_eq!(parse_version_pin(pin).as_deref(), Some("0.18.0-rc.2"));
    }

    #[test]
    fn a_pin_with_two_values_or_an_expression_is_refused() {
        assert_eq!(parse_version_pin("\"0.1.0\"\n\"0.2.0\"\n"), None);
        assert_eq!(parse_version_pin("\"0.1.0\" + \"-rc.1\"\n"), None);
        assert_eq!(parse_version_pin("# only a comment\n"), None);
        assert_eq!(parse_version_pin("\"\"\n"), None);
    }

    #[test]
    fn a_consumer_importing_the_pin_passes() {
        let flake = "  let\n      initramfsVersion = import ../version.nix;\n  in {};\n";
        assert_eq!(
            consumer_problem("flake.nix", "initramfsVersion", flake),
            None
        );
    }

    /// The shape that shipped `0.18.0` in an `0.18.0-rc.2` initramfs: a
    /// literal of the flake's own, which nothing compared with Cargo.toml.
    #[test]
    fn a_consumer_with_its_own_literal_is_refused() {
        let flake = "  let\n      initramfsVersion = \"0.18.0\";\n  in {};\n";
        let problem = consumer_problem("flake.nix", "initramfsVersion", flake)
            .expect("a literal version must be refused");
        assert!(problem.contains("\"0.18.0\""), "{problem}");
        assert!(problem.contains(PIN_IMPORT), "{problem}");
    }

    #[test]
    fn a_consumer_without_the_binding_is_refused() {
        let flake = "  let\n      version = import ../version.nix;\n  in {};\n";
        assert!(consumer_problem("flake.nix", "overlayVersion", flake).is_some());
    }

    #[test]
    fn extract_first_quoted_tolerates_trailing_junk() {
        assert_eq!(
            extract_first_quoted(" \"0.16.1\"; # comment").as_deref(),
            Some("0.16.1")
        );
        assert_eq!(extract_first_quoted("no quotes here"), None);
    }

    const OVERLAY: &str = "overlayVersion = import ../version.nix;\n";
    const INITRAMFS: &str = "initramfsVersion = import ../version.nix;\n";

    fn workspace_with(pin: &str, overlay: &str, initramfs: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace.package]\nversion = \"0.18.0-rc.2\"\n",
        )
        .expect("write Cargo.toml");
        for (path, body) in [
            (VERSION_PIN, pin),
            (PIN_CONSUMERS[0].0, overlay),
            (PIN_CONSUMERS[1].0, initramfs),
        ] {
            let file = root.join(path);
            std::fs::create_dir_all(file.parent().expect("nested path")).expect("mkdir");
            std::fs::write(file, body).expect("write fixture");
        }
        dir
    }

    #[test]
    fn a_tree_whose_pin_matches_the_workspace_is_clean() {
        let ws = workspace_with("\"0.18.0-rc.2\"\n", OVERLAY, INITRAMFS);
        run(ws.path()).expect("matching pin must pass");
    }

    #[test]
    fn a_pin_behind_the_workspace_fails() {
        let ws = workspace_with("\"0.18.0\"\n", OVERLAY, INITRAMFS);
        let err = run(ws.path()).expect_err("stale pin must fail").to_string();
        assert!(err.contains("0.18.0-rc.2"), "{err}");
    }

    #[test]
    fn an_initramfs_that_stops_using_the_pin_fails() {
        let ws = workspace_with(
            "\"0.18.0-rc.2\"\n",
            OVERLAY,
            "initramfsVersion = \"0.18.0\";\n",
        );
        let err = run(ws.path())
            .expect_err("a literal initramfs version must fail")
            .to_string();
        assert!(err.contains("nix/images/initramfs/flake.nix"), "{err}");
    }

    /// The real tree: the pin, both flakes and Cargo.toml as checked in.
    #[test]
    fn the_checked_in_tree_is_clean() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits under the workspace root");
        run(workspace).expect("the checked-in version pin must match the workspace");
    }
}
