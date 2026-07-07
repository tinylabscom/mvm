//! Shared handling for the per-VM helper binaries mvmctl spawns at runtime
//! (`mvm-hvf-supervisor`, `mvm-vz-supervisor`, `mvm-libkrun-supervisor`,
//! `mvm-bridge`, `mvm-substitution-endpoint`).
//!
//! They are separate bin targets, and `cargo run -- …` rebuilds only `mvmctl`,
//! never them — so in a source checkout each resolver's env→sibling→`target/`
//! ladder finds nothing (a missing binary) or a stale copy (an old binary):
//! after a code change the running guest silently executes the previous
//! supervisor. On the vz path that surfaces loudly (a newer
//! `ExecutionPlan`/`SupervisorConfig` trips `deny_unknown_fields`); on the hvf
//! path it boots fine and shows up only as an opaque downstream timeout. This
//! module centralizes both the staleness mtime check and the on-demand build
//! that materializes a missing helper from the checkout.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};

use crate::base::ui;

/// Modified-time of `p`, or `None` when it can't be read.
pub(crate) fn mtime_of(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// When `exe` is a source-checkout build (`<root>/target/<profile>/<bin>` with a
/// `Cargo.toml` at `<root>`), return `(<root>, "<profile>")` — the context in
/// which a per-VM helper the outer `cargo build` skipped can be materialized
/// with a nested `cargo build`. `None` for an installed binary, so an end-user's
/// mvmctl never shells out to cargo. The profile string doubles as the
/// `target/<profile>/` output dir name.
pub(crate) fn source_checkout_root_and_profile(exe: &Path) -> Option<(PathBuf, String)> {
    let profile_dir = exe.parent()?;
    let profile = profile_dir.file_name()?.to_str()?.to_owned();
    let target_dir = profile_dir.parent()?;
    if target_dir.file_name()?.to_str()? != "target" {
        return None;
    }
    let root = target_dir.parent()?;
    root.join("Cargo.toml")
        .is_file()
        .then(|| (root.to_path_buf(), profile))
}

/// A per-VM helper binary that `cargo run` does not build alongside `mvmctl`.
pub(crate) struct AuxBin {
    /// Bin/target name, e.g. `mvm-hvf-supervisor`.
    pub name: &'static str,
    /// Owning workspace package, e.g. `mvm-vm-host`.
    pub package: &'static str,
    /// Extra `cargo build` args (a `--features` pair for the libkrun bins).
    pub extra_build_args: &'static [&'static str],
}

impl AuxBin {
    /// Last-resort resolution: when the binary is missing from the usual places
    /// *and* mvmctl is running from a source checkout, build it now (the same
    /// `cargo build` a stale-hint would name) so `machine run` from a fresh
    /// checkout works instead of failing on one un-rebuilt helper. Returns
    /// `None` for an installed mvmctl — an end-user host never shells out to
    /// cargo — leaving the caller to bail with its own message.
    pub fn build_from_checkout(&self) -> Option<Result<PathBuf>> {
        let exe = std::env::current_exe().ok()?;
        let (root, profile) = source_checkout_root_and_profile(&exe)?;
        let prebuilt = root.join("target").join(&profile).join(self.name);
        if prebuilt.is_file() {
            return Some(Ok(prebuilt));
        }
        Some(self.build(&root, &profile))
    }

    /// Run `cargo build -p <package> --bin <name>` for `profile` in the checkout
    /// root and return the built binary's path. Safe to call from the running
    /// `mvmctl`: cargo releases the workspace build lock before the `run` phase,
    /// so this nested build does not deadlock the outer `cargo run`.
    fn build(&self, workspace_root: &Path, profile: &str) -> Result<PathBuf> {
        ui::info(&format!(
            "Building {} (one-time — `cargo run` builds only mvmctl)…",
            self.name
        ));
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.current_dir(workspace_root)
            .args(["build", "-p", self.package, "--bin", self.name])
            .args(self.extra_build_args);
        // The `target/<profile>/` dir name maps back to the build flag.
        match profile {
            "debug" => {}
            "release" => {
                cmd.arg("--release");
            }
            other => {
                cmd.args(["--profile", other]);
            }
        }
        let status = cmd
            .status()
            .with_context(|| format!("run cargo build for {}", self.name))?;
        if !status.success() {
            bail!("cargo build -p {} --bin {} failed", self.package, self.name);
        }
        let built = workspace_root.join("target").join(profile).join(self.name);
        if !built.is_file() {
            bail!(
                "cargo build reported success but {} is missing",
                built.display()
            );
        }
        Ok(built)
    }
}

/// `Some(hint)` naming `rebuild_cmd` when the supervisor binary predates
/// `mvmctl` (the `cargo run` skew where only `mvmctl` was rebuilt); else `None`.
/// An unknown mtime on either side yields `None` — an installed release has
/// equal-or-newer mtimes, so we never nag there, and we don't guess.
pub(crate) fn stale_aux_binary_hint(
    bin_mtime: Option<SystemTime>,
    self_mtime: Option<SystemTime>,
    rebuild_cmd: &str,
) -> Option<String> {
    let (bin, me) = (bin_mtime?, self_mtime?);
    (bin < me).then(|| {
        format!(
            "The supervisor binary is older than mvmctl and may be stale — rebuild it: {rebuild_cmd}"
        )
    })
}

/// Compare `supervisor_path`'s mtime against the running executable's and return
/// the rebuild hint when the supervisor is older. Consulted on the boot path so
/// a stale per-VM binary is self-diagnosing instead of failing cryptically.
pub(crate) fn supervisor_stale_hint(supervisor_path: &Path, rebuild_cmd: &str) -> Option<String> {
    let self_mtime = std::env::current_exe().ok().as_deref().and_then(mtime_of);
    stale_aux_binary_hint(mtime_of(supervisor_path), self_mtime, rebuild_cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn stale_aux_hint_fires_only_when_binary_predates_mvmctl() {
        let base = SystemTime::UNIX_EPOCH;
        let newer = base + Duration::from_secs(100);
        let cmd = "cargo build -p mvm-vm-host";

        // Binary older than mvmctl → hint naming the rebuild command.
        let hint = stale_aux_binary_hint(Some(base), Some(newer), cmd).expect("expected a hint");
        assert!(
            hint.contains(cmd),
            "hint must name the rebuild command: {hint}"
        );
        assert!(hint.contains("stale"));

        // At-least-as-new binary → no hint (installed release, equal mtimes).
        assert!(stale_aux_binary_hint(Some(newer), Some(base), cmd).is_none());
        assert!(stale_aux_binary_hint(Some(base), Some(base), cmd).is_none());

        // Unknown mtime on either side → no hint (don't guess).
        assert!(stale_aux_binary_hint(None, Some(newer), cmd).is_none());
        assert!(stale_aux_binary_hint(Some(base), None, cmd).is_none());
    }

    #[test]
    fn source_checkout_detected_only_under_target_with_a_manifest() {
        let root = tempfile::tempdir().expect("tempdir");
        let root = root.path();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        let rel = root.join("target").join("release");
        std::fs::create_dir_all(&rel).unwrap();

        // `<root>/target/release/mvmctl` → the checkout root + "release" profile.
        let (got_root, profile) =
            source_checkout_root_and_profile(&rel.join("mvmctl")).expect("checkout");
        assert_eq!(got_root, root);
        assert_eq!(profile, "release");

        // A custom profile dir is reported verbatim (it names the output dir).
        let custom = root.join("target").join("dist");
        std::fs::create_dir_all(&custom).unwrap();
        assert_eq!(
            source_checkout_root_and_profile(&custom.join("mvmctl"))
                .unwrap()
                .1,
            "dist"
        );

        // Installed layout (not under a `target/` dir) → None: never build.
        assert!(source_checkout_root_and_profile(Path::new("/usr/local/bin/mvmctl")).is_none());

        // Under `target/` but no manifest at the root → None (not a checkout).
        let bare = tempfile::tempdir().unwrap();
        let bare_rel = bare.path().join("target").join("debug");
        std::fs::create_dir_all(&bare_rel).unwrap();
        assert!(source_checkout_root_and_profile(&bare_rel.join("mvmctl")).is_none());
    }
}
