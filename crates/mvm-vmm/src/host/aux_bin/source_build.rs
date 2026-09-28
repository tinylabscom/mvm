//! Building a helper from the checkout the running `mvmctl` was compiled
//! from, when it is missing or older than its sources. See the parent module.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{
    AuxBin, CLI_BIN, Lookup, RebuildPlan, VerifyEnv, build_profile_of_dir, first_existing_bin,
    is_one_of, workspace_target_dirs_for,
};

/// One build of a helper from this process's own checkout, into the target
/// directory the running binary sits in, so the helper it produces is the one
/// resolution finds beside it.
pub(super) struct SourceBuild {
    plan: RebuildPlan,
    /// The helper, then each companion it spawns from beside itself.
    outputs: Vec<PathBuf>,
}

/// A helper this process has just built and signed.
pub(super) struct Built {
    pub(super) path: PathBuf,
    /// The cargo command that built it, for any error about the result.
    pub(super) command: String,
}

/// Why a helper has to be built before it is spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BuildReason {
    /// Nothing is at the path yet.
    Missing,
    /// A source it was built from has changed since, or cargo left no record
    /// of what it was built from.
    OutOfDate,
}

impl SourceBuild {
    /// The build that keeps `spec` current, when this process may run one.
    ///
    /// None when source builds are not allowed here, when an env override
    /// names the helper, when the helper is `mvmctl` itself (it is running),
    /// when the running binary does not live in this checkout's `target/`, or
    /// when a helper was supplied from outside that `target/` — an
    /// `MVM_AUX_BIN_DIR` set, say, which is somebody's deliberate choice.
    pub(super) fn plan(spec: &AuxBin, lookup: &Lookup, env: &VerifyEnv) -> Option<Self> {
        if !env.source_builds || lookup.override_path.is_some() || spec.bin == CLI_BIN {
            return None;
        }
        let root = env.workspace_root.as_ref()?;
        let binary_dir = env.binary_dir.as_ref()?;
        let checkout_targets = workspace_target_dirs_for(root);
        if !is_one_of(binary_dir, &checkout_targets) {
            return None;
        }
        if let Some(found) = first_existing_bin(spec.bin, &lookup.dirs)
            && !found
                .parent()
                .is_some_and(|dir| is_one_of(dir, &checkout_targets))
        {
            return None;
        }
        let profile = build_profile_of_dir(binary_dir)?;
        Some(Self {
            plan: RebuildPlan::for_helper(spec, root, binary_dir, profile),
            outputs: std::iter::once(spec.bin)
                .chain(spec.companions.iter().copied())
                .map(|bin| binary_dir.join(bin))
                .collect(),
        })
    }

    /// Whether the helper has to be built first. Answered from the dep-info
    /// file cargo writes beside every binary, which lists each source file of
    /// the binary and of every workspace crate it links: a helper at least as
    /// new as all of them, and as the lockfile, is taken as current. Asking
    /// cargo instead would cost a workspace-wide freshness check on every
    /// spawn, and would rebuild helpers that a differently configured cargo
    /// (the `just` recipes) had already made current.
    pub(super) fn needed(&self) -> Option<BuildReason> {
        if self.outputs.iter().any(|output| !output.is_file()) {
            return Some(BuildReason::Missing);
        }
        let current = self
            .outputs
            .iter()
            .all(|output| built_from_current_sources(output, &self.plan.root));
        (!current).then_some(BuildReason::OutOfDate)
    }

    /// Announce, build, and sign the helper. The line goes out before cargo
    /// starts, because from cold the build takes minutes.
    pub(super) fn run(self, spec: &AuxBin, env: &VerifyEnv, reason: BuildReason) -> Result<Built> {
        let command = self.plan.command_line();
        (env.notice)(&match reason {
            BuildReason::Missing => format!(
                "{bin} has not been built for this binary yet; building it from this \
                 checkout with `{command}`.",
                bin = spec.bin,
            ),
            BuildReason::OutOfDate => format!(
                "{bin} is older than its sources in this checkout; rebuilding it with \
                 `{command}`.",
                bin = spec.bin,
            ),
        });
        self.plan.run(env, &format!("Building {}", spec.bin))?;
        if let Some(absent) = self.outputs.iter().find(|output| !output.is_file()) {
            bail!(
                "`{command}` succeeded but did not produce {path}; run it yourself from {root} \
                 and check its output",
                path = absent.display(),
                root = self.plan.root.display(),
            );
        }
        let path = self
            .outputs
            .into_iter()
            .next()
            .expect("the helper is always an output");
        if let Some(entitlement) = spec.entitlement {
            env.signer.sign(&path, entitlement)?;
        }
        Ok(Built { path, command })
    }
}

/// Whether `helper` is newer than every input cargo recorded for it, and than
/// the workspace lockfile. False whenever that cannot be shown — no dep-info
/// file, an input that no longer exists — so doubt always ends in a build.
pub(super) fn built_from_current_sources(helper: &Path, workspace_root: &Path) -> bool {
    let modified = |path: &Path| std::fs::metadata(path).and_then(|meta| meta.modified());
    let Ok(built) = modified(helper) else {
        return false;
    };
    let mut dep_info = helper.as_os_str().to_os_string();
    dep_info.push(".d");
    let Ok(text) = std::fs::read_to_string(PathBuf::from(dep_info)) else {
        return false;
    };
    let mut inputs = dep_info_inputs(&text);
    if inputs.is_empty() {
        return false;
    }
    inputs.push(workspace_root.join("Cargo.lock"));
    inputs.into_iter().all(|input| {
        let input = if input.is_absolute() {
            input
        } else {
            workspace_root.join(input)
        };
        modified(&input).is_ok_and(|changed| changed <= built)
    })
}

/// The prerequisites of a Makefile-style dep-info file: every path after the
/// first `: ` of each rule, with `\ ` read as a space in a path.
pub(super) fn dep_info_inputs(text: &str) -> Vec<PathBuf> {
    let mut inputs = Vec::new();
    for line in text.lines() {
        let Some((_, prerequisites)) = line.split_once(": ") else {
            continue;
        };
        let mut current = String::new();
        let mut chars = prerequisites.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => current.extend(chars.next()),
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        inputs.push(PathBuf::from(std::mem::take(&mut current)));
                    }
                }
                c => current.push(c),
            }
        }
        if !current.is_empty() {
            inputs.push(PathBuf::from(current));
        }
    }
    inputs
}
