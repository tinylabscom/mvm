use std::collections::BTreeMap;

use anyhow::{Result, anyhow};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::pool::{PoolSpec, pool_artifacts_dir};

use super::{BackendBuildResult, BackendParams, BuilderBackend};
use crate::nix_manifest::NixManifest;
use crate::scripts::render_script;
use crate::shell_scripts;
use crate::shell_scripts::q as shell_quote;

/// Host backend: runs `nix build` directly on the host machine.
///
/// No Firecracker builder VM is needed. This is faster and avoids the networking
/// complexity of FC-based builds while still producing the same artifacts
/// (kernel + rootfs) that run inside Firecracker microVMs at runtime.
pub(crate) struct HostBackend<'a> {
    pub(crate) build_run_dir: &'a str,
    pub(crate) spec: &'a PoolSpec,
    pub(crate) timeout: u64,
    pub(crate) tenant_id: &'a str,
    pub(crate) pool_id: &'a str,
    nix_output_path: Option<String>,
    lock_hash: Option<String>,
}

impl<'a> HostBackend<'a> {
    pub(crate) fn new(params: BackendParams<'a>) -> Self {
        Self {
            build_run_dir: params.build_run_dir,
            spec: params.spec,
            timeout: params.timeout,
            tenant_id: params.tenant_id,
            pool_id: params.pool_id,
            nix_output_path: None,
            lock_hash: None,
        }
    }
}

fn resolve_build_attribute_host(
    env: &dyn BuildEnvironment,
    flake_ref: &str,
    role: &mvm_core::pool::Role,
    profile: &str,
) -> String {
    let system = if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    };

    // Read mvm-profiles.toml directly from the flake directory (no SSH needed).
    let manifest_path = format!("{}/mvm-profiles.toml", flake_ref);
    let manifest_check =
        env.shell_exec_stdout(&shell_scripts::cat_or_echo(&manifest_path, "__NOT_FOUND__"));

    if let Ok(content) = manifest_check
        && !content.contains("__NOT_FOUND__")
        && let Ok(manifest) = NixManifest::from_toml(&content)
        && manifest.resolve(role, profile).is_ok()
    {
        // Primary pattern: tenant-<role> (e.g., tenant-gateway, tenant-worker).
        // The flake exposes one build output per role; profile selects NixOS
        // modules within the flake but doesn't change the output attribute.
        let attr = format!("{}#packages.{}.tenant-{}", flake_ref, system, role);
        env.log_info(&format!("Manifest found, using attribute: {}", attr));
        return attr;
    }

    // Fallback without manifest: try tenant-<profile> (legacy convention).
    let attr = format!("{}#packages.{}.tenant-{}", flake_ref, system, profile);
    env.log_info(&format!(
        "No manifest found, using legacy attribute: {}",
        attr
    ));
    attr
}

/// The build script with every path and the attribute quoted: the attribute
/// carries the caller's flake reference, and the log path derives from ids.
fn render_build_script(timeout: impl std::fmt::Display, attr: &str, log: &str) -> Result<String> {
    let mut ctx = BTreeMap::new();
    ctx.insert("timeout", timeout.to_string());
    ctx.insert("attr", shell_quote(attr));
    ctx.insert("log", shell_quote(log));
    render_script("run_nix_build_host", &ctx)
}

/// The extraction script with the store path (read from `nix build` output)
/// and the revision directory quoted.
fn render_extract_script(out_path: &str, rev_dir: &str) -> Result<String> {
    let mut ctx = BTreeMap::new();
    ctx.insert("out_path", shell_quote(out_path));
    ctx.insert("rev_dir", shell_quote(rev_dir));
    render_script("extract_artifacts_host", &ctx)
}

impl BuilderBackend for HostBackend<'_> {
    fn prepare(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        // Verify nix is available on the host.
        env.shell_exec("command -v nix >/dev/null 2>&1")
            .map_err(|_| anyhow!("nix not found on host; install Nix to use host builder mode"))?;
        env.shell_exec(&shell_scripts::mkdir_p(self.build_run_dir))?;
        Ok(())
    }

    fn boot(&mut self, _env: &dyn BuildEnvironment) -> Result<()> {
        // No VM to boot — we run directly on the host.
        Ok(())
    }

    fn build(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        let attr = resolve_build_attribute_host(
            env,
            &self.spec.flake_ref,
            &self.spec.role,
            &self.spec.profile,
        );

        env.log_info(&format!("Running: nix build {}", attr));

        let log_path = format!("{}/nix-build.log", self.build_run_dir);

        // Compute flake lock hash for cache tracking.
        let lock_path = format!("{}/flake.lock", self.spec.flake_ref);
        self.lock_hash = env
            .shell_exec_stdout(&shell_scripts::sha256_of(&lock_path))
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());

        if let Err(build_err) =
            env.shell_exec_visible(&render_build_script(self.timeout, &attr, &log_path)?)
        {
            let log_tail = env
                .shell_exec_stdout(&shell_scripts::tail_quiet(&log_path, 50))
                .unwrap_or_default();
            let log_tail = log_tail.trim();
            if log_tail.is_empty() {
                return Err(build_err.context(format!("nix build failed for {}", attr)));
            }
            return Err(build_err.context(format!(
                "nix build failed for {}. Build output (last 50 lines):\n{}",
                attr, log_tail
            )));
        }

        let output = env.shell_exec_stdout(&shell_scripts::cat_quiet(&log_path))?;
        let out_path = output
            .lines()
            .rev()
            .find(|l| l.starts_with("/nix/store/"))
            .ok_or_else(|| anyhow!("nix build did not produce an output path"))?
            .to_string();

        env.log_info(&format!("Build output: {}", out_path));
        self.nix_output_path = Some(out_path);
        Ok(())
    }

    fn extract_artifacts(&mut self, env: &dyn BuildEnvironment) -> Result<BackendBuildResult> {
        let nix_output_path = self
            .nix_output_path
            .as_deref()
            .ok_or_else(|| anyhow!("missing nix output path before extract"))?;

        let revision_hash = nix_output_path
            .strip_prefix("/nix/store/")
            .and_then(|s| s.split('-').next())
            .unwrap_or("unknown")
            .to_string();

        let artifacts_dir = pool_artifacts_dir(self.tenant_id, self.pool_id);
        let rev_dir = format!("{}/revisions/{}", artifacts_dir, revision_hash);
        env.shell_exec(&shell_scripts::mkdir_p(&rev_dir))?;

        env.shell_exec_visible(&render_extract_script(nix_output_path, &rev_dir)?)?;

        // Best-effort sidecar emit (producer side). The dev
        // path does the same in `pipeline::dev_build`. mvmd's pool
        // builds are prod-only, so no `--impure` and no dev override
        // are passed. See `crate::builder_vm::emit_sidecar_via_passthru_query`.
        let attr = resolve_build_attribute_host(
            env,
            &self.spec.flake_ref,
            &self.spec.role,
            &self.spec.profile,
        );
        crate::builder_vm::emit_sidecar_via_passthru_query(env, &attr, &rev_dir, "", "");

        Ok(BackendBuildResult {
            revision_hash,
            lock_hash: self.lock_hash.clone(),
        })
    }

    fn teardown(&mut self, _env: &dyn BuildEnvironment) -> Result<()> {
        // Nothing to tear down — no VM, no TAP, no bridge.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: [&str; 6] = [
        "/n/PWN a b",
        "/n/PWN'; touch /tmp/PWN; '",
        "/n/PWN$(touch /tmp/PWN)",
        "/n/PWN`touch /tmp/PWN`",
        "/n/PWN\ntouch /tmp/PWN",
        "/n/PWN;rm -rf /",
    ];

    fn inert(script: &str, quoted: &[String]) {
        let mut rest = script.to_string();
        for q in quoted {
            assert!(rest.contains(q.as_str()), "{q} missing from {script}");
            rest = rest.replace(q.as_str(), "Q");
        }
        assert!(!rest.contains("PWN"), "leaks outside quotes: {rest}");
    }

    #[test]
    fn rendered_build_and_extract_scripts_keep_hostile_values_inert() {
        for v in HOSTILE {
            inert(
                &render_build_script(600, v, "/ok/log").unwrap(),
                &[shell_quote(v)],
            );
            inert(
                &render_build_script(600, "/ok#attr", v).unwrap(),
                &[shell_quote(v)],
            );
            inert(
                &render_extract_script(v, "/ok/rev").unwrap(),
                &[shell_quote(v)],
            );
            inert(
                &render_extract_script("/nix/store/ok", v).unwrap(),
                &[shell_quote(v)],
            );
        }
    }

    #[test]
    fn an_ordinary_build_script_keeps_its_command_line() {
        let script = render_build_script(600, "/f#packages.x", "/r/nix-build.log").unwrap();
        assert!(script.contains("timeout 600 nix build '/f#packages.x' --no-link --print-out-paths 2>&1 | tee '/r/nix-build.log'"), "{script}");
    }
}
