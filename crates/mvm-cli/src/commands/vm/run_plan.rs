//! `mvmctl run --mode plan|live` — SDK transports.
//!
//! Two transports share this module:
//!
//! - **plan** (Followup H-plan, already shipped): runs a
//!   Sandbox-shaped script with the SDK in record mode, lowers the
//!   captured recording, synthesises one `ExecutionPlan` per app
//!   and routes each through `mvm_hostd::supervisor::admit_for_run` for a
//!   dry-run admission check. **No microVM ever boots** — the value
//!   is that admission gates (signature, validity window, replay
//!   store, policy resolution) fire end-to-end without the cost of
//!   booting and tearing down a VM.
//! - **live** (Followup H-live, this module's other half): spawns
//!   the user's script with `MVM_SDK_MODE=live` and
//!   `MVM_CLI_BIN=<path-to-mvmctl>` so the SDK shells each
//!   `Sandbox` operation to existing `mvmctl up` / `proc start` /
//!   `fs write` / `down` against a real microVM. No plan
//!   synthesis here — the SDK drives plan-64 admission once per
//!   per-call shell via the wrapped verbs.
//!
//! ## How it works
//!
//! 1. The user's script is auto-exec'd on the host under
//!    `MVM_SDK_MODE=record + MVM_SDK_OUT_PATH=<tmp>` — the same
//!    spawn-and-capture dance `mvmctl compile <Sandbox-script>`
//!    uses. The SDK's atexit hook writes the recording.
//! 2. `mvm_sdk::runtime::compile_recording` lowers the recording
//!    into a `Workload`.
//! 3. For each app in the Workload, [`synthesize_plan`] is called
//!    with a `SynthesisInput` derived from the app's resources +
//!    a content-addressed placeholder image SHA. The placeholder
//!    is intentional: plan-mode is a **shape check**, not a real
//!    build, so there's no rootfs on disk to hash. The shape that
//!    flows downstream (validity window, signing, nonce, policy
//!    refs) is the same as the live path's.
//! 4. [`admit_for_run`] threads each plan through the full
//!    admission pipeline (sign → verify → window → nonce ledger).
//!    Failures surface verbatim so the user sees exactly which
//!    gate refused.
//!
//! ## What plan-mode does NOT check
//!
//! - The rootfs SHA against any on-disk artifact (no build runs).
//! - The runtime profile's backend slot (the supervisor's `launch`
//!   call is skipped entirely — admission is the only gate
//!   exercised).
//! - Bundle pin re-verify (plan-mode never sets a bundle pin).
//!
//! ## Security
//!
//! The Sandbox-script auto-exec runs *on the host* under the
//! invoking user. Same posture as `mvmctl compile <script>` — the
//! literal-only AST gate inside the language SDKs is the
//! host-side defence. Callers who don't want host execution use
//! the `@mvm.app` decorator path, which the decorator parser
//! handles statically.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use mvm_sdk::ir::{App, Workload};

use super::managed_secrets::lower_app_secrets;
use super::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};
use super::plan_builder::SynthesisInput;
use crate::commands::build::sandbox_record::{auto_exec_record_script, script_language_from_path};

use super::exec::{RunArgs, RunMode};

/// Dispatch an SDK-mode `mvmctl run` invocation. Plan and Live both
/// reach this entry now (Followup H-plan + Followup H-live);
/// `Record` is still refused at the `resolve_run_mode` layer.
pub(in crate::commands) fn dispatch_sdk_mode(mode: RunMode, args: &RunArgs) -> Result<()> {
    match mode {
        RunMode::Plan => run_plan_mode(args),
        RunMode::Live => run_live_mode(args),
        RunMode::Record => unreachable!(
            "exec::resolve_run_mode refuses RunMode::Record before reaching dispatch; this is a \
             logic bug — file an issue."
        ),
    }
}

/// Followup H-live (Plan 73): spawn the user's Sandbox-shaped
/// script with `MVM_SDK_MODE=live` + the resolved `mvmctl`
/// binary path on the env so the SDK shells each `Sandbox`
/// operation to `mvmctl up` / `proc start` / `fs write` / `down`
/// against a real microVM.
///
/// The wire shape — the env-var contract:
///
/// - `MVM_SDK_MODE=live` — branch in the SDK toggling the
///   subprocess transport on.
/// - `MVM_CLI_BIN=<absolute-path>` — the binary the SDK shells to.
///   We pass our own absolute path (resolved via
///   [`std::env::current_exe`]) so a `cargo run -- run --mode
///   live` flow finds the same `mvmctl` it invoked through.
/// - Inherited stdio + env — the SDK prints its own output;
///   nothing is captured here.
///
/// Errors: the user's script exit code propagates verbatim. We
/// surface a wrapped error only when the spawn itself fails (PATH
/// resolution, missing interpreter, etc.).
fn run_live_mode(args: &RunArgs) -> Result<()> {
    let script = extract_script_arg(args)?;
    let lang = script_language_from_path(&script).ok_or_else(|| {
        anyhow::anyhow!(
            "`mvmctl run --mode live` expected a `.py`, `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`, \
             `.mts`, or `.cts` script path, got {}.",
            script.display()
        )
    })?;

    let interpreter = crate::commands::build::sandbox_record::resolve_interpreter(lang)?;
    let mvmctl_bin = std::env::current_exe()
        .context("resolving the running mvmctl binary path for MVM_CLI_BIN")?;

    eprintln!(
        "mvmctl run --mode live: spawning {} {} (MVM_CLI_BIN={})",
        interpreter.display(),
        script.display(),
        mvmctl_bin.display(),
    );

    let mut cmd = std::process::Command::new(&interpreter);
    // Deno's default sandbox refuses fs + subprocess; the SDK's
    // live mode shells to `mvmctl`, so opt out explicitly. The
    // same opt-out lives in `auto_exec_record_script`.
    let basename = interpreter
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if basename.starts_with("deno") {
        cmd.arg("run").arg("--allow-all");
    }
    let status = cmd
        .arg(&script)
        .env("MVM_SDK_MODE", "live")
        .env("MVM_CLI_BIN", &mvmctl_bin)
        .status()
        .with_context(|| {
            format!(
                "spawning {} to run live-mode script {}",
                interpreter.display(),
                script.display()
            )
        })?;

    if !status.success() {
        anyhow::bail!(
            "live-mode script {} exited with {:?}; the SDK's subprocess transport reports each \
             failed `mvmctl` shell in its own diagnostic. Re-run the script directly to see the \
             unfiltered output.",
            script.display(),
            status.code(),
        );
    }
    Ok(())
}

fn run_plan_mode(args: &RunArgs) -> Result<()> {
    let script = extract_script_arg(args)?;
    let lang = script_language_from_path(&script).ok_or_else(|| {
        anyhow::anyhow!(
            "`mvmctl run --mode plan` expected a `.py`, `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`, \
             `.mts`, or `.cts` script path, got {}.",
            script.display()
        )
    })?;

    let workload = auto_exec_record_script(&script, lang).with_context(|| {
        format!(
            "lowering Sandbox-shaped script {} for plan-mode admission",
            script.display()
        )
    })?;

    if workload.apps.is_empty() {
        bail!(
            "Sandbox recording produced no apps to admit — the script must call \
             `Sandbox.create(...)` at least once."
        );
    }

    eprintln!(
        "mvmctl run --mode plan: workload {} has {} app(s); admitting each via mvm_hostd::supervisor::admit_for_run",
        workload.id,
        workload.apps.len()
    );

    let ledger = InMemoryNonceLedger::new();
    let clock = SystemClock;
    let mut admitted_count = 0usize;
    let mut failed_count = 0usize;

    for app in &workload.apps {
        let input = synthesis_input_for_app(&workload, app)?;
        match admit_for_run(&input, &clock, &ledger, None, None) {
            Ok(admitted) => {
                admitted_count += 1;
                println!(
                    "ADMITTED app={} plan_id={} signer={} cpus={} mem_mib={} workload={} tenant={}",
                    app.name,
                    admitted.plan_id.0,
                    admitted.signer_id,
                    admitted.plan.resources.cpus,
                    admitted.plan.resources.mem_mib,
                    admitted.plan.workload.0,
                    admitted.plan.tenant.0,
                );
            }
            Err(e) => {
                failed_count += 1;
                eprintln!("REJECTED app={} reason={:#}", app.name, e);
            }
        }
    }

    eprintln!(
        "mvmctl run --mode plan: {} admitted, {} rejected (no microVM booted)",
        admitted_count, failed_count
    );

    if failed_count > 0 {
        bail!(
            "plan-mode admission refused {} of {} app(s); see REJECTED lines above for details",
            failed_count,
            workload.apps.len()
        );
    }
    Ok(())
}

/// Pull the script path off `args.argv`. Both `--mode plan` and
/// `--mode live` consume the argv slot as a single positional:
/// the script. Anything else is an error.
fn extract_script_arg(args: &RunArgs) -> Result<PathBuf> {
    if !args.argv.is_empty() {
        if args.argv.len() > 1 {
            bail!(
                "`mvmctl run --mode plan|live` expected exactly one positional (the script \
                 path); got {} arguments: {:?}. Both SDK transport modes consume a single \
                 script — trailing argv has no meaning here.",
                args.argv.len(),
                args.argv
            );
        }
        return Ok(PathBuf::from(&args.argv[0]));
    }
    bail!(
        "`mvmctl run --mode plan|live` requires a script path. Pass a `.py`, `.ts`, or `.js` \
         script that builds a Sandbox: e.g. `mvmctl run --mode live ./hello.py`."
    )
}

/// Map an app from the Workload into a `SynthesisInput` for
/// `admit_for_run`. Plan-mode never builds a rootfs, so the
/// `image_sha256` is a deterministic placeholder derived from the
/// app's identity (`workload_id::app_name`). This is intentional:
/// plan-mode is a shape check; downstream consumers that want the
/// real artifact hash run the live path.
fn synthesis_input_for_app<'a>(workload: &'a Workload, app: &'a App) -> Result<SynthesisInput<'a>> {
    let lowered_secrets = lower_app_secrets(app);
    // `SynthesisInput` borrows `image_sha256` as `&str`; we need a
    // 64-char hex string that lives long enough. Since we can't
    // return a reference to a local in the synthesis input struct,
    // we leak the placeholder into a `Box<str>` whose lifetime is
    // bound to the call-site loop — that's why this helper takes
    // `'a` from both workload and app and returns a value owning
    // the string indirectly. To keep the borrowck happy we lean on
    // the fact that admit_for_run is fully synchronous and the
    // input is consumed before this function returns.
    //
    // The cleanest path is just to allocate a `String` and use
    // `Box::leak` once per app. Plan-mode runs once per CLI
    // invocation, so the leak is bounded by app count (typically
    // 1).
    let placeholder = placeholder_image_sha(&workload.id, &app.name);
    let leaked: &'static str = Box::leak(placeholder.into_boxed_str());

    Ok(SynthesisInput {
        vm_name: &app.name,
        tenant: None,
        backend_name: "firecracker",
        image_name: &app.name,
        image_sha256: leaked,
        image_cosign_bundle: None,
        intent: Some("code:execute"),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: lowered_secrets.secret_release,
        secrets: lowered_secrets.secrets,
        audit_event_prefix: None,
        cpus: app.resources.cpu_cores.max(1) as u32,
        mem_mib: app.resources.memory_mb.max(64) as u64,
        disk_mib: app.resources.rootfs_size_mb as u64,
        boot_timeout_secs: 60,
        exec_timeout_secs: 0,
        destroy_on_exit: true,
        bundle_pin: None,
        // Plan-mode synthesis (Followup H-plan) does not run the
        // install pipeline; it synthesizes one plan per Sandbox call
        // for dry-run admission. Followup B.3 wires deps_volume into
        // the live `mvmctl up` path only.
        deps_volume: None,
    })
}

/// SHA-256 over `workload_id::app_name` to derive a stable 64-char
/// hex placeholder image SHA for plan-mode admission. Distinct
/// apps in the same workload get distinct nonces *and* distinct
/// image SHAs, so the audit chain entries are independent. This
/// is not a real artifact hash — calling code documents the
/// caveat.
fn placeholder_image_sha(workload_id: &str, app_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workload_id.as_bytes());
    hasher.update(b"::");
    hasher.update(app_name.as_bytes());
    let bytes = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vm::exec::{RunMode, RunProfile};

    fn base_run_args() -> RunArgs {
        RunArgs {
            manifest: None,
            image: None,
            cpus: 2,
            memory: "512M".to_string(),
            profile: RunProfile::Standard,
            add_dir: Vec::new(),
            env: Vec::new(),
            timeout: 60,
            receipt: None,
            json: false,
            launch_plan: None,
            mode: Some(RunMode::Plan),
            dev: false,
            prod: false,
            dry_run: false,
            argv: Vec::new(),
        }
    }

    #[test]
    fn placeholder_image_sha_is_64_hex_chars() {
        let sha = placeholder_image_sha("wl-id", "app-1");
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn placeholder_image_sha_is_stable() {
        let a = placeholder_image_sha("wl", "app");
        let b = placeholder_image_sha("wl", "app");
        assert_eq!(a, b, "same inputs must yield same SHA");
    }

    #[test]
    fn placeholder_image_sha_differs_per_app() {
        let a = placeholder_image_sha("wl", "app1");
        let b = placeholder_image_sha("wl", "app2");
        assert_ne!(a, b, "different app names must yield different SHAs");
    }

    #[test]
    fn extract_script_arg_rejects_zero_args() {
        let args = base_run_args();
        let err = extract_script_arg(&args).expect_err("must require a script");
        assert!(err.to_string().contains("requires a script path"));
    }

    #[test]
    fn extract_script_arg_rejects_multiple_args() {
        let mut args = base_run_args();
        args.argv = vec!["a.py".to_string(), "b.py".to_string()];
        let err = extract_script_arg(&args).expect_err("must reject extra argv");
        assert!(err.to_string().contains("exactly one positional"));
    }

    #[test]
    fn extract_script_arg_accepts_one_positional() {
        let mut args = base_run_args();
        args.argv = vec!["./foo.py".to_string()];
        let p = extract_script_arg(&args).expect("one positional");
        assert_eq!(p, PathBuf::from("./foo.py"));
    }
}
