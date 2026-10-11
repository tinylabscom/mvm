//! `mvmctl run --mode plan|live` — SDK transports.
//!
//! Two transports share this module:
//!
//! - **plan**: runs a
//!   Sandbox-shaped script with the SDK in record mode, lowers the
//!   captured recording, synthesises one `ExecutionPlan` per app
//!   and routes each through `mvm_hostd::supervisor::admit_for_run` for a
//!   dry-run admission check. **No microVM ever boots** — the value
//!   is that admission gates (signature, validity window, replay
//!   store, policy resolution) fire end-to-end without the cost of
//!   booting and tearing down a VM.
//! - **live** (this module's other half): spawns the user's script with
//!   `MVM_SDK_MODE=live`, so the SDK drives each `Sandbox` operation
//!   in-process through `libmvm_hostlib` against a real microVM. When the
//!   library is installed beside this binary, `MVM_HOSTLIB_PATH` names it so
//!   the script drives the same build. No plan synthesis here — the library
//!   admits each launch through the client's admitted-boot path.
//!
//! ## How it works
//!
//! 1. The user's script is auto-exec'd on the host under
//!    `MVM_SDK_MODE=record + MVM_SDK_OUT_PATH=<tmp>` — the same
//!    spawn-and-capture dance `mvmctl compile <Sandbox-script>`
//!    uses. The SDK's atexit hook writes the recording.
//! 2. `mvm_sdk::runtime::compile_recording` lowers the recording
//!    into a `Workload`.
//! 3. The client plan service synthesizes each app using its resources +
//!    a content-addressed placeholder image SHA. The placeholder
//!    is intentional: plan-mode is a **shape check**, not a real
//!    build, so there's no rootfs on disk to hash. The shape that
//!    flows downstream (validity window, signing, nonce, policy
//!    refs) is the same as the live path's.
//! 4. The client threads each plan through the full
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
use std::path::{Path, PathBuf};

use crate::commands::build::sandbox_record::{
    LoadedRecording, auto_exec_record_script, script_language_from_path,
};
use mvm_client::sdk_plan::{PlanError, PlanOptions};

use super::exec::{RunArgs, RunMode};

/// Dispatch an SDK-mode `mvmctl run` invocation. Plan and Live both
/// reach this entry now; `Record` is still refused at the
/// `resolve_run_mode` layer.
pub(in crate::commands) fn dispatch_sdk_mode(
    mode: RunMode,
    args: &RunArgs,
    sdk: &super::exec::SdkTransportArgs,
) -> Result<()> {
    match mode {
        RunMode::Plan => run_plan_mode(args, sdk),
        RunMode::Live => run_live_mode(args),
        RunMode::Record => unreachable!(
            "exec::resolve_run_mode refuses RunMode::Record before reaching dispatch; this is a \
             logic bug — file an issue."
        ),
    }
}

/// Spawn the user's Sandbox-shaped script with `MVM_SDK_MODE=live`, so the
/// SDK drives each `Sandbox` operation in-process through `libmvm_hostlib`
/// against a real microVM. The script is the user's program; the SDK inside
/// it never runs `mvmctl`.
///
/// The env-var contract:
///
/// - `MVM_SDK_MODE=live` — selects the SDK's live transport.
/// - `MVM_HOSTLIB_PATH=<absolute-path>` — set only when the host library
///   sits beside this binary, as it does in an installed bundle and in a
///   cargo target directory, so the script loads the library this `mvmctl`
///   was built with. Absent otherwise, and the SDK's own lookup decides.
/// - `MVM_SDK_RUN_PROFILE=<profile>` — the explicit security profile
///   selected on this outer command. The language SDK validates it and
///   passes it to the machine it launches.
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
    let host_library = std::env::current_exe()
        .ok()
        .and_then(|exe| host_library_beside(&exe));

    match &host_library {
        Some(library) => eprintln!(
            "mvmctl run --mode live: spawning {} {} ({}={})",
            interpreter.display(),
            script.display(),
            mvm_sdk::env::MVM_HOSTLIB_PATH_ENV,
            library.display(),
        ),
        None => eprintln!(
            "mvmctl run --mode live: spawning {} {} (host library resolved by the SDK)",
            interpreter.display(),
            script.display(),
        ),
    }

    let mut cmd = crate::commands::build::sandbox_record::user_script_command(&interpreter);
    // Deno's default sandbox refuses the filesystem and native library
    // loading the SDK needs, so opt out explicitly. The same opt-out lives
    // in `auto_exec_record_script`.
    let basename = interpreter
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if basename.starts_with("deno") {
        cmd.arg("run").arg("--allow-all");
    }
    cmd.arg(&script)
        .env(mvm_sdk::env::MVM_SDK_MODE_ENV, "live")
        .env(mvm_sdk::env::MVM_SDK_RUN_PROFILE_ENV, args.profile.as_str());
    if let Some(library) = &host_library {
        cmd.env(mvm_sdk::env::MVM_HOSTLIB_PATH_ENV, library);
    }
    let status = cmd.status().with_context(|| {
        format!(
            "spawning {} to run live-mode script {}",
            interpreter.display(),
            script.display()
        )
    })?;

    if !status.success() {
        anyhow::bail!(
            "live-mode script {} exited with {:?}; the SDK reports each refused host-library \
             call as a typed error in its own diagnostic. Re-run the script directly to see the \
             unfiltered output.",
            script.display(),
            status.code(),
        );
    }
    Ok(())
}

/// The host library's file name on this platform.
const fn host_library_file_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libmvm_hostlib.dylib"
    } else {
        "libmvm_hostlib.so"
    }
}

/// The host library installed beside the binary at `exe`, when there is one.
/// The release bundle ships them side by side, and cargo writes both into
/// the same target directory.
fn host_library_beside(exe: &Path) -> Option<PathBuf> {
    let library = exe.parent()?.join(host_library_file_name());
    library.is_file().then_some(library)
}

fn run_plan_mode(args: &RunArgs, sdk: &super::exec::SdkTransportArgs) -> Result<()> {
    let script = extract_script_arg(args)?;
    let lang = script_language_from_path(&script).ok_or_else(|| {
        anyhow::anyhow!(
            "`mvmctl run --mode plan` expected a `.py`, `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`, \
             `.mts`, or `.cts` script path, got {}.",
            script.display()
        )
    })?;

    let recording = auto_exec_record_script(&script, lang).with_context(|| {
        format!(
            "lowering Sandbox-shaped script {} for plan-mode admission",
            script.display()
        )
    })?;

    eprintln!("recording sha256: {}", recording.digest_hex);
    let options = PlanOptions {
        acknowledged_divergences: sdk.ack_divergence.clone(),
        caller_commitment: args.caller_commitment.clone(),
    };
    if let Err(error) = recording.validate(&options) {
        render_validation_error(&recording, &error);
        return Err(error.into());
    }

    eprintln!(
        "mvmctl run --mode plan: workload {} has {} app(s); admitting each via mvm_hostd::supervisor::admit_for_run",
        recording.workload.id,
        recording.workload.apps.len()
    );

    let report = recording.admit_observing(&options, |app| match &app.result {
        Ok(admitted) => {
            println!(
                "ADMITTED app={} plan_id={} signer={} cpus={} mem_mib={} workload={} tenant={}",
                app.app,
                admitted.plan_id,
                admitted.signer_id,
                admitted.cpus,
                admitted.mem_mib,
                admitted.workload,
                admitted.tenant,
            );
        }
        Err(e) => {
            eprintln!("REJECTED app={} reason={:#}", app.app, e);
        }
    })?;

    let admitted_count = report.admitted_count();
    let failed_count = report.rejected_count();
    eprintln!(
        "mvmctl run --mode plan: {} admitted, {} rejected (no microVM booted)",
        admitted_count, failed_count
    );

    if failed_count > 0 {
        bail!(
            "plan-mode admission refused {} of {} app(s); see REJECTED lines above for details",
            failed_count,
            report.apps.len()
        );
    }
    Ok(())
}

/// Print evidence selected by the client's typed validation refusal.
fn render_validation_error(recording: &LoadedRecording, error: &PlanError) {
    match error {
        PlanError::EmbeddedSecrets { .. } => {
            for f in &recording.secret_findings {
                eprintln!(
                    "EMBEDDED SECRET: {} matched [{}]",
                    f.location,
                    f.rules.join(", ")
                );
            }
        }
        PlanError::Unacknowledged { findings, .. } => {
            for f in findings {
                eprintln!("UNACKNOWLEDGED divergence: {f}");
            }
        }
        PlanError::TooLarge { .. }
        | PlanError::Digest(_)
        | PlanError::Parse(_)
        | PlanError::Lower(_)
        | PlanError::NoApps
        | PlanError::Synthesis { .. } => {}
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::build::trace_secret_scan::scan_recording_for_secrets;
    use crate::commands::vm::exec::RunProfile;
    use base64::Engine;
    use mvm_client::builder::{RecordingSecretScanner as SecretsScanner, SecretFinding};
    use mvm_client::sdk_plan::{refuse_embedded_secrets, require_acknowledged};
    use mvm_sdk::runtime::{Divergence, RecordedOp, RuntimeRecording, SandboxCreate};
    use std::collections::BTreeMap;

    /// A library installed beside the binary is what a live script loads.
    #[test]
    fn the_host_library_beside_the_binary_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("mvmctl");
        std::fs::write(&exe, b"").unwrap();
        assert_eq!(host_library_beside(&exe), None, "no library, no override");
        let library = dir.path().join(host_library_file_name());
        std::fs::write(&library, b"").unwrap();
        assert_eq!(host_library_beside(&exe), Some(library));
    }

    /// A directory with the library's name is not the library.
    #[test]
    fn a_directory_named_like_the_library_is_not_used() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(host_library_file_name())).unwrap();
        assert_eq!(host_library_beside(&dir.path().join("mvmctl")), None);
    }

    // A realistic-shaped fake OpenAI key that matches the DEFAULT_RULES
    // openai_api_key regex (sk- + 48 alnum). Not a real credential.
    const FAKE_OPENAI: &str = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";

    #[test]
    fn secret_gate_passes_with_no_findings() {
        assert!(refuse_embedded_secrets(&[]).is_ok());
    }

    #[test]
    fn secret_gate_refuses_any_finding() {
        let findings = vec![SecretFinding {
            location: "create env[AWS]".to_string(),
            rules: vec!["aws_access_key_id".to_string()],
        }];
        let err = refuse_embedded_secrets(&findings).unwrap_err();
        assert!(err.to_string().contains("SecretRef"));
    }

    #[test]
    fn secret_gate_is_not_acknowledgeable() {
        // Unlike divergence findings, there is no --ack escape hatch for
        // embedded secrets — the message must direct to SecretRef only.
        let findings = vec![SecretFinding {
            location: "op#0 file /app/.env".to_string(),
            rules: vec!["openai_api_key".to_string()],
        }];
        let msg = refuse_embedded_secrets(&findings).unwrap_err().to_string();
        assert!(
            !msg.contains("--ack"),
            "secret refusal must not offer an ack escape hatch"
        );
    }

    #[test]
    fn scan_then_refuse_composition_rejects_embedded_secret() {
        // End-to-end gate composition: build a RuntimeRecording carrying a
        // raw secret, run the scan, feed the findings into refuse_embedded_secrets,
        // and assert we get a hard refusal.
        let body = format!("OPENAI_API_KEY={FAKE_OPENAI}\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());

        let recording = RuntimeRecording {
            workload_id: "wl".to_string(),
            create: SandboxCreate {
                template: Some("minimal".to_string()),
                image: None,
                env: BTreeMap::new(),
                include: Vec::new(),
                tags: BTreeMap::new(),
                ttl_seconds: None,
                resources: None,
                network: None,
            },
            ops: vec![RecordedOp::FilesWrite {
                path: "/app/.env".to_string(),
                bytes_b64: b64,
            }],
        };

        let findings = scan_recording_for_secrets(&recording, &SecretsScanner::default());
        assert!(
            !findings.is_empty(),
            "scan must surface the embedded secret"
        );

        let err = refuse_embedded_secrets(&findings).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SecretRef"),
            "refusal must direct to SecretRef"
        );
        assert!(
            !msg.contains("--ack"),
            "refusal must not offer an ack escape hatch"
        );
    }

    #[test]
    fn gate_passes_with_no_findings() {
        require_acknowledged(&[], &[]).expect("no findings must pass");
    }

    #[test]
    fn gate_refuses_unacknowledged() {
        let findings = vec![Divergence::KillDropped { op_index: 0 }];
        let err = require_acknowledged(&findings, &[]).expect_err("unacked must refuse");
        assert!(
            err.to_string().contains("unacknowledged divergence"),
            "got: {err}"
        );
    }

    #[test]
    fn gate_passes_when_all_kinds_acked() {
        let findings = vec![
            Divergence::KillDropped { op_index: 0 },
            Divergence::FilesWriteAfterEntrypoint {
                op_index: 1,
                path: "/app/x".to_string(),
            },
        ];
        let acks = vec![
            "kill-dropped".to_string(),
            "files-write-after-entrypoint".to_string(),
        ];
        require_acknowledged(&findings, &acks).expect("all kinds acked must pass");
    }

    #[test]
    fn gate_refuses_partial_acks() {
        let findings = vec![
            Divergence::KillDropped { op_index: 0 },
            Divergence::FilesWriteAfterEntrypoint {
                op_index: 1,
                path: "/app/x".to_string(),
            },
        ];
        let acks = vec!["kill-dropped".to_string()];
        let err = require_acknowledged(&findings, &acks).expect_err("partial ack must refuse");
        assert!(
            err.to_string().contains("unacknowledged divergence"),
            "got: {err}"
        );
    }

    fn base_run_args() -> RunArgs {
        RunArgs {
            profile: RunProfile::Standard,
            timeout: Some(60),
            ..Default::default()
        }
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

    #[test]
    fn live_profile_env_name_is_owned_by_the_sdk_registry() {
        assert_eq!(mvm_sdk::env::MVM_SDK_RUN_PROFILE_ENV, "MVM_SDK_RUN_PROFILE");
    }
}
