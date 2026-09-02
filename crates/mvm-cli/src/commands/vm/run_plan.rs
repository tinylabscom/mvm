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
//! - **live** (this module's other half): spawns
//!   the user's script with `MVM_SDK_MODE=live` and
//!   `MVM_CLI_BIN=<path-to-mvmctl>` so the SDK shells each
//!   `Sandbox` operation to existing `mvmctl up` / `proc start` /
//!   `fs write` / `down` against a real microVM. No plan
//!   synthesis here — the SDK drives admission once per
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

use crate::commands::build::trace_secret_scan::SecretFinding;
use mvm_contract::ir::{App, PortProto, PortTransform, Workload};

use super::managed_secrets::lower_app_secrets;
use crate::commands::build::sandbox_record::{
    LoadedRecording, auto_exec_record_script, script_language_from_path,
};
use mvm_core::plan::{IngressMapping, IngressProtocol, IngressTransform, SynthesisInput};
use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};

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

/// Spawn the user's Sandbox-shaped script with `MVM_SDK_MODE=live` and the
/// resolved `mvmctl` binary path on the env so the SDK shells each `Sandbox`
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
/// - `MVM_SDK_RUN_PROFILE=<profile>` — the explicit security profile
///   selected on this outer command. The language SDK validates it and
///   passes it to the nested `machine run`.
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
        .env(mvm_sdk::env::MVM_SDK_MODE_ENV, "live")
        .env(mvm_sdk::env::MVM_CLI_BIN_ENV, &mvmctl_bin)
        .env(mvm_sdk::env::MVM_SDK_RUN_PROFILE_ENV, args.profile.as_str())
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

fn run_plan_mode(args: &RunArgs, sdk: &super::exec::SdkTransportArgs) -> Result<()> {
    let script = extract_script_arg(args)?;
    let lang = script_language_from_path(&script).ok_or_else(|| {
        anyhow::anyhow!(
            "`mvmctl run --mode plan` expected a `.py`, `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`, \
             `.mts`, or `.cts` script path, got {}.",
            script.display()
        )
    })?;

    let LoadedRecording {
        workload,
        findings,
        digest_hex,
        secret_findings,
    } = auto_exec_record_script(&script, lang).with_context(|| {
        format!(
            "lowering Sandbox-shaped script {} for plan-mode admission",
            script.display()
        )
    })?;

    eprintln!("recording sha256: {digest_hex}");
    refuse_embedded_secrets(&secret_findings)?;
    require_acknowledged(&findings, &sdk.ack_divergence)?;

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
        let network_mode = crate::commands::machine::preflight_network();
        let input =
            synthesis_input_for_app(&workload, app, network_mode, args.caller_commitment.clone())?;
        // A recorded sandbox run is a developer artifact; nothing here is
        // sealed, so an unenforceable grant is reported, not fatal.
        match admit_for_run(
            &input,
            &clock,
            &ledger,
            None,
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        ) {
            Ok(admitted) => {
                admitted_count += 1;
                println!(
                    "ADMITTED app={} plan_id={} signer={} cpus={} mem_mib={} workload={} tenant={}",
                    app.name,
                    admitted.plan_id().0,
                    admitted.signer_id(),
                    admitted.plan().resources.cpus,
                    admitted.plan().resources.mem_mib,
                    admitted.plan().workload.0,
                    admitted.plan().tenant.0,
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

/// Refuse plan-mode admission when the recording carries raw secret-shaped
/// material. Unlike divergence findings, there is no acknowledgement path —
/// a raw secret in the workload definition defeats the host-substitution
/// posture, and the only fix is to replace the literal with a `SecretRef`.
fn refuse_embedded_secrets(findings: &[SecretFinding]) -> Result<()> {
    if findings.is_empty() {
        return Ok(());
    }
    for f in findings {
        eprintln!(
            "EMBEDDED SECRET: {} matched [{}]",
            f.location,
            f.rules.join(", ")
        );
    }
    bail!(
        "refusing plan-mode admission: {} location(s) carry raw secret-shaped material. \
         Replace each literal with a SecretRef so the value substitutes host-side and never \
         enters the workload definition. This is not acknowledgeable — remove the secret.",
        findings.len()
    )
}

/// Refuse admission while any divergence finding's class is not
/// explicitly acknowledged. The preview ran one way; the replay
/// behaves another — shipping that silently is the failure mode
/// this gate exists to stop.
fn require_acknowledged(findings: &[mvm_sdk::runtime::Divergence], acks: &[String]) -> Result<()> {
    let unacked: Vec<&mvm_sdk::runtime::Divergence> = findings
        .iter()
        .filter(|f| !acks.iter().any(|a| a == f.kind_slug()))
        .collect();
    if unacked.is_empty() {
        return Ok(());
    }
    for f in &unacked {
        eprintln!("UNACKNOWLEDGED divergence: {f}");
    }
    bail!(
        "refusing plan-mode admission: {} unacknowledged divergence finding(s). Re-run with \
         --ack-divergence <kind> for each class you accept (kinds above in brackets), or fix \
         the script so the recording lowers cleanly.",
        unacked.len()
    )
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
fn synthesis_input_for_app<'a>(
    workload: &'a Workload,
    app: &'a App,
    network_mode: mvm_contract::plan::NetworkMode,
    caller_commitment: Option<mvm_core::plan::CallerCommitment>,
) -> Result<SynthesisInput<'a>> {
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
    let ingress = lower_ingress(app)?;

    Ok(SynthesisInput {
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        network_mode,
        ingress,
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
        destroy_on_exit: true,
        bundle_pin: None,
        // Plan-mode synthesis does not run the install pipeline; it
        // synthesizes one plan per Sandbox call for dry-run admission.
        // deps_volume is wired into the live `mvmctl up` path only.
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        caller_commitment,
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    })
}

fn lower_ingress(app: &App) -> Result<Vec<IngressMapping>> {
    app.network
        .as_ref()
        .map(|network| {
            network
                .ports
                .iter()
                .map(|mapping| {
                    let builder = IngressMapping::builder()
                        .mapping_id(mapping.mapping_id)
                        .protocol(match mapping.proto {
                            PortProto::Tcp => IngressProtocol::Tcp,
                            PortProto::Udp => IngressProtocol::Udp,
                        })
                        .host_addr(&mapping.host_addr)
                        .host_port(mapping.host)
                        .guest_addr(&mapping.guest_addr)
                        .guest_port(mapping.guest)
                        .transform(match mapping.transform {
                            PortTransform::Opaque => IngressTransform::Opaque,
                            PortTransform::Http => IngressTransform::Http,
                            PortTransform::Tls => IngressTransform::Tls,
                        });
                    let builder = match mapping.tls_secret.as_deref() {
                        Some(secret) => builder.tls_secret(secret),
                        None => builder,
                    };
                    builder
                        .build()
                        .with_context(|| format!("invalid ingress mapping {}", mapping.mapping_id))
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
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
    use crate::commands::build::trace_secret_scan::scan_recording_for_secrets;
    use crate::commands::vm::exec::RunProfile;
    use base64::Engine;
    use mvm_hostd::supervisor::secrets_scanner::SecretsScanner;
    use mvm_sdk::runtime::{Divergence, RecordedOp, RuntimeRecording, SandboxCreate};
    use std::collections::BTreeMap;

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

        let findings =
            scan_recording_for_secrets(&recording, &SecretsScanner::with_default_rules());
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

    #[test]
    fn live_profile_env_name_is_owned_by_the_sdk_registry() {
        assert_eq!(mvm_sdk::env::MVM_SDK_RUN_PROFILE_ENV, "MVM_SDK_RUN_PROFILE");
    }
}
