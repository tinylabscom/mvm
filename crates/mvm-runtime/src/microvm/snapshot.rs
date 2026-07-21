//! Firecracker snapshot capture/restore: template snapshots (cold restore
//! into a fresh VM) and warm-start (restore into an already-running paused
//! Firecracker), plus the verity/overlay cmdline helpers consumed alongside.

use anyhow::{Context, Result};
use tracing::{instrument, warn};

use crate::base::shell::{run_in_vm, shell_quote};
use crate::base::ui;
use crate::firecracker;
use crate::network_provider::BridgeTapNetworkProvider;
use mvm_net::{NetworkProvider, NetworkSpec};

use super::daemon::{api_patch_socket, api_put_socket, start_vm_firecracker};
use super::flake_run::{FlakeRunConfig, create_dev_config_drive, create_dev_secrets_drive};
use super::guards::{FirecrackerGuard, TapGuard};
use super::run_info::write_vm_run_info;
use super::{abs_vms_dir, firecracker_vsock_uds_path, require_linux_env, resolve_running_vm_dir};

/// Restore a Firecracker VM from a template snapshot (instant start).
///
/// Instead of cold-booting, this loads a pre-captured snapshot where the
/// VM was already healthy. Config and secrets drives are created fresh
/// with the caller's runtime files and must be placed at the paths the
/// snapshot expects (matching the temporary VM used during snapshot creation).
///
/// The VM configuration (vCPUs, memory, drive IDs, network) must match
/// what was used when the snapshot was created.
#[instrument(skip_all, fields(template_id, name = %config.name))]
pub fn restore_from_template_snapshot(
    template_id: &str,
    config: &FlakeRunConfig,
    snapshot_dir: &str,
    _snapshot_info: &mvm_core::template::SnapshotInfo,
) -> Result<()> {
    config.validate()?;
    require_linux_env()?;

    // Verify the integrity sidecar *before* doing anything else: a
    // tampered snapshot must not cause
    // bridge ensure / TAP create / Firecracker spawn — none of those
    // should happen if we're going to refuse the bytes anyway. A
    // missing sidecar is a non-fatal warning unless
    // `MVM_SNAPSHOT_HMAC_STRICT=1`.
    crate::base::snapshot_integrity::verify_snapshot_artifacts(snapshot_dir)?;

    let slot = &config.slot;

    // Check if this VM name is already running
    let abs_dir = slot.vm_dir.clone();
    let abs_socket = format!("{}/fc.socket", abs_dir);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if firecracker::is_vm_running(&pid_file)? {
        ui::info(&format!("VM '{}' is already running.", slot.name));
        ui::info("Use 'mvmctl stop <name>' to shut it down first.");
        return Ok(());
    }

    // Provision the VM's bridge+TAP network + egress policy through the
    // NetworkProvider seam. `provision` is transactional
    // — it drops the TAP itself if the policy apply fails — and the TapGuard
    // below re-arms to tear the TAP down if a *later* start step fails. Same
    // operations, same order, as the direct calls this replaces.
    BridgeTapNetworkProvider::new()
        .provision(
            &mvm_core::protocol::vm_backend::VmId(slot.name.clone()),
            &NetworkSpec {
                policy: super::flake_run::firecracker_tap_policy(config),
                slot_index: slot.index,
            },
        )
        .map_err(|e| anyhow::anyhow!("network provision: {e}"))?;
    let mut tap_guard = TapGuard::new(slot);

    // Copy snapshot files to per-VM directory
    run_in_vm(&format!(
        "mkdir -p {dir} && cp {snap}/vmstate.bin {dir}/vmstate.bin && cp {snap}/mem.bin {dir}/mem.bin",
        snap = snapshot_dir,
        dir = abs_dir,
    ))?;

    // Create config and secrets drives in the new VM directory with fresh runtime data
    ui::info("Creating config drive...");
    let config_drive = create_dev_config_drive(&abs_dir, config)?;
    ui::info("Creating secrets drive...");
    let secrets_drive = create_dev_secrets_drive(&abs_dir, &config.secret_files)?;

    // The snapshot expects drives at the template runtime directory.
    // Create per-instance symlinks from template runtime paths to the instance drives.
    // This allows multiple concurrent instances from the same template, each with
    // their own config/secrets, while the snapshot finds drives at expected paths.
    //
    // Use flock to serialize symlink creation + snapshot load to prevent race conditions
    // when multiple instances start simultaneously.
    let template_runtime_dir = format!(
        "{}/templates/{}/runtime",
        mvm_core::config::mvm_home(),
        template_id
    );
    let lock_file = format!("{}.lock", template_runtime_dir);

    // Start Firecracker daemon in per-VM directory (before acquiring lock)
    start_vm_firecracker(&abs_dir, &abs_socket)?;
    let mut fc_guard = FirecrackerGuard::new(&abs_dir);
    let vsock_path = firecracker_vsock_uds_path(&abs_dir);

    // Atomic operation: create symlinks + load snapshot (serialized by flock)
    ui::info("Loading snapshot...");
    let vmstate_path = format!("{}/vmstate.bin", abs_dir);
    let mem_path = format!("{}/mem.bin", abs_dir);
    run_in_vm(&format!(
        r#"
        # Create lock directory
        mkdir -p {runtime_dir}

        # Use flock to serialize symlink creation and snapshot load
        (
            flock -x 200 || exit 1

            # Remove old symlinks (from previous instance that finished loading)
            rm -f {runtime_dir}/config.ext4 {runtime_dir}/secrets.ext4 {runtime_dir}/v.sock

            # Create symlinks to this instance's drives and vsock socket location
            ln -s {config} {runtime_dir}/config.ext4
            ln -s {secrets} {runtime_dir}/secrets.ext4
            ln -s {vsock} {runtime_dir}/v.sock

            # Load snapshot (Firecracker opens the drives via symlinks)
            response=$(sudo curl -s -w "\n%{{http_code}}" --unix-socket {socket} -X PUT \
                -H 'Content-Type: application/json' \
                -d '{{"snapshot_path": "{vmstate}", "mem_backend": {{"backend_type": "File", "backend_path": "{mem}"}}, "enable_diff_snapshots": false}}' \
                'http://localhost/snapshot/load')
            code=$(echo "$response" | tail -1)
            body=$(echo "$response" | sed '$d')
            if [ "$code" -ge 400 ]; then
                echo "[mvm] ERROR: PUT /snapshot/load returned $code: $body" >&2
                exit 1
            fi
        ) 200>{lock_file}
        "#,
        runtime_dir = template_runtime_dir,
        lock_file = lock_file,
        config = config_drive,
        secrets = secrets_drive,
        vsock = vsock_path,
        socket = abs_socket,
        vmstate = vmstate_path,
        mem = mem_path,
    ))?;

    // Resume vCPUs
    ui::info("Resuming VM from snapshot...");
    api_patch_socket(&abs_socket, "/vm", r#"{"state": "Resumed"}"#)?;

    // Make vsock socket accessible
    if let Err(e) = run_in_vm(&format!("sudo chmod 0666 {vsock_path} 2>/dev/null")) {
        warn!("failed to chmod vsock socket: {e}");
    }

    // Post-restore: remount drives and restart services with fresh config/secrets.
    if !config.config_files.is_empty() || !config.secret_files.is_empty() {
        ui::info("Sending post-restore signal (remounting drives, restarting services)...");
        // Wait for guest agent to be reachable after resume (may take a moment).
        let mut agent_ready = false;
        for attempt in 0..30 {
            if mvm_agentd::vsock::ping_at(&vsock_path).unwrap_or(false) {
                agent_ready = true;
                break;
            }
            if attempt == 29 {
                ui::warn(
                    "Guest agent not reachable after resume. Config/secrets may not be loaded.",
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        if agent_ready {
            // Mint a fresh generation token so this resume rotates the guest
            // CSPRNG — two clones of one snapshot must not draw identical
            // randomness. The token bytes are random; the content hash is
            // metadata only.
            let token = mvm_core::crypto::vmgenid::fresh_generation_token(&vsock_path).token;
            match mvm_agentd::vsock::post_restore_at(&vsock_path, token) {
                Ok(r) if r.acknowledged => ui::info("Post-restore complete."),
                Ok(_) => ui::warn("Post-restore signal returned failure."),
                Err(e) => ui::warn(&format!(
                    "Post-restore failed: {}. Services may need manual restart.",
                    e
                )),
            }
        }
    }

    // Persist run info
    write_vm_run_info(config, &abs_dir)?;

    // VM is fully restored — defuse guards so normal stop path handles cleanup
    fc_guard.defuse();
    tap_guard.defuse();

    ui::banner(&[
        &format!("MicroVM '{}' restored from snapshot!", config.name),
        "",
        &format!("  Guest IP: {}", slot.guest_ip),
        &format!("  Revision: {}", config.revision_hash),
        "",
        &format!("Use 'mvmctl stop {}' to shut down this VM.", config.name),
        "Use 'mvmctl status' to list all running VMs.",
    ]);

    Ok(())
}

/// Poll interval while waiting for the restored guest agent to re-accept on
/// the recreated vsock after a warm resume.
const WARM_AGENT_READY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// How many [`WARM_AGENT_READY_POLL_INTERVAL`] ticks to wait for the restored
/// agent before giving up on token delivery. The restored agent has been
/// observed re-accepting ~30–35s after a ~0.5s VMM resume; a 30s window
/// (60 × 500ms) raced that tail and the token silently no-op'd. Widened to 60s
/// so the token reliably lands while the latency root-cause is chased
/// separately.
const WARM_AGENT_READY_POLL_ATTEMPTS: u32 = 120;

/// Classify the warm-start reseed outcome from the agent-ready result and the
/// guest's post-restore reply. Pure so the tri-state honesty logic is
/// unit-tested without a live guest. Rotation is judged on the guest's
/// `reseeded` flag, not the remount/restart ack — the guest reseeds before it
/// remounts, so a failed remount still leaves a rotated VMGenID.
fn classify_reseed(
    agent_ready: bool,
    reply: Option<mvm_agentd::vsock::PostRestoreReply>,
) -> mvm_core::vm_backend::ReseedStatus {
    use mvm_core::vm_backend::ReseedStatus;
    match (agent_ready, reply) {
        (false, _) | (_, None) => ReseedStatus::Undelivered,
        (true, Some(r)) if r.reseeded => ReseedStatus::Rotated,
        (true, Some(_)) => ReseedStatus::NotRotated,
    }
}

/// Warm-restore an instance from its sealed snapshot into its already-running
/// (paused) Firecracker, then deliver the VMGenID token so the guest reseeds.
///
/// Precondition: a sealed snapshot from `pause` exists for `name`. Verifies the
/// snapshot's integrity sidecar *before* touching the VMM (a tampered snapshot
/// is refused), stops any paused Firecracker, boots a fresh blank VMM, loads
/// `vmstate.bin` + `mem.bin` into it via `PUT /snapshot/load` with `resume_vm`,
/// waits for the guest agent, and signals post-restore carrying `token` so the
/// guest rotates its VMGenID (distinct clones diverge). The host-side
/// counterpart of `mvmctl vm resume`, reachable from the backend layer for
/// `FirecrackerBackend::warm_start`.
pub fn warm_restore_instance(
    name: &str,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    // Defense in depth, *before* any work: every path below is derived from
    // `name` and several are interpolated into shell commands
    // (`start_vm_firecracker`, the kill). The CLI validates the name, but this
    // is a `pub fn` — re-validate at the boundary so no caller can smuggle
    // shell/JSON metacharacters in. The validator allows only `[a-z0-9-]`,
    // which is shell- and JSON-safe.
    mvm_core::naming::validate_vm_name(name)
        .with_context(|| format!("warm-start refused invalid VM name {name:?}"))?;

    let snapshot_dir = mvm_core::config::instance_snapshot_dir(name);
    let snapshot_dir = snapshot_dir.to_string_lossy().into_owned();
    warm_restore_instance_from_path(name, &snapshot_dir, token)
}

/// Warm-restore an instance from a caller-supplied snapshot directory.
///
/// Factored out from [`warm_restore_instance`] so that
/// [`crate::firecracker::FcForkRestorer`] can direct the load to the fork's
/// checkpoint content directory instead of the canonical
/// `instance_snapshot_dir(name)` path.
///
/// `snapshot_dir` must contain `vmstate.bin` and `mem.bin`. Name validation
/// and `require_linux_env()` are performed here so every caller gets the same
/// guards.
pub fn warm_restore_instance_from_path(
    name: &str,
    snapshot_dir: &str,
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> Result<mvm_core::vm_backend::ReseedStatus> {
    mvm_core::naming::validate_vm_name(name)
        .with_context(|| format!("warm-start refused invalid VM name {name:?}"))?;
    require_linux_env()?;

    let vm_dir = resolve_running_vm_dir(name)?;
    // The control socket + pid file every other FC op in this module uses
    // (`start_vm_firecracker`, `resume_vm`, balloon, …) — `{dir}/fc.socket`,
    // not a `runtime/` variant.
    let socket = format!("{vm_dir}/fc.socket");
    let pid_file = format!("{vm_dir}/fc.pid");

    if !std::path::Path::new(&format!("{snapshot_dir}/vmstate.bin")).exists() {
        anyhow::bail!(
            "no sealed snapshot at {snapshot_dir} for VM '{name}' — `mvmctl vm pause {name}` \
             first, or `mvmctl up` for a cold boot"
        );
    }
    // Refuse a tampered snapshot before any VMM interaction.
    crate::base::snapshot_integrity::verify_snapshot_artifacts(snapshot_dir)?;

    let vmstate = format!("{snapshot_dir}/vmstate.bin");
    let mem = format!("{snapshot_dir}/mem.bin");

    // Firecracker refuses `/snapshot/load` on a VMM that already started a
    // microVM ("operation not supported after starting the microVM"), so stop
    // the paused FC and bring up a fresh blank VMM to load the sealed snapshot
    // into. `start_vm_firecracker` clears the stale `fc.socket` + `runtime/v.sock`
    // first — otherwise the restored vsock device fails to bind (AddrInUse).
    if firecracker::is_vm_running(&pid_file)? {
        let q_pid = shell_quote(&pid_file);
        let _ = run_in_vm(&format!(
            "sudo kill -9 \"$(cat {q_pid})\" 2>/dev/null; sleep 1"
        ));
    }
    start_vm_firecracker(&vm_dir, &socket)
        .with_context(|| format!("starting fresh Firecracker for warm-start of '{name}'"))?;

    // Load + resume into the fresh VMM in a single call (resume_vm). Build the
    // body with `serde_json` (paths are JSON-escaped) and send it through
    // `api_put_socket`, which writes the body to a temp file and curls it via
    // `--data @<file>` — so the paths never traverse a shell, no injection.
    let body = serde_json::json!({
        "snapshot_path": vmstate,
        "mem_backend": { "backend_type": "File", "backend_path": mem },
        "resume_vm": true,
    })
    .to_string();
    api_put_socket(&socket, "/snapshot/load", &body)
        .with_context(|| format!("PUT /snapshot/load for warm-start of '{name}'"))?;

    // The VM is restored and resumed at this point. Delivering the VMGenID
    // token (so the guest reseeds) is best-effort — the agent re-accepts on
    // the recreated vsock a beat after resume, and a missed signal is safe to
    // re-send. A racy signal must not fail an otherwise-successful warm-start
    // (mirrors `restore_from_template_snapshot`'s post-restore policy).
    let vsock = firecracker_vsock_uds_path(&vm_dir);
    let mut agent_ready = false;
    for _ in 0..WARM_AGENT_READY_POLL_ATTEMPTS {
        if mvm_agentd::vsock::ping_at(&vsock).unwrap_or(false) {
            agent_ready = true;
            break;
        }
        std::thread::sleep(WARM_AGENT_READY_POLL_INTERVAL);
    }
    if !agent_ready {
        warn!(
            "warm-start of '{name}': guest agent not reachable to deliver VMGenID token; the VM is resumed but did not reseed — re-run resume to retry"
        );
        return Ok(classify_reseed(false, None));
    }
    let reply = match mvm_agentd::vsock::post_restore_at(&vsock, token) {
        Ok(r) => {
            if !r.reseeded {
                warn!("warm-start of '{name}': guest did not reseed VMGenID (VM is resumed)");
            }
            Some(r)
        }
        Err(e) => {
            warn!("warm-start of '{name}': post-restore signal failed: {e} (VM is resumed)");
            None
        }
    };
    Ok(classify_reseed(agent_ready, reply))
}

/// Write a full Firecracker snapshot to `vmstate_path` (VM state) and
/// `mem_path` (guest memory) while the VM is paused.
///
/// Sends `PUT /snapshot/create` to the per-VM control socket. The VM must
/// already be paused (call [`pause_vm`] first). The caller is responsible for
/// resuming the VM after capture with [`resume_vm`].
///
/// Both paths must be absolute — Firecracker resolves them on the host rather
/// than inside the VM, so a relative path would be interpreted from an
/// uncontrolled working directory.
#[instrument(skip_all, fields(name))]
pub fn create_snapshot_files(
    name: &str,
    vmstate_path: &std::path::Path,
    mem_path: &std::path::Path,
) -> Result<()> {
    require_linux_env()?;
    anyhow::ensure!(
        vmstate_path.is_absolute(),
        "vmstate_path must be absolute, got {}",
        vmstate_path.display()
    );
    anyhow::ensure!(
        mem_path.is_absolute(),
        "mem_path must be absolute, got {}",
        mem_path.display()
    );

    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    let socket = format!("{}/fc.socket", abs_dir);
    let q_socket = shell_quote(&socket);

    let vmstate_str = vmstate_path.to_string_lossy();
    let mem_str = mem_path.to_string_lossy();

    // PUT /snapshot/create with snapshot_type=Full writes vmstate + guest memory.
    // The VM must be paused before this call; Firecracker refuses the request
    // with an error if vCPUs are still running.
    let payload = format!(
        r#"{{"snapshot_type":"Full","snapshot_path":"{vmstate}","mem_file_path":"{mem}"}}"#,
        vmstate = vmstate_str,
        mem = mem_str,
    );
    api_put_socket(&socket, "/snapshot/create", &payload).with_context(|| {
        format!(
            "PUT /snapshot/create for VM '{}' (socket {})",
            name, q_socket
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warm_restore_refuses_names_with_shell_metacharacters() {
        // The name feeds shell-interpolated paths; warm_restore_instance must
        // reject anything outside the safe `[a-z0-9-]` charset *before* any
        // VMM work, on every platform (validation precedes require_linux_env).
        for bad in [
            "foo; rm -rf /",
            "a'b",
            "x$(id)",
            "../escape",
            "name with space",
            "UPPER",
        ] {
            let err = warm_restore_instance(bad, [0u8; mvm_core::crypto::vmgenid::GENID_BYTES])
                .expect_err("must refuse an unsafe VM name");
            assert!(
                err.to_string().contains("invalid VM name"),
                "rejection names the cause for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn classify_reseed_is_honest_about_rotation() {
        use mvm_agentd::vsock::PostRestoreReply;
        use mvm_core::vm_backend::ReseedStatus;

        // Agent never came back → token undelivered, reseed unknown.
        assert_eq!(classify_reseed(false, None), ReseedStatus::Undelivered);
        // Agent ready but the signal RPC errored (reply None) → undelivered.
        assert_eq!(classify_reseed(true, None), ReseedStatus::Undelivered);
        // Reachable + guest rotated → Rotated, regardless of the remount ack.
        assert_eq!(
            classify_reseed(
                true,
                Some(PostRestoreReply {
                    acknowledged: false,
                    reseeded: true
                })
            ),
            ReseedStatus::Rotated
        );
        // Reachable + acknowledged but did not rotate → NotRotated.
        assert_eq!(
            classify_reseed(
                true,
                Some(PostRestoreReply {
                    acknowledged: true,
                    reseeded: false
                })
            ),
            ReseedStatus::NotRotated
        );
    }

    #[test]
    fn warm_agent_ready_budget_covers_observed_post_restore_latency() {
        // The restored guest agent has been observed re-accepting ~30–35s after
        // a ~0.5s VMM resume; a 30s window raced it and the token silently
        // no-op'd. The widened window must cover that tail.
        let window = WARM_AGENT_READY_POLL_INTERVAL * WARM_AGENT_READY_POLL_ATTEMPTS;
        assert!(
            window >= std::time::Duration::from_secs(45),
            "warm agent-ready window {window:?} must cover the observed ~35s latency with margin"
        );
    }
}
