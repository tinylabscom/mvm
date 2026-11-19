//! Explicit native two-guest acceptance run. No VM or admission test doubles.

mod prepare;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mvm_hostd::actor_process;
use mvm_vmm::host::process_exit::{ProcessExitObserver, ProcessExitWait};

fn main() -> Result<()> {
    ensure!(
        cfg!(all(target_os = "macos", target_arch = "aarch64")),
        "this witness requires native Apple Silicon HVF"
    );
    let args: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(
        args.len() == 5,
        "usage: actor_live_hvf SOURCE_ROOT NEW_EVIDENCE_DIR VERIFIED_KERNEL PARENT_ELF WORKER_ELF"
    );
    let [source, evidence, kernel, parent, worker] = args.as_slice() else {
        unreachable!("argument count checked");
    };
    let bootstrap = prepare::prepare(source, evidence, kernel, parent, worker)?;
    let (launch, mut controller) = actor_process::launch_retained(&bootstrap)?;
    let event = ProcessExitObserver::arm(controller.id().try_into()?)?;
    let outcome = event.wait_event(Instant::now() + Duration::from_secs(300))?;
    ensure!(
        outcome == ProcessExitWait::Exited,
        "controller did not exit; original controller remains alive for cleanup, evidence retained"
    );
    let status = controller.wait()?;
    ensure!(
        status.success(),
        "controller failed; inspect retained evidence"
    );
    verify_evidence(evidence, &launch.plan_id)?;
    println!("ACTOR_LIVE_WITNESS=pass evidence={}", evidence.display());
    Ok(())
}

fn verify_evidence(evidence: &Path, parent_plan: &str) -> Result<()> {
    let home = mvm_core::config::mvm_home_strict()?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()?;
    let audit_path =
        mvm_hostd::audit::emitter::audit_path_for_tenant(&home.join("audit"), "actor-live");
    let audit = std::fs::read_to_string(&audit_path)?;
    let verified =
        mvm_core::audit_verify::file::verify_chain_bytes(&audit, &signer.verifying_key())?;
    for payload in [
        "actor-live-private-request-v1",
        "actor-live-private-response-v1",
    ] {
        ensure!(
            !audit.contains(payload),
            "application payload leaked into audit"
        );
    }
    let root_events: Vec<_> = verified
        .entries
        .iter()
        .filter(|event| event.plan_id.0 == parent_plan)
        .collect();
    for expected in [
        "actor.launch.running",
        "actor.release.terminal",
        "actor.controller.terminal",
    ] {
        ensure!(
            root_events.iter().any(|event| event.event == expected),
            "missing signed event {expected}"
        );
    }
    ensure!(
        root_events
            .iter()
            .any(|event| event.event == "actor.entrypoint.completed"
                && event
                    .labels
                    .get("exit_code")
                    .is_some_and(|code| code == "0")),
        "native exit without successful application completion is not acceptance"
    );
    let launched: Vec<_> = verified
        .entries
        .iter()
        .filter(|event| event.event == "plan.launched")
        .collect();
    ensure!(
        launched.len() == 2,
        "expected exactly parent and one child launch"
    );
    for event in &launched {
        ensure!(
            !mvm_core::config::vm_state_dir(&event.image_name).exists(),
            "used actor still has live runtime state"
        );
    }
    ensure!(
        !verified
            .entries
            .iter()
            .any(|event| event.event.starts_with("warm.")),
        "actor workflow entered warm capacity"
    );
    let reservations: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("actors/reservations.json"))?)?;
    let records = reservations
        .get("records")
        .and_then(serde_json::Value::as_array)
        .context("reservation records missing")?;
    ensure!(
        records.len() == 2
            && records.iter().all(|record| record
                .get("state")
                .and_then(|state| state.get("Terminal"))
                .is_some()),
        "root or child has an unconfirmed reservation"
    );
    std::fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "backend": "hvf",
            "posture": "trusted_host_development",
            "parent_plan_id": parent_plan,
            "signed_audit": audit_path,
            "launches": launched.len(),
            "terminal_reservations": records.len(),
            "application_exit_code": 0,
            "payload_free_audit": true,
            "helper_crash_recovery_exercised": false,
            "density_qualified": false
        }))?,
    )?;
    Ok(())
}
