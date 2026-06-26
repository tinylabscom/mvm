//! Explain an attested launch from the local hash-chained log.

use std::fmt::Write as _;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_core::launch_attestation::{
    LaunchAttestationEnvelope, LaunchAttestationLog, LaunchDerivationSource, LaunchOutcome,
    LaunchRunId, LaunchSourceKind,
};
use mvm_core::packs::{PackKind, Sha256Hex};
use mvm_core::user_config::MvmConfig;
use serde::Serialize;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Launch run id to explain.
    #[arg(value_name = "RUN_ID")]
    pub run_id: String,
    /// Emit the verified attestation record and hash-chain metadata as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ExplainReport {
    run_id: String,
    sequence: u64,
    previous_hash: Option<Sha256Hex>,
    entry_hash: Sha256Hex,
    log_head: Option<Sha256Hex>,
    record: mvm_core::launch_attestation::LaunchAttestationRecord,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let run_id = LaunchRunId::new(args.run_id.clone()).context("invalid run id")?;
    let log = LaunchAttestationLog::open_default().context("opening launch attestation log")?;
    let report = explain_from_log(&log, &run_id)?;
    if args.json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    print!("{}", render_human(&report));
    Ok(())
}

fn explain_from_log(log: &LaunchAttestationLog, run_id: &LaunchRunId) -> Result<ExplainReport> {
    let verified = log
        .verify()
        .context("verifying launch attestation log before explain")?;
    let entry = verified
        .entries
        .iter()
        .find(|entry| entry.record.run_id.as_str() == run_id.as_str())
        .with_context(|| {
            format!(
                "no launch attestation record found for run id {:?}",
                run_id.as_str()
            )
        })?;
    Ok(report_from_entry(entry, verified.head))
}

fn report_from_entry(
    entry: &LaunchAttestationEnvelope,
    log_head: Option<Sha256Hex>,
) -> ExplainReport {
    ExplainReport {
        run_id: entry.record.run_id.as_str().to_string(),
        sequence: entry.sequence,
        previous_hash: entry.previous_hash.clone(),
        entry_hash: entry.entry_hash.clone(),
        log_head,
        record: entry.record.clone(),
    }
}

fn render_human(report: &ExplainReport) -> String {
    let record = &report.record;
    let mut out = String::new();
    writeln!(&mut out, "Run {}", report.run_id).expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  outcome: {}",
        outcome_name(&record.result.outcome)
    )
    .expect("writing to String cannot fail");
    writeln!(&mut out, "  admitted: {}", record.policy_admission.admitted)
        .expect("writing to String cannot fail");
    if let Some(reason) = &record.policy_admission.refusal_reason {
        writeln!(&mut out, "  refusal_reason: {reason}").expect("writing to String cannot fail");
    }
    writeln!(
        &mut out,
        "  source: {} {}",
        source_kind_name(&record.source_input.kind),
        record.source_input.reference
    )
    .expect("writing to String cannot fail");
    if let Some(hash) = &record.source_input.identity_hash {
        writeln!(&mut out, "  source_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    if let Some(digest) = &record.source_input.oci_digest {
        writeln!(&mut out, "  oci_digest: {}", digest.as_str())
            .expect("writing to String cannot fail");
    }
    if let Some(hash) = &record.source_input.flake_lock_hash {
        writeln!(&mut out, "  flake_lock_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    writeln!(
        &mut out,
        "  builder: {} used_builder_vm={}",
        record.builder.builder_id, record.builder.used_builder_vm
    )
    .expect("writing to String cannot fail");
    if let Some(id) = &record.builder.build_environment_id {
        writeln!(&mut out, "  build_environment: {id}").expect("writing to String cannot fail");
    }
    writeln!(
        &mut out,
        "  derivation: {}",
        derivation_source_name(&record.derivation.source)
    )
    .expect("writing to String cannot fail");
    if let Some(id) = &record.derivation.identity {
        writeln!(&mut out, "  derivation_identity: {id}").expect("writing to String cannot fail");
    }
    if let Some(hash) = &record.derivation.parent_pack_hash {
        writeln!(&mut out, "  parent_pack_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    if let Some(hash) = &record.derivation.readiness_proof_hash {
        writeln!(&mut out, "  readiness_proof_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    writeln!(
        &mut out,
        "  backend: {} {} {}",
        record.backend.backend, record.backend.backend_version, record.backend.host_arch
    )
    .expect("writing to String cannot fail");
    writeln!(&mut out, "  launcher: {}", record.launcher_version)
        .expect("writing to String cannot fail");
    writeln!(&mut out, "  started_at: {}", record.started_at.to_rfc3339())
        .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  finished_at: {}",
        record.finished_at.to_rfc3339()
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  verified_at: {}",
        record.local_verification.verified_at.to_rfc3339()
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  verifier: {} files={} revocation_checked={}",
        record.local_verification.verifier_version,
        record.local_verification.file_count,
        record.local_verification.revocation_checked
    )
    .expect("writing to String cannot fail");
    if let Some(hash) = &record.local_verification.trust_root_hash {
        writeln!(&mut out, "  trust_root_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    writeln!(
        &mut out,
        "  plan_hash: {}",
        record.policy_admission.plan_hash.as_str()
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  policy_hash: {}",
        record.policy_admission.policy_hash.as_str()
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  network_policy_hash: {}",
        record.policy_admission.network_policy_hash.as_str()
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  command: {}",
        record.command.argv_redacted.join(" ")
    )
    .expect("writing to String cannot fail");
    writeln!(
        &mut out,
        "  command_hash: {}",
        record.command.argv_digest.as_str()
    )
    .expect("writing to String cannot fail");
    if let Some(hash) = &record.command.cwd_digest {
        writeln!(&mut out, "  cwd_hash: {}", hash.as_str()).expect("writing to String cannot fail");
    }
    if let Some(hash) = &record.command.environment_digest {
        writeln!(&mut out, "  environment_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    if let Some(status) = record.result.exit_status {
        writeln!(&mut out, "  exit_status: {status}").expect("writing to String cannot fail");
    }
    if let Some(output) = &record.result.output_digest {
        writeln!(
            &mut out,
            "  stdout: {} bytes sha256={}",
            output.stdout_bytes,
            output.stdout_sha256.as_str()
        )
        .expect("writing to String cannot fail");
        writeln!(
            &mut out,
            "  stderr: {} bytes sha256={}",
            output.stderr_bytes,
            output.stderr_sha256.as_str()
        )
        .expect("writing to String cannot fail");
    }
    if let Some(hash) = &record.result.error_digest {
        writeln!(&mut out, "  error_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    writeln!(&mut out, "  packs:").expect("writing to String cannot fail");
    for pack in &record.packs {
        writeln!(
            &mut out,
            "    - {} {}",
            pack_kind_name(&pack.kind),
            pack.pack_hash.as_str()
        )
        .expect("writing to String cannot fail");
        if let Some(key_id) = &pack.signer_key_id {
            writeln!(&mut out, "      signer: {}", key_id.0)
                .expect("writing to String cannot fail");
        }
        if let Some(channel) = &pack.channel {
            writeln!(&mut out, "      channel: {channel}").expect("writing to String cannot fail");
        }
        for artifact in &pack.artifact_hashes {
            writeln!(
                &mut out,
                "      artifact {}={}",
                artifact.name,
                artifact.sha256.as_str()
            )
            .expect("writing to String cannot fail");
        }
    }
    writeln!(&mut out, "  log_sequence: {}", report.sequence)
        .expect("writing to String cannot fail");
    writeln!(&mut out, "  entry_hash: {}", report.entry_hash.as_str())
        .expect("writing to String cannot fail");
    if let Some(hash) = &report.previous_hash {
        writeln!(&mut out, "  previous_hash: {}", hash.as_str())
            .expect("writing to String cannot fail");
    }
    if let Some(hash) = &report.log_head {
        writeln!(&mut out, "  log_head: {}", hash.as_str()).expect("writing to String cannot fail");
    }
    out
}

fn outcome_name(outcome: &LaunchOutcome) -> &'static str {
    match outcome {
        LaunchOutcome::Success => "success",
        LaunchOutcome::Refused => "refused",
        LaunchOutcome::BuilderFallback => "builder_fallback",
        LaunchOutcome::VerificationFailure => "verification_failure",
        LaunchOutcome::Interrupted => "interrupted",
        LaunchOutcome::LaunchFailure => "launch_failure",
    }
}

fn source_kind_name(kind: &LaunchSourceKind) -> &'static str {
    match kind {
        LaunchSourceKind::OciImage => "oci_image",
        LaunchSourceKind::Flake => "flake",
        LaunchSourceKind::LocalProject => "local_project",
        LaunchSourceKind::RuntimePack => "runtime_pack",
        LaunchSourceKind::BuilderPrepared => "builder_prepared",
    }
}

fn derivation_source_name(source: &LaunchDerivationSource) -> &'static str {
    match source {
        LaunchDerivationSource::WarmStandby => "warm_standby",
        LaunchDerivationSource::LocalSnapshot => "local_snapshot",
        LaunchDerivationSource::PreparedColdBoot => "prepared_cold_boot",
        LaunchDerivationSource::BuilderPrepare => "builder_prepare",
        LaunchDerivationSource::Refused => "refused",
    }
}

fn pack_kind_name(kind: &PackKind) -> &'static str {
    match kind {
        PackKind::Runtime => "runtime",
        PackKind::Builder => "builder",
        PackKind::ImageProject => "image_project",
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use mvm_core::launch_attestation::{
        BackendIdentity, BuilderIdentity, CommandIdentity, LaunchArtifactHash, LaunchDerivation,
        LaunchPackIdentity, LaunchResult, LaunchSourceInput, LocalVerification,
        OutputDigestMetadata, PolicyAdmission,
    };
    use mvm_core::packs::{PackBackend, Sha256Hex};
    use tempfile::TempDir;

    use super::*;

    fn hash(value: &str) -> Sha256Hex {
        Sha256Hex::from_bytes(value.as_bytes())
    }

    fn record(
        run_id: &str,
        outcome: LaunchOutcome,
    ) -> mvm_core::launch_attestation::LaunchAttestationRecord {
        let ts = Utc
            .with_ymd_and_hms(2026, 6, 25, 12, 0, 0)
            .single()
            .expect("valid timestamp");
        let admitted = !matches!(outcome, LaunchOutcome::Refused);
        let exit_status = matches!(outcome, LaunchOutcome::Success).then_some(0);
        mvm_core::launch_attestation::LaunchAttestationRecord::builder(
            LaunchRunId::new(run_id).expect("run id"),
        )
        .source_input(LaunchSourceInput {
            kind: LaunchSourceKind::OciImage,
            reference: "ghcr.io/tinylabs/demo@sha256:abc".to_string(),
            identity_hash: Some(hash("source")),
            oci_digest: None,
            flake_lock_hash: None,
        })
        .builder_identity(BuilderIdentity {
            used_builder_vm: matches!(outcome, LaunchOutcome::BuilderFallback),
            builder_id: "builder-a".to_string(),
            build_environment_id: Some("env-a".to_string()),
        })
        .pack(LaunchPackIdentity {
            kind: PackKind::Runtime,
            pack_hash: hash("runtime-pack"),
            signer_key_id: None,
            channel: Some("stable".to_string()),
            artifact_hashes: vec![LaunchArtifactHash {
                name: "rootfs".to_string(),
                sha256: hash("rootfs"),
            }],
        })
        .local_verification(LocalVerification {
            verified_at: ts,
            verifier_version: "test".to_string(),
            file_count: 1,
            revocation_checked: true,
            trust_root_hash: Some(hash("trust")),
        })
        .derivation(LaunchDerivation {
            source: if matches!(outcome, LaunchOutcome::BuilderFallback) {
                LaunchDerivationSource::BuilderPrepare
            } else if matches!(outcome, LaunchOutcome::Refused) {
                LaunchDerivationSource::Refused
            } else {
                LaunchDerivationSource::PreparedColdBoot
            },
            identity: Some("derived-a".to_string()),
            parent_pack_hash: Some(hash("parent")),
            readiness_proof_hash: Some(hash("ready")),
        })
        .policy_admission(PolicyAdmission {
            admitted,
            plan_hash: hash("plan"),
            policy_hash: hash("policy"),
            network_policy_hash: hash("network"),
            refusal_reason: (!admitted).then(|| "policy refused".to_string()),
        })
        .command(CommandIdentity {
            argv_redacted: vec!["<admitted-launch>".to_string()],
            argv_digest: hash("argv"),
            cwd_digest: Some(hash("cwd")),
            environment_digest: Some(hash("env")),
        })
        .result(LaunchResult {
            outcome,
            exit_status,
            output_digest: Some(OutputDigestMetadata {
                stdout_sha256: hash("stdout"),
                stderr_sha256: hash("stderr"),
                stdout_bytes: 12,
                stderr_bytes: 0,
            }),
            error_digest: None,
        })
        .backend(BackendIdentity {
            backend: PackBackend::Firecracker,
            backend_version: "test-backend".to_string(),
            host_arch: mvm_core::arch::GuestArch::host(),
        })
        .launcher_version("test-launcher")
        .started_at(ts)
        .finished_at(ts)
        .build()
        .expect("record")
    }

    #[test]
    fn explain_finds_record_and_includes_hash_chain_metadata() {
        let tmp = TempDir::new().expect("tempdir");
        let log = LaunchAttestationLog::open(tmp.path().join("launch.jsonl")).expect("log");
        log.append(record("run-a", LaunchOutcome::Success))
            .expect("append run-a");
        let appended = log
            .append(record("run-b", LaunchOutcome::BuilderFallback))
            .expect("append run-b");

        let report = explain_from_log(&log, &LaunchRunId::new("run-b").expect("run id"))
            .expect("explain report");

        assert_eq!(report.run_id, "run-b");
        assert_eq!(report.sequence, 1);
        assert_eq!(report.entry_hash, appended.entry_hash);
        assert_eq!(report.record.result.outcome, LaunchOutcome::BuilderFallback);
        assert_eq!(report.log_head, Some(appended.entry_hash));
    }

    #[test]
    fn explain_missing_record_is_an_error() {
        let tmp = TempDir::new().expect("tempdir");
        let log = LaunchAttestationLog::open(tmp.path().join("launch.jsonl")).expect("log");
        log.append(record("run-a", LaunchOutcome::Success))
            .expect("append run-a");

        let err = explain_from_log(&log, &LaunchRunId::new("missing").expect("run id"))
            .expect_err("missing record rejected");

        assert!(
            err.to_string()
                .contains("no launch attestation record found")
        );
    }

    #[test]
    fn human_report_includes_success_refusal_and_chain_fields() {
        let tmp = TempDir::new().expect("tempdir");
        let log = LaunchAttestationLog::open(tmp.path().join("launch.jsonl")).expect("log");
        let appended = log
            .append(record("run-refused", LaunchOutcome::Refused))
            .expect("append refused");
        let report = report_from_entry(&appended, Some(appended.entry_hash.clone()));

        let rendered = render_human(&report);

        assert!(rendered.contains("Run run-refused"));
        assert!(rendered.contains("outcome: refused"));
        assert!(rendered.contains("admitted: false"));
        assert!(rendered.contains("refusal_reason: policy refused"));
        assert!(rendered.contains("packs:"));
        assert!(rendered.contains("entry_hash:"));
        assert!(rendered.contains("log_head:"));
    }
}
