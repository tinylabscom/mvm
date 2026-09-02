//! Audit-chain emitter construction + policy-resolution audit hooks for
//! `mvmctl up` admission — turning the resolved [audit] policy section
//! into a chain-signed emitter, and the `plan.policy_resolved` /
//! `plan.failed` event helpers admission wires around it.

use anyhow::Result;

use crate::commands::cmd_audit;
use crate::commands::vm::audit_chain::{AuditEmitter, default_audit_dir};
use crate::commands::vm::policy_resolver::ResolveError;

pub(super) fn build_default_audit_emitter(
    signing_key: ed25519_dalek::SigningKey,
    audit_dir: Option<&std::path::Path>,
) -> Result<AuditEmitter> {
    let dir = match audit_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_audit_dir()?,
    };
    let emitter = match cmd_audit::active_signer_for(&dir) {
        Some(signer) => AuditEmitter::with_primary_signer(signing_key, &dir, signer),
        None => AuditEmitter::with_dir(signing_key, &dir),
    }?;
    emitter.with_decisions()
}

pub(super) fn build_policy_audit_emitter(
    signing_key: ed25519_dalek::SigningKey,
    audit_dir: Option<&std::path::Path>,
    policy: Option<&mvm_core::policy::AuditPolicy>,
) -> Result<AuditEmitter> {
    let emitter = match policy {
        Some(policy) => {
            let dir = match audit_dir {
                Some(dir) => dir.to_path_buf(),
                None => default_audit_dir()?,
            };
            match cmd_audit::active_signer_for(&dir) {
                Some(signer) => {
                    AuditEmitter::with_policy_and_primary_signer(signing_key, &dir, policy, signer)
                }
                None => AuditEmitter::with_policy(signing_key, &dir, policy),
            }
        }
        None => build_default_audit_emitter(signing_key, audit_dir),
    }?;
    emitter.with_decisions()
}

pub(super) fn emit_policy_resolved(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    slots_mode: &'static str,
) {
    if let Err(e) = emitter.emit_policy_resolved(plan, slots_mode) {
        tracing::warn!(error = %e, "audit emit_policy_resolved failed (non-fatal)");
    }
}

pub(super) fn emit_policy_resolve_failure(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    err: &anyhow::Error,
) {
    let class = match err.downcast_ref::<ResolveError>() {
        Some(ResolveError::BundleNotFound { .. }) => "policy-bundle-not-found",
        Some(ResolveError::BundleParseFailed { .. }) => "policy-bundle-parse-failed",
        Some(ResolveError::MixedRefs { .. }) => "policy-refs-mixed",
        Some(ResolveError::Unrecognized { .. }) => "policy-ref-unrecognized",
        Some(ResolveError::L4SpecInvalid { .. }) => "policy-l4-spec-invalid",
        Some(ResolveError::EgressPolicyInvalid { .. }) => "policy-egress-invalid",
        Some(ResolveError::PiiPolicyInvalid { .. }) => "policy-pii-invalid",
        Some(ResolveError::AuditPolicyInvalid { .. }) => "policy-audit-invalid",
        None => "policy-resolve",
    };
    if let Err(audit_err) = emitter.emit_failed(plan, class, &format!("{err:#}")) {
        tracing::warn!(
            error = %audit_err,
            "audit emit_failed for policy-resolve failed (non-fatal)"
        );
    }
}

pub(super) fn emit_policy_audit_invalid(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    err: &anyhow::Error,
) {
    if let Err(audit_err) = emitter.emit_failed(plan, "policy-audit-invalid", &format!("{err:#}")) {
        tracing::warn!(
            error = %audit_err,
            "audit emit_failed for policy-audit-invalid failed (non-fatal)"
        );
    }
}

#[cfg(test)]
mod policy_audit_admission_tests {
    use super::*;
    use mvm_core::plan::SynthesisInput;
    use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};
    use std::io::Write;

    use super::super::admission::resolve_policy_for_admission;
    use crate::commands::vm::host_signer::load_or_init_at;

    fn write_rootfs(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join("rootfs.ext4");
        let mut f = std::fs::File::create(&path).expect("create rootfs");
        f.write_all(bytes).expect("write rootfs");
        path
    }

    #[test]
    fn admission_emits_policy_resolved_live_when_bundle_parses() {
        // Manually stage a bundle whose tenant matches the synthesized
        // plan's tenant. We can't trivially make the synthesizer emit
        // `<tenant>:<workload>` refs (synthesis hard-codes
        // `local-default`), so this test exercises the audit-mode
        // branch via `resolve_policy_for_admission` directly with an
        // ExecutionPlan we mutate post-synthesis.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();

        // Stage a parseable bundle the live path will consume.
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-live.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-live"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
chain_signing = true
"#,
        )
        .unwrap();

        // Synthesize a default-refs plan, then rewrite the four
        // policy fields to `acme:vm-live`. The resolver requires
        // all four to agree on the same ref.
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"live-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                grants: None,
                stream_edges: Vec::new(),
                kernel_sha256: None,
                network_mode: Default::default(),
                ingress: Vec::new(),
                vm_name: "vm-live",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-live",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
                caller_commitment: None,
                audit_labels: Default::default(),
                agent_verbs: None,
                services: Vec::new(),
                extensions: Vec::new(),
                stream_retention: Default::default(),
                attestation_mode: mvm_contract::plan::AttestationMode::Noop,
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        )
        .expect("admit")
        .plan()
        .clone();
        plan.network_policy = PolicyRef("acme:vm-live".to_string());
        plan.egress_policy = PolicyRef("acme:vm-live".to_string());
        plan.tool_policy = PolicyRef("acme:vm-live".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-live".to_string());

        // Resolve policy, then construct the policy-derived emitter
        // and emit the hook. This mirrors `admit_plan_for_boot`'s
        // ordering: the `[audit]` section affects the success-path
        // audit emitter.
        let resolved = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect("live bundle must resolve");
        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = build_policy_audit_emitter(
            signer.signing,
            Some(audit_dir.path()),
            resolved.audit.as_ref(),
        )
        .unwrap();
        emit_policy_resolved(&plan, &emitter, resolved.slots_mode);

        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"slots_mode\":\"live\""),
            "audit chain must record slots_mode=live for tenant-scoped refs: {content}"
        );
    }

    #[test]
    fn admission_uses_bundle_audit_file_destination() {
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let stream_dir = tempfile::tempdir().unwrap();
        let stream_path = stream_dir.path().join("acme-audit.jsonl");
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-stream.toml"),
            format!(
                r#"
schema_version = 1
bundle_id      = "acme/vm-stream"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
chain_signing = true
stream_destinations = ["file://{}"]
"#,
                stream_path.display()
            ),
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"stream-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                grants: None,
                stream_edges: Vec::new(),
                kernel_sha256: None,
                network_mode: Default::default(),
                ingress: Vec::new(),
                vm_name: "vm-stream",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-stream",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
                caller_commitment: None,
                audit_labels: Default::default(),
                agent_verbs: None,
                services: Vec::new(),
                extensions: Vec::new(),
                stream_retention: Default::default(),
                attestation_mode: mvm_contract::plan::AttestationMode::Noop,
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        )
        .expect("admit")
        .plan()
        .clone();
        plan.network_policy = PolicyRef("acme:vm-stream".to_string());
        plan.egress_policy = PolicyRef("acme:vm-stream".to_string());
        plan.tool_policy = PolicyRef("acme:vm-stream".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-stream".to_string());

        let resolved = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect("stream bundle resolves");
        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let vk = signer.signing.verifying_key();
        let emitter = build_policy_audit_emitter(
            signer.signing,
            Some(audit_dir.path()),
            resolved.audit.as_ref(),
        )
        .unwrap();
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emit_policy_resolved(&plan, &emitter, resolved.slots_mode);

        let default_path = audit_dir.path().join("acme.jsonl");
        let default_content = std::fs::read_to_string(&default_path).unwrap();
        let stream_content = std::fs::read_to_string(&stream_path).unwrap();
        assert!(default_content.contains("plan.admitted"));
        assert!(stream_content.contains("plan.admitted"));
        assert_eq!(
            mvm_hostd::supervisor::verify_audit_chain(&default_path, &vk).unwrap(),
            2
        );
        assert_eq!(
            mvm_hostd::supervisor::verify_audit_chain(&stream_path, &vk).unwrap(),
            2
        );
    }

    #[test]
    fn admission_audits_rejected_unsigned_policy_audit() {
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-unsigned-audit.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-unsigned-audit"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
chain_signing = false
"#,
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unsigned-audit-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                grants: None,
                stream_edges: Vec::new(),
                kernel_sha256: None,
                network_mode: Default::default(),
                ingress: Vec::new(),
                vm_name: "vm-unsigned-audit",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-unsigned-audit",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
                caller_commitment: None,
                audit_labels: Default::default(),
                agent_verbs: None,
                services: Vec::new(),
                extensions: Vec::new(),
                stream_retention: Default::default(),
                attestation_mode: mvm_contract::plan::AttestationMode::Noop,
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        )
        .expect("admit")
        .plan()
        .clone();
        plan.network_policy = PolicyRef("acme:vm-unsigned-audit".to_string());
        plan.egress_policy = PolicyRef("acme:vm-unsigned-audit".to_string());
        plan.tool_policy = PolicyRef("acme:vm-unsigned-audit".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-unsigned-audit".to_string());

        let resolved = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect("bundle shape still resolves");
        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let err = match build_policy_audit_emitter(
            signer.signing.clone(),
            Some(audit_dir.path()),
            resolved.audit.as_ref(),
        ) {
            Ok(_) => panic!("chain_signing=false must reject admission audit construction"),
            Err(err) => err.context("opening audit chain emitter"),
        };
        let fallback = build_default_audit_emitter(signer.signing, Some(audit_dir.path())).unwrap();
        emit_policy_audit_invalid(&plan, &fallback, &err);

        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(content.contains("plan.failed"));
        assert!(content.contains("policy-audit-invalid"));
        assert!(content.contains("chain_signing"));
    }

    #[test]
    fn admission_fails_when_policy_bundle_missing() {
        // A plan whose refs name `acme:nope` but no bundle exists on
        // disk must fail admission with a typed `policy-bundle-not-found`
        // error and emit `plan.failed` with that class.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"missing-bundle-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                grants: None,
                stream_edges: Vec::new(),
                kernel_sha256: None,
                network_mode: Default::default(),
                ingress: Vec::new(),
                vm_name: "vm-nope",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-nope",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
                caller_commitment: None,
                audit_labels: Default::default(),
                agent_verbs: None,
                services: Vec::new(),
                extensions: Vec::new(),
                stream_retention: Default::default(),
                attestation_mode: mvm_contract::plan::AttestationMode::Noop,
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        )
        .expect("admit")
        .plan()
        .clone();
        plan.network_policy = PolicyRef("acme:nope".to_string());
        plan.egress_policy = PolicyRef("acme:nope".to_string());
        plan.tool_policy = PolicyRef("acme:nope".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:nope".to_string());

        let err = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect_err("missing bundle must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("acme") && msg.contains("nope"),
            "error must name the missing bundle: {msg}"
        );

        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = AuditEmitter::with_dir(signer.signing, audit_dir.path()).unwrap();
        emit_policy_resolve_failure(&plan, &emitter, &err);
        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"error_class\":\"policy-bundle-not-found\""),
            "audit chain must classify the failure: {content}"
        );
    }

    #[test]
    fn admission_fails_when_policy_bundle_has_unknown_disabled_inspector() {
        // Tightening regression: an `[egress].disabled_inspectors`
        // typo must fail admission with
        // `error_class=policy-egress-invalid` rather than silently
        // booting with the inspector still enforced.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-typo.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-typo"
bundle_version = 1

[network]
[egress]
disabled_inspectors = ["ssrf_guarrd"]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"typo-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                grants: None,
                stream_edges: Vec::new(),
                kernel_sha256: None,
                network_mode: Default::default(),
                ingress: Vec::new(),
                vm_name: "vm-typo",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-typo",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
                caller_commitment: None,
                audit_labels: Default::default(),
                agent_verbs: None,
                services: Vec::new(),
                extensions: Vec::new(),
                stream_retention: Default::default(),
                attestation_mode: mvm_contract::plan::AttestationMode::Noop,
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        )
        .expect("admit")
        .plan()
        .clone();
        plan.network_policy = PolicyRef("acme:vm-typo".to_string());
        plan.egress_policy = PolicyRef("acme:vm-typo".to_string());
        plan.tool_policy = PolicyRef("acme:vm-typo".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-typo".to_string());

        let err = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect_err("typo must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ssrf_guarrd"),
            "error must name the typo: {msg}"
        );

        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = AuditEmitter::with_dir(signer.signing, audit_dir.path()).unwrap();
        emit_policy_resolve_failure(&plan, &emitter, &err);
        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"error_class\":\"policy-egress-invalid\""),
            "audit chain must classify the failure: {content}"
        );
    }

    #[test]
    fn admission_fails_when_policy_bundle_has_bad_l4_cidr() {
        // A bundle that parses through TOML but carries an
        // unparseable `dst_cidr` must fail admission with
        // `policy-l4-spec-invalid`. Same hermetic shape as the
        // missing-bundle test.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-bad.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-bad"
bundle_version = 1

[network]

[[network.l4]]
proto    = "tcp"
dst_cidr = "not-a-cidr"
port_lo  = 443
port_hi  = 443

[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"bad-cidr-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                grants: None,
                stream_edges: Vec::new(),
                kernel_sha256: None,
                network_mode: Default::default(),
                ingress: Vec::new(),
                vm_name: "vm-bad",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-bad",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
                caller_commitment: None,
                audit_labels: Default::default(),
                agent_verbs: None,
                services: Vec::new(),
                extensions: Vec::new(),
                stream_retention: Default::default(),
                attestation_mode: mvm_contract::plan::AttestationMode::Noop,
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
            mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
        )
        .expect("admit")
        .plan()
        .clone();
        plan.network_policy = PolicyRef("acme:vm-bad".to_string());
        plan.egress_policy = PolicyRef("acme:vm-bad".to_string());
        plan.tool_policy = PolicyRef("acme:vm-bad".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-bad".to_string());

        let err = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect_err("bad CIDR must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not-a-cidr"),
            "error must name the bad CIDR: {msg}"
        );

        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = AuditEmitter::with_dir(signer.signing, audit_dir.path()).unwrap();
        emit_policy_resolve_failure(&plan, &emitter, &err);
        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"error_class\":\"policy-l4-spec-invalid\""),
            "audit chain must classify the failure: {content}"
        );
    }
}
