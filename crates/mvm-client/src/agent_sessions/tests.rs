//! Durable agent-session service regression tests.

use super::*;

fn fixture() -> (tempfile::TempDir, AgentSessions) {
    let dir = tempfile::tempdir().expect("fixture");
    let service = AgentSessions::at(dir.path().join("sessions"), dir.path().join("checkpoints"));
    (dir, service)
}

fn open(service: &AgentSessions) -> SessionReport {
    service
        .open(&OpenRequest {
            session_id: "durable-test".into(),
            resume_point: None,
            members: Vec::new(),
        })
        .expect("open")
}

fn park_request() -> ParkRequest {
    ParkRequest {
        session_id: "durable-test".into(),
        reason: "operator".into(),
        journal_cursor: 7,
        approval_head: None,
        retain_for: Some("1h".into()),
        expected_generation: Some(1),
    }
}

fn record_bytes(service: &AgentSessions) -> Vec<u8> {
    std::fs::read(
        service
            .sessions
            .session_dir(&parse_id("durable-test").unwrap())
            .join("session.json"),
    )
    .unwrap()
}

#[test]
fn record_filename_session_id_does_not_poison_listing_or_pins() {
    let (_dir, service) = fixture();
    service
        .open(&OpenRequest {
            session_id: "session.json".into(),
            resume_point: None,
            members: Vec::new(),
        })
        .unwrap();
    service.show("session.json").unwrap();
    assert_eq!(service.list().unwrap().len(), 1);
    assert!(
        mvm_runtime::agent_session::pinned_checkpoints(&service.sessions)
            .unwrap()
            .is_empty()
    );
    assert!(
        service
            .sessions
            .root()
            .join(".locks/session.json.lock")
            .is_file()
    );
    assert!(!service.sessions.root().join(".locks/session.json").exists());
}

#[test]
fn missing_record_filename_session_mutation_does_not_poison_catalog() {
    let (_dir, service) = fixture();
    let request = ParkRequest {
        session_id: "session.json".into(),
        ..park_request()
    };
    assert!(service.park(&request).is_err());
    assert!(
        service
            .renew(&RenewRequest {
                session_id: "session.json".into(),
                extend_for: "1h".into(),
                expected_deadline: None,
                expected_generation: None,
            })
            .is_err()
    );
    assert!(
        service
            .resume(&ResumeRequest {
                session_id: "session.json".into(),
                ..resume_request()
            })
            .is_err()
    );
    assert!(service.list().unwrap().is_empty());
    assert!(
        mvm_runtime::agent_session::pinned_checkpoints(&service.sessions)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn stored_open_park_list_show_and_exact_retry() {
    let (_dir, service) = fixture();
    let created = open(&service);
    assert_eq!(created.generation, 1);
    let parked = service.park(&park_request()).unwrap();
    assert_eq!(parked.session.journal_cursor, 7);
    assert_eq!(parked.session.state, Residency::Hibernated);
    assert!(!parked.replayed);
    assert_eq!(
        parked.warnings.len(),
        1,
        "no member means no audit authority"
    );
    assert!(
        parked.warnings[0].contains("parked, but the park was not recorded in the audit chain")
    );
    let bytes = record_bytes(&service);
    let retried = service.park(&park_request()).unwrap();
    assert!(retried.replayed);
    assert!(
        retried.warnings.is_empty(),
        "retry does not attempt another audit"
    );
    assert_eq!(bytes, record_bytes(&service));
    assert_eq!(service.list().unwrap().len(), 1);
    assert_eq!(
        service.show("durable-test").unwrap().generation,
        parked.session.generation
    );
    let encoded = serde_json::to_value(&parked).unwrap();
    let decoded: TransitionReport = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
}

#[test]
fn malformed_inputs_duplicate_open_and_generation_conflicts_preserve_storage() {
    let (_dir, service) = fixture();
    open(&service);
    let bytes = record_bytes(&service);
    assert!(
        service
            .open(&OpenRequest {
                session_id: "durable-test".into(),
                resume_point: None,
                members: Vec::new(),
            })
            .is_err()
    );
    let mut request = park_request();
    request.expected_generation = Some(42);
    assert!(service.park(&request).is_err());
    request.expected_generation = Some(1);
    request.approval_head = Some("not-a-digest".into());
    assert!(service.park(&request).is_err());
    assert!(
        service
            .show("../outside")
            .unwrap_err()
            .to_string()
            .contains("invalid session id")
    );
    assert_eq!(record_bytes(&service), bytes);
}

#[test]
fn renew_is_monotone_and_retry_is_write_free() {
    let (_dir, service) = fixture();
    open(&service);
    let parked = service.park(&park_request()).unwrap();
    let mut request = RenewRequest {
        session_id: "durable-test".into(),
        extend_for: "2h".into(),
        expected_deadline: parked.session.retain_until_unix,
        expected_generation: Some(parked.session.generation),
    };
    let renewed = service.renew(&request).unwrap();
    assert_eq!(renewed.warnings.len(), 1);
    assert!(
        renewed.warnings[0]
            .contains("renewed, but the renewal was not recorded in the audit chain")
    );
    assert!(renewed.session.retain_until_unix > parked.session.retain_until_unix);
    let bytes = record_bytes(&service);
    assert!(service.renew(&request).unwrap().replayed);
    assert_eq!(record_bytes(&service), bytes);
    request.expected_deadline = renewed.session.retain_until_unix;
    request.extend_for = "30m".into();
    assert!(service.renew(&request).is_err());
    assert_eq!(record_bytes(&service), bytes);
}

#[test]
fn corrupt_existing_record_is_not_overwritten() {
    let (_dir, service) = fixture();
    open(&service);
    let path = service
        .sessions
        .session_dir(&parse_id("durable-test").unwrap())
        .join("session.json");
    std::fs::write(&path, b"tampered").unwrap();
    assert!(service.show("durable-test").is_err());
    assert!(service.list().is_err());
    assert!(
        service
            .open(&OpenRequest {
                session_id: "durable-test".into(),
                resume_point: None,
                members: Vec::new(),
            })
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"tampered");
}

#[test]
fn lock_holds_one_persistent_inode_until_transaction_returns() {
    let (_dir, service) = fixture();
    let id = parse_id("durable-test").unwrap();
    let held = service.lock(&id).unwrap();
    let other = OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            service
                .sessions
                .root()
                .join(".locks")
                .join(format!("{}.lock", id.as_str())),
        )
        .unwrap();
    assert!(matches!(
        other.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(held);
    other.try_lock().expect("released on drop");
}

#[test]
fn resume_refuses_before_mutation_when_missing_kernel_or_checkpoint() {
    let (_dir, service) = fixture();
    open(&service);
    service.park(&park_request()).unwrap();
    let bytes = record_bytes(&service);
    let mut request = ResumeRequest {
        session_id: "durable-test".into(),
        backend: "mock".into(),
        image: "fixture".into(),
        image_sha256: "ab".repeat(32),
        kernel_sha256: Some("cd".repeat(32)),
        cpus: 1,
        mem_mib: 128,
        approval_head: None,
        boot: true,
        kernel: None,
        expected_generation: Some(1),
    };
    assert!(
        service
            .resume(&request)
            .unwrap_err()
            .to_string()
            .contains("--kernel")
    );
    request.boot = false;
    assert!(
        service
            .resume(&request)
            .unwrap_err()
            .to_string()
            .contains("no resume point")
    );
    assert_eq!(record_bytes(&service), bytes);
}

fn seed_resume_point(service: &AgentSessions, root: &Path) -> mvm_core::checkpoint::CheckpointMeta {
    let rootfs = root.join("rootfs.ext4");
    std::fs::write(&rootfs, b"stored checkpoint fixture").unwrap();
    let meta = mvm_runtime::checkpoint::capture_fs_quick(
        &service.checkpoints,
        mvm_runtime::checkpoint::CaptureFsQuickParams {
            id: mvm_core::checkpoint::CheckpointId::new("resume-base"),
            vm_name: "source-machine".into(),
            rootfs,
            supervisor_config_digest: "fixture-config".into(),
            runtime_overlay_version: None,
            tag: None,
            created_unix: 1,
            quiesced: true,
            grants: None,
            key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
        },
    )
    .unwrap();
    assert!(
        meta.content.iter().any(|blob| blob.name == "rootfs.ext4"),
        "resume fixture must capture the boot blob by its contract name: {:?}",
        meta.content
    );
    meta
}

fn resume_request() -> ResumeRequest {
    ResumeRequest {
        session_id: "durable-test".into(),
        backend: "hvf".into(),
        image: "fixture-image".into(),
        image_sha256: "ab".repeat(32),
        kernel_sha256: None,
        cpus: 1,
        mem_mib: 128,
        approval_head: None,
        boot: false,
        kernel: None,
        expected_generation: Some(1),
    }
}

fn open_park_at_checkpoint(service: &AgentSessions, digest: &CheckpointDigest) {
    service
        .open(&OpenRequest {
            session_id: "durable-test".into(),
            resume_point: Some(digest.to_string()),
            members: Vec::new(),
        })
        .unwrap();
    service.park(&park_request()).unwrap();
}

#[test]
fn real_checkpoint_resume_admits_once_and_audits_once() {
    let (home, service) = fixture();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    mvm_core::user_config::save(&mvm_core::user_config::MvmConfig::default(), None).unwrap();
    let parent = seed_resume_point(&service, home.path());
    open_park_at_checkpoint(&service, &parent.meta_digest);

    let id = parse_id("durable-test").unwrap();
    let mut stored = service.sessions.load(&id).unwrap();
    stored.approval_head =
        Some(ApprovalHead::parse(format!("sha256:{}", "cd".repeat(32))).unwrap());
    service.sessions.write(&stored).unwrap();
    let material = ResumePlanMaterial {
        backend_name: "hvf".into(),
        image_name: "fixture-image".into(),
        image_sha256: "ab".repeat(32),
        kernel_sha256: None,
        cpus: 1,
        mem_mib: 128,
    };
    let signed_labels =
        mvm_hostd::session_resume::synthesis_for_resume(&stored, &material).audit_labels;
    let request = resume_request();
    let request = ResumeRequest {
        approval_head: stored.approval_head.as_ref().map(ToString::to_string),
        ..request
    };
    let resumed = service.resume(&request).expect("fresh signed admission");
    assert!(!resumed.replayed);
    assert!(resumed.warnings.is_empty(), "{:?}", resumed.warnings);
    assert!(resumed.admitted_plan_id.is_some());
    assert_eq!(resumed.session.generation, 2);
    assert_eq!(resumed.session.state, Residency::Active);
    assert!(resumed.booted_sandbox.is_none());
    let bytes = record_bytes(&service);
    let retried = service.resume(&request).expect("exact retry");
    assert!(retried.replayed);
    assert_eq!(retried.admitted_plan_id, resumed.admitted_plan_id);
    assert_eq!(record_bytes(&service), bytes);
    let entries = verified_entries(home.path(), "local");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.event, "session.resumed");
    assert_eq!(
        entry.plan_id.0,
        resumed.admitted_plan_id.as_deref().unwrap()
    );
    assert_eq!(entry.labels["resumed_session"], "durable-test");
    assert_eq!(entry.labels["resumed_at_generation"], "2");
    assert_eq!(entry.labels["resumed_plan_id"], entry.plan_id.0);
    for (key, value) in signed_labels {
        assert_eq!(entry.labels.get(&key), Some(&value), "{key}");
    }
}

#[test]
fn edited_checkpoint_metadata_refuses_before_admission_and_preserves_generation() {
    let (home, service) = fixture();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let mut parent = seed_resume_point(&service, home.path());
    open_park_at_checkpoint(&service, &parent.meta_digest);
    let bytes = record_bytes(&service);
    parent.tag = Some("edited after capture".into());
    service.checkpoints.write_meta(&parent).unwrap();
    let error = service.resume(&resume_request()).unwrap_err();
    assert!(error.to_string().contains("integrity"), "{error:#}");
    assert_eq!(record_bytes(&service), bytes);
    assert!(!home.path().join("audit").exists());
}

#[test]
fn empty_listing_missing_sessions_and_invalid_open_inputs() {
    let (_home, service) = fixture();
    assert!(service.list().unwrap().is_empty());
    assert!(
        service
            .show("absent")
            .unwrap_err()
            .to_string()
            .contains("absent")
    );
    assert!(
        service
            .resume(&resume_request())
            .unwrap_err()
            .to_string()
            .contains("durable-test")
    );
    for (id, point, expected) in [
        ("../escape", None, "invalid session id"),
        (
            "durable-test",
            Some("not-a-digest"),
            "invalid --resume-point",
        ),
    ] {
        let error = service
            .open(&OpenRequest {
                session_id: id.into(),
                resume_point: point.map(str::to_owned),
                members: Vec::new(),
            })
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert!(service.list().unwrap().is_empty());
    }
}

#[test]
fn open_preserves_members_resume_point_and_resident_generation_one() {
    let (_home, service) = fixture();
    let digest = format!("sha256:{}", "1a".repeat(32));
    let opened = service
        .open(&OpenRequest {
            session_id: "durable-test".into(),
            resume_point: Some(digest.clone()),
            members: vec!["vm-alpha".into()],
        })
        .unwrap();
    assert_eq!(opened.state, Residency::Active);
    assert_eq!(opened.generation, 1);
    assert_eq!(opened.members, ["vm-alpha"]);
    assert_eq!(opened.parent_checkpoint, Some(digest));
    assert_eq!(opened.park_reason, None);
    assert_eq!(opened.storage_tier, None);
    assert_eq!(opened.approval_head, None);
    assert_eq!(opened.retention, None);
    assert_eq!(
        serde_json::to_value(&opened).unwrap(),
        serde_json::to_value(service.show("durable-test").unwrap()).unwrap()
    );
}

#[test]
fn all_operator_reasons_select_their_tiers_and_default_deadlines() {
    for (reason, typed, tier, seconds) in [
        (
            "approval-wait",
            ParkReason::ApprovalWait,
            StorageTier::Parked,
            86400,
        ),
        ("idle", ParkReason::Idle, StorageTier::Resident, 1800),
        (
            "host-shutdown",
            ParkReason::HostShutdown,
            StorageTier::Parked,
            172800,
        ),
        (
            "operator",
            ParkReason::Operator,
            StorageTier::Parked,
            172800,
        ),
        (
            "retention-demotion",
            ParkReason::RetentionDemotion,
            StorageTier::Cold,
            2592000,
        ),
    ] {
        let (_home, service) = fixture();
        open(&service);
        let before = now_unix();
        let parked = service
            .park(&ParkRequest {
                reason: reason.into(),
                retain_for: None,
                ..park_request()
            })
            .unwrap()
            .session;
        assert_eq!(parked.state, Residency::Hibernated);
        assert_eq!(parked.park_reason, Some(typed));
        assert_eq!(parked.storage_tier, Some(tier));
        assert_eq!(parked.journal_cursor, 7);
        assert!(
            (before + seconds..=now_unix() + seconds).contains(&parked.retain_until_unix.unwrap())
        );
        let shown = service.show("durable-test").unwrap();
        assert_eq!(shown.park_reason, parked.park_reason);
        assert_eq!(shown.storage_tier, parked.storage_tier);
        assert_eq!(shown.retain_until_unix, parked.retain_until_unix);
        assert!(matches!(
            shown.retention,
            Some(RetentionStatus::Alive { .. })
        ));
    }
}

#[test]
fn invalid_park_inputs_name_the_cause_and_preserve_record_bytes() {
    let (_home, service) = fixture();
    open(&service);
    let before = record_bytes(&service);
    let mut unknown = park_request();
    unknown.reason = "whenever".into();
    let error = service.park(&unknown).unwrap_err().to_string();
    for name in [
        "whenever",
        "approval-wait",
        "idle",
        "host-shutdown",
        "operator",
        "retention-demotion",
    ] {
        assert!(error.contains(name), "{error}");
    }
    for (request, expected) in [
        (
            ParkRequest {
                expected_generation: Some(4),
                ..park_request()
            },
            "at generation 1, not the expected 4",
        ),
        (
            ParkRequest {
                approval_head: Some("not-a-digest".into()),
                ..park_request()
            },
            "invalid --approval-head",
        ),
        (
            ParkRequest {
                retain_for: Some("forever".into()),
                ..park_request()
            },
            "invalid --retain-for",
        ),
    ] {
        let error = service.park(&request).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(record_bytes(&service), before);
    }
}

#[test]
fn park_retention_conflicts_and_unfenced_reparks_preserve_storage() {
    let (_home, service) = fixture();
    open(&service);
    let before = now_unix();
    let parked = service.park(&park_request()).unwrap();
    assert!(
        (before + 3600..=now_unix() + 3600).contains(&parked.session.retain_until_unix.unwrap())
    );
    let bytes = record_bytes(&service);
    for (request, expected) in [
        (
            ParkRequest {
                retain_for: Some("2h".into()),
                ..park_request()
            },
            "retain_for_secs: recorded 3600, retried 7200",
        ),
        (
            ParkRequest {
                expected_generation: None,
                ..park_request()
            },
            "not active",
        ),
    ] {
        let error = service.park(&request).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(record_bytes(&service), bytes);
    }
    let error = service
        .open(&OpenRequest {
            session_id: "durable-test".into(),
            resume_point: None,
            members: Vec::new(),
        })
        .unwrap_err();
    assert!(error.to_string().contains("already exists"));
    assert_eq!(record_bytes(&service), bytes);
}

fn renewal() -> RenewRequest {
    RenewRequest {
        session_id: "durable-test".into(),
        extend_for: "5h".into(),
        expected_deadline: None,
        expected_generation: None,
    }
}

#[test]
fn renewal_refusals_preserve_storage_and_name_the_reason() {
    let (_home, service) = fixture();
    open(&service);
    let bytes = record_bytes(&service);
    assert!(
        service
            .renew(&renewal())
            .unwrap_err()
            .to_string()
            .contains("not hibernated")
    );
    assert_eq!(record_bytes(&service), bytes);
    service.park(&park_request()).unwrap();
    let bytes = record_bytes(&service);
    for (duration, expected) in [("1m", "can only extend"), ("soon", "invalid --for")] {
        let error = service
            .renew(&RenewRequest {
                extend_for: duration.into(),
                ..renewal()
            })
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(record_bytes(&service), bytes);
    }
    // Seed historical state rather than introducing a second clock into the service.
    let id = parse_id("durable-test").unwrap();
    let mut record = service.sessions.load(&id).unwrap();
    record.retain_until_unix = Some(now_unix() - 1);
    service.sessions.write(&record).unwrap();
    let bytes = record_bytes(&service);
    let error = service.renew(&renewal()).unwrap_err();
    assert!(error.to_string().contains("past its promise"), "{error:#}");
    assert_eq!(record_bytes(&service), bytes);
    assert!(matches!(
        service.show("durable-test").unwrap().retention,
        Some(RetentionStatus::Expired { .. })
    ));
    record.state = mvm_runtime::agent_session::SandboxResidency::Closed;
    service.sessions.write(&record).unwrap();
    let bytes = record_bytes(&service);
    assert!(
        service
            .renew(&renewal())
            .unwrap_err()
            .to_string()
            .contains("closed")
    );
    assert_eq!(record_bytes(&service), bytes);
}

#[test]
fn resume_refuses_a_session_that_is_not_parked() {
    let (_home, service) = fixture();
    open(&service);
    let bytes = record_bytes(&service);
    let error = service.resume(&resume_request()).unwrap_err();
    assert!(error.to_string().contains("not parked"), "{error:#}");
    assert_eq!(record_bytes(&service), bytes);
}

fn verified_entries(
    home: &Path,
    tenant: &str,
) -> Vec<mvm_hostd::supervisor::audit::PlanAuditEntry> {
    let signer = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
    mvm_hostd::supervisor::audit_file::verify_audit_chain_entries(
        &home.join("audit").join(format!("{tenant}.jsonl")),
        &signer.signing.verifying_key(),
    )
    .unwrap()
}

#[test]
fn chained_park_and_renew_retries_preserve_signed_labels_and_write_once() {
    let (home, service) = fixture();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    service
        .open(&OpenRequest {
            session_id: "durable-test".into(),
            resume_point: Some(format!("sha256:{}", "ab".repeat(32))),
            members: vec!["vm-alpha".into()],
        })
        .unwrap();
    let mut record = service
        .sessions
        .load(&parse_id("durable-test").unwrap())
        .unwrap();
    record.approval_head =
        Some(ApprovalHead::parse(format!("sha256:{}", "cd".repeat(32))).unwrap());
    let material = ResumePlanMaterial {
        backend_name: "hvf".into(),
        image_name: "fixture".into(),
        image_sha256: "ab".repeat(32),
        kernel_sha256: None,
        cpus: 1,
        mem_mib: 128,
    };
    let labels = mvm_hostd::session_resume::synthesis_for_resume(&record, &material).audit_labels;
    for key in [
        "session_id",
        "session_generation",
        "session_parent_checkpoint",
        "session_approval_head",
    ] {
        assert!(labels.contains_key(key), "{labels:?}");
    }
    let mut plan = mvm_core::plan::signing::test_support::sample_plan();
    // Sentinel values ensure an accidental collision cannot hide behind equality.
    for key in labels.keys() {
        plan.audit_labels
            .insert(key.clone(), format!("signed-{key}"));
    }
    mvm_hostd::audit::plan_persist::write_plan("vm-alpha", &plan).unwrap();
    let request = ParkRequest {
        reason: "approval-wait".into(),
        ..park_request()
    };
    let parked = service.park(&request).unwrap();
    assert!(!parked.replayed && parked.warnings.is_empty(), "{parked:?}");
    let bytes = record_bytes(&service);
    assert!(service.park(&request).unwrap().replayed);
    assert_eq!(record_bytes(&service), bytes);
    let error = service
        .park(&ParkRequest {
            reason: "operator".into(),
            ..request
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("reason: recorded approval_wait, retried operator"),
        "{error:#}"
    );
    assert_eq!(record_bytes(&service), bytes);
    let request = RenewRequest {
        expected_deadline: parked.session.retain_until_unix,
        expected_generation: Some(1),
        ..renewal()
    };
    let before = now_unix();
    let renewed = service.renew(&request).unwrap();
    assert!(
        !renewed.replayed && renewed.warnings.is_empty(),
        "{renewed:?}"
    );
    assert!(
        (before + 5 * 3600..=now_unix() + 5 * 3600)
            .contains(&renewed.session.retain_until_unix.unwrap())
    );
    let bytes = record_bytes(&service);
    assert!(service.renew(&request).unwrap().replayed);
    assert_eq!(record_bytes(&service), bytes);
    let entries = verified_entries(home.path(), &plan.tenant.0);
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        for key in labels.keys() {
            assert_eq!(entry.labels.get(key), plan.audit_labels.get(key), "{key}");
        }
    }
    let park = &entries[0];
    assert_eq!(park.event, "session.parked");
    assert_eq!(park.labels["parked_session"], "durable-test");
    assert_eq!(park.labels["parked_at_generation"], "1");
    assert_eq!(park.labels["park_reason"], "approval-wait");
    assert_eq!(park.labels["park_storage_tier"], "parked");
    assert_eq!(
        park.labels["park_retain_until_unix"],
        parked.session.retain_until_unix.unwrap().to_string()
    );
    let renew = &entries[1];
    assert_eq!(renew.event, "session.renewed");
    assert_eq!(renew.labels["renewed_session"], "durable-test");
    assert_eq!(renew.labels["renewed_at_generation"], "1");
    assert_eq!(
        renew.labels["renewed_from_unix"],
        parked.session.retain_until_unix.unwrap().to_string()
    );
    assert_eq!(
        renew.labels["renewed_until_unix"],
        renewed.session.retain_until_unix.unwrap().to_string()
    );
}

#[cfg(feature = "test-support")]
#[test]
fn boot_refuses_parked_resident_and_active_sessions_without_mutation() {
    let (home, service) = fixture();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    open(&service);
    let active = service
        .sessions
        .load(&parse_id("durable-test").unwrap())
        .unwrap();
    for (reason, expected) in [
        (None, "not parked"),
        (Some("approval-wait"), "parked"),
        (Some("idle"), "resident"),
    ] {
        service.sessions.write(&active).unwrap();
        if let Some(reason) = reason {
            service
                .park(&ParkRequest {
                    reason: reason.into(),
                    ..park_request()
                })
                .unwrap();
        }
        let bytes = record_bytes(&service);
        let error = service
            .resume(&ResumeRequest {
                boot: true,
                backend: "mock".into(),
                ..resume_request()
            })
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains(expected), "{text}");
        if reason.is_some() {
            assert!(text.contains("not built"), "{text}");
        }
        assert_eq!(record_bytes(&service), bytes);
    }
}

#[cfg(feature = "test-support")]
fn install_runtime_overlay(home: &Path) {
    use mvm_build::runtime_overlay::{InstallOptions, install_overlay_into_cache};
    use mvm_fs::ext4::{Node, Owner};
    use mvm_fs::overlay::{REQUIRED_OVERLAY_GUEST_PATHS, read_overlay_artifact_from_dir};
    let source = home.join("runtime-overlay-source");
    std::fs::create_dir_all(&source).unwrap();
    let nodes = REQUIRED_OVERLAY_GUEST_PATHS
        .iter()
        .map(|path| Node::File {
            path: path.to_string(),
            mode: 0o755,
            data: b"session-resume-runtime-stub".to_vec(),
            xattrs: Vec::new(),
            owner: Owner::ROOT,
        })
        .collect();
    std::fs::write(
        source.join("overlay.ext4"),
        mvm_fs::ext4::build_image(nodes, &Default::default()).unwrap(),
    )
    .unwrap();
    std::fs::write(source.join("overlay.verity"), b"verity-sidecar").unwrap();
    std::fs::write(
        source.join("overlay.roothash"),
        format!("{}\n", "ab".repeat(32)),
    )
    .unwrap();
    std::fs::write(
        source.join("VERSION"),
        format!("{}\n", env!("CARGO_PKG_VERSION")),
    )
    .unwrap();
    let artifact = read_overlay_artifact_from_dir(&source, std::env::consts::ARCH).unwrap();
    install_overlay_into_cache(
        &artifact,
        &home.join("cache"),
        &InstallOptions { overwrite: true },
    )
    .unwrap();
}

#[cfg(feature = "test-support")]
#[test]
fn cold_boot_starts_the_session_and_exact_retry_never_boots_again() {
    let (home, service) = fixture();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    mvm_core::user_config::save(&mvm_core::user_config::MvmConfig::default(), None).unwrap();
    install_runtime_overlay(home.path());
    let parent = seed_resume_point(&service, home.path());
    service
        .open(&OpenRequest {
            session_id: "durable-test".into(),
            resume_point: Some(parent.meta_digest.to_string()),
            members: Vec::new(),
        })
        .unwrap();
    service
        .park(&ParkRequest {
            reason: "retention-demotion".into(),
            ..park_request()
        })
        .unwrap();
    assert_eq!(
        service.show("durable-test").unwrap().storage_tier,
        Some(StorageTier::Cold)
    );
    let kernel = home.path().join("vmlinux");
    std::fs::write(&kernel, b"stub-kernel").unwrap();
    let request = ResumeRequest {
        boot: true,
        backend: "mock".into(),
        kernel_sha256: Some(mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap()),
        kernel: Some(kernel),
        ..resume_request()
    };
    let booted = service.resume(&request).unwrap();
    assert_eq!(booted.session.state, Residency::Active);
    assert_eq!(booted.session.generation, 2);
    assert_eq!(booted.booted_sandbox.as_deref(), Some("durable-test"));
    assert_eq!(service.show("durable-test").unwrap().generation, 2);
    let bytes = record_bytes(&service);
    let chain_before = std::fs::read(home.path().join("audit/local.jsonl")).unwrap();
    let error = service.resume(&request).unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("already applied") && text.contains("never boots a second sandbox"),
        "{text}"
    );
    assert!(
        text.contains(booted.admitted_plan_id.as_deref().unwrap()),
        "{text}"
    );
    assert_eq!(record_bytes(&service), bytes);
    assert_eq!(
        std::fs::read(home.path().join("audit/local.jsonl")).unwrap(),
        chain_before
    );
    let entries = verified_entries(home.path(), "local");
    let resumed: Vec<_> = entries
        .iter()
        .filter(|entry| entry.event == "session.resumed")
        .collect();
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].plan_id.0, booted.admitted_plan_id.unwrap());
}

#[cfg(feature = "schema")]
#[test]
fn owned_requests_and_reports_have_schemas() {
    let _ = schemars::schema_for!(OpenRequest);
    let _ = schemars::schema_for!(ParkRequest);
    let _ = schemars::schema_for!(RenewRequest);
    let _ = schemars::schema_for!(ResumeRequest);
    let _ = schemars::schema_for!(SessionReport);
    let _ = schemars::schema_for!(TransitionReport);
}
