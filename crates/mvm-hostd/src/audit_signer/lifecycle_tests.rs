use std::path::PathBuf;

use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, RegisteredUnit, SignerHelperAppendLifecycleEntry,
    SignerHelperRegisterVm, SignerHelperRequest, SignerHelperResponse,
};
use mvm_core::protocol::lifecycle_audit::{
    LifecycleEvent, LifecycleLabel, LifecycleLabels, MAX_LIFECYCLE_LABEL_BYTES,
};

use super::*;
use crate::audit::audit_file::verify_audit_chain;
use crate::audit_signer::helper::SignerHelper;

const TENANT: &str = "acme";
const UNIT: &str = "controller";

fn registered() -> RegisteredUnit {
    RegisteredUnit {
        unit: UNIT.into(),
        epoch: ExecutionEpoch::FIRST,
    }
}

/// A host with its own `MVM_HOME` and host signer. One per test.
struct Host {
    _env: mvm_core::util::test_env::TestEnv,
    home: tempfile::TempDir,
    signer: crate::audit::host_keypair::HostSigner,
    key_path: PathBuf,
}

impl Host {
    fn new() -> Self {
        let (env, home) = crate::test_fixtures::isolated_mvm_home();
        let keys = mvm_core::config::mvm_keys_dir_at(home.path());
        let signer = crate::audit::host_keypair::load_or_init_at(&keys).expect("host signer");
        let key_path = keys.join("host-signer.ed25519");
        assert!(
            key_path.exists(),
            "the host key lives at {}",
            key_path.display()
        );
        Self {
            _env: env,
            home,
            signer,
            key_path,
        }
    }

    fn chain(&self, tenant: &str) -> PathBuf {
        self.home
            .path()
            .join("audit")
            .join(format!("{tenant}.jsonl"))
    }

    fn helper(&self) -> SignerHelper {
        let mut helper = SignerHelper::new(TENANT, Some(self.key_path.clone()));
        self.register(&mut helper, "vm-1", Some(registered()));
        helper
    }

    fn register(&self, helper: &mut SignerHelper, vm_id: &str, unit: Option<RegisteredUnit>) {
        let dir = self.home.path().join("audit");
        let path = |name: String| dir.join(name).to_string_lossy().into_owned();
        let registered = helper.dispatch(SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: "reg".into(),
            vm_id: vm_id.into(),
            tenant_id: TENANT.into(),
            workload_id: format!("wl-{vm_id}"),
            workload_chain_path: path(format!("{TENANT}.{vm_id}.workload.jsonl")),
            chain_head_secondary_path: path(format!("{vm_id}.head")),
            unit,
        }));
        assert!(matches!(
            registered,
            SignerHelperResponse::Registered { .. }
        ));
    }

    fn entries(&self, tenant: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.chain(tenant))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["entry"].clone())
            .collect()
    }
}

fn refusal(tenant: &str, labels: &[(LifecycleLabel, &str)]) -> LifecycleEntry {
    LifecycleEntry {
        tenant_id: tenant.into(),
        event: LifecycleEvent::StateCellRefused,
        labels: labels
            .iter()
            .map(|(k, v)| (*k, (*v).to_string()))
            .collect::<LifecycleLabels>(),
    }
}

fn through_helper(
    helper: &mut SignerHelper,
    vm_id: &str,
    entry: LifecycleEntry,
) -> SignerHelperResponse {
    helper.dispatch(SignerHelperRequest::AppendLifecycleEntry(
        SignerHelperAppendLifecycleEntry {
            request_id: "life".into(),
            vm_id: vm_id.into(),
            entry,
        },
    ))
}

fn refused_code(response: SignerHelperResponse) -> AuditSignerErrorCode {
    match response {
        SignerHelperResponse::Err { code, .. } => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn helper_and_emitter_writes_interleave_on_one_verifiable_tenant_chain() {
    let host = Host::new();
    let mut helper = host.helper();
    let emitter = AuditEmitter::new(host.signer.signing.clone()).unwrap();
    for n in 0..3 {
        emitter
            .emit_topology_decision(
                &TenantId(TENANT.into()),
                "topology.admitted",
                [("generation".to_string(), n.to_string())],
            )
            .unwrap();
        let entry = refusal(
            TENANT,
            &[
                (LifecycleLabel::Cell, "setpoint"),
                (LifecycleLabel::Reason, "no"),
            ],
        );
        assert!(matches!(
            through_helper(&mut helper, "vm-1", entry),
            SignerHelperResponse::LifecycleAppended { .. }
        ));
    }
    let verifying = host.signer.signing.verifying_key();
    assert_eq!(
        verify_audit_chain(&host.chain(TENANT), &verifying).unwrap(),
        6
    );
    let events: Vec<_> = host
        .entries(TENANT)
        .iter()
        .map(|e| e["event"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        events,
        [
            "topology.admitted",
            "state_cell.refused",
            "topology.admitted",
            "state_cell.refused",
            "topology.admitted",
            "state_cell.refused"
        ]
    );
    assert_eq!(host.entries(TENANT)[1]["labels"]["cell"], "setpoint");
    assert_eq!(
        host.entries(TENANT)[1]["labels"]["unit"],
        UNIT,
        "the registered unit"
    );
    assert_eq!(host.entries(TENANT)[1]["labels"]["epoch"], "1");
}

#[test]
fn another_tenants_chain_and_an_unregistered_vm_are_refused() {
    let host = Host::new();
    let mut helper = host.helper();
    assert_eq!(
        refused_code(through_helper(&mut helper, "vm-1", refusal("other", &[]))),
        AuditSignerErrorCode::InvalidRequest
    );
    assert_eq!(
        refused_code(through_helper(&mut helper, "vm-9", refusal(TENANT, &[]))),
        AuditSignerErrorCode::NotReady
    );
    assert!(!host.chain("other").exists());
    assert!(host.entries(TENANT).is_empty());
}

#[test]
fn labels_outside_the_event_or_over_the_bound_are_refused() {
    let host = Host::new();
    let mut helper = host.helper();
    let liveness_with_cell = LifecycleEntry {
        tenant_id: TENANT.into(),
        event: LifecycleEvent::LivenessSignalRefused,
        labels: LifecycleLabels::from([(LifecycleLabel::Cell, "c".to_string())]),
    };
    let long = "x".repeat(MAX_LIFECYCLE_LABEL_BYTES + 1);
    for entry in [
        liveness_with_cell,
        refusal(TENANT, &[(LifecycleLabel::Reason, &long)]),
    ] {
        assert_eq!(
            refused_code(through_helper(&mut helper, "vm-1", entry)),
            AuditSignerErrorCode::InvalidRequest
        );
    }
    assert!(host.entries(TENANT).is_empty());
}

#[test]
fn an_event_or_label_outside_the_closed_set_does_not_parse() {
    for request in [
        serde_json::json!({
            "verb": "append_lifecycle_entry", "request_id": "r", "vm_id": "vm-1",
            "entry": {"tenant_id": TENANT, "event": "plan.admitted", "labels": {}}
        }),
        serde_json::json!({
            "verb": "append_lifecycle_entry", "request_id": "r", "vm_id": "vm-1",
            "entry": {"tenant_id": TENANT, "event": "state_cell.refused", "labels": {"image": "x"}}
        }),
        serde_json::json!({
            "verb": "append_lifecycle_entry", "request_id": "r", "vm_id": "vm-1", "extra": 1,
            "entry": {"tenant_id": TENANT, "event": "state_cell.refused", "labels": {}}
        }),
    ] {
        assert!(serde_json::from_value::<SignerHelperRequest>(request).is_err());
    }
}

#[test]
fn a_signer_without_a_key_file_refuses() {
    let host = Host::new();
    assert_eq!(
        append(TENANT, Some(&registered()), None, &refusal(TENANT, &[])),
        Err(AuditSignerErrorCode::NotReady)
    );
    assert!(!host.chain(TENANT).exists());
}

#[tokio::test]
async fn the_per_vm_audit_signer_serves_its_own_tenant_only() {
    use crate::audit_signer::server::{LifecycleScope, serve_on_listener};
    let host = Host::new();
    let dir = host.home.path().join("audit");
    std::fs::create_dir_all(&dir).unwrap();
    let chain = crate::audit_signer::chain::Chain::open(
        &dir.join(format!("{TENANT}.vm-1.workload.jsonl")),
        &dir.join("vm-1.head"),
        Some(&host.key_path),
    )
    .unwrap();
    let socket = host.home.path().join("s.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(serve_on_listener(
        listener,
        std::sync::Arc::new(tokio::sync::Mutex::new(chain)),
        std::sync::Arc::new(LifecycleScope {
            tenant_id: TENANT.into(),
            unit: Some(registered()),
            key_path: Some(host.key_path.clone()),
        }),
        "wl-1".into(),
        65_536,
    ));
    let client = crate::audit::audit_client::AuditClient::new(&socket);
    let send = |tenant: &str| AppendEntryRequest::AppendLifecycleEntry {
        request_id: "r".into(),
        entry: refusal(tenant, &[(LifecycleLabel::Unit, UNIT)]),
    };
    assert!(matches!(
        client.append(&send(TENANT)).await.unwrap(),
        AppendEntryResponse::LifecycleAppended { .. }
    ));
    assert!(matches!(
        client.append(&send("other")).await.unwrap(),
        AppendEntryResponse::Err {
            code: AuditSignerErrorCode::InvalidRequest,
            ..
        }
    ));
    server.abort();
    let verifying = host.signer.signing.verifying_key();
    assert_eq!(
        verify_audit_chain(&host.chain(TENANT), &verifying).unwrap(),
        1
    );
    assert!(!host.chain("other").exists());
}

#[test]
fn an_entry_naming_another_unit_or_epoch_is_refused() {
    let host = Host::new();
    let mut helper = host.helper();
    for labels in [
        [(LifecycleLabel::Unit, "reader")],
        [(LifecycleLabel::Epoch, "2")],
    ] {
        assert_eq!(
            refused_code(through_helper(
                &mut helper,
                "vm-1",
                refusal(TENANT, &labels)
            )),
            AuditSignerErrorCode::InvalidRequest
        );
    }
    assert!(matches!(
        through_helper(
            &mut helper,
            "vm-1",
            refusal(TENANT, &[(LifecycleLabel::Unit, UNIT)])
        ),
        SignerHelperResponse::LifecycleAppended { .. }
    ));
    let entries = host.entries(TENANT);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["labels"]["unit"], UNIT);
}

#[test]
fn a_vm_registered_without_a_unit_cannot_append() {
    let host = Host::new();
    let mut helper = SignerHelper::new(TENANT, Some(host.key_path.clone()));
    host.register(&mut helper, "vm-2", None);
    assert_eq!(
        refused_code(through_helper(&mut helper, "vm-2", refusal(TENANT, &[]))),
        AuditSignerErrorCode::NotReady
    );
    assert!(host.entries(TENANT).is_empty());
}

/// The largest line one lifecycle entry can put on the chain, which bounds
/// what a guest's refusals can cost per entry.
#[test]
fn a_full_entry_is_a_bounded_line() {
    let host = Host::new();
    let mut helper = host.helper();
    let full = "x".repeat(MAX_LIFECYCLE_LABEL_BYTES);
    let entry = LifecycleEntry {
        tenant_id: TENANT.into(),
        event: LifecycleEvent::StateCellRefused,
        labels: [
            LifecycleLabel::Operation,
            LifecycleLabel::Cell,
            LifecycleLabel::Reason,
            LifecycleLabel::Suppressed,
        ]
        .into_iter()
        .map(|label| (label, full.clone()))
        .collect(),
    };
    assert!(matches!(
        through_helper(&mut helper, "vm-1", entry),
        SignerHelperResponse::LifecycleAppended { .. }
    ));
    let line = std::fs::read_to_string(host.chain(TENANT)).unwrap();
    assert!(
        line.len() <= 11 * 1024,
        "a full entry is {} bytes",
        line.len()
    );
}
