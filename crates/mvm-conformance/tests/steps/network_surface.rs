//! Hermetic witnesses for the single public FlowMux networking surface.

use cucumber::then;
use mvm_contract::protocol::network_flow::{FlowClass, Opcode};

use crate::world::CliWorld;

#[then("the generated schema and SDK models omit the retired raw stack field")]
fn generated_surfaces_omit_raw_stack(_world: &mut CliWorld) {
    let root = workspace_root();
    for relative in [
        "schema/workload-ir-v0.json",
        "crates/mvm-sdk/sdks/python/mvm/_ir/workload.py",
        "crates/mvm-sdk/sdks/typescript/src/ir/workload.ts",
    ] {
        let text = std::fs::read_to_string(root.join(relative)).expect("read generated surface");
        assert!(
            !text.contains("raw_ip_stack") && !text.contains("rawIpStack"),
            "{relative} still exposes the retired raw stack field"
        );
    }
}

#[then("stale workload IR naming the retired raw stack is refused with adapter guidance")]
fn stale_ir_is_refused(_world: &mut CliWorld) {
    let err = serde_json::from_str::<mvm_contract::ir::Network>(
        r#"{"mode":"bridge","raw_ip_stack":true}"#,
    )
    .expect_err("the retired field must not enter the IR domain");
    let message = err.to_string();
    assert!(
        message.contains("raw_ip_stack has been retired"),
        "{message}"
    );
    assert!(message.contains("SOCKS5h/UDP"), "{message}");
    assert!(message.contains("typed connector"), "{message}");
}

#[then("a stale signed plan naming the retired L3 mode is refused at deserialization")]
fn stale_plan_is_refused(_world: &mut CliWorld) {
    let err = serde_json::from_str::<mvm_contract::plan::NetworkMode>(r#""l3_vsock""#)
        .expect_err("the retired value must not enter the admitted domain");
    let message = err.to_string();
    assert!(message.contains("l3_vsock has been retired"), "{message}");
    assert!(message.contains("FlowMux loopback adapters"), "{message}");
}

#[then("FlowMux exposes TCP, UDP, DNS, mediated ping, HTTP proxy, and typed HTTP classes")]
fn supported_adapters_have_flow_classes(_world: &mut CliWorld) {
    assert_eq!(Opcode::OpenTcp.class(), FlowClass::Tcp);
    assert_eq!(Opcode::OpenUdp.class(), FlowClass::Udp);
    assert_eq!(Opcode::Resolve.class(), FlowClass::Dns);
    assert_eq!(Opcode::IcmpEcho.class(), FlowClass::Icmp);
    assert_eq!(Opcode::OpenHttp.class(), FlowClass::Http);
    assert_eq!(
        mvm_agentd::forward_proxy::proxy_env_url(),
        "http://127.0.0.1:18080"
    );
}

#[then("a typed HTTP connector is classified separately from opaque TCP")]
fn typed_http_is_distinct(_world: &mut CliWorld) {
    assert_eq!(Opcode::OpenHttp.class(), FlowClass::Http);
    assert_ne!(Opcode::OpenHttp.class(), Opcode::OpenTcp.class());
}

#[then("a networked workload requires a backend with no routable guest NIC")]
fn direct_socket_fails_closed(_world: &mut CliWorld) {
    let machine = mvm_runtime::machine::Machine::builder()
        .image("alpine")
        .network(mvm_runtime::machine::NetworkMode::HostVsockProxy)
        .build()
        .expect("build networked machine");
    let required = machine.required_capabilities();
    assert!(required.host_vsock_proxy);
    assert!(required.no_routable_guest_nic);
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("conformance crate is two levels below workspace root")
        .to_path_buf()
}
