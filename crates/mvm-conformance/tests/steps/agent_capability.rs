//! BDD witnesses for typed capability descriptor and binding invariants.

use cucumber::{given, then, when};
use mvm_contract::protocol::agent_capability::{
    CapabilityAuditEvent, CapabilityDescriptor, CapabilityFailureCode, CapabilityId,
    CapabilityInvocation, CapabilityLimits, SchemaRef,
};
use mvm_contract::protocol::agent_session::AgentRequestId;
use mvm_contract::protocol::broker::ServiceId;

use crate::world::CliWorld;

fn descriptor() -> CapabilityDescriptor {
    CapabilityDescriptor::builder()
        .id(CapabilityId::new(
            ServiceId::parse("host.dev.echo.v1").expect("valid BDD service"),
            "echo",
        )
        .expect("valid BDD capability"))
        .description("echo a bounded structured value")
        .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("valid schema"))
        .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("valid schema"))
        .limits(CapabilityLimits::new(1024, 1024, 100).expect("valid limits"))
        .build()
        .expect("valid descriptor")
}

#[given("an admitted typed echo capability")]
fn admitted_typed_capability(world: &mut CliWorld) {
    world.capability_descriptor = Some(descriptor());
    world.capability_outcome = None;
    world.capability_audit_json = None;
}

#[when(expr = "I create a typed invocation for the private value {string}")]
fn create_typed_invocation(world: &mut CliWorld, value: String) {
    let descriptor = world
        .capability_descriptor
        .as_ref()
        .expect("the capability must be admitted first");
    let payload = serde_json::json!({"value": value});
    let invocation = CapabilityInvocation::from_payload(
        descriptor.binding(),
        AgentRequestId::parse("bdd-capability-request").expect("valid request id"),
        &payload,
    )
    .expect("create typed invocation");
    world.capability_outcome = Some(invocation.validate_payload(descriptor, &payload));
    world.capability_invocation = Some(invocation.clone());
    world.capability_audit_json = Some(
        serde_json::to_string(&CapabilityAuditEvent::Invoked {
            capability: descriptor.id.clone(),
            descriptor_digest: descriptor.digest(),
            invocation_id: invocation.invocation_id,
            input_digest: invocation.input_digest,
        })
        .expect("serialize capability audit"),
    );
}

#[then("the typed invocation is valid")]
fn typed_invocation_is_valid(world: &mut CliWorld) {
    assert_eq!(world.capability_outcome, Some(Ok(())));
}

#[then("the capability audit excludes the private value")]
fn capability_audit_excludes_private_value(world: &mut CliWorld) {
    let audit = world
        .capability_audit_json
        .as_ref()
        .expect("the invocation must produce audit evidence");
    assert!(!audit.contains("private credential"));
    assert!(audit.contains("input_digest"));
}

#[when("I change the admitted descriptor limits")]
fn change_descriptor_limits(world: &mut CliWorld) {
    let descriptor = world
        .capability_descriptor
        .as_mut()
        .expect("the capability must be admitted first");
    descriptor.limits = CapabilityLimits::new(1024, 1024, 101).expect("valid changed limits");
    let payload = serde_json::json!({"value": "bounded"});
    let invocation = CapabilityInvocation::from_payload(
        descriptor.binding(),
        AgentRequestId::parse("bdd-capability-request-2").expect("valid request id"),
        &payload,
    )
    .expect("create typed invocation");
    let mut admitted_binding = descriptor.binding();
    admitted_binding.descriptor_digest[0] ^= 1;
    let mut downgraded = invocation;
    downgraded.binding = admitted_binding;
    world.capability_outcome = Some(downgraded.validate_payload(descriptor, &payload));
}

#[then("the typed invocation is refused for a binding mismatch")]
fn typed_invocation_binding_mismatch(world: &mut CliWorld) {
    assert_eq!(
        world.capability_outcome,
        Some(Err(CapabilityFailureCode::BindingMismatch))
    );
}
