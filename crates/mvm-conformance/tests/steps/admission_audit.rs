//! Steps for admission-audit witnesses: a signed execution plan is recorded as
//! a chain-signed audit entry, and tampering with that chain is detected on
//! verify.

use cucumber::{given, then, when};
use mvm_core::plan::test_support::PlanFixture;
use mvm_hostd::audit::{
    emitter::AuditEmitter,
    host_keypair::{self, HostSigner},
};

use crate::world::CliWorld;

fn isolated_home(world: &CliWorld) -> &std::path::Path {
    world
        .isolated_home
        .as_ref()
        .expect("a Given step must isolate the mvm home")
        .path()
}

/// Load (or create) the host signer in the isolated home so the same key is
/// used to sign the audit entry and to verify it through the CLI.
fn host_signer(world: &CliWorld) -> HostSigner {
    let keys_dir = isolated_home(world).join("keys");
    host_keypair::load_or_init_at(&keys_dir).expect("load or init host signer")
}

#[given("a workload plan was admitted in the audit chain")]
fn admit_plan_to_audit_chain(world: &mut CliWorld) {
    let home = isolated_home(world).to_path_buf();
    let signer = host_signer(world);
    let audit_dir = home.join("audit");
    let emitter = AuditEmitter::with_dir(signer.signing, &audit_dir)
        .expect("open audit emitter in isolated home");
    let plan = PlanFixture::new()
        .tenant("local")
        .plan_id("bdd-admitted")
        .build();
    emitter
        .emit_admitted(&plan, "host:test")
        .expect("emit plan.admitted entry");
}

#[when("the audit chain is tampered")]
fn tamper_audit_chain(world: &mut CliWorld) {
    let chain_path = isolated_home(world).join("audit").join("local.jsonl");
    let content = std::fs::read_to_string(&chain_path).expect("read audit chain");
    // Mutate the signed payload without touching the signature. Any byte
    // change in the entry invalidates the Ed25519 signature, so verification
    // must fail closed.
    let tampered = content.replacen("plan.admitted", "plan.hijacked", 1);
    assert_ne!(
        tampered, content,
        "the audit chain content must change after tampering"
    );
    std::fs::write(&chain_path, tampered).expect("write tampered audit chain");
}

#[then("the audit chain verifies clean")]
fn audit_chain_verifies_clean(world: &mut CliWorld) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "expected audit verify to succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("verifies clean"),
        "expected 'verifies clean' in output; got:\n{stdout}"
    );
}

#[then("the audit chain verify fails with a tampering error")]
fn audit_chain_tamper_refused(world: &mut CliWorld) {
    let output = world.last_output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected audit verify to fail on a tampered chain"
    );
    assert!(
        stderr.contains("verify failed") || stderr.contains("signature"),
        "expected a verify/signature refusal, got stderr:\n{stderr}"
    );
}
