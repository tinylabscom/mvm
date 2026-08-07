//! Steps for the secrets-and-PII witness: stored secrets have no public
//! reveal path, and outbound PII is redacted before it can leave the host.
//!
//! Both scenarios are hermetic: the secret service is built against isolated
//! temp stores, and the PII redactor is the same pure-Rust inspector the
//! egress proxy uses.

use cucumber::{given, then, when};
use mvm_client::secret::{SecretBindingMeta, SecretService, SecretValueInput};
use mvm_contract::ir::AuthType;
use mvm_core::crypto::secret_store::FileSecretStore;
use mvm_core::pii::PiiRedactor;
use mvm_hostd::keyholder::FileBindingStore;

use crate::world::CliWorld;

fn secret_service(tmp: &std::path::Path) -> SecretService {
    SecretService::builder()
        .store(std::sync::Arc::new(FileSecretStore::with_dir(
            tmp.join("secrets"),
        )))
        .bindings(std::sync::Arc::new(FileBindingStore::with_dir(
            tmp.join("bindings"),
        )))
        .machines_root(tmp.join("machines"))
        .build()
        .expect("build isolated secret service")
}

#[given(expr = "a bound secret {string} with value {string} in tenant {string}")]
fn given_bound_secret(world: &mut CliWorld, name: String, value: String, tenant: String) {
    let tmp = tempfile::tempdir().expect("create isolated secret store temp dir");
    let service = secret_service(tmp.path());

    service
        .put(&tenant, &name, SecretValueInput::new(value.clone()))
        .expect("store secret value");

    let binding = SecretBindingMeta {
        auth_type: AuthType::Bearer,
        allowed_hosts: vec!["example.com".to_string()],
        sigv4: None,
    };
    service
        .bind(&tenant, &name, binding)
        .expect("bind secret to a destination");

    world.secret_tmp = Some(tmp);
    world.secret_name = Some(name);
    world.secret_tenant = Some(tenant);
    world.secret_value = Some(value);
}

#[when("the secret metadata is queried")]
fn query_secret_metadata(world: &mut CliWorld) {
    let tmp = world
        .secret_tmp
        .as_ref()
        .expect("secret store temp dir must exist");
    let service = secret_service(tmp.path());
    let tenant = world.secret_tenant.as_ref().expect("tenant set");
    let name = world.secret_name.as_ref().expect("secret name set");
    let metadata = service
        .metadata(tenant, name)
        .expect("query metadata")
        .unwrap_or_else(|| panic!("secret {name} in tenant {tenant} must exist"));
    world.secret_metadata_json =
        Some(serde_json::to_string(&metadata).expect("serialize metadata"));
}

#[then("the metadata does not contain the raw secret value")]
fn metadata_has_no_raw_value(world: &mut CliWorld) {
    let json = world
        .secret_metadata_json
        .as_ref()
        .expect("metadata must be queried first");
    let value = world
        .secret_value
        .as_ref()
        .expect("secret value must be stored first");
    assert!(
        !json.contains(value),
        "secret metadata must not contain the raw value; got {json}"
    );
}

#[then("the metadata names the secret and its bound destination")]
fn metadata_names_secret_and_binding(world: &mut CliWorld) {
    let json = world
        .secret_metadata_json
        .as_ref()
        .expect("metadata must be queried first");
    let name = world.secret_name.as_ref().expect("secret name set");
    assert!(
        json.contains(&format!("\"name\":\"{name}\""))
            || json.contains(&format!("\"name\": \"{name}\"")),
        "metadata must name the secret; got {json}"
    );
    assert!(
        json.contains("example.com"),
        "metadata must include the bound destination; got {json}"
    );
}

#[given("an outbound body containing PII")]
fn outbound_body_with_pii(world: &mut CliWorld) {
    world.pii_body = Some("contact: alice@example.com ssn: 123-45-6789".to_string());
}

#[when("the body is redacted by the egress PII redactor")]
fn redact_pii(world: &mut CliWorld) {
    let body = world
        .pii_body
        .as_ref()
        .expect("PII body must be set")
        .as_bytes();
    let redactor = PiiRedactor::with_default_rules();
    let (out, fired) = redactor.redact(body);
    world.pii_redacted = Some(String::from_utf8_lossy(&out).to_string());
    world.pii_fired_rules = Some(fired.into_iter().map(|s| s.to_string()).collect());
}

#[then("the redacted body does not contain the original PII")]
fn redacted_body_lacks_pii(world: &mut CliWorld) {
    let redacted = world
        .pii_redacted
        .as_ref()
        .expect("body must be redacted first");
    assert!(
        !redacted.contains("alice@example.com"),
        "email PII must be removed; got {redacted}"
    );
    assert!(
        !redacted.contains("123-45-6789"),
        "SSN PII must be removed; got {redacted}"
    );
}

#[then("the redacted body contains the redaction mask")]
fn redacted_body_contains_mask(world: &mut CliWorld) {
    let redacted = world
        .pii_redacted
        .as_ref()
        .expect("body must be redacted first");
    assert!(
        redacted.contains("XXX"),
        "redacted body must contain the mask; got {redacted}"
    );
}

#[then("the PII redactor reports the categories it masked")]
fn redactor_reports_categories(world: &mut CliWorld) {
    let fired = world
        .pii_fired_rules
        .as_ref()
        .expect("redaction must run first");
    assert!(fired.contains(&"email".to_string()), "email rule must fire");
    assert!(
        fired.contains(&"us_ssn".to_string()),
        "us_ssn rule must fire"
    );
}
