//! `machine.run` and `machine.create`: boot or define a machine through the
//! local client's admitted launch.
//!
//! Both methods build an `mvm_client::LaunchRequest` and hand it to
//! `LocalBackend`, the same admitted-boot seam every in-process launcher uses:
//! the plan is synthesized, signed, verified, window- and replay-checked and
//! chain-audited before a byte of launch config reaches the backend. Nothing
//! here decides what a launch may do. The request builder validates every
//! field, and a field the launcher cannot honour yet — a command override, a
//! guest environment — is refused there with its own reason, so a binding
//! hears the same refusal a Rust caller would rather than a second opinion.

use std::collections::BTreeMap;

use mvm_client::{LaunchRequest, LaunchRequestBuilder, LifecycleMode, LocalBackend, MachineState};
use mvm_core::client::MvmError;
use mvm_core::rootfs_source::RootfsSource;
use serde::{Deserialize, Serialize};

use crate::status::Outcome;

/// Boots a machine. Request: a [`RunRequest`]. Reply: a [`RunReply`].
pub const MACHINE_RUN: &str = "machine.run";
/// Persists a machine definition without booting it. Request: a
/// [`CreateRequest`]. Reply: a `MachineState`.
pub const MACHINE_CREATE: &str = "machine.create";

/// Every launch method.
pub const METHODS: [&str; 2] = [MACHINE_RUN, MACHINE_CREATE];

/// Whether `method` is a launch method, checked before a backend is built.
pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Whether the machine outlives the caller's session.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunMode {
    /// Boots without a persisted definition; cleaned up when it exits or its
    /// TTL lapses.
    #[default]
    Transient,
    /// Persists a definition under the machine's name, then boots it.
    Persistent,
}

impl From<RunMode> for LifecycleMode {
    fn from(mode: RunMode) -> Self {
        match mode {
            RunMode::Transient => LifecycleMode::Transient,
            RunMode::Persistent => LifecycleMode::Persistent,
        }
    }
}

/// One outbound destination the workload may reach. Each one lands in the
/// signed plan's egress grant, which is what the host egress gate reads.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressTarget {
    host: String,
    port: u16,
}

/// A `machine.run` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunRequest {
    /// What to boot: an OCI reference (optionally `oci:`-prefixed), an
    /// absolute or `./`-relative rootfs path, or `flake:<ref>#<attr>`.
    image: String,
    #[serde(default)]
    mode: RunMode,
    /// Required for a persistent machine; generated for a transient one.
    #[serde(default)]
    name: Option<String>,
    /// Command override. The in-process launcher refuses a non-empty one.
    #[serde(default)]
    command: Vec<String>,
    /// Guest environment. The in-process launcher refuses a non-empty one.
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    cpus: Option<u32>,
    #[serde(default)]
    memory_mib: Option<u32>,
    /// Security profile; `standard` when absent.
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    /// Opaque TCP ingress, each written `host:guest`.
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    egress: Vec<EgressTarget>,
    /// Hypervisor override; the host's default when absent.
    #[serde(default)]
    backend: Option<String>,
    /// Persistent only: recreate a same-name definition whose config differs.
    #[serde(default)]
    force: bool,
}

/// A `machine.create` request: a persistent definition, never booted here.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateRequest {
    name: String,
    image: String,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    cpus: Option<u32>,
    #[serde(default)]
    memory_mib: Option<u32>,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    egress: Vec<EgressTarget>,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    force: bool,
}

/// A `machine.run` reply.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct RunReply {
    machine: MachineState,
    /// Content-addressed id of the admitted plan, for correlating with the
    /// chain-signed audit log.
    plan_id: String,
    /// `dev` or `prod`, resolved fail-closed the way the machine inventory
    /// resolves it. Only `dev` admits the DevOnly `guest.*` methods.
    build_mode: String,
}

/// The fields both requests share, in the order the builder takes them.
struct LaunchFields {
    mode: LifecycleMode,
    image: String,
    name: Option<String>,
    command: Vec<String>,
    env: BTreeMap<String, String>,
    cpus: Option<u32>,
    memory_mib: Option<u32>,
    profile: Option<String>,
    ttl_seconds: Option<u64>,
    ports: Vec<String>,
    egress: Vec<EgressTarget>,
    backend: Option<String>,
    force: bool,
}

impl From<RunRequest> for LaunchFields {
    fn from(r: RunRequest) -> Self {
        Self {
            mode: r.mode.into(),
            image: r.image,
            name: r.name,
            command: r.command,
            env: r.env,
            cpus: r.cpus,
            memory_mib: r.memory_mib,
            profile: r.profile,
            ttl_seconds: r.ttl_seconds,
            ports: r.ports,
            egress: r.egress,
            backend: r.backend,
            force: r.force,
        }
    }
}

impl From<CreateRequest> for LaunchFields {
    fn from(r: CreateRequest) -> Self {
        Self {
            mode: LifecycleMode::Persistent,
            image: r.image,
            name: Some(r.name),
            command: r.command,
            env: r.env,
            cpus: r.cpus,
            memory_mib: r.memory_mib,
            profile: r.profile,
            ttl_seconds: None,
            ports: r.ports,
            egress: r.egress,
            backend: r.backend,
            force: r.force,
        }
    }
}

/// Parse a rootfs declaration, refusing one that names nothing as an invalid
/// spec — the same class of refusal the builder gives every other field.
fn parse_image(image: &str) -> Result<RootfsSource, Outcome> {
    image.parse().map_err(|e| {
        Outcome::from(MvmError::InvalidSpec {
            reason: format!("image {image:?} names no rootfs source: {e}"),
        })
    })
}

/// Hand every field to the builder, which owns validation.
fn builder_for(fields: LaunchFields) -> Result<LaunchRequestBuilder, Outcome> {
    let mut builder = LaunchRequest::builder(fields.mode, parse_image(&fields.image)?)
        .command(fields.command)
        .force(fields.force);
    if let Some(name) = fields.name {
        builder = builder.name(name);
    }
    for (key, value) in fields.env {
        builder = builder.env(key, value);
    }
    if let Some(cpus) = fields.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(memory_mib) = fields.memory_mib {
        builder = builder.memory_mib(memory_mib);
    }
    if let Some(profile) = fields.profile {
        builder = builder.profile(profile);
    }
    if let Some(ttl) = fields.ttl_seconds {
        builder = builder.ttl_seconds(ttl);
    }
    if let Some(backend) = fields.backend {
        builder = builder.backend(backend);
    }
    for port in fields.ports {
        builder = builder.port(port);
    }
    for target in fields.egress {
        builder = builder.allow_egress(target.host, target.port);
    }
    Ok(builder)
}

/// Build and validate a launch request from `fields`.
fn launch_request(fields: LaunchFields) -> Result<LaunchRequest, Outcome> {
    builder_for(fields)?.build().map_err(Outcome::from)
}

/// Answer a launch `method` on `backend`.
pub(crate) async fn dispatch(backend: &LocalBackend, method: &str, request: &[u8]) -> Outcome {
    match answer(backend, method, request).await {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

async fn answer(backend: &LocalBackend, method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    Ok(match method {
        MACHINE_RUN => {
            let r: RunRequest = parse(request)?;
            let launched = backend.launch(launch_request(r.into())?).await?;
            let build_mode =
                mvm_client::inventory::resolve_workload_posture(None, &launched.machine.name)
                    .label()
                    .to_string();
            Outcome::ok(&RunReply {
                machine: launched.machine,
                plan_id: launched.plan_id,
                build_mode,
            })
        }
        MACHINE_CREATE => {
            let r: CreateRequest = parse(request)?;
            Outcome::ok(&backend.create_from_request(&launch_request(r.into())?)?)
        }
        other => return Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    })
}

fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|e| Outcome::invalid_input(&format!("request did not parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_INVALID_SPEC, MVM_HOSTLIB_OK};
    use mvm_core::client::MvmClient;
    use mvm_core::client::dto::{MachineFilter, MachineStatus};
    use mvm_core::util::test_env::TestEnv;

    /// An isolated `MVM_HOME` holding a hashable rootfs the mock boots.
    struct Home {
        _env: TestEnv,
        dir: tempfile::TempDir,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let mut env = TestEnv::new();
            env.isolate_mvm_home(dir.path());
            Self { _env: env, dir }
        }

        fn rootfs(&self) -> String {
            let path = self.dir.path().join("rootfs.ext4");
            std::fs::write(&path, b"hashable-rootfs-bytes\n").expect("write rootfs");
            path.to_string_lossy().into_owned()
        }

        fn audit_text(&self) -> String {
            std::fs::read_to_string(mvm_core::config::mvm_audit_dir().join("local.jsonl"))
                .unwrap_or_default()
        }
    }

    fn mock() -> LocalBackend {
        LocalBackend::with_hypervisor("mock")
    }

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn call(backend: &LocalBackend, method: &str, request: serde_json::Value) -> Outcome {
        run(dispatch(
            backend,
            method,
            &serde_json::to_vec(&request).expect("request encodes"),
        ))
    }

    fn body(outcome: &Outcome) -> serde_json::Value {
        serde_json::from_slice(&outcome.body).expect("body is JSON")
    }

    /// A transient run goes through the admitted boot: the reply names the
    /// machine and the plan, and the audit chain records the admission.
    #[test]
    fn a_transient_run_boots_through_admission_and_reports_the_plan() {
        let home = Home::new();
        let backend = mock();
        let outcome = call(
            &backend,
            MACHINE_RUN,
            serde_json::json!({
                "image": home.rootfs(),
                "name": "sdk-run",
                "cpus": 1,
                "memory_mib": 128,
                "ttl_seconds": 600,
            }),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        let reply = body(&outcome);
        assert_eq!(reply["machine"]["name"], "sdk-run");
        assert!(reply["plan_id"].as_str().is_some_and(|id| !id.is_empty()));
        assert_eq!(reply["build_mode"], "prod", "no accessible runtime is dev");
        assert!(
            home.audit_text().contains("plan.admitted"),
            "{}",
            home.audit_text()
        );
    }

    /// An egress allow-list becomes the definition's grant, which every boot
    /// of it is admitted under, rather than being dropped.
    #[test]
    fn egress_targets_ride_into_the_persisted_grants() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_CREATE,
            serde_json::json!({
                "name": "sdk-egress",
                "image": home.rootfs(),
                "egress": [{"host": "api.example.com", "port": 443}],
            }),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        let persisted = std::fs::read_to_string(mvm_core::config::machine_spec_path("sdk-egress"))
            .expect("the definition is persisted");
        assert!(persisted.contains("api.example.com"), "{persisted}");
    }

    /// The launcher's own refusals reach the binding as an invalid spec, with
    /// the launcher's reason, and nothing boots.
    #[test]
    fn a_command_override_is_refused_by_the_launcher_itself() {
        let home = Home::new();
        let backend = mock();
        let outcome = call(
            &backend,
            MACHINE_RUN,
            serde_json::json!({
                "image": home.rootfs(),
                "name": "sdk-cmd",
                "command": ["/bin/true"],
            }),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC);
        assert_eq!(body(&outcome)["code"], "INVALID_SPEC");
        assert!(
            body(&outcome)["message"]
                .as_str()
                .unwrap()
                .contains("command/entrypoint override"),
            "{}",
            body(&outcome)
        );
        let listed = run(backend.list_machines(MachineFilter::all())).unwrap();
        assert!(listed.iter().all(|m| m.name != "sdk-cmd"), "{listed:?}");
    }

    #[test]
    fn guest_environment_is_refused_rather_than_dropped() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({
                "image": home.rootfs(),
                "env": {"API_KEY": "value"},
            }),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC);
        assert!(
            body(&outcome)["message"]
                .as_str()
                .unwrap()
                .contains("environment variables")
        );
    }

    #[test]
    fn a_persistent_run_without_a_name_is_an_invalid_spec() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({"image": home.rootfs(), "mode": "persistent"}),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC);
    }

    #[test]
    fn an_image_that_names_nothing_is_an_invalid_spec() {
        let _home = Home::new();
        let outcome = call(&mock(), MACHINE_RUN, serde_json::json!({"image": "  "}));
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC);
    }

    #[test]
    fn a_malformed_port_is_refused_before_anything_boots() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({"image": home.rootfs(), "ports": ["not-a-port"]}),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC);
    }

    #[test]
    fn an_unknown_request_field_is_refused() {
        let _home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({"image": "alpine", "detach": true}),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    /// A created definition persists without booting, and `machine.start`
    /// through the client boots it.
    #[test]
    fn create_persists_a_definition_that_start_then_boots() {
        let home = Home::new();
        let backend = mock();
        let outcome = call(
            &backend,
            MACHINE_CREATE,
            serde_json::json!({"name": "sdk-def", "image": home.rootfs()}),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        assert_eq!(body(&outcome)["name"], "sdk-def");
        assert!(mvm_core::config::machine_spec_path("sdk-def").exists());

        let started =
            run(backend.start_machine(&mvm_core::client::dto::MachineId("sdk-def".into())))
                .expect("the definition boots");
        assert_eq!(started.status, MachineStatus::Running);
    }

    #[test]
    fn create_requires_a_name() {
        let _home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_CREATE,
            serde_json::json!({"image": "alpine"}),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn every_launch_method_is_known() {
        for method in METHODS {
            assert!(is_known(method), "{method}");
        }
        assert!(!is_known("machine.shell"));
    }
}
