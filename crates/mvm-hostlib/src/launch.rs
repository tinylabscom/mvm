//! `machine.run` and `machine.create`: boot or define a machine through the
//! local client's admitted launch.
//!
//! Both methods build an `mvm_client::LaunchRequest` and hand it to
//! `LocalBackend`, the same admitted-boot seam every in-process launcher uses:
//! the plan is synthesized, signed, verified, window- and replay-checked and
//! chain-audited before a byte of launch config reaches the backend. A
//! persistent machine boots through the same start the CLI's `machine run -d`
//! uses. Nothing here decides what a launch may do: the request builder
//! validates every field and refuses what it cannot honour with its own
//! reason, so a binding hears the same refusal a Rust caller would.
//!
//! A launch boots one of three sources: an `image`, a built `template` named
//! by the name its image was built under, or a `manifest` (a path or a built
//! slot's address). A `command` runs once the machine is up, with its `env`
//! filtered by the host's environment denylist, and the reply names the
//! process it started.

use std::collections::BTreeMap;

use mvm_client::{
    LaunchRequest, LaunchRequestBuilder, LaunchSource, LifecycleMode, LocalBackend, MachineState,
};
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

/// What a launch boots: the request's `image`, `template` and `manifest`
/// fields, of which exactly one is set. They are fields of each request
/// rather than a flattened struct because flattening would stop the request
/// refusing a field it does not know.
#[derive(Debug, Default)]
struct SourceFields {
    image: Option<String>,
    template: Option<String>,
    manifest: Option<String>,
}

impl SourceFields {
    /// The one source these fields name, resolved to what the launcher boots.
    fn resolve(self) -> Result<LaunchSource, Outcome> {
        let invalid = |reason: String| Outcome::from(MvmError::InvalidSpec { reason });
        match (self.image, self.template, self.manifest) {
            (Some(image), None, None) => Ok(LaunchSource::Image(parse_image(&image)?)),
            (None, Some(template), None) => {
                LaunchSource::from_template(&template).map_err(Outcome::from)
            }
            (None, None, Some(manifest)) => {
                LaunchSource::from_manifest(&manifest).map_err(Outcome::from)
            }
            (None, None, None) => Err(invalid(
                "a launch needs a source: `image`, `template` or `manifest`".to_string(),
            )),
            _ => Err(invalid(
                "a launch takes exactly one of `image`, `template` and `manifest`".to_string(),
            )),
        }
    }
}

/// A `machine.run` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunRequest {
    /// An OCI reference (optionally `oci:`-prefixed), an absolute or
    /// `./`-relative rootfs path, or `flake:<ref>#<attr>`. Exactly one of
    /// `image`, `template` and `manifest` is set.
    #[serde(default)]
    image: Option<String>,
    /// A template built on this host, named by the name its image was built
    /// under. Boots as a persistent machine.
    #[serde(default)]
    template: Option<String>,
    /// A manifest file, the directory holding one, or a built slot's
    /// 64-character address. Boots as a persistent machine.
    #[serde(default)]
    manifest: Option<String>,
    #[serde(default)]
    mode: RunMode,
    /// Required for a persistent machine; generated for a transient one.
    #[serde(default)]
    name: Option<String>,
    /// A command to start once the machine is up. The reply's `process` names
    /// it. Starting it is a DevOnly guest operation, so a sealed image
    /// refuses it.
    #[serde(default)]
    command: Vec<String>,
    /// The command's environment. Requires a `command`; a loader, shell or
    /// credential variable is refused.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// The command's working directory. Requires a `command`.
    #[serde(default)]
    cwd: Option<String>,
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
    /// An OCI reference (optionally `oci:`-prefixed), an absolute or
    /// `./`-relative rootfs path, or `flake:<ref>#<attr>`. Exactly one of
    /// `image`, `template` and `manifest` is set.
    #[serde(default)]
    image: Option<String>,
    /// A template built on this host, named by the name its image was built
    /// under. Boots as a persistent machine.
    #[serde(default)]
    template: Option<String>,
    /// A manifest file, the directory holding one, or a built slot's
    /// 64-character address. Boots as a persistent machine.
    #[serde(default)]
    manifest: Option<String>,
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
    /// `dev` or `prod`, decided by the admitted profile's `dev_guest` grant,
    /// the same declaration the guest agent's DevOnly refusal keys on. Only
    /// `dev` admits the DevOnly `guest.*` methods.
    build_mode: String,
    /// The token of the process `command` started, for `guest.proc.*`; absent
    /// when the request carried no command.
    #[serde(skip_serializing_if = "Option::is_none")]
    process: Option<String>,
}

/// The fields both requests share, in the order the builder takes them.
struct LaunchFields {
    mode: LifecycleMode,
    source: SourceFields,
    name: Option<String>,
    command: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: Option<String>,
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
            source: SourceFields {
                image: r.image,
                template: r.template,
                manifest: r.manifest,
            },
            name: r.name,
            command: r.command,
            env: r.env,
            cwd: r.cwd,
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
            source: SourceFields {
                image: r.image,
                template: r.template,
                manifest: r.manifest,
            },
            name: Some(r.name),
            command: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
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

/// The build_mode the SDK's DevOnly guard keys on.
///
/// The admitted profile's `dev_guest` grant decides, matching the guest
/// agent's own DevOnly refusal: a launch that did not declare a dev profile
/// is not a dev build even when the local boot is unsealed and
/// host-accessible — accessibility and the guest's dev profile answer
/// different questions, and conflating them let DevOnly verbs through on
/// plain launches. Fail closed: no profile, or a name no profile answers
/// to, resolves to `prod`.
fn declared_build_mode(profile: Option<&str>) -> String {
    match profile.and_then(mvm_client::profile::RunProfile::from_name) {
        Some(profile) if profile.grants().dev_guest => "dev",
        _ => "prod",
    }
    .to_string()
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
    let mut builder = LaunchRequest::builder_for(fields.mode, fields.source.resolve()?)
        .command(fields.command)
        .force(fields.force);
    if let Some(name) = fields.name {
        builder = builder.name(name);
    }
    for (key, value) in fields.env {
        builder = builder.env(key, value);
    }
    if let Some(cwd) = fields.cwd {
        builder = builder.cwd(cwd);
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
            let profile = r.profile.clone();
            let launched = backend.launch(launch_request(r.into())?).await?;
            Outcome::ok(&RunReply {
                machine: launched.machine,
                plan_id: launched.plan_id,
                build_mode: declared_build_mode(profile.as_deref()),
                process: launched.process,
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
    /// The DevOnly guard's label answers the declared profile, fail-closed:
    /// only a profile whose grants carry the dev guest is `dev`; no profile
    /// and unrecognised names are `prod` even though the local boot itself
    /// is unsealed — accessibility and the guest's dev profile are different
    /// questions.
    #[test]
    fn declared_build_mode_follows_the_dev_guest_grant() {
        assert_eq!(declared_build_mode(Some("dev")), "dev");
        assert_eq!(declared_build_mode(Some("permissive")), "dev");
        assert_eq!(declared_build_mode(Some("standard")), "prod");
        assert_eq!(declared_build_mode(Some("restrictive")), "prod");
        assert_eq!(declared_build_mode(Some("no-such-profile")), "prod");
        assert_eq!(declared_build_mode(None), "prod");
    }

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
        assert_eq!(
            reply["build_mode"], "prod",
            "no profile declares a dev guest"
        );
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

    /// Takes the command a launch starts, in place of the guest agent the
    /// mock backend does not run.
    #[derive(Default)]
    struct Starter {
        argv: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl mvm_client::launch::detached::CommandStarter for Starter {
        fn start(
            &self,
            _name: &str,
            command: mvm_client::launch::detached::BootCommand,
        ) -> anyhow::Result<String> {
            self.argv.lock().expect("lock").push(command.argv);
            Ok("proc-7".to_string())
        }
    }

    fn mock_starting(starter: &std::sync::Arc<Starter>) -> LocalBackend {
        mock().with_command_starter(std::sync::Arc::clone(starter)
            as std::sync::Arc<dyn mvm_client::launch::detached::CommandStarter>)
    }

    /// A command starts once the machine is up, and the reply names the
    /// process so the binding can wait on it.
    #[test]
    fn a_command_starts_after_boot_and_the_reply_names_its_process() {
        let home = Home::new();
        let starter = std::sync::Arc::new(Starter::default());
        let outcome = call(
            &mock_starting(&starter),
            MACHINE_RUN,
            serde_json::json!({
                "image": home.rootfs(),
                "name": "sdk-cmd",
                "command": ["/obscura", "serve", "--port", "9222"],
                "env": {"MODE": "headless"},
                "cwd": "/",
            }),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        assert_eq!(body(&outcome)["process"], "proc-7");
        assert_eq!(
            *starter.argv.lock().unwrap(),
            vec![vec![
                "/obscura".to_string(),
                "serve".into(),
                "--port".into(),
                "9222".into()
            ]]
        );
    }

    #[test]
    fn a_run_without_a_command_names_no_process() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({"image": home.rootfs(), "name": "sdk-nocmd"}),
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_OK, "{}", body(&outcome));
        assert!(
            body(&outcome).get("process").is_none(),
            "{}",
            body(&outcome)
        );
    }

    /// The host's environment denylist applies to a command's environment
    /// before anything boots.
    #[test]
    fn a_denied_environment_variable_is_refused_and_nothing_boots() {
        let home = Home::new();
        let backend = mock();
        let outcome = call(
            &backend,
            MACHINE_RUN,
            serde_json::json!({
                "image": home.rootfs(),
                "name": "sdk-denied",
                "command": ["/bin/true"],
                "env": {"LD_PRELOAD": "/tmp/x.so"},
            }),
        );
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_INVALID_SPEC,
            "{}",
            body(&outcome)
        );
        assert!(
            body(&outcome)["message"]
                .as_str()
                .unwrap()
                .contains("LD_PRELOAD"),
            "{}",
            body(&outcome)
        );
        let listed = run(backend.list_machines(MachineFilter::all())).unwrap();
        assert!(listed.iter().all(|m| m.name != "sdk-denied"), "{listed:?}");
    }

    #[test]
    fn an_environment_without_a_command_is_refused_rather_than_dropped() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({
                "image": home.rootfs(),
                "env": {"API_KEY": "value"},
            }),
        );
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_INVALID_SPEC,
            "{}",
            body(&outcome)
        );
    }

    /// A template is looked up among the images built on this host; one that
    /// was never built is refused with how to build it.
    #[test]
    fn a_template_nothing_was_built_as_is_an_invalid_spec() {
        let _home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({"template": "chromium", "mode": "persistent", "name": "b"}),
        );
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_INVALID_SPEC,
            "{}",
            body(&outcome)
        );
        let message = body(&outcome)["message"].as_str().unwrap().to_string();
        assert!(message.contains("chromium"), "{message}");
        assert!(message.contains("mvmctl machine build"), "{message}");
    }

    #[test]
    fn a_manifest_that_does_not_exist_is_an_invalid_spec() {
        let _home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_RUN,
            serde_json::json!({
                "manifest": "/nonexistent/mvm.toml",
                "mode": "persistent",
                "name": "m",
            }),
        );
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_INVALID_SPEC,
            "{}",
            body(&outcome)
        );
    }

    #[test]
    fn a_launch_names_exactly_one_source() {
        let home = Home::new();
        for request in [
            serde_json::json!({}),
            serde_json::json!({"image": home.rootfs(), "template": "chromium"}),
            serde_json::json!({"image": home.rootfs(), "manifest": "a".repeat(64)}),
        ] {
            let outcome = call(&mock(), MACHINE_RUN, request.clone());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_SPEC, "{request}");
            assert!(
                body(&outcome)["message"]
                    .as_str()
                    .unwrap()
                    .contains("`image`"),
                "{}",
                body(&outcome)
            );
        }
    }

    /// A definition only records what boots; a command has nowhere to live in
    /// it, so `machine.create` does not take one.
    #[test]
    fn create_takes_no_command() {
        let home = Home::new();
        let outcome = call(
            &mock(),
            MACHINE_CREATE,
            serde_json::json!({
                "name": "sdk-create-cmd",
                "image": home.rootfs(),
                "command": ["/bin/true"],
            }),
        );
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_INVALID_INPUT,
            "{}",
            body(&outcome)
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
