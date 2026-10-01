//! `RunArgs`'s `Default`: the values clap fills in when a flag is absent.

use super::{RunArgs, RunProfile};

/// The same values clap fills in when a flag is absent.
///
/// Two consumers want a `RunArgs` without spelling thirty fields: the
/// `machine` dispatch sites that build one programmatically, and the tests.
/// Writing them out by hand meant every new field edited every one of those
/// sites, so they drifted toward whatever the author happened to type rather
/// than toward what the CLI actually does.
///
/// The risk this introduces is that these values and the `#[arg(default_value)]`
/// attributes on `RunArgs` disagree. `parsed_defaults_match_the_default_impl` is the
/// witness: it parses a bare `run -- x` and compares the result field by field.
impl Default for RunArgs {
    fn default() -> Self {
        Self {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            detected_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
            manifest: None,
            image: None,
            flake: None,
            flake_profile: None,
            deployment: None,
            warm_pool_size: 0,
            gpu: false,
            gpu_device: None,
            pty: false,
            vm_name: None,
            runtime_pack: false,
            runtime: None,
            no_detect: false,
            net: false,
            network_preset: None,
            allow_host: Vec::new(),
            allow_endpoint: Vec::new(),
            approval: Vec::new(),
            approval_mode: None,
            ai_token_budget: None,
            peer: Vec::new(),
            // Must track the clap default, which is resolved from the backend
            // this host selects — a test pins the two together, because a
            // `Default` that disagrees with the parsed default is a silent
            // difference between constructing args and parsing them.
            cpus: crate::commands::shared::default_vcpus(),
            cpu_limit: None,
            grants_file: None,
            memory: "512M".to_string(),
            profile: RunProfile::Standard,
            mounts: Vec::new(),
            env: Vec::new(),
            allow_env: Vec::new(),
            secret: Vec::new(),
            timeout: None,
            receipt: None,
            caller_commitment: None,
            assets: Vec::new(),
            outputs: Vec::new(),
            json: false,
            dry_run: false,
            launch_plan: None,
            from_workload_ir: None,
            prod: false,
            argv: Vec::new(),
            agent_verb: Vec::new(),
            host_service: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            policy: Vec::new(),
            plan: None,
            policy_routes: Vec::new(),
            applied_policy: None,
            policy_backend: None,
        }
    }
}
