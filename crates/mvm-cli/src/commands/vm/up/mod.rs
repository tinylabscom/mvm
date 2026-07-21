//! Internal admission and boot helpers consumed by `machine/mod.rs`:
//! `start_persistent_oci_machine`, `admit_plan_for_boot`, `AdmitPlanForBootParams`,
//! `AdmissionContext`, `emit_launched_if`, `emit_failed_if`,
//! `persists_plan_before_start`, `resolve_workload_kernel`, `untrusted_transient_admit`,
//! and `load_workload_ir`.

use clap::Args as ClapArgs;

use super::shared::{clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec};

mod admission;
mod audit;
mod kernel;
mod oci_persist;
mod policy;
mod runtime_source;

pub(super) use admission::{
    AdmissionContext, AdmitPlanForBootParams, SECURITY_POLICY_FILENAME, admit_plan_for_boot,
    attach_guest_boot_config, attach_guest_boot_config_for_plan,
    attach_guest_security_policy_config, attach_host_signer_pubkey_config_for_plan,
    emit_boot_posture_if, emit_failed_if, emit_launched_if, guest_profile_for_boot,
};
#[cfg(feature = "mcp")]
pub(in crate::commands) use admission::untrusted_transient_admit;

pub(super) use kernel::{resolve_pinned_kernel, resolve_workload_kernel};
pub(in crate::commands) use kernel::resolve_kernel_pin_path;

pub(crate) use oci_persist::{persistent_oci_effective_initrd, persists_plan_before_start};
pub(super) use oci_persist::load_workload_ir;
pub(in crate::commands) use oci_persist::{PersistentImageStartParams, start_persistent_oci_machine};

pub(crate) use runtime_source::{
    RuntimeSourceStatus, attach_runtime_overlay, attach_runtime_overlay_if_cached,
    attach_runtime_overlay_if_cached_version, emit_runtime_source_status,
    resolve_runtime_source_status,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Nix flake reference (local path or remote URI)
    #[arg(long, value_parser = clap_flake_ref, conflicts_with = "manifest")]
    pub flake: Option<String>,
    /// Boot a pre-built manifest (path to `mvm.toml`, its directory, or a
    /// legacy slot name). Mutually exclusive with `--flake`.
    #[arg(short = 'm', long)]
    pub manifest: Option<String>,
    /// VM name (auto-generated if omitted)
    #[arg(long, value_parser = clap_vm_name)]
    pub name: Option<String>,
    /// Flake package variant (e.g. worker, gateway). Omit to use flake default
    #[arg(long)]
    pub profile: Option<String>,
    /// vCPU cores
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Memory (supports human-readable sizes: 512M, 4G, 1024K, or plain MB)
    #[arg(long)]
    pub memory: Option<String>,
    /// Runtime config (TOML) for persistent resources/volumes
    #[arg(long)]
    pub config: Option<String>,
    /// Attach a volume (repeatable). `host:/guest` shares a host dir
    /// (virtio-fs); `host:/guest:SIZE` is an ext4 disk image. Read-only
    /// by default — append `:rw` to grant writes. Guest path must be
    /// under /data, /work, or /mnt (system mounts are read-only).
    #[arg(short, long, value_parser = clap_volume_spec)]
    pub volume: Vec<String>,
    /// Hypervisor backend (firecracker, libkrun, qemu, hvf). Default: auto-detect per host
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    /// Port mapping (format: HOST:GUEST or PORT). Repeatable
    #[arg(short, long, value_parser = clap_port_spec)]
    pub port: Vec<String>,
    /// Environment variable to inject (format: KEY=VALUE). Repeatable
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Bind a named secret to an egress destination (format:
    /// NAME:HOST[,HOST...]). Adds a `SecretRef` to the workload — the guest
    /// only ever sees a placeholder; the host substitutes the real credential
    /// on outbound requests to the allow-listed hosts. Bearer auth +
    /// env-var mount by default; use `mvmctl secret set` for sigv4/hmac/file.
    /// Repeatable.
    #[arg(long = "secret")]
    pub secret: Vec<String>,
    /// Auto-forward declared ports after boot (blocks until Ctrl-C)
    #[arg(long)]
    pub forward: bool,
    /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
    #[arg(long, default_value = "0")]
    pub metrics_port: u16,
    /// Keep this many prelaunched supervisor standbys warm so the next
    /// auto-named `up` claims one instead of cold-booting. Omit to use the
    /// residency-policy default (`MVM_RESIDENCY`); pass `0` to disable.
    /// Supported by Firecracker and libkrun.
    #[arg(long)]
    pub warm_pool_size: Option<u32>,
    /// Reload ~/.mvm/config.toml automatically when it changes
    #[arg(long)]
    pub watch_config: bool,
    /// Watch the flake for changes and auto-rebuild + reboot (requires local --flake)
    #[arg(long)]
    pub watch: bool,
    /// Run in background (detached mode, like docker run -d)
    #[arg(short, long)]
    pub detach: bool,
    /// Block until the workload powers off, then exit with its code
    /// (one-shot workloads).
    #[arg(long, conflicts_with_all = ["detach", "up_json"])]
    pub wait: bool,
    /// After boot, drop into an interactive PTY console in the guest
    /// (like `docker run -it`). Implies the dev image for the bundled
    /// default microVM — a sealed prod image ships no console agent.
    /// The VM keeps running after the shell exits; `down` stops it.
    #[arg(long, conflicts_with_all = ["detach", "up_json", "wait", "forward"])]
    pub console: bool,
    /// Network preset (unrestricted, none, registries, dev)
    #[arg(long)]
    pub network_preset: Option<String>,
    /// Network allowlist entry (format: HOST:PORT). Repeatable
    #[arg(long)]
    pub network_allow: Vec<String>,
    /// Named security profile selecting the per-seam capability matrix
    /// (seccomp tier + egress posture). Defaults to `production`: the
    /// highest-security, deployable posture (seccomp floor + deny-all egress).
    /// The only alternative is `dev` — looser for development and never
    /// deployable (refused under `--prod`). Explicit `--seccomp` /
    /// `--network-preset` override the profile.
    #[arg(long = "security-profile")]
    pub security_profile: Option<String>,
    /// Seccomp profile tier (essential, minimal, standard, network, unrestricted).
    ///
    /// Overrides the `--security-profile` seccomp tier. `unrestricted` is
    /// opt-in only; the project's posture is "defaults must be safe."
    #[arg(long)]
    pub seccomp: Option<String>,
    /// Named dev network to attach VM to (default: "default")
    #[arg(long, default_value = "default")]
    pub network: String,
    /// Sandbox tag in `KEY=VALUE` form. Repeatable. Validated against
    /// `mvm_core::crypto::policy::InputValidator` charset/length rules.
    #[arg(long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    /// Sandbox time-to-live (e.g. `30s`, `5m`, `2h`, `7d`). After
    /// expiry the supervisor reaper tears the VM down. Omit for no
    /// TTL.
    #[arg(long)]
    pub ttl: Option<String>,
    /// Disable auto-resume when a caller connects to a sleeping VM.
    /// Default behaviour resumes on connect.
    #[arg(long)]
    pub no_auto_resume: bool,
    /// Tenant for the synthesized `ExecutionPlan`. When
    /// unset the value is resolved via the 4-level precedence chain
    /// (built-in `"local"` →
    /// `~/.mvm/config.toml` `[tenant] name` → `MVM_TENANT` env →
    /// `--tenant` flag). Identity / `mvmctl auth` is the subject of
    /// a separate effort; this flag is just the audit
    /// chain string label.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Skip admission (`synthesize → sign → verify → check_window
    /// → nonce`). One-release escape hatch; prints a deprecation warning
    /// when set. Will be removed once admission is the only path.
    #[arg(long)]
    pub no_supervisor: bool,
    /// Pin the launch to a specific `.mvmpkg` bundle. The path is
    /// read at admit time, verified against the local trust store
    /// (`~/.mvm/trusted-publishers/`), and embedded into the
    /// `ExecutionPlan` as a `PlanArtifact`. The supervisor's admit
    /// path then re-verifies the bundle against the pin before
    /// backend dispatch — claim 9 load-bearing at launch. Use the
    /// same path you handed to `mvmctl bundle fetch` /
    /// `mvmctl bundle install`.
    #[arg(long, value_name = "PATH")]
    pub bundle_pin: Option<std::path::PathBuf>,
    /// Build-mode override flags (`--dev` / `--prod`). Default: `--prod`.
    /// These also drive the app-deps gate when
    /// `--from-workload-ir` is set: `--prod` fails closed on missing
    /// SBOM / missing CVE scan / high or critical CVE findings;
    /// `--dev` warns and continues.
    #[command(flatten)]
    pub build_mode: super::super::shared::BuildModeFlags,
    /// Path to a Workload IR JSON describing the app being booted.
    /// When the IR carries `App.dependencies = Dependencies::Python
    /// | Dependencies::Node`, `mvmctl up` resolves the lockfile
    /// through `mvm_build::app_deps::install_app_deps` (cache-hit
    /// only — `mvmctl up` does not spawn the builder VM
    /// from this path; the volume must already exist) and pins
    /// the resulting `DepsVolumeBinding` into the synthesized
    /// `ExecutionPlan`. When omitted or when the IR carries
    /// `Dependencies::None`, the plan's `deps_volume` is `None`
    /// (claim-8 preserved; claim 9).
    #[arg(long = "from-workload-ir", value_name = "PATH")]
    pub from_workload_ir: Option<std::path::PathBuf>,
    /// Explicit operator acknowledgement that the
    /// selected backend's isolation tier is acceptable for this launch.
    /// A non-Tier-1 backend (libkrun, qemu, hvf) requires
    /// this flag. A future `--prod` mode will *block* rather than warn;
    /// today we surface the signal without changing default behaviour.
    /// libkrun isolation is not Firecracker isolation.
    #[arg(long)]
    pub accept_tier2_isolation: bool,

    /// Emit a one-line JSON envelope on stdout when the VM is up.
    /// Routes the friendly `[mvm]` chrome to stderr so the SDK
    /// live-mode transport can parse a
    /// single JSON document instead of teaching the SDK to scrape
    /// the human-formatted log.
    ///
    /// Envelope shape (schema_version=1):
    ///
    /// ```json
    /// {"schema_version": 1, "vm_id": "myvm",
    ///  "build_mode": "dev"|"prod"}
    /// ```
    ///
    /// `build_mode` is read from the resolved template's
    /// `TemplateRevision.build_mode` (defaulting to `prod`) and
    /// is the load-bearing signal the SDK uses to enforce the
    /// claim-4 dev-only `do_exec` rule client-side.
    #[arg(long = "up-json")]
    pub up_json: bool,
    /// Pin the workload kernel to the locally-built slim kernel in the mvm
    /// cache (`mvmctl kernel build --which workload`). When set, the
    /// boot path uses the cached workload kernel instead of whatever the
    /// image shipped; the image's own kernel file is ignored. If the cache
    /// entry is absent, the boot fails with a clear build hint.
    #[arg(long = "kernel-pin")]
    pub kernel_pin: Option<String>,
    /// Scrub undeclared secrets/PII on egress to HOST (masks); `HOST=audit` only
    /// reports. Repeatable. Per-destination egress redaction.
    #[arg(long = "redact", value_name = "HOST[=audit]")]
    pub redact: Vec<String>,
}

