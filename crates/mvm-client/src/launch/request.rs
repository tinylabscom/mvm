//! The typed launch request for the in-process local lifecycle.
//!
//! One request shape drives both lifecycle modes: a [`LifecycleMode::Transient`]
//! machine boots without a persisted definition and is cleaned up when it
//! exits (or its TTL lapses); a [`LifecycleMode::Persistent`] machine persists
//! a declarative spec first and is managed by name across starts and stops.
//!
//! Every field is validated at the client boundary, in
//! [`LaunchRequestBuilder::build`]. Fields the in-process backend cannot
//! honor are **refused**, never silently dropped: a command/entrypoint
//! override, guest environment variables, and an untyped network policy other
//! than deny-all all fail the build with an error naming what does support
//! them. Egress is expressed as a grant, which the plan is signed over and the
//! gate reads.

use mvm_core::client::{MvmError, Result};
use mvm_core::rootfs_source::RootfsSource;

pub use crate::secret::MachineSecretRef;
pub use crate::volume::AccessMode;

/// Whether the launched machine outlives this client's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleMode {
    /// No persisted definition: the machine exists only while running and its
    /// session-owned resources are released by the cleanup path.
    Transient,
    /// A declarative spec is persisted under the machine's name before any
    /// boot; stopping never deletes it, and removal is a separate confirmed
    /// caller action.
    Persistent,
}

/// Untyped network policy for the launch. Superseded by the egress grant on
/// [`LaunchRequestBuilder::allow_egress`], which is derived into the policy the
/// gate reads and is covered by the plan's signature.
///
/// This one is not: it is a bare carrier travelling next to the plan rather
/// than inside it, so an allow-list here would authorize egress that nothing
/// signed. Anything but deny-all is refused at validation rather than
/// persisted-but-not-enforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LaunchNetworkPolicy {
    /// Deny all egress (the only value this carrier admits).
    #[default]
    DenyAll,
    /// Named host allow-list — refused by [`LaunchRequestBuilder::build`];
    /// express it as an egress grant instead.
    AllowHosts(Vec<String>),
}

/// One typed volume attachment: a managed volume from the local encrypted
/// volume catalog, mounted at `guest_path`. Resolved through
/// [`crate::volume::VolumeService`] at launch, which owns the mount-root
/// policy, the read-write profile gate, and the exclusive lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchVolumeSpec {
    /// Managed volume name in the local catalog.
    pub volume: String,
    /// Absolute guest mount point (validated against the mount allow-roots).
    pub guest_path: String,
    /// Requested access mode; read-write requires a dev-tier profile.
    pub access: AccessMode,
}

/// A fully-validated launch request. Construct via [`LaunchRequest::builder`].
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub(crate) name: Option<String>,
    pub(crate) mode: LifecycleMode,
    pub(crate) image: RootfsSource,
    pub(crate) cpus: u32,
    pub(crate) memory_mib: u32,
    pub(crate) backend: Option<String>,
    pub(crate) profile: String,
    pub(crate) ttl_seconds: Option<u64>,
    pub(crate) volumes: Vec<LaunchVolumeSpec>,
    pub(crate) secret_refs: Vec<MachineSecretRef>,
    pub(crate) force: bool,
    /// What the workload is permitted to consume or reach. Rides into the
    /// signed plan, and its egress dimension is projected onto the launch
    /// config the egress gate reads — so an allow-list here is authorized by
    /// the same plan that was signed over it, rather than by a carrier
    /// travelling alongside one.
    pub(crate) grants: Option<mvm_contract::grants::Grants>,
}

impl LaunchRequest {
    /// Start building a request for `mode` from the already-parsed rootfs
    /// declaration `image` — a registry reference, an unpacked rootfs
    /// directory, or a pre-materialized `rootfs.ext4` path. Taking the parsed
    /// value rather than a string is what keeps a request that names nothing
    /// unbuildable rather than merely refused.
    pub fn builder(mode: LifecycleMode, image: RootfsSource) -> LaunchRequestBuilder {
        LaunchRequestBuilder {
            mode,
            image,
            name: None,
            command: Vec::new(),
            env: Vec::new(),
            cpus: 1,
            memory_mib: 512,
            backend: None,
            profile: "standard".to_string(),
            ttl_seconds: None,
            network: LaunchNetworkPolicy::DenyAll,
            volumes: Vec::new(),
            secret_refs: Vec::new(),
            force: false,
            grants: mvm_contract::grants::Grants::default(),
        }
    }

    /// The machine name, when the caller supplied one. Transient launches
    /// without a name get a generated one at launch time.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn mode(&self) -> LifecycleMode {
        self.mode
    }
}

/// Builder for [`LaunchRequest`]. `build` validates every field and refuses
/// unsupported ones — see the module docs.
#[derive(Debug, Clone)]
pub struct LaunchRequestBuilder {
    mode: LifecycleMode,
    image: RootfsSource,
    name: Option<String>,
    command: Vec<String>,
    env: Vec<(String, String)>,
    cpus: u32,
    memory_mib: u32,
    backend: Option<String>,
    profile: String,
    ttl_seconds: Option<u64>,
    network: LaunchNetworkPolicy,
    volumes: Vec<LaunchVolumeSpec>,
    secret_refs: Vec<MachineSecretRef>,
    force: bool,
    grants: mvm_contract::grants::Grants,
}

impl LaunchRequestBuilder {
    /// Machine name. Required for a persistent launch (the definition must be
    /// addressable later); optional for a transient one (generated if absent).
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Command/entrypoint override. Represented so a caller's intent is
    /// visible, but the in-process backend refuses a non-empty override at
    /// `build` — the image's baked entrypoint is the only thing that runs.
    #[must_use]
    pub fn command(mut self, argv: impl IntoIterator<Item = String>) -> Self {
        self.command.extend(argv);
        self
    }

    /// Guest environment variables. Refused when non-empty: the in-process
    /// boot path has no env delivery seam, and silently dropping values a
    /// caller believes were set is worse than a refusal.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// vCPU count (default 1, must be >= 1).
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    /// Guest memory in MiB (default 512, must be >= 1).
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Hypervisor backend name override (`firecracker`, `libkrun`, `hvf`,
    /// `mock`, …). Checked for selectability at launch time; default is the
    /// client's own backend.
    #[must_use]
    pub fn backend(mut self, backend: impl Into<String>) -> Self {
        self.backend = Some(backend.into());
        self
    }

    /// Machine profile (default `standard`). Only `dev` / `permissive`
    /// profiles may take writable volume attachments.
    #[must_use]
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Time-to-live in seconds. Recorded as the registry `expires_at`; the
    /// transient reaper stops and cleans an expired machine.
    #[must_use]
    pub fn ttl_seconds(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = Some(ttl_seconds);
        self
    }

    /// Guest network policy (default deny-all — the only admitted value).
    #[must_use]
    pub fn network(mut self, network: LaunchNetworkPolicy) -> Self {
        self.network = network;
        self
    }

    /// Bound the workload to `millicores` thousandths of one host core — a
    /// share of host CPU *time*, unrelated to [`cpus`], which is the vCPU count
    /// the guest sees.
    ///
    /// [`cpus`]: LaunchRequestBuilder::cpus
    #[must_use]
    pub fn cpu_millicores(mut self, millicores: u32) -> Self {
        self.grants.cpu = Some(mvm_contract::grants::CpuGrant::Share { millicores });
        self
    }

    /// Bound the workload's wall-clock runtime.
    #[must_use]
    pub fn wall_clock_secs(mut self, secs: std::num::NonZeroU32) -> Self {
        self.grants.wall_clock = Some(mvm_contract::grants::WallClockGrant::Secs { secs });
        self
    }

    /// Permit outbound access to one `host:port`. Repeatable; each call
    /// appends. Calling it at all is what lifts the workload off deny-all, and
    /// the allow-list lands in the signed plan the gate's policy is derived
    /// from.
    #[must_use]
    pub fn allow_egress(mut self, host: impl Into<String>, port: u16) -> Self {
        self.grants
            .egress
            .get_or_insert_with(Default::default)
            .allow
            .push(mvm_core::policy::network_policy::HostPort::new(host, port));
        self
    }

    /// Replace the whole permission set at once, for a caller that already has
    /// one in hand. Overwrites every dimension the setters above may have set.
    #[must_use]
    pub fn grants(mut self, grants: mvm_contract::grants::Grants) -> Self {
        self.grants = grants;
        self
    }

    /// Attach a managed volume at `guest_path`.
    #[must_use]
    pub fn volume(mut self, spec: LaunchVolumeSpec) -> Self {
        self.volumes.push(spec);
        self
    }

    /// Declare a typed secret reference (metadata only — never a value).
    /// Validated fail-closed at admission and recorded in the machine's
    /// `secret-refs.json` sidecar.
    #[must_use]
    pub fn secret_ref(mut self, secret_ref: MachineSecretRef) -> Self {
        self.secret_refs.push(secret_ref);
        self
    }

    /// Persistent mode only: allow recreating an existing same-name
    /// definition whose config differs (the reviewed recreate flow).
    #[must_use]
    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Validate every field and build the request. Unsupported fields are
    /// refused with an error naming the supported path, never ignored.
    pub fn build(self) -> Result<LaunchRequest> {
        let invalid = |reason: String| MvmError::InvalidSpec { reason };

        if let Some(name) = self.name.as_deref() {
            mvm_core::naming::validate_vm_name(name)
                .map_err(|e| invalid(format!("invalid machine name {name:?}: {e}")))?;
        } else if self.mode == LifecycleMode::Persistent {
            return Err(invalid(
                "a persistent machine requires a name (its definition is managed by name)".into(),
            ));
        }
        if self.cpus == 0 {
            return Err(invalid("cpus must be >= 1".into()));
        }
        if self.memory_mib == 0 {
            return Err(invalid("memory_mib must be >= 1".into()));
        }
        if !self.command.is_empty() {
            return Err(invalid(
                "a command/entrypoint override is not supported by the in-process local \
                 backend (the image's baked entrypoint runs); use `mvmctl machine run` \
                 for ad-hoc commands"
                    .into(),
            ));
        }
        if !self.env.is_empty() {
            return Err(invalid(
                "guest environment variables are not supported by the in-process local \
                 backend (no delivery seam; values would be silently dropped); use the \
                 CLI run path"
                    .into(),
            ));
        }
        if self.network != LaunchNetworkPolicy::DenyAll {
            return Err(invalid(
                "the in-process local backend admits only the deny-all network policy; \
                 an egress allow-list needs the CLI boot path, which enforces the \
                 resolved policy"
                    .into(),
            ));
        }
        if self.profile.trim().is_empty() {
            return Err(invalid("profile must not be empty".into()));
        }
        if self.ttl_seconds == Some(0) {
            return Err(invalid("ttl_seconds must be > 0 when set".into()));
        }
        for volume in &self.volumes {
            if volume.volume.trim().is_empty() {
                return Err(invalid("volume name must not be empty".into()));
            }
            if volume.guest_path.trim().is_empty() {
                return Err(invalid(format!(
                    "volume {:?} guest path must not be empty",
                    volume.volume
                )));
            }
        }
        Ok(LaunchRequest {
            name: self.name,
            mode: self.mode,
            image: self.image,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            backend: self.backend,
            profile: self.profile,
            ttl_seconds: self.ttl_seconds,
            volumes: self.volumes,
            secret_refs: self.secret_refs,
            force: self.force,
            // An untouched permission set stays absent, so a request that
            // granted nothing produces exactly the plan it produced before
            // grants were expressible.
            grants: (self.grants != mvm_contract::grants::Grants::default()).then_some(self.grants),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A parsed registry declaration — the shape a caller now has to arrive
    /// with, since the request type no longer accepts an uninterpreted string.
    fn oci(image_ref: &str) -> RootfsSource {
        image_ref.parse().expect("test image parses")
    }

    fn base(mode: LifecycleMode) -> LaunchRequestBuilder {
        LaunchRequest::builder(mode, oci("alpine:3.20")).name("web")
    }

    #[test]
    fn minimal_transient_request_builds_with_defaults() {
        let req = LaunchRequest::builder(LifecycleMode::Transient, oci("alpine:3.20"))
            .build()
            .expect("minimal transient request");
        assert_eq!(req.mode(), LifecycleMode::Transient);
        assert!(req.name().is_none(), "name is generated at launch time");
        assert_eq!((req.cpus, req.memory_mib), (1, 512));
        assert_eq!(req.profile, "standard");
        assert!(req.volumes.is_empty() && req.secret_refs.is_empty());
        assert!(!req.force);
    }

    #[test]
    fn persistent_request_requires_a_name() {
        let err = LaunchRequest::builder(LifecycleMode::Persistent, oci("alpine:3.20"))
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("requires a name"), "got: {err}");
        base(LifecycleMode::Persistent)
            .build()
            .expect("named persistent request");
    }

    #[test]
    fn an_empty_image_cannot_reach_a_request_at_all() {
        // This used to be a `build()` refusal on a `String` field. It is now
        // unrepresentable: the request names a parsed source, so the only way
        // to express an empty one is to fail the parse first.
        assert_eq!(
            "  ".parse::<RootfsSource>().unwrap_err(),
            mvm_core::rootfs_source::RootfsSourceParseError::Empty
        );
    }

    #[test]
    fn an_invalid_name_is_refused() {
        let err = LaunchRequest::builder(LifecycleMode::Transient, oci("img"))
            .name("Bad Name!")
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid machine name"),
            "got: {err}"
        );
    }

    #[test]
    fn zero_resources_are_refused() {
        let err = base(LifecycleMode::Transient).cpus(0).build().unwrap_err();
        assert!(err.to_string().contains("cpus"), "got: {err}");
        let err = base(LifecycleMode::Transient)
            .memory_mib(0)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("memory_mib"), "got: {err}");
    }

    #[test]
    fn command_override_is_refused_not_ignored() {
        let err = base(LifecycleMode::Transient)
            .command(["/bin/sh".to_string(), "-c".to_string(), "id".to_string()])
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("command/entrypoint override"),
            "got: {err}"
        );
    }

    #[test]
    fn env_vars_are_refused_not_ignored() {
        let err = base(LifecycleMode::Transient)
            .env("API_KEY", "value")
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("environment variables"),
            "got: {err}"
        );
    }

    #[test]
    fn network_policy_defaults_deny_all_and_allow_list_is_refused() {
        assert_eq!(LaunchNetworkPolicy::default(), LaunchNetworkPolicy::DenyAll);
        let err = base(LifecycleMode::Transient)
            .network(LaunchNetworkPolicy::AllowHosts(vec![
                "api.example.com".into(),
            ]))
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("deny-all"), "got: {err}");
    }

    #[test]
    fn zero_ttl_and_malformed_volumes_are_refused() {
        let err = base(LifecycleMode::Transient)
            .ttl_seconds(0)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("ttl_seconds"), "got: {err}");

        let err = base(LifecycleMode::Transient)
            .volume(LaunchVolumeSpec {
                volume: "".into(),
                guest_path: "/data/work".into(),
                access: AccessMode::ReadOnly,
            })
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("volume name"), "got: {err}");

        let err = base(LifecycleMode::Transient)
            .volume(LaunchVolumeSpec {
                volume: "work".into(),
                guest_path: " ".into(),
                access: AccessMode::ReadOnly,
            })
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("guest path"), "got: {err}");
    }
}
