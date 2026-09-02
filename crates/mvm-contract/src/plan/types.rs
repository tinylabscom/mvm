//! `*Ref` and `*Spec` types referenced from `ExecutionPlan`.
//!
//! Most fields here are opaque newtype wrappers so later resolvers
//! can be introduced without churning the wire format. Every type
//! carries `#[serde(deny_unknown_fields)]` so
//! adding a field is a fail-closed schema bump for older verifiers.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Deserializer, Serialize, de};

/// How a workload reaches the network. Closed by default: the guest gets no
/// virtio-net device and can reach nothing until networking is explicitly
/// requested. [`HostVsockProxy`](NetworkMode::HostVsockProxy) is the brokered,
/// no-NIC transport — egress and ingress are mediated by host brokers over
/// vsock, and the `network_policy` allowlist still gates which endpoints are
/// reachable. Carried in the signed `ExecutionPlan` so the transport is part of
/// the admitted contract, not a host-wide setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No guest NIC, no broker — the workload cannot reach the network.
    #[default]
    None,
    /// No guest NIC; egress and ingress are mediated by host brokers over vsock.
    HostVsockProxy,
}

impl<'de> Deserialize<'de> for NetworkMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = NetworkMode;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("none or host_vsock_proxy")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "none" => Ok(NetworkMode::None),
                    "host_vsock_proxy" => Ok(NetworkMode::HostVsockProxy),
                    "l3_vsock" => Err(E::custom(
                        "l3_vsock has been retired; use the authenticated FlowMux loopback adapters or a typed connector",
                    )),
                    _ => Err(E::unknown_variant(value, &["none", "host_vsock_proxy"])),
                }
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// Transport-neutral per-workload networking resource ceilings.
///
/// These limits are part of the signed execution plan. A runtime may enforce
/// a lower host ceiling, but it may never raise one of these values after
/// admission. The default preserves the bounds of plans authored before this
/// type existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkLimits {
    /// Aggregate concurrent TCP and typed-HTTP flows.
    #[serde(
        default = "NetworkLimits::default_max_tcp_flows",
        skip_serializing_if = "NetworkLimits::is_default_max_tcp_flows"
    )]
    pub max_tcp_flows: u32,
    /// Concurrent UDP associations.
    #[serde(
        default = "NetworkLimits::default_max_udp_associations",
        skip_serializing_if = "NetworkLimits::is_default_max_udp_associations"
    )]
    pub max_udp_associations: u32,
    /// Live host-owned DNS bindings.
    #[serde(
        default = "NetworkLimits::default_max_dns_bindings",
        skip_serializing_if = "NetworkLimits::is_default_max_dns_bindings"
    )]
    pub max_dns_bindings: u32,
    /// Declared ingress listeners.
    #[serde(
        default = "NetworkLimits::default_max_ingress_listeners",
        skip_serializing_if = "NetworkLimits::is_default_max_ingress_listeners"
    )]
    pub max_ingress_listeners: u16,
}

impl NetworkLimits {
    /// Start a validated limits builder from the compatibility defaults.
    #[must_use]
    pub const fn builder() -> NetworkLimitsBuilder {
        NetworkLimitsBuilder {
            limits: Self::defaults(),
        }
    }

    /// Whether every field has its compatibility default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Validate ceilings decoded from an untrusted or persisted wire value.
    /// Construction through the builder already calls this; runtime consumers
    /// call it again at their boundary so serde cannot bypass the invariant.
    pub fn validate(self) -> Result<Self, NetworkLimitsError> {
        if self.max_tcp_flows == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_tcp_flows",
            });
        }
        if self.max_udp_associations == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_udp_associations",
            });
        }
        if self.max_dns_bindings == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_dns_bindings",
            });
        }
        if self.max_ingress_listeners == 0 {
            return Err(NetworkLimitsError::Zero {
                field: "max_ingress_listeners",
            });
        }
        Ok(self)
    }

    const fn defaults() -> Self {
        Self {
            max_tcp_flows: Self::default_max_tcp_flows(),
            max_udp_associations: Self::default_max_udp_associations(),
            max_dns_bindings: Self::default_max_dns_bindings(),
            max_ingress_listeners: Self::default_max_ingress_listeners(),
        }
    }

    const fn default_max_tcp_flows() -> u32 {
        4096
    }

    const fn default_max_udp_associations() -> u32 {
        256
    }

    const fn default_max_dns_bindings() -> u32 {
        1024
    }

    const fn default_max_ingress_listeners() -> u16 {
        16
    }

    fn is_default_max_tcp_flows(value: &u32) -> bool {
        *value == Self::default_max_tcp_flows()
    }

    fn is_default_max_udp_associations(value: &u32) -> bool {
        *value == Self::default_max_udp_associations()
    }

    fn is_default_max_dns_bindings(value: &u32) -> bool {
        *value == Self::default_max_dns_bindings()
    }

    fn is_default_max_ingress_listeners(value: &u16) -> bool {
        *value == Self::default_max_ingress_listeners()
    }
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

/// Builder for a validated [`NetworkLimits`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkLimitsBuilder {
    limits: NetworkLimits,
}

impl NetworkLimitsBuilder {
    /// Set the aggregate TCP/HTTP flow ceiling.
    #[must_use]
    pub const fn max_tcp_flows(mut self, value: u32) -> Self {
        self.limits.max_tcp_flows = value;
        self
    }

    /// Set the UDP-association ceiling.
    #[must_use]
    pub const fn max_udp_associations(mut self, value: u32) -> Self {
        self.limits.max_udp_associations = value;
        self
    }

    /// Set the DNS-binding ceiling.
    #[must_use]
    pub const fn max_dns_bindings(mut self, value: u32) -> Self {
        self.limits.max_dns_bindings = value;
        self
    }

    /// Set the ingress-listener ceiling.
    #[must_use]
    pub const fn max_ingress_listeners(mut self, value: u16) -> Self {
        self.limits.max_ingress_listeners = value;
        self
    }

    /// Validate that every resource class retains a non-zero ceiling.
    pub fn build(self) -> Result<NetworkLimits, NetworkLimitsError> {
        self.limits.validate()
    }
}

/// Invalid signed networking limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetworkLimitsError {
    /// A zero ceiling would make a granted networking class unusable.
    #[error("network limit {field} must be greater than zero")]
    Zero { field: &'static str },
}

impl NetworkMode {
    /// Stable wire/CLI spelling. Matches the serde representation, so the
    /// CLI parser and the plan cannot drift apart.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HostVsockProxy => "host_vsock_proxy",
        }
    }
}

/// Transport protocol carried by a declared ingress mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressProtocol {
    Tcp,
    Udp,
}

/// Content treatment a declared ingress mapping requires from the host.
///
/// `Opaque` is the explicit no-transformation class. The endpoint refuses a
/// typed class when its host-owned transformation material is unavailable; it
/// never silently falls back to opaque relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressTransform {
    Opaque,
    Http,
    Tls,
}

/// One signed, transport-neutral ingress mapping.
///
/// The host owns the public listener and the guest receives bytes only through
/// the declared loopback target. `mapping_id` is the sole mapping identifier
/// carried by `InboundOpen`; addresses and transformation material never come
/// from unauthenticated flow bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressMapping {
    pub mapping_id: u16,
    pub protocol: IngressProtocol,
    /// Exact host address to bind. Wildcards are exposure declarations, not a
    /// runtime default, and therefore must appear literally in the signed plan.
    pub host_addr: String,
    pub host_port: u16,
    /// Exact loopback address inside the guest (`127.0.0.1` or `::1`).
    pub guest_addr: String,
    pub guest_port: u16,
    pub transform: IngressTransform,
    /// Plan-bound host secret containing the PEM certificate chain and private
    /// key used for TLS termination. The reference is signed; the resolved
    /// bytes remain inside the endpoint and never cross FlowMux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_secret: Option<String>,
}

impl IngressMapping {
    #[must_use]
    pub const fn builder() -> IngressMappingBuilder {
        IngressMappingBuilder::new()
    }

    /// Validate invariants that do not depend on host runtime state.
    pub fn validate(&self) -> Result<(), IngressMappingError> {
        if self.mapping_id == 0 {
            return Err(IngressMappingError::ZeroMappingId);
        }
        if self.host_addr.is_empty() {
            return Err(IngressMappingError::EmptyHostAddress);
        }
        if self.host_addr.parse::<core::net::IpAddr>().is_err() {
            return Err(IngressMappingError::InvalidHostAddress);
        }
        if self.host_port == 0 {
            return Err(IngressMappingError::ZeroPort { field: "host_port" });
        }
        if !matches!(self.guest_addr.as_str(), "127.0.0.1" | "::1") {
            return Err(IngressMappingError::GuestTargetNotLoopback);
        }
        if self.guest_port == 0 {
            return Err(IngressMappingError::ZeroPort {
                field: "guest_port",
            });
        }
        if self.protocol == IngressProtocol::Udp && self.transform != IngressTransform::Opaque {
            return Err(IngressMappingError::UnsupportedTransform {
                protocol: self.protocol,
                transform: self.transform,
            });
        }
        match (self.transform, self.tls_secret.as_deref()) {
            (IngressTransform::Tls, Some("")) => {
                return Err(IngressMappingError::EmptyTlsSecretReference);
            }
            (IngressTransform::Tls, None) => {
                return Err(IngressMappingError::MissingTlsSecretReference);
            }
            (IngressTransform::Opaque | IngressTransform::Http, Some(_)) => {
                return Err(IngressMappingError::UnexpectedTlsSecretReference);
            }
            (IngressTransform::Tls, Some(_))
            | (IngressTransform::Opaque | IngressTransform::Http, None) => {}
        }
        Ok(())
    }
}

/// Builder for the seven-field signed ingress mapping.
#[derive(Debug, Default)]
pub struct IngressMappingBuilder {
    mapping_id: Option<u16>,
    protocol: Option<IngressProtocol>,
    host_addr: Option<String>,
    host_port: Option<u16>,
    guest_addr: Option<String>,
    guest_port: Option<u16>,
    transform: Option<IngressTransform>,
    tls_secret: Option<String>,
}

impl IngressMappingBuilder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mapping_id: None,
            protocol: None,
            host_addr: None,
            host_port: None,
            guest_addr: None,
            guest_port: None,
            transform: None,
            tls_secret: None,
        }
    }

    #[must_use]
    pub const fn mapping_id(mut self, mapping_id: u16) -> Self {
        self.mapping_id = Some(mapping_id);
        self
    }

    #[must_use]
    pub const fn protocol(mut self, protocol: IngressProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    #[must_use]
    pub fn host_addr(mut self, host_addr: impl Into<String>) -> Self {
        self.host_addr = Some(host_addr.into());
        self
    }

    #[must_use]
    pub const fn host_port(mut self, host_port: u16) -> Self {
        self.host_port = Some(host_port);
        self
    }

    #[must_use]
    pub fn guest_addr(mut self, guest_addr: impl Into<String>) -> Self {
        self.guest_addr = Some(guest_addr.into());
        self
    }

    #[must_use]
    pub const fn guest_port(mut self, guest_port: u16) -> Self {
        self.guest_port = Some(guest_port);
        self
    }

    #[must_use]
    pub const fn transform(mut self, transform: IngressTransform) -> Self {
        self.transform = Some(transform);
        self
    }

    /// Set the signed reference to the host-only TLS PEM bundle.
    #[must_use]
    pub fn tls_secret(mut self, tls_secret: impl Into<String>) -> Self {
        self.tls_secret = Some(tls_secret.into());
        self
    }

    pub fn build(self) -> Result<IngressMapping, IngressMappingBuildError> {
        let mapping = IngressMapping {
            mapping_id: self
                .mapping_id
                .ok_or(IngressMappingBuildError::Missing("mapping_id"))?,
            protocol: self
                .protocol
                .ok_or(IngressMappingBuildError::Missing("protocol"))?,
            host_addr: self
                .host_addr
                .ok_or(IngressMappingBuildError::Missing("host_addr"))?,
            host_port: self
                .host_port
                .ok_or(IngressMappingBuildError::Missing("host_port"))?,
            guest_addr: self
                .guest_addr
                .ok_or(IngressMappingBuildError::Missing("guest_addr"))?,
            guest_port: self
                .guest_port
                .ok_or(IngressMappingBuildError::Missing("guest_port"))?,
            transform: self
                .transform
                .ok_or(IngressMappingBuildError::Missing("transform"))?,
            tls_secret: self.tls_secret,
        };
        mapping
            .validate()
            .map_err(IngressMappingBuildError::Invalid)?;
        Ok(mapping)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressMappingBuildError {
    #[error("missing required ingress mapping field {0}")]
    Missing(&'static str),
    #[error("invalid ingress mapping: {0}")]
    Invalid(IngressMappingError),
}

/// Why a signed ingress mapping is structurally invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressMappingError {
    #[error("ingress mapping id must be non-zero")]
    ZeroMappingId,
    #[error("ingress host address must not be empty")]
    EmptyHostAddress,
    #[error("ingress host address must be an exact IPv4 or IPv6 address")]
    InvalidHostAddress,
    #[error("ingress {field} must be non-zero")]
    ZeroPort { field: &'static str },
    #[error("ingress guest target must be loopback (127.0.0.1 or ::1)")]
    GuestTargetNotLoopback,
    #[error("ingress {transform:?} transformation is unsupported for {protocol:?}")]
    UnsupportedTransform {
        protocol: IngressProtocol,
        transform: IngressTransform,
    },
    #[error("TLS ingress requires a plan-bound certificate secret reference")]
    MissingTlsSecretReference,
    #[error("TLS ingress certificate secret reference must not be empty")]
    EmptyTlsSecretReference,
    #[error("only TLS ingress may carry a certificate secret reference")]
    UnexpectedTlsSecretReference,
}

/// Validate a complete signed ingress mapping set against its listener cap.
pub fn validate_ingress_mappings(
    mappings: &[IngressMapping],
    max_listeners: u16,
) -> Result<(), IngressMappingsError> {
    let count = u16::try_from(mappings.len()).unwrap_or(u16::MAX);
    if count > max_listeners {
        return Err(IngressMappingsError::TooMany {
            count,
            max: max_listeners,
        });
    }
    let mut ids = BTreeMap::new();
    let mut binds = BTreeMap::new();
    for (index, mapping) in mappings.iter().enumerate() {
        mapping
            .validate()
            .map_err(|source| IngressMappingsError::Invalid { index, source })?;
        if let Some(first) = ids.insert(mapping.mapping_id, index) {
            return Err(IngressMappingsError::DuplicateMappingId {
                mapping_id: mapping.mapping_id,
                first,
                duplicate: index,
            });
        }
        let bind = (
            mapping.protocol,
            mapping.host_addr.as_str(),
            mapping.host_port,
        );
        if let Some(first) = binds.insert(bind, index) {
            return Err(IngressMappingsError::DuplicateBind {
                first,
                duplicate: index,
            });
        }
    }
    Ok(())
}

/// Validate that every typed ingress mapping can obtain its host-owned
/// material from the same signed plan. Only keystore bindings are handed to
/// the endpoint's resolver today, so an external-provider reference is
/// refused rather than becoming a runtime downgrade to opaque relay.
pub fn validate_ingress_material(
    mappings: &[IngressMapping],
    secrets: &[SecretBinding],
) -> Result<(), IngressMappingsError> {
    for mapping in mappings {
        let Some(name) = mapping.tls_secret.as_deref() else {
            continue;
        };
        let Some(binding) = secrets.iter().find(|binding| binding.name == name) else {
            return Err(IngressMappingsError::TlsSecretNotInPlan {
                mapping_id: mapping.mapping_id,
            });
        };
        if !matches!(binding.source, SecretSource::Keystore { .. }) {
            return Err(IngressMappingsError::TlsSecretNotKeystore {
                mapping_id: mapping.mapping_id,
            });
        }
    }
    Ok(())
}

/// Why a signed ingress mapping set is inadmissible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressMappingsError {
    #[error("ingress declares {count} listeners, exceeding the admitted maximum {max}")]
    TooMany { count: u16, max: u16 },
    #[error("ingress mapping at index {index} is invalid: {source}")]
    Invalid {
        index: usize,
        source: IngressMappingError,
    },
    #[error("ingress mapping id {mapping_id} is duplicated at indexes {first} and {duplicate}")]
    DuplicateMappingId {
        mapping_id: u16,
        first: usize,
        duplicate: usize,
    },
    #[error("ingress listener bind is duplicated at indexes {first} and {duplicate}")]
    DuplicateBind { first: usize, duplicate: usize },
    #[error("ingress mapping {mapping_id} names a TLS secret absent from the signed plan")]
    TlsSecretNotInPlan { mapping_id: u16 },
    #[error("ingress mapping {mapping_id} names TLS material unavailable to the endpoint")]
    TlsSecretNotKeystore { mapping_id: u16 },
}

/// Whether this workload's captured output is written to a durable
/// transcript, or only fanned out to whoever is watching at the time.
///
/// Capture itself is not optional and is not expressed here: a live follower
/// works either way. What this decides is whether the host keeps an encrypted,
/// hash-chained copy on disk that outlives the run.
///
/// It rides in the signed plan rather than on a command line for one reason:
/// an unaudited opt-out makes a missing transcript indistinguishable from a
/// suppressed one. With the mode admitted and recorded, "was this run
/// recorded?" is answerable from the chain alone even when "what did it print?"
/// is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamRetention {
    /// Keep an encrypted transcript, sealed to a verifiable manifest at exit.
    #[default]
    Persist,
    /// Fan out live and keep nothing. No transcript is written, so a reader
    /// attaching after the workload ends finds no recording of it.
    Ephemeral,
}

impl StreamRetention {
    /// The label spelling, kept identical to the serde representation so an
    /// audit entry and a serialized plan can never disagree about the mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persist => "persist",
            Self::Ephemeral => "ephemeral",
        }
    }

    /// Whether a durable transcript is written under this mode.
    pub fn persists(self) -> bool {
        matches!(self, Self::Persist)
    }
}

/// How the workload image was specified — the source the deterministic build
/// pipeline consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// An OCI image reference.
    Oci,
    /// A bundled Nix template.
    NixTemplate,
    /// A Nix flake output (`.#app`).
    NixFlake,
    /// A local repo/project with detected Nix metadata.
    LocalProject,
}

/// Content-addressed digests (hex sha256) of the artifacts a build produced,
/// recorded so a launch is traceable to exact bytes. `None` = not applicable to
/// this workload (e.g. no initramfs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigests {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initramfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mvm_init: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_base: Option<String>,
}

/// Provenance of a workload build: what input was consumed, pinned how, by which
/// builder, producing which artifacts. Recorded in the signed plan so a launch
/// is traceable end-to-end to deterministic inputs and outputs. The build
/// pipeline populates it; absence (`None` on the plan) means provenance was not
/// recorded for this workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProvenance {
    /// Which kind of source produced this image.
    pub input_kind: InputKind,
    /// The supplied reference: OCI ref, flake ref, template name, or local
    /// project path.
    pub input_ref: String,
    /// Pin of the input: image manifest digest, `flake.lock` hash, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_digest: Option<String>,
    /// Identity/fingerprint of the builder VM that produced the artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_id: Option<String>,
    /// Content-addressed digests of the produced artifacts.
    #[serde(default)]
    pub artifacts: ArtifactDigests,
}

/// Stable identifier for an `ExecutionPlan` instance. Synthesis derives it
/// as the content-address of the plan body — `sha256:<64 lowercase hex>` over
/// every load-bearing field except the id itself — so a run is addressable and
/// hash-linkable by digest. The type stays an opaque `String` newtype: the
/// derivation lives in `mvm-core` (which owns the hashing crates), and this
/// no_std DTO crate only carries the value across the wire. Audit entries
/// reference this id verbatim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PlanId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TenantId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadId(pub String);

/// Reference to a runtime profile (Firecracker / libkrun / HVF / QEMU).
/// The open `BackendRegistry` resolves the name to a backend factory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeProfileRef(pub String);

/// The execution environment a workload is admitted to boot *in*, as opposed to
/// the image it boots. Content-addressed like [`SignedImageRef`].
///
/// This exists because the image digest alone does not determine how the
/// workload is confined. The same signed image, booted on a kernel built for a
/// different job, gets a different security posture — a kernel with
/// `CONFIG_USER_NS` enabled lets the guest enter a user namespace as uid 0,
/// which the workload kernel deliberately prevents. Without the kernel in the
/// plan, that difference is invisible: identical plan, identical image,
/// identical digests, and a posture decided by whatever the host had cached.
///
/// Pinning it makes the mismatch refusable at admission instead of silent at
/// boot. The struct (rather than a bare digest) is so the rest of the
/// environment — initrd, runtime overlay, seccomp tier — can be added without
/// another plan field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRef {
    /// Lowercase hex SHA-256 of the kernel image this workload boots.
    pub kernel_sha256: String,
}

/// Reference to a signed image. SHA-256 of the rootfs + name. The
/// `cosign_bundle` field
/// is the path or URL to the cosign keyless bundle that
/// `mvm-core::crypto::image_verify` validates against; in dev mode the
/// resolver may stub this to `None` and accept the digest alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedImageRef {
    pub name: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Cosign-keyless `.bundle` reference. Path on disk or URL
    /// resolvable by the supervisor. Stub in dev.
    pub cosign_bundle: Option<String>,
    /// False iff the sealed image declares no workload entrypoint.
    /// Defaults to true (every legacy plan + every dev image), and is
    /// skip-serialized when true so existing signed-plan fixtures stay
    /// byte-identical (the field is inside the signed payload). The
    /// supervisor refuses a plan whose image asserts entrypoint_present ==
    /// false — admission-time defense in depth behind the SDK's compile
    /// gate.
    #[serde(
        default = "default_entrypoint_present",
        skip_serializing_if = "is_entrypoint_present"
    )]
    pub entrypoint_present: bool,
}

fn default_entrypoint_present() -> bool {
    true
}

fn is_entrypoint_present(v: &bool) -> bool {
    *v
}

/// Resource budget. Hard caps; the supervisor refuses to start a VM
/// that would exceed the host's available capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpus: u32,
    pub mem_mib: u64,
    pub disk_mib: u64,
    pub timeouts: TimeoutSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutSpec {
    /// Max wall-clock for kernel boot + initramfs + minimal-init.
    pub boot_secs: u32,
    /// Max wall-clock for the workload itself. 0 = unbounded (only
    /// permitted for sleep-waking instances; supervisor enforces).
    pub exec_secs: u32,
}

/// Opaque pointer to a policy bundle. Until the real
/// `mvm-core::policy::PolicyBundle` resolver lands, this is a name the
/// supervisor's `Noop` resolver maps to a default-deny / open stance
/// per its bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FsPolicyRef(pub String);

/// Purpose label bound into the signed plan at admission time.
///
/// This is intentionally separate from [`WorkloadId`]: many workloads
/// can share the same security posture because they have the same
/// purpose (`code:execute`, `agent:web-research`, `deploy:publish`,
/// etc.). Resolvers use the intent to pick a concrete admission
/// profile before the backend boots.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadIntent(pub String);

/// Seccomp tier name as it appears in a signed `ExecutionPlan`.
///
/// The concrete filter lives in `mvm-core::crypto`; keeping this enum
/// in `mvm-core::plan` keeps the selected tier a typed, auditable plan
/// field decoupled from the filter impl.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanSeccompTier {
    Essential,
    Minimal,
    #[default]
    Standard,
    Network,
    Unrestricted,
}

impl core::fmt::Display for PlanSeccompTier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Essential => write!(f, "essential"),
            Self::Minimal => write!(f, "minimal"),
            Self::Standard => write!(f, "standard"),
            Self::Network => write!(f, "network"),
            Self::Unrestricted => write!(f, "unrestricted"),
        }
    }
}

impl core::str::FromStr for PlanSeccompTier {
    type Err = PlanSeccompTierParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "essential" => Ok(Self::Essential),
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "network" => Ok(Self::Network),
            "unrestricted" => Ok(Self::Unrestricted),
            _ => Err(PlanSeccompTierParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "unknown seccomp tier {value:?} (expected: essential, minimal, standard, network, unrestricted)"
)]
pub struct PlanSeccompTierParseError {
    pub value: String,
}

/// How a profile permits secrets to become visible to the workload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReleasePolicy {
    /// No secrets may be released.
    #[default]
    None,
    /// Secrets listed in `ExecutionPlan.secrets` may be released
    /// after plan signature, validity, replay, and policy checks pass.
    PlanBound,
    /// Secrets require the plan checks plus the plan's attestation
    /// requirement before release.
    AttestationBound,
}

/// Event naming and required labels for plan-bound audit output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTaxonomy {
    /// Prefix for events produced under this profile. Examples:
    /// `execution.code`, `agent.web`, `deploy.release`.
    pub event_prefix: String,
    /// Labels that must be copied into audit output for this profile.
    pub required_labels: Vec<String>,
}

/// Fully resolved admission controls for a signed plan.
///
/// This is the binding between a plan's declared purpose and the
/// concrete enforcement surfaces the runtime must use. The separate
/// top-level `network_policy`, `egress_policy`, `tool_policy`, and
/// `secrets` fields remain for backwards-compatible consumers; this
/// profile records why those refs were selected and which taxonomy
/// audit should use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProfile {
    pub id: String,
    pub intent: WorkloadIntent,
    pub seccomp_tier: PlanSeccompTier,
    pub network_policy: PolicyRef,
    pub fs_policy: FsPolicyRef,
    pub egress_policy: PolicyRef,
    pub tool_policy: PolicyRef,
    pub secret_release: SecretReleasePolicy,
    pub audit: AuditTaxonomy,
}

impl AdmissionProfile {
    /// Construct the local default profile used by legacy fixtures
    /// and direct local boots. This records the selected seccomp tier
    /// while leaving every policy ref at `local-default`.
    pub fn local_default(intent: impl Into<String>, seccomp_tier: PlanSeccompTier) -> Self {
        let intent = intent.into();
        let policy = PolicyRef("local-default".to_string());
        let fs_policy = FsPolicyRef("local-default".to_string());
        Self {
            id: format!("{intent}:{seccomp_tier}"),
            intent: WorkloadIntent(intent.clone()),
            seccomp_tier,
            network_policy: policy.clone(),
            fs_policy,
            egress_policy: policy.clone(),
            tool_policy: policy,
            secret_release: SecretReleasePolicy::None,
            audit: AuditTaxonomy {
                event_prefix: intent.replace(':', "."),
                required_labels: vec![
                    "intent".to_string(),
                    "admission_profile".to_string(),
                    "seccomp_tier".to_string(),
                ],
            },
        }
    }
}

/// Workload variant — `Dev` is the development sandbox (carries the
/// dev guest agent's RCE-by-design Exec handler, accepts looser
/// policies), `Prod` is the production posture (no dev primitives,
/// strict policy gates). The `L7EgressProxy` consults this at
/// construction time to refuse plain-HTTP egress for `Prod`.
///
/// Mirrors `passthru.variant` from Nix-side `mkGuest`. The supervisor
/// resolves it from the workload's `SignedImageRef.name` suffix or
/// from the policy bundle's bound variant; `audit::AuditEntry::variant`
/// records this for every entry, so the value flows through the audit
/// chain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Variant {
    Dev,
    Prod,
}

impl Variant {
    /// True iff this variant carries production-strict policy
    /// requirements (no dev RCE primitives, no plain-HTTP egress,
    /// verity-required rootfs, etc.).
    pub fn is_prod(self) -> bool {
        matches!(self, Variant::Prod)
    }
}

/// A secret binding from a name (visible inside the guest) to its
/// source (resolved by the supervisor's `KeystoreReleaser`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    /// Name as the workload sees it (e.g. env var name or
    /// `/run/mvm-secrets/<name>` file).
    pub name: String,
    pub source: SecretSource,
}

/// Where a secret comes from. Pluggable providers (Vault, AWS SM,
/// GCP SM) plus per-run attestation-gated release. A secret's raw
/// value never appears in a plan — only a reference the supervisor's
/// `KeystoreReleaser` resolves at admission; the plan (persisted to
/// `plan.json`) carries no plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SecretSource {
    /// Per-run release from the supervisor's keystore. The address
    /// resolves to a SecretId at the supervisor.
    Keystore { address: String },
    /// External provider (Vault, AWS SM, etc.). The provider URL +
    /// path are opaque to mvm-core::plan; resolved by `KeystoreReleaser`.
    External { provider: String, path: String },
}

/// Artifact-capture policy for the run. `capture_paths` are guest-side
/// directories the supervisor's `ArtifactCollector` sweeps post-run;
/// `retention_days` controls the cleanup sweeper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPolicy {
    pub capture_paths: Vec<String>,
    pub retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationSpec {
    /// 0 = no rotation required; supervisor warns but accepts.
    pub interval_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequirement {
    pub mode: AttestationMode,
}

/// Attestation modes. Real TPM2 / SEV / Apple providers land later;
/// the `Noop` mode lets every plan launch without attestation
/// (today's behaviour) for backwards compat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    /// No attestation. Stub. mvmctl warns; mvmd may refuse.
    Noop,
    /// TPM2 EK + AK quote. Supervisor's `KeystoreReleaser` gates
    /// secret release on a successful quote.
    Tpm2,
    /// AMD SEV-SNP report. Provider not yet implemented.
    SevSnp,
    /// Intel TDX quote. Provider not yet implemented.
    Tdx,
    /// Apple Device Attestation + Secure Enclave identity. Provider
    /// not yet implemented.
    AppleDeviceAttestation,
}

/// Release pinning: the workload runs at a specific release of
/// mvm/mvmd. Mismatch is grounds for refusal at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePin {
    pub release_id: String,
}

/// Lifecycle directives. The supervisor's plan state machine
/// consults these on workload exit / idle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostRunLifecycle {
    /// Tear down the VM on workload exit (one-shot semantics).
    pub destroy_on_exit: bool,
    /// Snapshot the VM after `idle_secs` of inactivity (sleep-wake).
    pub snapshot_on_idle: bool,
    /// Idle window before snapshot. Ignored if `snapshot_on_idle`
    /// is false. 0 = immediate.
    pub idle_secs: u32,
}

/// Convenience — the audit-labels alias the type uses. Free-form
/// `key: value` annotations the supervisor copies into every audit
/// entry generated for this plan.
pub type AuditLabels = BTreeMap<String, String>;

/// Opaque caller-supplied 32-byte commitment bound into an execution plan.
///
/// MVM validates only the byte width and canonical wire encoding. The caller
/// and external verifier define what the bytes commit to; MVM does not assign
/// a hash algorithm or interpret their semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(with = "String"))]
#[serde(try_from = "String", into = "String")]
pub struct CallerCommitment([u8; 32]);

impl CallerCommitment {
    /// Construct from the exact opaque bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse exactly 64 lowercase hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, CallerCommitmentParseError> {
        if value.len() != 64 {
            return Err(CallerCommitmentParseError::WrongLength { len: value.len() });
        }
        let mut bytes = [0u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = caller_commitment_nibble(pair[0])?;
            let low = caller_commitment_nibble(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact opaque bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render the canonical lowercase hexadecimal wire value.
    pub fn as_hex(&self) -> String {
        let mut value = String::with_capacity(64);
        for byte in self.0 {
            use core::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        value
    }
}

fn caller_commitment_nibble(byte: u8) -> Result<u8, CallerCommitmentParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CallerCommitmentParseError::NonHex {
            ch: char::from(byte),
        }),
    }
}

impl core::fmt::Display for CallerCommitment {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for CallerCommitment {
    type Err = CallerCommitmentParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl TryFrom<String> for CallerCommitment {
    type Error = CallerCommitmentParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(&value)
    }
}

impl From<CallerCommitment> for String {
    fn from(commitment: CallerCommitment) -> Self {
        commitment.as_hex()
    }
}

/// Invalid canonical encoding for a [`CallerCommitment`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallerCommitmentParseError {
    #[error("caller commitment hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    #[error("caller commitment hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

/// Per-plan replay-protection nonce. 16 random bytes, generated by
/// the plan signer. The supervisor's `NonceStore` (see
/// `crate::plan::validity`) refuses a second admission with the same
/// nonce for the same signer until the plan's `valid_until`
/// passes.
///
/// Wire format: 32-character lowercase hex string. Stored as a
/// string rather than `[u8; 16]` so JSON readers can eyeball it;
/// the type guarantees length and case via `from_hex` / `from_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(try_from = "String", into = "String")]
pub struct Nonce(String);

impl Nonce {
    /// Construct from 16 raw bytes. Always lowercases the hex.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut s = String::with_capacity(32);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        Self(s)
    }

    /// Construct from a hex string. Returns `Err` if the input is not
    /// exactly 32 lowercase hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, NonceParseError> {
        if hex.len() != 32 {
            return Err(NonceParseError::WrongLength { len: hex.len() });
        }
        for c in hex.chars() {
            if !matches!(c, '0'..='9' | 'a'..='f') {
                return Err(NonceParseError::NonHex { ch: c });
            }
        }
        Ok(Self(hex.to_string()))
    }

    /// 32-character lowercase-hex view.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Nonce {
    type Error = NonceParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_hex(&s)
    }
}

impl From<Nonce> for String {
    fn from(n: Nonce) -> Self {
        n.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NonceParseError {
    #[error("nonce hex must be exactly 32 chars, got {len}")]
    WrongLength { len: usize },
    #[error("nonce hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

#[cfg(test)]
mod caller_commitment_tests {
    use super::*;

    #[test]
    fn caller_commitment_round_trips_bytes_display_and_serde() {
        let commitment = CallerCommitment::from_bytes([0xabu8; 32]);
        let expected = "ab".repeat(32);
        assert_eq!(commitment.as_hex(), expected);
        assert_eq!(commitment.to_string(), expected);
        assert_eq!(commitment.as_bytes(), &[0xabu8; 32]);

        let json = serde_json::to_string(&commitment).expect("commitment serializes");
        assert_eq!(json, format!("\"{expected}\""));
        let recovered: CallerCommitment =
            serde_json::from_str(&json).expect("commitment deserializes");
        assert_eq!(recovered, commitment);
    }

    #[test]
    fn caller_commitment_rejects_noncanonical_or_wrong_length_hex() {
        assert!(matches!(
            CallerCommitment::from_hex(&"a".repeat(63)),
            Err(CallerCommitmentParseError::WrongLength { len: 63 })
        ));
        assert!(matches!(
            CallerCommitment::from_hex(&format!("{}G", "a".repeat(63))),
            Err(CallerCommitmentParseError::NonHex { ch: 'G' })
        ));
        assert!(matches!(
            CallerCommitment::from_hex(&"A".repeat(64)),
            Err(CallerCommitmentParseError::NonHex { ch: 'A' })
        ));
    }
}

/// Pin from an `ExecutionPlan` to an application-dependencies volume.
///
/// Backs security claim 9. When a workload mounts a deps volume at
/// `/app/.venv` (Python) or
/// `/app/node_modules` (Node), the plan binds the on-disk volume's
/// deterministic hashes here so the supervisor's admission gate can
/// re-verify them before launch.
///
/// Two hashes are pinned:
///
/// 1. **`volume_hash`** — the canonical
///    `sha256(content_sha256 || canonical(meta.json))` produced by
///    `mvm_sdk::compile::deps_audit::seal_volume`. This is the value
///    used as the volume directory name on disk
///    (`~/.mvm/volumes/deps/<volume_hash>/`).
/// 2. **`manifest_sha256`** — the SHA-256 of the canonical
///    `meta.json` bytes. Pinned separately so an attacker who
///    re-derives a volume hash for tampered content (which they
///    can't, modulo a SHA-256 break) still fails the second check.
///    Belt-and-suspenders against future hash-derivation changes.
///
/// Both are 64-character lowercase hex strings. The
/// `TryFrom<String>` impl rejects shorter/longer/uppercase/non-hex
/// inputs so a forged plan can't sneak a malformed pin past the
/// envelope's `deny_unknown_fields` gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepsVolumeBinding {
    /// Lowercase hex SHA-256, 64 chars. The volume directory name
    /// on disk under `~/.mvm/volumes/deps/`.
    #[serde(deserialize_with = "deserialize_sha256_hex")]
    pub volume_hash: String,
    /// Lowercase hex SHA-256, 64 chars. The hash of the canonical
    /// `meta.json` bytes inside the volume.
    #[serde(deserialize_with = "deserialize_sha256_hex")]
    pub manifest_sha256: String,
}

impl DepsVolumeBinding {
    /// Construct a binding. Returns `Err` if either hash is not
    /// 64 lowercase hex characters.
    pub fn new(
        volume_hash: impl Into<String>,
        manifest_sha256: impl Into<String>,
    ) -> Result<Self, DepsVolumeBindingError> {
        let volume_hash = validate_sha256_hex(volume_hash.into())?;
        let manifest_sha256 = validate_sha256_hex(manifest_sha256.into())?;
        Ok(Self {
            volume_hash,
            manifest_sha256,
        })
    }
}

/// Validation error for [`DepsVolumeBinding`] hash fields. Surfaces
/// through the `TryFrom<String>` impl on each field so a malformed
/// pin is rejected at serde deserialise time, before the supervisor
/// inspects the plan.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DepsVolumeBindingError {
    #[error("deps-volume hash must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    #[error("deps-volume hash must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

fn validate_sha256_hex(s: String) -> Result<String, DepsVolumeBindingError> {
    if s.len() != 64 {
        return Err(DepsVolumeBindingError::WrongLength { len: s.len() });
    }
    for c in s.chars() {
        if !matches!(c, '0'..='9' | 'a'..='f') {
            return Err(DepsVolumeBindingError::NonHex { ch: c });
        }
    }
    Ok(s)
}

fn deserialize_sha256_hex<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    validate_sha256_hex(s).map_err(serde::de::Error::custom)
}

/// Whether a [`HostShareGrant`] is a live directory share (virtio-fs)
/// or a disk image (virtio-blk).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareKind {
    DirShare,
    Disk,
}

/// A host-filesystem grant recorded in — and signed with — the
/// `ExecutionPlan`: one user `--volume` directory share or disk image.
///
/// Claim 1 ("no host-fs access from a guest beyond explicit shares") +
/// claim 8. Today user volumes attach as a host-side launch detail; this
/// binding makes each an *admitted, signed, audited* grant so a future
/// supervisor-side "refuse a share the admitted plan didn't name"
/// gate can allow them, and every admission emits the list to the
/// chain-signed audit log. `deny_unknown_fields` + the
/// absolute-path check keep a forged plan from smuggling a grant past
/// the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostShareGrant {
    /// Coordination tag/id the backend assigns (`uvol{idx}`) — the
    /// virtio-fs tag or virtio-blk device id.
    pub tag: String,
    /// Resolved (canonical) host path shared/attached. The CLI pins the
    /// symlink-resolved path here (TOCTOU-safe).
    pub host_path: String,
    /// Absolute guest mount point.
    #[serde(deserialize_with = "deserialize_abs_path")]
    pub guest_path: String,
    pub kind: ShareKind,
    pub read_only: bool,
    /// Disk-only: in-guest encryption requested. Always false for a
    /// directory share.
    #[serde(default)]
    pub encrypted: bool,
}

/// Reject a non-absolute or empty guest path at deserialize time.
fn deserialize_abs_path<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    if !s.starts_with('/') {
        return Err(serde::de::Error::custom(format!(
            "guest_path must be absolute (start with '/'), got {s:?}"
        )));
    }
    Ok(s)
}

#[cfg(test)]
mod host_share_grant_tests {
    use super::*;

    fn sample() -> HostShareGrant {
        HostShareGrant {
            tag: "uvol0".into(),
            host_path: "/host/src".into(),
            guest_path: "/work2".into(),
            kind: ShareKind::DirShare,
            read_only: true,
            encrypted: false,
        }
    }

    #[test]
    fn roundtrips_through_json() {
        let g = sample();
        let json = serde_json::to_string(&g).unwrap();
        // snake_case for the kind discriminant.
        assert!(json.contains("\"dir_share\""), "{json}");
        let back: HostShareGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn disk_kind_serializes_snake_case() {
        let json = serde_json::to_string(&ShareKind::Disk).unwrap();
        assert_eq!(json, "\"disk\"");
    }

    #[test]
    fn rejects_relative_guest_path() {
        let json = r#"{"tag":"uvol0","host_path":"/h","guest_path":"work2",
            "kind":"dir_share","read_only":false}"#;
        let err = serde_json::from_str::<HostShareGrant>(json).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let json = r#"{"tag":"uvol0","host_path":"/h","guest_path":"/g",
            "kind":"disk","read_only":false,"bogus":1}"#;
        assert!(serde_json::from_str::<HostShareGrant>(json).is_err());
    }

    #[test]
    fn encrypted_defaults_false_when_absent() {
        let json = r#"{"tag":"uvol0","host_path":"/h","guest_path":"/g",
            "kind":"disk","read_only":false}"#;
        let g: HostShareGrant = serde_json::from_str(json).unwrap();
        assert!(!g.encrypted);
    }
}

#[cfg(test)]
mod signed_image_ref_tests {
    use super::*;

    /// Byte-identity guard: a default-true `entrypoint_present` must
    /// NOT serialize, so every existing
    /// signed-plan fixture (which never carried the field) hashes the
    /// same bytes and its Ed25519 signature stays valid.
    #[test]
    fn serde_omits_entrypoint_present_when_true() {
        let r = SignedImageRef {
            name: "img".into(),
            sha256: "a".repeat(64),
            cosign_bundle: None,
            entrypoint_present: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("entrypoint_present"),
            "default-true field leaked into wire: {json}"
        );

        // A plan JSON without the key round-trips to true (default).
        let back: SignedImageRef =
            serde_json::from_str(r#"{"name":"img","sha256":"deadbeef","cosign_bundle":null}"#)
                .unwrap();
        assert!(back.entrypoint_present);
    }

    /// The guard field is serialized only when false — the one case the
    /// supervisor's admission gate must see on the wire.
    #[test]
    fn serde_emits_entrypoint_present_when_false() {
        let r = SignedImageRef {
            name: "img".into(),
            sha256: "a".repeat(64),
            cosign_bundle: None,
            entrypoint_present: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"entrypoint_present\":false"), "{json}");
        let back: SignedImageRef = serde_json::from_str(&json).unwrap();
        assert!(!back.entrypoint_present);
    }
}

#[cfg(test)]
mod network_mode_tests {
    use super::*;

    #[test]
    fn default_is_closed_none() {
        assert_eq!(NetworkMode::default(), NetworkMode::None);
    }

    #[test]
    fn serde_uses_snake_case_tokens() {
        assert_eq!(
            serde_json::to_string(&NetworkMode::HostVsockProxy).unwrap(),
            "\"host_vsock_proxy\""
        );
        assert_eq!(
            serde_json::from_str::<NetworkMode>("\"none\"").unwrap(),
            NetworkMode::None
        );
    }

    #[test]
    fn stale_l3_token_is_refused_with_migration_guidance() {
        let err = serde_json::from_str::<NetworkMode>("\"l3_vsock\"")
            .expect_err("retired mode must not enter the admitted domain");
        let message = err.to_string();
        assert!(message.contains("l3_vsock has been retired"), "{message}");
        assert!(message.contains("FlowMux loopback adapters"), "{message}");
        assert!(message.contains("typed connector"), "{message}");
    }

    #[test]
    fn unknown_token_is_not_reported_as_a_retired_mode() {
        let err = serde_json::from_str::<NetworkMode>("\"future_mode\"")
            .expect_err("unknown modes must fail closed");
        let message = err.to_string();
        assert!(message.contains("unknown variant"), "{message}");
        assert!(!message.contains("has been retired"), "{message}");
    }
}

#[cfg(test)]
mod network_limits_tests {
    use super::*;

    #[test]
    fn defaults_match_the_existing_endpoint_ceilings() {
        let limits = NetworkLimits::default();
        assert_eq!(limits.max_tcp_flows, 4096);
        assert_eq!(limits.max_udp_associations, 256);
        assert_eq!(limits.max_dns_bindings, 1024);
        assert_eq!(limits.max_ingress_listeners, 16);
    }

    #[test]
    fn default_fields_are_omitted_and_roundtrip() {
        let json = serde_json::to_string(&NetworkLimits::default()).unwrap();
        assert_eq!(json, "{}");
        assert_eq!(
            serde_json::from_str::<NetworkLimits>(&json).unwrap(),
            NetworkLimits::default()
        );
    }

    #[test]
    fn builder_preserves_custom_values() {
        let limits = NetworkLimits::builder()
            .max_tcp_flows(12)
            .max_udp_associations(13)
            .max_dns_bindings(14)
            .max_ingress_listeners(15)
            .build()
            .unwrap();
        assert_eq!(limits.max_tcp_flows, 12);
        assert_eq!(limits.max_udp_associations, 13);
        assert_eq!(limits.max_dns_bindings, 14);
        assert_eq!(limits.max_ingress_listeners, 15);
    }

    #[test]
    fn builder_refuses_zero_for_every_resource_class() {
        for result in [
            NetworkLimits::builder().max_tcp_flows(0).build(),
            NetworkLimits::builder().max_udp_associations(0).build(),
            NetworkLimits::builder().max_dns_bindings(0).build(),
            NetworkLimits::builder().max_ingress_listeners(0).build(),
        ] {
            assert!(matches!(result, Err(NetworkLimitsError::Zero { .. })));
        }
    }

    #[test]
    fn validation_refuses_a_zero_decoded_by_serde() {
        let decoded: NetworkLimits = serde_json::from_str(r#"{"max_tcp_flows":0}"#).unwrap();
        assert_eq!(
            decoded.validate(),
            Err(NetworkLimitsError::Zero {
                field: "max_tcp_flows"
            })
        );
    }
}

#[cfg(test)]
mod ingress_mapping_tests {
    use super::*;

    fn opaque_tcp() -> IngressMapping {
        IngressMapping {
            mapping_id: 1,
            protocol: IngressProtocol::Tcp,
            host_addr: "127.0.0.1".to_string(),
            host_port: 8443,
            guest_addr: "127.0.0.1".to_string(),
            guest_port: 8080,
            transform: IngressTransform::Opaque,
            tls_secret: None,
        }
    }

    #[test]
    fn valid_mapping_roundtrips_with_explicit_class() {
        let mapping = opaque_tcp();
        mapping.validate().unwrap();
        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("\"mapping_id\":1"), "{json}");
        assert!(json.contains("\"transform\":\"opaque\""), "{json}");
        assert_eq!(
            serde_json::from_str::<IngressMapping>(&json).unwrap(),
            mapping
        );
    }

    #[test]
    fn mapping_refuses_non_loopback_guest_target() {
        let mut mapping = opaque_tcp();
        mapping.guest_addr = "10.0.0.2".to_string();
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::GuestTargetNotLoopback)
        );
    }

    #[test]
    fn mapping_refuses_zero_identity_and_ports() {
        let mut mapping = opaque_tcp();
        mapping.mapping_id = 0;
        assert_eq!(mapping.validate(), Err(IngressMappingError::ZeroMappingId));

        let mut mapping = opaque_tcp();
        mapping.host_port = 0;
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::ZeroPort { field: "host_port" })
        );

        let mut mapping = opaque_tcp();
        mapping.guest_port = 0;
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::ZeroPort {
                field: "guest_port"
            })
        );
    }

    #[test]
    fn udp_refuses_typed_transformation() {
        let mut mapping = opaque_tcp();
        mapping.protocol = IngressProtocol::Udp;
        mapping.transform = IngressTransform::Tls;
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::UnsupportedTransform {
                protocol: IngressProtocol::Udp,
                transform: IngressTransform::Tls,
            })
        );
    }

    #[test]
    fn tls_requires_exactly_one_nonempty_host_secret_reference() {
        let mut mapping = opaque_tcp();
        mapping.transform = IngressTransform::Tls;
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::MissingTlsSecretReference)
        );

        mapping.tls_secret = Some(String::new());
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::EmptyTlsSecretReference)
        );

        mapping.tls_secret = Some("INGRESS_TLS_PEM".to_string());
        mapping.validate().unwrap();

        mapping.transform = IngressTransform::Opaque;
        assert_eq!(
            mapping.validate(),
            Err(IngressMappingError::UnexpectedTlsSecretReference)
        );
    }

    #[test]
    fn unknown_mapping_field_is_refused() {
        let mut json = serde_json::to_value(opaque_tcp()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<IngressMapping>(json).is_err());
    }

    #[test]
    fn mapping_set_refuses_duplicate_id_and_bind() {
        let first = opaque_tcp();
        let mut duplicate_id = first.clone();
        duplicate_id.host_port = 8444;
        assert_eq!(
            validate_ingress_mappings(&[first.clone(), duplicate_id], 16),
            Err(IngressMappingsError::DuplicateMappingId {
                mapping_id: 1,
                first: 0,
                duplicate: 1,
            })
        );

        let mut duplicate_bind = first.clone();
        duplicate_bind.mapping_id = 2;
        assert_eq!(
            validate_ingress_mappings(&[first, duplicate_bind], 16),
            Err(IngressMappingsError::DuplicateBind {
                first: 0,
                duplicate: 1,
            })
        );
    }

    #[test]
    fn mapping_set_refuses_listener_exhaustion() {
        assert_eq!(
            validate_ingress_mappings(&[opaque_tcp()], 0),
            Err(IngressMappingsError::TooMany { count: 1, max: 0 })
        );
    }

    #[test]
    fn tls_material_must_be_a_keystore_secret_in_the_same_plan() {
        let mapping = IngressMapping::builder()
            .mapping_id(7)
            .protocol(IngressProtocol::Tcp)
            .host_addr("127.0.0.1")
            .host_port(8443)
            .guest_addr("127.0.0.1")
            .guest_port(8080)
            .transform(IngressTransform::Tls)
            .tls_secret("INGRESS_TLS_PEM")
            .build()
            .unwrap();
        assert_eq!(
            validate_ingress_material(std::slice::from_ref(&mapping), &[]),
            Err(IngressMappingsError::TlsSecretNotInPlan { mapping_id: 7 })
        );

        let external = SecretBinding {
            name: "INGRESS_TLS_PEM".to_string(),
            source: SecretSource::External {
                provider: "vault".to_string(),
                path: "ingress/tls".to_string(),
            },
        };
        assert_eq!(
            validate_ingress_material(std::slice::from_ref(&mapping), &[external]),
            Err(IngressMappingsError::TlsSecretNotKeystore { mapping_id: 7 })
        );

        let keystore = SecretBinding {
            name: "INGRESS_TLS_PEM".to_string(),
            source: SecretSource::Keystore {
                address: "ingress/tls".to_string(),
            },
        };
        validate_ingress_material(&[mapping], &[keystore]).unwrap();
    }
}

#[cfg(test)]
mod build_provenance_tests {
    use super::*;

    #[test]
    fn input_kind_uses_snake_case_tokens() {
        assert_eq!(
            serde_json::to_string(&InputKind::NixFlake).unwrap(),
            "\"nix_flake\""
        );
        assert_eq!(
            serde_json::from_str::<InputKind>("\"local_project\"").unwrap(),
            InputKind::LocalProject
        );
    }

    #[test]
    fn provenance_round_trips_with_digests() {
        let prov = BuildProvenance {
            input_kind: InputKind::Oci,
            input_ref: "docker.io/library/alpine@sha256:abc".to_string(),
            lock_digest: Some("sha256:manifest".to_string()),
            builder_id: Some("builder-hvf-01".to_string()),
            artifacts: ArtifactDigests {
                kernel: Some("k".repeat(64)),
                rootfs: Some("r".repeat(64)),
                mvm_init: Some("i".repeat(64)),
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&prov).unwrap();
        let back: BuildProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back, prov);
    }

    #[test]
    fn absent_artifact_digests_are_omitted_not_null() {
        let digests = ArtifactDigests {
            kernel: Some("k".repeat(64)),
            ..Default::default()
        };
        let json = serde_json::to_string(&digests).unwrap();
        assert!(json.contains("kernel"));
        assert!(
            !json.contains("initramfs"),
            "absent digests omitted: {json}"
        );
    }
}

#[cfg(test)]
mod attestation_mode_tests {
    use super::*;

    #[test]
    fn attestation_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&AttestationMode::Noop).unwrap(),
            "\"noop\""
        );
        assert_eq!(
            serde_json::to_string(&AttestationMode::Tpm2).unwrap(),
            "\"tpm2\""
        );
        assert_eq!(
            serde_json::to_string(&AttestationMode::SevSnp).unwrap(),
            "\"sev_snp\""
        );
        assert_eq!(
            serde_json::to_string(&AttestationMode::Tdx).unwrap(),
            "\"tdx\""
        );
        assert_eq!(
            serde_json::to_string(&AttestationMode::AppleDeviceAttestation).unwrap(),
            "\"apple_device_attestation\""
        );
    }

    #[test]
    fn attestation_mode_round_trips_through_json() {
        for mode in [
            AttestationMode::Noop,
            AttestationMode::Tpm2,
            AttestationMode::SevSnp,
            AttestationMode::Tdx,
            AttestationMode::AppleDeviceAttestation,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: AttestationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode, "{json} round-trip failed");
        }
    }
}
