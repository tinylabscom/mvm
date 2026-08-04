//! The network lease: one signed grant of network identity for one VM boot.
//!
//! A lease is what makes local and cluster networking the same model. A
//! standalone `mvmctl` mints one locally; a control plane will later issue
//! one centrally. Either way the node-local data plane verifies the same
//! object, and the packet path never learns which produced it.
//!
//! What a lease is bound to is the point:
//!
//! - one VM boot, by [`VmInstanceIdentity`] — so a restart cannot replay it;
//! - one node — so it cannot be used elsewhere without an explicit
//!   migration;
//! - one plan digest and one policy epoch — so a plan revision retires it;
//! - a validity window — so losing the issuer eventually closes the path
//!   rather than leaving it open.
//!
//! Verification is fail-closed at every step, and a lease that does not
//! verify grants nothing at all.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::channel::VmInstanceIdentity;

/// Wire version of the lease object.
pub const LEASE_VERSION: u32 = 1;

/// A declared ingress mapping carried in a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseIngress {
    /// `"tcp"`. UDP ingress is not implemented and is refused at admission.
    pub proto: String,
    pub host_addr: String,
    pub host_port: u16,
    pub guest_port: u16,
}

/// One signed network grant for one VM boot.
///
/// The signature covers every field except itself; `signing_bytes` is the
/// canonical form both the issuer and the verifier hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkLease {
    pub version: u32,
    pub lease_id: String,

    // --- identity: what this lease is bound to ---
    pub tenant_id: String,
    pub node_id: String,
    pub vm_id: String,
    /// Fresh per boot. This is what stops a restarted machine from
    /// presenting its predecessor's lease.
    pub boot_id: String,
    pub plan_digest: String,

    // --- the grant ---
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    /// The point-to-point peer and synthetic resolver.
    pub gateway_ipv4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    /// CIDRs this VM may reach beyond its plan's host rules. Empty is the
    /// safe default.
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub ingress: Vec<LeaseIngress>,
    /// Digest of the egress policy this lease was issued against. A policy
    /// change that does not move the digest cannot silently widen a live
    /// lease.
    pub egress_policy_digest: String,

    // --- validity ---
    pub policy_epoch: u64,
    /// Milliseconds since the Unix epoch. Millisecond integers rather than
    /// a formatted timestamp so verification is arithmetic, not parsing.
    pub issued_at_millis: u64,
    pub not_before_millis: u64,
    pub expires_at_millis: u64,

    /// Signature over [`Self::signing_bytes`]. Hex-encoded.
    pub signature: String,
    /// Which key signed it, so a verifier can select the right one without
    /// trying them all.
    pub key_id: String,
}

impl NetworkLease {
    /// The exact bytes a signature covers: every field except `signature`,
    /// in a fixed order.
    ///
    /// Built by hand rather than by serializing the struct, so adding a
    /// field is a deliberate act — a new field that silently joined the
    /// signed form would change every existing lease's digest, and one that
    /// silently stayed out would be unauthenticated.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let mut push = |label: &str, value: &str| {
            out.extend_from_slice(label.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value.as_bytes());
            out.push(b'\n');
        };
        push("version", &self.version.to_string());
        push("lease_id", &self.lease_id);
        push("tenant_id", &self.tenant_id);
        push("node_id", &self.node_id);
        push("vm_id", &self.vm_id);
        push("boot_id", &self.boot_id);
        push("plan_digest", &self.plan_digest);
        push(
            "ipv4",
            &self.ipv4.map(|a| a.to_string()).unwrap_or_default(),
        );
        push(
            "ipv6",
            &self.ipv6.map(|a| a.to_string()).unwrap_or_default(),
        );
        push(
            "gateway_ipv4",
            &self.gateway_ipv4.map(|a| a.to_string()).unwrap_or_default(),
        );
        push("dns_name", self.dns_name.as_deref().unwrap_or(""));
        push("routes", &self.routes.join(","));
        push(
            "ingress",
            &self
                .ingress
                .iter()
                .map(|i| {
                    format!(
                        "{}:{}:{}:{}",
                        i.proto, i.host_addr, i.host_port, i.guest_port
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
        );
        push("egress_policy_digest", &self.egress_policy_digest);
        push("policy_epoch", &self.policy_epoch.to_string());
        push("issued_at_millis", &self.issued_at_millis.to_string());
        push("not_before_millis", &self.not_before_millis.to_string());
        push("expires_at_millis", &self.expires_at_millis.to_string());
        push("key_id", &self.key_id);
        out
    }

    /// The instance identity this lease is bound to.
    pub fn instance(&self) -> VmInstanceIdentity {
        VmInstanceIdentity::new(
            self.node_id.clone(),
            self.vm_id.clone(),
            self.boot_id.clone(),
            self.plan_digest.clone(),
        )
    }

    /// Whether the lease is inside its validity window.
    pub fn is_valid_at(&self, now_millis: u64) -> bool {
        now_millis >= self.not_before_millis && now_millis < self.expires_at_millis
    }

    /// Milliseconds until expiry, saturating at zero.
    pub fn remaining_millis(&self, now_millis: u64) -> u64 {
        self.expires_at_millis.saturating_sub(now_millis)
    }

    /// Routes parsed into CIDRs, refusing anything unparseable rather than
    /// skipping it.
    pub fn parsed_routes(&self) -> Result<Vec<IpNet>, LeaseError> {
        self.routes
            .iter()
            .map(|r| {
                r.parse::<IpNet>()
                    .map_err(|_| LeaseError::MalformedRoute(r.clone()))
            })
            .collect()
    }
}

/// Why a lease was refused. Every variant denies the whole lease: there is
/// no partial acceptance, because a lease that is wrong about its identity
/// is not a lease with one bad field.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    #[error("lease version {got} is not supported (this build reads {want})")]
    UnsupportedVersion { got: u32, want: u32 },
    #[error("lease signature does not verify under key {key_id:?}")]
    BadSignature { key_id: String },
    #[error("no trusted key with id {0:?}")]
    UnknownKey(String),
    /// The lease names a different boot than the one asking to use it.
    #[error("lease is bound to {expected} but was presented for {actual}")]
    WrongInstance { expected: String, actual: String },
    /// The lease was issued for another node.
    #[error("lease was issued for node {issued_for:?}, this node is {here:?}")]
    WrongNode { issued_for: String, here: String },
    #[error("lease is not valid until {not_before_millis} (now {now_millis})")]
    NotYetValid {
        not_before_millis: u64,
        now_millis: u64,
    },
    #[error("lease expired at {expires_at_millis} (now {now_millis})")]
    Expired {
        expires_at_millis: u64,
        now_millis: u64,
    },
    /// The plan's policy epoch has moved past the lease's.
    #[error("lease policy epoch {lease_epoch} is behind the admitted {plan_epoch}")]
    StaleEpoch { lease_epoch: u64, plan_epoch: u64 },
    /// The lease's egress digest does not match the admitted policy's.
    #[error("lease egress policy digest {lease:?} does not match the admitted {admitted:?}")]
    PolicyDigestMismatch { lease: String, admitted: String },
    #[error("lease assigns no address")]
    NoAddress,
    #[error("lease route {0:?} is not a CIDR")]
    MalformedRoute(String),
    /// A lease named an ingress protocol nothing lowers.
    #[error("lease declares ingress protocol {0:?} (expected \"tcp\" or \"udp\")")]
    UnknownIngressProto(String),
}

/// What the verifier checks a lease against.
#[derive(Debug, Clone)]
pub struct LeaseContext {
    /// The boot asking to use the lease. Host-owned; never guest-supplied.
    pub instance: VmInstanceIdentity,
    /// Policy epoch of the admitted plan.
    pub plan_policy_epoch: u64,
    /// Digest of the admitted egress policy.
    pub egress_policy_digest: String,
    pub now_millis: u64,
}

/// Verifies lease signatures. Abstracted so the standalone local authority
/// and a future central issuer share one verification path.
pub trait LeaseVerifier: Send + Sync {
    /// Whether `signature` is valid over `bytes` under `key_id`.
    fn verify(&self, key_id: &str, bytes: &[u8], signature: &str) -> Result<(), LeaseError>;
}

/// Check a lease end to end.
///
/// Order matters: version, then signature, then binding, then validity.
/// Nothing about the grant is read before the signature is confirmed, so a
/// forged lease cannot steer the verifier through its own fields.
pub fn verify_lease(
    lease: &NetworkLease,
    verifier: &dyn LeaseVerifier,
    ctx: &LeaseContext,
) -> Result<(), LeaseError> {
    if lease.version != LEASE_VERSION {
        return Err(LeaseError::UnsupportedVersion {
            got: lease.version,
            want: LEASE_VERSION,
        });
    }
    verifier.verify(&lease.key_id, &lease.signing_bytes(), &lease.signature)?;

    // Identity binding: the lease must name this exact boot.
    let bound = lease.instance();
    if bound.node_id != ctx.instance.node_id {
        return Err(LeaseError::WrongNode {
            issued_for: bound.node_id,
            here: ctx.instance.node_id.clone(),
        });
    }
    if !bound.is_same_boot(&ctx.instance) {
        return Err(LeaseError::WrongInstance {
            expected: bound.audit_label(),
            actual: ctx.instance.audit_label(),
        });
    }

    if ctx.now_millis < lease.not_before_millis {
        return Err(LeaseError::NotYetValid {
            not_before_millis: lease.not_before_millis,
            now_millis: ctx.now_millis,
        });
    }
    if ctx.now_millis >= lease.expires_at_millis {
        return Err(LeaseError::Expired {
            expires_at_millis: lease.expires_at_millis,
            now_millis: ctx.now_millis,
        });
    }
    if lease.policy_epoch != ctx.plan_policy_epoch {
        return Err(LeaseError::StaleEpoch {
            lease_epoch: lease.policy_epoch,
            plan_epoch: ctx.plan_policy_epoch,
        });
    }
    if lease.egress_policy_digest != ctx.egress_policy_digest {
        return Err(LeaseError::PolicyDigestMismatch {
            lease: lease.egress_policy_digest.clone(),
            admitted: ctx.egress_policy_digest.clone(),
        });
    }
    if lease.ipv4.is_none() && lease.ipv6.is_none() {
        return Err(LeaseError::NoAddress);
    }
    if let Some(unknown) = lease
        .ingress
        .iter()
        .find(|i| !matches!(i.proto.as_str(), "tcp" | "udp"))
    {
        return Err(LeaseError::UnknownIngressProto(unknown.proto.clone()));
    }
    lease.parsed_routes()?;
    Ok(())
}

/// Issues leases for a single host with no control plane.
///
/// The point is that `mvmctl` produces the *same* object a control plane
/// would, so there is one networking model rather than a local one and a
/// cluster one. The signature here is a keyed MAC over the same canonical
/// bytes: a standalone node is both issuer and verifier, so an asymmetric
/// key would buy nothing, and the shape stays identical for the day a real
/// issuer signs it.
#[derive(Debug, Clone)]
pub struct LocalLeaseAuthority {
    node_id: String,
    key_id: String,
    key: [u8; 32],
    /// How long a locally-issued lease lives.
    ttl_millis: u64,
}

/// Default lifetime of a locally-issued lease. Long enough that a normal
/// workload never notices, short enough that a leaked one is not forever.
pub const DEFAULT_LOCAL_LEASE_TTL_MILLIS: u64 = 24 * 60 * 60 * 1000;

impl LocalLeaseAuthority {
    pub fn new(node_id: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            node_id: node_id.into(),
            key_id: "local-node".to_string(),
            key,
            ttl_millis: DEFAULT_LOCAL_LEASE_TTL_MILLIS,
        }
    }

    pub fn with_ttl(mut self, ttl_millis: u64) -> Self {
        self.ttl_millis = ttl_millis;
        self
    }

    /// Mint a lease for one boot.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(&self, request: &LeaseRequest<'_>) -> NetworkLease {
        let mut lease = NetworkLease {
            version: LEASE_VERSION,
            lease_id: format!(
                "{}-{}-{}",
                request.instance.vm_id, request.instance.boot_id, request.now_millis
            ),
            tenant_id: request.tenant_id.to_string(),
            node_id: self.node_id.clone(),
            vm_id: request.instance.vm_id.clone(),
            boot_id: request.instance.boot_id.clone(),
            plan_digest: request.instance.plan_digest.clone(),
            ipv4: Some(request.ipv4),
            ipv6: None,
            gateway_ipv4: Some(request.gateway_ipv4),
            dns_name: request.dns_name.map(str::to_string),
            routes: request.routes.iter().map(|r| r.to_string()).collect(),
            ingress: request.ingress.to_vec(),
            egress_policy_digest: request.egress_policy_digest.to_string(),
            policy_epoch: request.policy_epoch,
            issued_at_millis: request.now_millis,
            not_before_millis: request.now_millis,
            expires_at_millis: request.now_millis.saturating_add(self.ttl_millis),
            signature: String::new(),
            key_id: self.key_id.clone(),
        };
        lease.signature = hex(&mac(&self.key, &lease.signing_bytes()));
        lease
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

/// Everything needed to mint one lease.
#[derive(Debug, Clone)]
pub struct LeaseRequest<'a> {
    pub instance: &'a VmInstanceIdentity,
    pub tenant_id: &'a str,
    pub ipv4: Ipv4Addr,
    pub gateway_ipv4: Ipv4Addr,
    pub dns_name: Option<&'a str>,
    pub routes: &'a [IpNet],
    pub ingress: &'a [LeaseIngress],
    pub egress_policy_digest: &'a str,
    pub policy_epoch: u64,
    pub now_millis: u64,
}

impl LeaseVerifier for LocalLeaseAuthority {
    fn verify(&self, key_id: &str, bytes: &[u8], signature: &str) -> Result<(), LeaseError> {
        if key_id != self.key_id {
            return Err(LeaseError::UnknownKey(key_id.to_string()));
        }
        let expected = hex(&mac(&self.key, bytes));
        // Constant-time compare: a signature check that leaks position
        // through timing is a signature check an attacker can walk.
        if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            return Err(LeaseError::BadSignature {
                key_id: key_id.to_string(),
            });
        }
        Ok(())
    }
}

/// Keyed MAC over the canonical bytes, built from the workspace's existing
/// SHA-256 rather than a new dependency.
fn mac(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    // HMAC-SHA256, written out: the workspace already carries sha2, and a
    // second MAC crate for one call site is not worth the dependency.
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(bytes);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// What to do while the issuer is unreachable.
///
/// Never "fall back to unrestricted". The choice is only how quickly an
/// already-admitted workload loses what it had.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ControlPlaneLossPolicy {
    /// Existing flows continue until the lease expires; no new flows.
    /// The conservative default.
    #[default]
    HoldExistingDenyNew,
    /// Existing and new flows both continue until the lease expires.
    HoldUntilExpiry,
    /// Everything stops immediately.
    DenyImmediately,
}

impl ControlPlaneLossPolicy {
    /// Whether a new flow may open while the issuer is unreachable and the
    /// lease is still inside its window.
    pub fn permits_new_flows(self) -> bool {
        matches!(self, Self::HoldUntilExpiry)
    }

    /// Whether established flows continue while the issuer is unreachable.
    pub fn holds_existing_flows(self) -> bool {
        !matches!(self, Self::DenyImmediately)
    }

    /// What to do once the lease itself has expired. There is exactly one
    /// answer, which is why this is a function and not a field.
    pub fn after_expiry_permits_anything(self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const NOW: u64 = 1_000_000;

    fn instance() -> VmInstanceIdentity {
        VmInstanceIdentity::new("node-1", "vm-a", "boot-1", "sha256:plan")
    }

    fn authority() -> LocalLeaseAuthority {
        LocalLeaseAuthority::new("node-1", KEY)
    }

    fn issue(authority: &LocalLeaseAuthority, instance: &VmInstanceIdentity) -> NetworkLease {
        authority.issue(&LeaseRequest {
            instance,
            tenant_id: "default",
            ipv4: Ipv4Addr::new(10, 201, 0, 6),
            gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
            dns_name: Some("vm-a.mvm.internal"),
            routes: &[],
            ingress: &[],
            egress_policy_digest: "sha256:egress",
            policy_epoch: 1,
            now_millis: NOW,
        })
    }

    fn ctx(instance: &VmInstanceIdentity, now_millis: u64) -> LeaseContext {
        LeaseContext {
            instance: instance.clone(),
            plan_policy_epoch: 1,
            egress_policy_digest: "sha256:egress".to_string(),
            now_millis,
        }
    }

    #[test]
    fn a_locally_issued_lease_verifies_for_the_boot_it_names() {
        let authority = authority();
        let instance = instance();
        let lease = issue(&authority, &instance);
        assert!(verify_lease(&lease, &authority, &ctx(&instance, NOW)).is_ok());
        assert_eq!(lease.instance(), instance);
    }

    #[test]
    fn a_lease_cannot_be_replayed_after_a_restart() {
        let authority = authority();
        let first_boot = instance();
        let lease = issue(&authority, &first_boot);
        let second_boot = VmInstanceIdentity::new("node-1", "vm-a", "boot-2", "sha256:plan");
        let err = verify_lease(&lease, &authority, &ctx(&second_boot, NOW)).unwrap_err();
        assert!(matches!(err, LeaseError::WrongInstance { .. }));
    }

    #[test]
    fn a_lease_cannot_be_transferred_to_another_vm() {
        let authority = authority();
        let lease = issue(&authority, &instance());
        let other = VmInstanceIdentity::new("node-1", "vm-b", "boot-1", "sha256:plan");
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&other, NOW)),
            Err(LeaseError::WrongInstance { .. })
        ));
    }

    #[test]
    fn a_lease_from_another_node_is_refused() {
        let authority = authority();
        let lease = issue(&authority, &instance());
        let elsewhere = VmInstanceIdentity::new("node-2", "vm-a", "boot-1", "sha256:plan");
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&elsewhere, NOW)),
            Err(LeaseError::WrongNode { .. })
        ));
    }

    #[test]
    fn a_lease_for_a_different_plan_is_refused() {
        let authority = authority();
        let lease = issue(&authority, &instance());
        let replanned = VmInstanceIdentity::new("node-1", "vm-a", "boot-1", "sha256:other");
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&replanned, NOW)),
            Err(LeaseError::WrongInstance { .. })
        ));
    }

    #[test]
    fn expiry_fails_closed() {
        let authority = authority().with_ttl(1000);
        let instance = instance();
        let lease = issue(&authority, &instance);
        assert!(verify_lease(&lease, &authority, &ctx(&instance, NOW + 999)).is_ok());
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&instance, NOW + 1000)),
            Err(LeaseError::Expired { .. })
        ));
        assert_eq!(lease.remaining_millis(NOW + 5000), 0);
    }

    #[test]
    fn a_lease_is_not_usable_before_its_window_opens() {
        let authority = authority();
        let instance = instance();
        let lease = issue(&authority, &instance);
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&instance, NOW - 1)),
            Err(LeaseError::NotYetValid { .. })
        ));
    }

    #[test]
    fn a_policy_epoch_bump_retires_the_lease() {
        let authority = authority();
        let instance = instance();
        let lease = issue(&authority, &instance);
        let mut context = ctx(&instance, NOW);
        context.plan_policy_epoch = 2;
        assert!(matches!(
            verify_lease(&lease, &authority, &context),
            Err(LeaseError::StaleEpoch { .. })
        ));
    }

    #[test]
    fn a_changed_egress_policy_digest_retires_the_lease() {
        let authority = authority();
        let instance = instance();
        let lease = issue(&authority, &instance);
        let mut context = ctx(&instance, NOW);
        context.egress_policy_digest = "sha256:different".to_string();
        assert!(matches!(
            verify_lease(&lease, &authority, &context),
            Err(LeaseError::PolicyDigestMismatch { .. })
        ));
    }

    #[test]
    fn tampering_with_any_signed_field_breaks_the_signature() {
        let authority = authority();
        let instance = instance();
        let base = issue(&authority, &instance);

        let mut wider_window = base.clone();
        wider_window.expires_at_millis += 1;
        assert!(matches!(
            verify_lease(&wider_window, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::BadSignature { .. })
        ));

        let mut different_address = base.clone();
        different_address.ipv4 = Some(Ipv4Addr::new(10, 201, 0, 10));
        assert!(matches!(
            verify_lease(&different_address, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::BadSignature { .. })
        ));

        let mut extra_route = base.clone();
        extra_route.routes.push("0.0.0.0/0".to_string());
        assert!(matches!(
            verify_lease(&extra_route, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::BadSignature { .. })
        ));

        let mut extra_ingress = base;
        extra_ingress.ingress.push(LeaseIngress {
            proto: "tcp".into(),
            host_addr: "0.0.0.0".into(),
            host_port: 8080,
            guest_port: 80,
        });
        assert!(matches!(
            verify_lease(&extra_ingress, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::BadSignature { .. })
        ));
    }

    #[test]
    fn a_lease_signed_by_another_key_is_refused() {
        let issuer = LocalLeaseAuthority::new("node-1", [1u8; 32]);
        let verifier = LocalLeaseAuthority::new("node-1", [2u8; 32]);
        let instance = instance();
        let lease = issue(&issuer, &instance);
        assert!(matches!(
            verify_lease(&lease, &verifier, &ctx(&instance, NOW)),
            Err(LeaseError::BadSignature { .. })
        ));
    }

    #[test]
    fn an_unknown_key_id_is_refused_before_any_comparison() {
        let authority = authority();
        let instance = instance();
        let mut lease = issue(&authority, &instance);
        lease.key_id = "someone-elses-key".to_string();
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::UnknownKey(_))
        ));
    }

    #[test]
    fn an_unsupported_version_is_refused_before_the_signature_is_read() {
        let authority = authority();
        let instance = instance();
        let mut lease = issue(&authority, &instance);
        lease.version = LEASE_VERSION + 1;
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::UnsupportedVersion { .. })
        ));
    }

    /// A protocol nothing lowers is refused rather than carried into a
    /// gateway that would have to guess what it meant.
    #[test]
    fn an_unknown_ingress_protocol_in_a_lease_is_refused_rather_than_ignored() {
        let authority = authority();
        let instance = instance();
        let lease = authority.issue(&LeaseRequest {
            instance: &instance,
            tenant_id: "default",
            ipv4: Ipv4Addr::new(10, 201, 0, 6),
            gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
            dns_name: None,
            routes: &[],
            ingress: &[LeaseIngress {
                proto: "sctp".into(),
                host_addr: "127.0.0.1".into(),
                host_port: 5353,
                guest_port: 53,
            }],
            egress_policy_digest: "sha256:egress",
            policy_epoch: 1,
            now_millis: NOW,
        });
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::UnknownIngressProto(_))
        ));
    }

    #[test]
    fn a_malformed_route_is_refused() {
        let authority = authority();
        let instance = instance();
        let mut lease = issue(&authority, &instance);
        lease.routes.push("not-a-cidr".to_string());
        lease.signature = hex(&mac(&KEY, &lease.signing_bytes()));
        assert!(matches!(
            verify_lease(&lease, &authority, &ctx(&instance, NOW)),
            Err(LeaseError::MalformedRoute(_))
        ));
    }

    #[test]
    fn a_lease_serde_roundtrips() {
        let lease = issue(&authority(), &instance());
        let json = serde_json::to_string(&lease).unwrap();
        assert_eq!(serde_json::from_str::<NetworkLease>(&json).unwrap(), lease);
    }

    #[test]
    fn losing_the_control_plane_never_opens_anything_up() {
        for policy in [
            ControlPlaneLossPolicy::HoldExistingDenyNew,
            ControlPlaneLossPolicy::HoldUntilExpiry,
            ControlPlaneLossPolicy::DenyImmediately,
        ] {
            assert!(
                !policy.after_expiry_permits_anything(),
                "{policy:?} must deny once the lease expires"
            );
        }
        assert!(!ControlPlaneLossPolicy::default().permits_new_flows());
        assert!(ControlPlaneLossPolicy::default().holds_existing_flows());
        assert!(!ControlPlaneLossPolicy::DenyImmediately.holds_existing_flows());
    }
}
