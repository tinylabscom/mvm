//! The per-VM gating-endpoint spawn seam.
//!
//! Behind a trait so the runner is unit-testable with no real VM and no real
//! endpoint process; the production impl is the one host-side egress bridge
//! (the claim-10 gate plus claims 12/13 substitution).

use super::*;

use mvm_core::crypto::secret_binding::FileBindingStore;
use mvm_vmm::host::network_endpoint_spawn::{
    EgressTlsDelivery, build_egress_tls_delivery, load_egress_tls_delivery,
    persist_egress_tls_delivery,
};

/// Where this boot's FlowMux identity comes from.
///
/// A cold boot mints one and hands the guest a drive carrying it. A warm claim
/// cannot: the child restores from its parent's memory image, so it already
/// holds the parent's signing key and there is no path back into a running
/// guest's memory to replace it. The child's endpoint therefore pins the key
/// its guest actually has, read from what the parent persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowMuxIdentitySource<'a> {
    /// Mint a fresh identity for this boot and emit a drive to attach.
    Mint,
    /// Inherit the identity the parent at this state dir persisted.
    InheritFrom(&'a Path),
}

/// What the workload runner needs to stand up the per-VM gating endpoint.
pub struct NetworkEndpointSpawnRequest<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    /// Transport-neutral resource ceilings from the admitted plan.
    pub network_limits: mvm_core::plan::NetworkLimits,
    /// Exact signed ingress mappings owned by this endpoint.
    pub ingress: &'a [mvm_core::plan::IngressMapping],
    /// Where the guest's half of the authenticated session comes from.
    pub identity: FlowMuxIdentitySource<'a>,
}

/// A stood-up endpoint: the channel, and the drive the guest reads its identity
/// from when this boot minted one.
pub struct SpawnedEndpoint {
    /// The host UDS the guest's `EGRESS_PORT` relays to.
    pub egress_uds: PathBuf,
    /// The identity drive to attach to the guest. `None` for a warm claim,
    /// whose guest already holds its key in restored memory.
    pub identity_drive: Option<PathBuf>,
}

/// Stand up the per-VM gating endpoint. The one host-side egress bridge
/// (claim-10 gate + claims 12/13 substitution).
pub trait NetworkEndpointSpawner: Send + Sync {
    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint>;
    /// Provision authentication without starting an endpoint or granting egress.
    fn prepare_identity(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>>;
}

/// The production `NetworkEndpointSpawner`: spawns the real `mvm-network-endpoint`
/// over the in-process-VMM UDS transport.
pub struct RealNetworkEndpointSpawner;

/// Provision a parent's guest key without tenant workload authority or egress.
pub(super) fn prepare_standby_identity(
    spawner: &dyn NetworkEndpointSpawner,
    spec: &StandbySpec,
) -> std::result::Result<Option<PathBuf>, StandbyError> {
    spawner
        .prepare_identity(&NetworkEndpointSpawnRequest {
            vm_name: &spec.id,
            state_dir: Path::new(&spec.vm_state_dir),
            tenant: "local",
            secrets: &[],
            redaction: &RedactionPolicy::default(),
            network_policy: &NetworkPolicy::deny_all(),
            network_limits: mvm_core::plan::NetworkLimits::default(),
            ingress: &[],
            identity: FlowMuxIdentitySource::Mint,
        })
        .map_err(|error| {
            StandbyError::SpawnFailed(format!("provision standby guest identity: {error:#}"))
        })
}

impl NetworkEndpointSpawner for RealNetworkEndpointSpawner {
    fn prepare_identity(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>> {
        let anchor_path = mvm_core::config::mvm_keys_dir()
            .join(mvm_vmm::host::broker_services_spawn::HOST_SIGNER_PUB);
        prepare_observation_identity(req, &anchor_path)
    }

    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        use mvm_vmm::host::flowmux_identity::{
            FlowMuxIdentityMaterial, IDENTITY_DRIVE_FILE, IdentityDriveContents,
            load_inheritable_identity,
        };
        use mvm_vmm::host::network_endpoint_spawn::FlowMuxIdentitySpawnConfig;

        let uds = vm_network_endpoint_socket(req.vm_name);
        let egress_ca = BootEgressCa::resolve(req)?;
        let (identity, identity_drive) = match req.identity {
            FlowMuxIdentitySource::Mint => {
                let material = FlowMuxIdentityMaterial::mint_from_host_signer(req.vm_name)
                    .context("minting this boot's FlowMux identity")?;
                let drive = req.state_dir.join(IDENTITY_DRIVE_FILE);
                material.write_drive_with(
                    &drive,
                    &IdentityDriveContents {
                        ingress: req.ingress,
                        egress_ca_cert_pem: egress_ca.guest_cert_pem(),
                    },
                )?;
                // Persisted so a warm child claimed from this VM pins the key
                // its restored guest actually holds.
                material.persist_inheritable(req.state_dir)?;
                (material.spawn_config().clone(), Some(drive))
            }
            FlowMuxIdentitySource::InheritFrom(parent_state_dir) => {
                let inherited =
                    load_inheritable_identity(parent_state_dir)?.with_context(|| {
                        format!(
                            "parent at {} persisted no FlowMux identity, so a claimed child's \
                         endpoint has no key to pin — refusing rather than minting one the \
                         restored guest does not hold",
                            parent_state_dir.display()
                        )
                    })?;
                (
                    FlowMuxIdentitySpawnConfig {
                        session_id: inherited.session_id,
                        host_signing_key_base64: host_signer_key_base64()?,
                        guest_verifying_key_base64: inherited.guest_verifying_key_base64,
                    },
                    None,
                )
            }
        };

        // Same seam for minted and inherited identities: the boot the endpoint
        // authenticates is the boot the telemetry dialer must expect.
        mvm_vmm::host::telemetry_registration::register_telemetry_boot(
            req.state_dir,
            req.vm_name,
            &identity.guest_verifying_key_base64,
        )
        .context("registering this boot's telemetry identity")?;

        spawn_network_endpoint(SubstitutionSpawnParams {
            vm_name: req.vm_name,
            state_dir: req.state_dir,
            tenant: req.tenant,
            secrets: req.secrets,
            redaction: req.redaction,
            transport: EndpointTransport::Uds { path: uds.clone() },
            // None ⇒ inherit the host's proxy environment, resolved once inside
            // `spawn_network_endpoint` for every backend.
            egress_proxy: None,
            session_marker: None,
            tls_intermediate: egress_ca.endpoint_tls(),
            network_policy: Some(req.network_policy),
            network_limits: req.network_limits,
            ingress: req.ingress,
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: Some(identity),
        })?;
        Ok(SpawnedEndpoint {
            egress_uds: uds,
            identity_drive,
        })
    }
}

fn prepare_observation_identity(
    req: &NetworkEndpointSpawnRequest<'_>,
    anchor_path: &Path,
) -> Result<Option<PathBuf>> {
    use base64::Engine as _;
    use mvm_vmm::host::flowmux_identity::{
        GuestIdentityMaterial, IDENTITY_DRIVE_FILE, IdentityDriveContents, InheritableIdentity,
        load_inheritable_identity,
    };

    let (identity, drive) = match req.identity {
        FlowMuxIdentitySource::Mint => {
            let anchor = mvm_agentd::vsock::load_host_signer_verifying_key(anchor_path)?
                .context("guest observations require the host signer public anchor")?;
            let guest = GuestIdentityMaterial::mint(anchor)?;
            let drive = req.state_dir.join(IDENTITY_DRIVE_FILE);
            guest.write_drive_with(&drive, &IdentityDriveContents::default())?;
            (
                InheritableIdentity {
                    session_id: req.vm_name.to_string(),
                    guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
                        .encode(guest.verifying_key().as_bytes()),
                },
                Some(drive),
            )
        }
        FlowMuxIdentitySource::InheritFrom(parent) => {
            let identity = load_inheritable_identity(parent)?
                .context("restored guest has no registered observation identity")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&identity.guest_verifying_key_base64)
                .context("invalid registered guest public key encoding")?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid registered guest public key length"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .context("invalid registered guest public key")?;
            (identity, None)
        }
    };
    identity.persist(req.state_dir)?;
    mvm_vmm::host::telemetry_registration::register_telemetry_boot(
        req.state_dir,
        req.vm_name,
        &identity.guest_verifying_key_base64,
    )
    .context("registering this boot's telemetry identity")?;
    Ok(drive)
}

/// This boot's egress CA, in the two shapes its two consumers need.
///
/// Both come off one value, so an endpoint cannot be configured to terminate
/// for a guest that was handed no certificate. That pairing is the whole point:
/// terminating under a certificate the guest does not trust turns a clean
/// refusal into a TLS verification failure the workload cannot act on.
// allow(secret-debug): `EgressTlsDelivery`'s own `Debug` is hand-written and
// redacts the key, so deriving here cannot print one.
#[derive(Debug)]
struct BootEgressCa(Option<EgressTlsDelivery>);

impl BootEgressCa {
    /// Resolve the CA for this boot, or nothing when it terminates nothing.
    ///
    /// A cold boot mints one over the destinations the plan's secret bindings
    /// admit and persists it; a warm claim reads its parent's, because the
    /// restored child already trusts the parent's certificate in memory and
    /// there is no path back into a running guest to replace it. A boot whose
    /// plan binds no destination gets nothing, which is what leaves the
    /// endpoint refusing rather than terminating.
    fn resolve(req: &NetworkEndpointSpawnRequest<'_>) -> Result<Self> {
        // Both arms need this. A claimed child's substitution registry is built
        // from the *child's* plan, so its bound destinations are the ones the
        // inherited certificate has to cover.
        let bindings = FileBindingStore::default_location()
            .context("opening the host secret-binding store")?;
        let hosts =
            mvm_core::crypto::secret_binding::bound_hosts(req.secrets, req.tenant, &bindings)
                .context("resolving the destinations this workload's secrets are bound to")?;
        match req.identity {
            FlowMuxIdentitySource::InheritFrom(parent_state_dir) => {
                Self::inherit(parent_state_dir, req.state_dir, &hosts)
            }
            FlowMuxIdentitySource::Mint => Self::mint(&hosts, req.state_dir),
        }
    }

    /// Mint and persist a CA name-constrained to `bound_hosts`. An empty set is
    /// not an error: a workload with nothing bound has nothing terminated.
    fn mint(bound_hosts: &[String], state_dir: &Path) -> Result<Self> {
        if bound_hosts.is_empty() {
            return Ok(Self(None));
        }
        let borrowed: Vec<&str> = bound_hosts.iter().map(String::as_str).collect();
        let delivery = build_egress_tls_delivery(&borrowed)?;
        persist_egress_tls_delivery(state_dir, &delivery)?;
        Ok(Self(Some(delivery)))
    }

    /// Take the CA the parent persisted, recording it in the child's own state
    /// dir — which is where the child's stop path and any further claim look.
    ///
    /// A claimed child gets its parent's certificate because that is the one its
    /// restored guest trusts, but it gets its **own** plan's secret bindings, so
    /// the two can disagree: a child binding a destination the parent did not
    /// would otherwise be handed a terminating endpoint whose leaves fall
    /// outside the certificate's permitted subtrees. Every conforming verifier
    /// rejects those inside the guest's own TLS stack, after the flow was
    /// admitted and with nothing recorded about why. Refuse the claim instead,
    /// naming the destination — the same fail-closed shape as a parent that
    /// persisted no FlowMux identity.
    fn inherit(parent_state_dir: &Path, state_dir: &Path, bound_hosts: &[String]) -> Result<Self> {
        let Some(inherited) = load_egress_tls_delivery(parent_state_dir)? else {
            // The parent terminated nothing. A child that binds a destination
            // has no certificate for it and no way to be given one.
            if let Some(host) = bound_hosts.first() {
                anyhow::bail!(
                    "this workload binds a secret to {host}, but the parent it is claimed \
                     from terminated nothing, so its guest trusts no egress certificate — \
                     refusing rather than admitting a flow whose TLS the guest would reject"
                );
            }
            return Ok(Self(None));
        };
        if let Some(host) = inherited.first_unpermitted(bound_hosts) {
            anyhow::bail!(
                "this workload binds a secret to {host}, which the egress certificate \
                 inherited from the parent at {} does not permit (it permits {:?}). A claimed \
                 child cannot be handed a different certificate — its guest already trusts \
                 the parent's — so the claim is refused rather than terminating under one \
                 the guest would reject.",
                parent_state_dir.display(),
                inherited.bound_hosts(),
            );
        }
        persist_egress_tls_delivery(state_dir, &inherited)?;
        Ok(Self(Some(inherited)))
    }

    /// The certificate to put on the guest's identity drive. Never the key.
    fn guest_cert_pem(&self) -> Option<&str> {
        self.0.as_ref().map(EgressTlsDelivery::cert_pem)
    }

    /// The cert+key the endpoint terminates under — `Some` only when the guest
    /// was handed the matching certificate above.
    fn endpoint_tls(&self) -> Option<(String, String)> {
        self.0
            .as_ref()
            .map(|ca| (ca.cert_pem().to_string(), ca.key_pem().to_string()))
    }
}

/// The host signer, base64-encoded for the endpoint's stdin.
fn host_signer_key_base64() -> Result<String> {
    use base64::Engine as _;
    let path = mvm_core::config::mvm_keys_dir()
        .join(mvm_vmm::host::broker_services_spawn::HOST_SIGNER_KEY);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading the host signer key at {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() == 32,
        "host signer key at {} is {} bytes, expected 32",
        path.display(),
        bytes.len()
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use mvm_vmm::host::flowmux_identity::{
        IDENTITY_DRIVE_FILE, InheritableIdentity, PUBLIC_IDENTITY_FILE, load_inheritable_identity,
    };
    use mvm_vmm::host::telemetry_registration::{
        TELEMETRY_REGISTRATION_FILE, resolve_expected_telemetry_peer,
    };

    fn prepare_test_identity(
        state: &Path,
        anchor: &Path,
        identity: FlowMuxIdentitySource<'_>,
    ) -> Result<Option<PathBuf>> {
        prepare_observation_identity(
            &NetworkEndpointSpawnRequest {
                vm_name: "isolated-guest",
                state_dir: state,
                tenant: "tenant",
                secrets: &[],
                redaction: &RedactionPolicy::default(),
                network_policy: &NetworkPolicy::deny_all(),
                network_limits: mvm_core::plan::NetworkLimits::default(),
                ingress: &[],
                identity,
            },
            anchor,
        )
    }

    #[test]
    fn observation_identity_needs_only_a_public_anchor_and_creates_no_endpoint() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().join("host-signer.pub");
        let host = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        std::fs::write(&anchor, host.verifying_key().as_bytes()).unwrap();
        let state = root.path().join("guest");
        let drive = prepare_test_identity(&state, &anchor, FlowMuxIdentitySource::Mint)
            .unwrap()
            .unwrap();
        assert_eq!(drive, state.join(IDENTITY_DRIVE_FILE));
        let image = std::fs::read(&drive).unwrap();
        assert!(
            image
                .windows(32)
                .any(|bytes| bytes == host.verifying_key().as_bytes())
        );
        assert!(!image.windows(32).any(|bytes| bytes == host.as_bytes()));
        let identity = load_inheritable_identity(&state).unwrap().unwrap();
        assert_eq!(identity.session_id, "isolated-guest");
        let mut files: Vec<_> = std::fs::read_dir(&state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        files.sort();
        assert_eq!(
            files,
            vec![
                std::ffi::OsString::from(IDENTITY_DRIVE_FILE),
                std::ffi::OsString::from(PUBLIC_IDENTITY_FILE),
                std::ffi::OsString::from(TELEMETRY_REGISTRATION_FILE),
            ]
        );
        let peer = resolve_expected_telemetry_peer(&state, "isolated-guest").unwrap();
        assert_eq!(peer.generation, 1);
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(peer.key.as_bytes()),
            identity.guest_verifying_key_base64,
            "the registered telemetry peer is this boot's minted guest key"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&drive).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let sibling = root.path().join("sibling");
        prepare_test_identity(&sibling, &anchor, FlowMuxIdentitySource::Mint).unwrap();
        assert_ne!(
            identity.guest_verifying_key_base64,
            load_inheritable_identity(&sibling)
                .unwrap()
                .unwrap()
                .guest_verifying_key_base64
        );
    }

    #[test]
    fn restored_observation_identity_preserves_the_key_without_minting_a_drive() {
        use base64::Engine as _;
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        let child = root.path().join("child");
        let identity = InheritableIdentity {
            session_id: "parent-session".into(),
            guest_verifying_key_base64: base64::engine::general_purpose::STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[38; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
        };
        identity.persist(&parent).unwrap();
        assert_eq!(
            prepare_test_identity(
                &child,
                &root.path().join("absent-anchor"),
                FlowMuxIdentitySource::InheritFrom(&parent)
            )
            .unwrap(),
            None
        );
        assert_eq!(
            load_inheritable_identity(&child).unwrap(),
            Some(identity.clone())
        );
        assert!(!child.join(IDENTITY_DRIVE_FILE).exists());
        // The child registers its own boot under the inherited key: same key,
        // fresh boot binding, so the parent's boot cannot be confused for it.
        let peer = resolve_expected_telemetry_peer(&child, "isolated-guest").unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(peer.key.as_bytes()),
            identity.guest_verifying_key_base64
        );
        assert_eq!(peer.generation, 1);
    }

    #[test]
    fn observation_identity_refuses_missing_or_malformed_anchors_before_writing() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().join("anchor");
        let state = root.path().join("guest");
        assert!(prepare_test_identity(&state, &anchor, FlowMuxIdentitySource::Mint).is_err());
        std::fs::write(&anchor, b"invalid-anchor").unwrap();
        assert!(prepare_test_identity(&state, &anchor, FlowMuxIdentitySource::Mint).is_err());
        assert!(!state.exists());
    }

    #[test]
    fn observation_identity_refuses_missing_and_malformed_parent_registration() {
        use base64::Engine as _;
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        let child = root.path().join("child");
        let anchor = root.path().join("unused-anchor");
        assert!(
            prepare_test_identity(&child, &anchor, FlowMuxIdentitySource::InheritFrom(&parent))
                .is_err()
        );
        for encoded in [
            "not-base64".to_string(),
            base64::engine::general_purpose::STANDARD.encode([1; 31]),
        ] {
            InheritableIdentity {
                session_id: "parent".into(),
                guest_verifying_key_base64: encoded,
            }
            .persist(&parent)
            .unwrap();
            assert!(
                prepare_test_identity(&child, &anchor, FlowMuxIdentitySource::InheritFrom(&parent))
                    .is_err()
            );
        }
        std::fs::write(parent.join(PUBLIC_IDENTITY_FILE), b"invalid-json").unwrap();
        assert!(
            prepare_test_identity(&child, &anchor, FlowMuxIdentitySource::InheritFrom(&parent))
                .is_err()
        );
        assert!(!child.exists());
    }

    #[test]
    fn observation_identity_propagates_drive_and_registration_write_errors() {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().join("anchor");
        std::fs::write(
            &anchor,
            ed25519_dalek::SigningKey::from_bytes(&[39; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let state = root.path().join("file-not-directory");
        std::fs::write(&state, b"occupied").unwrap();
        assert!(prepare_test_identity(&state, &anchor, FlowMuxIdentitySource::Mint).is_err());
        let state = root.path().join("guest");
        std::fs::create_dir_all(state.join(PUBLIC_IDENTITY_FILE)).unwrap();
        assert!(prepare_test_identity(&state, &anchor, FlowMuxIdentitySource::Mint).is_err());
    }

    fn hosts(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    #[test]
    fn a_warm_claimed_child_inherits_its_parents_egress_intermediate() {
        // The child restores its parent's memory, so it trusts the certificate
        // the parent's guest already holds. Minting a fresh one would leave the
        // endpoint terminating under an identity nothing in that guest trusts.
        let parent = tempfile::tempdir().expect("tempdir");
        let child = tempfile::tempdir().expect("tempdir");
        let minted =
            BootEgressCa::mint(&hosts(&["api.openai.com"]), parent.path()).expect("parent mints");

        let inherited =
            BootEgressCa::inherit(parent.path(), child.path(), &hosts(&["api.openai.com"]))
                .expect("child inherits");

        assert_eq!(
            inherited.guest_cert_pem(),
            minted.guest_cert_pem(),
            "a claimed child must terminate under the certificate its restored guest trusts"
        );
        assert_eq!(inherited.endpoint_tls(), minted.endpoint_tls());
        assert_eq!(
            load_egress_tls_delivery(child.path())
                .expect("load")
                .as_ref()
                .map(|ca| ca.cert_pem().to_string()),
            minted.guest_cert_pem().map(str::to_string),
            "the child records the inherited identity in its own state dir"
        );
    }

    #[test]
    fn a_claim_is_refused_when_the_inherited_certificate_does_not_permit_its_bound_hosts() {
        // The child's substitution registry comes from the CHILD's plan, so it
        // can bind a destination the parent never did. Terminating there would
        // mint a leaf outside the inherited certificate's permitted subtrees,
        // which the guest's own TLS stack rejects after the flow was admitted
        // and with nothing recorded about why.
        let parent = tempfile::tempdir().expect("tempdir");
        let child = tempfile::tempdir().expect("tempdir");
        BootEgressCa::mint(&hosts(&["api.openai.com"]), parent.path()).expect("parent mints");

        let refused = BootEgressCa::inherit(
            parent.path(),
            child.path(),
            &hosts(&["api.openai.com", "api.anthropic.com"]),
        )
        .expect_err("a destination the inherited certificate cannot cover must refuse the claim");

        let message = format!("{refused:#}");
        assert!(
            message.contains("api.anthropic.com"),
            "the refusal must name the destination that cannot be covered: {message}"
        );
        assert!(
            load_egress_tls_delivery(child.path())
                .expect("load")
                .is_none(),
            "a refused claim must not leave the child holding a key it may not use"
        );
    }

    #[test]
    fn a_claim_binding_nothing_new_inherits_a_subset_without_complaint() {
        let parent = tempfile::tempdir().expect("tempdir");
        let child = tempfile::tempdir().expect("tempdir");
        BootEgressCa::mint(
            &hosts(&["api.openai.com", "api.anthropic.com"]),
            parent.path(),
        )
        .expect("parent mints");

        let inherited =
            BootEgressCa::inherit(parent.path(), child.path(), &hosts(&["api.anthropic.com"]))
                .expect("a child binding a subset of the parent's destinations is covered");

        assert!(inherited.endpoint_tls().is_some());
    }

    /// A parent bound by wildcard holds a certificate for that whole subtree,
    /// so a child binding a name the wildcard admits is covered by it — and the
    /// child's own record keeps the parent's pattern, not the lowered subtree.
    /// The wildcard's apex is not admitted by the binding, so a child naming it
    /// is refused even though the certificate would accept it.
    #[test]
    fn a_child_binding_a_subdomain_of_its_parents_wildcard_inherits_it() {
        let parent = tempfile::tempdir().expect("tempdir");
        BootEgressCa::mint(&hosts(&["*.example.com"]), parent.path()).expect("parent mints");

        for child_hosts in [
            &["api.example.com"][..],
            &["a.b.example.com", "*.example.com"][..],
            &["*.api.example.com"][..],
        ] {
            let child = tempfile::tempdir().expect("tempdir");
            let inherited = BootEgressCa::inherit(parent.path(), child.path(), &hosts(child_hosts))
                .unwrap_or_else(|e| {
                    panic!("{child_hosts:?} is under the parent's wildcard: {e:#}")
                });
            assert!(inherited.endpoint_tls().is_some());
            assert_eq!(
                load_egress_tls_delivery(child.path())
                    .expect("load")
                    .expect("recorded")
                    .bound_hosts(),
                ["*.example.com"],
            );
        }

        let child = tempfile::tempdir().expect("tempdir");
        let refused = BootEgressCa::inherit(parent.path(), child.path(), &hosts(&["example.com"]))
            .expect_err("the apex is not bound by the parent's wildcard");
        assert!(format!("{refused:#}").contains("example.com"));
    }

    #[test]
    fn a_child_of_a_parent_that_terminated_nothing_terminates_nothing() {
        let parent = tempfile::tempdir().expect("tempdir");
        let child = tempfile::tempdir().expect("tempdir");

        let inherited = BootEgressCa::inherit(parent.path(), child.path(), &[])
            .expect("absence is not an error");

        assert!(inherited.guest_cert_pem().is_none());
        assert!(
            inherited.endpoint_tls().is_none(),
            "a child must not invent a certificate its restored guest never saw"
        );
    }

    #[test]
    fn a_child_that_binds_a_destination_cannot_claim_a_parent_that_terminated_nothing() {
        let parent = tempfile::tempdir().expect("tempdir");
        let child = tempfile::tempdir().expect("tempdir");

        let refused =
            BootEgressCa::inherit(parent.path(), child.path(), &hosts(&["api.openai.com"]))
                .expect_err(
                    "there is no certificate for the destination and no way to deliver one",
                );

        assert!(format!("{refused:#}").contains("api.openai.com"));
    }

    #[test]
    fn termination_is_not_enabled_when_no_ca_could_be_delivered() {
        // A workload whose plan binds no destination has nothing to terminate.
        // The endpoint must be configured without TLS material, so `terminable`
        // keeps returning `None` and the flow stays refused rather than failing
        // certificate verification inside the guest.
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = BootEgressCa::mint(&[], dir.path()).expect("an empty host set is not an error");

        assert!(ca.guest_cert_pem().is_none(), "nothing is delivered");
        assert!(ca.endpoint_tls().is_none(), "so nothing is terminated");
        assert!(
            load_egress_tls_delivery(dir.path())
                .expect("load")
                .is_none(),
            "and nothing is persisted for a claim to inherit"
        );
    }

    #[test]
    fn a_delivered_ca_enables_termination_under_exactly_the_delivered_certificate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = BootEgressCa::mint(&hosts(&["api.openai.com"]), dir.path()).expect("mint");

        let delivered = ca
            .guest_cert_pem()
            .expect("the guest is handed a certificate");
        let (endpoint_cert, endpoint_key) =
            ca.endpoint_tls().expect("so the endpoint may terminate");
        assert_eq!(
            delivered, endpoint_cert,
            "the endpoint's leaves must chain to the certificate the guest trusts"
        );
        assert!(
            !delivered.contains("PRIVATE KEY"),
            "the key never rides along with the certificate"
        );
        assert!(endpoint_key.contains("PRIVATE KEY"));
    }
}
