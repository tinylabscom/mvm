//! Bundle-pin plumbing and generated network-policy bundle synthesis for
//! `mvmctl up` admission — the in-memory bundle resolver used when the
//! CLI already has archive bytes in hand, and the helpers that turn a
//! resolved --network-preset / --network-allow into a signed PolicyBundle.

use anyhow::{Context, Result};
use mvm_core::policy::PolicyBundle;
use mvm_runtime::image;

/// Inputs for [`admit_plan_for_boot`]. Grouped so the helper avoids
/// the workspace `clippy::too_many_arguments = "deny"` ceiling and so
/// future callers (policy slots) can extend the shape without
/// churning every call site.
/// In-memory `BundleResolver` scoped to a single admission. Used
/// when `mvmctl up --bundle-pin <path>` already has the archive
/// bytes — no need to walk the filesystem registry again.
pub(super) struct InMemoryBundleResolver {
    bytes: Vec<u8>,
}

impl InMemoryBundleResolver {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl mvm_core::plan::BundleResolver for InMemoryBundleResolver {
    fn resolve(
        &self,
        _bundle_sha256: &str,
    ) -> std::result::Result<Vec<u8>, mvm_core::plan::BundleResolveError> {
        Ok(self.bytes.clone())
    }
}

/// Build a `PlanArtifact` pin from a verified bundle archive.
/// Pulls the 64-byte signature out of the `manifest.sig` entry,
/// hashes the archive for the bundle_sha256 field, and stamps the
/// publisher's `key_id`.
pub(super) fn bundle_pin_from_archive(
    archive: &[u8],
    key_id: mvm_core::plan::KeyId,
) -> Result<mvm_core::plan::PlanArtifact> {
    let mut tar = tar::Archive::new(std::io::Cursor::new(archive));
    for entry in tar.entries().context("walking archive entries")? {
        let mut entry = entry.context("reading archive entry")?;
        let path = entry
            .path()
            .context("reading archive entry path")?
            .to_string_lossy()
            .into_owned();
        if path == "manifest.sig" {
            let mut bytes = Vec::with_capacity(64);
            std::io::Read::read_to_end(&mut entry, &mut bytes)
                .context("reading manifest.sig bytes")?;
            let sig_arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("manifest.sig is {} bytes; expected 64", bytes.len())
            })?;
            return Ok(mvm_core::plan::PlanArtifact::new(
                mvm_core::plan::bundle_sha256(archive),
                &sig_arr,
                key_id,
            ));
        }
    }
    anyhow::bail!("archive has no manifest.sig entry")
}

/// Build the signed-plan host-fs grant list from the resolved volume
/// config. The `uvol{idx}` tag matches the id the backend assigns when
/// it attaches each volume (same `VmStartConfig.volumes` order), so the
/// admitted grants line up 1:1 with what actually gets attached.
pub(super) fn shares_from_volume_cfg(
    vols: &[image::RuntimeVolume],
) -> Vec<mvm_core::plan::HostShareGrant> {
    vols.iter()
        .enumerate()
        .map(|(idx, v)| mvm_core::plan::HostShareGrant {
            tag: format!("uvol{idx}"),
            host_path: v.host.clone(),
            guest_path: v.guest.clone(),
            kind: if v.materialized_image.is_some() {
                mvm_core::plan::ShareKind::DirShare
            } else {
                mvm_core::plan::ShareKind::Disk
            },
            read_only: v.read_only,
            encrypted: v.encrypted,
            content_sha256: None,
        })
        .collect()
}

fn generated_policy_ref(tenant: &str, vm_name: &str) -> Result<String> {
    fn valid_component(s: &str) -> bool {
        !s.is_empty() && !s.contains('/') && !s.contains('\\') && !s.contains(':')
    }
    if !valid_component(tenant) {
        anyhow::bail!(
            "tenant {tenant:?} cannot be encoded into a generated signed network policy ref"
        );
    }
    if !valid_component(vm_name) {
        anyhow::bail!(
            "vm name {vm_name:?} cannot be encoded into a generated signed network policy ref"
        );
    }
    Ok(format!("{tenant}:{vm_name}"))
}

pub(super) fn generated_policy_bundle_for_network_policy(
    tenant: &str,
    vm_name: &str,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<Option<(String, PolicyBundle)>> {
    use mvm_core::policy::bundle::{PolicyId, SCHEMA_VERSION as POLICY_SCHEMA_VERSION};
    use mvm_core::policy::policies::{
        ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, EgressPolicy, KeyPolicy, L4RuleSpec,
        PiiPolicy, ToolPolicy, WasiCapPolicy,
    };
    use std::net::{IpAddr, ToSocketAddrs};

    let Some(rules) = policy.resolve_rules() else {
        let policy_ref = generated_policy_ref(tenant, vm_name)?;
        let mut egress = EgressPolicy {
            mode: Some("open".to_string()),
            ..Default::default()
        };
        egress.redaction = mvm_core::policy::RedactionPolicy::default();
        return Ok(Some((
            policy_ref,
            PolicyBundle {
                schema_version: POLICY_SCHEMA_VERSION,
                bundle_id: PolicyId(format!("{tenant}/{vm_name}/cli-egress")),
                bundle_version: 1,
                network: BundleNetworkPolicy::default(),
                egress,
                pii: PiiPolicy::default(),
                tool: ToolPolicy::default(),
                artifact: ArtifactPolicy::default(),
                keys: KeyPolicy::default(),
                audit: AuditPolicy {
                    chain_signing: true,
                    ..Default::default()
                },
                wasi: WasiCapPolicy::default(),
                tenant_overlays: std::collections::BTreeMap::new(),
            },
        )));
    };
    if rules.is_empty() {
        return Ok(None);
    }

    let policy_ref = generated_policy_ref(tenant, vm_name)?;
    let mut l4 = Vec::new();
    let mut egress_allow = Vec::new();
    for rule in rules {
        let ips: Vec<IpAddr> = if let Ok(ip) = rule.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (rule.host.as_str(), 0u16)
                .to_socket_addrs()
                .with_context(|| {
                    format!(
                        "resolving {} for generated signed network policy",
                        rule.host
                    )
                })?
                .map(|sa| sa.ip())
                .collect()
        };
        if ips.is_empty() {
            anyhow::bail!(
                "resolving {} for generated signed network policy returned no addresses",
                rule.host
            );
        }
        egress_allow.push((rule.host.clone(), rule.port));
        for ip in ips {
            let dst_cidr = match ip {
                IpAddr::V4(v4) => format!("{v4}/32"),
                IpAddr::V6(v6) => format!("{v6}/128"),
            };
            l4.push(L4RuleSpec {
                proto: "tcp".to_string(),
                dst_cidr,
                port_lo: rule.port,
                port_hi: rule.port,
            });
        }
    }
    l4.sort_by(|a, b| {
        (&a.proto, &a.dst_cidr, a.port_lo, a.port_hi).cmp(&(
            &b.proto,
            &b.dst_cidr,
            b.port_lo,
            b.port_hi,
        ))
    });
    l4.dedup();
    egress_allow.sort();
    egress_allow.dedup();

    let bundle = PolicyBundle {
        schema_version: POLICY_SCHEMA_VERSION,
        bundle_id: PolicyId(format!("{tenant}/{vm_name}/cli-egress")),
        bundle_version: 1,
        network: BundleNetworkPolicy {
            preset: Some("cli-allow-list".to_string()),
            l4,
            observers: Vec::new(),
            flow_byte_log: None,
        },
        egress: EgressPolicy {
            allow_list: egress_allow,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            ..Default::default()
        },
        pii: PiiPolicy::default(),
        tool: ToolPolicy::default(),
        artifact: ArtifactPolicy::default(),
        keys: KeyPolicy::default(),
        audit: AuditPolicy {
            chain_signing: true,
            ..Default::default()
        },
        wasi: WasiCapPolicy::default(),
        tenant_overlays: std::collections::BTreeMap::new(),
    };
    mvm_core::policy::canonicalize_l4(&bundle.network.l4)
        .context("validating generated signed network policy L4 rules")?;
    Ok(Some((policy_ref, bundle)))
}

#[cfg(test)]
mod bundle_pin_tests {
    use super::*;
    use rand::Rng;

    /// Build a signed `.mvmpkg` archive in-memory so the
    /// `--bundle-pin` test path doesn't need a real fetched bundle.
    /// Uses mvm_plan's own writer + signing primitives.
    fn make_bundle_for_pin(sk: &ed25519_dalek::SigningKey) -> (Vec<u8>, mvm_core::plan::KeyId) {
        use mvm_core::plan::bundle::{
            ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest,
            key_id_from_pubkey, sha256_hex, write_bundle,
        };
        let key_id = key_id_from_pubkey(&sk.verifying_key());
        let kernel = b"kernel-bytes".to_vec();
        let rootfs = b"rootfs-bytes".to_vec();
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "test".to_string(),
            key_id: key_id.clone(),
            arch: mvm_core::arch::GuestArch::host().to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-05-13T00:00:00Z".to_string(),
            labels: Default::default(),
            artifacts: vec![
                BundleArtifact {
                    name: "vmlinux".to_string(),
                    role: ArtifactRole::Kernel,
                    path: "artifacts/vmlinux".to_string(),
                    sha256: sha256_hex(&kernel),
                    size_bytes: kernel.len() as u64,
                },
                BundleArtifact {
                    name: "rootfs.ext4".to_string(),
                    role: ArtifactRole::Rootfs,
                    path: "artifacts/rootfs.ext4".to_string(),
                    sha256: sha256_hex(&rootfs),
                    size_bytes: rootfs.len() as u64,
                },
            ],
            verity: None,
            resources: None,
        };
        let archive = write_bundle(
            &manifest,
            sk,
            vec![
                ("artifacts/vmlinux".to_string(), kernel),
                ("artifacts/rootfs.ext4".to_string(), rootfs),
            ],
        )
        .expect("write_bundle");
        (archive, key_id)
    }

    #[test]
    fn bundle_pin_from_archive_recovers_signature_and_sha() {
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let (archive, key_id) = make_bundle_for_pin(&sk);
        let pin = bundle_pin_from_archive(&archive, key_id.clone()).expect("recovers pin");
        assert_eq!(pin.bundle_sha256, mvm_core::plan::bundle_sha256(&archive));
        assert_eq!(pin.key_id, key_id);
        // Signature round-trips through base64 → bytes → verify.
        let sig_arr = pin.signature_bytes().expect("base64 decodes");
        assert_eq!(sig_arr.len(), 64);
    }

    #[test]
    fn bundle_pin_from_archive_missing_signature_errors() {
        // Bundle without a `manifest.sig` entry — built by hand so
        // the helper sees the gap. The function must bail with a
        // clear message rather than panic.
        let mut buf = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "manifest.json", std::io::Cursor::new(b""))
                .unwrap();
            tar.finish().unwrap();
        }
        let archive = buf.into_inner();
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        let key_id = mvm_core::plan::bundle::key_id_from_pubkey(&sk.verifying_key());
        let err = bundle_pin_from_archive(&archive, key_id).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("manifest.sig"), "msg was: {msg}");
    }

    #[test]
    fn in_memory_bundle_resolver_returns_archive_bytes() {
        let bytes = b"hello-archive".to_vec();
        let resolver = InMemoryBundleResolver::new(bytes.clone());
        let out = mvm_core::plan::BundleResolver::resolve(&resolver, "anything").unwrap();
        assert_eq!(out, bytes);
    }
}
