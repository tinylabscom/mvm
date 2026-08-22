//! The per-boot FlowMux identity a guest authenticates its egress session with.
//!
//! One authenticated session carries every byte between a guest and its
//! `mvm-network-endpoint`. The host pins the guest's verifying key when it
//! spawns the endpoint, so the guest must hold the matching signing key before
//! its egress client starts — which is before any control channel exists to
//! deliver one over.
//!
//! ## Why a drive and not the kernel cmdline
//!
//! The host-signer *public* key already rides `mvm.host_signer_pub=<hex>`
//! ([`super::egress_bridge`]), and that is fine: it is public. The guest's
//! signing key is not, and the cmdline is the wrong carrier for it — it is
//! world-readable at `/proc/cmdline` by the workload's own unprivileged uid, it
//! is logged verbatim when the workload runner assembles it, it is echoed to
//! the captured console log under `loglevel=8` on the builder paths, and it
//! appears in host `ps` output as `-append` on every QEMU path. The repo states
//! the invariant in [`super::network_endpoint_spawn::EgressTlsDelivery`]: keys
//! do not travel to a guest by a channel that leaks them.
//!
//! So the key rides a per-boot read-only ext4 drive instead. The guest mount
//! already exists and is already hardened (`nix/lib/mk-guest.nix` mounts it
//! `ro,noexec,nosuid,nodev`); only the host-side producer had been deleted.
//! The image is assembled **in memory** — the signing key is never written to a
//! host temp file on the way in — and is stamped with
//! [`IDENTITY_DRIVE_LABEL`] so a guest mounts it by content rather than by
//! device-enumeration order.

use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::TryRng;

use super::network_endpoint_spawn::FlowMuxIdentitySpawnConfig;

// The drive's label and filenames are declared on the reading side, in
// `mvm_agentd::flowmux_keys`, and used here. One declaration, so a rename
// cannot leave the writer and the reader describing different drives.
pub use mvm_agentd::flowmux_drive::{
    GUEST_SIGNING_KEY_FILE, GuestIngressTarget, HOST_SIGNER_PUB_FILE, IDENTITY_DRIVE_LABEL,
    INGRESS_TARGETS_FILE,
};

/// Mode the guest signing key is stored with. The drive is mounted read-only,
/// so this is belt-and-braces against a guest that copies it out badly.
const GUEST_SIGNING_KEY_MODE: u16 = 0o400;

/// Mode the public anchor is stored with.
const HOST_SIGNER_PUB_MODE: u16 = 0o444;

/// A minted per-boot identity: what the endpoint is told, and what the guest is
/// given.
///
/// `Debug` is hand-written and redacted — the struct holds a private key, and
/// a derived `Debug` would put it in any log line that formats a spawn request.
pub struct FlowMuxIdentityMaterial {
    spawn: FlowMuxIdentitySpawnConfig,
    guest_signing_key: [u8; 32],
    host_signer_pub: [u8; 32],
}

impl std::fmt::Debug for FlowMuxIdentityMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowMuxIdentityMaterial")
            .field("session_id", &self.spawn.session_id)
            .field("guest_signing_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl FlowMuxIdentityMaterial {
    /// Mint a fresh guest keypair for `session_id`, pinned to the host signer.
    ///
    /// The private half and the published verifying key are produced here
    /// together so they cannot drift: there is no path that hands the endpoint
    /// one key and the guest another.
    pub fn mint(session_id: impl Into<String>, host_signing_key: &SigningKey) -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut seed)
            .context("drawing system entropy for the guest FlowMux signing key")?;
        let guest_key = SigningKey::from_bytes(&seed);
        let b64 = base64::engine::general_purpose::STANDARD;
        Ok(Self {
            spawn: FlowMuxIdentitySpawnConfig {
                session_id: session_id.into(),
                host_signing_key_base64: b64.encode(host_signing_key.to_bytes()),
                guest_verifying_key_base64: b64.encode(guest_key.verifying_key().to_bytes()),
            },
            guest_signing_key: seed,
            host_signer_pub: host_signing_key.verifying_key().to_bytes(),
        })
    }

    /// Mint using the host's own signer at `~/.mvm/keys/host-signer.ed25519` —
    /// the same key the claim-8 audit chain is signed under, so a guest pins one
    /// host identity and not a second trust root.
    pub fn mint_from_host_signer(session_id: impl Into<String>) -> Result<Self> {
        let path =
            mvm_core::config::mvm_keys_dir().join(super::broker_services_spawn::HOST_SIGNER_KEY);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "reading the host signer key at {}. It is created on first use \
                 by the host-signer loader, which lives a layer above this \
                 crate; run `mvmctl doctor` once to create it.",
                path.display()
            )
        })?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "host signer key at {} is {} bytes, expected 32",
                path.display(),
                bytes.len()
            )
        })?;
        Self::mint(session_id, &SigningKey::from_bytes(&seed))
    }

    /// What the endpoint is told: the session id and both public halves.
    pub fn spawn_config(&self) -> &FlowMuxIdentitySpawnConfig {
        &self.spawn
    }

    /// The host-signer trust anchor the guest pins.
    pub fn host_signer_verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.host_signer_pub)
            .context("host signer public key is not a valid Ed25519 point")
    }

    /// Build the per-boot identity drive and write it to `path`.
    ///
    /// The image is assembled in memory, so the signing key never lands in a
    /// host temp file. The output itself is written 0600: it is per-VM state
    /// under `~/.mvm`, which is already 0700, and a mode on the image is one
    /// less thing depending on that.
    pub fn write_drive(&self, path: &Path) -> Result<()> {
        self.write_drive_with_ingress(path, &[])
    }

    /// Build the identity drive with the signed plan's guest-loopback ingress
    /// projection. Host bind addresses and transformation material are omitted.
    pub fn write_drive_with_ingress(
        &self,
        path: &Path,
        ingress: &[mvm_core::plan::IngressMapping],
    ) -> Result<()> {
        use mvm_fs::ext4::{BuildOptions, Node, build_image_with_options};

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let targets = ingress
            .iter()
            .map(|mapping| GuestIngressTarget {
                mapping_id: mapping.mapping_id,
                protocol: mapping.protocol,
                guest_addr: mapping.guest_addr.clone(),
                guest_port: mapping.guest_port,
            })
            .collect::<Vec<_>>();
        let targets_json =
            serde_json::to_vec(&targets).context("serializing guest ingress targets")?;
        let nodes = vec![
            Node::File {
                path: format!("/{GUEST_SIGNING_KEY_FILE}"),
                mode: GUEST_SIGNING_KEY_MODE,
                data: self.guest_signing_key.to_vec(),
                xattrs: Vec::new(),
            },
            Node::File {
                path: format!("/{HOST_SIGNER_PUB_FILE}"),
                mode: HOST_SIGNER_PUB_MODE,
                data: self.host_signer_pub.to_vec(),
                xattrs: Vec::new(),
            },
            Node::File {
                path: format!("/{INGRESS_TARGETS_FILE}"),
                mode: HOST_SIGNER_PUB_MODE,
                data: targets_json,
                xattrs: Vec::new(),
            },
        ];
        let image = build_image_with_options(
            nodes,
            &BuildOptions::default().with_volume_name(IDENTITY_DRIVE_LABEL.as_bytes()),
        )
        .map_err(|e| anyhow::anyhow!("building the FlowMux identity drive: {e}"))?;
        write_private(path, &image)
            .with_context(|| format!("writing the FlowMux identity drive to {}", path.display()))?;
        Ok(())
    }
}

/// Filename the identity drive is written under, inside the VM's state dir.
pub const IDENTITY_DRIVE_FILE: &str = "flowmux-identity.ext4";

/// Filename the inheritable half of a boot's identity is persisted under,
/// inside the VM's own state dir.
pub const PUBLIC_IDENTITY_FILE: &str = "flowmux-identity.json";

/// What a warm child needs to inherit from its parent, and nothing more.
///
/// Deliberately **not** [`FlowMuxIdentitySpawnConfig`]: that struct also
/// carries `host_signing_key_base64`, which is the host signer's *private*
/// key. It belongs in the endpoint's stdin and in `~/.mvm/keys`, not copied
/// into a per-VM state dir once per boot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InheritableIdentity {
    /// The session id the parent's guest handshakes under.
    pub session_id: String,
    /// The verifying key the parent's guest holds the private half of.
    pub guest_verifying_key_base64: String,
}

impl FlowMuxIdentityMaterial {
    /// The inheritable half of this identity.
    pub fn inheritable(&self) -> InheritableIdentity {
        InheritableIdentity {
            session_id: self.spawn.session_id.clone(),
            guest_verifying_key_base64: self.spawn.guest_verifying_key_base64.clone(),
        }
    }

    /// Persist the inheritable half beside the VM's state.
    ///
    /// A warm child restores from its parent's memory image, so it already
    /// holds the parent's signing key and cannot be handed a fresh one — there
    /// is no path back into a running guest's memory. The child's endpoint must
    /// therefore pin the parent's verifying key, and this file is how the claim
    /// path learns it. The host's own signing key is not written here.
    pub fn persist_inheritable(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating {}", state_dir.display()))?;
        let path = state_dir.join(PUBLIC_IDENTITY_FILE);
        let json = serde_json::to_vec_pretty(&self.inheritable())
            .context("serializing the inheritable FlowMux identity")?;
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))
    }
}

/// Load the inheritable identity a previous boot persisted in `state_dir`.
///
/// `None` when the VM was booted without one — a workload with no admitted
/// egress never gets an identity, and a claim from such a parent must not
/// invent one.
pub fn load_inheritable_identity(state_dir: &Path) -> Result<Option<InheritableIdentity>> {
    let path = state_dir.join(PUBLIC_IDENTITY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write `bytes` to `path` with mode 0600, creating it fresh.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Refuse an identity whose two halves do not describe the same keypair.
///
/// Cheap, and it turns a class of wiring mistake — handing the endpoint one
/// guest key while the drive carries another — into a launch failure instead of
/// a handshake that fails after boot with nothing pointing at the cause.
pub fn assert_identity_is_self_consistent(material: &FlowMuxIdentityMaterial) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let published = b64
        .decode(&material.spawn.guest_verifying_key_base64)
        .context("decoding the published guest verifying key")?;
    let derived = SigningKey::from_bytes(&material.guest_signing_key)
        .verifying_key()
        .to_bytes();
    if published != derived {
        bail!("minted FlowMux identity is inconsistent: published guest key is not the drive's");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    #[test]
    fn the_published_guest_key_is_the_one_on_the_drive() {
        let material = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        assert_identity_is_self_consistent(&material).expect("halves must match");
    }

    #[test]
    fn each_mint_draws_a_fresh_guest_key() {
        let a = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        let b = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        assert_ne!(
            a.spawn_config().guest_verifying_key_base64,
            b.spawn_config().guest_verifying_key_base64,
            "a per-boot identity must not repeat across boots"
        );
    }

    #[test]
    fn the_endpoint_is_told_the_host_signer_it_signs_with() {
        let material = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        let b64 = base64::engine::general_purpose::STANDARD;
        let told = b64
            .decode(&material.spawn_config().host_signing_key_base64)
            .expect("base64");
        assert_eq!(told, host_key().to_bytes());
        assert_eq!(
            material.host_signer_verifying_key().expect("anchor"),
            host_key().verifying_key(),
            "the guest's anchor must verify what the endpoint signs with"
        );
    }

    #[test]
    fn debug_never_prints_the_signing_key() {
        let material = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        let rendered = format!("{material:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        let leaked = hex::encode(material.guest_signing_key);
        assert!(
            !rendered.contains(&leaked),
            "signing key leaked: {rendered}"
        );
    }

    #[test]
    fn the_drive_carries_both_files_and_is_labelled_for_mount_by_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image_path = dir.path().join("identity.ext4");
        let material = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        material.write_drive(&image_path).expect("write drive");

        let image = std::fs::read(&image_path).expect("read image");
        // s_volume_name lives at superblock offset 0x78; the superblock starts
        // at byte 1024. Read it the same way stage0-init identifies the disk.
        let label_at = 1024 + 0x78;
        let label = &image[label_at..label_at + IDENTITY_DRIVE_LABEL.len()];
        assert_eq!(label, IDENTITY_DRIVE_LABEL.as_bytes());

        // The key bytes are in the image, and the image only.
        assert!(
            image
                .windows(32)
                .any(|w| w == material.guest_signing_key.as_slice()),
            "the drive must carry the signing key"
        );
        assert!(
            image.windows(32).any(|w| w == material.host_signer_pub),
            "the drive must carry the trust anchor"
        );
    }

    #[test]
    fn the_guest_decoder_reads_the_label_this_writer_stamps() {
        // Validate against the real writer rather than a synthetic byte layout,
        // and decode with the guest's own function — so a change to either side
        // of the on-disk superblock contract fails here instead of silently
        // desynchronizing the host writer and the guest reader.
        let dir = tempfile::tempdir().expect("tempdir");
        let image_path = dir.path().join("identity.ext4");
        FlowMuxIdentityMaterial::mint("s1", &host_key())
            .expect("mint")
            .write_drive(&image_path)
            .expect("write drive");
        let image = std::fs::read(&image_path).expect("read image");
        assert_eq!(
            mvm_agentd::flowmux_drive::ext4_volume_label_from_superblock(&image).as_deref(),
            Some(IDENTITY_DRIVE_LABEL),
            "the guest must find this drive by the label the host stamped"
        );
    }

    #[test]
    fn the_drive_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let image_path = dir.path().join("identity.ext4");
        FlowMuxIdentityMaterial::mint("s1", &host_key())
            .expect("mint")
            .write_drive(&image_path)
            .expect("write drive");
        let mode = std::fs::metadata(&image_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "identity drive must not be readable off-owner");
    }

    #[test]
    fn only_public_material_is_persisted_for_a_warm_child_to_inherit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let material = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        material.persist_inheritable(dir.path()).expect("persist");

        let raw = std::fs::read(dir.path().join(PUBLIC_IDENTITY_FILE)).expect("read");
        assert!(
            !raw.windows(32)
                .any(|w| w == material.guest_signing_key.as_slice()),
            "the guest signing key must never be persisted host-side"
        );
        let text = String::from_utf8(raw).expect("json is utf8");
        assert!(
            !text.contains(&material.spawn_config().host_signing_key_base64),
            "the host signer's private key must not be copied into per-VM state"
        );

        let loaded = load_inheritable_identity(dir.path())
            .expect("load")
            .expect("a persisted identity is there");
        assert_eq!(
            loaded.guest_verifying_key_base64,
            material.spawn_config().guest_verifying_key_base64,
            "a warm child must pin exactly the key its parent's guest holds"
        );
        assert_eq!(loaded.session_id, material.spawn_config().session_id);
    }

    #[test]
    fn a_parent_that_booted_without_egress_has_no_identity_to_inherit() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            load_inheritable_identity(dir.path())
                .expect("absence is not an error")
                .is_none(),
            "a claim from an egress-less parent must not invent an identity"
        );
    }

    #[test]
    fn an_inconsistent_identity_is_refused() {
        let mut material = FlowMuxIdentityMaterial::mint("s1", &host_key()).expect("mint");
        let other = FlowMuxIdentityMaterial::mint("s2", &host_key()).expect("mint");
        material.spawn.guest_verifying_key_base64 =
            other.spawn_config().guest_verifying_key_base64.clone();
        assert!(
            assert_identity_is_self_consistent(&material).is_err(),
            "a published key that is not the drive's must be refused"
        );
    }
}
