//! `mvmctl volume` — virtio-fs volume mount lifecycle. Plan 45 §D5
//! (Path C; renamed from the prior `share` subcommand without
//! behavioural change).
//!
//! This command owns two registries:
//! - managed local encrypted volumes in `~/.mvm/volumes/registry.json`
//! - per-VM mounts in `~/.mvm/instances/<vm>/volume_mounts.json`
//!
//! The actual `virtiofsd`-on-host + Firecracker virtio-device-attach
//! is a follow-up — the substrate routes through
//! `mvm_core::crypto::policy::MountPathPolicy` and emits the same
//! `MountVolume` / `UnmountVolume` vsock verbs the agent handler
//! already serves.
//!
//! Managed local volumes fail closed unless their host directory is
//! backed by encrypted storage (macOS encrypted APFS/FileVault volume
//! or Linux dm-crypt/LUKS chain). Ad-hoc `--host` mounts are still
//! accepted only when the exact directory also passes that check.
//!
//! ## `--remote` mode (mvmd proxy)
//!
//! Per plan 45 §D5 (Path C), `--remote` routes operations through
//! mvmd's REST API rather than executing locally. v1 stub only —
//! the actual `mvmctl::mvmd_client` module ships in a follow-up
//! once the mvmd-side bucket reconciliation lands (mvmd Sprint 137
//! W2). Today `--remote` returns a clear "not yet implemented"
//! error.

use std::fs::{self, File};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use mvm::vm::volume_registry::{
    LocalVolumeCatalog, LocalVolumeEncryption, LocalVolumeEntry, LocalVolumeState,
    MvmManagedVolumeEncryption, VolumeMountEntry, VolumeMountRegistry,
};
use mvm_core::crypto::key_rotation;
use mvm_core::crypto::policy::validate_mount_path;
use mvm_core::crypto::rotation_policy;
use mvm_core::domain::volume::{MasterKeyState, OrgId, WrapAlgorithm, WrappedKey};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use rand::RngCore;
use secrecy::ExposeSecret;

use super::Cli;
use super::shared::clap_vm_name;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: VolumeCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum VolumeCmd {
    /// Create a managed encrypted local volume.
    Create {
        /// Logical volume name (used as the virtio-fs tag).
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        volume: String,
        /// Root directory under which encrypted volume state
        /// will be created. Defaults to ~/.mvm/volumes/local.
        #[arg(long)]
        root: Option<String>,
        /// Use the previous host-backed encryption gate instead of
        /// an mvm-managed encrypted archive.
        #[arg(long)]
        host_backed: bool,
    },
    /// Decrypt a managed volume into its plaintext mount directory.
    Unlock { volume: String },
    /// Seal a managed volume and remove its plaintext mount directory.
    Lock { volume: String },
    /// List managed local volumes.
    Catalog {
        #[arg(long)]
        json: bool,
    },
    /// Mount a virtio-fs volume into a VM.
    ///
    /// Per plan 45 §D5 (Path C): operations against provider-backed
    /// (S3 / Hetzner / R2 / GCS / Azure) volumes route through mvmd
    /// via `--remote`. v1 mvm-side `mount` handles only local
    /// volumes (host directory exposed via virtio-fs).
    Mount {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Logical volume name (used as the virtio-fs tag).
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        #[arg(long)]
        volume: String,
        /// Absolute host directory exposed via virtio-fs. Advanced
        /// path: omitted for managed volumes created with
        /// `mvmctl volume create`.
        #[arg(long)]
        host: Option<String>,
        /// Mount point inside the VM (must be under /mnt, /data,
        /// or /work; never under /etc, /usr, /lib, /proc, /nix,
        /// etc.)
        #[arg(long)]
        guest: String,
        /// Mount the volume read-write (default: read-only).
        #[arg(long)]
        rw: bool,
        /// Route through mvmd REST instead of writing the local
        /// registry. Stub in v1 — see plan 45 §D5.
        #[arg(long)]
        remote: bool,
    },
    /// List registered volume mounts for a VM.
    Ls {
        #[arg(value_parser = clap_vm_name)]
        name: String,
        #[arg(long)]
        json: bool,
        /// Route through mvmd REST instead of reading the local
        /// registry. Stub in v1 — see plan 45 §D5.
        #[arg(long)]
        remote: bool,
    },
    /// Unmount a registered volume.
    Unmount {
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Guest mount path to detach.
        guest_path: String,
        /// Route through mvmd REST instead of editing the local
        /// registry. Stub in v1 — see plan 45 §D5.
        #[arg(long)]
        remote: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        VolumeCmd::Create {
            volume,
            root,
            host_backed,
        } => create(&volume, root.as_deref(), host_backed),
        VolumeCmd::Unlock { volume } => unlock(&volume),
        VolumeCmd::Lock { volume } => lock(&volume),
        VolumeCmd::Catalog { json } => catalog(json),
        VolumeCmd::Mount {
            name,
            volume,
            host,
            guest,
            rw,
            remote,
        } => {
            if remote {
                return remote_stub("volume mount");
            }
            mount(&name, &volume, host.as_deref(), &guest, rw)
        }
        VolumeCmd::Ls { name, json, remote } => {
            if remote {
                return remote_stub("volume ls");
            }
            ls(&name, json)
        }
        VolumeCmd::Unmount {
            name,
            guest_path,
            remote,
        } => {
            if remote {
                return remote_stub("volume unmount");
            }
            unmount(&name, &guest_path)
        }
    }
}

fn default_managed_volume_root() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("volumes")
        .join("local")
}

fn default_mvm_volume_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("volumes")
        .join("mvm-managed")
}

fn local_master_key_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("volumes")
        .join("master-keys")
        .join("local")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))?;
    Ok(())
}

fn remote_stub(op: &str) -> Result<()> {
    bail!("{op} --remote not yet implemented. Use the local volume registry for now.")
}

fn validate_volume_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        bail!(
            "volume name length {} outside [1, 32] (used as virtio-fs tag)",
            name.len()
        );
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("volume name {name:?} must be lowercase alphanumeric + hyphens");
    }
    if name.starts_with('-') {
        bail!("volume name {name:?} must not start with a hyphen");
    }
    Ok(())
}

fn create(volume_name: &str, root: Option<&str>, host_backed: bool) -> Result<()> {
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    if host_backed {
        return create_host_backed(volume_name, root);
    }
    create_mvm_managed(volume_name, root)
}

fn create_host_backed(volume_name: &str, root: Option<&str>) -> Result<()> {
    let root = match root {
        Some(root) => std::path::PathBuf::from(root),
        None => default_managed_volume_root(),
    };
    if !root.is_absolute() {
        bail!(
            "managed volume root must be absolute, got {}",
            root.display()
        );
    }
    std::fs::create_dir_all(&root)
        .with_context(|| format!("creating managed volume root {}", root.display()))?;
    crate::doctor::require_local_volume_host_path_encrypted(&root)?;

    let host_path = root.join(volume_name);
    if host_path.exists() && !host_path.is_dir() {
        bail!(
            "managed volume path {} exists but is not a directory",
            host_path.display()
        );
    }
    std::fs::create_dir_all(&host_path)
        .with_context(|| format!("creating managed volume {}", host_path.display()))?;
    crate::doctor::require_local_volume_host_path_encrypted(&host_path)?;

    let mut catalog = LocalVolumeCatalog::load()?;
    catalog.add(LocalVolumeEntry {
        volume_name: volume_name.to_string(),
        host_path: host_path.to_string_lossy().into_owned(),
        encrypted: true,
        encryption: LocalVolumeEncryption::HostBacked,
        created_at: mvm_core::util::time::utc_now(),
    })?;
    catalog.save()?;
    println!(
        "created encrypted local volume {volume_name:?} at {}",
        host_path.display()
    );
    mvm_core::audit_emit!(
        VolumeCreate,
        "volume={volume_name} host={} encrypted=true",
        host_path.display()
    );
    Ok(())
}

fn create_mvm_managed(volume_name: &str, root: Option<&str>) -> Result<()> {
    let root = match root {
        Some(root) => PathBuf::from(root),
        None => default_mvm_volume_root(),
    };
    if !root.is_absolute() {
        bail!(
            "managed volume root must be absolute, got {}",
            root.display()
        );
    }
    ensure_private_dir(&root)?;
    let ciphertext_dir = root.join("encrypted");
    let plaintext_dir = root.join("unlocked");
    ensure_private_dir(&ciphertext_dir)?;
    ensure_private_dir(&plaintext_dir)?;

    let ciphertext_path = ciphertext_dir.join(format!("{volume_name}.mvve"));
    let host_path = plaintext_dir.join(volume_name);
    if ciphertext_path.exists() || host_path.exists() {
        bail!(
            "managed volume {volume_name:?} already has on-disk state under {}",
            root.display()
        );
    }

    let (wrapped_key, dek) = generate_wrapped_volume_key()?;
    let scratch = tempfile::tempdir_in(&root).context("creating empty volume scratch dir")?;
    write_encrypted_volume_archive(scratch.path(), &ciphertext_path, dek.expose_secret())?;

    let mut catalog = LocalVolumeCatalog::load()?;
    catalog.add(LocalVolumeEntry {
        volume_name: volume_name.to_string(),
        host_path: host_path.to_string_lossy().into_owned(),
        encrypted: true,
        encryption: LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
            state: LocalVolumeState::Locked,
            ciphertext_path: ciphertext_path.to_string_lossy().into_owned(),
            wrapped_key,
        }),
        created_at: mvm_core::util::time::utc_now(),
    })?;
    catalog.save()?;
    println!(
        "created locked mvm-managed encrypted volume {volume_name:?} at {}",
        ciphertext_path.display()
    );
    mvm_core::audit_emit!(
        VolumeCreate,
        "volume={volume_name} ciphertext={} state=locked",
        ciphertext_path.display()
    );
    Ok(())
}

/// Plan 122 B1 — opportunistically roll the local master KEK when it is
/// past its 90-day lifetime, re-wrapping the catalog's mvm-managed volume
/// keys onto the new KEK. Invoked whenever a managed volume key is minted —
/// the closest thing to a periodic "on use" trigger the local CLI has.
///
/// Cheap and non-destructive: re-wrapping leaves the underlying DEK (and
/// the on-disk ciphertext) untouched, so an existing volume keeps
/// decrypting. Best-effort scope — only keys already at the current active
/// version are swept (a single re-wrap can't span mixed versions); a volume
/// wrapped under an older legacy KEK keeps unlocking via its recorded
/// version and the retained legacy key file. The age check itself lives in
/// `rotation_policy` and is fully unit-tested there.
fn maybe_rotate_local_master_key() -> Result<()> {
    let active_dir = local_master_key_dir();
    let manifest = key_rotation::load_manifest(&active_dir)?;
    let Some(active_version) = manifest
        .entries
        .iter()
        .find(|e| e.state == MasterKeyState::Active)
        .map(|e| e.version)
    else {
        return Ok(()); // nothing minted yet — the first key isn't a rotation
    };

    let mut catalog = LocalVolumeCatalog::load()?;
    let mut names: Vec<String> = Vec::new();
    let mut sweep: Vec<WrappedKey> = Vec::new();
    for (name, entry) in catalog.volumes.iter() {
        if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
            && enc.wrapped_key.master_key_version == active_version
        {
            names.push(name.clone());
            sweep.push(enc.wrapped_key.clone());
        }
    }

    let org = OrgId::new("local").context("constructing local org id")?;
    let decision = rotation_policy::rotate_if_due(
        &active_dir,
        &org,
        &mut sweep,
        rotation_policy::default_interval(),
        chrono::Utc::now(),
    )?;

    if let rotation_policy::RotationDecision::Rotated {
        from_version,
        to_version,
        migrated,
    } = decision
    {
        for (name, rewrapped) in names.into_iter().zip(sweep) {
            if let Some(LocalVolumeEntry {
                encryption: LocalVolumeEncryption::MvmManaged(enc),
                ..
            }) = catalog.volumes.get_mut(&name)
            {
                enc.wrapped_key = rewrapped;
            }
        }
        catalog.save()?;
        eprintln!(
            "rotated local master KEK v{from_version} → v{to_version}; \
             re-wrapped {migrated} volume key(s)"
        );
    }
    Ok(())
}

fn generate_wrapped_volume_key() -> Result<(WrappedKey, secrecy::SecretBox<Vec<u8>>)> {
    // Roll the KEK first if it's past its lifetime, then mint under the
    // (possibly fresh) active version.
    maybe_rotate_local_master_key()?;
    let active_dir = local_master_key_dir();
    let manifest = key_rotation::load_manifest(&active_dir)?;
    let version = if manifest.latest_version() == 0 {
        let org_id = OrgId::new("local").context("constructing local org id")?;
        key_rotation::rotate_master_key(&active_dir, &org_id)?.version
    } else {
        manifest.latest_version()
    };
    let master = key_rotation::load_master_key(&active_dir, version)?;
    let mut dek = vec![0u8; mvm_core::crypto::snapshot_encryption::KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut dek);
    let wrapped = mvm_core::crypto::snapshot_crypto::encrypt(&dek, master.expose_secret())
        .context("wrapping volume data key")?;
    Ok((
        WrappedKey {
            master_key_version: version,
            wrapped,
            algorithm: WrapAlgorithm::Aes256Gcm,
        },
        secrecy::SecretBox::new(Box::new(dek)),
    ))
}

fn unwrap_volume_key(entry: &LocalVolumeEntry) -> Result<secrecy::SecretBox<Vec<u8>>> {
    let enc = match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) => enc,
        LocalVolumeEncryption::HostBacked => {
            bail!(
                "volume {:?} is host-backed, not mvm-managed",
                entry.volume_name
            )
        }
    };
    let master =
        key_rotation::load_master_key(&local_master_key_dir(), enc.wrapped_key.master_key_version)
            .with_context(|| format!("loading master key for volume {:?}", entry.volume_name))?;
    let dek = match enc.wrapped_key.algorithm {
        WrapAlgorithm::Aes256Gcm => mvm_core::crypto::snapshot_crypto::decrypt(
            &enc.wrapped_key.wrapped,
            master.expose_secret(),
        )
        .with_context(|| format!("unwrapping data key for volume {:?}", entry.volume_name))?,
        WrapAlgorithm::AesKwp => {
            bail!("AES-KWP wrapped local volume keys are not supported by mvmctl")
        }
    };
    if dek.len() != mvm_core::crypto::snapshot_encryption::KEY_SIZE {
        bail!(
            "unwrapped data key for volume {:?} is {} bytes, expected {}",
            entry.volume_name,
            dek.len(),
            mvm_core::crypto::snapshot_encryption::KEY_SIZE
        );
    }
    Ok(secrecy::SecretBox::new(Box::new(dek)))
}

fn write_plain_archive(src_dir: &Path, archive_path: &Path) -> Result<()> {
    let archive = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(archive_path)
        .with_context(|| format!("creating archive {}", archive_path.display()))?;
    let mut builder = tar::Builder::new(archive);
    builder
        .append_dir_all(".", src_dir)
        .with_context(|| format!("archiving {}", src_dir.display()))?;
    builder.finish().context("finishing volume archive")?;
    Ok(())
}

fn write_encrypted_volume_archive(
    src_dir: &Path,
    ciphertext_path: &Path,
    dek: &[u8],
) -> Result<()> {
    if let Some(parent) = ciphertext_path.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp = ciphertext_path.with_extension(format!("{}.plain.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        write_plain_archive(src_dir, &tmp)?;
        mvm_core::crypto::snapshot_encryption::encrypt_file_in_place(&tmp, dek)
            .context("encrypting volume archive")?;
        fs::rename(&tmp, ciphertext_path).with_context(|| {
            format!(
                "renaming encrypted archive {} -> {}",
                tmp.display(),
                ciphertext_path.display()
            )
        })?;
        fs::set_permissions(ciphertext_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", ciphertext_path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn decrypt_volume_archive_to_dir(
    ciphertext_path: &Path,
    dest_dir: &Path,
    dek: &[u8],
) -> Result<()> {
    if dest_dir.exists() {
        let mut entries =
            fs::read_dir(dest_dir).with_context(|| format!("reading {}", dest_dir.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!(
                "plaintext volume directory {} already exists and is not empty",
                dest_dir.display()
            );
        }
    } else {
        fs::create_dir_all(dest_dir).with_context(|| format!("creating {}", dest_dir.display()))?;
    }
    fs::set_permissions(dest_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dest_dir.display()))?;

    let tmp = ciphertext_path.with_extension(format!("{}.decrypt.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        fs::copy(ciphertext_path, &tmp).with_context(|| {
            format!(
                "copy encrypted archive {} -> {}",
                ciphertext_path.display(),
                tmp.display()
            )
        })?;
        mvm_core::crypto::snapshot_encryption::decrypt_file_in_place(&tmp, dek)
            .context("decrypting volume archive")?;
        let file = File::open(&tmp).with_context(|| format!("opening {}", tmp.display()))?;
        let mut archive = tar::Archive::new(file);
        archive
            .unpack(dest_dir)
            .with_context(|| format!("unpacking volume into {}", dest_dir.display()))?;
        Ok(())
    })();
    let _ = fs::remove_file(&tmp);
    result
}

fn unlock(volume_name: &str) -> Result<()> {
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    let mut catalog = LocalVolumeCatalog::load()?;
    let entry = catalog
        .get(volume_name)
        .with_context(|| format!("no managed local volume named {volume_name:?}"))?
        .clone();
    let dek = unwrap_volume_key(&entry)?;
    let ciphertext_path = match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) => {
            if enc.state == LocalVolumeState::Unlocked {
                bail!("volume {volume_name:?} is already unlocked");
            }
            PathBuf::from(&enc.ciphertext_path)
        }
        LocalVolumeEncryption::HostBacked => {
            bail!("volume {volume_name:?} is host-backed and does not need unlock")
        }
    };
    decrypt_volume_archive_to_dir(
        &ciphertext_path,
        Path::new(&entry.host_path),
        dek.expose_secret(),
    )?;
    let entry = catalog
        .get_mut(volume_name)
        .expect("entry existed before unlock mutation");
    if let LocalVolumeEncryption::MvmManaged(enc) = &mut entry.encryption {
        enc.state = LocalVolumeState::Unlocked;
    }
    let host_path = entry.host_path.clone();
    catalog.save()?;
    println!(
        "unlocked volume {volume_name:?} at {}",
        Path::new(&host_path).display()
    );
    mvm_core::audit_emit!(VolumeOpen, "volume={volume_name} state=unlocked");
    Ok(())
}

fn lock(volume_name: &str) -> Result<()> {
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    let mut catalog = LocalVolumeCatalog::load()?;
    let entry = catalog
        .get(volume_name)
        .with_context(|| format!("no managed local volume named {volume_name:?}"))?
        .clone();
    let dek = unwrap_volume_key(&entry)?;
    let ciphertext_path = match &entry.encryption {
        LocalVolumeEncryption::MvmManaged(enc) => {
            if enc.state == LocalVolumeState::Locked {
                bail!("volume {volume_name:?} is already locked");
            }
            PathBuf::from(&enc.ciphertext_path)
        }
        LocalVolumeEncryption::HostBacked => {
            bail!("volume {volume_name:?} is host-backed and cannot be sealed by mvmctl")
        }
    };
    let host_path = PathBuf::from(&entry.host_path);
    if !host_path.is_dir() {
        bail!(
            "plaintext volume directory {} is missing; cannot lock",
            host_path.display()
        );
    }
    let tmp_ciphertext = ciphertext_path.with_extension(format!("{}.new", std::process::id()));
    write_encrypted_volume_archive(&host_path, &tmp_ciphertext, dek.expose_secret())?;
    fs::rename(&tmp_ciphertext, &ciphertext_path).with_context(|| {
        format!(
            "replacing encrypted archive {} -> {}",
            tmp_ciphertext.display(),
            ciphertext_path.display()
        )
    })?;
    fs::remove_dir_all(&host_path)
        .with_context(|| format!("removing plaintext volume dir {}", host_path.display()))?;
    let entry = catalog
        .get_mut(volume_name)
        .expect("entry existed before lock mutation");
    if let LocalVolumeEncryption::MvmManaged(enc) = &mut entry.encryption {
        enc.state = LocalVolumeState::Locked;
    }
    catalog.save()?;
    println!("locked volume {volume_name:?}");
    mvm_core::audit_emit!(VolumeLock, "volume={volume_name} state=locked");
    Ok(())
}

fn catalog(json: bool) -> Result<()> {
    let catalog = LocalVolumeCatalog::load()?;
    if json {
        let rows: Vec<&LocalVolumeEntry> = catalog.iter().map(|(_, v)| v).collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if catalog.is_empty() {
        println!("(no managed local volumes)");
        return Ok(());
    }
    println!("{:<22} {:<10} {:<12} HOST", "VOLUME", "ENCRYPTED", "STATE");
    for (_, e) in catalog.iter() {
        let state = match &e.encryption {
            LocalVolumeEncryption::HostBacked => "host-backed",
            LocalVolumeEncryption::MvmManaged(enc) => match enc.state {
                LocalVolumeState::Locked => "locked",
                LocalVolumeState::Unlocked => "unlocked",
            },
        };
        println!(
            "{:<22} {:<10} {:<12} {}",
            e.volume_name, e.encrypted, state, e.host_path
        );
    }
    Ok(())
}

fn resolve_mount_host(volume_name: &str, host: Option<&str>) -> Result<String> {
    if let Some(host) = host {
        return Ok(host.to_string());
    }
    let catalog = LocalVolumeCatalog::load()?;
    let entry = catalog.get(volume_name).with_context(|| {
        format!(
            "no managed local volume named {volume_name:?}; run `mvmctl volume create \
             {volume_name}` or pass --host <encrypted-dir>"
        )
    })?;
    if !entry.encrypted {
        bail!("managed local volume {volume_name:?} is not marked encrypted");
    }
    if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
        && enc.state != LocalVolumeState::Unlocked
    {
        bail!(
            "managed local volume {volume_name:?} is locked; run `mvmctl volume unlock \
             {volume_name}` before mounting"
        );
    }
    Ok(entry.host_path.clone())
}

fn mount(
    vm_name: &str,
    volume_name: &str,
    host: Option<&str>,
    guest: &str,
    rw: bool,
) -> Result<()> {
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {:?}", vm_name))?;
    validate_volume_name(volume_name)
        .with_context(|| format!("Invalid volume name: {:?}", volume_name))?;
    let ad_hoc_host = host.is_some();
    let host = resolve_mount_host(volume_name, host)?;

    // Host path must be absolute and exist on disk; otherwise
    // virtiofsd would fail later with a confusing message.
    if !std::path::Path::new(&host).is_absolute() {
        bail!("--host path must be absolute, got {:?}", host);
    }
    if !std::path::Path::new(&host).is_dir() {
        bail!("--host path {:?} is not an existing directory", host);
    }
    if ad_hoc_host {
        crate::doctor::require_local_volume_host_path_encrypted(std::path::Path::new(&host))?;
    }

    // Validate the guest-side path against the mount policy
    // before we touch the registry — same check the agent runs.
    let canonical_guest = validate_mount_path(guest)
        .with_context(|| format!("guest path {:?} rejected by policy", guest))?;

    let mut registry = VolumeMountRegistry::load(vm_name)?;
    registry.add(VolumeMountEntry {
        volume_name: volume_name.to_string(),
        host_path: host.clone(),
        guest_path: canonical_guest.clone(),
        read_only: !rw,
        attached_at: mvm_core::util::time::utc_now(),
    })?;
    registry.save(vm_name)?;

    println!(
        "{vm_name}: registered volume {volume_name:?} → {canonical_guest} (host={host}, ro={})",
        !rw
    );
    eprintln!(
        "note: virtiofsd-on-host + Firecracker virtio-device-attach are a follow-up; \
         the registry entry + agent MountVolume verb are ready."
    );
    mvm_core::audit_emit!(VmVolumeAdd, vm: vm_name, "volume={volume_name} host={host} guest={canonical_guest} ro={}" ,
        !rw
    );
    Ok(())
}

fn ls(vm_name: &str, json: bool) -> Result<()> {
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {:?}", vm_name))?;
    let registry = VolumeMountRegistry::load(vm_name)?;
    if json {
        let rows: Vec<&VolumeMountEntry> = registry.iter().map(|(_, v)| v).collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if registry.is_empty() {
        println!("(no volume mounts)");
        return Ok(());
    }
    println!(
        "{:<22} {:<22} {:<14} {:<4} HOST",
        "GUEST", "VOLUME", "ATTACHED", "RO"
    );
    for (_, e) in registry.iter() {
        println!(
            "{:<22} {:<22} {:<14} {:<4} {}",
            e.guest_path,
            e.volume_name,
            &e.attached_at[..e.attached_at.len().min(14)],
            if e.read_only { "yes" } else { "no" },
            e.host_path,
        );
    }
    Ok(())
}

fn unmount(vm_name: &str, guest_path: &str) -> Result<()> {
    validate_vm_name(vm_name).with_context(|| format!("Invalid VM name: {:?}", vm_name))?;
    let mut registry = VolumeMountRegistry::load(vm_name)?;
    let dropped = registry
        .remove(guest_path)
        .with_context(|| format!("VM {:?} has no volume mount at {:?}", vm_name, guest_path))?;
    registry.save(vm_name)?;
    println!(
        "{vm_name}: unmounted volume {} from {} (host={})",
        dropped.volume_name, dropped.guest_path, dropped.host_path
    );
    mvm_core::audit_emit!(VmVolumeRemove, vm: vm_name, "volume={} guest={}" ,
        dropped.volume_name, dropped.guest_path
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static DATA_DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct DataDirGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
        tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var("MVM_DATA_DIR").ok();
            unsafe { std::env::set_var("MVM_DATA_DIR", tmp.path()) };
            Self {
                _guard: guard,
                prev,
                tmp,
            }
        }

        fn path(&self) -> &Path {
            self.tmp.path()
        }
    }

    impl Drop for DataDirGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(prev) => std::env::set_var("MVM_DATA_DIR", prev),
                    None => std::env::remove_var("MVM_DATA_DIR"),
                }
            }
        }
    }

    #[test]
    fn mvm_managed_volume_create_unlock_lock_roundtrip() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false).unwrap();

        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(!Path::new(&entry.host_path).exists());
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => {
                assert_eq!(enc.state, LocalVolumeState::Locked);
                PathBuf::from(&enc.ciphertext_path)
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        };
        assert!(ciphertext.is_file());

        unlock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(Path::new(&entry.host_path).is_dir());
        assert!(matches!(
            &entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Unlocked,
                ..
            })
        ));

        fs::write(Path::new(&entry.host_path).join("hello.txt"), b"secret").unwrap();
        lock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(!Path::new(&entry.host_path).exists());
        assert!(matches!(
            &entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Locked,
                ..
            })
        ));

        unlock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert_eq!(
            fs::read(Path::new(&entry.host_path).join("hello.txt")).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn mvm_managed_mount_refuses_locked_volume() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false).unwrap();
        let err = mount("vm-1", "work", None, "/mnt/work", false).unwrap_err();
        assert!(err.to_string().contains("is locked"), "got: {err}");
    }

    #[test]
    fn mvm_managed_unlock_rejects_tampered_ciphertext() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false).unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => PathBuf::from(&enc.ciphertext_path),
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        };
        let mut bytes = fs::read(&ciphertext).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&ciphertext, bytes).unwrap();
        let err = unlock("work").unwrap_err();
        assert!(
            err.to_string().contains("decrypting volume archive")
                || err.to_string().contains("authentication failure"),
            "got: {err}"
        );
    }

    #[test]
    fn mvm_managed_unlock_rejects_missing_master_key() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false).unwrap();
        fs::remove_dir_all(local_master_key_dir()).unwrap();
        let err = unlock("work").unwrap_err();
        assert!(err.to_string().contains("loading master key"), "got: {err}");
    }

    #[test]
    fn create_rotates_stale_local_master_key_and_rewraps_catalog() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        // First volume mints master v1 and wraps "work" under it.
        create("work", Some(root.to_str().unwrap()), false).unwrap();

        // Backdate the active KEK to 91 days old so the next mint trips the
        // 90-day rotation policy.
        let active_dir = local_master_key_dir();
        let mut manifest = key_rotation::load_manifest(&active_dir).unwrap();
        manifest.entries[0].created_at = chrono::Utc::now() - chrono::Duration::days(91);
        fs::write(
            active_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // Creating a second volume runs the rotation check.
        create("work2", Some(root.to_str().unwrap()), false).unwrap();

        // KEK advanced v1 → v2.
        let manifest = key_rotation::load_manifest(&active_dir).unwrap();
        assert_eq!(manifest.latest_version(), 2);

        // The pre-existing "work" volume was re-wrapped onto v2 …
        let catalog = LocalVolumeCatalog::load().unwrap();
        match &catalog.get("work").unwrap().encryption {
            LocalVolumeEncryption::MvmManaged(enc) => {
                assert_eq!(enc.wrapped_key.master_key_version, 2);
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed"),
        }
        // … and still unlocks, proving the DEK survived the re-wrap.
        unlock("work").unwrap();
    }

    #[test]
    fn mvm_managed_unlock_rejects_wrong_master_key() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false).unwrap();
        let key_path = local_master_key_dir().join("v1.bin");
        fs::write(&key_path, [42u8; key_rotation::MASTER_KEY_BYTES]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = unlock("work").unwrap_err();
        assert!(
            err.to_string().contains("unwrapping data key")
                || err.to_string().contains("authentication"),
            "got: {err}"
        );
    }
}
