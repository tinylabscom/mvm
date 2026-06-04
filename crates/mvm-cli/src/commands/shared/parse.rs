//! Argument parsers — clap value parsers and post-parse domain converters.

use anyhow::{Context, Result};

use mvm_core::vm_backend::{VmVolume, VmVolumeKind};

/// Validate a VM name at Clap parse time.
pub fn clap_vm_name(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_vm_name(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a Nix flake reference at Clap parse time.
pub fn clap_flake_ref(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_flake_ref(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a port spec (`PORT` or `HOST:GUEST`) at Clap parse time.
pub fn clap_port_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("port spec must not be empty".to_owned());
    }
    if let Some((host_part, guest_part)) = s.split_once(':') {
        host_part
            .parse::<u16>()
            .map_err(|_| format!("invalid host port {:?} in {:?}", host_part, s))?;
        guest_part
            .parse::<u16>()
            .map_err(|_| format!("invalid guest port {:?} in {:?}", guest_part, s))?;
    } else {
        s.parse::<u16>()
            .map_err(|_| format!("invalid port {:?} — expected PORT or HOST:GUEST", s))?;
    }
    Ok(s.to_owned())
}

/// Validate a volume spec at Clap parse time. Delegates to
/// [`parse_volume_spec`] so the flag and the post-parse converter share
/// one grammar (no drift between clap-time and run-time validation).
pub fn clap_volume_spec(s: &str) -> Result<String, String> {
    parse_volume_spec(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Parse a port spec like `3000` or `8080:3000` into `(local, guest)`.
pub fn parse_port_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((local, guest)) = spec.split_once(':') {
        let local: u16 = local
            .parse()
            .with_context(|| format!("invalid local port '{}'", local))?;
        let guest: u16 = guest
            .parse()
            .with_context(|| format!("invalid guest port '{}'", guest))?;
        Ok((local, guest))
    } else {
        let port: u16 = spec
            .parse()
            .with_context(|| format!("invalid port '{}'", spec))?;
        Ok((port, port))
    }
}

/// Parse multiple port specs into `PortMapping` values.
pub fn parse_port_specs(specs: &[String]) -> Result<Vec<mvm::config::PortMapping>> {
    specs
        .iter()
        .map(|s| {
            let (host, guest) = parse_port_spec(s)?;
            Ok(mvm::config::PortMapping { host, guest })
        })
        .collect()
}

/// Parsed volume specification from the `--volume/-v` CLI flag (or the
/// `MVM_VOLUMES` env var).
///
/// Grammar (split on `:`):
/// - `host:/guest`             — live host-directory share (virtio-fs)
/// - `host:/guest:ro|rw`       — dir share, explicit mode
/// - `host:/guest:SIZE`        — persistent ext4 disk image (virtio-blk)
/// - `host:/guest:SIZE:ro|rw`  — disk, explicit mode
/// - `…:enc`                   — disk only: mark for encryption (Plan 101)
///
/// Disambiguation is positional: the token right after the guest mount
/// is the SIZE iff it isn't a `ro`/`rw`/`enc` keyword; its presence is
/// what makes the volume a disk rather than a dir share. Mode/`enc`
/// modifiers follow in any order.
///
/// **Default mode is read-only** — a security-posture choice. Writing to
/// a host directory or disk from inside a (potentially untrusted) guest
/// is a deliberate grant the operator opts into with an explicit `:rw`.
/// The base rootfs + every runtime-managed mount stay read-only and are
/// never user-controllable (see `validate_guest_mount`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeSpec {
    /// Live host-directory share over virtio-fs (two-way unless `read_only`).
    DirShare {
        host_dir: String,
        guest_mount: String,
        read_only: bool,
    },
    /// Persistent ext4 disk image attached as virtio-blk.
    Disk {
        host: String,
        guest: String,
        size: String,
        read_only: bool,
        /// `:enc` — route through in-guest encryption (Plan 101). Fails
        /// closed at launch until that lands; never silently plaintext.
        encrypted: bool,
    },
}

const VOLUME_GRAMMAR_HINT: &str = "expected host:/guest[:ro|rw] (dir share) \
     or host:/guest:SIZE[:ro|rw][:enc] (disk image)";

fn is_volume_keyword(tok: &str) -> bool {
    matches!(tok.to_ascii_lowercase().as_str(), "ro" | "rw" | "enc")
}

pub fn parse_volume_spec(spec: &str) -> Result<VolumeSpec> {
    if spec.is_empty() {
        anyhow::bail!("volume spec must not be empty");
    }
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid volume '{spec}' — {VOLUME_GRAMMAR_HINT}");
    }
    let host = parts[0];
    let guest = parts[1];
    if host.is_empty() {
        anyhow::bail!("invalid volume '{spec}' — empty host path; {VOLUME_GRAMMAR_HINT}");
    }
    if guest.is_empty() {
        anyhow::bail!("invalid volume '{spec}' — empty guest mount; {VOLUME_GRAMMAR_HINT}");
    }
    if !guest.starts_with('/') {
        anyhow::bail!(
            "invalid volume '{spec}' — guest mount '{guest}' must be an absolute path (start with '/')"
        );
    }

    let rest = &parts[2..];

    // Positional size: the first trailing token, iff it's not a keyword.
    let (size, modifiers) = match rest.first() {
        Some(first) if !is_volume_keyword(first) => {
            if first.is_empty() {
                anyhow::bail!("invalid volume '{spec}' — empty size field; {VOLUME_GRAMMAR_HINT}");
            }
            (Some(*first), &rest[1..])
        }
        _ => (None, rest),
    };

    // Default read-only: writes from a guest to a host path are opt-in
    // via an explicit `:rw`. Highest-security posture (see type docs).
    let mut read_only = true;
    let mut mode_seen = false;
    let mut encrypted = false;
    for m in modifiers {
        match m.to_ascii_lowercase().as_str() {
            "ro" | "rw" => {
                if mode_seen {
                    anyhow::bail!("invalid volume '{spec}' — mode (ro/rw) given more than once");
                }
                read_only = m.eq_ignore_ascii_case("ro");
                mode_seen = true;
            }
            "enc" => {
                if encrypted {
                    anyhow::bail!("invalid volume '{spec}' — 'enc' given more than once");
                }
                encrypted = true;
            }
            "" => anyhow::bail!("invalid volume '{spec}' — empty modifier; {VOLUME_GRAMMAR_HINT}"),
            other => anyhow::bail!(
                "invalid volume '{spec}' — unknown modifier '{other}'. \
                 The SIZE must come before ro/rw/enc; {VOLUME_GRAMMAR_HINT}"
            ),
        }
    }

    match size {
        Some(size) => Ok(VolumeSpec::Disk {
            host: host.to_string(),
            guest: guest.to_string(),
            size: size.to_string(),
            read_only,
            encrypted,
        }),
        None => {
            if encrypted {
                anyhow::bail!(
                    "invalid volume '{spec}' — 'enc' only applies to disk-image volumes \
                     (give a SIZE: host:/guest:SIZE:enc). A live directory share can't be \
                     encrypted by mvm."
                );
            }
            Ok(VolumeSpec::DirShare {
                host_dir: host.to_string(),
                guest_mount: guest.to_string(),
                read_only,
            })
        }
    }
}

/// Merge the `MVM_VOLUMES` env baseline with `--volume` flag values.
/// Env entries come first; flag values are appended (the flag adds to
/// the env, it does not replace it). See `mvm_core::config::mvm_volumes_env`.
pub fn merge_volume_specs(flag_specs: &[String]) -> Vec<String> {
    let mut out = mvm_core::config::mvm_volumes_env();
    out.extend(flag_specs.iter().cloned());
    out
}

/// Convert a parsed [`VolumeSpec`] into the backend-agnostic
/// [`VmVolume`] carried by `VmStartConfig`.
pub fn volume_spec_to_vm_volume(spec: &VolumeSpec) -> VmVolume {
    match spec {
        VolumeSpec::DirShare {
            host_dir,
            guest_mount,
            read_only,
        } => VmVolume {
            host: host_dir.clone(),
            guest: guest_mount.clone(),
            size: String::new(),
            read_only: *read_only,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        },
        VolumeSpec::Disk {
            host,
            guest,
            size,
            read_only,
            encrypted,
        } => VmVolume {
            host: host.clone(),
            guest: guest.clone(),
            size: size.clone(),
            read_only: *read_only,
            kind: VmVolumeKind::Disk,
            encrypted: *encrypted,
        },
    }
}

/// Sparse-create the backing image for one disk-image volume so the
/// hypervisor can attach it (a directory share needs nothing). The image
/// is created at its declared size if absent; an existing image is left
/// intact so its data survives. No-op for a directory share.
///
/// The sidecar-lock guard from `ensure_persistent_volume_image` is
/// released immediately: Apple Vz takes its own exclusive lock on a RW
/// disk at start, and a daemon-launched workload can't hold a host-side
/// guard for the VM's lifetime anyway. The guard's value is serializing
/// concurrent *creation*, which this still does.
pub fn materialize_disk_volume(v: &VmVolume) -> Result<()> {
    if !matches!(v.kind, VmVolumeKind::Disk) {
        return Ok(());
    }
    let size_mib = mvm_core::util::parse_human_size(&v.size)
        .with_context(|| format!("disk volume '{}' size '{}'", v.guest, v.size))?;
    let size_bytes = u64::from(size_mib) * 1024 * 1024;
    mvm_build::builder_vm_runtime::ensure_persistent_volume_image(
        std::path::Path::new(&v.host),
        size_bytes,
        v.read_only,
    )
    .with_context(|| format!("materializing disk volume image '{}'", v.host))?;
    Ok(())
}

/// Materialize every disk-image volume in `volumes` (dir shares skipped).
pub fn materialize_disk_volumes(volumes: &[VmVolume]) -> Result<()> {
    for v in volumes {
        materialize_disk_volume(v)?;
    }
    Ok(())
}

/// The only guest paths a user volume may mount on. An **allow-list**
/// (not a deny-list) so the base rootfs and every runtime-managed mount
/// (`/`, `/root`, `/etc`, `/usr`, `/nix`, `/dev`, the builder shares, …)
/// are read-only and never user-controllable *by construction* — a
/// volume can only land at/under one of these roots. These mirror the
/// in-guest `mvm_security::policy::MountPathPolicy` allow-roots and are
/// the only mountpoints mkGuest pre-creates on the read-only rootfs.
const ALLOWED_GUEST_MOUNT_ROOTS: &[&str] = &["/data", "/work", "/mnt"];

/// Guest paths reserved by the runtime even though they sit under an
/// allowed root: the config + secret drives. A *directory share* at
/// these is intercepted earlier as a config/secret drive; any other use
/// (e.g. a disk image) is refused here.
const RESERVED_UNDER_ALLOWED: &[&str] = &["/mnt/config", "/mnt/secrets"];

/// Enforce the user-volume mount allow-list: the guest path must be one
/// of [`ALLOWED_GUEST_MOUNT_ROOTS`] or a path under one, and must not be
/// a reserved drive path. Pure (no FS access). This is the Tier-0
/// guarantee that a user volume can never shadow or make-writable a
/// system mount.
pub fn validate_guest_mount(guest: &str) -> Result<()> {
    let g = guest.trim_end_matches('/');
    let g = if g.is_empty() { "/" } else { g };

    for r in RESERVED_UNDER_ALLOWED {
        if g == *r || g.starts_with(&format!("{r}/")) {
            anyhow::bail!(
                "guest mount '{guest}' is reserved by the mvm runtime ('{r}'); choose another path"
            );
        }
    }

    let allowed = ALLOWED_GUEST_MOUNT_ROOTS
        .iter()
        .any(|root| g == *root || g.starts_with(&format!("{root}/")));
    if !allowed {
        anyhow::bail!(
            "guest mount '{guest}' is not allowed — user volumes may only mount under {}. \
             The rootfs and all system mounts are read-only and not user-controllable.",
            ALLOWED_GUEST_MOUNT_ROOTS.join(", ")
        );
    }
    Ok(())
}

/// Expand a leading `~/` against `$HOME`. Leaves other paths untouched.
fn expand_tilde(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return std::path::PathBuf::from(home).join(rest);
    }
    std::path::PathBuf::from(p)
}

/// Host directories a user volume must never expose to a guest: the
/// host signer key, the audit chain, and common credential stores.
/// Sharing any of these would hand a guest the host's trust roots.
fn denied_host_roots() -> Vec<std::path::PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let h = std::path::PathBuf::from(home);
        for sub in [".mvm/keys", ".mvm/audit", ".ssh", ".gnupg", ".aws"] {
            roots.push(h.join(sub));
        }
    }
    roots
}

/// True if `path` is `root` or lives under it. Pure (lexical).
fn path_is_under(path: &std::path::Path, root: &std::path::Path) -> bool {
    path == root || path.starts_with(root)
}

/// Canonicalize a user-supplied host path and refuse protected
/// locations. Returns the resolved absolute path so the caller can
/// **pin** it (TOCTOU: a symlink swap between admit and attach can't
/// redirect the share). `expect_dir` true → the path must already exist
/// and be a directory (a virtio-fs share); false → a disk image that
/// may not exist yet (its parent is canonicalized instead).
fn validate_host_path(host: &str, expect_dir: bool) -> Result<String> {
    let raw = expand_tilde(host);
    let canonical = if raw.exists() {
        let c = std::fs::canonicalize(&raw)
            .with_context(|| format!("canonicalizing host path '{host}'"))?;
        if expect_dir && !c.is_dir() {
            anyhow::bail!("directory share '{host}' must be a directory, not a file");
        }
        if !expect_dir && c.is_dir() {
            anyhow::bail!(
                "disk-image volume '{host}' points at a directory; a disk image must be a file \
                 (use host:/guest without a SIZE for a directory share)"
            );
        }
        c
    } else if expect_dir {
        anyhow::bail!(
            "directory share '{host}' does not exist — a virtio-fs share must point at an \
             existing host directory"
        );
    } else {
        // Disk image to be created: canonicalize the parent (resolves
        // symlinks for the deny-check) and append the file name.
        let abs = if raw.is_absolute() {
            raw.clone()
        } else {
            std::env::current_dir()
                .context("resolving current dir for a relative volume path")?
                .join(&raw)
        };
        let parent = abs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("volume path '{host}' has no parent directory"))?;
        let file = abs
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("volume path '{host}' has no file name"))?;
        let parent_canon = if parent.exists() {
            std::fs::canonicalize(parent)
                .with_context(|| format!("canonicalizing parent of '{host}'"))?
        } else {
            parent.to_path_buf()
        };
        parent_canon.join(file)
    };

    for denied in denied_host_roots() {
        if path_is_under(&canonical, &denied) {
            anyhow::bail!(
                "refusing to share host path '{}' — it is inside a protected directory '{}' \
                 (host keys / audit / credentials are never exposed to a guest)",
                canonical.display(),
                denied.display()
            );
        }
    }

    Ok(canonical.to_string_lossy().into_owned())
}

/// Parse-then-validate a single volume spec into a [`VmVolume`], the
/// shared choke point for both `mvmctl up`/`run` and `mvmctl dev`.
///
/// Enforces, in order:
/// - **Encryption fail-closed (§8 / Plan 101):** a `:enc` disk is
///   refused with a clear error — never silently stored as plaintext.
/// - **Reserved guest mount (§7):** the guest path can't shadow a
///   runtime mount or the secrets/config drives.
/// - **Host-path safety (§7):** the host path is canonicalized (symlinks
///   resolved), checked against a protected-directory deny-list, and the
///   **resolved** path is pinned back onto the volume (TOCTOU-safe).
pub fn vm_volume_from_spec_validated(spec: &VolumeSpec) -> Result<VmVolume> {
    if let VolumeSpec::Disk {
        encrypted: true, ..
    } = spec
    {
        anyhow::bail!(
            "encrypted volumes (':enc') are not yet implemented — tracked in Plan 101. \
             Refusing to launch rather than store volume data unencrypted."
        );
    }

    let mut vmv = volume_spec_to_vm_volume(spec);
    validate_guest_mount(&vmv.guest)?;
    let expect_dir = matches!(vmv.kind, VmVolumeKind::DirShare);
    vmv.host = validate_host_path(&vmv.host, expect_dir)?;
    Ok(vmv)
}

#[cfg(test)]
mod volume_spec_tests {
    use super::*;

    #[test]
    fn dir_share_two_part_defaults_ro() {
        match parse_volume_spec("/h/src:/work").unwrap() {
            VolumeSpec::DirShare {
                host_dir,
                guest_mount,
                read_only,
            } => {
                assert_eq!(host_dir, "/h/src");
                assert_eq!(guest_mount, "/work");
                assert!(read_only, "default is read-only (security posture)");
            }
            _ => panic!("expected dir share"),
        }
    }

    #[test]
    fn dir_share_ro_and_rw_modes() {
        assert!(matches!(
            parse_volume_spec("/h:/g:ro").unwrap(),
            VolumeSpec::DirShare {
                read_only: true,
                ..
            }
        ));
        assert!(matches!(
            parse_volume_spec("/h:/g:rw").unwrap(),
            VolumeSpec::DirShare {
                read_only: false,
                ..
            }
        ));
        // Case-insensitive.
        assert!(matches!(
            parse_volume_spec("/h:/g:RO").unwrap(),
            VolumeSpec::DirShare {
                read_only: true,
                ..
            }
        ));
    }

    #[test]
    fn disk_three_part_size_defaults_ro_unencrypted() {
        match parse_volume_spec("/h/data.img:/data:10G").unwrap() {
            VolumeSpec::Disk {
                host,
                guest,
                size,
                read_only,
                encrypted,
            } => {
                assert_eq!(host, "/h/data.img");
                assert_eq!(guest, "/data");
                assert_eq!(size, "10G");
                assert!(read_only, "default is read-only (security posture)");
                assert!(!encrypted);
            }
            _ => panic!("expected disk"),
        }
    }

    #[test]
    fn disk_with_mode_and_enc_any_order() {
        for spec in ["/h:/d:10G:rw:enc", "/h:/d:10G:enc:rw"] {
            match parse_volume_spec(spec).unwrap() {
                VolumeSpec::Disk {
                    read_only,
                    encrypted,
                    size,
                    ..
                } => {
                    assert_eq!(size, "10G");
                    assert!(!read_only);
                    assert!(encrypted, "{spec}");
                }
                _ => panic!("expected disk for {spec}"),
            }
        }
        assert!(matches!(
            parse_volume_spec("/h:/d:10G:ro:enc").unwrap(),
            VolumeSpec::Disk {
                read_only: true,
                encrypted: true,
                ..
            }
        ));
    }

    #[test]
    fn enc_rejected_on_dir_share() {
        let err = parse_volume_spec("/h:/g:enc").unwrap_err().to_string();
        assert!(err.contains("only applies to disk"), "got: {err}");
    }

    #[test]
    fn rejects_malformed() {
        for spec in [
            "",                  // empty
            "/h",                // 1-part
            ":/g",               // empty host
            "/h:",               // empty guest
            "/h:rel/path",       // guest not absolute
            "/h:/g:10G:ro:rw",   // mode twice
            "/h:/g:10G:enc:enc", // enc twice
            "/h:/g:10G:bogus",   // unknown modifier
            "/h:/g:",            // empty size/modifier
        ] {
            assert!(parse_volume_spec(spec).is_err(), "should reject {spec:?}");
        }
    }

    #[test]
    fn clap_validator_matches_parser() {
        assert!(clap_volume_spec("/h:/g:10G:rw").is_ok());
        assert!(clap_volume_spec("/h:/g:enc").is_err());
    }

    #[test]
    fn validated_conversion_fails_closed_on_enc() {
        let spec = parse_volume_spec("/h/d.img:/data:10G:enc").unwrap();
        let err = vm_volume_from_spec_validated(&spec)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not yet implemented"), "got: {err}");
        assert!(err.contains("Plan 101"));
    }

    #[test]
    fn validated_conversion_enforces_mount_allow_list() {
        // The guest-mount allow-list fires before host-path validation,
        // so a fake host path is fine here. Anything not under
        // /data,/work,/mnt — including system paths — is refused.
        for guest in [
            "/",
            "/root",
            "/etc",
            "/etc/passwd",
            "/usr/bin",
            "/nix",
            "/nix-store/x",
            "/dev/foo",
            "/proc/1",
            "/srv/data",
            "/data-evil",
            "/workspace",
        ] {
            let spec = parse_volume_spec(&format!("/h:{guest}")).unwrap();
            assert!(
                vm_volume_from_spec_validated(&spec).is_err(),
                "should refuse mount outside the allow-list: {guest}"
            );
        }
        // The config/secret drives are reserved even though under /mnt.
        for guest in ["/mnt/config", "/mnt/secrets"] {
            let spec = parse_volume_spec(&format!("/h:{guest}")).unwrap();
            assert!(
                vm_volume_from_spec_validated(&spec).is_err(),
                "should reserve {guest}"
            );
        }
        // The allow-roots (and paths under them) pass the mount check —
        // validate_guest_mount is pure, so it returns Ok before the
        // host-path FS check would run.
        for guest in ["/data", "/work", "/mnt", "/mnt/extra", "/data/sub"] {
            assert!(
                validate_guest_mount(guest).is_ok(),
                "allow-root should pass: {guest}"
            );
        }
    }

    #[test]
    fn validated_conversion_maps_dir_and_disk_real_paths() {
        let scratch = tempfile::TempDir::new().unwrap();
        let src = scratch.path().join("src");
        std::fs::create_dir(&src).unwrap();
        let dir = vm_volume_from_spec_validated(
            &parse_volume_spec(&format!("{}:/data:ro", src.display())).unwrap(),
        )
        .unwrap();
        assert_eq!(dir.kind, VmVolumeKind::DirShare);
        assert!(dir.read_only);
        // Host path is pinned to the canonical resolved path.
        assert_eq!(
            dir.host,
            std::fs::canonicalize(&src).unwrap().to_string_lossy()
        );

        // Disk image need not exist yet (parent does).
        let img = scratch.path().join("d.img");
        let disk = vm_volume_from_spec_validated(
            &parse_volume_spec(&format!("{}:/data:5G", img.display())).unwrap(),
        )
        .unwrap();
        assert_eq!(disk.kind, VmVolumeKind::Disk);
        assert_eq!(disk.size, "5G");
    }

    #[test]
    fn dir_share_must_exist_and_be_a_directory() {
        let scratch = tempfile::TempDir::new().unwrap();
        let missing = scratch.path().join("nope");
        assert!(
            vm_volume_from_spec_validated(
                &parse_volume_spec(&format!("{}:/data", missing.display())).unwrap()
            )
            .is_err(),
            "a non-existent dir share must be refused"
        );
        // A file (not a dir) used as a dir share is refused.
        let f = scratch.path().join("file");
        std::fs::write(&f, b"x").unwrap();
        assert!(
            vm_volume_from_spec_validated(
                &parse_volume_spec(&format!("{}:/data", f.display())).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn path_is_under_matches_self_and_descendants() {
        use std::path::Path;
        assert!(path_is_under(Path::new("/a/b"), Path::new("/a/b")));
        assert!(path_is_under(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(!path_is_under(Path::new("/a/bc"), Path::new("/a/b")));
        assert!(!path_is_under(Path::new("/x"), Path::new("/a/b")));
    }
}
