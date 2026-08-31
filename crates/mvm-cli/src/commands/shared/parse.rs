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

/// Parsed mount specification from the `--mount` CLI flag, its compatibility
/// `--volume` alias, or the `MVM_VOLUMES` env var.
///
/// Grammar (split on `:`):
/// - `host:/guest`             — live host-directory share (virtio-fs)
/// - `host:/guest:ro|rw`       — dir share, explicit mode
/// - `host:/guest:SIZE`        — persistent ext4 disk image (virtio-blk)
/// - `host:/guest:SIZE:ro|rw`  — disk, explicit mode
/// - `…:enc`                   — disk only: mark for encryption
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
        /// `:enc` — route through in-guest encryption. Fails closed at
        /// launch until that lands; never silently plaintext.
        encrypted: bool,
    },
}

/// A live host-directory share accepted by transient `machine run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirShareSpec {
    /// Host directory served by virtio-fs.
    pub host_dir: String,
    /// Absolute guest mount point.
    pub guest_mount: String,
    /// Whether the guest must see the share read-only.
    pub read_only: bool,
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

/// Parse a transient live directory share and reject disk-image syntax.
pub fn parse_dir_share_spec(spec: &str) -> Result<DirShareSpec> {
    match parse_volume_spec(spec)? {
        VolumeSpec::DirShare {
            host_dir,
            guest_mount,
            read_only,
        } => {
            validate_guest_mount(&guest_mount)
                .map_err(|error| anyhow::anyhow!("invalid mount '{spec}': {error}"))?;
            Ok(DirShareSpec {
                host_dir,
                guest_mount,
                read_only,
            })
        }
        VolumeSpec::Disk { .. } => anyhow::bail!(
            "mount '{spec}' includes a disk size; transient machine run accepts only live host-directory shares"
        ),
    }
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
            materialized_image: None,
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
            materialized_image: None,
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
/// released immediately: the hypervisor (HVF) takes its own exclusive lock
/// on a RW disk at start, and a daemon-launched workload can't hold a host-side
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

/// Enforce the guest-mount policy: the guest path must sit under one of
/// the mount allow-roots and must neither sit inside a runtime-owned path
/// nor shadow one. Pure (no FS access).
///
/// This is the Tier-0 guarantee that a user volume can never shadow or
/// make-writable a system mount. It delegates to
/// `mvm_core::crypto::policy::MountPathPolicy` rather than keeping its own
/// copy of the roots: the agent applies the same policy before `mount(2)`,
/// and two copies of a security constant drift.
pub fn validate_guest_mount(guest: &str) -> Result<()> {
    mvm_core::crypto::policy::validate_mount_path(guest)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("{e}"))
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
    let mut roots = vec![
        mvm_core::config::mvm_keys_dir(),
        mvm_core::config::mvm_audit_dir(),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let h = std::path::PathBuf::from(home);
        for sub in [".ssh", ".gnupg", ".aws"] {
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
/// shared choke point for both `mvmctl up`/`run`.
///
/// Enforces, in order:
/// - **Encryption fail-closed:** a `:enc` disk is refused with a clear
///   error — never silently stored as plaintext.
/// - **Reserved guest mount:** the guest path can't shadow a runtime
///   mount or the secrets/config drives.
/// - **Host-path safety:** the host path is canonicalized (symlinks
///   resolved), checked against a protected-directory deny-list, and the
///   **resolved** path is pinned back onto the volume (TOCTOU-safe).
pub fn vm_volume_from_spec_validated(spec: &VolumeSpec) -> Result<VmVolume> {
    validate_volume_spec(spec)?;

    let mut vmv = volume_spec_to_vm_volume(spec);
    let expect_dir = matches!(vmv.kind, VmVolumeKind::DirShare);
    vmv.host = validate_host_path(&vmv.host, expect_dir)?;
    Ok(vmv)
}

/// Validate the security properties available from a parsed volume alone.
///
/// This deliberately does not inspect the host filesystem, so dry-run and
/// receipt construction can reject encryption and guest-path violations
/// without requiring a synthetic host path to exist.
pub fn validate_volume_spec(spec: &VolumeSpec) -> Result<()> {
    if let VolumeSpec::Disk {
        encrypted: true, ..
    } = spec
    {
        anyhow::bail!(
            "encrypted volumes (':enc') are not yet implemented — tracked in Plan 101. \
             Refusing to launch rather than store volume data unencrypted."
        );
    }

    let vmv = volume_spec_to_vm_volume(spec);
    validate_guest_mount(&vmv.guest)?;
    Ok(())
}

#[cfg(test)]
mod volume_spec_tests {
    use super::*;

    #[test]
    fn pure_volume_validation_does_not_require_the_host_path_to_exist() {
        let spec = parse_volume_spec("/missing/fixture.ext4:/work/fixtures:64M:ro")
            .expect("parse disk volume");

        validate_volume_spec(&spec).expect("pure validation");
    }

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
    fn transient_dir_share_rejects_a_guest_path_outside_the_mount_allow_list() {
        let error = parse_dir_share_spec("/host/wheels:/wheels:ro")
            .expect_err("/wheels is outside the guest mount allow-list")
            .to_string();

        assert!(error.contains("invalid mount"), "unexpected error: {error}");
        assert!(
            error.contains("allow-roots"),
            "error should name the allow-roots: {error}"
        );

        // And a share that would shadow a reserved drive, which sits
        // *inside* an allow-root and so the allow-roots alone would admit.
        let error = parse_dir_share_spec("/host/wheels:/mnt:ro")
            .expect_err("/mnt shadows the config and secret drives")
            .to_string();
        assert!(
            error.contains("shadow"),
            "error should explain the shadowing: {error}"
        );
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

    /// Claim-1 witness: the validated conversion enforces the guest-mount
    /// allow-list, in both containment directions.
    ///
    /// The conversion is the single choke point every user volume passes
    /// through, so this is where "no host-fs access from a guest beyond
    /// explicit shares" is established for the mount half. Replacing
    /// `validate_guest_mount` with `Ok(())` must fail this test.
    #[test]
    fn validated_conversion_enforces_mount_allow_list() {
        // The gate fires before host-path validation, so a fake host path
        // is fine here. Anything not under /data or /work — including
        // system paths and /mnt — is refused.
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
            // `/mnt` belongs to the runtime, which mounts the config and
            // secret drives beneath it before any user volume attaches.
            "/mnt",
            "/mnt/extra",
            "/mnt/config",
            "/mnt/secrets",
        ] {
            let spec = parse_volume_spec(&format!("/h:{guest}")).unwrap();
            assert!(
                vm_volume_from_spec_validated(&spec).is_err(),
                "should refuse mount outside the allow-list: {guest}"
            );
        }
        // The allow-roots and paths under them pass the mount check —
        // validate_guest_mount is pure, so it returns Ok before the
        // host-path FS check would run.
        for guest in ["/data", "/work", "/data/sub", "/work/src"] {
            assert!(
                validate_guest_mount(guest).is_ok(),
                "allow-root should pass: {guest}"
            );
        }
    }

    /// The guest-mount allow-list, in both directions.
    ///
    /// Replacing this whole function with `Ok(())` survived, which means
    /// nothing established that a user volume cannot shadow or
    /// make-writable a system mount — claim 1's "no host-fs access from a
    /// guest beyond explicit shares" resting on an unwitnessed check.
    #[test]
    fn the_guest_mount_allow_list_admits_only_allowed_roots() {
        // Every allowed root with a child, and a trailing slash that
        // normalizes rather than changing the verdict. `/mnt` is excluded
        // because the runtime owns the drives beneath it.
        for root in ["/data", "/work"] {
            validate_guest_mount(root).unwrap_or_else(|e| panic!("{root} must be allowed: {e}"));
            validate_guest_mount(&format!("{root}/sub"))
                .unwrap_or_else(|e| panic!("{root}/sub must be allowed: {e}"));
            validate_guest_mount(&format!("{root}/"))
                .unwrap_or_else(|e| panic!("{root}/ must be allowed: {e}"));
        }
        // Anything outside them is refused — including the rootfs itself
        // and paths that merely share a prefix with an allowed root.
        for denied in [
            "/",
            "/etc",
            "/usr",
            "/usr/local",
            "/root",
            "/proc",
            "/sys",
            "/dev",
            "/init",
            "/nix",
            "/datax",
            "/workshop",
            "/mnt/sub",
            "/mnttest",
            "/data/../etc",
            "relative/path",
            "",
        ] {
            assert!(
                validate_guest_mount(denied).is_err(),
                "{denied} must not be an allowed guest mount"
            );
        }
    }

    /// The runtime-owned drives remain protected even though `/mnt` itself
    /// is no longer a user allow-root.
    #[test]
    fn runtime_owned_mnt_tree_is_refused() {
        for reserved in ["/mnt/config", "/mnt/secrets"] {
            assert!(
                validate_guest_mount(reserved).is_err(),
                "{reserved} is owned by the runtime"
            );
            assert!(
                validate_guest_mount(&format!("{reserved}/nested")).is_err(),
                "{reserved}/nested is under a reserved drive"
            );
            let err = validate_guest_mount(&format!("{reserved}x"))
                .expect_err("{reserved}x is outside the allow-roots")
                .to_string();
            assert!(
                err.contains("allow-roots"),
                "{reserved}x must be refused by the narrowed allow-roots: {err}"
            );
        }
        // And the parent they live under must be refused too: a share at
        // `/mnt` hides both drives without ever naming them.
        assert!(
            validate_guest_mount("/mnt").is_err(),
            "/mnt shadows the config and secret drives"
        );
    }

    /// The protected host roots a share may never expose. Emptying this
    /// list survived, and an empty list means the host signer key, the
    /// audit chain and the user's credential stores all become shareable
    /// into a guest.
    #[test]
    fn the_protected_host_roots_cover_keys_audit_and_credentials() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("HOME", tmp.path());
        env.set("MVM_HOME", tmp.path().join("mvm"));

        let roots = denied_host_roots();
        assert!(
            !roots.is_empty(),
            "an empty protected-root list protects nothing"
        );
        assert!(
            roots.contains(&mvm_core::config::mvm_keys_dir()),
            "the host signer key directory must never be shareable"
        );
        assert!(
            roots.contains(&mvm_core::config::mvm_audit_dir()),
            "the audit chain must never be shareable"
        );
        for cred in [".ssh", ".gnupg", ".aws"] {
            assert!(
                roots.contains(&tmp.path().join(cred)),
                "~/{cred} must never be shareable"
            );
        }

        // And the list is actually consulted: a path inside one is under it.
        assert!(path_is_under(
            &tmp.path().join(".ssh").join("id_ed25519"),
            &tmp.path().join(".ssh")
        ));
    }

    /// The MiB→bytes conversion is two multiplications, and both survived
    /// every arithmetic mutation: nothing observed the size of the image
    /// that gets created. `*` becoming `+` or `/` turns a 10 MiB request
    /// into a few kilobytes, so the guest gets a disk orders of magnitude
    /// smaller than it asked for and fails on first write.
    ///
    /// Asserting the created file's length is what makes this
    /// discriminate; asserting the call returns `Ok` is what the
    /// whole-function `-> Ok(())` mutant passes.
    #[test]
    fn a_disk_volume_is_materialised_at_the_requested_size() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let host = tmp.path().join("data.img");
        let volume = VmVolume {
            materialized_image: None,
            host: host.to_string_lossy().into_owned(),
            guest: "/data".to_string(),
            size: "10M".to_string(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            encrypted: false,
        };

        materialize_disk_volume(&volume).expect("materialising a disk volume");

        let len = std::fs::metadata(&host).expect("the image exists").len();
        // The writer rounds down to a block boundary (observed: 64 KiB
        // short of the request), so this asserts the band rather than an
        // exact count — an exact count would encode the rounding as if it
        // were the contract. The band is still far tighter than any of the
        // arithmetic mutants: `10 + 1024 * 1024` is ~1 MiB, `10 * 1024 +
        // 1024` is ~11 KiB, and the two `/` forms collapse to 10 and 0.
        let requested = 10 * 1024 * 1024u64;
        assert!(
            len > requested - (1024 * 1024) && len <= requested,
            "a 10M request must produce very nearly 10 MiB, got {len} bytes"
        );

        // A directory share is not a disk and must not have an image
        // written for it — the early return is its own mutant.
        let share_host = tmp.path().join("share");
        let share = VmVolume {
            materialized_image: None,
            host: share_host.to_string_lossy().into_owned(),
            guest: "/share".to_string(),
            size: "10M".to_string(),
            read_only: false,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        };
        materialize_disk_volume(&share).expect("a dir share is a no-op");
        assert!(
            !share_host.exists(),
            "a directory share must not materialise a disk image"
        );
    }
}
